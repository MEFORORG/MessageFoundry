# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""restore-verify (ADR 0049 AC-5): the key-fingerprint precheck returns a clean KEY_MISMATCH BEFORE any
decrypt; a matching key (active OR a retired key still in the keyring after a rotation) decrypts + opens
the embedded store read-only + integrity_check + row-count compare (PASS); a corrupted archive is FAIL.
(The at-least-once-across-restore case, AC-11, lives in ``test_backup_restore_atleastonce.py``.)

The FULL verify (AC-13) opens the snapshot under the instance's LIVE store settings and decrypts +
authenticates its cipher-covered cells, so a PASS means the PHI was readable, not merely that a SQLite
file opened."""

from __future__ import annotations

import base64
import io
import json
import sqlite3
import tarfile
import tempfile
from collections.abc import Callable
from pathlib import Path

from messagefoundry.config.settings import BackupSettings, StoreSettings
from messagefoundry.pipeline import dr_backup
from messagefoundry.pipeline.dr_backup import (
    BackupRunner,
    _verify_archive_blocking,
    run_restore_verify,
)
from messagefoundry.store import MessageStatus, MessageStore
from messagefoundry.store.backup_codec import decrypt_stream, encrypt_stream
from messagefoundry.store.crypto import generate_key, make_cipher
from messagefoundry.store.store import Stage


async def _backup(
    tmp_path: Path, key_b64: str | None, *, allow_unencrypted: bool = False
) -> tuple[MessageStore, str, StoreSettings]:
    cipher = make_cipher(key_b64) if key_b64 else None
    store = await MessageStore.open(tmp_path / "msg.db", cipher=cipher)
    await store.enqueue_message(
        channel_id="c1",
        raw="MSH|^~\\&|x",
        deliveries=[("d1", "OUT|y")],
        control_id="CID-1",
        now=1.0,
    )
    ss = StoreSettings(path=str(tmp_path / "msg.db"), encryption_key=key_b64)
    runner = BackupRunner(
        store,
        BackupSettings(
            enabled=True,
            destination=str(tmp_path / "b"),
            allow_unencrypted=allow_unencrypted,
        ),
        store_settings=ss,
        config_dir=None,
    )
    result = await runner.run_once(now=1.0)
    assert result is not None
    return store, result.archive_path, ss


def _flip_one_aead_byte(db: Path, table: str, column: str) -> None:
    """Flip one bit inside a stored AEAD blob so the cell still PARSES as an ``mfenc:`` value but fails
    its GCM tag — the shape bit rot takes on an encrypted PHI cell. SQLite's own integrity check and
    every row count are blind to it, which is exactly why the verify has to open the cell itself."""
    conn = sqlite3.connect(db)
    try:
        row = conn.execute(
            f"SELECT id, {column} FROM {table} WHERE {column} LIKE 'mfenc:%'"  # constants
        ).fetchone()
        assert row is not None, f"no encrypted cell in {table}.{column} to corrupt"
        row_id, stored = row
        head, _, payload = str(stored).rpartition(":")
        blob = bytearray(base64.b64decode(payload))
        blob[-1] ^= 0x01  # the last byte is inside the GCM tag
        conn.execute(
            f"UPDATE {table} SET {column} = ? WHERE id = ?",  # constants
            (f"{head}:{base64.b64encode(bytes(blob)).decode()}", row_id),
        )
        conn.commit()
    finally:
        conn.close()


async def test_verify_pass_failclosed_and_key_mismatch(tmp_path) -> None:
    key_b64 = generate_key()
    store, archive, ss = await _backup(tmp_path, key_b64)

    # PASS with the right key.
    ok = await run_restore_verify(archive, store_settings=ss)
    assert ok.status == "PASS" and ok.integrity_ok is True
    assert ok.row_counts == ok.manifest_counts

    # KEY_MISMATCH with a different key — returned BEFORE any decrypt attempt (not an opaque tag error).
    other = StoreSettings(path="x", encryption_key=generate_key())
    km = await run_restore_verify(archive, store_settings=other)
    assert km.status == "KEY_MISMATCH"
    assert km.integrity_ok is False

    # FAIL on a corrupted archive (a flipped byte inside the ciphertext fails the GCM tag).
    blob = bytearray(Path(archive).read_bytes())
    blob[-40] ^= 0x01
    corrupt = Path(archive).with_suffix(".corrupt.mfbak")
    corrupt.write_bytes(bytes(blob))
    bad = await run_restore_verify(str(corrupt), store_settings=ss)
    assert bad.status == "FAIL"
    await store.close()


async def test_verify_accepts_a_retired_key_after_rotation(tmp_path) -> None:
    # AC-5 "incl. retired keys": a backup taken under key A must still verify PASS after a routine
    # rotation has moved A into encryption_keys_retired and made B the active key — not a false
    # KEY_MISMATCH (which would make ADR 0048's cold-seed activation refuse a recoverable archive).
    key_a = generate_key()
    store, archive, _ = await _backup(tmp_path, key_a)
    await store.close()

    key_b = generate_key()
    rotated = StoreSettings(
        path=str(tmp_path / "msg.db"),
        encryption_key=key_b,  # B is now active
        encryption_keys_retired=key_a,  # A is retired but still decrypt-capable
    )
    res = await run_restore_verify(archive, store_settings=rotated)
    assert res.status == "PASS" and res.integrity_ok is True
    assert res.row_counts == res.manifest_counts

    # A keyring with NEITHER the active nor any retired key matching is still a clean KEY_MISMATCH.
    foreign = StoreSettings(
        path="x", encryption_key=generate_key(), encryption_keys_retired=generate_key()
    )
    km = await run_restore_verify(archive, store_settings=foreign)
    assert km.status == "KEY_MISMATCH"


def _reseal_with_mutated_manifest(
    archive_path: str, key: bytes, out_path: Path, mutate: Callable[[dict[str, object]], None]
) -> None:
    """Decrypt ``archive_path`` under ``key``, apply ``mutate`` to its parsed ``manifest.json`` in
    place, then re-encrypt the resulting tar to ``out_path`` under the SAME key. Every other member
    (``store.db``, any ``config/`` entries) is carried over byte for byte — only the manifest changes.

    This is how BACKLOG #1722's pin proves the row-count compare fires: a real attacker can't get a
    tampered manifest.json past the archive's AES-GCM tag, but an operator restoring last week's
    tape after this week's schema migration, or a truncated snapshot whose write raced the manifest,
    can produce exactly this shape — a well-formed, correctly-keyed archive whose manifest counts
    disagree with what is actually in ``store.db``. The compare has to catch that on its own,
    because nothing else in the verify (the key precheck, the GCM tags, ``PRAGMA integrity_check``)
    looks at logical row counts at all."""
    with tempfile.TemporaryDirectory(prefix="mefor-test-reseal-") as tmp:
        tar_path = Path(tmp) / "archive.tar"
        with open(archive_path, "rb") as src, open(tar_path, "wb") as dst:
            decrypt_stream(src, dst, key)

        with tarfile.open(tar_path, "r:") as tar:
            payload: dict[str, tuple[tarfile.TarInfo, bytes]] = {}
            for member in tar.getmembers():
                fh = tar.extractfile(member)
                payload[member.name] = (member, fh.read() if fh is not None else b"")

        manifest = json.loads(payload[dr_backup._MANIFEST_MEMBER][1])
        assert isinstance(manifest, dict)
        mutate(manifest)
        manifest_bytes = json.dumps(manifest, sort_keys=True).encode("utf-8")

        rewritten_tar = Path(tmp) / "rewritten.tar"
        with tarfile.open(rewritten_tar, "w") as tar:
            for name, (member, data) in payload.items():
                if name == dr_backup._MANIFEST_MEMBER:
                    continue
                info = tarfile.TarInfo(name)
                info.size = len(data)
                info.mtime = member.mtime
                tar.addfile(info, io.BytesIO(data))
            info = tarfile.TarInfo(dr_backup._MANIFEST_MEMBER)
            info.size = len(manifest_bytes)
            tar.addfile(info, io.BytesIO(manifest_bytes))

        with open(rewritten_tar, "rb") as src, open(out_path, "wb") as dst:
            encrypt_stream(src, dst, key)


async def test_verify_fails_when_the_manifest_row_counts_disagree_with_the_snapshot(
    tmp_path,
) -> None:
    """BACKLOG #1722: pin the row-count compare itself. A manifest whose recorded ``messages`` count
    is one higher than the snapshot's real count must FAIL with a "row-count mismatch" reason —
    ``store.db`` is untouched, so the GCM tags authenticate fine and ``PRAGMA integrity_check`` still
    passes; only step (4), the compare this row is about, can catch it.

    Before this test, nothing in the suite could tell a working compare from a disabled one: every
    other test only asserts ``row_counts == manifest_counts`` on a GOOD archive, which holds whether
    or not the compare actually runs."""
    key_b64 = generate_key()
    store, archive, ss = await _backup(tmp_path, key_b64)
    key = base64.b64decode(key_b64)

    def _bump_messages_count(manifest: dict[str, object]) -> None:
        counts = dict(manifest["row_counts"])  # type: ignore[arg-type]
        counts["messages"] = counts.get("messages", 0) + 1
        manifest["row_counts"] = counts

    tampered = tmp_path / "tampered.mfbak"
    _reseal_with_mutated_manifest(archive, key, tampered, _bump_messages_count)

    res = await run_restore_verify(str(tampered), store_settings=ss)
    assert res.status == "FAIL", res.reason
    assert res.integrity_ok is True  # the snapshot itself is fine; only the manifest lied
    assert res.reason is not None and "row-count mismatch" in res.reason
    await store.close()


async def test_verify_passes_when_an_older_manifest_records_only_a_subset_of_tables(
    tmp_path,
) -> None:
    """The reverse of the test above, and the compatibility half of the same fix. Widening
    ``_count_tables`` to every table (from the old fixed four) means a manifest written by an OLDER
    build of this function has fewer keys than a snapshot's schema really has — that is expected, not
    tampering: ``run_restore_verify`` is documented as a standalone check of an archive from any
    earlier point (AC-5), so a narrower older manifest has to keep verifying PASS.

    Simulated by re-sealing a good archive with its manifest cut down to the OLD four-table shape
    (``messages``/``queue``/``message_events``/``audit_log``), values unchanged — the shape an
    archive taken before BACKLOG #1722 actually has."""
    key_b64 = generate_key()
    store, archive, ss = await _backup(tmp_path, key_b64)
    key = base64.b64decode(key_b64)

    def _shrink_to_the_old_four_tables(manifest: dict[str, object]) -> None:
        counts = dict(manifest["row_counts"])  # type: ignore[arg-type]
        old_style = {
            table: counts[table]
            for table in ("messages", "queue", "message_events", "audit_log")
            if table in counts
        }
        manifest["row_counts"] = old_style

    older = tmp_path / "older-shape.mfbak"
    _reseal_with_mutated_manifest(archive, key, older, _shrink_to_the_old_four_tables)

    res = await run_restore_verify(str(older), store_settings=ss)
    assert res.status == "PASS", res.reason
    await store.close()


async def test_verify_fails_when_the_manifest_expects_a_table_the_snapshot_does_not_have(
    tmp_path,
) -> None:
    """A manifest tracking a table with a NONZERO count that the snapshot's schema does not have at
    all is real data loss (the table existed when the archive was made and does not now), not a
    build-boundary artifact — it must still FAIL. ``_count_tables`` reports an absent table as 0 (the
    same convention the old fixed-list version used), so the compare treats a missing-with-count-0
    entry as agreement and a missing-with-nonzero-count entry as the mismatch it is."""
    key_b64 = generate_key()
    store, archive, ss = await _backup(tmp_path, key_b64)
    key = base64.b64decode(key_b64)

    def _add_a_phantom_table(manifest: dict[str, object]) -> None:
        counts = dict(manifest["row_counts"])  # type: ignore[arg-type]
        counts["a_table_this_snapshot_does_not_have"] = 3
        manifest["row_counts"] = counts

    tampered = tmp_path / "phantom-table.mfbak"
    _reseal_with_mutated_manifest(archive, key, tampered, _add_a_phantom_table)

    res = await run_restore_verify(str(tampered), store_settings=ss)
    assert res.status == "FAIL", res.reason
    assert res.reason is not None and "row-count mismatch" in res.reason
    await store.close()


async def test_full_restore_verify_opens_through_open_store(tmp_path) -> None:
    key_b64 = generate_key()
    store, archive, ss = await _backup(tmp_path, key_b64)
    res = await run_restore_verify(archive, store_settings=ss, full=True)
    assert res.status == "PASS" and res.integrity_ok is True
    await store.close()


# --- AC-13: the FULL verify opens the snapshot under the LIVE store settings --------------------


async def test_full_verify_passes_on_a_good_encrypted_archive(tmp_path) -> None:
    """The regression this fix exists for. A good ENCRYPTED archive must verify PASS under ``full``, and
    the PASS must be the strong claim: the snapshot's cipher-covered cells were opened and authenticated
    under the live keyring. Building a bare ``StoreSettings`` for the open cannot satisfy both halves —
    it opens keyless, so either the decrypt pass fails the archive or there is no decrypt pass at all."""
    key_b64 = generate_key()
    store, archive, ss = await _backup(tmp_path, key_b64)

    res = await run_restore_verify(archive, store_settings=ss, full=True)
    assert res.status == "PASS", res.reason
    assert res.integrity_ok is True
    assert res.decrypted_cells >= 1, "a full verify that decrypted nothing proves nothing"
    await store.close()


async def test_full_verify_fails_on_a_corrupted_aead_cell(tmp_path) -> None:
    """A bit-flipped AEAD cell in the snapshot must be FAIL. It survives ``PRAGMA quick_check`` and the
    manifest row counts untouched, so only decrypting the cell catches it."""
    key_b64 = generate_key()
    db = tmp_path / "msg.db"
    store = await MessageStore.open(db, cipher=make_cipher(key_b64))
    await store.enqueue_message(
        channel_id="c1",
        raw="MSH|^~\\&|x",
        deliveries=[("d1", "OUT|y")],
        control_id="CID-1",
        now=1.0,
    )
    await store.close()
    _flip_one_aead_byte(db, "messages", "raw")

    store = await MessageStore.open(db, cipher=make_cipher(key_b64))
    ss = StoreSettings(path=str(db), encryption_key=key_b64)
    runner = BackupRunner(
        store,
        BackupSettings(enabled=True, destination=str(tmp_path / "b")),
        store_settings=ss,
        config_dir=None,
    )
    result = await runner.run_once(now=1.0)
    assert result is not None
    await store.close()

    # The lightweight verify is blind to it by design — it never opens a cell.
    light = await run_restore_verify(result.archive_path, store_settings=ss)
    assert light.status == "PASS"

    res = await run_restore_verify(result.archive_path, store_settings=ss, full=True)
    assert res.status == "FAIL"
    assert "messages.raw" in (res.reason or "") and "did not decrypt" in (res.reason or "")


def test_full_verify_fails_when_the_snapshot_opens_without_its_key(tmp_path) -> None:
    """A keyless open of an ENCRYPTED snapshot is KEY_MISMATCH; a wrong-key one is FAIL. Both name the
    real cause, and the split is the point: with no key resolved nothing could have opened the cells, so
    the operator's key configuration is at fault and the archive is fine. A keyring that DOES hold keys
    and still cannot open a cell is indistinguishable from bit rot, so it keeps the harder verdict.

    This calls the blocking verify directly because that is the only way to reach the shipped defect's
    shape: the codec key is in hand (the archive itself decrypts fine), while the settings threaded into
    the full open resolve no key — which is what a bare ``StoreSettings(path=...)`` did. The snapshot
    then opens under the identity cipher, its PHI cells stay sealed, and a PASS there would be false.

    Synchronous on purpose: ``_verify_archive_blocking`` runs ``asyncio.run`` for the full open, so it
    needs a thread with no loop of its own — which is how the engine calls it (``asyncio.to_thread``)."""
    import asyncio

    key_b64 = generate_key()

    async def _setup() -> str:
        store, archive, _ = await _backup(tmp_path, key_b64)
        await store.close()
        return archive

    archive = asyncio.run(_setup())
    codec_key = base64.b64decode(key_b64)

    keyless = _verify_archive_blocking(
        archive_path=archive,
        keys=[codec_key],
        full=True,
        store_settings=StoreSettings(path="unused"),
    )
    assert keyless.status == "KEY_MISMATCH"
    assert "keyless open" in (keyless.reason or ""), keyless.reason

    wrong = _verify_archive_blocking(
        archive_path=archive,
        keys=[codec_key],
        full=True,
        store_settings=StoreSettings(path="unused", encryption_key=generate_key()),
    )
    assert wrong.status == "FAIL"
    assert "did not decrypt" in (wrong.reason or ""), wrong.reason

    # And with no settings at all the full verify refuses rather than falling back to a keyless open.
    absent = _verify_archive_blocking(archive_path=archive, keys=[codec_key], full=True)
    assert absent.status == "FAIL"
    assert "no live store settings" in (absent.reason or ""), absent.reason


async def _state_and_reference_store(db: Path, key_b64: str) -> MessageStore:
    """A keyed store carrying a transform-``state`` row and a ``reference`` snapshot as well as a
    message. Both tables are warmed EAGERLY by ``MessageStore.open`` and both decrypt through the
    fail-closed helper, so they are what turns a keyless open from a false PASS into a hard raise."""
    store = await MessageStore.open(db, cipher=make_cipher(key_b64))
    mid = await store.enqueue_ingress(channel_id="IB", raw="MSH|^~\\&|x")
    ingress = await store.claim_next_fifo("IB", stage=Stage.INGRESS.value)
    assert ingress is not None
    await store.route_handoff(
        ingress_id=ingress.id,
        message_id=mid,
        channel_id="IB",
        handlers=[("H", "MSH|^~\\&|x")],
        disposition=MessageStatus.ROUTED,
    )
    routed = await store.claim_next_fifo("IB", stage=Stage.ROUTED.value)
    assert routed is not None
    await store.transform_handoff(
        routed_id=routed.id,
        message_id=mid,
        channel_id="IB",
        deliveries=[("d1", "OUT|y")],
        state_ops=[("ns", "k", {"seq": 7})],
    )
    await store.write_reference_snapshot(name="prov", version="1", rows={"NPI1": "Dr Who"})
    return store


async def test_full_verify_passes_on_a_snapshot_holding_state_and_reference_rows(tmp_path) -> None:
    """A good encrypted archive that holds transform state must verify PASS — the half of the shipped
    defect that failed in the opposite direction.

    ``MessageStore.open`` warms the ``state`` and ``reference`` caches eagerly and both decrypt through
    the fail-closed ``decrypt_json_cell`` helper, so opening this snapshot keyless does not merely prove
    too little: it RAISES ``StoreKeylessError``. Under the shipped code every scheduled backup of a keyed
    store that had ever written state failed its own verify, with the missing key reported as a bad
    archive."""
    key_b64 = generate_key()
    db = tmp_path / "msg.db"
    store = await _state_and_reference_store(db, key_b64)
    ss = StoreSettings(path=str(db), encryption_key=key_b64)
    runner = BackupRunner(
        store,
        BackupSettings(enabled=True, destination=str(tmp_path / "b")),
        store_settings=ss,
        config_dir=None,
    )
    result = await runner.run_once(now=1.0)
    assert result is not None
    await store.close()

    res = await run_restore_verify(result.archive_path, store_settings=ss, full=True)
    assert res.status == "PASS", res.reason
    assert res.decrypted_cells >= 1


def test_full_verify_passes_on_an_archive_written_under_a_since_retired_key(tmp_path) -> None:
    """AC-5 "incl. retired keys", under ``full``. Rows are sealed under key A and backed up. A routine
    rotation then makes B active and moves A to ``encryption_keys_retired``. The full verify must still
    PASS. Every sealed cell in this snapshot was written under A, so the decrypt pass can count a cell
    only by using A from the keyring the full open inherits.

    The light-verify twin above proves the archive-key precheck finds A. The full verify needs A in a
    second place: the store it opens over the snapshot. The contrast arm shows that second place on its
    own. It hands the verify the archive key, so the precheck passes, but leaves A out of the store
    settings. The store's eager ``state`` warm-up then cannot open its cell, and the verdict turns.

    The settings name a live path that does not exist, and the test checks it still does not exist
    afterwards. A full verify that opened the configured path instead of the snapshot would create it.

    Synchronous for the same reason as the keyless test above: ``_verify_archive_blocking`` runs its own
    loop for the full open."""
    import asyncio

    key_a = generate_key()
    db = tmp_path / "msg.db"

    async def _setup() -> str:
        store = await _state_and_reference_store(db, key_a)
        try:
            runner = BackupRunner(
                store,
                BackupSettings(enabled=True, destination=str(tmp_path / "b")),
                store_settings=StoreSettings(path=str(db), encryption_key=key_a),
                config_dir=None,
            )
            result = await runner.run_once(now=1.0)
        finally:
            await store.close()
        assert result is not None
        return result.archive_path

    archive = asyncio.run(_setup())

    live = tmp_path / "live-after-rotation.db"  # never created; the verify must not create it
    key_b = generate_key()
    rotated = StoreSettings(
        path=str(live),
        encryption_key=key_b,  # B is now active
        encryption_keys_retired=key_a,  # A is retired but still decrypt-capable
    )
    res = asyncio.run(run_restore_verify(archive, store_settings=rotated, full=True))
    assert res.status == "PASS", res.reason
    assert res.integrity_ok is True
    assert res.row_counts == res.manifest_counts
    assert res.decrypted_cells >= 1, "a full verify that decrypted nothing proves nothing"
    assert not live.exists(), "the full verify opened the configured path, not the snapshot"

    # Contrast arm. This split (archive key in hand, store settings without it) is the shipped defect's
    # shape, reached through the blocking call as in the keyless test above.
    without_a = _verify_archive_blocking(
        archive_path=archive,
        keys=[base64.b64decode(key_a)],
        full=True,
        store_settings=StoreSettings(path=str(live), encryption_key=key_b),
    )
    # FAIL rather than KEY_MISMATCH: the keyring holds a key, so a cell it cannot open is
    # indistinguishable from corruption (see _full_open_check).
    assert without_a.status == "FAIL", without_a.reason
    # The precheck, the archive decrypt, the integrity check and the row counts all passed, so the full
    # leg alone turned the verdict.
    assert without_a.integrity_ok is True
    assert without_a.row_counts == without_a.manifest_counts
    reason = without_a.reason or ""
    assert reason.startswith("full restore-verify:") and "CipherError" in reason, reason
    assert not live.exists()


def test_full_verify_on_a_failed_open_reports_the_open_error_not_a_cleanup_error(tmp_path) -> None:
    """A full open that FAILS must report why it failed. The snapshot lives in a temp directory the
    verify unwinds on the way out, and ``MessageStore.open`` used to leave its aiosqlite handle open
    when a warm-up raised — on Windows that handle holds the file, the unlink is refused, and the
    ``PermissionError`` from the cleanup REPLACES the missing-key error one frame up. The operator then
    reads a file-locking complaint about a temp path that no longer exists.

    A ``state`` row is what makes this reachable: it is the eager warm-up that raises. Synchronous for
    the same reason as the keyless test above — the full open runs its own loop."""
    import asyncio

    key_b64 = generate_key()
    db = tmp_path / "msg.db"

    async def _setup() -> str:
        store = await _state_and_reference_store(db, key_b64)
        ss = StoreSettings(path=str(db), encryption_key=key_b64)
        runner = BackupRunner(
            store,
            BackupSettings(enabled=True, destination=str(tmp_path / "b")),
            store_settings=ss,
            config_dir=None,
        )
        result = await runner.run_once(now=1.0)
        assert result is not None
        await store.close()
        return result.archive_path

    archive = asyncio.run(_setup())

    res = _verify_archive_blocking(
        archive_path=archive,
        keys=[
            base64.b64decode(key_b64)
        ],  # the ARCHIVE decrypts; only the store settings are keyless
        full=True,
        store_settings=StoreSettings(path="unused"),
    )
    assert res.status == "KEY_MISMATCH", res.reason
    reason = res.reason or ""
    assert "encryption key" in reason, reason
    # The negative half, and the point of the test: no leaked handle, so no cleanup error over the top.
    assert "another process" not in reason and "WinError" not in reason, reason


async def test_full_verify_passes_on_a_good_unencrypted_archive(tmp_path) -> None:
    """A no-key (synthetic / no-PHI) instance still verifies PASS under ``full``. Nothing is sealed, so
    the decrypt pass has nothing to open and reports zero cells — a PASS that claims exactly that."""
    store, archive, ss = await _backup(tmp_path, None, allow_unencrypted=True)
    res = await run_restore_verify(archive, store_settings=ss, full=True, allow_unencrypted=True)
    assert res.status == "PASS", res.reason
    assert res.integrity_ok is True
    assert res.decrypted_cells == 0
    await store.close()


async def test_verify_missing_archive_is_reported(tmp_path) -> None:
    ss = StoreSettings(path=str(tmp_path / "msg.db"), encryption_key=generate_key())
    res = await run_restore_verify(str(tmp_path / "nope.mfbak"), store_settings=ss)
    assert res.status == "FAIL"


async def test_cumulative_plaintext_cap_stops_a_restore_that_would_fill_the_temp_dir(
    tmp_path, monkeypatch
) -> None:
    """The decrypt is what consumes the extract temp dir, and the per-member cap fires only after it.

    ``_extract_member`` bounds ``store.db``, but it reads ``archive.tar`` — which the decrypt has by
    then written to the same temp dir in full. So the cumulative ceiling has to be enforced at the
    decrypt, and this pins that it is: with the ceiling set below the archive's plaintext, the verify
    refuses. POST-AUTHENTICATION — every counted byte passed its GCM tag first; this is a resource
    bound on a legitimately-keyed archive, not a defence against an unauthenticated attacker.

    The control is not a sibling assertion here but every PASS test in this module: they all now run
    with the real ceiling in force, so a cap that refused ordinary archives would red them, and the
    refusal below is the cap firing rather than the cap breaking the restore path.
    """
    key_b64 = generate_key()
    store, archive, ss = await _backup(tmp_path, key_b64)

    monkeypatch.setattr(dr_backup, "_MAX_RESTORE_PLAINTEXT_BYTES", 2048)
    res = await run_restore_verify(archive, store_settings=ss)
    # Lands on the EXISTING codec arm — a FAIL reading "decrypt failed: ...", not a new status and not
    # a KEY_MISMATCH (the key matched; the archive was simply over the ceiling).
    assert res.status == "FAIL", res.reason
    assert res.reason is not None and "plaintext ceiling" in res.reason
    assert res.integrity_ok is False
    await store.close()


def test_cumulative_ceiling_stays_above_the_per_member_ceiling() -> None:
    """The off-by-one the docstring claims. A ``store.db`` at exactly the per-member cap is legal — the
    extract admits it — so a cumulative ceiling at or below that cap would refuse an archive this build
    is supposed to restore. The tar also carries the config bundle, the manifest and framing, so the
    cumulative ceiling must sit strictly above the member one. Pinned because the two constants are
    edited independently."""
    assert dr_backup._MAX_RESTORE_PLAINTEXT_BYTES > dr_backup._MAX_RESTORE_MEMBER_BYTES
