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
import sqlite3
from pathlib import Path

from messagefoundry.config.settings import BackupSettings, StoreSettings
from messagefoundry.pipeline.dr_backup import (
    BackupRunner,
    _verify_archive_blocking,
    run_restore_verify,
)
from messagefoundry.store import MessageStore
from messagefoundry.store.crypto import generate_key, make_cipher


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
    """A keyless or wrong-key open of an ENCRYPTED snapshot is FAIL, with the real cause named.

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
    assert keyless.status == "FAIL"
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
