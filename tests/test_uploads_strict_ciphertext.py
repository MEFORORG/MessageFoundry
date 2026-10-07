# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A keyed store refuses a plaintext upload until ``rotate-key`` seals it (BACKLOG #1169, ASVS 11.3.3).

**The owner ruling, 2026-09-23.** When a site first enables a key, uploads already stored as plaintext
are REFUSED until an operator runs ``rotate-key``, which reseals them. The engine does not reseal them
at startup, because that is unbounded boot-time work. It is fail-closed, like the DR backup surface.

**What each test pins.**

* On a keyed AES-GCM store, a plaintext upload is refused on every read path, and the refusal
  reaches the ``upload-cipher`` alert naming only the upload surface.
* The prune and the quota refuse it too. That is a named residual (it is outside retention until
  sealed), and the alternative let a planted sidecar delete another upload.
* ``rotate-key`` seals it, and it then reads normally. The CLI reports how many it sealed.
* ``[store].allow_unmarked_ciphertext`` restores the passthrough for uploads too.
* A keyless store is unchanged.
* ``serve`` logs the COUNT of plaintext uploads at startup, with the instruction, and no filename.
* Under ``vault_transit`` the passthrough stays, because no command can reseal there. That is a named
  residual in ``docs/PHI.md``, and a test pins it so a change to it is deliberate.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import time
from collections.abc import Callable
from pathlib import Path

import pytest

from messagefoundry.config.settings import EgressSettings
from messagefoundry.pipeline.alerts import (
    STORE_CIPHER_SUBJECT,
    UPLOAD_CIPHER_SUBJECT,
    UPLOADED_FILE_TABLE,
    alert_store_cipher_refusal,
)
from messagefoundry.store.crypto import (
    MARKER_PREFIX,
    UPLOADED_FILE_AAD_TABLE,
    AesGcmCipher,
    CipherError,
    generate_key,
    make_cipher,
)
from messagefoundry.store.crypto_transit import TransitCipher
from messagefoundry.uploads import (
    ResealResult,
    UploadNotFoundError,
    UploadQuotaError,
    UploadStore,
)

_ADT = "MSH|^~\\&|A|B|C|D|202601011200||ADT^A01|MSGID1|P|2.5\rPID|1||MRN123^^^HOSP||DOE^JOHN\r"
# A filename that would be PHI if it leaked into a log or an alert.
_PHI_NAME = "DOE_JOHN_MRN123.hl7"


def _keyed(key: str, *, allow_unmarked: bool = False) -> AesGcmCipher:
    cipher = make_cipher(key, write_v2=True, allow_unmarked=allow_unmarked)
    assert isinstance(cipher, AesGcmCipher)
    return cipher


async def _plaintext_upload(root: Path) -> str:
    """Write one upload with NO key, as a site does before it first enables one."""
    meta = await UploadStore(root, make_cipher(None), max_bytes=1 << 20).save(
        data=_ADT.encode(), filename=_PHI_NAME, uploader="op", uploader_id="u-op"
    )
    return meta.file_id


def _counts(caplog: pytest.LogCaptureFixture) -> list[str]:
    """The startup-count lines only. A refused read logs its own warnings, from the cipher and from
    the listing scan, and those are not what these tests are about."""
    return [
        r.getMessage()
        for r in caplog.records
        if r.name == "messagefoundry.uploads" and "stored as plaintext" in r.getMessage()
    ]


class _Sink:
    def __init__(self) -> None:
        self.events: list[tuple[str, str, int]] = []

    def integrity_drift(self, name: str, *, reason: str, drift_count: int) -> None:
        self.events.append((name, reason, drift_count))


# --- the refusal --------------------------------------------------------------------------------


async def test_a_plaintext_upload_is_refused_on_a_keyed_store(tmp_path: Path) -> None:
    root = tmp_path / "uploads"
    fid = await _plaintext_upload(root)
    cipher = _keyed(generate_key())
    cells: list[tuple[str, str]] = []
    cipher.set_refusal_hook(lambda table, column: cells.append((table, column)))
    store = UploadStore(root, cipher, max_bytes=1 << 20)

    with pytest.raises(CipherError):
        await store.get_meta(fid)
    with pytest.raises(CipherError):
        await store.read_bytes(fid)
    with pytest.raises(CipherError):
        await store.delete(fid)
    # The listing skips it rather than serve it, and a refusal never deletes.
    assert await store.list_files() == []
    assert (root / f"{fid}.meta").exists()
    # The refusal names the fix, not the loosening.
    with pytest.raises(CipherError, match="rotate-key"):
        await store.read_bytes(fid)

    # Each refusal reached the hook, naming only the upload surface.
    assert set(cells) == {(UPLOADED_FILE_TABLE, "meta"), (UPLOADED_FILE_TABLE, "body")}
    assert all(fid not in f"{t}.{c}" for t, c in cells)


def test_the_alert_and_the_cipher_spell_the_upload_table_the_same() -> None:
    assert UPLOADED_FILE_TABLE == UPLOADED_FILE_AAD_TABLE


def test_the_upload_alert_names_the_surface_and_the_fix_and_nothing_else() -> None:
    sink = _Sink()
    alert_store_cipher_refusal(sink, UPLOADED_FILE_TABLE, "meta")  # type: ignore[arg-type]
    [(subject, reason, count)] = sink.events
    # Its own subject, so expected upload refusals cannot throttle or mute a planted store row.
    assert (subject, count) == (UPLOAD_CIPHER_SUBJECT, 1)
    assert UPLOAD_CIPHER_SUBJECT != STORE_CIPHER_SUBJECT
    assert "uploaded_file.meta" in reason and "rotate-key" in reason
    # A store column keeps its own subject and wording: there, plaintext is never legitimate.
    alert_store_cipher_refusal(sink, "messages", "raw")  # type: ignore[arg-type]
    assert sink.events[1][0] == STORE_CIPHER_SUBJECT
    assert "rotate-key" not in sink.events[1][1]


async def test_a_refused_upload_is_outside_retention_until_sealed(tmp_path: Path) -> None:
    """The named residual, pinned so a change to it is deliberate. The prune refuses a plaintext
    sidecar just as a read does, so a legacy upload is not aged out until ``rotate-key`` seals it.
    The startup count is what tells the operator to run it."""
    root = tmp_path / "uploads"
    legacy = await _plaintext_upload(root)
    store = UploadStore(root, _keyed(generate_key()), max_bytes=1 << 20)
    assert (await store.prune_expired(now=10**12)).pruned == []
    assert (root / f"{legacy}.meta").exists() and (root / f"{legacy}.blob").exists()
    await store.reseal_to_active()
    assert [m.file_id for m in (await store.prune_expired(now=10**12)).pruned] == [legacy]


async def test_the_prune_never_deletes_a_file_a_plant_names(tmp_path: Path) -> None:
    """Why the prune refuses a plaintext sidecar rather than trusting it (review round 2).

    A plaintext sidecar is not bound to its path, so its JSON ``file_id`` can name a DIFFERENT,
    sealed upload. A prune that trusted it would delete that upload on every pass and write
    attacker-chosen names into the audit. Here a fresh sealed upload named by a planted, aged
    sidecar must survive."""
    import json

    root = tmp_path / "uploads"
    store = UploadStore(root, _keyed(generate_key()), max_bytes=1 << 20, retention_days=30)
    victim = await store.save(
        data=_ADT.encode(), filename="v.hl7", uploader="op", uploader_id="u-op"
    )
    (root / f"{'e' * 32}.meta").write_text(
        json.dumps({"file_id": victim.file_id, "uploader": "x", "uploaded_at": 0.0}),
        encoding="utf-8",
    )
    assert (await store.prune_expired()).pruned == []
    assert (await store.read_bytes(victim.file_id)).decode() == _ADT


# --- rotate-key seals it, then it reads ----------------------------------------------------------


def test_rotate_key_seals_a_refused_upload_and_it_reads_again(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The full cycle: no key, enable a key, refused, run ``rotate-key``, readable."""
    from messagefoundry.__main__ import main
    from messagefoundry.store.store import MessageStore

    monkeypatch.chdir(tmp_path)
    db, root = tmp_path / "cycle.db", tmp_path / "uploads"

    async def seed() -> str:
        store = await MessageStore.open(db)  # keyless, as before the key is enabled
        try:
            await store.enqueue_ingress(channel_id="c", raw=_ADT)
        finally:
            await store.close()
        return await _plaintext_upload(root)

    fid = asyncio.run(seed())
    key = generate_key()

    # Enable the key: the upload is now refused.
    with pytest.raises(CipherError):
        asyncio.run(UploadStore(root, _keyed(key), max_bytes=1 << 20).read_bytes(fid))

    monkeypatch.setenv("MEFOR_STORE_ENCRYPTION_KEY", key)
    monkeypatch.setenv("MEFOR_STORE_UPLOADS_DIR", str(root))
    assert main(["rotate-key", "--db", str(db)]) == 0
    out = capsys.readouterr().out
    assert "sealed 1 plaintext uploaded file(s)" in out
    assert _PHI_NAME not in out

    for suffix in (".meta", ".blob"):
        assert (root / f"{fid}{suffix}").read_text(encoding="utf-8").startswith(MARKER_PREFIX)
    readback = UploadStore(root, _keyed(key), max_bytes=1 << 20)
    assert asyncio.run(readback.read_bytes(fid)).decode() == _ADT
    assert asyncio.run(readback.get_meta(fid)).filename == _PHI_NAME


async def test_the_reseal_counts_uploads_not_values(tmp_path: Path) -> None:
    """One upload is two values; the count the operator compares must be one."""
    root = tmp_path / "uploads"
    await _plaintext_upload(root)
    result = await UploadStore(root, _keyed(generate_key()), max_bytes=1 << 20).reseal_to_active()
    assert result == ResealResult(resealed=2, skipped=0, sealed_plaintext=1)


def test_rotate_key_with_the_same_key_does_not_reset_the_key_age_clock(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The refusal makes ``rotate-key`` the fix for plaintext uploads, and an operator runs it with
    the SAME key. It used to stamp ``last_rotated`` = today on every run, which would make an old key
    look freshly rotated to the ASVS 13.3.4 watcher. A changed key still gets its stamp."""
    from messagefoundry.__main__ import main
    from messagefoundry.store.store import MessageStore

    monkeypatch.chdir(tmp_path)
    db = tmp_path / "stamp.db"
    key = generate_key()

    async def seed_and_backdate() -> None:
        store = await MessageStore.open(db, cipher=make_cipher(key))
        try:
            key_id = store.cipher_info().active_key_id
            assert key_id
            await store.upsert_secret_rotation_meta(
                "MEFOR_STORE_ENCRYPTION_KEY",
                fingerprint=key_id,
                tracked_since="2025-01-01",
                last_rotated="2025-01-01",
            )
        finally:
            await store.close()

    async def stamp(active: str) -> tuple[str, str]:
        store = await MessageStore.open(db, cipher=make_cipher(active))
        try:
            row = (await store.get_secret_rotation_meta())["MEFOR_STORE_ENCRYPTION_KEY"]
            return row.fingerprint, row.last_rotated
        finally:
            await store.close()

    asyncio.run(seed_and_backdate())
    monkeypatch.setenv("MEFOR_STORE_ENCRYPTION_KEY", key)
    assert main(["rotate-key", "--db", str(db)]) == 0
    assert asyncio.run(stamp(key))[1] == "2025-01-01"  # same key: the clock is untouched

    # Control: a real rotation still stamps.
    new_key = generate_key()
    monkeypatch.setenv("MEFOR_STORE_ENCRYPTION_KEY", new_key)
    monkeypatch.setenv("MEFOR_STORE_ENCRYPTION_KEYS_RETIRED", key)
    assert main(["rotate-key", "--db", str(db)]) == 0
    assert asyncio.run(stamp(new_key))[1] != "2025-01-01"


# --- the opt-out and the keyless store ------------------------------------------------------------


async def test_the_opt_out_restores_the_upload_passthrough(tmp_path: Path) -> None:
    root = tmp_path / "uploads"
    fid = await _plaintext_upload(root)
    store = UploadStore(root, _keyed(generate_key(), allow_unmarked=True), max_bytes=1 << 20)
    assert (await store.get_meta(fid)).filename == _PHI_NAME
    assert (await store.read_bytes(fid)).decode() == _ADT
    assert [m.file_id for m in await store.list_files()] == [fid]


async def test_a_keyless_store_is_unchanged(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    root = tmp_path / "uploads"
    fid = await _plaintext_upload(root)
    store = UploadStore(root, make_cipher(None), max_bytes=1 << 20)
    assert (await store.read_bytes(fid)).decode() == _ADT
    with caplog.at_level(logging.WARNING, logger="messagefoundry.uploads"):
        assert await store.warn_if_unsealed() == 0
    assert _counts(caplog) == []


# --- the startup count ----------------------------------------------------------------------------


async def test_the_startup_warning_logs_the_count_and_never_a_filename(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    root = tmp_path / "uploads"
    await _plaintext_upload(root)
    await _plaintext_upload(root)
    key = generate_key()
    store = UploadStore(root, _keyed(key), max_bytes=1 << 20)
    await store.save(data=_ADT.encode(), filename="sealed.hl7", uploader="op", uploader_id="u-op")

    with caplog.at_level(logging.WARNING, logger="messagefoundry.uploads"):
        assert await store.warn_if_unsealed() == 2  # the sealed one is not counted
    [line] = _counts(caplog)
    assert "2 uploaded file(s)" in line and "rotate-key" in line and "refused" in line
    assert _PHI_NAME not in line and "MRN123" not in line

    # After the reseal there is nothing left to warn about.
    await store.reseal_to_active()
    caplog.clear()
    with caplog.at_level(logging.WARNING, logger="messagefoundry.uploads"):
        assert await store.warn_if_unsealed() == 0
    assert _counts(caplog) == []


async def test_the_startup_warning_says_served_under_the_opt_out(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    root = tmp_path / "uploads"
    await _plaintext_upload(root)
    store = UploadStore(root, _keyed(generate_key(), allow_unmarked=True), max_bytes=1 << 20)
    with caplog.at_level(logging.WARNING, logger="messagefoundry.uploads"):
        assert await store.warn_if_unsealed() == 1
    [line] = _counts(caplog)
    assert "allow_unmarked_ciphertext" in line


def test_serve_logs_the_startup_count(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """The count is only useful if the serve path actually calls it."""
    pytest.importorskip("psutil")
    from fastapi.testclient import TestClient

    from messagefoundry.api import create_managed_app
    from messagefoundry.config.settings import StoreSettings

    root = tmp_path / "uploads"
    asyncio.run(_plaintext_upload(root))
    app = create_managed_app(
        store_settings=StoreSettings(
            path=str(tmp_path / "serve.db"), encryption_key=generate_key(), uploads_dir=str(root)
        ),
        poll_interval=0.05,
        egress_settings=EgressSettings(deny_by_default=False),
    )
    with caplog.at_level(logging.WARNING, logger="messagefoundry.uploads"), TestClient(app):
        pass
    [line] = _counts(caplog)
    assert "1 uploaded file(s)" in line and "rotate-key" in line


# --- vault_transit: the named residual ------------------------------------------------------------


async def test_vault_transit_keeps_the_upload_passthrough(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """``rotate-key`` refuses to run in ``vault_transit`` mode, so nothing could ever seal a plaintext
    upload there. Refusing it would strand the file for good, so the passthrough stays. Unmarked
    decrypts never reach Vault, so no client is needed."""
    root = tmp_path / "uploads"
    fid = await _plaintext_upload(root)
    cipher = TransitCipher(None, "mefor-store")
    # Control: the transit cipher itself still refuses an unmarked store value. The passthrough is
    # the upload store's decision, not a gap in the cipher.
    with pytest.raises(CipherError):
        cipher.decrypt("plaintext")
    store = UploadStore(root, cipher, max_bytes=1 << 20)
    assert (await store.read_bytes(fid)).decode() == _ADT
    assert await store.reseal_to_active() == ResealResult()
    with caplog.at_level(logging.WARNING, logger="messagefoundry.uploads"):
        assert await store.warn_if_unsealed() == 0
    assert _counts(caplog) == []


# --- an upload rotate-key can never seal stays inside retention (BACKLOG #2322, PR 2102 repair) ---


def _garble(path: Path) -> None:
    path.write_bytes(b"\xff\xfe not utf-8")


def _remove(path: Path) -> None:
    path.unlink()


_BREAKS = pytest.mark.parametrize("break_body", [_remove, _garble], ids=["missing", "undecodable"])
_DAY = 86_400


async def _unsealable_upload(root: Path, break_body: Callable[[Path], None]) -> str:
    """A plaintext upload whose body is then lost: the shape ``rotate-key`` holds back for good."""
    fid = await _plaintext_upload(root)
    break_body(root / f"{fid}.blob")
    return fid


def _age(root: Path, fid: str, days: float) -> None:
    """Set the sidecar's mtime ``days`` in the past (negative: in the future)."""
    when = time.time() - days * _DAY
    os.utime(root / f"{fid}.meta", (when, when))


def _files(root: Path) -> list[str]:
    return sorted(p.name for p in root.iterdir())


@_BREAKS
async def test_an_unsealable_upload_is_pruned_at_expiry(
    tmp_path: Path, break_body: Callable[[Path], None]
) -> None:
    """Both files go once the sidecar's mtime passes the window, and not before. The reseal holds it
    back on every run, so without this it sat on disk forever, the damaged body included."""
    root = tmp_path / "uploads"
    fid = await _unsealable_upload(root, break_body)
    store = UploadStore(root, _keyed(generate_key()), max_bytes=1 << 20, retention_days=30)
    assert await store.reseal_to_active() == ResealResult(unsealable=1)

    _age(root, fid, 29)
    assert (await store.prune_expired()).pruned == []
    assert f"{fid}.meta" in _files(root)

    _age(root, fid, 31)
    result = await store.prune_expired()
    assert _files(root) == []
    if break_body is _garble:
        # The body was removed, so the pass reports it. The owner is unverified, so it is blank.
        [meta] = result.pruned
        assert (meta.file_id, meta.uploader, meta.uploader_id, meta.filename) == (fid, "", "", "")
    else:
        assert result.pruned == []  # no body to remove, so no row, as for any body-less pair


@_BREAKS
async def test_an_unsealable_upload_is_removed_by_delete(
    tmp_path: Path, break_body: Callable[[Path], None]
) -> None:
    root = tmp_path / "uploads"
    fid = await _unsealable_upload(root, break_body)
    store = UploadStore(root, _keyed(generate_key()), max_bytes=1 << 20)
    meta = await store.delete(fid)
    assert (meta.file_id, meta.uploader_id, meta.filename) == (fid, "", "")
    assert _files(root) == []
    with pytest.raises(UploadNotFoundError):
        await store.get_meta(fid)


@_BREAKS
async def test_an_unsealable_upload_counts_toward_the_quota_and_is_never_listed(
    tmp_path: Path, break_body: Callable[[Path], None], caplog: pytest.LogCaptureFixture
) -> None:
    """It bills the uploader its sidecar names, at the body's size on disk. It is never listed, since
    the listing has no way to mark an upload unreadable. The startup warning counts it on a line of
    its own, which does not send the operator to rotate-key."""
    root = tmp_path / "uploads"
    fid = await _unsealable_upload(root, break_body)
    store = UploadStore(root, _keyed(generate_key()), max_bytes=1 << 20, max_files_per_user=1)

    on_disk = (root / f"{fid}.blob").stat().st_size if break_body is _garble else 0
    assert store._observed_sync("u-op") == (1, on_disk)
    with pytest.raises(UploadQuotaError):
        await store.save(data=_ADT.encode(), filename="b.hl7", uploader="op", uploader_id="u-op")
    assert await store.list_files() == []

    with caplog.at_level(logging.WARNING, logger="messagefoundry.uploads"):
        assert await store.warn_if_unsealed() == 0  # nothing rotate-key would seal
    assert _counts(caplog) == []
    [line] = [r.getMessage() for r in caplog.records if "rotate-key cannot seal" in r.getMessage()]
    assert "1 uploaded file(s)" in line and _PHI_NAME not in line


async def test_a_planted_lone_sidecar_is_never_sealed_and_ages_out(tmp_path: Path) -> None:
    """The cheapest plant: one hand-written sidecar naming another upload and a victim's quota.

    It is never sealed or listed. Its negative size is ignored. The prune removes its OWN path,
    never the id its JSON names, and a plant dated into the future is treated as expired rather
    than kept forever."""
    root = tmp_path / "uploads"
    store = UploadStore(root, _keyed(generate_key()), max_bytes=1 << 20, retention_days=30)
    victim = await store.save(
        data=_ADT.encode(), filename="v.hl7", uploader="op", uploader_id="u-op"
    )
    plant = "e" * 32
    (root / f"{plant}.meta").write_text(
        json.dumps({"file_id": victim.file_id, "uploader_id": "u-op", "size": -(10**9)}),
        encoding="utf-8",
    )
    assert await store.reseal_to_active() == ResealResult(unsealable=1)
    assert not (root / f"{plant}.meta").read_text(encoding="utf-8").startswith(MARKER_PREFIX)
    assert [m.file_id for m in await store.list_files()] == [victim.file_id]
    assert store._observed_sync("u-op") == (2, victim.size)

    _age(root, plant, -2)  # two days in the future
    assert (await store.prune_expired()).pruned == []  # no body, so no row
    assert _files(root) == [f"{victim.file_id}.blob", f"{victim.file_id}.meta"]
    assert (await store.read_bytes(victim.file_id)).decode() == _ADT


async def test_a_body_unreadable_for_another_cause_still_waits_for_rotate_key(
    tmp_path: Path,
) -> None:
    """Only a body that is missing or is not text makes an upload unsealable. One that cannot be
    opened for another cause can be sealed once that is fixed, so it is a skip, and it stays out of
    retention like any refused upload. A directory in the body's place stands in for that cause."""
    root = tmp_path / "uploads"
    fid = await _plaintext_upload(root)
    (root / f"{fid}.blob").unlink()
    (root / f"{fid}.blob").mkdir()
    store = UploadStore(root, _keyed(generate_key()), max_bytes=1 << 20)
    assert await store.reseal_to_active() == ResealResult(skipped=1)
    assert (await store.prune_expired(now=10**12)).pruned == []
    assert (root / f"{fid}.meta").exists()
    with pytest.raises(CipherError):
        await store.delete(fid)


def test_rotate_key_notes_an_unsealable_upload_and_does_not_warn(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The CLI says what happened and what removes it. It does not tell the operator to fix and
    re-run, which can never seal it, and it does not block retiring a key."""
    from messagefoundry.__main__ import main
    from messagefoundry.store.store import MessageStore

    monkeypatch.chdir(tmp_path)
    db, root = tmp_path / "cycle.db", tmp_path / "uploads"

    async def seed() -> None:
        store = await MessageStore.open(db)
        try:
            await store.enqueue_ingress(channel_id="c", raw=_ADT)
        finally:
            await store.close()
        await _unsealable_upload(root, _remove)

    asyncio.run(seed())
    monkeypatch.setenv("MEFOR_STORE_ENCRYPTION_KEY", generate_key())
    monkeypatch.setenv("MEFOR_STORE_UPLOADS_DIR", str(root))
    assert main(["rotate-key", "--db", str(db)]) == 0
    captured = capsys.readouterr()
    assert "note: 1 uploaded file(s) have a plaintext sidecar" in captured.out
    assert "could not be read" not in captured.err
