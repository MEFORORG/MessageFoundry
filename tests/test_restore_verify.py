# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""restore-verify (ADR 0049 AC-5): the key-fingerprint precheck returns a clean KEY_MISMATCH BEFORE any
decrypt; a matching key (active OR a retired key still in the keyring after a rotation) decrypts + opens
the embedded store read-only + integrity_check + row-count compare (PASS); a corrupted archive is FAIL.
(The at-least-once-across-restore case, AC-11, lives in ``test_backup_restore_atleastonce.py``.)"""

from __future__ import annotations

from pathlib import Path

from messagefoundry.config.settings import BackupSettings, StoreSettings
from messagefoundry.pipeline.dr_backup import BackupRunner, run_restore_verify
from messagefoundry.store import MessageStore
from messagefoundry.store.crypto import generate_key, make_cipher


async def _backup(tmp_path: Path, key_b64: str | None) -> tuple[MessageStore, str, StoreSettings]:
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
        BackupSettings(enabled=True, destination=str(tmp_path / "b")),
        store_settings=ss,
        config_dir=None,
    )
    result = await runner.run_once(now=1.0)
    assert result is not None
    return store, result.archive_path, ss


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


async def test_verify_missing_archive_is_reported(tmp_path) -> None:
    ss = StoreSettings(path=str(tmp_path / "msg.db"), encryption_key=generate_key())
    res = await run_restore_verify(str(tmp_path / "nope.mfbak"), store_settings=ss)
    assert res.status == "FAIL"
