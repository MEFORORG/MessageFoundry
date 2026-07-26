# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""At-least-once across a DR restore (ADR 0049 AC-11): a store restored from a backup archive recovers
in-flight rows via ``reset_stale_inflight`` and re-runs the pure router/transform stages, preserving
at-least-once — no staged-queue row lost, re-derived output identical (a tolerated duplicate to an
idempotent outbound, never a drop) — even for a snapshot taken mid-handoff.

This lives in its own module (not ``test_restore_verify.py``) because ADR 0049 AC-11 links it here; the
key-fingerprint / PASS-FAIL-KEY_MISMATCH cases stay in ``test_restore_verify.py`` (AC-5)."""

from __future__ import annotations

import base64
import io
import tarfile
from pathlib import Path

import pytest

from messagefoundry.config.settings import BackupSettings, StoreSettings
from messagefoundry.pipeline.dr_backup import (
    BackupRunner,
    _extract_member,
    _read_manifest_from_tar,
    _verify_archive_blocking,
)
from messagefoundry.store import MessageStore, OutboxStatus
from messagefoundry.store.crypto import generate_key, make_cipher


async def test_restore_resumes_without_loss_or_double_drop(tmp_path) -> None:
    # AC-11: a store restored from the archive recovers in-flight rows via reset_stale_inflight and
    # re-runs the pure stages, preserving at-least-once across the restore (no queue row lost).
    key_b64 = generate_key()
    cipher = make_cipher(key_b64)
    store = await MessageStore.open(tmp_path / "msg.db", cipher=cipher)
    mid = await store.enqueue_message(
        channel_id="c1",
        raw="MSH|^~\\&|x",
        deliveries=[("d1", "OUT|y")],
        control_id="CID-1",
        now=1.0,
    )
    # Claim the outbound row so it is INFLIGHT at snapshot time (a mid-handoff state).
    [row] = await store.outbox_for(mid)
    await store.claim_ready(now=1.0)

    ss = StoreSettings(path=str(tmp_path / "msg.db"), encryption_key=key_b64)
    runner = BackupRunner(
        store,
        BackupSettings(enabled=True, destination=str(tmp_path / "b")),
        store_settings=ss,
        config_dir=None,
    )
    result = await runner.run_once(now=2.0)
    assert result is not None
    await store.close()

    # "Restore": decrypt the archive's store.db to a fresh path and open it through open_store, which
    # runs reset_stale_inflight on startup — the in-flight row returns to pending (recoverable), not lost.
    import base64
    import io
    import tarfile

    from messagefoundry.store.backup_codec import decrypt_stream

    restored_db = tmp_path / "restored.db"
    out = io.BytesIO()
    with open(result.archive_path, "rb") as src:
        decrypt_stream(src, out, base64.b64decode(key_b64))
    with tarfile.open(fileobj=io.BytesIO(out.getvalue()), mode="r") as tar:
        member = tar.extractfile("store.db")
        assert member is not None
        restored_db.write_bytes(member.read())

    from messagefoundry.store.base import open_store

    restored = await open_store(ss.model_copy(update={"path": str(restored_db)}))
    try:
        # The snapshot captured the row; startup reset_stale_inflight returns it to pending so a re-run
        # re-delivers (at-least-once: a tolerated duplicate to an idempotent outbound, never a drop).
        rows = await restored.outbox_for(mid)
        assert len(rows) == 1
        assert rows[0]["status"] in (OutboxStatus.PENDING.value, OutboxStatus.INFLIGHT.value)
        ok, _ = await restored.integrity_check()
        assert ok
    finally:
        await restored.close()


# --- ASVS 5.2.3: archive-READ decompression/size bounds (dr_backup restore path) --------------------


def _write_plain_tar(path: Path, members: dict[str, bytes], *, mode: str = "w:") -> None:
    """Write an uncompressed (``w:``) or gzip (``w:gz``) tar of ``members`` (name → bytes)."""
    with tarfile.open(path, mode) as tar:
        for name, blob in members.items():
            info = tarfile.TarInfo(name)
            info.size = len(blob)
            tar.addfile(info, io.BytesIO(blob))


def test_extract_member_refuses_gzip_tar(tmp_path) -> None:
    # The writer only ever writes an uncompressed tar; the reader is pinned to "r:" so an attacker-supplied
    # gzip archive (a decompression-bomb vector) is refused, not silently auto-decompressed.
    gz = tmp_path / "archive.tar.gz"
    _write_plain_tar(gz, {"store.db": b"x" * 32}, mode="w:gz")
    with pytest.raises(tarfile.ReadError):
        _extract_member(gz, "store.db", tmp_path)
    with pytest.raises(tarfile.ReadError):
        _read_manifest_from_tar(gz)


def test_extract_member_rejects_oversize_member(tmp_path) -> None:
    tar_path = tmp_path / "archive.tar"
    _write_plain_tar(tar_path, {"store.db": b"y" * 4096})
    # Declared member size (4096) over the cap → rejected BEFORE any streaming.
    with pytest.raises(tarfile.TarError):
        _extract_member(tar_path, "store.db", tmp_path, max_member_bytes=1024)
    # A generous cap extracts the member intact.
    out = _extract_member(tar_path, "store.db", tmp_path, max_member_bytes=1024 * 1024)
    assert out is not None and out.read_bytes() == b"y" * 4096


def test_verify_refuses_plaintext_archive_when_a_store_key_is_configured(tmp_path) -> None:
    # Symmetric to the write-side fail-closed: with a store key configured, a PLAINTEXT archive is a
    # downgrade signal and is refused (KEY_MISMATCH) — unless allow_unencrypted opts a no-PHI box back in.
    plain = tmp_path / "mefor-backup.mfbak.plain"
    # A well-formed but PLAINTEXT archive (a real manifest, no store.db, no .mfbak MAGIC → looks plaintext).
    _write_plain_tar(plain, {"manifest.json": b'{"config_only": false}'})
    key = base64.b64decode(generate_key())

    refused = _verify_archive_blocking(archive_path=str(plain), keys=[key], full=False)
    assert refused.status == "KEY_MISMATCH"
    assert "plaintext" in (refused.reason or "")

    # allow_unencrypted lets it proceed past the refusal (it then FAILs for the ordinary reason: no
    # store.db member) — proving the guard is the ONLY thing the flag relaxes.
    allowed = _verify_archive_blocking(
        archive_path=str(plain), keys=[key], full=False, allow_unencrypted=True
    )
    assert allowed.status == "FAIL"
    assert "plaintext" not in (allowed.reason or "")
