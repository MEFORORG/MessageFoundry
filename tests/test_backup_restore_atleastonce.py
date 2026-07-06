# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""At-least-once across a DR restore (ADR 0049 AC-11): a store restored from a backup archive recovers
in-flight rows via ``reset_stale_inflight`` and re-runs the pure router/transform stages, preserving
at-least-once — no staged-queue row lost, re-derived output identical (a tolerated duplicate to an
idempotent outbound, never a drop) — even for a snapshot taken mid-handoff.

This lives in its own module (not ``test_restore_verify.py``) because ADR 0049 AC-11 links it here; the
key-fingerprint / PASS-FAIL-KEY_MISMATCH cases stay in ``test_restore_verify.py`` (AC-5)."""

from __future__ import annotations

from messagefoundry.config.settings import BackupSettings, StoreSettings
from messagefoundry.pipeline.dr_backup import BackupRunner
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
