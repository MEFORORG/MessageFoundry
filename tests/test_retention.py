"""Retention / purge enforcement (WP-12, PHI.md §8): body-purge keeps metadata, never touches an
in-flight or (for the messages window) a dead body; dead-letters have their own window; WAL/VACUUM
maintenance runs clean; the RetentionRunner audits each working pass and alerts past max_db_mb.
Time is injected throughout for determinism."""

from __future__ import annotations

import json
import time

import pytest

from messagefoundry.config.settings import RetentionSettings
from messagefoundry.pipeline.engine import Engine
from messagefoundry.pipeline.retention import RetentionRunner
from messagefoundry.store import MessageStore, OutboxStatus
from messagefoundry.store.store import DbStatus

DAY = 86_400.0


@pytest.fixture
async def store(tmp_path):
    s = await MessageStore.open(tmp_path / "retention.db")
    yield s
    await s.close()


# --- helpers: drive a message to a terminal state -----------------------------


async def _delivered(
    store: MessageStore,
    *,
    now: float,
    raw: str = "MSH|^~\\&|raw-body",
    payload: str = "OUT|delivered-body",
    summary: str = "MRN001 DOE^JOHN",
    control: str = "CID-DONE",
) -> tuple[str, str]:
    """Enqueue → claim → mark_done, leaving the message fully terminal (one DONE outbound row)."""
    mid = await store.enqueue_message(
        channel_id="c1",
        raw=raw,
        deliveries=[("d1", payload)],
        control_id=control,
        message_type="ADT^A01",
        summary=summary,
        now=now,
    )
    [row] = await store.outbox_for(mid)
    await store.claim_ready(now=now)
    await store.mark_done(row["id"], now=now)
    return mid, row["id"]


async def _dead(
    store: MessageStore,
    *,
    now: float,
    raw: str = "MSH|^~\\&|raw-dead",
    payload: str = "OUT|dead-body",
    control: str = "CID-DEAD",
) -> tuple[str, str]:
    """Enqueue → claim → dead_letter_now, leaving one DEAD outbound row."""
    mid = await store.enqueue_message(
        channel_id="c1", raw=raw, deliveries=[("d1", payload)], control_id=control, now=now
    )
    [row] = await store.outbox_for(mid)
    await store.claim_ready(now=now)
    await store.dead_letter_now(row["id"], "permanent reject", now=now)
    return mid, row["id"]


async def _payload(store: MessageStore, outbox_id: str) -> str:
    cur = await store._db.execute("SELECT payload FROM queue WHERE id=?", (outbox_id,))
    return (await cur.fetchone())["payload"]


# --- purge_message_bodies -----------------------------------------------------


async def test_purge_nulls_old_delivered_body_but_keeps_metadata(store: MessageStore) -> None:
    mid, outbox_id = await _delivered(store, now=0.0)

    purged = await store.purge_message_bodies(older_than=10 * DAY)

    assert purged == 1
    msg = await store.get_message(mid)
    assert msg is not None  # row kept — only the body was nulled
    assert msg["raw"] == ""  # PHI body purged
    assert msg["summary"] is None
    assert msg["error"] is None
    # Metadata retained so counts/disposition/audit still reflect what arrived.
    assert msg["control_id"] == "CID-DONE"
    assert msg["message_type"] == "ADT^A01"
    assert msg["received_at"] == 0.0
    # The delivered (terminal) outbound payload is nulled too.
    assert await _payload(store, outbox_id) == ""


async def test_purge_skips_recent_messages(store: MessageStore) -> None:
    mid, _ = await _delivered(store, now=10 * DAY)
    # Cutoff (older_than) is before the message's received_at → not eligible.
    purged = await store.purge_message_bodies(older_than=9 * DAY)
    assert purged == 0
    assert (await store.get_message(mid))["raw"] == "MSH|^~\\&|raw-body"


async def test_purge_skips_pending_and_inflight_messages(store: MessageStore) -> None:
    a = await store.enqueue_message(
        channel_id="c1", raw="MSH|first", deliveries=[("d1", "p")], now=0.0
    )
    b = await store.enqueue_message(
        channel_id="c1", raw="MSH|second", deliveries=[("d1", "p")], now=0.0
    )
    await store.claim_ready(1, now=0.0)  # claim just one → one INFLIGHT, one still PENDING

    purged = await store.purge_message_bodies(older_than=10 * DAY)

    assert purged == 0  # a body still in the pipeline must never be purged (at-least-once)
    assert (await store.get_message(a))["raw"] == "MSH|first"  # inflight — kept
    assert (await store.get_message(b))["raw"] == "MSH|second"  # pending — kept


async def test_purge_idempotent(store: MessageStore) -> None:
    await _delivered(store, now=0.0)
    assert await store.purge_message_bodies(older_than=10 * DAY) == 1
    assert await store.purge_message_bodies(older_than=10 * DAY) == 0  # nothing new


async def test_error_message_body_is_purged(store: MessageStore) -> None:
    from messagefoundry.store import MessageStatus

    eid = await store.record_received(
        channel_id="c1",
        raw="bad",
        status=MessageStatus.ERROR,
        error="parse: PID|MRN42 leak",
        now=0.0,
    )
    assert await store.purge_message_bodies(older_than=10 * DAY) == 1
    msg = await store.get_message(eid)
    assert msg["raw"] == "" and msg["error"] is None  # the error column can embed PHI fragments


# --- the two windows are decoupled --------------------------------------------


async def test_messages_window_keeps_dead_payload_for_its_own_window(store: MessageStore) -> None:
    mid, dead_id = await _dead(store, now=0.0)

    # The message window nulls the inbound body but leaves the DEAD row's payload (replayable until
    # its own window) — and because replay re-queues the row's own payload, never messages.raw, this
    # can't break a later replay.
    await store.purge_message_bodies(older_than=10 * DAY)
    assert (await store.get_message(mid))["raw"] == ""
    assert await _payload(store, dead_id) == "OUT|dead-body"

    # The dead-letter window then nulls the dead payload, keeping the row + status.
    purged = await store.purge_dead_letters(older_than=10 * DAY)
    assert purged == 1
    assert await _payload(store, dead_id) == ""
    [row] = await store.outbox_for(mid)
    assert row["status"] == OutboxStatus.DEAD.value  # row + disposition kept


async def test_purge_dead_letters_respects_window_and_is_idempotent(store: MessageStore) -> None:
    _, dead_id = await _dead(store, now=5 * DAY)
    # Cutoff before it died → kept.
    assert await store.purge_dead_letters(older_than=1 * DAY) == 0
    assert await _payload(store, dead_id) == "OUT|dead-body"
    # Past the window → purged, then idempotent.
    assert await store.purge_dead_letters(older_than=10 * DAY) == 1
    assert await store.purge_dead_letters(older_than=10 * DAY) == 0


# --- maintenance --------------------------------------------------------------


async def test_wal_checkpoint_and_vacuum_run_clean(store: MessageStore) -> None:
    await _delivered(store, now=0.0)
    await store.purge_message_bodies(older_than=10 * DAY)
    await store.wal_checkpoint()
    await store.vacuum()  # must not error (runs outside a txn) and must leave the DB usable
    cur = await store._db.execute("PRAGMA journal_mode")
    assert str((await cur.fetchone())[0]).lower() == "wal"
    ok, _ = await store.integrity_check()
    assert ok


# --- RetentionRunner ----------------------------------------------------------


class _RecordingSink:
    """An AlertSink that records storage_threshold calls (and ignores the delivery events)."""

    def __init__(self) -> None:
        self.storage: list[tuple[str, int, int]] = []

    def connection_stopped(self, name: str, *, detail: str) -> None:  # pragma: no cover - unused
        pass

    def queue_buildup(self, name: str, *, depth: int, oldest_age_seconds: float) -> None:  # noqa: E501  # pragma: no cover - unused
        pass

    def storage_threshold(self, path: str, *, size_bytes: int, limit_bytes: int) -> None:
        self.storage.append((path, size_bytes, limit_bytes))


async def test_run_once_purges_and_writes_one_audit_entry(store: MessageStore) -> None:
    await _delivered(store, now=0.0)
    runner = RetentionRunner(
        store, RetentionSettings(messages_days=1, dead_letter_days=1), clock=lambda: 10 * DAY
    )

    result = await runner.run_once()

    assert result.messages_purged == 1
    audit = [r for r in await store.list_audit(limit=10) if r["action"] == "retention_purge"]
    assert len(audit) == 1
    detail = json.loads(audit[0]["detail"])
    assert detail["messages_purged"] == 1 and detail["messages_days"] == 1
    assert audit[0]["actor"] == "system"
    # No message content in the audit detail (no PHI) — only counts/cutoffs/sizes.
    assert "raw" not in audit[0]["detail"] and "DOE" not in audit[0]["detail"]


async def test_run_once_no_work_writes_no_audit(store: MessageStore) -> None:
    await _delivered(store, now=0.0)
    # Everything off → a pass does nothing and must not spam the audit log.
    runner = RetentionRunner(store, RetentionSettings(), clock=lambda: 10 * DAY)
    result = await runner.run_once()
    assert not result.did_work
    assert [r for r in await store.list_audit(limit=10) if r["action"] == "retention_purge"] == []


async def test_max_db_mb_alert_fires(store: MessageStore, monkeypatch) -> None:
    big = DbStatus(
        path=store.path,
        size_bytes=5_000_000,
        disk_free_bytes=0,
        journal_mode="wal",
        messages=0,
        events=0,
        audit=0,
    )

    async def fake_status() -> DbStatus:
        return big

    monkeypatch.setattr(store, "db_status", fake_status)
    sink = _RecordingSink()
    runner = RetentionRunner(
        store, RetentionSettings(max_db_mb=1), alert_sink=sink, clock=lambda: 1000.0
    )

    result = await runner.run_once()

    assert result.over_limit
    assert sink.storage == [(store.path, 5_000_000, 1_000_000)]
    # over_limit counts as work → audited.
    audit = [r for r in await store.list_audit(limit=10) if r["action"] == "retention_purge"]
    assert len(audit) == 1 and json.loads(audit[0]["detail"])["over_limit"] is True


async def test_run_once_vacuums_when_due(store: MessageStore) -> None:
    now = 1_000_000.0
    lt = time.localtime(now)
    at = f"{lt.tm_hour:02d}:{lt.tm_min:02d}"  # exactly now's local time → reached
    runner = RetentionRunner(store, RetentionSettings(vacuum_at=at), clock=lambda: now)

    result = await runner.run_once()
    assert result.vacuumed
    assert runner._last_vacuum_day == runner._day_key(now)
    # Same day → not due again.
    assert runner._vacuum_due(now) is False


def test_vacuum_due_disabled_when_unset(store: MessageStore) -> None:
    runner = RetentionRunner(store, RetentionSettings())
    assert runner._vacuum_due(1_000_000.0) is False


def test_enabled_property(store: MessageStore) -> None:
    assert RetentionRunner(store, RetentionSettings()).enabled is False
    assert RetentionRunner(store, RetentionSettings(messages_days=1)).enabled is True
    assert RetentionRunner(store, RetentionSettings(max_db_mb=10)).enabled is True
    assert RetentionRunner(store, RetentionSettings(vacuum_at="03:30")).enabled is True


# --- settings validation ------------------------------------------------------


def test_settings_validation() -> None:
    with pytest.raises(ValueError):
        RetentionSettings(vacuum_at="25:00")
    with pytest.raises(ValueError):
        RetentionSettings(messages_days=-1)
    with pytest.raises(ValueError):
        RetentionSettings(purge_interval_seconds=0)
    assert RetentionSettings(vacuum_at="3:30").vacuum_time() == (3, 30)
    assert RetentionSettings(vacuum_at="").vacuum_time() is None


# --- Engine wiring ------------------------------------------------------------


async def test_engine_starts_and_stops_retention_runner(tmp_path) -> None:
    engine = await Engine.create(
        tmp_path / "engine.db", retention_settings=RetentionSettings(messages_days=1)
    )
    await engine.start()
    try:
        assert engine._retention_runner is not None
        assert engine._retention_runner.enabled is True
    finally:
        await engine.stop()


async def test_engine_without_retention_settings_has_no_runner(tmp_path) -> None:
    engine = await Engine.create(tmp_path / "engine2.db")
    await engine.start()
    try:
        assert engine._retention_runner is None
    finally:
        await engine.stop()
