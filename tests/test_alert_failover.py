# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""HA / DR failover event alerts (#145, ADR 0014 amendment): the new leadership_acquired / dr_activated
alert events + their leadership_lost / dr_released auto-resolving inverses, emitted at the cluster
leadership transitions (DbCoordinator + SqlServerCoordinator, in lockstep) and the DR activate/release."""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from messagefoundry.config.settings import (
    _ALERT_EVENT_TYPES,
    AlertRule,
    BackupSettings,
    DrSettings,
    StoreSettings,
)
from messagefoundry.pipeline.alert_sinks import _AUTO_RESOLVE, NotifierAlertSink
from messagefoundry.pipeline.alerts import LoggingAlertSink
from messagefoundry.pipeline.cluster import DbCoordinator
from messagefoundry.pipeline.cluster_sqlserver import SqlServerCoordinator
from messagefoundry.pipeline.dr import DrCoordinator
from messagefoundry.pipeline.dr_backup import BackupRunner
from messagefoundry.store import MessageStore
from messagefoundry.store.crypto import generate_key, make_cipher


class _RecordingSink:
    """Captures only the #145 leadership/DR events (structural — the coordinators call just these)."""

    def __init__(self) -> None:
        self.events: list[tuple[Any, ...]] = []

    def leadership_acquired(self, node: str, *, role: str, epoch: int | None = None) -> None:
        self.events.append(("leadership_acquired", node, role, epoch))

    def leadership_lost(self, node: str, *, role: str, reason: str) -> None:
        self.events.append(("leadership_lost", node, role, reason))

    def dr_activated(self, node: str, *, role: str) -> None:
        self.events.append(("dr_activated", node, role))

    def dr_released(self, node: str, *, role: str) -> None:
        self.events.append(("dr_released", node, role))


# --- settings: rule-targetability --------------------------------------------


def test_leadership_and_dr_events_are_rule_targetable() -> None:
    assert "leadership_acquired" in _ALERT_EVENT_TYPES
    assert "dr_activated" in _ALERT_EVENT_TYPES
    AlertRule(event_type="leadership_acquired")  # ok
    AlertRule(event_type="dr_activated")  # ok


def test_inverse_events_are_not_alert_types() -> None:
    # leadership_lost / dr_released are auto-resolve-only, never rule-targetable (a step-down/fail-back
    # needs no page).
    assert "leadership_lost" not in _ALERT_EVENT_TYPES
    assert "dr_released" not in _ALERT_EVENT_TYPES
    with pytest.raises(ValidationError, match="event_type"):
        AlertRule(event_type="leadership_lost")
    with pytest.raises(ValidationError, match="event_type"):
        AlertRule(event_type="dr_released")


def test_auto_resolve_map_pairs() -> None:
    assert _AUTO_RESOLVE["leadership_lost"] == "leadership_acquired"
    assert _AUTO_RESOLVE["dr_released"] == "dr_activated"


# --- LoggingAlertSink --------------------------------------------------------


def test_logging_sink_logs_transitions(caplog: pytest.LogCaptureFixture) -> None:
    sink = LoggingAlertSink()
    with caplog.at_level("INFO"):
        sink.leadership_acquired("nodeA", role="leader", epoch=3)
        sink.leadership_lost("nodeA", role="follower", reason="self-fenced")
        sink.dr_activated("dr-box", role="dr_standby")
        sink.dr_released("dr-box", role="primary")
    msgs = " ".join(r.getMessage() for r in caplog.records)
    assert "leadership_acquired" in msgs and "leadership_lost" in msgs
    assert "dr_activated" in msgs and "dr_released" in msgs


# --- NotifierAlertSink fan-out vs. auto-resolve ------------------------------


class _RecordingTransport:
    def __init__(self, name: str = "webhook") -> None:
        self.name = name
        self.events: list[dict[str, Any]] = []

    async def send(self, event: dict[str, Any], **_kw: Any) -> None:
        self.events.append(event)


async def _drain(sink: NotifierAlertSink) -> None:
    sink.start()
    await asyncio.sleep(0)
    await sink.aclose()
    for _ in range(10):
        if not sink._state_tasks:
            break
        await asyncio.gather(*list(sink._state_tasks), return_exceptions=True)
        await asyncio.sleep(0)


async def test_leadership_acquired_fans_out() -> None:
    t = _RecordingTransport()
    sink = NotifierAlertSink([t])
    sink.leadership_acquired("nodeA", role="leader", epoch=7)
    await _drain(sink)
    assert len(t.events) == 1
    ev = t.events[0]
    assert ev["type"] == "leadership_acquired"
    assert ev["connection"] == "nodeA" and ev["node"] == "nodeA"
    assert ev["role"] == "leader" and ev["epoch"] == 7
    # node/connection/role/epoch only (+ ts/severity the framework adds) — no message content.
    assert set(ev) <= {"type", "connection", "node", "role", "epoch", "ts", "severity"}


async def test_dr_activated_fans_out() -> None:
    t = _RecordingTransport()
    sink = NotifierAlertSink([t])
    sink.dr_activated("dr-box", role="dr_standby")
    await _drain(sink)
    assert len(t.events) == 1 and t.events[0]["type"] == "dr_activated"
    assert t.events[0]["role"] == "dr_standby"


async def test_inverse_events_do_not_notify() -> None:
    t = _RecordingTransport()
    sink = NotifierAlertSink([t])
    sink.leadership_lost("nodeA", role="follower", reason="released")
    sink.dr_released("dr-box", role="primary")
    await _drain(sink)
    assert t.events == []  # inverse events never notify — auto-resolve only


class _RecordingStore:
    def __init__(self) -> None:
        self.upserts: list[dict[str, object]] = []
        self.resolves: list[dict[str, object]] = []

    async def upsert_alert_instance(
        self,
        *,
        event_type: str,
        connection: str,
        severity: str,
        reason: str | None = None,
        escalation_tier: int = 0,
        now: float | None = None,
    ) -> None:
        self.upserts.append({"event_type": event_type, "connection": connection})

    async def resolve_alert_instances_for(
        self, *, event_type: str, connection: str, now: float | None = None
    ) -> int:
        self.resolves.append({"event_type": event_type, "connection": connection})
        return 1


async def test_leadership_lost_auto_resolves_acquired() -> None:
    store = _RecordingStore()
    sink = NotifierAlertSink([], store=store)
    sink.leadership_acquired("nodeA", role="leader", epoch=1)  # opens instance
    sink.leadership_lost("nodeA", role="follower", reason="lease taken or expired")  # resolves
    await _drain(sink)
    assert {u["event_type"] for u in store.upserts} == {"leadership_acquired"}
    assert store.resolves == [{"event_type": "leadership_acquired", "connection": "nodeA"}]


async def test_dr_released_auto_resolves_activated() -> None:
    store = _RecordingStore()
    sink = NotifierAlertSink([], store=store)
    sink.dr_activated("dr-box", role="dr_standby")
    sink.dr_released("dr-box", role="primary")
    await _drain(sink)
    assert store.resolves == [{"event_type": "dr_activated", "connection": "dr-box"}]


# --- DbCoordinator emits at leadership transitions ---------------------------


class _Clock:
    def __init__(self, t: float = 0.0) -> None:
        self.t = t

    def __call__(self) -> float:
        return self.t


class _FakeLeaseDB:
    def __init__(self, db_clock: _Clock) -> None:
        self._db_clock = db_clock
        self.row: dict[str, object] | None = None


class _FakeLeasePool:
    def __init__(self, db: _FakeLeaseDB) -> None:
        self._db = db

    async def fetchrow(self, sql: str, *args: object) -> dict[str, object] | None:
        _lease_key, owner, ttl, delay = args
        now = self._db._db_clock()
        row = self._db.row
        if row is None:
            self._db.row = {"owner": owner, "lease_expires_at": now + float(ttl), "leader_epoch": 1}  # type: ignore[arg-type]
            return {"owner": owner, "leader_epoch": 1}
        expired = float(row["lease_expires_at"]) + float(delay) < now  # type: ignore[arg-type]
        if row["owner"] == owner or expired:
            if row["owner"] != owner:
                row["leader_epoch"] = int(row["leader_epoch"]) + 1  # type: ignore[arg-type]
            row["owner"] = owner
            row["lease_expires_at"] = now + float(ttl)  # type: ignore[arg-type]
            return {"owner": owner, "leader_epoch": row["leader_epoch"]}
        return None

    async def execute(self, sql: str, *args: object) -> None:
        _lease_key, owner = args
        row = self._db.row
        if row is not None and row["owner"] == owner:
            row["lease_expires_at"] = 0.0


def _db_coord(
    pool: _FakeLeasePool, mono: _Clock, sink: _RecordingSink, node: str = "A"
) -> DbCoordinator:
    return DbCoordinator(
        pool,
        node,
        leader_lease_ttl_seconds=30.0,
        leader_fence_timeout_seconds=20.0,
        monotonic=mono,
        alert_sink=sink,  # type: ignore[arg-type]
    )


async def test_db_coordinator_emits_acquired_once_not_on_renew() -> None:
    dbc = _Clock(0.0)
    db = _FakeLeaseDB(dbc)
    sink = _RecordingSink()
    a = _db_coord(_FakeLeasePool(db), _Clock(0.0), sink)
    await a._maintain_leadership()  # acquire → emit
    await a._maintain_leadership()  # renew → NO second emit
    acquired = [e for e in sink.events if e[0] == "leadership_acquired"]
    assert acquired == [("leadership_acquired", "A", "leader", 1)]


async def test_db_coordinator_emits_lost_on_takeover() -> None:
    dbc = _Clock(0.0)
    db = _FakeLeaseDB(dbc)
    sink_a, sink_b = _RecordingSink(), _RecordingSink()
    a = _db_coord(_FakeLeasePool(db), _Clock(0.0), sink_a, node="A")
    b = _db_coord(_FakeLeasePool(db), _Clock(0.0), sink_b, node="B")
    await a._maintain_leadership()  # A leads
    dbc.t = 31.0  # A's lease expires
    await b._maintain_leadership()  # B takes over
    await a._maintain_leadership()  # A observes it is no longer leader → leadership_lost
    assert ("leadership_lost", "A", "follower", "lease taken or expired") in sink_a.events
    assert ("leadership_acquired", "B", "leader", 2) in sink_b.events


async def test_db_coordinator_emits_lost_on_self_fence() -> None:
    dbc = _Clock(0.0)
    db = _FakeLeaseDB(dbc)
    mono = _Clock(0.0)
    sink = _RecordingSink()
    a = _db_coord(_FakeLeasePool(db), mono, sink)
    await a._maintain_leadership()  # acquire at mono=0
    mono.t = 100.0  # well past the fence timeout with no renew
    a._check_fence()
    assert ("leadership_lost", "A", "follower", "self-fenced") in sink.events


async def test_db_coordinator_emits_lost_on_clean_release() -> None:
    dbc = _Clock(0.0)
    db = _FakeLeaseDB(dbc)
    sink = _RecordingSink()
    a = _db_coord(_FakeLeasePool(db), _Clock(0.0), sink)
    await a._maintain_leadership()
    await a._release_leadership()
    assert ("leadership_lost", "A", "follower", "released") in sink.events


# --- SqlServerCoordinator: lockstep ------------------------------------------


class _FakeSqlStore:
    """Only what SqlServerCoordinator needs for the release path + construction."""

    _settings = None

    def __init__(self) -> None:
        self.executed: list[str] = []

    async def _execute(self, sql: str, params: tuple[Any, ...]) -> None:
        self.executed.append(sql)


def test_sqlserver_coordinator_helpers_emit_lockstep() -> None:
    # The SQL Server sibling emits the SAME events via the SAME helper names as DbCoordinator.
    sink = _RecordingSink()
    c = SqlServerCoordinator(_FakeSqlStore(), "A", alert_sink=sink)  # type: ignore[arg-type]
    c._leader_epoch = 5
    c._alert_leadership_acquired()
    c._alert_leadership_lost("self-fenced")
    assert sink.events == [
        ("leadership_acquired", "A", "leader", 5),
        ("leadership_lost", "A", "follower", "self-fenced"),
    ]


async def test_sqlserver_coordinator_release_emits() -> None:
    sink = _RecordingSink()
    c = SqlServerCoordinator(_FakeSqlStore(), "A", alert_sink=sink)  # type: ignore[arg-type]
    c._is_leader = True
    await c._release_leadership()
    assert ("leadership_lost", "A", "follower", "released") in sink.events


# --- DrCoordinator activate/release ------------------------------------------


async def _seed(tmp_path: Path) -> tuple[MessageStore, str, StoreSettings]:
    key = generate_key()
    store = await MessageStore.open(tmp_path / "msg.db", cipher=make_cipher(key))
    await store.enqueue_message(
        channel_id="c1",
        raw="MSH|^~\\&|x",
        deliveries=[("d1", "OUT|y")],
        control_id="CID-1",
        now=1.0,
    )
    ss = StoreSettings(path=str(tmp_path / "msg.db"), encryption_key=key)
    runner = BackupRunner(
        store,
        BackupSettings(enabled=True, destination=str(tmp_path / "b")),
        store_settings=ss,
        config_dir=None,
    )
    res = await runner.run_once(now=1.0)
    assert res is not None
    return store, res.archive_path, ss


async def test_dr_coordinator_emits_activated_and_released(tmp_path: Path) -> None:
    store, archive, ss = await _seed(tmp_path)
    sink = _RecordingSink()
    state = {"active": False}

    async def act() -> None:
        state["active"] = True

    async def deact() -> None:
        state["active"] = False

    coord = DrCoordinator(
        store,
        DrSettings(enabled=True, seed_archive=archive, takeover_hook="exit 0"),
        store_settings=ss,
        activate_profile=act,
        deactivate_profile=deact,
        alert_sink=sink,  # type: ignore[arg-type]
    )
    try:
        await coord.activate(actor="alice")
        await coord.release(actor="alice")
    finally:
        await store.close()
    kinds = [e[0] for e in sink.events]
    assert "dr_activated" in kinds and "dr_released" in kinds
    # activate before release, and the same box label on both (so the fail-back resolves the promotion)
    act_ev = next(e for e in sink.events if e[0] == "dr_activated")
    rel_ev = next(e for e in sink.events if e[0] == "dr_released")
    assert act_ev[1] == rel_ev[1]  # same node label
    assert act_ev[2] == "dr_standby" and rel_ev[2] == "primary"
