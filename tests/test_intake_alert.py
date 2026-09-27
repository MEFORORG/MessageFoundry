# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The intake-pause alert and the ``[inbound]`` serve rung (BACKLOG #290, slice 3, ASVS 15.2.2).

``IntakeBoundMonitor`` raises ``intake_paused`` when a pause starts and ``intake_resumed``, its
auto-resolving inverse, when it ends: once per edge, never once per measurement. ``serve`` warns,
and never refuses, when the enforcement dial is enforcing and ``[inbound].max_staged_depth`` is
unset, because owner ruling R1 of 2026-09-27 ships that bound opt-in.

Every disk test fakes ``shutil.disk_usage``; none fills or measures a real disk.
"""

from __future__ import annotations

import logging
import shutil
from pathlib import Path
from typing import Any, cast

import pytest
from pydantic import ValidationError

from messagefoundry.config.settings import _ALERT_EVENT_TYPES, AlertRule, StoreBackend
from messagefoundry.pipeline import intake_bound
from messagefoundry.pipeline.alert_sinks import _AUTO_RESOLVE, NotifierAlertSink
from messagefoundry.pipeline.alerts import AlertSink, LoggingAlertSink, intake_pause_detail
from messagefoundry.pipeline.intake_bound import (
    DEPTH_REASON,
    DISK_REASON,
    IntakeBoundMonitor,
    disk_resume_at,
    intake_alert_subject,
)
from messagefoundry.store import Store
from messagefoundry.transports.base import IntakeGate
from tests.test_alert_sinks import _drain as _drain_transports
from tests.test_alert_sinks import _RecordingTransport
from tests.test_alert_state import _drain as _drain_state
from tests.test_alert_state import _RecordingStore
from tests.test_intake_pause import MIB, _Disk, _FakeStore
from tests.test_storage_floor import _serve, _write_quiet_config

DEPTH = intake_alert_subject(DEPTH_REASON)
DISK = intake_alert_subject(DISK_REASON)


class _RecordingSink(LoggingAlertSink):
    """Records the two intake events. Every other event logs, so an engine can run on it."""

    def __init__(self) -> None:
        self.events: list[tuple[str, str, dict[str, Any]]] = []

    def intake_paused(
        self, name: str, *, reason: str, value: int, limit: int, store_kind: str
    ) -> None:
        payload = {"reason": reason, "value": value, "limit": limit, "kind": store_kind}
        self.events.append(("paused", name, payload))

    def intake_resumed(
        self, name: str, *, reason: str, value: int, limit: int, store_kind: str
    ) -> None:
        payload = {"reason": reason, "value": value, "limit": limit, "kind": store_kind}
        self.events.append(("resumed", name, payload))

    def of(self, subject: str) -> list[tuple[str, dict[str, Any]]]:
        return [(kind, payload) for kind, name, payload in self.events if name == subject]

    def kinds(self, subject: str) -> list[str]:
        return [kind for kind, _payload in self.of(subject)]


def _monitor(store: _FakeStore, sink: object, **kw: Any) -> tuple[IntakeBoundMonitor, IntakeGate]:
    gate = IntakeGate()
    monitor = IntakeBoundMonitor(cast(Store, store), gate, alert_sink=cast(AlertSink, sink), **kw)
    return monitor, gate


# --- the monitor raises once per edge ------------------------------------------------------------


async def test_a_depth_pause_raises_at_its_start_and_not_again_inside_the_reminder_window() -> None:
    store, sink = _FakeStore(depth=50), _RecordingSink()
    monitor, gate = _monitor(store, sink, max_staged_depth=10)
    await monitor.check_once()
    assert not gate.is_open
    assert sink.kinds(DEPTH) == ["paused"], "a run that starts over the bound reports the pause"
    for depth in (50, 40, 11, 10):  # still over, then inside the no-flap band
        store.depth = depth
        await monitor.check_once()
    assert sink.kinds(DEPTH) == ["paused"], "no reminder before REALERT_SECONDS has passed"
    store.depth = 9
    await monitor.check_once()
    assert gate.is_open
    assert sink.kinds(DEPTH) == ["paused", "resumed"]
    for _ in range(3):
        await monitor.check_once()
    assert sink.kinds(DEPTH) == ["paused", "resumed"]


async def test_a_held_pause_is_raised_again_at_each_reminder_and_resolved_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The house pattern of queue_buildup: a condition that persists is raised again, so the
    notifier's re-alert, escalation and suspend logic see it. Only the resume is edge-only."""
    clock = [1000.0]
    monkeypatch.setattr(intake_bound, "_monotonic", lambda: clock[0])
    store, sink = _FakeStore(depth=50), _RecordingSink()
    monitor, _gate = _monitor(store, sink, max_staged_depth=10)
    await monitor.check_once()
    clock[0] += intake_bound.REALERT_SECONDS - 1
    await monitor.check_once()
    assert sink.kinds(DEPTH) == ["paused"]
    clock[0] += 1
    await monitor.check_once()
    assert sink.kinds(DEPTH) == ["paused", "paused"], "the reminder is due"
    await monitor.check_once()
    assert sink.kinds(DEPTH) == ["paused", "paused"], "and then not again until the next window"
    clock[0] += intake_bound.REALERT_SECONDS
    store.depth = 0
    await monitor.check_once()
    await monitor.check_once()
    assert sink.kinds(DEPTH) == ["paused", "paused", "resumed"]


async def test_a_second_pause_soon_after_the_first_raises_at_once() -> None:
    store, sink = _FakeStore(depth=50), _RecordingSink()
    monitor, _gate = _monitor(store, sink, max_staged_depth=10)
    await monitor.check_once()
    store.depth = 0
    await monitor.check_once()
    store.depth = 50
    await monitor.check_once()
    assert sink.kinds(DEPTH) == ["paused", "resumed", "paused"]


async def test_with_no_sink_the_monitor_raises_nothing_and_logs_each_pause_once(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """No notifier: the monitor's own WARNING is the record, with no second ALERT line."""
    store, gate = _FakeStore(depth=50), IntakeGate()
    monitor = IntakeBoundMonitor(cast(Store, store), gate, max_staged_depth=10)
    with caplog.at_level(logging.DEBUG):
        await monitor.check_once()
        store.depth = 0
        await monitor.check_once()
    assert gate.is_open
    warnings = [r for r in caplog.records if r.levelno >= logging.WARNING]
    assert len(warnings) == 1 and "intake PAUSED" in warnings[0].getMessage()
    assert not any("ALERT intake" in r.getMessage() for r in caplog.records)


async def test_the_depth_payload_carries_counts_and_the_store_kind_only() -> None:
    store, sink = _FakeStore(depth=50, backend=StoreBackend.POSTGRES), _RecordingSink()
    monitor, _gate = _monitor(store, sink, max_staged_depth=10)
    await monitor.check_once()
    store.depth = 3
    await monitor.check_once()
    # Capped one past the bound: the read only asks "over it or not".
    assert sink.of(DEPTH) == [
        ("paused", {"reason": DEPTH_REASON, "value": 11, "limit": 10, "kind": "postgres"}),
        ("resumed", {"reason": DEPTH_REASON, "value": 3, "limit": 10, "kind": "postgres"}),
    ]


async def test_a_clean_first_measurement_resolves_a_stale_pause_once() -> None:
    """A run that stopped while paused left its alert open. The next run's first clean measurement
    raises one intake_resumed, and later clean measurements raise nothing."""
    store, sink = _FakeStore(depth=0), _RecordingSink()
    monitor, gate = _monitor(store, sink, max_staged_depth=10)
    for _ in range(3):
        await monitor.check_once()
    assert gate.is_open
    assert sink.kinds(DEPTH) == ["resumed"]


async def test_a_bound_that_is_off_is_reported_clear_once() -> None:
    """Turning a bound off, or moving to a server store, must not strand an open pause alert. A
    monitor with both bounds off measures nothing but still clears both subjects, once."""
    sink = _RecordingSink()
    monitor, gate = _monitor(
        _FakeStore(backend=StoreBackend.SQLSERVER), sink, min_free_disk_mb=1024
    )
    assert not monitor.enabled
    for _ in range(3):
        await monitor.check_once()
    assert gate.is_open
    zero = {"value": 0, "limit": 0, "kind": "sqlserver"}
    assert sink.of(DEPTH) == [("resumed", {"reason": DEPTH_REASON, **zero})]
    assert sink.of(DISK) == [("resumed", {"reason": DISK_REASON, **zero})]


async def test_stopping_while_paused_raises_no_resume_and_the_next_read_resolves_it() -> None:
    store, sink = _FakeStore(depth=50), _RecordingSink()
    monitor, gate = _monitor(store, sink, max_staged_depth=10)
    await monitor.check_once()
    await monitor.stop()
    assert gate.is_open
    assert sink.kinds(DEPTH) == ["paused"], "a stopped monitor did not see the backlog drain"
    store.depth = 0
    await monitor.check_once()
    assert sink.kinds(DEPTH) == ["paused", "resumed"]


async def test_a_failed_read_reports_nothing() -> None:
    store, sink = _FakeStore(depth=50), _RecordingSink()
    store.fail = True
    monitor, _gate = _monitor(store, sink, max_staged_depth=10)
    await monitor.check_once()
    assert sink.kinds(DEPTH) == [], "an unmeasured backlog is neither paused nor clear"


async def test_a_disk_pause_reports_mib_against_the_floor(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    disk = _Disk(free_mib=512)
    monkeypatch.setattr(shutil, "disk_usage", disk)
    sink = _RecordingSink()
    monitor, gate = _monitor(_FakeStore(path=str(tmp_path / "s.db")), sink, min_free_disk_mb=1024)
    await monitor.check_once()
    disk.free_mib = 1100  # back over the floor, inside the band
    await monitor.check_once()
    disk.free_mib = disk_resume_at(1024 * MIB) / MIB
    await monitor.check_once()
    assert gate.is_open
    assert sink.of(DISK) == [
        ("paused", {"reason": DISK_REASON, "value": 512, "limit": 1024, "kind": "sqlite"}),
        ("resumed", {"reason": DISK_REASON, "value": 1126, "limit": 1024, "kind": "sqlite"}),
    ]


async def test_each_bound_is_its_own_alert_subject(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(shutil, "disk_usage", _Disk(free_mib=1))
    store, sink = _FakeStore(depth=50, path=str(tmp_path / "s.db")), _RecordingSink()
    monitor, _gate = _monitor(store, sink, max_staged_depth=10, min_free_disk_mb=1024)
    await monitor.check_once()
    assert [(kind, name) for kind, name, _payload in sink.events] == [
        ("paused", DEPTH),
        ("paused", DISK),
    ]
    store.depth = 0
    await monitor.check_once()
    # The drained backlog resolves its own subject and leaves the disk pause open.
    assert sink.kinds(DEPTH) == ["paused", "resumed"]
    assert sink.kinds(DISK) == ["paused"]


async def test_a_start_inside_the_band_does_not_resolve_another_nodes_pause(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The subject is shared by every node on the store. A node that starts while the backlog sits
    between the resume line and the bound must not report a clear: another node may still hold its
    pause there. It reports the clear once the backlog passes the resume line."""
    store, sink = _FakeStore(depth=10), _RecordingSink()
    monitor, gate = _monitor(store, sink, max_staged_depth=10)
    await monitor.check_once()
    assert gate.is_open and sink.kinds(DEPTH) == []
    store.depth = 9
    await monitor.check_once()
    assert sink.kinds(DEPTH) == ["resumed"]

    disk = _Disk(free_mib=1100)  # over the 1024 MiB floor, under the 1126 MiB resume line
    monkeypatch.setattr(shutil, "disk_usage", disk)
    sink2 = _RecordingSink()
    monitor2, _gate2 = _monitor(
        _FakeStore(path=str(tmp_path / "s.db")), sink2, min_free_disk_mb=1024
    )
    await monitor2.check_once()
    assert sink2.kinds(DISK) == []
    disk.free_mib = 2048
    await monitor2.check_once()
    assert sink2.kinds(DISK) == ["resumed"]


async def test_a_report_the_sink_refused_is_retried(caplog: pytest.LogCaptureFixture) -> None:
    class _Flaky(_RecordingSink):
        def __init__(self) -> None:
            super().__init__()
            self.down = True

        def intake_paused(self, name: str, **kw: Any) -> None:
            if self.down:
                raise RuntimeError("sink down")
            super().intake_paused(name, **kw)

    sink = _Flaky()
    monitor, _gate = _monitor(_FakeStore(depth=50), sink, max_staged_depth=10)
    with caplog.at_level(logging.WARNING, logger="messagefoundry.pipeline.intake_bound"):
        await monitor.check_once()
        await monitor.check_once()
    assert sink.kinds(DEPTH) == []
    assert sum("could not be raised" in r.getMessage() for r in caplog.records) == 1
    sink.down = False
    await monitor.check_once()
    assert sink.kinds(DEPTH) == ["paused"], "the lost pause edge is raised at the next measurement"


async def test_a_failure_made_moot_by_a_drain_still_logs_the_next_outage(
    caplog: pytest.LogCaptureFixture,
) -> None:
    class _Flaky(_RecordingSink):
        down = True

        def intake_paused(self, name: str, **kw: Any) -> None:
            if self.down:
                raise RuntimeError("sink down")
            super().intake_paused(name, **kw)

    store, sink = _FakeStore(depth=0), _Flaky()
    monitor, _gate = _monitor(store, sink, max_staged_depth=10)
    await monitor.check_once()  # the start clear is reported
    with caplog.at_level(logging.WARNING, logger="messagefoundry.pipeline.intake_bound"):
        store.depth = 50
        await monitor.check_once()  # the pause report fails
        store.depth = 0
        await monitor.check_once()  # drained before the sink came back: the report is moot
        store.depth = 50
        await monitor.check_once()  # a second outage on a second pause
    failures = [r for r in caplog.records if "could not be raised" in r.getMessage()]
    assert len(failures) == 2, "the second outage must be logged too"


async def test_a_sink_without_the_intake_methods_cannot_break_a_measurement() -> None:
    monitor, gate = _monitor(_FakeStore(depth=50), object(), max_staged_depth=10)
    await monitor.check_once()
    assert not gate.is_open


async def test_the_engine_hands_its_sink_to_the_monitor_and_clears_off_bounds(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from messagefoundry.config.settings import RetentionSettings
    from messagefoundry.pipeline.engine import Engine

    monkeypatch.setattr(shutil, "disk_usage", _Disk(free_mib=10))
    sink = _RecordingSink()
    engine = await Engine.create(
        tmp_path / "engine.db",
        retention_settings=RetentionSettings(),
        alert_sink=cast(AlertSink, sink),
    )
    await engine.start()
    try:
        # Measured before start returns: the low disk pauses, and the off depth bound is cleared.
        assert sink.kinds(DISK) == ["paused"]
        assert sink.of(DEPTH) == [
            ("resumed", {"reason": DEPTH_REASON, "value": 0, "limit": 0, "kind": "sqlite"})
        ]
    finally:
        await engine.stop()


async def test_an_engine_with_both_bounds_off_still_clears_both(tmp_path: Path) -> None:
    from messagefoundry.pipeline.engine import Engine

    sink = _RecordingSink()
    engine = await Engine.create(tmp_path / "engine2.db", alert_sink=cast(AlertSink, sink))
    await engine.start()
    try:
        assert sink.kinds(DEPTH) == ["resumed"] and sink.kinds(DISK) == ["resumed"]
    finally:
        await engine.stop()


async def test_a_sink_that_raises_does_not_stop_the_release(
    caplog: pytest.LogCaptureFixture,
) -> None:
    class _Broken:
        def intake_paused(self, name: str, **_kw: Any) -> None:
            raise RuntimeError("sink down")

        def intake_resumed(self, name: str, **_kw: Any) -> None:
            raise RuntimeError("sink down")

    store = _FakeStore(depth=50)
    monitor, gate = _monitor(store, _Broken(), max_staged_depth=10)
    with caplog.at_level(logging.WARNING, logger="messagefoundry.pipeline.intake_bound"):
        await monitor.check_once()
        assert not gate.is_open
        store.depth = 0
        await monitor.check_once()
    assert gate.is_open, "a broken sink must not freeze the pause"
    assert any("could not be raised" in r.getMessage() for r in caplog.records)


def test_the_subject_is_outside_the_connection_name_grammar() -> None:
    from messagefoundry.connection_names import is_connection_name

    assert not is_connection_name(DEPTH)
    assert not is_connection_name(DISK)


# --- the sinks -----------------------------------------------------------------------------------


def test_the_logging_sink_warns_on_a_pause_and_logs_the_resume_at_debug(
    caplog: pytest.LogCaptureFixture,
) -> None:
    sink = LoggingAlertSink()
    with caplog.at_level(logging.DEBUG, logger="messagefoundry.pipeline.alerts"):
        sink.intake_paused(DEPTH, reason=DEPTH_REASON, value=11, limit=10, store_kind="sqlite")
        sink.intake_resumed(DEPTH, reason=DEPTH_REASON, value=3, limit=10, store_kind="sqlite")
    paused, resumed = caplog.records
    assert paused.levelno == logging.WARNING and "ALERT intake_paused" in paused.getMessage()
    # "More than" the limit, never the capped value, which would understate a large backlog.
    assert "more than 10 staged messages (sqlite store)" in paused.getMessage()
    assert "11" not in paused.getMessage()
    assert resumed.levelno == logging.DEBUG and "intake_resumed" in resumed.getMessage()


def test_the_disk_detail_gives_the_free_mib() -> None:
    assert (
        intake_pause_detail(reason=DISK_REASON, value=512, limit=1024, store_kind="sqlite")
        == "intake paused: 512 MiB free, below the 1024 MiB floor (sqlite store)"
    )


async def test_the_notifier_pages_the_pause_and_resolves_it_on_resume() -> None:
    transport, store = _RecordingTransport("webhook"), _RecordingStore()
    # The shared fake records the two calls the sink makes; it omits the startup-only listing.
    sink = NotifierAlertSink([transport], store=cast(Any, store))
    sink.intake_paused(DISK, reason=DISK_REASON, value=512, limit=1024, store_kind="sqlite")
    sink.intake_resumed(DISK, reason=DISK_REASON, value=1200, limit=1024, store_kind="sqlite")
    await _drain_transports(sink)
    await _drain_state(sink)
    assert len(transport.events) == 1, "a resume needs no page"
    event = transport.events[0]
    assert event["type"] == "intake_paused" and event["connection"] == DISK
    assert (event["reason"], event["value"], event["limit"], event["store_kind"]) == (
        DISK_REASON,
        512,
        1024,
        "sqlite",
    )
    # Counts, sizes and labels only (plus the ts/severity the framework adds): no message content.
    assert set(event) <= {
        "type",
        "connection",
        "reason",
        "value",
        "limit",
        "store_kind",
        "detail",
        "ts",
        "severity",
    }
    assert event["detail"] == "intake paused: 512 MiB free, below the 1024 MiB floor (sqlite store)"
    assert store.upserts[0]["event_type"] == "intake_paused"
    assert store.upserts[0]["reason"] == event["detail"]
    assert store.resolves == [{"event_type": "intake_paused", "connection": DISK}]


def test_the_pause_is_rule_targetable_and_the_resume_is_not() -> None:
    assert "intake_paused" in _ALERT_EVENT_TYPES
    AlertRule(event_type="intake_paused")
    assert "intake_resumed" not in _ALERT_EVENT_TYPES
    with pytest.raises(ValidationError, match="event_type"):
        AlertRule(event_type="intake_resumed")
    assert _AUTO_RESOLVE["intake_resumed"] == "intake_paused"


def test_every_shipped_sink_implements_both_events() -> None:
    for cls in (LoggingAlertSink, NotifierAlertSink):
        for method in ("intake_paused", "intake_resumed"):
            assert callable(getattr(cls, method, None)), f"{cls.__name__}.{method}"


# --- the serve rung ------------------------------------------------------------------------------

_RUNG = "[inbound].max_staged_depth"


@pytest.fixture
def serve_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """tests/test_storage_floor.py's serve environment, with a disk well over the floor."""
    from messagefoundry.store.crypto import generate_key

    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("MEFOR_STORE_ENCRYPTION_KEY", generate_key())
    monkeypatch.setattr("uvicorn.run", lambda *a, **k: None)
    monkeypatch.setattr(shutil, "disk_usage", _Disk(free_mib=4096))
    return tmp_path


def _rung_lines(text: str) -> list[str]:
    return [ln for ln in text.splitlines() if _RUNG in ln and "unbounded" in ln]


def test_the_rung_notes_once_at_info_under_enforce_and_still_starts(
    serve_env: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _write_quiet_config(serve_env)  # the dial ships enforcing and the bound ships unset
    assert _serve() == 0
    captured = capsys.readouterr()
    # serve's own logging handler writes to stdout (NSSM captures it), so the line lands there.
    lines = _rung_lines(captured.out)
    assert len(lines) == 1
    assert "INFO" in lines[0] and "WARNING" not in lines[0], "an opt-in bound is not a warning"
    assert _RUNG not in captured.err, "the rung never refuses, so stderr carries nothing of it"


def test_the_rung_is_silent_when_the_bound_is_set(
    serve_env: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _write_quiet_config(serve_env, "inbound.max_staged_depth = 100000\n")
    assert _serve() == 0
    captured = capsys.readouterr()
    assert _rung_lines(captured.out + captured.err) == []


def test_the_rung_is_silent_when_the_dial_is_not_enforcing(
    serve_env: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _write_quiet_config(serve_env, 'security.enforcement = "warn"\n')
    assert _serve() == 0
    captured = capsys.readouterr()
    assert _rung_lines(captured.out + captured.err) == []
