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

import asyncio
import logging
import shutil
from pathlib import Path
from typing import Any, NamedTuple, cast

import pytest
from pydantic import ValidationError

from messagefoundry.__main__ import main
from messagefoundry.config.settings import _ALERT_EVENT_TYPES, AlertRule, StoreBackend
from messagefoundry.pipeline.alert_sinks import _AUTO_RESOLVE, NotifierAlertSink
from messagefoundry.pipeline.alerts import AlertSink, LoggingAlertSink
from messagefoundry.pipeline.intake_bound import (
    DEPTH_REASON,
    DISK_REASON,
    IntakeBoundMonitor,
    disk_resume_at,
    intake_alert_subject,
)
from messagefoundry.store import Store
from messagefoundry.transports.base import IntakeGate

MIB = 1 << 20
SAMPLES_CONFIG = Path(__file__).resolve().parent.parent / "samples" / "config"


# --- fakes ---------------------------------------------------------------------------------------


class _FakeStore:
    def __init__(
        self, *, depth: int = 0, backend: StoreBackend = StoreBackend.SQLITE, path: str = ":memory:"
    ) -> None:
        self.depth = depth
        self.backend = backend
        self.path = path

    async def staged_intake_depth(self, *, limit: int | None = None) -> int:
        return self.depth if limit is None else min(self.depth, limit)


class _RecordingSink:
    """Only the two intake events, which is all the monitor calls."""

    def __init__(self) -> None:
        self.events: list[tuple[str, str, dict[str, Any]]] = []

    def intake_paused(
        self, name: str, *, reason: str, value: int, limit: int, store_kind: str
    ) -> None:
        self.events.append(
            ("paused", name, {"reason": reason, "value": value, "limit": limit, "kind": store_kind})
        )

    def intake_resumed(
        self, name: str, *, reason: str, value: int, limit: int, store_kind: str
    ) -> None:
        self.events.append(
            (
                "resumed",
                name,
                {"reason": reason, "value": value, "limit": limit, "kind": store_kind},
            )
        )

    def kinds(self) -> list[str]:
        return [kind for kind, _name, _payload in self.events]


def _monitor(store: _FakeStore, sink: object, **kw: Any) -> tuple[IntakeBoundMonitor, IntakeGate]:
    gate = IntakeGate()
    return IntakeBoundMonitor(
        cast(Store, store), gate, alert_sink=cast(AlertSink, sink), **kw
    ), gate


class _Usage(NamedTuple):
    total: int
    used: int
    free: int


class _Disk:
    def __init__(self, free_mib: float) -> None:
        self.free_mib = free_mib

    def __call__(self, path: object) -> _Usage:
        free = int(self.free_mib * MIB)
        return _Usage(total=1 << 40, used=(1 << 40) - free, free=free)


# --- the monitor raises once per edge ------------------------------------------------------------


async def test_a_depth_pause_raises_one_alert_at_each_edge_and_none_between() -> None:
    store, sink = _FakeStore(depth=50), _RecordingSink()
    monitor, gate = _monitor(store, sink, max_staged_depth=10)
    await monitor.check_once()
    assert not gate.is_open
    assert sink.kinds() == ["paused"], "a run that starts over the bound reports the pause alone"
    for depth in (50, 40, 11, 10):  # still over, then inside the no-flap band
        store.depth = depth
        await monitor.check_once()
    assert sink.kinds() == ["paused"], "a measurement that changes nothing raises nothing"
    store.depth = 9
    await monitor.check_once()
    assert gate.is_open
    assert sink.kinds() == ["paused", "resumed"]
    for _ in range(3):
        await monitor.check_once()
    assert sink.kinds() == ["paused", "resumed"]


async def test_the_depth_payload_carries_counts_and_the_store_kind_only() -> None:
    store, sink = _FakeStore(depth=50, backend=StoreBackend.POSTGRES), _RecordingSink()
    monitor, _gate = _monitor(store, sink, max_staged_depth=10)
    await monitor.check_once()
    store.depth = 3
    await monitor.check_once()
    paused, resumed = sink.events
    # Capped one past the bound: the read only asks "over it or not".
    assert paused == (
        "paused",
        "intake:staged_depth",
        {"reason": DEPTH_REASON, "value": 11, "limit": 10, "kind": "postgres"},
    )
    assert resumed == (
        "resumed",
        "intake:staged_depth",
        {"reason": DEPTH_REASON, "value": 3, "limit": 10, "kind": "postgres"},
    )


async def test_a_clean_first_measurement_resolves_a_stale_pause_once() -> None:
    """A run that stopped while paused left its alert open. The next run's first clean measurement
    raises one intake_resumed, and later clean measurements raise nothing."""
    store, sink = _FakeStore(depth=0), _RecordingSink()
    monitor, gate = _monitor(store, sink, max_staged_depth=10)
    for _ in range(3):
        await monitor.check_once()
    assert gate.is_open
    assert sink.kinds() == ["resumed"]


async def test_stopping_while_paused_raises_no_resume_and_the_next_start_reports_afresh() -> None:
    store, sink = _FakeStore(depth=50), _RecordingSink()
    monitor, gate = _monitor(store, sink, max_staged_depth=10)
    await monitor.check_once()
    await monitor.stop()
    assert gate.is_open
    assert sink.kinds() == ["paused"], "a stopped monitor did not see the backlog drain"
    store.depth = 0
    await monitor.check_once()
    assert sink.kinds() == ["paused", "resumed"]


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
    assert sink.events == [
        (
            "paused",
            "intake:disk_floor",
            {"reason": DISK_REASON, "value": 512, "limit": 1024, "kind": "sqlite"},
        ),
        (
            "resumed",
            "intake:disk_floor",
            {"reason": DISK_REASON, "value": 1126, "limit": 1024, "kind": "sqlite"},
        ),
    ]


async def test_each_bound_is_its_own_alert_subject(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(shutil, "disk_usage", _Disk(free_mib=1))
    store, sink = _FakeStore(depth=50, path=str(tmp_path / "s.db")), _RecordingSink()
    monitor, _gate = _monitor(store, sink, max_staged_depth=10, min_free_disk_mb=1024)
    await monitor.check_once()
    assert [name for _kind, name, _payload in sink.events] == [
        "intake:staged_depth",
        "intake:disk_floor",
    ]
    store.depth = 0
    await monitor.check_once()
    # The drained backlog resolves its own subject and leaves the disk pause open.
    assert sink.events[-1][:2] == ("resumed", "intake:staged_depth")
    assert len(sink.events) == 3


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

    for reason in (DEPTH_REASON, DISK_REASON):
        assert not is_connection_name(intake_alert_subject(reason))


# --- the sinks -----------------------------------------------------------------------------------


def test_the_logging_sink_warns_on_a_pause_and_logs_the_resume_at_debug(
    caplog: pytest.LogCaptureFixture,
) -> None:
    sink = LoggingAlertSink()
    with caplog.at_level(logging.DEBUG, logger="messagefoundry.pipeline.alerts"):
        sink.intake_paused(
            "intake:staged_depth", reason=DEPTH_REASON, value=11, limit=10, store_kind="sqlite"
        )
        sink.intake_resumed(
            "intake:staged_depth", reason=DEPTH_REASON, value=3, limit=10, store_kind="sqlite"
        )
    paused, resumed = caplog.records
    assert paused.levelno == logging.WARNING and "ALERT intake_paused" in paused.getMessage()
    assert "staged_depth: 11" in paused.getMessage() and "sqlite" in paused.getMessage()
    assert resumed.levelno == logging.DEBUG and "intake_resumed" in resumed.getMessage()


class _RecordingTransport:
    name = "webhook"

    def __init__(self) -> None:
        self.events: list[dict[str, Any]] = []

    async def send(self, event: dict[str, Any], **_kw: Any) -> None:
        self.events.append(event)


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
        self.upserts.append({"event_type": event_type, "connection": connection, "reason": reason})

    async def resolve_alert_instances_for(
        self, *, event_type: str, connection: str, now: float | None = None
    ) -> int:
        self.resolves.append({"event_type": event_type, "connection": connection})
        return 1

    async def list_active_alert_instances(self, *, limit: int = 1000) -> list[Any]:
        return []


async def _drain(sink: NotifierAlertSink) -> None:
    sink.start()
    await asyncio.sleep(0)
    await sink.aclose()
    for _ in range(10):
        if not sink._state_tasks:
            break
        await asyncio.gather(*list(sink._state_tasks), return_exceptions=True)
        await asyncio.sleep(0)


async def test_the_notifier_pages_the_pause_and_resolves_it_on_resume() -> None:
    transport, store = _RecordingTransport(), _RecordingStore()
    sink = NotifierAlertSink([transport], store=store)
    sink.intake_paused(
        "intake:disk_floor", reason=DISK_REASON, value=512, limit=1024, store_kind="sqlite"
    )
    sink.intake_resumed(
        "intake:disk_floor", reason=DISK_REASON, value=1200, limit=1024, store_kind="sqlite"
    )
    await _drain(sink)
    assert len(transport.events) == 1, "a resume needs no page"
    event = transport.events[0]
    assert event["type"] == "intake_paused" and event["connection"] == "intake:disk_floor"
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
    assert "512 MiB free" in event["detail"]
    assert store.upserts[0]["event_type"] == "intake_paused"
    assert store.upserts[0]["reason"] == event["detail"]
    assert store.resolves == [{"event_type": "intake_paused", "connection": "intake:disk_floor"}]


def test_the_notifier_unit_label_matches_the_monitors_disk_reason() -> None:
    """The notifier spells the disk reason as a literal so it need not import the monitor."""
    assert DISK_REASON == "disk_floor"


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


def _write_quiet_config(tmp_path: Path, extra: str = "") -> None:
    """tests/test_storage_floor.py's loopback fixture, which reaches a clean exit 0."""
    (tmp_path / "messagefoundry.toml").write_text(
        "security.block_unlisted_outbound = true\n"
        'alerts.email_smtp_host = "smtp.example.org"\n'
        'alerts.email_from = "sec@example.org"\n'
        'alerts.email_to = ["ops@example.org"]\n'
        "security.delete_message_bodies_after_days = 30\n"
        "retention.dead_letter_days = 30\n"
        "retention.reference_snapshot_days = 30\n"
        "retention.state_max_age_days = 30\n"
        "retention.search_preset_days = 30\n"
        "security.local_access_only = true\n" + extra,
        encoding="utf-8",
    )


@pytest.fixture
def serve_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    from messagefoundry.store.crypto import generate_key

    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("MEFOR_STORE_ENCRYPTION_KEY", generate_key())
    monkeypatch.setattr("uvicorn.run", lambda *a, **k: None)
    monkeypatch.setattr(shutil, "disk_usage", _Disk(free_mib=4096))  # well over the floor
    return tmp_path


def _serve() -> int:
    return main(["serve", "--config", str(SAMPLES_CONFIG), "--env", "dev"])


def _rung_lines(text: str) -> list[str]:
    return [ln for ln in text.splitlines() if _RUNG in ln and "unbounded" in ln]


def test_the_rung_warns_once_under_enforce_and_still_starts(
    serve_env: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _write_quiet_config(serve_env)  # the dial ships enforcing and the bound ships unset
    assert _serve() == 0
    captured = capsys.readouterr()
    # serve's own logging handler writes to stdout (NSSM captures it), so the line lands there.
    lines = _rung_lines(captured.out)
    assert len(lines) == 1
    assert "WARNING" in lines[0]
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
