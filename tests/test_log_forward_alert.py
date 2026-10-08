# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A log forwarder that is absent or losing records raises an alert and shows on ``GET /status``
(BACKLOG #2612).

Three layers, each tested where it lives: the in-memory reading
(:func:`~messagefoundry.logging_setup.forwarder_status`), the runner's check that turns a reading
into an alert, and the status model. No test opens a socket or resolves a name.
"""

from __future__ import annotations

import asyncio
import logging
import queue
import socket
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from messagefoundry import logging_setup
from messagefoundry.api.app import _log_forwarder_health
from messagefoundry.config.models import ConnectorType
from messagefoundry.config.settings import (
    _ALERT_CONTROL_EVENT_TYPES,
    _ALERT_EVENT_TYPES,
    AlertRule,
    EgressSettings,
)
from messagefoundry.config.wiring import ConnectionSpec, InboundConnection, Registry
from messagefoundry.logging_setup import (
    ForwarderStatus,
    SyslogForward,
    _ForwardQueueHandler,
    _ForwardQueueListener,
    _TimeoutSysLogHandler,
    configure_logging,
    forwarder_status,
)
from messagefoundry.pipeline import wiring_runner
from messagefoundry.pipeline.alert_sinks import NotifierAlertSink
from messagefoundry.pipeline.alerts import AlertSink, LoggingAlertSink
from messagefoundry.pipeline.wiring_runner import RegistryRunner
from messagefoundry.store.store import MessageStore

#: Synthetic HL7 (never real PHI). It goes through a forwarder that drops it, and must not come
#: back out in an alert.
SYNTHETIC_RECORD = "PID|1||100^^^H^MR||DOE^JANE^Q||19800101|F"

FORWARD = SyslogForward(host="collector.invalid", port=6514, protocol="tcp")


@pytest.fixture(autouse=True)
def _no_network_and_restored_logging(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """No name lookup, and the root logger and the module's forwarder state put back afterwards."""

    def _no_dns(*args: Any, **kwargs: Any) -> Any:
        raise AssertionError("a forwarder health test resolved a name")

    monkeypatch.setattr(socket, "getaddrinfo", _no_dns)
    monkeypatch.setattr(logging_setup, "_forward_configured", False)
    monkeypatch.setattr(logging_setup, "_forward_start_failure", "")
    root = logging.getLogger()
    saved, level = root.handlers[:], root.level
    try:
        yield
    finally:
        for handler in root.handlers[:]:
            root.removeHandler(handler)
            if handler not in saved:
                handler.close()
        for handler in saved:
            root.addHandler(handler)
        root.setLevel(level)


class _RecordingSink(LoggingAlertSink):
    def __init__(self) -> None:
        self.forward_failures: list[tuple[str, str, str, int]] = []

    def log_forward_failed(self, name: str, *, kind: str, reason: str, count: int = 0) -> None:
        self.forward_failures.append((name, kind, reason, count))


@pytest.fixture
async def store(tmp_path: Path) -> Any:
    s = await MessageStore.open(tmp_path / "forward.db")
    yield s
    await s.close()


def _runner(store: MessageStore, sink: AlertSink) -> RegistryRunner:
    reg = Registry()
    reg.add_inbound(
        InboundConnection(
            "IB_TEST_ADT",
            ConnectionSpec(ConnectorType.MLLP, {"host": "127.0.0.1", "port": 0}),
            router="r",
        )
    )
    reg.add_router("r", lambda m: [])
    return RegistryRunner(
        reg,
        store,
        poll_interval=0.02,
        alert_sink=sink,
        egress=EgressSettings(deny_by_default=False),
    )


def _fail_the_start(monkeypatch: pytest.MonkeyPatch, exc: OSError) -> None:
    def _refuse(self: Any) -> None:
        raise exc

    monkeypatch.setattr(_TimeoutSysLogHandler, "createSocket", _refuse)


class _Collector(logging.Handler):
    """A stand-in for the socket handler. ``down`` makes every send a network failure, reported
    the way :meth:`_TimeoutSysLogHandler.handleError` reports one."""

    def __init__(self, *, down: bool = False) -> None:
        super().__init__()
        self.down = down
        self.send_failed = False
        self.lines: list[str] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.send_failed = self.down
        if not self.down:
            self.lines.append(record.getMessage())


def _attach(
    collector: _Collector, *, maxsize: int = 100
) -> tuple[_ForwardQueueHandler, _ForwardQueueListener]:
    """A forwarder on the root logger whose listener thread is NOT started, so the test decides
    when a record leaves the queue."""
    records: queue.Queue[Any] = queue.Queue(maxsize=maxsize)
    listener = _ForwardQueueListener(records, collector)
    handler = _ForwardQueueHandler(records, listener)
    handler.setFormatter(logging.Formatter("%(message)s"))
    logging.getLogger().addHandler(handler)
    logging_setup._forward_configured = True
    return handler, listener


def _record(text: str) -> logging.LogRecord:
    return logging.LogRecord("mefor.test", logging.INFO, __file__, 1, text, None, None)


# --- the reading -------------------------------------------------------------------------------


def test_no_forwarder_configured_reads_off() -> None:
    configure_logging("INFO")
    status = forwarder_status()
    assert status == ForwarderStatus()
    assert status.state == "off"
    assert _log_forwarder_health() is None


@pytest.mark.parametrize(
    ("exc", "word"),
    [
        (socket.gaierror(11001, "no such name"), "permanent"),
        (ConnectionRefusedError("collector down"), "transient"),
    ],
)
def test_a_forwarder_that_fails_at_start_reads_not_installed(
    monkeypatch: pytest.MonkeyPatch, exc: OSError, word: str
) -> None:
    _fail_the_start(monkeypatch, exc)
    assert configure_logging("INFO", forward=FORWARD) is False  # and the start goes on
    status = forwarder_status()
    assert (status.configured, status.installed, status.start_failure) == (True, False, word)
    assert status.state == "not_installed"
    info = _log_forwarder_health()
    assert info is not None
    assert (info.state, info.installed, info.start_failure) == ("not_installed", False, word)
    # A fixed word, never the exception text or the host.
    dumped = info.model_dump_json()
    assert "collector" not in dumped and "no such name" not in dumped


def test_a_later_configure_without_a_forwarder_clears_the_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _fail_the_start(monkeypatch, ConnectionRefusedError("collector down"))
    configure_logging("INFO", forward=FORWARD)
    configure_logging("INFO")
    assert forwarder_status() == ForwarderStatus()


def test_a_healthy_forwarder_reads_healthy() -> None:
    collector = _Collector()
    handler, listener = _attach(collector)
    handler.handle(_record("one"))
    assert forwarder_status().queued == 1  # a level, not a loss
    listener.handle(handler._records.get_nowait())
    status = forwarder_status()
    assert collector.lines == ["one"]
    assert (status.installed, status.lost, status.queued, status.state) == (True, 0, 0, "healthy")
    info = _log_forwarder_health()
    assert info is not None and info.state == "healthy"


def test_a_full_queue_is_counted_and_reads_degraded() -> None:
    handler, _ = _attach(_Collector(), maxsize=1)
    for _ in range(3):
        handler.handle(_record(SYNTHETIC_RECORD))
    status = forwarder_status()
    # Two of the three did not fit. The drop warning is a record too, so the count may be higher.
    assert status.queue_dropped == handler.dropped >= 2
    assert status.lost == status.queue_dropped
    assert status.state == "degraded"


def test_a_send_that_fails_with_no_spool_is_counted_as_unsent() -> None:
    # Before BACKLOG #2612 this record was lost with no count: nothing rose until the queue filled.
    collector = _Collector(down=True)
    handler, listener = _attach(collector)
    listener.handle(_record("one"))
    status = forwarder_status()
    assert (status.unsent, status.send_failing, status.state) == (1, True, "degraded")
    collector.down = False
    listener.handle(_record("two"))
    status = forwarder_status()
    assert (status.unsent, status.send_failing) == (1, False)
    assert status.state == "degraded"  # the lost record is still missing at the collector
    assert handler.dropped == 0


def test_a_closed_forwarder_is_not_reported_as_installed() -> None:
    handler, _ = _attach(_Collector())
    handler.close()
    assert forwarder_status().installed is False


# --- the runner's check ------------------------------------------------------------------------


async def test_a_failed_start_raises_the_alert_once(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    _fail_the_start(monkeypatch, socket.gaierror(11001, "no such name"))
    configure_logging("INFO", forward=FORWARD)
    sink = _RecordingSink()
    runner = _runner(store, sink)
    for _ in range(3):
        runner._check_log_forwarder()
    assert sink.forward_failures == [("forwarder", "not_installed", "permanent", 0)]


async def test_a_rising_drop_count_raises_the_alert_with_no_record_text(
    store: MessageStore,
) -> None:
    handler, _ = _attach(_Collector(), maxsize=1)
    sink = _RecordingSink()
    runner = _runner(store, sink)
    runner._check_log_forwarder(now=0.0)
    assert sink.forward_failures == []  # nothing lost yet
    for _ in range(3):
        handler.handle(_record(SYNTHETIC_RECORD))
    dropped = handler.dropped
    runner._check_log_forwarder(now=1.0)
    assert sink.forward_failures == [("forwarder", "dropping", "queue_full", dropped)]
    assert "DOE" not in repr(sink.forward_failures) and "PID" not in repr(sink.forward_failures)


async def test_a_healthy_forwarder_raises_nothing(store: MessageStore) -> None:
    collector = _Collector()
    handler, listener = _attach(collector)
    sink = _RecordingSink()
    runner = _runner(store, sink)
    for now in (0.0, 1_000.0):
        handler.handle(_record("fine"))
        listener.handle(handler._records.get_nowait())
        runner._check_log_forwarder(now=now)
    assert sink.forward_failures == []


async def test_no_forwarder_raises_nothing(store: MessageStore) -> None:
    configure_logging("INFO")
    sink = _RecordingSink()
    _runner(store, sink)._check_log_forwarder()
    assert sink.forward_failures == []


def _reading(**counts: int) -> ForwarderStatus:
    return ForwarderStatus(configured=True, installed=True, **counts)  # type: ignore[arg-type]


async def test_a_rise_is_throttled_and_the_throttled_part_is_carried(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    readings = iter(
        [
            _reading(queue_dropped=2),
            _reading(queue_dropped=5),  # inside the window: no alert
            _reading(queue_dropped=5, unsent=2),  # past it: the 3 and the 2 together
            _reading(queue_dropped=5, unsent=2),  # nothing new
            _reading(queue_dropped=5, unsent=2, spool_read_errors=4),
            _reading(),  # a rebuilt forwarder: counts restart, and that is not a loss
            _reading(spool_dropped=1, undeliverable=1),
        ]
    )
    monkeypatch.setattr(wiring_runner, "forwarder_status", lambda: next(readings))
    sink = _RecordingSink()
    runner = _runner(store, sink)
    window = wiring_runner._BUILDUP_REALERT_SECONDS
    for now in (0.0, 10.0, window + 1, 2 * window + 2, 3 * window + 3, 4 * window + 4, 5 * window):
        runner._check_log_forwarder(now=now)
    assert sink.forward_failures == [
        ("forwarder", "dropping", "queue_full", 2),
        ("forwarder", "dropping", "queue_full,collector_unreachable", 5),
        ("forwarder", "spool_unreadable", "spool_read_failed", 4),
        ("forwarder", "dropping", "send_error,spool_refused", 2),
    ]


async def test_a_sink_that_raises_does_not_escape_the_check(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    class _Raising(LoggingAlertSink):
        def log_forward_failed(self, name: str, **_kw: Any) -> None:
            raise RuntimeError("sink bug")

    monkeypatch.setattr(wiring_runner, "forwarder_status", lambda: _reading(queue_dropped=1))
    _runner(store, _Raising())._check_log_forwarder(now=0.0)  # logs, never raises


# --- the alert type ----------------------------------------------------------------------------


def test_the_event_type_is_rule_targetable_and_takes_no_control_action() -> None:
    assert "log_forward_failed" in _ALERT_EVENT_TYPES
    assert "log_forward_failed" not in _ALERT_CONTROL_EVENT_TYPES  # "forwarder" is no connection
    assert AlertRule(event_type="log_forward_failed").event_type == "log_forward_failed"


class _RecordingTransport:
    name = "t"

    def __init__(self) -> None:
        self.events: list[dict[str, Any]] = []

    async def send(self, event: dict[str, Any], **_kw: Any) -> None:
        self.events.append(event)


async def test_the_notifier_payload_is_counts_and_fixed_words() -> None:
    transport = _RecordingTransport()
    sink = NotifierAlertSink([transport])
    sink.log_forward_failed("forwarder", kind="dropping", reason="queue_full", count=7)
    sink.start()
    await asyncio.sleep(0)
    await sink.aclose()
    assert len(transport.events) == 1
    event = transport.events[0]
    assert event["type"] == "log_forward_failed"
    assert event["connection"] == "forwarder"
    assert (event["kind"], event["detail"], event["count"]) == (
        "dropping",
        "dropping: queue_full",
        7,
    )


def test_the_logging_sink_writes_one_line(caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level(logging.WARNING, logger="messagefoundry.pipeline.alerts"):
        LoggingAlertSink().log_forward_failed("forwarder", kind="not_installed", reason="permanent")
    assert [r.getMessage() for r in caplog.records] == [
        "ALERT log_forward_failed: forwarder not_installed (permanent; count 0)"
    ]
