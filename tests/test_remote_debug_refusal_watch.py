# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A script the remote-debugging guard refused gets an audit row and an alert (vault BACKLOG #2742,
item 3).

The owner's ruling (2026-10-13) fixes four things, and each has a test here: one audit action and
one alert kind, both named ``remote_debug_refused``; ``serve`` only; one row and one alert for each
pass, carrying a count; and no file name in the row or in the alert.

**How a refusal is driven.** An injection needs the operating system's leave to attach to a
process, which not every platform gives a test. So these tests call the guard's real hook function
with the interpreter's event, as ``tests/test_remote_debug_guard.py`` does. That moves the real
count the watch reads. The injection itself, through ``sys.remote_exec`` into a child, is that
file's subject. One test here does run a child interpreter: the state where an earlier audit hook
raises on the engine's probe event cannot be built in this process, because an audit hook cannot
be removed.
"""

from __future__ import annotations

import ast
import asyncio
import json
import logging
import os
import queue
import subprocess
import sys
import threading
from collections.abc import AsyncIterator, Callable
from pathlib import Path
from typing import Any, cast

import pytest
from pydantic import ValidationError

from messagefoundry import remotedebug
from messagefoundry.config.settings import (
    _ALERT_CONTROL_EVENT_TYPES,
    _ALERT_EVENT_TYPES,
    AlertRule,
    EgressSettings,
)
from messagefoundry.connection_names import is_connection_name
from messagefoundry.pipeline import Engine, remote_debug_watch
from messagefoundry.pipeline.alert_sinks import _AUTO_RESOLVE, NotifierAlertSink
from messagefoundry.pipeline.alerts import AlertSink, LoggingAlertSink, remote_debug_refused_detail
from messagefoundry.pipeline.intake_bound import INTAKE_SUBJECT_MAX_LENGTH
from messagefoundry.pipeline.remote_debug_watch import (
    AUDIT_ACTION,
    CHECK_INTERVAL_SECONDS,
    RemoteDebugRefusalWatch,
)
from messagefoundry.remotedebug import REMOTE_SCRIPT_EVENT, RemoteScriptRefused
from messagefoundry.store.base import AuditStore
from messagefoundry.store.store import MessageStore
from tests import test_remote_debug_guard as _guard_tests
from tests._ast_sites import call_sites, code_names, parse_source
from tests._refusal_log_capture import TOKEN, assert_no_token, until
from tests.test_alert_sinks import _drain as _drain_transports
from tests.test_alert_sinks import _RecordingTransport
from tests.test_alert_state import _drain as _drain_state
from tests.test_alert_state import _RecordingStore

_REPO = Path(__file__).resolve().parents[1]
_ENGINE = _REPO / "messagefoundry"

#: A file name the injecting process might choose. It holds the shared planted token, so the
#: shared scan finds it, and its absence from a row is a finding and not an accident.
PLANTED_NAME = f"{TOKEN}-script.py"
PLANTED_PATH = os.path.join("some", "directory", PLANTED_NAME)

# The guard suite's fixture, bound here by name so pytest finds it in this module too: a count at
# zero and a private report queue for each test, both put back afterwards. One copy, so a new
# piece of guard state is isolated in one place.
reports = _guard_tests.reports


@pytest.fixture
def refuse(reports: queue.SimpleQueue[str]) -> Callable[..., None]:
    """Refuse one injected script, through the guard's real hook function."""

    def _refuse(path: str = PLANTED_PATH, *, times: int = 1) -> None:
        for _ in range(times):
            with pytest.raises(RemoteScriptRefused):
                remotedebug._guard(REMOTE_SCRIPT_EVENT, (path,))

    return _refuse


@pytest.fixture
async def store(tmp_path: Path) -> AsyncIterator[MessageStore]:
    opened = await MessageStore.open(tmp_path / "watch.db")
    try:
        yield opened
    finally:
        await opened.close()


async def _rows(store: MessageStore) -> list[dict[str, Any]]:
    """The watch's audit rows, oldest first, each with its detail parsed."""
    rows = await store.recent_audit_of([AUDIT_ACTION], limit=50)
    return [{**row, "detail": json.loads(row["detail"])} for row in reversed(rows)]


class _RefusingStore:
    """An audit store that refuses every write while ``down`` is set, and records the rest."""

    def __init__(self) -> None:
        self.down = False
        self.written: list[tuple[str, str | None, dict[str, Any]]] = []

    async def record_audit(
        self, action: str, *, actor: str | None = None, detail: str | None = None, **_kw: Any
    ) -> None:
        if self.down:
            raise RuntimeError("the audit log refuses writes")
        self.written.append((action, actor, json.loads(detail or "{}")))


class _Sink(LoggingAlertSink):
    """Records the refusal alert. Every other event logs, so an engine can run on it. While
    ``down`` is set the call raises, as a broken sink would."""

    def __init__(self) -> None:
        self.alerts: list[tuple[str, int, int]] = []
        self.threads: list[str] = []
        self.down = False

    def remote_debug_refused(self, name: str, *, count: int, total: int) -> None:
        if self.down:
            raise RuntimeError("sink down")
        self.threads.append(threading.current_thread().name)
        self.alerts.append((name, count, total))


def _on(store: object, **kw: Any) -> RemoteDebugRefusalWatch:
    return RemoteDebugRefusalWatch(cast(AuditStore, store), **kw)


# --- one row for each pass, with a count ---------------------------------------------------------


# 500 is the flood: the injecting process sets the rate, and a pass still adds one row.
@pytest.mark.parametrize("refusals", [3, 1, 500])
async def test_the_refusals_between_two_passes_make_one_row_with_their_count(
    store: MessageStore, refuse: Callable[..., None], refusals: int
) -> None:
    watch = _on(store)
    refuse(times=refusals)
    await watch.run_once()

    (row,) = await _rows(store)
    assert row["action"] == "remote_debug_refused"
    assert row["detail"] == {
        "count": refusals,
        "total": refusals,
        "process": None,
        "pid": os.getpid(),
    }
    # The engine wrote it, not a user, and no client address was in scope.
    assert row["actor"] == "system"


async def test_no_refusal_makes_no_row(store: MessageStore, refuse: Callable[..., None]) -> None:
    watch = _on(store)
    await watch.run_once()
    await watch.run_once()
    assert await _rows(store) == []
    # CONTROL: the same watch on the same store does write once something is refused, so the
    # empty reading above is not a watch that cannot write.
    refuse()
    await watch.run_once()
    assert len(await _rows(store)) == 1


async def test_two_passes_with_refusals_in_each_make_two_rows(
    store: MessageStore, refuse: Callable[..., None]
) -> None:
    watch = _on(store)
    refuse(times=2)
    await watch.run_once()
    refuse(times=5)
    await watch.run_once()
    await watch.run_once()  # nothing new: no third row

    assert [(row["detail"]["count"], row["detail"]["total"]) for row in await _rows(store)] == [
        (2, 2),
        (5, 7),
    ]


async def test_the_first_pass_counts_from_the_start_of_the_process(
    store: MessageStore, refuse: Callable[..., None]
) -> None:
    """A refusal made before the watch exists is one made before the engine opened its store. A
    caller who can restart the engine aims for exactly that window."""
    refuse(times=4)
    watch = _on(store)
    await watch.run_once()
    (row,) = await _rows(store)
    assert (row["detail"]["count"], row["detail"]["total"]) == (4, 4)


async def test_the_row_names_the_engine_process(
    store: MessageStore, refuse: Callable[..., None]
) -> None:
    watch = _on(store, node="node:engine-b")
    refuse()
    await watch.run_once()
    (row,) = await _rows(store)
    assert row["detail"]["process"] == "node:engine-b"


# --- no file name --------------------------------------------------------------------------------


async def test_the_file_name_is_in_the_warning_and_not_in_the_row(
    store: MessageStore, refuse: Callable[..., None], caplog: pytest.LogCaptureFixture
) -> None:
    watch = _on(store)
    refuse(PLANTED_PATH)
    await watch.run_once()

    (raw,) = await store.recent_audit_of([AUDIT_ACTION], limit=5)
    assert PLANTED_NAME not in json.dumps(raw, default=str)
    assert TOKEN not in json.dumps(raw, default=str)
    # CONTROL: the hook did see that name, and the guard's WARNING line carries it. So the name
    # was there to leak, and the search above could have found it.
    queued = remotedebug._reports.get_nowait()
    assert queued == PLANTED_NAME
    with caplog.at_level(logging.WARNING, logger="messagefoundry.remotedebug"):
        remotedebug._report(queued)
    assert PLANTED_NAME in caplog.records[-1].getMessage()


async def test_a_refused_row_is_logged_without_a_file_name(
    refuse: Callable[..., None], caplog: pytest.LogCaptureFixture
) -> None:
    """The ERROR line for a row the store refused prints the row's detail, which holds no name."""
    refusing = _RefusingStore()
    refusing.down = True
    watch = _on(refusing)
    refuse(PLANTED_PATH)
    with caplog.at_level(logging.ERROR, logger=remote_debug_watch.__name__):
        await watch.run_once()
    (record,) = caplog.records
    assert record.levelno == logging.ERROR
    assert "remote_debug_refused audit row failed" in record.getMessage()
    assert '"count": 1' in record.getMessage()
    assert_no_token(caplog.records)  # message, args and traceback


# --- a row the store refuses is owed -------------------------------------------------------------


async def test_a_row_the_store_refuses_is_written_by_a_later_pass_with_the_larger_count(
    refuse: Callable[..., None],
) -> None:
    refusing = _RefusingStore()
    watch = _on(refusing)
    refusing.down = True
    refuse(times=2)
    await watch.run_once()
    refuse(times=3)
    await watch.run_once()
    assert refusing.written == []

    refusing.down = False
    await watch.run_once()
    await watch.run_once()  # paid: nothing more is owed
    ((action, actor, detail),) = refusing.written
    assert (action, actor) == ("remote_debug_refused", "system")
    assert (detail["count"], detail["total"]) == (5, 5)


async def test_two_passes_at_once_write_one_row(refuse: Callable[..., None]) -> None:
    """The mark moves after the write. Without a turn each, both passes would read the same
    refusals as unreported and each write a row for them."""

    class _Slow(_RefusingStore):
        async def record_audit(self, action: str, **kw: Any) -> None:
            await asyncio.sleep(0.01)
            await super().record_audit(action, **kw)

    slow = _Slow()
    watch = _on(slow)
    refuse(times=3)
    await asyncio.gather(watch.run_once(), watch.run_once())
    assert [(d["count"], d["total"]) for _a, _actor, d in slow.written] == [(3, 3)]


# --- one alert for each pass, with a count -------------------------------------------------------


@pytest.mark.parametrize("refusals", [3, 1, 500])
async def test_the_refusals_between_two_passes_make_one_alert_with_their_count(
    refuse: Callable[..., None], refusals: int
) -> None:
    sink, audit = _Sink(), _RefusingStore()
    watch = _on(audit, alert_sink=sink)
    refuse(times=refusals)
    await watch.run_once()
    assert sink.alerts == [("remote_debug:refused", refusals, refusals)]
    # One row beside it, with the same count: the two say the same thing.
    assert [(d["count"], d["total"]) for _a, _actor, d in audit.written] == [(refusals, refusals)]


async def test_no_refusal_raises_no_alert(refuse: Callable[..., None]) -> None:
    sink = _Sink()
    watch = _on(_RefusingStore(), alert_sink=sink)
    await watch.run_once()
    await watch.run_once()
    assert sink.alerts == []
    # CONTROL: the same watch and sink do raise once something is refused.
    refuse()
    await watch.run_once()
    assert len(sink.alerts) == 1


async def test_two_passes_with_refusals_in_each_raise_two_alerts(
    refuse: Callable[..., None],
) -> None:
    sink = _Sink()
    watch = _on(_RefusingStore(), alert_sink=sink)
    refuse(times=2)
    await watch.run_once()
    refuse(times=5)
    await watch.run_once()
    await watch.run_once()  # nothing new: no third alert
    assert [(count, total) for _name, count, total in sink.alerts] == [(2, 2), (5, 7)]


async def test_the_file_name_is_in_the_warning_and_not_in_the_alert(
    refuse: Callable[..., None], caplog: pytest.LogCaptureFixture
) -> None:
    """Through the shipped notifier, to a transport and to the alert-state store: what an
    operator's webhook receives and what the alert list shows."""
    transport, state = _RecordingTransport("webhook"), _RecordingStore()
    sink = NotifierAlertSink([transport], store=cast(Any, state))
    watch = _on(_RefusingStore(), alert_sink=sink)
    refuse(PLANTED_PATH)
    with caplog.at_level(logging.WARNING):
        await watch.run_once()
        await _drain_state(sink)
        await _drain_transports(sink)

    (event,) = transport.events
    (row,) = state.upserts
    # Two counts and fixed words, plus the ts and severity the framework adds.
    assert set(event) == {"type", "connection", "count", "total", "detail", "ts", "severity"}
    assert (event["type"], event["connection"]) == ("remote_debug_refused", "remote_debug:refused")
    assert (event["count"], event["total"]) == (1, 1)
    assert event["detail"] == row["reason"] == remote_debug_refused_detail(count=1, total=1)
    assert (row["event_type"], row["connection"]) == (
        "remote_debug_refused",
        "remote_debug:refused",
    )
    for carrier in (repr(event), repr(state.upserts)):
        assert TOKEN not in carrier
    assert_no_token(caplog.records)  # the alert's own log lines, and the failed-row ERROR
    # CONTROL: the hook did see that name, and the guard's WARNING line carries it. So the name
    # was there to leak, and the search above could have found it.
    queued = remotedebug._reports.get_nowait()
    assert queued == PLANTED_NAME
    with caplog.at_level(logging.WARNING, logger="messagefoundry.remotedebug"):
        remotedebug._report(queued)
    assert PLANTED_NAME in caplog.records[-1].getMessage()


def test_the_logging_sink_warns_with_two_counts_and_fixed_words(
    caplog: pytest.LogCaptureFixture,
) -> None:
    with caplog.at_level(logging.WARNING, logger="messagefoundry.pipeline.alerts"):
        LoggingAlertSink().remote_debug_refused("remote_debug:refused", count=3, total=7)
    (record,) = caplog.records
    assert record.levelno == logging.WARNING
    message = record.getMessage()
    assert message.startswith("ALERT remote_debug_refused: 'remote_debug:refused' refused 3 ")
    assert "(7 since this process started)" in message and "None ran" in message


def test_the_detail_leads_with_the_count_and_fits_the_reason_column() -> None:
    detail = remote_debug_refused_detail(count=12, total=40)
    assert detail.startswith("refused 12 script(s)")
    # The store keeps about the first 200 characters of a reason.
    assert len(remote_debug_refused_detail(count=10**6, total=10**6)) <= 200


# --- each is owed each refusal once --------------------------------------------------------------


async def test_a_sink_that_raises_is_retried_with_the_larger_count(
    refuse: Callable[..., None], caplog: pytest.LogCaptureFixture
) -> None:
    sink, audit = _Sink(), _RefusingStore()
    watch = _on(audit, alert_sink=sink)
    sink.down = True
    refuse(times=2)
    with caplog.at_level(logging.ERROR, logger=remote_debug_watch.__name__):
        await watch.run_once()
    assert any("alert could not be raised" in r.getMessage() for r in caplog.records)
    refuse(times=3)
    sink.down = False
    await watch.run_once()
    await watch.run_once()  # paid: nothing more is owed
    assert sink.alerts == [("remote_debug:refused", 5, 5)]
    # The rows did not wait for the sink: each pass wrote its own.
    assert [(d["count"], d["total"]) for _a, _actor, d in audit.written] == [(2, 2), (3, 5)]


async def test_a_refused_row_neither_stops_nor_repeats_the_alert(
    refuse: Callable[..., None],
) -> None:
    sink, audit = _Sink(), _RefusingStore()
    watch = _on(audit, alert_sink=sink)
    audit.down = True
    refuse(times=2)
    await watch.run_once()
    await watch.run_once()  # the row is still owed; the alert is not
    assert sink.alerts == [("remote_debug:refused", 2, 2)]
    audit.down = False
    await watch.run_once()
    assert len(audit.written) == 1 and len(sink.alerts) == 1


# --- on the event loop ---------------------------------------------------------------------------


async def test_the_loop_raises_on_the_event_loop_and_the_alert_store_gets_its_row(
    refuse: Callable[..., None],
) -> None:
    transport, state = _RecordingTransport("webhook"), _RecordingStore()
    sink = NotifierAlertSink([transport], store=cast(Any, state))
    audit = _RefusingStore()
    watch = _on(audit, alert_sink=sink, interval_seconds=0.01)
    refuse(times=3)
    watch.start()
    try:
        await until(lambda: bool(audit.written), "the watch's first pass")
    finally:
        await watch.stop()
    await _drain_state(sink)
    await _drain_transports(sink)

    assert [row["connection"] for row in state.upserts] == ["remote_debug:refused"]
    assert [event["count"] for event in transport.events] == [3]
    # The control: the same call from a worker thread writes no row. So the row above proves the
    # watch raised on the loop.
    await asyncio.to_thread(sink.remote_debug_refused, "remote_debug:control", count=1, total=1)
    await _drain_state(sink)
    assert [row["connection"] for row in state.upserts] == ["remote_debug:refused"]


async def test_the_loop_raises_from_the_loop_thread(refuse: Callable[..., None]) -> None:
    sink = _Sink()
    watch = _on(_RefusingStore(), alert_sink=sink, interval_seconds=0.01)
    refuse()
    watch.start()
    try:
        await until(lambda: bool(sink.alerts), "the refusal alert")
    finally:
        await watch.stop()
    assert sink.threads == [threading.current_thread().name]


# --- the alert type ------------------------------------------------------------------------------


def test_the_alert_is_rule_targetable_and_takes_no_control_action() -> None:
    assert "remote_debug_refused" in _ALERT_EVENT_TYPES
    assert "remote_debug_refused" not in _ALERT_CONTROL_EVENT_TYPES
    AlertRule(event_type="remote_debug_refused")
    with pytest.raises(ValidationError, match="connection-scoped event_type"):
        AlertRule(event_type="remote_debug_refused", control_action="restart_inbound")


def test_the_alert_has_no_inverse() -> None:
    """A refusal is an event, not a state that clears, so nothing auto-resolves it."""
    assert "remote_debug_refused" not in _AUTO_RESOLVE.values()
    assert not [inverse for inverse in _AUTO_RESOLVE if inverse.startswith("remote_debug")]
    # CONTROL: the map is populated, so the two readings above are not of an empty map.
    assert _AUTO_RESOLVE["crl_reload_applied"] == "crl_reload_refused"


def test_every_shipped_sink_implements_the_alert() -> None:
    for cls in (LoggingAlertSink, NotifierAlertSink):
        assert callable(getattr(cls, "remote_debug_refused", None)), cls.__name__
    assert callable(getattr(AlertSink, "remote_debug_refused", None))


def test_the_subject_names_the_process_and_is_no_connection_name() -> None:
    lone = _on(_RefusingStore())
    node = _on(_RefusingStore(), node="node:engine-b")
    long_node = _on(_RefusingStore(), node="node:" + "h" * 400)
    assert lone._subject == "remote_debug:refused"
    assert node._subject == "remote_debug:refused@node:engine-b"
    assert len(long_node._subject) <= INTAKE_SUBJECT_MAX_LENGTH
    for subject in (lone._subject, node._subject, long_node._subject):
        assert not is_connection_name(subject)


async def test_two_processes_on_one_store_keep_two_alert_instances(
    store: MessageStore, refuse: Callable[..., None]
) -> None:
    """On a real store: each process's alert is its own ``alert_instance`` row, and a second
    raise from one process stays on that process's row."""
    for node in ("shard:a", "shard:b"):
        sink = NotifierAlertSink([], store=store)
        watch = _on(_RefusingStore(), alert_sink=sink, node=node)
        refuse()
        await watch.run_once()
        refuse()
        await watch.run_once()
        await sink.drain_state(5.0)
    rows = await store.list_active_alert_instances(allowed_channels=None)
    mine = sorted(
        (row.connection, row.count) for row in rows if row.event_type == "remote_debug_refused"
    )
    assert mine == [("remote_debug:refused@shard:a", 2), ("remote_debug:refused@shard:b", 2)]


# --- the loop ------------------------------------------------------------------------------------


async def test_the_loop_passes_at_once_and_again_as_it_stops(
    refuse: Callable[..., None],
) -> None:
    """An hour-long interval, so only the first pass and the last one can have run."""
    refusing = _RefusingStore()
    watch = _on(refusing, interval_seconds=3600.0)
    refuse(times=2)
    watch.start()
    try:
        await until(lambda: len(refusing.written) == 1, "the first pass's row")
        refuse(times=3)  # in the last interval: no timed pass will come for it
    finally:
        await watch.stop()
    assert [(d["count"], d["total"]) for _a, _actor, d in refusing.written] == [(2, 2), (3, 5)]
    await watch.stop()  # idempotent


async def test_a_pass_that_fails_does_not_end_the_loop(
    refuse: Callable[..., None], caplog: pytest.LogCaptureFixture
) -> None:
    refusing = _RefusingStore()
    readings = iter([RuntimeError("no reading")])

    def read() -> int:
        fault = next(readings, None)
        if fault is not None:
            raise fault
        return 1

    watch = _on(refusing, read=read, interval_seconds=0.01)
    with caplog.at_level(logging.ERROR, logger=remote_debug_watch.__name__):
        watch.start()
        try:
            await until(lambda: bool(refusing.written), "the row after the failed pass")
        finally:
            await watch.stop()
    assert any("check failed" in record.getMessage() for record in caplog.records)
    assert len(refusing.written) == 1


async def test_a_last_pass_that_hangs_is_cancelled(
    refuse: Callable[..., None], monkeypatch: pytest.MonkeyPatch
) -> None:
    class _Hung(_RefusingStore):
        async def record_audit(self, action: str, **_kw: Any) -> None:
            await asyncio.Event().wait()

    monkeypatch.setattr(remote_debug_watch, "_STOP_SECONDS", 0.05)
    watch = _on(_Hung(), interval_seconds=3600.0)
    refuse()
    watch.start()
    await asyncio.sleep(0)
    task = watch._task
    assert task is not None
    await watch.stop()
    assert task.cancelled()


async def test_a_loop_task_cancelled_elsewhere_does_not_cancel_the_stop(
    refuse: Callable[..., None],
) -> None:
    """The engine awaits this stop on its way to closing the store. A stop that raised
    ``CancelledError`` for a task something else cancelled would end the engine's stop there."""
    watch = _on(_RefusingStore(), interval_seconds=3600.0)
    watch.start()
    await asyncio.sleep(0)
    task = watch._task
    assert task is not None
    task.cancel()
    await watch.stop()  # returns: no CancelledError
    assert task.cancelled()


def test_the_interval_is_the_one_the_documents_state() -> None:
    """One row a pass, so the interval is the bound on rows, and the operator documents state
    it. A shorter one would let the injecting process add rows faster than they say."""
    seconds = f"{CHECK_INTERVAL_SECONDS:g} seconds"
    assert seconds == "30 seconds"
    for doc in ("docs/SECURITY-LOOSENING.md", "changelog.d/2742.added.md"):
        assert f"every {seconds}" in (_REPO / doc).read_text(encoding="utf-8"), doc


# --- the engine runs it, and only serve builds an engine -----------------------------------------


async def test_the_engine_writes_the_row_on_its_own_store(
    tmp_path: Path, refuse: Callable[..., None], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(Engine, "instance_identity", property(lambda _self: "shard:a"))
    sink = _Sink()
    opened = await MessageStore.open(tmp_path / "engine.db")
    engine = Engine(
        opened,
        alert_sink=cast(AlertSink, sink),
        egress_settings=EgressSettings(deny_by_default=False),
    )
    await engine.start()
    try:
        watch = engine._remote_debug_watch
        assert watch is not None and watch._task is not None
        assert watch._store is opened and watch._node == "shard:a"
        assert watch._alert_sink is sink
        refuse(times=3)
        await watch.run_once()
        # Passes take turns in the order they asked. This one finishes after the loop's first
        # pass, which leaves the loop in its 30-second wait.
        await watch.run_once()
        refuse(times=2)  # so only the pass the engine's stop makes can report these
    finally:
        await engine.stop()  # which closes the store, so the rows are read from a second open
    assert engine._remote_debug_watch is None
    reopened = await MessageStore.open(tmp_path / "engine.db")
    try:
        details = [row["detail"] for row in await _rows(reopened)]
    finally:
        await reopened.close()
    assert [(d["count"], d["total"], d["process"]) for d in details] == [
        (3, 3, "shard:a"),
        (2, 5, "shard:a"),
    ]
    assert sink.alerts == [
        ("remote_debug:refused@shard:a", 3, 3),
        ("remote_debug:refused@shard:a", 2, 5),
    ]


def test_the_watch_defaults_to_the_logging_sink() -> None:
    """With no notifier the alert is a log line, as for every other alert."""
    assert isinstance(_on(_RefusingStore())._alert_sink, LoggingAlertSink)


def _functions_naming(source: str, name: str) -> set[str]:
    """The top-level functions of ``source`` whose code spells ``name``, imports included."""
    found = set()
    for node in parse_source(source).body:
        if not isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            continue
        imported = {
            alias.name
            for sub in ast.walk(node)
            if isinstance(sub, ast.Import | ast.ImportFrom)
            for alias in sub.names
        }
        if name in code_names(node) | imported:
            found.add(node.name)
    return found


def _construction_sites(name: str) -> list[str]:
    """Each file of the engine package that calls ``name``, as a posix path under the package."""
    sites = []
    for path in sorted(_ENGINE.rglob("*.py")):
        text = path.read_text(encoding="utf-8")
        # The text test is only a cheap first cut: a call needs the name and a bracket.
        if f"{name}(" in text and call_sites(parse_source(text), name):
            sites.append(path.relative_to(_ENGINE).as_posix())
    return sites


def test_only_serve_builds_what_runs_the_watch() -> None:
    """A census, from the watch back to the command line: the watch is built in one place, the
    engine; the engine is built in one place, the managed app; and of the command line's
    functions only ``serve`` names the managed app. So ``supervise``, ``rotate-key``, ``backup``
    and every other command start no watch."""
    assert _construction_sites("RemoteDebugRefusalWatch") == ["pipeline/engine.py"]
    # `Engine(...)` in the package. `Engine.create(...)` is a classmethod on the engine itself,
    # called by tests and embedders, never by a command.
    assert _construction_sites("Engine") == ["api/app.py"]
    assert _construction_sites("create_managed_app") == ["__main__.py"]

    command_line = (_ENGINE / "__main__.py").read_text(encoding="utf-8")
    assert _functions_naming(command_line, "create_managed_app") == {"_serve"}
    for reach in ("Engine", "RemoteDebugRefusalWatch", "remote_debug_watch"):
        assert _functions_naming(command_line, reach) == set(), reach
    # CONTROL: the probe does see a name a command function uses, so the empty sets above are
    # not a probe that finds nothing.
    assert "_supervise" in _functions_naming(command_line, "install_remote_debug_guard")


# --- the state where the guard reads as missing --------------------------------------------------

_SECOND_CAUSE = """\
import asyncio, json, sys

from messagefoundry import remotedebug
from messagefoundry.pipeline.remote_debug_watch import RemoteDebugRefusalWatch

mode, out = sys.argv[1], sys.argv[2]


def earlier(event, args):
    if mode == "probe" and event == remotedebug._PROBE_EVENT:
        raise ValueError("an event this hook does not know")
    if mode == "refuses" and event == "sys.addaudithook":
        raise RuntimeError("this hook refuses every new one")


sys.addaudithook(earlier)
remotedebug.install_remote_debug_guard()
sys.unraisablehook = lambda unraisable: None
refused = 0
for _ in range(3):
    try:
        sys.audit(remotedebug.REMOTE_SCRIPT_EVENT, "C:/somewhere/zqx-planted-script-name.py")
    except remotedebug.RemoteScriptRefused:
        refused += 1


class Store:
    rows = []

    async def record_audit(self, action, *, actor=None, detail=None):
        self.rows.append(json.loads(detail))


asyncio.run(RemoteDebugRefusalWatch(Store()).run_once())
posture = remotedebug.remote_debug_posture()
with open(out, "w", encoding="utf-8") as fh:
    json.dump(
        {
            "enabled": posture.interpreter_enabled,
            "guard_installed": posture.guard_installed,
            "refused": refused,
            "rows": [[row["count"], row["total"]] for row in Store.rows],
        },
        fh,
    )
"""


def _second_cause(tmp_path: Path, mode: str) -> dict[str, Any]:
    script = tmp_path / "second_cause.py"
    script.write_text(_SECOND_CAUSE, encoding="utf-8")
    out = tmp_path / f"{mode}.json"
    try:
        proc = subprocess.run(
            [sys.executable, str(script), mode, str(out)],
            env=_guard_tests._child_env(),
            capture_output=True,
            text=True,
            timeout=50,  # under the suite's per-test watchdog, so a hung child is reported here
        )
    except subprocess.TimeoutExpired as exc:
        pytest.fail(f"the child did not finish: {exc.stderr!r}")
    assert proc.returncode == 0 and out.exists(), proc.stderr[-2000:]
    reading: dict[str, Any] = json.loads(out.read_text(encoding="utf-8"))
    if reading["enabled"] is not True:
        # An interpreter built without the interface: the guard installs nothing there.
        pytest.skip("the child interpreter does not accept injected scripts")
    return reading


def test_a_guard_that_reads_as_missing_but_refuses_still_gets_its_row(tmp_path: Path) -> None:
    """An earlier audit hook raises on the engine's probe event. The posture then reads the guard
    as missing and the guard starts no reporter, so no WARNING is written. The hook is in place
    all the same: it refuses and counts, and the watch reads the count."""
    reading = _second_cause(tmp_path, "probe")
    assert reading["guard_installed"] is False
    assert reading["refused"] == 3
    assert reading["rows"] == [[3, 3]]


def test_a_guard_that_is_missing_refuses_nothing_and_gets_no_row(tmp_path: Path) -> None:
    """CONTROL for the test above, and the limit of this watch: where an earlier hook refused the
    engine's, nothing is refused, nothing is counted and no row is written."""
    reading = _second_cause(tmp_path, "refuses")
    assert reading["guard_installed"] is False
    assert reading["refused"] == 0
    assert reading["rows"] == []
