# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Fail-closed application-log write guard (BACKLOG #122, ADR 0162).

The control is fail-closed, so a passing test proves nothing on its own — a guard that never fires
passes every "nothing broke" assertion. Every stage here is therefore driven by a **genuinely broken
sink** (a real closed OS handle; a real path whose parent directory has been replaced by a file), and
each direction carries its negative control:

* stage 1 rolls and heals, and a HEALTHY run rolls nothing and stops nothing;
* stage 2 stops, and the ``continue`` policy under the SAME failure stops nothing;
* the error path writes no record content to the last-resort channel, and the stdlib handler it
  replaces demonstrably DOES — so the assertion is proven able to see that class of leak.

**The last block is the one that decides the item.** Everything before it drives the guard directly
or hands the runner a synthesized ``LogSinkEvent``; neither shows that the ENGINE refuses to process.
``test_an_unwritable_log_makes_the_engine_refuse_to_process`` runs the whole chain — a real
unwritable file, the real handler ``configure_logging`` installs, the real guard, a real running
``RegistryRunner`` — and asserts a committed ingress row is still ``RECEIVED`` with no outbound rows,
against a negative control on the identical rig that shows the row IS processed when the log is
healthy, and a recovery test that shows a restart drains it. Both claim modes, because pooled and
per_lane halt the internal stages by different mechanisms.
"""

from __future__ import annotations

import asyncio
import io
import logging
import shutil
from collections.abc import Callable
from pathlib import Path

import pytest
from pydantic import ValidationError

from messagefoundry import logging_guard
from messagefoundry.api.app import _outbound_down_detail
from messagefoundry.config.models import ConnectorType
from messagefoundry.config.settings import LoggingSettings, LogWriteFailurePolicy, load_settings
from messagefoundry.config.wiring import (
    ConnectionSpec,
    InboundConnection,
    OutboundConnection,
    Registry,
    Send,
)
from messagefoundry.logging_guard import (
    _MAX_ROLLS_PER_WINDOW,
    GuardedFileHandler,
    GuardedStreamHandler,
    LogSinkEvent,
    LogWriteGuard,
    active_guard,
    set_active_guard,
)
from messagefoundry.logging_setup import LogFile, configure_logging
from messagefoundry.pipeline import wiring_runner
from messagefoundry.pipeline.alerts import LoggingAlertSink
from messagefoundry.pipeline.wiring_runner import RegistryRunner
from messagefoundry.store import MessageStore
from messagefoundry.store.store import MessageStatus, Stage

RAW = "MSH|^~\\&|A|B|C|D|20260101||ADT^A01|M1|P|2.5.1\rPID|1||100^^^H^MR||DOE^JANE\r"
INBOUND = "IB_TEST"
OUTBOUND = "OB_TEST"
# The outbound a reload ADDS while the halt is latched (ADR 0189 door six) — a second, distinct lane
# so the door-six test can assert on a destination the halt provably never saw.
OUTBOUND_ADDED = "OB_TEST_ADDED"
# What the door-six test patches `_WORKER_ERROR_BACKOFF_SECONDS` down to, so its absence-of-a-spin
# window covers many claim cycles rather than one. Named here so the window and the cadence it is
# measured against can never be edited apart.
_BACKOFF = 0.05


# --- helpers -----------------------------------------------------------------


def _record(message: str, *args: object) -> logging.LogRecord:
    return logging.LogRecord("t", logging.INFO, "caller.py", 1, message, args, None)


def _file_handler(path: Path, guard: LogWriteGuard) -> GuardedFileHandler:
    handler = GuardedFileHandler(str(path), guard=guard, sink="file")
    handler.setFormatter(logging.Formatter("%(message)s"))
    return handler


def _break_the_open_handle(handler: logging.FileHandler) -> None:
    """Make the sink GENUINELY unwritable, not stubbed: close the real file object the handler holds,
    so the next write raises out of CPython's io layer exactly as a yanked handle would."""
    assert handler.stream is not None
    handler.stream.close()


def _replace_directory_with_a_file(directory: Path) -> None:
    """Make the REPLACEMENT genuinely impossible to open: put a regular FILE where the log's parent
    directory belongs. Both the rename-aside and the fresh open then fail at the OS, on Windows and
    POSIX alike, with no permission fixture and no monkeypatching of the code under test."""
    shutil.rmtree(directory)
    directory.write_text("not a directory", encoding="utf-8")


# --- stage 1: RECOVER --------------------------------------------------------


def test_healthy_sink_never_rolls_and_never_escalates(tmp_path: Path) -> None:
    # THE NEGATIVE CONTROL. An ordinary run must not roll a file, must not stop anything, and must
    # leave every sink 'healthy' — a guard that fires on a working log is an outage generator.
    events: list[LogSinkEvent] = []
    guard = LogWriteGuard()
    guard.set_escalation(events.append)
    handler = _file_handler(tmp_path / "app.log", guard)

    for i in range(25):
        handler.emit(_record("ordinary line %d", i))
    handler.close()

    assert events == []
    assert [s.state for s in guard.status()] == ["healthy"]
    assert [s.rollovers for s in guard.status()] == [0]
    assert list(tmp_path.iterdir()) == [tmp_path / "app.log"]  # nothing rolled aside
    assert "ordinary line 24" in (tmp_path / "app.log").read_text(encoding="utf-8")


def test_stage1_renames_the_broken_file_aside_rolls_fresh_and_keeps_running(tmp_path: Path) -> None:
    # A write failure on a sink whose DIRECTORY is still writable heals: the broken file is renamed
    # aside (its prior content preserved for the operator), a fresh file takes the live path, the
    # rollover event is RECORDED in it, and the record whose write failed is re-written rather than
    # lost (count-and-log). Nothing stops.
    events: list[LogSinkEvent] = []
    guard = LogWriteGuard()
    guard.set_escalation(events.append)
    log_path = tmp_path / "app.log"
    handler = _file_handler(log_path, guard)
    handler.emit(_record("before the break"))

    _break_the_open_handle(handler)
    handler.emit(_record("after the break"))

    assert [e.stage for e in events] == ["rolled"]
    assert events[0].stop_requested is False  # stage 1 stops NOTHING, ever
    status = guard.status()[0]
    assert status.state == "rolled" and status.rollovers == 1

    aside = [p for p in tmp_path.iterdir() if ".broken-" in p.name]
    assert len(aside) == 1
    assert aside[0].read_text(encoding="utf-8") == "before the break\n"  # evidence preserved
    assert str(aside[0]) == status.rolled_aside

    fresh = log_path.read_text(encoding="utf-8")
    assert "was rolled after a write failure" in fresh  # the rollover event is RECORDED
    assert aside[0].name in fresh  # …and it names where the evidence went
    assert "after the break" in fresh  # the failed record is re-written, not dropped

    # And the sink KEEPS WORKING afterwards — a heal that leaves a dead handler is not a heal.
    handler.emit(_record("after the heal"))
    assert "after the heal" in log_path.read_text(encoding="utf-8")


def test_stage1_heals_the_latch_so_a_later_break_escalates_again(tmp_path: Path) -> None:
    events: list[LogSinkEvent] = []
    guard = LogWriteGuard()
    guard.set_escalation(events.append)
    handler = _file_handler(tmp_path / "app.log", guard)

    for _ in range(3):
        _break_the_open_handle(handler)
        handler.emit(_record("break"))

    assert [e.stage for e in events] == ["rolled", "rolled", "rolled"]
    assert guard.status()[0].rollovers == 3


def test_a_sink_that_keeps_needing_a_roll_is_declared_unwritable(tmp_path: Path) -> None:
    # "Heals" and "keeps needing to be healed" are not the same sink. Rolling per record would mean
    # one rename, one fresh file and one page per log line forever; past the flap bound the honest
    # verdict is stage 2. Driven by real rolls, not by poking the counter.
    events: list[LogSinkEvent] = []
    guard = LogWriteGuard()
    guard.set_escalation(events.append)
    handler = _file_handler(tmp_path / "app.log", guard)

    for _ in range(_MAX_ROLLS_PER_WINDOW + 1):
        _break_the_open_handle(handler)
        handler.emit(_record("break"))

    assert [e.stage for e in events[:-1]] == ["rolled"] * _MAX_ROLLS_PER_WINDOW
    assert events[-1].stage == "unwritable"
    assert "is a failing log rather than a transient" in events[-1].reason
    assert guard.status()[0].state == "unwritable"


def test_the_flap_bound_does_not_fire_on_an_ordinary_transient(tmp_path: Path) -> None:
    # …and the bound is loose enough that a genuine one-off never trips it (the negative control for
    # the test above — otherwise a bound of 1 would pass it and be an outage generator).
    events: list[LogSinkEvent] = []
    guard = LogWriteGuard()
    guard.set_escalation(events.append)
    handler = _file_handler(tmp_path / "app.log", guard)
    _break_the_open_handle(handler)
    handler.emit(_record("break"))

    assert [e.stage for e in events] == ["rolled"]


# --- stage 2: STOP -----------------------------------------------------------


def test_stage2_fires_only_when_the_replacement_is_also_unwritable(tmp_path: Path) -> None:
    # The whole point of the two-stage split: this is the SAME initial failure as the stage-1 test,
    # and it escalates only because the replacement cannot be written either.
    events: list[LogSinkEvent] = []
    guard = LogWriteGuard()
    guard.set_escalation(events.append)
    log_dir = tmp_path / "logs"
    log_dir.mkdir()
    handler = _file_handler(log_dir / "app.log", guard)
    handler.emit(_record("before the break"))

    _break_the_open_handle(handler)
    _replace_directory_with_a_file(log_dir)
    handler.emit(_record("after the break"))

    assert [e.stage for e in events] == ["unwritable"]
    assert events[0].stop_requested is True  # the default policy asks for the fail-closed stop
    assert "the replacement failed too" in events[0].reason
    assert guard.status()[0].state == "unwritable"


def test_stage2_escalation_is_latched_to_one_page_per_break(tmp_path: Path) -> None:
    # A broken disk emits a log line per message; without the latch that is one page per message.
    events: list[LogSinkEvent] = []
    guard = LogWriteGuard()
    guard.set_escalation(events.append)
    log_dir = tmp_path / "logs"
    log_dir.mkdir()
    handler = _file_handler(log_dir / "app.log", guard)
    _break_the_open_handle(handler)
    _replace_directory_with_a_file(log_dir)

    for i in range(10):
        handler.emit(_record("line %d", i))

    assert len(events) == 1


def test_continue_policy_reports_the_same_failure_without_asking_for_a_stop(tmp_path: Path) -> None:
    # The documented opt-out, driven by the IDENTICAL genuine failure: still detected, still alerted,
    # simply not asked to stop.
    events: list[LogSinkEvent] = []
    guard = LogWriteGuard(stop_on_unwritable=False)
    guard.set_escalation(events.append)
    log_dir = tmp_path / "logs"
    log_dir.mkdir()
    handler = _file_handler(log_dir / "app.log", guard)
    _break_the_open_handle(handler)
    _replace_directory_with_a_file(log_dir)
    handler.emit(_record("after the break"))

    assert [e.stage for e in events] == ["unwritable"]
    assert events[0].stop_requested is False


# --- PHI on the error path ---------------------------------------------------

PHI_TOKEN = "DOE^JANE^Q^^^^L"


def test_the_stdlib_handler_this_guard_replaces_does_write_record_content_to_stderr(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    # RED FIRST, in the "prove the instrument can see it" direction. logging.Handler.handleError
    # writes 'Message: %r' / 'Arguments: %s' straight to stderr, BELOW the handler's filter chain.
    # Without this test, the assertion in the next one could pass because the token never reaches
    # stderr at all — this proves stderr is exactly where such a leak WOULD land.
    #
    # PIN raiseExceptions=True, and the pin is the whole reason this test is trustworthy. THIS SUITE
    # sets it to False for the entire session (tests/conftest.py
    # `_tolerate_logging_on_closed_capture_streams`, a session-scoped autouse fixture), under which the
    # stdlib handleError is a NO-OP and this assertion could never pass — measured: it failed here
    # exactly that way. Reading the ambient value would have made the leak-detector look broken; the
    # honest reading is that a control asserting what a mechanism DOES must pin the setting that
    # enables the mechanism, or it is measuring the fixture rather than the stdlib.
    monkeypatch.setattr(logging, "raiseExceptions", True)
    unguarded = logging.FileHandler(tmp_path / "plain.log", encoding="utf-8")
    unguarded.setFormatter(logging.Formatter("%(message)s"))
    assert unguarded.stream is not None
    unguarded.stream.close()
    unguarded.emit(_record("patient %s admitted", PHI_TOKEN))

    assert PHI_TOKEN in capsys.readouterr().err


def test_the_guard_writes_no_record_content_to_the_last_resort_channel(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # The guarded sink's stage-2 path must name the SINK and the CAUSE and nothing from the record.
    guard = LogWriteGuard()
    log_dir = tmp_path / "logs"
    log_dir.mkdir()
    handler = _file_handler(log_dir / "app.log", guard)
    _break_the_open_handle(handler)
    _replace_directory_with_a_file(log_dir)
    handler.emit(_record("patient %s admitted", PHI_TOKEN))

    captured = capsys.readouterr().err
    assert PHI_TOKEN not in captured
    assert "admitted" not in captured
    assert "IS UNWRITABLE" in captured  # the operator still learns the sink is down


def test_stage1_rewrites_the_failed_record_through_the_handlers_filter_chain(
    tmp_path: Path,
) -> None:
    # The re-write on the stage-1 path goes through self.format on a record the handler's filters
    # already mutated in place, so the rolled-to file carries the REDACTED rendering — the same text
    # the sink would have written had it not failed, never the raw one.
    from messagefoundry.logging_setup import RedactionFilter

    guard = LogWriteGuard()
    log_path = tmp_path / "app.log"
    handler = _file_handler(log_path, guard)
    handler.addFilter(RedactionFilter())
    _break_the_open_handle(handler)
    handler.handle(_record("received %s", RAW))

    rolled_to = log_path.read_text(encoding="utf-8")
    assert "DOE^JANE" not in rolled_to
    assert guard.status()[0].state == "rolled"


# --- hostile ambient environment --------------------------------------------


@pytest.mark.parametrize("raise_exceptions", [False, True])
def test_the_guard_fires_with_logging_raiseexceptions_switched_off(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, raise_exceptions: bool
) -> None:
    # AMBIENT PIN. logging.raiseExceptions is a process-global that any library (or a deployment
    # convention) can flip to False, and the stdlib handleError is a NO-OP when it is. Our override
    # deliberately does not consult it, so the two-stage control cannot be silently disabled by an
    # ambient setting we do not own. Run the whole stage-1 path under the hostile value.
    #
    # PARAMETRIZED OVER BOTH VALUES, because this suite's own session fixture sets it to False for
    # every test in this file: pinning only False would re-assert the ambient value and never
    # exercise the default True at all. "The guard is indifferent to this flag" is a claim about
    # both settings, so both are measured.
    monkeypatch.setattr(logging, "raiseExceptions", raise_exceptions)
    events: list[LogSinkEvent] = []
    guard = LogWriteGuard()
    guard.set_escalation(events.append)
    handler = _file_handler(tmp_path / "app.log", guard)
    handler.emit(_record("before"))
    _break_the_open_handle(handler)
    handler.emit(_record("after"))

    assert [e.stage for e in events] == ["rolled"]
    assert "after" in (tmp_path / "app.log").read_text(encoding="utf-8")


def test_the_pin_is_load_bearing_the_stdlib_handler_goes_silent_under_the_same_value(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    # …and the pin above is load-bearing rather than decorative: the handler it replaces reports
    # NOTHING AT ALL under the same ambient value. That is the failure mode the guard removes.
    # The monkeypatch is deliberately explicit even though this suite's session fixture already
    # sets False — a control must state the value it is asserting under, not inherit it.
    monkeypatch.setattr(logging, "raiseExceptions", False)
    unguarded = logging.FileHandler(tmp_path / "plain.log", encoding="utf-8")
    unguarded.setFormatter(logging.Formatter("%(message)s"))
    assert unguarded.stream is not None
    unguarded.stream.close()
    unguarded.emit(_record("dropped without a trace"))

    assert capsys.readouterr().err == ""


def test_stdout_sink_is_guarded_and_reports_when_the_stream_is_gone(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The default engine sink is stdout, whose file the engine does NOT own (NSSM does). There is
    # nothing to rename, so the roll RE-RESOLVES ``sys.stdout`` — and a genuinely dead stdout, with
    # nothing live to rebind to, still reaches stage 2 rather than vanishing.
    #
    # sys.stdout is PINNED to the dead stream on purpose. Without the pin this test passed for the
    # wrong reason: the handler could never heal because it re-attempted the same closed object, so
    # "stage 2 fires" was true of every stdout failure including the recoverable ones. That is the
    # hair trigger measured in the full suite (see the swapped-stream test below); the pin is what
    # makes this assert the UNRECOVERABLE case it names.
    events: list[LogSinkEvent] = []
    guard = LogWriteGuard()
    guard.set_escalation(events.append)
    stream = io.StringIO()
    handler = GuardedStreamHandler(stream, guard=guard, sink="stdout")
    handler.setFormatter(logging.Formatter("%(message)s"))
    handler.emit(_record("healthy"))
    assert stream.getvalue() == "healthy\n"

    monkeypatch.setattr("sys.stdout", stream)
    stream.close()
    handler.emit(_record("after the break"))
    assert [e.stage for e in events] == ["unwritable"]
    assert events[0].sink == "stdout"
    assert events[0].stop_requested is True  # the only sink, and it is gone


# --- configure_logging wiring ------------------------------------------------


@pytest.fixture(autouse=True)
def _restore_process_logging():  # type: ignore[no-untyped-def]
    """configure_logging replaces the ROOT handlers and publishes a process-wide guard. Snapshot and
    restore both, so a test here cannot leak a rolled/unwritable sink into the rest of the suite."""
    root = logging.getLogger()
    handlers = list(root.handlers)
    level = root.level
    guard = active_guard()
    yield
    root.handlers[:] = handlers
    root.setLevel(level)
    set_active_guard(guard)


def test_configure_logging_installs_a_guarded_file_sink_beside_stdout(tmp_path: Path) -> None:
    path = tmp_path / "engine.log"
    configure_logging("INFO", log_file=LogFile(path=str(path)))
    logging.getLogger("t").info("a line the engine wrote")

    assert "a line the engine wrote" in path.read_text(encoding="utf-8")
    guard = active_guard()
    assert guard is not None
    assert sorted(s.sink for s in guard.status()) == ["file", "stdout"]
    assert all(s.state == "healthy" for s in guard.status())


def test_configure_logging_refuses_a_log_file_it_cannot_open(tmp_path: Path) -> None:
    # FAIL CLOSED AT CONFIGURATION TIME, on a genuinely impossible path (the parent is a file).
    # Starting an engine that cannot log is the silent blindness #122 exists to end.
    parent = tmp_path / "not-a-dir"
    parent.write_text("regular file", encoding="utf-8")
    with pytest.raises(OSError):
        configure_logging("INFO", log_file=LogFile(path=str(parent / "engine.log")))


def test_configure_logging_threads_the_stop_policy_onto_the_guard() -> None:
    configure_logging("INFO", stop_on_write_failure=False)
    guard = active_guard()
    assert guard is not None and guard.stop_on_unwritable is False


# --- settings: one file, one rotation owner ----------------------------------


def test_settings_refuse_an_engine_log_file_inside_the_supervisor_rotation_dir(
    tmp_path: Path,
) -> None:
    with pytest.raises(ValueError, match="rotates"):
        LoggingSettings(log_dir=str(tmp_path), file=str(tmp_path / "engine.log"))


def test_settings_accept_an_engine_log_file_outside_the_supervisor_rotation_dir(
    tmp_path: Path,
) -> None:
    supervisor = tmp_path / "nssm"
    supervisor.mkdir()
    settings = LoggingSettings(log_dir=str(supervisor), file=str(tmp_path / "engine.log"))
    assert settings.on_write_failure is LogWriteFailurePolicy.STOP  # fail-closed by default


def test_settings_refuse_the_legacy_planned_rotation_key_names(tmp_path: Path) -> None:
    # `[logging]` is pydantic extra="ignore", and CONFIGURATION.md carried `max_bytes`/`backups` as
    # accepted-but-ignored planned keys. Silently ignoring them now that the sink is REAL would give
    # an operator the 50 MB / 5-backup defaults while their file said otherwise — a control that
    # reports success while doing something else. Refuse, naming the real keys.
    with pytest.raises(ValueError, match="file_max_bytes"):
        LoggingSettings(file=str(tmp_path / "engine.log"), max_bytes=1000)
    with pytest.raises(ValueError, match="file_backup_count"):
        LoggingSettings(file=str(tmp_path / "engine.log"), backups=2)


@pytest.mark.parametrize(
    ("env_var", "names"),
    [("MEFOR_LOGGING_MAX_BYTES", "file_max_bytes"), ("MEFOR_LOGGING_BACKUPS", "file_backup_count")],
)
def test_the_legacy_rotation_key_is_refused_from_env_where_the_file_gate_does_not_reach(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, env_var: str, names: str
) -> None:
    # WHICH LAYER REFUSES DEPENDS ON WHERE THE KEY CAME FROM, and the model validator above is not
    # the one a file reaches. `_reject_unknown_file_keys` refuses an unrecognized key in the TOML
    # before any model is built, so a FILE carrying either spelling stops there. The env layer is
    # different: `docs/CONFIGURATION.md` states plainly that the refusal "covers the FILE. It does not
    # cover env or CLI", so a misspelled `MEFOR_*` is normally dropped in SILENCE.
    #
    # These two spellings are the exception, and that is the whole point of keeping the model
    # validator once the loader gained a generic refusal. Without this test the docstring's claim
    # about the env layer is unpinned prose, and the validator looks like dead weight next to the
    # loader — which is exactly how a second line of defence gets deleted as redundant.
    config = tmp_path / "messagefoundry.toml"
    config.write_text('[logging]\nlevel = "INFO"\n', encoding="utf-8")
    monkeypatch.setenv(env_var, "7")
    with pytest.raises(ValidationError, match=names):
        load_settings(config_path=config)


def test_the_legacy_rotation_key_is_refused_in_the_file_by_the_loader(tmp_path: Path) -> None:
    # The other half of the pair, so the docs cannot go stale in either direction. A file spelling is
    # refused by the LOADER, not by the model validator, and the message an operator actually reads
    # is the loader's. Pinned as a pair with the env test so a future loader change that swallowed
    # one of these lands here rather than in a deployment.
    config = tmp_path / "messagefoundry.toml"
    for legacy in ("max_bytes", "backups"):
        config.write_text(f"[logging]\n{legacy} = 7\n", encoding="utf-8")
        with pytest.raises(ValueError, match=f"unrecognized config key.*{legacy}"):
            load_settings(config_path=config)


# --- the engine response: stop this process's connections, and say why -------


class _RecordingSink(LoggingAlertSink):
    def __init__(self) -> None:
        self.stopped: list[tuple[str, str]] = []
        self.log_failures: list[tuple[str, str, str, int | None]] = []

    def connection_stopped(self, name: str, *, detail: str) -> None:
        self.stopped.append((name, detail))

    def log_write_failed(
        self, name: str, *, stage: str, reason: str, stopped: int | None = None
    ) -> None:
        self.log_failures.append((name, stage, reason, stopped))


class _StubSource:
    def __init__(self) -> None:
        self.stopped = False

    async def stop(self) -> None:
        self.stopped = True


def _graph(store: MessageStore, sink: _RecordingSink) -> tuple[RegistryRunner, _StubSource]:
    reg = Registry()
    reg.add_inbound(
        InboundConnection(
            INBOUND,
            ConnectionSpec(ConnectorType.MLLP, {"host": "127.0.0.1", "port": 0}),
            router="r",
        )
    )
    reg.add_router("r", lambda m: [])
    reg.add_outbound(
        OutboundConnection(OUTBOUND, ConnectionSpec(ConnectorType.MLLP, {"host": "h", "port": 1}))
    )
    runner = RegistryRunner(reg, store, poll_interval=0.02, alert_sink=sink)
    source = _StubSource()
    runner._sources[INBOUND] = source  # type: ignore[assignment]
    return runner, source


@pytest.fixture
async def store(tmp_path: Path):  # type: ignore[no-untyped-def]
    s = await MessageStore.open(tmp_path / "guard.db")
    yield s
    await s.close()


async def test_unwritable_log_stops_intake_and_delivery_and_names_the_cause(
    store: MessageStore,
) -> None:
    sink = _RecordingSink()
    runner, source = _graph(store, sink)

    await runner._respond_to_log_sink_event(
        LogSinkEvent(sink="file", stage="unwritable", reason="disk full", stop_requested=True)
    )

    assert source.stopped is True  # intake halted — nothing new is accepted that cannot be logged
    assert (
        OUTBOUND in runner._outbound_paused
    )  # delivery paused, queue RETAINED (not dead-lettered)
    # The WHY, on the channel that does not depend on the broken log.
    assert sink.log_failures == [("file", "unwritable", "disk full", 2)]
    # …and the per-connection stop the operator's existing machinery already understands (ADR 0014),
    # now actually DRIVEN by a log-write failure and carrying the cause.
    assert sorted(name for name, _ in sink.stopped) == [INBOUND, OUTBOUND]
    assert all("application log sink 'file' is unwritable" in d for _, d in sink.stopped)


async def test_stage1_roll_alerts_but_stops_nothing(store: MessageStore) -> None:
    # THE NEGATIVE CONTROL at the engine level: a transient that healed must not take feeds down.
    sink = _RecordingSink()
    runner, source = _graph(store, sink)

    await runner._respond_to_log_sink_event(
        LogSinkEvent(
            sink="file", stage="rolled", reason="momentary lock", rolled_aside="/x/a.broken"
        )
    )

    assert source.stopped is False
    assert OUTBOUND not in runner._outbound_paused
    assert sink.stopped == []
    assert sink.log_failures == [("file", "rolled", "momentary lock", None)]


async def test_continue_policy_alerts_but_stops_nothing(store: MessageStore) -> None:
    sink = _RecordingSink()
    runner, source = _graph(store, sink)

    await runner._respond_to_log_sink_event(
        LogSinkEvent(sink="file", stage="unwritable", reason="disk full", stop_requested=False)
    )

    assert source.stopped is False
    assert OUTBOUND not in runner._outbound_paused
    assert sink.stopped == []
    assert sink.log_failures == [("file", "unwritable", "disk full", None)]


async def test_the_halt_is_latched_so_a_second_event_does_not_restop(store: MessageStore) -> None:
    sink = _RecordingSink()
    runner, _source = _graph(store, sink)
    event = LogSinkEvent(sink="file", stage="unwritable", reason="disk full", stop_requested=True)

    await runner._respond_to_log_sink_event(event)
    await runner._respond_to_log_sink_event(event)

    assert len(sink.log_failures) == 1


async def test_the_escalation_bridges_from_a_worker_thread_onto_the_engine_loop(
    store: MessageStore,
) -> None:
    # The failure surfaces inside logging.Handler.emit, on WHATEVER thread logged — a handler worker
    # thread, a connector thread, the loop itself. The bridge must hand the event to the loop rather
    # than mutate runner state off-loop, and it must not block the thread that was logging.
    sink = _RecordingSink()
    runner, source = _graph(store, sink)
    runner._loop = asyncio.get_running_loop()

    await asyncio.to_thread(
        runner._on_log_sink_event,
        LogSinkEvent(sink="file", stage="unwritable", reason="disk full", stop_requested=True),
    )
    for _ in range(200):
        if source.stopped:
            break
        await asyncio.sleep(0.01)

    assert source.stopped is True
    assert [f[1] for f in sink.log_failures] == ["unwritable"]


async def test_the_runner_subscribes_at_start_and_unsubscribes_at_stop(store: MessageStore) -> None:
    # Without this the whole control is inert in the shipped engine while every unit test above
    # still passes — the "green signal that means nothing" shape (ADR 0158).
    guard = LogWriteGuard()
    set_active_guard(guard)
    runner = RegistryRunner(Registry(), store, poll_interval=0.02)
    await runner.start()
    try:
        assert guard._escalation == runner._on_log_sink_event
    finally:
        await runner.stop()
    assert guard._escalation is None


async def test_the_store_is_untouched_so_ack_on_receipt_still_holds(store: MessageStore) -> None:
    # ACK-ON-RECEIPT BOUNDARY. A message already durably committed to the ingress stage was ACKed to
    # its sender. The application log and the message STORE are different durable records, and an
    # application-log failure is not a store failure: the row must survive the halt exactly as it was
    # — still pending, still claimable, never dead-lettered and never re-enqueued.
    message_id = await store.enqueue_ingress(channel_id=INBOUND, raw=RAW, now=0.0)
    before = await store.stats()

    sink = _RecordingSink()
    runner, _source = _graph(store, sink)
    await runner._respond_to_log_sink_event(
        LogSinkEvent(sink="file", stage="unwritable", reason="disk full", stop_requested=True)
    )

    assert await store.stats() == before
    claimed = await store.claim_next_fifo(INBOUND, stage=Stage.INGRESS.value, now=1.0)
    assert claimed is not None and claimed.message_id == message_id


# --- THE END-TO-END CONTROL: does the engine actually REFUSE TO PROCESS? -----
#
# Everything above this line either drives the guard directly or hands the runner a hand-built
# LogSinkEvent. Both are necessary and neither is sufficient: a synthesized event proves the
# RESPONSE, not that a genuinely broken sink ever produces one, and none of it proves the outcome
# the owner's ruling is actually about — "we never want to process stuff if the processing cannot be
# logged". These two tests close that gap as a PAIR, over the whole chain (real unwritable file ->
# real GuardedFileHandler installed by configure_logging -> real guard -> real running
# RegistryRunner -> the pipeline), and the negative control is what makes the positive one mean
# anything: a rig where nothing ever drains would pass the "nothing was processed" assertion for the
# wrong reason.


def _installed_file_sink() -> GuardedFileHandler:
    """The guarded file handler configure_logging just put on the root logger."""
    sinks = [h for h in logging.getLogger().handlers if isinstance(h, GuardedFileHandler)]
    assert len(sinks) == 1, f"expected one guarded file sink, found {len(sinks)}"
    return sinks[0]


def _break_sink_and_replacement(handler: GuardedFileHandler, directory: Path) -> None:
    """Make the sink AND everything it could roll to genuinely unwritable, at the OS.

    Closes the live handle and puts a regular FILE where the log's parent directory belongs, so the
    rename-aside and the fresh open both fail. Deliberately ONE call with no await and no I/O between
    the two steps: a stage-1 roll landing in the gap would open a fresh handle inside the directory
    and make the rmtree fail on Windows, turning a race into a confusing error instead of the
    condition under test."""
    stream = handler.stream
    if stream is not None:
        stream.close()
    shutil.rmtree(directory)
    directory.write_text("not a directory", encoding="utf-8")


def _file_outbound(name: str, directory: Path, *, auto_start: bool) -> OutboundConnection:
    """One FILE outbound writing ``{MSH-10}.hl7`` into ``directory``."""
    return OutboundConnection(
        name,
        ConnectionSpec(
            ConnectorType.FILE, {"directory": str(directory), "filename": "{MSH-10}.hl7"}
        ),
        auto_start=auto_start,
    )


def _e2e_registry(
    outdir: Path,
    *,
    outbound_auto_start: bool = True,
    added_outdir: Path | None = None,
    added_auto_start: bool = True,
) -> Registry:
    """A real graph: MLLP inbound -> router -> handler -> FILE outbound writing into ``outdir``.

    The inbound binds an ephemeral port and is never connected to; every message in these tests is
    put on the ingress stage directly, because the question is what the ROUTER and TRANSFORM workers
    do with a message that is already durably in the store — the listener stopping is the easy half.

    ``outbound_auto_start=False`` engine-PARKS the delivery lane at boot (#115), which is the one
    down state a log-failure halt skips — the lane is already paused, so the halt never reaches it
    and its ``_gate_parked`` marker survives. The default leaves every other caller unchanged.

    ``added_outdir`` declares a SECOND file outbound (``OUTBOUND_ADDED``) and makes the handler fan
    out to both — the lane ADR 0189's door-six test has a later reload add. It is a knob here rather
    than a post-hoc ``reg.handlers[...]`` write in the caller, because that write would bypass
    ``add_handler``'s duplicate guard and its ``handler_accepts`` bookkeeping.
    ``added_auto_start=False`` engine-parks that second lane at boot, so a runner can queue it a
    genuine row without delivering one."""
    reg = Registry()
    reg.add_outbound(_file_outbound(OUTBOUND, outdir, auto_start=outbound_auto_start))
    if added_outdir is not None:
        reg.add_outbound(_file_outbound(OUTBOUND_ADDED, added_outdir, auto_start=added_auto_start))
    reg.add_inbound(
        InboundConnection(
            INBOUND,
            ConnectionSpec(ConnectorType.MLLP, {"host": "127.0.0.1", "port": 0}),
            router="r",
        )
    )
    reg.add_router("r", lambda m: ["h"])
    if added_outdir is None:
        reg.add_handler("h", lambda m: Send(OUTBOUND, m))
    else:
        reg.add_handler("h", lambda m: [Send(OUTBOUND, m), Send(OUTBOUND_ADDED, m)])
    return reg


async def _until(predicate: Callable[[], bool], timeout: float = 5.0) -> bool:
    elapsed = 0.0
    while not predicate():
        if elapsed > timeout:
            return False
        await asyncio.sleep(0.02)
        elapsed += 0.02
    return True


async def _until_outbound_row(
    store: MessageStore, message_id: str, timeout: float = 5.0, *, count: int = 1
) -> bool:
    """Wait for the message to reach the OUTBOUND stage — i.e. the router and transform ran.

    ``count`` is the number of rows to wait FOR: the default of 1 is every single-destination caller,
    and a fan-out passes its destination count, because waiting for "any row" would return on the
    first one and race the second."""
    elapsed = 0.0
    while len(await store.outbox_for(message_id)) < count:
        if elapsed > timeout:
            return False
        await asyncio.sleep(0.02)
        elapsed += 0.02
    return True


async def _until_delivery_status(
    store: MessageStore, message_id: str, destination: str, status: str, timeout: float = 5.0
) -> bool:
    """Wait for ONE destination's outbound row to reach ``status`` in the STORE.

    The store is the authority on a delivery, and a written file is not: the connector writes, and the
    row's terminal write commits after it. Anything that must know a delivery has RESOLVED — as
    opposed to merely having produced bytes — has to ask here."""
    elapsed = 0.0
    while True:
        rows = await store.outbox_for(message_id)
        if any(r["destination_name"] == destination and r["status"] == status for r in rows):
            return True
        if elapsed > timeout:
            return False
        await asyncio.sleep(0.02)
        elapsed += 0.02


async def _added_row(store: MessageStore, message_id: str) -> dict[str, object]:
    """The ``OUTBOUND_ADDED`` delivery row, for comparing a WHOLE row across a time window.

    Whole-row equality is deliberate: a claim/reschedule cycle rewrites ``next_attempt_at``,
    ``updated_at`` and ``status``, and naming only the fields we expect to move would let a future
    cycle that moves a different one pass unnoticed."""
    matched = [
        r for r in await store.outbox_for(message_id) if r["destination_name"] == OUTBOUND_ADDED
    ]
    assert len(matched) == 1, f"expected one {OUTBOUND_ADDED} row, found {len(matched)}"
    return matched[0]


async def _until_processed(store: MessageStore, message_id: str, timeout: float = 5.0) -> bool:
    """Wait for the TERMINAL disposition, not for the delivered file.

    The file appearing means the connector wrote it; ``PROCESSED`` means the store finalizer has since
    resolved every stage's rows, and it lands strictly later. Asserting the status right after the
    file appears is a race, and it is one this test hit: measured 'routed' where 'processed' was
    expected, three times out of four, on a rig that had passed on the first run."""
    elapsed = 0.0
    while (await store.get_message(message_id))["status"] != MessageStatus.PROCESSED.value:
        if elapsed > timeout:
            return False
        await asyncio.sleep(0.02)
        elapsed += 0.02
    return True


def _kill_every_sink(logdir: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Make the process genuinely unable to log ANYWHERE — the condition the halt is actually about.

    BOTH sinks, because a stop is asked for only when no guarded sink can accept a record: a healthy
    stdout beside a dead file means the processing IS still being logged, and halting there would be
    a control resting on a false premise. ``configure_logging`` installs stdout AND the opt-in file,
    so a file-only break is not the condition under test.

    The stdout handler is re-pointed at an already-closed stream rather than having pytest's own
    capture object closed underneath it — killing the sink under test must not also kill the harness
    that reports the result. ``sys.stdout`` is pinned to the same closed object so the stage-1
    re-resolve has nothing live to rebind to."""
    _break_sink_and_replacement(_installed_file_sink(), logdir)
    dead = io.StringIO()
    dead.close()
    for handler in logging.getLogger().handlers:
        if isinstance(handler, GuardedStreamHandler):
            handler.stream = dead
    monkeypatch.setattr("sys.stdout", dead)


def _revive_every_sink(logdir: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The operator's ACTUAL repair, and the exact inverse of :func:`_kill_every_sink`: give the log
    back a real directory and a live stdout.

    Every recovery test must call this, because "the operator fixed the disk" and "the operator
    restarted and hoped" are different situations with different correct outcomes — and a recovery
    test that skips it is asserting the second while claiming the first. The handlers are left holding
    their DEAD handles on purpose: re-opening them is the guard's job (a repaired directory does not
    un-close a file object), so this also exercises the roll inside the re-validation probe."""
    logdir.unlink()  # the regular FILE _kill_every_sink left where the directory belongs
    logdir.mkdir()
    monkeypatch.setattr("sys.stdout", io.StringIO())


def _e2e_runner(
    store: MessageStore,
    outdir: Path,
    logdir: Path,
    claim_mode: str,
    alert_sink: LoggingAlertSink | None = None,
) -> RegistryRunner:
    # alert_sink is optional because only the refusal tests read the page back; None leaves the
    # runner to build its own, which is what every other caller here wants.
    configure_logging("INFO", log_file=LogFile(path=str(logdir / "engine.log")))
    return RegistryRunner(
        _e2e_registry(outdir),
        store,
        poll_interval=0.02,
        claim_mode=claim_mode,
        alert_sink=alert_sink,
    )


# BOTH CLAIM MODES, because the halt reaches the internal stages by two DIFFERENT mechanisms and a
# single-mode test would leave one of them unexercised: pooled (the shipped default) pauses each
# stage dispatcher's lane; per_lane returns out of the router/transform worker at its loop-top gate.
# "The engine refuses to process" is a claim about the engine, not about one claim mode.
CLAIM_MODES = ["pooled", "per_lane"]


@pytest.mark.parametrize("claim_mode", CLAIM_MODES)
async def test_a_healthy_log_lets_the_engine_process_a_committed_row(
    store: MessageStore, tmp_path: Path, claim_mode: str
) -> None:
    # THE NEGATIVE CONTROL, and it is the load-bearing half of the pair. It proves this rig DOES
    # process a row put on the ingress stage — so when the hostile test asserts the row was NOT
    # processed, that assertion is capable of failing.
    outdir, logdir = tmp_path / "out", tmp_path / "logs"
    outdir.mkdir()
    logdir.mkdir()
    runner = _e2e_runner(store, outdir, logdir, claim_mode)
    await runner.start()
    try:
        message_id = await store.enqueue_ingress(channel_id=INBOUND, raw=RAW)
        assert await _until(lambda: any(outdir.iterdir())), "the healthy engine never delivered"
        assert await _until_processed(store, message_id), "delivered but never finalized"
    finally:
        await runner.stop()


@pytest.mark.parametrize("claim_mode", CLAIM_MODES)
async def test_an_unwritable_log_makes_the_engine_refuse_to_process(
    store: MessageStore, tmp_path: Path, claim_mode: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    # THE TEST THAT MATTERS. Same rig, same message, one difference: the application log is
    # GENUINELY unwritable and so is anything the guard could roll to. The owner's ruling — "we never
    # want to process stuff if the processing cannot be logged" — is an ENFORCEMENT claim, so the
    # assertion is about the message, not about a warning: after the halt the committed ingress row
    # must still be sitting there, unrouted and undelivered, rather than quietly flowing through a
    # pipeline with no application log behind it.
    #
    # MEASURED RED before the runner learned to halt its internal stages: the row reached the
    # OUTBOUND stage anyway, because stopping the listener leaves the router and transform workers
    # draining the backlog. Only the outbound pause kept it from being delivered.
    outdir, logdir = tmp_path / "out", tmp_path / "logs"
    outdir.mkdir()
    logdir.mkdir()
    runner = _e2e_runner(store, outdir, logdir, claim_mode)
    await runner.start()
    try:
        _kill_every_sink(logdir, monkeypatch)
        logging.getLogger("t").warning("a record this engine cannot write anywhere")
        assert await _until(lambda: runner._log_write_stopped), "the halt never fired"

        # A message durably committed to the ingress stage — the ACK-on-receipt state a sender was
        # already told AA for. The engine must now leave it alone.
        message_id = await store.enqueue_ingress(channel_id=INBOUND, raw=RAW)
        # Generous next to the control above, which delivers in well under this at poll_interval 0.02.
        await asyncio.sleep(1.0)

        assert list(outdir.iterdir()) == []  # nothing was delivered
        assert await store.outbox_for(message_id) == []  # nothing even reached the outbound stage
        # RECEIVED, not ROUTED/FILTERED/UNROUTED/PROCESSED: the router never ran on it.
        assert (await store.get_message(message_id))["status"] == MessageStatus.RECEIVED.value
        # …and the row is intact and still claimable, so fixing the disk and restarting drains it.
        claimed = await store.claim_next_fifo(INBOUND, stage=Stage.INGRESS.value)
        assert claimed is not None and claimed.message_id == message_id
        await store.release_claimed([claimed.id])  # leave it exactly as the halt left it
    finally:
        await runner.stop()


@pytest.mark.parametrize("claim_mode", CLAIM_MODES)
async def test_restarting_the_connections_re_arms_processing_after_the_halt(
    store: MessageStore, tmp_path: Path, claim_mode: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    # THE RECOVERY HALF, and it is not optional: a fail-closed halt whose re-arm is broken is an
    # engine that stays deaf after the disk is fixed, and nothing above would notice. The ADR promises
    # "fix the disk, restart, and the backlog drains" — this is that sentence, measured. It also
    # covers the ordering trap in _start_inbound_unsafe: resume BEFORE the worker respawn, or the
    # respawned worker hits its own gate and exits while the restart reports success.
    outdir, logdir = tmp_path / "out", tmp_path / "logs"
    outdir.mkdir()
    logdir.mkdir()
    runner = _e2e_runner(store, outdir, logdir, claim_mode)
    await runner.start()
    try:
        _kill_every_sink(logdir, monkeypatch)
        logging.getLogger("t").warning("a record this engine cannot write anywhere")
        assert await _until(lambda: runner._log_write_stopped), "the halt never fired"
        message_id = await store.enqueue_ingress(channel_id=INBOUND, raw=RAW)
        await asyncio.sleep(0.3)
        assert await store.outbox_for(message_id) == []  # still halted

        _revive_every_sink(logdir, monkeypatch)  # the operator actually fixes the disk
        await runner.restart_inbound(INBOUND)  # …and only THEN restarts
        await runner.start_outbound(OUTBOUND)

        assert await _until(lambda: any(outdir.iterdir())), (
            "the backlog never drained after the restart"
        )
        assert await _until_processed(store, message_id), "drained but never finalized"
        assert INBOUND not in runner._log_halted
    finally:
        await runner.stop()


@pytest.mark.parametrize("claim_mode", CLAIM_MODES)
async def test_a_restart_is_refused_while_the_log_is_still_unwritable(
    store: MessageStore, tmp_path: Path, claim_mode: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    # THE OTHER HALF OF THE ENFORCEMENT, and it was a MEASURED hole rather than a hypothetical: the
    # halt fired correctly, and then `restart_inbound` + `start_outbound` re-armed the entire pipeline
    # while the guard's own state still read {'file': 'unwritable', 'stdout': 'unwritable'}. The
    # message went to PROCESSED with no application log behind it, in BOTH claim modes. Worse, it was
    # unrecoverable-by-design: `_log_write_stopped` and the guard's per-sink `already_down` latch are
    # both one-shot, so after that first restart NOTHING could ever fail-closed again in that process.
    #
    # A fail-closed control that any restart disarms is a control with an off switch. The recovery
    # tests above pass because they REPAIR the log first; this one proves the repair is what earns the
    # re-arm, rather than the restart command by itself.
    outdir, logdir = tmp_path / "out", tmp_path / "logs"
    outdir.mkdir()
    logdir.mkdir()
    runner = _e2e_runner(store, outdir, logdir, claim_mode)
    await runner.start()
    try:
        _kill_every_sink(logdir, monkeypatch)
        logging.getLogger("t").warning("a record this engine cannot write anywhere")
        assert await _until(lambda: runner._log_write_stopped), "the halt never fired"

        # The operator restarts WITHOUT fixing anything. Deliberately no _revive_every_sink.
        await runner.restart_inbound(INBOUND)
        await runner.start_outbound(OUTBOUND)

        message_id = await store.enqueue_ingress(channel_id=INBOUND, raw=RAW)
        await asyncio.sleep(1.0)  # generous: the repaired path drains far inside this

        assert INBOUND in runner._log_halted  # the re-arm was refused, not silently granted
        assert INBOUND not in runner._sources  # …and intake did not come back either
        assert list(outdir.iterdir()) == []
        assert await store.outbox_for(message_id) == []
        assert (await store.get_message(message_id))["status"] == MessageStatus.RECEIVED.value

        # The refusal is not permanent — it is conditioned on the log, so the SAME restart works once
        # the disk is fixed. Without this the test would also pass against an engine that simply never
        # restarts anything, which is the wrong control for the right reason.
        _revive_every_sink(logdir, monkeypatch)
        await runner.restart_inbound(INBOUND)
        await runner.start_outbound(OUTBOUND)
        assert await _until(lambda: any(outdir.iterdir())), "the repaired engine never drained"
        assert await _until_processed(store, message_id), "drained but never finalized"
    finally:
        await runner.stop()


@pytest.mark.parametrize("claim_mode", CLAIM_MODES)
async def test_restart_outbound_is_refused_while_the_log_is_still_unwritable(
    store: MessageStore, tmp_path: Path, claim_mode: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    # THE SECOND DOOR INTO DELIVERY, and the one that had no gate. The test above drives
    # `restart_inbound` + `start_outbound`; nothing covered `restart_outbound`, which reached
    # `_start_outbound_unsafe` straight through. `RegistryRunner._outbound_start_permitted` carries
    # what that would have cost and why this door is reachable with no operator at all.
    #
    # QUEUED WORK IS THE SUBJECT, not scenery. The lane is paused while the log is still healthy and
    # a message is driven onto the outbound stage BEFORE the halt, so a real delivery is sitting
    # there when the restart arrives. On an empty lane "no file was written" cannot tell a working
    # gate from a lane that had nothing to deliver.
    outdir, logdir = tmp_path / "out", tmp_path / "logs"
    outdir.mkdir()
    logdir.mkdir()
    sink = _RecordingSink()
    runner = _e2e_runner(store, outdir, logdir, claim_mode, alert_sink=sink)
    await runner.start()
    try:
        await runner.stop_outbound(OUTBOUND)
        message_id = await store.enqueue_ingress(channel_id=INBOUND, raw=RAW)
        assert await _until_outbound_row(store, message_id), "never reached the outbound stage"
        assert list(outdir.iterdir()) == []  # paused: routed and transformed, but not shipped

        _kill_every_sink(logdir, monkeypatch)
        logging.getLogger("t").warning("a record this engine cannot write anywhere")
        assert await _until(lambda: runner._log_write_stopped), "the halt never fired"

        # The restart arrives with NOTHING repaired. Deliberately no _revive_every_sink.
        await runner.restart_outbound(OUTBOUND)
        await asyncio.sleep(1.0)  # generous: the repaired lane below ships far inside this

        assert list(outdir.iterdir()) == []  # the queued row was NOT delivered
        assert OUTBOUND in runner._outbound_paused  # …and the lane was left PAUSED, not resumed
        assert runner._log_write_stopped  # the halt is still latched — a restart must not disarm it
        # …and its delivery row is retained PENDING, not dead-lettered by the refusal.
        assert len(await store.outbox_for(message_id)) == 1
        # The refusal PAGED rather than passing silently. `stopped=0` is the refusal's own signature:
        # the halt itself reports how many connections it stopped, which is non-zero here.
        assert [f for f in sink.log_failures if f[3] == 0 and OUTBOUND in f[2]], (
            f"the refusal never paged: {sink.log_failures}"
        )

        # THE OTHER HALF, and it is required: a refusal-only test also passes against a lane that is
        # permanently broken, which is the wrong engine for the right reason. The REPAIR is what earns
        # the restart, so the same call must now deliver the same row.
        _revive_every_sink(logdir, monkeypatch)
        await runner.restart_outbound(OUTBOUND)
        # The delivered file IS the un-pause, so no separate _outbound_paused assertion here — unlike
        # the refusal half above, where "nothing delivered" and "left paused" are different outcomes
        # (an un-paused lane could merely be slow).
        assert await _until(lambda: any(outdir.iterdir())), "the repaired lane never delivered"
        assert await _until_processed(store, message_id), "delivered but never finalized"
    finally:
        await runner.stop()


def test_revalidate_reports_a_process_that_still_cannot_log(tmp_path: Path) -> None:
    # The guard-level unit behind the refusal above. `unwritable` is set only by a failed write and
    # nothing clears it, so a cached read cannot tell "fixed" from "still broken" — revalidate answers
    # by WRITING. Both directions, because a revalidate that always said False would pass the refusal
    # test for the wrong reason.
    logdir = tmp_path / "logs"
    logdir.mkdir()
    guard = LogWriteGuard()
    handler = _file_handler(logdir / "engine.log", guard)
    _break_the_open_handle(handler)
    _replace_directory_with_a_file(logdir)
    handler.emit(_record("first write after the break"))
    assert [s.state for s in guard.status()] == ["unwritable"]

    assert guard.revalidate() is False  # still broken: the probe write cannot land
    assert guard.can_log() is False

    logdir.unlink()
    logdir.mkdir()
    assert guard.revalidate() is True  # repaired: the probe rolled to a fresh file and wrote
    assert guard.can_log() is True
    assert [s.state for s in guard.status()] == ["healthy"]
    # The latch is genuinely cleared, so a LATER break pages again instead of being swallowed.
    events: list[LogSinkEvent] = []
    guard.set_escalation(events.append)
    _break_the_open_handle(handler)
    _replace_directory_with_a_file(logdir)
    handler.emit(_record("a second, independent break"))
    assert [e.stage for e in events] == ["unwritable"]
    assert events[0].stop_requested is True


# --- the two observability channels the ADR leans on, each pinned ------------


def test_the_alert_type_is_operator_rule_targetable() -> None:
    # ADR 0162 §5 claims an operator can route "the engine went deaf" APART from one stalled lane.
    # That claim is only true if `log_write_failed` is in settings._ALERT_EVENT_TYPES — a name added
    # to alert_sinks but omitted there is silently un-targetable (AlertRule rejects it), which is
    # precisely the defect ALERT-12 records for lane_stuck and rcsi_off_degraded.
    from messagefoundry.config.settings import AlertRule, AlertSeverity
    from messagefoundry.pipeline.alert_sinks import AlertRuleSet

    rules = AlertRuleSet(
        [AlertRule(event_type="log_write_failed", severity=AlertSeverity.CRITICAL)]
    )
    assert rules.decide({"type": "log_write_failed", "connection": "file"}).severity == "critical"
    # …and a different event still falls through to the default, so the rule is targeted, not global.
    assert rules.decide({"type": "connection_stopped", "connection": "IB_X"}).severity == "warning"


def test_status_reports_per_sink_health_from_process_memory(tmp_path: Path) -> None:
    # The THIRD channel, and the ADR's reason for having it: a log line about a broken log sink may
    # never land and an engine with no notifier configured pages nobody, but /status answers from
    # process memory. So it must report the break WITHOUT touching the filesystem it is reporting on.
    from messagefoundry.api.app import _log_sink_health

    logdir = tmp_path / "logs"
    logdir.mkdir()
    configure_logging("INFO", log_file=LogFile(path=str(logdir / "engine.log")))
    assert {s.sink: s.state for s in _log_sink_health()} == {"stdout": "healthy", "file": "healthy"}

    _break_sink_and_replacement(_installed_file_sink(), logdir)
    logging.getLogger("t").warning("a record this engine cannot write anywhere")

    reported = {s.sink: s for s in _log_sink_health()}
    assert reported["file"].state == "unwritable"
    assert reported["stdout"].state == "healthy"  # the break is per-sink, not global
    # Metadata only — a scrubbed reason and a timestamp, never a line of the log.
    assert reported["file"].last_event and reported["file"].last_event_at
    assert "a record this engine cannot write anywhere" not in (reported["file"].last_event or "")


def test_a_second_responder_taking_the_slot_is_announced(
    capsys: pytest.CaptureFixture[str],
) -> None:
    # The escalation seam holds ONE responder. A second RegistryRunner in the same process takes the
    # slot and the first engine is silently unguarded from then on — a fail-closed control that
    # disappears with every assertion in this file still green. One process runs one engine, so this
    # is not made an error; it is made AUDIBLE, which is the difference between a known limit and a
    # silent one.
    guard = LogWriteGuard()
    guard.set_escalation(lambda event: None)
    capsys.readouterr()  # discard anything from the first wiring
    guard.set_escalation(lambda event: None)

    assert "no longer guarded" in capsys.readouterr().err


def test_re_wiring_the_same_responder_is_silent(capsys: pytest.CaptureFixture[str]) -> None:
    # …and the negative control, because a warning that fires on the ordinary case gets ignored:
    # re-installing the SAME callback (a restart re-subscribing) displaces nobody and says nothing.
    def responder(event: LogSinkEvent) -> None:
        return None

    guard = LogWriteGuard()
    guard.set_escalation(responder)
    capsys.readouterr()
    guard.set_escalation(responder)
    guard.set_escalation(None)

    assert capsys.readouterr().err == ""


@pytest.mark.parametrize("claim_mode", CLAIM_MODES)
async def test_a_reload_re_arms_exactly_the_inbounds_it_re_binds(
    store: MessageStore, tmp_path: Path, claim_mode: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    # MEASURED, because the reload path was read two ways before it was run. reload() quiesces every
    # source and then calls _start_inbound_unsafe for each inbound the new graph re-binds — which is
    # where the re-arm lives — so a reload DOES resume the inbounds it re-binds, and leaves the ones
    # it declines to bind (deployed=False / auto_start=False+not-previously-listening / DR-filtered)
    # halted. Both halves matter: "a reload fixes it" and "a reload fixes nothing" are each half
    # right, and shipping either sentence alone would send an operator the wrong way during an
    # incident.
    outdir, logdir = tmp_path / "out", tmp_path / "logs"
    outdir.mkdir()
    logdir.mkdir()
    runner = _e2e_runner(store, outdir, logdir, claim_mode)
    await runner.start()
    try:
        _kill_every_sink(logdir, monkeypatch)
        logging.getLogger("t").warning("a record this engine cannot write anywhere")
        assert await _until(lambda: runner._log_write_stopped), "the halt never fired"
        message_id = await store.enqueue_ingress(channel_id=INBOUND, raw=RAW)
        await asyncio.sleep(0.3)
        assert await store.outbox_for(message_id) == []  # still halted

        _revive_every_sink(logdir, monkeypatch)  # a reload re-arms only once the log works again
        await runner.reload(_e2e_registry(outdir))

        assert INBOUND not in runner._log_halted  # re-bound, therefore re-armed
        # …and it re-armed the STAGES, not just the flag: the row moves again. The OUTBOUND pause is
        # operator-owned and a reload must NOT resume it (#115/#233), so the row reaches the outbound
        # stage and waits there — the honest reach of a reload, and why the docs still say restart.
        assert await _until_outbound_row(store, message_id), "the reload re-armed nothing"
        assert list(outdir.iterdir()) == []  # …but delivery is still paused
        await runner.start_outbound(OUTBOUND)
        assert await _until(lambda: any(outdir.iterdir())), "never drained after reload + resume"
        assert await _until_processed(store, message_id), "drained but never finalized"
    finally:
        await runner.stop()


@pytest.mark.parametrize("claim_mode", CLAIM_MODES)
async def test_a_runner_started_into_a_dead_log_comes_up_halted(
    store: MessageStore, tmp_path: Path, claim_mode: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    # THE RE-ARM PATH THAT WAS NOT GATED, and it was found by execution rather than review. Every
    # OTHER door back into processing asks `_log_recovery_ok` first — `restart_inbound`,
    # `start_outbound`, a reload's `_start_inbound_unsafe`. `RegistryRunner.start` did not: it cleared
    # `_log_write_stopped` and `_log_halted` unconditionally, on the reasoning that a fresh start is a
    # fresh engine.
    #
    # MEASURED RED, in BOTH claim modes, on the rig below: with both sinks unwritable BEFORE the
    # runner was built, a committed ingress row went to `PROCESSED` and was DELIVERED while
    # `guard.can_log()` read False the whole time. That is the item's own sentence — processing what
    # cannot be logged — reached through the one path the halt did not cover. It is not hypothetical
    # plumbing: `Engine` starts a RegistryRunner on leadership acquisition and on the reload that
    # first builds one, and neither asks about the log.
    #
    # The engine comes up HALTED rather than refusing to start, because /status, the alert state and
    # the recovery paths are what an operator needs precisely here.
    outdir, logdir = tmp_path / "out", tmp_path / "logs"
    outdir.mkdir()
    logdir.mkdir()
    configure_logging("INFO", log_file=LogFile(path=str(logdir / "engine.log")))
    _kill_every_sink(logdir, monkeypatch)  # the log dies BEFORE the runner exists
    logging.getLogger("t").warning("a record this process cannot write anywhere")
    guard = active_guard()
    assert guard is not None and not guard.can_log(), "the rig never made the process unable to log"

    runner = RegistryRunner(_e2e_registry(outdir), store, poll_interval=0.02, claim_mode=claim_mode)
    await runner.start()
    try:
        assert runner._log_write_stopped, "start cleared the halt against an unwritable log"
        assert INBOUND in runner._log_halted
        assert INBOUND not in runner._sources, "intake stayed up with the internal stages halted"

        message_id = await store.enqueue_ingress(channel_id=INBOUND, raw=RAW)
        await asyncio.sleep(1.0)  # generous: the healthy rig above delivers far inside this
        assert list(outdir.iterdir()) == []
        assert await store.outbox_for(message_id) == []
        assert (await store.get_message(message_id))["status"] == MessageStatus.RECEIVED.value

        # …and the halt is CONDITIONED, not permanent — otherwise this test would also pass against a
        # runner that simply never processes anything, which is the wrong control for the right reason.
        _revive_every_sink(logdir, monkeypatch)
        await runner.restart_inbound(INBOUND)
        await runner.start_outbound(OUTBOUND)
        assert await _until(lambda: any(outdir.iterdir())), "the repaired engine never drained"
        assert await _until_processed(store, message_id), "drained but never finalized"
    finally:
        await runner.stop()


@pytest.mark.parametrize("claim_mode", CLAIM_MODES)
async def test_a_stop_then_start_does_not_resume_delivery_into_a_dead_log(
    store: MessageStore, tmp_path: Path, claim_mode: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    # THE DELIVERY TIER OF THE START-TIME HALT, and the test above does not reach it. That one leaves
    # its message stranded at the INGRESS stage, so its `outdir` assertion is satisfied by the
    # internal-stage halt alone and would stay green against a runner whose outbound lanes came up
    # wide open. Here a real delivery row is ALREADY on the outbound stage when the restart arrives,
    # which is the only arrangement that can tell those two engines apart.
    #
    # MEASURED RED before `start` parked the delivery lanes, in BOTH claim modes: the queued row was
    # written into `outdir` while `guard.can_log()` read False throughout. The route in is ordinary —
    # `_teardown_body` clears `_outbound_paused` (an operator pause is in-memory and deliberately does
    # not survive a teardown), and `start`'s own outbound spawn asked nothing about the log — so a
    # service restart, an HA demote-then-promote, or `stop()`+`start()` from the API would each have
    # resumed delivery with no application log behind it on a first deployment.
    outdir, logdir = tmp_path / "out", tmp_path / "logs"
    outdir.mkdir()
    logdir.mkdir()
    runner = _e2e_runner(store, outdir, logdir, claim_mode)
    await runner.start()
    try:
        # Park the lane while the log still works, so a GENUINE delivery is queued and waiting. On an
        # empty outbound stage "no file was written" cannot tell a working gate from an empty lane.
        await runner.stop_outbound(OUTBOUND)
        message_id = await store.enqueue_ingress(channel_id=INBOUND, raw=RAW)
        assert await _until_outbound_row(store, message_id), "never reached the outbound stage"
        assert list(outdir.iterdir()) == []  # paused: routed and transformed, but not shipped

        _kill_every_sink(logdir, monkeypatch)
        logging.getLogger("t").warning("a record this engine cannot write anywhere")
        assert await _until(lambda: runner._log_write_stopped), "the halt never fired"

        # The restart arrives with NOTHING repaired. Deliberately no _revive_every_sink.
        await runner.stop()
        await runner.start()
        await asyncio.sleep(1.0)  # generous: the repaired restart below ships far inside this

        assert runner._log_write_stopped, "start disarmed the halt against an unwritable log"
        assert list(outdir.iterdir()) == [], (
            "a queued row shipped with no application log behind it"
        )
        assert OUTBOUND in runner._outbound_paused  # the lane came back DOWN, not merely slow
        # …and its delivery row is retained PENDING, not dead-lettered by the refusal.
        assert len(await store.outbox_for(message_id)) == 1

        # THE CONTROL, and it carries the attribution: the ONLY difference between these two arms is
        # whether the log works. The same stop()+start(), on the same rig, with the same queued row,
        # must deliver once the disk is fixed — otherwise this test would also pass against an engine
        # that never resumes delivery after any restart, which is the wrong engine for the right
        # reason. It also proves the assertion above is capable of failing.
        _revive_every_sink(logdir, monkeypatch)
        await runner.stop()
        await runner.start()

        assert await _until(lambda: any(outdir.iterdir())), "the repaired restart never delivered"
        assert await _until_processed(store, message_id), "delivered but never finalized"
        assert OUTBOUND not in runner._outbound_paused
    finally:
        await runner.stop()


@pytest.mark.parametrize("claim_mode", CLAIM_MODES)
async def test_a_reload_that_re_deploys_a_parked_lane_is_refused_into_a_dead_log(
    store: MessageStore, tmp_path: Path, claim_mode: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    # THE THIRD DOOR, and it is the one the halt walks straight past. `_stop_all_for_log_failure`
    # pauses the outbound lanes that are RUNNING; a lane the ENGINE parked (auto_start=False #115 /
    # deployed=False #233) is already in `_outbound_paused`, so the halt skips it and its
    # `_gate_parked` marker survives untouched. A reload that flips the flag back then calls
    # `_unpark_outbound_lane`, which is the one resume path that never asked about the log.
    #
    # MEASURED RED before that helper was gated, in BOTH claim modes: the reload resumed the lane and
    # its queued row was delivered with both sinks dead. `start_outbound`'s docstring reasons that a
    # reload is safe because `_stop_outbound_unsafe` drops the `_gate_parked` marker — true of a lane
    # the HALT paused, and silent about the lane the halt never touched.
    outdir, logdir = tmp_path / "out", tmp_path / "logs"
    outdir.mkdir()
    logdir.mkdir()
    parked = _e2e_registry(outdir, outbound_auto_start=False)  # engine-parked at boot
    configure_logging("INFO", log_file=LogFile(path=str(logdir / "engine.log")))
    runner = RegistryRunner(parked, store, poll_interval=0.02, claim_mode=claim_mode)
    await runner.start()
    try:
        assert OUTBOUND in runner._gate_parked, "the rig never engine-parked the lane"
        message_id = await store.enqueue_ingress(channel_id=INBOUND, raw=RAW)
        assert await _until_outbound_row(store, message_id), "never reached the outbound stage"
        assert list(outdir.iterdir()) == []

        _kill_every_sink(logdir, monkeypatch)
        logging.getLogger("t").warning("a record this engine cannot write anywhere")
        assert await _until(lambda: runner._log_write_stopped), "the halt never fired"
        assert OUTBOUND in runner._gate_parked  # the halt left the engine-park marker in place

        # The operator re-deploys the lane with NOTHING repaired. `_e2e_registry` defaults
        # auto_start=True, so this reload is exactly the "flip the flag back" case (AC-4).
        await runner.reload(_e2e_registry(outdir))
        await asyncio.sleep(1.0)  # generous: the repaired reload below ships far inside this

        assert list(outdir.iterdir()) == [], (
            "a queued row shipped with no application log behind it"
        )
        assert OUTBOUND in runner._outbound_paused  # the lane stayed down
        assert (
            OUTBOUND in runner._gate_parked
        )  # …and recoverably so: a later reload can still lift it
        assert len(await store.outbox_for(message_id)) == 1

        # THE CONTROL: the same reload, once the disk is fixed, must un-park the lane and ship the
        # same row. Without it a refusal-only assertion would also pass against an engine that can
        # never re-deploy a parked lane at all.
        _revive_every_sink(logdir, monkeypatch)
        await runner.reload(_e2e_registry(outdir))

        assert await _until(lambda: any(outdir.iterdir())), "the repaired reload never delivered"
        assert await _until_processed(store, message_id), "delivered but never finalized"
        assert OUTBOUND not in runner._gate_parked
    finally:
        await runner.stop()


# --- the door nobody has enumerated (ADR 0189) -------------------------------


@pytest.mark.parametrize("claim_mode", CLAIM_MODES)
async def test_an_unguarded_start_cannot_deliver_while_the_halt_is_latched(
    store: MessageStore, tmp_path: Path, claim_mode: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    # THE TEST THAT JUSTIFIES THE LATCH, and the only one here that is not about a door somebody
    # already found. The four tests above each pin ONE entry into resuming delivery — start_outbound,
    # restart_outbound, stop-then-start, and the reload's un-park — and each of those four was
    # discovered the same way: in behaviour, after the previous fix shipped. Four gates are a
    # completeness claim nobody can verify (CLAUDE.md section 11, SDS-3.6), so this test deliberately
    # declines to use any of them.
    #
    # `_start_outbound_unsafe` is the unguarded primitive every one of the four doors eventually
    # calls. Driving it DIRECTLY is a stand-in for the fifth door — whatever it turns out to be — and
    # what it asserts is structural: with the delivery tier's halt latched and both sinks genuinely
    # dead, a lane brought up by a path that asked NOTHING still ships no bytes. That is a claim about
    # the claim gate, which every delivery passes through whichever door started the lane, and it
    # cannot be satisfied by adding a fifth gate at a fifth door.
    #
    # MEASURED RED on main before `_delivery_halted` existed, in BOTH claim modes: the queued row was
    # written into `outdir` while `guard.can_log()` read False throughout.
    outdir, logdir = tmp_path / "out", tmp_path / "logs"
    outdir.mkdir()
    logdir.mkdir()
    runner = _e2e_runner(store, outdir, logdir, claim_mode)
    await runner.start()
    try:
        # Park the lane while the log still works, so a GENUINE delivery is queued and waiting — on an
        # empty outbound stage "no file was written" cannot tell a working gate from an empty lane.
        await runner.stop_outbound(OUTBOUND)
        message_id = await store.enqueue_ingress(channel_id=INBOUND, raw=RAW)
        assert await _until_outbound_row(store, message_id), "never reached the outbound stage"
        assert list(outdir.iterdir()) == []

        _kill_every_sink(logdir, monkeypatch)
        logging.getLogger("t").warning("a record this engine cannot write anywhere")
        assert await _until(lambda: runner._log_write_stopped), "the halt never fired"
        assert runner._delivery_halted, "the delivery tier's latch never closed"

        # THE FIFTH DOOR: straight past start_outbound, restart_outbound, the teardown park and the
        # reload's un-park, into the primitive all four of them share. Nothing is repaired first.
        await runner._start_outbound_unsafe(OUTBOUND)
        await asyncio.sleep(1.0)  # generous: the repaired restart below ships far inside this

        # THE LOAD-BEARING ASSERTION, and it is bytes on disk written by a real File connector out of
        # a real store — not a read-back of the flag this change adds.
        assert list(outdir.iterdir()) == [], (
            "a queued row shipped with no application log behind it"
        )
        # …and the row is RETAINED PENDING, not dead-lettered and not stranded INFLIGHT by the refusal.
        assert len(await store.outbox_for(message_id)) == 1
        assert runner._delivery_halted, "the unguarded start cleared the latch"
        # The lane also reports the CAUSE rather than an operator pause it never had.
        assert runner.outbound_status(OUTBOUND) == "log_halted"
        assert not runner.outbound_running(OUTBOUND)
        # …and a resend's 409 names the log rather than pointing at a start button that is refused
        # while the sinks are dead. The old wording is the one this must NOT be.
        detail = _outbound_down_detail(runner, OUTBOUND)
        assert "application log" in detail
        assert "start it before resending" not in detail

        # THE CONTROL, and it carries the attribution: the ONLY difference between these two arms is
        # whether the log works. The same rig, the same queued row, delivered once the disk is fixed —
        # so the refusal above cannot be an engine that never delivers, and the assertion is shown able
        # to fail. Recovery goes through a GATED door on purpose: lifting the latch is the doors' job,
        # and the claim gate is defence in depth behind them, never the recovery path.
        _revive_every_sink(logdir, monkeypatch)
        await runner.restart_outbound(OUTBOUND)
        assert not runner._delivery_halted, "a repaired restart left the latch closed"

        assert await _until(lambda: any(outdir.iterdir())), "the repaired restart never delivered"
        assert await _until_processed(store, message_id), "delivered but never finalized"
        assert runner.outbound_status(OUTBOUND) == "running"
        # The NEGATIVE control on the 409 wording: a lane that is merely operator-paused must still
        # get the start-it instruction, so the branch above is a discrimination and not a rewrite.
        await runner.stop_outbound(OUTBOUND)
        assert "start it before resending" in _outbound_down_detail(runner, OUTBOUND)
    finally:
        await runner.stop()


@pytest.mark.parametrize("claim_mode", CLAIM_MODES)
async def test_a_reload_that_adds_an_outbound_into_a_dead_log_lands_it_paused(
    store: MessageStore, tmp_path: Path, claim_mode: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    # DOOR SIX, which ADR 0189 named in option 4's rejection and did not close. Every other door is
    # about a lane the halt ALREADY saw. This one is about a lane that did not exist when the halt
    # ran: `_stop_all_for_log_failure` pauses the lanes in `self.registry.outbound`, so an outbound a
    # LATER reload adds is in neither `_outbound_paused` nor `_gate_parked`, the reload's un-park gate
    # never asks about it, and `_reconcile_outbounds` builds its connector and arms its lane.
    #
    # WHAT IS RED HERE IS THE LANE STATE, NOT THE BYTES, and saying so is the point. The claim gate
    # this ADR added already refuses every row, so `outdir_added` stays empty with or without the fix
    # — the byte assertion below is a guard against a regression in the latch, not the discriminator
    # for this door. What the ungated lane does instead is reach that gate once per backoff for the
    # halt's whole duration, which is why the row-untouched assertion is here too: it is the spin
    # itself, and in pooled it is the assertion that moves.
    outdir, added, logdir = tmp_path / "out", tmp_path / "added", tmp_path / "logs"
    outdir.mkdir()
    added.mkdir()
    logdir.mkdir()

    # PHASE 1 — a healthy engine queues a real row to the lane, with the lane engine-parked so nothing
    # delivers it. A row addressed to a connection the engine does not currently declare is the whole
    # premise: an operator removed it from the graph and later adds it back, and its rows waited.
    # STDOUT ONLY here, and it is not a shortcut: `configure_logging` REMOVES a prior file handler
    # without closing it (it closes only its own forward-queue handler, since an embedding host may
    # still be using the rest), so a second call for the same path would leave phase 1's OS handle open
    # and `_kill_every_sink`'s rmtree would fail on Windows with a PermissionError rather than
    # producing the condition under test. Phase 2 is the only call here that opens the file sink.
    configure_logging("INFO")
    seeding = RegistryRunner(
        _e2e_registry(outdir, added_outdir=added, added_auto_start=False),
        store,
        poll_interval=0.02,
        claim_mode=claim_mode,
    )
    await seeding.start()
    try:
        message_id = await store.enqueue_ingress(channel_id=INBOUND, raw=RAW)
        assert await _until_outbound_row(store, message_id, count=2), (
            "never fanned out to both lanes"
        )
        # Wait for the first lane's row to be DONE IN THE STORE, not merely for its file to exist.
        # Those are different instants and the gap is a real race this test hit: the connector writes
        # the file, and the store write marking the row done commits after it. Stopping the runner in
        # that gap leaves the row INFLIGHT, phase 2's `reset_stale_inflight` reverts it to PENDING, and
        # the message can then never reach PROCESSED — because that lane is paused by the halt for the
        # rest of the test and nothing will ever deliver it again. It surfaced once in six runs, at the
        # control arm's "delivered but never finalized", a good three assertions away from its cause.
        assert await _until_delivery_status(store, message_id, OUTBOUND, "done"), (
            "the first lane never recorded its delivery"
        )
    finally:
        await seeding.stop()
    assert list(added.iterdir()) == [], "the engine-parked lane delivered at boot"
    # The premise of everything below: exactly one row is left for the lane phase 2 has never heard of.
    assert await _until_delivery_status(
        store, message_id, OUTBOUND_ADDED, "pending", timeout=0.0
    ), "the engine-parked lane's row is not waiting PENDING"

    # PHASE 2 — a second engine comes up on the SAME store WITHOUT that connection. The row sits: the
    # pooled lane provider is `registry.outbound | _destinations`, and this graph has it in neither.
    runner = _e2e_runner(store, outdir, logdir, claim_mode)
    await runner.start()
    try:
        assert OUTBOUND_ADDED not in runner._destinations

        _kill_every_sink(logdir, monkeypatch)
        logging.getLogger("t").warning("a record this engine cannot write anywhere")
        assert await _until(lambda: runner._log_write_stopped), "the halt never fired"
        assert runner._delivery_halted, "the delivery tier's latch never closed"
        assert OUTBOUND_ADDED not in runner._outbound_paused, (
            "the halt cannot have paused a lane that is not in its registry — the rig is wrong"
        )

        before = await _added_row(store, message_id)

        # A margin of TEN claim cycles, not one, and the patch goes on BEFORE the reload. The pooled
        # gate parks its lane for `_WORKER_ERROR_BACKOFF_SECONDS`, read from the module at call time —
        # so patching works, and patching it AFTER the reload would not: the reload's own notify_work
        # arms the lane immediately and the first park would already have taken the shipped 1.0 s.
        # A window merely LONGER than one backoff buys a margin of one claim, and a test that
        # discriminates by exactly one event is one scheduling hiccup from proving nothing. Ten cycles
        # is a real margin AND finishes in half the wall clock a single un-patched cycle would need.
        monkeypatch.setattr(wiring_runner, "_WORKER_ERROR_BACKOFF_SECONDS", _BACKOFF)
        assert runner.halted_claim_gate_hits == 0, "the rig spun before the door was even opened"

        # THE DOOR: a reload ADDS the connection, deployed and auto-start, with nothing repaired.
        await runner.reload(_e2e_registry(outdir, added_outdir=added))
        await asyncio.sleep(10 * _BACKOFF)

        # THE LOAD-BEARING ASSERTION. The lane must land where the halt put every other lane: PAUSED,
        # with NO engine-park marker. The marker is the half that matters — `_park_outbound_lane`
        # would also satisfy the pause, and the very next reload's un-park gate would lift it again.
        assert OUTBOUND_ADDED in runner._outbound_paused, (
            "a reload brought an outbound up while the delivery halt was latched"
        )
        assert OUTBOUND_ADDED not in runner._gate_parked, (
            "parked, not stopped — a later reload would lift this marker and re-open the door"
        )
        # …and it never reached the claim gate, from the engine's side and the store's. The counter
        # names the event; the row is the independent cross-check (see :func:`_added_row`).
        assert runner.halted_claim_gate_hits == 0, (
            "a delivery lane reached the claim gate while halted — a door is missing"
        )
        assert await _added_row(store, message_id) == before, (
            "the lane claimed and rescheduled its head while the process was refusing to work"
        )
        # The latch is intact and no byte moved (true with or without the gate — see the note above).
        assert runner._delivery_halted, "the reload cleared the latch"
        assert list(added.iterdir()) == [], "a queued row shipped with no application log behind it"
        assert before["status"] == "pending", "the row was not retained PENDING"
        assert runner.outbound_status(OUTBOUND_ADDED) == "log_halted"

        # THE CONTROL, and it carries the attribution: the only difference between the two arms is
        # whether the log works. Recovery is the ordinary one — the operator fixes the disk and starts
        # the lane through a GATED door, which re-validates the sinks and lifts the latch — and it
        # ships the SAME retained row. Without this arm the refusal above would also pass against an
        # engine that can never bring an added outbound up at all.
        _revive_every_sink(logdir, monkeypatch)
        await runner.start_outbound(OUTBOUND_ADDED)
        assert not runner._delivery_halted, "a repaired start left the latch closed"

        assert await _until(lambda: any(added.iterdir())), "the repaired start never delivered"
        assert await _until_processed(store, message_id), "delivered but never finalized"
        assert runner.outbound_status(OUTBOUND_ADDED) == "running"
    finally:
        await runner.stop()


# --- the hair trigger on the DEFAULT sink, found by running the suite ---------


def test_a_swapped_stdout_stream_heals_at_stage_1_and_stops_nothing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # THE REGRESSION THIS FILE EXISTS TO PREVENT REPEATING, and it was found by the full suite rather
    # than by review. The stdout handler holds the stream OBJECT it was built with. When a supervisor
    # swaps the capture file — or, identically, when pytest tears its capture down — that object is
    # closed and every later write raises "I/O operation on closed file", INCLUDING stage 1's own
    # notice write. Stage 1 therefore failed by construction and every stdout write failure escalated
    # to stage 2. Measured in the full suite: it halted a running load engine's seven connections and
    # the load run sent ZERO messages. Re-resolving sys.stdout is the honest roll for a stream the
    # engine did not open, and it is what "a re-attempt clears the transient" always claimed to do.
    events: list[LogSinkEvent] = []
    guard = LogWriteGuard()
    guard.set_escalation(events.append)
    original, replacement = io.StringIO(), io.StringIO()
    handler = GuardedStreamHandler(original, guard=guard, sink="stdout")
    handler.setFormatter(logging.Formatter("%(message)s"))
    handler.emit(_record("before the swap"))

    monkeypatch.setattr("sys.stdout", replacement)
    original.close()  # the object the handler still points at is now dead
    handler.emit(_record("after the swap"))

    assert [e.stage for e in events] == ["rolled"]  # healed — NOT a stop
    assert guard.status()[0].state == "rolled"
    written = replacement.getvalue()
    assert "was rolled after a write failure" in written  # the event is recorded on the live stream
    assert "after the swap" in written  # …and the record that failed is re-written, not dropped
    handler.emit(_record("and it keeps working"))
    assert "and it keeps working" in replacement.getvalue()


def test_one_dead_sink_beside_a_healthy_one_does_not_ask_for_a_stop(tmp_path: Path) -> None:
    # "Can this process still log?" is the question the ruling asks, and it is NOT "did a sink
    # break?". With the opt-in [logging].file configured there are two sinks; stopping every
    # connection because ONE of them died — while the other is still accepting every record — is a
    # control resting on a false premise. It is still recorded, still alerted, still on /status:
    # visibility is unconditional, only the ENFORCEMENT is conditioned on the thing it is about.
    events: list[LogSinkEvent] = []
    guard = LogWriteGuard()
    guard.set_escalation(events.append)
    guard.register("file")  # healthy, never touched
    log_dir = tmp_path / "logs"
    log_dir.mkdir()
    handler = GuardedStreamHandler(io.StringIO(), guard=guard, sink="stdout")
    handler.setFormatter(logging.Formatter("%(message)s"))
    handler.stream.close()
    handler._roll = lambda: None  # type: ignore[method-assign]  # no live stdout to re-resolve to
    handler.emit(_record("stdout is gone but the file sink is fine"))

    assert [e.stage for e in events] == ["unwritable"]
    assert events[0].stop_requested is False  # detected and alerted, but nothing is stopped
    assert {s.sink: s.state for s in guard.status()} == {"file": "healthy", "stdout": "unwritable"}


def test_the_last_sink_dying_does_ask_for_a_stop(tmp_path: Path) -> None:
    # …and the paired positive: once the OTHER sink is unwritable too, the process genuinely cannot
    # log and the halt is asked for. Without this the test above would be indistinguishable from
    # having disarmed the control.
    events: list[LogSinkEvent] = []
    guard = LogWriteGuard()
    guard.set_escalation(events.append)
    log_dir = tmp_path / "logs"
    log_dir.mkdir()
    file_handler = _file_handler(log_dir / "app.log", guard)
    stdout_handler = GuardedStreamHandler(io.StringIO(), guard=guard, sink="stdout")
    stdout_handler.setFormatter(logging.Formatter("%(message)s"))
    stdout_handler.stream.close()
    stdout_handler._roll = lambda: None  # type: ignore[method-assign]
    stdout_handler.emit(_record("stdout first"))
    assert events[-1].stop_requested is False

    _break_the_open_handle(file_handler)
    _replace_directory_with_a_file(log_dir)
    file_handler.emit(_record("and now the file too"))

    assert [e.stage for e in events] == ["unwritable", "unwritable"]
    assert events[-1].stop_requested is True  # nothing left that can log: HALT


# --- BACKLOG #1591: the guard's OWN diagnostics go through the scrubbers ------
#
# The reason string the guard builds from a failed write is not guaranteed the handler filter chain
# -- ``logging_guard``'s module docstring lists the four consumers and says which of them can reach
# it. ``safe_exc`` covered the PHI limb; nothing covered control characters or credentials, so an
# exception message carrying a CR/LF forged a whole physical line on a sink an operator reads
# during an incident.
#
# These tests drive a REAL exception out of a REAL stream write, not a synthesized ``LogSinkEvent``:
# the reason has to be the one the guard built for the assertion to be about the shipped path. Each
# direction carries its control -- an ordinary failure reason must survive intact (a scrubber that
# mangles every diagnostic is worse than the leak), and the scrubber raising must still leave the
# operator told that a sink broke.

#: A crafted exception message: a CR/LF pair followed by text shaped like a whole log record. If any
#: consumer takes it verbatim, that tail becomes its own physical line and reads as engine output.
_FORGED_TAIL = "2026-01-01T00:00:00Z CRITICAL messagefoundry: all sinks healthy"
_FORGED_REASON = f"cannot write\r\n{_FORGED_TAIL}"

#: A synthetic DSN (never a real credential) inside a failure message. The password must be masked
#: and the scheme plus user must survive, so an operator still learns WHICH connection failed.
_DSN_REASON = "reopen failed for postgres://mefor_svc:s3cr3t-pw@dbhost:5432/mefor"


class _HostileWriteStream(io.StringIO):
    """A real stream object whose ``write`` raises a CHOSEN exception.

    The suite's other breakages (a closed handle, a directory replaced by a file) are genuine but
    give whatever message CPython or the OS decides -- and none of them contains a control character,
    so they cannot exercise the thing under test. This narrows the substitution to the exception
    VALUE: the handler, the guard, the roll and the notice write are all the shipped code, and the
    exception still arrives at ``handleError`` through ``sys.exception()`` exactly as a real one
    does. ``io.StringIO`` is the base so ``close``/``flush`` behave, which the roll depends on."""

    def __init__(self, exc: BaseException) -> None:
        super().__init__()
        self._exc = exc

    def write(self, s: str) -> int:
        raise self._exc


def _fail_the_next_write(handler: GuardedFileHandler, message: str) -> None:
    # CLOSE THE REAL HANDLE BEFORE REBINDING. Dropping the last reference to it instead leaves the
    # OS handle alive until the interpreter happens to collect it, and CPython's open() does not ask
    # for FILE_SHARE_DELETE -- so on Windows the os.replace inside _roll would raise PermissionError
    # and every test built on this helper would flip to stage 2 for a reason unrelated to what it
    # asserts. `_break_the_open_handle` above closes explicitly for the same reason.
    if handler.stream is not None:
        handler.stream.close()
    handler.stream = _HostileWriteStream(OSError(message))


def test_a_stream_error_cannot_forge_a_line_in_the_notice_it_causes(tmp_path: Path) -> None:
    # CONSUMER 1 of 4, and the one the row is named for. The notice is written by ``_emit_direct``,
    # deliberately below ``Handler.handle``, so no filter will ever scrub it -- the escape has to
    # happen where the reason is built or not at all.
    guard = LogWriteGuard()
    log_path = tmp_path / "app.log"
    handler = _file_handler(log_path, guard)
    _fail_the_next_write(handler, _FORGED_REASON)

    handler.emit(_record("ordinary"))

    lines = log_path.read_text(encoding="utf-8").splitlines()
    # Exactly two physical lines: the rollover notice and the re-written record. A third line IS the
    # defect -- it would be the forged one.
    assert len(lines) == 2, f"the notice forged an extra physical line: {lines!r}"
    assert "was rolled after a write failure" in lines[0]
    assert lines[1] == "ordinary"
    # The text survives in escaped form, so the operator still reads the real cause.
    assert "cannot write\\r\\n" in lines[0]
    assert _FORGED_TAIL in lines[0]  # …on the notice's own line, not on one of its own


def test_the_ordinary_failure_reason_survives_the_scrub_intact(tmp_path: Path) -> None:
    # THE NEGATIVE CONTROL for every assertion above. A scrubber that mangles ordinary diagnostics
    # would pass the forged-line tests and cost the operator the message they need during an
    # incident, so the real closed-handle break must read exactly as it did before.
    guard = LogWriteGuard()
    log_path = tmp_path / "app.log"
    handler = _file_handler(log_path, guard)
    _break_the_open_handle(handler)

    handler.emit(_record("ordinary"))

    notice = log_path.read_text(encoding="utf-8").splitlines()[0]
    # The REASON span only, not the whole line. The line also carries the rolled-aside path, and on
    # Windows a temp directory whose next segment starts with n or x puts a literal backslash-n or
    # backslash-x in it -- so asserting "no escapes anywhere on this line" would red on somebody
    # else's machine while claiming the scrubber had mangled a diagnostic.
    reason = notice[notice.index("(") + 1 : notice.rindex(")")]
    assert "ValueError" in reason and "closed file" in reason
    assert "\\x" not in reason and "\\n" not in reason  # nothing was escaped that should not be
    assert "<diagnostic dropped" not in reason  # and the fallback did not fire


def test_status_and_the_alert_carry_no_raw_newline_from_a_stage_two_break(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # CONSUMERS 2, 3 and 4, which stage 2 fires at once. Scrubbing at the notice writer would leave
    # all three carrying the raw CR/LF, which is why the escape is done where the string is built
    # and again at the guard boundary that publishes it.
    events: list[LogSinkEvent] = []
    guard = LogWriteGuard()
    guard.set_escalation(events.append)
    log_dir = tmp_path / "logs"
    log_dir.mkdir()
    handler = _file_handler(log_dir / "app.log", guard)
    _fail_the_next_write(handler, _FORGED_REASON)
    _replace_directory_with_a_file(log_dir)  # the roll cannot succeed: stage 2

    handler.emit(_record("ordinary"))

    assert [e.stage for e in events] == ["unwritable"]
    reason = events[0].reason
    assert "\n" not in reason and "\r" not in reason, "the AlertSink page carries a raw line break"
    assert "cannot write\\r\\n" in reason

    last_event = guard.status()[0].last_event or ""
    assert "\n" not in last_event and "\r" not in last_event, "/status carries a raw line break"
    assert "cannot write\\r\\n" in last_event

    err = capsys.readouterr().err.splitlines()
    unwritable = [line for line in err if "IS UNWRITABLE" in line]
    assert len(unwritable) == 1
    assert _FORGED_TAIL in unwritable[0]  # on the guard's own line, not on a forged one


def test_a_credential_in_a_failure_message_is_masked_before_it_reaches_the_notice(
    tmp_path: Path,
) -> None:
    # The second scrubber the notice path was missing. ``safe_exc`` redacts HL7-shaped PHI and knows
    # nothing about credential labels, and the handler's CredentialScrubFilter never runs here, so a
    # connection string in the failure message reached the sink whole.
    guard = LogWriteGuard()
    log_path = tmp_path / "app.log"
    handler = _file_handler(log_path, guard)
    _fail_the_next_write(handler, _DSN_REASON)

    handler.emit(_record("ordinary"))

    notice = log_path.read_text(encoding="utf-8").splitlines()[0]
    assert "s3cr3t-pw" not in notice
    assert "postgres://mefor_svc" in notice  # the label survives: WHICH connection failed


def test_the_notice_is_still_emitted_when_the_scrubber_itself_raises(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # EMIT ANYWAY. A guard that goes silent because its own scrubber raised is strictly worse than
    # one reporting a degraded string: the operator would lose the fact that a sink broke at all.
    #
    # This is also the test that pins the CALL SHAPE. It can only be written because the guard calls
    # ``scrub_control_chars`` through a module-level name in its own namespace; an inlined
    # ``.translate(...)`` or a call through another module's binding would make the monkeypatch
    # below reach nothing, and this test would then pass for the wrong reason -- it asserts the
    # DEGRADED text, so a no-op patch goes red rather than green.
    def boom(text: str) -> str:
        raise RuntimeError("the scrubber is broken")

    monkeypatch.setattr(logging_guard, "scrub_control_chars", boom)
    guard = LogWriteGuard()
    log_path = tmp_path / "app.log"
    handler = _file_handler(log_path, guard)
    _fail_the_next_write(handler, _FORGED_REASON)

    handler.emit(_record("ordinary"))

    lines = log_path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 2, f"the degraded notice forged an extra physical line: {lines!r}"
    assert "was rolled after a write failure" in lines[0]
    assert "<diagnostic dropped" in lines[0]  # the degradation NAMES itself on the sink
    assert _FORGED_TAIL not in lines[0]  # …and carries nothing at all from the unscrubbed string
    assert guard.status()[0].state == "rolled"  # the break is still reported, which is the point
    # …and it is not swallowed: the stderr channel names the exception the scrubber raised.
    assert "could not be scrubbed" in capsys.readouterr().err


class _HostileRollHandler(GuardedFileHandler):
    """A sink whose roll reports a rolled-aside path carrying a line break.

    Not a contrived case: a newline is a legal filename character on POSIX, so an operator who
    configures ``[logging].file`` with one gets it interpolated into the notice and onto ``/status``.
    Subclassing is the platform-independent way to drive it -- ``_roll`` is the documented subclass
    seam and its return value is whatever the subclass says it is, so the mixin must not assume it
    is safe."""

    def _roll(self) -> str | None:
        super()._roll()
        return f"{self.baseFilename}.broken-x\r\n{_FORGED_TAIL}"


def test_a_hostile_rolled_aside_path_cannot_forge_a_line_either(tmp_path: Path) -> None:
    # The notice interpolates TWO strings the filter chain never sees. Escaping only the reason
    # would be a control resting on a false premise: the same notice would still be forgeable
    # through its other limb, and ``/status`` reports that limb too.
    guard = LogWriteGuard()
    log_path = tmp_path / "app.log"
    handler = _HostileRollHandler(str(log_path), guard=guard, sink="file")
    handler.setFormatter(logging.Formatter("%(message)s"))
    _break_the_open_handle(handler)

    handler.emit(_record("ordinary"))

    lines = log_path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 2, f"the rolled-aside path forged an extra physical line: {lines!r}"
    assert "previous file renamed to" in lines[0]
    assert "broken-x\\r\\n" in lines[0]
    rolled_aside = guard.status()[0].rolled_aside or ""
    assert "\n" not in rolled_aside and "\r" not in rolled_aside


def test_a_hostile_sink_label_cannot_forge_a_line_on_the_last_resort_channel(
    capsys: pytest.CaptureFixture[str],
) -> None:
    # THE THIRD INTERPOLATED LIMB. The stderr line carries the sink LABEL beside the reason, and
    # ``register`` takes an arbitrary str. The label is a program literal at every in-tree call
    # site, so this is unreachable today -- but escaping is one C-level pass with no credential
    # patterns behind it, so closing the limb costs less than arguing that nobody will open it.
    guard = LogWriteGuard()
    guard.register(f"file\r\n{_FORGED_TAIL}")

    guard.record_unwritable(f"file\r\n{_FORGED_TAIL}", reason="disk full")

    err = capsys.readouterr().err.splitlines()
    assert len(err) == 1, f"the sink label forged an extra physical line: {err!r}"
    assert "IS UNWRITABLE" in err[0]
    assert "file\\r\\n" in err[0]


def test_the_scrubs_run_in_the_handler_chains_order_and_the_reverse_would_leak() -> None:
    # ORDER, AND IT IS A CORRECTNESS PROPERTY RATHER THAN A STYLE ONE. _install_phi_filters installs
    # CredentialScrubFilter BEFORE ControlCharScrubFilter. Reversing it here does not merely diverge
    # from the chain, it DEFEATS the credential pass: the patterns are whitespace-delimited, so the
    # escape turns the LF between "bearer" and the token into a literal backslash-n and the pattern
    # no longer matches. The second assertion is the control that proves the first is load-bearing.
    from messagefoundry.controlchars import scrub_control_chars
    from messagefoundry.secretscrub import scrub_credentials

    hostile = "auth retry failed: bearer\nZXlKaGJHY2lPaUpJVXpJMU5pSjk.synthetic-token-value"

    assert "synthetic-token-value" not in logging_guard._safe_diagnostic(hostile)
    assert "synthetic-token-value" in scrub_credentials(scrub_control_chars(hostile)), (
        "the reversed order no longer leaks, so this test has stopped measuring the order"
    )


def test_a_credential_straddling_the_output_bound_is_masked_before_it_is_cut() -> None:
    # The bound is applied LAST, after both scrubs, and that is the correctness point. Slicing
    # BEFORE the credential pass cuts the trailing "@" that _DSN_PASSWORD needs, the pattern then
    # matches nothing, and the surviving PREFIX of the password is published to every consumer.
    limit = logging_guard._DIAGNOSTIC_LIMIT
    dsn = "postgres://mefor_svc:s3cr3t-pw@dbhost:5432/mefor"
    straddling = "q" * (limit - 27) + dsn

    scrubbed = logging_guard._safe_diagnostic(straddling)
    assert "s3cr3t" not in scrubbed
    assert len(scrubbed) == limit  # …and the output is still bounded


def test_the_diagnostic_scrub_is_not_idempotent_so_it_runs_exactly_once() -> None:
    # PINNED AS A LIMIT, NOT AS A VIRTUE. An earlier revision scrubbed again at the guard boundary
    # as belt and braces, on the premise that a second pass costs nothing. It does not: escaping
    # removes the whitespace _CREDENTIAL_KV's value class terminates on, so pass two swallows the
    # placeholder and everything up to the next real space -- and /status would then disagree with
    # the notice already written on the sink. If this test ever goes green as an equality, the
    # boundary belt can come back; until then the precondition on record_rollover is the control.
    once = logging_guard._safe_diagnostic("password=hunter2\nsecond half of the diagnostic")
    assert "hunter2" not in once and "second half of the diagnostic" in once
    assert logging_guard._safe_diagnostic(once) != once, (
        "the diagnostic scrub has become idempotent; re-read _safe_diagnostic's docstring, which "
        "tells callers to run it exactly once because it was not"
    )
    # …while the escape-only arm IS idempotent, which is what lets a path and a label be escaped
    # wherever they are touched without anyone tracking whether it already happened.
    escaped = logging_guard._escape_only("a\r\nb", fallback="x")
    assert logging_guard._escape_only(escaped, fallback="x") == escaped


def test_the_fallback_cannot_raise_on_a_diagnostic_that_is_not_a_string() -> None:
    # The whole contract of this module is that a broken log sink never becomes an application
    # exception. ``_roll`` is a subclass seam and the guard's stage methods are public, so a caller
    # can hand in something that is not a str; the fallback must not itself raise while handling it.
    # Each arm reports its OWN sentinel: /status presents rolled_aside as a filename, so a sentence
    # about scrubbers landing there would read as one.
    assert logging_guard._safe_diagnostic(12345) == logging_guard._DIAGNOSTIC_DROPPED  # type: ignore[arg-type]
    assert (
        logging_guard._escape_only(object(), fallback=logging_guard._PATH_DROPPED)  # type: ignore[arg-type]
        == logging_guard._PATH_DROPPED
    )


def test_a_legitimate_path_is_not_rewritten_by_the_credential_patterns() -> None:
    # WHY THE PATH LIMB TAKES _escape_only, NOT _safe_diagnostic. /status publishes rolled_aside so
    # an operator can find the broken file. Running a path through the credential patterns lets a
    # directory segment ending in a credential word swallow the rest of the path, so /status would
    # name a file that does not exist -- during the incident this guard exists for.
    path = "/var/log/mefor/secret=1/app.log.broken-x"

    assert logging_guard._escape_only(path, fallback=logging_guard._PATH_DROPPED) == path
    assert logging_guard._safe_diagnostic(path) != path, (
        "the credential patterns no longer rewrite this path, so the split has stopped being needed"
    )


def test_the_guards_scrub_composition_still_covers_the_installed_filter_chain() -> None:
    # THE DRIFT ALARM the composition cannot provide by construction. _scrub_diagnostic hand-copies
    # what _install_phi_filters installs, and the precedent is not hypothetical: CredentialScrubFilter
    # joined that chain under BACKLOG #1478 and this module only learned of it under #1591, so the
    # guard's diagnostics shipped with no credential pass for the whole interval. Pinning the
    # MEMBERSHIP makes the next divergence loud; the order test above pins the other half.
    from messagefoundry import logging_setup

    handler = logging.NullHandler()
    logging_setup._install_phi_filters(handler)
    installed = {type(f).__name__ for f in handler.filters}

    # Each installed filter is either composed by _scrub_diagnostic, covered by safe_exc at the
    # point every reason is built, or carries a written carve-out in _safe_diagnostic's docstring.
    accounted = {
        "RedactionFilter",  # safe_exc, applied with the scrub by _safe_reason
        "CredentialScrubFilter",  # scrub_credentials, composed by _scrub_diagnostic
        "ControlCharScrubFilter",  # scrub_control_chars, composed by _scrub_diagnostic
        "CredentialQueryScrubFilter",  # carve-out: no guard diagnostic carries a request URL
    }
    assert installed == accounted, (
        f"the handler filter chain has moved: {sorted(installed ^ accounted)}. logging_guard's "
        "_scrub_diagnostic stands in for that chain on a path no filter reaches, so a filter added "
        "there and not here silently does not apply to the guard's own diagnostics"
    )
