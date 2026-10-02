# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The engine process refuses a script injected through the interpreter's remote debugging, and
reports the interpreter setting (vault BACKLOG #2700).

Python 3.14 lets another process run a script inside a running interpreter (PEP 768,
``sys.remote_exec``). ``messagefoundry/remotedebug.py`` installs an audit hook that raises on the
event the target raises first, and the interpreter then drops the script.

**That behaviour is the interpreter's, so the first test injects into a real child.** A unit test
of the hook function would pass on an interpreter that ignored the hook's exception. The control is
the same child without the hook: the injected script runs there. Without that control a blocked
attach, a wrong process id or a script that never fires would all read as "the hook worked".

Every other arm has a control too, named in its test.
"""

from __future__ import annotations

import ast
import io
import json
import logging
import os
import queue
import socket
import subprocess
import sys
import time
from collections.abc import AsyncIterator, Callable, Iterator
from pathlib import Path
from types import SimpleNamespace
from typing import cast

import httpx
import pytest

import messagefoundry
from messagefoundry import remotedebug
from messagefoundry.api import create_app
from messagefoundry.config.settings import (
    AlertsSettings,
    ApiSettings,
    AuthSettings,
    SecretRotationSettings,
    SecuritySettings,
    StoreSettings,
    security_loosenings,
)
from messagefoundry.controlchars import scrub_log_argument
from messagefoundry.logging_guard import active_guard
from messagefoundry.logging_setup import LogFile, SyslogForward, configure_logging
from messagefoundry.pipeline import Engine
from messagefoundry.remotedebug import (
    REMOTE_SCRIPT_EVENT,
    RemoteDebugPosture,
    RemoteScriptRefused,
    install_remote_debug_guard,
    remote_debug_loosening,
    remote_debug_posture,
)
from tests._ast_sites import callee_name, named_func, parse_source

_REPO = Path(messagefoundry.__file__).resolve().parents[1]

#: Seconds to wait for a child to start, for an injected script to run, and for a child to stop.
#: Generous, so a starved machine does not turn the control into a false "nothing ran", and
#: shorter than the suite's per-test watchdog, so a wait that fails says what it was waiting for.
_WAIT = 20.0

#: The injection test's own watchdog, above the sum of its waits. The suite default is shorter
#: than three child interpreters can need on a starved runner.
_INJECTION_TEST_TIMEOUT = 240

# The target process. It idles in Python, so the interpreter reaches the point where it looks for
# an injected script. It writes its OWN process id: on Windows a virtual environment's python.exe
# is a launcher, so the id ``Popen`` returns is not the interpreter's.
_TARGET = """\
import logging
import os
import pathlib
import sys
import time

mode, ready, log, stop, final = sys.argv[1:6]
logging.basicConfig(filename=log, level=logging.WARNING)

from messagefoundry.remotedebug import install_remote_debug_guard, remote_debug_posture

if mode in ("guarded", "loud"):
    install_remote_debug_guard()
if mode == "loud":
    # Undo the one thing the install does to the interpreter's own report of a refusal.
    sys.unraisablehook = sys.__unraisablehook__
posture = remote_debug_posture()
pathlib.Path(ready).write_text(
    f"{os.getpid()} {posture.interpreter_enabled} {posture.guard_installed}", encoding="utf-8"
)
deadline = time.monotonic() + 120
while time.monotonic() < deadline and not os.path.exists(stop):
    time.sleep(0.02)
pathlib.Path(final).write_text(str(remote_debug_posture().refused_scripts), encoding="utf-8")
"""


def _wait_for(condition: Callable[[], object], what: str) -> None:
    deadline = time.monotonic() + _WAIT
    while not condition():
        if time.monotonic() > deadline:
            raise AssertionError(f"timed out after {_WAIT:.0f}s waiting for {what}")
        time.sleep(0.05)


class _Target:
    """One child interpreter, and the files it and the injected script write."""

    def __init__(self, directory: Path, mode: str) -> None:
        directory.mkdir()
        self.ready = directory / "ready.txt"
        self.log = directory / "target.log"
        self.stop = directory / "stop"
        self.final = directory / "final.txt"
        self.marker = directory / "marker.txt"
        self.stderr = directory / "stderr.txt"
        # In a directory of its own, so the test can tell the file name from the path in the
        # target's log.
        self.script = directory / "directory-that-must-not-be-logged" / "injected_by_the_test.py"
        self.script.parent.mkdir()
        self.script.write_text(
            f"import pathlib\npathlib.Path({str(self.marker)!r}).write_text('ran')\n",
            encoding="utf-8",
        )
        target = directory / "target.py"
        target.write_text(_TARGET, encoding="utf-8")
        env = dict(os.environ)
        # The target must accept injected scripts, or neither arm measures anything.
        env.pop("PYTHON_DISABLE_REMOTE_DEBUG", None)
        # The tree under test, ahead of whatever copy is installed.
        env["PYTHONPATH"] = str(_REPO)
        with open(self.stderr, "wb") as stderr:
            self.process = subprocess.Popen(
                [
                    sys.executable,
                    str(target),
                    mode,
                    str(self.ready),
                    str(self.log),
                    str(self.stop),
                    str(self.final),
                ],
                env=env,
                stderr=stderr,
            )

    def wait_until_ready(self) -> None:
        _wait_for(
            lambda: self.ready.exists() and self.ready.read_text("utf-8").count(" ") == 2,
            "the target to start",
        )
        pid, enabled, guarded = self.ready.read_text("utf-8").split()
        self.pid = int(pid)
        self.interpreter_enabled = enabled == "True"
        self.guard_installed = guarded == "True"

    def logged_the_refusal(self) -> bool:
        return self.log.exists() and REMOTE_SCRIPT_EVENT in self.log.read_text("utf-8")

    def close(self) -> str:
        """Stop the target and return what it wrote to ``final``."""
        self.stop.write_text("", encoding="utf-8")
        try:
            self.process.wait(timeout=_WAIT)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait(timeout=_WAIT)
        return self.final.read_text("utf-8") if self.final.exists() else ""


@pytest.fixture
def start_target(tmp_path: Path) -> Iterator[Callable[[str], _Target]]:
    """Start a target in ``mode``, and kill whatever a failed test left running."""
    started: list[_Target] = []

    def start(mode: str) -> _Target:
        target = _Target(tmp_path / mode, mode)
        started.append(target)
        return target

    yield start
    for target in started:
        if target.process.poll() is None:
            target.process.kill()
            target.process.wait(timeout=_WAIT)


def _inject(target: _Target) -> None:
    try:
        sys.remote_exec(target.pid, str(target.script))
    except PermissionError as exc:
        # The platform refused the attach itself (ptrace scope on Linux, no task port on macOS).
        # Nothing was measured, in either direction.
        pytest.skip(f"this platform refused to attach to a child process: {exc}")


@pytest.mark.timeout(_INJECTION_TEST_TIMEOUT)
@pytest.mark.skipif(
    not sys.is_remote_debug_enabled(),
    reason="this test process was started with remote debugging off, so it cannot inject",
)
def test_an_injected_script_runs_without_the_hook_and_not_with_it(
    start_target: Callable[[str], _Target],
) -> None:
    control, guarded, loud = (start_target(mode) for mode in ("unguarded", "guarded", "loud"))
    for target in (control, guarded, loud):
        target.wait_until_ready()

    # CONTROL: no hook. The injected script runs. This is what the engine parent would allow.
    assert control.interpreter_enabled, "the target was started with remote debugging off"
    assert not control.guard_installed
    _inject(control)
    _wait_for(control.marker.exists, "the injected script to run in the unguarded target")
    assert control.close() == "0"

    # The same target with the hook installed, and the same injection.
    for target in (guarded, loud):
        assert target.interpreter_enabled and target.guard_installed
        _inject(target)
        _wait_for(target.logged_the_refusal, "the guarded target to log the refusal")
        # The hook raised before that line was written, and the target went on running Python
        # until it was told to stop. A script the interpreter had only put off would have run.
        assert target.close() == "1", "the hook did not count exactly one refused script"
        assert not target.marker.exists(), "the injected script ran although the hook raised"

    logged = guarded.log.read_text("utf-8")
    assert "WARNING" in logged
    assert guarded.script.name in logged
    # The file name only: the directory is the injecting process's business, not the log's.
    directory = guarded.script.parent.name
    assert directory not in logged

    # The interpreter reports the hook's exception itself, with the full path. The install drops
    # that report. CONTROL: the "loud" target put the interpreter's own hook back, and there the
    # path is on standard error, so the check on the guarded target could have failed.
    assert directory in loud.stderr.read_text("utf-8", errors="replace")
    assert directory not in guarded.stderr.read_text("utf-8", errors="replace")


# --- the hook function -------------------------------------------------------------------------


@pytest.fixture
def reports(monkeypatch: pytest.MonkeyPatch) -> queue.SimpleQueue[str]:
    """A private report queue, so a reporter thread already running in this process (an earlier
    test called ``serve``) cannot take what a test here puts on it."""
    private: queue.SimpleQueue[str] = queue.SimpleQueue()
    monkeypatch.setattr(remotedebug, "_reports", private)
    # The count too: it is module state, and a later test in this process reads it.
    monkeypatch.setattr(remotedebug, "_refused", 0)
    return private


def test_the_hook_refuses_the_script_event_and_queues_the_file_name_only(
    reports: queue.SimpleQueue[str],
) -> None:
    path = os.path.join("some", "directory", "payload.py")
    with pytest.raises(RemoteScriptRefused):
        remotedebug._guard(REMOTE_SCRIPT_EVENT, (path,))
    assert reports.get_nowait() == "payload.py"
    assert remotedebug._refused == 1
    # An event with no usable argument is still refused. The hook must not fail open on a shape
    # it did not expect.
    for args in ((), (None,), (b"bytes",)):
        with pytest.raises(RemoteScriptRefused):
            remotedebug._guard(REMOTE_SCRIPT_EVENT, args)
        assert reports.get_nowait() == ""
    assert remotedebug._refused == 4


def test_the_hook_lets_every_other_event_through(reports: queue.SimpleQueue[str]) -> None:
    for event, args in (
        ("open", ("a.txt", "r", 0)),
        ("socket.connect", (object(), ("h", 1))),
        ("sys._getframe", (object(),)),
        ("cpython.remote_debugger_script_x", ("p.py",)),
        ("cpython.remote_debugger", ("p.py",)),
        ("", ()),
    ):
        remotedebug._guard(event, args)  # returns: no exception
    assert reports.empty()
    # CONTROL: the same call shape with the watched event does raise, so the loop above could
    # have failed.
    with pytest.raises(RemoteScriptRefused):
        remotedebug._guard(REMOTE_SCRIPT_EVENT, ("p.py",))


def test_a_flood_of_refusals_is_counted_but_does_not_grow_the_queue(
    reports: queue.SimpleQueue[str],
) -> None:
    attempts = remotedebug._REPORT_BACKLOG + 25
    for _ in range(attempts):
        with pytest.raises(RemoteScriptRefused):
            remotedebug._guard(REMOTE_SCRIPT_EVENT, ("p.py",))
    assert remotedebug._refused == attempts
    assert reports.qsize() == remotedebug._REPORT_BACKLOG


def test_the_warning_names_the_event_and_escapes_the_file_name(
    caplog: pytest.LogCaptureFixture,
) -> None:
    # The injecting process chooses the name. On POSIX it may hold a line break, which would
    # otherwise start a forged log line.
    name = "evil\nCRITICAL forged line.py"
    with caplog.at_level(logging.WARNING, logger="messagefoundry.remotedebug"):
        remotedebug._report(name)
    (record,) = caplog.records
    assert record.levelno == logging.WARNING
    message = record.getMessage()
    assert REMOTE_SCRIPT_EVENT in message
    assert "\n" not in message
    assert scrub_log_argument(name) in message and scrub_log_argument(name) != name


def test_the_reporter_outlives_a_failing_log_call(monkeypatch: pytest.MonkeyPatch) -> None:
    """Nothing restarts the reporter thread, so one failing log call must not end it. Without the
    guard the first name's error leaves the loop, and this test sees it instead of ``_Stop``."""

    class _Stop(BaseException):
        pass

    class _Feed:
        def __init__(self) -> None:
            self.names = iter(["first", "second"])

        def get(self) -> str:
            try:
                return next(self.names)
            except StopIteration:
                raise _Stop from None

    written: list[str] = []

    def report(name: str) -> None:
        if name == "first":
            raise RuntimeError("the log call failed")
        written.append(name)

    monkeypatch.setattr(remotedebug, "_reports", _Feed())
    monkeypatch.setattr(remotedebug, "_report", report)
    with pytest.raises(_Stop):
        remotedebug._report_refusals()
    assert written == ["second"]


def test_a_long_file_name_is_cut(reports: queue.SimpleQueue[str]) -> None:
    with pytest.raises(RemoteScriptRefused):
        remotedebug._guard(REMOTE_SCRIPT_EVENT, ("x" * 5000,))
    assert len(reports.get_nowait()) == remotedebug._FILE_NAME_LIMIT


# --- the refusal line and the log sinks (vault BACKLOG #2742) -----------------------------------

#: File names the injecting process could choose, and how the log must spell each. Written as
#: escapes so this file stays ASCII. The last one is the control: a plain name is logged as it is.
_NAMES = [
    pytest.param("pay\udcffload.py", r"pay\udcffload.py", id="lone-low-surrogate"),
    pytest.param("pay\ud83dload.py", r"pay\ud83dload.py", id="lone-high-surrogate"),
    pytest.param("pay\u4e2dload.py", r"pay\u4e2dload.py", id="outside-cp1252"),
    pytest.param("pay\U0001f600load.py", r"pay\U0001f600load.py", id="astral"),
    pytest.param("pay\xe9load.py", r"pay\xe9load.py", id="latin-1"),
    pytest.param("payload.py", "payload.py", id="plain-ascii"),
]


@pytest.mark.parametrize(("name", "spelled"), _NAMES)
def test_the_warning_is_ascii_whatever_the_file_name(
    caplog: pytest.LogCaptureFixture, name: str, spelled: str
) -> None:
    with caplog.at_level(logging.WARNING, logger="messagefoundry.remotedebug"):
        remotedebug._report(name)
    message = caplog.records[-1].getMessage()
    assert message.isascii()
    assert f"script file name {spelled})" in message


class _Sinks:
    """The three sinks ``configure_logging`` builds, each one readable by the test.

    Standard output is a strict cp1252 stream: the encoding a redirected stdout has on a stock
    Windows install, with none of the leniency ``main()`` adds. The forwarder sends UDP to a
    socket this object holds."""

    def __init__(self, directory: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        self.directory = directory
        self.log = directory / "engine.log"
        self._stdout = io.BytesIO()
        # Held here: dropping the wrapper would close the buffer under it.
        self._stream = io.TextIOWrapper(
            self._stdout, encoding="cp1252", errors="strict", write_through=True
        )
        monkeypatch.setattr(sys, "stdout", self._stream)
        self.collector = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.collector.bind(("127.0.0.1", 0))
        self.collector.settimeout(0.2)
        configure_logging(
            "INFO",
            log_file=LogFile(path=str(self.log)),
            forward=SyslogForward(host="127.0.0.1", port=self.collector.getsockname()[1]),
            # Nothing here is an engine, and the control arm fails every sink on purpose.
            stop_on_write_failure=False,
        )

    def on_stdout(self) -> str:
        return self._stdout.getvalue().decode("cp1252")

    def in_file(self) -> str:
        return self.log.read_text("utf-8")

    def rolled_aside(self) -> list[str]:
        return sorted(p.name for p in self.directory.iterdir() if ".broken-" in p.name)

    def states(self) -> dict[str, str]:
        guard = active_guard()
        assert guard is not None
        return {status.sink: status.state for status in guard.status()}

    def forwarded(self, wait: float) -> str:
        """Every datagram that arrives within ``wait`` seconds, or up to the refusal line."""
        received = ""
        deadline = time.monotonic() + wait
        while REMOTE_SCRIPT_EVENT not in received and time.monotonic() < deadline:
            try:
                received += self.collector.recvfrom(65535)[0].decode("utf-8")
            except TimeoutError:
                continue
        return received


@pytest.fixture
def build_sinks(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Callable[[], _Sinks]]:
    """Build the sinks from the test body, not from fixture set-up. pytest puts its own stdout
    back between the two, and the stdout sink moves to whatever ``sys.stdout`` is when a write
    fails, so sinks built in set-up would be rescued by pytest's lenient stream."""
    built: list[_Sinks] = []

    def build() -> _Sinks:
        built.append(_Sinks(tmp_path, monkeypatch))
        return built[-1]

    yield build
    for one in built:
        one.collector.close()


@pytest.mark.parametrize(("name", "spelled"), _NAMES)
def test_the_refusal_line_reaches_every_sink_whatever_the_file_name(
    build_sinks: Callable[[], _Sinks], name: str, spelled: str
) -> None:
    """The injecting process chooses the name, and it must not be able to keep the refusal out
    of a log. The control for these arms is the test below, on the same sinks."""
    sinks = build_sinks()
    remotedebug._report(name)
    wanted = f"script file name {spelled})"
    assert REMOTE_SCRIPT_EVENT in sinks.in_file() and wanted in sinks.in_file()
    assert wanted in sinks.on_stdout()
    # The forwarder renders JSON, so a backslash in the name arrives doubled.
    assert json.dumps(wanted)[1:-1] in sinks.forwarded(_WAIT)
    assert sinks.rolled_aside() == []
    assert sinks.states() == {"stdout": "healthy", "file": "healthy"}


def test_without_the_escape_a_lone_surrogate_keeps_the_line_out_of_every_sink(
    build_sinks: Callable[[], _Sinks], monkeypatch: pytest.MonkeyPatch
) -> None:
    """CONTROL for the test above: the same sinks and the same name, with the name passed as it
    came. The line reaches none of them and the log file is rolled aside, so every assertion
    above could have failed.

    This arm depends on the sinks themselves failing on a lone surrogate, which they do for any
    logger's line. If a later change makes the sinks take any string, this arm goes red: delete
    it then, and the escape is no longer what protects the line."""
    sinks = build_sinks()
    monkeypatch.setattr(remotedebug, "_ascii", lambda name: name)
    remotedebug._report("pay\udcffload.py")
    assert REMOTE_SCRIPT_EVENT not in sinks.in_file()
    assert REMOTE_SCRIPT_EVENT not in sinks.on_stdout()
    assert REMOTE_SCRIPT_EVENT not in sinks.forwarded(1.0)
    assert len(sinks.rolled_aside()) == 1
    assert sinks.states() == {"stdout": "unwritable", "file": "unwritable"}


# --- installing --------------------------------------------------------------------------------


class _Installs:
    """Stand-ins for ``sys.addaudithook`` and the reporter thread, which cannot be undone."""

    def __init__(self, monkeypatch: pytest.MonkeyPatch, *, enabled: bool = True) -> None:
        self.hooks: list[object] = []
        self.reporters = 0
        monkeypatch.setattr(sys, "is_remote_debug_enabled", lambda: enabled)
        monkeypatch.setattr(sys, "addaudithook", self.hooks.append)
        # Restored afterwards: a successful install wraps it.
        monkeypatch.setattr(sys, "unraisablehook", sys.unraisablehook)
        monkeypatch.setattr(remotedebug, "_start_reporter", self._start)

    def _start(self) -> None:
        self.reporters += 1


def test_install_adds_one_hook_and_a_second_call_adds_nothing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    installs = _Installs(monkeypatch)
    before = sys.unraisablehook
    # Not there, then there once added, then there on each later call.
    answers = iter([False, True, True, True])
    monkeypatch.setattr(remotedebug, "_guard_answers", lambda: next(answers))
    install_remote_debug_guard()
    wrapped = sys.unraisablehook
    install_remote_debug_guard()
    install_remote_debug_guard()
    assert installs.hooks == [remotedebug._guard]
    assert installs.reporters == 1
    assert wrapped is not before and sys.unraisablehook is wrapped


def test_install_tries_again_while_the_hook_does_not_answer(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The control for the test above, and the reason "once" is measured and not remembered: the
    interpreter drops a new hook without an error when one already installed objects, so a flag
    set after ``sys.addaudithook`` returned would say "installed" for a hook that is not there."""
    installs = _Installs(monkeypatch)
    before = sys.unraisablehook
    monkeypatch.setattr(remotedebug, "_guard_answers", lambda: False)
    install_remote_debug_guard()
    install_remote_debug_guard()
    assert installs.hooks == [remotedebug._guard, remotedebug._guard]
    # A hook the interpreter dropped gets no reporter thread, and the unraisable hook is put back.
    assert installs.reporters == 0
    assert sys.unraisablehook is before


def test_the_unraisable_hook_is_wrapped_before_the_audit_hook_is_added(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A refusal in between would be reported by the interpreter with the script's full path."""
    installs = _Installs(monkeypatch)
    before = sys.unraisablehook
    seen: list[bool] = []
    monkeypatch.setattr(
        sys, "addaudithook", lambda hook: seen.append(sys.unraisablehook is not before)
    )
    answers = iter([False, True])
    monkeypatch.setattr(remotedebug, "_guard_answers", lambda: next(answers))
    install_remote_debug_guard()
    assert seen == [True] and installs.reporters == 1


def test_a_probe_another_hook_objects_to_reads_as_not_installed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Another audit hook may raise on an event it does not know. The probe must not pass that
    on: it would stop ``serve`` at its first statement and fail the posture route."""

    def objecting(event: str, *args: object) -> None:
        raise ValueError(f"unknown event {event}")

    monkeypatch.setattr(sys, "audit", objecting)
    assert remotedebug._guard_answers() is False
    assert remote_debug_posture().guard_installed is False

    # CONTROL: a hook that objects AFTER this one answered still reads as installed, so the
    # False above is the probe's answer and not a blanket result of catching the error.
    def answering_then_objecting(event: str, *args: object) -> None:
        remotedebug._guard(event, args)
        raise ValueError(f"unknown event {event}")

    monkeypatch.setattr(sys, "audit", answering_then_objecting)
    assert remotedebug._guard_answers() is True


def test_install_adds_nothing_where_the_interpreter_refuses_injection_already(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Every child the engine starts is in this state, so none of them pays for a hook whose
    # event cannot fire.
    installs = _Installs(monkeypatch, enabled=False)
    monkeypatch.setattr(remotedebug, "_guard_answers", lambda: False)
    install_remote_debug_guard()
    assert installs.hooks == [] and installs.reporters == 0


def test_the_unraisable_wrapper_drops_its_own_refusal_and_passes_the_rest_on() -> None:
    seen: list[object] = []
    hook = remotedebug._without_own_refusals(seen.append)

    def unraisable(exc: BaseException) -> sys.UnraisableHookArgs:
        try:
            raise exc
        except BaseException as caught:  # the shape the interpreter hands an unraisable hook
            return cast(
                "sys.UnraisableHookArgs",
                SimpleNamespace(
                    exc_type=type(caught),
                    exc_value=caught,
                    exc_traceback=caught.__traceback__,
                    err_msg=None,
                    object=None,
                ),
            )

    other = unraisable(ValueError("anything else"))
    hook(other)
    hook(unraisable(RuntimeError("a RuntimeError that is not the refusal")))
    assert len(seen) == 2 and seen[0] is other
    hook(unraisable(RemoteScriptRefused("refused")))
    assert len(seen) == 2


def test_the_probe_is_answered_by_the_real_hook_and_by_nothing_else() -> None:
    """``guard_installed`` is read by asking the hook, through the interpreter's own audit call."""
    answer: list[bool] = []
    remotedebug._guard(remotedebug._PROBE_EVENT, (answer,))
    assert answer == [True]
    # A probe argument of another shape is ignored, not appended to and not raised on.
    remotedebug._guard(remotedebug._PROBE_EVENT, ("not a list",))
    remotedebug._guard(remotedebug._PROBE_EVENT, ())


@pytest.mark.skipif(not sys.is_remote_debug_enabled(), reason="the hook is not installed here")
def test_the_real_install_is_seen_by_the_posture_and_is_not_repeated(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Against the real interpreter, with no stand-in for ``sys.addaudithook``. The hook stays in
    this test process afterwards, which is harmless: it raises on one event nothing here uses."""
    added: list[object] = []
    real = sys.addaudithook
    monkeypatch.setattr(sys, "unraisablehook", sys.unraisablehook)  # restored afterwards

    def counting(hook: object) -> None:
        added.append(hook)
        real(hook)  # type: ignore[arg-type]

    monkeypatch.setattr(sys, "addaudithook", counting)
    install_remote_debug_guard()
    first = len(added)
    assert first <= 1  # 0 when an earlier test in this process ran `serve`
    assert remote_debug_posture().guard_installed
    install_remote_debug_guard()
    assert len(added) == first
    # Other audited operations still work with the hook in place.
    sys.audit("messagefoundry.tests.some_other_event", 1)
    assert Path(__file__).read_bytes()


# --- what is reported --------------------------------------------------------------------------

_OFF = RemoteDebugPosture(interpreter_enabled=False, guard_installed=False)
_GUARDED = RemoteDebugPosture(interpreter_enabled=True, guard_installed=True, refused_scripts=3)
_UNGUARDED = RemoteDebugPosture(interpreter_enabled=True, guard_installed=False)


def test_the_entry_follows_the_reading() -> None:
    assert remote_debug_loosening(_OFF) is None
    # The hook without the interface is the same as no interface: nothing to report.
    assert remote_debug_loosening(RemoteDebugPosture(False, True)) is None

    guarded = remote_debug_loosening(_GUARDED)
    assert guarded is not None and guarded[0] == "remote_debug_enabled"
    assert "It has refused 3 since this process started" in guarded[1]
    # The start-up warning is taken before anything can have been refused, so it carries no count.
    quiet = remote_debug_loosening(RemoteDebugPosture(True, True))
    assert quiet is not None and "It has refused" not in quiet[1]
    # The wording must not read as "closed": the hook leaves the start-up window and the
    # memory-write capability.
    assert "residual" in guarded[1] and "can still run code" in guarded[1]
    assert "earlier in start-up still runs" in guarded[1]

    unguarded = remote_debug_loosening(_UNGUARDED)
    assert unguarded is not None and unguarded[0] == "remote_debug_unguarded"
    assert "NOT installed" in unguarded[1]


def _names(remote_debug: RemoteDebugPosture | None) -> list[str]:
    return [
        name
        for name, _ in security_loosenings(
            SecuritySettings(),
            StoreSettings(),
            AuthSettings(),
            AlertsSettings(),
            SecretRotationSettings(),
            cleartext_hops=(),
            expiry_relaxed_hops=(),
            hostname_unchecked_hops=(),
            query_credential_hops=(),
            unverified_db_hops=(),
            attested_hops=(),
            revocation_attested_hops=(),
            api=ApiSettings(),
            store_privilege=None,
            audit_chain_unkeyed=None,
            remote_debug=remote_debug,
        )
    ]


def test_the_registry_names_the_reading_and_is_quiet_without_one() -> None:
    assert _names(_GUARDED) == ["remote_debug_enabled"]
    assert _names(_UNGUARDED) == ["remote_debug_unguarded"]
    assert _names(_OFF) == []
    # None is "this call site is not the engine process", never a clean reading it could report.
    assert _names(None) == []


@pytest.fixture
async def engine(tmp_path: Path) -> AsyncIterator[Engine]:
    eng = await Engine.create(tmp_path / "posture.db", poll_interval=0.02)
    yield eng
    await eng.stop()


async def _route_names(engine: Engine) -> list[str]:
    app = create_app(engine, allow_no_auth=True)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as client:
        resp = await client.get("/security/posture")
    assert resp.status_code == 200
    return [entry["switch"] for entry in resp.json()["loosenings"]]


@pytest.mark.parametrize(
    ("reading", "expected"),
    [
        (_GUARDED, ["remote_debug_enabled"]),
        (_OFF, []),  # the control: the route can be quiet
    ],
)
async def test_the_posture_route_reports_the_reading_of_its_own_process(
    engine: Engine,
    monkeypatch: pytest.MonkeyPatch,
    reading: RemoteDebugPosture,
    expected: list[str],
) -> None:
    monkeypatch.setattr("messagefoundry.api.app.remote_debug_posture", lambda: reading)
    assert await _route_names(engine) == expected


async def test_the_posture_route_reads_the_live_process_when_nothing_is_pinned(
    engine: Engine,
) -> None:
    """No stand-in: the route's answer must match what this process reads about itself."""
    entry = remote_debug_loosening(remote_debug_posture())
    assert await _route_names(engine) == ([] if entry is None else [entry[0]])


# --- serve and supervise install it before anything else ---------------------------------------


def _first_statement_installs_the_guard(source: str, function: str) -> bool:
    """Whether ``function`` in ``source`` begins, after its docstring, with a bare call to
    ``install_remote_debug_guard()``."""
    node = named_func(parse_source(source), function)
    first = node.body[1] if ast.get_docstring(node) is not None else node.body[0]
    return (
        isinstance(first, ast.Expr)
        and isinstance(first.value, ast.Call)
        and callee_name(first.value, bare_only=True) == "install_remote_debug_guard"
        and not first.value.args
        and not first.value.keywords
    )


@pytest.mark.parametrize("function", ["_serve", "_supervise"])
def test_serve_and_supervise_install_the_guard_first(function: str) -> None:
    """Before the imports and before config: a script injected ahead of the hook runs."""
    source = (_REPO / "messagefoundry" / "__main__.py").read_text(encoding="utf-8")
    assert _first_statement_installs_the_guard(source, function)


def test_the_first_statement_check_can_fail() -> None:
    late = 'def _serve(args):\n    """Doc."""\n    import x\n    install_remote_debug_guard()\n'
    assert not _first_statement_installs_the_guard(late, "_serve")
    other = "def _serve(args):\n    remotedebug.install_remote_debug_guard()\n"
    assert not _first_statement_installs_the_guard(other, "_serve")
    first = 'def _serve(args):\n    """Doc."""\n    install_remote_debug_guard()\n    import x\n'
    assert _first_statement_installs_the_guard(first, "_serve")
