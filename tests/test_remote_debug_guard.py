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
import logging
import os
import queue
import subprocess
import sys
import time
from collections.abc import AsyncIterator, Callable, Iterator
from pathlib import Path

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
from messagefoundry.pipeline import Engine
from messagefoundry.remotedebug import (
    REMOTE_SCRIPT_EVENT,
    RemoteDebugPosture,
    RemoteScriptRefused,
    install_remote_debug_guard,
    remote_debug_loosening,
    remote_debug_posture,
)

_REPO = Path(messagefoundry.__file__).resolve().parents[1]

#: Seconds to wait for a child to start, for an injected script to run, and for a child to stop.
#: Generous: a starved machine must not turn the control into a false "nothing ran".
_WAIT = 60.0

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

if mode == "guarded":
    install_remote_debug_guard()
posture = remote_debug_posture()
pathlib.Path(ready).write_text(
    f"{os.getpid()} {posture.interpreter_enabled} {posture.guard_installed}", encoding="utf-8"
)
deadline = time.monotonic() + 300
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
        )
        _wait_for(
            lambda: self.ready.exists() and self.ready.read_text("utf-8").count(" ") == 2, mode
        )
        pid, enabled, guarded = self.ready.read_text("utf-8").split()
        self.pid = int(pid)
        self.interpreter_enabled = enabled == "True"
        self.guard_installed = guarded == "True"

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
def targets(tmp_path: Path) -> Iterator[list[_Target]]:
    started: list[_Target] = []
    yield started
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


def test_an_injected_script_runs_without_the_hook_and_not_with_it(
    tmp_path: Path, targets: list[_Target]
) -> None:
    # CONTROL: no hook. The injected script runs. This is what the engine parent would allow.
    control = _Target(tmp_path / "control", "unguarded")
    targets.append(control)
    assert control.interpreter_enabled, "the target was started with remote debugging off"
    assert not control.guard_installed
    _inject(control)
    _wait_for(control.marker.exists, "the injected script to run in the unguarded target")
    assert control.close() == "0"

    # The same target with the hook installed, and the same injection.
    guarded = _Target(tmp_path / "guarded", "guarded")
    targets.append(guarded)
    assert guarded.interpreter_enabled and guarded.guard_installed
    _inject(guarded)
    _wait_for(
        lambda: guarded.log.exists() and REMOTE_SCRIPT_EVENT in guarded.log.read_text("utf-8"),
        "the guarded target to log the refusal",
    )
    # The target keeps running Python until it is told to stop, so a script the interpreter had
    # merely deferred would run in that window.
    assert guarded.close() == "1", "the hook did not count exactly one refused script"
    assert not guarded.marker.exists(), "the injected script ran although the hook raised"

    logged = guarded.log.read_text("utf-8")
    assert "WARNING" in logged
    assert guarded.script.name in logged
    # The file name only: the directory is the injecting process's business, not the log's.
    assert guarded.script.parent.name not in logged


# --- the hook function -------------------------------------------------------------------------


@pytest.fixture
def reports(monkeypatch: pytest.MonkeyPatch) -> queue.SimpleQueue[str]:
    """A private report queue, so a reporter thread already running in this process (an earlier
    test called ``serve``) cannot take what a test here puts on it."""
    private: queue.SimpleQueue[str] = queue.SimpleQueue()
    monkeypatch.setattr(remotedebug, "_reports", private)
    return private


def test_the_hook_refuses_the_script_event_and_queues_the_file_name_only(
    reports: queue.SimpleQueue[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(remotedebug, "_refused", 0)
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
    reports: queue.SimpleQueue[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(remotedebug, "_refused", 0)
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
    with caplog.at_level(logging.WARNING, logger="messagefoundry.remotedebug"):
        remotedebug._report("evil\nCRITICAL forged line.py")
    (record,) = caplog.records
    assert record.levelno == logging.WARNING
    message = record.getMessage()
    assert REMOTE_SCRIPT_EVENT in message
    assert "\n" not in message
    assert "evil\\nCRITICAL forged line.py" in message


def test_a_long_file_name_is_cut(reports: queue.SimpleQueue[str]) -> None:
    with pytest.raises(RemoteScriptRefused):
        remotedebug._guard(REMOTE_SCRIPT_EVENT, ("x" * 5000,))
    assert len(reports.get_nowait()) == remotedebug._FILE_NAME_LIMIT


# --- installing --------------------------------------------------------------------------------


class _Installs:
    """Stand-ins for ``sys.addaudithook`` and the reporter thread, which cannot be undone."""

    def __init__(self, monkeypatch: pytest.MonkeyPatch, *, enabled: bool = True) -> None:
        self.hooks: list[object] = []
        self.reporters = 0
        monkeypatch.setattr(sys, "is_remote_debug_enabled", lambda: enabled)
        monkeypatch.setattr(sys, "addaudithook", self.hooks.append)
        monkeypatch.setattr(remotedebug, "_start_reporter", self._start)

    def _start(self) -> None:
        self.reporters += 1


def test_install_adds_one_hook_and_a_second_call_adds_nothing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    installs = _Installs(monkeypatch)
    answers = iter([False, True, True])
    monkeypatch.setattr(remotedebug, "_guard_answers", lambda: next(answers))
    install_remote_debug_guard()
    install_remote_debug_guard()
    install_remote_debug_guard()
    assert installs.hooks == [remotedebug._guard]
    assert installs.reporters == 1


def test_install_tries_again_while_the_hook_does_not_answer(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The control for the test above, and the reason "once" is measured and not remembered: the
    interpreter drops a new hook without an error when one already installed objects, so a flag
    set after ``sys.addaudithook`` returned would say "installed" for a hook that is not there."""
    installs = _Installs(monkeypatch)
    monkeypatch.setattr(remotedebug, "_guard_answers", lambda: False)
    install_remote_debug_guard()
    install_remote_debug_guard()
    assert installs.hooks == [remotedebug._guard, remotedebug._guard]


def test_install_adds_nothing_where_the_interpreter_refuses_injection_already(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Every child the engine starts is in this state, so none of them pays for a hook whose
    # event cannot fire.
    installs = _Installs(monkeypatch, enabled=False)
    monkeypatch.setattr(remotedebug, "_guard_answers", lambda: False)
    install_remote_debug_guard()
    assert installs.hooks == [] and installs.reporters == 0


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
    assert "3 refused since start" in guarded[1]
    # The wording must not read as "closed": the hook leaves the memory-write capability.
    assert "residual" in guarded[1] and "can still run code" in guarded[1]

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
        (_UNGUARDED, ["remote_debug_unguarded"]),
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
    tree = ast.parse(source)
    (node,) = [n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == function]
    body = list(node.body)
    if (
        body
        and isinstance(body[0], ast.Expr)
        and isinstance(body[0].value, ast.Constant)
        and isinstance(body[0].value.value, str)
    ):
        body = body[1:]
    first = body[0]
    return (
        isinstance(first, ast.Expr)
        and isinstance(first.value, ast.Call)
        and isinstance(first.value.func, ast.Name)
        and first.value.func.id == "install_remote_debug_guard"
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
