# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Tests for the pwsh burst lock (tests/_spawn_lock.py) -- BACKLOG #1304.

THE PROPERTY UNDER TEST is mutual exclusion between a BURST and a SINGLE launch, and it is asserted
with a positive control: the same probe run with the lock disabled must actually overlap. A
concurrency test that would pass against a no-op is the failure mode this repo has already paid for,
so the control is not optional here.

THE SECOND THING THESE PIN is that the remedy did not quietly disarm what it protects. ``run_single``
must still be interceptable by ``monkeypatch.setattr(harness.subprocess, "run", ...)``, because
``test_worktree_gate_control_plane.py`` drives the #1304 launch-timeout diagnostic that way. An
indirection that bypassed the patch would leave that test passing while proving nothing.
"""

from __future__ import annotations

import ast
import os
import shutil
import subprocess
import threading
import time
from collections.abc import Sequence
from pathlib import Path, PurePosixPath
from typing import Any

import pytest

from tests import _spawn_lock
from tests._spawn_lock import run_single, single_spawn, spawn_burst


@pytest.fixture
def lock_root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Point the module at a private root, so a test never waits on a real run's storm."""
    root = tmp_path / "pwsh-burst"
    (root / "readers").mkdir(parents=True)
    monkeypatch.setattr(_spawn_lock, "_ROOT", root)
    return root


class _Window:
    """Records when each side held the lock, so overlap is decided on timestamps, not on a flag."""

    def __init__(self) -> None:
        self.spans: list[tuple[str, float, float]] = []
        self._guard = threading.Lock()

    def record(self, who: str, start: float, end: float) -> None:
        with self._guard:
            self.spans.append((who, start, end))

    def overlapped(self) -> bool:
        for i, (_, a_start, a_end) in enumerate(self.spans):
            for _, b_start, b_end in self.spans[i + 1 :]:
                if a_start < b_end and b_start < a_end:
                    return True
        return False


def _burst(window: _Window, hold: float, ready: threading.Event) -> None:
    with spawn_burst("probe"):
        start = time.monotonic()
        ready.set()
        time.sleep(hold)
        window.record("burst", start, time.monotonic())


def _single(window: _Window, hold: float) -> None:
    with single_spawn():
        start = time.monotonic()
        time.sleep(hold)
        window.record("single", start, time.monotonic())


def test_a_burst_and_a_single_launch_never_hold_the_lock_at_once(lock_root: Path) -> None:
    """The whole point: while a storm runs, no single launch is in flight beside it."""
    window = _Window()
    ready = threading.Event()
    burst = threading.Thread(target=_burst, args=(window, 0.4, ready))
    burst.start()
    assert ready.wait(10), "the burst never took the lock"
    single = threading.Thread(target=_single, args=(window, 0.05))
    single.start()
    burst.join(30)
    single.join(30)

    assert len(window.spans) == 2, f"a side never recorded: {window.spans}"
    assert not window.overlapped(), f"burst and single launch overlapped: {window.spans}"


def test_the_control_without_the_lock_does_overlap(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """POSITIVE CONTROL for the row above. With the lock disabled the same probe MUST overlap.

    Without this, a lock that silently did nothing -- an unwritable root, a typo in the directory
    name -- would pass the mutual-exclusion assertion by never letting either side run concurrently
    in the first place, and the suite would report a fix that is not there.
    """
    monkeypatch.setattr(_spawn_lock, "_ROOT", None)
    window = _Window()
    ready = threading.Event()
    burst = threading.Thread(target=_burst, args=(window, 0.4, ready))
    burst.start()
    assert ready.wait(10)
    single = threading.Thread(target=_single, args=(window, 0.05))
    single.start()
    burst.join(30)
    single.join(30)

    assert window.overlapped(), (
        f"the unlocked control did NOT overlap, so the locked assertion proves nothing: "
        f"{window.spans}"
    )


def test_a_single_launch_gives_up_and_runs_rather_than_waiting_forever(
    lock_root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """FAIL-OPEN, the property that makes this safe to land: a wedged turnstile costs a bounded wait,
    never a hung test. A lock that could block forever would be a worse failure than the flake."""
    monkeypatch.setattr(_spawn_lock, "_SINGLE_WAIT_S", 0.3)
    (lock_root / "burst.lock").write_text("wedged", encoding="ascii")

    start = time.monotonic()
    with single_spawn():
        waited = time.monotonic() - start
    assert waited >= 0.25, f"it did not wait for the turnstile at all: {waited:.3f}s"
    assert waited < 20, f"it waited far past its own bound: {waited:.3f}s"


def test_a_burst_starts_even_when_a_reader_never_drains(
    lock_root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The same fail-open rule on the storm side: an abandoned reader must not stall the burst."""
    monkeypatch.setattr(_spawn_lock, "_BURST_DRAIN_S", 0.3)
    (lock_root / "readers" / "99999-1-0.lock").write_text("", encoding="ascii")

    start = time.monotonic()
    with spawn_burst("probe"):
        waited = time.monotonic() - start
    assert waited < 20, f"the burst stalled behind a stuck reader: {waited:.3f}s"


def test_an_abandoned_turnstile_is_reaped_rather_than_waited_out(lock_root: Path) -> None:
    """A crashed storm must not keep every later launch queued behind a file nobody owns."""
    gate = lock_root / "burst.lock"
    gate.write_text("crashed", encoding="ascii")
    old = time.time() - (_spawn_lock._BURST_STALE_S + 60)
    os.utime(gate, (old, old))

    start = time.monotonic()
    with single_spawn():
        waited = time.monotonic() - start
    assert waited < 5, f"a stale turnstile was waited out instead of reaped: {waited:.3f}s"
    assert not gate.exists(), "the stale turnstile was not reaped"


def test_a_stale_reader_entry_does_not_hold_a_burst(lock_root: Path) -> None:
    """The reader-side twin of the row above: an entry older than any legitimate hold is abandoned."""
    entry = lock_root / "readers" / "99999-1-0.lock"
    entry.write_text("", encoding="ascii")
    old = time.time() - (_spawn_lock._READER_STALE_S + 60)
    os.utime(entry, (old, old))

    assert _spawn_lock._live_readers(lock_root) == 0
    assert not entry.exists(), "the stale reader entry was not reaped"


def test_no_lock_root_runs_both_sides_unsynchronised(monkeypatch: pytest.MonkeyPatch) -> None:
    """No directory, no lock, no failure. A test must never fail BECAUSE the lock was unavailable."""
    monkeypatch.setattr(_spawn_lock, "_ROOT", None)
    with spawn_burst("probe"):
        pass
    with single_spawn():
        pass


def test_a_single_launch_releases_its_ticket(lock_root: Path) -> None:
    """A leaked ticket would make every later burst pay the full drain timeout."""
    with single_spawn():
        assert _spawn_lock._live_readers(lock_root) == 1
    assert _spawn_lock._live_readers(lock_root) == 0


def test_run_single_still_honours_a_patched_subprocess_run(
    lock_root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """NEGATIVE CONTROL protecting the #1304 diagnostic.

    ``test_worktree_gate_control_plane.py::test_a_pwsh_LAUNCH_timeout_is_reported_as_its_own_event``
    drives the launch timeout with ``monkeypatch.setattr(harness.subprocess, "run", ...)``. That
    patches the ``subprocess`` MODULE, so it only reaches ``run_single`` while this looks the
    attribute up at call time. A ``from subprocess import run`` in _spawn_lock.py would bypass it and
    leave that test green against a diagnostic that no longer fires.
    """
    seen: list[Any] = []

    def never_returns(*args: object, **kwargs: object) -> None:
        seen.append(args)
        raise subprocess.TimeoutExpired(cmd="pwsh", timeout=45)

    monkeypatch.setattr(subprocess, "run", never_returns)
    with pytest.raises(subprocess.TimeoutExpired):
        run_single(["pwsh", "-NoProfile", "-Command", "exit 0"], capture_output=True, text=True)
    assert seen, "run_single did not route through the patched subprocess.run"


@pytest.mark.skipif(shutil.which("pwsh") is None, reason="pwsh (PowerShell 7) not on PATH")
def test_run_single_returns_what_subprocess_run_returns(lock_root: Path) -> None:
    """The wrapper must be transparent -- it adds a lock, not a behaviour change."""
    proc = run_single(
        ["pwsh", "-NoProfile", "-NonInteractive", "-Command", "Write-Output ok"],
        capture_output=True,
        text=True,
        check=False,
        timeout=120,
    )
    assert proc.returncode == 0
    assert "ok" in proc.stdout


def test_run_single_refuses_a_cheap_command(
    lock_root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """THE SEAM IS TYPED, NOT CONVENTIONAL, and this is the failure that makes that worth enforcing.

    ``run_single`` is otherwise a total ``subprocess.run`` passthrough, so nothing would stop
    this tier's hundreds of cheap ``git`` calls being routed through it. Every held ticket
    extends every concurrent burst's drain wait, so bursts would stop draining, hit
    ``_BURST_DRAIN_S`` and proceed unsynchronised -- the lock disabling itself, failing open
    exactly as designed, with nothing red.

    THE ACCEPT ARM CALLS ``run_single`` RATHER THAN RE-IMPLEMENTING ITS PARSE, and
    re-implementing it is why this row was red. The first version copied
    ``Path(cmd[0]).name.lower()`` into the assertion, so it exercised ``pathlib`` and never the
    seam. That copy passes on Windows, where ``Path`` is ``WindowsPath`` and splits on both
    separators; on Linux ``PurePosixPath`` splits on neither backslash nor drive, so the Windows
    spelling below parsed to ITSELF and the ubuntu leg raised ``AssertionError``. A test that
    re-implements the function it checks agrees with that function by construction and disagrees
    with the host instead, which is the wrong argument to be having.
    """
    with pytest.raises(ValueError, match="interpreter launch"):
        run_single(["git", "--version"], capture_output=True, text=True)

    assert frozenset({"pwsh", "powershell"}) == _spawn_lock._LOCKED_INTERPRETERS

    # THE REFUTED VALUE, pinned rather than described. ``PurePosixPath`` is host-independent by
    # construction, so this computes the same everywhere and keeps the reason the parse cannot be
    # ``pathlib``'s sitting beside the parse that replaced it.
    windows_pwsh = r"C:\Program Files\PowerShell\7\pwsh.exe"
    assert PurePosixPath(windows_pwsh).name.lower().removesuffix(".exe") != "pwsh"

    # The allowlist is on the BINARY NAME, so a full path and a .exe suffix must still be ACCEPTED,
    # and must reach ``subprocess.run`` unaltered -- ``run_single`` adds a lock, not a rewrite.
    spellings = [windows_pwsh, "/usr/bin/pwsh", "PowerShell.EXE"]
    seen: list[str] = []

    def record(cmd: Sequence[str], **kwargs: object) -> None:
        seen.append(cmd[0])

    monkeypatch.setattr(subprocess, "run", record)
    for spelling in spellings:
        run_single([spelling, "-NoProfile", "-Command", "exit 0"])
    assert seen == spellings, "a valid interpreter spelling was refused or rewritten"


def test_the_storm_counts_are_unchanged() -> None:
    """THE REMEDY MUST NOT HAVE WEAKENED WHAT IT PROTECTS, and this is where that is pinned.

    Cutting ``RACERS`` was the cheap candidate fix for #1304 and it is the wrong one: ``_race``
    exists to prove exactly one of N concurrent claimers wins, and ``_require_real_contention``
    SKIPS when the host cannot produce contention at that N. A lower N turns a race test into a
    sequential one that still reports green -- the always-pass failure ``tests/_dead_pid.py``
    records for a sibling flake. If a later change needs these numbers down, it needs evidence that
    the property survives, not this test deleted.
    """
    from tests.test_session_mail import DRAINS, RACERS

    assert RACERS == 16, "RACERS moved; see tests/_spawn_lock.py for why that is not the #1304 fix"
    assert DRAINS == 8, "DRAINS moved; the same argument applies"


#: The ``subprocess`` entry points that start a process. ``run_single`` wraps only ``run``, but a
#: bare ``check_output`` of pwsh starves in a storm exactly as a bare ``run`` does.
_LAUNCHERS = frozenset(
    f"subprocess.{f}" for f in ("run", "Popen", "call", "check_call", "check_output")
)


def _is_pwsh_list(node: ast.expr | None) -> bool:
    """A list or tuple literal whose first element names an interpreter ``run_single`` locks.

    Normalised as ``run_single`` normalises it, so ``pwsh.exe`` and a full path count too.
    """
    if not isinstance(node, (ast.List, ast.Tuple)) or not node.elts:
        return False
    head = node.elts[0]
    if not isinstance(head, ast.Constant):
        return False
    binary = str(head.value).replace("\\", "/").rsplit("/", 1)[-1].lower().removesuffix(".exe")
    return binary in _spawn_lock._LOCKED_INTERPRETERS


def _unwrapped_pwsh_launches(source: str) -> list[int]:
    """Lines where a ``subprocess`` launcher starts pwsh outside the spawn lock.

    Two spellings of the command are seen, positional or as ``args=``: a literal list, and a NAME
    bound to one by a plain assignment in the same scope. ``test_announce_hook.py`` builds its
    command as ``args = ["pwsh", ...]`` and passes the name, so a literal-only check would not see
    its main launch at all. A launch inside ``with single_spawn():`` holds the lock by hand and is
    not an offender.

    AT LEAST THESE SHAPES, NOT EVERY SHAPE. A name bound in an enclosing scope or by an annotated
    assignment, or an aliased import of ``subprocess``, is not resolved. Rebinding one name from
    pwsh to git in the same scope errs loud: the git call is flagged too.
    """
    tree = ast.parse(source)
    held: list[tuple[int, int]] = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.With, ast.AsyncWith)) and any(
            isinstance(item.context_expr, ast.Call)
            and ast.unparse(item.context_expr.func).rsplit(".", 1)[-1] == "single_spawn"
            for item in node.items
        ):
            held.append((node.lineno, node.end_lineno or node.lineno))

    def own_nodes(scope: ast.AST) -> list[ast.AST]:
        # One scope's nodes, NOT its nested functions'. Walking the module with ast.walk would bind
        # a name from one function and then flag an unrelated use of that name in another.
        out: list[ast.AST] = []
        stack = list(ast.iter_child_nodes(scope))
        while stack:
            n = stack.pop()
            out.append(n)
            if not isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
                stack.extend(ast.iter_child_nodes(n))
        return out

    offenders: set[int] = set()
    scopes: list[ast.AST] = [tree]
    scopes += [
        n
        for n in ast.walk(tree)
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda))
    ]
    for scope in scopes:
        nodes = own_nodes(scope)
        pwsh_names = {
            target.id
            for n in nodes
            if isinstance(n, ast.Assign) and _is_pwsh_list(n.value)
            for target in n.targets
            if isinstance(target, ast.Name)
        }
        for n in nodes:
            if not isinstance(n, ast.Call) or ast.unparse(n.func) not in _LAUNCHERS:
                continue
            keyword = next((k.value for k in n.keywords if k.arg == "args"), None)
            first = n.args[0] if n.args else keyword
            if first is None:
                continue
            if not (
                _is_pwsh_list(first) or (isinstance(first, ast.Name) and first.id in pwsh_names)
            ):
                continue
            if any(start <= n.lineno <= end for start, end in held):
                continue
            offenders.add(n.lineno)
    return sorted(offenders)


def test_the_unwrapped_launch_finder_sees_every_shape_it_claims_to() -> None:
    """POSITIVE CONTROL for the gate below. A finder that returns nothing passes every file."""
    source = (
        "import subprocess\n"
        "def a():\n"
        "    subprocess.run(['pwsh', '-File', 'x'])\n"  # 3: literal, unwrapped
        "def b():\n"
        "    args = ['pwsh', '-File', 'x']\n"
        "    subprocess.run(args, check=False)\n"  # 6: name, unwrapped
        "def c():\n"
        "    subprocess.Popen(['powershell', '-c', 'x'])\n"  # 8: Popen, unwrapped
        "def d():\n"
        "    with single_spawn():\n"
        "        subprocess.Popen(['pwsh', '-c', 'x'])\n"  # 11: held by hand
        "def e():\n"
        "    run_single(['pwsh', '-c', 'x'])\n"  # 13: wrapped
        "    subprocess.run(['git', 'status'])\n"  # 14: not an interpreter
        "    args = ['git', 'status']\n"
        "    subprocess.run(args)\n"  # 16: a name bound to something else
        "def f(ex):\n"
        "    ex.submit(lambda: subprocess.run(['pwsh', '-c', 'x']))\n"  # 18: inside a lambda
        "    subprocess.check_output(args=[r'C:\\\\ps\\\\pwsh.EXE', '-c', 'x'])\n"  # 19: keyword, path
    )
    assert _unwrapped_pwsh_launches(source) == [3, 6, 8, 18, 19]


@pytest.mark.parametrize("name", ["test_coord_usage.py", "test_announce_hook.py"])
def test_a_wrapped_file_does_not_quietly_grow_an_unwrapped_pwsh_launch(name: str) -> None:
    """THE CONVENTION IN A DOCSTRING, MADE INTO A GATE -- BACKLOG #1304.

    ``tests/test_coord_usage.py`` reds ``main``'s harness leg when one of its ``pwsh`` launches
    starves, and the fix routed all 21 of them through ``run_single``. Nothing stopped a 22nd being
    added next to them as a bare ``subprocess.run(["pwsh", ...])``: it would pass review by
    resembling its neighbours, and rejoin the population that produced the reds. ``run_single``'s own
    docstring makes the general point -- "A convention in a docstring would not have held that line."

    PARSED, NOT GREPPED. A regex over the source counts matches in comments and docstrings, and this
    module's files are heavily commented ABOUT ``subprocess.run(["pwsh"``, so a text search reports
    the prose and fails. The AST sees calls only.

    This gates the files that have CI evidence, not the tier. ``tests/test_announce_hook.py`` joined
    on 2026-09-26, after its own launches timed out at 45s on the windows-2025 leg in at least four
    jobs; that file's docstring carries the run ids. Wrapping the other ~65 launcher files is the
    unbuilt ``run_pwsh`` abstraction the module docstring names; a gate that demanded it here would
    fail on work nobody has scheduled.
    """
    source = Path(__file__).resolve().parent / name
    offenders = _unwrapped_pwsh_launches(source.read_text(encoding="utf-8"))

    assert not offenders, (
        f"{source.name} launches pwsh outside the spawn lock at line(s) {offenders} instead of "
        "through run_single, so that launch does not take the shared side of the lock and a storm "
        "will not wait for it (BACKLOG #1304). Use run_single (or `with single_spawn():` for a "
        "Popen), or state in the file why this launch is exempt and relax this gate deliberately."
    )


def test_the_single_wait_outlasts_the_storm_window_ci_measured() -> None:
    """THE CEILING MUST EXCEED THE STORM, and nothing caught it the first time it did not.

    ``_SINGLE_WAIT_S`` shipped at 30.0, sized from a 20-core box's 26.5s of bursts, while the same
    comment block already recorded CI's own overlap window as 30-39s. So it was set AT THE BOTTOM of
    the range it exists to cover, and on a 4-vCPU runner two launches waited it out, gave up while
    the storm still held the turnstile, launched into it and blew their caller's 45s bound.

    A WAIT SHORTER THAN THE STORM IS WORSE THAN NO WAIT: it pays the full delay and still lands in
    the contention, which is the shape the job log showed. Nothing failed when the constant was too
    small -- the module fails open by design, so the symptom surfaced as somebody else's timeout on
    a different leg. That is exactly the defect a pin is for.

    The bound is asserted against the MEASURED window rather than a literal, so re-sizing the wait on
    new evidence is free while dropping it back under the storm is not.
    """
    ci_overlap_window_top_s = 39.0  # tests/_spawn_lock.py: 2.4-3.1 percent of a ~1250s CI run

    assert ci_overlap_window_top_s < _spawn_lock._SINGLE_WAIT_S, (
        "a single launch gives up before CI's measured storm ends, so it launches into the "
        "contention anyway -- the #1304 failure this constant exists to remove"
    )
    assert _spawn_lock._SINGLE_WAIT_S < _spawn_lock._BURST_STALE_S, (
        "a waiter must give up before the turnstile reap, or an ABANDONED storm is waited out "
        "instead of being cleared by staleness"
    )


def test_a_finished_run_directory_is_reaped_but_a_live_one_is_not(tmp_path: Path) -> None:
    """The key is per-RUN, so without reaping every pytest run leaks a directory into a shared .git.

    The LIVE arm is the half that matters: a reaper that also deleted the current run's directory
    would take the lock out from under the run using it, and every test would still pass because the
    module fails open. So both arms are asserted, not just the deletion.
    """
    runs = tmp_path / "pwsh-burst"
    stale = runs / "old-run"
    fresh = runs / "recent-run"
    mine = runs / _spawn_lock._run_id()
    for d in (stale, fresh, mine):
        (d / "readers").mkdir(parents=True)
    old = time.time() - (_spawn_lock._REAP_RUNS_AFTER_S + 3600)
    os.utime(stale, (old, old))
    os.utime(mine, (old, old))  # even an OLD-looking current run must survive

    _spawn_lock._reap_finished_runs(runs)

    assert not stale.exists(), "a finished run's directory was left behind"
    assert fresh.exists(), "a recent run's directory was reaped"
    assert mine.exists(), "the CURRENT run's own directory was reaped out from under it"


def test_the_real_lock_root_resolves() -> None:
    """THE SILENT NO-OP GUARD, and the reason it exists is that every other test here monkeypatches
    ``_ROOT``. If ``_lock_root`` returned None in the real checkout the lock would be inert
    everywhere, the module would fail open exactly as designed, and the whole suite would still be
    green -- a fix that is not there, reported as one.

    Asserted against the real repository rather than a fixture, because resolving the git common dir
    is the step that would break.
    """
    root = _spawn_lock._lock_root()
    assert root is not None, "the lock root did not resolve, so the lock is inert in this checkout"
    assert (root / "readers").is_dir()
    assert root.name == _spawn_lock._run_id()


def test_the_run_id_is_shared_by_xdist_workers_and_private_otherwise(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Scope check. Workers of ONE run must agree; two unrelated local runs must not serialise.

    xdist exports ``PYTEST_XDIST_TESTRUNUID`` into every worker from a single per-run uuid, which is
    what makes the four workers of a CI job share one lock. With it absent the key falls back to the
    process, so a developer's run does not queue behind a peer session's storm.
    """
    monkeypatch.setenv("PYTEST_XDIST_TESTRUNUID", "shared-run-uid")
    assert _spawn_lock._run_id() == "shared-run-uid"

    monkeypatch.delenv("PYTEST_XDIST_TESTRUNUID", raising=False)
    assert _spawn_lock._run_id() == f"pid-{os.getpid()}"
