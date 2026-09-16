# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Keep a pwsh STORM and a single pwsh LAUNCH off the same vCPUs -- BACKLOG #1304.

THE FAILURE THIS EXISTS TO REMOVE. ``tests/test_worktree_gate.py`` raises ``PWSH LAUNCH TIMED OUT
after 45s`` on the ``windows-2025`` harness leg. That leg is not itself a required context, but
``CI gate`` aggregates it, so the flake reds ``main`` and keeps PRs out of the merge queue.

THE CAUSE IS MEASURED, NOT GUESSED, and it is recorded in full in commit ``5e5a8a5ab`` and in the
``raise`` this module protects. In short: ``tests/test_session_mail.py::_race`` starts 16 concurrent
``pwsh`` processes, three times per job, on a 4-vCPU runner. Across five windows-2025 harness jobs
EVERY test over 20 seconds completes inside the window where the spawn-heavy files overlap -- a
window that is 2.4 to 3.1 percent of the run. Held within ONE file, so worker, fixtures and code are
constant and only the clock moves::

    test_worktree_gate_control_plane  inside  n=20   p50 4.39s  max 67.94s
                                      outside n=151  p50 1.98s  max  5.20s

A ``pwsh`` startup regression is REFUTED there. Raising the ceiling is NOT the fix: the failure is a
launch that never returns, so a higher bound only makes the next occurrence take longer to fail.

WHAT THIS DOES. A bulk spawner takes the lock EXCLUSIVELY for the length of its storm; every single
launch takes it SHARED. So the storm still gets all 16 of its concurrent processes -- the property
its test actually asserts is untouched -- and no single launch is in flight beside it.

WHY NOT SIMPLY CUT THE RACER COUNT. ``_race`` exists to prove that exactly one of N concurrent
claimers wins, and ``_require_real_contention`` SKIPS the test when the host cannot produce real
contention at that N. Lowering N to fit a small runner turns a race test into a sequential one that
still reports green. ``tests/_dead_pid.py`` records the same lesson for a sibling flake: converting a
loud false-failure into a quiet always-pass is worse than the flake it replaces.

WHY NOT AN XDIST GROUP, stated precisely because the obvious reading of ``--dist loadgroup`` is wrong.
It does not serialise groups against each other; it PINS same-group tests to one worker. Putting the
spawn-heavy files in one group would therefore stop them overlapping each other, at the cost of
collapsing the tier's four heaviest files onto a single worker that then sets the wall clock -- and
it would still leave the other three workers launching pwsh throughout the storm. It also lives in
the pytest invocation in ``.github/workflows/ci.yml`` rather than beside the code it governs, and it
separates only the files that are spawn-heavy TODAY. This module binds the constraint to the call
site instead, so a new bulk spawner opts in by wrapping itself.

WHY NOT ``scripts/coord/lock.ps1``, which is this repository's own cross-session mutex. Three
independent reasons: it is PowerShell, so every lock operation would spawn a ``pwsh`` inside the
remedy for too many spawns; it is exclusive-only, and this needs shared/exclusive because the 16
racers must still run concurrently; and it fails LOUDLY on timeout by design, which is the opposite
of the fail-open posture below.

WHAT THIS DOES NOT COVER, recorded so the next reader does not assume the tier is now safe.
``scripts/coord/overlap.ps1`` defaults ``ParallelLimit = 16`` and several manifest files invoke it,
each able to hold 16 runspaces spawning ``git``; ``test_announce_hook.py`` runs a 2-way pwsh pool.
Those are unwrapped: they were found by sweeping the tier, not by CI evidence, and this change
deliberately does not wrap on a hunch. Roughly 66 other files in the tier launch ``pwsh`` without
taking the shared side at all, so a storm does not wait for them. The missing abstraction is a shared
``run_pwsh`` launcher that every site uses; until that exists, ``_note`` below is what makes the next
occurrence tell you which of those gaps it came from.

EVERY FAILURE MODE HERE DEGRADES TO TODAY'S BEHAVIOUR, WHICH IS THE PROPERTY THAT MAKES IT SAFE TO
LAND. No lock directory, a saturated wait, a stale entry reaped while its owner is in fact alive, an
``OSError`` on any filesystem call -- each one proceeds WITHOUT the lock. The worst case is the
unsynchronised run we have now; there is no path here that blocks a test forever or fails one. That
mirrors ``tests/conftest.py``'s per-process slot, which states the same rule: "It never fails a run."

THE LOCK IS SCOPED TO ONE PYTEST RUN, NOT TO THE MACHINE, and the difference only matters off CI.
``xdist`` generates one ``testrunuid`` per run (``workermanage.py``) and exports it into every worker
as ``PYTEST_XDIST_TESTRUNUID`` (``remote.py``), so all four workers of one job agree on the key while
two unrelated local runs do not serialise against each other. On a CI runner there is exactly one run,
so run-scoped and machine-scoped are the same thing precisely where the fix has to work.

STALENESS IS BY TIMESTAMP, NOT BY PROBING THE OWNER PID. ``tests/conftest.py`` reaps its slots by
shelling out to ``tasklist``; doing that here would start a process inside the remedy for too many
processes. Every hold in this module is bounded by its own caller's timeout, so age alone is
sufficient -- and reaping a live holder only drops us back to the unsynchronised behaviour above.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import threading
import time
from collections.abc import Iterator, Sequence
from contextlib import contextmanager, suppress
from itertools import count
from pathlib import Path
from typing import Any, Final, cast

#: Longest a single launch will WAIT for a storm to finish before giving up and running anyway.
#:
#: SIZED FROM THE STORM, measured 2026-09-16 on a 20-core developer box carrying 2 competing pytest
#: processes and 28 resident pwsh at the start of the run -- the process count is quoted because a
#: timing from a shared box without one is not a measurement. ``tests/test_session_mail.py`` spends
#: 26.5s total in its three bursts (20.26s + 3.77s + 2.47s by ``--durations``), dominated by one.
#: That box has 20 cores, so it CANNOT reproduce the 4-vCPU failure and these are lower bounds; they
#: are used only to size a wait, never to argue the fix works. CI's own figure agrees in magnitude --
#: 2.4 to 3.1 percent of a ~1250s run is a 30-39s overlap window.
#:
#: THE BURSTS DO NOT OVERLAP EACH OTHER: all four live in one file, and ``--dist loadfile`` gives a
#: file to ONE worker, which runs its tests in sequence. So a waiting test queues behind at most one
#: burst, and this bound is a per-test bound in practice rather than only a per-call one.
_SINGLE_WAIT_S: Final = 30.0

#: Longest a storm will wait for in-flight single launches to drain before starting anyway. A single
#: hold is one ``pwsh`` launch, bounded by its caller at 45s but observed at a ~2s median, so this is
#: generous. Proceeding early costs only the overlap we have today.
_BURST_DRAIN_S: Final = 15.0

#: A reader entry older than this is treated as abandoned. The longest legitimate hold is one gate
#: launch at ``GATE_TIMEOUT_S`` (45s) plus process overhead, so 120s cannot reap a live holder that is
#: behaving; if it ever does, the effect is that a storm starts beside it, which is today's behaviour.
_READER_STALE_S: Final = 120.0

#: A turnstile older than this is treated as abandoned. The longest legitimate storm is bounded by
#: its own test at ``@pytest.mark.timeout(300)`` with per-racer ``timeout=240``, so 360s clears it.
_BURST_STALE_S: Final = 360.0

#: A run directory older than this belongs to a process that is long gone. Far above any run length,
#: so it cannot reap a live peer; see ``_reap_finished_runs``.
_REAP_RUNS_AFTER_S: Final = 86400.0

#: Commands ``run_single`` will hold a ticket across. A PowerShell start carries Windows' process
#: spawn tax and is measured in seconds here, which is what makes serialising it worth a lock; a
#: ``git`` call in this tier is milliseconds and is not. See ``run_single`` for what routing the
#: cheap ones through the lock would silently do to it.
_LOCKED_INTERPRETERS: Final = frozenset({"pwsh", "powershell"})

_POLL_S: Final = 0.05

#: Distinguishes concurrent readers inside ONE process. xdist workers are separate processes, so the
#: pid separates those; a ``ThreadPoolExecutor`` inside one test is why the thread id and counter are
#: needed as well.
_TICKET = count()


def _run_id() -> str:
    """The key every worker of one pytest run agrees on, and that two unrelated runs do not share."""
    return os.environ.get("PYTEST_XDIST_TESTRUNUID") or f"pid-{os.getpid()}"


def _age(path: Path) -> float | None:
    """Seconds since ``path`` was created, or ``None`` if it is gone or unreadable."""
    try:
        return time.time() - path.stat().st_mtime
    except OSError:
        return None


def _lock_root() -> Path | None:
    """Machine-global for the repo, then narrowed to this run. ``None`` means run without the lock.

    The git common dir is shared by every worktree of the checkout, which is the same directory
    ``tests/conftest.py`` anchors its slots to. PURE QUERY: it resolves and creates, and does NOT
    reap -- ``_ROOT`` below does that once, so a caller asking only whether the path resolves cannot
    trigger a recursive delete over a shared ``.git`` as a side effect.

    IT COSTS ONE ``git`` CALL PER PROCESS, WHICH UNDER ``-n 4`` IS FIVE PER RUN, and that is worth
    stating plainly in a module whose subject is too many processes. The result is cached in
    ``_ROOT``, so it is five at import and none per launch. ``tests/conftest.py`` already resolves
    the same value in the same processes; collapsing the two into one shared, side-effect-free
    helper is the right follow-on and is not done here, because importing a conftest re-runs its
    slot-claiming import side effects.
    """
    try:
        common = subprocess.run(
            ["git", "rev-parse", "--path-format=absolute", "--git-common-dir"],
            capture_output=True,
            text=True,
            check=False,
            timeout=30,
        ).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return None
    if not common:
        return None
    root = Path(common) / "mefor-coord" / "pwsh-burst" / _run_id()
    try:
        (root / "readers").mkdir(parents=True, exist_ok=True)
    except OSError:
        return None
    return root


def _reap_finished_runs(runs: Path) -> None:
    """Drop the directories of runs that ended long ago.

    The key is per-RUN, so without this every pytest run would leave a directory behind forever in a
    checkout's shared ``.git`` -- ``tests/conftest.py``'s slots do not accumulate because they reuse
    32 fixed names, and this would. A day is far longer than any run, so a directory that old belongs
    to a process that is gone; and deleting one that somehow is not costs only the lock, per the
    fail-open rule in the module docstring. Best-effort: a peer reaping the same directory
    concurrently, or a file held open, is ignored rather than raised.

    ``os.scandir`` rather than ``iterdir``: it serves ``is_dir()`` and ``stat()`` from the directory
    read that already happened, so this costs no syscall per entry beyond the one listing.
    """
    cutoff = time.time() - _REAP_RUNS_AFTER_S
    mine = _run_id()
    try:
        with os.scandir(runs) as entries:
            stale = [
                e.path
                for e in entries
                if e.name != mine and e.is_dir() and e.stat().st_mtime < cutoff
            ]
    except OSError:
        return
    for path in stale:
        shutil.rmtree(path, ignore_errors=True)


_ROOT: Final = _lock_root()

if _ROOT is not None:
    # Once per process, at the one place that should ever sweep -- never from a query.
    _reap_finished_runs(_ROOT.parent)


def _turnstile_blocks(root: Path) -> bool:
    """Is a storm holding the turnstile right now? Reaps it first if it is abandoned."""
    gate = root / "burst.lock"
    age = _age(gate)
    if age is None:
        return False
    if age > _BURST_STALE_S:
        with suppress(OSError):
            gate.unlink(missing_ok=True)
        return False
    return True


def _live_readers(root: Path) -> int:
    """Count in-flight single launches, reaping abandoned entries as it goes."""
    readers = root / "readers"
    try:
        entries = list(readers.iterdir())
    except OSError:
        return 0
    live = 0
    for entry in entries:
        age = _age(entry)
        if age is None:
            continue
        if age > _READER_STALE_S:
            with suppress(OSError):
                entry.unlink(missing_ok=True)
            continue
        live += 1
    return live


def _note(message: str) -> None:
    """Record a fail-open event where the NEXT #1304 occurrence will be read.

    THE FIX IS DELIBERATELY PARTIAL -- other spawn sources in this tier are unwrapped -- so when a
    launch times out again the log has to separate three outcomes that otherwise look identical: the
    lock did not cover that source, the lock covered it and fell open, or the cause is something
    else. Without this the turnstile's label is written and never read by anything.

    stderr, because pytest captures it per test and surfaces it on failure, which is exactly when it
    is wanted. Never raises: a diagnostic that can fail a run is worse than no diagnostic.
    """
    with suppress(OSError, ValueError):
        print(f"[spawn-lock] {message}", file=sys.stderr)


def _turnstile_holder(root: Path) -> str:
    """The label a storm wrote, for the diagnostic above. ``unknown`` rather than a raise."""
    try:
        return (root / "burst.lock").read_text(encoding="utf-8", errors="replace").strip() or "?"
    except OSError:
        return "no holder (it finished while we waited)"


@contextmanager
def single_spawn() -> Iterator[None]:
    """Hold the SHARED side across one process launch.

    Waits out a storm if one is running, registers as a reader so a storm about to start waits for
    this launch instead of racing it, then yields. Gives up waiting after ``_SINGLE_WAIT_S`` and runs
    anyway, because a bounded overlap is today's behaviour and a test that never returns is not.
    """
    root = _ROOT
    if root is None:
        yield
        return

    started = time.monotonic()
    deadline = started + _SINGLE_WAIT_S
    ticket = root / "readers" / f"{os.getpid()}-{threading.get_ident()}-{next(_TICKET)}.lock"
    held = False
    try:
        while True:
            if not _turnstile_blocks(root):
                try:
                    # Register BEFORE re-checking: a storm that takes the turnstile between the check
                    # above and this write still sees this entry when it drains, so the two cannot
                    # both conclude they have the field to themselves.
                    fd = os.open(ticket, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
                    os.close(fd)
                    held = True
                except OSError:
                    pass  # cannot register: fall through and run unsynchronised
                if not held or not _turnstile_blocks(root):
                    break
                # A storm won the race for the turnstile. Stand down and wait for it.
                with suppress(OSError):
                    ticket.unlink(missing_ok=True)
                held = False
            if time.monotonic() >= deadline:
                _note(
                    f"single launch waited {time.monotonic() - started:.1f}s behind "
                    f"{_turnstile_holder(root)} and proceeded UNSYNCHRONISED"
                )
                break
            time.sleep(_POLL_S)
        yield
    finally:
        if held:
            with suppress(OSError):
                ticket.unlink(missing_ok=True)


@contextmanager
def spawn_burst(label: str) -> Iterator[None]:
    """Hold the EXCLUSIVE side across a burst of concurrent process launches.

    ``label`` is written into the turnstile so a stuck run names its own holder rather than leaving
    the next reader to guess. Takes the turnstile to stop NEW single launches, then waits for the
    in-flight ones to drain so they finish at full speed instead of inside this burst.

    The burst itself is never blocked: if the turnstile cannot be taken, or the drain does not finish
    inside ``_BURST_DRAIN_S``, it proceeds regardless.
    """
    root = _ROOT
    if root is None:
        yield
        return

    gate = root / "burst.lock"
    held = False
    deadline = time.monotonic() + _BURST_DRAIN_S
    while time.monotonic() < deadline:
        try:
            fd = os.open(gate, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
            os.write(fd, f"{label} pid={os.getpid()} at={time.time():.0f}".encode())
            os.close(fd)
            held = True
            break
        except FileExistsError:
            if not _turnstile_blocks(root):  # reaps an abandoned turnstile, then retries
                continue
            time.sleep(_POLL_S)
        except OSError:
            break  # cannot take it at all: run unsynchronised rather than fail the test
    if not held:
        _note(f"burst {label!r} could not take the turnstile; running UNSYNCHRONISED")
    try:
        if held:
            while time.monotonic() < deadline and _live_readers(root):
                time.sleep(_POLL_S)
            if _live_readers(root):
                _note(f"burst {label!r} started with in-flight launches it could not drain")
        yield
    finally:
        if held:
            with suppress(OSError):
                gate.unlink(missing_ok=True)


def run_single(cmd: Sequence[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
    """``subprocess.run`` for ONE INTERPRETER launch, held on the shared side of the lock.

    A drop-in at the call site so wrapping a launch is a one-word edit rather than a re-indent of the
    block around it -- which keeps this change off the same lines as the open work on these files.

    IT REFUSES ANYTHING BUT AN INTERPRETER, AND THAT GUARD IS THE POINT RATHER THAN TIDINESS. The
    lock's cost model only holds for a spawn expensive enough to be worth serialising. Route this
    tier's hundreds of cheap ``git`` calls through here and every held ticket extends every
    concurrent burst's drain wait, so bursts stop draining, hit ``_BURST_DRAIN_S`` and proceed
    unsynchronised -- the fix disables ITSELF, fails open exactly as designed, and nothing goes red.
    ``test_spawn_lock.py`` pins the storm counts against weakening the writers; this pins the reader
    population against weakening them. A convention in a docstring would not have held that line.

    ``subprocess.run`` is looked up on the MODULE at call time, deliberately. Module objects are
    singletons, so ``test_worktree_gate_control_plane.py``'s
    ``monkeypatch.setattr(harness.subprocess, "run", ...)`` -- which drives the launch-timeout
    diagnostic -- still intercepts this call. A ``from subprocess import run`` here would silently
    bypass that test's patch and the test would stop proving anything.
    """
    binary = Path(cmd[0]).name.lower().removesuffix(".exe") if cmd else ""
    if binary not in _LOCKED_INTERPRETERS:
        raise ValueError(
            f"run_single is for an interpreter launch, not {cmd[0]!r}. Only "
            f"{sorted(_LOCKED_INTERPRETERS)} are expensive enough to be worth the lock; holding a "
            "ticket across a cheap call starves every concurrent burst's drain and silently "
            "disables this module. Call subprocess.run directly."
        )
    with single_spawn():
        return cast("subprocess.CompletedProcess[str]", subprocess.run(cmd, **kwargs))
