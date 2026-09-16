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

WHY NOT AN XDIST GROUP. ``--dist loadgroup`` would separate the files that are spawn-heavy TODAY, and
it lives in the pytest invocation in ``.github/workflows/ci.yml`` rather than beside the code it
governs. This module binds the constraint to the call site, so a new bulk spawner opts in by wrapping
itself rather than by someone remembering to edit a workflow.

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
import subprocess
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

_POLL_S: Final = 0.05

#: Distinguishes concurrent readers inside ONE process. xdist workers are separate processes, so the
#: pid separates those; a ``ThreadPoolExecutor`` inside one test is why the thread id and counter are
#: needed as well.
_TICKET = count()


def _run_id() -> str:
    """The key every worker of one pytest run agrees on, and that two unrelated runs do not share."""
    return os.environ.get("PYTEST_XDIST_TESTRUNUID") or f"pid-{os.getpid()}"


def _lock_root() -> Path | None:
    """Machine-global for the repo, then narrowed to this run. ``None`` means run without the lock.

    The git common dir is shared by every worktree of the checkout, which is the same directory
    ``tests/conftest.py`` anchors its slots to. Resolving it costs one ``git`` call per process, so
    the result is cached in ``_ROOT`` below rather than recomputed per launch.
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


_ROOT: Final = _lock_root()


def _age(path: Path) -> float | None:
    """Seconds since ``path`` was created, or ``None`` if it is gone or unreadable."""
    try:
        return time.time() - path.stat().st_mtime
    except OSError:
        return None


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

    deadline = time.monotonic() + _SINGLE_WAIT_S
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
    try:
        if held:
            while time.monotonic() < deadline and _live_readers(root):
                time.sleep(_POLL_S)
        yield
    finally:
        if held:
            with suppress(OSError):
                gate.unlink(missing_ok=True)


def run_single(cmd: Sequence[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
    """``subprocess.run`` for ONE launch, held on the shared side of the lock.

    A drop-in at the call site so wrapping a launch is a one-word edit rather than a re-indent of the
    block around it -- which keeps this change off the same lines as the open work on these files.

    ``subprocess.run`` is looked up on the MODULE at call time, deliberately. Module objects are
    singletons, so ``test_worktree_gate_control_plane.py``'s
    ``monkeypatch.setattr(harness.subprocess, "run", ...)`` -- which drives the launch-timeout
    diagnostic -- still intercepts this call. A ``from subprocess import run`` here would silently
    bypass that test's patch and the test would stop proving anything.
    """
    with single_spawn():
        return cast("subprocess.CompletedProcess[str]", subprocess.run(cmd, **kwargs))
