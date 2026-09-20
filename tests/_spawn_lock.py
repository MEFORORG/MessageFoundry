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
deliberately does not wrap on a hunch. Roughly 65 other files in the tier launch ``pwsh`` without
taking the shared side at all, so a storm does not wait for them. The missing abstraction is a shared
``run_pwsh`` launcher that every site uses; until that exists, ``_note`` below is what makes the next
occurrence tell you which of those gaps it came from.

ONE OF THOSE GAPS HAS SINCE PRODUCED ITS OWN CI EVIDENCE AND IS NOW WRAPPED, which is the mechanism
this paragraph predicted rather than an exception to it. ``tests/test_coord_usage.py`` failed
``main``'s harness leg four times in eleven runs on 2026-09-19, always as a single launch starving
past its 60-second ceiling, and its 21 ``pwsh`` CALL SITES were routed through ``run_single`` on that
evidence. Its two ``bash`` sites were not, by the ``_LOCKED_INTERPRETERS`` rule below. SITES ARE NOT
LAUNCHES: five of the 21 sit inside shared helpers that the file's tests call about 117 times, so the
wrapped population is roughly 140 launches. Size anything against the launches, never against 21.

TWO OF THOSE FOUR JOB LOGS WERE READ AND THEY BLAME DIFFERENT LAUNCHES, which is the limb that
matters: the last ``usage.ps1`` reader in job 105984649514, a middle
``install-usage-statusline.ps1`` in job 105958065037. The same test had already completed several
``pwsh`` launches before the one that starved, so a first-launch cold start is refuted rather than
untested. The 4-of-11 rate is as reported with this change's brief; only the two jobs above were
re-read here. ``tests/test_worktree_prune_merged.py`` is the next candidate by exposure and has no such
evidence yet: its ``test_disqualifiers`` arms are the tier's longest tests at 102-106s against a 120s
per-test bound. Sweeping it in on that alone is the hunch this paragraph refuses.

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
#:
#: WAS 30.0, AND CI MEASURED THAT TOO SMALL -- raised 2026-09-16 on the evidence the ``_note`` below
#: was added to collect, from job 104922278187 on PR 1203. Two launches each waited the ceiling out
#: and gave up while the storm still held the turnstile::
#:
#:     [spawn-lock] single launch waited 30.4s behind session_mail._race claimed x16 pid=1064 ...
#:     [spawn-lock] single launch waited 30.1s behind session_mail._race claimed x16 pid=1064 ...
#:
#: Same storm, same pid, both launches. Each then launched INTO it and blew its caller's 45s bound.
#: The old value was sized from the 20-core box's 26.5s of bursts above, while the SAME paragraph
#: already recorded CI's window as 30-39s -- so the ceiling sat at the bottom of the range it had to
#: cover. A storm is not faster on a smaller runner, which is the direction that matters here.
#:
#: THIS IS NOT THE "RAISING THE CEILING" THE MODULE DOCSTRING REFUTES, and the two are easy to fuse
#: because both are seconds. That refutation is about ``GATE_TIMEOUT_S``, the caller's bound on a
#: launch ALREADY RUNNING: a launch that never returns does not return any sooner for being given
#: longer, so raising it only delays the same failure. This constant is the opposite end -- how long
#: a launch WAITS BEFORE IT STARTS, so that it starts on an idle machine instead of inside a storm.
#: Raising it removes the contention rather than tolerating more of it.
#:
#: RAISING THIS CANNOT PUSH A LAUNCH PAST ITS OWN TIMEOUT, which is the objection to check before
#: believing that. The wait happens in ``single_spawn`` BEFORE ``subprocess.run`` is called, so the
#: caller's ``timeout=`` clock starts at process launch and never includes the wait. Nor does a
#: waiter hold anything: it registers its reader ticket only once the turnstile is clear, so a long
#: wait cannot be reaped by ``_READER_STALE_S`` and cannot stall a storm's drain.
#:
#: IT CAN PUSH A TEST PAST **PYTEST'S** TIMEOUT, THOUGH, AND THAT IS THE BOUND THAT LIMITS ADOPTION.
#: The paragraph above is about ``subprocess.run(timeout=)`` and says nothing about the per-test
#: clock, which keeps running through the wait: the tooling tier runs ``--timeout=120`` and every
#: launch a test makes is charged to that one budget. So the question before wrapping a file is not
#: whether a launch survives, it is whether the TEST's own runtime plus its waits fit.
#:
#: WAITS, PLURAL, AND THE SINGULAR IS THE TRAP. "A waiter queues behind at most one burst" is a
#: property of ONE LAUNCH, and it holds: ``--dist loadfile`` puts the bursts in one file on one
#: worker, so they never overlap each other. It does NOT bound a TEST. ``test_session_mail.py``
#: fires three bursts per job, so a test making four or five launches over a minute can meet burst 1
#: before its second launch and burst 2 before its fifth, and pay each wait separately. Do not size
#: an adoption decision on one wait.
#:
#: WHAT THAT RULES OUT TODAY. ``tests/test_coord_usage.py`` had to split its 8-launch, 90.88s test
#: into five arms before its launches could take the shared side at all (BACKLOG #1304), and
#: ``tests/test_worktree_prune_merged.py`` at 102-106s per test is not a candidate as it stands.
#: Neither split makes an arm SAFE against the 90s ceiling -- it cannot, while the ceiling is flat --
#: it only moves the arms from cannot-fit to usually-fits, with the fail-open below as the floor.
#:
#: THE LOCAL DEFAULT IS TIGHTER THAN THE TIER'S, WHICH IS THE CASE A CI-ONLY READING MISSES.
#: ``pyproject.toml`` sets ``--timeout=60`` repo-wide, so a developer running a wrapped file beside
#: ``test_session_mail.py`` has a 60s per-test budget against a 90s wait ceiling: the wait alone can
#: exhaust it before a process starts. On CI the tier overrides to 120 and this does not bite.
#:
#: MAKING THE WAIT BUDGET-AWARE -- capping it at the test's remaining pytest time instead of a flat
#: ceiling -- is the change that would lift all of this, and it is unbuilt. Until it is, raising
#: ``_SINGLE_WAIT_S`` on fresh storm evidence is not the free move the paragraph above makes it look:
#: ``tests/test_spawn_lock.py`` pins it only from BELOW, so a raise past the per-test timeout would
#: pass every existing assertion and make wrapped tests killable during a storm.
#:
#: WAITING IS ALSO CHEAPER THAN THE FAILURE IT REPLACES. The poll exits the instant the turnstile
#: clears, so a run with no storm in flight pays nothing at all. The observed failure cost 30s of
#: waiting plus a 45s timeout; waiting the storm out instead costs its remaining seconds plus a
#: launch at the ~2s median recorded below.
#:
#: 90.0 IS DELIBERATELY GENEROUS RATHER THAN TIGHT, because a tight ceiling is what produced this
#: failure. It is ~2.3x the top of the only measured window, and stays well under both the storm's
#: own ``@pytest.mark.timeout(300)`` bound and the 360s ``_BURST_STALE_S`` reap -- so an ABANDONED
#: turnstile is still cleared by staleness, never by a waiter giving up on a live one.
_SINGLE_WAIT_S: Final = 90.0

#: Longest a storm will wait for in-flight single launches to drain before starting anyway. A single
#: hold is one ``pwsh`` launch, bounded by its caller at 45s but observed at a ~2s median, so this is
#: generous. Proceeding early costs only the overlap we have today.
#:
#: THE ~2s MEDIAN DOES NOT COVER THE WHOLE POPULATION, and the replacement figure is a BOUND rather
#: than a measurement, said plainly so nobody sizes against it as if it were one.
#: ``tests/test_coord_usage.py``'s requirement-4 test ran 8 launches in 90.88s on windows-2025 (run
#: 35472705438), which is 11.4s per launch AVERAGED, with the test's own Python work, file writes and
#: fixture setup charged in. The heavy launches there -- the installer, and a ``usage.ps1`` that walks
#: a home directory -- are therefore somewhere ABOVE 11.4s, not at it, since the same file's other
#: launches are cheaper. Nobody has timed a single launch in isolation. What is established is that
#: the tail is several times the ~2s median this constant was sized on.
#:
#: IT IS STILL NOT RAISED, and the reason is the drain's shape rather than the launch cost. Under
#: ``--dist loadfile`` a file's tests run sequentially on one worker, so one worker holds at most one
#: ticket at a time: adding call sites raises the chance a burst arrives mid-launch, and adds no
#: ticket to drain. A drain that does time out proceeds unsynchronised, which is the pre-lock
#: baseline, so the cost of this constant being small is bounded by what we already had.
#:
#: READ ``spawn_burst`` BEFORE TREATING THIS AS A DRAIN BUDGET, because it is not only that. One
#: ``deadline`` is set from this constant BEFORE the turnstile-acquire loop and then reused by the
#: drain loop, so a burst that spends 6s contending for the gate has 9s left to drain. A reader
#: sizing "how long may a drain wait" against 15.0 is reading a number the acquire may already have
#: spent. Splitting the two budgets is a real change and is not made here.
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
    # SPLIT ON BOTH SEPARATORS REGARDLESS OF HOST, which pathlib alone does not. PurePosixPath
    # does not treat a backslash as a separator, so on Linux the .name of a Windows-spelled pwsh
    # path is the WHOLE SPELLING and this allowlist then refuses a launch it should take. That is
    # measured on the ubuntu leg, which is where it failed. The tier writes Windows spellings and
    # this module is imported on both platforms, so the parse cannot be the host path flavour.
    # test_spawn_lock.py pins the refuted value beside the fixed one, so a later simplification
    # back to pathlib has to argue with it rather than rediscover it on a red leg.
    spelling = cmd[0] if cmd else ""
    binary = spelling.replace("\\", "/").rsplit("/", 1)[-1].lower().removesuffix(".exe")
    if binary not in _LOCKED_INTERPRETERS:
        raise ValueError(
            f"run_single is for an interpreter launch, not {spelling!r}. Only "
            f"{sorted(_LOCKED_INTERPRETERS)} are expensive enough to be worth the lock; holding a "
            "ticket across a cheap call starves every concurrent burst's drain and silently "
            "disables this module. Call subprocess.run directly."
        )
    with single_spawn():
        return cast("subprocess.CompletedProcess[str]", subprocess.run(cmd, **kwargs))
