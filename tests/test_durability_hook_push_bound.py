# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A durability push that never finishes leaves the hook's own shells running forever.

``scripts/hooks/durability_push.sh`` detaches its push so the commit returns immediately. Nothing
above the background job waits for it, which is the design and it works. What did not work is what
happens when the push itself never ends: the job doing the work had no deadline, so it stayed.

**THIS FILE PINS ONE MODE, AND IT IS NOT THE ONE THAT WAS FOUND IN THE WILD.** Measured 2026-09-22 on
a developer machine: eighteen ``sh .git/hooks/post-commit`` processes alive across nine commits, the
oldest 40 hours, three of them spinning -- 57 CPU-hours between them. In every one of those repos the
push had already SUCCEEDED (the moving tag matched HEAD and ``refs/mefor/durability/...`` had been
written, which is the hook's last statement), so the work had finished and the shells stayed anyway.
That failure is unexplained and is NOT covered here. The mode covered here -- a push that wedges --
is real, reproducible, and was verified to leak the same shells forever. Do not read a green run of
this file as evidence that the 2026-09-22 leak is fixed.

**THE ARMING IS THE WHOLE TEST, SO IT IS ASSERTED AND NOT ASSUMED.** "No process is left behind" is
also what a push that never started looks like, and that is the shape this file exists to avoid
shipping. The wedged test waits for the push to APPEAR first and SKIPS if it never does, then waits
for it to go. A skip, unlike a pass, says plainly that nothing was measured.

**THE PUSH IS WEDGED WITH ``core.sshCommand``, NOT WITH A NETWORK.** An ``ssh://`` remote whose
transport is a sleep hangs deterministically and offline, so this measures the hook rather than the
state of somebody's DNS.

**EVERY PROCESS THIS FILE CREATES CARRIES A TOKEN, FOR TWO REASONS.** The suite runs under
``pytest-xdist``, and every worker's hook has the identical ``sh .git/hooks/post-commit`` command
line, so counting those would let one worker fail another. And a test about leaked processes must not
leak any: the fixture tears down by the same token it asserts on. The sleeper's duration carries the
token too, because ``exec`` replaces the wrapper and a bare ``sleep 900`` would be untraceable.

**AND THIS FILE DID LEAK, MEASURED 2026-10-17.** Orphaned, SUSPENDED ``git update-ref
refs/mefor/durability/r<token>/main``, ``git push --quiet --force priv ...`` and ``git-receive-pack``
processes, 5 to 12 hours old, every one carrying this file's ``r<token>`` repository name or its
temporary directory. Two routes, both closed here:

* **The owner died before teardown.** An xdist worker that hits the per-test timeout leaves by
  ``os._exit`` (``--timeout-method=thread``), and no fixture runs. Reproduced the same day: a worker
  went "node down" and the wedge's transport shell outlived it. So on Windows every ``git commit``
  that can fire the hook starts SUSPENDED, joins a kill-on-close job (``messagefoundry.proctree``),
  and only then runs. Everything the hook detaches is in that job, so it dies with the worker by
  any route.
* **Teardown killed a shell mid-spawn.** The old teardown killed whatever it found in one pass, in
  PID order. Killing an MSYS shell between its ``CreateProcess(CREATE_SUSPENDED)`` and the resume
  leaves the child suspended forever with a dead parent -- the state measured -- and a shell killed
  after the pass can still have spawned the next statement. Teardown now ends the jobs, which
  kills every member at once, a child created suspended included; then it sweeps until two passes
  in a row find nothing, and FAILS the test if anything survives.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import time
import uuid
from collections.abc import Iterator
from pathlib import Path

import psutil
import pytest

from messagefoundry import proctree
from tests._proc_tree import alive, cmdline_of, kill_all, tree_of, wait_until

ROOT = Path(__file__).resolve().parents[1]
#: Overridable so this file can be run red-first against a pre-fix hook, the control the sibling
#: suite established:  MEFOR_DURABILITY_HOOK=/tmp/old.sh pytest tests/test_durability_hook_push_bound.py
HOOK = Path(
    os.environ.get("MEFOR_DURABILITY_HOOK") or (ROOT / "scripts" / "hooks" / "durability_push.sh")
)
#: Every budget here lives under a 60s PER-TEST watchdog (``--timeout=60`` in pyproject.toml, 120s on
#: the Windows legs). Exceed it and pytest-timeout kills the test and dumps stacks, which reads as a
#: hang rather than as the assertion that was about to fire -- measured while writing this file. So
#: the worst case is APPEAR_WAIT + REAP_WAIT and it must stay well inside that. A subprocess timeout
#: above the watchdog would be an inert guard, so this one sits below it.
TIMEOUT = 30
#: The hook's bound, set low so the tests do not wait out the 300s default.
BOUND = 5
APPEAR_WAIT = 15.0
#: The bound plus its ``-k`` grace plus slack. A leak has no deadline at all, so this only has to be
#: longer than the bound, not tight.
REAP_WAIT = 25.0
#: A local bare remote lands in well under a second; this is only a ceiling.
LAND_WAIT = 10.0
#: How long to watch for a moving-tag push that must NOT happen. A negative assertion always spends
#: its whole budget, so this is sized to "the bound plus its grace, and no more": if the discard were
#: going to follow the timed-out capture, it would start within that. The ordering test's worst case
#: is LAND_WAIT + LAND_WAIT + APPEAR_WAIT + DISCARD_WATCH, which must stay under the 60s watchdog.
DISCARD_WATCH = 12.0
#: Teardown, where there is no job to end (POSIX). Against a reachable remote the hook's background
#: work finishes well inside SETTLE, so nothing is killed mid-spawn. SWEEP bounds the kill passes.
#: Both come out of the same 60s watchdog, so they stay small beside the budgets above.
SETTLE = 3.0
SWEEP = 10.0

pytestmark = pytest.mark.skipif(
    shutil.which("sh") is None, reason="durability_push.sh is a /bin/sh hook and needs sh on PATH"
)


#: Nothing this file starts predates its import, so older processes are skipped unread: see
#: ``_ours`` for what a full command-line walk costs on a loaded box.
_IMPORTED = time.time() - 1.0


def _matching(token: str) -> list[str]:
    """Command lines of every live process, started since this file loaded, carrying ``token``."""
    hits: list[str] = []
    for proc in psutil.process_iter():
        try:
            if proc.create_time() < _IMPORTED:
                continue
        except psutil.Error:  # the process died mid-walk
            continue
        line = cmdline_of(proc)
        if line and token in line:
            hits.append(line)
    return hits


def git(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(repo), *args], capture_output=True, text=True, timeout=TIMEOUT, check=True
    ).stdout.strip()


def _arm(repo: Path) -> None:
    subprocess.run(["git", "init", "-q", "-b", "main", str(repo)], check=True, capture_output=True)
    git(repo, "config", "user.email", "t@example.invalid")
    git(repo, "config", "user.name", "t")
    git(repo, "config", "commit.gpgsign", "false")
    hook = repo / ".git" / "hooks" / "post-commit"
    shutil.copy2(HOOK, hook)
    hook.chmod(0o755)


def _commit(
    jobs: list[int], repo: Path, text: str, *extra: str
) -> subprocess.CompletedProcess[str]:
    if "--amend" not in extra:
        (repo / "a.txt").write_text(text, encoding="utf-8")
        subprocess.run(
            ["git", "-C", str(repo), "add", "-A"], check=True, capture_output=True, timeout=TIMEOUT
        )
    return _run_in_job(jobs, ["git", "-C", str(repo), "commit", "-q", *extra, "-m", text.strip()])


def _run_in_job(jobs: list[int], argv: list[str]) -> subprocess.CompletedProcess[str]:
    """``subprocess.run`` for a command whose descendants must not outlive this process.

    On Windows it starts suspended, joins a fresh kill-on-close job, and only then runs, so nothing
    it starts -- the hook's detached push included -- is created outside the job; the job goes on
    ``jobs`` for teardown to end. Elsewhere there is no job and teardown's sweep is the guard.
    Never waits on the pipes after a kill: a detached descendant can hold them open."""
    proc = subprocess.Popen(  # noqa: S603 - fixed argv, no shell
        argv,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        creationflags=proctree.ADOPT_CREATIONFLAGS,
    )
    try:
        job = proctree.resume_into_job(proc.pid, who="durability test commit")
        if job is not None:
            jobs.append(job)
        out, err = proc.communicate(timeout=TIMEOUT)
    except BaseException:
        # Reap it, and close the pipes here rather than drain them: a detached descendant can hold
        # them open, and the job teardown ends that descendant.
        proc.kill()
        for pipe in (proc.stdout, proc.stderr):
            if pipe is not None:
                pipe.close()
        proc.wait(timeout=TIMEOUT)
        raise
    return subprocess.CompletedProcess(argv, proc.returncode, out, err)


def _sleep_mark(token: str) -> str:
    """A valid sleep interval unique to one test, so the wedged transport stays findable."""
    return f"900.{int(token[:6], 16) % 1000000:06d}"


def _wedge(repo: Path, tmp_path: Path, token: str) -> None:
    """Point the repo's remote at a transport that never returns, offline.

    ``exec`` replaces the wrapper shell, so the surviving process is the sleep itself and the script
    path is gone from its command line. The DURATION therefore carries the token, which is what makes
    the process findable for teardown.

    **THE DURATION MUST BE A VALID INTERVAL, AND THE TOKEN IS HEX.** An earlier version spelled it
    ``sleep 9{token[:6]}``, which is ``sleep 9a3f10b`` whenever the token carries a letter -- an
    invalid interval. ``sleep`` then exited immediately, the transport died, the push failed fast, and
    the reap assertion passed because there was never anything to reap. Measured: the push appeared in
    1 of 3 trials. So the token is folded to decimal here, and `_sleep_mark` is the single spelling
    both the wedge and the teardown use.
    """
    sleeper = tmp_path / f"sleeper-{token}.sh"
    sleeper.write_text(
        f"#!/bin/sh\nexec sleep {_sleep_mark(token)}\n", encoding="utf-8", newline="\n"
    )
    sleeper.chmod(0o755)
    git(repo, "remote", "set-url", "priv", "ssh://nowhere.invalid/x.git")
    git(repo, "config", "core.sshCommand", f"sh {sleeper.as_posix()}")


def _ours(token: str, root: Path, since: float) -> list[psutil.Process]:
    """Every live process this test made: created after ``since``, and either its command line
    carries the token, the sleeper's mark or the test's temporary directory, or its working
    directory lies inside that directory.

    **THE HOOK'S OWN SHELLS CARRY NO TOKEN.** Their command line is the bare
    ``sh .git/hooks/post-commit``, identical in every worker, so nothing in it ties one to THIS test.
    The working directory does, and psutil exposes it where ``Win32_Process`` does not. Those shells
    DO leak here, against the fixed hook, on the success path: measured 2026-09-22, a passing run
    left a pair alive with a dead parent and flat CPU, still there 95s later.

    The command line is checked as well because a process frozen before it ever ran need not yield
    a working directory. The 2026-10-17 ``update-ref`` and ``push`` carry ``r<token>``, and
    ``git-receive-pack`` the bare repository's path.

    **THE CREATION TIME GOES FIRST, BECAUSE A FULL READ IS SLOW.** Measured 2026-10-17 on a loaded
    developer box: a walk reading every process's command line took up to 24s, and reading every
    working directory as well added up to 21s more. psutil holds each process's creation time from
    the walk itself, so everything older than this test is skipped before anything else is read."""
    root_text = str(root).lower()
    needles = (token, _sleep_mark(token), root_text, root.as_posix().lower())
    found: list[psutil.Process] = []
    for proc in psutil.process_iter():
        try:
            if proc.create_time() < since:
                continue
            line = " ".join(proc.cmdline()).lower()
            if any(n in line for n in needles) or str(proc.cwd()).lower().startswith(root_text):
                found.append(proc)
        except psutil.Error:  # gone, or not ours to read
            continue
    return found


def _created(proc: psutil.Process) -> float:
    try:
        return proc.create_time()
    except psutil.Error:
        return 0.0


def _reap(
    token: str, root: Path, since: float, jobs: list[int], *, settle: float = SETTLE
) -> list[str]:
    """Leave no process of this test running; return the command lines of any that stayed.

    On Windows, end every job first. That kills each member at once, a child created suspended
    mid-spawn included, so nothing is left half-started. With no job (POSIX) let the hook finish
    instead, so no shell is killed between spawning a child and resuming it. Then sweep, oldest
    first -- parents before the children they could still spawn -- until two passes in a row find
    nothing. ``kill`` is ``TerminateProcess`` on Windows, which ends a suspended process without
    resuming it, so a process frozen before it ran never runs here.
    """
    if jobs:
        for job in jobs:
            proctree.terminate_job(job)
        jobs.clear()
    else:
        wait_until(lambda: not _ours(token, root, since), settle)
    deadline = time.monotonic() + SWEEP
    quiet = 0
    while time.monotonic() < deadline:
        procs = _ours(token, root, since)
        if not procs:
            quiet += 1
            if quiet == 2:
                return []
        else:
            quiet = 0
            kill_all(sorted(procs, key=_created))
        time.sleep(0.2)
    survivors: list[str] = []
    for proc in _ours(token, root, since):
        try:
            survivors.append(f"{proc.pid} [{proc.status()}] {' '.join(proc.cmdline())}")
        except psutil.Error:
            continue
    return survivors


@pytest.fixture
def jobs() -> list[int]:
    """The kill-on-close jobs this test's commits joined (Windows); ``token`` ends them."""
    return []


@pytest.fixture
def token(tmp_path: Path, jobs: list[int]) -> Iterator[str]:
    """A token unique to one test, and the teardown that FAILS the test if any process of its
    outlives it -- on failure as well as on success."""
    value = uuid.uuid4().hex[:12]
    # A margin below now, so a process started in this same instant still counts as this test's.
    since = time.time() - 1.0
    try:
        yield value
    finally:
        survivors = _reap(value, tmp_path, since, jobs)
    assert not survivors, (
        f"THIS TEST LEFT {len(survivors)} PROCESS(ES) RUNNING after its teardown -- the leak "
        "measured 2026-10-17, suspended git processes with a dead parent, hours old:\n"
        + "\n".join(survivors)
    )


@pytest.fixture
def live(tmp_path: Path, token: str) -> tuple[Path, Path]:
    """An armed repo whose durability remote is a local bare repo the push can actually reach."""
    bare = tmp_path / "priv.git"
    subprocess.run(
        ["git", "init", "-q", "--bare", "-b", "main", str(bare)], check=True, capture_output=True
    )
    repo = tmp_path / f"r{token}"
    repo.mkdir()
    _arm(repo)
    git(repo, "remote", "add", "priv", str(bare))
    git(repo, "config", "mefor.durabilityRemote", "priv")
    return repo, bare


def test_a_WEDGED_push_is_REAPED_rather_than_left_running_forever(
    live: tuple[Path, Path], tmp_path: Path, token: str, jobs: list[int]
) -> None:
    repo, _ = live
    git(repo, "config", "mefor.durabilityPushTimeout", str(BOUND))
    _wedge(repo, tmp_path, token)

    proc = _commit(jobs, repo, "one\n")
    assert proc.returncode == 0, "THE HOOK FAILED A COMMIT\n" + proc.stdout + proc.stderr

    # THE NEEDLE IS THE REFNAME, NOT THE BARE TOKEN, AND THE DIFFERENCE IS A MEASURED LIMIT OF THE
    # FIX. The refname carries the repo directory name, so it identifies THIS test's `git push` among
    # every other xdist worker's -- and the push is what the bound actually reaps.
    #
    # The bare token ALSO matches the ssh transport the push spawned, and that process SURVIVES the
    # bound: measured on this platform, `timeout` kills `git push` and the transport helper's own
    # child outlives it, because MSYS process-group emulation does not carry a group kill to
    # grandchildren. Asserting on the bare token here would be asserting a fix that does not exist.
    # The residue is named in the hook's own comment beside the bound; it is in the commit's job,
    # and the `token` fixture ends that job, so this file leaks nothing. Widening this needle is a
    # change to the FIX, not the test.
    push_needle = f"rescue/auto/r{token}"

    if not wait_until(lambda: bool(_matching(push_needle)), APPEAR_WAIT):
        pytest.skip(
            f"could not arm: no process carrying {push_needle!r} appeared within {APPEAR_WAIT}s, so "
            "the wedged push never started and the bound cannot be observed on this run"
        )

    # A WEDGE THAT COLLAPSES ON ITS OWN IS NOT A WEDGE, AND MUST NOT READ AS A REAP. If the push
    # disappears before the bound could possibly have fired, something other than the bound ended it,
    # and the reap assertion below would pass on that. This is not hypothetical: it is precisely how
    # the invalid-interval bug described in `_wedge` produced a green run.
    settle = min(BOUND - 2.0, 3.0)
    time.sleep(settle)
    if not _matching(push_needle):
        pytest.skip(
            f"could not arm: the push carrying {push_needle!r} vanished within {settle}s, well "
            f"before the {BOUND}s bound could fire, so it was never wedged"
        )

    last: list[str] = []

    def reaped() -> bool:
        nonlocal last
        last = _matching(push_needle)
        return not last

    assert wait_until(reaped, REAP_WAIT), (
        f"THE BOUND DID NOT FIRE. A push carrying {push_needle!r} was still running {REAP_WAIT}s "
        f"after a commit whose mefor.durabilityPushTimeout is {BOUND}s. Unbounded it outlives the "
        f"repository and the test run: measured at 40 hours on a real machine.\n" + "\n".join(last)
    )


def test_a_TIMED_OUT_orphan_capture_STOPS_the_push_that_would_discard_it(
    live: tuple[Path, Path], tmp_path: Path, token: str, jobs: list[int]
) -> None:
    """Preserve, then discard -- and a timed-out preserve must not be followed by the discard.

    The hook force-moves ``refs/tags/rescue/auto/<repo>/<branch>`` on every commit. After a rewrite
    the old tip is no longer an ancestor, so before moving the tag the hook pushes that tip to an
    immutable ``rescue/orphan/...`` name. If THAT push times out the tip was never captured, and
    moving the tag then discards exactly the commits the capture exists for.

    **THE OBSERVABLE IS WHETHER THE MOVING PUSH IS ATTEMPTED, NOT ``$LAST``.** An earlier version of
    this test asserted that ``$LAST`` did not advance, and it was INERT: both pushes go to the same
    wedged remote, so the moving push times out too and ``$LAST`` fails to advance either way. It
    passed against a deliberately ungated hook, which is the whole failure it existed to catch.
    So this watches the two pushes instead. The orphan capture is
    ``refs/tags/rescue/orphan/...`` and the moving tag is ``refs/tags/rescue/auto/...``, so the two
    are distinguishable in a command line. Gated: the orphan push appears and the moving push never
    does. Ungated: the moving push follows it once the bound fires.
    """
    repo, _ = live
    first = _commit(jobs, repo, "one\n")
    assert first.returncode == 0, "THE HOOK FAILED A COMMIT\n" + first.stdout + first.stderr

    branch = git(repo, "symbolic-ref", "--short", "HEAD")
    last_ref = f"refs/mefor/durability/r{token}/{branch}"
    orphan_needle = f"rescue/orphan/r{token}"
    moving_needle = f"rescue/auto/r{token}"

    # The reachable remote must land first, or there is no $LAST and the orphan path is never taken.
    if not wait_until(lambda: _resolves(repo, last_ref), LAND_WAIT):
        pytest.skip(
            f"could not arm: {last_ref} was never written, so the orphan path is unreachable"
        )

    # Quiesce, so the FIRST commit's moving push cannot be mistaken for the amend's.
    if not wait_until(lambda: not _matching(moving_needle), LAND_WAIT):
        pytest.skip("could not arm: the first commit's moving push never finished")

    # Now wedge the remote and rewrite, so the orphan capture is attempted and times out.
    git(repo, "config", "mefor.durabilityPushTimeout", str(BOUND))
    _wedge(repo, tmp_path, token)
    amended = _commit(jobs, repo, "one, corrected\n", "--amend")
    assert amended.returncode == 0, "THE HOOK FAILED A COMMIT\n" + amended.stdout + amended.stderr

    if not wait_until(lambda: bool(_matching(orphan_needle)), APPEAR_WAIT):
        pytest.skip(
            f"could not arm: no orphan capture carrying {orphan_needle!r} was attempted, so the "
            "preserve-then-discard path was never entered and the gate cannot be observed"
        )

    # Past the bound and its grace, the moving push would have started by now if it were going to.
    seen: list[str] = []

    def moving_started() -> bool:
        nonlocal seen
        seen = _matching(moving_needle)
        return bool(seen)

    assert not wait_until(moving_started, DISCARD_WATCH), (
        f"THE DISCARD RAN AFTER THE PRESERVE TIMED OUT. A moving-tag push carrying {moving_needle!r} "
        f"started even though the orphan capture never landed, so the tag stops covering the tip the "
        f"capture failed to preserve, and $LAST would advance past it. Preserve, then discard -- a "
        f"failed preserve must stop.\n" + "\n".join(seen)
    )


def _resolves(repo: Path, ref: str) -> bool:
    got = subprocess.run(
        ["git", "-C", str(repo), "rev-parse", "--verify", "--quiet", ref],
        capture_output=True,
        text=True,
        timeout=TIMEOUT,
    )
    return got.returncode == 0 and bool(got.stdout.strip())


def test_the_BOUND_does_not_break_a_push_that_finishes(
    live: tuple[Path, Path], token: str, jobs: list[int]
) -> None:
    """Durability outranks the bound, so the ordinary path must still land its ref."""
    repo, bare = live
    git(repo, "config", "mefor.durabilityPushTimeout", str(BOUND))
    proc = _commit(jobs, repo, "one\n")
    assert proc.returncode == 0, "THE HOOK FAILED A COMMIT\n" + proc.stdout + proc.stderr

    ref = f"refs/tags/rescue/auto/r{token}/main"
    assert wait_until(lambda: _resolves(bare, ref), LAND_WAIT), (
        f"{ref} never reached the remote. The bound must not cost durability on a push that works."
    )


@pytest.mark.parametrize("bad", ["", "abc", "0"])
def test_a_MISCONFIGURED_bound_falls_back_instead_of_failing_the_commit(
    live: tuple[Path, Path], bad: str, jobs: list[int]
) -> None:
    """One value per arm of the hook's guard. The hook's first contract is that it never fails one."""
    repo, _ = live
    git(repo, "config", "mefor.durabilityPushTimeout", bad)
    proc = _commit(jobs, repo, f"bad-{bad or 'empty'}\n")
    assert proc.returncode == 0, (
        f"mefor.durabilityPushTimeout={bad!r} FAILED A COMMIT. The hook's first contract is that it "
        "never does.\n" + proc.stdout + proc.stderr
    )


# --- the teardown itself -------------------------------------------------------------------------


def test_the_TEARDOWN_ends_a_SUSPENDED_process_frozen_before_it_ran(
    tmp_path: Path, token: str
) -> None:
    """The 2026-10-17 shape: a process carrying this test's token, frozen before it ever ran, in no
    job. On Windows it is created suspended and never resumed, which is what a shell killed between
    ``CreateProcess(CREATE_SUSPENDED)`` and the resume leaves; elsewhere it is stopped on start. The
    census must SEE it first, or "nothing survived" would only mean nothing was found."""
    since = time.time() - 1.0
    frozen = subprocess.Popen(  # noqa: S603 - fixed argv, no shell
        [sys.executable, "-c", "import time; time.sleep(60)", token],
        cwd=tmp_path,
        creationflags=proctree.ADOPT_CREATIONFLAGS,
    )
    tree = tree_of(frozen.pid)
    if sys.platform != "win32":
        for proc in tree:
            proc.suspend()
    assert wait_until(lambda: len(_ours(token, tmp_path, since)) >= len(tree), APPEAR_WAIT), (
        "could not arm: the teardown census did not see the frozen process"
    )
    # No settle: a frozen process never finishes, so waiting for it would only spend the budget.
    assert _reap(token, tmp_path, since, [], settle=0) == []
    frozen.wait(timeout=TIMEOUT)
    assert not alive(tree)


@pytest.mark.skipif(sys.platform != "win32", reason="the kill-on-close job object is Windows-only")
def test_what_a_commit_DETACHES_is_in_the_job_so_it_dies_with_this_process(
    token: str, jobs: list[int]
) -> None:
    """The hook detaches its push with ``( ... & )``, so nothing waits for it. Started the way
    ``_commit`` starts a commit, a detached grandchild must still land in the job: ending the job
    ends it, and closing the job's last handle -- what Windows does when this process dies by any
    route -- would end it the same way."""
    mark = _sleep_mark(token)
    ran = _run_in_job(jobs, ["sh", "-c", f"( sleep {mark} & ) >/dev/null 2>&1"])
    assert ran.returncode == 0, ran.stdout + ran.stderr
    assert jobs, "could not arm: the command joined no job"
    assert wait_until(lambda: bool(_matching(mark)), APPEAR_WAIT), (
        "could not arm: the detached sleeper never appeared"
    )
    proctree.terminate_job(jobs.pop())
    assert wait_until(lambda: not _matching(mark), REAP_WAIT), (
        "A PROCESS THE COMMIT DETACHED ESCAPED THE JOB, so it would outlive a worker killed by the "
        "per-test timeout:\n" + "\n".join(_matching(mark))
    )
