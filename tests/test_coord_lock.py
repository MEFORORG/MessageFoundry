# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Tests for the cross-session operation mutex (``scripts/coord/lock.ps1``).

``git worktree add -b <name> <base>`` writes ``.git/config``, so two sessions creating worktrees at
once race ``.git/config.lock`` -- reproduced on Windows as "could not lock config file", leaving
orphaned branches behind. ``new.ps1`` now serializes that call through this lock.

The load-bearing test is ``test_eight_concurrent_claimants_never_hold_it_at_once``: it launches eight
real processes at once and asserts that no two are ever inside the critical section together, via a
CreateNew sentinel taken under the lock. Counting winners instead would test the scheduler -- a
straggler that arrives after the winner released wins legitimately, which is what made the earlier
form fail under CI load. Anything less than genuine concurrency would pass against a lock that does
not lock at all -- which is the failure mode this file exists to exclude.
The number is not arbitrary: a read-modify-write in this same codebase was measured silently losing 4
of 8 concurrent PowerShell writes, so eight is the shape already known to break the naive approach.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

LOCK = Path(__file__).resolve().parents[1] / "scripts" / "coord" / "lock.ps1"

pytestmark = pytest.mark.skipif(
    shutil.which("pwsh") is None or os.name != "nt",
    reason="lock.ps1 needs pwsh on Windows",
)


def _git(cwd: Path, *args: str) -> None:
    subprocess.run(["git", "-C", str(cwd), *args], check=True, capture_output=True, text=True)


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    r = tmp_path / "repo"
    r.mkdir()
    _git(r, "init", "-q")
    _git(r, "config", "user.email", "t@example.invalid")
    _git(r, "config", "user.name", "t")
    (r / "f.txt").write_text("x", encoding="utf-8")
    _git(r, "add", "f.txt")
    _git(r, "commit", "-qm", "init")
    return r


def acquire(
    repo: Path,
    *,
    name: str = "t",
    timeout: int = 2,
    hold_ms: int = 0,
    barrier: Path | None = None,
    witness: Path | None = None,
) -> subprocess.CompletedProcess[str]:
    """Take the lock, optionally hold it, release. Prints ACQUIRED on success.

    ``barrier`` makes concurrency REAL rather than assumed. Without it a claimant races for the lock
    the moment *its own* ``pwsh`` has booted, and cold-start times vary by far more than any
    reasonable hold: a straggler that arrives after the winner has already released then wins
    legitimately, and the caller sees two winners against a lock that never misbehaved. With it, the
    claimant signals readiness *after* start-up and waits for the go file, so pwsh cold-start time is
    excluded from the race. It does NOT cover Enter-CoordLock's own prologue: the ``git rev-parse``
    spawn at lock.ps1:47 runs after the gate and before the deadline is set at lock.ps1:56, and under
    CPU load that alone spread the cohort's deadline start by 645-2134 ms. ``witness`` is what makes
    the test sound despite that -- see the test below.
    """
    gate = ""
    if barrier is not None:
        gate = (
            f"[IO.File]::WriteAllText((Join-Path '{barrier}' \"ready-$PID\"), ''); "
            f"$bd = (Get-Date).AddSeconds(120); "
            f"while (-not (Test-Path (Join-Path '{barrier}' 'go'))) {{ "
            f"if ((Get-Date) -gt $bd) {{ throw 'barrier timeout' }}; "
            f"Start-Sleep -Milliseconds 10 }}; "
        )
    enter = leave = ""
    if witness is not None:
        # Asserts the invariant the mutex actually PROMISES -- that two claimants are never inside the
        # critical section at once -- with no reference to a clock. CreateNew is the same atomic
        # test-and-set the lock itself uses, so a second simultaneous holder throws. NB: at this
        # hold/timeout ratio no second LEGITIMATE acquirer exists within a round, so "sentinel already
        # exists" can only mean overlap; lowering hold_ms re-arms a false positive in this bare catch.
        enter = (
            f"try {{ $w = [IO.File]::Open('{witness}', 'CreateNew', 'Write', 'None') }} "
            f"catch {{ Write-Error 'MUTEX-VIOLATED'; exit 9 }}; "
        )
        leave = f"$w.Dispose(); Remove-Item -LiteralPath '{witness}' -Force; "
    script = (
        f". '{LOCK}'; "
        f"{gate}"
        f"$l = Enter-CoordLock -Name '{name}' -TimeoutSeconds {timeout} -Repo '{repo}'; "
        f"{enter}"
        f"Write-Output 'ACQUIRED'; "
        f"Start-Sleep -Milliseconds {hold_ms}; "
        f"{leave}"
        f"Exit-CoordLock $l"
    )
    return subprocess.run(
        ["pwsh", "-NoProfile", "-NonInteractive", "-Command", script],
        capture_output=True,
        text=True,
        timeout=180,
        check=False,
    )


def test_lock_can_be_taken_and_released(repo: Path) -> None:
    first = acquire(repo)
    assert "ACQUIRED" in first.stdout, first.stderr
    # Released, so an immediate second attempt must succeed -- a lock that never frees is a wedge.
    second = acquire(repo)
    assert "ACQUIRED" in second.stdout, second.stderr


def test_eight_concurrent_claimants_never_hold_it_at_once(repo: Path, tmp_path: Path) -> None:
    """Eight real processes, one lock, all reaching for it at the same instant.

    Asserts OCCUPANCY, not winner count. The barrier releases the cohort together, but each process
    then runs Enter-CoordLock's own prologue (a ``git rev-parse`` spawn, lock.ps1:47) before its deadline
    is set (lock.ps1:56), and nothing synchronizes that. A winner-count assertion tolerates only
    (hold - timeout) of that skew; under CPU load the skew was measured at 645-2134 ms, so counting
    winners tests the scheduler, not the mutex. Measured directly: in five multi-winner rounds the hold
    intervals were strictly DISJOINT -- the extra winners acquired legitimately, after release.

    The witness sentinel is what makes this sound. hold_ms is sized so that a lock which did not lock
    would put all eight inside the critical section together and trip it; the margin over the measured
    skew is (hold - timeout) = 7 s, ~3.3x. Validated both ways per the project's make-it-fail-first
    rule: with Enter-CoordLock stubbed to a no-op it FAILS 3/3 (7 violations each); against the real
    lock it PASSES 8/8 at 40 CPU burners -- the exact load at which the old assertion failed 8/12.
    Cost: the winner now holds for 8 s, so this test's floor wall-time is ~8-9 s on every run.
    """
    barrier = tmp_path / "barrier"
    barrier.mkdir()

    with ThreadPoolExecutor(max_workers=8) as pool:
        claims = [
            pool.submit(
                acquire,
                repo,
                timeout=1,
                hold_ms=8000,
                barrier=barrier,
                witness=tmp_path / "holder.sentinel",
            )
            for _ in range(8)
        ]
        deadline = time.monotonic() + 120
        while len(list(barrier.glob("ready-*"))) < 8:
            assert time.monotonic() < deadline, (
                f"only {len(list(barrier.glob('ready-*')))} of 8 claimants reached the barrier"
            )
            time.sleep(0.02)
        (barrier / "go").write_text("", encoding="utf-8")
        results = [c.result() for c in claims]

    violations = [r for r in results if "MUTEX-VIOLATED" in r.stderr]
    assert not violations, f"{len(violations)} claimants held the lock simultaneously"
    winners = [r for r in results if "ACQUIRED" in r.stdout]
    assert winners, "nobody acquired -- the lock is wedged"
    # Everyone else must FAIL, not silently proceed. Silent success is the bug.
    assert all(
        "Timed out" in r.stderr
        for r in results
        if "ACQUIRED" not in r.stdout and "MUTEX-VIOLATED" not in r.stderr
    )


def test_timeout_refuses_to_steal_and_names_the_holder(repo: Path) -> None:
    """On timeout it must fail loudly with the holder's identity -- never break the lock."""
    lock_dir = (
        Path(
            subprocess.run(
                ["git", "-C", str(repo), "rev-parse", "--path-format=absolute", "--git-common-dir"],
                capture_output=True,
                text=True,
                check=True,
            ).stdout.strip()
        )
        / "mefor-coord"
        / "locks"
    )
    lock_dir.mkdir(parents=True, exist_ok=True)
    held = lock_dir / "t.lock"
    held.write_text("pid=999999 host=OTHERBOX at=2026-07-29T00:00:00.0000000Z", encoding="utf-8")

    proc = acquire(repo, timeout=1)
    assert "ACQUIRED" not in proc.stdout
    assert "Timed out" in proc.stderr
    assert "pid=999999" in proc.stderr  # names the holder
    assert "NOT stealing" in proc.stderr
    assert held.exists(), "the lock must survive a timeout -- stealing re-opens the race"


def test_distinct_names_do_not_block_each_other(repo: Path) -> None:
    """One mutex per operation: an unrelated lock must not serialize against this one."""
    lock_dir = (
        Path(
            subprocess.run(
                ["git", "-C", str(repo), "rev-parse", "--path-format=absolute", "--git-common-dir"],
                capture_output=True,
                text=True,
                check=True,
            ).stdout.strip()
        )
        / "mefor-coord"
        / "locks"
    )
    lock_dir.mkdir(parents=True, exist_ok=True)
    (lock_dir / "other.lock").write_text("pid=1", encoding="utf-8")

    proc = acquire(repo, name="t", timeout=2)
    assert "ACQUIRED" in proc.stdout, proc.stderr


def test_lock_is_shared_between_the_primary_and_its_worktrees(repo: Path, tmp_path: Path) -> None:
    """A lock only helps if every worktree resolves to the SAME file as the primary checkout.

    This is what makes it usable for `git worktree add`, whose damage is to the one shared .git.
    """
    wt = tmp_path / "wt"
    _git(repo, "worktree", "add", "-q", "-b", "wt-branch", str(wt))

    hold_script = (
        f". '{LOCK}'; $l = Enter-CoordLock -Name 'shared' -TimeoutSeconds 5 -Repo '{repo}'; "
        f"Write-Output 'ACQUIRED'; Start-Sleep -Milliseconds 2500; Exit-CoordLock $l"
    )
    holder = subprocess.Popen(  # take it from the primary and hold
        ["pwsh", "-NoProfile", "-NonInteractive", "-Command", hold_script],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        assert holder.stdout is not None
        assert "ACQUIRED" in holder.stdout.readline()  # only proceed once it truly holds the lock
        contender = acquire(wt, name="shared", timeout=1)  # from the WORKTREE
        assert "ACQUIRED" not in contender.stdout, "worktree resolved to a different lock file"
        assert "Timed out" in contender.stderr
    finally:
        holder.wait(timeout=60)
