# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Tests for the cross-session operation mutex (``scripts/coord/lock.ps1``).

``git worktree add -b <name> <base>`` writes ``.git/config``, so two sessions creating worktrees at
once race ``.git/config.lock`` -- reproduced on Windows as "could not lock config file", leaving
orphaned branches behind. ``new.ps1`` now serializes that call through this lock.

The load-bearing test is ``test_only_one_of_eight_concurrent_claimants_wins``: it launches eight real
processes at once and asserts exactly one acquires. Anything less than genuine concurrency would pass
against a lock that does not lock at all -- which is the failure mode this file exists to exclude.
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
) -> subprocess.CompletedProcess[str]:
    """Take the lock, optionally hold it, release. Prints ACQUIRED on success.

    ``barrier`` makes concurrency REAL rather than assumed. Without it a claimant races for the lock
    the moment *its own* ``pwsh`` has booted, and cold-start times vary by far more than any
    reasonable hold: a straggler that arrives after the winner has already released then wins
    legitimately, and the caller sees two winners against a lock that never misbehaved. With it, the
    claimant signals readiness *after* start-up and waits for the go file, so the whole cohort
    arrives within milliseconds of each other however long any individual process took to start.
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
    script = (
        f". '{LOCK}'; "
        f"{gate}"
        f"$l = Enter-CoordLock -Name '{name}' -TimeoutSeconds {timeout} -Repo '{repo}'; "
        f"Write-Output 'ACQUIRED'; "
        f"Start-Sleep -Milliseconds {hold_ms}; "
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


def test_only_one_of_eight_concurrent_claimants_wins(repo: Path, tmp_path: Path) -> None:
    """Eight real processes, one lock, all reaching for it at the same instant.

    The barrier is load-bearing, not ceremony. ``ThreadPoolExecutor`` only starts the eight processes
    together; it says nothing about when each one, after ``pwsh`` start-up, actually reaches
    ``Enter-CoordLock``. On an idle machine that spread is tens of milliseconds and the test looks
    fine; on a loaded CI runner cold-starting eight shells it can exceed the 1500 ms hold, and then a
    straggler finds the lock already released and wins on its own merits. The result is two winners
    and an accusation against a mutex that did nothing wrong — measured, not theorised: delaying one
    claimant by 1.9 s reproduces exactly that against the unmodified lock.

    Releasing the cohort only once all eight are parked on the gate also makes the file's headline
    claim true rather than hopeful: the overlap is now guaranteed, so a lock that did not lock could
    not pass this by getting lucky with scheduling.
    """
    barrier = tmp_path / "barrier"
    barrier.mkdir()

    with ThreadPoolExecutor(max_workers=8) as pool:
        claims = [
            pool.submit(acquire, repo, timeout=1, hold_ms=1500, barrier=barrier) for _ in range(8)
        ]
        deadline = time.monotonic() + 120
        while len(list(barrier.glob("ready-*"))) < 8:
            assert time.monotonic() < deadline, (
                f"only {len(list(barrier.glob('ready-*')))} of 8 claimants reached the barrier"
            )
            time.sleep(0.02)
        (barrier / "go").write_text("", encoding="utf-8")
        results = [c.result() for c in claims]

    winners = [r for r in results if "ACQUIRED" in r.stdout]
    assert len(winners) == 1, f"expected exactly 1 winner, got {len(winners)}"
    # Everyone else must FAIL, not silently proceed. Silent success is the bug.
    assert all("Timed out" in r.stderr for r in results if "ACQUIRED" not in r.stdout)


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
