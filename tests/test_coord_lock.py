# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
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
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from pathlib import Path

import pytest

from tests._spawn_lock import spawn_burst

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


def _pwsh(script: str, timeout: int = 120) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["pwsh", "-NoProfile", "-NonInteractive", "-Command", script],
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )


def _lock_file(repo: Path, name: str = "t") -> Path:
    common = subprocess.run(
        ["git", "-C", str(repo), "rev-parse", "--path-format=absolute", "--git-common-dir"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()
    lock_dir = Path(common) / "mefor-coord" / "locks"
    lock_dir.mkdir(parents=True, exist_ok=True)
    return lock_dir / f"{name}.lock"


def acquire(
    repo: Path,
    *,
    name: str = "t",
    timeout: int = 2,
    hold_ms: int = 0,
    barrier: Path | None = None,
    witness: Path | None = None,
    prove_owned: bool = False,
    attempted: Path | None = None,
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
    if attempted is not None:
        # Marks the first real create attempt, which the barrier alone cannot place.
        gate += (
            "$realOpen = ${function:Open-CoordLockFile}; "
            "function Open-CoordLockFile([string]$Path) { "
            f"[IO.File]::WriteAllText('{attempted}', ''); & $realOpen $Path }}; "
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
    if prove_owned:
        # A returned path is not proof: the lock file must name THIS process.
        enter += (
            'try { if ((Get-Content -LiteralPath $l -Raw -EA Stop) -match "pid=$PID ") '
            "{ Write-Output 'OWNED' } } catch { }; "
        )
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
    return _pwsh(script, timeout=180)


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

    # Eight concurrent pwsh, and the winner holds for 8 s -- the same shape as the storm BACKLOG #1304
    # is about, found by sweeping the tier rather than by CI evidence. Nothing about the claimants
    # changes; the lock only keeps single-launch tests off these vCPUs while they run.
    with (
        spawn_burst("coord_lock.mutex_under_load x8"),
        ThreadPoolExecutor(max_workers=8) as pool,
    ):
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
    held = _lock_file(repo)
    held.write_text("pid=999999 host=OTHERBOX at=2026-07-29T00:00:00.0000000Z", encoding="utf-8")

    proc = acquire(repo, timeout=1)
    assert "ACQUIRED" not in proc.stdout
    assert "Timed out" in proc.stderr
    assert "pid=999999" in proc.stderr  # names the holder
    assert "NOT stealing" in proc.stderr
    # Its content, not just its name: a holder's file replaced by this call would still exist.
    assert "pid=999999" in held.read_text(encoding="utf-8"), "stealing re-opens the race"


def test_distinct_names_do_not_block_each_other(repo: Path) -> None:
    """One mutex per operation: an unrelated lock must not serialize against this one."""
    _lock_file(repo, "other").write_text("pid=1", encoding="utf-8")

    proc = acquire(repo, name="t", timeout=2)
    assert "ACQUIRED" in proc.stdout, proc.stderr


# A real FileStream that creates the file, then fails where a full disk would. FileStream buffers, so
# the failure can arrive at Write or only at Dispose. The finalizer path must not throw.
_FAILING_STREAM = r"""
Add-Type -TypeDefinition @'
using System.IO;
public class B4FailingStream : FileStream {
    private readonly bool onWrite; private bool thrown;
    public B4FailingStream(string p, bool onWrite)
        : base(p, FileMode.CreateNew, FileAccess.Write, FileShare.None) { this.onWrite = onWrite; }
    public override void Write(byte[] b, int o, int c) {
        if (onWrite) throw new IOException("simulated disk full on write");
        base.Write(b, o, c);
    }
    protected override void Dispose(bool disposing) {
        base.Dispose(disposing);
        if (disposing && !onWrite && !thrown) { thrown = true; throw new IOException("simulated disk full on close"); }
    }
}
'@
"""


@pytest.mark.parametrize(
    ("on_write", "message"),
    [(True, "simulated disk full on write"), (False, "simulated disk full on close")],
)
def test_a_failed_holder_write_removes_only_its_own_file_and_does_not_wedge(
    repo: Path, on_write: bool, message: str
) -> None:
    """The failure must surface at once, and the file this call made must not block the next one."""
    flag = "$true" if on_write else "$false"
    script = (
        f". '{LOCK}'; {_FAILING_STREAM}\n"
        f"function Open-CoordLockFile([string]$Path) {{ [B4FailingStream]::new($Path, {flag}) }}\n"
        f"$l = Enter-CoordLock -Name 't' -TimeoutSeconds 2 -Repo '{repo}'; Write-Output 'ACQUIRED'"
    )
    proc = _pwsh(script)
    assert "ACQUIRED" not in proc.stdout, proc.stdout
    assert message in proc.stderr, proc.stderr
    assert "Timed out" not in proc.stderr, proc.stderr
    assert not _lock_file(repo).exists(), "the orphaned lock would wedge every later caller"
    following = acquire(repo)
    assert "ACQUIRED" in following.stdout, following.stderr


def test_an_unexpected_create_failure_throws_and_leaves_the_holders_file(repo: Path) -> None:
    """A method failure of another type must stop here, not fall through to the cleanup."""
    held = _lock_file(repo)
    held.write_text("pid=999999 host=OTHERBOX at=2026-07-29T00:00:00.0000000Z", encoding="utf-8")
    script = (
        f". '{LOCK}'\n"
        "function Open-CoordLockFile([string]$Path) { [System.IO.File]::Open('', 'CreateNew') }\n"
        f"$l = Enter-CoordLock -Name 't' -TimeoutSeconds 1 -Repo '{repo}'; Write-Output 'ACQUIRED'"
    )
    proc = _pwsh(script, timeout=60)
    assert "ACQUIRED" not in proc.stdout, proc.stdout
    assert "pid=999999" in held.read_text(encoding="utf-8")


# Puts a real lock file into the NTFS delete-pending state. An ordinary File.Delete does not on this
# OS, because it uses POSIX semantics and frees the name at once, so this sets the legacy disposition
# with a second handle open. Measured: CreateNew then raises UnauthorizedAccessException, not IOException.
_DELETE_PENDING_HOLDER = r"""
Add-Type -TypeDefinition @'
using System; using System.Runtime.InteropServices; using Microsoft.Win32.SafeHandles;
public static class B4Native {
  [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
  public static extern SafeFileHandle CreateFileW(string n, uint a, uint s, IntPtr sa, uint d, uint f, IntPtr t);
  [StructLayout(LayoutKind.Sequential)] public struct FDI { [MarshalAs(UnmanagedType.U1)] public bool DeleteFile; }
  [DllImport("kernel32.dll", SetLastError=true)]
  public static extern bool SetFileInformationByHandle(SafeFileHandle h, int c, ref FDI i, uint z);
}
'@
$r = [IO.File]::Open($env:B4_LOCK, 'Open', 'Read', [IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete)
$h = [B4Native]::CreateFileW($env:B4_LOCK, 0x00010000, 7, [IntPtr]::Zero, 3, 0, [IntPtr]::Zero)
$i = New-Object B4Native+FDI; $i.DeleteFile = $true
if (-not [B4Native]::SetFileInformationByHandle($h, 4, [ref]$i, 1)) { throw 'disposition not set' }
[Console]::Out.WriteLine('PENDING'); [Console]::Out.Flush()
$bound = (Get-Date).AddSeconds(90)
while (-not (Test-Path -LiteralPath $env:B4_RELEASE) -and (Get-Date) -lt $bound) { Start-Sleep -Milliseconds 20 }
$h.Dispose(); $r.Dispose()
"""


@contextmanager
def _delete_pending(lock: Path, release: Path) -> Iterator[None]:
    """Hold ``lock`` in delete-pending until ``release`` exists or the block ends."""
    lock.write_text("pid=1 host=DELETING at=2026-07-29T00:00:00.0000000Z", encoding="utf-8")
    holder = subprocess.Popen(
        ["pwsh", "-NoProfile", "-NonInteractive", "-Command", _DELETE_PENDING_HOLDER],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        env={**os.environ, "B4_LOCK": str(lock), "B4_RELEASE": str(release)},
    )
    try:
        assert holder.stdout is not None
        assert "PENDING" in holder.stdout.readline()
        yield
    finally:
        release.write_text("", encoding="utf-8")
        try:
            holder.wait(timeout=60)
        except subprocess.TimeoutExpired:
            holder.kill()
            holder.wait(timeout=10)
        if holder.stdout is not None:
            holder.stdout.close()


def test_a_delete_pending_lock_is_waited_out(repo: Path, tmp_path: Path) -> None:
    """The name clears when the last handle closes, so this is a wait and not a failure.

    The name is released only after the claimant has really attempted the create, so the attempt
    is inside the pending window however long its start-up took.
    """
    barrier = tmp_path / "barrier"
    barrier.mkdir()
    release = tmp_path / "release"
    attempted = tmp_path / "attempted"
    with _delete_pending(_lock_file(repo), release), ThreadPoolExecutor(max_workers=1) as pool:
        claim = pool.submit(
            acquire, repo, timeout=30, barrier=barrier, prove_owned=True, attempted=attempted
        )
        deadline = time.monotonic() + 90
        while not list(barrier.glob("ready-*")):
            assert time.monotonic() < deadline, "the claimant never reached the barrier"
            time.sleep(0.02)
        (barrier / "go").write_text("", encoding="utf-8")
        while not attempted.exists():
            assert time.monotonic() < deadline, "the claimant never attempted the create"
            time.sleep(0.02)
        release.write_text("", encoding="utf-8")
        proc = claim.result()
    assert "OWNED" in proc.stdout, f"returned without holding the lock: {proc.stdout}{proc.stderr}"


def test_a_delete_pending_lock_that_outlasts_the_wait_names_no_false_holder(
    repo: Path, tmp_path: Path
) -> None:
    """The file's text belongs to a deleted lock, so printing it as the holder would be false."""
    release = tmp_path / "release"
    with _delete_pending(_lock_file(repo), release):
        proc = acquire(repo, timeout=1)
    assert "ACQUIRED" not in proc.stdout
    assert "access denied" in proc.stderr.lower(), proc.stderr
    assert "held by" not in proc.stderr, proc.stderr


def test_a_genuine_denial_fails_at_once_and_names_no_holder(repo: Path) -> None:
    """A directory at the lock path raises the same exception as delete-pending and never clears."""
    _lock_file(repo).mkdir()
    started = time.monotonic()
    proc = acquire(repo, timeout=45)
    elapsed = time.monotonic() - started
    assert "ACQUIRED" not in proc.stdout
    assert "access" in proc.stderr.lower(), proc.stderr
    assert "held by" not in proc.stderr, proc.stderr
    assert "Timed out" not in proc.stderr, proc.stderr
    assert elapsed < 30, f"spun for {elapsed:.1f}s on a denial that cannot clear"


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
