# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The in-use refusals ``scripts/worktree/remove.ps1`` makes on BOTH removal routes.

Vault BACKLOG #2988: ``-Name`` had neither the claim refusal nor the quiet-period refusal that
``-Path`` gained in engine PR 2014, so a session could remove a sibling a Builder was still working
in, and the claim sweep then released its claim with no ``.history`` line. Vault BACKLOG #2985
lists the known defects of the ``-Path`` route; the ones driven here are part B item 1 (a worker
whose claim names its PARENT tree), part B item 3 (``mefor.claimsRoot``), items 8, 11, 14 and 16.

Same rules as ``tests/test_worktree_remove_path.py``, whose rig this reuses: the real script runs
against a synthetic repository under ``tmp_path``, each refusal is paired with the run that is
supposed to succeed, and the session registry is a throwaway home.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

import pytest

from tests.test_worktree_remove_path import (
    _ENV,
    SCRIPT,
    Rig,
    _claim,
    _commit,
    _common,
    _git,
    _out,
    build_rig,
    pytestmark,  # noqa: F401  (the same Windows-and-pwsh skip)
    settle_worktrees,
)

#: Each route is driven against a SIBLING, which both can reach: ``-Name`` by its directory name,
#: ``-Path`` by its full path.
ROUTES = ("-Name", "-Path")


@pytest.fixture
def rig(tmp_path: Path) -> Rig:
    return build_rig(tmp_path)


def _sibling(rig: Rig, name: str) -> Path:
    return rig.add(rig.primary.parent / f"Repo-{name}")


def _target(route: str, wt: Path) -> list[str]:
    return [route, wt.name.removeprefix("Repo-") if route == "-Name" else str(wt)]


#: Whether the deny bound, asked of .NET directly, and NOT of the script's helper: a helper that
#: swallowed access-denied would otherwise answer "listed" and turn its own regression into a skip.
#: The call is the one the helper makes. Only an UnauthorizedAccessException counts as bound (exit 3);
#: any other throw is exit 5, so an unrelated error cannot pass for ACL coverage. What the script's
#: helper did with the directory is in the script's own output, which a failure prints.
#:
#: It runs as a -File script, the way the rig runs remove.ps1. Under -Command, pwsh appends the
#: arguments to the command text and leaves $args empty: the first version of this probe was such a
#: one-liner, threw on every directory, never skipped, and so the ACL tests failed on a runner where
#: the deny does not bind (engine PR 2371, the run on head 2d369bff). whoami is named by its full
#: path, because under the CI leg's Git Bash a bare one resolves to MSYS's, which has no /priv.
_PROBE = r"""
param([string]$Dir)
$ErrorActionPreference = 'Stop'
$opts = [System.IO.EnumerationOptions]::new()
$opts.IgnoreInaccessible = $false
$opts.AttributesToSkip = [System.IO.FileAttributes]0
$code = 0
try {
    foreach ($e in [System.IO.DirectoryInfo]::new($Dir).EnumerateFileSystemInfos('*', $opts)) {}
    Write-Output "PROBE: .NET listed '$Dir'"
} catch {
    $x = $_.Exception
    while ($x -and $x -isnot [System.UnauthorizedAccessException]) { $x = $x.InnerException }
    if ($x) { $code = 3; Write-Output "PROBE: .NET was denied '$Dir': $($x.Message)" }
    else { $code = 5; Write-Output "PROBE: .NET failed on '$Dir', not denied: $($_.Exception.GetType().FullName): $($_.Exception.Message)" }
}
Write-Output "PROBE: whoami /priv of this pwsh:"
try { & (Join-Path $env:SystemRoot 'System32\whoami.exe') /priv | Out-String | Write-Output }
catch { Write-Output "PROBE: whoami /priv failed: $($_.Exception.Message)" }
exit $code
"""


def _run_probe(root: Path, directory: Path) -> subprocess.CompletedProcess[str]:
    """The probe, run as the rig runs remove.ps1: a pwsh -File child, from root, with the rig's env."""
    probe_file = root / "probe-listing.ps1"
    probe_file.write_text(_PROBE, encoding="utf-8")
    return subprocess.run(
        ["pwsh", "-NoProfile", "-NonInteractive", "-File", str(probe_file), str(directory)],
        cwd=str(root),
        capture_output=True,
        # pwsh writes in the console's code page. The probe must not change that page: it is shared
        # with the caller's terminal and outlives the probe. What it prints is ASCII in practice,
        # so a page that is not UTF-8 costs at most a replaced character, never a decode error.
        encoding="utf-8",
        errors="replace",
        check=False,
        timeout=120,
        env={**_ENV, "USERPROFILE": str(root / "home")},
    )


def _explain(
    directory: Path, probe: subprocess.CompletedProcess[str], proc: subprocess.CompletedProcess[str]
) -> str:
    return (
        f"denied directory: {directory}\nprobe exit {probe.returncode}:\n{_out(probe)}\n"
        f"script exit {proc.returncode}, stdout and stderr:\n{_out(proc)}"
    )


#: The privileges that let a process read past a deny ACE. .NET opens a directory with
#: FILE_FLAG_BACKUP_SEMANTICS, which honours SeBackupPrivilege when it is ENABLED in the token.
_BYPASS_PRIVILEGES = ("SeBackupPrivilege", "SeRestorePrivilege")


@contextmanager
def _privileges_disabled(names: tuple[str, ...] = _BYPASS_PRIVILEGES) -> Iterator[int]:
    """Disable ``names`` in this process's token while the block runs, then put back what was on.
    Child processes copy the token as it stands, so pwsh and remove.ps1 started inside see them off.
    Yields how many were on. A privilege the token does not hold is left alone.

    Why: the CI leg runs pytest under Git Bash, and the MSYS runtime is believed to ENABLE backup and
    restore privileges at start when the token holds them, as an elevated runneradmin's does. Not
    measured on the runner; the probe's whoami /priv is how a skip there reports it.
    """
    if sys.platform != "win32":
        yield 0
        return
    import ctypes
    from ctypes import wintypes

    class Luid(ctypes.Structure):
        _fields_ = [("LowPart", wintypes.DWORD), ("HighPart", wintypes.LONG)]

    class LuidAndAttributes(ctypes.Structure):
        _fields_ = [("Luid", Luid), ("Attributes", wintypes.DWORD)]

    class TokenPrivileges(ctypes.Structure):
        _fields_ = [
            ("PrivilegeCount", wintypes.DWORD),
            ("Privileges", LuidAndAttributes * len(names)),
        ]

    advapi = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.GetCurrentProcess.restype = wintypes.HANDLE
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    advapi.OpenProcessToken.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.HANDLE),
    ]
    advapi.LookupPrivilegeValueW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.LPCWSTR,
        ctypes.POINTER(Luid),
    ]
    advapi.AdjustTokenPrivileges.argtypes = [
        wintypes.HANDLE,
        wintypes.BOOL,
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.c_void_p,
        ctypes.POINTER(wintypes.DWORD),
    ]
    token = wintypes.HANDLE()
    # TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY
    if not advapi.OpenProcessToken(
        kernel.GetCurrentProcess(), 0x0020 | 0x0008, ctypes.byref(token)
    ):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        off = TokenPrivileges(len(names))
        for i, name in enumerate(names):
            if not advapi.LookupPrivilegeValueW(None, name, ctypes.byref(off.Privileges[i].Luid)):
                raise ctypes.WinError(ctypes.get_last_error())
            off.Privileges[i].Attributes = 0
        was = TokenPrivileges()
        size = wintypes.DWORD()
        if not advapi.AdjustTokenPrivileges(
            token,
            False,
            ctypes.byref(off),
            ctypes.sizeof(was),
            ctypes.byref(was),
            ctypes.byref(size),
        ):
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            # PreviousState lists only the privileges this call changed, so these were enabled.
            yield int(was.PrivilegeCount)
        finally:
            if was.PrivilegeCount and not advapi.AdjustTokenPrivileges(
                token, False, ctypes.byref(was), 0, None, None
            ):
                raise ctypes.WinError(ctypes.get_last_error())
    finally:
        kernel.CloseHandle(token)


@contextmanager
def _denied_listing(rig: Rig, directory: Path) -> Iterator[subprocess.CompletedProcess[str]]:
    """Deny this user the right to list ``directory``, with the bypass privileges off, and give both
    back afterwards. Run the script inside the block.

    The deny must take effect, or the test proves nothing. On the hosted windows-2025 runner the
    script went on listing the directory after this deny, as runneradmin (engine PR 2371, run
    39005284295). Turning the bypass privileges off is the fix for the cause believed above. If the
    deny still does not bind, the test skips and the skip prints the probe's privileges. A skip
    leaves the access-denied branch undriven on that runner: the planted-file test drives a different
    exception, and the static pin reads two strings.
    """
    who = subprocess.run(
        ["whoami"], capture_output=True, text=True, check=False, timeout=30
    ).stdout.strip()
    made = subprocess.run(
        ["icacls", str(directory), "/deny", f"{who}:(RD)"],
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )
    if not who or made.returncode != 0:
        pytest.skip(f"could not deny access with icacls: {made.stdout} {made.stderr}")
    try:
        with _privileges_disabled() as were_on:
            probe = _run_probe(rig.root, directory)
            if probe.returncode == 0:
                pytest.skip(
                    f"{who} can still list {directory} after the deny, with {were_on} bypass "
                    f"privilege(s) turned off.\n{_out(probe)}"
                )
            assert probe.returncode == 3, f"the probe did not see a denial:\n{_out(probe)}"
            yield probe
    finally:
        subprocess.run(
            ["icacls", str(directory), "/remove:d", who],
            capture_output=True,
            check=False,
            timeout=30,
        )


# --- vault BACKLOG #2988: -Name has the claim and quiet-period refusals ------------------------------


@pytest.mark.parametrize("route", ROUTES)
def test_a_claimed_tree_is_refused_on_both_routes_and_force_does_not_override(
    rig: Rig, route: str
) -> None:
    """Red before the fix on -Name: the tree went with exit 0 and the sweep deleted the claim file,
    leaving no line in the claims .history file. Now the claim refuses and is left exactly as it was,
    so its release goes through claim.ps1, which records it."""
    wt = _sibling(rig, "held")
    (wt / "untracked-work.txt").write_text("not committed\n", encoding="utf-8")
    claim = _claim(rig, "9201", wt)
    before = claim.read_bytes()

    proc = rig.run(*_target(route, wt), "-Force")

    assert proc.returncode != 0
    assert "still holds 1 work claim(s): 9201" in _out(proc), _out(proc)
    assert wt.exists() and rig.is_registered(wt)
    assert (wt / "untracked-work.txt").is_file()
    assert claim.read_bytes() == before, "the refusal touched the claim it refused on"

    # Control: with the claim released, the same route removes the tree.
    claim.unlink()
    proc = rig.run(*_target(route, wt), "-Force")
    assert proc.returncode == 0, _out(proc)
    assert not wt.exists()


@pytest.mark.parametrize("route", ROUTES)
def test_a_tree_git_wrote_to_recently_is_refused_on_both_routes(rig: Rig, route: str) -> None:
    wt = _sibling(rig, "warm")
    _commit(wt, "just-now.txt")

    proc = rig.run(*_target(route, wt), "-Force", settle=False)

    assert proc.returncode != 0
    assert "Target was active recently" in _out(proc), _out(proc)
    assert "git last wrote to" in _out(proc), _out(proc)
    assert wt.exists() and rig.is_registered(wt)

    proc = rig.run(*_target(route, wt))
    assert proc.returncode == 0, _out(proc)
    assert not wt.exists()


def test_name_does_not_clear_a_sibling_a_live_session_in_a_parent_tree_is_working_in(
    rig: Rig,
) -> None:
    """The case engine PR 2014 staged for -Path, on the -Name route (vault BACKLOG #2988, closing
    step 3). A LIVE session, with a real process, is recorded in a parent tree under
    .claude/worktrees and works in a sibling. -Name reads no session registry at all, so what
    refuses is the claim, then the fresh git state. Only when both are gone does the tree go."""
    parent = rig.add(rig.primary / ".claude" / "worktrees" / "parent")
    sibling = _sibling(rig, "b288")
    _commit(sibling, "built.txt")
    (sibling / "scratch-notes.txt").write_text("untracked work in progress\n", encoding="utf-8")
    claim = _claim(rig, "9288", sibling)

    # The base interpreter, for the reason the -Path twin of this test gives.
    interpreter = getattr(sys, "_base_executable", None) or sys.executable
    session = subprocess.Popen(
        [interpreter, "-c", "import time; time.sleep(300)"], cwd=str(rig.root)
    )
    try:
        (rig.home / ".claude" / "sessions" / f"{session.pid}.json").write_text(
            json.dumps(
                {
                    "cwd": str(parent),
                    "pid": session.pid,
                    "sessionId": "live-in-parent",
                    "startedAt": int(time.time() * 1000),
                }
            ),
            encoding="utf-8",
        )

        proc = rig.run("-Name", "b288", "-Force", settle=False)
        assert proc.returncode != 0
        assert "still holds 1 work claim(s): 9288" in _out(proc), _out(proc)
        assert claim.exists(), "the refusal released the claim"

        claim.unlink()
        proc = rig.run("-Name", "b288", "-Force", settle=False)
        assert proc.returncode != 0
        assert "Target was active recently" in _out(proc), _out(proc)
        assert (sibling / "scratch-notes.txt").is_file()
        assert sibling.exists() and rig.is_registered(sibling)

        proc = rig.run("-Name", "b288", "-Force")
        assert proc.returncode == 0, _out(proc)
        assert not sibling.exists()
        assert parent.exists()
    finally:
        session.kill()
        session.wait(timeout=30)


def test_name_refuses_a_target_holding_a_registered_worktree(rig: Rig) -> None:
    """A session launched in a sibling puts its subagents' trees under the sibling's own
    .claude/worktrees, where their claims name THEM and not the sibling. Removing the sibling would
    delete those trees and leave them registered. -Path refused this; now -Name does too."""
    wt = _sibling(rig, "host")
    inner = rig.add(wt / ".claude" / "worktrees" / "agent-x")

    proc = rig.run("-Name", "host", "-Force")
    assert proc.returncode != 0
    assert "contains 1 other registered worktree" in _out(proc), _out(proc)
    assert inner.exists() and rig.is_registered(inner)

    _git(rig.primary, "worktree", "remove", "--force", str(inner))
    proc = rig.run("-Name", "host", "-Force")
    assert proc.returncode == 0, _out(proc)
    assert not wt.exists()


# --- vault BACKLOG #2985, part B item 1: a claim that names the PARENT tree ----------------------------


@pytest.mark.parametrize("route", ROUTES)
def test_a_reused_quiet_tree_a_worker_just_ran_tests_in_is_refused(rig: Rig, route: str) -> None:
    """The residue the Lander's review named. A tree two days quiet and clean, whose worker's claim
    names the PARENT tree, was removed with exit 0 while the worker only read files and ran tests:
    no commit, checkout or fetch, so no git state moved. A test run rewrites .pytest_cache, and
    that is what refuses now. Red before the fix on both routes.

    The cache is an OLD one rewritten in place, as a second run leaves it: that moves neither the
    root's write time nor the cache directory's, so only the walk inside the cache can see it. A run
    still in progress has written nothing yet, and this does not claim to see one."""
    parent = rig.add(rig.primary / ".claude" / "worktrees" / "parent")
    wt = _sibling(rig, "reused")
    _claim(rig, "9301", parent)
    nodeids = wt / ".pytest_cache" / "v" / "cache" / "nodeids"
    nodeids.parent.mkdir(parents=True)
    nodeids.write_text("[]\n", encoding="utf-8")
    settle_worktrees(rig.primary)
    # What the worker's test run leaves behind, and nothing else.
    nodeids.write_text('["tests/test_x.py::test_y"]\n', encoding="utf-8")

    proc = rig.run(*_target(route, wt), "-Force", settle=False)

    assert proc.returncode != 0
    assert "Target was active recently" in _out(proc), _out(proc)
    assert "working tree" in _out(proc), _out(proc)
    assert wt.exists() and rig.is_registered(wt)

    # Control: the same tree once the cache is as old as the rest.
    proc = rig.run(*_target(route, wt))
    assert proc.returncode == 0, _out(proc)
    assert not wt.exists()


def test_a_cache_too_big_to_date_refuses(rig: Rig) -> None:
    """A cannot-tell of the working-tree signal: past the cap the cache is not sampled."""
    wt = _sibling(rig, "bigcache")
    cache = wt / ".ruff_cache"
    cache.mkdir()
    for i in range(5001):
        (cache / f"{i}").write_bytes(b"")

    # Not settled: the cap refuses before any write time is read, and dating 5001 files is slow.
    proc = rig.run("-Path", str(wt), "-Force", settle=False)

    assert proc.returncode != 0
    assert "more than 5000 entries" in _out(proc), _out(proc)
    assert wt.exists()


# --- vault BACKLOG #2985, part B item 3: mefor.claimsRoot ---------------------------------------------


@pytest.mark.parametrize("route", ROUTES)
def test_a_claim_in_the_registry_mefor_claims_root_names_refuses(rig: Rig, route: str) -> None:
    """claim.ps1 writes to the repository mefor.claimsRoot names. Red before the fix: this script
    read only the clone's own registry, which is empty here, and removed the tree."""
    wt = _sibling(rig, "shared")
    registry = rig.root / "Registry"
    registry.mkdir()
    _git(registry, "init", "-q", "-b", "main")
    claims = registry / ".git" / "mefor-coord" / "claims"
    claims.mkdir(parents=True)
    held = claims / "9401.json"
    held.write_text(
        json.dumps({"key": "9401", "worktree": str(wt).replace("\\", "/"), "note": "t"}),
        encoding="utf-8",
    )
    _git(rig.primary, "config", "mefor.claimsRoot", str(registry))

    proc = rig.run(*_target(route, wt), "-Force")
    assert proc.returncode != 0
    assert "still holds 1 work claim(s): 9401" in _out(proc), _out(proc)
    assert wt.exists()

    held.unlink()
    proc = rig.run(*_target(route, wt))
    assert proc.returncode == 0, _out(proc)
    assert not wt.exists()


def test_the_clones_own_registry_is_still_read_when_mefor_claims_root_is_set(rig: Rig) -> None:
    """A claim taken before the setting was made, or by an older claim.ps1, sits in the clone's own
    registry. Reading only the one the setting names would miss it."""
    wt = _sibling(rig, "both")
    registry = rig.root / "Registry"
    registry.mkdir()
    _git(registry, "init", "-q", "-b", "main")
    _git(rig.primary, "config", "mefor.claimsRoot", str(registry))
    claim = _claim(rig, "9402", wt)

    proc = rig.run("-Name", "both", "-Force")
    assert proc.returncode != 0
    assert "still holds 1 work claim(s): 9402" in _out(proc), _out(proc)

    claim.unlink()
    proc = rig.run("-Name", "both")
    assert proc.returncode == 0, _out(proc)
    assert not wt.exists()


@pytest.mark.parametrize(
    ("setting", "needle"),
    [("not-a-repo", "is not a git repository"), ("Registry", "relative path")],
    ids=["not-a-repository", "relative"],
)
def test_a_claims_root_that_cannot_be_followed_refuses(rig: Rig, setting: str, needle: str) -> None:
    wt = _sibling(rig, "lost")
    if setting == "not-a-repo":
        (rig.root / setting).mkdir()
        setting = str(rig.root / setting)
    _git(rig.primary, "config", "mefor.claimsRoot", setting)

    # A home directory under git would otherwise make the plain directory resolve to that repository.
    ceiling = {"GIT_CEILING_DIRECTORIES": str(rig.root)}
    proc = rig.run("-Path", str(wt), "-Force", extra=ceiling)
    assert proc.returncode != 0
    assert needle in _out(proc), _out(proc)
    assert wt.exists()

    _git(rig.primary, "config", "--unset", "mefor.claimsRoot")
    assert rig.run("-Path", str(wt)).returncode == 0
    assert not wt.exists()


# --- vault BACKLOG #2985, items 14, 15 and 16: claim files nothing can match -----------------------------


@pytest.mark.parametrize(
    ("body", "needle"),
    [
        # Item 16. Two records, the second naming the target: the old read joined both worktrees
        # into one string, matched neither, and let the tree go.
        ("ARRAY", "is not one JSON object"),
        # Item 16. A blank holder could not be matched and was not refused either.
        ('{"key": "9502", "worktree": "   "}', "names no worktree"),
    ],
    ids=["json-array", "blank-worktree"],
)
def test_a_claim_file_of_a_shape_claim_ps1_never_writes_refuses(
    rig: Rig, body: str, needle: str
) -> None:
    wt = _sibling(rig, "odd")
    claims = _common(rig) / "mefor-coord" / "claims"
    claims.mkdir(parents=True)
    odd = claims / "9502.json"
    if body == "ARRAY":
        body = json.dumps(
            [
                {"key": "9502", "worktree": "C:/somewhere/else"},
                {"key": "9502", "worktree": str(wt).replace("\\", "/")},
            ]
        )
    odd.write_text(body, encoding="utf-8")

    for route in ROUTES:
        proc = rig.run(*_target(route, wt), "-Force")
        assert proc.returncode != 0, route
        assert f"9502.json {needle}" in _out(proc), (route, _out(proc))
        assert wt.exists()

    odd.unlink()
    assert rig.run("-Path", str(wt)).returncode == 0
    assert not wt.exists()


@pytest.mark.parametrize("route", ROUTES)
def test_a_claims_directory_that_cannot_be_listed_refuses(rig: Rig, route: str) -> None:
    """Item 14's cannot-tell, and item 15: access-denied must not read as "no claims"."""
    wt = _sibling(rig, "locked")
    claims = _common(rig) / "mefor-coord" / "claims"
    claims.mkdir(parents=True)

    with _denied_listing(rig, claims) as probe:
        proc = rig.run(*_target(route, wt), "-Force")
    assert proc.returncode != 0, _explain(claims, probe, proc)
    assert "claims are unknown" in _out(proc), _explain(claims, probe, proc)
    assert wt.exists()

    proc = rig.run(*_target(route, wt))
    assert proc.returncode == 0, _out(proc)
    assert not wt.exists()


@pytest.mark.parametrize("route", ROUTES)
@pytest.mark.parametrize("registry", ["claims", "alloc"])
def test_a_registry_path_whose_listing_throws_refuses(rig: Rig, route: str, registry: str) -> None:
    """The guard the two ACL tests in this file lean on when a runner cannot be denied: a FILE where
    the claims or allocation directory belongs. The script sees something there, and listing it
    throws. Red before the fix: Get-ChildItem listed the file as no records, and the tree went.

    It throws at the top of the walk only. A throw from a directory deeper in the allocation walk is
    driven by the ACL test alone, so on a runner where that test skips, it is not driven."""
    wt = _sibling(rig, "planted")
    planted = _common(rig) / "mefor-coord" / registry
    planted.parent.mkdir(parents=True, exist_ok=True)
    planted.write_text("not a directory\n", encoding="utf-8")

    proc = rig.run(*_target(route, wt), "-Force")
    assert proc.returncode != 0, _out(proc)
    noun = "claims" if registry == "claims" else "allocations"
    # The listing's own words, so a different cannot-tell refusal firing first cannot pass this.
    assert f"Could not list {noun} under" in _out(proc), _out(proc)
    assert wt.exists() and rig.is_registered(wt)

    planted.unlink()
    proc = rig.run(*_target(route, wt))
    assert proc.returncode == 0, _out(proc)
    assert not wt.exists()


def test_the_listing_probe_tells_listed_from_failed_for_another_reason(tmp_path: Path) -> None:
    """A control for the probe the ACL tests skip on, run on every runner. The denied answer (exit 3)
    needs a deny that binds, so only the ACL tests drive it."""
    listable = tmp_path / "listable"
    listable.mkdir()
    (listable / "one.txt").write_text("x\n", encoding="utf-8")
    planted = tmp_path / "planted"
    planted.write_text("not a directory\n", encoding="utf-8")

    ok = _run_probe(tmp_path, listable)
    assert ok.returncode == 0, _out(ok)
    assert f".NET listed '{listable}'" in _out(ok), _out(ok)
    # A privilege name, which whoami does not localize: proof the Windows whoami ran, not MSYS's.
    assert "SeChangeNotifyPrivilege" in _out(ok), _out(ok)
    bad = _run_probe(tmp_path, planted)
    assert bad.returncode == 5, _out(bad)
    assert "not denied: System.IO.IOException" in _out(bad), _out(bad)


def test_turning_a_privilege_off_reaches_a_child_process() -> None:
    """What the ACL tests rely on to make the deny bind under an elevated token: a privilege turned
    off in this process is off in a child started afterwards, and is back on once the block ends.
    Driven with SeChangeNotifyPrivilege, which every token holds enabled."""
    whoami = [str(Path(os.environ["SYSTEMROOT"], "System32", "whoami.exe")), "/priv"]

    def state() -> str:
        out = subprocess.run(whoami, capture_output=True, text=True, check=True, timeout=30).stdout
        return next(line for line in out.splitlines() if line.startswith("SeChangeNotifyPrivilege"))

    assert state().rstrip().endswith("Enabled"), state()
    with _privileges_disabled(("SeChangeNotifyPrivilege",)) as were_on:
        assert were_on == 1
        assert state().rstrip().endswith("Disabled"), state()
    assert state().rstrip().endswith("Enabled"), state()


def test_the_listing_helper_does_not_skip_what_it_may_not_read() -> None:
    """.NET's EnumerationOptions defaults IgnoreInaccessible to TRUE, and then an unlistable directory
    lists as empty, which is the fail-open these refusals exist to stop. The ACL tests drive this
    only where a deny binds, so the setting is pinned here as well, on every runner."""
    text = SCRIPT.read_text(encoding="utf-8")
    body = text[text.index("function Get-EntriesOrThrow") :]
    body = body[: body.index("\n}\n")]
    assert "$opts.IgnoreInaccessible = $false" in body, body
    assert "EnumerateFileSystemInfos('*', $opts)" in body, body


# --- vault BACKLOG #2985, item 11: the allocation guard's fail-closed branches --------------------------


@pytest.mark.parametrize("route", ROUTES)
def test_an_allocation_directory_that_cannot_be_listed_refuses(rig: Rig, route: str) -> None:
    """Red before the fix on -Name, which swallowed the listing error and read it as "no records"."""
    wt = _sibling(rig, "allocs")
    hidden = _common(rig) / "mefor-coord" / "alloc" / "backlog"
    hidden.mkdir(parents=True)

    with _denied_listing(rig, hidden) as probe:
        proc = rig.run(*_target(route, wt), "-Force")
    assert proc.returncode != 0, _explain(hidden, probe, proc)
    assert "allocations are unknown" in _out(proc), _explain(hidden, probe, proc)
    assert wt.exists()

    proc = rig.run(*_target(route, wt))
    assert proc.returncode == 0, _out(proc)
    assert not wt.exists()


@pytest.mark.parametrize(
    "body",
    ["{ half-written", "ARRAY", '{"number": "9601", "kind": "backlog", "worktree": ""}'],
    ids=["unparseable", "json-array", "blank-worktree"],
)
def test_an_allocation_record_nothing_can_match_refuses_path_too(rig: Rig, body: str) -> None:
    """An allocation cannot be re-keyed, so a record that might name this tree refuses. Red before
    the fix for the two records that parse: the old read skipped them and burned the number."""
    wt = _sibling(rig, "garbled")
    alloc = _common(rig) / "mefor-coord" / "alloc" / "backlog"
    alloc.mkdir(parents=True)
    bad = alloc / "9601.json"
    if body == "ARRAY":
        body = json.dumps(
            [
                {"number": "9601", "kind": "backlog", "worktree": "C:/somewhere/else"},
                {"number": "9601", "kind": "backlog", "worktree": str(wt).replace("\\", "/")},
            ]
        )
    bad.write_text(body, encoding="utf-8")

    proc = rig.run("-Path", str(wt), "-Force")
    assert proc.returncode != 0
    assert "9601.json" in _out(proc), _out(proc)
    assert wt.exists()

    assert rig.run("-Path", str(wt), "-AllowOrphanedAllocations").returncode == 0
    assert not wt.exists()


# --- vault BACKLOG #2985, item 8: a directory left behind is not a clean removal ----------------------


def test_a_directory_git_leaves_behind_is_reported_and_exits_non_zero(rig: Rig) -> None:
    """A junction inside a tolerated cache directory: git drops the registration, exits 0 and leaves
    the directory (measured on git 2.55.0.windows.5). Red before the fix: the run said "Removed".
    Whatever git does, the content outside the tree must survive."""
    wt = _sibling(rig, "leaves")
    outside = rig.root / "shared-packages"
    outside.mkdir()
    precious = outside / "precious.txt"
    precious.write_text("lives outside every worktree\n", encoding="utf-8")
    (wt / "node_modules").mkdir()
    made = subprocess.run(
        ["cmd", "/c", "mklink", "/J", str(wt / "node_modules" / "pkg"), str(outside)],
        capture_output=True,
        text=True,
        check=False,
    )
    if made.returncode != 0:
        pytest.skip(f"could not create a junction: {made.stderr or made.stdout}")

    proc = rig.run("-Path", str(wt))

    assert precious.read_text(encoding="utf-8") == "lives outside every worktree\n"
    if not wt.exists():
        pytest.skip("this git deleted the whole tree, so there is no leftover to report")
    assert proc.returncode != 0, _out(proc)
    assert "the directory is still there" in _out(proc), _out(proc)
    assert "Removed worktree" not in _out(proc), _out(proc)
