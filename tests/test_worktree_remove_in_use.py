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
import subprocess
import sys
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

import pytest

from tests.test_worktree_remove_path import (
    _REPO,
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


#: The question the script asks of a directory, in the script's own words: a .NET walk that throws on
#: an entry it may not read. Run in pwsh, as the script is, so the probe and the script cannot disagree.
_PROBE = (
    "$o = [System.IO.EnumerationOptions]::new(); $o.IgnoreInaccessible = $false; "
    "try { foreach ($e in [System.IO.DirectoryInfo]::new($args[0]).EnumerateFileSystemInfos('*', $o)) {} "
    "exit 0 } catch { exit 3 }"
)


@contextmanager
def _denied_listing(directory: Path) -> Iterator[None]:
    """Deny this user the right to list ``directory``, and give it back afterwards.

    The deny must take effect, or the test proves nothing. On the hosted windows-2025 runner the
    account runneradmin could still list the directory after this deny (engine PR 2371, run
    39005284295). Why was not measured. So the listing is probed with the script's own call, and
    the test skips when it still works. A skip cannot hide a regression on its own: the planted-file
    test fails the listing on every runner, and a static test pins IgnoreInaccessible.
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
        probe = subprocess.run(
            ["pwsh", "-NoProfile", "-NonInteractive", "-Command", _PROBE, str(directory)],
            capture_output=True,
            text=True,
            check=False,
            timeout=120,
        )
        if probe.returncode == 0:
            pytest.skip(
                f"{who} can still list the directory after the deny. The cause was not measured."
            )
        yield
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

    with _denied_listing(claims):
        proc = rig.run(*_target(route, wt), "-Force")
    assert proc.returncode != 0
    assert "claims are unknown" in _out(proc), _out(proc)
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


def test_the_listing_helper_does_not_skip_what_it_may_not_read() -> None:
    """.NET's EnumerationOptions defaults IgnoreInaccessible to TRUE, and then an unlistable directory
    lists as empty, which is the fail-open these refusals exist to stop. The ACL tests drive this
    only where a deny binds, so the setting is pinned here as well, on every runner."""
    text = (_REPO / "scripts" / "worktree" / "remove.ps1").read_text(encoding="utf-8")
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

    with _denied_listing(hidden):
        proc = rig.run(*_target(route, wt), "-Force")
    assert proc.returncode != 0
    assert "allocations are unknown" in _out(proc), _out(proc)
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
