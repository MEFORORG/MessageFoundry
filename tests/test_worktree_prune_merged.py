# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Tests for the destructive worktree pruner (``scripts/worktree/prune-merged.ps1``).

This script once removed a worktree another live session was working in: ``git worktree remove
--force`` deleted the ``.git`` pointer and deregistered the tree, then failed to delete the directory,
leaving a folder git no longer recognised. It also printed ``Done. Pruned 5`` when four removals had
succeeded. These tests exist because a tool that deletes other people's checkouts needs proof that it
**refuses**, not just proof that it works.

Every test drives the REAL script as a subprocess against a synthetic repo built under ``tmp_path``,
never against this checkout -- so what is under test is the logic an operator runs.

Two rules govern the assertions, both learned by mutating the script and watching tests survive:

* **Assert the DECISION and the REASON, not survival.** Defence in depth means deleting the primary
  veto still leaves the directory intact (the ``-Apply`` re-check catches it), so a survival-only
  assertion passes on a script that has lost its main fence.
* **Every veto test carries a positive control in the same invocation.** ``repo-clean`` must come back
  ``removed``, so "nothing was pruned" can never pass because the candidate set was empty or the run
  refused for an unrelated reason.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "worktree" / "prune-merged.ps1"

pytestmark = pytest.mark.skipif(
    shutil.which("pwsh") is None or os.name != "nt",
    reason="prune-merged.ps1 needs pwsh on Windows (Process.StartTime liveness fence)",
)

NOW_MS = int(time.time() * 1000)

# Metadata files the activity signal reads. Backdating these is how a fixture gets past the veto
# without turning it off.
_GITDIR_FILES = ("index", "HEAD", "ORIG_HEAD", "FETCH_HEAD", "COMMIT_EDITMSG", "MERGE_MSG")


def _git(repo: Path, *args: str) -> str:
    proc = subprocess.run(
        ["git", "-C", str(repo), *args], check=True, capture_output=True, text=True
    )
    return proc.stdout


def _commit(repo: Path, name: str, text: str) -> None:
    (repo / name).write_text(text, encoding="utf-8")
    _git(repo, "add", "--", name)
    _git(repo, "commit", "-qm", f"add {name}")


def _head(repo: Path) -> str:
    return _git(repo, "rev-parse", "HEAD").strip()


def _add_worktree(primary: Path, path: Path, branch: str) -> None:
    """``worktree add -b`` only -- never a verb the session harness gate refuses."""
    _git(primary, "worktree", "add", "-q", "-b", branch, str(path))


def _backdate(primary: Path, worktree: Path, hours: float) -> None:
    """Age a worktree's PRIVATE git metadata so the activity veto releases it."""
    gitdir = Path(
        subprocess.run(
            ["git", "-C", str(worktree), "rev-parse", "--absolute-git-dir"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
    )
    when = time.time() - hours * 3600
    for rel in (*_GITDIR_FILES, "logs/HEAD"):
        f = gitdir / rel
        if f.exists():
            os.utime(f, (when, when))


class Fixture:
    """A synthetic repo family: one primary, one nested worktree, and eight siblings."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self.primary = root / "wt" / "repo"
        self.cfg = root / "cfg"

    def sibling(self, slug: str) -> Path:
        return self.primary.parent / f"{self.primary.name}-{slug}"

    def write_session(
        self,
        *,
        pid: int,
        cwd: Path | str,
        session_id: str,
        entrypoint: str = "claude-desktop",
        started_at: int | None = None,
    ) -> None:
        rec: dict[str, Any] = {
            "pid": pid,
            "sessionId": session_id,
            "cwd": str(cwd),
            "startedAt": NOW_MS if started_at is None else started_at,
            "version": "2.1.220",
            "kind": "interactive",
            "entrypoint": entrypoint,
        }
        (self.cfg / "sessions" / f"{pid}.json").write_text(json.dumps(rec), encoding="utf-8")


def _build(root: Path) -> Fixture:
    """Build the fixture family.

    No network and no push: ``origin`` is a real bare repo so ``-Fetch`` would work offline, and the
    remote-tracking refs the merge signals read are written with ``update-ref`` directly.
    """
    fx = Fixture(root)
    origin = root / "origin.git"
    subprocess.run(["git", "init", "-q", "--bare", str(origin)], check=True, capture_output=True)

    fx.primary.mkdir(parents=True)
    _git(fx.primary, "init", "-q", "-b", "main")
    _git(fx.primary, "config", "user.email", "t@example.invalid")
    _git(fx.primary, "config", "user.name", "t")
    _git(fx.primary, "remote", "add", "origin", str(origin))
    _commit(fx.primary, "seed.txt", "seed")
    main_tip = _head(fx.primary)
    _git(fx.primary, "update-ref", "refs/remotes/origin/main", main_tip)

    # A nested worktree, where EnterWorktree/new.ps1 put them. Must never be a candidate.
    _add_worktree(fx.primary, fx.primary / ".claude" / "worktrees" / "nested", "nested-branch")

    # The positive control: clean, no commits beyond origin/main, nobody in it.
    _add_worktree(fx.primary, fx.sibling("clean"), "clean")

    wt = fx.sibling("dirty")
    _add_worktree(fx.primary, wt, "dirty")
    (wt / "seed.txt").write_text("modified", encoding="utf-8")

    wt = fx.sibling("untracked")
    _add_worktree(fx.primary, wt, "untracked")
    (wt / "brand_new_module.py").write_text("# never committed anywhere\n", encoding="utf-8")

    wt = fx.sibling("ahead")
    _add_worktree(fx.primary, wt, "ahead")
    _commit(wt, "ahead.txt", "unique work")

    wt = fx.sibling("locked")
    _add_worktree(fx.primary, wt, "locked")
    _git(fx.primary, "worktree", "lock", "--reason", "in use by a bench run", str(wt))

    # Squash-merge shape: unique commits, and the branch's OWN upstream deleted.
    wt = fx.sibling("gone")
    _add_worktree(fx.primary, wt, "gone")
    _commit(wt, "gone.txt", "squashed upstream")
    _git(fx.primary, "update-ref", "refs/remotes/origin/gone", _head(wt))
    _git(fx.primary, "branch", "--set-upstream-to=origin/gone", "gone")
    _git(fx.primary, "update-ref", "-d", "refs/remotes/origin/gone")

    # ANOTHER branch's upstream is gone: `new.ps1 -Base origin/<parent>` leaves this shape, and it is
    # not a merge signal for the child.
    _git(fx.primary, "update-ref", "refs/remotes/origin/parent", main_tip)
    wt = fx.sibling("child")
    _add_worktree(fx.primary, wt, "child")
    _git(fx.primary, "branch", "--set-upstream-to=origin/parent", "child")
    _commit(wt, "child.txt", "never pushed")
    _git(fx.primary, "update-ref", "-d", "refs/remotes/origin/parent")

    _git(fx.primary, "worktree", "add", "-q", "--detach", str(fx.sibling("detached")))

    # A SEPARATE repo living beside the primary: shares the name prefix, shares no .git.
    decoy = fx.sibling("decoy")
    decoy.mkdir()
    _git(decoy, "init", "-q")

    (fx.cfg / "sessions").mkdir(parents=True)
    return fx


@pytest.fixture(scope="session")
def sleeper() -> Iterator[int]:
    """A pid that is unambiguously LIVE for the fence.

    NOT ``os.getpid()``: the fence calls a record STALE when its process started more than
    ``StartSkewMinutes`` (15) before the recorded ``startedAt``, so a pytest process older than 15
    minutes silently flips to STALE and the veto tests would pass for the wrong reason.
    """
    proc = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(900)"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        yield proc.pid
    finally:
        proc.kill()
        proc.wait(timeout=30)


@pytest.fixture(scope="session")
def readonly_fx(tmp_path_factory: pytest.TempPathFactory) -> Fixture:
    """Shared by the dry-run tests, which provably mutate nothing."""
    return _build(tmp_path_factory.mktemp("prune-ro"))


@pytest.fixture
def fx(tmp_path: Path) -> Fixture:
    """Function-scoped, for the -Apply tests.

    Worktree registrations are absolute-path-bound, so a mutated fixture must be rebuilt, not copied.
    """
    return _build(tmp_path)


def run(fx: Fixture, *extra: str, config_root: Path | str | None = "") -> dict[str, Any]:
    """Invoke the real script with -Json and parse its receipt.

    ``config_root=""`` means the fixture's own root; ``None`` omits the flag entirely.
    """
    root = fx.cfg if config_root == "" else config_root
    args = [
        "pwsh",
        "-NoProfile",
        "-NonInteractive",
        "-File",
        str(SCRIPT),
        "-RepoRoot",
        str(fx.primary),
        "-SkipFetch",
        "-SkipGh",
        "-Json",
    ]
    if root is not None:
        args += ["-ConfigRoot", str(root)]
    args += list(extra)
    proc = subprocess.run(args, capture_output=True, text=True, timeout=180, check=False)
    assert proc.stdout.strip(), f"no JSON on stdout (exit {proc.returncode}): {proc.stderr}"
    out: dict[str, Any] = json.loads(proc.stdout)
    out["_exit"] = proc.returncode
    out["_stdout"] = proc.stdout
    return out


def run_text(fx: Fixture, *extra: str) -> subprocess.CompletedProcess[str]:
    """Same, without -Json: the human summary is a separate surface and can lie on its own."""
    return subprocess.run(
        [
            "pwsh",
            "-NoProfile",
            "-NonInteractive",
            "-File",
            str(SCRIPT),
            "-RepoRoot",
            str(fx.primary),
            "-ConfigRoot",
            str(fx.cfg),
            "-SkipFetch",
            "-SkipGh",
            *extra,
        ],
        capture_output=True,
        text=True,
        timeout=180,
        check=False,
    )


def by_leaf(res: dict[str, Any], slug: str) -> dict[str, Any]:
    leaf = f"repo-{slug}"
    hits: list[dict[str, Any]] = [c for c in res["candidates"] if c["Leaf"] == leaf]
    assert hits, f"{leaf} was not a candidate; got {[c['Leaf'] for c in res['candidates']]}"
    return hits[0]


def live_record(fx: Fixture, sleeper: int, cwd: Path, sid: str = "aaaaaaaa-1111") -> None:
    fx.write_session(pid=sleeper, cwd=cwd, session_id=sid)


# --------------------------------------------------------------------------------------------------
# Scope: what is and is not a candidate
# --------------------------------------------------------------------------------------------------


def test_candidate_set_excludes_primary_nested_detached_and_foreign_repos(
    readonly_fx: Fixture, sleeper: int
) -> None:
    live_record(readonly_fx, sleeper, readonly_fx.primary, "cafe0001-0000")
    res = run(readonly_fx, "-IdleHours", "0")
    leaves = {c["Leaf"] for c in res["candidates"]}
    assert leaves == {
        "repo-clean",
        "repo-dirty",
        "repo-untracked",
        "repo-ahead",
        "repo-locked",
        "repo-gone",
        "repo-child",
    }
    assert "nested" not in leaves  # nested under the PRIMARY: not a `<primary>-` sibling
    assert "repo-decoy" not in leaves  # a separate repo that merely shares the name prefix
    assert [e["leaf"] for e in res["excluded"]] == ["repo-detached"]


def test_bracketed_parent_directory_still_matches(tmp_path: Path) -> None:
    """Anti-vacuity control: `-like` reads `[br]` as a character class and matches nothing.

    Every "was not pruned" assertion in this file would pass for free against an empty candidate set.
    """
    fx = _build(tmp_path / "[br]")
    res = run(fx, "-IdleHours", "0")
    assert res["counts"]["candidates"] == 7


# --------------------------------------------------------------------------------------------------
# The rule: prune = merged AND clean AND NOT occupied
# --------------------------------------------------------------------------------------------------


def test_clean_merged_unoccupied_is_pruned(fx: Fixture, sleeper: int) -> None:
    live_record(fx, sleeper, fx.primary)
    res = run(fx, "-Apply", "-IdleHours", "0")
    d = by_leaf(res, "clean")
    assert d["Decision"] == "PRUNE"
    assert d["Outcome"] == "removed"
    assert not fx.sibling("clean").exists()
    # Both merge signals fire here: `clean` has nothing beyond origin/main and `gone`'s own upstream
    # was deleted. Only `clean` is CONTAINED in origin/main, so only its branch may be deleted.
    assert res["counts"]["removed"] == 2
    assert res["counts"]["branchesDeleted"] == 1
    assert res["counts"]["branchesKept"] == 1
    assert res["_exit"] == 0


def test_occupied_worktree_is_never_pruned(fx: Fixture, sleeper: int) -> None:
    """The incident. A worktree can be clean AND merged AND occupied at the same time."""
    live_record(fx, sleeper, fx.sibling("gone"), "bbbbbbbb-2222")
    res = run(fx, "-Apply", "-IdleHours", "0")

    d = by_leaf(res, "gone")
    assert d["Decision"] == "SKIP", "occupancy must be decided BEFORE the removal, not caught by it"
    assert d["Reason"].startswith("occupied by 1 session(s)")
    assert d["Occupants"][0]["State"] == "LIVE"
    assert fx.sibling("gone").exists()

    # Positive control in the same invocation: the run was capable of removing something.
    assert by_leaf(res, "clean")["Outcome"] == "removed"


def test_vscode_session_vetoes_exactly_like_a_desktop_one(fx: Fixture, sleeper: int) -> None:
    """The fence is path-based; the launching surface is irrelevant to it."""
    fx.write_session(
        pid=sleeper,
        cwd=fx.sibling("gone"),
        session_id="cccccccc-3333",
        entrypoint="claude-vscode",
    )
    res = run(fx, "-IdleHours", "0")
    d = by_leaf(res, "gone")
    assert d["Decision"] == "SKIP"
    assert d["Occupants"][0]["Surface"] == "claude-vscode"


def test_session_in_a_nested_worktree_vetoes_its_ancestor(fx: Fixture, sleeper: int) -> None:
    """`<sibling>/.claude/worktrees/<x>` is gitignored, so the PARENT reads perfectly clean.

    Removing the parent with --force deletes the nested checkout too and leaves it registered with no
    directory -- the exact orphan state the incident produced.
    """
    outer = fx.sibling("clean")
    inner = outer / ".claude" / "worktrees" / "inner"
    _add_worktree(fx.primary, inner, "inner-branch")
    live_record(fx, sleeper, inner, "dddddddd-4444")

    res = run(fx, "-Apply", "-IdleHours", "0")
    d = by_leaf(res, "clean")
    assert d["Decision"] == "SKIP"
    assert "nested inner" in d["Reason"]
    assert outer.exists() and inner.exists()


def test_a_worktree_containing_another_is_refused_even_when_empty(
    fx: Fixture, sleeper: int
) -> None:
    """No session in the nested tree at all -- containment alone must disqualify it."""
    live_record(fx, sleeper, fx.primary)
    outer = fx.sibling("clean")
    _add_worktree(fx.primary, outer / ".claude" / "worktrees" / "inner", "inner-branch")

    res = run(fx, "-Apply", "-IdleHours", "0")
    d = by_leaf(res, "clean")
    assert d["Decision"] == "SKIP"
    assert "nested registered worktree" in d["Reason"]
    assert d["NestedWorktrees"] == ["inner"]
    assert outer.exists()


def test_dead_record_is_not_a_veto_and_not_a_permission(fx: Fixture, sleeper: int) -> None:
    """Liveness may only VETO. A DEAD verdict must not authorise the removal by itself."""
    dead = _find_free_pid()
    fx.write_session(pid=dead, cwd=fx.sibling("clean"), session_id="eeeeeeee-5555")
    live_record(fx, sleeper, fx.primary)  # keeps the fence available

    res = run(fx)  # default -IdleHours: signal 2 still stands
    d = by_leaf(res, "clean")
    assert d["Occupants"] == []  # not a veto
    assert d["Decision"] == "SKIP"  # and not a green light either
    assert d["Reason"].startswith("recently active")


def test_unreadable_record_vetoes_while_the_fence_stays_available(
    fx: Fixture, sleeper: int
) -> None:
    live_record(fx, sleeper, fx.primary)
    (fx.cfg / "sessions" / "weird.json").write_text(
        json.dumps(
            {
                "pid": "not-a-number",
                "sessionId": "ffffffff-6666",
                "cwd": str(fx.sibling("clean")),
                "startedAt": NOW_MS,
            }
        ),
        encoding="utf-8",
    )
    res = run(fx, "-IdleHours", "0")
    assert res["fence"]["available"] is True
    assert "[UNREADABLE]" in by_leaf(res, "clean")["Reason"]


# --------------------------------------------------------------------------------------------------
# Fence unavailable => refuse, loudly
# --------------------------------------------------------------------------------------------------


def test_empty_registry_refuses_everything(fx: Fixture) -> None:
    """An empty roster is 'I could not look', not 'nobody is here'. Run with -Apply on purpose."""
    res = run(fx, "-Apply", "-IdleHours", "0")
    assert res["_exit"] == 2
    assert res["fence"]["available"] is False
    assert res["fence"]["recordsExamined"] == 0
    assert res["counts"]["removed"] == 0
    assert all(c["Decision"] == "SKIP" for c in res["candidates"])
    assert all(any("fence unavailable" in r for r in c["Reasons"]) for c in res["candidates"]), (
        "every candidate must name the fence, or a mutant that drops the check still passes"
    )
    assert fx.sibling("clean").exists()


def test_missing_config_root_refuses_everything(fx: Fixture, tmp_path: Path) -> None:
    res = run(fx, "-Apply", "-IdleHours", "0", config_root=tmp_path / "nope")
    assert res["_exit"] == 2
    assert res["fence"]["rootsExamined"] == 0
    assert "no Claude config root" in res["fence"]["detail"]
    assert res["counts"]["removed"] == 0


def test_only_a_malformed_record_is_unavailable_not_empty(fx: Fixture) -> None:
    (fx.cfg / "sessions" / "12345.json").write_text("{not json", encoding="utf-8")
    res = run(fx, "-Apply", "-IdleHours", "0")
    assert res["_exit"] == 2
    assert res["fence"]["recordsExamined"] == 0
    assert res["fence"]["available"] is False


def test_negative_idle_hours_is_refused(fx: Fixture, sleeper: int) -> None:
    """A negative cut-off puts the boundary in the FUTURE, disarming signal 2 while looking set."""
    live_record(fx, sleeper, fx.primary)
    res = run(fx, "-Apply", "-IdleHours", "-1")
    assert res["_exit"] == 2
    assert "IdleHours" in res["error"]
    assert fx.sibling("clean").exists()


# --------------------------------------------------------------------------------------------------
# Reduced assurance is announced, never silent
# --------------------------------------------------------------------------------------------------


def test_disabled_activity_veto_is_declared(fx: Fixture, sleeper: int) -> None:
    live_record(fx, sleeper, fx.primary)
    res = run(fx, "-IdleHours", "0")
    assert res["fence"]["activityVeto"] is False
    assert any("activity veto DISABLED" in r for r in res["fence"]["reducedAssurance"])

    text = run_text(fx, "-IdleHours", "0").stdout
    assert "REDUCED ASSURANCE" in text


def test_explicit_config_root_is_declared_as_fixture_scope(fx: Fixture, sleeper: int) -> None:
    live_record(fx, sleeper, fx.primary)
    res = run(fx, "-IdleHours", "0")
    assert any(
        "real session registry was NOT consulted" in r for r in res["fence"]["reducedAssurance"]
    )


def test_fence_contribution_is_reported_not_implied(fx: Fixture, sleeper: int) -> None:
    """The number that matters is how many candidates signal 1 vetoed -- measured 0 of 4 in the wild."""
    live_record(fx, sleeper, fx.primary)  # in the primary: vetoes no candidate
    res = run(fx, "-IdleHours", "0")
    assert res["fence"]["liveInRepo"] == 1
    assert res["fence"]["vetoedCandidates"] == 0

    text = run_text(fx, "-IdleHours", "0").stdout
    assert "0 of 7 candidate(s) vetoed by signal 1" in text


# --------------------------------------------------------------------------------------------------
# The other disqualifiers
# --------------------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("slug", "needle"),
    [
        ("dirty", "dirty: 1 uncommitted tracked change(s)"),
        ("untracked", "--force would delete them unrecoverably"),
        ("locked", "locked by git: in use by a bench run"),
        ("ahead", "not merged (no merge signal)"),
        ("child", "not merged"),
    ],
)
def test_disqualifiers(readonly_fx: Fixture, sleeper: int, slug: str, needle: str) -> None:
    live_record(readonly_fx, sleeper, readonly_fx.primary, "cafe0002-0000")
    res = run(readonly_fx, "-IdleHours", "0")
    d = by_leaf(res, slug)
    assert d["Decision"] == "SKIP"
    assert needle in d["Reason"]


def test_gone_upstream_of_another_branch_is_not_a_merge_signal(
    readonly_fx: Fixture, sleeper: int
) -> None:
    """`new.ps1 -Base origin/<parent>` leaves the child pointing at the PARENT's upstream."""
    live_record(readonly_fx, sleeper, readonly_fx.primary, "cafe0003-0000")
    d = by_leaf(run(readonly_fx, "-IdleHours", "0"), "child")
    assert d["Decision"] == "SKIP"
    assert any("belongs to ANOTHER branch" in n for n in d["Notes"])


def test_never_used_is_reported_separately_from_merged(readonly_fx: Fixture, sleeper: int) -> None:
    """'0 commits beyond origin/main' is true of a merged branch AND of one that never advanced.

    The second is the incident's shape, so it must not be reported as though something was merged.
    """
    live_record(readonly_fx, sleeper, readonly_fx.primary, "cafe0004-0000")
    d = by_leaf(run(readonly_fx, "-IdleHours", "0"), "clean")
    assert d["Decision"] == "PRUNE"
    assert d["NeverUsed"] is True
    assert "never used" in d["Reason"]


def test_merge_is_not_evaluated_for_a_disqualified_candidate(
    readonly_fx: Fixture, sleeper: int
) -> None:
    """`Merged: false` would claim it was checked and found unmerged. It was never asked."""
    live_record(readonly_fx, sleeper, readonly_fx.primary, "cafe0005-0000")
    d = by_leaf(run(readonly_fx, "-IdleHours", "0"), "dirty")
    assert d["Merged"] is None
    assert d["MergeReason"] == "not evaluated (already disqualified)"


def test_activity_veto_fires_then_releases(fx: Fixture, sleeper: int) -> None:
    live_record(fx, sleeper, fx.primary)
    d = by_leaf(run(fx), "clean")
    assert d["Decision"] == "SKIP"
    assert d["Reason"].startswith("recently active")

    _backdate(fx.primary, fx.sibling("clean"), hours=100)
    d = by_leaf(run(fx), "clean")
    assert d["Decision"] == "PRUNE"
    assert d["ActivityAgeHours"] > 36


def test_name_overrides_activity_but_never_occupancy_or_a_lock(fx: Fixture, sleeper: int) -> None:
    live_record(fx, sleeper, fx.sibling("gone"), "77777777-8888")
    res = run(fx, "-Name", "clean")
    d = by_leaf(res, "clean")
    assert d["Decision"] == "PRUNE"
    assert any("overridden by -Name" in n for n in d["Notes"])
    assert [c["Leaf"] for c in res["candidates"]] == ["repo-clean"]

    for slug in ("gone", "locked"):
        d = by_leaf(run(fx, "-Name", slug), slug)
        assert d["Decision"] == "SKIP", f"-Name must not override {slug}"


def test_unreadable_git_metadata_fails_closed(fx: Fixture, sleeper: int) -> None:
    """A half-removed worktree exits 128 with no output, which used to read as CLEAN."""
    live_record(fx, sleeper, fx.primary)
    victim = fx.sibling("clean")
    (victim / ".git").unlink()  # the orphan shape: directory present, pointer gone

    d = by_leaf(run(fx), "clean")
    assert d["Decision"] == "SKIP"
    assert any("git status failed" in r for r in d["Reasons"])
    assert any("activity unknown" in r for r in d["Reasons"])


# --------------------------------------------------------------------------------------------------
# Outcomes, not intentions
# --------------------------------------------------------------------------------------------------


def test_counts_report_successes_not_candidates(fx: Fixture, sleeper: int) -> None:
    """The original defect: `Done. Pruned 5` after four removals succeeded.

    A held-open file makes `worktree remove --force` fail for real (msvcrt's share mode omits
    FILE_SHARE_DELETE), reproducing the incident's exact error without mocking anything.
    """
    live_record(fx, sleeper, fx.primary)
    _backdate(fx.primary, fx.sibling("gone"), hours=100)
    _backdate(fx.primary, fx.sibling("clean"), hours=100)

    blocker = (fx.sibling("gone") / "seed.txt").open("rb")
    try:
        res = run(fx, "-Apply")
    finally:
        blocker.close()

    assert res["counts"]["prunable"] == 2, "both should have been eligible"
    assert res["counts"]["removed"] == 1
    assert res["counts"]["failed"] == 1
    assert res["_exit"] == 1
    assert by_leaf(res, "clean")["Outcome"] == "removed"
    assert by_leaf(res, "gone")["Outcome"] in {"orphaned", "failed"}


def test_human_summary_matches_the_counts(fx: Fixture, sleeper: int) -> None:
    """The text surface is what an operator reads, and it can over-report on its own."""
    live_record(fx, sleeper, fx.primary)
    _backdate(fx.primary, fx.sibling("gone"), hours=100)
    _backdate(fx.primary, fx.sibling("clean"), hours=100)

    blocker = (fx.sibling("gone") / "seed.txt").open("rb")
    try:
        proc = run_text(fx, "-Apply")
    finally:
        blocker.close()

    assert "Done. removed 1, failed 1" in proc.stdout
    assert "Pruned 2" not in proc.stdout
    assert proc.returncode == 1


def test_failed_removal_is_diagnosed_and_the_branch_survives(fx: Fixture, sleeper: int) -> None:
    live_record(fx, sleeper, fx.primary)
    _backdate(fx.primary, fx.sibling("gone"), hours=100)

    blocker = (fx.sibling("gone") / "seed.txt").open("rb")
    try:
        res = run(fx, "-Apply", "-Name", "gone")
    finally:
        blocker.close()

    d = by_leaf(res, "gone")
    assert d["Outcome"] in {"orphaned", "failed"}
    assert d["BranchOutcome"] == "kept"
    if d["Outcome"] == "orphaned":
        assert "ORPHANED" in d["OutcomeDetail"]
        assert "registered=" in d["OutcomeDetail"]
    branches = _git(fx.primary, "branch", "--list", "gone")
    assert "gone" in branches, "a failed removal must not take the branch with it"


def test_orphan_state_prints_the_recovery_recipe(fx: Fixture, sleeper: int) -> None:
    """The orphaned directory is what nearly cost a session its work.

    Neither ``worktree repair`` nor ``worktree add`` alone recovers it -- only move-aside then re-add
    -- so a red error without the recipe leaves the operator stuck.
    """
    live_record(fx, sleeper, fx.primary)
    _backdate(fx.primary, fx.sibling("gone"), hours=100)

    blocker = (fx.sibling("gone") / "seed.txt").open("rb")
    try:
        proc = run_text(fx, "-Apply", "-Name", "gone")
    finally:
        blocker.close()

    if "ORPHANED" not in proc.stdout:
        pytest.skip("git removed the directory despite the open handle on this filesystem")
    assert ".git pointer" in proc.stdout
    assert "registration:" in proc.stdout
    assert "Move-Item" in proc.stdout
    assert "worktree add" in proc.stdout
    assert "'git worktree prune' was NOT run" in proc.stdout
    assert proc.returncode == 1


def test_branch_with_unique_commits_is_kept_never_force_deleted(fx: Fixture, sleeper: int) -> None:
    """`gone` is a merge signal for the WORKTREE and never a licence to delete the BRANCH.

    `branch -d` refuses a branch merged only into origin/main whenever local main lags, so `-D` used
    to be the routine path -- overriding git's last protection on a verdict formed seconds earlier.
    """
    live_record(fx, sleeper, fx.primary)
    _backdate(fx.primary, fx.sibling("gone"), hours=100)
    tip = _git(fx.primary, "rev-parse", "gone").strip()

    res = run(fx, "-Apply", "-Name", "gone")
    d = by_leaf(res, "gone")
    assert d["Outcome"] == "removed"
    assert d["BranchOutcome"] == "kept"
    assert "not on origin/main" in d["BranchDetail"]
    assert res["counts"]["branchesKept"] == 1
    assert _git(fx.primary, "rev-parse", "gone").strip() == tip


def test_worktree_prune_is_never_run(fx: Fixture, sleeper: int) -> None:
    """`git worktree prune` deregisters ANY worktree whose directory is momentarily missing.

    That includes the `.claude/worktrees` ones this script must never touch, and it would finish off
    a half-removed tree.
    """
    live_record(fx, sleeper, fx.primary)
    _backdate(fx.primary, fx.sibling("clean"), hours=100)
    nested = fx.primary / ".claude" / "worktrees" / "nested"
    moved = fx.primary.parent / "nested-moved-aside"
    nested.rename(moved)
    try:
        res = run(fx, "-Apply")
        assert res["counts"]["removed"] == 1  # the control still worked
        registered = _git(fx.primary, "worktree", "list")
        assert "nested" in registered, "the missing nested worktree must still be registered"
    finally:
        moved.rename(nested)


def test_dry_run_mutates_nothing_and_does_not_fetch(fx: Fixture, sleeper: int) -> None:
    live_record(fx, sleeper, fx.primary)
    _backdate(fx.primary, fx.sibling("clean"), hours=100)
    before = sorted(p.name for p in fx.primary.parent.iterdir())

    res = run(fx, config_root=fx.cfg)
    assert by_leaf(res, "clean")["Decision"] == "PRUNE"
    assert by_leaf(res, "clean")["Outcome"] == "not attempted"
    assert res["fetched"] is False
    assert "skipped (-SkipFetch)" in res["refs"]
    assert sorted(p.name for p in fx.primary.parent.iterdir()) == before


# --------------------------------------------------------------------------------------------------
# Refusals about where it is run
# --------------------------------------------------------------------------------------------------


def test_refuses_from_a_linked_worktree(fx: Fixture) -> None:
    proc = subprocess.run(
        [
            "pwsh",
            "-NoProfile",
            "-NonInteractive",
            "-File",
            str(SCRIPT),
            "-RepoRoot",
            str(fx.sibling("clean")),
            "-ConfigRoot",
            str(fx.cfg),
            "-SkipFetch",
            "-SkipGh",
            "-Json",
        ],
        capture_output=True,
        text=True,
        timeout=180,
        check=False,
    )
    assert proc.returncode == 2
    assert json.loads(proc.stdout)["error"] == "not the primary checkout"


def test_refuses_outside_a_repository(tmp_path: Path) -> None:
    plain = tmp_path / "plain"
    plain.mkdir()
    proc = subprocess.run(
        [
            "pwsh",
            "-NoProfile",
            "-NonInteractive",
            "-File",
            str(SCRIPT),
            "-RepoRoot",
            str(plain),
            "-SkipFetch",
            "-SkipGh",
            "-Json",
        ],
        capture_output=True,
        text=True,
        timeout=180,
        check=False,
    )
    assert proc.returncode == 2
    assert json.loads(proc.stdout)["error"] == "not a git repository"


# --------------------------------------------------------------------------------------------------
# Static guard: the defect class where a probe silently never runs
# --------------------------------------------------------------------------------------------------


def test_gh_json_field_list_is_one_argv_entry() -> None:
    """`--json number, headRefOid` is three argv entries; gh rejects the third and the block dies.

    That is the whole exact-tip merge probe silently never running while the receipt still claimed a
    PR probe was scoped -- a green gate that cannot see the thing it guards.
    """
    src = SCRIPT.read_text(encoding="utf-8")
    assert "--json number,headRefOid" in src
    assert "--json number, " not in src


def _find_free_pid() -> int:
    proc = subprocess.Popen(
        ["cmd", "/c", "exit"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )
    proc.wait(timeout=30)
    time.sleep(0.3)
    return proc.pid
