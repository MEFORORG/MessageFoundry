# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Tests for the allocation-stranding sweep and for `alloc.ps1 -For` (BACKLOG #1414).

**THE LOAD-BEARING ARM IS THE ONE THAT RUNS THE REAL GATE.** A sweep that reports who can commit a
number is a SECOND definition of ownership sitting beside `Ledger.owns`, and a second definition that
is never compared to the first is exactly the failure this repository already names for `parse_items`:
two parsers agreeing on today's corpus by luck. So `test_the_sweep_agrees_with_the_real_gate` builds
each interesting shape in a throwaway repo, asks the sweep, then asks `scripts/hooks/ledger_check.py`
itself, and requires the two to say the same thing.

**THE CLASSIFIER IS DRIVEN TO EVERY VERDICT, INCLUDING ITS WORST.** A classifier that has never been
made to return `drifted-branch-held` or `orphan-branch-absent` is an assertion, not an instrument --
and the live registry currently produces zero of the first, so nothing but a fabricated input can
exercise it. That is the point of fabricating one.

**`-For` IS EXECUTED, NOT PATTERN-MATCHED.** `test_ledger_check.py` records why: its own allocator
assertions were `read_text()` checks that stayed green through the entire period the allocator refused
every backlog allocation. These run pwsh against a throwaway repo with its own registry.
"""

from __future__ import annotations

import importlib.util
import json
import shutil
import subprocess
import sys
from pathlib import Path
from types import ModuleType

import pytest

_ROOT = Path(__file__).resolve().parents[1]
_SWEEP = _ROOT / "scripts" / "coord" / "alloc_strand_sweep.py"
_ALLOC = _ROOT / "scripts" / "coord" / "alloc.ps1"
_GATE = _ROOT / "scripts" / "hooks" / "ledger_check.py"
_PWSH = shutil.which("pwsh")


def _load(path: Path, name: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


sweep_mod = _load(_SWEEP, "alloc_strand_sweep")


def _wt(path: str, branch: str | None) -> object:
    return sweep_mod.Worktree(path=sweep_mod.norm_path(path), branch=branch)


def _claim(worktree: str, branch: str, number: str = "1500", title: str = "t") -> object:
    return sweep_mod.Claim(
        kind="backlog",
        number=number,
        title=title,
        branch=branch,
        worktree=sweep_mod.norm_path(worktree),
        claimed="2026-09-03T00:00:00",
    )


# --- the classifier, driven to every verdict -------------------------------------------------------


def test_a_landed_number_is_inert_whatever_its_keys_say() -> None:
    """`check_backlog` examines `head - base`, so a number on the base is never re-examined.

    Fabricated with BOTH keys dead on purpose: if `landed` were not checked first, this input would
    come back `orphan-branch-absent` and the census would report the entire history as stranded.
    """
    claim = _claim("C:/gone", "vanished")
    assert sweep_mod.classify(claim, [], set(), True)[0] == "landed"


def test_the_ordinary_case_is_aligned() -> None:
    claim = _claim("C:/tree/a", "feature")
    trees = [_wt("C:/tree/a", "feature")]
    assert sweep_mod.classify(claim, trees, {"feature"}, False)[0] == "aligned"


def test_the_1414_shape_is_reported_as_drifted_branch_held() -> None:
    """The item's instance A, fabricated because the live registry holds none of it.

    Entitlement is recorded to tree A; A has moved to another branch; the recorded branch is checked
    out in tree B. Git refuses to check one branch out in two worktrees, so the two keys cannot be
    brought back together -- which is the whole of BACKLOG #1414.
    """
    claim = _claim("C:/tree/a", "recorded")
    trees = [_wt("C:/tree/a", "somewhere-else"), _wt("C:/tree/b", "recorded")]
    verdict, held_by = sweep_mod.classify(claim, trees, {"recorded", "somewhere-else"}, False)
    assert verdict == "drifted-branch-held"
    assert held_by == "c:/tree/b"


def test_a_drifted_tree_whose_branch_is_unheld_is_only_a_checkout_away() -> None:
    claim = _claim("C:/tree/a", "recorded")
    trees = [_wt("C:/tree/a", "somewhere-else")]
    assert sweep_mod.classify(claim, trees, {"recorded"}, False)[0] == "drifted-branch-free"


def test_a_dead_worktree_is_rescued_by_the_branch_key() -> None:
    """PR 703's fallback: the path is mortal, the branch is not."""
    claim = _claim("C:/gone", "recorded")
    trees = [_wt("C:/tree/b", "recorded")]
    assert sweep_mod.classify(claim, trees, {"recorded"}, False)[0] == "orphan-branch-held"


def test_a_dead_worktree_with_a_surviving_unheld_branch_is_recoverable() -> None:
    claim = _claim("C:/gone", "recorded")
    assert sweep_mod.classify(claim, [], {"recorded"}, False)[0] == "orphan-branch-free"


def test_a_dead_worktree_AND_a_deleted_branch_is_the_unrecoverable_verdict() -> None:
    """PR 703 states this residual as its own limit; nothing here closes it, it is only counted.

    The discriminator against the verdict above is BRANCH EXISTENCE, which is why the branch set is a
    required input. The first cut of the sweep inferred it from "is any worktree standing on it" and
    reported 49 claims as recoverable without ever asking whether the branch was still there.
    """
    claim = _claim("C:/gone", "deleted-branch")
    assert sweep_mod.classify(claim, [], set(), False)[0] == "orphan-branch-absent"


def test_a_legacy_claim_with_no_recorded_branch_falls_to_the_path_alone() -> None:
    claim = _claim("C:/gone", "")
    assert sweep_mod.classify(claim, [_wt("C:/tree/b", "anything")], {"anything"}, False)[0] == (
        "orphan-branch-absent"
    )


def test_a_detached_head_can_never_satisfy_the_branch_key() -> None:
    """`rev-parse --abbrev-ref HEAD` reports "HEAD" on a detached checkout and names no branch.

    The gate spells this out; the sweep must agree, or it would report a route that does not exist.
    Live evidence that this is not a corner case: most worktrees on this clone are detached.
    """
    claim = _claim("C:/gone", "recorded")
    assert not sweep_mod.owns_from(claim, _wt("C:/tree/b", None))
    assert sweep_mod.classify(claim, [_wt("C:/tree/b", None)], {"recorded"}, False)[0] == (
        "orphan-branch-free"
    )


def test_ownership_comparison_is_case_and_separator_insensitive() -> None:
    """Windows hands the same tree back with either separator and either case.

    `Ledger.owns` casefolds and swaps separators before comparing; a sweep that did not would report
    a live tree as gone, which is the false-positive direction that manufactures a population.
    """
    claim = _claim("C:/Tree/A", "recorded")
    assert sweep_mod.owns_from(claim, _wt("c:\\tree\\a", None))


# --- respent titles: the only registry-visible trace of the third limb -----------------------------


def test_two_claims_sharing_a_title_are_reported_as_one_respent_number() -> None:
    claims = [
        _claim("C:/console", "console-branch", number="1422", title="The review gate passes green"),
        _claim("C:/builder", "builder-branch", number="1423", title="The review gate passes green"),
        _claim("C:/other", "b", number="1424", title="something entirely different"),
    ]
    pairs = sweep_mod.respent_titles(claims)
    assert len(pairs) == 1
    assert [c.number for c in pairs[0][1]] == ["1422", "1423"]


def test_a_title_differing_only_in_whitespace_and_case_still_pairs() -> None:
    claims = [
        _claim("C:/a", "x", number="1", title="Same  Work"),
        _claim("C:/b", "y", number="2", title="same work"),
    ]
    assert len(sweep_mod.respent_titles(claims)) == 1


def test_an_untitled_claim_never_pairs() -> None:
    """Empty titles would otherwise collapse into one enormous false group."""
    claims = [_claim("C:/a", "x", number="1", title=""), _claim("C:/b", "y", number="2", title="")]
    assert sweep_mod.respent_titles(claims) == []


# --- the load-bearing arm: the sweep and the real gate must agree ----------------------------------


def _git(repo: Path, *args: str) -> str:
    out = subprocess.run(
        ["git", "-C", str(repo), *args], capture_output=True, text=True, encoding="utf-8"
    )
    assert out.returncode == 0, out.stderr
    return out.stdout


def _rig(tmp: Path) -> Path:
    """A throwaway repo with an origin, a second worktree, and its own allocation registry."""
    bare = tmp / "origin.git"
    subprocess.run(["git", "init", "-q", "--bare", str(bare)], check=True)
    repo = tmp / "A"
    subprocess.run(["git", "clone", "-q", str(bare), str(repo)], check=True)
    _git(repo, "config", "user.email", "t@t")
    _git(repo, "config", "user.name", "t")
    (repo / "docs").mkdir()
    (repo / "docs" / "BACKLOG.md").write_text("# b\n\n## 1. seed\n", encoding="utf-8")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "seed")
    _git(repo, "branch", "-M", "main")
    _git(repo, "push", "-q", "origin", "main")
    _git(repo, "checkout", "-q", "-b", "work")
    _git(repo, "commit", "-q", "--allow-empty", "-m", "wip")
    _git(repo, "checkout", "-q", "main")
    _git(repo, "worktree", "add", "-q", str(tmp / "B"), "work")
    return repo


def _write_claim(repo: Path, number: str, worktree: str, branch: str) -> Path:
    common = Path(_git(repo, "rev-parse", "--path-format=absolute", "--git-common-dir").strip())
    directory = common / "mefor-coord" / "alloc" / "backlog"
    directory.mkdir(parents=True, exist_ok=True)
    target = directory / f"{number}.json"
    target.write_text(
        json.dumps(
            {
                "number": number,
                "kind": "backlog",
                "title": "t",
                "branch": branch,
                "worktree": worktree,
                "claimed": "x",
            }
        ),
        encoding="utf-8",
    )
    return directory.parent


def _gate_accepts(cwd: Path) -> bool:
    out = subprocess.run(
        [sys.executable, str(_GATE)], cwd=cwd, capture_output=True, text=True, encoding="utf-8"
    )
    return out.returncode == 0


def test_the_sweep_agrees_with_the_real_gate(tmp_path: Path) -> None:
    """The sweep's `commit_from` must name exactly the trees `Ledger.owns` accepts.

    Both the accepting and the refusing tree are asserted. An arm that only ever checks the happy
    tree cannot fail when the sweep over-reports, and over-reporting a route is the direction that
    sends someone to a worktree where the gate then refuses them.
    """
    repo = _rig(tmp_path)
    other = tmp_path / "B"
    top_a = _git(repo, "rev-parse", "--path-format=absolute", "--show-toplevel").strip()
    alloc = _write_claim(repo, "1500", top_a, "main")

    findings = sweep_mod.sweep(repo, alloc, ("backlog",), "origin/main", scan_refs=False)
    found = next(f for f in findings if f.claim.number == "1500")
    assert sweep_mod.norm_path(top_a) in found.commit_from
    assert sweep_mod.norm_path(other) not in found.commit_from

    for tree in (repo, other):
        (tree / "docs" / "BACKLOG.md").write_text(
            "# b\n\n## 1. seed\n\n## 1500. filed\n", encoding="utf-8"
        )
        _git(tree, "add", "docs/BACKLOG.md")
    assert _gate_accepts(repo), "the gate refused the tree the sweep said owns the number"
    assert not _gate_accepts(other), "the gate accepted a tree the sweep said does not own it"


def test_the_sweep_sees_the_1414_deadlock_the_gate_produces(tmp_path: Path) -> None:
    """End to end: entitlement in A, the work's branch held by B, and neither tree is both.

    This is the shape the item filed. The sweep must report B as unable to commit, and the real gate
    must actually refuse there -- the control that has to fire for the other assertion to mean
    anything.
    """
    repo = _rig(tmp_path)
    other = tmp_path / "B"
    top_a = _git(repo, "rev-parse", "--path-format=absolute", "--show-toplevel").strip()
    alloc = _write_claim(repo, "1500", top_a, "main")

    findings = sweep_mod.sweep(repo, alloc, ("backlog",), "origin/main", scan_refs=False)
    found = next(f for f in findings if f.claim.number == "1500")
    assert found.verdict == "aligned"  # A is live and still on the recorded branch

    (other / "docs" / "BACKLOG.md").write_text(
        "# b\n\n## 1. seed\n\n## 1500. filed\n", encoding="utf-8"
    )
    _git(other, "add", "docs/BACKLOG.md")
    assert not _gate_accepts(other)

    # The documented recovery: alias the held branch into the entitled tree and commit THERE.
    _git(repo, "checkout", "-q", "-b", "work-alias", "work")
    (repo / "docs" / "BACKLOG.md").write_text(
        "# b\n\n## 1. seed\n\n## 1500. filed\n", encoding="utf-8"
    )
    _git(repo, "add", "docs/BACKLOG.md")
    assert _gate_accepts(repo), "the aliased entitled tree must satisfy the path key"
    _git(repo, "commit", "-qm", "file 1500")
    _git(repo, "push", "-q", "origin", "work-alias:work")
    assert "## 1500." in _git(repo, "show", "origin/work:docs/BACKLOG.md")


def test_recreating_a_worktree_at_the_recorded_path_restores_ownership(tmp_path: Path) -> None:
    """The owner-ruled #1282 remedy, MEASURED rather than asserted.

    docs/LEDGER-GATE.md has carried "recreate a worktree at the recorded path" as an owner ruling
    since 2026-08-21, and nothing had ever executed it. It is the load-bearing claim behind calling
    the keyless state recoverable, so it is the one that most needs a test: if it were false, the
    `orphan-branch-absent` verdict would mean permanently lost rather than awkward.

    Three arms, because only the middle one can fail for the right reason: the number is owned, then
    the worktree is destroyed and the gate must REFUSE (the control), then the path is recreated and
    the gate must accept again.
    """
    repo = _rig(tmp_path)
    doomed = tmp_path / "doomed"
    _git(repo, "worktree", "add", "-q", "-b", "doomed-branch", str(doomed))
    top = _git(doomed, "rev-parse", "--path-format=absolute", "--show-toplevel").strip()
    _write_claim(repo, "1500", top, "doomed-branch")

    def stage_row(tree: Path) -> None:
        (tree / "docs" / "BACKLOG.md").write_text(
            "# b\n\n## 1. seed\n\n## 1500. filed\n", encoding="utf-8"
        )
        _git(tree, "add", "docs/BACKLOG.md")

    stage_row(doomed)
    assert _gate_accepts(doomed), "baseline: the recorded worktree must own its own number"

    _git(repo, "worktree", "remove", "--force", str(doomed))
    stage_row(repo)
    assert not _gate_accepts(repo), "control: with the tree gone, no other tree may commit it"

    # The remedy. The branch is deliberately NOT reused, so only the PATH key can be what rescues it.
    _git(repo, "worktree", "add", "-q", "--detach", str(doomed))
    stage_row(doomed)
    assert _gate_accepts(doomed), (
        "recreating a worktree at the recorded path must restore ownership -- the owner-ruled #1282 "
        "remedy, and the reason a keyless allocation is recoverable rather than lost"
    )


def test_a_pruned_worktree_is_not_counted_as_live(tmp_path: Path) -> None:
    """A removed directory leaves an administrative entry behind; that entry is not a route.

    This is the #1282 state, and reading it as live would report a stranded number as committable --
    the false-clean direction.
    """
    repo = _rig(tmp_path)
    shutil.rmtree(tmp_path / "B")
    live = sweep_mod.live_worktrees(repo)
    assert sweep_mod.norm_path(tmp_path / "B") not in {w.path for w in live}
    assert sweep_mod.norm_path(_git(repo, "rev-parse", "--show-toplevel").strip()) in {
        w.path for w in live
    }


# --- alloc.ps1 -For, executed ----------------------------------------------------------------------


def _alloc(repo: Path, *args: str) -> subprocess.CompletedProcess[str]:
    assert _PWSH
    return subprocess.run(
        [_PWSH, "-NoProfile", "-File", str(repo / "scripts" / "coord" / "alloc.ps1"), *args],
        cwd=repo,
        capture_output=True,
        text=True,
    )


def _alloc_rig(tmp: Path) -> Path:
    """A throwaway repo carrying its own alloc.ps1, floor constant, registry and second worktree.

    The seam is the process working directory, exactly as `test_ledger_check.py` documents: `$repo`
    and `$common` come from `git rev-parse` against the cwd, so this repo gets its OWN registry and
    cannot spend a real ledger number.
    """
    repo = tmp / "rig"
    (repo / "scripts" / "coord").mkdir(parents=True)
    (repo / "scripts" / "hooks").mkdir(parents=True)
    (repo / "docs").mkdir()
    shutil.copy(_ALLOC, repo / "scripts" / "coord" / "alloc.ps1")
    (repo / "scripts" / "hooks" / "ledger_check.py").write_text(
        "PUBLIC_BACKLOG_FLOOR = 100\n", encoding="utf-8"
    )
    (repo / "docs" / "BACKLOG.md").write_text("# rig\n\n## 5. item\n", encoding="utf-8")
    subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
    subprocess.run(["git", "add", "-A"], cwd=repo, check=True)
    subprocess.run(
        ["git", "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "rig"],
        cwd=repo,
        check=True,
    )
    _git(repo, "worktree", "add", "-q", "-b", "builder-branch", str(tmp / "builder"))
    return repo


@pytest.mark.skipif(not _PWSH, reason="pwsh not on PATH")
def test_the_rig_cannot_reach_the_real_registry(tmp_path: Path) -> None:
    """FIRST, because every later arm here spends real numbers if this is false.

    Claims are never released, so a rig that resolved to the project registry would burn production
    ledger numbers permanently and silently on every test run.
    """
    repo = _alloc_rig(tmp_path)
    out = _alloc(repo, "-Kind", "backlog", "-ShowFloor")
    assert out.returncode == 0, out.stderr
    real = str(_ROOT / ".git").lower()
    assert real not in out.stdout.lower().replace("/", "\\"), out.stdout


@pytest.mark.skipif(not _PWSH, reason="pwsh not on PATH")
def test_For_records_the_named_worktree_and_its_branch(tmp_path: Path) -> None:
    """The third limb closed at birth: the Console allocates, the Builder's tree is recorded."""
    repo = _alloc_rig(tmp_path)
    builder = tmp_path / "builder"
    out = _alloc(repo, "-Kind", "backlog", "-Title", "builders item", "-For", str(builder))
    assert out.returncode == 0, out.stdout + out.stderr
    claims = sorted((repo / ".git" / "mefor-coord" / "alloc" / "backlog").glob("*.json"))
    assert len(claims) == 1
    claim = json.loads(claims[0].read_text(encoding="utf-8"))
    assert sweep_mod.norm_path(claim["worktree"]) == sweep_mod.norm_path(builder)
    assert claim["branch"] == "builder-branch"


@pytest.mark.skipif(not _PWSH, reason="pwsh not on PATH")
def test_without_For_the_allocating_tree_is_still_recorded(tmp_path: Path) -> None:
    """The control for the arm above: the default must be untouched by this change.

    Without it, a `-For` that silently became the default would pass every other assertion here.
    """
    repo = _alloc_rig(tmp_path)
    out = _alloc(repo, "-Kind", "backlog", "-Title", "my own item")
    assert out.returncode == 0, out.stdout + out.stderr
    claims = sorted((repo / ".git" / "mefor-coord" / "alloc" / "backlog").glob("*.json"))
    claim = json.loads(claims[0].read_text(encoding="utf-8"))
    assert sweep_mod.norm_path(claim["worktree"]) == sweep_mod.norm_path(repo)


@pytest.mark.skipif(not _PWSH, reason="pwsh not on PATH")
def test_For_refuses_a_path_that_is_not_a_worktree(tmp_path: Path) -> None:
    """A typo must refuse, not write a claim born pointing where the gate will never accept it."""
    repo = _alloc_rig(tmp_path)
    out = _alloc(repo, "-Kind", "backlog", "-Title", "t", "-For", str(tmp_path / "no-such-tree"))
    assert out.returncode != 0
    assert "not inside a git worktree" in (out.stdout + out.stderr)
    assert not list((repo / ".git" / "mefor-coord" / "alloc" / "backlog").glob("*.json"))


@pytest.mark.skipif(not _PWSH, reason="pwsh not on PATH")
def test_For_refuses_a_worktree_belonging_to_a_different_clone(tmp_path: Path) -> None:
    """A different clone keeps its own registry, so a claim written here would never be found there.

    This is the failure mode that looks most like success: the path exists, it is a real git tree,
    and the claim file is written -- into a registry the committing session never reads.
    """
    repo = _alloc_rig(tmp_path)
    stranger = tmp_path / "stranger"
    subprocess.run(["git", "init", "-q", str(stranger)], check=True)
    out = _alloc(repo, "-Kind", "backlog", "-Title", "t", "-For", str(stranger))
    assert out.returncode != 0
    assert "DIFFERENT clone" in (out.stdout + out.stderr)
    assert not list((repo / ".git" / "mefor-coord" / "alloc" / "backlog").glob("*.json"))
