# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Tests for the ledger gate (scripts/hooks/ledger_check.py).

The defect under test merges CLEAN, which is what makes it dangerous: two sessions each pick "the next
free number", create differently-NAMED files, git merges both without a conflict, and the ledger is
quietly corrupt. It has happened three times in this repo.

Every test builds a real throwaway git repo, stages a real commit, and runs the real hook against it — so
what is asserted is the contract git will actually invoke.
"""

from __future__ import annotations

import importlib.util
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path
from types import ModuleType

import pytest

CHECK = Path(__file__).resolve().parents[1] / "scripts" / "hooks" / "ledger_check.py"

ROW = "| [{n}]({n}-{slug}.md) | {title} | Accepted |"
README_HEAD = "# Architecture Decision Records\n\n| ADR | Decision | Status |\n|---|---|---|\n"


def git(repo: Path, *args: str) -> str:
    """Run git and return stdout, TOLERATING a non-zero exit.

    Tolerance is deliberate and load-bearing: the merge in
    test_MAIN_merged_INTO_another_seats_branch_is_committable is SUPPOSED to conflict, and git exits 1
    when it does. Do not add check=True here.

    What tolerance costs is that a broken git is indistinguishable from a command with no output, so
    anything that builds a PATH from this must use git_read() below instead.
    """
    proc = subprocess.run(
        ["git", "-C", str(repo), *args], capture_output=True, text=True, check=False
    )
    return proc.stdout


def git_read(repo: Path, *args: str) -> str:
    """Read a value out of git, raising with stderr when git fails, for anything that builds a path.

    ***THE TOLERANT HELPER ABOVE RETURNS "" ON ANY FAILURE, AND "" IS NOT AN ERROR TO Path().***
    Measured 2026-09-18: every git call in one suite run returned empty, `Path("") / "mefor-coord"` is
    a RELATIVE path, and five claim records were written to the checkout root instead of the temp repo.
    The run reported no problem from the write itself, because the write succeeded.
    """
    proc = subprocess.run(
        ["git", "-C", str(repo), *args], capture_output=True, text=True, check=False
    )
    if proc.returncode != 0:
        raise RuntimeError(
            f"git {' '.join(args)} failed in {repo} (exit {proc.returncode}): {proc.stderr.strip()}"
        )
    return proc.stdout


def run_check(repo: Path, *args: str) -> tuple[int, str]:
    proc = subprocess.run(
        [sys.executable, str(CHECK), *args],
        cwd=repo,
        capture_output=True,
        text=True,
        check=False,
    )
    return proc.returncode, proc.stdout + proc.stderr


def write(repo: Path, rel: str, text: str) -> None:
    p = repo / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")


def allocate(
    repo: Path,
    kind: str,
    number: str,
    *,
    worktree: Path | None = None,
    branch: str | None = None,
    omit_branch: bool = False,
) -> None:
    """Mimic what scripts/coord/alloc.ps1 writes, so the hook's ownership check has something to read.

    ***THE `branch` FIELD IS NOT DECORATION AND THIS HELPER USED TO OMIT IT.*** The real allocator
    records `number`, `kind`, `title`, `branch`, `worktree` and `claimed`; this fixture wrote only the
    first two and the worktree. That made it a SECOND, SILENTLY DIFFERENT definition of the record --
    the defect this repo's test families exist to catch -- and it mattered the moment ownership grew a
    branch fallback (BACKLOG #1282): every arm below would have passed for the wrong reason, because
    the fallback short-circuits on a missing branch.

    `omit_branch` reproduces a LEGACY record written before the allocator recorded one, so the
    path-only behaviour stays pinned.
    """
    common = git_read(repo, "rev-parse", "--path-format=absolute", "--git-common-dir").strip()
    top = git_read(repo, "rev-parse", "--path-format=absolute", "--show-toplevel").strip()
    # ***THE ROOT MUST BE ABSOLUTE, AND `--path-format=absolute` IS A REQUEST, NOT A GUARANTEE.***
    # A relative base here does not fail -- it silently retargets the write at the pytest process's
    # cwd, i.e. this checkout, which is how five records leaked on 2026-09-18. git_read() covers the
    # failure case; this covers a git that succeeds and answers relatively anyway.
    root = Path(common)
    assert root.is_absolute(), (
        f"git reported a non-absolute common dir ({common!r}); writing a claim under it would land "
        f"in the pytest cwd ({Path.cwd()}) rather than in {repo}"
    )
    d = root / "mefor-coord" / "alloc" / kind
    d.mkdir(parents=True, exist_ok=True)
    claim: dict[str, str] = {"number": number, "kind": kind, "worktree": str(worktree or top)}
    if not omit_branch:
        claim["branch"] = branch or git_read(repo, "rev-parse", "--abbrev-ref", "HEAD").strip()
    (d / f"{number}.json").write_text(json.dumps(claim), encoding="utf-8")


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    """A repo whose origin/main already carries ADR 0001 and BACKLOG #1 — i.e. the base to collide with."""
    r = tmp_path / "repo"
    r.mkdir()
    git(r, "init", "-q", "-b", "main")
    git(r, "config", "user.email", "t@t")
    git(r, "config", "user.name", "t")
    git(r, "config", "commit.gpgsign", "false")

    write(r, "docs/adr/0001-first.md", "# 0001 — First\n")
    write(
        r,
        "docs/adr/README.md",
        README_HEAD + ROW.format(n="0001", slug="first", title="First") + "\n",
    )
    write(r, "docs/BACKLOG.md", "# Backlog\n\n## 1. First item\n\nbody\n")
    git(r, "add", "-A")
    git(r, "commit", "-qm", "base")
    # A local ref named origin/main stands in for the remote: the hook only ever reads it.
    git(r, "update-ref", "refs/remotes/origin/main", "HEAD")
    return r


# ----------------------------------------------------------------- the collision this exists to stop


def test_reusing_an_adr_number_from_main_is_blocked(repo: Path) -> None:
    """The exact defect: a DIFFERENT filename under an EXISTING number. Merges clean; corrupts silently."""
    write(repo, "docs/adr/0001-second-thing.md", "# 0001 — Second\n")
    git(repo, "add", "docs/adr/0001-second-thing.md")

    code, out = run_check(repo)
    assert code == 1
    assert "ADR 0001 already exists" in out
    assert "alloc.ps1" in out  # the block must say how to proceed


def test_a_declared_companion_under_the_same_number_is_allowed(repo: Path) -> None:
    """ADR 0013 in the real repo: one number, ONE index row, two files, deliberately. Must not be broken."""
    write(repo, "docs/adr/0001-first-increment-2.md", "# 0001 — First, increment 2\n")
    # The index row for 0001 names the companion file — that declaration is what makes it legal.
    row = (
        "| [0001](0001-first.md) | First. Increment 2 lives beside it under the same number: "
        "[0001-first-increment-2](0001-first-increment-2.md) | Accepted |"
    )
    write(repo, "docs/adr/README.md", README_HEAD + row + "\n")
    allocate(repo, "adr", "0001")
    git(repo, "add", "-A")

    code, out = run_check(repo)
    assert code == 0, out


def test_a_NEAR_MISS_of_the_rows_filename_is_not_a_declared_companion(repo: Path) -> None:
    """BACKLOG #2001. `0001-fir` is a substring of the row's `0001-first.md`, and that used to pass.

    The row names no such file, so this is an undeclared reuse of 0001: the collision the gate stops.
    """
    write(repo, "docs/adr/0001-fir.md", "# 0001 -- Stray\n")
    allocate(repo, "adr", "0001")
    git(repo, "add", "-A")

    code, out = run_check(repo)
    assert code == 1, out
    assert "ADR 0001 already exists" in out


def test_a_new_adr_number_must_be_allocated(repo: Path) -> None:
    write(repo, "docs/adr/0002-new.md", "# 0002 — New\n")
    write(
        repo,
        "docs/adr/README.md",
        README_HEAD + ROW.format(n="0002", slug="new", title="New") + "\n",
    )
    git(repo, "add", "-A")

    code, out = run_check(repo)
    assert code == 1
    assert "not allocated to this worktree" in out


def test_an_allocated_and_indexed_adr_passes(repo: Path) -> None:
    write(repo, "docs/adr/0002-new.md", "# 0002 — New\n")
    write(
        repo,
        "docs/adr/README.md",
        README_HEAD
        + ROW.format(n="0001", slug="first", title="First")
        + "\n"
        + ROW.format(n="0002", slug="new", title="New")
        + "\n",
    )
    allocate(repo, "adr", "0002")
    git(repo, "add", "-A")

    code, out = run_check(repo)
    assert code == 0, out


def test_a_number_allocated_to_a_DIFFERENT_worktree_is_blocked(repo: Path, tmp_path: Path) -> None:
    """A sibling session holds 0002. Hand-writing it here must not slip through.

    ***THE OTHER BRANCH IS LOAD-BEARING AND USED TO BE IMPLICIT.*** A sibling SESSION is in another
    worktree AND on another branch -- git refuses an ORDINARY second checkout of one branch in two
    worktrees (a DEFAULT, not a law of git; `Ledger.owns` records what defeats it, BACKLOG #1039), so
    that pairing is not a coincidence, it is the shape a live sibling has. Once ownership grew a
    branch fallback (BACKLOG #1282) this arm had to name the branch or it would have been asserting
    the weaker "different path" and passing for a reason unrelated to sibling-ness.
    """
    write(repo, "docs/adr/0002-new.md", "# 0002 — New\n")
    write(
        repo,
        "docs/adr/README.md",
        README_HEAD + ROW.format(n="0002", slug="new", title="New") + "\n",
    )
    allocate(
        repo,
        "adr",
        "0002",
        worktree=tmp_path / "some-other-worktree",
        branch="claude/some-other-session",
    )
    git(repo, "add", "-A")

    code, out = run_check(repo)
    assert code == 1
    assert "not allocated to this worktree" in out


def test_a_number_whose_worktree_IS_GONE_is_committable_from_the_SAME_BRANCH(
    repo: Path, tmp_path: Path
) -> None:
    """BACKLOG #1282. The recorded path is dead; the branch is alive and is THIS one.

    ***THIS IS THE ARM THE CHANGE EXISTS FOR, AND IT IS A DELIBERATE LOOSENING.*** Before it, a
    worktree removed by anything other than scripts/worktree/remove.ps1 stranded its numbers
    permanently -- 43 of them by 2026-08-30 -- because `owns` compared a path and nothing else, and
    nothing anywhere reported the loss.

    ***IT IS SAFE ONLY BECAUSE GIT REFUSES AN ORDINARY SECOND CHECKOUT OF ONE BRANCH IN TWO
    WORKTREES.*** The gate exists to stop two sessions filing one number, and two sessions do not hold
    one branch -- so "the session on this branch" is as single-valued as "the session in this
    worktree" was, while outliving it. A branch that is free to check out is one nobody is working in.

    ***THAT REFUSAL IS A DEFAULT, NOT A LAW OF GIT, AND THIS DOCSTRING SAID IT FLAT (BACKLOG #1039).***
    `git worktree add --force` / `-f` and `git checkout --ignore-other-worktrees` both get past it, so
    forcing a second checkout makes the branch key non-exclusive and leaks entitlement to a tree that
    never allocated the number. `Ledger.owns` carries the full statement of the residual; it is named
    here because THIS is the sentence that licenses the loosening, and a flat version of it here
    contradicts the qualified version there.

    **Recorded because the miss generalises: the first sweep for this premise used a CASE-SENSITIVE
    grep and this site is in capitals**, so the strongest instance in the repository was the one left
    behind while the ledger row said the sweep was finished.
    """
    write(repo, "docs/adr/0002-new.md", "# 0002 — New\n")
    write(
        repo,
        "docs/adr/README.md",
        README_HEAD + ROW.format(n="0002", slug="new", title="New") + "\n",
    )
    here = git(repo, "rev-parse", "--abbrev-ref", "HEAD").strip()
    allocate(repo, "adr", "0002", worktree=tmp_path / "worktree-that-was-deleted", branch=here)
    git(repo, "add", "-A")

    code, out = run_check(repo)
    assert code == 0, out


def test_a_LEGACY_record_with_no_branch_still_falls_back_to_the_path_alone(
    repo: Path, tmp_path: Path
) -> None:
    """A record written before the allocator recorded a branch must not become a free pass.

    ***THE FALLBACK SHORT-CIRCUITS ON A MISSING BRANCH, AND THAT IS THE DIRECTION THAT MATTERS.***
    An absent field must refuse, never allow -- otherwise every pre-branch allocation in the registry
    would be committable from anywhere, which is the opposite of the gate's purpose.
    """
    write(repo, "docs/adr/0002-new.md", "# 0002 — New\n")
    write(
        repo,
        "docs/adr/README.md",
        README_HEAD + ROW.format(n="0002", slug="new", title="New") + "\n",
    )
    allocate(repo, "adr", "0002", worktree=tmp_path / "some-other-worktree", omit_branch=True)
    git(repo, "add", "-A")

    code, out = run_check(repo)
    assert code == 1
    assert "not allocated to this worktree" in out


# ----------------------------------------------------------------- restoring a number the base LOST


def lose_adr_0002(repo: Path) -> str:
    """Put ADR 0002 on the base, then take it away again, and return the bytes the base lost.

    This is the only state in which the restore carve-out (BACKLOG #1468) is reachable: the number is
    absent from the base's TIP and present in its HISTORY. Nothing in the gate polices an ADR deletion
    -- check_adrs says so outright, because git already prints one in the diffstat -- so a base can
    reach this state by a revert, a bad merge resolution, or a plain delete.
    """
    body = "# 0002 — Second\n\nThe decision.\n"
    write(repo, "docs/adr/0002-second.md", body)
    write(
        repo,
        "docs/adr/README.md",
        README_HEAD
        + ROW.format(n="0001", slug="first", title="First")
        + "\n"
        + ROW.format(n="0002", slug="second", title="Second")
        + "\n",
    )
    git(repo, "add", "-A")
    git(repo, "commit", "-qm", "add ADR 0002")
    git(repo, "rm", "-q", "docs/adr/0002-second.md")
    write(
        repo,
        "docs/adr/README.md",
        README_HEAD + ROW.format(n="0001", slug="first", title="First") + "\n",
    )
    git(repo, "add", "-A")
    git(repo, "commit", "-qm", "revert: drop ADR 0002")
    git(repo, "update-ref", "refs/remotes/origin/main", "HEAD")
    git(repo, "checkout", "-q", "-b", "restore-0002")
    # ***ASSERT THE PRECONDITION, BECAUSE git() ABOVE IS THE TOLERANT HELPER.*** Its own docstring
    # says a broken git is indistinguishable from a command with no output. Without this, a silently
    # no-op `git rm` leaves a repo where nothing was ever lost -- and the refusal arms below would
    # still pass, on the ORDINARY refusal, for a reason unrelated to what they claim to test.
    tip = git_read(repo, "ls-tree", "--name-only", "refs/remotes/origin/main", "docs/adr/")
    assert "0002-second.md" not in tip, f"0002 should be gone from the base tip, got: {tip}"
    past = git_read(repo, "rev-list", "refs/remotes/origin/main", "--", "docs/adr/0002-second.md")
    assert past.strip(), "0002 should still be reachable in the base's history"
    return body


def restore_the_index_row(repo: Path) -> None:
    write(
        repo,
        "docs/adr/README.md",
        README_HEAD
        + ROW.format(n="0001", slug="first", title="First")
        + "\n"
        + ROW.format(n="0002", slug="second", title="Second")
        + "\n",
    )


def test_restoring_the_exact_bytes_the_base_lost_is_allowed(repo: Path) -> None:
    """The row's whole subject: a number the base SPENT and then lost, put back as it was.

    Unowned and unallocated, deliberately -- the commonest restore is of an ADR that landed years
    before, whose allocating worktree was reaped the same week and whose claim record may never have
    existed. Requiring ownership here is what has no path: `alloc.ps1` would mint a SECOND number for
    a document that already has one, renumbering something already cited.
    """
    body = lose_adr_0002(repo)
    write(repo, "docs/adr/0002-second.md", body)
    restore_the_index_row(repo)
    git(repo, "add", "-A")

    code, out = run_check(repo)
    assert code == 0, out


def test_restoring_a_lost_number_with_DIFFERENT_bytes_is_refused(repo: Path) -> None:
    """The first mutation: same number, same path, content the base never carried there.

    ***THE REFUSAL TEXT IS THE ASSERTION, NOT THE EXIT CODE.*** A gate that cannot see refuses
    everything and scores exactly like a gate that works, so this pins WHICH refusal fired -- and it
    must be the restore one, not the ownership one, because the remedies differ and the ownership
    text ("a sibling session may be holding this number") is false of a number the base already spent.
    """
    lose_adr_0002(repo)
    write(repo, "docs/adr/0002-second.md", "# 0002 — Second\n\nA DIFFERENT decision.\n")
    restore_the_index_row(repo)
    git(repo, "add", "-A")

    code, out = run_check(repo)
    assert code == 1
    assert "is a RESTORE, but not of the bytes" in out
    assert "restore the file EXACTLY first" in out
    # It must NOT claim a sibling holds a number the base already spent -- that was the false half of
    # the old text. It must still offer the recover route, because a claim record can outlive the
    # commit that landed the number and still name a live tree.
    assert "a sibling session may be holding" not in out.lower()
    assert "if a claim record still names a live tree" in out.lower()


def test_restoring_lost_bytes_under_a_DIFFERENT_FILENAME_is_refused(repo: Path) -> None:
    """The second mutation: right bytes, right number, wrong path.

    Differently-NAMED files under one number is the exact signature the gate exists for, so the
    carve-out is anchored on the path as well as the bytes. Dropping the path anchor would let the
    collision walk straight through the restore door.
    """
    body = lose_adr_0002(repo)
    write(repo, "docs/adr/0002-second-thing.md", body)
    write(
        repo,
        "docs/adr/README.md",
        README_HEAD
        + ROW.format(n="0001", slug="first", title="First")
        + "\n"
        + ROW.format(n="0002", slug="second-thing", title="Second thing")
        + "\n",
    )
    git(repo, "add", "-A")

    code, out = run_check(repo)
    assert code == 1
    assert "is a RESTORE, but not of the bytes" in out


def test_the_refusal_never_builds_a_SHELL_COMMAND_from_the_staged_path(repo: Path) -> None:
    """A filename is attacker-influenceable, and this gate's deny text is read by an agent that acts.

    ***FOLDING IS NOT ESCAPING, AND AN EARLIER DRAFT CONFLATED THEM.*** `_safe_for_message` exists to
    stop a value forging a SECOND remedy block (BACKLOG #1040) -- it strips control characters. It does
    NOT quote, so `$( )`, backticks and `;` survive it intact. The draft printed
    `git checkout $(git rev-list -1 origin/main -- <path>)^ -- <path>` with the staged path spliced in,
    and `ADR_FILE` admits `[^/]+` before `.md`, so a crafted filename put a live command substitution
    inside a block the gate tells a reader to run.

    Pinned as an ABSENCE of the construction rather than a property of one filename: the remedy must
    not echo the staged path at all.
    """
    lose_adr_0002(repo)
    hostile = "docs/adr/0002-second$(id)`whoami`;echo.md"
    write(repo, hostile, "# 0002 — Second\n\nDifferent.\n")
    restore_the_index_row(repo)
    git(repo, "add", "-A")

    code, out = run_check(repo)
    assert code == 1
    # Pin WHICH refusal fired. Since BACKLOG #2002 the row rule also refuses this file (the row links
    # 0002-second.md), so `code == 1` alone would pass with the restore refusal gone.
    assert "is a RESTORE, but not of the bytes" in out
    # The refusal fired on the number, so the hostile basename must not appear in the remedy at all.
    assert "$(id)" not in out
    assert "`whoami`" not in out
    assert "git checkout $(" not in out


def test_a_TRUNCATED_history_refuses_with_its_own_text_rather_than_guessing(repo: Path) -> None:
    """A shallow clone cannot tell a restore from an invention, and must say so instead of choosing.

    ***AN EMPTY RESULT SET IS TWO DIFFERENT ANSWERS.*** Past a graft boundary `rev-list` reports no
    commits and exits 0, which is byte-identical to "the base never held this number". Answering the
    second on evidence for neither is how a genuine restore would have been steered into `alloc.ps1`
    -- the number-burn this whole carve-out exists to stop, reached through its own blind spot.

    Measured on a managed worktree of this repository: `--is-shallow-repository` is true and only 900
    commits are reachable from origin/main, so this is the live shape here, not a contrived one.
    """
    lose_adr_0002(repo)
    # Graft the history away: the ADR's commits become unreachable, the tip does not move.
    tip = git_read(repo, "rev-parse", "HEAD").strip()
    (repo / ".git" / "shallow").write_text(tip + "\n", encoding="utf-8")
    write(repo, "docs/adr/0002-second.md", "# 0002 — Second\n\nThe decision.\n")
    restore_the_index_row(repo)
    git(repo, "add", "-A")

    code, out = run_check(repo)
    assert code == 1
    assert "TRUNCATED" in out
    assert "--deepen" in out
    # It must not assert the base never held the number, which it cannot see.
    assert "is a RESTORE, but not of the bytes" not in out


def test_the_history_walk_is_BOUNDED_and_the_bound_is_reported(repo: Path) -> None:
    """The walk is capped, so past the cap a negative is ignorance -- and must not be worded as fact.

    Without this the bound is unpinned in both directions: lowering RESTORE_HISTORY_DEPTH to 0 leaves
    every other arm green except the two happy paths, and nothing would notice the refusal text quietly
    starting to claim "matches no blob its own path held" about revisions it never read.
    """
    source = CHECK.read_text(encoding="utf-8")
    m = re.search(r"^RESTORE_HISTORY_DEPTH = (\d+)$", source, re.M)
    assert m, "the bound must stay a named constant, not an inline literal"
    assert int(m.group(1)) > 0, "a bound of 0 silently disables the carve-out"

    # At a bound of 1 the walk saturates on a path with two revisions, so it must report TRUNCATED
    # rather than deny. Run against a patched copy so the real constant is not the thing under test.
    lose_adr_0002(repo)
    write(repo, "docs/adr/0002-second.md", "# 0002 — Second\n\nThe decision.\n")
    restore_the_index_row(repo)
    git(repo, "add", "-A")
    patched = repo / "ledger_check_bounded.py"
    patched.write_text(
        re.sub(r"^RESTORE_HISTORY_DEPTH = \d+$", "RESTORE_HISTORY_DEPTH = 1", source, flags=re.M),
        encoding="utf-8",
    )
    proc = subprocess.run(
        [sys.executable, str(patched)], cwd=repo, capture_output=True, text=True, check=False
    )
    assert proc.returncode == 1
    assert "TRUNCATED" in proc.stdout + proc.stderr


def test_a_number_the_base_NEVER_held_is_still_refused_unallocated(repo: Path) -> None:
    """The third mutation, and the one that proves the carve-out did not widen into the ordinary case.

    0003 was never on the base at all, so no history read can excuse it and the ownership rule must
    still bite with its ORIGINAL text. This is the arm that fails first if the predicate is ever
    loosened from "these bytes at this path" to "this number looks historical".
    """
    lose_adr_0002(repo)
    write(repo, "docs/adr/0003-third.md", "# 0003 — Third\n")
    write(
        repo,
        "docs/adr/README.md",
        README_HEAD
        + ROW.format(n="0001", slug="first", title="First")
        + "\n"
        + ROW.format(n="0003", slug="third", title="Third")
        + "\n",
    )
    git(repo, "add", "-A")

    code, out = run_check(repo)
    assert code == 1
    assert "not allocated to this worktree" in out
    assert "not with the bytes" not in out


def test_a_number_still_ON_the_base_is_a_collision_not_a_restore(repo: Path) -> None:
    """The carve-out is unreachable while the base still carries the number, and must stay so.

    ***IT NEEDS AN INPUT BOTH RULES WOULD ACCEPT, AND TWO EARLIER DRAFTS DID NOT PRODUCE ONE.*** The
    first staged `0001-first-again.md`, a path with no history, so the carve-out's PATH anchor refused
    it whatever the order was. The second re-added the base's own declared file, which the collision
    rule correctly ALLOWS as the file its index row already names -- so neither could detect the
    reordering it claimed to pin.

    The discriminating input is a SECOND file at a live number, undeclared by its row, whose path and
    bytes the base's history does carry. The collision rule must refuse it; the carve-out, if it were
    ever consulted first, would grant it. A restore door that opens on a LIVE number is the original
    defect with a new name.
    """
    alt = "# 0001 — First, alternate take\n"
    write(repo, "docs/adr/0001-alt.md", alt)
    git(repo, "add", "-A")
    git(repo, "commit", "-qm", "a second file under 0001")
    git(repo, "rm", "-q", "docs/adr/0001-alt.md")
    git(repo, "commit", "-qm", "drop the alternate")
    git(repo, "update-ref", "refs/remotes/origin/main", "HEAD")
    git(repo, "checkout", "-q", "-b", "readd-0001-alt")
    write(repo, "docs/adr/0001-alt.md", alt)
    git(repo, "add", "-A")

    # The number is LIVE on the base, and the staged bytes are ones its own path once carried --
    # i.e. the carve-out's condition is satisfied and must not be reached.
    assert "0001-first.md" in git_read(
        repo, "ls-tree", "--name-only", "refs/remotes/origin/main", "docs/adr/"
    ), "the base must still carry 0001, or this is not the collision case"

    code, out = run_check(repo)
    assert code == 1
    assert "ADR 0001 already exists" in out
    assert "is a RESTORE" not in out


def test_a_revert_of_the_commit_that_dropped_an_adr_is_committable(repo: Path) -> None:
    """The likeliest real shape, staged by git itself rather than by this test.

    `git revert` re-adds the file with the parent's bytes, which is a restore by construction -- and
    it is an ADD with no MERGE_HEAD, so the merge-parent carve-out cannot reach it. Built through the
    real verb because a hand-written equivalent would be testing this file's idea of a revert.
    """
    lose_adr_0002(repo)
    dropped = git_read(repo, "rev-parse", "refs/remotes/origin/main").strip()
    git(repo, "revert", "--no-commit", dropped)
    staged = git_read(repo, "diff", "--cached", "--name-status")
    assert "A\tdocs/adr/0002-second.md" in staged, staged

    code, out = run_check(repo)
    assert code == 0, out


def test_the_restore_carve_out_does_not_run_in_CI(repo: Path) -> None:
    """CI never reaches it, so a shallow runner cannot be asked a question it has no history for.

    The carve-out sits inside the `not self.ci` ownership arm that CI already skips (a fresh runner
    has no allocation store, so every ADR would read as unowned). Pinned because the reasoning behind
    added_files() -- shallow checkouts, `fatal: no merge base` -- would apply to a history walk if one
    ever ran there, and the reason it does not is a line of code, not a property of git.

    ***IT STAGES THE CASE THE LOCAL GATE REFUSES, AND THAT IS WHAT MAKES IT DISCRIMINATE.*** Asserting
    that CI accepts a VALID restore proves nothing -- CI accepts that with the carve-out disabled too,
    which a mutation run confirmed. Restoring with the WRONG bytes separates them: the local gate
    refuses it (see the DIFFERENT_bytes arm), so a green CI here can only mean CI consulted neither
    the ownership rule nor the carve-out.
    """
    lose_adr_0002(repo)
    write(repo, "docs/adr/0002-second.md", "# 0002 — Second\n\nA DIFFERENT decision.\n")
    restore_the_index_row(repo)
    git(repo, "add", "-A")
    git(repo, "commit", "-qm", "restore ADR 0002")

    code, out = run_check(repo, "--ci")
    assert code == 0, out


# ----------------------------------------------------------------- the dropped-row defect (0077/0079/0080)


def test_a_new_adr_with_no_index_row_is_blocked(repo: Path) -> None:
    """Three real ADRs shipped with no index row. The tail-append hazard shows up as a DROPPED ROW."""
    write(repo, "docs/adr/0002-new.md", "# 0002 — New\n")
    allocate(repo, "adr", "0002")
    git(repo, "add", "-A")

    code, out = run_check(repo)
    assert code == 1
    assert "no row in docs/adr/README.md" in out


def test_a_new_adr_whose_row_names_ANOTHER_file_is_blocked(repo: Path) -> None:
    """BACKLOG #2002. The gate asked only whether the new number HAD a row, never what it named.

    Allocated, and 0002 has a row, so before the fix this exited 0 with 0002-new.md unindexed.
    """
    write(repo, "docs/adr/0002-new.md", "# 0002 -- New\n")
    write(
        repo,
        "docs/adr/README.md",
        README_HEAD
        + ROW.format(n="0001", slug="first", title="First")
        + "\n"
        + ROW.format(n="0002", slug="something-else", title="New")
        + "\n",
    )
    allocate(repo, "adr", "0002")
    git(repo, "add", "-A")

    code, out = run_check(repo)
    assert code == 1, out
    assert "ADR 0002's row in docs/adr/README.md does not link the 0002 file" in out


def test_a_new_adr_whose_row_names_ANOTHER_file_is_blocked_in_CI_mode(repo: Path) -> None:
    """BACKLOG #2002, the --ci backstop. CI skips ownership, never the row rule."""
    write(repo, "docs/adr/0002-new.md", "# 0002 -- New\n")
    write(
        repo,
        "docs/adr/README.md",
        README_HEAD
        + ROW.format(n="0001", slug="first", title="First")
        + "\n"
        + ROW.format(n="0002", slug="something-else", title="New")
        + "\n",
    )
    git(repo, "add", "-A")
    git(repo, "commit", "-qm", "new ADR, wrong row")

    code, out = run_check(repo, "--ci")
    assert code == 1, out
    assert "does not link the 0002 file" in out


def test_a_reused_base_number_gets_ONE_refusal_not_two(repo: Path) -> None:
    """BACKLOG #2002. The row-names-file rule is scoped to NEW numbers: a base number already got it
    as the companion question, and a second block for the same file would only repeat that one."""
    write(repo, "docs/adr/0001-second-thing.md", "# 0001 -- Second\n")
    git(repo, "add", "-A")

    code, out = run_check(repo)
    assert code == 1, out
    assert "ADR 0001 already exists" in out
    assert "does not link the 0001 file" not in out


def test_a_pre_existing_unindexed_adr_does_not_block_unrelated_commits(repo: Path) -> None:
    """Old debt must not fail every future commit — that is how a gate gets uninstalled."""
    write(repo, "docs/adr/0009-legacy.md", "# 0009 — Legacy, never indexed\n")
    git(repo, "add", "-A")
    git(repo, "commit", "-qm", "legacy debt")
    git(repo, "update-ref", "refs/remotes/origin/main", "HEAD")

    write(repo, "README.md", "unrelated change\n")
    git(repo, "add", "README.md")

    code, out = run_check(repo)
    assert code == 0, out


def test_duplicate_index_rows_are_blocked(repo: Path) -> None:
    write(repo, "docs/adr/0002-new.md", "# 0002 — New\n")
    write(
        repo,
        "docs/adr/README.md",
        README_HEAD
        + ROW.format(n="0002", slug="new", title="New")
        + "\n"
        + ROW.format(n="0002", slug="new", title="New again")
        + "\n",
    )
    allocate(repo, "adr", "0002")
    git(repo, "add", "-A")

    code, out = run_check(repo)
    assert code == 1
    assert "duplicate index row" in out


def test_a_companion_declared_in_a_row_written_WITHOUT_the_space_is_allowed(repo: Path) -> None:
    """BACKLOG #2003. The row-counting pattern already took `|[0001]`; the row finder did not.

    Before the fix index_row returned "" for this row, so the declared companion read as an undeclared
    reuse of 0001 and was refused, while the has-a-row test counted the same row. One pattern now.
    """
    write(repo, "docs/adr/0001-first-increment-2.md", "# 0001 -- First, increment 2\n")
    row = (
        "|[0001](0001-first.md) | First. Companion: "
        "[0001-first-increment-2](0001-first-increment-2.md) | Accepted |"
    )
    write(repo, "docs/adr/README.md", README_HEAD + row + "\n")
    allocate(repo, "adr", "0001")
    git(repo, "add", "-A")

    code, out = run_check(repo)
    assert code == 0, out


def test_a_row_split_across_a_newline_after_the_pipe_is_not_a_row(repo: Path) -> None:
    """BACKLOG #2003. `\\s*` under re.M crossed a newline, so a bare `|` line counted the next line.

    index_row reads one line at a time and never saw such a "row", so the two disagreed. With the
    shared pattern neither sees it, and the new ADR has no row.
    """
    write(repo, "docs/adr/0002-new.md", "# 0002 -- New\n")
    write(
        repo,
        "docs/adr/README.md",
        README_HEAD
        + ROW.format(n="0001", slug="first", title="First")
        + "\n|\n[0002](0002-new.md) | New | Accepted |\n",
    )
    allocate(repo, "adr", "0002")
    git(repo, "add", "-A")

    code, out = run_check(repo)
    assert code == 1, out
    assert "ADR 0002 (0002-new.md) has no row" in out


# ----------------------------------------------------------------- BACKLOG numbers


def test_an_allocated_backlog_number_passes(repo: Path) -> None:
    write(
        repo, "docs/BACKLOG.md", "# Backlog\n\n## 1. First item\n\nbody\n\n## 1001. Mine\n\nbody\n"
    )
    allocate(repo, "backlog", "1001")
    git(repo, "add", "docs/BACKLOG.md")

    code, out = run_check(repo)
    assert code == 0, out


def test_editing_backlog_without_adding_a_number_passes(repo: Path) -> None:
    write(repo, "docs/BACKLOG.md", "# Backlog\n\n## 1. First item\n\nbody, now edited\n")
    git(repo, "add", "docs/BACKLOG.md")

    code, out = run_check(repo)
    assert code == 0, out


# ------------------------------------------------- the REVERSE arm: a number that DISAPPEARS (#1470)
#
# Everything above asks which numbers APPEARED. An item is destroyed by losing its `## N.` heading,
# which adds no number at all: the banner, the fields and the body stay in the file, re-attributed to
# the item ABOVE. That happened on 642225f78 and reached main with every wired gate green.
#
# Each must-fire arm below is paired with a must-NOT-fire arm exercising the SAME machinery, because a
# rule of this shape has two ways to be useless and the tests for them do not overlap: one that never
# fires is invisible, and one that fires on a stale branch or on a moving main reddens a REQUIRED leg
# for everybody.


def test_moving_an_item_into_the_ARCHIVE_is_not_a_deletion(repo: Path) -> None:
    """Retirement is the sanctioned way an item leaves docs/BACKLOG.md, and it must stay silent.

    The number space is the UNION of the live file and the archive, so a verbatim move keeps the id in
    the set on both sides. Without that union this rule would refuse every retirement in the repo.
    """
    write(repo, "docs/BACKLOG.md", "# Backlog\n")
    write(
        repo,
        "docs/archive/backlog/BACKLOG-CLOSED.md",
        "# Closed\n\n## 1. First item\n\nbody\n",
    )
    git(repo, "add", "-A")

    code, out = run_check(repo)
    assert code == 0, out


def test_a_number_this_branch_INVENTED_and_then_withdrew_is_not_a_deletion(repo: Path) -> None:
    """`git commit --amend` taking back an item you filed one commit ago must not read as destruction.

    The parent carries #1001 and the index does not, which is byte-for-byte the shape the arm above
    refuses. What separates them is the `& base` intersection in `_item_sets`: #1001 never reached
    origin/main, so nothing shared was lost.

    ***MAIN MUST MOVE AHEAD HERE, AND THAT IS THE WHOLE RIG RATHER THAN SCENERY.*** The first version
    of this test left `base - head` EMPTY, which short-circuits the reverse arm before `prior` is
    computed at all -- so it passed without the intersection ever running, and `& base` could have
    been deleted as redundant with all 50 tests green. Proven by deleting it: with this rig the test
    goes red naming #1001, and restoring it goes green. Keep #1002 on origin/main, or this test stops
    testing anything.
    """
    # origin/main gains #1002, so `base - head` is non-empty and the reverse arm actually runs.
    git(repo, "checkout", "-q", "-b", "sibling")
    write(
        repo,
        "docs/BACKLOG.md",
        "# Backlog\n\n## 1. First item\n\nbody\n\n## 1002. Theirs\n\nbody\n",
    )
    git(repo, "commit", "-qam", "somebody else files 1002")
    git(repo, "update-ref", "refs/remotes/origin/main", "sibling")
    git(repo, "checkout", "-q", "main")

    write(
        repo, "docs/BACKLOG.md", "# Backlog\n\n## 1. First item\n\nbody\n\n## 1001. Mine\n\nbody\n"
    )
    allocate(repo, "backlog", "1001")
    git(repo, "add", "docs/BACKLOG.md")
    git(repo, "commit", "-qm", "file 1001 -- NOT pushed, so origin/main never sees it")

    write(repo, "docs/BACKLOG.md", "# Backlog\n\n## 1. First item\n\nbody\n")
    git(repo, "add", "docs/BACKLOG.md")

    code, out = run_check(repo)
    assert code == 0, out
    assert "1001" not in out, (
        "#1001 is on the parent and NOT on origin/main, so the `& base` intersection must drop it; "
        f"reporting it means the intersection is gone:\n{out}"
    )


def test_main_MOVING_AHEAD_is_not_a_deletion_by_this_change(repo: Path, tmp_path: Path) -> None:
    """The false positive that would have reddened a REQUIRED leg for everybody.

    A two-way comparison cannot see WHICH SIDE MOVED. In `--ci`, HEAD is the merge ref computed when
    the event fired and origin/main is fetched when the job starts, so anything that lands in between
    is in base and not in head. A rule reading `base - head` reports somebody else's landed item as
    destroyed by this pull request; under a merge queue that window is minutes wide.

    The arm asks the commit's own PARENTS instead, so main advancing afterwards changes nothing. This
    test is the guard on that choice: swap `prior` back to `base` and it goes red.
    """
    # This change: an ordinary edit that deletes nothing.
    write(repo, "docs/BACKLOG.md", "# Backlog\n\n## 1. First item\n\nbody, now edited\n")
    git(repo, "add", "docs/BACKLOG.md")
    git(repo, "commit", "-qm", "edit a body")

    # Meanwhile, somebody else's item lands on main -- AFTER the commit under test was written.
    other = tmp_path / "other"
    git(repo, "worktree", "add", "-q", "-b", "sibling", str(other), "refs/remotes/origin/main")
    write(
        other,
        "docs/BACKLOG.md",
        "# Backlog\n\n## 1. First item\n\nbody\n\n## 1002. Theirs\n\nbody\n",
    )
    git(other, "add", "docs/BACKLOG.md")
    git(other, "commit", "-qm", "somebody else files 1002", "--no-verify")
    git(repo, "update-ref", "refs/remotes/origin/main", "sibling")

    code, out = run_check(repo, "--ci")
    assert code == 0, f"main moving ahead is not this change deleting anything; got:\n{out}"


def test_a_rewrite_that_changes_no_heading_scores_nothing(repo: Path) -> None:
    """The negative control the detector must pass: rewrite the file, keep every id, stay silent.

    A rule that plants a violation has to REFUSE to score a plant that did not change the item set --
    otherwise the must-fire arm above is satisfied by a detector that simply always fires.
    """
    write(
        repo,
        "docs/BACKLOG.md",
        "# Backlog\n\nA new preamble paragraph.\n\n## 1. First item\n\nan entirely rewritten body\n",
    )
    git(repo, "add", "docs/BACKLOG.md")

    code, out = run_check(repo)
    assert code == 0, out


# ------------------------------------------- item identity is the PARSER's, not a regex kept in here


def test_a_SUB_heading_inside_a_body_is_not_an_item(repo: Path) -> None:
    """`### N.` is a sub-heading, and the gate must not police it as a number in either direction.

    This file used to scan with its own `^#{2,3} (\\d+)\\.` regex -- a second definition of item
    identity beside `backlog_status_check.parse_items`, which CLAUDE.md section 11 names as the single
    source. Against the real ledger the two readings return the same 746 ids, so this is the arm that
    can tell them apart: under the old regex `### 9999.` is an unallocated item and the commit is
    refused; under the parser it is prose.
    """
    write(
        repo,
        "docs/BACKLOG.md",
        "# Backlog\n\n## 1. First item\n\nbody\n\n### 9999. a sub-heading, not an item\n\nmore body\n",
    )
    git(repo, "add", "docs/BACKLOG.md")

    code, out = run_check(repo)
    assert code == 0, out
    assert "9999" not in out, out


def test_conflict_markers_QUOTED_IN_PROSE_do_not_trip_the_refusal(repo: Path) -> None:
    """Item #1257 quotes all three markers inline in backticks, so a substring test calls it corrupt.

    The parser anchors on a line start, and this pins that: a gate that refuses the ledger for
    describing a conflict is one every seat learns to bypass.
    """
    write(
        repo,
        "docs/BACKLOG.md",
        "# Backlog\n\n## 1. First item\n\nresolve a `<<<<<<< HEAD` / `=======` / `>>>>>>> theirs` "
        "block by hand\n",
    )
    git(repo, "add", "docs/BACKLOG.md")

    code, out = run_check(repo)
    assert code == 0, out


# ----------------------------------------------------------------- encoding


# The real docs/BACKLOG.md and docs/adr/README.md are full of em-dashes, ✅ and ⚠️. Every other test in
# this file writes pure ASCII, which is exactly why this shipped broken: `git(...)` used `text=True` with
# NO `encoding=`, so it decoded git's output with the LOCALE default — cp1252 on Windows. The decode blew
# up inside subprocess's reader thread, `proc.stdout` came back **None**, and the caller died on
# `findall(None)`, blocking every commit that touched either ledger file.
NON_ASCII_BODY = "body — with an em-dash, ✅ a check, ⚠️ a warning, and a ≥ sign\n"


def test_a_utf8_backlog_does_not_crash_the_gate(repo: Path) -> None:
    """A non-ASCII ledger must parse. The gate's own crash was the failure mode it exists to prevent."""
    write(repo, "docs/BACKLOG.md", f"# Backlog\n\n## 1. First item\n\n{NON_ASCII_BODY}")
    git(repo, "add", "docs/BACKLOG.md")

    code, out = run_check(repo)
    assert code == 0, out
    assert "Traceback" not in out
    assert "UnicodeDecodeError" not in out


def test_ci_mode_works_on_a_SHALLOW_clone_with_no_reachable_merge_base(
    repo: Path, tmp_path: Path
) -> None:
    """The live CI failure: a shallow checkout has no common ancestor, so a THREE-dot diff dies with
    `fatal: no merge base` — and because git() used to swallow that, the gate reported PASS on every run
    where it could not see. It must now still CATCH the reused number from a depth-1 clone."""
    # main gains an ADR; the "PR" adds a DIFFERENT file under the SAME number — the real collision shape.
    write(repo, "docs/adr/0002-theirs.md", "# 0002 — Theirs\n")
    write(
        repo,
        "docs/adr/README.md",
        README_HEAD
        + ROW.format(n="0001", slug="first", title="First")
        + "\n"
        + ROW.format(n="0002", slug="theirs", title="Theirs")
        + "\n",
    )
    git(repo, "add", "-A")
    git(repo, "commit", "-qm", "main takes 0002")
    git(repo, "update-ref", "refs/remotes/origin/main", "HEAD")

    # A depth-1 clone: HEAD has NO history, so `origin/main...HEAD` cannot resolve an ancestor.
    shallow = tmp_path / "shallow"
    subprocess.run(
        ["git", "clone", "--depth=1", "--no-local", repo.as_uri(), str(shallow)],
        capture_output=True,
        check=True,
    )
    for k, v in (("user.email", "t@t"), ("user.name", "t"), ("commit.gpgsign", "false")):
        git(shallow, "config", k, v)
    assert (shallow / ".git" / "shallow").exists(), "clone was not shallow — test proves nothing"

    # The colliding session adds its OWN file under main's number. main's index row still names THEIRS —
    # which is what makes this a collision rather than a declared companion (cf. ADR 0013).
    write(shallow, "docs/adr/0002-mine.md", "# 0002 — Mine\n")
    git(shallow, "add", "-A")
    git(shallow, "commit", "-qm", "PR also takes 0002")

    code, out = run_check(shallow, "--ci")
    assert "no merge base" not in out, out
    assert "Traceback" not in out, out
    assert code == 1, f"the reused number must still be CAUGHT on a shallow clone:\n{out}"
    assert "ADR 0002 already exists" in out


def test_a_utf8_adr_index_does_not_crash_the_gate(repo: Path) -> None:
    write(repo, "docs/adr/0002-new.md", "# 0002 — New\n")
    write(
        repo,
        "docs/adr/README.md",
        README_HEAD
        + ROW.format(n="0001", slug="first", title="First — ✅ done")
        + "\n"
        + ROW.format(n="0002", slug="new", title="New — ⚠️ proposed")
        + "\n",
    )
    allocate(repo, "adr", "0002")
    git(repo, "add", "-A")

    code, out = run_check(repo)
    assert code == 0, out
    assert "Traceback" not in out


# ----------------------------------------------------------------- scope


def test_a_commit_touching_no_ledger_file_passes(repo: Path) -> None:
    write(repo, "messagefoundry/x.py", "x = 1\n")
    git(repo, "add", "-A")

    code, out = run_check(repo)
    assert code == 0, out


def test_ci_mode_skips_the_ownership_rule_but_still_catches_a_reused_number(repo: Path) -> None:
    """CI has no registry — but the stale-base collision is exactly what --ci exists to catch."""
    write(repo, "docs/adr/0002-new.md", "# 0002 — New\n")
    write(
        repo,
        "docs/adr/README.md",
        README_HEAD + ROW.format(n="0002", slug="new", title="New") + "\n",
    )
    git(repo, "add", "-A")
    git(repo, "commit", "-qm", "add 0002 without allocating")

    # unallocated, but properly indexed -> CI must not care about ownership
    code, out = run_check(repo, "--ci")
    assert code == 0, out

    # now reuse a number that already exists on the base -> CI must still block
    write(repo, "docs/adr/0001-collision.md", "# 0001 — Collision\n")
    git(repo, "add", "-A")
    git(repo, "commit", "-qm", "reuse 0001")

    code, out = run_check(repo, "--ci")
    assert code == 1
    assert "ADR 0001 already exists" in out


# ----------------------------------------------------- a path is a RECORD, not a word (BACKLOG #1871)
#
# The gate used to end every path read in `.split()`, which tears a filename at its space. Neither
# half matches ADR_FILE, so the file was invisible: no collision check, no index-row check. The
# regex was never at fault -- `[^/]+` matches a space -- the tear happened before it ran.
#
# PLAIN IS THE CONTROL. It passes before and after the fix, so a failure on SPACED is attributable
# to the space rather than to a fixture that staged nothing. ACCENTED is the core.quotePath case:
# under git's default, a non-ASCII path arrives C-quoted ("docs/adr/0192-caf\303\251.md") in
# line-oriented output, so splitting lines alone would still hide it. Reading NUL-terminated output
# with -z is what makes both arrive verbatim.

SPACED = "docs/adr/0190-with space.md"
PLAIN = "docs/adr/0191-nospace.md"
ACCENTED = "docs/adr/0192-café.md"


@pytest.fixture(scope="module")
def gate() -> ModuleType:
    """The hook loaded by path. It is a stdlib script, not a package."""
    spec = importlib.util.spec_from_file_location("ledger_check", CHECK)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _stage_the_three(repo: Path) -> None:
    # Pinned, not inherited: with quotePath off, line-oriented output would not quote ACCENTED, and a
    # regression to .splitlines() would pass this suite on that runner.
    git(repo, "config", "core.quotePath", "true")
    for rel in (SPACED, PLAIN, ACCENTED):
        write(repo, rel, "# ADR\n")
    git(repo, "add", "-A")


def test_added_files_keeps_a_path_with_a_SPACE_whole(
    repo: Path, gate: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    _stage_the_three(repo)
    monkeypatch.chdir(repo)

    seen = gate.Ledger(ci=False).added_files()

    assert PLAIN in seen, f"the control was not seen, so this fixture proves nothing: {seen}"
    assert SPACED in seen, f"a path holding a space was torn: {seen}"
    assert ACCENTED in seen, f"a non-ASCII path arrived quoted: {seen}"
    assert sorted(seen) == sorted([SPACED, PLAIN, ACCENTED]), f"stray fragments: {seen}"


def test_added_files_in_CI_mode_keeps_a_path_with_a_SPACE_whole(
    repo: Path, gate: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    _stage_the_three(repo)
    git(repo, "commit", "-qm", "three ADRs")
    monkeypatch.chdir(repo)

    seen = gate.Ledger(ci=True).added_files()

    assert PLAIN in seen, f"the control was not seen, so this fixture proves nothing: {seen}"
    assert SPACED in seen, f"a path holding a space was torn: {seen}"
    assert ACCENTED in seen, f"a non-ASCII path arrived quoted: {seen}"
    assert sorted(seen) == sorted([SPACED, PLAIN, ACCENTED]), f"stray fragments: {seen}"


def test_base_adr_numbers_keeps_a_path_with_a_SPACE_whole(
    repo: Path, gate: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The BASE side matters on its own: a torn base file is a number missing from the taken set."""
    _stage_the_three(repo)
    git(repo, "commit", "-qm", "three ADRs")
    git(repo, "update-ref", "refs/remotes/origin/main", "HEAD")
    monkeypatch.chdir(repo)

    taken = gate.Ledger(ci=False).base_adr_numbers()

    assert taken.get("0191") == "0191-nospace.md", f"the control was not seen: {taken}"
    assert taken.get("0190") == "0190-with space.md", f"a path holding a space was torn: {taken}"
    assert taken.get("0192") == "0192-café.md", f"a non-ASCII path arrived quoted: {taken}"
    assert taken == {
        "0001": "0001-first.md",
        "0190": "0190-with space.md",
        "0191": "0191-nospace.md",
        "0192": "0192-café.md",
    }, f"stray entries: {taken}"


def test_paths_refuses_output_that_was_not_NUL_terminated(gate: ModuleType) -> None:
    """A caller that forgets -z must fail loudly, not read every file as one bogus path."""
    assert gate._paths("") == []
    assert gate._paths("a b.md\0c.md\0") == ["a b.md", "c.md"]
    with pytest.raises(ValueError, match="-z"):
        gate._paths("docs/adr/0001-a.md\ndocs/adr/0002-b.md\n")


@pytest.mark.parametrize(
    "rel", ["docs/adr/0001-second thing.md", "docs/adr/0001-café.md"], ids=["space", "non-ascii"]
)
def test_reusing_a_base_number_under_an_ODD_filename_is_blocked(repo: Path, rel: str) -> None:
    """The collision itself, end to end, from the added side. Before the fix this exited 0."""
    git(repo, "config", "core.quotePath", "true")
    write(repo, rel, "# 0001 -- Second\n")
    git(repo, "add", "-A")

    code, out = run_check(repo)
    assert code == 1, out
    assert "ADR 0001 already exists" in out


def test_a_number_held_on_the_base_by_a_SPACED_filename_is_still_taken(repo: Path) -> None:
    """The collision from the BASE side. Allocated and indexed, so ONLY the collision rule can refuse."""
    write(repo, "docs/adr/0002-with space.md", "# 0002 -- Spaced\n")
    write(
        repo,
        "docs/adr/README.md",
        README_HEAD
        + ROW.format(n="0001", slug="first", title="First")
        + "\n"
        + ROW.format(n="0002", slug="with space", title="Spaced")
        + "\n",
    )
    git(repo, "add", "-A")
    git(repo, "commit", "-qm", "base gains a spaced ADR")
    git(repo, "update-ref", "refs/remotes/origin/main", "HEAD")

    write(repo, "docs/adr/0002-other.md", "# 0002 -- Other\n")
    allocate(repo, "adr", "0002")
    git(repo, "add", "-A")

    code, out = run_check(repo)
    assert code == 1, out
    assert "ADR 0002 already exists" in out


# --------------------------------------------------------------------------------------------------
# WIRING. Everything above tests the gate's LOGIC against a throwaway repo. None of it notices if the
# gate is never invoked -- and on 2026-07-27 that is exactly what happened: the ledger gate had to move
# out of .git/hooks/pre-commit because `pre-commit install` and install-git-hooks.ps1 both want that
# file, and their chaining fails on Windows. Logic tests stayed green throughout. These assert the gate
# is actually WIRED UP, which is the property that was silently lost.
# --------------------------------------------------------------------------------------------------

_CONFIG = Path(__file__).resolve().parents[1] / ".pre-commit-config.yaml"
_INSTALLER = Path(__file__).resolve().parents[1] / "scripts" / "coord" / "install-git-hooks.ps1"
_CI = Path(__file__).resolve().parents[1] / ".github" / "workflows" / "ci.yml"

#: The `--depth=N` in the ledger step's own fetch. Not a free-standing number: see the test below.
_FETCH_DEPTH = re.compile(r"--depth=(\d+)\s+origin\s+main")


def test_ADDING_a_backlog_that_the_base_lacks_is_not_a_wall_of_unallocated_numbers(
    tmp_path: Path,
) -> None:
    """docs/BACKLOG.md was gitignored until the cutover published it, so the base has no version of it.

    `git show base:docs/BACKLOG.md` exits 128 for that, which crashed the gate; and treating the missing
    base as an empty ledger is no better — every heading in the imported file then reads as a brand-new
    number and the gate reports ~229 items as 'not allocated to this worktree'. Numbers that do not
    exist on base cannot be collided with, so the correct answer is to police nothing.
    """
    r = tmp_path / "repo"
    r.mkdir()
    git(r, "init", "-q", "-b", "main")
    git(r, "config", "user.email", "t@t")
    git(r, "config", "user.name", "t")
    git(r, "config", "commit.gpgsign", "false")
    write(r, "README.md", "base with NO backlog\n")
    git(r, "add", "-A")
    git(r, "commit", "-qm", "base")
    git(r, "update-ref", "refs/remotes/origin/main", "HEAD")

    write(r, "docs/BACKLOG.md", "# Backlog\n\n## 7. Seven\n\nb\n\n## 42. Forty-two\n\nb\n")
    git(r, "add", "-A")
    code, out = run_check(r)
    assert code == 0, out
    assert "not allocated" not in out


def test_a_branch_that_PREDATES_the_backlog_is_not_a_ledger_violation(tmp_path: Path) -> None:
    """The mirror image of the case above, and it broke every open branch the hour BACKLOG.md landed.

    CI's change set is `diff base HEAD`. The moment origin/main gained docs/BACKLOG.md, every branch
    cut before that merge began listing the file as changed — as a DELETION relative to base — while
    its own HEAD had no copy. The rule then read HEAD for a file that was never there and died on
    `git show HEAD:docs/BACKLOG.md` (exit 128). A stale branch is not a number collision.
    """
    r = tmp_path / "repo"
    r.mkdir()
    git(r, "init", "-q", "-b", "main")
    git(r, "config", "user.email", "t@t")
    git(r, "config", "user.name", "t")
    git(r, "config", "commit.gpgsign", "false")
    write(r, "README.md", "no backlog yet\n")
    git(r, "add", "-A")
    git(r, "commit", "-qm", "root")
    root = git(r, "rev-parse", "HEAD").strip()

    # main moves on and PUBLISHES the backlog...
    write(r, "docs/BACKLOG.md", "# Backlog\n\n## 1. First\n\nb\n")
    git(r, "add", "-A")
    git(r, "commit", "-qm", "publish backlog")
    git(r, "update-ref", "refs/remotes/origin/main", "HEAD")

    # ...while this branch was cut BEFORE it and never touched the file.
    git(r, "checkout", "-q", "-b", "stale", root)
    write(r, "src.py", "x = 1\n")
    git(r, "add", "-A")
    git(r, "commit", "-qm", "unrelated work")

    code, out = run_check(r, "--ci")
    assert code == 0, out
    assert "BACKLOG" not in out


def test_an_unreachable_base_ref_never_reports_success(tmp_path: Path) -> None:
    """System-level property: an unresolvable base must never read as "nothing to check".

    SCOPE, honestly: this does NOT isolate ``base_has``'s own rev-parse guard. Removing that guard
    leaves this test green, because ``changed_files()``/``base_adr_numbers()`` already raise on the
    missing ref before the backlog rule is reached. The guard stays as defence-in-depth — if the
    backlog rule is ever reordered ahead of those calls, absence-probing would otherwise answer
    "absent" for an unfetched base and silently disable itself — but that path is not reachable
    today, so no test can currently pin it. Claiming otherwise would be the false assurance this
    gate exists to prevent.
    """
    r = tmp_path / "repo"
    r.mkdir()
    git(r, "init", "-q", "-b", "main")
    git(r, "config", "user.email", "t@t")
    git(r, "config", "user.name", "t")
    git(r, "config", "commit.gpgsign", "false")
    write(r, "docs/BACKLOG.md", "# Backlog\n\n## 3. Three\n\nb\n")
    git(r, "add", "-A")
    git(r, "commit", "-qm", "base")
    # NOTE: refs/remotes/origin/main is deliberately never created.
    code, out = run_check(r)
    assert code != 0, "a missing base ref must not read as 'nothing to check'"


# ------------------------------------------------------- a merge allocates nothing (BACKLOG #1441 case)
#
# The pair below is deliberately disjoint: the first arm reds if the gate refuses a merge that invents
# no number, the second reds if it stops policing during one. A single arm would pass on a gate that had
# simply been switched off while MERGE_HEAD exists, which is the mutation that matters here.


def _diverge_and_merge(repo: Path, tmp_path: Path, *, number: str) -> None:
    """Leave ``repo`` mid-merge, carrying ``number`` from a branch owned by ANOTHER worktree.

    `--no-commit --no-ff` is the whole point: a clean merge auto-commits and tears down MERGE_HEAD, so
    the state the hook actually runs in would never be reached.
    """
    git(repo, "checkout", "-q", "-b", "sibling")
    backlog = (repo / "docs/BACKLOG.md").read_text(encoding="utf-8")
    write(repo, "docs/BACKLOG.md", backlog + f"\n## {number}. From a sibling worktree\n\nbody\n")
    git(repo, "add", "-A")
    # Allocated to the SIBLING while it is the one committing, so this commit is legal there...
    allocate(repo, "backlog", number, worktree=repo, branch="sibling")
    git(repo, "commit", "-qm", f"sibling files #{number}")
    # ...and then re-pointed at a worktree that is not this one, which is the real situation: the
    # allocation record belongs to the session that filed it, and the merger is somebody else.
    allocate(repo, "backlog", number, worktree=tmp_path / "somewhere-else", branch="sibling")

    git(repo, "checkout", "-q", "main")
    write(repo, "docs/unrelated.md", "a file that does not collide\n")
    git(repo, "add", "-A")
    git(repo, "commit", "-qm", "main moves on")
    git(repo, "merge", "--no-commit", "--no-ff", "sibling")


def test_a_merge_carrying_ANOTHER_worktrees_number_is_committable(
    repo: Path, tmp_path: Path
) -> None:
    """The measured case: a Lander resolving a docs/BACKLOG.md tail conflict on somebody else's PR.

    Before this, the gate refused it -- the number is real, allocated and committed, just not HERE --
    and its remedy named a worktree the worktree gate forbids the merger from entering.
    """
    _diverge_and_merge(repo, tmp_path, number="1441")

    code, out = run_check(repo)
    assert code == 0, f"a merge that allocates nothing must commit; got:\n{out}"
    assert "1441" not in out

    # DELIBERATELY NOT asserted here: that 1441 is absent from the message. It is true, and it belongs
    # to the arm above. Asserting it here made both arms red under the same mutation, which is exactly
    # the overlap that stops a pair from localising a failure -- caught by running the mutation.


def test_MAIN_merged_INTO_another_seats_branch_is_committable(repo: Path, tmp_path: Path) -> None:
    """The direction the first fix MISSED, and the one a Lander actually resolves.

    ***THE TWO DIRECTIONS ARE NOT SYMMETRIC AND THE FIRST VERSION ONLY HANDLED ONE.*** Merging their
    branch into mine puts their number on MERGE_HEAD. Merging main into THEIRS puts it on HEAD, and a
    rule that reads only MERGE_HEAD refuses it. The arm above covers the first; without this one the
    pair passed while the measured PR 850 case stayed broken -- two mutations proved those arms
    disjoint FROM EACH OTHER, which says nothing about whether either points at the real shape.

    ***THE MERGER MUST BE ON A DIFFERENTLY-NAMED BRANCH, AND THAT IS NOT INCIDENTAL.*** git refuses
    an ORDINARY second checkout of one branch in two worktrees (a DEFAULT, not a law of git;
    `Ledger.owns` records what defeats it, BACKLOG #1039), so a merger does not stand on the author's
    branch -- it cuts its own from theirs, exactly as `lander-fix/850` was cut. Stay on the author's
    branch NAME and `owns()`'s branch fallback (BACKLOG #1282) returns True, so the run passes for a
    reason unrelated to merging.
    The first reproduction of this did precisely that and reported a false all-clear.
    """
    git(repo, "checkout", "-q", "-b", "sibling")
    backlog = (repo / "docs/BACKLOG.md").read_text(encoding="utf-8")
    write(repo, "docs/BACKLOG.md", backlog + "\n## 1441. Filed by the sibling\n\nbody\n")
    allocate(repo, "backlog", "1441", worktree=repo, branch="sibling")
    git(repo, "commit", "-qam", "sibling files #1441")

    # ***MAIN MUST TOUCH docs/BACKLOG.md TOO, OR THIS TEST PASSES VACUOUSLY.*** check_backlog()
    # returns early unless the STAGED diff contains a ledger file. If main moves only in some other
    # file, the merge stages only that file, the rule is never reached, and the arm reports success
    # without having exercised anything. The first version of this test did exactly that: it passed
    # under a mutation that restored the very bug it was written to catch.
    git(repo, "checkout", "-q", "main")
    backlog = (repo / "docs/BACKLOG.md").read_text(encoding="utf-8")
    write(repo, "docs/BACKLOG.md", backlog + "\n## 1440. Filed on main\n\nbody\n")
    allocate(repo, "backlog", "1440", worktree=repo, branch="main")
    git(repo, "commit", "-qam", "main files #1440")
    git(repo, "update-ref", "refs/remotes/origin/main", "HEAD")

    # The number now belongs to a worktree that is not this one AND a branch this one is not on.
    allocate(repo, "backlog", "1441", worktree=tmp_path / "somewhere-else", branch="sibling")

    git(repo, "checkout", "-q", "-b", "lander-fix/850", "sibling")
    git(repo, "merge", "--no-commit", "--no-ff", "origin/main")
    # ***THE MERGE CONFLICTS, AND THE RESOLUTION HAS TO BE WRITTEN OUT.*** Both sides appended at the
    # tail of docs/BACKLOG.md, which is the very conflict a Lander is here to resolve. `git add -A`
    # alone stages the file WITH its markers still in it -- a state no commit should ever reach, and
    # one the gate now refuses outright rather than scan (`parse_items` will not read a conflicted
    # source, because a conflicted ledger parses into a census counting items from BOTH sides). This
    # test is about the OWNERSHIP question, so the conflict is resolved the way a Lander resolves it
    # -- keep both items -- and the ownership rule then gets a file it can actually read.
    write(
        repo,
        "docs/BACKLOG.md",
        "# Backlog\n\n## 1. First item\n\nbody\n"
        "\n## 1441. Filed by the sibling\n\nbody\n"
        "\n## 1440. Filed on main\n\nbody\n",
    )
    git(repo, "add", "-A")

    code, out = run_check(repo)
    assert code == 0, f"main merged into another seat's branch must commit; got:\n{out}"


def _ledger_hook() -> dict[str, object]:
    """The ledger-gate entry from .pre-commit-config.yaml, or fail loudly.

    Plain import, deliberately NOT pytest.importorskip: pyyaml is pinned in requirements.lock and
    constraints.lock, so it is always present where CI runs. importorskip would turn a missing
    dependency into a silent SKIP — and a wiring test that skips is exactly the failure this test
    exists to catch.
    """
    import yaml

    cfg = yaml.safe_load(_CONFIG.read_text(encoding="utf-8"))
    for repo in cfg["repos"]:
        for hook in repo.get("hooks", []):
            if hook.get("id") == "ledger-gate":
                return hook
    raise AssertionError(
        "no 'ledger-gate' hook in .pre-commit-config.yaml — the ledger gate is NOT wired up, and every "
        "logic test above still passes"
    )


def test_the_ledger_gate_is_wired_into_pre_commit() -> None:
    hook = _ledger_hook()
    assert "ledger_check.py" in str(hook["entry"]), hook["entry"]
    # It inspects the staged TREE (which ADR/BACKLOG numbers the commit introduces), not a file list,
    # so it must run even when no file it "owns" changed. Without always_run a commit that touches only
    # unrelated files would skip the gate entirely.
    assert hook.get("always_run") is True, "ledger-gate must be always_run"
    assert hook.get("pass_filenames") is False, "ledger-gate must not be given a file list"


def test_the_installer_no_longer_writes_a_pre_commit_hook() -> None:
    """The contention must stay impossible, not merely resolved once.

    If install-git-hooks.ps1 starts writing .git/hooks/pre-commit again, the next `pre-commit install`
    chains to pre-commit.legacy and — on Windows — blocks every commit in the repo.
    """
    src = _INSTALLER.read_text(encoding="utf-8")
    assert "WriteAllText($preCommit" not in src, (
        "install-git-hooks.ps1 writes a pre-commit hook again — that re-creates the two-owner conflict"
    )
    # ...and it must still MIGRATE an old standalone install away, or upgrading users stay broken.
    assert "Remove-Item -LiteralPath $preCommit" in src, (
        "the installer must remove a previously-installed standalone ledger hook"
    )


def test_the_CI_ledger_step_fetches_DEEPER_THAN_ONE() -> None:
    """The reverse arm's CI coverage depends on this fetch depth, and nothing else pins it.

    ***THE DEPENDENCY IS NEW AND IT IS INVISIBLE AT THE SITE THAT MATTERS.*** `actions/checkout` takes
    `refs/pull/N/merge` at its default depth of 1, so HEAD is a shallow GRAFT whose parent objects are
    absent. The arm reads those parents; the base tip arrives ONLY because this step runs
    `git fetch --no-tags --depth=200 origin main` before invoking the gate. Trim that to `--depth=1`
    as a plausible speedup and the arm stops being able to see anything -- and it would go SILENT
    rather than red, which is the exact failure shape this whole item exists to catch.

    Until this test existed the dependency lived in a comment beside the fetch. A comment cannot fail.

    The depth is asserted as a FLOOR, not pinned to 200: the number is a judgement about how far main
    can move, and re-tuning it is legitimate. Dropping to 1 is not.
    """
    import yaml

    cfg = yaml.safe_load(_CI.read_text(encoding="utf-8"))
    steps = [
        s
        for job in cfg["jobs"].values()
        for s in job.get("steps", [])
        if "Ledger gate" in str(s.get("name", ""))
    ]
    assert len(steps) == 1, f"expected exactly one ledger-gate step in ci.yml, found {len(steps)}"
    run = str(steps[0]["run"])

    assert "ledger_check.py --ci" in run, (
        f"the ledger-gate step no longer invokes the gate -- this test is now vacuous:\n{run}"
    )
    depths = [int(d) for d in _FETCH_DEPTH.findall(run)]
    assert depths, (
        "the ledger-gate step no longer fetches origin main with an explicit --depth. If the "
        f"checkout became deep, say so here rather than deleting the assertion:\n{run}"
    )
    assert min(depths) > 1, (
        f"--depth={min(depths)} leaves HEAD's parents unfetched, and the reverse arm (BACKLOG #1470) "
        "reads them. At depth 1 it goes SILENT, not red."
    )


_ALLOC = Path(__file__).resolve().parents[1] / "scripts" / "coord" / "alloc.ps1"

# Kept deliberately identical to the pattern in scripts/coord/alloc.ps1 — the point of this test is to
# fail the moment the two drift. A duplicated regex that is TESTED is not the same hazard as a
# duplicated value that is not: this one fails loudly on drift, which is the property being bought.
_FLOOR_RE = re.compile(r"(?m)^PUBLIC_BACKLOG_FLOOR\s*(?::[^=]+)?=\s*(\d+)")


# --- the partition guard must never again read the whole-set maximum -------------------------------
#
# On 2026-08-03 filing BACKLOG #1000 -- the FIRST legitimate item in the post-partition public sequence
# -- made every backlog allocation in the repository throw:
#
#     REFUSING TO ALLOCATE. The all-refs backlog maximum (1000) has reached the public floor (1000).
#
# One number was serving two incompatible purposes. The emit start wants the maximum over EVERYTHING so
# a number is never re-issued; the residual detector wants the maximum of the maintainer-internal
# sequence, to see it running out of room below the partition. The detector read the union, so a public
# item sitting where public items are SUPPOSED to sit read as a breach. The guard fired on correct input.
#
# These are source-text assertions, matching the seam above, and deliberately so: executing the
# allocator to test it would either spend a real number (claims are never released -- "holes are free,
# collisions are not") or write to .git/mefor-coord/alloc/**, and a test that mutates the ledger
# registry to check the ledger registry is its own hazard.


def test_the_allocator_measures_the_partition_band_separately() -> None:
    """`Get-Floor` must return BOTH numbers, or the conflation is available to be made again."""
    src = _ALLOC.read_text(encoding="utf-8")
    assert "SubFloorMax" in src, (
        "alloc.ps1 no longer computes a sub-partition maximum. The residual detector needs the highest "
        "number BELOW the floor; if it reads the whole-set maximum instead, the first public item at "
        "the boundary bricks every backlog allocation (this happened, with BACKLOG #1000)."
    )
    assert "Floor       =" in src or "Floor =" in src, (
        "alloc.ps1's Get-Floor must still return the whole-set Floor for the emit start — without it "
        "the allocator can re-issue a number that already exists."
    )


# --- EXECUTION tests: the allocator is actually RUN, in a throwaway repo ---------------------------
#
# Nothing in tests/ had ever executed alloc.ps1. The two references above are `read_text()` assertions,
# and they stayed green through the entire period the allocator refused every backlog allocation. A
# gate that is only ever read is not a gate that has been tested.
#
# The seam is the PROCESS WORKING DIRECTORY, and it is the only one: alloc.ps1 takes no -Repo switch
# and reads no environment variable. `$repo` and `$common` come from `git rev-parse` against the cwd,
# so a throwaway git repo gets its OWN registry under its own .git AND supplies its own
# ledger_check.py, which is where the floor is parsed from. That makes the boundary injectable.
#
# FLOOR = 100, deliberately not 10: at 10 the warn tier (9) and the highest sub-boundary number (9)
# coincide, and every tier assertion would pass for the wrong reason.

_PWSH = shutil.which("pwsh")
