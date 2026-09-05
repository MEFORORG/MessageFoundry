# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Tests for the ledger gate (scripts/hooks/ledger_check.py).

The defect under test merges CLEAN, which is what makes it dangerous: two sessions each pick "the next
free number", create differently-NAMED files, git merges both without a conflict, and the ledger is
quietly corrupt. It has happened three times in this repo.

Every test builds a real throwaway git repo, stages a real commit, and runs the real hook against it — so
what is asserted is the contract git will actually invoke.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

CHECK = Path(__file__).resolve().parents[1] / "scripts" / "hooks" / "ledger_check.py"

ROW = "| [{n}]({n}-{slug}.md) | {title} | Accepted |"
README_HEAD = "# Architecture Decision Records\n\n| ADR | Decision | Status |\n|---|---|---|\n"


def git(repo: Path, *args: str) -> str:
    proc = subprocess.run(
        ["git", "-C", str(repo), *args], capture_output=True, text=True, check=False
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
    common = git(repo, "rev-parse", "--path-format=absolute", "--git-common-dir").strip()
    top = git(repo, "rev-parse", "--path-format=absolute", "--show-toplevel").strip()
    d = Path(common) / "mefor-coord" / "alloc" / kind
    d.mkdir(parents=True, exist_ok=True)
    claim: dict[str, str] = {"number": number, "kind": kind, "worktree": str(worktree or top)}
    if not omit_branch:
        claim["branch"] = branch or git(repo, "rev-parse", "--abbrev-ref", "HEAD").strip()
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
    worktree AND on another branch -- git refuses one branch in two worktrees, so that pairing is not
    a coincidence, it is the only shape a live sibling can have. Once ownership grew a branch fallback
    (BACKLOG #1282) this arm had to name the branch or it would have been asserting the weaker
    "different path" and passing for a reason unrelated to sibling-ness.
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

    ***IT IS SAFE ONLY BECAUSE GIT REFUSES ONE BRANCH IN TWO WORKTREES.*** The gate exists to stop two
    sessions filing one number, and two sessions cannot hold one branch -- so "the session on this
    branch" is exactly as single-valued as "the session in this worktree" was, while outliving it. A
    branch that is free to check out is one nobody is working in.
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


# ----------------------------------------------------------------- the dropped-row defect (0077/0079/0080)


def test_a_new_adr_with_no_index_row_is_blocked(repo: Path) -> None:
    """Three real ADRs shipped with no index row. The tail-append hazard shows up as a DROPPED ROW."""
    write(repo, "docs/adr/0002-new.md", "# 0002 — New\n")
    allocate(repo, "adr", "0002")
    git(repo, "add", "-A")

    code, out = run_check(repo)
    assert code == 1
    assert "no row in docs/adr/README.md" in out


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


# ----------------------------------------------------------------- BACKLOG numbers


def test_a_new_backlog_number_must_be_allocated(repo: Path) -> None:
    """Two sessions adding '## 227.' land ~1,600 lines apart in one file and BOTH ship.

    Uses an ABOVE-FLOOR number deliberately. With a below-floor one this test still goes red, but on
    the partition rule instead of the ownership rule — passing for the wrong reason and asserting
    nothing about allocation. The reason is asserted below for the same reason.
    """
    write(
        repo, "docs/BACKLOG.md", "# Backlog\n\n## 1. First item\n\nbody\n\n## 1001. Mine\n\nbody\n"
    )
    git(repo, "add", "docs/BACKLOG.md")

    code, out = run_check(repo)
    assert code == 1
    assert "BACKLOG item #1001" in out
    assert "was not allocated to this worktree" in out, (
        "must fail on the OWNERSHIP rule; if this now reports the public floor, the test has stopped "
        f"exercising allocation:\n{out}"
    )


def test_an_allocated_backlog_number_passes(repo: Path) -> None:
    write(
        repo, "docs/BACKLOG.md", "# Backlog\n\n## 1. First item\n\nbody\n\n## 1001. Mine\n\nbody\n"
    )
    allocate(repo, "backlog", "1001")
    git(repo, "add", "docs/BACKLOG.md")

    code, out = run_check(repo)
    assert code == 0, out


def test_a_backlog_number_below_the_public_floor_is_refused(repo: Path) -> None:
    """The partition: new items live at #1000+, so the overlap with the internal ledger stays closed.

    Allocated to THIS worktree, so ownership is satisfied and the floor is the only thing that can
    reject it — otherwise the test would pass on the ownership rule and prove nothing.
    """
    write(repo, "docs/BACKLOG.md", "# Backlog\n\n## 1. First item\n\nbody\n\n## 2. Mine\n\nbody\n")
    allocate(repo, "backlog", "2")
    git(repo, "add", "docs/BACKLOG.md")

    code, out = run_check(repo)
    assert code == 1
    assert "below the public floor" in out, out


def test_the_public_floor_also_refuses_in_ci_mode(repo: Path) -> None:
    """The floor is the FIRST backlog rule that can fail in --ci.

    The ownership rule cannot: it reads a per-clone registry and compares a worktree path, and a runner
    has neither — so `check_backlog()` computed the added-number set and discarded it, leaving the CI
    ledger step unable to fail on the backlog half at all.
    """
    write(repo, "docs/BACKLOG.md", "# Backlog\n\n## 1. First item\n\nbody\n\n## 2. Mine\n\nbody\n")
    git(repo, "add", "docs/BACKLOG.md")
    git(repo, "commit", "-m", "add a below-floor item", "--no-verify")

    code, out = run_check(repo, "--ci")
    assert code == 1, out
    assert "below the public floor" in out, out


def test_editing_backlog_without_adding_a_number_passes(repo: Path) -> None:
    write(repo, "docs/BACKLOG.md", "# Backlog\n\n## 1. First item\n\nbody, now edited\n")
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


def test_a_utf8_backlog_still_catches_an_unallocated_number(repo: Path) -> None:
    """The dangerous direction: a crash-to-empty would parse as 'no numbers taken' and pass silently."""
    write(
        repo,
        "docs/BACKLOG.md",
        f"# Backlog\n\n## 1. First item\n\n{NON_ASCII_BODY}\n## 1001. Mine — ⚠️ unallocated\n\nbody\n",
    )
    git(repo, "add", "docs/BACKLOG.md")

    code, out = run_check(repo)
    assert code == 1, out
    assert "BACKLOG item #1001" in out
    # Above the floor deliberately: a below-floor number would be rejected by the partition rule even
    # if the UTF-8 read had crashed to empty, so this test would pass while proving nothing about the
    # decode — the exact false-clean it exists to catch.
    assert "was not allocated to this worktree" in out, out


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


# --------------------------------------------------------------------------------------------------
# WIRING. Everything above tests the gate's LOGIC against a throwaway repo. None of it notices if the
# gate is never invoked -- and on 2026-07-27 that is exactly what happened: the ledger gate had to move
# out of .git/hooks/pre-commit because `pre-commit install` and install-git-hooks.ps1 both want that
# file, and their chaining fails on Windows. Logic tests stayed green throughout. These assert the gate
# is actually WIRED UP, which is the property that was silently lost.
# --------------------------------------------------------------------------------------------------

_CONFIG = Path(__file__).resolve().parents[1] / ".pre-commit-config.yaml"
_INSTALLER = Path(__file__).resolve().parents[1] / "scripts" / "coord" / "install-git-hooks.ps1"


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


def test_a_number_INVENTED_during_a_merge_is_still_refused(repo: Path, tmp_path: Path) -> None:
    """The other half, and the one that keeps the arm above from being a hole.

    Same mid-merge state, plus a heading no commit anywhere carries. Being inside a merge must not
    become a way to file an unallocated number.
    """
    _diverge_and_merge(repo, tmp_path, number="1441")

    merged = (repo / "docs/BACKLOG.md").read_text(encoding="utf-8")
    write(repo, "docs/BACKLOG.md", merged + "\n## 1442. Invented while merging\n\nbody\n")
    git(repo, "add", "-A")

    code, out = run_check(repo)
    assert code != 0, "a number on no parent is a fresh allocation, merge or not"
    assert "1442" in out, out
    # DELIBERATELY NOT asserted here: that 1441 is absent from the message. It is true, and it belongs
    # to the arm above. Asserting it here made both arms red under the same mutation, which is exactly
    # the overlap that stops a pair from localising a failure -- caught by running the mutation.


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


_ALLOC = Path(__file__).resolve().parents[1] / "scripts" / "coord" / "alloc.ps1"

# Kept deliberately identical to the pattern in scripts/coord/alloc.ps1 — the point of this test is to
# fail the moment the two drift. A duplicated regex that is TESTED is not the same hazard as a
# duplicated value that is not: this one fails loudly on drift, which is the property being bought.
_FLOOR_RE = re.compile(r"(?m)^PUBLIC_BACKLOG_FLOOR\s*(?::[^=]+)?=\s*(\d+)")


def test_the_public_floor_is_parseable_by_the_allocator() -> None:
    """`alloc.ps1` PARSES the floor out of this gate so the value is defined exactly once.

    That coupling is to SOURCE TEXT, which is a weaker contract than an import, so it is pinned here.
    Without this test the break is silent and lands on the wrong person: whoever reformats the constant
    gets a green CI, and an unrelated session hits "refusing to allocate" days later — where the
    tempting repair is to hardcode the floor back into alloc.ps1, re-creating the two-copies drift the
    single source exists to remove.

    The realistic break is a type annotation. `PUBLIC_BACKLOG_FLOOR: Final[int] = 1000` is idiomatic in
    a mypy-strict codebase and is tolerated; splitting, computing or renaming the value is not.
    """
    matches = _FLOOR_RE.findall(CHECK.read_text(encoding="utf-8"))
    assert len(matches) == 1, (
        "scripts/coord/alloc.ps1 parses PUBLIC_BACKLOG_FLOOR out of ledger_check.py and expects exactly "
        f"one match; found {len(matches)}. Keep the name and the literal on one line."
    )
    assert int(matches[0]) > 0


def test_the_allocator_still_parses_the_floor_the_same_way() -> None:
    """The allocator's own regex must accept the constant as written — not merely a similar one."""
    alloc_src = _ALLOC.read_text(encoding="utf-8")
    assert "PUBLIC_BACKLOG_FLOOR" in alloc_src, (
        "alloc.ps1 no longer reads the floor from the gate — the value is defined twice again"
    )
    # The annotation-tolerant form; if alloc.ps1 reverts to the naive `\s*=\s*` it breaks on Final[int].
    assert r"(?::[^=]+)?" in alloc_src, (
        "alloc.ps1's floor regex must tolerate a type annotation "
        "(PUBLIC_BACKLOG_FLOOR: Final[int] = 1000), or an ordinary tidy-up silently disarms allocation"
    )


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


def test_the_residual_detector_does_not_read_the_whole_set_maximum() -> None:
    """The exact regression: the guard compared `$observed` (union max) against the public floor."""
    src = _ALLOC.read_text(encoding="utf-8")
    assert re.search(r"\$observed\s+-ge\s+\$PublicBacklogFloor", src) is None, (
        "alloc.ps1 compares the WHOLE-SET maximum against PUBLIC_BACKLOG_FLOOR again. That is the "
        "2026-08-03 defect verbatim: every public item at or above the floor is indistinguishable from "
        "an internal breach in this data, so the comparison fires on the partition working as designed. "
        "Measure the sub-floor band instead."
    )
    assert re.search(r"\$subFloorMax\s+-ge\s+\$warnAt", src), (
        "the residual warning must be derived from the sub-partition maximum, not the union maximum"
    )


def test_the_floor_preview_evaluates_the_same_guard_as_a_real_allocation() -> None:
    """`-ShowFloor` must not be able to disagree with the run it previews.

    It could, and did: the `-ShowFloor` block `return`ed 19 lines before the guard, so it printed a
    `next:` number while every real allocation threw. An inspector that skips the checks it previews
    answers a question adjacent to the one asked — and it is worse than no inspector, because a peer
    session verified the allocator with it, got a green answer, and recorded it as a fact.
    """
    src = _ALLOC.read_text(encoding="utf-8")
    show_at = src.index("if ($ShowFloor)")
    assert "$residualWarning" in src[:show_at], (
        "$residualWarning must be computed BEFORE the -ShowFloor block, so the preview and the real "
        "allocation evaluate one shared expression rather than two that can drift apart."
    )
    assert src.count("$residualWarning") >= 3, (
        "-ShowFloor must consult $residualWarning too; if only the allocation path reads it, the "
        "preview is once again reporting a number the allocator would refuse to issue."
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


def _mkrepo(tmp: Path, floor: int, items: list[int]) -> Path:
    """A throwaway repo carrying its own alloc.ps1, its own floor constant, and its own registry."""
    repo = tmp / "rig"
    (repo / "scripts" / "coord").mkdir(parents=True)
    (repo / "scripts" / "hooks").mkdir(parents=True)
    (repo / "docs").mkdir()
    shutil.copy(_ALLOC, repo / "scripts" / "coord" / "alloc.ps1")
    (repo / "scripts" / "hooks" / "ledger_check.py").write_text(
        f"PUBLIC_BACKLOG_FLOOR = {floor}\n", encoding="utf-8"
    )
    body = "# rig\n\n" + "".join(f"## {n}. item {n}\n\n> OPEN\n\n" for n in items)
    (repo / "docs" / "BACKLOG.md").write_text(body, encoding="utf-8")
    subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
    subprocess.run(["git", "add", "-A"], cwd=repo, check=True)
    subprocess.run(
        ["git", "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "rig"],
        cwd=repo,
        check=True,
    )
    return repo


def _alloc(repo: Path, *args: str) -> subprocess.CompletedProcess[str]:
    assert _PWSH
    return subprocess.run(
        [_PWSH, "-NoProfile", "-File", str(repo / "scripts" / "coord" / "alloc.ps1"), *args],
        cwd=repo,
        capture_output=True,
        text=True,
    )


@pytest.mark.skipif(not _PWSH, reason="pwsh not on PATH")
def test_the_rig_cannot_reach_the_real_registry(tmp_path: Path) -> None:
    """FIRST, because every later test here spends real numbers if this is false.

    The registry lives beside the git common dir, so a throwaway repo must resolve to its OWN .git.
    If it resolved to the project's, these tests would burn production ledger numbers on every run --
    and claims are never released, so the damage would be permanent and silent.
    """
    repo = _mkrepo(tmp_path, floor=100, items=[5, 7])
    out = _alloc(repo, "-Kind", "backlog", "-ShowFloor")
    assert out.returncode == 0, out.stderr
    real = str(Path(__file__).resolve().parents[1] / ".git").lower()
    assert real not in out.stdout.lower().replace("/", "\\"), (
        f"the rig resolved to the REAL registry — refusing to run the rest.\n{out.stdout}"
    )
    assert str(tmp_path).lower()[:12] in out.stdout.lower(), out.stdout


@pytest.mark.skipif(not _PWSH, reason="pwsh not on PATH")
def test_a_public_number_at_the_boundary_does_not_brick_allocation(tmp_path: Path) -> None:
    """The 2026-08-03 regression, executed rather than pattern-matched.

    An item at exactly the floor is the FIRST legitimate public allocation. Before the fix this threw
    `REFUSING TO ALLOCATE … has reached the public floor` for every subsequent caller, repo-wide.
    """
    repo = _mkrepo(tmp_path, floor=100, items=[5, 100])
    out = _alloc(repo, "-Kind", "backlog", "-Title", "after the boundary")
    assert out.returncode == 0, f"allocation refused on legitimate input:\n{out.stdout}{out.stderr}"
    assert "ALLOCATED BACKLOG #101" in out.stdout, out.stdout
    assert "REFUSING" not in out.stdout + out.stderr


@pytest.mark.skipif(not _PWSH, reason="pwsh not on PATH")
def test_the_warning_reads_the_sub_boundary_band_not_the_union(tmp_path: Path) -> None:
    """A public number above the boundary must NOT trip the runway warning; a sub-boundary one must."""
    quiet = _alloc(
        _mkrepo(tmp_path / "a", floor=100, items=[5, 100]), "-Kind", "backlog", "-ShowFloor"
    )
    assert "WOULD WARN" not in quiet.stdout, (
        f"a public item at the boundary tripped the internal-runway warning:\n{quiet.stdout}"
    )
    loud = _alloc(_mkrepo(tmp_path / "b", floor=100, items=[95]), "-Kind", "backlog", "-ShowFloor")
    assert "WOULD WARN" in loud.stdout, (
        f"sub-boundary 95 is past the 90 warn tier and did not warn:\n{loud.stdout}"
    )


@pytest.mark.skipif(not _PWSH, reason="pwsh not on PATH")
def test_lowering_the_boundary_is_refused(tmp_path: Path) -> None:
    """The replacement refusal, and it must actually fire.

    Neither the pre-commit gate nor CI can catch a LOWERED floor: both read only the current value and
    have no memory of the previous one. The ratchet beside the registry is the only instrument that can.
    """
    repo = _mkrepo(tmp_path, floor=100, items=[5])
    first = _alloc(repo, "-Kind", "backlog", "-Title", "sets the ratchet")
    assert first.returncode == 0, first.stderr
    gate = repo / "scripts" / "hooks" / "ledger_check.py"
    gate.write_text("PUBLIC_BACKLOG_FLOOR = 50\n", encoding="utf-8")
    after = _alloc(repo, "-Kind", "backlog", "-Title", "should be refused")
    assert after.returncode != 0, f"a lowered boundary was accepted:\n{after.stdout}"
    assert "REFUSING TO ALLOCATE" in after.stdout + after.stderr


@pytest.mark.skipif(not _PWSH, reason="pwsh not on PATH")
def test_showfloor_agrees_with_a_real_allocation(tmp_path: Path) -> None:
    """The preview must not be able to contradict the run it previews — it could, and did."""
    repo = _mkrepo(tmp_path, floor=100, items=[5, 100])
    preview = _alloc(repo, "-Kind", "backlog", "-ShowFloor")
    assert "next     : 101" in preview.stdout, preview.stdout
    real = _alloc(repo, "-Kind", "backlog", "-Title", "must match the preview")
    assert "ALLOCATED BACKLOG #101" in real.stdout, (
        f"-ShowFloor promised 101 and the allocator issued something else:\n{real.stdout}"
    )

    # And the refusal case must agree too, in the same direction.
    (repo / "scripts" / "hooks" / "ledger_check.py").write_text(
        "PUBLIC_BACKLOG_FLOOR = 50\n", encoding="utf-8"
    )
    assert "WOULD REFUSE" in _alloc(repo, "-Kind", "backlog", "-ShowFloor").stdout
    assert _alloc(repo, "-Kind", "backlog", "-Title", "x").returncode != 0
