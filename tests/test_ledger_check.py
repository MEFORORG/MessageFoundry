"""Tests for the ledger gate (scripts/hooks/ledger_check.py).

The defect under test merges CLEAN, which is what makes it dangerous: two sessions each pick "the next
free number", create differently-NAMED files, git merges both without a conflict, and the ledger is
quietly corrupt. It has happened three times in this repo.

Every test builds a real throwaway git repo, stages a real commit, and runs the real hook against it — so
what is asserted is the contract git will actually invoke.
"""

from __future__ import annotations

import json
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


def allocate(repo: Path, kind: str, number: str, *, worktree: Path | None = None) -> None:
    """Mimic what scripts/coord/alloc.ps1 writes, so the hook's ownership check has something to read."""
    common = git(repo, "rev-parse", "--path-format=absolute", "--git-common-dir").strip()
    top = git(repo, "rev-parse", "--path-format=absolute", "--show-toplevel").strip()
    d = Path(common) / "mefor-coord" / "alloc" / kind
    d.mkdir(parents=True, exist_ok=True)
    claim = {"number": number, "kind": kind, "worktree": str(worktree or top)}
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
    """A sibling session holds 0002. Hand-writing it here must not slip through."""
    write(repo, "docs/adr/0002-new.md", "# 0002 — New\n")
    write(
        repo,
        "docs/adr/README.md",
        README_HEAD + ROW.format(n="0002", slug="new", title="New") + "\n",
    )
    allocate(repo, "adr", "0002", worktree=tmp_path / "some-other-worktree")
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
    """Two sessions adding '## 227.' land ~1,600 lines apart in one file and BOTH ship."""
    write(repo, "docs/BACKLOG.md", "# Backlog\n\n## 1. First item\n\nbody\n\n## 2. Mine\n\nbody\n")
    git(repo, "add", "docs/BACKLOG.md")

    code, out = run_check(repo)
    assert code == 1
    assert "BACKLOG item #2" in out


def test_an_allocated_backlog_number_passes(repo: Path) -> None:
    write(repo, "docs/BACKLOG.md", "# Backlog\n\n## 1. First item\n\nbody\n\n## 2. Mine\n\nbody\n")
    allocate(repo, "backlog", "2")
    git(repo, "add", "docs/BACKLOG.md")

    code, out = run_check(repo)
    assert code == 0, out


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
        f"# Backlog\n\n## 1. First item\n\n{NON_ASCII_BODY}\n## 2. Mine — ⚠️ unallocated\n\nbody\n",
    )
    git(repo, "add", "docs/BACKLOG.md")

    code, out = run_check(repo)
    assert code == 1, out
    assert "BACKLOG item #2" in out


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
