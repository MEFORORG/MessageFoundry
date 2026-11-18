# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""An ADR that arrives by RENAME or COPY is an added ADR to the ledger gate (BACKLOG #5453).

`git diff --diff-filter=A` asks git for added paths, and git detects renames by default
(diff.renames), so a `git mv` onto `docs/adr/NNNN-x.md` reports as `R`, not `A`, and was filtered
out. A `diff.renames=copies` config does the same to a copy, as `C`. Either way the file never
reached check_adrs, so the collision, ownership and index-row rules were all skipped for it.

THE CONTROL IS A LEGITIMATE SLUG RENAME WHOSE ROW FOLLOWS IT. It passes before and after the fix, so
the fix is shown not to refuse a rename the index still covers.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

CHECK = Path(__file__).resolve().parents[1] / "scripts" / "hooks" / "ledger_check.py"

ROW = "| [{n}]({n}-{slug}.md) | {title} | Accepted |"
README_HEAD = "# Architecture Decision Records\n\n| ADR | Decision | Status |\n|---|---|---|\n"
BODY = "# A synthetic decision record\n\n" + "Line of body text that stays the same.\n" * 20


def git(repo: Path, *args: str) -> str:
    proc = subprocess.run(
        ["git", "-C", str(repo), *args], capture_output=True, text=True, check=False
    )
    if proc.returncode != 0:
        raise RuntimeError(f"git {' '.join(args)} failed: {proc.stderr.strip()}")
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


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    """A base holding ADR 0001 and a non-ADR note whose body could be moved onto an ADR path."""
    r = tmp_path / "repo"
    r.mkdir()
    git(r, "init", "-q", "-b", "main")
    git(r, "config", "user.email", "t@t")
    git(r, "config", "user.name", "t")
    git(r, "config", "commit.gpgsign", "false")
    # Pinned, not inherited: rename detection is git's default, but a runner's global config could
    # turn it off and let the unfixed gate pass this suite for the wrong reason.
    git(r, "config", "diff.renames", "true")
    write(r, "docs/adr/0001-first.md", BODY)
    write(r, "docs/notes/draft.md", BODY.replace("synthetic", "drafted"))
    write(
        r,
        "docs/adr/README.md",
        README_HEAD + ROW.format(n="0001", slug="first", title="First") + "\n",
    )
    git(r, "add", "-A")
    git(r, "commit", "-qm", "base")
    git(r, "update-ref", "refs/remotes/origin/main", "HEAD")
    return r


def _staged_status(repo: Path) -> str:
    return git(repo, "diff", "--cached", "--name-status")


def test_a_rename_onto_a_base_adr_number_is_blocked(repo: Path) -> None:
    git(repo, "mv", "docs/notes/draft.md", "docs/adr/0001-moved.md")
    # The premise: git itself reports this as a rename, which is what the filter used to drop.
    assert _staged_status(repo).startswith("R"), _staged_status(repo)

    code, out = run_check(repo)
    assert code == 1, out
    assert "ADR 0001 already exists" in out


def test_a_rename_onto_a_base_adr_number_is_blocked_in_CI_mode(repo: Path) -> None:
    git(repo, "mv", "docs/notes/draft.md", "docs/adr/0001-moved.md")
    git(repo, "commit", "-qm", "move a note onto ADR 0001")

    code, out = run_check(repo, "--ci")
    assert code == 1, out
    assert "ADR 0001 already exists" in out


def test_a_rename_onto_a_new_number_with_no_index_row_is_blocked(repo: Path) -> None:
    git(repo, "mv", "docs/notes/draft.md", "docs/adr/0002-moved.md")
    git(repo, "commit", "-qm", "move a note onto ADR 0002")

    code, out = run_check(repo, "--ci")
    assert code == 1, out
    assert "ADR 0002" in out and "has no row in docs/adr/README.md" in out


def test_a_copy_onto_a_base_adr_number_is_blocked(repo: Path) -> None:
    # With copy detection on, a copy from a file the same change modifies reports as `C`.
    git(repo, "config", "diff.renames", "copies")
    write(repo, "docs/adr/0001-copy.md", BODY)
    write(repo, "docs/adr/0001-first.md", BODY + "One added line.\n")
    git(repo, "add", "-A")
    assert any(line.startswith("C") for line in _staged_status(repo).splitlines()), _staged_status(
        repo
    )

    code, out = run_check(repo)
    assert code == 1, out
    assert "ADR 0001 already exists" in out


def test_CONTROL_a_slug_rename_whose_row_follows_it_passes(repo: Path) -> None:
    git(repo, "mv", "docs/adr/0001-first.md", "docs/adr/0001-renamed.md")
    write(
        repo,
        "docs/adr/README.md",
        README_HEAD + ROW.format(n="0001", slug="renamed", title="First") + "\n",
    )
    git(repo, "add", "-A")

    code, out = run_check(repo)
    assert code == 0, out
