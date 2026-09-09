# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Tests for the pre-rename repository slug guard.

THE DEFECT IT GUARDS. The private vault repository was renamed on 2026-09-05, and GitHub keeps a
PERMANENT redirect from its old path. A stale reference therefore does not fail -- it quietly
answers, correctly, about the vault, under a name that is gone. Nothing else in this repository
reports that, which is what makes it worth a guard rather than a one-time sweep.

WHAT THESE ARMS ARE FOR. A guard that passes on a clean tree and a guard that cannot fail at all
render identically, so the clean-tree arm proves nothing by itself. Every arm below that matters
plants a violation and requires the guard to SEE it: a bare slug, a bare slug hiding on the same
line as a legitimate new one, a pinned exemption drifting up, and the same pin drifting down. The
git-failure arm exists because "no matches" and "the search never ran" are the same empty output.

None of these tests writes the pre-rename slug as a literal, for the same reason the guard does
not: the test file is inside the population the guard scans, so a literal here would make this
module fail the rule it is checking. The needle is imported from the guard.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts" / "quality"))

from stale_repo_slug_check import (  # noqa: E402
    ALLOWED,
    NEW_SLUG,
    OLD_SLUG,
    GitError,
    check,
)

_ROOT = Path(__file__).resolve().parents[1]


def _repo(tmp_path: Path) -> Path:
    """An isolated git repository. Files need only be ADDED -- `git grep` reads the index."""
    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
    return tmp_path


def _track(repo: Path, relative: str, text: str) -> None:
    target = repo / relative
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(text, encoding="utf-8")
    subprocess.run(["git", "add", "--", relative], cwd=repo, check=True)


def _pinned_path() -> str:
    """The single pinned exemption, read from the guard rather than restated here."""
    assert len(ALLOWED) == 1, "these arms assume one pinned exemption; re-read them if that changed"
    return next(iter(ALLOWED))


# --------------------------------------------------------------------------------------------
# The positive control: this repository is clean, and the guard is what keeps it that way.
# --------------------------------------------------------------------------------------------


def test_this_repository_is_clean() -> None:
    assert check(_ROOT) == []


# --------------------------------------------------------------------------------------------
# The negative controls: each plants a violation and requires the guard to report it.
# --------------------------------------------------------------------------------------------


def test_a_planted_bare_slug_fires(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    _track(repo, "docs/NOTES.md", f"See {OLD_SLUG} for the record.\n")

    problems = check(repo)

    assert problems, "a bare pre-rename slug in a tracked file must be reported"
    assert any("docs/NOTES.md:1" in problem for problem in problems)


def test_the_current_slug_alone_does_not_fire(tmp_path: Path) -> None:
    """The new name CONTAINS the old one as a prefix, so a substring search over-reports."""
    repo = _repo(tmp_path)
    _track(repo, "docs/NOTES.md", f"See {NEW_SLUG} for the record.\n")
    _track(repo, _pinned_path(), f"quoted: {OLD_SLUG}\n")

    assert check(repo) == []


def test_a_bare_slug_hiding_beside_a_current_one_fires(tmp_path: Path) -> None:
    """Per-LINE matching passes this line; the defect is that it should not."""
    repo = _repo(tmp_path)
    _track(repo, "docs/NOTES.md", f"engine {NEW_SLUG}, vault {OLD_SLUG} -- one of these is stale\n")
    _track(repo, _pinned_path(), f"quoted: {OLD_SLUG}\n")

    problems = check(repo)

    assert problems, "a bare slug on a line that also carries the current one must still be seen"


def test_the_pinned_exemption_permits_exactly_its_count(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    path = _pinned_path()
    _track(repo, path, "\n".join(f"quoted: {OLD_SLUG}" for _ in range(ALLOWED[path])) + "\n")

    assert check(repo) == []


def test_the_pinned_exemption_fires_when_it_drifts_up(tmp_path: Path) -> None:
    """One more occurrence is a NEW stale reference wearing the exemption."""
    repo = _repo(tmp_path)
    path = _pinned_path()
    lines = [f"quoted: {OLD_SLUG}" for _ in range(ALLOWED[path] + 1)]
    _track(repo, path, "\n".join(lines) + "\n")

    problems = check(repo)

    assert problems, "an exempt path holding MORE than its pin must be reported"
    assert any("pinned at" in problem for problem in problems)


def test_the_pinned_exemption_fires_when_it_drifts_down(tmp_path: Path) -> None:
    """A pin protecting nothing is the failure this guard is least likely to notice on its own."""
    repo = _repo(tmp_path)
    _track(repo, _pinned_path(), "the quoted passage moved somewhere else\n")

    problems = check(repo)

    assert problems, "an exempt path holding FEWER than its pin must be reported"
    assert any("pinned at" in problem for problem in problems)


def test_an_untracked_file_is_not_scanned(tmp_path: Path) -> None:
    """Scope is the tracked tree, which is the population a reader greps."""
    repo = _repo(tmp_path)
    _track(repo, _pinned_path(), f"quoted: {OLD_SLUG}\n")
    (repo / "scratch.md").write_text(f"See {OLD_SLUG}\n", encoding="utf-8")

    assert check(repo) == []


def test_a_directory_that_is_not_a_repository_is_not_reported_as_clean(tmp_path: Path) -> None:
    """ "No matches" and "the search never ran" are the same empty output."""
    with pytest.raises(GitError):
        check(tmp_path)


def test_a_missing_root_is_not_reported_as_clean(tmp_path: Path) -> None:
    """This arrives as an OSError rather than an exit code, so it needs its own handling."""
    with pytest.raises(GitError):
        check(tmp_path / "does-not-exist")


def test_the_guard_exits_nonzero_on_a_violation(tmp_path: Path) -> None:
    """The exit code is what pre-commit reads, so it gets its own arm."""
    repo = _repo(tmp_path)
    _track(repo, "docs/NOTES.md", f"See {OLD_SLUG}\n")

    proc = subprocess.run(
        [
            sys.executable,
            str(_ROOT / "scripts" / "quality" / "stale_repo_slug_check.py"),
            "--root",
            str(repo),
        ],
        capture_output=True,
        text=True,
    )

    assert proc.returncode == 1, proc.stderr
    assert "docs/NOTES.md" in proc.stderr


def test_the_guard_exits_zero_on_this_repository() -> None:
    proc = subprocess.run(
        [sys.executable, str(_ROOT / "scripts" / "quality" / "stale_repo_slug_check.py")],
        capture_output=True,
        text=True,
    )

    assert proc.returncode == 0, proc.stderr
