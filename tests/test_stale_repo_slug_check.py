# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Tests for the retired repository path guard.

THE DEFECT IT GUARDS. The private vault repository was renamed on 2026-09-05 and transferred into
the organization on 2026-09-19, and GitHub keeps a PERMANENT redirect from every path it has ever
had. A stale reference therefore does not fail -- it quietly answers, correctly, about the vault,
under a path that is gone. Nothing else in this repository reports that, which is what makes it
worth a guard rather than a one-time sweep.

WHY THE ARMS CHANGED WITH THE TRANSFER, WHICH IS THE PART WORTH READING. The guard used to
EXCLUDE the ``-vault`` form with a negative lookahead, because that form was the CURRENT path and
a plain prefix search over-reported it. The transfer retired it. An arm that asserted the
exclusion would now be pinning the bug in place, so it has been inverted: the pre-transfer path
must FIRE. The general lesson is that an exclusion written around the NAME cannot see a move that
changes only the OWNER.

WHAT THESE ARMS ARE FOR. A guard that passes on a clean tree and a guard that cannot fail at all
render identically, so the clean-tree arm proves nothing by itself. Every arm below that matters
plants a violation and requires the guard to SEE it: each retired path in turn, one hiding on the
same line as the live path, a pinned exemption drifting up, and the same pin drifting down. The
git-failure arm exists because "no matches" and "the search never ran" are the same empty output.

None of these tests writes a retired path as a literal, for the same reason the guard does not:
the test file is inside the population the guard scans, so a literal here would make this module
fail the rule it is checking. The needle is imported from the guard.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts" / "quality"))

from stale_repo_slug_check import (  # noqa: E402
    ALLOWED,
    CURRENT_METHOD_SLUG,
    CURRENT_SLUG,
    RETIRED_METHOD,
    RETIRED_PREFIX,
    GitError,
    check,
)

_ROOT = Path(__file__).resolve().parents[1]

#: The path the vault carried between the rename and the transfer. Assembled, never a literal.
PRE_TRANSFER = f"{RETIRED_PREFIX}-vault"


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


def _satisfy_pin(repo: Path) -> None:
    """Fill the pinned path to EXACTLY its count.

    Arms that expect a specific violation must not also be carrying pin drift, or they pass for
    the wrong reason -- the failure this guard's own docstring warns about, one level up.
    """
    path = _pinned_path()
    _track(repo, path, "\n".join(f"quoted: {RETIRED_PREFIX}" for _ in range(ALLOWED[path])) + "\n")


# --------------------------------------------------------------------------------------------
# The positive control: this repository is clean, and the guard is what keeps it that way.
# --------------------------------------------------------------------------------------------


def test_this_repository_is_clean() -> None:
    assert check(_ROOT) == []


# --------------------------------------------------------------------------------------------
# The negative controls: each plants a violation and requires the guard to report it.
# --------------------------------------------------------------------------------------------


def test_a_planted_pre_rename_path_fires(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    _satisfy_pin(repo)
    _track(repo, "docs/NOTES.md", f"See {RETIRED_PREFIX} for the record.\n")

    problems = check(repo)

    assert problems, "a pre-rename path in a tracked file must be reported"
    assert any("docs/NOTES.md:1" in problem for problem in problems)


def test_a_planted_pre_transfer_path_fires(tmp_path: Path) -> None:
    """THE REGRESSION ARM. The old lookahead allowed this form; the 2026-09-19 transfer retired it.

    Eleven live references across eight files sat under it, all green, until the guard stopped
    excluding the suffix.
    """
    repo = _repo(tmp_path)
    _satisfy_pin(repo)
    _track(repo, "docs/NOTES.md", f"See {PRE_TRANSFER} for the record.\n")

    problems = check(repo)

    assert problems, "the pre-transfer path must be reported now that it is retired"
    assert any("docs/NOTES.md:1" in problem for problem in problems)


def test_a_planted_retired_playbook_path_fires(tmp_path: Path) -> None:
    """The role playbooks moved on 2026-09-19 too, and every seat reads them on every start."""
    repo = _repo(tmp_path)
    _satisfy_pin(repo)
    _track(repo, "docs/NOTES.md", f"Read the playbook in {RETIRED_METHOD}.\n")

    problems = check(repo)

    assert problems, "the retired playbook path must be reported"
    assert any("docs/NOTES.md:1" in problem for problem in problems)


def test_the_live_paths_alone_do_not_fire(tmp_path: Path) -> None:
    """The live paths sit under a different OWNER, so they share no prefix with the retired ones."""
    repo = _repo(tmp_path)
    _satisfy_pin(repo)
    _track(repo, "docs/NOTES.md", f"vault {CURRENT_SLUG}, playbooks {CURRENT_METHOD_SLUG}\n")

    assert check(repo) == []


def test_a_live_repository_under_the_retired_owner_does_not_fire(tmp_path: Path) -> None:
    """THE REASON THIS GUARD LISTS PATHS RATHER THAN REJECTING THE OWNER.

    The retired account still holds repositories this tree names legitimately, and captured
    GitHub API payloads under tests/fixtures carry owner-qualified API URLs that are not
    repository references at all. Both were measured present on 2026-09-19. A guard keyed on the
    bare owner would fail each of them, and the usual repair -- exempting the paths -- would blind
    it to real stale references in the same files.
    """
    repo = _repo(tmp_path)
    _satisfy_pin(repo)
    owner = RETIRED_PREFIX.split("/", 1)[0]
    _track(repo, "docs/NOTES.md", f"{owner}/claude-multisession is still there\n")
    _track(repo, "tests/fixtures/payload.json", f'{{"url": "api/users/{owner}/received_events"}}\n')

    assert check(repo) == []


def test_a_retired_path_hiding_beside_the_live_one_fires(tmp_path: Path) -> None:
    """Per-LINE matching would pass this line; the defect is that it should not."""
    repo = _repo(tmp_path)
    _satisfy_pin(repo)
    _track(
        repo, "docs/NOTES.md", f"now {CURRENT_SLUG}, was {PRE_TRANSFER} -- one of these is dead\n"
    )

    problems = check(repo)

    assert problems, "a retired path on a line that also carries the live one must still be seen"
    assert any("docs/NOTES.md:1" in problem for problem in problems)


def test_the_pinned_exemption_permits_exactly_its_count(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    _satisfy_pin(repo)

    assert check(repo) == []


def test_the_pinned_exemption_fires_when_it_drifts_up(tmp_path: Path) -> None:
    """One more occurrence is a NEW stale reference wearing the exemption."""
    repo = _repo(tmp_path)
    path = _pinned_path()
    lines = [f"quoted: {RETIRED_PREFIX}" for _ in range(ALLOWED[path] + 1)]
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
    _satisfy_pin(repo)
    (repo / "scratch.md").write_text(f"See {RETIRED_PREFIX}\n", encoding="utf-8")

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
    _satisfy_pin(repo)
    _track(repo, "docs/NOTES.md", f"See {PRE_TRANSFER}\n")

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
