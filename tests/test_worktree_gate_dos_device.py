# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Does the DOS-device spelling of a governed root compare equal to the root?

BACKLOG #5454. ``Get-ComparablePath`` in ``scripts/hooks/worktree_gate.ps1`` folded the extended-length
prefixes (backslash backslash question-mark backslash, and its UNC form) onto the plain drive-letter
spelling, but not the DOS-device prefixes (backslash backslash dot backslash, and its UNC form).
``GetFullPath`` returns a DOS-device path unchanged, so ``\\\\.\\C:\\<governed>`` matched no governed root
in any rule that compares through ``Get-ComparablePath``.

MEASURED 2026-11-18 on Windows: ``git -C '\\\\.\\D:\\<worktree>' rev-parse --git-common-dir`` exits 0 and
names the real common dir, so the spelling reaches the repository with no setup at all, the same as the
extended-length prefix the gate already folds.

The comparison helper is imported from ``tests/test_worktree_gate_path_aliases.py``, so it runs the
SHIPPED functions; two end-to-end rows drive the real hook through ``tests/test_worktree_gate.py``.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from tests.test_worktree_gate import assert_denied, edit, run_gate

# The pwsh and Windows gates come with the helper: GetFullPath applies HOST path rules, so on POSIX
# every row here would be a relative path. Imported by name, so this module carries them too.
from tests.test_worktree_gate_path_aliases import comparable, pytestmark  # noqa: F401

B = chr(92)


def test_the_dos_device_spellings_of_a_local_path_compare_equal() -> None:
    """The defect: each of these names the same local file as ``C:\\Repo``."""
    got = comparable(
        [
            B + B + "." + B + "C:" + B + "Repo",
            "//./C:/Repo",
            B + B + "." + B + "UNC" + B + "localhost" + B + "C$" + B + "Repo",
            B + B + "." + B + "C:" + B + "Other" + B + ".." + B + "Repo",
        ]
    )
    assert got == ["c:/repo"] * 4, got


def test_a_dos_device_path_to_a_REMOTE_admin_share_is_NOT_folded_onto_the_local_drive() -> None:
    """Control: a share on another box is another machine's drive, so it must not fold onto ``c:``.

    Passes on the gate with and without the fold, so a failure here is the fold over-reaching.
    """
    (got,) = comparable([B + B + "." + B + "UNC" + B + "otherbox" + B + "C$" + B + "Repo"])
    assert got == "//otherbox/c$/repo"


def test_a_dos_device_path_to_a_non_drive_device_stays_distinct() -> None:
    """Control: a device that is not a drive letter keeps its prefix, so it never reads as relative."""
    got = comparable([B + B + "." + B + "PhysicalDrive0", B + B + "." + B + "pipe" + B + "x"])
    assert got == ["//./physicaldrive0", "//./pipe/x"], got


def test_a_dot_dot_segment_behind_the_extended_length_prefix_is_resolved() -> None:
    """GetFullPath returns a question-mark-prefixed path verbatim, ``..`` included."""
    got = comparable(
        [
            B + B + "?" + B + "C:" + B + "Other" + B + ".." + B + "Repo",
            B + B + "?" + B + "C:" + B + "Repo" + B + "." + B + "x" + B + "..",
        ]
    )
    assert got == ["c:/repo"] * 2, got


def test_an_edit_through_the_dos_device_spelling_of_the_primary_is_denied(
    tmp_path: Path, primary: Path, repos_file: Path
) -> None:
    """End to end: rule 1 sees the governed primary behind the device prefix."""
    target = B + B + "." + B + str(primary / "src" / "app.py")
    assert_denied(run_gate(edit(target, cwd=tmp_path / "Repo-alerts"), repos_file))


def test_an_edit_through_an_extended_length_dot_dot_spelling_is_denied(
    tmp_path: Path, primary: Path, repos_file: Path
) -> None:
    target = B + B + "?" + B + str(tmp_path / "Repo-alerts" / ".." / "Repo" / "src" / "app.py")
    assert_denied(run_gate(edit(target, cwd=tmp_path / "Repo-alerts"), repos_file))


@pytest.fixture
def primary(tmp_path: Path) -> Path:
    return tmp_path / "Repo"


@pytest.fixture
def repos_file(tmp_path: Path, primary: Path) -> Path:
    f = tmp_path / "repos.txt"
    f.write_text("# governed" + chr(10) + str(primary) + chr(10), encoding="utf-8")
    return f
