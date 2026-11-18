# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Does a DEVICE spelling of a governed root compare equal to the root?

BACKLOG #5454. ``Get-ComparablePath`` in ``scripts/hooks/worktree_gate.ps1`` folded the extended-length
prefixes (backslash backslash question-mark backslash, and its UNC form) onto the plain drive-letter
spelling, but not the DOS-device prefix (backslash backslash dot backslash, and its UNC form), the
NT-namespace prefix (backslash question-mark question-mark backslash) or the GLOBALROOT form of either.
``GetFullPath`` keeps a device prefix on what it returns, so each of those matched no governed root in
any rule that compares through ``Get-ComparablePath``.

MEASURED 2026-11-18 on Windows: ``git -C <spelling> rev-parse --git-common-dir`` exits 0 and names the
real common dir for the dot-device, NT-namespace and dot-device GLOBALROOT spellings of a worktree, and
for an extended-length spelling with a trailing dot or a ``..`` segment. None needs any setup.

The comparison helper is imported from ``tests/test_worktree_gate_path_aliases.py``, so it runs the
SHIPPED functions; the end-to-end rows drive the real hook through ``tests/test_worktree_gate.py``.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from tests.test_worktree_gate import assert_denied, bash, edit, run_gate

# The pwsh and Windows gates come with the helper: GetFullPath applies HOST path rules, so on POSIX
# every row here would be a relative path. Imported by name, so this module carries them too.
from tests.test_worktree_gate_path_aliases import comparable, pytestmark  # noqa: F401

B = chr(92)


def dev(prefix: str, rest: str) -> str:
    """``prefix`` and ``rest`` written with forward slashes, returned with backslashes."""
    return (prefix + rest).replace("/", B)


def test_the_device_spellings_of_a_local_path_compare_equal() -> None:
    """The defect: each of these names the same local file as ``C:\\Repo``."""
    got = comparable(
        [
            dev("//./", "C:/Repo"),
            "//./C:/Repo",
            dev("//./", "UNC/localhost/C$/Repo"),
            dev("//./", "C:/Other/../Repo"),
            dev("/??/", "C:/Repo"),
            dev("/??/", "UNC/localhost/C$/Repo"),
            dev("//./", "GLOBALROOT/??/C:/Repo"),
            dev("//?/", "GLOBALROOT/??/C:/Repo"),
            "/??/C:/Repo",
            dev("//?/", "C:"),
        ]
    )
    assert got[:9] == ["c:/repo"] * 9, got
    assert got[9] == "c:", got


def test_an_extended_length_path_is_normalised_the_way_git_normalises_it() -> None:
    """GetFullPath returns a question-mark-prefixed path verbatim: ``..``, ``.`` and a trailing dot."""
    got = comparable(
        [
            dev("//?/", "C:/Other/../Repo"),
            dev("//?/", "C:/Repo/./x/.."),
            dev("//?/", "C:/Repo."),
            dev("//?/", "C:/Repo./src"),
            dev("//?/", "UNC/localhost/C$/Other/../Repo"),
        ]
    )
    assert got[:3] == ["c:/repo"] * 3, got
    assert got[3:] == ["c:/repo/src", "c:/repo"], got


def test_a_dot_dot_that_climbs_OUT_of_the_root_resolves_where_git_lands() -> None:
    """The one class the fold moves from DENY to ALLOW, pinned so it stays a decision.

    Before the fold this compared lexically as ``c:/repo/../elsewhere`` and matched ``c:/repo``. git
    resolves it to ``C:\\Elsewhere``, and the plain drive spelling already compared that way.
    """
    got = comparable(
        [dev("//?/", "C:/Repo/../Elsewhere"), "C:" + B + "Repo" + B + ".." + B + "Elsewhere"]
    )
    assert got == ["c:/elsewhere"] * 2, got


def test_a_device_path_to_a_REMOTE_admin_share_is_NOT_folded_onto_the_local_drive() -> None:
    """Control: a share on another box is another machine's drive, so it must not fold onto ``c:``.

    The over-reach assertion is ``!= "c:/repo"``, which holds on the gate with and without the fold, so
    only a fold that over-reaches turns it red. The exact form is pinned separately below it.
    """
    got = comparable([dev("//./", "UNC/otherbox/C$/Repo"), dev("/??/", "UNC/otherbox/C$/Repo")])
    assert "c:/repo" not in got, got
    assert got == ["//otherbox/c$/repo"] * 2, got


def test_a_device_path_that_is_not_a_drive_keeps_its_prefix() -> None:
    """Control: a device that is not a drive letter or UNC path keeps its prefix, for BOTH prefixes.

    It must never read as a relative path. The volume rows are the spelling the docstring names as
    still open: they keep their prefix and match no drive-letter root.
    """
    got = comparable(
        [
            dev("//./", "PhysicalDrive0"),
            dev("//./", "pipe/x"),
            dev("//?/", "pipe/x"),
            dev("//./", "Volume{abc}/Repo"),
            dev("//?/", "Volume{abc}/Repo"),
            dev("//?/", "GLOBALROOT/Device/HarddiskVolume3/Repo"),
        ]
    )
    assert got == [
        "//./physicaldrive0",
        "//./pipe/x",
        "//?/pipe/x",
        "//./volume{abc}/repo",
        "//?/volume{abc}/repo",
        "//?/globalroot/device/harddiskvolume3/repo",
    ], got


# --------------------------------------------------------------------------- rule 1, end to end


@pytest.mark.parametrize("prefix", ["//./", "/??/", "//./GLOBALROOT/??/"])
def test_an_edit_through_a_device_spelling_of_the_primary_is_denied(
    tmp_path: Path, primary: Path, repos_file: Path, prefix: str
) -> None:
    """End to end: rule 1 sees the governed primary behind the device prefix."""
    target = prefix.replace("/", B) + str(primary / "src" / "app.py")
    assert_denied(run_gate(edit(target, cwd=tmp_path / "Repo-alerts"), repos_file))


def test_an_edit_through_an_extended_length_dot_dot_spelling_is_denied(
    tmp_path: Path, primary: Path, repos_file: Path
) -> None:
    target = B + B + "?" + B + str(tmp_path / "Repo-alerts" / ".." / "Repo" / "src" / "app.py")
    assert_denied(run_gate(edit(target, cwd=tmp_path / "Repo-alerts"), repos_file))


def test_an_edit_through_an_extended_length_trailing_dot_spelling_is_denied(
    tmp_path: Path, primary: Path, repos_file: Path
) -> None:
    target = B + B + "?" + B + str(primary) + "." + B + "src" + B + "app.py"
    assert_denied(run_gate(edit(target, cwd=tmp_path / "Repo-alerts"), repos_file))


# --------------------------------------------------------------------------- rule 3c, end to end


@pytest.fixture
def repo(tmp_path: Path) -> SimpleNamespace:
    """A REAL governed repo: rule 3c asks git for the common dir of the ``-C`` target."""
    if shutil.which("git") is None:
        pytest.skip("needs git on PATH")
    primary = tmp_path / "Primary"
    for args in (
        ["init", "-b", "main", str(primary)],
        ["-C", str(primary), "config", "user.email", "t@example.com"],
        ["-C", str(primary), "config", "user.name", "t"],
        ["-C", str(primary), "commit", "--allow-empty", "-m", "seed"],
    ):
        subprocess.run(["git", *args], check=True, capture_output=True, text=True)
    elsewhere = tmp_path / "Elsewhere"
    elsewhere.mkdir()
    repos = tmp_path / "repos.txt"
    repos.write_text(str(primary) + chr(10), encoding="utf-8")
    return SimpleNamespace(primary=primary, elsewhere=elsewhere, repos=repos)


@pytest.mark.parametrize(
    ("prefix", "suffix"),
    [
        ("//./", ""),
        ("/??/", ""),
        ("//./GLOBALROOT/??/", ""),
        ("//?/", "."),
    ],
)
def test_an_unquoted_device_spelled_git_C_disarm_is_denied(
    repo: SimpleNamespace, prefix: str, suffix: str
) -> None:
    """The exploit the item measured, under the PowerShell tool, which passes the token unquoted."""
    target = prefix.replace("/", B) + str(repo.primary) + suffix
    cmd = "git -C " + target + " config core.hooksPath x"
    reason = assert_denied(run_gate(bash(cmd, repo.elsewhere, tool="PowerShell"), repo.repos))
    assert "SHARED git configuration" in reason


@pytest.mark.xfail(
    strict=True,
    reason=(
        "OPEN, named in Get-ComparablePath's docstring: Test-ShellLiteralPath refuses a quoted -C value "
        "before the fold sees it, so a quoted device spelling is still allowed. A pass here means the gap "
        "closed and the docstring is stale."
    ),
)
def test_a_QUOTED_device_spelled_git_C_disarm_is_denied(repo: SimpleNamespace) -> None:
    target = B + B + "." + B + str(repo.primary)
    cmd = "git -C '" + target + "' config core.hooksPath x"
    assert_denied(run_gate(bash(cmd, repo.elsewhere), repo.repos))


@pytest.fixture
def primary(tmp_path: Path) -> Path:
    return tmp_path / "Repo"


@pytest.fixture
def repos_file(tmp_path: Path, primary: Path) -> Path:
    f = tmp_path / "repos.txt"
    f.write_text("# governed" + chr(10) + str(primary) + chr(10), encoding="utf-8")
    return f
