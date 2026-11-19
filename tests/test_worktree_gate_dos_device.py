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
real common dir for at least the dot-device, NT-namespace (either separator), dot-device ``Global`` and
dot-device GLOBALROOT spellings of a worktree, and for an extended-length spelling with a trailing dot or
a ``..`` segment. None needs any setup.

THE FOLD READS SOME GOVERNED PATHS AS UNGOVERNED, so it is never the only answer. Review round
1850f169 measured five shapes the pre-#5454 gate denied and the fold allowed: ``\\\\?\\UNC\\?\\C:\\<gov>``, a
``..`` climb past the drive that names the drive again, a final ``nul`` segment, a trailing dot that
trims into an exemption, and a bare ``\\\\?\\UNC`` that folded to the "could not resolve" sentinel. Every
governed-path decision now asks the folded form AND the pre-#5454 lexical form and denies if either
does; rules 3c and 3d also ask git for the absolute common dir. The rows below pin each of the five as a
DENY, with ungoverned ALLOW controls so a gate that denied every such spelling would fail them.

WHAT THESE ROWS DO NOT SHOW, at least: that every device spelling is folded (``Get-ComparablePath``'s
docstring lists the open classes), or anything about the double-quoted escaped spelling under the Bash
tool.

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
            dev("//?/", "Global/C:/Repo"),
            dev("//./", "Global/C:/Repo"),
            dev("//?/", "GLOBALROOT/Global??/C:/Repo"),
            dev("//?/", "GLOBALROOT/DosDevices/C:/Repo"),
            dev("//?/", "C:/Repo/a" + chr(10) + "b/.."),
            dev("//?/", "C:"),
        ]
    )
    assert got[:14] == ["c:/repo"] * 14, got
    assert got[14] == "c:", got


def test_the_device_fold_does_not_depend_on_the_current_culture() -> None:
    """Under tr-TR a culture-folding ``-match`` does not match ``I:`` against ``[a-z]``."""
    got = comparable(
        [dev("//?/", "I:/Repo"), dev("//./", "I:/Repo"), dev("/??/", "I:/Repo")],
        prelude="[System.Globalization.CultureInfo]::CurrentCulture = 'tr-TR'",
    )
    assert got == ["i:/repo"] * 3, got


def test_an_extended_length_path_is_normalised_with_the_drive_as_its_root() -> None:
    """GetFullPath returns a question-mark-prefixed path verbatim: ``..``, ``.`` and a trailing dot.

    The fold resolves them with the DRIVE as the root, which is not always how git or a writer does;
    the rule 1 rows below pin the cases where the two differ.
    """
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


def test_a_dot_dot_that_climbs_OUT_of_the_root_keeps_its_lexical_form() -> None:
    """The fold resolves the climb; the lexical form keeps it, and the gate asks both.

    The lexical form is the pre-#5454 comparison, which matched ``c:/repo``, so the end-to-end row
    below still denies: no verdict moves from DENY to ALLOW.
    """
    path = dev("//?/", "C:/Repo/../Elsewhere")
    plain = "C:" + B + "Repo" + B + ".." + B + "Elsewhere"
    assert comparable([path, plain]) == ["c:/elsewhere"] * 2
    assert comparable([path], lexical=True) == ["c:/repo/../elsewhere"]


def test_a_bare_extended_UNC_prefix_keeps_its_device_form_not_the_sentinel() -> None:
    """Review round 1850f169: ``\\\\?\\UNC`` folded to "", the "could not resolve" sentinel.

    The pre-#5454 form was the non-empty ``unc``; the lexical form still is, and the fold now keeps the
    device form where its remainder does not resolve.
    """
    paths = [dev("//?/", "UNC"), dev("//?/", "UNC/")]
    assert comparable(paths) == ["//?/unc"] * 2
    assert comparable(paths, lexical=True) == ["unc"] * 2


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


@pytest.mark.parametrize("prefix", ["//./", "/??/", "//./GLOBALROOT/??/", "//?/Global/"])
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


def test_an_edit_through_a_newline_segment_that_dot_dot_removes_is_denied(
    tmp_path: Path, primary: Path, repos_file: Path
) -> None:
    """A newline in a removed segment must not stop the prefix match. The pre-#5454 gate denied this."""
    target = (
        B + B + "?" + B + str(primary / "src") + B + "a" + chr(10) + "b" + B + ".." + B + "app.py"
    )
    assert_denied(run_gate(edit(target, cwd=tmp_path / "Repo-alerts"), repos_file))


@pytest.mark.parametrize(
    "prefix", ["//./", "/??/", "//?/", "//./GLOBALROOT/??/", "//?/Global/", "//./Global/"]
)
def test_an_edit_through_a_device_spelling_of_an_UNGOVERNED_path_is_allowed(
    tmp_path: Path, repos_file: Path, prefix: str
) -> None:
    """Control: a gate that denied every device spelling would pass the deny rows above."""
    target = prefix.replace("/", B) + str(tmp_path / "Elsewhere" / "app.py")
    assert run_gate(edit(target, cwd=tmp_path / "Elsewhere"), repos_file) is None


def test_an_edit_through_an_UNGOVERNED_extended_length_dot_dot_spelling_is_allowed(
    tmp_path: Path, repos_file: Path
) -> None:
    """Control for the ``..`` deny row: the same climb into a tree nobody governs passes."""
    target = B + B + "?" + B + str(tmp_path / "Elsewhere" / "x" / ".." / "src" / "app.py")
    assert run_gate(edit(target, cwd=tmp_path / "Elsewhere"), repos_file) is None


def test_an_edit_through_an_UNGOVERNED_newline_segment_is_allowed(
    tmp_path: Path, repos_file: Path
) -> None:
    """Control for the newline deny row: a newline segment under an ungoverned path passes."""
    elsewhere = tmp_path / "Elsewhere" / "src"
    target = B + B + "?" + B + str(elsewhere) + B + "a" + chr(10) + "b" + B + ".." + B + "app.py"
    assert run_gate(edit(target, cwd=tmp_path / "Elsewhere"), repos_file) is None


# ------------------------------------------- rule 1, the review round 1850f169 DENY-to-ALLOW rows
#
# Each row below was DENIED by the pre-#5454 gate and ALLOWED by the fold alone (measured by that review
# against origin/main). Each is denied now because rule 1 asks the lexical form too.


def test_a_dot_dot_that_climbs_OUT_of_the_primary_is_still_denied(
    tmp_path: Path, primary: Path, repos_file: Path
) -> None:
    """The pre-#5454 gate denied it, and the gate only tightens."""
    target = B + B + "?" + B + str(primary / ".." / "Elsewhere" / "app.py")
    assert_denied(run_gate(edit(target, cwd=tmp_path / "Elsewhere"), repos_file))


def test_a_dot_dot_climb_past_the_drive_that_names_the_drive_again_is_denied(
    tmp_path: Path, primary: Path, repos_file: Path
) -> None:
    """The fold read ``c:/c:/<primary>/...``; a ``\\\\?\\`` writer lands in the primary's coord state."""
    # One `..` per segment after the drive, and one more for the drive itself.
    climb = (B + "..") * len(primary.parts)
    claim = B.join([str(primary), ".git", "mefor-coord", "claims", "1.json"])
    target = B + B + "?" + B + str(primary) + climb + B + claim
    assert_denied(run_gate(edit(target, cwd=tmp_path / "Elsewhere"), repos_file))


@pytest.mark.parametrize("prefix", ["//?/", "//./"])
def test_a_final_nul_segment_in_the_primary_is_denied(
    tmp_path: Path, primary: Path, repos_file: Path, prefix: str
) -> None:
    """The fold read ``//./nul``; a device-prefixed writer creates a real file named nul there.

    The question-mark row was denied by the pre-#5454 gate (review round 1850f169). The dot row was
    allowed by it as well as by the fold (review round 8e7d5e24), so it is a new deny, not a restored one.
    """
    target = prefix.replace("/", B) + str(primary / "src" / "nul")
    assert_denied(run_gate(edit(target, cwd=tmp_path / "Elsewhere"), repos_file))


@pytest.mark.parametrize("prefix", ["//?/", "//./"])
def test_a_final_nul_segment_in_an_UNGOVERNED_tree_is_allowed(
    tmp_path: Path, repos_file: Path, prefix: str
) -> None:
    """Control: the reserved name alone does not deny."""
    target = prefix.replace("/", B) + str(tmp_path / "Elsewhere" / "src" / "nul")
    assert run_gate(edit(target, cwd=tmp_path / "Elsewhere"), repos_file) is None


@pytest.mark.parametrize(
    "tail", [[".claude", "worktrees.", "x", "a.py"], [".git", "mefor-coord.", "x.md"]]
)
def test_a_trailing_dot_beside_an_exemption_is_denied(
    tmp_path: Path, primary: Path, repos_file: Path, tail: list[str]
) -> None:
    """The fold trimmed ``worktrees.`` and ``mefor-coord.`` into the exemptions.

    A ``\\\\?\\`` writer keeps the trailing-dot name as a distinct sibling directory, inside the primary's
    working tree or its .git, outside any exemption.
    """
    target = B + B + "?" + B + str(primary) + B + B.join(tail)
    assert_denied(run_gate(edit(target, cwd=tmp_path / "Elsewhere"), repos_file))


def test_the_trailing_dot_exemption_rows_have_a_real_exemption_beside_them(
    tmp_path: Path, primary: Path, repos_file: Path
) -> None:
    """Control: without the dot each spelling IS exempt, so the deny above is the dot's."""
    nested = B + B + "?" + B + str(primary / ".claude" / "worktrees" / "x" / "a.py")
    coord = B + B + "?" + B + str(primary / ".git" / "mefor-coord" / "x.md")
    assert run_gate(edit(nested, cwd=tmp_path / "Elsewhere"), repos_file) is None
    assert run_gate(edit(coord, cwd=tmp_path / "Elsewhere"), repos_file) is None


# --------------------------------------------------------------------------- rule 3c, end to end


@pytest.fixture
def repo(tmp_path: Path) -> SimpleNamespace:
    """A REAL governed repo and a real UNGOVERNED one: rule 3c asks git for the ``-C`` common dir."""
    if shutil.which("git") is None:
        pytest.skip("needs git on PATH")
    primary = tmp_path / "Primary"
    elsewhere = tmp_path / "Elsewhere"
    for args in (
        ["init", "-b", "main", str(primary)],
        ["init", "-b", "main", str(elsewhere)],
    ):
        subprocess.run(["git", *args], check=True, capture_output=True, text=True)
    repos = tmp_path / "repos.txt"
    repos.write_text(str(primary) + chr(10), encoding="utf-8")
    return SimpleNamespace(primary=primary, elsewhere=elsewhere, repos=repos)


# Each spelling is a template over the governed path: {b} with backslashes, {f} with forward slashes.
DISARM_SPELLINGS = [
    B + B + "." + B + "{b}",
    B + "??" + B + "{b}",
    "/??/{f}",
    B + B + "." + B + "GLOBALROOT" + B + "??" + B + "{b}",
    # git refuses the question-mark Global form (rc=128) but takes this one (rc=0, measured 2026-11-18).
    B + B + "." + B + "Global" + B + "{b}",
    B + B + "." + B + "GLOBALROOT" + B + "Global??" + B + "{b}",
    B + B + "?" + B + "{b}.",
    # Review round 1850f169: denied by the pre-#5454 gate, whose two replaces reduced it to the drive
    # path, and allowed by the one-pass fold, which stopped at `//?/c:/...`. git enters it (rc=0).
    B + B + "?" + B + "UNC" + B + "?" + B + "{b}",
]

# Spellings NEITHER path form folds onto the drive, which git still enters (review round 1850f169
# measured rc=0 for each). Rule 3c denies them through git's ABSOLUTE common dir, not through the fold.
ABSOLUTE_COMMON_DIR_SPELLINGS = [
    B + B + "?" + B + "X:" + B + ".." + B + "{b}",
    B + B + "?" + B + "." + B + "{b}",
    B + B + "." + B + "Global" + B + "Global" + B + "{b}",
]


@pytest.mark.parametrize("spelling", DISARM_SPELLINGS)
def test_an_unquoted_device_spelled_git_C_disarm_is_denied(
    repo: SimpleNamespace, spelling: str
) -> None:
    """The exploit the item measured, under the PowerShell tool, which passes the token unquoted."""
    target = spelling.format(b=str(repo.primary), f=str(repo.primary).replace(B, "/"))
    cmd = "git -C " + target + " config core.hooksPath x"
    reason = assert_denied(run_gate(bash(cmd, repo.elsewhere, tool="PowerShell"), repo.repos))
    assert "SHARED git configuration" in reason


@pytest.mark.parametrize("spelling", ABSOLUTE_COMMON_DIR_SPELLINGS)
def test_a_git_C_disarm_neither_form_folds_is_denied_through_the_absolute_common_dir(
    repo: SimpleNamespace, spelling: str
) -> None:
    """Rule 3c asks git for the absolute common dir, which names the governed repo behind these."""
    target = spelling.format(b=str(repo.primary))
    cmd = "git -C " + target + " config core.hooksPath x"
    reason = assert_denied(run_gate(bash(cmd, repo.elsewhere, tool="PowerShell"), repo.repos))
    assert "SHARED git configuration" in reason


@pytest.mark.parametrize("spelling", ABSOLUTE_COMMON_DIR_SPELLINGS)
def test_a_git_C_neither_form_folds_into_an_UNGOVERNED_repo_is_allowed(
    repo: SimpleNamespace, spelling: str
) -> None:
    """Control: the absolute common dir of a repository nobody governs does not deny."""
    target = spelling.format(b=str(repo.elsewhere))
    cmd = "git -C " + target + " config core.hooksPath x"
    assert run_gate(bash(cmd, repo.elsewhere, tool="PowerShell"), repo.repos) is None


@pytest.mark.parametrize("spelling", DISARM_SPELLINGS)
def test_a_device_spelled_git_C_into_an_UNGOVERNED_repo_is_allowed(
    repo: SimpleNamespace, spelling: str
) -> None:
    """Control: the same spellings of a repository nobody governs pass, so the deny is the fold's."""
    target = spelling.format(b=str(repo.elsewhere), f=str(repo.elsewhere).replace(B, "/"))
    cmd = "git -C " + target + " config core.hooksPath x"
    assert run_gate(bash(cmd, repo.elsewhere, tool="PowerShell"), repo.repos) is None


# --------------------------------------------- rules 3 and 3d, the lexical form end to end
#
# `\\?\UNC\?\<path>` is the spelling only the LEXICAL form reads as the drive path (its two replaces), and
# git enters it (rc=0, review round 1850f169). The rule 3 row denies only while rule 3 still asks the
# lexical form: dropping that pass from Test-GovernedEitherForm turns it red (it fails on fe218d603d8).
# The rule 3d row is ALSO held by git's absolute common dir, which a linked worktree reports anyway, so
# it pins the deny and not rule 3d's lexical pass; it passed on fe218d603d8 too.
UNC_Q = B + B + "?" + B + "UNC" + B + "?" + B


def test_a_tree_swap_only_the_lexical_form_reads_as_the_primary_is_denied(
    repo: SimpleNamespace,
) -> None:
    cmd = "git -C " + UNC_Q + str(repo.primary) + " checkout other"
    reason = assert_denied(run_gate(bash(cmd, repo.elsewhere, tool="PowerShell"), repo.repos))
    assert "SHARED PRIMARY" in reason


def test_the_same_tree_swap_into_an_UNGOVERNED_repo_is_allowed(repo: SimpleNamespace) -> None:
    """Control for the row above."""
    cmd = "git -C " + UNC_Q + str(repo.elsewhere) + " checkout other"
    assert run_gate(bash(cmd, repo.elsewhere, tool="PowerShell"), repo.repos) is None


def _linked_worktree(main: Path, wt: Path) -> None:
    git = ["git", "-c", "user.name=t", "-c", "user.email=t@example.invalid", "-C", str(main)]
    subprocess.run([*git, "commit", "-q", "--allow-empty", "-m", "init"], check=True)
    subprocess.run([*git, "worktree", "add", "-q", "-b", "wt-branch", str(wt)], check=True)


def test_removing_a_governed_worktree_only_the_lexical_form_reads_is_denied(
    tmp_path: Path, repo: SimpleNamespace
) -> None:
    wt = tmp_path / "Primary-wt"
    _linked_worktree(repo.primary, wt)
    cmd = "git worktree remove " + UNC_Q + str(wt)
    assert_denied(run_gate(bash(cmd, repo.elsewhere, tool="PowerShell"), repo.repos))


def test_removing_an_UNGOVERNED_worktree_the_same_way_is_allowed(
    tmp_path: Path, repo: SimpleNamespace
) -> None:
    """Control for the row above."""
    wt = tmp_path / "Elsewhere-wt"
    _linked_worktree(repo.elsewhere, wt)
    cmd = "git worktree remove " + UNC_Q + str(wt)
    assert run_gate(bash(cmd, repo.elsewhere, tool="PowerShell"), repo.repos) is None


@pytest.mark.xfail(
    strict=True,
    raises=AssertionError,
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
