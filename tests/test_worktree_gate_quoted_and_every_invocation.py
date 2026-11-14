# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The worktree gate reads a single-quoted path, and rules 3 and 3b judge every git invocation on a line.

* BACKLOG #5642 -- the shared ``cd``, ``-C``, ``--work-tree``, ``--git-dir`` and ``GIT_DIR`` readers
  stripped DOUBLE quotes only, so a SINGLE-quoted path to a governed checkout resolved to a
  quote-tainted path that named nothing, and rules 3, 3b and 3c allowed the command.
* BACKLOG #5655 -- rule 3 read ``-C`` off the whole raw line, so any earlier or quoted ``-C`` suppressed
  the inferred cwd target of a later invocation, and rule 3b judged only the first verb-bearing segment.

Each row of the ``_is_denied`` and ``_is_judged`` tests was measured ALLOW on origin/main before its
fix. The ALLOW controls beside them keep a gate that denied everything from passing, and the
``already_denied`` rows pin shapes origin/main denied, so a reading that reversed one would be seen. THE FIX IS ADDITIVE: every reading main made is still made,
first and unchanged, and the new readings can only add a deny (see the hook's ADDED READINGS note).
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from tests.test_worktree_gate import assert_denied, run_gate
from tests.test_worktree_gate_hijack import _make_repo, shell

pytestmark = pytest.mark.skipif(
    shutil.which("pwsh") is None or shutil.which("git") is None,
    reason="needs pwsh (PowerShell 7) and git on PATH",
)

_DISARM = "core." + "hooksPath /nope"


@pytest.fixture
def rig(tmp_path: Path) -> SimpleNamespace:
    """A governed primary with a linked worktree, plus an UNGOVERNED repository beside it."""
    r = _make_repo(tmp_path, "Primary")
    outside = tmp_path / "Outside"
    subprocess.run(
        ["git", "init", "-q", "-b", "main", str(outside)], check=True, capture_output=True
    )
    r.outside = outside
    r.tmp = tmp_path
    return r


def _fmt(rig: SimpleNamespace, template: str) -> str:
    return template.format(
        p=rig.primary.as_posix(),
        tmp=rig.tmp.as_posix(),
        wt=rig.wt.as_posix(),
        o=rig.outside.as_posix(),
        b=rig.other,
        k=_DISARM,
    )


def _cwd(rig: SimpleNamespace, where: str) -> Path:
    return {"primary": rig.primary, "outside": rig.outside, "wt": rig.wt, "tmp": rig.tmp}[where]


def _reason(rig: SimpleNamespace, command: str, cwd: Path, tool: str = "Bash") -> str:
    return assert_denied(run_gate(shell(command, cwd, tool), rig.repos))


def _allowed(rig: SimpleNamespace, command: str, cwd: Path, tool: str = "Bash") -> bool:
    return run_gate(shell(command, cwd, tool), rig.repos) is None


# ------------------------------------------------------------------ BACKLOG #5642, single quotes


@pytest.mark.parametrize("tool", ["Bash", "PowerShell"])
@pytest.mark.parametrize(
    ("template", "text"),
    [
        ("git -C '{p}' reset --hard", "SHARED PRIMARY"),
        ("git --work-tree='{p}' reset --hard", "SHARED PRIMARY"),
        ("git -C '{wt}' checkout {b}", "LINKED WORKTREE"),
        ("git -C '{p}' config {k}", "SHARED git configur"),
        ("git --git-dir='{p}/.git' config {k}", "SHARED git configur"),
    ],
)
def test_a_single_quoted_governed_path_is_denied(
    rig: SimpleNamespace, template: str, text: str, tool: str
) -> None:
    reason = _reason(rig, _fmt(rig, template), rig.outside, tool)
    assert text in reason, reason


@pytest.mark.parametrize(
    ("template", "text"),
    [
        ("GIT_WORK_TREE='{p}' git reset --hard", "SHARED PRIMARY"),
        ("GIT_DIR='{p}/.git' git config {k}", "SHARED git configur"),
        ("cd '{wt}' && git checkout {b}", "LINKED WORKTREE"),
        # A word the shell joins from quoted pieces names the primary too.
        ("git -C '{tmp}'/'Primary' reset --hard", "SHARED PRIMARY"),
        # An earlier quote character inside another quote does not switch the reading off.
        ("echo '\"' ; git -C '{p}' config {k}", "SHARED git configur"),
        ("echo '\"' ; git --work-tree='{p}' reset --hard", "SHARED PRIMARY"),
    ],
)
def test_a_single_quoted_governed_path_is_denied_posix_only_spellings(
    rig: SimpleNamespace, template: str, text: str
) -> None:
    reason = _reason(rig, _fmt(rig, template), rig.outside)
    assert text in reason, reason


@pytest.mark.parametrize(
    ("template", "where", "text"),
    [
        ("cd '{p}' && git reset --hard", "outside", "SHARED PRIMARY"),
        ("git -C '{p}' worktree remove ../Primary-wt", "outside", "worktree remove"),
        # The quote-tainted token named nothing, so rule 3c fell back to the governed cwd and denied.
        # Unquoted, the write lands in the ungoverned repository; the added reading cannot remove that
        # deny, which is the cost of a change that is strictly tighter than origin/main.
        ("git --git-dir='{o}/.git' config {k}", "primary", "SHARED git configur"),
    ],
)
def test_what_origin_main_already_denied_stays_denied(
    rig: SimpleNamespace, template: str, where: str, text: str
) -> None:
    """DENY on origin/main, measured; pinned so the added readings are seen not to reverse it."""
    reason = _reason(rig, _fmt(rig, template), _cwd(rig, where))
    assert text in reason, reason


@pytest.mark.parametrize(
    "template",
    [
        "git -C '{o}' reset --hard",
        "git --work-tree='{o}' reset --hard",
        "git -C '{o}' config {k}",
        "git --git-dir='{o}/.git' config {k}",
        "cd '{o}' && git reset --hard",
        "git commit -m \"see -C '{p}' later\"",
        "git stash push -m \"try --work-tree='{p}' later\"",
        "echo '\"' ; git stash push -m \"try -C '{p}' later\"",
        "echo \"then cd '{p}' && git log\" ; git config {k}",
    ],
)
def test_single_quote_controls_stay_allowed(rig: SimpleNamespace, template: str) -> None:
    """Reading the quotes must resolve the path, not deny every quoted one or a quoted mention."""
    assert _allowed(rig, _fmt(rig, template), rig.outside)


# ------------------------------------------------------------------ BACKLOG #5655, every invocation


@pytest.mark.parametrize(
    ("template", "where", "text"),
    [
        # An EARLIER command's -C suppressed the inferred cwd target of the later reset.
        ("git -C {o} status ; git reset --hard", "primary", "SHARED PRIMARY"),
        ("git -C {o} status && git checkout {b}", "primary", "SHARED PRIMARY"),
        # A QUOTED -C, which no git reads, suppressed it the same way.
        ("echo ' -C {o}' ; git reset --hard", "primary", "SHARED PRIMARY"),
        # A chdir into the primary, then a git whose target is inferred after a git with -C.
        ("cd {p} && git -C {o} status && git reset --hard", "outside", "SHARED PRIMARY"),
        # Rule 3b on a later invocation of the same line, class A and class B.
        ("git -C {o} checkout main ; git -C {wt} checkout {b}", "outside", "LINKED WORKTREE"),
        ("git -C {o} reset --hard ; git -C {wt} reset --hard", "outside", "LINKED WORKTREE"),
        # Rule 3b on a later LINE.
        ("git -C {o} checkout main\ngit -C {wt} checkout {b}", "outside", "LINKED WORKTREE"),
        ("git -C {o} reset --hard\ngit -C {wt} reset --hard", "outside", "LINKED WORKTREE"),
    ],
)
def test_every_invocation_is_judged(
    rig: SimpleNamespace, template: str, where: str, text: str
) -> None:
    reason = _reason(rig, _fmt(rig, template), _cwd(rig, where))
    assert text in reason, reason


@pytest.mark.parametrize(
    ("template", "where"),
    [
        ("git -C {o} reset --hard", "primary"),
        ("git -C {o} status ; git reset --hard", "outside"),
        ("git -C {o} reset --hard ; git -C {o} checkout main", "primary"),
        ("git -C {o} checkout main\ngit -C {o} reset --hard", "outside"),
        ("git reset --hard ; git -C {o} status", "outside"),
        ("git -C {wt} reset --hard ; git status", "wt"),
    ],
)
def test_every_invocation_controls_stay_allowed(
    rig: SimpleNamespace, template: str, where: str
) -> None:
    """An invocation that names an ungoverned tree, or the session's own worktree, is still allowed."""
    assert _allowed(rig, _fmt(rig, template), _cwd(rig, where))


# ------------------------------------------------------------------ review round 3411eb8641
#
# Each row was measured ALLOW on the first build of this branch (and on origin/main) by the reviewer.


@pytest.mark.parametrize(
    ("template", "where", "text", "tool"),
    [
        # A chdir on an EARLIER line, then a decoy -C that switched the old text fallback off.
        ("cd {p}\ngit -C {o} status ; git reset --hard", "outside", "SHARED PRIMARY", "Bash"),
        (
            "Set-Location {p}\ngit -C {o} status; git reset --hard",
            "outside",
            "SHARED PRIMARY",
            "PowerShell",
        ),
        ("cd {wt}\ngit -C {o} status ; git checkout {b}", "outside", "LINKED WORKTREE", "Bash"),
        # A harmless disarm-key write earlier on the line hid a later one from rule 3c.
        ("git config alias.lg log ; git -C '{p}' config {k}", "outside", "SHARED git", "Bash"),
        ("git -C {o} config alias.lg log ; git -C {p} config {k}", "outside", "SHARED git", "Bash"),
        # A relative --git-dir or GIT_DIR was rooted on the line's first -C, not on the cwd.
        (
            "git -C {o}/sub status ; git --git-dir=../Primary/.git checkout {b}",
            "outside",
            "through --git-dir or GIT_DIR",
            "Bash",
        ),
        (
            "git -C {o}/sub status ; GIT_DIR=../Primary/.git git checkout {b}",
            "outside",
            "through --git-dir or GIT_DIR",
            "Bash",
        ),
        (
            "git -C {o}/sub status ; git --git-dir='../Primary/.git' checkout {b}",
            "outside",
            "through --git-dir or GIT_DIR",
            "Bash",
        ),
        # A relative tree handed to rule 3b was asked of git from the hook's own directory.
        (
            "git -C {o} status ; git -C ../Primary-wt checkout {b}",
            "outside",
            "LINKED WORKTREE",
            "Bash",
        ),
        (
            "git -C {o} status ; cd ../Primary-wt && git checkout {b}",
            "outside",
            "LINKED WORKTREE",
            "Bash",
        ),
        (
            "git -C {o} status ; git -C ../Primary-wt reset --hard",
            "outside",
            "LINKED WORKTREE",
            "Bash",
        ),
        # A git word the owning-token pattern misses read an earlier command's -C.
        ("git -C {o} stash list ; git.EXE reset --hard", "primary", "SHARED PRIMARY", "Bash"),
    ],
)
def test_review_round_one_shapes_are_denied(
    rig: SimpleNamespace, template: str, where: str, text: str, tool: str
) -> None:
    reason = _reason(rig, _fmt(rig, template), _cwd(rig, where), tool)
    assert text in reason, reason


@pytest.mark.parametrize(
    "template",
    ["git -C '{wt}' checkout 'feat(x)'", "git -C {o} status ; git -C {wt} checkout 'feat(x)'"],
)
def test_a_quoted_destination_the_scan_blanks_is_still_read(
    rig: SimpleNamespace, template: str
) -> None:
    """A branch name that needs quoting is read from the raw line, as the first reading reads it."""
    subprocess.run(
        ["git", "-C", str(rig.primary), "branch", "feat(x)"], check=True, capture_output=True
    )
    reason = _reason(rig, _fmt(rig, template), rig.outside)
    assert "LINKED WORKTREE" in reason, reason


# ------------------------------------------------------------------ review round b62475f26d


@pytest.mark.parametrize(
    ("template", "where", "text"),
    [
        # Rule 3c's window starts at the git word that owns the disarm, not at an earlier command's.
        ("git -C {o} status ; git.EXE config {k}", "primary", "SHARED git"),
        # A chdir glued to `&&` is followed.
        ("cd {p}&&git config {k}", "outside", "SHARED git"),
        # An unrelated earlier line holding a paren does not switch the earlier-line chdir off.
        ("cd {p}\necho $(date)\ngit -C {o} status ; git reset --hard", "outside", "SHARED PRIMARY"),
    ],
)
def test_review_round_two_shapes_are_denied(
    rig: SimpleNamespace, template: str, where: str, text: str
) -> None:
    reason = _reason(rig, _fmt(rig, template), _cwd(rig, where))
    assert text in reason, reason


@pytest.mark.parametrize(
    ("template", "where"),
    [
        # A -C after a -c disarm decides where the command runs, as origin/main reads it.
        ("git -c {kv} -C {o} commit -m x", "primary"),
        ("git -c {kv} -C {o} commit -m x", "wt"),
        # After an earlier line moved the shell, the session cwd is not where the checkout runs.
        ("cd {o}\ngit -C {o} status ; git checkout {b}", "wt"),
        # A grep's -c after an excused bare config read is not a git disarm.
        ("git config core.hooksPath ; grep -c alias.x f", "primary"),
    ],
)
def test_review_round_two_controls_stay_allowed(
    rig: SimpleNamespace, template: str, where: str
) -> None:
    """ALLOW on origin/main; the first build of the added readings refused each one."""
    cmd = _fmt(rig, template.replace("{kv}", "core." + "hooksPath=/nope"))
    assert _allowed(rig, cmd, _cwd(rig, where))


# ------------------------------------------------------------------ review round f99d8271af


@pytest.mark.parametrize(
    ("template", "tool"),
    [
        ("if (git -C {o} diff --quiet) {{ git reset --hard }}", "PowerShell"),
        ("git -C {o} log $(git reset --hard)", "Bash"),
    ],
)
def test_an_invocation_joined_by_a_bracket_reads_its_own_window(
    rig: SimpleNamespace, template: str, tool: str
) -> None:
    """ALLOW on origin/main and on the round-two head: the window began at the earlier git word."""
    reason = _reason(rig, _fmt(rig, template), rig.primary, tool)
    assert "SHARED PRIMARY" in reason, reason


_SUBST = "user.name=$(git config user.name)"


@pytest.mark.parametrize(
    ("template", "where", "text", "tool"),
    [
        # A git word inside a substitution that closes before the verb does not own the window, so
        # the invocation's own quoted -C or --work-tree is still read (review round c17b991ada).
        ("git -C '{p}' -c {s} reset --hard", "outside", "SHARED PRIMARY", "Bash"),
        ("git -C '{p}' --git-dir=$(pwd)/.git reset --hard", "outside", "SHARED PRIMARY", "Bash"),
        (
            "git --work-tree='{p}' --git-dir=${{PWD}}/.git reset --hard",
            "outside",
            "SHARED PRIMARY",
            "Bash",
        ),
        ("git -C '{wt}' -c {s} checkout {b}", "outside", "LINKED WORKTREE", "Bash"),
    ],
)
def test_a_git_word_in_a_closed_substitution_does_not_own_the_window(
    rig: SimpleNamespace, template: str, where: str, text: str, tool: str
) -> None:
    cmd = _fmt(rig, template.replace("{s}", _SUBST))
    reason = _reason(rig, cmd, _cwd(rig, where), tool)
    assert text in reason, reason


@pytest.mark.parametrize(
    ("template", "tool"),
    [
        ("if (git -C {o} diff --quiet) {{ git -C {o} reset --hard }}", "PowerShell"),
        ("git -C {o} -c {s} reset --hard", "Bash"),
        ("git -C {o} --git-dir=$(pwd)/.git reset --hard", "Bash"),
    ],
)
def test_bracket_controls_stay_allowed(rig: SimpleNamespace, template: str, tool: str) -> None:
    """ALLOW on origin/main from the primary: each command acts on the ungoverned repository."""
    cmd = _fmt(rig, template.replace("{s}", _SUBST))
    assert _allowed(rig, cmd, rig.primary, tool)
