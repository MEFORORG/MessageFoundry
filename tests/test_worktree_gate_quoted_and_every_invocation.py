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
import time
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


# ------------------------------------------------------------------ review round 73e9b81f0a
#
# DENY on ff2d69b286, ALLOW on 8e1c8eb5e4: the owning-word search missed a path-qualified git and
# answered an earlier command's git across `;`.


@pytest.mark.parametrize(
    ("template", "tool"),
    [
        ("git -C {o} status ; /usr/bin/git reset --hard", "Bash"),
        (r"git -C {o} status ; \git reset --hard", "Bash"),
        ("git -C {o} status ; C:/Tools/Git/cmd/git.exe reset --hard", "Bash"),
        ("git -C {o} status ; git.cmd reset --hard", "Bash"),
        (r"git -C {o} status; C:\Tools\Git\cmd\git.exe reset --hard", "PowerShell"),
    ],
)
def test_a_path_qualified_git_after_an_earlier_command_is_rule_3s(
    rig: SimpleNamespace, template: str, tool: str
) -> None:
    reason = _reason(rig, _fmt(rig, template), rig.primary, tool)
    assert "SHARED PRIMARY" in reason, reason


@pytest.mark.parametrize(
    "template",
    [
        "git config alias.lg log ; /usr/bin/git -C '{p}' config {k}",
        r"git config alias.lg log ; git -C '{p}' -c a=\) config {k}",
    ],
)
def test_a_later_disarm_owned_by_a_path_git_or_after_a_closer_is_rule_3cs(
    rig: SimpleNamespace, template: str
) -> None:
    reason = _reason(rig, _fmt(rig, template), rig.outside)
    assert "SHARED git" in reason, reason


# ------------------------------------------------------------------ BACKLOG #5655 closing steps 1, 3, 6
#
# Each row of test_closing_step_shapes_are_denied was measured ALLOW on origin/main f0e49f45c5c, run
# from an ungoverned repository. Other DENY rows below are not all origin/main's: several are refusals
# this branch adds.


@pytest.mark.parametrize(
    ("template", "text"),
    [
        # Step 1: the broad git word answered the git inside the closed `$( )`, so no `-C` was read.
        ("git -C '{p}' -c user.name=$(git log -1 --format=%an) config {k}", "SHARED git configur"),
        # Step 3: an earlier line's subshell chdir switched the added reading off.
        ("(cd {tmp} && ls)\ngit -C '{p}' reset --hard", "SHARED PRIMARY"),
    ],
)
def test_closing_step_shapes_are_denied(rig: SimpleNamespace, template: str, text: str) -> None:
    reason = _reason(rig, _fmt(rig, template), rig.outside)
    assert text in reason, reason


@pytest.mark.parametrize(
    ("template", "tool"),
    [
        ("git -C '{o}' -c user.name=$(git log -1 --format=%an) config {k}", "Bash"),
        ("git -C '{o}' -c user.name=$(git config user.name) config {k}", "Bash"),
        ("(cd {tmp} && ls)\ngit -C '{o}' reset --hard", "Bash"),
        ("git commit -m '' ; git -C {o} status", "Bash"),
    ],
)
def test_closing_step_controls_stay_allowed(rig: SimpleNamespace, template: str, tool: str) -> None:
    assert _allowed(rig, _fmt(rig, template), rig.outside, tool)


# Step 6: the known false denies of the added readings, pinned as KNOWN. Each row is a command whose
# verdict should be ALLOW and is DENY; a change that fixes one fails its row here, and the row then
# moves to the ALLOW controls above. Plain asserts rather than a strict xfail, so a pwsh launch timeout
# (BACKLOG #1304) surfaces as itself instead of reading as the expected failure.
@pytest.mark.parametrize(
    ("template", "where", "tool"),
    [
        # An earlier bracket-joined command's `-C` decides the later reset.
        ("if (git -C '{p}' diff --quiet) {{ git reset --hard }}", "outside", "PowerShell"),
        # The later-disarm filter counts `.git` as a git word, so the grep's `-c alias.lg` is judged.
        ("git config core.hooksPath ; grep --exclude-dir=.git -c alias.lg f", "primary", "Bash"),
        # Rule 3c's first window starts at a git inside a closed `$( )`, or at the git of a `.git`
        # path, so it names no `-C` and falls back to the session cwd. DENY on origin/main too.
        ("git -C {o} -c user.name=$(git log -1 --format=%an) config {k}", "primary", "Bash"),
        ("git -C {o} --git-dir=$(echo .git) config {k}", "primary", "Bash"),
        # KNOWN FALSE DENIES below, each ALLOW on origin/main f0e49f45c5c (measured with the PR 3030
        # reviewer probes) and listed in the hook's ADDED READINGS note.
        # A `config` pathspec after a closed `$( )` reads as a config disarm of the `-C` repository.
        ("git -C '{p}' log $(git rev-parse HEAD) -- config core.hooksPath x", "outside", "Bash"),
        # $absC folds the `-C` inside the closed `$( )` as the outer invocation's.
        ("(cd {tmp} && ls)\ngit -c a=$(git -C '{p}' log -1) config {k}", "outside", "Bash"),
        # Rule 3c's owning-word reading compares bracket counts, not nesting, so the owner git in an
        # earlier closed `$( )` decides the disarm in a later one.
        ("echo $(git -C '{p}' log -1) $(/usr/bin/git config {k})", "outside", "Bash"),
        # Each is refused on a line of its own (origin/main's too); the $absC fallback carries that
        # refusal past an earlier line's chdir in parentheses. A fix belongs in the one-line reading.
        ("(cd {tmp} && ls)\ngit -C '{p}' stash list", "outside", "Bash"),
        ("(cd {tmp} && ls)\ngit -C '{p}' ''--git-dir={o}/.git config {k}", "outside", "Bash"),
        (
            "(cd {tmp} && ls)\ngit -C '{o}' log $(git -C '{p}' rev-parse HEAD) -- config core.hooksPath x",
            "outside",
            "Bash",
        ),
    ],
)
def test_known_false_denies_of_the_added_readings_still_deny(
    rig: SimpleNamespace, template: str, where: str, tool: str
) -> None:
    assert not _allowed(rig, _fmt(rig, template), _cwd(rig, where), tool)


# Quoted forms the gate's unquoting does not read as the shell does (closing step 7), left ALLOW as on
# origin/main f0e49f45c5c. Each names the primary, so each should be DENY; a fix flips its row.
@pytest.mark.parametrize(
    "template",
    [
        "git -C $'{p}' reset --hard",
        "git -C ''{p} reset --hard",
        "git -C {p}'' reset --hard",
        "bash -c 'git -C '\"'\"'{p}'\"'\"' reset --hard'",
        r"bash -c 'git -C '\''{p}'\'' reset --hard'",
    ],
)
def test_known_gap_joined_quote_forms_stay_allowed(rig: SimpleNamespace, template: str) -> None:
    assert _allowed(rig, _fmt(rig, template), rig.outside)


@pytest.mark.parametrize(
    "template",
    [
        # Review round c49803c0c3, finding 4: the git runs in the ungoverned repository. Allowed on
        # origin/main; refused by this branch's former joined `bash -c` reading.
        r"bash -c 'git -C '\''{o}'\'' stash list'",
        r"bash -c 'git -C '\''{o}'\'' reset --hard'",
    ],
)
def test_a_joined_bash_payload_naming_an_ungoverned_repo_is_allowed_from_the_primary(
    rig: SimpleNamespace, template: str
) -> None:
    assert _allowed(rig, _fmt(rig, template), rig.primary)


# Review round 34781a2201: shapes the first build of this change got wrong.
@pytest.mark.parametrize(
    ("template", "where", "tool"),
    [
        # Rule 3c's owning word must not cross `;` to an earlier command's `-C`.
        ("git -C '{p}' log ; /usr/bin/git config {k}", "outside", "Bash"),
        (r"git -C '{p}' log ; \git config {k}", "outside", "Bash"),
        # PowerShell passes a leading `''` as an argument of its own, so it joins nothing -- only while
        # $PSNativeCommandArgumentPassing is not Legacy. Under Legacy the empty argument is dropped and
        # this command runs against the primary, so this row pins the gate's ALLOW, not a safe command.
        ("git -C ''{p} reset --hard", "outside", "PowerShell"),
    ],
)
def test_review_round_controls_stay_allowed(
    rig: SimpleNamespace, template: str, where: str, tool: str
) -> None:
    assert _allowed(rig, _fmt(rig, template), _cwd(rig, where), tool)


@pytest.mark.parametrize(
    ("template", "where", "text"),
    [
        # A later absolute `-C` after a relative one, behind an earlier subshell chdir.
        ("(cd {tmp} && ls)\ngit -C Primary -C '{p}' reset --hard", "outside", "SHARED PRIMARY"),
        # Origin/main's reading of an empty pair glued to a chdir verb is kept: the scan is unchanged.
        ("git commit -C HEAD && cd'' . && git config {k}", "primary", "SHARED git configur"),
    ],
)
def test_review_round_shapes_are_denied(
    rig: SimpleNamespace, template: str, where: str, text: str
) -> None:
    reason = _reason(rig, _fmt(rig, template), _cwd(rig, where))
    assert text in reason, reason


def test_a_disarm_inside_a_substitution_is_not_the_outer_commands(rig: SimpleNamespace) -> None:
    # The substitution's git runs in the cwd; the outer `-C` must not decide it.
    assert _allowed(rig, _fmt(rig, "git -C '{p}' log $(/usr/bin/git config {k})"), rig.outside)


@pytest.mark.parametrize("tool", ["Bash", "PowerShell"])
def test_a_spacey_quoted_suffix_names_its_own_repository(rig: SimpleNamespace, tool: str) -> None:
    # `<p>' copy'` names `<p> copy`, an ungoverned repository; origin/main allows this.
    copy = rig.tmp / "Primary copy"
    subprocess.run(["git", "init", "-q", "-b", "main", str(copy)], check=True, capture_output=True)
    assert _allowed(rig, _fmt(rig, "git -C {p}' copy' reset --hard"), rig.outside, tool)
    assert _allowed(rig, _fmt(rig, "echo a'' ; git -C {p}' copy' reset --hard"), rig.outside, tool)


def test_origin_mains_bare_read_with_a_glued_pair_still_denies(rig: SimpleNamespace) -> None:
    # A false deny origin/main already makes, not one of the added readings': bash runs this as the
    # bare read `git config core.hooksPath`. Pinned as known, with its refusal text.
    reason = _reason(rig, "git config core.hooksPath''", rig.primary)
    assert "SHARED git configur" in reason, reason


@pytest.mark.parametrize(
    "template",
    ["git -C '{p}''' reset --hard", "git -C '{p}''' config {k}", "git -C ''\"{p}\" reset --hard"],
)
def test_powershell_escaped_or_leading_pairs_stay_allowed(
    rig: SimpleNamespace, template: str
) -> None:
    # PowerShell passes `'<p>'''` as `<p>'` and `''"<p>"` as two arguments, so none names the primary.
    # The two-argument reading of `''"<p>"` holds only while $PSNativeCommandArgumentPassing is not
    # Legacy; under Legacy the empty argument is dropped and that row runs against the primary, so it
    # pins the gate's ALLOW, not a safe command.
    assert _allowed(rig, _fmt(rig, template), rig.outside, "PowerShell")


def test_a_bash_payload_on_an_earlier_line_does_not_hide_a_later_lines_payload(
    rig: SimpleNamespace,
) -> None:
    # Review round 462e4285: an intermediate head emitted line 1's payload ahead of line 2's, so rule
    # 3b judged line 1's checkout (in an ungoverned repository) and never reached line 2's. Measured
    # ALLOW on that head (2026-11-17) and DENY on origin/main f0e49f45c5c.
    who = ["-c", "user.name=t", "-c", "user.email=t@example.invalid"]
    for args in (["commit", "-q", "--allow-empty", "-m", "x"], ["branch", rig.other]):
        subprocess.run(
            ["git", *who, "-C", str(rig.outside), *args], check=True, capture_output=True
        )
    first = r"bash -c 'git -C '\''{o}'\'' checkout {b}'"
    second = "bash -c 'git -C {wt} -C \"\" checkout {b}'"
    reason = _reason(rig, _fmt(rig, first + "\n" + second), rig.outside)
    assert "LINKED WORKTREE" in reason, reason


def test_known_gap_an_inner_config_word_ahead_of_the_disarm(rig: SimpleNamespace) -> None:
    # Known gap, ALLOW on origin/main f0e49f45c5c too: the disarm match starts at the `config` inside
    # the closed `$( )`, so rule 3c's added reading reads only the inner invocation. A fix flips this.
    command = _fmt(rig, "git -C '{p}' -c user.name=$(git config user.name) config {k}")
    assert _allowed(rig, command, rig.outside)


def test_known_gap_a_separator_inside_a_closed_substitution(rig: SimpleNamespace) -> None:
    # Known gap, ALLOW on origin/main f0e49f45c5c too: the `|` inside the closed `$( )` stops rule 3c's
    # owning-word reading, so the outer quoted `-C` is not read. A fix flips this row.
    command = _fmt(rig, "git -C '{p}' -c user.name=$(git log -1 | head -1) config {k}")
    assert _allowed(rig, command, rig.outside)


def test_a_long_run_of_glued_pairs_costs_about_what_a_short_line_does(rig: SimpleNamespace) -> None:
    # Review round c49803c0c3, finding 3: an intermediate head's joined reading grew with the square
    # of the line, and a 12 KB run of glued `''` after one `-C` outran the gate's 45 s test budget
    # (27.7 s in that review; origin/main about 2 s). The ceiling is generous on purpose, so a slow
    # pwsh launch does not flake it: the regression it guards costs tens of seconds.
    short = _fmt(rig, "git -C {o}'' reset --hard")
    long = _fmt(rig, "git -C {o}" + "''" * 5900 + " reset --hard")
    started = time.monotonic()
    assert _allowed(rig, short, rig.outside)
    short_s = time.monotonic() - started
    started = time.monotonic()
    assert _allowed(rig, long, rig.outside)
    long_s = time.monotonic() - started
    assert long_s < 3 * short_s + 20, (short_s, long_s)


# ------------------------------------------------------------------ BACKLOG #5655 step 3, three gaps
# Each DENY row below was measured ALLOW on origin/main 9421dcbf272 (2026-11-20). The ALLOW rows
# beside them aim the same spellings at the ungoverned repository, so a gate that refused every such
# spelling would fail them.


@pytest.mark.parametrize("tool", ["Bash", "PowerShell"])
@pytest.mark.parametrize(
    ("template", "text"),
    [
        ("cd {p} && git -C {o} log $(git reset --hard)", "SHARED PRIMARY"),
        ("cd {p} && git -C {o} log $(git config {k})", "SHARED git configur"),
    ],
)
def test_a_chdir_ahead_of_a_bracket_joined_invocation_is_read(
    rig: SimpleNamespace, template: str, text: str, tool: str
) -> None:
    # The substitution's git runs in <p>; its prefix holds the `$(`, which the chdir follower does
    # not read past, so the inner command stood in the session cwd.
    reason = _reason(rig, _fmt(rig, template), rig.outside, tool)
    assert text in reason, reason


@pytest.mark.parametrize("tool", ["Bash", "PowerShell"])
def test_an_earlier_lines_chdir_ahead_of_a_bracket_joined_invocation_is_read(
    rig: SimpleNamespace, tool: str
) -> None:
    # No separator before the bracket on this line, so the shell stands in the earlier line's chdir.
    tail = "\ngit -C {o} log $(git reset --hard)"
    reason = _reason(rig, _fmt(rig, "cd {p}" + tail), rig.outside, tool)
    assert "SHARED PRIMARY" in reason, reason
    assert _allowed(rig, _fmt(rig, "cd {o}" + tail), rig.outside, tool)
    # A separator before the bracket on this line, with no chdir ahead of it.
    joined = "\necho hi; git -C {o} log $(git reset --hard)"
    reason = _reason(rig, _fmt(rig, "cd {p}" + joined), rig.outside, tool)
    assert "SHARED PRIMARY" in reason, reason
    assert _allowed(rig, _fmt(rig, "cd {o}" + joined), rig.outside, tool)


def test_a_chdir_ahead_of_a_powershell_block_is_read(rig: SimpleNamespace) -> None:
    command = _fmt(rig, "cd {p}; if (git -C {o} diff --quiet) {{ git reset --hard }}")
    reason = _reason(rig, command, rig.outside, "PowerShell")
    assert "SHARED PRIMARY" in reason, reason


@pytest.mark.parametrize("tool", ["Bash", "PowerShell"])
@pytest.mark.parametrize(
    "template",
    [
        "cd {o} && git -C {o} log $(git reset --hard)",
        "cd {o} && git -C {o} log $(git config {k})",
    ],
)
def test_a_chdir_ahead_of_a_bracket_into_an_ungoverned_repository_is_allowed(
    rig: SimpleNamespace, template: str, tool: str
) -> None:
    assert _allowed(rig, _fmt(rig, template), rig.outside, tool)


@pytest.mark.parametrize("tool", ["Bash", "PowerShell"])
@pytest.mark.parametrize(
    "template",
    [
        "git -c {d} --git-dir={p}/.git commit -m x",
        "git -c {d} --git-dir {p}/.git commit -m x",
        "git -c {d} --git-dir='{p}/.git' commit -m x",
    ],
)
def test_a_git_dir_after_a_dash_c_disarm_is_promoted(
    rig: SimpleNamespace, template: str, tool: str
) -> None:
    # The `--git-dir` follows the disarm, so the window read up to the disarm never saw it and the
    # session cwd answered first.
    command = _fmt(rig, template.replace("{d}", "core.hooksPath=/nope"))
    reason = _reason(rig, command, rig.outside, tool)
    assert "SHARED git configur" in reason, reason


@pytest.mark.parametrize("tool", ["Bash", "PowerShell"])
def test_a_git_dir_after_a_dash_c_disarm_into_an_ungoverned_repository_is_allowed(
    rig: SimpleNamespace, tool: str
) -> None:
    command = _fmt(rig, "git -c core.hooksPath=/nope --git-dir={o}/.git commit -m x")
    assert _allowed(rig, command, rig.outside, tool)


@pytest.mark.parametrize("tool", ["Bash", "PowerShell"])
@pytest.mark.parametrize(
    ("command", "where", "text"),
    [
        ("git.EXE reset --hard", "primary", "SHARED PRIMARY"),
        ("git.EXE config {k}", "primary", "SHARED git configur"),
        ("git.Exe -C {p} reset --hard", "outside", "SHARED PRIMARY"),
    ],
)
def test_a_git_word_with_an_upper_case_suffix_is_read(
    rig: SimpleNamespace, command: str, where: str, text: str, tool: str
) -> None:
    # Windows runs git.exe for `git.EXE`; the case-sensitive token read only `git.exe`.
    reason = _reason(rig, _fmt(rig, command), _cwd(rig, where), tool)
    assert text in reason, reason


@pytest.mark.parametrize("tool", ["Bash", "PowerShell"])
@pytest.mark.parametrize(
    ("command", "where"),
    [
        ("git.EXE reset --hard", "outside"),
        ("git.EXE config {k}", "outside"),
        ("git.EXE status", "primary"),
    ],
)
def test_a_git_word_with_an_upper_case_suffix_elsewhere_is_allowed(
    rig: SimpleNamespace, command: str, where: str, tool: str
) -> None:
    assert _allowed(rig, _fmt(rig, command), _cwd(rig, where), tool)
