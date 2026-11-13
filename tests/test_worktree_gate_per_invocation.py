# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The worktree gate reads each git invocation's OWN tokens, however they are quoted.

Three rows, one shape: a token that decides which tree or repository a git command acts on was read
from the wrong place, so the gate judged a different path from the one the shell hands git.

* BACKLOG #5642 -- the shared ``cd``, ``-C``, ``--work-tree``, ``--git-dir`` and ``GIT_DIR`` readers
  stripped DOUBLE quotes only, so a SINGLE-quoted path to the governed checkout resolved to a
  quote-tainted path that names nothing, and rules 3, 3b, 3c and 3d allowed it.
* BACKLOG #5643 -- rule 3d sliced the raw line at its FIRST `worktree remove|move` and judged one
  invocation, resolving a relative victim from the line's first `-C`, so a quoted mention, a second
  invocation or another command's `-C` let a governed linked worktree be removed or moved.
* BACKLOG #5655 -- rule 3 let any earlier or quoted `-C` on a line decide where a later command ran,
  and rule 3b judged only the first verb-bearing segment.

Each deny row was measured ALLOW on the gate before its fix, and each has an ALLOW control beside it
so a gate that denied everything could not pass.
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


@pytest.fixture
def rig(tmp_path: Path) -> SimpleNamespace:
    """A governed primary with two linked worktrees, plus two UNGOVERNED repositories beside it."""
    r = _make_repo(tmp_path, "Primary")
    wt2 = tmp_path / "Primary-wt2"
    subprocess.run(
        ["git", "-C", str(r.primary), "worktree", "add", "-q", "-b", "wt2", str(wt2)],
        check=True,
        capture_output=True,
    )
    outside = tmp_path / "Outside"
    outside2 = tmp_path / "deeper" / "Outside2"
    for repo in (outside, outside2):
        subprocess.run(
            ["git", "init", "-q", "-b", "main", str(repo)], check=True, capture_output=True
        )
    r.wt2 = wt2
    r.outside = outside
    r.outside2 = outside2
    r.tmp = tmp_path
    return r


def _reason(rig: SimpleNamespace, command: str, cwd: Path) -> str:
    return assert_denied(run_gate(shell(command, cwd), rig.repos))


def _allowed(rig: SimpleNamespace, command: str, cwd: Path) -> bool:
    return run_gate(shell(command, cwd), rig.repos) is None


# ------------------------------------------------------------------ BACKLOG #5642, single quotes


@pytest.mark.parametrize(
    "template",
    [
        "git -C '{p}' reset --hard",
        "git --work-tree='{p}' reset --hard",
        "GIT_WORK_TREE='{p}' git reset --hard",
    ],
)
def test_a_single_quoted_path_to_the_primary_is_rule_3s(
    rig: SimpleNamespace, template: str
) -> None:
    """MEASURED ALLOW before #5642, from an ungoverned cwd; the double-quoted spelling always denied."""
    reason = _reason(rig, template.format(p=rig.primary.as_posix()), rig.outside)
    assert "SHARED PRIMARY" in reason, reason


def test_a_single_quoted_dash_C_into_a_linked_worktree_is_rule_3bs(rig: SimpleNamespace) -> None:
    reason = _reason(rig, f"git -C '{rig.wt.as_posix()}' checkout {rig.other}", rig.outside)
    assert "LINKED WORKTREE" in reason, reason


@pytest.mark.parametrize(
    "template",
    [
        "git -C '{p}' config core.hooksPath /nope",
        "git --git-dir='{p}/.git' config core.hooksPath /nope",
        "GIT_DIR='{p}/.git' git config core.hooksPath /nope",
    ],
)
def test_a_single_quoted_repository_token_is_rule_3cs(rig: SimpleNamespace, template: str) -> None:
    reason = _reason(rig, template.format(p=rig.primary.as_posix()), rig.outside)
    assert "SHARED git configur" in reason, reason


def test_a_single_quoted_dash_C_base_is_rule_3ds(rig: SimpleNamespace) -> None:
    reason = _reason(
        rig, f"git -C '{rig.primary.as_posix()}' worktree remove ../Primary-wt2", rig.outside
    )
    assert "worktree remove" in reason, reason


@pytest.mark.parametrize(
    "template",
    [
        "git -C '{o}' reset --hard",
        "git --work-tree='{o}' reset --hard",
        "git -C '{o}' config core.hooksPath /nope",
        "git --git-dir='{o}/.git' config core.hooksPath /nope",
        "cd '{o}' && git reset --hard",
    ],
)
def test_a_single_quoted_UNGOVERNED_path_is_still_allowed(
    rig: SimpleNamespace, template: str
) -> None:
    """The control: stripping the quotes must resolve the path, not deny every quoted one."""
    assert _allowed(rig, template.format(o=rig.outside.as_posix()), rig.outside)


def test_a_single_quoted_ungoverned_git_dir_from_the_primary_matches_its_double_quoted_twin(
    rig: SimpleNamespace,
) -> None:
    """The one verdict #5642 moves toward ALLOW, pinned so it is seen rather than discovered.

    From a governed cwd the quote-tainted token named nothing, git rejected it, and the rule fell back
    to the cwd and denied. The write lands in the ungoverned repository, which is what the
    double-quoted spelling has always been allowed to do; the two spellings now agree.
    """
    o = rig.outside.as_posix()
    double = f'git --git-dir="{o}/.git" config core.hooksPath /nope'
    single = f"git --git-dir='{o}/.git' config core.hooksPath /nope"
    assert _allowed(rig, double, rig.primary)
    assert _allowed(rig, single, rig.primary)


# ------------------------------------------------------------------ BACKLOG #5643, rule 3d per invocation
#
# Rule 3d sliced the RAW line at its FIRST `worktree remove|move` and judged that one invocation,
# resolving a relative victim from the line's FIRST `-C`. Each row below was measured ALLOW before.


def test_a_quoted_mention_before_the_real_remove_does_not_hide_it(rig: SimpleNamespace) -> None:
    cmd = f"echo 'git worktree remove x' ; git worktree remove {rig.wt2.as_posix()}"
    assert "worktree remove" in _reason(rig, cmd, rig.outside)


def test_a_second_remove_on_the_line_is_judged(rig: SimpleNamespace) -> None:
    cmd = (
        f"git worktree remove {rig.outside.as_posix()}/nope ; "
        f"git worktree remove {rig.wt2.as_posix()}"
    )
    assert "worktree remove" in _reason(rig, cmd, rig.outside)


def test_a_quoted_mention_before_a_real_move_does_not_hide_it(rig: SimpleNamespace) -> None:
    cmd = (
        f"echo 'git worktree move x y' ; "
        f"git worktree move {rig.wt2.as_posix()} {rig.tmp.as_posix()}/moved"
    )
    assert "worktree move" in _reason(rig, cmd, rig.outside)


def test_a_later_commands_dash_C_does_not_reroot_a_relative_victim(rig: SimpleNamespace) -> None:
    cmd = f"git worktree remove Primary-wt2 ; git -C {rig.outside2.as_posix()} status"
    assert "worktree remove" in _reason(rig, cmd, rig.tmp)


def test_cumulative_dash_C_is_folded(rig: SimpleNamespace) -> None:
    cmd = f"git -C {rig.tmp.as_posix()} -C Primary worktree remove ../Primary-wt2"
    assert "worktree remove" in _reason(rig, cmd, rig.outside)


@pytest.mark.parametrize(
    "template",
    [
        "echo 'git worktree remove {wt2}'",
        "git worktree remove {o}/nope ; git -C {wt2} status",
        "git -C {o2} worktree remove Primary-wt2",
    ],
)
def test_rule_3d_controls_stay_allowed(rig: SimpleNamespace, template: str) -> None:
    """A mention is not a removal, and an explicit `-C` elsewhere still decides where the victim is."""
    cmd = template.format(
        wt2=rig.wt2.as_posix(), o=rig.outside.as_posix(), o2=rig.outside2.as_posix()
    )
    assert _allowed(rig, cmd, rig.tmp)


# ------------------------------------------------------------------ BACKLOG #5655, rules 3 and 3b
#
# Rule 3 read `-C` off the WHOLE raw line and set its inferred-target flag the same way, so any
# earlier or quoted `-C` decided where a later command ran; rule 3b judged only the first
# verb-bearing segment. Each deny row below was measured ALLOW before.


def test_an_earlier_commands_dash_C_does_not_move_a_later_reset_off_the_primary(
    rig: SimpleNamespace,
) -> None:
    cmd = f"git -C {rig.outside.as_posix()} status && git reset --hard"
    assert "SHARED PRIMARY" in _reason(rig, cmd, rig.primary)


def test_an_earlier_dash_C_does_not_suppress_the_chdir_fallback(rig: SimpleNamespace) -> None:
    cmd = f"git -C {rig.outside.as_posix()} status ; cd {rig.primary.as_posix()} ; git reset --hard"
    assert "SHARED PRIMARY" in _reason(rig, cmd, rig.outside)


def test_a_quoted_dash_C_does_not_suppress_the_chdir_fallback(rig: SimpleNamespace) -> None:
    cmd = f"git commit -m 'x -C y' ; cd {rig.primary.as_posix()} ; git reset --hard"
    assert "SHARED PRIMARY" in _reason(rig, cmd, rig.outside)


@pytest.mark.parametrize("sep", [" ; ", "\n"])
def test_rule_3b_judges_a_later_invocation(rig: SimpleNamespace, sep: str) -> None:
    cmd = f"git -C {rig.outside.as_posix()} clean -fd{sep}git switch {rig.other}"
    assert "LINKED WORKTREE" in _reason(rig, cmd, rig.wt)


def test_rule_3b_judges_a_later_invocations_own_dash_C(rig: SimpleNamespace) -> None:
    cmd = (
        f"git -C {rig.outside.as_posix()} status ; git -C {rig.wt.as_posix()} checkout {rig.other}"
    )
    assert "LINKED WORKTREE" in _reason(rig, cmd, rig.outside)


@pytest.mark.parametrize(
    ("template", "where"),
    [
        ("cd {p} && git -C {o} rebase main", "outside"),
        ("git -C {o} status && git -C {o} reset --hard", "primary"),
        ("git -C {o} status ; git reset --hard", "wt"),
        ("git status ; git reset --hard", "outside"),
        ("git -C {o} status ; git switch -c brand-new", "wt"),
    ],
)
def test_rule_3_and_3b_controls_stay_allowed(
    rig: SimpleNamespace, template: str, where: str
) -> None:
    """An invocation's OWN `-C` still decides, and a session's own worktree is still its own."""
    cmd = template.format(p=rig.primary.as_posix(), o=rig.outside.as_posix())
    cwd = {"outside": rig.outside, "primary": rig.primary, "wt": rig.wt}[where]
    assert _allowed(rig, cmd, cwd)


# ------------------------------------------------------------------ review round one, same rows


@pytest.mark.parametrize("quote", ["''", '""'])
def test_an_empty_dash_C_is_the_cwd_under_either_quote(rig: SimpleNamespace, quote: str) -> None:
    """git reads an empty `-C` as the current directory; `-C ''` allowed under 3c before this round."""
    reason = _reason(rig, f"git -C {quote} config core.hooksPath /nope", rig.primary)
    assert "SHARED git configur" in reason, reason


def test_an_empty_single_quoted_dash_C_in_a_linked_worktree_is_rule_3bs(
    rig: SimpleNamespace,
) -> None:
    assert "LINKED WORKTREE" in _reason(rig, f"git -C '' switch {rig.other}", rig.wt)


def test_a_backtick_substitution_does_not_borrow_the_outer_dash_C(rig: SimpleNamespace) -> None:
    cmd = f"echo -C {rig.outside.as_posix()} `git reset --hard`"
    assert "SHARED PRIMARY" in _reason(rig, cmd, rig.primary)


def test_a_later_invocations_quoted_destination_is_read_raw(rig: SimpleNamespace) -> None:
    subprocess.run(
        ["git", "-C", str(rig.primary), "branch", "feat(x)"], check=True, capture_output=True
    )
    cmd = f"git -C {rig.outside.as_posix()} clean -fd ; git switch 'feat(x)'"
    assert "LINKED WORKTREE" in _reason(rig, cmd, rig.wt)


def test_a_later_invocations_relative_dash_C_is_rooted_at_the_session_cwd(
    rig: SimpleNamespace,
) -> None:
    cmd = f"git -C {rig.outside.as_posix()} status ; git -C ../Primary-wt switch {rig.other}"
    assert "LINKED WORKTREE" in _reason(rig, cmd, rig.outside)


# ------------------------------------------------------------------ review round two, same rows


def _quoted_dotdot_dir(rig: SimpleNamespace) -> None:
    """A directory literally named `'..'` inside the primary, which the shell can name with `"'..'"`."""
    (rig.primary / "'..'").mkdir()


@pytest.mark.parametrize(
    "template",
    [
        "git -C \"'..'\" config core.hooksPath /nope",
        "cd \"'..'\" && git config core.hooksPath /nope",
        "git -C \"'..'\" reset --hard",
    ],
)
def test_a_literal_quote_inside_double_quotes_is_not_stripped(
    rig: SimpleNamespace, template: str
) -> None:
    """The shell keeps the inner `'..'` as text; stripping it as a quote allowed what main denied."""
    _quoted_dotdot_dir(rig)
    assert_denied(run_gate(shell(template, rig.primary), rig.repos))


def test_a_spacey_quoted_chdir_is_not_guessed_as_the_cwd(rig: SimpleNamespace) -> None:
    """A blanked chdir target is unknown, so the added reading answers nothing rather than the cwd."""
    spacey = rig.tmp / "a b"
    subprocess.run(
        ["git", "init", "-q", "-b", "main", str(spacey)], check=True, capture_output=True
    )
    assert _allowed(rig, f'cd "{spacey.as_posix()}" && git reset --hard', rig.primary)
    assert _allowed(rig, f'cd "{spacey.as_posix()}" && git worktree remove Primary-wt2', rig.tmp)


def test_a_cd_after_an_inferred_invocation_does_not_refuse_it(rig: SimpleNamespace) -> None:
    cmd = f"git stash && cd {rig.primary.as_posix()} && git -C {rig.outside.as_posix()} rebase main"
    assert _allowed(rig, cmd, rig.outside)


# ------------------------------------------------------------------ Manager repair round, same rows


def test_an_absolute_own_dash_C_is_read_after_an_unfollowable_chdir(rig: SimpleNamespace) -> None:
    o, o2, p = rig.outside.as_posix(), rig.outside2.as_posix(), rig.primary.as_posix()
    cmd = f"cd {o} && git -C {o2} fetch && cd {o2} && git -C {p} reset --hard"
    assert "SHARED PRIMARY" in _reason(rig, cmd, rig.outside)


def test_an_absolute_own_dash_C_into_a_linked_worktree_after_pushd_popd(
    rig: SimpleNamespace,
) -> None:
    o, o2, w = rig.outside.as_posix(), rig.outside2.as_posix(), rig.wt.as_posix()
    cmd = f"pushd {o} ; popd ; git -C {o2} status ; git -C {w} checkout {rig.other}"
    assert "LINKED WORKTREE" in _reason(rig, cmd, rig.outside)


@pytest.mark.parametrize(
    ("template", "where", "text"),
    [
        ("git -C {o} status ; echo cd ; git reset --hard", "primary", "SHARED PRIMARY"),
        (
            "git -C {o2} status ; echo cd ; git worktree remove Primary-wt2",
            "tmp",
            "worktree remove",
        ),
        ("git -C {o} clean -fd ; echo cd ; git switch {b}", "wt", "LINKED WORKTREE"),
    ],
)
def test_a_chdir_word_that_is_only_an_argument_does_not_switch_the_reading_off(
    rig: SimpleNamespace, template: str, where: str, text: str
) -> None:
    cmd = template.format(o=rig.outside.as_posix(), o2=rig.outside2.as_posix(), b=rig.other)
    cwd = {"primary": rig.primary, "tmp": rig.tmp, "wt": rig.wt}[where]
    assert text in _reason(rig, cmd, cwd)


@pytest.mark.parametrize(
    "template",
    [
        "git stash push -m \"try -C '{p}' later\"",
        "git stash push -m \"see --work-tree='{p}' bug\"",
    ],
)
def test_a_single_quoted_path_inside_a_double_quoted_message_is_not_a_token(
    rig: SimpleNamespace, template: str
) -> None:
    """Allowed on origin/main; round one's strip made the mention a live path and refused it."""
    assert _allowed(rig, template.format(p=rig.primary.as_posix()), rig.outside)


def test_a_single_quoted_spacey_chdir_is_not_guessed_as_the_cwd(rig: SimpleNamespace) -> None:
    spacey = rig.tmp / "a b"
    subprocess.run(
        ["git", "init", "-q", "-b", "main", str(spacey)], check=True, capture_output=True
    )
    assert _allowed(rig, f"cd '{spacey.as_posix()}' && git reset --hard", rig.primary)
