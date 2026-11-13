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
* A line holding more git invocations than the gate can judge inside its hook timeout is refused,
  because a killed hook lets the command through (review of BACKLOG #5643).

(BACKLOG #5655, per-invocation rules 3 and 3b, was taken back out of this branch and goes to a
 later Builder as one design; its tests went with it.)

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


# ------------------------------------------------------------------ Manager repair round, same rows


@pytest.mark.parametrize(
    ("template", "where", "text"),
    [
        (
            "git -C {o2} status ; echo cd ; git worktree remove Primary-wt2",
            "tmp",
            "worktree remove",
        ),
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


# ------------------------------------------------------------------ Manager convergence round


_DISARM = "core." + "hooksPath /nope"


@pytest.mark.parametrize(
    "template",
    [
        "echo '\"' ; git -C '{p}' config {k}",
        "echo '\"' ; git --git-dir='{p}/.git' config {k}",
        "echo '\"' ; GIT_DIR='{p}/.git' git config {k}",
    ],
)
def test_an_earlier_quote_character_does_not_switch_the_strip_off(
    rig: SimpleNamespace, template: str
) -> None:
    """The quote count read `'"'` as opening a double-quoted span; the scanner does not."""
    reason = _reason(rig, template.format(p=rig.primary.as_posix(), k=_DISARM), rig.outside)
    assert "SHARED git configur" in reason, reason


def test_an_earlier_quote_character_does_not_switch_the_strip_off_for_work_tree(
    rig: SimpleNamespace,
) -> None:
    cmd = f"echo '\"' ; git --work-tree='{rig.primary.as_posix()}' reset --hard"
    assert "SHARED PRIMARY" in _reason(rig, cmd, rig.outside)


def test_an_earlier_quote_character_does_not_make_a_message_live(rig: SimpleNamespace) -> None:
    """The other direction: the mention stays inside its message, as on origin/main."""
    cmd = f"echo '\"' ; git stash push -m \"try -C '{rig.primary.as_posix()}' later\""
    assert _allowed(rig, cmd, rig.outside)


# ------------------------------------------------------------------ rule 3e: the time budget
#
# A hook killed by its 15 s timeout lets the command through, so each shape below must come back
# DENIED, by any rule, well inside that timeout. The bound includes pwsh start-up, which the gate's own
# clock cannot see. Each was measured past 15 s before the budget, with the trailing reset unjudged.

_HOOK_BOUND_S = 13


def _denied_in_time(rig: SimpleNamespace, cmd: str, cwd: Path) -> str:
    import time

    started = time.monotonic()
    reason = _reason(rig, cmd, cwd)
    elapsed = time.monotonic() - started
    assert elapsed < _HOOK_BOUND_S, f"the verdict took {elapsed:.1f}s; the install timeout is 15s"
    return reason


def test_a_line_of_150_worktree_removes_is_refused_in_time(rig: SimpleNamespace) -> None:
    """Measured 24.3 s before."""
    removes = " ; ".join(f"git worktree remove {rig.tmp.as_posix()}/nope{i}" for i in range(150))
    _denied_in_time(rig, f"{removes} ; git reset --hard", rig.primary)


def test_one_git_token_with_200_worktree_remove_words_is_refused_in_time(
    rig: SimpleNamespace,
) -> None:
    """Measured 18.7 s before: a count of git tokens saw two."""
    words = " ".join(f"worktree remove {rig.tmp.as_posix()}/n{i}" for i in range(200))
    _denied_in_time(rig, f"git {words} ; git reset --hard", rig.primary)


def test_twenty_removes_behind_a_97_kb_prefix_are_refused_in_time(rig: SimpleNamespace) -> None:
    """Measured 25.7 s before: every invocation rescanned its own long prefix."""
    filler = " ".join(f"'w{i:05d}'" for i in range(97 * 1024 // 9))
    removes = " && ".join(f"git worktree remove ../n{i}" for i in range(19))
    cmd = (
        f"cd '{rig.outside.as_posix()}' && echo {filler} && {removes} && "
        f"git -C {rig.primary.as_posix()} reset --hard"
    )
    _denied_in_time(rig, cmd, rig.outside)


def test_200_identical_remove_lines_are_refused_in_time(rig: SimpleNamespace) -> None:
    """Measured 24.0 s before: a count over distinct lines saw one."""
    lines = "\n".join([f"git worktree remove {rig.tmp.as_posix()}/nope"] * 200)
    _denied_in_time(rig, f"{lines}\ngit reset --hard", rig.primary)


def test_commits_with_two_line_messages_are_not_double_counted(rig: SimpleNamespace) -> None:
    """The count read the physical and the logical view of each commit, refusing 11 commits."""
    cmd = "\n".join(f'git commit --allow-empty -q -m "a{i}\nb{i}"' for i in range(11))
    assert _allowed(rig, cmd, rig.outside)


def test_a_quote_pair_joined_to_a_further_piece_is_not_stripped(rig: SimpleNamespace) -> None:
    """git receives `<tmp>/Outside/../Primary`, the primary. DENY on origin/main; stripping the pair
    alone read the ungoverned `<tmp>/Outside` and allowed it."""
    cmd = f"git -C '{rig.outside.as_posix()}'\"/../Primary\" reset --hard"
    assert_denied(run_gate(shell(cmd, rig.primary), rig.repos))


def test_a_quoted_cd_mention_in_a_message_is_not_a_chdir(rig: SimpleNamespace) -> None:
    """Allowed on origin/main. The prefix cut inside the message left an unclosed quote, which the
    blanked-span test read as outside every span, so the mention became a live chdir."""
    p = rig.primary.as_posix()
    cmd = f"echo \"then cd '{p}' && git log\" ; git config {_DISARM}"
    assert _allowed(rig, cmd, rig.outside)


def test_an_echoed_cd_does_not_move_rule_3ds_own_base(rig: SimpleNamespace) -> None:
    """The real victim is the governed `<tmp>/Primary-wt2`; `echo cd` moves no shell."""
    cmd = f"echo cd {rig.outside2.as_posix()} && git worktree remove ../Primary-wt2"
    assert "worktree remove" in _reason(rig, cmd, rig.outside)
