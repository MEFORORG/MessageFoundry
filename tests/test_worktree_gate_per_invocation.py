# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Rule 3d of the worktree gate judges more of the ``git worktree remove`` and ``move`` invocations on a line.

BACKLOG #5643: rule 3d sliced the raw line at its FIRST ``worktree remove|move`` and judged one
invocation, resolving a relative victim from the line's first ``-C``, so a quoted mention, a second
invocation or another command's ``-C`` let a governed linked worktree be removed or moved.

Each deny row was measured ALLOW on the gate before its fix, and each has an ALLOW control beside it
so a gate that denied everything could not pass.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
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


def test_a_spacey_quoted_chdir_is_not_guessed_as_the_cwd(rig: SimpleNamespace) -> None:
    """A blanked chdir target is unknown, so the added reading answers nothing rather than the cwd."""
    spacey = rig.tmp / "a b"
    subprocess.run(
        ["git", "init", "-q", "-b", "main", str(spacey)], check=True, capture_output=True
    )
    assert _allowed(rig, f'cd "{spacey.as_posix()}" && git worktree remove Primary-wt2', rig.tmp)


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


def test_an_echoed_cd_does_not_move_rule_3ds_own_base(rig: SimpleNamespace) -> None:
    """The real victim is the governed `<tmp>/Primary-wt2`; `echo cd` moves no shell."""
    cmd = f"echo cd {rig.outside2.as_posix()} && git worktree remove ../Primary-wt2"
    assert "worktree remove" in _reason(rig, cmd, rig.outside)


@pytest.mark.parametrize("between", ["-C ${HOME}", "-C $(pwd)", "2>&1"])
def test_a_remove_with_a_separator_class_character_before_it_is_judged(
    rig: SimpleNamespace, between: str
) -> None:
    """Measured ALLOW before: the added reading skipped any `[;&|(){}]` between git and `worktree`."""
    cmd = f"echo 'git worktree remove x' ; git {between} worktree remove {rig.wt2.as_posix()}"
    assert "worktree remove" in _reason(rig, cmd, rig.outside)


# ------------------------------------------------------------------ review round 8d822d77


def _rel(rig: SimpleNamespace) -> dict[str, str]:
    return {"o2": rig.outside2.as_posix(), "tmp": rig.tmp.as_posix()}


@pytest.mark.parametrize(
    "template",
    [
        "echo 'git -C {o2} worktree remove x' ; git 2>&1 worktree remove ../Primary-wt2",
        "git -C {o2} status ; git -C {tmp} 2>&1 worktree remove Primary-wt2",
        "git -C {o2} status ; git 2>&1 worktree remove ../Primary-wt2",
        "git -C {o2} status ; git -c x.y=$(echo z) worktree remove ../Primary-wt2",
        "git -C {o2} status ; git 2>&1 worktree move ../Primary-wt2 ../moved",
    ],
)
def test_a_relative_victim_behind_an_in_invocation_character_is_judged(
    rig: SimpleNamespace, template: str
) -> None:
    """Measured ALLOW before: the own base was dropped, and the first base was another command's."""
    reason = _reason(rig, template.format(**_rel(rig)), rig.outside)
    assert "worktree" in reason, reason


@pytest.mark.parametrize(
    "template",
    [
        "git -C {o2} status ; git 2>&1 worktree remove ../nope",
        "git -C {o2} status ; git 2>&1 worktree move ../nope ../moved",
    ],
)
def test_a_relative_ungoverned_victim_behind_one_is_still_allowed(
    rig: SimpleNamespace, template: str
) -> None:
    assert _allowed(rig, template.format(**_rel(rig)), rig.outside)


def test_an_echoed_worktree_remove_after_a_git_command_is_not_judged(rig: SimpleNamespace) -> None:
    """ALLOW on c4d0d4d06f, a false DENY on 3c60a7985a: `echo` removes nothing."""
    cmd = (
        f"git worktree remove {rig.outside.as_posix()}/nope ; "
        f"echo worktree remove {rig.wt2.as_posix()}"
    )
    assert _allowed(rig, cmd, rig.tmp)


def test_a_powershell_script_block_opening_on_git_is_judged(rig: SimpleNamespace) -> None:
    """`{` was not in the git-token prefix class, so no rule saw the removal. The space before the
    closing brace is load-bearing: a `}` touching the victim is still read as part of it (a stated
    residual, like `$(...)`)."""
    reason = _reason_tool(rig, f"& {{git worktree remove {rig.wt2.as_posix()} }}", rig.tmp)
    assert "worktree remove" in reason, reason


@pytest.mark.skipif(sys.platform != "win32", reason="git.exe answers to `Git` on Windows only")
def test_an_upper_case_git_is_judged_on_windows(rig: SimpleNamespace) -> None:
    reason = _reason(rig, f"Git worktree remove {rig.wt2.as_posix()}", rig.tmp)
    assert "worktree remove" in reason, reason


def _reason_tool(rig: SimpleNamespace, command: str, cwd: Path) -> str:
    return assert_denied(run_gate(shell(command, cwd, tool="PowerShell"), rig.repos))
