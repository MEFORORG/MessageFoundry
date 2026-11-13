# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Rule 3d of the worktree gate judges every ``git worktree remove`` or ``move`` on a line.

BACKLOG #5643: rule 3d sliced the raw line at its FIRST ``worktree remove|move`` and judged one
invocation, resolving a relative victim from the line's first ``-C``, so a quoted mention, a second
invocation or another command's ``-C`` let a governed linked worktree be removed or moved.

Each deny row was measured ALLOW on the gate before its fix, and each has an ALLOW control beside it
so a gate that denied everything could not pass.
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from tests.test_worktree_gate import assert_denied, run_gate
from tests.test_worktree_gate_hijack import _make_repo, shell


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
