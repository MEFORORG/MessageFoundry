# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The worktree gate reads each git invocation's OWN tokens, however they are quoted.

Three rows, one shape: a token that decides which tree or repository a git command acts on was read
from the wrong place, so the gate judged a different path from the one the shell hands git.

* BACKLOG #5642 -- the shared ``cd``, ``-C``, ``--work-tree``, ``--git-dir`` and ``GIT_DIR`` readers
  stripped DOUBLE quotes only, so a SINGLE-quoted path to the governed checkout resolved to a
  quote-tainted path that names nothing, and rules 3, 3b, 3c and 3d allowed it.

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
    assert _allowed(rig, double, rig.primary) == _allowed(rig, single, rig.primary)
