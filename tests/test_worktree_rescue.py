# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""``scripts/worktree/rescue.ps1``: no prompt without ``-Name``, and its own stash entry only.

The stash half is BACKLOG #5957 and is described above its tests, further down.

Vault BACKLOG #3627. With ``-Name`` Mandatory, a call that left it out made PowerShell prompt on
stdin, and a caller with stdin open and silent hung; ``tests/_no_prompt.py`` says why the launch
must keep both of those conditions.

The script anchors on ``$PSScriptRoot``, so it runs from a copy inside a throwaway repository. The
real checkout is never in reach: a guard that failed open here would stash the repository it names.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest

from tests._no_prompt import run_holding_stdin_open
from tests._spawn_lock import single_spawn

_RESCUE = Path(__file__).resolve().parents[1] / "scripts" / "worktree" / "rescue.ps1"
_GATES = _RESCUE.with_name("worktree-gates.ps1")

pytestmark = pytest.mark.skipif(
    shutil.which("pwsh") is None or os.name != "nt",
    reason="rescue.ps1 is a PowerShell script driven through pwsh on Windows",
)


# An inherited GIT_DIR or GIT_WORK_TREE would point every git call here, and the copied script's, at the
# repository it names instead of the throwaway one, and rescue.ps1 refuses any GIT_CONFIG carrier; strip
# every GIT_* so the real checkout stays out of reach and the script runs.
_ENV = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(repo), *args], check=True, capture_output=True, text=True, env=_ENV
    ).stdout


def test_a_call_without_name_refuses_instead_of_prompting(tmp_path: Path) -> None:
    """``-NoInstall`` alone leaves ``-Name`` unbound. Verified red (a 45s hang) pre-fix."""
    repo = tmp_path / "repo"
    _seed(repo)
    _commit_all(repo)
    # Dirty, so a guard that failed open would reach the stash rather than the nothing-to-do exit.
    (repo / "work.txt").write_text("uncommitted\n", encoding="utf-8")

    rc, err = run_holding_stdin_open(
        [
            "pwsh",
            "-NoProfile",
            "-File",
            str(repo / "scripts" / "worktree" / "rescue.ps1"),
            "-NoInstall",
        ],
        cwd=repo,
        env=_ENV,
    )
    assert rc != 0, "a rescue naming no worktree must be refused"
    assert "-Name" in err, err
    # Refused means NOTHING moved: the work is still here and nothing was stashed.
    assert (repo / "work.txt").is_file()
    assert _git(repo, "stash", "list") == ""


# --- BACKLOG #5957: the clone-wide stash stack ------------------------------------------------------
#
# The stash stack is shared by every worktree and session on a clone, so the rescue must apply ITS OWN
# entry, by id, and must refuse when its push created none. A stand-in ``new.ps1`` keeps these tests off
# the network and the venv build; it creates the worktree exactly where rescue.ps1 expects it and, when
# asked, pushes a second session's entry inside the window between rescue's push and its apply.

_FAKE_NEW = r"""
param([string]$Name, [string]$Base, [switch]$NoInstall, [switch]$Sqlserver)
$ErrorActionPreference = 'Stop'
$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$Target = Join-Path (Split-Path $RepoRoot -Parent) ('{0}-{1}' -f (Split-Path $RepoRoot -Leaf), $Name)
if ($env:RESCUE_TEST_CONCURRENT_PUSH) {
    Set-Content -LiteralPath (Join-Path $RepoRoot 'foreign.txt') -Value 'another session'
    & git -C $RepoRoot stash push --include-untracked -m 'foreign concurrent'
    if ($LASTEXITCODE -ne 0) { exit 3 }
}
& git -C $RepoRoot worktree add --no-track $Target -b $Name $Base
exit $LASTEXITCODE
"""


def _seed(repo: Path) -> None:
    """A primary checkout holding rescue.ps1 and the stand-in new.ps1, not yet committed."""
    (repo / "scripts" / "worktree").mkdir(parents=True)
    shutil.copy2(_RESCUE, repo / "scripts" / "worktree" / "rescue.ps1")
    shutil.copy2(_GATES, repo / "scripts" / "worktree" / "worktree-gates.ps1")
    (repo / "scripts" / "worktree" / "new.ps1").write_text(_FAKE_NEW, encoding="utf-8")
    (repo / "base.txt").write_text("base\n", encoding="utf-8")
    _git(repo, "init", "-q", "-b", "main")
    _git(repo, "config", "user.email", "t@example.invalid")
    _git(repo, "config", "user.name", "t")
    # Keep any user-scope hook directory away from this throwaway repository.
    _git(repo, "config", "core.hooksPath", ".git/no-hooks")


def _commit_all(repo: Path) -> None:
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "seed", "--no-verify")


def _stash_entries(repo: Path) -> list[tuple[str, str]]:
    out = _git(repo, "stash", "list", "--format=%H%x09%gs")
    entries: list[tuple[str, str]] = []
    for line in out.splitlines():
        sha, _, subject = line.partition("\t")
        entries.append((sha, subject))
    return entries


def _push_foreign(repo: Path) -> str:
    """Another session's entry, already on the stack before the rescue starts."""
    (repo / "base.txt").write_text("foreign edit\n", encoding="utf-8")
    _git(repo, "stash", "push", "-m", "foreign earlier")
    return _stash_entries(repo)[0][0]


def _rescue(
    repo: Path, name: str, *, concurrent: bool = False, extra_env: dict[str, str] | None = None
) -> subprocess.CompletedProcess[str]:
    env = dict(_ENV)
    env.pop("RESCUE_TEST_CONCURRENT_PUSH", None)
    if concurrent:
        env["RESCUE_TEST_CONCURRENT_PUSH"] = "1"
    env.update(extra_env or {})
    with single_spawn():
        return subprocess.run(
            [
                "pwsh",
                "-NoProfile",
                "-File",
                str(repo / "scripts" / "worktree" / "rescue.ps1"),
                "-Name",
                name,
                "-NoInstall",
            ],
            cwd=repo,
            env=env,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=50,
            check=False,
        )


def _make_work(repo: Path) -> None:
    (repo / "work.txt").write_text("rescued work\n", encoding="utf-8")  # untracked
    (repo / "base.txt").write_text("rescued edit\n", encoding="utf-8")  # tracked


def test_a_foreign_entry_already_on_the_stack_is_left_alone(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    _seed(repo)
    _commit_all(repo)
    foreign = _push_foreign(repo)
    _make_work(repo)

    proc = _rescue(repo, "pre")
    assert proc.returncode == 0, proc.stdout + proc.stderr

    target = tmp_path / "repo-pre"
    assert (target / "work.txt").read_text(encoding="utf-8") == "rescued work\n"
    assert (target / "base.txt").read_text(encoding="utf-8") == "rescued edit\n"
    assert _git(repo, "status", "--porcelain") == ""
    assert _stash_entries(repo) == [(foreign, "On main: foreign earlier")]
    assert _git(repo, "for-each-ref", "refs/worktree-rescue") == "", (
        "the anchor ref was left behind"
    )


def test_an_entry_pushed_during_the_window_is_not_popped_into_the_worktree(tmp_path: Path) -> None:
    """Verified red pre-fix: the bare pop took the concurrent entry and stranded the rescued one."""
    repo = tmp_path / "repo"
    _seed(repo)
    _commit_all(repo)
    _make_work(repo)

    proc = _rescue(repo, "race", concurrent=True)
    assert proc.returncode == 0, proc.stdout + proc.stderr

    target = tmp_path / "repo-race"
    assert (target / "work.txt").read_text(encoding="utf-8") == "rescued work\n"
    assert (target / "base.txt").read_text(encoding="utf-8") == "rescued edit\n"
    assert not (target / "foreign.txt").exists(), (
        "another session's stash landed in the new worktree"
    )
    entries = _stash_entries(repo)
    # The concurrent entry is still on the stack and the rescue's own entry was dropped.
    assert [subject for _, subject in entries] == ["On main: foreign concurrent"], entries
    assert "foreign.txt" in _git(repo, "show", "--name-only", "--format=", f"{entries[0][0]}^3")


def test_a_push_that_creates_no_entry_is_refused_and_touches_nothing(tmp_path: Path) -> None:
    """Edited content inside a nested repository: status reports it, git stash cannot carry it.

    Verified red pre-fix: the push printed "No local changes to save" and exited 0, and the bare pop
    then moved the foreign entry into the new worktree.
    """
    repo = tmp_path / "repo"
    _seed(repo)
    nested = repo / "nested"
    nested.mkdir()
    _git(nested, "init", "-q", "-b", "main")
    _git(nested, "config", "user.email", "t@example.invalid")
    _git(nested, "config", "user.name", "t")
    _git(nested, "config", "core.hooksPath", ".git/no-hooks")
    (nested / "x.txt").write_text("x\n", encoding="utf-8")
    _git(nested, "add", "x.txt")
    _git(nested, "commit", "-qm", "n", "--no-verify")
    _commit_all(repo)  # records nested/ as a gitlink
    foreign = _push_foreign(repo)
    (nested / "x.txt").write_text("edited inside the nested repository\n", encoding="utf-8")
    assert _git(repo, "status", "--porcelain").strip(), "the fixture must look dirty to status"

    proc = _rescue(repo, "empty")
    assert proc.returncode != 0, proc.stdout + proc.stderr
    out = _flat(proc.stderr + proc.stdout)
    assert "git stash push created no entry although status reported" in out
    # Positive control for the popped-entry test below: git saved nothing, so the stack is untouched.
    assert "The stash stack was not touched" in out
    assert not (tmp_path / "repo-empty").exists()
    assert _stash_entries(repo) == [(foreign, "On main: foreign earlier")]
    assert (nested / "x.txt").read_text(encoding="utf-8") == "edited inside the nested repository\n"


def test_a_linked_worktrees_copy_refuses_and_moves_nothing(tmp_path: Path) -> None:
    """BACKLOG #5957 item 1 (S34-32): the script anchors on its own path, so a linked copy must refuse."""
    repo = tmp_path / "repo"
    _seed(repo)
    _commit_all(repo)
    linked = tmp_path / "linked"
    _git(repo, "worktree", "add", "-q", "--no-track", str(linked), "-b", "linked")
    (linked / "work.txt").write_text("a linked worktree's own work\n", encoding="utf-8")

    proc = _rescue(linked, "fromlinked")
    assert proc.returncode != 0, proc.stdout + proc.stderr
    assert "LINKED worktree" in proc.stderr + proc.stdout
    assert (linked / "work.txt").read_text(encoding="utf-8") == "a linked worktree's own work\n"
    assert _stash_entries(repo) == []
    assert not (tmp_path / "linked-fromlinked").exists()


def test_an_existing_branch_of_that_name_is_refused_before_the_stash(tmp_path: Path) -> None:
    """new.ps1 reuses an existing branch and ignores -Base, so the work would land on another commit."""
    repo = tmp_path / "repo"
    _seed(repo)
    _commit_all(repo)
    _git(repo, "branch", "taken")
    _make_work(repo)

    proc = _rescue(repo, "taken")
    assert proc.returncode != 0, proc.stdout + proc.stderr
    assert "already exists" in proc.stderr + proc.stdout
    assert _stash_entries(repo) == []
    assert (repo / "work.txt").is_file()


def test_an_inherited_git_redirect_is_refused(tmp_path: Path) -> None:
    """GIT_DIR naming the primary's .git would also pass a linked copy off as the primary."""
    repo = tmp_path / "repo"
    _seed(repo)
    _commit_all(repo)
    _make_work(repo)

    proc = _rescue(repo, "redir", extra_env={"GIT_DIR": str(repo / ".git")})
    assert proc.returncode != 0, proc.stdout + proc.stderr
    assert "GIT_DIR" in proc.stderr + proc.stdout
    assert _stash_entries(repo) == []
    assert (repo / "work.txt").is_file()


def test_changes_stash_cannot_carry_are_reported_as_left_behind(tmp_path: Path) -> None:
    """A tracked edit moves; an edit inside a nested repository cannot, and the script must say so."""
    repo = tmp_path / "repo"
    _seed(repo)
    nested = repo / "nested"
    nested.mkdir()
    _git(nested, "init", "-q", "-b", "main")
    _git(nested, "config", "user.email", "t@example.invalid")
    _git(nested, "config", "user.name", "t")
    _git(nested, "config", "core.hooksPath", ".git/no-hooks")
    (nested / "x.txt").write_text("x\n", encoding="utf-8")
    _git(nested, "add", "x.txt")
    _git(nested, "commit", "-qm", "n", "--no-verify")
    _commit_all(repo)
    _make_work(repo)
    (nested / "x.txt").write_text("edited inside the nested repository\n", encoding="utf-8")

    proc = _rescue(repo, "partial")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    out = proc.stdout + proc.stderr
    assert "STILL in the primary" in out
    assert "nested" in out
    assert "The primary checkout is clean again" not in out
    assert (tmp_path / "repo-partial" / "work.txt").read_text(encoding="utf-8") == "rescued work\n"
    assert _stash_entries(repo) == []


# --- Messages that must stay true when another session moves the stack --------------------------------
#
# A ``git.cmd`` placed first on the script's PATH stands in for another session: it forwards every call to
# the real git and, when asked, refuses the rescue's ``stash drop`` or pops the rescue's entry straight
# after its push. Only the pwsh child sees it; ``_git`` above still runs the real git.

_GIT_WRAPPER = r"""@echo off
setlocal
if /I "%~3 %~4"=="stash drop" if defined RESCUE_TEST_FAIL_DROP exit /b 1
"{git}" %*
set rc=%ERRORLEVEL%
if /I "%~3 %~4"=="stash push" if defined RESCUE_TEST_POP_AFTER_PUSH "{git}" -C %2 stash pop -q >nul 2>&1
exit /b %rc%
"""


def _flat(text: str) -> str:
    """Console output without pwsh's colour codes or its wrapped-error gutter, one space per run."""
    text = re.sub(r"\x1b\[[0-9;]*m", "", text)
    text = re.sub(r"\n\s*\|", " ", text)
    return " ".join(text.split())


def _wrapped_env(tmp_path: Path, **flags: str) -> dict[str, str]:
    real = shutil.which("git")
    assert real, "git must be on PATH"
    shim = tmp_path / "shim"
    shim.mkdir()
    (shim / "git.cmd").write_text(_GIT_WRAPPER.replace("{git}", real), encoding="ascii")
    env = {"PATH": f"{shim}{os.pathsep}{_ENV.get('PATH', '')}"}
    env.update(flags)
    return env


def test_a_failed_own_drop_is_reported_with_a_drop_command_that_works(tmp_path: Path) -> None:
    """The success output must not leave the rescue's entry on the shared stack unmentioned."""
    repo = tmp_path / "repo"
    _seed(repo)
    _commit_all(repo)
    foreign = _push_foreign(repo)
    _make_work(repo)

    proc = _rescue(repo, "nodrop", extra_env=_wrapped_env(tmp_path, RESCUE_TEST_FAIL_DROP="1"))
    out = _flat(proc.stdout + proc.stderr)
    assert proc.returncode == 0, out
    assert (tmp_path / "repo-nodrop" / "work.txt").read_text(encoding="utf-8") == "rescued work\n"
    entries = _stash_entries(repo)
    assert len(entries) == 2 and entries[1][0] == foreign, entries
    own = entries[0][0]
    assert f"Stash commit {own} is still on the shared stash list" in out, out
    assert "stays on the stash list as a spare copy" in out, out
    # The printed command re-finds the position by SHA and drops only that entry.
    found = re.search(r"\$n = @\(git .*?run this command again\.' \}", out)
    assert found, out
    command = found.group(0)
    assert own in command, command
    with single_spawn():
        ran = subprocess.run(
            ["pwsh", "-NoProfile", "-Command", command],
            cwd=repo,
            env=_ENV,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=50,
            check=False,
        )
    assert ran.returncode == 0, ran.stdout + ran.stderr
    assert _stash_entries(repo) == [(foreign, "On main: foreign earlier")]


def test_an_entry_popped_before_the_read_back_is_not_called_untouched(tmp_path: Path) -> None:
    """The push made an entry and a peer popped it: the stack WAS touched, and the message must say so."""
    repo = tmp_path / "repo"
    _seed(repo)
    _commit_all(repo)
    _make_work(repo)

    proc = _rescue(repo, "popped", extra_env=_wrapped_env(tmp_path, RESCUE_TEST_POP_AFTER_PUSH="1"))
    out = _flat(proc.stdout + proc.stderr)
    assert proc.returncode != 0, out
    assert "The stash stack was not touched" not in out, out
    assert "did not report 'No local changes to save'" in out, out
    assert "refs/worktree-rescue/" in out, out
    assert not (tmp_path / "repo-popped").exists()
    # The stand-in peer popped into the primary itself, so the work is back where it started.
    assert (repo / "work.txt").read_text(encoding="utf-8") == "rescued work\n"
    assert _stash_entries(repo) == []
