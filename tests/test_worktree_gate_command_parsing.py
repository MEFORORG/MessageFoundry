# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""How rule 3 reads a shell command: which tree it decides the command acts on, and where a verb may
come from.

Two defect families live here, and they pull in opposite directions, which is why they are fixed and
tested together.

BYPASSES (the gate said ALLOW to a real tree swap). Rule 3 resolved its target from `-C` or cwd only,
while rule 3b resolved `cd`/`pushd` as well -- so a relatively-spelled `cd <primary> && git reset --hard`
fell between them: rule 3 saw the session's own worktree and handed off to 3b, which saw the primary and
returned "Rule 3 owns it". Rule 3 had already declined. Separately, rule 3 parsed `-C` case-INsensitively,
so git's lowercase `-c name=value` config override was captured as if it were a path.

FALSE POSITIVES (the gate said DENY to something that ran no git at all). The verb scan read the raw
command string, so a second line of prose, an echoed command, or a commit message could supply the verb.
Those matter more than nuisance value: rule 3's deny text is the only control on the shell-write path, so
every spurious deny erodes compliance with the one guard that has nothing behind it.

Each case below was measured against the shipped hook before the fix.
"""

from __future__ import annotations

import shutil
from pathlib import Path
from typing import Any

import pytest

from tests.test_worktree_gate import assert_denied, run_gate  # reuse the subprocess harness

pytestmark = pytest.mark.skipif(
    shutil.which("pwsh") is None, reason="pwsh (PowerShell 7) not on PATH"
)


def shell(command: str, cwd: Path | str, tool: str = "Bash") -> dict[str, Any]:
    return {
        "session_id": "s-1",
        "cwd": str(cwd),
        "hook_event_name": "PreToolUse",
        "tool_name": tool,
        "tool_input": {"command": command},
    }


@pytest.fixture
def primary(tmp_path: Path) -> Path:
    return tmp_path / "Repo"


@pytest.fixture
def nested(primary: Path) -> Path:
    """A first-party worktree, where `../../..` IS the primary -- the natural relative spelling."""
    return primary / ".claude" / "worktrees" / "wt-1"


@pytest.fixture
def repos_file(tmp_path: Path, primary: Path) -> Path:
    f = tmp_path / "repos.txt"
    f.write_text(f"{primary}\n", encoding="utf-8")
    return f


# ------------------------------------------------------------------ bypasses that must now be denied


def test_a_lowercase_config_override_does_not_shadow_the_real_dash_C(
    nested: Path, repos_file: Path
) -> None:
    """`-match` is case-insensitive in PowerShell, so the `-C <path>` parser captured git's lowercase
    `-c name=value` config override instead -- and because it takes the FIRST match, a real `-C` later in
    the same command was never seen at all. Here `-C ../../..` IS the primary, so reading `-c` as the path
    resolves the target to a bogus directory inside the worktree, which is ungoverned, and the tree swap
    is allowed.

    This shape, not the simpler `git -c x=y checkout main` at cwd=primary, is the one that discriminates.
    That simpler case now denies EITHER WAY: since target paths resolve relative to the session cwd, the
    bogus `core.pager=cat` lands inside the primary and is governed by accident. A test written on it
    passes against the bug -- verified by mutation -- and would have shipped as a green blind spot."""
    reason = assert_denied(
        run_gate(shell("git -c core.pager=cat -C ../../.. checkout main", cwd=nested), repos_file)
    )
    assert "SHARED PRIMARY" in reason


def test_a_config_override_whose_value_looks_like_an_outside_path_still_denies(
    primary: Path, repos_file: Path
) -> None:
    """The second discriminator: a config value that resolves OUTSIDE the primary. Read as a path it makes
    the command look ungoverned; read correctly, the target falls back to the cwd, which is the primary."""
    assert_denied(
        run_gate(
            shell("git -c include.path=C:/Windows/Temp/x checkout main", cwd=primary), repos_file
        )
    )


# Not a bypass fix -- a regression guard. This case denied before the change too, and it is here so a
# future edit to the config-override parsing cannot break the ordinary path while fixing the exotic one.
def test_a_config_override_does_not_break_an_ordinary_deny(primary: Path, repos_file: Path) -> None:
    assert_denied(
        run_gate(shell("git -c advice.detachedHead=false switch main", cwd=primary), repos_file)
    )


@pytest.mark.parametrize(
    "command",
    [
        "cd ../../.. && git checkout main",
        "cd ../../.. && git reset --hard origin/main",
        "cd ../../.. ; git clean -xfd",
        "cd ../../.. ; git stash",
        "cd ../../.. && git rebase origin/main",
        "pushd ../../.. ; git restore .",
        "cd ../../.. && git switch main",
    ],
)
def test_a_relative_cd_to_the_primary_is_denied(
    nested: Path, repos_file: Path, command: str
) -> None:
    """The whole point of the fix. `../../..` from a nested worktree IS the primary, but the in-text
    fallback only ever matched the primary's LITERAL spelling, so none of these named it. The seven cases
    span seven verbs, and rule 3b handles only checkout/switch -- so for five of them there was never even
    a hand-off to bow out of; they were plain misses."""
    reason = assert_denied(run_gate(shell(command, cwd=nested), repos_file))
    assert "SHARED PRIMARY" in reason


def test_a_relative_work_tree_flag_pointing_at_the_primary_is_denied(
    nested: Path, repos_file: Path
) -> None:
    """`--work-tree` is resolved structurally. Spelled relatively it never appears in the in-text scan, so
    only the resolver can catch it."""
    assert_denied(run_gate(shell("git --work-tree=../../.. checkout main", cwd=nested), repos_file))


def test_a_relative_cd_that_leaves_the_primary_is_allowed(primary: Path, repos_file: Path) -> None:
    """The resolver must cut both ways: resolving `cd` means a session in the primary that cds OUT of it
    is no longer denied on the strength of its cwd alone. This is a false positive the fix removes."""
    assert run_gate(shell("cd ../Elsewhere && git checkout main", cwd=primary), repos_file) is None


# ------------------------------------------------------- false positives that must now be allowed


def test_a_verb_on_a_later_line_of_prose_is_not_a_git_verb(primary: Path, repos_file: Path) -> None:
    """The scan class excludes `|;&` but not newline, so a `merge` five words into a second line of
    narration was read as the subcommand of the `git` on line one. Denied a command that ran `git status`."""
    assert run_gate(shell("git status\necho about to merge stuff", cwd=primary), repos_file) is None


def test_an_echoed_command_is_not_a_command(primary: Path, repos_file: Path) -> None:
    """The git-detection class includes the quote characters, so quoting a command for display made it
    look like an invocation. This denied a read-only diagnostic during the audit that produced this fix."""
    assert run_gate(shell('echo "git checkout main"', cwd=primary), repos_file) is None


@pytest.mark.parametrize(
    "message",
    [
        "chore: clean up dead code",
        "fix: I am about to merge the release branch",
        "refactor: reset the counters on restart",
        "docs: restore the missing section",
    ],
)
def test_a_commit_message_cannot_supply_the_verb(
    primary: Path, repos_file: Path, message: str
) -> None:
    """`git commit` is not a gated verb, but the message that follows it was scanned as if it were
    arguments. Committing in the primary is ordinary, sanctioned work -- and this denied it based on a
    word in the subject line."""
    assert run_gate(shell(f'git commit -m "{message}"', cwd=primary), repos_file) is None


# ---------------------------------------------------- what the quote handling must NOT break


def test_a_quoted_program_path_still_supplies_its_git_token(
    primary: Path, repos_file: Path
) -> None:
    """Blanking quoted spans is what stops a commit message supplying a verb -- but a quoted absolute
    program path is a REAL spelling, and blanking it wholesale would erase the git token and turn the fix
    into a false negative. The program-path form is collapsed to a bare token first."""
    cmd = '"C:\\Program Files\\Git\\bin\\git.exe" checkout main'
    assert_denied(run_gate(shell(cmd, cwd=primary), repos_file))


def test_the_absolute_spellings_still_deny(tmp_path: Path, primary: Path, repos_file: Path) -> None:
    """Regression guard: the structured resolver must not displace the in-text fallback for the literal
    spellings that already worked."""
    worktree = tmp_path / "Repo-alerts"
    assert_denied(run_gate(shell(f'git -C "{primary}" checkout main', cwd=worktree), repos_file))
    assert_denied(run_gate(shell(f"cd {primary} && git checkout main", cwd=worktree), repos_file))


def test_a_worktrees_own_relative_work_is_still_allowed(nested: Path, repos_file: Path) -> None:
    """A worktree owns its own history. Resolving `cd` must not start denying a worktree's own commands."""
    assert run_gate(shell("cd . && git switch -c feature/x", cwd=nested), repos_file) is None
    assert run_gate(shell("git rebase origin/main", cwd=nested), repos_file) is None
