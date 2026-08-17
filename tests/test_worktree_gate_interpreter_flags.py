# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Which flags count as an INTERPRETER flag, and why the answer has to be a rule rather than a list.

``Get-ScannableSegments`` does not blank the quoted argument of an interpreter flag, it RECURSES into
it, because that span is code that runs -- see ``test_worktree_gate_shell_semantics`` for the regression
that established it. WHICH flags counted was a fixed list of literals (``-c``, ``-lc``, ``-ec``,
``-Command``, ``-EncodedCommand``, ``/[ckCK]``), matched case-SENSITIVELY. Every spelling that list did
not carry was a route around the WHOLE gate: the argument reverted to an ordinary quoted span, was
blanked, and its contents became invisible to rules 3, 3b, 3c and 3d alike. BACKLOG #1097.

**The accepted spellings were established by EXECUTION, not read off documentation.** Driven against the
real binaries on this box -- pwsh 7.6.4, Windows PowerShell 5.1, Git Bash, cmd.exe:

* PowerShell binds a parameter by any unambiguous PREFIX of its name, so every spelling from ``-C`` to
  ``-Command`` RUNS, on BOTH hosts;
* matching is case-INsensitive -- ``-command``, ``-COM`` and ``-CoMmAnD`` all run;
* both hosts take the same parameter under the ``/`` sigil: ``/c``, ``/Com``, ``/COMMAND`` run;
* ``-Cm``, ``-Cmd``, ``-Cnd`` and ``-Comd`` do NOT run: each is reported as a script-file name. That
  negative is what BOUNDS the family -- it is the prefixes of the parameter name, never any letter
  cluster -- and :func:`test_the_prefix_family_is_bounded` pins it so a fix cannot widen into
  ``-C[a-z]*``;
* a POSIX shell takes its command in a short-option CLUSTER and the cluster is open-ended: Git Bash runs
  ``-c``, ``-lc``, ``-ec``, ``-xc``, ``-euc``, ``-euxc`` and ``-ic``;
* cmd.exe accepts its switches CONCATENATED: ``/Q/C``, ``/q/c``, ``/s/c`` and ``/V:ON/C`` all run.

**Measured against the gate as committed at ea75c378, before the fix**: this file was 52 failed / 24
passed. The spellings that already denied were ``-Command`` in that exact case, ``/c``/``/C`` when
DOUBLE-quoted, ``-c``/``-lc``/``-ec``, and ``cmd /c``/``/C``/``/k``/``/K``. Every other case here was a
live ALLOW on a command that resets the shared primary's working tree.

**The tests are written by FAMILY, never by spelling**, which is the whole point. A test pinning
``-Command`` cannot see this defect at all, and one pinning ``-Com`` alone cannot see ``-Comm``. That is
the #1000 shape -- a control read as green because its tests carry one member of a family -- and it is
how this bypass sat underneath a suite that already carried interpreter-recursion tests.

**What this file does NOT claim.** Not that every spelling is covered: at least these, established by
execution. Known and deliberately uncovered, each recorded in the gate beside the rule -- an option
cluster with letters AFTER the command letter (``bash -cl``, measured to run); a base64
``-EncodedCommand`` payload, which recursion reaches but no rule can read; ``pwsh -File <script>``, whose
code is not in the command at all; more than one level of nesting, which the function has never done;
and a quoted argument that SPANS LINES, matched by neither the old list nor the new rule (see
:func:`test_a_multi_line_interpreter_argument_still_denies`).
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from tests.test_worktree_gate import assert_denied, run_gate  # reuse the subprocess harness

pytestmark = pytest.mark.skipif(
    shutil.which("pwsh") is None, reason="pwsh (PowerShell 7) not on PATH"
)

# A gated verb aimed at the tree the session is standing in. Every case wraps exactly this, so a
# difference in verdict is a difference in whether the WRAPPER was recognised, never in the payload.
PAYLOAD = "git reset --hard"

# The prefix family, generated rather than typed -- typing it out would be the enumeration this item
# exists to remove, and it would drift from the gate's own alternation the first time either changed.
COMMAND_PREFIXES = ["Command"[:n] for n in range(1, len("Command") + 1)]


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
    """A first-party worktree, where ``../../..`` IS the primary -- the natural relative spelling."""
    return primary / ".claude" / "worktrees" / "wt-1"


@pytest.fixture
def repos_file(tmp_path: Path, primary: Path) -> Path:
    f = tmp_path / "repos.txt"
    f.write_text(f"{primary}\n", encoding="utf-8")
    return f


# ------------------------------------------------------------------ the PowerShell prefix family


@pytest.mark.parametrize("quote", ['"', "'"])
@pytest.mark.parametrize("sigil", ["-", "/"])
@pytest.mark.parametrize("prefix", COMMAND_PREFIXES)
def test_every_prefix_of_the_command_parameter_is_recursed_into(
    primary: Path, repos_file: Path, sigil: str, prefix: str, quote: str
) -> None:
    """All 28 of these run the payload. The list this replaced carried exactly two -- ``-Command``
    double- and single-quoted -- so ``-Com``, ``-Comm``, ``/Com`` and ``/c '...'`` were ALLOWs on a
    command that swaps the shared tree."""
    command = f"pwsh -NoProfile {sigil}{prefix} {quote}{PAYLOAD}{quote}"
    reason = assert_denied(run_gate(shell(command, cwd=primary), repos_file))
    assert "SHARED PRIMARY" in reason


@pytest.mark.parametrize(
    "flag", ["-command", "-COMMAND", "-com", "-COM", "-CoMmAnD", "/COMMAND", "/Com"]
)
def test_the_flag_is_recognised_whatever_its_case(
    primary: Path, repos_file: Path, flag: str
) -> None:
    """Parameter matching is case-insensitive on both hosts, but the matcher ran through
    ``[regex]::Matches`` with no options -- case-SENSITIVELY. So plain lowercase ``-command`` was a
    bypass sitting immediately beside the one spelling the list did carry."""
    assert_denied(run_gate(shell(f'pwsh -NoProfile {flag} "{PAYLOAD}"', cwd=primary), repos_file))


@pytest.mark.parametrize("flag", ["-Cm", "-Cmd", "-Cnd", "-Comd"])
def test_the_prefix_family_is_bounded(primary: Path, repos_file: Path, flag: str) -> None:
    """The negative that keeps the fix honest, and it must stay ALLOW.

    Measured: pwsh REFUSES each of these ("not recognized as the name of a script file"), so the command
    runs nothing and there is nothing to deny. A matcher spelled ``-C[a-z]*`` would deny all four, read
    as more thorough, and have stopped describing the family -- the any-letters widening that produced a
    separate fail-open in #1086's candidate. The mandatory whitespace-then-quote after the flag is what
    refuses them."""
    assert run_gate(shell(f'pwsh -NoProfile {flag} "{PAYLOAD}"', cwd=primary), repos_file) is None


# ------------------------------------------------------------------ the POSIX and cmd.exe families


@pytest.mark.parametrize("flag", ["-c", "-lc", "-ec", "-xc", "-euc", "-euxc", "-ic"])
def test_a_shell_option_cluster_ending_in_the_command_letter_is_an_interpreter_flag(
    primary: Path, repos_file: Path, flag: str
) -> None:
    """A POSIX shell's flags are a CLUSTER and the cluster is open-ended. The list held three members of
    it, so ``-xc`` and ``-euc`` were ALLOWs; the property that matters is "short options ending in the
    command letter", so that is what the gate matches."""
    assert_denied(run_gate(shell(f'bash {flag} "{PAYLOAD}"', cwd=primary), repos_file))


@pytest.mark.parametrize("flag", ["/c", "/C", "/k", "/K", "/Q/C", "/q/c", "/s/c", "/V:ON/C"])
def test_a_cmd_switch_cluster_is_an_interpreter_flag(
    primary: Path, repos_file: Path, flag: str
) -> None:
    """cmd.exe accepts its switches concatenated -- all eight measured to run. The old ``/[ckCK]``
    pattern saw the first four and none of the clusters."""
    assert_denied(run_gate(shell(f'cmd {flag} "{PAYLOAD}"', cwd=primary), repos_file))


def test_the_slash_form_is_recognised_under_either_quote(primary: Path, repos_file: Path) -> None:
    """``/c`` had a pattern of its own that accepted DOUBLE quotes only, so ``/c '...'`` -- this repo's
    own single-quote idiom -- allowed while ``/c "..."`` denied. The verdict turned on the quote
    character rather than on what ran."""
    assert_denied(run_gate(shell(f"cmd /c '{PAYLOAD}'", cwd=primary), repos_file))


# ------------------------------------------------------- the recursion feeds every rule, not just 3


@pytest.fixture
def repo(tmp_path: Path) -> SimpleNamespace:
    """A real governed primary + a linked worktree + a free branch to hijack onto."""
    if shutil.which("git") is None:
        pytest.skip("needs git on PATH")

    def git(*args: str, cwd: Path | None = None) -> None:
        subprocess.run(
            ["git", *args],
            cwd=str(cwd) if cwd else None,
            check=True,
            capture_output=True,
            text=True,
        )

    primary = tmp_path / "Primary"
    git("init", "-b", "main", str(primary))
    git("config", "user.email", "t@example.com", cwd=primary)
    git("config", "user.name", "t", cwd=primary)
    (primary / "seed.txt").write_text("seed\n", encoding="utf-8")
    git("add", "seed.txt", cwd=primary)
    git("commit", "-m", "seed", cwd=primary)
    git("branch", "claude/other-branch", cwd=primary)
    wt = tmp_path / "Primary-wt"
    git("worktree", "add", "-b", "wt-branch", str(wt), cwd=primary)
    repos = tmp_path / "repos.txt"
    repos.write_text(f"{primary}\n", encoding="utf-8")
    return SimpleNamespace(primary=primary, wt=wt, repos=repos, other="claude/other-branch")


@pytest.mark.skipif(shutil.which("git") is None, reason="needs git on PATH")
@pytest.mark.parametrize("flag", ["-Com", "-command", "/Com"])
def test_an_abbreviated_flag_does_not_hide_a_worktree_hijack(
    repo: SimpleNamespace, flag: str
) -> None:
    """Rule 3b rides the same scan, so an unrecognised wrapper disarmed it too: a session could pull
    another session's worktree onto its branch by spelling the flag four characters short."""
    command = f'pwsh {flag} "git checkout {repo.other}"'
    reason = assert_denied(run_gate(shell(command, cwd=repo.wt), repo.repos))
    assert "LINKED WORKTREE" in reason


@pytest.mark.skipif(shutil.which("git") is None, reason="needs git on PATH")
@pytest.mark.parametrize(
    ("program", "flag"), [("pwsh", "-Com"), ("pwsh", "-command"), ("pwsh", "/Com"), ("bash", "-xc")]
)
def test_an_abbreviated_flag_does_not_hide_a_shared_config_disarm(
    repo: SimpleNamespace, program: str, flag: str
) -> None:
    """The severe one, and the item's own sentence: whatever a session may not do directly it could do
    inside ``pwsh -Com '...'``. Rule 3c refuses a ``core.hooksPath`` repoint because that turns off the
    ledger, claim and secret-leak commit gates for every worktree at once -- and an unrecognised wrapper
    made the refusal skippable by typing four fewer characters."""
    command = f'{program} {flag} "git config core.hooksPath /dev/null"'
    reason = assert_denied(run_gate(shell(command, cwd=repo.primary), repo.repos))
    assert "core.hookspath" in reason.lower()


@pytest.mark.parametrize(
    ("program", "flag"),
    [
        ("pwsh", "-Com"),
        ("pwsh", "-command"),
        ("pwsh", "/Com"),
        ("bash", "-xc"),
        ("pwsh", "-Command"),  # already denied before the fix -- the regression control
    ],
)
def test_an_abbreviated_flag_does_not_hide_a_relative_cd_to_the_primary(
    nested: Path, repos_file: Path, program: str, flag: str
) -> None:
    """The two defects COMPOSE, and the composition is worse than either alone.

    ``../../..`` from a nested worktree IS the primary -- that is simply how a session names the repo
    root, and BACKLOG #1061 was the work of teaching the resolver to see it. Wrapping the same command
    in a flag the matcher did not carry put it back out of reach: measured ALLOW on the committed gate
    for the first four spellings, DENY for the fifth, which is the same command with four more
    characters typed. A gate whose verdict turns on how a flag is abbreviated is not a gate."""
    command = f'{program} {flag} "cd ../../.. && git reset --hard"'
    reason = assert_denied(run_gate(shell(command, cwd=nested), repos_file))
    assert "SHARED PRIMARY" in reason


# --------------------------------------------------- what a wider matcher must NOT start refusing


def test_a_flag_needs_its_quoted_argument_adjacent(primary: Path, repos_file: Path) -> None:
    """``grep -C 3 "git checkout main"`` takes a COUNT before its pattern, so the quoted span is not
    that flag's argument. The mandatory whitespace-then-quote keeps a context flag out of the family --
    the same requirement that refuses ``-Comd``."""
    assert run_gate(shell('grep -C 3 "git checkout main"', cwd=primary), repos_file) is None


def test_gits_own_dash_C_path_argument_does_not_become_a_false_deny(
    tmp_path: Path, primary: Path, repos_file: Path
) -> None:
    """``-C`` is now in the family -- it is a working spelling of ``-Command`` -- and ``git -C "<path>"``
    is a shape the gate itself PRINTS in the remedy text of at least three of its own rules. Recursing
    into a path yields a segment carrying no git token, so it changes no verdict: a call aimed at a
    sibling is still allowed and one aimed at the primary is still denied by the structural resolver."""
    sibling = tmp_path / "Repo-alerts"
    assert run_gate(shell(f'git -C "{sibling}" rebase main', cwd=primary), repos_file) is None
    assert_denied(run_gate(shell(f'git -C "{primary}" checkout main', cwd=sibling), repos_file))


@pytest.mark.parametrize(
    "command",
    [
        'pwsh -Com "echo about to merge stuff"',
        'ssh box "git checkout main"',
        'git commit -m "chore: clean up dead code"',
        'bash -xc "echo restoring the backup"',
        'tar -C "/tmp/x" -xf archive.tar',
    ],
)
def test_the_wider_matcher_does_not_resurrect_the_false_positives(
    primary: Path, repos_file: Path, command: str
) -> None:
    """Recursion only ADDS a scan line, and a line still needs a git token AND a gated verb to deny.
    These are the false positives earlier fixes were paid for: prose inside an interpreter argument, a
    command that runs on another HOST, a commit subject line, a verb word used as English, and a path
    argument that happens to sit behind a family flag."""
    assert run_gate(shell(command, cwd=primary), repos_file) is None


# ------------------------------------------------------------------ a limit, recorded as a limit


@pytest.mark.parametrize("flag", ["-Command", "-Com"])
def test_a_multi_line_interpreter_argument_still_denies(
    primary: Path, repos_file: Path, flag: str
) -> None:
    """A REGRESSION PIN, and NOT evidence about the recursion.

    ``Get-ScannableSegments`` splits per line before it looks for an interpreter flag, so a quoted
    argument spanning lines is matched by neither the old list nor the new rule. Both forms below deny
    anyway, because every line of such a span reaches the scanner RAW and the payload line carries the
    git token and the verb by itself. That is an accident of the raw scan, it is load-bearing, and a
    change that blanks message bodies would remove it (BACKLOG #1086). This pins the verdict so such a
    change cannot flip it silently. It cannot tell you WHICH mechanism produced the verdict -- and on
    this gate no test can, which is why the multi-line form was left alone here instead of being
    "fixed" against a green nobody could have seen fail."""
    command = f'pwsh -NoProfile {flag} "\n{PAYLOAD}\n"'
    assert_denied(run_gate(shell(command, cwd=primary), repos_file))
