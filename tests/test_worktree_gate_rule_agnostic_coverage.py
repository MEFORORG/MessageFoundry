# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""The escape-blind span scan is RULE-AGNOSTIC, so its coverage must be too.

WHAT THE DEFECT WAS is stated once, in `Remove-QuotedSpans` in the hook itself, and pinned by
`tests/test_worktree_gate_escaped_quote.py`. This suite does not restate it. It exists for a
property that suite cannot show: the scan blanks text BEFORE any rule is dispatched, so it disarms
whichever rule WOULD have judged that text. The sibling suite parametrises two verbs, and both reach
the SAME rule -- the one guarding the primary working tree.

WHY A SINGLE-RULE SUITE OVER A RULE-AGNOSTIC DEFECT IS THE SHAPE TO DISTRUST. The class survived in
this codebase behind fourteen green gate suites, none of which could see it. A green suite is
evidence only about the classes it can SEE. Pinning one rule against a defect that disarms all of
them rebuilds that exact condition one layer up: a later change that repairs one rule's own matching
while leaving the scan blind would keep every row green.

SO THIS ASSERTS THE RULE IDS THE GATE ITSELF RECORDED, not merely that a deny happened. "The command
was DENIED" and "the command was denied BY THE RULE WE EXPECTED" are different claims, and only the
second catches a fix that denies for an accidental reason -- a suite checking outcomes alone passes
when the right answer arrives by the wrong route. The ids come from the gate's own receipt log beside
the allowlist rather than from the deny prose, which is a message to a human and is rewritten
whenever a remediation changes.

FOUR RULES, MEASURED RATHER THAN ASSUMED: against the pre-fix hook on a real governed repository one
identical escape wrapper turned DENY into ALLOW on the primary working tree, the linked-worktree
hijack, the shared git configuration and worktree removal.

DELIBERATELY NOT DUPLICATED HERE, so a reader does not mistake the omissions for gaps: the
ordinary-quoted-commit-message and unterminated-quote boundaries live in
`tests/test_worktree_gate_quote_straddle.py`, and the escape-inside-a-real-span control and the
program-path spellings live in `tests/test_worktree_gate_escaped_quote.py`. Third copies would add no
information.

A NOTE ON WHAT IS **NOT** AN ARM HERE, because it was reported as one and is not. `git worktree add`
allows with AND without the escape -- two seats measured that independently, on separate trees -- so
it says nothing about escape handling. Whether it should be governed at all is a real and separate
question. A case built on that false premise would have pressured its next reader to widen a security
gate until a test went green.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from tests.test_worktree_gate import assert_denied, run_gate  # reuse the subprocess harness

pytestmark = pytest.mark.skipif(
    shutil.which("pwsh") is None or shutil.which("git") is None,
    reason="needs pwsh (PowerShell 7) and git on PATH",
)

# Built from character codes rather than written inline, matching the sibling suites: a test about
# escaping must not depend on how this file's own literals escape. This is not hypothetical -- one
# draft of the FIX was written through a shell heredoc and arrived with the backslash silently
# removed, leaving a line that still parsed and asserted nothing.
BS = chr(92)
DQ = '"'


def git(*args: str, cwd: Path | None = None) -> None:
    subprocess.run(
        ["git", *args], cwd=str(cwd) if cwd else None, check=True, capture_output=True, text=True
    )


@pytest.fixture
def repo(tmp_path: Path) -> SimpleNamespace:
    """A real governed primary plus a linked worktree.

    The sibling suites string-match paths and need no real repo. Three of the four rules here ask git
    itself what it is looking at, so the multi-rule coverage this suite exists to assert is reachable
    only against a real one -- which is also why a synthetic fixture reported one of these arms as a
    fail-open when it was simply unreachable.
    """
    primary = tmp_path / "Primary"
    git("init", "-b", "main", str(primary))
    git("config", "user.email", "t@example.com", cwd=primary)
    git("config", "user.name", "t", cwd=primary)
    (primary / "seed.txt").write_text("seed\n", encoding="utf-8")
    git("add", "-A", cwd=primary)
    git("commit", "-m", "seed", cwd=primary)
    # A branch that exists and is checked out NOWHERE -- the grabbable one the hijack rule guards.
    git("branch", "claude/other-branch", cwd=primary)
    wt = tmp_path / "Primary-wt"
    git("worktree", "add", "-b", "wt-branch", str(wt), cwd=primary)
    repos = tmp_path / "repos.txt"
    repos.write_text(f"{primary}\n", encoding="utf-8")
    return SimpleNamespace(primary=primary, wt=wt, repos=repos, log=tmp_path / "worktree-gate.log")


def shell(command: str, cwd: Path | str) -> dict[str, Any]:
    """A Bash tool payload, matching the sibling suites' harness."""
    return {
        "session_id": "s-1",
        "cwd": str(cwd),
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": command},
    }


def straddle(inner: str) -> str:
    """Wrap a command in two backslash-escaped quotes: two shell literals, live command between."""
    return f"echo {BS}{DQ} ; {inner} ; echo {BS}{DQ}"


def rules_logged(repo: SimpleNamespace) -> list[str]:
    """The rule ids the gate recorded, read from its own receipt log beside the allowlist."""
    if not repo.log.exists():
        return []
    text = repo.log.read_text(encoding="utf-8", errors="replace")
    return [m.group(1) for m in re.finditer(r"\trule=(\S+)\t", text)]


# Each arm names the rule it must reach, so the coverage assertion has something to compare against
# that does not drift when a parametrisation is edited.
ARMS: list[tuple[str, str]] = [
    ("3", "primary working tree"),
    ("3b", "linked worktree hijack"),
    ("3c", "shared git configuration"),
    ("3d", "worktree removal"),
]


def arm_command(rule: str, repo: SimpleNamespace) -> tuple[str, Path]:
    """The gated command for an arm, plus the cwd it must be issued from.

    The cwd is part of the arm and not incidental: standing in the linked worktree is what separates
    the hijack rule from the primary-tree rule for the very same verb.
    """
    if rule == "3":
        return f"git -C {repo.primary} reset --hard", repo.primary
    if rule == "3b":
        return "git checkout claude/other-branch", repo.wt
    if rule == "3c":
        return f"git -C {repo.primary} config core.hooksPath /dev/null", repo.primary
    if rule == "3d":
        return f"git -C {repo.primary} worktree remove {repo.wt}", repo.primary
    raise AssertionError(f"unknown arm {rule!r}")


@pytest.mark.parametrize("rule,what", ARMS, ids=[r for r, _ in ARMS])
def test_an_escaped_quote_does_not_hide_a_gated_command(
    repo: SimpleNamespace, rule: str, what: str
) -> None:
    """One offender arm per rule, each with its own positive control run first.

    The control asserts the bare command is gated in this fixture AT ALL. Without it a row could go
    green because the command never reached a rule, and an arm that cannot fail is not evidence --
    which is precisely how a synthetic fixture once made an ungoverned verb look like a fail-open.
    """
    command, cwd = arm_command(rule, repo)
    control = run_gate(shell(command, cwd=cwd), repo.repos)
    assert control is not None, (
        f"positive control failed: the bare {what} command is not gated in this fixture, so the "
        "escaped arm below would prove nothing"
    )
    assert_denied(control)
    assert_denied(run_gate(shell(straddle(command), cwd=cwd), repo.repos))


def test_the_escape_arms_cover_more_than_one_rule(repo: SimpleNamespace) -> None:
    """THE POINT OF THIS FILE. The defect is rule-agnostic, so one-rule coverage is not evidence.

    An assertion rather than a comment, because the failure it guards against is SILENT: an edit that
    narrows the parametrisation, or a fixture change that quietly stops one arm reaching its rule,
    leaves every other row in this file green and says nothing at all.
    """
    for rule, _ in ARMS:
        command, cwd = arm_command(rule, repo)
        assert_denied(run_gate(shell(straddle(command), cwd=cwd), repo.repos))
    seen = set(rules_logged(repo))
    assert seen >= {r for r, _ in ARMS}, (
        "the escaped straddle must be shown to disarm EVERY listed rule, not just the first. "
        f"expected at least {sorted(r for r, _ in ARMS)}, the gate recorded {sorted(seen)}"
    )


def test_an_ungoverned_repo_is_untouched(tmp_path: Path) -> None:
    """Anti-vacuity on the other axis: the deny must come from GOVERNANCE, not from the backslash.

    The identical escaped shape against a repo that is not on the allowlist must still ALLOW. Without
    it, a scan that simply refused anything containing an escaped quote would pass every row above
    while denying ordinary work in every session on the box -- the fail-closed direction is safe for
    the tree and still wrong.
    """
    other = tmp_path / "Ungoverned"
    git("init", "-b", "main", str(other))
    repos = tmp_path / "repos-elsewhere.txt"
    repos.write_text(f"{tmp_path / 'NoSuchGovernedCheckout'}\n", encoding="utf-8")
    command = straddle(f"git -C {other} reset --hard")
    assert run_gate(shell(command, cwd=other), repos) is None, (
        "an ungoverned repo was denied -- the scan is now firing on the escape rather than on the "
        "target, which is a false-deny surface across every session on the box"
    )


def test_the_receipt_reader_can_observe_a_rule_id(repo: SimpleNamespace) -> None:
    """The positive control for `rules_logged`, which the coverage assertion rests on.

    A reader that returns nothing makes that assertion fail loudly. A reader whose PATTERN has
    drifted returns a stale or partial set and fails it QUIETLY in the other direction -- or, worse,
    satisfies it by accident. Assert the instrument sees a known-good deny before anything trusts
    what it does not see.
    """
    assert not rules_logged(repo), "the receipt log must start empty, or the reading below is stale"
    assert_denied(run_gate(shell(f"git -C {repo.primary} reset --hard", repo.primary), repo.repos))
    assert rules_logged(repo) == ["3"], (
        "the receipt log did not record the rule for a deny the gate definitely made -- the reader "
        f"is broken, not the gate. Saw: {rules_logged(repo)!r}"
    )
