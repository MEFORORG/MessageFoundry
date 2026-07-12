"""The installer must register a matcher for every tool the gate script actually branches on.

This exists because it went wrong. Rule 3 (git verbs that swap the shared primary's working tree) was
implemented in scripts/hooks/worktree_gate.ps1 and shipped — but install-gate.ps1 registered matchers only
for `Write|Edit|MultiEdit|NotebookEdit` and `Task|Agent|Workflow`. Claude Code therefore never invoked the
hook for a `Bash` or `PowerShell` call, so the rule was DEAD CODE the moment it was installed, and nothing
said so.

The 66 existing gate tests could not catch it: they pipe a payload straight into the script, which
bypasses matcher dispatch entirely. They test the LOGIC. This tests the WIRING — the seam where a rule
that works in isolation silently never runs in production.
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
GATE = ROOT / "scripts" / "hooks" / "worktree_gate.ps1"
INSTALLER = ROOT / "scripts" / "worktree" / "install-gate.ps1"

# `if ($tool -in @("Bash", "PowerShell")) {` / `if ($tool -notin @("Write", "Edit", ...))`
TOOL_BRANCH = re.compile(r"\$tool\s+-(?:not)?in\s+@\(([^)]*)\)")
QUOTED = re.compile(r'"([^"]+)"')


def tools_the_gate_handles() -> set[str]:
    """Every tool name the gate script dispatches on."""
    text = GATE.read_text(encoding="utf-8")
    tools: set[str] = set()
    for group in TOOL_BRANCH.findall(text):
        tools.update(QUOTED.findall(group))
    return tools


def tools_the_installer_registers() -> set[str]:
    """Every tool name reachable through the installer's PreToolUse matchers."""
    text = INSTALLER.read_text(encoding="utf-8")
    block = text.split("$matchers = @(", 1)[1].split("$entries", 1)[0]
    tools: set[str] = set()
    for matcher in QUOTED.findall(block):
        tools.update(matcher.split("|"))
    return tools


def test_the_gate_handles_the_tools_we_expect() -> None:
    """Guard the guard: if a rule is added or removed, this test should be the thing that notices."""
    assert tools_the_gate_handles() == {
        "Write",
        "Edit",
        "MultiEdit",
        "NotebookEdit",
        "Task",
        "Agent",
        "Workflow",
        "Bash",
        "PowerShell",
    }


def test_every_tool_the_gate_handles_is_registered_by_the_installer() -> None:
    """A rule the hook implements but the installer does not match NEVER FIRES, and nothing says so."""
    handled = tools_the_gate_handles()
    registered = tools_the_installer_registers()
    unwired = handled - registered
    assert not unwired, (
        f"scripts/hooks/worktree_gate.ps1 branches on {sorted(unwired)}, but install-gate.ps1 registers no "
        f"matcher for them — those rules would be silently dead once installed. "
        f"Registered: {sorted(registered)}"
    )


def test_the_installer_does_not_register_tools_the_gate_ignores() -> None:
    """The inverse drift: matching a tool the script does nothing with just burns a subprocess per call."""
    stray = tools_the_installer_registers() - tools_the_gate_handles()
    assert not stray, (
        f"install-gate.ps1 matches {sorted(stray)}, which worktree_gate.ps1 never inspects."
    )
