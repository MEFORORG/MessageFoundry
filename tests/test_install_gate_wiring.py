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

import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest

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


def matcher_block() -> str:
    text = INSTALLER.read_text(encoding="utf-8")
    return text.split("$matchers = @(", 1)[1].split("$entries", 1)[0]


def tools_the_installer_registers() -> set[str]:
    """Every tool name the installer CAN register -- including the ones behind an opt-in switch.

    This is deliberately the permissive reading. It answers "did someone add a rule and forget the
    matcher entirely", which is the drift this file exists for. It does NOT answer "does the default
    install wire it" (see below) and it cannot answer "is it wired on this machine" at all -- that needs
    the live settings.json, which is tests/test_gate_installed_parity.py.
    """
    tools: set[str] = set()
    for matcher in QUOTED.findall(matcher_block()):
        tools.update(matcher.split("|"))
    return tools


def tools_registered_by_default() -> set[str]:
    """What a bare `install-gate.ps1` writes: the unconditional array, plus blocks guarded by a NEGATED
    switch (`-not $NoDispatchGate` is on unless you opt out). A block guarded by a plain `if ($Switch)`
    is opt-IN and contributes nothing by default."""
    block = matcher_block()
    tools: set[str] = set()
    unconditional, _, rest = block.partition("if (")
    for matcher in QUOTED.findall(unconditional):
        tools.update(matcher.split("|"))
    for chunk in ("if (" + rest).split("if (")[1:]:
        guard, _, body = chunk.partition(")")
        if "-not" in guard:  # opt-OUT: on unless suppressed
            for matcher in QUOTED.findall(body):
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
        "EnterWorktree",
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


def test_the_default_install_wires_rules_1_2_and_3_and_nothing_else() -> None:
    """Pin what a bare `install-gate.ps1` actually turns on.

    The permissive test above is satisfied by a matcher sitting behind an opt-in switch, which is exactly
    how a rule can be "registered by the installer" and still never fire. Rule 4 (EnterWorktree) is
    deliberately opt-in -- it compounds with rule 2 to leave a primary-resident session no in-session path
    to isolation, so activating it as a side effect of installing an unrelated fix would be a trap. That
    decision belongs in this assertion, where changing it is visible, rather than in a switch nobody reads.
    """
    assert tools_registered_by_default() == {
        "Write",
        "Edit",
        "MultiEdit",
        "NotebookEdit",
        "Bash",
        "PowerShell",
        "Task",
        "Agent",
        "Workflow",
    }


def test_every_opt_in_tool_is_guarded_by_a_plain_switch() -> None:
    """The opt-in must be real: a tool named outside a guard is on by default whatever the docs say."""
    opt_in = tools_the_installer_registers() - tools_registered_by_default()
    assert opt_in == {"EnterWorktree"}, f"unexpected opt-in set: {sorted(opt_in)}"
    assert re.search(r"if \(\$EnterWorktreeGate\)", matcher_block()), (
        "EnterWorktree must be added inside an `if ($EnterWorktreeGate)` block"
    )


# ----------------------------------------------------------------------------- the -Status audit


def test_status_prints_a_sha_beside_each_version() -> None:
    """`-Status` is the only way to see whether the RUNNING gate matches this checkout, and nothing
    exercised it. It also shipped a defect worth pinning: `$GateVersion` is bumped by hand, and rules 1a,
    3c and 3d were added without a bump -- so it printed the SAME version on both lines directly above a
    *** STALE *** verdict. The SHA comparison caught the drift, but a label that disagrees with the verdict
    beside it is the ambiguity this whole audit exists to remove.

    Asserting the SHA is printed makes agreement visible rather than asserted. Read-only and safe to run
    anywhere: `-Status` sits above the CLAUDECODE refusal precisely so a session can audit but not install.
    """
    if shutil.which("pwsh") is None:
        pytest.skip("SKIP (nothing run): pwsh not on PATH")
    r = subprocess.run(
        ["pwsh", "-NoProfile", "-NonInteractive", "-File", str(INSTALLER), "-Status"],
        capture_output=True,
        text=True,
        timeout=120,
        env={**os.environ, "CLAUDECODE": "1"},
    )
    assert r.returncode == 0, f"-Status must never fail:\n{(r.stderr + r.stdout)[:800]}"
    out = r.stdout
    print(out)
    assert "installed   :" in out and "source      :" in out
    # The source line always resolves (this checkout), so it must always carry a hash.
    src_line = next(ln for ln in out.splitlines() if ln.startswith("source      :"))
    assert re.search(r"\bsha [0-9a-f]{12}\b", src_line), (
        f"the source line must show its hash, not just a hand-bumped version: {src_line!r}"
    )
    assert re.search(r"\bv\d{4}\.\d{2}\.\d{2}\.\d+", src_line), (
        f"version label missing: {src_line!r}"
    )
