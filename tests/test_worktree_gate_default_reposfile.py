# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Run the gate the way PRODUCTION runs it: with no arguments at all.

Every other test in this suite passes `-ReposFile` so it can point at a temp allowlist. That is necessary
for isolation and it left a hole the size of the whole product: **a parameter default is not evaluated when
a value is supplied**, so the default expression was never once executed by 192 passing tests.

It shipped broken. `Join-Path ( if ... )` opens a command-invocation group, so PowerShell parsed the `if`
as a command name and the hook died with "The term 'if' is not recognized" before its first line. A
`PreToolUse` hook that exits non-zero-but-not-2 lets the tool call through, so the gate was **OFF for every
real tool call on the machine** while `install-gate.ps1 -Status` reported `IN SYNC` — parity compares the
installed copy to source, and both were equally broken.

These tests therefore assert the one property no other test could: that the script is *runnable as
installed*. They never write, and they never depend on this machine's real allowlist contents.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
GATE = ROOT / "scripts" / "hooks" / "worktree_gate.ps1"

pytestmark = pytest.mark.skipif(
    shutil.which("pwsh") is None, reason="pwsh (PowerShell 7) not on PATH"
)


def run_bare(
    payload: dict[str, object], home: Path | None = None
) -> subprocess.CompletedProcess[str]:
    """Invoke the hook with NO -ReposFile, exactly as Claude Code does."""
    env = dict(os.environ)
    if home is not None:
        env["USERPROFILE"] = str(home)
        env["HOME"] = str(home)
    return subprocess.run(
        ["pwsh", "-NoProfile", "-NonInteractive", "-File", str(GATE)],
        input=json.dumps(payload),
        capture_output=True,
        text=True,
        timeout=90,
        env=env,
    )


def read_payload() -> dict[str, object]:
    return {
        "session_id": "s-1",
        "cwd": "C:/nowhere",
        "hook_event_name": "PreToolUse",
        "tool_name": "Read",
        "tool_input": {"file_path": "C:/nowhere/x.txt"},
    }


def test_the_gate_runs_at_all_with_no_arguments(tmp_path: Path) -> None:
    """The regression. The default $ReposFile expression must EVALUATE, not just parse.

    A bare `( if ... )` is a command-invocation group -- PowerShell reads `if` as a command name. Nothing
    caught it because no test omitted -ReposFile.
    """
    r = run_bare(read_payload(), home=tmp_path)
    combined = r.stderr + r.stdout
    assert "is not recognized" not in combined, (
        f"the default $ReposFile expression does not evaluate -- the hook dies before rule 1:\n"
        f"{combined[:800]}"
    )
    assert "ParserError" not in combined and "ParentContainsErrorRecordException" not in combined, (
        f"the script failed to parse or run:\n{combined[:800]}"
    )
    assert r.returncode == 0, f"a hook must always exit 0:\n{combined[:800]}"


def test_a_bare_invocation_with_no_allowlist_is_a_silent_allow(tmp_path: Path) -> None:
    """The kill switch, through the production path: an absent allowlist under the resolved home means the
    gate is off, and it must say nothing at all rather than erroring."""
    r = run_bare(read_payload(), home=tmp_path)
    assert r.returncode == 0
    assert r.stdout.strip() == "", f"expected a silent allow, got: {r.stdout[:400]}"
    assert r.stderr.strip() == "", f"a clean run must not write to stderr: {r.stderr[:400]}"


def test_a_bare_invocation_reads_the_allowlist_under_the_resolved_home(tmp_path: Path) -> None:
    """Proves the default path is not merely evaluable but CORRECT: drop an allowlist where the default
    expression should look, and the gate must deny against it with no -ReposFile given."""
    hooks = tmp_path / ".claude" / "hooks"
    hooks.mkdir(parents=True)
    governed = tmp_path / "Governed"
    (hooks / "worktree-gate.repos.txt").write_text(f"{governed}\n", encoding="utf-8")

    r = run_bare(
        {
            "session_id": "s-1",
            "cwd": str(governed),
            "hook_event_name": "PreToolUse",
            "tool_name": "Edit",
            "tool_input": {"file_path": str(governed / "src" / "app.py")},
        },
        home=tmp_path,
    )
    assert r.returncode == 0, r.stderr
    assert r.stdout.strip(), (
        "the gate found no allowlist at the default location -- it denied nothing"
    )
    decision = json.loads(r.stdout)["hookSpecificOutput"]
    assert decision["permissionDecision"] == "deny"
    assert "SHARED PRIMARY" in decision["permissionDecisionReason"]
