# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The context-budget hook must never report a percentage of a guessed window.

WHY THIS FILE EXISTS. The hook shipped with a hardcoded 200,000-token default window. Nothing set
the override, the real window was 1,000,000, and every percentage it printed was five times too
large. A seat read 95 percent at 19 percent full, told a peer it was about to go quiet, and the peer
started sequencing around a handoff that was never coming. Measured 2026-09-13.

The defect was not the arithmetic. It was that a wrong denominator produces a PLAUSIBLE number, and
the only guard was a "greater than 100 percent" check that cannot fire from below. These tests pin
the property that replaced it: no configured window means no percentage.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest

HOOK = Path(__file__).resolve().parents[1] / "scripts" / "hooks" / "context-budget.ps1"
PWSH = shutil.which("pwsh") or shutil.which("powershell")

# The `tooling` marker is NOT written here. tests/conftest.py applies it from
# tests/tooling_manifest.txt, so that one reviewed list is the single definition of the tier.
pytestmark = pytest.mark.skipif(PWSH is None, reason="PowerShell is not on PATH")


def run_hook(env_overrides: dict[str, str]) -> str:
    """Run the hook with a token count injected, and return its additionalContext (or "")."""
    env = dict(os.environ)
    # Clear every knob this hook reads, so a developer's own shell cannot change the verdict.
    for key in list(env):
        if key.startswith("MEFOR_CONTEXT_BUDGET_"):
            del env[key]
    env.update(env_overrides)

    assert PWSH is not None  # the module-level skipif guarantees this at runtime
    proc = subprocess.run(
        [PWSH, "-NoProfile", "-File", str(HOOK)],
        input=json.dumps({"transcript_path": ""}),
        capture_output=True,
        text=True,
        env=env,
        timeout=120,
    )
    # Fail-open is a hard property of this hook: it must never wedge a turn.
    assert proc.returncode == 0, f"hook exited {proc.returncode}: {proc.stderr}"
    if not proc.stdout.strip():
        return ""
    parsed: str = json.loads(proc.stdout)["hookSpecificOutput"]["additionalContext"]
    return parsed


def test_no_configured_window_reports_no_percentage() -> None:
    """The regression itself. Absolute count yes, fullness figure no."""
    text = run_hook({"MEFOR_CONTEXT_BUDGET_TOKENS": "190300"})

    assert text, "the hook said nothing at all; it should report the absolute count"
    assert "190.3k" in text, f"the measured count is missing: {text}"
    assert "%" not in text, f"a percentage was reported with no window configured: {text}"
    # The failure mode was a confident level word attached to an invented number.
    for level in ("WARN", "SOFT", "HARD"):
        assert f"[context-budget] {level}" not in text, (
            f"level {level} claimed without a window: {text}"
        )
    assert "MEFOR_CONTEXT_BUDGET_MAX_TOKENS" in text, "the hook must name its own fix"


def test_configured_window_reports_a_percentage() -> None:
    """The positive control. Without this, the test above passes on a hook that says nothing ever."""
    text = run_hook(
        {"MEFOR_CONTEXT_BUDGET_TOKENS": "950000", "MEFOR_CONTEXT_BUDGET_MAX_TOKENS": "1000000"}
    )

    assert "95%" in text, f"expected 95% of a 1M window: {text}"
    assert "[context-budget] HARD" in text, f"950k of 1M is past the 0.92 hard threshold: {text}"


def test_the_real_world_case_is_quiet_not_alarming() -> None:
    """190.3k of a 1M window is 19 percent, which is below WARN. The hook must stay silent.

    This is the exact reading that produced the false alarm. Pinning it as SILENT, not merely as
    'not HARD', is the point: the old hook called this 95 percent spent.
    """
    text = run_hook(
        {"MEFOR_CONTEXT_BUDGET_TOKENS": "190300", "MEFOR_CONTEXT_BUDGET_MAX_TOKENS": "1000000"}
    )

    assert text == "", f"19 percent of the window should produce no output at all, got: {text}"


def test_a_ceiling_smaller_than_the_count_is_named_as_wrong() -> None:
    """The surviving half-guard. A configured ceiling the count exceeds is reported as the fault."""
    text = run_hook(
        {"MEFOR_CONTEXT_BUDGET_TOKENS": "871400", "MEFOR_CONTEXT_BUDGET_MAX_TOKENS": "200000"}
    )

    assert "CEILING WRONG" in text, f"an impossible percentage was not caught: {text}"
    assert "871.4k" in text, f"the absolute count should still be reported: {text}"
    assert "%" not in text, f"no fullness figure may be given once the ceiling is known bad: {text}"


def test_disable_flag_silences_the_hook() -> None:
    text = run_hook(
        {
            "MEFOR_CONTEXT_BUDGET_TOKENS": "950000",
            "MEFOR_CONTEXT_BUDGET_MAX_TOKENS": "1000000",
            "MEFOR_CONTEXT_BUDGET_DISABLE": "1",
        }
    )
    assert text == "", f"the disable flag did not silence the hook: {text}"


def test_the_hook_carries_no_default_window() -> None:
    """Grep the source. A default is the defect, so its absence is worth pinning directly.

    A behavioural test cannot distinguish 'no default' from 'a default that happens to be huge',
    and reintroducing a default is the specific regression this file guards against.
    """
    source = HOOK.read_text(encoding="utf-8")
    # Match an ASSIGNMENT to $maxTokens, anchored left. A looser "contains $maxTokens and ="
    # also matches `$frac = [double]$used / [double]$maxTokens`, where $maxTokens is on the
    # right-hand side -- which is a read, not a default.
    assign = re.compile(r"^\s*\$maxTokens\s*=\s*(?P<rhs>.+?)\s*$")
    live = [
        m.group("rhs")
        for line in source.splitlines()
        if not line.strip().startswith("#")
        for m in [assign.match(line)]
        if m
    ]

    # Positive control: the assignments we DO expect must be found, or a zero here means the
    # grep is broken rather than the source clean.
    assert live, "found no $maxTokens assignment at all; this test's search is broken"
    assert "0" in live, f"the unknown-window sentinel is gone: {live}"

    for rhs in live:
        if rhs in ("0", "$parsed"):
            continue
        pytest.fail(f"a default window was reintroduced: $maxTokens = {rhs}")
