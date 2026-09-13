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


def write_transcript(tmp_path: Path, model: str | None, tokens: int) -> str:
    """One usage-bearing assistant record, the shape the hook's backward walk looks for."""
    message: dict[str, object] = {
        "usage": {
            "input_tokens": tokens,
            "cache_read_input_tokens": 0,
            "cache_creation_input_tokens": 0,
            "output_tokens": 0,
        }
    }
    if model is not None:
        message["model"] = model
    path = tmp_path / "transcript.jsonl"
    path.write_text(json.dumps({"message": message}) + chr(10), encoding="utf-8")
    return str(path)


def run_hook(env_overrides: dict[str, str], transcript: str = "") -> str:
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
        input=json.dumps({"transcript_path": transcript}),
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


def test_the_unknown_model_arm_assigns_nothing() -> None:
    """Grep the source for the one edit that would undo this fix: a fallback on the default arm.

    The behavioural tests above already catch most of it -- an unknown model with 950k tokens must
    stay unresolved. But they cannot see INTENT, and the tempting change here is small and looks
    like a tidy-up: filling in the empty `default { }` so the switch "handles every case". That arm
    is empty on purpose, and this pins it.
    """
    source = HOOK.read_text(encoding="utf-8")

    sentinel = re.compile(r"^\s*\$maxTokens\s*=\s*0\s*$", re.MULTILINE)
    assert sentinel.search(source), "the unknown-window sentinel ($maxTokens = 0) is gone"

    arm = re.search(r"^\s*default\s*\{(?P<body>[^}]*)\}", source, re.MULTILINE)
    assert arm is not None, "the switch's default arm is gone; this test's search is broken"
    assert "$maxTokens" not in arm.group("body"), (
        f"the default arm assigns a fallback window: {arm.group('body')!r}. "
        "An unmapped model must fall through to no percentage, never to a guess."
    )


def test_no_window_is_assigned_outside_a_model_match() -> None:
    """Every window literal in the hook must sit inside the model table or be the sentinel."""
    source = HOOK.read_text(encoding="utf-8")
    assigns = re.findall(r"^\s*\$maxTokens\s*=\s*(?P<rhs>\S+)", source, re.MULTILINE)

    # Positive control: a zero here means the search is broken, not the source clean.
    assert assigns, "found no $maxTokens assignment at all; this test's search is broken"

    allowed = {"0", "$parsed", "1000000", "200000"}
    unexpected = [r for r in assigns if r.rstrip(";") not in allowed]
    assert not unexpected, f"unrecognised window assignment(s): {unexpected}"


# --- window resolved from the model in the transcript -------------------------------------------
#
# Claude Code hands the status line a resolved context_window_size and hands a hook neither the
# window nor the model. These pin the workaround: read the model off the record the hook already
# walks to, and map it. An unknown model must fall through to silence, never to a guess.


def test_a_1m_model_in_the_transcript_resolves_its_own_window(tmp_path: Path) -> None:
    tr = write_transcript(tmp_path, "claude-opus-5", 950_000)
    text = run_hook({}, transcript=tr)

    assert "95%" in text, f"claude-opus-5 should resolve to a 1M window: {text}"
    assert "1000k tokens" in text, f"the resolved window should be reported: {text}"


def test_a_200k_model_in_the_transcript_resolves_a_different_window(tmp_path: Path) -> None:
    """The discriminating arm. If the table returned one constant, this and the test above cannot
    both pass -- 190k is 19 percent of 1M (silent) and 95 percent of 200k (HARD)."""
    tr = write_transcript(tmp_path, "claude-haiku-4-5-20251001", 190_000)
    text = run_hook({}, transcript=tr)

    assert "95%" in text, f"claude-haiku-4-5 should resolve to a 200k window: {text}"
    assert "200k tokens" in text, f"the resolved window should be reported: {text}"


def test_the_same_count_is_silent_on_the_1m_model(tmp_path: Path) -> None:
    """Same 190k, other model. This is the real-world reading that started all of this."""
    tr = write_transcript(tmp_path, "claude-opus-5", 190_000)
    assert run_hook({}, transcript=tr) == "", "190k of 1M is 19 percent and must be silent"


def test_a_1m_suffix_overrides_the_base_model(tmp_path: Path) -> None:
    tr = write_transcript(tmp_path, "claude-sonnet-4-5-20250929[1m]", 950_000)
    text = run_hook({}, transcript=tr)

    assert "95%" in text, f"a [1m] suffix must win over the base id's 200k: {text}"


def test_an_unknown_model_falls_through_to_silence_not_a_guess(tmp_path: Path) -> None:
    """The safety property that lets the table be incomplete. A model it does not know must
    produce NO percentage -- never a fallback constant."""
    tr = write_transcript(tmp_path, "claude-something-not-shipped-yet", 950_000)
    text = run_hook({}, transcript=tr)

    assert "%" not in text, f"an unknown model produced a percentage: {text}"
    assert "NO WINDOW RESOLVED" in text, f"expected the unresolved branch: {text}"
    assert "claude-something-not-shipped-yet" in text, (
        "the hook should name the model it could not map"
    )


def test_synthetic_is_not_treated_as_a_model(tmp_path: Path) -> None:
    """Real transcripts carry '<synthetic>' on some records. It is not a model id."""
    tr = write_transcript(tmp_path, "<synthetic>", 950_000)
    text = run_hook({}, transcript=tr)

    assert "%" not in text, f"'<synthetic>' was mapped to a window: {text}"


def test_the_operator_override_beats_the_model_table(tmp_path: Path) -> None:
    """A configured window wins, so an operator can correct a wrong or missing table entry."""
    tr = write_transcript(tmp_path, "claude-opus-5", 190_000)
    text = run_hook({"MEFOR_CONTEXT_BUDGET_MAX_TOKENS": "200000"}, transcript=tr)

    assert "95%" in text, f"the override should have forced a 200k window: {text}"
