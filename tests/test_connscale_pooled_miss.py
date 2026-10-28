# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A pooled step that never started can no longer leave a run green (BACKLOG #3132).

``run_connscale`` used to swallow EVERY pooled step that failed to start, so a claim-mode A/B could
report the missing arm instead of comparing per_lane against nothing. A single-arm pooled profile has
no comparison, so the miss reached nothing: the step left no record, ``zero_loss`` graded what was
left, and a run whose every step failed to start read PASS. Pinning the operator sweep to pooled
would have carried that into the N=1500 run, and turned a setup fault into a slow, mislabelled exit 1.

Now a single-arm profile re-raises, as per_lane always did, and where an A/B does swallow a miss the
run fails even if no comparison row can see it.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from harness.load.connscale import runner as runner_mod
from harness.load.connscale.profile import load_connscale_profile_text
from harness.load.connscale.report import EXIT_SLO_VIOLATION
from harness.load.connscale.runner import ConnScaleError, run_connscale

_POOLED_ONLY = """
[connscale]
name = "pooled-only"
counts = [10]
aggregate_rate = 5.0
sweep_mode = "fixed_aggregate"
claim_modes = ["pooled"]
"""

# A fusion A/B: both arms are pooled, so both are swallowed when they fail to start.
_POOLED_FUSE_AB = """
[connscale]
name = "pooled-fuse-ab"
counts = [10]
aggregate_rate = 5.0
sweep_mode = "fixed_aggregate"
claim_modes = ["pooled"]
fuse_modes = [false, true]
"""


def _refuse_every_step(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    calls: list[str] = []

    async def _refuse(_profile: object, *, claim_mode: str, **_kw: Any) -> object:
        calls.append(claim_mode)
        raise ConnScaleError("engine failed to start (synthetic)")

    monkeypatch.setattr(runner_mod, "_run_one_step", _refuse)
    return calls


async def test_a_single_arm_pooled_setup_fault_raises_like_per_lane(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = _refuse_every_step(monkeypatch)
    profile = load_connscale_profile_text(_POOLED_ONLY)

    with pytest.raises(ConnScaleError, match="synthetic"):
        await run_connscale(profile, engine_api_port_base=9000, sink_port=8000)
    assert calls == ["pooled"]  # stopped at the first fault, not one wait per cell


async def test_a_swallowed_miss_no_comparison_row_sees_still_fails_the_run(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = _refuse_every_step(monkeypatch)
    # Stands in for a comparison that cannot see the miss: in a real fusion A/B, a cell whose B0 and
    # B1 both failed while another cell ran leaves no row and no baseline gap, so the comparison
    # passes. Forcing it to pass here leaves the swallowed-miss gate as the only thing that can fail.
    monkeypatch.setattr(
        runner_mod, "build_fuse_comparison", lambda *_a, **_kw: SimpleNamespace(ok=True)
    )
    profile = load_connscale_profile_text(_POOLED_FUSE_AB)

    report = await run_connscale(profile, engine_api_port_base=9000, sink_port=8000)

    assert calls == ["pooled", "pooled"]  # an A/B keeps sweeping past a pooled miss
    assert report.records == []
    assert any("POOLED ARM MISSING" in note for note in report.notes), report.notes
    assert not report.result_ok
    assert report.exit_code == EXIT_SLO_VIOLATION
