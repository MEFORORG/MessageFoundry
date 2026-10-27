# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A pooled step that never started fails the run, whatever the profile's arms (BACKLOG #3132).

``run_connscale`` keeps sweeping when a POOLED step fails to start, so a claim-mode A/B can report the
missing arm instead of comparing per_lane against nothing. Each A/B comparison folds that miss into its
own ``ok``. A single-arm pooled profile has no comparison, so the miss reached nothing: the step left no
record, ``zero_loss`` graded the steps that were left, and a run whose every step failed to start read
PASS. Pinning the operator sweep to pooled would have carried that into the N=1500 run.
"""

from __future__ import annotations

from typing import Any

import pytest

from harness.load.connscale import runner as runner_mod
from harness.load.connscale.profile import load_connscale_profile_text
from harness.load.connscale.runner import ConnScaleError, run_connscale

_POOLED_ONLY = """
[connscale]
name = "pooled-only"
counts = [10]
aggregate_rate = 5.0
sweep_mode = "fixed_aggregate"
claim_modes = ["pooled"]
"""


async def test_a_single_arm_pooled_run_whose_step_never_started_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def _refuse(_profile: object, **_kw: Any) -> object:
        raise ConnScaleError("engine failed to start (synthetic)")

    monkeypatch.setattr(runner_mod, "_run_one_step", _refuse)
    profile = load_connscale_profile_text(_POOLED_ONLY)

    report = await run_connscale(profile, engine_api_port_base=9000, sink_port=8000)

    assert report.records == []
    assert any("POOLED ARM MISSING" in note for note in report.notes), report.notes
    assert not report.result_ok
    assert report.exit_code != 0
