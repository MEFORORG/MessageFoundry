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

from typing import Any

import pytest

from harness.load.connscale import runner as runner_mod
from harness.load.connscale.profile import load_connscale_profile_text
from harness.load.connscale.report import EXIT_SLO_VIOLATION, ConnScaleRecord
from harness.load.connscale.runner import ConnScaleError, _build_record, run_connscale
from harness.load.enginepoll import EnginePoller, EngineSample
from harness.load.metrics import Counters, Histogram

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
counts = [10, 20]
aggregate_rate = 5.0
sweep_mode = "fixed_aggregate"
claim_modes = ["pooled"]
fuse_modes = [false, true]
"""


def _sample(n: int) -> EngineSample:
    return EngineSample(
        elapsed_s=0.0,
        pending=0,
        inflight=0,
        done=n,
        dead=0,
        read=n,
        written=n,
        out_dead=0,
        queue_depth=0,
        in_pipeline=0,
        db_size_bytes=0,
        journal_mode="wal",
        synchronous="normal",
        uptime_s=0.0,
    )


def _clean_record(*, fuse_mode: bool, mode: str, count: int) -> ConnScaleRecord:
    """A real record for a step that ran and lost nothing: 4 sent, read, written and delivered."""
    poller = EnginePoller("http://127.0.0.1:1", token=None, origin=0.0)
    poller._samples = [_sample(0), _sample(4)]
    return _build_record(
        claim_mode="pooled",
        fuse_mode=fuse_mode,
        batch_mode=False,
        mode=mode,
        count=count,
        aggregate_rate=5.0,
        metrics_counters=Counters(sent=4, acked=4, sink_received=4),
        ack_hist=Histogram(),
        poller=poller,
        samples=[],
        in_hold_samples=0,
        in_hold_floor_ticks=0,
        proc_readings=[],
        drain_seconds=1.0,
        reload_seconds=None,
    )


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
    # The N=10 cell fails to start in BOTH arms; the N=20 cell runs clean in both. The fusion
    # comparison pairs B1 against the B0 cells it saw, so N=10 leaves it no row and no baseline gap.
    calls: list[tuple[bool, int]] = []

    async def _step(
        _profile: object, *, fuse_mode: bool, mode: str, count: int, **_kw: Any
    ) -> ConnScaleRecord:
        calls.append((fuse_mode, count))
        if count == 10:
            raise ConnScaleError("engine failed to start (synthetic)")
        return _clean_record(fuse_mode=fuse_mode, mode=mode, count=count)

    monkeypatch.setattr(runner_mod, "_run_one_step", _step)
    profile = load_connscale_profile_text(_POOLED_FUSE_AB)

    report = await run_connscale(profile, engine_api_port_base=9000, sink_port=8000)

    # An A/B keeps sweeping past a pooled miss, so all four steps were tried.
    assert sorted(calls) == [(False, 10), (False, 20), (True, 10), (True, 20)]
    assert len(report.records) == 2
    assert any("POOLED ARM MISSING" in note for note in report.notes), report.notes
    # The control: the comparison and every SLO pass, so only the swallowed-miss gate can fail it.
    assert report.fuse_comparison is not None and report.fuse_comparison.ok
    assert all(check.ok for check in report.slos)
    assert not report.result_ok
    assert report.exit_code == EXIT_SLO_VIOLATION
