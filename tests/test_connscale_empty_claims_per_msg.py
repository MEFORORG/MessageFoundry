# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""BACKLOG #1101: the empty-claims monotonicity SLO must measure the engine, not the runner.

The SLO used to read ``empty_claims_per_s``, which carries wall clock in its denominator. Anything
that slowed the run -- CPU contention on a shared CI runner, or the O(N) reload probe firing mid-hold
and stalling commits -- collapsed the numerator while the denominator kept ticking, so the metric
fell and the gate went red with **no engine change**. Measured on one commit, one box: four contended
replicates spread **0.451 to 2.49** against a 0.75 floor. That is a coin flip, not a detector.

The fix reads ``empty_claims_per_msg`` instead. Both inputs are deltas over the SAME first-to-last
in-hold samples, so the span cancels and the quantity is exactly ``Δempty_claims / Δread``.

**These tests exist to stop the fix from being the WRONG kind of fix.** A metric that never fails is
not an improvement on one that fails at random, and a correction is the easiest place to skip
measuring because it feels like it has already paid its dues. So the invariance property and the
still-detects-a-real-regression property are pinned TOGETHER: neither alone is evidence.
"""

from __future__ import annotations

import pytest

from harness.load.connscale.report import ConnScaleRecord, NoLoss
from harness.load.connscale.runner import _empty_claims_per_msg, _monotonic_slo


def _rec(
    mode: str,
    count: int,
    *,
    per_msg: float | None,
    claim_mode: str = "per_lane",
) -> ConnScaleRecord:
    """A record carrying only the fields these SLOs read; the rest are inert placeholders."""
    return ConnScaleRecord(
        sweep_mode=mode,
        count=count,
        offered_aggregate_rate=35.0,
        sent=1000,
        acked=1000,
        nak=0,
        deferred=0,
        timeouts=0,
        no_loss=NoLoss(True, 1000, 1000, 1000, 1000, 0, "ok"),
        in_pipeline_peak=3,
        drain_seconds=1.2,
        executor_queue_depth_peak=2,
        executor_busy_peak=1,
        pool_wait_p50_ms=None,
        pool_wait_p95_ms=None,
        pool_wait_p99_ms=None,
        pool_wait_max_ms=None,
        pool_idle_min=None,
        pool_size_max=None,
        empty_claims_per_s=10.0,
        idle_poll_per_s=4.0,
        wake_fanout_per_s=6.0,
        empty_claims_per_msg=per_msg,
        fd_count_peak=100,
        reload_seconds=None,
        ack_p50_ms=None,
        ack_p95_ms=None,
        ack_p99_ms=None,
        claim_mode=claim_mode,
    )


# --------------------------------------------------------------------------------------------------
# The property the fix exists for.
# --------------------------------------------------------------------------------------------------


def test_per_msg_is_invariant_when_the_whole_run_is_slowed() -> None:
    """Contention scales numerator and denominator identically, so the ratio does not move.

    This is the defect reproduced arithmetically. A run that is slowed by 3x reports a third of the
    empty claims per SECOND and a third of the messages per second -- the engine behaved identically,
    only the clock changed.
    """
    fast = _empty_claims_per_msg(total_per_s=450.0, achieved_read_per_s=9.0)
    slowed = _empty_claims_per_msg(total_per_s=150.0, achieved_read_per_s=3.0)

    assert fast == pytest.approx(50.0)
    assert slowed == pytest.approx(50.0), (
        "per-message must not move when the run is uniformly slowed; if it does, the fix has "
        "reproduced the very wall-clock dependence #1101 records"
    )


def test_per_second_would_have_moved_on_the_same_data() -> None:
    """The negative half of the pair: show the OLD metric fails on data the new one survives.

    Without this, 'the new metric is stable' is unfalsifiable -- a constant would also pass.
    """
    fast_per_s, slowed_per_s = 450.0, 150.0
    floor = 0.75
    assert slowed_per_s < fast_per_s * floor, (
        "the old per-second metric must visibly collapse here, otherwise this fixture does not "
        "exercise the defect at all"
    )
    # ...while per-message, on the identical run, is unchanged.
    assert _empty_claims_per_msg(fast_per_s, 9.0) == _empty_claims_per_msg(slowed_per_s, 3.0)


def test_per_msg_is_none_when_no_messages_were_absorbed() -> None:
    """Undefined must stay undefined. Returning 0.0 would chain through the comparison as a reading."""
    assert _empty_claims_per_msg(total_per_s=12.0, achieved_read_per_s=0.0) is None
    assert _empty_claims_per_msg(total_per_s=0.0, achieved_read_per_s=0.0) is None


# --------------------------------------------------------------------------------------------------
# The property that stops this being a gate that never fires.
# --------------------------------------------------------------------------------------------------


def test_slo_still_fails_on_a_genuine_herd_collapse() -> None:
    """A REAL regression -- per-message herd size dropping with N -- must still go red.

    The engine claim wall #3 makes is that the per-commit herd GROWS with connection count. A drop
    means the instrumentation or the fanout changed. The fix must not buy stability by becoming blind.
    """
    records = [
        _rec("fixed_aggregate", 12, per_msg=40.0),
        _rec("fixed_aggregate", 24, per_msg=10.0),  # collapsed, far under the 0.75 floor
    ]
    check = _monotonic_slo("empty_claims_monotonic", records, lambda r: r.empty_claims_per_msg)
    assert not check.ok, "a genuine per-message collapse must fail the SLO"
    assert "fixed_aggregate@N=24" in str(check.observed)


def test_slo_passes_on_the_healthy_shape() -> None:
    """The measured healthy readings: 39.1 at N=12 rising to 77.8 at N=24, a clean 2.0x."""
    records = [
        _rec("fixed_aggregate", 12, per_msg=39.1),
        _rec("fixed_aggregate", 24, per_msg=77.8),
    ]
    assert _monotonic_slo("empty_claims_monotonic", records, lambda r: r.empty_claims_per_msg).ok


def test_slo_skips_undefined_readings_without_failing() -> None:
    """None is 'no reading', not 'a reading of zero'."""
    records = [
        _rec("fixed_aggregate", 12, per_msg=40.0),
        _rec("fixed_aggregate", 24, per_msg=None),
    ]
    assert _monotonic_slo("empty_claims_monotonic", records, lambda r: r.empty_claims_per_msg).ok


# --------------------------------------------------------------------------------------------------
# The latent grouping defect, fixed in the same pass.
# --------------------------------------------------------------------------------------------------


def test_monotonicity_does_not_chain_across_claim_modes() -> None:
    """Grouping by sweep_mode ALONE compares per_lane against pooled.

    ``compare.py`` states pooled's empty-claim rate SHOULD be materially lower, so a CORRECT engine
    would fail this the moment a profile set ``claim_modes = ["per_lane", "pooled"]``. No shipped
    profile does, which is the only reason it has never fired -- the grouping is wrong regardless.
    Ordered so that a sweep_mode-only grouping sorts pooled's low N=12 after per_lane's high N=24.
    """
    records = [
        _rec("fixed_aggregate", 12, per_msg=40.0, claim_mode="per_lane"),
        _rec("fixed_aggregate", 24, per_msg=80.0, claim_mode="per_lane"),
        _rec("fixed_aggregate", 12, per_msg=4.0, claim_mode="pooled"),
        _rec("fixed_aggregate", 24, per_msg=8.0, claim_mode="pooled"),
    ]
    check = _monotonic_slo("empty_claims_monotonic", records, lambda r: r.empty_claims_per_msg)
    assert check.ok, (
        "each claim mode rises monotonically on its own; failing here means prev_val is being "
        f"chained across claim modes, which is the #1101 latent defect. observed={check.observed}"
    )


def test_a_regression_inside_one_claim_mode_is_still_caught() -> None:
    """The grouping fix must not become a way to hide a real drop behind a second claim mode."""
    records = [
        _rec("fixed_aggregate", 12, per_msg=40.0, claim_mode="per_lane"),
        _rec("fixed_aggregate", 24, per_msg=5.0, claim_mode="per_lane"),  # real collapse
        _rec("fixed_aggregate", 12, per_msg=4.0, claim_mode="pooled"),
        _rec("fixed_aggregate", 24, per_msg=8.0, claim_mode="pooled"),
    ]
    check = _monotonic_slo("empty_claims_monotonic", records, lambda r: r.empty_claims_per_msg)
    assert not check.ok
    assert "N=24" in str(check.observed)
