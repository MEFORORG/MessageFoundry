# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The fusion and batch A/B comparator (``harness/load/connscale/compare.py``): axis wording and
the sigma label (BACKLOG #5430 item 1, S26-75), a B1 whose reconcile was INCONCLUSIVE meeting the
lift bar (BACKLOG #5574 item 8), and a drained INCONCLUSIVE B0 trial as a lift reference (BACKLOG
#5574 item 5). Pure and hermetic: synthetic records, no engine."""

from __future__ import annotations

from dataclasses import replace

from harness.load.connscale.compare import (
    FUSE_GO,
    FUSE_INCONCLUSIVE,
    FUSE_NO_GO,
    build_batch_comparison,
    build_fuse_comparison,
)
from harness.load.connscale.report import ConnScaleRecord, NoLoss

_CELL = ("pooled", "fixed_aggregate", 256)


def _rec(
    *,
    b1: bool,
    axis: str,
    read: float,
    sent: int = 1000,
    sink_received: int = 1000,
    no_loss_ok: bool = True,
    inconclusive: bool = False,
    drain_seconds: float | None = 1.0,
) -> ConnScaleRecord:
    """One synthetic record on the ``fuse`` or ``batch`` axis, B1 when ``b1``."""
    detail = "ok" if no_loss_ok else "engine counters went backwards"
    return ConnScaleRecord(
        sweep_mode=_CELL[1],
        count=_CELL[2],
        offered_aggregate_rate=400.0,
        sent=sent,
        acked=sent,
        nak=0,
        deferred=0,
        no_loss=NoLoss(
            no_loss_ok,
            sent,
            sent,
            sink_received,
            sink_received,
            0,
            detail,
            inconclusive=inconclusive,
        ),
        in_pipeline_peak=90,
        drain_seconds=drain_seconds,
        executor_queue_depth_peak=None,
        executor_busy_peak=None,
        pool_wait_p50_ms=None,
        pool_wait_p95_ms=None,
        pool_wait_p99_ms=None,
        pool_wait_max_ms=None,
        pool_idle_min=None,
        pool_size_max=None,
        empty_claims_per_s=0.0,
        idle_poll_per_s=0.0,
        wake_fanout_per_s=0.0,
        empty_claims_per_msg=None,
        fd_count_peak=100,
        reload_seconds=None,
        ack_p50_ms=1.0,
        ack_p95_ms=2.0,
        ack_p99_ms=3.0,
        claim_mode=_CELL[0],
        achieved_read_per_s=read,
        achieved_written_per_s=read,
        fuse_thread_hops=b1 and axis == "fuse",
        batch_handoff_statements=b1 and axis == "batch",
    )


def _arm(b1: bool, axis: str, reads: list[float], **kw: object) -> list[ConnScaleRecord]:
    return [_rec(b1=b1, axis=axis, read=r, **kw) for r in reads]  # type: ignore[arg-type]


def _reset(recs: list[ConnScaleRecord]) -> list[ConnScaleRecord]:
    """The same trials with an INCONCLUSIVE reconcile, as a counter reset leaves them."""
    return [replace(r, no_loss=replace(r.no_loss, ok=False, inconclusive=True)) for r in recs]


# --------------------------------------------------------------------------- #
# BACKLOG #5430 item 1 (S26-75): the batch A/B speaks of batching, and the sigma label is the bar
# --------------------------------------------------------------------------- #


def test_batch_lift_reason_names_batching_and_adr_0075_not_fusion() -> None:
    recs = _arm(False, "batch", [100.0, 101.0, 99.0]) + _arm(True, "batch", [102.0, 103.0, 101.0])
    cmp = build_batch_comparison(recs, (False, True))
    assert cmp is not None
    reason = cmp.rows[0].reason
    assert cmp.rows[0].verdict == FUSE_NO_GO
    assert "statement batching banked no worthwhile margin" in reason
    assert "ADR 0075" in reason
    assert "fusion" not in reason.lower() and "ADR 0071" not in reason


def test_fusion_lift_reason_is_unchanged() -> None:
    recs = _arm(False, "fuse", [100.0, 101.0, 99.0]) + _arm(True, "fuse", [102.0, 103.0, 101.0])
    cmp = build_fuse_comparison(recs, (False, True))
    assert cmp is not None
    assert cmp.rows[0].reason == (
        "lift +2.0% < 10% -- fusion banked no worthwhile margin "
        "(null/negative → ADR 0071 escalates to free-threading)"
    )


def test_batch_breach_missing_arm_and_baseline_texts_do_not_name_fusion() -> None:
    breach = _arm(False, "batch", [100.0, 101.0, 99.0]) + _arm(
        True, "batch", [120.0, 121.0, 119.0], no_loss_ok=False, sink_received=900
    )
    cmp = build_batch_comparison(breach, (False, True))
    assert cmp is not None
    assert cmp.rows[0].verdict == FUSE_NO_GO
    assert "statement batching must never drop a message" in cmp.rows[0].reason

    b1_missing = build_batch_comparison(_arm(False, "batch", [100.0, 101.0]), (False, True))
    assert b1_missing is not None
    assert b1_missing.rows[0].reason == "B1 (batching on) arm absent — engine never ran it"
    assert (
        len(b1_missing.notes) == 1
        and "statement batching (B1) arm(s) MISSING" in (b1_missing.notes[0])
    )

    b0_missing = build_batch_comparison(_arm(True, "batch", [100.0, 101.0]), (False, True))
    assert b0_missing is not None
    assert b0_missing.baseline_missing == [_CELL]
    assert any("B0 (batching-off) BASELINE" in note for note in b0_missing.notes)

    for text in [
        cmp.rows[0].reason,
        b1_missing.rows[0].reason,
        *b1_missing.notes,
        *b0_missing.notes,
    ]:
        assert "fusion" not in text.lower(), text


def test_the_sigma_label_names_the_multiple_applied() -> None:
    recs = _arm(False, "fuse", [100.0, 101.0, 99.0]) + _arm(True, "fuse", [120.0, 121.0, 119.0])
    three = build_fuse_comparison(recs, (False, True), sigma_multiple=3.0)
    assert three is not None
    table = three.render_table()
    assert "2sigma" not in table
    assert "> 3sigma |" in table and "3sigma=" in table
    assert "> 3sigma," in three.rows[0].reason

    half = build_fuse_comparison(recs, (False, True), sigma_multiple=2.5)
    assert half is not None
    assert "> 2.5sigma |" in half.render_table() and "2.5sigma=" in half.render_table()

    # One trial per arm: the INCONCLUSIVE reason names the bar it could not establish.
    single = _arm(False, "fuse", [100.0]) + _arm(True, "fuse", [130.0])
    one = build_fuse_comparison(single, (False, True), sigma_multiple=2.5)
    assert one is not None
    assert "establish the 2.5sigma spread" in one.rows[0].reason

    # The default multiple still reads "2sigma", as before.
    default = build_fuse_comparison(recs, (False, True))
    assert default is not None
    assert "2sigma=" in default.render_table() and "> 2sigma," in default.rows[0].reason


# --------------------------------------------------------------------------- #
# BACKLOG #5574 item 8: a B1 whose reconcile was INCONCLUSIVE is not graded on its lift
# --------------------------------------------------------------------------- #


def test_an_inconclusive_b1_under_the_lift_bar_is_inconclusive_not_banked_nothing() -> None:
    # B1's counters reset mid-step, so its intake rate is a clamped stand-in and reads far below
    # B0. It drained and the sink kept up, so only the lift bar is left, and that bar would grade a
    # rate the reconcile could not judge.
    b1 = _reset(_arm(True, "fuse", [30.0, 31.0, 29.0]))
    cmp = build_fuse_comparison(_arm(False, "fuse", [100.0, 101.0, 99.0]) + b1, (False, True))
    assert cmp is not None
    row = cmp.rows[0]
    assert row.verdict == FUSE_INCONCLUSIVE, row.reason
    assert "banked no worthwhile margin" not in row.reason
    assert "INCONCLUSIVE" in row.reason
    assert row.candidate_lost and not row.ok and not cmp.ok
    assert cmp.overall_verdict == FUSE_INCONCLUSIVE

    # One reset trial beside two clean ones is the same: the arm's mean carries the stand-in.
    mixed = _arm(True, "batch", [102.0, 103.0]) + _reset(_arm(True, "batch", [40.0]))
    batch = build_batch_comparison(
        _arm(False, "batch", [100.0, 101.0, 99.0]) + mixed, (False, True)
    )
    assert batch is not None
    assert batch.rows[0].verdict == FUSE_INCONCLUSIVE, batch.rows[0].reason
    assert not batch.ok


def test_an_inconclusive_b1_still_meets_the_definite_no_gos_first() -> None:
    # The drain and keeping-up guards read the drain gauge and the sink, not the engine counters,
    # so an INCONCLUSIVE reconcile does not pre-empt them.
    undrained = _reset(_arm(True, "fuse", [130.0, 131.0, 129.0], drain_seconds=None))
    cmp = build_fuse_comparison(
        _arm(False, "fuse", [100.0, 101.0, 99.0]) + undrained, (False, True)
    )
    assert cmp is not None
    assert cmp.rows[0].verdict == FUSE_NO_GO
    assert "did not fully drain" in cmp.rows[0].reason

    behind = _reset(_arm(True, "fuse", [130.0, 131.0, 129.0], sink_received=500))
    cmp = build_fuse_comparison(_arm(False, "fuse", [100.0, 101.0, 99.0]) + behind, (False, True))
    assert cmp is not None
    assert cmp.rows[0].verdict == FUSE_NO_GO
    assert "not keeping up" in cmp.rows[0].reason


# --------------------------------------------------------------------------- #
# BACKLOG #5574 item 5: a drained B0 trial whose reconcile was INCONCLUSIVE is no reference
# --------------------------------------------------------------------------- #


def test_a_drained_inconclusive_b0_trial_is_no_reference_for_a_go() -> None:
    # Four clean B0 trials at 100/s and one whose counters reset (90/s, clamped). The true lift of
    # B1's 108/s is 8%, under the bar, but against the dragged mean of 98/s it reads +10.2% and
    # outside 2sigma, so this read GO.
    for axis, build in (("fuse", build_fuse_comparison), ("batch", build_batch_comparison)):
        b0 = _arm(False, axis, [100.0, 100.0, 100.0, 100.0]) + _reset(_arm(False, axis, [90.0]))
        b1 = _arm(True, axis, [108.0, 108.1, 107.9, 108.0, 108.0])
        cmp = build(b0 + b1, (False, True))
        assert cmp is not None
        row = cmp.rows[0]
        assert row.lift_pct is not None and row.lift_pct >= 10.0 and row.significant
        assert row.verdict == FUSE_INCONCLUSIVE, row.reason
        assert "1 B0 trial(s) drained but could not clear zero-loss" in row.reason
        assert cmp.overall_verdict == FUSE_INCONCLUSIVE


def test_a_drowned_or_lossy_b0_is_still_a_reference() -> None:
    # The drowning-baseline case stands: a B0 whose drain timed out read its counters, so a
    # fully-draining B1 with the lift is a GO. So is a B0 trial that proved a loss.
    drowned = _reset(_arm(False, "fuse", [100.0, 101.0, 99.0, 100.0], drain_seconds=None))
    cmp = build_fuse_comparison(
        drowned + _arm(True, "fuse", [120.0, 121.0, 119.0, 120.0]), (False, True)
    )
    assert cmp is not None
    assert cmp.rows[0].verdict == FUSE_GO, cmp.rows[0].reason

    lossy = _arm(False, "fuse", [100.0, 101.0, 99.0], no_loss_ok=False, sink_received=900)
    cmp = build_fuse_comparison(lossy + _arm(True, "fuse", [120.0, 121.0, 119.0]), (False, True))
    assert cmp is not None
    assert cmp.rows[0].verdict == FUSE_GO, cmp.rows[0].reason


def test_a_drained_inconclusive_b0_does_not_rescue_a_lift_under_the_bar() -> None:
    # B0's unsound trial only lowers its mean, so a lift under the bar is still a NO-GO.
    b0 = _arm(False, "fuse", [100.0, 101.0, 99.0]) + _reset(_arm(False, "fuse", [90.0]))
    cmp = build_fuse_comparison(b0 + _arm(True, "fuse", [99.0, 100.0, 98.0]), (False, True))
    assert cmp is not None
    assert cmp.rows[0].verdict == FUSE_NO_GO
    assert "banked no worthwhile margin" in cmp.rows[0].reason
