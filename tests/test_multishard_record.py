# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""The multishard record's achieved/delivered rates must be HOLD-BRACKETED steady-state rates.

The original metric divided the baseline→post-drain read-delta by the nominal hold, so any intake
that spilled into the post-hold flush + drain was counted against a 60s divisor — under overload the
WS-B N=8 record printed 857 msg/s for a ~230-240 msg/s steady state (~3.5x inflation; the number that
initially mis-supported a "collapse contradicts the ceiling" reading, WS_B_REPORT.md REVISED
2026-07-02). These tests pin the fix: the rate comes from the hold-bracket samples over the measured
hold wall time, spill never inflates it, and the documented fallback (bracket sample missing) is the
old behavior rather than a dishonest zero.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import cast

import pytest

from harness.load.enginepoll import EnginePoller, EngineSample
from harness.load.metrics import Counters, Histogram, LiveMetrics
from harness.load.multishard import _build_record


def _sample(*, read: int, written: int) -> EngineSample:
    return EngineSample(
        elapsed_s=1.0,
        pending=0,
        inflight=0,
        done=written,
        dead=0,
        read=read,
        written=written,
        out_dead=0,
        queue_depth=0,
        in_pipeline=0,
        db_size_bytes=0,
        journal_mode="wal",
        synchronous="normal",
        uptime_s=1.0,
    )


_BASE = _sample(read=0, written=0)
_HOLD_BEGIN = _sample(read=100, written=100)  # ramp traffic that precedes the hold
_HOLD_END = _sample(read=700, written=640)  # +600 read / +540 written during the 60s hold
_FINAL = _sample(read=2200, written=2140)  # post-hold flush + drain spill (the inflation source)


def _record(**overrides: object) -> object:
    kwargs: dict[str, object] = dict(
        engines=2,
        count_per_engine=15,
        per_conn_rate=13.0,
        hold_seconds=60.0,
        cluster_enabled=False,
        metrics=LiveMetrics(
            Counters(sent=2200, acked=2200, sink_received=2140), Histogram(), Histogram()
        ),
        poller=cast(EnginePoller, SimpleNamespace(baseline=_BASE, final=_FINAL)),
        samples=[_HOLD_END],
        drain_seconds=5.0,
        hold_start_iso="2026-07-02T00:00:00+00:00",
        drain_complete_iso="2026-07-02T00:03:00+00:00",
        per_engine=(),
        hold_begin=_HOLD_BEGIN,
        hold_end=_HOLD_END,
        hold_elapsed_s=60.0,
    )
    kwargs.update(overrides)
    return _build_record(**kwargs)  # type: ignore[arg-type]


def test_achieved_is_hold_bracketed_not_window_inflated() -> None:
    rec = _record()
    # (700-100)/60 = 10/s — NOT (2200-0)/60 ≈ 36.7/s, which counts ramp + post-hold spill.
    assert rec.achieved_aggregate_rate == pytest.approx(10.0)  # type: ignore[attr-defined]
    assert rec.delivered_aggregate_rate == pytest.approx(9.0)  # type: ignore[attr-defined]


def test_achieved_uses_measured_wall_time_not_nominal_hold() -> None:
    # A hold that actually ran 75s (slow gather/scheduling) must divide by 75, not the nominal 60.
    rec = _record(hold_elapsed_s=75.0)
    assert rec.achieved_aggregate_rate == pytest.approx(600 / 75.0)  # type: ignore[attr-defined]


def test_missing_bracket_falls_back_to_legacy_window() -> None:
    # A failed bracket sample (poller API error) falls back to the legacy baseline→final / nominal
    # hold — the documented, distortion-prone caveat — rather than reporting 0 for a run that moved
    # traffic. Both directions pinned: begin missing and end missing.
    for missing in ({"hold_begin": None}, {"hold_end": None}):
        rec = _record(**missing)  # type: ignore[arg-type]
        assert rec.achieved_aggregate_rate == pytest.approx(2200 / 60.0)  # type: ignore[attr-defined]
