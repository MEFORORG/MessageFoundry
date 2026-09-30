# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The estate runner's achieved rates are read over the in-hold readings only (BACKLOG #2011).

``_run_one`` appends a post-drain final to ``samples`` so the no-loss reconcile can read it. Until
#2011 the achieved rates were read from ``samples[0]`` to ``samples[-1]``, so the drain tail sat
inside every rate while the docstring said "hold window". Through the drain the driver has stopped
offering, so ``read`` flattens while the span keeps growing, and the tail dilutes the rate.

These tests pin the window at ``_build_record`` with synthetic samples, pin the call site's order in
``_run_one``, and pin the ``rate_window`` marker every estate output carries.
"""

from __future__ import annotations

import inspect
import json
from types import SimpleNamespace
from typing import cast

from harness.load.enginepoll import EnginePoller, EngineSample
from harness.load.estate import runner
from harness.load.estate.profile import get_estate_profile
from harness.load.estate.report import RATE_WINDOW, EstateRecord, EstateReport
from harness.load.metrics import Counters, Histogram, LiveMetrics

# The in-hold readings run at 100 read/s and 200 written/s for 4 seconds. The post-drain final lands
# 10 seconds later with both counters flat, which is what a drain after the driver stopped looks like.
_HOLD_READ_PER_S = 100.0
_HOLD_WRITTEN_PER_S = 200.0
_HOLD_TICKS = 5  # readings at t = 0..4
_DRAIN_GAP_S = 10.0


def _sample(elapsed_s: float, *, read: int, written: int) -> EngineSample:
    return EngineSample(
        elapsed_s=elapsed_s,
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
        uptime_s=elapsed_s,
    )


def _hold_then_final() -> list[EngineSample]:
    hold = [
        _sample(float(t), read=int(_HOLD_READ_PER_S * t), written=int(_HOLD_WRITTEN_PER_S * t))
        for t in range(_HOLD_TICKS)
    ]
    last = hold[-1]
    final = _sample(last.elapsed_s + _DRAIN_GAP_S, read=last.read, written=last.written)
    return [*hold, final]


def _record(samples: list[EngineSample], in_hold_samples: int) -> EstateRecord:
    profile = get_estate_profile("estate-smoke")
    counters = Counters()
    counters.sent = samples[-1].read
    counters.acked = samples[-1].read
    metrics = LiveMetrics(counters=counters, ack=Histogram(), e2e=Histogram())
    poller = cast(EnginePoller, SimpleNamespace(baseline=samples[0], final=samples[-1]))
    return runner._build_record(
        profile=profile,
        metrics=metrics,
        poller=poller,
        samples=samples,
        in_hold_samples=in_hold_samples,
        drain_seconds=1.0,
    )


def test_the_achieved_rates_exclude_the_post_drain_final() -> None:
    samples = _hold_then_final()
    record = _record(samples, in_hold_samples=_HOLD_TICKS)

    assert record.achieved_read_per_s == _HOLD_READ_PER_S
    assert record.achieved_written_per_s == _HOLD_WRITTEN_PER_S
    assert record.achieved_total_event_rate == _HOLD_READ_PER_S + _HOLD_WRITTEN_PER_S
    assert record.achieved_per_conn_event_rate == (
        (_HOLD_READ_PER_S + _HOLD_WRITTEN_PER_S) / record.count
    )
    assert record.in_hold_samples == _HOLD_TICKS


def test_the_fixture_discriminates_the_drain_tail_changes_the_rate() -> None:
    """Control arm: the old window, run to the post-drain final, reads a DIFFERENT rate.

    Without this, the arm above would also pass on a fixture whose tail changes nothing, and so could
    not tell the fixed window from the defect.
    """
    samples = _hold_then_final()
    old_window = _record(samples, in_hold_samples=len(samples))

    span = samples[-1].elapsed_s - samples[0].elapsed_s
    assert old_window.achieved_read_per_s == samples[-1].read / span
    assert old_window.achieved_read_per_s < _HOLD_READ_PER_S


def test_a_single_in_hold_reading_reports_zero_and_says_why() -> None:
    samples = _hold_then_final()
    record = _record([samples[0], samples[-1]], in_hold_samples=1)

    assert (record.achieved_read_per_s, record.achieved_written_per_s) == (0.0, 0.0)
    assert record.in_hold_samples == 1


def test_run_one_counts_the_in_hold_readings_before_it_appends_the_final() -> None:
    """The call site's order is the fix: a count taken after the append puts the tail back in.

    ``_run_one`` needs a live engine, so its order is pinned on its source text.
    """
    source = inspect.getsource(runner._run_one)
    count_at = source.index("in_hold_samples = len(samples)")
    append_at = source.index("samples.append(final)")
    assert count_at < append_at
    assert "in_hold_samples=in_hold_samples" in source


def test_every_estate_output_carrying_a_rate_carries_the_window_marker() -> None:
    assert RATE_WINDOW == "in_hold_excl_drain"
    record = _record(_hold_then_final(), in_hold_samples=_HOLD_TICKS)
    report = EstateReport(
        profile="estate-smoke",
        engine_url="https://127.0.0.1:1",
        db_backend=None,
        records=[record],
        slos=[],
        result_ok=True,
        exit_code=0,
    )

    payload = json.loads(report.to_json())
    (rec,) = payload["records"]
    assert rec["rate_window"] == RATE_WINDOW
    assert rec["in_hold_samples"] == _HOLD_TICKS
    assert f"rate_window={RATE_WINDOW}" in report.render_console()
