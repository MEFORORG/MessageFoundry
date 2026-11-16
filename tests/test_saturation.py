# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""SaturationDetector — the rising-backlog DERIVATIVE signal (BACKLOG #93, ADR 0014 amendment).

The headline is the **key property**: the detector fires on a lane whose backlog is rising sustained
(ingest > drain) but must **NOT** fire on a bursty-but-DRAINING lane (a spike the worker is clearing).
Pure + synchronous, so these are deterministic table tests over ``observe`` with controlled timestamps.
"""

from __future__ import annotations

import pytest

from messagefoundry.pipeline.saturation import SaturationDetector, SaturationSignal


def _feed(detector: SaturationDetector, depths: list[int]) -> SaturationSignal | None:
    """Feed a depth series at 1-second steps and return the last observation's result."""
    result: SaturationSignal | None = None
    for i, depth in enumerate(depths):
        result = detector.observe(float(i), depth)
    return result


def test_fires_on_sustained_rising_backlog() -> None:
    # A lane whose pending depth climbs monotonically — ingest sustained over drain. It should fire.
    det = SaturationDetector(sustain_samples=3)
    sig = _feed(det, [0, 5, 10, 15])  # 4 samples = sustain_samples + 1; every step rises
    assert sig is not None
    assert sig.depth == 15
    assert sig.depth_start == 0
    assert sig.samples == 4
    assert sig.growth_per_second == pytest.approx(15 / 3)  # (15-0) over the 3s span


def test_does_not_fire_on_bursty_but_draining_lane() -> None:
    # THE KEY PROPERTY. A burst spikes the depth, then the worker DRAINS it back down. Even though the
    # window contains a big momentary depth, it is not RISING across the window — a decrease appears —
    # so the detector must stay silent (a draining lane is not becoming overloaded).
    det = SaturationDetector(sustain_samples=3)
    assert _feed(det, [0, 50, 40, 20]) is None  # spike then drain → no sustained growth
    # And a lane that keeps draining stays silent.
    assert det.observe(4.0, 10) is None
    assert det.observe(5.0, 5) is None


def test_does_not_fire_before_window_is_primed() -> None:
    # Needs sustain_samples + 1 observations before it can decide; fewer returns None.
    det = SaturationDetector(sustain_samples=3)
    assert det.observe(0.0, 1) is None
    assert det.observe(1.0, 2) is None
    assert det.observe(2.0, 3) is None  # only 3 samples; window needs 4
    assert det.observe(3.0, 4) is not None  # 4th primes it → rising → fires


def test_flat_backlog_does_not_fire() -> None:
    # A steady non-empty backlog (arrivals == departures) is not GROWING — no derivative signal.
    det = SaturationDetector(sustain_samples=3)
    assert _feed(det, [7, 7, 7, 7]) is None


def test_single_dip_in_window_suppresses() -> None:
    # A window that rises overall but dips once mid-way is a burst being partly cleared, not sustained
    # saturation — one decrease is enough to suppress (conservative, avoids false pages).
    det = SaturationDetector(sustain_samples=3)
    assert _feed(det, [0, 10, 8, 20]) is None  # net rise 0→20, but a 10→8 dip breaks "sustained"
    assert det.observe(4.0, 25) is None  # window [10,8,20,25] still carries the 8 dip → suppressed
    # Once the dip has fully aged out of the bounded window and growth is monotonic again, it fires.
    assert det.observe(5.0, 30) is not None  # window [8,20,25,30] — all non-decreasing → fires


def test_window_is_bounded_so_old_spike_ages_out() -> None:
    # The history is capped at sustain_samples + 1, so a lane that spiked long ago then settled into
    # steady growth is judged on the RECENT window, not the ancient spike.
    det = SaturationDetector(sustain_samples=2)  # keeps 3 samples
    det.observe(0.0, 100)  # ancient spike
    det.observe(1.0, 1)  # drained
    det.observe(2.0, 2)
    sig = det.observe(3.0, 3)  # window is now [1,2,3] — rising, spike gone
    assert sig is not None and sig.depth_start == 1 and sig.depth == 3


def test_reset_clears_history() -> None:
    det = SaturationDetector(sustain_samples=2)
    _feed(det, [1, 2, 3])  # would be primed
    det.reset()
    assert det.observe(0.0, 4) is None  # history cleared → not primed again yet


def test_sustain_samples_floor() -> None:
    with pytest.raises(ValueError):
        SaturationDetector(sustain_samples=1)  # fewer than 2 can't tell a burst from growth


# --- BACKLOG #5768: a flat step is not a rise, and a window with no time span has no rate ----------


@pytest.mark.parametrize(
    "depths",
    [
        [0, 0, 0, 1],  # a primed idle lane takes one message
        [0, 0, 5, 5],  # one tick's burst, then nothing more arrives
        [0, 5, 5, 10],  # a flat step mid-window
        [3, 4, 5, 5],  # rises, then stops rising
    ],
)
def test_a_window_with_a_flat_step_does_not_fire(depths: list[int]) -> None:
    assert _feed(SaturationDetector(sustain_samples=3), depths) is None


def test_the_flat_step_ages_out_and_sustained_rise_then_fires() -> None:
    det = SaturationDetector(sustain_samples=2)  # keeps 3 samples
    assert _feed(det, [0, 0, 1]) is None
    sig = det.observe(3.0, 2)  # window [0, 1, 2]: every step rose
    assert sig is not None and sig.depth_start == 0 and sig.depth == 2


@pytest.mark.parametrize("stamps", [[5.0, 5.0, 5.0], [5.0, 4.0, 3.0]], ids=["still", "back"])
def test_a_window_with_no_forward_time_span_does_not_fire(stamps: list[float]) -> None:
    det = SaturationDetector(sustain_samples=2)
    results = [det.observe(ts, depth) for ts, depth in zip(stamps, [1, 2, 3], strict=True)]
    assert results[-1] is None
