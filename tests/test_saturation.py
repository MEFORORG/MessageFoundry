# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""SaturationDetector — the rising-backlog DERIVATIVE signal (BACKLOG #93, ADR 0014 amendment).

The headline is the **key property**: the detector fires on a lane whose backlog is rising sustained
(ingest > drain) but must **NOT** fire on a bursty-but-DRAINING lane (a spike the worker is clearing).
Pure + synchronous, so these are deterministic table tests over ``observe`` with controlled timestamps.
"""

from __future__ import annotations

import pytest

from messagefoundry.config.models import SATURATION_MIN_GROWTH_DEFAULT
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
    # Needs sustain_samples + 1 observations before it can decide; fewer returns None. The floor is
    # 1 so this tests priming alone.
    det = SaturationDetector(sustain_samples=3, min_growth=1)
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
    det = SaturationDetector(sustain_samples=2, min_growth=1)  # keeps 3 samples
    det.observe(0.0, 100)  # ancient spike
    det.observe(1.0, 1)  # drained
    det.observe(2.0, 2)
    sig = det.observe(3.0, 3)  # window is now [1,2,3] — rising, spike gone
    assert sig is not None and sig.depth_start == 1 and sig.depth == 3


def test_reset_clears_history() -> None:
    det = SaturationDetector(sustain_samples=2, min_growth=1)
    _feed(det, [1, 2, 3])  # would be primed
    det.reset()
    assert det.observe(0.0, 4) is None  # history cleared → not primed again yet


def test_sustain_samples_floor() -> None:
    with pytest.raises(ValueError):
        SaturationDetector(sustain_samples=1)  # fewer than 2 can't tell a burst from growth


# --- BACKLOG #5768: a rise must clear the growth floor before it counts as sustained ----------------


@pytest.mark.parametrize(
    "depths",
    [
        [0, 0, 0, 1],  # a primed idle lane takes one message
        [0, 0, 4, 4],  # one tick's small burst
        [5, 5, 5, 9],  # a busy lane takes a few more
    ],
)
def test_a_rise_below_the_default_floor_does_not_fire(depths: list[int]) -> None:
    assert depths[-1] - depths[0] < SATURATION_MIN_GROWTH_DEFAULT
    assert _feed(SaturationDetector(sustain_samples=3), depths) is None


def test_slow_growth_past_the_floor_fires_with_flat_steps() -> None:
    # An outbound sampled on each retry, faster than its arrivals: flat steps, slow net growth.
    depths = [5, 5, 6, 6, 7, 8, 8, 9, 10]
    assert depths[-1] - depths[0] >= SATURATION_MIN_GROWTH_DEFAULT
    sig = _feed(SaturationDetector(sustain_samples=len(depths) - 1), depths)
    assert sig is not None and sig.depth_start == 5 and sig.depth == 10


def test_steady_growth_slower_than_the_floor_per_window_still_fires() -> None:
    # +1 a sample over a 3-step window: each window rises 3, under the floor of 5, but the run since
    # the lane last fell clears it.
    det = SaturationDetector(sustain_samples=3)
    results = [det.observe(float(i), i) for i in range(8)]
    assert results[:5] == [None] * 5
    assert results[5] is not None and results[5].depth == 5


def test_a_drain_below_the_starting_depth_restarts_the_count() -> None:
    # The count starts at 3, rises 4, then the lane drains to 1, below 3: the count restarts at 1.
    det = SaturationDetector(sustain_samples=2)
    assert _feed(det, [3, 5, 7, 1, 2, 3]) is None
    sig = det.observe(6.0, 6)  # 6 is 5 above the new start of 1, but only 3 above the old one
    assert sig is not None and sig.depth == 6


def test_growth_with_a_small_dip_every_few_samples_fires_once_past_the_floor() -> None:
    # +1, +1, +1, -1 repeating: a 1-message dip never falls below the starting depth of 0, so it
    # does not restart the count. The first dip-free window after the net rise reaches 5 fires.
    det = SaturationDetector(sustain_samples=3)
    depths = [0, 1, 2, 3, 2, 3, 4, 5, 4, 5, 6, 7]
    results = [det.observe(float(i), d) for i, d in enumerate(depths)]
    assert results[:7] == [None] * 7
    assert results[7] is not None and results[7].depth == 5


def test_reset_restarts_the_run() -> None:
    det = SaturationDetector(sustain_samples=2)
    _feed(det, [0, 1, 2, 3])
    det.reset()
    assert _feed(det, [3, 4, 5]) is None  # the run starts again at 3, so a rise of 2


def test_the_floor_is_exact() -> None:
    assert _feed(SaturationDetector(sustain_samples=2, min_growth=3), [0, 1, 2]) is None
    assert _feed(SaturationDetector(sustain_samples=2, min_growth=3), [0, 1, 3]) is not None


def test_min_growth_floor() -> None:
    with pytest.raises(ValueError):
        SaturationDetector(sustain_samples=2, min_growth=0)
