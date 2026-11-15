# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The open-loop rate governor offers what the phase's rate curve integrates to (BACKLOG #5573).

Driven by a deterministic fake clock: ``asyncio.get_running_loop().time()`` and ``asyncio.sleep``
are replaced inside :mod:`harness.load.governor`, so every tick lands where the governor asked and
the counts below are exact functions of the code, not of host speed.

The defect pinned here: the governor fixed the NEXT send time from the rate at the moment of the
send, so a ramp starting at zero or a small rate scheduled its second send ``1 / tiny-rate`` seconds
out and never pulled it in as the rate rose, and a zero-rate stretch left the deadline behind, so
the return to a positive rate fired the whole stretch's worth of sends in one tick.
"""

from __future__ import annotations

import asyncio
from collections import Counter
from dataclasses import dataclass
from types import SimpleNamespace
from typing import Any

import pytest

from harness.load import governor as governor_mod
from harness.load.metrics import Counters as LoadCounters
from harness.load.profile import Phase, TypeMix


class _FakeClock:
    def __init__(self) -> None:
        self.now = 0.0
        self.sleeps = 0

    def time(self) -> float:
        return self.now

    async def sleep(self, delay: float) -> None:
        self.sleeps += 1
        if self.sleeps > 1_000_000:  # a governor that never advances time would hang the test
            raise AssertionError("governor spun without sleeping forward")
        self.now += max(0.0, delay)


class _CountingGovernor(governor_mod.RateGovernor):
    """Records each emission's fake-clock time instead of building and routing a message."""

    def __init__(self, clock: _FakeClock) -> None:
        corpus: Any = SimpleNamespace(sampler=lambda mix: None)
        super().__init__(corpus, None, LoadCounters())  # type: ignore[arg-type]
        self._clock = clock
        self.emitted: list[float] = []

    def _emit_one(self, sampler: Any) -> None:
        self.emitted.append(self._clock.now)


@dataclass(frozen=True)
class _VPhase(Phase):
    """A rate curve with a zero-rate stretch in the middle: ``rate_start`` until 2 s, zero until 4 s,
    then ``rate_start`` again. The shipped profile shape is linear, so this is a test-only curve; it
    is the shape of a ramp back up from zero inside one phase."""

    def rate_at(self, t_in_phase: float) -> float:
        return 0.0 if 2.0 <= t_in_phase < 4.0 else self.rate_start


def _run(phase: Phase, monkeypatch: pytest.MonkeyPatch) -> _CountingGovernor:
    clock = _FakeClock()
    fake_asyncio = SimpleNamespace(get_running_loop=lambda: clock, sleep=clock.sleep)
    monkeypatch.setattr(governor_mod, "asyncio", fake_asyncio)
    gov = _CountingGovernor(clock)
    mix = TypeMix({"ADT^A01": 1.0})

    async def go() -> None:
        await gov._run_open(phase, mix, asyncio.Event())

    asyncio.run(go())
    return gov


def _ramp(rate_start: float, rate_end: float, duration: float = 10.0) -> Phase:
    return Phase(
        name="ramp",
        kind="ramp",
        loop="open",
        duration_s=duration,
        rate_start=rate_start,
        rate_end=rate_end,
    )


def _within(actual: int, expected: float) -> bool:
    # The fake clock makes the count exact up to the trapezoid rule's rounding at a tick that
    # straddles a curve's kink, so one send of slack, not a percentage.
    return abs(actual - expected) <= 1


def test_constant_rate_offers_rate_times_duration(monkeypatch: pytest.MonkeyPatch) -> None:
    gov = _run(_ramp(100.0, 100.0), monkeypatch)
    assert _within(len(gov.emitted), 1000), len(gov.emitted)
    assert gov._counters.deferred == 0


def test_ramp_from_zero_offers_the_integral(monkeypatch: pytest.MonkeyPatch) -> None:
    # 0 -> 1000 msg/s over 10 s integrates to 5000 sends. The old governor scheduled its second
    # send from the rate of its first tick (about 2 msg/s) and so offered a small fraction of it.
    gov = _run(_ramp(0.0, 1000.0), monkeypatch)
    assert _within(len(gov.emitted), 5000), len(gov.emitted)
    assert gov._counters.deferred == 0


def test_a_slow_ramp_from_zero_offers_the_integral(monkeypatch: pytest.MonkeyPatch) -> None:
    # 0 -> 10 msg/s over 100 s integrates to 500. The old governor's first positive tick read about
    # 0.002 msg/s and scheduled the next send 500 s out, past the end of the phase: it sent ONE.
    gov = _run(_ramp(0.0, 10.0, duration=100.0), monkeypatch)
    assert _within(len(gov.emitted), 500), len(gov.emitted)


def test_ramp_from_a_small_rate_offers_the_integral(monkeypatch: pytest.MonkeyPatch) -> None:
    # 0.1 -> 1000.1 msg/s over 10 s integrates to 5001. The old governor's second send waited the
    # first rate's full 10 s interval, which is the whole phase.
    gov = _run(_ramp(0.1, 1000.1), monkeypatch)
    assert _within(len(gov.emitted), 5001), len(gov.emitted)


def test_ramp_down_offers_the_integral(monkeypatch: pytest.MonkeyPatch) -> None:
    gov = _run(_ramp(1000.0, 0.0), monkeypatch)
    assert _within(len(gov.emitted), 5000), len(gov.emitted)


def test_a_zero_rate_stretch_does_not_burst_on_the_way_back_up(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # 100 msg/s for 0-2 s and 4-6 s, zero between: 400 sends, spread evenly. The old governor left
    # its deadline at 2 s through the zero stretch and fired ~200 sends in the first tick after 4 s.
    phase = _VPhase(name="v", kind="ramp", loop="open", duration_s=6.0, rate_start=100.0)
    gov = _run(phase, monkeypatch)
    assert _within(len(gov.emitted), 400), len(gov.emitted)
    in_gap = [t for t in gov.emitted if 2.06 <= t < 4.0]
    assert not in_gap, in_gap[:5]
    # No single instant carries more than a tick's worth of sends at 100 msg/s.
    burst = max(Counter(gov.emitted).values())
    assert burst <= 6, burst
    assert gov._counters.deferred == 0


def test_a_phase_integrating_below_one_still_offers_one(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # 0.05 msg/s for 10 s integrates to 0.5. The phase offers the ceiling, as the old schedule did.
    gov = _run(_ramp(0.05, 0.05), monkeypatch)
    assert len(gov.emitted) == 1


def test_zero_rate_phase_offers_nothing(monkeypatch: pytest.MonkeyPatch) -> None:
    gov = _run(_ramp(0.0, 0.0, duration=2.0), monkeypatch)
    assert gov.emitted == []
    assert gov._counters.deferred == 0
