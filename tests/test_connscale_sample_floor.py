# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""BACKLOG #1430: the connscale in-hold sampler must produce at least two readings per sweep step.

A window needs two endpoints. `_empty_claim_rates` and `_throughput_rates` each read a first and a
last engine sample, and both return zeros behind a silent `len(samples) < 2` guard. The step's sample
list reached two only by counting the post-drain final, so the HOLD itself contributed one reading:
in 20 of 20 cells at hold 1.5 and hold 3.0, measured by the Builder who filed the item.

**THE CAUSE WAS THE PROBE ON THE POLL'S TICK, and it is arithmetic rather than luck.** `_sample_loop`
used to poll the engine and then run the OS process-table walk on the same tick, so one tick cost the
poll interval PLUS the walk. Measured on the maintainer's box on 2026-09-06, over `FdSampler` against
a live child process: a front-load walk plus per-PID read costs 0.99-1.47 s (median 1.04, n=4) and a
cached tick costs 0.23-0.25 s (median 0.24, n=8), against a `poll_interval_s` of 0.25. The CI cell's
`hold_seconds = 1.5` cannot fit two of those, so the second reading was unreachable.

WHAT THIS MODULE PINS, in the order the item requires them:

1. the FLOOR -- the sampler does not return with fewer than `_MIN_IN_HOLD_SAMPLES` readings, even
   when `stop` is already set before it starts;
2. the SPACING -- the floor's own readings are an interval apart, because two readings taken back to
   back span nearly no time and a rate over that span is a fabricated number rather than a missing
   one;
3. the DECOUPLING -- a probe that costs multiples of the interval no longer decides how many engine
   samples the hold produces, which is the fix aimed at the measured cause;
4. the BOUND -- a poller that answers `None` forever cannot hold the step open;
5. the PROVENANCE -- the loop reports how many readings the floor had to supply, so a step that
   limped to the floor is not filed as one that cleared it.

It does NOT narrow the rate window. That is BACKLOG #1420's fix (a), a separate item, and the ledger
records that taking it first ships a silent green: it zeroes wall #3 while the SLO still reports
`ok=true`.
"""

from __future__ import annotations

import asyncio
import time

import pytest

from harness.load.connscale.probe import ProcSample
from harness.load.connscale.runner import (
    _MIN_IN_HOLD_SAMPLES,
    ProcReading,
    _probe_loop,
    _sample_loop,
)
from harness.load.enginepoll import EngineSample

pytestmark = pytest.mark.timeout(30)

#: The CI cell's cadence, so the timings here are the ones the shipped smoke actually runs at
#: (`tests/test_connscale_smoke.py`: `poll_interval_s = 0.25`, `hold_seconds = 1.5`).
_INTERVAL_S = 0.25
_HOLD_S = 1.5


def _engine_sample(elapsed: float) -> EngineSample:
    """A minimal engine reading. Only `elapsed_s` matters here -- this module counts and spaces
    readings, it does not derive anything from their counters."""
    return EngineSample(
        elapsed_s=elapsed,
        pending=0,
        inflight=0,
        done=0,
        dead=0,
        read=0,
        written=0,
        out_dead=0,
        queue_depth=0,
        in_pipeline=0,
        db_size_bytes=0,
        journal_mode="wal",
        synchronous="normal",
        uptime_s=elapsed,
    )


class _FakePoller:
    """A poller that answers instantly, so the loop's own cadence is the only thing under test.

    `answers` is the sequence of verdicts: True hands back a reading, False hands back `None` (the
    shape a transient poll failure takes). The last verdict repeats forever."""

    def __init__(self, answers: tuple[bool, ...] = (True,)) -> None:
        self._answers = answers
        self.calls = 0
        self.origin = time.perf_counter()

    async def sample_once(self) -> EngineSample | None:
        verdict = self._answers[min(self.calls, len(self._answers) - 1)]
        self.calls += 1
        return _engine_sample(time.perf_counter() - self.origin) if verdict else None


class _SlowSampler:
    """A stand-in for the OS probe at the cost the real one was MEASURED at: one front-load walk of
    `cost_s` blocking a worker thread, exactly as `FdSampler.sample_proc` does."""

    def __init__(self, cost_s: float) -> None:
        self.cost_s = cost_s
        self.calls = 0

    def sample_proc(self) -> ProcSample:
        self.calls += 1
        time.sleep(self.cost_s)
        return ProcSample(handles=61, cpu_seconds=1.0, working_set_bytes=6_000_000)


async def _hold(stop: asyncio.Event, seconds: float) -> None:
    """Stand in for the step's hold: run for `seconds`, then stop the sampler."""
    await asyncio.sleep(seconds)
    stop.set()


async def _run_sampler(
    poller: _FakePoller, *, hold_s: float, interval: float = _INTERVAL_S
) -> tuple[list[EngineSample], int]:
    """Drive `_sample_loop` for one simulated hold. Returns the in-hold readings and the number of
    make-up ticks the floor had to spend.

    THE ONE LINE THAT MOVED FOR THE RED RUN. Against unmodified code this called
    `_sample_loop(poller, None, interval, stop, out)` -- the old parameter list, with the OS probe on
    the poll's tick. Every assertion below is the same in both arms."""
    stop = asyncio.Event()
    out: list[EngineSample] = []
    floor_ticks, _ = await asyncio.gather(
        _sample_loop(poller, interval, stop, out),  # type: ignore[arg-type]
        _hold(stop, hold_s),
    )
    return out, floor_ticks


async def test_a_hold_too_short_for_a_second_tick_still_yields_two_readings() -> None:
    """THE FLOOR, at its hardest case: a hold that ends before the sampler's first interval does.

    This is the item's own shape, with the hold shortened so the arithmetic is unambiguous rather than
    dependent on the host: one reading fits, a second cannot, and the floor must supply it anyway."""
    poller = _FakePoller()
    samples, floor_ticks = await _run_sampler(poller, hold_s=0.05)
    assert len(samples) >= _MIN_IN_HOLD_SAMPLES, (
        f"the hold produced {len(samples)} in-hold reading(s), not {_MIN_IN_HOLD_SAMPLES}. A window "
        f"needs two endpoints; with one, `_empty_claim_rates` reaches two only by counting the "
        f"post-drain final, and BACKLOG #1420's fix (a) cannot be built at all (BACKLOG #1430)."
    )
    # THE PROVENANCE, asserted on the arm that must produce it. A hold this short cannot reach the
    # floor unaided, so the count of make-up ticks has to be non-zero -- otherwise the field would
    # report "cleared it comfortably" about a step that did not, which is the reading it exists to
    # prevent.
    assert floor_ticks >= 1, (
        f"the floor supplied a reading and reported {floor_ticks} make-up tick(s), so a starved step "
        f"files as a healthy one"
    )


async def test_the_floors_own_readings_are_spaced_by_the_poll_interval() -> None:
    """THE SPACING. A floor that fires its make-up readings back to back satisfies the count and
    destroys what the count was for: the span between them goes to nearly zero, and Δcounters over
    that span is a fabricated rate rather than the honest zeros the guards return today."""
    poller = _FakePoller()
    samples, _ = await _run_sampler(poller, hold_s=0.05)
    span = samples[1].elapsed_s - samples[0].elapsed_s
    # A generous floor on the wait: this asserts the interval was WAITED, not its precision.
    assert span >= _INTERVAL_S * 0.5, (
        f"the first two readings are {span:.4f}s apart against a {_INTERVAL_S}s interval -- the floor "
        f"fired them back to back, so the window it created spans nearly nothing"
    )


async def test_a_probe_costing_multiples_of_the_interval_no_longer_starves_the_sampler() -> None:
    """THE DECOUPLING, aimed at the MEASURED cause rather than at the symptom.

    The probe cost here is the top of the measured front-load range (1.47 s), and the hold is the CI
    cell's 1.5 s. On the shared tick that combination yields exactly one reading. On separate tasks the
    engine samples at its own cadence while the walk blocks a worker thread, so the hold produces the
    handful of readings the interval affords -- and the probe still gets its reading, because wall #4
    must not be traded away for wall #3."""
    poller = _FakePoller()
    sampler = _SlowSampler(cost_s=1.47)
    stop = asyncio.Event()
    samples: list[EngineSample] = []
    readings: list[ProcReading] = []
    await asyncio.gather(
        _sample_loop(poller, _INTERVAL_S, stop, samples),  # type: ignore[arg-type]
        _probe_loop(sampler, _INTERVAL_S, stop, readings, time.perf_counter()),  # type: ignore[arg-type]
        _hold(stop, _HOLD_S),
    )
    # 1.5s of hold at a 0.25s interval affords 5 whole intervals; require most of them so the
    # assertion cannot pass on a host that merely limped to the floor.
    assert len(samples) >= 4, (
        f"a {sampler.cost_s}s probe left the {_HOLD_S}s hold with {len(samples)} engine reading(s). "
        f"The probe is back on the poll's tick, which is the defect BACKLOG #1430 measured."
    )
    assert sampler.calls >= 1 and len(readings) >= 1, (
        f"the OS probe read {len(readings)} time(s) over the hold -- decoupling it must not cost "
        f"wall #4 its reading (probe calls: {sampler.calls})"
    )


async def test_a_poller_that_never_answers_cannot_hold_the_step_open() -> None:
    """THE BOUND. The floor counts ATTEMPTS past the stop, not readings, so an engine that has stopped
    answering ends the step with an honest short window instead of spinning inside it."""
    poller = _FakePoller(answers=(False,))
    started = time.perf_counter()
    samples, _ = await _run_sampler(poller, hold_s=0.05)
    elapsed = time.perf_counter() - started
    assert samples == []
    # At most `_MIN_IN_HOLD_SAMPLES` make-up ticks of one interval each, plus the hold itself.
    assert elapsed < 0.05 + _INTERVAL_S * (_MIN_IN_HOLD_SAMPLES + 2), (
        f"the sampler stayed in its floor for {elapsed:.2f}s against a dead poller -- the make-up "
        f"ticks are unbounded"
    )


async def test_a_hold_with_room_to_spare_is_not_extended_by_the_floor() -> None:
    """THE CONTROL. The floor must be a floor, not a tax: a hold that already affords several readings
    must stop when it is told to. Without this arm, a loop that always ran two extra ticks would pass
    every assertion above."""
    poller = _FakePoller()
    started = time.perf_counter()
    samples, floor_ticks = await _run_sampler(poller, hold_s=_HOLD_S)
    elapsed = time.perf_counter() - started
    assert len(samples) >= 4, len(samples)
    assert floor_ticks == 0, (
        f"a hold that met the floor unaided reported {floor_ticks} make-up tick(s) -- the field "
        f"cannot separate a starved step from a healthy one if it fires on both"
    )
    assert elapsed < _HOLD_S + _INTERVAL_S * 2, (
        f"a {_HOLD_S}s hold that already met the floor took {elapsed:.2f}s to stop -- the make-up "
        f"ticks are running when they are not needed"
    )
