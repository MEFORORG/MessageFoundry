# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #1430: the connscale in-hold sampler must produce at least two readings per sweep step.

A window needs two endpoints. `_empty_claim_rates` and `_throughput_rates` each read a first and a
last engine sample, and both return zeros behind a silent `len(samples) < 2` guard. Before this floor
the step's sample list reached two only by counting the post-drain final, so the HOLD itself
contributed one reading: in 20 of 20 cells at hold 1.5 and hold 3.0, measured by the Builder who
filed the item.

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

It does NOT narrow the rate window itself. BACKLOG #1420's fix (a) does that, in `_build_record`,
and it is BUILT: the rates now read `samples[:in_hold_samples]`, which EXCLUDES the post-drain final.
That makes this floor load-bearing for wall #3. Fix (a) could only land after it, because the ledger
measured that taking (a) first ships a silent green: it zeroes wall #3 while the SLO still reports
`ok=true`. `tests/test_connscale_rate_window_description.py` pins the slice.
"""

from __future__ import annotations

import asyncio
import dataclasses
import time

import pytest

from harness.load.connscale import runner
from harness.load.connscale.probe import _PROBE_TIMEOUT_S, ProbeDegraded, ProcSample, _gap
from harness.load.connscale.profile import ConnScaleProfile
from harness.load.connscale.report import ConnScaleRecord, monotonic_lane
from harness.load.connscale.runner import (
    _FD_PROBE_MAKEUP_ATTEMPTS,
    _MIN_IN_HOLD_SAMPLES,
    ProcReading,
    _derive_proc,
    _monotonic_slo,
    _probe_loop,
    _sample_loop,
)
from harness.load.enginepoll import EngineSample
from tests import test_connscale_smoke as smoke
from tests.test_connscale_probe_degradation import _record
from tests.test_connscale_smoke import _assert_fd_probe

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
    shape a transient poll failure takes). The last verdict repeats forever.

    Given the hold's `stop`, it also counts the polls made AFTER the hold ended -- the floor's make-up
    attempts, read off the loop's own behaviour rather than off a stopwatch -- and refuses one past
    `max_calls_after_stop`, so an unbounded floor fails at once instead of spinning to the timeout."""

    def __init__(
        self,
        answers: tuple[bool, ...] = (True,),
        *,
        stop: asyncio.Event | None = None,
        max_calls_after_stop: int | None = None,
    ) -> None:
        self._answers = answers
        self.stop = stop
        self._max_calls_after_stop = max_calls_after_stop
        self.calls = 0
        self.calls_after_stop = 0
        self.origin = time.perf_counter()

    async def sample_once(self) -> EngineSample | None:
        if self.stop is not None and self.stop.is_set():
            self.calls_after_stop += 1
            cap = self._max_calls_after_stop
            assert cap is None or self.calls_after_stop <= cap, (
                f"the sampler polled {self.calls_after_stop} times after the hold ended against a "
                f"bound of {cap} -- the make-up ticks are unbounded"
            )
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
    poller: _FakePoller,
    *,
    hold_s: float,
    interval: float = _INTERVAL_S,
) -> tuple[list[EngineSample], int]:
    """Drive `_sample_loop` for one simulated hold. Returns the in-hold readings and the number of
    make-up ticks the floor had to spend. The hold ends on the poller's own `stop` when it was given
    one, so the poller and the loop can never be watching two different events.

    THE ONE LINE THAT MOVED FOR THE RED RUN. Against unmodified code this called
    `_sample_loop(poller, None, interval, stop, out)` -- the old parameter list, with the OS probe on
    the poll's tick, and every assertion was the same in both arms. The dead-poller and control arms
    were later moved from timing the step to counting its polls; their bounds did not change."""
    stop = poller.stop if poller.stop is not None else asyncio.Event()
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
        f"needs two endpoints; with one, the rate window that BACKLOG #1420's fix (a) cut has no "
        f"span, so wall #3 goes ungraded (BACKLOG #1430)."
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


async def test_a_poller_that_never_answers_cannot_hold_the_step_open(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """THE BOUND. The floor counts ATTEMPTS past the stop, not readings, so an engine that has stopped
    answering ends the step with an honest short window instead of spinning inside it: at most
    `_MIN_IN_HOLD_SAMPLES` make-up ticks, each under one interval.

    COUNTED, NOT TIMED. This arm used to assert the step's elapsed seconds against
    `0.05 + interval * (floor + 2)`, and a loaded windows-2022 merge-queue runner measured 1.21 s
    against that 1.05 s bound on 2026-10-07. Elapsed time is the attempts TIMES what one tick costs on
    that box, and only the first factor is the property. So both halves of the bound are read off the
    loop's own decisions: the poller counts the polls made after the hold ended, and the make-up
    sleeps are recorded as the delays the loop ASKED for, which no runner's speed can move. That is
    also stricter than the stopwatch was: a floor taking one extra attempt fitted inside the old
    1.05 s, and fails here. A make-up tick asking for 2x the interval only grazed it, at 1.05 s."""
    slept: list[float] = []
    real_sleep = asyncio.sleep

    class _RecordingAsyncio:
        """The runner's `asyncio`, with `sleep` -- the make-up tick's only use of it -- recorded."""

        async def sleep(self, delay: float) -> None:
            slept.append(delay)
            await real_sleep(delay)

        def __getattr__(self, name: str) -> object:
            return getattr(asyncio, name)

    monkeypatch.setattr(runner, "asyncio", _RecordingAsyncio())
    poller = _FakePoller(
        answers=(False,), stop=asyncio.Event(), max_calls_after_stop=_MIN_IN_HOLD_SAMPLES
    )
    samples, floor_ticks = await _run_sampler(poller, hold_s=0.05)
    assert samples == []
    assert floor_ticks == poller.calls_after_stop, (
        f"the loop reported {floor_ticks} make-up tick(s) but polled {poller.calls_after_stop} "
        f"time(s) after the hold -- the provenance field miscounts the floor's attempts"
    )
    assert len(slept) == poller.calls_after_stop, (slept, poller.calls_after_stop)
    assert all(0.0 <= delay <= _INTERVAL_S for delay in slept), (
        f"the floor's make-up ticks asked to sleep {slept} against a {_INTERVAL_S}s interval -- each "
        f"must be the REST of one interval, or the bound on attempts no longer bounds the step"
    )


async def test_a_hold_with_room_to_spare_is_not_extended_by_the_floor() -> None:
    """THE CONTROL. The floor must be a floor, not a tax: a hold that already affords several readings
    must stop when it is told to. Without this arm, a loop that always ran two extra ticks would pass
    every assertion above.

    The extra ticks are COUNTED as polls after the hold ended, for the reason the dead-poller arm
    gives: this arm's stopwatch had 0.5 s of headroom, less than a loaded runner was measured to add
    to that arm on 2026-10-07."""
    poller = _FakePoller(stop=asyncio.Event(), max_calls_after_stop=0)
    samples, floor_ticks = await _run_sampler(poller, hold_s=_HOLD_S)
    assert len(samples) >= 4, len(samples)
    assert floor_ticks == 0, (
        f"a hold that met the floor unaided reported {floor_ticks} make-up tick(s) -- the field "
        f"cannot separate a starved step from a healthy one if it fires on both"
    )
    assert poller.calls_after_stop == 0, (
        f"a {_HOLD_S}s hold that already met the floor polled {poller.calls_after_stop} more time(s) "
        f"after it ended -- the make-up ticks are running when they are not needed"
    )


# --- BACKLOG #1488: the OS probe's make-up floor ------------------------------------------------------
#
# The failing windows-2022 merge-queue run of 2026-11-19 recorded `1/1 ('walk_timeout',)` on all four
# steps: one probe attempt per step, and that attempt spent the walk's whole 5 s budget against a 1.5 s
# hold. The stand-ins below keep that SHAPE at test scale. Their first attempt costs longer than the
# hold, so the window holds exactly one reading, and what that reading is decides the arm.

#: How long the stand-in's slow attempt blocks its worker thread. Longer than `_STARVED_HOLD_S`, which is
#: the whole point: it is the walk that outlasts the window.
_SLOW_ATTEMPT_S = 0.15
_STARVED_HOLD_S = 0.05


def _measured(handles: int) -> ProcSample:
    """A reading that measured, naming the PID it summed as the runner's real probe does (#1210)."""
    return ProcSample(handles, 1.0, 6_000_000, frozenset({4100}), None, frozenset({4100}))


class _ScriptedSampler:
    """An `FdSampler` stand-in that answers from a script of `(cost_s, sample)` entries, the last one
    repeating. It counts the calls made after the window's `stop`, which are the floor's make-up
    attempts read off the loop's own behaviour rather than off a stopwatch, and refuses one past
    `_FD_PROBE_MAKEUP_ATTEMPTS`, so an unbounded floor fails at once instead of spinning to the
    timeout, as `_FakePoller` does for the engine sampler."""

    def __init__(self, script: list[tuple[float, ProcSample]], stop: asyncio.Event) -> None:
        self._script = script
        self._stop = stop
        self.calls = 0
        self.calls_after_stop = 0

    def sample_proc(self) -> ProcSample:
        if self._stop.is_set():
            self.calls_after_stop += 1
            assert self.calls_after_stop <= _FD_PROBE_MAKEUP_ATTEMPTS, (
                f"the probe was called {self.calls_after_stop} times after its stop against a bound "
                f"of {_FD_PROBE_MAKEUP_ATTEMPTS} -- the make-up floor is unbounded"
            )
        cost, sample = self._script[min(self.calls, len(self._script) - 1)]
        self.calls += 1
        time.sleep(cost)
        return sample


async def _hold_from_first_call(sampler: _ScriptedSampler, stop: asyncio.Event) -> None:
    """End the window `_STARVED_HOLD_S` after the first probe call STARTS, not after the loop does.

    The sampler reads `stop` on its worker thread, so a hold timed from the loop's start could end
    before a late-scheduled thread made the in-window call, and that call would count as a make-up
    one. Timing the hold from the call's own start removes that race on a loaded runner."""
    while not sampler.calls:
        await asyncio.sleep(0.005)
    await _hold(stop, _STARVED_HOLD_S)


async def _probe_step(script: list[tuple[float, ProcSample]]) -> tuple[list[ProcReading], int]:
    """Drive `_probe_loop` for one simulated step. Returns its readings and the make-up attempts it
    reported, after checking that number against the sampler's own count."""
    stop = asyncio.Event()
    sampler = _ScriptedSampler(script, stop)
    readings: list[ProcReading] = []
    floor_ticks, _ = await asyncio.gather(
        _probe_loop(sampler, _INTERVAL_S, stop, readings, time.perf_counter()),  # type: ignore[arg-type]
        _hold_from_first_call(sampler, stop),
    )
    assert floor_ticks == sampler.calls_after_stop, (
        f"the loop reported {floor_ticks} make-up attempt(s) but probed {sampler.calls_after_stop} "
        f"time(s) after its stop -- the provenance field miscounts the floor"
    )
    return readings, floor_ticks


def _step_record(readings: list[ProcReading], *, count: int, floor_ticks: int) -> ConnScaleRecord:
    """The wall #4 half of a record, derived from the probe's readings the way `_build_record` does."""
    proc = _derive_proc(readings)
    return dataclasses.replace(
        _record(count=count),
        fd_count_peak=proc.handles_peak,
        fd_count_peak_pids=proc.handles_peak_pids,
        fd_probe_ticks=proc.probe_ticks,
        fd_probe_degraded_ticks=proc.probe_degraded_ticks,
        fd_probe_degraded=proc.probe_degraded,
        fd_probe_floor_ticks=floor_ticks,
    )


async def test_a_window_whose_only_reading_spent_its_budget_gets_a_makeup_reading() -> None:
    """THE FLOOR, at the failing run's shape: the one in-window attempt is a spent budget, and the
    step still ends with a measured reading because the floor took one more."""
    readings, floor_ticks = await _probe_step(
        [(_SLOW_ATTEMPT_S, _gap(ProbeDegraded.WALK_TIMEOUT)), (0.0, _measured(140))]
    )
    assert floor_ticks == 1, floor_ticks
    assert [r.proc.handles for r in readings] == [None, 140], readings


async def test_the_floor_is_bounded_and_a_probe_that_never_measures_still_fails_wall_four() -> None:
    """THE BOUND, and the requirement the floor must not buy its way past. A probe that spends its
    budget on every attempt ends after `_FD_PROBE_MAKEUP_ATTEMPTS` make-up attempts, and a run built
    from such steps still fails WALL #4 NEVER COMPARED: the floor gives the probe another draw, it does
    not turn a run that never measured into a pass."""
    records = []
    for count in (12, 24):
        readings, floor_ticks = await _probe_step(
            [
                (_SLOW_ATTEMPT_S, _gap(ProbeDegraded.WALK_TIMEOUT)),
                (0.0, _gap(ProbeDegraded.WALK_TIMEOUT)),
            ]
        )
        assert floor_ticks == _FD_PROBE_MAKEUP_ATTEMPTS, floor_ticks
        assert all(r.proc.handles is None for r in readings), readings
        records.append(_step_record(readings, count=count, floor_ticks=floor_ticks))
    with pytest.raises(AssertionError, match="WALL #4 NEVER COMPARED") as e:
        _assert_fd_probe(records)
    assert f"floor={_FD_PROBE_MAKEUP_ATTEMPTS}" in str(e.value)


async def test_a_gap_that_did_not_spend_its_budget_gets_no_makeup_and_still_fails() -> None:
    """A gap from any other cause means the probe RAN and produced nothing usable. The floor must not
    retry it, or a broken probe would get a second chance to hide behind a later reading."""
    readings, floor_ticks = await _probe_step(
        [(_SLOW_ATTEMPT_S, _gap(ProbeDegraded.WALK_EMPTY)), (0.0, _measured(140))]
    )
    assert floor_ticks == 0, floor_ticks
    broken = _step_record(readings, count=12, floor_ticks=floor_ticks)
    with pytest.raises(AssertionError, match="PROBE DEFECT"):
        _assert_fd_probe([broken, _record(count=24, fd=150)])


async def test_a_window_that_measured_is_not_extended_by_the_floor() -> None:
    """THE CONTROL. Without it, a loop that always probed once more past its stop would pass every
    arm above."""
    _, floor_ticks = await _probe_step([(0.0, _measured(140))])
    assert floor_ticks == 0, floor_ticks


async def test_a_collapse_measured_on_makeup_readings_still_fails_the_fd_slo() -> None:
    """A make-up reading is a real reading, so it must be able to fail the SLO it now feeds. Both steps
    of one lane measure only on their make-up attempt, and the FD count collapses from 1000 to 100
    across N: the pair is compared, and `fd_count_monotonic` must go red."""
    records = []
    for count, handles in ((12, 1000), (24, 100)):
        readings, floor_ticks = await _probe_step(
            [(_SLOW_ATTEMPT_S, _gap(ProbeDegraded.WALK_TIMEOUT)), (0.0, _measured(handles))]
        )
        assert floor_ticks == 1, floor_ticks
        records.append(_step_record(readings, count=count, floor_ticks=floor_ticks))
    assert monotonic_lane(records[0]) == monotonic_lane(records[1])
    _assert_fd_probe(records)  # a comparable pair exists, so the run-level bound is met
    check = _monotonic_slo("fd_count_monotonic", records, lambda r: r.fd_count_peak)
    assert not check.ok, check.observed


#: The smoke fixture's setup time on the failing job (135856508516), from pytest's slowest-durations
#: line. A measurement, not a contract.
_SMOKE_SETUP_MEASURED_S = 53.41


def test_the_makeup_floor_fits_inside_the_smokes_watchdog() -> None:
    """Pins the arithmetic in the comment on `_FD_PROBE_MAKEUP_ATTEMPTS`, reading the smoke's own
    watchdog and step axes, so a longer sweep or a shorter timeout fails here rather than in a killed
    worker."""
    (watchdog_s,) = smoke.pytestmark.args
    profile = smoke._smoke_profile(30000)  # any valid port: only the axes are read
    assert isinstance(profile, ConnScaleProfile)
    steps = (
        len(profile.counts)
        * (2 if profile.sweep_mode == "both" else 1)
        * len(profile.claim_modes)
        * len(profile.fuse_modes)
        * len(profile.batch_modes)
        * len(profile.sandbox_modes)
        * profile.trials
    )
    # A walk just inside its budget, then a read that spends all of it.
    attempt_s = 2 * _PROBE_TIMEOUT_S
    # The in-window attempt can exceed the walk timeouts the measured run spent by one more budget.
    worst_s = _SMOKE_SETUP_MEASURED_S + steps * (
        _PROBE_TIMEOUT_S + _FD_PROBE_MAKEUP_ATTEMPTS * attempt_s
    )
    assert worst_s < watchdog_s, (
        f"{steps} smoke steps x {_FD_PROBE_MAKEUP_ATTEMPTS} make-up attempt(s) put the worst case at "
        f"{worst_s:.0f}s against the smoke's {watchdog_s}s watchdog"
    )


def test_an_empty_window_is_not_a_timed_out_one() -> None:
    """A window that took no reading at all did not time out, so `fd_probe_floor_ticks` must not say
    it did."""
    assert not runner._only_budget_gaps([])
    assert runner._only_budget_gaps([ProcReading(0.0, _gap(ProbeDegraded.READ_TIMEOUT))])
