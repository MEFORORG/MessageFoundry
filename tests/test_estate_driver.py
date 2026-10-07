# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Estate driver (#216) — the EVENT-calibrated weights make every connection emit the SAME event rate.

The load-bearing check is on EVENTS, not messages: the driver must weight each connection's message
rate by its served fan-out so a hub (more events per message) is driven SLOWER than a simple feed. A
uniform driver (the connscale round-robin) would give hubs and simples equal msg/s, so hubs would
over-contribute events and the total would silently overshoot — exactly the miscalibration these tests
must FAIL on.
"""

from __future__ import annotations

import asyncio
import math
from typing import Never

import pytest

from harness.config.estate._shape import events_per_msg, hub_flags
from harness.load.corpus import build_corpus
from harness.load.correlator import Correlator
from harness.load.estate import driver as estate_driver
from harness.load.estate.driver import EstateDriver
from harness.load.ids import ControlIds
from harness.load.metrics import Counters, Histogram, LiveMetrics
from harness.load.profile import LoadProfile, Phase, TypeMix

_MIX = TypeMix({"ADT^A01": 1.0})


def _driver_with_fakes(
    *, count: int, simple_fraction: float, hub_fanout: int, per_conn_event_rate: float
) -> tuple[EstateDriver, list[int], tuple[bool, ...]]:
    """A driver whose N PersistentConnections are replaced by fakes that just record each submission's
    count, so we can assert the event-weighted spread without a real engine/socket."""
    metrics = LiveMetrics(Counters(), Histogram(), Histogram())
    correlator = Correlator(1_000_000, metrics)
    flags = hub_flags(count, simple_fraction)
    driver = EstateDriver(
        host="127.0.0.1",
        base_port=2600,
        hub_flags=flags,
        hub_fanout=hub_fanout,
        per_conn_event_rate=per_conn_event_rate,
        correlator=correlator,
        metrics=metrics,
    )

    sent_per_conn = [0] * count

    class _FakeConn:
        def __init__(self, idx: int) -> None:
            self._idx = idx

        def submit_nowait(self, out, on_done=None):
            sent_per_conn[self._idx] += 1
            return True

    driver._conns = [_FakeConn(i) for i in range(count)]  # type: ignore[misc]  # a duck-typed fake
    return driver, sent_per_conn, flags


def _build_corpus():
    ids = ControlIds(prefix="ES")
    return build_corpus(
        LoadProfile(
            name="c",
            description="",
            targets=(),
            phases=(
                Phase(name="h", kind="sustained", loop="open", duration_s=1.0, rate_start=1.0),
            ),
            default_mix=_MIX,
            corpus_count_per_trigger=5,
        ),
        ids,
    )


class _VirtualTimer:
    """Stand-in for the driver module's ``asyncio``: a clock the test owns, ticking at ``quantum``.

    WHY THE CALIBRATION RUNS ON IT. This test divided the events the driver offered by the WALL-CLOCK
    seconds ``asyncio.run`` took, so the denominator carried event-loop setup and teardown, the
    overshoot past the hold, and every stall the runner imposed -- while the numerator stopped at the
    driver's last tick before the hold ended. On a loaded windows-2022 merge-queue runner on
    2026-10-07 that read 8753 events/s against the 10000 target, and it failed 14 of 40 runs locally
    under 16 CPU hogs, at 8055-8944. Nothing in that gap is calibration: the weights decide how many
    events each MESSAGE carries, and the token bucket decides how many messages each SECOND of the
    driver's own clock is owed. So the driver keeps its real token bucket and runs on this clock
    instead, and "per second" means per second of the schedule it was handed.

    ``run_hold`` reads exactly ``get_running_loop().time()`` and ``sleep()`` through the module; any
    other attribute it reads that way fails loud here. (A name bound at import time, such as
    ``from asyncio import sleep``, would bypass this swap altogether -- the two-sided clock check in
    the test is what notices that.) ``sleep`` advances by whole ``quantum`` ticks and at least one, as
    a coarse OS timer returns late and never early, so the bucket emits in catch-up BATCHES rather
    than one send per tick. The batches stay far under ``_BATCH_CAP``, so the stall branch that
    counts ``deferred`` is not exercised here.
    """

    def __init__(self, quantum: float) -> None:
        self.now = 0.0
        self._quantum = quantum

    def get_running_loop(self) -> _VirtualTimer:
        return self

    def time(self) -> float:
        return self.now

    async def sleep(self, delay: float) -> None:
        self.now += max(1, math.ceil(delay / self._quantum)) * self._quantum

    def __getattr__(self, name: str) -> Never:
        raise AttributeError(
            f"the estate driver read asyncio.{name}, which _VirtualTimer does not model; widen the "
            f"stand-in only if run_hold's clock genuinely changed"
        )


#: How far the realized event rate may sit from the spec target. On the test's own clock the only
#: error left is where the last tick lands in the final quantum (half of one 1/64 s tick either way
#: over a 2 s hold, 0.4%), so 2% is room, not slack. It is what lets (c) see a mis-scaled driver at all: against the old wall-clock
#: band of 10%, an aggregate rate 5% low, 5% high or 8% high passed, and a UNIFORM driver --
#: 10.08% over the target here -- passed or failed (c) by the width of one runner's stall.
_EVENT_RATE_REL = 0.02


# A 1 ms timer, and Windows' default 1/64 s tick. At this test's 4300 msg/s the finer one emits a
# handful per tick and the coarser one batches of about 67, and the calibration must hold under both.
@pytest.mark.parametrize("quantum", [0.001, 1 / 64], ids=["1ms", "win-default"])
def test_event_calibration_holds_the_target_event_rate(
    monkeypatch: pytest.MonkeyPatch, quantum: float
) -> None:
    # A scaled-up per-connection EVENT budget (the ratios/identity are magnitude-independent) so the
    # hold banks enough sends for statistics.
    count, simple_fraction, hub_fanout, budget = 100, 0.72, 3, 100.0
    driver, sent, flags = _driver_with_fakes(
        count=count,
        simple_fraction=simple_fraction,
        hub_fanout=hub_fanout,
        per_conn_event_rate=budget,
    )
    corpus = _build_corpus()
    # Seconds of the DRIVER'S clock, so a longer hold costs no wall time and shrinks the part-tick.
    hold = 2.0
    clock = _VirtualTimer(quantum)
    monkeypatch.setattr(estate_driver, "asyncio", clock)

    async def drive() -> None:
        await driver.run_hold(corpus=corpus, mix=_MIX, hold_seconds=hold)

    asyncio.run(drive())
    # The seam is live, from both sides: a correct driver stops on the first tick at or past the hold.
    # One that read its clock anywhere else would leave this clock at zero (it never ran on it) or
    # carry it far past the hold (it slept on it while timing itself on the wall clock) -- either way
    # this test would quietly be back on the runner's wall clock.
    assert hold <= clock.now < hold + 2 * quantum, (clock.now, hold, quantum)
    # The bucket emits for every due instant up to its LAST tick before the hold, which lands
    # somewhere in the final quantum; take the middle of it, so the at-most-one-tick error sits
    # evenly either side of the band instead of all on the low side.
    elapsed = hold - quantum / 2

    total_msgs = sum(sent)
    assert total_msgs > 500, total_msgs  # enough samples for the assertions to mean something

    simple_idx = [i for i, f in enumerate(flags) if not f]
    hub_idx = [i for i, f in enumerate(flags) if f]

    # (a) Within each class the per-connection MESSAGE rate is uniform (round-robin → max-min <= 1).
    simple_counts = [sent[i] for i in simple_idx]
    hub_counts = [sent[i] for i in hub_idx]
    assert max(simple_counts) - min(simple_counts) <= 1, simple_counts
    assert max(hub_counts) - min(hub_counts) <= 1, hub_counts

    # (b) The per-class MESSAGE split matches each class's target share (a UNIFORM driver would give
    # every connection equal msg/s → simple share would be 72/100, not the event-weighted 0.837).
    simple_msgs = sum(simple_counts)
    #   msg_rate_simple = budget/2, msg_rate_hub = budget/(1+F); shares ∝ those × class size.
    r_simple = budget / 2
    r_hub = budget / (1 + hub_fanout)
    agg_simple = r_simple * len(simple_idx)
    agg_hub = r_hub * len(hub_idx)
    expected_simple_share = agg_simple / (agg_simple + agg_hub)
    realized_simple_share = simple_msgs / total_msgs
    assert realized_simple_share == pytest.approx(expected_simple_share, abs=0.03), (
        realized_simple_share,
        expected_simple_share,
    )

    # (c) THE load-bearing check — realized EVENT rate ≈ the spec target, derived from the GRAPH's
    # fan-out × the driver's ACTUAL submissions, compared to a spec number (budget × count) the driver
    # was NOT handed as an event total (reference-invariance: a check that reads back the driver's own
    # configured rate cannot fail; this one can). events_per_msg here is the graph topology math, not a
    # driver internal read.
    realized_events = sum(sent[i] * events_per_msg(flags[i], hub_fanout) for i in range(count))
    realized_event_rate = realized_events / elapsed
    spec_total_event_rate = (
        budget * count
    )  # = per_conn_event_rate × count, NOT handed to the driver
    assert realized_event_rate == pytest.approx(spec_total_event_rate, rel=_EVENT_RATE_REL), (
        realized_event_rate,
        spec_total_event_rate,
    )

    # (d) …and therefore every connection contributes ≈ the SAME per-connection event rate (the estate
    # invariant): both classes land near ``budget`` events/sec despite very different message rates.
    per_conn_event_rate_realized = realized_event_rate / count
    assert per_conn_event_rate_realized == pytest.approx(budget, rel=_EVENT_RATE_REL)
    # Each class, measured on its own, also lands near the budget (a hub's low msg rate × high fan-out ≈
    # a simple's high msg rate × low fan-out) — this is what a uniform driver would violate.
    simple_ev_rate = sum(simple_counts) * 2 / elapsed / len(simple_idx)
    hub_ev_rate = sum(hub_counts) * (1 + hub_fanout) / elapsed / len(hub_idx)
    assert simple_ev_rate == pytest.approx(budget, rel=_EVENT_RATE_REL)
    assert hub_ev_rate == pytest.approx(budget, rel=_EVENT_RATE_REL)


def test_uniform_message_split_would_fail_the_event_calibration() -> None:
    # Guard the guard: prove the (b) assertion actually DISCRIMINATES. A UNIFORM per-connection message
    # rate (what the connscale round-robin does) yields a simple MESSAGE share of n_simple/count = 0.72,
    # which is NOT the event-weighted target share — so the calibrated driver's realized share must
    # differ from 0.72 by a clear margin (else the test could pass a miscalibrated uniform driver).
    count, simple_fraction, hub_fanout = 100, 0.72, 3
    n_simple = sum(1 for f in hub_flags(count, simple_fraction) if not f)
    uniform_simple_share = n_simple / count  # 0.72 — what a uniform driver would produce
    r_simple, r_hub = 1 / 2, 1 / (1 + hub_fanout)
    calibrated_simple_share = (r_simple * n_simple) / (
        r_simple * n_simple + r_hub * (count - n_simple)
    )
    assert abs(calibrated_simple_share - uniform_simple_share) > 0.08


def test_all_simple_estate_drives_only_simple() -> None:
    # simple_fraction = 1.0 → every connection simple; the driver must still hold the event rate with no
    # hub class (the two-class merge degrades cleanly to one class).
    driver, sent, flags = _driver_with_fakes(
        count=20, simple_fraction=1.0, hub_fanout=3, per_conn_event_rate=50.0
    )
    corpus = _build_corpus()

    async def drive() -> None:
        await driver.run_hold(corpus=corpus, mix=_MIX, hold_seconds=0.3)

    asyncio.run(drive())
    assert all(n > 0 for n in sent), sent
    assert max(sent) - min(sent) <= 1, sent  # uniform across the all-simple estate


def test_open_batches_do_not_raise_and_ports_are_contiguous() -> None:
    metrics = LiveMetrics(Counters(), Histogram(), Histogram())
    correlator = Correlator(1000, metrics)
    driver = EstateDriver(
        host="127.0.0.1",
        base_port=59000,
        hub_flags=(False, False, True, False, True),
        hub_fanout=2,
        per_conn_event_rate=1.0,
        correlator=correlator,
        metrics=metrics,
    )
    assert driver.ports == [59000, 59001, 59002, 59003, 59004]

    async def run() -> None:
        await driver.open(connect_batch=2, batch_pause_s=0.0)
        await asyncio.sleep(0.05)
        await driver.stop(0.1)

    asyncio.run(run())


def test_rejects_empty_and_bad_fanout() -> None:
    metrics = LiveMetrics(Counters(), Histogram(), Histogram())
    correlator = Correlator(1000, metrics)
    with pytest.raises(ValueError, match=">= 1"):
        EstateDriver(
            host="127.0.0.1",
            base_port=2600,
            hub_flags=(),
            hub_fanout=3,
            per_conn_event_rate=1.0,
            correlator=correlator,
            metrics=metrics,
        )
    with pytest.raises(ValueError, match="hub_fanout"):
        EstateDriver(
            host="127.0.0.1",
            base_port=2600,
            hub_flags=(False, True),
            hub_fanout=0,
            per_conn_event_rate=1.0,
            correlator=correlator,
            metrics=metrics,
        )
