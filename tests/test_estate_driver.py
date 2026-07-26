# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Estate driver (#216) — the EVENT-calibrated weights make every connection emit the SAME event rate.

The load-bearing check is on EVENTS, not messages: the driver must weight each connection's message
rate by its served fan-out so a hub (more events per message) is driven SLOWER than a simple feed. A
uniform driver (the connscale round-robin) would give hubs and simples equal msg/s, so hubs would
over-contribute events and the total would silently overshoot — exactly the miscalibration these tests
must FAIL on.
"""

from __future__ import annotations

import asyncio
import time

import pytest

from harness.config.estate._shape import events_per_msg, hub_flags
from harness.load.corpus import build_corpus
from harness.load.correlator import Correlator
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

        def submit_nowait(self, out, on_done=None):  # type: ignore[no-untyped-def]
            sent_per_conn[self._idx] += 1
            return True

    driver._conns = [_FakeConn(i) for i in range(count)]  # type: ignore[assignment]
    return driver, sent_per_conn, flags


def _build_corpus():  # type: ignore[no-untyped-def]
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


def test_event_calibration_holds_the_target_event_rate() -> None:
    # A scaled-up per-connection EVENT budget (the ratios/identity are magnitude-independent) so a short
    # hold banks enough sends for statistics.
    count, simple_fraction, hub_fanout, budget = 100, 0.72, 3, 100.0
    driver, sent, flags = _driver_with_fakes(
        count=count,
        simple_fraction=simple_fraction,
        hub_fanout=hub_fanout,
        per_conn_event_rate=budget,
    )
    corpus = _build_corpus()
    hold = 0.5

    async def drive() -> None:
        await driver.run_hold(corpus=corpus, mix=_MIX, hold_seconds=hold)

    t0 = time.perf_counter()
    asyncio.run(drive())
    elapsed = time.perf_counter() - t0

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
    assert realized_event_rate == pytest.approx(spec_total_event_rate, rel=0.10), (
        realized_event_rate,
        spec_total_event_rate,
    )

    # (d) …and therefore every connection contributes ≈ the SAME per-connection event rate (the estate
    # invariant): both classes land near ``budget`` events/sec despite very different message rates.
    per_conn_event_rate_realized = realized_event_rate / count
    assert per_conn_event_rate_realized == pytest.approx(budget, rel=0.10)
    # Each class, measured on its own, also lands near the budget (a hub's low msg rate × high fan-out ≈
    # a simple's high msg rate × low fan-out) — this is what a uniform driver would violate.
    simple_ev_rate = sum(simple_counts) * 2 / elapsed / len(simple_idx)
    hub_ev_rate = sum(hub_counts) * (1 + hub_fanout) / elapsed / len(hub_idx)
    assert simple_ev_rate == pytest.approx(budget, rel=0.12)
    assert hub_ev_rate == pytest.approx(budget, rel=0.12)


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
