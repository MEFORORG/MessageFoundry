# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Sender + governor driven against the real correlation sink on loopback (no engine).

The sink doubles as the peer here: it ACKs each frame (so the sender records ACK latency) *and*
records the arrival end-to-end. So a clean run has ``sent == acked == matched`` with both histograms
populated — exercising the full send→ACK→correlate path, rate shaping, closed-loop concurrency, and
graceful stop, without standing up an engine.
"""

from __future__ import annotations

import asyncio

from harness.load.corpus import build_corpus
from harness.load.correlator import Correlator
from harness.load.governor import RateGovernor
from harness.load.ids import ControlIds
from harness.load.metrics import Counters, Histogram, LiveMetrics
from harness.load.profile import Target, load_profile_text
from harness.load.sender import ConnectionPool, Dispatcher
from harness.load.sink import CorrelationSink

_IDS = ControlIds(prefix="LS", width=12)

_PROFILE_TMPL = """
[load]
name = "sender-test"
corpus_count_per_trigger = 3
[[load.target]]
name = "hub"
types = ["ADT"]
[load.mix]
"ADT^A05" = 1.0
[[load.phase]]
name = "run"
kind = "sustained"
loop = "{loop}"
rate_start = {rate}
duration_s = {dur}
{conc_line}
"""


def _profile(loop: str, *, rate: float = 0.0, conc: int = 1, dur: float = 0.4) -> object:
    # concurrency is only valid (and required) on closed-loop phases; the open loop is rate-shaped.
    conc_line = f"concurrency = {conc}" if loop == "closed" else ""
    return load_profile_text(
        _PROFILE_TMPL.format(loop=loop, rate=rate, dur=dur, conc_line=conc_line)
    )


async def _harness(loop: str, *, rate: float = 0.0, conc: int = 1, dur: float = 0.4):  # type: ignore[no-untyped-def]
    m = LiveMetrics(Counters(), Histogram(), Histogram())
    correlator = Correlator(capacity=100_000, metrics=m)

    sink = CorrelationSink(_IDS, correlator, m, host="127.0.0.1", ports=(0,))
    await sink.start()
    port = sink.bound_ports[0]

    profile = _profile(loop, rate=rate, conc=conc, dur=dur)
    corpus = build_corpus(profile, _IDS)  # type: ignore[arg-type]
    target = Target(name="hub", host="127.0.0.1", port=port, types=("ADT",))
    pool = ConnectionPool(target, 4, correlator, m)
    dispatcher = Dispatcher([(target, pool)], seed="t")
    dispatcher.start()

    governor = RateGovernor(corpus, dispatcher, m.counters)
    stop = asyncio.Event()
    await governor.run_phase(profile.phases[0], profile.default_mix, stop)  # type: ignore[attr-defined]

    await dispatcher.stop(grace=2.0)
    # Allow any final ACKs/arrivals to settle before reading counters.
    await asyncio.sleep(0.1)
    await sink.stop()
    return m.counters, m.ack, m.e2e, correlator


def test_open_loop_sends_acks_and_correlates() -> None:
    counters, ack_hist, e2e_hist, correlator = asyncio.run(_harness("open", rate=300.0, dur=0.4))
    assert counters.sent > 0
    assert counters.acked == counters.sent  # the sink AA's everything
    assert counters.nak == 0
    assert (
        correlator.matched == counters.sent
    )  # every send timed end-to-end (1:1 loopback, no fan-out)
    assert ack_hist.count == counters.sent and e2e_hist.count == counters.sent
    assert counters.correlation_misses == 0


def test_open_loop_rate_is_roughly_honored() -> None:
    rate, dur = 300.0, 0.5
    counters, *_ = asyncio.run(_harness("open", rate=rate, dur=dur))
    expected = rate * dur
    # Generous band: timing on a busy CI box is imprecise, but it shouldn't be wildly off.
    assert 0.4 * expected < counters.sent < 1.8 * expected, (counters.sent, expected)


def test_closed_loop_delivers_without_loss() -> None:
    counters, ack_hist, e2e_hist, correlator = asyncio.run(_harness("closed", conc=8, dur=0.4))
    assert counters.sent > 0
    assert counters.acked == counters.sent
    assert correlator.matched == counters.sent
    assert counters.deferred == 0  # closed loop self-limits; it never defers


def test_dispatcher_routes_only_accepting_targets() -> None:
    m = LiveMetrics(Counters(), Histogram(), Histogram())
    correlator = Correlator(capacity=8, metrics=m)
    adt = Target(name="adt", host="127.0.0.1", port=1, types=("ADT",))
    oru = Target(name="oru", host="127.0.0.1", port=2, types=("ORU",))
    pool_a = ConnectionPool(adt, 1, correlator, m)
    pool_o = ConnectionPool(oru, 1, correlator, m)
    disp = Dispatcher([(adt, pool_a), (oru, pool_o)], seed="t")
    # Routing selection only — no real connections started.
    assert disp.route("ADT") is pool_a
    assert disp.route("ORU") is pool_o
    assert disp.route("SIU") is None  # nothing accepts it


def test_dispatcher_never_routes_to_zero_weight_target() -> None:
    m = LiveMetrics(Counters(), Histogram(), Histogram())
    correlator = Correlator(capacity=8, metrics=m)
    zero = Target(name="zero", host="127.0.0.1", port=1, types=("ADT",), weight=0.0)
    real = Target(name="real", host="127.0.0.1", port=2, types=("ADT",), weight=3.0)
    pool_zero = ConnectionPool(zero, 1, correlator, m)
    pool_real = ConnectionPool(real, 1, correlator, m)
    disp = Dispatcher([(zero, pool_zero), (real, pool_real)], seed="t")
    # A weight-0 target must never be selected while a positive-weight sibling is eligible.
    assert all(disp.route("ADT") is pool_real for _ in range(200))
