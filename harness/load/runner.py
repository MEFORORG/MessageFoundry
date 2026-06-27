# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""The load runner — wires the sink, sender pool, governor, and engine poller into one run.

Orchestration: start the correlation sink → preflight the engine (reachable + target inbounds exist)
→ run each phase through the rate governor (per-phase latency histograms, counter snapshots at the
boundaries) → stop offering and measure engine-side drain → reconcile and build the report. Cleanup
(sink/pool/poller) runs in a ``finally`` so an error or interrupt still tears down cleanly.
"""

from __future__ import annotations

import asyncio
import contextlib
import time

from messagefoundry.console.client import ApiError

from harness.load.corpus import build_corpus
from harness.load.correlator import Correlator
from harness.load.enginepoll import EnginePoller
from harness.load.governor import RateGovernor
from harness.load.ids import ControlIds
from harness.load.metrics import Counters, Histogram, LiveMetrics
from harness.load.profile import LoadProfile
from harness.load.report import PhaseRecord, RunReport, build_report
from harness.load.sender import ConnectionPool, Dispatcher
from harness.load.sink import CorrelationSink

_STOP_GRACE = 5.0
_SETTLE = 0.25  # let final ACKs/arrivals settle before the final engine sample


class PreflightError(RuntimeError):
    """The engine isn't reachable, or it isn't serving the profile's target inbound ports."""


async def run_load(
    profile: LoadProfile,
    *,
    engine_url: str,
    id_prefix: str,
    token: str | None = None,
    sink_host: str = "127.0.0.1",
    sink_port: int = 2700,
    sink_ports: int = 1,
    db_backend: str | None = None,
) -> RunReport:
    ids = ControlIds(prefix=id_prefix)
    # Generate + parse the corpus off the event loop (hl7apy validation is slow) before anything runs.
    corpus = await asyncio.to_thread(build_corpus, profile, ids)

    metrics = LiveMetrics(Counters(), Histogram(), Histogram())
    correlator = Correlator(profile.correlator_capacity, metrics)

    sink = CorrelationSink(
        ids,
        correlator,
        metrics,
        host=sink_host,
        ports=tuple(sink_port + i for i in range(sink_ports)),
    )
    poller = EnginePoller(engine_url, token, origin=time.perf_counter())
    pools = [
        (t, ConnectionPool(t, profile.pool_size, correlator, metrics)) for t in profile.targets
    ]
    dispatcher = Dispatcher(pools, seed=profile.seed)

    poll_stop = asyncio.Event()
    poll_task: asyncio.Task[None] | None = None
    try:
        await sink.start()
        await poller.open()
        await _preflight(poller, profile)  # raises PreflightError if unreachable / ports missing

        dispatcher.start()
        poll_task = asyncio.create_task(poller.run(profile.poll_interval_s, poll_stop))

        governor = RateGovernor(corpus, dispatcher, metrics.counters)
        records = await _run_phases(profile, metrics, governor)

        # Stop offering; let the engine drain its backlog. Swap in a throwaway histogram first so the
        # drain tail (high-latency backlog deliveries) doesn't pollute the last measured phase.
        metrics.ack = Histogram()
        metrics.e2e = Histogram()
        poll_stop.set()
        if poll_task is not None:
            with contextlib.suppress(asyncio.CancelledError):
                await poll_task
            poll_task = None
        drain_seconds = await poller.await_drain(
            timeout=profile.drain_timeout_s, interval=profile.poll_interval_s
        )

        await dispatcher.stop(_STOP_GRACE)
        await asyncio.sleep(_SETTLE)
        await poller.sample_once()  # truly-final engine state for reconciliation
        return build_report(
            profile,
            engine_url,
            records,
            metrics.counters,
            poller,
            drain_seconds,
            db_backend=db_backend,
        )
    finally:
        poll_stop.set()
        if poll_task is not None:
            poll_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await poll_task
        with contextlib.suppress(Exception):
            await dispatcher.stop(_STOP_GRACE)
        with contextlib.suppress(Exception):
            await sink.stop()
        with contextlib.suppress(Exception):
            await poller.close()


async def _run_phases(
    profile: LoadProfile, metrics: LiveMetrics, governor: RateGovernor
) -> list[PhaseRecord]:
    records: list[PhaseRecord] = []
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for phase in profile.phases:
        start_counters = metrics.counters.snapshot()
        # Fresh per-phase histograms so warmup/ramp/spike don't pollute the steady-state SLO check.
        metrics.ack = Histogram()
        metrics.e2e = Histogram()
        ack_hist, e2e_hist = metrics.ack, metrics.e2e
        t0 = loop.time()
        await governor.run_phase(phase, profile.mix_for(phase), stop)
        wall = loop.time() - t0
        records.append(
            PhaseRecord(
                phase, start_counters, metrics.counters.snapshot(), ack_hist, e2e_hist, wall
            )
        )
    return records


async def _preflight(poller: EnginePoller, profile: LoadProfile) -> None:
    sample = await poller.sample_once()  # establishes the baseline + proves reachability
    if sample is None:
        raise PreflightError(
            "engine is not reachable for metrics — check --engine and that the engine is running"
        )
    ports = await asyncio.to_thread(_engine_ports, poller)
    missing = sorted({t.port for t in profile.targets} - ports)
    if missing:
        raise PreflightError(
            f"engine is not serving inbound port(s) {missing} — did you serve harness/config/load "
            f"(with matching MEFOR_LOAD_*_PORT)? engine ports seen: {sorted(ports)}"
        )


def _engine_ports(poller: EnginePoller) -> set[int]:
    client = poller.client
    if client is None:
        return set()
    try:
        return {r.port for r in client.connections() if r.port}
    except ApiError:
        return set()
