# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""The DRIVER-ONLY connscale tool (WS-C, option #2) — drive + sink physically OFF the engine box.

Where :func:`~harness.load.connscale.runner.run_connscale` OWNS (spawns) the engine subprocess per
step, this drives ALREADY-RUNNING engines reached over the network and **never spawns an engine**. It
is the connscale drive loop with the engine-spawn / store-reset removed and every network collaborator
reused as-is:

* :class:`~harness.load.connscale.driver.ConnScaleDriver` — one per engine band, each owning ``count``
  :class:`~harness.load.sender.PersistentConnection`s dialing ``engine_host:inbound_base + i`` on the
  ENGINE box, all sharing ONE :class:`~harness.load.correlator.Correlator` + :class:`LiveMetrics` so the
  aggregate no-loss reconcile spans every band;
* :class:`~harness.load.sink.CorrelationSink` — bound LOCALLY on the load-gen box (``sink_host``) over
  the UNION of every band's sink ports, so the engines deliver their outbound fan-out back here;
* :class:`~harness.load.enginepoll.EnginePoller` — over the REMOTE engine ``/stats`` URLs, the
  authoritative drain + no-loss backbone (it already SUMS read/written/backlog across the URLs).

**Why this tool exists (the attribution-policy gate).** The achieved-intake/delivered "ceiling" a
batch_ab / connscale A/B reads is only meaningful when the driver + sink are NOT stealing CPU from the
engine, AND when the sink is not itself the delivered-throughput cap: a single co-located sink LISTENER
caps ~135-144/s delivered. So the rig runs the engine(s) on one box and drives from another with the
sink split into **>= 5-6 sink PROCESSES**, each well under the per-listener cap. Genuine sink PROCESSES
(not just multiple listeners in one process) come from launching several ``connscale-remote`` processes,
each owning a DISJOINT band via the multishard ``--engine-index-base`` split — the same de-confound
instrument :func:`~harness.load.multishard.run_multishard` uses to split a high-aggregate run across
processes under the ~457 msg/s single-process ACK ceiling. This module supplies the band math + the
disjointness gate; the rig launches the N processes.

Metadata/counters only — never message bodies or control-id lists (PHI rule).
"""

from __future__ import annotations

import asyncio
import contextlib
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone

from harness.load.connscale.driver import ConnScaleDriver
from harness.load.connscale.report import NoLoss
from harness.load.connscale.runner import ConnScaleError, _reconcile
from harness.load.correlator import Correlator
from harness.load.enginepoll import EngineSample, EnginePoller, sample_until_reconciled
from harness.load.failover import _await_port
from harness.load.ids import ControlIds
from harness.load.metrics import Counters, Histogram, LiveMetrics
from harness.load.multishard import _build_ms_corpus
from harness.load.profile import TypeMix

_STOP_GRACE = 5.0
_SETTLE = 0.5
_POLL_INTERVAL_S = 1.0
_CONNECT_BATCH = 50
_CONNECT_BATCH_PAUSE_S = 0.05
_PORTS_READY_TIMEOUT = 60.0
_CORRELATOR_CAPACITY = 5_000_000
_MIX = TypeMix({"ADT^A01": 1.0})


@dataclass(frozen=True)
class ConnScaleRemoteReport:
    """The driver-only outcome: the aggregate no-loss reconcile (summed REMOTE ``/stats`` vs the shared
    client counters), the achieved intake + delivered rates over the hold, and the sink layout so an
    operator can confirm the >= 5-6-listener attribution gate was actually met."""

    engine_bands: int
    count_per_band: int
    per_conn_rate: float
    offered_aggregate_rate: float
    engine_index_base: int
    sink_host: str
    sink_ports: tuple[int, ...]  # every LOCAL sink listener this process bound (union of the bands)
    hold_start_iso: str
    drain_complete_iso: str
    achieved_aggregate_rate: float
    delivered_aggregate_rate: float
    sent: int
    acked: int
    nak: int
    deferred: int
    timeouts: int
    no_loss: NoLoss
    in_pipeline_peak: int
    drain_seconds: float | None
    notes: list[str] = field(default_factory=list)

    @property
    def result_ok(self) -> bool:
        return self.no_loss.ok

    @property
    def exit_code(self) -> int:
        return 0 if self.result_ok else 1

    def to_json_dict(self) -> dict[str, object]:
        return {
            "schema_version": 1,
            "kind": "connscale_remote",
            "result": "PASS" if self.result_ok else "FAIL",
            "exit_code": self.exit_code,
            "engine_bands": self.engine_bands,
            "count_per_band": self.count_per_band,
            "per_conn_rate": round(self.per_conn_rate, 4),
            "offered_aggregate_rate": round(self.offered_aggregate_rate, 2),
            "engine_index_base": self.engine_index_base,
            "sink": {"host": self.sink_host, "ports": list(self.sink_ports)},
            "window": {
                "hold_start": self.hold_start_iso,
                "drain_complete": self.drain_complete_iso,
            },
            "throughput": {
                "achieved_aggregate_rate": round(self.achieved_aggregate_rate, 2),
                "delivered_aggregate_rate": round(self.delivered_aggregate_rate, 2),
                "in_pipeline_peak": self.in_pipeline_peak,
                "drain_seconds": self.drain_seconds,
            },
            "traffic": {
                "sent": self.sent,
                "acked": self.acked,
                "nak": self.nak,
                "deferred": self.deferred,
                "timeouts": self.timeouts,
            },
            "no_loss": {
                "ok": self.no_loss.ok,
                "sent": self.no_loss.sent,
                "engine_read": self.no_loss.engine_read,
                "engine_written": self.no_loss.engine_written,
                "sink_received": self.no_loss.sink_received,
                "backlog": self.no_loss.backlog,
                "detail": self.no_loss.detail,
            },
            "notes": self.notes,
        }

    def render_console(self) -> str:
        loss = "OK" if self.no_loss.ok else f"LOSS ({self.no_loss.detail})"
        drain = "n/a" if self.drain_seconds is None else f"{self.drain_seconds:.2f}s"
        return "\n".join(
            [
                f"connscale-remote (driver-only) -- {self.engine_bands} engine band(s), "
                f"C={self.count_per_band} R={self.per_conn_rate:g} index_base={self.engine_index_base}",
                f"  sink: {self.sink_host} ports={list(self.sink_ports)} "
                f"({len(self.sink_ports)} local listener process-band)",
                f"  offered={self.offered_aggregate_rate:.0f}/s "
                f"achieved={self.achieved_aggregate_rate:.0f}/s "
                f"delivered={self.delivered_aggregate_rate:.0f}/s",
                f"  zero_loss={loss} in_pipeline_peak={self.in_pipeline_peak} drain={drain} "
                f"deferred={self.deferred} timeouts={self.timeouts}",
                f"  window=[{self.hold_start_iso} .. {self.drain_complete_iso}]",
                f"RESULT: {'PASS' if self.result_ok else 'FAIL'} -> exit {self.exit_code}",
            ]
        )


def check_remote_bands(
    inbound_bases: list[int], sink_bases: list[int], *, count: int, sink_ports: int
) -> tuple[int, ...]:
    """Validate the per-band port layout of ONE ``connscale-remote`` process and return the flat tuple
    of LOCAL sink listener ports (the union of every band's ``[sink_base, sink_base + sink_ports)``).

    Fails loud BEFORE binding anything if any block overlaps or runs off the top of the port space —
    the same guard shape as :func:`~harness.load.multishard._check_port_layout`, so a mis-typed band
    split surfaces as a clear error, not a bind failure deep in startup. Sink bands MUST be disjoint
    (overlapping listeners would double-bind); inbound and sink blocks must not collide."""
    if not inbound_bases or not sink_bases:
        raise ConnScaleError("connscale-remote needs at least one inbound-base and one sink-base")
    if len(inbound_bases) != len(sink_bases):
        raise ConnScaleError(
            f"--inbound-base ({len(inbound_bases)}) and --sink-base ({len(sink_bases)}) must list the "
            f"SAME number of bands (one per engine)"
        )
    if count < 1:
        raise ConnScaleError(f"--count must be >= 1, got {count}")
    if sink_ports < 1:
        raise ConnScaleError(f"--sink-ports must be >= 1, got {sink_ports}")

    inbound_blocks = [(b, b + count - 1) for b in inbound_bases]
    sink_blocks = [(b, b + sink_ports - 1) for b in sink_bases]
    for label, hi in (
        ("inbound", max(hi for _, hi in inbound_blocks)),
        ("sink", max(hi for _, hi in sink_blocks)),
    ):
        if hi > 65535:
            raise ConnScaleError(
                f"{label} port {hi} runs past 65535 — lower the base(s), count, or N"
            )
    _reject_overlaps(inbound_blocks, "inbound")
    _reject_overlaps(sink_blocks, "sink")
    for ilo, ihi in inbound_blocks:
        for slo, shi in sink_blocks:
            if ilo <= shi and slo <= ihi:
                raise ConnScaleError(
                    f"inbound block [{ilo},{ihi}] overlaps sink block [{slo},{shi}] — move the bases apart"
                )
    # Flat union of the sink ports, de-duped defensively (the disjointness check already forbids dups).
    ports: list[int] = []
    for base in sink_bases:
        for j in range(sink_ports):
            ports.append(base + j)
    return tuple(ports)


def _reject_overlaps(blocks: list[tuple[int, int]], label: str) -> None:
    ordered = sorted(blocks)
    for (alo, ahi), (blo, bhi) in zip(ordered, ordered[1:]):
        if blo <= ahi:
            raise ConnScaleError(
                f"{label} bands [{alo},{ahi}] and [{blo},{bhi}] overlap — sink/inbound bands per process "
                f"must be DISJOINT (this is the multishard --engine-index-base split gate)"
            )


async def run_connscale_remote(
    *,
    engine_urls: list[str],
    engine_host: str,
    inbound_bases: list[int],
    sink_host: str,
    sink_bases: list[int],
    sink_ports: int = 1,
    count: int,
    per_conn_rate: float,
    hold_seconds: float,
    drain_timeout: float,
    engine_index_base: int = 0,
    connect_batch: int = _CONNECT_BATCH,
    connect_batch_pause_s: float = _CONNECT_BATCH_PAUSE_S,
) -> ConnScaleRemoteReport:
    """Drive N already-running engine bands from off-box and reconcile no-loss against the REMOTE
    ``/stats``. Reuses the connscale drive collaborators verbatim; spawns nothing.

    ``engine_urls`` (one per band) are the remote ``http://<engine-ip>:<api>`` bases the poller reads.
    ``inbound_bases`` (one per band) is where each band's senders dial ``engine_host:inbound_base + i``.
    ``sink_bases`` (one per band) + ``sink_ports`` are the LOCAL listeners the engines deliver to; they
    are validated disjoint and bound on ``sink_host``. ``engine_index_base`` offsets the run-scoped
    control-id prefix so a SECOND concurrent ``connscale-remote`` process (its own disjoint bands) can't
    collide on ids — the split that yields >= 5-6 sink PROCESSES."""
    n = len(inbound_bases)
    if len(engine_urls) != n:
        raise ConnScaleError(
            f"--engine-url count ({len(engine_urls)}) must equal the number of --inbound-base bands ({n})"
        )
    sink_port_tuple = check_remote_bands(
        inbound_bases, sink_bases, count=count, sink_ports=sink_ports
    )

    # Run-scoped, ASCII-alnum control-id prefix. The index base keeps a concurrent peer process's ids
    # disjoint from this one's (each process has its own correlator/sink, so this is belt-and-braces +
    # makes the attribution/report unambiguous when several processes share the drive).
    prefix = f"CSR{engine_index_base}x{time.perf_counter_ns():x}"[:16]
    ids = ControlIds(prefix=prefix)
    metrics = LiveMetrics(Counters(), Histogram(), Histogram())
    correlator = Correlator(_CORRELATOR_CAPACITY, metrics)
    corpus = await asyncio.to_thread(_build_ms_corpus, ids)

    from harness.load.sink import CorrelationSink

    # ONE sink over the UNION of every band's disjoint listener ports, bound on the load-gen box.
    sink = CorrelationSink(ids, correlator, metrics, host=sink_host, ports=sink_port_tuple)
    # One driver per band, all dialing the ENGINE box's inbound IP (NOT the sink host — decoupled).
    drivers = [
        ConnScaleDriver(
            host=engine_host,
            base_port=inbound_bases[k],
            count=count,
            correlator=correlator,
            metrics=metrics,
        )
        for k in range(n)
    ]
    poller = EnginePoller(engine_urls, token=None, origin=time.perf_counter())
    samples: list[EngineSample] = []
    notes: list[str] = []
    aggregate_rate = per_conn_rate * count  # per band
    try:
        await sink.start()
        await poller.open()
        await poller.sample_once()  # aggregate baseline

        # Preflight EVERY band's inbound block reachable on the ENGINE box before the hold.
        for base in inbound_bases:
            await _await_port(engine_host, base, timeout=_PORTS_READY_TIMEOUT)
            await _await_port(engine_host, base + count - 1, timeout=_PORTS_READY_TIMEOUT)

        for driver in drivers:
            await driver.open(connect_batch=connect_batch, batch_pause_s=connect_batch_pause_s)

        sampler_stop = asyncio.Event()
        sample_task = asyncio.create_task(
            _sample_loop(poller, _POLL_INTERVAL_S, sampler_stop, samples)
        )
        loop = asyncio.get_running_loop()
        hold_begin = await poller.sample_once()
        hold_started = loop.time()
        hold_start_iso = _now_iso()
        hold_tasks = [
            asyncio.create_task(
                driver.run_hold(
                    corpus=corpus,
                    mix=_MIX,
                    aggregate_rate=aggregate_rate,
                    hold_seconds=hold_seconds,
                )
            )
            for driver in drivers
        ]
        await asyncio.gather(*hold_tasks)
        hold_end = await poller.sample_once()
        hold_elapsed_s = loop.time() - hold_started

        sampler_stop.set()
        with contextlib.suppress(asyncio.CancelledError):
            await sample_task
        # Stop the drivers FIRST (flush queued sends + grace in-flight ACKs) BEFORE draining, so all
        # offered messages have reached the engines' ingress before await_drain waits for empty.
        await asyncio.gather(*(driver.stop(_STOP_GRACE) for driver in drivers))
        drain_seconds = await poller.await_drain(timeout=drain_timeout, interval=_POLL_INTERVAL_S)
        await asyncio.sleep(_SETTLE)
        if drain_seconds is not None:
            final = await sample_until_reconciled(
                poller, metrics.counters, timeout=drain_timeout, interval=_POLL_INTERVAL_S
            )
        else:
            final = await poller.sample_once()
        if final is not None:
            samples.append(final)
        drain_complete_iso = _now_iso()

        c = metrics.counters.snapshot()
        base_sample, final_sample = poller.baseline, poller.final
        no_loss = _reconcile(c, base_sample, final_sample, unconfirmed_budget=n * count)
        in_pipeline_peak = max((s.in_pipeline for s in samples), default=0)
        if hold_begin is not None and hold_end is not None and hold_elapsed_s > 0:
            achieved = max(0.0, (hold_end.read - hold_begin.read) / hold_elapsed_s)
            delivered = max(0.0, (hold_end.written - hold_begin.written) / hold_elapsed_s)
        else:
            achieved = delivered = 0.0
            notes.append("achieved/delivered unavailable — a hold-bracket /stats sample failed")
        return ConnScaleRemoteReport(
            engine_bands=n,
            count_per_band=count,
            per_conn_rate=per_conn_rate,
            offered_aggregate_rate=n * count * per_conn_rate,
            engine_index_base=engine_index_base,
            sink_host=sink_host,
            sink_ports=sink_port_tuple,
            hold_start_iso=hold_start_iso,
            drain_complete_iso=drain_complete_iso,
            achieved_aggregate_rate=achieved,
            delivered_aggregate_rate=delivered,
            sent=c.sent,
            acked=c.acked,
            nak=c.nak,
            deferred=c.deferred,
            timeouts=c.timeouts,
            no_loss=no_loss,
            in_pipeline_peak=in_pipeline_peak,
            drain_seconds=drain_seconds,
            notes=notes,
        )
    finally:
        for driver in drivers:
            with contextlib.suppress(Exception):
                await driver.stop(_STOP_GRACE)
        with contextlib.suppress(Exception):
            await sink.stop()
        with contextlib.suppress(Exception):
            await poller.close()


def _now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


async def _sample_loop(
    poller: EnginePoller, interval: float, stop: asyncio.Event, out: list[EngineSample]
) -> None:
    """Sample the aggregate remote engine view every ``interval`` until ``stop`` (off the event loop)."""
    while not stop.is_set():
        sample = await poller.sample_once()
        if sample is not None:
            out.append(sample)
        try:
            await asyncio.wait_for(stop.wait(), timeout=interval)
        except (asyncio.TimeoutError, TimeoutError):
            pass
