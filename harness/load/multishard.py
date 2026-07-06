# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""The multi-ENGINE store-contention orchestrator (WS-B) — N ``serve`` engines, ONE shared store.

Where :mod:`harness.load.connscale.runner` sweeps CONNECTION count against a SINGLE owned engine, this
sweeps ENGINE-PROCESS count against ONE shared store, to answer the pre-1500-connection gate: *does one
unified server DB hold when N engine processes commit concurrently, or is the shared store the aggregate
ceiling at some N\\*?*

This is emphatically **not** ``serve --shard`` / ``supervise`` (ADR 0037 L3): that gives each shard its
OWN db file plus SHARED outbounds — the inverse of what this measures. Here every engine points at the
**same** ``MEFOR_STORE_*`` store, with **disjoint** inbound/sink/API ports AND **disjoint connection
names** (a per-engine ``MEFOR_CONNSCALE_NAME_PREFIX``), so the N engines contend on the store's
write/commit path while their FIFO lanes stay isolated (a same-named lane across engines would share
rows — cross-engine claim/steal — confounding the measurement AND a correctness hazard).

Everything is reused from the single-engine connscale step, fanned N-wide:

* :class:`~harness.load.failover.EngineNode` — one owned ``serve`` subprocess per engine (looped N times
  with a per-engine env window: disjoint ports + name prefix ``E{k}``, the SHARED store env, no
  ``[cluster]`` = all active, the three insecure-test escapes).
* :class:`~harness.load.connscale.driver.ConnScaleDriver` — one per engine (its own N persistent MLLP
  conns + token bucket), all sharing ONE :class:`~harness.load.correlator.Correlator` +
  :class:`~harness.load.metrics.LiveMetrics` so the aggregate no-loss reconcile spans every engine.
* :class:`~harness.load.sink.CorrelationSink` — ONE sink over the UNION of every engine's sink ports.
* :class:`~harness.load.enginepoll.EnginePoller` — ONE poller over ALL engine URLs (it already SUMS
  read/written/backlog/in_pipeline and ``await_drain`` already requires EVERY url to reach
  ``in_pipeline == 0``), the aggregate throughput + zero-loss backbone.

The orchestrator prints ISO-8601 timestamps at hold-start and drain-complete so a server-box operator
can bracket the store's wait-stat delta (``sys.dm_os_wait_stats`` / file-IO stalls) to exactly the
steady-state window. Metrics + metadata only — never message bodies or control-id lists (PHI rule).
"""

from __future__ import annotations

import asyncio
import contextlib
import os
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from harness.load.connscale.driver import ConnScaleDriver
from harness.load.connscale.report import NoLoss
from harness.load.connscale.runner import (
    ConnScaleError,
    _await_node_healthy,
    _build_corpus,
    _node_env,
    _reconcile,
)
from harness.load.correlator import Correlator
from harness.load.enginepoll import EngineSample, EnginePoller, sample_until_reconciled
from harness.load.failover import EngineNode, _await_port
from harness.load.ids import ControlIds
from harness.load.metrics import Counters, Histogram, LiveMetrics
from harness.load.profile import TypeMix

_CONFIG_DIR = "harness/config/connscale"
_STOP_GRACE = 5.0
_SETTLE = 0.5  # let final ACKs/arrivals settle before the truly-final aggregate sample
_HEALTH_TIMEOUT = 30.0
_PORTS_READY_TIMEOUT = 60.0
_CONNECT_BATCH = 50
_CONNECT_BATCH_PAUSE_S = 0.05
_POLL_INTERVAL_S = 1.0
_DRAIN_TIMEOUT_S = 120.0
_CORRELATOR_CAPACITY = 5_000_000  # generous ring for N engines' aggregate stream
_CORPUS_COUNT_PER_TRIGGER = 20
_SEED = "messagefoundry-multishard"
# One trivial ADT type — the connscale graph routes every message identically (the wall is the store,
# not message-type spread).
_MIX = TypeMix({"ADT^A01": 1.0})


# --- the aggregate record ----------------------------------------------------


@dataclass(frozen=True)
class EngineAttribution:
    """One engine's own view of ITS lanes at drain — the disjoint-isolation proof. On a shared store,
    if same-index lanes across engines had collided (identical names), an engine could claim/deliver a
    peer's rows; a clean run has every inbound row this engine reports carrying THIS engine's name tag
    (``E{k}``) with a positive read count and nothing else."""

    node_id: str
    name_tag: str  # the per-engine connection-name tag (e.g. "E0")
    inbound_rows: int  # number of inbound (source) connection rows this engine reports
    foreign_rows: int  # inbound rows whose name does NOT carry this engine's tag (a steal ⇒ > 0)
    reads: int  # Σ inbound read across this engine's own rows


@dataclass(frozen=True)
class MultiShardRecord:
    """One N-engine step: the aggregate store-contention view across the N concurrently-active engines.

    All traffic/throughput numbers are AGGREGATE (summed engine-side ``read``/``written`` deltas over
    the hold, and the shared correlator's counters). ``no_loss`` reconciles the summed engine counters
    against the shared client counters exactly as the single-engine step does — just N-wide."""

    engines: int  # N concurrently-active engine processes this step
    count_per_engine: int  # inbound connections per engine (C)
    per_conn_rate: float  # target msg/s per connection (R)
    offered_aggregate_rate: float  # N * C * R — the total offered rate this step
    cluster_enabled: bool  # the [cluster]-ON comparison arm (PRIMARY sweep is OFF)

    # --- ISO-8601 steady-window brackets (the operator's wait-stat window) ---
    hold_start_iso: str
    drain_complete_iso: str

    # --- aggregate throughput / no-loss ---
    achieved_aggregate_rate: float  # summed engine read-delta ACROSS THE HOLD ONLY (messages/s in)
    delivered_aggregate_rate: (
        float  # summed engine written-delta across the hold only (deliveries/s)
    )
    sent: int
    acked: int
    nak: int
    deferred: int
    no_loss: (
        NoLoss  # zero_loss: read>=sent, sink_received>=written, aggregate backlog+in_pipeline==0
    )
    in_pipeline_peak: int  # aggregate NOT-DONE rows across all engines' stages (headline gauge)
    drain_seconds: float | None

    # --- server-DB pool wait (aggregate — first engine reporting a pool; None on SQLite) ---
    pool_wait_p95_ms: float | None

    # --- ACK-on-receipt latency (across every engine's lanes) ---
    ack_p50_ms: float
    ack_p95_ms: float
    ack_p99_ms: float

    # Unconfirmed sends (in-flight at a connection close with no ACK seen). The reconcile excuses
    # these from the intake bound only up to ~one per connection (engines × count); surfaced here so
    # the tolerance width is visible on a PASSING record too. Default 0 for older artifacts.
    timeouts: int = 0

    # --- per-engine disjoint-lane attribution (the no-cross-engine-steal proof) ---
    per_engine: tuple[EngineAttribution, ...] = ()

    @property
    def any_cross_engine_steal(self) -> bool:
        """True iff ANY engine reported an inbound row not carrying its own name tag — a shared-store
        lane collision (the measurement would be invalid)."""
        return any(e.foreign_rows > 0 for e in self.per_engine)

    def to_json_dict(self) -> dict[str, object]:
        return {
            "engines": self.engines,
            "count_per_engine": self.count_per_engine,
            "per_conn_rate": round(self.per_conn_rate, 4),
            "offered_aggregate_rate": round(self.offered_aggregate_rate, 2),
            "cluster_enabled": self.cluster_enabled,
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
            "pool_wait": {"p95_ms": self.pool_wait_p95_ms},
            "ack_ms": {
                "p50": round(self.ack_p50_ms, 3),
                "p95": round(self.ack_p95_ms, 3),
                "p99": round(self.ack_p99_ms, 3),
            },
            "per_engine": [
                {
                    "node_id": e.node_id,
                    "name_tag": e.name_tag,
                    "inbound_rows": e.inbound_rows,
                    "foreign_rows": e.foreign_rows,
                    "reads": e.reads,
                }
                for e in self.per_engine
            ],
            "cross_engine_steal": self.any_cross_engine_steal,
        }

    def render_console(self) -> str:
        loss = "OK" if self.no_loss.ok else f"LOSS ({self.no_loss.detail})"
        pool = "n/a" if self.pool_wait_p95_ms is None else f"{self.pool_wait_p95_ms:.1f}ms"
        drain = "n/a" if self.drain_seconds is None else f"{self.drain_seconds:.2f}s"
        return (
            f"N={self.engines:<3} C={self.count_per_engine} R={self.per_conn_rate:g} "
            f"cluster={'on' if self.cluster_enabled else 'off'} | "
            f"offered={self.offered_aggregate_rate:.0f}/s "
            f"achieved={self.achieved_aggregate_rate:.0f}/s "
            f"delivered={self.delivered_aggregate_rate:.0f}/s | "
            f"zero_loss={loss} in_pipeline_peak={self.in_pipeline_peak} drain={drain} | "
            f"ack p50/p95/p99={self.ack_p50_ms:.1f}/{self.ack_p95_ms:.1f}/{self.ack_p99_ms:.1f}ms "
            f"pool_wait_p95={pool} deferred={self.deferred} | "
            f"window=[{self.hold_start_iso} .. {self.drain_complete_iso}]"
        )


@dataclass(frozen=True)
class MultiShardReport:
    """The sweep over N (a :class:`MultiShardRecord` per engine count)."""

    store_backend: str
    cluster_enabled: bool
    records: list[MultiShardRecord] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    @property
    def result_ok(self) -> bool:
        """PASS iff every step reconciled zero-loss (the mechanics + isolation held at every N)."""
        return bool(self.records) and all(r.no_loss.ok for r in self.records)

    @property
    def exit_code(self) -> int:
        return 0 if self.result_ok else 1

    def to_json_dict(self) -> dict[str, object]:
        return {
            "schema_version": 1,
            "kind": "multishard",
            "store_backend": self.store_backend,
            "cluster_enabled": self.cluster_enabled,
            "result": "PASS" if self.result_ok else "FAIL",
            "exit_code": self.exit_code,
            "records": [r.to_json_dict() for r in self.records],
            "notes": self.notes,
        }

    def render_console(self) -> str:
        lines = [
            f"Multi-engine store-contention report -- backend {self.store_backend} "
            f"(cluster {'ON' if self.cluster_enabled else 'OFF'})",
            "",
        ]
        for r in self.records:
            lines.append(r.render_console())
        for note in self.notes:
            lines.append(f"note: {note}")
        lines.append("")
        lines.append(f"RESULT: {'PASS' if self.result_ok else 'FAIL'} -> exit {self.exit_code}")
        return "\n".join(lines)


# --- the orchestrator --------------------------------------------------------


async def run_multishard(
    *,
    engine_counts: Sequence[int],
    count_per_engine: int,
    per_conn_rate: float,
    hold_seconds: float,
    inbound_base: int = 20000,
    sink_base: int = 40000,
    stride: int = 200,
    api_base: int = 9000,
    engine_index_base: int = 0,
    store_backend: str = "sqlite",
    cluster_enabled: bool = False,
    sink_host: str = "127.0.0.1",
    base_env: Mapping[str, str] | None = None,
    cwd: Path | None = None,
    db_path: str | None = None,
    install_executor_shim: bool = False,
    drain_timeout_s: float = _DRAIN_TIMEOUT_S,
) -> MultiShardReport:
    """Run the N-engine store-contention sweep and return a :class:`MultiShardReport`.

    ``base_env`` supplies the SHARED store connection (``MEFOR_STORE_*``) and defaults to the process
    env. ``db_path`` (SQLite only) forces every engine's ``MEFOR_STORE_PATH`` at the SAME file so they
    genuinely share one store; on a server backend the shared connection comes from ``MEFOR_STORE_*``.
    ``drain_timeout_s`` bounds the post-hold drain + settled reconcile (a short value keeps the CI smoke
    inside its per-test budget; the bench uses the long default).

    ``engine_index_base`` offsets the per-engine lane index — engine ``k`` is tagged
    ``E{k + engine_index_base}`` (name prefix, node id, attribution) — so a SECOND concurrent
    orchestrator process can drive DISJOINT lanes on the SAME store. This is the WS-B de-confound
    instrument: one orchestrator process has a measured ~457 msg/s single-process ACK ceiling, so a
    high-aggregate multi-engine run must be split across >=2 processes (each under the ceiling, each
    with its own disjoint ``--inbound-base``/``--sink-base``/``--api-base`` port bands) — validated
    2026-07-02 as `deconf-engine-index-base.patch` (foreign_rows == 0 held across both halves)."""
    base_env = dict(os.environ if base_env is None else base_env)
    cwd = cwd or Path.cwd()
    records: list[MultiShardRecord] = []
    notes: list[str] = []
    for engines in engine_counts:
        record = await _run_one_step(
            engines=engines,
            count_per_engine=count_per_engine,
            per_conn_rate=per_conn_rate,
            hold_seconds=hold_seconds,
            inbound_base=inbound_base,
            sink_base=sink_base,
            stride=stride,
            api_base=api_base,
            engine_index_base=engine_index_base,
            store_backend=store_backend,
            cluster_enabled=cluster_enabled,
            sink_host=sink_host,
            base_env=base_env,
            cwd=cwd,
            db_path=db_path,
            install_executor_shim=install_executor_shim,
            drain_timeout_s=drain_timeout_s,
        )
        records.append(record)
    return MultiShardReport(
        store_backend=store_backend,
        cluster_enabled=cluster_enabled,
        records=records,
        notes=notes,
    )


async def _run_one_step(
    *,
    engines: int,
    count_per_engine: int,
    per_conn_rate: float,
    hold_seconds: float,
    inbound_base: int,
    sink_base: int,
    stride: int,
    api_base: int,
    engine_index_base: int,
    store_backend: str,
    cluster_enabled: bool,
    sink_host: str,
    base_env: Mapping[str, str],
    cwd: Path,
    db_path: str | None,
    install_executor_shim: bool,
    drain_timeout_s: float,
) -> MultiShardRecord:
    if engines < 1:
        raise ConnScaleError(f"engine count must be >= 1, got {engines}")
    if count_per_engine < 1:
        raise ConnScaleError(f"count per engine must be >= 1, got {count_per_engine}")
    _check_port_layout(engines, count_per_engine, inbound_base, sink_base, stride, api_base)

    # ONE run-scoped control-id prefix shared by every engine's driver (pid + monotonic ns) so a re-run
    # against a reused server DB can't collide with a prior run's seqs, AND so the ONE sink can recover
    # every engine's seqs against a single id scheme.
    prefix = f"MS{os.getpid():x}{time.perf_counter_ns():x}"[:16]
    ids = ControlIds(prefix=prefix)
    corpus = await asyncio.to_thread(_build_ms_corpus, ids)
    metrics = LiveMetrics(Counters(), Histogram(), Histogram())
    correlator = Correlator(_CORRELATOR_CAPACITY, metrics)

    # Per-engine port windows (stride keeps the inbound and sink blocks non-overlapping across engines).
    inbound_bases = [inbound_base + stride * k for k in range(engines)]
    sink_bases = [sink_base + stride * k for k in range(engines)]
    api_ports = [api_base + k for k in range(engines)]
    # The ONE sink absorbs the UNION of every engine's single sink port (sink_ports=1 per engine here).
    all_sink_ports = tuple(sink_bases)

    from harness.load.sink import CorrelationSink

    sink = CorrelationSink(ids, correlator, metrics, host=sink_host, ports=all_sink_ports)

    nodes: list[EngineNode] = []
    drivers: list[ConnScaleDriver] = []
    for k in range(engines):
        env = _node_env(
            base_env,
            count=count_per_engine,
            base_port=inbound_bases[k],
            transform="cheap",
            sink_host=sink_host,
            sink_port=sink_bases[k],
            sink_ports=1,
            install_executor_shim=install_executor_shim,
            db_path=db_path,  # SAME file for every engine ⇒ one shared SQLite store
            # DISJOINT connection names ⇒ disjoint FIFO lanes on the shared store. The index base
            # keeps DISJOINTNESS ACROSS ORCHESTRATOR PROCESSES too (the split-driver de-confound).
            name_prefix=f"E{k + engine_index_base}",
        )
        env = _apply_cluster_env(
            env, cluster_enabled=cluster_enabled, node_id=f"ms-e{k + engine_index_base}"
        )
        nodes.append(
            EngineNode(
                f"ms-e{k + engine_index_base}",
                api_ports[k],
                env=env,
                config_dir=_CONFIG_DIR,
                cwd=cwd,
            )
        )
        drivers.append(
            ConnScaleDriver(
                host=sink_host,
                base_port=inbound_bases[k],
                count=count_per_engine,
                correlator=correlator,
                metrics=metrics,
            )
        )

    poller = EnginePoller([n.url for n in nodes], token=None, origin=time.perf_counter())
    samples: list[EngineSample] = []
    aggregate_rate = per_conn_rate * count_per_engine  # per-engine offered rate
    try:
        await sink.start()
        # Start the engines STRICTLY ONE AT A TIME — start engine k, wait until it is healthy, then
        # start k+1. Two shared-store races force full serialization, not just an engine-0 gate:
        # (1) SQLite: `serve` runs `PRAGMA journal_mode=WAL` + the schema DDL at open, and a
        #     same-instant second opener can hit "database is locked" before WAL exists.
        # (2) SQL Server (WS-B Finding 2, the co-start convoy): EVERY open re-runs the full multi-
        #     round-trip schema DDL batch under the exclusive `mefor:schema_init` applock (no schema-
        #     version fast-path) and then reset_stale_inflight's unindexed status scan — N peers
        #     started simultaneously convoy on the applock + LCK_M_IX/X on the shared tables, and a
        #     loser blows the 30s command timeout and fails startup (observed rc=2 at N>=4, N=16
        #     never started). Serial start+gate removes the convoy for a few seconds per engine —
        #     negligible for a measurement tool, and the steady-state measurement is unaffected.
        for node in nodes:
            await node.start()
            await _await_node_healthy(node, timeout=_HEALTH_TIMEOUT)
        await poller.open()
        await poller.sample_once()  # aggregate baseline

        # Preflight EVERY engine's inbound block (first + last port bound, all N rows reported), so the
        # connect storm is over before the hold.
        for k in range(engines):
            await _await_port(sink_host, inbound_bases[k], timeout=_PORTS_READY_TIMEOUT)
            await _await_port(
                sink_host, inbound_bases[k] + count_per_engine - 1, timeout=_PORTS_READY_TIMEOUT
            )
        # Wait until EVERY engine reports its own C inbound rows. The poller's `client` is the PRIMARY
        # engine only, so the single-engine `_await_inbound_rows` would undercount here — sum each
        # engine's /connections directly.
        await _await_inbound_rows_all(nodes, count_per_engine, timeout=_PORTS_READY_TIMEOUT)

        # Ramp every engine's connections open, then HOLD all N concurrently.
        for driver in drivers:
            await driver.open(connect_batch=_CONNECT_BATCH, batch_pause_s=_CONNECT_BATCH_PAUSE_S)

        sampler_stop = asyncio.Event()
        sample_task = asyncio.create_task(
            _sample_loop(poller, _POLL_INTERVAL_S, sampler_stop, samples)
        )
        # Bracket the hold with explicit samples + a wall clock, so achieved/delivered are computed
        # over EXACTLY the steady-state window. Dividing the baseline→post-drain read-delta by the
        # nominal hold instead (the original metric) inflated the rate wherever intake spilled past
        # the hold — the WS-B N=8 record printed 857/s for a ~230-240/s steady state because the
        # numerator's window was 341s against a 60s divisor (WS_B_REPORT.md, REVISED 2026-07-02).
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

        # Stop offering everywhere; then drain the aggregate pipeline; final reconcile.
        sampler_stop.set()
        with contextlib.suppress(asyncio.CancelledError):
            await sample_task
        # Stop every driver FIRST (flush queued sends + grace in-flight ACKs) BEFORE draining, so all
        # offered messages have reached the engines' ingress stages before await_drain waits for empty
        # (the same intake-gap fix as the single-engine step).
        await asyncio.gather(*(driver.stop(_STOP_GRACE) for driver in drivers))
        drain_seconds = await poller.await_drain(timeout=drain_timeout_s, interval=_POLL_INTERVAL_S)
        await asyncio.sleep(_SETTLE)
        if drain_seconds is not None:
            final = await sample_until_reconciled(
                poller, metrics.counters, timeout=drain_timeout_s, interval=_POLL_INTERVAL_S
            )
        else:
            # Drain timed out — the verdict is determined (backlog != 0 fails the reconcile); a
            # second drain_timeout_s of settle-polling would only delay the honest failure.
            final = await poller.sample_once()
        if final is not None:
            samples.append(final)
        drain_complete_iso = _now_iso()

        # Per-engine disjoint-lane attribution: read EACH engine's OWN /connections and confirm every
        # inbound row it reports carries its own name tag (no cross-engine steal on the shared store).
        per_engine = await _attribute_engines(nodes, engine_index_base)

        return _build_record(
            engines=engines,
            count_per_engine=count_per_engine,
            per_conn_rate=per_conn_rate,
            hold_seconds=hold_seconds,
            cluster_enabled=cluster_enabled,
            metrics=metrics,
            poller=poller,
            samples=samples,
            drain_seconds=drain_seconds,
            hold_start_iso=hold_start_iso,
            drain_complete_iso=drain_complete_iso,
            per_engine=per_engine,
            hold_begin=hold_begin,
            hold_end=hold_end,
            hold_elapsed_s=hold_elapsed_s,
        )
    finally:
        for driver in drivers:
            with contextlib.suppress(Exception):
                await driver.stop(_STOP_GRACE)
        with contextlib.suppress(Exception):
            await sink.stop()
        with contextlib.suppress(Exception):
            await poller.close()
        for node in nodes:
            with contextlib.suppress(Exception):
                await node.stop()


def _build_record(
    *,
    engines: int,
    count_per_engine: int,
    per_conn_rate: float,
    hold_seconds: float,
    cluster_enabled: bool,
    metrics: LiveMetrics,
    poller: EnginePoller,
    samples: list[EngineSample],
    drain_seconds: float | None,
    hold_start_iso: str,
    drain_complete_iso: str,
    per_engine: tuple[EngineAttribution, ...],
    hold_begin: EngineSample | None = None,
    hold_end: EngineSample | None = None,
    hold_elapsed_s: float = 0.0,
) -> MultiShardRecord:
    c = metrics.counters.snapshot()
    base, final = poller.baseline, poller.final
    # Budget = total connection count across every engine (at most ~one stranded in-flight per
    # connection is a plausible teardown artifact; more is a systemic no-ACK fault).
    no_loss = _reconcile(c, base, final, unconfirmed_budget=engines * count_per_engine)
    in_pipeline_peak = max((s.in_pipeline for s in samples), default=0)
    # Aggregate achieved/delivered rate = the read/written delta across EXACTLY the hold window
    # (bracket samples + measured wall time), so the number is a true steady-state rate. The
    # baseline→final delta over the nominal hold (the fallback below, and the original metric) counts
    # intake that spills into the post-hold flush + drain against a 60s divisor — under overload that
    # inflated WS-B's N=8 "achieved" ~3.5x (857/s printed for a ~230-240/s steady state). The
    # fallback only runs when a bracket sample failed (poller API error); its distortion is the known
    # caveat, preferred over reporting 0 for a run that did move traffic.
    if hold_begin is not None and hold_end is not None and hold_elapsed_s > 0:
        read_delta = hold_end.read - hold_begin.read
        written_delta = hold_end.written - hold_begin.written
        achieved = read_delta / hold_elapsed_s
        delivered = written_delta / hold_elapsed_s
    else:
        read_delta = (final.read - base.read) if (base and final) else 0
        written_delta = (final.written - base.written) if (base and final) else 0
        achieved = read_delta / hold_seconds if hold_seconds > 0 else 0.0
        delivered = written_delta / hold_seconds if hold_seconds > 0 else 0.0
    pool_p95 = _peak_float([s.pool_wait_p95_ms for s in samples])
    ack = metrics.ack.summary()
    offered = engines * count_per_engine * per_conn_rate
    return MultiShardRecord(
        engines=engines,
        count_per_engine=count_per_engine,
        per_conn_rate=per_conn_rate,
        offered_aggregate_rate=offered,
        cluster_enabled=cluster_enabled,
        hold_start_iso=hold_start_iso,
        drain_complete_iso=drain_complete_iso,
        achieved_aggregate_rate=max(0.0, achieved),
        delivered_aggregate_rate=max(0.0, delivered),
        sent=c.sent,
        acked=c.acked,
        nak=c.nak,
        deferred=c.deferred,
        timeouts=c.timeouts,
        no_loss=no_loss,
        in_pipeline_peak=in_pipeline_peak,
        drain_seconds=drain_seconds,
        pool_wait_p95_ms=pool_p95,
        ack_p50_ms=ack.p50_ms,
        ack_p95_ms=ack.p95_ms,
        ack_p99_ms=ack.p99_ms,
        per_engine=per_engine,
    )


# --- helpers -----------------------------------------------------------------


async def _await_inbound_rows_all(
    nodes: list[EngineNode], count_per_engine: int, *, timeout: float
) -> None:
    """Wait until EVERY engine reports its own ``count_per_engine`` inbound rows (so the connect storm
    is over before the hold). Each engine has its OWN API + its OWN disjoint lanes, so we read each
    node directly and require all to reach the per-engine count — the aggregate poller's single client
    would only see the primary engine's rows."""
    loop = asyncio.get_running_loop()
    start = loop.time()
    while loop.time() - start < timeout:
        counts = await loop.run_in_executor(None, _inbound_rows_per_node, nodes)
        if all(n >= count_per_engine for n in counts):
            return
        await asyncio.sleep(0.25)
    counts = await loop.run_in_executor(None, _inbound_rows_per_node, nodes)
    raise ConnScaleError(
        f"not every engine reported {count_per_engine} inbound connections within {timeout}s "
        f"(last seen per engine: {counts})"
    )


def _inbound_rows_per_node(nodes: list[EngineNode]) -> list[int]:
    from messagefoundry.console.client import ApiError, EngineClient

    counts: list[int] = []
    for node in nodes:
        try:
            client = EngineClient(node.url)
            try:
                rows = client.connections()
            finally:
                client.close()
            counts.append(sum(1 for r in rows if r.read is not None))
        except ApiError:
            counts.append(0)  # transiently unreachable → 0, keep waiting
    return counts


async def _attribute_engines(
    nodes: list[EngineNode], engine_index_base: int = 0
) -> tuple[EngineAttribution, ...]:
    """Read each engine's OWN ``/connections`` (off the event loop) and attribute its inbound rows.

    On the shared store each engine k names its lanes ``IB_E{k+base}_CS_...`` (via
    MEFOR_CONNSCALE_NAME_PREFIX). A row this engine reports whose name does NOT carry its own tag
    would mean a cross-engine steal (a same-named lane shared across engines) — the
    disjoint-isolation the gate requires would be broken. We read per engine (not the aggregate
    poller) precisely to catch that — including a steal from a PEER ORCHESTRATOR PROCESS's engines
    when the run is split across processes with disjoint ``engine_index_base`` ranges."""
    loop = asyncio.get_running_loop()
    return tuple(
        await loop.run_in_executor(None, _attribute_engines_sync, nodes, engine_index_base)
    )


def _attribute_engines_sync(
    nodes: list[EngineNode], engine_index_base: int = 0
) -> list[EngineAttribution]:
    from messagefoundry.console.client import ApiError, EngineClient

    out: list[EngineAttribution] = []
    for k, node in enumerate(nodes):
        tag = f"E{k + engine_index_base}"
        marker = f"_{tag}_"  # e.g. "_E0_" — present in IB_E0_CS_00000, absent in a peer's IB_E1_...
        inbound_rows = 0
        foreign_rows = 0
        reads = 0
        try:
            client = EngineClient(node.url)
            try:
                rows = client.connections()
            finally:
                client.close()
        except ApiError:
            # A node unreachable at attribution time (already torn down / transient) surfaces as an
            # empty attribution — the smoke asserts positive rows, so it won't silently pass.
            out.append(EngineAttribution(node.node_id, tag, 0, 0, 0))
            continue
        for row in rows:
            if row.read is None:  # inbound (source) rows carry a read counter; skip outbound rows
                continue
            inbound_rows += 1
            if marker in row.name:
                reads += row.read
            else:
                foreign_rows += 1
        out.append(EngineAttribution(node.node_id, tag, inbound_rows, foreign_rows, reads))
    return out


def _build_ms_corpus(ids: ControlIds):  # type: ignore[no-untyped-def]
    """A tiny synthetic ADT corpus the drivers replay — reuses the connscale corpus builder via a
    minimal profile shim (one generated type; fresh MSH-10 per send)."""
    from harness.load.connscale.profile import ConnScaleProfile, ConnScaleSlo

    shim = ConnScaleProfile(
        name="multishard-corpus",
        description="",
        counts=(1,),
        per_conn_rate=1.0,
        aggregate_rate=1.0,
        sweep_mode="fixed_per_conn",
        hold_seconds=1.0,
        connect_batch=1,
        connect_batch_pause_s=0.0,
        poll_interval_s=1.0,
        drain_timeout_s=1.0,
        base_port=1,
        transform="cheap",
        reload_probe=False,
        store_backend=None,
        corpus_count_per_trigger=_CORPUS_COUNT_PER_TRIGGER,
        correlator_capacity=_CORRELATOR_CAPACITY,
        seed=_SEED,
        slo=ConnScaleSlo(),
    )
    return _build_corpus(shim, ids)


def _apply_cluster_env(
    env: dict[str, str], *, cluster_enabled: bool, node_id: str
) -> dict[str, str]:
    """The three insecure-test escapes on EVERY engine; ``[cluster]`` OFF (PRIMARY sweep: all N engines
    write simultaneously with disjoint rows) or ON (the lease-protocol comparison arm)."""
    env = dict(env)
    # Loopback API + no auth + the config-source/TLS escapes so `serve --host 127.0.0.1` starts clean.
    env["MEFOR_ALLOW_INSECURE_TLS"] = "1"
    env["MEFOR_ALLOW_INSECURE_CONFIG_SOURCE"] = "1"
    env["MEFOR_AUTH_ENABLED"] = "false"
    if cluster_enabled:
        env["MEFOR_CLUSTER_ENABLED"] = "true"
        env["MEFOR_CLUSTER_NODE_ID"] = node_id
    return env


def _check_port_layout(
    engines: int,
    count_per_engine: int,
    inbound_base: int,
    sink_base: int,
    stride: int,
    api_base: int,
) -> None:
    """Fail loud BEFORE spawning anything if the per-engine port windows would overlap or run off the
    top of the port space. Each engine k occupies inbound [inbound_base+stride*k, +count) and a single
    sink port sink_base+stride*k; stride must exceed the per-engine inbound block."""
    if stride < count_per_engine:
        raise ConnScaleError(
            f"stride {stride} must be >= count_per_engine {count_per_engine} so each engine's inbound "
            f"block [base, base+count) doesn't overlap the next engine's"
        )
    hi_inbound = inbound_base + stride * (engines - 1) + count_per_engine - 1
    hi_sink = sink_base + stride * (engines - 1)
    hi_api = api_base + engines - 1
    for label, hi in (("inbound", hi_inbound), ("sink", hi_sink), ("api", hi_api)):
        if hi > 65535:
            raise ConnScaleError(
                f"{label} port {hi} at N={engines} runs past 65535 — lower the base/stride or N"
            )
    # The inbound blocks and the sink block must not collide (an inbound listener + the sink fighting
    # for one port surfaces as a bind error deep in startup).
    lo_sink = sink_base
    if inbound_base <= hi_sink and lo_sink <= hi_inbound:
        raise ConnScaleError(
            f"inbound port block [{inbound_base}, {hi_inbound}] overlaps the sink block "
            f"[{lo_sink}, {hi_sink}] — move --inbound-base / --sink-base apart"
        )


def _now_iso() -> str:
    """Timezone-aware ISO-8601 (UTC, seconds resolution) — the operator's wait-stat window bracket."""
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


async def _sample_loop(
    poller: EnginePoller, interval: float, stop: asyncio.Event, out: list[EngineSample]
) -> None:
    """Sample the aggregate engine view every ``interval`` until ``stop`` (off the event loop, inside
    the poller). Simpler than the connscale sampler — no FD probe, since the store (not per-process FDs)
    is the wall this campaign reads."""
    while not stop.is_set():
        sample = await poller.sample_once()
        if sample is not None:
            out.append(sample)
        try:
            await asyncio.wait_for(stop.wait(), timeout=interval)
        except (asyncio.TimeoutError, TimeoutError):
            pass


def _peak_float(values: list[float | None]) -> float | None:
    present = [v for v in values if v is not None]
    return max(present) if present else None
