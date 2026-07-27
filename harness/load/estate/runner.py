# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""The estate run orchestrator (#216) — drive the calibrated heterogeneous shape, read the achieved one.

Parallels :func:`~harness.load.connscale.runner.run_connscale`, but drives a HETEROGENEOUS estate at an
EVENT-calibrated per-connection rate (via :class:`~harness.load.estate.driver.EstateDriver`) instead of
sweeping connection count at a uniform rate. The harness OWNS the engine subprocess (the
:class:`~harness.load.failover.EngineNode` pattern). It:

1. env-injects ``MEFOR_ESTATE_COUNT`` / ``SIMPLE_FRACTION`` / ``HUB_FANOUT`` (+ base/sink/transform) and
   spawns a fresh engine on ``harness/config/estate``;
2. starts the :class:`~harness.load.sink.CorrelationSink`, opens the :class:`~harness.load.enginepoll.
   EnginePoller`, preflights that the engine serves all N inbound ports + reports all N inbound rows;
3. ramps N :class:`~harness.load.sender.PersistentConnection`s open in batches;
4. HOLDS the calibrated schedule for ``hold_seconds``, sampling the engine + the CPU/FD probe each tick;
5. stops offering, drains, reconciles no-loss, and reports the ACHIEVED event rate + realized shape
   against the spec — the honest-shape readout.

The heavy 1,500-connection run is operator-run on the bench rig; the CI smoke uses a small count on
SQLite. The engine gets a fresh DB per run so residue can't bleed across counts.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import os
import tempfile
import time
from collections.abc import Mapping
from pathlib import Path

from harness.config.estate._shape import hub_flags, simple_count
from harness.load.connscale.probe import FdSampler, ProcSample
from harness.load.corpus import Corpus, build_corpus
from harness.load.correlator import Correlator
from harness.load.enginepoll import EnginePoller, EngineSample, sample_until_reconciled
from harness.load.estate.driver import EstateDriver
from harness.load.estate.profile import EstateProfile
from harness.load.estate.report import (
    EXIT_OK,
    EXIT_SLO_VIOLATION,
    EstateRecord,
    EstateReport,
    NoLoss,
    SloCheck,
)
from harness.load.failover import EngineNode, FailoverError, _await_port
from harness.load.ids import ControlIds
from harness.load.metrics import Counters, Histogram, LiveMetrics
from harness.load.profile import TypeMix
from harness.load.sink import CorrelationSink

log = logging.getLogger(__name__)

_CONFIG_DIR = "harness/config/estate"
_STOP_GRACE = 5.0
_SETTLE = 0.5  # let final ACKs/arrivals settle before the truly-final engine sample
_HEALTH_TIMEOUT = 30.0
_PORTS_READY_TIMEOUT = 60.0  # waiting for the engine to report all N inbound rows (N can be large)
# A single trivial ADT type — every estate feed routes identically; the shape is per-connection fan-out,
# not message-type spread, so the mix only needs to drive ONE generated type.
_MIX = TypeMix({"ADT^A01": 1.0})
# A3: a flat cumulative CPU counter over a non-trivial span is a wrong PID binding, not an idle engine —
# report a gap rather than a fabricated 0.00 (mirrors the connscale runner's guard).
_CPU_FLAT_GAP_SPAN_S = 5.0
_PROC_BY_SAMPLE: dict[int, ProcSample] = {}


class EstateError(RuntimeError):
    """An estate run setup/orchestration failure."""


async def run_estate(
    profile: EstateProfile,
    *,
    engine_api_port: int,
    sink_host: str = "127.0.0.1",
    sink_port: int,
    sink_ports: int = 1,
    base_env: Mapping[str, str] | None = None,
    cwd: Path | None = None,
) -> EstateReport:
    """Run the estate demo-shape drive and return an :class:`EstateReport`. The harness OWNS the engine
    subprocess (EngineNode); ``base_env`` supplies any server-DB connection (``MEFOR_STORE_*``) and
    defaults to the process environment."""
    base_env = dict(os.environ if base_env is None else base_env)
    cwd = cwd or Path.cwd()
    notes: list[str] = []
    records: list[EstateRecord] = []
    try:
        record = await _run_one(
            profile,
            api_port=engine_api_port,
            sink_host=sink_host,
            sink_port=sink_port,
            sink_ports=sink_ports,
            base_env=base_env,
            cwd=cwd,
        )
        records.append(record)
    except (EstateError, FailoverError) as exc:
        raise EstateError(str(exc)) from exc

    slos = _evaluate_slos(profile, records)
    result_ok = all(c.ok for c in slos)
    return EstateReport(
        profile=profile.name,
        engine_url=f"http://{sink_host}:{engine_api_port}",
        db_backend=profile.store_backend,
        records=records,
        slos=slos,
        result_ok=result_ok,
        exit_code=EXIT_OK if result_ok else EXIT_SLO_VIOLATION,
        notes=notes,
    )


async def _run_one(
    profile: EstateProfile,
    *,
    api_port: int,
    sink_host: str,
    sink_port: int,
    sink_ports: int,
    base_env: Mapping[str, str],
    cwd: Path,
) -> EstateRecord:
    prefix = f"ES{os.getpid():x}{time.perf_counter_ns():x}"[:16]
    ids = ControlIds(prefix=prefix)
    corpus = await asyncio.to_thread(_build_corpus, profile, ids)
    metrics = LiveMetrics(Counters(), Histogram(), Histogram())
    correlator = Correlator(profile.correlator_capacity, metrics)
    sink = CorrelationSink(
        ids,
        correlator,
        metrics,
        host=sink_host,
        ports=tuple(sink_port + i for i in range(sink_ports)),
    )
    db_path: str | None = None
    if profile.store_backend is None:
        db_dir = tempfile.mkdtemp(prefix="mefor-estate-")
        db_path = str(Path(db_dir) / "estate.db")
    node = EngineNode(
        f"estate-{profile.count}",
        api_port,
        env=_node_env(
            base_env,
            profile=profile,
            sink_host=sink_host,
            sink_port=sink_port,
            sink_ports=sink_ports,
            db_path=db_path,
        ),
        config_dir=_CONFIG_DIR,
        cwd=cwd,
    )
    poller = EnginePoller(node.url, token=None, origin=time.perf_counter())
    flags = hub_flags(profile.count, profile.simple_fraction)
    driver = EstateDriver(
        host=sink_host,
        base_port=profile.base_port,
        hub_flags=flags,
        hub_fanout=profile.hub_fanout,
        per_conn_event_rate=profile.per_conn_event_rate,
        correlator=correlator,
        metrics=metrics,
    )
    samples: list[EngineSample] = []
    try:
        await sink.start()
        await node.start()
        try:
            await _await_node_healthy(node, timeout=_HEALTH_TIMEOUT)
            await poller.open()
            await poller.sample_once()  # baseline
            await _await_port(sink_host, profile.base_port, timeout=_PORTS_READY_TIMEOUT)
            await _await_port(
                sink_host, profile.base_port + profile.count - 1, timeout=_PORTS_READY_TIMEOUT
            )
            await _await_inbound_rows(poller, profile.count, timeout=_PORTS_READY_TIMEOUT)
        except (EstateError, FailoverError) as exc:
            raise EstateError(_startup_failure_detail(exc, node)) from exc
        pid = node.pid
        fd_sampler = FdSampler(pid) if pid is not None else None

        await driver.open(
            connect_batch=profile.connect_batch, batch_pause_s=profile.connect_batch_pause_s
        )
        sampler_stop = asyncio.Event()
        sample_task = asyncio.create_task(
            _sample_loop(poller, fd_sampler, profile.poll_interval_s, sampler_stop, samples)
        )
        hold_task = asyncio.create_task(
            driver.run_hold(corpus=corpus, mix=_MIX, hold_seconds=profile.hold_seconds)
        )
        await hold_task

        sampler_stop.set()
        with contextlib.suppress(asyncio.CancelledError):
            await sample_task
        # Stop the driver FIRST (flush queued sends + grace in-flight ACKs) BEFORE draining, so all
        # offered messages reach ingress before we wait for the pipeline to empty (the connscale
        # intake-gap fix).
        await driver.stop(_STOP_GRACE)
        drain_seconds = await poller.await_drain(
            timeout=profile.drain_timeout_s, interval=profile.poll_interval_s
        )
        await asyncio.sleep(_SETTLE)
        if drain_seconds is not None:
            final = await sample_until_reconciled(
                poller,
                metrics.counters,
                timeout=profile.drain_timeout_s,
                interval=profile.poll_interval_s,
            )
        else:
            final = await poller.sample_once()
        if final is not None:
            samples.append(final)
        return _build_record(
            profile=profile,
            metrics=metrics,
            poller=poller,
            samples=samples,
            drain_seconds=drain_seconds,
        )
    finally:
        with contextlib.suppress(Exception):
            await driver.stop(_STOP_GRACE)
        with contextlib.suppress(Exception):
            await sink.stop()
        with contextlib.suppress(Exception):
            await poller.close()
        with contextlib.suppress(Exception):
            await node.stop()


def _build_corpus(profile: EstateProfile, ids: ControlIds) -> Corpus:
    from harness.load.profile import LoadProfile, Phase

    shim = LoadProfile(
        name="estate-corpus",
        description="",
        targets=(),
        phases=(Phase(name="hold", kind="sustained", loop="open", duration_s=1.0, rate_start=1.0),),
        default_mix=_MIX,
        corpus_count_per_trigger=profile.corpus_count_per_trigger,
        seed=profile.seed,
    )
    return build_corpus(shim, ids)


def _node_env(
    base: Mapping[str, str],
    *,
    profile: EstateProfile,
    sink_host: str,
    sink_port: int,
    sink_ports: int,
    db_path: str | None,
    inbound_bind_host: str = "127.0.0.1",
) -> dict[str, str]:
    env = dict(base)
    env["MEFOR_SECURITY_REQUIRE_SIGN_IN"] = (
        "false"  # the poller reads /stats without a bearer token
    )
    env["MEFOR_ESTATE_COUNT"] = str(profile.count)
    env["MEFOR_ESTATE_SIMPLE_FRACTION"] = repr(profile.simple_fraction)
    env["MEFOR_ESTATE_HUB_FANOUT"] = str(profile.hub_fanout)
    env["MEFOR_ESTATE_BASE_PORT"] = str(profile.base_port)
    env["MEFOR_ESTATE_TRANSFORM"] = profile.transform
    env["MEFOR_ESTATE_SINK_HOST"] = sink_host
    env["MEFOR_ESTATE_SINK_PORT"] = str(sink_port)
    env["MEFOR_ESTATE_SINK_PORTS"] = str(sink_ports)
    env["MEFOR_INBOUND_BIND_HOST"] = inbound_bind_host
    if db_path is not None:
        env["MEFOR_STORE_PATH"] = db_path
    return env


def _startup_failure_detail(exc: BaseException, node: EngineNode) -> str:
    detail = str(exc)
    tail = node.log_tail()
    if tail and tail not in detail:
        detail = f"{detail}\n{tail}"
    return detail


async def _await_node_healthy(node: EngineNode, *, timeout: float) -> None:
    import httpx

    start = time.perf_counter()
    async with httpx.AsyncClient(timeout=4.0) as client:
        while time.perf_counter() - start < timeout:
            if not node.alive:
                raise EstateError(f"engine exited during startup:\n{node.log_tail()}")
            if await node.healthy(client):
                return
            await asyncio.sleep(0.25)
    raise EstateError(f"engine did not become healthy within {timeout}s:\n{node.log_tail()}")


async def _await_inbound_rows(poller: EnginePoller, count: int, *, timeout: float) -> None:
    loop = asyncio.get_running_loop()
    start = loop.time()
    while loop.time() - start < timeout:
        n = await loop.run_in_executor(None, _count_inbound_rows, poller)
        if n >= count:
            return
        await asyncio.sleep(0.25)
    raise EstateError(
        f"engine never reported all {count} inbound connections within {timeout}s "
        f"(last seen {_count_inbound_rows(poller)})"
    )


def _count_inbound_rows(poller: EnginePoller) -> int:
    client = poller.client
    if client is None:
        return 0
    try:
        return sum(1 for r in client.connections() if r.read is not None)
    except Exception:  # noqa: BLE001 - a transient poll failure → report 0, keep waiting
        return 0


async def _sample_loop(
    poller: EnginePoller,
    fd_sampler: FdSampler | None,
    interval: float,
    stop: asyncio.Event,
    out: list[EngineSample],
) -> None:
    loop = asyncio.get_running_loop()
    while not stop.is_set():
        sample = await poller.sample_once()
        if sample is not None:
            if fd_sampler is not None:
                proc = await loop.run_in_executor(None, fd_sampler.sample_proc)
                _PROC_BY_SAMPLE[id(sample)] = proc
            out.append(sample)
        with contextlib.suppress(TimeoutError):
            await asyncio.wait_for(stop.wait(), timeout=interval)


def _build_record(
    *,
    profile: EstateProfile,
    metrics: LiveMetrics,
    poller: EnginePoller,
    samples: list[EngineSample],
    drain_seconds: float | None,
) -> EstateRecord:
    c = metrics.counters.snapshot()
    base, final = poller.baseline, poller.final
    no_loss = _reconcile(c, base, final, unconfirmed_budget=profile.count)
    in_pipeline_peak = max((s.in_pipeline for s in samples), default=0)
    read_per_s, written_per_s = _throughput_rates(samples)
    # Achieved EVENT rate = in + out over the hold window (the calibration target's own units).
    achieved_total_ev = read_per_s + written_per_s
    achieved_per_conn_ev = achieved_total_ev / profile.count if profile.count else 0.0
    # Drain the per-sample OS-probe side map ONCE (each id(sample) can only be popped once), then derive
    # both the CPU denominator and the FD/RSS peaks from the same readings.
    readings = _collect_proc(samples)
    cpu_total, cpu_mean, span = _cpu_from(readings)
    # CPU-microseconds per pipeline event over the SAME window: the honest headroom denominator (in+out
    # events, not messages). None when either the CPU probe or the event count is unavailable/zero.
    total_events_in_span = (achieved_total_ev * span) if span > 0.0 else 0.0
    cpu_us_per_event: float | None = None
    if cpu_total is not None and total_events_in_span > 0.0:
        cpu_us_per_event = (cpu_total / total_events_in_span) * 1_000_000.0
    fd_peak, ws_peak = _fd_ws_from(readings)
    ack = metrics.ack.summary()

    n_simple = simple_count(profile.count, profile.simple_fraction)
    return EstateRecord(
        count=profile.count,
        simple_count=n_simple,
        hub_count=profile.count - n_simple,
        hub_fanout=profile.hub_fanout,
        target_total_event_rate=profile.total_event_rate,
        target_per_conn_event_rate=profile.per_conn_event_rate,
        achieved_written_per_s=written_per_s,
        achieved_read_per_s=read_per_s,
        achieved_total_event_rate=achieved_total_ev,
        achieved_per_conn_event_rate=achieved_per_conn_ev,
        sent=c.sent,
        acked=c.acked,
        nak=c.nak,
        deferred=c.deferred,
        timeouts=c.timeouts,
        no_loss=no_loss,
        in_pipeline_peak=in_pipeline_peak,
        drain_seconds=drain_seconds,
        ack_p50_ms=ack.p50_ms,
        ack_p95_ms=ack.p95_ms,
        ack_p99_ms=ack.p99_ms,
        cpu_seconds_total=cpu_total,
        cpu_util_cores_mean=cpu_mean,
        cpu_us_per_event=cpu_us_per_event,
        working_set_peak_bytes=ws_peak,
        fd_count_peak=fd_peak,
    )


def _reconcile(
    c: Counters,
    base: EngineSample | None,
    final: EngineSample | None,
    *,
    unconfirmed_budget: int,
) -> NoLoss:
    sent = c.sent
    sink_received = c.sink_received
    if base is None or final is None:
        return NoLoss(
            False,
            sent,
            0,
            0,
            sink_received,
            -1,
            "engine metrics unavailable — cannot verify no-loss",
        )
    read = final.read - base.read
    written = final.written - base.written
    backlog = final.backlog
    # An unconfirmed send (in-flight at a connection close, no ACK seen) is bounded-excused; past the
    # budget it is a systemic no-ACK fault. The bound is a FRACTION of the run (at most half), floored
    # by the connection count — NOT "~one per connection", a model this sender breaks because
    # `_inflight` is an unbounded deque. Mirrors the connscale/report reconciles; see report.py.
    unconfirmed = c.timeouts
    budget = max(unconfirmed_budget, sent // 2)
    over_budget = unconfirmed > budget
    excused = 0 if over_budget else unconfirmed
    read_short = sent - excused - read
    deliver_short = written - sink_received
    drained = backlog == 0
    ok = read_short <= 0 and deliver_short <= 0 and drained and not over_budget
    parts: list[str] = []
    if read_short > 0:
        parts.append(
            f"engine_read {read} < confirmed sent {sent - excused} (lost {read_short} on intake)"
        )
    if deliver_short > 0:
        parts.append(
            f"sink_received {sink_received} < engine_written {written} (lost {deliver_short})"
        )
    if not drained:
        parts.append(f"backlog {backlog} not drained")
    if over_budget:
        parts.append(
            f"{unconfirmed} unconfirmed sends exceed the stranding budget "
            f"({budget} = max(connections, half the run)) — systemic no-ACK fault"
        )
    detail = "; ".join(parts) if parts else "read>=sent, sink_received>=written, backlog drained"
    return NoLoss(ok, sent, read, written, sink_received, backlog, detail)


def _throughput_rates(samples: list[EngineSample]) -> tuple[float, float]:
    """Achieved (read/s, written/s) over the hold window, first→last sample."""
    if len(samples) < 2:
        return 0.0, 0.0
    first, last = samples[0], samples[-1]
    span = last.elapsed_s - first.elapsed_s
    if span <= 0.0:
        return 0.0, 0.0
    read = (last.read - first.read) / span
    written = (last.written - first.written) / span
    return max(0.0, read), max(0.0, written)


def _collect_proc(samples: list[EngineSample]) -> list[tuple[float, ProcSample]]:
    """Drain the per-sample :class:`ProcSample` side map ONCE (each ``id(sample)`` is popped a single
    time), pairing each reading with its sample's elapsed time. Both the CPU and FD/RSS derivations run
    off this one list, so neither steals the other's readings."""
    readings: list[tuple[float, ProcSample]] = []
    for s in samples:
        proc = _PROC_BY_SAMPLE.pop(id(s), None)
        if proc is not None:
            readings.append((s.elapsed_s, proc))
    return readings


def _cpu_from(readings: list[tuple[float, ProcSample]]) -> tuple[float | None, float | None, float]:
    """Total CPU-seconds + mean cores-busy over the window, summed piecewise over same-PID-set intervals
    (BACKLOG #220 / A3). Returns ``(cpu_total, cpu_mean, covered_span_s)``; CPU fields ``None`` on a gap
    or a flat-counter wrong binding. ``covered_span`` is the clean CPU span used as the per-event window."""
    cpu_readings = [
        (e, p.cpu_seconds, p.cpu_pids)
        for e, p in readings
        if p.cpu_seconds is not None and p.cpu_pids is not None
    ]
    if len(cpu_readings) < 2:
        return None, None, 0.0
    total = 0.0
    covered_span = 0.0
    clean = 0
    for (ea, ca, pa), (eb, cb, pb) in zip(cpu_readings, cpu_readings[1:], strict=False):
        if pa != pb:
            continue  # subtree membership changed — not a clean CPU delta, degrade to a gap
        d = eb - ea
        if d <= 0.0:
            continue
        total += max(0.0, cb - ca)
        covered_span += d
        clean += 1
    if clean == 0:
        return None, None, 0.0
    if total == 0.0 and covered_span >= _CPU_FLAT_GAP_SPAN_S:
        # A flat cumulative CPU counter over seconds is a wrong PID binding, not an idle engine.
        return None, None, 0.0
    cpu_mean = total / covered_span if covered_span > 0.0 else None
    return total, cpu_mean, covered_span


def _fd_ws_from(readings: list[tuple[float, ProcSample]]) -> tuple[int | None, int | None]:
    handles = [p.handles for _, p in readings if p.handles is not None]
    ws = [p.working_set_bytes for _, p in readings if p.working_set_bytes is not None]
    return (max(handles) if handles else None, max(ws) if ws else None)


def _evaluate_slos(profile: EstateProfile, records: list[EstateRecord]) -> list[SloCheck]:
    out: list[SloCheck] = []
    slo = profile.slo
    if slo.zero_loss:
        all_ok = all(r.no_loss.ok for r in records)
        out.append(SloCheck("zero_loss", True, all_ok, all_ok))
    if slo.max_drain_seconds is not None:
        worst = max(
            (r.drain_seconds for r in records if r.drain_seconds is not None),
            default=None,
        )
        ok = worst is not None and worst <= slo.max_drain_seconds
        out.append(
            SloCheck(
                "max_drain_seconds", slo.max_drain_seconds, worst if worst is not None else -1.0, ok
            )
        )
    return out
