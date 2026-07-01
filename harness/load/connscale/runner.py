# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""The connection-scale run orchestrator (B11) — sweep connection count, read the 6 walls.

Parallels :func:`~harness.load.runner.run_load`, but sweeps **connection count** instead of offered
rate, and the harness OWNS the engine subprocess (the :class:`~harness.load.failover.EngineNode`
pattern) so it can install the executor boot-shim at boot and time cold-start/reload at scale. For
each ``(sweep_mode, N)`` step it:

1. env-injects ``MEFOR_CONNSCALE_COUNT=N`` (+ base/sink/transform + the executor-shim gate) and spawns
   a fresh engine on ``harness/config/connscale``;
2. starts the :class:`~harness.load.sink.CorrelationSink`, opens the :class:`~harness.load.enginepoll.
   EnginePoller`, preflights that the engine serves all N inbound ports;
3. ramps N :class:`~harness.load.sender.PersistentConnection`s open in batches (avoid a connect storm)
   and waits until the engine's ``/connections`` reports N inbound rows;
4. HOLDS a steady aggregate rate for ``hold_seconds``, sampling the engine + the FD probe each tick;
5. optionally fires a grow-reload mid-hold and times it (wall #5);
6. stops offering, drains, takes a final sample, and appends a :class:`ConnScaleRecord`.

Each N gets a FRESH engine (its own DB + ports) so a prior N's residue can't bleed into the next
step's counters. The heavy 500/1000/1500 sweep is operator-run; the CI smoke uses N=50/100 on SQLite.
"""

from __future__ import annotations

import asyncio
import contextlib
import os
import tempfile
import time
from collections.abc import Mapping
from pathlib import Path

from harness.load.connscale.driver import ConnScaleDriver
from harness.load.connscale.probe import FdSampler, time_reload
from harness.load.connscale.profile import ConnScaleProfile
from harness.load.connscale.report import (
    EXIT_OK,
    EXIT_SLO_VIOLATION,
    ConnScaleRecord,
    ConnScaleReport,
    NoLoss,
    SloCheck,
)
from harness.load.corpus import Corpus, build_corpus
from harness.load.correlator import Correlator
from harness.load.enginepoll import EngineSample, EnginePoller
from harness.load.failover import EngineNode, _await_port
from harness.load.ids import ControlIds
from harness.load.metrics import Counters, Histogram, LiveMetrics
from harness.load.profile import TypeMix
from harness.load.sink import CorrelationSink

# The engine-side env gate for the executor boot-shim (messagefoundry.pipeline.connscale_shim.SHIM_ENV).
# Hard-coded here (a plain env-var name) so the harness sets it in the engine SUBPROCESS env without
# importing the engine's pipeline package into the driver process.
SHIM_ENV = "MEFOR_CONNSCALE_EXECUTOR_SHIM"

_CONFIG_DIR = "harness/config/connscale"
_STOP_GRACE = 5.0
_SETTLE = 0.5  # let final ACKs/arrivals settle before the truly-final engine sample
_HEALTH_TIMEOUT = 30.0
_PORTS_READY_TIMEOUT = 60.0  # waiting for the engine to report all N inbound rows (N can be large)
# A single trivial ADT type — the connscale graph routes every message identically, so the mix only
# needs to drive ONE generated type (the wall is per-connection machinery, not message-type spread).
_MIX = TypeMix({"ADT^A01": 1.0})


class ConnScaleError(RuntimeError):
    """A connection-scale run setup/orchestration failure."""


async def run_connscale(
    profile: ConnScaleProfile,
    *,
    engine_api_port_base: int,
    sink_host: str = "127.0.0.1",
    sink_port: int,
    sink_ports: int = 1,
    base_env: Mapping[str, str] | None = None,
    cwd: Path | None = None,
    install_executor_shim: bool = True,
) -> ConnScaleReport:
    """Run the connection-count sweep and return a :class:`ConnScaleReport`. The harness OWNS the
    engine subprocess per step (EngineNode); ``base_env`` supplies any server-DB connection
    (``MEFOR_STORE_*``) and defaults to the process environment."""
    base_env = dict(os.environ if base_env is None else base_env)
    cwd = cwd or Path.cwd()
    records: list[ConnScaleRecord] = []
    notes: list[str] = []
    db_backend = profile.store_backend  # None == sqlite
    # The boot-shim only populates wall #1 on a backend-agnostic engine; it is harness-only + env-gated.
    shim_installed = install_executor_shim
    api_port = engine_api_port_base
    step = 0
    for mode in profile.modes():
        for count in profile.counts:
            rate = profile.aggregate_rate_for(mode, count)
            record = await _run_one_step(
                profile,
                mode=mode,
                count=count,
                aggregate_rate=rate,
                api_port=api_port + step,
                sink_host=sink_host,
                sink_port=sink_port,
                sink_ports=sink_ports,
                base_env=base_env,
                cwd=cwd,
                install_executor_shim=install_executor_shim,
                notes=notes,
            )
            records.append(record)
            step += 1
    slos = _evaluate_slos(profile, records)
    result_ok = all(c.ok for c in slos)
    return ConnScaleReport(
        profile=profile.name,
        engine_url=f"http://{sink_host}:{api_port}",
        db_backend=db_backend,
        shim_installed=shim_installed,
        records=records,
        slos=slos,
        result_ok=result_ok,
        exit_code=EXIT_OK if result_ok else EXIT_SLO_VIOLATION,
        notes=notes,
    )


async def _run_one_step(
    profile: ConnScaleProfile,
    *,
    mode: str,
    count: int,
    aggregate_rate: float,
    api_port: int,
    sink_host: str,
    sink_port: int,
    sink_ports: int,
    base_env: Mapping[str, str],
    cwd: Path,
    install_executor_shim: bool,
    notes: list[str],
) -> ConnScaleRecord:
    # Run-scoped control-id prefix (pid + monotonic ns) so a re-run against a shared server DB can't
    # collide with a prior run's seqs.
    prefix = f"CS{os.getpid():x}{time.perf_counter_ns():x}"[:16]
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
    # On SQLite (no server backend) give each step its OWN DB file so a prior N's residue can't bleed
    # into this step's counters. On a server backend the connection comes from MEFOR_STORE_* in base_env.
    db_path: str | None = None
    if profile.store_backend is None:
        db_dir = tempfile.mkdtemp(prefix="mefor-connscale-")
        db_path = str(Path(db_dir) / f"cs-{mode}-{count}.db")
    node = EngineNode(
        f"cs-{mode}-{count}",
        api_port,
        env=_node_env(
            base_env,
            count=count,
            base_port=profile.base_port,
            transform=profile.transform,
            sink_host=sink_host,
            sink_port=sink_port,
            sink_ports=sink_ports,
            install_executor_shim=install_executor_shim,
            db_path=db_path,
        ),
        config_dir=_CONFIG_DIR,
        cwd=cwd,
    )
    poller = EnginePoller(node.url, token=None, origin=time.perf_counter())
    driver = ConnScaleDriver(
        host=sink_host,
        base_port=profile.base_port,
        count=count,
        correlator=correlator,
        metrics=metrics,
    )
    fd_sampler: FdSampler | None = None
    samples: list[EngineSample] = []
    try:
        await sink.start()
        await node.start()
        await _await_node_healthy(node, timeout=_HEALTH_TIMEOUT)
        await poller.open()
        await poller.sample_once()  # baseline
        # Preflight: the engine binds N contiguous inbound ports; wait for the first + last to listen.
        await _await_port(sink_host, profile.base_port, timeout=_PORTS_READY_TIMEOUT)
        await _await_port(sink_host, profile.base_port + count - 1, timeout=_PORTS_READY_TIMEOUT)
        await _await_inbound_rows(poller, count, timeout=_PORTS_READY_TIMEOUT)
        # FD sampler keyed on the engine PID (the harness owns it).
        pid = node.pid
        fd_sampler = FdSampler(pid) if pid is not None else None

        # Ramp N connections open in batches (avoid a connect storm) then HOLD steady, sampling each tick.
        await driver.open(
            connect_batch=profile.connect_batch, batch_pause_s=profile.connect_batch_pause_s
        )
        sampler_stop = asyncio.Event()
        sample_task = asyncio.create_task(
            _sample_loop(poller, fd_sampler, profile.poll_interval_s, sampler_stop, samples)
        )
        reload_seconds: float | None = None
        hold_task = asyncio.create_task(
            driver.run_hold(
                corpus=corpus,
                mix=_MIX,
                aggregate_rate=aggregate_rate,
                hold_seconds=profile.hold_seconds,
            )
        )
        if profile.reload_probe:
            # Fire a no-op reload of the running --config dir mid-hold and time it (wall #5). A grow-
            # reload (the connections.toml path) is a separate operator experiment; the in-place reload
            # of the N-inbound graph already costs O(connections) to quiesce-and-swap.
            await asyncio.sleep(min(profile.hold_seconds * 0.5, profile.hold_seconds))
            reload_seconds = await _time_reload(poller)
        await hold_task

        # Stop offering; drain the pipeline; final sample.
        sampler_stop.set()
        with contextlib.suppress(asyncio.CancelledError):
            await sample_task
        # Stop the driver FIRST (flush every queued send + grace the in-flight ACKs) BEFORE draining,
        # so all offered messages have reached the engine's ingress stage before we wait for the
        # pipeline to empty. Draining first would let a message still in the driver's send queue arrive
        # AFTER await_drain returned, so the final sample's `read` could trail `sent` on a slow runner —
        # the "engine_read < sent" intake-gap flake. With the driver stopped first, await_drain only
        # returns once the full intake has been read and delivered.
        await driver.stop(_STOP_GRACE)
        drain_seconds = await poller.await_drain(
            timeout=profile.drain_timeout_s, interval=profile.poll_interval_s
        )
        await asyncio.sleep(_SETTLE)
        # Poll the SETTLED reconcile condition (read >= sent, sink_received >= written) rather than
        # trusting a single fixed-instant sample — the durable fix for the intake/delivery-count lag a
        # noisy runner shows even after a clean drain (mf-ci-test-flakes: assert the actual settled
        # condition, not a timing). Bounded; on timeout it falls through to the last sample and the
        # no-loss reconcile reports the residual shortfall honestly.
        final = await _sample_until_reconciled(
            poller,
            metrics.counters,
            timeout=profile.drain_timeout_s,
            interval=profile.poll_interval_s,
        )
        if final is not None:
            samples.append(final)
        return _build_record(
            mode=mode,
            count=count,
            aggregate_rate=aggregate_rate,
            metrics_counters=metrics.counters,
            ack_hist=metrics.ack,
            poller=poller,
            samples=samples,
            drain_seconds=drain_seconds,
            reload_seconds=reload_seconds,
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


def _build_corpus(profile: ConnScaleProfile, ids: ControlIds) -> Corpus:
    # A tiny synthetic ADT corpus the driver replays (one generated type; fresh MSH-10 per send).
    from harness.load.profile import LoadProfile, Phase

    shim = LoadProfile(
        name="connscale-corpus",
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
    count: int,
    base_port: int,
    transform: str,
    sink_host: str,
    sink_port: int,
    sink_ports: int,
    install_executor_shim: bool,
    db_path: str | None,
    name_prefix: str = "",
) -> dict[str, str]:
    env = dict(base)
    env["MEFOR_AUTH_ENABLED"] = "false"  # the poller reads /stats etc. without a bearer token
    env["MEFOR_CONNSCALE_COUNT"] = str(count)
    env["MEFOR_CONNSCALE_BASE_PORT"] = str(base_port)
    env["MEFOR_CONNSCALE_TRANSFORM"] = transform
    env["MEFOR_CONNSCALE_SINK_HOST"] = sink_host
    env["MEFOR_CONNSCALE_SINK_PORT"] = str(sink_port)
    env["MEFOR_CONNSCALE_SINK_PORTS"] = str(sink_ports)
    # Per-engine connection-name tag: empty (the single-engine connscale default) leaves the historical
    # IB_CS_{i}.. names byte-identical; the multishard orchestrator sets a distinct value per engine so
    # a shared store's FIFO lanes stay disjoint across engines.
    if name_prefix:
        env["MEFOR_CONNSCALE_NAME_PREFIX"] = name_prefix
    if db_path is not None:
        env["MEFOR_STORE_PATH"] = db_path  # SQLite: this step's own DB file
    if install_executor_shim:
        env[SHIM_ENV] = "1"  # harness-only: install the default-sized instrumented executor
    return env


async def _await_node_healthy(node: EngineNode, *, timeout: float) -> None:
    import httpx

    start = time.perf_counter()
    async with httpx.AsyncClient(timeout=4.0) as client:
        while time.perf_counter() - start < timeout:
            if not node.alive:
                raise ConnScaleError(f"engine exited during startup:\n{node.log_tail()}")
            if await node.healthy(client):
                return
            await asyncio.sleep(0.25)
    raise ConnScaleError(f"engine did not become healthy within {timeout}s:\n{node.log_tail()}")


async def _await_inbound_rows(poller: EnginePoller, count: int, *, timeout: float) -> None:
    """Wait until the engine's /connections reports all ``count`` inbound rows present (so the
    steady-state hold isn't polluted by the connect storm)."""
    loop = asyncio.get_running_loop()
    start = loop.time()
    while loop.time() - start < timeout:
        n = await loop.run_in_executor(None, _count_inbound_rows, poller)
        if n >= count:
            return
        await asyncio.sleep(0.25)
    raise ConnScaleError(
        f"engine never reported all {count} inbound connections within {timeout}s "
        f"(last seen {_count_inbound_rows(poller)})"
    )


def _count_inbound_rows(poller: EnginePoller) -> int:
    client = poller.client
    if client is None:
        return 0
    try:
        # An inbound row carries a `read` counter (None on outbound rows); count the inbound side.
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
    """Sample the engine + the FD probe every ``interval`` until ``stop``. The FD probe rides the same
    tick OFF the event loop (run_in_executor), like the engine poll, so neither blocks the loop."""
    loop = asyncio.get_running_loop()
    while not stop.is_set():
        sample = await poller.sample_once()
        if sample is not None:
            if fd_sampler is not None:
                fd = await loop.run_in_executor(None, fd_sampler.sample)
                _FD_BY_SAMPLE[id(sample)] = fd
            out.append(sample)
        try:
            await asyncio.wait_for(stop.wait(), timeout=interval)
        except asyncio.TimeoutError:
            pass


# FD readings are keyed to the EngineSample they were taken alongside (EngineSample is frozen, so we
# can't attach the FD count to it directly without bloating the shared dataclass for a connscale-only
# field). A small side map by sample identity, drained when the record is built.
_FD_BY_SAMPLE: dict[int, int | None] = {}


async def _time_reload(poller: EnginePoller) -> float | None:
    client = poller.client
    if client is None:
        return None
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, time_reload, client, None)


async def _sample_until_reconciled(
    poller: EnginePoller, counters: Counters, *, timeout: float, interval: float
) -> EngineSample | None:
    """Re-sample the engine until the no-loss reconcile condition SETTLES — every offered message has
    been read (``read >= sent``) and every delivery has reached the sink (``sink_received >= written``)
    — or ``timeout`` elapses. The durable fix for the intake/delivery count-lag a noisy runner shows
    even after a clean drain: assert the actual settled condition, not a single fixed-instant sample
    (mf-ci-test-flakes). The baseline-relative deltas are used, mirroring the reconcile. On timeout the
    last sample is returned and the no-loss check reports the residual shortfall honestly (no masking)."""
    loop = asyncio.get_running_loop()
    base = poller.baseline
    start = loop.time()
    last = poller.final
    while loop.time() - start < timeout:
        sample = await poller.sample_once()
        if sample is not None:
            last = sample
            if base is not None:
                read = sample.read - base.read
                written = sample.written - base.written
                # Settled: intake fully read AND every counted delivery arrived at the sink AND the
                # pipeline is empty (no in-flight rows that could still move the counts).
                if (
                    read >= counters.sent
                    and counters.sink_received >= written
                    and sample.in_pipeline == 0
                ):
                    return sample
        await asyncio.sleep(interval)
    return last


def _build_record(
    *,
    mode: str,
    count: int,
    aggregate_rate: float,
    metrics_counters: Counters,
    ack_hist: Histogram,
    poller: EnginePoller,
    samples: list[EngineSample],
    drain_seconds: float | None,
    reload_seconds: float | None,
) -> ConnScaleRecord:
    c = metrics_counters.snapshot()
    base, final = poller.baseline, poller.final
    no_loss = _reconcile(c, base, final)
    in_pipeline_peak = max((s.in_pipeline for s in samples), default=0)

    # Wall #1: executor saturation (None when the shim isn't installed → all-None samples).
    exec_qd = _peak_int([s.executor_queue_depth for s in samples])
    exec_busy = _peak_int([s.executor_busy for s in samples])

    # Wall #2: pool wait (PRIMARY percentiles = the max over the hold; occupancy = min idle seen).
    pool_p50 = _peak_float([s.pool_wait_p50_ms for s in samples])
    pool_p95 = _peak_float([s.pool_wait_p95_ms for s in samples])
    pool_p99 = _peak_float([s.pool_wait_p99_ms for s in samples])
    pool_max = _peak_float([s.pool_wait_max_ms for s in samples])
    pool_idle_min = _min_int([s.pool_idle for s in samples])
    pool_size_max = _peak_int([s.pool_size for s in samples])

    # Wall #3: empty-claim RATES over the hold (Δcount / Δt), SEPARATED into idle-poll vs wake-fanout.
    total_per_s, idle_per_s, wake_per_s = _empty_claim_rates(samples)

    # Wall #4: FD count peak (drained from the side map; None when the OS probe couldn't read).
    fd_peak = _fd_peak(samples)

    # Wall #6: ACK percentiles for this N step.
    ack = ack_hist.summary()

    return ConnScaleRecord(
        sweep_mode=mode,
        count=count,
        offered_aggregate_rate=aggregate_rate,
        sent=c.sent,
        acked=c.acked,
        nak=c.nak,
        deferred=c.deferred,
        no_loss=no_loss,
        in_pipeline_peak=in_pipeline_peak,
        drain_seconds=drain_seconds,
        executor_queue_depth_peak=exec_qd,
        executor_busy_peak=exec_busy,
        pool_wait_p50_ms=pool_p50,
        pool_wait_p95_ms=pool_p95,
        pool_wait_p99_ms=pool_p99,
        pool_wait_max_ms=pool_max,
        pool_idle_min=pool_idle_min,
        pool_size_max=pool_size_max,
        empty_claims_per_s=total_per_s,
        idle_poll_per_s=idle_per_s,
        wake_fanout_per_s=wake_per_s,
        fd_count_peak=fd_peak,
        reload_seconds=reload_seconds,
        ack_p50_ms=ack.p50_ms,
        ack_p95_ms=ack.p95_ms,
        ack_p99_ms=ack.p99_ms,
    )


def _reconcile(c: Counters, base: EngineSample | None, final: EngineSample | None) -> NoLoss:
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
    read_short = sent - read
    deliver_short = written - sink_received
    drained = backlog == 0
    ok = read_short <= 0 and deliver_short <= 0 and drained
    parts: list[str] = []
    if read_short > 0:
        parts.append(f"engine_read {read} < sent {sent} (lost {read_short} on intake)")
    if deliver_short > 0:
        parts.append(
            f"sink_received {sink_received} < engine_written {written} (lost {deliver_short})"
        )
    if not drained:
        parts.append(f"backlog {backlog} not drained")
    detail = "; ".join(parts) if parts else "read>=sent, sink_received>=written, backlog drained"
    return NoLoss(ok, sent, read, written, sink_received, backlog, detail)


def _empty_claim_rates(samples: list[EngineSample]) -> tuple[float, float, float]:
    """Empty-claim rates over the hold window: (total/s, idle_poll/s, wake_fanout/s), from the FIRST
    to LAST in-hold sample. SEPARATED — never summed into one number (critic must-change #3)."""
    if len(samples) < 2:
        return 0.0, 0.0, 0.0
    first, last = samples[0], samples[-1]
    span = last.elapsed_s - first.elapsed_s
    if span <= 0.0:
        return 0.0, 0.0, 0.0
    total = (last.empty_claims - first.empty_claims) / span
    idle = (last.empty_claims_idle_poll - first.empty_claims_idle_poll) / span
    wake = (last.empty_claims_wake_fanout - first.empty_claims_wake_fanout) / span
    return max(0.0, total), max(0.0, idle), max(0.0, wake)


def _fd_peak(samples: list[EngineSample]) -> int | None:
    peak: int | None = None
    for s in samples:
        fd = _FD_BY_SAMPLE.pop(id(s), None)
        if fd is not None and (peak is None or fd > peak):
            peak = fd
    return peak


def _peak_int(values: list[int | None]) -> int | None:
    present = [v for v in values if v is not None]
    return max(present) if present else None


def _peak_float(values: list[float | None]) -> float | None:
    present = [v for v in values if v is not None]
    return max(present) if present else None


def _min_int(values: list[int | None]) -> int | None:
    present = [v for v in values if v is not None]
    return min(present) if present else None


def _evaluate_slos(profile: ConnScaleProfile, records: list[ConnScaleRecord]) -> list[SloCheck]:
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
    if slo.fd_monotonic:
        out.append(_monotonic_slo("fd_count_monotonic", records, lambda r: r.fd_count_peak))
    if slo.empty_claims_monotonic:
        out.append(
            _monotonic_slo("empty_claims_monotonic", records, lambda r: r.empty_claims_per_s)
        )
    return out


#: Noise tolerance for the loose monotonicity smoke: a larger-N metric may dip up to this fraction below a
#: smaller-N reading without failing. These are timing-derived counters (empty-claims/sec especially) and CI
#: runners are noisy (mf-ci-test-flakes), so only a REAL regression (a drop past the band) should fail — a
#: strict `>=` flaked on ~10% jitter (empty_claims 398.7 < 442.9 on windows-2022). 0.25 absorbs runner jitter
#: while still catching a genuine collapse (a halving).
_MONOTONIC_TOLERANCE = 0.25


def _monotonic_slo(  # type: ignore[no-untyped-def]
    name: str, records: list[ConnScaleRecord], key, *, tolerance: float = _MONOTONIC_TOLERANCE
) -> SloCheck:
    """A LOOSE per-mode monotonicity smoke: within a sweep mode the metric at a larger N must be >= a
    smaller N **minus a noise ``tolerance``** (default 25%) — the wall exists and scales, but these are
    timing-derived counters on noisy CI runners (mf-ci-test-flakes), so a small dip is jitter, not a
    regression. Fails only on a real drop (``v < prior * (1 - tolerance)``). Missing readings (None) are
    skipped, not failed."""
    ok = True
    detail_parts: list[str] = []
    by_mode: dict[str, list[ConnScaleRecord]] = {}
    for r in records:
        by_mode.setdefault(r.sweep_mode, []).append(r)
    floor = 1.0 - tolerance
    for mode, rs in by_mode.items():
        ordered = sorted(rs, key=lambda r: r.count)
        prev_val: float | None = None
        for r in ordered:
            val = key(r)
            if val is None:
                continue
            v = float(val)
            if prev_val is not None and v < prev_val * floor:
                ok = False
                detail_parts.append(
                    f"{mode}@N={r.count}: {v:.1f} < prior {prev_val:.1f} * {floor:.2f}"
                )
            prev_val = v
    observed = "monotonic" if ok else "; ".join(detail_parts)
    return SloCheck(name, f"non-decreasing vs N (±{int(tolerance * 100)}% jitter)", observed, ok)
