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
import logging
import os
import tempfile
import time
from collections.abc import Mapping
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any

from harness.load.connscale import intake_audit
from harness.load.connscale.compare import (
    ClaimModeComparison,
    FuseModeComparison,
    build_batch_comparison,
    build_comparison,
    build_fuse_comparison,
)
from harness.load.connscale.driver import ConnScaleDriver
from harness.load.connscale.intake_audit import IntakeAudit, IntakeLedger, StoreReader
from harness.load.connscale.probe import FdSampler, ProcSample, time_reload
from harness.load.connscale.profile import ConnScaleProfile
from harness.load.connscale.report import (
    EXIT_OK,
    EXIT_SLO_VIOLATION,
    ConnScaleRecord,
    ConnScaleReport,
    NoLoss,
    SloCheck,
    herd_floor_readings,
    monotonic_pairs,
)
from harness.load.corpus import Corpus, build_corpus
from harness.load.correlator import Correlator
from harness.load.enginepoll import EnginePoller, EngineSample, sample_until_reconciled
from harness.load.failover import EngineNode, FailoverError, _await_port
from harness.load.ids import ControlIds
from harness.load.metrics import Counters, Histogram, LiveMetrics
from harness.load.profile import TypeMix
from harness.load.sink import CorrelationSink

# The engine-side env gate for the executor boot-shim (messagefoundry.pipeline.connscale_shim.SHIM_ENV).
# Hard-coded here (a plain env-var name) so the harness sets it in the engine SUBPROCESS env without
# importing the engine's pipeline package into the driver process.
SHIM_ENV = "MEFOR_CONNSCALE_EXECUTOR_SHIM"

log = logging.getLogger(__name__)

# The pipeline tables a run writes to, in a delete-safe order (child rows before the `messages` they FK
# to). On a SERVER backend every (mode, count) step shares ONE database, so — mirroring the SQLite
# fresh-file-per-step path — each step first EMPTIES these so the pooled arm never runs second against
# the per_lane arm's residue (the carryover confound). Table lists verified against the store schemas
# (store/sqlserver.py, store/postgres.py) and match the reset the store tests use. Neither backend has
# an `outbox` table: SQL Server's legacy one was folded into `queue` and DROPped (ASVS 14.2.7), and
# Postgres never had one. Naming it here would fail the reset with *Invalid object name*.
_SQLSERVER_PIPELINE_TABLES = (
    "message_events",
    "queue",
    "response",
    "delivered_keys",
    "messages",
)

_CONFIG_DIR = "harness/config/connscale"
_STOP_GRACE = 5.0
_SETTLE = 0.5  # let final ACKs/arrivals settle before the truly-final engine sample
_HEALTH_TIMEOUT = 30.0
# One spelling, because both audit moments report it and they must not drift into disagreeing about
# why nothing ran -- a reader comparing the two moments of a disabled step reads the difference as
# meaningful.
_AUDIT_DISABLED = "intake audit disabled for this profile"
_PORTS_READY_TIMEOUT = 60.0  # waiting for the engine to report all N inbound rows (N can be large)
# A single trivial ADT type — the connscale graph routes every message identically, so the mix only
# needs to drive ONE generated type (the wall is per-connection machinery, not message-type spread).
_MIX = TypeMix({"ADT^A01": 1.0})


class ConnScaleError(RuntimeError):
    """A connection-scale run setup/orchestration failure."""


def sweep_step_count(profile: ConnScaleProfile) -> int:
    """How many sweep steps :func:`run_connscale` runs for ``profile`` -- and therefore how many API
    ports it consumes, since step ``k`` binds ``engine_api_port_base + k``.

    This is the ONE definition of the loop's cardinality, and it exists so a caller can reserve the
    range the sweep will ACTUALLY use. Reserving only the base leaves every later step's port merely
    assumed free, which is BACKLOG #1103: a taken port anywhere in the range kills the engine at
    startup, reported as ``EADDRINUSE`` on Linux and as the far less obvious *"access forbidden"*
    ``WinError 10013`` on Windows. Callers reserve ``[base, base + sweep_step_count(profile))``.

    :func:`run_connscale` checks its own step index against this number on every iteration, so the
    two cannot drift silently: growing the sweep with a new axis without teaching this function about
    it fails loudly on the first step past the reserved block instead of binding an unreserved port.
    A pooled-arm miss consumes a step and then abandons the rest of that cell's trials, so the real
    step count can be LOWER than this -- never higher, which is what makes it a safe reservation
    width.
    """
    return (
        len(profile.claim_modes)
        * len(profile.fuse_modes)
        * len(profile.batch_modes)
        * len(profile.modes())
        * len(profile.counts)
        * profile.trials
    )


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
    # The API-port range the caller was told to reserve (BACKLOG #1103). Every step below is checked
    # against it before it binds, so a sweep that grew an axis sweep_step_count() does not count
    # fails LOUDLY on the first unreserved port rather than binding it and dying inside uvicorn with
    # an errno that does not name a port problem.
    reserved_api_ports = sweep_step_count(profile)
    # (sweep_mode, count) whose POOLED arm failed to start → the loud reason, surfaced in the A/B.
    missing_detail: dict[tuple[str, int], str] = {}
    # (claim_mode, sweep_mode, count) whose arm failed to start → the loud reason for the fusion A/B
    # (keyed with claim_mode since the fusion comparison pairs within a claim mode).
    fuse_missing_detail: dict[tuple[str, str, int], str] = {}
    # ... and the same for the statement-batching A/B (ADR 0075 Bench B): a pooled-arm miss is recorded
    # for the batch comparison too, so a swallowed B0/B1 batching arm is never silently compared against
    # nothing.
    batch_missing_detail: dict[tuple[str, str, int], str] = {}
    # claim_mode is the OUTER axis (ADR 0066 A/B): each mode gets a full (sweep_mode × counts) sweep,
    # so a single-arm profile (the default ("per_lane",)) is byte-identical to the pre-A/B behavior.
    # fuse_mode (ADR 0071 B5) nests just inside claim_mode: each (claim_mode, count) cell runs each
    # fuse arm (B0 off / B1 on) as a distinct step, tagged on the record so the fusion A/B can pair
    # them. The default single-arm (False,) iterates once ⇒ the sweep is byte-identical to pre-B5.
    # trial (ADR 0071 B5 PR5) is the INNERMOST axis: each cell runs profile.trials times as distinct
    # steps so ONE invocation banks >= 3 trials/arm for the §6.4b ">2σ" spread guard. The default
    # trials=1 iterates once ⇒ the whole sweep (steps, ports, records) is byte-identical to pre-PR5.
    # batch_mode (ADR 0075 Bench B) nests alongside fuse_mode: each (claim_mode, fuse, count) cell runs
    # each batching arm (B0 off / B1 on) as a distinct step, tagged on the record so the batch A/B can
    # pair them. The default single-arm (False,) iterates once ⇒ byte-identical to pre-ADR-0075. At most
    # ONE of {claim_modes, fuse_modes, batch_modes} is multi-arm per profile (validated in profile.py),
    # so fusion stays OFF in both batching arms (the two levers don't compose, ADR 0075).
    for claim_mode in profile.claim_modes:
        for fuse_mode in profile.fuse_modes:
            for batch_mode in profile.batch_modes:
                for mode in profile.modes():
                    for count in profile.counts:
                        rate = profile.aggregate_rate_for(mode, count)
                        for trial in range(profile.trials):
                            if step >= reserved_api_ports:
                                raise ConnScaleError(
                                    f"sweep step {step} would bind API port {api_port + step}, "
                                    f"past the reserved range [{api_port}, "
                                    f"{api_port + reserved_api_ports}) that sweep_step_count() "
                                    f"sized at {reserved_api_ports} -- the sweep has an axis "
                                    f"sweep_step_count() does not count, so the caller under-"
                                    f"reserved and this port was never verified free (BACKLOG "
                                    f"#1103)"
                                )
                            try:
                                record = await _run_one_step(
                                    profile,
                                    claim_mode=claim_mode,
                                    fuse_mode=fuse_mode,
                                    batch_mode=batch_mode,
                                    mode=mode,
                                    count=count,
                                    trial=trial,
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
                            except (ConnScaleError, FailoverError) as exc:
                                # The per_lane BASELINE must start — a failure there is a real setup
                                # fault, so it propagates (exit 2). A POOLED arm can legitimately refuse
                                # to start (the SQL Server RCSI fail-closed gate); record the miss LOUDLY
                                # and keep the sweep going so the A/B never silently compares per_lane
                                # against nothing. FailoverError is caught too: the port preflight
                                # (`_await_port`) raises it, and it must NOT escape to crash the whole
                                # sweep with no report (_run_one_step normally re-wraps startup faults as
                                # ConnScaleError carrying the engine log tail — defense in depth). Fusion
                                # and statement-batching never cause a miss (each fails OPEN / no-ops to
                                # the async path), so the miss gate stays keyed on claim_mode.
                                if claim_mode != "pooled":
                                    raise
                                # Only attribute the miss to the RCSI fail-closed gate when the engine
                                # log actually shows it; otherwise surface the REAL failure (OOM at 1500
                                # conns, a DB-connect fault, a config error, a port-bind clash) so an
                                # operator doesn't flip a DB setting and burn another multi-minute (or
                                # per-box-dollar) run chasing a phantom RCSI problem.
                                reason = _pooled_miss_reason(str(exc))
                                fuse_tag = "B1" if fuse_mode else "B0"
                                batch_tag = "B1" if batch_mode else "B0"
                                notes.append(
                                    f"POOLED ARM MISSING [{mode}] N={count} fuse={fuse_tag} "
                                    f"batch={batch_tag}: {reason}"
                                )
                                missing_detail[(mode, count)] = reason
                                fuse_missing_detail[(claim_mode, mode, count)] = reason
                                batch_missing_detail[(claim_mode, mode, count)] = reason
                                step += 1
                                # A pooled-arm miss is a DETERMINISTIC RCSI/startup refusal, identical
                                # for every trial of this cell — record it ONCE and stop retrying (don't
                                # log it or burn a multi-minute spawn trials times). The remaining trials
                                # of this cell are skipped; the outer sweep continues.
                                break
                            records.append(record)
                            step += 1
    slos = _evaluate_slos(profile, records)
    comparison: ClaimModeComparison | None = build_comparison(
        records, profile.claim_modes, missing_detail=missing_detail
    )
    fuse_comparison: FuseModeComparison | None = build_fuse_comparison(
        records, profile.fuse_modes, missing_detail=fuse_missing_detail
    )
    # The statement-batching A/B (ADR 0075 Bench B) reuses the SAME comparator via build_batch_comparison
    # (keyed on batch_handoff_statements). It is None for a single-arm batch_modes (the pre-ADR-0075
    # shape), and at most one of {claim, fuse, batch} is multi-arm per profile, so at most one of the
    # three comparisons is non-None for a given run.
    batch_comparison: FuseModeComparison | None = build_batch_comparison(
        records, profile.batch_modes, missing_detail=batch_missing_detail
    )
    # A multi-arm run additionally fails on a throughput regression, a NO-collapse, or a missing pooled
    # arm (comparison.ok folds those in). A single-arm run has no comparison ⇒ unchanged verdict. The
    # fusion/batching A/Bs fold ONLY their correctness gate (.ok = every B1 arm held zero-loss +
    # present) — a NO-GO/INCONCLUSIVE throughput verdict is a legitimate measurement, not a red build.
    result_ok = (
        all(c.ok for c in slos)
        and (comparison is None or comparison.ok)
        and (fuse_comparison is None or fuse_comparison.ok)
        and (batch_comparison is None or batch_comparison.ok)
    )
    return ConnScaleReport(
        profile=profile.name,
        engine_url=f"https://{sink_host}:{api_port}",
        db_backend=db_backend,
        shim_installed=shim_installed,
        records=records,
        slos=slos,
        result_ok=result_ok,
        exit_code=EXIT_OK if result_ok else EXIT_SLO_VIOLATION,
        notes=notes,
        comparison=comparison,
        fuse_comparison=fuse_comparison,
        batch_comparison=batch_comparison,
    )


async def _run_one_step(
    profile: ConnScaleProfile,
    *,
    claim_mode: str,
    fuse_mode: bool,
    batch_mode: bool,
    mode: str,
    count: int,
    trial: int,
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
    # A per-arm + per-trial tag: the fusion arm (b0/b1), the batching arm (bt0/bt1), and the trial index
    # (t{trial}) so the two fusion arms, the two batching arms, and the ``profile.trials`` repeats of one
    # (claim_mode, mode, count) cell never collide on the SQLite DB filename or the engine-node name
    # (which prefixes the node's log file). A single-arm axis always emits its b0/bt0 segment, so the
    # only string delta vs pre-ADR-0075 is the constant -bt0 insert; the measurements are unchanged.
    fuse_tag = "b1" if fuse_mode else "b0"
    batch_tag = "bt1" if batch_mode else "bt0"
    tag = f"cs-{claim_mode}-{fuse_tag}-{batch_tag}-{mode}-{count}-t{trial}"
    if profile.store_backend is None:
        db_dir = tempfile.mkdtemp(prefix="mefor-connscale-")
        db_path = str(Path(db_dir) / f"{tag}.db")
    # Captured rather than inlined into EngineNode: the BACKLOG #1292 intake audit opens THIS step's
    # store afterwards, and it must resolve the same MEFOR_STORE_* the engine itself was given (the
    # per-step SQLite file, or the shared server connection) instead of re-deriving them.
    node_env = _node_env(
        base_env,
        claim_mode=claim_mode,
        fuse_mode=fuse_mode,
        batch_mode=batch_mode,
        count=count,
        base_port=profile.base_port,
        transform=profile.transform,
        sink_host=sink_host,
        sink_port=sink_port,
        sink_ports=sink_ports,
        install_executor_shim=install_executor_shim,
        db_path=db_path,
    )
    node = EngineNode(tag, api_port, env=node_env, config_dir=_CONFIG_DIR, cwd=cwd)
    poller = EnginePoller(node.url, token=None, origin=time.perf_counter())
    # BACKLOG #1292: the per-message send ledger the intake audit reads. None disables the audit
    # wholesale (the sender's write path is then byte-identical to pre-#1292).
    ledger = IntakeLedger() if profile.intake_audit else None
    driver = ConnScaleDriver(
        host=sink_host,
        base_port=profile.base_port,
        count=count,
        correlator=correlator,
        metrics=metrics,
        ledger=ledger,
    )
    fd_sampler: FdSampler | None = None
    samples: list[EngineSample] = []
    try:
        await sink.start()
        # SERVER backend: empty the shared store so THIS step starts clean — the analog of the SQLite
        # fresh-file-per-step above. Without it the pooled arm always runs SECOND against the per_lane
        # arm's residue (tens of thousands of rows across the shared FIFO lanes), a systematic handicap
        # that biases achieved throughput + idle-poll rate and can wrongly flip the verdict to REGRESS
        # on table growth, not claim mode. Logged before start() as the carryover-fix evidence.
        if profile.store_backend is not None:
            before, after = await _reset_server_store(profile.store_backend, base_env)
            log.info(
                "connscale reset [%s] claim_mode=%s N=%d: store had %d pipeline row(s) "
                "(messages+queue), %d after reset — step starts from an empty store",
                mode,
                claim_mode,
                count,
                before,
                after,
            )
        await node.start()
        # Any start/preflight failure is re-wrapped as ConnScaleError carrying the engine LOG TAIL
        # (captured NOW, before the `finally` stops the node and unlinks its log). This lets
        # run_connscale distinguish the benign pooled RCSI fail-closed gate from a REAL defect, and
        # converts the port-preflight's FailoverError so it can't escape and crash the whole sweep.
        try:
            await _await_node_healthy(node, timeout=_HEALTH_TIMEOUT)
            await poller.open()
            await poller.sample_once()  # baseline
            # Preflight: the engine binds N contiguous inbound ports; wait for the first + last to listen.
            await _await_port(sink_host, profile.base_port, timeout=_PORTS_READY_TIMEOUT)
            await _await_port(
                sink_host, profile.base_port + count - 1, timeout=_PORTS_READY_TIMEOUT
            )
            await _await_inbound_rows(poller, count, timeout=_PORTS_READY_TIMEOUT)
        except (ConnScaleError, FailoverError) as exc:
            raise ConnScaleError(_startup_failure_detail(exc, node)) from exc
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
        if drain_seconds is not None:
            # Poll the SETTLED reconcile condition (read >= confirmed sent, sink_received >= written)
            # rather than trusting a single fixed-instant sample — the durable fix for the
            # intake/delivery-count lag a noisy runner shows even after a clean drain
            # (mf-ci-test-flakes: assert the actual settled condition, not a timing). Bounded; on
            # timeout it falls through to the last sample and the no-loss reconcile reports the
            # residual shortfall honestly.
            final = await sample_until_reconciled(
                poller,
                metrics.counters,
                timeout=profile.drain_timeout_s,
                interval=profile.poll_interval_s,
            )
        else:
            # The drain already timed out — the verdict (backlog != 0 fails the reconcile) is
            # determined, so burning a second drain_timeout_s polling for a settle that cannot come
            # would only compound a genuine failure across sweep steps into the pytest watchdog.
            final = await poller.sample_once()
        if final is not None:
            samples.append(final)

        # --- BACKLOG #1292: the intake audit, at its TWO moments -------------------------------
        # MOMENT 1, LIVE (engine still up), and only on a shortfall: does every message the harness
        # read a response frame for actually HAVE a row right now? If it does, nothing was lost and
        # the shortfall is in the `engine_read` gauge. Gated on the shortfall because on a clean step
        # it would only re-confirm what MOMENT 2 confirms anyway, at a page sweep per step.
        # `poller.baseline`/`poller.final`, NOT the local `final`: those are the exact two samples
        # `_build_record` hands `_reconcile`, and the audit has to be triggered by the shortfall the
        # step will actually REPORT. The two diverge on the drain-timeout path, where the local
        # `final` can be None while the poller still holds an earlier sample.
        read_short = _read_shortfall(
            metrics.counters, poller.baseline, poller.final, unconfirmed_budget=count
        )
        # The part no excusal forgives, computed HERE because only this side knows whether the
        # excusal was clamped. The audit must not re-derive it -- see `_unexplained_shortfall`.
        unexplained_short = _unexplained_shortfall(metrics.counters, poller.baseline, poller.final)
        # The two NOT_RUN reasons answer different questions, and each is stated at the branch it
        # describes. The disabled one has to be reachable on a step that DID have a shortfall: "no
        # shortfall to attribute" printed on a failing step is a false statement about the run, in
        # the one field whose entire job is attribution, on exactly the step someone opens the
        # artifact to read.
        if ledger is None:
            audit_live = intake_audit.not_run(_AUDIT_DISABLED, moment=intake_audit.MOMENT_LIVE)
        elif read_short > 0:
            audit_live = await intake_audit.run_intake_audit(
                ledger,
                _store_reader(node_env, metrics.counters.sent),
                moment=intake_audit.MOMENT_LIVE,
                sent=metrics.counters.sent,
                read_short=read_short,
                unexplained_short=unexplained_short,
            )
        else:
            audit_live = intake_audit.not_run(
                "no intake shortfall to attribute at this moment",
                moment=intake_audit.MOMENT_LIVE,
            )
        # MOMENT 2, POST-MORTEM. Stop the engine FIRST, so the store is committed and quiesced: with
        # no process running, "we sampled too early" is no longer available as an explanation, which
        # is what separates outcome 1 (sample lag) from outcome 2 (sum coverage). `stop()` is
        # idempotent, so the `finally` below still runs it on every other path.
        audit_final = intake_audit.not_run(_AUDIT_DISABLED)
        if ledger is not None:
            with contextlib.suppress(Exception):
                await node.stop()
            if node.alive:
                # Refuse to CALL it a post-mortem when it would not be one. A read taken while the
                # engine is still running answers the LIVE question, and labelling it post_mortem
                # would destroy the one distinction the second moment exists to make.
                audit_final = intake_audit.not_run(
                    "the engine did not stop, so a post-mortem read would not be post-mortem"
                )
            else:
                audit_final = await intake_audit.run_intake_audit(
                    ledger,
                    _store_reader(node_env, metrics.counters.sent),
                    moment=intake_audit.MOMENT_POST_MORTEM,
                    sent=metrics.counters.sent,
                    read_short=read_short,
                    unexplained_short=unexplained_short,
                )
        return _build_record(
            claim_mode=claim_mode,
            fuse_mode=fuse_mode,
            batch_mode=batch_mode,
            mode=mode,
            count=count,
            aggregate_rate=aggregate_rate,
            metrics_counters=metrics.counters,
            ack_hist=metrics.ack,
            poller=poller,
            samples=samples,
            drain_seconds=drain_seconds,
            reload_seconds=reload_seconds,
            audit_live=audit_live,
            audit_final=audit_final,
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
    claim_mode: str = "per_lane",
    fuse_mode: bool = False,
    batch_mode: bool = False,
    count: int,
    base_port: int,
    transform: str,
    sink_host: str,
    inbound_bind_host: str = "127.0.0.1",
    sink_port: int,
    sink_ports: int,
    install_executor_shim: bool,
    db_path: str | None,
    name_prefix: str = "",
) -> dict[str, str]:
    env = dict(base)
    env["MEFOR_SECURITY_REQUIRE_SIGN_IN"] = (
        "false"  # the poller reads /stats etc. without a bearer token
    )
    # ADR 0066 A/B seam: settings.py parses MEFOR_PIPELINE_CLAIM_MODE into PipelineSettings.claim_mode,
    # which threads __main__ -> api/app -> engine -> RegistryRunner.start() (pooled builds
    # StageDispatchers). "per_lane" is the engine default, so a per_lane arm is behaviorally unchanged.
    env["MEFOR_PIPELINE_CLAIM_MODE"] = claim_mode
    # ADR 0061 seam, PINNED rather than inherited (BACKLOG #1211). settings.py parses
    # MEFOR_PIPELINE_PER_LANE_WAKE into PipelineSettings.per_lane_wake, whose default is already False,
    # so injecting "false" is behaviorally identical to what this rig ran before -- same as the two B0
    # flags below.
    #
    # IT IS PINNED BECAUSE A RECORDED NUMBER'S MEANING MUST NOT DEPEND ON AN UNPINNED ENV VAR. The
    # predicted herd floor (report.predict_herd_levels) is now RECORDED on every run so BACKLOG #1415
    # can arm a gate from its distribution, and that whole plan needs every recorded floor to be about
    # the same engine. This flag moves BOTH terms of the prediction at once: with it on, a commit wakes
    # only its own lane, so the `wake` term collapses toward zero, AND the idle backstop steps from
    # poll_interval (0.25s) to _PER_LANE_IDLE_BACKSTOP_SECONDS (30.0s, pipeline/wiring_runner.py), so
    # the `idle` term falls by two orders of magnitude. An unrelated flip of the engine default would
    # therefore rewrite every floor recorded after it, with no connscale change and nothing anywhere
    # reporting a problem -- exactly the silent-subject-swap the harvest exists to avoid.
    env["MEFOR_PIPELINE_PER_LANE_WAKE"] = "false"
    # ADR 0071 B5 A/B seam: settings.py parses MEFOR_PIPELINE_FUSE_THREAD_HOPS into
    # PipelineSettings.fuse_thread_hops. Fusion only ACTIVATES on SQL Server + claim_mode=pooled + this
    # flag on (it fails OPEN to the async path elsewhere), so injecting "false" (the engine default) on
    # the B0 arm — and on every pre-B5 single-arm sweep — is behaviorally unchanged.
    env["MEFOR_PIPELINE_FUSE_THREAD_HOPS"] = "true" if fuse_mode else "false"
    # ADR 0075 Bench B A/B seam: settings.py parses MEFOR_PIPELINE_BATCH_HANDOFF_STATEMENTS into
    # PipelineSettings.batch_handoff_statements. Statement-batching only activates on SQL Server (a
    # provable no-op on Postgres/SQLite), so injecting "false" (the engine default) on the B0 arm — and
    # on every pre-ADR-0075 single-arm sweep — is behaviorally unchanged. Batching does NOT compose with
    # fusion (ADR 0075), so the batch A/B keeps fuse OFF in both arms (the profile's one-multi-arm-axis
    # rule enforces it); this seam sets the two flags independently.
    env["MEFOR_PIPELINE_BATCH_HANDOFF_STATEMENTS"] = "true" if batch_mode else "false"
    env["MEFOR_CONNSCALE_COUNT"] = str(count)
    env["MEFOR_CONNSCALE_BASE_PORT"] = str(base_port)
    env["MEFOR_CONNSCALE_TRANSFORM"] = transform
    env["MEFOR_CONNSCALE_SINK_HOST"] = sink_host
    # Inbound listener interface: loopback for a co-located single-box run (unchanged); a two-box batch
    # drive sets 0.0.0.0 so the off-box ConnScaleDriver can reach base_port + i on the engine box. The
    # engine honors MEFOR_INBOUND_BIND_HOST for its inbound bind (the same env the two-box shardcert
    # rig uses), so this is additive and behavior-preserving for the default.
    env["MEFOR_INBOUND_BIND_HOST"] = inbound_bind_host
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


def _store_reader(node_env: Mapping[str, str], sent: int) -> StoreReader:
    """A one-shot reader over THIS step's own store, for the BACKLOG #1292 intake audit.

    Goes through the ``Store`` protocol (``open_store`` -> ``count_messages``/``list_messages``) so
    SQLite and the two server backends take one path, and resolves its settings from the SAME env the
    engine subprocess was given. It deliberately does NOT go through ``GET /messages``: that route is
    ``require_phi_read`` and charges a per-actor anti-automation budget, so a per-message sweep would
    be 429'd -- and it would also read the numbers through the very API layer under suspicion.

    The engine-package import sits INSIDE the call, mirroring ``_reset_server_store`` directly above:
    this rig OWNS the engine subprocess and inspects its store, which is why it is the one part of
    ``harness/load`` that reaches past the HTTP API at all.
    """
    # 4x the sends plus a floor: `messages` holds one row per RECEIVED message and this store is
    # exclusive to the step, so a table meaningfully larger than the run means the assumption is
    # wrong -- report TRUNCATED rather than sweep an unbounded table.
    row_cap = max(4 * sent + 1000, 10_000)

    async def _read() -> intake_audit.StoreSnapshot:
        from messagefoundry.config.settings import load_settings
        from messagefoundry.store.base import open_store

        store = await open_store(load_settings(environ=node_env).store)
        try:
            return await intake_audit.sweep_store(store, row_cap=row_cap)
        finally:
            await store.close()

    return _read


async def _reset_server_store(backend: str, env: Mapping[str, str]) -> tuple[int, int]:
    """Empty the pipeline tables of the SHARED server store before a step, so every (mode, count) step
    is apples-to-apples (the pooled arm never inherits the per_lane arm's rows). Opens a short-lived
    store connection from the same ``MEFOR_STORE_*`` the engine uses (``load_settings(environ=env)``),
    truncates, and closes — mirroring the reset the store tests use. Returns
    ``(rows_before, rows_after)`` across ``messages+queue`` so the caller can log the carryover-fix
    evidence. Never called for SQLite (the runner gives each SQLite step its own DB file instead)."""
    from messagefoundry.config.settings import load_settings

    settings = load_settings(environ=env).store
    if backend == "sqlserver":
        from messagefoundry.store.sqlserver import SqlServerStore

        ss_store = await SqlServerStore.open(settings)
        try:
            async with ss_store._pool.acquire() as conn:
                cur = await conn.cursor()
                before = await _count_pipeline_rows_sqlserver(cur)
                # DELETE (not TRUNCATE): `queue` FKs `messages`, and TRUNCATE is blocked by an FK
                # reference — the ordered DELETE (children first) is what the store tests use.
                for table in _SQLSERVER_PIPELINE_TABLES:
                    await cur.execute(f"DELETE FROM {table}")
                await conn.commit()
                after = await _count_pipeline_rows_sqlserver(cur)
        finally:
            await ss_store.close()
        return before, after
    if backend == "postgres":
        from messagefoundry.store.postgres import PostgresStore

        pg_store = await PostgresStore.open(settings)
        try:
            before = await _count_pipeline_rows_postgres(pg_store)
            # Postgres has no legacy `outbox` table; one CASCADE TRUNCATE clears the staged pipeline.
            await pg_store._pool.execute(
                "TRUNCATE message_events, queue, response, delivered_keys, messages"
                " RESTART IDENTITY CASCADE"
            )
            after = await _count_pipeline_rows_postgres(pg_store)
        finally:
            await pg_store.close()
        return before, after
    raise ConnScaleError(f"cannot reset store for unknown server backend {backend!r}")


async def _count_pipeline_rows_sqlserver(cur: Any) -> int:
    """messages + queue row count (the two most indicative pipeline tables) on an open SQL Server
    cursor — the carryover-fix evidence gauge."""
    total = 0
    for table in ("messages", "queue"):
        await cur.execute(f"SELECT COUNT(*) FROM {table}")
        row = await cur.fetchone()
        total += int(row[0]) if row and row[0] is not None else 0
    return total


async def _count_pipeline_rows_postgres(store: Any) -> int:
    """messages + queue row count on an open Postgres store — the carryover-fix evidence gauge."""
    total = 0
    for table in ("messages", "queue"):
        n = await store._pool.fetchval(f"SELECT count(*) FROM {table}")
        total += int(n) if n is not None else 0
    return total


def _startup_failure_detail(exc: BaseException, node: EngineNode) -> str:
    """Fold the engine's LOG TAIL into a startup-failure detail string (captured before the node is
    stopped + its log unlinked). Avoids duplicating a tail an inner raise already embedded."""
    detail = str(exc)
    tail = node.log_tail()
    if tail and tail not in detail:
        detail = f"{detail}\n{tail}"
    return detail


def _pooled_miss_reason(detail: str) -> str:
    """Turn a pooled-arm startup failure into the recorded miss reason. Attribute it to the SQL Server
    RCSI fail-closed gate ONLY when the engine log actually shows that gate; otherwise surface the REAL
    failure (with its log tail) so nobody flips RCSI chasing an unrelated defect."""
    if _is_rcsi_gate(detail):
        return (
            "engine refused to start under claim_mode=pooled -- READ_COMMITTED_SNAPSHOT is OFF on the "
            "target SQL Server DB (require_rcsi_for_pooled=true fail-closed gate); set RCSI ON on the "
            "target DB or MEFOR_PIPELINE_REQUIRE_RCSI_FOR_POOLED=false for a smoke (production wants "
            "RCSI on)"
        )
    return (
        "engine failed to start under claim_mode=pooled -- NOT the RCSI gate; real startup failure "
        f"(engine log tail below):\n{detail}"
    )


def _is_rcsi_gate(detail: str) -> bool:
    """True iff a startup-failure detail carries the ``require_rcsi_for_pooled`` RuntimeError signature
    (the pooled-mode RCSI-off fail-closed gate), not some other crash. Matches the store's raised
    message + the traceback frame name, both of which land in the captured log tail."""
    if "READ_COMMITTED_SNAPSHOT" not in detail:
        return False
    return "require_rcsi_for_pooled" in detail or "pooled claim mode requires" in detail


async def _await_node_healthy(node: EngineNode, *, timeout: float) -> None:
    import httpx

    from harness.load.tlsmat import harness_ssl_context

    start = time.perf_counter()
    # Pin to the run's own certificate (harness.load.tlsmat): the harness minted it and handed it to
    # the node as operator-supplied [api] material, so it is on disk before the process starts. That
    # is what makes pinning cheaper than skipping verification here -- there is no file to wait for.
    async with httpx.AsyncClient(timeout=4.0, verify=harness_ssl_context()) as client:
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
                proc = await loop.run_in_executor(None, fd_sampler.sample_proc)
                _PROC_BY_SAMPLE[id(sample)] = proc
            out.append(sample)
        with contextlib.suppress(TimeoutError):
            await asyncio.wait_for(stop.wait(), timeout=interval)


# OS-side process readings (handle count + CPU-seconds + working set) are keyed to the EngineSample
# they were taken alongside (EngineSample is frozen + shared, so we don't bloat it with connscale-only
# footprint fields). A small side map by sample identity, drained when the record is built.
_PROC_BY_SAMPLE: dict[int, ProcSample] = {}


async def _time_reload(poller: EnginePoller) -> float | None:
    client = poller.client
    if client is None:
        return None
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, time_reload, client, None)


def _build_record(
    *,
    claim_mode: str,
    fuse_mode: bool,
    batch_mode: bool,
    mode: str,
    count: int,
    aggregate_rate: float,
    metrics_counters: Counters,
    ack_hist: Histogram,
    poller: EnginePoller,
    samples: list[EngineSample],
    drain_seconds: float | None,
    reload_seconds: float | None,
    audit_live: IntakeAudit | None = None,
    audit_final: IntakeAudit | None = None,
) -> ConnScaleRecord:
    c = metrics_counters.snapshot()
    base, final = poller.baseline, poller.final
    # Budget = this step's connection count. NOT "~one stranded in-flight per connection" — that
    # model was retired (this sender's `_inflight` is unbounded, so stranding scales with
    # rate x ACK-latency): `_reconcile` treats the count only as a small-run FLOOR under its
    # half-the-run fraction, and its separate intake floor keeps `read >= sent // 2` required here
    # even when `count` exceeds half the step's sends (the short-hold smoke cells).
    no_loss = _reconcile(c, base, final, unconfirmed_budget=count)
    live = audit_live if audit_live is not None else intake_audit.not_run("audit not wired")
    post = audit_final if audit_final is not None else intake_audit.not_run("audit not wired")
    # BACKLOG #1292: ATTRIBUTE the reconcile's own failure text, never soften it. `ok` is untouched --
    # a genuine invariant failure still fails the step on the count check exactly as before -- and the
    # audit verdict is APPENDED so a CI reader gets the attribution in the same message that
    # currently gives them only a number they cannot act on.
    if not no_loss.ok and post.verdict != intake_audit.VERDICT_NOT_RUN:
        no_loss = replace(no_loss, detail=f"{no_loss.detail}; {post.summary()}")
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

    # Wall #3: empty-claim RATES over the step's sample window (Δcount / Δt), SEPARATED into
    # idle-poll vs wake-fanout. That window is the hold PLUS the post-drain tail; `_empty_claim_rates`
    # defines it once and this comment does not restate it (BACKLOG #1420).
    total_per_s, idle_per_s, wake_per_s = _empty_claim_rates(samples)

    # Achieved throughput = engine read/written deltas over the SAME window as the empty-claim rates
    # (msg/s actually absorbed/delivered vs the OFFERED aggregate rate) — the A/B non-regression guard.
    achieved_read_per_s, achieved_written_per_s = _throughput_rates(samples)

    # Wall #3, the ASSERTED form: empty claims per MESSAGE ABSORBED (BACKLOG #1101). Both rates above
    # are Δ/span over that same window, so dividing them cancels the span exactly and leaves
    # Δclaims/Δread — no wall clock, and therefore nothing for a mid-hold reload stall to move. (It is
    # NOT contention-immune; that claim was retracted in `_empty_claims_per_msg`, BACKLOG #1211.) This
    # is what `_empty_claims_base_reading_slo` reads; the per-second form is retained for the report
    # because it is the operator-facing number.
    empty_per_msg = _empty_claims_per_msg(total_per_s, achieved_read_per_s)

    # Wall #4 + footprint: handle peak + CPU-seconds + working set, drained from the side map (each
    # None where the OS probe couldn't read).
    proc = _drain_proc(samples)

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
        timeouts=c.timeouts,
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
        empty_claims_per_msg=empty_per_msg,
        fd_count_peak=proc.handles_peak,
        # Carried BESIDE fd_count_peak, never instead of it: a consumer that sees None needs to know
        # whether the probe could not measure or measured nothing, and those are different verdicts.
        fd_probe_ticks=proc.probe_ticks,
        fd_probe_degraded_ticks=proc.probe_degraded_ticks,
        fd_probe_degraded=proc.probe_degraded,
        reload_seconds=reload_seconds,
        ack_p50_ms=ack.p50_ms,
        ack_p95_ms=ack.p95_ms,
        ack_p99_ms=ack.p99_ms,
        claim_mode=claim_mode,
        achieved_read_per_s=achieved_read_per_s,
        achieved_written_per_s=achieved_written_per_s,
        cpu_seconds_total=proc.cpu_seconds_total,
        cpu_util_cores_peak=proc.cpu_util_cores_peak,
        cpu_util_cores_mean=proc.cpu_util_cores_mean,
        working_set_peak_bytes=proc.working_set_peak_bytes,
        fuse_thread_hops=fuse_mode,
        batch_handoff_statements=batch_mode,
        intake_audit=post,
        intake_audit_live=live,
    )


@dataclass(frozen=True)
class _Excusal:
    """How many unconfirmed sends the intake bound forgives this step, and whether that broke."""

    unconfirmed: int
    budget: int
    excused: int
    over_budget: bool


def _excusal(c: Counters, *, unconfirmed_budget: int) -> _Excusal:
    """THE definition of the unconfirmed-send excusal, extracted so ``_reconcile`` and the BACKLOG
    #1292 intake audit compute the SAME ``sent - excused``.

    The audit exists to explain the ``engine_read {read} < confirmed sent {sent - excused}`` message,
    so it has to be triggered by that exact quantity. A second copy of this arithmetic beside it
    would let the audit fire on a shortfall the reconcile does not report, or stay silent on one it
    does -- either way attributing the wrong failure. Behaviour is verbatim what ``_reconcile``
    computed inline before the extraction.
    """
    unconfirmed = c.timeouts
    # Three quarters, not half — half was sized against a 16% worst-observed and windows-2025 has
    # since produced 51% on a lossless run, failing `main` at 9b03057f by ONE message. `excused` is
    # clamped rather than zeroed so an over-budget failure stops claiming intake loss it cannot show.
    # `ok` still requires `not over_budget`, so the verdict is unchanged. Full rationale: report.py.
    budget = max(unconfirmed_budget, 3 * c.sent // 4)
    over_budget = unconfirmed > budget
    return _Excusal(unconfirmed, budget, 0 if over_budget else unconfirmed, over_budget)


def _read_shortfall(
    c: Counters,
    base: EngineSample | None,
    final: EngineSample | None,
    *,
    unconfirmed_budget: int,
) -> int:
    """``confirmed sent - engine_read`` -- the shortfall ``_reconcile`` reports as intake loss, and
    the trigger for the LIVE intake audit. 0 when the engine gauges are unavailable (there is then no
    shortfall to attribute; ``_reconcile`` fails the step on its own for that)."""
    if base is None or final is None:
        return 0
    return (
        c.sent
        - _excusal(c, unconfirmed_budget=unconfirmed_budget).excused
        - (final.read - base.read)
    )


def _unexplained_shortfall(
    c: Counters, base: EngineSample | None, final: EngineSample | None
) -> int:
    """The part of the shortfall NO excusal can forgive -- ``sent - unconfirmed - engine_read``.

    THE PRODUCER OWNS THIS BECAUSE ONLY THE PRODUCER CAN COMPUTE IT. ``_read_shortfall`` subtracts
    ``excused``, which ``_excusal`` CLAMPS TO 0 over budget, and it then returns a bare int -- so the
    clamp state is destroyed one line after being computed. A consumer handed only that int cannot
    tell the two worlds apart: in-budget the unconfirmed sends are ALREADY subtracted out, so a
    residual shortfall is a genuine gauge finding, while over-budget the same number silently
    contains them. Comparing the shortfall against the unconfirmed COUNT to guess which world it is
    gets the common (in-budget) case backwards and would silence a real gauge finding.

    Subtracting the UNCLAMPED ``c.timeouts`` makes the quantity mean the same thing in both worlds,
    so the audit never has to reconstruct budget arithmetic it does not own. Uses ``c.timeouts`` --
    the same input ``_excusal`` calls ``unconfirmed`` -- rather than the ledger, keeping one
    definition of the population.
    """
    if base is None or final is None:
        return 0
    return c.sent - c.timeouts - (final.read - base.read)


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
    # A `timeouts`-counted message (in-flight at a connection close with no ACK seen — a mid-run reset
    # or the stop-grace expiring) is UNCONFIRMED, not lost: `sent` was counted at write-buffer time, so
    # the frame may never have left the closed socket. Requiring `read >= sent` false-fails exactly when
    # timeouts > 0 (the "lost 1 on intake" CI flake); requiring `read >= sent - timeouts` accepts the
    # unconfirmed sends as unconfirmed while ANY FURTHER shortfall is a real, confirmed-then-lost
    # message and still fails. With timeouts == 0 (every healthy run) it is exactly read >= sent.
    #
    # BUT the excusal must never go VACUOUS: with `timeouts == sent` an unbounded excusal degrades the
    # intake bound to `read >= 0` and a total ACK-path regression would pass zero_loss. That cap used
    # to be `unconfirmed_budget` alone, modelled as "~one stranded in-flight frame per connection" —
    # a model this sender breaks (`_inflight` is an UNBOUNDED deque; open-loop sends are paced by the
    # offered rate, not an ACK slot), so genuine teardown stranding scales with rate x ACK-latency,
    # not the connection count. Bound it as a FRACTION instead — at most three quarters of the run, floored by the
    # connection count for tiny runs.
    #
    # That cap ALONE does NOT keep `read >= sent // 2` required, though the comment here used to claim
    # it did: `max()` treats the connection count as a FLOOR, and THIS call site passes the step's
    # `count` verbatim (_build_record above). A short, low-rate step sends barely more than one
    # message per connection — connscale-smoke's N=100 cell is ~105 sends against budget
    # max(100, 52) = 100 — so the count wins the max() and the bound collapses to `read >= 5`. So the
    # guarantee is enforced SEPARATELY below as an intake floor the excusal cannot lower. See
    # harness/load/report.py's copy for the full rationale; the three copies are kept in step
    # deliberately.
    ex = _excusal(c, unconfirmed_budget=unconfirmed_budget)
    unconfirmed, budget, excused, over_budget = (
        ex.unconfirmed,
        ex.budget,
        ex.excused,
        ex.over_budget,
    )
    read_short = sent - excused - read
    # The anti-vacuity guarantee, independent of the excusal: at least half the sends must be
    # observed at intake whatever the budget forgives (nothing clamps `excused` to `sent`, so without
    # this a `timeouts > sent` run would pass at `read >= 0`). Zero at sent == 0, rounds DOWN on an
    # odd `sent`, so it is never stricter than the documented bound.
    floor_short = sent // 2 - read
    deliver_short = written - sink_received
    drained = backlog == 0
    ok = read_short <= 0 and floor_short <= 0 and deliver_short <= 0 and drained and not over_budget
    parts: list[str] = []
    if read_short > 0:
        parts.append(
            f"engine_read {read} < confirmed sent {sent - excused} (lost {read_short} on intake)"
        )
    if floor_short > 0:
        parts.append(
            f"engine_read {read} < intake floor {sent // 2} (half of {sent} sent) — "
            f"the unconfirmed-send excusal cannot lower this floor"
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
            f"({budget} = max(connections, three quarters of the run)) — systemic no-ACK fault "
            f"(possible accepted-and-dropped); nothing excused"
        )
    elif unconfirmed > 0 and read < sent:
        # Honest reporting either way: the gap is attributed to unconfirmed sends, not silently absorbed.
        parts.append(
            f"{unconfirmed} unconfirmed send(s) (no ACK before connection close) "
            f"not observed at intake — not counted as loss"
        )
    detail = "; ".join(parts) if parts else "read>=sent, sink_received>=written, backlog drained"
    return NoLoss(ok, sent, read, written, sink_received, backlog, detail)


def _empty_claim_rates(samples: list[EngineSample]) -> tuple[float, float, float]:
    """Empty-claim rates over the sweep step's sample window: (total/s, idle_poll/s, wake_fanout/s),
    from ``samples[0]`` to ``samples[-1]``. SEPARATED — never summed into one number (critic
    must-change #3).

    **THE WINDOW IS NOT THE HOLD, AND THIS IS THE ONE PLACE THAT SAYS SO** (BACKLOG #1420). Every
    other description of it points here rather than restating it. ``samples[0]`` is the first in-hold
    reading, but ``samples[-1]`` is NOT in-hold: the step appends one final engine sample after
    ``sampler_stop.set()``, after ``driver.stop(_STOP_GRACE)``, after ``poller.await_drain(...)`` and
    after ``asyncio.sleep(_SETTLE)`` — and, on the drained path, after ``sample_until_reconciled``
    has spent up to a second ``drain_timeout_s``. So the span is the hold PLUS that whole tail,
    bounded under the shipped ``connscale-smoke`` profile by 5.0 + 30.0 + 0.5 + 30.0 = 65.5 s against
    a 3.0 s hold. **Five sites called this window "first to last in-hold samples"**, and the last
    sample is not in-hold, so all five described a window the code does not compute. Scope, because
    the count depends on it: needle ``in-hold``, corpus ``harness/load/connscale/`` plus
    ``tests/test_connscale_empty_claims_per_msg.py``. Three of the five are in this file. All five
    now point here instead of restating it.

    **WHAT THAT COSTS THE METRIC.** Through the tail the engine keeps polling an emptying queue, so
    ``empty_claims`` can keep rising while ``read`` stops — an idle-drain regime the rates do not
    intend to cover. The algebra in :func:`_empty_claims_per_msg` is unaffected (the span still
    cancels); what the tail changes is which regime both deltas cover. **The tail is currently INSIDE
    the number.** Narrowing the window to exclude the final sample would change what the number
    MEANS, so readings either side of such a change would not be comparable — that is BACKLOG #1420's
    candidate fix (a), and it is not taken here.
    """
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


def _empty_claims_per_msg(total_per_s: float, achieved_read_per_s: float) -> float | None:
    """Empty claims per message absorbed — the wall-clock-free form of wall #3 (BACKLOG #1101).

    Both inputs are Δ/span over the SAME window — ``samples[0]`` to ``samples[-1]``, defined once in
    :func:`_empty_claim_rates` — so ``span`` cancels and this is exactly ``Δempty_claims / Δread``.
    That removes the per-SECOND form's defect, which keeps ``span`` in the denominator so a slow arm
    reads as an improvement (#1101). **That window is the hold PLUS the post-drain tail, not the hold
    alone**; read :func:`_empty_claim_rates` for what the tail is and what it costs (BACKLOG #1420).

    **IT IS NOT CONTENTION-IMMUNE, AND THIS DOCSTRING USED TO SAY IT WAS** (BACKLOG #1211). The old
    wording — *"that is why it survives runner contention: slowing the run scales numerator and
    denominator identically"* — is an argument from the algebra that the measurements refute. Three
    excursions past the SLO band were recorded on `windows-2025`, on pull requests with ZERO overlap
    with connscale, the store or the pipeline:

    ===========  ============================  =====================  ==========
    PR           reading at ``N=24``           band floor             short by
    ===========  ============================  =====================  ==========
    #343         36                            48.4 * 0.75 = 36.30    0.30
    #355         34.9                          48.2 * 0.75 = 36.15    1.25
    ===========  ============================  =====================  ==========

    WHY THE ALGEBRA DOES NOT DELIVER WHAT IT LOOKS LIKE IT DELIVERS: ``span`` cancelling makes the
    ratio free of WALL CLOCK, not free of CONTENTION. The two counters do not respond to load
    identically — empty claims are produced by POLLING, which continues on its own cadence, while
    reads are produced by WORK ARRIVING. Under contention those two decouple, so their ratio moves
    even though neither is divided by time. Cancelling ``span`` was necessary and is not sufficient.

    **THOSE ROWS ARE NOW THE TAIL OF A SAMPLED DISTRIBUTION.** The readings are real and the
    correction above still holds. What has changed is that the population they came from has since
    been sampled, and it is recorded ONCE, in BACKLOG #1211 -- the numbers live there, along with what
    the sample does not cover, and are deliberately not restated at this line. Read against that
    sample, these rows sit in a wide left tail that healthy hosted-runner legs occupy routinely, with
    no connscale change anywhere near them.

    An earlier reading of those same excursions is SUPERSEDED by that harvest: this docstring used to
    argue that the margin was WIDENING across independent runs (0.30 then 1.25) against a ``prior``
    that barely moved, and so was a trend rather than noise. A handful of points cannot separate a
    trend from a wide spread. The harvest measured the spread.

    **THE HOLD ON THE BAND IS DISCHARGED (BACKLOG #1211).** This docstring used to say the band must
    not be touched until several deliberate samples at one N on a hosted runner existed, because
    picking a wider number from the failures on hand is how the 0.25 came to be trusted in the first
    place. THE SAMPLES NOW EXIST, and they retired the band rather than widening it: the vs-N SLO on
    this metric is gone, ``_empty_claims_base_reading_slo`` replaced it with a strictly-positive
    base-count sign test, and nothing in CI now grades this ratio against a threshold. The ratio is
    still computed and RECORDED on every run, so BACKLOG #1415 can arm the predicted herd floor from a
    distribution instead of from excursions.

    Do not re-open the hold from the rows above. A sample selected on having excursioned cannot
    measure the distribution it excursioned from -- which is exactly why the harvest was run.

    Returns ``None`` when no messages were absorbed in the window. The ratio is genuinely undefined
    there and returning 0.0 would be a fabricated reading that then chains through the monotonicity
    comparison as a real one.
    """
    if achieved_read_per_s <= 0.0:
        return None
    return max(0.0, total_per_s / achieved_read_per_s)


def _throughput_rates(samples: list[EngineSample]) -> tuple[float, float]:
    """Achieved (read/s, written/s) over the window, first→last sample (same span as the empty-claim
    rates), so both arms are measured identically for the A/B non-regression guard."""
    if len(samples) < 2:
        return 0.0, 0.0
    first, last = samples[0], samples[-1]
    span = last.elapsed_s - first.elapsed_s
    if span <= 0.0:
        return 0.0, 0.0
    read = (last.read - first.read) / span
    written = (last.written - first.written) / span
    return max(0.0, read), max(0.0, written)


#: A3: a readable process whose cumulative CPU counter is EXACTLY flat across at least this many seconds
#: is a wrong binding, not an idle engine — the CPU fields degrade to None (a visible gap) rather than a
#: plausible 0.00. Sized above the sampler's coarse tick so a single short window can't trip it.
_CPU_FLAT_GAP_SPAN_S = 5.0


@dataclass(frozen=True)
class _ProcDerived:
    """Derived process-footprint gauges over the window (each None where the OS probe couldn't read).

    The last three fields are the window's probe PROVENANCE, not gauges: they say how much of the
    window the OS probe actually measured and, where it did not, WHY. Without them a ``None`` gauge is
    indistinguishable across a starved host, a dead process tree and a broken enumerator — three
    conditions with three different verdicts."""

    handles_peak: int | None
    cpu_seconds_total: float | None
    cpu_util_cores_peak: float | None
    cpu_util_cores_mean: float | None
    working_set_peak_bytes: int | None
    #: How many probe ticks this window collected at all. The SCOPE for the count below: "2 degraded"
    #: means nothing without it, and 2-of-3 and 2-of-200 warrant opposite reactions.
    probe_ticks: int
    #: How many of those ticks were full gaps (:attr:`ProcSample.degraded` set).
    probe_degraded_ticks: int
    #: The DISTINCT degradation causes seen across the window, sorted. Values are
    #: :class:`ProbeDegraded` members, carried as plain strings so the report layer need not import
    #: the probe. Empty when every tick read something.
    probe_degraded: tuple[str, ...]


def _drain_proc(samples: list[EngineSample]) -> _ProcDerived:
    """Drain the per-sample :class:`ProcSample` side map and derive the footprint gauges: peak handle
    count, peak working set, total CPU-seconds consumed over the window, and the peak/mean CPU
    utilisation (cores busy). A cumulative CPU-seconds counter isn't meaningfully "averaged", so
    peak/mean are reported as cores-busy.

    CPU is derived as a **piecewise sum over consecutive intervals whose summed-over PID set is
    unchanged**, NOT as endpoint-difference (``last − first``). Each reading is a SUM across the engine
    subtree, and A3's periodic re-resolution can add a joining ``serve --shard`` worker or drop a
    departing one mid-window. Differencing sums taken over DIFFERENT process sets is not a clean CPU
    delta — a joining PID inflates it by that process's whole lifetime CPU, a departing one drives it
    negative into the ``max(0.0, …)`` clamp. So each same-set interval contributes ``max(0, Δcpu)`` to
    the total and its elapsed span to ``covered_span``; a set-change interval is degraded to a gap (it
    contributes nothing), and the peak-cores loop is gated the same way. The flat-CPU-gap guard and
    ``cpu_mean`` are recomputed over ``covered_span``, and the CPU gauges degrade to ``None`` when zero
    clean intervals contributed (or fewer than two CPU readings exist). See BACKLOG #220.

    It also carries the window's probe PROVENANCE through to the record: how many ticks were collected,
    how many of those were full gaps, and the distinct causes behind them. The gauges alone cannot
    express the difference between "the host was too slow to answer" and "the enumerator returned zero
    rows" — both are ``None`` — and a consumer that has to choose a verdict needs exactly that."""
    readings: list[tuple[float, ProcSample]] = []
    for s in samples:
        proc = _PROC_BY_SAMPLE.pop(id(s), None)
        if proc is not None:
            readings.append((s.elapsed_s, proc))
    handles = [p.handles for _, p in readings if p.handles is not None]
    working_set = [p.working_set_bytes for _, p in readings if p.working_set_bytes is not None]
    # A CPU reading is usable only when both its counter AND the PID set it summed are known — the set
    # is what lets us tell a clean interval from a membership-changed one (#220).
    cpu_readings = [
        (e, p.cpu_seconds, p.cpu_pids)
        for e, p in readings
        if p.cpu_seconds is not None and p.cpu_pids is not None
    ]

    handles_peak = max(handles) if handles else None
    ws_peak = max(working_set) if working_set else None

    # Probe PROVENANCE for the window. A gauge that reads None because the host was starved and one
    # that reads None because the enumerator is broken are the same value and opposite findings, so the
    # causes the probe recorded per tick are carried through to the record rather than discarded here.
    probe_ticks = len(readings)
    degraded = [p.degraded for _, p in readings if p.degraded is not None]
    causes = tuple(sorted({str(c) for c in degraded}))

    def _derived(
        cpu_total: float | None, cpu_peak: float | None, cpu_mean: float | None
    ) -> _ProcDerived:
        """Assemble the result, filling the provenance fields in ONE place. The CPU gauges have three
        legitimate exit paths; routing them all through here means no path can ship a gap that has
        dropped its cause on the way out."""
        return _ProcDerived(
            handles_peak=handles_peak,
            cpu_seconds_total=cpu_total,
            cpu_util_cores_peak=cpu_peak,
            cpu_util_cores_mean=cpu_mean,
            working_set_peak_bytes=ws_peak,
            probe_ticks=probe_ticks,
            probe_degraded_ticks=len(degraded),
            probe_degraded=causes,
        )

    cpu_total: float | None = None
    cpu_mean: float | None = None
    cpu_peak: float | None = None
    if len(cpu_readings) >= 2:
        total = 0.0
        covered_span = 0.0
        peak = 0.0
        clean_intervals = 0
        for (ea, ca, pa), (eb, cb, pb) in zip(cpu_readings, cpu_readings[1:], strict=False):
            if pa != pb:
                # Subtree membership changed across this interval: the two summed counters cover
                # DIFFERENT process sets, so their difference is not a CPU delta. Degrade to a gap.
                continue
            d = eb - ea
            if d <= 0.0:
                continue
            delta = max(0.0, cb - ca)
            total += delta
            covered_span += d
            peak = max(peak, delta / d)
            clean_intervals += 1
        if clean_intervals == 0:
            # Every interval was a membership change (or non-advancing time): no clean CPU measurement
            # survived, so report a gap rather than a fabricated 0.00.
            return _derived(None, None, None)
        # A3 / B-class guard, recomposed over the summed clean span: a FLAT cumulative CPU counter over
        # a non-trivial covered span is not a physical "0% CPU" — the counter's unit is 100 ns (Windows
        # ticks) / a clock tick (POSIX), and we only got here because the process was READABLE. A live
        # process that consumed literally zero CPU across seconds does not exist; the sampler is bound to
        # the wrong process (an idle launcher/supervisor, or a subtree cached before the shard workers
        # spawned). Reporting 0.00 here is the signature defect of this harness: a plausible number where
        # there is no measurement. Emit an explicit gap (None) so it renders "n/a" and draws no verdict.
        if total == 0.0 and covered_span >= _CPU_FLAT_GAP_SPAN_S:
            return _derived(None, None, None)
        cpu_total = total
        cpu_peak = peak
        if covered_span > 0.0:
            cpu_mean = total / covered_span
    return _derived(cpu_total, cpu_peak, cpu_mean)


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
    if profile.intake_audit:
        # BACKLOG #1292, and DELIBERATELY NOT folded into zero_loss: this is a per-MESSAGE check and
        # zero_loss is a per-COUNT one, so they can disagree, and each disagreement is informative.
        # It is strictly ADDITIONAL -- it can fail a step whose counts reconciled, because a
        # confirmed-then-absent message that happened to be excused as a timeout passes the count
        # check today. PROBE_UNUSABLE does NOT fail here: an unanswerable instrument is not evidence
        # of a defect in either direction, and it is reported as its own observation instead.
        suspect = [r for r in records if r.intake_audit.engine_suspect]
        # THE SCOPE TRAVELS WITH THE VERDICT, and that is not decoration here. `_evaluate_slos` is
        # SHARED with the batch-box aggregate (batchbox.py), whose records are folded from
        # remote-driver reports and carry a NOT_RUN audit by construction -- those driver processes
        # poll a REMOTE engine and have no store to read. A bare "clean" there would be a green
        # earned by nothing at all. So the observation always names how many steps were actually
        # audited, and zero-audited says so in those words instead of passing itself off as a finding
        # of no defect. The per-step guarantee is asserted in tests/test_connscale_smoke.py, where
        # the audit genuinely runs; this line is the operator-facing summary of it.
        audited = sum(1 for r in records if r.intake_audit.conclusive)
        if suspect:
            observed = "; ".join(
                f"{r.sweep_mode}@N={r.count} {r.intake_audit.summary()}" for r in suspect
            )
        elif audited == 0:
            observed = (
                f"NOT AUDITED -- 0 of {len(records)} step(s) carry an intake audit, so this says "
                f"nothing about per-message intake"
            )
        else:
            observed = f"clean ({audited} of {len(records)} step(s) audited)"
        out.append(
            SloCheck("intake_audit", "no accept-ACKed message absent", observed, not suspect)
        )
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
    if slo.empty_claims_base_reading:
        out.append(_empty_claims_base_reading_slo(profile, records))
    return out


def _empty_claims_base_reading_slo(
    profile: ConnScaleProfile, records: list[ConnScaleRecord]
) -> SloCheck:
    """Wall #3, asserted only as far as a hosted runner can actually measure it (BACKLOG #1211).

    THIS REPLACED A vs-N MONOTONICITY GATE THAT WAS MEASURABLY BROKEN IN FIVE WAYS. The evidence is
    recorded ONCE, in BACKLOG #1211 -- the counts live there and are deliberately not restated at this
    line, and so does what the harvest does NOT cover: it read a bounded scan window, and a run that
    was cancelled or killed uploaded no artifact and contributed no legs at all. So a low observed
    false-positive rate there is weak evidence about flake and is NOT evidence this check cannot fire.
    What matters at this line is what is now asserted and what is not.

    ASSERTED: every ``per_lane`` lane that produced a base-count reading produced a STRICTLY POSITIVE
    one. That is narrow on purpose. It is the one thing about this metric a 4-vCPU hosted runner
    measures without ambiguity, it fires on a dead counter -- the case the retired gate PASSED, since
    ``not (0.0 < 0.0)`` is true -- and it cannot flake on level noise, because it is a sign test rather
    than a threshold.

    NOT ASSERTED: the predicted herd floor. ``herd_floor_readings`` computes it and both emitters
    RECORD it on every run, pass or fail, but no verdict here rides on it. Its own pre-landing check
    failed: on run 33448760672, a push to ``main`` whose ``test (windows-2022, py3.14)`` job PASSED,
    the base reading was 13.12 against a floor of 15.30. Gating on it would have reddened a green leg,
    which is the defect this item exists to remove. Enabling it once its own distribution is harvested
    is BACKLOG #1415.

    NOT ASSERTED EITHER: the vs-N slope, in any form. Nothing in CI now claims the curve rises. That
    is a real loss and BACKLOG #1211 names it as one.

    ZERO GRADED LANES REPORTS ``ok=True`` and says so in words, following the ``intake_audit`` shape a
    few lines above. The run-level bound -- that SOME lane was graded -- belongs in the smoke test,
    where the metric genuinely runs; that is exactly where wall #4 already puts its equivalent.
    """
    readings = herd_floor_readings(
        records, lambda r: r.empty_claims_per_msg, base_count=min(profile.counts)
    )
    graded = [r for r in readings if r.ok is not None]
    dead = [r for r in graded if r.value is not None and r.value <= 0.0]
    expectation = "a positive empty-claims-per-message reading at the base connection count"
    if dead:
        observed = "; ".join(
            f"{r.label}@N={r.count}: {r.value} -- the empty-claim counter did not move"
            for r in dead
        )
        return SloCheck("empty_claims_base_reading", expectation, observed, False)
    if not graded:
        reasons = "; ".join(f"{r.label}: {r.not_graded}" for r in readings) or "no lanes"
        return SloCheck(
            "empty_claims_base_reading",
            expectation,
            f"NOT GRADED -- 0 of {len(readings)} lane(s) produced a base reading at "
            f"N={min(profile.counts)} ({reasons}), so this says nothing about wall #3",
            True,
        )
    return SloCheck(
        "empty_claims_base_reading",
        expectation,
        f"present ({len(graded)} of {len(readings)} lane(s) graded)",
        True,
    )


#: Noise tolerance for the loose monotonicity smoke: a larger-N metric may dip up to this fraction below a
#: smaller-N reading without failing. These are timing-derived counters and CI runners are noisy
#: (mf-ci-test-flakes), so only a drop past the band should fail.
#:
#: THIS COMMENT USED TO CLAIM 0.25 "catches a genuine collapse (a halving)". THAT IS FALSIFIED (BACKLOG
#: #1211). A reading at half its prior does trip the band, but so do healthy runs: the measured
#: empty-claims population on at least one CI leg reaches well below half the prior with nothing wrong.
#: The band therefore does not SEPARATE a collapse from health, which is what "catches" implied. The
#: distribution behind that is recorded once, in BACKLOG #1211, and is not restated here.
#:
#: WHO STILL GRADES AGAINST THIS VALUE: `fd_count_monotonic`, and nothing else. `empty_claims_monotonic`
#: was retired by #1211, so every number in this comment's own history -- the strict `>=` that flaked on
#: ~10% jitter (empty_claims 398.7 < 442.9 on windows-2022) included -- is evidence about a metric this
#: constant no longer gates. **DO NOT RETUNE 0.25 ON EMPTY-CLAIMS EVIDENCE.** It would be tuning the FD
#: gate against a distribution the FD gate never reads.
#:
#: AND THE FD RATIO DISTRIBUTION HAS NEVER BEEN HARVESTED. So 0.25 is inherited, not validated, for its
#: one remaining consumer. Harvest FD ratios before moving it; the same fitted-to-the-failures-on-hand
#: mistake is available here and would look exactly as reasonable as it did the first time.
#:
#: The empty-claims emitters still PASS this value as their recorded band width (`render_readings_markdown`
#: / `readings_payload`), but nothing grades against it there -- the rows are recorded, and the width is
#: held fixed so they stay comparable with the payloads already harvested for #1211. Changing it would
#: break that comparability silently, on top of retuning the FD gate.
_MONOTONIC_TOLERANCE = 0.25


def _monotonic_slo(  # type: ignore[no-untyped-def]
    name: str, records: list[ConnScaleRecord], key, *, tolerance: float = _MONOTONIC_TOLERANCE
) -> SloCheck:
    """A LOOSE per-mode monotonicity smoke: within a sweep mode the metric at a larger N must be >= a
    smaller N **minus a noise ``tolerance``** (default 25%) — the wall exists and scales, but these are
    timing-derived counters on noisy CI runners (mf-ci-test-flakes), so a small dip is jitter, not a
    regression. Fails only on a real drop (``v < prior * (1 - tolerance)``). Missing readings (None) are
    skipped, not failed.

    **SCOPE: FD COUNT, AND NOTHING ELSE (BACKLOG #1211).** ``fd_count_monotonic`` over
    ``fd_count_peak`` is the only caller. ``empty_claims_monotonic`` was the other one and was retired:
    a harvest recorded in #1211 sampled the healthy empty-claims spread and found it wide enough that
    this shape could not tell a collapse from a normal hosted-runner leg, and it passed a curve
    flattened to half its healthy value. That harvest is a sample, not a census -- read its own
    coverage limits beside it in #1211, not the counts alone. Do not point this function back at ``empty_claims_per_msg``, and do not read a
    green here as evidence about wall #3 -- that is ``_empty_claims_base_reading_slo``'s subject now.

    THE "SKIPPED, NOT FAILED" RULE ABOVE IS A HOLE THIS FUNCTION CANNOT CLOSE ALONE. Skip every
    reading in a group and it returns ok=True observed='monotonic' having compared no pairs at all.
    The run-level bound that some group actually had a pair to compare lives in
    ``tests/test_connscale_smoke.py`` (WALL #4 NEVER COMPARED), because only a real run knows whether
    the metric was measurable. Any new caller needs its own such bound or it inherits the hole."""
    # The pairing itself — including the group-by-(sweep_mode, claim_mode) rule BACKLOG #1101 records
    # as load-bearing — lives in `monotonic_pairs`. The emitter that records EVERY reading reads the
    # same function, so a passing run and a failing run cannot describe the sequence differently.
    pairs = monotonic_pairs(records, key, tolerance=tolerance)
    breaches = [p for p in pairs if not p.ok]
    observed = (
        "monotonic"
        if not breaches
        else "; ".join(
            f"{p.label}@N={p.count}: {p.value:.3g} < prior {p.prior:.3g} * {p.tolerance_floor:.2f}"
            for p in breaches
        )
    )
    return SloCheck(
        name, f"non-decreasing vs N (±{int(tolerance * 100)}% jitter)", observed, not breaches
    )
