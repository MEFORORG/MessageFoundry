# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""The batch_ab two-box matrix drive (ADR 0075 Bench B) — the engine half + the driver half.

Where a bare ``--connscale batch_ab`` OWNS (co-locates) the engine with the driver + sink, the isolated
statement-batching A/B needs the engine on one box and the driver + the ``>= 6`` sink PROCESSES on
another (the attribution policy: the driver/sink must not steal CPU from the engine, and a single sink
listener caps ~135-144/s delivered). Running that by hand is ~100 hand-orchestrated ``connscale-remote``
drives — one per (batch arm × count × trial) cell, each an RTT point. This module collapses it to TWO
coordinated commands that walk the SAME ``batch_ab`` matrix in lockstep over the file-drop coord:

* :func:`run_batch_engine` (ENGINE box) — for each ``(batch_mode, count, trial)`` cell it launches ONE
  connscale engine (``harness/config/connscale``) with ``MEFOR_PIPELINE_BATCH_HANDOFF_STATEMENTS`` set
  per arm, fusion OFF, and ``MEFOR_PIPELINE_CLAIM_MODE`` per ``--claim-mode``; posts
  :data:`~harness.load.coord.BATCH_CELL_READY` carrying the topology (inbound base, API port, the agreed
  sink band) + the engine subprocess's PID + node id (for external per-PID CPU correlation); waits for
  the driver's :data:`~harness.load.coord.BATCH_CELL_DONE`; tears the engine down; next cell. It NEVER
  drives load and NEVER binds a sink.
* :func:`run_batch_driver` (LOAD-GEN box) — for each cell it waits for that cell's ``BATCH_CELL_READY``,
  runs the ``>= 6`` sink-PROCESS fleet (spawns ``sink_procs`` real ``connscale-remote`` processes, each
  owning a DISJOINT inbound sub-band + a DISJOINT local sink port via ``--engine-index-base 0..k``),
  aggregates their per-proc JSON into ONE cell :class:`~harness.load.connscale.report.ConnScaleRecord`,
  posts ``BATCH_CELL_DONE``, next cell. After the whole matrix it computes the B0/B1 verdict via
  :func:`~harness.load.connscale.compare.build_batch_comparison` and returns a
  :class:`~harness.load.connscale.report.ConnScaleReport` (records + ``batch_comparison``). It NEVER
  spawns an engine.

Both halves derive the cell list from the SAME profile + ``--claim-mode`` (identical iteration order),
so the per-cell run-ids match and the two boxes stay in lockstep across the whole matrix. The channel
carries metadata/counters only — never message bodies or control-id lists (PHI rule).
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import sys
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from harness.load.connscale.compare import build_batch_comparison
from harness.load.connscale.profile import FUSE_OFF, ConnScaleProfile
from harness.load.connscale.report import (
    EXIT_OK,
    EXIT_SLO_VIOLATION,
    ConnScaleRecord,
    ConnScaleReport,
    NoLoss,
)

# Imported through the runner module so a test can monkeypatch these seams on THIS module (the network
# collaborators the structural tests fake): the owned engine subprocess, the health/port preflights, the
# server-store reset, the per-step env builder, and the SLO evaluator.
from harness.load.connscale.runner import (
    _CONFIG_DIR,
    ConnScaleError,
    _await_node_healthy,
    _evaluate_slos,
    _node_env,
    _reset_server_store,
)
from harness.load.coord import BATCH_CELL_DONE, BATCH_CELL_READY, FileDropCoord
from harness.load.failover import EngineNode, FailoverError, _await_port

_HEALTH_TIMEOUT = 30.0
_PORTS_READY_TIMEOUT = 60.0
_STOP_GRACE = 5.0
_DEFAULT_SINK_PROCS = 6  # the >= 5-6 sink-PROCESS attribution gate


# --- the matrix cell ---------------------------------------------------------


@dataclass(frozen=True)
class BatchCell:
    """One cell of the batch_ab matrix. The per-cell id ``(batch_mode, count, trial)`` (plus the fixed
    claim/fuse/sweep axes for full disambiguation) scopes the coord run-id, so the engine + driver
    rendezvous per cell without a shared bus."""

    claim_mode: str
    fuse_mode: bool
    batch_mode: bool
    sweep_mode: str
    count: int
    trial: int

    @property
    def cell_id(self) -> str:
        """A filesystem-safe cell key both halves derive identically (it becomes the coord run-id
        suffix). The essential discriminator is ``(batch_mode, count, trial)``; the claim/fuse/sweep
        segments keep it unambiguous if a profile ever widened those axes."""
        return "-".join(
            (
                self.claim_mode,
                "f1" if self.fuse_mode else "f0",
                "bt1" if self.batch_mode else "bt0",
                self.sweep_mode,
                str(self.count),
                f"t{self.trial}",
            )
        )


def iter_batch_cells(profile: ConnScaleProfile, *, claim_mode: str) -> list[BatchCell]:
    """The batch_ab cell list, in the SAME nesting order :func:`run_connscale` walks (batch arm × sweep
    mode × count × trial). Fusion is pinned OFF (batching does not compose with fusion, ADR 0075) and
    the claim mode is the ``--claim-mode`` pin (batch_ab's profile pins a single ``pooled`` claim axis),
    so both halves — given the same profile + flag — produce the identical, order-stable list."""
    cells: list[BatchCell] = []
    for batch_mode in profile.batch_modes:
        for mode in profile.modes():
            for count in profile.counts:
                for trial in range(profile.trials):
                    cells.append(
                        BatchCell(
                            claim_mode=claim_mode,
                            fuse_mode=FUSE_OFF,
                            batch_mode=batch_mode,
                            sweep_mode=mode,
                            count=count,
                            trial=trial,
                        )
                    )
    return cells


# --- the driver-side band plan (pure) ----------------------------------------


@dataclass(frozen=True)
class BandPlan:
    """One ``connscale-remote`` process's slice of a cell: a DISJOINT inbound sub-band on the engine box
    and a DISJOINT single local sink port, tagged with a distinct ``engine_index_base`` so the >= 6
    processes' control-ids never collide."""

    index: int  # engine_index_base (0..procs-1)
    inbound_base: int  # engine inbound sub-band start (engine_host:inbound_base + i)
    conn_count: int  # inbound connections this process drives
    sink_base: int  # this process's single LOCAL sink listener port
    sink_ports: int  # always 1 (one listener per process = one sink PROCESS)


def plan_driver_bands(
    *, inbound_base: int, count: int, sink_base: int, sink_procs: int
) -> list[BandPlan]:
    """Split a cell's ``count`` inbound connections across ``sink_procs`` DISJOINT bands, one per sink
    PROCESS. Process ``k`` drives a contiguous inbound sub-range ``[inbound_base+offset, +share)`` and
    binds the single local sink port ``sink_base+k`` — so together the bands cover every inbound port
    exactly once (no over-drive, no collision) and the engine's ``sink_procs`` contiguous delivery ports
    line up one-to-one with the ``sink_procs`` sink PROCESSES. The remainder is spread over the first
    ``count % sink_procs`` bands so shares differ by at most one."""
    if count < 1:
        raise ConnScaleError(f"batch cell count must be >= 1, got {count}")
    if sink_procs < 1:
        raise ConnScaleError(f"sink_procs must be >= 1, got {sink_procs}")
    procs = min(
        sink_procs, count
    )  # never a zero-connection band (connscale-remote needs count >= 1)
    base_share, rem = divmod(count, procs)
    plans: list[BandPlan] = []
    offset = 0
    for k in range(procs):
        share = base_share + (1 if k < rem else 0)
        plans.append(
            BandPlan(
                index=k,
                inbound_base=inbound_base + offset,
                conn_count=share,
                sink_base=sink_base + k,
                sink_ports=1,
            )
        )
        offset += share
    return plans


def build_remote_argv(
    plan: BandPlan,
    *,
    engine_host: str,
    api_port: int,
    sink_host: str,
    per_conn_rate: float,
    hold_seconds: float,
    drain_timeout: float,
    report_path: Path,
) -> list[str]:
    """The ``python -m harness connscale-remote`` argv for one band (pure, so the split is unit-testable
    without spawning). One engine URL/band per process, this band's disjoint inbound sub-base + single
    local sink port, and the ``--engine-index-base`` id-disjointness tag."""
    return [
        sys.executable,
        "-m",
        "harness",
        "connscale-remote",
        "--engine-url",
        f"http://{engine_host}:{api_port}",
        "--engine-host",
        engine_host,
        "--inbound-base",
        str(plan.inbound_base),
        "--sink-host",
        sink_host,
        "--sink-base",
        str(plan.sink_base),
        "--sink-ports",
        str(plan.sink_ports),
        "--count",
        str(plan.conn_count),
        "--per-conn-rate",
        repr(per_conn_rate),
        "--hold-seconds",
        repr(hold_seconds),
        "--drain-timeout",
        repr(drain_timeout),
        "--engine-index-base",
        str(plan.index),
        "--report-json",
        str(report_path),
    ]


# --- the driver-side per-cell aggregation (pure) -----------------------------


def aggregate_cell_record(
    cell: BatchCell,
    proc_reports: list[dict[str, Any]],
    *,
    expected_bands: int | None = None,
) -> ConnScaleRecord:
    """Fold the ``sink_procs`` ``connscale-remote`` JSON reports of ONE cell into a single tagged
    :class:`ConnScaleRecord` for the batch comparison.

    The client-side counters are SUMMED (each process drove a disjoint inbound sub-band + owns its own
    sink port): total offered/sent, and the union sink_received across the >= 6 sink ports. The
    engine-total gauges are the MAX across processes (all procs poll the SAME engine's ``/stats``, so
    each already carries the engine-wide read/written total — summing would 6x it): the achieved intake
    "ceiling", the delivered rate, engine_read/engine_written, in_pipeline peak. The aggregate no-loss
    reconcile then compares the engine's read against the TOTAL offered and the UNION sink_received
    against the engine's written — the correct whole-cell reconcile a single process cannot express.

    ``expected_bands`` (the driver passes ``len(plans)``) is a defense-in-depth guard: the fold requires
    EXACTLY that many band reports, so a partial fleet (a lost band) can't quietly fold into a
    spuriously-low but "valid-looking" aggregate. A null/missing engine-total gauge (engine_read /
    engine_written / backlog) is a HARD error for the same reason — coercing it to 0 would fake a clean
    backlog / a low intake ceiling and let a broken cell pass as valid."""
    if not proc_reports:
        raise ConnScaleError(f"cell {cell.cell_id}: no connscale-remote reports to aggregate")
    if expected_bands is not None and len(proc_reports) != expected_bands:
        raise ConnScaleError(
            f"cell {cell.cell_id}: expected {expected_bands} band report(s), got "
            f"{len(proc_reports)} — a partial fleet cannot yield a trustworthy aggregate"
        )

    def _traffic(r: dict[str, Any], key: str) -> int:
        return int(r.get("traffic", {}).get(key, 0))

    def _noloss(r: dict[str, Any], key: str) -> Any:
        return r.get("no_loss", {}).get(key)

    def _thr(r: dict[str, Any], key: str) -> Any:
        return r.get("throughput", {}).get(key)

    def _engine_gauge(key: str) -> int:
        """An engine-wide no-loss gauge taken as the MAX across bands (each proc polls the SAME engine,
        so its report already carries the engine total). A null/missing value is a HARD error — never
        coerced to 0, which would fake a drained backlog or a spuriously-low intake ceiling and let a
        partial/failed cell read as a valid aggregate (ADR 0075 review, defense-in-depth)."""
        vals: list[int] = []
        for r in proc_reports:
            v = _noloss(r, key)
            if v is None:
                raise ConnScaleError(
                    f"cell {cell.cell_id}: a connscale-remote report is missing the engine gauge "
                    f"{key!r}; refusing to coerce a null engine total to 0"
                )
            vals.append(int(v))
        return max(vals)

    agg_sent = sum(_traffic(r, "sent") for r in proc_reports)
    agg_acked = sum(_traffic(r, "acked") for r in proc_reports)
    agg_nak = sum(_traffic(r, "nak") for r in proc_reports)
    agg_deferred = sum(_traffic(r, "deferred") for r in proc_reports)
    agg_timeouts = sum(_traffic(r, "timeouts") for r in proc_reports)
    agg_sink_received = sum(int(_noloss(r, "sink_received") or 0) for r in proc_reports)
    offered = sum(float(r.get("offered_aggregate_rate", 0.0)) for r in proc_reports)

    engine_read = _engine_gauge("engine_read")
    engine_written = _engine_gauge("engine_written")
    backlog = _engine_gauge("backlog")
    achieved_read = max((float(_thr(r, "achieved_aggregate_rate") or 0.0) for r in proc_reports))
    achieved_written = max(
        (float(_thr(r, "delivered_aggregate_rate") or 0.0) for r in proc_reports)
    )
    in_pipeline_peak = max((int(_thr(r, "in_pipeline_peak") or 0) for r in proc_reports), default=0)

    # A timed-out drain in ANY process (drain_seconds None) poisons the cell's worst-case drain — the
    # whole pipeline did not empty for that band (mirrors the fusion comparator's None-poisons rule).
    drains = [_thr(r, "drain_seconds") for r in proc_reports]
    drain_seconds: float | None = (
        max(float(d) for d in drains) if drains and all(d is not None for d in drains) else None
    )

    read_short = agg_sent - engine_read
    deliver_short = engine_written - agg_sink_received
    no_loss_ok = read_short <= 0 and deliver_short <= 0 and backlog == 0
    parts: list[str] = []
    if read_short > 0:
        parts.append(f"engine_read {engine_read} < aggregate sent {agg_sent} (lost {read_short})")
    if deliver_short > 0:
        parts.append(
            f"union sink_received {agg_sink_received} < engine_written {engine_written} "
            f"(lost {deliver_short})"
        )
    if backlog != 0:
        parts.append(f"backlog {backlog} not drained")
    detail = (
        "; ".join(parts)
        if parts
        else "engine_read>=sent, union sink_received>=written, backlog drained"
    )
    no_loss = NoLoss(
        ok=no_loss_ok,
        sent=agg_sent,
        engine_read=engine_read,
        engine_written=engine_written,
        sink_received=agg_sink_received,
        backlog=backlog,
        detail=detail,
    )

    return ConnScaleRecord(
        sweep_mode=cell.sweep_mode,
        count=cell.count,
        offered_aggregate_rate=offered,
        sent=agg_sent,
        acked=agg_acked,
        nak=agg_nak,
        deferred=agg_deferred,
        no_loss=no_loss,
        in_pipeline_peak=in_pipeline_peak,
        drain_seconds=drain_seconds,
        executor_queue_depth_peak=None,
        executor_busy_peak=None,
        pool_wait_p50_ms=None,
        pool_wait_p95_ms=None,
        pool_wait_p99_ms=None,
        pool_wait_max_ms=None,
        pool_idle_min=None,
        pool_size_max=None,
        empty_claims_per_s=0.0,
        idle_poll_per_s=0.0,
        wake_fanout_per_s=0.0,
        fd_count_peak=None,
        reload_seconds=None,
        ack_p50_ms=0.0,
        ack_p95_ms=0.0,
        ack_p99_ms=0.0,
        timeouts=agg_timeouts,
        claim_mode=cell.claim_mode,
        achieved_read_per_s=achieved_read,
        achieved_written_per_s=achieved_written,
        fuse_thread_hops=cell.fuse_mode,
        batch_handoff_statements=cell.batch_mode,
    )


def _failed_cell_record(cell: BatchCell, detail: str) -> ConnScaleRecord:
    """A cell whose >= 6 sink-PROCESS fleet could not be driven or aggregated (a crashed remote band, an
    empty/short fleet, a null engine gauge), materialised as an EXPLICIT failed/loss
    :class:`ConnScaleRecord` (``no_loss.ok = False``, zero throughput) tagged with the cell's A/B arm.

    It surfaces in the ``zero_loss`` SLO (``all(r.no_loss.ok …)`` turns False) and, because it carries the
    cell's ``batch_handoff_statements``/``fuse_thread_hops``/``claim_mode`` tags, in the B0/B1 batch
    verdict (its arm's ``zero_loss_ok`` collapses → the cell counts as a candidate loss). So a broken
    band FAILS the cell loudly instead of vanishing from the no-loss accounting — the same "fail the step,
    never drop it" posture the connscale runner takes. ``drain_seconds=None`` poisons the worst-case
    drain (a cell that never ran never drained)."""
    no_loss = NoLoss(
        ok=False,
        sent=0,
        engine_read=0,
        engine_written=0,
        sink_received=0,
        backlog=0,
        detail=f"cell drive failed: {detail}",
    )
    return ConnScaleRecord(
        sweep_mode=cell.sweep_mode,
        count=cell.count,
        offered_aggregate_rate=0.0,
        sent=0,
        acked=0,
        nak=0,
        deferred=0,
        no_loss=no_loss,
        in_pipeline_peak=0,
        drain_seconds=None,
        executor_queue_depth_peak=None,
        executor_busy_peak=None,
        pool_wait_p50_ms=None,
        pool_wait_p95_ms=None,
        pool_wait_p99_ms=None,
        pool_wait_max_ms=None,
        pool_idle_min=None,
        pool_size_max=None,
        empty_claims_per_s=0.0,
        idle_poll_per_s=0.0,
        wake_fanout_per_s=0.0,
        fd_count_peak=None,
        reload_seconds=None,
        ack_p50_ms=0.0,
        ack_p95_ms=0.0,
        ack_p99_ms=0.0,
        timeouts=0,
        claim_mode=cell.claim_mode,
        achieved_read_per_s=0.0,
        achieved_written_per_s=0.0,
        fuse_thread_hops=cell.fuse_mode,
        batch_handoff_statements=cell.batch_mode,
    )


# --- the ENGINE half ---------------------------------------------------------


@dataclass(frozen=True)
class BatchCellEngineInfo:
    """One cell's engine-subprocess identity — the per-PID CPU-correlation record, also advertised in
    that cell's ``BATCH_CELL_READY``."""

    cell_id: str
    node_id: str
    pid: int | None
    batch_mode: bool
    count: int
    trial: int
    inbound_base: int
    api_port: int
    error: str | None = None


@dataclass
class BatchEngineReport:
    """The ENGINE half's outcome — the per-cell subprocess identities (PID + node id) so the operator's
    EXTERNAL per-PID CPU capture maps each reading to a batch cell + arm. The throughput/verdict is the
    DRIVER half's report (it holds the sinks + aggregation)."""

    profile: str
    claim_mode: str
    cells: list[BatchCellEngineInfo] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return bool(self.cells) and all(c.error is None for c in self.cells)

    def to_json_dict(self) -> dict[str, object]:
        return {
            "schema_version": 1,
            "kind": "batch_engine",
            "profile": self.profile,
            "claim_mode": self.claim_mode,
            "result": "PASS" if self.ok else "FAIL",
            "cells": [
                {
                    "cell_id": c.cell_id,
                    "node_id": c.node_id,
                    "pid": c.pid,
                    "role": "connscale-engine",
                    "batch_handoff_statements": c.batch_mode,
                    "count": c.count,
                    "trial": c.trial,
                    "inbound_base": c.inbound_base,
                    "api_port": c.api_port,
                    "error": c.error,
                }
                for c in self.cells
            ],
            "notes": self.notes,
        }

    def render(self) -> str:
        lines = [
            f"Batch ENGINE (batch_ab two-box) -- profile {self.profile!r} claim_mode={self.claim_mode}"
            f"  cells={len(self.cells)}  {'OK' if self.ok else 'HAD ERRORS'}",
            "  per-cell engine PID (for external per-PID CPU correlation):",
        ]
        for c in self.cells:
            tag = "B1" if c.batch_mode else "B0"
            err = f"  ERROR: {c.error}" if c.error else ""
            lines.append(
                f"    {c.cell_id:<28} {c.node_id} pid={c.pid} arm={tag} N={c.count} "
                f"inbound_base={c.inbound_base} api={c.api_port}{err}"
            )
        for note in self.notes:
            lines.append(f"  note: {note}")
        return "\n".join(lines)


async def run_batch_engine(
    *,
    profile: ConnScaleProfile,
    claim_mode: str = "pooled",
    coord: FileDropCoord,
    store_env: Mapping[str, str] | None = None,
    cwd: Path | None = None,
    inbound_bind_host: str = "0.0.0.0",
    sink_host: str = "127.0.0.1",
    inbound_base: int | None = None,
    api_base: int = 9000,
    sink_base: int = 40000,
    sink_procs: int = _DEFAULT_SINK_PROCS,
    cell_timeout: float = 1800.0,
    reset_store: bool = True,
) -> BatchEngineReport:
    """The ENGINE-box half. Walks the batch_ab matrix; per cell launches ONE connscale engine with the
    batch flag per arm + fusion OFF + ``--claim-mode``, advertises the topology + the engine PID in
    ``BATCH_CELL_READY``, waits for the driver's ``BATCH_CELL_DONE``, tears down, next. Does NOT drive.

    ``store_env`` must point the engine at the batch profile's store (``MEFOR_STORE_*``; batch only
    activates on SQL Server). ``sink_base``/``sink_procs`` are the agreed sink band the driver's >= 6 sink
    PROCESSES bind on the LOAD-GEN box — the engine delivers its outbound fan-out round-robin across
    ``sink_base..sink_base+procs-1`` (``sink_host`` = the load-gen box)."""
    import os

    cwd = cwd or Path.cwd()
    base_env = {**os.environ, **dict(store_env or {})}
    inbound = profile.base_port if inbound_base is None else inbound_base
    cells = iter_batch_cells(profile, claim_mode=claim_mode)
    report = BatchEngineReport(profile=profile.name, claim_mode=claim_mode)

    for step, cell in enumerate(cells):
        api_port = api_base + step
        procs = min(sink_procs, cell.count)  # the engine's delivery ports == the sink PROCESS count
        cell_coord = coord.for_run(f"{coord.run_id}.{cell.cell_id}")
        cell_coord.clear_messages(BATCH_CELL_READY, BATCH_CELL_DONE)  # first mover: no stale drop

        node_env = _node_env(
            base_env,
            claim_mode=cell.claim_mode,
            fuse_mode=cell.fuse_mode,
            batch_mode=cell.batch_mode,
            count=cell.count,
            base_port=inbound,
            transform=profile.transform,
            sink_host=sink_host,
            inbound_bind_host=inbound_bind_host,
            sink_port=sink_base,
            sink_ports=procs,
            install_executor_shim=False,
            db_path=None,  # batch is SQL-Server-scoped: the store comes from MEFOR_STORE_*
        )
        node = EngineNode(
            f"batch-{cell.cell_id}", api_port, env=node_env, config_dir=_CONFIG_DIR, cwd=cwd
        )
        try:
            # Empty the shared store so THIS cell is apples-to-apples (the pooled/batch handoff never
            # inherits the prior cell's rows — the carryover confound run_connscale fixes per step).
            if reset_store and profile.store_backend is not None:
                with contextlib.suppress(Exception):
                    await _reset_server_store(profile.store_backend, node_env)
            await node.start()
            await _await_node_healthy(node, timeout=_HEALTH_TIMEOUT)
            # Preflight the engine's OWN inbound bind on loopback (127.0.0.1 reaches a 0.0.0.0 listener);
            # the DRIVER separately proves off-box reachability from its side.
            await _await_port("127.0.0.1", inbound, timeout=_PORTS_READY_TIMEOUT)
            await _await_port("127.0.0.1", inbound + cell.count - 1, timeout=_PORTS_READY_TIMEOUT)
        except (ConnScaleError, FailoverError) as exc:
            info = BatchCellEngineInfo(
                cell_id=cell.cell_id,
                node_id=node.node_id,
                pid=None,
                batch_mode=cell.batch_mode,
                count=cell.count,
                trial=cell.trial,
                inbound_base=inbound,
                api_port=api_port,
                error=f"engine did not start: {exc}",
            )
            report.cells.append(info)
            report.notes.append(f"CELL {cell.cell_id} ENGINE START FAILED: {exc}")
            # Tell the driver this cell is unusable so it skips + posts DONE (keeps the matrix in
            # lockstep instead of hanging both boxes on a READY that never comes).
            cell_coord.post(BATCH_CELL_READY, {"cell_id": cell.cell_id, "error": info.error})
            with contextlib.suppress(Exception):
                await cell_coord.await_message(BATCH_CELL_DONE, timeout=cell_timeout)
            with contextlib.suppress(Exception):
                await node.stop()
            continue

        pid = getattr(node, "pid", None)
        info = BatchCellEngineInfo(
            cell_id=cell.cell_id,
            node_id=node.node_id,
            pid=pid,
            batch_mode=cell.batch_mode,
            count=cell.count,
            trial=cell.trial,
            inbound_base=inbound,
            api_port=api_port,
        )
        report.cells.append(info)
        try:
            cell_coord.post(
                BATCH_CELL_READY,
                {
                    "cell_id": cell.cell_id,
                    "claim_mode": cell.claim_mode,
                    "batch_mode": cell.batch_mode,
                    "sweep_mode": cell.sweep_mode,
                    "count": cell.count,
                    "trial": cell.trial,
                    "inbound_base": inbound,
                    "api_port": api_port,
                    "sink_base": sink_base,
                    "sink_procs": procs,
                    "hold_seconds": profile.hold_seconds,
                    "drain_timeout_s": profile.drain_timeout_s,
                    "aggregate_rate": profile.aggregate_rate_for(cell.sweep_mode, cell.count),
                    # The engine subprocess identity for the operator's EXTERNAL per-PID CPU capture.
                    "engine": {"pid": pid, "node_id": node.node_id, "role": "connscale-engine"},
                },
            )
            await cell_coord.await_message(BATCH_CELL_DONE, timeout=cell_timeout)
        finally:
            with contextlib.suppress(Exception):
                await node.stop()
    return report


# --- the DRIVER half ---------------------------------------------------------


# Module-level so a structural test can monkeypatch the subprocess spawn (no real connscale-remote runs).
async def _run_remote_proc(argv: list[str], report_path: Path, cwd: Path) -> dict[str, Any]:
    """Spawn one ``connscale-remote`` process, wait for it, and return its JSON report. Real work — the
    tests replace this seam with a synthetic report per band so the fleet drive runs offline."""
    proc = await asyncio.create_subprocess_exec(
        *argv,
        cwd=str(cwd),
        stdout=asyncio.subprocess.DEVNULL,
        stderr=asyncio.subprocess.DEVNULL,
    )
    await proc.wait()
    data = json.loads(report_path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ConnScaleError(f"connscale-remote report {report_path} is not a JSON object")
    return data


async def _drive_cell_fleet(
    cell: BatchCell,
    ready: Mapping[str, Any],
    *,
    engine_host: str,
    sink_host: str,
    cwd: Path,
    report_dir: Path,
) -> tuple[list[dict[str, Any]], int]:
    """Run the >= 6 sink-PROCESS fleet for ONE cell: plan the disjoint bands from the advertised
    topology, spawn one ``connscale-remote`` per band concurrently, and collect their JSON reports.
    Returns ``(reports, band_count)`` where ``band_count == len(plans)`` (the aggregation's expected-band
    guard).

    A band that RAISES (a crashed remote process) fails the WHOLE cell (raises :class:`ConnScaleError`)
    rather than silently shrinking the fleet into a partial aggregate — the caller records it as an
    explicit failed/loss cell so a crashed band can never vanish from the no-loss accounting."""
    inbound_base = int(ready["inbound_base"])
    api_port = int(ready["api_port"])
    sink_base = int(ready["sink_base"])
    sink_procs = int(ready["sink_procs"])
    count = int(ready["count"])
    hold_seconds = float(ready.get("hold_seconds", 60.0))
    drain_timeout = float(ready.get("drain_timeout_s", 300.0))
    aggregate_rate = float(ready.get("aggregate_rate", 0.0))
    # Per-connection rate so the SUMMED offered load across the fleet == the profile's aggregate for the
    # cell (each process offers per_conn_rate * its share; the shares sum to `count`).
    per_conn_rate = aggregate_rate / count if count > 0 else 0.0

    plans = plan_driver_bands(
        inbound_base=inbound_base, count=count, sink_base=sink_base, sink_procs=sink_procs
    )
    tasks = []
    for plan in plans:
        report_path = report_dir / f"{cell.cell_id}.p{plan.index}.json"
        argv = build_remote_argv(
            plan,
            engine_host=engine_host,
            api_port=api_port,
            sink_host=sink_host,
            per_conn_rate=per_conn_rate,
            hold_seconds=hold_seconds,
            drain_timeout=drain_timeout,
            report_path=report_path,
        )
        tasks.append(_run_remote_proc(argv, report_path, cwd))
    # return_exceptions=True so a crashed band is COLLECTED (never left un-retrieved) and every sibling
    # still completes — then fail the whole cell explicitly if ANY band raised, so the caller records a
    # failed/loss cell instead of the cell silently going absent from the verdict.
    results = await asyncio.gather(*tasks, return_exceptions=True)
    failures = [
        (plan.index, res)
        for plan, res in zip(plans, results, strict=True)
        if isinstance(res, BaseException)
    ]
    if failures:
        detail = "; ".join(
            f"band {idx} raised {type(exc).__name__}: {exc}" for idx, exc in failures
        )
        raise ConnScaleError(
            f"cell {cell.cell_id}: {len(failures)}/{len(plans)} sink band(s) failed: {detail}"
        )
    reports = [res for res in results if isinstance(res, dict)]
    return reports, len(plans)


async def run_batch_driver(
    *,
    profile: ConnScaleProfile,
    claim_mode: str = "pooled",
    engine_host: str,
    coord: FileDropCoord,
    sink_host: str = "0.0.0.0",
    cwd: Path | None = None,
    report_dir: Path | None = None,
    cell_timeout: float = 900.0,
) -> ConnScaleReport:
    """The LOAD-GEN-box half. Walks the SAME batch_ab matrix; per cell waits for ``BATCH_CELL_READY``,
    runs the >= 6 sink-PROCESS ``connscale-remote`` fleet against the engine box, aggregates the per-proc
    JSON into ONE cell record, posts ``BATCH_CELL_DONE``. After the matrix it computes the B0/B1
    statement-batching verdict via :func:`build_batch_comparison` and returns a full
    :class:`ConnScaleReport` (records + ``batch_comparison``). Spawns NO engine + binds the sinks LOCALLY
    on ``sink_host`` (the load-gen box)."""
    import tempfile

    cwd = cwd or Path.cwd()
    report_dir = report_dir or Path(tempfile.mkdtemp(prefix="mefor-batch2box-"))
    cells = iter_batch_cells(profile, claim_mode=claim_mode)
    records: list[ConnScaleRecord] = []
    notes: list[str] = []

    for cell in cells:
        cell_coord = coord.for_run(f"{coord.run_id}.{cell.cell_id}")
        ready = await cell_coord.await_message(BATCH_CELL_READY, timeout=cell_timeout)
        if ready.get("error"):
            # The engine could not start this cell — record the miss (build_batch_comparison surfaces a
            # missing arm) and release the engine so the matrix stays in lockstep.
            notes.append(f"CELL {cell.cell_id} skipped: engine error: {ready['error']}")
            cell_coord.post(BATCH_CELL_DONE, {"cell_id": cell.cell_id, "skipped": True})
            continue
        try:
            proc_reports, band_count = await _drive_cell_fleet(
                cell,
                ready,
                engine_host=engine_host,
                sink_host=sink_host,
                cwd=cwd,
                report_dir=report_dir,
            )
            record = aggregate_cell_record(cell, proc_reports, expected_bands=band_count)
            records.append(record)
            cell_coord.post(
                BATCH_CELL_DONE,
                {
                    "cell_id": cell.cell_id,
                    "sent": record.sent,
                    "sink_received": record.no_loss.sink_received,
                    "no_loss_ok": record.no_loss.ok,
                    "achieved_read_per_s": round(record.achieved_read_per_s, 2),
                },
            )
        except (ConnScaleError, OSError, ValueError) as exc:
            # A cell whose fleet couldn't be driven or aggregated (a crashed band, an empty/short fleet,
            # a null engine gauge) is recorded as an EXPLICIT failed/loss cell so it surfaces in the
            # zero-loss SLO + the B0/B1 verdict — never a silent gap in the matrix (mirrors the connscale
            # runner failing a step rather than dropping it).
            notes.append(f"CELL {cell.cell_id} drive failed: {exc}")
            records.append(_failed_cell_record(cell, str(exc)))
            cell_coord.post(BATCH_CELL_DONE, {"cell_id": cell.cell_id, "error": str(exc)})

    batch_comparison = build_batch_comparison(records, profile.batch_modes)
    slos = _evaluate_slos(profile, records)
    result_ok = (
        bool(records)
        and all(c.ok for c in slos)
        and (batch_comparison is None or batch_comparison.ok)
    )
    return ConnScaleReport(
        profile=profile.name,
        engine_url=f"http://{engine_host} (per-cell API ports)",
        db_backend=profile.store_backend,
        shim_installed=False,
        records=records,
        slos=slos,
        result_ok=result_ok,
        exit_code=EXIT_OK if result_ok else EXIT_SLO_VIOLATION,
        notes=notes,
        batch_comparison=batch_comparison,
    )
