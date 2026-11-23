# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
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
import logging
import math
import sys
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from harness.load.connscale.compare import build_batch_comparison
from harness.load.connscale.profile import FUSE_OFF, SANDBOX_OFF, ConnScaleProfile
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
from messagefoundry.support.redact import redact_log_text
from messagefoundry.terminal_text import escape_for_terminal

log = logging.getLogger(__name__)

_RESET_ERROR_CHARS = 1000  # past any store refusal's remedy; the text travels in the READY message
_HEALTH_TIMEOUT = 30.0
_PORTS_READY_TIMEOUT = 60.0
_STOP_GRACE = 5.0
_DEFAULT_SINK_PROCS = 6  # the >= 5-6 sink-PROCESS attribution gate


# The engine's shipped ``[auth]`` defaults, the floor the rig sets each sign-in limit no lower than,
# copied rather than imported, because tests/test_dependency_boundaries.py bans a direct
# ``messagefoundry.config`` import here without an allow-list entry. (That rule is static: this
# module still loads engine config transitively, through runner.py.)
# tests/test_bench_batch_two_box.py pins each copy to the ``AuthSettings`` field default, so a moved
# engine default fails CI there. A rig run from a checkout whose engine default moved ahead of these
# copies would use the stale copy as its floor.
SHIPPED_MAX_SESSIONS_PER_USER = 5
SHIPPED_LOGIN_RATE_LIMIT_PER_IP = 10
SHIPPED_LOGIN_RATE_LIMIT_GLOBAL = 60

#: The ``[auth]`` limits a fleet of rig sign-ins from one address meets, as
#: ``(env name, shipped default)``.
_SESSIONS_ENV = "MEFOR_AUTH_MAX_SESSIONS_PER_USER"
_RIG_SIGN_IN_LIMITS = (
    (_SESSIONS_ENV, SHIPPED_MAX_SESSIONS_PER_USER),
    ("MEFOR_AUTH_LOGIN_RATE_LIMIT_PER_IP", SHIPPED_LOGIN_RATE_LIMIT_PER_IP),
    ("MEFOR_AUTH_LOGIN_RATE_LIMIT_GLOBAL", SHIPPED_LOGIN_RATE_LIMIT_GLOBAL),
)
#: The two switches that turn the engine's sign-in rate limiter off whatever its counts say.
_RATE_LIMIT_ENABLED_ENV = "MEFOR_AUTH_LOGIN_RATE_LIMIT_ENABLED"
_RATE_LIMIT_WINDOW_ENV = "MEFOR_AUTH_LOGIN_RATE_LIMIT_WINDOW_SECONDS"
#: The spellings of false the engine's settings model reads (pydantic's lax bool).
_FALSE_WORDS = frozenset({"0", "off", "f", "false", "n", "no"})


def rig_sign_in_env(procs: int) -> dict[str, str]:
    """The ``[auth]`` env a cell's engine needs so ``procs`` driver processes can all sign in.

    Each of the driver's ``procs`` ``connscale-remote`` processes signs in for itself as the one rig
    Administrator, from the one load-gen box address. At least these engine limits meet that fleet:

    * the per-user session cap (``SHIPPED_MAX_SESSIONS_PER_USER``): past it a login ends the
      user's oldest session, so one process past the cap would end the first one's, which would
      sign in again and end the next;
    * the per-address sign-in limit (``SHIPPED_LOGIN_RATE_LIMIT_PER_IP`` attempts per window,
      successes counted too): every process signs in at the start of the cell, inside one window,
      so one process past that limit would be refused with HTTP 429 (BACKLOG #2795);
    * the all-clients sign-in limit (``SHIPPED_LOGIN_RATE_LIMIT_GLOBAL`` per window), met the same
      way by one process past it.

    Every one is named, at ``procs`` doubled (for a process that signs in again) plus two, or
    at its shipped default, whichever is higher, so the caller ALWAYS sets it explicitly unless
    the environment already does. That is what sizes
    each limit against the value in effect: the engine ranks the environment above a
    ``messagefoundry.toml`` in its working directory, so a stricter value there cannot refuse the
    fleet, and a small fleet never runs below a stock engine whose defaults match the copies above.
    A TOML value of 0 (no limit) is replaced by that finite size too; to run the rig's engine with
    no limit, set the variable to 0 in the environment. A value the environment sets is checked by
    :func:`check_operator_sign_in_limits`.

    The per-address value also sets the engine's per-user credential-ceremony limit and its
    repeated-credential audit limit, and the all-clients value that audit limit's global ceiling, so
    those are sized with them. Each process signing in for itself keeps the rig's sessions apart;
    one session handed to every process would need none of this, and is not what the rig does.
    """
    size = _fleet_sign_in_size(procs)
    return {name: str(max(size, shipped)) for name, shipped in _RIG_SIGN_IN_LIMITS}


def _fleet_sign_in_size(procs: int) -> int:
    """The sign-ins and sessions a fleet of ``procs`` driver processes may need: one each, doubled
    for a process that signs in again, plus two."""
    return 2 * procs + 2


def env_setting(environ: Mapping[str, str], name: str) -> str | None:
    """The value ``environ`` gives the engine setting ``name`` (an upper-case ``MEFOR_`` name), or
    None. The engine's loader folds the case of everything after ``MEFOR_``, and of two spellings
    the later one wins, so this reads the setting the same way."""
    found: str | None = None
    for key, value in environ.items():
        if key.startswith("MEFOR_") and key.upper() == name:
            found = value
    return found


def _rate_limiter_off(environ: Mapping[str, str]) -> bool:
    """Whether ``environ`` turns the engine's sign-in rate limiter off: switched off, or a window
    of 0 or less. A ``messagefoundry.toml`` the engine also reads is not consulted."""
    if (env_setting(environ, _RATE_LIMIT_ENABLED_ENV) or "").lower() in _FALSE_WORDS:
        return True
    try:
        return float(env_setting(environ, _RATE_LIMIT_WINDOW_ENV) or "60") <= 0
    except ValueError:
        return False  # the engine's loader refuses it


def check_operator_sign_in_limits(procs: int, environ: Mapping[str, str]) -> None:
    """Refuse a sign-in limit ``environ`` sets that a fleet of ``procs`` would certainly meet.

    A value the operator's environment sets stands over :func:`rig_sign_in_env`'s, so it is the
    value in effect, and this raises :class:`ConnScaleError` naming one the fleet would meet,
    before any engine starts:

    * a rate count below ``procs``: each process signs in once at the start of a cell, so one of
      them would be refused with HTTP 429. A count of at least ``procs`` but below
      :func:`rig_sign_in_env`'s size passes; a second sign-in past it is refused with HTTP 429,
      which ``rigadmin.RigSignInRateLimited`` names;
    * a session cap below :func:`rig_sign_in_env`'s size. A sign-in past the cap is not refused: it
      silently ends another process's oldest session, and that one's renewal ends the next. So a
      second session a process takes (a step-up re-proof signs in to one of its own) must fit too.

    No limit passes: 0 for any of the three, below 0 for the session cap, and either rate count
    while ``environ`` turns the rate limiter off. A value that is not a number is left for the
    engine's loader to refuse. One the loader reads as a whole number, such as ``3.0``, is read
    here as a number too.
    """
    limiter_off = _rate_limiter_off(environ)
    size = _fleet_sign_in_size(procs)
    for name, _shipped in _RIG_SIGN_IN_LIMITS:
        held = env_setting(environ, name)
        if held is None:
            continue
        try:
            value = float(held)
        except ValueError:
            continue
        if name == _SESSIONS_ENV:
            if 0 < value < size:
                raise ConnScaleError(
                    f"{name}={held.strip()} in the environment is below the {size} sessions a "
                    f"fleet of {procs} driver processes may hold, so a sign-in past it would end "
                    f"another process's session. Unset it, set it to at least {size}, or set it "
                    "to 0 for no cap"
                )
        elif not (value == 0 or limiter_off) and value < procs:
            raise ConnScaleError(
                f"{name}={held.strip()} in the environment is below the {procs} driver processes "
                "that each sign in at the start of a cell, so the engine would refuse one with "
                f"HTTP 429. Unset it, set it to at least {size}, or set it to 0 for no limit"
            )


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
    so both halves — given the same profile + flag — produce the identical, order-stable list.

    A profile with a sandbox arm or a warm-up is REFUSED (BACKLOG #3132): the batch box runs every
    cell at ``[sandbox].mode = off`` with no warm-up, and the shared SLOs would then fail every cell
    for an axis the box never ran."""
    if profile.sandbox_modes != (SANDBOX_OFF,) or profile.warmup_timeout_s > 0.0:
        raise ConnScaleError(
            f"the batch box runs no sandbox arm and no warm-up; profile {profile.name!r} names "
            f"sandbox_modes={list(profile.sandbox_modes)} and warmup_timeout_s="
            f"{profile.warmup_timeout_s}. Run it with the single-box connscale runner instead"
        )
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
        f"https://{engine_host}:{api_port}",
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


def _band_stranding(report: Mapping[str, Any]) -> tuple[bool | None, str]:
    """The stranding arm one band's ``_reconcile`` judged, as the band published it.

    ``(True, why)`` over budget, ``(False, "")`` within it, ``(None, "")`` when the report does not
    say, or says something its own numbers contradict (BACKLOG #5574): a missing or malformed field
    must not clear the arm. The verdict is read, never worked out again here, because only the band
    knows the budget argument it passed (connscale-remote publishes the excusal its
    ``_reconcile_judged`` verdict rests on); the check here is only that ``over_budget`` is
    ``unconfirmed > budget``, the comparison ``_excusal`` makes. The numbers must also agree with
    the rest of the report: neither is negative, and the unconfirmed count is no more than the
    band's ``traffic.timeouts``, which ``_excusal`` takes it out of.
    """
    no_loss = report.get("no_loss")
    traffic = report.get("traffic")
    if not isinstance(no_loss, Mapping) or not isinstance(traffic, Mapping):
        return None, ""
    stranding = no_loss.get("stranding")
    if not isinstance(stranding, Mapping):
        return None, ""
    over, unconfirmed, budget = (stranding.get(k) for k in ("over_budget", "unconfirmed", "budget"))
    timeouts = traffic.get("timeouts")
    if (
        not isinstance(over, bool)
        # Each isinstance is spelled out so the comparisons below are typed; bool is an int subtype.
        or not isinstance(unconfirmed, int)
        or not isinstance(budget, int)
        or not isinstance(timeouts, int)
        or any(isinstance(v, bool) for v in (unconfirmed, budget, timeouts))
        or over != (unconfirmed > budget)
        or unconfirmed < 0
        or budget < 0
        or unconfirmed > timeouts
    ):
        return None, ""
    if not over:
        return False, ""
    band = escape_for_terminal(str(report.get("engine_index_base", "?")), single_line=True)
    return True, (
        f"band at engine index {band}: {unconfirmed} unconfirmed sends exceed its stranding budget "
        f"({budget}) — systemic no-ACK fault, judged on that band's client counters alone"
    )


def _band_client_only_loss(report: Mapping[str, Any]) -> bool:
    """The band's own reconcile proved a loss while it judged no engine-delta arm (the counters
    reset, or it could not read the engine), so only its client-counter arms ran, and no other band
    can correct those. The condition :func:`aggregate_cell_record` counts as ``client_lost``."""
    no_loss = report.get("no_loss")
    if not isinstance(no_loss, Mapping):
        return False
    backlog = no_loss.get("backlog")
    engine_unjudged = no_loss.get("counter_reset") is not None or (
        isinstance(backlog, int) and backlog < 0
    )
    return engine_unjudged and no_loss.get("ok") is False and no_loss.get("inconclusive") is False


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
    if agg_sent <= 0:
        # A fleet that sent nothing reconciles vacuously (BACKLOG #5431's empty run, at the cell).
        raise ConnScaleError(f"cell {cell.cell_id}: the fleet sent nothing")
    offered = sum(float(r.get("offered_aggregate_rate", 0.0)) for r in proc_reports)

    engine_read = _engine_gauge("engine_read")
    engine_written = _engine_gauge("engine_written")
    backlog = _engine_gauge("backlog")
    # A band whose hold-bracket /stats sample failed reports a placeholder 0.0 rate and no rate window
    # and says so with `rates_measured: false` (BACKLOG #5431; a report from before then lacks the key
    # and is read as measured). Every band reads the same engine, so one measured band suffices; with
    # none, the cell has no rate and must fail rather than read as a measured 0.0 msg/s.
    if not any(_thr(r, "rates_measured") is not False for r in proc_reports):
        raise ConnScaleError(
            f"cell {cell.cell_id}: no band measured a hold-bracket rate (every /stats bracket "
            "sample failed)"
        )
    achieved_read = max(float(_thr(r, "achieved_aggregate_rate") or 0.0) for r in proc_reports)
    achieved_written = max(float(_thr(r, "delivered_aggregate_rate") or 0.0) for r in proc_reports)
    in_pipeline_peak = max((int(_thr(r, "in_pipeline_peak") or 0) for r in proc_reports), default=0)

    # A timed-out drain in ANY process (drain_seconds None) poisons the cell's worst-case drain — the
    # whole pipeline did not empty for that band (mirrors the fusion comparator's None-poisons rule).
    drains = [_thr(r, "drain_seconds") for r in proc_reports]
    drain_seconds: float | None = (
        max(float(d) for d in drains) if drains and all(d is not None for d in drains) else None
    )

    # A band whose engine counters reset mid-cell makes every engine delta no run total, and a band
    # report that does not say is refused, never read as "no reset": a missing field must not clear
    # a cell. A band that could not read the engine at all reports the stand-ins 0/0/-1 (connscale
    # `_reconcile`), which are not readings either. Each such band is a reason the cell cannot
    # clear, and every reason is reported, not only the first. The reset text comes out of another
    # process's report file, so it is escaped to one line.
    resets: list[str] = []
    blind = 0
    trusted: list[dict[str, Any]] = []
    # Bands whose own reconcile PROVED a loss while it could judge no engine-delta arm: with the
    # counters reset or the engine unread, only its client-counter arms (the stranding budget, the
    # reload guards) ran, and those read nothing another band could correct. The cell keeps that
    # verdict rather than demote it to INCONCLUSIVE (BACKLOG #5574). A band that judged its engine
    # arms is not counted: its delivery arm compares one band's sink with the engine-wide written.
    client_lost = 0
    # The stranding arm, read off EVERY band's published `no_loss.stranding`, whatever its engine
    # arms did (BACKLOG #5574). It reads only that band's sends and timeouts, so no other band can
    # correct it, and a band over budget is a loss the cell keeps. Taking it off the band's overall
    # verdict would keep it only where the engine arms went unjudged: the same flood beside a clean
    # engine read would pass the cell, and beside a reset would fail it.
    stranding: list[str] = []
    stranding_unjudged = 0
    for r in proc_reports:
        over_budget, why = _band_stranding(r)
        nl = r.get("no_loss", {})
        engine_unjudged = False
        if "counter_reset" not in nl:
            resets.append("a band report does not say whether the engine counters reset")
        elif nl["counter_reset"] is not None:
            resets.append(escape_for_terminal(str(nl["counter_reset"]), single_line=True))
            engine_unjudged = True
        elif int(nl.get("backlog", 0) or 0) >= 0:
            trusted.append(r)
        if int(nl.get("backlog", 0) or 0) < 0:
            blind += 1
            engine_unjudged = True
        # A band already counted over the stranding budget is not counted twice, and one whose
        # client-only loss is kept needs no stranding arm to clear it, so it is not called unjudged.
        if (
            engine_unjudged
            and not over_budget
            and nl.get("ok") is False
            and nl.get("inconclusive") is False
        ):
            client_lost += 1
        elif over_budget is None:
            stranding_unjudged += 1
        elif over_budget:
            stranding.append(why)
    # Every band reads the SAME engine, so one band's readings are the engine totals and a proven
    # loss needs only the bands that read it cleanly (BACKLOG #5574): one band's reset or blindness
    # must not suppress a loss the others still prove. The two arms differ in what a reset does.
    #   delivery: a reset only ever LOWERS the engine counters, so a written delta taken across one
    #             is a lower bound of what the engine wrote, and a union sink short of it is a loss
    #             whichever band saw the reset.
    #   intake:   the same lower bound makes `sent - read` an OVERestimate, so no band's read may
    #             judge intake once any band names a reset (or will not say).
    judged_written = max((int(_noloss(r, "engine_written")) for r in trusted), default=None)
    judged_read = (
        None if resets else max((int(_noloss(r, "engine_read")) for r in trusted), default=None)
    )
    read_short = 0 if judged_read is None else agg_sent - judged_read
    deliver_short = 0 if judged_written is None else judged_written - agg_sink_received
    # A negative backlog is the metrics-unavailable stand-in, refused below as no reading; only a
    # positive one is rows left in the pipeline.
    drained = backlog <= 0
    lost = read_short > 0 or deliver_short > 0 or bool(stranding) or client_lost > 0
    # Reasons the cell cannot CLEAR itself although no arm proved a loss (BACKLOG #5574), as in
    # harness/load/report.py's copy: both arms above are inequalities an empty, unsettled or
    # undelivering cell satisfies trivially.
    unproven: list[str] = []
    # A fleet that sent nothing was refused above, so only the undelivering cell remains here.
    # The written figure is quoted only from a band that read the engine cleanly: with none, the
    # all-band max is a blind band's stand-in 0 or a delta across a reset, not a reading.
    if agg_sink_received == 0 and (judged_written is None or judged_written <= 0):
        written_read = (
            "not read cleanly by any band" if judged_written is None else str(judged_written)
        )
        unproven.append(
            f"nothing was delivered (union sink_received 0, engine_written {written_read}) — "
            f"no delivery to reconcile"
        )
    if drain_seconds is None:
        unproven.append("a band's drain timed out — the final counts are an unsettled snapshot")
    if resets:
        unjudged = (
            "the intake arm was not judged"
            if trusted
            else "the intake and delivery arms were not judged (no band read the engine cleanly)"
        )
        unproven.append(
            f"{'; '.join(dict.fromkeys(resets))} — the read/written deltas cannot be reconciled "
            f"against this cell's sends, so {unjudged}"
        )
    if blind:
        unjudged = (
            "the cell cannot clear"
            if trusted
            else "the loss arms were not judged (no band read the engine cleanly)"
        )
        unproven.append(f"{blind} band(s) could not read the engine metrics — {unjudged}")
    if stranding_unjudged:
        unproven.append(
            f"{stranding_unjudged} band report(s) do not say whether their sends broke the "
            f"stranding budget (no_loss.stranding.over_budget) — their stranding arm was not judged"
        )
    no_loss_ok = not lost and drained and not unproven
    parts: list[str] = []
    if read_short > 0:
        parts.append(f"engine_read {judged_read} < aggregate sent {agg_sent} (lost {read_short})")
    if deliver_short > 0:
        parts.append(
            f"union sink_received {agg_sink_received} < engine_written {judged_written} "
            f"(lost {deliver_short})"
        )
    parts.extend(stranding)
    if client_lost:
        parts.append(
            f"{client_lost} band(s) proved a loss on client counters alone (their engine arms "
            f"were not judged) — see the band report"
        )
    if not drained:
        parts.append(f"backlog {backlog} not drained")
    parts.extend(unproven)
    detail = (
        "; ".join(parts)
        if parts
        else "engine_read>=sent, union sink_received>=written, backlog drained"
    )
    # Publish the engine totals the verdict rests on, where it rests on any, so the artifact's
    # numbers reproduce its detail; with no clean band they stay the all-band max.
    no_loss = NoLoss(
        ok=no_loss_ok,
        sent=agg_sent,
        engine_read=engine_read if judged_read is None else judged_read,
        engine_written=engine_written if judged_written is None else judged_written,
        sink_received=agg_sink_received,
        backlog=backlog,
        detail=detail,
        inconclusive=not no_loss_ok and not lost,
    )

    return ConnScaleRecord(
        rate_window=_bands_rate_window(proc_reports),
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
        empty_claims_per_msg=None,
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
        trial=cell.trial,
    )


def _bands_rate_window(proc_reports: list[dict[str, Any]]) -> str | None:
    """The rate window the band reports say their rates were read over (BACKLOG #2012).

    Read off the reports rather than assumed, so a band from a connscale-remote that names another
    window, or none, shows up on the cell. ``None`` when no band names one; different windows come
    back joined with ``|``, as ``report.records_rate_window`` joins them.
    """
    windows = sorted(
        {
            str(r.get("throughput", {}).get("rate_window") or "unrecorded")
            for r in proc_reports
            # A band whose bracket sample failed measured no rate, so it names no window to join.
            if r.get("throughput", {}).get("rates_measured") is not False
        }
    )
    if not windows or windows == ["unrecorded"]:
        return None
    return "|".join(windows)


def _failed_cell_record(
    cell: BatchCell, detail: str, survivors: list[dict[str, Any]] | None = None
) -> ConnScaleRecord:
    """A cell whose >= 6 sink-PROCESS fleet could not be driven or aggregated (a crashed remote band, an
    empty/short fleet, a fleet that sent nothing, a null engine gauge), materialised as an EXPLICIT
    failed :class:`ConnScaleRecord` (``no_loss.ok = False``, zero throughput) tagged with the cell's
    A/B arm. It fails closed whatever it is labelled.

    It is INCONCLUSIVE (BACKLOG #5574) unless a band that did report proved a loss no other band can
    correct: the cell measured nothing as a whole, which is how the reconcilers label a step that
    sent nothing. ``survivors`` are the band reports that came back. A band among them over its own
    stranding budget (:func:`_band_stranding`), or one whose own reconcile proved a loss on client
    counters alone (:func:`_band_client_only_loss`), makes the cell LOSS, and the detail says so.

    It surfaces in the ``zero_loss`` SLO (``all(r.no_loss.ok …)`` turns False) and, because it carries the
    cell's ``batch_handoff_statements``/``fuse_thread_hops``/``claim_mode`` tags, in the B0/B1 batch
    verdict (its arm's ``zero_loss_ok`` collapses → a candidate loss on a B1 cell; on a B0 cell the zero-loss SLO is what fails). So a broken
    band FAILS the cell loudly instead of vanishing from the no-loss accounting — the same "fail the step,
    never drop it" posture the connscale runner takes. ``drain_seconds=None`` poisons the worst-case
    drain (a cell that never ran never drained)."""
    proven: list[str] = []
    for r in survivors or []:
        over, why = _band_stranding(r)
        if over:
            proven.append(why)
        elif _band_client_only_loss(r):
            band = escape_for_terminal(str(r.get("engine_index_base", "?")), single_line=True)
            proven.append(
                f"band at engine index {band} proved a loss on client counters alone (its engine "
                f"arms were not judged) — see the band report"
            )
    no_loss = NoLoss(
        ok=False,
        sent=0,
        engine_read=0,
        engine_written=0,
        sink_received=0,
        backlog=0,
        detail="; ".join([f"cell drive failed: {detail}", *proven]),
        inconclusive=not proven,
    )
    # No `rate_window`: the cell measured no rate, so it names no window (BACKLOG #2012).
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
        empty_claims_per_msg=None,
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
        trial=cell.trial,
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
    # Refuse an operator sign-in limit too small for the largest cell's fleet before any engine
    # starts; the cell fleet grows with the count, so the largest covers every smaller one. Each
    # cell then fails the way an engine that did not start fails, so the driver box reads an error
    # READY for every cell instead of waiting on one that never comes, or on a stale one.
    try:
        if cells:
            check_operator_sign_in_limits(min(sink_procs, max(c.count for c in cells)), base_env)
    except ConnScaleError as exc:
        report.notes.append(f"SIGN-IN LIMIT REFUSED, NO CELL RAN: {exc}")
        for step, cell in enumerate(cells):
            error = f"engine not started: {exc}"
            report.cells.append(
                BatchCellEngineInfo(
                    cell_id=cell.cell_id,
                    node_id=f"batch-{cell.cell_id}",
                    pid=None,
                    batch_mode=cell.batch_mode,
                    count=cell.count,
                    trial=cell.trial,
                    inbound_base=inbound,
                    api_port=api_base + step,
                    error=error,
                )
            )
            cell_coord = coord.for_run(f"{coord.run_id}.{cell.cell_id}")
            cell_coord.clear_messages(BATCH_CELL_READY, BATCH_CELL_DONE)
            cell_coord.post(BATCH_CELL_READY, {"cell_id": cell.cell_id, "error": error})
        return report

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
        # RIGS SIGN IN, AND THIS RIG'S DRIVE IS SPLIT OVER PROCESSES: the session cap and the
        # sign-in rate limits are sized to the fleet this cell advertises (rig_sign_in_env says why).
        # Only where unset, so a value the operator's environment sets stands; the check before the loop
        # refused one too small for the largest cell.
        for key, value in rig_sign_in_env(procs).items():
            if env_setting(node_env, key) is None:  # any spelling the engine reads stands
                node_env[key] = value
        node = EngineNode(
            f"batch-{cell.cell_id}", api_port, env=node_env, config_dir=_CONFIG_DIR, cwd=cwd
        )
        try:
            # Empty the shared store so THIS cell is apples-to-apples (the pooled/batch handoff never
            # inherits the prior cell's rows — the carryover confound run_connscale fixes per step).
            if reset_store and profile.store_backend is not None:
                try:
                    await _reset_server_store(profile.store_backend, node_env)
                except Exception as exc:
                    # Measuring on the prior cell's rows would be the confound above, so the cell
                    # is missed.
                    raise ConnScaleError(_store_reset_failure(exc)) from exc
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
            try:
                await cell_coord.await_message(BATCH_CELL_DONE, timeout=cell_timeout)
            except Exception as wait_exc:
                kind = type(wait_exc).__name__
                log.warning("batch cell %s: wait for DONE failed: %s", cell.cell_id, kind)
                report.notes.append(
                    f"CELL {cell.cell_id}: wait for the driver's DONE failed ({kind}) after the "
                    "engine did not start; moving to the next cell"
                )
            await _stop_cell_node(node, cell.cell_id, report)
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
            await _stop_cell_node(node, cell.cell_id, report)
    return report


def _store_reset_failure(exc: Exception) -> str:
    """Why a store reset failed, for the cell's error. The store's refusal names its remedy (the RCSI
    statement a DBA runs, for one), so its text is kept. It goes through the redactor first, because
    a driver error's text can carry connection details, and is escaped since it reaches a terminal."""
    detail = redact_log_text(str(exc))[:_RESET_ERROR_CHARS]
    return f"store reset failed: {type(exc).__name__}: {escape_for_terminal(detail)}"


async def _stop_cell_node(node: EngineNode, cell_id: str, report: BatchEngineReport) -> None:
    """Stop a cell's engine. A failure is logged and noted by exception type only, and never becomes
    a cell error: the cell's result is already decided by the time teardown runs (BACKLOG #5857).

    The note reads the process, not the code path: a cell that failed its health or port wait did
    spawn an engine. ``alive`` sees only the root process's last known state, so neither note
    claims the whole process tree is gone."""
    try:
        await node.stop()
    except Exception as exc:
        kind = type(exc).__name__
        log.warning("batch cell %s: engine stop raised %s", cell_id, kind)
        report.notes.append(
            f"CELL {cell_id}: engine stop raised {kind} and its root process still reads as "
            "RUNNING; check that it exited"
            if node.alive
            else f"CELL {cell_id}: cleanup stop raised {kind}; its root process is not running "
            "(it may never have started; child processes were not checked)"
        )


# --- the DRIVER half ---------------------------------------------------------


# What a band may spend beyond its hold and its two drain windows. It covers at least: interpreter
# start-up, signing in, the inbound port preflight (two waits of up to 60 s), the batched connects,
# binding its sinks, the engine reads that bracket the hold, the sender stop graces, closing its
# sinks and poller, and writing its report. A child still running past the bound is hung, and is
# killed so it cannot hang the driver (BACKLOG #5304).
_REMOTE_PROC_SLACK = 300.0

# How much of a band's stderr is kept: the tail is what names why it failed.
_STDERR_TAIL_BYTES = 4096


def _remote_proc_timeout(hold_seconds: float, drain_timeout: float) -> float:
    """The wall-clock bound on one ``connscale-remote`` band. The child may spend ``drain_timeout``
    twice, once awaiting the drain and once more sampling until the counts reconcile (remote.py), so
    a band that is slow but healthy has its measured report read rather than killed."""
    return hold_seconds + 2 * drain_timeout + _REMOTE_PROC_SLACK


def _stderr_reason(said: bytes) -> str:
    """The tail of what a ``connscale-remote`` child wrote to stderr, as the reason its band failed.
    Escaped, since it reaches the operator's terminal in the cell's notes."""
    tail = said.decode("utf-8", "replace").strip()[-600:]
    return escape_for_terminal(tail) if tail else "it said nothing on stderr"


async def _kill_and_reap(proc: asyncio.subprocess.Process) -> bool:
    """Kill ``proc`` and wait, bounded, for it to exit. False when it is still there after
    ``_STOP_GRACE``: a child stuck in uninterruptible I/O must not hang the driver either."""
    with contextlib.suppress(ProcessLookupError):
        proc.kill()
    try:
        await asyncio.wait_for(proc.wait(), _STOP_GRACE)
    except TimeoutError:
        return False
    return True


# Module-level so a structural test can monkeypatch the subprocess spawn (no real connscale-remote runs).
async def _run_remote_proc(
    argv: list[str], report_path: Path, cwd: Path, *, timeout: float
) -> dict[str, Any]:
    """Spawn one ``connscale-remote`` process, wait for it, and return its JSON report. Real work — the
    tests replace this seam with a synthetic report per band so the fleet drive runs offline.

    Any file already at ``report_path`` is removed before the spawn (BACKLOG #5304), so only a report
    THIS child wrote can be read: a child that fails before writing would otherwise hand back the band
    report an earlier run left at the same path.

    A child still running after ``timeout`` seconds is killed and the band fails, and so is one left
    running when this wait is cancelled: an unbounded wait let one hung child hang the whole driver."""
    report_path.unlink(missing_ok=True)
    proc = await asyncio.create_subprocess_exec(
        *argv,
        cwd=str(cwd),
        stdout=asyncio.subprocess.DEVNULL,
        stderr=asyncio.subprocess.PIPE,
    )
    stderr = proc.stderr
    assert stderr is not None  # stderr=PIPE above
    heard = bytearray()

    async def _hear() -> None:
        # Read as it arrives, so what a child said before it hung -- the only clue to the phase it
        # hung in -- is still here once it has been killed. Only the tail is kept.
        while chunk := await stderr.read(65536):
            heard.extend(chunk)
            del heard[:-_STDERR_TAIL_BYTES]

    hearing = asyncio.ensure_future(_hear())
    try:
        try:
            await asyncio.wait_for(proc.wait(), timeout)
            hung, reaped = False, True
        except TimeoutError:
            # A child that exited just as the bound fired is not hung: its report stands.
            hung = proc.returncode is None
            reaped = await _kill_and_reap(proc)
        # The pipe closes once the child exits. Bounded, since a grandchild that outlived the
        # child could hold it open; asyncio.wait never raises what the reader hit.
        done, _ = await asyncio.wait({hearing}, timeout=_STOP_GRACE)
        cut = "" if hearing in done else " (stderr was still open, so this tail may be cut short)"
        if hung:
            fate = "was killed" if reaped else f"did not exit within {_STOP_GRACE:g}s of the kill"
            raise ConnScaleError(
                f"connscale-remote was still running after {timeout:g}s and {fate}: "
                f"{_stderr_reason(bytes(heard))}{cut}"
            )
    finally:
        if proc.returncode is None:
            await _kill_and_reap(proc)
        hearing.cancel()
        await asyncio.gather(hearing, return_exceptions=True)
    said = bytes(heard)
    if not report_path.exists():
        # The process writes its report only when it ran. One that could not start (a band layout
        # it refused, a sign-in the engine refused) says why on stderr and writes nothing, and that
        # reason used to be discarded, leaving a bare FileNotFoundError.
        raise ConnScaleError(
            f"connscale-remote exited {proc.returncode} and wrote no report: {_stderr_reason(said)}"
        )
    try:
        data = json.loads(report_path.read_text(encoding="utf-8"))
    except ValueError as exc:
        # A child killed or failing mid-write leaves a partial report; its exit and stderr say why.
        raise ConnScaleError(
            f"connscale-remote exited {proc.returncode} and its report {report_path} is not JSON "
            f"({exc}): {_stderr_reason(said)}"
        ) from exc
    if not isinstance(data, dict):
        raise ConnScaleError(
            f"connscale-remote exited {proc.returncode} and its report {report_path} is not a JSON "
            f"object: {_stderr_reason(said)}"
        )
    # A report on disk does not by itself mean the child finished cleanly, so its exit code is read
    # too. A child that ran exits with the code its report records: 0 on PASS, 1 on its own FAIL
    # verdict, whose counts the aggregation judges again. Any other exit, or one the report does
    # not record, fails the band with the child's stderr reason rather than reading the report
    # as if nothing had gone wrong.
    recorded = data.get("exit_code")
    if proc.returncode != 0 and not (type(recorded) is int and recorded == proc.returncode):
        raise ConnScaleError(
            f"connscale-remote exited {proc.returncode}, but its report records exit code "
            f"{recorded!r}: {_stderr_reason(said)}"
        )
    return data


def _ready_number[N: (int, float)](
    ready: Mapping[str, Any], key: str, kind: type[N], *, default: N | None = None
) -> N:
    """One numeric field of a READY payload, refused as :class:`ConnScaleError` when it is missing or
    not a number (BACKLOG #5428). A bare ``int(ready[key])`` raised KeyError or TypeError, which the
    driver did not catch, so a malformed READY ended it without posting DONE."""
    value = ready.get(key, default)
    if (
        isinstance(value, bool)
        or not isinstance(value, int | float)
        or not math.isfinite(value)
        or (kind is int and value != int(value))
    ):
        raise ConnScaleError(f"READY field {key!r} is {value!r}, not a finite {kind.__name__}")
    return kind(value)


class CellFleetFailed(ConnScaleError):
    """A band of one cell's fleet raised. ``reports`` are the reports its sibling bands wrote."""

    def __init__(self, message: str, reports: list[dict[str, Any]] | None = None) -> None:
        super().__init__(message)
        # A default, so a copy or unpickle that rebuilds the error from its message alone works.
        self.reports = reports or []


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

    A band that RAISES (a crashed remote process) fails the WHOLE cell (raises :class:`CellFleetFailed`)
    rather than silently shrinking the fleet into a partial aggregate — the caller records it as an
    explicit failed/loss cell so a crashed band can never vanish from the no-loss accounting. The
    error carries the reports the other bands did write, so a loss one of them proved is kept."""
    inbound_base = _ready_number(ready, "inbound_base", int)
    api_port = _ready_number(ready, "api_port", int)
    sink_base = _ready_number(ready, "sink_base", int)
    sink_procs = _ready_number(ready, "sink_procs", int)
    count = _ready_number(ready, "count", int)
    hold_seconds = _ready_number(ready, "hold_seconds", float, default=60.0)
    drain_timeout = _ready_number(ready, "drain_timeout_s", float, default=300.0)
    # Required, and positive: it decides whether any load is offered at all.
    aggregate_rate = _ready_number(ready, "aggregate_rate", float)
    if aggregate_rate <= 0.0 or count < 1:
        raise ConnScaleError(
            f"READY offers no load: aggregate_rate {aggregate_rate}, count {count}"
        )
    # Per-connection rate so the SUMMED offered load across the fleet == the profile's aggregate for the
    # cell (each process offers per_conn_rate * its share; the shares sum to `count`).
    per_conn_rate = aggregate_rate / count

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
        tasks.append(
            _run_remote_proc(
                argv,
                report_path,
                cwd,
                timeout=_remote_proc_timeout(hold_seconds, drain_timeout),
            )
        )
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
        raise CellFleetFailed(
            f"cell {cell.cell_id}: {len(failures)}/{len(plans)} sink band(s) failed: {detail}",
            [res for res in results if isinstance(res, dict)],
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
    # Cells whose engine never started (BACKLOG #5428). They stay out of `records`, because a 0.0 msg/s
    # placeholder trial would skew its arm's mean and spread, and instead fail the run outright, the
    # way run_connscale's `steps_missed` does; a wholly-missing arm also surfaces in the verdict.
    cells_missed = 0
    cells_failed = 0  # cells whose drive failed: their placeholder records alone must not decide
    missing_detail: dict[tuple[str, str, int], str] = {}

    for cell in cells:
        cell_coord = coord.for_run(f"{coord.run_id}.{cell.cell_id}")
        ready = await cell_coord.await_message(BATCH_CELL_READY, timeout=cell_timeout)
        if ready.get("error"):
            # The engine could not start this cell -- release it so the matrix stays in lockstep.
            cells_missed += 1
            detail = f"engine error: {ready['error']}"
            missing_detail[(cell.claim_mode, cell.sweep_mode, cell.count)] = detail
            notes.append(f"CELL {cell.cell_id} skipped: {detail}")
            cell_coord.post(BATCH_CELL_DONE, {"cell_id": cell.cell_id, "skipped": True})
            continue
        done: dict[str, Any]
        # The band reports this cell got back, kept for a failed aggregation's record below.
        proc_reports: list[dict[str, Any]] = []
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
            done = {
                "cell_id": cell.cell_id,
                "sent": record.sent,
                "sink_received": record.no_loss.sink_received,
                "no_loss_ok": record.no_loss.ok,
                "achieved_read_per_s": round(record.achieved_read_per_s, 2),
                "rate_window": record.rate_window,
            }
        except (ConnScaleError, OSError, ValueError) as exc:
            # A cell whose fleet couldn't be driven or aggregated (a malformed READY, a crashed band, an
            # empty/short fleet, a null engine gauge) is recorded as an EXPLICIT failed/loss cell so it
            # surfaces in the zero-loss SLO + the B0/B1 verdict — never a silent gap in the matrix
            # (mirrors the connscale runner failing a step rather than dropping it).
            notes.append(f"CELL {cell.cell_id} drive failed: {exc}")
            cells_failed += 1
            survivors = exc.reports if isinstance(exc, CellFleetFailed) else proc_reports
            record = _failed_cell_record(cell, str(exc), survivors)
            done = {"cell_id": cell.cell_id, "error": str(exc)}
        # One record and one DONE per cell, posted outside the try so a failed post cannot add a
        # second, failed record for a cell that already ran.
        records.append(record)
        cell_coord.post(BATCH_CELL_DONE, done)

    if cells_missed:
        notes.append(f"{cells_missed} cell(s) never ran (engine failed to start): the run FAILS")
    batch_comparison = build_batch_comparison(
        records, profile.batch_modes, missing_detail=missing_detail
    )
    slos = _evaluate_slos(profile, records)
    result_ok = (
        bool(records)
        and cells_missed == 0
        # A failed drive fails the run even with zero_loss off, where its 0.0 msg/s placeholder
        # would otherwise only skew its arm's mean.
        and cells_failed == 0
        and all(c.ok for c in slos)
        and (batch_comparison is None or batch_comparison.ok)
    )
    return ConnScaleReport(
        profile=profile.name,
        # The engine always serves TLS (ADR 0172), and build_remote_argv dials it over https.
        engine_url=f"https://{engine_host} (per-cell API ports)",
        db_backend=profile.store_backend,
        shim_installed=False,
        records=records,
        slos=slos,
        result_ok=result_ok,
        exit_code=EXIT_OK if result_ok else EXIT_SLO_VIOLATION,
        notes=notes,
        batch_comparison=batch_comparison,
    )
