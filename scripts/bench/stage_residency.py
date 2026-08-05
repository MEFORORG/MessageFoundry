#!/usr/bin/env python
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Where does a message's wall-clock actually go — AS A FUNCTION OF OFFERED LOAD?

Nine falsifiers asked *"is X a lever?"* and got nine no's. Nobody has ever asked where the time goes as
the offered rate climbs. This tool answers that from data the engine already writes — ``message_events``
(one row per stage boundary: ``received`` / ``routed`` / ``transformed`` / ``delivered``, each stamped
``ts`` by the ENGINE's own clock, so there is no cross-box skew to correct).

Read this header before reading a number out of the output. Every rule below exists because a previous
run got it wrong.

1. COHORT SEMANTICS — the window selects MESSAGES, never EVENTS
--------------------------------------------------------------
``--since/--until`` select the messages whose ``received`` stamp falls in the window, and then **every
event of those messages is aggregated with NO ts filter**. This is not a detail; it is the difference
between a correct answer and a manufactured one.

An EVENT-ts filter (what this tool did before) truncates the trailing ``delivered`` rows of exactly the
SLOWEST messages: their ``delivered_max`` is then not their last delivery, so ``W_last`` and
``E2E_complete`` are UNDER-reported — and the under-reporting GROWS with offered load (more rows in
flight at the window edge). That is a load-dependent attenuation of the very slope a load ladder exists
to estimate: it drives the fitted slope toward zero and manufactures the verdict *"latency is flat, the
latency line is a red herring"* out of a windowing artifact.

2. NEVER JOIN TO ``messages``
-----------------------------
``shardcert._reset_store`` DELETEs nine NAMED tables (``queue``, ``outbox``, ``response``,
``delivered_keys``, ``state``, ``leader_lease``, ``nodes``, ``cluster_config``, ``messages``) — and
``message_events`` is **not** one of them. It runs **once per RUNG**. SQL Server's ``message_events`` has
no FK to ``messages``, so nothing cascades either.

=> after a climb, ``message_events`` holds EVERY rung while ``messages`` holds only the LAST. Any
analysis that joins the two silently keeps one rung and returns a clean-looking wrong answer (this has
already fired once). This tool reads ``message_events`` and NOTHING else. Rungs separate on ``ts``
alone: ``--list-rungs`` / ``--per-rung``.

3. TWO BASES, BOTH PRINTED
--------------------------
A fan-out message has **one ``transformed`` per handler** and **one ``delivered`` per destination** (8
and 8 at the c6-n4x2 shape) — not one apiece. Pivoting on ``MIN(ts)`` collapses those to their FIRST,
which is how an earlier version printed 151 ms for a life that was really 479 ms.

first-delivery basis (kept ONLY for continuity with STEP 2 — it is NOT the message's life)::

    A          = routed - received
    B          = transformed_min - routed
    C_first    = delivered_min - transformed_min
    E2E_first  = delivered_min - received                (identity: A + B + C_first)

completion basis (the actual life; every fan-out row in existence)::

    B_last         = transformed_max - routed
    W_last         = delivered_max - transformed_max     <- the clean outbound wait (SIGNED)
    E2E_complete   = delivered_max - received            (identity: A + B_last + W_last)
    transform_span = transformed_max - transformed_min
    delivery_span  = delivered_max - delivered_min
    L_s3a          = delivered_min - transformed_max     <- STEP 3a's signed L, kept for continuity

**E2E_complete is the only strictly-positive, reference-free latency in the set.** It has a true zero and
no arbitrary origin, so it — not ``W_last`` — is what belongs in a log-log regression against offered
rate. ``W_last`` and ``L_s3a`` STRADDLE ZERO (a delivery can land before a sibling handler's transform;
S3a measured L 50.6% negative). Never put a sign-straddling, near-zero-mean quantity in a ratio or a log.
The ``neg%`` column makes the sign visible instead of burying it in a mean.

4. CENSORING IS REPORTED, NOT SILENTLY DROPPED
----------------------------------------------
A message with ZERO ``delivered`` rows is not "partial" — it never completed. The old tool dropped those
from the population *before* the fan-out gate could see them, so the gate could print "OK" on a rung
where a fifth of the messages never delivered. Near a collapse rung the never-delivered messages are
SYSTEMATICALLY THE SLOW ONES, so dropping them flattens latency exactly where honesty matters most.
This tool counts them (no-routed / no-transformed / no-delivered), prints them, and ``--strict`` fails
on them.

5. RETRIES ARE DETECTED
-----------------------
A delivery retry writes an ADDITIONAL ``delivered`` row (``detail='attempt N'``), which reads as a
fan-out anomaly and inflates ``delivered_max``. This tool selects ``COUNT(DISTINCT destination)``
alongside ``COUNT(*)`` on ``delivered``, so a retried message is identified as a RETRY rather than
averaged in as an 8-way fan-out that happened to have 9 rows.

6. THE PER-LANE NUMBERS ARE NOT A THROUGHPUT ESTIMATOR — READ THE WARNING
------------------------------------------------------------------------
Under the fan-out-to-all shape every message hits every destination, and the outbound lane key IS the
destination name. So each lane receives EXACTLY ONE delivery per message and the mean per-lane
inter-delivery gap is IDENTICALLY ``1/lambda`` at steady state — for any engine, any service time, any
bottleneck. ``lanes / mean_gap == delivery_rate`` is FLOW CONSERVATION, not a measurement, and any
"confirmation" built on it is an identity, not evidence.

What IS informative is lane OCCUPANCY: ``rho = lambda_deliveries × S_lane / lanes``. This tool cannot measure
``S_lane`` (``message_events`` has no claim boundary — there is no ``claimed_at`` stamp), so it reports
``occupancy_accounted`` = ``n_deliveries × --service-ms / window``: a LOWER BOUND on rho built from an
externally-supplied service time. **Feed it the rung's OWN measured service** (the harness report's
``claim_timing.by_stage.outbound`` + ``phase_timing`` send_ack + mark_done) so that a service time
INFLATING with load is visible — that is the only surviving mechanism by which the 8 outbound lanes could
become the binding constraint. It also reports the gap DISTRIBUTION, whose SHAPE (unlike its mean) does
carry information: a rising share of near-zero gaps is the signature of the dispatcher's greedy backlog
re-arm compressing a swept-discovered backlog.

7. THE CONCURRENCY NUMERATOR IS COUNTED, NOT DERIVED
----------------------------------------------------
``concurrency.n_outbound_rows`` is the time-average of ``N(t) = #transformed<=t - #delivered<=t`` — an
EXACT counting process over the rung's full event streams. No pairing, no ``claimed_at``, no Little's
law. Two things it is NOT:

* it is NOT capped at 8. It counts QUEUED **plus** IN-SERVICE outbound rows; only rows in service are
  bounded by the 8 destination lanes. "N is about 8, therefore the lanes are saturated" is a category error.
* its time-average EQUALS ``lambda × W`` on this same data ALGEBRAICALLY. It corroborates the arithmetic; it
  cannot validate Little's law. A check that cannot fail is not a check — cross it against an
  INDEPENDENT gauge (the engine's sampled ``in_pipeline`` queue depth) if you want one that can.

Usage (reads the same MEFOR_STORE_* env the engine uses)::

    python scripts/bench/stage_residency.py --list-rungs                 # discover the rung windows
    python scripts/bench/stage_residency.py --per-rung --json rungs.json \
        --expect-transformed 8 --expect-delivered 8 --trim-head-s 30 --trim-tail-s 10
    python scripts/bench/stage_residency.py --since 1.75e9 --until 1.75e9 \
        --expect-transformed 8 --expect-delivered 8       # ONE cohort, by hand
    python scripts/bench/stage_residency.py --json out.json --limit 50000   # the STEP 2 invocation

PHI: reads ``message_id``, ``event``, ``ts`` and ``destination``. ``destination`` is a CONNECTION NAME
(``OB_SHARED_07``), never a payload — it is required to tell a retry from a fan-out and to see per-lane
structure. No message body is read, ever.
"""

from __future__ import annotations

import argparse
import asyncio
import io
import json
import math
import statistics
import sys
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from messagefoundry.config.settings import load_settings  # noqa: E402
from messagefoundry.store.base import open_store  # noqa: E402

_EVENTS = ("received", "routed", "transformed", "delivered")

#: Idle gap (s) in the ``received`` stream that separates two ladder rungs. Between rungs the fleet is
#: torn down, the store is reset and a fresh fleet comes up — dead air far longer than any intra-rung
#: inter-arrival at these rates. VALIDATE it per run: ``--list-rungs`` must yield exactly as many rungs
#: as were armed, and each rung's ``received`` count must equal that rung's ``acked`` in the drive report.
_RUNG_GAP_S = 10.0

#: Accounted outbound service per delivery (ms) — claim 13.37 + send_ack 0.53 + mark_done 10.52, from the
#: STEP 2 soak's own claim_timing/phase_timing. Used ONLY as the numerator of ``occupancy_accounted``,
#: which is therefore a LOWER BOUND on true lane occupancy. Re-measure it per run and pass --service-ms.
_SERVICE_MS = 24.42


# --------------------------------------------------------------------------------------------------
# SQL. Every query reads message_events and NOTHING else (rule 2), and a window selects MESSAGES via a
# `received`-cohort subselect, never events (rule 1).
# --------------------------------------------------------------------------------------------------


def _cohort_pred(since: float | None, until: float | None) -> str:
    """``message_id IN (the messages RECEIVED in the window)`` — the cohort, as a SQL fragment.

    The bounds are INLINED as float literals, deliberately: the three backends do not share a paramstyle
    (``?`` for aiosqlite/aioodbc, ``$1`` for asyncpg) and one query has to run on all three. They are
    argparse floats, validated finite below — they cannot carry SQL. A bench-only diagnostic; never a
    write path, never PHI.
    """
    if since is None and until is None:
        return ""
    lo = f" AND ts >= {since!r}" if since is not None else ""
    hi = f" AND ts < {until!r}" if until is not None else ""
    return (
        " AND message_id IN (SELECT message_id FROM message_events "
        f"WHERE event = 'received'{lo}{hi})"
    )


def _agg_sql(since: float | None, until: float | None) -> str:
    """MIN/MAX/COUNT/COUNT(DISTINCT destination) per ``(message_id, event)``.

    One query yields BOTH bases, the fan-out multiplicity that the old ``MIN``-only pivot threw away, and
    the distinct-destination count that separates a RETRY (9 delivered rows, 8 destinations) from a
    fan-out anomaly. Aggregated in the store; no raw rows hauled back; no join.
    """
    events = ",".join(f"'{e}'" for e in _EVENTS)
    return (
        "SELECT message_id, event, MIN(ts) AS ts_min, MAX(ts) AS ts_max, COUNT(*) AS n, "
        "COUNT(DISTINCT destination) AS n_dest "
        "FROM message_events "
        f"WHERE event IN ({events}){_cohort_pred(since, until)} "
        "GROUP BY message_id, event"
    )


def _lane_sql(since: float | None, until: float | None) -> str:
    """Every ``delivered`` row of the cohort as ``(destination, ts)`` — the per-lane stream."""
    return (
        "SELECT destination, ts FROM message_events "
        f"WHERE event = 'delivered' AND destination IS NOT NULL{_cohort_pred(since, until)} "
        "ORDER BY destination, ts"
    )


def _transformed_sql(since: float | None, until: float | None) -> str:
    """Every ``transformed`` row of the cohort as a ts stream — the BIRTH of an outbound row.

    The routed->outbound handoff writes one ``transformed`` per handler and produces the outbound rows in
    the SAME committed transaction, so a ``transformed`` stamp is the birth of an outbound row and a
    ``delivered`` stamp is its death. Counting births minus deaths gives ``N_out(t)`` EXACTLY (see
    ``_counting_n``) — no pairing, no ``claimed_at`` column, no Little's law.
    """
    return (
        "SELECT ts FROM message_events "
        f"WHERE event = 'transformed'{_cohort_pred(since, until)} "
        "ORDER BY ts"
    )


def _extent_sql() -> str:
    return "SELECT COUNT(*), MIN(ts), MAX(ts) FROM message_events"


def _received_ts_sql() -> str:
    return "SELECT ts FROM message_events WHERE event = 'received' ORDER BY ts"


async def _query(store: Any, sql: str) -> list[tuple[Any, ...]]:
    """Run ``sql`` through the BACKEND's own connection primitives, returning positional rows.

    The ``Store`` protocol exposes no raw-query escape hatch by design (``base.py``: route a one-off
    through the backend's own ``_acquire``/``_cursor``). This is a bench diagnostic, so it does exactly
    that rather than widening the protocol. ``tuple(row)`` normalises ``aiosqlite.Row`` / ``pyodbc.Row``
    / ``asyncpg.Record`` to a positional tuple.

    ORDER MATTERS: ``SqlServerStore`` has BOTH ``_pool`` and ``_acquire``/``_cursor``; ``PostgresStore``
    has ``_pool`` only. Test for the aioodbc cursor pair BEFORE the asyncpg pool.
    """
    db = getattr(store, "_db", None)  # SQLite — a single aiosqlite handle.
    if db is not None:
        cur = await db.execute(sql)
        try:
            return [tuple(r) for r in await cur.fetchall()]
        finally:
            await cur.close()

    if hasattr(store, "_acquire") and hasattr(store, "_cursor"):  # SQL Server — aioodbc (EF-6).
        async with store._acquire() as conn, store._cursor(conn) as cur:
            await cur.execute(sql)
            return [tuple(r) for r in await cur.fetchall()]

    pool = getattr(store, "_pool", None)  # Postgres — asyncpg.
    if pool is not None:
        async with pool.acquire() as conn:
            rows = await conn.fetch(sql)
        return [tuple(r) for r in rows]

    raise RuntimeError(f"no known connection primitive on {type(store).__name__}")


# --------------------------------------------------------------------------------------------------
# Aggregation
# --------------------------------------------------------------------------------------------------


@dataclass
class _Agg:
    """One message's stage stamps. ``*_min``/``*_max`` differ only where the message fans out."""

    received: float | None = None
    routed: float | None = None
    t_min: float | None = None
    t_max: float | None = None
    n_transformed: int = 0
    d_min: float | None = None
    d_max: float | None = None
    n_delivered: int = 0
    n_dest: int = 0

    @property
    def complete(self) -> bool:
        """Ran the whole path. An incomplete message is CENSORED — counted and reported (rule 4), never
        silently dropped and never zeroed (a zero would drag every statistic toward the floor)."""
        return (
            self.received is not None
            and self.routed is not None
            and self.t_min is not None
            and self.d_min is not None
        )

    @property
    def retried(self) -> bool:
        """More ``delivered`` rows than distinct destinations means at least one redelivery attempt."""
        return self.n_delivered > self.n_dest


@dataclass
class _Lane:
    destination: str
    ts: list[float] = field(default_factory=list)


def _pct(values: list[float], p: float) -> float:
    if not values:
        return 0.0
    s = sorted(values)
    k = max(0, min(len(s) - 1, int(round((p / 100.0) * (len(s) - 1)))))
    return s[k]


def _summarise(
    basis: str, name: str, values: list[float], *, signed: bool = False
) -> dict[str, Any]:
    """Median + an explicit quantile ladder + the negative fraction. The mean is printed but is NEVER the
    headline: a statistic used for a verdict must be location-invariant, must not divide by a near-zero
    or sign-straddling quantity, and must not presuppose distributional structure."""
    n = len(values)
    neg = sum(1 for v in values if v < 0.0)
    return {
        "basis": basis,
        "stage": name,
        "signed": signed,
        "n": n,
        "mean_ms": round(statistics.fmean(values) * 1000, 3) if values else 0.0,
        "p50_ms": round(_pct(values, 50) * 1000, 3),
        "p90_ms": round(_pct(values, 90) * 1000, 3),
        "p95_ms": round(_pct(values, 95) * 1000, 3),
        "p99_ms": round(_pct(values, 99) * 1000, 3),
        "frac_negative": round(neg / n, 4) if n else 0.0,
    }


def _decompose(aggs: list[_Agg]) -> list[dict[str, Any]]:
    a: list[float] = []
    b: list[float] = []
    c_first: list[float] = []
    e2e_first: list[float] = []
    b_last: list[float] = []
    w_last: list[float] = []
    e2e_complete: list[float] = []
    t_span: list[float] = []
    d_span: list[float] = []
    l_s3a: list[float] = []

    for m in aggs:
        rec, rou = m.received, m.routed  # `complete` proved these; rebound for mypy --strict.
        tmin, tmax, dmin, dmax = m.t_min, m.t_max, m.d_min, m.d_max
        if rec is None or rou is None or tmin is None or tmax is None:
            continue
        if dmin is None or dmax is None:
            continue
        a.append(rou - rec)
        b.append(tmin - rou)
        c_first.append(dmin - tmin)
        e2e_first.append(dmin - rec)
        b_last.append(tmax - rou)
        w_last.append(dmax - tmax)
        e2e_complete.append(dmax - rec)
        t_span.append(tmax - tmin)
        d_span.append(dmax - dmin)
        l_s3a.append(dmin - tmax)

    f, k = "first-delivery", "completion"
    return [
        _summarise(f, "A   received -> routed", a),
        _summarise(f, "B   routed -> transformed_min  (FIRST transform)", b),
        _summarise(f, "C_first   transformed_min -> delivered_min", c_first),
        _summarise(f, "E2E_first   received -> delivered_min  (NOT the whole life)", e2e_first),
        _summarise(k, "B_last   routed -> transformed_max  (LAST transform)", b_last),
        _summarise(
            k, "W_last   transformed_max -> delivered_max  (OUTBOUND WAIT)", w_last, signed=True
        ),
        _summarise(k, "E2E_complete   received -> delivered_max  (WHOLE LIFE)", e2e_complete),
        _summarise(k, "transform_span   transformed_max - transformed_min", t_span),
        _summarise(k, "delivery_span    delivered_max - delivered_min", d_span),
        _summarise(
            k, "L_s3a   transformed_max -> delivered_min  (S3a signed L)", l_s3a, signed=True
        ),
    ]


def _census(aggs: list[_Agg], expect_t: int | None, expect_d: int | None) -> dict[str, Any]:
    """The population census + fan-out gate. LOUD by construction, and TRI-STATE.

    Four independent failure modes, reported separately because they mean different things:

    * CENSORED — the message never routed / never transformed / never delivered. NOT a fan-out problem:
      a COMPLETION problem. Near a collapse rung these are systematically the SLOW messages, so dropping
      them biases latency DOWN exactly where it matters.
    * MODAL MISMATCH — the typical message's fan-out is not the topology's => the SHAPE is not what you
      think it is (wiring, or a wrong ``--expect``).
    * PARTIAL — right modal, but some complete-path messages are missing fan-out rows. In COHORT mode a
      window CANNOT clip a delivery, so a partial is genuinely in flight or dead-lettered.
    * RETRY — more ``delivered`` rows than distinct destinations; ``delivered_max`` is a REDELIVERY, so
      that message's W_last/E2E_complete are inflated.

    ``ok`` is ``None`` when the gate is UNARMED (no topology passed). "No verdict" must be
    distinguishable from "verdict: failed" — a bare ``False`` would read as a refutation never made.
    """
    total = len(aggs)
    complete = [m for m in aggs if m.complete]
    no_route = sum(1 for m in aggs if m.routed is None)
    no_transform = sum(1 for m in aggs if m.routed is not None and m.t_min is None)
    no_delivery = sum(1 for m in aggs if m.t_min is not None and m.d_min is None)
    censored = total - len(complete)
    retried = sum(1 for m in complete if m.retried)

    hist = Counter((m.n_transformed, m.n_delivered) for m in complete)
    modal, modal_n = hist.most_common(1)[0] if hist else ((0, 0), 0)
    expected = (expect_t, expect_d) if expect_t is not None and expect_d is not None else None
    full = sum(n for key, n in hist.items() if key == expected) if expected is not None else 0
    modal_ok: bool | None = None if expected is None else modal == expected
    ok: bool | None = None
    if expected is not None:
        ok = bool(modal_ok) and full == len(complete) and censored == 0 and retried == 0

    return {
        "messages_in_cohort": total,
        "complete_path": len(complete),
        "censored": censored,
        "censored_frac": round(censored / total, 4) if total else 0.0,
        "censored_breakdown": {
            "no_routed": no_route,
            "no_transformed": no_transform,
            "no_delivered": no_delivery,
        },
        "retried_messages": retried,
        "modal": list(modal),
        "modal_count": modal_n,
        "modal_share": round(modal_n / len(complete), 4) if complete else 0.0,
        "modal_ok": modal_ok,
        "expected": list(expected) if expected else None,
        "full_fanout_messages": full if expected else None,
        "partial_fanout_messages": (len(complete) - full) if expected else None,
        "histogram": [
            {"n_transformed": key[0], "n_delivered": key[1], "messages": v}
            for key, v in hist.most_common(12)
        ],
        "ok": ok,
    }


def _lane_stats(lanes: list[_Lane], service_ms: float, lo: float, hi: float) -> dict[str, Any]:
    """Per-destination (= per outbound LANE) delivery structure, over the ANALYSIS WINDOW ``[lo, hi]``.

    READ RULE 6. Under fan-out-to-all each lane takes exactly one delivery per message, so
    ``lanes / mean_gap`` REPRODUCES the delivery rate identically — flow conservation, not evidence. It
    must never be used as a "manipulation check" or a decision rule.

    What is reported here that DOES carry information:

    * ``occupancy_accounted`` = n × service_ms / window — a LOWER BOUND on lane utilisation rho, built
      from an EXTERNALLY supplied service time (this table has no claim boundary, so the tool cannot
      measure S_lane). If the bound is already near 1.0 the lanes are provably saturated. Feed it the
      rung's OWN measured service time (``claim_timing.by_stage.outbound`` + ``phase_timing`` send_ack +
      mark_done) via ``--service-ms``, so that a service time INFLATING with load is visible — that is the
      only surviving mechanism by which the lanes could become the bound.
    * ``frac_gaps_below_service`` — the share of inter-delivery gaps shorter than the accounted service
      time, i.e. deliveries arriving back-to-back. Its GROWTH with load is the signature of greedy
      backlog compression (the sweep wait would then NOT be a throughput bound); its FLATNESS is the
      opposite.
    * the gap quantile ladder — SHAPE, not mean.

    Report the MAX over lanes, not just the mean: a sustained rung requires EVERY lane to keep up, so the
    binding constraint is the SLOWEST lane, and averaging over lanes destroys exactly that.
    """
    svc = service_ms / 1000.0
    window = max(0.0, hi - lo)
    out: list[dict[str, Any]] = []
    for lane in sorted(lanes, key=lambda x: x.destination):
        ts = sorted(t for t in lane.ts if lo <= t < hi)
        n = len(ts)
        gaps = [b - a for a, b in zip(ts, ts[1:], strict=False)]
        below = sum(1 for g in gaps if g < svc)
        out.append(
            {
                "destination": lane.destination,
                "deliveries": n,
                "window_s": round(window, 3),
                "rate_per_s": round(n / window, 3) if window > 0 else 0.0,
                "gap_mean_ms": round(statistics.fmean(gaps) * 1000, 3) if gaps else 0.0,
                "gap_p50_ms": round(_pct(gaps, 50) * 1000, 3),
                "gap_p90_ms": round(_pct(gaps, 90) * 1000, 3),
                "gap_p99_ms": round(_pct(gaps, 99) * 1000, 3),
                "frac_gaps_below_service": round(below / len(gaps), 4) if gaps else 0.0,
                "occupancy_accounted": round(min(1.0, n * svc / window), 4) if window > 0 else 0.0,
            }
        )
    occ = [float(x["occupancy_accounted"]) for x in out]
    frac = [float(x["frac_gaps_below_service"]) for x in out]
    return {
        "service_ms": service_ms,
        "lanes_observed": len(out),
        "occupancy_accounted_mean": round(statistics.fmean(occ), 4) if occ else 0.0,
        "occupancy_accounted_max": round(max(occ), 4) if occ else 0.0,
        "frac_gaps_below_service_mean": round(statistics.fmean(frac), 4) if frac else 0.0,
        "identity_warning": (
            "lanes / mean_gap == delivery_rate is FLOW CONSERVATION under fan-out-to-all "
            "(one delivery per lane per message). It is NOT a measurement and NOT a check."
        ),
        "lanes": out,
    }


def _segment(ts: list[float], gap: float) -> list[tuple[float, float, int]]:
    """Segment a sorted ts stream on idle gaps >= ``gap`` -> ``[(first_ts, last_ts, n), ...]``."""
    if not ts:
        return []
    segs: list[tuple[float, float, int]] = []
    start = prev = ts[0]
    n = 1
    for t in ts[1:]:
        if t - prev >= gap:
            segs.append((start, prev, n))
            start, n = t, 0
        prev = t
        n += 1
    segs.append((start, prev, n))
    return segs


# --------------------------------------------------------------------------------------------------
# Collection
# --------------------------------------------------------------------------------------------------


def _build_aggs(rows: list[tuple[Any, ...]]) -> dict[str, _Agg]:
    by_msg: dict[str, _Agg] = {}
    for mid, event, ts_min, ts_max, n, n_dest in rows:
        m = by_msg.setdefault(str(mid), _Agg())
        lo_f, hi_f, cnt, dst = float(ts_min), float(ts_max), int(n), int(n_dest)
        if event == "received":
            m.received = lo_f
        elif event == "routed":
            m.routed = lo_f
        elif event == "transformed":
            m.t_min, m.t_max, m.n_transformed = lo_f, hi_f, cnt
        elif event == "delivered":
            m.d_min, m.d_max, m.n_delivered, m.n_dest = lo_f, hi_f, cnt, dst
    return by_msg


def _build_lanes(rows: list[tuple[Any, ...]]) -> list[_Lane]:
    by_dest: dict[str, _Lane] = {}
    for dest, ts in rows:
        d = str(dest)
        by_dest.setdefault(d, _Lane(d)).ts.append(float(ts))
    return list(by_dest.values())


def _counting_n(births: list[float], deaths: list[float], lo: float, hi: float) -> dict[str, float]:
    """Time-average and peak of the EXACT counting process ``N(t) = #births<=t - #deaths<=t`` over
    ``[lo, hi]``.

    This is the concurrency numerator, and it is measured, not derived. It needs NO pairing of a birth to
    its death (the store does not record which outbound row a ``delivered`` belongs to), NO ``claimed_at``
    column, and NO Little's law: it is a count.

    IT IS EXACT ONLY IF EVERY birth AND death IN THE WINDOW IS IN THE STREAMS. So the caller passes the
    FULL RUNG's streams and averages over a SUB-window: a rung's cohort is closed (the store is reset
    between rungs and the fleet is fresh), so within a rung nothing is born or dies outside the cohort.
    Passing a TRIMMED cohort's streams here would drop births that are still alive during the window and
    under-count N — do not do it.

    ONE THING THIS CANNOT DO: it cannot validate Little's law. Its time-average equals ``lambda x W`` on
    this same data ALGEBRAICALLY. Compare it against an INDEPENDENT gauge (the engine's sampled
    ``in_pipeline`` queue depth) if you want a cross-check that can actually fail.
    """
    if hi <= lo:
        return {"time_avg": 0.0, "peak": 0.0, "at_lo": 0.0, "at_hi": 0.0}
    marks: list[tuple[float, int]] = [(t, 1) for t in births] + [(t, -1) for t in deaths]
    marks.sort()
    n = 0
    area = 0.0
    peak = 0.0
    prev = lo
    at_lo = 0.0
    for t, delta in marks:
        if t <= lo:
            n += delta
            continue
        if at_lo == 0.0 and prev == lo:
            at_lo = float(n)
        clamped = min(t, hi)
        if clamped > prev:
            area += n * (clamped - prev)
            peak = max(peak, float(n))
            prev = clamped
        if t >= hi:
            break
        n += delta
    if prev < hi:
        area += n * (hi - prev)
        peak = max(peak, float(n))
    return {
        "time_avg": round(area / (hi - lo), 4),
        "peak": round(peak, 4),
        "at_lo": round(at_lo, 4),
        "at_hi": round(float(n), 4),
    }


async def _window_report(
    store: Any,
    *,
    since: float | None,
    until: float | None,
    trim_head_s: float,
    trim_tail_s: float,
    expect_t: int | None,
    expect_d: int | None,
    full_only: bool,
    limit: int | None,
    service_ms: float,
    label: str,
) -> dict[str, Any]:
    """One rung / one window, decomposed. THREE populations, deliberately kept distinct:

    * the COHORT — every message ``received`` in ``[since, until)``. Its streams (all births, all deaths)
      are read in FULL, with NO event-ts filter, so nothing is ever truncated.
    * the ANALYSIS WINDOW ``[lo, hi]`` = the cohort's received span, trimmed by ``trim_head_s`` /
      ``trim_tail_s``. This is a TIME window, and it is what the RATES and the CONCURRENCY numerator are
      averaged over. Trimming it cannot censor anything: the counting process uses the FULL streams.
    * the LATENCY POPULATION — the cohort messages RECEIVED inside the analysis window. Every one of them
      contributes its whole life, because its events were never ts-filtered.

    Keeping these separate is what makes the steady-state trim safe. Trimming an EVENT window (the old
    behaviour) truncates the slowest messages' deliveries and drives the fitted latency slope to zero.
    """
    aggs_map = _build_aggs(await _query(store, _agg_sql(since, until)))
    lane_rows = await _query(store, _lane_sql(since, until))
    transformed_ts = [float(r[0]) for r in await _query(store, _transformed_sql(since, until))]

    # Deterministic order (by received ts) so a --limit run is reproducible, and the census is computed
    # over the FULL cohort BEFORE any truncation — a gate must never read "OK" on an arbitrary subset.
    aggs = sorted(aggs_map.values(), key=lambda m: m.received if m.received is not None else 0.0)
    recv_all = [m.received for m in aggs if m.received is not None]
    if not recv_all:
        lo = hi = 0.0
    else:
        lo = min(recv_all) + trim_head_s
        # UNTRIMMED tail: the window must end just PAST the last arrival, or the half-open bound silently
        # drops the cohort's last message. The cost is that lambda = n/span then overstates the true
        # arrival rate by 1/span (<1% at a 120 s hold). TRIM, and the window becomes a clean fixed
        # interval over which n/window is exact — which is why the run pre-registers a trim.
        hi = (
            (max(recv_all) - trim_tail_s)
            if trim_tail_s > 0
            else math.nextafter(max(recv_all), math.inf)
        )
    window_s = max(0.0, hi - lo)

    in_win = (
        [m for m in aggs if m.received is not None and lo <= m.received < hi] if window_s else []
    )
    census = _census(in_win, expect_t, expect_d)

    pop = [m for m in in_win if m.complete]
    population = "complete-path"
    if full_only and census["expected"] is not None:
        want = (int(census["expected"][0]), int(census["expected"][1]))
        pop = [m for m in pop if (m.n_transformed, m.n_delivered) == want]
        population = "full-fan-out only"
    if limit is not None:
        pop = pop[:limit]

    delivered_ts = [float(ts) for _, ts in lane_rows]
    n_out = _counting_n(transformed_ts, delivered_ts, lo, hi)
    # Messages in flight: born at `received`, dead at the LAST delivery. Same caveat — its time-average is
    # lambda x W by construction, so it corroborates the arithmetic; it cannot validate it.
    n_e2e = _counting_n(
        [m.received for m in aggs if m.received is not None],
        [m.d_max for m in aggs if m.d_max is not None],
        lo,
        hi,
    )

    n_recv_win = sum(1 for m in aggs if m.received is not None and lo <= m.received < hi)
    n_del_win = sum(1 for ts in delivered_ts if lo <= ts < hi)
    return {
        "label": label,
        "window": {"since": since, "until": until},
        "analysis_window": {"lo": lo, "hi": hi, "seconds": round(window_s, 3)},
        "trim_head_s": trim_head_s,
        "trim_tail_s": trim_tail_s,
        # Rates from the SAME event stream over the SAME window as N and W — never mixed with a drive-side
        # figure computed over a different interval (N, lambda and W must share a population).
        "lambda_msg_per_s": round(n_recv_win / window_s, 4) if window_s > 0 else 0.0,
        "lambda_del_per_s": round(n_del_win / window_s, 4) if window_s > 0 else 0.0,
        "concurrency": {
            "n_outbound_rows": n_out,  # EXACT count: transformed(born) - delivered(died)
            "n_messages_in_flight": n_e2e,
            "note": (
                "n_outbound_rows counts QUEUED + IN-SERVICE outbound rows. It has NO cap of 8 — the "
                "8-lane cap bounds only rows IN SERVICE. Do NOT compare this number to 8 and call the "
                "lanes saturated; compare lane_stats.occupancy_accounted to 1.0 for that."
            ),
        },
        "population": population,
        "population_n": len(pop),
        "census": census,
        "lane_stats": _lane_stats(_build_lanes(lane_rows), service_ms, lo, hi),
        "stages": _decompose(pop),
    }


async def _collect(
    args: argparse.Namespace, expect_t: int | None, expect_d: int | None
) -> dict[str, Any]:
    settings = load_settings()
    store = await open_store(settings.store)
    try:
        extent = await _query(store, _extent_sql())
        n_rows, ts_lo, ts_hi = (
            (int(extent[0][0]), extent[0][1], extent[0][2]) if extent else (0, None, None)
        )
        table = {
            "rows": n_rows,
            "ts_min": float(ts_lo) if ts_lo is not None else None,
            "ts_max": float(ts_hi) if ts_hi is not None else None,
        }

        if args.list_rungs or args.per_rung:
            recv = [float(r[0]) for r in await _query(store, _received_ts_sql())]
            segs = _segment(recv, args.rung_gap)
            rungs: list[dict[str, Any]] = []
            for i, (lo, hi, n) in enumerate(segs):
                # `until` runs to the START of the next rung so a cohort cannot leak a neighbouring
                # rung's messages. In COHORT mode the drain tail is captured regardless (a counted
                # message's events are never ts-filtered), so this bound is about ISOLATION, not clipping.
                nxt = segs[i + 1][0] if i + 1 < len(segs) else None
                end = nxt if nxt is not None else (hi + 1.0)
                rungs.append(
                    {
                        "rung": i,
                        "received": n,
                        "first_received": lo,
                        "last_received": hi,
                        "offered_span_s": round(hi - lo, 3),
                        "since": lo - 0.5,
                        "until": end,
                    }
                )
            if args.list_rungs:
                return {
                    "mode": "list-rungs",
                    "table": table,
                    "rung_gap_s": args.rung_gap,
                    "rungs": rungs,
                }

            reports: list[dict[str, Any]] = []
            for r in rungs:
                # The COHORT is always the WHOLE rung (`since`..`until` = the rung's own bounds), so the
                # counting process N(t) sees every birth and every death and is EXACT. The steady-state
                # TRIM is applied INSIDE _window_report, to the ANALYSIS WINDOW (a time interval) and to
                # the LATENCY POPULATION (which messages) — never to the event streams. That is what makes
                # trimming safe: it cannot truncate a slow message's deliveries.
                if float(r["offered_span_s"]) <= args.trim_head_s + args.trim_tail_s:
                    reports.append(
                        {
                            "label": f"rung {r['rung']}",
                            "rung": r["rung"],
                            "error": "trim window empty — rung shorter than trim_head + trim_tail",
                            "received_untrimmed": r["received"],
                        }
                    )
                    continue
                rep = await _window_report(
                    store,
                    since=float(r["since"]),
                    until=float(r["until"]),
                    trim_head_s=args.trim_head_s,
                    trim_tail_s=args.trim_tail_s,
                    expect_t=expect_t,
                    expect_d=expect_d,
                    full_only=args.full_fanout_only,
                    limit=args.limit,
                    service_ms=args.service_ms,
                    label=f"rung {r['rung']}",
                )
                rep["rung"] = r["rung"]
                rep["received_untrimmed"] = r["received"]
                reports.append(rep)
            return {
                "mode": "per-rung",
                "table": table,
                "rung_gap_s": args.rung_gap,
                "rungs": reports,
            }

        rep = await _window_report(
            store,
            since=args.since,
            until=args.until,
            trim_head_s=args.trim_head_s,
            trim_tail_s=args.trim_tail_s,
            expect_t=expect_t,
            expect_d=expect_d,
            full_only=args.full_fanout_only,
            limit=args.limit,
            service_ms=args.service_ms,
            label="window",
        )
        return {"mode": "residency", "table": table, **rep}
    finally:
        await store.close()


# --------------------------------------------------------------------------------------------------
# Rendering
# --------------------------------------------------------------------------------------------------


def _render_rungs(d: dict[str, Any]) -> str:
    t = d["table"]
    out = [
        "",
        "LADDER RUNGS in message_events  (segmented on `received` idle gaps "
        f">= {d['rung_gap_s']:g}s)",
        f"  table: {t['rows']} rows  ts {t['ts_min']} .. {t['ts_max']}",
        "",
        "  _reset_store DELETEs `messages` PER RUNG but never `message_events` — this table holds EVERY",
        "  rung of the climb while `messages` holds only the last. Window by ts; NEVER join.",
        "",
        "  MANIPULATION CHECK, do it NOW: the rung COUNT below must equal the number of rungs you armed,",
        "  and each rung's `received` must equal that rung's `acked` in the drive report JSON. A mismatch",
        "  means the segmentation is wrong (retry with --rung-gap) and every per-rung number is VOID.",
        "",
        f"  {'rung':>4} {'received':>9} {'offered span':>13}   paste this",
    ]
    for r in d["rungs"]:
        out.append(
            f"  {r['rung']:>4} {r['received']:>9} {r['offered_span_s']:>12.1f}s   "
            f"--since {r['since']!r} --until {r['until']!r}"
        )
    out.append("")
    return "\n".join(out)


def _render_census(c: dict[str, Any], population: str) -> list[str]:
    out = [
        "POPULATION CENSUS",
        f"  cohort={c['messages_in_cohort']}  complete-path={c['complete_path']}  "
        f"CENSORED={c['censored']} ({c['censored_frac'] * 100:.1f}%)  retried={c['retried_messages']}",
        f"  censored breakdown: no_routed={c['censored_breakdown']['no_routed']}  "
        f"no_transformed={c['censored_breakdown']['no_transformed']}  "
        f"no_delivered={c['censored_breakdown']['no_delivered']}",
        f"  modal (n_transformed, n_delivered) = ({c['modal'][0]}, {c['modal'][1]})  "
        f"in {c['modal_count']} of {c['complete_path']} complete ({c['modal_share'] * 100:.1f}%)",
    ]
    if c["expected"] is None:
        out += [
            "  topology expectation: UNKNOWN — pass --expect-transformed/--expect-delivered to ARM the",
            "  gate. Until then this is an UNGATED report and no verdict is made (ok=null).",
        ]
    else:
        out.append(f"  topology implies:  ({c['expected'][0]}, {c['expected'][1]})")
    out.append(
        "  histogram: "
        + "  ".join(
            f"({h['n_transformed']},{h['n_delivered']})={h['messages']}" for h in c["histogram"]
        )
    )
    if c["expected"] is not None and not c["ok"]:
        out += [
            "",
            "  ##############################################################################",
            "  ##  GATE FAILED — DO NOT READ THE NUMBERS BELOW AS THIS COHORT'S RESIDENCY",
        ]
        if not c["modal_ok"]:
            out += [
                f"  ##  MODAL MISMATCH: the typical message fans out ({c['modal'][0]}, "
                f"{c['modal'][1]}) but the topology",
                f"  ##  implies ({c['expected'][0]}, {c['expected'][1]}). The SHAPE is not what you "
                "think it is — check the wiring",
                "  ##  and the --expect flags you passed.",
            ]
        if c["censored"]:
            out += [
                f"  ##  CENSORED: {c['censored']} of {c['messages_in_cohort']} cohort messages never "
                "completed. Near a collapse",
                "  ##  rung these are SYSTEMATICALLY THE SLOW ONES, so excluding them BIASES THE LATENCY",
                "  ##  BELOW DOWNWARD — which is the direction that manufactures a 'latency is flat'",
                "  ##  verdict. Exclude this cohort from any fit and REPORT it as excluded.",
            ]
        if c["partial_fanout_messages"]:
            out += [
                f"  ##  PARTIAL FAN-OUT: {c['partial_fanout_messages']} complete-path messages are "
                "missing fan-out rows. In",
                "  ##  COHORT mode a window CANNOT clip a delivery, so these are genuinely still in",
                "  ##  flight or dead-lettered — a real completion failure, not a windowing artifact.",
            ]
        if c["retried_messages"]:
            out += [
                f"  ##  RETRIES: {c['retried_messages']} messages have more `delivered` rows than "
                "distinct destinations. Their",
                "  ##  delivered_max is a REDELIVERY, which INFLATES W_last / E2E_complete. Retry rate",
                "  ##  plausibly rises with load => a load-dependent UPWARD bias on latency.",
            ]
        if population == "full-fan-out only":
            out += [
                "  ##  --full-fanout-only is ACTIVE: the excluded messages are the SLOW ones, so the",
                "  ##  survivors are a BIASED (fast) sample. Fix the rung; do not filter it.",
            ]
        out.append(
            "  ##############################################################################"
        )
    elif c["expected"] is not None:
        out.append("  gate: OK — no censoring, no partials, no retries, modal == topology.")
    return out


def _render_lanes(ls: dict[str, Any]) -> list[str]:
    out = [
        "",
        f"PER-LANE (the outbound lane key IS the destination name)   service_ms={ls['service_ms']:g}",
        "  !! lanes / mean_gap == delivery_rate is an IDENTITY under fan-out-to-all (one delivery per",
        "  !! lane per message). It is flow conservation, NOT a measurement. NEVER gate on it.",
        f"  lanes={ls['lanes_observed']}   occupancy_accounted mean="
        f"{ls['occupancy_accounted_mean']:.3f} MAX={ls['occupancy_accounted_max']:.3f}   "
        "(a LOWER BOUND on rho: no claim stamp in this table)",
        f"  frac gaps < service (back-to-back deliveries) mean="
        f"{ls['frac_gaps_below_service_mean']:.3f}   <- its GROWTH with load = backlog compression",
        "",
        f"  {'destination':<16} {'n':>7} {'rate/s':>8} {'gap p50':>10} {'gap p90':>10} "
        f"{'gap p99':>10} {'<svc':>6} {'occ':>6}",
    ]
    for lane in ls["lanes"]:
        out.append(
            f"  {lane['destination']:<16} {lane['deliveries']:>7} {lane['rate_per_s']:>8.2f} "
            f"{lane['gap_p50_ms']:>8.1f}ms {lane['gap_p90_ms']:>8.1f}ms {lane['gap_p99_ms']:>8.1f}ms "
            f"{lane['frac_gaps_below_service'] * 100:>5.1f}% {lane['occupancy_accounted']:>6.3f}"
        )
    return out


def _render_stages(stages: list[dict[str, Any]]) -> list[str]:
    out = [
        "",
        f"  {'stage':<58} {'n':>7} {'mean':>9} {'p50':>9} {'p90':>9} {'p95':>9} "
        f"{'p99':>9} {'neg%':>6}",
    ]
    basis = ""
    for s in stages:
        if s["basis"] != basis:
            basis = s["basis"]
            label = (
                "-- FIRST-DELIVERY BASIS (STEP 2 continuity ONLY — not the message's life) --"
                if basis == "first-delivery"
                else "-- COMPLETION BASIS (the actual life; every fan-out row in existence) --"
            )
            out.append(f"  {label}")
        out.append(
            f"  {s['stage']:<58} {s['n']:>7} {s['mean_ms']:>8.1f}ms "
            f"{s['p50_ms']:>7.1f}ms {s['p90_ms']:>7.1f}ms {s['p95_ms']:>7.1f}ms "
            f"{s['p99_ms']:>7.1f}ms {s['frac_negative'] * 100:>5.1f}%"
        )
    return out


def _render_concurrency(c: dict[str, Any]) -> list[str]:
    o, e = c["n_outbound_rows"], c["n_messages_in_flight"]
    return [
        "",
        "CONCURRENCY — the EXACT counting process (births - deaths), not lambda x W",
        f"  N_outbound_rows   time-avg={o['time_avg']:.3f}  peak={o['peak']:.0f}   "
        f"(transformed = born, delivered = died)",
        f"  N_messages_in_flight time-avg={e['time_avg']:.3f}  peak={e['peak']:.0f}",
        "  N_outbound_rows is QUEUED + IN-SERVICE. It is NOT capped at 8 — only rows IN SERVICE are.",
        "  Do not read 'N ~ 8' as 'the 8 lanes are saturated'; read occupancy_accounted for that.",
        "  Its time-average equals lambda x W on this same data ALGEBRAICALLY — it corroborates the",
        "  arithmetic, it cannot validate it. Cross-check it against the engine's SAMPLED in_pipeline.",
    ]


def _render_report(r: dict[str, Any]) -> list[str]:
    w, aw = r["window"], r["analysis_window"]
    win = (
        "whole table"
        if w["since"] is None and w["until"] is None
        else f"{w['since']} .. {w['until']}"
    )
    out = [
        "",
        f"=== {r['label'].upper()} ===",
        f"  cohort (RECEIVED ts, events NEVER ts-filtered): {win}",
        f"  analysis window: {aw['lo']} .. {aw['hi']}  ({aw['seconds']:.1f}s; "
        f"trim head={r['trim_head_s']:g}s tail={r['trim_tail_s']:g}s)",
        f"  population: {r['population']} (n={r['population_n']})   "
        f"lambda_msg={r['lambda_msg_per_s']:.3f}/s   lambda_del={r['lambda_del_per_s']:.3f}/s",
        "",
    ]
    out += _render_census(r["census"], r["population"])
    out += _render_concurrency(r["concurrency"])
    out += _render_stages(r["stages"])
    out += _render_lanes(r["lane_stats"])
    return out


_FOOTER = [
    "",
    "  Identities (per message): E2E_first = A + B + C_first;  E2E_complete = A + B_last + W_last.",
    "  W_last and L_s3a are SIGNED — a delivery can land BEFORE a sibling handler's transform. Read the",
    "  MEDIAN and the ladder; never a ratio of means, never a log of a sign-straddling quantity.",
    "  E2E_complete is the ONLY strictly-positive, reference-free latency here — regress on THAT.",
    "  Read each term against the stage's MEASURED service time (report `claim_timing.by_stage`): a",
    "  residency that dwarfs its stage's service time is IDLE WAITING — that is the residual.",
    "",
]


def _render(d: dict[str, Any]) -> str:
    t = d["table"]
    out = [
        "",
        "PER-STAGE RESIDENCY — where a message's wall-clock actually goes",
        f"  table: {t['rows']} rows  ts {t['ts_min']} .. {t['ts_max']}",
        "  (message_events is cleared by NOTHING — not _reset_store, not the fleet, not the ladder. If",
        "   this table was not truncated before the run, it holds PRIOR runs too. Check --list-rungs.)",
    ]
    if d["mode"] == "per-rung":
        for r in d["rungs"]:
            if "error" in r:
                out += ["", f"=== RUNG {r['rung']} — SKIPPED: {r['error']} ==="]
                continue
            out += _render_report(r)
    else:
        out += _render_report(d)
    out += _FOOTER
    return "\n".join(out)


def _finite(v: float | None, flag: str) -> float | None:
    if v is not None and not math.isfinite(v):
        raise SystemExit(f"{flag} must be a finite epoch-seconds value, got {v!r}")
    return v


def _gate_failures(d: dict[str, Any]) -> list[str]:
    reports = d["rungs"] if d["mode"] == "per-rung" else [d]
    return [
        str(r.get("label", "window"))
        for r in reports
        if "error" in r or r.get("census", {}).get("ok") is not True
    ]


def main() -> int:
    # This report carries U+2014 EM DASH. On Windows a REDIRECTED stdout defaults to the ANSI codepage, so
    # `... > out.txt` would die with UnicodeEncodeError at exactly the moment the artifact is banked.
    for stream in (sys.stdout, sys.stderr):
        if isinstance(stream, io.TextIOWrapper):
            stream.reconfigure(encoding="utf-8", errors="replace")

    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("--json", type=Path, default=None, help="also write the decomposition as JSON")
    ap.add_argument(
        "--limit",
        type=int,
        default=None,
        help="cap the messages kept AFTER the census (deterministic: earliest received first)",
    )
    ap.add_argument(
        "--since",
        type=float,
        default=None,
        help="COHORT bound: keep messages whose `received` ts >= S. Their EVENTS are never ts-filtered.",
    )
    ap.add_argument(
        "--until",
        type=float,
        default=None,
        help="COHORT bound: keep messages whose `received` ts < U. Their EVENTS are never ts-filtered.",
    )
    ap.add_argument(
        "--list-rungs",
        action="store_true",
        help="segment message_events into ladder rungs and print a --since/--until for each",
    )
    ap.add_argument(
        "--per-rung",
        action="store_true",
        help="segment into rungs and emit the FULL residency + lane report for EVERY rung, in one JSON",
    )
    ap.add_argument(
        "--rung-gap",
        type=float,
        default=_RUNG_GAP_S,
        help=f"idle gap (s) separating rungs (default {_RUNG_GAP_S:g})",
    )
    ap.add_argument(
        "--trim-head-s",
        type=float,
        default=0.0,
        help="--per-rung: drop messages received in the rung's first S seconds (fill transient)",
    )
    ap.add_argument(
        "--trim-tail-s",
        type=float,
        default=0.0,
        help="--per-rung: drop messages received in the rung's last S seconds (stop edge)",
    )
    ap.add_argument(
        "--service-ms",
        type=float,
        default=_SERVICE_MS,
        help=f"accounted outbound service per delivery, ms (default {_SERVICE_MS:g}) — RE-MEASURE IT",
    )
    ap.add_argument(
        "--expect-transformed",
        type=int,
        default=None,
        help="topology's handler count H — arms the gate",
    )
    ap.add_argument(
        "--expect-delivered",
        type=int,
        default=None,
        help="topology's delivering (destination) count D — arms the gate",
    )
    ap.add_argument(
        "--full-fanout-only",
        action="store_true",
        help="restrict to full-fan-out messages (BIASED: the excluded messages are the SLOW ones)",
    )
    ap.add_argument(
        "--strict",
        action="store_true",
        help="exit 2 if ANY reported cohort fails the gate (censoring / partial / retry / modal)",
    )
    args = ap.parse_args()

    if args.list_rungs and args.per_rung:
        raise SystemExit("--list-rungs and --per-rung are mutually exclusive")
    args.since = _finite(args.since, "--since")
    args.until = _finite(args.until, "--until")
    if args.since is not None and args.until is not None and args.until <= args.since:
        raise SystemExit(f"--until ({args.until!r}) must be greater than --since ({args.since!r})")
    if args.trim_head_s < 0 or args.trim_tail_s < 0:
        raise SystemExit("--trim-head-s / --trim-tail-s must be >= 0")
    if args.service_ms <= 0:
        raise SystemExit("--service-ms must be > 0")

    expect_t, expect_d = args.expect_transformed, args.expect_delivered
    if args.strict and (expect_t is None or expect_d is None):
        raise SystemExit(
            "--strict needs an ARMED gate: pass --expect-transformed H --expect-delivered D. "
            "Refusing to fail on a verdict this tool never made."
        )

    d = asyncio.run(_collect(args, expect_t, expect_d))

    # The JSON artifact is written BEFORE the table renders: rendering to a redirected stdout can still
    # fail on a legacy console, and the artifact is the thing you cannot re-derive once the next soak
    # starts.
    if args.json:
        args.json.write_text(json.dumps(d, indent=2), encoding="utf-8")

    if d["mode"] == "list-rungs":
        print(_render_rungs(d))
        if not d["rungs"]:
            print("  NO `received` EVENTS — nothing to segment.", file=sys.stderr)
            return 1
        if args.json:
            print(f"  wrote {args.json}")
        return 0

    reports = d["rungs"] if d["mode"] == "per-rung" else [d]
    if not any(r.get("population_n") for r in reports):
        print(
            "\n  NO COMPLETE-PATH MESSAGES FOUND.\n"
            "  Either no soak has run against this store, or the cohort window excluded every message,\n"
            "  or this is not the store the soak wrote to — check MEFOR_STORE_* in THIS shell (with none\n"
            "  set, settings default to a local SQLite file and this script measures an empty one).\n"
            "  `message_events` is NOT cleared by _reset_store, so an inherited rig's rows persist: run\n"
            "  --list-rungs to see what is actually in the table before concluding it is the wrong one.\n",
            file=sys.stderr,
        )
        return 1

    print(_render(d))
    if args.json:
        print(f"  wrote {args.json}")
    if args.strict:
        bad = _gate_failures(d)
        if bad:
            print(f"  GATE FAILED (--strict) for: {', '.join(bad)}", file=sys.stderr)
            return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
