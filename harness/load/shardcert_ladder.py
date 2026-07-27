# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Turnkey two-box SIZING **ceiling-pin** ladder (PR-C2, ADR 0073).

Automates the manual per-rung ceiling hunt (``C1-MANUAL-LADDER-runbook.md``) that pinned the post-#842
delivered-throughput ceiling by hand: two commands per rate, one per box, run N times. Here an
:func:`run_engine_ladder` (engine box) and an :func:`run_drive_ladder` (load-gen box) iterate the SAME
fixed rung plan in LOCKSTEP, meeting per rung under a per-rung ``run_id`` (:meth:`FileDropCoord.for_run`),
reusing the already-rig-validated C1 primitives (:func:`run_shardcert_engine` / :func:`run_shardcert_drive`)
UNCHANGED. It adds four things the manual flow lacked:

1. **A rate ladder that climbs past the known floor** until a rung is not sustained, with an early-stop
   signal (the drive posts :data:`LADDER_STOP`; the engine skips the rest — best-effort, degrades to the
   bounded plan on a lost signal, never a hang).
2. **A post-hold DRAIN WINDOW** — the drive tallies its sinks only after the engine's RELIABLE store-truth
   drain gate (:data:`ENGINE_DRAINED`), so a teardown-frozen in-flight tail is absorbed rather than
   mis-read as loss. This is what lets :func:`classify_rung` tell true congestion-collapse (the engine
   could not clear the backlog) from a latency tail (the engine drained clean but the sink came up short).
3. **A soak** at the pinned sustainable rate (≥5 min) that asserts lossless + a bounded/draining
   in_pipeline slope (the sustainable-vs-slow-saturation discriminator).
4. **One consolidated report** (JSON + human-readable): a per-rung table (ingress offered / outbound
   offered / delivered / drained / verdict), the pinned ceiling in BOTH ingress-msg/s and
   outbound-deliveries/s, the soak slope, and the per-shard ``send_ack``/``mark_done`` phase-timing split.

**Judged ONLY by the reliable authorities** — the DRIVE sink socket-truth (``S == A*delivering ∧ A>0 ∧
S>0 ∧ Σinversions==0 ∧ Σrepeats==0 ∧ lanes≥2``) and the ENGINE store-truth (``drained ∧ stranded==0 ∧
dead_total==0``). The remote ``/stats`` poller stays advisory (unreliable on a unified store — #841) and is
never gated on. **This bench REPORTS numbers; it does NOT flip ``SYSTEM-REQUIREMENTS.md §8`` or grade its
own fix** (the two-box governance rule). Counts + synthetic topology only — never message bodies /
control-ids (PHI rule).

The **target** is the 45M-messages/day figure = 45_000_000 / 86_400 ≈ **520.83 TOTAL message events/s**
(:data:`TARGET_EVENTS_PER_S`) — inbound *and* outbound, per the owner ruling. An accepted message DELIVERS
to ``delivering`` (D) destinations, so it produces ``1 + D`` total events (``delivered = ingress * D``) and
the sustainable ingress that saturates the budget is ``TARGET_EVENTS_PER_S / (1 + D)``. The report states
BOTH figures.

.. warning::
   **The fan-out is ``delivering`` (D), never ``dests``** (BACKLOG #209). ``dests`` is the count of shared
   outbound destination CONNECTIONS — the sink port-band width, TOPOLOGY. ``handlers`` (H) is how many the
   router SELECTS (it feeds the reported ``txn/msg = 3 + 2H + 2D`` and NEVER any delivery arithmetic). They
   all default to each other (``H = D = dests = 8``), which is what the graph did before the split, so no
   published run changes. But modelling the reference ``H=20, D=4`` ADT hub by simply raising ``dests`` to
   20 would build 20 connections, deliver 20 copies, and report ``sustained_events_per_s = p*21`` against a
   truth of ``p*5`` — a **4.2x overstatement of the headline number the §8 decision keys off**. That is
   harness defect **B10** again, in the permissive direction. Keep D out of ``dests`` and dests out of the
   arithmetic.

.. warning::
   Until 2026-07-10 :data:`TARGET_EVENTS_PER_S` was named ``TARGET_INGRESS_PER_S`` and the gate compared it
   against a pure **ingress** rate — a units defect (harness defect **B10**) that made the gate
   ``(1 + dests)``x too strict, i.e. **9x** at the bench default ``dests=8``. Every "52x short" figure
   published before that date carries that inflation. The JSON keys were renamed in ``schema_version`` 3 so
   that a stale consumer fails loudly with a ``KeyError`` rather than silently reading a boolean whose
   meaning flipped; ``schema_version`` 4 adds ``handlers``/``delivering`` for the same reason.
"""

from __future__ import annotations

import contextlib
import enum
import os
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from harness.config.shardcert._shape import BROADCAST
from harness.load.coord import (
    DRIVE_START,
    ENGINE_DRAINED,
    ENGINE_RUNG_REPORT,
    LADDER_SOAK,
    LADDER_STOP,
    RUNG_ABORTED,
    SHARDS_READY,
    CoordTimeout,
    FileDropCoord,
)
from harness.load.enginepoll import EMPTY_POOL_STATS, PoolStats
from harness.load.shardcert import (
    FIDELITY_ACKED_FLOOR,
    FIDELITY_GATE_VERSION,
    FIDELITY_SENT_FLOOR,
    INBOUND_BAND_CHECK_BASIS,
    PRODUCT_STORE_POOL_SIZE,
    RungFidelity,
    ShardCertDriveReport,
    ShardCertEngineReport,
    fidelity_note,
    inbound_band_count,
    run_shardcert_drive,
    run_shardcert_engine,
    rung_fidelity,
)

#: 45M messages/day as the sustained TOTAL message-event rate (inbound + outbound) the ladder pins
#: against. NOT an ingress rate: one ingress message DELIVERED to ``delivering`` (D) destinations produces
#: ``1 + D`` events, so the ingress that saturates this budget is ``TARGET_EVENTS_PER_S / (1 + D)``.
TARGET_EVENTS_PER_S = 45_000_000 / 86_400  # ≈ 520.833…

#: The Phase-5 **D4 derate**: a PUBLISHABLE claim is HALF the measured RAW ceiling (headroom for the gap
#: between a saturated synthetic bench and a real estate). A 45M/day CLAIM therefore needs a RAW ceiling of
#: ``TARGET_EVENTS_PER_S / PUBLISHABLE_DERATE`` ≈ 1041 events/s, i.e. ~521 raw ingress/s at fan-out 1.
#:
#: This was previously nowhere in the ladder, and it did not matter: under BROADCAST the shape CAPPED ingress
#: at ~16 msg/s, so :attr:`ConsolidatedLadderReport.clears_target_events` — which compares the RAW events/s
#: against the target — could never trip however wrong it was. Under PARTITIONED it CAN trip, at p >= 260
#: ingress/s, which is HALF the ingress a publishable claim actually requires. The raw gate is kept (it is a
#: real measurement) but it is now reported BESIDE the publishable one, so the derate cannot be dropped on
#: the way from the JSON to a claim.
PUBLISHABLE_DERATE = 0.5

#: A slope (in_pipeline rows per second over the soak hold) at or below this magnitude reads as
#: "flat or draining" — a sustainable plateau. Above it, the backlog is growing = slow saturation.
#: D4 coupling: the soak's in_pipeline trace/slope are now a SINGLE-store view (shardcert.py de-dups the
#: N×-summed unified-store poller). Pre-fix, this threshold was applied to an N×-inflated slope, so the
#: EFFECTIVE true-growth sensitivity was ~tol/N (≈0.25 rows/s at the N=4 rig). Dropping 1.0 → 0.25 preserves
#: that effective sensitivity, now N-INDEPENDENT (the slope is a true per-store rate for any shard count).
#: Left at 1.0 the gate would be ~N× too loose and a slow-saturating soak would pass spuriously (the
#: handoff's "12–23/s" warning); paired with the bounded soak drain (D2). Re-calibrate against a rig soak if
#: the true "flat" bar differs.
_SLOPE_FLAT_TOL = 0.25

#: The phase-timing INFO line the bench-gated ``MEFOR_DELIVERY_PHASE_TIMING`` lever emits per window (from
#: ``messagefoundry.pipeline.wiring_runner``). Same shape the rig's ``aggregate.py`` parsed.
_PHASE_RE = re.compile(
    r"send_ack n=(\d+) mean=([\d.]+)ms max=([\d.]+)ms "
    r"\| mark_done n=(\d+) mean=([\d.]+)ms max=([\d.]+)ms"
)

#: Each ``delivery phase timing`` INFO line covers a fixed 5-second window; ``wiring_runner`` emits one per
#: 5s for as long as deliveries flow — through the hold AND the post-hold drain — so the window COUNT
#: recovers the TRUE delivery SPAN (unlike ``hold_seconds``, which omits the drain tail). Used for the
#: span-correct MEASURED delivered rate (D3): span ≈ (Σ windows across shards / shard count) × 5s.
_PHASE_WINDOW_SECONDS = 5.0

#: The CLAIM phase-timing INFO line the SAME ``MEFOR_DELIVERY_PHASE_TIMING`` lever emits per window (from
#: ``messagefoundry.pipeline.phase_timing.ClaimPhaseTiming``) — the store-claim round-trip #842 could not
#: see. Deliberately DISJOINT from ``_PHASE_RE`` (no send_ack/mark_done fields; ``_claim_lines`` guards on
#: the distinct "claim phase timing" substring) so the two phase lines can never cross-match.
#: NOTE (2026-07-13): the engine emits ONE line PER STAGE per window —
#: ``claim phase timing (stage=%s): claim n=...`` (``pipeline/phase_timing.py``). The original regex did
#: NOT capture ``stage=``, so :func:`aggregate_claim_timing` n-weighted INGRESS + ROUTED + OUTBOUND +
#: RESPONSE into ONE ``claim_mean_ms``. **Every claim_mean this programme has quoted is a four-stage
#: BLEND, not the outbound claim.** The blended aggregate is retained (its Σn·mean busy-time is still
#: exact and existing reports depend on it) and the per-stage split is now carried alongside it in
#: ``ClaimTiming.by_stage``. ``stage`` is OPTIONAL in the pattern so a pre-stage log still parses.
_CLAIM_RE = re.compile(
    r"claim phase timing(?: \(stage=(?P<stage>\w+)\))?: "
    r"claim n=(?P<n>\d+) mean=(?P<mean>[\d.]+)ms max=(?P<max>[\d.]+)ms \| "
    r"lanes/claim=(?P<lanes>[\d.]+) rows/claim=(?P<rows>[\d.]+) "
    r"rearm=(?P<rearm>\d+) empty=(?P<empty>\d+) claimers=(?P<claimers>\d+)"
)

#: The LANE EPISODE timing line the SAME ``MEFOR_DELIVERY_PHASE_TIMING`` lever emits per window (from
#: ``messagefoundry.pipeline.phase_timing.LaneEpisodeTiming``) — ``S_lane``, the pooled dispatcher's per-lane
#: SERVICE TIME (STEP 4 ARM 1). Disjoint from ``_PHASE_RE`` and ``_CLAIM_RE`` (distinct "lane episode timing"
#: substring, distinct fields), so the three phase lines can never cross-match.
#:
#: ``stage`` is CAPTURED and :func:`aggregate_episode_timing` splits ``by_stage`` — the engine emits ONE line
#: per stage per window, and n-weighting all four into a single mean is a mistake this programme has ALREADY
#: made once (see the ``_CLAIM_RE`` note: every ``claim_mean`` quoted before 2026-07-13 is a four-stage
#: BLEND). ARM 1's arithmetic is the OUTBOUND stage only: read ``by_stage["outbound"]``.
_EPISODE_RE = re.compile(
    r"lane episode timing \(stage=(?P<stage>\w+)\): "
    r"episode n=(?P<n>\d+) mean=(?P<mean>[\d.]+)ms max=(?P<max>[\d.]+)ms \| "
    r"rows/episode=(?P<rows>[\d.]+) lambda_max_per_lane=(?P<lam>[\d.]+)/s \| "
    r"dropped n=(?P<dropn>\d+) sum=(?P<dropsum>[\d.]+)ms \| "
    r"lanes=(?P<lanes>\d+) slots=(?P<slots>\d+) window=(?P<window>[\d.]+)s "
    r"utilization=(?P<util>[\d.]+)"
)


# =====================================================================================================
# Phase-timing aggregation (extends the rig's aggregate.py: n-weighted mean, drop each stage's first
# ramp window). Reads the per-shard node logs the engine persisted with MEFOR_BENCH_KEEP_NODE_LOGS.
# =====================================================================================================


def _drop_ramp_window(matches: list[re.Match[str]]) -> list[re.Match[str]]:
    """Drop the first (RAMP) window of EACH STAGE within one node log, preserving file order.

    **Why per-stage and not per-file (the 2026-07-13 fix).** The engine emits one timing line PER STAGE
    per window (``stage=ingress|routed|outbound|response`` — ``pipeline/phase_timing.py``), so a log's
    lines are four INTERLEAVED window streams, not one. The aggregators used to do ``matches[1:]``, which
    drops ONE line from the WHOLE FILE: only whichever stage happened to log first lost its ramp window,
    and every other stage kept a ramp window it was supposed to lose. The intent has always been "drop
    each stage's first window" (the fleet is still filling, and a process's first episode window is a
    near-zero-span partial — see ``LaneEpisodeTiming._window_start``), so group by stage and drop each
    group's first.

    **NO PUBLISHED NUMBER MOVES — do not re-litigate 13.37 ms.** Recomputed over the banked raw rig lines
    (714 outbound windows, n=63,484 claims), STEP 2's published outbound claim reads **13.368 ms either
    way**: a **0.003%** change. The ramp windows carry n≈1 and the mean is n-weighted, so they were
    already invisible. The MECHANISM was wrong and is worth fixing; the numbers it produced were not.

    **Why fix it now, then.** The contamination scales with the ramp window's share of the run: a long
    rig hold is ~180 windows/stage, but a 120 s hold is only ~24 — the shape the next rig run uses, where
    an undropped ramp window has ~8x the weight it had in the runs above.

    **The grouping key is whatever ``stage`` group the caller's pattern captured.** A pattern with NO
    ``stage`` group (``_PHASE_RE``) and a pre-stage (legacy) log where ``stage`` is ``None`` (``_CLAIM_RE``,
    whose ``stage`` is optional) both collapse to ONE implicit group — i.e. exactly the previous per-file
    behaviour, bit for bit. Grouping is per CALL, and each aggregator calls this once per log, so the drop
    is per ``(file, stage)``: shard-b's ramp windows are dropped even for a stage shard-a already showed.
    **Do not hoist ``seen`` out of the caller's per-file loop** — that would silently keep every shard's
    ramp window but the first's.

    ``_PHASE_RE`` is the delivery ``send_ack``/``mark_done`` line and is deliberately NOT split. Its
    single-stage-ness is an **INVARIANT OF THE EMITTER, not something this parser enforces**:
    ``DeliveryPhaseTiming.maybe_emit(*, stage="outbound")`` takes ``stage`` as a DEFAULTED parameter, and
    the sole call site (``wiring_runner``) passes ``"outbound"`` — pinned by
    ``test_delivery_phase_line_has_exactly_one_emitter_and_it_is_outbound``. Should a second stage ever
    emit it, the per-stage drop is NOT a one-line change: ``_PHASE_RE`` would need a ``stage`` group AND
    ``aggregate_phase_timing`` would have to move off positional ``m.group(1)..m.group(6)`` to NAMED groups
    (a leading group shifts every index — the exact trap ``_CLAIM_RE`` already sprang), AND ``PhaseTiming``
    would need a ``by_stage`` split, or it would keep blending stages into one mean the way ``claim_mean``
    did."""
    seen: set[str | None] = set()
    kept: list[re.Match[str]] = []
    for m in matches:
        stage: str | None = m.groupdict().get("stage")
        if stage in seen:
            kept.append(m)
        else:
            seen.add(stage)  # this stage's FIRST window == its ramp window
    return kept


@dataclass(frozen=True)
class PhaseTiming:
    """The per-delivery ``send_ack`` (MLLP send→ACK) vs ``mark_done`` (store-completion round-trip) split,
    n-weighted across every shard × steady-state window of a rung (each stage's first ramp window dropped).
    Counts + latencies only — never a payload / control-id (PHI rule)."""

    windows: int
    deliveries: int  # Σ mark_done n over the aggregated windows (the n-weighted denominator)
    send_ack_mean_ms: float
    send_ack_max_ms: float
    mark_done_mean_ms: float
    mark_done_max_ms: float

    @property
    def empty(self) -> bool:
        return self.windows == 0

    def render(self) -> str:
        if self.empty:
            return "phase timing: (none captured — MEFOR_DELIVERY_PHASE_TIMING off or no delivered rows)"
        return (
            f"phase timing: deliveries={self.deliveries} windows={self.windows} | "
            f"send_ack mean/max={self.send_ack_mean_ms:.2f}/{self.send_ack_max_ms:.2f}ms | "
            f"mark_done mean/max={self.mark_done_mean_ms:.2f}/{self.mark_done_max_ms:.2f}ms"
        )

    def to_json_dict(self) -> dict[str, object]:
        return {
            "windows": self.windows,
            "deliveries": self.deliveries,
            "send_ack_mean_ms": round(self.send_ack_mean_ms, 3),
            "send_ack_max_ms": round(self.send_ack_max_ms, 3),
            "mark_done_mean_ms": round(self.mark_done_mean_ms, 3),
            "mark_done_max_ms": round(self.mark_done_max_ms, 3),
        }

    @classmethod
    def from_json_dict(cls, d: Mapping[str, Any]) -> PhaseTiming:
        return cls(
            windows=int(d.get("windows", 0)),
            deliveries=int(d.get("deliveries", 0)),
            send_ack_mean_ms=float(d.get("send_ack_mean_ms", 0.0)),
            send_ack_max_ms=float(d.get("send_ack_max_ms", 0.0)),
            mark_done_mean_ms=float(d.get("mark_done_mean_ms", 0.0)),
            mark_done_max_ms=float(d.get("mark_done_max_ms", 0.0)),
        )


def _phase_lines(text: str) -> list[re.Match[str]]:
    """Every ``delivery phase timing`` INFO line in ``text``, as regex matches (in file order)."""
    out: list[re.Match[str]] = []
    for line in text.splitlines():
        if "delivery phase timing" not in line:
            continue
        m = _PHASE_RE.search(line)
        if m is not None:
            out.append(m)
    return out


def aggregate_phase_timing(
    log_paths: Sequence[Path], *, drop_first_window: bool = True
) -> PhaseTiming:
    """Aggregate the ``send_ack``/``mark_done`` phase-timing windows across the per-shard node logs of ONE
    rung into a single n-weighted :class:`PhaseTiming`. Each STAGE's FIRST window in each log is dropped
    (the ramp window — the fleet is still filling), per :func:`_drop_ramp_window`; the n-weighted mean is
    ``Σ(mean×n) / Σn`` and the max is the max over windows. A missing/empty/unreadable log contributes
    nothing (never raises — a bench report must not crash on a truncated log).

    The delivery line has no ``stage`` group (one emitter, always ``stage=outbound``), so the per-stage
    drop collapses to the per-file drop this has always done — its behaviour is unchanged."""
    sa_num = 0.0
    sa_n = 0
    sa_max = 0.0
    md_num = 0.0
    md_n = 0
    md_max = 0.0
    windows = 0
    for path in log_paths:
        try:
            text = Path(path).read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        matches = _phase_lines(text)
        if drop_first_window:
            matches = _drop_ramp_window(matches)  # per STAGE, not per file
        for m in matches:
            san, sam, samx = int(m.group(1)), float(m.group(2)), float(m.group(3))
            mdn, mdm, mdmx = int(m.group(4)), float(m.group(5)), float(m.group(6))
            sa_num += sam * san
            sa_n += san
            sa_max = max(sa_max, samx)
            md_num += mdm * mdn
            md_n += mdn
            md_max = max(md_max, mdmx)
            windows += 1
    return PhaseTiming(
        windows=windows,
        deliveries=md_n,
        send_ack_mean_ms=(sa_num / sa_n) if sa_n else 0.0,
        send_ack_max_ms=sa_max,
        mark_done_mean_ms=(md_num / md_n) if md_n else 0.0,
        mark_done_max_ms=md_max,
    )


@dataclass(frozen=True)
class ClaimTiming:
    """The per-claim store round-trip (the phase #842 could not see), n-weighted across every shard ×
    steady-state window of a rung (each stage's first ramp window dropped). Counts + latencies + ratios
    only — never a payload / control-id / lane name (PHI rule)."""

    windows: int
    claims: int  # Σ claim n over the aggregated windows (the n-weighted denominator)
    claim_mean_ms: float
    claim_max_ms: float
    lanes_per_claim: float  # n-weighted mean lanes offered per claim
    rows_per_claim: float  # n-weighted mean rows returned per claim
    rearm: int  # Σ H2 skip-and-complete lanes (real work, not overhead)
    empty: int  # Σ pure-overhead claims (returned nothing AND rearmed nothing)
    #: PER-STAGE split (2026-07-13). The fields ABOVE are a FOUR-STAGE BLEND (ingress + routed +
    #: outbound + response) — the engine emits one timing line per stage and the parser used to discard
    #: `stage=`. The blend is retained (its Σn·mean busy-time is exact, and prior reports quote it) but it
    #: is NOT the outbound claim and must never be read as one. Read `by_stage["outbound"]` for that.
    #: Empty on a pre-stage log.
    by_stage: dict[str, ClaimTiming] = field(default_factory=dict)

    @property
    def is_empty(self) -> bool:
        return self.windows == 0

    def render(self) -> str:
        if self.is_empty:
            return "claim timing: (none captured — MEFOR_DELIVERY_PHASE_TIMING off or no claims)"
        return (
            f"claim timing: claims={self.claims} windows={self.windows} | "
            f"claim mean/max={self.claim_mean_ms:.2f}/{self.claim_max_ms:.2f}ms | "
            f"lanes/claim={self.lanes_per_claim:.2f} rows/claim={self.rows_per_claim:.2f} "
            f"rearm={self.rearm} empty={self.empty}"
        )

    def to_json_dict(self) -> dict[str, object]:
        return {
            "windows": self.windows,
            "claims": self.claims,
            "claim_mean_ms": round(self.claim_mean_ms, 3),
            "claim_max_ms": round(self.claim_max_ms, 3),
            "lanes_per_claim": round(self.lanes_per_claim, 3),
            "rows_per_claim": round(self.rows_per_claim, 3),
            "rearm": self.rearm,
            "empty": self.empty,
            # PER-STAGE (2026-07-13). The flat fields above are a four-stage BLEND — read
            # by_stage["outbound"] for the outbound claim. Omitted when empty (a pre-stage log), so an
            # older consumer sees a byte-identical dict.
            **(
                {"by_stage": {st: ct.to_json_dict() for st, ct in self.by_stage.items()}}
                if self.by_stage
                else {}
            ),
        }

    @classmethod
    def from_json_dict(cls, d: Mapping[str, Any]) -> ClaimTiming:
        return cls(
            windows=int(d.get("windows", 0)),
            claims=int(d.get("claims", 0)),
            claim_mean_ms=float(d.get("claim_mean_ms", 0.0)),
            claim_max_ms=float(d.get("claim_max_ms", 0.0)),
            lanes_per_claim=float(d.get("lanes_per_claim", 0.0)),
            rows_per_claim=float(d.get("rows_per_claim", 0.0)),
            rearm=int(d.get("rearm", 0)),
            empty=int(d.get("empty", 0)),
            by_stage={
                st: ClaimTiming.from_json_dict(v)
                for st, v in (d.get("by_stage") or {}).items()
                if isinstance(v, Mapping)
            },
        )


#: An empty :class:`ClaimTiming` — the default when a rung's ENGINE_RUNG_REPORT carried no claim aggregate
#: (report absent, or the MEFOR_DELIVERY_PHASE_TIMING lever off), mirroring the empty ``PhaseTiming`` default.
_EMPTY_CLAIM_TIMING = ClaimTiming(0, 0, 0.0, 0.0, 0.0, 0.0, 0, 0)


def _claim_lines(text: str) -> list[re.Match[str]]:
    """Every ``claim phase timing`` INFO line in ``text``, as regex matches (in file order). Guarded on the
    distinct "claim phase timing" substring so the delivery (send_ack/mark_done) line can never match here."""
    out: list[re.Match[str]] = []
    for line in text.splitlines():
        if "claim phase timing" not in line:
            continue
        m = _CLAIM_RE.search(line)
        if m is not None:
            out.append(m)
    return out


def aggregate_claim_timing(
    log_paths: Sequence[Path], *, drop_first_window: bool = True
) -> ClaimTiming:
    """Aggregate the CLAIM phase-timing windows across the per-shard node logs of ONE rung into a single
    n-weighted :class:`ClaimTiming` — the store-claim round-trip #842 could not see, now carried into the
    consolidated report (D6). Each STAGE's FIRST claim window in each log is dropped (the ramp window) — see
    :func:`_drop_ramp_window`, and note that a pre-stage log (``stage`` absent) keeps its old single-drop
    behaviour exactly. The n-weighted mean is ``Σ(mean×n) / Σn`` (n = claim count), the max is the max over
    windows, lanes/rows-per-claim are n-weighted, and rearm/empty are summed. A missing/empty/unreadable log
    contributes nothing (never raises — a bench report must not crash on a truncated log)."""
    claim_num = 0.0
    claim_n = 0
    claim_max = 0.0
    lanes_num = 0.0
    rows_num = 0.0
    rearm = 0
    empty = 0
    windows = 0
    per_stage: dict[str, dict[str, float]] = {}
    for path in log_paths:
        try:
            text = Path(path).read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        matches = _claim_lines(text)
        if drop_first_window:
            matches = _drop_ramp_window(matches)  # per STAGE, not per file
        for m in matches:
            # NAMED groups: the pattern gained an optional leading `stage` group (2026-07-13), so the
            # positional indices this used to read are no longer stable.
            cn, cm, cmx = int(m["n"]), float(m["mean"]), float(m["max"])
            lpc, rpc = float(m["lanes"]), float(m["rows"])
            rearm += int(m["rearm"])
            empty += int(m["empty"])
            claim_num += cm * cn
            claim_n += cn
            claim_max = max(claim_max, cmx)
            lanes_num += lpc * cn
            rows_num += rpc * cn
            windows += 1
            # Per-stage split — the whole point of the fix. `stage` is None on a pre-stage log.
            st = m["stage"]
            if st:
                acc = per_stage.setdefault(
                    st,
                    {
                        "num": 0.0,
                        "n": 0,
                        "max": 0.0,
                        "lanes": 0.0,
                        "rows": 0.0,
                        "rearm": 0,
                        "empty": 0,
                        "windows": 0,
                    },
                )
                acc["num"] += cm * cn
                acc["n"] += cn
                acc["max"] = max(acc["max"], cmx)
                acc["lanes"] += lpc * cn
                acc["rows"] += rpc * cn
                acc["rearm"] += int(m["rearm"])
                acc["empty"] += int(m["empty"])
                acc["windows"] += 1
    by_stage = {
        st: ClaimTiming(
            windows=int(a["windows"]),
            claims=int(a["n"]),
            claim_mean_ms=(a["num"] / a["n"]) if a["n"] else 0.0,
            claim_max_ms=a["max"],
            lanes_per_claim=(a["lanes"] / a["n"]) if a["n"] else 0.0,
            rows_per_claim=(a["rows"] / a["n"]) if a["n"] else 0.0,
            rearm=int(a["rearm"]),
            empty=int(a["empty"]),
        )
        for st, a in sorted(per_stage.items())
    }
    return ClaimTiming(
        windows=windows,
        claims=claim_n,
        claim_mean_ms=(claim_num / claim_n) if claim_n else 0.0,
        claim_max_ms=claim_max,
        lanes_per_claim=(lanes_num / claim_n) if claim_n else 0.0,
        rows_per_claim=(rows_num / claim_n) if claim_n else 0.0,
        rearm=rearm,
        empty=empty,
        by_stage=by_stage,
    )


@dataclass(frozen=True)
class EpisodeTiming:
    """``S_lane`` — the pooled dispatcher's per-lane SERVICE TIME (reserve→release for a COMPLETED drain),
    n-weighted across every shard × steady-state window of a rung (each stage's first ramp window dropped),
    plus the lane's non-service OCCUPANCY. STEP 4 ARM 1's headline number.

    **Read ``by_stage["outbound"]``, never the blend.** The engine emits one line PER STAGE; the flat fields
    here are the four-stage n-weighted blend, kept only because it is a well-defined busy-time total. Reading
    it as "the outbound S_lane" is exactly the error already committed once on ``claim_mean`` (see
    ``_CLAIM_RE``), and on the prefix stages an episode drains a BATCH, so the blend mixes different units of
    work.

    **How to read it (no Little's law anywhere).** A lane is a single-server queue, so its ceiling is the
    RECIPROCAL of its service time — measured directly::

        lambda_max_per_lane ~= rows / S_lane_total          # MESSAGES/s (rows-based, batch-correct)
        aggregate_ceiling   ~= min(lanes, slots) / S_lane   # slots = max_processing_lanes, the pool cap

    ``utilization`` is the falsifier for the "lanes do NOT bind" branch: ``lambda_max`` is the ceiling of a
    lane that is back-to-back busy with COMPLETED services, so a lane burning real slot time on EMPTY claims
    has a lower true ceiling than ``1/S_lane`` suggests. A utilization near 1.0 means the lanes BIND whatever
    ``S_lane`` reads. Cross-check ``dropped_ms`` here and ``empty=`` on the claim line of the same window.

    Counts + latencies + ratios only — never a payload / control-id / lane name (PHI rule)."""

    windows: int
    episodes: int  # Σ episode n over the aggregated windows (the n-weighted denominator)
    episode_mean_ms: float
    episode_max_ms: float
    rows_per_episode: float  # n-weighted; MUST read ~1.00 on stage=outbound (hard-1 per_lane_limit)
    lambda_max_per_lane: (
        float  # rows / Σ(mean×n) — messages/s, correct on the batching prefix stages too
    )
    dropped: int  # Σ non-service releases (empty / rearm / claim error / pause / RETRY / STOP)
    dropped_ms: float  # Σ their occupancy — lane time that served nothing
    lanes: float  # n-weighted mean SERVABLE lane count (excludes PAUSED/STOPPED)
    slots: (
        float  # n-weighted mean max_processing_lanes (the concurrency cap; min(lanes, slots) binds)
    )
    utilization: float  # n-weighted mean (episode + dropped occupancy) / (window × lanes)
    #: PER-STAGE split — the ONLY correct read for ARM 1. Empty on a log with no episode lines.
    by_stage: dict[str, EpisodeTiming] = field(default_factory=dict)

    @property
    def is_empty(self) -> bool:
        return self.windows == 0

    @property
    def aggregate_ceiling_per_s(self) -> float:
        """``min(lanes, slots) / S_lane`` — the fan-out-to-all aggregate bound this stage's lanes impose.
        NOT ``lanes / S_lane``: concurrent episodes are capped by the dispatcher's slot pool, so at a lane
        count above ``max_processing_lanes`` the naive form over-states the ceiling."""
        if self.episode_mean_ms <= 0.0:
            return 0.0
        servers = min(self.lanes, self.slots)
        return servers * self.rows_per_episode * 1000.0 / self.episode_mean_ms

    def render(self) -> str:
        if self.is_empty:
            return "lane episode (S_lane): (none captured — MEFOR_DELIVERY_PHASE_TIMING off or no episodes)"
        return (
            f"lane episode (S_lane): episodes={self.episodes} windows={self.windows} | "
            f"S_lane mean/max={self.episode_mean_ms:.2f}/{self.episode_max_ms:.2f}ms | "
            f"rows/episode={self.rows_per_episode:.2f} lambda_max/lane={self.lambda_max_per_lane:.2f}/s | "
            f"dropped={self.dropped} ({self.dropped_ms:.1f}ms) | "
            f"lanes={self.lanes:.1f} slots={self.slots:.0f} utilization={self.utilization:.3f} | "
            f"aggregate_ceiling~{self.aggregate_ceiling_per_s:.1f}/s"
        )

    def to_json_dict(self) -> dict[str, object]:
        return {
            "windows": self.windows,
            "episodes": self.episodes,
            "episode_mean_ms": round(self.episode_mean_ms, 3),
            "episode_max_ms": round(self.episode_max_ms, 3),
            "rows_per_episode": round(self.rows_per_episode, 3),
            "lambda_max_per_lane": round(self.lambda_max_per_lane, 3),
            "dropped": self.dropped,
            "dropped_ms": round(self.dropped_ms, 3),
            "lanes": round(self.lanes, 3),
            "slots": round(self.slots, 3),
            "utilization": round(self.utilization, 4),
            "aggregate_ceiling_per_s": round(self.aggregate_ceiling_per_s, 3),
            **(
                {"by_stage": {st: et.to_json_dict() for st, et in self.by_stage.items()}}
                if self.by_stage
                else {}
            ),
        }

    @classmethod
    def from_json_dict(cls, d: Mapping[str, Any]) -> EpisodeTiming:
        return cls(
            windows=int(d.get("windows", 0)),
            episodes=int(d.get("episodes", 0)),
            episode_mean_ms=float(d.get("episode_mean_ms", 0.0)),
            episode_max_ms=float(d.get("episode_max_ms", 0.0)),
            rows_per_episode=float(d.get("rows_per_episode", 0.0)),
            lambda_max_per_lane=float(d.get("lambda_max_per_lane", 0.0)),
            dropped=int(d.get("dropped", 0)),
            dropped_ms=float(d.get("dropped_ms", 0.0)),
            lanes=float(d.get("lanes", 0.0)),
            slots=float(d.get("slots", 0.0)),
            utilization=float(d.get("utilization", 0.0)),
            by_stage={
                st: EpisodeTiming.from_json_dict(v)
                for st, v in (d.get("by_stage") or {}).items()
                if isinstance(v, Mapping)
            },
        )


#: An empty :class:`EpisodeTiming` — the default when a rung's ENGINE_RUNG_REPORT carried no episode
#: aggregate (report absent, or the MEFOR_DELIVERY_PHASE_TIMING lever off).
_EMPTY_EPISODE_TIMING = EpisodeTiming(0, 0, 0.0, 0.0, 0.0, 0.0, 0, 0.0, 0.0, 0.0, 0.0)


def _episode_lines(text: str) -> list[re.Match[str]]:
    """Every ``lane episode timing`` INFO line in ``text``, as regex matches (in file order). Guarded on the
    distinct substring so neither the delivery nor the claim phase line can match here."""
    out: list[re.Match[str]] = []
    for line in text.splitlines():
        if "lane episode timing" not in line:
            continue
        m = _EPISODE_RE.search(line)
        if m is not None:
            out.append(m)
    return out


class _EpisodeAcc:
    """Mutable n-weighted accumulator for one stage's (or the blend's) episode windows."""

    __slots__ = (
        "windows",
        "n",
        "num",
        "max",
        "rows_num",
        "dropped",
        "dropped_ms",
        "lanes_num",
        "slots_num",
        "util_num",
    )

    def __init__(self) -> None:
        self.windows = 0
        self.n = 0  # Σ episode count (the n-weighted denominator)
        self.num = 0.0  # Σ mean × n  == total booked service time (ms)
        self.max = 0.0
        self.rows_num = 0.0  # Σ rows/episode × n == Σ rows
        self.dropped = 0
        self.dropped_ms = 0.0
        self.lanes_num = 0.0
        self.slots_num = 0.0
        self.util_num = 0.0

    def add(self, m: re.Match[str]) -> None:
        n = int(m["n"])
        mean = float(m["mean"])
        self.windows += 1
        self.n += n
        self.num += mean * n
        self.max = max(self.max, float(m["max"]))
        self.rows_num += float(m["rows"]) * n
        self.dropped += int(m["dropn"])
        self.dropped_ms += float(m["dropsum"])
        # lanes / slots / utilization are per-WINDOW properties, but weighting them by n keeps a busy
        # window from being averaged away by an almost-idle one (the same n-weighting the claim/phase
        # aggregates use). A window with n==0 contributes nothing to any of them — it also cannot be
        # emitted (LaneEpisodeTiming rolls a fully-empty window forward silently).
        self.lanes_num += float(m["lanes"]) * n
        self.slots_num += float(m["slots"]) * n
        self.util_num += float(m["util"]) * n

    def build(self, by_stage: dict[str, EpisodeTiming] | None = None) -> EpisodeTiming:
        n = self.n
        mean = (self.num / n) if n else 0.0
        rows = (self.rows_num / n) if n else 0.0
        # λ from ROWS per booked SECOND — not 1/mean. On INGRESS/ROUTED an episode drains a prefix of many
        # rows, so 1/mean would under-state the per-lane MESSAGE rate by the batch factor while looking
        # identical in shape to the (hard-1) outbound line.
        busy_s = self.num / 1000.0  # Σ(mean_ms × n) → seconds of booked service
        lam = (self.rows_num / busy_s) if busy_s > 0.0 else 0.0
        return EpisodeTiming(
            windows=self.windows,
            episodes=n,
            episode_mean_ms=mean,
            episode_max_ms=self.max,
            rows_per_episode=rows,
            lambda_max_per_lane=lam,
            dropped=self.dropped,
            dropped_ms=self.dropped_ms,
            lanes=(self.lanes_num / n) if n else 0.0,
            slots=(self.slots_num / n) if n else 0.0,
            utilization=(self.util_num / n) if n else 0.0,
            by_stage=by_stage or {},
        )


def aggregate_episode_timing(
    log_paths: Sequence[Path], *, drop_first_window: bool = True
) -> EpisodeTiming:
    """Aggregate the LANE EPISODE windows across the per-shard node logs of ONE rung into an n-weighted
    :class:`EpisodeTiming` — ``S_lane``, STEP 4 ARM 1's headline number, carried into the consolidated report
    instead of being hand-grepped out of per-shard node logs (the manual step whose missing n-weighting +
    ramp-window drop is the already-committed ``claim_mean`` error).

    Applies the SAME two corrections :func:`aggregate_claim_timing` does — each STAGE's FIRST episode window
    in each log is dropped (the ramp window, while the fleet is still filling; :func:`_drop_ramp_window`) and
    the mean is ``Σ(mean×n) / Σn`` — and splits ``by_stage``, because the outbound stage is the only one
    ARM 1's arithmetic is about. A
    missing/empty/unreadable log contributes nothing (never raises — a bench report must not crash on a
    truncated log)."""
    blend = _EpisodeAcc()
    per_stage: dict[str, _EpisodeAcc] = {}
    for path in log_paths:
        try:
            text = Path(path).read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        matches = _episode_lines(text)
        if drop_first_window:
            matches = _drop_ramp_window(matches)  # per STAGE, not per file
        for m in matches:
            blend.add(m)
            per_stage.setdefault(m["stage"], _EpisodeAcc()).add(m)
    return blend.build({st: acc.build() for st, acc in sorted(per_stage.items())})


def _rung_log_paths(keep_dir: Path, shards: Sequence[str]) -> list[Path]:
    """The persisted per-shard node-log paths for a rung — ``<keep_dir>/shard-<s>.log`` (the
    ``EngineNode`` names each log ``<node_id>.log`` and ``ShardCertNode.node_id == "shard-<s>"``)."""
    return [keep_dir / f"shard-{s}.log" for s in shards]


# =====================================================================================================
# in_pipeline soak slope (from the engine half's in-hold trace)
# =====================================================================================================


def in_pipeline_slope(trace: Sequence[Sequence[float]]) -> float | None:
    """Least-squares slope (rows/second) of an ``[[elapsed_s, in_pipeline], ...]`` trace, or ``None`` with
    fewer than two points. A slope near zero (or negative) = the backlog is flat/draining (sustainable); a
    materially positive slope = the fleet is slowly saturating (a plateau that only LOOKS lossless early)."""
    pts = [(float(t), float(v)) for t, v in trace if t is not None and v is not None]
    if len(pts) < 2:
        return None
    n = len(pts)
    sx = sum(t for t, _ in pts)
    sy = sum(v for _, v in pts)
    sxx = sum(t * t for t, _ in pts)
    sxy = sum(t * v for t, v in pts)
    denom = n * sxx - sx * sx
    if abs(denom) < 1e-9:  # all samples at (effectively) the same instant → slope undefined
        return None
    return (n * sxy - sx * sy) / denom


def slope_is_draining(slope: float | None, *, tol: float = _SLOPE_FLAT_TOL) -> bool:
    """Whether an in_pipeline slope reads as flat-or-draining (sustainable). ``None`` (too few points) is
    treated as NOT-proven-draining — a soak with no trace cannot certify the plateau."""
    return slope is not None and slope <= tol


# =====================================================================================================
# Rung plan + per-rung classification (pure — the unit-tested core)
# =====================================================================================================


@dataclass(frozen=True)
class LadderRung:
    """One rung of the ladder. ``ingress_rate`` is the whole-fleet offered INGRESS msg/s (the
    ``aggregate_rate`` the drive splits across its K sender-workers); the OUTBOUND delivery rate is
    ``ingress_rate * delivering`` — the FAN-OUT, not the destination-connection count."""

    index: int
    ingress_rate: float
    hold_seconds: float
    drain_timeout: float
    is_soak: bool = False

    @property
    def run_suffix(self) -> str:
        return "soak" if self.is_soak else f"r{self.index}"

    def outbound_rate(self, delivering: int) -> float:
        """Deliveries/s at this rung. Keyed on ``delivering`` (D), NEVER ``dests`` (BACKLOG #209): a
        destination CONNECTION that no handler sends to carries no deliveries."""
        return self.ingress_rate * delivering


def plan_climb_rungs(
    rates: Sequence[float], *, hold_seconds: float, drain_timeout: float
) -> list[LadderRung]:
    """Build the ascending, de-duplicated climb rungs from ``rates`` (INGRESS msg/s). Ascending so the
    highest-sustained-so-far is always the current pinned candidate; de-duplicated so a repeated rate is
    driven once. **Fail loud** on an empty plan."""
    ordered = sorted(dict.fromkeys(float(r) for r in rates))
    if not ordered:
        raise ValueError("plan_climb_rungs needs at least one rate")
    return [
        LadderRung(index=i, ingress_rate=r, hold_seconds=hold_seconds, drain_timeout=drain_timeout)
        for i, r in enumerate(ordered)
    ]


class RungVerdict(enum.Enum):
    """The per-rung ceiling classification — the drain-window's collapse-vs-tail decision.

    * :attr:`SUSTAINED` — the engine drained clean (store-truth) AND the drive was lossless (sink-truth).
      The rung held; the highest such rung is the pinned ceiling candidate.
    * :attr:`COLLAPSED` — the engine store-truth was CONFIRMED and it did NOT drain clean (stranded/dead
      rows remained, or in_pipeline never drained within the window). The fleet genuinely could not sustain
      the offered load — a REAL ceiling that brackets the pinned rate from above.
    * :attr:`FROZEN_TAIL` — the engine DID drain clean (store-truth: nothing stranded/lost) but the sink
      tally came up short with NO ordering/dup break. The shortfall is a teardown-frozen / latency tail, NOT
      collapse — inconclusive (re-run with a longer drain), and NOT counted as the ceiling. With the drain
      gate ON this is rare; it is the diagnostic for a degraded/absent gate.
    * :attr:`INCONCLUSIVE` — the rung's outcome could NOT be trusted, so it must NOT be scored as a real
      SUSTAINED/COLLAPSED (that would fabricate a plausible ceiling — the B-class defect). Two disjoint
      causes, both "nothing certified":
        1. **Store-truth unconfirmed** — neither the ENGINE_DRAINED drain gate nor the ENGINE_RUNG_REPORT
           arrived, so there is no reliable store-truth at all (a coordination glitch).
        2. **Cross-observer inconsistency** (A4b) — the two INDEPENDENT observers of the rung (the ENGINE
           store-truth tally and the DRIVE sink socket count) are mutually contradictory beyond tolerance,
           OR a required collector read zero on a non-zero-volume run (see :func:`observers_inconclusive`).
           Trusting either observer to break the tie is exactly the silent-fabrication the ladder refuses.
      Either way it halts the climb (the rung cannot certify the next one) and is EXCLUDED from the collapse
      bracket, leaving the pinned rate an honest FLOOR — never a false bracketed ceiling below the true one.
    * :attr:`CORRECTNESS_FAIL` — a per-lane FIFO inversion or a duplicate delivery. A hard correctness break
      that FAILs the whole ladder verdict, independent of throughput.
    """

    SUSTAINED = "sustained"
    COLLAPSED = "collapsed"
    FROZEN_TAIL = "frozen_tail"
    INCONCLUSIVE = "inconclusive"
    CORRECTNESS_FAIL = "correctness_fail"


#: Cross-observer agreement tolerance (A4b), as a fraction of the expected deliveries ``A×delivering``. The
#: two INDEPENDENT observers of a rung — the ENGINE store-truth tally and the DRIVE sink socket count — may
#: differ by up to ``tol × A×delivering`` deliveries (a benign teardown/latency tail, lane-boundary rounding)
#: before the harness treats the difference as a genuine CONTRADICTION rather than measurement noise. Kept
#: small so the guard fires only on a MATERIAL inter-observer inconsistency, never on a few-delivery tail.
_OBSERVER_DISAGREE_TOL = 0.01


def observers_inconclusive(
    *,
    engine_ok: bool,
    acked: int,
    sink_received: int,
    delivering: int,
    engine_stranded: int,
    engine_dead_total: int,
    handlers: int = 0,
    ingress_stranded: int = -1,
    routed_stranded: int = -1,
    outbound_stranded: int = -1,
    tol: float = _OBSERVER_DISAGREE_TOL,
) -> bool:
    """Whether the two INDEPENDENT observers of a rung — the ENGINE store-truth tally and the DRIVE sink
    socket count — are mutually INCONSISTENT, so neither's sustained-vs-collapsed read can be trusted and the
    rung must downgrade to INCONCLUSIVE instead of fabricating a plausible SUSTAINED/COLLAPSED (A4b, the
    harness sibling of the merged ``test_harness_invariants`` guard; BACKLOG #219).

    Returns False (**guard inert**) when the raw observer counts were not supplied (``acked < 0`` or
    ``sink_received < 0``): the boolean ``no_loss`` alone cannot convey the MAGNITUDE a tolerance needs, so
    the pure truth-table callers (no counts) keep their verdict; the integration path
    (:func:`build_rung_outcome`) always passes the real tallies.

    **BACKLOG #209 — this guard keys on ``delivering`` (D), the FAN-OUT, never ``dests``.** It is the
    silent one: at ``D < dests`` an over-expected ``A×dests`` inflates BOTH ``expected`` and ``permit``, so
    trigger (a) — ``sink_received > permit + slack`` — can never fire. The A4b cross-observer guard would be
    DISARMED with no error, no note, and no failing test (every pre-#209 run had ``D == dests``, so the two
    coincided). A disarmed guard does not fail loudly; it just quietly stops catching fabrications.

    **BACKLOG #209 — the permit also accounts for the non-delivering-handler strand budget at ``H > D``.**
    ``expected`` is a DELIVERY count (``A×D``) but ``engine_stranded`` / ``engine_dead_total`` are ROW counts
    across ALL pipeline stages (ingress + routed + outbound). At the ADT-hub shape the router SELECTS ``H``
    handlers but only ``D`` DELIVER — the other ``H − D`` per message self-filter (their transform returns
    ``None``). A stranded/dead routed row of one of those NON-delivering handlers blocks ZERO deliveries: it
    was never going to produce one. So the old "each unclear row blocks at least one delivery" premise is
    FALSE at ``H > D`` — it holds only at ``H == D`` (the pre-#209 graph). Subtracting every such row from a
    DELIVERY permit under-counts the permit; at a genuine ``H > D`` collapse the routed strand count scales
    with ``H`` (``~A×H``) while deliveries scale with ``D`` (``~A×D``), so the permit goes strongly NEGATIVE
    and ``S > permit + slack`` fires on ANY nonzero sink — a real COLLAPSE mislabeled INCONCLUSIVE, a
    fabricated verdict in the very guard whose job is to prevent fabricated verdicts.

    The fix has TWO parts, and the ORDER between them is load-bearing::

        unclear = max(0, engine_stranded) + max(0, engine_dead_total)
        # (a′) a FULLY-lossless sink can NOT coexist with any unclear row — fire BEFORE `free`:
        if sink_received ≥ expected and unclear > 0:  return True
        # (a) below the lossless line the sink UNDER-counts; only THEN credit the H>D budget:
        free    = acked × max(0, handlers − delivering)   # non-delivering-handler routed rows
        if H > D and the per-stage strand split is present (BACKLOG #229):
            blocked = ingress_stranded × D + max(0, routed_stranded − free) + outbound_stranded
        else:  # H==D, or per-stage counts absent (sentinel) → stage-blind, pre-#229 identical
            blocked = max(0, unclear − free)
        permit  = expected − blocked

    **Why the lossless-sink clause precedes ``free`` (the fix for the stage-blind over-forgiveness).** ``free``
    was originally applied to the WHOLE opaque ``unclear`` tally, stage-blind. But ``engine_stranded`` is
    ``status NOT IN ('done','dead')`` across ALL stages, and a self-filtering handler's routed row is finalized
    TERMINAL (``FILTERED``/``UNROUTED``; its routed row is DELETEd in the same transform-handoff transaction —
    see :meth:`store.handoff` / :meth:`transform_handoff`). A row that self-filters therefore NEVER enters the
    ``stranded`` tally, so ``free`` had no legitimate population to absorb: every ``unclear`` row is a genuinely
    stuck/dead **delivery-bearing** row. A FULLY-lossless sink (``S ≥ A×D``) asserts every accepted message
    delivered all D copies — impossible if ANY such row is still non-terminal or dead. Charging that
    contradiction to ``free`` would forgive an INGRESS strand (blocks D copies) or a delivering-path strand
    (blocks ≥1) as if it blocked ZERO — a stage-blind over-forgiveness that let a fully-lossless sink coincident
    with strands fabricate a bracketed COLLAPSED (the exact B-class defect this guard exists to prevent). So the
    lossless-sink clause fires first, unconditionally on ``unclear > 0``, and ``free`` is consulted ONLY on the
    UNDER-counting branch, where the sink honestly reports loss and the two observers can genuinely AGREE.

    ``free`` (on the under-counting branch) absorbs stranded AND dead jointly because a DEAD-lettered row and a
    stranded row are treated identically by the permit; it lets a GENUINE H>D collapse — routed strands scaling
    with H, deliveries with D, and the sink honestly SHORT — read as the honest COLLAPSED the observers agree
    on rather than a fabricated INCONCLUSIVE.

    **BACKLOG #229 — the under-counting branch now charges each strand its true per-stage weight.** ``stranded``
    is an opaque all-stage total, so a stage-blind ``max(0, unclear − free)`` credited an INGRESS strand (blocks
    all D copies — the message never routed) or an OUTBOUND strand (blocks ≥1) to the ``free`` window as if it
    blocked 0, MISSING a partial over-count (sink > the store's *real* capacity, yet < A×D) at H>D. With the
    per-stage split (``ingress_stranded`` / ``routed_stranded`` / ``outbound_stranded``, threaded from
    ``_queue_breakdown`` in ``shardcert.py`` via ``ShardCertEngineReport`` + BOTH engine coord payloads) the
    permit charges ``blocked = ingress_stranded×D + max(0, routed_stranded − free) + outbound_stranded``. The
    ``free`` budget is credited AGAINST the ROUTED strands ONLY — the non-delivering handlers' routed rows —
    which is the load-bearing bit: a genuine H>D collapse strands ~A×H routed rows, ~A×(H−D) of them
    non-delivering, so crediting ``free`` there keeps the collapse an honest COLLAPSED instead of re-fabricating
    the INCONCLUSIVE this guard exists to prevent. The sound branch is GATED to ``H > D`` **and** all three
    per-stage counts present (``≥ 0``); at H==D (``free==0``) or an absent split (an older payload / aborted
    rung → the ``< 0`` sentinel) it falls back to the stage-blind ``max(0, unclear − free)``, byte-identical to
    the pre-#229 formula.

    **``H == D`` identity (matches the pre-fix formula wherever the two observers can disagree, so no published
    run regresses).** At ``H == D`` (and for any caller that does not pass ``handlers`` — it defaults to ``0``
    with ``max(0, 0 − D) == 0``), ``free == 0``, so the UNDER-counting branch is ``permit == expected −
    max(0, stranded) − max(0, dead)`` — EXACTLY the old expression. (Reaching that branch already guarantees
    ``stranded ≥ 0`` and ``dead ≥ 0``: the ``< 0`` sentinel path below returns first when ``not engine_ok``,
    and when ``engine_ok`` the store-truth pass bar forces both to ``0``, so ``max(0, s) + max(0, d)`` equals
    ``max(0, s + d)`` and the terms fold identically.) The lossless-sink clause (a′) is the ONE point where the
    fixed guard is STRICTER than the raw pre-fix arithmetic even at ``H == D``: the old formula absorbed up to
    ``slack`` genuinely-stuck rows as delivery noise, so a lossless sink with ``0 < unclear ≤ slack`` slipped
    through; (a′) now fires on it, because a stranded row is an EXACT store count, not a noisy delivery tail,
    and cannot be reconciled with a lossless sink. Every published ``H == D`` run had ``stranded == 0`` on a
    lossless rung (a run that stranded rows was not lossless), so this stricter edge changes no real verdict —
    it only removes a corner where the noise slack wrongly forgave a real contradiction.

    Two triggers, each a hard inter-observer contradiction rather than a mere shortfall:

    (a) **The sink counted MORE deliveries than the engine's own store-truth permits.** Split in two by the
        lossless line. When the sink is FULLY lossless (``S ≥ A×D``) and the engine reports ANY unclear row,
        the two are irreconcilable outright — a lossless sink means every copy landed, which leaves no stuck or
        dead row — so it fires without consulting ``free`` (clause a′ above). When the sink UNDER-counts, the
        engine's ``unclear`` rows are reconciled against a permit ``A×D − max(0, unclear − free)`` that credits
        up to ``free`` of them to the self-filtering handlers; a sink beyond that permit + a ``tol × A×D`` slack
        over-counts against the reliable store-truth. Either way the tie was silently broken in the engine's
        favour and stamped COLLAPSED, fabricating a bracketed ceiling from a contradiction. This CANNOT
        false-positive on a genuine collapse, where the sink UNDER-counts and ``S ≤ permit`` holds.

    (b) **A required collector read ZERO on a run that processed a non-zero volume.** The sink tally is the
        drive box's ONLY reliable delivery observer. If the fleet accept-ACK'd a non-zero intake (``A > 0``)
        and the engine store-truth says it delivered that intake CLEAN (``engine_ok``), a sink count of ZERO
        is a blind/absent collector, not a measured zero — it cannot certify SUSTAINED nor a benign
        FROZEN_TAIL. (A genuine total collapse also reads ``S == 0``, but then the engine CONFIRMS it —
        ``engine_ok`` is False — and the run is honestly COLLAPSED, not caught here.)
    """
    if acked < 0 or sink_received < 0:
        return False  # observer counts not supplied ⇒ guard inert (see docstring)
    if acked == 0 or delivering <= 0:
        return False  # no non-zero volume to reconcile across the two observers
    expected = acked * delivering
    slack = tol * expected
    # (b) blind required collector: the engine says all-clean-delivered, the sink saw nothing.
    if sink_received == 0 and engine_ok:
        return True
    # (a) the sink over-counts vs the engine store-truth's permitted deliveries. When the engine claims a
    # collapse we need the strand/dead tally to compute the permit; an unknown tally (a sentinel <0) can't
    # detect (a), so we leave such a rung to the COLLAPSED branch rather than guess.
    if not engine_ok and (engine_stranded < 0 or engine_dead_total < 0):
        return False
    unclear = max(0, engine_stranded) + max(0, engine_dead_total)
    # (a′) A FULLY-lossless sink (``S ≥ A×D``) coincident with ANY unclear row is a HARD contradiction that
    # NO handler budget can explain, so it is charged BEFORE ``free`` is consulted. ``S ≥ A×D`` asserts every
    # one of the A accepted messages delivered all D copies — which leaves ZERO non-terminal or dead rows: a
    # self-filtering handler's routed row is finalized TERMINAL (``FILTERED``/``UNROUTED``, its routed row
    # DELETEd in the transform-handoff txn — see ``store.handoff``/``transform_handoff``), so it never enters
    # the ``stranded`` (``status NOT IN ('done','dead')``) tally in the first place. Every row that DOES count
    # as unclear is therefore a genuinely stuck/dead delivery-bearing row, and it cannot coexist with a
    # lossless sink. Crediting such a row to the non-delivering-handler ``free`` budget would forgive an
    # INGRESS strand (blocks D copies) or a delivering-path strand (blocks ≥1) as if it blocked nothing — the
    # exact stage-blind over-forgiveness that would let this contradiction fabricate a bracketed COLLAPSED.
    if sink_received >= expected and unclear > 0:
        return True
    # Below here the sink UNDER-counts (``S < A×D``) — a real shortfall, not a lossless-vs-stranded
    # contradiction. The non-delivering-handler budget A×(H−D) lets a GENUINE H>D collapse (where the routed
    # strand count scales with H while deliveries scale with D, and the sink honestly under-counts) read as
    # the honest COLLAPSED the observers AGREE on, rather than a fabricated INCONCLUSIVE.
    free = acked * max(0, handlers - delivering)
    if (
        handlers > delivering
        and ingress_stranded >= 0
        and routed_stranded >= 0
        and outbound_stranded >= 0
    ):
        # BACKLOG #229 — SOUND per-stage `blocked`. `stranded` is opaque across all stages, so the
        # stage-blind `max(0, unclear - free)` credits an INGRESS strand (which blocks all D copies — the
        # message never routed) or an OUTBOUND strand (blocks 1) to the non-delivering-handler `free` budget
        # as if it blocked ZERO, missing a partial over-count (S beyond the store's REAL capacity, yet below
        # A×D) at H>D. With the per-stage split in hand we charge each strand its true weight:
        #   * INGRESS strand → blocks all `delivering` copies (never routed).
        #   * OUTBOUND strand → blocks exactly 1 (one message→destination delivery).
        #   * ROUTED strand → blocks in [0, 1]: a delivering handler's routed row blocks 1, a NON-delivering
        #     handler's blocks 0. We cannot tell which from the count, so the `free` budget (the A×(H−D)
        #     non-delivering routed rows) is credited AGAINST the routed strands ONLY — crediting it against
        #     ingress/outbound would re-introduce the stage-blindness. This is the load-bearing tension: a
        #     genuine H>D collapse strands ~A×H routed rows, of which ~A×(H−D) are non-delivering; `free`
        #     absorbs exactly those so the collapse reads as the honest COLLAPSED the observers agree on,
        #     rather than re-fabricating the INCONCLUSIVE this guard exists to prevent.
        blocked = ingress_stranded * delivering + max(0, routed_stranded - free) + outbound_stranded
    else:
        # H==D (free==0 ⇒ `blocked == unclear`, so permit == expected − unclear) OR the per-stage split is
        # absent (an older payload / aborted rung → the `< 0` sentinel): the stage-blind tally, byte-identical
        # to the pre-#229 formula `expected - max(0, stranded) - max(0, dead)` (see docstring).
        blocked = max(0, unclear - free)
    permit = expected - blocked
    return sink_received > permit + slack


def classify_rung(
    *,
    engine_reported: bool,
    engine_ok: bool,
    no_loss: bool,
    lane_inversions: int,
    lane_repeats: int,
    acked: int = -1,
    sink_received: int = -1,
    delivering: int = 1,
    handlers: int = 0,
    engine_stranded: int = 0,
    engine_dead_total: int = 0,
    ingress_stranded: int = -1,
    routed_stranded: int = -1,
    outbound_stranded: int = -1,
    observer_tol: float = _OBSERVER_DISAGREE_TOL,
) -> RungVerdict:
    """Classify one rung from the two RELIABLE authorities only. ``engine_reported`` is whether the ENGINE
    store-truth was confirmed at all (from the ENGINE_DRAINED drain gate or the ENGINE_RUNG_REPORT);
    ``engine_ok`` is the store-truth pass bar (``drained ∧ stranded==0 ∧ dead_total==0``); ``no_loss`` is the
    DRIVE sink socket-truth (``S == A*delivering ∧ A>0 ∧ S>0``). The remote poller is NEVER an input.

    The ``acked``/``sink_received``/``delivering``/``handlers``/``engine_stranded``/``engine_dead_total``
    counts feed the A4b cross-observer guard (:func:`observers_inconclusive`); they default to a sentinel that
    leaves the guard INERT, so a caller passing only the booleans keeps the historical truth-table. The
    integration path (:func:`build_rung_outcome`) always supplies them — with ``delivering``, the FAN-OUT,
    never ``dests``, and ``handlers`` (H) so the permit can credit the non-delivering-handler strand budget at
    ``H > D`` (``handlers`` defaults to ``0`` ⇒ that budget is empty ⇒ the pre-#209 ``H == D`` behaviour).

    Order matters: (1) a correctness break (from the always-present sink-truth) outranks everything; (2) an
    UNCONFIRMED engine store-truth is INCONCLUSIVE — a coord glitch, distinct from a proven collapse, so it
    never fabricates a bracketed ceiling; (3) A4b: two CONFIRMED-but-CONTRADICTORY observers (or a blind
    required collector) are also INCONCLUSIVE — trusting one to break the tie is the exact silent fabrication
    this ladder refuses; (4) a CONFIRMED non-drained engine that the sink does NOT contradict is a true
    COLLAPSE; (5) the engine having drained clean, a lossless run is SUSTAINED and a short sink tally is a
    (benign) frozen tail, never collapse.

    **NO FILLING TERM — and that is a KNOWN GAP, stated so nobody assumes otherwise (2026-07-13).** A rung
    can be lossless-and-drained yet still have been FILLING (its in-flight backlog growing through the hold,
    drained only *after* the offer stopped). ``shardcert.ShardCertStepRecord.filling`` detects that from an
    E2E-latency split — but ONLY on the CO-LOCATED ladder (``run_shardcert_ladder``), where one process both
    sends and sinks so a ``Correlator`` can join the timestamps. On THIS (two-box) path senders and sinks are
    separate processes behind a metadata-only coord, so there is no E2E stream to split and no filling signal
    exists to consult. **Every two-box ceiling — including the ~16 msg/s STEP-4 plateau — is therefore
    measured WITHOUT the filling gate**, and may over-report the sustainable rate by counting a still-filling
    rung as SUSTAINED. Closing this needs a real in-hold latency-growth signal plumbed into the two-box tier
    (engine-side ``E2E_complete`` out of ``message_events``, or a cross-process correlation); adding a
    ``filling`` term HERE is the other half of that change, and neither half is worth anything alone."""
    if lane_inversions > 0 or lane_repeats > 0:
        return RungVerdict.CORRECTNESS_FAIL
    if not engine_reported:
        return RungVerdict.INCONCLUSIVE
    if observers_inconclusive(
        engine_ok=engine_ok,
        acked=acked,
        sink_received=sink_received,
        delivering=delivering,
        handlers=handlers,
        engine_stranded=engine_stranded,
        engine_dead_total=engine_dead_total,
        ingress_stranded=ingress_stranded,
        routed_stranded=routed_stranded,
        outbound_stranded=outbound_stranded,
        tol=observer_tol,
    ):
        return RungVerdict.INCONCLUSIVE
    if not engine_ok:
        return RungVerdict.COLLAPSED
    if no_loss:
        return RungVerdict.SUSTAINED
    return RungVerdict.FROZEN_TAIL


def stops_climb(verdict: RungVerdict) -> bool:
    """Whether hitting ``verdict`` stops the climb: a true collapse, a correctness break, or an unconfirmed
    store-truth (can't certify further rungs without the reliable drain proof). A frozen tail does NOT stop
    (the engine sustained it — keep probing for the real collapse), nor does sustained."""
    return verdict in (
        RungVerdict.COLLAPSED,
        RungVerdict.CORRECTNESS_FAIL,
        RungVerdict.INCONCLUSIVE,
    )


# =====================================================================================================
# Per-rung consolidated record + the whole-ladder report
# =====================================================================================================


@dataclass(frozen=True)
class RungOutcome:
    """One driven rung, folding the DRIVE sink-truth + the ENGINE store-truth (+ phase timing) into the
    classified verdict. Counts + synthetic topology only (never bodies / control-ids — PHI rule)."""

    index: int
    is_soak: bool
    ingress_rate: float
    # TOPOLOGY: shared outbound CONNECTIONS. NOT the fan-out — see `delivering` (BACKLOG #209).
    dests: int
    # H: handlers the router SELECTED. Feeds `txn_per_message`; never delivery arithmetic.
    handlers: int
    # D: destinations an accepted message actually delivered to. *** THE FAN-OUT ***
    delivering: int
    hold_seconds: float
    offered: int  # round(ingress_rate * hold_seconds) — the ingress offer
    acked: int  # A (accept-ACK'd intake)
    sink_received: int  # S (socket-observed deliveries)
    no_loss: bool
    lane_inversions: int
    lane_repeats: int
    lanes_observed: int
    ack_p50_ms: float
    ack_p99_ms: float
    drive_drain_seconds: float | None
    # ENGINE store-truth (from ENGINE_RUNG_REPORT; None ⇒ the engine half's report never arrived)
    engine_reported: bool
    engine_ok: bool
    engine_drained: bool
    engine_stranded: int
    engine_dead_total: int
    engine_in_pipeline_final: int
    # soak only
    in_pipeline_slope: float | None
    phase: PhaseTiming
    verdict: RungVerdict
    #: D6: the per-claim store round-trip aggregate (the phase #842 could not see). Defaults empty when the
    #: rung's ENGINE_RUNG_REPORT is absent or carried no claim timing (mirrors the empty ``phase`` fallback).
    claim: ClaimTiming = _EMPTY_CLAIM_TIMING
    #: STEP 4 ARM 1: ``S_lane`` — the pooled dispatcher's per-lane SERVICE TIME (reserve→release), plus the
    #: lane's non-service occupancy. Read ``episode.by_stage["outbound"]``, never the four-stage blend.
    #: Defaults empty when the rung's ENGINE_RUNG_REPORT is absent or the bench lever was off.
    episode: EpisodeTiming = _EMPTY_EPISODE_TIMING
    #: D1: the RELIABLE engine-side drain time (from the ENGINE_DRAINED gate / ENGINE_RUNG_REPORT) — the
    #: authority the verdict already trusts, guaranteed present for a SUSTAINED rung (drained ⇒ drain_s is not
    #: None). Preferred over the advisory ``drive_drain_seconds`` (which "zeroes/misses under load") for the
    #: honest sustainable rate, so a load-correlated drive-poll miss can't drop a sustained rung's ceiling.
    engine_drain_seconds: float | None = None
    #: BACKLOG #229: the delivery-blocking rows (non-terminal + dead) SPLIT by pipeline stage, from the
    #: engine store-truth (ENGINE_DRAINED gate / ENGINE_RUNG_REPORT). The A4b cross-observer permit charges
    #: an ingress strand D copies, an outbound strand 1, a routed strand [0,1] — sound at H>D, where the
    #: stage-blind opaque total mis-credited an ingress/outbound strand as blocking 0. ``-1`` = NOT READ (an
    #: older payload / aborted rung) ⇒ the permit falls back to the stage-blind, pre-#229 arithmetic.
    engine_ingress_stranded: int = -1
    engine_routed_stranded: int = -1
    engine_outbound_stranded: int = -1
    #: WHICH SHAPE served this rung (from the drive report, which learned it from SHARDS_READY). Load-bearing
    #: for reading `handlers`/`delivering`: under `partitioned` they are the DERIVED accounting pair (1, 1),
    #: which a legal BROADCAST run can also produce with a totally different lane topology.
    routing: str = BROADCAST
    #: ARTIFACT 4: Σ sender-worker ``sent`` — the DRIVE-side half of the FIDELITY gate, from
    #: ``ShardCertDriveReport.sent`` (which the DRIVER_DONE coord drops have always carried). ``-1`` = NOT
    #: RECORDED ⇒ :attr:`fidelity` is UNKNOWN ⇒ the rung is VOID for the ceiling. FAIL-CLOSED: a defaulted
    #: sentinel that reads as a PASS is exactly how the ``filling`` gate died on this path.
    sent: int = -1
    #: ⭐ THE DEFERRAL CAUSE SPLIT (fidelity gate v2), from ``ShardCertDriveReport``. ``sent`` is ENGINE-PACED
    #: — it advances only after a pop from a BOUNDED queue whose writer ``drain()``s first, so an engine that
    #: stops reading its socket fills the TCP window, blocks the writer, fills the queue and SUPPRESSES
    #: ``sent``. A ``sent`` shortfall therefore cannot name a culprit on its own, and v1 pretended it could:
    #: it called EVERY shortfall a DRIVE_SHORTFALL, voided the rung as a rig failure, and told the operator
    #: to buy drive boxes — discarding the single most likely signature of a REAL intake bind. These two
    #: counters are what arbitrate. ``-1`` = NOT RECORDED ⇒ OFFER_SHORTFALL (cause UNATTRIBUTED), which
    #: voids FAIL-CLOSED and blames NOBODY — never a silent default to "the rig".
    deferred_backpressure: int = -1  # full send buffers ⇒ THE ENGINE would not take the bytes
    deferred_schedule: int = -1  # tick-lag / no target ⇒ THE RIG could not schedule the sends
    #: ARTIFACT 5: lanes-per-shard, so ``G = len(shards) x lanes_per_shard`` — the INGRESS/ROUTED per-lane
    #: pool width — can be compared against ``dests`` (L, the OUTBOUND one) when reading any plateau.
    lanes_per_shard: int = 1
    #: ARTIFACT 2: the store pool this rung ran on (requested + engine-observed max + acquire_wait evidence
    #: + the pre-registered tripwire), carried over ENGINE_RUNG_REPORT. Empty ⇒ the report never arrived or
    #: the engine half is older — which reads as "not measured", never as "no queueing".
    pool: PoolStats = EMPTY_POOL_STATS
    notes: tuple[str, ...] = ()

    @property
    def fidelity(self) -> RungFidelity:
        """ARTIFACT 4 — was this rung EVIDENCE ABOUT THE ENGINE, or just a readback of the PLAN?

        ``classify_rung`` never compares ``acked`` to ``offered`` and never sees ``sent`` at all: its
        SUSTAINED arm is ``no_loss``, the identity ``S == A x D``, which is SCALE-FREE. A rung that offered
        520/s, pushed 16/s and delivered all 16 losslessly is SUSTAINED — so an under-driven climb (the
        DEFAULT expectation, since partitioned needs ~520/s of drive against the ~16 the rig pushes today)
        reports a pinned ceiling that is a pure function of the ladder plan.

        This is the missing comparison, on the SAME pure predicate the co-located ``ShardCertStepRecord``
        calls (:func:`~harness.load.shardcert.rung_fidelity`). Not admissible ⇒ VOID for the ceiling, with
        the reason recorded, so nobody can ever again confuse "my load generator is too small" with "the
        engine bound".

        ⭐ v2: the ``sent``-shortfall arm is CAUSE-SPLIT on :attr:`deferred_backpressure` /
        :attr:`deferred_schedule`. Passing them is not optional plumbing — WITHOUT them every shortfall
        scores OFFER_SHORTFALL (cause unattributed) and a real BACKPRESSURE_BIND, the very finding this gate
        exists to surface, is silently downgraded to "we don't know"."""
        return rung_fidelity(
            sent=self.sent,
            acked=self.acked,
            offered=self.offered,
            deferred_backpressure=self.deferred_backpressure,
            deferred_schedule=self.deferred_schedule,
        )

    @property
    def fidelity_reason(self) -> str | None:
        """The VOID/BIND reason, from the SAME inputs as :attr:`fidelity` — so the note and the verdict can
        never disagree (the JSON used to rebuild it from a DIFFERENT, split-less argument list, which meant
        a BACKPRESSURE_BIND rung could carry a note that said 'go add drive boxes')."""
        return fidelity_note(
            self.fidelity,
            sent=self.sent,
            acked=self.acked,
            offered=self.offered,
            deferred_backpressure=self.deferred_backpressure,
            deferred_schedule=self.deferred_schedule,
        )

    @property
    def fidelity_admissible(self) -> bool:
        """This rung may be used to PIN a ceiling. Everything else — including an UNKNOWN gate — may not."""
        return self.fidelity is RungFidelity.ADMISSIBLE

    @property
    def fidelity_driven(self) -> bool:
        """The offered RATE was established against the engine (it reached the wire, or the ENGINE itself
        refused to read it), so this rung's RATE LABEL is real and it may BRACKET the ceiling — even though
        an engine-bound rung may not PIN one.

        ⭐ THE BRACKET AND THE PIN ARE DIFFERENT QUESTIONS, and collapsing them throws away real findings.
        A SATURATING ENGINE IS EXACTLY ``acked < 0.95 x offered`` — that is this project's own model of a
        ceiling (``_is_ceiling`` fires on the same shortfall) — so the top rung of a genuine saturation
        climb is typically BOTH ``COLLAPSED`` and fidelity-ENGINE_BOUND. Bracketing on ``admissible`` would
        discard it and print "no ceiling reached (raise the ladder)" on a run that MEASURED THE COLLAPSE.
        Only a rung whose rate never reached the engine at all (DRIVE_SHORTFALL / OFFER_SHORTFALL / UNKNOWN)
        can neither pin nor bracket. This mirrors the co-located ladder, which splits on the same predicate."""
        return self.fidelity.driven

    @property
    def sent_ratio(self) -> float | None:
        """``sent / offered`` — emitted so :data:`~harness.load.shardcert.FIDELITY_SENT_FLOOR` (the one
        pre-registered bar the code admits is UNMEASURED) can be RE-DERIVED from banked runs, which is that
        bar's own stated remediation plan. It named this key on the two-box rung; the key did not exist."""
        if self.offered <= 0 or self.sent < 0:
            return None
        return self.sent / self.offered

    @property
    def rate_drain_seconds(self) -> float | None:
        """The drain used for the honest sustainable rate: the RELIABLE engine-side drain when present (the
        authority the verdict trusts, guaranteed for a SUSTAINED rung), else the advisory drive-side drain."""
        return (
            self.engine_drain_seconds
            if self.engine_drain_seconds is not None
            else self.drive_drain_seconds
        )

    def outbound_rate(self) -> float:
        """Deliveries/s — keyed on the FAN-OUT (D), never on the destination-connection count."""
        return self.ingress_rate * self.delivering

    def outbound_delivered_expected(self) -> int:
        """The sink's expected socket count: ``A × D``. This IS the no-loss identity — key it on ``dests``
        and every healthy ``H != D`` rung reads LOSS (BACKLOG #209)."""
        return self.acked * self.delivering

    @property
    def txn_per_message(self) -> int:
        """The ADR 0051 durable-write cost of one ingress message on the shape this rung SERVED:
        ``3 + 2H + 2D``. The ``2H`` term is charged before any handler runs, so a self-filtering handler
        still costs its 2 — which is precisely the waste the ``accepts=`` seam (ADR 0084) removes and this
        rung's ``handlers``/``delivering`` split exists to make visible. Reported, never gated on."""
        return 3 + 2 * self.handlers + 2 * self.delivering

    @property
    def sustainable_ingress_rate(self) -> float | None:
        """The HONEST sustainable INGRESS rate this rung actually proves (D1). A SUSTAINED rung only shows
        the engine DELIVERED all ``offered × D`` messages within ``hold + drain`` — NOT that it kept up
        at the offered ``ingress_rate`` in real time. The honest rate spreads the offer over the REAL span it
        took to clear: ``ingress_rate × hold / (hold + drain)`` using the RELIABLE measured drain
        (:attr:`rate_drain_seconds` — the engine-side store-truth drain preferred over the advisory drive
        poll), never the drain TIMEOUT. A rung that only drained its backlog post-hold reports a rate well
        below its offered ``ingress_rate`` (the raw offered rate overstates it by ``(hold + drain) / hold``).
        ``None`` only when NO drain was measured at all — which for a SUSTAINED rung cannot happen (the engine
        drain is guaranteed present), so a sustained rung is never dropped from the pinned ceiling."""
        drain = self.rate_drain_seconds
        if drain is None:
            return None
        span = self.hold_seconds + drain
        if span <= 0:
            return None
        return self.ingress_rate * self.hold_seconds / span

    @property
    def accepted_ingress_rate(self) -> float | None:
        """The ACCEPTED-derived sustainable ingress — the HONEST FLOOR under
        :attr:`sustainable_ingress_rate`, which is OFFERED-derived.

        ``sustainable_ingress_rate`` spreads the rung's OFFERED ``ingress_rate`` over ``hold + drain``;
        ``acked`` never enters it. A rung only has to accept within :data:`~harness.load.shardcert._INTAKE_TOL`
        (5%) of the offer to be SUSTAINED, so the pinned ceiling can overstate the truly-accepted rate by up
        to that tolerance — and it does so precisely AT the ceiling, where offered and accepted diverge. This
        divides the messages the fleet actually accept-ACKed (``A``) by the same real span, so the two can be
        read side by side and the gap is visible rather than assumed away. ``None`` when no drain was
        measured (same condition as its offered-derived sibling)."""
        drain = self.rate_drain_seconds
        if drain is None:
            return None
        span = self.hold_seconds + drain
        if span <= 0:
            return None
        return self.acked / span

    def delivered_rate_per_s(self, shard_count: int) -> float | None:
        """The HONEST MEASURED outbound delivery rate (D3): socket-observed deliveries (``sink_received``)
        over the TRUE delivery SPAN — NOT ``sink_received / hold_seconds``. Deliveries continue through the
        post-hold drain, so dividing by the hold alone overstates the rate by ~``(hold + drain) / hold``. The
        span is recovered from the per-5s ``delivery phase timing`` windows: ``phase.windows`` sums across
        ``shard_count`` concurrent shards, so ``(phase.windows / shard_count) × _PHASE_WINDOW_SECONDS`` is the
        wall-clock span over which the shards delivered. ``None`` when no phase windows were captured
        (``MEFOR_DELIVERY_PHASE_TIMING`` off / no delivered rows) or ``shard_count`` is non-positive — an
        unmeasured span cannot honestly denominate a rate."""
        if self.phase.windows <= 0 or shard_count <= 0:
            return None
        span_s = (self.phase.windows / shard_count) * _PHASE_WINDOW_SECONDS
        if span_s <= 0:
            return None
        return self.sink_received / span_s

    def render(self) -> str:
        tag = "soak" if self.is_soak else f"r{self.index}"
        eng = (
            f"engine_ok={self.engine_ok} drained={self.engine_drained} "
            f"stranded={self.engine_stranded} dead={self.engine_dead_total}"
            if self.engine_reported
            else "engine=<no report>"
        )
        slope = (
            ""
            if self.in_pipeline_slope is None
            else f" in_pipeline_slope={self.in_pipeline_slope:+.2f}/s"
        )
        sustain = (
            ""
            if self.sustainable_ingress_rate is None
            else f" sustainable_ingress={self.sustainable_ingress_rate:g}/s"
        )
        # ARTIFACT 3: the ACCEPTED-derived rate is printed BESIDE the offered-derived one, never instead of
        # it. The two standing side by side IS the instrument: when they diverge, the run was under-driven
        # and the offered-derived figure is fiction.
        accepted = (
            ""
            if self.accepted_ingress_rate is None
            else f" accepted_ingress={self.accepted_ingress_rate:g}/s"
        )
        # ARTIFACT 4: a VOID rung must SAY it is void, in the same line an operator reads its rate from.
        fid = (
            ""
            if self.fidelity is RungFidelity.ADMISSIBLE
            else f" [VOID: {self.fidelity.value.upper()}]"
        )
        return (
            f"{tag:5} ingress={self.ingress_rate:g}/s outbound={self.outbound_rate():g}/s{sustain}"
            f"{accepted} "
            f"offered={self.offered} sent={self.sent} A={self.acked} S={self.sink_received} "
            f"(expect A*delivering={self.outbound_delivered_expected()}) | {eng} | "
            f"inv={self.lane_inversions} rep={self.lane_repeats} lanes={self.lanes_observed}{slope} "
            f"=> {self.verdict.value.upper()}{fid}"
        )

    def to_json_dict(self) -> dict[str, object]:
        return {
            "index": self.index,
            "is_soak": self.is_soak,
            "verdict": self.verdict.value,
            "ingress_rate": round(self.ingress_rate, 3),
            "outbound_rate": round(self.outbound_rate(), 3),
            # D1: the HONEST sustainable ingress this rung proves (offered spread over hold + MEASURED
            # drain), not the inflated raw offered ingress_rate. None when the drain was not measured.
            "sustainable_ingress_rate": (
                None
                if self.sustainable_ingress_rate is None
                else round(self.sustainable_ingress_rate, 3)
            ),
            # The ACCEPTED-derived floor beside the OFFERED-derived rate above: `sustainable_ingress_rate` is
            # offered x hold / (hold + drain) and never looks at `acked`, and SUSTAINED only bounds the intake
            # shortfall by _INTAKE_TOL (5%) — so at the ceiling the offered figure can overstate what was
            # truly accepted. Emit both; never quote the offered one alone.
            "accepted_ingress_rate": (
                None if self.accepted_ingress_rate is None else round(self.accepted_ingress_rate, 3)
            ),
            # BACKLOG #209: `dests` is the destination-CONNECTION count (topology); `delivering` is the
            # FAN-OUT every delivery figure here keys off; `handlers` is what the router selected (cost only).
            # `routing` names the shape: under `partitioned` the pair is the DERIVED (1, 1), not the build one.
            "dests": self.dests,
            "handlers": self.handlers,
            "delivering": self.delivering,
            "routing": self.routing,
            # ARTIFACT 5: G's per-shard half. The report's `topology.inbound_bands` is the fleet figure; this
            # is here so a rung read in isolation still names the INGRESS pool width it ran against.
            "lanes_per_shard": self.lanes_per_shard,
            "txn_per_message": self.txn_per_message,  # 3 + 2H + 2D (ADR 0051) — reported, not gated
            "hold_seconds": self.hold_seconds,
            "offered_ingress": self.offered,
            # ARTIFACT 4: `sent` (the DRIVE's own offer count) beside `offered` (the PLAN) and `acked` (what
            # the ENGINE took). All three were never in one place, so the ladder could not tell a drive
            # shortfall from an engine intake bind — it called both SUSTAINED.
            "sent": self.sent,
            # v7: so the UNMEASURED pre-registered 0.98 sent bar can be RE-DERIVED from banked artifacts.
            "sent_ratio": None if self.sent_ratio is None else round(self.sent_ratio, 4),
            "acked": self.acked,
            # ⭐ v7: THE DEFERRAL CAUSE SPLIT — the gate's shortfall discriminator, and the only thing in the
            # artifact that can tell an ENGINE BACKPRESSURE BIND from a rig that ran out. `offered - sent` is
            # ENGINE-PACED (bounded queue + drain()), so it names no culprit by itself. -1 = NOT RECORDED,
            # which scores OFFER_SHORTFALL (unattributed) and blames nobody.
            "deferred_backpressure": self.deferred_backpressure,
            "deferred_schedule": self.deferred_schedule,
            "fidelity": self.fidelity.value,
            "fidelity_admissible": self.fidelity_admissible,  # may PIN a ceiling
            # v7: the offered RATE was established (or the ENGINE refused to read it) ⇒ this rung may BRACKET
            # a ceiling even when it may not pin one. An engine bind is a FINDING, not a void.
            "fidelity_driven": self.fidelity_driven,
            "fidelity_reason": self.fidelity_reason,
            "fidelity_gate_version": FIDELITY_GATE_VERSION,
            "sink_received": self.sink_received,
            "outbound_expected": self.outbound_delivered_expected(),  # A * delivering, NOT A * dests
            "no_loss": self.no_loss,
            "lane_inversions": self.lane_inversions,
            "lane_repeats": self.lane_repeats,
            "lanes_observed": self.lanes_observed,
            "ack_ms": {"p50": round(self.ack_p50_ms, 3), "p99": round(self.ack_p99_ms, 3)},
            "drive_drain_seconds": self.drive_drain_seconds,
            "engine_drain_seconds": self.engine_drain_seconds,  # D1: the reliable drain used for the rate
            "engine": {
                "reported": self.engine_reported,
                "ok": self.engine_ok,
                "drained": self.engine_drained,
                "stranded": self.engine_stranded,
                "dead_total": self.engine_dead_total,
                # BACKLOG #229: the per-stage strand split the A4b permit charges by weight (ingress→D,
                # outbound→1, routed→[0,1]). -1 = NOT READ (older payload / aborted rung → stage-blind).
                "ingress_stranded": self.engine_ingress_stranded,
                "routed_stranded": self.engine_routed_stranded,
                "outbound_stranded": self.engine_outbound_stranded,
                "in_pipeline_final": self.engine_in_pipeline_final,
            },
            "in_pipeline_slope": self.in_pipeline_slope,
            "phase_timing": self.phase.to_json_dict(),
            "claim_timing": self.claim.to_json_dict(),  # D6: the store-claim round-trip #842 could not see
            # ARM 1: S_lane. Read `episode_timing.by_stage.outbound`, NOT the flat four-stage blend.
            "episode_timing": self.episode.to_json_dict(),
            # ARTIFACT 2: the pool this rung ran on + its saturation evidence + the pre-registered tripwire.
            # A POOL BIND looks IDENTICAL to the pooled-claim wall in every column (strands at outbound,
            # claim_mean grows, immune to drive and to disk) — this block is the only thing that separates
            # them, and it must be in the artifact or the run is unauditable.
            "store_pool": self.pool.to_json_dict(),
            "notes": list(self.notes),
        }


def build_rung_outcome(
    rung: LadderRung,
    drive: ShardCertDriveReport,
    gate: Mapping[str, Any] | None,
    report: Mapping[str, Any] | None,
) -> RungOutcome:
    """Fold a rung's DRIVE report + BOTH engine coord messages into a classified :class:`RungOutcome`.

    The engine store-truth (``engine_ok`` / stranded / dead / drained) that DRIVES the classifier is taken
    from the **reliable** ``gate`` (the ENGINE_DRAINED drain-gate payload, which the drive AWAITS before it
    tallies its sinks — so it is present on every non-degraded rung), preferring it over the later, more
    fragile ``report`` (ENGINE_RUNG_REPORT, posted only after fleet teardown + node-log aggregation). This is
    the fix for the false-ceiling defect: a late/lost ENGINE_RUNG_REPORT no longer looks like a store-truth
    collapse — the verdict rests on the drain gate, and ENGINE_RUNG_REPORT only ADDS the phase-timing + soak
    slope. Store-truth is ``engine_reported`` only if AT LEAST ONE of the two arrived; with neither, the rung
    is classified INCONCLUSIVE (a coord glitch, never a fabricated collapse)."""
    notes: list[str] = list(drive.notes)
    truth = gate if gate is not None else report  # prefer the reliable drain gate for store-truth
    engine_reported = truth is not None
    engine_drain_seconds: float | None = (
        None  # D1: the RELIABLE engine drain (gate/report) for the rate
    )
    if truth is None:
        engine_ok = False
        engine_drained = False
        engine_stranded = -1
        engine_dead_total = -1
        engine_in_pipeline_final = -1
        # BACKLOG #229: no store-truth ⇒ no per-stage split; the sentinel keeps the permit stage-blind.
        engine_ingress_stranded = -1
        engine_routed_stranded = -1
        engine_outbound_stranded = -1
        notes.append(
            "engine store-truth UNCONFIRMED (neither ENGINE_DRAINED nor ENGINE_RUNG_REPORT arrived) — "
            "rung is INCONCLUSIVE, NOT a proven collapse (excluded from the ceiling bracket)"
        )
    else:
        engine_ok = bool(truth.get("engine_ok", False))
        engine_drained = bool(truth.get("drained", False))
        engine_stranded = int(truth.get("stranded", -1))
        engine_dead_total = int(truth.get("dead_total", -1))
        # BACKLOG #229: the per-stage strand split (from BOTH the gate and the report). A `< 0` sentinel
        # default (an older payload that never carried the split) leaves the permit on the stage-blind path.
        engine_ingress_stranded = int(truth.get("ingress_stranded", -1))
        engine_routed_stranded = int(truth.get("routed_stranded", -1))
        engine_outbound_stranded = int(truth.get("outbound_stranded", -1))
        engine_in_pipeline_final = int(truth.get("in_pipeline_final", -1))
        _raw_drain = truth.get("drain_seconds")
        engine_drain_seconds = None if _raw_drain is None else float(_raw_drain)
        if gate is None:
            notes.append(
                "engine store-truth from ENGINE_RUNG_REPORT (drain gate absent — degraded)"
            )

    # Phase timing + the soak in_pipeline slope live ONLY on ENGINE_RUNG_REPORT (the gate has neither).
    slope: float | None = None
    phase = PhaseTiming(0, 0, 0.0, 0.0, 0.0, 0.0)
    claim = _EMPTY_CLAIM_TIMING
    episode = _EMPTY_EPISODE_TIMING
    pool = EMPTY_POOL_STATS
    if report is not None:
        raw_slope = report.get("in_pipeline_slope")
        slope = None if raw_slope is None else float(raw_slope)
        phase_raw = report.get("phase_timing")
        if isinstance(phase_raw, Mapping):
            phase = PhaseTiming.from_json_dict(phase_raw)
        claim_raw = report.get("claim_timing")  # D6: the store-claim round-trip aggregate
        if isinstance(claim_raw, Mapping):
            claim = ClaimTiming.from_json_dict(claim_raw)
        episode_raw = report.get("episode_timing")  # ARM 1: S_lane (reserve→release)
        if isinstance(episode_raw, Mapping):
            episode = EpisodeTiming.from_json_dict(episode_raw)
        pool_raw = report.get("store_pool")  # ARTIFACT 2: the pool's saturation evidence
        if isinstance(pool_raw, Mapping):
            pool = PoolStats.from_json_dict(pool_raw)
        for note in report.get("notes", []) or []:
            notes.append(f"engine: {note}")
    elif engine_reported:
        notes.append("engine phase timing / soak slope absent (ENGINE_RUNG_REPORT not read)")
    # ARTIFACT 2: an unmeasured pool is UNKNOWN, never innocent — say so, because the whole point of the
    # tripwire is that a pool bind is otherwise indistinguishable from the claim wall it would be blamed on.
    if not pool.measured:
        notes.append(
            "store pool NOT MEASURED for this rung (no ENGINE_RUNG_REPORT store_pool block) — a pool bind "
            "cannot be ruled out from this rung's data, and it is column-for-column identical to a claim wall"
        )
    elif pool.tripped and pool.trip_reason is not None:
        notes.append(pool.trip_reason)
    if pool.requested_matches_engine is False:
        notes.append(
            f"store pool MISMATCH: the harness requested {pool.requested} but the engine reports a "
            f"configured maximum of {pool.max_size} — MEFOR_STORE_POOL_SIZE did not reach the shard "
            "processes; this run's pool is NOT the one it claims"
        )

    verdict = classify_rung(
        engine_reported=engine_reported,
        engine_ok=engine_ok,
        no_loss=drive.no_loss,
        lane_inversions=drive.lane_inversions,
        lane_repeats=drive.lane_repeats,
        # A4b cross-observer guard: reconcile the ENGINE store-truth tally against the DRIVE sink count so a
        # contradiction (or a blind collector) downgrades to INCONCLUSIVE instead of a fabricated verdict.
        # It keys on `delivering` — the FAN-OUT. On `dests` the permit inflates at D < dests and trigger (a)
        # can never fire: the guard would be silently DISARMED (BACKLOG #209/#219). It also needs `handlers`
        # (H): at H > D the permit credits the non-delivering-handler strand budget A×(H−D) so a GENUINE
        # collapse (strands scale with H, deliveries with D) is not fabricated INCONCLUSIVE (BACKLOG #209).
        acked=drive.acked,
        sink_received=drive.sink_received,
        delivering=drive.delivering,
        handlers=drive.handlers,
        engine_stranded=engine_stranded,
        engine_dead_total=engine_dead_total,
        # BACKLOG #229: the per-stage strand split, so the permit charges an ingress strand D copies, an
        # outbound strand 1, a routed strand [0,1] — sound at H>D, where the stage-blind opaque total
        # mis-credited an ingress/outbound strand as blocking 0. Absent (sentinel) ⇒ stage-blind fallback.
        ingress_stranded=engine_ingress_stranded,
        routed_stranded=engine_routed_stranded,
        outbound_stranded=engine_outbound_stranded,
    )
    # A4b: distinguish this INCONCLUSIVE from the store-truth-unconfirmed one (which already noted itself
    # above) so an operator sees WHY a confirmed rung would not certify — the two observers disagreed.
    if verdict is RungVerdict.INCONCLUSIVE and engine_reported:
        notes.append(
            "cross-observer INCONCLUSIVE: the ENGINE store-truth and the DRIVE sink count are "
            f"inconsistent (acked={drive.acked} delivering={drive.delivering} "
            f"sink_received={drive.sink_received} engine_ok={engine_ok} stranded={engine_stranded} "
            f"dead={engine_dead_total}) — neither observer is trusted to break the tie (excluded from "
            "the ceiling bracket)"
        )
    # ARTIFACT 4: the FIDELITY gate. It is deliberately NOT folded into `verdict` — a drive shortfall is not
    # a statement about the engine at all, so calling it COLLAPSED would be a second fabrication on top of
    # the first. It is a SEPARATE axis: the verdict says what the fleet did; fidelity says whether the rung
    # was worth asking. A non-admissible rung is VOID for the ceiling (see ConsolidatedLadderReport.
    # pinned_rung) and carries the reason so the two failure modes can never be conflated again.
    #
    # ⭐ v2 — THE CAUSE SPLIT IS PASSED THROUGH. `sent` is ENGINE-PACED, so a shortfall names no culprit on
    # its own; `deferred_backpressure` (the engine would not read its socket) vs `deferred_schedule` (the
    # generator could not even schedule the send) is what arbitrates. Dropping these on the floor here would
    # silently score EVERY shortfall as OFFER_SHORTFALL — a fail-closed void, but one that discards the
    # BACKPRESSURE_BIND finding the gate exists to produce.
    fidelity = rung_fidelity(
        sent=drive.sent,
        acked=drive.acked,
        offered=drive.offered,
        deferred_backpressure=drive.deferred_backpressure,
        deferred_schedule=drive.deferred_schedule,
    )
    fid_note = fidelity_note(
        fidelity,
        sent=drive.sent,
        acked=drive.acked,
        offered=drive.offered,
        deferred_backpressure=drive.deferred_backpressure,
        deferred_schedule=drive.deferred_schedule,
    )
    if fid_note is not None:
        notes.append(fid_note)
    # ARTIFACT 5: G < L is a SETUP condition that governs how this rung's ceiling must be read, so it rides
    # with the rung. (The engine half also notes it; this is the DRIVE-side, report-bearing copy.)
    if drive.inbound_band_narrower:
        notes.append(
            f"inbound bands G={drive.inbound_bands} < outbound lanes L={drive.dests}: the INGRESS/ROUTED "
            "per-lane pools are narrower than the outbound one, so this rung's intake ceiling may be an "
            "INGRESS ceiling — a destination sweep in this shape plateaus on the wrong pool"
        )
    return RungOutcome(
        index=rung.index,
        is_soak=rung.is_soak,
        ingress_rate=rung.ingress_rate,
        dests=drive.dests,
        handlers=drive.handlers,
        delivering=drive.delivering,
        # The mode rides WITH the accounting pair it qualifies — a rung recording (1, 1) without naming the
        # shape that produced it is unattributable (see RungOutcome.routing).
        routing=drive.routing,
        hold_seconds=rung.hold_seconds,
        offered=drive.offered,
        # ARTIFACT 4/5/2: the three inputs the rung record never carried — the drive's own `sent` (the
        # fidelity gate's other half), the inbound lane count (G), and the engine's pool evidence.
        sent=drive.sent,
        # The gate's shortfall discriminator, carried onto the record so the JSON is auditable and the
        # consolidated report can re-derive the verdict without re-reading the drive report.
        deferred_backpressure=drive.deferred_backpressure,
        deferred_schedule=drive.deferred_schedule,
        lanes_per_shard=drive.lanes,
        pool=pool,
        acked=drive.acked,
        sink_received=drive.sink_received,
        no_loss=drive.no_loss,
        lane_inversions=drive.lane_inversions,
        lane_repeats=drive.lane_repeats,
        lanes_observed=drive.lanes_observed,
        ack_p50_ms=drive.ack_p50_ms,
        ack_p99_ms=drive.ack_p99_ms,
        drive_drain_seconds=drive.drain_seconds,
        engine_reported=engine_reported,
        engine_ok=engine_ok,
        engine_drained=engine_drained,
        engine_stranded=engine_stranded,
        engine_dead_total=engine_dead_total,
        engine_ingress_stranded=engine_ingress_stranded,
        engine_routed_stranded=engine_routed_stranded,
        engine_outbound_stranded=engine_outbound_stranded,
        engine_in_pipeline_final=engine_in_pipeline_final,
        in_pipeline_slope=slope,
        phase=phase,
        claim=claim,
        episode=episode,
        engine_drain_seconds=engine_drain_seconds,
        verdict=verdict,
        notes=tuple(notes),
    )


def pick_soak_rate(records: Sequence[RungOutcome], override: float | None = None) -> float | None:
    """The soak rate: an explicit ``override`` if given, else the highest HONEST SUSTAINABLE rate any
    SUSTAINED climb rung actually proved (:attr:`RungOutcome.sustainable_ingress_rate`). ``None`` when
    nothing sustained (⇒ the ladder skips the soak and says so).

    B8: this used to select the rung's raw OFFERED ``ingress_rate``, which is not a sustainable rate. A climb
    rung is a VOLUME test — a SUSTAINED rung proves only that the fleet DELIVERED ``offered × delivering``
    within ``hold + drain``, never that it kept up at ``ingress_rate`` in real time. The offered rate
    overstates the honest one by ``(hold + drain) / hold`` (see :attr:`sustainable_ingress_rate`).

    Worse, ``max()`` over OFFERED rates selects the HIGHEST sustained rung — which is the rung with the
    LONGEST drain, i.e. the MOST overstated estimator on the whole ladder. The soak then offers a rate the
    fleet was never shown to sustain and collapses by construction. And a long soak amortizes the drain
    discount away (at ``hold=900`` the overstatement factor is ~1.03, not ~2.8), so nothing is left to hide
    it: the collapse looks real. Observed on the pooled ceiling re-run — offered climb pinned at 36/s while
    the honest rate sat flat at ~13/s across every rung, so the auto-picked 900s soak ran at ~2.8x
    sustainable. Selecting on the drain-discounted rate picks the operating point the climb actually proved.

    A rung whose drain was never measured yields ``None`` (an unmeasured span cannot denominate a rate) and
    is skipped. For a SUSTAINED rung the engine-side drain is guaranteed present, so this cannot silently
    empty the candidate set and turn a real ceiling into a skipped soak.

    ARTIFACT 4: a rung that FAILED FIDELITY is skipped too, for the same reason B8 skips an unmeasured drain
    — it is not a rate the fleet was shown to sustain. An under-driven rung's ``sustainable_ingress_rate`` is
    built from the OFFERED rate, so soaking it hands the fleet a rate nobody ever pushed; the soak would then
    collapse (or "hold") for reasons that have nothing to do with the engine. Same candidate set as
    :attr:`ConsolidatedLadderReport.pinned_rung`, so the soak still cannot exceed the published ceiling."""
    if override is not None:
        return override
    proved = [
        r.sustainable_ingress_rate
        for r in records
        if not r.is_soak and r.verdict is RungVerdict.SUSTAINED and r.fidelity_admissible
    ]
    measured = [rate for rate in proved if rate is not None]
    return max(measured) if measured else None


@dataclass
class ConsolidatedLadderReport:
    """The whole ladder's consolidated verdict — the ONE report the drive box emits. Per-rung records +
    the pinned ceiling (in BOTH ingress and outbound terms) + the soak + the phase split."""

    shards: tuple[str, ...]
    dests: int  # TOPOLOGY: shared outbound CONNECTIONS = sink port-band width. NOT the fan-out.
    handlers: int  # H: handlers the router SELECTED per (shard, lane). Cost model only.
    delivering: int  # D: destinations an accepted message delivered to. *** THE FAN-OUT ***
    driver_count: int
    sink_count: int
    #: ⭐ THE SHAPE THIS BANKED ARTIFACT MEASURED. `handlers`/`delivering` above are the DERIVED accounting
    #: pair, and `partitioned` derives (1, 1) — which a LEGAL broadcast run (`--dests 64 --handlers 1
    #: --delivering 1`) also writes, from a graph that funnels ALL traffic onto ONE strict-FIFO lane at
    #: ~16 msg/s instead of round-robining 64 lanes at ~800+. This is the report a 45M/day claim gets quoted
    #: from; without this key the claim is unattributable to its shape.
    routing: str = BROADCAST
    #: ARTIFACT 5: lanes-per-shard, learned from the drive report (which learned it from SHARDS_READY). With
    #: ``shards`` this gives ``G = len(shards) x lanes_per_shard`` — the INGRESS/ROUTED per-lane pool width,
    #: the OTHER pool the lane-scaling law applies to. It was computed on both boxes and recorded on neither,
    #: so a lane sweep that plateaued on the INBOUND pool was indistinguishable from an outbound/claim wall.
    lanes_per_shard: int = 1
    climb: list[RungOutcome] = field(default_factory=list)
    soak: RungOutcome | None = None
    notes: list[str] = field(default_factory=list)
    # The climb ended because a two-box RENDEZVOUS/timeout broke (a CoordTimeout in run_shardcert_drive),
    # NOT a clean collapse/exhaustion — an infrastructure failure, not a bench result. Drives exit_code 2
    # (setup/timeout) so an exit-code-gated harness never reads a mid-run infra death as a PASS.
    climb_aborted: bool = False
    # The SOAK-stage two-box rendezvous/timeout broke (a CoordTimeout in run_shardcert_drive's soak leg), so
    # the soak never produced a measurement — DISTINCT from a legitimately-skipped soak (no sustained rung,
    # which posts LADDER_SOAK {"skip": true}). Folded into setup_degraded (exit 2) so an aborted soak renders
    # ABORTED, never a clean PASS with soak=null (B2).
    soak_aborted: bool = False

    # --- derived measurements (the ceiling is a MEASUREMENT; only correctness fails the verdict) ---

    @property
    def all_records(self) -> list[RungOutcome]:
        return [*self.climb, *([self.soak] if self.soak is not None else [])]

    @property
    def txn_per_message(self) -> int:
        """The ADR 0051 durable-write cost of one ingress message on the SHAPE this ladder served:
        ``3 + 2H + 2D`` (mirrors :attr:`RungOutcome.txn_per_message` / :attr:`ShardCertShape`). The bench
        SELF-REPORTS this in ``render`` AND ``to_json_dict``; deriving both from one property keeps the
        rendered header and the JSON from drifting apart (a published figure disagreeing with its own JSON
        is the B1-B10 shape) when the #213 model — where ``2H`` becomes ``2·H_accepted`` — is folded in."""
        return 3 + 2 * self.handlers + 2 * self.delivering

    # --- ARTIFACT 5: the INBOUND pool, beside the outbound one ----------------------------------------

    @property
    def inbound_bands(self) -> int:
        """``G`` — the inbound MLLP bands the fleet exposed (``shards x lanes_per_shard``) = the width of the
        INGRESS and ROUTED hard-1 per-lane pools. ``dests`` (L) is the OUTBOUND width. The lane-scaling law
        applies to all THREE (``ingress ≈ G/cycle``, ``routed ≈ G/cycle``, ``outbound ≈ L/cycle``)."""
        return inbound_band_count(len(self.shards), self.lanes_per_shard)

    @property
    def inbound_band_narrower(self) -> bool:
        """``G < L`` — the INBOUND pool is the narrow one, so a destination/lane sweep on this run PLATEAUS
        on ingress and any ceiling it pins may be an INGRESS ceiling wearing an outbound costume. TRUE AT THE
        SHIPPED DEFAULTS (4 shards x 1 lane = 4 bands vs 8 dests) — which is why it is recorded and warned,
        not refused."""
        return self.dests > 0 and self.inbound_bands < self.dests

    # --- ARTIFACT 2: the store pool roll-up -----------------------------------------------------------

    @property
    def store_pool(self) -> PoolStats:
        """The pool the ladder ran on. Taken from the PINNED rung when there is one (the rung the headline is
        quoted from — its pool is the one that matters), else the first rung that measured a pool at all."""
        pinned = self.pinned_rung
        if pinned is not None and pinned.pool.measured:
            return pinned.pool
        for r in self.all_records:
            if r.pool.measured:
                return r.pool
        return self.climb[0].pool if self.climb else EMPTY_POOL_STATS

    @property
    def pool_tripped_rungs(self) -> list[float]:
        """The ingress rates whose rung TRIPPED the pre-registered pool tripwire — i.e. the rungs where the
        STORE POOL, not the claim query and not a lane, was the constraint. Non-empty ⇒ do not attribute this
        ladder's ceiling to anything else until the pool is widened and it is re-run."""
        return [r.ingress_rate for r in self.all_records if r.pool.tripped]

    @property
    def ceiling_pool_bound(self) -> bool:
        """⭐ **THE PUBLISHED CEILING IS A STORE-POOL BIND, NOT AN ENGINE ONE.** The rung the headline ceiling
        is quoted FROM (:attr:`pinned_rung`), or — absent a pin — the rung that BRACKETED it, tripped the
        pre-registered pool tripwire.

        The tripwire used to be ADVISORY ONLY: it appended a string to ``notes`` and a rate to
        ``store_pool.tripped_at_rates``, and then entered NO verdict, NO bracket, NO result token and NO exit
        code — ``pool_tripped_rungs`` was emitted to JSON and READ BY NOTHING. So a pool-bound ceiling still
        shipped as a confident, BRACKETED, ``result: PASS``, exit 0 — which is verbatim the failure the
        tripwire exists to prevent, because a pool bind is column-for-column identical to the pooled-claim
        wall it would otherwise be blamed on (and would have commissioned an engine rewrite against a BENCH
        ARTIFACT).

        The rung's NUMBER IS REAL, so this does not VOID it (unlike a fidelity void, where no rate was ever
        established). What it does is ATTRIBUTE THE RESOURCE: the ceiling is named as pool-bound in the
        headline and the ``result`` token, so it can never be quoted as *the engine's* ceiling. Raise
        ``--store-pool-size`` and re-run before attributing this ladder's wall to anything else."""
        # FAIL-SAFE, and deliberately so: ANY driven rung that tripped the tripwire taints the ceiling.
        #
        # v1 keyed on the PINNED rung (falling back to the bracketing one only when nothing pinned), and it
        # was INERT ON THE CASE THAT MATTERS. A pool bind does not announce itself on the rung it lets
        # through — it announces itself on the rung it BREAKS. Executed: a ladder that sustains 20/s on a
        # healthy pool and collapses at 40/s BECAUSE the store pool saturated reported pool tripped on
        # rung=[40.0], first_collapse=40.0, bracketed=True, ceiling_pool_bound=FALSE, result=PASS, exit 0 —
        # i.e. the pool's own wall, published as the ENGINE's ceiling. That is verbatim the failure this
        # tripwire exists to prevent (a pool bind is column-for-column identical to the pooled-claim wall,
        # and would have commissioned an engine rewrite against a BENCH ARTIFACT).
        #
        # `driven_climb` IS the measured region (the climb stops at the collapse), so a trip anywhere in it
        # means the pool was a LIVE CONSTRAINT on this measurement. Taint, don't void: the rate is real, it
        # just is not the ENGINE's. Raise --store-pool-size and re-run. A false taint costs one cheap re-run;
        # a missed one costs an engine rewrite.
        return any(r.pool.tripped for r in self.driven_climb)

    @property
    def ceiling_admissible(self) -> bool:
        """The published ceiling is EVIDENCE ABOUT THE ENGINE: a rate was pinned from a rung the engine
        actually held, AND the store pool was not the constraint at that rung. False ⇒ the number may exist,
        but it is not quotable as the engine's ceiling."""
        return self.pinned_ingress_rate is not None and not self.ceiling_pool_bound

    @property
    def admissible_climb(self) -> list[RungOutcome]:
        """The climb rungs that are EVIDENCE ABOUT THE ENGINE (ARTIFACT 4) — the only ones a ceiling may be
        pinned from. A rung that failed FIDELITY is VOID: a DRIVE SHORTFALL says the load generator could not
        push the plan (not an engine result at all) and an ENGINE INTAKE BIND says the engine refused it (a
        real finding, but a bind at INTAKE — not a sustainable rate). Both used to serialise as SUSTAINED and
        pin a ceiling that was a pure function of the plan."""
        return [r for r in self.climb if r.fidelity_admissible]

    @property
    def driven_climb(self) -> list[RungOutcome]:
        """⭐ The climb rungs whose OFFERED RATE WAS ESTABLISHED against the engine — the rungs that may
        BRACKET the ceiling. A SUPERSET of :attr:`admissible_climb`: it also holds the ENGINE-BOUND rungs
        (ENGINE_INTAKE_BIND / BACKPRESSURE_BIND), which may not PIN a ceiling but are REAL ENGINE FINDINGS
        at REAL rates.

        THE PIN AND THE BRACKET ARE DIFFERENT QUESTIONS. Pinning asks "what rate did the engine hold?" —
        only an admissible rung can answer. Bracketing asks "at what rate did it stop holding?" — and the
        answer to THAT is, by construction, a rung the engine failed: an engine saturating at R produces
        exactly ``acked < 0.95 x offered`` (the same shortfall ``_is_ceiling`` reads as a ceiling) and
        typically COLLAPSES at the same time. Bracketing on ``admissible`` threw that rung out and made the
        report announce "no ceiling reached — raise the ladder" on a run that had MEASURED A GENUINE
        COLLAPSE. Only a rung whose rate never reached the engine (DRIVE_SHORTFALL / OFFER_SHORTFALL /
        UNKNOWN) can neither pin nor bracket, because a bracket is a RATE and no rate was established.

        This is the same ``fidelity.driven`` split the CO-LOCATED ladder makes at its ceiling; the two
        callers now agree."""
        return [r for r in self.climb if r.fidelity_driven]

    @property
    def voided_climb(self) -> list[RungOutcome]:
        """The climb rungs excluded from PINNING the ceiling by the fidelity gate, in ladder order. NOTE
        this includes the ENGINE-BOUND rungs, which are real findings and DO still bracket — "void for the
        pin" is not "void for the bracket". :attr:`not_driven_climb` is the strictly-nothing-established set."""
        return [r for r in self.climb if not r.fidelity_admissible]

    @property
    def not_driven_climb(self) -> list[RungOutcome]:
        """The climb rungs that established NO RATE AT ALL (the offer never reached the engine, or we cannot
        say it did). These alone are void for BOTH the pin and the bracket."""
        return [r for r in self.climb if not r.fidelity_driven]

    @property
    def pinned_ingress_rate(self) -> float | None:
        """The pinned HONEST sustainable-ingress ceiling (D1): the highest per-rung
        ``sustainable_ingress_rate`` (offered spread over hold + MEASURED drain) over the SUSTAINED,
        FIDELITY-ADMISSIBLE climb rungs — NOT the raw offered ``ingress_rate``. The raw offered rate
        overstates the sustainable rate by ``(hold + drain) / hold`` because a SUSTAINED rung merely
        DELIVERED all offered messages within hold + drain; it never proved it KEPT UP at the offered rate. A
        floor if the climb never collapsed. ``None`` if no rung sustained (or none had a measured drain, or
        none was admissible).

        ⚠️ STILL OFFERED-DERIVED. Read it beside :attr:`pinned_accepted_ingress_rate`, which is built from
        what the engine ACTUALLY ACCEPTED. The fidelity gate now bounds the gap (an admissible rung accepted
        >= 95% of its offer), but it does not close it — and it closes it LEAST at the ceiling, which is
        exactly where offered and accepted diverge."""
        honest = [
            r.sustainable_ingress_rate
            for r in self.admissible_climb
            if r.verdict is RungVerdict.SUSTAINED and r.sustainable_ingress_rate is not None
        ]
        return max(honest) if honest else None

    @property
    def pinned_outbound_rate(self) -> float | None:
        """The pinned ceiling in DELIVERIES/s. Keyed on the fan-out ``delivering``, never on ``dests``
        (BACKLOG #209) — a destination CONNECTION no handler sends to carries no deliveries."""
        p = self.pinned_ingress_rate
        return None if p is None else p * self.delivering

    @property
    def pinned_rung(self) -> RungOutcome | None:
        """The SUSTAINED, FIDELITY-ADMISSIBLE climb rung whose HONEST ``sustainable_ingress_rate`` IS the
        pinned ceiling — the rung ``pinned_ingress_rate`` reports. ``None`` if nothing sustained with a
        measured drain and an admissible fidelity."""
        candidates = [
            r
            for r in self.admissible_climb
            if r.verdict is RungVerdict.SUSTAINED and r.sustainable_ingress_rate is not None
        ]
        if not candidates:
            return None
        return max(candidates, key=lambda r: r.sustainable_ingress_rate or 0.0)

    # --- ARTIFACT 3: the ACCEPTED-derived ceiling, carried all the way to the headline -----------------
    #
    # `sustainable_ingress_rate` (and therefore `pinned_ingress_rate`, `sustained_events_per_s`,
    # `publishable_events_per_s`, and the soak rate) is OFFERED-derived: `ingress_rate x hold / (hold +
    # drain)`. `acked` NEVER ENTERS IT. So if the drive cannot push the offered rate, the ladder still
    # reports a ceiling built from WHAT WE ASKED FOR. The accepted-derived siblings below are built from
    # what the engine ACTUALLY ACCEPTED over the same real span, and they are emitted BESIDE — never
    # instead of — the offered figures. The two standing side by side is the point.

    @property
    def pinned_accepted_ingress_rate(self) -> float | None:
        """The pinned rung's ACCEPTED-derived ingress (``A / (hold + drain)``) — the honest FLOOR under
        :attr:`pinned_ingress_rate`. ``None`` when nothing pinned or the drain was unmeasured.

        ⚠️ **THIS IS NOT THE UNDER-DRIVE DETECTOR — THE FIDELITY GATE IS.** It reads :attr:`pinned_rung`,
        which is drawn from :attr:`admissible_climb`, and admissible means ``acked >= 0.95 x offered`` BY
        DEFINITION. So the accepted/offered divergence observable HERE is bounded to ≤ 5%
        (:data:`~harness.load.shardcert.FIDELITY_ACKED_FLOOR`) BY CONSTRUCTION: this is a bounded honest
        REFINEMENT of the offered figure, not the instrument that catches an under-driven run. A run the rig
        could not drive is caught by ``fidelity`` (the rung goes VOID and never reaches this property at
        all). Read the divergence across ALL rungs — including void ones — via
        :attr:`max_accepted_vs_offered_gap`, which is where the real gap lives."""
        pinned = self.pinned_rung
        return None if pinned is None else pinned.accepted_ingress_rate

    @property
    def accepted_events_per_s(self) -> float | None:
        """The ACCEPTED-derived rate in TOTAL message events/s — the same ``x (1 + D)`` currency the 45M/day
        budget uses, so it can be read directly against :data:`TARGET_EVENTS_PER_S` beside the offered-derived
        :attr:`sustained_events_per_s`. Without this the accepted number was a passenger: it existed per rung
        and every headline still keyed off the offer."""
        p = self.pinned_accepted_ingress_rate
        return None if p is None else p * (1 + self.delivering)

    @property
    def clears_target_events_accepted(self) -> bool:
        """Whether the ACCEPTED-derived rate clears the raw 45M/day events target — the same gate as
        :attr:`clears_target_events`, on the honest floor rather than the offer."""
        e = self.accepted_events_per_s
        return e is not None and e >= TARGET_EVENTS_PER_S

    @property
    def accepted_vs_offered_ratio(self) -> float | None:
        """``accepted / offered`` at the pinned rung. 1.0 ⇒ the engine took everything the plan asked for and
        the two ceilings agree. Below 1.0 ⇒ the offered-derived ceiling overstates by exactly this much.
        ``None`` when nothing pinned.

        ⚠️ **BOUNDED BY CONSTRUCTION, AND THEREFORE NOT AN UNDER-DRIVE DETECTOR.** The pinned rung is
        FIDELITY-ADMISSIBLE, so ``acked >= 0.95 x offered`` and this ratio cannot fall below ~0.95 here (the
        drain term can only push it further DOWN toward that floor, never past what an admissible rung
        accepted). A >5% divergence is UNREACHABLE at the headline. Anyone reading this as "the gate that
        catches an under-driven run" is trusting a gate that cannot fire: that gate is ``fidelity``. See
        :attr:`max_accepted_vs_offered_gap` for the unbounded, all-rungs view."""
        offered = self.pinned_ingress_rate
        accepted = self.pinned_accepted_ingress_rate
        if offered is None or accepted is None or offered <= 0:
            return None
        return accepted / offered

    @property
    def max_accepted_vs_offered_gap(self) -> float | None:
        """The LARGEST ``1 - accepted/offered`` gap across EVERY climb rung — **including the FIDELITY-VOID
        ones**, which is where the real divergence lives (an under-driven rung's offered-derived rate is
        pure plan; its accepted-derived one is what happened). :attr:`accepted_vs_offered_ratio` is capped at
        the headline by the admissibility floor and so can never show this. ``None`` when no rung had both
        rates measured."""
        gaps = [
            1.0 - (r.accepted_ingress_rate / r.sustainable_ingress_rate)
            for r in self.climb
            if r.sustainable_ingress_rate is not None
            and r.sustainable_ingress_rate > 0
            and r.accepted_ingress_rate is not None
        ]
        return max(gaps) if gaps else None

    @property
    def pinned_measured_delivered_rate_per_s(self) -> float | None:
        """The pinned rung's HONEST MEASURED outbound delivery rate (D3) — socket-observed deliveries over
        the span-correct (phase-window) denominator, NOT ``sink_received / hold_seconds``. A cross-check on
        the ingress-derived ``pinned_outbound_rate``. ``None`` if nothing pinned or no phase windows."""
        pinned = self.pinned_rung
        return None if pinned is None else pinned.delivered_rate_per_s(len(self.shards))

    @property
    def first_collapse_ingress_rate(self) -> float | None:
        """The lowest ingress rate at a PROVEN store-truth COLLAPSE (brackets the ceiling from above).
        ``None`` if the climb never truly collapsed — then the pinned rate is a FLOOR (the true ceiling is
        above the top rung). Requires ``engine_reported`` so an INCONCLUSIVE rung (unconfirmed store-truth —
        a coord glitch) can NEVER fabricate a collapse bracket below the real ceiling.

        ⚠️ ALSO REQUIRES THAT THE RATE WAS ESTABLISHED (:attr:`driven_climb`). The fidelity gate was applied
        to :attr:`pinned_rung` and NOT here, so a rung nobody drove still set the bracket TOP — **at its
        OFFERED ingress_rate, a rate that was never driven** — a scored quantity that is a pure function of
        the PLAN.

        ⭐ BUT THE CANDIDATE SET IS ``driven_climb``, **NOT** ``admissible_climb`` — AND THAT DISTINCTION IS
        LOAD-BEARING IN THE OTHER DIRECTION. An earlier pass drew this from ``admissible_climb``, which
        EXCLUDES the engine-bound verdicts. But **an engine saturating at rate R is EXACTLY** ``acked <
        0.95 x offered`` — the project's own model of a ceiling (``_is_ceiling`` fires on that same
        shortfall) — so the top rung of a REAL saturation climb is normally BOTH ``COLLAPSED`` and
        ENGINE_INTAKE_BIND/BACKPRESSURE_BIND. Excluding it threw the genuine collapse out of the bracket and
        made the report print "no ceiling reached — raise the ladder" on a run that had MEASURED ONE. AN
        ENGINE BIND IS A FINDING, NOT A VOID: it keeps its rate label and brackets. Only a rung whose offer
        never reached the engine (DRIVE_SHORTFALL / OFFER_SHORTFALL / UNKNOWN) is excluded here.

        For those, the COLLAPSE ITSELF IS STILL REAL — the engine genuinely failed to drain — so it is not
        discarded: it is named in :attr:`void_collapse_notes` and flagged by :attr:`has_void_collapse`. What
        is fiction is the RATE LABEL on it, and only a rate can bracket a ceiling."""
        collapsed = [
            r.ingress_rate
            for r in self.driven_climb
            if r.verdict is RungVerdict.COLLAPSED and r.engine_reported
        ]
        return min(collapsed) if collapsed else None

    @property
    def void_collapsed_climb(self) -> list[RungOutcome]:
        """Climb rungs that COLLAPSED with confirmed store-truth but whose RATE WAS NEVER ESTABLISHED (not
        merely "not admissible" — an ENGINE-BOUND collapse IS driven, and it brackets). The collapse is a
        real engine event; its offered rate label is not a rate anything was driven at, so it cannot bracket
        the ceiling — but it must not vanish from the report either."""
        return [
            r
            for r in self.climb
            if r.verdict is RungVerdict.COLLAPSED and r.engine_reported and not r.fidelity_driven
        ]

    @property
    def has_void_collapse(self) -> bool:
        """A real collapse happened at a rate that was never driven — visible to the operator, and priced
        into NOTHING (not the bracket, not ``bracketed``)."""
        return bool(self.void_collapsed_climb)

    @property
    def void_collapse_notes(self) -> list[str]:
        """The operator-facing note for each :attr:`void_collapsed_climb` rung."""
        return [
            f"rung r{r.index} COLLAPSED at an OFFERED {r.ingress_rate:g}/s that was never driven "
            f"(sent={r.sent} of offered={r.offered}, {r.fidelity.value}) — THE COLLAPSE IS REAL, the RATE "
            "LABEL is fiction. It does NOT bracket the ceiling (a bracket is a RATE, and no rate was "
            "established here). Fix the rig and re-run before reading this as saturation."
            for r in self.void_collapsed_climb
        ]

    @property
    def ceiling_bracketed(self) -> bool:
        """A real ceiling was pinned (a sustained rung with a collapse above it), vs a floor-only climb
        (nothing collapsed ⇒ the ceiling is unpinned above the top rung — raise the ladder).

        The two sides have DIFFERENT admission bars, deliberately: the FLOOR is pinned only from a rung the
        engine actually HELD (:attr:`admissible_climb`), while the TOP is set by any rung whose RATE WAS
        ESTABLISHED and which then collapsed (:attr:`driven_climb`) — including an engine-bound one, which
        is what a real saturation looks like. A rung nobody drove can do NEITHER. ``bracketed`` reads "we
        pinned the ceiling from both sides", and it must mean it — in both directions."""
        return self.pinned_ingress_rate is not None and self.first_collapse_ingress_rate is not None

    @property
    def sustained_events_per_s(self) -> float | None:
        """The pinned SUSTAINED rate expressed in TOTAL message events/s — the currency the 45M/day budget
        is denominated in. One ingress message yields itself plus one event per DELIVERED copy: ``1 + D``.

        **This is the headline number the SYSTEM-REQUIREMENTS §8 decision keys off, so the multiplier has to
        be the fan-out.** ``1 + dests`` would overstate it by ``(1 + dests) / (1 + D)`` — 4.2x at the
        reference ADT hub (``dests=20, D=4``: 21 vs 5). That is harness defect B10 in the permissive
        direction, and it is why ``dests`` no longer means fan-out anywhere (BACKLOG #209)."""
        p = self.pinned_ingress_rate
        return None if p is None else p * (1 + self.delivering)

    @property
    def clears_target_events(self) -> bool:
        """Whether the pinned SUSTAINED **RAW** rate clears the 45M/day = ~521 TOTAL events/s target.

        ⚠️ **RAW, NOT PUBLISHABLE.** A publishable 45M/day CLAIM is HALF the measured raw ceiling (the
        Phase-5 D4 derate, :data:`PUBLISHABLE_DERATE`), so it needs a raw ~1041 events/s — TWICE what this
        property gates on. Use :attr:`clears_target_events_publishable` for a claim; this one is the raw
        measurement. Under BROADCAST the distinction was academic (the shape capped ingress at ~16 msg/s, so
        this gate could never trip); under PARTITIONED it trips at 260 ingress/s, half the ingress a claim
        actually requires — hence both are now reported.

        B10: this used to compare a pure ingress rate against the total-events budget, making the gate
        ``(1 + dests)``x too strict (9x at the bench default ``dests=8``). It now keys off
        :attr:`sustained_events_per_s`, i.e. ``ingress × (1 + delivering)``."""
        e = self.sustained_events_per_s
        return e is not None and e >= TARGET_EVENTS_PER_S

    @property
    def publishable_events_per_s(self) -> float | None:
        """The pinned rate AFTER the D4 derate — the number a 45M/day claim may actually be made on
        (``sustained_events_per_s × PUBLISHABLE_DERATE``). ``None`` when nothing pinned."""
        e = self.sustained_events_per_s
        return None if e is None else e * PUBLISHABLE_DERATE

    @property
    def clears_target_events_publishable(self) -> bool:
        """Whether the DERATED (publishable) rate clears the 45M/day target — **the bar a CLAIM must pass**.
        Equivalent to a RAW ceiling of ``TARGET_EVENTS_PER_S / PUBLISHABLE_DERATE`` ≈ 1041 events/s.

        ⚠️ Still OFFERED-derived (it derates :attr:`sustained_events_per_s`). Read it beside
        :attr:`clears_target_events_accepted_publishable`, the SAME bar on the honest floor — which is the
        one to quote, since a claim must not rest on the offer."""
        e = self.publishable_events_per_s
        return e is not None and e >= TARGET_EVENTS_PER_S

    @property
    def publishable_accepted_events_per_s(self) -> float | None:
        """ARTIFACT 3, carried into the CLAIM currency: the ACCEPTED-derived rate after the D4 derate — the
        number a 45M/day claim may be made on WITHOUT resting on the offer. The offered-derived
        :attr:`publishable_events_per_s` overstates it by up to the admissibility floor (~5%), and it does so
        LEAST forgivingly at the ceiling, which is exactly where a claim is quoted from."""
        e = self.accepted_events_per_s
        return None if e is None else e * PUBLISHABLE_DERATE

    @property
    def clears_target_events_accepted_publishable(self) -> bool:
        """**THE CLAIM BAR, ON THE HONEST FLOOR.** The derated ACCEPTED rate against the 45M/day target."""
        e = self.publishable_accepted_events_per_s
        return e is not None and e >= TARGET_EVENTS_PER_S

    # --- ARTIFACT 4 ON THE SOAK — the rung that CERTIFIES the ceiling ---------------------------------
    #
    # The fidelity gate shipped LIVE on the climb and DEAD on the soak: every roll-up iterated `self.climb`,
    # which EXCLUDES `self.soak`, and `soak_ok` gated on the verdict alone. `classify_rung`'s SUSTAINED arm
    # is the scale-free `no_loss` identity (S == A*D), so a soak whose engine accepted 80% of the offer — or
    # that the rig never drove at all — was SUSTAINED, `soak_ok` was True, and the run published a confident
    # HELD ceiling while `any_engine_intake_bind` read False. That is not a silent miss: it is an
    # AFFIRMATIVELY FALSE report field, produced by the gate built to prevent exactly it.
    #
    # This is the same LIVE-on-one-caller/DEAD-on-the-other shape as the `filling` gate — cited in this
    # file's own header as the precedent NOT to repeat, and then repeated one rung over. Two-box climb+soak
    # is the ONLY path STEP 4/5 runs.

    @property
    def soak_fidelity(self) -> RungFidelity | None:
        """The SOAK's fidelity to its own plan, or ``None`` when no soak ran."""
        return None if self.soak is None else self.soak.fidelity

    @property
    def soak_fidelity_admissible(self) -> bool:
        """The soak was actually DRIVEN at its rate and the engine TOOK it — the only condition under which
        "the operating point held" is a statement about the engine rather than a readback of the plan."""
        return self.soak is not None and self.soak.fidelity_admissible

    @property
    def soak_drive_shortfall(self) -> bool:
        """The soak's LOAD GENERATOR could not push the rate (``sent`` short). The long hold was never driven,
        so "it held" would be a readback of the plan — but a collapse would be a FABRICATION too. This is a
        RIG failure: it folds into :attr:`setup_degraded` (exit 2), NOT into :attr:`soak_not_sustained`."""
        return (
            self.soak is not None
            and not self.soak_aborted
            and self.soak.fidelity is RungFidelity.DRIVE_SHORTFALL
        )

    @property
    def soak_fidelity_unknown(self) -> bool:
        """The soak's fidelity inputs were never recorded (an older drive half / a synthetic record). Nothing
        was proven either way — FAIL-CLOSED (never a PASS), but never a fabricated negative either: it lands
        on the existing ``SOAK_UNCONFIRMED`` label, not on "did not hold"."""
        return (
            self.soak is not None
            and not self.soak_aborted
            and self.soak.fidelity is RungFidelity.UNKNOWN
        )

    @property
    def soak_offer_shortfall(self) -> bool:
        """⭐ FAIL-CLOSED: the soak's ``sent`` fell short and the DEFERRAL CAUSE WAS NOT RECORDED, so we
        CANNOT say whether the RIG ran out or the ENGINE applied backpressure. Those are OPPOSITE findings.

        Epistemically identical to :attr:`soak_fidelity_unknown` — nothing was proven either way — so it
        lands on the same ``SOAK_UNCONFIRMED`` label and is EXCLUDED from :attr:`soak_not_sustained`. Without
        this arm an unattributed soak fell through to "the operating point did NOT hold", FABRICATING A
        PROVEN NEGATIVE out of an unmeasured cause — the same fabrication class this file refuses everywhere
        else. It must also never default to DRIVE_SHORTFALL: we did not measure that."""
        return (
            self.soak is not None
            and not self.soak_aborted
            and self.soak.fidelity is RungFidelity.OFFER_SHORTFALL
        )

    @property
    def soak_fidelity_unattributed(self) -> bool:
        """The soak's fidelity was NOT ESTABLISHED — either the gate's inputs were unrecorded
        (:attr:`soak_fidelity_unknown`) or the shortfall's CAUSE was (:attr:`soak_offer_shortfall`). Both
        prove NOTHING: fail-closed to ``SOAK_UNCONFIRMED``, never a PASS and never a fabricated collapse."""
        return self.soak_fidelity_unknown or self.soak_offer_shortfall

    @property
    def soak_engine_intake_bind(self) -> bool:
        """The drive DID push the soak rate and the ENGINE would not accept it. A REAL product finding — the
        engine refused the operating point — so it must NOT set :attr:`soak_ok`, and it correctly reads as
        :attr:`soak_not_sustained`."""
        return (
            self.soak is not None
            and not self.soak_aborted
            and self.soak.fidelity is RungFidelity.ENGINE_INTAKE_BIND
        )

    @property
    def soak_backpressure_bind(self) -> bool:
        """⭐ The soak's ``sent`` fell short because THE ENGINE STOPPED READING ITS SOCKET (TCP backpressure
        throttled the drive). **AN ENGINE FINDING, NOT A RIG FAILURE** — the engine refused the operating
        point just as surely as an intake bind did, it simply refused it one layer lower.

        v1 would have called this a DRIVE SHORTFALL, folded it into :attr:`setup_degraded`, exited 2 and told
        the operator to buy drive boxes — discarding the finding. It belongs with
        :attr:`soak_engine_intake_bind`: NOT :attr:`soak_ok`, and a genuine :attr:`soak_not_sustained`."""
        return (
            self.soak is not None
            and not self.soak_aborted
            and self.soak.fidelity is RungFidelity.BACKPRESSURE_BIND
        )

    @property
    def soak_engine_bound(self) -> bool:
        """The soak was refused BY THE ENGINE — at intake (``acked`` short) or at the socket (``sent`` short
        through backpressure). Either way the operating point did not hold, and the finding is the ENGINE's."""
        return self.soak_engine_intake_bind or self.soak_backpressure_bind

    @property
    def soak_ok(self) -> bool:
        """The soak (if run) HELD by the two RELIABLE authorities — its verdict is SUSTAINED, which already
        encodes the engine store-truth (drained ∧ stranded==0 ∧ dead==0) AND the drive sink socket-truth
        (no_loss) — **AND it was FIDELITY-ADMISSIBLE** (ARTIFACT 4): the rig actually drove the rate and the
        engine actually took it. Without that term the SUSTAINED arm is scale-free, so an under-driven or
        short-taken soak certified a ceiling nobody ever offered the engine.

        The in_pipeline slope is REPORTED as advisory context (render's flat/GROWING label) but is NOT gated
        on (B5): the D4-de-inflated slope proved SIGN-UNSTABLE across rates and read False on runs passing
        both authorities. Saturation is instead caught by verdict==SUSTAINED requiring the backlog to DRAIN
        inside the bounded soak window (D2). No soak ⇒ vacuously False."""
        if self.soak is None:
            return False
        return self.soak.verdict is RungVerdict.SUSTAINED and self.soak.fidelity_admissible

    @property
    def correctness_ok(self) -> bool:
        """No driven rung had a FIFO inversion / duplicate, AND every rung whose FIFO evidence is
        LOAD-BEARING (a SUSTAINED rung — the ones that can be pinned) had non-vacuous FIFO evidence
        (``lanes_observed >= 2``). The ceiling/collapse is a throughput MEASUREMENT, not a verdict failure —
        so the non-vacuity gate is NOT applied to a COLLAPSED/FROZEN_TAIL rung (a near-zero-delivery collapse
        legitimately observes <2 lanes; failing the verdict on it would mislabel a throughput ceiling as a
        correctness break). Mirrors the single-box ShardCertLadderReport.ok, which never gates on lanes."""
        recs = self.all_records
        if not recs:
            return False
        if any(r.verdict is RungVerdict.CORRECTNESS_FAIL for r in recs):
            return False
        return all(r.lanes_observed >= 2 for r in recs if r.verdict is RungVerdict.SUSTAINED)

    @property
    def store_truth_unconfirmed(self) -> bool:
        """A CLIMB rung was INCONCLUSIVE — either its ENGINE store-truth never arrived (neither the
        ENGINE_DRAINED gate nor the ENGINE_RUNG_REPORT) OR the two independent observers were mutually
        inconsistent (A4b — the store-truth and the DRIVE sink count contradicted, or a required collector
        read zero on a non-zero-volume run). Like a rendezvous abort, either is a DEGRADATION, not a clean
        bench result — nothing was certified — so it must NOT read as a PASS. (A soak-only inconclusive is
        supplementary and does not trip this — the climb still pinned the ceiling.) The JSON key name is kept
        for schema_version 3 back-compat even though it now also covers the cross-observer cause."""
        return any(r.verdict is RungVerdict.INCONCLUSIVE for r in self.climb)

    @property
    def setup_degraded(self) -> bool:
        """The run hit a RIG/infra degradation (a climb OR soak rendezvous abort, an unconfirmed store-truth,
        or — ARTIFACT 4 — a SOAK the LOAD GENERATOR could not drive), NOT a clean measurement. Surfaced as
        exit 2 so an exit-code-gated harness never reads it as PASS.

        The soak DRIVE SHORTFALL belongs here and nowhere else: the rig failing to offer the rate is not a
        collapse, and scoring it as one would fabricate a product finding out of a load-generator limit —
        the precise conflation this gate exists to abolish, in the opposite direction.

        ⭐ ARTIFACT 2 adds the POOL: a ceiling measured on a rung that tripped the pre-registered store-pool
        tripwire is a RESOURCE bind, not an engine ceiling. It is a real number, so it is not voided — but it
        must not exit 0 as a clean PASS either, or the tripwire is decorative. :attr:`result_label` names it
        POOL_BOUND rather than folding it into the generic SETUP_DEGRADED token, because "the pool was the
        wall" is a specific and actionable finding (raise ``--store-pool-size`` and re-run)."""
        return (
            self.climb_aborted
            or self.soak_aborted
            or self.store_truth_unconfirmed
            or self.soak_drive_shortfall
            or self.ceiling_pool_bound
        )

    @property
    def soak_store_truth_unconfirmed(self) -> bool:
        """B9: a soak RAN, but its ENGINE store-truth never arrived (INCONCLUSIVE — neither the ENGINE_DRAINED
        gate nor the ENGINE_RUNG_REPORT). Nothing was proven about the soak either way: it is UNKNOWN, not
        proven-failed.

        Deliberately NOT folded into :attr:`setup_degraded`, because :attr:`store_truth_unconfirmed` already
        rules that "a soak-only inconclusive is supplementary ... the climb still pinned the ceiling" — so it
        stays exit 0. But it must not read as a PASS either, hence its own ``SOAK_UNCONFIRMED`` label.

        ARTIFACT 4 adds a SECOND way to prove nothing: a soak whose FIDELITY inputs were never recorded. Same
        epistemic state (UNKNOWN, not proven-failed), so it lands on the same label rather than fabricating a
        "did not hold".

        ⭐ v2 adds a THIRD: a soak whose ``sent`` fell short with the CAUSE UNRECORDED
        (:attr:`soak_offer_shortfall`). "The rig ran out" and "the engine applied backpressure" are opposite
        findings and an unattributed shortfall distinguishes NEITHER — so it proves nothing, exactly like the
        other two, and must not be scored as a collapse."""
        return (
            self.soak is not None
            and not self.soak_aborted
            and (self.soak.verdict is RungVerdict.INCONCLUSIVE or self.soak_fidelity_unattributed)
        )

    @property
    def soak_not_sustained(self) -> bool:
        """B9: a soak RAN, its store-truth WAS confirmed, and it did not hold — COLLAPSED or FROZEN_TAIL.

        Excluding INCONCLUSIVE is load-bearing, not defensive. Without it a soak whose engine store-truth
        never arrived (a coord glitch — ``classify_rung`` returns INCONCLUSIVE exactly when
        ``engine_reported`` is False) would be stamped "did NOT hold", fabricating a proven negative out of
        an unknown. That is the same fabrication class as B6/B7, and the codebase refuses it everywhere else:
        ``classify_rung`` will not score an unconfirmed rung COLLAPSED, and ``first_collapse_ingress_rate``
        requires ``engine_reported``. An unconfirmed soak is :attr:`soak_store_truth_unconfirmed`, not this.

        Distinct from :attr:`soak_aborted` (the soak never produced a measurement ⇒ ``setup_degraded`` ⇒
        exit 2) and from a legitimately SKIPPED soak (no sustained rung to soak). This one is a real PRODUCT
        signal: the offered operating point was not sustainable over the long hold.

        ARTIFACT 4 keeps that meaning EXACT by excluding the two non-product causes and INCLUDING the one
        product cause the verdict could not see:

        * a soak the RIG could not drive (:attr:`soak_drive_shortfall`) is EXCLUDED — it is a rig failure
          (``setup_degraded``, exit 2). Scoring it "did not hold" would fabricate a collapse from a load
          generator that never offered the load.
        * a soak whose fidelity was UNRECORDED (:attr:`soak_fidelity_unknown`) is EXCLUDED for the same
          reason INCONCLUSIVE is: it proves nothing (``SOAK_UNCONFIRMED``).
        * a soak whose shortfall CAUSE was unrecorded (:attr:`soak_offer_shortfall`) is EXCLUDED — v2. It is
          the same epistemic state as UNKNOWN (nothing proven), and scoring it "did not hold" would fabricate
          a proven negative out of a cause we did not measure.
        * a soak the drive DID push and the ENGINE would not take (:attr:`soak_engine_intake_bind`) is
          INCLUDED — it is a real product finding (the engine refused the operating point), and it used to
          serialise as SUSTAINED because the ``no_loss`` identity is scale-free.
        * ⭐ a soak the ENGINE throttled at the socket (:attr:`soak_backpressure_bind`) is INCLUDED — v2. The
          engine refused the operating point one layer lower; v1 called this a rig failure and voided it."""
        return (
            self.soak is not None
            and not self.soak_aborted
            and self.soak.verdict is not RungVerdict.INCONCLUSIVE
            and not self.soak_drive_shortfall
            and not self.soak_fidelity_unattributed
            and not self.soak_ok
        )

    @property
    def ok(self) -> bool:
        """Correctness held (the throughput ceiling is a measurement, not a pass/fail). A setup degradation
        is surfaced via ``exit_code`` (2), not by flipping ``ok``."""
        return self.correctness_ok

    @property
    def exit_code(self) -> int:
        """0 (correctness held) / 1 (a correctness break) / 2 (a setup degradation — a two-box rendezvous
        abort OR an unconfirmed store-truth — so a mid-run infra glitch or a nothing-certified run never
        reads as a PASS).

        **B9 — the exit code does NOT encode whether the soak sustained.** A collapsed 900s soak exits **0**,
        because a throughput ceiling is a MEASUREMENT, not a correctness verdict (see :attr:`ok`). That is
        deliberate, but it is a trap for an exit-code-gated harness: a run that saturated still exits 0.
        Automation that wants "did the offered operating point hold?" must read :attr:`soak_ok` /
        :attr:`soak_not_sustained` (or the ``result`` field, which no longer says ``PASS`` in that case) —
        never the exit code alone."""
        if self.setup_degraded:
            return 2
        return 0 if self.ok else 1

    @property
    def result_label(self) -> str:
        """The single-token result. B9: a run whose soak COLLAPSED used to report ``PASS`` (because ``ok``
        tracks correctness only), so the JSON headline of a saturating run read as a pass — alongside a
        ``pinned_ingress_rate`` taken from the 60s climb, which the soak had just disproved. Now:

        * ``SETUP_DEGRADED`` — not a bench result (exit 2). Includes (ARTIFACT 4) a soak the LOAD GENERATOR
          could not drive: the rig failed, which is not a collapse and must not fabricate one.
        * ``FAIL`` — a correctness break: FIFO inversion or duplicate delivery (exit 1).
        * ``SOAK_NOT_SUSTAINED`` — correctness held, and the soak's store-truth was CONFIRMED and did not
          hold (exit 0; a product measurement, not a correctness failure). **Do not quote this run's pinned
          ceiling** — it comes from the short climb, which this soak just disproved. Now also covers a soak
          the drive DID push and the ENGINE would not accept (an intake bind — a real refusal of the
          operating point, which the scale-free ``no_loss`` verdict scored as SUSTAINED).
        * ``SOAK_UNCONFIRMED`` — correctness held, but nothing was proven about the soak (exit 0): its
          store-truth never arrived, or its FIDELITY inputs were never recorded. Re-run it. Neither a pass
          nor a proven saturation.
        * ``POOL_BOUND`` — correctness held and a rate WAS measured, but the rung the headline ceiling comes
          from TRIPPED the pre-registered store-pool tripwire (exit 2). The number is real; **it is not the
          ENGINE's ceiling** — it is the pool's. Called out by name rather than folded into SETUP_DEGRADED
          because it is specific and actionable: raise ``--store-pool-size`` and re-run. Before this token
          existed, a pool-bound ceiling shipped as a confident, bracketed ``PASS`` at exit 0, which is
          exactly the artifact the tripwire was built to stop (a pool bind is indistinguishable, column for
          column, from the pooled-claim wall it would have been blamed on).
        * ``PASS`` — correctness held, and the soak either sustained (DRIVEN, and the engine took it) or was
          legitimately skipped."""
        if self.setup_degraded:
            # POOL_BOUND is NAMED rather than flattened into SETUP_DEGRADED — but only when it is the SOLE
            # degradation. An abort / unconfirmed store-truth / un-driven soak means NOTHING was measured,
            # and that dominates: attributing a ceiling to the pool on a run that never produced one would
            # be a fabrication of exactly the kind this gate exists to stop.
            nothing_measured = (
                self.climb_aborted
                or self.soak_aborted
                or self.store_truth_unconfirmed
                or self.soak_drive_shortfall
            )
            return "SETUP_DEGRADED" if nothing_measured else "POOL_BOUND"
        if not self.ok:
            return "FAIL"
        if self.soak_not_sustained:
            return "SOAK_NOT_SUSTAINED"
        if self.soak_store_truth_unconfirmed:
            return "SOAK_UNCONFIRMED"
        return "PASS"

    def render(self) -> str:
        lines = [
            "ShardCert two-box SIZING ladder — pin the post-#842 delivered ceiling vs the 521/s "
            "TOTAL-EVENTS target (45M/day, inbound + outbound)",
            f"  topology: shards={'/'.join(self.shards)} dests={self.dests} conns  "
            f"routing={self.routing}  "
            f"H={self.handlers} selected, D={self.delivering} delivering  "
            f"K={self.driver_count} senders x M={self.sink_count} sinks",
            f"    (delivered = ingress x D; total events = ingress x (1 + D); "
            f"txn/msg = 3 + 2H + 2D = {self.txn_per_message})",
            # ARTIFACT 5: the THREE pools, stated. ingress ~= G/cycle, routed ~= G/cycle, outbound ~= L/cycle.
            f"    pools: G={self.inbound_bands} inbound bands ({len(self.shards)} shards x "
            f"{self.lanes_per_shard} lanes) vs L={self.dests} outbound lanes"
            + (
                "   <= INBOUND IS THE NARROW POOL: a lane/destination sweep here plateaus on INGRESS"
                if self.inbound_band_narrower
                else ""
            ),
            # ARTIFACT 2: the pool this ceiling was measured on, and whether it was the constraint.
            f"    {self.store_pool.render()}",
            "",
            "  climb (ascending ingress rate; stops at the first collapse):",
        ]
        for r in self.climb:
            lines.append("    " + r.render())
        lines.append("")
        # ARTIFACT 4: the fidelity roll-up, ABOVE the ceiling — because if the climb was not driven, the
        # ceiling below it is a readback of the plan and must not be read first.
        voided = self.voided_climb
        if voided:
            lines.append(
                f"  ⚠ FIDELITY: {len(voided)} of {len(self.climb)} climb rung(s) VOID for the ceiling "
                "(not evidence about the engine):"
            )
            for r in voided:
                lines.append(
                    f"    r{r.index} @ {r.ingress_rate:g}/s: {r.fidelity.value.upper()} "
                    f"(offered={r.offered} sent={r.sent} acked={r.acked})"
                )
            lines.append("")
        # A REAL collapse at a rate nobody drove: shown, and priced into NOTHING (not the bracket, not
        # `bracketed`). The collapse is an engine event; its offered rate label is a plan number.
        for note in self.void_collapse_notes:
            lines.append(f"  ⚠ {note}")
        if self.void_collapse_notes:
            lines.append("")
        pin = self.pinned_ingress_rate
        if pin is None:
            lines.append(
                "  pinned ceiling: NONE — no rung sustained (lower the start rate / check setup)"
            )
        else:
            out = self.pinned_outbound_rate or 0.0
            pinned = self.pinned_rung
            pin_drain = None if pinned is None else pinned.rate_drain_seconds
            honest_ctx = (
                ""
                if pinned is None or pin_drain is None
                else (
                    f"  [honest: offered {pinned.ingress_rate:g}/s over hold {pinned.hold_seconds:g}s "
                    f"+ measured drain {pin_drain:.1f}s]"
                )
            )
            lines.append(
                f"  pinned sustainable ceiling: {pin:g} ingress/s = {out:g} outbound/s"
                + (
                    ""
                    if self.ceiling_bracketed
                    else "  (FLOOR — climb never collapsed; raise the ladder)"
                )
                + honest_ctx
            )
            # ⭐ ARTIFACT 2: the RESOURCE ATTRIBUTION, printed against the number itself — not buried in a
            # note. A pool bind is column-for-column identical to the pooled-claim wall, so a ceiling whose
            # own rung exhausted the store pool must never be readable as THE ENGINE'S ceiling.
            if self.ceiling_pool_bound:
                lines.append(
                    "    ⚠ POOL-BOUND CEILING — NOT AN ENGINE CEILING: the rung this number is quoted from "
                    f"TRIPPED the pre-registered store-pool tripwire (pool size "
                    f"{self.store_pool.requested}, product default {PRODUCT_STORE_POOL_SIZE}). The STORE "
                    "POOL was the constraint, not the claim query and not a lane — and a pool bind looks "
                    "identical to a pooled-claim wall in every column. The rate above is REAL, but it is "
                    "the POOL's wall: do NOT quote it as the engine's. Raise --store-pool-size and re-run."
                )
            # ARTIFACT 3: the ACCEPTED-derived ceiling, printed directly beneath its offered-derived twin.
            # The offered figure is `ingress_rate x hold/(hold+drain)` and `acked` never enters it; this one
            # is `A / (hold+drain)`. When they diverge, the run was under-driven (or the engine short-took)
            # and the number above is fiction.
            acc = self.pinned_accepted_ingress_rate
            if acc is None:
                lines.append(
                    "    accepted-derived ceiling: (none — no drain measured, so no honest span)"
                )
            else:
                ratio = self.accepted_vs_offered_ratio
                # HONEST BANNER: this ratio is BOUNDED BELOW by the admissibility floor (the pinned rung
                # accepted >= 95% of its offer by definition), so it is a <=5% REFINEMENT of the offered
                # figure — NOT the under-drive detector. That detector is the FIDELITY block above. Saying
                # otherwise would point an operator at a gate that cannot fire.
                gap = (
                    ""
                    if ratio is None
                    else f"  [accepted/offered = {ratio:.1%}"
                    + (
                        ""
                        if ratio >= 0.99
                        else f" — the offered figure above OVERSTATES THIS RUN by {1 - ratio:.1%} "
                        f"(bounded by the {FIDELITY_ACKED_FLOOR:.0%} admissibility floor; "
                        "the UNDER-DRIVE detector is the FIDELITY gate, not this ratio)"
                    )
                    + "]"
                )
                acc_ev = self.accepted_events_per_s or 0.0
                lines.append(
                    f"    accepted-derived ceiling (from acked, NOT offered): {acc:g} ingress/s "
                    f"= {acc_ev:g} events/s{gap}"
                )
            worst = self.max_accepted_vs_offered_gap
            if worst is not None and worst > 0.01:
                # ACROSS ALL RUNGS, void ones included — where the real divergence lives. The headline ratio
                # above cannot show this, by construction.
                lines.append(
                    f"    worst accepted-vs-offered gap across the WHOLE climb (void rungs included): "
                    f"{worst:.1%}"
                )
            fc = self.first_collapse_ingress_rate
            if fc is not None:
                lines.append(
                    f"    first collapse at: {fc:g} ingress/s = {fc * self.delivering:g} outbound/s"
                )
            ev = self.sustained_events_per_s
            lines.append(
                f"    clears {TARGET_EVENTS_PER_S:.1f}/s TOTAL-EVENTS target? "
                f"{'YES' if self.clears_target_events else 'NO'} "
                f"({pin:g} ingress/s x (1 + {self.delivering} delivering) = {ev:g} events/s "
                f"vs {TARGET_EVENTS_PER_S:.1f} events/s)"
            )
        lines.append("")
        if self.soak is not None:
            slope = self.soak.in_pipeline_slope
            slope_txt = "n/a" if slope is None else f"{slope:+.2f} rows/s"
            drain = (
                "flat/draining"
                if slope_is_draining(slope)
                else "GROWING (slow saturation)"
                if slope is not None
                else "unknown (no trace)"
            )
            # ARTIFACT 4: the soak line is a custom f-string, NOT `RungOutcome.render()` — which is exactly
            # how it shipped without the `[VOID: …]` tag every climb rung got. The tag is appended here.
            soak_fid = (
                ""
                if self.soak.fidelity is RungFidelity.ADMISSIBLE
                else f"  [VOID: {self.soak.fidelity.value.upper()} — offered={self.soak.offered} "
                f"sent={self.soak.sent} acked={self.soak.acked}]"
            )
            lines.append(
                f"  soak ({self.soak.hold_seconds:g}s @ {self.soak.ingress_rate:g} ingress/s): "
                f"{self.soak.verdict.value.upper()}  in_pipeline slope={slope_txt} ({drain})  "
                f"-> soak_ok={self.soak_ok}{soak_fid}"
            )
            lines.append("    " + self.soak.phase.render())
        elif self.soak_aborted:
            lines.append(
                "  soak: ABORTED (two-box rendezvous/timeout broke during the soak — NOT a bench result)"
            )
        else:
            lines.append("  soak: (skipped — no sustained rung to soak)")
        lines.append("")
        lines.append("  per-rung phase timing (send_ack vs mark_done, n-weighted):")
        n_shards = len(self.shards)
        for r in self.all_records:
            tag = "soak" if r.is_soak else f"r{r.index}"
            dr = r.delivered_rate_per_s(n_shards)  # D3: span-correct MEASURED delivered rate
            dr_txt = "" if dr is None else f"  measured delivered={dr:g}/s (span-correct)"
            lines.append(f"    {tag:5} {r.phase.render()}{dr_txt}")
        lines.append(
            "  per-rung claim timing (store-claim round-trip #842 could not see, n-weighted):"
        )
        for r in self.all_records:
            tag = "soak" if r.is_soak else f"r{r.index}"
            lines.append(f"    {tag:5} {r.claim.render()}")
        for note in self.notes:
            lines.append(f"  note: {note}")
        lines.append("")
        if self.result_label == "POOL_BOUND":
            # A real measurement whose RESOURCE is named — deliberately NOT the SETUP-DEGRADED wording
            # below, which says "nothing was measured". Something WAS measured; the pool owns it.
            lines.append(
                f"RESULT: POOL-BOUND CEILING (the store pool was the constraint at the pinned rung — a "
                f"RESOURCE bind, NOT the engine's ceiling; raise --store-pool-size and re-run) "
                f"-> exit {self.exit_code}"
            )
        elif self.setup_degraded:
            if self.climb_aborted:
                reason = "two-box rendezvous/timeout broke mid-run"
            elif self.soak_aborted:
                reason = "two-box rendezvous/timeout broke during the soak — soak not measured"
            elif self.soak_drive_shortfall and self.soak is not None:
                # THE RIG failed, not the engine. Do NOT render this as a collapse.
                reason = (
                    f"the SOAK was never DRIVEN: the load generator sent {self.soak.sent} of "
                    f"{self.soak.offered} offered at {self.soak.ingress_rate:g}/s. 'The operating point "
                    "held' would be a readback of the plan, and 'it collapsed' would be a fabrication — "
                    "so this run certifies NOTHING. Add sender workers / drive boxes and re-run"
                )
            else:
                reason = (
                    "a climb rung was INCONCLUSIVE (engine store-truth never confirmed, or the two "
                    "observers were inconsistent) — nothing certified"
                )
            lines.append(
                f"RESULT: SETUP-DEGRADED ({reason} — NOT a bench result) -> exit {self.exit_code}"
            )
        else:
            lines.append(
                f"RESULT: {'PASS' if self.ok else 'FAIL'} (correctness) -> exit {self.exit_code}"
            )
            if self.soak_not_sustained and self.soak is not None:
                # B9: exit stays 0 (throughput is a measurement) — but say so loudly, because the JSON
                # headline and the climb-derived pinned ceiling both otherwise read as a clean pass.
                cause = (
                    " [ENGINE INTAKE BIND: the drive PUSHED it (sent="
                    f"{self.soak.sent} of {self.soak.offered}) and the engine accepted only "
                    f"{self.soak.acked} — the engine REFUSED the operating point]"
                    if self.soak_engine_intake_bind
                    # v2: the ENGINE refused it at the SOCKET. Named as an engine finding, because v1 would
                    # have called this exact signature a rig failure and sent the operator to buy hardware.
                    else (
                        " [ENGINE BACKPRESSURE BIND: the engine STOPPED READING ITS SOCKET, so TCP "
                        f"backpressure throttled the drive to sent={self.soak.sent} of "
                        f"{self.soak.offered} (deferred: backpressure="
                        f"{self.soak.deferred_backpressure} schedule={self.soak.deferred_schedule}) — an "
                        "ENGINE refusal of the operating point, NOT a rig shortfall]"
                    )
                    if self.soak_backpressure_bind
                    else ""
                )
                lines.append(
                    f"        SOAK NOT SUSTAINED (soak verdict={self.soak.verdict.value} @ "
                    f"{self.soak.ingress_rate:g}/s ingress over {self.soak.hold_seconds:g}s){cause} — the "
                    "offered operating point did NOT hold. Do not quote this run's pinned ceiling."
                )
            elif self.soak_store_truth_unconfirmed and self.soak is not None:
                # NOT "did not hold" — nothing was proven either way. Asserting a negative here would be the
                # same fabrication B6/B7 were about.
                why = (
                    "its FIDELITY inputs were never recorded"
                    if self.soak_fidelity_unknown
                    # v2 FAIL-CLOSED: the shortfall is REAL but its CAUSE is not attributed. Say exactly
                    # that — do NOT guess, and above all do not default to blaming the rig.
                    else (
                        f"the drive sent only {self.soak.sent} of {self.soak.offered} offered and the "
                        "DEFERRAL CAUSE WAS NOT RECORDED — we cannot say whether THE RIG ran out or THE "
                        "ENGINE applied backpressure, and those are OPPOSITE findings"
                    )
                    if self.soak_offer_shortfall
                    else "store-truth never arrived"
                )
                lines.append(
                    f"        SOAK UNCONFIRMED ({why} @ {self.soak.ingress_rate:g}/s "
                    f"ingress over {self.soak.hold_seconds:g}s) — the soak proved NOTHING either way; "
                    "re-run it. The climb still pinned the ceiling."
                )
        return "\n".join(lines)

    def to_json_dict(self) -> dict[str, object]:
        return {
            # v2 (B9): `result` gained SOAK_NOT_SUSTAINED + SOAK_UNCONFIRMED, and the two booleans below are
            # new. A collapsed soak used to serialize as "PASS". `exit_code` is unchanged (0 — a throughput
            # ceiling is a measurement, not a correctness verdict), so gate automation on `result`, not exit.
            #
            # v3 (B10): the 45M/day target is TOTAL message events/s (in + out), not ingress/s. The keys
            # `target_ingress_per_s` and `ceiling.clears_target_ingress` are REMOVED, not redefined — a
            # boolean whose meaning silently flipped is exactly this harness's signature defect, so a stale
            # consumer must KeyError rather than branch on a wrong-but-plausible value. Replacements:
            # `target_events_per_s`, `ceiling.sustained_events_per_s`, `ceiling.clears_target_events`.
            #
            # v4 (BACKLOG #209): `topology.dests` STOPPED meaning the fan-out — it is now the count of shared
            # outbound destination CONNECTIONS. The fan-out is `topology.delivering` (D) and the router's
            # selection width is `topology.handlers` (H). Every delivery figure below (pinned_outbound_rate,
            # sustained_events_per_s, each rung's outbound_expected) keys off D. A pre-v4 consumer that reads
            # `dests` and multiplies by it will OVERSTATE deliveries on any H != D run — hence the bump: the
            # version is the only thing that tells it the multiplier moved.
            #
            # v5 (PARTITIONED routing). THREE things moved, and this is THE banked artifact a 45M/day claim
            # is quoted from:
            #  * `topology.routing` is NEW and names the shape. Under `partitioned`, handlers/delivering are
            #    the DERIVED accounting pair (1, 1) while the graph BUILT H = D = dests — and (1, 1) is also
            #    what a LEGAL broadcast `--handlers 1 --delivering 1` run writes, from a ~50x slower graph.
            #    Do NOT read handlers/delivering without reading routing.
            #  * `ceiling.clears_target_events` is explicitly the RAW gate; `clears_target_events_publishable`
            #    (new) applies the D4 half-derate and is the bar a CLAIM must pass. The raw gate could never
            #    trip under broadcast (the shape capped ingress at ~16/s), so nobody was misled before.
            #  * each rung's `lanes_observed` is now the UNION of the sinks' lane-key sets, not a MAX.
            #
            # v6 (THE FOUR BENCH ARTIFACTS, 2026-07-14). ⚠️ **MOSTLY ADDITIVE, WITH ONE DELIBERATE
            # REDEFINITION** — do NOT diff a v6 run against a v5 one on the ceiling keys.
            #
            # THE REDEFINITION: the ceiling is now pinned ONLY from FIDELITY-ADMISSIBLE rungs (rungs the rig
            # actually DROVE and the engine actually TOOK), on BOTH sides — the floor (`pinned_rung`) and the
            # upper bracket (`first_collapse_ingress_rate`). A v5 ceiling may have been pinned from, or
            # bracketed by, a rung that was NEVER DRIVEN, so these keys are NOT directly comparable across
            # the bump:
            #     ceiling.pinned_ingress_rate, ceiling.pinned_accepted_ingress_rate,
            #     ceiling.pinned_outbound_rate, ceiling.pinned_measured_delivered_rate_per_s,
            #     ceiling.first_collapse_ingress_rate, ceiling.bracketed,
            #     ceiling.sustained_events_per_s, ceiling.publishable_events_per_s,
            #     ceiling.clears_target_events, ceiling.clears_target_events_publishable
            # `soak_ok` / `soak_not_sustained` / `result` also gained a FIDELITY term (see below), so their
            # meaning is likewise narrowed — correctly, and NOT comparably. Everything else is additive.
            #
            # WHAT IS ADDED — four things that could each MANUFACTURE A FAKE CEILING, now recorded, so a
            # run's ceiling is auditable from its own artifact:
            #  * `store_pool` (+ per-rung `store_pool`) — the EFFECTIVE MEFOR_STORE_POOL_SIZE, which NOW
            #    DEFAULTS TO THE PRODUCT 40 (it was pinned at 8 by a bare `setdefault`, recorded nowhere) —
            #    plus the acquire_wait saturation evidence and a PRE-REGISTERED TRIPWIRE. ⚠️ THE DEFAULT
            #    MOVED: a v6 run's fleet is NOT configured like a v5 run's. That is deliberate and loud.
            #  * `ceiling.pinned_accepted_*` / `accepted_events_per_s` / `publishable_accepted_events_per_s`
            #    — the ACCEPTED-derived ceiling carried to the HEADLINE and into the CLAIM currency.
            #    `pinned_ingress_rate` is still offered-derived (Σ-n busy-time exact); it is now READ BESIDE
            #    the figure built from what the engine actually took. NOTE: at the headline that gap is
            #    BOUNDED to <= 5% by the admissibility floor — it is a refinement, NOT the under-drive
            #    detector. The under-drive detector is `fidelity`. `max_accepted_vs_offered_gap` (all rungs,
            #    void ones included) is where a real divergence shows.
            #  * `fidelity` (+ per-rung, + the SOAK) — the pre-registered gate: sent >= 98% and acked >= 95%
            #    of offered. A rung failing it is VOID FOR THE CEILING. A DRIVE SHORTFALL and an ENGINE
            #    INTAKE BIND used to serialise identically, as SUSTAINED. The roll-up covers the SOAK too:
            #    an un-driven soak used to certify a held ceiling with `any_drive_shortfall: false`.
            #  * `topology.inbound_bands` (G) — the INGRESS/ROUTED pool width beside `dests` (L, the outbound
            #    one). At G < L (TRUE AT THE SHIPPED DEFAULTS) a sweep plateaus on the INBOUND pool. The
            #    check is COUNT-only: `inbound_band_check_basis` says what a clean verdict does NOT exclude.
            #
            # v7 (THE TWO REVIEW BLOCKERS, 2026-07-14) — ADDITIVE keys, but TWO SCORING FIXES that CHANGE
            # `ceiling.first_collapse_ingress_rate`, `ceiling.bracketed`, `result` and `exit_code` on
            # affected runs. Do NOT diff a v7 run against a v6 one on those keys.
            #
            #  (1) THE BRACKET NOW ADMITS ENGINE-BOUND RUNGS. v6 drew `first_collapse_ingress_rate` from
            #      `admissible_climb`, which EXCLUDES the engine-bind verdicts — but an engine saturating at
            #      R is EXACTLY `acked < 0.95 x offered` (the same shortfall `_is_ceiling` calls a ceiling),
            #      so the top rung of a REAL saturation climb was thrown out of its own bracket and v6
            #      reported "no ceiling reached — raise the ladder" on a run that MEASURED THE COLLAPSE. An
            #      ENGINE BIND IS A FINDING, NOT A VOID. The bracket now draws from `driven_climb` (the rate
            #      reached the engine, or the engine refused to read it); only DRIVE_SHORTFALL /
            #      OFFER_SHORTFALL / UNKNOWN — where NO rate was established — still void it. The PIN is
            #      unchanged (`admissible_climb`): only a rung the engine HELD may pin. New keys:
            #      `ceiling.bracket_basis`, per-rung `fidelity_driven`.
            #  (2) THE POOL TRIPWIRE NOW TAINTS THE VERDICT. In v6 `pool.tripped` appended a note and built
            #      `store_pool.tripped_at_rates` — emitted to JSON and READ BY NOTHING. It entered no
            #      verdict, no bracket, no result token and no exit code, so a POOL-BOUND ceiling shipped as
            #      a confident, bracketed `result: PASS`, exit 0 — verbatim the artifact the tripwire exists
            #      to prevent (a pool bind is column-for-column identical to the pooled-claim wall). It now
            #      names the RESOURCE: `ceiling.pool_bound` / `ceiling.admissible`, `result: POOL_BOUND`,
            #      exit 2. The RATE IS STILL PUBLISHED — the number is real — it simply may never be quoted
            #      as the ENGINE's ceiling.
            #  (3) `fidelity` gate v2 — the `sent`-shortfall arm is CAUSE-SPLIT (new per-rung
            #      `deferred_backpressure` / `deferred_schedule` / `sent_ratio`). ⚠️ NARROWING: a v6
            #      `drive_shortfall` verdict is a v7 `backpressure_bind` (AN ENGINE FINDING), `drive_shortfall`
            #      or `offer_shortfall` (cause unattributed). v6 called EVERY sent shortfall a rig failure —
            #      but `sent` is ENGINE-PACED, so v6 would void a real engine bind and send the operator to
            #      buy drive boxes.
            #
            # v8 (BACKLOG #229) — ADDITIVE, and the ONE scoring change bites ONLY at H > D (the ADT-hub shape
            # #209 enabled, never yet run on the rig), so NO published run (all H == D) is affected. The A4b
            # cross-observer permit (`observers_inconclusive`) stopped charging strands STAGE-BLIND: each
            # per-rung `engine` block now carries `ingress_stranded` / `routed_stranded` / `outbound_stranded`
            # (the delivery-blocking rows split by pipeline stage), and the under-counting branch charges an
            # ingress strand D copies, an outbound strand 1, a routed strand [0,1] (crediting the
            # non-delivering-handler `free` budget against ROUTED strands only). At H == D or when the split is
            # absent (an older engine payload → a `< 0` sentinel) the permit is byte-identical to v7.
            "schema_version": 8,
            "kind": "shardcert_ladder_two_box",
            "result": self.result_label,
            "exit_code": self.exit_code,
            "climb_aborted": self.climb_aborted,
            "soak_aborted": self.soak_aborted,
            "soak_not_sustained": self.soak_not_sustained,
            "soak_store_truth_unconfirmed": self.soak_store_truth_unconfirmed,
            "store_truth_unconfirmed": self.store_truth_unconfirmed,
            "topology": {
                "shards": list(self.shards),
                "dests": self.dests,  # destination CONNECTIONS (port-band width) — NOT the fan-out
                "handlers": self.handlers,  # H: router selection width (cost model only)
                "delivering": self.delivering,  # D: THE fan-out — every delivery figure keys off this
                # broadcast | partitioned. REQUIRED to interpret handlers/delivering (see the v5 note).
                "routing": self.routing,
                "txn_per_message": self.txn_per_message,  # ADR 0051 (3 + 2H + 2D)
                "events_per_message": 1 + self.delivering,
                "driver_count": self.driver_count,
                "sink_count": self.sink_count,
                # v6 (ARTIFACT 5): G — the INGRESS/ROUTED per-lane pool width — beside `dests` (L, the
                # OUTBOUND one). The lane-scaling law applies to all THREE pools. At G < L the INBOUND side
                # is the narrow one, so a lane/destination sweep PLATEAUS on ingress and manufactures what
                # reads, column for column, as an outbound/pooled-claim wall. TRUE AT THE SHIPPED DEFAULTS.
                "lanes_per_shard": self.lanes_per_shard,
                "inbound_bands": self.inbound_bands,
                "inbound_bands_narrower_than_dests": self.inbound_band_narrower,
                # WHAT A CLEAN (G >= L) VERDICT DOES NOT SAY. The check compares lane COUNTS, and the three-
                # pool law assumes ONE cycle — which it is not: the ingress cycle is strictly heavier. So
                # `inbound_bands_narrower_than_dests: false` excludes a COUNT asymmetry and nothing more.
                "inbound_band_check_basis": INBOUND_BAND_CHECK_BASIS,
            },
            # v6 (ARTIFACT 2): the pool the pinned ceiling was measured on, its acquire_wait evidence, and
            # the PRE-REGISTERED TRIPWIRE. A pool bind is indistinguishable from the pooled-claim wall in
            # every column we have ever looked at; this block is the discriminator. `tripped_at_rates`
            # non-empty ⇒ the STORE POOL was the constraint, and this ladder's ceiling attributes to it.
            "store_pool": {
                **self.store_pool.to_json_dict(),
                "product_default": PRODUCT_STORE_POOL_SIZE,
                "tripped_at_rates": self.pool_tripped_rungs,
            },
            # v6 (ARTIFACT 4): the fidelity roll-up.
            #
            # ⚠️ IT ITERATES `all_records` — **INCLUDING THE SOAK**. Every one of these keys used to iterate
            # `self.climb`, which EXCLUDES the soak: the one rung whose job is to CERTIFY the ceiling. An
            # un-driven soak therefore produced `all_admissible: true`, `void_rungs: []` and
            # `any_drive_shortfall: false` — affirmatively FALSE values, emitted by the gate built to
            # prevent exactly that, on a run that contained the failure it names. The ceiling PINNING still
            # (correctly) draws only from the climb; the ROLL-UP must see everything that ran.
            "fidelity": {
                "gate_version": FIDELITY_GATE_VERSION,
                "sent_floor": FIDELITY_SENT_FLOOR,
                "acked_floor": FIDELITY_ACKED_FLOOR,
                "all_admissible": all(r.fidelity_admissible for r in self.all_records),
                "admissible_rungs": sum(1 for r in self.all_records if r.fidelity_admissible),
                "void_rungs": [
                    {
                        "index": r.index,
                        "is_soak": r.is_soak,
                        "ingress_rate": round(r.ingress_rate, 3),
                        "fidelity": r.fidelity.value,
                        "offered": r.offered,
                        "sent": r.sent,
                        "acked": r.acked,
                    }
                    for r in self.all_records
                    if not r.fidelity_admissible
                ],
                # The two failure modes, called by name, because conflating them is the whole defect:
                # a DRIVE SHORTFALL is a statement about the RIG; an ENGINE INTAKE BIND is a real engine
                # finding — and a DIFFERENT one from a lane/claim wall (the bind is at INTAKE).
                "any_drive_shortfall": any(
                    r.fidelity is RungFidelity.DRIVE_SHORTFALL for r in self.all_records
                ),
                "any_engine_intake_bind": any(
                    r.fidelity is RungFidelity.ENGINE_INTAKE_BIND for r in self.all_records
                ),
                # ⭐ v7: the two arms gate v1 COULD NOT EXPRESS, and the reason it was dangerous.
                #  * `any_backpressure_bind` — a `sent` shortfall the ENGINE caused (it stopped reading its
                #    socket). v1 called this a DRIVE SHORTFALL, VOIDED the rung as a rig failure and told the
                #    operator to add drive boxes — discarding the single most likely signature of a real
                #    intake bind. IT IS AN ENGINE FINDING and it may BE the ceiling.
                #  * `any_offer_shortfall` — a `sent` shortfall whose CAUSE WAS NOT RECORDED. FAIL-CLOSED:
                #    it voids, and it blames NOBODY. Not a silent skip and not a default to "the rig".
                "any_backpressure_bind": any(
                    r.fidelity is RungFidelity.BACKPRESSURE_BIND for r in self.all_records
                ),
                "any_offer_shortfall": any(
                    r.fidelity is RungFidelity.OFFER_SHORTFALL for r in self.all_records
                ),
                # The CLIMB-only view is kept explicitly (that IS the ceiling's candidate set), so widening
                # the roll-up above cannot be misread as widening what the ceiling is pinned from.
                "climb_all_admissible": not self.voided_climb,
                "climb_admissible_rungs": len(self.admissible_climb),
                # v7: the BRACKET's candidate set — strictly wider than the pin's (engine binds included).
                "climb_driven_rungs": len(self.driven_climb),
                "climb_not_driven_rungs": len(self.not_driven_climb),
                # THE SOAK, CALLED OUT BY NAME. `soak_ok` now requires this to be "admissible".
                "soak_fidelity": (None if self.soak_fidelity is None else self.soak_fidelity.value),
                "soak_fidelity_admissible": self.soak_fidelity_admissible,
                # v7: WHO refused the soak. `soak_engine_bound` (intake OR backpressure) is an ENGINE
                # finding ⇒ SOAK_NOT_SUSTAINED. `soak_drive_shortfall` is the RIG ⇒ SETUP_DEGRADED, exit 2 —
                # THE ONLY VOID ARM. `soak_fidelity_unattributed` is FAIL-CLOSED ⇒ SOAK_UNCONFIRMED: it
                # blames nobody, because the cause was not measured.
                "soak_drive_shortfall": self.soak_drive_shortfall,
                "soak_backpressure_bind": self.soak_backpressure_bind,
                "soak_engine_bound": self.soak_engine_bound,
                "soak_offer_shortfall": self.soak_offer_shortfall,
                "soak_fidelity_unattributed": self.soak_fidelity_unattributed,
                # v7: taken from the rung's OWN property, which carries the deferral cause split. Rebuilding
                # the note here from a split-less argument list printed "backpressure=-1 schedule=-1" on a
                # rung whose verdict WAS attributed — a note that contradicted its own verdict.
                "soak_fidelity_reason": (None if self.soak is None else self.soak.fidelity_reason),
            },
            "target_events_per_s": round(TARGET_EVENTS_PER_S, 3),
            # The D4 half-derate, emitted so a consumer cannot silently drop it between this JSON and a claim.
            "publishable_derate": PUBLISHABLE_DERATE,
            "raw_events_per_s_needed_to_publish": round(
                TARGET_EVENTS_PER_S / PUBLISHABLE_DERATE, 3
            ),
            "ceiling": {
                # D1: honest sustainable rate (offered spread over hold + MEASURED drain), not the inflated
                # raw offered ingress_rate. clears_target_events keys off pinned_ingress_rate x (1 + D).
                # OFFERED-derived (offered x hold / (hold + drain)); `acked` never enters it, and SUSTAINED
                # only bounds the intake shortfall by _INTAKE_TOL (5%) — so read it beside the rung's
                # ACCEPTED-derived `accepted_ingress_rate` (the honest floor), which is emitted per rung.
                "pinned_ingress_rate": (
                    None if self.pinned_ingress_rate is None else round(self.pinned_ingress_rate, 3)
                ),
                "pinned_ingress_rate_basis": "offered (within _INTAKE_TOL=5% of accepted)",
                # ⭐ v7 (ARTIFACT 2): THE RESOURCE ATTRIBUTION. `pool_bound` ⇒ the rung this ceiling is quoted
                # from EXHAUSTED THE STORE POOL, so the wall is the POOL's, not the engine's. The rate above
                # is still real and still published (unlike a fidelity void, where no rate was established) —
                # but `admissible` is False and it must NEVER be quoted as the ENGINE's ceiling. In v6 the
                # tripwire touched nothing at all and this shipped as `result: PASS`, exit 0.
                "pool_bound": self.ceiling_pool_bound,
                "admissible": self.ceiling_admissible,
                # ⭐ v7: WHICH rungs may set the bracket TOP. Engine-bound rungs are INCLUDED — a saturating
                # engine IS `acked < offered`, so excluding them discarded real collapses (see the v7 note).
                "bracket_basis": (
                    "driven_climb: the offered rate reached the engine (or the ENGINE refused to read it). "
                    "An ENGINE_INTAKE_BIND / BACKPRESSURE_BIND rung is a FINDING and DOES bracket; only "
                    "DRIVE_SHORTFALL / OFFER_SHORTFALL / UNKNOWN (no rate established) cannot. The PIN is "
                    "stricter: admissible_climb only."
                ),
                # ⭐ v6 (ARTIFACT 3): the ACCEPTED-derived ceiling, carried to the HEADLINE. Everything above
                # is OFFERED-derived — `acked` never enters `sustainable_ingress_rate` — so an under-driven
                # rung reports a ceiling built from WHAT WE ASKED FOR, and until now the accepted figure was
                # a passenger (emitted per rung, never a selector, with no events/s sibling). These are its
                # counterparts in every currency the offered number is quoted in. READ THEM SIDE BY SIDE:
                # when `accepted_vs_offered_ratio` < 1, the offered figures overstate this run by that much.
                "pinned_accepted_ingress_rate": (
                    None
                    if self.pinned_accepted_ingress_rate is None
                    else round(self.pinned_accepted_ingress_rate, 3)
                ),
                "pinned_accepted_ingress_rate_basis": "accepted (acked / (hold + measured drain))",
                "accepted_events_per_s": (
                    None
                    if self.accepted_events_per_s is None
                    else round(self.accepted_events_per_s, 3)
                ),
                "clears_target_events_accepted": self.clears_target_events_accepted,
                # ⚠️ BOUNDED BY CONSTRUCTION to [~0.95, 1.0]: the pinned rung is FIDELITY-ADMISSIBLE, so it
                # accepted >= 95% of its offer BY DEFINITION. This is a <= 5% REFINEMENT of the offered
                # figure — NOT the under-drive detector (that is `fidelity`; a rung the rig could not drive
                # never reaches this property). `max_accepted_vs_offered_gap` below is the unbounded view.
                "accepted_vs_offered_ratio": (
                    None
                    if self.accepted_vs_offered_ratio is None
                    else round(self.accepted_vs_offered_ratio, 4)
                ),
                "accepted_vs_offered_ratio_bounded_by_admissibility_floor": True,
                # The LARGEST accepted-vs-offered gap across EVERY climb rung, VOID ONES INCLUDED — the only
                # place a real (> 5%) divergence between the plan and what the engine took can be seen.
                "max_accepted_vs_offered_gap": (
                    None
                    if self.max_accepted_vs_offered_gap is None
                    else round(self.max_accepted_vs_offered_gap, 4)
                ),
                "pinned_outbound_rate": (
                    None
                    if self.pinned_outbound_rate is None
                    else round(self.pinned_outbound_rate, 3)
                ),
                # D3: span-correct MEASURED delivered rate (phase-window denominator), a cross-check on the
                # ingress-derived pinned_outbound_rate — NOT sink_received / hold_seconds.
                "pinned_measured_delivered_rate_per_s": (
                    None
                    if self.pinned_measured_delivered_rate_per_s is None
                    else round(self.pinned_measured_delivered_rate_per_s, 3)
                ),
                # ⚠️ FIDELITY-GATED (v6). The bracket TOP is drawn from `admissible_climb`, the SAME
                # candidate set as the floor. A rung that failed fidelity used to set this at its OFFERED
                # rate — a rate that was never driven — and flip `bracketed` to true on the strength of it.
                # A collapse at an un-driven rate is a REAL engine event with a FICTIONAL rate label, so it
                # is reported (below) and brackets NOTHING.
                "first_collapse_ingress_rate": self.first_collapse_ingress_rate,
                "bracketed": self.ceiling_bracketed,
                "has_void_collapse": self.has_void_collapse,
                "void_collapses": [
                    {
                        "index": r.index,
                        "offered_ingress_rate": round(r.ingress_rate, 3),
                        "fidelity": r.fidelity.value,
                        "offered": r.offered,
                        "sent": r.sent,
                        "acked": r.acked,
                    }
                    for r in self.void_collapsed_climb
                ],
                # B10: total events = ingress x (1 + delivering). Gate on events, never on ingress alone —
                # and never on (1 + dests), which is a 4.2x overstatement at the reference hub (#209).
                "sustained_events_per_s": (
                    None
                    if self.sustained_events_per_s is None
                    else round(self.sustained_events_per_s, 3)
                ),
                # RAW measurement vs the PUBLISHABLE bar. `clears_target_events` is the raw gate — it trips at
                # HALF the ingress a 45M/day claim needs. `clears_target_events_publishable` applies the D4
                # half-derate and is the one a claim must pass. Never quote the raw gate as "we hit 45M/day".
                "clears_target_events": self.clears_target_events,
                "publishable_events_per_s": (
                    None
                    if self.publishable_events_per_s is None
                    else round(self.publishable_events_per_s, 3)
                ),
                "clears_target_events_publishable": self.clears_target_events_publishable,
                # ⭐ THE CLAIM BAR ON THE HONEST FLOOR (v6). `publishable_events_per_s` above derates the
                # OFFERED ceiling, so the single gate governing a public 45M/day claim was still built from
                # what we ASKED for. These are its ACCEPTED-derived counterparts. Quote THESE.
                "publishable_accepted_events_per_s": (
                    None
                    if self.publishable_accepted_events_per_s is None
                    else round(self.publishable_accepted_events_per_s, 3)
                ),
                "clears_target_events_accepted_publishable": (
                    self.clears_target_events_accepted_publishable
                ),
            },
            "soak": None if self.soak is None else self.soak.to_json_dict(),
            # v6: `soak_ok` now carries a FIDELITY term — a soak nobody drove, or one the engine short-took,
            # cannot certify the ceiling. See `fidelity.soak_*`.
            "soak_ok": self.soak_ok,
            "soak_drive_shortfall": self.soak_drive_shortfall,  # a RIG failure ⇒ setup_degraded (exit 2)
            "soak_engine_intake_bind": self.soak_engine_intake_bind,  # a real PRODUCT finding
            "climb": [r.to_json_dict() for r in self.climb],
            "notes": self.notes,
        }


def build_consolidated_report(
    *,
    shards: Sequence[str],
    dests: int,
    handlers: int,
    delivering: int,
    routing: str,
    driver_count: int,
    sink_count: int,
    climb: Sequence[RungOutcome],
    soak: RungOutcome | None,
    notes: Sequence[str] = (),
    climb_aborted: bool = False,
    soak_aborted: bool = False,
    lanes_per_shard: int = 1,
) -> ConsolidatedLadderReport:
    """Assemble the consolidated report from the driven rung outcomes — a thin, PURE constructor so the
    report shape can be unit-tested from synthetic outcomes without a live fleet.

    ``handlers``/``delivering``/``routing`` are REQUIRED, deliberately not defaulted (BACKLOG #209):
    ``delivering`` is the multiplier under ``sustained_events_per_s``, the headline the §8 decision keys
    off, and ``routing`` is what makes that pair READABLE (the derived (1, 1) is ambiguous without it). A
    default here is a stale constant waiting to be forgotten by a future caller — and it would fabricate a
    plausible number rather than fail.

    ``lanes_per_shard`` DOES default (to 1, the shipped value): unlike the fan-out it is not a multiplier on
    any headline, and a wrong-but-plausible G cannot inflate a rate — it can only under-report the inbound
    pool width, which the ``G < L`` warning then flags anyway. The real caller
    (:func:`run_drive_ladder`) always passes the value SHARDS_READY advertised."""
    return ConsolidatedLadderReport(
        shards=tuple(shards),
        dests=dests,
        handlers=handlers,
        delivering=delivering,
        routing=routing,
        lanes_per_shard=lanes_per_shard,
        driver_count=driver_count,
        sink_count=sink_count,
        climb=list(climb),
        soak=soak,
        notes=list(notes),
        climb_aborted=climb_aborted,
        soak_aborted=soak_aborted,
    )


# =====================================================================================================
# The two lockstep ladder loops (engine box + load-gen box). These reuse the merged per-rung halves
# UNCHANGED and are kept thin — the classification / planning / report logic above is the tested core.
# =====================================================================================================


@dataclass
class EngineLadderResult:
    """The engine box's own outcome — a thin record of the rungs it armed + drained (the DRIVE box owns the
    consolidated report). Store-truth verdicts are posted per rung as ENGINE_RUNG_REPORT for the drive."""

    rungs_armed: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def render(self) -> str:
        lines = [
            f"ShardCert ENGINE ladder — armed {len(self.rungs_armed)} rung(s): "
            f"{', '.join(self.rungs_armed) or '(none)'}"
        ]
        for note in self.notes:
            lines.append(f"  note: {note}")
        return "\n".join(lines)


async def _seen_stop(base_coord: FileDropCoord, grace: float) -> bool:
    """Poll for ``LADDER_STOP`` under the base run_id for up to ``grace`` seconds; True if it lands. A
    BOUNDED poll (not a single non-blocking read) so the drive's just-posted STOP — which it emits only
    ~1s after reading our ENGINE_RUNG_REPORT + classifying — is caught, avoiding a wasted full
    ``drive_start_timeout`` on a rung the drive will never drive."""
    if grace <= 0:
        return base_coord.read(LADDER_STOP) is not None
    with contextlib.suppress(CoordTimeout):
        await base_coord.await_message(LADDER_STOP, timeout=grace)
        return True
    return False


def _engine_rung_payload(report: ShardCertEngineReport) -> dict[str, object]:
    """The metadata-only ENGINE_RUNG_REPORT payload for a rung — the engine store-truth verdict the drive
    folds into the classifier + the in_pipeline slope. Phase timing is added by the caller (it reads the
    node logs after teardown). Never bodies / control-ids (PHI rule)."""
    return {
        "engine_ok": report.ok,
        "drained": report.drained,
        "stranded": report.stranded_nonterminal,
        "dead_total": report.dead_total,
        # BACKLOG #229: the per-stage strand split (non-terminal + dead, by stage) on the report path too —
        # the gate is preferred for store-truth, but a degraded rung falls back to THIS report, so a
        # gate-only thread would leave that fallback stage-blind. `-1` = NOT READ ⇒ stage-blind fallback.
        "ingress_stranded": report.ingress_stranded,
        "routed_stranded": report.routed_stranded,
        "outbound_stranded": report.outbound_stranded,
        "engine_dead": report.engine_dead,
        "in_pipeline_final": report.in_pipeline_final,
        "in_pipeline_slope": in_pipeline_slope(report.in_pipeline_trace),
        # B3: whether this rung's store-truth was INVALIDATED by a drive abort (sinks reaped mid-delivery) —
        # so the engine never reports a fabricated collapse. valid is the convenience inverse for consumers.
        "aborted": report.aborted,
        "valid": not report.aborted,
        # The RELIABLE engine-side drain time (D1): the drive prefers it over its advisory remote drain for
        # the honest sustainable rate. Present on the report path too (not just the ENGINE_DRAINED gate).
        "drain_seconds": report.drain_seconds,
        # ARTIFACT 2: the store pool + its saturation evidence. THE ENGINE BOX IS THE ONLY HALF THAT CAN SEE
        # THIS (it polls the shards' /status) and the DRIVE BOX IS THE ONLY HALF THAT WRITES A REPORT — so
        # without this wire the evidence dies on the engine box, which is exactly what happened before
        # (STEP 2 hand-scraped `pool.acquire_wait` from /status by hand, per rung, per shard).
        "store_pool": report.pool.to_json_dict(),
        # ARTIFACT 5: G's per-shard half from the box that BUILT the graph. The drive learns `lanes` from
        # SHARDS_READY independently; carrying it here too means a rung's report is self-contained.
        "lanes_per_shard": report.lanes_per_shard,
        "notes": list(report.notes),
    }


def _attach_rung_timings(payload: dict[str, object], rung_logs: Sequence[Path]) -> None:
    """Attach ALL THREE phase-timing aggregates to an ENGINE_RUNG_REPORT payload from the rung's per-shard
    node logs: the delivery ``send_ack``/``mark_done`` split (``phase_timing``), the CLAIM store round-trip
    (``claim_timing``, D6 — the phase #842 could not see), and the LANE EPISODE (``episode_timing`` —
    ``S_lane``, STEP 4 ARM 1). All three are SIBLINGS gated by the same ``MEFOR_DELIVERY_PHASE_TIMING`` lever;
    every one must be attached or the drive box's aggregate stays empty despite the node logs carrying the
    lines — which for ``S_lane`` would mean ARM 1's headline number exists only as an INFO line to be
    hand-grepped per rung, per shard, with no n-weighting and no ramp-window drop."""
    payload["phase_timing"] = aggregate_phase_timing(rung_logs).to_json_dict()
    payload["claim_timing"] = aggregate_claim_timing(rung_logs).to_json_dict()
    payload["episode_timing"] = aggregate_episode_timing(rung_logs).to_json_dict()


async def run_engine_ladder(
    *,
    rates: Sequence[float],
    dests: int,
    handlers: int | None = None,
    delivering: int | None = None,
    hold_seconds: float,
    drain_timeout: float,
    sink_port: int,
    sink_ports: int,
    sink_host: str,
    inbound_bind_host: str,
    claim_mode: str,
    store_env: Mapping[str, str],
    base_coord: FileDropCoord,
    keep_logs_base: Path,
    cwd: Path | None = None,
    # Engine-side FALLBACK hold; the DRIVE half's LADDER_SOAK dictates whether a soak runs at all. The
    # default is a real 300s soak — dropping/zeroing it does NOT skip (the drive's --no-soak is the "off").
    soak_hold_seconds: float = 300.0,
    soak_drain_timeout: float = 300.0,
    climb_drive_start_timeout: float = 300.0,
    soak_drive_start_timeout: float = 300.0,
    stop_poll_grace: float = 10.0,
    post_drain_grace: float = 8.0,
    soak_timeout: float = 900.0,
    #: ARTIFACT 2: the EFFECTIVE MEFOR_STORE_POOL_SIZE for every shard PROCESS. None ⇒ resolve from the
    #: ambient env, else the PRODUCT default (40) — never the old hardcoded 8.
    store_pool_size: int | None = None,
    #: ARTIFACT 5: refuse (rather than warn) to arm a rung whose inbound band count G is below the outbound
    #: lane count L. Off by default because G < L is TRUE at the shipped defaults.
    strict_bands: bool = False,
) -> EngineLadderResult:
    """The ENGINE-box ladder loop. Iterates the fixed climb plan (fresh per-rung store + ``run_id``),
    posting each rung's store-truth + phase timing as ENGINE_RUNG_REPORT, then arms one soak rung at the
    rate the drive selects (LADDER_SOAK).

    ``climb_drive_start_timeout`` must comfortably exceed the DRIVE half's per-rung child bring-up (it
    re-spawns K+M ``python -m harness`` children each rung and awaits every SINK_BOUND then DRIVER_ARMED
    before posting DRIVE_START) — hence a generous default (minutes), NOT a few seconds, so a slow/cold
    load-gen box is never mis-read as "drive unresponsive". The early-stop is kept cheap instead by a
    BOUNDED ``stop_poll_grace`` poll of LADDER_STOP before arming each rung after the first: the drive posts
    STOP right after it reads our prior ENGINE_RUNG_REPORT, so a few seconds' grace catches it and avoids
    wasting a full ``climb_drive_start_timeout`` on a rung the drive will never drive. Lost signal → the
    bounded plan still finishes (the CoordTimeout branch below re-checks STOP).

    ``handlers`` (H) / ``delivering`` (D) are the BACKLOG #209 shape split (both default to ``dests``). The
    ENGINE box owns the shape for the whole ladder; the DRIVE box has NO shape flag and learns H/D/dests per
    rung from SHARDS_READY, so the two halves cannot drift."""
    result = EngineLadderResult()
    climb = plan_climb_rungs(rates, hold_seconds=hold_seconds, drain_timeout=drain_timeout)
    keep_logs_base.mkdir(parents=True, exist_ok=True)
    # Clear the BASE-run cross-rung signals at startup so a re-run under the same base run_id can't read a
    # STALE LADDER_STOP (which the first pre-arm check below would mis-read as "the drive already stopped"
    # → an immediate false early-break) or a stale LADDER_SOAK. Safe here: no real STOP/SOAK is posted until
    # after rung 0's handshake, so a startup clear never races a live signal. The drive clears the same pair
    # at the top of run_drive_ladder — clearing from both sides at startup is idempotent.
    base_coord.clear_messages(LADDER_STOP, LADDER_SOAK)

    for rung in climb:
        # Early-stop: before arming any rung after the first, give the drive's just-posted LADDER_STOP a
        # brief window to land (a bounded poll — see _seen_stop). Skip the poll for the first rung (no prior
        # STOP is possible) so r0 arms immediately.
        if rung.index > 0 and await _seen_stop(base_coord, stop_poll_grace):
            result.notes.append(f"early-stop: LADDER_STOP seen before arming {rung.run_suffix}")
            break
        rung_coord = base_coord.for_run(f"{base_coord.run_id}.{rung.run_suffix}")
        # Fresh per-rung handshake: a re-run with the same base run_id must not read a stale drop.
        rung_coord.clear_messages(
            SHARDS_READY, DRIVE_START, ENGINE_DRAINED, ENGINE_RUNG_REPORT, RUNG_ABORTED
        )
        keep_dir = keep_logs_base / rung.run_suffix
        keep_dir.mkdir(parents=True, exist_ok=True)
        rung_env = {**store_env, "MEFOR_BENCH_KEEP_NODE_LOGS": str(keep_dir)}
        try:
            report = await run_shardcert_engine(
                dests=dests,
                handlers=handlers,
                delivering=delivering,
                hold_seconds=rung.hold_seconds,
                kill=False,
                drain_timeout=rung.drain_timeout,
                sink_port=sink_port,
                sink_ports=sink_ports,
                store_env=rung_env,
                coord=rung_coord,
                cwd=cwd,
                inbound_bind_host=inbound_bind_host,
                sink_host=sink_host,
                claim_mode=claim_mode,
                drive_start_timeout=climb_drive_start_timeout,
                post_drain_grace=post_drain_grace,
                signal_drained=True,
                abort_signal=RUNG_ABORTED,
                # The CLIMB needs the in_pipeline trace, not just the soak (2026-07-13, STEP 4).
                #
                # A climb rung is judged on `no_loss` + `drained` — but a rung that is FILLING (backlog
                # growing all through the hold) still drains eventually and still loses nothing, so it
                # passes both and INFLATES the reported ceiling. That is not hypothetical: it is how
                # s4-climbA's ~16 msg/s plateau was measured.
                #
                # The E2E `fill_ratio` term cannot close this on the TWO-BOX rig — a sink process's
                # Correlator never sees `on_send` (the senders are other processes), so the drive report
                # carries no e2e at all and the term abstains. `in_pipeline_slope` is the discriminator
                # that DOES survive the box split: it is read from the engine's own /stats, so it needs no
                # cross-process clock and no correlation. Sampling it on the climb is what makes a filling
                # rung visible on the only path STEP 4 actually runs.
                sample_in_pipeline=True,
                store_pool_size=store_pool_size,
                strict_bands=strict_bands,
            )
        except CoordTimeout:
            # The drive did not drive this rung within the (short) DRIVE_START window. If it stopped (STOP
            # now present) this is the expected end of the climb; otherwise the drive is unresponsive.
            if base_coord.read(LADDER_STOP) is not None:
                result.notes.append(
                    f"early-stop: DRIVE_START timeout on {rung.run_suffix} + LADDER_STOP"
                )
            else:
                result.notes.append(
                    f"aborting climb: no DRIVE_START for {rung.run_suffix} and no LADDER_STOP "
                    "(drive unresponsive)"
                )
            break
        payload = _engine_rung_payload(report)
        _attach_rung_timings(payload, _rung_log_paths(keep_dir, report.shards))
        rung_coord.post(ENGINE_RUNG_REPORT, payload)
        result.rungs_armed.append(rung.run_suffix)
        if report.aborted:
            # B3 belt-and-suspenders: the drive aborted this rung mid-delivery (store-truth INVALID). Stop
            # the climb even if LADDER_STOP was lost — a torn-down rung is not a measurement to climb past.
            result.notes.append(
                f"{rung.run_suffix}: store-truth INVALID — drive aborted mid-delivery (stopping climb)"
            )
            break

    # Soak: the drive picks the rate (highest sustained, or an override) and posts LADDER_SOAK.
    try:
        soak_msg = await base_coord.await_message(LADDER_SOAK, timeout=soak_timeout)
    except CoordTimeout:
        result.notes.append("no LADDER_SOAK from the drive — ending without a soak")
        return result
    if soak_msg.get("skip"):
        result.notes.append("drive signalled no soak (no sustained rung)")
        return result

    soak_rate = float(soak_msg["soak_rate"])
    soak_rung = LadderRung(
        index=-1,
        ingress_rate=soak_rate,
        hold_seconds=float(soak_msg.get("hold_seconds", soak_hold_seconds)),
        drain_timeout=float(soak_msg.get("drain_timeout", soak_drain_timeout)),
        is_soak=True,
    )
    soak_coord = base_coord.for_run(f"{base_coord.run_id}.soak")
    soak_coord.clear_messages(
        SHARDS_READY, DRIVE_START, ENGINE_DRAINED, ENGINE_RUNG_REPORT, RUNG_ABORTED
    )
    keep_dir = keep_logs_base / "soak"
    keep_dir.mkdir(parents=True, exist_ok=True)
    soak_env = {**store_env, "MEFOR_BENCH_KEEP_NODE_LOGS": str(keep_dir)}
    try:
        report = await run_shardcert_engine(
            dests=dests,
            handlers=handlers,
            delivering=delivering,
            hold_seconds=soak_rung.hold_seconds,
            kill=False,
            drain_timeout=soak_rung.drain_timeout,
            sink_port=sink_port,
            sink_ports=sink_ports,
            store_env=soak_env,
            coord=soak_coord,
            cwd=cwd,
            inbound_bind_host=inbound_bind_host,
            sink_host=sink_host,
            claim_mode=claim_mode,
            drive_start_timeout=soak_drive_start_timeout,
            post_drain_grace=post_drain_grace,
            signal_drained=True,
            abort_signal=RUNG_ABORTED,
            sample_in_pipeline=True,
            # The soak must run on the SAME pool + band shape as the climb it was pinned from, or the soak
            # is testing a different fleet than the ceiling it is soaking (ARTIFACTS 2/5).
            store_pool_size=store_pool_size,
            strict_bands=strict_bands,
        )
    except CoordTimeout:
        result.notes.append("soak: no DRIVE_START from the drive")
        return result
    payload = _engine_rung_payload(report)
    _attach_rung_timings(payload, _rung_log_paths(keep_dir, report.shards))
    soak_coord.post(ENGINE_RUNG_REPORT, payload)
    result.rungs_armed.append("soak")
    return result


async def run_drive_ladder(
    *,
    engine_host: str,
    rates: Sequence[float],
    hold_seconds: float,
    drain_timeout: float,
    driver_count: int,
    sink_count: int | None,
    sink_host: str,
    base_coord: FileDropCoord,
    allow_insecure: bool = False,
    # NB: the DEFAULT is a real 300s soak — the "off" switch is ``do_soak=False`` (CLI ``--no-soak``), NOT a
    # dropped/zero ``soak_hold_seconds`` (0 arms a degenerate 0s soak, it does not skip).
    soak_hold_seconds: float = 300.0,
    soak_drain_timeout: float = 300.0,
    soak_rate_override: float | None = None,
    do_soak: bool = True,
    shards_ready_timeout: float = 300.0,
    engine_rung_report_timeout: float = 120.0,
    engine_drained_timeout: float | None = None,
) -> ConsolidatedLadderReport:
    """The LOAD-GEN-box ladder loop + the consolidated report. Iterates the SAME climb plan the engine
    arms, driving each rung with the merged multi-process :func:`run_shardcert_drive` (K senders + M sinks)
    under the drain gate, classifies each rung, and — at the first COLLAPSE — posts LADDER_STOP and stops
    climbing. Then picks the soak rate, posts LADDER_SOAK, drives the soak, and builds the report.

    It takes NO shape argument (BACKLOG #209): ``dests``/``handlers``/``delivering`` are learned from the
    engine's SHARDS_READY (via :attr:`ShardCertDriveReport`), so the shape has ONE source of truth across the
    box boundary. A shape flag on both CLIs would be a two-place constant that drifts invisibly — and the
    drift would surface as a fabricated ceiling, not an error."""
    climb = plan_climb_rungs(rates, hold_seconds=hold_seconds, drain_timeout=drain_timeout)
    # Clear cross-rung signals so a re-run under the same base run_id doesn't read a stale STOP/SOAK.
    base_coord.clear_messages(LADDER_STOP, LADDER_SOAK)

    outcomes: list[RungOutcome] = []
    notes: list[str] = []
    shards: tuple[str, ...] = ()
    # The shape the ENGINE served, learned per rung from its SHARDS_READY. 0 until the first rung reports —
    # an aborted-before-any-rung climb legitimately has no shape to name (and pins no ceiling either).
    dests = 0
    handlers = 0
    delivering = 0
    # The routing mode the engine box served, learned with the rest of the shape. BROADCAST until a rung
    # reports — the same "nothing served yet" posture as the zeros above, and the correct default anyway.
    routing = BROADCAST
    # ARTIFACT 5: lanes-per-shard — the OTHER half of G, learned from the same SHARDS_READY post as the shape.
    # The drive has always received it (it slices sender bands with it) and always dropped it on the floor.
    lanes_per_shard = 1
    # The EFFECTIVE sink_count. `sink_count=None` means "derive from the engine's advertised band width"
    # (BACKLOG #209 back-compat: --dests below the old literal 8 narrows the band). run_shardcert_drive
    # resolves it per rung and echoes it on ShardCertDriveReport.sink_count, so the consolidated report
    # names the count actually run, not None. Seed with a caller-supplied value; overwritten from the
    # first drive report either way.
    resolved_sink_count = sink_count if sink_count is not None else 0

    stopped = False
    climb_aborted = False
    soak_aborted = False
    for rung in climb:
        rung_coord = base_coord.for_run(f"{base_coord.run_id}.{rung.run_suffix}")
        try:
            drive = await run_shardcert_drive(
                engine_host=engine_host,
                aggregate_rate=rung.ingress_rate,
                hold_seconds=rung.hold_seconds,
                driver_count=driver_count,
                sink_count=sink_count,
                sink_host=sink_host,
                coord=rung_coord,
                drain_timeout=rung.drain_timeout,
                allow_insecure=allow_insecure,
                shards_ready_timeout=shards_ready_timeout,
                await_engine_drained=True,
                engine_drained_timeout=engine_drained_timeout,
            )
        except CoordTimeout as exc:
            # The engine half never handed off this rung within the window (dead / desynced) — a two-box
            # RENDEZVOUS failure, NOT a bench result. Post LADDER_STOP so the engine stops climbing
            # IMMEDIATELY on its next pre-arm check instead of hanging on the next rung's DRIVE_START, and
            # flag the run as a setup abort (exit_code 2) so a mid-run infra death never reads as a PASS.
            base_coord.post(
                LADDER_STOP, {"stopped_at": rung.run_suffix, "verdict": "drive_aborted"}
            )
            # B3: also tell the ENGINE on the RUNG coord that THIS rung aborted, so its in-flight drain —
            # failing only because we reaped its sinks — marks the rung's store-truth INVALID rather than
            # posting a fabricated collapse. LADDER_STOP is polled only BETWEEN rungs; this is per-rung.
            rung_coord.post(RUNG_ABORTED, {"reason": "drive_aborted", "detail": str(exc)})
            notes.append(
                f"{rung.run_suffix}: drive aborted ({exc}) — posted LADDER_STOP + RUNG_ABORTED, setup-abort"
            )
            climb_aborted = True
            stopped = True
            break
        shards = drive.shards
        dests, handlers, delivering = drive.dests, drive.handlers, drive.delivering
        routing = drive.routing
        lanes_per_shard = drive.lanes  # ARTIFACT 5: G = len(shards) x this
        resolved_sink_count = (
            drive.sink_count
        )  # the count actually run (derived when caller passed None)
        # Store-truth for the classifier comes from the RELIABLE drain gate (ENGINE_DRAINED — the drive
        # awaited it before tallying, so it is already on disk); the later, more fragile ENGINE_RUNG_REPORT
        # only ADDS the phase timing + soak slope, so a late/lost report can no longer fabricate a collapse.
        gate = rung_coord.read(ENGINE_DRAINED)
        report_msg = await _read_engine_report(rung_coord, timeout_seen=engine_rung_report_timeout)
        outcome = build_rung_outcome(rung, drive, gate, report_msg)
        outcomes.append(outcome)
        if stops_climb(outcome.verdict):
            base_coord.post(
                LADDER_STOP, {"stopped_at": rung.run_suffix, "verdict": outcome.verdict.value}
            )
            notes.append(
                f"early-stop: {rung.run_suffix} classified {outcome.verdict.value} — posted LADDER_STOP"
            )
            stopped = True
            break

    # Soak selection + handshake.
    soak_rate = pick_soak_rate(outcomes, soak_rate_override) if do_soak else None
    soak_outcome: RungOutcome | None = None
    if soak_rate is None:
        base_coord.post(LADDER_SOAK, {"skip": True})
        # ARTIFACT 4: `pick_soak_rate` now (correctly) requires FIDELITY-ADMISSIBLE, so a climb whose rungs
        # ALL SUSTAINED but were never DRIVEN yields no soak rate. The old blanket note — "no sustained rung"
        # — reports that as though NOTHING sustained, i.e. as though the engine collapsed at the first rung.
        # It is the exact conflation this gate exists to abolish, discarded at the precise line an operator
        # reads to find out WHY the soak was skipped. And since an under-driven climb is the DEFAULT
        # expectation, it is the note MOST runs will print. Name the three causes apart.
        sustained = [r for r in outcomes if not r.is_soak and r.verdict is RungVerdict.SUSTAINED]
        void_sustained = [r for r in sustained if not r.fidelity_admissible]
        if not do_soak:
            notes.append("no soak (soak disabled)")
        elif sustained and len(void_sustained) == len(sustained):
            notes.append(
                f"no soak: {len(sustained)} of {len(outcomes)} climb rung(s) SUSTAINED but ALL were "
                "FIDELITY-VOID (drive shortfall / engine intake bind) — nothing was DRIVEN at a rate worth "
                "soaking. THIS IS NOT 'the engine collapsed at the first rung': the rungs held; the load "
                "generator (or the engine's intake) never produced the offered rate. Fix the rig and re-run."
            )
        else:
            notes.append("no soak (no sustained rung)")
    else:
        base_coord.post(
            LADDER_SOAK,
            {
                "soak_rate": soak_rate,
                "hold_seconds": soak_hold_seconds,
                "drain_timeout": soak_drain_timeout,
            },
        )
        soak_rung = LadderRung(
            index=-1,
            ingress_rate=soak_rate,
            hold_seconds=soak_hold_seconds,
            drain_timeout=soak_drain_timeout,
            is_soak=True,
        )
        soak_coord = base_coord.for_run(f"{base_coord.run_id}.soak")
        try:
            drive = await run_shardcert_drive(
                engine_host=engine_host,
                aggregate_rate=soak_rate,
                hold_seconds=soak_hold_seconds,
                driver_count=driver_count,
                sink_count=sink_count,
                sink_host=sink_host,
                coord=soak_coord,
                drain_timeout=soak_drain_timeout,
                allow_insecure=allow_insecure,
                shards_ready_timeout=shards_ready_timeout,
                await_engine_drained=True,
                engine_drained_timeout=engine_drained_timeout,
            )
            if not shards:
                # A soak-only run (every climb rung aborted before reporting) still has to name the shape it
                # served — otherwise the report's delivery arithmetic would key off a zero fan-out.
                shards = drive.shards
                dests, handlers, delivering = drive.dests, drive.handlers, drive.delivering
                routing = drive.routing
                lanes_per_shard = drive.lanes
                resolved_sink_count = drive.sink_count
            gate = soak_coord.read(ENGINE_DRAINED)
            report_msg = await _read_engine_report(
                soak_coord, timeout_seen=engine_rung_report_timeout
            )
            soak_outcome = build_rung_outcome(soak_rung, drive, gate, report_msg)
        except CoordTimeout as exc:
            # A soak rendezvous failure does NOT set climb_aborted (the CLIMB already pinned the ceiling), but
            # it IS a setup degradation: the soak never produced a measurement, so it must read as ABORTED
            # (exit 2), never a clean PASS with soak=null (B2). Also tell the ENGINE on the RUNG coord so its
            # soak drain failure — from our reaped sinks — marks the soak store-truth INVALID, not a collapse
            # (B3).
            soak_aborted = True
            soak_coord.post(RUNG_ABORTED, {"reason": "soak_drive_aborted", "detail": str(exc)})
            notes.append(
                f"soak: drive aborted ({exc}) — soak ABORTED (setup-degraded, not a bench result)"
            )

    if stopped and not climb_aborted:
        notes.append("climb stopped at the ceiling (early-stop)")
    return build_consolidated_report(
        shards=shards,
        dests=dests,
        handlers=handlers,
        delivering=delivering,
        routing=routing,
        lanes_per_shard=lanes_per_shard,
        driver_count=driver_count,
        sink_count=resolved_sink_count,
        climb=outcomes,
        soak=soak_outcome,
        notes=notes,
        climb_aborted=climb_aborted,
        soak_aborted=soak_aborted,
    )


async def _read_engine_report(
    coord: FileDropCoord, *, timeout_seen: float
) -> dict[str, Any] | None:
    """Read back a rung's ENGINE_RUNG_REPORT (posted by the engine box after teardown) over the shared
    coord dir, or ``None`` if it never arrives within ``timeout_seen``. This is the SUPPLEMENTARY message
    (phase timing + soak slope, plus a redundant store-truth cross-check); the classifier's store-truth
    comes from the reliable ENGINE_DRAINED gate, so a lost report only drops the phase timing, never the
    verdict. Bounded so a lost report can't hang the drive-ladder."""
    with contextlib.suppress(CoordTimeout):
        return await coord.await_message(ENGINE_RUNG_REPORT, timeout=timeout_seen)
    return None


def store_env_from_environ() -> dict[str, str]:
    """The ambient ``MEFOR_STORE_*`` connection env (the unified store every ``serve --shard`` shares)."""
    return {k: v for k, v in os.environ.items() if k.startswith("MEFOR_STORE_")}
