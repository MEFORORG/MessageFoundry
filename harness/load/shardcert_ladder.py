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

**Judged ONLY by the reliable authorities** — the DRIVE sink socket-truth (``S == A*dests ∧ A>0 ∧ S>0 ∧
Σinversions==0 ∧ Σrepeats==0 ∧ lanes≥2``) and the ENGINE store-truth (``drained ∧ stranded==0 ∧
dead_total==0``). The remote ``/stats`` poller stays advisory (unreliable on a unified store — #841) and is
never gated on. **This bench REPORTS numbers; it does NOT flip ``SYSTEM-REQUIREMENTS.md §8`` or grade its
own fix** (the two-box governance rule). Counts + synthetic topology only — never message bodies /
control-ids (PHI rule).

The **target** is the 45M-messages/day figure = 45_000_000 / 86_400 ≈ **520.83 TOTAL message events/s**
(:data:`TARGET_EVENTS_PER_S`) — inbound *and* outbound, per the owner ruling. Because every accepted
message fans out to ``dests`` destinations, one ingress message produces ``1 + dests`` total events
(``delivered = ingress * dests``). So the sustainable ingress that saturates the budget is
``TARGET_EVENTS_PER_S / (1 + dests)``, and the report states BOTH figures.

.. warning::
   Until 2026-07-10 this constant was named ``TARGET_INGRESS_PER_S`` and the gate compared it against a
   pure **ingress** rate — a units defect (harness defect **B10**) that made the gate ``(1 + dests)``x too
   strict, i.e. **9x** at the bench default ``dests=8``. Every "52x short" figure published before that
   date carries that inflation. The JSON keys were renamed in ``schema_version`` 3 so that a stale
   consumer fails loudly with a ``KeyError`` rather than silently reading a boolean whose meaning flipped.
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
from harness.load.shardcert import (
    ShardCertDriveReport,
    ShardCertEngineReport,
    run_shardcert_drive,
    run_shardcert_engine,
)

#: 45M messages/day as the sustained TOTAL message-event rate (inbound + outbound) the ladder pins
#: against. NOT an ingress rate: one ingress message with ``dests`` destinations produces ``1 + dests``
#: events, so the ingress that saturates this budget is ``TARGET_EVENTS_PER_S / (1 + dests)``.
TARGET_EVENTS_PER_S = 45_000_000 / 86_400  # ≈ 520.833…

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
_CLAIM_RE = re.compile(
    r"claim n=(\d+) mean=([\d.]+)ms max=([\d.]+)ms \| "
    r"lanes/claim=([\d.]+) rows/claim=([\d.]+) rearm=(\d+) empty=(\d+) claimers=(\d+)"
)


# =====================================================================================================
# Phase-timing aggregation (extends the rig's aggregate.py: n-weighted mean, drop each shard's first
# ramp window). Reads the per-shard node logs the engine persisted with MEFOR_BENCH_KEEP_NODE_LOGS.
# =====================================================================================================


@dataclass(frozen=True)
class PhaseTiming:
    """The per-delivery ``send_ack`` (MLLP send→ACK) vs ``mark_done`` (store-completion round-trip) split,
    n-weighted across every shard × steady-state window of a rung (each shard's first ramp window dropped).
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
    rung into a single n-weighted :class:`PhaseTiming`. Each log's FIRST phase window is dropped (the ramp
    window — the fleet is still filling) exactly as the rig's ``aggregate.py`` does; the n-weighted mean is
    ``Σ(mean×n) / Σn`` and the max is the max over windows. A missing/empty/unreadable log contributes
    nothing (never raises — a bench report must not crash on a truncated log)."""
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
        if drop_first_window and matches:
            matches = matches[1:]  # drop this shard's first (ramp) window
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
    steady-state window of a rung (each shard's first ramp window dropped). Counts + latencies + ratios
    only — never a payload / control-id / lane name (PHI rule)."""

    windows: int
    claims: int  # Σ claim n over the aggregated windows (the n-weighted denominator)
    claim_mean_ms: float
    claim_max_ms: float
    lanes_per_claim: float  # n-weighted mean lanes offered per claim
    rows_per_claim: float  # n-weighted mean rows returned per claim
    rearm: int  # Σ H2 skip-and-complete lanes (real work, not overhead)
    empty: int  # Σ pure-overhead claims (returned nothing AND rearmed nothing)

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
    consolidated report (D6). Each log's FIRST claim window is dropped (the ramp window) exactly as
    :func:`aggregate_phase_timing` does; the n-weighted mean is ``Σ(mean×n) / Σn`` (n = claim count), the max
    is the max over windows, lanes/rows-per-claim are n-weighted, and rearm/empty are summed. A
    missing/empty/unreadable log contributes nothing (never raises — a bench report must not crash on a
    truncated log)."""
    claim_num = 0.0
    claim_n = 0
    claim_max = 0.0
    lanes_num = 0.0
    rows_num = 0.0
    rearm = 0
    empty = 0
    windows = 0
    for path in log_paths:
        try:
            text = Path(path).read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        matches = _claim_lines(text)
        if drop_first_window and matches:
            matches = matches[1:]  # drop this shard's first (ramp) window
        for m in matches:
            cn, cm, cmx = int(m.group(1)), float(m.group(2)), float(m.group(3))
            lpc, rpc = float(m.group(4)), float(m.group(5))
            rearm += int(m.group(6))
            empty += int(m.group(7))
            claim_num += cm * cn
            claim_n += cn
            claim_max = max(claim_max, cmx)
            lanes_num += lpc * cn
            rows_num += rpc * cn
            windows += 1
    return ClaimTiming(
        windows=windows,
        claims=claim_n,
        claim_mean_ms=(claim_num / claim_n) if claim_n else 0.0,
        claim_max_ms=claim_max,
        lanes_per_claim=(lanes_num / claim_n) if claim_n else 0.0,
        rows_per_claim=(rows_num / claim_n) if claim_n else 0.0,
        rearm=rearm,
        empty=empty,
    )


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
    ``ingress_rate * dests``."""

    index: int
    ingress_rate: float
    hold_seconds: float
    drain_timeout: float
    is_soak: bool = False

    @property
    def run_suffix(self) -> str:
        return "soak" if self.is_soak else f"r{self.index}"

    def outbound_rate(self, dests: int) -> float:
        return self.ingress_rate * dests


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
    * :attr:`INCONCLUSIVE` — the engine store-truth could NOT be confirmed at all (neither the ENGINE_DRAINED
      drain gate nor the ENGINE_RUNG_REPORT arrived). This is a coordination glitch, NOT proof the fleet
      failed to sustain — so it must NOT be scored as a real COLLAPSED (that would fabricate a false
      bracketed ceiling below the true one). It halts the climb (store-truth is required to certify) but is
      EXCLUDED from the collapse bracket, leaving the pinned rate an honest FLOOR.
    * :attr:`CORRECTNESS_FAIL` — a per-lane FIFO inversion or a duplicate delivery. A hard correctness break
      that FAILs the whole ladder verdict, independent of throughput.
    """

    SUSTAINED = "sustained"
    COLLAPSED = "collapsed"
    FROZEN_TAIL = "frozen_tail"
    INCONCLUSIVE = "inconclusive"
    CORRECTNESS_FAIL = "correctness_fail"


def classify_rung(
    *,
    engine_reported: bool,
    engine_ok: bool,
    no_loss: bool,
    lane_inversions: int,
    lane_repeats: int,
) -> RungVerdict:
    """Classify one rung from the two RELIABLE authorities only. ``engine_reported`` is whether the ENGINE
    store-truth was confirmed at all (from the ENGINE_DRAINED drain gate or the ENGINE_RUNG_REPORT);
    ``engine_ok`` is the store-truth pass bar (``drained ∧ stranded==0 ∧ dead_total==0``); ``no_loss`` is the
    DRIVE sink socket-truth (``S == A*dests ∧ A>0 ∧ S>0``). The remote poller is NEVER an input.

    Order matters: (1) a correctness break (from the always-present sink-truth) outranks everything; (2) an
    UNCONFIRMED engine store-truth is INCONCLUSIVE — a coord glitch, distinct from a proven collapse, so it
    never fabricates a bracketed ceiling; (3) a CONFIRMED non-drained engine is a true COLLAPSE; (4) the
    engine having drained clean, a lossless run is SUSTAINED and a short sink tally is a (benign) frozen
    tail, never collapse."""
    if lane_inversions > 0 or lane_repeats > 0:
        return RungVerdict.CORRECTNESS_FAIL
    if not engine_reported:
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
    dests: int
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
    #: D1: the RELIABLE engine-side drain time (from the ENGINE_DRAINED gate / ENGINE_RUNG_REPORT) — the
    #: authority the verdict already trusts, guaranteed present for a SUSTAINED rung (drained ⇒ drain_s is not
    #: None). Preferred over the advisory ``drive_drain_seconds`` (which "zeroes/misses under load") for the
    #: honest sustainable rate, so a load-correlated drive-poll miss can't drop a sustained rung's ceiling.
    engine_drain_seconds: float | None = None
    notes: tuple[str, ...] = ()

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
        return self.ingress_rate * self.dests

    def outbound_delivered_expected(self) -> int:
        return self.acked * self.dests

    @property
    def sustainable_ingress_rate(self) -> float | None:
        """The HONEST sustainable INGRESS rate this rung actually proves (D1). A SUSTAINED rung only shows
        the engine DELIVERED all ``offered × dests`` messages within ``hold + drain`` — NOT that it kept up
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
        return (
            f"{tag:5} ingress={self.ingress_rate:g}/s outbound={self.outbound_rate():g}/s{sustain} "
            f"offered={self.offered} A={self.acked} S={self.sink_received} "
            f"(expect A*dests={self.outbound_delivered_expected()}) | {eng} | "
            f"inv={self.lane_inversions} rep={self.lane_repeats} lanes={self.lanes_observed}{slope} "
            f"=> {self.verdict.value.upper()}"
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
            "dests": self.dests,
            "hold_seconds": self.hold_seconds,
            "offered_ingress": self.offered,
            "acked": self.acked,
            "sink_received": self.sink_received,
            "outbound_expected": self.outbound_delivered_expected(),
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
                "in_pipeline_final": self.engine_in_pipeline_final,
            },
            "in_pipeline_slope": self.in_pipeline_slope,
            "phase_timing": self.phase.to_json_dict(),
            "claim_timing": self.claim.to_json_dict(),  # D6: the store-claim round-trip #842 could not see
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
        notes.append(
            "engine store-truth UNCONFIRMED (neither ENGINE_DRAINED nor ENGINE_RUNG_REPORT arrived) — "
            "rung is INCONCLUSIVE, NOT a proven collapse (excluded from the ceiling bracket)"
        )
    else:
        engine_ok = bool(truth.get("engine_ok", False))
        engine_drained = bool(truth.get("drained", False))
        engine_stranded = int(truth.get("stranded", -1))
        engine_dead_total = int(truth.get("dead_total", -1))
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
    if report is not None:
        raw_slope = report.get("in_pipeline_slope")
        slope = None if raw_slope is None else float(raw_slope)
        phase_raw = report.get("phase_timing")
        if isinstance(phase_raw, Mapping):
            phase = PhaseTiming.from_json_dict(phase_raw)
        claim_raw = report.get("claim_timing")  # D6: the store-claim round-trip aggregate
        if isinstance(claim_raw, Mapping):
            claim = ClaimTiming.from_json_dict(claim_raw)
        for note in report.get("notes", []) or []:
            notes.append(f"engine: {note}")
    elif engine_reported:
        notes.append("engine phase timing / soak slope absent (ENGINE_RUNG_REPORT not read)")

    verdict = classify_rung(
        engine_reported=engine_reported,
        engine_ok=engine_ok,
        no_loss=drive.no_loss,
        lane_inversions=drive.lane_inversions,
        lane_repeats=drive.lane_repeats,
    )
    return RungOutcome(
        index=rung.index,
        is_soak=rung.is_soak,
        ingress_rate=rung.ingress_rate,
        dests=drive.dests,
        hold_seconds=rung.hold_seconds,
        offered=drive.offered,
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
        engine_in_pipeline_final=engine_in_pipeline_final,
        in_pipeline_slope=slope,
        phase=phase,
        claim=claim,
        engine_drain_seconds=engine_drain_seconds,
        verdict=verdict,
        notes=tuple(notes),
    )


def pick_soak_rate(records: Sequence[RungOutcome], override: float | None = None) -> float | None:
    """The soak rate: an explicit ``override`` if given, else the highest HONEST SUSTAINABLE rate any
    SUSTAINED climb rung actually proved (:attr:`RungOutcome.sustainable_ingress_rate`). ``None`` when
    nothing sustained (⇒ the ladder skips the soak and says so).

    B8: this used to select the rung's raw OFFERED ``ingress_rate``, which is not a sustainable rate. A climb
    rung is a VOLUME test — a SUSTAINED rung proves only that the fleet DELIVERED ``offered × dests`` within
    ``hold + drain``, never that it kept up at ``ingress_rate`` in real time. The offered rate overstates the
    honest one by ``(hold + drain) / hold`` (see :attr:`sustainable_ingress_rate`).

    Worse, ``max()`` over OFFERED rates selects the HIGHEST sustained rung — which is the rung with the
    LONGEST drain, i.e. the MOST overstated estimator on the whole ladder. The soak then offers a rate the
    fleet was never shown to sustain and collapses by construction. And a long soak amortizes the drain
    discount away (at ``hold=900`` the overstatement factor is ~1.03, not ~2.8), so nothing is left to hide
    it: the collapse looks real. Observed on the pooled ceiling re-run — offered climb pinned at 36/s while
    the honest rate sat flat at ~13/s across every rung, so the auto-picked 900s soak ran at ~2.8x
    sustainable. Selecting on the drain-discounted rate picks the operating point the climb actually proved.

    A rung whose drain was never measured yields ``None`` (an unmeasured span cannot denominate a rate) and
    is skipped. For a SUSTAINED rung the engine-side drain is guaranteed present, so this cannot silently
    empty the candidate set and turn a real ceiling into a skipped soak."""
    if override is not None:
        return override
    proved = [
        r.sustainable_ingress_rate
        for r in records
        if not r.is_soak and r.verdict is RungVerdict.SUSTAINED
    ]
    measured = [rate for rate in proved if rate is not None]
    return max(measured) if measured else None


@dataclass
class ConsolidatedLadderReport:
    """The whole ladder's consolidated verdict — the ONE report the drive box emits. Per-rung records +
    the pinned ceiling (in BOTH ingress and outbound terms) + the soak + the phase split."""

    shards: tuple[str, ...]
    dests: int
    driver_count: int
    sink_count: int
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
    def pinned_ingress_rate(self) -> float | None:
        """The pinned HONEST sustainable-ingress ceiling (D1): the highest per-rung
        ``sustainable_ingress_rate`` (offered spread over hold + MEASURED drain) over the SUSTAINED climb
        rungs — NOT the raw offered ``ingress_rate``. The raw offered rate overstates the sustainable rate by
        ``(hold + drain) / hold`` because a SUSTAINED rung merely DELIVERED all offered messages within
        hold + drain; it never proved it KEPT UP at the offered rate. A floor if the climb never collapsed.
        ``None`` if no rung sustained (or none had a measured drain to compute an honest rate)."""
        honest = [
            r.sustainable_ingress_rate
            for r in self.climb
            if r.verdict is RungVerdict.SUSTAINED and r.sustainable_ingress_rate is not None
        ]
        return max(honest) if honest else None

    @property
    def pinned_outbound_rate(self) -> float | None:
        p = self.pinned_ingress_rate
        return None if p is None else p * self.dests

    @property
    def pinned_rung(self) -> RungOutcome | None:
        """The SUSTAINED climb rung whose HONEST ``sustainable_ingress_rate`` IS the pinned ceiling — the
        rung ``pinned_ingress_rate`` reports. ``None`` if nothing sustained with a measured drain."""
        candidates = [
            r
            for r in self.climb
            if r.verdict is RungVerdict.SUSTAINED and r.sustainable_ingress_rate is not None
        ]
        if not candidates:
            return None
        return max(candidates, key=lambda r: r.sustainable_ingress_rate or 0.0)

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
        a coord glitch) can NEVER fabricate a collapse bracket below the real ceiling."""
        collapsed = [
            r.ingress_rate
            for r in self.climb
            if r.verdict is RungVerdict.COLLAPSED and r.engine_reported
        ]
        return min(collapsed) if collapsed else None

    @property
    def ceiling_bracketed(self) -> bool:
        """A real ceiling was pinned (a sustained rung with a collapse above it), vs a floor-only climb
        (nothing collapsed ⇒ the ceiling is unpinned above the top rung — raise the ladder)."""
        return self.pinned_ingress_rate is not None and self.first_collapse_ingress_rate is not None

    @property
    def sustained_events_per_s(self) -> float | None:
        """The pinned SUSTAINED rate expressed in TOTAL message events/s — the currency the 45M/day budget
        is denominated in. One ingress message yields itself plus one event per destination."""
        p = self.pinned_ingress_rate
        return None if p is None else p * (1 + self.dests)

    @property
    def clears_target_events(self) -> bool:
        """Whether the pinned SUSTAINED rate clears the 45M/day = ~521 TOTAL events/s target. This is the
        number the §8 N-active decision keys off — but the bench only REPORTS it; the owner decides.

        B10: this used to compare a pure ingress rate against the total-events budget, making the gate
        ``(1 + dests)``x too strict (9x at the bench default ``dests=8``)."""
        e = self.sustained_events_per_s
        return e is not None and e >= TARGET_EVENTS_PER_S

    @property
    def soak_ok(self) -> bool:
        """The soak (if run) HELD by the two RELIABLE authorities ALONE: its verdict is SUSTAINED — which
        already encodes the engine store-truth (drained ∧ stranded==0 ∧ dead==0) AND the drive sink
        socket-truth (no_loss). The in_pipeline slope is REPORTED as advisory context (render's flat/GROWING
        label) but is NOT gated on (B5): the D4-de-inflated slope proved SIGN-UNSTABLE across rates and read
        False on runs passing both authorities. Saturation is instead caught by verdict==SUSTAINED requiring
        the backlog to DRAIN inside the bounded soak window (D2). No soak ⇒ vacuously False."""
        if self.soak is None:
            return False
        return self.soak.verdict is RungVerdict.SUSTAINED

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
        """A CLIMB rung's ENGINE store-truth never arrived (INCONCLUSIVE — neither the ENGINE_DRAINED gate
        nor the ENGINE_RUNG_REPORT). Like a rendezvous abort, this is a coord/infra DEGRADATION, not a clean
        bench result — nothing was certified — so it must NOT read as a PASS. (A soak-only inconclusive is
        supplementary and does not trip this — the climb still pinned the ceiling.)"""
        return any(r.verdict is RungVerdict.INCONCLUSIVE for r in self.climb)

    @property
    def setup_degraded(self) -> bool:
        """The run hit a two-box coord/infra degradation (a climb OR soak rendezvous abort, or an unconfirmed
        store-truth), NOT a clean measurement — surfaced as exit 2 so an exit-code-gated harness never reads
        it as PASS."""
        return self.climb_aborted or self.soak_aborted or self.store_truth_unconfirmed

    @property
    def soak_store_truth_unconfirmed(self) -> bool:
        """B9: a soak RAN, but its ENGINE store-truth never arrived (INCONCLUSIVE — neither the ENGINE_DRAINED
        gate nor the ENGINE_RUNG_REPORT). Nothing was proven about the soak either way: it is UNKNOWN, not
        proven-failed.

        Deliberately NOT folded into :attr:`setup_degraded`, because :attr:`store_truth_unconfirmed` already
        rules that "a soak-only inconclusive is supplementary ... the climb still pinned the ceiling" — so it
        stays exit 0. But it must not read as a PASS either, hence its own ``SOAK_UNCONFIRMED`` label."""
        return (
            self.soak is not None
            and not self.soak_aborted
            and self.soak.verdict is RungVerdict.INCONCLUSIVE
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
        signal: the offered operating point was not sustainable over the long hold."""
        return (
            self.soak is not None
            and not self.soak_aborted
            and self.soak.verdict is not RungVerdict.INCONCLUSIVE
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

        * ``SETUP_DEGRADED`` — not a bench result (exit 2).
        * ``FAIL`` — a correctness break: FIFO inversion or duplicate delivery (exit 1).
        * ``SOAK_NOT_SUSTAINED`` — correctness held, and the soak's store-truth was CONFIRMED and did not
          hold (exit 0; a product measurement, not a correctness failure). **Do not quote this run's pinned
          ceiling** — it comes from the short climb, which this soak just disproved.
        * ``SOAK_UNCONFIRMED`` — correctness held, but the soak's store-truth never arrived (exit 0). Nothing
          was proven about the soak; re-run it. Neither a pass nor a proven saturation.
        * ``PASS`` — correctness held, and the soak either sustained or was legitimately skipped."""
        if self.setup_degraded:
            return "SETUP_DEGRADED"
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
            f"  topology: shards={'/'.join(self.shards)} dests={self.dests} "
            f"K={self.driver_count} senders x M={self.sink_count} sinks   "
            f"(delivered = ingress x dests; total events = ingress x (1 + dests))",
            "",
            "  climb (ascending ingress rate; stops at the first collapse):",
        ]
        for r in self.climb:
            lines.append("    " + r.render())
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
            fc = self.first_collapse_ingress_rate
            if fc is not None:
                lines.append(
                    f"    first collapse at: {fc:g} ingress/s = {fc * self.dests:g} outbound/s"
                )
            ev = self.sustained_events_per_s
            lines.append(
                f"    clears {TARGET_EVENTS_PER_S:.1f}/s TOTAL-EVENTS target? "
                f"{'YES' if self.clears_target_events else 'NO'} "
                f"({pin:g} ingress/s x (1 + {self.dests} dests) = {ev:g} events/s "
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
            lines.append(
                f"  soak ({self.soak.hold_seconds:g}s @ {self.soak.ingress_rate:g} ingress/s): "
                f"{self.soak.verdict.value.upper()}  in_pipeline slope={slope_txt} ({drain})  "
                f"-> soak_ok={self.soak_ok}"
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
        if self.setup_degraded:
            if self.climb_aborted:
                reason = "two-box rendezvous/timeout broke mid-run"
            elif self.soak_aborted:
                reason = "two-box rendezvous/timeout broke during the soak — soak not measured"
            else:
                reason = "engine store-truth never confirmed (INCONCLUSIVE) — nothing certified"
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
                lines.append(
                    f"        SOAK NOT SUSTAINED (soak verdict={self.soak.verdict.value} @ "
                    f"{self.soak.ingress_rate:g}/s ingress over {self.soak.hold_seconds:g}s) — the offered "
                    "operating point did NOT hold. Do not quote this run's pinned ceiling."
                )
            elif self.soak_store_truth_unconfirmed and self.soak is not None:
                # NOT "did not hold" — nothing was proven either way. Asserting a negative here would be the
                # same fabrication B6/B7 were about.
                lines.append(
                    f"        SOAK UNCONFIRMED (store-truth never arrived @ {self.soak.ingress_rate:g}/s "
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
            "schema_version": 3,
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
                "dests": self.dests,
                "driver_count": self.driver_count,
                "sink_count": self.sink_count,
            },
            "target_events_per_s": round(TARGET_EVENTS_PER_S, 3),
            "ceiling": {
                # D1: honest sustainable rate (offered spread over hold + MEASURED drain), not the inflated
                # raw offered ingress_rate. clears_target_events keys off pinned_ingress_rate x (1 + dests).
                "pinned_ingress_rate": (
                    None if self.pinned_ingress_rate is None else round(self.pinned_ingress_rate, 3)
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
                "first_collapse_ingress_rate": self.first_collapse_ingress_rate,
                "bracketed": self.ceiling_bracketed,
                # B10: total events = ingress x (1 + dests). Gate on events, never on ingress alone.
                "sustained_events_per_s": (
                    None
                    if self.sustained_events_per_s is None
                    else round(self.sustained_events_per_s, 3)
                ),
                "clears_target_events": self.clears_target_events,
            },
            "soak": None if self.soak is None else self.soak.to_json_dict(),
            "soak_ok": self.soak_ok,
            "climb": [r.to_json_dict() for r in self.climb],
            "notes": self.notes,
        }


def build_consolidated_report(
    *,
    shards: Sequence[str],
    dests: int,
    driver_count: int,
    sink_count: int,
    climb: Sequence[RungOutcome],
    soak: RungOutcome | None,
    notes: Sequence[str] = (),
    climb_aborted: bool = False,
    soak_aborted: bool = False,
) -> ConsolidatedLadderReport:
    """Assemble the consolidated report from the driven rung outcomes — a thin, PURE constructor so the
    report shape can be unit-tested from synthetic outcomes without a live fleet."""
    return ConsolidatedLadderReport(
        shards=tuple(shards),
        dests=dests,
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
        "notes": list(report.notes),
    }


def _attach_rung_timings(payload: dict[str, object], rung_logs: Sequence[Path]) -> None:
    """Attach BOTH phase-timing aggregates to an ENGINE_RUNG_REPORT payload from the rung's per-shard node
    logs: the delivery ``send_ack``/``mark_done`` split (``phase_timing``) AND the CLAIM store round-trip
    (``claim_timing``, D6 — the phase #842 could not see). The claim aggregate is a SIBLING of phase_timing,
    gated by the same ``MEFOR_DELIVERY_PHASE_TIMING`` lever; BOTH must be attached or the drive box's claim
    aggregate stays empty despite the node logs carrying the claim lines."""
    payload["phase_timing"] = aggregate_phase_timing(rung_logs).to_json_dict()
    payload["claim_timing"] = aggregate_claim_timing(rung_logs).to_json_dict()


async def run_engine_ladder(
    *,
    rates: Sequence[float],
    dests: int,
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
    soak_hold_seconds: float = 300.0,
    soak_drain_timeout: float = 300.0,
    climb_drive_start_timeout: float = 300.0,
    soak_drive_start_timeout: float = 300.0,
    stop_poll_grace: float = 10.0,
    post_drain_grace: float = 8.0,
    soak_timeout: float = 900.0,
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
    bounded plan still finishes (the CoordTimeout branch below re-checks STOP)."""
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
    sink_count: int,
    sink_host: str,
    base_coord: FileDropCoord,
    allow_insecure: bool = False,
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
    climbing. Then picks the soak rate, posts LADDER_SOAK, drives the soak, and builds the report."""
    climb = plan_climb_rungs(rates, hold_seconds=hold_seconds, drain_timeout=drain_timeout)
    # Clear cross-rung signals so a re-run under the same base run_id doesn't read a stale STOP/SOAK.
    base_coord.clear_messages(LADDER_STOP, LADDER_SOAK)

    outcomes: list[RungOutcome] = []
    notes: list[str] = []
    shards: tuple[str, ...] = ()
    dests = 0

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
        dests = drive.dests
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
        notes.append("no soak (no sustained rung / soak disabled)")
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
                shards, dests = drive.shards, drive.dests
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
        driver_count=driver_count,
        sink_count=sink_count,
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
