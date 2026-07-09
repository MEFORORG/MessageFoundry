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

The **target** is the 45M-messages/day figure = 45_000_000 / 86_400 ≈ **520.83 msg/s of INGRESS**
(:data:`TARGET_INGRESS_PER_S`). Because every accepted message fans out to ``dests`` destinations,
``delivered = ingress * dests``, so the report always states BOTH figures and is explicit that 521/s is
measured against INGRESS, not the outbound delivery rate.
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

#: 45M messages/day, expressed as the sustained INGRESS rate the ladder pins against.
TARGET_INGRESS_PER_S = 45_000_000 / 86_400  # ≈ 520.833…

#: A slope (in_pipeline rows per second over the soak hold) at or below this magnitude reads as
#: "flat or draining" — a sustainable plateau. Above it, the backlog is growing = slow saturation.
_SLOPE_FLAT_TOL = 1.0

#: The phase-timing INFO line the bench-gated ``MEFOR_DELIVERY_PHASE_TIMING`` lever emits per window (from
#: ``messagefoundry.pipeline.wiring_runner``). Same shape the rig's ``aggregate.py`` parsed.
_PHASE_RE = re.compile(
    r"send_ack n=(\d+) mean=([\d.]+)ms max=([\d.]+)ms "
    r"\| mark_done n=(\d+) mean=([\d.]+)ms max=([\d.]+)ms"
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
    notes: tuple[str, ...] = ()

    def outbound_rate(self) -> float:
        return self.ingress_rate * self.dests

    def outbound_delivered_expected(self) -> int:
        return self.acked * self.dests

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
        return (
            f"{tag:5} ingress={self.ingress_rate:g}/s outbound={self.outbound_rate():g}/s "
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
        if gate is None:
            notes.append(
                "engine store-truth from ENGINE_RUNG_REPORT (drain gate absent — degraded)"
            )

    # Phase timing + the soak in_pipeline slope live ONLY on ENGINE_RUNG_REPORT (the gate has neither).
    slope: float | None = None
    phase = PhaseTiming(0, 0, 0.0, 0.0, 0.0, 0.0)
    if report is not None:
        raw_slope = report.get("in_pipeline_slope")
        slope = None if raw_slope is None else float(raw_slope)
        phase_raw = report.get("phase_timing")
        if isinstance(phase_raw, Mapping):
            phase = PhaseTiming.from_json_dict(phase_raw)
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
        verdict=verdict,
        notes=tuple(notes),
    )


def pick_soak_rate(records: Sequence[RungOutcome], override: float | None = None) -> float | None:
    """The soak rate: an explicit ``override`` if given, else the highest SUSTAINED climb rung's ingress
    rate (the "supported operating point" — the last rung that held losslessly AND drained clean). ``None``
    when there is nothing sustained to soak (⇒ the ladder skips the soak and says so)."""
    if override is not None:
        return override
    sustained = [
        r.ingress_rate for r in records if not r.is_soak and r.verdict is RungVerdict.SUSTAINED
    ]
    return max(sustained) if sustained else None


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

    # --- derived measurements (the ceiling is a MEASUREMENT; only correctness fails the verdict) ---

    @property
    def all_records(self) -> list[RungOutcome]:
        return [*self.climb, *([self.soak] if self.soak is not None else [])]

    @property
    def pinned_ingress_rate(self) -> float | None:
        """The highest SUSTAINED climb-rung ingress rate — the pinned sustainable ceiling (a floor if the
        climb never collapsed). ``None`` if no rung sustained."""
        sustained = [r.ingress_rate for r in self.climb if r.verdict is RungVerdict.SUSTAINED]
        return max(sustained) if sustained else None

    @property
    def pinned_outbound_rate(self) -> float | None:
        p = self.pinned_ingress_rate
        return None if p is None else p * self.dests

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
    def clears_target_ingress(self) -> bool:
        """Whether the pinned SUSTAINED ingress rate clears the 45M/day = ~521 msg/s INGRESS target. This
        is the number the §8 N-active decision keys off — but the bench only REPORTS it; the owner decides."""
        p = self.pinned_ingress_rate
        return p is not None and p >= TARGET_INGRESS_PER_S

    @property
    def soak_ok(self) -> bool:
        """The soak (if run) held: SUSTAINED and its in_pipeline slope is flat/draining (not slow
        saturation). No soak ⇒ vacuously False (nothing to certify)."""
        if self.soak is None:
            return False
        return self.soak.verdict is RungVerdict.SUSTAINED and slope_is_draining(
            self.soak.in_pipeline_slope
        )

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
        """The run hit a two-box coord/infra degradation (a rendezvous abort or an unconfirmed store-truth),
        NOT a clean measurement — surfaced as exit 2 so an exit-code-gated harness never reads it as PASS."""
        return self.climb_aborted or self.store_truth_unconfirmed

    @property
    def ok(self) -> bool:
        """Correctness held (the throughput ceiling is a measurement, not a pass/fail). A setup degradation
        is surfaced via ``exit_code`` (2), not by flipping ``ok``."""
        return self.correctness_ok

    @property
    def exit_code(self) -> int:
        """0 (correctness held) / 1 (a correctness break) / 2 (a setup degradation — a two-box rendezvous
        abort OR an unconfirmed store-truth — so a mid-run infra glitch or a nothing-certified run never
        reads as a PASS)."""
        if self.setup_degraded:
            return 2
        return 0 if self.ok else 1

    def render(self) -> str:
        lines = [
            "ShardCert two-box SIZING ladder — pin the post-#842 delivered ceiling vs the 521/s ingress "
            "target (45M/day)",
            f"  topology: shards={'/'.join(self.shards)} dests={self.dests} "
            f"K={self.driver_count} senders x M={self.sink_count} sinks   "
            f"(delivered = ingress x dests; 521/s target is INGRESS)",
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
            lines.append(
                f"  pinned sustainable ceiling: {pin:g} ingress/s = {out:g} outbound/s"
                + (
                    ""
                    if self.ceiling_bracketed
                    else "  (FLOOR — climb never collapsed; raise the ladder)"
                )
            )
            fc = self.first_collapse_ingress_rate
            if fc is not None:
                lines.append(
                    f"    first collapse at: {fc:g} ingress/s = {fc * self.dests:g} outbound/s"
                )
            lines.append(
                f"    clears 521/s INGRESS target? {'YES' if self.clears_target_ingress else 'NO'} "
                f"({pin:g} vs {TARGET_INGRESS_PER_S:.1f} ingress/s)"
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
        else:
            lines.append("  soak: (skipped — no sustained rung to soak)")
        lines.append("")
        lines.append("  per-rung phase timing (send_ack vs mark_done, n-weighted):")
        for r in self.all_records:
            tag = "soak" if r.is_soak else f"r{r.index}"
            lines.append(f"    {tag:5} {r.phase.render()}")
        for note in self.notes:
            lines.append(f"  note: {note}")
        lines.append("")
        if self.setup_degraded:
            reason = (
                "two-box rendezvous/timeout broke mid-run"
                if self.climb_aborted
                else "engine store-truth never confirmed (INCONCLUSIVE) — nothing certified"
            )
            lines.append(
                f"RESULT: SETUP-DEGRADED ({reason} — NOT a bench result) -> exit {self.exit_code}"
            )
        else:
            lines.append(
                f"RESULT: {'PASS' if self.ok else 'FAIL'} (correctness) -> exit {self.exit_code}"
            )
        return "\n".join(lines)

    def to_json_dict(self) -> dict[str, object]:
        return {
            "schema_version": 1,
            "kind": "shardcert_ladder_two_box",
            "result": "SETUP_DEGRADED" if self.setup_degraded else ("PASS" if self.ok else "FAIL"),
            "exit_code": self.exit_code,
            "climb_aborted": self.climb_aborted,
            "store_truth_unconfirmed": self.store_truth_unconfirmed,
            "topology": {
                "shards": list(self.shards),
                "dests": self.dests,
                "driver_count": self.driver_count,
                "sink_count": self.sink_count,
            },
            "target_ingress_per_s": round(TARGET_INGRESS_PER_S, 3),
            "ceiling": {
                "pinned_ingress_rate": self.pinned_ingress_rate,
                "pinned_outbound_rate": self.pinned_outbound_rate,
                "first_collapse_ingress_rate": self.first_collapse_ingress_rate,
                "bracketed": self.ceiling_bracketed,
                "clears_target_ingress": self.clears_target_ingress,
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
        "notes": list(report.notes),
    }


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
        rung_coord.clear_messages(SHARDS_READY, DRIVE_START, ENGINE_DRAINED, ENGINE_RUNG_REPORT)
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
        payload["phase_timing"] = aggregate_phase_timing(
            _rung_log_paths(keep_dir, report.shards)
        ).to_json_dict()
        rung_coord.post(ENGINE_RUNG_REPORT, payload)
        result.rungs_armed.append(rung.run_suffix)

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
    soak_coord.clear_messages(SHARDS_READY, DRIVE_START, ENGINE_DRAINED, ENGINE_RUNG_REPORT)
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
            sample_in_pipeline=True,
        )
    except CoordTimeout:
        result.notes.append("soak: no DRIVE_START from the drive")
        return result
    payload = _engine_rung_payload(report)
    payload["phase_timing"] = aggregate_phase_timing(
        _rung_log_paths(keep_dir, report.shards)
    ).to_json_dict()
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
    engine_drained_timeout: float = 300.0,
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
            notes.append(
                f"{rung.run_suffix}: drive aborted ({exc}) — posted LADDER_STOP, setup-abort"
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
            # A soak rendezvous failure is noted but does NOT set climb_aborted — the CLIMB already pinned
            # the ceiling; the soak is supplementary.
            notes.append(f"soak: drive aborted ({exc}) — soak inconclusive")

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
