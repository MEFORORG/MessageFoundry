# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""The pipeline-claim-mode A/B comparison (ADR 0066) — per_lane vs pooled, per connection count.

The claim-storm collapse is an ENGINE-SIDE phenomenon, so the primary differentiator counters already
exist per record (achieved throughput, ACK percentiles, the SEPARATED empty-claim rates, pool-wait,
CPU/FD footprint). This module reads a connscale run's records — which now carry a ``claim_mode`` tag
— groups them by ``(sweep_mode, count)`` and lays the ``per_lane`` (baseline) and ``pooled``
(candidate) arms side by side, computing three guards:

* **candidate zero-loss** (the hard guard) — the pooled arm must NOT breach the at-least-once
  reconcile (``no_loss.ok``) at any count. A pooled arm that dropped messages FAILS the row outright,
  independent of throughput. This is the authoritative signal: it reads the independent sink counter,
  not the ``/stats`` achieved-rate poller that zeroes under overload.
* **throughput non-regression** — the pooled arm's achieved intake msg/s must be >= the per_lane arm's
  within a tolerance at EVERY count (pooled must not cost throughput to buy the footprint collapse).
  *Only judged where the comparison is SOUND* — i.e. both arms held zero-loss. When the ``per_lane``
  baseline itself breached zero-loss it was drowning and its achieved rate is a poller-zeroed phantom;
  the row is then reported as a **resilience win** (per_lane broke, pooled held), NOT as a vacuous
  throughput pass against a zero baseline. If no count has a sound baseline, the summary reports
  ``throughput_non_regression = null`` (inconclusive), never a phantom ``True``.
* **idle-poll collapse** — the pooled arm's ``empty_claims_idle_poll`` rate should be *materially*
  lower than per_lane's (the thundering-herd re-SELECT floor is what pooled dispatchers collapse: K
  batch-claimers per stage vs ~one worker per lane). Only asserted where per_lane's idle-poll rate
  clears a noise floor; below it the collapse is negligible-either-way and reported inconclusive.

A **missing pooled arm** (the engine refused to start — e.g. SQL Server ``READ_COMMITTED_SNAPSHOT``
OFF under the fail-closed ``require_rcsi_for_pooled`` gate) is detected structurally (a baseline
``(sweep_mode, count)`` with no pooled record) and reported LOUDLY as a failing row — never silently
compared against nothing.

Metrics + metadata only (no message bodies / control-ids) — pure + deterministic, unit-testable.
"""

from __future__ import annotations

import math
import statistics
from collections.abc import Callable
from dataclasses import dataclass, field

from harness.load.connscale.profile import FUSE_OFF, FUSE_ON
from harness.load.connscale.report import ConnScaleRecord

BASELINE_MODE = "per_lane"
CANDIDATE_MODE = "pooled"

#: The pooled arm's achieved intake msg/s must be >= the per_lane arm's × (1 - this) at every count.
DEFAULT_THROUGHPUT_TOLERANCE = 0.10
#: "Materially lower" bar for the idle-poll collapse: pooled idle-poll/s <= per_lane × this ⇒ PASS.
DEFAULT_COLLAPSE_MATERIAL_RATIO = 0.50
#: Below this per_lane idle-poll rate the collapse is negligible either way ⇒ INCONCLUSIVE (avoids a
#: noisy near-zero measurement flipping the verdict).
DEFAULT_IDLE_FLOOR_PER_S = 5.0

# Collapse verdict labels.
COLLAPSE_PASS = "PASS"  # pooled materially lower (<= material ratio)
COLLAPSE_WARN = "WARN"  # pooled lower, but not materially (between material ratio and 1.0)
COLLAPSE_FAIL = "FAIL"  # pooled NOT lower (>= per_lane) where per_lane cleared the floor
COLLAPSE_INCONCLUSIVE = "INCONCLUSIVE"  # per_lane idle-poll below the noise floor
COLLAPSE_MISSING = "MISSING"  # no pooled arm to compare


@dataclass(frozen=True)
class _ArmMetrics:
    """One arm's read-off for a ``(sweep_mode, count)`` cell (all from the tagged record)."""

    claim_mode: str
    achieved_read_per_s: float
    achieved_written_per_s: float
    idle_poll_per_s: float
    wake_fanout_per_s: float
    ack_p99_ms: float
    pool_wait_p99_ms: float | None
    cpu_seconds_total: float | None
    cpu_util_cores_mean: float | None
    fd_count_peak: int | None
    working_set_peak_bytes: int | None
    # --- loss reconcile (the AUTHORITATIVE signal; from the independent sink counter, NOT the
    # /stats achieved-rate poller that zeroes under overload — see the report's reading caveat). ---
    no_loss_ok: bool
    sent: int
    sink_received: int
    backlog: int
    no_loss_detail: str

    @classmethod
    def from_record(cls, r: ConnScaleRecord) -> _ArmMetrics:
        return cls(
            claim_mode=r.claim_mode,
            achieved_read_per_s=r.achieved_read_per_s,
            achieved_written_per_s=r.achieved_written_per_s,
            idle_poll_per_s=r.idle_poll_per_s,
            wake_fanout_per_s=r.wake_fanout_per_s,
            ack_p99_ms=r.ack_p99_ms,
            pool_wait_p99_ms=r.pool_wait_p99_ms,
            cpu_seconds_total=r.cpu_seconds_total,
            cpu_util_cores_mean=r.cpu_util_cores_mean,
            fd_count_peak=r.fd_count_peak,
            working_set_peak_bytes=r.working_set_peak_bytes,
            no_loss_ok=r.no_loss.ok,
            sent=r.no_loss.sent,
            sink_received=r.no_loss.sink_received,
            backlog=r.no_loss.backlog,
            no_loss_detail=r.no_loss.detail,
        )


@dataclass(frozen=True)
class ComparisonRow:
    """The per_lane-vs-pooled comparison at one ``(sweep_mode, count)`` step."""

    sweep_mode: str
    count: int
    baseline: _ArmMetrics
    candidate: _ArmMetrics | None  # None ⇒ the pooled arm is MISSING (failed to start)
    pooled_missing: bool
    throughput_ok: bool
    throughput_delta_pct: float | None
    collapse_verdict: str
    collapse_delta_pct: float | None
    collapse_ratio: float | None
    # Loss reconcile: ``candidate_lost`` ⇒ the pooled arm breached zero-loss (hard fail).
    # ``throughput_comparable`` ⇒ both arms held zero-loss, so the achieved-rate delta is sound
    # (a breached baseline has a poller-zeroed achieved rate the throughput guard must not read).
    candidate_lost: bool = False
    throughput_comparable: bool = True
    missing_detail: str = ""

    @property
    def resilience_win(self) -> bool:
        """per_lane breached zero-loss but pooled held it — the 'pooled survives, per_lane breaks'
        outcome the poller-zeroed throughput delta cannot show."""
        return not self.pooled_missing and not self.baseline.no_loss_ok and not self.candidate_lost

    @property
    def ok(self) -> bool:
        """A row passes when the pooled arm exists, held zero-loss, the idle-poll collapse did not
        fail (a WARN / INCONCLUSIVE collapse does not fail the run — only a genuine NO-collapse where
        per_lane cleared the floor does), and throughput did not regress *where the comparison is
        sound*. A baseline that itself breached zero-loss yields no sound throughput comparison, so
        the row passes on the resilience basis (pooled held) rather than on a phantom-zero delta."""
        if self.pooled_missing or self.candidate_lost:
            return False
        if self.collapse_verdict == COLLAPSE_FAIL:
            return False
        if self.throughput_comparable and not self.throughput_ok:
            return False
        return True


@dataclass(frozen=True)
class ClaimModeComparison:
    """The full A/B: one :class:`ComparisonRow` per ``(sweep_mode, count)``, plus the guard config and
    an overall verdict."""

    baseline_mode: str
    candidate_mode: str
    throughput_tolerance: float
    collapse_material_ratio: float
    idle_floor_per_s: float
    rows: list[ComparisonRow] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return all(row.ok for row in self.rows) and bool(self.rows)

    @property
    def missing_arms(self) -> int:
        return sum(1 for row in self.rows if row.pooled_missing)

    @property
    def candidate_zero_loss_ok(self) -> bool:
        """The hard guard: every PRESENT pooled arm held zero-loss (none dropped a message)."""
        return not any(row.candidate_lost for row in self.rows)

    @property
    def baseline_zero_loss_breaches(self) -> int:
        """Counts where per_lane breached the at-least-once reconcile (context for the resilience
        story; it also marks those counts' throughput comparison unsound)."""
        return sum(1 for row in self.rows if not row.baseline.no_loss_ok)

    @property
    def resilience_wins(self) -> int:
        """Counts where per_lane breached zero-loss but pooled held it."""
        return sum(1 for row in self.rows if row.resilience_win)

    @property
    def throughput_non_regression(self) -> bool | None:
        """Aggregate throughput verdict over ONLY the counts with a sound comparison (both arms held
        zero-loss). ``None`` (inconclusive) when no count qualifies — so a run where every per_lane
        baseline drowned reports ``null``, never a phantom ``True`` compared against a zeroed rate."""
        comparable = [r for r in self.rows if r.throughput_comparable and not r.pooled_missing]
        return all(r.throughput_ok for r in comparable) if comparable else None

    @property
    def worst_collapse(self) -> str:
        """The worst collapse verdict across rows (for the one-line summary)."""
        order = [
            COLLAPSE_MISSING,
            COLLAPSE_FAIL,
            COLLAPSE_WARN,
            COLLAPSE_INCONCLUSIVE,
            COLLAPSE_PASS,
        ]
        seen = {row.collapse_verdict for row in self.rows}
        for verdict in order:
            if verdict in seen:
                return verdict
        return COLLAPSE_INCONCLUSIVE

    def to_json_dict(self) -> dict[str, object]:
        return {
            "kind": "claim_mode_ab",
            "baseline": self.baseline_mode,
            "candidate": self.candidate_mode,
            "guards": {
                "throughput_tolerance": self.throughput_tolerance,
                "collapse_material_ratio": self.collapse_material_ratio,
                "idle_floor_per_s": self.idle_floor_per_s,
            },
            "overall_ok": self.ok,
            "summary": {
                "candidate_zero_loss_ok": self.candidate_zero_loss_ok,
                "throughput_non_regression": self.throughput_non_regression,
                "baseline_zero_loss_breaches": self.baseline_zero_loss_breaches,
                "resilience_wins": self.resilience_wins,
                "worst_collapse": self.worst_collapse,
                "missing_arms": self.missing_arms,
            },
            "rows": [_row_json(row) for row in self.rows],
            "notes": self.notes,
        }

    def render_table(self) -> str:
        lines: list[str] = []
        lines.append(
            f"Claim-mode A/B (ADR 0066) -- baseline {self.baseline_mode!r} vs "
            f"candidate {self.candidate_mode!r}"
        )
        lines.append(
            f"guards: throughput non-regression (pooled >= per_lane * "
            f"{1.0 - self.throughput_tolerance:.2f}) | idle-poll collapse "
            f"(pooled <= per_lane * {self.collapse_material_ratio:.2f} where per_lane > "
            f"{self.idle_floor_per_s:.1f}/s)"
        )
        overall = "PASS" if self.ok else "FAIL"
        lines.append(
            f"overall: {overall}  (candidate_zero_loss_ok={self.candidate_zero_loss_ok}, "
            f"throughput_non_regression={_tnr_label(self.throughput_non_regression)}, "
            f"resilience_wins={self.resilience_wins}, worst_collapse={self.worst_collapse}, "
            f"missing_arms={self.missing_arms})"
        )
        for row in self.rows:
            lines.append("")
            lines.append(f"[{row.sweep_mode}] N={row.count}")
            if row.pooled_missing:
                lines.append(
                    f"  POOLED ARM MISSING -- {row.missing_detail or 'engine did not start'}"
                )
                lines.append(
                    f"  achieved_read/s        per_lane={row.baseline.achieved_read_per_s:.2f}  "
                    f"pooled=n/a   (no comparison)"
                )
                continue
            cand = row.candidate
            assert cand is not None  # not pooled_missing ⇒ candidate present
            b = row.baseline
            lines.append(
                f"  achieved_read/s        per_lane={b.achieved_read_per_s:>9.2f}  "
                f"pooled={cand.achieved_read_per_s:>9.2f}  "
                f"{_delta(row.throughput_delta_pct):>9}  "
                f"throughput: {'OK' if row.throughput_ok else 'REGRESS'}"
            )
            lines.append(
                f"  idle_poll/s            per_lane={b.idle_poll_per_s:>9.2f}  "
                f"pooled={cand.idle_poll_per_s:>9.2f}  "
                f"{_delta(row.collapse_delta_pct):>9}  "
                f"collapse: {row.collapse_verdict}"
            )
            lines.append(
                f"  zero_loss              per_lane={_yn(b.no_loss_ok):>9}  "
                f"pooled={_yn(cand.no_loss_ok):>9}  {'':>9}  loss: {_loss_label(row)}"
            )
            lines.append(_metric_line("wake_fanout/s", b.wake_fanout_per_s, cand.wake_fanout_per_s))
            lines.append(_metric_line("ack_p99_ms", b.ack_p99_ms, cand.ack_p99_ms))
            lines.append(
                _metric_line("pool_wait_p99_ms", b.pool_wait_p99_ms, cand.pool_wait_p99_ms)
            )
            lines.append(
                _metric_line("cpu_seconds_total", b.cpu_seconds_total, cand.cpu_seconds_total)
            )
            lines.append(
                _metric_line("cpu_util_cores_mean", b.cpu_util_cores_mean, cand.cpu_util_cores_mean)
            )
            lines.append(_metric_line("fd_count_peak", b.fd_count_peak, cand.fd_count_peak))
            lines.append(
                _metric_line(
                    "working_set_bytes", b.working_set_peak_bytes, cand.working_set_peak_bytes
                )
            )
        return "\n".join(lines)


def build_comparison(
    records: list[ConnScaleRecord],
    claim_modes: tuple[str, ...],
    *,
    missing_detail: dict[tuple[str, int], str] | None = None,
    throughput_tolerance: float = DEFAULT_THROUGHPUT_TOLERANCE,
    collapse_material_ratio: float = DEFAULT_COLLAPSE_MATERIAL_RATIO,
    idle_floor_per_s: float = DEFAULT_IDLE_FLOOR_PER_S,
) -> ClaimModeComparison | None:
    """Build the per_lane-vs-pooled A/B from a run's records. Returns ``None`` for a single-arm profile
    (nothing to compare). ``missing_detail`` maps a ``(sweep_mode, count)`` whose pooled arm failed to
    start to the loud reason (from the runner), surfaced on the missing row."""
    modes = [m for m in claim_modes]
    if len(modes) < 2:
        return None
    baseline_mode = BASELINE_MODE if BASELINE_MODE in modes else modes[0]
    candidate_mode = (
        CANDIDATE_MODE if CANDIDATE_MODE in modes else next(m for m in modes if m != baseline_mode)
    )
    missing_detail = missing_detail or {}

    by_key: dict[tuple[str, str, int], ConnScaleRecord] = {}
    for r in records:
        by_key[(r.claim_mode, r.sweep_mode, r.count)] = r

    # Iterate the (sweep_mode, count) cells the BASELINE produced, in first-seen order, so the report
    # is stable and a missing pooled arm is detected against the baseline that always runs.
    baseline_cells: list[tuple[str, int]] = []
    seen: set[tuple[str, int]] = set()
    for r in records:
        if r.claim_mode == baseline_mode:
            key = (r.sweep_mode, r.count)
            if key not in seen:
                seen.add(key)
                baseline_cells.append(key)

    rows: list[ComparisonRow] = []
    for sweep_mode, count in baseline_cells:
        base_rec = by_key[(baseline_mode, sweep_mode, count)]
        base = _ArmMetrics.from_record(base_rec)
        cand_rec = by_key.get((candidate_mode, sweep_mode, count))
        if cand_rec is None:
            rows.append(
                ComparisonRow(
                    sweep_mode=sweep_mode,
                    count=count,
                    baseline=base,
                    candidate=None,
                    pooled_missing=True,
                    throughput_ok=False,
                    throughput_delta_pct=None,
                    collapse_verdict=COLLAPSE_MISSING,
                    collapse_delta_pct=None,
                    collapse_ratio=None,
                    missing_detail=missing_detail.get((sweep_mode, count), ""),
                )
            )
            continue
        cand = _ArmMetrics.from_record(cand_rec)
        # The throughput delta is only SOUND when both arms held zero-loss; a breached (drowning)
        # baseline has a poller-zeroed achieved rate we must not read as a pass/fail.
        candidate_lost = not cand.no_loss_ok
        throughput_comparable = base.no_loss_ok and cand.no_loss_ok
        thr_ok, thr_delta = _throughput_verdict(
            base.achieved_read_per_s, cand.achieved_read_per_s, throughput_tolerance
        )
        collapse, col_delta, ratio = _collapse_verdict(
            base.idle_poll_per_s, cand.idle_poll_per_s, collapse_material_ratio, idle_floor_per_s
        )
        rows.append(
            ComparisonRow(
                sweep_mode=sweep_mode,
                count=count,
                baseline=base,
                candidate=cand,
                pooled_missing=False,
                throughput_ok=thr_ok,
                throughput_delta_pct=thr_delta,
                collapse_verdict=collapse,
                collapse_delta_pct=col_delta,
                collapse_ratio=ratio,
                candidate_lost=candidate_lost,
                throughput_comparable=throughput_comparable,
            )
        )

    notes: list[str] = []
    missing = [
        f"[{sm}] N={n}" for (sm, n) in baseline_cells if (candidate_mode, sm, n) not in by_key
    ]
    if missing:
        notes.append(
            f"{len(missing)} pooled arm(s) MISSING (engine failed to start): {', '.join(missing)} "
            "-- on SQL Server this is the RCSI fail-closed gate (READ_COMMITTED_SNAPSHOT OFF); set "
            "RCSI ON or MEFOR_PIPELINE_REQUIRE_RCSI_FOR_POOLED=false for a smoke."
        )
    return ClaimModeComparison(
        baseline_mode=baseline_mode,
        candidate_mode=candidate_mode,
        throughput_tolerance=throughput_tolerance,
        collapse_material_ratio=collapse_material_ratio,
        idle_floor_per_s=idle_floor_per_s,
        rows=rows,
        notes=notes,
    )


def _throughput_verdict(
    baseline: float, candidate: float, tolerance: float
) -> tuple[bool, float | None]:
    """(ok, delta_pct). ok when the candidate cleared ``baseline × (1 - tolerance)``. A zero/negative
    baseline can't regress, so it passes with no delta."""
    if baseline <= 0.0:
        return True, None
    ok = candidate >= baseline * (1.0 - tolerance)
    return ok, (candidate - baseline) / baseline * 100.0


def _collapse_verdict(
    baseline_idle: float, candidate_idle: float, material_ratio: float, floor: float
) -> tuple[str, float | None, float | None]:
    """(verdict, delta_pct, ratio) for the idle-poll collapse. Below the per_lane noise floor the
    collapse is negligible-either-way ⇒ INCONCLUSIVE with no ratio."""
    if baseline_idle < floor:
        return COLLAPSE_INCONCLUSIVE, None, None
    ratio = candidate_idle / baseline_idle
    delta_pct = (candidate_idle - baseline_idle) / baseline_idle * 100.0
    if ratio <= material_ratio:
        verdict = COLLAPSE_PASS
    elif ratio < 1.0:
        verdict = COLLAPSE_WARN
    else:
        verdict = COLLAPSE_FAIL
    return verdict, delta_pct, ratio


def _row_json(row: ComparisonRow) -> dict[str, object]:
    out: dict[str, object] = {
        "sweep_mode": row.sweep_mode,
        "count": row.count,
        "pooled_missing": row.pooled_missing,
        "ok": row.ok,
        "throughput": {
            "ok": row.throughput_ok,
            "per_lane_read_per_s": round(row.baseline.achieved_read_per_s, 2),
            "pooled_read_per_s": (
                None if row.candidate is None else round(row.candidate.achieved_read_per_s, 2)
            ),
            "delta_pct": _round_or_none(row.throughput_delta_pct, 2),
        },
        "collapse": {
            "verdict": row.collapse_verdict,
            "per_lane_idle_poll_per_s": round(row.baseline.idle_poll_per_s, 2),
            "pooled_idle_poll_per_s": (
                None if row.candidate is None else round(row.candidate.idle_poll_per_s, 2)
            ),
            "delta_pct": _round_or_none(row.collapse_delta_pct, 2),
            "ratio": _round_or_none(row.collapse_ratio, 4),
        },
        "loss": {
            # The authoritative reconcile (independent sink counter), the guard the poller-zeroed
            # achieved rate cannot express.
            "per_lane_zero_loss": row.baseline.no_loss_ok,
            "pooled_zero_loss": (None if row.candidate is None else row.candidate.no_loss_ok),
            "candidate_lost": row.candidate_lost,
            "throughput_comparable": row.throughput_comparable,
            "resilience_win": row.resilience_win,
            "per_lane_detail": row.baseline.no_loss_detail,
            "pooled_detail": (None if row.candidate is None else row.candidate.no_loss_detail),
        },
    }
    if row.missing_detail:
        out["missing_detail"] = row.missing_detail
    if row.candidate is not None:
        b, c = row.baseline, row.candidate
        out["metrics"] = {
            "ack_p99_ms": _pair(b.ack_p99_ms, c.ack_p99_ms),
            "wake_fanout_per_s": _pair(b.wake_fanout_per_s, c.wake_fanout_per_s),
            "pool_wait_p99_ms": _pair(b.pool_wait_p99_ms, c.pool_wait_p99_ms),
            "cpu_seconds_total": _pair(b.cpu_seconds_total, c.cpu_seconds_total),
            "cpu_util_cores_mean": _pair(b.cpu_util_cores_mean, c.cpu_util_cores_mean),
            "fd_count_peak": _pair(b.fd_count_peak, c.fd_count_peak),
            "working_set_peak_bytes": _pair(b.working_set_peak_bytes, c.working_set_peak_bytes),
        }
    return out


def _pair(baseline: float | int | None, candidate: float | int | None) -> dict[str, object]:
    return {"per_lane": baseline, "pooled": candidate}


def _delta(delta_pct: float | None) -> str:
    if delta_pct is None:
        return "n/a"
    return f"{delta_pct:+.1f}%"


def _yn(ok: bool) -> str:
    return "yes" if ok else "NO"


def _tnr_label(value: bool | None) -> str:
    """Render the aggregate throughput verdict, distinguishing an inconclusive ``None`` (no
    sound-baseline count) from a real ``True``/``False`` — the phantom-pass fix must read visibly."""
    if value is None:
        return "n/a (no sound-baseline count)"
    return str(value)


def _loss_label(row: ComparisonRow) -> str:
    if row.candidate_lost:
        detail = row.candidate.no_loss_detail if row.candidate is not None else ""
        return f"CANDIDATE LOST -- pooled breached zero-loss ({detail})"
    if row.resilience_win:
        return "RESILIENCE -- per_lane breached zero-loss, pooled held (throughput delta not sound)"
    return "both clean"


def _metric_line(label: str, baseline: float | int | None, candidate: float | int | None) -> str:
    return f"  {label:<22} per_lane={_fmt(baseline):>9}  pooled={_fmt(candidate):>9}"


def _fmt(value: float | int | None) -> str:
    if value is None:
        return "n/a"
    if isinstance(value, float):
        return f"{value:.2f}"
    return str(value)


def _round_or_none(value: float | None, digits: int) -> float | None:
    return None if value is None else round(value, digits)


def _drain_fmt(drain_seconds_worst: float | None) -> str:
    """Render a worst-case drain time, distinguishing a TIMED-OUT drain (``None`` = await_drain never
    saw the whole-pipeline reach 0, i.e. stranded) from a finite completed drain — so the table reader
    isn't left reading a timeout as merely 'unmeasured'."""
    return "TIMED-OUT" if drain_seconds_worst is None else f"{drain_seconds_worst:.2f}"


# =============================================================================
# Thread-hop-fusion A/B (ADR 0071 B5) — B0 (fusion off) vs B1 (fusion on).
# =============================================================================
#
# The claim-mode A/B above answers "does pooled cost throughput?"; this fusion A/B answers the ADR
# 0071 §6.4(b) promote-to-Accepted question: "does turning fusion ON lift the SQL-Server ceiling by a
# margin worth shipping?". It pairs the B0 (fusion off) and B1 (fusion on) arms at the SAME
# (claim_mode, sweep_mode, count) cell and, over >= 3 trials per arm, emits a GO / NO-GO / INCONCLUSIVE
# verdict against the §6.4(b) guards:
#
#   * throughput lift    -- B1 achieved intake msg/s (the "ceiling") must rise >= 10% AND by > 2σ of
#                           the combined trial spread (a margin outside trial noise, not a lucky run);
#   * in_pipeline        -- B1 must drain like B0 (its whole-pipeline drain COMPLETES + a flat-or-lower
#                           post-load drain time): a higher intake bought by a growing backlog is a
#                           mirage, not a real ceiling lift. Read from the AUTHORITATIVE await_drain
#                           completion signal (whole-pipeline in_pipeline==0), NOT the /stats-poller
#                           in_pipeline peak (which under-samples under overload, §10 item 8);
#   * delivered/offered  -- B1 must deliver >= 0.98 of what was offered (it is keeping up end-to-end);
#   * zero-loss held     -- B1 must NOT breach the at-least-once reconcile at any count (hard guard).
#
# SQLite is NOT a valid throughput proxy for this axis (its write-lock regime is not the profiled
# idle-store marshaling wall, ADR 0071 §8) — the real verdict is the SQL-Server leg on the AWS bench
# rig. This module is metrics + metadata only (no bodies / control-ids), pure + deterministic, so the
# verdict logic unit-tests without a live run.

#: B1's achieved intake msg/s (the ceiling) must clear B0 * (1 + this) — a >= 10% lift.
DEFAULT_FUSE_MIN_LIFT_PCT = 10.0
#: ... AND the lift must exceed this many σ of the combined per-arm trial spread (outside trial noise).
DEFAULT_FUSE_SIGMA_MULTIPLE = 2.0
#: B1 must deliver at least this fraction of offered (sink_received / sent) — not a backlog mirage.
DEFAULT_FUSE_MIN_DELIVERED_OFFERED = 0.98
#: B1's worst post-load DRAIN TIME may exceed B0's by at most this fraction (+1 s absolute) and still
#: count as "flat-or-lower" — a small noise cushion so runner jitter doesn't flip a real lift to NO-GO.
#: (Was the /stats-poller in_pipeline peak; now the authoritative drain signal — ADR 0071 §10 item 8.)
DEFAULT_FUSE_IN_PIPELINE_TOLERANCE = 0.05

# Fusion GO/NO-GO verdict labels.
FUSE_GO = (
    "GO"  # lift >= 10% & > 2σ, in_pipeline flat-or-lower, delivered/offered >= 0.98, zero-loss held
)
FUSE_NO_GO = (
    "NO-GO"  # a hard guard failed, or the lift is below the 10% bar (fusion banked nothing)
)
FUSE_INCONCLUSIVE = (
    "INCONCLUSIVE"  # the mean lift meets 10% but is within trial spread (need more trials)
)
FUSE_MISSING = (
    "MISSING"  # the B1 (fusion on) arm is absent — never silently compared against nothing
)

FUSE_B0_LABEL = "fuse=off (B0)"
FUSE_B1_LABEL = "fuse=on (B1)"

# The SAME §6.4(b) verdict machinery drives the ADR 0075 statement-batching A/B (Bench B): its axis
# discriminator is the record's ``batch_handoff_statements`` tag rather than ``fuse_thread_hops``, and
# it is relabelled for that axis. build_batch_comparison() below is a thin wrapper over
# build_fuse_comparison() — ONE verdict path, no fork, no reintroduced poller-peak.
FUSE_AXIS_KIND = "fuse_mode_ab"
FUSE_TITLE = "Thread-hop-fusion A/B (ADR 0071 B5)"
FUSE_GUARDS_REF = "ADR 0071 6.4b"
BATCH_AXIS_KIND = "batch_mode_ab"
BATCH_TITLE = "Statement-batching A/B (ADR 0075 Bench B)"
BATCH_GUARDS_REF = "ADR 0075 Bench B"
BATCH_B0_LABEL = "batch=off (B0)"
BATCH_B1_LABEL = "batch=on (B1)"


def _fuse_thread_hops(r: ConnScaleRecord) -> bool:
    """Default arm discriminator for the fusion A/B: pair B0 vs B1 by the ``fuse_thread_hops`` tag."""
    return r.fuse_thread_hops


def _batch_handoff_statements(r: ConnScaleRecord) -> bool:
    """Arm discriminator for the statement-batching A/B: pair B0 vs B1 by the
    ``batch_handoff_statements`` tag (fusion stays OFF in both arms — the two levers don't compose,
    ADR 0075)."""
    return r.batch_handoff_statements


@dataclass(frozen=True)
class _FuseArm:
    """One fusion arm's read-off for a ``(claim_mode, sweep_mode, count)`` cell, aggregated over its
    trials (mean + sample spread of the achieved intake rate; worst-case drain; all-trials zero-loss)."""

    fuse: bool
    trials: int
    mean_read_per_s: float
    sd_read_per_s: float  # sample stddev of the intake rate across trials (0.0 for < 2 trials)
    mean_written_per_s: float
    in_pipeline_peak: (
        int  # worst (max) /stats-poller in_pipeline peak — CONTEXT ONLY, no longer gated
    )
    # --- the AUTHORITATIVE WHOLE-PIPELINE drain signal (the same ``await_drain`` the runner already
    # trusts; the /stats poller peak under-samples under overload — ADR 0071 §10 item 8).
    # ``drain_seconds_worst`` = the worst (longest) post-load drain time across trials, and is **``None``
    # when ANY trial's drain TIMED OUT** — ``await_drain`` returns a finite time only once the
    # whole-pipeline ``in_pipeline`` gauge (NOT-DONE rows across ingress+routed+outbound) reaches 0, so a
    # timeout means rows stranded in SOME stage. A ``None`` here is the WORST case ("never drained"), NOT
    # "unmeasured": a timed-out trial poisons the worst-case so a partial strand can't be dropped. (The
    # outbound-only ``no_loss.backlog`` can read 0 while ingress/routed still hold rows, so it is NOT a
    # whole-pipeline gauge — drain completion is.) ---
    drain_seconds_worst: float | None
    delivered_offered: float | None  # mean sink_received/sent across trials (None if no sent)
    zero_loss_ok: bool  # every trial held the at-least-once reconcile
    offered_rate: float

    @property
    def drain_completed(self) -> bool:
        """Every trial's post-load drain COMPLETED — ``await_drain`` saw the whole-pipeline
        ``in_pipeline`` gauge reach 0 (no rows stranded in ANY stage). Exactly
        ``drain_seconds_worst is not None`` by construction: a timed-out trial poisons the worst case."""
        return self.drain_seconds_worst is not None

    @classmethod
    def from_records(cls, fuse: bool, recs: list[ConnScaleRecord]) -> _FuseArm:
        reads = [r.achieved_read_per_s for r in recs]
        writtens = [r.achieved_written_per_s for r in recs]
        ratios = [r.no_loss.sink_received / r.no_loss.sent for r in recs if r.no_loss.sent > 0]
        drains = [r.drain_seconds for r in recs]
        completed = [d for d in drains if d is not None]
        # A timed-out drain (None) POISONS the worst case: ``await_drain`` never saw ``in_pipeline``
        # reach 0, so there is no finite whole-pipeline drain time to trust — the arm did NOT fully
        # drain. Only when EVERY trial completed is the worst-case the max of the finite drain times.
        drain_seconds_worst = max(completed) if recs and len(completed) == len(drains) else None
        return cls(
            fuse=fuse,
            trials=len(recs),
            mean_read_per_s=statistics.fmean(reads) if reads else 0.0,
            sd_read_per_s=statistics.stdev(reads) if len(reads) >= 2 else 0.0,
            mean_written_per_s=statistics.fmean(writtens) if writtens else 0.0,
            in_pipeline_peak=max((r.in_pipeline_peak for r in recs), default=0),
            drain_seconds_worst=drain_seconds_worst,
            delivered_offered=statistics.fmean(ratios) if ratios else None,
            zero_loss_ok=all(r.no_loss.ok for r in recs) and bool(recs),
            offered_rate=recs[0].offered_aggregate_rate if recs else 0.0,
        )


@dataclass(frozen=True)
class FuseComparisonRow:
    """The B0-vs-B1 fusion comparison at one ``(claim_mode, sweep_mode, count)`` cell."""

    claim_mode: str
    sweep_mode: str
    count: int
    baseline: _FuseArm  # B0 (fusion off)
    candidate: _FuseArm | None  # B1 (fusion on); None ⇒ the fusion arm is MISSING
    verdict: str  # FUSE_GO | FUSE_NO_GO | FUSE_INCONCLUSIVE | FUSE_MISSING
    lift_pct: float | None  # (B1 - B0) / B0 * 100 of the achieved intake rate
    sigma: float | None  # 2σ reference: combined per-arm trial spread of the intake rate
    significant: bool  # the lift exceeds sigma_multiple × sigma (outside trial noise)
    in_pipeline_ok: (
        bool  # B1 whole-pipeline drain COMPLETED AND drain time flat-or-lower vs B0 (authoritative)
    )
    delivered_offered_ok: bool  # B1 delivered/offered >= the floor
    candidate_lost: bool  # B1 breached zero-loss (hard fail)
    reason: str  # a human one-liner explaining the verdict
    candidate_missing: bool = False

    @property
    def ok(self) -> bool:
        """A CORRECTNESS gate distinct from the throughput decision: the run fails only when the
        fusion arm is missing or breached zero-loss. A NO-GO / INCONCLUSIVE throughput verdict is a
        legitimate measurement outcome (fusion banked nothing → ADR 0071 escalates to free-threading),
        recorded — never a red build."""
        return not self.candidate_missing and not self.candidate_lost


@dataclass(frozen=True)
class FuseModeComparison:
    """The full fusion A/B: one :class:`FuseComparisonRow` per ``(claim_mode, sweep_mode, count)``,
    plus the §6.4(b) guard config and an overall GO/NO-GO verdict."""

    min_lift_pct: float
    sigma_multiple: float
    min_delivered_offered: float
    in_pipeline_tolerance: float
    rows: list[FuseComparisonRow] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    # Axis labelling (defaulted to the fusion axis so a pre-existing fuse run's JSON/table is byte-
    # identical). The statement-batching A/B (ADR 0075) reuses this SAME class + verdict path via
    # build_batch_comparison(), only overriding these labels — there is no second comparator.
    axis_kind: str = FUSE_AXIS_KIND
    title: str = FUSE_TITLE
    guards_ref: str = FUSE_GUARDS_REF
    baseline_label: str = FUSE_B0_LABEL
    candidate_label: str = FUSE_B1_LABEL
    # (claim_mode, sweep_mode, count) cells with a B1 (fusion-on) record but NO B0 baseline record —
    # the fusion-off baseline (itself a pooled arm) failed or was omitted there, so the lift is
    # uncomputable. Folded into overall_verdict/ok so a swallowed baseline can never let a GO on the
    # surviving counts mask it (ADR 0071 §6.4b).
    baseline_missing: list[tuple[str, str, int]] = field(default_factory=list)

    @property
    def overall_verdict(self) -> str:
        """GO only if EVERY present cell is GO; NO-GO if any cell is NO-GO or the B1 arm is missing;
        otherwise INCONCLUSIVE (some cell could not clear the noise bar, none failed outright)."""
        verdicts = [row.verdict for row in self.rows]
        if self.baseline_missing:
            return FUSE_NO_GO  # a swallowed B0 baseline is a run gap, never a GO
        if not verdicts:
            return FUSE_INCONCLUSIVE
        if any(v in (FUSE_NO_GO, FUSE_MISSING) for v in verdicts):
            return FUSE_NO_GO
        if all(v == FUSE_GO for v in verdicts):
            return FUSE_GO
        return FUSE_INCONCLUSIVE

    @property
    def ok(self) -> bool:
        """The correctness fold for the run's exit code: every present B1 arm held zero-loss and none
        is missing. The GO/NO-GO throughput decision is reported separately and does NOT fail the run
        (a null/negative fusion result banks nothing but is not an error, ADR 0071 §6.4b)."""
        return bool(self.rows) and all(row.ok for row in self.rows) and not self.baseline_missing

    @property
    def candidate_zero_loss_ok(self) -> bool:
        return not any(row.candidate_lost for row in self.rows)

    @property
    def missing_arms(self) -> int:
        return sum(1 for row in self.rows if row.candidate_missing)

    @property
    def go_cells(self) -> int:
        return sum(1 for row in self.rows if row.verdict == FUSE_GO)

    @property
    def no_go_cells(self) -> int:
        return sum(1 for row in self.rows if row.verdict == FUSE_NO_GO)

    @property
    def inconclusive_cells(self) -> int:
        return sum(1 for row in self.rows if row.verdict == FUSE_INCONCLUSIVE)

    def to_json_dict(self) -> dict[str, object]:
        return {
            "kind": self.axis_kind,
            "baseline": self.baseline_label,
            "candidate": self.candidate_label,
            "guards": {
                "min_lift_pct": self.min_lift_pct,
                "sigma_multiple": self.sigma_multiple,
                "min_delivered_offered": self.min_delivered_offered,
                "in_pipeline_tolerance": self.in_pipeline_tolerance,
            },
            "overall_verdict": self.overall_verdict,
            "overall_ok": self.ok,
            "summary": {
                "candidate_zero_loss_ok": self.candidate_zero_loss_ok,
                "go_cells": self.go_cells,
                "no_go_cells": self.no_go_cells,
                "inconclusive_cells": self.inconclusive_cells,
                "missing_arms": self.missing_arms,
                "baseline_missing": len(self.baseline_missing),
            },
            "baseline_missing": [list(cell) for cell in self.baseline_missing],
            "rows": [_fuse_row_json(row) for row in self.rows],
            "notes": self.notes,
        }

    def render_table(self) -> str:
        lines: list[str] = []
        lines.append(
            f"{self.title} -- baseline {self.baseline_label} vs candidate {self.candidate_label}"
        )
        lines.append(
            f"guards ({self.guards_ref}): lift >= {self.min_lift_pct:.0f}% AND > {self.sigma_multiple:.0f}"
            f"sigma | in_pipeline flat-or-lower | delivered/offered >= {self.min_delivered_offered:.2f}"
            f" | zero-loss held  (SQL Server is the valid leg; SQLite is NOT a throughput proxy)"
        )
        lines.append(
            f"overall: {self.overall_verdict}  (GO={self.go_cells}, NO-GO={self.no_go_cells}, "
            f"INCONCLUSIVE={self.inconclusive_cells}, missing={self.missing_arms}, "
            f"candidate_zero_loss_ok={self.candidate_zero_loss_ok})"
        )
        if self.baseline_missing:
            _bm = ", ".join(f"[{cm}/{sm}] N={n}" for (cm, sm, n) in self.baseline_missing)
            lines.append(f"  BASELINE MISSING (B0 absent -> run FAILS): {_bm}")
        for row in self.rows:
            lines.append("")
            lines.append(f"[{row.claim_mode}/{row.sweep_mode}] N={row.count}  =>  {row.verdict}")
            lines.append(f"  {row.reason}")
            if row.candidate_missing:
                lines.append(
                    f"  achieved_read/s        B0={row.baseline.mean_read_per_s:.2f}  "
                    f"B1=n/a   (no comparison)"
                )
                continue
            cand = row.candidate
            assert cand is not None  # not candidate_missing ⇒ candidate present
            b = row.baseline
            lines.append(
                f"  achieved_read/s (ceiling) B0={b.mean_read_per_s:>9.2f}  "
                f"B1={cand.mean_read_per_s:>9.2f}  {_delta(row.lift_pct):>9}  "
                f"2sigma={_fmt(_two_sigma(row.sigma, self.sigma_multiple)):>9}  "
                f"significant: {_yn(row.significant)}"
            )
            lines.append(
                f"  drain_seconds (worst)     B0={_drain_fmt(b.drain_seconds_worst):>9}  "
                f"B1={_drain_fmt(cand.drain_seconds_worst):>9}  {'':>9}  drained+flat-or-lower: "
                f"{_yn(row.in_pipeline_ok)}"
            )
            lines.append(
                f"  in_pipeline_peak (poller) B0={b.in_pipeline_peak:>9}  "
                f"B1={cand.in_pipeline_peak:>9}  {'':>9}  context only (under-samples; not gated)"
            )
            lines.append(
                f"  delivered/offered         B0={_fmt(b.delivered_offered):>9}  "
                f"B1={_fmt(cand.delivered_offered):>9}  {'':>9}  keeping-up: {_yn(row.delivered_offered_ok)}"
            )
            lines.append(
                f"  zero_loss                 B0={_yn(b.zero_loss_ok):>9}  "
                f"B1={_yn(cand.zero_loss_ok):>9}  {'':>9}  candidate_lost: {_yn(row.candidate_lost)}"
            )
            lines.append(_fuse_metric_line("trials", b.trials, cand.trials))
            lines.append(
                _fuse_metric_line(
                    "achieved_written/s", b.mean_written_per_s, cand.mean_written_per_s
                )
            )
        return "\n".join(lines)


def build_fuse_comparison(
    records: list[ConnScaleRecord],
    fuse_modes: tuple[bool, ...],
    *,
    missing_detail: dict[tuple[str, str, int], str] | None = None,
    min_lift_pct: float = DEFAULT_FUSE_MIN_LIFT_PCT,
    sigma_multiple: float = DEFAULT_FUSE_SIGMA_MULTIPLE,
    min_delivered_offered: float = DEFAULT_FUSE_MIN_DELIVERED_OFFERED,
    in_pipeline_tolerance: float = DEFAULT_FUSE_IN_PIPELINE_TOLERANCE,
    arm_of: Callable[[ConnScaleRecord], bool] = _fuse_thread_hops,
    axis_kind: str = FUSE_AXIS_KIND,
    title: str = FUSE_TITLE,
    guards_ref: str = FUSE_GUARDS_REF,
    baseline_label: str = FUSE_B0_LABEL,
    candidate_label: str = FUSE_B1_LABEL,
) -> FuseModeComparison | None:
    """Build the B0-vs-B1 fusion A/B from a run's records. Returns ``None`` for a single-arm
    ``fuse_modes`` (nothing to compare — the pre-existing single-arm shape). Groups records by
    ``(claim_mode, sweep_mode, count, arm)`` so >= 2 trials per arm feed the mean + spread, then pairs
    each B0 cell against its B1 arm and applies the ADR 0071 §6.4(b) guards. ``missing_detail`` maps a
    ``(claim_mode, sweep_mode, count)`` whose B1 arm never ran to a loud reason (surfaced on the missing
    row).

    ``arm_of`` selects the boolean A/B discriminator (default the ``fuse_thread_hops`` tag); the
    statement-batching A/B (ADR 0075) passes ``batch_handoff_statements`` + the batch labels through
    :func:`build_batch_comparison` to reuse this EXACT verdict path (``_FuseArm`` / ``_in_pipeline_ok``
    / ``_fuse_verdict``) — one comparator, only the discriminator + labels differ."""
    modes = list(fuse_modes)
    if len(modes) < 2 or FUSE_OFF not in modes or FUSE_ON not in modes:
        return None
    missing_detail = missing_detail or {}

    groups: dict[tuple[str, str, int, bool], list[ConnScaleRecord]] = {}
    for r in records:
        groups.setdefault((r.claim_mode, r.sweep_mode, r.count, arm_of(r)), []).append(r)

    # Iterate the (claim_mode, sweep_mode, count) cells the B0 baseline produced, first-seen order, so
    # the report is stable and a missing B1 arm is detected against the baseline that always runs.
    baseline_cells: list[tuple[str, str, int]] = []
    seen: set[tuple[str, str, int]] = set()
    for r in records:
        if arm_of(r) is FUSE_OFF:
            key = (r.claim_mode, r.sweep_mode, r.count)
            if key not in seen:
                seen.add(key)
                baseline_cells.append(key)

    rows: list[FuseComparisonRow] = []
    for claim_mode, sweep_mode, count in baseline_cells:
        base = _FuseArm.from_records(FUSE_OFF, groups[(claim_mode, sweep_mode, count, FUSE_OFF)])
        cand_recs = groups.get((claim_mode, sweep_mode, count, FUSE_ON))
        if not cand_recs:
            rows.append(
                FuseComparisonRow(
                    claim_mode=claim_mode,
                    sweep_mode=sweep_mode,
                    count=count,
                    baseline=base,
                    candidate=None,
                    verdict=FUSE_MISSING,
                    lift_pct=None,
                    sigma=None,
                    significant=False,
                    in_pipeline_ok=False,
                    delivered_offered_ok=False,
                    candidate_lost=False,
                    candidate_missing=True,
                    reason=missing_detail.get(
                        (claim_mode, sweep_mode, count),
                        "B1 (fusion on) arm absent — engine never ran it",
                    ),
                )
            )
            continue
        cand = _FuseArm.from_records(FUSE_ON, cand_recs)
        row = _fuse_row(
            claim_mode,
            sweep_mode,
            count,
            base,
            cand,
            min_lift_pct=min_lift_pct,
            sigma_multiple=sigma_multiple,
            min_delivered_offered=min_delivered_offered,
            in_pipeline_tolerance=in_pipeline_tolerance,
        )
        rows.append(row)

    notes: list[str] = []
    missing = [
        f"[{cm}/{sm}] N={n}"
        for (cm, sm, n) in baseline_cells
        if not groups.get((cm, sm, n, FUSE_ON))
    ]
    if missing:
        notes.append(
            f"{len(missing)} fusion (B1) arm(s) MISSING: {', '.join(missing)} -- the B0 baseline is "
            "never silently compared against nothing. Fusion fails OPEN to the async path, so a missing "
            "B1 arm is a run/setup gap (the whole pooled arm refused to start, or the profile omitted "
            "it), not a fusion fault."
        )
    # Orphan B1 (fusion-on) arms whose B0 baseline never produced a record: the fusion-off baseline
    # (itself a pooled arm) failed or was omitted at that cell, so the lift is uncomputable. Detect them
    # so a swallowed baseline can't drop a count from BOTH the table and the ok-fold and let a GO on the
    # surviving counts mask it (ADR 0071 §6.4b). ``seen`` is the set of B0 baseline cells built above.
    baseline_missing: list[tuple[str, str, int]] = []
    seen_b1: set[tuple[str, str, int]] = set()
    for r in records:
        if arm_of(r) is FUSE_ON:
            key = (r.claim_mode, r.sweep_mode, r.count)
            if key not in seen and key not in seen_b1:
                seen_b1.add(key)
                baseline_missing.append(key)
    if baseline_missing:
        notes.append(
            f"{len(baseline_missing)} B0 (fusion-off) BASELINE arm(s) MISSING for a present B1 arm: "
            + ", ".join(f"[{cm}/{sm}] N={n}" for (cm, sm, n) in baseline_missing)
            + " -- the fusion-off baseline (a pooled arm) failed or was omitted there, so the lift is "
            "uncomputable. This FAILS the run (overall NO-GO) so a swallowed baseline can never let a GO "
            "on other counts mask it."
        )
    return FuseModeComparison(
        min_lift_pct=min_lift_pct,
        sigma_multiple=sigma_multiple,
        min_delivered_offered=min_delivered_offered,
        in_pipeline_tolerance=in_pipeline_tolerance,
        rows=rows,
        notes=notes,
        baseline_missing=baseline_missing,
        axis_kind=axis_kind,
        title=title,
        guards_ref=guards_ref,
        baseline_label=baseline_label,
        candidate_label=candidate_label,
    )


def build_batch_comparison(
    records: list[ConnScaleRecord],
    batch_modes: tuple[bool, ...],
    *,
    missing_detail: dict[tuple[str, str, int], str] | None = None,
    min_lift_pct: float = DEFAULT_FUSE_MIN_LIFT_PCT,
    sigma_multiple: float = DEFAULT_FUSE_SIGMA_MULTIPLE,
    min_delivered_offered: float = DEFAULT_FUSE_MIN_DELIVERED_OFFERED,
    in_pipeline_tolerance: float = DEFAULT_FUSE_IN_PIPELINE_TOLERANCE,
) -> FuseModeComparison | None:
    """Build the B0-vs-B1 statement-batching A/B (ADR 0075 Bench B) from a run's records.

    A thin wrapper over :func:`build_fuse_comparison` — the SAME §6.4(b) verdict path (conjunctive
    >= 10% & > 2σ lift, the authoritative whole-pipeline drain signal via ``_in_pipeline_ok`` from
    #812, delivered/offered floor, hard zero-loss gate) — only the arm discriminator
    (``batch_handoff_statements`` instead of ``fuse_thread_hops``) and the axis labels differ. Returns
    ``None`` for a single-arm ``batch_modes`` (nothing to compare). ``missing_detail`` maps a
    ``(claim_mode, sweep_mode, count)`` whose B1 (batching-on) arm never ran to a loud reason."""
    return build_fuse_comparison(
        records,
        batch_modes,
        missing_detail=missing_detail,
        min_lift_pct=min_lift_pct,
        sigma_multiple=sigma_multiple,
        min_delivered_offered=min_delivered_offered,
        in_pipeline_tolerance=in_pipeline_tolerance,
        arm_of=_batch_handoff_statements,
        axis_kind=BATCH_AXIS_KIND,
        title=BATCH_TITLE,
        guards_ref=BATCH_GUARDS_REF,
        baseline_label=BATCH_B0_LABEL,
        candidate_label=BATCH_B1_LABEL,
    )


def _in_pipeline_ok(base: _FuseArm, cand: _FuseArm, tolerance: float) -> bool:
    """Did B1's higher intake ride a growing backlog (a mirage), or drain like B0 (a real lift)?

    Read from the AUTHORITATIVE WHOLE-PIPELINE drain signal the harness already computes, NOT the
    /stats-poller ``in_pipeline`` peak, which under-samples under overload and produced false NO-GO
    *reasons* (ADR 0071 §10 item 8). The signal is drain COMPLETION: ``await_drain`` returns a finite
    ``drain_seconds`` only once the whole-pipeline ``in_pipeline`` gauge (NOT-DONE rows across
    ingress+routed+outbound) reaches 0 and the counters settle; on timeout it returns ``None``. So
    ``drain_seconds_worst is None`` means at least one trial's drain never completed — rows stranded in
    SOME stage. (The outbound-only ``no_loss.backlog`` can read 0 while ingress/routed still hold rows,
    so it is NOT usable here — a fully-offered arm that strands upstream would false-pass; the whole-
    pipeline drain gauge is the only reliable one.)

    1. **Candidate fully drained.** If B1's worst drain did NOT complete (``drain_seconds_worst is
       None``) the whole pipeline never emptied — the backlog mirage — so FAIL, never auto-pass. This is
       the exact overload regime the guard targets: a timed-out drain is the strongest strand signal.
    2. **Drain time flat-or-lower.** Otherwise (B1 fully drained) B1's worst (longest) completed drain
       must not exceed B0's beyond a small cushion (× (1 + tolerance) + 1 s). A longer drain means a
       larger backlog accumulated behind the higher intake. If B0 itself never drained
       (``drain_seconds_worst is None``) B0 is the drowning arm and a fully-draining B1 is unambiguously
       flat-or-lower ⇒ pass.
    """
    # Order matters: the candidate-timeout FAIL is checked FIRST, so a B1 that never drained can never be
    # rescued by a B0 that also never drained.
    if cand.drain_seconds_worst is None:
        return False
    if base.drain_seconds_worst is None:
        return True
    return cand.drain_seconds_worst <= base.drain_seconds_worst * (1.0 + tolerance) + 1.0


def _fuse_row(
    claim_mode: str,
    sweep_mode: str,
    count: int,
    base: _FuseArm,
    cand: _FuseArm,
    *,
    min_lift_pct: float,
    sigma_multiple: float,
    min_delivered_offered: float,
    in_pipeline_tolerance: float,
) -> FuseComparisonRow:
    candidate_lost = not cand.zero_loss_ok
    # "flat-or-lower" (ADR 0071 §10 item 8): does B1's higher intake ride a growing backlog (a mirage),
    # or drain like B0 (a real ceiling lift)? Judged from the AUTHORITATIVE whole-pipeline drain signal
    # (await_drain COMPLETION + post-load drain time), NOT the /stats-poller in_pipeline peak — that
    # gauge UNDER-samples under overload (the 2026-07-06 fuse_ab bench read a spuriously low B0 peak of
    # 1369/7801/9316 vs a steady B1 ~21k and fired a FALSE "in_pipeline grew" NO-GO at N=1024, though B1
    # in fact drained FASTER: ~143 s vs ~158 s). See :func:`_in_pipeline_ok`.
    in_pipeline_ok = _in_pipeline_ok(base, cand, in_pipeline_tolerance)
    delivered_offered_ok = (
        cand.delivered_offered is not None and cand.delivered_offered >= min_delivered_offered
    )

    lift_pct: float | None = None
    sigma: float | None = None
    significant = False
    if base.mean_read_per_s > 0.0:
        lift_pct = (cand.mean_read_per_s - base.mean_read_per_s) / base.mean_read_per_s * 100.0
        # The 2σ reference is the combined per-arm trial spread of the intake rate. Requiring >= 2
        # trials per arm to claim significance is the "need spread to trust the margin" guard: a single
        # trial has sd 0, which would make ANY positive delta look infinitely significant.
        if base.trials >= 2 and cand.trials >= 2:
            sigma = math.sqrt(base.sd_read_per_s**2 + cand.sd_read_per_s**2)
            diff = cand.mean_read_per_s - base.mean_read_per_s
            significant = diff > sigma_multiple * sigma

    verdict, reason = _fuse_verdict(
        base,
        cand,
        lift_pct=lift_pct,
        sigma=sigma,
        significant=significant,
        candidate_lost=candidate_lost,
        in_pipeline_ok=in_pipeline_ok,
        delivered_offered_ok=delivered_offered_ok,
        min_lift_pct=min_lift_pct,
        sigma_multiple=sigma_multiple,
        min_delivered_offered=min_delivered_offered,
    )
    return FuseComparisonRow(
        claim_mode=claim_mode,
        sweep_mode=sweep_mode,
        count=count,
        baseline=base,
        candidate=cand,
        verdict=verdict,
        lift_pct=lift_pct,
        sigma=sigma,
        significant=significant,
        in_pipeline_ok=in_pipeline_ok,
        delivered_offered_ok=delivered_offered_ok,
        candidate_lost=candidate_lost,
        reason=reason,
    )


def _fuse_verdict(
    base: _FuseArm,
    cand: _FuseArm,
    *,
    lift_pct: float | None,
    sigma: float | None,
    significant: bool,
    candidate_lost: bool,
    in_pipeline_ok: bool,
    delivered_offered_ok: bool,
    min_lift_pct: float,
    sigma_multiple: float,
    min_delivered_offered: float,
) -> tuple[str, str]:
    """Apply the ADR 0071 §6.4(b) guards in priority order. The correctness guards (zero-loss,
    in_pipeline, delivered/offered) gate first — a breach is a NO-GO regardless of the raw intake
    number. Then the throughput bar: below 10% is a NO-GO (fusion banked nothing); >= 10% but within
    trial spread is INCONCLUSIVE (need more/cleaner trials); >= 10% and outside 2σ is a GO."""
    if candidate_lost:
        return FUSE_NO_GO, "B1 breached zero-loss -- fusion must never drop a message (hard guard)"
    if not in_pipeline_ok:
        if not cand.drain_completed:
            return FUSE_NO_GO, (
                "B1 pipeline did not fully drain (await_drain timed out -- the whole-pipeline in_pipeline "
                "gauge never reached 0, rows stranded in ingress/routed/outbound) -- the higher intake "
                "rides a backlog, not a real ceiling lift"
            )
        return FUSE_NO_GO, (
            f"B1 drain time grew (B1 {_fmt(cand.drain_seconds_worst)}s > B0 "
            f"{_fmt(base.drain_seconds_worst)}s) -- the higher intake rode a larger backlog, not a real "
            "ceiling lift"
        )
    if not delivered_offered_ok:
        shown = "n/a" if cand.delivered_offered is None else f"{cand.delivered_offered:.3f}"
        return FUSE_NO_GO, (
            f"delivered/offered {shown} < {min_delivered_offered:.2f} -- B1 is not keeping up end-to-end"
        )
    if lift_pct is None:
        return FUSE_INCONCLUSIVE, "B0 baseline intake ~0 -- no sound lift to measure"
    if lift_pct < min_lift_pct:
        return FUSE_NO_GO, (
            f"lift {lift_pct:+.1f}% < {min_lift_pct:.0f}% -- fusion banked no worthwhile margin "
            "(null/negative → ADR 0071 escalates to free-threading)"
        )
    if not significant:
        if base.trials < 2 or cand.trials < 2:
            return FUSE_INCONCLUSIVE, (
                f"lift {lift_pct:+.1f}% >= {min_lift_pct:.0f}% but only "
                f"{min(base.trials, cand.trials)} trial(s) per arm -- need >= 2 to establish the "
                f"{sigma_multiple:.0f}sigma spread"
            )
        two_sigma = sigma_multiple * (sigma or 0.0)
        return FUSE_INCONCLUSIVE, (
            f"lift {lift_pct:+.1f}% >= {min_lift_pct:.0f}% but within trial spread (delta <= "
            f"{sigma_multiple:.0f}sigma={two_sigma:.1f}/s) -- inconclusive, need cleaner trials"
        )
    return FUSE_GO, (
        f"lift {lift_pct:+.1f}% >= {min_lift_pct:.0f}% and > {sigma_multiple:.0f}sigma, in_pipeline "
        f"flat-or-lower, delivered/offered >= {min_delivered_offered:.2f}, zero-loss held"
    )


def _fuse_row_json(row: FuseComparisonRow) -> dict[str, object]:
    out: dict[str, object] = {
        "claim_mode": row.claim_mode,
        "sweep_mode": row.sweep_mode,
        "count": row.count,
        "verdict": row.verdict,
        "ok": row.ok,
        "reason": row.reason,
        "candidate_missing": row.candidate_missing,
        "throughput": {
            "b0_read_per_s": round(row.baseline.mean_read_per_s, 2),
            "b1_read_per_s": (
                None if row.candidate is None else round(row.candidate.mean_read_per_s, 2)
            ),
            "lift_pct": _round_or_none(row.lift_pct, 2),
            "sigma": _round_or_none(row.sigma, 3),
            "significant": row.significant,
            "b0_trials": row.baseline.trials,
            "b1_trials": (None if row.candidate is None else row.candidate.trials),
        },
        "guards": {
            "in_pipeline_ok": row.in_pipeline_ok,
            # The AUTHORITATIVE whole-pipeline drain signal the guard now reads (ADR 0071 §10 item 8): B1's
            # await_drain COMPLETED (in_pipeline reached 0 — no rows stranded in ANY stage) and its
            # post-load drain time is flat-or-lower vs B0. A null drain_seconds_worst = the drain TIMED
            # OUT (rows stranded), i.e. drain_completed=false.
            "b0_drain_completed": row.baseline.drain_completed,
            "b1_drain_completed": (
                None if row.candidate is None else row.candidate.drain_completed
            ),
            "b0_drain_seconds_worst": _round_or_none(row.baseline.drain_seconds_worst, 3),
            "b1_drain_seconds_worst": (
                None
                if row.candidate is None
                else _round_or_none(row.candidate.drain_seconds_worst, 3)
            ),
            # The /stats-poller in_pipeline peak — CONTEXT ONLY (under-samples under overload); the
            # guard NO LONGER reads it, but it is retained for the run's diagnostic trail.
            "b0_in_pipeline_peak": row.baseline.in_pipeline_peak,
            "b1_in_pipeline_peak": (
                None if row.candidate is None else row.candidate.in_pipeline_peak
            ),
            "delivered_offered_ok": row.delivered_offered_ok,
            "b0_delivered_offered": _round_or_none(row.baseline.delivered_offered, 4),
            "b1_delivered_offered": (
                None
                if row.candidate is None
                else _round_or_none(row.candidate.delivered_offered, 4)
            ),
            "candidate_lost": row.candidate_lost,
            "b0_zero_loss": row.baseline.zero_loss_ok,
            "b1_zero_loss": (None if row.candidate is None else row.candidate.zero_loss_ok),
        },
    }
    return out


def _two_sigma(sigma: float | None, multiple: float) -> float | None:
    return None if sigma is None else multiple * sigma


def _fuse_metric_line(label: str, b0: float | int | None, b1: float | int | None) -> str:
    return f"  {label:<24} B0={_fmt(b0):>9}  B1={_fmt(b1):>9}"
