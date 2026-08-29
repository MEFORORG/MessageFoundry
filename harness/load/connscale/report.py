# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""The connection-scale report — the 6 walls keyed by connection count (B11).

A curve-shaped report (vs the throughput-shaped :class:`~harness.load.report.RunReport`): one
:class:`ConnScaleRecord` per ``(sweep_mode, N)`` step, carrying the 6-wall section + a no-loss
reconcile, plus an SLO verdict. **Metrics + metadata only** — never message bodies or control-id lists
(PHI rule). Pure + deterministic, so it unit-tests without a live run.

That rule is why the BACKLOG #1292 intake audit reports **sequence numbers**, not the control ids it
actually matched on: a seq is a dense integer minted by the harness's own counter and meaningless
outside the run, so it identifies the message for a follow-up without putting a list of message
identifiers into a shared artifact. The control ids are emitted NOWHERE -- not here and not to the
log; the previous wording sent readers to a log line that never carried them, and invited a
maintainer to make the sentence true by logging exactly what this rule exists to keep out.

The thundering-herd measurement is reported **explicitly and separated** (critic must-change #3): the
``fixed_aggregate`` sweep (constant R across N) IS the herd measurement, so the report carries the
``empty_claims_wake_fanout``-per-second slope vs N AS the wake-fanout cost, kept DISTINCT from the
idle-poll re-SELECT floor (``empty_claims_idle_poll``). The two are never summed into one number.
"""

from __future__ import annotations

import csv
import io
import json
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from harness._spreadsheet import SPREADSHEET_FORMULA_TRIGGERS, spreadsheet_safe
from harness.load.connscale.intake_audit import (
    MOMENT_LIVE,
    VERDICT_INTAKE_COMPLETE,
    VERDICT_NOT_RUN,
    IntakeAudit,
    not_run,
)

if TYPE_CHECKING:
    from collections.abc import Callable

    from harness.load.connscale.compare import (
        ClaimModeComparison,
        FuseModeComparison,
    )

# Exit codes (shared with the load CLI).
EXIT_OK = 0
EXIT_SLO_VIOLATION = 1

SCHEMA_VERSION = 1

# The shared rule (harness/_spreadsheet.py) — this module used to carry its own copy, and was the one
# writer with no formula-injection test at all, which is how the copies drifted unnoticed.
_CSV_FORMULA_TRIGGERS = SPREADSHEET_FORMULA_TRIGGERS


def _spreadsheet_safe(value: str) -> str:
    """Neutralize a leading formula trigger so a text cell can't execute when the CSV opens in
    Excel/Sheets (CSV formula injection, ASVS 1.2.10)."""
    return spreadsheet_safe(value)


@dataclass(frozen=True)
class SloCheck:
    name: str
    threshold: float | int | bool | str | None
    observed: float | int | bool | str
    ok: bool


@dataclass(frozen=True)
class NoLoss:
    ok: bool
    sent: int
    engine_read: int
    engine_written: int
    sink_received: int
    backlog: int
    detail: str


@dataclass(frozen=True)
class ConnScaleRecord:
    """One sweep step: the 6 connection-scale walls at connection count ``count`` for ``sweep_mode``."""

    sweep_mode: str  # fixed_aggregate | fixed_per_conn
    count: int  # the connection count this row measures
    offered_aggregate_rate: float  # the offered total msg/s held this step

    # --- traffic / no-loss ---
    sent: int
    acked: int
    nak: int
    deferred: int
    no_loss: NoLoss
    in_pipeline_peak: int  # the headline "is the engine keeping up at this N" gauge
    drain_seconds: float | None

    # --- wall #1: executor saturation (shim-only; None when the boot-shim isn't installed) ---
    executor_queue_depth_peak: int | None
    executor_busy_peak: int | None

    # --- wall #2: server-DB pool wait (PRIMARY acquire-wait percentiles + occupancy) ---
    pool_wait_p50_ms: float | None
    pool_wait_p95_ms: float | None
    pool_wait_p99_ms: float | None
    pool_wait_max_ms: float | None
    pool_idle_min: int | None  # secondary occupancy: min idle seen (0 ⇒ saturated)
    pool_size_max: int | None

    # --- wall #3: idle-poll storm + thundering herd (SEPARATED, not summed) ---
    empty_claims_per_s: float  # total empty claims/sec over the hold
    idle_poll_per_s: float  # the steady poll-interval re-SELECT floor
    wake_fanout_per_s: (
        float  # the per-commit thundering-herd cost (the herd slope vs N is read here)
    )
    # Empty claims PER MESSAGE absorbed, over the same first→last in-hold window as the rates above.
    # BACKLOG #1101: the per-SECOND form has wall clock in its denominator, so anything that slows the
    # run — CPU contention on a shared CI runner, or the O(N) reload probe firing mid-hold — collapses
    # it without the engine changing. Per-message is the quantity wall #3 actually means (the herd size
    # per commit) and is immune to that: numerator and denominator are both deltas over the SAME
    # samples, so the span cancels algebraically rather than by assumption. None when the window
    # absorbed no messages, in which case the ratio is undefined and must not be invented as 0.
    empty_claims_per_msg: float | None

    # --- wall #4: FD / socket count ---
    fd_count_peak: int | None  # None when the OS probe couldn't read the PID

    # --- wall #5: config-reload latency ---
    reload_seconds: float | None  # None when the reload probe was off / errored

    # --- wall #6: ACK-on-receipt latency ---
    ack_p50_ms: float
    ack_p95_ms: float
    ack_p99_ms: float

    # Unconfirmed sends (in-flight at a connection close with no ACK seen). The reconcile excuses
    # these from the intake bound only up to ~one per connection; surfaced here so the tolerance
    # width is visible on a PASSING record too, not just in a failing no_loss detail. Default 0 so
    # older JSON artifacts deserialize unchanged.
    timeouts: int = 0

    # --- claim-mode A/B (ADR 0066) + achieved throughput + process footprint ---
    # All default so an older artifact / a single-arm record deserializes unchanged. ``claim_mode``
    # tags which pipeline claim mode this step ran (per_lane|pooled). Achieved throughput is the
    # engine read/written delta over the hold window (msg/s actually absorbed/delivered, vs the
    # OFFERED aggregate rate). CPU is expressed as total CPU-seconds consumed over the window plus the
    # peak/mean core-utilisation derived from it (a cumulative CPU-seconds counter isn't meaningfully
    # "averaged", so peak/mean are reported as cores busy).
    claim_mode: str = "per_lane"
    achieved_read_per_s: float = 0.0  # engine intake msg/s over the hold (Δread / Δt)
    achieved_written_per_s: float = 0.0  # engine delivery msg/s over the hold (Δwritten / Δt)
    cpu_seconds_total: float | None = None  # CPU-seconds consumed over the measured window
    cpu_util_cores_peak: float | None = None  # peak per-interval CPU utilisation (cores busy)
    cpu_util_cores_mean: float | None = None  # mean CPU utilisation over the window (cores busy)
    working_set_peak_bytes: int | None = None  # peak resident working set (RSS) bytes
    # The thread-hop-fusion A/B axis (ADR 0071 B5). Tags which fusion arm this step ran: False = B0
    # (fusion off, the engine default), True = B1 (fusion on). Defaulted so an older artifact / a
    # non-fusion record deserializes unchanged. The fuse comparison pairs B0 vs B1 by this tag.
    fuse_thread_hops: bool = False
    # The statement-batching A/B axis (ADR 0075 Bench B). Tags which batching arm this step ran: False =
    # B0 (batching off, the engine default), True = B1 (batching on). Defaulted so an older artifact / a
    # non-batching record deserializes unchanged. The batch comparison pairs B0 vs B1 by this tag (it
    # reuses the fusion comparator's verdict path keyed on this field instead of ``fuse_thread_hops``).
    batch_handoff_statements: bool = False
    # --- wall #4 probe provenance: why `fd_count_peak` is None, when it is None ---
    # `fd_count_peak = None` used to be the whole story, and it is the same value whether the host was
    # too starved to enumerate, the process tree was gone, or the enumerator ran and returned zero
    # rows. Those warrant different verdicts, so the OS probe's own account of the window travels with
    # the gauge. `fd_probe_ticks` is the SCOPE for `fd_probe_degraded_ticks` (a degraded count without
    # its denominator is not readable), and `fd_probe_degraded` holds the DISTINCT causes as strings
    # (`harness.load.connscale.probe.ProbeDegraded` values) — strings, so this module keeps its
    # independence from the probe. All three default so an older artifact deserializes unchanged;
    # an empty `fd_probe_degraded` alongside `fd_probe_ticks == 0` means the probe did not run at all,
    # which is itself distinct from having run and failed.
    fd_probe_ticks: int = 0
    fd_probe_degraded_ticks: int = 0
    fd_probe_degraded: tuple[str, ...] = ()
    # --- BACKLOG #1292: the intake audit, the PER-MESSAGE discriminator for a no_loss shortfall ---
    # `no_loss` compares COUNTS, and a shortfall in it reads identically whether the engine lost an
    # acknowledged message or the `engine_read` gauge was short. These carry the per-message verdict
    # that separates the two. `intake_audit` is the POST-MORTEM one (taken against the stopped,
    # committed store, so sampling timing cannot explain it) and is the authoritative field;
    # `intake_audit_live` is the one taken while the engine was still up, and runs only on a
    # shortfall -- the DELTA between them is what says sample-lag vs sum-coverage. Both default to a
    # NOT_RUN verdict so an older artifact / a record built without the audit deserializes unchanged
    # and never reads as a clean pass it did not earn.
    intake_audit: IntakeAudit = field(default_factory=lambda: not_run("audit not wired"))
    intake_audit_live: IntakeAudit = field(
        default_factory=lambda: not_run("audit not wired", moment=MOMENT_LIVE)
    )

    def to_json_dict(self) -> dict[str, object]:
        return {
            "claim_mode": self.claim_mode,
            "fuse_thread_hops": self.fuse_thread_hops,
            "batch_handoff_statements": self.batch_handoff_statements,
            "sweep_mode": self.sweep_mode,
            "count": self.count,
            "offered_aggregate_rate": round(self.offered_aggregate_rate, 2),
            "achieved": {
                "read_per_s": round(self.achieved_read_per_s, 2),
                "written_per_s": round(self.achieved_written_per_s, 2),
            },
            "cpu": {
                "seconds_total": _round_or_none(self.cpu_seconds_total, 3),
                "util_cores_peak": _round_or_none(self.cpu_util_cores_peak, 3),
                "util_cores_mean": _round_or_none(self.cpu_util_cores_mean, 3),
            },
            "working_set": {"peak_bytes": self.working_set_peak_bytes},
            "traffic": {
                "sent": self.sent,
                "acked": self.acked,
                "nak": self.nak,
                "deferred": self.deferred,
                "timeouts": self.timeouts,
                "in_pipeline_peak": self.in_pipeline_peak,
                "drain_seconds": self.drain_seconds,
            },
            "no_loss": {
                "ok": self.no_loss.ok,
                "sent": self.no_loss.sent,
                "engine_read": self.no_loss.engine_read,
                "engine_written": self.no_loss.engine_written,
                "sink_received": self.no_loss.sink_received,
                "backlog": self.no_loss.backlog,
                "detail": self.no_loss.detail,
            },
            "wall1_executor": {
                "queue_depth_peak": self.executor_queue_depth_peak,
                "busy_peak": self.executor_busy_peak,
            },
            "wall2_pool_wait": {
                "p50_ms": self.pool_wait_p50_ms,
                "p95_ms": self.pool_wait_p95_ms,
                "p99_ms": self.pool_wait_p99_ms,
                "max_ms": self.pool_wait_max_ms,
                "idle_min": self.pool_idle_min,
                "size_max": self.pool_size_max,
            },
            "wall3_empty_claims": {
                "total_per_s": round(self.empty_claims_per_s, 2),
                # SEPARATED (critic must-change #3): idle-poll re-SELECTs vs the per-commit herd.
                "idle_poll_per_s": round(self.idle_poll_per_s, 2),
                "wake_fanout_per_s": round(self.wake_fanout_per_s, 2),
                # The ASSERTED form (BACKLOG #1101). The per-second numbers above are operator-facing
                # and carry wall clock; this one is what the monotonicity SLO reads, because it does
                # not move when the runner is merely slow. None when no messages were absorbed.
                "total_per_msg": (
                    None
                    if self.empty_claims_per_msg is None
                    else round(self.empty_claims_per_msg, 3)
                ),
            },
            "wall4_fd": {
                "count_peak": self.fd_count_peak,
                # The gap's account of itself. Present even on a clean window (0 degraded of N ticks),
                # because "the probe measured every tick" is a fact worth reading in an artifact too.
                "probe": {
                    "ticks": self.fd_probe_ticks,
                    "degraded_ticks": self.fd_probe_degraded_ticks,
                    "degraded": list(self.fd_probe_degraded),
                },
            },
            # BACKLOG #1292. Sequence numbers and MSA-1 codes only -- never control ids, per the
            # module docstring's metadata-only rule.
            "intake_audit": {
                "post_mortem": self.intake_audit.to_json_dict(),
                "live": self.intake_audit_live.to_json_dict(),
            },
            "wall5_reload": {"seconds": self.reload_seconds},
            "wall6_ack_ms": {
                "p50": round(self.ack_p50_ms, 3),
                "p95": round(self.ack_p95_ms, 3),
                "p99": round(self.ack_p99_ms, 3),
            },
        }


#: Hard cap on rows a CI step summary may carry. An oversized ``$GITHUB_STEP_SUMMARY`` write is dropped
#: ENTIRELY rather than trimmed, so a large profile must lose rows instead of losing the whole surface.
#: Truncation is always stated in the rendered text -- never a silent cap.
_MAX_SUMMARY_ROWS = 200


def lane_label(sweep_mode: str, claim_mode: str) -> str:
    """The lane's name as every connscale reading spells it.

    ``per_lane`` is the default claim mode and stays unqualified, so a pre-existing SLO detail string
    is unchanged. Defined once because the emitter and the SLO must agree: a reading filed under
    ``fixed_per_conn`` that a failure reports as ``fixed_per_conn/pooled`` is two distributions.
    """
    return sweep_mode if claim_mode == "per_lane" else f"{sweep_mode}/{claim_mode}"


@dataclass(frozen=True)
class MonotonicPair:
    """One consecutive smaller-N-to-larger-N comparison inside a single lane.

    The lane is ``(sweep_mode, claim_mode)`` — grouping by ``sweep_mode`` alone would chain a pooled
    reading onto a per_lane one, which BACKLOG #1101 records as wrong independently of whether a
    shipped profile currently triggers it.

    This is the SINGLE definition of the pairing. :func:`monotonic_pairs` is read both by the SLO that
    fails on an excursion and by the emitter that records every reading, so the numbers a passing run
    reports and the numbers a failing run reports cannot drift apart.
    """

    label: str  # ``sweep_mode``, or ``sweep_mode/claim_mode`` when the claim mode is not per_lane
    count: int  # the LARGER N — the reading being judged
    value: float  # the metric at that N
    prior: float  # the metric at the previous N in the same lane
    tolerance_floor: float  # the FRACTION, e.g. 0.75 — what the detail string prints after "*"
    threshold: float  # ``prior * tolerance_floor`` — the number ``value`` must actually beat
    ok: bool


def monotonic_pairs(
    records: list[ConnScaleRecord],
    key: Callable[[ConnScaleRecord], float | int | None],
    *,
    tolerance: float,
) -> list[MonotonicPair]:
    """Every consecutive comparison the loose monotonicity smoke makes, passing ones included.

    The SLO only ever needed the violations. An excursion-only record cannot establish the metric's
    variance, because the sample is selected on having already left the band (BACKLOG #1211) — so this
    returns the whole sequence and lets the caller decide which half it wants.

    Readings of ``None`` are skipped rather than failed, and a skipped reading does not become the
    ``prior`` for the next N.
    """
    by_lane: dict[tuple[str, str], list[ConnScaleRecord]] = {}
    for r in records:
        by_lane.setdefault((r.sweep_mode, r.claim_mode), []).append(r)

    floor = 1.0 - tolerance
    pairs: list[MonotonicPair] = []
    for (mode, claim_mode), rs in by_lane.items():
        prev_val: float | None = None
        for r in sorted(rs, key=lambda r: r.count):
            val = key(r)
            if val is None:
                continue
            v = float(val)
            if prev_val is not None:
                pairs.append(
                    MonotonicPair(
                        label=lane_label(mode, claim_mode),
                        count=r.count,
                        value=v,
                        prior=prev_val,
                        tolerance_floor=floor,
                        threshold=prev_val * floor,
                        ok=not (v < prev_val * floor),
                    )
                )
            prev_val = v
    return pairs


@dataclass(frozen=True)
class DiagnosticField:
    """One reading emitted for DIAGNOSIS, with no band and therefore no verdict.

    Deliberately separate from :class:`MonotonicPair`. A pair carries `prior`, `threshold` and an `ok`
    flag because its metric HAS an SLO band; these fields do not. Rendering a floor for a band-less
    field would print a threshold computed from an adjacent reading -- a number that looks measured and
    is manufactured by the renderer. Two shapes, because there are two kinds of reading.
    """

    label: str
    read: Callable[[ConnScaleRecord], object]
    #: Why this field is here -- which competing explanation it separates. Emitted in the table's
    #: preamble so a reader meeting it in a job summary knows what it is FOR, not just what it is.
    discriminates: str


#: The band-less readings emitted on every run (BACKLOG #1366).
#:
#: THESE ARE EXACTLY THE FIELDS THAT SEPARATE THE SURVIVING EXPLANATIONS for a connscale failure, which
#: is why the set is small and named rather than "everything on the record". Without them a failure is
#: permanently undiagnosable: the ratio says THAT something moved, and nothing says WHICH.
#:
#: Single definition -- the emitter and its tests both read this tuple, so a field added here is
#: covered without editing a second list.
DIAGNOSTIC_FIELDS: tuple[DiagnosticField, ...] = (
    DiagnosticField(
        "drain_seconds",
        lambda r: r.drain_seconds,
        "drain-tail vs reload-probe: these two separate ONLY on drain_seconds against reload_seconds",
    ),
    DiagnosticField(
        "reload_seconds",
        lambda r: r.reload_seconds,
        "the other half of that pair; None means the reload probe did not measure this step",
    ),
    DiagnosticField(
        "fd_probe_ticks",
        lambda r: r.fd_probe_ticks,
        "how many intervals the FD walk actually sampled -- a low count is a coarse gauge, not a fault",
    ),
    DiagnosticField(
        "fd_probe_degraded_ticks",
        lambda r: r.fd_probe_degraded_ticks,
        "contention vs probe-cost: NON-ZERO means the walk could not measure, ZERO means it measured "
        "cleanly and any wrong reading is a wrong SUBJECT rather than a failed sample",
    ),
    DiagnosticField(
        "cpu_util_cores_mean",
        lambda r: r.cpu_util_cores_mean,
        "how loaded the box was across the hold, which is the input every contention story needs",
    ),
)


@dataclass(frozen=True)
class ConnScaleReport:
    profile: str
    engine_url: str
    db_backend: str | None
    shim_installed: bool  # whether the executor boot-shim populated wall #1
    records: list[ConnScaleRecord]
    slos: list[SloCheck]
    result_ok: bool
    exit_code: int
    notes: list[str] = field(default_factory=list)
    # The per-count per_lane-vs-pooled A/B (ADR 0066), present only for a multi-arm profile
    # (``claim_modes`` with >1 entry). ``None`` for a single-arm run so a pre-existing report is
    # byte-identical.
    comparison: ClaimModeComparison | None = None
    # The per-cell B0-vs-B1 thread-hop-fusion A/B (ADR 0071 B5), present only for a multi-arm
    # ``fuse_modes`` profile (e.g. fuse_ab). ``None`` for a single fusion arm so a pre-existing report
    # is byte-identical.
    fuse_comparison: FuseModeComparison | None = None
    # The per-cell B0-vs-B1 statement-batching A/B (ADR 0075 Bench B), present only for a multi-arm
    # ``batch_modes`` profile (e.g. batch_ab). It is a :class:`FuseModeComparison` produced by the SAME
    # comparator (``build_batch_comparison`` reuses ``build_fuse_comparison``'s verdict path, keyed on
    # ``batch_handoff_statements`` and relabelled for the batching axis). ``None`` for a single batching
    # arm so a pre-existing report is byte-identical.
    batch_comparison: FuseModeComparison | None = None

    def to_json_dict(self) -> dict[str, object]:
        out: dict[str, object] = {
            "schema_version": SCHEMA_VERSION,
            "kind": "connscale",
            "profile": self.profile,
            "engine_url": self.engine_url,
            "db_backend": self.db_backend,
            "executor_shim_installed": self.shim_installed,
            "result": "PASS" if self.result_ok else "FAIL",
            "exit_code": self.exit_code,
            # Honest coverage caveat: on SQLite (the CI smoke) the pool wall is a no-op and the
            # executor wall is under-threshold at small N — stated so a reader doesn't over-read it.
            "coverage": _coverage_note(self.db_backend, self.shim_installed),
            "records": [r.to_json_dict() for r in self.records],
            "slo": [
                {"name": c.name, "threshold": c.threshold, "observed": c.observed, "ok": c.ok}
                for c in self.slos
            ],
            "notes": self.notes,
        }
        if self.comparison is not None:
            out["comparison"] = self.comparison.to_json_dict()
        if self.fuse_comparison is not None:
            out["fuse_comparison"] = self.fuse_comparison.to_json_dict()
        if self.batch_comparison is not None:
            out["batch_comparison"] = self.batch_comparison.to_json_dict()
        return out

    def to_json(self) -> str:
        return json.dumps(self.to_json_dict(), indent=2)

    def render_readings_markdown(
        self,
        metric: str,
        key: Callable[[ConnScaleRecord], float | int | None],
        *,
        tolerance: float,
        context: dict[str, str] | None = None,
        max_rows: int = _MAX_SUMMARY_ROWS,
    ) -> str:
        """Every reading of one monotonic metric as a markdown table — the passing ones included.

        BACKLOG #1211 needs the metric's true variance, and the SLO records a number only when it has
        already left the band. A sample selected on having excursioned cannot measure the distribution
        it excursioned from, so this renders the whole sequence on every run.

        Pure: returns the text and writes nothing. Row count is capped because an oversized
        ``$GITHUB_STEP_SUMMARY`` write is dropped in full rather than trimmed; a truncation SAYS so.
        """
        pair_by_row = {
            (p.label, p.count): p for p in monotonic_pairs(self.records, key, tolerance=tolerance)
        }
        rows: list[str] = []
        dropped = 0
        for r in sorted(self.records, key=lambda r: (r.sweep_mode, r.claim_mode, r.count)):
            val = key(r)
            if val is None:
                continue
            if len(rows) >= max_rows:
                dropped += 1
                continue
            label = lane_label(r.sweep_mode, r.claim_mode)
            pair = pair_by_row.get((label, r.count))
            if pair is None:
                # First reading in its lane: a real sample, but nothing to compare it against.
                rows.append(f"| {label} | {r.count} | {float(val):.4g} | | | | first in lane |")
            else:
                margin = pair.value - pair.threshold
                verdict = "within band" if pair.ok else "OUTSIDE BAND"
                rows.append(
                    f"| {label} | {r.count} | {pair.value:.4g} | {pair.prior:.4g} "
                    f"| {pair.threshold:.4g} | {margin:+.4g} | {verdict} |"
                )

        head = [f"### connscale {metric} readings"]
        ctx = {
            "profile": self.profile,
            "db_backend": self.db_backend or "sqlite",
            **(context or {}),
        }
        head.append("")
        head.append(" | ".join(f"{k}: {v}" for k, v in ctx.items()))
        head.append("")
        head.append(
            f"Recorded on every run, pass or fail (BACKLOG #1211). Band is prior * "
            f"{1.0 - tolerance:.2f}; a positive margin is inside it."
        )
        head.append("")
        if not rows:
            head.append(f"No {metric} reading was produced by this run.")
            return "\n".join(head) + "\n"
        head.append(f"| lane | N | {metric} | prior | band floor | margin | verdict |")
        head.append("|---|---|---|---|---|---|---|")
        out = head + rows
        if dropped:
            out.append("")
            out.append(f"{dropped} further row(s) not shown: capped at {max_rows}.")
        return "\n".join(out) + "\n"

    def readings_payload(
        self,
        metric: str,
        key: Callable[[ConnScaleRecord], float | int | None],
        *,
        tolerance: float,
        context: dict[str, str] | None = None,
    ) -> dict[str, object]:
        """The same readings as :meth:`render_readings_markdown`, machine-readable.

        WHY THIS EXISTS RATHER THAN JUST THE TABLE. The markdown goes to ``$GITHUB_STEP_SUMMARY``,
        and **no GitHub API exposes a step summary** -- measured 2026-08-27, on this repo, from two
        directions: the jobs endpoint carries no summary-bearing key, and the rendered page answers
        "Sign in to view logs" even though the repository is public. So every passing run's readings
        have been written and then been unreachable to any tool, which defeats the point of
        recording a passing run at all. An uploaded artifact IS fully API-reachable
        (``gh run download``), as this repo's own load reports already demonstrate.

        NOT CAPPED, deliberately, where the markdown is. That cap exists because an oversized step
        summary write is dropped IN FULL rather than trimmed; an artifact has no such cliff, and
        silently dropping rows from the machine-readable copy would be the worse trade.

        Both this and the table go through :func:`monotonic_pairs`, so they cannot disagree about a
        lane, a band or a verdict -- the single-definition rule that function's docstring states.
        """
        pair_by_row = {
            (p.label, p.count): p for p in monotonic_pairs(self.records, key, tolerance=tolerance)
        }
        readings: list[dict[str, object]] = []
        for r in sorted(self.records, key=lambda r: (r.sweep_mode, r.claim_mode, r.count)):
            val = key(r)
            if val is None:
                continue
            label = lane_label(r.sweep_mode, r.claim_mode)
            pair = pair_by_row.get((label, r.count))
            if pair is None:
                # First reading in its lane: a real sample with nothing to compare against. Recorded
                # rather than skipped -- it is the PRIOR for the next N and a reader needs its value.
                readings.append(
                    {
                        "lane": label,
                        "count": r.count,
                        "value": float(val),
                        "first_in_lane": True,
                    }
                )
                continue
            readings.append(
                {
                    "lane": label,
                    "count": r.count,
                    "value": pair.value,
                    "prior": pair.prior,
                    "threshold": pair.threshold,
                    "margin": pair.value - pair.threshold,
                    "ratio": (pair.value / pair.prior) if pair.prior else None,
                    "ok": pair.ok,
                    "first_in_lane": False,
                }
            )
        return {
            "schema_version": 1,
            "metric": metric,
            "profile": self.profile,
            "db_backend": self.db_backend or "sqlite",
            "tolerance": tolerance,
            "band_floor_fraction": 1.0 - tolerance,
            "context": dict(context or {}),
            "readings": readings,
        }

    def render_diagnostics_markdown(
        self,
        fields: tuple[DiagnosticField, ...] = DIAGNOSTIC_FIELDS,
        *,
        context: dict[str, str] | None = None,
        max_rows: int = _MAX_SUMMARY_ROWS,
    ) -> str:
        """The band-less diagnostic table, emitted on every run (BACKLOG #1366).

        NOT a variant of :meth:`render_readings_markdown`, and the separation is the point. That one
        renders `prior`, `band floor` and `margin` because its metric has an SLO band. ONLY
        ``empty_claims_monotonic`` and ``fd_count_monotonic`` have one; every field here has none, so
        those columns would be a floor computed from whichever reading happened to precede it --
        false precision manufactured by the renderer rather than measured by anything.

        So this table carries NO verdict column and NO threshold. It says what was observed and what
        each field is FOR, and leaves the judgement to a reader who has the competing explanations in
        front of them.

        Pure: returns text, writes nothing. Row count capped for the same reason as the banded table --
        an oversized ``$GITHUB_STEP_SUMMARY`` write is dropped in full rather than trimmed.
        """
        head = ["### connscale diagnostics (no band, no verdict)"]
        ctx = {
            "profile": self.profile,
            "db_backend": self.db_backend or "sqlite",
            **(context or {}),
        }
        head.append("")
        head.append(" | ".join(f"{k}: {v}" for k, v in ctx.items()))
        head.append("")
        head.append(
            "Recorded on every run, pass or fail. **None of these has an SLO band**, so there is no "
            "threshold here and nothing below is a verdict -- they are the readings that separate "
            "competing explanations for a failure (BACKLOG #1366)."
        )
        head.append("")
        for f in fields:
            head.append(f"- `{f.label}` -- {f.discriminates}")
        head.append("")

        if not self.records:
            head.append("No record was produced by this run.")
            return "\n".join(head) + "\n"

        head.append("| lane | N | " + " | ".join(f.label for f in fields) + " |")
        head.append("|---|---|" + "---|" * len(fields))

        rows: list[str] = []
        dropped = 0
        for r in sorted(self.records, key=lambda r: (r.sweep_mode, r.claim_mode, r.count)):
            if len(rows) >= max_rows:
                dropped += 1
                continue
            cells = []
            for f in fields:
                v = f.read(r)
                # `None` renders as an explicit dash, NEVER as 0. "the probe did not measure" and
                # "the probe measured zero" are different verdicts and the whole point of these
                # fields is telling them apart.
                cells.append("-" if v is None else (f"{v:.4g}" if isinstance(v, float) else str(v)))
            rows.append(
                f"| {lane_label(r.sweep_mode, r.claim_mode)} | {r.count} | "
                + " | ".join(cells)
                + " |"
            )

        out = head + rows
        if dropped:
            out.append("")
            out.append(f"{dropped} further row(s) not shown: capped at {max_rows}.")
        return "\n".join(out) + "\n"

    def to_csv(self) -> str:
        """One row per (sweep_mode, N) step — for spreadsheet curve plotting."""
        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow(
            [
                "profile",
                "claim_mode",
                "fuse_thread_hops",
                "batch_handoff_statements",
                "sweep_mode",
                "count",
                "offered_rate",
                "achieved_read_per_s",
                "achieved_written_per_s",
                "sent",
                "acked",
                "no_loss",
                "in_pipeline_peak",
                "exec_queue_depth_peak",
                "exec_busy_peak",
                "pool_wait_p99_ms",
                "pool_idle_min",
                "empty_claims_per_s",
                "idle_poll_per_s",
                "wake_fanout_per_s",
                "fd_count_peak",
                "cpu_seconds_total",
                "cpu_util_cores_mean",
                "working_set_peak_bytes",
                "reload_seconds",
                "ack_p99_ms",
            ]
        )
        for r in self.records:
            writer.writerow(
                [
                    _spreadsheet_safe(self.profile),
                    _spreadsheet_safe(r.claim_mode),
                    r.fuse_thread_hops,
                    r.batch_handoff_statements,
                    _spreadsheet_safe(r.sweep_mode),
                    r.count,
                    round(r.offered_aggregate_rate, 2),
                    round(r.achieved_read_per_s, 2),
                    round(r.achieved_written_per_s, 2),
                    r.sent,
                    r.acked,
                    r.no_loss.ok,
                    r.in_pipeline_peak,
                    _na(r.executor_queue_depth_peak),
                    _na(r.executor_busy_peak),
                    _na(r.pool_wait_p99_ms),
                    _na(r.pool_idle_min),
                    round(r.empty_claims_per_s, 2),
                    round(r.idle_poll_per_s, 2),
                    round(r.wake_fanout_per_s, 2),
                    _na(r.fd_count_peak),
                    _na(_round_or_none(r.cpu_seconds_total, 2)),
                    _na(_round_or_none(r.cpu_util_cores_mean, 3)),
                    _na(r.working_set_peak_bytes),
                    _na(r.reload_seconds),
                    round(r.ack_p99_ms, 2),
                ]
            )
        return buf.getvalue()

    def render_console(self) -> str:
        lines: list[str] = []
        lines.append(
            f"Connection-scale report -- profile {self.profile!r} against {self.engine_url} "
            f"(backend {self.db_backend or 'sqlite'})"
        )
        lines.append(_coverage_note(self.db_backend, self.shim_installed))
        lines.append("")
        header = (
            f"{'claim':<9}{'mode':<16}{'N':>6}{'rate':>8}{'achv/s':>8}{'sent':>9}{'inpipe':>7}{'exqd':>6}"
            f"{'poolp99':>9}{'idle':>6}{'empty/s':>9}{'wake/s':>8}{'idle/s':>8}{'fd':>7}{'cpu_s':>8}{'reload':>8}{'ackp99':>9}"
        )
        lines.append(header)
        lines.append("-" * len(header))
        for r in self.records:
            lines.append(
                f"{r.claim_mode:<9}{r.sweep_mode:<16}{r.count:>6}{r.offered_aggregate_rate:>8.0f}"
                f"{r.achieved_read_per_s:>8.0f}{r.sent:>9}"
                f"{r.in_pipeline_peak:>7}{_na(r.executor_queue_depth_peak):>6}"
                f"{_na(r.pool_wait_p99_ms):>9}{_na(r.pool_idle_min):>6}"
                f"{r.empty_claims_per_s:>9.1f}{r.wake_fanout_per_s:>8.1f}{r.idle_poll_per_s:>8.1f}"
                f"{_na(r.fd_count_peak):>7}{_na(_round_or_none(r.cpu_seconds_total, 1)):>8}"
                f"{_na(r.reload_seconds):>8}{r.ack_p99_ms:>9.1f}"
            )
        # The `fd` column renders `n/a` on a gap, and nobody can act on `n/a`. Name the mechanism beside
        # it, with the scope of the count, so the console says which of the probe's degrade paths fired.
        for r in self.records:
            if r.fd_probe_degraded_ticks:
                causes = ", ".join(r.fd_probe_degraded) or "cause not recorded"
                lines.append(
                    f"fd probe: {r.sweep_mode}@N={r.count} -- {r.fd_probe_degraded_ticks} of "
                    f"{r.fd_probe_ticks} tick(s) measured nothing [{causes}]"
                )
        # BACKLOG #1292: the per-message attribution, printed whenever it says anything beyond "clean".
        # A `no_loss` shortfall renders as a bare count in the table above, which is exactly the
        # unattributable failure this exists to replace -- so the verdict goes on the console beside
        # it, not only in the JSON artifact.
        for r in self.records:
            for audit in (r.intake_audit_live, r.intake_audit):
                if audit.verdict in (VERDICT_INTAKE_COMPLETE, VERDICT_NOT_RUN):
                    continue
                lines.append(f"{r.sweep_mode}@N={r.count} -- {audit.summary()}")
        lines.append("")
        lines.append("SLOs:")
        if not self.slos:
            lines.append("  (none defined)")
        for c in self.slos:
            lines.append(
                f"  [{'PASS' if c.ok else 'FAIL'}] {c.name}: observed={c.observed} threshold={c.threshold}"
            )
        for note in self.notes:
            lines.append(f"note: {note}")
        if self.comparison is not None:
            lines.append("")
            lines.append(self.comparison.render_table())
        if self.fuse_comparison is not None:
            lines.append("")
            lines.append(self.fuse_comparison.render_table())
        if self.batch_comparison is not None:
            lines.append("")
            lines.append(self.batch_comparison.render_table())
        violated = sum(1 for c in self.slos if not c.ok)
        lines.append("")
        lines.append(
            f"RESULT: {'PASS' if self.result_ok else 'FAIL'}"
            f"{'' if self.result_ok else f' ({violated} violated)'} -> exit {self.exit_code}"
        )
        return "\n".join(lines)


def _coverage_note(db_backend: str | None, shim_installed: bool) -> str:
    parts: list[str] = []
    if db_backend in (None, "sqlite"):
        parts.append(
            "SQLite store: the pool-wait wall (#2) is a documented NO-OP (no pool), so its curve is "
            "absent here — run against postgres/sqlserver for real pool-wait coverage"
        )
    if not shim_installed:
        parts.append(
            "executor boot-shim NOT installed: wall #1 (executor queue depth/busy) is unmeasured this "
            "run (set MEFOR_CONNSCALE_EXECUTOR_SHIM in the engine env to populate it)"
        )
    return "coverage: " + ("; ".join(parts) if parts else "all walls measured") + "."


def _na(value: object) -> object:
    """Render a missing measurement as the literal ``n/a`` (a None gauge — e.g. pool on SQLite, the
    executor shim off, or an unreadable FD probe), so a curve cell is never silently 0."""
    return "n/a" if value is None else value


def _round_or_none(value: float | None, digits: int) -> float | None:
    """Round a float gauge for the JSON artifact, preserving ``None`` (an unreadable probe) as ``None``
    so a missing CPU/RSS reading is never coerced to a misleading 0.0."""
    return None if value is None else round(value, digits)
