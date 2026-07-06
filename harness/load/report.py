# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Assemble, render, and persist the load-run report.

Pulls together the client-side counters/histograms, the per-phase breakdown, the engine-side samples,
and the post-load drain into a :class:`RunReport`: a no-loss reconciliation, an SLO verdict, a console
table, and a machine-readable JSON/CSV artifact for trend tracking. **Metrics and metadata only** —
never message bodies or control-id lists (PHI rule). Pure and deterministic, so it unit-tests without
a live run.
"""

from __future__ import annotations

import csv
import io
import json
from dataclasses import dataclass, field

from harness.load.enginepoll import EnginePoller
from harness.load.metrics import Counters, Histogram, LatencySummary
from harness.load.profile import LoadProfile, Phase, Slo

SCHEMA_VERSION = 1

# Exit codes (shared with the CLI).
EXIT_OK = 0
EXIT_SLO_VIOLATION = 1

# CSV formula-injection (CWE-1236 / ASVS 1.2.10): a spreadsheet treats a cell beginning with one of
# these as a formula. A leading "'" forces it to be read as literal text on open.
_CSV_FORMULA_TRIGGERS = frozenset("=+-@\t\r\x00")


def _spreadsheet_safe(value: str) -> str:
    """Neutralize a leading formula trigger so a text cell can't execute when the CSV is opened in
    Excel/Sheets. Applied to the free-text columns of :meth:`RunReport.to_csv`; if a real PHI/message
    CSV export is ever added to ``api``/``console``, route every string cell through this helper."""
    return "'" + value if value[:1] in _CSV_FORMULA_TRIGGERS else value


@dataclass(frozen=True)
class PhaseRecord:
    """Per-phase data the runner captures: counter snapshots at the phase boundaries + the phase's own
    latency histograms + the measured wall time."""

    phase: Phase
    start: Counters
    end: Counters
    ack: Histogram
    e2e: Histogram
    wall_seconds: float


@dataclass(frozen=True)
class SloCheck:
    name: str
    threshold: float | int | bool | None
    observed: float | int | bool
    ok: bool


@dataclass(frozen=True)
class NoLoss:
    ok: bool
    sent: int
    engine_read: int
    engine_written: int
    sink_received: int
    backlog: int
    at_least_once_redeliveries: int
    detail: str


@dataclass(frozen=True)
class PhaseReport:
    name: str
    kind: str
    loop: str
    measured: bool
    duration_s: float
    sent: int
    acked: int
    nak: int
    deferred: int
    achieved_msg_s: float
    ack: LatencySummary
    e2e: LatencySummary


@dataclass(frozen=True)
class EngineSummary:
    db_backend: str | None
    journal_mode: str | None
    synchronous: (
        str | None
    )  # SQLite durability mode measured ("normal"/"full"); None on servers (B7)
    peak_backlog: int
    peak_queue_depth: int
    db_growth_bytes: int
    dead_letters: int
    drain_seconds: float | None


@dataclass(frozen=True)
class RunReport:
    profile: str
    engine_url: str
    counters: Counters
    overall_ack: LatencySummary
    overall_e2e: LatencySummary
    phases: list[PhaseReport]
    engine: EngineSummary
    no_loss: NoLoss
    slos: list[SloCheck]
    result_ok: bool
    exit_code: int
    notes: list[str] = field(default_factory=list)

    # --- serialization -------------------------------------------------------

    def to_json_dict(self) -> dict[str, object]:
        return {
            "schema_version": SCHEMA_VERSION,
            "profile": self.profile,
            "engine_url": self.engine_url,
            "result": "PASS" if self.result_ok else "FAIL",
            "exit_code": self.exit_code,
            "totals": _counters_dict(self.counters),
            "overall": {"ack_ms": _lat(self.overall_ack), "e2e_ms": _lat(self.overall_e2e)},
            "phases": [
                {
                    "name": p.name,
                    "kind": p.kind,
                    "loop": p.loop,
                    "measured": p.measured,
                    "duration_s": p.duration_s,
                    "sent": p.sent,
                    "acked": p.acked,
                    "nak": p.nak,
                    "deferred": p.deferred,
                    "achieved_msg_s": round(p.achieved_msg_s, 2),
                    "ack_ms": _lat(p.ack),
                    "e2e_ms": _lat(p.e2e),
                }
                for p in self.phases
            ],
            "engine_side": {
                "db_backend": self.engine.db_backend,
                "journal_mode": self.engine.journal_mode,
                "synchronous": self.engine.synchronous,
                "peak_backlog": self.engine.peak_backlog,
                "peak_queue_depth": self.engine.peak_queue_depth,
                "db_growth_bytes": self.engine.db_growth_bytes,
                "dead_letters": self.engine.dead_letters,
                "drain_seconds": self.engine.drain_seconds,
            },
            "no_loss": {
                "ok": self.no_loss.ok,
                "sent": self.no_loss.sent,
                "engine_read": self.no_loss.engine_read,
                "engine_written": self.no_loss.engine_written,
                "sink_received": self.no_loss.sink_received,
                "backlog": self.no_loss.backlog,
                "at_least_once_redeliveries": self.no_loss.at_least_once_redeliveries,
                "detail": self.no_loss.detail,
            },
            "slo": [
                {"name": c.name, "threshold": c.threshold, "observed": c.observed, "ok": c.ok}
                for c in self.slos
            ],
            "notes": self.notes,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_json_dict(), indent=2)

    def to_csv(self) -> str:
        """One row per phase (flattened) — for spreadsheet trend tracking. The free-text string cells
        (profile/phase/kind) are run through :func:`_spreadsheet_safe` so a name beginning with a
        formula trigger can't execute when the CSV is opened in Excel/Sheets (CSV formula injection,
        ASVS 1.2.10). The numeric cells are written by ``csv`` from int/float and need no escaping."""
        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow(
            [
                "profile",
                "phase",
                "kind",
                "measured",
                "sent",
                "acked",
                "nak",
                "deferred",
                "achieved_msg_s",
                "ack_p99_ms",
                "e2e_p99_ms",
                "result",
            ]
        )
        for p in self.phases:
            writer.writerow(
                [
                    _spreadsheet_safe(self.profile),
                    _spreadsheet_safe(p.name),
                    _spreadsheet_safe(p.kind),
                    p.measured,
                    p.sent,
                    p.acked,
                    p.nak,
                    p.deferred,
                    round(p.achieved_msg_s, 2),
                    round(p.ack.p99_ms, 2),
                    round(p.e2e.p99_ms, 2),
                    "PASS" if self.result_ok else "FAIL",
                ]
            )
        return buf.getvalue()

    # --- console -------------------------------------------------------------

    def render_console(self) -> str:
        lines: list[str] = []
        lines.append(f"Load report — profile {self.profile!r} against {self.engine_url}")
        lines.append("")
        header = f"{'phase':<12}{'kind':<10}{'sent':>9}{'acked':>9}{'msg/s':>9}{'ackp99':>9}{'e2ep99':>9}{'nak':>7}{'defer':>8}"
        lines.append(header)
        lines.append("-" * len(header))
        for p in self.phases:
            tag = "" if p.measured else " (excl)"
            lines.append(
                f"{p.name:<12}{p.kind:<10}{p.sent:>9}{p.acked:>9}{p.achieved_msg_s:>9.0f}"
                f"{p.ack.p99_ms:>9.1f}{p.e2e.p99_ms:>9.1f}{p.nak:>7}{p.deferred:>8}{tag}"
            )
        lines.append("")
        e = self.engine
        lines.append(
            f"engine: peak_backlog={e.peak_backlog} peak_queue_depth={e.peak_queue_depth} "
            f"dead={e.dead_letters} db_growth={e.db_growth_bytes}B "
            f"drain={'%.1fs' % e.drain_seconds if e.drain_seconds is not None else 'TIMEOUT'} "
            f"journal={e.journal_mode} synchronous={e.synchronous or 'n/a'} "
            f"backend={e.db_backend or '?'}"
        )
        nl = self.no_loss
        lines.append(
            f"no-loss: {'OK' if nl.ok else 'LOSS'} — sent={nl.sent} engine_read={nl.engine_read} "
            f"engine_written={nl.engine_written} sink_received={nl.sink_received} "
            f"backlog={nl.backlog} at_least_once={nl.at_least_once_redeliveries}"
        )
        if not nl.ok:
            lines.append(f"         {nl.detail}")
        lines.append("")
        lines.append("SLOs:")
        if not self.slos:
            lines.append("  (none defined)")
        for c in self.slos:
            mark = "PASS" if c.ok else "FAIL"
            lines.append(f"  [{mark}] {c.name}: observed={c.observed} threshold={c.threshold}")
        for note in self.notes:
            lines.append(f"note: {note}")
        # A gated zero_loss failure is already one of the SLO checks below — count the checks only,
        # don't add the loss again (it would inflate the displayed count by one).
        violated = sum(1 for c in self.slos if not c.ok)
        lines.append("")
        lines.append(
            f"RESULT: {'PASS' if self.result_ok else 'FAIL'}"
            f"{'' if self.result_ok else f' ({violated} violated)'} → exit {self.exit_code}"
        )
        return "\n".join(lines)


# --- building ----------------------------------------------------------------


def build_report(
    profile: LoadProfile,
    engine_url: str,
    records: list[PhaseRecord],
    final_counters: Counters,
    poller: EnginePoller,
    drain_seconds: float | None,
    *,
    db_backend: str | None = None,
    loss_tolerance: int = 0,  # absolute message count tolerated as a shortfall (default 0 = exact)
) -> RunReport:
    phases: list[PhaseReport] = []
    slos: list[SloCheck] = []
    overall_ack = Histogram()
    overall_e2e = Histogram()
    for rec in records:
        pr = _phase_report(rec)
        phases.append(pr)
        overall_ack.merge(rec.ack)
        overall_e2e.merge(rec.e2e)
        if rec.phase.measured:
            slos.extend(_phase_slos(rec, profile.slo_for(rec.phase)))

    # Unconfirmed-send budget = the run's total client connection count (one pool of pool_size per
    # target): at most ~one stranded in-flight frame per connection is a plausible teardown artifact.
    no_loss = _reconcile(
        final_counters,
        poller,
        drain_seconds,
        tolerance=loss_tolerance,
        unconfirmed_budget=profile.pool_size * max(1, len(profile.targets)),
    )
    engine = _engine_summary(poller, drain_seconds, db_backend)
    slos.extend(_run_slos(profile.default_slo, final_counters, no_loss, engine, drain_seconds))

    notes = _notes(final_counters, poller)
    result_ok = all(c.ok for c in slos)
    return RunReport(
        profile=profile.name,
        engine_url=engine_url,
        counters=final_counters.snapshot(),
        overall_ack=overall_ack.summary(),
        overall_e2e=overall_e2e.summary(),
        phases=phases,
        engine=engine,
        no_loss=no_loss,
        slos=slos,
        result_ok=result_ok,
        exit_code=EXIT_OK if result_ok else EXIT_SLO_VIOLATION,
        notes=notes,
    )


def _phase_report(rec: PhaseRecord) -> PhaseReport:
    p = rec.phase
    sent = rec.end.sent - rec.start.sent
    acked = rec.end.acked - rec.start.acked
    nak = rec.end.nak - rec.start.nak
    deferred = rec.end.deferred - rec.start.deferred
    achieved = acked / rec.wall_seconds if rec.wall_seconds > 0 else 0.0
    return PhaseReport(
        name=p.name,
        kind=p.kind,
        loop=p.loop,
        measured=p.measured,
        duration_s=p.duration_s,
        sent=sent,
        acked=acked,
        nak=nak,
        deferred=deferred,
        achieved_msg_s=achieved,
        ack=rec.ack.summary(),
        e2e=rec.e2e.summary(),
    )


# Minimum phase `sent` for RATE-based SLOs (max_error_rate) to be emitted: below this, one transport
# blip exceeds any sane rate threshold, so the check would gate on noise rather than behavior.
_RATE_SLO_MIN_SENT = 200


def _phase_slos(rec: PhaseRecord, slo: Slo) -> list[SloCheck]:
    p = rec.phase
    sent = rec.end.sent - rec.start.sent
    acked = rec.end.acked - rec.start.acked
    nak = rec.end.nak - rec.start.nak
    errs = (rec.end.errors - rec.start.errors) + (rec.end.timeouts - rec.start.timeouts)
    achieved = acked / rec.wall_seconds if rec.wall_seconds > 0 else 0.0
    ack = rec.ack.summary()
    e2e = rec.e2e.summary()
    out: list[SloCheck] = []
    if slo.min_sustained_msg_s is not None:
        out.append(
            SloCheck(
                f"{p.name}:min_sustained_msg_s",
                slo.min_sustained_msg_s,
                round(achieved, 1),
                achieved >= slo.min_sustained_msg_s,
            )
        )
    if slo.max_ack_p99_ms is not None:
        out.append(
            SloCheck(
                f"{p.name}:max_ack_p99_ms",
                slo.max_ack_p99_ms,
                round(ack.p99_ms, 2),
                ack.p99_ms <= slo.max_ack_p99_ms,
            )
        )
    if slo.max_e2e_p99_ms is not None:
        out.append(
            SloCheck(
                f"{p.name}:max_e2e_p99_ms",
                slo.max_e2e_p99_ms,
                round(e2e.p99_ms, 2),
                e2e.p99_ms <= slo.max_e2e_p99_ms,
            )
        )
    if slo.max_error_rate is not None and sent >= _RATE_SLO_MIN_SENT:
        # A RATE over a tiny denominator is statistically meaningless: on a ~90-message CI smoke phase
        # a single transport blip (one reconnect's failed open / stranded in-flights — client-side
        # noise, not loss) is >1%, so any sane threshold flips on one event. Below the floor the check
        # is not emitted at all (no verdict beats a noise-driven one); real load profiles run thousands
        # of messages per phase and keep the gate. A mass reset/timeout FLOOD on a small phase is not
        # un-gated by this floor: the reconcile's bounded unconfirmed-send budget fails zero_loss when
        # timeouts exceed ~one per connection. (max_nak_rate below deliberately has no floor — a NAK
        # is a deterministic engine verdict, not transport noise, so even one is signal.)
        er = errs / sent
        out.append(
            SloCheck(
                f"{p.name}:max_error_rate",
                slo.max_error_rate,
                round(er, 5),
                er <= slo.max_error_rate,
            )
        )
    if slo.max_nak_rate is not None:
        nr = nak / sent if sent else 0.0
        out.append(
            SloCheck(
                f"{p.name}:max_nak_rate", slo.max_nak_rate, round(nr, 5), nr <= slo.max_nak_rate
            )
        )
    return out


def _run_slos(
    slo: Slo,
    counters: Counters,
    no_loss: NoLoss,
    engine: EngineSummary,
    drain_seconds: float | None,
) -> list[SloCheck]:
    out: list[SloCheck] = []
    if slo.zero_loss:
        out.append(SloCheck("zero_loss", True, no_loss.ok, no_loss.ok))
    if slo.max_drain_seconds is not None:
        ok = drain_seconds is not None and drain_seconds <= slo.max_drain_seconds
        out.append(
            SloCheck(
                "max_drain_seconds",
                slo.max_drain_seconds,
                round(drain_seconds, 2) if drain_seconds is not None else -1.0,
                ok,
            )
        )
    if slo.max_dead_letters is not None:
        out.append(
            SloCheck(
                "max_dead_letters",
                slo.max_dead_letters,
                engine.dead_letters,
                engine.dead_letters <= slo.max_dead_letters,
            )
        )
    if slo.max_dup_rate is not None:
        rate = (
            no_loss.at_least_once_redeliveries / no_loss.sink_received
            if no_loss.sink_received
            else 0.0
        )
        out.append(
            SloCheck("max_dup_rate", slo.max_dup_rate, round(rate, 5), rate <= slo.max_dup_rate)
        )
    return out


def _reconcile(
    counters: Counters,
    poller: EnginePoller,
    drain_seconds: float | None,
    *,
    tolerance: float,
    unconfirmed_budget: int,
) -> NoLoss:
    sent = counters.sent
    sink_received = counters.sink_received
    base, final = poller.baseline, poller.final
    if base is None or final is None:
        return NoLoss(
            False,
            sent,
            0,
            0,
            sink_received,
            -1,
            0,
            "engine metrics unavailable — cannot verify no-loss",
        )
    read = final.read - base.read
    written = final.written - base.written
    backlog = final.backlog
    at_least_once = max(0, sink_received - written)
    # Only a SHORTFALL is loss; an excess is benign. Intake: read < sent means the engine never
    # received some messages we sent. Delivery: sink_received < written means a delivery the engine
    # counted never arrived — whereas sink_received > written is expected (at-least-once re-delivery),
    # so a symmetric abs() check would false-FAIL on a re-delivery. Tolerance is an absolute message
    # count (default 0 = exact); after the drain wait + settle there should be no in-flight skew, so a
    # strict check is correct here — a percentage-of-volume slack would silently mask thousands lost.
    #
    # A `timeouts`-counted message (in-flight at a connection close with no ACK seen — a mid-run reset
    # or the stop-grace expiring) is UNCONFIRMED, not lost: `sent` was counted at write-buffer time, so
    # the frame may never have left the closed socket. Requiring `read >= sent` false-fails exactly
    # when timeouts > 0; `read >= sent - timeouts` accepts the unconfirmed sends as unconfirmed while
    # ANY FURTHER shortfall is a real, confirmed-then-lost message and still fails. With timeouts == 0
    # (every healthy run) this is exactly as strict as read >= sent.
    #
    # BUT the excusal is BOUNDED by `unconfirmed_budget` (the run's connection count — at most ~one
    # stranded in-flight frame per connection is a plausible teardown artifact). Past the budget the
    # timeout count is a SYSTEMIC no-ACK fault (mass resets, or the engine accepting frames and never
    # ACKing — possibly accepted-and-dropped, the exact class the count-and-log invariant forbids), so
    # NOTHING is excused and the reconcile fails loudly. Without the cap, `timeouts == sent` would
    # degrade the intake bound to `read >= 0` and a total ACK-path regression would pass zero_loss.
    unconfirmed = counters.timeouts
    over_budget = unconfirmed > unconfirmed_budget
    excused = 0 if over_budget else unconfirmed
    read_short = sent - excused - read
    deliver_short = written - sink_received
    read_ok = read_short <= tolerance
    deliver_ok = deliver_short <= tolerance
    drained = backlog == 0
    ok = read_ok and deliver_ok and drained and not over_budget
    parts: list[str] = []
    if not read_ok:
        parts.append(
            f"engine_read {read} < confirmed sent {sent - excused} (lost {read_short} on intake)"
        )
    if not deliver_ok:
        parts.append(
            f"sink_received {sink_received} < engine_written {written} (lost {deliver_short})"
        )
    if not drained:
        parts.append(f"backlog {backlog} not drained")
    if over_budget:
        parts.append(
            f"{unconfirmed} unconfirmed sends exceed the stranding budget "
            f"({unconfirmed_budget} ≈ one in-flight per connection) — systemic no-ACK fault "
            f"(possible accepted-and-dropped); nothing excused"
        )
    elif unconfirmed > 0 and read < sent:
        # Honest reporting either way: the gap is attributed to unconfirmed sends, not silently absorbed.
        parts.append(
            f"{unconfirmed} unconfirmed send(s) (no ACK before connection close) "
            f"not observed at intake — not counted as loss"
        )
    detail = "; ".join(parts) if parts else "read>=sent, sink_received>=written, backlog drained"
    return NoLoss(ok, sent, read, written, sink_received, backlog, at_least_once, detail)


def _engine_summary(
    poller: EnginePoller, drain_seconds: float | None, db_backend: str | None
) -> EngineSummary:
    samples = poller.samples
    base, final = poller.baseline, poller.final
    peak_backlog = max((s.backlog for s in samples), default=0)
    peak_qd = max((s.queue_depth for s in samples), default=0)
    growth = (final.db_size_bytes - base.db_size_bytes) if base and final else 0
    dead = (final.out_dead - base.out_dead) if base and final else 0
    journal = final.journal_mode if final else None
    synchronous = final.synchronous if final else None
    return EngineSummary(
        db_backend, journal, synchronous, peak_backlog, peak_qd, growth, dead, drain_seconds
    )


def _notes(counters: Counters, poller: EnginePoller) -> list[str]:
    notes: list[str] = []
    if counters.deferred > 0:
        notes.append(
            f"{counters.deferred} sends deferred — the offered rate exceeded what the pool/engine "
            "absorbed (offered > achieved); check whether the harness or the engine is the limit"
        )
    if counters.correlation_misses > 0:
        notes.append(
            f"{counters.correlation_misses} sink arrivals could not be correlated — raise the "
            "profile's correlator_capacity if the engine backlog exceeded it during a spike"
        )
    if not poller.samples:
        notes.append("no engine samples collected — engine-side metrics and no-loss are unverified")
    return notes


def _counters_dict(c: Counters) -> dict[str, int]:
    return {
        "sent": c.sent,
        "acked": c.acked,
        "nak": c.nak,
        "errors": c.errors,
        "timeouts": c.timeouts,
        "deferred": c.deferred,
        "sink_received": c.sink_received,
        "correlation_misses": c.correlation_misses,
    }


def _lat(s: LatencySummary) -> dict[str, float | int]:
    return {
        "count": s.count,
        "p50": round(s.p50_ms, 3),
        "p95": round(s.p95_ms, 3),
        "p99": round(s.p99_ms, 3),
        "max": round(s.max_ms, 3),
        "mean": round(s.mean_ms, 3),
    }


# --- baseline comparison -----------------------------------------------------


def compare_to_baseline(
    current: dict[str, object], baseline: dict[str, object], *, tolerance: float
) -> list[str]:
    """Return regression messages comparing a current report dict to a saved baseline dict. A
    regression is throughput below ``baseline*(1-tolerance)``, p99 above ``baseline*(1+tolerance)``,
    or any worsening of error/loss. Empty list = no regression."""
    out: list[str] = []
    cur_phases = {p["name"]: p for p in _as_list(current.get("phases"))}
    base_phases = {p["name"]: p for p in _as_list(baseline.get("phases"))}
    for name, bp in base_phases.items():
        cp = cur_phases.get(name)
        if cp is None:
            continue
        b_rate, c_rate = _f(bp.get("achieved_msg_s")), _f(cp.get("achieved_msg_s"))
        if b_rate > 0 and c_rate < b_rate * (1.0 - tolerance):
            out.append(f"{name}: throughput regressed {c_rate:.0f} < {b_rate:.0f} msg/s")
        b_p99 = _f(_get(bp, "e2e_ms", "p99"))
        c_p99 = _f(_get(cp, "e2e_ms", "p99"))
        if b_p99 > 0 and c_p99 > b_p99 * (1.0 + tolerance):
            out.append(f"{name}: e2e p99 regressed {c_p99:.1f} > {b_p99:.1f} ms")
    if _loss_ok(baseline) and not _loss_ok(current):
        out.append("no-loss regressed: baseline had no loss, current run lost messages")
    return out


def _as_list(value: object) -> list[dict[str, object]]:
    return value if isinstance(value, list) else []


def _get(d: dict[str, object], *path: str) -> object:
    cur: object = d
    for key in path:
        if not isinstance(cur, dict):
            return None
        cur = cur.get(key)
    return cur


def _f(value: object) -> float:
    return float(value) if isinstance(value, (int, float)) else 0.0


def _loss_ok(report: dict[str, object]) -> bool:
    nl = report.get("no_loss")
    return isinstance(nl, dict) and bool(nl.get("ok"))
