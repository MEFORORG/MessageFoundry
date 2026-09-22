# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
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

from harness._spreadsheet import SPREADSHEET_FORMULA_TRIGGERS, spreadsheet_safe
from harness.load.enginepoll import EnginePoller
from harness.load.metrics import Counters, Histogram, LatencySummary
from harness.load.profile import LoadProfile, Phase, Slo

SCHEMA_VERSION = 3  # 1→2: committed_txns + txn_per_message_measured; 2→3: body_copies +
# copies_per_message (the #207 sizing proxy — a COPY COUNT, never a byte figure; ADR 0141)

# Exit codes (shared with the CLI).
EXIT_OK = 0
EXIT_SLO_VIOLATION = 1

# CSV formula-injection (CWE-1236 / ASVS 1.2.10): a spreadsheet treats a cell beginning with one of
# these as a formula. A leading "'" forces it to be read as literal text on open. The rule is the
# shared one (harness/_spreadsheet.py) — this module used to carry its own copy.
_CSV_FORMULA_TRIGGERS = SPREADSHEET_FORMULA_TRIGGERS


def _spreadsheet_safe(value: str) -> str:
    """Neutralize a leading formula trigger so a text cell can't execute when the CSV is opened in
    Excel/Sheets. Applied to the free-text columns of :meth:`RunReport.to_csv`; if a real PHI/message
    CSV export is ever added to ``api``/``console``, route every string cell through this helper."""
    return spreadsheet_safe(value)


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
    #: Most of what the run offered was never replied to, so it is a weak MEASUREMENT even when
    #: nothing it confirmed was lost. It decides no verdict (BACKLOG #1866) — it exists so `render`
    #: can surface the note on a PASSING run without matching on `detail`'s wording, which would
    #: also have surfaced the benign per-run stranding note and made an indented line under
    #: `no-loss: OK` the normal shape of a contended CI log. Defaulted, so every existing positional
    #: construction is unchanged.
    heavily_stranded: bool = False


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
    # #207 loose end 1 — the MEASURED durable-write cost, self-differenced from the live
    # `committed_txns` store counter (final − base), beside the ANALYTICAL `3 + 2H + 2N` model
    # (ADR 0051). ``committed_txns`` is the run delta; ``txn_per_message_measured`` divides it by the
    # run message count (``Counters.acked``). The per-message figure is ``None`` — "not measured" —
    # whenever the counter never moved (Postgres never wired it, so it reads a flat 0) or no message
    # was acked, NEVER a fabricated 0.0/msg: every real run that acks a message commits at least its
    # ingress row, so a 0 delta over acked traffic is an unwired counter, not a zero-transaction run.
    committed_txns: int = 0
    txn_per_message_measured: float | None = None
    # #207 loose end 2 — the SIZING proxy, self-differenced from the live `body_copies` store counter
    # (final − base) exactly as `committed_txns` above. ``copies_per_message`` divides it by the run
    # message count (``Counters.acked``) to give the measured **body copies per message** — the live
    # counterpart of the analytical `2 + H + N` amplification model
    # (tests/test_bytes_per_message_amplification.py).
    #
    # IT IS A COPY COUNT, NOT BYTES, and it is BACKEND-DEPENDENT — both facts are rendered with the
    # figure (ADR 0141). SQLite store-once-dedups a byte-identical fan-out (`shared_body` + `body_ref`
    # ⇒ 1 copy) where SQL Server writes N inline copies, so the same traffic reads differently per
    # backend and the backend name is part of the reading. No bytes/msg figure is published from it:
    # converting copies to durable bytes needs NVARCHAR UTF-16 (×2), cipher expansion, and row/index/
    # transaction-log overhead, none of which this counter sees — a `db_size_bytes`-delta ÷ acked
    # figure is plausible-but-wrong, and the refusal to publish one stands.
    #
    # ``copies_per_message`` is ``None`` — "not measured" — whenever the counter never moved (Postgres
    # never wired it, so it reads a flat 0) or nothing was acked, NEVER a fabricated 0.0/msg: every
    # real run that acks a message writes at least its `messages.raw` + ingress `queue.payload` copies,
    # so a 0 delta over acked traffic is an unwired counter, not a zero-copy run.
    body_copies: int = 0
    copies_per_message: float | None = None


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
                # #207: the MEASURED durable-write cost beside the analytical 3+2H+2N model. `null`
                # per-message ⇒ NOT MEASURED (Postgres never wired the counter, or no acked message),
                # never a fabricated 0/msg — see EngineSummary.
                "committed_txns": self.engine.committed_txns,
                "txn_per_message_measured": (
                    round(self.engine.txn_per_message_measured, 3)
                    if self.engine.txn_per_message_measured is not None
                    else None
                ),
                # #207 loose end 2: the SIZING proxy — body COPIES per message, the live counterpart
                # of the analytical 2+H+N model. `null` per-message ⇒ NOT MEASURED (Postgres never
                # wired the counter, or no acked message), never a fabricated 0/msg. The unit and the
                # backend travel WITH the number because it is neither bytes nor backend-portable
                # (SQLite dedups an identical fan-out to 1 copy, SQL Server writes N) — and no
                # bytes/msg figure is published from it (ADR 0141). See EngineSummary.
                "body_copies": self.engine.body_copies,
                "copies_per_message": (
                    round(self.engine.copies_per_message, 3)
                    if self.engine.copies_per_message is not None
                    else None
                ),
                "copies_per_message_backend": self.engine.db_backend,
                "copies_per_message_unit": "body copies (NOT bytes)",
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
            f"drain={f'{e.drain_seconds:.1f}s' if e.drain_seconds is not None else 'TIMEOUT'} "
            f"journal={e.journal_mode} synchronous={e.synchronous or 'n/a'} "
            f"backend={e.db_backend or '?'}"
        )
        # #207: the MEASURED txn/msg beside the analytical 3+2H+2N cost model. "not measured" when the
        # live committed_txns counter never moved (Postgres) or nothing was acked — never a bogus 0.
        measured = (
            f"{e.txn_per_message_measured:.2f}/msg"
            if e.txn_per_message_measured is not None
            else "not measured"
        )
        lines.append(f"txn/msg (measured): {measured} (committed_txns={e.committed_txns})")
        # #207 loose end 2: the SIZING proxy, beside the measured txn/msg. The label carries BOTH
        # caveats into the operator's terminal — the backend (SQLite dedups an identical fan-out to one
        # copy, SQL Server writes N, and the rig/production backend is SQL Server) and "NOT bytes"
        # (durable bytes need UTF-16 width, cipher expansion, and row/index/tx-log overhead this
        # counter cannot see, so no bytes/msg is published — ADR 0141). "not measured", never a bogus 0.
        copies = (
            f"{e.copies_per_message:.2f}/msg"
            if e.copies_per_message is not None
            else "not measured"
        )
        lines.append(
            f"copies/msg ({e.db_backend or '?'}; NOT bytes): {copies} (body_copies={e.body_copies})"
        )
        nl = self.no_loss
        lines.append(
            f"no-loss: {'OK' if nl.ok else 'LOSS'} — sent={nl.sent} engine_read={nl.engine_read} "
            f"engine_written={nl.engine_written} sink_received={nl.sink_received} "
            f"backlog={nl.backlog} at_least_once={nl.at_least_once_redeliveries}"
        )
        # `if not nl.ok` was right while every detail line meant a failure. The heavily-stranded
        # note now fires precisely on runs that PASS (BACKLOG #1866), so the verdict alone would
        # keep the one reader-facing signal about a poorly confirmed run out of the console and the
        # CI log. Widen to that ONE case and no further: testing `detail` against the all-clear
        # string instead would also print the benign per-run stranding note, which fires on
        # essentially every contended run, making an indented line under `no-loss: OK` the normal
        # shape — and any operator or script reading a detail line as a failure signal would then
        # false-positive on healthy runs.
        if not nl.ok or nl.heavily_stranded:
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
    # target). IT NO LONGER BOUNDS ANY VERDICT — it is the small-run floor under a stranding width
    # that `_reconcile` now only REPORTS (BACKLOG #1866), so changing `pool_size` or the target count
    # changes when a note prints and nothing else. It is NOT "~one stranded in-flight frame per
    # connection" either, a model retired because this sender's in-flight deque is unbounded.
    # Whatever this value is, `_reconcile` still requires that every message the engine replied to
    # has an ingress row, and still fails a run that offered messages and got no reply at all.
    no_loss = _reconcile(
        final_counters,
        poller,
        drain_seconds,
        tolerance=loss_tolerance,
        unconfirmed_budget=profile.pool_size * max(1, len(profile.targets)),
    )
    engine = _engine_summary(poller, drain_seconds, db_backend, final_counters.acked)
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

# The no-loss detail when nothing at all is worth saying. Named so THIS module states it once; the
# connscale and estate copies still spell the same literal out, and nothing pins the three equal, so
# do not read this constant as single-sourcing the string across the reconcile copies.
_NO_LOSS_ALL_CLEAR = "read>=sent, sink_received>=written, backlog drained"


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
        # of messages per phase and keep the gate.
        #
        # WHAT BACKS THIS SUPPRESSION IS NARROWER THAN IT USED TO BE, AND SAYING SO IS THE POINT.
        # This comment used to answer "then what catches a mass reset/timeout FLOOD below the floor?"
        # with "the reconcile fails zero_loss when timeouts exceed its stranding budget". That
        # sentence is no longer true of this copy (BACKLOG #1866 — `_reconcile` carries the reasoning
        # and the full list of what it gives up; it is not repeated here). The consequence for THIS
        # suppression is the part that belongs here: **a PARTIAL flood on a sub-floor phase is now
        # gated by nothing.** That is a real gap opened deliberately, in exchange for a gate that
        # does not red on host speed, and it is named rather than left implied.
        #
        # Mind the scope difference too: the reconcile is computed ONCE over the run's final
        # counters, so a flood confined to a sub-floor MEASURED phase inside a large multi-phase run
        # was already gated by neither. No shipped profile has such a phase today (reference's only
        # sub-floor phase is `warmup`, which is unmeasured). (max_nak_rate below deliberately has no
        # floor — a NAK is a deterministic engine verdict, not transport noise, so even one is signal.)
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
    # THE EXCUSAL IS NOW UNCONDITIONAL, AND A STRANDING COUNT NO LONGER FAILS A RUN. It used to be
    # cancelled wholesale past a budget of `max(unconfirmed_budget, 3 * sent // 4)`, on the ground
    # that an unbounded excusal degrades the intake bound to `read >= 0` and a total ACK-path
    # regression would pass as zero-loss. The ground was right; the instrument was a third fraction
    # of the OFFERED volume, and it shares the defect that ejected two pull requests from the merge
    # queue (see `ack_path_dead` below for the runs). Windows-2025 `merge_group` run 35657866239
    # reported 79 timeouts of 90 sent — 88 percent — against this budget of 67, so retiring only the
    # intake floor would have left that pull request ejected by the next detector along.
    #
    # It is not needed for its stated purpose. `sent == acked + nak + timeouts` (every send resolves
    # exactly once — pinned in tests/test_load_runner.py), so with the excusal unconditional and
    # clamped, `read_short` is exactly `acked + nak - read`: EVERY MESSAGE THE ENGINE REPLIED TO MUST
    # HAVE AN INGRESS ROW. That is never vacuous — it is exact — and it is an engine invariant rather
    # than a tuned number, because both reply paths commit first and build the reply second: an
    # accept-ACK follows `store.enqueue_ingress`, a NAK follows `store.record_received`
    # (`messagefoundry/pipeline/wiring_runner.py`). So it fails a confirmed-then-lost message at
    # magnitude ONE at any host speed, which no budget on `timeouts` ever did.
    #
    # `timeouts > sent` IS STILL VACUOUS HERE, AND THE CLAMP BELOW DOES NOT FIX IT — do not read it
    # as doing so. Clamped, `read_short` is `-read`; unclamped it is `sent - timeouts - read`; both
    # are <= 0 unconditionally, so the clamp only keeps the reported "confirmed sent" figure from
    # going negative. That state is a COUNTER BUG rather than an engine fault — a send resolves
    # exactly once — and what actually catches it is the identity `acked + timeouts == sent`
    # asserted in tests/test_load_runner.py, plus `ack_path_dead` below whenever the flood is total.
    #
    # The remaining half of the ground, a total ACK-path regression, is caught by `ack_path_dead`
    # below, on its signature. That is strictly better coverage: the budget could only ever catch a
    # dead ACK path while the connection-count arm did not dominate, and this file recorded that as a
    # known open gap ("once `unconfirmed_budget >= sent` the max() forgives even a 100%-dead ACK
    # path"). `tests/test_harness_reconcile.py` carries the control that closes it.
    #
    # The budget survives as REPORTING ONLY. A heavily stranded run is worth saying out loud — it is
    # a poorly confirmed measurement even when it lost nothing — so the width is still computed and
    # still named in the detail. It no longer decides `ok`.
    # `unconfirmed` is the CLAMPED count and is the only one used from here down — for the bound, for
    # the width test and for both notes. An earlier draft clamped it for the arithmetic and then
    # tested and printed `counters.timeouts` beside it, so in the `timeouts > sent` counter-bug state
    # the two notes reported different numbers of "unconfirmed sends" in one report.
    unconfirmed = min(counters.timeouts, sent)
    budget = max(unconfirmed_budget, 3 * sent // 4)
    heavily_stranded = unconfirmed > budget
    read_short = sent - unconfirmed - read
    # THE ANTI-VACUITY GUARD, AND IT IS A SIGNATURE RATHER THAN A FRACTION OF THE OFFERED VOLUME.
    # (BACKLOG #1866.)
    #
    # It was an intake floor, `read >= sent // 2`, and it is the detector that ejected PR 1233 from
    # the merge queue (windows-2025 `merge_group` run 35656074083: `engine_read 36 < intake floor
    # 45`, on a run whose every delivery arrived — fan-out 2 over 36 read, 72 received). Its sibling
    # in tests/test_load_runner.py, `acked >= sent // 4`, ejected PR 1283 twenty minutes later
    # (run 35657866239: 90 sent / 11 acked / 79 timeouts), and the stranding budget above was the
    # third of the same family.
    #
    # THE TRIGGER IS THE VARIABLE, AND THE MECHANISM BEHIND IT IS NOT ESTABLISHED. Both heads were
    # green on the same leg as a `pull_request` event. BACKLOG #1866 carries the run split and is
    # the one place it is recorded; it is a live count that decays, so it is not restated here.
    # What is known of the difference is only that the queue launches entries in BATCHES — hosted
    # runners are one VM per job, so a shared-runner story is NOT the explanation and must not be
    # written down as one. Nothing below depends on a mechanism: these are invariants that hold at
    # any host speed, which is the whole point of replacing thresholds that did not.
    #
    # READ THIS BEFORE TRUSTING A GREEN FROM THIS FUNCTION. `sample_until_reconciled`
    # (harness/load/enginepoll.py) stops polling on `read >= sent - timeouts` AND
    # `sink_received >= written` AND an empty pipeline — which is `read_ok` AND `deliver_ok` AND
    # `drained`, the same three arms rearranged. So ON A RUN WHOSE SAMPLER SETTLED, all three hold
    # by construction and `ok` is decided by `ack_path_dead` alone; the three only carry information
    # on a run that exhausted `drain_timeout_s` without settling.
    #
    # The coupling is not new — the sampler has always stopped on the reconcile's own condition, and
    # `read_short` has always been that condition. WHAT IS NEW is that the retired floor was the one
    # arm the sampler could NOT satisfy, so removing it left `ack_path_dead` as the only independent
    # bit. The worked case: an engine that ingests 1 of 90 sends, ACKs that 1 and strands 89 settles
    # immediately (1 >= 90 - 89), reads clean on every arm, and passes. That is the documented
    # give-up — 89 unconfirmed sends are not provable loss — but it is worth seeing stated as "the
    # gate went green on a run that moved one message" rather than inferred from three inequalities.
    #
    # The failing side IS armed, and it is measured rather than argued: sabotaging the ingress
    # commit for ONE of 90 accept-ACKed messages makes the poll exhaust its timeout and the run red
    # with `lost 1 on intake`. The cost is that such a run takes the full `drain_timeout_s` to fail.
    #
    # With `nak == 0` the floor reduces to `acked >= sent // 2`: how much of the OFFERED volume this
    # host confirmed, which is a throughput reading wearing a loss label. It added nothing to the
    # exact bound `read_short` already carries, and what it GESTURED at — a dead ACK path — it could
    # not catch, because that signature is a HIGH read with no ACKs, which clears a floor on `read`
    # by construction. This file recorded that as a known open gap. Close it on the signature
    # instead, which costs nothing in host-independence: an engine that demonstrably ingested
    # messages while the sender saw NOT ONE reply has a dead ACK path at any speed. A NAK counts as
    # a reply — it is itself proof the reply path runs — so the predicate is `acked + nak == 0`, not
    # `acked == 0`, and an engine rejecting every message is not reported as a dead one.
    #
    # It also has margin, which is the property `sent // 2` and `sent // 4` both lacked: teardown
    # weather never reaches zero replies, and the worst merge-group run on record still confirmed 11
    # of 90, whereas a dead ACK path lands on exactly zero whatever the host is doing.
    #
    # WHAT THIS NO LONGER CATCHES, stated rather than left to be discovered: an UNCONFIRMED send —
    # one counted at write-buffer time whose reply never arrived before the connection closed — that
    # never reached the engine at all. It is now excused at every magnitude, where the floor failed
    # the run once `read` fell under half of `sent`. Nothing here can tell such a send from one whose
    # frame never left the socket, so the old trip was a coin flip on host speed rather than a
    # detection. A PARTIAL reply-path regression (the engine replying to some messages it commits and
    # silently not to others) is the same shape and is given up with it. Both remain visible as a
    # heavily-stranded note, and the drain and rate SLOs are where a throughput verdict belongs.
    # No `read > 0` gate, and that omission is deliberate. Gating on it left a TOTAL BLACKOUT green:
    # a run that offered messages while the engine ingested nothing, replied to nothing and
    # delivered nothing satisfies `read_short` (everything is excused), `deliver_short` (0 - 0) and
    # `drained` (an empty pipeline), so `read > 0` was the only thing standing between "the engine
    # did absolutely nothing" and a clean zero-loss verdict — and it is false in exactly that case.
    # `sent > 0` alone is the honest guard: a run that offered nothing is not judged on its replies.
    #
    # NO SAMPLE FLOOR, WHICH IS A BEHAVIOUR CHANGE ON VERY SMALL RUNS — say it rather than discover
    # it. At `sent == 1` with the single reply stranded at teardown, the old code passed (the
    # connection-count budget covered it and `1 // 2 - 0 <= 0` cleared the floor) and this fails.
    # The margin argument for zero replies is a claim about a ~90-message run and does not carry to
    # a handful of sends. A floor is deliberately NOT added: it would be one more tuned number in a
    # function whose defect was tuned numbers, and every profile this copy serves offers two orders
    # of magnitude more than that. Revisit if a genuinely tiny load profile ever ships.
    ack_path_dead = sent > 0 and counters.acked + counters.nak == 0
    deliver_short = written - sink_received
    read_ok = read_short <= tolerance
    deliver_ok = deliver_short <= tolerance
    drained = backlog == 0
    ok = read_ok and deliver_ok and drained and not ack_path_dead
    parts: list[str] = []
    if not read_ok:
        parts.append(
            f"engine_read {read} < confirmed sent {sent - unconfirmed} (lost {read_short} on intake)"
        )
    if ack_path_dead:
        parts.append(
            f"{sent} sent and the sender saw no reply at all (acked 0, nak 0, engine_read {read}) "
            f"— a dead ACK path: no accept-ACK and no NAK came back; no stranding width and no "
            f"tolerance may excuse this"
        )
    if not deliver_ok:
        parts.append(
            f"sink_received {sink_received} < engine_written {written} (lost {deliver_short})"
        )
    if not drained:
        parts.append(f"backlog {backlog} not drained")
    if heavily_stranded:
        # A NOTE, not a verdict: this no longer decides `ok`. It says the run is poorly confirmed —
        # most of what it offered was never replied to — which makes it a weak MEASUREMENT even
        # when nothing it confirmed was lost.
        #
        # The "everything replied to was accounted for" clause is conditioned on `read_ok`, because
        # a flood can coexist with a real confirmed loss: printed unconditionally it contradicted
        # the shortfall clause in the same string, on the same line, for the same run.
        accounted = (
            "every message the engine replied to was accounted for"
            if read_ok
            else "and a confirmed message is missing besides — see the shortfall above"
        )
        parts.append(
            f"{counters.timeouts} unconfirmed sends exceed the stranding budget "
            f"({budget} = max(connections, three quarters of the run)) — a poorly confirmed run, "
            f"not a loss verdict; {accounted}"
        )
    elif unconfirmed > 0 and read < sent:
        # Honest reporting either way: the gap is attributed to unconfirmed sends, not silently absorbed.
        parts.append(
            f"{unconfirmed} unconfirmed send(s) (no ACK before connection close) "
            f"not observed at intake — not counted as loss"
        )
    detail = "; ".join(parts) if parts else _NO_LOSS_ALL_CLEAR
    return NoLoss(
        ok, sent, read, written, sink_received, backlog, at_least_once, detail, heavily_stranded
    )


def _engine_summary(
    poller: EnginePoller,
    drain_seconds: float | None,
    db_backend: str | None,
    message_count: int,
) -> EngineSummary:
    samples = poller.samples
    base, final = poller.baseline, poller.final
    peak_backlog = max((s.backlog for s in samples), default=0)
    peak_qd = max((s.queue_depth for s in samples), default=0)
    growth = (final.db_size_bytes - base.db_size_bytes) if base and final else 0
    dead = (final.out_dead - base.out_dead) if base and final else 0
    journal = final.journal_mode if final else None
    synchronous = final.synchronous if final else None
    # #207: self-difference the live committed_txns counter exactly as db_size/out_dead above. A 0
    # delta over acked traffic means the backend never wired the counter (Postgres reads a flat 0) —
    # so the per-message figure is None ("not measured"), never a fabricated 0/msg. `message_count`
    # is Counters.acked (the run's message count); guard against division by zero when nothing acked.
    committed_txns = (final.committed_txns - base.committed_txns) if base and final else 0
    txn_per_message_measured = (
        committed_txns / message_count if message_count > 0 and committed_txns > 0 else None
    )
    # #207 loose end 2: the same self-difference for the body-copy counter — the SIZING proxy. Same
    # "0 delta ⇒ not measured" rule (Postgres never wired it): a run that acked messages always wrote
    # at least 2 copies each, so a flat 0 is an unwired counter, never a zero-copy run. The figure is a
    # COPY COUNT, and backend-dependent — `db_backend` is rendered with it and no byte figure is
    # derived from it (ADR 0141).
    body_copies = (final.body_copies - base.body_copies) if base and final else 0
    copies_per_message = (
        body_copies / message_count if message_count > 0 and body_copies > 0 else None
    )
    return EngineSummary(
        db_backend,
        journal,
        synchronous,
        peak_backlog,
        peak_qd,
        growth,
        dead,
        drain_seconds,
        committed_txns,
        txn_per_message_measured,
        body_copies,
        copies_per_message,
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
