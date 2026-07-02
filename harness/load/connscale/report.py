# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""The connection-scale report — the 6 walls keyed by connection count (B11).

A curve-shaped report (vs the throughput-shaped :class:`~harness.load.report.RunReport`): one
:class:`ConnScaleRecord` per ``(sweep_mode, N)`` step, carrying the 6-wall section + a no-loss
reconcile, plus an SLO verdict. **Metrics + metadata only** — never message bodies or control-id lists
(PHI rule). Pure + deterministic, so it unit-tests without a live run.

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

# Exit codes (shared with the load CLI).
EXIT_OK = 0
EXIT_SLO_VIOLATION = 1

SCHEMA_VERSION = 1

_CSV_FORMULA_TRIGGERS = frozenset("=+-@\t\r\x00")


def _spreadsheet_safe(value: str) -> str:
    """Neutralize a leading formula trigger so a text cell can't execute when the CSV opens in
    Excel/Sheets (CSV formula injection, ASVS 1.2.10)."""
    return "'" + value if value[:1] in _CSV_FORMULA_TRIGGERS else value


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

    def to_json_dict(self) -> dict[str, object]:
        return {
            "sweep_mode": self.sweep_mode,
            "count": self.count,
            "offered_aggregate_rate": round(self.offered_aggregate_rate, 2),
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
            },
            "wall4_fd": {"count_peak": self.fd_count_peak},
            "wall5_reload": {"seconds": self.reload_seconds},
            "wall6_ack_ms": {
                "p50": round(self.ack_p50_ms, 3),
                "p95": round(self.ack_p95_ms, 3),
                "p99": round(self.ack_p99_ms, 3),
            },
        }


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

    def to_json_dict(self) -> dict[str, object]:
        return {
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

    def to_json(self) -> str:
        return json.dumps(self.to_json_dict(), indent=2)

    def to_csv(self) -> str:
        """One row per (sweep_mode, N) step — for spreadsheet curve plotting."""
        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow(
            [
                "profile",
                "sweep_mode",
                "count",
                "offered_rate",
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
                "reload_seconds",
                "ack_p99_ms",
            ]
        )
        for r in self.records:
            writer.writerow(
                [
                    _spreadsheet_safe(self.profile),
                    _spreadsheet_safe(r.sweep_mode),
                    r.count,
                    round(r.offered_aggregate_rate, 2),
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
            f"{'mode':<16}{'N':>6}{'rate':>8}{'sent':>9}{'inpipe':>8}{'exqd':>6}"
            f"{'poolp99':>9}{'idle':>6}{'empty/s':>9}{'wake/s':>8}{'idle/s':>8}{'fd':>8}{'reload':>8}{'ackp99':>9}"
        )
        lines.append(header)
        lines.append("-" * len(header))
        for r in self.records:
            lines.append(
                f"{r.sweep_mode:<16}{r.count:>6}{r.offered_aggregate_rate:>8.0f}{r.sent:>9}"
                f"{r.in_pipeline_peak:>8}{_na(r.executor_queue_depth_peak):>6}"
                f"{_na(r.pool_wait_p99_ms):>9}{_na(r.pool_idle_min):>6}"
                f"{r.empty_claims_per_s:>9.1f}{r.wake_fanout_per_s:>8.1f}{r.idle_poll_per_s:>8.1f}"
                f"{_na(r.fd_count_peak):>8}{_na(r.reload_seconds):>8}{r.ack_p99_ms:>9.1f}"
            )
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
