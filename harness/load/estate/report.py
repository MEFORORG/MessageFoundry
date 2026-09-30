# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The estate report — the achieved demo SHAPE keyed by connection count (#216).

Where the connscale report is a 6-wall curve, the estate report answers one question honestly: did the
harness drive the calibrated heterogeneous shape? Per ``count`` step it carries the realized
simple/hub CONNECTION split (topology, by count), the achieved total events/sec + per-connection
events/sec vs the spec target, a no-loss reconcile, ACK latency, and the CPU-**per-event** denominator
(so headroom is reported against the true in+out event volume, not messages). **Metrics + metadata
only** — never message bodies or control-id lists (PHI rule). Pure + deterministic, so it unit-tests
without a live run.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field

# Exit codes (shared with the load / connscale CLIs).
EXIT_OK = 0
EXIT_SLO_VIOLATION = 1

# 2 since BACKLOG #2011: records gained `rate_window`, `in_hold_samples` and `make_up_samples`, and
# every rate-derived value moved to the window `runner._throughput_rates` defines.
SCHEMA_VERSION = 2

#: Names the window an estate record's rates were computed over (BACKLOG #2011). The window, and what
#: moved when it changed, are defined once in `harness.load.estate.runner._throughput_rates`. No reader
#: in this tree consumes the field yet; it exists so a later one can tell the two populations apart,
#: and renaming the name or the value would hide that split from it. It is owned here, not imported
#: from the connscale report: the two harnesses mark their own windows.
RATE_WINDOW = "in_hold_excl_drain"


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
class EstateRecord:
    """One estate step at connection count ``count``: the achieved shape + no-loss + headroom."""

    count: int
    simple_count: int  # connections that are simple pass-through (topology, by count)
    hub_count: int  # connections that are fan-out hubs
    hub_fanout: int

    # --- calibration target vs achieved (EVENTS, not messages — the load-bearing readout) ---
    target_total_event_rate: float  # per_conn_event_rate × count
    target_per_conn_event_rate: float
    achieved_written_per_s: float  # engine delivery msg/s over the rate window (Δwritten / Δt)
    achieved_read_per_s: float  # engine intake msg/s over the rate window (Δread / Δt)
    achieved_total_event_rate: float  # read/s + written/s = in + out events/sec
    achieved_per_conn_event_rate: float  # achieved_total_event_rate / count

    # --- traffic / no-loss ---
    sent: int
    acked: int
    nak: int
    deferred: int
    timeouts: int
    no_loss: NoLoss
    in_pipeline_peak: int
    drain_seconds: float | None

    # --- ACK-on-receipt latency ---
    ack_p50_ms: float
    ack_p95_ms: float
    ack_p99_ms: float

    # --- the rate window: how many readings the achieved rates were read over, and how many of those
    # were make-up readings taken after the sampler stopped. Required, so a record can never carry the
    # RATE_WINDOW marker without the counts it was read from. ---
    in_hold_samples: int
    make_up_samples: int

    # --- headroom: CPU-per-event denominator (None where the OS probe couldn't read) ---
    cpu_seconds_total: float | None = None
    cpu_util_cores_mean: float | None = None
    cpu_us_per_event: float | None = None  # CPU-microseconds per pipeline event = headroom gauge
    working_set_peak_bytes: int | None = None
    fd_count_peak: int | None = None

    def to_json_dict(self) -> dict[str, object]:
        return {
            "count": self.count,
            "rate_window": RATE_WINDOW,
            "in_hold_samples": self.in_hold_samples,
            "make_up_samples": self.make_up_samples,
            "shape": {
                "simple_count": self.simple_count,
                "hub_count": self.hub_count,
                "hub_fanout": self.hub_fanout,
                "simple_fraction_realized": round(self.simple_count / self.count, 4)
                if self.count
                else 0.0,
            },
            "events": {
                "target_total_per_s": round(self.target_total_event_rate, 2),
                "target_per_conn_per_s": round(self.target_per_conn_event_rate, 4),
                "achieved_total_per_s": round(self.achieved_total_event_rate, 2),
                "achieved_per_conn_per_s": round(self.achieved_per_conn_event_rate, 4),
            },
            "achieved_messages": {
                "read_per_s": round(self.achieved_read_per_s, 2),
                "written_per_s": round(self.achieved_written_per_s, 2),
            },
            "cpu": {
                "seconds_total": _round_or_none(self.cpu_seconds_total, 3),
                "util_cores_mean": _round_or_none(self.cpu_util_cores_mean, 3),
                "us_per_event": _round_or_none(self.cpu_us_per_event, 3),
            },
            "working_set": {"peak_bytes": self.working_set_peak_bytes},
            "fd": {"count_peak": self.fd_count_peak},
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
            "ack_ms": {
                "p50": round(self.ack_p50_ms, 3),
                "p95": round(self.ack_p95_ms, 3),
                "p99": round(self.ack_p99_ms, 3),
            },
        }


@dataclass(frozen=True)
class EstateReport:
    profile: str
    engine_url: str
    db_backend: str | None
    records: list[EstateRecord]
    slos: list[SloCheck]
    result_ok: bool
    exit_code: int
    notes: list[str] = field(default_factory=list)

    def to_json_dict(self) -> dict[str, object]:
        return {
            "schema_version": SCHEMA_VERSION,
            "kind": "estate",
            "profile": self.profile,
            "engine_url": self.engine_url,
            "db_backend": self.db_backend,
            "result": "PASS" if self.result_ok else "FAIL",
            "exit_code": self.exit_code,
            "records": [r.to_json_dict() for r in self.records],
            "slo": [
                {"name": c.name, "threshold": c.threshold, "observed": c.observed, "ok": c.ok}
                for c in self.slos
            ],
            "notes": self.notes,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_json_dict(), indent=2)

    def render_console(self) -> str:
        lines: list[str] = []
        lines.append(
            f"Estate report -- profile {self.profile!r} against {self.engine_url} "
            f"(backend {self.db_backend or 'sqlite'})"
        )
        lines.append("")
        header = (
            f"{'N':>6}{'simple':>8}{'hub':>6}{'fan':>5}{'tgt_ev/s':>10}{'ach_ev/s':>10}"
            f"{'ev/conn':>9}{'sent':>9}{'inpipe':>7}{'noloss':>8}{'cpu_us/ev':>11}{'ackp99':>9}"
        )
        lines.append(header)
        lines.append("-" * len(header))
        for r in self.records:
            lines.append(
                f"{r.count:>6}{r.simple_count:>8}{r.hub_count:>6}{r.hub_fanout:>5}"
                f"{r.target_total_event_rate:>10.1f}{r.achieved_total_event_rate:>10.1f}"
                f"{r.achieved_per_conn_event_rate:>9.3f}{r.sent:>9}{r.in_pipeline_peak:>7}"
                f"{('ok' if r.no_loss.ok else 'FAIL'):>8}{_na(_round_or_none(r.cpu_us_per_event, 2)):>11}"
                f"{r.ack_p99_ms:>9.1f}"
            )
        lines.append(f"rates: rate_window={RATE_WINDOW} (the post-drain final is excluded)")
        for r in self.records:
            if r.in_hold_samples < 2:
                lines.append(
                    f"WARNING: N={r.count} rates were read over {r.in_hold_samples} reading(s); a "
                    "rate window needs two, so its achieved rates read 0.0, not a measured zero"
                )
            elif r.make_up_samples:
                lines.append(
                    f"note: N={r.count} rate window ends on {r.make_up_samples} make-up reading(s) "
                    "taken after the sampler stopped, so it may run past the hold"
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


def _na(value: object) -> object:
    return "n/a" if value is None else value


def _round_or_none(value: float | None, digits: int) -> float | None:
    return None if value is None else round(value, digits)
