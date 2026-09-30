# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Prometheus ``/metrics`` exporter (+ an optional, off-by-default OpenTelemetry seam).

The hard rules this module enforces (BACKLOG #21):

* **No PHI in the exposition.** The *only* label names that ever appear are ``connection``
  (the inbound connection name == ``channel_id``), ``destination`` (the outbound connection
  name), ``status`` (an :class:`OutboxStatus`/:class:`MessageStatus` enum *value*), ``version``
  (the build string) and the histogram ``le`` bucket boundary. These are all operator-assigned
  configuration identifiers and constants — never a message field value. We never read
  ``messages.raw`` / ``summary`` / ``control_id`` / ``message_type`` / any HL7 field here.
* **A scrape adds zero event-loop blocking.** Every store read is ``await``ed inside
  :func:`gather_snapshot` (the reads are already off-loop via the read pool). The collector and
  the renderer run *purely synchronously* over the in-memory :class:`_Snapshot` gathered *before*
  them — no DB I/O, no ``sleep``, no sync sqlite.

Counters here are process-lifetime (``since=engine.started_at``) and so reset on restart — the
correct Prometheus counter contract. ``queue_depth`` / ``in_pipeline`` / ``oldest_pending_age``
are gauges (current state).

**The engine renders the text exposition itself.** It used ``prometheus_client`` for that until
BACKLOG #2501; the renderer below reproduces that library's output byte for byte, and
``tests/test_metrics_exposition.py`` holds it to golden files the library wrote. The library is
a development dependency now, kept for that test and for its parser. The families here use a fixed
set of legacy-valid metric and label names, so the renderer carries none of the library's name
escaping; a test pins every name to the legacy character set.
"""

from __future__ import annotations

import math
import time
from collections import deque
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Literal

import psutil

from messagefoundry import __version__
from messagefoundry.pipeline.sync_reply import SyncReplyMetrics
from messagefoundry.store.pool_metrics import PoolStatus
from messagefoundry.store.store import (
    ClaimProcStatus,
    DestinationMetrics,
    InboundMetrics,
    LatencyHistogram,
)

if TYPE_CHECKING:  # avoid pulling the heavy engine import into the default path
    from messagefoundry.pipeline import Engine

__all__ = [
    "DEFAULT_LATENCY_BUCKETS",
    "METRICS_CONTENT_TYPE",
    "MetricsHistory",
    "MetricsSample",
    "OtelMetricsExporter",
    "build_otel_meter_provider",
    "gather_snapshot",
    "render_metrics",
]


# --- historical-metrics ring (BACKLOG #76, ADR 0065 amendment) --------------
# A tiny, in-memory, bounded ring of point-in-time samples for the console trend charts. It is the
# FIRST SLICE deliberately: a durable history table would flip store_schema (out of scope), so this
# holds only the last `capacity` samples in process memory (lost on restart — the correct posture for a
# cosmetic trend view). It is fed by the existing ~1s /ws/stats sampler (no new background task), and
# each sample is derived from the `outbox_by_status` dict that loop ALREADY fetches per tick, so the
# sampler adds ZERO extra store I/O. Metadata only — aggregate counts, never a message body / PHI.


@dataclass(frozen=True)
class MetricsSample:
    """One point-in-time metrics sample: epoch ``ts`` + the outbound-row count by status at that instant.

    Aggregate counts only (never a message field / body). ``outbox_by_status`` is copied at record time
    so a later mutation of the caller's dict can't rewrite history.
    """

    ts: float
    outbox_by_status: Mapping[str, int] = field(default_factory=dict)


class MetricsHistory:
    """A bounded, in-memory ring of :class:`MetricsSample` for the console trend charts (#76).

    ``record`` is the cheap append the /ws/stats sampler calls each tick; it DEDUPES on a minimum
    inter-sample interval so several open sockets (each running their own 1s loop) never double-append
    the same instant. Thread-affinity is the asyncio event loop — every writer (the /ws/stats loop) and
    the single reader (``GET /metrics/history``) run on it, so no lock is needed.
    """

    def __init__(self, *, capacity: int = 900, min_interval: float = 0.9) -> None:
        # capacity 900 × ~1s ≈ 15 min of trend at the /ws/stats cadence — bounded memory, no durability.
        self._samples: deque[MetricsSample] = deque(maxlen=max(1, capacity))
        self._capacity = max(1, capacity)
        self._min_interval = min_interval
        self._last_ts = 0.0

    @property
    def capacity(self) -> int:
        return self._capacity

    def record(self, ts: float, outbox_by_status: Mapping[str, int]) -> None:
        """Append a sample IF at least ``min_interval`` has elapsed since the last one (dedupe across
        concurrent sockets). Cheap: one dict copy + a deque append, no I/O."""
        if self._samples and (ts - self._last_ts) < self._min_interval:
            return
        self._last_ts = ts
        self._samples.append(MetricsSample(ts=ts, outbox_by_status=dict(outbox_by_status)))

    def samples(self) -> list[MetricsSample]:
        """The retained samples, oldest-first (a copy — the ring keeps mutating under the sampler)."""
        return list(self._samples)


# Cumulative delivery-latency bucket boundaries (seconds) — the Prometheus ``le`` ladder.
DEFAULT_LATENCY_BUCKETS: tuple[float, ...] = (
    0.05,
    0.1,
    0.25,
    0.5,
    1.0,
    2.5,
    5.0,
    10.0,
    30.0,
    60.0,
    120.0,
    300.0,
)
# The header prometheus_client 0.26.0 sent as CONTENT_TYPE_LATEST, kept byte-identical so a scraper
# sees no change. Text format 1.0.0 differs from 0.0.4 only in allowing UTF-8 metric and label names,
# and every name here is legacy ASCII, so the body is valid under either version.
METRICS_CONTENT_TYPE = "text/plain; version=1.0.0; charset=utf-8"
_RATE_WINDOW = 60.0  # seconds; window for connection_metrics' throughput aggregates

_MetricType = Literal["counter", "gauge", "histogram"]


@dataclass(frozen=True)
class _Sample:
    """One exposition line: the exposed sample name, its labels, and its value."""

    name: str
    labels: dict[str, str]
    value: float


class _Family:
    """One metric family: the HELP and TYPE header plus its samples, in the order added.

    ``name`` is the family name. For a counter it never ends ``_total``: that suffix is stripped here
    and put back on every exposed sample and on the HELP and TYPE lines, which is how the exposition
    names counters. A caller may pass the name with or without it.
    """

    __slots__ = ("_labelnames", "documentation", "name", "samples", "type")

    def __init__(
        self, name: str, documentation: str, typ: _MetricType, labels: Sequence[str] = ()
    ) -> None:
        if typ == "counter":
            name = name.removesuffix("_total")
        self.name = name
        self.documentation = documentation
        self.type: _MetricType = typ
        self._labelnames = tuple(labels)
        self.samples: list[_Sample] = []

    @property
    def exposed_name(self) -> str:
        """The name on the HELP and TYPE lines."""
        return f"{self.name}_total" if self.type == "counter" else self.name

    def _labels(self, values: Sequence[str]) -> dict[str, str]:
        return dict(zip(self._labelnames, values, strict=True))

    def add_metric(self, labels: Sequence[str], value: float) -> None:
        """Add one counter or gauge sample."""
        self.samples.append(_Sample(self.exposed_name, self._labels(labels), value))

    def add_histogram(
        self, labels: Sequence[str], buckets: Sequence[tuple[str, float]], sum_value: float
    ) -> None:
        """Add one histogram: a ``_bucket`` line per ``le`` boundary, then ``_count`` and ``_sum``.

        ``buckets`` are cumulative and end with ``+Inf``, whose value is also the count.
        """
        base = self._labels(labels)
        for boundary, count in buckets:
            self.samples.append(_Sample(f"{self.name}_bucket", {**base, "le": boundary}, count))
        self.samples.append(_Sample(f"{self.name}_count", dict(base), buckets[-1][1]))
        self.samples.append(_Sample(f"{self.name}_sum", dict(base), sum_value))


def _gauge(name: str, documentation: str, labels: Sequence[str] = ()) -> _Family:
    return _Family(name, documentation, "gauge", labels)


def _counter(name: str, documentation: str, labels: Sequence[str] = ()) -> _Family:
    return _Family(name, documentation, "counter", labels)


def _format_value(value: float) -> str:
    """A sample value as Go's ``strconv.FormatFloat(v, 'g', -1, 64)`` would write it.

    The same algorithm as ``prometheus_client.utils.floatToGoString``: Python's shortest ``repr``,
    except the special values and a positive number with more than six integer digits, which Go
    writes in exponent form.
    """
    d = float(value)
    if math.isnan(d):
        return "NaN"
    if math.isinf(d):
        return "+Inf" if d > 0 else "-Inf"
    s = repr(d)
    dot = s.find(".")
    if d > 0 and dot > 6:
        mantissa = f"{s[0]}.{s[1:dot]}{s[dot + 1 :]}".rstrip("0.")
        return f"{mantissa}e+{dot - 1:02d}"
    return s


def _escape_label_value(value: str) -> str:
    """Backslash, newline and double quote, escaped in that order, as the format requires."""
    return value.replace("\\", r"\\").replace("\n", r"\n").replace('"', r"\"")


def _escape_help(text: str) -> str:
    """Backslash and newline, escaped in that order. A HELP line leaves a double quote alone."""
    return text.replace("\\", r"\\").replace("\n", r"\n")


def _render_exposition(families: Iterable[_Family]) -> bytes:
    """The Prometheus text exposition of ``families``, UTF-8 encoded.

    Labels are written sorted by name, as prometheus_client wrote them, not in declaration order.
    """
    out: list[str] = []
    for family in families:
        name = family.exposed_name
        out.append(f"# HELP {name} {_escape_help(family.documentation)}\n")
        out.append(f"# TYPE {name} {family.type}\n")
        for sample in family.samples:
            labels = ""
            if sample.labels:
                pairs = ",".join(
                    f'{key}="{_escape_label_value(value)}"'
                    for key, value in sorted(sample.labels.items())
                )
                labels = f"{{{pairs}}}"
            out.append(f"{sample.name}{labels} {_format_value(sample.value)}\n")
    return "".join(out).encode("utf-8")


# Host resource gauges (BACKLOG #74). psutil reads are microsecond-scale OS-counter reads, so they run
# inline in gather_snapshot (off the pure-sync scrape path). cpu_percent(interval=None) is non-blocking
# and reports the busy fraction since the *previous* call; prime it once at import so the first scrape
# reports a real interval rather than 0. Values are host/process aggregates — never PHI, and carry no
# labels, so they leave the strict {connection,destination,status,version,le} label allowlist untouched.
_PROC = psutil.Process()
try:  # pragma: no cover - priming; the returned 0.0 first-call value is discarded  # noqa: SIM105
    psutil.cpu_percent(interval=None)
except psutil.Error:
    pass


@dataclass(frozen=True)
class _HostMetrics:
    cpu_percent: float | None
    mem_used_bytes: float | None
    mem_total_bytes: float | None
    process_rss_bytes: float | None


def _read_host_metrics() -> _HostMetrics:
    """Read host CPU%/memory + this process's RSS via psutil.

    Returns all-``None`` if psutil cannot read the counters (e.g. a locked-down container that blocks
    ``/proc`` or the perf counters) so a scrape never fails on the host-metrics addition.
    """
    try:
        vm = psutil.virtual_memory()
        return _HostMetrics(
            cpu_percent=psutil.cpu_percent(interval=None),
            mem_used_bytes=float(vm.total - vm.available),
            mem_total_bytes=float(vm.total),
            process_rss_bytes=float(_PROC.memory_info().rss),
        )
    except psutil.Error:  # pragma: no cover - only in a sandbox that blocks counters
        return _HostMetrics(None, None, None, None)


@dataclass(frozen=True)
class _Snapshot:
    """An in-memory, point-in-time view of everything the exposition needs.

    Built by :func:`gather_snapshot` (the only place store reads happen) so that
    :meth:`_MetricsCollector.collect` is a pure, synchronous transform with no I/O.
    """

    version: str
    inbound: dict[str, InboundMetrics]  # by channel_id (inbound connection name)
    destinations: dict[tuple[str, str], DestinationMetrics]  # by (channel_id, destination_name)
    latency: Sequence[LatencyHistogram]
    outbox_by_status: dict[str, int]  # OutboxStatus value -> count
    in_pipeline: int  # not-done rows across every stage
    now: float
    # Host resource gauges (BACKLOG #74); None when psutil cannot read the counters.
    host_cpu_percent: float | None = None
    host_mem_used_bytes: float | None = None
    host_mem_total_bytes: float | None = None
    process_rss_bytes: float | None = None
    # DB throughput signals (BACKLOG #93). The server-store connection-pool snapshot (None on SQLite —
    # no pool), plus the always-on A1 cost counters (physical commits + body copies) that /stats already
    # exposes, surfaced here as Prometheus counters. All label-less (host/store aggregates), so the
    # strict {connection,destination,status,version,le} label allowlist is untouched.
    pool: PoolStatus | None = None
    committed_txns: int = 0
    body_copies: int = 0
    fenced_writes: int = 0
    # ADR 0114 AC-7's degraded gauge. None when the backend has no fifo_claim_proc lever or the flag
    # is off — the gauges are then ABSENT rather than 0, so a scrape can tell "not requested" from
    # "requested and degraded" (a constant 0 on every SQLite fleet would be pure alert noise).
    claim_proc: ClaimProcStatus | None = None
    # ADR 0154 D8: per-inbound synchronous-reply counters, read from the runner rather than the
    # store — they are process-lifetime in-memory counts, not persisted aggregates. Empty on every
    # instance with no reply_from inbound, so those scrapes are byte-identical.
    sync_replies: dict[str, SyncReplyMetrics] = field(default_factory=dict)


async def gather_snapshot(engine: Engine) -> _Snapshot:
    """Read every aggregate the exposition needs, off the event loop, into a frozen snapshot.

    All ``await``s — and therefore all store I/O — live here; nothing downstream blocks.
    """
    now = time.time()
    # Engine.registry_runner is a public property; the counters live with the runner that owns the
    # resolvers because api/metrics.py otherwise builds every family from engine.store alone.
    runner = engine.registry_runner
    sync_replies = runner.sync_reply_metrics() if runner is not None else {}
    cm = await engine.store.connection_metrics(
        since=engine.started_at or now, now=now, rate_window=_RATE_WINDOW
    )
    latency = await engine.store.delivery_latency_histogram(
        buckets=DEFAULT_LATENCY_BUCKETS, now=now
    )
    outbox = await engine.store.stats()
    in_pipeline = await engine.store.in_pipeline_depth()
    host = _read_host_metrics()
    # DB throughput signals (#93): the connection-pool snapshot (sync, cached counters — no DB I/O; None
    # on SQLite) + the always-on A1 physical-commit / body-copy counters (getattr-with-default so a
    # backend without them reports 0 rather than raising a scrape).
    pool = engine.store.pool_status()
    committed_txns = int(getattr(engine.store, "committed_txns", 0))
    body_copies = int(getattr(engine.store, "body_copies", 0))
    fenced_writes = int(getattr(engine.store, "fenced_writes", 0))
    return _Snapshot(
        sync_replies=sync_replies,
        version=__version__,
        inbound=cm.inbound,
        destinations=cm.destinations,
        latency=latency,
        outbox_by_status=outbox,
        in_pipeline=in_pipeline,
        now=now,
        host_cpu_percent=host.cpu_percent,
        host_mem_used_bytes=host.mem_used_bytes,
        host_mem_total_bytes=host.mem_total_bytes,
        process_rss_bytes=host.process_rss_bytes,
        pool=pool,
        committed_txns=committed_txns,
        body_copies=body_copies,
        fenced_writes=fenced_writes,
        claim_proc=engine.store.claim_proc_status(),
    )


class _MetricsCollector:
    """Turns one :class:`_Snapshot` into the metric families :func:`_render_exposition` writes.

    :meth:`collect` is **pure-sync** — it only reads ``self._s``; it does no ``await``, no DB
    access, and no other I/O. That keeps a scrape off the event loop and side-effect free. The
    family ORDER it yields is the order on the wire, so a reorder changes the scrape bytes.
    """

    def __init__(self, snap: _Snapshot) -> None:
        self._s = snap

    def collect(self) -> Iterable[_Family]:
        s = self._s

        build = _gauge(
            "messagefoundry_build_info",
            "Build metadata; constant 1, version carried as a label.",
            labels=["version"],
        )
        build.add_metric([s.version], 1.0)
        yield build

        # --- host resource gauges (BACKLOG #74) ------------------------------
        # Host/process aggregates, no PHI, no labels — absent when psutil couldn't read the counters.
        if s.host_cpu_percent is not None:
            cpu = _gauge(
                "messagefoundry_host_cpu_percent",
                "Host-wide CPU utilization percent (0-100) since the previous scrape.",
            )
            cpu.add_metric([], s.host_cpu_percent)
            yield cpu
        if s.host_mem_used_bytes is not None and s.host_mem_total_bytes is not None:
            mem_used = _gauge(
                "messagefoundry_host_memory_used_bytes",
                "Host physical memory in use (total - available), bytes.",
            )
            mem_used.add_metric([], s.host_mem_used_bytes)
            yield mem_used
            mem_total = _gauge(
                "messagefoundry_host_memory_total_bytes",
                "Host total physical memory, bytes.",
            )
            mem_total.add_metric([], s.host_mem_total_bytes)
            yield mem_total
        if s.process_rss_bytes is not None:
            rss = _gauge(
                "messagefoundry_process_resident_memory_bytes",
                "Resident set size (RSS) of the engine process, bytes.",
            )
            rss.add_metric([], s.process_rss_bytes)
            yield rss

        # --- inbound counters (per connection) -------------------------------
        # Counter family names omit the _total suffix; _Family appends it to every exposed sample.
        received = _counter(
            "messagefoundry_messages_received",
            "Messages received on an inbound connection (process lifetime).",
            labels=["connection"],
        )
        errored = _counter(
            "messagefoundry_messages_errored",
            "Messages that failed intake/validation on an inbound connection (process lifetime).",
            labels=["connection"],
        )
        for channel_id, im in s.inbound.items():
            received.add_metric([channel_id], float(im.read))
            errored.add_metric([channel_id], float(im.errored))
        yield received

        # ADR 0154 D8 — the synchronous-reply SLO series. Labelled `status`, NOT `outcome`: the label
        # allowlist above is a PHI contract, and the outcome enum is a fixed non-PHI constant set, so
        # it rides an existing label rather than widening a deliberately closed one.
        # rate(timeout)/rate(total) IS the proxy API's error budget, which is why `degraded` is a
        # distinct label value rather than folded into timeout.
        if s.sync_replies:
            replies = _counter(
                "messagefoundry_http_sync_replies_total",
                "Synchronous captured-downstream replies resolved, by outcome (process lifetime).",
                labels=["connection", "status"],
            )
            wait = _gauge(
                "messagefoundry_http_sync_reply_wait_seconds",
                "Mean time an HTTP turn blocked on a captured downstream reply (process lifetime). "
                "Answers 'is this approaching reply_timeout?' before the pager does.",
                labels=["connection"],
            )
            waiters = _gauge(
                "messagefoundry_http_sync_reply_waiters",
                "HTTP turns currently blocked on a captured downstream reply.",
                labels=["connection"],
            )
            for connection, m in sorted(s.sync_replies.items()):
                for status, count in sorted(m.totals.items()):
                    replies.add_metric([connection, status], float(count))
                wait.add_metric([connection], m.mean_wait_seconds)
                waiters.add_metric([connection], float(m.live))
            yield replies
            yield wait
            yield waiters
        yield errored

        # --- outbound counters + gauges (per connection/destination) ---------
        deliveries = _counter(
            "messagefoundry_deliveries",
            "Messages delivered to an outbound connection (process lifetime).",
            labels=["connection", "destination"],
        )
        deliveries_dead = _counter(
            "messagefoundry_deliveries_dead",
            "Outbound deliveries that dead-lettered (process lifetime).",
            labels=["connection", "destination"],
        )
        queue_depth = _gauge(
            "messagefoundry_queue_depth",
            "Current pending + inflight outbound rows for a destination.",
            labels=["connection", "destination"],
        )
        oldest_pending_age = _gauge(
            "messagefoundry_oldest_pending_age_seconds",
            "Age (seconds) of the oldest queued outbound row for a destination.",
            labels=["connection", "destination"],
        )
        for (channel_id, destination), dm in s.destinations.items():
            deliveries.add_metric([channel_id, destination], float(dm.written))
            deliveries_dead.add_metric([channel_id, destination], float(dm.dead))
            queue_depth.add_metric([channel_id, destination], float(dm.queue_depth))
            if dm.oldest_pending_at is not None:
                oldest_pending_age.add_metric(
                    [channel_id, destination], s.now - dm.oldest_pending_at
                )
        yield deliveries
        yield deliveries_dead
        yield queue_depth
        yield oldest_pending_age

        # --- outbox status + whole-pipeline depth gauges ---------------------
        outbox_status = _gauge(
            "messagefoundry_outbox_status",
            "Current count of outbound rows by status.",
            labels=["status"],
        )
        for status, count in s.outbox_by_status.items():
            outbox_status.add_metric([status], float(count))
        yield outbox_status

        in_pipeline = _gauge(
            "messagefoundry_in_pipeline",
            "Current not-done rows across every stage (ingress + routed + outbound).",
        )
        in_pipeline.add_metric([], float(s.in_pipeline))
        yield in_pipeline

        # --- DB throughput signals (BACKLOG #93) -----------------------------
        # Always-on A1 cost counters: physical commits + raw/payload body copies (process lifetime).
        # These are the store's write/commit-throughput signal (the DB work per message) — label-less.
        committed = _counter(
            "messagefoundry_store_committed_txns",
            "Physical store transactions committed (process lifetime).",
        )
        committed.add_metric([], float(s.committed_txns))
        yield committed
        body_copies = _counter(
            "messagefoundry_store_body_copies",
            "Raw/payload body strings durably written to the store (process lifetime).",
        )
        body_copies.add_metric([], float(s.body_copies))
        yield body_copies
        # ADR 0157 C3 split-brain signal. A counter rather than a gauge because it only ever grows;
        # alert on rate(...) > 0, not on an absolute value.
        fenced = _counter(
            "messagefoundry_store_fenced_writes",
            "Terminal queue resolves rejected by the leader-epoch fence (process lifetime).",
        )
        fenced.add_metric([], float(s.fenced_writes))
        yield fenced

        # ADR 0114 AC-7 degraded gauge. Emitted ONLY when [store].fifo_claim_proc is on: a constant
        # 0 on every fleet that never asked for the lever is noise a scraper cannot alert on, and
        # absence is the honest encoding of "not applicable here". Numeric and LABEL-LESS by
        # design — the human-readable degrade reason is free text (it embeds a proc name and, on the
        # probe-failure arm, an exception string), so carrying it as a label would both blow the
        # cardinality budget and break this module's strict {connection,destination,status,version,le}
        # allowlist. The reason string lives on /status and the console store panel instead.
        cp = s.claim_proc
        if cp is not None:
            effective = _gauge(
                "messagefoundry_store_claim_proc_effective",
                "1 when the ADR 0114 stored-procedure claim path passed its startup gate and is"
                " active, 0 when it degraded to the shipped ad-hoc batch (claims still flow).",
            )
            effective.add_metric([], 1.0 if cp.effective else 0.0)
            yield effective
            # Which stored head form the deployed modules matched. "verbatim" means this server did
            # NOT rewrite the CREATE OR ALTER head — no engine measured to date does, so a fleet
            # reporting 1 here is a live counterexample worth knowing about, not a fault.
            verbatim = _gauge(
                "messagefoundry_store_claim_proc_head_verbatim",
                "1 when at least one deployed claim procedure's stored definition kept the CREATE"
                " OR ALTER head verbatim (this server does not rewrite it), else 0.",
            )
            verbatim.add_metric([], 1.0 if "verbatim" in cp.head_forms.values() else 0.0)
            yield verbatim

        # Connection-pool saturation + acquire-wait (server backends only; absent on SQLite, which has
        # no pool). [store].pool_size previously emitted NO saturation metric — these close that gap.
        pool = s.pool
        if pool is not None:
            pool_max = _gauge(
                "messagefoundry_store_pool_max_connections",
                "Configured maximum size of the store connection pool.",
            )
            pool_max.add_metric([], float(pool.max_size))
            yield pool_max
            pool_size = _gauge(
                "messagefoundry_store_pool_open_connections",
                "Connections currently open in the store pool.",
            )
            pool_size.add_metric([], float(pool.size))
            yield pool_size
            pool_idle = _gauge(
                "messagefoundry_store_pool_idle_connections",
                "Currently-free (idle) connections in the store pool.",
            )
            pool_idle.add_metric([], float(pool.idle))
            yield pool_idle
            # The explicit SATURATION signal: 1 when the pool has zero idle connections (every stage
            # worker waiting on it contends), 0 otherwise.
            pool_saturated = _gauge(
                "messagefoundry_store_pool_saturated",
                "1 when the store pool has zero idle connections (saturated), else 0.",
            )
            pool_saturated.add_metric([], 1.0 if pool.idle == 0 else 0.0)
            yield pool_saturated
            # Acquire-wait percentiles (seconds — Prometheus base unit) + the sampled count. The time a
            # worker waits for a pooled connection grows monotonically with contention once saturated.
            aw = pool.acquire_wait
            for name, value_ms in (
                ("p50", aw.p50_ms),
                ("p95", aw.p95_ms),
                ("p99", aw.p99_ms),
                ("max", aw.max_ms),
            ):
                g = _gauge(
                    f"messagefoundry_store_pool_acquire_wait_{name}_seconds",
                    f"Store pool acquire() wait {name} (seconds) since process start.",
                )
                g.add_metric([], value_ms / 1000.0)
                yield g
            waits = _counter(
                "messagefoundry_store_pool_acquire_waits",
                "Store pool acquire() waits sampled (process lifetime).",
            )
            waits.add_metric([], float(aw.count))
            yield waits

        # --- delivery-latency histogram (per connection/destination) ---------
        latency = _Family(
            "messagefoundry_delivery_latency_seconds",
            "Delivery latency (updated_at - created_at) over done outbound rows.",
            "histogram",
            labels=["connection", "destination"],
        )
        for h in s.latency:
            buckets: list[tuple[str, float]] = [
                (str(boundary), float(cum))
                for boundary, cum in zip(DEFAULT_LATENCY_BUCKETS, h.bucket_counts)  # noqa: B905
            ]
            buckets.append(("+Inf", float(h.count)))
            latency.add_histogram(
                [h.channel_id, h.destination_name],
                buckets=buckets,
                sum_value=h.sum_seconds,
            )
        yield latency


def _render_snapshot(snap: _Snapshot) -> bytes:
    """The text exposition of one snapshot. Pure and synchronous: no I/O."""
    return _render_exposition(_MetricsCollector(snap).collect())


async def render_metrics(engine: Engine) -> bytes:
    """Gather a snapshot (off-loop) then render the Prometheus text exposition (pure sync)."""
    return _render_snapshot(await gather_snapshot(engine))


# --- optional OpenTelemetry seam (off by default) ---------------------------
# Everything below is a SEAM only: it is never auto-wired into ``serve`` / the ASGI lifespan.
# The ``opentelemetry`` imports are FUNCTION-LOCAL and guarded so the default Prometheus path
# never needs the SDK installed (mypy ignores the module via the pyproject override).


def build_otel_meter_provider(*, endpoint: str | None = None) -> Any:
    """Build an OpenTelemetry ``MeterProvider`` with an OTLP exporter.

    Lazily imports the OTel SDK; raises a clear :class:`RuntimeError` telling the operator to
    install the optional extra if it is missing. Returns the provider so the caller owns its
    lifecycle (this module never registers it globally or wires it into ``serve``).
    """
    try:
        from opentelemetry.exporter.otlp.proto.grpc.metric_exporter import (
            OTLPMetricExporter,
        )
        from opentelemetry.sdk.metrics import MeterProvider
        from opentelemetry.sdk.metrics.export import PeriodicExportingMetricReader
    except ImportError as exc:  # pragma: no cover - exercised only without the extra
        raise RuntimeError(
            "OpenTelemetry export requires the optional extra: pip install messagefoundry[otel]"
        ) from exc

    exporter = OTLPMetricExporter(endpoint=endpoint) if endpoint else OTLPMetricExporter()
    reader = PeriodicExportingMetricReader(exporter)
    return MeterProvider(metric_readers=[reader])


class OtelMetricsExporter:
    """A small, off-by-default OpenTelemetry bridge over the same snapshot.

    Like the Prometheus path, it records *only* aggregate counts/latency keyed by connection
    name + status — never a message field. Instruments are observable/sync and read solely from
    the latest snapshot, so they honor the same PHI and no-blocking rules.
    """

    def __init__(self, engine: Engine, *, endpoint: str | None = None) -> None:
        try:
            from opentelemetry.metrics import Observation
        except ImportError as exc:  # pragma: no cover - exercised only without the extra
            raise RuntimeError(
                "OpenTelemetry export requires the optional extra: pip install messagefoundry[otel]"
            ) from exc

        self._engine = engine
        self._provider = build_otel_meter_provider(endpoint=endpoint)
        self._snapshot: _Snapshot | None = None
        self._Observation = Observation

        meter = self._provider.get_meter("messagefoundry")
        meter.create_observable_gauge(
            "messagefoundry_in_pipeline",
            callbacks=[self._observe_in_pipeline],
            description="Current not-done rows across every stage.",
        )
        meter.create_observable_gauge(
            "messagefoundry_queue_depth",
            callbacks=[self._observe_queue_depth],
            description="Current pending + inflight outbound rows per destination.",
        )

    async def refresh(self) -> None:
        """Pull a fresh snapshot (off-loop) so the next observable callback reads current data."""
        self._snapshot = await gather_snapshot(self._engine)

    async def aclose(self) -> None:
        """Shut the meter provider down, flushing any pending export."""
        shutdown = getattr(self._provider, "shutdown", None)
        if shutdown is not None:
            shutdown()

    # Observable callbacks are pure-sync over the cached snapshot (no I/O, no PHI).
    def _observe_in_pipeline(self, _options: Any) -> Iterable[Any]:
        s = self._snapshot
        if s is None:
            return []
        return [self._Observation(s.in_pipeline)]

    def _observe_queue_depth(self, _options: Any) -> Iterable[Any]:
        s = self._snapshot
        if s is None:
            return []
        return [
            self._Observation(
                dm.queue_depth,
                {"connection": channel_id, "destination": destination},
            )
            for (channel_id, destination), dm in s.destinations.items()
        ]
