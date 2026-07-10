# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Prometheus ``/metrics`` exporter (+ an optional, off-by-default OpenTelemetry seam).

The hard rules this module enforces (BACKLOG #21):

* **No PHI in the exposition.** The *only* label names that ever appear are ``connection``
  (the inbound connection name == ``channel_id``), ``destination`` (the outbound connection
  name), ``status`` (an :class:`OutboxStatus`/:class:`MessageStatus` enum *value*), ``version``
  (the build string) and the histogram ``le`` bucket boundary. These are all operator-assigned
  configuration identifiers and constants — never a message field value. We never read
  ``messages.raw`` / ``summary`` / ``control_id`` / ``message_type`` / any HL7 field here.
* **A scrape adds zero event-loop blocking.** Every store read is ``await``ed inside
  :func:`gather_snapshot` (the reads are already off-loop via the read pool). The
  ``prometheus_client`` ``collect()`` runs *purely synchronously* over the in-memory
  :class:`_Snapshot` gathered *before* it — no DB I/O, no ``sleep``, no sync sqlite.

Counters here are process-lifetime (``since=engine.started_at``) and so reset on restart — the
correct Prometheus counter contract. ``queue_depth`` / ``in_pipeline`` / ``oldest_pending_age``
are gauges (current state).
"""

from __future__ import annotations

import time
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

import psutil
from prometheus_client import CONTENT_TYPE_LATEST, CollectorRegistry, generate_latest
from prometheus_client.core import (
    CounterMetricFamily,
    GaugeMetricFamily,
    HistogramMetricFamily,
)

from messagefoundry import __version__
from messagefoundry.store.store import DestinationMetrics, InboundMetrics, LatencyHistogram

if TYPE_CHECKING:  # avoid pulling the heavy engine import into the default path
    from messagefoundry.pipeline import Engine

__all__ = [
    "DEFAULT_LATENCY_BUCKETS",
    "METRICS_CONTENT_TYPE",
    "OtelMetricsExporter",
    "build_otel_meter_provider",
    "gather_snapshot",
    "render_metrics",
]

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
METRICS_CONTENT_TYPE = CONTENT_TYPE_LATEST
_RATE_WINDOW = 60.0  # seconds; window for connection_metrics' throughput aggregates

# Host resource gauges (BACKLOG #74). psutil reads are microsecond-scale OS-counter reads, so they run
# inline in gather_snapshot (off the pure-sync scrape path). cpu_percent(interval=None) is non-blocking
# and reports the busy fraction since the *previous* call; prime it once at import so the first scrape
# reports a real interval rather than 0. Values are host/process aggregates — never PHI, and carry no
# labels, so they leave the strict {connection,destination,status,version,le} label allowlist untouched.
_PROC = psutil.Process()
try:  # pragma: no cover - priming; the returned 0.0 first-call value is discarded
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


async def gather_snapshot(engine: Engine) -> _Snapshot:
    """Read every aggregate the exposition needs, off the event loop, into a frozen snapshot.

    All ``await``s — and therefore all store I/O — live here; nothing downstream blocks.
    """
    now = time.time()
    cm = await engine.store.connection_metrics(
        since=engine.started_at or now, now=now, rate_window=_RATE_WINDOW
    )
    latency = await engine.store.delivery_latency_histogram(
        buckets=DEFAULT_LATENCY_BUCKETS, now=now
    )
    outbox = await engine.store.stats()
    in_pipeline = await engine.store.in_pipeline_depth()
    host = _read_host_metrics()
    return _Snapshot(
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
    )


class _MetricsCollector:
    """A ``prometheus_client`` custom collector that renders one :class:`_Snapshot`.

    :meth:`collect` is **pure-sync** — it only reads ``self._s``; it does no ``await``, no DB
    access, and no other I/O. That keeps a scrape off the event loop and side-effect free.
    """

    def __init__(self, snap: _Snapshot) -> None:
        self._s = snap

    def collect(self) -> Iterable[Any]:
        s = self._s

        build = GaugeMetricFamily(
            "messagefoundry_build_info",
            "Build metadata; constant 1, version carried as a label.",
            labels=["version"],
        )
        build.add_metric([s.version], 1.0)
        yield build

        # --- host resource gauges (BACKLOG #74) ------------------------------
        # Host/process aggregates, no PHI, no labels — absent when psutil couldn't read the counters.
        if s.host_cpu_percent is not None:
            cpu = GaugeMetricFamily(
                "messagefoundry_host_cpu_percent",
                "Host-wide CPU utilization percent (0-100) since the previous scrape.",
            )
            cpu.add_metric([], s.host_cpu_percent)
            yield cpu
        if s.host_mem_used_bytes is not None and s.host_mem_total_bytes is not None:
            mem_used = GaugeMetricFamily(
                "messagefoundry_host_memory_used_bytes",
                "Host physical memory in use (total - available), bytes.",
            )
            mem_used.add_metric([], s.host_mem_used_bytes)
            yield mem_used
            mem_total = GaugeMetricFamily(
                "messagefoundry_host_memory_total_bytes",
                "Host total physical memory, bytes.",
            )
            mem_total.add_metric([], s.host_mem_total_bytes)
            yield mem_total
        if s.process_rss_bytes is not None:
            rss = GaugeMetricFamily(
                "messagefoundry_process_resident_memory_bytes",
                "Resident set size (RSS) of the engine process, bytes.",
            )
            rss.add_metric([], s.process_rss_bytes)
            yield rss

        # --- inbound counters (per connection) -------------------------------
        # CounterMetricFamily names omit the _total suffix; prometheus appends it on render.
        received = CounterMetricFamily(
            "messagefoundry_messages_received",
            "Messages received on an inbound connection (process lifetime).",
            labels=["connection"],
        )
        errored = CounterMetricFamily(
            "messagefoundry_messages_errored",
            "Messages that failed intake/validation on an inbound connection (process lifetime).",
            labels=["connection"],
        )
        for channel_id, im in s.inbound.items():
            received.add_metric([channel_id], float(im.read))
            errored.add_metric([channel_id], float(im.errored))
        yield received
        yield errored

        # --- outbound counters + gauges (per connection/destination) ---------
        deliveries = CounterMetricFamily(
            "messagefoundry_deliveries",
            "Messages delivered to an outbound connection (process lifetime).",
            labels=["connection", "destination"],
        )
        deliveries_dead = CounterMetricFamily(
            "messagefoundry_deliveries_dead",
            "Outbound deliveries that dead-lettered (process lifetime).",
            labels=["connection", "destination"],
        )
        queue_depth = GaugeMetricFamily(
            "messagefoundry_queue_depth",
            "Current pending + inflight outbound rows for a destination.",
            labels=["connection", "destination"],
        )
        oldest_pending_age = GaugeMetricFamily(
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
        outbox_status = GaugeMetricFamily(
            "messagefoundry_outbox_status",
            "Current count of outbound rows by status.",
            labels=["status"],
        )
        for status, count in s.outbox_by_status.items():
            outbox_status.add_metric([status], float(count))
        yield outbox_status

        in_pipeline = GaugeMetricFamily(
            "messagefoundry_in_pipeline",
            "Current not-done rows across every stage (ingress + routed + outbound).",
        )
        in_pipeline.add_metric([], float(s.in_pipeline))
        yield in_pipeline

        # --- delivery-latency histogram (per connection/destination) ---------
        latency = HistogramMetricFamily(
            "messagefoundry_delivery_latency_seconds",
            "Delivery latency (updated_at - created_at) over done outbound rows.",
            labels=["connection", "destination"],
        )
        for h in s.latency:
            buckets: list[tuple[str, float]] = [
                (str(boundary), float(cum))
                for boundary, cum in zip(DEFAULT_LATENCY_BUCKETS, h.bucket_counts)
            ]
            buckets.append(("+Inf", float(h.count)))
            latency.add_metric(
                [h.channel_id, h.destination_name],
                buckets=buckets,
                sum_value=h.sum_seconds,
            )
        yield latency


async def render_metrics(engine: Engine) -> bytes:
    """Gather a snapshot (off-loop) then render the Prometheus text exposition (pure sync)."""
    snap = await gather_snapshot(engine)
    registry = CollectorRegistry()
    registry.register(_MetricsCollector(snap))
    return generate_latest(registry)


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
