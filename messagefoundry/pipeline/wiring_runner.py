# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Run a code-first wiring :class:`~messagefoundry.config.wiring.Registry` as a **staged pipeline**.

Staged pipeline (ADR 0001, Step A): for each **inbound connection** a listener decodes/parses/
(strict-)validates each message **synchronously** (still NAKing those failures), then commits the
raw to the **ingress** stage and ACKs (**ACK-on-receipt**). A per-inbound **ingress worker** then
runs the **Router** (returns handler names) + named **Handlers** (filter → transform → ``Send``,
combined — not split) and **hands off** the resulting deliveries to the **outbound** stage in one
transaction. One delivery worker per **outbound connection** drains its rows (across all inbounds)
independently, with retries. Router/Handlers are pure; a re-run after a crash re-derives the same
output (at-least-once).

Every received message is persisted before the ACK (``RECEIVED``); its disposition is then recorded
as it flows (the count-and-log invariant): ``ROUTED`` (≥1 delivery → ``PROCESSED`` once drained),
``UNROUTED`` (router routed nowhere), ``FILTERED`` (handlers dropped it), or ``ERROR``/dead-letter at
the failing stage. Decode/parse/validate failures still NAK + record ``ERROR`` synchronously;
routing/transform failures are post-ACK (no NAK — a logged ``ERROR``/dead-letter + alert).

Reuses the store, the connector registry, and the ACK builder.
"""

from __future__ import annotations

import asyncio
import functools
import json
import logging
import time
import urllib.parse
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from messagefoundry.config.models import (
    AckAfter,
    AckMode,
    BuildupThreshold,
    ConnectorType,
    ContentType,
    Destination,
    InternalErrorPolicy,
    OrderingMode,
    OutboundSigning,
    RetryPolicy,
    Source,
)
from messagefoundry.config.db_lookup import DbLookupError, activated as db_lookup_activated
from messagefoundry.config.run_context import RunContext, run_contexts
from messagefoundry.config.settings import EgressSettings
from messagefoundry.config.wiring import (
    InboundConnection,
    OutboundConnection,
    Registry,
    WiringError,
    resolve_env_settings,
)
from messagefoundry.parsing import HL7PeekError, Peek, RawMessage, normalize, summarize, validate
from messagefoundry.pipeline.alerts import AlertSink, LoggingAlertSink
from messagefoundry.pipeline.cluster import ClusterCoordinator, NullCoordinator
from messagefoundry.redaction import safe_exc, safe_text
from messagefoundry.pipeline.dryrun import route_only, transform_one
from messagefoundry.store import MessageStatus, QueueStore, Stage
from messagefoundry.transports import (
    DeliveryError,
    DestinationConnector,
    NegativeAckError,
    SourceConnector,
    build_destination,
    build_source,
)
from messagefoundry.transports.database import DatabaseLookupExecutor
from messagefoundry.transports.mllp import build_ack

__all__ = ["RegistryRunner"]

log = logging.getLogger(__name__)

# A delivery worker backs off this long after an *unexpected* error (e.g. the store being briefly
# unavailable) before retrying, so a transient failure logs once and recovers instead of hot-looping.
_WORKER_ERROR_BACKOFF_SECONDS = 1.0

# A queue_buildup alert re-fires at most this often per connection while the lane stays over threshold,
# so an ongoing stall reminds the operator without spamming on every backed-off retry.
_BUILDUP_REALERT_SECONDS = 300.0

# The ingress worker has no per-message "failure" to hang a buildup check on (a slow-but-working
# router just falls behind), so it polls the lane depth at most this often — bounding the extra
# COUNT+MIN query rate on the ingress hot path regardless of throughput.
_BUILDUP_CHECK_INTERVAL = 1.0

# How long the handler's worker thread blocks on a single db_lookup() before giving up (ADR 0010).
# A live lookup that exceeds this raises (→ the message's transform fails and dead-letters) rather than
# pinning a worker thread forever; the orphaned query still completes on the loop and releases its conn.
_LOOKUP_RESULT_TIMEOUT_SECONDS = 30.0


def _peek_for_loopback(
    ic: InboundConnection, body: str
) -> tuple[str | None, str | None, str | None, bool]:
    """Derive ``(control_id, message_type, summary, peek_failed)`` for a re-ingressed loopback body
    (ADR 0013 Increment 2, Q5) — the re-ingress worker's parsing step, kept in ``pipeline/`` (not the
    store) so the store stays parsing-free, exactly as ``_handle_inbound`` peeks before
    ``enqueue_ingress``. An HL7V2 loopback runs ``Peek.parse`` (``peek_failed=True`` on ``HL7PeekError``
    → the child is recorded RECEIVED→ERROR, not dropped); any other ``content_type`` (x12/text/json) is
    relayed verbatim as a ``RawMessage`` — no parse, ``message_type`` = the content_type value."""
    if ic.content_type is ContentType.HL7V2:
        try:
            peek = Peek.parse(body)
        except HL7PeekError:
            return None, None, None, True
        return peek.control_id, peek.message_type, (summarize(peek) or None), False
    return None, ic.content_type.value, None, False


class RegistryRunner:
    """Runs every inbound connection in a Registry + one delivery worker per outbound."""

    def __init__(
        self,
        registry: Registry,
        store: QueueStore,
        *,
        poll_interval: float = 0.25,
        claim_limit: int = 20,
        inbound_bind_host: str = "127.0.0.1",
        allow_insecure_bind: bool = False,
        delivery_defaults: RetryPolicy | None = None,
        ordering_default: OrderingMode | None = None,
        internal_error_default: InternalErrorPolicy | None = None,
        buildup_default: BuildupThreshold | None = None,
        ack_after_default: AckAfter | None = None,
        alert_sink: AlertSink | None = None,
        egress: EgressSettings | None = None,
        simulate_all: bool = False,
        env_values: Mapping[str, Any] | None = None,
        active_environment: str | None = None,
        coordinator: ClusterCoordinator | None = None,
        max_correlation_depth: int = 8,
    ) -> None:
        self.registry = registry
        self.store = store
        # ADR 0013 Increment 2: the loop-prevention cap for re-ingress. A re-ingressed message at this
        # correlation depth still routes; the next hop (depth+1) dead-letters its work-row and ERRORs the
        # origin. Coarse by design (bounds total work, not topology). From [pipeline] max_correlation_depth.
        self._max_correlation_depth = max_correlation_depth
        # Cluster coordination seam (Track B Step 3). Threaded in + held so Step 4 can consult the
        # cheap, synchronous is_leader() gate. None → the no-op NullCoordinator (always leader), so
        # single-node operation is byte-identical to before this seam existed.
        self._coordinator: ClusterCoordinator = coordinator or NullCoordinator()
        # The active environment name ([ai].environment / serve --env), published around each
        # router/transform run so a Handler's current_environment() resolves (ADR 0006-style per-face
        # logic). A deployment constant, so the read is pure/re-run-safe.
        self._active_environment = active_environment
        self.poll_interval = poll_interval
        self.claim_limit = claim_limit
        # Global outbound defaults (from [delivery]); a connection's own settings override them.
        # An outbound with none inherits these (per-connection override > global default > built-in).
        self._delivery_defaults = delivery_defaults or RetryPolicy()
        self._ordering_default = ordering_default or OrderingMode.FIFO
        self._internal_error_default = internal_error_default or InternalErrorPolicy.CONTINUE
        self._buildup_default = buildup_default or BuildupThreshold()
        # Global inbound ACK-timing default (from [inbound]); a connection's own ack_after overrides
        # it. Step A only supports INGEST (ACK-on-receipt); a resolved DELIVERED fails loud at start.
        self._ack_after_default = ack_after_default or AckAfter.INGEST
        # Where the delivery workers report operational stalls (a stopped connection, a building
        # backlog). Defaults to the logging sink until a real notifier is wired (docs/BACKLOG.md item 5).
        self._alert_sink: AlertSink = alert_sink or LoggingAlertSink()
        # Fail-closed outbound destination allowlist (WP-11c); empty = unrestricted. Enforced at
        # build_check (config load/reload) and start, so a non-allowed destination is refused.
        self._egress = egress or EgressSettings()
        # Deployment-wide shadow override ([shadow].simulate_all_egress, #15): when True, EVERY outbound
        # runs egress-suppressed regardless of its own simulate= flag. Resolved per-connection into
        # self._simulate at reconcile (per-connection simulate OR this).
        self._simulate_all = simulate_all
        # The interface inbound listeners bind to (service-level; authors never set a host). Loopback
        # by default — see config.settings.InboundSettings.bind_host.
        self._inbound_bind_host = inbound_bind_host
        # Whether `serve --allow-insecure-bind` was passed — the dev escape that downgrades the MLLP
        # exposed-gate (a non-loopback plaintext bind) from refuse to a loud warning (ADR 0002 §0).
        self._allow_insecure_bind = allow_insecure_bind
        # This instance's environment values (DEV/PROD): env() references in connection specs resolve
        # against this map when a connector is built (a missing key fails loud — see resolve_env_settings).
        self._env_values: dict[str, Any] = dict(env_values or {})
        self._sources: dict[str, SourceConnector] = {}
        self._destinations: dict[str, DestinationConnector] = {}
        # One delivery worker per outbound connection, addressable by name so a reload can
        # gracefully stop/swap a single connection's worker without touching its siblings.
        self._workers: dict[str, asyncio.Task[None]] = {}
        # Two workers per inbound connection (staged pipeline, ADR 0001 Step B): a ROUTER worker drains
        # the ingress stage (Router → routed-stage rows) and a TRANSFORM worker drains the routed stage
        # (handler transform → outbound rows). Both run independently of whether the source is actively
        # listening, so messages already ACKed at ingress are always carried through (even while the
        # source is stopped). Addressable by inbound name so a reload/restart can re-arm one in place.
        self._router_workers: dict[str, asyncio.Task[None]] = {}
        self._transform_workers: dict[str, asyncio.Task[None]] = {}
        # ADR 0013 Increment 2: a RESPONSE worker per LOOPBACK inbound, draining its Stage.RESPONSE
        # tokens (a captured reply owes a re-ingress) via ingress_handoff. Non-loopback inbounds have none.
        self._response_workers: dict[str, asyncio.Task[None]] = {}
        # connector + retry are re-resolved per item from these maps, so a reload can swap an
        # outbound's settings under a running worker without tearing the worker down.
        self._retry: dict[str, RetryPolicy] = {}
        self._ordering: dict[str, OrderingMode] = {}
        self._internal_error: dict[str, InternalErrorPolicy] = {}
        self._buildup: dict[str, BuildupThreshold] = {}
        # Effective per-connection egress-suppression (#15): per-connection simulate= OR simulate_all.
        self._simulate: dict[str, bool] = {}
        # Connections that FAILED to build/bind at start (name → reason). A failed connection is
        # isolated, never fatal — the rest of the graph still comes up (a failed connection must not
        # crash the engine, ADR 0031). A failed OUTBOUND still gets its delivery worker, but with no
        # connector in _destinations, so rows routed to it are retried + alerted (never silently
        # dropped) and a reload/restart that builds it self-heals the lane; a failed INBOUND simply
        # isn't listening. Cleared when the connection later builds/binds (reload, start_inbound).
        self._failed: dict[str, str] = {}
        # Per-connection re-alert throttle: the earliest time a queue_buildup alert may fire again.
        self._next_buildup_alert: dict[str, float] = {}
        # Live-lookup executor (db_lookup, ADR 0010): built from registry.lookups at start/reload, None
        # when the graph declares no DatabaseLookup — in which case the transform path stays byte-identical
        # (inline call, no thread hop, no runner). The engine loop is captured at start so a handler's
        # worker thread can bridge a db_lookup back onto it (run_coroutine_threadsafe).
        self._lookup_executor: DatabaseLookupExecutor | None = None
        self._loop: asyncio.AbstractEventLoop | None = None
        self._stop = asyncio.Event()
        # Per-stage wake events so a producer wakes only its own downstream consumer class. A single
        # shared auto-clearing event would let an idle worker of one class swallow another class's
        # wakeup (lost wakeup) — masked by poll_interval but defeating the prompt set(). Listener →
        # router (_ingress_work); router → transform (_routed_work); transform / replay → delivery
        # (_work). Each worker class waits on (and clears) only its own event.
        self._ingress_work = asyncio.Event()
        self._routed_work = asyncio.Event()
        # ADR 0013 Increment 2: wakes the per-loopback re-ingress worker when a Stage.RESPONSE work-row
        # is produced (a captured reply owes a re-ingress) — a sibling of _ingress_work/_routed_work.
        self._response_work = asyncio.Event()
        self._work = asyncio.Event()
        self._running = False
        self._reload_lock = asyncio.Lock()  # serialize concurrent reloads

    @property
    def running(self) -> bool:
        return self._running

    @property
    def coordinator(self) -> ClusterCoordinator:
        """The cluster coordinator threaded in by the engine (Track B Step 3). Step 4 consumes its
        cheap, synchronous ``is_leader`` gate; this exposes the object."""
        return self._coordinator

    def notify_work(self) -> None:
        """Wake every stage worker now (e.g. after a replay re-queues rows at an unknown stage)."""
        self._ingress_work.set()
        self._routed_work.set()
        self._response_work.set()
        self._work.set()

    def set_env_values(self, values: Mapping[str, Any]) -> None:
        """Replace the environment values used to resolve ``env()`` refs when (re)building connectors.
        The engine calls this on reload so a promote picks up edited values without a restart (M-23)."""
        self._env_values = dict(values)

    def _build_lookup_executor(self) -> DatabaseLookupExecutor | None:
        """Build the pooled live-lookup executor from the current graph's ``DatabaseLookup`` specs, or
        ``None`` if the graph declares none (so the transform path stays byte-identical — inline call,
        no thread hop, no runner). Resolves ``env()`` in each spec and fail-closed egress-checks the
        server, exactly like a DATABASE source. ``build_check`` already validated these on a reload, so
        this won't raise there; at start a bad spec surfaces here and unwinds the partial start."""
        if not self.registry.lookups:
            return None
        resolved: dict[str, dict[str, Any]] = {}
        for name, spec in self.registry.lookups.items():
            settings = resolve_env_settings(spec.settings, self._env_values)
            check_lookup_allowed(name, settings, self._egress)
            resolved[name] = settings
        return DatabaseLookupExecutor(resolved)

    def _run_lookup(
        self, connection: str, statement: str, params: Mapping[str, Any] | None
    ) -> list[dict[str, Any]]:
        """The lookup runner published to Handlers (``db_lookup`` → this). Called FROM the handler's
        worker thread (``transform_one`` runs off the loop when lookups are declared), it bridges the
        async query onto the engine loop via ``run_coroutine_threadsafe`` and blocks the WORKER THREAD —
        never the loop — for the result (bounded by ``_LOOKUP_RESULT_TIMEOUT_SECONDS``)."""
        executor = self._lookup_executor
        loop = self._loop
        if executor is None or loop is None:  # only published when both exist; guard defensively
            raise DbLookupError("db_lookup is unavailable — no lookup connections are configured")
        future = asyncio.run_coroutine_threadsafe(
            executor.query(connection, statement, params), loop
        )
        return future.result(_LOOKUP_RESULT_TIMEOUT_SECONDS)

    # --- per-connection control (console operations) -------------------------

    def inbound_running(self, name: str) -> bool:
        return name in self._sources

    def connection_failed(self, name: str) -> str | None:
        """The failure reason if this connection failed to build/bind at start, else None. A failed
        connection is isolated, not fatal (ADR 0031): the engine starts the rest of the graph and an
        operator recovers it (fix the cause, then reload or — for an inbound — restart it)."""
        return self._failed.get(name)

    def degraded_connections(self) -> dict[str, str]:
        """Snapshot of ``{connection: reason}`` for connections that failed to start (ADR 0031).
        Empty when every connection came up — the API/console use it to flag a degraded engine."""
        return dict(self._failed)

    def outbound_simulated(self, name: str) -> bool:
        """Whether the named outbound is in **simulate** mode — egress suppressed (#15). The *effective*
        value (per-connection ``simulate=`` OR ``[shadow].simulate_all_egress``), for the ``/connections``
        API + console so a simulated lane is unmissable.

        Prefers the value resolved at reconcile (what the delivery worker actually uses, and the only
        source for a *draining* outbound the registry no longer declares); falls back to resolving from
        the registry for a connection that is declared but not yet reconciled (e.g. the metadata endpoint
        on a not-yet-started engine)."""
        if name in self._simulate:
            return self._simulate[name]
        oc = self.registry.outbound.get(name)
        return (bool(oc.simulate) or self._simulate_all) if oc is not None else False

    def _resolve_simulate(self, name: str, oc: OutboundConnection) -> bool:
        """Resolve a connection's effective simulate flag and log **once** when a lane (newly) enters
        simulate mode (so it's loud in the operator log, not just the API)."""
        simulate = bool(oc.simulate) or self._simulate_all
        if simulate and not self._simulate.get(name, False):
            log.warning(
                "outbound %r is in SIMULATE mode — real egress SUPPRESSED (no delivery to the live "
                "peer); messages still finalize PROCESSED for shadow/parallel-run comparison (#15)",
                name,
            )
        return simulate

    def build_test_connector(self, name: str) -> tuple[str, SourceConnector | DestinationConnector]:
        """Build a **fresh** connector for the named connection so it can be reachability-tested —
        never the live one in ``_sources``/``_destinations`` (probing the live connector would disturb
        running traffic). Resolves ``env()`` and enforces the ``[egress]`` allowlist fail-closed, the
        same as a real build. Returns ``("in", source)`` or ``("out", destination)``. Raises
        :class:`KeyError` if ``name`` isn't a connection, :class:`WiringError` on a bad ``env()`` /
        egress. The caller closes the connector (``stop()`` / ``aclose()``) after testing."""
        ic = self.registry.inbound.get(name)
        if ic is not None:
            source_cfg = _source_config(ic, self._inbound_bind_host, self._env_values)
            check_source_allowed(source_cfg, name, self._egress)
            return "in", build_source(source_cfg)
        oc = self.registry.outbound.get(name)
        if oc is not None:
            dest_cfg = _dest_config(oc, self._env_values)
            check_egress_allowed(dest_cfg, self._egress)
            return "out", build_destination(dest_cfg)
        raise KeyError(name)

    async def start_inbound(self, name: str) -> None:
        """Start receiving on one inbound connection (no-op if already listening).

        Public console/API entrypoint — takes the reload lock so it can't race a concurrent
        reload()/stop() mutating _sources/_workers (review M-10). Internal callers that already hold
        the lock (start, reload) use :meth:`_start_inbound_unsafe`."""
        async with self._reload_lock:
            await self._start_inbound_unsafe(name)

    async def stop_inbound(self, name: str) -> None:
        """Stop receiving on one inbound connection (its delivery workers keep draining)."""
        async with self._reload_lock:
            await self._stop_inbound_unsafe(name)

    async def restart_inbound(self, name: str) -> None:
        # One lock span so stop+start is atomic w.r.t. a concurrent reload (review M-10).
        async with self._reload_lock:
            await self._stop_inbound_unsafe(name)
            await self._start_inbound_unsafe(name)

    async def _start_inbound_unsafe(self, name: str) -> None:
        """start_inbound body without the reload lock — for callers that already hold it (start,
        reload). asyncio.Lock isn't reentrant, so the public wrappers must not call each other."""
        if name in self._sources:
            return
        ic = self.registry.inbound[name]
        # Resolve + guard the ACK-timing setting (per-connection override > global default). Step A
        # only ships ACK-on-receipt; reject a resolved 'delivered' loud at start/reload rather than
        # silently downgrade (covers a global [inbound] ack_after='delivered' inherited by a
        # connection — the per-connection case is already rejected in inbound()). Compare by VALUE,
        # not identity: AckAfter is a str-Enum, so a stray raw-string 'delivered' must still be caught.
        if (ic.ack_after or self._ack_after_default) == AckAfter.DELIVERED:
            raise WiringError(
                f"inbound connection {name!r}: ack_after='delivered' is not yet implemented "
                "(Step A ships ACK-on-receipt only — use ack_after='ingest', the default)"
            )
        source_cfg = _source_config(ic, self._inbound_bind_host, self._env_values)
        check_source_allowed(source_cfg, ic.name, self._egress)  # fail-closed connect allowlist
        # Exposed-gate (ADR 0002 §0 / ADR 0025 §9): refuse a non-loopback MLLP or DICOM SCP listener
        # without TLS at start (cleartext PHI on the wire). Each guard no-ops for the other's type.
        check_mllp_tls_exposure(source_cfg, ic.name, allow_insecure_bind=self._allow_insecure_bind)
        check_dimse_tls_exposure(source_cfg, ic.name, allow_insecure_bind=self._allow_insecure_bind)
        source = build_source(source_cfg)
        # Leader-gate the source's intake (Track B Step 4b). is_leader is a cheap, synchronous bound
        # method = Callable[[], bool]; passing the bound METHOD (not the coordinator) keeps transports/
        # free of any pipeline/cluster import. Only POLL sources act on it — they skip a scan when it
        # returns False so exactly one node ingests a shared external resource (a dir / DB table /
        # remote dir); LISTEN sources (MLLP/TCP) accept-and-ignore it (each binds its own endpoint). For
        # single-node (NullCoordinator) is_leader is always True, so every poll source scans as before.
        # Bind BEFORE registering: a failed bind (e.g. port in use) must not leave a dead source in
        # _sources, where inbound_running() would report True and a retry would no-op (review M-9).
        await source.start(self._make_handler(ic), leader_gate=self._coordinator.is_leader)
        self._sources[name] = source
        self._failed.pop(
            name, None
        )  # bound successfully — clear any prior start failure (ADR 0031)
        # Once the source is live, note (start-time only, never per-tick) that a poll source's intake
        # is leader-gated, so an operator reading the log knows only the leader polls this resource.
        if getattr(source, "polls_shared_resource", False):
            log.info(
                "inbound %r polls a shared external resource; intake is leader-gated (only the "
                "cluster leader polls it — single-node always does)",
                name,
            )
        # Ensure this inbound's router + transform workers are running. They are registry-tied, not
        # source-tied — so a per-connection start/restart, or a reload, re-arms a worker that exited
        # (e.g. halted by the STOP internal-error policy), otherwise the restarted source would resume
        # ACK-on-receipt into an ingress/routed backlog with nothing draining it. Idempotent (same guard
        # reload() uses); only runs once the runner is up so start()'s own spawn loop owns first boot.
        if self._running:
            self._ensure_inbound_workers(name)

    async def _stop_inbound_unsafe(self, name: str) -> None:
        """stop_inbound body without the reload lock — for callers that already hold it."""
        source = self._sources.pop(name, None)
        if source is not None:
            await source.stop()

    def _record_failed(self, name: str, exc: BaseException, *, kind: str) -> None:
        """Isolate a connection that failed to build/bind (ADR 0031): record the reason, log it
        loudly, and alert — the engine keeps the rest of the graph running. Reuses the AlertSink
        ``connection_stopped`` signal: its meaning ("this connection is down until an operator
        intervenes") fits a startup failure exactly, so no new sink method is needed."""
        reason = safe_exc(exc)
        self._failed[name] = reason
        log.error(
            "%s connection %r failed to start — ISOLATED, engine continues (fix the cause, then "
            "reload%s): %s",
            kind,
            name,
            " or restart it" if kind == "inbound" else "",
            reason,
            exc_info=exc,
        )
        try:
            self._alert_sink.connection_stopped(name, detail=f"failed to start: {reason}")
        except Exception:
            log.exception("alert sink raised on connection_stopped for %r", name)

    def _start_outbound(self, name: str, oc: OutboundConnection) -> None:
        """Build one outbound connector + spawn its delivery worker. A build failure (unresolvable
        ``env()`` / cert, an egress-allowlist refusal, a capture/backend mismatch) is ISOLATED
        (ADR 0031): the connection is recorded failed and the worker is STILL spawned, but with no
        connector — so rows routed to it are retried + buildup-alerted (never silently dropped,
        preserving the count-and-log + at-least-once invariants) and a later reload/restart that builds
        the connector self-heals the lane. retry/ordering/etc. are set regardless of build outcome
        because the worker reads them live per item (a reload can swap a working connector under the
        already-spawned worker)."""
        self._retry[name] = oc.retry or self._delivery_defaults
        self._ordering[name] = oc.ordering or self._ordering_default
        self._internal_error[name] = oc.internal_error or self._internal_error_default
        self._buildup[name] = oc.buildup or self._buildup_default
        self._simulate[name] = self._resolve_simulate(name, oc)
        try:
            dest = _dest_config(oc, self._env_values)
            check_egress_allowed(dest, self._egress)  # fail-closed egress allowlist (WP-11c)
            connector = build_destination(dest)
            # ADR 0013: a capturing outbound on a backend that can't persist captures must not deliver
            # — but (ADR 0031) degrade THIS lane, don't crash the engine. Rows routed here are retried,
            # not dropped, so the ADR 0013 "never silently drop replies" intent is preserved.
            if getattr(connector, "capture_response", False) and not getattr(
                self.store, "supports_response_capture", True
            ):
                raise RuntimeError(
                    f"outbound {name!r} sets capture_response=True but the store backend does not "
                    "support request/response capture (ADR 0013); use the SQLite or Postgres backend"
                )
        except Exception as exc:
            self._destinations.pop(name, None)  # no live connector for a failed lane
            self._record_failed(name, exc, kind="outbound")
            self._spawn_worker(name)  # drains→retries routed rows via the connector-None path
            return
        self._destinations[name] = connector
        self._failed.pop(name, None)
        self._spawn_worker(name)

    async def start(self) -> None:
        async with self._reload_lock:
            if self._running:
                return
            self._stop.clear()
            # Capture the engine loop so a handler's worker thread can bridge a db_lookup back onto it.
            self._loop = asyncio.get_running_loop()
            try:
                # Per-connection fault isolation (ADR 0031): a single outbound build / inbound bind
                # failure no longer aborts startup — it is recorded + alerted and the rest of the graph
                # still comes up (a failed connection must not crash the engine). The outer except below
                # stays a backstop for genuinely fatal, graph-wide startup errors (the store, the
                # lookup executor), which still unwind + raise.
                for name, oc in self.registry.outbound.items():
                    self._start_outbound(name, oc)
                # Build the live-lookup executor from the graph (env-resolved + egress-checked here);
                # None when no DatabaseLookup is declared, keeping the transform path byte-identical. A
                # failure here is graph-wide (not one connection), so let it hit the backstop below.
                self._lookup_executor = self._build_lookup_executor()
                for ic in self.registry.inbound.values():
                    try:
                        await self._start_inbound_unsafe(ic.name)
                    except Exception as exc:
                        # Isolate this inbound (bad bind / port in use / cleartext-exposure refusal /
                        # bad env): record it failed and continue. It never binds insecurely — the
                        # guard still refused; we just don't also kill the engine over it.
                        self._record_failed(ic.name, exc, kind="inbound")
                # A router + transform worker per inbound — spawned even for an inbound whose source
                # failed to bind, so any crash-recovered ingress/routed backlog still drains (the source
                # just isn't listening). They drain ingress→routed→outbound, independent of listen state.
                for name in self.registry.inbound:
                    self._ensure_inbound_workers(name)
            except Exception:
                # A truly fatal startup error (store / lookup executor — NOT a single connection, which
                # is isolated above) must not leave half the graph wired with _running still False:
                # unwind everything we started so the listeners are released and a retry can rebind (M-8).
                log.exception("wiring start failed; unwinding the partial start")
                await self._teardown_unsafe()
                raise
            self._running = True
            if self._failed:
                log.warning(
                    "wiring started DEGRADED: %d inbound, %d outbound connection(s); "
                    "%d failed to start (isolated, engine running): %s",
                    len(self.registry.inbound),
                    len(self.registry.outbound),
                    len(self._failed),
                    ", ".join(f"{n} ({r})" for n, r in self._failed.items()),
                )
            else:
                log.info(
                    "wiring started: %d inbound, %d outbound connection(s)",
                    len(self.registry.inbound),
                    len(self.registry.outbound),
                )

    async def stop(self) -> None:
        async with self._reload_lock:  # serialize against an in-flight reload (no torn-down state)
            had_state = self._running or bool(self._sources or self._workers or self._destinations)
            await self._teardown_unsafe()
            if had_state:
                log.info("wiring stopped")

    async def _teardown_unsafe(self) -> None:
        """Tear down all sources/workers/destinations and mark stopped. Lock-free (callers hold
        _reload_lock) and idempotent — cleans up whatever is registered even if the runner never
        reached _running, so a half-started runner (review M-8) and a double stop() are both safe."""
        self._stop.set()
        self._ingress_work.set()
        self._routed_work.set()
        self._response_work.set()
        self._work.set()
        for source in self._sources.values():
            await source.stop()
        inbound_tasks = (
            *self._router_workers.values(),
            *self._transform_workers.values(),
            *self._response_workers.values(),
        )
        for task in (*self._workers.values(), *inbound_tasks):
            task.cancel()
        await asyncio.gather(*self._workers.values(), *inbound_tasks, return_exceptions=True)
        for connector in self._destinations.values():
            await connector.aclose()
        if self._lookup_executor is not None:
            await self._lookup_executor.aclose()
            self._lookup_executor = None
        self._workers.clear()
        self._router_workers.clear()
        self._transform_workers.clear()
        self._response_workers.clear()
        self._destinations.clear()
        self._retry.clear()
        self._internal_error.clear()
        self._buildup.clear()
        self._simulate.clear()
        self._next_buildup_alert.clear()
        self._sources.clear()
        self._running = False

    # --- outbound worker management ------------------------------------------

    def _spawn_worker(self, name: str) -> None:
        """Start a delivery worker for one outbound connection (drains its outbox rows)."""
        task = asyncio.create_task(self._delivery_worker(name))
        task.add_done_callback(functools.partial(self._on_worker_done, name))
        self._workers[name] = task

    def _on_worker_done(self, name: str, task: asyncio.Task[None]) -> None:
        """A delivery worker should only finish on shutdown — its loop swallows + backs off on
        errors. If one somehow dies while the engine is running, log and respawn so the destination
        keeps draining rather than silently stalling (review H-1)."""
        if self._stop.is_set() or not self._running or task.cancelled():
            return  # expected shutdown / cancellation
        if task.exception() is None:
            return
        if self._workers.get(name) is task:  # still the registered worker (not mid-reconcile/stop)
            log.error(
                "delivery worker %r exited unexpectedly; respawning",
                name,
                exc_info=task.exception(),
            )
            self._spawn_worker(name)

    def _inbound_worker_coro(self, kind: str):  # type: ignore[no-untyped-def]
        """The coroutine factory for an inbound worker ``kind`` (``router`` | ``transform`` |
        ``response``). The ``response`` worker (ADR 0013) runs only for loopback inbounds."""
        return {
            "router": self._router_worker,
            "transform": self._transform_worker,
            "response": self._response_worker,
        }[kind]

    def _inbound_worker_dict(self, kind: str) -> dict[str, asyncio.Task[None]]:
        return {
            "router": self._router_workers,
            "transform": self._transform_workers,
            "response": self._response_workers,
        }[kind]

    def _ensure_inbound_workers(self, name: str) -> None:
        """Ensure the router + transform (+ for a loopback inbound, the response) workers for one inbound
        are running, spawning any that exited (a STOP-policy halt, a reload adding the inbound, or a
        crash). Idempotent — the shared re-arm used by start(), start_inbound(), and reload()."""
        kinds = ["router", "transform"]
        ic = self.registry.inbound.get(name)
        if ic is not None and ic.spec.type is ConnectorType.LOOPBACK:
            # ADR 0013: a loopback inbound also gets a RESPONSE worker draining its Stage.RESPONSE tokens.
            kinds.append("response")
        for kind in kinds:
            task = self._inbound_worker_dict(kind).get(name)
            if task is None or task.done():
                self._spawn_inbound_worker(kind, name)

    def _spawn_inbound_worker(self, kind: str, name: str) -> None:
        """Start the ``kind`` (router/transform) worker for one inbound connection."""
        workers = self._inbound_worker_dict(kind)
        task = asyncio.create_task(self._inbound_worker_coro(kind)(name))
        task.add_done_callback(functools.partial(self._on_inbound_worker_done, kind, name))
        workers[name] = task

    def _on_inbound_worker_done(self, kind: str, name: str, task: asyncio.Task[None]) -> None:
        """A router/transform worker should only finish on shutdown or a STOP-policy halt. If it dies
        on an unexpected error while running, respawn it so the inbound keeps processing (mirrors the
        delivery worker's supervisor). A STOP-policy halt returns normally (no exception) and is left
        down until a reload re-arms it."""
        if self._stop.is_set() or not self._running or task.cancelled():
            return  # expected shutdown / cancellation
        if task.exception() is None:
            return  # normal return (e.g. STOP policy halted the lane) — not respawned
        if self._inbound_worker_dict(kind).get(name) is task:
            log.error(
                "%s worker %r exited unexpectedly; respawning",
                kind,
                name,
                exc_info=task.exception(),
            )
            self._spawn_inbound_worker(kind, name)

    def build_check(self, registry: Registry) -> None:
        """Construct (and discard) every connector in ``registry`` so a bad connector spec fails
        BEFORE a reload quiesces anything — i.e. the running graph is left untouched. Construction
        is side-effect-free (no socket bind / file I/O — binding happens later in ``start_inbound``).
        Raises :class:`WiringError` so the API maps it to 422 like other invalid-config errors."""
        build_check_registry(
            registry,
            inbound_bind_host=self._inbound_bind_host,
            env_values=self._env_values,
            egress=self._egress,
        )

    async def _reconcile_outbounds(self, old: Registry, new: Registry) -> None:
        """Bring the outbound connectors/workers in line with ``new`` without tearing down a live
        worker (so its in-flight outbox batch keeps draining). A worker re-resolves its connector
        per item, so a changed connector is swapped in place; the old one is closed (a single racing
        send at most fails and retries — outbounds are idempotent). An outbound dropped by ``new`` is
        left running so rows already queued to it still drain. Connector builds here cannot fail —
        :meth:`_build_check` already validated them before any quiesce."""
        for name, oc in new.outbound.items():
            # workers read retry + ordering + internal-error policy live each item, so a reload
            # retunes (incl. re-arming a previously stopped connection) without a restart
            self._retry[name] = oc.retry or self._delivery_defaults
            self._ordering[name] = oc.ordering or self._ordering_default
            self._internal_error[name] = oc.internal_error or self._internal_error_default
            self._buildup[name] = oc.buildup or self._buildup_default
            self._simulate[name] = self._resolve_simulate(name, oc)
            worker = self._workers.get(name)
            failed = name in self._failed  # ADR 0031: live worker, but no connector (start failed)
            if worker is None or worker.done():
                # added (or replacing a crashed worker): close any stale connector, build + spawn.
                stale = self._destinations.pop(name, None)
                if stale is not None:
                    await stale.aclose()
                self._destinations[name] = build_destination(_dest_config(oc, self._env_values))
                self._failed.pop(name, None)
                self._spawn_worker(name)
            elif failed or old.outbound.get(name) is None or old.outbound[name].spec != oc.spec:
                # live worker but a missing/mismatched connector → (re)build it in place, close any old
                # one. `failed` covers an outbound that failed to build at START (ADR 0031): its worker
                # is alive with no connector, so a reload once the cause is fixed self-heals the lane
                # (build_check above already re-validated the whole new registry, so this build can't
                # fail here — a still-broken connector would have raised before any quiesce).
                old_conn = self._destinations.get(name)
                self._destinations[name] = build_destination(_dest_config(oc, self._env_values))
                self._failed.pop(name, None)
                if old_conn is not None:
                    await old_conn.aclose()
            # else: unchanged & live → leave the worker/connector as-is.
        # Outbounds removed by ``new`` keep their worker so already-queued rows finish draining.

    # --- atomic reload (quiesce-and-swap) ------------------------------------

    async def reload(self, new_registry: Registry) -> None:
        """Atomically swap to ``new_registry`` on the running graph (whole-config swap).

        Quiesce-and-swap, in this order: (0) build-check every new connector — a bad spec raises
        here, before anything is touched, so the running graph is left intact; (1) stop accepting new
        inbound messages; (2) swap the registry + restart the inbound listeners from it (Router/
        Handler changes take effect immediately — the inbound path reads ``self.registry`` live);
        (3) reconcile the outbound connectors/workers *without* tearing them down, so in-flight
        outbox rows keep draining (at-least-once preserved). If any step fails the previous graph's
        intake is restored before the error propagates. Restarting inbounds before reconciling
        outbounds means a slow/hung outbound never blocks the engine's intake.
        """
        async with self._reload_lock:
            self.build_check(new_registry)  # raises before any change on a bad connector
            if not self._running:
                self.registry = new_registry
                return

            old = self.registry
            old_inbound_names = list(self._sources)

            # 1. Quiesce intake: stop every inbound source so no NEW messages are accepted. Any
            #    message already in flight completes under its arrival-time registry (snapshotted in
            #    _make_handler), so it stays consistent even if a source's stop() returns early.
            for name in old_inbound_names:
                await self._stop_inbound_unsafe(
                    name
                )  # we hold _reload_lock — use the unsafe variant

            try:
                # 2. Swap the registry and restart inbound listeners from it (intake back up first).
                self.registry = new_registry
                # Rebuild the live-lookup executor from the new graph, closing the old pools. build_check
                # already validated the new specs, so this can't fail on a bad spec here.
                old_lookup_executor = self._lookup_executor
                self._lookup_executor = self._build_lookup_executor()
                if old_lookup_executor is not None:
                    await old_lookup_executor.aclose()
                for ic in new_registry.inbound.values():
                    await self._start_inbound_unsafe(ic.name)
                # 2b. Ensure the router + transform workers run for every inbound in the new graph.
                # Workers read self.registry live, so a Router/Handler change applies to rows processed
                # after the swap; a removed inbound keeps its workers so residual ingress/routed rows
                # still drain.
                for name in new_registry.inbound:
                    self._ensure_inbound_workers(name)
                # 3. Reconcile outbound connectors/workers (intake already live).
                await self._reconcile_outbounds(old, new_registry)
            except Exception:
                # Roll back to the previous graph's intake so a failed reload leaves the engine
                # accepting exactly what it did before (the realistic failure is an inbound bind).
                log.exception("reload failed; rolling back inbound intake to the previous graph")
                self.registry = old
                for name in list(self._sources):
                    await self._stop_inbound_unsafe(name)
                for name in old_inbound_names:
                    try:
                        await self._start_inbound_unsafe(name)
                    except Exception:
                        log.exception("rollback: could not restart inbound %r", name)
                raise

            # Wake every stage (new connections / freshly enqueued rows may sit at any stage).
            self._ingress_work.set()
            self._routed_work.set()
            self._work.set()
            log.info(
                "wiring reloaded: %d inbound, %d outbound connection(s)",
                len(new_registry.inbound),
                len(new_registry.outbound),
            )

    # --- inbound path --------------------------------------------------------

    def _make_handler(self, ic: InboundConnection):  # type: ignore[no-untyped-def]
        # The listener only decodes/parses/validates and commits the raw message to the ingress stage
        # before ACKing (ACK-on-receipt) — it no longer routes, so it needs no registry snapshot.
        # Routing happens later in the router worker against the LIVE registry, so a message ingested
        # before a reload is routed under the new graph (the staged model decouples intake from
        # routing). The inbound name is fixed for this source.
        async def on_message(raw: bytes) -> str | None:
            return await self._handle_inbound(ic, raw)

        return on_message

    async def _handle_inbound(self, ic: InboundConnection, raw: bytes) -> str | None:
        ack_mode = ic.ack_mode
        reply = ack_mode is not AckMode.NONE
        src = ic.spec.type.value
        hl7v2 = ic.content_type is ContentType.HL7V2

        if not hl7v2 and ic.content_type.is_binary:
            # Binary ingress (ADR 0028): a byte-oriented content type carries raw bytes that cannot
            # ride the str/TEXT store as text — a NUL/non-UTF-8 body is rejected (Postgres) or
            # truncated (SQLite/SQL Server). Base64-carry them at the source boundary via
            # RawMessage.from_bytes (the one encode); never attempt a text decode. The router/transform
            # workers route the carriage form as a RawMessage and a codec recovers bytes via .raw_bytes.
            await self.store.enqueue_ingress(
                channel_id=ic.name,
                raw=RawMessage.from_bytes(raw, ic.content_type.value).raw,
                control_id=None,
                message_type=ic.content_type.value,
                source_type=src,
                summary=None,
            )
            self._ingress_work.set()
            return None

        # Decode with the connection's configured charset. A genuine decode failure means the bytes
        # aren't valid in the declared encoding — record ERROR (preserving the exact bytes via a
        # lossless latin-1 view) and NAK, rather than silently substituting U+FFFD into the stored
        # raw and the delivered copy (review H-3). HL7 also normalizes line endings to \r; a non-HL7
        # body (JSON/XML/text) is decoded verbatim — \r-normalizing it would corrupt it (ADR 0004).
        encoding = ic.spec.settings.get("encoding", "utf-8")
        try:
            text = (
                normalize(raw, encoding=encoding, errors="strict")
                if hl7v2
                else raw.decode(encoding)
            )
        except UnicodeDecodeError as exc:
            await self.store.record_received(
                channel_id=ic.name,
                raw=raw.decode("latin-1"),  # lossless byte view — the declared encoding rejected it
                status=MessageStatus.ERROR,
                error=f"decode error ({encoding}): {safe_exc(exc)}",
                source_type=src,
                message_type=None if hl7v2 else ic.content_type.value,
            )
            return (
                build_ack(raw, code="AR", text="decode error", ack_mode=ack_mode)
                if (hl7v2 and reply)
                else None
            )

        if not hl7v2:
            # Payload-agnostic ingress (ADR 0004): a non-HL7 inbound skips HL7 peek/validate and the
            # HL7 ACK. The decoded body is committed verbatim and the router/transform workers route it
            # as a RawMessage; the source connector owns its own receive-time response (no MLLP ACK).
            await self.store.enqueue_ingress(
                channel_id=ic.name,
                raw=text,
                control_id=None,
                message_type=ic.content_type.value,
                source_type=src,
                summary=None,
            )
            self._ingress_work.set()
            return None

        try:
            peek = Peek.parse(text)
        except HL7PeekError as exc:
            await self.store.record_received(
                channel_id=ic.name,
                raw=text,
                status=MessageStatus.ERROR,
                error=f"parse error: {safe_exc(exc)}",
                source_type=src,
            )
            return build_ack(text, code="AR", text=str(exc), ack_mode=ack_mode) if reply else None

        if ic.validation.strict:
            # hl7apy validation is CPU-bound (full structure/cardinality parse) — run it off the event
            # loop so a strict feed can't stall every other listener, worker, and API call (review M-11).
            result = await asyncio.to_thread(
                validate, text, expected_version=ic.validation.hl7_version
            )
            if not result.ok:
                joined = "; ".join(result.errors)
                # Persist a PHI-scrubbed form: hl7apy error strings quote the offending field VALUE
                # (PHI), so this is a persisted-disposition write that must go through the scrub like
                # every other one — it keeps the field NAME / segment ID (the diagnostic an operator
                # needs) but cuts the value (review #120). The scrubbed text is gated behind
                # messages:view_summary on read, like every other stored error.
                persisted = f"strict-validation failed: {safe_text(joined)}"
                await self._record(ic, peek, text, MessageStatus.ERROR, error=persisted)
                # The AE ACK goes back to the partner that SENT this message (their own data) and is
                # transient (never persisted), so it may carry the fuller, bounded validation text.
                return (
                    build_ack(peek, code="AE", text=joined[:200], ack_mode=ack_mode)
                    if reply
                    else None
                )

        # ACK-on-receipt (staged pipeline, ADR 0001 Step A): persist the raw message durably to the
        # ingress stage, then ACK. Routing/transform/delivery run AFTER the ACK in the ingress worker,
        # so a slow/hung router or outbound never stalls intake — and a router/handler failure no
        # longer NAKs the sender (it becomes a logged ERROR/dead-letter at the ingress stage). Decode,
        # parse, and strict validation above stay synchronous and still NAK, preserving the partner
        # contract for a malformed message. ack_after='delivered' (defer the ACK) is rejected at
        # wiring in Step A, so this is always ACK-on-ingest.
        await self.store.enqueue_ingress(
            channel_id=ic.name,
            raw=text,
            control_id=peek.control_id,
            message_type=peek.message_type,
            source_type=src,
            summary=summarize(peek) or None,
        )
        self._ingress_work.set()  # wake the router worker to route the freshly-committed message
        return build_ack(peek, code="AA", ack_mode=ack_mode) if reply else None

    async def _record(
        self,
        ic: InboundConnection,
        peek: Peek,
        raw: str,  # already the decoded, \r-normalized text (see _handle_inbound)
        status: MessageStatus,
        *,
        error: str | None = None,
    ) -> None:
        await self.store.record_received(
            channel_id=ic.name,
            raw=raw,
            status=status,
            error=error,
            control_id=peek.control_id,
            message_type=peek.message_type,
            source_type=ic.spec.type.value,
            summary=summarize(peek) or None,
        )

    # --- delivery path -------------------------------------------------------

    async def _delivery_worker(self, name: str) -> None:
        while not self._stop.is_set():
            try:
                # FIFO (default): claim only the due head — a backing-off head blocks the lane
                # (head-of-line), so order is preserved. UNORDERED: claim a batch and rotate past a
                # backing-off row to drain others. Resolved live so a reload can retune it.
                if self._ordering.get(name, self._ordering_default) is OrderingMode.FIFO:
                    # FIFO: claim only the due head; the head blocks the lane while it backs off. Under
                    # active-passive HA the graph runs on the leader ONLY, so one node drains this lane;
                    # the Postgres claim also reclaims a prior leader's stranded head for failover FIFO.
                    # H2: if the claimed head is an already-delivered duplicate (its outbox_id is in the
                    # idempotency ledger), claim_next_fifo completes it in place and returns None — so the
                    # worker never re-sends it; it simply re-polls and the lane advances (no reorder).
                    head = await self.store.claim_next_fifo(name)
                    items = [head] if head is not None else []
                else:
                    # UNORDERED lanes are intentionally NOT lane-owned — concurrent draining across
                    # nodes is fine, so claim_ready stays unchanged.
                    items = await self.store.claim_ready(
                        limit=self.claim_limit, destination_name=name
                    )
                if not items:
                    await self._wait_for_work(self._work)
                    continue
                for item in items:
                    # Connector + retry re-resolved per item so a reload can swap an outbound's
                    # settings under us with at most one racing send (which fails + retries —
                    # outbounds are idempotent).
                    retry = self._retry.get(name) or RetryPolicy()
                    connector = self._destinations.get(name)
                    if connector is None:
                        # No connector for a claimed row: either a brief mid-reconcile window, or this
                        # outbound failed to build at start (ADR 0031) and its lane is degraded. Either
                        # way RETRY the row (never strand/drop it) — it self-heals when a reload/restart
                        # builds the connector — and alert on the growing backlog of a failed lane.
                        failure = self._failed.get(name)
                        detail = (
                            f"outbound failed to start: {failure}"
                            if failure
                            else "outbound reloading"
                        )
                        await self.store.mark_failed(item.id, detail, retry)
                        await self._maybe_alert_buildup(name)
                        continue
                    # L1 pre-send leadership re-check (active-passive HA). The graph runs on the leader
                    # ONLY, but leadership can be lost (a self-fence) BETWEEN claiming this row and the
                    # send below. A cheap, SYNCHRONOUS is_leader() read (cached state — no DB round-trip)
                    # closes that narrow window: a node that has stopped being leader must not emit egress
                    # as a stale ex-leader. We do NOT drop the row — re-queue it via the existing retry
                    # (mark_failed → PENDING with backoff) so the new leader delivers it (count-and-log,
                    # REL-4). This is a cheap fast-path guard, NOT the authority: the durable backstop is
                    # H1's store-checked leader_epoch fence, which rejects a superseded ex-leader's claim
                    # at the DB inside the claim transaction even if this in-memory check raced. On the
                    # single-node NullCoordinator is_leader() is always True, so this never fires and the
                    # delivery path is byte-identical.
                    if not self._coordinator.is_leader():
                        await self.store.mark_failed(
                            item.id,
                            "leadership lost before send; re-queued for the new leader",
                            retry,
                        )
                        continue
                    try:
                        if self._simulate.get(name, False):
                            # Shadow / parallel-run (#15): suppress the real egress entirely — no bytes/
                            # SQL leave the box. With egress suppressed there is no real partner reply to
                            # capture or re-ingress, so treat it as a completed ONE-WAY delivery: response
                            # = None → mark_done → the message finalizes PROCESSED, and the would-send
                            # outbound payload is retained on the done row for parity comparison. (A
                            # capturing/reingress_to outbound therefore captures nothing in simulate.)
                            response = None
                        else:
                            response = await connector.send(item.payload)
                    except NegativeAckError as exc:
                        # Partner rejection. AR/CR (permanent) → fail-fast: the partner will never
                        # accept this message, so dead-letter it now rather than block the FIFO lane
                        # forever (still replayable from the DLQ). AE/CE (transient) → retry per
                        # policy, like a transport failure.
                        if exc.permanent:
                            await self.store.dead_letter_now(item.id, safe_exc(exc))
                        else:
                            await self.store.mark_failed(item.id, safe_exc(exc), retry)
                            await self._maybe_alert_buildup(name)
                    except DeliveryError as exc:
                        # Transport failure (connect/IO/timeout/unparseable ACK) — transient; retry
                        # per policy (retry-forever by default, so nothing is silently lost).
                        await self.store.mark_failed(item.id, safe_exc(exc), retry)
                        await self._maybe_alert_buildup(name)
                    except Exception as exc:
                        # Internal/code error (our bug, not the partner). The per-connection policy
                        # decides: STOP halts the lane (preserve the message, alert an operator) while
                        # CONTINUE (default) dead-letters this row and advances so a code bug can't
                        # wedge the lane forever. Log the exception TYPE only — the full detail goes to
                        # the secured store's last_error, never the general log (PHI).
                        if (
                            self._internal_error.get(name, self._internal_error_default)
                            is InternalErrorPolicy.STOP
                        ):
                            log.error(
                                "delivery worker %r: internal error delivering %s (%s); STOPPING "
                                "connection (operator must fix + reload/restart to resume)",
                                name,
                                item.id,
                                type(exc).__name__,
                            )
                            # Preserve the message for replay (reschedule, don't dead-letter) and halt
                            # this worker. A normal return is not respawned (_on_worker_done); a later
                            # reload re-spawns the worker, re-arming the lane.
                            await self.store.mark_failed(
                                item.id,
                                f"internal error (connection stopped): {safe_exc(exc)}",
                                retry,
                            )
                            self._alert_sink.connection_stopped(
                                name, detail=f"{type(exc).__name__} delivering {item.id}"
                            )
                            return
                        log.warning(
                            "delivery worker %r: internal error delivering %s (%s); dead-lettering",
                            name,
                            item.id,
                            type(exc).__name__,
                        )
                        await self.store.dead_letter_now(
                            item.id, f"internal error: {safe_exc(exc)}"
                        )
                    else:
                        # ADR 0013: a capturing outbound returns a DeliveryResponse; persist the reply
                        # AND mark the row done in ONE transaction (exactly-once capture). A non-capturing
                        # outbound returns None → plain mark_done, byte-identical. The XOR (never both)
                        # is the single-writer discipline that yields exactly one captured reply per row.
                        if response is not None:
                            # ADR 0013 Increment 2: if this outbound declares reingress_to, the same
                            # capture transaction also produces a Stage.RESPONSE work-row; wake the
                            # re-ingress worker. Read live from the registry (a reload swaps it).
                            oc = self.registry.outbound.get(name)
                            reingress_to = (
                                oc.spec.settings.get("reingress_to") if oc is not None else None
                            )
                            await self.store.complete_with_response(
                                item.id,
                                body=response.body,
                                outcome=response.outcome,
                                detail=response.detail,
                                reingress_to=reingress_to,
                            )
                            if reingress_to is not None:
                                self._response_work.set()  # wake the re-ingress worker for the new token
                        else:
                            await self.store.mark_done(item.id)
            except asyncio.CancelledError:
                raise
            except Exception:
                # A store error in the loop itself (claim_ready / mark_* failing — DB locked, disk
                # full) must never kill the worker: that would silently stop THIS destination from
                # draining while inbound keeps ACKing (review H-1). Log, back off, and keep going.
                log.exception(
                    "delivery worker %r: unexpected error; backing off and retrying", name
                )
                if await self._stop_or_sleep(_WORKER_ERROR_BACKOFF_SECONDS):
                    return

    async def _router_worker(self, name: str) -> None:
        """Drain the **ingress** stage for one inbound — the router half of the split pipeline (ADR
        0001 Step B).

        Strict FIFO per inbound (preserving arrival order into routing): claim the oldest ingress row,
        run its Router (``route_only``), and hand the selected handlers to the **routed** stage
        (``route_handoff``) — one routed row per handler. It runs no transform. A Router failure no
        longer NAKs the sender (already ACKed at ingress) — under the global ``internal_error`` policy
        it dead-letters the ingress row (``CONTINUE`` → message ``ERROR``, advance) or halts this lane
        preserving the row (``STOP`` → ``connection_stopped`` alert, return). Shares the delivery
        worker's wait/backoff supervision.
        """
        last_buildup_check = 0.0
        while not self._stop.is_set():
            try:
                # FIFO per inbound: claim only the due head (ingress rows never back off, so this is
                # effectively the oldest pending row for this inbound). Under active-passive HA the graph
                # runs on the leader ONLY, so a single node drains this lane.
                item = await self.store.claim_next_fifo(name, stage=Stage.INGRESS.value)
                if item is None:
                    await self._wait_for_work(self._ingress_work)
                    continue
                ic = self.registry.inbound.get(name)
                if ic is None:
                    # The inbound was removed from the registry but residual ingress rows remain.
                    # Revert this just-claimed row to pending and EXIT the worker — there is nothing to
                    # route it with until a reload restores the inbound (which re-arms this worker and
                    # drains the backlog). Reschedule with a retry-FOREVER policy (NOT the outbound
                    # delivery defaults, whose finite max_attempts would dead-letter an ACKed-but-
                    # never-attempted message purely for being removed) so the message is never dropped.
                    await self.store.mark_failed(item.id, "inbound not in registry", RetryPolicy())
                    return
                try:
                    # Publish the live graph's run-scoped views (code sets / reference snapshots /
                    # active environment) so a call-time code_set(...)/reference(...)/current_environment()
                    # inside the Router resolves (the loader only had them active during import). Views
                    # are read from self.registry/self.store live, so a reload's swapped tables apply to
                    # the next routed row; run_contexts restores cleanly after each run (no leak). The
                    # set of providers is the run_context registry (router phase) — features add one
                    # provider there, never edit this call site.
                    with run_contexts(
                        RunContext(
                            code_sets=self.registry.code_sets,
                            reference_view=self.store.reference_view(),
                            active_environment=self._active_environment,
                            ingest_time=item.created_at,
                        ),
                        phase="router",
                    ):
                        names = route_only(self.registry, ic, item.payload)
                except Exception as exc:
                    # Router code error (incl. an unknown handler name). Post-ACK, so no NAK — the
                    # global internal_error policy decides. Log the exception TYPE only; full detail
                    # goes to the secured store's last_error, never the general log (PHI).
                    if self._internal_error_default is InternalErrorPolicy.STOP:
                        log.error(
                            "router worker %r: router error on %s (%s); STOPPING ingest processing "
                            "(operator must fix + reload to resume)",
                            name,
                            item.id,
                            type(exc).__name__,
                        )
                        await self.store.mark_failed(
                            item.id,
                            f"router error (ingest stopped): {safe_exc(exc)}",
                            self._delivery_defaults,
                        )
                        self._alert_sink.connection_stopped(
                            name, detail=f"router {type(exc).__name__} on {item.id}"
                        )
                        return
                    log.warning(
                        "router worker %r: router error on %s (%s); dead-lettering",
                        name,
                        item.id,
                        type(exc).__name__,
                    )
                    await self.store.dead_letter_now(item.id, f"router error: {safe_exc(exc)}")
                    continue
                disposition = MessageStatus.ROUTED if names else MessageStatus.UNROUTED
                await self.store.route_handoff(
                    ingress_id=item.id,
                    message_id=item.message_id,
                    channel_id=name,
                    handlers=[(h, item.payload) for h in names],
                    disposition=disposition,
                )
                if names:
                    self._routed_work.set()  # wake the transform worker for the new routed rows
                # Off the hot path (rate-limited): alert if this inbound's ingress backlog is building
                # (a slow/hung router). Uses the global buildup threshold (no per-inbound override yet).
                now = time.time()
                if now - last_buildup_check >= _BUILDUP_CHECK_INTERVAL:
                    last_buildup_check = now
                    await self._maybe_alert_buildup(
                        name, stage=Stage.INGRESS.value, threshold=self._buildup_default
                    )
            except asyncio.CancelledError:
                raise
            except Exception:
                # A store error in the loop itself (claim/handoff failing — DB locked, disk full) must
                # never kill the worker: that would stall routing while the listener keeps ACKing. Log,
                # back off, and keep going (mirrors the delivery worker).
                log.exception("router worker %r: unexpected error; backing off and retrying", name)
                if await self._stop_or_sleep(_WORKER_ERROR_BACKOFF_SECONDS):
                    return

    async def _response_worker(self, name: str) -> None:
        """Drain the **response** stage for one LOOPBACK inbound — re-ingress a captured reply as a new
        inbound message (ADR 0013 Increment 2). Strict FIFO per loopback lane: claim the oldest
        ``Stage.RESPONSE`` token, peek the reply body for the loopback's ``content_type``, and hand it
        off **atomically** via :meth:`~messagefoundry.store.base.QueueStore.ingress_handoff` (which
        produces the re-ingressed message + ingress row, depth-caps it, or errors a non-peekable body).
        Mirrors :meth:`_router_worker`'s claim / missing-inbound / backoff supervision. Re-ingress is an
        internal stage with no source of its own (``LoopbackSource`` is inert); under active-passive HA
        the whole graph (and thus this worker) runs on the leader ONLY, so a single node drains it."""
        while not self._stop.is_set():
            try:
                item = await self.store.claim_next_fifo(name, stage=Stage.RESPONSE.value)
                if item is None:
                    await self._wait_for_work(self._response_work)
                    continue
                ic = self.registry.inbound.get(name)
                if ic is None:
                    # The loopback was removed by a reload but residual tokens remain. Revert the claim
                    # (retry-FOREVER, never dropped) and EXIT; a reload restoring the loopback re-arms
                    # this worker and drains the backlog — mirrors the router worker's missing-inbound exit.
                    await self.store.mark_failed(item.id, "inbound not in registry", RetryPolicy())
                    return
                # Peek the reply body for the loopback's content_type (in pipeline/, not the store), then
                # hand off in one atomic transaction. response_body_for_work_row reads the same immutable
                # artifact ingress_handoff re-reads for the message raw, so peek and raw always agree.
                body = await self.store.response_body_for_work_row(item.id)
                control_id, message_type, summary, peek_failed = _peek_for_loopback(ic, body or "")
                produced = await self.store.ingress_handoff(
                    response_row_id=item.id,
                    loopback_channel_id=name,
                    correlation_depth_cap=self._max_correlation_depth,
                    control_id=control_id,
                    message_type=message_type,
                    summary=summary,
                    peek_failed=peek_failed,
                )
                if produced:
                    # Wake the loopback's router worker to route the freshly-ingressed answer (a no-op
                    # wake for a depth-capped / peek-failed token that produced no ingress row).
                    self._ingress_work.set()
            except asyncio.CancelledError:
                raise
            except Exception:
                # A store error in the loop itself (claim/handoff failing) must never kill the worker —
                # log, back off, keep going (mirrors the router/delivery workers).
                log.exception(
                    "response worker %r: unexpected error; backing off and retrying", name
                )
                if await self._stop_or_sleep(_WORKER_ERROR_BACKOFF_SECONDS):
                    return

    async def _transform_worker(self, name: str) -> None:
        """Drain the **routed** stage for one inbound — the transform half of the split pipeline (ADR
        0001 Step B).

        Strict FIFO per inbound (preserving order into transform): claim the oldest routed row, run its
        **single** handler's transform (``transform_one``), and hand the resulting deliveries to the
        **outbound** stage (``transform_handoff``). A slow/failing transform here can no longer block
        routing — the router worker keeps producing routed rows independently. A transform failure is
        post-ACK (no NAK): under the global ``internal_error`` policy it dead-letters the routed row
        (``CONTINUE`` → message ``ERROR``, advance) or halts this lane (``STOP`` → ``connection_stopped``
        alert, return). A handler removed since routing (a racing reload) is dead-lettered too —
        recoverable via per-message replay once restored, matching the missing-outbound path.
        """
        last_buildup_check = 0.0
        while not self._stop.is_set():
            try:
                # FIFO per inbound at the routed stage. Under active-passive HA the graph runs on the
                # leader ONLY, so a single node drains this lane.
                item = await self.store.claim_next_fifo(name, stage=Stage.ROUTED.value)
                if item is None:
                    await self._wait_for_work(self._routed_work)
                    continue
                ic = self.registry.inbound.get(name)
                if ic is None:
                    # Inbound removed; nothing to transform with until a reload restores it (which
                    # re-arms this worker). Revert the row (retry-forever) and exit (mirrors the router
                    # worker), so the ACKed-but-unprocessed message is never dropped.
                    await self.store.mark_failed(item.id, "inbound not in registry", RetryPolicy())
                    return
                hname = item.handler_name
                if hname is None or hname not in self.registry.handlers:
                    # Handler gone (removed/renamed since routing). Can't transform this row; dead-letter
                    # it (message ERROR, replayable once restored) — the per-row analogue of the startup
                    # dead_letter_missing_handlers sweep. Dead-lettering (vs reverting) avoids a hot-loop
                    # on a permanently-missing handler and gives the operator visibility.
                    log.warning(
                        "transform worker %r: handler %r for %s is missing; dead-lettering",
                        name,
                        hname,
                        item.id,
                    )
                    await self.store.dead_letter_now(
                        item.id, f"handler {hname!r} removed from registry"
                    )
                    continue
                # ADR 0013 Increment 2: for a RE-INGRESSED message (only ever on a loopback inbound),
                # feed the run-context `response` provider the ORIGIN request's captured replies so its
                # Handler can read them via response_get(dest). A normal message → None (byte-identical,
                # and the metadata read is skipped entirely for non-loopback inbounds).
                response_view: dict[str, Any] | None = None
                if ic.spec.type is ConnectorType.LOOPBACK:
                    msg = await self.store.get_message(item.message_id)
                    raw_meta = msg.get("metadata") if msg else None
                    meta = json.loads(raw_meta) if raw_meta else {}
                    corr = meta.get("correlation_id") if isinstance(meta, dict) else None
                    if corr:
                        # {destination_name: latest CapturedResponse}: correlate_response orders by
                        # (dest, response_seq), so the last per destination wins (the authoritative
                        # reply). Immutable committed rows → re-run-stable (ADR 0009).
                        response_view = {
                            c.destination_name: c for c in await self.store.correlate_response(corr)
                        }
                try:
                    # Same as the router worker, plus the transform-only providers: publish the run-scoped
                    # views so call-time code_set(...)/reference(...)/state_get(...)/current_environment()
                    # inside the Handler resolve; restored cleanly after the run. The transform phase adds
                    # the store's transform-state read-through cache view (ADR 0005) so state_get(...)
                    # resolves against committed writes. Providers come from the run_context registry
                    # (transform phase) — features add one provider, never edit this call site.
                    with run_contexts(
                        RunContext(
                            code_sets=self.registry.code_sets,
                            reference_view=self.store.reference_view(),
                            state_view=self.store.state_view(),
                            response_view=response_view,
                            active_environment=self._active_environment,
                            ingest_time=item.created_at,
                        ),
                        phase="transform",
                    ):
                        if self._lookup_executor is not None:
                            # The graph declares ≥1 DatabaseLookup, so a Handler may call db_lookup() — a
                            # LIVE, synchronous DB read (ADR 0010). A handler is synchronous and must not
                            # block the event loop, so run the transform OFF the loop in a worker thread.
                            # asyncio.to_thread copies THIS context into the thread — the run_contexts
                            # views AND the active lookup runner — so db_lookup()/code_set()/reference()/
                            # state_get()/current_environment() all resolve there, while the loop stays
                            # free to service the lookup's async query and every other connection. The
                            # runner bridges back onto the loop (run_coroutine_threadsafe). db_lookup is
                            # the deliberate re-run-stability exception (ADR 0009) and raises in dry-run.
                            with db_lookup_activated(self._run_lookup):
                                deliveries_preview, state_preview = await asyncio.to_thread(
                                    transform_one,
                                    self.registry,
                                    hname,
                                    item.payload,
                                    self.registry.inbound[name].content_type.value,
                                )
                        else:
                            # No DatabaseLookup declared → byte-identical to before: run inline on the loop.
                            deliveries_preview, state_preview = transform_one(
                                self.registry,
                                hname,
                                item.payload,
                                self.registry.inbound[name].content_type.value,
                            )
                except Exception as exc:
                    # Handler/transform code error (incl. an unknown outbound name). Post-ACK, so no
                    # NAK — the global internal_error policy decides. Log the exception TYPE only (PHI).
                    if self._internal_error_default is InternalErrorPolicy.STOP:
                        log.error(
                            "transform worker %r: handler error on %s (%s); STOPPING transform "
                            "processing (operator must fix + reload to resume)",
                            name,
                            item.id,
                            type(exc).__name__,
                        )
                        await self.store.mark_failed(
                            item.id,
                            f"handler error (transform stopped): {safe_exc(exc)}",
                            self._delivery_defaults,
                        )
                        self._alert_sink.connection_stopped(
                            name, detail=f"handler {type(exc).__name__} on {item.id}"
                        )
                        return
                    log.warning(
                        "transform worker %r: handler error on %s (%s); dead-lettering",
                        name,
                        item.id,
                        type(exc).__name__,
                    )
                    await self.store.dead_letter_now(item.id, f"handler error: {safe_exc(exc)}")
                    continue
                deliveries = [(d.to, d.payload) for d in deliveries_preview]
                state_ops = [(s.namespace, s.key, s.value) for s in state_preview]
                await self.store.transform_handoff(
                    routed_id=item.id,
                    message_id=item.message_id,
                    channel_id=name,
                    deliveries=deliveries,
                    state_ops=state_ops,
                )
                if deliveries:
                    self._work.set()  # wake the outbound delivery workers for the freshly-queued rows
                # Off the hot path (rate-limited): alert if this inbound's routed (transform) backlog is
                # building behind a slow/hung handler — reported separately from the ingress lane.
                now = time.time()
                if now - last_buildup_check >= _BUILDUP_CHECK_INTERVAL:
                    last_buildup_check = now
                    await self._maybe_alert_buildup(
                        name, stage=Stage.ROUTED.value, threshold=self._buildup_default
                    )
            except asyncio.CancelledError:
                raise
            except Exception:
                # A store error in the loop itself must never kill the worker (mirrors the others).
                log.exception(
                    "transform worker %r: unexpected error; backing off and retrying", name
                )
                if await self._stop_or_sleep(_WORKER_ERROR_BACKOFF_SECONDS):
                    return

    async def _maybe_alert_buildup(
        self,
        name: str,
        *,
        stage: str = Stage.OUTBOUND.value,
        threshold: BuildupThreshold | None = None,
    ) -> None:
        """Raise a ``queue_buildup`` alert if a lane has crossed its depth/age threshold.

        Used for both stages: an outbound lane that isn't draining (a retry-forever head; ``threshold``
        defaults to the connection's resolved one) and an ingress lane backing up behind a slow router
        (caller passes ``stage='ingress'`` + the global threshold). The single COUNT+MIN query is
        cheap and rate-paced by callers. The re-alert is throttled per (stage, connection)
        (``_BUILDUP_REALERT_SECONDS``) so an ongoing stall reminds the operator without spamming. A
        sink must never raise (contract), but we still guard so an alerting bug can't kill the worker."""
        threshold = threshold or self._buildup.get(name) or self._buildup_default
        if threshold.max_depth is None and threshold.max_oldest_seconds is None:
            return  # buildup alerting disabled for this lane
        key = f"{stage}:{name}"
        now = time.time()
        if now < self._next_buildup_alert.get(key, 0.0):
            return  # re-alert throttled
        depth, oldest_created = await self.store.pending_depth(name, stage=stage)
        if depth == 0:
            return
        oldest_age = (now - oldest_created) if oldest_created is not None else None
        crossed = (threshold.max_depth is not None and depth >= threshold.max_depth) or (
            threshold.max_oldest_seconds is not None
            and oldest_age is not None
            and oldest_age >= threshold.max_oldest_seconds
        )
        if not crossed:
            return
        self._next_buildup_alert[key] = now + _BUILDUP_REALERT_SECONDS
        try:
            self._alert_sink.queue_buildup(name, depth=depth, oldest_age_seconds=oldest_age or 0.0)
        except Exception:
            log.exception("alert sink raised on queue_buildup for %r", name)

    async def _wait_for_work(self, event: asyncio.Event) -> None:
        """Wait up to ``poll_interval`` for ``event`` (this worker class's wake event), then clear it.
        Per-class events mean a worker only clears its own signal, so one class can't swallow another's
        wakeup; ``poll_interval`` still backstops any missed set()."""
        try:
            await asyncio.wait_for(event.wait(), self.poll_interval)
        except asyncio.TimeoutError:
            pass
        finally:
            event.clear()

    async def _stop_or_sleep(self, delay: float) -> bool:
        """Sleep up to ``delay`` seconds; return True if a stop was requested meanwhile (so a
        backing-off worker exits promptly on shutdown instead of sleeping out the full delay)."""
        try:
            await asyncio.wait_for(self._stop.wait(), delay)
            return True
        except asyncio.TimeoutError:
            return False


def _source_config(ic: InboundConnection, bind_host: str, env_values: Mapping[str, Any]) -> Source:
    # Resolve any env() references first (a missing value raises WiringError here, before bind).
    settings = resolve_env_settings(ic.spec.settings, env_values)
    # Inbound MLLP/TCP/X12 listeners never carry an author-supplied host (wiring rejects one) — they
    # bind to the per-connection bind_address if set, else the service-level [inbound].bind_host. File
    # and other inbounds have no host and ignore this. A peer-IP allowlist rides into the connector's
    # settings so the listener can reject a non-allowlisted peer at accept time. (bind_address and the
    # allowlist are MLLP/TCP-only at wiring, so for X12 both fields are None here = unchanged behaviour.)
    if ic.spec.type in (
        ConnectorType.MLLP,
        ConnectorType.TCP,
        ConnectorType.X12,
        ConnectorType.DIMSE,
    ):
        settings["host"] = ic.bind_address or bind_host
        if ic.source_ip_allowlist:
            settings["source_ip_allowlist"] = list(ic.source_ip_allowlist)
    return Source(type=ic.spec.type, settings=settings, ack_mode=ic.ack_mode)


def _dest_config(oc: OutboundConnection, env_values: Mapping[str, Any]) -> Destination:
    # Resolve env() first so any signing key/password ref is materialized here, then assemble the
    # typed signing config (ASVS 4.1.5, ADR 0018) from the resolved sign_* settings. None = signing
    # off (every existing outbound unchanged). The connector loads the key + mints the signature; this
    # is the single choke point feeding start/check/dry-run, so a bad key fails loud at all three.
    settings = resolve_env_settings(oc.spec.settings, env_values)
    return Destination(
        name=oc.name,
        type=oc.spec.type,
        settings=settings,
        retry=oc.retry or RetryPolicy(),
        sign=OutboundSigning.from_settings(settings),
    )


def build_check_registry(
    registry: Registry,
    *,
    inbound_bind_host: str,
    env_values: Mapping[str, Any],
    egress: EgressSettings,
) -> None:
    """Construct (and discard) every connector in ``registry`` + run the fail-closed connect/egress
    allowlists, so a bad connector spec or a non-allowlisted host fails as a :class:`WiringError`
    BEFORE anything is applied. The standalone core of :meth:`RegistryRunner.build_check`, callable
    offline — e.g. the ``connection`` CLI validating an edit before it persists (ADR 0007). Builds
    nothing live (no socket bind / file I/O — binding happens later in ``start_inbound``)."""
    try:
        for ic in registry.inbound.values():
            source_cfg = _source_config(ic, inbound_bind_host, env_values)
            check_source_allowed(source_cfg, ic.name, egress)
            build_source(source_cfg)
        reingress_targets: set[str] = set()
        for oc in registry.outbound.values():
            dest = _dest_config(oc, env_values)
            check_egress_allowed(dest, egress)  # fail-closed egress allowlist (WP-11c)
            build_destination(dest)
            # ADR 0013 Increment 2: reingress_to must name an existing Loopback() inbound. This is a
            # CROSS-registry fact (build_outbound_connection is registry-blind), enforced here so it
            # fails at `check`/dry-run with no store, like every other connector validation.
            target = oc.spec.settings.get("reingress_to")
            if target is not None:
                tic = registry.inbound.get(str(target))
                if tic is None or tic.spec.type is not ConnectorType.LOOPBACK:
                    raise WiringError(
                        f"outbound connection {oc.name!r}: reingress_to names unknown/non-loopback "
                        f"inbound {target!r} — declare it as inbound(..., Loopback(), ...) (ADR 0013)."
                    )
                reingress_targets.add(str(target))
        # A loopback inbound with no capturing outbound pointing at it is legal but inert (never fed) —
        # surface it (it may be a staging artifact), but don't error.
        for iname, ic in registry.inbound.items():
            if ic.spec.type is ConnectorType.LOOPBACK and iname not in reingress_targets:
                log.warning(
                    "loopback inbound %r has no reingress_to source; it will never receive a message",
                    iname,
                )
        resolved_lookups: dict[str, dict[str, Any]] = {}
        for lname, lspec in registry.lookups.items():
            lsettings = resolve_env_settings(lspec.settings, env_values)
            check_lookup_allowed(lname, lsettings, egress)  # fail-closed connect allowlist
            resolved_lookups[lname] = lsettings
        if resolved_lookups:
            # Construct (and discard) the executor: validates each DSN (TLS/auth) without opening a pool.
            DatabaseLookupExecutor(resolved_lookups)
    except WiringError:
        raise
    except Exception as exc:
        raise WiringError(f"connector build failed: {exc}") from exc


def _allowlist_for(conn_type: ConnectorType, egress: EgressSettings) -> list[str]:
    """The ``[egress]`` allowlist that governs a connector type (X12 shares TCP's; REST/SOAP/FHIR share
    the HTTP list). Returns ``[]`` for a type with no egress list — which under ``deny_by_default`` means
    'nothing is configured to permit it', so the destination is refused."""
    if conn_type is ConnectorType.MLLP:
        return egress.allowed_mllp
    if conn_type in (ConnectorType.TCP, ConnectorType.X12, ConnectorType.DIMSE):
        return egress.allowed_tcp  # DIMSE is a raw socket (the Phase-2 C-STORE SCU dials it out)
    if conn_type is ConnectorType.FILE:
        return egress.allowed_file_dirs
    if conn_type in (
        ConnectorType.REST,
        ConnectorType.SOAP,
        ConnectorType.FHIR,
        ConnectorType.DICOMWEB,
    ):
        return egress.allowed_http  # DICOMWEB is STOW-RS over HTTP (gated like REST/SOAP/FHIR)
    if conn_type is ConnectorType.DATABASE:
        return egress.allowed_db
    if conn_type is ConnectorType.REMOTEFILE:
        return egress.allowed_remote
    return []


def check_source_allowed(source: Source, name: str, egress: EgressSettings) -> None:
    """Fail-closed connect-allowlist for an inbound connector that **dials out** to a server to receive
    (today: the DATABASE source, which polls a SQL host). Reuses ``[egress].allowed_db``: although the
    DB source pulls data *in* rather than exfiltrating it, it still opens an outbound connection to an
    operator-named host, so the same allowlist guards against pointing the engine at an arbitrary
    server. Opt-in (an empty list = unrestricted), matching destinations; checked at load/reload/start.

    A TCP/MLLP/File *source* is a local **listener** (it binds ``[inbound].bind_host`` and waits for
    peers, never dialing out), so there is nothing to connect-gate here — ``[egress].allowed_tcp``
    governs only the TCP *destination* (see :func:`check_egress_allowed`).

    Under ``[egress].deny_by_default`` a DATABASE/REMOTEFILE source whose allowlist is empty is refused
    outright; a listener source (TCP/MLLP/File) never dials out, so it is unaffected."""
    if egress.deny_by_default:
        if source.type is ConnectorType.DATABASE and not egress.allowed_db:
            raise WiringError(
                f"inbound {name!r}: [egress].deny_by_default is set and [egress].allowed_db is empty "
                "— list the DATABASE server to permit it"
            )
        if source.type is ConnectorType.REMOTEFILE and not egress.allowed_remote:
            raise WiringError(
                f"inbound {name!r}: [egress].deny_by_default is set and [egress].allowed_remote is "
                "empty — list the REMOTEFILE host to permit it"
            )
    if source.type is ConnectorType.DATABASE and egress.allowed_db:
        host = str(source.settings.get("server", ""))
        port = source.settings.get("port", 1433)
        if not _mllp_egress_allowed(host, port, egress.allowed_db):  # same host[:port] matching
            log.warning(
                "connect denied: inbound %r DATABASE server %r not in [egress].allowed_db",
                name,
                host,
            )
            raise WiringError(
                f"inbound {name!r}: DATABASE server {host!r} is not in the "
                "[egress].allowed_db allowlist"
            )
    elif source.type is ConnectorType.REMOTEFILE and egress.allowed_remote:
        host = str(source.settings.get("host", ""))
        port = source.settings.get("port")
        if not _mllp_egress_allowed(host, port, egress.allowed_remote):  # same host[:port] matching
            log.warning(
                "connect denied: inbound %r REMOTEFILE host %r not in [egress].allowed_remote",
                name,
                host,
            )
            raise WiringError(
                f"inbound {name!r}: REMOTEFILE host {host!r} is not in the "
                "[egress].allowed_remote allowlist"
            )


def check_lookup_allowed(name: str, settings: Mapping[str, Any], egress: EgressSettings) -> None:
    """Fail-closed connect-allowlist for a ``DatabaseLookup`` (it dials out to a SQL host for a live,
    read-only ``db_lookup``). Reuses ``[egress].allowed_db`` (opt-in; an empty list = unrestricted), like
    the DATABASE source — checked at load/reload/start so the engine is never pointed at a non-allowlisted
    server. ``settings`` are the already-``env()``-resolved connection settings. Under
    ``[egress].deny_by_default`` an empty ``allowed_db`` refuses the lookup outright."""
    if egress.deny_by_default and not egress.allowed_db:
        raise WiringError(
            f"DatabaseLookup {name!r}: [egress].deny_by_default is set and [egress].allowed_db is "
            "empty — list the lookup server to permit it"
        )
    if egress.allowed_db:
        host = str(settings.get("server", ""))
        port = settings.get("port", 1433)
        if not _mllp_egress_allowed(host, port, egress.allowed_db):  # same host[:port] matching
            log.warning(
                "connect denied: DatabaseLookup %r server %r not in [egress].allowed_db", name, host
            )
            raise WiringError(
                f"DatabaseLookup {name!r}: server {host!r} is not in the [egress].allowed_db allowlist"
            )


_LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "::1", "::ffff:127.0.0.1"})


def check_mllp_tls_exposure(source: Source, name: str, *, allow_insecure_bind: bool) -> None:
    """Exposed-gate (ADR 0002 §0, MLLP side): refuse a **non-loopback MLLP listener without TLS** — it
    would put HL7 bodies on the wire in cleartext. Set ``tls=true`` (+ cert) on the connection, or pass
    ``serve --allow-insecure-bind`` to accept the risk on a trusted segment (then warn). Loopback binds
    and TLS-on binds pass unconditionally. MLLP only (raw-TCP/X12 TLS is out of ADR-0002 scope)."""
    if source.type is not ConnectorType.MLLP:
        return
    host = str(source.settings.get("host", "127.0.0.1"))
    if host in _LOOPBACK_HOSTS or source.settings.get("tls"):
        return
    if allow_insecure_bind:
        log.warning(
            "inbound %r binds non-loopback host %r without TLS (--allow-insecure-bind); HL7 bodies "
            "cross the network in cleartext — set tls=true (+ tls_cert_file/tls_key_file) on it.",
            name,
            host,
        )
        return
    raise WiringError(
        f"inbound connection {name!r} binds non-loopback host {host!r} without TLS; HL7 bodies would "
        "cross the network in cleartext. Set tls=true (+ tls_cert_file/tls_key_file) on the MLLP "
        "connection, or pass `serve --allow-insecure-bind` to accept the cleartext risk on a trusted, "
        "firewalled network."
    )


def check_dimse_tls_exposure(source: Source, name: str, *, allow_insecure_bind: bool) -> None:
    """Exposed-gate (ADR 0025 §9, DIMSE side): refuse a **non-loopback DICOM C-STORE SCP without TLS** —
    it would put DICOM header + pixel-data PHI on the wire in cleartext. The DIMSE sibling of
    :func:`check_mllp_tls_exposure` (the shipped guard is MLLP-only; TCP/X12/DIMSE listeners were not
    covered, so this is **net-new** security work, not a fold-in). Set ``tls=true`` (+ cert) on the
    ``DICOM(...)`` connection, or pass ``serve --allow-insecure-bind`` to accept the risk on a trusted
    segment (then warn). Loopback binds and TLS-on binds pass unconditionally."""
    if source.type is not ConnectorType.DIMSE:
        return
    host = str(source.settings.get("host", "127.0.0.1"))
    if host in _LOOPBACK_HOSTS or source.settings.get("tls"):
        return
    if allow_insecure_bind:
        log.warning(
            "inbound %r binds non-loopback host %r without DICOM-over-TLS (--allow-insecure-bind); "
            "DICOM PHI (header + pixel data) crosses the network in cleartext — set tls=true "
            "(+ tls_cert_file/tls_key_file) on the DICOM connection.",
            name,
            host,
        )
        return
    raise WiringError(
        f"inbound connection {name!r} binds non-loopback host {host!r} without TLS; DICOM PHI (header "
        "+ pixel data) would cross the network in cleartext. Set tls=true (+ tls_cert_file/"
        "tls_key_file) on the DICOM connection, or pass `serve --allow-insecure-bind` to accept the "
        "cleartext risk on a trusted, firewalled network."
    )


def check_egress_allowed(dest: Destination, egress: EgressSettings) -> None:
    """Fail-closed: refuse (raise :class:`WiringError`) an outbound destination not on the ``[egress]``
    allowlist (WP-11c — ASVS 13.2.4/13.2.5/14.2.3), so a fat-fingered or hostile destination can't
    exfiltrate PHI. Opt-in per transport (an empty list = unrestricted), checked against the resolved
    (``env()``-substituted) destination at config load/reload/start. Webhook/SMTP alert sinks carry no
    PHI bodies and keep their own ``[alerts]`` host allowlists.

    Under ``[egress].deny_by_default`` a destination whose transport has no allowlist is refused
    outright (fail-closed); with the list set, the per-list matching below is unchanged."""
    if egress.deny_by_default and not _allowlist_for(dest.type, egress):
        log.warning(
            "egress denied: outbound %r %s has no [egress] allowlist under deny_by_default",
            dest.name,
            dest.type.value,
        )
        raise WiringError(
            f"outbound {dest.name!r}: [egress].deny_by_default is set and no allowlist permits a "
            f"{dest.type.value} destination — add it to the matching [egress].allowed_* list"
        )
    if dest.type is ConnectorType.MLLP and egress.allowed_mllp:
        host = str(dest.settings.get("host", "127.0.0.1"))
        port = dest.settings.get("port")
        if not _mllp_egress_allowed(host, port, egress.allowed_mllp):
            log.warning(
                "egress denied: outbound %r MLLP %s:%s not in [egress].allowed_mllp",
                dest.name,
                host,
                port,
            )
            raise WiringError(
                f"outbound {dest.name!r}: MLLP destination {host}:{port} is not in the "
                "[egress].allowed_mllp allowlist"
            )
    elif dest.type is ConnectorType.TCP and egress.allowed_tcp:
        host = str(dest.settings.get("host", "127.0.0.1"))
        port = dest.settings.get("port")
        if not _mllp_egress_allowed(host, port, egress.allowed_tcp):  # same host[:port] matching
            log.warning(
                "egress denied: outbound %r TCP %s:%s not in [egress].allowed_tcp",
                dest.name,
                host,
                port,
            )
            raise WiringError(
                f"outbound {dest.name!r}: TCP destination {host}:{port} is not in the "
                "[egress].allowed_tcp allowlist"
            )
    elif dest.type is ConnectorType.X12 and egress.allowed_tcp:
        # X12 is raw TCP, so it shares the [egress].allowed_tcp allowlist (same host[:port] matching).
        host = str(dest.settings.get("host", "127.0.0.1"))
        port = dest.settings.get("port")
        if not _mllp_egress_allowed(host, port, egress.allowed_tcp):
            log.warning(
                "egress denied: outbound %r X12 %s:%s not in [egress].allowed_tcp",
                dest.name,
                host,
                port,
            )
            raise WiringError(
                f"outbound {dest.name!r}: X12 destination {host}:{port} is not in the "
                "[egress].allowed_tcp allowlist"
            )
    elif dest.type is ConnectorType.DIMSE and egress.allowed_tcp:
        # DIMSE (the Phase-2 C-STORE SCU destination) dials a raw socket, so it shares the
        # [egress].allowed_tcp allowlist (same host[:port] matching as X12). Gated now so a future SCU
        # destination is never fail-open (ADR 0025 §6.4).
        host = str(dest.settings.get("host", "127.0.0.1"))
        port = dest.settings.get("port")
        if not _mllp_egress_allowed(host, port, egress.allowed_tcp):
            log.warning(
                "egress denied: outbound %r DIMSE %s:%s not in [egress].allowed_tcp",
                dest.name,
                host,
                port,
            )
            raise WiringError(
                f"outbound {dest.name!r}: DIMSE destination {host}:{port} is not in the "
                "[egress].allowed_tcp allowlist"
            )
    elif dest.type is ConnectorType.FILE and egress.allowed_file_dirs:
        directory = dest.settings.get("directory")
        if directory is None or not _dir_egress_allowed(str(directory), egress.allowed_file_dirs):
            log.warning(
                "egress denied: outbound %r File dir %r not under [egress].allowed_file_dirs",
                dest.name,
                directory,
            )
            raise WiringError(
                f"outbound {dest.name!r}: File directory {directory!r} is not under any "
                "[egress].allowed_file_dirs entry"
            )
    elif (
        dest.type
        in (
            ConnectorType.REST,
            ConnectorType.SOAP,
            ConnectorType.FHIR,
            ConnectorType.DICOMWEB,
        )
        and egress.allowed_http
    ):
        # DICOMWEB (STOW-RS) folds into the HTTP host-check branch: it stores its endpoint under "url"
        # (the same key Rest()/FHIR() use), so the host gate reads it unchanged (ADR 0025 §6.4).
        url = str(dest.settings.get("url", ""))
        if not _http_egress_allowed(url, egress.allowed_http):
            host = urllib.parse.urlsplit(url).hostname or ""
            log.warning(
                "egress denied: outbound %r %s host %r not in [egress].allowed_http",
                dest.name,
                dest.type.value,
                host,
            )
            raise WiringError(
                f"outbound {dest.name!r}: {dest.type.value} host {host!r} is not in the "
                "[egress].allowed_http allowlist"
            )
        # ADR 0024: the SMART Backend Services token endpoint is a SECOND egress host — the connector
        # POSTs the signed client_assertion there — so gate it too. Left ungated, a crafted
        # smart_token_url would exfiltrate the assertion to an unlisted host (a fail-open hole). Only
        # REST/FHIR carry it; an unset value is a no-op.
        token_url = str(dest.settings.get("smart_token_url", ""))
        if token_url and not _http_egress_allowed(token_url, egress.allowed_http):
            host = urllib.parse.urlsplit(token_url).hostname or ""
            log.warning(
                "egress denied: outbound %r SMART token endpoint host %r not in [egress].allowed_http",
                dest.name,
                host,
            )
            raise WiringError(
                f"outbound {dest.name!r}: SMART token endpoint host {host!r} is not in the "
                "[egress].allowed_http allowlist"
            )
    elif dest.type is ConnectorType.DATABASE and egress.allowed_db:
        host = str(dest.settings.get("server", ""))
        port = dest.settings.get("port", 1433)
        if not _mllp_egress_allowed(host, port, egress.allowed_db):  # same host[:port] matching
            log.warning(
                "egress denied: outbound %r DATABASE server %r not in [egress].allowed_db",
                dest.name,
                host,
            )
            raise WiringError(
                f"outbound {dest.name!r}: DATABASE server {host!r} is not in the "
                "[egress].allowed_db allowlist"
            )
    elif dest.type is ConnectorType.REMOTEFILE and egress.allowed_remote:
        host = str(dest.settings.get("host", ""))
        port = dest.settings.get("port")
        if not _mllp_egress_allowed(host, port, egress.allowed_remote):  # same host[:port] matching
            log.warning(
                "egress denied: outbound %r REMOTEFILE host %r not in [egress].allowed_remote",
                dest.name,
                host,
            )
            raise WiringError(
                f"outbound {dest.name!r}: REMOTEFILE host {host!r} is not in the "
                "[egress].allowed_remote allowlist"
            )


def _mllp_egress_allowed(host: str, port: object, allowed: list[str]) -> bool:
    host = host.lower()
    for entry in allowed:
        allow_host, _, allow_port = entry.partition(":")
        if allow_host.strip().lower() == host and (
            not allow_port or str(port) == allow_port.strip()
        ):
            return True
    return False


def _dir_egress_allowed(directory: str, allowed: list[str]) -> bool:
    try:
        target = Path(directory).resolve()
    except (OSError, ValueError, RuntimeError):
        return False
    for entry in allowed:
        try:
            base = Path(entry).resolve()
        except (OSError, ValueError, RuntimeError):
            continue
        if target == base or base in target.parents:
            return True
    return False


def _http_egress_allowed(url: str, allowed: list[str]) -> bool:
    """True if ``url``'s host (and port, when an allow entry pins one) is on the allowlist — the same
    ``host`` / ``host:port`` matching as MLLP."""
    parts = urllib.parse.urlsplit(url)
    host = (parts.hostname or "").lower()
    for entry in allowed:
        allow_host, _, allow_port = entry.partition(":")
        if allow_host.strip().lower() == host and (
            not allow_port or str(parts.port) == allow_port.strip()
        ):
            return True
    return False
