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
    RetryPolicy,
    Source,
)
from messagefoundry.config.active_environment import activated as environment_activated
from messagefoundry.config.code_sets import activated as code_sets_activated
from messagefoundry.config.reference import activated as reference_activated
from messagefoundry.config.state import activated as state_activated
from messagefoundry.config.settings import EgressSettings
from messagefoundry.config.wiring import (
    InboundConnection,
    OutboundConnection,
    Registry,
    WiringError,
    resolve_env_settings,
)
from messagefoundry.parsing import HL7PeekError, Peek, normalize, summarize, validate
from messagefoundry.pipeline.alerts import AlertSink, LoggingAlertSink
from messagefoundry.pipeline.cluster import ClusterCoordinator, NullCoordinator
from messagefoundry.redaction import safe_exc
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
        delivery_defaults: RetryPolicy | None = None,
        ordering_default: OrderingMode | None = None,
        internal_error_default: InternalErrorPolicy | None = None,
        buildup_default: BuildupThreshold | None = None,
        ack_after_default: AckAfter | None = None,
        alert_sink: AlertSink | None = None,
        egress: EgressSettings | None = None,
        env_values: Mapping[str, Any] | None = None,
        active_environment: str | None = None,
        coordinator: ClusterCoordinator | None = None,
    ) -> None:
        self.registry = registry
        self.store = store
        # Cluster coordination seam (Track B Step 3). Threaded in + held so Steps 4/5 can consult the
        # cheap, synchronous gates (is_leader / owns_lane) on the hot path — this step adds NO call
        # sites; the object is only stored + exposed. None → the no-op NullCoordinator (every gate
        # True), so single-node operation is byte-identical to before this seam existed.
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
        # The interface inbound listeners bind to (service-level; authors never set a host). Loopback
        # by default — see config.settings.InboundSettings.bind_host.
        self._inbound_bind_host = inbound_bind_host
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
        # connector + retry are re-resolved per item from these maps, so a reload can swap an
        # outbound's settings under a running worker without tearing the worker down.
        self._retry: dict[str, RetryPolicy] = {}
        self._ordering: dict[str, OrderingMode] = {}
        self._internal_error: dict[str, InternalErrorPolicy] = {}
        self._buildup: dict[str, BuildupThreshold] = {}
        # Per-connection re-alert throttle: the earliest time a queue_buildup alert may fire again.
        self._next_buildup_alert: dict[str, float] = {}
        self._stop = asyncio.Event()
        # Per-stage wake events so a producer wakes only its own downstream consumer class. A single
        # shared auto-clearing event would let an idle worker of one class swallow another class's
        # wakeup (lost wakeup) — masked by poll_interval but defeating the prompt set(). Listener →
        # router (_ingress_work); router → transform (_routed_work); transform / replay → delivery
        # (_work). Each worker class waits on (and clears) only its own event.
        self._ingress_work = asyncio.Event()
        self._routed_work = asyncio.Event()
        self._work = asyncio.Event()
        self._running = False
        self._reload_lock = asyncio.Lock()  # serialize concurrent reloads

    @property
    def running(self) -> bool:
        return self._running

    @property
    def coordinator(self) -> ClusterCoordinator:
        """The cluster coordinator threaded in by the engine (Track B Step 3). Steps 4/5 consume its
        cheap, synchronous gates (``is_leader`` / ``owns_lane``); this step only exposes the object."""
        return self._coordinator

    def notify_work(self) -> None:
        """Wake every stage worker now (e.g. after a replay re-queues rows at an unknown stage)."""
        self._ingress_work.set()
        self._routed_work.set()
        self._work.set()

    def set_env_values(self, values: Mapping[str, Any]) -> None:
        """Replace the environment values used to resolve ``env()`` refs when (re)building connectors.
        The engine calls this on reload so a promote picks up edited values without a restart (M-23)."""
        self._env_values = dict(values)

    # --- per-connection control (console operations) -------------------------

    def inbound_running(self, name: str) -> bool:
        return name in self._sources

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

    async def start(self) -> None:
        async with self._reload_lock:
            if self._running:
                return
            self._stop.clear()
            try:
                for name, oc in self.registry.outbound.items():
                    dest = _dest_config(oc, self._env_values)
                    check_egress_allowed(
                        dest, self._egress
                    )  # fail-closed egress allowlist (WP-11c)
                    self._destinations[name] = build_destination(dest)
                    self._retry[name] = oc.retry or self._delivery_defaults
                    self._ordering[name] = oc.ordering or self._ordering_default
                    self._internal_error[name] = oc.internal_error or self._internal_error_default
                    self._buildup[name] = oc.buildup or self._buildup_default
                    self._spawn_worker(name)
                for ic in self.registry.inbound.values():
                    await self._start_inbound_unsafe(ic.name)
                # A router + transform worker per inbound — spawned after the sources bind, so a bind
                # failure above unwinds before any inbound worker exists. They drain ingress→routed→
                # outbound, independently of the source's listen state.
                for name in self.registry.inbound:
                    self._ensure_inbound_workers(name)
            except Exception:
                # A partial start (typically an inbound bind failure) must not leave half the graph
                # wired with _running still False — unwind everything we started so the listeners are
                # released and a retry can rebind the same ports (review M-8).
                log.exception("wiring start failed; unwinding the partial start")
                await self._teardown_unsafe()
                raise
            self._running = True
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
        self._work.set()
        for source in self._sources.values():
            await source.stop()
        inbound_tasks = (*self._router_workers.values(), *self._transform_workers.values())
        for task in (*self._workers.values(), *inbound_tasks):
            task.cancel()
        await asyncio.gather(*self._workers.values(), *inbound_tasks, return_exceptions=True)
        for connector in self._destinations.values():
            await connector.aclose()
        self._workers.clear()
        self._router_workers.clear()
        self._transform_workers.clear()
        self._destinations.clear()
        self._retry.clear()
        self._internal_error.clear()
        self._buildup.clear()
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
        """The coroutine factory for an inbound worker ``kind`` (``"router"`` | ``"transform"``)."""
        return self._router_worker if kind == "router" else self._transform_worker

    def _inbound_worker_dict(self, kind: str) -> dict[str, asyncio.Task[None]]:
        return self._router_workers if kind == "router" else self._transform_workers

    def _ensure_inbound_workers(self, name: str) -> None:
        """Ensure both the router and transform worker for one inbound are running, spawning any that
        exited (a STOP-policy halt, a reload adding the inbound, or a crash). Idempotent — the shared
        re-arm used by start(), start_inbound(), and reload()."""
        for kind in ("router", "transform"):
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
            worker = self._workers.get(name)
            if worker is None or worker.done():
                # added (or replacing a crashed worker): close any stale connector, build + spawn.
                stale = self._destinations.pop(name, None)
                if stale is not None:
                    await stale.aclose()
                self._destinations[name] = build_destination(_dest_config(oc, self._env_values))
                self._spawn_worker(name)
            elif old.outbound.get(name) is None or old.outbound[name].spec != oc.spec:
                # live worker, connector type/settings changed → swap in place, close the old one.
                old_conn = self._destinations.get(name)
                self._destinations[name] = build_destination(_dest_config(oc, self._env_values))
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
                detail = "; ".join(result.errors)[:200]
                await self._record(ic, peek, text, MessageStatus.ERROR, error=detail)
                return build_ack(peek, code="AE", text=detail, ack_mode=ack_mode) if reply else None

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
                    # lane_owner() gates the claim to a single owner per lane (Track B Step 5) so strict
                    # FIFO holds ACROSS nodes; it's None single-node (byte-identical no-owner claim).
                    head = await self.store.claim_next_fifo(
                        name, owner=self._coordinator.lane_owner()
                    )
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
                        # No connector for a claimed row (extremely unlikely mid-reconcile).
                        # Reschedule it rather than strand the claimed row, then move on.
                        await self.store.mark_failed(item.id, "outbound reloading", retry)
                        continue
                    try:
                        await connector.send(item.payload)
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
                # effectively the oldest pending row for this inbound). lane_owner() gates the claim to a
                # single owner per lane (Track B Step 5) so strict FIFO holds across nodes; None
                # single-node (byte-identical).
                item = await self.store.claim_next_fifo(
                    name, stage=Stage.INGRESS.value, owner=self._coordinator.lane_owner()
                )
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
                    # Publish the live graph's code sets so a call-time code_set(...) inside the
                    # Router resolves (the loader only had them active during import). The active set
                    # is read from self.registry live, so a reload's swapped tables apply to the next
                    # routed row; activated() restores cleanly after each run (no leak across rows).
                    with (
                        code_sets_activated(self.registry.code_sets),
                        reference_activated(self.store.reference_view()),
                        environment_activated(self._active_environment),
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
                # lane_owner() gates the claim to a single owner per lane (Track B Step 5) so strict
                # FIFO holds across nodes; None single-node (byte-identical no-owner claim).
                item = await self.store.claim_next_fifo(
                    name, stage=Stage.ROUTED.value, owner=self._coordinator.lane_owner()
                )
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
                try:
                    # Same as the router worker: make the live graph's code sets active so a call-time
                    # code_set(...) inside the Handler resolves; restored cleanly after the run. Also
                    # publish the store's transform-state read-through cache view (ADR 0005) so a
                    # call-time state_get(...) inside the Handler resolves against committed writes.
                    with (
                        code_sets_activated(self.registry.code_sets),
                        reference_activated(self.store.reference_view()),
                        state_activated(self.store.state_view()),
                        environment_activated(self._active_environment),
                    ):
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
    # Inbound MLLP/TCP listeners never carry an author-supplied host (wiring rejects one) — they bind
    # to the service-level interface. File and other inbounds have no host and ignore this.
    if ic.spec.type in (ConnectorType.MLLP, ConnectorType.TCP):
        settings["host"] = bind_host
    return Source(type=ic.spec.type, settings=settings, ack_mode=ic.ack_mode)


def _dest_config(oc: OutboundConnection, env_values: Mapping[str, Any]) -> Destination:
    return Destination(
        name=oc.name,
        type=oc.spec.type,
        settings=resolve_env_settings(oc.spec.settings, env_values),
        retry=oc.retry or RetryPolicy(),
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
        for oc in registry.outbound.values():
            dest = _dest_config(oc, env_values)
            check_egress_allowed(dest, egress)  # fail-closed egress allowlist (WP-11c)
            build_destination(dest)
    except WiringError:
        raise
    except Exception as exc:
        raise WiringError(f"connector build failed: {exc}") from exc


def check_source_allowed(source: Source, name: str, egress: EgressSettings) -> None:
    """Fail-closed connect-allowlist for an inbound connector that **dials out** to a server to receive
    (today: the DATABASE source, which polls a SQL host). Reuses ``[egress].allowed_db``: although the
    DB source pulls data *in* rather than exfiltrating it, it still opens an outbound connection to an
    operator-named host, so the same allowlist guards against pointing the engine at an arbitrary
    server. Opt-in (an empty list = unrestricted), matching destinations; checked at load/reload/start.

    A TCP/MLLP/File *source* is a local **listener** (it binds ``[inbound].bind_host`` and waits for
    peers, never dialing out), so there is nothing to connect-gate here — ``[egress].allowed_tcp``
    governs only the TCP *destination* (see :func:`check_egress_allowed`)."""
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


def check_egress_allowed(dest: Destination, egress: EgressSettings) -> None:
    """Fail-closed: refuse (raise :class:`WiringError`) an outbound destination not on the ``[egress]``
    allowlist (WP-11c — ASVS 13.2.4/13.2.5/14.2.3), so a fat-fingered or hostile destination can't
    exfiltrate PHI. Opt-in per transport (an empty list = unrestricted), checked against the resolved
    (``env()``-substituted) destination at config load/reload/start. Webhook/SMTP alert sinks carry no
    PHI bodies and keep their own ``[alerts]`` host allowlists."""
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
    elif dest.type in (ConnectorType.REST, ConnectorType.SOAP) and egress.allowed_http:
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
