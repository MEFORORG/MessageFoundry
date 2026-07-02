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
import errno
import functools
import json
import logging
import time
import urllib.parse
from collections.abc import Mapping, Sequence
from contextlib import ExitStack
from dataclasses import dataclass
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
    Priority,
    RetryPolicy,
    Source,
    StallThreshold,
)
from messagefoundry.config.db_lookup import DbLookupError, activated as db_lookup_activated
from messagefoundry.config.fhir_lookup import (
    FhirLookupError,
    activated as fhir_lookup_activated,
)
from messagefoundry.config.run_context import RunContext, run_contexts
from messagefoundry.config.settings import EgressSettings, StoreBackend
from messagefoundry.config.wiring import (
    InboundConnection,
    OutboundConnection,
    PortConflictError,
    Registry,
    WiringError,
    bindings_overlap,
    inbound_binding_conflicts,
    resolve_env_settings,
    resolve_listener_binding,
)
from messagefoundry.parsing import HL7PeekError, Peek, RawMessage, normalize, summarize, validate
from messagefoundry.parsing.peek import DEFAULT_MAX_MESSAGE_BYTES
from messagefoundry.pipeline.alerts import AlertSink, LoggingAlertSink
from messagefoundry.pipeline.cluster import ClusterCoordinator, NullCoordinator
from messagefoundry.redaction import safe_exc, safe_text
from messagefoundry.pipeline.dryrun import route_only, transform_one
from messagefoundry.store import MessageStatus, QueueStore, Stage
from messagefoundry.store.base import pool_over_provisioned_warning
from messagefoundry.transports import (
    DeliveryError,
    DestinationConnector,
    NegativeAckError,
    SourceConnector,
    build_destination,
    build_source,
)
from messagefoundry.transports.base import ConnectionEventSink
from messagefoundry.transports.database import DatabaseLookupExecutor
from messagefoundry.transports.fhir import FhirLookupExecutor
from messagefoundry.transports.mllp import build_ack

__all__ = ["RegistryRunner"]

log = logging.getLogger(__name__)

# A delivery worker backs off this long after an *unexpected* error (e.g. the store being briefly
# unavailable) before retrying, so a transient failure logs once and recovers instead of hot-looping.
_WORKER_ERROR_BACKOFF_SECONDS = 1.0

# A queue_buildup alert re-fires at most this often per connection while the lane stays over threshold,
# so an ongoing stall reminds the operator without spamming on every backed-off retry.
_BUILDUP_REALERT_SECONDS = 300.0

# Bound on the in-runner connection-event queue (#46). A flood of refused/garbage connections can't grow
# memory without limit — excess events are dropped + counted (a diagnostic log, not a reliability surface).
_CONN_EVENT_QUEUE_MAX = 10000
# How long teardown waits for the drain queue to flush before cancelling the drainer (bounded shutdown).
_CONN_EVENT_FLUSH_GRACE = 2.0

# The ingress worker has no per-message "failure" to hang a buildup check on (a slow-but-working
# router just falls behind), so it polls the lane depth at most this often — bounding the extra
# COUNT+MIN query rate on the ingress hot path regardless of throughput.
_BUILDUP_CHECK_INTERVAL = 1.0

# How long the handler's worker thread blocks on a single db_lookup() before giving up (ADR 0010).
# A live lookup that exceeds this raises (→ the message's transform fails and dead-letters) rather than
# pinning a worker thread forever; the orphaned query still completes on the loop and releases its conn.
_LOOKUP_RESULT_TIMEOUT_SECONDS = 30.0

# Engine-level ingress size ceiling for NON-HL7 content types (SEC-017, CWE-770). The HL7 path already
# enforces this via Peek.parse → enforce_size_limits; the binary/text branches had only the per-transport
# frame cap (each individually disable-able with max_frame_bytes=0). Mirroring the HL7 cap here makes the
# 16 MiB ceiling an engine-level invariant (belt-and-suspenders) rather than a per-transport one, so an
# operator who disabled a transport cap (or a future transport that ships without one) still can't buffer
# a multi-GB body whole. Measured on the raw BYTES pre-base64-inflation (binary) / the decoded str (text,
# matching enforce_size_limits' len(norm) convention).
_INGRESS_MAX_BYTES = DEFAULT_MAX_MESSAGE_BYTES

# OSError errnos a listener bind raises when the (host, port) can't be taken — classified into a clear
# PortConflictError naming the connection + binding, instead of a bare unattributed OSError aborting the
# inbound. EADDRINUSE: another process/instance holds it; EADDRNOTAVAIL: the bind_address isn't a local
# interface; EACCES: a privileged port (<1024) without permission. The within-graph + reserved-port
# cases are caught statically before the bind (_guard_port_conflict); this catches the EXTERNAL ones.
_BIND_CONFLICT_ERRNOS = frozenset({errno.EADDRINUSE, errno.EADDRNOTAVAIL, errno.EACCES})


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


@dataclass
class EmptyClaimCounters:
    """Read-only, additive worker-loop counters for the connection-scale harness (B11).

    A stage worker that claims its lane and finds it empty (``if not items:``) does a wasted DB
    round-trip — an **empty claim**. There are two distinct sources, and the connection-scale wall
    report must keep them SEPARATE (don't sum them into one number):

    * ``idle_poll`` — the empty claim followed a ``poll_interval`` *timeout* in ``_wait_for_work`` (no
      wake event arrived): the steady 0.25s idle re-SELECT every idle worker does. Scales with the
      number of idle workers × 1/poll_interval.
    * ``wake_fanout`` — the empty claim followed a *wake* (a producer ``event.set()``): the per-commit
      **thundering-herd**. The per-stage wake events are engine-wide singletons, so one committed
      message wakes ALL ~N workers of a stage and each re-SELECTs — but only one finds the new row, so
      the other ~N-1 are woken-but-found-nothing. At a constant aggregate rate (the harness's
      ``fixed_aggregate`` sweep) this is the wake-fanout cost, rising with N.

    ``total`` (== idle_poll + wake_fanout) is surfaced as ``StatsResponse.empty_claims``; the split is
    surfaced as ``empty_claims_idle_poll`` / ``empty_claims_wake_fanout`` so the report can plot the
    herd slope distinctly from the idle-poll floor. All monotonic; default 0 (byte-identical when the
    harness never reads them). Mutated only on the engine event loop (no lock needed)."""

    total: int = 0
    idle_poll: int = 0
    wake_fanout: int = 0

    def record_empty(self, *, woken: bool) -> None:
        """Account one empty claim, classified by whether the worker was last *woken* (wake-fanout) or
        timed out on the poll interval (idle-poll)."""
        self.total += 1
        if woken:
            self.wake_fanout += 1
        else:
            self.idle_poll += 1


class RegistryRunner:
    """Runs every inbound connection in a Registry + one delivery worker per outbound."""

    def __init__(
        self,
        registry: Registry,
        store: QueueStore,
        *,
        poll_interval: float = 0.25,
        claim_limit: int = 20,
        fifo_claim_batch: int = 1,
        inbound_bind_host: str = "127.0.0.1",
        reserved_bindings: Sequence[tuple[str, str, int]] = (),
        allow_insecure_bind: bool = False,
        delivery_defaults: RetryPolicy | None = None,
        ordering_default: OrderingMode | None = None,
        internal_error_default: InternalErrorPolicy | None = None,
        buildup_default: BuildupThreshold | None = None,
        stall_default: StallThreshold | None = None,
        ack_after_default: AckAfter | None = None,
        priority_default: Priority | None = None,
        dr_threshold: Priority | None = None,
        alert_sink: AlertSink | None = None,
        egress: EgressSettings | None = None,
        simulate_all: bool = False,
        env_values: Mapping[str, Any] | None = None,
        active_environment: str | None = None,
        coordinator: ClusterCoordinator | None = None,
        max_correlation_depth: int = 8,
        connection_events: bool = True,
        response_sent_default: bool = True,
        per_lane_wake: bool = False,
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
        # ADR 0058 batch-claim: max rows the INGRESS/ROUTED FIFO claim takes per commit. 1 = OFF (the
        # workers call the single claim_next_fifo, byte-identical). > 1 claims the contiguous due
        # head-prefix in one commit (claim_next_fifo_batch) and processes each row in FIFO order. Clamp
        # the floor to 1 so a stray 0/negative can never disable the claim. From [store].fifo_claim_batch.
        self._fifo_batch = max(1, fifo_claim_batch)
        # Global outbound defaults (from [delivery]); a connection's own settings override them.
        # An outbound with none inherits these (per-connection override > global default > built-in).
        self._delivery_defaults = delivery_defaults or RetryPolicy()
        self._ordering_default = ordering_default or OrderingMode.FIFO
        self._internal_error_default = internal_error_default or InternalErrorPolicy.CONTINUE
        self._buildup_default = buildup_default or BuildupThreshold()
        # message_stall threshold default (#50). StallThreshold() is OFF (max_oldest_seconds=None), so a
        # connection inherits "no stall alert" unless [delivery].stall_max_oldest_seconds or a per-
        # connection stall= sets one — deny-by-default.
        self._stall_default = stall_default or StallThreshold()
        # Global inbound ACK-timing default (from [inbound]); a connection's own ack_after overrides
        # it. Step A only supports INGEST (ACK-on-receipt); a resolved DELIVERED fails loud at start.
        self._ack_after_default = ack_after_default or AckAfter.INGEST
        # DR run-profile (#61, ADR 0048). _priority_default is the global [delivery].priority a
        # connection inherits when it declares no priority= (resolution: per-connection override >
        # global default > built-in NORMAL). _dr_threshold is the THIS-RUN run-profile gate: when set
        # (a DR box under the DR profile), start() binds only connections whose resolved tier rank >=
        # the threshold rank — the rest are recorded in _filtered and report status:"filtered" (distinct
        # from ADR 0031's "failed"). None (the default, every normal deployment) = no DR filtering, so
        # every connection starts subject only to ADR 0031 — byte-identical to before this seam.
        self._priority_default = priority_default or Priority.NORMAL
        self._dr_threshold = dr_threshold
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
        # Reserved service bindings a listener must not steal — each (label, host, port), e.g. the
        # engine's own API listener ([api].host:[api].port). Threaded from the Engine (empty in
        # tests/embedding, where no API socket is bound). Consulted by the static port-conflict pass
        # (build_check / start) so an inbound on the API port is refused with a clear message, not a
        # bare OSError once uvicorn already holds it.
        self._reserved_bindings: tuple[tuple[str, str, int], ...] = tuple(reserved_bindings)
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
        self._stall: dict[str, StallThreshold] = {}
        # Effective per-connection egress-suppression (#15): per-connection simulate= OR simulate_all.
        self._simulate: dict[str, bool] = {}
        # Per-outbound-lane health (#46), for the edge-triggered connection_lost/restored events. True
        # (or unset) = healthy; flipped on the FIRST transport DeliveryError and back on the next
        # success, so a retry storm emits one transition pair, not one per delivery. A partner reject
        # (NegativeAckError) is not a transport failure and never flips it.
        self._lane_healthy: dict[str, bool] = {}
        # Connections that FAILED to build/bind at start (name → reason). A failed connection is
        # isolated, never fatal — the rest of the graph still comes up (a failed connection must not
        # crash the engine, ADR 0031). A failed OUTBOUND still gets its delivery worker, but with no
        # connector in _destinations, so rows routed to it are retried + alerted (never silently
        # dropped) and a reload/restart that builds it self-heals the lane; a failed INBOUND simply
        # isn't listening. Cleared when the connection later builds/binds (reload, start_inbound).
        self._failed: dict[str, str] = {}
        # Connections SKIPPED by the DR run-profile (#61, ADR 0048): name → reason (e.g. "DR profile
        # threshold=critical: connection tier=normal is below threshold"). Distinct from _failed (ADR
        # 0031): a filtered connection did not FAIL to build/bind — it was deliberately not started
        # because its resolved priority tier is below [dr].priority_threshold. Surfaced as
        # status:"filtered" on /connections + /connections/{name}/metadata so an operator can tell a
        # deliberately-parked DR feed from a broken one. Empty unless a DR run-profile is active.
        self._filtered: dict[str, str] = {}
        # Per-connection re-alert throttle: the earliest time a queue_buildup alert may fire again.
        self._next_buildup_alert: dict[str, float] = {}
        # Same per-connection re-alert throttle for the message_stall alert (#50), kept independent so a
        # buildup alert can't suppress a stall alert (and vice-versa) on the same lane.
        self._next_stall_alert: dict[str, float] = {}
        # Live-lookup executor (db_lookup, ADR 0010): built from registry.lookups at start/reload, None
        # when the graph declares no DatabaseLookup — in which case the transform path stays byte-identical
        # (inline call, no thread hop, no runner). The engine loop is captured at start so a handler's
        # worker thread can bridge a db_lookup back onto it (run_coroutine_threadsafe).
        self._lookup_executor: DatabaseLookupExecutor | None = None
        # Live FHIR-lookup executor (fhir_lookup, ADR 0043): the read-side sibling of _lookup_executor,
        # built from registry.fhir_lookups at start/reload, None when the graph declares no FhirLookup.
        # When either executor is set, the transform runs off-loop with the matching runner(s) activated.
        self._fhir_lookup_executor: FhirLookupExecutor | None = None
        # ADR 0057: per-inbound "inline Step-A fast-path eligible" flag, computed once at graph-build
        # (start/reload, after the lookup executors are (re)built) and cached. True iff the inbound opts
        # in (ic.inline) AND the graph declares no live lookup (db/fhir) AND ack_after resolves to
        # ingest AND the inbound isn't a LOOPBACK. Per-message gates (single-handler, all-deliver) are
        # re-checked at runtime in _router_worker; an ineligible/missing name reads False (the split
        # path), so this is byte-identical when nobody opts in. Empty until start().
        self._inline_ok: dict[str, bool] = {}
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
        # Per-lane wake events (B12, ADR 0061). DEFAULT-OFF: when False the four singleton events above
        # are the wake mechanism (byte-identical to before B12); `_lane_events` stays EMPTY and is never
        # consulted. When True, each (stage, lane) has its OWN Event so a committed message wakes only its
        # own worker instead of every worker of that stage — killing the thundering-herd empty-claim storm
        # at connection scale. Keyed by the STABLE lane-name string (INGRESS/ROUTED/RESPONSE by channel_id,
        # OUTBOUND by destination_name) so a sticky set survives a worker spawn/respawn/reload. `_stop`
        # stays a singleton (global shutdown, not per-lane). See _lane_event / _wake_lane / _wake_all.
        self._per_lane_wake = per_lane_wake
        self._lane_events: dict[Stage, dict[str, asyncio.Event]] = {s: {} for s in Stage}
        self._singleton_for_stage: dict[Stage, asyncio.Event] = {
            Stage.INGRESS: self._ingress_work,
            Stage.ROUTED: self._routed_work,
            Stage.RESPONSE: self._response_work,
            Stage.OUTBOUND: self._work,
        }
        # Connection-event log (Corepoint-style #46): on each listen source the runner injects a sink
        # that put_nowait's an event dict onto this bounded queue; a single drain task writes them to the
        # store OFF the accept/delivery hot path (pure observer — the listener never awaits a store
        # write). connection_events=False → no sink injected (byte-identical). Created in start(), torn
        # down (after a best-effort flush) in _teardown_unsafe.
        self._connection_events = connection_events
        # Master switch for "Response Sent" ACK capture (#46); a per-inbound capture_ack overrides it.
        self._response_sent_default = response_sent_default
        self._conn_event_q: asyncio.Queue[dict[str, Any]] | None = None
        self._conn_event_drainer: asyncio.Task[None] | None = None
        self._conn_events_dropped = 0
        self._running = False
        self._reload_lock = asyncio.Lock()  # serialize concurrent reloads
        # B11 read-only worker-loop instrumentation: empty-claim counts (router/transform/delivery),
        # split into idle-poll re-SELECTs vs per-commit wake-fanout (the thundering herd). Surfaced via
        # /stats; default 0, so byte-identical when the connection-scale harness never reads it.
        self._empty_claims = EmptyClaimCounters()

    @property
    def running(self) -> bool:
        return self._running

    @property
    def empty_claims(self) -> EmptyClaimCounters:
        """The B11 read-only empty-claim counters (idle-poll vs wake-fanout). The ``/stats`` route
        reads these to surface the connection-scale wall signals; nothing in the engine mutates routing
        from them."""
        return self._empty_claims

    @property
    def coordinator(self) -> ClusterCoordinator:
        """The cluster coordinator threaded in by the engine (Track B Step 3). Step 4 consumes its
        cheap, synchronous ``is_leader`` gate; this exposes the object."""
        return self._coordinator

    def _lane_event(self, stage: Stage, key: str) -> asyncio.Event:
        """Get-or-create the wake Event for one (stage, lane) — STRICT: create+store on a miss, else
        return the SAME stored object. NEVER replace a live Event (a replace between a producer's set()
        and the worker's first wait() would drop the sticky set → lost wakeup) and NEVER no-op on a miss
        (a missing lane must be created so a wake to a not-yet-spawned worker's lane sticks). Called ONLY
        when per_lane_wake is True — the OFF path never touches _lane_events. ADR 0061."""
        return self._lane_events[stage].setdefault(key, asyncio.Event())

    def _wake_lane(self, stage: Stage, key: str) -> None:
        """Wake the worker for one (stage, lane). OFF → the whole-stage singleton (byte-identical to the
        pre-B12 set()); ON → only this lane's Event. ADR 0061."""
        if not self._per_lane_wake:
            self._singleton_for_stage[stage].set()
        else:
            self._lane_event(stage, key).set()

    def _wake_all(self, *stages: Stage) -> None:
        """Wake EVERY worker of the given stages — for lane-agnostic producers (notify_work / reload /
        teardown) that can't name a single lane. OFF → the stage singletons; ON → every registered lane
        Event of those stages. MUST stay synchronous + await-free: it snapshots the Event list before
        iterating so a concurrent reload/producer mutating _lane_events can't raise 'dict changed size
        during iteration'. ADR 0061."""
        if not self._per_lane_wake:
            for stage in stages:
                self._singleton_for_stage[stage].set()
        else:
            for stage in stages:
                for ev in list(self._lane_events[stage].values()):
                    ev.set()

    def notify_work(self) -> None:
        """Wake every stage worker now (e.g. after a replay re-queues rows at an unknown stage)."""
        self._wake_all(Stage.INGRESS, Stage.ROUTED, Stage.RESPONSE, Stage.OUTBOUND)

    def set_env_values(self, values: Mapping[str, Any]) -> None:
        """Replace the environment values used to resolve ``env()`` refs when (re)building connectors.
        The engine calls this on reload so a promote picks up edited values without a restart (M-23)."""
        self._env_values = dict(values)

    # --- connection-event capture (Corepoint-style transport/lifecycle log, #46) ----------------
    def _make_connection_event_sink(self, ic: InboundConnection) -> ConnectionEventSink | None:
        """The per-inbound sink the runner injects on a source, or ``None`` when capture is off (→ the
        source's emit sites are no-ops, byte-identical). The closure binds the connection name +
        transport + ``direction='inbound'``; the source supplies ``(kind, peer_host, reason)``. It only
        ``put_nowait``'s onto the bounded drain queue — never an awaited store write — so a listener's
        accept path is never blocked by capture (pure observer). The per-inbound
        ``capture_connection_errors`` overrides the ``[diagnostics].connection_events`` master switch
        (``None`` = inherit)."""
        enabled = ic.capture_connection_errors
        if enabled is None:
            enabled = self._connection_events
        if not enabled:
            return None
        name = ic.name
        transport = ic.spec.type.value

        async def _sink(kind: str, peer_host: str | None, reason: str | None) -> None:
            self._enqueue_connection_event(
                connection=name,
                transport=transport,
                direction="inbound",
                kind=kind,
                peer_host=peer_host,
                message_id=None,
                reason=reason,
            )

        return _sink

    def _enqueue_connection_event(self, **fields: Any) -> None:
        """Non-blocking enqueue onto the drain queue (#46). On overflow drop the event + count it — a
        connection-event flood must never block a listener/delivery lane or grow memory unbounded."""
        q = self._conn_event_q
        if q is None:
            return
        try:
            q.put_nowait(fields)
        except asyncio.QueueFull:
            self._conn_events_dropped += 1

    async def _connection_event_drainer(self) -> None:
        """Write queued connection events to the store OFF the listener/delivery hot path (#46). One
        write per event, **fail-soft**: a store error drops that one observation, never a message or the
        listener. Cancelled (after a best-effort flush) on teardown."""
        q = self._conn_event_q
        assert q is not None
        while True:
            fields = await q.get()
            try:
                await self.store.record_connection_event(**fields)
            except asyncio.CancelledError:
                raise
            except Exception:
                log.warning("connection-event write failed; dropping one event")
            finally:
                q.task_done()

    def _outbound_transport(self, name: str) -> str:
        """The transport label of an outbound connection for a connection event, read live from the
        registry (a reload can swap it). ``'unknown'`` if the connection is gone mid-reconcile."""
        oc = self.registry.outbound.get(name)
        return oc.spec.type.value if oc is not None else "unknown"

    def _note_lane_unhealthy(self, name: str, message_id: str, exc: BaseException) -> None:
        """Edge-trigger ``connection_lost`` + a throttled ``connection_error`` alert on the FIRST
        transport ``DeliveryError`` after the lane was healthy (#46) — not per retry. No-op when capture
        is off (byte-identical) or the lane is already marked down."""
        if not self._connection_events or not self._lane_healthy.get(name, True):
            return
        self._lane_healthy[name] = False
        reason = safe_exc(exc)
        self._enqueue_connection_event(
            connection=name,
            transport=self._outbound_transport(name),
            direction="outbound",
            kind="connection_lost",
            peer_host=None,
            message_id=message_id,
            reason=reason,
        )
        try:
            self._alert_sink.connection_error(name, kind="connection_lost", detail=reason)
        except Exception:
            log.warning("alert sink raised on connection_error for %r", name)

    def _note_lane_healthy(self, name: str) -> None:
        """Edge-trigger ``connection_restored`` on the FIRST successful delivery after the lane was down
        (#46). Store-row only (a recovery needs no alert). No-op when capture is off or already healthy."""
        if not self._connection_events or self._lane_healthy.get(name, True):
            return
        self._lane_healthy[name] = True
        self._enqueue_connection_event(
            connection=name,
            transport=self._outbound_transport(name),
            direction="outbound",
            kind="connection_restored",
            peer_host=None,
            message_id=None,
            reason=None,
        )
        # Auto-resolve the matching open alert instance (ADR 0044, #56) — no notification (a recovery
        # needs no page); the sink resolves the connection_error instance when alert-state is wired.
        try:
            self._alert_sink.connection_restored(name)
        except Exception:
            log.warning("alert sink raised on connection_restored for %r", name)

    def _capture_ack_enabled(self, ic: InboundConnection) -> bool:
        """Whether to record the "Response Sent" ACK for this inbound (ADR 0021, #46). Only a reply-
        capable LISTEN source (MLLP/TCP) actually returns an ACK to a sender — a FILE/DB/poll source has
        no reply channel, so it captures nothing (ADR 0021 §3). The per-inbound ``capture_ack`` overrides
        the ``[diagnostics].response_sent`` master switch (``None`` = inherit)."""
        if ic.spec.type not in (ConnectorType.MLLP, ConnectorType.TCP):
            return False
        return ic.capture_ack if ic.capture_ack is not None else self._response_sent_default

    def _recompute_inline_ok(self) -> None:
        """Recompute the per-inbound ADR 0057 inline-fast-path eligibility cache from the current graph
        and the just-(re)built lookup executors. MUST be called after ``self._lookup_executor`` /
        ``self._fhir_lookup_executor`` are set for the live graph (start + reload).

        The graph-level gates (P-config opt-in, P-lookup no live lookups, P-ack ingest, not LOOPBACK):
        per ADR 0057 §2 P-lookup is graph-level (lookup presence keys off ``registry.lookups`` /
        ``fhir_lookups``, not per-handler), so a single declared lookup disables the inline path for the
        WHOLE graph. The per-message gates (M-single / M-deliver) are re-checked at runtime. Anything
        not eligible falls back to today's split path verbatim — byte-identical when nobody opts in.
        """
        no_lookups = self._lookup_executor is None and self._fhir_lookup_executor is None
        inline_ok: dict[str, bool] = {}
        for name, ic in self.registry.inbound.items():
            resolved_ack_after = ic.ack_after or self._ack_after_default
            inline_ok[name] = (
                ic.inline
                and no_lookups
                and resolved_ack_after == AckAfter.INGEST
                and ic.spec.type is not ConnectorType.LOOPBACK
            )
        self._inline_ok = inline_ok

    def _build_lookup_executor(self) -> DatabaseLookupExecutor | None:
        """Build the pooled live-lookup executor from the current graph's ``DatabaseLookup`` specs, or
        ``None`` if the graph declares none (so ``db_lookup`` is unavailable and the lookup runner is not
        activated — but the transform still runs OFF the loop either way, for availability; SEC-013).
        Resolves ``env()`` in each spec and fail-closed egress-checks the server, exactly like a DATABASE
        source. ``build_check`` already validated these on a reload, so this won't raise there; at start a
        bad spec surfaces here and unwinds the partial start."""
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
        worker thread (``transform_one`` always runs off the loop), it bridges the async query onto the
        engine loop via ``run_coroutine_threadsafe`` and blocks the WORKER THREAD — never the loop — for
        the result (bounded by ``_LOOKUP_RESULT_TIMEOUT_SECONDS``)."""
        executor = self._lookup_executor
        loop = self._loop
        if executor is None or loop is None:  # only published when both exist; guard defensively
            raise DbLookupError("db_lookup is unavailable — no lookup connections are configured")
        future = asyncio.run_coroutine_threadsafe(
            executor.query(connection, statement, params), loop
        )
        return future.result(_LOOKUP_RESULT_TIMEOUT_SECONDS)

    def _build_fhir_lookup_executor(self) -> FhirLookupExecutor | None:
        """Build the live FHIR-read executor from the current graph's ``FhirLookup`` specs, or ``None`` if
        the graph declares none (so ``fhir_lookup`` is unavailable and its runner is not activated). Mirrors
        :meth:`_build_lookup_executor`: resolves ``env()`` in each spec and fail-closed egress-checks the
        FHIR host against ``[egress].allowed_http`` (ADR 0043), exactly as the FHIR outbound is gated."""
        if not self.registry.fhir_lookups:
            return None
        resolved: dict[str, dict[str, Any]] = {}
        for name, spec in self.registry.fhir_lookups.items():
            settings = resolve_env_settings(spec.settings, self._env_values)
            check_fhir_lookup_allowed(name, settings, self._egress)
            resolved[name] = settings
        return FhirLookupExecutor(resolved)

    def _run_fhir_lookup(self, connection: str, query: str) -> dict[str, Any]:
        """The FHIR-lookup runner published to Handlers (``fhir_lookup`` → this). Called FROM the handler's
        worker thread, it bridges the async GET onto the engine loop via ``run_coroutine_threadsafe`` and
        blocks the WORKER THREAD — never the loop — for the result (bounded by
        ``_LOOKUP_RESULT_TIMEOUT_SECONDS``)."""
        executor = self._fhir_lookup_executor
        loop = self._loop
        if executor is None or loop is None:  # only published when both exist; guard defensively
            raise FhirLookupError(
                "fhir_lookup is unavailable — no FhirLookup connections are configured"
            )
        future = asyncio.run_coroutine_threadsafe(executor.read(connection, query), loop)
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

    def connection_filtered(self, name: str) -> str | None:
        """The reason this connection was skipped by the DR run-profile (its resolved priority tier is
        below ``[dr].priority_threshold``), else ``None`` (#61, ADR 0048). A filtered connection is
        **not** failed (ADR 0031) — it was deliberately not started; the two are surfaced as the distinct
        ``status:"filtered"`` vs ``status:"failed"`` so an operator can tell a parked DR feed from a
        broken one."""
        return self._filtered.get(name)

    def filtered_connections(self) -> dict[str, str]:
        """Snapshot of ``{connection: reason}`` for connections the DR run-profile parked below the
        priority threshold (#61, ADR 0048). Empty unless a DR run-profile is active — the sibling of
        :meth:`degraded_connections`, kept distinct so a parked DR feed is never confused with an
        ADR-0031 failure."""
        return dict(self._filtered)

    def resolved_priority(self, name: str) -> Priority:
        """The connection's resolved DR / priority tier (#61, ADR 0048): its own ``priority=`` override,
        else the global ``[delivery].priority`` default, else the built-in ``NORMAL`` (resolution order:
        per-connection override > global default > built-in). Defined for both an inbound and an
        outbound; unknown names resolve to the global default."""
        ic = self.registry.inbound.get(name)
        if ic is not None:
            return ic.priority or self._priority_default
        oc = self.registry.outbound.get(name)
        if oc is not None:
            return oc.priority or self._priority_default
        return self._priority_default

    def _dr_filters_out(self, name: str, declared: Priority | None) -> bool:
        """Whether the DR run-profile parks this connection (its resolved tier is below the threshold).

        ``False`` when no DR run-profile is active (``_dr_threshold is None``) — every normal deployment,
        so the start path is byte-identical to before this seam. When a DR profile IS active, records the
        reason in ``_filtered`` and returns ``True`` for a below-threshold connection so :meth:`start`
        skips binding/building it. The comparison is on the explicit total order (``rank``), so it is
        unambiguous: a connection runs iff ``resolved.rank >= threshold.rank``."""
        threshold = self._dr_threshold
        if threshold is None:
            return False
        resolved = declared or self._priority_default
        if resolved.rank >= threshold.rank:
            self._filtered.pop(name, None)  # at/above threshold — not parked
            return False
        self._filtered[name] = (
            f"DR run-profile threshold={threshold.value}: connection tier={resolved.value} is below "
            f"threshold — not started (status:filtered, ADR 0048)"
        )
        return True

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

    def _guard_port_conflict(self, ic: InboundConnection) -> None:
        """Refuse to bind ``ic`` if its resolved ``(host, port)`` collides with a reserved service
        binding (the API listener) or an already-bound sibling source — raising :class:`PortConflictError`
        before the bind. A no-op for a non-listener or an unresolvable ``env()`` port (nothing to
        compare). Per-connection by design: when the second of a conflicting pair starts, the first is
        already in ``_sources`` and is named here, so it stays up while this one is isolated (ADR 0031);
        the whole-graph view is covered by :func:`inbound_binding_conflicts` at build_check/reload."""
        binding = resolve_listener_binding(
            ic, bind_host=self._inbound_bind_host, env_values=self._env_values
        )
        if binding is None:
            return
        host, port = binding
        for label, rhost, rport in self._reserved_bindings:
            if bindings_overlap(host, port, rhost, rport):
                raise PortConflictError(
                    f"inbound connection {ic.name!r} binds port {port}, reserved for {label}"
                )
        for other_name in self._sources:
            other = self.registry.inbound.get(other_name)
            if other is None:
                continue
            other_binding = resolve_listener_binding(
                other, bind_host=self._inbound_bind_host, env_values=self._env_values
            )
            if other_binding is not None and bindings_overlap(host, port, *other_binding):
                raise PortConflictError(
                    f"inbound connection {ic.name!r} cannot bind port {port}: already bound by "
                    f"{other_name!r}"
                )

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
        # Refuse a listener whose resolved (host, port) collides with a reserved service binding (the
        # API listener) or an already-bound sibling — BEFORE the bind, so the message names the
        # contended port + the other side rather than surfacing as a bare OSError on the loser of an OS
        # bind race. The external case (another process holds the port) can't be known statically; the
        # source.start() bind below classifies that OSError into the same PortConflictError.
        self._guard_port_conflict(ic)
        source_cfg = _source_config(ic, self._inbound_bind_host, self._env_values)
        check_source_allowed(source_cfg, ic.name, self._egress)  # fail-closed connect allowlist
        # Exposed-gate (ADR 0002 §0 / ADR 0025 §9): refuse a non-loopback MLLP or DICOM SCP listener
        # without TLS at start, and a non-loopback raw-TCP/X12 listener (plaintext-only — no TLS option)
        # at start (cleartext PHI on the wire). Each guard no-ops for the other's type.
        check_mllp_tls_exposure(source_cfg, ic.name, allow_insecure_bind=self._allow_insecure_bind)
        check_dimse_tls_exposure(source_cfg, ic.name, allow_insecure_bind=self._allow_insecure_bind)
        check_tcp_tls_exposure(source_cfg, ic.name, allow_insecure_bind=self._allow_insecure_bind)
        check_http_tls_exposure(source_cfg, ic.name, allow_insecure_bind=self._allow_insecure_bind)
        source = build_source(source_cfg)
        # Inject the connection-event sink (#46) BEFORE start so a listen source can emit accept/refuse/
        # close. None when capture is off (byte-identical). transports/ stays store-agnostic — the sink
        # is a runner-owned coroutine that only enqueues onto the off-hot-path drain queue.
        source.on_connection_event = self._make_connection_event_sink(ic)
        # Leader-gate the source's intake (Track B Step 4b). is_leader is a cheap, synchronous bound
        # method = Callable[[], bool]; passing the bound METHOD (not the coordinator) keeps transports/
        # free of any pipeline/cluster import. Only POLL sources act on it — they skip a scan when it
        # returns False so exactly one node ingests a shared external resource (a dir / DB table /
        # remote dir); LISTEN sources (MLLP/TCP) accept-and-ignore it (each binds its own endpoint). For
        # single-node (NullCoordinator) is_leader is always True, so every poll source scans as before.
        # Bind BEFORE registering: a failed bind (e.g. port in use) must not leave a dead source in
        # _sources, where inbound_running() would report True and a retry would no-op (review M-9).
        # The HTTP listen source (ADR 0023) gets a receipt handler returning the committed message_id for
        # its 202; every other source gets the standard handler whose str return is a wire reply/ACK.
        make_handler = (
            self._make_http_handler if ic.spec.type is ConnectorType.HTTP else self._make_handler
        )
        try:
            await source.start(make_handler(ic), leader_gate=self._coordinator.is_leader)
        except OSError as exc:
            # Classify a bind failure (port already taken by an EXTERNAL process, an unavailable
            # bind_address, a privileged port) into a named PortConflictError so the operator sees which
            # connection + binding failed, not a bare unattributed OSError. Re-raised, so ADR 0031's
            # per-connection isolation in start() records it failed (engine DEGRADED) — or a direct
            # start_inbound caller (console) gets the clear reason. Non-bind OSErrors propagate as-is.
            if exc.errno in _BIND_CONFLICT_ERRNOS:
                host = source_cfg.settings.get("host")
                port = source_cfg.settings.get("port")
                detail = (
                    "another process or instance is already bound there"
                    if exc.errno == errno.EADDRINUSE
                    else (exc.strerror or "bind failed")
                )
                raise PortConflictError(
                    f"inbound connection {name!r}: cannot bind {host}:{port} — {detail}"
                ) from exc
            raise
        self._sources[name] = source
        self._failed.pop(
            name, None
        )  # bound successfully — clear any prior start failure (ADR 0031)
        # An operator that explicitly starts a DR-parked inbound (POST /connections/{name}/start) is
        # overriding the run-profile, so it is no longer "filtered" — clear that marker too (#61).
        self._filtered.pop(name, None)
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
        self._stall[name] = oc.stall or self._stall_default
        self._simulate[name] = self._resolve_simulate(name, oc)
        # DR run-profile (#61, ADR 0048): a below-threshold outbound is NOT built — but its delivery
        # worker still spawns (the retry/ordering/etc. above are set regardless), so a row routed to it
        # sits in the outbound stage and backs off via the retry policy, self-healing on the next full
        # (non-DR) startup. This is exactly the ADR-0031 degraded-outbound branch (the worker's "no
        # connector for a claimed row" path), so the count-and-log + at-least-once invariants hold: the
        # row is queued + retried + buildup-alerted, never silently dropped. status:"filtered" (not
        # "failed") tells the operator it was deliberately parked.
        if self._dr_filters_out(name, oc.priority):
            self._destinations.pop(name, None)  # no live connector for a parked lane
            self._spawn_worker(name)
            return
        self._filtered.pop(
            name, None
        )  # at/above threshold this run — clear any prior parked marker
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
            # Connection-event drain task (#46): created before any source binds so an early accept's
            # enqueued event has a consumer. Skipped entirely when capture is off (no sink, no queue).
            if self._connection_events:
                self._conn_event_q = asyncio.Queue(maxsize=_CONN_EVENT_QUEUE_MAX)
                self._conn_event_drainer = asyncio.create_task(self._connection_event_drainer())
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
                self._fhir_lookup_executor = self._build_fhir_lookup_executor()
                # ADR 0057: compute the inline-fast-path eligibility now that the lookup executors are
                # known (P-lookup needs both to be None). Default-OFF unless an inbound opted in.
                self._recompute_inline_ok()
                for ic in self.registry.inbound.values():
                    # DR run-profile (#61, ADR 0048): a below-threshold inbound LISTENER is NOT bound
                    # (no source.start) — but its router + transform workers are still spawned below, so
                    # any crash-recovered ingress/routed backlog carried in the (cold-restored) store
                    # still drains. The listener simply isn't accepting NEW work — the operator intent of
                    # a DR box running only its critical feeds. status:"filtered" (not "failed")
                    # distinguishes it from an ADR-0031 bind failure.
                    if self._dr_filters_out(ic.name, ic.priority):
                        continue
                    self._filtered.pop(
                        ic.name, None
                    )  # at/above threshold this run — clear the marker
                    try:
                        await self._start_inbound_unsafe(ic.name)
                    except Exception as exc:
                        # Isolate this inbound (bad bind / port in use / cleartext-exposure refusal /
                        # bad env): record it failed and continue. It never binds insecurely — the
                        # guard still refused; we just don't also kill the engine over it.
                        self._record_failed(ic.name, exc, kind="inbound")
                # A router + transform worker per inbound — spawned even for an inbound whose source
                # failed to bind OR was DR-filtered, so any crash-recovered ingress/routed backlog still
                # drains (the source just isn't listening). They drain ingress→routed→outbound,
                # independent of listen state (AC-3: a filtered inbound still drains its backlog).
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
            if self._dr_threshold is not None:
                # DR run-profile filter summary (#61, ADR 0048): log the curated critical set up front so
                # an operator can audit which feeds are live and which are deliberately parked on EVERY
                # failover, rather than discovering a mis-tagged feed only when it is absent under load.
                total = len(self.registry.inbound) + len(self.registry.outbound)
                started = total - len(self._filtered)
                log.warning(
                    "DR run-profile threshold=%s: %d of %d connection(s) started; %d below-threshold "
                    "filtered (status:filtered, not failed): %s",
                    self._dr_threshold.value,
                    started,
                    total,
                    len(self._filtered),
                    ", ".join(sorted(self._filtered)) or "(none)",
                )
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
            # Soft over-provisioning check (ADR 0062): warn if this engine's SERVER-DB connection pool is
            # sized past the inverted-U optimum. SQLite has no pool (pool_status() -> None) -> skipped, and
            # the default pool never trips it (not > the optimum). Advisory only — never blocks startup.
            _pool = self.store.pool_status()
            if _pool is not None:
                _pool_warn = pool_over_provisioned_warning(
                    _pool.max_size, len(self.registry.inbound)
                )
                if _pool_warn is not None:
                    log.warning(_pool_warn)

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
        # B12 (ADR 0061): break every waiting worker out of its wait so cancel()+gather lands promptly.
        # OFF sets the four stage singletons (byte-identical); ON sets every registered lane Event.
        self._wake_all(Stage.INGRESS, Stage.ROUTED, Stage.RESPONSE, Stage.OUTBOUND)
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
        # Connection-event drainer (#46): sources are stopped above, so no new events enqueue — flush
        # what's queued (bounded), then cancel the drainer. Un-flushed events on a hard crash are lost by
        # design (a diagnostic trail, not a reliability surface).
        if self._conn_event_drainer is not None:
            if self._conn_event_q is not None:
                try:
                    await asyncio.wait_for(self._conn_event_q.join(), _CONN_EVENT_FLUSH_GRACE)
                except (asyncio.TimeoutError, asyncio.CancelledError):
                    pass
            self._conn_event_drainer.cancel()
            await asyncio.gather(self._conn_event_drainer, return_exceptions=True)
            self._conn_event_drainer = None
            self._conn_event_q = None
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
        self._lane_healthy.clear()
        self._next_buildup_alert.clear()
        self._sources.clear()
        # B12 (ADR 0061): drop the per-lane wake Events now that every worker is cancelled+gathered. Safe
        # here (post-teardown) — NEVER clear/delete lane Events mid-run (a removed-but-draining worker and
        # a re-added lane both reuse them by name via get-or-create). No-op when per_lane_wake is off.
        for _lane_dict in self._lane_events.values():
            _lane_dict.clear()
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
        crash). Idempotent — the shared re-arm used by start(), start_inbound(), and reload().

        FIFO LOAD-BEARING ASSUMPTION (ADR 0059): there is exactly **ONE serial writer per (stage,
        lane-key)**. This dict is keyed by inbound ``name`` and only ever holds one task per kind, so each
        inbound has a single router worker (writing the ``routed`` lane, keyed by channel_id) and a single
        transform worker (writing the ``outbound`` lanes, keyed by destination_name). The delivery worker
        (one per outbound) is likewise singular. Seq-only per-lane FIFO (no created_at clamp backstop)
        relies on this: a single serial writer assigns the DB seq (rowid/IDENTITY/SERIAL) in receive
        order, so claim-by-seq == receive order. **Do NOT spawn a second concurrent writer into any lane**
        (e.g. sharding a lane across two workers without partitioning the lane key) — it would let a
        higher seq commit before a lower one and silently break per-lane FIFO. The outbound
        ``destination_name`` fan-in is multi-writer across inbounds **by design**, but seq is still
        DB-assigned in commit order there, so the first committer gets the lower seq (no honored
        cross-inbound receive order to violate)."""
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
        Raises :class:`WiringError` so the API maps it to 422 like other invalid-config errors.

        This is the COMMON validation every config-application path runs (reload's live-runner swap,
        the runner-None bring-up, and ``reload(dry_run=True)``'s pre-flight all funnel through here),
        so the store-capability gates that must hold on every such path live here too: the
        pass-through (PT) backend allow-list (:func:`check_pt_backend_supported`) rejects a PT inbound
        on a backend that can't re-ingress (Postgres/SQL Server/any non-SQLite) BEFORE the swap, so a
        reload/promote can never bring a PT-on-non-SQLite graph live."""
        build_check_registry(
            registry,
            inbound_bind_host=self._inbound_bind_host,
            env_values=self._env_values,
            egress=self._egress,
            reserved_bindings=self._reserved_bindings,
        )
        # PT-backend allow-list — folded in here (vs only at Engine.start) so EVERY reload + dry-run
        # path that build-checks the new registry also rejects a PT-on-non-SQLite graph before any
        # swap. RegistryRunner carries the resolved store, so the gate sees the backend's capability.
        check_pt_backend_supported(registry, self.store)

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
            self._stall[name] = oc.stall or self._stall_default
            self._simulate[name] = self._resolve_simulate(name, oc)
            worker = self._workers.get(name)
            failed = name in self._failed  # ADR 0031: live worker, but no connector (start failed)
            # DR run-profile (#61, ADR 0048): a reload re-evaluates against the threshold. A
            # below-threshold outbound keeps (or gets) its delivery worker but NO live connector — its
            # routed rows queue + back off + self-heal on the next full startup, exactly the parked-lane
            # behavior. Close any live connector from a prior (non-DR) run so it stops delivering.
            if self._dr_filters_out(name, oc.priority):
                stale = self._destinations.pop(name, None)
                if stale is not None:
                    await stale.aclose()
                self._failed.pop(name, None)
                if worker is None or worker.done():
                    self._spawn_worker(name)
                continue
            self._filtered.pop(name, None)
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
                # The FHIR-read executor holds no pools (a shared, stateless opener), so no aclose: just
                # rebuild it from the new graph (None when the new graph declares no FhirLookup).
                self._fhir_lookup_executor = self._build_fhir_lookup_executor()
                # ADR 0057: re-evaluate inline eligibility against the swapped graph + rebuilt executors
                # (a reload may add/remove a lookup, flip an inbound's inline=, or change ack_after).
                self._recompute_inline_ok()
                for ic in new_registry.inbound.values():
                    # DR run-profile (#61, ADR 0048): a reload re-evaluates the whole graph against the
                    # threshold (the profile is a per-run decision read at start/reload), so a
                    # below-threshold inbound stays parked (status:"filtered") and is not re-bound; its
                    # workers below still drain any backlog. No DR profile → byte-identical to before.
                    if self._dr_filters_out(ic.name, ic.priority):
                        continue
                    self._filtered.pop(ic.name, None)
                    await self._start_inbound_unsafe(ic.name)
                # 2b. Ensure the router + transform workers run for every inbound in the new graph.
                # Workers read self.registry live, so a Router/Handler change applies to rows processed
                # after the swap. A REMOVED inbound's router/transform/response workers EXIT on their
                # first residual row (they see `ic is None`, revert the row retry-FOREVER, and return —
                # :1994); the residual ingress/routed rows then SIT until a later reload RE-ADDS the
                # inbound, which re-arms the worker here and its claim-first loop drains the backlog.
                # (B12/ADR 0061: the lane's wake Event is kept across this remove→re-add, reused by name.)
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

            # Wake every stage (new connections / freshly enqueued rows may sit at any stage). B12 (ADR
            # 0061): the OFF branch preserves the exact pre-B12 set (ingress+routed+outbound — note it has
            # always OMITTED response) for byte-identity; the ON branch ALSO wakes RESPONSE lanes, fixing
            # that asymmetry (a residual Stage.RESPONSE token on a reloaded loopback no longer waits out
            # the poll). A missed wake here still self-heals on the poll backstop, so this is promptness.
            _reload_stages = (
                (Stage.INGRESS, Stage.ROUTED, Stage.RESPONSE, Stage.OUTBOUND)
                if self._per_lane_wake
                else (Stage.INGRESS, Stage.ROUTED, Stage.OUTBOUND)
            )
            self._wake_all(*_reload_stages)
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

    def _make_http_handler(self, ic: InboundConnection):  # type: ignore[no-untyped-def]
        # The HTTP listen source (ADR 0023) needs the engine message_id back so its 202 respond-with-
        # receipt can carry it (AC-2) — distinct from the MLLP/TCP handler, whose str return is a wire
        # REPLY to frame. So HTTP gets its own handler returning the committed message_id (or None when
        # the body was NOT committed: a recorded ERROR from a decode/size guard). The receipt semantics
        # (which the source maps to 202/4xx) are HTTP's own response logic, exactly as the HL7 ACK is
        # MLLP's — the ingress commit + count-and-log + disposition machine are the SAME as _handle_inbound.
        async def on_request(raw: bytes) -> str | None:
            return await self._handle_inbound_http(ic, raw)

        return on_request

    async def _handle_inbound_http(self, ic: InboundConnection, raw: bytes) -> str | None:
        """Commit a POSTed HTTP body to the ingress stage and return the engine ``message_id`` (the
        first-slice receipt, ADR 0023 D3). Returns ``None`` when the body was NOT committed — a
        decode/size-guard failure that recorded an ``ERROR`` (count-and-log: still persisted, never
        accepted-and-dropped). The source maps a returned id to a ``202`` and a ``None`` here to a ``202``
        without an id (the engine guard already recorded the disposition; a pre-ingress
        oversize/malformed/allowlist refusal is the source's own synchronous ``4xx`` BEFORE this runs).

        Shares the SAME store calls, size ceiling, decode handling, and disposition machine as
        :meth:`_handle_inbound`; it differs only in returning the id instead of a wire ACK and in not
        building an HL7 ACK frame (HTTP is the carrier, the 202 is the receipt)."""
        src = ic.spec.type.value
        hl7v2 = ic.content_type is ContentType.HL7V2

        if not hl7v2 and ic.content_type.is_binary:
            # Binary ingress (ADR 0028) — base64-carry at the boundary; never text-decode. Engine size
            # ceiling on the RAW bytes (SEC-017), mirroring _handle_inbound. ERROR + None on overrun.
            if len(raw) > _INGRESS_MAX_BYTES:
                await self.store.record_received(
                    channel_id=ic.name,
                    raw=raw.decode("latin-1"),
                    status=MessageStatus.ERROR,
                    error=f"ingress exceeds max size ({len(raw)} > {_INGRESS_MAX_BYTES} bytes)",
                    source_type=src,
                    message_type=ic.content_type.value,
                )
                return None
            mid = await self.store.enqueue_ingress(
                channel_id=ic.name,
                raw=RawMessage.from_bytes(raw, ic.content_type.value).raw,
                control_id=None,
                message_type=ic.content_type.value,
                source_type=src,
                summary=None,
            )
            self._wake_lane(Stage.INGRESS, ic.name)  # B12: wake only this inbound's router lane
            return mid

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
            return None

        if not hl7v2:
            if len(text) > _INGRESS_MAX_BYTES:
                await self.store.record_received(
                    channel_id=ic.name,
                    raw=text,
                    status=MessageStatus.ERROR,
                    error=f"ingress exceeds max size ({len(text)} > {_INGRESS_MAX_BYTES} bytes)",
                    source_type=src,
                    message_type=ic.content_type.value,
                )
                return None
            mid = await self.store.enqueue_ingress(
                channel_id=ic.name,
                raw=text,
                control_id=None,
                message_type=ic.content_type.value,
                source_type=src,
                summary=None,
            )
            self._wake_lane(Stage.INGRESS, ic.name)  # B12: wake only this inbound's router lane
            return mid

        # HL7-over-HTTP: parse (+ optional strict validate) before committing, recording ERROR on a
        # malformed message exactly as MLLP does — but the synchronous response is the source's 202/4xx,
        # not an HL7 ACK frame (the HL7-ACK-over-HTTP / SOAP-reply path is the deferred ADR 0013 seam).
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
            return None
        if ic.validation.strict:
            result = await asyncio.to_thread(
                validate, text, expected_version=ic.validation.hl7_version
            )
            if not result.ok:
                persisted = f"strict-validation failed: {safe_text('; '.join(result.errors))}"
                await self._record(ic, peek, text, MessageStatus.ERROR, error=persisted)
                return None
        mid = await self.store.enqueue_ingress(
            channel_id=ic.name,
            raw=text,
            control_id=peek.control_id,
            message_type=peek.message_type,
            source_type=src,
            summary=summarize(peek) or None,
        )
        self._wake_lane(Stage.INGRESS, ic.name)  # B12: wake only this inbound's router lane
        return mid

    async def _handle_inbound(self, ic: InboundConnection, raw: bytes) -> str | None:
        ack_mode = ic.ack_mode
        reply = ack_mode is not AckMode.NONE
        src = ic.spec.type.value
        hl7v2 = ic.content_type is ContentType.HL7V2

        if not hl7v2 and ic.content_type.is_binary:
            # Engine-level ingress size guard (SEC-017, CWE-770): the HL7 path enforces a 16 MiB ceiling
            # via Peek.parse → enforce_size_limits; mirror it here for binary ingress so the cap is an
            # engine invariant, not just a per-transport frame cap (which is disable-able). Measure on the
            # RAW bytes (pre-base64-inflation) so the carriage codec can't blow past the ceiling. Record
            # ERROR + return None (no HL7 ACK for non-HL7) — count-and-log, never crash the connection.
            if len(raw) > _INGRESS_MAX_BYTES:
                await self.store.record_received(
                    channel_id=ic.name,
                    raw=raw.decode(
                        "latin-1"
                    ),  # lossless byte view (same pattern as the decode-error path)
                    status=MessageStatus.ERROR,
                    error=f"ingress exceeds max size ({len(raw)} > {_INGRESS_MAX_BYTES} bytes)",
                    source_type=src,
                    message_type=ic.content_type.value,
                )
                return None
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
            self._wake_lane(Stage.INGRESS, ic.name)  # B12: wake only this inbound's router lane
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
            decode_err = f"decode error ({encoding}): {safe_exc(exc)}"
            mid = await self.store.record_received(
                channel_id=ic.name,
                raw=raw.decode("latin-1"),  # lossless byte view — the declared encoding rejected it
                status=MessageStatus.ERROR,
                error=decode_err,
                source_type=src,
                message_type=None if hl7v2 else ic.content_type.value,
            )
            ack = (
                build_ack(raw, code="AR", text="decode error", ack_mode=ack_mode)
                if (hl7v2 and reply)
                else None
            )
            if ack is not None and self._capture_ack_enabled(ic):
                await self._capture_ack(
                    mid,
                    ic.name,
                    ack_code="AR",
                    ack_phase="decode",
                    ack_body=None,
                    detail=decode_err,
                )
            return ack

        if not hl7v2:
            # Engine-level ingress size guard (SEC-017, CWE-770), mirroring the HL7 path's
            # enforce_size_limits (which measures len(norm) on the decoded str). Measure on the decoded
            # text the same way so the engine ceiling matches the HL7 path. Record ERROR + return None
            # (no HL7 ACK for non-HL7) — count-and-log, never crash the connection.
            if len(text) > _INGRESS_MAX_BYTES:
                await self.store.record_received(
                    channel_id=ic.name,
                    raw=text,
                    status=MessageStatus.ERROR,
                    error=f"ingress exceeds max size ({len(text)} > {_INGRESS_MAX_BYTES} bytes)",
                    source_type=src,
                    message_type=ic.content_type.value,
                )
                return None
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
            self._wake_lane(Stage.INGRESS, ic.name)  # B12: wake only this inbound's router lane
            return None

        try:
            peek = Peek.parse(text)
        except HL7PeekError as exc:
            parse_err = f"parse error: {safe_exc(exc)}"
            mid = await self.store.record_received(
                channel_id=ic.name,
                raw=text,
                status=MessageStatus.ERROR,
                error=parse_err,
                source_type=src,
            )
            ack = build_ack(text, code="AR", text=str(exc), ack_mode=ack_mode) if reply else None
            if ack is not None and self._capture_ack_enabled(ic):
                await self._capture_ack(
                    mid, ic.name, ack_code="AR", ack_phase="parse", ack_body=None, detail=parse_err
                )
            return ack

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
                mid = await self._record(ic, peek, text, MessageStatus.ERROR, error=persisted)
                # The AE ACK goes back to the partner that SENT this message (their own data) and is
                # transient (never persisted), so it may carry the fuller, bounded validation text.
                ack = (
                    build_ack(peek, code="AE", text=joined[:200], ack_mode=ack_mode)
                    if reply
                    else None
                )
                if ack is not None and self._capture_ack_enabled(ic):
                    # PHI-1: the DURABLE ack detail is the safe_text-scrubbed `persisted`, NEVER the raw
                    # `joined` (hl7apy quotes the offending field VALUE = PHI) — #120 preserved.
                    await self._capture_ack(
                        mid,
                        ic.name,
                        ack_code="AE",
                        ack_phase="strict",
                        ack_body=None,
                        detail=persisted,
                    )
                return ack

        # ACK-on-receipt (staged pipeline, ADR 0001 Step A): persist the raw message durably to the
        # ingress stage, then ACK. Routing/transform/delivery run AFTER the ACK in the ingress worker,
        # so a slow/hung router or outbound never stalls intake — and a router/handler failure no
        # longer NAKs the sender (it becomes a logged ERROR/dead-letter at the ingress stage). Decode,
        # parse, and strict validation above stay synchronous and still NAK, preserving the partner
        # contract for a malformed message. ack_after='delivered' (defer the ACK) is rejected at
        # wiring in Step A, so this is always ACK-on-ingest.
        mid = await self.store.enqueue_ingress(
            channel_id=ic.name,
            raw=text,
            control_id=peek.control_id,
            message_type=peek.message_type,
            source_type=src,
            summary=summarize(peek) or None,
        )
        self._wake_lane(
            Stage.INGRESS, ic.name
        )  # B12: wake only this inbound's router lane (was the herd)
        ack = build_ack(peek, code="AA", ack_mode=ack_mode) if reply else None
        if ack is not None and self._capture_ack_enabled(ic):
            # The AA frame echoes MSH/MSA control fields; record_ack_sent stores its body only on an
            # encrypted store (else NULL), so default-on capture never lands raw ACK PHI in the clear.
            await self._capture_ack(
                mid, ic.name, ack_code="AA", ack_phase="ingest", ack_body=ack, detail=None
            )
        return ack

    async def _record(
        self,
        ic: InboundConnection,
        peek: Peek,
        raw: str,  # already the decoded, \r-normalized text (see _handle_inbound)
        status: MessageStatus,
        *,
        error: str | None = None,
    ) -> str:
        return await self.store.record_received(
            channel_id=ic.name,
            raw=raw,
            status=status,
            error=error,
            control_id=peek.control_id,
            message_type=peek.message_type,
            source_type=ic.spec.type.value,
            summary=summarize(peek) or None,
        )

    async def _capture_ack(
        self,
        message_id: str,
        inbound_name: str,
        *,
        ack_code: str,
        ack_phase: str,
        ack_body: str | None,
        detail: str | None,
    ) -> None:
        """Record the "Response Sent" ACK/NAK we returned to the sender (ADR 0021, #46) — SYNCHRONOUSLY
        (no fire-and-forget vs key-rotation race) but **fail-soft**: a capture/store error must never
        flip the ACK already computed nor tear down the listener. The store applies the PHI fail-safe
        (AA body only on an encrypted store; every NAK body NULL; detail scrubbed)."""
        outcome = "accepted" if ack_code in ("AA", "CA") else "rejected"
        try:
            await self.store.record_ack_sent(
                message_id=message_id,
                inbound_name=inbound_name,
                ack_body=ack_body,
                ack_code=ack_code,
                ack_phase=ack_phase,
                outcome=outcome,
                detail=detail,
            )
        except Exception as exc:
            log.warning("ack capture failed for %r: %s", inbound_name, safe_exc(exc))

    # --- delivery path -------------------------------------------------------

    async def _delivery_worker(self, name: str) -> None:
        # B11: was the previous wait a wake (.set() — herd) or a poll-interval timeout (idle)? Seeds
        # False so the first claim at startup classifies as idle-poll, not a spurious wake.
        woken = False
        # B12 (ADR 0061): wait on THIS outbound lane's Event when per-lane wake is on (get-or-create also
        # registers the lane); else the shared singleton (byte-identical). Resolved once — the object is
        # stable for the worker's life (never replaced), so a sticky set survives a respawn.
        wait_ev = self._lane_event(Stage.OUTBOUND, name) if self._per_lane_wake else self._work
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
                    self._empty_claims.record_empty(woken=woken)  # B11 wall #3
                    woken = await self._wait_for_work(wait_ev)
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
                        await self._maybe_alert_stall(name)
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
                            await self._maybe_alert_stall(name)
                    except DeliveryError as exc:
                        # Transport failure (connect/IO/timeout/unparseable ACK) — transient; retry
                        # per policy (retry-forever by default, so nothing is silently lost).
                        await self.store.mark_failed(item.id, safe_exc(exc), retry)
                        await self._maybe_alert_buildup(name)
                        await self._maybe_alert_stall(name)
                        # #46: edge-trigger connection_lost (+ throttled alert) on the lane going down.
                        self._note_lane_unhealthy(name, item.id, exc)
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
                        # #46: a successful delivery means the lane is up — edge-trigger
                        # connection_restored if it had been marked down (no-op otherwise).
                        self._note_lane_healthy(name)
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
                                # B12 (ADR 0061): CROSS-LANE — wake the loopback's RESPONSE lane
                                # (reingress_to), NOT this delivery worker's own OUTBOUND lane.
                                self._wake_lane(Stage.RESPONSE, reingress_to)
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
        woken = False  # B11: previous wait was a wake (herd) vs poll-interval timeout (idle)?
        # B12 (ADR 0061): wait on THIS inbound's INGRESS lane Event when per-lane wake is on; else the
        # shared singleton (byte-identical). Resolved once — stable for the worker's life.
        wait_ev = (
            self._lane_event(Stage.INGRESS, name) if self._per_lane_wake else self._ingress_work
        )
        while not self._stop.is_set():
            try:
                # FIFO per inbound: claim the due head (ingress rows never back off, so this is
                # effectively the oldest pending row for this inbound). Under active-passive HA the graph
                # runs on the leader ONLY, so a single node drains this lane. ADR 0058: when
                # fifo_claim_batch == 1 (default) claim the single head (byte-identical); when > 1 claim
                # the contiguous due head-prefix in one commit and process each row in FIFO order below.
                if self._fifo_batch <= 1:
                    one = await self.store.claim_next_fifo(name, stage=Stage.INGRESS.value)
                    items = [one] if one is not None else []
                else:
                    items = await self.store.claim_next_fifo_batch(
                        name, stage=Stage.INGRESS.value, limit=self._fifo_batch
                    )
                if not items:
                    self._empty_claims.record_empty(woken=woken)  # B11 wall #3
                    woken = await self._wait_for_work(wait_ev)
                    continue
                for item in items:
                    ic = self.registry.inbound.get(name)
                    if ic is None:
                        # The inbound was removed from the registry but residual ingress rows remain.
                        # Revert this just-claimed row to pending and EXIT the worker — there is nothing to
                        # route it with until a reload restores the inbound (which re-arms this worker and
                        # drains the backlog). Reschedule with a retry-FOREVER policy (NOT the outbound
                        # delivery defaults, whose finite max_attempts would dead-letter an ACKed-but-
                        # never-attempted message purely for being removed) so the message is never
                        # dropped. The unprocessed batch tail stays INFLIGHT and is recovered in order by
                        # reset_stale_inflight on the next start/reload (ADR 0058 INV-3).
                        await self.store.mark_failed(
                            item.id, "inbound not in registry", RetryPolicy()
                        )
                        return
                    inline = self._inline_ok.get(name, False)
                    if inline:
                        # ADR 0057 G6 — ingress-lane attempts ceiling. The fused inline path widens the
                        # work under ONE re-runnable unit, so a deterministic process-crash (segfault/OOM,
                        # no exception to catch) inside route_only/transform_one/handoff would re-pend +
                        # re-run forever: C2 durably bumped attempts each pass, but no ingress/routed-lane
                        # path enforces max_attempts today (mark_failed's ceiling is delivery-only). Close
                        # that crash-loop here: a re-claimed item whose attempts have reached the finite
                        # delivery cap is dead-lettered (matches mark_failed's `attempts >= max_attempts`
                        # semantics, sqlserver.py mark_failed). max_attempts None = retry forever
                        # (no ceiling), unchanged.
                        max_attempts = self._delivery_defaults.max_attempts
                        if max_attempts is not None and item.attempts >= max_attempts:
                            log.warning(
                                "router worker %r: inline item %s exhausted ingress attempts "
                                "(%d >= %d); dead-lettering (poison-crash ceiling G6)",
                                name,
                                item.id,
                                item.attempts,
                                max_attempts,
                            )
                            await self.store.dead_letter_now(item.id, "ingress attempts exhausted")
                            continue
                    try:
                        # Publish the live graph's run-scoped views (code sets / reference snapshots /
                        # active environment) so a call-time code_set(...)/reference(...)/
                        # current_environment() inside the Router resolves (the loader only had them
                        # active during import). Views are read from self.registry/self.store live, so a
                        # reload's swapped tables apply to the next routed row; run_contexts restores
                        # cleanly after each run (no leak). The set of providers is the run_context
                        # registry (router phase) — features add one provider there, never edit this call.
                        with run_contexts(
                            RunContext(
                                code_sets=self.registry.code_sets,
                                reference_view=self.store.reference_view(),
                                active_environment=self._active_environment,
                                ingest_time=item.created_at,
                            ),
                            phase="router",
                        ):
                            # Run the Router OFF the event loop (SEC-013, CWE-1322). A Router is arbitrary
                            # synchronous Python whose CPU cost can scale with attacker-influenced content
                            # (ReDoS over a field, O(n^2) build); running it inline would let one message
                            # stall the single loop, freezing every listener, worker, and the API.
                            # asyncio.to_thread copies THIS context (the run_contexts views) into the
                            # worker thread, so a call-time code_set()/reference()/current_environment()
                            # still resolves. db_lookup raises on a Router by design, so no lookup runner.
                            names = await asyncio.to_thread(
                                route_only, self.registry, ic, item.payload
                            )
                        # ADR 0057 inline Step-A fast-path (G1: this whole block is INSIDE the inner try,
                        # so a raise from transform_one OR handoff routes to the internal_error policy
                        # below — NOT the outer retry-forever except). Eligible iff the inbound opted in
                        # AND the graph has no live lookup AND ack_after=ingest AND not LOOPBACK
                        # (graph-level gates, cached in self._inline_ok) — plus the per-message gates here.
                        if inline and len(names) == 1:
                            # M-single held. Run the single handler's transform OFF the loop (G4: keep the
                            # to_thread hop — SEC-013), mirroring _transform_worker. No lookup ExitStack:
                            # self._inline_ok already guaranteed no live lookup runner (INV-7), so a
                            # db_lookup()/fhir_lookup() inside the handler raises (fail-closed) — no hang.
                            hname = names[0]
                            content_type = ic.content_type.value
                            with run_contexts(
                                RunContext(
                                    code_sets=self.registry.code_sets,
                                    reference_view=self.store.reference_view(),
                                    state_view=self.store.state_view(),
                                    response_view=None,
                                    active_environment=self._active_environment,
                                    ingest_time=item.created_at,
                                ),
                                phase="transform",
                            ):
                                deliveries_preview, state_preview = await asyncio.to_thread(
                                    transform_one,
                                    self.registry,
                                    hname,
                                    item.payload,
                                    content_type,
                                )
                            # Split deliveries / pass-through / state exactly as the transform worker does.
                            deliveries = [
                                (d.to, d.payload)
                                for d in deliveries_preview
                                if not d.is_passthrough
                            ]
                            pt_deliveries = [d for d in deliveries_preview if d.is_passthrough]
                            state_ops = list(state_preview)
                            # M-deliver gate: only the pure all-deliver case is fused. A zero-delivery
                            # (filtering) handler, any state-op, or any pass-through Send FALLS BACK to the
                            # split path — handoff lacks _maybe_finalize (G2: a zero-delivery fused message
                            # would strand non-terminal) and the state-MERGE / PT-child machinery
                            # transform_handoff carries. The split path finalizes those correctly (FILTERED
                            # via transform_handoff's _maybe_finalize; state/PT via its dedicated handling).
                            if deliveries and not state_ops and not pt_deliveries:
                                # CF — the fused single commit: consume the ingress row, insert one
                                # outbound row per delivery, set ROUTED. G5: no DB connection/txn is held
                                # across the to_thread calls above — C2 committed + released before this
                                # block, and handoff opens a fresh txn now. Idempotent against a crash
                                # re-run (its DELETE-guard returns False as a no-op if the ingress row was
                                # already consumed — INV-1, no duplicate outbound).
                                await self.store.handoff(
                                    ingress_id=item.id,
                                    message_id=item.message_id,
                                    channel_id=name,
                                    deliveries=deliveries,
                                    disposition=MessageStatus.ROUTED,
                                )
                                # B12 (ADR 0061): fan-out — wake EACH distinct destination's delivery
                                # lane for the fused outbound rows (not one whole-stage set). OFF: each
                                # call sets the shared singleton (idempotent), net-identical to today.
                                for _dest in {d for d, _ in deliveries}:
                                    self._wake_lane(Stage.OUTBOUND, _dest)
                                continue  # fused — bypass the split route_handoff path entirely
                            # else: ineligible per-message → fall through to the split path verbatim.
                    except Exception as exc:
                        # Router code error (incl. an unknown handler name) OR — on the inline fast-path —
                        # a transform_one/handoff failure (G1). Post-ACK, so no NAK — the global
                        # internal_error policy decides. Log the exception TYPE only; full detail goes to
                        # the secured store's last_error, never the general log (PHI).
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
                        # B12 (ADR 0061): the routed rows are on THIS inbound's ROUTED lane (`name`) —
                        # wake only its transform worker.
                        self._wake_lane(Stage.ROUTED, name)
                # Off the hot path (rate-limited), ONCE PER BATCH (ADR 0058): alert if this inbound's
                # ingress backlog is building (a slow/hung router). Uses the global buildup threshold.
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
        woken = False  # B11: previous wait was a wake (herd) vs poll-interval timeout (idle)?
        # B12 (ADR 0061): wait on THIS loopback's RESPONSE lane Event when per-lane wake is on; else the
        # shared singleton (byte-identical). Resolved once.
        wait_ev = (
            self._lane_event(Stage.RESPONSE, name) if self._per_lane_wake else self._response_work
        )
        while not self._stop.is_set():
            try:
                item = await self.store.claim_next_fifo(name, stage=Stage.RESPONSE.value)
                if item is None:
                    self._empty_claims.record_empty(woken=woken)  # B11 wall #3 (loopback lane)
                    woken = await self._wait_for_work(wait_ev)
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
                    # wake for a depth-capped / peek-failed token that produced no ingress row). B12 (ADR
                    # 0061): the re-ingress lands on THIS loopback's own INGRESS lane (`name`).
                    self._wake_lane(Stage.INGRESS, name)
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
        woken = False  # B11: previous wait was a wake (herd) vs poll-interval timeout (idle)?
        # B12 (ADR 0061): wait on THIS inbound's ROUTED lane Event when per-lane wake is on; else the
        # shared singleton (byte-identical). Resolved once.
        wait_ev = self._lane_event(Stage.ROUTED, name) if self._per_lane_wake else self._routed_work
        while not self._stop.is_set():
            try:
                # FIFO per inbound at the routed stage. Under active-passive HA the graph runs on the
                # leader ONLY, so a single node drains this lane. ADR 0058: single head when
                # fifo_claim_batch == 1 (default, byte-identical); else the contiguous due head-prefix in
                # one commit, processed in FIFO order below.
                if self._fifo_batch <= 1:
                    one = await self.store.claim_next_fifo(name, stage=Stage.ROUTED.value)
                    items = [one] if one is not None else []
                else:
                    items = await self.store.claim_next_fifo_batch(
                        name, stage=Stage.ROUTED.value, limit=self._fifo_batch
                    )
                if not items:
                    self._empty_claims.record_empty(woken=woken)  # B11 wall #3
                    woken = await self._wait_for_work(wait_ev)
                    continue
                for item in items:
                    ic = self.registry.inbound.get(name)
                    if ic is None:
                        # Inbound removed; nothing to transform with until a reload restores it (which
                        # re-arms this worker). Revert the row (retry-forever) and exit (mirrors the
                        # router worker), so the ACKed-but-unprocessed message is never dropped. The
                        # unprocessed batch tail stays INFLIGHT and is recovered in order by
                        # reset_stale_inflight on the next start/reload (ADR 0058 INV-3).
                        await self.store.mark_failed(
                            item.id, "inbound not in registry", RetryPolicy()
                        )
                        return
                    hname = item.handler_name
                    if hname is None or hname not in self.registry.handlers:
                        # Handler gone (removed/renamed since routing). Can't transform this row;
                        # dead-letter it (message ERROR, replayable once restored) — the per-row analogue
                        # of the startup dead_letter_missing_handlers sweep. Dead-lettering (vs reverting)
                        # avoids a hot-loop on a permanently-missing handler and gives operator visibility.
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
                                c.destination_name: c
                                for c in await self.store.correlate_response(corr)
                            }
                    try:
                        # Same as the router worker, plus the transform-only providers: publish the
                        # run-scoped views so call-time code_set(...)/reference(...)/state_get(...)/
                        # current_environment() inside the Handler resolve; restored cleanly after the run.
                        # The transform phase adds the store's transform-state read-through cache view
                        # (ADR 0005) so state_get(...) resolves against committed writes. Providers come
                        # from the run_context registry (transform phase) — features add one provider,
                        # never edit this call site.
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
                            # Run the Handler's transform OFF the event loop UNCONDITIONALLY (SEC-013,
                            # CWE-1322). A Handler is arbitrary synchronous Python whose CPU cost can scale
                            # with attacker-influenced content (ReDoS, O(n^2) build, large fan-out); the
                            # old no-lookup fast-path ran it inline on the single loop, so one pathological
                            # message could stall every listener, worker, and the API. asyncio.to_thread
                            # copies THIS context (the run_contexts views, plus the lookup runner(s) when
                            # activated) into the worker thread, so code_set()/reference()/state_get()/
                            # current_environment() — and db_lookup()/fhir_lookup() on the lookup path —
                            # resolve there while the loop stays free.
                            content_type = self.registry.inbound[name].content_type.value
                            # Activate whichever live-lookup runner(s) the graph declares so a Handler call
                            # to db_lookup()/fhir_lookup() resolves inside the worker thread, bridging back
                            # onto the loop (run_coroutine_threadsafe). Both are the deliberate
                            # re-run-stability exception (ADR 0009/0010/0043) and raise in dry-run (no
                            # runner published there). When neither is declared the transform still hops off
                            # the loop (SEC-013) and both calls raise.
                            with ExitStack() as lookup_stack:
                                if self._lookup_executor is not None:
                                    lookup_stack.enter_context(
                                        db_lookup_activated(self._run_lookup)
                                    )
                                if self._fhir_lookup_executor is not None:
                                    lookup_stack.enter_context(
                                        fhir_lookup_activated(self._run_fhir_lookup)
                                    )
                                deliveries_preview, state_preview = await asyncio.to_thread(
                                    transform_one,
                                    self.registry,
                                    hname,
                                    item.payload,
                                    content_type,
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
                    # Split outbound deliveries from pass-through (PT) Sends (ADR 0013, generalized): a PT
                    # target re-ingresses the body through an internal inbound's own router (a fresh
                    # INGRESS row on the PT channel), produced atomically in the SAME transform_handoff
                    # transaction as the outbound rows + routed-row DELETE. transform_one already validated
                    # each target and tagged PT ones (is_passthrough).
                    deliveries = [
                        (d.to, d.payload) for d in deliveries_preview if not d.is_passthrough
                    ]
                    pt_deliveries = [
                        (d.to, d.payload) for d in deliveries_preview if d.is_passthrough
                    ]
                    state_ops = [(s.namespace, s.key, s.value) for s in state_preview]
                    await self.store.transform_handoff(
                        routed_id=item.id,
                        message_id=item.message_id,
                        channel_id=name,
                        deliveries=deliveries,
                        state_ops=state_ops,
                        pt_deliveries=pt_deliveries,
                        correlation_depth_cap=self._max_correlation_depth,
                    )
                    if deliveries:
                        # B12 (ADR 0061): fan-out — wake EACH distinct destination's delivery lane for
                        # the queued outbound rows (not one whole-stage set). OFF: each call sets the
                        # shared singleton (idempotent), net-identical to today.
                        for _dest in {d for d, _ in deliveries}:
                            self._wake_lane(Stage.OUTBOUND, _dest)
                    if pt_deliveries:
                        # A PT child INGRESS row was committed on EACH PT channel — wake those channels'
                        # router workers so they re-route without waiting for the idle-poll. B12 (ADR 0061):
                        # CROSS-LANE fan-out — wake each DISTINCT PT target's INGRESS lane (NOT this
                        # transforming inbound's own lane). OFF: each call sets the shared ingress singleton
                        # (idempotent), net-identical to the single pre-B12 set().
                        for _pt_target in {d for d, _ in pt_deliveries}:
                            self._wake_lane(Stage.INGRESS, _pt_target)
                # Off the hot path (rate-limited), ONCE PER BATCH (ADR 0058): alert if this inbound's
                # routed (transform) backlog is building behind a slow/hung handler — reported separately
                # from the ingress lane.
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

    async def _maybe_alert_stall(self, name: str) -> None:
        """Raise a ``message_stall`` alert if an outbound lane's **oldest undelivered message** has aged
        past the connection's resolved :class:`StallThreshold` (#50, Corepoint "Max Message Stall").

        Modeled exactly on :meth:`_maybe_alert_buildup` but a single age dimension, and it **reuses the
        same metric** — the oldest pending row's age (``delivered_age``) from ``store.pending_depth`` —
        rather than inventing a new one. Off by default: ``StallThreshold.max_oldest_seconds is None``
        disables it, so nothing fires unless an operator configures a threshold (deny-by-default). The
        re-alert is throttled per connection so an ongoing stall reminds without spamming; the sink must
        never raise (contract), but we guard so an alerting bug can't kill the worker."""
        threshold = self._stall.get(name) or self._stall_default
        if threshold.max_oldest_seconds is None:
            return  # stall alerting disabled for this lane (deny-by-default)
        now = time.time()
        if now < self._next_stall_alert.get(name, 0.0):
            return  # re-alert throttled
        depth, oldest_created = await self.store.pending_depth(name, stage=Stage.OUTBOUND.value)
        if depth == 0 or oldest_created is None:
            return
        oldest_age = now - oldest_created
        if oldest_age < threshold.max_oldest_seconds:
            return  # oldest message hasn't stalled long enough yet
        self._next_stall_alert[name] = now + _BUILDUP_REALERT_SECONDS
        try:
            self._alert_sink.message_stall(name, oldest_age_seconds=oldest_age)
        except Exception:
            log.exception("alert sink raised on message_stall for %r", name)

    async def _wait_for_work(self, event: asyncio.Event) -> bool:
        """Wait up to ``poll_interval`` for ``event`` (this worker class's wake event), then clear it.
        Per-class events mean a worker only clears its own signal, so one class can't swallow another's
        wakeup; ``poll_interval`` still backstops any missed set().

        Returns ``True`` if a wake event arrived (a producer ``.set()`` — the per-commit herd) and
        ``False`` if it timed out on the poll interval (an idle re-poll). The worker uses this to
        classify its NEXT empty claim as wake-fanout vs idle-poll (B11). Read-only: the return value is
        observability-only and never changes the wait/clear behavior."""
        woken = True
        try:
            await asyncio.wait_for(event.wait(), self.poll_interval)
        except asyncio.TimeoutError:
            woken = False
        finally:
            event.clear()
        return woken

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
    # allowlist are MLLP/TCP/DIMSE/X12/HTTP-only at wiring; all five are LISTEN types that bind an iface.)
    if ic.spec.type in (
        ConnectorType.MLLP,
        ConnectorType.TCP,
        ConnectorType.X12,
        ConnectorType.DIMSE,
        ConnectorType.HTTP,
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
    reserved_bindings: Sequence[tuple[str, str, int]] = (),
) -> None:
    """Construct (and discard) every connector in ``registry`` + run the fail-closed connect/egress
    allowlists, so a bad connector spec or a non-allowlisted host fails as a :class:`WiringError`
    BEFORE anything is applied. The standalone core of :meth:`RegistryRunner.build_check`, callable
    offline — e.g. the ``connection`` CLI validating an edit before it persists (ADR 0007). Builds
    nothing live (no socket bind / file I/O — binding happens later in ``start_inbound``)."""
    # Port-conflict pre-flight (env-resolved + reserved-port aware): a listener stealing a sibling's or
    # the API's (host, port) fails the whole reload here, before quiescing, naming both ends — rather
    # than half-applying and surfacing as a bare bind OSError. PortConflictError is a WiringError → 422.
    conflicts = inbound_binding_conflicts(
        registry,
        bind_host=inbound_bind_host,
        env_values=env_values,
        reserved=reserved_bindings,
    )
    if conflicts:
        raise PortConflictError("; ".join(conflicts))
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
        resolved_fhir_lookups: dict[str, dict[str, Any]] = {}
        for fname, fspec in registry.fhir_lookups.items():
            fsettings = resolve_env_settings(fspec.settings, env_values)
            check_fhir_lookup_allowed(
                fname, fsettings, egress
            )  # fail-closed egress allowlist (ADR 0043)
            resolved_fhir_lookups[fname] = fsettings
        if resolved_fhir_lookups:
            # Construct (and discard): validates each FHIR URL/TLS/SMART-auth without issuing a read.
            FhirLookupExecutor(resolved_fhir_lookups)
    except WiringError:
        raise
    except Exception as exc:
        raise WiringError(f"connector build failed: {exc}") from exc


def check_pt_backend_supported(registry: Registry, store: QueueStore) -> None:
    """Reject a graph with a pass-through (PT) inbound on a store backend that doesn't implement PT
    re-ingress, BEFORE any inbound listener accepts a message.

    **ALLOW-LIST semantics:** PT is permitted only on a backend whose ``supports_pt_reingress`` is
    ``True`` (SQLite today). Postgres, SQL Server, and any future backend default to ``False`` (set on
    the ``Store`` base), so a backend that hasn't implemented the ``pt_deliveries`` branch of
    :meth:`transform_handoff` is rejected here rather than at the first Handler ``Send`` into a PT
    connector (which would NotImplementedError *after* the inbound was already ACKed). Names the
    offending PT connection(s) and the backend.

    This is the **single source of truth** for the gate: it runs on EVERY config-application path —
    ``Engine.start`` calls it directly, and the reload (live-runner + runner-None bring-up) and
    ``reload(dry_run=True)`` paths reach it via :meth:`RegistryRunner.build_check` — so a PT-on-non-
    SQLite graph is rejected with a :class:`WiringError` (422) before any swap/start, leaving any
    already-running graph untouched. No-op when the backend supports PT or the graph has no PT inbound,
    so the SQLite path is byte-identical."""
    if getattr(store, "supports_pt_reingress", False):
        return  # backend opted in (SQLite) — PT is permitted, nothing to gate
    pt_inbounds = sorted(
        name for name, ic in registry.inbound.items() if ic.spec.type is ConnectorType.PT
    )
    if not pt_inbounds:
        return  # no PT connector in the graph — any backend is fine
    backend = getattr(store, "backend", None)
    backend_name = backend.value if isinstance(backend, StoreBackend) else type(store).__name__
    names = ", ".join(repr(n) for n in pt_inbounds)
    plural = "s" if len(pt_inbounds) > 1 else ""
    raise WiringError(
        f"Pass-through (PT) connector{plural} {names} require{'' if plural else 's'} the SQLite "
        f"store backend; backend {backend_name!r} does not support PT re-ingress yet."
    )


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
    if conn_type is ConnectorType.EMAIL:
        return egress.allowed_smtp  # SMTP destination (ADR 0029)
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


def _check_smart_token_url_egress(
    label: str, settings: Mapping[str, Any], allowed_http: list[str]
) -> None:
    """Gate a SMART Backend Services token endpoint (ADR 0024): the connector POSTs the signed
    ``client_assertion`` there, so a crafted ``smart_token_url`` pointing at an un-allowlisted host
    would exfiltrate the assertion (a fail-open hole). Shared by the FHIR **outbound** and the
    **FhirLookup** read arm so the two never drift out of lockstep — DELTA-04 was exactly that drift
    (the read arm gated only ``url``). Only REST/FHIR/FhirLookup carry the key; an unset value is a
    no-op. Call only when ``allowed_http`` is non-empty (matching the host gate's own guard)."""
    token_url = str(settings.get("smart_token_url", ""))
    if token_url and not _http_egress_allowed(token_url, allowed_http):
        host = urllib.parse.urlsplit(token_url).hostname or ""
        log.warning(
            "egress denied: %s SMART token endpoint host %r not in [egress].allowed_http",
            label,
            host,
        )
        raise WiringError(
            f"{label}: SMART token endpoint host {host!r} is not in the [egress].allowed_http allowlist"
        )


def check_fhir_lookup_allowed(
    name: str, settings: Mapping[str, Any], egress: EgressSettings
) -> None:
    """Fail-closed egress allowlist for a ``FhirLookup`` (it dials out to an HTTP(S) FHIR host for a live,
    read-only ``fhir_lookup``, ADR 0043). Reuses ``[egress].allowed_http`` — the **exact arm** the FHIR
    outbound + SMART token endpoint use (a read is an egress host) — checked at load/reload/start so the
    engine is never pointed at a non-allowlisted FHIR server. ``settings`` are the already-``env()``-resolved
    connection settings. Under ``[egress].deny_by_default`` an empty ``allowed_http`` refuses the read
    outright — an un-allowlisted FHIR read can never dial out (the SSRF-shaped fail-open is closed)."""
    if egress.deny_by_default and not egress.allowed_http:
        raise WiringError(
            f"FhirLookup {name!r}: [egress].deny_by_default is set and [egress].allowed_http is "
            "empty — list the FHIR host to permit it"
        )
    if egress.allowed_http:
        url = str(settings.get("url", ""))
        if not _http_egress_allowed(
            url, egress.allowed_http
        ):  # same host[:port] matching as the FHIR outbound
            host = urllib.parse.urlsplit(url).hostname or url
            log.warning(
                "connect denied: FhirLookup %r host %r not in [egress].allowed_http", name, host
            )
            raise WiringError(
                f"FhirLookup {name!r}: host {host!r} is not in the [egress].allowed_http allowlist"
            )
        # The SMART token endpoint (ADR 0024) is a SECOND egress host on this read arm — gate it with
        # the same allowlist as the FHIR outbound, or a crafted smart_token_url (set via
        # with_smart_backend()) exfiltrates the signed client_assertion to an unlisted host (DELTA-04).
        _check_smart_token_url_egress(f"FhirLookup {name!r}", settings, egress.allowed_http)


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


def check_http_tls_exposure(source: Source, name: str, *, allow_insecure_bind: bool) -> None:
    """Exposed-gate (ADR 0002 §0 / ADR 0023 §D4, HTTP side): refuse a **non-loopback inbound HTTP
    listener without TLS** — it would put POSTed bodies (frequently PHI: HL7-over-HTTP, FHIR, X12) on the
    wire in cleartext. The HTTP sibling of :func:`check_mllp_tls_exposure`. Like MLLP/DICOM the HTTP
    source *does* support TLS, so the escape hatch is ``tls=true`` (+ cert) on the ``Http(...)``
    connection; otherwise bind loopback or pass ``serve --allow-insecure-bind`` to accept the risk on a
    trusted segment (then warn). Loopback binds and TLS-on binds pass unconditionally."""
    if source.type is not ConnectorType.HTTP:
        return
    host = str(source.settings.get("host", "127.0.0.1"))
    if host in _LOOPBACK_HOSTS or source.settings.get("tls"):
        return
    if allow_insecure_bind:
        log.warning(
            "inbound %r binds non-loopback host %r for an HTTP listener without TLS "
            "(--allow-insecure-bind); POSTed bodies (frequently PHI) cross the network in cleartext — "
            "set tls=true (+ tls_cert_file/tls_key_file) on the Http connection.",
            name,
            host,
        )
        return
    raise WiringError(
        f"inbound connection {name!r} binds non-loopback host {host!r} without TLS; POSTed bodies "
        "(frequently PHI) would cross the network in cleartext. Set tls=true (+ tls_cert_file/"
        "tls_key_file) on the Http connection, or pass `serve --allow-insecure-bind` to accept the "
        "cleartext risk on a trusted, firewalled network."
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


def check_tcp_tls_exposure(source: Source, name: str, *, allow_insecure_bind: bool) -> None:
    """Exposed-gate (ADR 0002 §0, raw-TCP/X12 side): refuse a **non-loopback raw-TCP or X12 listener**
    on a cleartext bind — it would put raw-TCP/X12 payloads (frequently PHI: X12 270/271 eligibility,
    raw/FHIR bodies) on the wire in plaintext. The TCP/X12 sibling of :func:`check_mllp_tls_exposure`
    and :func:`check_dimse_tls_exposure`, generalizing the exposed-gate to the remaining cleartext-only
    LISTEN types. Unlike MLLP/DICOM these connectors are **plaintext-only** — they have **no** ``tls=``
    option (``asyncio.start_server`` is called with no ``ssl=`` arg), so there is no TLS escape hatch:
    the only ways forward are a loopback bind, OS-level firewall/segmentation, or
    ``serve --allow-insecure-bind`` to accept the cleartext risk (then warn). Loopback binds pass
    unconditionally; the guard no-ops for any non-TCP/X12 type."""
    if source.type not in (ConnectorType.TCP, ConnectorType.X12):
        return
    host = str(source.settings.get("host", "127.0.0.1"))
    if host in _LOOPBACK_HOSTS:
        return
    if allow_insecure_bind:
        log.warning(
            "inbound %r binds non-loopback host %r for a plaintext-only %s listener "
            "(--allow-insecure-bind); X12/raw-TCP payloads (frequently PHI) cross the network in "
            "cleartext — these listeners have no TLS, so firewall/segment them.",
            name,
            host,
            source.type.value.upper(),
        )
        return
    raise WiringError(
        f"inbound connection {name!r} binds non-loopback host {host!r} on a plaintext-only "
        f"{source.type.value.upper()} listener; raw-TCP/X12 payloads (frequently PHI) would cross the "
        "network in cleartext. TCP/X12 listeners are plaintext-only (no TLS option) — bind loopback, "
        "firewall/segment the port at the OS level, or pass `serve --allow-insecure-bind` to accept "
        "the cleartext risk on a trusted, firewalled network."
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
        # POSTs the signed client_assertion there — so gate it with the same allowlist. Shared helper,
        # so the FhirLookup read arm in check_fhir_lookup_allowed stays in lockstep (DELTA-04).
        _check_smart_token_url_egress(f"outbound {dest.name!r}", dest.settings, egress.allowed_http)
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
    elif dest.type is ConnectorType.EMAIL and egress.allowed_smtp:
        # SMTP destination (ADR 0029): the SMTP host is gated with the same host[:port] matching as
        # MLLP/TCP/DB, so a fat-fingered or hostile mail relay can't exfiltrate PHI.
        host = str(dest.settings.get("host", ""))
        port = dest.settings.get("port", 587)
        if not _mllp_egress_allowed(host, port, egress.allowed_smtp):  # same host[:port] matching
            log.warning(
                "egress denied: outbound %r EMAIL host %r not in [egress].allowed_smtp",
                dest.name,
                host,
            )
            raise WiringError(
                f"outbound {dest.name!r}: EMAIL host {host!r} is not in the "
                "[egress].allowed_smtp allowlist"
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
