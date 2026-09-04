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
import ipaddress
import json
import logging
import time
import urllib.parse
from collections.abc import Callable, Iterable, Mapping, Sequence
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import Enum, StrEnum
from pathlib import Path
from typing import Any, Protocol, cast

from messagefoundry.auth.ratelimit import SlidingWindowRateLimiter
from messagefoundry.config.db_lookup import DbLookupError
from messagefoundry.config.db_lookup import activated as db_lookup_activated
from messagefoundry.config.fhir_lookup import (
    FhirLookupError,
)
from messagefoundry.config.fhir_lookup import (
    activated as fhir_lookup_activated,
)
from messagefoundry.config.models import (
    AckAfter,
    AckMode,
    BatchConfig,
    BuildupThreshold,
    ConnectorType,
    ContentType,
    Destination,
    InternalErrorPolicy,
    OrderingMode,
    OutboundSigning,
    Priority,
    RetryPolicy,
    SaturationThreshold,
    Schedule,
    Source,
    StallThreshold,
)
from messagefoundry.config.run_context import RunContext, run_contexts
from messagefoundry.config.settings import DeliverySettings, EgressSettings, StoreBackend
from messagefoundry.config.tls_policy import (
    HopPosture,
    TrustAnchorPolicy,
    active_hop_posture,
    current_hop_posture,
    is_loopback_hop_host,
)
from messagefoundry.config.wiring import (
    InboundConnection,
    OutboundConnection,
    PortConflictError,
    Registry,
    WiringError,
    apply_sync_reply_capture_implication,
    bindings_overlap,
    inbound_binding_conflicts,
    resolve_env_settings,
    resolve_listener_binding,
)
from messagefoundry.logging_guard import LogSinkEvent
from messagefoundry.logging_guard import active_guard as active_log_guard
from messagefoundry.parsing import (
    HL7PeekError,
    Peek,
    RawMessage,
    encode_batch,
    normalize,
    summarize,
    validate,
)
from messagefoundry.parsing.binary import (
    DOC_REF_MARKER,
    DocRefError,
    chunk_b64,
    iter_obx_documents,
    make_doc_ref,
    reattach_documents_in_hl7,
)
from messagefoundry.parsing.message import Message
from messagefoundry.parsing.peek import DEFAULT_MAX_MESSAGE_BYTES
from messagefoundry.parsing.sniff import attachment_mime_agrees, b64_head
from messagefoundry.pipeline.alerts import AlertSink, LoggingAlertSink
from messagefoundry.pipeline.cluster import ClusterCoordinator, NullCoordinator
from messagefoundry.pipeline.dryrun import TransformOutcome, route_only, transform_one
from messagefoundry.pipeline.phase_timing import (
    # Explicit re-exports (`as`): the pre-#842 import surface — tests and the harness node-log parser
    # import these names from wiring_runner, not from phase_timing.
    _DELIVERY_PHASE_EMIT_INTERVAL as _DELIVERY_PHASE_EMIT_INTERVAL,
)
from messagefoundry.pipeline.phase_timing import (
    DELIVERY_PHASE_TIMING_ENV as DELIVERY_PHASE_TIMING_ENV,
)
from messagefoundry.pipeline.phase_timing import (
    ClaimPhaseTiming,
    DeliveryPhaseTiming,
    delivery_phase_timing_enabled,
)
from messagefoundry.pipeline.reply_wait import ReplyRendezvous
from messagefoundry.pipeline.sandbox import SandboxMode, SandboxPolicy, SandboxSession
from messagefoundry.pipeline.saturation import SaturationDetector
from messagefoundry.pipeline.sharding import owner_shard_of_destination
from messagefoundry.pipeline.stage_dispatcher import (
    LaneItemResult,
    LaneResultKind,
    StageDispatcher,
)
from messagefoundry.pipeline.sync_reply import SyncReplyMetrics, SyncReplyResolverImpl
from messagefoundry.redaction import safe_exc, safe_text
from messagefoundry.store import (
    MessageStatus,
    OutboxItem,
    QueueStore,
    Stage,
    StreamingAttachmentsUnsupported,
)
from messagefoundry.store.base import AuditStore, pool_over_provisioned_warning
from messagefoundry.store.metadata import user_metadata
from messagefoundry.transports import (
    DeliveryError,
    DestinationConnector,
    NegativeAckError,
    SourceConnector,
    build_destination,
    build_source,
)
from messagefoundry.transports.base import (
    ConnectionEventSink,
    IntakeAuditSink,
    IntakeRateLimiter,
    SyncReplyResolver,
)
from messagefoundry.transports.database import DatabaseLookupExecutor
from messagefoundry.transports.fhir import FhirLookupExecutor
from messagefoundry.transports.mllp import build_ack

__all__ = ["NotDeployedError", "RegistryRunner", "ShardLaneOwnershipError"]

log = logging.getLogger(__name__)

# Process-in-place dedup-ledger prune policy (ADR 0129, BACKLOG #142): bound the store's processed_files
# table per connection by age AND count. Applied once per poll tick, only when a new file was recorded,
# so a stable read-only share never churns the store.
PROCESSED_FILE_LEDGER_TTL_SECONDS = 30 * 24 * 3600  # 30 days
PROCESSED_FILE_LEDGER_KEEP_MAX = 100_000


#: Peers whose successful authentication we remember, to exempt them from the GLOBAL failed-attempt
#: arm (AC-19). Bounded so a churn of distinct source addresses cannot grow it without limit.
_INTAKE_SUCCESS_KEEP_MAX = 10_000


class _IntakeRateLimiter:
    """Runner-side failed-attempt budget for an intake-authenticating source (ADR 0154 D6).

    Two windows, deliberately:

    * **per-peer** — bounds one address guessing a credential;
    * **global** — bounds aggregate refusal volume, which matters because every refusal drives an
      ``audit_log`` write that takes the store-wide lock.

    **The global arm never refuses a peer that has already authenticated in this window** (AC-19).
    ``SlidingWindowRateLimiter`` refuses on the global bucket *regardless of key*, so consulting it for
    everyone would hand an attacker a denial-of-service against a legitimate partner: roughly one bad
    request per second exhausts the shared budget, and the partner's valid message is then refused
    ``429`` **pre-ingress**, where it is not even counted. That is exactly the silent-loss defect this
    design exists to avoid, merely relocated from the per-peer arm to the global one.

    Injected as a synchronous predicate, so ``transports/`` gains no ``auth/`` edge. In-process and
    non-distributed: under HA only the leader binds (so it is effectively global), and under engine
    sharding each shard counts separately, making the effective ceiling N x limit for N shards.
    """

    def __init__(self, *, per_peer: int, glob: int, window_seconds: float = 60.0) -> None:
        self._window = window_seconds
        self._per_peer = SlidingWindowRateLimiter(
            per_key=per_peer, glob=0, window_seconds=window_seconds
        )
        self._global = (
            SlidingWindowRateLimiter(per_key=0, glob=glob, window_seconds=window_seconds)
            if glob
            else None
        )
        self._succeeded: dict[str, float] = {}

    def check(self, peer: str) -> bool:
        # would_allow, never allow: consulting must not consume the budget, or a correctly
        # authenticated partner's Nth request would be refused as though it had been guessing.
        if not self._per_peer.would_allow(peer):
            return False
        if self._global is None or self._authenticated_recently(peer):
            return True
        return self._global.would_allow(peer)

    def charge_failure(self, peer: str) -> None:
        self._per_peer.allow(peer)
        if self._global is not None:
            self._global.allow(peer)

    def note_success(self, peer: str) -> None:
        now = time.monotonic()
        if len(self._succeeded) >= _INTAKE_SUCCESS_KEEP_MAX:
            cutoff = now - self._window
            self._succeeded = {k: v for k, v in self._succeeded.items() if v > cutoff}
        self._succeeded[peer] = now

    def _authenticated_recently(self, peer: str) -> bool:
        stamp = self._succeeded.get(peer)
        if stamp is None:
            return False
        if time.monotonic() - stamp > self._window:
            del self._succeeded[peer]
            return False
        return True


class _StoreProcessedLedger:
    """Runner-side adapter backing a leave-in-place (``after_read='leave'``, BACKLOG #142) poll source's
    dedup ledger with the store's ``processed_files`` table, closing over the inbound's channel id.
    Injected via the source's :attr:`~messagefoundry.transports.base.SourceConnector.processed_ledger`
    seam so ``transports/`` never imports ``store/``; the source passes only a **HASHED** ``file_key``
    (never a cleartext filename). :meth:`prune` bounds growth by age + count."""

    def __init__(self, store: QueueStore, channel_id: str) -> None:
        self._store = store
        self._channel_id = channel_id

    async def is_processed(self, file_key: str) -> bool:
        return await self._store.is_file_processed(channel_id=self._channel_id, file_key=file_key)

    async def mark_processed(self, file_key: str) -> None:
        await self._store.record_processed_file(channel_id=self._channel_id, file_key=file_key)

    async def prune(self) -> None:
        await self._store.prune_processed_files(
            channel_id=self._channel_id,
            older_than=time.time() - PROCESSED_FILE_LEDGER_TTL_SECONDS,
            keep_last=PROCESSED_FILE_LEDGER_KEEP_MAX,
        )


class NotDeployedError(RuntimeError):
    """A runtime CONTROL (start/restart — and, at the API layer, resend) targeted a connection that is
    present in the graph but ``deployed=False`` (#233, ADR 0111).

    Raised instead of acting, because there is nothing to act ON: a not-deployed connection has no
    connector (its ``env()`` values may not even exist yet), no listener, and — for an outbound — no
    delivery worker at all. Unlike ``auto_start=False`` (deployed, just not up right now — an operator
    start is the *designed* override), deploying a connection is a **config change, not a runtime
    action**: flip ``deployed`` and reload. Starting it here would resolve secrets that were never
    provisioned and half-wire a lane the graph says does not exist yet. The API maps this to 409."""

    def __init__(self, name: str) -> None:
        super().__init__(
            f"connection {name!r} is present in the config but NOT deployed (deployed=false) — "
            "deploying it is a config change, not a runtime action: set deployed=true (and supply "
            "its env() values), then reload"
        )
        self.name = name


class ShardLaneOwnershipError(RuntimeError):
    """An outbound CONTROL (pause/resume/restart — and, at the API layer, purge) targeted a lane
    another engine shard owns (ADR 0073). Raised instead of acting: a non-owning shard has no
    delivery worker/dispatcher lane, so its pause would report quiesced INSTANTLY and unlock the
    require-stopped purge while the owning shard keeps claiming and delivering. The API maps this to
    409, naming the owner so the operator can retarget that shard's API/console tab."""

    def __init__(self, name: str, *, owner: str | None, shard: str | None) -> None:
        super().__init__(
            f"outbound {name!r} is owned by engine shard {owner!r} (this is shard {shard!r}) — "
            "issue the control against the owning shard's API"
        )
        self.name = name
        self.owner = owner
        self.shard = shard


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

# BACKLOG #214: default cap on how many of ONE message's sibling routed rows transform CONCURRENTLY in
# the transform worker. 1 = OFF (the exact sequential handoff loop, byte-identical to pre-#214). > 1
# overlaps the pure off-loop transforms of a message's co-claimed sibling rows (bounded by this cap,
# min'd with the run length) while every store handoff stays serial + in claim order — so the single-
# serial-writer invariant per-destination outbound FIFO relies on is untouched. It doubles as the live-
# lookup (db_lookup/fhir_lookup) fan-out guard. Kept a module constant / instance attribute — NOT a
# [transform] settings section (owner-coordinated); a user-facing knob is a deliberate follow-up.
_DEFAULT_TRANSFORM_CONCURRENCY = 1

# ADR 0073: how often a SHARDED engine's read-only watchdog re-checks the buildup/stall thresholds
# of the outbound lanes it does NOT own. With one delivery consumer per lane, a hung (not crashed)
# owner would otherwise stall its lanes with zero paging anywhere — the supervisor's liveness test
# is process-exit only, and the buildup/stall alerts fire only in the owner's delivery path.
_SHARD_WATCHDOG_INTERVAL_SECONDS = 30.0

# WS-C empty-claim storm (2026-07-02 bench finding; amends ADR 0061). With per-lane wake ON, a
# committed row wakes ITS lane's worker directly, so the poll backstop is no longer the normal-case
# latency path — it is only a lost-wake SAFETY NET. At connection scale a short backstop makes
# O(lanes × stages) idle workers re-claim the shared queue every poll_interval — a store-side
# empty-claim storm that saturated the bench store box (UPDLOCK convoy, ~92% CPU) at ZERO message
# volume, inert to poll_interval and pool_size. With wake ON we back the idle poll off to this long
# interval. At-least-once is preserved WITHOUT the short poll because every deferred-work path now
# has its own wake: a producer commit wakes the lane (ADR 0061); a mark_failed retry ARMS a timer
# for its next_attempt_at (_mark_failed_and_arm); startup/promotion recovery precedes worker spawn
# (the first loop iteration always claims); a clustered lease reclaim calls notify_work. The
# backstop only bounds a genuinely lost wake — added latency, never loss (workers always re-claim
# at the top of the loop). per_lane_wake=OFF keeps poll_interval (byte-identical).
_PER_LANE_IDLE_BACKSTOP_SECONDS = 30.0
# Arm the retry wake a hair past next_attempt_at so the claim's `next_attempt_at <= now` predicate
# is already true when the woken worker claims (an early wake would claim nothing and then sleep a
# full backstop — worse than no wake).
_RETRY_WAKE_SLACK_SECONDS = 0.05

# #134 (ADR 0082): the batch delivery body's coalescing poll slice — how long it waits between
# top-up claims while a partial batch is still filling (bounded by the head's max_wait_ms deadline).
# Small so a graceful stop / a newly-arrived row is observed promptly; the deadline (not this) bounds
# the total wait.
_BATCH_POLL_SECONDS = 0.02

# How long the handler's worker thread blocks on a single db_lookup() before giving up (ADR 0010).
# A live lookup that exceeds this raises (→ the message's transform fails and dead-letters) rather than
# pinning a worker thread forever; the orphaned query still completes on the loop and releases its conn.
_LOOKUP_RESULT_TIMEOUT_SECONDS = 30.0

# How long a single strict hl7apy validate may run before the message dead-letters (#89, DoS backstop).
# Mirrors the _LOOKUP_RESULT_TIMEOUT_SECONDS rationale: a pathological body that makes hl7apy's
# structure/cardinality parse spin can otherwise pin the listener's off-loop worker; the timeout frees
# the listener and routes the message to ERROR/dead-letter. It CANNOT kill the to_thread worker (no
# thread cancellation in CPython) — the orphaned validate leaks its thread until it returns, bounded by
# the 16 MiB / segment caps enforce_size_limits fires BEFORE the slow parse (validate.py). Per-inbound
# `validation.strict_timeout_s` overrides this; <= 0 there disables the backstop entirely. Owner-tunable.
_STRICT_VALIDATE_TIMEOUT_SECONDS = 5.0


def _strict_validate_timeout(ic: InboundConnection) -> float | None:
    """The effective wall-clock (seconds) for this inbound's strict validate, or ``None`` if disabled.

    Resolves the per-connection ``validation.strict_timeout_s`` against the engine default (#89):
    ``None`` inherits ``_STRICT_VALIDATE_TIMEOUT_SECONDS``; ``<= 0`` disables the backstop (returns
    ``None`` → the caller runs the validate un-timed, the pre-#89 behaviour). The value is trusted config,
    not an HL7 field."""
    configured = ic.validation.strict_timeout_s
    effective = _STRICT_VALIDATE_TIMEOUT_SECONDS if configured is None else configured
    return effective if effective > 0 else None


# Engine-level ingress size ceiling for NON-HL7 content types (SEC-017, CWE-770). The HL7 path already
# enforces this via Peek.parse → enforce_size_limits; the binary/text branches had only the per-transport
# frame cap (each individually disable-able with max_frame_bytes=0). Mirroring the HL7 cap here makes the
# 16 MiB ceiling an engine-level invariant (belt-and-suspenders) rather than a per-transport one, so an
# operator who disabled a transport cap (or a future transport that ships without one) still can't buffer
# a multi-GB body whole. Measured on the raw BYTES pre-base64-inflation (binary) / the decoded str (text,
# matching enforce_size_limits' len(norm) convention).
_INGRESS_MAX_BYTES = DEFAULT_MAX_MESSAGE_BYTES

# The generic MIME a detached document's stored content_type is downgraded to when the sender-declared
# OBX-5.2 label contradicts the document's magic bytes (ASVS 1.3.4/5.2.2). Matches the download route's
# _DEFAULT_ATTACHMENT_MIME so a mislabelled active-content payload is served as inert bytes either way.
_DEFAULT_ATTACHMENT_MIME = "application/octet-stream"


def _nul_safe_error_raw(raw: bytes, content_type: str, *, text: str | None = None) -> str:
    """Return a store-bindable ``str`` for a failed-ingress ``raw`` (INGEST-4 / ADR 0028 §168).

    The ERROR/dead-letter paths store a byte view of the rejected body. A latin-1 (or decoded) view
    that carries a NUL (U+0000) is store-hostile: Postgres REJECTS it at bind (the raise is uncaught,
    unwinds out of ``_handle_inbound`` into the transport's ``except`` and drops the whole TCP
    connection with NO ERROR row — a count-and-log violation, CLAUDE.md §2), and SQLite/SQL Server
    truncate the stored value at the first NUL. U+0000 is the ONLY store-hostile latin-1 codepoint
    (U+0001..U+00FF ride TEXT/NVARCHAR intact), so we keep the faithful, human-readable view when it
    is NUL-free and escalate to the ADR 0028 ``mfb64:v1:`` byte-carriage only when a NUL is present —
    the exact original bytes are then recoverable via ``RawMessage.raw_bytes``. Because ``b"\\x00" in
    raw`` and ``"\\x00" in raw.decode("latin-1")`` are bijective, the NUL check on the view is exact.

    ``text`` supplies an already-decoded view (the post-decode NUL guard reuses this helper); when
    omitted the pre-decode ERROR paths get the lossless ``latin-1`` view of the raw bytes."""
    view = text if text is not None else raw.decode("latin-1")
    if "\x00" not in view:
        return view
    return RawMessage.from_bytes(raw, content_type).raw


class _StreamBudgetExceeded(Exception):
    """A very-large-document detach was refused because it would push the aggregate in-flight streaming
    budget ([inbound].stream_inflight_budget_bytes) over its ceiling (#149, ADR 0105 Phase 1a) — the
    backpressure DoS guard that replaces the frame cap. Caught in the ingress path and turned into an
    ``ERROR`` disposition + NAK (never accepted-and-dropped), exactly like an over-cap message."""


# OSError errnos a listener bind raises when the (host, port) can't be taken — classified into a clear
# PortConflictError naming the connection + binding, instead of a bare unattributed OSError aborting the
# inbound. EADDRINUSE: another process/instance holds it; EADDRNOTAVAIL: the bind_address isn't a local
# interface; EACCES: a privileged port (<1024) without permission. The within-graph + reserved-port
# cases are caught statically before the bind (_guard_port_conflict); this catches the EXTERNAL ones.
_BIND_CONFLICT_ERRNOS = frozenset({errno.EADDRINUSE, errno.EADDRNOTAVAIL, errno.EACCES})

# ADR 0066: the two stages whose pooled claim batches the contiguous due head-prefix (per_lane_limit =
# fifo_claim_batch). OUTBOUND/RESPONSE are hard-1 (the dispatcher re-clamps; H2 atomicity + single-
# outstanding-head retry semantics — exactly as ADR 0058 excludes them from batching).
_PREFIX_STAGES = frozenset({Stage.INGRESS, Stage.ROUTED})


class TeardownReason(StrEnum):
    """Why :meth:`RegistryRunner._teardown_unsafe` is running (ADR 0157 C6).

    SHUTDOWN — the historical single path (process stop, a failed start's unwind). Statement-for-
    statement unchanged, and the ONLY value single-node SQLite can reach: the only DEMOTE caller is
    ``Engine._stop_graph``, reachable only from ``_reconcile_graph``, which runs only under
    ``is_clustered()`` — and ``[cluster].enabled`` is rejected on SQLite at config load.
    DEMOTE — loss of leadership, racing a lease this node no longer holds. Dispatchers drain
    cooperatively BEFORE any hard cancel, and both phases are bounded. An inbound that cannot stop
    inside the budget is ABANDONED — not awaited, and not cancelled."""

    SHUTDOWN = "shutdown"
    DEMOTE = "demote"


#: Share of the demotion budget given to the cooperative quiesce phase. Larger than the source
#: share because quiesce overrun is the only one that can STRAND: a hard-cancelled serializer
#: leaves rows INFLIGHT, whereas an abandoned listener is duplicate-direction.
_DEMOTE_QUIESCE_SHARE = 0.7
#: Used only if a caller passes no budget. Equals the stock 10/20/30 derivation; unreachable single-node.
_DEMOTE_BUDGET_FALLBACK_SECONDS = 4.5
#: How long start() waits for a PRIOR demotion's abandoned stops before cancelling them. Sized to
#: 2x the client-shutdown grace because MLLP/TCP/X12/HTTP each consume that grace TWICE, serially,
#: inside one stop() — a 1x bound would cancel in precisely the slow-but-healthy case it exists to
#: settle, taking the ADR 0031 rebind-failure branch instead.
_PENDING_STOP_SETTLE_SECONDS = 10.0


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
    #: BACKLOG #1270. Claim ROUND-TRIPS the store aborted on a lock timeout — a different unit from
    #: every other field here, which is why it takes a different noun. The three above count LANES; a
    #: 256-lane chunk that aborts adds 256 to ``total`` and **1** to this. Do not divide one by the
    #: other: they are not a part and a whole. #1270's first attempt made exactly that mistake, naming
    #: a per-attempt event with a per-lane word and documenting it as a sub-count of ``total``.
    #:
    #: The two counters above classify why the WORKER was awake and are structurally blind to why the
    #: STORE returned nothing; this is the store-side axis. It asserts one thing: "a claim attempt
    #: aborted on a lock timeout, so at least one row it needed was held". It never names a lane and
    #: never says HOW MANY lanes were held — after the rollback the store has read no row.
    #:
    #: **POOLED MODE ONLY, and zero does NOT mean "no contention".** Only the dispatcher calls
    #: ``claim_fifo_heads``; the four per-lane worker call sites cannot observe an abort at all, so a
    #: per-lane engine reports zero forever. Postgres's ``FOR UPDATE SKIP LOCKED`` does not abort, so
    #: it structurally produces no such event either. Zero reads as NOT ESTABLISHED, never as a clean
    #: bill — the same absence-of-a-veto rule the occupancy fence carries.
    claim_lock_timeouts: int = 0

    def record_empty(self, *, woken: bool) -> None:
        """Account one empty claim FOR ONE LANE, classified by whether the worker was last *woken*
        (wake-fanout) or timed out on the poll interval (idle-poll)."""
        self.total += 1
        if woken:
            self.wake_fanout += 1
        else:
            self.idle_poll += 1

    def record_claim_lock_timeout(self) -> None:
        """Account ONE claim round-trip the store aborted on a lock timeout (BACKLOG #1270).

        Once per aborted ATTEMPT, never once per lane in the chunk: the lanes it covered are already
        booked by :meth:`record_empty`, and the store cannot say which of them was actually held."""
        self.claim_lock_timeouts += 1


# --- bench-gated per-delivery phase timing (default OFF) --------------------------------------------
# The delivery-body sub-phases (send_ack, mark_done) now live in phase_timing.py alongside the CLAIM
# phase: the 2026-07-09 rig ladder showed those two body phases account for only 9-18 ms of a 62-190 ms
# per-lane delivery cycle. The claim round-trip that RE-FEEDS the lane is the rest of it, and is timed
# by ClaimPhaseTiming. Reading either alone attributes the ceiling to the wrong phase — #842's premise
# ("it is EITHER send_ack OR mark_done") was false. DELIVERY_PHASE_TIMING_ENV / DeliveryPhaseTiming /
# delivery_phase_timing_enabled are imported at the top of this module; the names re-export unchanged
# from here, so the pre-existing import surface (tests + the harness log parser) still resolves.


class _ItemOutcome(Enum):
    """How a worker's per-item body resolved one claimed row — the loop control flow expressed as
    data (ADR 0066, the shared-body extraction). Each ``_process_*_item`` method returns one of
    these and its worker loop translates it back to the loop's control flow:

    * ``PROCESSED`` — the row reached a terminal state for this pass (handed off / delivered /
      retried-with-backoff / dead-lettered): the loop advances to the next claimed item.
    * ``STOPPED`` — the lane must halt (a STOP internal-error policy, or a missing-inbound exit):
      the worker returns and stays down until a reload/restart re-arms it.

    Scope (PR1, this commit): these two members carry today's per_lane loops exactly — every branch
    that re-pends with backoff (``mark_failed``) and every clean/dead-letter branch both map to the
    loop's ``continue``, so a single ``PROCESSED`` is byte-identical here. The park-vs-idle
    distinction the pooled StageDispatcher needs (ADR 0066 §4.5: a retryable failure → ``PARKED(until
    = mark_failed's next_attempt_at)`` + exact timer, vs a clean/dead-letter-CONTINUE → IDLE/READY)
    is NOT expressible in these two members and is **deliberately deferred to the pooled-dispatcher
    PR**, which will surface the retry-park case (and thread through the ``next_attempt_at`` that
    ``_mark_failed_and_arm`` computes) so the dispatcher never re-reads the store to find the park
    deadline. Do not read ``PROCESSED`` as sufficient for that transition — it is the per_lane
    ``continue``, not the pooled park signal.

    Module-private by design — a control-flow carrier between the loops and the extracted bodies,
    not an API."""

    PROCESSED = "processed"
    STOPPED = "stopped"


def _to_lane_result(outcome: tuple[_ItemOutcome, float | None]) -> LaneItemResult:
    """Map a ``_process_*_item`` result (the per_lane control-flow carrier) onto the pooled
    dispatcher's :class:`LaneItemResult` (ADR 0066 §4.5): ``(PROCESSED, None)`` → ``RESOLVED``,
    ``(PROCESSED, next_attempt_at)`` → ``RETRY`` (park the lane until that deadline), ``(STOPPED, _)``
    → ``STOP``. Only the delivery body ever surfaces a non-``None`` ``retry_until`` (ingress / routed /
    response never re-pend-with-backoff, so they always resolve or stop). The per_lane worker loops
    ignore this mapping — they read ``outcome[0]`` directly; it exists only for the pooled adapters."""
    item_outcome, retry_until = outcome
    if item_outcome is _ItemOutcome.STOPPED:
        return LaneItemResult(LaneResultKind.STOP)
    if retry_until is not None:
        return LaneItemResult(LaneResultKind.RETRY, retry_until)
    return LaneItemResult(LaneResultKind.RESOLVED)


@dataclass(frozen=True)
class _RoutedPrep:
    """The pure/read-only result of preparing ONE routed row for its (serial) handoff — BACKLOG #214.

    Splitting the transform *computation* (pure, off-loop, no store write) from the *handoff* (the sole
    per-lane writer) is what lets a message's sibling routed rows overlap their transforms concurrently
    while every store handoff stays serial and in ascending claim order — so per-destination outbound
    FIFO (``ORDER BY seq``, ADR 0059; correct only under one serial writer per lane) is preserved.
    Exactly one field is populated: ``missing_handler`` (the row's handler is gone → dead-letter on
    apply), ``error`` (the handler raised → internal-error policy on apply), or ``outcome`` (the
    transform produced deliveries/state/meta to hand off). A handler raise is captured here rather than
    raised so a concurrent ``gather`` never cancels a sibling (ADR 0057 policy is applied on the serial
    apply, in claim order)."""

    missing_handler: bool = False
    error: Exception | None = None
    outcome: TransformOutcome | None = None


def _contiguous_by_message(items: Sequence[OutboxItem]) -> list[list[OutboxItem]]:
    """Partition a FIFO-ordered routed batch into maximal runs of CONSECUTIVE rows sharing a
    ``message_id`` (BACKLOG #214). A message's routed rows are produced contiguously in one
    ``route_handoff`` transaction (ascending ``seq``), so each run is exactly one message's sibling rows
    — the unit whose transforms may overlap. Order within and across runs is the batch's claim order, so
    a serial in-order handoff over the runs preserves global claim order."""
    runs: list[list[OutboxItem]] = []
    for item in items:
        if runs and runs[-1][0].message_id == item.message_id:
            runs[-1].append(item)
        else:
            runs.append([item])
    return runs


class _FusedHandoffStore(Protocol):
    """The synchronous fused-handoff surface a fused worker hop drives (ADR 0071 B5, PR1). Only the SQL
    Server store ships it (``supports_fused_sync_handoff``); the base ``QueueStore`` protocol declares
    just the capability flag, so this narrows ``self.store`` at the SQL-Server-scoped fusion call sites
    (via ``cast``) without importing the concrete store into ``pipeline/`` or widening the base
    protocol. A ``cast`` is a typing-only assertion — every call to a method here is already guarded by
    ``self._fusion_active`` (True only on SQL Server)."""

    def open_sync_handoff_pool(self, stage: str, size: int) -> Any: ...
    def sync_handoff_pool(self, stage: str) -> Any: ...
    def close_sync_handoff_pool(self) -> None: ...
    def route_handoff_sync(
        self,
        conn: Any,
        *,
        ingress_id: str,
        message_id: str,
        channel_id: str,
        handlers: Sequence[tuple[str, str]],
        disposition: MessageStatus,
        now: float | None = None,
    ) -> bool: ...
    def transform_handoff_sync(
        self,
        conn: Any,
        *,
        routed_id: str,
        message_id: str,
        channel_id: str,
        deliveries: Sequence[tuple[str, str]],
        state_ops: Sequence[tuple[str, str, Any]] = (),
        pt_deliveries: Sequence[tuple[str, str]] = (),
        meta_ops: Sequence[tuple[str, str]] = (),
        declined: Sequence[str] = (),
        correlation_depth_cap: int = 8,
        now: float | None = None,
    ) -> tuple[bool, list[tuple[tuple[str, str], Any]]]: ...
    def publish_state_cache(self, applied: Sequence[tuple[tuple[str, str], Any]]) -> None: ...


@dataclass(frozen=True)
class _FusedRouteResult:
    """The result record returned by :meth:`RegistryRunner._fused_route_and_handoff` (ADR 0071 B5). A
    single fused hop ran ``route_only`` (CPU) then ``route_handoff_sync`` (its own committed txn). The
    error-classification boundary is load-bearing: ``route_exc`` carries ONLY a ``route_only`` raise
    (CONTENT — the future PR3 caller re-raises it inside the internal-error try for STOP/CONTINUE
    policy); ``handoff_exc`` carries a sync-conn acquire or a ``*_handoff_sync`` fault (INFRA — re-raised
    OUTSIDE that try so T17 re-pends the head, never a content dead-letter). At most one is ever set."""

    names: list[str]
    disposition: MessageStatus | None  # None iff route_exc set (never computed)
    handed_off: bool
    route_exc: Exception | None
    handoff_exc: Exception | None
    wake_target: (
        str | None
    )  # the ROUTED lane to wake after commit (== channel_id when names non-empty)


@dataclass(frozen=True)
class _FusedTransformResult:
    """The result record returned by :meth:`RegistryRunner._fused_transform_and_handoff` (ADR 0071 B5).
    A single fused hop ran ``transform_one`` (CPU, under the lookup ExitStack) then
    ``transform_handoff_sync`` (its own committed txn). Same CONTENT/INFRA boundary as
    :class:`_FusedRouteResult`. ``applied_state`` is the committed transform-state writes the loop must
    republish via ``publish_state_cache`` after the single completion (the sync twin never mutates the
    loop-owned cache). ``outbound_wakes`` / ``ingress_wakes`` are the distinct downstream lanes the loop
    wakes after the commit (delivery lanes / PT-target INGRESS lanes)."""

    deliveries: list[tuple[str, str]]
    pt_deliveries: list[tuple[str, str]]
    applied_state: list[tuple[tuple[str, str], Any]]
    xform_exc: Exception | None
    handoff_exc: Exception | None
    outbound_wakes: tuple[str, ...]
    ingress_wakes: tuple[str, ...]


def _resolve_send_pace(settings: Mapping[str, Any]) -> float:
    """The resolved per-lane egress send-pacing interval in seconds (BACKLOG #82) from a connection's
    settings: ``send_min_interval_seconds`` coerced to a float, with ``None``/absent/``0`` → ``0.0`` (no
    pacing). Never negative — a negative value is rejected at wiring, and this clamps defensively so a
    directly-constructed spec can't ask the delivery seam to sleep on a negative interval."""
    raw = settings.get("send_min_interval_seconds")
    if raw is None:
        return 0.0
    return max(0.0, float(raw))


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
        saturation_default: SaturationThreshold | None = None,
        ack_after_default: AckAfter | None = None,
        stream_inflight_budget_bytes: int = 0,  # #149 ADR 0105: streaming-detach concurrency DoS guard (0=off)
        priority_default: Priority | None = None,
        dr_threshold: Priority | None = None,
        alert_sink: AlertSink | None = None,
        egress: EgressSettings | None = None,
        hop_posture: HopPosture | None = None,
        trust_anchor_policy: TrustAnchorPolicy | None = None,
        simulate_all: bool = False,
        env_values: Mapping[str, Any] | None = None,
        active_environment: str | None = None,
        coordinator: ClusterCoordinator | None = None,
        max_correlation_depth: int = 8,
        connection_events: bool = True,
        response_sent_default: bool = True,
        per_lane_wake: bool = False,
        claim_mode: str = "pooled",  # ADR 0066/#744: "pooled" (default) | "per_lane" (byte-identical opt-out)
        pooled_claimers_per_stage: int = 1,
        pooled_sweep_interval: float = 0.25,
        pooled_claim_lane_chunk: int = 256,
        pooled_max_processing_lanes: int = 256,
        require_rcsi_for_pooled: bool = True,
        infra_fault_policy: str = "stop",
        infra_fault_stop_after: int = 10,
        infra_fault_backoff_cap: float = 60.0,
        # #109 (ADR 0095): what an outbound does on a PERMANENT credential/auth fault — "stop" (default)
        # halts the lane immediately + retains the queued rows un-errored (no re-auth storm that could
        # lock out the partner account); "dead_letter" keeps the historical fail-fast dead-letter path.
        credential_fault_policy: str = "stop",
        # #147 (ADR 0095): the per-connection active-window scheduler's tick granularity (seconds) and an
        # injectable UTC clock (mirrors dryrun's ingest_time seam) so tests drive schedule boundaries
        # deterministically. None → wall clock (datetime.now(timezone.utc)).
        schedule_tick: float = 30.0,
        schedule_clock: Callable[[], datetime] | None = None,
        fuse_thread_hops: bool = False,  # ADR 0071 B5: SQL-Server-only thread-hop fusion (default-OFF)
        pooled_fusing_workers: int = 8,
        batch_handoff_statements: bool = False,  # ADR 0075: SQL-Server-only per-hop batching (default-OFF)
        snapshot_on_send: bool = False,  # ADR 0104: copy-on-Send at Send construction (default-OFF)
        sandbox_policy: SandboxPolicy
        | None = None,  # ADR 0087 #197: opt-in subprocess isolation (default-OFF)
        sandbox_config_source: tuple[str | None, str | None] | None = None,
    ) -> None:
        self.registry = registry
        self.store = store
        #: ADR 0154 D3. One rendezvous per runner: the waiter and the capturing worker are the same
        #: process by construction (under HA the graph runs on the leader only), so process-local is
        #: the right scope. It carries no information — every signal is a latency hint and the waiter
        #: re-reads the store — so a shard that never sees a signal is merely slower, never wrong.
        self._reply_rendezvous = ReplyRendezvous()
        #: Per-inbound sync-reply counters, exposed via sync_reply_metrics() (ADR 0154 D8).
        self._sync_reply_metrics: dict[str, SyncReplyMetrics] = {}
        # ADR 0087 (#197) opt-in Router/Handler subprocess isolation. None or mode=off → in-process,
        # byte-identical, zero overhead (no session ever constructed). mode=subprocess → one PERSISTENT
        # worker child per inbound, built lazily on first dispatch (off the loop, inside the worker
        # thread) and closed at stop(). The (config_dir, env) source lets the child re-load the SAME
        # message graph to look a Router/Handler up by name; None config_dir (embedding) can't isolate,
        # so _sandbox_for degrades to in-process. Read ONCE at construction (a /config/reload does NOT
        # re-read it — restart to change, exactly like claim_mode).
        self._sandbox_policy = sandbox_policy
        self._sandbox_config_source = sandbox_config_source
        self._sandbox_sessions: dict[str, SandboxSession] = {}
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
        # BACKLOG #214 (opt-in, default 1 → byte-identical): cap on how many of ONE message's co-claimed
        # sibling routed rows transform CONCURRENTLY in the transform worker. Overlap is realized only
        # when the batch claim co-claims siblings (``fifo_claim_batch`` > 1) AND this is > 1; the store
        # handoff always stays serial + in claim order (single-serial-writer per lane preserved). A
        # module attribute, not a settings section — a user-facing knob is a deliberate follow-up.
        self._transform_concurrency = max(1, _DEFAULT_TRANSFORM_CONCURRENCY)
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
        # saturation (rising-backlog derivative) threshold default (#93, ADR 0014 amendment).
        # SaturationThreshold() is OFF (sustain_samples=None), so a lane inherits "no saturation alert"
        # unless [delivery].saturation_sustain_samples sets one — deny-by-default (it overlaps the
        # buildup age dimension). Global-only for now (see settings.py); applied to every stage lane.
        self._saturation_default = saturation_default or SaturationThreshold()
        # Global inbound ACK-timing default (from [inbound]); a connection's own ack_after overrides
        # it. Step A only supports INGEST (ACK-on-receipt); a resolved DELIVERED fails loud at start.
        self._ack_after_default = ack_after_default or AckAfter.INGEST
        # #149 (ADR 0105 Phase 1a) very-large-document streaming: the aggregate in-flight DoS budget
        # (bytes of over-threshold bodies concurrently mid-detach across every inbound) and its running
        # counter. 0 = unlimited (per-connection max_message_bytes still bounds a single body). Mutated
        # only on the event loop inside _handle_inbound's detach (no lock needed — asyncio is single-
        # threaded and the increment/refuse/decrement never awaits across the check).
        self._stream_inflight_budget = max(0, stream_inflight_budget_bytes)
        self._stream_inflight_bytes = 0
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
        # #200 (ADR 0092): the instance's derived security posture (PHI? production?), stamped as the
        # active hop posture for the whole connector-construction block in build_check so each cell keys
        # its posture-keyed insecure-hop refusal on this config's posture. None (a test/embedding that
        # derives none) leaves it unstamped → a cell fail-closes (treats the hop as prod-PHI).
        self._hop_posture = hop_posture
        # #190 (ADR 0093): the instance-wide [tls] client trust-anchor policy, threaded onto every
        # outbound Destination by _dest_config so the internal-outbound TLS context builders (MLLP/DICOM/
        # FTPS) resolve the same org internal-CA anchor at build_check AND live construction. None → the
        # default system/no-op policy (byte-identical — the OS trust store verifies the peer).
        self._trust_anchor_policy = trust_anchor_policy or TrustAnchorPolicy()
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
        # ADR 0157 Inc 4: inbound stop() tasks a DEMOTE abandoned when they overran the budget. Always
        # EMPTY unless a demotion abandoned one, which is why every consumer sits behind a falsy-list
        # guard and single-node never touches this list.
        self._pending_source_stops: list[asyncio.Task[None]] = []
        self._destinations: dict[str, DestinationConnector] = {}
        # One delivery worker per outbound connection, addressable by name so a reload can
        # gracefully stop/swap a single connection's worker without touching its siblings.
        self._workers: dict[str, asyncio.Task[None]] = {}
        # --- outbound operator PAUSE (connection controls) ---------------------------------------
        # Operator-paused outbounds: delivery halted, queued rows RETAINED PENDING (never dropped/
        # reordered). The RELOAD-SURVIVING source of truth — outbound_running() reads it, a reload
        # re-applies it to the pooled dispatcher, and the per_lane delivery worker gates on it. A pause
        # is COOPERATIVE: the <=1 in-flight OUTBOUND head finishes first (never a task.cancel), so no row
        # strands INFLIGHT (which purge's PENDING-only cancel_queued could never clear).
        self._outbound_paused: set[str] = set()
        # Per paused outbound: an Event SET only once the lane has drained to ZERO in-flight (the pooled
        # dispatcher's on_lane_paused callback, or the per_lane worker's loop-top gate, sets it), CLEARED
        # on resume/re-stop. outbound_quiesced() — the PURGE precondition — is set-membership AND this
        # Event set, so 'stopped' means truly quiesced, not merely "won't claim new".
        self._outbound_quiesced: dict[str, asyncio.Event] = {}
        # per_lane-mode resume Events: the delivery worker awaits its lane's Event at the loop-top pause
        # gate; start_outbound sets it. Unused in pooled mode (the dispatcher's resume_lane re-arms).
        self._outbound_resume: dict[str, asyncio.Event] = {}
        # Which of _outbound_paused this ENGINE parked (auto_start=False #115 / deployed=False #233) as
        # opposed to an OPERATOR pausing it. Both reuse _outbound_paused (so every consumer — status,
        # /connections rows, buildup/stall suppression — is honest with no further change), but a reload
        # must treat them oppositely: a lane the GRAPH parked must RESUME the moment the graph says it
        # should run again (flip the flag + reload = deployed, with no other change), while a lane the
        # OPERATOR paused must stay paused across a reload. Without this discriminator a re-deployed lane
        # rebuilds its connector and respawns its worker, then sits paused forever.
        self._gate_parked: set[str] = set()
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
        # Opt-in HL7 batch aggregation (#134, ADR 0082): per-outbound BatchConfig (None = no batching,
        # the unchanged one-message-per-send path). Read live per delivery so a reload can turn batching
        # on/off under a running worker.
        self._batch: dict[str, BatchConfig | None] = {}
        # Per-connection egress send pacing (BACKLOG #82): the resolved minimum seconds between sends on
        # each outbound lane (0.0 = no pacing, the default → byte-identical). Re-resolved per outbound at
        # start/reconcile so a reload retunes it. _send_pace_at is the per-lane pacing CLOCK — the
        # monotonic timestamp of that lane's last send-gate — keyed on the outbound name so independent
        # lanes pace independently (NOT a shared bucket, which would cross-couple lanes in pooled mode).
        # The clock is intentionally NOT reset on reload (a reload must not license an immediate burst).
        self._send_pace: dict[str, float] = {}
        self._send_pace_at: dict[str, float] = {}
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
        # Saturation (rising-backlog derivative) alert state (#93, ADR 0014 amendment). One bounded
        # depth-sample detector per "stage:lane" (the SMALL rate history), plus an independent per-key
        # re-alert throttle so a saturation page can't suppress buildup/stall (and vice-versa). Both keyed
        # by "stage:name" because the same connection saturates independently at ingress/routed/outbound.
        self._saturation_detectors: dict[str, SaturationDetector] = {}
        self._next_saturation_alert: dict[str, float] = {}
        # Live-lookup executor (db_lookup, ADR 0010): built from registry.lookups at start/reload, None
        # when the graph declares no DatabaseLookup — in which case the transform path stays byte-identical
        # (inline call, no thread hop, no runner). The engine loop is captured at start so a handler's
        # worker thread can bridge a db_lookup back onto it (run_coroutine_threadsafe).
        self._lookup_executor: DatabaseLookupExecutor | None = None
        # Live FHIR-lookup executor (fhir_lookup, ADR 0043): the read-side sibling of _lookup_executor,
        # built from registry.fhir_lookups at start/reload, None when the graph declares no FhirLookup.
        # When either executor is set, the transform runs off-loop with the matching runner(s) activated.
        self._fhir_lookup_executor: FhirLookupExecutor | None = None
        # ADR 0071 B5: the per-stage FUSING executors (SQL-Server-only thread-hop fusion). SEPARATE from
        # asyncio's default to_thread executor (which serves the listener strict-validate/decrypt hot
        # path) so DB-latency-holding fused hops can't starve that CPU executor, and PER-STAGE (not
        # shared) because a transform hop can block up to _LOOKUP_RESULT_TIMEOUT_SECONDS on a bridged
        # live lookup while the route hop never blocks. Stay None unless fusion activates in
        # _start_pooled_dispatchers; torn down in _teardown_unsafe (a reload NEVER rebuilds/tears them).
        self._fuse_route_executor: ThreadPoolExecutor | None = None
        self._fuse_transform_executor: ThreadPoolExecutor | None = None
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
        # WS-C: with per-lane wake ON the idle backstop backs off to the long safety-net interval
        # (idle lanes stop storming the store's claim path); OFF keeps poll_interval byte-identical.
        self._idle_backstop = (
            _PER_LANE_IDLE_BACKSTOP_SECONDS if per_lane_wake else self.poll_interval
        )
        self._lane_events: dict[Stage, dict[str, asyncio.Event]] = {s: {} for s in Stage}
        # Pooled per-stage claimers (ADR 0066). DEFAULT (since #744): claim_mode="pooled" replaces the
        # per-inbound router/transform + per-outbound delivery workers with one StageDispatcher per stage
        # (built in start()). The "per_lane" opt-out builds today's per-inbound/per-outbound workers and
        # constructs ZERO pooled objects (the byte-identical sentinel asserts _dispatchers stays empty for
        # per_lane). Read once at construction — a /config/reload never re-reads claim_mode (restart to
        # change, exactly like per_lane_wake).
        self._claim_mode = claim_mode
        self._pooled_claimers_per_stage = pooled_claimers_per_stage
        self._pooled_sweep_interval = pooled_sweep_interval
        self._pooled_claim_lane_chunk = pooled_claim_lane_chunk
        self._pooled_max_processing_lanes = pooled_max_processing_lanes
        self._require_rcsi_for_pooled = require_rcsi_for_pooled
        # Pooled T17 infra-fault bound (ADR 0070). Threaded into each StageDispatcher; read once here.
        self._infra_fault_policy = infra_fault_policy
        self._infra_fault_stop_after = infra_fault_stop_after
        self._infra_fault_backoff_cap = infra_fault_backoff_cap
        # #109 (ADR 0095): credential-fault (partner account-lockout protection) policy. Validated here
        # so a bad value fails loud at construction, mirroring the infra_fault_policy assert above.
        assert credential_fault_policy in ("stop", "dead_letter")
        self._credential_fault_policy = credential_fault_policy
        # #147 (ADR 0095): per-connection active-window scheduler. `_schedule_clock` is injectable for
        # deterministic tests (returns an AWARE UTC datetime); `_schedule_tick` is the reconcile
        # granularity. `_schedule_workers` holds one cooperatively-cancellable task per SCHEDULED
        # connection, spawned in start() and cancelled in _teardown_unsafe (empty = no scheduled
        # connections = byte-identical always-on lifecycle).
        self._schedule_tick = schedule_tick
        self._schedule_clock: Callable[[], datetime] = schedule_clock or (lambda: datetime.now(UTC))
        self._schedule_workers: dict[str, asyncio.Task[None]] = {}
        # ADR 0071 B5 thread-hop fusion. FROZEN intent read ONCE here; a /config/reload never re-reads it
        # (restart to change, exactly like claim_mode). ``_fusion_active`` is the EFFECTIVE decision,
        # resolved in _start_pooled_dispatchers AFTER trying to open the sync pools + build the per-stage
        # executors: it is True only when the flag is set AND the store is SQL Server (with the sync
        # handoff twins) AND claim_mode="pooled" AND the pools+executors opened OK — else the engine runs
        # the async path (fail-closed, reachable, never a lane outage). Byte-identical when off/non-SS.
        self._fuse_thread_hops = fuse_thread_hops
        self._fusing_workers = pooled_fusing_workers
        self._fusion_active = False
        # ADR 0075 per-hop SQL statement batching. FROZEN intent read ONCE here; a /config/reload never
        # re-reads it (restart to change, exactly like fuse_thread_hops). Resolved to the store in start()
        # via _activate_statement_batching(): True only when the flag is set AND the store is SQL Server
        # (the only backend that ships the batched handoff forms) — else the async path (fail-closed,
        # byte-identical). Independent of claim_mode: batching works on the plain async handoff too.
        self._batch_handoff_statements = batch_handoff_statements
        # ADR 0104 copy-on-Send (default-OFF); every transform-phase RunContext this runner builds carries
        # it, so Send.__post_init__ snapshots on the split, inline, and fused paths alike. Read ONCE here —
        # a /config/reload never re-reads it (restart to change, exactly like fuse_thread_hops).
        self._snapshot_on_send = snapshot_on_send
        # /stats-style gauge: True when the flag was set on a fusion-capable engine but the sync
        # handoff pool could not be opened at start (command_timeout==0 / session-cap / connect fault),
        # so fusion fell back to the async path. Distinct from "ignored on a non-SS backend".
        self._fusion_pool_open_failed = False
        # One StageDispatcher per stage in pooled mode (empty in per_lane mode — nothing pooled built).
        self._dispatchers: dict[Stage, StageDispatcher] = {}
        # Set True when pooled mode started on SQL Server with RCSI OFF and
        # require_rcsi_for_pooled=False downgraded the fail-closed gate to a warning (a /stats gauge).
        self._rcsi_off_degraded = False
        # Pooled INGRESS/ROUTED buildup-alert rate limiter (D1): the per_lane buildup check lives in the
        # worker loops (dropped in pooled mode), so the pooled adapter re-adds it, throttled per
        # (stage, lane) to _BUILDUP_CHECK_INTERVAL so it never runs a COUNT+MIN per claimed item.
        self._pooled_buildup_at: dict[str, float] = {}
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
        # ADR 0073: sharded-only read-only watchdog over NON-owned outbound lanes (hung-owner paging).
        self._shard_watchdog: asyncio.Task[None] | None = None
        # #122 (ADR 0162): fail-closed application-log write guard. The escalation arrives on whatever
        # thread was logging, so the response is bounced onto this runner's loop as a task; the latch
        # makes the stop fire once per break rather than once per dropped record.
        self._log_guard_tasks: set[asyncio.Task[None]] = set()
        self._log_write_stopped = False
        # Inbounds whose INTERNAL stages (router / transform / loopback response) the halt shut down.
        # Per-inbound rather than one process-wide flag because the RE-ARM is per-connection: a
        # restart of inbound A must not silently re-arm B's processing while B's listener stays down.
        self._log_halted: set[str] = set()
        self._running = False
        self._reload_lock = asyncio.Lock()  # serialize concurrent reloads
        # B11 read-only worker-loop instrumentation: empty-claim counts (router/transform/delivery),
        # split into idle-poll re-SELECTs vs per-commit wake-fanout (the thundering herd). Surfaced via
        # /stats; default 0, so byte-identical when the connection-scale harness never reads it.
        self._empty_claims = EmptyClaimCounters()
        # Bench-gated per-delivery phase timing (default OFF). Resolved ONCE here (not per delivery) so
        # the per-item body is a single bool check when off — no perf_counter, no allocation. BOTH the
        # pooled OUTBOUND StageDispatcher (_dispatch_delivery) and the per_lane _delivery_worker flow
        # through _process_delivery_item, so timing there covers both claim modes with one change.
        self._delivery_phase_timing = delivery_phase_timing_enabled()
        # logger=log keeps the emitted INFO line's logger NAME on wiring_runner, exactly as #842
        # shipped it — the module extraction must not move the rig's node-log surface.
        self._delivery_phase_stats = DeliveryPhaseTiming(logger=log)
        # per_lane's CLAIM lives here (the pooled claim is timed inside StageDispatcher). Timing both
        # makes the pooled-vs-per_lane A/B apples-to-apples: per_lane claims once per lane worker
        # (concurrent, no table variables), pooled claims once per chunk on K serial claimer tasks.
        self._claim_phase_stats = ClaimPhaseTiming(logger=log)

    @property
    def running(self) -> bool:
        return self._running

    @property
    def has_residual_state(self) -> bool:
        """Anything still built after a teardown that did not complete (ADR 0157 D7).

        Deliberately NOT the same expression as ``stop()``'s ``had_state``, and the two differences are
        both load-bearing. It omits ``_running`` because this is asked precisely when ``_running`` is
        already False (the ``finally`` in ``_teardown_unsafe`` clears it on every path, including a raise
        or an outside cancel). It ADDS ``_dispatchers`` because they are cleared early in teardown, before
        the destination ``aclose()`` / executor-shutdown awaits — so a cancel landing between those leaves
        ``_dispatchers`` populated while the other three are not.
        """
        return bool(self._sources or self._workers or self._destinations or self._dispatchers)

    @property
    def fusion_active(self) -> bool:
        """Whether ADR 0071 B5 thread-hop fusion is EFFECTIVELY active this run (SQL Server, pooled,
        pools+executors opened OK). False on every other backend/mode and when the flag is off — the
        /stats seam a fused-vs-async A/B reads. Only meaningful after :meth:`start`."""
        return self._fusion_active

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

    # --- engine-shard lane ownership (ADR 0073) --------------------------------

    def _destination_owner(self, name: str) -> str | None:
        """The shard that owns claiming/delivery for outbound lane ``name`` — ``None`` when this
        process is not sharded (single-shard/unsharded: every lane is locally owned). Reads the live
        registry, so a reload's swapped graph is reflected immediately."""
        reg = self.registry
        if reg.shard_id is None or reg.all_shard_ids is None:
            return None
        return owner_shard_of_destination(name, reg.all_shard_ids)

    def _owns_destination(self, name: str) -> bool:
        """ADR 0073 single-delivery-consumer gate: True unless a sharded registry assigns outbound
        lane ``name`` to a DIFFERENT shard. Deliberately a *predicate* (rendezvous over the pinned
        shard universe, total over any string) rather than membership in a registry-derived set: a
        destination a reload dropped from ``registry.outbound`` keeps exactly one owner, so its
        still-queued rows keep draining on that shard instead of stranding everywhere."""
        owner = self._destination_owner(name)
        return owner is None or owner == self.registry.shard_id

    def destination_owner(self, name: str) -> str | None:
        """Public read of :meth:`_destination_owner` for the API surfaces (``/connections`` rows,
        the purge handler's ownership 409) — ``None`` when unsharded."""
        return self._destination_owner(name)

    def _wake_lane(self, stage: Stage, key: str) -> None:
        """Wake the worker for one (stage, lane). ADR 0066 pooled: route to the stage's dispatcher
        (``mark_ready`` — sync, await-free, ``Event.set()``-shaped, create-or-stick on an unknown lane)
        and NEVER touch the per_lane singletons/lane-events; a wake before the dispatcher exists is a
        no-op (the dispatcher's start-time seed-all-READY + immediate sweep covers it). per_lane OFF →
        the whole-stage singleton (byte-identical to the pre-B12 set()); ON → only this lane's Event
        (ADR 0061).

        Sharded (ADR 0073): a wake for a lane ANOTHER shard owns is dropped here — the single choke
        point for every producer wake (transform handoffs, retry re-wakes, response captures).
        ``mark_ready`` is create-or-stick, so an ungated cross-shard wake would register the lane on
        THIS shard's dispatcher and make it a second concurrent claimer — the exact per-lane FIFO
        hazard the single-consumer invariant closes. The owning shard discovers cross-shard produce
        via its sweep/idle poll instead (the documented wake gap)."""
        if self.registry.shard_id is not None:
            if stage is Stage.OUTBOUND and not self._owns_destination(key):
                return
            if stage is Stage.RESPONSE and key not in self.registry.inbound:
                return  # the reingress_to loopback lives on (and is drained by) another shard
        if self._claim_mode == "pooled":
            d = self._dispatchers.get(stage)
            if d is not None:
                d.mark_ready(key)
            return
        if not self._per_lane_wake:
            self._singleton_for_stage[stage].set()
        else:
            self._lane_event(stage, key).set()

    def _wake_all(self, *stages: Stage) -> None:
        """Wake EVERY worker of the given stages — for lane-agnostic producers (notify_work / reload /
        teardown) that can't name a single lane. ADR 0066 pooled: broadcast ``notify_work()`` to each
        stage's dispatcher (re-ready every registry lane, unpark PARKED lanes, request an immediate
        sweep). OFF → the stage singletons; ON → every registered lane Event of those stages. MUST stay
        synchronous + await-free: it snapshots the Event list before iterating so a concurrent
        reload/producer mutating _lane_events can't raise 'dict changed size during iteration'. ADR 0061."""
        if self._claim_mode == "pooled":
            for stage in stages:
                d = self._dispatchers.get(stage)
                if d is not None:
                    d.notify_work()
            return
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

    def _intake_auth_enabled(self, ic: InboundConnection) -> bool:
        return (
            ic.spec.type is ConnectorType.HTTP
            and str(ic.spec.settings.get("intake_auth") or "none") != "none"
        )

    def _make_intake_audit_sink(self, ic: InboundConnection) -> IntakeAuditSink | None:
        """The per-inbound tamper-evident audit sink for intake-auth refusals (ADR 0154 D6).

        ``None`` unless this inbound actually authenticates, so every other connection is
        byte-identical. Unlike the ``connection_event`` sink this one **awaits** a store write: an
        ``audit_log`` row is a hash chain and cannot be enqueued out of order. It is on the refusal
        path only, never the accept path, so it cannot slow legitimate intake.

        This is the engine's first internal writer of ``record_audit(client=)`` (ADR 0150), and the
        column's "NULL means no client was in scope" docstring is exactly why: here one demonstrably is.
        """
        if not self._intake_auth_enabled(ic):
            return None
        # The runner holds its store as the narrower QueueStore; record_audit lives on AuditStore
        # (Store = QueueStore + AuditStore + AuthStore), which all three shipped backends implement.
        # Guarded rather than assumed, so a store without the audit plane degrades to the log +
        # connection_event channels instead of raising on every refusal.
        if not hasattr(self.store, "record_audit"):
            return None
        audit_store = cast(AuditStore, self.store)
        name = ic.name

        async def _sink(action: str, client: str | None, detail: str | None) -> None:
            try:
                await audit_store.record_audit(
                    action, channel_id=name, client=client, detail=detail
                )
            except Exception as exc:  # fail-soft: an audit failure must not drop an HTTP client
                log.warning("intake auth audit write failed: %s", safe_exc(exc))

        return _sink

    def _make_sync_reply_resolver(self, ic: InboundConnection) -> SyncReplyResolver | None:
        """The per-inbound synchronous-reply resolver (ADR 0154 D2/D3), or ``None``.

        ``None`` unless this inbound declares ``reply_from``, which is what keeps every other
        connection on the shipped ``202`` path byte for byte (AC-8).

        Also re-runs the cross-registry validation **here**, where ``[delivery]`` is resolved. The
        offline arm in ``build_check_registry`` skips the effective ``ordering``/``max_attempts``
        refusals whenever its caller could not supply those defaults, so this is the backstop that
        makes them unconditional — a graph that would serialise every concurrent caller behind one
        FIFO lane fails to start rather than degrading silently under load, and ADR 0031 isolates
        that to this one connection.
        """
        if ic.spec.type is not ConnectorType.HTTP or not ic.spec.settings.get("reply_from"):
            return None
        check_http_sync_reply(
            ic,
            self.registry,
            delivery=DeliverySettings(
                ordering=self._ordering_default,
                # The runner resolves an outbound's retry as `oc.retry or self._delivery_defaults`,
                # so the inherited max_attempts is that default policy's — not a separate scalar.
                retry_max_attempts=self._delivery_defaults.max_attempts,
            ),
        )
        settings = ic.spec.settings
        metrics = self._sync_reply_metrics.setdefault(ic.name, SyncReplyMetrics(ic.name))
        return SyncReplyResolverImpl(
            self.store,
            self._reply_rendezvous,
            destination=str(settings["reply_from"]),
            timeout=float(settings.get("reply_timeout") or 30.0),
            content_type=str(settings.get("reply_content_type") or "passthrough"),
            on_timeout=str(settings.get("reply_on_timeout") or "504"),
            metrics=metrics,
        )

    def sync_reply_metrics(self) -> dict[str, SyncReplyMetrics]:
        """Per-inbound synchronous-reply counters, keyed by connection name (ADR 0154 D8).

        The PUBLIC accessor the metrics exporter reads. api/metrics.py builds every family per scrape
        from engine.store alone and has no view of the runner, while transports/ may not import api/
        (AC-17) — so the counters live with the runner that owns the resolvers, and the exporter pulls
        them through here rather than reaching into a private attribute.
        """
        return dict(self._sync_reply_metrics)

    def _make_intake_rate_limiter(self, ic: InboundConnection) -> IntakeRateLimiter | None:
        """The per-inbound failed-attempt budget, or ``None`` when both arms are disabled."""
        if not self._intake_auth_enabled(ic):
            return None
        per_peer = int(ic.spec.settings.get("intake_auth_rate_limit") or 0)
        glob = int(ic.spec.settings.get("intake_auth_rate_limit_global") or 0)
        if not per_peer and not glob:
            return None
        return _IntakeRateLimiter(per_peer=per_peer, glob=glob)

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
        # #200 (ADR 0092): stamp the derived posture around the live executor build so the DSN's
        # weakened-TLS refusal (_build_dsn → _weakened_tls_permitted) keys on THIS instance's posture,
        # applying the production-PHI clamp. engine.start()/reload build the executor here WITHOUT going
        # through build_check_registry's active_hop_posture scope, so an unstamped build would fall back
        # to the UNCLAMPED escape at query time and let a prod-PHI weakened-TLS live read cross.
        with active_hop_posture(self._hop_posture):
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
            _apply_egress_proxy_default(settings, self._egress)  # ADR 0126: site-wide forward proxy
            check_fhir_lookup_allowed(name, settings, self._egress)
            resolved[name] = settings
        # #200 (ADR 0092): stamp the derived posture around the live executor build so each connection's
        # cleartext/verify-off hop guard (refuse_cleartext_egress / refuse_verify_off) captures THIS
        # instance's posture rather than the unstamped fail-closed default. engine.start()/reload build
        # the executor here outside build_check_registry's active_hop_posture scope, so an unstamped build
        # would either fail-closed a legit dev read or (via the send-time re-assertion) mis-key the hop.
        with active_hop_posture(self._hop_posture):
            return FhirLookupExecutor(resolved)

    def _run_fhir_lookup(
        self,
        connection: str,
        query: str,
        params: Mapping[str, str | list[str]] | None = None,
    ) -> dict[str, Any]:
        """The FHIR-lookup runner published to Handlers (``fhir_lookup`` → this). Called FROM the handler's
        worker thread, it bridges the async GET onto the engine loop via ``run_coroutine_threadsafe`` and
        blocks the WORKER THREAD — never the loop — for the result (bounded by
        ``_LOOKUP_RESULT_TIMEOUT_SECONDS``). ``params`` (BACKLOG #204) carries the safely-encoded
        structured search form; the executor percent-encodes each value before it reaches the URL."""
        executor = self._fhir_lookup_executor
        loop = self._loop
        if executor is None or loop is None:  # only published when both exist; guard defensively
            raise FhirLookupError(
                "fhir_lookup is unavailable — no FhirLookup connections are configured"
            )
        future = asyncio.run_coroutine_threadsafe(executor.read(connection, query, params), loop)
        return future.result(_LOOKUP_RESULT_TIMEOUT_SECONDS)

    # --- per-connection control (console operations) -------------------------

    def inbound_running(self, name: str) -> bool:
        return name in self._sources

    # --- outbound operator pause: read accessors (connection controls) -------

    def _validate_outbound(self, name: str) -> None:
        """Raise :class:`KeyError` for a name that is neither a declared nor a still-draining outbound,
        so the API 404s an unknown connection. A reload-dropped outbound still in ``_destinations`` is
        controllable while it drains."""
        if name not in self.registry.outbound and name not in self._destinations:
            raise KeyError(name)

    def _mark_outbound_quiesced(self, name: str) -> None:
        """Pooled dispatcher ``on_lane_paused`` callback: the outbound ``name`` lane reached PAUSED
        (drained to zero in-flight). Set its quiescence Event so ``outbound_quiesced`` / ``outbound_status``
        report 'stopped' (the purge precondition). Get-or-create so a pause on a never-seen lane still
        signals."""
        self._outbound_quiesced.setdefault(name, asyncio.Event()).set()

    def outbound_running(self, name: str) -> bool:
        """Whether the named outbound is actively delivering (operator intent): the engine is running
        AND the outbound is not operator-paused. Raises :class:`KeyError` for a name that is neither a
        declared nor a draining outbound, so the API 404s an unknown connection (mirrors
        :meth:`inbound_running`'s membership semantics + the outbound control handlers)."""
        self._validate_outbound(name)
        return self._running and name not in self._outbound_paused

    def outbound_quiesced(self, name: str) -> bool:
        """Whether a PAUSED outbound has fully DRAINED to zero in-flight — the PURGE precondition. True
        iff the outbound is operator-paused AND its quiescence Event is set (delivery halted, no row
        mid-flight). Merely being in ``_outbound_paused`` is NOT enough: a graceful pause returns before
        the in-flight head resolves, and ``cancel_queued`` cannot cancel an INFLIGHT row — so purge must
        wait for true quiescence. Never raises (an unknown name → False; a purge caller 404s earlier)."""
        if name not in self._outbound_paused:
            return False
        ev = self._outbound_quiesced.get(name)
        return ev is not None and ev.is_set()

    def outbound_status(self, name: str) -> str:
        """Tri-state delivery status for one outbound: 'running' (not paused), 'stopping' (paused, an
        in-flight head still resolving — the quiescence Event not yet set), or 'stopped' (paused AND
        quiesced — zero in-flight, safe to purge). A name not in ``_outbound_paused`` → 'running' (the
        status-plumbing caller already special-cases failed/filtered; a real unknown 404s on control)."""
        if name not in self._outbound_paused:
            return "running"
        return "stopped" if self.outbound_quiesced(name) else "stopping"

    def outbound_waiting_for_reply(self, name: str) -> bool:
        """#136 (ADR 0065 amendment): whether the named outbound's LIVE connector is currently awaiting a
        reply (past its ``waiting_display_delay``) — the per-message "Waiting for Reply" display state.
        Duck-typed: a connector without the side-band marker (File/REST/…, or an outbound not currently
        ACK-waiting, incl. a future no-ack mode) reports False. Read off the event loop by
        ``list_connections``; never raises (an unknown/undeployed name → False)."""
        connector = self._destinations.get(name)
        probe = getattr(connector, "waiting_for_reply", None)
        return bool(probe(time.monotonic())) if callable(probe) else False

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

    def _auto_start_enabled(self, name: str, kind: str) -> bool:
        """The connection's declared ``auto_start`` (#115), by role. ``True`` for a name the registry no
        longer declares (a reload-dropped outbound that is only draining) — there is nothing left to
        gate, and defaulting to False would park a lane the graph never asked to disable."""
        if kind == "inbound":
            ic = self.registry.inbound.get(name)
            return ic.auto_start if ic is not None else True
        oc = self.registry.outbound.get(name)
        return oc.auto_start if oc is not None else True

    def _deployed(self, name: str, kind: str) -> bool:
        """The connection's declared ``deployed`` (#233, ADR 0111), by role — read from the REGISTRY (the
        graph), never from live runner state, because at-least-once (ADR 0001) requires a crash re-run to
        re-derive an identical decision.

        ``deployed=False`` WINS over ``auto_start``: every gate consults this FIRST and ignores
        ``auto_start`` entirely when it is set, so the two flags can never disagree about whether a lane
        comes up. ``True`` for a name the registry no longer declares (a reload-dropped outbound that is
        only draining) — it was deployed when its rows were produced, and they must still drain."""
        if kind == "inbound":
            ic = self.registry.inbound.get(name)
            return ic.deployed if ic is not None else True
        oc = self.registry.outbound.get(name)
        return oc.deployed if oc is not None else True

    def _log_declined(self, hname: str, message_id: str, declined: Sequence[str]) -> None:
        """Log each ``Send`` ``transform_one`` declined because its target is present but NOT DEPLOYED
        (#233, ADR 0111). Called from all three in-pipeline transform sites (split, ADR-0057 inline,
        ADR-0071 fused) — a no-op (one falsiness check) on a graph with nothing declined.

        Count-and-log (CLAUDE.md §12): a skipped destination the operator cannot see would be an
        accept-and-drop. Names only — the connection, the handler, the message id — never a body, so it
        is safe at INFO (PHI stays in the store). This is the log half; the durable half (a
        per-destination ``message_events`` row + the NOT_DEPLOYED disposition) is the store's."""
        for dest in declined:
            log.info(
                "handler %r sent to connection %r, which is present but NOT DEPLOYED (deployed=false) "
                "— delivery declined, no outbound row queued (message %s)",
                hname,
                dest,
                message_id,
            )

    def _outbound_lane_live(self, name: str) -> bool:
        """Whether ``name``'s delivery lane is actually UP right now: a built connector AND not paused.
        The #115 reload gate's question — 'is it up?', not 'was it declared startable?' — so a reload
        neither resurrects a start-disabled lane (never started, or started then stopped) nor undoes an
        operator who DID start one at runtime."""
        return name in self._destinations and name not in self._outbound_paused

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
            dest_cfg = _dest_config(oc, self._env_values, self._trust_anchor_policy, self._egress)
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

    def _require_owned_destination(self, name: str) -> None:
        """Refuse an outbound CONTROL for a lane another shard owns (ADR 0073). Without this, a
        non-owning shard's pause reports quiesced instantly (it has no worker/dispatcher lane) and
        unlocks the require-stopped purge while the owning shard keeps claiming and delivering — the
        operator is told 'stopped' about a lane that is very much running. The 409 the API maps this
        to names the owning shard so the operator can retarget."""
        if not self._owns_destination(name):
            raise ShardLaneOwnershipError(
                name, owner=self._destination_owner(name), shard=self.registry.shard_id
            )

    async def start_outbound(self, name: str) -> None:
        """RESUME delivery on one outbound connection (no-op if not paused). The OPPOSITE primitive to
        the inbound stop/start: it un-pauses DELIVERY, keeping the connector WARM. Takes the reload lock
        so it can't race a concurrent reload/stop (review M-10). Sharded: owner-only (ADR 0073).

        **REFUSES while a #122 log-failure halt is in force and the log is still unwritable** (ADR
        0162). Delivery is processing: a paused outbound holds rows the halt retained, and un-pausing
        it would ship them with no application log behind them — the same violation as re-arming an
        inbound, reached by the other door. Gated HERE rather than in ``_start_outbound_unsafe`` so a
        reload's outbound reconciliation is untouched; a reload never un-pauses an operator-paused
        lane (#115/#233), so this public entry point is the only way delivery resumes."""
        async with self._reload_lock:
            self._require_owned_destination(name)
            if not self._log_recovery_ok():
                self._log_write_refused_restart(name)
                return
            await self._start_outbound_unsafe(name)

    async def stop_outbound(self, name: str) -> None:
        """PAUSE delivery on one outbound connection while RETAINING its queued rows PENDING (the
        opposite kind of stop from an inbound's — an inbound stop halts intake but keeps delivery
        draining; this halts delivery but keeps the queue). Requests a COOPERATIVE pause and RETURNS
        FAST — it does NOT await the in-flight head to drain, so a hung/slow destination can never hang
        the caller (the HTTP request). The lane only *counts as* 'stopped' once its quiescence Event
        fires (:meth:`outbound_quiesced`); until then it is 'stopping'. Sharded: owner-only (ADR 0073)."""
        async with self._reload_lock:
            self._require_owned_destination(name)
            self._stop_outbound_unsafe(name)

    async def restart_outbound(self, name: str) -> None:
        """Stop + start delivery for one outbound in a single lock span (atomic w.r.t. a concurrent
        reload). The connector is kept WARM throughout (``_destinations[name]`` is never torn down) — a
        restart deliberately keeps MLLP sockets / DB pools / SMART tokens warm, exactly like a reload.
        Sharded: owner-only (ADR 0073)."""
        async with self._reload_lock:
            self._require_owned_destination(name)
            self._stop_outbound_unsafe(name)
            await self._start_outbound_unsafe(name)

    def _stop_outbound_unsafe(self, name: str) -> None:
        """stop_outbound body without the reload lock (callers hold it). Sync + returns fast: it flags
        the pause and requests it in whichever claim mode is active, but NEVER awaits the in-flight
        drain (cooperative). NEVER ``task.cancel`` a worker/serializer — a cancelled mid-delivery row
        strands INFLIGHT forever (``reset_stale_inflight`` is startup/DR-only), defeating require-stopped."""
        self._validate_outbound(name)
        self._outbound_paused.add(name)
        # The OPERATOR now owns this lane's down state — a reload must not resume it (#115/#233): drop any
        # engine-park marker so _unpark_outbound_lane leaves it alone even if the graph says it may run.
        self._gate_parked.discard(name)
        # (Re)create the quiescence Event CLEARED: the lane is not yet drained. The pooled dispatcher's
        # on_lane_paused (via _mark_outbound_quiesced) / the per_lane worker's loop-top gate SETs it once
        # in-flight hits zero.
        ev = self._outbound_quiesced.get(name)
        if ev is None:
            self._outbound_quiesced[name] = asyncio.Event()
        else:
            ev.clear()
        if self._claim_mode == "pooled":
            d = self._dispatchers.get(Stage.OUTBOUND)
            if d is not None:
                d.pause_lane(name)  # fires on_lane_paused synchronously if the lane is already idle
        else:
            # per_lane: clear the resume Event so the worker blocks at its loop-top gate, then nudge it
            # so it reaches the gate promptly (sets the quiescence Event once its <=1 head has resolved).
            self._outbound_resume.setdefault(name, asyncio.Event()).clear()
            worker = self._workers.get(name)
            if worker is None or worker.done():
                # No live delivery worker (content-STOP exited it, or never spawned) => already zero in-flight,
                # and no loop-top pause gate will ever fire; signal quiescence directly so purge is permitted.
                # (The quiesced Event was just created/cleared above, so [name] exists — mirror the
                # worker-done special-case idiom in _start_outbound_unsafe.)
                self._outbound_quiesced[name].set()
            else:
                self._wake_lane(Stage.OUTBOUND, name)

    def _park_outbound_lane(self, name: str) -> None:
        """Record ``name``'s delivery lane as DELIBERATELY DOWN — the state both the ``auto_start=False``
        boot gate (#115) and the ``deployed=False`` gate (#233, ADR 0111) must leave behind (each also on
        the reload that re-evaluates it). The two differ in what they do NEXT, not here: a start-disabled
        lane still gets a delivery worker (parked at the pause gate, ready for an operator start), a
        not-deployed lane gets none at all.

        Reuses the operator-pause state rather than inventing a parallel one, so every existing consumer
        is honest with no further change: ``outbound_status`` reports ``"stopped"`` (it was reporting
        ``"running"``, because the gate wrote no state at all), ``/connections`` therefore emits a
        standalone row for a never-trafficked lane instead of hiding it, and the buildup/stall pages stay
        suppressed (both are scoped to ``_outbound_paused`` membership) so a deliberately-down lane can
        never page the operator.

        Quiescence is signalled IMMEDIATELY, not left to the worker/dispatcher pause gate: a lane that
        was never started has zero rows in flight, so it is genuinely 'stopped' from the first tick — not
        a transient 'stopping' that a status read could race.

        Recorded in ``_gate_parked`` so a later reload can tell an ENGINE park from an OPERATOR pause and
        resume only the former — see :meth:`_unpark_outbound_lane`."""
        self._outbound_paused.add(name)
        self._gate_parked.add(name)
        self._outbound_quiesced.setdefault(name, asyncio.Event()).set()
        if self._claim_mode == "pooled":
            d = self._dispatchers.get(Stage.OUTBOUND)
            if d is not None:
                d.pause_lane(name)
            # d is None at boot (_start_outbound runs before the dispatchers exist) — _start_pooled_
            # dispatchers replays _outbound_paused onto the fresh OUTBOUND dispatcher before it starts.
        else:
            # per_lane: the delivery worker blocks at its loop-top pause gate until start_outbound sets
            # this (a cleared Event is the gate; setdefault creates it cleared, clear() is for a re-park).
            self._outbound_resume.setdefault(name, asyncio.Event()).clear()

    def _unpark_outbound_lane(self, name: str) -> None:
        """Undo a :meth:`_park_outbound_lane` — but ONLY for a lane the ENGINE parked.

        The exact inverse (drop the pause, clear the quiescence signal, re-arm the pooled lane / release
        the per_lane gate). A NO-OP for a lane that is not in ``_gate_parked``: an OPERATOR pause must
        survive a reload (a reload never undoes an operator action), and a lane that was never parked has
        nothing to undo — so this is a pure one-set-membership check on every normal reload.

        Without it, a connection RE-DEPLOYED by a reload (flip ``deployed`` back to true — AC-4's "with no
        other change") rebuilds its connector and respawns its worker, and then sits PAUSED forever: the
        reconcile's build/spawn branch never touched the pause state that the gate had written. Same for
        an ``auto_start`` flipped back to true."""
        if name not in self._gate_parked:
            return
        self._gate_parked.discard(name)
        self._outbound_paused.discard(name)
        ev = self._outbound_quiesced.get(name)
        if ev is not None:
            ev.clear()
        if self._claim_mode == "pooled":
            d = self._dispatchers.get(Stage.OUTBOUND)
            if d is not None:
                d.resume_lane(name)
        else:
            self._outbound_resume.setdefault(name, asyncio.Event()).set()

    async def _ensure_destination_built(self, name: str) -> None:
        """Build ``name``'s connector into ``_destinations`` if the lane has none — the missing half of
        an operator start (#115). The ``auto_start=False`` boot gate leaves a CONNECTOR-LESS lane, so a
        resume alone could never deliver a single byte: the advertised ``POST /connections/{name}/start``
        looked like it worked (the route even returned ``running: true``) and silently did nothing.

        A no-op in four cases: the connector is already live (so a restart keeps it WARM — never
        rebuilds an MLLP socket / DB pool / SMART token); the registry no longer declares the outbound
        (a reload-dropped lane that is only draining — nothing to build it FROM); the lane is
        DR-parked (#61, ADR 0048), which is a RUN-PROFILE decision that survives a reload by design and
        would be re-applied under the operator's feet on the next one; or the outbound is NOT DEPLOYED
        (#233), whose whole contract is that its connector is never built (its ``env()`` values may not
        exist). ``auto_start`` is the boot gate an operator IS meant to override at runtime; the DR
        threshold and ``deployed`` are not. (``_start_outbound_unsafe`` already refuses a not-deployed
        lane with :class:`NotDeployedError`; the guard here is the defense-in-depth that keeps THIS
        method — the only place a connector is built outside start/reload — from ever resolving the
        secrets of a connection the graph says is not deployed.)

        A build failure is ISOLATED, not raised (ADR 0031, exactly like the start-time path): the lane is
        recorded failed + alerted and the resume still proceeds, so rows are retried via the
        connector-None path and a later fix + reload/restart self-heals — rather than 500ing the control
        route and leaving the operator with no status to read."""
        if name in self._destinations or name in self._filtered:
            return
        oc = self.registry.outbound.get(name)
        if oc is None or not oc.deployed:
            return
        connector: DestinationConnector | None = None
        try:
            dest = _dest_config(oc, self._env_values, self._trust_anchor_policy, self._egress)
            check_egress_allowed(dest, self._egress)  # fail-closed egress allowlist (WP-11c)
            # #200 (ADR 0092): stamp the derived instance posture, exactly as _start_outbound does —
            # an unstamped build makes the posture-keyed insecure-hop cells decide against the wrong
            # (fail-closed/no-op default) posture.
            with active_hop_posture(self._hop_posture):
                connector = build_destination(dest)
            # Opt-in at-start directory validation (#114) — the same hook _start_outbound awaits, so an
            # operator START of a File/RemoteFile outbound with validate_directory=true gets the same
            # refusal the engine start path gives it, isolated the same way (this method never raises).
            await connector.validate_startup()
        except Exception as exc:
            await self._aclose_quietly(connector, name)
            self._destinations.pop(name, None)
            self._record_failed(name, exc, kind="outbound")
            return
        self._destinations[name] = connector
        self._failed.pop(name, None)

    async def _aclose_quietly(self, connector: DestinationConnector | None, name: str) -> None:
        """Release whatever a BUILT-but-rejected connector allocated (a File alternate-credential worker
        thread + token, ADR 0132; an HTTP client) — the lane is not going live, so it must not outlive
        the failure. A close error is logged, never allowed to mask the failure that caused it."""
        if connector is None:
            return
        try:
            await connector.aclose()
        except Exception:
            log.exception("closing the rejected connector for outbound %r raised", name)

    async def _start_outbound_unsafe(self, name: str) -> None:
        """start_outbound body without the reload lock. RESUMES delivery for a paused outbound, BUILDING
        its connector first if the lane has none (a start-disabled / DR-parked / failed lane is
        connector-less — see :meth:`_ensure_destination_built`). A connector that IS live is kept WARM (a
        pause never tore down ``_destinations``), so a plain resume/restart never rebuilds it. Idempotent
        for a name that isn't paused.

        REFUSES a ``deployed=False`` outbound (#233, ADR 0111) with :class:`NotDeployedError`: unlike
        ``auto_start=False`` — a boot gate an operator is *meant* to override at runtime — deploying a
        connection is a config change. There is no delivery worker to resume and no connector to build."""
        self._validate_outbound(name)
        if not self._deployed(name, "outbound"):
            raise NotDeployedError(name)
        await self._ensure_destination_built(name)
        self._outbound_paused.discard(name)
        # The OPERATOR now owns this lane's UP state — the engine park (if any) is spent, and a reload
        # must respect the start (#115): drop the marker so _unpark_outbound_lane can't re-park it.
        self._gate_parked.discard(name)
        # Clear the quiescence signal — the lane is running again (not stopped). The buildup/stall alert
        # suppression (scoped to _outbound_paused membership) lifts here too, so a genuinely backed-up
        # resumed lane can page again.
        ev = self._outbound_quiesced.get(name)
        if ev is not None:
            ev.clear()
        if self._claim_mode == "pooled":
            d = self._dispatchers.get(Stage.OUTBOUND)
            if d is not None:
                d.resume_lane(name)
        else:
            # per_lane: release the loop-top gate; respawn the worker if it exited (STOP policy / crash).
            self._outbound_resume.setdefault(name, asyncio.Event()).set()
            worker = self._workers.get(name)
            if worker is None or worker.done():
                self._spawn_worker(name)

    # --- per-connection active-window scheduler (#147, ADR 0095) --------------

    def _start_schedulers(self) -> None:
        """Spawn one active-window scheduler task per scheduled inbound/outbound connection. Called
        once from :meth:`start` under the reload lock; idempotent per name (a live task is not
        re-spawned). Byte-identical no-op when no connection declares a ``schedule``."""
        for ic in self.registry.inbound.values():
            if ic.schedule is not None:
                self._spawn_scheduler(ic.name, "inbound", ic.schedule)
        for oc in self.registry.outbound.values():
            if oc.schedule is not None:
                self._spawn_scheduler(oc.name, "outbound", oc.schedule)

    def _spawn_scheduler(self, name: str, kind: str, schedule: Schedule) -> None:
        existing = self._schedule_workers.get(name)
        if existing is not None and not existing.done():
            return
        self._schedule_workers[name] = asyncio.create_task(
            self._schedule_worker(name, kind, schedule)
        )

    async def _schedule_worker(self, name: str, kind: str, schedule: Schedule) -> None:
        """Reconcile ``name``'s live listen/deliver state against its active-window ``schedule`` every
        ``_schedule_tick`` seconds until the runner stops. Cooperatively cancellable (it sleeps via
        :meth:`_stop_or_sleep`, which returns True on stop). A reconcile error is logged and swallowed —
        a transient start/stop failure must never kill the scheduler and freeze the connection's
        calendar (the next tick retries)."""
        while not self._stop.is_set():
            try:
                await self._reconcile_schedule(name, kind, schedule)
            except asyncio.CancelledError:
                raise
            except Exception:
                log.exception("schedule worker %r: reconcile failed; will retry next tick", name)
            if await self._stop_or_sleep(self._schedule_tick):
                return

    async def _reconcile_schedule(self, name: str, kind: str, schedule: Schedule) -> None:
        """Bring ``name`` up or park it to match its schedule at the current (injectable) clock — one
        idempotent step. Reuses the SAME per-connection lifecycle the API uses: an inbound is
        started/stopped by binding/unbinding its listener (its router/transform workers keep draining
        any in-flight backlog); an outbound is resumed/paused (a park RETAINS its queued rows pending,
        never dropped). A schedule-park is a clean stop — in-flight messages follow normal stop
        semantics. Distinct stop-reason logging keeps a schedule-park legible vs a credential-fault or
        content STOP (#109)."""
        # Sharding (ADR 0073): only the OWNING shard drives an outbound's delivery lifecycle — a
        # non-owner's start_outbound/stop_outbound raises ShardLaneOwnershipError. Skip so the scheduler
        # doesn't error every tick on a lane another shard owns (single-shard/unsharded owns everything).
        if kind == "outbound" and not self._owns_destination(name):
            return
        # Present but NOT DEPLOYED (#233, ADR 0111): the connection has no listener and no delivery
        # worker, so it has no calendar to keep — a schedule on it is inert config, retained (like the
        # rest of the connection) for the day it IS deployed. Gated ABOVE the start/park branches, not
        # just the start one, so neither half can act: start_inbound/start_outbound would raise
        # NotDeployedError and the scheduler would log an exception EVERY tick.
        if not self._deployed(name, kind):
            return
        active = schedule.is_active(self._schedule_clock())
        running = self.inbound_running(name) if kind == "inbound" else self.outbound_running(name)
        if active and not running:
            # Per-connection auto-start (#115): ``auto_start=False`` means the ENGINE never brings this
            # connection up on its own — only an explicit operator start does. A scheduler tick IS the
            # engine, so an in-window tick must not resurrect a start-disabled connection; without this
            # gate the boot gate was silently defeated by the very first in-window tick. The park branch
            # below is deliberately NOT gated: if the connection is somehow up, the schedule still owns
            # its calendar and closes the window cleanly.
            if not self._auto_start_enabled(name, kind):
                return
            log.info("schedule: connection %r entering active window — starting", name)
            if kind == "inbound":
                await self.start_inbound(name)
            else:
                await self.start_outbound(name)
        elif not active and running:
            log.info("schedule: connection %r leaving active window — parking (clean stop)", name)
            if kind == "inbound":
                await self.stop_inbound(name)
            else:
                await self.stop_outbound(name)

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
        reload). asyncio.Lock isn't reentrant, so the public wrappers must not call each other.

        REFUSES a ``deployed=False`` inbound (#233, ADR 0111) with :class:`NotDeployedError` — binding
        its listener would resolve ``env()`` values the graph never promised exist, and claim a port the
        deployed connection that superseded it may hold. start()/reload() gate BEFORE calling this (a
        not-deployed inbound is skipped silently there, not treated as a fault), so this raise is the
        operator/API path: deploying is a config change, not a runtime action."""
        if name in self._sources:
            return
        if not self._deployed(name, "inbound"):
            raise NotDeployedError(name)
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
        # #200: thread the derived instance posture so --allow-insecure-bind is CLAMPED — a
        # production-PHI listener refuses cleartext even with the flag (a per-connection
        # tls_hop_attested is the surgical per-hop opt-in).
        check_mllp_tls_exposure(
            source_cfg,
            ic.name,
            allow_insecure_bind=self._allow_insecure_bind,
            posture=self._hop_posture,
        )
        check_dimse_tls_exposure(
            source_cfg,
            ic.name,
            allow_insecure_bind=self._allow_insecure_bind,
            posture=self._hop_posture,
        )
        check_tcp_tls_exposure(
            source_cfg,
            ic.name,
            allow_insecure_bind=self._allow_insecure_bind,
            posture=self._hop_posture,
        )
        check_http_tls_exposure(
            source_cfg,
            ic.name,
            allow_insecure_bind=self._allow_insecure_bind,
            posture=self._hop_posture,
        )
        # #1005: the revocation sibling of the four gates above. Separate because it fires on the
        # opposite condition -- those refuse a listener with NO TLS, this one refuses a listener
        # whose TLS is correct but whose client certificates are never checked for revocation.
        check_inbound_revocation(source_cfg, ic.name, posture=self._hop_posture)
        # ADR 0154 D7, immediately after its confidentiality sibling and deliberately separate from it:
        # check_http_tls_exposure returns early whenever tls is truthy, which is exactly the case an
        # authentication requirement most needs to cover. No allow_insecure_bind is passed — a
        # cleartext escape hatch does not get to waive authentication.
        check_http_intake_auth(source_cfg, ic.name, posture=self._hop_posture)
        # #200 (ADR 0092): stamp the posture for the source build too (a DATABASE poll source keys its
        # weakened-TLS refusal on it), matching the exposure-check posture threading above.
        with active_hop_posture(self._hop_posture):
            source = build_source(source_cfg)
        # Inject the connection-event sink (#46) BEFORE start so a listen source can emit accept/refuse/
        # close. None when capture is off (byte-identical). transports/ stays store-agnostic — the sink
        # is a runner-owned coroutine that only enqueues onto the off-hot-path drain queue.
        source.on_connection_event = self._make_connection_event_sink(ic)
        # Inject the inbound's declared content format (ADR 0004) the same runtime way — the transport
        # Source config carries no content_type (it lives on the wiring's InboundConnection). A content-
        # sniffing poll source (RemoteFileSource) reads it to gate its HL7-header quarantine to hl7v2
        # drops only, so a legitimate X12/DICOM/binary drop is not wrongly rejected.
        source.content_type = ic.content_type
        # Inject the intake-auth seams (ADR 0154 D6) the same runtime way. Both are None unless this
        # inbound actually authenticates, so every other connection stays byte-identical. The audit
        # sink keeps transports/ store-free; the limiter is a SYNCHRONOUS predicate, so transports/
        # gains no auth/ edge either — pipeline/ owns both, which is the only layer allowed to.
        source.on_intake_audit = self._make_intake_audit_sink(ic)
        source.intake_rate_limiter = self._make_intake_rate_limiter(ic)
        # ADR 0154 D2: the resolver that lets the listener return bytes out of the store while
        # transports/ imports neither store/ nor pipeline/ (AC-17). None unless this inbound declares
        # reply_from, so every other connection keeps the shipped 202 path byte for byte.
        source.sync_reply = self._make_sync_reply_resolver(ic)
        if source.sync_reply is not None:
            # ADR 0154 D5/AC-10: stop() wakes blocked turns through this BEFORE closing writers.
            source.reply_drain = self._reply_rendezvous.drain
        # Inject the process-in-place dedup ledger (#142): a store-backed adapter keyed to THIS inbound, so
        # a leave-in-place (after_read='leave') File/RemoteFile source records/skips files it has ingested
        # by a HASHED key. Every other source ignores it (byte-identical); transports/ stays store-agnostic
        # — the same runtime-injection shape as on_connection_event / content_type above.
        source.processed_ledger = _StoreProcessedLedger(self.store, ic.name)
        # Leader-gate the source's intake (Track B Step 4b). is_leader is a cheap, synchronous bound
        # method = Callable[[], bool]; passing the bound METHOD (not the coordinator) keeps transports/
        # free of any pipeline/cluster import. Only POLL sources act on it — they skip a scan when it
        # returns False so exactly one node ingests a shared external resource (a dir / DB table /
        # remote dir); LISTEN sources (MLLP/TCP) accept-and-ignore it (each binds its own endpoint). For
        # single-node (NullCoordinator) is_leader is always True, so every poll source scans as before.
        # Opt-in at-start directory validation (#114, ADR 0031 amendment): a File/RemoteFile source with
        # validate_directory=true fails-fast HERE on a missing/unusable directory (default no-op for every
        # other source and for the flag-off default — byte-identical). The raise propagates to the caller
        # (start/reload/API), which isolates the connection as ADR-0031 `failed` — the opt-in alternative
        # to the historical run-time deferral (a dead directory logged-and-retried every poll). Placed at
        # bind, NOT build_check: an intermittently-available dir must still let the graph BUILD.
        await source.validate_startup()
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
            # #122 (ADR 0162): BEFORE the spawn, or a worker respawned into a still-halted inbound
            # would hit its loop-top gate and exit again — a restart that reports success and re-arms
            # nothing.
            if not self._resume_inbound_processing(name):
                # The log is STILL unwritable, so this connection must not come back. The listener is
                # already bound by the time we get here, so undo that too: leaving intake up with the
                # internal stages halted would ACK a sender into a lane nothing is draining. Deliberately
                # not a raise — reload() rolls the WHOLE graph back on an exception from here, and one
                # unwritable log must not turn a routine reload into a full intake rollback.
                self._log_write_refused_restart(name)
                await self._stop_inbound_unsafe(name)
                return
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

    # --- #122 / ADR 0162: fail-closed application-log write guard ------------

    def _on_log_sink_event(self, event: LogSinkEvent) -> None:
        """The guard's escalation, called SYNCHRONOUSLY from whatever thread emitted the record that
        could not be written — the event loop, a handler worker thread, a connector thread. It does one
        thing: hand the event to this runner's loop. Never blocks (we are inside a failing
        ``logging.Handler.emit``) and never raises (the guard is already handling a failure)."""
        loop = self._loop
        if loop is None or loop.is_closed():
            return  # not started, or already torn down — nothing to stop
        try:
            loop.call_soon_threadsafe(self._spawn_log_sink_response, event)
        except RuntimeError:
            return  # the loop closed between the check and the call

    def _spawn_log_sink_response(self, event: LogSinkEvent) -> None:
        task = asyncio.ensure_future(self._respond_to_log_sink_event(event))
        self._log_guard_tasks.add(task)
        task.add_done_callback(self._log_guard_tasks.discard)

    async def _respond_to_log_sink_event(self, event: LogSinkEvent) -> None:
        """Alert on every stage; STOP only on stage 2 under the ``stop`` policy."""
        try:
            if event.stage != "unwritable" or not event.stop_requested:
                # Stage 1 rolled and healed, or the operator chose the "continue" opt-out. Page either
                # way — a sink that rolls repeatedly is a disk about to become stage 2 — but stop nothing.
                self._alert_sink.log_write_failed(
                    event.sink, stage=event.stage, reason=event.reason
                )
                return
            await self._stop_all_for_log_failure(sink=event.sink, reason=event.reason)
        except Exception:
            # NEVER-RAISE: this runs as a bare task off a logging failure. A raise here would be an
            # unretrieved-exception warning at best and would lose the alert at worst.
            log.exception("log-sink escalation response failed for sink %r", event.sink)

    async def _stop_all_for_log_failure(self, *, sink: str, reason: str) -> None:
        """FAIL CLOSED (the #122 ruling): the application log cannot be written, so this process stops
        processing. CLAUDE.md §1 counts and logs every message a connection takes in or puts out;
        processing a message that cannot be logged IS the violation, so **all three tiers** halt —
        intake (the listener unbinds), the INTERNAL stages (router / transform / loopback response,
        via :meth:`_halt_inbound_processing`), and delivery (each owned outbound is paused). Stopping
        only the first and last is what a listener-only halt looks like, and it leaves the backlog
        being routed and transformed with no application log behind it.

        **Scope is the process, and pretending otherwise would be a lie.** The application log is a
        process-global handler set on the root logger — the failure is a property of the SINK, and no
        per-connection attribution exists to narrow it with. So this stops every connection this
        process owns: all of them on a single-process engine, this shard's on a sharded fleet (ADR
        0037), which is the narrowest honest scope available.

        **ACK-on-receipt is preserved, and the boundary is worth stating in the code.** The message
        STORE is a different durable record from the application log and is untouched by an
        application-log failure — this method performs no store I/O. A message already committed to the
        ingress stage stays committed: stopping an inbound unbinds the LISTENER (nothing already ACKed
        is un-ACKed, lost, or re-delivered), and pausing an outbound RETAINS its queued rows PENDING
        un-errored rather than dead-lettering them. Fix the disk, reload, and the backlog drains."""
        if self._log_write_stopped:
            return  # latched: one halt per break
        self._log_write_stopped = True
        detail = f"application log sink {sink!r} is unwritable ({reason})"
        inbounds = [name for name in self.registry.inbound if name in self._sources]
        outbounds = [
            name
            for name in self.registry.outbound
            if self._owns_destination(name) and name not in self._outbound_paused
        ]
        # Alert BEFORE stopping, and through the NOTIFIER rather than a log line: the sink this is
        # about is the one that just broke, so a log line may never land. If the stop itself wedges,
        # the operator has already been told why the engine is going quiet.
        self._alert_sink.log_write_failed(
            sink,
            stage="unwritable",
            reason=reason,
            stopped=len(inbounds) + len(outbounds),
        )
        async with self._reload_lock:
            # THE INTERNAL STAGES FIRST, and they are not an afterthought — they are the half that
            # makes this an enforcement. See :meth:`_halt_inbound_processing`.
            #
            # EVERY REGISTRY INBOUND, deliberately wider than `inbounds` above (which is the BOUND
            # ones, for the alert count and the per-connection stop): an inbound whose listener never
            # bound — isolated by ADR 0031, stopped by an operator, outside its active window — still
            # has router/transform workers draining whatever is already in its lanes. Halting only
            # the bound ones would leave exactly those backlogs processing unlogged.
            self._halt_inbound_processing(self.registry.inbound)
            for name in inbounds:
                try:
                    await self._stop_inbound_unsafe(name)
                except Exception:
                    # One connection refusing to stop must not leave the others running: this is a
                    # fail-closed halt, so a partial stop is strictly better than an abandoned one.
                    log.exception("log-failure stop: inbound %r did not stop cleanly", name)
            for name in outbounds:
                try:
                    self._stop_outbound_unsafe(name)
                except Exception:
                    log.exception("log-failure stop: outbound %r did not pause cleanly", name)
        for name in inbounds + outbounds:
            try:
                # ADR 0014's connection_stopped reports a stop but was never DRIVEN by a log-write
                # failure (#122's own Nearest-existing-mechanism note). Driving it here is what makes
                # the halt legible to the machinery an operator already has — alert rules, ADR 0044
                # durable alert state, the console's stopped view — with the CAUSE in the detail.
                self._alert_sink.connection_stopped(name, detail=detail)
            except Exception:
                log.exception("alert sink raised on connection_stopped for %r", name)

    def _halt_inbound_processing(self, names: Iterable[str]) -> None:
        """Shut down the INTERNAL stages — router, transform, and a loopback's response re-ingress —
        for these inbounds. Sync + await-free; callers hold the reload lock.

        **This is the half of "refuse to process" that stopping the listener does not cover, and its
        absence was measured rather than reasoned about.** The router/transform workers are
        registry-tied, not source-tied (see :meth:`_ensure_inbound_workers`), and ``stop_inbound`` is
        documented as halting intake *while delivery keeps draining*. So with only the listener
        stopped, a message already durably on the ingress stage still flowed ingress -> routed ->
        outbound with no application log behind it: a message that reached the outbound stage after
        the halt, which is exactly "processing stuff that cannot be logged". The outbound pause meant
        it was never delivered, which makes the gap quiet rather than harmless.

        **Cooperative in both claim modes, and NEVER a ``task.cancel``** — a cancelled mid-item worker
        strands its claimed row INFLIGHT and ``reset_stale_inflight`` is startup/DR-only:

        * **pooled** (the default): ``pause_lane`` per stage, the same primitive
          :meth:`_stop_outbound_unsafe` uses. A lane mid-episode reaches PAUSED at its quiesce point,
          so **at most the one in-flight head completes** — bounded, and strictly better than
          stranding its row.
        * **per_lane**: the loop-top gate in the router/transform/response workers reads
          :attr:`_log_halted` and returns at the worker's next turn, the same terminal state a
          STOP-policy halt leaves behind. The wake below is why "next turn" is immediate rather than
          up to a whole ``poll_interval`` of further processing.
        """
        halted = list(names)  # materialised: registry.inbound is a live dict we iterate twice
        self._log_halted.update(halted)
        for stage in (Stage.INGRESS, Stage.ROUTED, Stage.RESPONSE):
            dispatcher = self._dispatchers.get(stage)
            if dispatcher is None:
                continue  # not pooled, or no loopback inbound => no RESPONSE dispatcher
            for name in halted:
                dispatcher.pause_lane(name)
        if self._claim_mode != "pooled":
            # per_lane only: a worker parked in _wait_for_work must be woken to reach its gate. NOT
            # via _wake_lane, whose pooled branch is mark_ready() — re-readying a lane we just paused.
            self._wake_all(Stage.INGRESS, Stage.ROUTED, Stage.RESPONSE)

    def _log_recovery_ok(self) -> bool:
        """May this process resume processing? Only if it can LOG again — re-tested by writing.

        **The halt is not the whole control; refusing to un-halt on a false premise is the other
        half.** Recovery is an operator action ("I fixed the disk"), and a control that simply
        believes them is a control with an off switch. So every path that would lift the halt asks
        the guard to re-validate its dead sinks by writing a real record to them, and a process that
        still cannot log stays halted no matter how many times it is restarted.

        On success the latch is cleared, which matters as much as the refusal: ``_log_write_stopped``
        is a one-shot, so leaving it set after a genuine recovery would mean a LATER break never
        halted anything again. Cheap by construction — it does nothing until a halt has fired.

        The re-validation write is SYNCHRONOUS on the calling (event-loop) thread. That is the same
        posture as every other log write in this engine — stdlib logging is synchronous throughout,
        including the syslog forwarder — and this one runs at most once per operator recovery action,
        never on the hot path, so it is not the blocking-the-loop hazard the async rules are about."""
        if not self._log_write_stopped:
            return True
        guard = active_log_guard()
        if guard is None or guard.revalidate():
            self._log_write_stopped = False
            return True
        return False

    def _log_write_refused_restart(self, name: str) -> None:
        """Page that a recovery attempt was REFUSED because the application log is still unwritable.

        Through the notifier, not a log line, for the same reason the halt itself alerts that way: the
        thing that is broken is the log. Without this the refusal is invisible — the operator asked for
        a restart, got no error (a raise here would roll a reload back), and the connection simply
        stays down. ``stopped=0``: nothing was newly stopped, the point is that nothing was STARTED."""
        guard = active_log_guard()
        dead = (
            ",".join(s.sink for s in guard.status() if s.state == "unwritable")
            if guard is not None
            else "unknown"
        )
        try:
            self._alert_sink.log_write_failed(
                dead or "unknown",
                stage="unwritable",
                reason=(
                    f"refused to restart connection {name!r}: the application log is still "
                    "unwritable, so the engine would be processing what it cannot log"
                ),
                stopped=0,
            )
        except Exception:
            log.exception("alert sink raised on a refused log-failure restart for %r", name)

    async def _unbind_for_log_failure(self) -> None:
        """Take intake back down when :meth:`start` came up into an unwritable application log (#122).

        The counterpart of :meth:`_stop_all_for_log_failure`'s inbound half, for the one case that
        method cannot cover: at ``start`` there was no halt to fire, the log was *already* dead. Called
        with the reload lock held, AFTER the dispatchers exist, so the internal stages are halted
        before the listeners go down rather than after.

        **Unbinding is not belt-and-braces.** Leaving intake up with the internal stages halted would
        ACK a sender into a lane nothing is draining — the same reason
        :meth:`_start_inbound_unsafe`'s own refusal path stops the listener it just bound. Pages
        through the NOTIFIER rather than a log line, for the reason the whole control does: the thing
        that is broken is the log."""
        bound = [name for name in self.registry.inbound if name in self._sources]
        for name in bound:
            try:
                await self._stop_inbound_unsafe(name)
            except Exception:
                # One listener refusing to unbind must not leave the others up: a fail-closed halt is
                # better partial than abandoned (same rule as _stop_all_for_log_failure).
                log.exception("log-failure start: inbound %r did not stop cleanly", name)
        guard = active_log_guard()
        dead = (
            ",".join(s.sink for s in guard.status() if s.state == "unwritable")
            if guard is not None
            else "unknown"
        )
        try:
            self._alert_sink.log_write_failed(
                dead or "unknown",
                stage="unwritable",
                reason=(
                    "the engine started while the application log was unwritable, so it is running "
                    "HALTED: intake is down and nothing is being routed or transformed. Fix the log, "
                    "then restart the connections"
                ),
                stopped=len(bound),
            )
        except Exception:
            log.exception("alert sink raised on a log-failure start halt")

    def _resume_inbound_processing(self, name: str) -> bool:
        """Re-arm one inbound's internal stages after a log-failure halt (#122, ADR 0162). Returns
        whether it re-armed.

        The recovery path the ADR promises — fix the disk, restart the connection, the backlog drains
        — and it must live HERE rather than in a reload: a reload deliberately never rebuilds the
        dispatchers, so a paused ingress lane would otherwise stay paused for the life of the process
        and the halt would be unrecoverable without a restart. Per-inbound, so restarting A leaves B
        halted until B is restarted too. A no-op when this inbound was never halted.

        **REFUSES while the log is still unwritable** (:meth:`_log_recovery_ok`). Re-arming there
        would hand back exactly the state the halt exists to prevent — measured: a restart with the
        sinks still dead resumed the whole pipeline and drove a message to PROCESSED with no
        application log behind it, and neither latch could ever fire again."""
        if name not in self._log_halted:
            return True
        if not self._log_recovery_ok():
            return False
        self._log_halted.discard(name)
        for stage in (Stage.INGRESS, Stage.ROUTED, Stage.RESPONSE):
            dispatcher = self._dispatchers.get(stage)
            if dispatcher is not None:
                dispatcher.resume_lane(name)
        return True

    async def _start_outbound(self, name: str, oc: OutboundConnection) -> None:
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
        # #134 (ADR 0082): per-outbound batch aggregation (None = the unchanged one-per-send path).
        # No global [delivery] default — batching is strictly opt-in per outbound.
        self._batch[name] = oc.batch
        # BACKLOG #82: resolve the per-lane egress pacing interval (None/0 = off) so the delivery seam
        # reads a plain float; re-resolved here + in _reconcile_outbounds so a reload retunes it.
        self._send_pace[name] = _resolve_send_pace(oc.spec.settings)
        self._simulate[name] = self._resolve_simulate(name, oc)
        # Present but NOT DEPLOYED (#233, ADR 0111) — checked FIRST, so deployed=False WINS over
        # auto_start (which is ignored entirely below). No connector is built, so its env() values are
        # NEVER resolved: this is what lets a connection whose credentials do not exist yet sit in the
        # config without failing the build and bringing the engine up DEGRADED at every boot.
        #
        # And, unlike EVERY other down state (auto_start, DR park, ADR-0031 build failure), NO DELIVERY
        # WORKER IS SPAWNED. Those states all keep the worker so a routed row queues + retries + self-
        # heals — the right answer for a lane that is *coming back*. A not-deployed lane is not coming
        # back without a config change, so a queued row there could only sit forever and buildup-alert on
        # an INTENTIONAL state — the exact defect this feature removes. Nothing can queue to it anyway:
        # transform_one declines a Send to it BEFORE any outbound row is committed (the count-and-log
        # record is the decline event, not a stranded row). With no worker, nothing can claim, back off,
        # buildup-alert or stall-alert. Any row that PREDATES the flag flip is retained PENDING (the lane
        # stays in the registry, so the startup dead_letter_missing_destinations sweep leaves it alone)
        # and drains untouched the moment the connection is deployed.
        if not oc.deployed:
            self._destinations.pop(name, None)  # never a live connector for a not-deployed lane
            self._park_outbound_lane(name)
            return
        # Per-connection auto-start (#115): a start-disabled outbound is NOT built at engine start — its
        # lane is recorded START-DISABLED (paused + quiesced), so it honestly reports status:"stopped"
        # and /connections emits a row for it even before it ever carries traffic. An operator can bring
        # it up at runtime (POST /connections/{name}/start -> _start_outbound_unsafe, which BUILDS the
        # connector this gate declined to build and bypasses this gate). Its delivery worker still spawns
        # (it parks at the loop-top pause gate), so a routed row is RETAINED PENDING and drains the moment
        # the lane is started — never dropped, never claimed connector-less, and never buildup-paged (the
        # alert suppression is scoped to _outbound_paused, which this lane now joins). No-op
        # (byte-identical) when auto_start is True — every normal connection. Boot-time gate only.
        if not oc.auto_start:
            self._destinations.pop(name, None)  # no live connector for a start-disabled lane
            self._park_outbound_lane(name)
            self._spawn_worker(name)
            return
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
        connector: DestinationConnector | None = None
        try:
            dest = _dest_config(oc, self._env_values, self._trust_anchor_policy, self._egress)
            check_egress_allowed(dest, self._egress)  # fail-closed egress allowlist (WP-11c)
            # #200 (ADR 0092): stamp the derived instance posture for the connector build so each cell's
            # posture-keyed insecure-hop refusal decides against THIS config's posture — NOT the unstamped
            # fail-closed/no-op default. engine.start() never calls build_check (add_registry has already
            # set the runner), so without this the raw/MLLP/DB guards no-op (a prod-PHI plaintext outbound
            # would ship cleartext) and the HTTP guards fail-closed (a legit non-prod cleartext lane would
            # wrongly refuse) on the primary serve path. Mirrors _start_inbound_unsafe threading posture
            # into the exposure checks. No-op (None) in a test/embedding that derives no posture.
            with active_hop_posture(self._hop_posture):
                connector = build_destination(dest)
            # ADR 0013: a capturing outbound on a backend that can't persist captures must not deliver
            # — but (ADR 0031) degrade THIS lane, don't crash the engine. Rows routed here are retried,
            # not dropped, so the ADR 0013 "never silently drop replies" intent is preserved.
            if getattr(connector, "capture_response", False) and not getattr(
                self.store, "supports_response_capture", True
            ):
                raise RuntimeError(
                    f"outbound {name!r} sets capture_response=True but the store backend does not "
                    "support request/response capture (ADR 0013) — SQLite, Postgres, and SQL Server "
                    "all do"
                )
            # Opt-in at-start directory validation (#114) — the outbound mirror of the source hook
            # awaited in _start_inbound_unsafe. A File/RemoteFile outbound with validate_directory=true
            # fails-fast HERE on a missing/unusable target directory; the default is a no-op on every
            # connector, so every lane authored today starts byte-identically. Deliberately INSIDE this
            # try: a DestinationStartupError then takes the SAME ADR-0031 isolation path as a build
            # failure — the lane is recorded failed with NO connector and its worker is STILL spawned,
            # so rows routed to it are retried + buildup-alerted, never dropped. On an outbound that
            # degraded-lane state IS "invalid means not-started". Placed at start, NOT build_check: an
            # intermittently-available directory must still let the graph BUILD.
            await connector.validate_startup()
        except Exception as exc:
            await self._aclose_quietly(connector, name)
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
            if self._sources or self._workers or self._destinations or self._dispatchers:
                # ADR 0157 D7: a prior teardown raised or was cancelled from outside, so _running is
                # False (the finally) but the built state survives. Building on top of it would leave
                # orphaned listeners bound — and _start_inbound_unsafe's `if name in self._sources:
                # return` would silently skip EVERY rebind — plus two dispatchers per stage claiming one
                # lane, the per-lane FIFO hazard the single-consumer invariant exists to close.
                # Idempotent, and structurally unreachable after a clean stop, so single-node never
                # enters it.
                await self._teardown_unsafe(TeardownReason.SHUTDOWN)
            self._stop.clear()
            # Capture the engine loop so a handler's worker thread can bridge a db_lookup back onto it.
            self._loop = asyncio.get_running_loop()
            # #122 (ADR 0162): subscribe to the application-log write guard. Done here, after the loop
            # is captured, because the escalation's ONLY job is to bounce onto that loop. A process
            # whose logging was never configured through configure_logging has no guard, and the
            # subscription is simply skipped — no engine behaviour depends on the guard existing.
            guard = active_log_guard()
            if guard is not None:
                # A START IS A RE-ARM, SO IT IS GATED ON THE LOG LIKE EVERY OTHER ONE. This used to
                # clear both latches unconditionally, and that made `start` the single door back into
                # processing that never asked whether the log worked — the exact shape
                # :meth:`_resume_inbound_processing` was gated for, reached by the one path that
                # bypasses it. MEASURED, in both claim modes, with both sinks made unwritable BEFORE
                # the runner was built: a committed ingress row went to ``PROCESSED`` and was
                # delivered while ``guard.can_log()`` read False throughout.
                #
                # :meth:`~messagefoundry.logging_guard.LogWriteGuard.revalidate` re-tests each DEAD
                # sink by writing a real record to it, so the ordinary case — a guard
                # ``configure_logging`` built moments ago, with nothing dead — has nothing to probe,
                # answers True, and the clear happens exactly as before.
                if guard.revalidate():
                    self._log_write_stopped = False  # a restart re-arms the halt
                    self._log_halted.clear()  # …and un-halts every inbound's internal stages
                else:
                    # START HALTED rather than refuse to start: ``/status``, the alert state and every
                    # recovery path live in a RUNNING engine, and tearing them down is how an operator
                    # loses the explanation for why the engine went quiet — the same reason ADR 0162
                    # rejects halting the whole engine. The per_lane workers read this set at their
                    # loop top; the pooled lanes are paused in :meth:`_start_pooled_dispatchers`, and
                    # the listeners that bound above come back down in :meth:`_unbind_for_log_failure`.
                    self._log_write_stopped = True
                    self._log_halted.update(self.registry.inbound)
                guard.set_escalation(self._on_log_sink_event)
            # Connection-event drain task (#46): created before any source binds so an early accept's
            # enqueued event has a consumer. Skipped entirely when capture is off (no sink, no queue).
            if self._connection_events:
                self._conn_event_q = asyncio.Queue(maxsize=_CONN_EVENT_QUEUE_MAX)
                self._conn_event_drainer = asyncio.create_task(self._connection_event_drainer())
            if self.registry.shard_id is not None:
                # ADR 0073 sharded-mode extras: page on a non-owned lane backing up (a hung owner is
                # invisible to the supervisor and never pages itself), and warn on the per_lane_wake
                # combination (cross-shard produce has no wake — only the 30s idle backstop).
                self._shard_watchdog = asyncio.create_task(self._non_owned_lane_watchdog())
                if self._claim_mode != "pooled" and self._per_lane_wake:
                    log.warning(
                        "sharded engine with per_lane_wake=True: a cross-shard send into an idle "
                        "owned lane is discovered only by the %.0fs idle backstop (no cross-process "
                        "wake) — prefer claim_mode='pooled' (<=%.2fs sweep) for sharded fleets",
                        _PER_LANE_IDLE_BACKSTOP_SECONDS,
                        self._pooled_sweep_interval,
                    )
            try:
                # Per-connection fault isolation (ADR 0031): a single outbound build / inbound bind
                # failure no longer aborts startup — it is recorded + alerted and the rest of the graph
                # still comes up (a failed connection must not crash the engine). The outer except below
                # stays a backstop for genuinely fatal, graph-wide startup errors (the store, the
                # lookup executor), which still unwind + raise.
                for name, oc in self.registry.outbound.items():
                    await self._start_outbound(name, oc)
                # Build the live-lookup executor from the graph (env-resolved + egress-checked here);
                # None when no DatabaseLookup is declared, keeping the transform path byte-identical. A
                # failure here is graph-wide (not one connection), so let it hit the backstop below.
                self._lookup_executor = self._build_lookup_executor()
                self._fhir_lookup_executor = self._build_fhir_lookup_executor()
                # ADR 0057: compute the inline-fast-path eligibility now that the lookup executors are
                # known (P-lookup needs both to be None). Default-OFF unless an inbound opted in.
                self._recompute_inline_ok()
                for ic in self.registry.inbound.values():
                    # Present but NOT DEPLOYED (#233, ADR 0111) — checked FIRST, so deployed=False WINS
                    # over auto_start (ignored entirely for it). The LISTENER is not bound, so no source
                    # is built and its env() values are never resolved; unlike an ADR-0031 bind failure
                    # this is not a fault, so the engine is NOT degraded. Its router + transform workers
                    # ARE still spawned below (the ADR-0048 AC-3 rule): flipping a live feed to
                    # not-deployed while rows are in flight must not STRAND them — the listener stops
                    # accepting NEW work while the existing ingress/routed backlog drains to completion.
                    if not ic.deployed:
                        continue
                    # Per-connection auto-start (#115): a start-disabled inbound listener is NOT bound at
                    # engine start — it reports status:"stopped" and an operator can start it at runtime
                    # (POST /connections/{name}/start). Its router + transform workers are still spawned
                    # below (backlog drains), exactly like a DR-filtered listener. No-op (byte-identical)
                    # when auto_start is True — every normal connection.
                    if not ic.auto_start:
                        continue
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
                # independent of listen state (AC-3: a filtered inbound still drains its backlog). ADR
                # 0066: no-op under pooled (the gate is inside _ensure_inbound_workers) — the pooled
                # StageDispatchers replace them below.
                for name in self.registry.inbound:
                    self._ensure_inbound_workers(name)
                # ADR 0066 pooled mode: replace the per-lane router/transform/delivery workers with one
                # StageDispatcher per stage. INSIDE the try so a fail-closed RCSI verify unwinds the
                # partial start via the except below (teardown + re-raise). The engine already ran
                # reset_stale_inflight before runner.start(), so each dispatcher's start-time
                # seed-all-READY + immediate sweep re-claims any recovered rows with no wake.
                if self._claim_mode == "pooled":
                    await self._start_pooled_dispatchers()
                # ADR 0075: resolve per-hop statement batching on the store (SQL-Server-only, fail-closed).
                # Independent of claim_mode, so it runs for both pooled and per_lane.
                self._activate_statement_batching()
                # #122 (ADR 0162): this runner came up into an unwritable application log, so the
                # listeners that bound above have to come back down. LAST, because the halt is only
                # complete once the dispatchers exist to be paused (step 2.6).
                if self._log_write_stopped:
                    await self._unbind_for_log_failure()
            except Exception:
                # A truly fatal startup error (store / lookup executor — NOT a single connection, which
                # is isolated above) must not leave half the graph wired with _running still False:
                # unwind everything we started so the listeners are released and a retry can rebind (M-8).
                log.exception("wiring start failed; unwinding the partial start")
                # Explicitly SHUTDOWN (ADR 0157): a partial start is not a demotion — there is no lease
                # being handed over, so there is nothing to bound and no reason to abandon a listener.
                await self._teardown_unsafe(TeardownReason.SHUTDOWN)
                raise
            self._running = True
            # #147 (ADR 0095): spawn one active-window scheduler task per SCHEDULED connection. Each
            # AUTO-STARTs/STOPs its connection through the same start_inbound/stop_inbound (or
            # start_outbound/stop_outbound) path the API uses — a schedule-park is a clean stop, never a
            # crash. Spawned AFTER _running is set so the first reconcile can (re)park an auto-started
            # connection immediately. No-op (byte-identical) when no connection declares a schedule.
            self._start_schedulers()
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

    def _sandbox_for(self, name: str) -> SandboxSession | None:
        """The persistent sandbox worker for inbound ``name`` (ADR 0087), or ``None`` to run in-process.

        Returns ``None`` — the byte-identical in-process path — unless ``[sandbox].mode=subprocess``
        AND a config source is available (an embedded runner with no config dir can't re-load the
        graph in a child, so it degrades to in-process). The :class:`SandboxSession` object is created
        here (cheap; loop-safe) but the child subprocess is spawned lazily inside the worker thread on
        first dispatch, so this never blocks the event loop. Sessions are reused per inbound and reaped
        at :meth:`stop`."""
        policy = self._sandbox_policy
        if policy is None or policy.mode is SandboxMode.OFF:
            return None
        cfg_dir = self._sandbox_config_source[0] if self._sandbox_config_source else None
        if cfg_dir is None:
            return None
        session = self._sandbox_sessions.get(name)
        if session is None:
            env = self._sandbox_config_source[1] if self._sandbox_config_source else None
            # The engine's code-set tables travel once per spawn in the boot frame (not per dispatch),
            # so the child serves exactly what mode=off would rather than its own re-read of codesets/.
            session = SandboxSession(
                policy,
                inbound=name,  # attributes the child's relayed stderr to this feed (ADR 0176)
                config_dir=cfg_dir,
                env=env,
                code_sets=self.registry.code_sets,
            )
            self._sandbox_sessions[name] = session
        return session

    async def stop(
        self,
        *,
        reason: TeardownReason = TeardownReason.SHUTDOWN,
        budget_seconds: float | None = None,
    ) -> None:
        """Stop the graph. ``reason`` is keyword-only with a SHUTDOWN default, so all ~170 existing
        ``runner.stop()`` call sites across the engine, the tests and the harness are unchanged and
        behave identically (ADR 0157 C6)."""
        async with self._reload_lock:  # serialize against an in-flight reload (no torn-down state)
            had_state = self._running or bool(self._sources or self._workers or self._destinations)
            await self._teardown_unsafe(reason, budget_seconds=budget_seconds)
            if reason is TeardownReason.SHUTDOWN and self._pending_source_stops:
                # Never orphan a task at loop close. Under DEMOTE we deliberately leave them running —
                # settling them is start()'s job, at the next promotion.
                await self._settle_pending_source_stops()
            if had_state:
                log.info("wiring stopped")  # UNCHANGED string on the SHUTDOWN path

    async def _stop_sources_demote(self, budget: float) -> None:
        """DEMOTE-only bounded, CONCURRENT source stop (ADR 0157 Inc 4 / D6). NEVER raises.

        ONE phase-level deadline over ALL tasks — not a per-source timeout under a semaphore, which
        would cost ``ceil(N/C) x budget`` (~63s at the 1,500-connection target against an ~8s margin).

        ``asyncio.wait`` is the primitive, NOT ``wait_for``: it never cancels its awaitables, so
        "abandon, do not cancel" is a property of the call itself rather than of one ``asyncio.shield``
        token a later edit can silently drop.

        Tasks are created eagerly, outside any gate. The four ``asyncio.start_server`` sources
        (MLLP/TCP/X12/HTTP) call ``server.close()`` in their SYNCHRONOUS prologue, so accept stops on
        the first loop pass after task creation — before this ``wait``'s timeout can fire, even at
        budget 0.0 — and the expensive part is only the client drain. Note the precise claim:
        ``create_task`` merely SCHEDULES, so nothing runs until we suspend on the ``wait`` below; do not
        insert anything between them.

        Abandonment is safe for those four. It is NOT safe for DICOM, which releases its port inside
        ``await to_thread(server.shutdown)`` — an abandoned DICOM stop can still hold the port at
        re-promotion. File/RemoteFile/Database/Timer only set an Event, but each is leader-gated and
        parks on that Event, so an abandoned one finishes at most its single in-flight scan.

        The bound is applied HERE, at the call site — never by editing a transport constant, which would
        make ``transports/`` know about clustering (the one-way dependency rule).
        """
        # A PREVIOUS demotion's stops have had a whole leadership term; cancel them rather than
        # accumulating a generation per flap. Generation-scoped, so no arbitrary count cap is needed.
        for stale in self._pending_source_stops:
            stale.cancel()
        self._pending_source_stops = []
        sources = list(self._sources.items())  # snapshot BEFORE the first await
        if not sources:
            return
        tasks = [asyncio.create_task(src.stop(), name=f"demote-stop:{n}") for n, src in sources]
        _done, still = await asyncio.wait(tasks, timeout=max(0.0, budget))
        for task in _done:
            if not task.cancelled() and task.exception() is not None:
                log.warning("demotion: an inbound stop() failed: %s", task.exception())
        if still:
            self._pending_source_stops = list(still)
            for task in still:
                task.add_done_callback(self._reap_pending_stop)
            log.warning(
                "demotion: %d inbound listener(s) did not stop within %.2fs and were ABANDONED "
                "(their listening sockets are already closed; the client drain finishes in the "
                "background and is settled at the next promotion). The node is NOT quiescent — a "
                "message mid-handler still finishes its commit and its ACK, which count-and-log "
                "requires; the successor drains the body.",
                len(still),
                budget,
            )

    async def _quiesce_workers_demote(self, budget: float) -> None:
        """per_lane parity for the pooled quiesce (ADR 0157 Inc 5). NEVER raises.

        These loops are ``while not self._stop.is_set()`` and ``_stop`` was set at the top of teardown,
        so they exit on their own once the CURRENT claimed prefix resolves. ``asyncio.wait`` never
        cancels and never raises on timeout; the existing cancel + gather below remains the fallback.

        No-op in pooled mode: all FOUR dicts are empty there, because ``_ensure_inbound_workers``
        returns early under ``pooled`` and ``_spawn_worker`` is a documented pooled no-op.

        MUST run ABOVE the source phase, or per_lane workers keep issuing post-demotion terminal writes
        for the whole source phase.
        """
        live = [
            task
            for task in (
                *self._workers.values(),
                *self._router_workers.values(),
                *self._transform_workers.values(),
                *self._response_workers.values(),
            )
            if not task.done()
        ]
        if live:
            await asyncio.wait(live, timeout=max(0.0, budget))

    async def _quiesce_dispatchers_demote(self, budget: float) -> None:
        """DEMOTE-only cooperative dispatcher stop (ADR 0157 Inc 5). NEVER raises. No-op in per_lane.

        ``d.stop()`` cancels the lane serializers, and a cancelled serializer leaves its claimed prefix
        INFLIGHT BY DESIGN. On Postgres that is latency; on SQL Server there is no periodic in-flight
        recovery at all. So on the one path we KNOW is handing over, drain first: a serializer allowed
        to reach its terminal transition leaves ZERO rows INFLIGHT — its tail is ``release_claimed``'d,
        its faulting head ``reschedule_claimed``'d, and a claimed OUTBOUND head that has not sent hits
        the pre-send bail and re-pends un-errored.

        ``stop()`` still runs unconditionally afterwards: it is BOTH the state-clearing path AND the
        hard-cancel fallback, so there is exactly ONE dispatcher teardown to keep correct, not two.
        """
        if not self._dispatchers:
            return
        dispatchers = list(self._dispatchers.values())  # held across an await
        drained = await asyncio.gather(
            *(d.quiesce(budget) for d in dispatchers), return_exceptions=True
        )
        if any(result is not True for result in drained):
            log.warning(
                "demotion: %d of %d stage dispatcher(s) did not drain within %.2fs — hard "
                "cancelling. Their claimed rows stay INFLIGHT: bounded on Postgres by "
                "reclaim_expired_leases, but on SQL Server recovered ONLY by the successor's "
                "on-promotion reset_stale_inflight — so if no node takes over, they strand.",
                sum(1 for result in drained if result is not True),
                len(dispatchers),
                budget,
            )
        await asyncio.gather(*(d.stop() for d in dispatchers), return_exceptions=True)
        self._dispatchers.clear()

    def _reap_pending_stop(self, task: asyncio.Task[None]) -> None:
        """Retrieve an abandoned stop's exception, else asyncio logs 'never retrieved' at GC."""
        if task in self._pending_source_stops:
            self._pending_source_stops.remove(task)
        if not task.cancelled() and task.exception() is not None:
            log.warning(
                "demotion: an abandoned inbound stop() ended with an error: %s", task.exception()
            )

    async def _settle_pending_source_stops(self) -> None:
        """Join a prior demotion's abandoned stops, BOUNDED — and the bound is mandatory.

        This runs inside ``_reload_lock``, which ``reload()``, ``stop()``, the per-connection
        start/stop/restart and every ``/connections`` handler also take. An unbounded join would
        therefore wedge re-promotion, engine shutdown and the connection API for as long as a wedged
        File/Database ``stop()`` runs (those gather with no cancel and no timeout).

        On timeout we cancel and proceed: a failed rebind is isolated per connection (ADR 0031,
        operator-recoverable), whereas refusing to re-promote strands the whole graph — and
        strand-direction is forbidden.
        """
        pending = [task for task in self._pending_source_stops if not task.done()]
        self._pending_source_stops = []
        if not pending:
            return
        _done, still = await asyncio.wait(pending, timeout=_PENDING_STOP_SETTLE_SECONDS)
        for task in still:
            task.cancel()
        if still:
            await asyncio.gather(*still, return_exceptions=True)
            log.warning(
                "%d abandoned inbound stop(s) did not finish within %.1fs and were cancelled; a "
                "rebind of those ports may fail (isolated per connection, ADR 0031)",
                len(still),
                _PENDING_STOP_SETTLE_SECONDS,
            )

    async def _teardown_unsafe(
        self,
        reason: TeardownReason = TeardownReason.SHUTDOWN,
        *,
        budget_seconds: float | None = None,
    ) -> None:
        """Tear down all sources/workers/destinations and mark stopped. Lock-free (callers hold
        _reload_lock) and idempotent — cleans up whatever is registered even if the runner never
        reached _running, so a half-started runner (review M-8) and a double stop() are both safe.

        ``reason`` (ADR 0157 C6) selects the SOURCE + DISPATCHER phases only; every other phase, and
        their order, is shared. Under SHUTDOWN the executed statements are today's, verbatim.

        **THE INVARIANT: ``self._running = False`` must execute on every path.**
        ``Engine._reconcile_graph``'s bring-up branch is ``is_leader() and not running``, so a teardown
        that returns or raises without clearing it makes this node **un-re-promotable, silently, with no
        exception**. Two mechanisms enforce it: every DEMOTE bound is absorbed at its own call site (a
        timeout CONTINUES the sequence rather than unwinding it — unwinding would skip the worker
        cancel, the destination aclose and every ``.clear()``), and the ``finally`` below.

        The ``finally`` is a BACKSTOP, **not** a licence to wrap this coroutine in ``wait_for`` from
        OUTSIDE: a cancelled teardown still leaves ``_sources`` populated, which is why ``start()``
        re-runs teardown on residual state and ``_reconcile_graph`` carries a ``has_residual_state``
        branch (ADR 0157 D7).
        """
        demote = reason is TeardownReason.DEMOTE
        budget = (
            max(
                0.0,
                budget_seconds if budget_seconds is not None else _DEMOTE_BUDGET_FALLBACK_SECONDS,
            )
            if demote
            else 0.0
        )
        try:
            await self._teardown_body(demote, budget)
        finally:
            self._running = False

    async def _teardown_body(self, demote: bool, budget: float) -> None:
        """The teardown sequence itself. Split out ONLY so the ``finally`` above contains no await —
        an external cancel therefore cannot interrupt the one statement that must always run."""
        self._stop.set()
        # #122 (ADR 0162): unsubscribe from the log guard FIRST, so a record emitted during teardown
        # cannot schedule a stop against a runner that is already stopping. clear_escalation is a
        # no-op unless WE are still the installed responder (a second runner that registered after us
        # keeps its subscription — silently unwiring it would leave that engine unguarded).
        guard = active_log_guard()
        if guard is not None:
            guard.clear_escalation(self._on_log_sink_event)
        for _guard_task in list(self._log_guard_tasks):
            _guard_task.cancel()
        self._log_guard_tasks.clear()
        # #147 (ADR 0095): cancel the active-window scheduler tasks FIRST so no schedule tick calls
        # start/stop_inbound/outbound while the rest of teardown runs (a task blocked awaiting the reload
        # lock is interrupted by cancel). Empty in the always-on case, so this is a no-op there.
        if self._schedule_workers:
            _sched_tasks = list(self._schedule_workers.values())
            self._schedule_workers.clear()
            for _t in _sched_tasks:
                _t.cancel()
            await asyncio.gather(*_sched_tasks, return_exceptions=True)
        # B12 (ADR 0061): break every waiting worker out of its wait so cancel()+gather lands promptly.
        # OFF sets the four stage singletons (byte-identical); ON sets every registered lane Event. ADR
        # 0066 pooled: skip — the shared _stop.set() already breaks the dispatchers' loops, and _wake_all
        # here would notify_work() dispatchers we are about to stop.
        if self._claim_mode != "pooled":
            self._wake_all(Stage.INGRESS, Stage.ROUTED, Stage.RESPONSE, Stage.OUTBOUND)
        if demote:
            # ADR 0157 Inc 5: DEMOTE INVERTS the ADR 0066 D3 order below, deliberately. Egress is the
            # split-brain-relevant action, so its budget must start NOW rather than after the source
            # phase. A listener staying up for those milliseconds is CORRECT under count-and-log (its
            # ACKed message is durable at the ingress stage, PENDING and never INFLIGHT, and the
            # successor drains it), and a listener wake into an already-cleared dispatcher is a verified
            # no-op (_wake_lane returns on `is None`) — which is what D3 exists to guarantee, and what
            # makes the inversion safe.
            await self._quiesce_workers_demote(budget * _DEMOTE_QUIESCE_SHARE)
            await self._quiesce_dispatchers_demote(budget * _DEMOTE_QUIESCE_SHARE)
            await self._stop_sources_demote(budget * (1.0 - _DEMOTE_QUIESCE_SHARE))
        else:
            for source in self._sources.values():
                await source.stop()
            # ADR 0066 D3 ordering: stop the pooled dispatchers AFTER the sources are stopped — so a
            # listener can no longer mark_ready an already-cleared dispatcher — NOT right after
            # _stop.set(). The shared _stop already broke their loops; d.stop() cancels each
            # claimer/sweep/lane task + timer and clears its state, then we drop the dict. A cancelled
            # serializer leaves its claimed rows INFLIGHT for reset_stale_inflight (crash-safety) —
            # never released. Empty in per_lane mode, so this is a no-op there and the per_lane worker
            # cancel/gather below is unchanged.
            if self._dispatchers:
                await asyncio.gather(
                    *(d.stop() for d in self._dispatchers.values()), return_exceptions=True
                )
                self._dispatchers.clear()
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
                try:  # noqa: SIM105
                    await asyncio.wait_for(self._conn_event_q.join(), _CONN_EVENT_FLUSH_GRACE)
                except (TimeoutError, asyncio.CancelledError):
                    pass
            self._conn_event_drainer.cancel()
            await asyncio.gather(self._conn_event_drainer, return_exceptions=True)
            self._conn_event_drainer = None
            self._conn_event_q = None
        if self._shard_watchdog is not None:
            self._shard_watchdog.cancel()
            await asyncio.gather(self._shard_watchdog, return_exceptions=True)
            self._shard_watchdog = None
        for connector in self._destinations.values():
            await connector.aclose()
        # ADR 0071 B5: tear down the per-stage fusing executors + drop the dedicated synchronous handoff
        # pools — AFTER the dispatchers stopped (no fused hop can be submitted now) and BEFORE the lookup
        # executor closes. Run the shutdown OFF the loop (bounded), so a fused worker mid-COMMIT draining
        # can never wedge the loop; cancel_futures drops any not-yet-started hop. Reliability-core: a
        # reload never reaches here (only stop() tears down) — the executors + pools survive a reload.
        fusing = [
            e for e in (self._fuse_route_executor, self._fuse_transform_executor) if e is not None
        ]
        if fusing:
            store = cast(_FusedHandoffStore, self.store)

            def _shutdown_fusing() -> None:
                for executor in fusing:
                    executor.shutdown(wait=True, cancel_futures=True)
                store.close_sync_handoff_pool()  # SS-only; only built when the store is SQL Server

            await asyncio.to_thread(_shutdown_fusing)
            self._fuse_route_executor = None
            self._fuse_transform_executor = None
        self._fusion_active = False
        # ADR 0087 (#197): stop the per-inbound sandbox worker children (kills + reaps each subprocess).
        # Run OFF the loop (each close() waits on a process) so a draining child can't wedge the loop.
        # No-op unless [sandbox].mode=subprocess actually spawned any.
        if self._sandbox_sessions:
            _sessions = list(self._sandbox_sessions.values())
            self._sandbox_sessions.clear()

            def _close_sandboxes() -> None:
                for _s in _sessions:
                    _s.close()

            await asyncio.to_thread(_close_sandboxes)
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
        self._batch.clear()
        self._send_pace.clear()  # BACKLOG #82: drop pacing config + clock on a full teardown
        self._send_pace_at.clear()
        self._simulate.clear()
        self._lane_healthy.clear()
        self._next_buildup_alert.clear()
        self._next_stall_alert.clear()
        # #93: drop the per-lane saturation depth-sample history + re-alert throttle so a start()-after-
        # stop() (or a full reload teardown) begins sampling a fresh backlog curve, not a stale one.
        self._saturation_detectors.clear()
        self._next_saturation_alert.clear()
        self._sources.clear()
        # B12 (ADR 0061): drop the per-lane wake Events now that every worker is cancelled+gathered. Safe
        # here (post-teardown) — NEVER clear/delete lane Events mid-run (a removed-but-draining worker and
        # a re-added lane both reuse them by name via get-or-create). No-op when per_lane_wake is off.
        for _lane_dict in self._lane_events.values():
            _lane_dict.clear()
        # ADR 0066: reset pooled-mode transient state (no-ops in per_lane mode — empty/False already).
        self._pooled_buildup_at.clear()
        # Connection controls: operator pauses are in-memory and do NOT survive a full teardown — clear
        # them so a start()-after-stop() begins with every outbound running (a fresh dispatcher has no
        # PAUSED lanes; a stale _outbound_paused would make outbound_running lie about the new lane).
        self._outbound_paused.clear()
        self._outbound_quiesced.clear()
        self._outbound_resume.clear()
        self._gate_parked.clear()
        self._rcsi_off_degraded = False
        # ADR 0071 B5: reset the fusion degraded gauge so a start()-after-stop() begins clean (the
        # executors + pools were already torn down above; _fusion_active reset there too).
        self._fusion_pool_open_failed = False
        # NOTE: `self._running = False` is NOT here — it moved into _teardown_unsafe's `finally`
        # (ADR 0157 D7) so a raised or cancelled teardown still leaves this node re-promotable.

    # --- outbound worker management ------------------------------------------

    def _spawn_worker(self, name: str) -> None:
        """Start a delivery worker for one outbound connection (drains its outbox rows). ADR 0066 D5:
        in pooled mode the per-outbound delivery worker is replaced by the OUTBOUND StageDispatcher, so
        this is a no-op — the mode gate lives HERE (not at each call site) so ``_start_outbound`` /
        ``_reconcile_outbounds`` still build the connector into ``self._destinations`` (the pooled
        delivery body re-resolves from it) without leaking a per_lane worker.

        Sharded (ADR 0073): a lane another shard owns gets NO local worker — same choke-point
        placement, so start/reconcile/respawn all inherit the gate while the connector stays built
        (status, DR parking and the dead-letter sweeps keep keying off the full outbound map)."""
        if self._claim_mode == "pooled":
            return
        if not self._owns_destination(name):
            log.info(
                "outbound %r: delivery lane owned by shard %r (this is shard %r) — no local "
                "delivery worker (ADR 0073 single consumer per lane)",
                name,
                self._destination_owner(name),
                self.registry.shard_id,
            )
            return
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
        # ADR 0066 D5: pooled mode replaces the per-inbound router/transform (+ loopback response)
        # workers with the per-stage StageDispatchers, so this is a no-op — the gate lives HERE so no
        # call site (start / start_inbound / reload) can leak a per_lane inbound worker under pooled.
        if self._claim_mode == "pooled":
            return
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

    # --- pooled-mode dispatcher management (ADR 0066) ------------------------

    def _has_loopback_inbound(self) -> bool:
        """Whether the live registry holds any LOOPBACK inbound — the condition for a RESPONSE
        dispatcher (ADR 0013 re-ingress tokens drain only on a loopback lane)."""
        return any(ic.spec.type is ConnectorType.LOOPBACK for ic in self.registry.inbound.values())

    def _pooled_lane_provider(self, stage: Stage) -> Callable[[], set[str]]:
        """The live-registry lane set for one stage's dispatcher (ADR 0066 §4). INGRESS/ROUTED = this
        engine's inbound lanes; RESPONSE = the loopback inbound lanes; OUTBOUND = the outbound lanes
        (registry ∪ any built connector still draining after a reload dropped it), each filtered to
        the lanes THIS shard owns (ADR 0073 — a no-op unsharded; the predicate form keeps a
        reload-dropped lane draining on exactly its owner). Read live so a reload's swapped graph is
        reflected without rebuilding the dispatcher."""
        if stage is Stage.OUTBOUND:
            return lambda: {
                dest
                for dest in set(self.registry.outbound) | set(self._destinations)
                if self._owns_destination(dest)
            }
        if stage is Stage.RESPONSE:
            return lambda: {
                n
                for n, ic in self.registry.inbound.items()
                if ic.spec.type is ConnectorType.LOOPBACK
            }
        return lambda: set(self.registry.inbound)  # INGRESS / ROUTED

    def _make_dispatcher(self, stage: Stage) -> StageDispatcher:
        """Construct one StageDispatcher for ``stage`` (ADR 0066 §5), bound to the matching per-item
        adapter, a live lane provider, and the pooled knobs. INGRESS/ROUTED batch the contiguous due
        head-prefix (``per_lane_limit`` = the ``fifo_claim_batch`` knob clamped 1..64); OUTBOUND/RESPONSE
        are hard-1 (the dispatcher re-clamps). ``claim_lane_chunk`` is clamped to the backend store's own
        chunk (SQLite 200, server 500) so the dispatcher never over-sends lanes the store would drop."""
        adapter = {
            Stage.INGRESS: self._dispatch_ingress,
            Stage.ROUTED: self._dispatch_routed,
            Stage.OUTBOUND: self._dispatch_delivery,
            Stage.RESPONSE: self._dispatch_response,
        }[stage]
        per_lane_limit = min(max(self._fifo_batch, 1), 64) if stage in _PREFIX_STAGES else 1
        backend_chunk = 200 if self.store.backend is StoreBackend.SQLITE else 500
        claim_lane_chunk = min(self._pooled_claim_lane_chunk, backend_chunk)
        # ADR 0071 B5 slot-budget clamp: under fusion the two FUSED stages (INGRESS/ROUTED) run at most
        # ~pooled_fusing_workers concurrent hops (the executor width), so reserving the full 256
        # processing slots for a handful of workers would inflate in_pipeline and widen the crash-replay
        # recovery set. Clamp their effective max_processing_lanes to ~2xW. The non-fused stages
        # (OUTBOUND/RESPONSE) keep the full budget, and OFF/non-SS is byte-identical (never clamped).
        max_processing_lanes = self._pooled_max_processing_lanes
        if self._fusion_active and stage in _PREFIX_STAGES:
            max_processing_lanes = min(max_processing_lanes, 2 * self._fusing_workers)
        return StageDispatcher(
            stage,
            self.store,
            process_item=adapter,
            lane_provider=self._pooled_lane_provider(stage),
            per_lane_limit=per_lane_limit,
            claimers_per_stage=self._pooled_claimers_per_stage,
            sweep_interval=self._pooled_sweep_interval,
            claim_lane_chunk=claim_lane_chunk,
            max_processing_lanes=max_processing_lanes,
            stop_event=self._stop,
            alert_sink=self._alert_sink,
            # Connection controls: only the OUTBOUND dispatcher signals per-lane quiescence back to the
            # runner (the pause primitive is outbound-only) so 'stopped' means zero in-flight.
            on_lane_paused=(self._mark_outbound_quiesced if stage is Stage.OUTBOUND else None),
            empty_counter=self._empty_claims,
            infra_fault_policy=self._infra_fault_policy,
            infra_fault_stop_after=self._infra_fault_stop_after,
            infra_fault_backoff_cap=self._infra_fault_backoff_cap,
        )

    async def _start_pooled_dispatchers(self) -> None:
        """Build + start the pooled StageDispatchers (ADR 0066 §5) — called once from ``start()`` under
        the pooled branch. (1) fail-closed RCSI verify; (2) one dispatcher per stage (RESPONSE only when
        a loopback inbound exists); (3) start each (seed-all-READY + one immediate sweep); (4) note that
        ``per_lane_wake`` is subsumed. A RuntimeError from step 1 propagates — ``start()``'s except tears
        down the partial start — UNLESS ``require_rcsi_for_pooled`` is false, which downgrades it to a
        loud warning + a persistent degraded gauge + an AlertSink event."""
        # (1) RCSI fail-closed gate (SQL Server; a no-op on SQLite / Postgres).
        try:
            await self.store.require_rcsi_for_pooled()
        except RuntimeError as exc:
            if self._require_rcsi_for_pooled:
                raise  # fail closed — start()'s except unwinds the partial start
            log.warning(
                "pooled claim mode starting DEGRADED: %s (require_rcsi_for_pooled=false); the ADR 0066 "
                "§3.2 correctness proofs assume READ_COMMITTED_SNAPSHOT on",
                safe_exc(exc),
            )
            self._rcsi_off_degraded = True
            try:
                self._alert_sink.rcsi_off_degraded("pipeline", detail=safe_exc(exc))
            except Exception:
                log.warning("alert sink raised on rcsi_off_degraded")
        # (1.5) ADR 0071 B5: decide EFFECTIVE thread-hop fusion — BEFORE the _make_dispatcher loop so the
        # slot-budget clamp reaches the fused INGRESS/ROUTED dispatchers. Fail-closed: a pool-open failure
        # leaves it inactive and the engine runs the async path (never a lane outage).
        self._fusion_active = await self._activate_fusion()
        # Construction sentinel (byte-identical default): fusion inactive ⇒ NO fusing executor was built
        # (and no sync handoff pool was left open). Asserted on construction state, not bound-callable
        # identity — the async _process_*_item path is untouched by this PR.
        assert self._fusion_active or (
            self._fuse_route_executor is None and self._fuse_transform_executor is None
        )
        # (2) one dispatcher per stage; RESPONSE only when a loopback inbound exists.
        stages = [Stage.INGRESS, Stage.ROUTED, Stage.OUTBOUND]
        if self._has_loopback_inbound():
            stages.append(Stage.RESPONSE)
        for stage in stages:
            self._dispatchers[stage] = self._make_dispatcher(stage)
        # (2.5) Replay the already-recorded outbound pauses onto the FRESH OUTBOUND dispatcher, BEFORE it
        # starts. _start_outbound ran before this (start() builds the outbounds first), so an
        # auto_start=False lane is already in _outbound_paused with no dispatcher to tell — without this
        # replay the boot gate would be defeated by step (3)'s seed-all-READY. pause_lane on an
        # unregistered key registers it ALREADY-PAUSED, so the seed cannot arm it (#115).
        out = self._dispatchers.get(Stage.OUTBOUND)
        if out is not None:
            for n in self._outbound_paused:
                out.pause_lane(n)
        # (2.6) THE #122 SIBLING OF (2.5), and it fails the same way if it is missing: replay an
        # in-force log-failure halt onto the FRESH INGRESS/ROUTED/RESPONSE dispatchers before step (3)
        # seeds every lane READY. Without it a runner that came up into an unwritable application log
        # starts DRAINING under pooled, because the halt then survives only in the per_lane workers'
        # loop-top gate — which pooled mode does not run. Measured: a committed ingress row reached
        # PROCESSED with both sinks dead.
        for stage in (Stage.INGRESS, Stage.ROUTED, Stage.RESPONSE):
            internal = self._dispatchers.get(stage)
            if internal is None:
                continue
            for n in self._log_halted:
                internal.pause_lane(n)
        # (3) start each (seed-all-READY + immediate sweep). reset_stale_inflight already ran (engine).
        for dispatcher in self._dispatchers.values():
            await dispatcher.start()
        # (4) per_lane_wake is subsumed by pooled precision (logged once).
        if self._per_lane_wake:
            log.info(
                "ADR 0066: per_lane_wake subsumed by pooled claim_mode (per-lane precision is "
                "structural in the dispatcher; the sweep is the bounded backstop)"
            )
        log.info(
            "pooled claim mode started: %d stage dispatcher(s) (%s)",
            len(self._dispatchers),
            ", ".join(s.value for s in self._dispatchers),
        )

    def _activate_statement_batching(self) -> bool:
        """Resolve EFFECTIVE ADR 0075 per-hop statement batching (called once from :meth:`start`). It
        needs the flag AND a SQL Server store that ships the batched handoff forms (exposed via
        ``set_batch_handoff_statements``); every other backend logs "ignored" and keeps the async path
        (fail-closed, byte-identical). Returns the effective decision.

        Unlike fusion this opens no pools/executors — it only flips a store-side dispatch flag — so it
        cannot fail-closed to a lane outage; it either batches or runs the unchanged async handoff."""
        if not self._batch_handoff_statements:
            return False
        setter = getattr(self.store, "set_batch_handoff_statements", None)
        if setter is None:
            log.info(
                "batch_handoff_statements ignored on %s (SQL-Server-only); running the async handoff path",
                self.store.backend.value,
            )
            return False
        active = bool(setter(True))
        log.info(
            "ADR 0075 per-hop statement batching ACTIVE (SQL Server): route/transform handoffs fold "
            "non-result DML into fewer round-trips (same logical sequence, one commit/hop)"
        )
        # Bench confounder note (not a fault): batching only reshapes the ASYNC handoff path. When ADR
        # 0071 fusion is ALSO active, fused hops run the UNBATCHED sync twins, so the two levers are not
        # additive on the fused stages — an A/B that leaves both on cannot attribute a delta cleanly.
        if self._fusion_active:
            log.warning(
                "ADR 0075 batching AND ADR 0071 fusion are both active: fused stages run the UNBATCHED "
                "sync handoff twins (only the async path batches). The levers are NOT additive — do not "
                "run a batching A/B with fusion on."
            )
        return active

    async def _activate_fusion(self) -> bool:
        """Resolve EFFECTIVE ADR 0071 B5 thread-hop fusion (called once from :meth:`_start_pooled_
        dispatchers`). Static capability is decoupled from pool-open success: fusion needs the flag AND a
        SQL Server store that ships the synchronous handoff twins AND ``claim_mode="pooled"``; then it
        tries to open the two dedicated synchronous pyodbc handoff pools (one connection per fusing
        worker) + build the two per-stage fusing executors. Returns True only when ALL of that succeeds.

        **Fail-closed, REACHABLE, never a lane outage:** a non-SS backend logs "ignored" and returns
        False (async path). A pool-open failure — including :class:`SyncHandoffUnavailable` on
        ``[store].command_timeout==0`` (would let the finalize applock wait forever on a worker), a
        session-cap, or a connect fault — logs a LOUD warning, sets the degraded gauge, drops any
        partially-opened pool, and returns False (the engine still starts, on the async path). The pool
        open runs OFF the loop (it opens real connections; must not block the loop at startup)."""
        if not self._fuse_thread_hops:
            return False
        # ADR 0087 isolation is incompatible with ADR 0071 fusion: the fused route/transform twins
        # (_run_fused_route / _run_fused_transform) call route_only/transform_one WITHOUT a `sandbox=`,
        # so the Router, the Handler, AND the `accepts=` predicate (ADR 0084) would all run IN the engine
        # process — silently OUTSIDE the forbidden-import guard and resource caps the operator turned on.
        # Rather than run user config code unsandboxed under a config that asked for a sandbox, fail
        # CLOSED to the async (sandboxed) path. An IPC round-trip inside a fused hop would negate the
        # fusion anyway, so degrading is the right trade — never a silent isolation bypass.
        if self._sandbox_policy is not None and self._sandbox_policy.mode is SandboxMode.SUBPROCESS:
            log.warning(
                "fuse_thread_hops is set but [sandbox].mode=subprocess: fusion runs Router/Handler/"
                "accepts= code in-process (unsandboxed), so it is DISABLED — running the async sandboxed "
                "pipeline path. Turn the sandbox off to use fusion, or leave fusion off to keep isolation."
            )
            return False
        backend = self.store.backend
        if backend is not StoreBackend.SQLSERVER:
            log.info(
                "fuse_thread_hops ignored on %s (SQL-Server-only); running the async pipeline path",
                backend.value,
            )
            return False
        if not getattr(self.store, "supports_fused_sync_handoff", False):
            log.info(
                "fuse_thread_hops ignored: store lacks the synchronous fused-handoff twins; "
                "running the async pipeline path"
            )
            return False
        if self._claim_mode != "pooled":
            # Unreachable today (this method is only called from the pooled branch), but keep the AND
            # condition explicit + self-documenting per ADR 0071 §3.
            log.info(
                "fuse_thread_hops ignored: claim_mode=%r (fusion requires pooled); running async",
                self._claim_mode,
            )
            return False
        store = cast(_FusedHandoffStore, self.store)
        try:
            # One pool per FUSED handoff, keyed by the PRODUCED stage: route_handoff_sync writes routed
            # rows ("routed"); transform_handoff_sync writes outbound rows ("outbound"). Each is sized to
            # its executor's worker count so a fused hop never blocks acquiring a connection. Off-loop.
            await asyncio.to_thread(
                store.open_sync_handoff_pool, Stage.ROUTED.value, self._fusing_workers
            )
            await asyncio.to_thread(
                store.open_sync_handoff_pool, Stage.OUTBOUND.value, self._fusing_workers
            )
        except Exception as exc:  # noqa: BLE001 — fail-closed to the async path, never crash start
            await asyncio.to_thread(store.close_sync_handoff_pool)  # drop any partially-opened pool
            self._fusion_pool_open_failed = True
            log.warning(
                "ADR 0071 fuse_thread_hops is set but the synchronous fused-handoff pool could not be "
                "opened (%s); FALLING BACK to the async pipeline path — fusion INACTIVE, no lane "
                "outage (the engine runs normally on the async handoff)",
                safe_exc(exc),
            )
            return False
        # Pools are open; build the two PER-STAGE executors (distinct thread_name_prefix). Separate from
        # the default to_thread executor (listener strict-validate/decrypt) — a DB-bound fused hop must
        # not starve it — and per-stage so a ~30s bridged-lookup transform hop never blocks a route hop.
        self._fuse_route_executor = ThreadPoolExecutor(
            max_workers=self._fusing_workers, thread_name_prefix="mefor-fuse-route"
        )
        self._fuse_transform_executor = ThreadPoolExecutor(
            max_workers=self._fusing_workers, thread_name_prefix="mefor-fuse-transform"
        )
        self._fusion_pool_open_failed = False
        log.info(
            "ADR 0071 thread-hop fusion ACTIVE (SQL Server, pooled): %d fusing worker(s)/stage + "
            "matched synchronous handoff pools",
            self._fusing_workers,
        )
        return True

    async def _reload_pooled_dispatchers(self, new_registry: Registry) -> None:
        """Re-arm the pooled dispatchers after a reload swapped the graph (ADR 0066 §4, the pooled
        analog of ``_ensure_inbound_workers`` on reload). NEVER tears a dispatcher down mid-run (its
        lane provider reads the live registry, so a removed lane simply stops being claimed); it only
        LAZILY constructs + starts a RESPONSE dispatcher if the new graph introduced a loopback and none
        exists yet, then broadcasts ``notify_work()`` to every dispatcher (new lanes / freshly enqueued
        rows sit at any stage; the sweep is the backstop for a missed nudge)."""
        if Stage.RESPONSE not in self._dispatchers and self._has_loopback_inbound():
            dispatcher = self._make_dispatcher(Stage.RESPONSE)
            self._dispatchers[Stage.RESPONSE] = dispatcher
            await dispatcher.start()
        for dispatcher in self._dispatchers.values():
            dispatcher.notify_work()
        # Connection controls — reload survival (belt-and-suspenders): re-apply every operator pause
        # SYNCHRONOUSLY right after the notify_work broadcast — no await in the gap, still under
        # _reload_lock — so a claimer can't slip a row out of a deliberately-paused lane between the
        # nudge and the re-pause. notify_work already SKIPS PAUSED lanes (the primary reload-survival
        # fix), so this only matters if a lane's PAUSED phase was somehow lost; pause_lane is idempotent
        # on an already-PAUSED lane.
        out = self._dispatchers.get(Stage.OUTBOUND)
        if out is not None:
            for n in self._outbound_paused:
                out.pause_lane(n)
        # …and the #122 halt on the INTERNAL stages, for the same reason and in the same gap. A
        # reload never LIFTS a halt (that rides _resume_inbound_processing, which is gated on the log
        # working again), so re-applying it here can only ever be a no-op or a repair; a lane whose
        # PAUSED phase was lost while the log is still dead would otherwise start draining unlogged.
        for stage in (Stage.INGRESS, Stage.ROUTED, Stage.RESPONSE):
            internal = self._dispatchers.get(stage)
            if internal is None:
                continue
            for n in self._log_halted:
                internal.pause_lane(n)

    async def _pooled_maybe_buildup(self, lane: str, stage: str) -> None:
        """Pooled INGRESS/ROUTED buildup-alert hook (ADR 0066 D1). The per_lane buildup depth check lives
        in the router/transform worker LOOPS (dropped in pooled mode), so the pooled per-stage adapter
        calls this after each processed item — rate-limited per (stage, lane) to ``_BUILDUP_CHECK_INTERVAL``
        so it never runs a COUNT+MIN per claimed item. ``_maybe_alert_buildup`` additionally self-throttles
        the actual alert emit via ``_next_buildup_alert`` (300 s)."""
        key = f"{stage}:{lane}"
        now = time.time()
        if now - self._pooled_buildup_at.get(key, 0.0) < _BUILDUP_CHECK_INTERVAL:
            return
        self._pooled_buildup_at[key] = now
        try:
            await self._maybe_alert_buildup(lane, stage=stage, threshold=self._buildup_default)
        except Exception:
            # A buildup-check store error (e.g. a transient SS/PG COUNT deadlock/timeout under exactly the
            # load this alert targets) is a DIAGNOSTIC — it must NEVER escape the adapter as a T17 body
            # exception, which would park the lane and release_claimed the already-RESOLVED head's siblings.
            # (In per_lane the equivalent check sits inside the worker loop's own except:backoff.)
            log.exception("pooled buildup check failed for stage %s lane %s", stage, lane)

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
        reload/promote can never bring a PT-on-non-SQLite graph live; the reference-set backend
        allow-list (:func:`check_reference_backend_supported`) does the same for an ADR 0006
        ``Reference(...)`` on a backend with no snapshot store (SQL Server)."""
        build_check_registry(
            registry,
            inbound_bind_host=self._inbound_bind_host,
            env_values=self._env_values,
            egress=self._egress,
            reserved_bindings=self._reserved_bindings,
            posture=self._hop_posture,
            trust_anchor_policy=self._trust_anchor_policy,
        )
        # PT-backend allow-list — folded in here (vs only at Engine.start) so EVERY reload + dry-run
        # path that build-checks the new registry also rejects a PT-on-non-SQLite graph before any
        # swap. RegistryRunner carries the resolved store, so the gate sees the backend's capability.
        check_pt_backend_supported(registry, self.store)
        # Reference-set backend allow-list, same rationale (ADR 0006): a reload/promote that ADDS the
        # first Reference(...) onto a backend with no snapshot store must fail 422 here, before the swap.
        check_reference_backend_supported(registry, self.store)

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
            self._send_pace[name] = _resolve_send_pace(
                oc.spec.settings
            )  # BACKLOG #82 (see _start_outbound)
            self._simulate[name] = self._resolve_simulate(name, oc)
            worker = self._workers.get(name)
            failed = name in self._failed  # ADR 0031: live worker, but no connector (start failed)
            # Present but NOT DEPLOYED (#233, ADR 0111) — checked FIRST, so deployed=False WINS over
            # auto_start. Unconditional (NOT keyed on the lane's live state, as the auto_start gate
            # below is): an operator start is a legitimate override of auto_start, but there is no
            # operator override of `deployed` — it is a config fact, so a reload that (re-)declares the
            # connection not-deployed tears any live connector back down. Nothing is dropped: an already-
            # queued row is retained PENDING, and a new one cannot be produced (transform_one declines
            # the Send). No worker is spawned; a worker that predates the flip stays alive but PARKED at
            # its pause gate — never cancel one, a cancelled mid-delivery row strands INFLIGHT forever.
            if not oc.deployed:
                stale = self._destinations.pop(name, None)
                if stale is not None:
                    await stale.aclose()
                self._failed.pop(name, None)
                self._park_outbound_lane(name)
                continue
            # Per-connection auto-start (#115): a reload must not RESURRECT a start-disabled lane. It had
            # no gate at all here, and in the DEFAULT pooled mode `live` below is keyed on the CONNECTOR
            # (which the boot gate popped) — so the not-live branch built one and the lane started
            # delivering, silently undoing auto_start=False on the next reload/GUI edit. The gate is the
            # lane's LIVE state, not the flag alone: an outbound an operator DID start at runtime is live
            # here and reconciles normally (a reload never undoes an operator action), while one that is
            # down (never started, started-then-stopped, or newly ADDED by this reload) stays parked with
            # no connector — its queued rows are retained PENDING, exactly like the DR park below.
            if not oc.auto_start and not self._outbound_lane_live(name):
                stale = self._destinations.pop(name, None)
                if stale is not None:
                    await stale.aclose()
                self._failed.pop(name, None)
                self._park_outbound_lane(name)
                if worker is None or worker.done():
                    self._spawn_worker(name)
                continue
            # Past both gates: the GRAPH now says this lane may deliver. Lift any park the ENGINE put on
            # it (an earlier deployed=False / auto_start=False that this reload just flipped back) —
            # otherwise the branches below would faithfully rebuild its connector and respawn its worker
            # and the lane would sit PAUSED forever, so "flip the flag and reload" (AC-4: with no other
            # change) would silently not deploy it. A no-op for an OPERATOR pause (not in _gate_parked):
            # a reload never undoes an operator action. Placed ABOVE the DR gate so a DR park applies its
            # own semantics (queued rows RETRIED, status:"filtered") to a clean, unpaused lane.
            self._unpark_outbound_lane(name)
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
            # Per_lane has one delivery worker per outbound; pooled has ONE OUTBOUND dispatcher for all,
            # so self._workers is always empty in pooled — judging "live" by worker presence would rebuild
            # every connector on every reload (dropping every warm MLLP socket / DB pool / SMART token).
            # In pooled a connector is live iff it is BUILT; the spec-mismatch elif below still rebuilds a
            # genuinely-changed one. The per_lane branch is the exact negation of the old check (unchanged).
            live = (
                name in self._destinations
                if self._claim_mode == "pooled"
                else (worker is not None and not worker.done())
            )
            if not live:
                # added (or replacing a crashed worker): close any stale connector, build + spawn.
                stale = self._destinations.pop(name, None)
                if stale is not None:
                    await stale.aclose()
                # #200 (ADR 0092): stamp the posture for the reload rebuild too. build_check above vetted
                # the new registry against the real posture, but the HTTP cells fail-closed when unstamped
                # — so an unstamped rebuild here would raise InsecureHopRefused on a legit non-prod cleartext
                # lane AFTER intake is quiesced (the "connector builds here cannot fail" invariant).
                with active_hop_posture(self._hop_posture):
                    self._destinations[name] = build_destination(
                        _dest_config(oc, self._env_values, self._trust_anchor_policy, self._egress)
                    )
                self._failed.pop(name, None)
                self._spawn_worker(name)
            elif failed or old.outbound.get(name) is None or old.outbound[name].spec != oc.spec:
                # live worker but a missing/mismatched connector → (re)build it in place, close any old
                # one. `failed` covers an outbound that failed to build at START (ADR 0031): its worker
                # is alive with no connector, so a reload once the cause is fixed self-heals the lane
                # (build_check above already re-validated the whole new registry, so this build can't
                # fail here — a still-broken connector would have raised before any quiesce).
                old_conn = self._destinations.get(name)
                # #200 (ADR 0092): stamp the posture for the in-place rebuild too (see the branch above).
                with active_hop_posture(self._hop_posture):
                    self._destinations[name] = build_destination(
                        _dest_config(oc, self._env_values, self._trust_anchor_policy, self._egress)
                    )
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
                # ADR 0087 (#197): recycle the per-inbound sandbox worker children so the NEW graph
                # reaches them. Each child holds the registry it load_config'd at spawn, so a stale child
                # would keep routing/transforming/deciding accepts= against the OLD graph — and a reload
                # that RETROFITS an `accepts=` predicate would make the parent dispatch phase='accepts' to
                # a child that has no such predicate, which returns a denial → SandboxError → EVERY message
                # dead-letters until restart. Dropping the sessions here makes the next dispatch respawn a
                # child that re-loads the swapped config (its docstring's "Router/Handler changes take
                # effect immediately" now also holds under mode=subprocess). Off-loop: close() waits on a
                # process. No-op unless mode=subprocess actually spawned any.
                if self._sandbox_sessions:
                    _stale_sessions = list(self._sandbox_sessions.values())
                    self._sandbox_sessions.clear()

                    def _close_stale_sandboxes() -> None:
                        for _s in _stale_sessions:
                            _s.close()

                    await asyncio.to_thread(_close_stale_sandboxes)
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
                    # Present but NOT DEPLOYED (#233, ADR 0111) — checked FIRST, so deployed=False WINS
                    # over auto_start. Unconditional (unlike the auto_start gate below, which honors an
                    # operator start): `deployed` is a config fact, not a runtime one, so a reload that
                    # declares the inbound not-deployed leaves it UNBOUND even if an operator had it
                    # listening a moment ago — step 1 above already quiesced every source. Its router +
                    # transform workers are still re-armed below, so an in-flight backlog drains (AC-3).
                    if not ic.deployed:
                        continue
                    # Per-connection auto-start (#115): a reload must not BIND a start-disabled listener
                    # (it had no gate here at all, so every reload/GUI edit silently undid auto_start=False
                    # and the feed came up). The test is "was it LISTENING before this reload?", not "is it
                    # now?" — step 1 above just unbound every source, so the live state is uniformly False
                    # here; `old_inbound_names` is the snapshot taken before the quiesce. That keeps a
                    # listener an operator started at runtime bound across a reload (a reload never undoes
                    # an operator action) while a never-started one stays down. Its router/transform
                    # workers are still re-armed below, so any backlog drains (the AC-3 rule).
                    if not ic.auto_start and ic.name not in old_inbound_names:
                        continue
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
                # ADR 0066 pooled: no per-lane workers to re-arm (_ensure_inbound_workers is a no-op).
                # Instead lazily add a RESPONSE dispatcher if the new graph introduced a loopback, and
                # nudge every dispatcher; residual/new lanes the nudge misses are covered by the sweep.
                if self._claim_mode == "pooled":
                    await self._reload_pooled_dispatchers(new_registry)
                else:
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
            # ADR 0066 pooled: the dispatchers were already nudged in _reload_pooled_dispatchers above,
            # so skip the tail wake (it would be a redundant notify_work broadcast).
            if self._claim_mode != "pooled":
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
                    raw=_nul_safe_error_raw(raw, ic.content_type.value),
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
                raw=_nul_safe_error_raw(raw, ic.content_type.value),
                status=MessageStatus.ERROR,
                error=f"decode error ({encoding}): {safe_exc(exc)}",
                source_type=src,
                message_type=None if hl7v2 else ic.content_type.value,
            )
            return None

        if "\x00" in text:
            # INGEST-4: the body decoded cleanly but carries a NUL (U+0000) — invalid in every text
            # payload we accept (HL7 v2 field data, JSON, XML 1.0, X12) and store-hostile (Postgres
            # rejects it at bind → dropped connection; SQLite/SQL Server truncate). Dead-letter it here,
            # BEFORE Peek.parse and any store write, so text (and every value derived from it) is
            # NUL-free for the rest of this handler. HTTP owns its own 202/4xx response — no HL7 ACK.
            await self.store.record_received(
                channel_id=ic.name,
                raw=_nul_safe_error_raw(raw, ic.content_type.value, text=text),
                status=MessageStatus.ERROR,
                error="ingress body contains a NUL (U+0000), invalid in a text/HL7 payload",
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
        # #149 (ADR 0105 Phase 1a): mirror the MLLP path — a streaming inbound raises the peek ceiling to
        # its max_message_bytes and downgrades whole-body strict validation to header-only over threshold.
        peek_max_bytes = ic.max_message_bytes or DEFAULT_MAX_MESSAGE_BYTES
        streaming_over = self._streaming_over_threshold(ic, text)
        try:
            peek = Peek.parse(text, max_bytes=peek_max_bytes)
        except HL7PeekError as exc:
            await self.store.record_received(
                channel_id=ic.name,
                raw=text,
                status=MessageStatus.ERROR,
                error=f"parse error: {safe_exc(exc)}",
                source_type=src,
            )
            return None
        if ic.validation.strict and streaming_over:
            # Whole-body strict validation is downgraded to header-only over the streaming threshold (the
            # MSH structure Peek.parse validated) — see _handle_inbound for the rationale.
            log.info(
                "strict validation downgraded to header-only for streaming inbound %r (%d bytes >= "
                "threshold %d)",
                ic.name,
                len(text),
                ic.stream_threshold_bytes,
            )
        elif ic.validation.strict:
            timeout = _strict_validate_timeout(ic)
            try:
                # wait_for frees THIS listener path but cannot kill the to_thread worker (no thread
                # cancellation in CPython) — the orphaned hl7apy validate leaks its thread until it
                # returns, accepted-by-design (mirrors _run_lookup), bounded by enforce_size_limits'
                # 16 MiB / segment caps that fire before the slow parse (#89).
                result = await asyncio.wait_for(
                    asyncio.to_thread(validate, text, expected_version=ic.validation.hl7_version),
                    timeout,
                )
            except TimeoutError:
                # DoS backstop (#89): a pathological body made hl7apy spin past the budget. Dead-letter
                # it instead of pinning intake. The message string is PHI-safe/value-free (only the
                # numeric timeout). HTTP owns its own 202/4xx response — no HL7 ACK here.
                timed_out = f"strict-validation timed out after {timeout}s"
                await self._record(ic, peek, text, MessageStatus.ERROR, error=timed_out)
                return None
            if not result.ok:
                persisted = f"strict-validation failed: {safe_text('; '.join(result.errors))}"
                await self._record(ic, peek, text, MessageStatus.ERROR, error=persisted)
                return None
        # #149 (ADR 0105 Phase 1a): detach over-threshold documents before the ingress commit. A detach
        # failure records ERROR + returns None (HTTP maps None to a 202-without-id; the disposition is
        # recorded) — never accepted-and-dropped.
        skeleton = text
        attachment_refs: list[str] = []
        if streaming_over:
            try:
                skeleton, attachment_refs = await self._detach_documents(ic, text)
            except (_StreamBudgetExceeded, StreamingAttachmentsUnsupported, DocRefError) as exc:
                await self._record(
                    ic,
                    peek,
                    text,
                    MessageStatus.ERROR,
                    error=f"streaming detach failed: {safe_exc(exc)}",
                )
                return None
        mid = await self.store.enqueue_ingress(
            channel_id=ic.name,
            raw=skeleton,
            control_id=peek.control_id,
            message_type=peek.message_type,
            source_type=src,
            summary=summarize(peek) or None,
            attachment_refs=attachment_refs or None,
        )
        self._wake_lane(Stage.INGRESS, ic.name)  # B12: wake only this inbound's router lane
        return mid

    def _streaming_over_threshold(self, ic: InboundConnection, text: str) -> bool:
        """Whether ``ic`` is a streaming inbound (``stream_threshold_bytes`` set) and ``text`` is at/above
        that threshold — the gate for the over-threshold detach path (#149, ADR 0105 Phase 1a). Below
        threshold or unset ⇒ False ⇒ the byte-identical no-detach fast path (and no strict downgrade)."""
        threshold = ic.stream_threshold_bytes
        return threshold is not None and len(text) >= threshold

    async def _detach_documents(self, ic: InboundConnection, text: str) -> tuple[str, list[str]]:
        """Detach every oversized OBX-5 ED base64 document from an over-threshold HL7 body into the
        store's content-addressed attachment substrate and return ``(skeleton_text, attachment_refs)``
        (#149, ADR 0105 Phase 1a, Approach B — VERBATIM).

        Reuses the strip-in-OBX mechanism through the parsed :class:`Message` model, but the value lifted
        out is stored **byte-for-byte** (no decode/encode): ``put_attachment`` seals the exact base64
        slices and content-addresses them, and the OBX-5.5 value is replaced by the small
        ``mfdoc:v1:ref:<sha256>:<content_type>`` handle so the pipeline carries only the small skeleton.
        The attachment chunks commit here (at refcount 0); the caller then commits the referencing
        skeleton row and increfs each ref in the SAME transaction (``enqueue_ingress(attachment_refs=…)``)
        — the two-object commit. A crash between the two leaves the attachment orphaned at refcount 0 for
        the startup sweep to reclaim (no ACK was sent, so the sender resends and content-addressing dedups
        the resend). If the message carries no qualifying document the original ``text`` is returned
        unchanged with no refs (byte-identical, no attachment row).

        Raises :class:`_StreamBudgetExceeded` when the aggregate in-flight budget would be exceeded, and
        :class:`~messagefoundry.store.StreamingAttachmentsUnsupported` on a backend without streaming
        support (SQL Server / Postgres in Phase 1a) — both are turned into an ``ERROR``/NAK by the
        caller. The whole body is buffered once (accepted-by-design until the streaming decoder, ADR 0105
        Phase-C); the budget bounds how many such buffers can be concurrent."""
        size = len(text)
        budget = self._stream_inflight_budget
        if budget and self._stream_inflight_bytes + size > budget:
            raise _StreamBudgetExceeded(
                f"streaming in-flight budget exceeded ({self._stream_inflight_bytes} + {size} > "
                f"{budget} bytes); refusing the detach (backpressure)"
            )
        # Reserve the budget for the whole detach window (buffer + per-chunk seal); release in finally the
        # instant the attachment(s) are durable and the skeleton is small — the peak this bounds is passed.
        self._stream_inflight_bytes += size
        try:
            message = Message.parse(text)
            refs: list[str] = []
            detached = 0
            for occ, verbatim_b64, content_type in iter_obx_documents(message):
                # ASVS 1.3.4/5.2.2: OBX-5.2 is a sender-controlled MIME label. If it names a sniffable
                # family (image/pdf/zip/xml/json) whose magic bytes the document contradicts, store the
                # generic octet-stream so the download route can never serve a mislabelled active-content
                # payload as its claimed inert type. Non-sniffable labels are kept as declared.
                safe_ct = content_type
                if not attachment_mime_agrees(content_type, b64_head(verbatim_b64)):
                    safe_ct = _DEFAULT_ATTACHMENT_MIME
                ref = await self.store.put_attachment(chunk_b64(verbatim_b64), safe_ct)
                message.set("OBX-5.5", make_doc_ref(ref, safe_ct), occurrence=occ)
                if ref not in refs:
                    refs.append(ref)
                detached += 1
            if detached == 0:
                # An over-threshold body with no detachable document (e.g. a large non-ED message): keep
                # it byte-identical — no attachment, no skeleton re-encode divergence, no ref to incref.
                return text, []
            return message.encode(), refs
        finally:
            self._stream_inflight_bytes -= size

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
                    raw=_nul_safe_error_raw(raw, ic.content_type.value),
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
                raw=_nul_safe_error_raw(raw, ic.content_type.value),
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

        if "\x00" in text:
            # INGEST-4: the body decoded cleanly but carries a NUL (U+0000) — invalid in every text
            # payload we accept (HL7 v2 field data, JSON, XML 1.0, X12) and store-hostile (Postgres
            # rejects it at bind, which would unwind out of this handler into the transport and drop the
            # whole connection with no ERROR row — a count-and-log violation; SQLite/SQL Server truncate
            # at the first NUL). Dead-letter it here, BEFORE Peek.parse and any store write, so text (and
            # control_id/summary/strict-fail errors derived from it) is NUL-free for the rest of this
            # handler. NAK AR mirrors the decode/parse-error precedent for a malformed body.
            nul_err = "ingress body contains a NUL (U+0000), invalid in a text/HL7 payload"
            mid = await self.store.record_received(
                channel_id=ic.name,
                raw=_nul_safe_error_raw(raw, ic.content_type.value, text=text),
                status=MessageStatus.ERROR,
                error=nul_err,
                source_type=src,
                message_type=None if hl7v2 else ic.content_type.value,
            )
            ack = (
                build_ack(raw, code="AR", text="invalid NUL in body", ack_mode=ack_mode)
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
                    detail=nul_err,
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

        # #149 (ADR 0105 Phase 1a): a streaming inbound raises the peek/total-body ceiling to its
        # per-connection max_message_bytes so a large document is admitted (then detached under the cap);
        # a non-streaming inbound keeps the engine 16 MiB default. A body over the resolved cap raises
        # HL7PeekError here → recorded ERROR + NAK AR (the max_message_bytes rejection).
        peek_max_bytes = ic.max_message_bytes or DEFAULT_MAX_MESSAGE_BYTES
        streaming_over = self._streaming_over_threshold(ic, text)
        try:
            peek = Peek.parse(text, max_bytes=peek_max_bytes)
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

        if ic.validation.strict and streaming_over:
            # #149 (ADR 0105 Phase 1a): whole-body hl7apy strict validation cannot complete over the
            # streaming threshold (the detached document is opaque and the full parse would materialize
            # it), so it is DOWNGRADED to header-only — the MSH structure Peek.parse already validated
            # above. Not a regression: ED-document feeds aren't whole-body strict-validated today. Below
            # threshold, full strict validation still runs (byte-identical) via the branch below.
            log.info(
                "strict validation downgraded to header-only for streaming inbound %r (%d bytes >= "
                "threshold %d)",
                ic.name,
                len(text),
                ic.stream_threshold_bytes,
            )
        elif ic.validation.strict:
            # hl7apy validation is CPU-bound (full structure/cardinality parse) — run it off the event
            # loop so a strict feed can't stall every other listener, worker, and API call (review M-11).
            timeout = _strict_validate_timeout(ic)
            try:
                # wait_for frees THIS listener but cannot kill the to_thread worker (no thread
                # cancellation in CPython) — the orphaned hl7apy validate leaks its thread until it
                # returns, accepted-by-design (mirrors _run_lookup), bounded by enforce_size_limits'
                # 16 MiB / segment caps that fire before the slow parse (#89).
                result = await asyncio.wait_for(
                    asyncio.to_thread(validate, text, expected_version=ic.validation.hl7_version),
                    timeout,
                )
            except TimeoutError:
                # DoS backstop (#89): a pathological body made hl7apy spin past the budget. Dead-letter
                # + NAK AE instead of pinning the listener. The stored/ACK string is PHI-safe/value-free
                # (only the numeric timeout) — unlike the validation-error path below it quotes no field.
                timed_out = f"strict-validation timed out after {timeout}s"
                mid = await self._record(ic, peek, text, MessageStatus.ERROR, error=timed_out)
                ack = (
                    build_ack(peek, code="AE", text=timed_out, ack_mode=ack_mode) if reply else None
                )
                if ack is not None and self._capture_ack_enabled(ic):
                    await self._capture_ack(
                        mid,
                        ic.name,
                        ack_code="AE",
                        ack_phase="strict",
                        ack_body=None,
                        detail=timed_out,
                    )
                return ack
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

        # #149 (ADR 0105 Phase 1a): an over-threshold streaming inbound detaches its oversized OBX-5 ED
        # documents VERBATIM into the attachment substrate BEFORE the ingress commit, so the pipeline
        # carries only the small skeleton + a `mfdoc:v1:ref:` handle. This runs AFTER the synchronous
        # header parse/validate (a malformed header already NAK'd above) and BEFORE the commit/ACK, so a
        # detach failure (budget/backpressure or an unsupported backend) is a synchronous ERROR + NAK AE
        # — the message is NEVER accepted-and-dropped, and no ACK is sent for a body we couldn't store.
        skeleton = text
        attachment_refs: list[str] = []
        if streaming_over:
            try:
                skeleton, attachment_refs = await self._detach_documents(ic, text)
            except (
                _StreamBudgetExceeded,
                StreamingAttachmentsUnsupported,
                DocRefError,
            ) as exc:
                detach_err = f"streaming detach failed: {safe_exc(exc)}"
                mid = await self._record(ic, peek, text, MessageStatus.ERROR, error=detach_err)
                ack = (
                    build_ack(peek, code="AE", text="streaming detach failed", ack_mode=ack_mode)
                    if reply
                    else None
                )
                if ack is not None and self._capture_ack_enabled(ic):
                    await self._capture_ack(
                        mid,
                        ic.name,
                        ack_code="AE",
                        ack_phase="ingest",
                        ack_body=None,
                        detail=detach_err,
                    )
                return ack

        # ACK-on-receipt (staged pipeline, ADR 0001 Step A): persist the raw message durably to the
        # ingress stage, then ACK. Routing/transform/delivery run AFTER the ACK in the ingress worker,
        # so a slow/hung router or outbound never stalls intake — and a router/handler failure no
        # longer NAKs the sender (it becomes a logged ERROR/dead-letter at the ingress stage). Decode,
        # parse, and strict validation above stay synchronous and still NAK, preserving the partner
        # contract for a malformed message. ack_after='delivered' (defer the ACK) is rejected at
        # wiring in Step A, so this is always ACK-on-ingest. Under #149 the persisted body is the
        # SKELETON and the attachment increfs commit in the SAME transaction (the two-object commit), so
        # the AA ACK below still fires only after the whole document is durable.
        mid = await self.store.enqueue_ingress(
            channel_id=ic.name,
            raw=skeleton,
            control_id=peek.control_id,
            message_type=peek.message_type,
            source_type=src,
            summary=summarize(peek) or None,
            attachment_refs=attachment_refs or None,
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
                # Connection controls: loop-top operator-PAUSE gate, BEFORE the claim. When paused, signal
                # quiescence (the <=1 in-flight _process_delivery_item below already finished on the prior
                # iteration — a FIFO RETRY re-pends its head PENDING — so zero rows are INFLIGHT here) and
                # block on the per-lane resume Event. COOPERATIVE — never a task.cancel; mirrors the
                # _stop.is_set() loop guard. The in-flight item ALWAYS finishes before the loop re-checks.
                if name in self._outbound_paused:
                    self._outbound_quiesced.setdefault(name, asyncio.Event()).set()
                    woken = await self._wait_for_resume(name)
                    continue
                # FIFO (default): claim only the due head — a backing-off head blocks the lane
                # (head-of-line), so order is preserved. UNORDERED: claim a batch and rotate past a
                # backing-off row to drain others. Resolved live so a reload can retune it.
                # perf_counter_ns ONLY when the bench lever is on — otherwise a single bool check. A
                # claim that RAISES is not timed (the worker's outer except logs it and backs off); a
                # timeout-capped duration would distort the claim-latency figure this measures.
                _claim_t0 = time.perf_counter_ns() if self._delivery_phase_timing else 0
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
                    # nodes is fine for ORDERING. That is a statement about lane ownership, not about
                    # who may claim at all: claim_ready is leader-epoch fenced like every other claim
                    # path (ADR 0157 C5), so a superseded ex-leader draining an unordered lane claims
                    # nothing.
                    items = await self.store.claim_ready(
                        limit=self.claim_limit, destination_name=name
                    )
                if self._delivery_phase_timing:
                    # One lane per claim in per_lane mode (this worker owns exactly `name`). Recorded
                    # synchronously; counts only, never the lane name (destination_name = PHI-adjacent).
                    # NOTE: claim_next_fifo returns None both for "nothing pending" and for an H2
                    # in-place completion / poison dead-letter (which DID write), and per_lane cannot
                    # tell them apart — so `empty` is an UPPER BOUND here. Pooled gets `rearm` back and
                    # books it as work. Compare the two modes' `empty` with that asymmetry in mind.
                    self._claim_phase_stats.record_claim(
                        time.perf_counter_ns() - _claim_t0, lanes=1, rows=len(items)
                    )
                    self._claim_phase_stats.maybe_emit(stage="outbound", claimers=1)
                if not items:
                    self._empty_claims.record_empty(woken=woken)  # B11 wall #3
                    woken = await self._wait_for_work(wait_ev)
                    continue
                for item in items:
                    # BACKLOG #82: pace this lane's egress BEFORE the send seam so ONE hook covers both
                    # the single-message and the batch body (below) — a paced batch counts as one
                    # interval. Sits between claim and send (outside the produce→complete transaction),
                    # so it delays without reordering; cancellable via the loop's CancelledError.
                    await self._pace_outbound(name)
                    # #134 (ADR 0082): a batching outbound coalesces this claimed head + the lane's next
                    # due rows into ONE BHS…BTS envelope; the plain path delivers one message per send.
                    batch_cfg = self._batch.get(name)
                    if batch_cfg is not None:
                        outcome = await self._process_delivery_batch(name, item, batch_cfg)
                    else:
                        outcome = await self._process_delivery_item(name, item)
                    if outcome[0] is _ItemOutcome.STOPPED:
                        return
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

    async def _user_metadata_for(self, message_id: str) -> dict[str, str] | None:
        """The message's user-metadata bag as a flat ``{key: value}`` map for a ``dynamic_headers``
        outbound (#68), or ``None`` when it has none. Reads the decrypted metadata column ONLY (never the
        raw PHI body), strips the engine-internal correlation-lineage keys via
        :func:`~messagefoundry.store.metadata.user_metadata`, and keeps only ``str`` values (the shape
        :class:`~messagefoundry.config.wiring.SetMeta` writes). Pure w.r.t. the committed message row, so
        an at-least-once re-run reads the same bag and re-derives identical headers — **until retention
        nulls the column**. Past the body window ``messages.metadata`` is blanked (ASVS 14.2.7), so a
        DEAD row replayed after its message was purged reads ``None`` here and is delivered with no
        ``dynamic_headers`` rather than the headers of its first attempt. Accepted: retaining PHI past
        its window purely to serve a degraded replay is the defect 14.2.7 exists to close. Pinned by
        test — see PHI.md §8."""
        raw_meta = await self.store.message_metadata_json(message_id)
        user_json = user_metadata(raw_meta)
        if not user_json:
            return None
        try:
            loaded = json.loads(user_json)
        except ValueError:
            return None
        if not isinstance(loaded, dict):
            return None
        return {str(k): v for k, v in loaded.items() if isinstance(v, str)}

    async def _hydrate_payload(self, payload: str) -> str:
        """Re-attach any detached very-large document into ``payload`` at the terminal egress, just
        before it hits the wire (#149, ADR 0105 Phase 1b). A delivery/skeleton row carries a small
        ``mfdoc:v1:ref:`` handle in ``OBX-5.5``; splice the stored VERBATIM base64 back in (Approach B —
        no decode/encode) so the partner receives the full inline document (Epic's MLLP MDM receiver does
        not cap the frame). A payload with **no** handle is returned byte-identical after a single
        substring check — the below-threshold / no-detach / Handler-built (never-detached) delivery path
        is untouched, and no store read happens.

        Hydration is a **pure READ** off the immutable, content-addressed attachment; it does **not**
        decref (the message may fan out to several outbounds and is replayable — the refcount is released
        only on retention/purge, never on delivery), so every send and every retry re-derives the
        IDENTICAL frame. **Fail-loud:** a missing / GC'd attachment (or a backend without streaming
        support) is turned into a :class:`DeliveryError` so the row takes the normal ERROR/retry path and
        the connector **never** receives an un-hydrated handle (which would deliver ``mfdoc:v1:ref:…``
        into the partner's ``OBX-5.5`` = silent corruption)."""
        if DOC_REF_MARKER not in payload:
            return payload  # no detached document → byte-identical, no store read (the common path)

        async def _reader(sha256: str) -> str:
            # The store read runs off the event loop (aiosqlite), chunk-by-chunk, and the pieces
            # concatenate to the exact verbatim OBX-5.5 base64 the sender sent (Approach B).
            return "".join([chunk async for chunk in self.store.read_attachment(sha256)])

        try:
            return await reattach_documents_in_hl7(payload, _reader)
        except (DocRefError, KeyError, StreamingAttachmentsUnsupported) as exc:
            # A missing/GC'd attachment (KeyError), a malformed handle (DocRefError), or an unsupported
            # backend — surface as a retryable DeliveryError (the message reached NEITHER wire nor peer),
            # exactly like the encoding-override / raw-separators pre-send failures. The row re-pends with
            # backoff (or dead-letters per policy); the buildup/stall alerts make a stuck lane loud.
            raise DeliveryError(f"document re-attach failed: {safe_exc(exc)}") from exc

    async def _pace_outbound(self, name: str) -> None:
        """Apply this outbound lane's egress send pacing (BACKLOG #82): wait until at least
        ``send_min_interval_seconds`` has elapsed since this lane's previous send began, then stamp the
        lane's send clock. Called once per ``send()`` — immediately before the item/batch delivery seam in
        BOTH the per_lane :meth:`_delivery_worker` and the pooled :meth:`_dispatch_delivery`, so it covers
        the single-message AND batch bodies in BOTH claim modes with one hook (**per-envelope** pacing: a
        batch counts as one interval).

        No pacing configured (``0.0`` — the default) is a single dict read and an immediate return, so the
        delivery path stays byte-identical; the pacing clock is only touched once a lane actually paces.
        The clock is per-lane (keyed on ``name``), so independent outbounds never delay one another. The
        delivery worker is the lane's single serial sender (per-lane FIFO invariant, ADR 0067 — asserted
        in ``MLLPDestination.send``), so there is no intra-lane race on the clock; this is a pure **wait**
        that reorders nothing (the row is already claimed) and its ``asyncio.sleep`` is cancellable by the
        connection's stop signal (CancelledError propagates out of the delivery loop, never swallowed)."""
        interval = self._send_pace.get(name, 0.0)
        if interval <= 0.0:
            return  # no pacing on this lane → byte-identical, clock untouched
        last = self._send_pace_at.get(name)
        if last is not None:
            elapsed = time.monotonic() - last
            if elapsed < interval:
                await asyncio.sleep(interval - elapsed)
        # Stamp AFTER any wait so the next interval is measured from THIS send's start (send-to-send
        # rate), matching the documented per-envelope semantics.
        self._send_pace_at[name] = time.monotonic()

    async def _process_delivery_item(
        self, name: str, item: OutboxItem
    ) -> tuple[_ItemOutcome, float | None]:
        """Deliver one claimed outbound row — the per-item body of :meth:`_delivery_worker`,
        extracted verbatim (ADR 0066, pure code motion) so the loop and the pooled dispatcher share
        it. Returns ``(outcome, retry_until)``: ``(PROCESSED, None)`` where the loop advanced with the
        row resolved (delivered / dead-lettered), ``(PROCESSED, next_attempt_at)`` where it re-pended
        with backoff (``mark_failed``, so the pooled dispatcher PARKs the lane until that time —
        surfaced from ``_mark_failed_and_arm``'s additive return, no store re-read), and
        ``(STOPPED, None)`` where the STOP internal-error policy halted the lane. The per_lane loop
        reads only ``outcome[0]``; ``retry_until`` is the pooled-dispatcher park signal (ADR 0066
        §4.5). Store errors propagate to the caller's backoff."""
        # Connector + retry re-resolved per item so a reload can swap an outbound's
        # settings under us with at most one racing send (which fails + retries —
        # outbounds are idempotent). retry_until is the row's re-pend deadline when a send failure
        # re-pends it (mark_failed); None for a delivered / dead-lettered / stopped row. The pooled
        # dispatcher parks the lane on a non-None value; the per_lane loop ignores it.
        retry_until: float | None = None
        retry = self._retry.get(name) or RetryPolicy()
        connector = self._destinations.get(name)
        if connector is None:
            # No connector for a claimed row: either a brief mid-reconcile window, or this
            # outbound failed to build at start (ADR 0031) and its lane is degraded. Either
            # way RETRY the row (never strand/drop it) — it self-heals when a reload/restart
            # builds the connector — and alert on the growing backlog of a failed lane.
            failure = self._failed.get(name)
            detail = f"outbound failed to start: {failure}" if failure else "outbound reloading"
            retry_until = await self._mark_failed_and_arm(name, item.id, detail, retry)
            await self._maybe_alert_buildup(name)
            await self._maybe_alert_stall(name)
            return _ItemOutcome.PROCESSED, retry_until
        # L1 pre-send leadership re-check (active-passive HA). The graph runs on the leader
        # ONLY, but leadership can be lost (a self-fence) BETWEEN claiming this row and the
        # send below. A cheap, SYNCHRONOUS is_leader() read (cached state — no DB round-trip)
        # closes that narrow window: a node that has stopped being leader must not emit egress
        # as a stale ex-leader.
        #
        # RELEASE the claim (attempts--, next_attempt_at UNCHANGED, no last_error) rather than
        # mark_failed: losing leadership is NOT a delivery failure and must not spend a retry.
        # Under a finite RetryPolicy.max_attempts, mark_failed here re-reads the claim's own
        # attempts++ and dead-letters on `attempts >= max_attempts` — writing terminal DEAD on a
        # row that was NEVER SENT. The new leader never sees a DEAD row, so that is a STRAND,
        # which the count-and-log invariant forbids (duplication is permitted; loss is not).
        # release_claimed is guarded `status='inflight'`, so it is idempotent if the row already
        # resolved.
        #
        # Then STOP the lane rather than resolving it: a demoted node must stop claiming, and a
        # release without a stop would hot-spin — release applies no backoff, so the row is
        # immediately due again — for however long teardown takes, which is not bounded against
        # the fence-to-expiry margin (ADR 0157 F2). _teardown_unsafe clears the dispatchers and
        # workers and start() rebuilds them, so promotion re-arms the lane; a STOPPED lane never
        # outlives the term that stopped it.
        #
        # This is a cheap fast-path guard, NOT the authority: the durable backstop is
        # H1's store-checked leader_epoch fence, which rejects a superseded ex-leader's claim
        # at the DB inside the claim transaction even if this in-memory check raced. On the
        # single-node NullCoordinator is_leader() is always True, so this never fires and the
        # delivery path is byte-identical.
        if not self._coordinator.is_leader():
            await self.store.release_claimed([item.id])
            log.warning(
                "delivery worker %r: leadership lost before send; released %d claimed row(s) "
                "un-errored (no attempt spent) and stopped the lane for the new leader",
                name,
                1,
            )
            return _ItemOutcome.STOPPED, None
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
                # PHASE (a): the connector send->ACK round-trip. On a real cross-box outbound this is
                # the partner dial + write + wait-for-ACK — a prime suspect for the ~83 ms ceiling that
                # loopback can't reproduce. Timed only when the bench lever is on (else `_send_t0 = 0`,
                # no perf_counter). See the DeliveryPhaseTiming note.
                # #149 (ADR 0105 Phase 1b): re-attach any detached very-large document VERBATIM just
                # before the send (BEFORE the send timer — a store read, not the partner round-trip). A
                # payload with no handle is returned byte-identical; a missing attachment raises a
                # DeliveryError (caught below → retry), so a handle NEVER reaches the connector.
                payload = await self._hydrate_payload(item.payload)
                _send_t0 = time.perf_counter_ns() if self._delivery_phase_timing else 0
                if getattr(connector, "consumes_metadata", False):
                    # #68: an opted-in outbound (REST/FHIR with dynamic_headers) gets this message's
                    # user-metadata bag so it can project http.header.* entries onto the request. The
                    # read touches only the small metadata column (never the raw body).
                    metadata = await self._user_metadata_for(item.message_id)
                    response = await connector.send(payload, metadata=metadata)
                else:
                    # Default: NO metadata read and the historical send(payload) call shape —
                    # byte-identical for every non-consuming connector.
                    response = await connector.send(payload)
                if self._delivery_phase_timing:
                    self._delivery_phase_stats.record_send_ack(time.perf_counter_ns() - _send_t0)
        except NegativeAckError as exc:
            # Partner rejection. AR/CR (permanent) → fail-fast: the partner will never
            # accept this message, so dead-letter it now rather than block the FIFO lane
            # forever (still replayable from the DLQ). AE/CE (transient) → retry per
            # policy, like a transport failure.
            if exc.permanent and getattr(exc, "credential_fault", False):
                # #109 (ADR 0095): a PERMANENT CREDENTIAL/AUTH fault (bad password / would lock out the
                # partner account) — NOT a bad message. Under the "stop" policy (default) STOP the lane
                # IMMEDIATELY (no dead-lettering the backlog, no re-auth storm that could trip the
                # partner's account lockout) and RETAIN this claimed row UN-ERRORED (release it back to
                # PENDING, undoing only the claim's attempts++ — no backoff, no last_error), so the
                # queue is intact for an operator to resume after fixing the credential (reload/restart
                # re-arms the STOPPED lane). The "dead_letter" policy opts back into the historical
                # fail-fast dead-letter of just this row.
                if self._credential_fault_policy == "stop":
                    await self.store.release_claimed([item.id])
                    log.error(
                        "delivery worker %r: PERMANENT credential/auth fault (%s); STOPPING the lane "
                        "and retaining %d queued row(s) un-errored to protect the partner account "
                        "(operator must fix the credential + reload/restart to resume)",
                        name,
                        exc.code,
                        1,
                    )
                    self._alert_sink.connection_stopped(
                        name,
                        detail=f"credential fault ({exc.code}); lane stopped, queue retained (#109)",
                    )
                    return _ItemOutcome.STOPPED, None
                await self.store.dead_letter_now(item.id, safe_exc(exc))
            elif exc.permanent:
                await self.store.dead_letter_now(item.id, safe_exc(exc))
            else:
                retry_until = await self._mark_failed_and_arm(name, item.id, safe_exc(exc), retry)
                await self._maybe_alert_buildup(name)
                await self._maybe_alert_stall(name)
        except DeliveryError as exc:
            # Transport failure (connect/IO/timeout/unparseable ACK) — transient; retry
            # per policy (the shipped cap is 100 attempts, then the row dead-letters into the
            # replayable DLQ — bounded, not discarded).
            retry_until = await self._mark_failed_and_arm(name, item.id, safe_exc(exc), retry)
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
                return _ItemOutcome.STOPPED, None
            log.warning(
                "delivery worker %r: internal error delivering %s (%s); dead-lettering",
                name,
                item.id,
                type(exc).__name__,
            )
            await self.store.dead_letter_now(item.id, f"internal error: {safe_exc(exc)}")
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
                reingress_to = oc.spec.settings.get("reingress_to") if oc is not None else None
                # PHASE (b): the store completion round-trip (the other ~83 ms suspect). Timed around
                # the store call ONLY (not the registry read / wake). See DeliveryPhaseTiming.
                _done_t0 = time.perf_counter_ns() if self._delivery_phase_timing else 0
                await self.store.complete_with_response(
                    item.id,
                    body=response.body,
                    outcome=response.outcome,
                    detail=response.detail,
                    # #154: the captured allow-listed HTTP response headers ({} → NULL, byte-identical).
                    response_headers=response.headers,
                    reingress_to=reingress_to,
                )
                if self._delivery_phase_timing:
                    self._delivery_phase_stats.record_mark_done(time.perf_counter_ns() - _done_t0)
                # ADR 0154 D3 — the latency hint, and its POSITION is the correctness argument.
                #
                # Strictly after the await returned NORMALLY. Under SQLite group commit
                # complete_with_response enrols in a shared batch whose future resolves post-commit,
                # so a signal here is committed-authoritative; in a `finally`, or before the await,
                # it would fire on a transaction that may have rolled back.
                #
                # It is only ever a hint — the woken turn re-reads the store — so both ways it can be
                # "wrong" are harmless: it can fire for a vanished row that wrote nothing
                # (complete_with_response returns normally in that case), and it can fail to fire at
                # all when an engine shard other than the listener's owns this lane. The first costs
                # one extra read; the second costs latency, never correctness.
                #
                # NOT placed beside the _wake_lane below, which is where the ADR says to put it: that
                # call is nested under `if reingress_to is not None`, and a reply_from outbound never
                # re-ingresses, so a hint there would be unreachable dead code.
                # destination_name is NULL on ingress/routed rows and set on outbound ones, so it is
                # non-None everywhere this path runs — but the type says otherwise, and a hint keyed
                # on None would silently match nothing rather than fail, so the guard is explicit.
                if item.destination_name is not None:
                    self._reply_rendezvous.signal(item.message_id, item.destination_name)
                if reingress_to is not None:
                    # B12 (ADR 0061): CROSS-LANE — wake the loopback's RESPONSE lane
                    # (reingress_to), NOT this delivery worker's own OUTBOUND lane.
                    self._wake_lane(Stage.RESPONSE, reingress_to)
            else:
                # PHASE (b): the store completion round-trip (plain mark_done — the non-capturing path).
                _done_t0 = time.perf_counter_ns() if self._delivery_phase_timing else 0
                await self.store.mark_done(item.id)
                if self._delivery_phase_timing:
                    self._delivery_phase_stats.record_mark_done(time.perf_counter_ns() - _done_t0)
            # Emit the throttled per-process summary (send_ack vs mark_done) after a delivered row —
            # a no-op between windows. Only on the delivered path (a retried/dead-lettered row records
            # neither phase, so there is nothing new to summarize).
            if self._delivery_phase_timing:
                self._delivery_phase_stats.maybe_emit(stage="outbound")
        return _ItemOutcome.PROCESSED, retry_until

    async def _process_delivery_batch(
        self, name: str, head: OutboxItem, cfg: BatchConfig
    ) -> tuple[_ItemOutcome, float | None]:
        """Deliver a contiguous FIFO head-prefix as ONE ``BHS``…``BTS`` envelope (#134 / ADR 0082) —
        the batch counterpart of :meth:`_process_delivery_item`, shared by the per_lane worker and the
        pooled dispatcher (via :meth:`_dispatch_delivery`).

        Starting from the already-claimed ``head``, coalesce the lane's next due rows (each via
        ``claim_next_fifo`` — the same H2 skip-and-complete single claim) until **either** ``cfg.max_count``
        rows are held **or** ``cfg.max_wait_ms`` has elapsed since the head's ingest time **or** a graceful
        stop signals a flush (ADR 0082 decision #4) — whichever comes first — then frame + ``send`` **once**
        + complete all N in one store transaction. Mirrors the single-row disposition ladder over the whole
        batch: on success ``mark_batch_done`` all N; a transient/transport failure ``mark_batch_failed`` all
        N (re-claimed as the identical prefix); a permanent reject ``dead_letter_batch`` all N (decision #1).

        **Invariants.** Every member is INFLIGHT throughout the window, so a crash recovers the whole set in
        ``seq`` order (``reset_stale_inflight``). The members are the lane's oldest contiguous rows in
        ``seq`` order, so strict per-lane FIFO holds within and across batches. Framing is **deterministic
        given a member set** — ``encode_batch`` derives nothing from a clock (BHS-7 from the head's re-run-
        stable ``created_at``, BHS-11 from the head member's control id, members verbatim). A crash *before*
        ``send`` re-runs cleanly (the first send is the re-run's). A crash *after* ``send`` but before
        completion re-sends the batch, which may now coalesce newly-arrived contiguous rows into a **larger**
        envelope — the ADR 0082 "whole batch re-sent on crash-after-send, partner idempotent" consequence:
        at-least-once holds under **per-message** idempotency (the standard HL7-batch partner; dedup by
        MSH-10, not BHS-11). Batching is MLLP-only and rejected on a capturing outbound at wiring (one batch
        ACK), so the response is always one-way here.

        The lane's processing slot is held for the coalescing window (bounded by ``max_wait_ms`` and by
        ``max_count`` sequential claims) — a deliberate, opt-in trade of a held slot for envelope size."""
        retry = self._retry.get(name) or RetryPolicy()
        items: list[OutboxItem] = [head]
        # Deadline measured from the head's ingest time (ADR 0009, re-run-stable). created_at is now
        # projected by every outbound claim; fall back to now defensively (a slightly later window start).
        base = head.created_at if head.created_at is not None else time.time()
        deadline = base + cfg.max_wait_ms / 1000.0
        while len(items) < cfg.max_count:
            more = await self.store.claim_next_fifo(name)
            if more is not None:
                items.append(more)
                continue  # drain everything instantly due first, regardless of stop (never a WAIT)
            # Nothing more immediately due. A graceful stop flushes what's drained NOW (decision #4) —
            # never waiting for stragglers; the head aging out flushes the partial; else wait a poll slice
            # (interruptible by stop so shutdown lands promptly instead of waiting the whole deadline).
            if self._stop.is_set():
                break
            remaining = deadline - time.time()
            if remaining <= 0:
                break
            try:  # noqa: SIM105
                await asyncio.wait_for(
                    self._stop.wait(), timeout=min(_BATCH_POLL_SECONDS, remaining)
                )
            except TimeoutError:
                pass
        ids = [it.id for it in items]
        retry_until: float | None = None
        connector = self._destinations.get(name)
        if connector is None:
            failure = self._failed.get(name)
            detail = f"outbound failed to start: {failure}" if failure else "outbound reloading"
            retry_until = await self._mark_batch_failed_and_arm(name, ids, detail, retry)
            await self._maybe_alert_buildup(name)
            await self._maybe_alert_stall(name)
            return _ItemOutcome.PROCESSED, retry_until
        # L1 batch twin — see the single-item path for the full rationale. Same reasoning, and the
        # stakes are higher here: mark_batch_failed decides ONE disposition from the head's
        # attempts and applies it to all N, so a finite retry cap dead-letters the whole batch on a
        # leadership change, un-sent.
        if not self._coordinator.is_leader():
            await self.store.release_claimed(ids)
            log.warning(
                "delivery worker %r: leadership lost before send; released %d claimed row(s) "
                "un-errored (no attempt spent) and stopped the lane for the new leader",
                name,
                len(ids),
            )
            return _ItemOutcome.STOPPED, None
        # Frame + send inside ONE try so a FRAMING error (an unparseable / non-HL7 head member — MLLP is
        # payload-agnostic, ADR 0004, so a non-hl7v2 feed can reach here) routes to the internal-error
        # policy below (dead-letter / STOP) instead of stranding every claimed row INFLIGHT forever with
        # no send and no disposition. Members are carried VERBATIM (the head too — never re-encoded); only
        # the head is PARSED, for the BHS separators + the BHS-11 control id.
        try:
            control_id = Message.parse(head.payload).control_id or head.id  # FIFO-aligned, stable
            # #149 (ADR 0105 Phase 1b): re-attach each member's detached document VERBATIM before framing
            # the envelope, so a batched streaming feed delivers full inline documents (never a raw
            # mfdoc:v1:ref: handle). Members with no handle are byte-identical; a missing attachment raises
            # a DeliveryError (caught below → the whole batch re-pends), so the peer never sees a handle.
            hydrated: list[Message | str] = [
                await self._hydrate_payload(it.payload) for it in items
            ]
            envelope = encode_batch(
                hydrated,
                control_id=control_id,
                timestamp=_hl7_batch_timestamp(head.created_at),
            )
            if self._simulate.get(name, False):
                pass  # shadow / parallel-run: suppress the real egress; still complete all N below.
            else:
                await connector.send(envelope)
        except NegativeAckError as exc:
            if exc.permanent:
                await self.store.dead_letter_batch(ids, safe_exc(exc))
            else:
                retry_until = await self._mark_batch_failed_and_arm(name, ids, safe_exc(exc), retry)
                await self._maybe_alert_buildup(name)
                await self._maybe_alert_stall(name)
        except DeliveryError as exc:
            retry_until = await self._mark_batch_failed_and_arm(name, ids, safe_exc(exc), retry)
            await self._maybe_alert_buildup(name)
            await self._maybe_alert_stall(name)
            self._note_lane_unhealthy(name, head.id, exc)
        except Exception as exc:
            # A framing error (unparseable/non-HL7 head) or an internal/code error — NOT the partner's
            # fault. The per-connection policy decides: STOP halts the lane (preserve the batch, alert);
            # CONTINUE (default) dead-letters all N (bad data can never frame/deliver — replayable from
            # the DLQ) so a code bug or a mis-typed feed can't wedge the lane forever.
            if (
                self._internal_error.get(name, self._internal_error_default)
                is InternalErrorPolicy.STOP
            ):
                log.error(
                    "delivery worker %r: framing/internal error delivering a batch of %d (%s); STOPPING "
                    "connection (operator must fix + reload/restart to resume)",
                    name,
                    len(ids),
                    type(exc).__name__,
                )
                await self.store.mark_batch_failed(
                    ids, f"internal error (connection stopped): {safe_exc(exc)}", retry
                )
                self._alert_sink.connection_stopped(
                    name, detail=f"{type(exc).__name__} delivering a batch of {len(ids)}"
                )
                return _ItemOutcome.STOPPED, None
            log.warning(
                "delivery worker %r: framing/internal error delivering a batch of %d (%s); dead-lettering",
                name,
                len(ids),
                type(exc).__name__,
            )
            await self.store.dead_letter_batch(ids, f"internal error: {safe_exc(exc)}")
        else:
            self._note_lane_healthy(name)
            await self.store.mark_batch_done(ids)
        return _ItemOutcome.PROCESSED, retry_until

    async def _mark_batch_failed_and_arm(
        self, lane: str, ids: Sequence[str], error: str, retry: RetryPolicy
    ) -> float | None:
        """``mark_batch_failed`` + (per_lane wake ON) arm a one-shot retry wake at the shared deadline —
        the batch counterpart of :meth:`_mark_failed_and_arm`. All N re-pend to the same
        ``next_attempt_at``, so one timer re-claims the identical prefix. Pooled skips the arming (the
        dispatcher parks off the returned deadline); per_lane arming is byte-identical to the single row."""
        next_at = await self.store.mark_batch_failed(list(ids), error, retry)
        if self._claim_mode != "pooled" and self._per_lane_wake and next_at is not None:
            delay = max(0.0, next_at - time.time()) + _RETRY_WAKE_SLACK_SECONDS
            asyncio.get_running_loop().call_later(delay, self._wake_lane, Stage.OUTBOUND, lane)
        return next_at

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
            # #122 (ADR 0162): the application log is unwritable and this process has fail-closed.
            # Return BEFORE the claim so no row is left INFLIGHT — the same terminal state a
            # STOP-policy halt leaves, re-armed by restarting this inbound.
            if name in self._log_halted:
                return
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
                    outcome = await self._process_ingress_item(name, item)
                    if outcome[0] is _ItemOutcome.STOPPED:
                        return
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

    async def _apply_router_internal_error(
        self, name: str, item: OutboxItem, exc: Exception
    ) -> tuple[_ItemOutcome, float | None]:
        """Apply the global ``internal_error`` policy to a **router-phase CONTENT** fault (a router raise,
        incl. an unknown handler name) — the single source of truth for both the async ingress except
        block and the fused route branch (ADR 0071 B5 PR3; ADR 0057 STOP/CONTINUE). STOP: log + durably
        ``mark_failed`` the head + a ``connection_stopped`` alert + ``(STOPPED, None)``. CONTINUE
        (default): log + ``dead_letter_now`` + ``(PROCESSED, None)``. Post-ACK, so no NAK; the log emits
        the exception TYPE only (full detail goes to the secured store's ``last_error``, never the
        general log — PHI). Byte-identical to the inlined except block it replaces."""
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
            return _ItemOutcome.STOPPED, None
        log.warning(
            "router worker %r: router error on %s (%s); dead-lettering",
            name,
            item.id,
            type(exc).__name__,
        )
        await self.store.dead_letter_now(item.id, f"router error: {safe_exc(exc)}")
        return _ItemOutcome.PROCESSED, None

    async def _apply_transform_internal_error(
        self, name: str, item: OutboxItem, exc: Exception
    ) -> tuple[_ItemOutcome, float | None]:
        """Apply the global ``internal_error`` policy to a **transform-phase CONTENT** fault (a handler
        raise, incl. an unknown outbound name) — the single source of truth for both the async routed
        except block and the fused transform branch (ADR 0071 B5 PR3). Same shape as
        :meth:`_apply_router_internal_error` with the transform wording. Byte-identical to the inlined
        except block it replaces."""
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
            return _ItemOutcome.STOPPED, None
        log.warning(
            "transform worker %r: handler error on %s (%s); dead-lettering",
            name,
            item.id,
            type(exc).__name__,
        )
        await self.store.dead_letter_now(item.id, f"handler error: {safe_exc(exc)}")
        return _ItemOutcome.PROCESSED, None

    async def _process_ingress_item(
        self, name: str, item: OutboxItem
    ) -> tuple[_ItemOutcome, float | None]:
        """Route one claimed ingress row — the per-item body of :meth:`_router_worker`, extracted
        verbatim (ADR 0066, pure code motion) so the loop and the pooled dispatcher share it. Returns
        ``(outcome, retry_until)``: the ingress path never re-pends-with-backoff, so ``retry_until`` is
        always ``None`` (``(PROCESSED, None)`` where the loop advanced, ``(STOPPED, None)`` on a missing
        inbound or the STOP internal-error policy — the body already ``mark_failed``'d / dead-lettered
        the head per policy). The per_lane loop reads only ``outcome[0]``. Store errors propagate to the
        caller's backoff."""
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
            # max_attempts=None is EXPLICIT (#1051): RetryPolicy's own default is now the finite 100,
            # so a bare RetryPolicy() here would dead-letter an ACKed-but-never-attempted message
            # purely for outliving a reload — the one thing these three sites exist to prevent.
            await self.store.mark_failed(
                item.id, "inbound not in registry", RetryPolicy(max_attempts=None)
            )
            return _ItemOutcome.STOPPED, None
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
                return _ItemOutcome.PROCESSED, None
        # ADR 0071 B5 PR3 — fused route+handoff dispatch (SQL Server, pooled, flag on). Fuse
        # route_only (CONTENT) + route_handoff_sync (INFRA) into ONE worker hop, gated on the
        # real guard _fusion_active (True only on SS with the sync twins + executors opened OK).
        # INLINE keeps the async path (NOT fused in v1), so the G6 inline ceiling above still
        # governs it. Byte-identical when fusion is off / non-SS / inline.
        if self._fusion_active and not inline:
            result = await self._fused_route_and_handoff(name, ic, item)
            if result.route_exc is not None:  # CONTENT: a router raise → internal-error policy
                return await self._apply_router_internal_error(name, item, result.route_exc)
            if result.handoff_exc is not None:  # INFRA: acquire/handoff fault → propagate → T17
                raise result.handoff_exc
            if result.wake_target is not None:  # ROUTED lane (disposition already committed sync)
                self._wake_lane(Stage.ROUTED, result.wake_target)
            return _ItemOutcome.PROCESSED, None
        try:
            # Publish the live graph's run-scoped views (code sets / reference snapshots /
            # active environment) so a call-time code_set(...)/reference(...)/
            # current_environment() inside the Router resolves (the loader only had them
            # active during import). Views are read from self.registry/self.store live, so a
            # reload's swapped tables apply to the next routed row; run_contexts restores
            # cleanly after each run (no leak). The set of providers is the run_context
            # registry (router phase) — features add one provider there, never edit this call.
            router_rc = RunContext(
                code_sets=self.registry.code_sets,
                reference_view=self.store.reference_view(),
                active_environment=self._active_environment,
                ingest_time=item.created_at,
                message_id=item.message_id,  # #162: key the unmapped-capture drain per message
            )
            with run_contexts(router_rc, phase="router"):
                # Run the Router OFF the event loop (SEC-013, CWE-1322). A Router is arbitrary
                # synchronous Python whose CPU cost can scale with attacker-influenced content
                # (ReDoS over a field, O(n^2) build); running it inline would let one message
                # stall the single loop, freezing every listener, worker, and the API.
                # asyncio.to_thread copies THIS context (the run_contexts views) into the
                # worker thread, so a call-time code_set()/reference()/current_environment()
                # still resolves. db_lookup raises on a Router by design, so no lookup runner.
                # ADR 0087 (#197): when [sandbox].mode=subprocess, route_only marshals the Router
                # to the per-inbound worker child (router_rc travels with it) instead of running it
                # in this thread; sandbox=None (the default) is the byte-identical in-process path.
                names = await asyncio.to_thread(
                    route_only,
                    self.registry,
                    ic,
                    item.payload,
                    sandbox=self._sandbox_for(name),
                    run_context=router_rc,
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
                inline_rc = RunContext(
                    code_sets=self.registry.code_sets,
                    reference_view=self.store.reference_view(),
                    state_view=self.store.state_view(),
                    response_view=None,
                    active_environment=self._active_environment,
                    ingest_time=item.created_at,
                    message_id=item.message_id,  # #162: key the unmapped-capture drain per message
                    snapshot_on_send=self._snapshot_on_send,  # ADR 0104 copy-on-Send (inline path)
                )
                with run_contexts(inline_rc, phase="transform"):
                    # ADR 0087 (#197): sandbox=subprocess marshals the Handler to the per-inbound
                    # worker (inline_rc travels with it); sandbox=None is the byte-identical path.
                    (
                        deliveries_preview,
                        state_preview,
                        meta_preview,
                        declined,
                    ) = await asyncio.to_thread(
                        transform_one,
                        self.registry,
                        hname,
                        item.payload,
                        content_type,
                        sandbox=self._sandbox_for(name),
                        run_context=inline_rc,
                    )
                # Split deliveries / pass-through / state exactly as the transform worker does.
                deliveries = [(d.to, d.payload) for d in deliveries_preview if not d.is_passthrough]
                pt_deliveries = [d for d in deliveries_preview if d.is_passthrough]
                state_ops = list(state_preview)
                # NB: intentionally NO _log_declined here (unlike the split + fused-sync transform
                # workers). A non-empty `declined` fails the fusion gate below (`and not declined`), so a
                # declined message ALWAYS falls back to the split path, whose transform worker logs — and
                # durably records — the decline exactly once. Logging here too would emit a DUPLICATE INFO
                # line for every declined Send on an inline inbound (#233, ADR 0111 review finding); the
                # message_events record stays single either way, so this is log hygiene.
                # M-deliver gate: only the pure all-deliver case is fused. A zero-delivery
                # (filtering) handler, any state-op, any pass-through Send, or any SetMeta write
                # (ADR 0081, #150 — the fused handoff carries no metadata-merge) FALLS BACK to the
                # split path — handoff lacks _maybe_finalize (G2: a zero-delivery fused message
                # would strand non-terminal) and the state-MERGE / PT-child / metadata machinery
                # transform_handoff carries. The split path finalizes those correctly (FILTERED
                # via transform_handoff's _maybe_finalize; state/PT/meta via its dedicated handling).
                #
                # `declined` (#233, ADR 0111) joins that list: a Send to a not-deployed connection has
                # to be RECORDED (count-and-log), and `handoff` — a lean 3-statement fast-path — has
                # nowhere to record it, so a message carrying one falls back to the split path whose
                # transform_handoff does. The empty-`deliveries` fallback ALSO covers the declined-only
                # case, and must be preserved regardless: store.handoff never runs the finalizer, so a
                # zero-delivery message committed through it would strand non-terminal (G2).
                if (
                    deliveries
                    and not state_ops
                    and not pt_deliveries
                    and not meta_preview
                    and not declined
                ):
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
                    # fused — bypass the split route_handoff path entirely
                    return _ItemOutcome.PROCESSED, None
                # else: ineligible per-message → fall through to the split path verbatim.
        except Exception as exc:
            # Router code error (incl. an unknown handler name) OR — on the inline fast-path —
            # a transform_one/handoff failure (G1). Post-ACK, so no NAK — the global
            # internal_error policy decides (factored into _apply_router_internal_error, the
            # single source of truth shared with the fused route branch; byte-identical).
            return await self._apply_router_internal_error(name, item, exc)
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
        return _ItemOutcome.PROCESSED, None

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
            if name in self._log_halted:  # #122 (ADR 0162) — see _router_worker's gate
                return
            try:
                item = await self.store.claim_next_fifo(name, stage=Stage.RESPONSE.value)
                if item is None:
                    self._empty_claims.record_empty(woken=woken)  # B11 wall #3 (loopback lane)
                    woken = await self._wait_for_work(wait_ev)
                    continue
                outcome = await self._process_response_item(name, item)
                if outcome[0] is _ItemOutcome.STOPPED:
                    return
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

    async def _process_response_item(
        self, name: str, item: OutboxItem
    ) -> tuple[_ItemOutcome, float | None]:
        """Re-ingress one claimed response token — the per-item body of :meth:`_response_worker`,
        extracted verbatim (ADR 0066, pure code motion) so the loop and the pooled dispatcher share
        it. Returns ``(outcome, retry_until)``: the response path never re-pends-with-backoff, so
        ``retry_until`` is always ``None`` (``(PROCESSED, None)`` where the loop advanced,
        ``(STOPPED, None)`` on the missing-inbound exit). The per_lane loop reads only ``outcome[0]``.
        Store errors propagate to the caller's backoff."""
        ic = self.registry.inbound.get(name)
        if ic is None:
            # The loopback was removed by a reload but residual tokens remain. Revert the claim
            # (retry-FOREVER, never dropped) and EXIT; a reload restoring the loopback re-arms
            # this worker and drains the backlog — mirrors the router worker's missing-inbound exit.
            # max_attempts=None is EXPLICIT (#1051): RetryPolicy's own default is now the finite 100,
            # so a bare RetryPolicy() here would dead-letter an ACKed-but-never-attempted message
            # purely for outliving a reload — the one thing these three sites exist to prevent.
            await self.store.mark_failed(
                item.id, "inbound not in registry", RetryPolicy(max_attempts=None)
            )
            return _ItemOutcome.STOPPED, None
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
        return _ItemOutcome.PROCESSED, None

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
            if name in self._log_halted:  # #122 (ADR 0162) — see _router_worker's gate
                return
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
                # Process the claimed FIFO batch. BACKLOG #214: when intra-message transform concurrency
                # is enabled this overlaps a message's sibling rows' transforms while keeping the handoff
                # serial + in claim order; default (concurrency 1 / single row / fused) it is the exact
                # sequential per-item loop. Returns True iff the lane must halt (STOP policy / missing
                # inbound), matching the old `for item in items` early return.
                if await self._process_routed_batch(name, items):
                    return
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

    async def _process_routed_batch(self, name: str, items: Sequence[OutboxItem]) -> bool:
        """Process one claimed FIFO batch of routed rows; return ``True`` iff the lane must STOP (a STOP
        internal-error policy or a missing inbound), matching the worker loop's old ``for item in
        items`` early return.

        BACKLOG #214 — intra-message concurrent transform. When ``_transform_concurrency > 1`` (opt-in;
        default 1 → the exact sequential loop) and the batch holds a run of >= 2 sibling rows of ONE
        message (co-claimed only when ``fifo_claim_batch`` > 1), those rows' **pure** transforms are
        computed CONCURRENTLY (bounded by the cap, via ``asyncio.gather`` so each runs as its own Task
        with an isolated contextvar context) while every store handoff is applied SERIALLY in ascending
        claim order. The handoff is the SOLE per-lane writer and stays serial + rowid-ordered, so
        ``seq`` == claim order for every destination — shared-destination siblings and cross-message
        rows alike — preserving per-destination outbound FIFO (ADR 0059) and the at-least-once staged
        handoff (each row keeps its own atomic claim→produce→complete txn). **Sibling state-visibility
        (deterministic per-batch snapshot, ADR 0005):** because every sibling's PURE transform is computed
        BEFORE any sibling's handoff commits, a LIVE ``state_view()`` read would be interleaving-dependent.
        So this concurrent run freezes ONE point-in-time copy of the committed transform-state at
        run-start (``dict(self.store.state_view())``) and threads it into every sibling's
        :meth:`_prepare_routed`, so each deterministically observes the state as of the message-batch's
        start — no sibling sees another sibling's in-run ``state_set``/``set_meta`` write, independent of
        interleaving. Defined semantics: *a message's sibling handlers read message-batch-start
        transform-state/meta; they do not chain it to each other.* This is READ-side only — final
        committed state (the apply is serial in claim order), per-destination FIFO, and at-least-once are
        all unchanged. The sequential / single-row / fused paths keep reading the LIVE ``state_view()`` —
        byte-identical — so their commit-before-next-transform visibility is preserved. The fused (SQL
        Server) path stays sequential: there transform + handoff are one off-loop write, so overlapping
        them would parallelize the WRITE. Default / single-row / fused / missing-inbound → the exact
        sequential ``_process_routed_item`` loop."""
        ic = self.registry.inbound.get(name)
        if self._transform_concurrency <= 1 or self._fusion_active or ic is None or len(items) < 2:
            for item in items:
                if (await self._process_routed_item(name, item))[0] is _ItemOutcome.STOPPED:
                    return True
            return False
        for run in _contiguous_by_message(items):
            if len(run) < 2:
                # A lone row (no sibling to overlap) goes through the shared per-item path unchanged.
                if (await self._process_routed_item(name, run[0]))[0] is _ItemOutcome.STOPPED:
                    return True
                continue
            # >= 2 sibling routed rows of one message: overlap the PURE transforms (bounded), then
            # apply the handoffs SERIALLY below. The cap doubles as the live-lookup fan-out guard.
            cap = min(self._transform_concurrency, len(run))
            sem = asyncio.Semaphore(cap)
            # BACKLOG #214 state-visibility guard: freeze ONE point-in-time copy of the committed
            # transform-state at run-start and share it across every sibling's compute. Because all
            # siblings compute before any sibling's serial _apply_routed commits, reading the LIVE
            # state_view() would be interleaving-dependent; reading this frozen snapshot makes every
            # sibling deterministically observe message-batch-start state (no sibling sees another's
            # in-run write). dict(state_view()) is a point-in-time copy: state_view() is a live
            # MappingProxyType over the store's cache and each committed write REPLACES a key (never an
            # in-place mutation), so the copied {(ns, key): value} references never change afterwards.
            # READ-side only — no store write, no txn-boundary change, no reordering (the apply below
            # stays the sole serial in-claim-order writer, so the final committed state is unchanged).
            state_snapshot: Mapping[tuple[str, str], Any] = dict(self.store.state_view())

            async def _compute(
                it: OutboxItem,
                _sem: asyncio.Semaphore = sem,
                _ic: InboundConnection = ic,
                _snap: Mapping[tuple[str, str], Any] = state_snapshot,
            ) -> _RoutedPrep:
                async with _sem:
                    return await self._prepare_routed(name, _ic, it, state_snapshot=_snap)

            preps = await asyncio.gather(*(_compute(it) for it in run), return_exceptions=True)
            for it, prep in zip(run, preps, strict=True):
                if isinstance(prep, BaseException):
                    # An INFRA fault in prepare (a store-read error — NOT a handler raise, which is
                    # captured as data). Mirror the sequential path: propagate to the worker's backoff.
                    # Lower-claim siblings already handed off (committed, in order); this row + any
                    # higher un-applied rows stay INFLIGHT and recover in claim order via
                    # reset_stale_inflight (ADR 0058 INV-3 / ADR 0001 at-least-once).
                    raise prep
                if (await self._apply_routed(name, it, prep))[0] is _ItemOutcome.STOPPED:
                    return True
        return False

    async def _process_routed_item(
        self, name: str, item: OutboxItem
    ) -> tuple[_ItemOutcome, float | None]:
        """Transform one claimed routed row — the per-item body of :meth:`_transform_worker`,
        extracted verbatim (ADR 0066, pure code motion) so the loop and the pooled dispatcher share
        it. Returns ``(outcome, retry_until)``: the routed path never re-pends-with-backoff, so
        ``retry_until`` is always ``None`` (``(PROCESSED, None)`` where the loop advanced,
        ``(STOPPED, None)`` on a missing inbound or the STOP internal-error policy — the body already
        ``mark_failed``'d / dead-lettered the head per policy). The per_lane loop reads only
        ``outcome[0]``. Store errors propagate to the caller's backoff."""
        ic = self.registry.inbound.get(name)
        if ic is None:
            # Inbound removed; nothing to transform with until a reload restores it (which
            # re-arms this worker). Revert the row (retry-forever) and exit (mirrors the
            # router worker), so the ACKed-but-unprocessed message is never dropped. The
            # unprocessed batch tail stays INFLIGHT and is recovered in order by
            # reset_stale_inflight on the next start/reload (ADR 0058 INV-3).
            # max_attempts=None is EXPLICIT (#1051): RetryPolicy's own default is now the finite 100,
            # so a bare RetryPolicy() here would dead-letter an ACKed-but-never-attempted message
            # purely for outliving a reload — the one thing these three sites exist to prevent.
            await self.store.mark_failed(
                item.id, "inbound not in registry", RetryPolicy(max_attempts=None)
            )
            return _ItemOutcome.STOPPED, None
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
            await self.store.dead_letter_now(item.id, f"handler {hname!r} removed from registry")
            return _ItemOutcome.PROCESSED, None
        # ADR 0071 B5 PR3 — fused transform+handoff dispatch (SQL Server, pooled, flag on). Fuse
        # transform_one (CONTENT) + transform_handoff_sync (INFRA) into ONE worker hop, gated on
        # the real guard _fusion_active. The missing-handler guard above STAYS ahead of this: the
        # fused callable only asserts hname is not None, it does NOT check hname in
        # registry.handlers. The callable does its OWN loopback response_view prefetch on the loop
        # (do not double-read here). Byte-identical when fusion is off / non-SS.
        if self._fusion_active:
            result = await self._fused_transform_and_handoff(name, ic, item)
            if result.xform_exc is not None:  # CONTENT: a handler raise → internal-error policy
                return await self._apply_transform_internal_error(name, item, result.xform_exc)
            if result.handoff_exc is not None:  # INFRA: acquire/handoff fault → propagate → T17
                raise result.handoff_exc
            # LOOP-side publish of the committed transform-state (the sync twin never mutates the
            # loop-owned read-through cache — ADR 0071 B5).
            cast(_FusedHandoffStore, self.store).publish_state_cache(result.applied_state)
            for _dest in result.outbound_wakes:  # fan-out: each DISTINCT delivery lane
                self._wake_lane(Stage.OUTBOUND, _dest)
            for _pt in result.ingress_wakes:  # cross-lane: each DISTINCT PT-target INGRESS lane
                self._wake_lane(Stage.INGRESS, _pt)
            return _ItemOutcome.PROCESSED, None
        # Non-fused (default) path — split into a PURE compute (_prepare_routed) and the store WRITE
        # (_apply_routed) so a message's sibling rows can overlap the compute under intra-message
        # concurrency (BACKLOG #214) while the handoff stays the sole serial per-lane writer. Here they
        # run back-to-back, byte-identical to the inlined body. The missing-handler guard above stays
        # ahead of both (it also gates the fused branch); _prepare_routed re-checks it only so the
        # concurrent-batch entry (which does not pre-check) is self-contained.
        prep = await self._prepare_routed(name, ic, item)
        return await self._apply_routed(name, item, prep)

    async def _prepare_routed(
        self,
        name: str,
        ic: InboundConnection,
        item: OutboxItem,
        *,
        state_snapshot: Mapping[tuple[str, str], Any] | None = None,
    ) -> _RoutedPrep:
        """PURE, read-only compute for one routed row — the overlap-able half of the transform stage
        (BACKLOG #214). Does NO store write: only the loopback ``response_view`` read + the off-loop
        ``transform_one`` (SEC-013), under the same run-context + live-lookup activation as the inlined
        body. Returns a :class:`_RoutedPrep` capturing the handler-missing guard, a handler raise (as
        data, so a concurrent ``gather`` never cancels a sibling), or the produced
        :class:`TransformOutcome`. The caller applies it — the SOLE writer — serially in claim order via
        :meth:`_apply_routed`. Sibling computes are structurally ISOLATED: ``asyncio.gather`` runs each
        call as its own Task with its own copied contextvar context, so the per-run ``run_contexts``/
        lookup activation and the ``to_thread`` context copy never cross between siblings.

        **Sibling state-visibility (BACKLOG #214) — deterministic under concurrency.** ``state_view()``
        (ADR 0005) is a LIVE read-through cache updated only at each row's ``transform_handoff`` commit.
        The sequential path (``state_snapshot=None``) reads it live: it commits each row before the next
        transforms, so a later sibling observes an earlier sibling's ``state_set``/``set_meta`` write.
        Under concurrent transform every sibling's compute runs HERE *before* any sibling's
        :meth:`_apply_routed` commits, so a live read would be interleaving-dependent (a later sibling
        might see the run-start value or nothing at all, depending on scheduling). To make it
        DETERMINISTIC, :meth:`_process_routed_batch` freezes ONE point-in-time copy of the committed
        state at run-start and threads it in as ``state_snapshot``; every sibling then reads that SAME
        frozen mapping, so each deterministically observes the state as of the message-batch's start and
        none sees another sibling's in-run write — independent of how the transforms interleave. The
        FINAL committed state is identical to the sequential path (the apply is still serial in claim
        order) and FIFO/at-least-once are unaffected; only the intra-run READ is snapshot-isolated.
        Defined semantics: *a message's sibling handlers read message-batch-start transform-state/meta;
        they do not chain it to each other.* When ``state_snapshot`` is None (sequential/single-row/fused
        path) the live ``state_view()`` is used, exactly as before — byte-identical.

        An unexpected store-read fault (loopback metadata read) PROPAGATES — the caller treats
        it as INFRA and backs off, exactly like the inlined path."""
        hname = item.handler_name
        if hname is None or hname not in self.registry.handlers:
            return _RoutedPrep(missing_handler=True)
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
            # Same as the router worker, plus the transform-only providers: publish the
            # run-scoped views so call-time code_set(...)/reference(...)/state_get(...)/
            # current_environment() inside the Handler resolve; restored cleanly after the run.
            # The transform phase adds the store's transform-state read-through cache view
            # (ADR 0005) so state_get(...) resolves against committed writes. Providers come
            # from the run_context registry (transform phase) — features add one provider,
            # never edit this call site.
            transform_rc = RunContext(
                code_sets=self.registry.code_sets,
                reference_view=self.store.reference_view(),
                # BACKLOG #214: sequential/single-row/fused path (state_snapshot is None) reads the LIVE
                # view — byte-identical. A concurrent sibling-run passes a FROZEN run-start copy so every
                # sibling reads the same point-in-time state (deterministic; see this method's docstring).
                state_view=(
                    state_snapshot if state_snapshot is not None else self.store.state_view()
                ),
                response_view=response_view,
                active_environment=self._active_environment,
                ingest_time=item.created_at,
                message_id=item.message_id,  # #162: key the unmapped-capture drain per message
                snapshot_on_send=self._snapshot_on_send,  # ADR 0104 copy-on-Send (split path)
            )
            with run_contexts(transform_rc, phase="transform"):
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
                        lookup_stack.enter_context(db_lookup_activated(self._run_lookup))
                    if self._fhir_lookup_executor is not None:
                        lookup_stack.enter_context(fhir_lookup_activated(self._run_fhir_lookup))
                    # ADR 0087 (#197): sandbox=subprocess marshals the Handler to the per-inbound
                    # worker (transform_rc travels with it); a db_lookup/fhir_lookup inside a
                    # sandboxed Handler fails closed there (they can't bridge across the process
                    # boundary in this PR). sandbox=None is the byte-identical in-process path.
                    outcome = await asyncio.to_thread(
                        transform_one,
                        self.registry,
                        hname,
                        item.payload,
                        content_type,
                        sandbox=self._sandbox_for(name),
                        run_context=transform_rc,
                    )
        except Exception as exc:
            # Handler/transform code error (incl. an unknown outbound name). CONTENT: captured as
            # data, NOT raised, so a concurrent gather never cancels a sibling; the serial apply
            # feeds it to the internal_error policy (post-ACK, no NAK). Byte-identical outcome to
            # the old inlined except block, just deferred to _apply_routed.
            return _RoutedPrep(error=exc)
        return _RoutedPrep(outcome=outcome)

    async def _apply_routed(
        self, name: str, item: OutboxItem, prep: _RoutedPrep
    ) -> tuple[_ItemOutcome, float | None]:
        """Apply one prepared routed row — the SOLE per-lane writer (BACKLOG #214). Called serially in
        ascending claim (rowid/seq) order so per-destination outbound FIFO is preserved even when the
        siblings' transforms were computed concurrently. Mirrors the sequential tail of
        :meth:`_process_routed_item` exactly: handler-missing → dead-letter (``PROCESSED``); handler
        raise → internal-error policy (``STOP``/``CONTINUE``); else ``transform_handoff`` + lane wakes
        (``PROCESSED``). Returns ``(outcome, None)`` — the routed path never re-pends-with-backoff."""
        if prep.missing_handler:
            # Handler gone (removed/renamed since routing). Can't transform this row;
            # dead-letter it (message ERROR, replayable once restored) — the per-row analogue
            # of the startup dead_letter_missing_handlers sweep. Dead-lettering (vs reverting)
            # avoids a hot-loop on a permanently-missing handler and gives operator visibility.
            hname = item.handler_name
            log.warning(
                "transform worker %r: handler %r for %s is missing; dead-lettering",
                name,
                hname,
                item.id,
            )
            await self.store.dead_letter_now(item.id, f"handler {hname!r} removed from registry")
            return _ItemOutcome.PROCESSED, None
        if prep.error is not None:
            # Handler/transform code error (incl. an unknown outbound name). Post-ACK, so no
            # NAK — the global internal_error policy decides (factored into
            # _apply_transform_internal_error, shared with the fused transform branch;
            # byte-identical).
            return await self._apply_transform_internal_error(name, item, prep.error)
        outcome = prep.outcome
        assert outcome is not None  # exactly one _RoutedPrep field is populated
        hname = item.handler_name
        assert hname is not None  # a produced outcome implies the handler ran
        # Split outbound deliveries from pass-through (PT) Sends (ADR 0013, generalized): a PT
        # target re-ingresses the body through an internal inbound's own router (a fresh
        # INGRESS row on the PT channel), produced atomically in the SAME transform_handoff
        # transaction as the outbound rows + routed-row DELETE. transform_one already validated
        # each target and tagged PT ones (is_passthrough) — and DECLINED any Send to a
        # not-deployed connection (#233), so none of those can appear in deliveries_preview and
        # therefore none can become an outbound row here.
        deliveries = [(d.to, d.payload) for d in outcome.deliveries if not d.is_passthrough]
        pt_deliveries = [(d.to, d.payload) for d in outcome.deliveries if d.is_passthrough]
        state_ops = [(s.namespace, s.key, s.value) for s in outcome.state_ops]
        meta_ops = [(m.key, m.value) for m in outcome.meta_ops]
        declined = outcome.declined
        self._log_declined(hname, item.message_id, declined)
        await self.store.transform_handoff(
            routed_id=item.id,
            message_id=item.message_id,
            channel_id=name,
            deliveries=deliveries,
            state_ops=state_ops,
            pt_deliveries=pt_deliveries,
            meta_ops=meta_ops,
            declined=declined,  # #233: persist the decline as a not_deployed event in the same txn
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
        return _ItemOutcome.PROCESSED, None

    # --- ADR 0071 B5: fused CPU-stage + store-handoff callables (wired into dispatch in PR3) ------
    # Each prepares a SINGLE fused worker-thread hop — route_only/transform_one (CPU, off-loop, SEC-013;
    # NO DB connection held across the CPU work, G4/G5) followed by a route_handoff_sync/transform_
    # handoff_sync on a FRESH per-stage synchronous pyodbc connection (its own committed txn) — so the
    # whole multi-statement aioodbc handoff marshals back to the loop in ONE completion instead of per
    # statement (ADR 0071 §5.1). ``loop.run_in_executor`` (unlike ``asyncio.to_thread``) does NOT
    # auto-copy contextvars, so the worker RE-ESTABLISHES the run_contexts (and, for the transform, the
    # live-lookup ExitStack) ITSELF; db_lookup/fhir_lookup still bridge to the loop via
    # run_coroutine_threadsafe. Error-classification boundary (load-bearing): ONLY a route_only/
    # transform_one raise is CONTENT (route_exc/xform_exc → the PR3 caller re-raises INSIDE the
    # internal_error try for STOP/CONTINUE policy); a sync-conn acquire or any *_handoff_sync statement/
    # commit raise is INFRA (handoff_exc → re-raised OUTSIDE → T17 re-pend, never a content dead-letter).
    # Wired into _process_ingress_item / _process_routed_item under the _fusion_active gate (PR3); the
    # async (non-fused) path stays byte-identical when fusion is off / non-SS / inline.

    async def _fused_route_and_handoff(
        self, name: str, ic: InboundConnection, item: OutboxItem, *, now: float | None = None
    ) -> _FusedRouteResult:
        """Fuse ``route_only`` + ``route_handoff_sync`` for one ingress row into a single dispatch to
        the dedicated route executor (ADR 0071 B5). Builds the router-phase RunContext ON THE LOOP (its
        views read the live store/registry, mirroring :meth:`_process_ingress_item`), then runs the CPU
        + handoff off-loop and returns the :class:`_FusedRouteResult`. Wired into the dispatch path in
        PR3 (gated on ``_fusion_active`` in :meth:`_process_ingress_item`)."""
        assert self._fuse_route_executor is not None, "fusion inactive: no route executor"
        loop = asyncio.get_running_loop()
        rc = RunContext(
            code_sets=self.registry.code_sets,
            reference_view=self.store.reference_view(),
            active_environment=self._active_environment,
            ingest_time=item.created_at,
            message_id=item.message_id,  # #162: key the unmapped-capture drain per message
        )
        return await loop.run_in_executor(
            self._fuse_route_executor, self._run_fused_route, name, ic, item, rc, now
        )

    def _run_fused_route(
        self,
        name: str,
        ic: InboundConnection,
        item: OutboxItem,
        rc: RunContext,
        now: float | None,
    ) -> _FusedRouteResult:
        """The synchronous route-fusion body (runs on ``_fuse_route_executor``). Re-establishes
        run_contexts itself (run_in_executor does not copy contextvars), runs ``route_only`` (CONTENT
        boundary — a raise here is ``route_exc``), then acquires a fresh ``routed`` sync connection and
        runs ``route_handoff_sync`` in its own committed txn (INFRA boundary — a raise here is
        ``handoff_exc``). Never both."""
        try:
            with run_contexts(rc, phase="router"):
                names = route_only(self.registry, ic, item.payload)
        except (
            Exception
        ) as exc:  # CONTENT: route_only raise → PR3 re-raises inside internal_error try
            return _FusedRouteResult(
                names=[],
                disposition=None,
                handed_off=False,
                route_exc=exc,
                handoff_exc=None,
                wake_target=None,
            )
        disposition = MessageStatus.ROUTED if names else MessageStatus.UNROUTED
        store = cast(_FusedHandoffStore, self.store)
        try:
            with store.sync_handoff_pool(Stage.ROUTED.value).acquire() as conn:
                handed_off = store.route_handoff_sync(
                    conn,
                    ingress_id=item.id,
                    message_id=item.message_id,
                    channel_id=name,
                    handlers=[(h, item.payload) for h in names],
                    disposition=disposition,
                    now=now,
                )
        except (
            Exception
        ) as exc:  # INFRA: acquire/handoff fault → PR3 re-raises OUTSIDE → T17 re-pend
            return _FusedRouteResult(
                names=names,
                disposition=disposition,
                handed_off=False,
                route_exc=None,
                handoff_exc=exc,
                wake_target=None,
            )
        # Mirror _process_ingress_item: wake this inbound's ROUTED lane iff the router selected handlers
        # (the loop does the wake after the single completion — mark_ready is sync, ADR 0066 §4.2).
        return _FusedRouteResult(
            names=names,
            disposition=disposition,
            handed_off=handed_off,
            route_exc=None,
            handoff_exc=None,
            wake_target=name if names else None,
        )

    async def _fused_transform_and_handoff(
        self, name: str, ic: InboundConnection, item: OutboxItem, *, now: float | None = None
    ) -> _FusedTransformResult:
        """Fuse ``transform_one`` + ``transform_handoff_sync`` for one routed row into a single dispatch
        to the dedicated transform executor (ADR 0071 B5). Builds the transform-phase RunContext (incl.
        the loopback ``response_view``, an async store read) + the ``content_type`` ON THE LOOP, then
        runs the CPU (under the live-lookup ExitStack, re-established on the worker) + handoff off-loop
        and returns the :class:`_FusedTransformResult`. Wired into the dispatch path in PR3 (gated on
        ``_fusion_active`` in :meth:`_process_routed_item`)."""
        assert self._fuse_transform_executor is not None, "fusion inactive: no transform executor"
        loop = asyncio.get_running_loop()
        # ADR 0013 Increment 2: a re-ingressed LOOPBACK message feeds its Handler the origin request's
        # captured replies (response_get). Read on the loop (async store calls); None otherwise —
        # byte-identical to the split _process_routed_item path.
        response_view: dict[str, Any] | None = None
        if ic.spec.type is ConnectorType.LOOPBACK:
            msg = await self.store.get_message(item.message_id)
            raw_meta = msg.get("metadata") if msg else None
            meta = json.loads(raw_meta) if raw_meta else {}
            corr = meta.get("correlation_id") if isinstance(meta, dict) else None
            if corr:
                response_view = {
                    c.destination_name: c for c in await self.store.correlate_response(corr)
                }
        rc = RunContext(
            code_sets=self.registry.code_sets,
            reference_view=self.store.reference_view(),
            state_view=self.store.state_view(),
            response_view=response_view,
            active_environment=self._active_environment,
            ingest_time=item.created_at,
            message_id=item.message_id,  # #162: key the unmapped-capture drain per message
            snapshot_on_send=self._snapshot_on_send,  # ADR 0104 copy-on-Send (fused path)
        )
        content_type = ic.content_type.value
        return await loop.run_in_executor(
            self._fuse_transform_executor,
            self._run_fused_transform,
            name,
            item,
            rc,
            content_type,
            now,
        )

    def _run_fused_transform(
        self,
        name: str,
        item: OutboxItem,
        rc: RunContext,
        content_type: str,
        now: float | None,
    ) -> _FusedTransformResult:
        """The synchronous transform-fusion body (runs on ``_fuse_transform_executor``). Re-establishes
        run_contexts AND the live-lookup ExitStack itself (a db_lookup/fhir_lookup call bridges back to
        the loop), runs ``transform_one`` (CONTENT boundary — a raise here is ``xform_exc``), then
        acquires a fresh ``outbound`` sync connection and runs ``transform_handoff_sync`` in its own
        committed txn (INFRA boundary — a raise here is ``handoff_exc``), returning the committed
        transform-state the LOOP must republish via ``publish_state_cache`` (the sync twin never mutates
        the loop-owned cache)."""
        hname = item.handler_name
        assert hname is not None, "fused transform requires a routed row carrying a handler_name"
        try:
            with run_contexts(rc, phase="transform"), ExitStack() as lookup_stack:
                if self._lookup_executor is not None:
                    lookup_stack.enter_context(db_lookup_activated(self._run_lookup))
                if self._fhir_lookup_executor is not None:
                    lookup_stack.enter_context(fhir_lookup_activated(self._run_fhir_lookup))
                deliveries_preview, state_preview, meta_preview, declined = transform_one(
                    self.registry, hname, item.payload, content_type
                )
        except (
            Exception
        ) as exc:  # CONTENT: transform_one raise → PR3 re-raises inside internal_error try
            return _FusedTransformResult(
                deliveries=[],
                pt_deliveries=[],
                applied_state=[],
                xform_exc=exc,
                handoff_exc=None,
                outbound_wakes=(),
                ingress_wakes=(),
            )
        # transform_one DECLINED any Send to a not-deployed connection (#233), so the fused sync twin
        # produces no outbound row for one either — the seam covers this path with no change to it.
        deliveries = [(d.to, d.payload) for d in deliveries_preview if not d.is_passthrough]
        pt_deliveries = [(d.to, d.payload) for d in deliveries_preview if d.is_passthrough]
        state_ops = [(s.namespace, s.key, s.value) for s in state_preview]
        meta_ops = [(m.key, m.value) for m in meta_preview]
        self._log_declined(hname, item.message_id, declined)
        store = cast(_FusedHandoffStore, self.store)
        try:
            with store.sync_handoff_pool(Stage.OUTBOUND.value).acquire() as conn:
                _handed_off, applied = store.transform_handoff_sync(
                    conn,
                    routed_id=item.id,
                    message_id=item.message_id,
                    channel_id=name,
                    deliveries=deliveries,
                    state_ops=state_ops,
                    pt_deliveries=pt_deliveries,
                    meta_ops=meta_ops,
                    declined=declined,  # #233: persist the decline in the same fused-hop txn
                    correlation_depth_cap=self._max_correlation_depth,
                    now=now,
                )
        except (
            Exception
        ) as exc:  # INFRA: acquire/handoff fault → PR3 re-raises OUTSIDE → T17 re-pend
            return _FusedTransformResult(
                deliveries=deliveries,
                pt_deliveries=pt_deliveries,
                applied_state=[],
                xform_exc=None,
                handoff_exc=exc,
                outbound_wakes=(),
                ingress_wakes=(),
            )
        # Fan-out wake targets (dispatched by the loop after the single completion): each DISTINCT
        # delivery lane + each DISTINCT PT-target INGRESS lane (mirrors _process_routed_item's fan-out).
        return _FusedTransformResult(
            deliveries=deliveries,
            pt_deliveries=pt_deliveries,
            applied_state=applied,
            xform_exc=None,
            handoff_exc=None,
            outbound_wakes=tuple({d for d, _ in deliveries}),
            ingress_wakes=tuple({d for d, _ in pt_deliveries}),
        )

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
        # Connection controls: a deliberately-paused outbound's queue GROWS by design (delivery halted,
        # rows retained) — never false-page on it. Scoped to _outbound_paused membership + the OUTBOUND
        # stage, and it LIFTS immediately on start_outbound, so a genuinely backed-up RESUMED lane still
        # trips buildup. (INGRESS/ROUTED lanes never appear in _outbound_paused; the stage guard is belt.)
        if stage == Stage.OUTBOUND.value and name in self._outbound_paused:
            return
        # #93 (ADR 0014 amendment): the saturation (rising-backlog derivative) check rides the SAME
        # per-lane tick as buildup and shares the paused guard above, but is INDEPENDENT of the buildup
        # ceiling — it fires on rising depth even when the absolute depth/age ceiling is not crossed
        # (a lane becoming overloaded before it hits the ceiling). Off by default (zero cost — see the
        # method's early return), so this adds nothing to the hot path unless an operator opts in.
        await self._maybe_alert_saturation(name, stage=stage)
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

    async def _maybe_alert_saturation(
        self, name: str, *, stage: str = Stage.OUTBOUND.value
    ) -> None:
        """Raise a ``saturation`` alert if a lane's backlog is **rising sustained** (#93, ADR 0014
        amendment) — the DERIVATIVE signal, distinct from :meth:`_maybe_alert_buildup`'s absolute
        depth/age ceiling. A bounded per-``(stage, lane)`` :class:`SaturationDetector` samples the
        pending depth; a lane whose depth climbs monotonically over the window trips (sustained rising
        depth ⇔ ingest > drain by queue conservation), while a bursty-but-DRAINING lane (spike then
        fall) does not — the whole point.

        **Deny-by-default and zero-cost when off:** ``sustain_samples is None`` (the default) returns
        before any store read, so a deployment that does not opt in pays nothing on the buildup tick.
        When on, it does its own cheap ``pending_depth`` COUNT+MIN (the buildup read is separate and
        gated on the buildup threshold, which may itself be off). The re-alert is throttled per
        ``(stage, connection)`` (``_BUILDUP_REALERT_SECONDS``) independently of buildup/stall; a sink
        must never raise (contract), but we guard so an alerting bug can't kill the worker."""
        # A deliberately-paused outbound's backlog grows by design — never false-page it (the shared
        # buildup caller already guards this, but re-guard so a direct call is safe too).
        if stage == Stage.OUTBOUND.value and name in self._outbound_paused:
            return
        sustain = self._saturation_default.sustain_samples
        if sustain is None:
            return  # saturation alerting disabled (deny-by-default) — no store read, no cost
        key = f"{stage}:{name}"
        now = time.time()
        depth, _oldest = await self.store.pending_depth(name, stage=stage)
        detector = self._saturation_detectors.get(key)
        if detector is None:
            detector = SaturationDetector(sustain)
            self._saturation_detectors[key] = detector
        # Sample EVERY tick (even when throttled) so the depth window stays continuous; the throttle
        # only gates the notification, never the sampling.
        signal = detector.observe(now, depth)
        if signal is None:
            return  # backlog not rising sustained (flat, falling, or window not yet primed)
        if now < self._next_saturation_alert.get(key, 0.0):
            return  # re-alert throttled — same lane paged too recently
        self._next_saturation_alert[key] = now + _BUILDUP_REALERT_SECONDS
        try:
            self._alert_sink.saturation_rising(
                name,
                stage=stage,
                depth=signal.depth,
                depth_start=signal.depth_start,
                growth_per_second=signal.growth_per_second,
            )
        except Exception:
            log.exception("alert sink raised on saturation for %r", name)

    async def _non_owned_lane_watchdog(self) -> None:
        """Sharded-only (ADR 0073): periodically run the buildup/stall checks over the outbound
        lanes THIS shard does not own. With a single delivery consumer per lane, a hung (not
        crashed) owner stalls its lanes with zero paging anywhere — the supervisor's liveness test
        is process-exit only, and the buildup/stall alerts otherwise fire only inside the owner's
        delivery path. Every shard produces into shared lanes, so every shard watches the ones it
        cannot drain: a pure ``pending_depth`` read per lane per tick, throttled by the alert
        machinery's own re-alert window. Known limitation (documented in the ADR): an operator
        pause on the OWNER is per-process state and invisible here, so a deliberately-paused lane
        can page from a sibling — the owner's ``/connections`` row (``paused``/``owner_shard``)
        disambiguates."""
        while not self._stop.is_set():
            try:
                await asyncio.wait_for(self._stop.wait(), timeout=_SHARD_WATCHDOG_INTERVAL_SECONDS)
                return  # stop signalled — exit quietly
            except TimeoutError:
                pass  # tick: run the checks below
            for name in list(self.registry.outbound):
                if self._stop.is_set():
                    return
                if self._owns_destination(name):
                    continue  # the local delivery path already checks lanes this shard drains
                try:
                    await self._maybe_alert_buildup(name)
                    await self._maybe_alert_stall(name)
                except Exception:
                    # A watchdog read failure is a diagnostic, never fatal — next tick retries.
                    log.exception("non-owned-lane watchdog check failed for %r", name)

    async def _maybe_alert_stall(self, name: str) -> None:
        """Raise a ``message_stall`` alert if an outbound lane's **oldest undelivered message** has aged
        past the connection's resolved :class:`StallThreshold` (#50, Corepoint "Max Message Stall").

        Modeled exactly on :meth:`_maybe_alert_buildup` but a single age dimension, and it **reuses the
        same metric** — the oldest pending row's age (``delivered_age``) from ``store.pending_depth`` —
        rather than inventing a new one. Off by default: ``StallThreshold.max_oldest_seconds is None``
        disables it, so nothing fires unless an operator configures a threshold (deny-by-default). The
        re-alert is throttled per connection so an ongoing stall reminds without spamming; the sink must
        never raise (contract), but we guard so an alerting bug can't kill the worker."""
        # Connection controls: suppress the stall page on a deliberately operator-paused outbound (its
        # oldest message ages by design); lifts immediately on start_outbound (stall is OUTBOUND-only).
        if name in self._outbound_paused:
            return
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

    # --- pooled-mode per-stage adapters (ADR 0066) ---------------------------
    # The pooled StageDispatcher's process_item callable has signature (lane, item) -> LaneItemResult;
    # these thin adapters run the SAME extracted per-item body the per_lane loops run and map its
    # (_ItemOutcome, retry_until) 2-tuple through _to_lane_result. Unused in per_lane mode (start()
    # never constructs a dispatcher there), so the default path never reaches them.

    async def _dispatch_ingress(self, lane: str, item: OutboxItem) -> LaneItemResult:
        result = _to_lane_result(await self._process_ingress_item(lane, item))
        # D1: the per_lane ingress buildup check lived in the router-worker loop; re-add it here
        # (rate-limited) since pooled mode has no such loop.
        await self._pooled_maybe_buildup(lane, Stage.INGRESS.value)
        return result

    async def _dispatch_routed(self, lane: str, item: OutboxItem) -> LaneItemResult:
        result = _to_lane_result(await self._process_routed_item(lane, item))
        await self._pooled_maybe_buildup(lane, Stage.ROUTED.value)  # D1 (see _dispatch_ingress)
        return result

    async def _dispatch_delivery(self, lane: str, item: OutboxItem) -> LaneItemResult:
        # BACKLOG #82: pace this lane's egress BEFORE the send seam (mirrors the per_lane worker) so one
        # hook covers the single-message AND batch bodies in the POOLED claim mode too.
        await self._pace_outbound(lane)
        # #134 (ADR 0082): batch inside the pooled claim (decision #5) — the dispatcher claims one head
        # per lane as always; a batching lane's delivery body coalesces its own tail (claim_next_fifo)
        # into one BHS…BTS envelope, so per_lane and pooled share the exact batch body with NO change to
        # the StageDispatcher state machine (the held slot spans the bounded max_wait_ms window).
        batch_cfg = self._batch.get(lane)
        if batch_cfg is not None:
            return _to_lane_result(await self._process_delivery_batch(lane, item, batch_cfg))
        return _to_lane_result(await self._process_delivery_item(lane, item))

    async def _dispatch_response(self, lane: str, item: OutboxItem) -> LaneItemResult:
        return _to_lane_result(await self._process_response_item(lane, item))

    async def _wait_for_work(self, event: asyncio.Event) -> bool:
        """Wait up to the idle backstop for ``event`` (this worker class's wake event), then clear it.
        Per-class events mean a worker only clears its own signal, so one class can't swallow another's
        wakeup; the backstop still bounds any missed set().

        The backstop is ``poll_interval`` with per-lane wake OFF (byte-identical to pre-WS-C), and the
        long ``_PER_LANE_IDLE_BACKSTOP_SECONDS`` with it ON — the wake is the latency path, and every
        deferred-work source has its own wake (see the constant's comment), so the short re-poll only
        stormed the store's claim path from idle lanes (the WS-C finding).

        Returns ``True`` if a wake event arrived (a producer ``.set()`` — the per-commit herd) and
        ``False`` if it timed out on the backstop (an idle re-poll). The worker uses this to
        classify its NEXT empty claim as wake-fanout vs idle-poll (B11). Read-only: the return value is
        observability-only and never changes the wait/clear behavior."""
        woken = True
        try:
            await asyncio.wait_for(event.wait(), self._idle_backstop)
        except TimeoutError:
            woken = False
        finally:
            event.clear()
        return woken

    async def _wait_for_resume(self, name: str) -> bool:
        """Block a per_lane delivery worker at its loop-top pause gate until ``name`` is resumed
        (:meth:`start_outbound` sets the resume Event) or the idle backstop elapses. Returns ``True`` if
        a resume/wake arrived, ``False`` on the backstop timeout (the caller re-checks the gate — belt-
        and-suspenders against a lost resume set; the returned flag seeds the NEXT empty-claim's
        wake-vs-idle classification, exactly like :meth:`_wait_for_work`). COOPERATIVE: the worker's
        in-flight item already resolved before this gate, so nothing is stranded INFLIGHT."""
        ev = self._outbound_resume.setdefault(name, asyncio.Event())
        try:
            await asyncio.wait_for(ev.wait(), self._idle_backstop)
            return True
        except TimeoutError:
            return False

    async def _mark_failed_and_arm(
        self, lane: str, outbox_id: str, error: str, retry: RetryPolicy
    ) -> float | None:
        """``mark_failed`` + (per-lane wake ON) arm a one-shot timer that wakes this OUTBOUND lane just
        past the row's ``next_attempt_at`` — the retry re-claim used to ride the short idle poll, which
        the WS-C backstop removed, so the retry schedule needs its own wake. Slack keeps the wake at-or-
        after due time (an early wake claims nothing, then sleeps a whole backstop). ``mark_failed``
        returns ``None`` when the row dead-lettered (or vanished) — nothing to re-claim, no timer. The
        timer only sets an Event: firing after shutdown or a reload respawn is harmless (events are
        get-or-create by stable lane name), and at-least-once never depends on it (the backstop and the
        always-re-claim loop still bound a lost timer to added latency, never loss).

        Returns the row's re-pended ``next_attempt_at`` (``None`` when it dead-lettered/vanished) — the
        additive ADR 0066 return the delivery body surfaces as its ``retry_until`` so the pooled
        dispatcher PARKs the lane on it. In ``pooled`` mode the timer arming is skipped (the dispatcher
        arms its own exact park timer off the returned deadline); the per_lane arming is byte-identical."""
        next_at = await self.store.mark_failed(outbox_id, error, retry)
        if self._claim_mode != "pooled" and self._per_lane_wake and next_at is not None:
            delay = max(0.0, next_at - time.time()) + _RETRY_WAKE_SLACK_SECONDS
            asyncio.get_running_loop().call_later(delay, self._wake_lane, Stage.OUTBOUND, lane)
        return next_at

    async def _stop_or_sleep(self, delay: float) -> bool:
        """Sleep up to ``delay`` seconds; return True if a stop was requested meanwhile (so a
        backing-off worker exits promptly on shutdown instead of sleeping out the full delay)."""
        try:
            await asyncio.wait_for(self._stop.wait(), delay)
            return True
        except TimeoutError:
            return False


def _hl7_batch_timestamp(created_at: float | None) -> str:
    """Format an outbound row's re-run-stable ingest time (epoch seconds) as a deterministic HL7 BHS-7
    batch-creation DTM (``YYYYMMDDHHMMSS``, **UTC** — TZ-independent, so a re-run on any host re-derives
    the byte-identical envelope; #134 / ADR 0082). Empty string when ``created_at`` is absent (defensive:
    every outbound claim now projects it) — still deterministic."""
    if created_at is None:
        return ""
    return time.strftime("%Y%m%d%H%M%S", time.gmtime(created_at))


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
    return Source(
        type=ic.spec.type,
        # #333: carry the connection name so a connector's operator-facing warning can name itself (the
        # generic-ODBC TLS reminder was anonymous, and its remedy is per-connection).
        name=ic.name,
        settings=settings,
        ack_mode=ic.ack_mode,
        # #200 (ADR 0092): surface the per-connection insecure-hop attestation as a typed field so the
        # cell (built inside build_check_registry's active_hop_posture scope) can ALLOW a legitimately-
        # secure hop. Default False → keyed purely on posture; a bad attested/reason pair fails loud here.
        tls_hop_attested=bool(settings.get("tls_hop_attested", False)),
        tls_hop_attested_reason=_hop_attested_reason(settings),
    )


def _hop_attested_reason(settings: Mapping[str, Any]) -> str | None:
    """The env-resolved ``tls_hop_attested_reason`` connector setting as ``str | None`` (#200)."""
    reason = settings.get("tls_hop_attested_reason")
    return None if reason is None else str(reason)


def _apply_egress_proxy_default(settings: dict[str, Any], egress: EgressSettings | None) -> None:
    """Fill the site-wide ``[egress]`` forward-proxy default into a connection's resolved settings when it
    set no per-connection proxy (ADR 0126, #112/#128). A per-connection ``proxy_url`` / ``proxy_no_proxy``
    wins verbatim; only an ABSENT value inherits the ``egress`` default. ``None`` egress / no default →
    byte-identical, so a graph without an ``[egress].proxy_url`` is unchanged."""
    if egress is None:
        return
    if egress.proxy_url and not settings.get("proxy_url"):
        settings["proxy_url"] = egress.proxy_url
    if egress.proxy_no_proxy and not settings.get("proxy_no_proxy"):
        settings["proxy_no_proxy"] = list(egress.proxy_no_proxy)


def _dest_config(
    oc: OutboundConnection,
    env_values: Mapping[str, Any],
    trust_anchor_policy: TrustAnchorPolicy | None = None,
    egress: EgressSettings | None = None,
) -> Destination:
    # Resolve env() first so any signing key/password ref is materialized here, then assemble the
    # typed signing config (ASVS 4.1.5, ADR 0018) from the resolved sign_* settings. None = signing
    # off (every existing outbound unchanged). The connector loads the key + mints the signature; this
    # is the single choke point feeding start/check/dry-run, so a bad key fails loud at all three.
    settings = resolve_env_settings(oc.spec.settings, env_values)
    # ADR 0126: merge the site-wide forward-proxy default (a per-connection proxy wins). This is the one
    # choke point feeding start/check/dry-run, so the same effective proxy is built at all three.
    _apply_egress_proxy_default(settings, egress)
    # ADR 0153: MIRROR the cleartext-acceptance declaration into the resolved settings. The connectors
    # read the typed Destination fields below, but the deep settings-driven seams — the forward-proxy
    # credential chain, the HTTP Digest / OAuth2 / SMART token-endpoint providers — receive only a
    # settings mapping, exactly as they already do for `tls_hop_attested`. The connection NAME rides
    # with it so the acceptance audit record those seams emit can still name the declaration that
    # produced it. Written ONLY when the flag is set, so an outbound that declared nothing carries no
    # new keys and is byte-identical.
    if oc.cleartext_accepted:
        settings["cleartext_accepted"] = True
        settings["cleartext_reason"] = oc.cleartext_reason
        settings["cleartext_connection"] = oc.name
    return Destination(
        name=oc.name,
        type=oc.spec.type,
        settings=settings,
        retry=oc.retry or RetryPolicy(),
        sign=OutboundSigning.from_settings(settings),
        # BACKLOG #107: surface the per-outbound raw-separator escape-hatch as a typed field. Default
        # False → byte-identical; only an explicit `hl7_raw_separators=True` (MLLP() factory or a
        # connections.toml setting) flips it. The MLLP connector reads config.hl7_raw_separators.
        hl7_raw_separators=bool(settings.get("hl7_raw_separators", False)),
        # #200 (ADR 0092): the per-outbound insecure-hop attestation, typed here so the cell can ALLOW a
        # legitimately-secure egress hop even on production-PHI. Default False → keyed purely on posture.
        tls_hop_attested=bool(settings.get("tls_hop_attested", False)),
        tls_hop_attested_reason=_hop_attested_reason(settings),
        # ADR 0153 decision 2: the per-outbound cleartext-hop ACCEPTANCE ("this hop is NOT secure and we
        # accept that"). A TOP-LEVEL outbound key, not a transport setting, so it is read off the
        # OutboundConnection rather than the env-resolved settings dict — one authoring surface, and no
        # env() indirection on a governance declaration that must be legible in review. Default off →
        # byte-identical.
        cleartext_accepted=oc.cleartext_accepted,
        cleartext_reason=oc.cleartext_reason,
        # #201 (ADR 0078 amendment): per-connection attestation that revocation is checked for a VERIFYING
        # outbound TLS hop, typed here so the connector's revocation gate can ALLOW it even on prod-PHI.
        # Default False → keyed purely on posture (existing verifying outbounds byte-identical).
        tls_revocation_attested=bool(settings.get("tls_revocation_attested", False)),
        # #190 (ADR 0093): thread the instance-wide [tls] client trust-anchor policy onto the outbound
        # (the SINGLE choke point feeding build_check AND live construction, so the internal-outbound TLS
        # context builders resolve the same anchor both places). None → the default system/no-op policy,
        # byte-identical to before this seam.
        trust_anchor_policy=trust_anchor_policy or TrustAnchorPolicy(),
        # #136 (ADR 0065 amendment): the cosmetic "Waiting for Reply" pre-display delay, threaded onto the
        # Destination so the MLLP connector can size its side-band waiting window. DISPLAY ONLY — no
        # delivery effect. Default 0.0 → byte-identical.
        waiting_display_delay=oc.waiting_display_delay,
    )


def build_check_registry(
    registry: Registry,
    *,
    inbound_bind_host: str,
    env_values: Mapping[str, Any],
    egress: EgressSettings,
    reserved_bindings: Sequence[tuple[str, str, int]] = (),
    posture: HopPosture | None = None,
    trust_anchor_policy: TrustAnchorPolicy | None = None,
    delivery: DeliverySettings | None = None,
) -> None:
    """Construct (and discard) every **deployed** connector in ``registry`` + run the fail-closed
    connect/egress allowlists, so a bad connector spec or a non-allowlisted host fails as a
    :class:`WiringError` BEFORE anything is applied. The standalone core of
    :meth:`RegistryRunner.build_check`, callable offline — e.g. the ``connection`` CLI validating an edit
    before it persists (ADR 0007). Builds nothing live (no socket bind / file I/O — binding happens later
    in ``start_inbound``).

    A ``deployed=False`` connection (#233, ADR 0111) is SKIPPED — see :func:`_build_check_connectors`.

    ``posture`` (#200, ADR 0092) is the instance's derived security posture (PHI? production?), stamped
    as the active hop posture for the whole connector-construction block so each cell keys its
    posture-keyed insecure-hop refusal on the LOADED config's posture rather than guessing — the ENFORCED
    construction-time gate that fires at ``messagefoundry check`` / dry-run / reload. ``None`` (an
    embedding/test that doesn't derive a posture) leaves the posture unstamped: a cell then fail-closes
    (treats each hop as prod-PHI). Every ``serve``/``reload`` caller passes the config's real posture.

    ``trust_anchor_policy`` (#190, ADR 0093) is the instance ``[tls]`` client trust-anchor policy the
    internal-outbound TLS context builders resolve their org internal-CA fallback against. ``None`` → the
    default system/no-op policy (byte-identical — the OS trust store verifies the peer)."""
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
        # Stamp the derived posture for the whole build so a cell's posture-keyed hop-refusal (ADR 0092)
        # decides against THIS config's posture. The port-conflict pre-flight above builds no connector,
        # so it need not run inside the scope.
        with active_hop_posture(posture):
            _build_check_connectors(
                registry, inbound_bind_host, env_values, egress, trust_anchor_policy, delivery
            )
    except WiringError:
        raise
    except Exception as exc:
        raise WiringError(f"connector build failed: {exc}") from exc


def _build_check_connectors(
    registry: Registry,
    inbound_bind_host: str,
    env_values: Mapping[str, Any],
    egress: EgressSettings,
    trust_anchor_policy: TrustAnchorPolicy | None = None,
    delivery: DeliverySettings | None = None,
) -> None:
    """Construct-and-discard every DEPLOYED connector + run the connect/egress allowlists (the body of
    :func:`build_check_registry`, split out so the whole block runs inside the ``active_hop_posture``
    scope with a single ``try`` in the caller). Raises the raw connector error; the caller wraps a
    non-:class:`WiringError` as one.

    **A ``deployed=False`` connection (#233, ADR 0111) is skipped entirely** — no ``_source_config`` /
    ``_dest_config``, therefore no :func:`resolve_env_settings`, therefore its ``env()`` values are NEVER
    resolved and no connector is ever built for it.

    This skip IS the feature. This loop is the one place that build-checks EVERY connection with no
    lifecycle filter at all (``auto_start`` / DR-park / simulate all dodge it by never reaching a build),
    and it is reached from ``messagefoundry check`` (the required commit/CI gate), from every live reload
    and promote, and from every ``connection upsert``/``remove`` (the GUI write path — where one
    unresolvable connection currently blocks edits to EVERY OTHER connection). Without the skip, a
    connection whose credentials do not exist yet still explodes on all of those paths and the state buys
    nothing. The fail-loud guarantee is UNCHANGED for a deployed connection: a missing ``env()`` value on
    one still raises here, which is exactly the promote-time gate ("a graph whose env keys aren't defined
    for the target never goes live")."""
    # ADR 0154 D4: normalise the graph BEFORE validating it, so the passthrough content-type rule
    # below sees the implied header rather than refusing the ADR's own headline shape. Idempotent.
    apply_sync_reply_capture_implication(registry)
    for ic in registry.inbound.values():
        if not ic.deployed:
            continue
        source_cfg = _source_config(ic, inbound_bind_host, env_values)
        check_source_allowed(source_cfg, ic.name, egress)
        # ADR 0154 D4's cross-registry arm: reply_from's target must exist, be deployed, capture
        # responses, and resolve to a lane that can actually serve concurrent callers.
        check_http_sync_reply(ic, registry, delivery=delivery)
        # ADR 0154 D7's parallel offline arm. The runner-side call in _start_inbound_unsafe does NOT
        # fire at `messagefoundry check`, so without this a config that refuses to start would pass
        # the commit/CI gate and only fail at serve. Same predicate, and posture-keyed the same way:
        # the ADR describes this arm as running "without a posture", but that is not true of the
        # source — build_check_registry takes one and `messagefoundry check` passes the real derived
        # posture, which active_hop_posture has stamped around this whole loop. Warning-only here
        # would leave this gate weaker at check time than every posture-keyed neighbour.
        check_http_intake_auth(source_cfg, ic.name, posture=current_hop_posture())
        build_source(source_cfg)
    # The whole config's Loopback inbounds — NOT just this process's. Under engine sharding (ADR 0073)
    # `registry.inbound` holds only this shard's inbounds while EVERY shard keeps every outbound, so a
    # capturing outbound whose loopback is owned by a sibling shard must still validate here: the runtime
    # already spans that split (the delivering shard produces the Stage.RESPONSE row; the loopback's shard
    # drains it — _wake_lane). Unsharded this is exactly `registry.inbound`'s loopbacks, so a typo'd or
    # non-loopback target still fails on every shard.
    loopbacks = registry.loopback_inbound_names()
    reingress_targets: set[str] = set()
    for oc in registry.outbound.values():
        if not oc.deployed:
            continue
        dest = _dest_config(oc, env_values, trust_anchor_policy, egress)
        check_egress_allowed(dest, egress)  # fail-closed egress allowlist (WP-11c)
        build_destination(dest)
        # ADR 0013 Increment 2: reingress_to must name an existing Loopback() inbound. This is a
        # CROSS-registry fact (build_outbound_connection is registry-blind), enforced here so it
        # fails at `check`/dry-run with no store, like every other connector validation.
        target = oc.spec.settings.get("reingress_to")
        if target is not None:
            if str(target) not in loopbacks:
                raise WiringError(
                    f"outbound connection {oc.name!r}: reingress_to names unknown/non-loopback "
                    f"inbound {target!r} — declare it as inbound(..., Loopback(), ...) (ADR 0013)."
                )
            reingress_targets.add(str(target))
    # A loopback inbound with no capturing outbound pointing at it is legal but inert (never fed) —
    # surface it (it may be a staging artifact), but don't error. A not-deployed loopback is inert BY
    # DECLARATION (#233), so the warning would be noise on exactly the config that already says so.
    for iname, ic in registry.inbound.items():
        if (
            ic.deployed
            and ic.spec.type is ConnectorType.LOOPBACK
            and iname not in reingress_targets
        ):
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
        _apply_egress_proxy_default(fsettings, egress)  # ADR 0126: site-wide forward proxy
        check_fhir_lookup_allowed(
            fname, fsettings, egress
        )  # fail-closed egress allowlist (ADR 0043)
        resolved_fhir_lookups[fname] = fsettings
    if resolved_fhir_lookups:
        # Construct (and discard): validates each FHIR URL/TLS/SMART-auth without issuing a read.
        FhirLookupExecutor(resolved_fhir_lookups)


def check_pt_backend_supported(registry: Registry, store: QueueStore) -> None:
    """Reject a graph with a pass-through (PT) inbound on a store backend that doesn't implement PT
    re-ingress, BEFORE any inbound listener accepts a message.

    **ALLOW-LIST semantics:** PT is permitted only on a backend whose ``supports_pt_reingress`` is
    ``True`` — SQLite, Postgres, and SQL Server all set it today. The ``False`` default lives on the
    ``QueueStore`` protocol (store/base.py), so a FUTURE backend that hasn't implemented the
    ``pt_deliveries`` branch of :meth:`transform_handoff` is rejected here rather than at the first
    Handler ``Send`` into a PT connector (which would NotImplementedError *after* the inbound was
    already ACKed). Names the offending PT connection(s) and the backend.

    This is the **single source of truth** for the gate: it runs on EVERY config-application path —
    ``Engine.start`` calls it directly, and the reload (live-runner + runner-None bring-up) and
    ``reload(dry_run=True)`` paths reach it via :meth:`RegistryRunner.build_check` — so a PT graph on a
    PT-incapable backend is rejected with a :class:`WiringError` (422) before any swap/start, leaving any
    already-running graph untouched. No-op when the backend supports PT or the graph has no PT inbound,
    so the path on today's three backends is byte-identical."""
    if getattr(store, "supports_pt_reingress", False):
        return  # backend opted in (SQLite/Postgres/SQL Server) — PT is permitted, nothing to gate
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
        f"Pass-through (PT) connector{plural} {names} require{'' if plural else 's'} a store backend "
        f"with PT re-ingress support (SQLite, Postgres, and SQL Server all have it); backend "
        f"{backend_name!r} does not support PT re-ingress."
    )


def check_reference_backend_supported(registry: Registry, store: QueueStore) -> None:
    """Reject a graph that declares a reference set (ADR 0006 ``Reference(...)``) on a store backend that
    doesn't implement the snapshot store, BEFORE any inbound listener accepts a message.

    **ALLOW-LIST semantics** (the :func:`check_pt_backend_supported` shape): permitted only on a backend
    whose ``supports_reference_sets`` is ``True``. All three shipped backends are (SQLite the reference
    implementation, Postgres ported, SQL Server ported at parity — BACKLOG #235), so today the gate
    guards any future backend that leaves the base-protocol default ``False``. No-op when the backend
    supports sets, and no-op when the graph declares none, so a deployment that doesn't use reference
    sets is untouched either way.

    **Why ENGINE-REFUSAL and not an ADR-0031 lane degrade.** A reference set is registry-GLOBAL and the
    read is a runtime-only ``reference(name)`` call inside a Handler body: there is no sound static
    handler->refset edge to scope a degrade to (``config/reachability.py``'s is self-declared heuristic and
    cannot see a computed name), so ANY handler on ANY inbound may read the set. Nor is it analogous to
    the capture case — a capture-incapable lane still retries its rows and drops nothing, whereas an
    unmaterializable set makes every reading handler raise post-ACK, forever. Refusing the graph is the
    only sound choice; the gate keys on DECLARATION, so it fires even with ``sync_on_startup`` off (the
    set still never materializes).

    Folded into :meth:`RegistryRunner.build_check` as well as ``Engine.start``, so EVERY config-application
    path (reload, promote, ``reload(dry_run=True)``) reaches it and a reload that ADDS a ``Reference(...)``
    fails 422 before any swap, leaving the running graph untouched."""
    if getattr(store, "supports_reference_sets", False):
        return  # backend implements the snapshot store (SQLite/Postgres) — nothing to gate
    if not registry.references:
        return  # no reference set declared — any backend is fine
    backend = getattr(store, "backend", None)
    backend_name = backend.value if isinstance(backend, StoreBackend) else type(store).__name__
    names = ", ".join(repr(n) for n in sorted(registry.references))
    plural = "s" if len(registry.references) > 1 else ""
    raise WiringError(
        f"Reference set{plural} {names} require{'' if plural else 's'} a store backend that implements "
        f"ADR 0006 reference snapshots; backend {backend_name!r} does not, so "
        f"every reference(...) read would raise at run time, after the ACK."
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
    if conn_type is ConnectorType.DIRECT:
        return egress.allowed_direct  # Direct S/MIME-over-SMTP HISP relay (ADR 0085)
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


# Every settings key naming a SECOND egress host that the HTTP family POSTs **credentials** to — a
# host distinct from the data ``url`` the caller's own gate already checks. Each one must ride the
# same ``[egress].allowed_http`` allowlist or it is a fail-open credential-exfiltration hole: the
# allowlist would gate the data host while the credential leaves for anywhere.
#
# ADD A KEY HERE when a new credential-bearing endpoint setting is introduced. That is the whole
# maintenance contract — both call sites iterate this table, so a new key is gated on both arms at
# once and cannot repeat the DELTA-04 drift (one arm gated, the other not).
_CREDENTIAL_EGRESS_URL_KEYS: tuple[tuple[str, str], ...] = (
    # ADR 0024 — the connector POSTs a signed ``client_assertion`` here.
    ("smart_token_url", "SMART token endpoint"),
    # ADR 0126 — the client-credentials grant POSTs ``client_id`` + ``client_secret`` here, either as
    # form fields or as a Basic header (``transports/http_auth.py`` ``_fetch_token``). Ungated until
    # 2026-07-31: the scheme was constrained to http(s) and nothing else, so a crafted
    # ``oauth2_token_url`` exfiltrated the client credentials to any host while ``[egress]
    # .allowed_http`` gated only the data URL. Found re-scoring ASVS 14.2.3.
    ("oauth2_token_url", "OAuth2 token endpoint"),
)


def _check_credential_token_url_egress(
    label: str, settings: Mapping[str, Any], allowed_http: list[str]
) -> None:
    """Gate every credential-bearing token endpoint on an HTTP-family connection against
    ``[egress].allowed_http`` — see :data:`_CREDENTIAL_EGRESS_URL_KEYS` for the keys and why each one
    carries a secret. A crafted token URL pointing at an un-allowlisted host would exfiltrate the
    credential (a fail-open hole), so this is checked at config load/reload/start alongside the data
    host. Shared by the FHIR/REST **outbound** and the **FhirLookup** read arm so the two never drift
    out of lockstep — DELTA-04 was exactly that drift (the read arm gated only ``url``). An unset key
    is a no-op. Call only when ``allowed_http`` is non-empty (matching the host gate's own guard)."""
    for key, what in _CREDENTIAL_EGRESS_URL_KEYS:
        token_url = str(settings.get(key, "") or "")
        if token_url and not _http_egress_allowed(token_url, allowed_http):
            host = urllib.parse.urlsplit(token_url).hostname or ""
            log.warning(
                "egress denied: %s %s host %r not in [egress].allowed_http",
                label,
                what,
                host,
            )
            raise WiringError(
                f"{label}: {what} host {host!r} is not in the [egress].allowed_http allowlist"
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
        # Every credential-bearing token endpoint is a SECOND egress host on this read arm — gate
        # each with the same allowlist as the FHIR outbound, or a crafted smart_token_url (set via
        # with_smart_backend()) exfiltrates the signed client_assertion, and a crafted
        # oauth2_token_url exfiltrates client_id + client_secret, to an unlisted host (DELTA-04).
        _check_credential_token_url_egress(f"FhirLookup {name!r}", settings, egress.allowed_http)


_LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "::1", "::ffff:127.0.0.1"})


def _inbound_insecure_bind_permitted(
    *, allow_insecure_bind: bool, attested: bool, posture: HopPosture | None
) -> bool:
    """Whether an off-loopback, cleartext inbound listener may bind (warn-and-cross) rather than being
    REFUSED (#200, ADR 0092). Consumed by the four exposed-gate checks past their loopback / TLS-on
    early returns.

    STRICT by default (decision 5 — the shipped exposed-gate refuses every off-loopback cleartext bind
    regardless of environment): a bind is permitted only by a per-connection ``tls_hop_attested`` (the
    segment is secure by other means), or by ``--allow-insecure-bind`` — and that flag is **CLAMPED to
    a non production-PHI instance** (decision 2), exactly mirroring the global TLS escape. So a
    production-PHI listener **refuses cleartext even WITH** ``--allow-insecure-bind``.

    An **unstamped** posture (``None``) means the check ran outside the ENFORCED gate — the serve /
    reload path that stamps the derived posture always passes a real one, so ``None`` is a direct /
    embedding call, where the shipped exposed-gate warn is preserved (the flag is honored). The clamp is
    an ADD at the enforced surface, never a new refusal for an un-postured call. Adds coverage (the
    prod-PHI clamp + the attestation opt-in); never loosens the shipped no-flag refusal."""
    if attested:
        return True
    if not allow_insecure_bind:
        return False
    if posture is None:
        return True  # un-postured (direct/embedding) call: preserve the shipped warn (see above)
    return not (posture.enforcing and posture.is_phi)


def _inbound_revocation_gap_permitted(*, attested: bool, posture: HopPosture | None) -> bool:
    """Whether a VERIFYING inbound mTLS listener that checks NO revocation may bind (warn-and-cross)
    rather than being REFUSED (BACKLOG #1005). The revocation sibling of
    :func:`_inbound_insecure_bind_permitted`, and deliberately the same three rungs in the same order.

    A per-connection ``tls_revocation_attested`` permits it -- the operator declaring that a
    revocation-checking PKI covers these certificates outside the engine, exactly as the outbound
    ``Destination.tls_revocation_attested`` does for a verified outbound hop.

    An **unstamped** posture (``None``) permits it, for the same reason the sibling does: the check
    ran outside the ENFORCED gate, so this is a direct / embedding call and must never acquire a new
    refusal there. Otherwise it is refused only on an instance that is BOTH enforcing AND PHI --
    every other instance warns and crosses.

    There is deliberately NO blunt process-wide escape here. ``MEFOR_ALLOW_INSECURE_TLS`` governs
    weakened TLS, and a listener that verifies its peers correctly but does not check revocation is
    not a weakened-TLS hop; reusing that escape would let one env var silence a control it was never
    scoped to."""
    if attested:
        return True
    if posture is None:
        return True  # un-postured (direct/embedding) call: never a new refusal (see above)
    return not (posture.enforcing and posture.is_phi)


def check_inbound_revocation(
    source: Source, name: str, *, posture: HopPosture | None = None
) -> None:
    """Exposed-gate sibling (BACKLOG #1005, ASVS 12.1.4 band B1): refuse an mTLS listener that
    verifies client certificates but checks NO revocation, on an enforcing production-PHI instance.

    **Measured on this tree**: the three server builders load a CA, set ``CERT_REQUIRED`` and finish
    with ``harden_verify_flags`` -- strict RFC 5280 path validation, NOT revocation -- so a client
    certificate revoked this morning keeps authenticating until its ``notAfter``. Set
    ``tls_crl_file`` on the connection (a PEM carrying the CA and its CRL), or declare
    ``tls_revocation_attested=true`` if your PKI checks revocation outside the engine.

    **Why this refusal cannot be delegated away for two of the three listeners.**
    ``harden_verify_flags``' own docstring delegates live revocation to the deploying org -- OCSP
    must-staple at a proxy plus the OS trust store. That is credible for the API/UI surface. **An
    HTTP proxy can terminate neither MLLP framing nor DIMSE**, so for those two the named delegation
    does not reach and no workaround remains.

    Applies only where an mTLS listener exists: MLLP (which also serves the inbound HTTP listener),
    HTTP and DIMSE. Raw TCP/X12 have no TLS option at all, so they cannot have a client certificate
    to revoke."""
    if source.type not in (ConnectorType.MLLP, ConnectorType.HTTP, ConnectorType.DIMSE):
        return
    settings = source.settings
    # No mTLS means no client certificate is requested, so there is nothing whose revocation could
    # matter -- the same composition rule the outbound verify-off arm states.
    if not settings.get("tls") or not settings.get("tls_ca_file"):
        return
    if settings.get("tls_crl_file"):
        return
    if _inbound_revocation_gap_permitted(attested=source.tls_revocation_attested, posture=posture):
        log.warning(
            "inbound %r requires and verifies a client certificate (mTLS) but checks NO revocation: "
            "a revoked partner certificate would keep authenticating until its notAfter. Set "
            "tls_crl_file on the connection, or tls_revocation_attested=true if your PKI checks "
            "revocation outside the engine.",
            name,
        )
        return
    raise WiringError(
        f"inbound connection {name!r} requires and verifies a client certificate (mTLS) but checks "
        "no revocation, on an enforcing production-PHI instance; a partner certificate revoked "
        "today would keep authenticating to this interface until its notAfter. Set tls_crl_file "
        "(a PEM carrying the CA and its CRL) on the connection, or set "
        "tls_revocation_attested=true if a revocation-checking PKI covers these certificates "
        "outside the engine. An HTTP proxy can terminate neither MLLP nor DIMSE, so for those "
        "listeners the documented out-of-engine delegation does not reach."
    )


def check_mllp_tls_exposure(
    source: Source, name: str, *, allow_insecure_bind: bool, posture: HopPosture | None = None
) -> None:
    """Exposed-gate (ADR 0002 §0, MLLP side): refuse a **non-loopback MLLP listener without TLS** — it
    would put HL7 bodies on the wire in cleartext. Set ``tls=true`` (+ cert) on the connection, or pass
    ``serve --allow-insecure-bind`` to accept the risk on a trusted segment (then warn). Loopback binds
    and TLS-on binds pass unconditionally. MLLP only (raw-TCP/X12 TLS is out of ADR-0002 scope)."""
    if source.type is not ConnectorType.MLLP:
        return
    host = str(source.settings.get("host", "127.0.0.1"))
    if host in _LOOPBACK_HOSTS or source.settings.get("tls"):
        return
    if _inbound_insecure_bind_permitted(
        allow_insecure_bind=allow_insecure_bind, attested=source.tls_hop_attested, posture=posture
    ):
        log.warning(
            "inbound %r binds non-loopback host %r without TLS "
            "(--allow-insecure-bind / tls_hop_attested); HL7 bodies cross the network in cleartext — "
            "set tls=true (+ tls_cert_file/tls_key_file) on it.",
            name,
            host,
        )
        return
    raise WiringError(
        f"inbound connection {name!r} binds non-loopback host {host!r} without TLS; HL7 bodies would "
        "cross the network in cleartext. Set tls=true (+ tls_cert_file/tls_key_file) on the MLLP "
        "connection, or pass `serve --allow-insecure-bind` to accept the cleartext risk on a trusted, "
        "firewalled network (refused even with the flag on a production-PHI instance — set "
        "tls_hop_attested=true if the segment is secured by other means)."
    )


def check_http_tls_exposure(
    source: Source, name: str, *, allow_insecure_bind: bool, posture: HopPosture | None = None
) -> None:
    """Exposed-gate (ADR 0002 §0 / ADR 0023 §D4, HTTP side): refuse a **non-loopback inbound HTTP
    listener without TLS** — it would put POSTed bodies (frequently PHI: HL7-over-HTTP, FHIR, X12) on the
    wire in cleartext. The HTTP sibling of :func:`check_mllp_tls_exposure`. Like MLLP/DICOM the HTTP
    source *does* support TLS, so the escape hatch is ``tls=true`` (+ cert) on the ``Http(...)``
    connection; otherwise bind loopback or pass ``serve --allow-insecure-bind`` to accept the risk on a
    trusted segment (then warn). ``--allow-insecure-bind`` is CLAMPED (#200): a production-PHI listener
    refuses cleartext even with it (``posture``-keyed via :func:`_inbound_insecure_bind_permitted`).
    Loopback binds and TLS-on binds pass unconditionally."""
    if source.type is not ConnectorType.HTTP:
        return
    host = str(source.settings.get("host", "127.0.0.1"))
    if host in _LOOPBACK_HOSTS or source.settings.get("tls"):
        return
    if _inbound_insecure_bind_permitted(
        allow_insecure_bind=allow_insecure_bind, attested=source.tls_hop_attested, posture=posture
    ):
        log.warning(
            "inbound %r binds non-loopback host %r for an HTTP listener without TLS "
            "(--allow-insecure-bind / tls_hop_attested); POSTed bodies (frequently PHI) cross the "
            "network in cleartext — set tls=true (+ tls_cert_file/tls_key_file) on the Http connection.",
            name,
            host,
        )
        return
    raise WiringError(
        f"inbound connection {name!r} binds non-loopback host {host!r} without TLS; POSTed bodies "
        "(frequently PHI) would cross the network in cleartext. Set tls=true (+ tls_cert_file/"
        "tls_key_file) on the Http connection, or pass `serve --allow-insecure-bind` to accept the "
        "cleartext risk on a trusted, firewalled network (refused even with the flag on a "
        "production-PHI instance — set tls_hop_attested=true if the segment is secured by other means)."
    )


#: Minimum prefix length an entry of ``source_ip_allowlist`` must carry before it counts as an
#: effective peer control (ADR 0154 D7). Generous on purpose — ``/8`` admits ``10.0.0.0/8``, a
#: legitimate private scope — but it excludes ``0.0.0.0/0`` and ``::/0``, which allow-list the entire
#: internet while reading, in a config file, exactly like a restriction.
_INTAKE_ALLOWLIST_MIN_PREFIX_V4 = 8
_INTAKE_ALLOWLIST_MIN_PREFIX_V6 = 32


def _has_effective_peer_control(settings: Mapping[str, Any]) -> bool:
    """Whether this HTTP listener actually requires a peer to be someone in particular.

    **Strength-based, not presence-based.** Each of the obvious presence tests has a trivially
    worthless satisfying instance: ``source_ip_allowlist = ["0.0.0.0/0"]`` parses fine and restricts
    nobody, and ``tls`` + ``tls_ca_file`` means *"any certificate this CA ever signed"* — no subject
    binding at all. A gate satisfied by controls that authenticate nobody is theatre, so a
    configuration that fails this test is treated exactly as one with no control, and is not given a
    softer landing for having a control that does not work.
    """
    mode = str(settings.get("intake_auth") or "none")
    if mode in ("api_key", "bearer"):
        return bool(settings.get("intake_api_key"))
    if mode == "mtls_subject":
        # The subject list is what tls_ca_file alone does not give you.
        return bool(settings.get("tls_ca_file")) and bool(settings.get("intake_client_subjects"))

    allowlist = settings.get("source_ip_allowlist")
    if not allowlist:
        return False
    for entry in allowlist:
        try:
            net = ipaddress.ip_network(str(entry), strict=False)
        except ValueError:
            return False  # unparseable: cannot be shown to restrict anyone, so it does not count
        floor = (
            _INTAKE_ALLOWLIST_MIN_PREFIX_V4 if net.version == 4 else _INTAKE_ALLOWLIST_MIN_PREFIX_V6
        )
        if net.prefixlen < floor:
            return False  # ONE too-wide entry defeats the whole list
    return True


def check_http_sync_reply(
    ic: InboundConnection,
    registry: Registry,
    *,
    delivery: DeliverySettings | None = None,
) -> None:
    """Cross-registry refusals for a ``reply_from`` inbound (ADR 0154 D4).

    These are the facts one ``Http()`` call cannot know, because they are about the *other*
    connection. Runs with no store, so it fires at ``messagefoundry check`` and in dry-run exactly as
    at serve.

    The ``ordering``/``max_attempts`` pair is the subtle one, and both are refusals rather than
    warnings because together they make the feature's headline use case unserviceable. ``ordering``
    resolves to **FIFO**, which drains one message at a time and blocks the head on failure — so N
    concurrent HTTP callers do not get N concurrent downstream calls; they serialise behind a single
    lane bounded by one partner round-trip, and one transiently-failing head message holds that lane
    until an operator purges it, timing out **every** concurrent and subsequent caller.
    ``max_attempts`` resolves to retry-forever, which is not merely incoherent with "the caller gave
    up 30 seconds ago" — it is a total outage with a config-shaped cause.

    **Both are read as EFFECTIVE values, never declared ones.** ``OutboundConnection.ordering``
    defaults to ``None`` meaning *inherit*, and ``retry`` defaults to no ``RetryPolicy`` object at
    all; resolution against ``[delivery]`` happens in the runner. A literal ``ordering == FIFO`` test
    would therefore pass cleanly for the overwhelmingly common shape — the exact shape this refusal
    exists to catch. When ``delivery`` is not supplied the caller could not resolve them either, so
    that arm is **skipped rather than guessed**; the runner re-checks at start, where the resolved
    values always exist.
    """
    settings = ic.spec.settings
    reply_from = settings.get("reply_from")
    if not reply_from:
        return
    name, target = ic.name, str(reply_from)

    oc = registry.outbound.get(target)
    if oc is None:
        raise WiringError(
            f"inbound connection {name!r}: reply_from names unknown outbound {target!r} — a "
            "synchronous reply can only come from an outbound declared in this graph"
        )
    if not oc.deployed:
        raise WiringError(
            f"inbound connection {name!r}: reply_from names {target!r}, which is declared "
            "deployed=False — it will never run, so every HTTP turn could only time out"
        )
    if not oc.spec.settings.get("capture_response"):
        raise WiringError(
            f"inbound connection {name!r}: reply_from names {target!r}, which does not set "
            "capture_response=True — with no captured reply there is nothing to return, and every "
            "call would block until reply_timeout"
        )

    # apply_sync_reply_capture_implication has already added content-type for any factory that HAS
    # the allow-list. One that does not cannot echo a content type at all, so refuse here rather than
    # let it surface as an AttributeError deep in the capture path.
    if (
        settings.get("reply_content_type") == "passthrough"
        and "capture_response_headers" not in oc.spec.settings
    ):
        raise WiringError(
            f"inbound connection {name!r}: reply_content_type='passthrough' needs {target!r} to "
            "capture the partner's content-type, but that connector has no "
            "capture_response_headers setting — pin a literal MIME type on reply_content_type "
            "instead"
        )

    if ic.ack_after is AckAfter.DELIVERED:
        raise WiringError(
            f"inbound connection {name!r}: reply_from cannot be combined with ack_after='delivered' "
            "— the HTTP turn already blocks on the downstream reply, so deferring the receipt too "
            "would mean waiting for the same delivery twice"
        )

    if delivery is None:
        return  # the caller could not resolve [delivery]; the runner re-checks at start

    if (oc.ordering or delivery.ordering) is OrderingMode.FIFO:
        declared = oc.ordering.value if oc.ordering else "unset, inheriting [delivery].ordering"
        raise WiringError(
            f"inbound connection {name!r}: reply_from names {target!r}, whose EFFECTIVE ordering is "
            f"FIFO (declared: {declared}). A FIFO lane drains one message at a time and blocks the "
            "head on failure, so concurrent HTTP callers serialise behind a single partner "
            "round-trip and one stuck message times out every caller — set ordering=UNORDERED on "
            "that outbound"
        )

    effective_attempts = (
        oc.retry.max_attempts if oc.retry is not None else delivery.retry_max_attempts
    )
    if effective_attempts is None:
        declared = (
            "no retry policy, inheriting [delivery].retry_max_attempts"
            if oc.retry is None
            else "max_attempts=None"
        )
        raise WiringError(
            f"inbound connection {name!r}: reply_from names {target!r}, whose EFFECTIVE max_attempts "
            f"is unset — retry forever (declared: {declared}). Retrying forever is incoherent with a "
            "caller that gave up seconds ago; set a finite max_attempts so a failed delivery "
            "dead-letters instead of holding the lane"
        )


def check_http_intake_auth(source: Source, name: str, *, posture: HopPosture | None = None) -> None:
    """Peer-control gate (ADR 0154 D7): refuse an **off-loopback HTTP listener with no effective peer
    control** — no sufficiently narrow ``source_ip_allowlist``, no ``intake_auth``, and no
    ``mtls_subject`` binding. Refuses under an enforcing PHI posture, warns otherwise.

    **A separate function, never folded into :func:`check_http_tls_exposure`.** That gate returns early
    the moment ``tls`` is truthy — precisely the case an authentication requirement most needs to
    cover. ``Http(port=..., tls=True, tls_cert_file=...)`` on ``0.0.0.0`` therefore binds a PHI intake
    socket today with no peer identity requirement at all, and passes every gate.

    **The composition rule, stated once: TLS is confidentiality; intake auth is authentication.**
    Enabling auth is never an argument for relaxing the exposed gate, and TLS being on is never a
    reason to skip auth. ``check_http_tls_exposure`` is unchanged and unweakened by this.

    **It ignores ``allow_insecure_bind`` entirely** — note the deliberate signature divergence from its
    four siblings. Handing a *cleartext* escape hatch the power to also waive *authentication* is a
    category error, so this gate is posture-keyed only. ``posture is None`` (a direct or embedding
    call) warns rather than refusing: a new refusal must not start firing for un-postured callers.

    A raise is a :class:`WiringError`, so ADR 0031 degrades that one connection rather than the engine.
    Loopback binds start byte-identical (ADR 0148 GIVEN 1).
    """
    if source.type is not ConnectorType.HTTP:
        return
    host = str(source.settings.get("host", "127.0.0.1"))
    # CIDR-aware, and it treats an empty host as loopback — which matches HttpSource's own
    # `s.get("host") or "127.0.0.1"` fallback. Reused rather than minting another _LOOPBACK_HOSTS
    # frozenset; the tree already carries five same-named copies across two distinct contents.
    if is_loopback_hop_host(host):
        return
    if _has_effective_peer_control(source.settings):
        return

    detail = (
        f"inbound connection {name!r} binds non-loopback host {host!r} with no effective peer "
        "control: anyone who can reach the socket can submit a message. Set intake_auth "
        "(api_key/bearer with intake_api_key, or mtls_subject with tls_ca_file + "
        "intake_client_subjects), or narrow source_ip_allowlist so every entry is at least a "
        f"/{_INTAKE_ALLOWLIST_MIN_PREFIX_V4} (IPv4) or /{_INTAKE_ALLOWLIST_MIN_PREFIX_V6} (IPv6). "
        "Note that tls + tls_ca_file alone does NOT satisfy this: it accepts any certificate that CA "
        "ever signed, which binds no subject. TLS is confidentiality; this gate is authentication."
    )
    if posture is not None and posture.enforcing and posture.is_phi:
        raise WiringError(detail)
    log.warning("%s (warned, not refused: this instance is not an enforcing PHI posture)", detail)


def check_dimse_tls_exposure(
    source: Source, name: str, *, allow_insecure_bind: bool, posture: HopPosture | None = None
) -> None:
    """Exposed-gate (ADR 0025 §9, DIMSE side): refuse a **non-loopback DICOM C-STORE SCP without TLS** —
    it would put DICOM header + pixel-data PHI on the wire in cleartext. The DIMSE sibling of
    :func:`check_mllp_tls_exposure` (the shipped guard is MLLP-only; TCP/X12/DIMSE listeners were not
    covered, so this is **net-new** security work, not a fold-in). Set ``tls=true`` (+ cert) on the
    ``DICOM(...)`` connection, or pass ``serve --allow-insecure-bind`` to accept the risk on a trusted
    segment (then warn). ``--allow-insecure-bind`` is CLAMPED (#200): a production-PHI listener refuses
    cleartext even with it (``posture``-keyed). Loopback binds and TLS-on binds pass unconditionally."""
    if source.type is not ConnectorType.DIMSE:
        return
    host = str(source.settings.get("host", "127.0.0.1"))
    if host in _LOOPBACK_HOSTS or source.settings.get("tls"):
        return
    if _inbound_insecure_bind_permitted(
        allow_insecure_bind=allow_insecure_bind, attested=source.tls_hop_attested, posture=posture
    ):
        log.warning(
            "inbound %r binds non-loopback host %r without DICOM-over-TLS "
            "(--allow-insecure-bind / tls_hop_attested); DICOM PHI (header + pixel data) crosses the "
            "network in cleartext — set tls=true (+ tls_cert_file/tls_key_file) on the DICOM connection.",
            name,
            host,
        )
        return
    raise WiringError(
        f"inbound connection {name!r} binds non-loopback host {host!r} without TLS; DICOM PHI (header "
        "+ pixel data) would cross the network in cleartext. Set tls=true (+ tls_cert_file/"
        "tls_key_file) on the DICOM connection, or pass `serve --allow-insecure-bind` to accept the "
        "cleartext risk on a trusted, firewalled network (refused even with the flag on a "
        "production-PHI instance — set tls_hop_attested=true if the segment is secured by other means)."
    )


def check_tcp_tls_exposure(
    source: Source, name: str, *, allow_insecure_bind: bool, posture: HopPosture | None = None
) -> None:
    """Exposed-gate (ADR 0002 §0, raw-TCP/X12 side): refuse a **non-loopback raw-TCP or X12 listener**
    on a cleartext bind — it would put raw-TCP/X12 payloads (frequently PHI: X12 270/271 eligibility,
    raw/FHIR bodies) on the wire in plaintext. The TCP/X12 sibling of :func:`check_mllp_tls_exposure`
    and :func:`check_dimse_tls_exposure`, generalizing the exposed-gate to the remaining cleartext-only
    LISTEN types. Unlike MLLP/DICOM these connectors are **plaintext-only** — they have **no** ``tls=``
    option (``asyncio.start_server`` is called with no ``ssl=`` arg), so there is no TLS escape hatch:
    the only ways forward are a loopback bind, OS-level firewall/segmentation, or
    ``serve --allow-insecure-bind`` to accept the cleartext risk (then warn). ``--allow-insecure-bind``
    is CLAMPED (#200): a production-PHI listener refuses cleartext even with it (``posture``-keyed).
    Loopback binds pass unconditionally; the guard no-ops for any non-TCP/X12 type."""
    if source.type not in (ConnectorType.TCP, ConnectorType.X12):
        return
    host = str(source.settings.get("host", "127.0.0.1"))
    if host in _LOOPBACK_HOSTS:
        return
    if _inbound_insecure_bind_permitted(
        allow_insecure_bind=allow_insecure_bind, attested=source.tls_hop_attested, posture=posture
    ):
        log.warning(
            "inbound %r binds non-loopback host %r for a plaintext-only %s listener "
            "(--allow-insecure-bind / tls_hop_attested); X12/raw-TCP payloads (frequently PHI) cross "
            "the network in cleartext — these listeners have no TLS, so firewall/segment them.",
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
        "the cleartext risk on a trusted, firewalled network (refused even with the flag on a "
        "production-PHI instance — set tls_hop_attested=true if the segment is secured by other means)."
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
        # Credential-bearing token endpoints are SECOND egress hosts — the connector POSTs the signed
        # client_assertion (ADR 0024) or client_id + client_secret (ADR 0126) there — so gate each
        # with the same allowlist. Shared helper, so the FhirLookup read arm in
        # check_fhir_lookup_allowed stays in lockstep (DELTA-04).
        _check_credential_token_url_egress(
            f"outbound {dest.name!r}", dest.settings, egress.allowed_http
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
    elif dest.type is ConnectorType.DIRECT and egress.allowed_direct:
        # Direct S/MIME-over-SMTP (ADR 0085): the HISP relay host is gated with the same host[:port]
        # matching as EMAIL/MLLP, but against its own [egress].allowed_direct list so a Direct relay is
        # permitted independently of generic SMTP egress.
        host = str(dest.settings.get("host", ""))
        port = dest.settings.get("port", 587)
        if not _mllp_egress_allowed(host, port, egress.allowed_direct):  # same host[:port] matching
            log.warning(
                "egress denied: outbound %r DIRECT host %r not in [egress].allowed_direct",
                dest.name,
                host,
            )
            raise WiringError(
                f"outbound {dest.name!r}: DIRECT host {host!r} is not in the "
                "[egress].allowed_direct allowlist"
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
