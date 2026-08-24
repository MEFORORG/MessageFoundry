# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Backend-agnostic store interface + construction seam.

The engine and API depend on the store **protocols**, not on a concrete backend, so adding a new
backend (SQL Server, Postgres, …) only means implementing these methods and registering it in
:func:`open_store`. Today the sole backend is the SQLite :class:`~messagefoundry.store.store.MessageStore`.

The contract is **segregated by concern** so each consumer depends only on the slice it uses
(interface segregation — see docs/ARCHITECTURE.md §"Architectural standard"):

* :class:`QueueStore` — the message inbox/outbox lifecycle + reads + store health. The engine,
  the :class:`~messagefoundry.pipeline.wiring_runner.RegistryRunner`, and the message routes use this.
* :class:`AuditStore` — the audit log + PHI-view trail.
* :class:`AuthStore` — users, roles, sessions, AD-group maps. Only :class:`AuthService` uses this,
  and it can no longer reach the queue/message methods.
* :class:`Store` — the composite a backend implements and :func:`open_store` returns.

Read methods return :class:`Row` — a minimal protocol (key access + ``keys()``) satisfied by both
``aiosqlite.Row`` and a plain ``dict``, so a non-SQLite backend can return its own row mapping without
the callers caring.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import AsyncIterator, Collection, Iterable, Mapping, Sequence
from functools import partial
from pathlib import Path
from typing import Any, Protocol, runtime_checkable

from messagefoundry.config.models import RetryPolicy
from messagefoundry.config.settings import SqliteSync, StoreBackend, StoreSettings
from messagefoundry.config.tls_policy import HopPosture
from messagefoundry.store.content_search import (
    DEFAULT_SCAN_LIMIT,
    MAX_SCAN_LIMIT,
    ContentSearchError,
    SearchSpec,
    SearchTarget,
    make_spec,
)
from messagefoundry.store.crypto import Cipher, CipherInfo, make_cipher
from messagefoundry.store.document_strip import StripResult
from messagefoundry.store.keyprovider import resolve_key_provider
from messagefoundry.store.pool_metrics import PoolStatus
from messagefoundry.store.store import (
    UPLOAD_RESERVATION_STALE_AFTER,
    AlertInstance,
    CapturedResponse,
    ClaimedHeads,
    ClaimProcStatus,
    ConnectionEvent,
    ConnectionMetrics,
    DbStatus,
    LatencyHistogram,
    MessageSearchResult,
    MessageStatus,
    MessageStore,
    OutboxItem,
    OwnedLanes,
    ReingressOriginMissing,
    ReingressOutcome,
    ReplyWaitState,
    ResendError,
    ResendKeyConflict,
    ResendOutcome,
    ResendSourceAmbiguous,
    ResendSourceEmpty,
    ResendSourceNotFound,
    SessionRecord,
    Stage,
    StreamingAttachmentsUnsupported,
    UserRecord,
    WebAuthnCredential,
)

log = logging.getLogger(__name__)

__all__ = [
    "AdminStore",
    "AuditStore",
    "AuthStore",
    "ContentSearchError",
    "DbaDelegatedError",
    "DEFAULT_SCAN_LIMIT",
    "MAX_SCAN_LIMIT",
    "MessageSearchResult",
    "OwnedLanes",
    "PoolStatus",
    "QueueStore",
    "ReingressOriginMissing",
    "ReingressOutcome",
    "ResendError",
    "ResendKeyConflict",
    "ResendOutcome",
    "ResendSourceAmbiguous",
    "ResendSourceEmpty",
    "ResendSourceNotFound",
    "Row",
    "SearchSpec",
    "SearchTarget",
    "Store",
    "StoreLifecycle",
    "StreamingAttachmentsUnsupported",
    "backend_supports_reference_sets",
    "make_spec",
    "open_store",
    "sqlite_settings",
    "warm_pool_connections",
    "warm_pool_target",
    "pool_over_provisioned_warning",
    "POOL_SIZE_OPTIMUM",
    "POOL_SIZE_CLIFF",
    "UPLOAD_RESERVATION_STALE_AFTER",
]


class DbaDelegatedError(RuntimeError):
    """A store operation that is **DBA-delegated** for the server-DB backends (BACKLOG #52) was invoked
    on a ``postgres``/``sqlserver`` store — today only :meth:`Store.snapshot_to` (ADR 0049 DR backup).
    DB-tier backup / restore / PITR on those backends is owned by infra (``pg_dump`` / Always On), not
    reimplemented in the engine, so the snapshot raises this rather than producing a half-baked copy. The
    BackupRunner / ``backup`` CLI catch it and fall back to a config-only backup (or skip) per
    ``[backup].config_only_on_server_db``."""


class Row(Protocol):
    """A read result: key access + ``keys()`` (satisfied by ``aiosqlite.Row`` and ``dict``)."""

    def __getitem__(self, key: str) -> Any: ...
    def keys(self) -> Iterable[str]: ...


class StoreLifecycle(Protocol):
    """Open-store handle basics shared by every backend."""

    path: str

    #: Which configured backend this handle is (``StoreSettings.backend``). Self-describing so a
    #: capability gate (e.g. the PT allow-list in ``Engine.start``) can name the backend in its error
    #: without re-threading ``StoreSettings`` through the engine.
    backend: StoreBackend

    async def close(self) -> None: ...

    async def snapshot_to(self, dest_path: str | Path, *, method: str = "vacuum_into") -> None:
        """Produce a **consistent single-file snapshot** of the store at ``dest_path`` (ADR 0049 DR
        backup) — never a raw file copy under WAL. **SQLite only**: on the server-DB backends
        (postgres/sqlserver) this raises :class:`DbaDelegatedError` (DB-tier backup is DBA-delegated,
        #52). ``method`` is ``"vacuum_into"`` (default — ``VACUUM INTO`` on the writer connection under
        the store lock, mandatory off-peak) or ``"online_backup"`` (the page-batched SQLite Online Backup
        API, low-contention).

        The snapshot is **point-in-time consistent and non-mutating**: it first checkpoints the WAL, then
        copies the DB **as it is** — it never claims, mutates, resets, completes, or dead-letters a
        staged-queue row, and never touches the leader lease or audit chain (the reliability +
        count-and-log invariants hold; on restore, the startup ``reset_stale_inflight`` + pure-stage
        replay recover any in-flight rows). Runs OFF the event loop (a worker thread), like the store's
        other long PRAGMA work, so it never blocks asyncio. The resulting file has no ``-wal``/``-shm``
        sidecars to reconcile."""
        ...


class QueueStore(StoreLifecycle, Protocol):
    """The durable message inbox/outbox queue — the contract the engine + message routes use.

    Covers the transactional write path, the per-destination delivery worker, recovery/replay, the
    read helpers the API/console render, and store-health/metrics. Deliberately excludes auth and the
    audit log so a queue consumer cannot reach them.
    """

    #: Whether this backend implements the staged ingress pipeline (``enqueue_ingress``/``handoff``).
    #: ``False`` backends are rejected at engine start rather than trapping the first received message in
    #: a ``NotImplementedError``. Today SQLite, Postgres, and SQL Server all set this ``True`` (each ships
    #: the full staged pipeline); the flag guards a future staging-incapable backend.
    supports_ingest_stage: bool

    #: Whether this backend can capture request/response replies (ADR 0013: the ``response`` table +
    #: :meth:`complete_with_response`). ``True`` on SQLite/Postgres/SQL Server; a backend returning
    #: ``False`` makes the runner reject a capturing outbound at start (fail-closed) rather than drop
    #: captures.
    supports_response_capture: bool

    #: Whether this backend implements pass-through (PT) re-ingress — the ``pt_deliveries`` branch of
    #: :meth:`transform_handoff` (ConnectorType.PT, ADR 0013 generalized). **Allow-list semantics:**
    #: ``False`` by default (this base + any future backend), but SQLite, Postgres, and SQL Server ALL
    #: set it ``True`` today — each ships the ``pt_deliveries`` branch. A future backend that has not
    #: implemented that branch leaves the base default and has its graph rejected at startup: the engine
    #: rejects a graph containing a PT inbound on any ``False`` backend (see :meth:`Engine.start`), so a
    #: Handler ``Send`` into a PT connector can never reach the unimplemented ``transform_handoff``
    #: branch at runtime.
    supports_pt_reingress: bool = False

    #: Whether this backend ships the synchronous fused-handoff twins (``route_handoff_sync`` /
    #: ``transform_handoff_sync`` + a dedicated synchronous connection source) that let a fused worker-
    #: thread hop collapse a multi-statement handoff into ONE executor completion (ADR 0071 B5). The
    #: profiled wall is aioodbc's per-statement thread crossing, so this is ``True`` **only** on the
    #: SQL Server backend; Postgres (asyncpg is loop-native — nothing to fuse) and SQLite (its handoff
    #: lock is loop-affine) keep the async path by construction and leave this ``False``. A future
    #: fused-hop dispatcher gates on this flag before taking the sync path.
    supports_fused_sync_handoff: bool = False

    #: Whether this backend ships the streaming-attachment substrate (#149, ADR 0105): the
    #: ``attachment`` + ``attachment_chunk`` + ``message_attachment`` tables and :meth:`put_attachment` /
    #: :meth:`read_attachment` / :meth:`attachments_for` / :meth:`attachment_incref` /
    #: :meth:`attachment_decref` / :meth:`sweep_orphan_attachments`. ``True`` on SQLite, Postgres, and
    #: SQL Server (all three ship the substrate after Phase 4); a backend that leaves it ``False`` has its
    #: streaming ops raise :class:`~messagefoundry.store.store.StreamingAttachmentsUnsupported`, so a
    #: streaming connection targeting it fails clearly rather than silently degrading.
    supports_streaming_attachments: bool = False

    #: Whether this backend implements the ADR 0006 reference-set snapshot store: the ``reference`` +
    #: ``reference_version`` tables behind :meth:`reference_view` / :meth:`write_reference_snapshot` /
    #: :meth:`converge_reference_cache`. **Allow-list semantics** like :attr:`supports_pt_reingress`:
    #: ``False`` by default (this base + any future backend), ``True`` on all three shipped backends —
    #: SQLite (the reference implementation), Postgres (ported), and SQL Server (ported at parity,
    #: BACKLOG #235). A graph declaring at least one ``Reference(...)`` is REFUSED fail-closed on a
    #: ``False`` backend at ``messagefoundry check``, at engine start, and on reload/promote, so a
    #: Handler's ``reference(...)`` read can never raise per-message — post-ACK, forever — on a backend
    #: that could never materialize the set.
    supports_reference_sets: bool = False

    #: A1 live cost counters (always-on, additive; surfaced via ``/stats``). ``committed_txns`` = durable
    #: **write**-path transactions committed on this handle — the *committed transactions per message*
    #: currency ADR 0051 sizes capacity on (``3 + 2H + 2N`` per ingress message, H = handlers routed,
    #: N = destinations). Read-snapshot-release commits (e.g. the RCSI hygiene commit a SQL Server read
    #: needs, or SQLite's read-pool ``COMMIT``) are excluded, so the counter stays the write currency the
    #: cost model validates rather than a superset that also counts every live lookup.
    #: ``body_copies`` = raw/payload body strings durably written (the ``2 + H + N`` per-message
    #: amplification), counted store-once-aware where a backend dedups an identical fan-out body. Both
    #: start at 0 and only grow; incrementing them is a bare int add at the existing commit / body-write
    #: sites (no new lock, no commit-boundary change). Fully wired on SQLite + SQL Server; the Postgres
    #: handle exposes them at 0 for protocol / ``/stats`` uniformity (its ``async with conn.transaction()``
    #: commit idiom is a separate wiring pass). Consumers read them with ``getattr(store, name, 0)`` so an
    #: older engine without the fields degrades gracefully.
    committed_txns: int
    body_copies: int

    #: ``fenced_writes`` = TERMINAL queue resolves REJECTED by the H1 leader-epoch fence since store open
    #: (ADR 0157 C3). Additive and monotone like the two above, read the same ``getattr(store, name, 0)``
    #: way, and **Postgres-only**: it is the one backend where terminal resolves carry the fence, so the
    #: SQLite and SQL Server handles expose it at a permanent 0 for protocol / ``/stats`` uniformity. A
    #: non-zero value means a superseded ex-leader tried to resolve a row the current leader owns and was
    #: stopped — the split-brain signal an operator actually wants paged on.
    fenced_writes: int

    # --- write path ----------------------------------------------------------
    async def enqueue_message(
        self,
        *,
        channel_id: str,
        raw: str,
        deliveries: Sequence[tuple[str, str]],
        control_id: str | None = None,
        message_type: str | None = None,
        source_type: str | None = None,
        summary: str | None = None,
        metadata: str | None = None,
        now: float | None = None,
    ) -> str: ...

    async def record_received(
        self,
        *,
        channel_id: str,
        raw: str,
        status: MessageStatus,
        error: str | None = None,
        control_id: str | None = None,
        message_type: str | None = None,
        source_type: str | None = None,
        summary: str | None = None,
        metadata: str | None = None,
        now: float | None = None,
    ) -> str: ...

    async def enqueue_ingress(
        self,
        *,
        channel_id: str,
        raw: str,
        control_id: str | None = None,
        message_type: str | None = None,
        source_type: str | None = None,
        summary: str | None = None,
        metadata: str | None = None,
        attachment_refs: Sequence[str] | None = None,
        now: float | None = None,
    ) -> str:
        """Durably persist a freshly-received raw message to the ingress stage (status ``RECEIVED`` +
        one ``stage='ingress'`` queue row) in one transaction — the staged pipeline's ACK-on-receipt
        boundary. The inbound may be ACKed once this returns. Returns the message id.

        ``attachment_refs`` (#149, ADR 0105 Phase 1a) are the content addresses of documents the ingress
        detach lifted into the attachment substrate; each distinct ref is increffed in the SAME
        transaction as the skeleton row (the two-object commit). Only a backend whose
        :attr:`supports_streaming_attachments` is True ever receives a non-empty value."""
        ...

    async def handoff(
        self,
        *,
        ingress_id: str,
        message_id: str,
        channel_id: str,
        deliveries: Sequence[tuple[str, str]],
        disposition: MessageStatus,
        now: float | None = None,
    ) -> bool:
        """Advance a message from ingress to outbound in one transaction (claim→produce→complete):
        consume the in-flight ingress row, insert one outbound row per delivery, set the post-router
        ``disposition`` (``ROUTED``/``FILTERED``/``UNROUTED``). Idempotent against worker restart —
        returns ``False`` (a no-op) if the ingress row was already consumed by a prior run. The Step-A
        combined router+transform primitive; the split pipeline uses :meth:`route_handoff` +
        :meth:`transform_handoff` instead.

        **LIVE for the ADR 0057 inline fast-path** (re-activated under ADR 0001 Step B for eligible
        single-handler, all-deliver, no-lookup messages). Unlike :meth:`transform_handoff` it does NOT
        run the finalizer, so it **must not be called with empty ``deliveries``** — a zero-delivery
        message would set the disposition but produce no outbound row, leaving it non-terminal forever
        (it would never reach ``FILTERED``). The caller (``_router_worker``) enforces this: a filtering
        handler takes the split path instead (ADR 0057 guardrail G2)."""
        ...

    async def route_handoff(
        self,
        *,
        ingress_id: str,
        message_id: str,
        channel_id: str,
        handlers: Sequence[tuple[str, str]],
        disposition: MessageStatus,
        now: float | None = None,
    ) -> bool:
        """Advance a message from the ingress stage to the **routed** stage in one transaction (the
        router half of the split pipeline, ADR 0001 Step B): consume the in-flight ingress row, insert
        one ``stage='routed'`` row per selected handler (each ``(handler_name, raw_payload)``), set the
        intermediate ``disposition`` (``ROUTED`` with handlers, ``UNROUTED`` with none). Idempotent
        against worker restart — ``False`` if the ingress row was already consumed."""
        ...

    async def transform_handoff(
        self,
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
    ) -> bool:
        """Advance one handler assignment from the **routed** stage to outbound in one transaction (the
        transform half of the split pipeline, ADR 0001 Step B): consume the in-flight routed row,
        insert one outbound row per delivery, **apply each declared state write** (``state_ops``:
        ``(namespace, key, value)`` upserts, ADR 0005), and let the finalizer recompute the terminal
        disposition (this method never writes ``messages.status`` directly). The state writes commit
        atomically with the outbound rows, so a crash before commit leaves no state and a re-run applies
        them exactly-once (preserving the pure-re-run invariant). Idempotent against worker restart —
        ``False`` if the routed row was already consumed.

        ``declined`` (#233, ADR 0111) names the destinations of each ``Send`` the transform addressed
        that is present in the graph but **not deployed** — one entry per declined Send. Each is
        recorded as a per-destination ``not_deployed`` ``message_events`` row **in this same
        transaction**, before the finalizer runs, so it is both the count-and-log record of the skipped
        leg and the persisted signal the finalizer uses to emit ``NOT_DEPLOYED`` (rather than
        ``FILTERED``) for a message whose every delivery was declined. Empty ``declined`` is
        byte-identical to the pre-feature path.

        ``pt_deliveries`` (ADR 0013, generalized) are ``(pass_through_inbound_name, body)`` Sends into an
        internal pass-through inbound: each produces a new INGRESS-stage child message on the PT channel
        **in this same transaction** (re-routed by the PT inbound's own router), bounded by
        ``correlation_depth_cap``. Empty ``pt_deliveries`` is byte-identical to the pre-feature path."""
        ...

    def state_view(self) -> Mapping[tuple[str, str], Any]:
        """A read-only view of the engine-maintained transform-state read-through cache (ADR 0005):
        ``{(namespace, key): decoded_value}``. The runner publishes it around each router/transform run
        so a Handler's synchronous ``state_get(...)`` resolves. Reflects writes as they commit."""
        ...

    # --- reference sets (ADR 0006 Tier 1) ------------------------------------
    def reference_view(self) -> Mapping[str, Mapping[str, Any]]:
        """A read-only view of the active reference snapshots (ADR 0006): ``{name: {key: value}}``. The
        runner publishes it around each router/transform run so ``reference("name").get(key)`` resolves.
        Swaps in a new snapshot only after a sync commits."""
        ...

    async def write_reference_snapshot(
        self, *, name: str, version: str, rows: Mapping[str, Any]
    ) -> None:
        """Materialize a new reference snapshot for ``name`` and atomically make it active (ADR 0006):
        one transaction replaces the set's rows and flips the active version; the read cache swaps only
        after commit, so a failed sync leaves the last-good snapshot live."""
        ...

    async def converge_reference_cache(self) -> list[str]:
        """Refresh this node's in-process reference read cache from the shared store (Track B Step 6).

        The follower read-through: re-loads any set whose authoritative active version (in the shared
        store) is newer than the version currently reflected in this handle's cache, **without**
        re-reading the external source. Returns the names of the sets actually refreshed (``[]`` when
        nothing changed). Multi-node Postgres implements it for real; single-node backends (SQLite,
        SQL Server) return ``[]`` (a single node is the sole writer, so its cache is always current)."""
        ...

    async def converge_state_cache(self) -> list[str]:
        """Refresh this node's in-process transform-STATE read cache from the shared store (Track B
        Step 6b).

        The follower read-through for ADR 0005 state: re-reads any namespace whose per-namespace version
        (in the shared store) is newer than the version currently reflected in this handle's cache, so a
        sibling node's state write reaches every node. Returns the namespace names actually refreshed
        (``[]`` when nothing changed). Multi-node Postgres implements it for real; single-node backends
        (SQLite, SQL Server) return ``[]`` (a single node is the sole writer, so its cache is always
        current)."""
        ...

    def enable_state_convergence(self) -> None:
        """Turn on per-namespace state-version bumping for cross-node convergence (Track B Step 6b). The
        engine calls this only in a cluster (``coordinator.is_clustered()``) BEFORE workers start, so a
        sibling's :meth:`converge_state_cache` sees every write. Single-node never calls it → no version
        writes → byte-identical. A no-op on backends without cross-node convergence (SQLite, SQL Server)."""
        ...

    # --- delivery worker path ------------------------------------------------
    async def claim_ready(
        self,
        limit: int = 10,
        now: float | None = None,
        *,
        stage: str = Stage.OUTBOUND.value,
        channel_id: str | None = None,
        destination_name: str | None = None,
    ) -> list[OutboxItem]: ...

    async def claim_next_fifo(
        self,
        name: str,
        now: float | None = None,
        *,
        stage: str = Stage.OUTBOUND.value,
    ) -> OutboxItem | None:
        """Claim the single oldest *due* pending row for one lane at ``stage`` (strict FIFO; the head
        blocks the lane while it backs off). The lane key is stage-aware: ``destination_name`` for
        outbound, ``channel_id`` for ingress. Per-lane ordering is **seq-only** (ADR 0059): the row's
        monotonic insert counter — SQLite ``rowid``, SQL Server ``BIGINT IDENTITY``, Postgres
        ``BIGSERIAL`` — which the DB assigns in insert-commit order, so with one serial writer per lane it
        IS receive order, with zero wall-clock dependence. ``created_at`` is an ingest-time (ADR 0009) /
        metrics column, no longer an ordering key (and no longer per-lane-clamped). ``None`` when nothing
        is pending or the head isn't due.

        On the Postgres backend (active-passive HA) the claim also reclaims this lane's stranded head —
        a crashed/fenced prior leader's expired-lease ``inflight`` row — in the same transaction before
        the head SELECT, so per-lane FIFO order survives failover. SQLite/SQL Server are single active
        node and have no such residue."""
        ...

    async def claim_next_fifo_batch(
        self, name: str, now: float | None = None, *, stage: str, limit: int
    ) -> list[OutboxItem]:
        """Claim the **contiguous DUE head-prefix** (up to ``limit`` rows) for one lane at ``stage`` in
        ONE commit — the batched cousin of :meth:`claim_next_fifo` (ADR 0058). It takes the ``limit``
        oldest pending rows of the lane in ``seq`` (``rowid`` on SQLite) order — seq-only per-lane FIFO
        (ADR 0059) — **stopping at the first
        not-due (``next_attempt_at > now``) or producer-locked head** (never skipping past it),
        bumping ``attempts+1`` on each claimed row and flipping them to ``inflight`` in the one claim
        commit, then releasing all locks before returning the list.

        Ordered oldest-first; the caller processes the list strictly in that order, one route/transform +
        one separate-commit handoff per row (so a crash mid-batch re-pends only the still-inflight tail,
        recovered in order by :meth:`reset_stale_inflight` — a pure re-run). An empty list is exactly
        :meth:`claim_next_fifo` returning ``None`` (head not due / nothing pending → the lane blocks). A
        not-due/locked head therefore **truncates the prefix**; it is never reached past (strict per-lane
        FIFO, #285). **INGRESS/ROUTED lanes only** — the outbound/delivery claim is never batched (its
        in-claim skip-and-complete dedup must stay atomic), so callers pass an ingress/routed ``stage``.

        Per-backend: SQLite claims under its single-writer lock (no row locks; the lone writer is the
        no-skip guarantee); Postgres uses an inner ``FOR UPDATE`` (no ``SKIP LOCKED`` — a locked head
        blocks) over the lane's oldest pending rows, then an outer window that truncates at the first
        not-due row, after the same-txn stranded-head reclaim; SQL Server uses ``TOP(@limit) WITH
        (UPDLOCK, ROWLOCK)`` (no ``READPAST`` — a locked head blocks) with a contiguous-due-prefix
        cutoff CTE (its ``LOCK_ESCALATION=DISABLE`` + ``ROWLOCK`` + bounded ``limit`` keep it to N row
        locks, no escalation). Default OFF: ``[store].fifo_claim_batch == 1`` means the workers call the
        single claim and this is never invoked."""
        ...

    async def claim_fifo_heads(
        self,
        stage: str,
        lanes: Sequence[str],
        now: float | None = None,
        *,
        per_lane_limit: int = 1,
    ) -> ClaimedHeads:
        """Claim, in ONE transaction, at most the **contiguous DUE head-prefix** (up to
        ``per_lane_limit`` rows) of EACH requested lane at ``stage`` — the pooled-claimer multi-lane
        primitive (ADR 0066 §3). Where the per-lane claims (:meth:`claim_next_fifo` /
        :meth:`claim_next_fifo_batch`) deliberately BLOCK on a producer-locked head, this claim
        **never waits on a row lock** — the mandate's inversion, so a shared claimer connection is
        never pinned in a lock-wait across hundreds of sibling lanes. Those per-lane claims (and
        :meth:`claim_ready`) are **untouched** — ``per_lane`` mode keeps calling them.

        **Probe-then-claim, head-pinned (the #285 inversion, ADR 0066 §3.2).** Per lane: a
        NON-locking snapshot read discovers the min-seq PENDING rows *regardless of due-ness* (never
        "min seq among due", which would skip a backing-off head); the prefix is cut at the first
        not-due row (a not-due HEAD empties the lane — head-of-line blocking preserved, identical to
        the single claim's ``None``); a lock-probe confined to exactly the discovered ID set skips
        (never waits on) locked rows; then only the longest surviving prefix **anchored at the
        discovered head** is claimed. A locked/vanished HEAD therefore yields an **EMPTY lane —
        never ``[N+1, ...]``** (the #285 trap); a mid-prefix gap truncates the kept prefix before it.
        Rows outside the kept prefixes are **never UPDATEd** — their ``attempts`` stay untouched by
        construction (no release step, no G6 inflation under a wedged head). On SQLite the
        process-wide lock totally orders producers and claimers, so the locked-head case is
        unobservable and the lock itself is the no-skip guarantee.

        Returned items carry **post-increment ``attempts``** (the G6 ceiling reads them), seq-
        ascending per lane. The H1 ``epoch_guard`` applies to the probe AND the claim UPDATE, so a
        fenced ex-leader claims 0 rows across all lanes in one shot (fail-closed on a missing lease).

        **OUTBOUND/RESPONSE are hard-1:** ``per_lane_limit`` is clamped to 1 there (H2 atomicity +
        single-outstanding-head retry semantics — exactly as ADR 0058 excludes them from batching).
        The **H2 skip-and-complete** runs per claimed outbound row in the SAME claim transaction,
        code-identical to :meth:`claim_next_fifo`'s: an already-delivered re-pended head is completed
        DONE in place (never returned, never re-sent) and its lane is reported in
        ``ClaimedHeads.rearm`` so the caller re-queues it immediately. Decryption happens after
        commit; an undecryptable row is dead-lettered standalone and dropped, and a lane whose whole
        claimed prefix was consumed (H2/poison) also joins ``rearm``.

        **The lane set is always explicit** (the caller's ready-lane subset, registry-intersected).
        There is deliberately no all-lanes-of-stage claim form: disjoint-inbound sharding runs
        multiple engines against ONE shared store (ADR 0063), so an unscoped claim would steal the
        sibling shard's heads — shard safety is a today requirement. Lanes are de-duplicated
        preserving request order and **clamped to a per-backend chunk** (500 on the server backends,
        200 on SQLite to bound the lock hold); the caller covers the remainder with a second call.
        An empty ``lanes`` returns an empty result without touching the store. On the Postgres
        backend the lane-array stranded-lease reclaim (the multi-lane twin of the single claim's)
        runs FIRST in the same transaction, so failover FIFO is preserved per lane."""
        ...

    async def list_fifo_lanes(
        self,
        stage: str,
        now: float | None = None,
        *,
        limit: int = 4096,
        after: str | None = None,
    ) -> list[tuple[str, float]]:
        """Read-only lane discovery for the pooled dispatcher's clock-driven sweep (ADR 0066 §3.6):
        every lane with >=1 PENDING row at ``stage``, paired with its **HEAD row's** (seq-min pending
        row's) ``next_attempt_at`` — no locks, no writes, O(distinct lanes) index seeks.

        Returning the HEAD's due time (never ``MIN(next_attempt_at)``) is load-bearing: it keeps the
        sweep head-of-line-aware (a lane whose head is backing off reports the head's due time, never
        a due tail row's — no empty-claim churn) and lets the dispatcher arm **exact** retry timers
        for re-pends this runner never performed (H2 re-pend, PG lease reclaim, replay, a sibling
        node's ``mark_failed``). ``limit`` + ``after`` (a resume-strictly-after-lane cursor; lanes
        are returned in ascending lane order) bound pathological universes. Results are store-wide
        at ``stage`` — the caller intersects with its own registry lanes (the shard filter, ADR 0066
        §4.4). ``now`` is accepted for signature parity with the claims; the result does not depend
        on it (due-ness is the caller's judgment against the returned head times)."""
        ...

    async def release_claimed(self, ids: Sequence[str], now: float | None = None) -> None:
        """Return **never-dispatched** INFLIGHT rows to ``pending``, undoing exactly the claim's
        ``attempts`` increment (ADR 0066 §3.1): ``attempts = attempts - 1`` (floored at 0
        defensively), ``next_attempt_at`` **UNCHANGED** (a release is not a failure — no backoff),
        owner/lease cleared, ``updated_at = now``. FIFO-neutral: ``seq`` is never re-minted, so the
        released rows are reconsidered as the lane's head in their original order. The pooled lane
        task calls this on the unprocessed tail when it parks/stops mid-prefix, so tail ``attempts``
        never inflate (rows are never processed out of order and never burn retries they didn't
        use). Rows not currently ``inflight`` (already re-pended / dead / done / unknown ids) are
        left untouched — idempotent. Chunked <=500 ids per statement."""
        ...

    async def reschedule_claimed(
        self, ids: Sequence[str], next_attempt_at: float, now: float | None = None
    ) -> None:
        """Re-pend never-dispatched INFLIGHT rows to ``pending`` with a **durable backoff** — the
        pooled T17 machinery-fault head path (ADR 0070 fix A). Identical to :meth:`release_claimed`'s
        claim-increment undo (``attempts = MAX(attempts - 1, 0)``, ``status`` inflight→pending,
        owner/lease cleared, ``updated_at = now``) but sets ``next_attempt_at`` to the supplied
        **backoff deadline** instead of leaving it unchanged. This is the whole point of fix A: a plain
        release leaves the faulting head **past-due**, so the ~0.25 s sweep re-readies it and a broken
        dependency is re-claimed ~4×/s (an escalation-less spin); a reschedule dates the head into the
        future, so :meth:`list_fifo_lanes` reports it **not-due** and the dispatcher arms an exact
        re-claim timer, collapsing the spin to the backoff cadence. FIFO-neutral (``seq``/rowid is
        never re-minted, so the rescheduled head keeps its position). Guarded ``status='inflight'`` so
        an already-resolved row (dead-lettered / re-pended / done / unknown id) is left untouched —
        idempotent. Never touches the retry/``attempts`` ledger beyond undoing the claim's +1, so the
        G6 poison ceiling is unaffected (a T17 fault is *not* the message's fault). Chunked <=500 ids
        per statement, one commit for the call."""
        ...

    def set_leader_epoch(self, epoch: int | None, *, lease_key: str | None = None) -> None:
        """Push this node's currently-held **leader epoch** (the H1 fencing token) into the store so a
        superseded ex-leader can be fenced **inside** the existing statement's own transaction.

        The engine calls this on **promotion** — and re-stamps it on every leader+running reconcile pass
        (ADR 0157 D2) — reading the value from the cluster coordinator
        (:meth:`ClusterCoordinator.current_epoch` / :meth:`ClusterCoordinator.lease_key`) and pushing it
        here, so the **store never imports the coordinator** (the one-way ARCH-6 dependency direction).

        ``epoch=None`` **OMITS THE GUARD ENTIRELY** — it means *no fence*, not "a safe null token", and
        the emitted SQL is then character-identical to pre-H1. That is why demotion deliberately does
        **not** clear it (ADR 0157 C4): clearing on demotion would disarm the guard at precisely the
        moment a superseded ex-leader is most likely to still be writing.

        With a non-``None`` epoch the server-DB backends splice a ``leader_lease.leader_epoch``
        comparison. Which statements carry it, and with which polarity, differs by backend — see
        :meth:`ClusterCoordinator.current_epoch` for the authoritative scope. It is **not** a general
        write fence.

        Cheap + synchronous (it only stamps cached state — no DB round-trip). A **no-op on SQLite**
        (single active node — no second writer to fence)."""
        ...

    async def warm_pool(self) -> None:
        """Pre-establish pooled connections so a connection-burst — notably the post-promotion delivery
        workers in active-passive HA — does not pay cold connects (TCP + TLS + login) on the hot path.
        It is a **recovery/drain optimization, not intake**: the inbound listener binds before this
        matters, so the engine fires it as a **background task** on graph start/promotion and never
        blocks listener bring-up on it.

        **Best-effort and safe by construction:** it leaves headroom below the pool maximum so a
        concurrent startup caller is never starved while connections are held, never strands a pooled
        connection (every connection it acquires is released even on timeout/cancellation), and never
        raises. A **no-op on SQLite** (a single connection — there is no pool to warm). The server
        backends share :func:`warm_pool_connections`."""
        ...

    async def require_rcsi_for_pooled(self) -> None:
        """Fail closed if this backend cannot guarantee the pooled claim's snapshot-read semantics
        (ADR 0066 §3.3). **Default: a no-op** — SQLite's process-wide lock totally orders producers
        and claimers (§3.5) and Postgres uses plain MVCC snapshots (§3.4), so neither has anything to
        verify. Only the SQL Server backend overrides it to hard-verify ``READ_COMMITTED_SNAPSHOT`` is
        ON and raise a :class:`RuntimeError` (with the DBA remediation statement) when it is OFF. The
        runner ``await``s this unconditionally at pooled ``start()`` so no ``isinstance`` reach is
        needed; ``[pipeline].require_rcsi_for_pooled=false`` downgrades a raise to a warning."""
        return None

    async def mark_done(self, outbox_id: str, now: float | None = None) -> None: ...

    async def mark_batch_done(self, outbox_ids: Sequence[str], now: float | None = None) -> None:
        """Complete N delivered outbound rows in **one transaction** — the batch counterpart of
        :meth:`mark_done` (ADR 0082 / BACKLOG #134). All N were delivered by a single ``BHS``…``BTS``
        envelope send, so they flip ``DONE`` together: each writes its H2 idempotency-ledger row and
        ``delivered`` event, and the finalizer runs **once per distinct ``message_id``**. A vanished
        member is an idempotent per-row no-op. Atomic — a crash before commit rolls all N back to
        ``INFLIGHT`` and :meth:`reset_stale_inflight` recovers them in ``seq`` order for a byte-identical
        re-send."""
        ...

    async def complete_with_response(
        self,
        outbox_id: str,
        *,
        body: str,
        outcome: str,
        detail: str | None = None,
        response_headers: Mapping[str, str] | None = None,
        reingress_to: str | None = None,
        now: float | None = None,
    ) -> None:
        """Mark one outbound row delivered **and** persist the partner's captured reply (ADR 0013) in
        one atomic transaction — :meth:`mark_done` plus an immutable ``response`` row keyed
        ``(message_id, destination_name, response_seq)``. The delivery worker calls **exactly one** of
        this or :meth:`mark_done` per successful delivery (the capture XOR). The ``response`` table is
        invisible to disposition (the finalizer scans ``queue`` only), so a captured delivery finalizes
        ``PROCESSED`` exactly as a one-way one does.

        When ``reingress_to`` is set (Increment 2), the same transaction *also* inserts a drainable
        ``Stage.RESPONSE`` work-row on the named loopback inbound's lane (a token referencing the
        artifact) so the reply is re-ingressed; ``None`` is byte-identical to Increment 1 (no work-row).

        ``response_headers`` (BACKLOG #154) is the connector's captured **allow-listed** HTTP response
        headers; ``None``/empty stores ``NULL`` (byte-identical). It is JSON-encoded and encrypted at
        rest exactly like ``detail``, and surfaced back through :meth:`correlate_response` as
        :attr:`CapturedResponse.headers` (so a re-ingressed Handler reads it via
        ``response_get(dest).headers``)."""
        ...

    async def correlate_response(self, message_id: str) -> list[CapturedResponse]:
        """Every captured reply for ``message_id`` (ADR 0013), ordered by destination then
        ``response_seq`` (latest seq per destination = the authoritative reply). The PHI read surface
        behind the audited, body-gated ``GET /messages/{id}/responses`` route. Also returns the inbound
        ``ack_sent`` rows (ADR 0021): they sort under a sentinel synthetic ``destination_name`` disjoint
        from every real destination, so the outbound per-destination authoritative-reply ordering is
        unaffected."""
        ...

    async def record_ack_sent(
        self,
        *,
        message_id: str,
        inbound_name: str,
        ack_body: str | None,
        ack_code: str,
        ack_phase: str,
        outcome: str,
        detail: str | None = None,
        now: float | None = None,
    ) -> None:
        """Record the ACK/NAK MessageFoundry **returned** to an inbound sender — Corepoint's "Response
        Sent" (ADR 0021 §§1-6) — as an immutable ``kind='ack_sent'`` row on the ``response`` table,
        keyed to ``message_id`` under a sentinel synthetic ``destination_name`` (``\\x1fack:<inbound>``)
        provably disjoint from every outbound destination.

        Captured **synchronously** after the ingress commit, so it is finalizer-invisible (``response``
        is not a ``queue`` stage) and never NAKs the sender. **PHI fail-safe** (#120): a NAK passes
        ``ack_body=None`` → ``body`` is always ``NULL`` (the AE/AR frame quotes the offending field
        value); an AA ``ack_body`` is stored **only when the store is encrypted**, else ``body`` is
        ``NULL`` — so default-on capture never forces raw ACK PHI onto an unencrypted store. ``detail``
        is the ``safe_text``-scrubbed, bounded reason (encrypted). ``ack_code``/``ack_phase`` are non-PHI
        plaintext disposition metadata."""
        ...

    async def ingress_handoff(
        self,
        *,
        response_row_id: str,
        loopback_channel_id: str,
        correlation_depth_cap: int,
        control_id: str | None,
        message_type: str | None,
        summary: str | None,
        peek_failed: bool = False,
        now: float | None = None,
    ) -> bool:
        """Consume one INFLIGHT ``Stage.RESPONSE`` work-row and produce the re-ingressed message+ingress
        row in one transaction (ADR 0013 Increment 2) — the re-ingress edge. A guarded ``DELETE`` of the
        work-row is the exactly-once commit, so a committed run is an idempotent no-op (``False``). The
        re-ingress worker peeks the loopback body and passes the derived metadata in. Returns ``True`` if
        this call performed the handoff."""
        ...

    async def response_body_for_work_row(self, response_row_id: str) -> str | None:
        """The decrypted artifact body a ``Stage.RESPONSE`` work-row references (ADR 0013 Increment 2) —
        read by the re-ingress worker to HL7-peek the reply (in ``pipeline/``) before
        :meth:`ingress_handoff`. ``None`` if the row/artifact is gone."""
        ...

    async def mark_failed(
        self, outbox_id: str, error: str, retry: RetryPolicy, now: float | None = None
    ) -> float | None:
        """Reschedule one outbox row with exponential backoff, or dead-letter it once a finite
        ``max_attempts`` is exhausted. Returns the row's new ``next_attempt_at`` (epoch seconds) when
        it was RESCHEDULED — the runner arms a per-lane retry wake at that time (WS-C: with the long
        idle backstop, the retry re-claim no longer rides a short poll) — and ``None`` when the row
        dead-lettered or no longer exists (nothing to re-claim)."""
        ...

    async def dead_letter_now(self, outbox_id: str, error: str, now: float | None = None) -> None:
        """Force one outbox row terminal (``DEAD``) immediately — **fail-fast**, no retry consumed
        and no backoff. For deliveries that can never succeed as-is and must not hold the FIFO lane:
        a permanent partner reject (``AR``), an internal/code error under the error-and-continue
        policy, or an undecryptable payload. Replayable via the dead-letter API like any dead row.
        Contrast :meth:`mark_failed`, which reschedules with backoff (and only dead-letters once a
        finite ``max_attempts`` is exhausted)."""
        ...

    async def mark_batch_failed(
        self,
        outbox_ids: Sequence[str],
        error: str,
        retry: RetryPolicy,
        now: float | None = None,
    ) -> float | None:
        """Re-pend (or dead-letter) N outbound rows that FAILED **as a unit** — the batch counterpart of
        :meth:`mark_failed` (ADR 0082). One disposition, decided from the head member's attempts and
        applied identically to every member, so all N re-pend to the same ``next_attempt_at`` (re-claimed
        as the identical contiguous prefix — strict FIFO preserved) or all dead-letter together. Returns
        the shared ``next_attempt_at`` when rescheduled, ``None`` when the batch dead-lettered."""
        ...

    async def dead_letter_batch(
        self, outbox_ids: Sequence[str], error: str, now: float | None = None
    ) -> None:
        """Force N outbound rows terminal (``DEAD``) in one transaction — the batch counterpart of
        :meth:`dead_letter_now` (ADR 0082 ratified decision #1). A **permanent** envelope reject
        dead-letters all N together (atomic, no retry consumed); the operator replays the batch."""
        ...

    # --- recovery / replay ---------------------------------------------------
    async def pending_depth(
        self, name: str, *, stage: str = Stage.OUTBOUND.value
    ) -> tuple[int, float | None]:
        """Backlog shape for one lane at ``stage``: ``(pending_count, oldest_created_at)`` — the number
        of rows still waiting and the enqueue time of the oldest (``None`` when empty). Lane key is
        stage-aware (``destination_name`` outbound, ``channel_id`` ingress). The workers use this to
        raise a ``queue_buildup`` alert when a lane stops draining. Cheap: a single COUNT + MIN."""
        ...

    async def reply_wait_state(self, message_id: str, destination_name: str) -> ReplyWaitState:
        """Metadata-only state for one synchronous-reply wait tick (ADR 0154 D3): the message's own
        status, the awaited destination's outbound row states, and the highest committed
        ``response_seq`` for it.

        The inbound HTTP listener's sync-reply path polls this while a caller is blocked, so it must
        stay cheap and must decrypt **nothing** — see :class:`ReplyWaitState`, which also documents
        why the message status is returned alongside the rows rather than the rows being read alone.
        Returning ``latest_response_seq`` rather than the body is what keeps a tick metadata-only:
        the reply is fetched once, through :meth:`correlate_response`, after a row is proven
        committed."""
        ...

    async def reset_stale_inflight(
        self,
        now: float | None = None,
        *,
        stage: str | None = None,
        owned: OwnedLanes | None = None,
    ) -> int:
        """Return ``inflight`` rows (claimed before a crash) to ``pending``. ``stage=None`` (default)
        recovers every stage in one pass — the right startup behavior; pass a stage to scope it.

        ``owned=None`` (default) is the unconditional single-node recovery. Pass :class:`OwnedLanes`
        to scope recovery to the caller's config-graph lanes (ADR 0073): each stage is filtered by
        its lane key (``channel_id`` for ingress/routed/response, ``destination_name`` for
        outbound), so an engine shard restarting against a shared unified store recovers exactly its
        own crash residue and never re-pends a live sibling shard's in-flight rows. An empty owned
        set matches nothing for the stages it scopes."""
        ...

    async def dead_letter_missing_destinations(
        self, valid_names: set[str], now: float | None = None
    ) -> int: ...

    async def dead_letter_missing_handlers(
        self, valid_names: set[str], now: float | None = None
    ) -> int:
        """Dead-letter non-terminal **routed** rows whose ``handler_name`` left the registry (a removed
        handler no transform worker can run). The routed-stage parallel of
        :meth:`dead_letter_missing_destinations`; call once at startup. Returns the rows killed."""
        ...

    # --- process-in-place dedup ledger (ADR 0129, BACKLOG #142) --------------
    async def is_file_processed(self, *, channel_id: str, file_key: str) -> bool:
        """True iff the leave-in-place (``after_read='leave'``) source ``channel_id`` already ingested
        the file whose **HASHED** ``file_key`` is given. ``file_key`` is a derived id (sha256 of the
        file's path-relative-to-root + mtime/size) — **never** a cleartext path (which can embed an MRN).
        A single PK lookup on the ``processed_files`` table (HASHES/IDS-ONLY, stored in the clear, never
        logged at INFO+). Implemented on SQLite, Postgres, and SQL Server at parity."""
        ...

    async def record_processed_file(
        self, *, channel_id: str, file_key: str, now: float | None = None
    ) -> None:
        """Record that source ``channel_id`` has ingested the file identified by the HASHED ``file_key``
        — called **after** a successful emit, with the **file** (not each split message) as the dedup
        unit. Idempotent on the ``(channel_id, file_key)`` PK, so a crash-re-run is a no-op (the ledger
        is a pure side record, invisible to the finalizer). No body/PHI is ever passed here."""
        ...

    async def prune_processed_files(
        self, *, channel_id: str, older_than: float, keep_last: int, now: float | None = None
    ) -> int:
        """Bound the dedup ledger for one connection: delete rows recorded before ``older_than`` and any
        surplus beyond the newest ``keep_last``. Returns the number deleted. A re-poll of a
        pruned-then-re-seen file simply re-ingests it (a bounded duplicate — at-least-once)."""
        ...

    # --- streaming attachments (#149, ADR 0105 Phase 0) ----------------------
    async def put_attachment(self, chunks: Iterable[str], content_type: str) -> str:
        """Store a detached very-large document as content-addressed, per-chunk-sealed rows and return
        its ``ref`` (the sha256 of the verbatim concatenated plaintext). Identical content **dedups** to
        the same ref. The fresh attachment sits at ``refcount=0`` until the caller increfs (Phase 1).
        Raises :class:`~messagefoundry.store.store.StreamingAttachmentsUnsupported` on a backend whose
        :attr:`supports_streaming_attachments` is ``False``."""
        ...

    def read_attachment(self, ref: str) -> AsyncIterator[str]:
        """Yield the detached document's chunks back as decrypted plaintext in ``seq`` order — the exact
        verbatim slices that were put (Approach B: concatenating them reconstructs the OBX-5.5 value
        byte-for-byte). Raises :class:`KeyError` if the attachment does not exist."""
        ...

    async def attachments_for(self, message_id: str) -> Sequence[Row]:
        """The distinct attachments a single message holds — the operator read surface (#149, ADR 0105
        Phase 3b). One row per ``message_attachment`` linkage JOINed to its ``attachment`` header,
        carrying ``attachment_id`` (the sha256 content address), ``content_type``, and ``total_bytes``.
        **Metadata only — no chunk ciphertext is read or decrypted** (the bulky bytes ride
        :meth:`read_attachment`), so this stays cheap enough for the message-detail view. Returns ``[]``
        for a message with no detached document (or on a backend without the substrate)."""
        ...

    async def attachment_incref(self, ref: str) -> None:
        """Add one live reference to an attachment (store-once refcount). Raises :class:`KeyError` if the
        attachment does not exist."""
        ...

    async def attachment_decref(self, ref: str) -> None:
        """Drop one reference and GC the attachment + all its chunks at refcount 0. Clamped at 0;
        tolerant of a missing ref (idempotent)."""
        ...

    async def sweep_orphan_attachments(self) -> int:
        """Reclaim orphaned attachment storage at startup (refcount-0 **and** header-less/incomplete
        chunks) so no PHI chunk accumulates at rest. Call once where :meth:`reset_stale_inflight` runs.
        Returns the number of attachments reclaimed."""
        ...

    async def release_message_attachments(self, message_id: str) -> None:
        """Release (decref + delete the linkage rows for) every attachment a single message holds, in one
        transaction (#149, ADR 0105 Phase 3a). Idempotent — a re-run finds the join rows gone and decrefs
        nothing, so a shared attachment a sibling message still references never underflows/GCs early.
        :meth:`purge_message_bodies` releases the whole eligible set via the same seam. Raises
        :class:`~messagefoundry.store.store.StreamingAttachmentsUnsupported` on a backend whose
        :attr:`supports_streaming_attachments` is ``False``."""
        ...

    async def replay(self, message_id: str, now: float | None = None) -> int: ...

    async def resend_to(
        self,
        *,
        message_id: str,
        to: str,
        idempotency_key: str,
        from_: str | None = None,
        body_override: str | None = None,
        now: float | None = None,
    ) -> ResendOutcome: ...

    async def reingress(
        self,
        *,
        origin_message_id: str,
        raw: str,
        idempotency_key: str,
        now: float | None = None,
    ) -> ReingressOutcome: ...

    async def replay_dead(
        self,
        *,
        channel_id: str | None = None,
        destination_name: str | None = None,
        now: float | None = None,
    ) -> int: ...

    async def cancel_queued(
        self,
        channel_id: str | None,
        destination_name: str,
        *,
        top_only: bool = False,
        now: float | None = None,
    ) -> int: ...

    # --- read helpers (API / console) ----------------------------------------
    # Row sequences are returned as Sequence[Row] (covariant) so a backend may return its own row
    # type (e.g. aiosqlite.Row) — list[Row] would be invariant and reject that.
    async def get_message(self, message_id: str) -> dict[str, Any] | None: ...

    async def message_metadata_json(self, message_id: str) -> str | None:
        """The message's **decrypted** ``metadata`` JSON (ADR 0081), or ``None`` when absent/unknown.

        A lightweight read for the delivery worker's per-message dynamic HTTP headers (#68): it decrypts
        ONLY the small metadata column, never the raw PHI body ``get_message`` would. Returns the full
        metadata object (engine-internal + ``user`` keys); the caller extracts the ``user`` bag with
        :func:`~messagefoundry.store.metadata.user_metadata`."""
        ...

    async def list_messages(
        self,
        *,
        channel_id: str | None = None,
        status: str | None = None,
        message_type: str | None = None,
        control_id: str | None = None,
        limit: int = 50,
        offset: int = 0,
        allowed_channels: Sequence[str] | None = None,
        received_from: float | None = None,
        received_to: float | None = None,
    ) -> Sequence[Row]: ...

    async def count_messages(
        self,
        *,
        channel_id: str | None = None,
        status: str | None = None,
        message_type: str | None = None,
        control_id: str | None = None,
        allowed_channels: Sequence[str] | None = None,
        received_from: float | None = None,
        received_to: float | None = None,
    ) -> int: ...

    async def search_messages(
        self,
        spec: SearchSpec,
        *,
        channel_id: str | None = None,
        status: str | None = None,
        message_type: str | None = None,
        control_id: str | None = None,
        limit: int = 50,
        allowed_channels: Sequence[str] | None = None,
    ) -> MessageSearchResult:
        """Scan-and-decrypt content search (ADR 0046 #51): metadata pre-filter in SQL, then decrypt +
        match each candidate body in memory off the event loop — the only mechanism that works while the
        store cipher is on (the at-rest bytes are per-row random-nonced AES-GCM ciphertext)."""
        ...

    async def list_dead(
        self,
        *,
        channel_id: str | None = None,
        destination_name: str | None = None,
        limit: int = 50,
        offset: int = 0,
        allowed_channels: Sequence[str] | None = None,
    ) -> Sequence[Row]: ...

    async def count_dead(
        self,
        *,
        channel_id: str | None = None,
        destination_name: str | None = None,
        allowed_channels: Sequence[str] | None = None,
    ) -> int: ...

    async def outbox_for(self, message_id: str) -> Sequence[Row]: ...

    async def outbox_payloads_for(self, message_id: str) -> Sequence[Row]:
        """Like :meth:`outbox_for` but the rows also carry the **decrypted transformed ``payload``**
        (PHI body) per destination — the #14 parity-comparison read path. Kept separate from
        :meth:`outbox_for` so the metadata-only message-detail view never decrypts bodies; the API
        gates this on ``MESSAGES_VIEW_RAW`` and audits every access."""
        ...

    async def events_for(self, message_id: str) -> Sequence[Row]: ...

    # --- connection events (Corepoint-style transport/lifecycle log, #46) -----
    async def record_message_event(
        self,
        message_id: str,
        event: str,
        *,
        destination: str | None = None,
        detail: str | None = None,
        now: float | None = None,
    ) -> None:
        """Append one ``message_events`` row with a caller-supplied kind (ADR 0154 D8).

        Lives on this protocol rather than :class:`AuditStore` because ``message_events`` is the
        per-message **disposition timeline** — queue-domain, the sibling of
        :meth:`record_connection_event` — not the tamper-evident ``audit_log``. That placement is also
        what lets ``pipeline/`` reach it through the store it already holds, with no cast.

        Before this there was **no** public message-event writer: ``_event`` is private to each
        backend and only ever called inside a store-owned transaction, so neither ``pipeline/`` nor
        ``transports/`` could record a disposition event at all.

        ``event`` is validated against :data:`MESSAGE_EVENT_KINDS` at runtime — the static
        literal-call-site guard in ``tests/test_phi_logging_inventory.py`` AST-walks for a *constant*
        first argument and therefore cannot see a kind forwarded through here."""
        ...

    async def record_connection_event(
        self,
        *,
        connection: str,
        transport: str,
        direction: str,
        kind: str,
        peer_host: str | None = None,
        message_id: str | None = None,
        reason: str | None = None,
        now: float | None = None,
    ) -> None:
        """Append one **metadata-only** connection event to the ``connection_event`` log (#46): the
        inbound lifecycle (``established``/``closed``) + the pre-ingress failures
        (``peer_not_allowlisted``/``at_capacity``/``frame_oversize``/``peer_reset``/``framing_error``)
        + the outbound lane transitions (``connection_lost``/``connection_restored``).

        It is a **pure observer**: a single short INSERT in its own transaction, touching no ``queue``
        row and calling no finalizer, so it can never pin a message's disposition or inflate received
        counts (``connection_event`` is invisible to ``_maybe_finalize_message``, which scans ``queue``
        only). ``message_id`` is a nullable, **non-FK** correlation hint (set only for outbound lane
        events). ``reason`` is ``safe_text``-scrubbed (#120) and encrypted at rest on every backend; the
        raw frame / message body is **never** passed here. The caller (runner) wraps every emit
        fail-soft, so a store error here can never wedge a listener or delivery lane."""
        ...

    async def list_connection_events(
        self,
        *,
        connection: str | None = None,
        kinds: Sequence[str] | None = None,
        since: float | None = None,
        limit: int = 100,
        allowed_channels: Sequence[str] | None = None,
    ) -> list[ConnectionEvent]:
        """Read connection events newest-first, optionally filtered by ``connection``, an ``kinds``
        allow-set, and a ``since`` timestamp. ``reason`` is decrypted at the boundary. The read accessor
        for the engine ``GET /events`` route + the deferred console "Event Log" page; runs on the
        lockfree read path. ``limit`` is clamped server-side.

        ``allowed_channels`` applies the same per-channel RBAC scope as :meth:`list_dead` /
        :meth:`list_messages`: ``None`` = all channels (no restriction); a set restricts the read to
        **inbound**-direction events whose ``connection`` is in the allow-set, and **excludes every
        outbound-direction event** (an outbound spans channels, so a channel-scoped caller must not see
        shared-outbound topology — the same boundary ``connection_metadata``/``test``/``purge`` enforce);
        an empty set matches nothing."""
        ...

    # --- operator alert-state (resolvable alert instances, ADR 0044 #56) ------
    async def upsert_alert_instance(
        self,
        *,
        event_type: str,
        connection: str,
        severity: str,
        reason: str | None = None,
        escalation_tier: int = 0,
        now: float | None = None,
    ) -> None:
        """Record/fold one operator-alert occurrence into a resolvable ``alert_instance`` (ADR 0044),
        de-duped on ADR 0014's ``(event_type, connection)`` throttle key: if a live (``open`` or
        ``acknowledged``) instance for the key exists, bump ``last_seen`` + ``count`` (refresh
        ``severity``/``reason``; an acknowledged instance stays acknowledged); otherwise insert a fresh
        ``open`` row. ``escalation_tier`` (#81, ADR 0133) is the notifier's occurrence-driven escalation
        level for this fire — persisted **monotonic** within an open instance (``MAX``), reset on reopen.

        A **pure observer** (like :meth:`record_connection_event`): a single short upsert in its own
        transaction, touching no ``queue`` row and calling no finalizer, so it can never pin a message's
        disposition. ``reason`` is ``safe_text``-scrubbed (#120) and encrypted at rest on every backend;
        no message body is ever passed here. The caller (the ``_emit`` chokepoint) wraps it fail-soft, so
        a store error here can never wedge a delivery worker."""
        ...

    async def list_active_alert_instances(
        self,
        *,
        limit: int = 200,
        allowed_channels: Sequence[str] | None = None,
    ) -> list[AlertInstance]:
        """Read **open + acknowledged** alert instances newest-``last_seen`` first — the read accessor for
        the ``GET /alerts/active`` route. Runs on the lockfree read path; ``limit`` clamped server-side.
        ``allowed_channels`` applies the same per-channel RBAC scope as :meth:`list_connection_events`
        (``None`` = all; a set restricts to instances whose ``connection`` is in the allow-set)."""
        ...

    async def ack_alert_instance(
        self, alert_id: int, *, actor: str, now: float | None = None
    ) -> bool:
        """Acknowledge a live instance (``open``/``acknowledged`` → ``acknowledged``), recording
        ``acked_by``/``acked_at``. Idempotent. Returns ``True`` iff a non-resolved instance with this id
        existed (so the API 404s a resolved/unknown id)."""
        ...

    async def resolve_alert_instance(self, alert_id: int, *, now: float | None = None) -> bool:
        """Resolve a live instance (``open``/``acknowledged`` → ``resolved``), recording ``resolved_at``.
        Returns ``True`` iff a non-resolved instance with this id existed."""
        ...

    async def resolve_alert_instances_for(
        self, *, event_type: str, connection: str, now: float | None = None
    ) -> int:
        """Auto-resolve the live instance(s) for a ``(event_type, connection)`` key on the inverse
        lifecycle signal (e.g. ``connection_restored``). Returns the count resolved."""
        ...

    async def suspend_alert_instance(
        self, alert_id: int, *, until: float, now: float | None = None
    ) -> AlertInstance | None:
        """Windowed suspend (#143, ADR 0044 amendment): set ``suspended_until`` on a live instance so its
        NOTIFICATIONS are muted until that epoch. **Notification-only** — status/count/visibility are
        untouched (the open condition stays on the dashboard; only the notify is muted for the window).
        Returns the updated instance (for the API echo + seeding the sink's suspend cache), or ``None``
        if the id is unknown or already resolved."""
        ...

    async def resume_alert_instance(
        self, alert_id: int, *, now: float | None = None
    ) -> AlertInstance | None:
        """Clear a windowed suspend (#143) so re-alerts resume immediately. Idempotent. Returns the
        updated instance, or ``None`` if unknown / already resolved."""
        ...

    async def get_alert_instance(
        self, alert_id: int, *, allowed_channels: Sequence[str] | None = None
    ) -> AlertInstance | None:
        """Read one alert instance by id (any status), RBAC-scoped like
        :meth:`list_active_alert_instances` — the API echo after an ack/resolve. ``None`` if unknown or
        outside the caller's channels."""
        ...

    async def count_open_alerts_by_connection(self) -> dict[str, int]:
        """The **open** (not acknowledged, not resolved) instance count per ``connection`` — backs
        ``ConnectionRow.alerts_active`` (ADR 0044 D4). Lockfree read."""
        ...

    async def purge_alert_instances(self, *, older_than: float, now: float | None = None) -> int:
        """Age-DELETE **resolved** instances whose ``resolved_at`` predates ``older_than`` (ADR 0044 D5
        retention) — metadata-only, never an open/acknowledged instance. Returns the number purged."""
        ...

    async def stats(self) -> dict[str, int]: ...

    async def in_pipeline_depth(self) -> int:
        """Count of NOT-DONE rows (status ``pending``|``inflight``) across **every** stage
        (ingress + routed + outbound) — a whole-pipeline drain gauge, vs :meth:`stats` which sees only
        the outbound stage. Lets a consumer tell a true drain from a stalled router/transform."""
        ...

    # --- at-rest key rotation (PHI.md §3, ASVS 11.2.2) -----------------------
    async def reencrypt_to_active(self, *, batch: int = 500) -> int: ...

    # --- per-key AES-GCM invocation bound (ASVS 11.3.4) ----------------------
    async def add_cipher_invocations(self, key_id: str, count: int) -> int:
        """Atomically add ``count`` invocations to ``key_id``'s persisted total; return the new total.

        The one accounting primitive behind the persisted per-key AES-GCM invocation bound: block
        reservations, the close-time settlement, and the DR backup codec's post-run aggregate all go
        through it. Atomic, so every process sharing this one unified store — engine shards,
        ``[cluster]`` HA nodes, an offline ``rotate-key`` — charges the same row. See
        :mod:`messagefoundry.store.gcm_bound`."""
        ...

    async def cipher_invocations(self, key_id: str) -> int:
        """``key_id``'s persisted cumulative invocation total (0 when the key has no row yet)."""
        ...

    async def checkpoint_cipher_invocations(self, *, settle: bool = False) -> int | None:
        """Reconcile the live cipher's spend against its persisted reserve; return the cumulative total,
        or ``None`` when the store's cipher carries no bound (identity / ``vault_transit``). See
        :func:`messagefoundry.store.gcm_bound.checkpoint_invocations`."""
        ...

    # --- cross-process upload-quota reservation (ASVS 2.3.4) -----------------
    async def reserve_upload_quota(
        self,
        uploader_id: str,
        *,
        files: int,
        size_bytes: int,
        max_files: int = 0,
        max_total_bytes: int = 0,
        stale_after: float = UPLOAD_RESERVATION_STALE_AFTER,
    ) -> bool:
        """Atomically reserve (or release) an uploader's IN-FLIGHT upload budget; return whether the
        reserve applied. The one cross-process decision point behind the per-uploader upload quota.

        **Why the store owns this.** ``UploadStore._quota_lock`` is an ``asyncio.Lock``, so it is
        per-event-loop and therefore per-process. Engine sharding is the built, shipped, default
        scaling axis and nothing partitions ``uploads_dir`` per shard, so N shards over one directory
        hold N independent locks and each can overshoot the budget by one file. Every shard sits on
        the ONE unified store (ADR 0063 — and ``require_unified_store`` makes a server DB mandatory
        past one shard), so this row is authoritative for all of them.

        **What is counted here, and what is not.** The files already ON DISK are counted by the
        caller's sidecar scan, which is uncached and therefore already fleet-visible. The gap this
        closes is only the uploads IN FLIGHT on other shards — reserved but not yet landed, so
        invisible to any scan. The caller passes its remaining HEADROOM (cap minus what its scan
        observed) as ``max_files`` / ``max_total_bytes``; this method holds only the in-flight sum.

        ``files > 0`` reserves: the post-add in-flight totals must fit inside the headroom or nothing
        is written and this returns ``False`` (fail-closed — a caller that forgets the headroom
        arguments gets the 0 defaults and is refused). ``files <= 0`` releases, always applies,
        clamps at zero, ignores the headroom arguments and returns ``True``.

        ``stale_after`` bounds a leak: a process killed between reserve and release never releases,
        and its slot would otherwise consume the uploader's budget forever. A row whose reservation
        has been CONTINUOUSLY outstanding for longer than ``stale_after`` seconds is reset to zero
        before the add. The reset can only restore today's behaviour (an overshoot bounded by the
        number of concurrent writers), never something worse."""
        ...

    # --- retention / purge + maintenance (PHI.md §8) -------------------------
    async def purge_message_bodies(
        self,
        *,
        older_than: float,
        now: float | None = None,
        connection_cutoffs: Mapping[str, float] | None = None,
    ) -> int:
        """Null PHI message bodies received before ``older_than`` (keeping the message ROW — the Mirth
        Data-Pruner pattern — while blanking its PHI columns, ``metadata`` included, ASVS 14.2.7).
        ``connection_cutoffs`` (#34, ADR 0027) optionally overrides the cutoff per ``channel_id``
        (``float('-inf')`` = keep forever); default empty ⇒ a single global cutoff, byte-identical to
        the prior behaviour. Returns the number purged."""
        ...

    async def strip_embedded_documents(
        self,
        *,
        older_than: float,
        now: float | None = None,
        connection_cutoffs: Mapping[str, float] | None = None,
        min_bytes: int = 0,
        content_types: Mapping[str, str] | None = None,
    ) -> StripResult:
        """Strip bulky base64 embedded documents from stored message bodies **in place** (#47, ADR 0042):
        replace each ``mfb64:v1:`` carriage value / HL7 OBX-5 ED embed with a small self-describing
        tombstone (size + content-type + pruned ts) via the codec, keep the surrounding message
        byte-stable + parseable, and set the message's ``documents_pruned`` flag. Eligibility mirrors
        :meth:`purge_message_bodies` (per-connection-or-global cutoff AND not in-flight); ``min_bytes``
        skips a sub-threshold embed; ``content_types`` (channel_id -> declared content_type) labels a
        bare-mfb64 tombstone. Idempotent (an already-tombstoned body is skipped). Returns a
        :class:`StripResult` (counts + bytes reclaimed; no message content)."""
        ...

    async def purge_dead_letters(
        self,
        *,
        older_than: float,
        now: float | None = None,
        connection_cutoffs: Mapping[str, float] | None = None,
    ) -> int:
        """Null dead-lettered outbound bodies updated before ``older_than`` (their own window).
        ``connection_cutoffs`` (#34, ADR 0027) optionally overrides the cutoff per ``destination_name``
        (``float('-inf')`` = keep forever); default empty ⇒ a single global cutoff. Returns the number
        purged."""
        ...

    async def purge_state(self, *, older_than: float, now: float | None = None) -> int:
        """Delete transform-state entries (ADR 0005) last written before ``older_than`` (age-based
        retention). Returns the number purged. Off unless ``[retention].state_max_age_days`` is set."""
        ...

    async def purge_connection_events(self, *, older_than: float, now: float | None = None) -> int:
        """Delete connection-event rows (#46) older than ``older_than`` (age-based — they are metadata
        with no body to null and no FK). Returns the number purged. Driven by the
        ``[retention].connection_event_retention_hours`` override, else the message-body window."""
        ...

    async def purge_search_presets(self, *, older_than: float, now: float | None = None) -> int:
        """Delete saved-search presets (ADR 0136) last edited **or used** before ``older_than``.

        The stored ``criteria`` is the operator's own content/``field_value`` needle — PHI-shaped by
        construction (PHI.md §2, PL-2) and encrypted at rest — so it needs a window like every other
        PHI tier (ASVS 14.2.7). The whole ROW is deleted rather than blanked: a preset's entire payload
        IS its criteria, so nulling would leave the console listing a recallable-but-broken preset. It
        backs no count and carries no disposition, so count-and-log does not reach it (the same
        reasoning that already permits :meth:`purge_state` / :meth:`purge_connection_events` to delete).

        Keys on **last-USED** (#306, amending ADR 0136 / ADR 0027): the cutoff is compared against the
        LATER of ``updated_at`` (written by :meth:`upsert_search_preset`) and ``last_used_at`` (written
        by :meth:`get_search_preset`), so a preset an operator runs daily but never re-saves is kept.
        The greatest-of-two is null-safe on every backend — a row that predates the column
        (``last_used_at`` NULL) still ages out on ``updated_at`` alone. Returns the number purged. Off
        unless ``[retention].search_preset_days`` is set."""
        ...

    async def purge_reference_snapshots(
        self, *, older_than: float, declared: Collection[str], now: float | None = None
    ) -> int:
        """Delete ORPHANED reference snapshots — sets no longer declared in config — synced before
        ``older_than``. Returns the number of ``reference`` rows deleted.

        ``reference.value`` is a versioned lookup snapshot (ADR 0006) and can hold patient-keyed rows,
        so PHI.md §2 classifies it **PL-2**. Before ASVS 14.2.7 it had **no purge path at all**: a set
        dropped from config left its fully-decryptable snapshot in the store indefinitely, replaced only
        by the next sync's build-new-then-flip — which never comes for a set nobody declares any more.

        **Orphan-scoped by design, and that limit must be stated rather than glossed.** A set that IS
        declared is never touched however old its ``synced_at``, because its snapshot is live data the
        engine serves. So the normal case — a wired set holding live PHI — is still purged by nothing.
        That is an honest residual, not a closed cell; do not let a classification table describe this as
        `rides <window>`, which would machine-bless a false claim.

        **``declared`` must be non-empty and implementations MUST reject an empty one.** An empty
        collection reads as "every set is abandoned", so a caller that loaded a registry declaring zero
        reference sets — a subset ``--config``, a per-team split, a harness redirect pointed at the real
        DB — would wipe every snapshot in the store. Absence-based guards fail open by construction, so
        this one is positive-signal: an empty ``declared`` is a programming error, not an instruction.
        Worse, ``ReferenceSyncRunner`` deliberately does **not** advance ``synced_at`` when a source
        fetch fails, so the victim would be precisely the last-good snapshot of a still-wired set whose
        source is merely down.

        **Eligibility must be re-asserted INSIDE the delete statement**, not read first and trusted. The
        caller computes ``declared`` outside any store lock, so a config reload can commit a fresh
        patient-keyed snapshot between the decision and the delete; a purge that then fires deletes live
        data and the set goes present-but-empty, returning ``None`` from ``reference(name).get(k)``
        silently. Do not assume any backend's own locking closes this — the race is at the caller level
        on all three.

        **The ``reference_version`` pointer row SURVIVES.** Deleting it is invisible to
        :meth:`converge_reference_cache`, which only adds/updates names present in a fresh read, so a
        cluster follower would keep serving the purged PHI from RAM forever. Keeping the pointer costs a
        row and makes the set read as present-but-empty; that trade is deliberate and recorded."""
        ...

    async def wal_checkpoint(self) -> None: ...

    async def vacuum(self) -> None: ...

    # --- at-rest posture (M5) -------------------------------------------------
    def cipher_info(self) -> CipherInfo:
        """The **non-secret** at-rest cipher posture (M5): whether encryption is on and, if so, the
        active key's **fingerprint** (``active_key_id``) — never key bytes. The public accessor the M5
        ``GET /security/posture`` route reads instead of reaching a backend's private ``_cipher``."""
        ...

    def cipher(self) -> Cipher:
        """This store's **live** at-rest cipher instance.

        For a caller that must encrypt/decrypt under the store's DEK from OUTSIDE the store — today only
        the ADR 0134 uploaded-logs :class:`~messagefoundry.uploads.UploadStore`. It must share THIS
        instance rather than build a second one from the same key material: the AES-GCM invocation bound
        (ASVS 11.3.4) is per-instance state, so a second instance would neither charge the key's
        persisted ``cipher_meta`` row nor see the fleet cumulative — it would keep encrypting under a key
        this cipher has already fail-closed on at 2**32. ``build_store_cipher`` remains for the
        store-LESS construction path (tests / embedding with no engine), where there is no bound to share.

        Holding the object is not itself a secret exposure: it exposes no key bytes (the DEK is zeroized
        at construction; only the one-way fingerprint and OpenSSL's internal copy survive)."""
        ...

    # --- store health / metrics ----------------------------------------------
    async def db_status(self) -> DbStatus: ...

    def pool_status(self) -> PoolStatus | None:
        """A read-only snapshot of this backend's connection pool, or ``None`` on a backend with no
        pool (SQLite). The **server-only** observability surface behind ``/status``'s additive ``pool``
        field (B11): the PRIMARY ``acquire_wait`` percentiles (the connection-scale wall — they grow
        monotonically with worker contention once the pool saturates) plus a secondary size/idle
        occupancy boolean. Synchronous + cheap (it reads the live pool's size/idle accessors + a
        snapshot of the in-process acquire-wait histogram — no DB round-trip), and additive: an older
        client deserializes ``/status`` unchanged because the field defaults ``None``. Returns ``None``
        on SQLite (no pool)."""
        ...

    def claim_proc_status(self) -> ClaimProcStatus | None:
        """The ADR 0114 sub-lever A stored-procedure-claim startup-gate verdict, or ``None`` when
        this backend has no such lever (AC-6: SQL Server is the only one that reads its flag, whose
        literal name this module therefore does not write) or that flag is off. AC-7's **degraded
        gauge** — the surface an operator can actually see the degraded
        state on (``/status``, ``/metrics``, the console store panel); before it existed the whole
        signal was one WARNING at ``open()``. Synchronous + free (three attributes the gate recorded
        once at open — no DB round-trip), read-only, and additive: the ``/status`` field defaults
        ``None``, so an older client deserializes it unchanged."""
        ...

    async def integrity_check(self) -> tuple[bool, str]: ...

    async def connection_metrics(
        self, *, since: float, now: float | None = None, rate_window: float = 60.0
    ) -> ConnectionMetrics: ...

    async def delivery_latency_histogram(
        self, *, buckets: Sequence[float], now: float | None = None
    ) -> Sequence[LatencyHistogram]:
        """Per-(channel_id, destination_name) delivery-latency histogram over outbound rows that
        reached status='done'. Latency = updated_at - created_at (seconds), clamped to >= 0 (clock-
        skew guard). bucket_counts are CUMULATIVE (Prometheus le semantics). Read-only; runs off the
        event loop."""
        ...


class AuditStore(Protocol):
    """The audit log + PHI-view trail (tamper-evident hash chain)."""

    async def record_view(
        self, message_id: str, *, actor: str | None = None, now: float | None = None
    ) -> None: ...

    async def record_audit(
        self,
        action: str,
        *,
        actor: str | None = None,
        channel_id: str | None = None,
        detail: str | None = None,
        client: str | None = None,
        now: float | None = None,
    ) -> None:
        """Append a general audit row (the PHI-access + admin-action trail).

        ``client`` is the caller's network address (ADR 0150) — the "from where" an incident responder
        needs to trace an action to a host. It is threaded EXPLICITLY from the request: API callers pass
        ``client_ip(request)``; engine-internal writes (background workers, ``system`` actions) omit it
        and the column is NULL. NULL means "no client was in scope", never "unknown" — an ambient
        carrier (ContextVar) was rejected precisely because it inherits into ``asyncio.create_task``
        workers and would stamp an unrelated operator's address onto ``system`` rows.

        The address is folded into the tamper-evident hash chain as a conditional trailing element, so
        rows written before this column existed (``client`` NULL) still verify byte-identically — see
        :func:`~messagefoundry.store.store.audit_row_hash`."""
        ...

    async def list_audit(
        self,
        *,
        limit: int = 50,
        actor: str | None = None,
        action: str | None = None,
        since: float | None = None,
        until: float | None = None,
    ) -> Sequence[Row]:
        """Most-recent-first audit entries, optionally scoped (BACKLOG #170).

        The optional filters — ``actor`` (exact identity), ``action`` (exact event type), and an
        inclusive time window ``since <= ts <= until`` (``ts`` is the epoch-float audit column on
        every backend) — are ANDed. Every value is passed as a bound parameter (never interpolated),
        so an attacker-influenced filter can never inject SQL. Ordering, ``limit``, and the hash-chain
        read semantics are unchanged; passing no filter is byte-identical to the limit-only query.
        """
        ...

    async def security_events_for_user(
        self, username: str, *, limit: int = 100
    ) -> Sequence[Row]: ...

    async def create_pending_approval(
        self,
        *,
        approval_id: str,
        operation: str,
        params: str,
        requester: str,
        requested_at: float,
        expires_at: float | None,
    ) -> None: ...

    async def get_pending_approval(self, approval_id: str) -> Row | None: ...

    async def list_pending_approvals(self, *, now: float, limit: int = 100) -> Sequence[Row]: ...

    async def decide_pending_approval(
        self,
        approval_id: str,
        *,
        status: str,
        approver: str | None,
        decided_at: float,
        from_status: str = "pending",
    ) -> bool: ...

    async def audit_anchor(self) -> tuple[int, str]: ...

    async def verify_audit_chain(
        self,
        *,
        expected_anchor: tuple[int, str] | None = None,
        expected_prefix: tuple[int, str] | None = None,
    ) -> tuple[bool, str | None]: ...

    async def rekey_audit_chain(
        self, *, expected_anchor: tuple[int, str] | None = None
    ) -> tuple[bool, str]:
        """Non-silent #190-D migration: enable HMAC keying of the audit chain on an existing keyless
        store. Refuses without a DEK, is a no-op if already keyed, and verifies the existing keyless
        chain first (refusing on any break, so a forged chain is never blessed). Sets a watermark; never
        rewrites existing row hashes. Returns ``(ok, message)``."""
        ...

    async def has_prior_backup_history(self) -> bool:
        """True iff the audit log carries at least one ``dr_backup`` row — the #102 server-DB DR-seed
        gate's "restored, not freshly-bootstrapped" signal. A ``dr_backup`` row is written on every
        leader-gated backup SUCCESS (the run that PRODUCES a seed archive), so a server DB restored from
        an operating primary carries ≥1; a passive DR standby is never the leader and writes none, so a
        fresh/unrestored DR DB (non-empty only because engine bootstrap + operator login wrote to it) has
        zero. Read-only (a single indexed existence check), all backends. NOTE: this proves prior backup
        history, NOT vintage/completeness of a DBA-managed restore (see BACKLOG #102 residuals)."""
        ...


class AuthStore(Protocol):
    """Users, roles, sessions, and AD-group mappings — the contract :class:`AuthService` uses.

    Segregated from the queue/message contract so the auth subsystem cannot reach inbox/outbox rows.
    """

    # --- users ---------------------------------------------------------------
    async def create_user(
        self,
        *,
        user_id: str,
        username: str,
        auth_provider: str,
        display_name: str | None = None,
        email: str | None = None,
        password_hash: str | None = None,
        must_change_password: bool = False,
        now: float | None = None,
    ) -> None: ...

    async def get_user(self, user_id: str) -> UserRecord | None: ...

    async def get_user_by_username(self, username: str) -> UserRecord | None: ...

    async def list_users(self) -> Sequence[UserRecord]: ...

    async def count_users(self) -> int: ...

    # ``must_change_password`` DEFAULTS TO TRUE, and the default is a security control rather than a
    # style choice (BACKLOG #1245). Passing False is what records the credential claim in
    # ``users.password_claimed_at``, and that stamp is write-once and monotonic -- once set it can
    # never be undone, and an account carrying it is permanently exempt from WP-3 auto-retirement.
    # So the DANGEROUS branch must never be the one a caller gets by omission. With False as the
    # default a caller that simply forgot the keyword would silently stamp a claim on an account
    # nobody claimed, which is the very shape #1245 documents. Every existing caller passes the
    # argument explicitly, so this default is unreachable today -- it exists to bound the NEXT caller.
    async def set_password(
        self,
        user_id: str,
        *,
        password_hash: str,
        must_change_password: bool = True,
        now: float | None = None,
    ) -> None: ...

    async def set_user_disabled(
        self, user_id: str, *, disabled: bool, now: float | None = None
    ) -> None: ...

    async def update_user_profile(
        self,
        user_id: str,
        *,
        display_name: str | None,
        email: str | None,
        now: float | None = None,
    ) -> None: ...

    async def delete_user(self, user_id: str) -> None: ...

    # --- MFA: native TOTP second factor (local accounts, WP-14) --------------
    async def set_totp_secret(
        self, user_id: str, *, secret: str | None, now: float | None = None
    ) -> None: ...

    async def get_totp_secret(self, user_id: str) -> str | None: ...

    async def enable_totp(
        self, user_id: str, *, recovery_code_hashes: list[str], now: float | None = None
    ) -> None: ...

    async def disable_totp(self, user_id: str, *, now: float | None = None) -> None: ...

    async def get_recovery_code_hashes(self, user_id: str) -> list[str]: ...

    async def consume_recovery_code_hash(
        self, user_id: str, code_hash: str, *, now: float | None = None
    ) -> bool: ...

    async def consume_totp_step(self, user_id: str, step: int) -> bool: ...

    # --- MFA: WebAuthn passkeys second factor (local accounts, WP-14b / ADR 0068) ---
    async def add_webauthn_credential(self, cred: WebAuthnCredential) -> None: ...

    async def list_webauthn_credentials(self, user_id: str) -> list[WebAuthnCredential]: ...

    async def get_webauthn_credential(
        self, credential_id_hash: str
    ) -> WebAuthnCredential | None: ...

    async def has_webauthn_credentials(self, user_id: str) -> bool: ...

    async def any_webauthn_credentials(self) -> bool: ...

    async def delete_webauthn_credential(self, user_id: str, credential_id_hash: str) -> bool: ...

    async def delete_all_webauthn_credentials(self, user_id: str) -> int: ...

    async def update_webauthn_sign_count(
        self, credential_id_hash: str, *, expected: int, new: int, used_at: float
    ) -> bool: ...

    async def record_login_success(self, user_id: str, *, now: float | None = None) -> None: ...

    async def record_login_failure(
        self,
        user_id: str,
        *,
        failed_attempts: int,
        locked_until: float | None,
        now: float | None = None,
    ) -> None: ...

    # --- roles / AD-group maps -----------------------------------------------
    async def upsert_role(
        self,
        *,
        role_id: str,
        display_name: str,
        description: str | None = None,
        builtin: bool = True,
        permissions: str | None = None,
    ) -> None:
        """Create-or-update a role. ``permissions`` is a JSON array of ``Permission`` wire values for a
        custom role (ADR 0045), or ``None`` for a built-in row (which resolves from code)."""
        ...

    async def list_roles(self) -> Sequence[Row]: ...

    async def get_role(self, role_id: str) -> Row | None: ...

    async def delete_custom_role(self, role_id: str) -> bool:
        """Delete a custom (``builtin`` false) role + its user/AD-group assignments in one transaction;
        a built-in row is never removed. Returns ``True`` iff a custom role was deleted (ADR 0045)."""
        ...

    async def get_user_role_ids(self, user_id: str) -> list[str]: ...

    # --- saved-search presets (ADR 0136, BACKLOG #151) — per-user, criteria encrypted at rest -----

    async def upsert_search_preset(
        self,
        *,
        preset_id: str,
        owner_user_id: str,
        name: str,
        criteria: str,
        now: float | None = None,
    ) -> tuple[str, bool]:
        """Create-or-replace a per-user preset by ``(owner, name)`` (id reused on a name collision so the
        cell-AAD stays stable). ``criteria`` is a JSON blob encrypted at rest. Returns
        ``(effective_id, replaced)``."""
        ...

    async def list_search_presets(self, owner_user_id: str) -> list[dict[str, Any]]:
        """A user's presets (id/name/timestamps only — NEVER the criteria)."""
        ...

    async def get_search_preset(
        self, *, preset_id: str, owner_user_id: str, now: float | None = None
    ) -> dict[str, Any] | None:
        """One owner-scoped preset with its criteria DECRYPTED, or ``None``.

        A hit **stamps ``last_used_at``** (#306) — the only writer of that column — so
        :meth:`purge_search_presets` can key on last-USED. Best-effort: a stamp failure is logged and
        swallowed, never raised, so it cannot break the recall. ``now`` overrides the clock (tests)."""
        ...

    async def delete_search_preset(self, *, preset_id: str, owner_user_id: str) -> bool:
        """Delete an owner_user_id-scoped preset; ``True`` iff a row was removed. Idempotent."""
        ...

    async def set_user_roles(
        self,
        user_id: str,
        role_ids: Sequence[str],
        *,
        assigned_by: str | None = None,
        now: float | None = None,
    ) -> None: ...

    async def set_user_channel_scope(
        self, user_id: str, scope_json: str | None, *, now: float | None = None
    ) -> None: ...

    async def set_user_federated_subject(
        self, user_id: str, issuer: str, subject: str, *, now: float | None = None
    ) -> None:
        """Bind a user's verified federated ``(issuer, sub)`` identity (BACKLOG #1015). Recorded on the
        first federated login so a later login whose reassignable username resolves to this account but
        carries a different subject is refused, not handed the account."""
        ...

    async def get_user_by_federated_subject(self, issuer: str, subject: str) -> UserRecord | None:
        """The account bound to this verified ``(issuer, sub)``, or ``None`` (BACKLOG #1256).

        **The inverse of the #1015 guard, and the direction that guard cannot look.** That check
        resolves a user by USERNAME and asks whether *this account* carries a different subject --
        so it constrains WHICH subject may bind to a given account, and is structurally incapable of
        seeing a SECOND ACCOUNT already holding the same subject. Nothing else could see it either:
        measured, there is no UNIQUE constraint naming the federated columns on any of the three
        backends (0/0/0, against 13/8/10 total UNIQUE declarations as the positive control).

        Deliberately a lookup rather than a scan: it sits on the federated login path, and
        ``list_users()`` would make every sign-in O(number of accounts).
        """
        ...

    async def roles_for_ad_groups(self, groups: Iterable[str]) -> set[str]: ...

    async def list_ad_group_role_map(self) -> Sequence[Row]: ...

    async def set_ad_group_role_map(self, entries: Iterable[tuple[str, str]]) -> None: ...

    async def channels_for_ad_groups(self, groups: Iterable[str]) -> set[str]: ...

    async def list_ad_group_scope_map(self) -> Sequence[Row]: ...

    async def set_ad_group_scope_map(self, entries: Iterable[tuple[str, str]]) -> None: ...

    # --- sessions ------------------------------------------------------------
    async def create_session(
        self,
        *,
        token_hash: str,
        user_id: str,
        expires_at: float,
        client: str | None = None,
        seed_reauth: bool = True,
        now: float | None = None,
    ) -> None: ...

    async def get_session(self, token_hash: str) -> SessionRecord | None: ...

    async def list_sessions(
        self, user_id: str, *, now: float | None = None
    ) -> list[SessionRecord]: ...

    async def touch_session(self, token_hash: str, *, now: float | None = None) -> None: ...

    async def rotate_session(self, token_hash: str, *, new_token_hash: str) -> bool:
        """Re-key a live session to ``new_token_hash``, in place (ASVS 7.2.4).

        A pure re-key: every other column — ``user_id``, ``created_at``, ``expires_at``, ``client``,
        ``reauth_at``, ``mfa_verified_at`` — is carried forward byte-identical. It stamps **nothing**,
        deliberately, so "the session is the same session, under a new name" is the whole contract.
        In particular ``expires_at`` is untouched, so no amount of rotation can extend the absolute
        session lifetime, and ``mfa_verified_at`` survives, so a rotation cannot strand a caller
        behind the ASVS 6.3.3 MFA access gate holding a token that gate has never seen verified.

        Returns **True** when a row was re-keyed, **False** when there was none to re-key — the row
        is gone, expired-and-purged, or ``revoked_at IS NOT NULL``. This is the one session UPDATE
        that reports its rowcount: every other one is deliberately blind (a write against a dead hash
        is a silent no-op), but a caller rotating a session is about to hand the new token to a user,
        so it must be able to fail closed if the session died underneath it.
        """
        ...

    async def mark_session_reauthed(
        self, token_hash: str, *, now: float | None = None, client: str | None = None
    ) -> None:
        """Refresh the session's step-up freshness (``reauth_at``). When ``client`` is given, also
        re-anchor the session's last-verified client address to it (the new-client-IP risk signal in
        WP-L3-13 uses this so a re-verify from a roamed address clears the forced step-up); a ``None``
        ``client`` leaves the stored address unchanged."""
        ...

    async def mark_session_mfa_verified(
        self, token_hash: str, *, now: float | None = None
    ) -> None: ...

    async def revoke_session(self, token_hash: str, *, now: float | None = None) -> None: ...

    async def revoke_user_sessions(
        self, user_id: str, *, except_token_hash: str | None = None, now: float | None = None
    ) -> int: ...

    async def enforce_session_cap(
        self, user_id: str, *, keep: int, now: float | None = None
    ) -> None: ...

    async def purge_expired_sessions(self, *, now: float | None = None) -> int: ...


class AdminStore(AuthStore, AuditStore, Protocol):
    """Auth + audit-log reads — the surface :class:`AuthService` exposes to its admin endpoints.

    Wider than :class:`AuthStore` because the user-administration routes also read the audit log,
    but still excludes :class:`QueueStore`: the auth subsystem can never reach inbox/outbox rows.
    """


@runtime_checkable
class Store(QueueStore, AuditStore, AuthStore, Protocol):
    """The full store contract — every backend implements all three concerns in one handle.

    Kept ``runtime_checkable`` so ``isinstance(store, Store)`` can smoke-check a backend. The concerns
    deliberately share one SQLite file/handle (single-file inbox/outbox + audit + auth, no broker);
    the segregation is in the *contract* each consumer depends on, not in the physical store.
    """


def resolve_active_key(settings: StoreSettings) -> str | None:
    """The effective base64 active key, sourced through the :class:`KeyProvider` seam selected by
    ``[store].key_provider`` (ADR 0019). The default ``auto`` provider is the env-then-DPAPI ladder —
    ``encryption_key`` (env/config) if set, else the Windows DPAPI-protected ``encryption_key_file``
    decrypted (WP-11d), else ``None`` (→ identity cipher) — so the default is **byte-identical** to the
    pre-seam behavior. The env key takes precedence so a deployment can override the file.

    Fail-closed: a configured-but-unreadable/foreign DPAPI key file raises ``DpapiError`` here, and a
    selected-but-unresolvable/unknown provider raises ``KeyProviderError`` — both propagate so
    ``serve`` refuses to start rather than silently degrading to the identity (plaintext) cipher."""
    return resolve_key_provider(settings).active_key()


def resolve_decrypt_keys(settings: StoreSettings) -> list[str]:
    """The full **decrypt-capable** base64 keyring for this store — the active key followed by every
    retired (decrypt-only) key — sourced through the same :class:`KeyProvider` seam as
    :func:`resolve_active_key`/``open_store`` (ADR 0019). This is exactly the set the store cipher can
    decrypt with (``make_cipher(active, retired)`` in ``open_store``), so a caller that must decrypt
    *any* value the store could read — e.g. the DR restore-verify checking a backup taken under a
    now-retired key after a rotation (ADR 0049 AC-5: "incl. retired keys") — uses this, not just the
    active key. Order is active-first; duplicates and empties are dropped; an unset active key yields an
    empty list (identity cipher)."""
    provider = resolve_key_provider(settings)
    ordered: list[str] = []
    active = provider.active_key()
    if active:
        ordered.append(active)
    for retired in provider.retired_keys():
        if retired:
            ordered.append(retired)
    # De-dup while preserving order (active first) so a key listed both active + retired isn't tried twice.
    seen: set[str] = set()
    keyring: list[str] = []
    for k in ordered:
        if k not in seen:
            seen.add(k)
            keyring.append(k)
    return keyring


def build_store_cipher(settings: StoreSettings) -> Cipher:
    """Build the at-rest cipher for ``settings`` — the SAME construction ``open_store`` uses (active key
    + retired decrypt-only keyring, ``write_v2=aad_bind``). Exposed so a store-DECOUPLED PHI-at-rest
    surface — the offline uploaded-logs files (ADR 0134) — encrypts under the identical DEK / keyring /
    rotation posture as the message store, without reaching into a live ``Store`` instance's private
    cipher. No key configured → the identity cipher (plaintext), exactly like the store."""
    if settings.cipher_provider == "vault_transit":
        # ADR 0138: bulk at-rest crypto INSIDE Vault/OpenBao Transit — the plaintext DEK never enters
        # engine heap (ASVS 13.3.3). Lazy-imported so the base install pulls no Vault SDK; fails closed at
        # open (KeyProviderError → serve refuses) rather than degrading to plaintext.
        from messagefoundry.store.crypto_transit import build_transit_cipher

        return build_transit_cipher(settings)
    if settings.cipher_provider != "aesgcm":
        raise ValueError(
            f"[store].cipher_provider={settings.cipher_provider!r} is not a known cipher provider "
            "(expected 'aesgcm' or 'vault_transit')"
        )
    retired = [k.strip() for k in settings.encryption_keys_retired.split(",") if k.strip()]
    return make_cipher(resolve_active_key(settings), retired, write_v2=settings.aad_bind)


async def open_store(
    settings: StoreSettings,
    *,
    message_events: str = "all",
    posture: HopPosture | None = None,
) -> Store:
    """Open the store for the configured backend — the single backend-selection seam.

    ``sqlite`` is the default; ``postgres`` is a production server-DB backend with single-node parity
    (lazy-imported, needs the ``postgres`` extra); ``sqlserver`` is a production server-DB backend,
    lazy-imported (needs the ``sqlserver`` extra). Unknown backends raise ``NotImplementedError``.

    ``message_events`` is the ``[diagnostics].message_events`` verbosity (#63) — sourced by the caller
    that holds ``ServiceSettings`` (serve/engine); it lives outside ``StoreSettings``, mirroring the
    ``engine._connection_events`` caller-gate. The audit-chain HMAC key (#190) is derived here from the
    live cipher and threaded into every backend, so no caller has to handle key material.

    ``posture`` (#200, ADR 0092) is the deriving instance's :class:`HopPosture`, threaded into the
    server-DB backends so the engine<->store weakened-TLS refusal (``connection_string`` / ``_build_ssl``)
    clamps the ``MEFOR_ALLOW_INSECURE_TLS`` escape on a production-PHI hop (decision 2). ``None`` (SQLite —
    no TLS — or a backup/restore utility / test) leaves it unclamped, byte-identical to pre-#200.
    """
    # The at-rest cipher via the single build_store_cipher seam: ADR 0019 key sourcing + the ADR 0138
    # cipher_provider dispatch. Default `aesgcm` is the in-process AES-256-GCM keyring (active + retired
    # decrypt-only, write_v2=aad_bind — which now defaults ON, so new writes are cell-bound mfenc:v2;
    # aad_bind=false selects the frozen v1 writer, byte-identical at rest). `vault_transit` runs the bulk
    # crypto inside Vault/OpenBao Transit so the DEK never enters heap (ASVS 13.3.3). No key → identity.
    cipher = build_store_cipher(settings)
    # #190: HKDF-derived HMAC key for the tamper-evident audit chain; None for the identity cipher (the
    # chain then stays the keyless SHA-256 chain, byte-identical to a pre-#190 store).
    audit_mac_key = cipher.audit_mac_key()
    # ADR 0138: an isolated-module audit MAC (Vault/OpenBao Transit generate_hmac) — set only by the
    # vault_transit cipher, so the chain is keyed even though no HMAC key ever enters heap. None for the
    # in-process (aesgcm/identity) ciphers, keeping their audit chain byte-identical. Wired into ALL
    # THREE backends (ASVS 13.3.3): `TransitCipher.audit_mac_key()` returns None BY DESIGN, so a server
    # backend given only `audit_mac_key` had no keying secret at all — under vault_transit its whole
    # chain ran UNKEYED (never even a keyless PREFIX: with no secret in hand the fresh-store watermark
    # was never written), while the posture claimed the most isolated MAC available. Every backend now
    # takes both and gates on "either secret present" (`_audit_keyed_capable`).
    audit_mac_fn = cipher.audit_mac_fn()
    if settings.backend is StoreBackend.SQLITE:
        return await MessageStore.open(
            settings.path,
            synchronous=settings.synchronous.value,
            cipher=cipher,
            group_commit_window_ms=settings.group_commit_window_ms,
            group_commit_max_batch=settings.group_commit_max_batch,
            audit_mac_key=audit_mac_key,
            audit_mac_fn=audit_mac_fn,
            message_events=message_events,
        )
    if settings.backend is StoreBackend.SQLSERVER:
        from messagefoundry.store.sqlserver import SqlServerStore  # lazy: optional aioodbc dep

        return await SqlServerStore.open(
            settings,
            cipher=cipher,
            audit_mac_key=audit_mac_key,
            audit_mac_fn=audit_mac_fn,
            message_events=message_events,
            posture=posture,
        )
    if settings.backend is StoreBackend.POSTGRES:
        from messagefoundry.store.postgres import PostgresStore  # lazy: optional asyncpg dep

        return await PostgresStore.open(
            settings,
            cipher=cipher,
            audit_mac_key=audit_mac_key,
            audit_mac_fn=audit_mac_fn,
            message_events=message_events,
            posture=posture,
        )
    raise NotImplementedError(f"store backend {settings.backend.value!r} is not implemented yet")


def backend_supports_reference_sets(backend: StoreBackend) -> bool:
    """Does ``backend`` implement the ADR 0006 reference-set snapshot store? — the OFFLINE twin of the
    :attr:`QueueStore.supports_reference_sets` capability flag.

    ``messagefoundry check`` has a DECLARED backend (``settings.store.backend``) but no live store and no
    DB to dial, so it cannot read the flag off an instance. It reads it off the store CLASS instead —
    lazy-imported exactly as :func:`open_store` does, which is import-safe because every backend defers its
    DB driver (aioodbc/asyncpg/pyodbc) to ``.open``. Going through the class keeps ONE source of truth, so
    the static gate cannot drift from the runtime gate (a backend that flips its flag flips both at once).

    An unknown backend returns ``False`` — fail-closed, matching the flag's allow-list default."""
    if backend is StoreBackend.SQLITE:
        return bool(MessageStore.supports_reference_sets)
    if backend is StoreBackend.POSTGRES:
        from messagefoundry.store.postgres import PostgresStore  # lazy: driver lives in .open

        return bool(PostgresStore.supports_reference_sets)
    if backend is StoreBackend.SQLSERVER:
        from messagefoundry.store.sqlserver import SqlServerStore  # lazy: driver lives in .open

        return bool(SqlServerStore.supports_reference_sets)
    return False


def sqlite_settings(path: str | Path, *, synchronous: str = "NORMAL") -> StoreSettings:
    """Build a SQLite ``StoreSettings`` (convenience for callers that only have a path)."""
    return StoreSettings(path=str(path), synchronous=SqliteSync(synchronous.lower()))


# Upper bound (seconds) on the background pool warm-up's release cleanup. A release over a dead
# connection (failover to a gone node) can hang; this bounds it so a stuck release can never hang
# stop()/re-promotion — on expiry a bounded partial strand is accepted (see _release_held). Generous
# headroom over a healthy release (sub-second) so we never abort a slow-but-live one and strand it.
_CLEANUP_TIMEOUT_SECONDS = 5.0


def warm_pool_target(maxsize: int, configured: int | None) -> int:
    """Resolve how many connections :func:`warm_pool_connections` should pre-open for a pool of
    ``maxsize``. An explicit ``configured`` count is clamped to ``maxsize - 1`` (always leave the pool a
    free slot); otherwise the default is ``min(maxsize - 1, maxsize // 2)`` so a warm never pins more than
    half the pool — leaving slots for the concurrent startup work (on-promotion recovery, the coordinator
    heartbeat, the first delivery workers). A pool of ``maxsize <= 1`` is never warmed (returns 0)."""
    if maxsize <= 1:
        return 0
    if configured is not None:
        return min(configured, maxsize - 1)
    # maxsize >= 2 here, so maxsize // 2 >= 1 — no lower clamp needed.
    return min(maxsize - 1, maxsize // 2)


# ADR 0062 — the store connection-pool inverted-U. On a shared server DB, over-provisioning the pool past
# the optimum thrashes it (WRITELOG serialization + per-message finalizer applocks) and COLLAPSES
# throughput; the catastrophic cliff is ~2x the optimum. These bound the soft over-provisioning warning.
POOL_SIZE_OPTIMUM = 40
POOL_SIZE_CLIFF = 80
_POOL_CONCURRENCY_PER_INBOUND = 2.5


def pool_over_provisioned_warning(pool_max_size: int, n_inbound: int) -> str | None:
    """A soft over-provisioning check for a **server-DB** connection pool (ADR 0062). Returns a warning
    string when ``pool_max_size`` looks oversized, else ``None``. SQLite has no pool, so the caller only
    invokes this when a pool exists (``Store.pool_status()`` is not ``None``). Two triggers:

    (a) **Cliff** — ``pool_max_size >= POOL_SIZE_CLIFF`` (~80), regardless of interface count: past this the
        extra connections thrash a shared instance and collapse throughput (the measured inverted-U).
    (b) **Idle over-provision** — above the optimum AND well beyond this engine's expected concurrency
        (~``2.5 x n_inbound``): the excess connections are dead-weight on a shared server DB.

    Pure + side-effect-free (the caller logs the message); the constants are the ADR 0062 findings. The
    default pool (``POOL_SIZE_OPTIMUM``) never warns — it is not > the optimum."""
    if pool_max_size >= POOL_SIZE_CLIFF:
        return (
            f"[store].pool_size={pool_max_size} is at/beyond the measured connection-pool cliff "
            f"(~{POOL_SIZE_CLIFF}): over-provisioning a shared server DB thrashes it (WRITELOG + finalizer "
            f"applock contention) and collapses throughput. The optimum is ~{POOL_SIZE_OPTIMUM} per engine — "
            f"scale by SHARDING (more engines), not a bigger pool. See ADR 0062."
        )
    demand = max(1, round(n_inbound * _POOL_CONCURRENCY_PER_INBOUND))
    if pool_max_size > POOL_SIZE_OPTIMUM and pool_max_size > demand:
        return (
            f"[store].pool_size={pool_max_size} looks over-provisioned for {n_inbound} inbound "
            f"interface(s) (~{demand} concurrent connections expected). Past ~{POOL_SIZE_OPTIMUM} the extra "
            f"connections are idle/contention on a shared server DB — consider lowering [store].pool_size. "
            f"See ADR 0062."
        )
    return None


# BACKLOG #1052 (ASVS 13.2.6) — bound a STORE pooled-connection borrow, the counterpart of the
# connector tier's ``transports/database.py::_DEFAULT_DB_ACQUIRE_TIMEOUT``. Same 30 s default, and the
# same reasoning inverted: the connector's pool is never legitimately exhausted (one worker per
# connection), whereas the store's pool IS legitimately contended by every lane — so 30 s is chosen to
# sit far above a healthy wait (the dogfood box measured 340-958 ms cold ODBC acquires; the B11
# acquire-wait histogram is the live signal) and to mean "the pool is wedged or the DB is
# unresponsive", not "the pool is busy". Operators retune it with ``[store].acquire_timeout``.
DEFAULT_STORE_ACQUIRE_TIMEOUT = 30.0


class StoreAcquireTimeout(RuntimeError):
    """A store pooled-connection borrow exceeded ``[store].acquire_timeout``.

    An ordinary ``Exception`` on purpose, so it lands in the store callers' existing ``except
    Exception`` handling and is treated as a transient stage failure (retry / dead-letter) — never a
    crashed connection or a lost message. Deliberately NOT a ``TimeoutError``: since Python 3.11 that
    is a subclass of ``OSError``, and connector-error handling elsewhere keys off ``OSError`` to mean
    "the network moved", which this is not. The message is numeric + PHI-free."""


def _salvage_late_borrow(pool: Any, backend: str, borrow: asyncio.Future[Any]) -> None:
    """Release a connection that arrived AFTER its borrower gave up (a done-callback on the shielded
    borrow task). Never raises — it runs on the event loop's callback path.

    Without this the bound would be a slow leak of the very resource it protects: the pool marks a
    connection in-use before handing it over, so a borrow abandoned mid-flight leaves a connection
    nobody holds and nobody can return, permanently shrinking a pool that is already wedged. This is
    the acquire-side counterpart of the leak-freedom invariant :func:`warm_pool_connections`
    documents, made explicit because ``asyncio.wait_for`` cannot provide it: on expiry it cancels the
    inner task, and a cancellation that lands in the same loop iteration the borrow resolves discards
    the already-acquired connection."""
    if borrow.cancelled() or borrow.exception() is not None:
        return  # the cancel won the race, or the borrow failed — nothing was handed over
    conn = borrow.result()

    async def _release() -> None:
        try:
            await pool.release(conn)
        except Exception:  # noqa: BLE001 - hygiene only; there is no caller left to inform
            log.debug("%s: releasing a late pool borrow failed", backend, exc_info=True)

    asyncio.ensure_future(_release())


async def acquire_pooled(pool: Any, *, timeout: float, backend: str) -> Any:
    """Borrow a pooled connection within ``timeout`` seconds, or raise :class:`StoreAcquireTimeout`.

    The single bounded chokepoint both server backends' ``_acquire`` helpers go through, so there is
    one place that decides what happens at the limit and the two cannot drift. The caller releases the
    connection exactly as it did when it used ``async with pool.acquire()``: both drivers' acquire
    context managers do nothing on exit but ``await pool.release(conn)`` (aioodbc 0.5.0
    ``utils.py:86-103``, asyncpg 0.31.0 ``pool.py:1059-1068``), so an explicit release is equivalent.

    **The borrow is shielded, then cancelled, then salvaged** — that ordering is the whole point.
    A bare ``asyncio.wait_for(pool.acquire(), timeout)`` cancels the borrow at the instant the timer
    fires, which races the pool's own mark-in-use step; ``shield`` moves the cancellation out of that
    race, and the explicit cancel afterwards keeps a wedged pool from accumulating one detached borrow
    per retry. Whichever of the two wins, :func:`_salvage_late_borrow` returns the connection if one
    was actually handed over. The caller's own cancellation takes the same path — it must, or a
    shutdown mid-borrow would strand a slot the pool never recovers."""
    borrow: asyncio.Future[Any] = asyncio.ensure_future(_as_awaitable(pool.acquire()))
    try:
        return await asyncio.wait_for(asyncio.shield(borrow), timeout)
    except TimeoutError as exc:
        borrow.cancel()
        borrow.add_done_callback(partial(_salvage_late_borrow, pool, backend))
        raise StoreAcquireTimeout(
            f"{backend}: store pool acquire timed out after {timeout:g}s "
            f"(pool exhausted or database unresponsive); retune with [store].acquire_timeout"
        ) from exc
    except asyncio.CancelledError:
        borrow.cancel()
        borrow.add_done_callback(partial(_salvage_late_borrow, pool, backend))
        raise


async def _as_awaitable(acquire: Any) -> Any:
    """Await whatever the driver's ``pool.acquire()`` returned. aioodbc hands back a ``_ContextManager``
    and asyncpg a ``PoolAcquireContext``; neither is a plain coroutine, and only this wrapper makes
    both safe to pass to ``ensure_future`` regardless of which awaitable shape a driver adopts next."""
    return await acquire


async def warm_pool_connections(pool: Any, *, target: int, timeout: float, backend: str) -> int:
    """Pre-establish up to ``target`` pooled connections CONCURRENTLY, then release them all, so a later
    burst (e.g. the post-promotion delivery workers in active-passive HA) finds them warm instead of
    paying a cold connect (TCP + TLS + login) on the hot path. Holding the connections **simultaneously**
    is what forces the pool to create them — a sequential acquire/release would only ever reuse one.
    Shared by the server backends (their pools differ only in how the maximum size is read); SQLite has
    no pool and overrides :meth:`QueueStore.warm_pool` with a no-op.

    Safe by construction: a per-connection connect failure is absorbed (the pool is left partially
    warm), the whole warm-up is bounded by ``timeout``, and every connection actually acquired is
    **always** released — even if a cancellation is delivered mid-cleanup — so warming can never strand a
    connection out of the pool. Returns the number warmed. The caller leaves headroom below the pool
    maximum so a concurrent startup caller is never starved while connections are held (see
    :func:`warm_pool_target`).

    **Cancellation-safe, bounded cleanup** (reliability-core): a re-fire (demote→re-promote) or ``stop()``
    cancel can land while we are suspended in ``await pool.release(...)`` — a real suspension point for
    both drivers (asyncpg reset / aioodbc rollback). Because the pool persists across a failover flap, an
    interrupted release would strand a slot the incoming leader term then can't use. So the drain+release
    runs as a **shielded** sub-task (a cancel can't interrupt it mid-loop) that is also **bounded** (a
    release stuck on a *dead* connection can't hang ``stop()``/re-promotion — both callers gather this
    task with no timeout). On the bound lapsing we accept a *bounded* partial strand rather than hang. See
    :func:`_release_held`.

    **Relied-upon invariant** (leak-freedom of the acquire side rests on it): ``pool.acquire()`` must
    mark the connection in-use atomically with returning it — true for ``asyncpg>=0.29`` and
    ``aioodbc>=0.5``. Combined with CPython's cancellation semantics (a ``CancelledError`` delivered while
    suspended at the ``await`` *raises* rather than yielding the already-resolved connection, so the
    post-``await`` append never runs), no half-acquired connection can escape ``held`` and leak.

    **Acquire-and-release ONLY** — this deliberately opens NO cursor and runs NO statement, so it neither
    needs nor uses the EF-6 ``_cursor`` close-before-release discipline. If a liveness probe (``SELECT 1``)
    is ever wanted on a warmed connection, route it through the backend's own ``_acquire``/``_cursor``
    wrapper, never the raw pool here."""
    if target <= 0:
        return 0
    held: list[Any] = []

    async def _acquire_one() -> None:
        # Append the instant it is acquired (a list append between awaits is atomic on the loop) so the
        # cleanup below releases it even if the gather is cancelled or times out mid-flight.
        held.append(await pool.acquire())

    tasks = [asyncio.create_task(_acquire_one()) for _ in range(target)]
    try:
        # return_exceptions=True: a single failed connect is a partial warm, not a raise.
        await asyncio.wait_for(asyncio.gather(*tasks, return_exceptions=True), timeout)
    except TimeoutError:
        log.warning(
            "%s: pool warm-up did not finish within %gs; continuing with a partially warm pool",
            backend,
            timeout,
        )
    finally:
        for task in tasks:
            task.cancel()
        await _release_held(pool, tasks, held, backend)
    return len(held)


async def _release_held(
    pool: Any, tasks: list[asyncio.Task[None]], held: list[Any], backend: str
) -> None:
    """Drain the (now-cancelled) acquire tasks and release every held connection, **shielded** so a
    cancellation delivered to the caller (a re-fire or ``stop()`` cancel) can't interrupt the release
    mid-way and strand a slot the incoming leader then needs. The release is **bounded** inside
    :func:`_drain_and_release` (so a release stuck on a dead node can't hang ``stop()``/re-promotion —
    both callers gather this task with no timeout), which lets ``cleanup`` resolve normally here; we just
    wait it out and re-raise any cancellation once the pool is clean."""
    cleanup = asyncio.ensure_future(_drain_and_release(pool, tasks, held, backend))
    cancelled = False
    while not cleanup.done():
        try:
            await asyncio.shield(cleanup)
        except asyncio.CancelledError:
            cancelled = True  # caller cancelled us; keep waiting for the (bounded) shielded cleanup
    if cancelled:
        raise asyncio.CancelledError


async def _drain_and_release(
    pool: Any, tasks: list[asyncio.Task[None]], held: list[Any], backend: str
) -> None:
    # Drain cancellations/exceptions so none are left unretrieved, then release every held connection
    # CONCURRENTLY (a sibling stuck on a dead connection must not block freeing the live ones) and
    # BOUNDED (``_CLEANUP_TIMEOUT_SECONDS``) so a release that hangs on a dead node can't hang stop()/
    # re-promotion. On the bound lapsing the stuck release(s) are abandoned — a bounded partial strand
    # the pool discards (the pool is closing at stop(), or re-grown at re-fire). The bound lives HERE so
    # the caller's ``cleanup`` task always resolves normally (a TimeoutError escaping a *shielded* future
    # would otherwise be logged at ERROR by the loop).
    await asyncio.gather(*tasks, return_exceptions=True)
    if not held:
        return
    releases = [asyncio.ensure_future(_release_one(pool, conn, backend)) for conn in held]
    try:
        await asyncio.wait_for(
            asyncio.gather(*releases, return_exceptions=True), _CLEANUP_TIMEOUT_SECONDS
        )
    except TimeoutError:
        log.warning(
            "%s: pool warm-up release did not finish within %gs; abandoning the stuck release(s) "
            "(a bounded partial strand the pool discards)",
            backend,
            _CLEANUP_TIMEOUT_SECONDS,
        )
        for release in releases:
            release.cancel()
        await asyncio.gather(*releases, return_exceptions=True)


async def _release_one(pool: Any, conn: Any, backend: str) -> None:
    try:
        await pool.release(conn)
    except Exception as exc:  # noqa: BLE001 - best-effort: a release error must not propagate
        log.warning("%s: pool warm-up connection release failed: %s", backend, exc)
