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
from collections.abc import Iterable, Mapping, Sequence
from pathlib import Path
from typing import Any, Protocol, runtime_checkable

from messagefoundry.config.models import RetryPolicy
from messagefoundry.config.settings import SqliteSync, StoreBackend, StoreSettings
from messagefoundry.store.content_search import (
    DEFAULT_SCAN_LIMIT,
    MAX_SCAN_LIMIT,
    ContentSearchError,
    SearchSpec,
    SearchTarget,
    make_spec,
)
from messagefoundry.store.crypto import CipherInfo, make_cipher
from messagefoundry.store.document_strip import StripResult
from messagefoundry.store.keyprovider import resolve_key_provider
from messagefoundry.store.pool_metrics import PoolStatus
from messagefoundry.store.store import (
    AlertInstance,
    CapturedResponse,
    ConnectionEvent,
    ConnectionMetrics,
    DbStatus,
    LatencyHistogram,
    MessageSearchResult,
    MessageStatus,
    MessageStore,
    OutboxItem,
    SessionRecord,
    Stage,
    UserRecord,
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
    "PoolStatus",
    "QueueStore",
    "Row",
    "SearchSpec",
    "SearchTarget",
    "Store",
    "StoreLifecycle",
    "make_spec",
    "open_store",
    "sqlite_settings",
    "warm_pool_connections",
    "warm_pool_target",
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
    #: ``False`` by default (this base, Postgres, SQL Server, and any future backend), ``True`` only on
    #: the SQLite backend that ships the slice. The engine rejects a graph containing a PT inbound at
    #: startup on any ``False`` backend (see :meth:`Engine.start`), so a Handler ``Send`` into a PT
    #: connector can never reach the unimplemented ``transform_handoff`` branch at runtime.
    supports_pt_reingress: bool = False

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
        now: float | None = None,
    ) -> str:
        """Durably persist a freshly-received raw message to the ingress stage (status ``RECEIVED`` +
        one ``stage='ingress'`` queue row) in one transaction — the staged pipeline's ACK-on-receipt
        boundary. The inbound may be ACKed once this returns. Returns the message id."""
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

    def set_leader_epoch(self, epoch: int | None, *, lease_key: str | None = None) -> None:
        """Push this node's currently-held **leader epoch** (the H1 fencing token) into the store so the
        FIFO claim can fence a superseded ex-leader, **inside** the existing single claim transaction.

        The engine calls this on promotion/demotion: it reads the value from the cluster coordinator
        (:meth:`ClusterCoordinator.current_epoch` / :meth:`ClusterCoordinator.lease_key`) and pushes it
        here, so the **store never imports the coordinator** (the one-way ARCH-6 dependency direction).
        ``epoch=None`` disables the guard (single-node / not yet leader / demoted) — the claim is then
        byte-identical to before H1. With a non-``None`` epoch the server-DB backends add
        ``leader_lease.leader_epoch <= :held`` to the claim's UPDATE so a paused/superseded ex-leader
        (whose held epoch is now strictly older than the live leader's) claims **0 rows**.

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

    async def mark_done(self, outbox_id: str, now: float | None = None) -> None: ...

    async def complete_with_response(
        self,
        outbox_id: str,
        *,
        body: str,
        outcome: str,
        detail: str | None = None,
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
        artifact) so the reply is re-ingressed; ``None`` is byte-identical to Increment 1 (no work-row)."""
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
    ) -> None: ...

    async def dead_letter_now(self, outbox_id: str, error: str, now: float | None = None) -> None:
        """Force one outbox row terminal (``DEAD``) immediately — **fail-fast**, no retry consumed
        and no backoff. For deliveries that can never succeed as-is and must not hold the FIFO lane:
        a permanent partner reject (``AR``), an internal/code error under the error-and-continue
        policy, or an undecryptable payload. Replayable via the dead-letter API like any dead row.
        Contrast :meth:`mark_failed`, which reschedules with backoff (and only dead-letters once a
        finite ``max_attempts`` is exhausted)."""
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

    async def reset_stale_inflight(
        self, now: float | None = None, *, stage: str | None = None
    ) -> int:
        """Return ``inflight`` rows (claimed before a crash) to ``pending``. ``stage=None`` (default)
        recovers every stage in one pass — the right startup behavior; pass a stage to scope it."""
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

    async def replay(self, message_id: str, now: float | None = None) -> int: ...

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
    ) -> Sequence[Row]: ...

    async def count_messages(
        self,
        *,
        channel_id: str | None = None,
        status: str | None = None,
        message_type: str | None = None,
        control_id: str | None = None,
        allowed_channels: Sequence[str] | None = None,
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
        now: float | None = None,
    ) -> None:
        """Record/fold one operator-alert occurrence into a resolvable ``alert_instance`` (ADR 0044),
        de-duped on ADR 0014's ``(event_type, connection)`` throttle key: if a live (``open`` or
        ``acknowledged``) instance for the key exists, bump ``last_seen`` + ``count`` (refresh
        ``severity``/``reason``; an acknowledged instance stays acknowledged); otherwise insert a fresh
        ``open`` row.

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

    # --- retention / purge + maintenance (PHI.md §8) -------------------------
    async def purge_message_bodies(
        self,
        *,
        older_than: float,
        now: float | None = None,
        connection_cutoffs: Mapping[str, float] | None = None,
    ) -> int:
        """Null PHI message bodies received before ``older_than`` (keeping metadata rows; the Mirth
        Data-Pruner pattern). ``connection_cutoffs`` (#34, ADR 0027) optionally overrides the cutoff
        per ``channel_id`` (``float('-inf')`` = keep forever); default empty ⇒ a single global cutoff,
        byte-identical to the prior behaviour. Returns the number purged."""
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

    async def wal_checkpoint(self) -> None: ...

    async def vacuum(self) -> None: ...

    # --- at-rest posture (M5) -------------------------------------------------
    def cipher_info(self) -> CipherInfo:
        """The **non-secret** at-rest cipher posture (M5): whether encryption is on and, if so, the
        active key's **fingerprint** (``active_key_id``) — never key bytes. The public accessor the M5
        ``GET /security/posture`` route reads instead of reaching a backend's private ``_cipher``."""
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
        now: float | None = None,
    ) -> None: ...

    async def list_audit(self, *, limit: int = 50) -> Sequence[Row]: ...

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
        self, approval_id: str, *, status: str, approver: str | None, decided_at: float
    ) -> bool: ...

    async def audit_anchor(self) -> tuple[int, str]: ...

    async def verify_audit_chain(
        self, *, expected_anchor: tuple[int, str] | None = None
    ) -> tuple[bool, str | None]: ...


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

    async def set_password(
        self,
        user_id: str,
        *,
        password_hash: str,
        must_change_password: bool = False,
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


async def open_store(settings: StoreSettings) -> Store:
    """Open the store for the configured backend — the single backend-selection seam.

    ``sqlite`` is the default; ``postgres`` is a production server-DB backend with single-node parity
    (lazy-imported, needs the ``postgres`` extra); ``sqlserver`` is a production server-DB backend,
    lazy-imported (needs the ``sqlserver`` extra). Unknown backends raise ``NotImplementedError``.
    """
    # AES-256-GCM keyring at rest when a key is set (STORE-1): active key (env or DPAPI key file) +
    # any retired decrypt-only keys for an in-progress rotation (WP-5). No key → identity cipher.
    retired = [k.strip() for k in settings.encryption_keys_retired.split(",") if k.strip()]
    cipher = make_cipher(resolve_active_key(settings), retired)
    if settings.backend is StoreBackend.SQLITE:
        return await MessageStore.open(
            settings.path,
            synchronous=settings.synchronous.value,
            cipher=cipher,
            group_commit_window_ms=settings.group_commit_window_ms,
            group_commit_max_batch=settings.group_commit_max_batch,
        )
    if settings.backend is StoreBackend.SQLSERVER:
        from messagefoundry.store.sqlserver import SqlServerStore  # lazy: optional aioodbc dep

        return await SqlServerStore.open(settings, cipher=cipher)
    if settings.backend is StoreBackend.POSTGRES:
        from messagefoundry.store.postgres import PostgresStore  # lazy: optional asyncpg dep

        return await PostgresStore.open(settings, cipher=cipher)
    raise NotImplementedError(f"store backend {settings.backend.value!r} is not implemented yet")


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
