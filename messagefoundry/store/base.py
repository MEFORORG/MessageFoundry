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

from collections.abc import Iterable, Mapping, Sequence
from pathlib import Path
from typing import Any, Protocol, runtime_checkable

from messagefoundry.config.models import RetryPolicy
from messagefoundry.config.settings import SqliteSync, StoreBackend, StoreSettings
from messagefoundry.store.crypto import make_cipher
from messagefoundry.store.store import (
    CapturedResponse,
    ConnectionMetrics,
    DbStatus,
    MessageStatus,
    MessageStore,
    OutboxItem,
    SessionRecord,
    Stage,
    UserRecord,
)

__all__ = [
    "AdminStore",
    "AuditStore",
    "AuthStore",
    "QueueStore",
    "Row",
    "Store",
    "StoreLifecycle",
    "open_store",
    "sqlite_settings",
]


class Row(Protocol):
    """A read result: key access + ``keys()`` (satisfied by ``aiosqlite.Row`` and ``dict``)."""

    def __getitem__(self, key: str) -> Any: ...
    def keys(self) -> Iterable[str]: ...


class StoreLifecycle(Protocol):
    """Open-store handle basics shared by every backend."""

    path: str

    async def close(self) -> None: ...


class QueueStore(StoreLifecycle, Protocol):
    """The durable message inbox/outbox queue — the contract the engine + message routes use.

    Covers the transactional write path, the per-destination delivery worker, recovery/replay, the
    read helpers the API/console render, and store-health/metrics. Deliberately excludes auth and the
    audit log so a queue consumer cannot reach them.
    """

    #: Whether this backend implements the staged ingress pipeline (``enqueue_ingress``/``handoff``).
    #: ``False`` backends (e.g. SQL Server, gated on BACKLOG #1) are rejected at engine start rather
    #: than trapping the first received message in a ``NotImplementedError``.
    supports_ingest_stage: bool

    #: Whether this backend can capture request/response replies (ADR 0013: the ``response`` table +
    #: :meth:`complete_with_response`). ``True`` on SQLite/Postgres/SQL Server; a backend returning
    #: ``False`` makes the runner reject a capturing outbound at start (fail-closed) rather than drop
    #: captures.
    supports_response_capture: bool

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
        :meth:`transform_handoff` instead."""
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
        now: float | None = None,
    ) -> bool:
        """Advance one handler assignment from the **routed** stage to outbound in one transaction (the
        transform half of the split pipeline, ADR 0001 Step B): consume the in-flight routed row,
        insert one outbound row per delivery, **apply each declared state write** (``state_ops``:
        ``(namespace, key, value)`` upserts, ADR 0005), and let the finalizer recompute the terminal
        disposition (this method never writes ``messages.status`` directly). The state writes commit
        atomically with the outbound rows, so a crash before commit leaves no state and a re-run applies
        them exactly-once (preserving the pure-re-run invariant). Idempotent against worker restart —
        ``False`` if the routed row was already consumed."""
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
        owner: str | None = None,
    ) -> OutboxItem | None:
        """Claim the single oldest *due* pending row for one lane at ``stage`` (strict FIFO; the head
        blocks the lane while it backs off). The lane key is stage-aware: ``destination_name`` for
        outbound, ``channel_id`` for ingress. ``None`` when nothing is pending or the head isn't due.

        ``owner`` is this node's cluster identity (Track B Step 5 lane ownership): ``None`` single-node
        (the byte-identical path; SQLite/SQL Server always ignore it), or the coordinator's node_id
        when clustered, gating the claim by an atomic per-lane lease so a FIFO lane is processed by
        exactly one node at a time and strict per-lane FIFO holds across nodes."""
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
        behind the audited, body-gated ``GET /messages/{id}/responses`` route."""
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

    async def stats(self) -> dict[str, int]: ...

    async def in_pipeline_depth(self) -> int:
        """Count of NOT-DONE rows (status ``pending``|``inflight``) across **every** stage
        (ingress + routed + outbound) — a whole-pipeline drain gauge, vs :meth:`stats` which sees only
        the outbound stage. Lets a consumer tell a true drain from a stalled router/transform."""
        ...

    # --- at-rest key rotation (PHI.md §3, ASVS 11.2.2) -----------------------
    async def reencrypt_to_active(self, *, batch: int = 500) -> int: ...

    # --- retention / purge + maintenance (PHI.md §8) -------------------------
    async def purge_message_bodies(self, *, older_than: float, now: float | None = None) -> int: ...

    async def purge_dead_letters(self, *, older_than: float, now: float | None = None) -> int: ...

    async def purge_state(self, *, older_than: float, now: float | None = None) -> int:
        """Delete transform-state entries (ADR 0005) last written before ``older_than`` (age-based
        retention). Returns the number purged. Off unless ``[retention].state_max_age_days`` is set."""
        ...

    async def wal_checkpoint(self) -> None: ...

    async def vacuum(self) -> None: ...

    # --- store health / metrics ----------------------------------------------
    async def db_status(self) -> DbStatus: ...

    async def integrity_check(self) -> tuple[bool, str]: ...

    async def connection_metrics(
        self, *, since: float, now: float | None = None, rate_window: float = 60.0
    ) -> ConnectionMetrics: ...


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
    ) -> None: ...

    async def list_roles(self) -> Sequence[Row]: ...

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
    """The effective base64 active key: ``encryption_key`` (env/config) if set, else the Windows
    DPAPI-protected ``encryption_key_file`` decrypted (WP-11d). ``None`` when neither is configured
    (→ identity cipher). The env key takes precedence so a deployment can override the file. A
    configured-but-unreadable/foreign key file raises ``DpapiError`` here — fail-closed, not silently
    unencrypted."""
    if settings.encryption_key:
        return settings.encryption_key
    if settings.encryption_key_file:
        from messagefoundry.secrets_dpapi import load_protected_key

        return load_protected_key(settings.encryption_key_file)
    return None


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
            settings.path, synchronous=settings.synchronous.value, cipher=cipher
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
