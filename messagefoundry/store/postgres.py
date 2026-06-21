# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""PostgreSQL implementation of the :class:`~messagefoundry.store.base.Store` protocol.

A **production** server-database backend with single-node parity to the SQLite
:class:`~messagefoundry.store.store.MessageStore`: it implements the **full** staged pipeline
(ingress → routed → outbound, ADR 0001 Step B; ``supports_ingest_stage = True``), the transform-state
read-through cache (ADR 0005), reference snapshots (ADR 0006), at-rest encryption/rotation (STORE-1 /
WP-5), and retention purges. It replicates every semantic of the SQLite reference — most importantly
the finalizer's ROUTED→FILTERED collapse in :meth:`_maybe_finalize_message`.

Concurrency is handled by Postgres row-locking: the staged claims use ``FOR UPDATE SKIP LOCKED`` so
independent workers don't block or double-claim (correct for a single node today, and the foundation
for multi-node leases in Track B Step 2). This phase is single-node parity — there is **no** lease
fencing yet — but per-message finalize, the audit chain, and schema init are serialized with Postgres
**advisory locks** so the four known SQL-Server-backend concurrency bugs are fixed by construction:

* **H-6** — the pool sets ``command_timeout`` so a statement actually times out (the SQL Server
  backend's per-connection timeout was inert on some drivers).
* **H-7** — ``record_audit`` and ``_backfill_audit_chain`` take ``pg_advisory_xact_lock`` on the audit
  chain before read-tail + insert, so concurrent writers can't fork the chain.
* **H-8** — :meth:`_maybe_finalize_message` ports the full multi-stage finalizer (not the simpler
  outbound-only one) and is serialized per ``message_id`` with a per-message advisory lock, so it
  re-counts on a fresh snapshot — no double-finalize; different ids never contend. A finalizer that
  spans **more than one** message (``cancel_queued`` and the dead-letter sweeps) pre-acquires every
  per-message lock up front in a **canonical (sorted) order** via :meth:`_lock_finalize_batch`, so two
  such callers with overlapping message sets can't form a lock cycle (no multi-message deadlock). The
  per-message lock only mutually-excludes finalize-vs-finalize; the direct ``messages.status`` writers
  (``handoff``/``route_handoff``/``replay``/``replay_dead``) are pipeline-ordered to never overlap a
  finalize for the same id (the router produces the routed rows a later transform consumes+finalizes),
  so they don't take it — narrower than SQLite's global single-writer lock, but safe by ordering.
* **M-6** — every multi-statement write runs inside ``async with conn.transaction():`` (asyncpg
  auto-rolls-back on exception), so a failed statement can't strand a half-open txn on a pooled
  connection.

``asyncpg`` is an **optional extra** (``pip install 'messagefoundry[postgres]'``); it's imported
lazily in :meth:`PostgresStore.open` so SQLite-only installs never touch it. Placeholders are
``$1,$2,…`` and variable-length IN-lists use ``= ANY($n)`` (never a dynamically-built ``IN (?,?)``).
"""

from __future__ import annotations

import json
import logging
import os
import socket
import time
from collections.abc import Iterable, Mapping, Sequence
from types import MappingProxyType
from typing import Any
from uuid import uuid4

from messagefoundry.config.models import RetryPolicy
from messagefoundry.config.settings import (
    INSECURE_TLS_ESCAPE_ENV,
    StoreSettings,
    insecure_tls_allowed,
)
from messagefoundry.redaction import safe_text
from messagefoundry.store.audit_tee import emit_audit_tee
from messagefoundry.store.base import Row
from messagefoundry.store.crypto import PREFIX as _ENC_PREFIX
from messagefoundry.store.crypto import AesGcmCipher, Cipher, CipherError, IdentityCipher
from messagefoundry.store.store import (
    ConnectionMetrics,
    DbStatus,
    DestinationMetrics,
    InboundMetrics,
    LatencyHistogram,
    CapturedResponse,
    MessageStatus,
    MessageStore,
    OutboxItem,
    OutboxStatus,
    SessionRecord,
    Stage,
    UserRecord,
    audit_row_hash,
)

log = logging.getLogger(__name__)

# Advisory-lock keys passed to the TWO-key pg_advisory_xact_lock(classid, hashtext($key)). They
# serialize the audit-chain append (H-7) and schema init across concurrent opens; the finalize lock is
# per-message (its key is built from the message id) so different messages never contend (H-8). A
# distinct integer ``classid`` per family partitions the 32-bit hashtext space, so an audit/schema key
# can never hash-collide with a finalize key (only same-family same-hash keys can still collide, which
# is acceptable). The key strings are namespaced by db_schema at runtime (see ``_lock_key``) so two
# deployments sharing one database via different schemas don't share lock identity.
_LOCK_CLASS_AUDIT = 1
_LOCK_CLASS_SCHEMA = 2
_LOCK_CLASS_FINALIZE = 3
_AUDIT_LOCK = "mefor_audit_chain"
_SCHEMA_LOCK = "mefor_schema_init"
_FINALIZE_LOCK_PREFIX = "mefor_finalize:"

# Schema (PostgreSQL). All DDL is `IF NOT EXISTS`, run once under the schema advisory lock so
# concurrent opens don't race on CREATE. Epoch timestamps are DOUBLE PRECISION; ids TEXT (uuid4 hex);
# bodies/PHI columns TEXT; booleans BOOLEAN; auto-ids BIGSERIAL. The `queue.seq` BIGSERIAL is the FIFO
# tiebreak that replaces SQLite's implicit rowid (same-transaction inserts get increasing seq, so
# handler-list order survives ORDER BY created_at, seq).
_SCHEMA: list[str] = [
    """CREATE TABLE IF NOT EXISTS messages (
        id           TEXT PRIMARY KEY,
        channel_id   TEXT NOT NULL,
        received_at  DOUBLE PRECISION NOT NULL,
        source_type  TEXT,
        control_id   TEXT,
        message_type TEXT,
        raw          TEXT NOT NULL,
        status       TEXT NOT NULL,
        error        TEXT,
        summary      TEXT,
        metadata     TEXT
    )""",
    "CREATE INDEX IF NOT EXISTS ix_messages_channel ON messages(channel_id, received_at)",
    "CREATE INDEX IF NOT EXISTS ix_messages_control ON messages(channel_id, control_id)",
    """CREATE TABLE IF NOT EXISTS queue (
        id               TEXT PRIMARY KEY,
        message_id       TEXT NOT NULL REFERENCES messages(id),
        stage            TEXT NOT NULL,
        channel_id       TEXT NOT NULL,
        destination_name TEXT,
        handler_name     TEXT,
        payload          TEXT NOT NULL,
        status           TEXT NOT NULL,
        attempts         INTEGER NOT NULL DEFAULT 0,
        next_attempt_at  DOUBLE PRECISION NOT NULL,
        last_error       TEXT,
        created_at       DOUBLE PRECISION NOT NULL,
        updated_at       DOUBLE PRECISION NOT NULL,
        seq              BIGSERIAL,
        owner            TEXT,
        lease_expires_at DOUBLE PRECISION
    )""",
    # Track B Step 2: additive multi-node row-lease columns. NULL while a row is pending/terminal; set
    # only while inflight (owner = the claiming store instance, lease_expires_at = claim time + TTL).
    # CREATE TABLE above declares them on a fresh DB; a pre-existing Step-1 `queue` table is migrated
    # by the guarded one-shot ADD COLUMN in _migrate_lease_columns (NOT a per-open ALTER, which would
    # take ACCESS EXCLUSIVE on `queue` every startup).
    "CREATE INDEX IF NOT EXISTS ix_queue_ready ON queue(stage, status, next_attempt_at)",
    "CREATE INDEX IF NOT EXISTS ix_queue_fifo_out"
    " ON queue(stage, destination_name, status, created_at, seq)",
    "CREATE INDEX IF NOT EXISTS ix_queue_fifo_in"
    " ON queue(stage, channel_id, status, created_at, seq)",
    "CREATE INDEX IF NOT EXISTS ix_queue_message ON queue(message_id)",
    # ix_queue_lease (the reclaim sweep's index) is created in _migrate_lease_columns, AFTER the lease
    # columns are guaranteed present — on a Step-1 table the index references a not-yet-added column.
    """CREATE TABLE IF NOT EXISTS message_events (
        id          BIGSERIAL PRIMARY KEY,
        message_id  TEXT NOT NULL REFERENCES messages(id),
        ts          DOUBLE PRECISION NOT NULL,
        event       TEXT NOT NULL,
        destination TEXT,
        detail      TEXT
    )""",
    "CREATE INDEX IF NOT EXISTS ix_events_message ON message_events(message_id, ts)",
    """CREATE TABLE IF NOT EXISTS state (
        namespace  TEXT NOT NULL,
        key        TEXT NOT NULL,
        value      TEXT NOT NULL,
        set_at     DOUBLE PRECISION NOT NULL,
        message_id TEXT,
        PRIMARY KEY (namespace, key)
    )""",
    "CREATE INDEX IF NOT EXISTS ix_state_set_at ON state(set_at)",
    """CREATE TABLE IF NOT EXISTS reference (
        name    TEXT NOT NULL,
        version TEXT NOT NULL,
        key     TEXT NOT NULL,
        value   TEXT NOT NULL,
        PRIMARY KEY (name, version, key)
    )""",
    "CREATE INDEX IF NOT EXISTS ix_reference_name ON reference(name)",
    """CREATE TABLE IF NOT EXISTS reference_version (
        name      TEXT PRIMARY KEY,
        version   TEXT NOT NULL,
        synced_at DOUBLE PRECISION NOT NULL,
        row_count INTEGER NOT NULL
    )""",
    # Captured request/response replies (ADR 0013) — immutable artifact, NOT a queue stage, so it is
    # invisible to _maybe_finalize_message's `FROM queue` scan. response_seq is replay-stable (1+MAX,
    # not queue.attempts which replay resets). body/detail are cipher-encrypted at rest (PHI).
    """CREATE TABLE IF NOT EXISTS response (
        message_id       TEXT NOT NULL REFERENCES messages(id),
        destination_name TEXT NOT NULL,
        response_seq     INTEGER NOT NULL,
        body             TEXT,
        outcome          TEXT NOT NULL,
        detail           TEXT,
        captured_at      DOUBLE PRECISION NOT NULL,
        PRIMARY KEY (message_id, destination_name, response_seq)
    )""",
    "CREATE INDEX IF NOT EXISTS ix_response_message ON response(message_id)",
    """CREATE TABLE IF NOT EXISTS audit_log (
        id         BIGSERIAL PRIMARY KEY,
        ts         DOUBLE PRECISION NOT NULL,
        actor      TEXT,
        action     TEXT NOT NULL,
        channel_id TEXT,
        detail     TEXT,
        row_hash   TEXT
    )""",
    "CREATE INDEX IF NOT EXISTS ix_audit_ts ON audit_log(ts)",
    """CREATE TABLE IF NOT EXISTS pending_approvals (
        id           TEXT PRIMARY KEY,
        operation    TEXT NOT NULL,
        params       TEXT NOT NULL,
        requester    TEXT NOT NULL,
        requested_at DOUBLE PRECISION NOT NULL,
        status       TEXT NOT NULL DEFAULT 'pending',
        approver     TEXT,
        decided_at   DOUBLE PRECISION,
        expires_at   DOUBLE PRECISION
    )""",
    "CREATE INDEX IF NOT EXISTS ix_pending_approvals_status"
    " ON pending_approvals(status, requested_at)",
    """CREATE TABLE IF NOT EXISTS users (
        id                   TEXT PRIMARY KEY,
        username             TEXT NOT NULL UNIQUE,
        auth_provider        TEXT NOT NULL,
        display_name         TEXT,
        email                TEXT,
        disabled             BOOLEAN NOT NULL DEFAULT FALSE,
        created_at           DOUBLE PRECISION NOT NULL,
        updated_at           DOUBLE PRECISION NOT NULL,
        last_login_at        DOUBLE PRECISION,
        password_hash        TEXT,
        password_changed_at  DOUBLE PRECISION,
        must_change_password BOOLEAN NOT NULL DEFAULT FALSE,
        failed_attempts      INTEGER NOT NULL DEFAULT 0,
        locked_until         DOUBLE PRECISION,
        channel_scope        TEXT,
        totp_secret          TEXT,
        totp_enabled         BOOLEAN NOT NULL DEFAULT FALSE,
        totp_enrolled_at     DOUBLE PRECISION,
        totp_recovery_codes  TEXT,
        last_totp_step       INTEGER
    )""",
    """CREATE TABLE IF NOT EXISTS roles (
        id           TEXT PRIMARY KEY,
        display_name TEXT NOT NULL,
        description  TEXT,
        builtin      BOOLEAN NOT NULL DEFAULT TRUE
    )""",
    """CREATE TABLE IF NOT EXISTS user_roles (
        user_id     TEXT NOT NULL REFERENCES users(id),
        role_id     TEXT NOT NULL REFERENCES roles(id),
        assigned_at DOUBLE PRECISION NOT NULL,
        assigned_by TEXT,
        PRIMARY KEY (user_id, role_id)
    )""",
    """CREATE TABLE IF NOT EXISTS ad_group_role_map (
        ad_group TEXT NOT NULL,
        role_id  TEXT NOT NULL REFERENCES roles(id),
        PRIMARY KEY (ad_group, role_id)
    )""",
    """CREATE TABLE IF NOT EXISTS ad_group_scope_map (
        ad_group TEXT NOT NULL,
        channel  TEXT NOT NULL,
        PRIMARY KEY (ad_group, channel)
    )""",
    """CREATE TABLE IF NOT EXISTS sessions (
        token_hash   TEXT PRIMARY KEY,
        user_id      TEXT NOT NULL REFERENCES users(id),
        created_at   DOUBLE PRECISION NOT NULL,
        expires_at   DOUBLE PRECISION NOT NULL,
        last_used_at DOUBLE PRECISION NOT NULL,
        revoked_at   DOUBLE PRECISION,
        client       TEXT,
        reauth_at    DOUBLE PRECISION,
        mfa_verified_at DOUBLE PRECISION
    )""",
    "CREATE INDEX IF NOT EXISTS ix_sessions_user ON sessions(user_id)",
    "CREATE INDEX IF NOT EXISTS ix_sessions_expires ON sessions(expires_at)",
    # Track B Step 6: the cluster-wide CONFIG-RELOAD version token. A single-row table (id always 1)
    # holding a monotonically-increasing config_version: an operator reload on one node bumps it, and
    # every other node's config-convergence loop sees the higher version and reloads its OWN (identically
    # deployed) config dir to converge. The DbCoordinator owns it (read/cache/bump); it lands in
    # db_schema via the pool's search_path like every other table. CREATE TABLE IF NOT EXISTS is safe on
    # a fresh OR existing DB (no ALTER/migration).
    """CREATE TABLE IF NOT EXISTS cluster_config (
        id              INTEGER PRIMARY KEY,
        config_version  BIGINT NOT NULL,
        updated_at      DOUBLE PRECISION NOT NULL
    )""",
    # Track B Step 6b: the per-namespace transform-STATE version token (mirrors reference_version's role
    # for reference sets). A clustered node's transform_handoff bumps a namespace's version in the SAME
    # txn as its state writes; every other node's state-convergence loop sees the higher version and
    # read-throughs that whole namespace's rows from the shared state table into its OWN _state_cache. So
    # a sibling's transform-state write reaches every node without each node re-reading the state table.
    # Single-node never bumps (the gate is off), so this table stays empty and behaviour is byte-identical.
    # CREATE TABLE IF NOT EXISTS is safe on a fresh OR existing DB (no ALTER/migration) and lands in
    # db_schema via the pool's search_path like every other table.
    """CREATE TABLE IF NOT EXISTS state_version (
        namespace  TEXT PRIMARY KEY,
        version    BIGINT NOT NULL,
        updated_at DOUBLE PRECISION NOT NULL
    )""",
]


def _build_ssl(settings: StoreSettings) -> Any:
    """Build the asyncpg ``ssl`` arg from the store settings, mirroring the SQL Server backend's
    refuse-weakened-TLS logic (ASVS 12.3.2).

    A weakened posture (``trust_server_certificate=true`` or ``encrypt=false``) is MITM-able, so it
    **refuses** unless the explicit ``MEFOR_ALLOW_INSECURE_TLS`` dev escape is set — it can't be
    silently turned on in production. Returns the ``ssl`` value to pass to ``asyncpg.create_pool``:
    ``False`` (no TLS) only under the escape with ``encrypt=false``; an SSLContext that skips cert
    verification under the escape with ``trust_server_certificate=true``; otherwise a default
    verifying SSLContext (``True``)."""
    if (settings.trust_server_certificate or not settings.encrypt) and not insecure_tls_allowed():
        raise ValueError(
            "Postgres TLS is weakened (trust_server_certificate=true or encrypt=false), which is "
            f"MITM-able. Use a trusted server certificate, or set {INSECURE_TLS_ESCAPE_ENV}=1 to "
            "explicitly allow it for a trusted-network dev/test bind."
        )
    if not settings.encrypt:
        return False  # escape set (checked above) — plaintext connection, dev/test only
    if settings.trust_server_certificate:
        import ssl as _ssl

        # escape set (checked above) — encrypt but skip server-cert verification (trusted-net dev).
        ctx = _ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = _ssl.CERT_NONE
        return ctx
    return True  # verifying TLS (the secure default)


class PostgresStore:
    """PostgreSQL-backed durable queue (the :class:`Store` protocol). Open with :meth:`open`."""

    # Postgres implements the full staged ingress pipeline (enqueue_ingress/route_handoff/
    # transform_handoff), so the engine starts the staged runner on this backend.
    supports_ingest_stage = True

    # Postgres implements request/response capture (ADR 0013: the `response` table +
    # complete_with_response), with the same single-transaction atomicity as SQLite.
    supports_response_capture = True

    #: Every (table, column) the store cipher covers — raw bodies plus the PHI-bearing nullable text
    #: columns (error/last_error/detail). Used by the on-open migration and rotate-key (mirrors
    #: MessageStore._CIPHER_COLUMNS).
    _CIPHER_COLUMNS = (
        ("messages", "raw"),
        ("queue", "payload"),
        ("messages", "error"),
        ("queue", "last_error"),
        ("message_events", "detail"),
        ("users", "totp_secret"),  # MFA secret (WP-14) — id-keyed, rides the migration + rotation
        # NB: the `response` table (ADR 0013) is cipher-covered (body, detail) but has a COMPOSITE PK,
        # so it rides the composite helpers below, not this id-keyed list (like state/reference).
    )

    def __init__(self, pool: Any, settings: StoreSettings, *, cipher: Cipher | None = None) -> None:
        self._pool = pool
        self._settings = settings
        self._cipher: Cipher = cipher or IdentityCipher()
        self.path = f"{settings.server}/{settings.database}"  # descriptor for db_status
        # Track B Step 2: the identity stamped on a row's lease when THIS instance claims it (host:pid
        # + a short random suffix so two stores in one process still differ). reclaim_expired_leases /
        # recover_inflight_on_promotion use it to recover only OTHER (prior-leader) instances' rows and
        # never steal a live node's own in-flight row.
        self._owner = f"{socket.gethostname()}:{os.getpid()}:{uuid4().hex[:8]}"
        # Read-through caches (loaded at open; updated only after the owning txn commits) — mirror the
        # SQLite store's _state_cache / _reference_cache so a Handler's synchronous state_get(...) /
        # reference("name").get(key) resolves.
        self._state_cache: dict[tuple[str, str], Any] = {}
        self._reference_cache: dict[str, dict[str, Any]] = {}
        # The active reference VERSION currently reflected in _reference_cache, per set (Track B Step 6).
        # converge_reference_cache() compares the shared store's authoritative active version against
        # this to decide which sets a FOLLOWER must re-load (read-through), so a leader-materialized
        # snapshot reaches every node without each node re-reading the external source. Populated at
        # open (_load_reference_cache) and on every write_reference_snapshot.
        self._reference_versions: dict[str, str] = {}
        # Per-namespace version this node's _state_cache reflects (Track B Step 6b). converge_state_cache()
        # compares the shared store's authoritative state_version against this to decide which namespaces a
        # FOLLOWER must re-read (read-through), mirroring _reference_versions for reference sets. Seeded at
        # open (_load_state_cache) and advanced on every gated transform_handoff/purge_state bump.
        self._state_versions: dict[str, int] = {}
        # Gates the in-txn state-version bump. The engine flips it on (enable_state_convergence) only when
        # clustered, BEFORE workers start; single-node never turns it on, so no state_version rows are ever
        # written and the backend stays byte-identical.
        self._cluster_state_convergence: bool = False

    @classmethod
    async def open(
        cls, settings: StoreSettings, *, cipher: Cipher | None = None
    ) -> "PostgresStore":
        try:
            import asyncpg
        except ImportError as exc:  # pragma: no cover - exercised only without the extra
            raise RuntimeError(
                "Postgres backend requires the 'postgres' extra: "
                "pip install 'messagefoundry[postgres]'"
            ) from exc
        server_settings = {"application_name": settings.application_name}
        if settings.db_schema:
            # Resolve unqualified table names against the configured schema (it must already exist).
            server_settings["search_path"] = settings.db_schema
        pool = await asyncpg.create_pool(
            host=settings.server,
            port=settings.port,
            database=settings.database,
            user=settings.username,
            password=settings.password,
            ssl=_build_ssl(settings),
            min_size=1,
            max_size=max(1, settings.pool_size),
            timeout=settings.connect_timeout,  # connection-acquire/connect timeout (seconds)
            # H-6: a real per-statement timeout (>0) so a hung statement actually times out, unlike
            # the SQL Server backend's inert per-connection attribute. 0 = no limit (asyncpg: None).
            command_timeout=(settings.command_timeout or None),
            server_settings=server_settings,
        )
        store = cls(pool, settings, cipher=cipher)
        await store._ensure_schema()
        await store._encrypt_existing_rows()  # one-time PHI-at-rest migration when a key is set
        await store._backfill_audit_chain()  # chain any pre-existing (unhashed) audit rows
        await (
            store._load_state_cache()
        )  # populate the in-memory state read-through cache (ADR 0005)
        await store._load_reference_cache()  # populate the reference-snapshot read cache (ADR 0006)
        return store

    async def _ensure_schema(self) -> None:
        """Create the schema once, serialized across concurrent opens by a schema advisory lock so
        two processes can't race the DDL (the lock auto-releases at txn end)."""
        async with self._pool.acquire() as conn:
            async with conn.transaction():
                await self._advisory_lock(conn, _LOCK_CLASS_SCHEMA, _SCHEMA_LOCK)
                for statement in _SCHEMA:
                    await conn.execute(statement)
                await self._migrate_lease_columns(conn)

    async def _migrate_lease_columns(self, conn: Any) -> None:
        """Track B Step 2: add the lease columns to a pre-existing Step-1 ``queue`` table, but ONLY if
        they are actually missing. ``ALTER TABLE ... ADD COLUMN IF NOT EXISTS`` is a no-op on an
        already-migrated table yet still takes an ACCESS EXCLUSIVE lock on ``queue`` to inspect the
        catalog — far heavier than the neighbouring ``CREATE INDEX IF NOT EXISTS`` and run on EVERY
        open. Gating on ``information_schema`` keeps re-opens of an already-migrated DB lock-free
        (this runs under the schema advisory lock alongside the CREATEs). Also creates the lease
        index here — AFTER the columns are guaranteed present — since on a Step-1 table the index
        would reference a not-yet-added column if it lived in the _SCHEMA loop."""
        present = {
            r["column_name"]
            for r in await conn.fetch(
                "SELECT column_name FROM information_schema.columns"
                " WHERE table_name='queue' AND column_name = ANY($1::text[])",
                ["owner", "lease_expires_at"],
            )
        }
        if "owner" not in present:
            await conn.execute("ALTER TABLE queue ADD COLUMN owner TEXT")
        if "lease_expires_at" not in present:
            await conn.execute("ALTER TABLE queue ADD COLUMN lease_expires_at DOUBLE PRECISION")
        # The reclaim sweep scans inflight rows by lease expiry (reclaim_expired_leases). Partial:
        # only inflight rows carry a lease, so the index needn't cover the pending/terminal majority.
        await conn.execute(
            "CREATE INDEX IF NOT EXISTS ix_queue_lease ON queue(lease_expires_at)"
            " WHERE status='inflight'"
        )
        # Step-up re-verification (ASVS 7.5.3) adds sessions.reauth_at; pre-existing rows get NULL.
        sessions_has_reauth = await conn.fetch(
            "SELECT 1 FROM information_schema.columns"
            " WHERE table_name='sessions' AND column_name='reauth_at'"
        )
        if not sessions_has_reauth:
            await conn.execute("ALTER TABLE sessions ADD COLUMN reauth_at DOUBLE PRECISION")
        # MFA (WP-14): TOTP columns on users + sessions.mfa_verified_at on a pre-existing DB. Column
        # names are static literals (not user input). Idempotent: skipped once present.
        users_cols = {
            r["column_name"]
            for r in await conn.fetch(
                "SELECT column_name FROM information_schema.columns WHERE table_name='users'"
            )
        }
        for column, decl in (
            ("totp_secret", "TEXT"),
            ("totp_enabled", "BOOLEAN NOT NULL DEFAULT FALSE"),
            ("totp_enrolled_at", "DOUBLE PRECISION"),
            ("totp_recovery_codes", "TEXT"),
            ("last_totp_step", "INTEGER"),
        ):
            if column not in users_cols:
                await conn.execute(f"ALTER TABLE users ADD COLUMN {column} {decl}")
        sessions_has_mfa = await conn.fetch(
            "SELECT 1 FROM information_schema.columns"
            " WHERE table_name='sessions' AND column_name='mfa_verified_at'"
        )
        if not sessions_has_mfa:
            await conn.execute("ALTER TABLE sessions ADD COLUMN mfa_verified_at DOUBLE PRECISION")
        # Active-active scale-out was dropped: drop the retired per-lane FIFO-ownership table from any DB
        # that was opened by an earlier build. Failover FIFO safety no longer depends on a lane lease —
        # claim_next_fifo reclaims a stranded head from the queue table directly. IF EXISTS is a no-op on
        # a fresh DB / a DB already migrated; runs under the schema advisory lock alongside the CREATEs.
        await conn.execute("DROP TABLE IF EXISTS lane_leases")

    async def close(self) -> None:
        await self._pool.close()

    # --- PHI-at-rest cipher seam for nullable text columns (WP-5) -------------

    def _enc(self, value: str | None) -> str | None:
        if not value:  # None or "" → leave blank (covers purged/empty values)
            return value
        return self._cipher.encrypt(value)

    def _dec(self, value: str | None) -> str | None:
        if value is None:
            return value
        return self._cipher.decrypt(value)  # '' and legacy plaintext pass through unchanged

    def _decode_record(self, record: Any, *columns: str) -> dict[str, Any]:
        """Materialize an ``asyncpg.Record`` as a dict and decrypt the named cipher-covered text
        columns (mirrors MessageStore._decode_row)."""
        d = dict(record)
        for col in columns:
            if col in d:
                d[col] = self._dec(d[col])
        return d

    # --- advisory-lock helpers -----------------------------------------------

    def _lock_key(self, key: str) -> str:
        """Namespace an advisory-lock key by the configured schema so two deployments sharing one
        database via different ``db_schema`` values don't share lock identity (advisory locks are
        database-scoped, not schema-scoped)."""
        return f"{self._settings.db_schema or 'public'}:{key}"

    async def _advisory_lock(self, conn: Any, classid: int, key: str) -> None:
        """Take a transaction-scoped advisory lock in the ``classid`` family (auto-released at commit).
        Uses the two-key form so each family has its own 32-bit hashtext namespace (no cross-family
        collisions)."""
        await conn.execute(
            "SELECT pg_advisory_xact_lock($1, hashtext($2))", classid, self._lock_key(key)
        )

    async def _lock_finalize_batch(self, conn: Any, message_ids: Iterable[str]) -> None:
        """Acquire the per-message finalize advisory lock for every id in a **canonical (sorted)**
        order, up front, before any finalize work. A multi-message finalizer (cancel_queued, the
        dead-letter sweeps) holds all its per-message xact locks until commit; acquiring them in one
        deterministic order across all such callers means no two can form a lock cycle, so concurrent
        multi-message finalizes can't deadlock (the per-message lock is re-entrant, so
        :meth:`_maybe_finalize_message` re-taking it inside the loop is a no-op)."""
        for mid in sorted(set(message_ids)):
            await self._advisory_lock(conn, _LOCK_CLASS_FINALIZE, f"{_FINALIZE_LOCK_PREFIX}{mid}")

    # --- pooled-statement helpers --------------------------------------------

    async def _fetchall(self, sql: str, *params: Any) -> list[Any]:
        return list(await self._pool.fetch(sql, *params))

    async def _fetchone(self, sql: str, *params: Any) -> Any:
        return await self._pool.fetchrow(sql, *params)

    async def _execute(self, sql: str, *params: Any) -> None:
        await self._pool.execute(sql, *params)

    async def _count(self, table: str) -> int:
        row = await self._pool.fetchrow(f"SELECT COUNT(*) AS n FROM {table}")  # table is a constant
        return int(row["n"]) if row else 0

    # --- open-time loaders / migrations --------------------------------------

    async def _load_state_cache(self) -> None:
        """Populate the in-memory transform-state cache from the ``state`` table (ADR 0005).

        Also seeds :attr:`_state_versions` from ``state_version`` (Track B Step 6b): a fresh clustered node
        loads the WHOLE ``state`` table here (so it starts fully converged), and recording the per-namespace
        versions means its first convergence tick won't needlessly re-read every namespace it already holds."""
        rows = await self._fetchall("SELECT namespace, key, value FROM state")
        cache: dict[tuple[str, str], Any] = {}
        for r in rows:
            cache[(r["namespace"], r["key"])] = json.loads(self._cipher.decrypt(r["value"]))
        self._state_cache = cache
        vrows = await self._fetchall("SELECT namespace, version FROM state_version")
        self._state_versions = {r["namespace"]: int(r["version"]) for r in vrows}

    async def _load_reference_cache(self) -> None:
        """Populate the in-memory reference cache from the ACTIVE snapshot of each set (ADR 0006).

        Drives from ``reference_version`` (the authoritative active-version list) with a LEFT JOIN so a
        set synced to ZERO rows still loads as a present empty ``{}`` after a reopen. Also records each
        set's active version in :attr:`_reference_versions` (Track B Step 6) so a later
        :meth:`converge_reference_cache` knows which sets a follower must read-through."""
        cache, versions = await self._read_active_reference_snapshots()
        self._reference_cache = cache
        self._reference_versions = versions

    async def _read_active_reference_snapshots(
        self,
    ) -> tuple[dict[str, dict[str, Any]], dict[str, str]]:
        """Read every set's ACTIVE snapshot (rows + version) from the shared store, decrypting values.

        The shared JOIN/decrypt logic behind both the open-time :meth:`_load_reference_cache` and the
        follower :meth:`converge_reference_cache`. Drives from ``reference_version`` (the authoritative
        active-version list) LEFT JOIN ``reference`` so a set synced to ZERO rows is still a present
        empty ``{}``. Returns ``({name: {key: value}}, {name: version})``."""
        rows = await self._fetchall(
            "SELECT v.name AS name, v.version AS version, r.key AS key, r.value AS value "
            "FROM reference_version v "
            "LEFT JOIN reference r ON r.name = v.name AND r.version = v.version"
        )
        cache: dict[str, dict[str, Any]] = {}
        versions: dict[str, str] = {}
        for r in rows:
            entry = cache.setdefault(r["name"], {})
            versions[r["name"]] = r["version"]
            if r["key"] is not None:  # NULL key = the LEFT-JOIN miss of an empty snapshot
                entry[r["key"]] = json.loads(self._cipher.decrypt(r["value"]))
        return cache, versions

    async def converge_reference_cache(self) -> list[str]:
        """Pull any newer shared reference snapshot into this node's local cache (Track B Step 6).

        The FOLLOWER read-through: read the authoritative active versions from the shared store and,
        for each set whose active version differs from the one this handle currently reflects, re-load
        that set's rows from the shared ``reference`` table (decrypt) into :attr:`_reference_cache` —
        **without** re-reading the external source. It issues a real read each call (a
        ``reference_version`` JOIN ``reference`` + per-row decrypt), but mutates nothing when the
        versions already match (the leader's own just-written sets). Returns the names refreshed
        (``[]`` when none advanced). The runner only calls this when clustered
        (``coordinator.is_clustered()``), so single-node Postgres never issues this read."""
        cache, versions = await self._read_active_reference_snapshots()
        refreshed: list[str] = []
        for name, version in versions.items():
            if self._reference_versions.get(name) != version:
                self._reference_cache[name] = cache[name]
                self._reference_versions[name] = version
                refreshed.append(name)
        return refreshed

    def enable_state_convergence(self) -> None:
        """Turn on per-namespace state-version bumping (Track B Step 6b). The engine calls this in a
        cluster (is_clustered()) BEFORE workers start, so a sibling's converge_state_cache sees every
        write. Single-node never calls it → no state_version writes → byte-identical."""
        self._cluster_state_convergence = True

    async def converge_state_cache(self) -> list[str]:
        """Pull any newer shared transform-state writes into this node's local cache (Track B Step 6b).

        FOLLOWER read-through: read the per-namespace versions, and for each namespace whose version
        differs from the one this handle reflects, re-read THAT WHOLE namespace's rows from the shared
        state table (decrypt) and swap them into _state_cache. Returns the namespace names refreshed.
        Only called when clustered (coordinator.is_clustered()), so single-node never issues this read.

        Read-skew-safe ordering: the version scan runs FIRST, then each changed namespace's rows, so the
        recorded version is always ≤ the data freshness — the worst case is one harmless extra re-converge,
        never a skipped write. Decrypt every changed namespace into locals BEFORE mutating the cache, so a
        decrypt failure raises before any partial mutation (like :meth:`converge_reference_cache`).

        Unlike reference convergence (sets are written only by the leader, so a node never converges a set
        it also writes), transform state is written on EVERY node (one transform worker per inbound), so a
        local ``transform_handoff`` can commit + publish a new key to a namespace we are mid-converge on.
        Each pending entry therefore captures the per-node reflected version observed when its rows were
        read (``seen``); if a local write advanced that version before we mutate, the read snapshot is stale
        and the destructive del-then-reseed would transiently drop the just-committed local key (regressing
        ``_state_versions`` below the DB), so we MERGE the read rows non-destructively instead (never
        clobbering a newer local write) and leave the reflected version below the DB so the next tick does a
        clean reseed that reconciles any sibling deletes the merge skipped."""
        vrows = await self._fetchall("SELECT namespace, version FROM state_version")
        versions = {r["namespace"]: int(r["version"]) for r in vrows}
        pending: list[tuple[str, int, int | None, dict[str, Any]]] = []
        for ns, version in versions.items():
            seen = self._state_versions.get(ns)
            if seen != version:
                rows = await self._fetchall("SELECT key, value FROM state WHERE namespace=$1", ns)
                fresh = {r["key"]: json.loads(self._cipher.decrypt(r["value"])) for r in rows}
                pending.append((ns, version, seen, fresh))
        refreshed: list[str] = []
        for ns, version, seen, fresh in pending:
            if self._state_versions.get(ns) == seen:
                # No local write intervened during our read → safe destructive reseed (drop the
                # namespace's old entries first, handling a sibling's deletes/purges, then re-seed).
                for ck in [c for c in self._state_cache if c[0] == ns]:
                    del self._state_cache[ck]
                for k, v in fresh.items():
                    self._state_cache[(ns, k)] = v
            else:
                # A local transform_handoff committed + published to THIS namespace during our read
                # window, advancing the DB version past `version`. A destructive reseed from the stale
                # `fresh` would drop that just-committed local key; merge non-destructively instead
                # (setdefault keeps any newer local value) so the sibling rows we read still land. We
                # deliberately record `version` (< the DB version the local write bumped to) so the next
                # tick does a clean reseed that reconciles any sibling deletes this merge could not see.
                for k, v in fresh.items():
                    self._state_cache.setdefault((ns, k), v)
            self._state_versions[ns] = version
            refreshed.append(ns)
        return refreshed

    async def _backfill_audit_chain(self) -> None:
        """Fill ``row_hash`` for audit rows written before hash-chaining (idempotent; fills only
        NULLs, chained from the prior row). H-7: takes the audit-chain advisory lock first so a
        concurrent ``record_audit`` can't fork the chain while this backfills."""
        async with self._pool.acquire() as conn:
            async with conn.transaction():
                await self._advisory_lock(conn, _LOCK_CLASS_AUDIT, _AUDIT_LOCK)
                rows = await conn.fetch(
                    "SELECT id, ts, actor, action, channel_id, detail, row_hash FROM audit_log"
                    " ORDER BY id"
                )
                prev = ""
                updates: list[tuple[str, int]] = []
                for r in rows:
                    if r["row_hash"]:
                        prev = r["row_hash"]
                        continue
                    prev = audit_row_hash(
                        prev,
                        ts=r["ts"],
                        actor=r["actor"],
                        action=r["action"],
                        channel_id=r["channel_id"],
                        detail=r["detail"],
                    )
                    updates.append((prev, r["id"]))
                for row_hash, rid in updates:
                    await conn.execute(
                        "UPDATE audit_log SET row_hash=$1 WHERE id=$2", row_hash, rid
                    )

    async def _encrypt_existing_rows(self) -> None:
        """Encrypt legacy plaintext values in the cipher-covered columns in place when encryption is
        enabled (STORE-1 / WP-5). Idempotent + batched: skips rows already carrying the ciphertext
        prefix and NULL / blank values; bounded memory (chunks of 500)."""
        if not self._cipher.encrypts:
            return
        like = f"{_ENC_PREFIX}%"
        total = 0
        for table, column in self._CIPHER_COLUMNS:
            while True:
                rows = await self._fetchall(
                    f"SELECT id, {column} AS v FROM {table}"
                    f" WHERE {column} NOT LIKE $1 AND {column} <> '' LIMIT 500",
                    like,
                )
                if not rows:
                    break
                async with self._pool.acquire() as conn:
                    async with conn.transaction():
                        for r in rows:
                            await conn.execute(
                                f"UPDATE {table} SET {column}=$1 WHERE id=$2",
                                self._cipher.encrypt(r["v"]),
                                r["id"],
                            )
                total += len(rows)
        total += await self._encrypt_existing_composite(
            "state", ("namespace", "key"), like, encrypt=True
        )
        total += await self._encrypt_existing_composite(
            "reference", ("name", "version", "key"), like, encrypt=True
        )
        # The `response` table (composite PK + TWO cipher columns — ADR 0013) migrates each column.
        for col in ("body", "detail"):
            total += await self._encrypt_existing_composite(
                "response",
                ("message_id", "destination_name", "response_seq"),
                like,
                encrypt=True,
                value_col=col,
            )
        if total:
            log.info("encrypted %d existing value(s) at rest", total)

    async def _encrypt_existing_composite(
        self,
        table: str,
        pk_cols: tuple[str, ...],
        like: str,
        *,
        encrypt: bool,
        value_col: str = "value",
    ) -> int:
        """Encrypt the ``value_col`` of a composite-PK table (``state``/``reference``/``response``) in
        place — the migration loop for tables that can't ride the id-keyed loop. ``encrypt=True`` is the
        on-open plaintext→active migration (this method's only caller; rotation uses
        :meth:`_reencrypt_composite`). ``value_col`` defaults to ``value`` (state/reference);
        ``response`` passes ``body``/``detail``."""
        rotated = 0
        pk_select = ", ".join(pk_cols)
        while True:
            rows = await self._fetchall(
                f"SELECT {pk_select}, {value_col} AS v FROM {table}"
                f" WHERE {value_col} NOT LIKE $1 AND {value_col} <> '' LIMIT 500",
                like,
            )
            if not rows:
                break
            where = " AND ".join(f"{c}=${i + 2}" for i, c in enumerate(pk_cols))
            async with self._pool.acquire() as conn:
                async with conn.transaction():
                    for r in rows:
                        await conn.execute(
                            f"UPDATE {table} SET {value_col}=$1 WHERE {where}",
                            self._cipher.encrypt(r["v"]),
                            *[r[c] for c in pk_cols],
                        )
            rotated += len(rows)
        return rotated

    # --- at-rest key rotation (PHI.md §3, ASVS 11.2.2) -----------------------

    async def reencrypt_to_active(self, *, batch: int = 500) -> int:
        """Re-encrypt every cipher-covered value under the **active** key — the key-rotation
        re-encrypt path (run offline via ``messagefoundry rotate-key``). Rewrites plaintext or
        retired-key values; skips values already under the active key (idempotent) and NULL/blank
        ones. A value no configured key can decrypt raises before any UPDATE (PHI is never dropped).
        Returns the number of values rewritten. Ported, not stubbed — Postgres supports rotation."""
        cipher = self._cipher
        if not isinstance(cipher, AesGcmCipher):
            return 0  # identity cipher (no key) — nothing to rotate
        active_like = f"{_ENC_PREFIX}{cipher.active_key_id}:%"
        total = 0
        for table, column in self._CIPHER_COLUMNS:
            while True:
                rows = await self._fetchall(
                    f"SELECT id, {column} AS v FROM {table}"
                    f" WHERE {column} NOT LIKE $1 AND {column} <> '' LIMIT $2",
                    active_like,
                    batch,
                )
                if not rows:
                    break
                # decrypt (via the keyring) → encrypt (active) up front so a CipherError (a prior key
                # not supplied) propagates before any UPDATE — the batch is all-or-nothing.
                updates = [(cipher.encrypt(cipher.decrypt(r["v"])), r["id"]) for r in rows]
                async with self._pool.acquire() as conn:
                    async with conn.transaction():
                        for new_value, rid in updates:
                            await conn.execute(
                                f"UPDATE {table} SET {column}=$1 WHERE id=$2", new_value, rid
                            )
                total += len(rows)
        total += await self._reencrypt_composite(
            cipher, "state", ("namespace", "key"), active_like, batch
        )
        total += await self._reencrypt_composite(
            cipher, "reference", ("name", "version", "key"), active_like, batch
        )
        # The `response` table (composite PK + two cipher columns — ADR 0013) rotates each column.
        for col in ("body", "detail"):
            total += await self._reencrypt_composite(
                cipher,
                "response",
                ("message_id", "destination_name", "response_seq"),
                active_like,
                batch,
                value_col=col,
            )
        if total:
            log.info("re-encrypted %d value(s) under the active key (rotation)", total)
        return total

    async def _reencrypt_composite(
        self,
        cipher: AesGcmCipher,
        table: str,
        pk_cols: tuple[str, ...],
        active_like: str,
        batch: int,
        value_col: str = "value",
    ) -> int:
        """Re-encrypt the ``value_col`` of a composite-PK table under the active key (the rotation
        parallel of :meth:`_encrypt_existing_composite`). Decrypt→encrypt up front; a value no key can
        decrypt raises before any UPDATE. ``value_col`` defaults to ``value``; ``response`` rotates
        ``body``/``detail``."""
        rotated = 0
        pk_select = ", ".join(pk_cols)
        where = " AND ".join(f"{c}=${i + 2}" for i, c in enumerate(pk_cols))
        while True:
            rows = await self._fetchall(
                f"SELECT {pk_select}, {value_col} AS v FROM {table}"
                f" WHERE {value_col} NOT LIKE $1 AND {value_col} <> '' LIMIT $2",
                active_like,
                batch,
            )
            if not rows:
                break
            updates = [
                (cipher.encrypt(cipher.decrypt(r["v"])), [r[c] for c in pk_cols]) for r in rows
            ]
            async with self._pool.acquire() as conn:
                async with conn.transaction():
                    for new_value, pk_vals in updates:
                        await conn.execute(
                            f"UPDATE {table} SET {value_col}=$1 WHERE {where}", new_value, *pk_vals
                        )
            rotated += len(rows)
        return rotated

    # --- internal write helpers ----------------------------------------------

    async def _event(
        self,
        conn: Any,
        message_id: str,
        event: str,
        destination: str | None,
        detail: str | None,
        now: float,
    ) -> None:
        """Append a ``message_events`` row, encrypting ``detail`` here so the cipher boundary lives in
        ONE place (mirrors MessageStore._event; ``detail`` is a declared cipher column). Callers pass
        plaintext — never pre-wrap with ``_enc``."""
        detail = safe_text(detail) if detail else detail  # PHI chokepoint (#120)
        await conn.execute(
            "INSERT INTO message_events (message_id, ts, event, destination, detail)"
            " VALUES ($1,$2,$3,$4,$5)",
            message_id,
            now,
            event,
            destination,
            self._enc(detail),
        )

    async def _insert_message(
        self,
        conn: Any,
        mid: str,
        *,
        channel_id: str,
        raw: str,
        status: str,
        control_id: str | None,
        message_type: str | None,
        source_type: str | None,
        summary: str | None,
        metadata: str | None,
        error: str | None,
        now: float,
    ) -> None:
        await conn.execute(
            "INSERT INTO messages"
            " (id, channel_id, received_at, source_type, control_id,"
            "  message_type, raw, status, error, summary, metadata)"
            " VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)",
            mid,
            channel_id,
            now,
            source_type,
            control_id,
            message_type,
            self._cipher.encrypt(raw),
            status,
            self._enc(error),
            summary,
            metadata,
        )

    async def _fifo_created_at(
        self, conn: Any, stage: str, lane_col: str, lane_val: str, now: float
    ) -> float:
        """The ``created_at`` to stamp on a new ``stage`` row so per-lane FIFO order (``ORDER BY
        created_at, seq``) survives a backward wall-clock step — clamps up to the lane's current max
        (mirrors MessageStore._fifo_created_at). ``lane_col`` is a code-controlled literal."""
        row = await conn.fetchrow(
            f"SELECT MAX(created_at) AS m FROM queue WHERE stage=$1 AND {lane_col}=$2",
            stage,
            lane_val,
        )
        last = None if row is None else row["m"]
        if last is not None and now < last:
            log.warning(
                "clock regression on the %s lane %r: created_at %.6f < lane max %.6f; clamping to "
                "preserve FIFO order",
                stage,
                lane_val,
                now,
                last,
            )
            return float(last)
        return now

    async def _insert_outbound_row(
        self, conn: Any, mid: str, channel_id: str, dest_name: str, payload: str, now: float
    ) -> None:
        """Insert one ``stage='outbound'`` queue row (one message→destination delivery)."""
        created_at = await self._fifo_created_at(
            conn, Stage.OUTBOUND.value, "destination_name", dest_name, now
        )
        await conn.execute(
            "INSERT INTO queue"
            " (id, message_id, stage, channel_id, destination_name, payload,"
            "  status, attempts, next_attempt_at, created_at, updated_at)"
            " VALUES ($1,$2,$3,$4,$5,$6,$7,0,$8,$9,$10)",
            uuid4().hex,
            mid,
            Stage.OUTBOUND.value,
            channel_id,
            dest_name,
            self._cipher.encrypt(payload),
            OutboxStatus.PENDING.value,
            now,
            created_at,
            now,
        )

    async def _insert_routed_row(
        self, conn: Any, mid: str, channel_id: str, handler_name: str, payload: str, now: float
    ) -> None:
        """Insert one ``stage='routed'`` queue row (one handler assignment awaiting transform)."""
        created_at = await self._fifo_created_at(
            conn, Stage.ROUTED.value, "channel_id", channel_id, now
        )
        await conn.execute(
            "INSERT INTO queue"
            " (id, message_id, stage, channel_id, destination_name, handler_name, payload,"
            "  status, attempts, next_attempt_at, created_at, updated_at)"
            " VALUES ($1,$2,$3,$4,NULL,$5,$6,$7,0,$8,$9,$10)",
            uuid4().hex,
            mid,
            Stage.ROUTED.value,
            channel_id,
            handler_name,
            self._cipher.encrypt(payload),
            OutboxStatus.PENDING.value,
            now,
            created_at,
            now,
        )

    async def _apply_state_op(
        self, conn: Any, namespace: str, key: str, value_json: str, message_id: str, now: float
    ) -> None:
        """Upsert one state entry within the current transaction (ON CONFLICT (namespace,key) — the
        Postgres equivalent of SQLite's INSERT OR REPLACE). ``value_json`` is JSON-encoded then
        cipher-encrypted so PHI never hits disk in the clear."""
        await conn.execute(
            "INSERT INTO state (namespace, key, value, set_at, message_id)"
            " VALUES ($1,$2,$3,$4,$5)"
            " ON CONFLICT (namespace, key) DO UPDATE SET"
            " value=excluded.value, set_at=excluded.set_at, message_id=excluded.message_id",
            namespace,
            key,
            self._cipher.encrypt(value_json),
            now,
            message_id,
        )

    @staticmethod
    def _lane_col(stage: str) -> str:
        """The FIFO/depth lane column for a stage (code-controlled literal): ``channel_id`` for
        ingress/routed/response, ``destination_name`` for outbound."""
        return (
            "channel_id"
            if stage in (Stage.INGRESS.value, Stage.ROUTED.value, Stage.RESPONSE.value)
            else "destination_name"
        )

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
    ) -> str:
        """Atomically persist an inbound message and its per-destination outbound rows directly — the
        pre-staged-pipeline single-step write (kept for tests and any single-dispatcher path). With
        ``deliveries`` the message is ``ROUTED``; with none it is ``UNROUTED``."""
        now = time.time() if now is None else now
        mid = uuid4().hex
        status = MessageStatus.ROUTED.value if deliveries else MessageStatus.UNROUTED.value
        async with self._pool.acquire() as conn:
            async with conn.transaction():
                await self._insert_message(
                    conn,
                    mid,
                    channel_id=channel_id,
                    raw=raw,
                    status=status,
                    control_id=control_id,
                    message_type=message_type,
                    source_type=source_type,
                    summary=summary,
                    metadata=metadata,
                    error=None,
                    now=now,
                )
                for dest_name, payload in deliveries:
                    await self._insert_outbound_row(conn, mid, channel_id, dest_name, payload, now)
                await self._event(
                    conn, mid, "received", None, f"{len(deliveries)} destination(s)", now
                )
        return mid

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
    ) -> str:
        """Log an inbound message that isn't routed (``FILTERED`` or parse/validation ``ERROR``),
        stored with no queue rows so an operator still sees exactly what arrived."""
        error = safe_text(error) if error else error  # PHI chokepoint (#120)
        now = time.time() if now is None else now
        mid = uuid4().hex
        event = "error" if status is MessageStatus.ERROR else "filtered"
        async with self._pool.acquire() as conn:
            async with conn.transaction():
                await self._insert_message(
                    conn,
                    mid,
                    channel_id=channel_id,
                    raw=raw,
                    status=status.value,
                    control_id=control_id,
                    message_type=message_type,
                    source_type=source_type,
                    summary=summary,
                    metadata=metadata,
                    error=error,
                    now=now,
                )
                await self._event(conn, mid, event, None, error, now)
        return mid

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
        """Durably persist a freshly-received raw message to the **ingress stage** — the staged
        pipeline's ACK-on-receipt boundary (ADR 0001). In one transaction: insert the message
        (status ``RECEIVED``) and a single ``stage='ingress'`` queue row holding the raw body. Once
        this returns the message is durable and the inbound may be ACKed. Returns the message id."""
        now = time.time() if now is None else now
        mid = uuid4().hex
        async with self._pool.acquire() as conn:
            async with conn.transaction():
                await self._insert_message(
                    conn,
                    mid,
                    channel_id=channel_id,
                    raw=raw,
                    status=MessageStatus.RECEIVED.value,
                    control_id=control_id,
                    message_type=message_type,
                    source_type=source_type,
                    summary=summary,
                    metadata=metadata,
                    error=None,
                    now=now,
                )
                ingress_created_at = await self._fifo_created_at(
                    conn, Stage.INGRESS.value, "channel_id", channel_id, now
                )
                await conn.execute(
                    "INSERT INTO queue"
                    " (id, message_id, stage, channel_id, destination_name, payload,"
                    "  status, attempts, next_attempt_at, created_at, updated_at)"
                    " VALUES ($1,$2,$3,$4,NULL,$5,$6,0,$7,$8,$9)",
                    uuid4().hex,
                    mid,
                    Stage.INGRESS.value,
                    channel_id,
                    self._cipher.encrypt(raw),
                    OutboxStatus.PENDING.value,
                    now,
                    ingress_created_at,
                    now,
                )
                await self._event(conn, mid, "received", None, "ingress", now)
        return mid

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
        """Advance a message from ingress to outbound in one transaction (the Step-A combined
        primitive): consume the in-flight ingress row, insert one outbound row per delivery, set the
        post-router ``disposition``. Idempotent: ``False`` (no-op) if the ingress row was already
        consumed by a prior run."""
        now = time.time() if now is None else now
        async with self._pool.acquire() as conn:
            async with conn.transaction():
                deleted = await conn.fetchval(
                    "DELETE FROM queue WHERE id=$1 AND stage=$2 AND status=$3 RETURNING id",
                    ingress_id,
                    Stage.INGRESS.value,
                    OutboxStatus.INFLIGHT.value,
                )
                if deleted is None:
                    return False  # already handed off (crash-restart) — idempotent no-op
                for dest_name, payload in deliveries:
                    await self._insert_outbound_row(
                        conn, message_id, channel_id, dest_name, payload, now
                    )
                await conn.execute(
                    "UPDATE messages SET status=$1 WHERE id=$2", disposition.value, message_id
                )
                event = {
                    MessageStatus.ROUTED: "routed",
                    MessageStatus.FILTERED: "filtered",
                    MessageStatus.UNROUTED: "unrouted",
                }.get(disposition, "routed")
                await self._event(
                    conn,
                    message_id,
                    event,
                    None,
                    f"{len(deliveries)} destination(s)",
                    now,
                )
        return True

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
        """Advance a message from the ingress stage to the **routed** stage (the router half of the
        split pipeline): consume the in-flight ingress row, insert one ``stage='routed'`` row per
        selected handler (in handler-list order — same-txn rows get increasing ``seq``, preserving
        order), set the intermediate ``disposition`` (``ROUTED``/``UNROUTED``). Idempotent: ``False``
        if the ingress row was already consumed."""
        now = time.time() if now is None else now
        async with self._pool.acquire() as conn:
            async with conn.transaction():
                deleted = await conn.fetchval(
                    "DELETE FROM queue WHERE id=$1 AND stage=$2 AND status=$3 RETURNING id",
                    ingress_id,
                    Stage.INGRESS.value,
                    OutboxStatus.INFLIGHT.value,
                )
                if deleted is None:
                    return False  # already handed off (crash-restart) — idempotent no-op
                for handler_name, payload in handlers:
                    await self._insert_routed_row(
                        conn, message_id, channel_id, handler_name, payload, now
                    )
                await conn.execute(
                    "UPDATE messages SET status=$1 WHERE id=$2", disposition.value, message_id
                )
                event = "routed" if disposition is MessageStatus.ROUTED else "unrouted"
                await self._event(conn, message_id, event, None, f"{len(handlers)} handler(s)", now)
        return True

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
        """Advance one handler assignment from the **routed** stage to outbound (the transform half of
        the split pipeline): consume the in-flight routed row, insert one outbound row per delivery,
        apply each declared state write (ADR 0005) atomically with them, then let the finalizer
        recompute the terminal disposition (this method never writes ``messages.status``). State
        exactly-once: each op upserts by (namespace,key) inside this same transaction; the read cache
        is updated only after commit. Idempotent: ``False`` if the routed row was already consumed."""
        now = time.time() if now is None else now
        applied: list[tuple[tuple[str, str], Any]] = []
        async with self._pool.acquire() as conn:
            async with conn.transaction():
                deleted = await conn.fetchval(
                    "DELETE FROM queue WHERE id=$1 AND stage=$2 AND status=$3 RETURNING id",
                    routed_id,
                    Stage.ROUTED.value,
                    OutboxStatus.INFLIGHT.value,
                )
                if deleted is None:
                    return False  # already handed off (crash-restart) — idempotent no-op
                for dest_name, payload in deliveries:
                    await self._insert_outbound_row(
                        conn, message_id, channel_id, dest_name, payload, now
                    )
                for namespace, key, value in state_ops:
                    value_json = json.dumps(value)
                    await self._apply_state_op(conn, namespace, key, value_json, message_id, now)
                    applied.append(((namespace, key), value))
                # Track B Step 6b: bump each DISTINCT namespace's version IN THE SAME txn as its writes —
                # atomic, so a follower that sees the new version is guaranteed the rows are committed.
                # Gated on clustered (single-node never writes state_version → byte-identical). Idempotent
                # on a crash-restart: a re-run returns False above (the routed row is gone) before reaching
                # here, so the bump never double-applies.
                bumped: list[tuple[str, int]] = []
                if self._cluster_state_convergence and state_ops:
                    for ns in dict.fromkeys(n for n, _, _ in state_ops):  # distinct, order-stable
                        row = await conn.fetchrow(
                            "INSERT INTO state_version (namespace, version, updated_at) "
                            "VALUES ($1, 1, $2) "
                            "ON CONFLICT (namespace) DO UPDATE SET "
                            "version = state_version.version + 1, updated_at = excluded.updated_at "
                            "RETURNING version",
                            ns,
                            now,
                        )
                        assert row is not None, "state_version upsert returned no row"
                        bumped.append((ns, int(row["version"])))
                await self._event(
                    conn,
                    message_id,
                    "transformed",
                    None,
                    f"{len(deliveries)} destination(s)",
                    now,
                )
                # H-8: serialize per-message finalize on the advisory lock, then recompute on a fresh
                # snapshot. The lock is taken inside this txn, so it auto-releases at commit.
                await self._maybe_finalize_message(conn, message_id, now)
        # Commit succeeded → publish the committed state writes to the read-through cache.
        for ck, cv in applied:
            self._state_cache[ck] = cv
        # The writer records its own new per-namespace versions so its own converge_state_cache() skips
        # re-reading the namespaces it just wrote (Track B Step 6b).
        for ns, ver in bumped:
            self._state_versions[ns] = ver
        return True

    # --- transform-state / reference views (ADR 0005 / 0006) -----------------

    def state_view(self) -> Mapping[tuple[str, str], Any]:
        """A read-only, live window onto the transform-state read-through cache (ADR 0005)."""
        return MappingProxyType(self._state_cache)

    def reference_view(self) -> Mapping[str, Mapping[str, Any]]:
        """A read-only, live window onto the active reference snapshots (ADR 0006)."""
        return MappingProxyType(self._reference_cache)

    async def write_reference_snapshot(
        self, *, name: str, version: str, rows: Mapping[str, Any]
    ) -> None:
        """Materialize a new reference snapshot and atomically make it active (ADR 0006). In one
        transaction: drop the set's prior rows, insert the new snapshot (each value JSON-encoded then
        encrypted), and upsert the ``reference_version`` pointer. The read cache swaps only after
        commit, so a failed sync leaves the last-good snapshot live. Ported, not stubbed."""
        encrypted = [
            (name, version, k, self._cipher.encrypt(json.dumps(v))) for k, v in rows.items()
        ]
        async with self._pool.acquire() as conn:
            async with conn.transaction():
                await conn.execute("DELETE FROM reference WHERE name=$1", name)
                for n, ver, k, v in encrypted:
                    await conn.execute(
                        "INSERT INTO reference (name, version, key, value) VALUES ($1,$2,$3,$4)",
                        n,
                        ver,
                        k,
                        v,
                    )
                await conn.execute(
                    "INSERT INTO reference_version (name, version, synced_at, row_count)"
                    " VALUES ($1,$2,$3,$4)"
                    " ON CONFLICT (name) DO UPDATE SET"
                    " version=excluded.version, synced_at=excluded.synced_at,"
                    " row_count=excluded.row_count",
                    name,
                    version,
                    time.time(),
                    len(encrypted),
                )
        # Commit succeeded → swap the active snapshot in the read cache (plaintext, decoded form) and
        # record the active version so a follower's converge_reference_cache() (Track B Step 6) can tell
        # this node already reflects it (no needless re-load on the node that just wrote it).
        self._reference_cache[name] = dict(rows)
        self._reference_versions[name] = version

    # --- delivery worker path ------------------------------------------------

    async def claim_ready(
        self,
        limit: int = 10,
        now: float | None = None,
        *,
        stage: str = Stage.OUTBOUND.value,
        channel_id: str | None = None,
        destination_name: str | None = None,
    ) -> list[OutboxItem]:
        """Atomically claim up to ``limit`` due rows at ``stage`` (UNORDERED — skips a backing-off row
        to drain others), marking them ``inflight`` and bumping ``attempts``, via a single
        ``FOR UPDATE SKIP LOCKED`` CTE so concurrent workers don't block or double-claim. An
        undecryptable payload is dead-lettered and dropped (poison-row containment), not raised."""
        now = time.time() if now is None else now
        lease_until = now + self._settings.lease_ttl_seconds  # Track B Step 2: stamp the lease
        # All filters are bound; explicit ::text casts let asyncpg type the optional-filter idiom.
        sql = (
            "WITH due AS ("
            " SELECT id FROM queue"
            " WHERE stage=$1 AND status=$2 AND next_attempt_at<=$3"
            " AND ($4::text IS NULL OR channel_id=$4)"
            " AND ($5::text IS NULL OR destination_name=$5)"
            " ORDER BY next_attempt_at LIMIT $6 FOR UPDATE SKIP LOCKED"
            ")"
            " UPDATE queue q SET status=$7, attempts=attempts+1, updated_at=$3,"
            " owner=$8, lease_expires_at=$9"
            " FROM due WHERE q.id=due.id RETURNING q.*"
        )
        rows = await self._fetchall(
            sql,
            stage,
            OutboxStatus.PENDING.value,
            now,
            channel_id,
            destination_name,
            limit,
            OutboxStatus.INFLIGHT.value,
            self._owner,
            lease_until,
        )
        items: list[OutboxItem] = []
        for row in rows:
            try:
                items.append(self._outbox_item(row))
            except CipherError as exc:
                log.warning("dead-lettering undecryptable queue row %s: %s", row["id"], exc)
                await self.dead_letter_now(row["id"], f"undecryptable payload: {exc}")
        return items

    async def claim_next_fifo(
        self,
        name: str,
        now: float | None = None,
        *,
        stage: str = Stage.OUTBOUND.value,
    ) -> OutboxItem | None:
        """Claim the single oldest *due* pending row for one lane at ``stage`` (strict FIFO — the head
        blocks the lane while it backs off). Lane key is stage-aware (``destination_name`` outbound,
        ``channel_id`` ingress/routed). Ordering is ``created_at, seq`` (seq = the BIGSERIAL tiebreak
        that preserves same-txn insertion order). ``FOR UPDATE SKIP LOCKED`` on the head keeps
        concurrent pollers non-blocking. ``None`` when nothing is pending or the head isn't due.

        FAILOVER FIFO SAFETY (active-passive HA): the claim runs in ONE transaction that FIRST reclaims
        this lane's stranded head — a crashed/fenced prior leader's claimed rows are still ``inflight``
        under an expired ROW lease, and the PENDING-only head SELECT would skip them and reorder past
        the true head N. So before the head SELECT, this lane's expired-lease ``inflight`` rows are
        returned to ``pending`` (scoped to ``lease_expires_at < now`` so it never disturbs a live
        node's actively-processed rows — their leases are kept in the future by the worker's renew
        timer), restoring head-of-line blocking: the recovered N is reconsidered as the (due) head and
        blocks the lane until delivered. Without this, after a promotion the new leader would deliver
        N+1 before N (a per-lane FIFO break across failover). The wall-clock lease shares Track B
        Step 2's NTP assumption: set ``lease_ttl_seconds`` comfortably above clock skew + the claim
        cadence."""
        now = time.time() if now is None else now
        lease_until = now + self._settings.lease_ttl_seconds  # Track B Step 2: stamp the lease
        lane_col = self._lane_col(stage)  # code-controlled literal
        head_sql = (
            "WITH head AS ("
            f" SELECT id, next_attempt_at FROM queue WHERE stage=$1 AND {lane_col}=$2 AND status=$3"
            " ORDER BY created_at, seq LIMIT 1 FOR UPDATE SKIP LOCKED"
            ")"
            " UPDATE queue q SET status=$4, attempts=attempts+1, updated_at=$5,"
            " owner=$6, lease_expires_at=$7"
            " FROM head WHERE q.id=head.id AND head.next_attempt_at<=$5 RETURNING q.*"
        )
        async with self._pool.acquire() as conn:
            async with conn.transaction():
                # FIRST recover this lane's stranded head: a crashed/fenced predecessor's claimed rows
                # are still inflight under an expired ROW lease, and the PENDING-only head SELECT below
                # would skip them and reorder past N. Return them to pending IN THIS TXN before the head
                # SELECT so the oldest recovered row is reconsidered as the (now-due) head and blocks the
                # lane. Bounded to this single lane and to already-expired leases, so it never steals a
                # live node's own actively-leased rows.
                await conn.execute(
                    f"UPDATE queue SET status=$3, owner=NULL, lease_expires_at=NULL,"
                    f" next_attempt_at=$4, updated_at=$4"
                    f" WHERE stage=$1 AND {lane_col}=$2 AND status=$5"
                    f" AND lease_expires_at IS NOT NULL AND lease_expires_at < $4",
                    stage,
                    name,
                    OutboxStatus.PENDING.value,
                    now,
                    OutboxStatus.INFLIGHT.value,
                )
                # THEN claim the head in the SAME txn, stamping the queue row's own owner + row lease.
                row = await conn.fetchrow(
                    head_sql,
                    stage,
                    name,
                    OutboxStatus.PENDING.value,
                    OutboxStatus.INFLIGHT.value,
                    now,
                    self._owner,
                    lease_until,
                )
        return await self._fifo_item_or_dead_letter(row)

    async def _fifo_item_or_dead_letter(self, row: Any) -> OutboxItem | None:
        """Decode a claimed FIFO head into an :class:`OutboxItem`, or dead-letter an undecryptable head
        and return ``None`` so the lane advances on the next poll (mirrors SQLite). Runs AFTER the claim
        txn so the dead-letter is its own transaction."""
        if row is None:
            return None  # nothing pending, or the head is backing off — block the lane
        try:
            return self._outbox_item(row)
        except CipherError as exc:
            # An undecryptable head must not stall the lane — dead-letter it and let the next poll
            # advance, rather than raising into the worker (mirrors SQLite).
            log.warning("dead-lettering undecryptable queue row %s: %s", row["id"], exc)
            await self.dead_letter_now(row["id"], f"undecryptable payload: {exc}")
            return None

    def _outbox_item(self, row: Any) -> OutboxItem:
        """Build an :class:`OutboxItem` from a claimed ``queue`` record, decrypting the payload (may
        raise :class:`CipherError`, which the callers contain)."""
        return OutboxItem(
            id=row["id"],
            message_id=row["message_id"],
            channel_id=row["channel_id"],
            destination_name=row["destination_name"],
            payload=self._cipher.decrypt(row["payload"]),
            attempts=row["attempts"],
            stage=row["stage"],
            handler_name=row["handler_name"],
            created_at=row["created_at"],  # claim RETURNING q.* includes it (ingest-time, ADR 0009)
        )

    async def dead_letter_now(self, outbox_id: str, error: str, now: float | None = None) -> None:
        """Force one row terminal (``DEAD``) immediately — fail-fast, no retry consumed. Serializes
        the finalize per message (H-8)."""
        error = safe_text(
            error
        )  # PHI chokepoint (#120) — incl. the f"undecryptable payload: {exc}" callers
        now = time.time() if now is None else now
        async with self._pool.acquire() as conn:
            async with conn.transaction():
                row = await conn.fetchrow("SELECT * FROM queue WHERE id=$1", outbox_id)
                if row is None:
                    return
                await conn.execute(
                    "UPDATE queue SET status=$1, next_attempt_at=$2, last_error=$3, updated_at=$4,"
                    " owner=NULL, lease_expires_at=NULL WHERE id=$5",
                    OutboxStatus.DEAD.value,
                    now,
                    self._enc(error),
                    now,
                    outbox_id,
                )
                await self._event(
                    conn, row["message_id"], "dead", row["destination_name"], error, now
                )
                await self._maybe_finalize_message(conn, row["message_id"], now)

    async def mark_done(self, outbox_id: str, now: float | None = None) -> None:
        now = time.time() if now is None else now
        async with self._pool.acquire() as conn:
            async with conn.transaction():
                row = await conn.fetchrow("SELECT * FROM queue WHERE id=$1", outbox_id)
                if row is None:
                    return
                await conn.execute(
                    "UPDATE queue SET status=$1, last_error=NULL, updated_at=$2,"
                    " owner=NULL, lease_expires_at=NULL WHERE id=$3",
                    OutboxStatus.DONE.value,
                    now,
                    outbox_id,
                )
                await self._event(
                    conn,
                    row["message_id"],
                    "delivered",
                    row["destination_name"],
                    f"attempt {row['attempts']}",
                    now,
                )
                await self._maybe_finalize_message(conn, row["message_id"], now)

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
        """Mark one outbound row delivered AND persist the partner's captured reply in one transaction
        (ADR 0013) — the Postgres twin of :meth:`MessageStore.complete_with_response`, with the
        **identical single-transaction atomicity** (mark-done + INSERT response under one
        ``conn.transaction()``). ``response_seq`` is ``1 + MAX(seq)`` per ``(message_id,
        destination_name)`` so it is replay-stable, and the ``response`` table is invisible to the
        finalizer (it scans ``queue`` only). When ``reingress_to`` is set (Increment 2) the same
        transaction also inserts the drainable ``Stage.RESPONSE`` work-row (identical to SQLite)."""
        now = time.time() if now is None else now
        async with self._pool.acquire() as conn:
            async with conn.transaction():
                row = await conn.fetchrow("SELECT * FROM queue WHERE id=$1", outbox_id)
                if row is None:
                    return
                message_id = row["message_id"]
                destination_name = row["destination_name"]
                await conn.execute(
                    "UPDATE queue SET status=$1, last_error=NULL, updated_at=$2,"
                    " owner=NULL, lease_expires_at=NULL WHERE id=$3",
                    OutboxStatus.DONE.value,
                    now,
                    outbox_id,
                )
                seq = await conn.fetchval(
                    "SELECT COALESCE(MAX(response_seq), 0) + 1 FROM response"
                    " WHERE message_id=$1 AND destination_name=$2",
                    message_id,
                    destination_name,
                )
                await conn.execute(
                    "INSERT INTO response"
                    " (message_id, destination_name, response_seq, body, outcome, detail, captured_at)"
                    " VALUES ($1,$2,$3,$4,$5,$6,$7)",
                    message_id,
                    destination_name,
                    seq,
                    self._enc(body),
                    outcome,
                    self._enc(detail),
                    now,
                )
                if reingress_to is not None:
                    # ADR 0013 Increment 2: drainable Stage.RESPONSE work-row in the SAME txn (orphan-free)
                    # — a token referencing the immutable artifact by its PK, on the loopback inbound's lane.
                    artifact_ref = f"{message_id}\x1f{destination_name}\x1f{seq}"
                    work_created = await self._fifo_created_at(
                        conn, Stage.RESPONSE.value, "channel_id", reingress_to, now
                    )
                    await conn.execute(
                        "INSERT INTO queue"
                        " (id, message_id, stage, channel_id, destination_name, handler_name, payload,"
                        "  status, attempts, next_attempt_at, created_at, updated_at)"
                        " VALUES ($1,$2,$3,$4,NULL,NULL,$5,$6,0,$7,$8,$9)",
                        uuid4().hex,
                        message_id,
                        Stage.RESPONSE.value,
                        reingress_to,
                        self._enc(artifact_ref),
                        OutboxStatus.PENDING.value,
                        now,
                        work_created,
                        now,
                    )
                await self._event(
                    conn,
                    message_id,
                    "delivered",
                    destination_name,
                    f"attempt {row['attempts']} (response {outcome})",
                    now,
                )
                await self._maybe_finalize_message(conn, message_id, now)

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
        """Postgres twin of :meth:`MessageStore.ingress_handoff` (ADR 0013 Increment 2) — the same
        single-transaction guarded-DELETE handoff under one ``conn.transaction()``. A no-op (work-row
        already consumed) rolls the transaction back via the internal sentinel and returns ``False``."""

        class _Noop(Exception):
            pass

        now = time.time() if now is None else now
        try:
            async with self._pool.acquire() as conn:
                async with conn.transaction():
                    wr = await conn.fetchrow(
                        "SELECT message_id, payload FROM queue WHERE id=$1 AND stage=$2 AND status=$3",
                        response_row_id,
                        Stage.RESPONSE.value,
                        OutboxStatus.INFLIGHT.value,
                    )
                    if wr is None:
                        raise _Noop()  # already consumed by a committed prior run
                    origin_id = wr["message_id"]
                    try:
                        ref = self._dec(wr["payload"]) or ""
                        origin_msg_id, dest, seq_s = ref.split("\x1f")
                        seq = int(seq_s)
                    except Exception:  # noqa: BLE001 - any decrypt/parse failure = an unrecoverable ref
                        # A corrupt/undecryptable work-row reference can never be re-ingressed: dead-letter
                        # the token + ERROR the origin in THIS transaction and CONSUME it (return True ⇒
                        # the conn.transaction() commits) — never re-loop. Mirrors the SQLite branch and
                        # the depth-cap branch (NOT the _Noop rollback, which would leave the token live).
                        await conn.execute(
                            "UPDATE queue SET status=$1, last_error=$2, next_attempt_at=$3,"
                            " updated_at=$4 WHERE id=$5",
                            OutboxStatus.DEAD.value,
                            self._enc("re-ingress work-row reference is corrupt/unparseable"),
                            now,
                            now,
                            response_row_id,
                        )
                        await self._event(
                            conn, origin_id, "dead", None, "re-ingress ref corrupt", now
                        )
                        await self._maybe_finalize_message(conn, origin_id, now)
                        return True
                    art = await conn.fetchrow(
                        "SELECT body FROM response"
                        " WHERE message_id=$1 AND destination_name=$2 AND response_seq=$3",
                        origin_msg_id,
                        dest,
                        seq,
                    )
                    body = self._dec(art["body"]) if (art and art["body"] is not None) else ""
                    body = body or ""
                    mrow = await conn.fetchrow(
                        "SELECT metadata FROM messages WHERE id=$1", origin_id
                    )
                    origin_meta: dict[str, Any] = {}
                    if mrow and mrow["metadata"]:
                        loaded = json.loads(mrow["metadata"])
                        if isinstance(loaded, dict):
                            origin_meta = loaded
                    child_depth = int(origin_meta.get("correlation_depth", 0) or 0) + 1
                    root = origin_meta.get("correlation_root_id") or origin_id
                    if child_depth > correlation_depth_cap:
                        await conn.execute(
                            "UPDATE queue SET status=$1, last_error=$2, next_attempt_at=$3,"
                            " updated_at=$4 WHERE id=$5",
                            OutboxStatus.DEAD.value,
                            self._enc(
                                f"re-ingress correlation depth exceeded "
                                f"({child_depth} > {correlation_depth_cap})"
                            ),
                            now,
                            now,
                            response_row_id,
                        )
                        await self._event(
                            conn,
                            origin_id,
                            "dead",
                            dest,
                            f"re-ingress depth cap ({child_depth})",
                            now,
                        )
                        await self._maybe_finalize_message(conn, origin_id, now)
                        return True
                    new_mid = MessageStore._reingress_message_id(origin_id, dest, seq, body)
                    exists = await conn.fetchval("SELECT 1 FROM messages WHERE id=$1", new_mid)
                    if exists is None:
                        child_meta = json.dumps(
                            {
                                "correlation_id": origin_id,
                                "correlation_root_id": root,
                                "correlation_depth": child_depth,
                                "reingress_of_seq": seq,
                            }
                        )
                        await self._insert_message(
                            conn,
                            new_mid,
                            channel_id=loopback_channel_id,
                            raw=body,
                            status=(
                                MessageStatus.ERROR.value
                                if peek_failed
                                else MessageStatus.RECEIVED.value
                            ),
                            control_id=control_id,
                            message_type=message_type,
                            source_type="reingress",
                            summary=summary,
                            metadata=child_meta,
                            error="re-ingress body failed HL7 peek" if peek_failed else None,
                            now=now,
                        )
                        if not peek_failed:
                            ingress_created = await self._fifo_created_at(
                                conn, Stage.INGRESS.value, "channel_id", loopback_channel_id, now
                            )
                            await conn.execute(
                                "INSERT INTO queue (id, message_id, stage, channel_id,"
                                " destination_name, handler_name, payload, status, attempts,"
                                " next_attempt_at, created_at, updated_at)"
                                " VALUES ($1,$2,$3,$4,NULL,NULL,$5,$6,0,$7,$8,$9)",
                                uuid4().hex,
                                new_mid,
                                Stage.INGRESS.value,
                                loopback_channel_id,
                                self._cipher.encrypt(body),
                                OutboxStatus.PENDING.value,
                                now,
                                ingress_created,
                                now,
                            )
                        await self._event(
                            conn,
                            new_mid,
                            "received",
                            None,
                            f"reingress from {origin_id}/{dest}/seq{seq}",
                            now,
                        )
                        await self._event(
                            conn,
                            origin_id,
                            "reingressed",
                            dest,
                            f"-> {new_mid} depth {child_depth}",
                            now,
                        )
                    deleted = await conn.fetchval(
                        "DELETE FROM queue WHERE id=$1 AND stage=$2 AND status=$3 RETURNING id",
                        response_row_id,
                        Stage.RESPONSE.value,
                        OutboxStatus.INFLIGHT.value,
                    )
                    if deleted is None:
                        raise _Noop()  # unreachable under single-owner claim; roll back defensively
                    await self._maybe_finalize_message(conn, origin_id, now)
        except _Noop:
            return False
        return True

    async def response_body_for_work_row(self, response_row_id: str) -> str | None:
        """The decrypted artifact body a ``Stage.RESPONSE`` work-row references (ADR 0013) — the Postgres
        twin of :meth:`MessageStore.response_body_for_work_row`."""
        row = await self._pool.fetchrow(
            "SELECT payload FROM queue WHERE id=$1 AND stage=$2",
            response_row_id,
            Stage.RESPONSE.value,
        )
        if row is None:
            return None
        ref = self._dec(row["payload"]) or ""
        try:
            mid, dest, seq_s = ref.split("\x1f")
        except ValueError:
            return None
        art = await self._pool.fetchrow(
            "SELECT body FROM response WHERE message_id=$1 AND destination_name=$2 AND response_seq=$3",
            mid,
            dest,
            int(seq_s),
        )
        return self._dec(art["body"]) if (art and art["body"] is not None) else ""

    async def correlate_response(self, message_id: str) -> list[CapturedResponse]:
        """Every captured reply for ``message_id`` (ADR 0013), ordered by destination then
        ``response_seq``; ``body``/``detail`` decrypted. The PHI read surface behind the audited,
        body-gated ``GET /messages/{id}/responses`` route."""
        rows = await self._pool.fetch(
            "SELECT message_id, destination_name, response_seq, body, outcome, detail, captured_at"
            " FROM response WHERE message_id=$1 ORDER BY destination_name, response_seq",
            message_id,
        )
        return [
            CapturedResponse(
                message_id=r["message_id"],
                destination_name=r["destination_name"],
                response_seq=r["response_seq"],
                outcome=r["outcome"],
                detail=self._dec(r["detail"]),
                captured_at=r["captured_at"],
                body=self._dec(r["body"]),
            )
            for r in rows
        ]

    async def mark_failed(
        self, outbox_id: str, error: str, retry: RetryPolicy, now: float | None = None
    ) -> None:
        """Reschedule with exponential backoff, or dead-letter if retries are exhausted."""
        error = safe_text(error)  # PHI chokepoint (#120)
        now = time.time() if now is None else now
        async with self._pool.acquire() as conn:
            async with conn.transaction():
                row = await conn.fetchrow("SELECT * FROM queue WHERE id=$1", outbox_id)
                if row is None:
                    return
                attempts = row["attempts"]
                # max_attempts None = retry forever; a finite cap dead-letters once exhausted.
                if retry.max_attempts is not None and attempts >= retry.max_attempts:
                    status, next_at, event = OutboxStatus.DEAD.value, now, "dead"
                else:
                    backoff = min(
                        retry.max_backoff_seconds,
                        retry.backoff_seconds * (retry.backoff_multiplier ** (attempts - 1)),
                    )
                    status, next_at, event = OutboxStatus.PENDING.value, now + backoff, "failed"
                await conn.execute(
                    "UPDATE queue SET status=$1, next_attempt_at=$2, last_error=$3, updated_at=$4,"
                    " owner=NULL, lease_expires_at=NULL WHERE id=$5",
                    status,
                    next_at,
                    self._enc(error),
                    now,
                    outbox_id,
                )
                await self._event(
                    conn,
                    row["message_id"],
                    event,
                    row["destination_name"],
                    f"attempt {attempts}: {error}",
                    now,
                )
                if status == OutboxStatus.DEAD.value:
                    await self._maybe_finalize_message(conn, row["message_id"], now)

    async def pending_depth(
        self, name: str, *, stage: str = Stage.OUTBOUND.value
    ) -> tuple[int, float | None]:
        """``(pending_count, oldest_created_at)`` for one lane at ``stage`` (lane key stage-aware)."""
        lane_col = self._lane_col(stage)
        row = await self._fetchone(
            f"SELECT COUNT(*) AS n, MIN(created_at) AS oldest FROM queue"
            f" WHERE stage=$1 AND {lane_col}=$2 AND status=$3",
            stage,
            name,
            OutboxStatus.PENDING.value,
        )
        count = int(row["n"]) if row is not None else 0
        oldest = row["oldest"] if row is not None else None
        return count, (float(oldest) if oldest is not None else None)

    # --- recovery / replay ---------------------------------------------------

    async def reset_stale_inflight(
        self, now: float | None = None, *, stage: str | None = None
    ) -> int:
        """Return ``inflight`` rows (claimed before a crash) to ``pending``. ``stage=None`` recovers
        every stage in one pass (the right startup behavior).

        This is the **unconditional** single-node recovery: it reclaims *every* inflight row, ignoring
        the lease columns, which is correct on a single node (any inflight row at startup is this node's
        own crash residue). The additive multi-node mechanism is the lease columns + the owner-aware
        :meth:`reclaim_expired_leases`: in active-passive clustered mode the engine does NOT call this
        unconditional startup reset (which would steal a live sibling's in-flight rows) and instead runs
        :meth:`reclaim_expired_leases` periodically on the leader (recovering only rows whose lease has
        actually expired), plus the one-shot lease-blind :meth:`recover_inflight_on_promotion` on
        promotion. Expiry-gating this unconditional reset would strand a just-crashed single node's
        in-flight rows until their leases expire, so single-node keeps the unconditional path."""
        now = time.time() if now is None else now
        sql = (
            "UPDATE queue SET status=$1, next_attempt_at=$2, updated_at=$2,"
            " owner=NULL, lease_expires_at=NULL"
            " WHERE status=$3 AND ($4::text IS NULL OR stage=$4)"
        )
        result = await self._pool.execute(
            sql, OutboxStatus.PENDING.value, now, OutboxStatus.INFLIGHT.value, stage
        )
        return _rowcount(result)

    # --- multi-node row leases (Track B Step 2; additive, Postgres-only) ------
    # These are NOT on the Store protocol and NOT on the SQLite backend: SQLite is single-node, so its
    # unconditional reset_stale_inflight remains correct. In active-passive mode the leader runs the
    # lease-gated reclaim_expired_leases sweep (see reset_stale_inflight); a freshly-promoted leader
    # additionally runs the one-shot recover_inflight_on_promotion.

    async def reclaim_expired_leases(
        self, now: float | None = None, *, stage: str | None = None
    ) -> int:
        """Multi-node-safe reclaim: return to ``pending`` ONLY inflight rows whose lease has **expired**
        (``lease_expires_at < now``), clearing ``owner``/``lease_expires_at`` and making them due now.
        This is what a future leader periodic sweep calls; it must NEVER reclaim a row whose lease is
        still in the future, since that would steal a live sibling node's in-flight row. ``stage=None``
        sweeps every stage; pass a stage to scope it. Returns the number reclaimed.

        Clock assumption: the no-theft guarantee is a wall-clock lease — the reclaiming node compares
        its own ``now`` against a ``lease_expires_at`` stamped by the (possibly different) holder node's
        clock. It holds only when node clocks are synchronized (NTP) to well within ``lease_ttl_seconds``;
        set the TTL comfortably larger than expected skew + the renew interval so a skewed reclaimer
        can't beat a live holder's lease."""
        now = time.time() if now is None else now
        result = await self._pool.execute(
            "UPDATE queue SET status=$3, owner=NULL, lease_expires_at=NULL,"
            " next_attempt_at=$1, updated_at=$1"
            " WHERE status=$4 AND lease_expires_at IS NOT NULL AND lease_expires_at < $1"
            " AND ($2::text IS NULL OR stage=$2)",
            now,
            stage,
            OutboxStatus.PENDING.value,
            OutboxStatus.INFLIGHT.value,
        )
        return _rowcount(result)

    async def recover_inflight_on_promotion(self, *, now: float | None = None) -> int:
        """On active-passive promotion: recover the PRIOR leader's stranded work IMMEDIATELY, without
        waiting out the per-row lease TTL — the dominant ~``[store].lease_ttl_seconds`` failover-recovery
        delay on Postgres (#293; SQL Server already recovers at once via its on-promotion
        ``reset_stale_inflight``).

        **Owner-scoped queue-row reclaim** — return INFLIGHT rows owned by ANY OTHER store instance
        (the prior leader) to PENDING, **ignoring** lease expiry. Scoped to ``owner IS DISTINCT FROM
        self._owner``, so it is STRUCTURALLY incapable of re-pending THIS node's own freshly-claimed
        rows (no self-theft); at promotion this node has not claimed anything yet, so the set is exactly
        the prior leader's residue. Re-pending the stranded lane HEAD restores per-lane head-of-line
        blocking (no N+1-before-N reorder).

        **Safe ONLY in active-passive** (the wired graph runs on the leader ONLY): the prior leader
        self-fenced and its LEADERSHIP lease expired on the DB clock before this node could acquire it
        (``heartbeat < fence < leader_lease_ttl`` is validator-enforced), so there is no live processor
        whose rows this could steal — the SAME interlock the shipping SQL Server on-promotion
        ``reset_stale_inflight`` relies on. Returns the number of queue rows re-pended."""
        now = time.time() if now is None else now
        async with self._pool.acquire() as conn:
            async with conn.transaction():
                result = await conn.execute(
                    "UPDATE queue SET status=$1, owner=NULL, lease_expires_at=NULL,"
                    " next_attempt_at=$2, updated_at=$2"
                    " WHERE status=$3 AND owner IS DISTINCT FROM $4",
                    OutboxStatus.PENDING.value,
                    now,
                    OutboxStatus.INFLIGHT.value,
                    self._owner,
                )
        return _rowcount(result)

    async def dead_letter_missing_destinations(
        self, valid_names: set[str], now: float | None = None
    ) -> int:
        """Dead-letter every non-terminal **outbound** row whose ``destination_name`` left the
        registry. Scoped to ``stage='outbound'``. Returns the rows killed."""
        now = time.time() if now is None else now
        async with self._pool.acquire() as conn:
            async with conn.transaction():
                rows = await conn.fetch(
                    "SELECT id, message_id, destination_name FROM queue"
                    " WHERE stage=$1 AND status = ANY($2::text[])",
                    Stage.OUTBOUND.value,
                    [OutboxStatus.PENDING.value, OutboxStatus.INFLIGHT.value],
                )
                orphans = [r for r in rows if r["destination_name"] not in valid_names]
                if not orphans:
                    return 0
                error = "destination removed from outbound registry"
                # Pre-lock all affected messages' finalize locks in canonical order before the loop
                # finalizes any, so concurrent multi-message sweeps/cancels can't deadlock.
                await self._lock_finalize_batch(conn, (r["message_id"] for r in orphans))
                for row in orphans:
                    await conn.execute(
                        "UPDATE queue SET status=$1, next_attempt_at=$2, last_error=$3, updated_at=$4,"
                        " owner=NULL, lease_expires_at=NULL WHERE id=$5",
                        OutboxStatus.DEAD.value,
                        now,
                        self._enc(error),
                        now,
                        row["id"],
                    )
                    await self._event(
                        conn,
                        row["message_id"],
                        "dead",
                        row["destination_name"],
                        error,
                        now,
                    )
                    await self._maybe_finalize_message(conn, row["message_id"], now)
        log.warning(
            "dead-lettered %d orphaned outbox row(s) at startup for missing destination(s): %s",
            len(orphans),
            ", ".join(sorted({r["destination_name"] for r in orphans})),
        )
        return len(orphans)

    async def dead_letter_missing_handlers(
        self, valid_names: set[str], now: float | None = None
    ) -> int:
        """Dead-letter every non-terminal **routed** row whose ``handler_name`` left the registry
        (no transform worker can run it). Scoped to ``stage='routed'``. Returns the rows killed."""
        now = time.time() if now is None else now
        async with self._pool.acquire() as conn:
            async with conn.transaction():
                rows = await conn.fetch(
                    "SELECT id, message_id, handler_name FROM queue"
                    " WHERE stage=$1 AND status = ANY($2::text[])",
                    Stage.ROUTED.value,
                    [OutboxStatus.PENDING.value, OutboxStatus.INFLIGHT.value],
                )
                orphans = [r for r in rows if r["handler_name"] not in valid_names]
                if not orphans:
                    return 0
                error = "handler removed from registry"
                # Pre-lock all affected messages' finalize locks in canonical order before the loop
                # finalizes any, so concurrent multi-message sweeps/cancels can't deadlock.
                await self._lock_finalize_batch(conn, (r["message_id"] for r in orphans))
                for row in orphans:
                    await conn.execute(
                        "UPDATE queue SET status=$1, next_attempt_at=$2, last_error=$3, updated_at=$4,"
                        " owner=NULL, lease_expires_at=NULL WHERE id=$5",
                        OutboxStatus.DEAD.value,
                        now,
                        self._enc(error),
                        now,
                        row["id"],
                    )
                    await self._event(conn, row["message_id"], "dead", None, error, now)
                    await self._maybe_finalize_message(conn, row["message_id"], now)
        log.warning(
            "dead-lettered %d orphaned routed row(s) at startup for missing handler(s): %s",
            len(orphans),
            ", ".join(sorted({r["handler_name"] for r in orphans})),
        )
        return len(orphans)

    async def replay(self, message_id: str, now: float | None = None) -> int:
        """Re-queue a message for re-processing/re-delivery (attempts reset). Two modes: **recover**
        any ``dead``/``pending`` row (never a ``done`` sibling — the M-2 hazard), else **re-send** the
        ``done`` rows. ``cancelled`` rows are never touched. Returns rows requeued."""
        now = time.time() if now is None else now
        async with self._pool.acquire() as conn:
            async with conn.transaction():
                stuck_row = await conn.fetchrow(
                    "SELECT COUNT(*) AS n FROM queue WHERE message_id=$1 AND status = ANY($2::text[])",
                    message_id,
                    [OutboxStatus.DEAD.value, OutboxStatus.PENDING.value],
                )
                stuck = int(stuck_row["n"]) if stuck_row else 0
                replay_from = (
                    [OutboxStatus.DEAD.value, OutboxStatus.PENDING.value]
                    if stuck
                    else [OutboxStatus.DONE.value]
                )
                result = await conn.execute(
                    "UPDATE queue SET status=$1, attempts=0, next_attempt_at=$2, last_error=NULL,"
                    " updated_at=$2 WHERE message_id=$3 AND status = ANY($4::text[])",
                    OutboxStatus.PENDING.value,
                    now,
                    message_id,
                    replay_from,
                )
                count = _rowcount(result)
                if count:
                    pre = await conn.fetchrow(
                        "SELECT 1 FROM queue WHERE message_id=$1 AND stage = ANY($2::text[])"
                        " AND status=$3 LIMIT 1",
                        message_id,
                        [Stage.INGRESS.value, Stage.ROUTED.value],
                        OutboxStatus.PENDING.value,
                    )
                    status = MessageStatus.RECEIVED.value if pre else MessageStatus.ROUTED.value
                    await conn.execute(
                        "UPDATE messages SET status=$1, error=NULL WHERE id=$2", status, message_id
                    )
                    await self._event(conn, message_id, "replayed", None, f"{count} row(s)", now)
        return count

    async def replay_dead(
        self,
        *,
        channel_id: str | None = None,
        destination_name: str | None = None,
        now: float | None = None,
    ) -> int:
        """Re-queue dead-lettered **outbound** deliveries only (optionally scoped): set them back to
        ``pending`` with attempts reset, revert each affected message from ``error`` to ``routed``.
        Scoped to ``stage='outbound'`` to match the dead-letter view. Returns rows requeued."""
        now = time.time() if now is None else now
        async with self._pool.acquire() as conn:
            async with conn.transaction():
                ids = await conn.fetch(
                    "SELECT DISTINCT message_id FROM queue WHERE stage=$1 AND status=$2"
                    " AND ($3::text IS NULL OR channel_id=$3)"
                    " AND ($4::text IS NULL OR destination_name=$4)",
                    Stage.OUTBOUND.value,
                    OutboxStatus.DEAD.value,
                    channel_id,
                    destination_name,
                )
                message_ids = [r["message_id"] for r in ids]
                if not message_ids:
                    return 0
                result = await conn.execute(
                    "UPDATE queue SET status=$1, attempts=0, next_attempt_at=$2, last_error=NULL,"
                    " updated_at=$2 WHERE stage=$3 AND status=$4"
                    " AND ($5::text IS NULL OR channel_id=$5)"
                    " AND ($6::text IS NULL OR destination_name=$6)",
                    OutboxStatus.PENDING.value,
                    now,
                    Stage.OUTBOUND.value,
                    OutboxStatus.DEAD.value,
                    channel_id,
                    destination_name,
                )
                count = _rowcount(result)
                for message_id in message_ids:
                    await conn.execute(
                        "UPDATE messages SET status=$1, error=NULL WHERE id=$2 AND status=$3",
                        MessageStatus.ROUTED.value,
                        message_id,
                        MessageStatus.ERROR.value,
                    )
                    await self._event(conn, message_id, "replayed", None, "dead-letter replay", now)
        return count

    async def cancel_queued(
        self,
        channel_id: str | None,
        destination_name: str,
        *,
        top_only: bool = False,
        now: float | None = None,
    ) -> int:
        """Soft-cancel **pending** deliveries for a destination: mark them ``cancelled``, log a
        ``cancelled`` event each, and finalize any message whose deliveries are now all terminal.
        ``channel_id=None`` cancels across all producers; ``top_only`` cancels just the head. Returns
        the number cancelled."""
        now = time.time() if now is None else now
        query = (
            "SELECT id, message_id FROM queue"
            " WHERE destination_name=$1 AND status=$2 AND ($3::text IS NULL OR channel_id=$3)"
            " ORDER BY next_attempt_at, created_at"
        )
        if top_only:
            query += " LIMIT 1"
        async with self._pool.acquire() as conn:
            async with conn.transaction():
                rows = await conn.fetch(
                    query, destination_name, OutboxStatus.PENDING.value, channel_id
                )
                if not rows:
                    return 0
                ids = [r["id"] for r in rows]
                await conn.execute(
                    "UPDATE queue SET status=$1, updated_at=$2 WHERE id = ANY($3::text[])",
                    OutboxStatus.CANCELLED.value,
                    now,
                    ids,
                )
                for r in rows:
                    await self._event(
                        conn,
                        r["message_id"],
                        "cancelled",
                        destination_name,
                        "manual purge",
                        now,
                    )
                # Pre-lock every affected message's finalize lock in canonical order before finalizing
                # any, so two concurrent multi-message cancels can't form a lock cycle (deadlock).
                await self._lock_finalize_batch(conn, (r["message_id"] for r in rows))
                for message_id in {r["message_id"] for r in rows}:
                    await self._maybe_finalize_message(conn, message_id, now)
        return len(ids)

    # --- read helpers (API / console) ----------------------------------------

    async def get_message(self, message_id: str) -> dict[str, Any] | None:
        record = await self._fetchone("SELECT * FROM messages WHERE id=$1", message_id)
        if record is None:
            return None
        d = dict(record)
        d["raw"] = self._cipher.decrypt(d["raw"])  # decrypt the body for display
        d["error"] = self._dec(d["error"])  # error may embed raw HL7 fragments (WP-5)
        return d

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
    ) -> list[dict[str, Any]]:
        """Most-recent-first message listing (metadata only — bodies omitted until a message is
        opened + audited). ``allowed_channels`` restricts to a per-channel RBAC scope."""
        where, params = self._message_filter(
            channel_id, status, message_type, control_id, allowed_channels
        )
        n = len(params)
        rows = await self._fetchall(
            "SELECT id, channel_id, received_at, source_type, control_id, message_type,"
            " status, error, summary, metadata,"
            " (SELECT event FROM message_events e WHERE e.message_id = messages.id"
            "  ORDER BY e.id DESC LIMIT 1) AS last_event"
            f" FROM messages{where}"
            f" ORDER BY received_at DESC, id DESC LIMIT ${n + 1} OFFSET ${n + 2}",
            *params,
            limit,
            offset,
        )
        return [self._decode_record(r, "error") for r in rows]

    async def count_messages(
        self,
        *,
        channel_id: str | None = None,
        status: str | None = None,
        message_type: str | None = None,
        control_id: str | None = None,
        allowed_channels: Sequence[str] | None = None,
    ) -> int:
        where, params = self._message_filter(
            channel_id, status, message_type, control_id, allowed_channels
        )
        row = await self._fetchone(f"SELECT COUNT(*) AS n FROM messages{where}", *params)
        return int(row["n"]) if row else 0

    async def list_dead(
        self,
        *,
        channel_id: str | None = None,
        destination_name: str | None = None,
        limit: int = 50,
        offset: int = 0,
        allowed_channels: Sequence[str] | None = None,
    ) -> list[dict[str, Any]]:
        """Dead-lettered deliveries (one row per failed message→destination), newest first, joined
        with message metadata. Bodies omitted. ``allowed_channels`` restricts to a per-channel scope."""
        where, params = self._dead_filter(channel_id, destination_name, allowed_channels)
        n = len(params)
        rows = await self._fetchall(
            "SELECT o.id AS outbox_id, o.message_id, o.channel_id, o.destination_name,"
            " o.attempts, o.last_error, o.updated_at,"
            " m.control_id, m.message_type, m.received_at, m.summary"
            f" FROM queue o JOIN messages m ON m.id = o.message_id{where}"
            f" ORDER BY o.updated_at DESC, o.id DESC LIMIT ${n + 1} OFFSET ${n + 2}",
            *params,
            limit,
            offset,
        )
        return [self._decode_record(r, "last_error") for r in rows]

    async def count_dead(
        self,
        *,
        channel_id: str | None = None,
        destination_name: str | None = None,
        allowed_channels: Sequence[str] | None = None,
    ) -> int:
        where, params = self._dead_filter(channel_id, destination_name, allowed_channels)
        row = await self._fetchone(f"SELECT COUNT(*) AS n FROM queue o{where}", *params)
        return int(row["n"]) if row else 0

    @staticmethod
    def _message_filter(
        channel_id: str | None,
        status: str | None,
        message_type: str | None,
        control_id: str | None,
        allowed_channels: Sequence[str] | None = None,
    ) -> tuple[str, list[Any]]:
        clauses: list[str] = []
        params: list[Any] = []
        for column, value in (
            ("channel_id", channel_id),
            ("status", status),
            ("message_type", message_type),
            ("control_id", control_id),
        ):
            if value is not None:
                params.append(value)
                clauses.append(f"{column}=${len(params)}")
        _append_channel_scope_pg(clauses, params, "channel_id", allowed_channels)
        where = f" WHERE {' AND '.join(clauses)}" if clauses else ""
        return where, params

    @staticmethod
    def _dead_filter(
        channel_id: str | None,
        destination_name: str | None,
        allowed_channels: Sequence[str] | None = None,
    ) -> tuple[str, list[Any]]:
        # Scoped to outbound DEAD rows — the per-destination delivery DLQ.
        params: list[Any] = [Stage.OUTBOUND.value, OutboxStatus.DEAD.value]
        clauses = ["o.stage=$1", "o.status=$2"]
        if channel_id is not None:
            params.append(channel_id)
            clauses.append(f"o.channel_id=${len(params)}")
        if destination_name is not None:
            params.append(destination_name)
            clauses.append(f"o.destination_name=${len(params)}")
        _append_channel_scope_pg(clauses, params, "o.channel_id", allowed_channels)
        return f" WHERE {' AND '.join(clauses)}", params

    async def outbox_for(self, message_id: str) -> list[dict[str, Any]]:
        """The outbound deliveries for a message (one row per destination). Scoped to
        ``stage='outbound'`` — the transient ingress/routed rows aren't deliveries."""
        rows = await self._fetchall(
            "SELECT * FROM queue WHERE message_id=$1 AND stage=$2 ORDER BY destination_name",
            message_id,
            Stage.OUTBOUND.value,
        )
        # Only last_error is decrypted here; the encrypted `payload` body is left as-is on purpose —
        # bodies come through get_message (audited). Don't add `payload` to this projection's decrypt.
        return [self._decode_record(r, "last_error") for r in rows]

    async def outbox_payloads_for(self, message_id: str) -> list[dict[str, Any]]:
        """Like :meth:`outbox_for`, but also decrypts the transformed ``payload`` (PHI body) for the
        parity-comparison read path (#14). A separate method so ``outbox_for`` (message-detail
        metadata) never decrypts bodies; the API gates this on ``MESSAGES_VIEW_RAW`` and audits it."""
        rows = await self._fetchall(
            "SELECT * FROM queue WHERE message_id=$1 AND stage=$2 ORDER BY destination_name",
            message_id,
            Stage.OUTBOUND.value,
        )
        return [self._decode_record(r, "last_error", "payload") for r in rows]

    async def events_for(self, message_id: str) -> list[dict[str, Any]]:
        rows = await self._fetchall(
            "SELECT * FROM message_events WHERE message_id=$1 ORDER BY id", message_id
        )
        return [self._decode_record(r, "detail") for r in rows]

    async def stats(self) -> dict[str, int]:
        """Outbound-queue depth by status (scoped to outbound rows — the delivery backlog)."""
        rows = await self._fetchall(
            "SELECT status, COUNT(*) AS n FROM queue WHERE stage=$1 GROUP BY status",
            Stage.OUTBOUND.value,
        )
        return {r["status"]: int(r["n"]) for r in rows}

    async def in_pipeline_depth(self) -> int:
        """NOT-DONE rows (``pending``|``inflight``) across every stage — the whole-pipeline drain gauge."""
        rows = await self._fetchall(
            "SELECT COUNT(*) AS n FROM queue WHERE stage IN ($1,$2,$3) AND status IN ($4,$5)",
            Stage.INGRESS.value,
            Stage.ROUTED.value,
            Stage.OUTBOUND.value,
            OutboxStatus.PENDING.value,
            OutboxStatus.INFLIGHT.value,
        )
        return int(rows[0]["n"]) if rows else 0

    # --- audit log -----------------------------------------------------------

    async def record_view(
        self, message_id: str, *, actor: str | None = None, now: float | None = None
    ) -> None:
        """Append a ``viewed`` audit event (called whenever a message body / PHI is opened)."""
        now = time.time() if now is None else now
        async with self._pool.acquire() as conn:
            async with conn.transaction():
                await self._event(conn, message_id, "viewed", None, actor or "", now)

    async def record_audit(
        self,
        action: str,
        *,
        actor: str | None = None,
        channel_id: str | None = None,
        detail: str | None = None,
        now: float | None = None,
    ) -> None:
        """Append a row to the audit hash chain. H-7: takes the audit-chain advisory lock first, so
        concurrent writers serialize on the read-tail + insert and can't fork the chain.

        After the row commits, a **PHI-safe metadata copy** is teed off-box via the shared
        :func:`~messagefoundry.store.audit_tee.emit_audit_tee` (sec-offbox-log) — the same redaction
        path the SQLite and SQL Server backends use."""
        now = time.time() if now is None else now
        async with self._pool.acquire() as conn:
            async with conn.transaction():
                await self._advisory_lock(conn, _LOCK_CLASS_AUDIT, _AUDIT_LOCK)
                last = await conn.fetchrow(
                    "SELECT row_hash FROM audit_log ORDER BY id DESC LIMIT 1"
                )
                prev = last["row_hash"] if last and last["row_hash"] else ""
                row_hash = audit_row_hash(
                    prev, ts=now, actor=actor, action=action, channel_id=channel_id, detail=detail
                )
                await conn.execute(
                    "INSERT INTO audit_log (ts, actor, action, channel_id, detail, row_hash)"
                    " VALUES ($1,$2,$3,$4,$5,$6)",
                    now,
                    actor,
                    action,
                    channel_id,
                    detail,
                    row_hash,
                )
        # Tee off-box AFTER the transaction commits + the connection is released (only forward what
        # truly persisted; never hold the advisory lock / a pooled connection across a syslog send).
        emit_audit_tee(action=action, actor=actor, channel_id=channel_id, detail=detail, ts=now)

    async def list_audit(self, *, limit: int = 50) -> Sequence[Row]:
        """Most-recent-first audit entries (for review tooling / tests)."""
        return await self._fetchall("SELECT * FROM audit_log ORDER BY id DESC LIMIT $1", limit)

    async def security_events_for_user(self, username: str, *, limit: int = 100) -> Sequence[Row]:
        """A user's own security events (``auth.*``), most-recent-first — for ``GET
        /me/security-events`` (ASVS 6.3.5/6.3.7); admin-initiated changes go out-of-band by email."""
        return await self._fetchall(
            "SELECT ts, action, detail FROM audit_log "
            "WHERE actor = $1 AND action LIKE 'auth.%' ORDER BY id DESC LIMIT $2",
            username,
            limit,
        )

    # --- dual-control approvals (ASVS 2.3.5) ---------------------------------

    async def create_pending_approval(
        self,
        *,
        approval_id: str,
        operation: str,
        params: str,
        requester: str,
        requested_at: float,
        expires_at: float | None,
    ) -> None:
        """Persist a high-value action awaiting a distinct second approver (dual-control, 2.3.5)."""
        await self._execute(
            "INSERT INTO pending_approvals "
            "(id, operation, params, requester, requested_at, status, expires_at) "
            "VALUES ($1,$2,$3,$4,$5,'pending',$6)",
            approval_id,
            operation,
            params,
            requester,
            requested_at,
            expires_at,
        )

    async def get_pending_approval(self, approval_id: str) -> Row | None:
        row: Row | None = await self._fetchone(
            "SELECT id, operation, params, requester, requested_at, status, approver, decided_at,"
            " expires_at FROM pending_approvals WHERE id = $1",
            approval_id,
        )
        return row

    async def list_pending_approvals(self, *, now: float, limit: int = 100) -> Sequence[Row]:
        """Open (still-``pending``, unexpired) approval requests, newest-first."""
        return await self._fetchall(
            "SELECT id, operation, params, requester, requested_at, status, approver, decided_at,"
            " expires_at FROM pending_approvals"
            " WHERE status = 'pending' AND (expires_at IS NULL OR expires_at > $1)"
            " ORDER BY requested_at DESC LIMIT $2",
            now,
            limit,
        )

    async def decide_pending_approval(
        self, approval_id: str, *, status: str, approver: str | None, decided_at: float
    ) -> bool:
        """Atomically move a still-``pending`` request to ``status`` (approved/rejected/expired).
        Returns ``True`` iff this call made the transition — guards against a double decision."""
        result = await self._pool.execute(
            "UPDATE pending_approvals SET status = $1, approver = $2, decided_at = $3"
            " WHERE id = $4 AND status = 'pending'",
            status,
            approver,
            decided_at,
            approval_id,
        )
        return _rowcount(result) > 0

    async def audit_anchor(self) -> tuple[int, str]:
        """The audit log's external anchor — ``(row_count, head_hash)`` (head ``""`` when empty)."""
        row = await self._fetchone(
            "SELECT COUNT(*) AS n, "
            "(SELECT row_hash FROM audit_log ORDER BY id DESC LIMIT 1) AS head FROM audit_log"
        )
        if row is None:
            return 0, ""
        return int(row["n"]), (row["head"] or "")

    async def verify_audit_chain(
        self, *, expected_anchor: tuple[int, str] | None = None
    ) -> tuple[bool, str | None]:
        """Recompute the audit hash-chain in order; returns ``(ok, message)``. Pass ``expected_anchor``
        from :meth:`audit_anchor` (held out-of-band) to also detect tail-truncation."""
        rows = await self._fetchall(
            "SELECT id, ts, actor, action, channel_id, detail, row_hash FROM audit_log ORDER BY id"
        )
        prev = ""
        count = 0
        for r in rows:
            expected = audit_row_hash(
                prev,
                ts=r["ts"],
                actor=r["actor"],
                action=r["action"],
                channel_id=r["channel_id"],
                detail=r["detail"],
            )
            if r["row_hash"] != expected:
                return False, f"audit chain broken at row id={r['id']}"
            prev = r["row_hash"]
            count += 1
        if expected_anchor is not None:
            exp_count, exp_head = expected_anchor
            if count < exp_count or prev != exp_head:
                return (
                    False,
                    f"audit log diverges from recorded anchor (have {count} row(s) head {prev[:12]!r}, "
                    f"expected {exp_count} head {exp_head[:12]!r}) — truncated or rewritten",
                )
        return True, f"verified {count} audit row(s)"

    # --- auth: users / roles / sessions --------------------------------------

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
    ) -> None:
        now = time.time() if now is None else now
        await self._execute(
            "INSERT INTO users (id, username, auth_provider, display_name, email, disabled,"
            " created_at, updated_at, last_login_at, password_hash, password_changed_at,"
            " must_change_password, failed_attempts, locked_until)"
            " VALUES ($1,$2,$3,$4,$5,FALSE,$6,$6,NULL,$7,$8,$9,0,NULL)",
            user_id,
            username,
            auth_provider,
            display_name,
            email,
            now,
            password_hash,
            now if password_hash is not None else None,
            must_change_password,
        )

    async def get_user(self, user_id: str) -> UserRecord | None:
        d = await self._fetchone("SELECT * FROM users WHERE id=$1", user_id)
        return UserRecord.from_mapping(dict(d)) if d else None

    async def get_user_by_username(self, username: str) -> UserRecord | None:
        d = await self._fetchone("SELECT * FROM users WHERE username=$1", username)
        return UserRecord.from_mapping(dict(d)) if d else None

    async def list_users(self) -> list[UserRecord]:
        rows = await self._fetchall("SELECT * FROM users ORDER BY username")
        return [UserRecord.from_mapping(dict(r)) for r in rows]

    async def count_users(self) -> int:
        return await self._count("users")

    async def set_password(
        self,
        user_id: str,
        *,
        password_hash: str,
        must_change_password: bool = False,
        now: float | None = None,
    ) -> None:
        now = time.time() if now is None else now
        await self._execute(
            "UPDATE users SET password_hash=$1, password_changed_at=$2, must_change_password=$3,"
            " failed_attempts=0, locked_until=NULL, updated_at=$2 WHERE id=$4",
            password_hash,
            now,
            must_change_password,
            user_id,
        )

    # --- MFA: native TOTP second factor (local accounts, WP-14) --------------

    async def set_totp_secret(
        self, user_id: str, *, secret: str | None, now: float | None = None
    ) -> None:
        """Stage (or clear) a user's base32 TOTP secret, store-cipher encrypted. Does not enable MFA."""
        now = time.time() if now is None else now
        await self._execute(
            "UPDATE users SET totp_secret=$1, updated_at=$2 WHERE id=$3",
            self._enc(secret),
            now,
            user_id,
        )

    async def get_totp_secret(self, user_id: str) -> str | None:
        d = await self._fetchone("SELECT totp_secret FROM users WHERE id=$1", user_id)
        if not d or d["totp_secret"] is None:
            return None
        return self._dec(d["totp_secret"])

    async def enable_totp(
        self, user_id: str, *, recovery_code_hashes: list[str], now: float | None = None
    ) -> None:
        now = time.time() if now is None else now
        await self._execute(
            "UPDATE users SET totp_enabled=TRUE, totp_enrolled_at=$1, totp_recovery_codes=$2,"
            " updated_at=$1 WHERE id=$3",
            now,
            json.dumps(recovery_code_hashes),
            user_id,
        )

    async def disable_totp(self, user_id: str, *, now: float | None = None) -> None:
        now = time.time() if now is None else now
        await self._execute(
            "UPDATE users SET totp_secret=NULL, totp_enabled=FALSE, totp_enrolled_at=NULL,"
            " totp_recovery_codes=NULL, updated_at=$1 WHERE id=$2",
            now,
            user_id,
        )

    async def get_recovery_code_hashes(self, user_id: str) -> list[str]:
        d = await self._fetchone("SELECT totp_recovery_codes FROM users WHERE id=$1", user_id)
        if not d or d["totp_recovery_codes"] is None:
            return []
        return [str(h) for h in json.loads(d["totp_recovery_codes"])]

    async def consume_recovery_code_hash(
        self, user_id: str, code_hash: str, *, now: float | None = None
    ) -> bool:
        """Atomically remove one recovery-code hash; ``True`` iff present. The ``SELECT ... FOR UPDATE``
        + ``UPDATE`` run in one transaction, so concurrent verifications (even cross-node) can't
        double-spend a single-use recovery code (WP-14)."""
        now = time.time() if now is None else now
        async with self._pool.acquire() as conn:
            async with conn.transaction():
                row = await conn.fetchrow(
                    "SELECT totp_recovery_codes FROM users WHERE id=$1 FOR UPDATE", user_id
                )
                if row is None or row["totp_recovery_codes"] is None:
                    return False
                hashes = [str(h) for h in json.loads(row["totp_recovery_codes"])]
                if code_hash not in hashes:
                    return False  # already consumed by a concurrent caller
                hashes.remove(code_hash)
                await conn.execute(
                    "UPDATE users SET totp_recovery_codes=$1, updated_at=$2 WHERE id=$3",
                    json.dumps(hashes),
                    now,
                    user_id,
                )
                return True

    async def consume_totp_step(self, user_id: str, step: int) -> bool:
        """Atomically record ``step`` as the user's highest consumed TOTP time-step; ``True`` iff newly
        consumed (strictly greater than any prior step). A code replayed inside its ±1-step verify
        window resolves to a non-greater step and returns ``False`` — single-use per ASVS 6.5.1. The
        ``SELECT ... FOR UPDATE`` + ``UPDATE`` run in one transaction (no cross-node double-spend)."""
        async with self._pool.acquire() as conn:
            async with conn.transaction():
                row = await conn.fetchrow(
                    "SELECT last_totp_step FROM users WHERE id=$1 FOR UPDATE", user_id
                )
                if row is None:
                    return False
                last = row["last_totp_step"]
                if last is not None and last >= step:
                    return False  # already consumed (or an older step) — replay within the window
                await conn.execute("UPDATE users SET last_totp_step=$1 WHERE id=$2", step, user_id)
                return True

    async def set_user_disabled(
        self, user_id: str, *, disabled: bool, now: float | None = None
    ) -> None:
        now = time.time() if now is None else now
        await self._execute(
            "UPDATE users SET disabled=$1, updated_at=$2 WHERE id=$3", disabled, now, user_id
        )

    async def update_user_profile(
        self,
        user_id: str,
        *,
        display_name: str | None,
        email: str | None,
        now: float | None = None,
    ) -> None:
        now = time.time() if now is None else now
        await self._execute(
            "UPDATE users SET display_name=$1, email=$2, updated_at=$3 WHERE id=$4",
            display_name,
            email,
            now,
            user_id,
        )

    async def delete_user(self, user_id: str) -> None:
        async with self._pool.acquire() as conn:
            async with conn.transaction():
                await conn.execute("DELETE FROM user_roles WHERE user_id=$1", user_id)
                await conn.execute("DELETE FROM sessions WHERE user_id=$1", user_id)
                await conn.execute("DELETE FROM users WHERE id=$1", user_id)

    async def record_login_success(self, user_id: str, *, now: float | None = None) -> None:
        now = time.time() if now is None else now
        await self._execute(
            "UPDATE users SET last_login_at=$1, failed_attempts=0, locked_until=NULL,"
            " updated_at=$1 WHERE id=$2",
            now,
            user_id,
        )

    async def record_login_failure(
        self,
        user_id: str,
        *,
        failed_attempts: int,
        locked_until: float | None,
        now: float | None = None,
    ) -> None:
        now = time.time() if now is None else now
        await self._execute(
            "UPDATE users SET failed_attempts=$1, locked_until=$2, updated_at=$3 WHERE id=$4",
            failed_attempts,
            locked_until,
            now,
            user_id,
        )

    async def upsert_role(
        self,
        *,
        role_id: str,
        display_name: str,
        description: str | None = None,
        builtin: bool = True,
    ) -> None:
        await self._execute(
            "INSERT INTO roles (id, display_name, description, builtin) VALUES ($1,$2,$3,$4)"
            " ON CONFLICT (id) DO UPDATE SET display_name=excluded.display_name,"
            " description=excluded.description, builtin=excluded.builtin",
            role_id,
            display_name,
            description,
            builtin,
        )

    async def list_roles(self) -> Sequence[Row]:
        return await self._fetchall("SELECT * FROM roles ORDER BY id")

    async def get_user_role_ids(self, user_id: str) -> list[str]:
        rows = await self._fetchall(
            "SELECT role_id FROM user_roles WHERE user_id=$1 ORDER BY role_id", user_id
        )
        return [str(r["role_id"]) for r in rows]

    async def set_user_roles(
        self,
        user_id: str,
        role_ids: Sequence[str],
        *,
        assigned_by: str | None = None,
        now: float | None = None,
    ) -> None:
        now = time.time() if now is None else now
        async with self._pool.acquire() as conn:
            async with conn.transaction():
                await conn.execute("DELETE FROM user_roles WHERE user_id=$1", user_id)
                for role_id in role_ids:
                    await conn.execute(
                        "INSERT INTO user_roles (user_id, role_id, assigned_at, assigned_by)"
                        " VALUES ($1,$2,$3,$4)",
                        user_id,
                        role_id,
                        now,
                        assigned_by,
                    )

    async def set_user_channel_scope(
        self, user_id: str, scope_json: str | None, *, now: float | None = None
    ) -> None:
        """Set a user's per-channel scope (JSON list of connection names, or ``None`` = all)."""
        now = time.time() if now is None else now
        await self._execute(
            "UPDATE users SET channel_scope=$1, updated_at=$2 WHERE id=$3", scope_json, now, user_id
        )

    async def roles_for_ad_groups(self, groups: Iterable[str]) -> set[str]:
        normalized = sorted({g.strip().lower() for g in groups if g.strip()})
        if not normalized:
            return set()
        rows = await self._fetchall(
            "SELECT DISTINCT role_id FROM ad_group_role_map WHERE ad_group = ANY($1::text[])",
            normalized,
        )
        return {str(r["role_id"]) for r in rows}

    async def list_ad_group_role_map(self) -> Sequence[Row]:
        return await self._fetchall(
            "SELECT ad_group, role_id FROM ad_group_role_map ORDER BY ad_group, role_id"
        )

    async def set_ad_group_role_map(self, entries: Iterable[tuple[str, str]]) -> None:
        pairs = sorted({(g.strip().lower(), r) for g, r in entries if g.strip()})
        async with self._pool.acquire() as conn:
            async with conn.transaction():
                await conn.execute("DELETE FROM ad_group_role_map")
                for ad_group, role_id in pairs:
                    await conn.execute(
                        "INSERT INTO ad_group_role_map (ad_group, role_id) VALUES ($1,$2)",
                        ad_group,
                        role_id,
                    )

    async def channels_for_ad_groups(self, groups: Iterable[str]) -> set[str]:
        normalized = sorted({g.strip().lower() for g in groups if g.strip()})
        if not normalized:
            return set()
        rows = await self._fetchall(
            "SELECT DISTINCT channel FROM ad_group_scope_map WHERE ad_group = ANY($1::text[])",
            normalized,
        )
        return {str(r["channel"]) for r in rows}

    async def list_ad_group_scope_map(self) -> Sequence[Row]:
        return await self._fetchall(
            "SELECT ad_group, channel FROM ad_group_scope_map ORDER BY ad_group, channel"
        )

    async def set_ad_group_scope_map(self, entries: Iterable[tuple[str, str]]) -> None:
        pairs = sorted(
            {(g.strip().lower(), c.strip()) for g, c in entries if g.strip() and c.strip()}
        )
        async with self._pool.acquire() as conn:
            async with conn.transaction():
                await conn.execute("DELETE FROM ad_group_scope_map")
                for ad_group, channel in pairs:
                    await conn.execute(
                        "INSERT INTO ad_group_scope_map (ad_group, channel) VALUES ($1,$2)",
                        ad_group,
                        channel,
                    )

    async def create_session(
        self,
        *,
        token_hash: str,
        user_id: str,
        expires_at: float,
        client: str | None = None,
        seed_reauth: bool = True,
        now: float | None = None,
    ) -> None:
        now = time.time() if now is None else now
        await self._execute(
            # reauth_at ($6) seeds the step-up window from login (ASVS 7.5.3); seed_reauth=False leaves
            # it NULL for an MFA-PENDING session (WP-14) so a stolen pre-MFA token can't enroll/step-up.
            "INSERT INTO sessions (token_hash, user_id, created_at, expires_at, last_used_at,"
            " revoked_at, client, reauth_at) VALUES ($1,$2,$3,$4,$3,NULL,$5,$6)",
            token_hash,
            user_id,
            now,
            expires_at,
            client,
            now if seed_reauth else None,
        )

    async def get_session(self, token_hash: str) -> SessionRecord | None:
        d = await self._fetchone("SELECT * FROM sessions WHERE token_hash=$1", token_hash)
        return SessionRecord.from_mapping(dict(d)) if d else None

    async def list_sessions(self, user_id: str, *, now: float | None = None) -> list[SessionRecord]:
        """A user's active (not revoked/expired) sessions, most-recently-used first (WP-10)."""
        now = time.time() if now is None else now
        rows = await self._fetchall(
            "SELECT * FROM sessions WHERE user_id=$1 AND revoked_at IS NULL AND expires_at > $2"
            " ORDER BY last_used_at DESC",
            user_id,
            now,
        )
        return [SessionRecord.from_mapping(dict(r)) for r in rows]

    async def touch_session(self, token_hash: str, *, now: float | None = None) -> None:
        now = time.time() if now is None else now
        await self._execute(
            "UPDATE sessions SET last_used_at=$1 WHERE token_hash=$2", now, token_hash
        )

    async def mark_session_reauthed(
        self, token_hash: str, *, now: float | None = None, client: str | None = None
    ) -> None:
        now = time.time() if now is None else now
        # COALESCE keeps the stored client when none is supplied; a re-verify carrying the current
        # address re-anchors the session to it (WP-L3-13 new-client-IP step-up).
        await self._execute(
            "UPDATE sessions SET reauth_at=$1, client=COALESCE($2, client) WHERE token_hash=$3",
            now,
            client,
            token_hash,
        )

    async def mark_session_mfa_verified(self, token_hash: str, *, now: float | None = None) -> None:
        now = time.time() if now is None else now
        await self._execute(
            "UPDATE sessions SET mfa_verified_at=$1 WHERE token_hash=$2", now, token_hash
        )

    async def revoke_session(self, token_hash: str, *, now: float | None = None) -> None:
        now = time.time() if now is None else now
        await self._execute(
            "UPDATE sessions SET revoked_at=$1 WHERE token_hash=$2 AND revoked_at IS NULL",
            now,
            token_hash,
        )

    async def revoke_user_sessions(
        self, user_id: str, *, except_token_hash: str | None = None, now: float | None = None
    ) -> int:
        """Revoke a user's active sessions (all, or all but ``except_token_hash``). Returns the count."""
        now = time.time() if now is None else now
        result = await self._pool.execute(
            "UPDATE sessions SET revoked_at=$1 WHERE user_id=$2 AND revoked_at IS NULL"
            " AND ($3::text IS NULL OR token_hash != $3)",
            now,
            user_id,
            except_token_hash,
        )
        return _rowcount(result)

    async def enforce_session_cap(
        self, user_id: str, *, keep: int, now: float | None = None
    ) -> None:
        """Revoke a user's active sessions beyond the ``keep`` most recently created (AUTH-SESS-CAP)."""
        if keep <= 0:
            return
        now = time.time() if now is None else now
        await self._execute(
            "UPDATE sessions SET revoked_at=$1 WHERE user_id=$2 AND revoked_at IS NULL"
            " AND token_hash NOT IN ("
            "  SELECT token_hash FROM sessions WHERE user_id=$2 AND revoked_at IS NULL"
            "  ORDER BY created_at DESC, token_hash DESC LIMIT $3"
            ")",
            now,
            user_id,
            keep,
        )

    async def purge_expired_sessions(self, *, now: float | None = None) -> int:
        now = time.time() if now is None else now
        result = await self._pool.execute("DELETE FROM sessions WHERE expires_at < $1", now)
        return _rowcount(result)

    # --- retention / purge + maintenance (PHI.md §8) -------------------------

    async def purge_message_bodies(self, *, older_than: float, now: float | None = None) -> int:
        """Null the PHI **bodies** of fully-resolved messages received before ``older_than`` while
        keeping their metadata rows (the Mirth Data-Pruner pattern). Eligible only when the message has
        no queue row still ``pending``/``inflight``. Ported, not stubbed — Postgres supports retention.
        Returns the number of messages whose body was nulled."""
        now = time.time() if now is None else now
        inflight = [OutboxStatus.PENDING.value, OutboxStatus.INFLIGHT.value]
        # A message past the cutoff with nothing still in flight. This subquery is embedded in three
        # UPDATEs below; it consumes exactly $1 (older_than) and $2 (inflight[]), so each outer query
        # must keep passing those two FIRST and continue its own binds from $3. Don't add/remove a bind
        # here without re-numbering the outer queries.
        eligible = (
            "SELECT id FROM messages m WHERE m.received_at < $1"
            " AND NOT EXISTS (SELECT 1 FROM queue q WHERE q.message_id = m.id"
            " AND q.status = ANY($2::text[]))"
        )
        async with self._pool.acquire() as conn:
            async with conn.transaction():
                result = await conn.execute(
                    f"UPDATE messages SET raw='', summary=NULL, error=NULL"
                    f" WHERE raw <> '' AND id IN ({eligible})",
                    older_than,
                    inflight,
                )
                purged = _rowcount(result)
                await conn.execute(
                    f"UPDATE queue SET payload='', last_error=NULL"
                    f" WHERE stage=$3 AND status = ANY($4::text[]) AND payload <> ''"
                    f" AND message_id IN ({eligible})",
                    older_than,
                    inflight,
                    Stage.OUTBOUND.value,
                    [OutboxStatus.DONE.value, OutboxStatus.CANCELLED.value],
                )
                await conn.execute(
                    f"UPDATE message_events SET detail=NULL"
                    f" WHERE detail IS NOT NULL AND message_id IN ({eligible})",
                    older_than,
                    inflight,
                )
                # Captured replies (ADR 0013) are PHI on the same window as the body; null in place
                # (row kept, FK to messages(id) never violated — purge keeps the messages row).
                await conn.execute(
                    f"UPDATE response SET body=NULL, detail=NULL"
                    f" WHERE (body IS NOT NULL OR detail IS NOT NULL) AND message_id IN ({eligible})",
                    older_than,
                    inflight,
                )
        return purged

    async def purge_dead_letters(self, *, older_than: float, now: float | None = None) -> int:
        """Null the bodies of dead-lettered **outbound** rows last updated before ``older_than`` (their
        own retention window). Keeps the row + ``dead`` status; blanks ``payload`` + ``last_error``.
        Ported, not stubbed. Returns the number of dead rows purged."""
        now = time.time() if now is None else now
        result = await self._pool.execute(
            "UPDATE queue SET payload='', last_error=NULL"
            " WHERE stage=$1 AND status=$2 AND payload <> '' AND updated_at < $3",
            Stage.OUTBOUND.value,
            OutboxStatus.DEAD.value,
            older_than,
        )
        return _rowcount(result)

    async def purge_state(self, *, older_than: float, now: float | None = None) -> int:
        """Delete transform-state entries last written before ``older_than`` (ADR 0005 retention) and
        evict them from the read cache after commit. Ported, not stubbed. Returns the number purged.

        Track B Step 6b: when clustered, bump the version of each DISTINCT namespace a row was purged from
        (atomically with the delete) so a follower's converge_state_cache() re-reads it and drops the same
        keys (the version-scan reload re-seeds the surviving rows, leaving the purged keys gone). Gated, so
        single-node writes no state_version rows and stays byte-identical."""
        now = time.time() if now is None else now
        async with self._pool.acquire() as conn:
            async with conn.transaction():
                rows = await conn.fetch(
                    "SELECT namespace, key FROM state WHERE set_at < $1", older_than
                )
                purged_keys = [(r["namespace"], r["key"]) for r in rows]
                if not purged_keys:
                    return 0
                await conn.execute("DELETE FROM state WHERE set_at < $1", older_than)
                bumped: list[tuple[str, int]] = []
                if self._cluster_state_convergence:
                    for ns in dict.fromkeys(n for n, _ in purged_keys):  # distinct, order-stable
                        vrow = await conn.fetchrow(
                            "INSERT INTO state_version (namespace, version, updated_at) "
                            "VALUES ($1, 1, $2) "
                            "ON CONFLICT (namespace) DO UPDATE SET "
                            "version = state_version.version + 1, updated_at = excluded.updated_at "
                            "RETURNING version",
                            ns,
                            now,
                        )
                        assert vrow is not None, "state_version upsert returned no row"
                        bumped.append((ns, int(vrow["version"])))
        # Commit succeeded → evict the purged keys from the read-through cache.
        for ck in purged_keys:
            self._state_cache.pop(ck, None)
        # Record this node's new per-namespace versions so its own converge skips re-reading them.
        for ns, ver in bumped:
            self._state_versions[ns] = ver
        return len(purged_keys)

    async def wal_checkpoint(self) -> None:
        """No-op on Postgres — there is no SQLite WAL to checkpoint (Postgres autovacuum/checkpointer
        manage this). Present for ``Store`` protocol completeness."""

    async def vacuum(self) -> None:
        """No-op on Postgres — autovacuum reclaims space; manual VACUUM is a DBA operation here, not
        an engine concern. Present for ``Store`` protocol completeness."""

    # --- store health / metrics ----------------------------------------------

    async def db_status(self) -> DbStatus:
        size = await self._fetchone("SELECT pg_database_size(current_database()) AS b")
        return DbStatus(
            path=self.path,
            size_bytes=int(size["b"]) if size and size["b"] is not None else 0,
            disk_free_bytes=0,  # not readily available for a remote Postgres server
            journal_mode="postgres",
            messages=await self._count("messages"),
            events=await self._count("message_events"),
            audit=await self._count("audit_log"),
        )

    async def integrity_check(self) -> tuple[bool, str]:
        # A connectivity probe; deep checks (amcheck / pg_amcheck) are an out-of-band DBA task.
        await self._fetchone("SELECT 1 AS ok")
        return True, "ok (postgres; deep checks are a DBA task)"

    async def connection_metrics(
        self, *, since: float, now: float | None = None, rate_window: float = 60.0
    ) -> ConnectionMetrics:
        """Aggregate per-channel inbound and per-destination outbound metrics for the connections
        dashboard (mirrors the SQLite store; outbound rows only)."""
        now = time.time() if now is None else now
        rate_since = now - rate_window

        count_rows = await self._fetchall(
            "SELECT channel_id, COUNT(*) AS read,"
            " SUM(CASE WHEN status=$1 THEN 1 ELSE 0 END) AS errored"
            " FROM messages WHERE received_at>=$2 GROUP BY channel_id",
            MessageStatus.ERROR.value,
            since,
        )
        counts = {r["channel_id"]: (r["read"], r["errored"]) for r in count_rows}
        last_rows = await self._fetchall(
            "SELECT channel_id, MAX(received_at) AS last_at FROM messages GROUP BY channel_id"
        )
        inbound: dict[str, InboundMetrics] = {}
        for r in last_rows:
            read, errored = counts.pop(r["channel_id"], (0, 0))
            inbound[r["channel_id"]] = InboundMetrics(
                read=int(read), errored=int(errored or 0), last_at=r["last_at"]
            )
        for cid, (read, errored) in counts.items():
            inbound[cid] = InboundMetrics(read=int(read), errored=int(errored or 0), last_at=None)

        dest_rows = await self._fetchall(
            "SELECT channel_id, destination_name,"
            " SUM(CASE WHEN status IN ($1,$2) THEN 1 ELSE 0 END) AS queue_depth,"
            " SUM(CASE WHEN status=$3 AND updated_at>=$4 THEN 1 ELSE 0 END) AS written,"
            " SUM(CASE WHEN status=$5 AND updated_at>=$6 THEN 1 ELSE 0 END) AS dead,"
            " MIN(CASE WHEN status=$7 THEN created_at END) AS oldest_pending_at,"
            " SUM(CASE WHEN status=$8 AND updated_at>=$9 THEN 1 ELSE 0 END) AS recent_done,"
            " MAX(CASE WHEN status=$10 THEN updated_at END) AS last_done_at"
            " FROM queue WHERE stage=$11 GROUP BY channel_id, destination_name",
            OutboxStatus.PENDING.value,
            OutboxStatus.INFLIGHT.value,
            OutboxStatus.DONE.value,
            since,
            OutboxStatus.DEAD.value,
            since,
            OutboxStatus.PENDING.value,
            OutboxStatus.DONE.value,
            rate_since,
            OutboxStatus.DONE.value,
            Stage.OUTBOUND.value,
        )
        destinations: dict[tuple[str, str], DestinationMetrics] = {}
        for r in dest_rows:
            destinations[(r["channel_id"], r["destination_name"])] = DestinationMetrics(
                queue_depth=int(r["queue_depth"] or 0),
                written=int(r["written"] or 0),
                dead=int(r["dead"] or 0),
                oldest_pending_at=r["oldest_pending_at"],
                recent_done=int(r["recent_done"] or 0),
                last_done_at=r["last_done_at"],
            )
        return ConnectionMetrics(inbound=inbound, destinations=destinations)

    async def delivery_latency_histogram(
        self, *, buckets: Sequence[float], now: float | None = None
    ) -> Sequence[LatencyHistogram]:
        """Per-(channel_id, destination_name) delivery-latency histogram over outbound rows that
        reached status='done'. Latency = updated_at - created_at (seconds), clamped to >= 0 (clock-
        skew guard). bucket_counts are CUMULATIVE (Prometheus le semantics). Read-only; runs off the
        event loop."""
        # Only the NUMBER of CASE clauses (len(buckets)) is generated; each boundary is a BOUND
        # parameter ($n, never string-interpolated), so this is injection-safe. Bucket boundaries
        # bind to $1..$n, then stage and status take the trailing placeholders.
        n = len(buckets)
        bucket_cols = ", ".join(
            f"SUM(CASE WHEN (updated_at - created_at) <= ${i + 1} THEN 1 ELSE 0 END) AS b{i}"
            for i in range(n)
        )
        select_cols = f"{bucket_cols}, " if bucket_cols else ""
        sql = (
            "SELECT channel_id, destination_name, "
            f"{select_cols}"
            "SUM(CASE WHEN updated_at >= created_at THEN updated_at - created_at ELSE 0 END)"
            " AS sum_seconds,"
            " COUNT(*) AS cnt"
            f" FROM queue WHERE stage=${n + 1} AND status=${n + 2}"
            " GROUP BY channel_id, destination_name"
            " ORDER BY channel_id, destination_name"
        )
        rows = await self._fetchall(sql, *buckets, Stage.OUTBOUND.value, OutboxStatus.DONE.value)
        return [
            LatencyHistogram(
                channel_id=r["channel_id"],
                destination_name=r["destination_name"],
                bucket_counts=tuple(int(r[f"b{i}"] or 0) for i in range(n)),
                sum_seconds=float(r["sum_seconds"] or 0),
                count=int(r["cnt"] or 0),
            )
            for r in rows
        ]

    # --- internals -----------------------------------------------------------

    async def _maybe_finalize_message(self, conn: Any, message_id: str, now: float) -> None:
        """Drive a message to its terminal disposition from its queue rows across **all** stages — the
        single source of truth for the staged-pipeline count-and-log flow (ADR 0001 Step B; the FULL
        finalizer with the ROUTED→FILTERED collapse, ported from MessageStore, not the simpler
        outbound-only one).

        H-8: takes the **per-message** finalize advisory lock (before the ``messages`` UPDATE *within
        finalize*) so per-message finalize is serialized — the lock auto-releases at the enclosing
        transaction's commit — and recomputes on a fresh snapshot, so no double-finalize. Different
        message_ids never contend. The lock is re-entrant, so a caller that pre-locks a batch in
        canonical order (:meth:`_lock_finalize_batch` in cancel_queued / the dead-letter sweeps, to
        avoid a multi-message lock-ordering deadlock) re-takes it here as a no-op.

        The message is **not** finalized while ANY row at ANY stage is still pending/inflight. Once
        nothing is in flight, in strict precedence: any **dead** row anywhere → ``ERROR``; else any
        **outbound** row exists → ``PROCESSED``; else **no rows remain** and the message is still
        ``ROUTED`` → ``FILTERED`` (every selected handler ran and produced zero deliveries); else leave
        the disposition the handoff set."""
        await self._advisory_lock(
            conn, _LOCK_CLASS_FINALIZE, f"{_FINALIZE_LOCK_PREFIX}{message_id}"
        )
        rows = await conn.fetch(
            "SELECT stage, status, COUNT(*) AS n FROM queue WHERE message_id=$1 GROUP BY stage, status",
            message_id,
        )
        if any(
            r["status"] in (OutboxStatus.PENDING.value, OutboxStatus.INFLIGHT.value) for r in rows
        ):
            return  # in flight at any stage → still moving; do not finalize
        if any(r["status"] == OutboxStatus.DEAD.value for r in rows):
            status = MessageStatus.ERROR.value
        elif any(r["stage"] == Stage.OUTBOUND.value for r in rows):
            status = MessageStatus.PROCESSED.value  # all delivered (or operator-cancelled)
        elif not rows:
            # No queue rows remain. ROUTED here means every handler's transform produced zero
            # deliveries → collapse to FILTERED. UNROUTED / already-FILTERED keep their status.
            msg = await conn.fetchrow("SELECT status FROM messages WHERE id=$1", message_id)
            if msg is None or msg["status"] != MessageStatus.ROUTED.value:
                return
            status = MessageStatus.FILTERED.value
        else:
            return  # only terminal non-dead non-outbound rows (shouldn't occur) — leave as-is
        await conn.execute("UPDATE messages SET status=$1 WHERE id=$2", status, message_id)


def _rowcount(command_tag: str) -> int:
    """Parse the affected-row count out of an asyncpg command tag (e.g. ``"UPDATE 3"`` → ``3``,
    ``"DELETE 0"`` → ``0``). asyncpg returns the tag string from ``Connection.execute``; the count is
    its last whitespace-separated token. Returns 0 when no trailing integer is present."""
    if not command_tag:
        return 0
    token = command_tag.rsplit(" ", 1)[-1]
    try:
        return int(token)
    except ValueError:
        return 0


def _append_channel_scope_pg(
    clauses: list[str],
    params: list[Any],
    column: str,
    allowed_channels: Sequence[str] | None,
) -> None:
    """Restrict ``column`` to a per-channel RBAC scope using a Postgres ``= ANY($n::text[])`` array
    bind (the dialect-correct parallel of ``store._append_channel_scope``'s ``IN (?, …)``). ``None`` =
    no restriction; an empty set = match nothing. ``column`` is a code-controlled literal."""
    if allowed_channels is None:
        return
    if allowed_channels:
        params.append(list(allowed_channels))
        clauses.append(f"{column} = ANY(${len(params)}::text[])")
    else:
        clauses.append("1=0")  # scoped to no channels
