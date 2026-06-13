"""**EXPERIMENTAL** SQL Server implementation of the :class:`~messagefoundry.store.base.Store` protocol.

Mirrors the SQLite :class:`~messagefoundry.store.store.MessageStore` semantics (transactional
inbox/outbox, at-least-once delivery, retries, replay, dead-lettering) in T-SQL over ``aioodbc``.
Concurrency is handled by SQL Server row-locking — ``claim_ready`` claims due rows with
``WITH (READPAST, UPDLOCK, ROWLOCK)`` so independent delivery workers don't block or double-claim,
lifting SQLite's single-writer ceiling.

``aioodbc`` is an **optional extra** (``pip install 'messagefoundry[sqlserver]'``) and also needs the
Microsoft ODBC Driver 18 at the OS level. It's imported lazily in :meth:`SqlServerStore.open` so
SQLite-only installs never touch it. **Status: experimental** — verified against a real SQL Server
only via the CI service-container job; treat as preview until that's green for your version.
"""

from __future__ import annotations

import logging
import time
from collections.abc import AsyncIterator, Iterable, Sequence
from contextlib import asynccontextmanager
from typing import Any
from uuid import uuid4

from messagefoundry.config.models import RetryPolicy
from messagefoundry.config.settings import (
    INSECURE_TLS_ESCAPE_ENV,
    SqlAuth,
    StoreSettings,
    insecure_tls_allowed,
)
from messagefoundry.store.crypto import PREFIX as _ENC_PREFIX
from messagefoundry.store.crypto import Cipher, CipherError, IdentityCipher
from messagefoundry.store.store import (
    ConnectionMetrics,
    DbStatus,
    DestinationMetrics,
    InboundMetrics,
    MessageStatus,
    OutboxItem,
    OutboxStatus,
    SessionRecord,
    Stage,
    UserRecord,
    _append_channel_scope,
    audit_row_hash,
)

log = logging.getLogger(__name__)

# Schema (T-SQL). Idempotent: guarded by OBJECT_ID / IndexProperty so re-open is a no-op. Epoch
# timestamps are FLOAT; ids are NVARCHAR(64) (uuid4 hex); bodies NVARCHAR(MAX).
_SCHEMA: list[str] = [
    """IF OBJECT_ID('messages','U') IS NULL CREATE TABLE messages (
        id NVARCHAR(64) NOT NULL PRIMARY KEY, channel_id NVARCHAR(256) NOT NULL,
        received_at FLOAT NOT NULL, source_type NVARCHAR(64) NULL, control_id NVARCHAR(256) NULL,
        message_type NVARCHAR(64) NULL, raw NVARCHAR(MAX) NOT NULL, status NVARCHAR(32) NOT NULL,
        error NVARCHAR(MAX) NULL, summary NVARCHAR(MAX) NULL, metadata NVARCHAR(MAX) NULL)""",
    """IF INDEXPROPERTY(OBJECT_ID('messages'),'ix_messages_channel','IndexID') IS NULL
        CREATE INDEX ix_messages_channel ON messages(channel_id, received_at)""",
    """IF INDEXPROPERTY(OBJECT_ID('messages'),'ix_messages_control','IndexID') IS NULL
        CREATE INDEX ix_messages_control ON messages(channel_id, control_id)""",
    """IF OBJECT_ID('outbox','U') IS NULL CREATE TABLE outbox (
        id NVARCHAR(64) NOT NULL PRIMARY KEY, message_id NVARCHAR(64) NOT NULL,
        channel_id NVARCHAR(256) NOT NULL, destination_name NVARCHAR(256) NOT NULL,
        payload NVARCHAR(MAX) NOT NULL, status NVARCHAR(32) NOT NULL,
        attempts INT NOT NULL DEFAULT 0, next_attempt_at FLOAT NOT NULL, last_error NVARCHAR(MAX) NULL,
        created_at FLOAT NOT NULL, updated_at FLOAT NOT NULL)""",
    """IF INDEXPROPERTY(OBJECT_ID('outbox'),'ix_outbox_ready','IndexID') IS NULL
        CREATE INDEX ix_outbox_ready ON outbox(status, next_attempt_at)""",
    """IF INDEXPROPERTY(OBJECT_ID('outbox'),'ix_outbox_message','IndexID') IS NULL
        CREATE INDEX ix_outbox_message ON outbox(message_id)""",
    """IF OBJECT_ID('message_events','U') IS NULL CREATE TABLE message_events (
        id INT IDENTITY(1,1) PRIMARY KEY, message_id NVARCHAR(64) NOT NULL, ts FLOAT NOT NULL,
        event NVARCHAR(64) NOT NULL, destination NVARCHAR(256) NULL, detail NVARCHAR(MAX) NULL)""",
    """IF INDEXPROPERTY(OBJECT_ID('message_events'),'ix_events_message','IndexID') IS NULL
        CREATE INDEX ix_events_message ON message_events(message_id, ts)""",
    """IF OBJECT_ID('audit_log','U') IS NULL CREATE TABLE audit_log (
        id INT IDENTITY(1,1) PRIMARY KEY, ts FLOAT NOT NULL, actor NVARCHAR(256) NULL,
        action NVARCHAR(128) NOT NULL, channel_id NVARCHAR(256) NULL, detail NVARCHAR(MAX) NULL,
        row_hash NVARCHAR(64) NULL)""",
    """IF COL_LENGTH('audit_log','row_hash') IS NULL
        ALTER TABLE audit_log ADD row_hash NVARCHAR(64) NULL""",
    """IF INDEXPROPERTY(OBJECT_ID('audit_log'),'ix_audit_ts','IndexID') IS NULL
        CREATE INDEX ix_audit_ts ON audit_log(ts)""",
    """IF OBJECT_ID('users','U') IS NULL CREATE TABLE users (
        id NVARCHAR(64) NOT NULL PRIMARY KEY, username NVARCHAR(256) NOT NULL UNIQUE,
        auth_provider NVARCHAR(16) NOT NULL, display_name NVARCHAR(256) NULL,
        email NVARCHAR(256) NULL, disabled BIT NOT NULL DEFAULT 0, created_at FLOAT NOT NULL,
        updated_at FLOAT NOT NULL, last_login_at FLOAT NULL, password_hash NVARCHAR(512) NULL,
        password_changed_at FLOAT NULL, must_change_password BIT NOT NULL DEFAULT 0,
        failed_attempts INT NOT NULL DEFAULT 0, locked_until FLOAT NULL,
        channel_scope NVARCHAR(MAX) NULL)""",
    """IF COL_LENGTH('users','channel_scope') IS NULL
        ALTER TABLE users ADD channel_scope NVARCHAR(MAX) NULL""",
    """IF OBJECT_ID('roles','U') IS NULL CREATE TABLE roles (
        id NVARCHAR(64) NOT NULL PRIMARY KEY, display_name NVARCHAR(128) NOT NULL,
        description NVARCHAR(512) NULL, builtin BIT NOT NULL DEFAULT 1)""",
    """IF OBJECT_ID('user_roles','U') IS NULL CREATE TABLE user_roles (
        user_id NVARCHAR(64) NOT NULL, role_id NVARCHAR(64) NOT NULL, assigned_at FLOAT NOT NULL,
        assigned_by NVARCHAR(256) NULL, CONSTRAINT pk_user_roles PRIMARY KEY (user_id, role_id))""",
    """IF OBJECT_ID('ad_group_role_map','U') IS NULL CREATE TABLE ad_group_role_map (
        ad_group NVARCHAR(256) NOT NULL, role_id NVARCHAR(64) NOT NULL,
        CONSTRAINT pk_ad_group_role_map PRIMARY KEY (ad_group, role_id))""",
    """IF OBJECT_ID('ad_group_scope_map','U') IS NULL CREATE TABLE ad_group_scope_map (
        ad_group NVARCHAR(256) NOT NULL, channel NVARCHAR(256) NOT NULL,
        CONSTRAINT pk_ad_group_scope_map PRIMARY KEY (ad_group, channel))""",
    """IF OBJECT_ID('sessions','U') IS NULL CREATE TABLE sessions (
        token_hash NVARCHAR(64) NOT NULL PRIMARY KEY, user_id NVARCHAR(64) NOT NULL,
        created_at FLOAT NOT NULL, expires_at FLOAT NOT NULL, last_used_at FLOAT NOT NULL,
        revoked_at FLOAT NULL, client NVARCHAR(256) NULL)""",
    """IF INDEXPROPERTY(OBJECT_ID('sessions'),'ix_sessions_user','IndexID') IS NULL
        CREATE INDEX ix_sessions_user ON sessions(user_id)""",
    """IF INDEXPROPERTY(OBJECT_ID('sessions'),'ix_sessions_expires','IndexID') IS NULL
        CREATE INDEX ix_sessions_expires ON sessions(expires_at)""",
]


def _odbc_brace(value: str) -> str:
    """ODBC-quote a value in braces, doubling any internal ``}`` — neutralizes ``; { } =`` inside it
    so an attacker-influenced value (e.g. a password) can't inject extra connection keywords."""
    return "{" + value.replace("}", "}}") + "}"


def connection_string(settings: StoreSettings) -> str:
    """Build an ODBC connection string for the Microsoft ODBC Driver 18 from store settings.

    Free-text values are brace-quoted to prevent connection-string injection (STORE-5), and the
    ``Encrypt``/``TrustServerCertificate`` security flags are emitted **last** so — ODBC being
    last-wins on duplicate keywords — nothing earlier can downgrade TLS. Identity fields are also
    validated up front (see ``StoreSettings._no_odbc_injection``)."""
    # A weakened TLS posture (TrustServerCertificate=yes, or Encrypt=no) is MITM-able, so it REFUSES
    # unless the explicit MEFOR_ALLOW_INSECURE_TLS dev escape is set (ASVS 12.3.2) — it can't be
    # silently turned on in production.
    if (settings.trust_server_certificate or not settings.encrypt) and not insecure_tls_allowed():
        raise ValueError(
            "SQL Server TLS is weakened (trust_server_certificate=true or encrypt=false), which is "
            f"MITM-able. Use a trusted server certificate, or set {INSECURE_TLS_ESCAPE_ENV}=1 to "
            "explicitly allow it for a trusted-network dev/test bind."
        )
    parts = [
        "DRIVER={ODBC Driver 18 for SQL Server}",
        f"SERVER={settings.server},{settings.port}",  # server validated; port is an int
        f"DATABASE={_odbc_brace(settings.database or '')}",
        f"Connection Timeout={settings.connect_timeout}",
        f"APP={_odbc_brace(settings.application_name)}",
    ]
    if settings.auth is SqlAuth.SQL:
        parts.append(f"UID={_odbc_brace(settings.username or '')}")
        parts.append(f"PWD={_odbc_brace(settings.password or '')}")
    elif settings.auth is SqlAuth.INTEGRATED:
        parts.append("Trusted_Connection=yes")
    elif settings.auth is SqlAuth.ENTRA:
        parts.append("Authentication=ActiveDirectoryDefault")
    parts.append(f"Encrypt={'yes' if settings.encrypt else 'no'}")
    parts.append(f"TrustServerCertificate={'yes' if settings.trust_server_certificate else 'no'}")
    return ";".join(parts) + ";"


class SqlServerStore:
    """SQL Server-backed durable queue (the :class:`Store` protocol). Open with :meth:`open`."""

    # The staged ingress pipeline (enqueue_ingress/handoff) is NOT implemented on SQL Server yet
    # (multi-writer per-stage queues are gated on BACKLOG #1). The engine refuses to start the staged
    # runner on this backend rather than trapping the first message in a NotImplementedError.
    supports_ingest_stage = False

    def __init__(self, pool: Any, settings: StoreSettings, *, cipher: Cipher | None = None) -> None:
        self._pool = pool
        self._settings = settings
        self._cipher: Cipher = cipher or IdentityCipher()
        self.path = f"{settings.server}/{settings.database}"  # descriptor for db_status

    @classmethod
    async def open(
        cls, settings: StoreSettings, *, cipher: Cipher | None = None
    ) -> "SqlServerStore":
        try:
            import aioodbc
        except ImportError as exc:  # pragma: no cover - exercised only without the extra
            raise RuntimeError(
                "SQL Server backend requires the 'sqlserver' extra: "
                "pip install 'messagefoundry[sqlserver]' (plus the Microsoft ODBC Driver 18)"
            ) from exc
        pool = await aioodbc.create_pool(
            dsn=connection_string(settings),
            minsize=1,
            maxsize=max(1, settings.pool_size),
            autocommit=False,
        )
        store = cls(pool, settings, cipher=cipher)
        await store._ensure_schema()
        await store._encrypt_existing_rows()  # one-time PHI-at-rest migration when a key is set
        await store._backfill_audit_chain()  # chain any pre-existing (unhashed) audit rows
        return store

    async def _backfill_audit_chain(self) -> None:
        """Fill ``row_hash`` for audit rows written before hash-chaining (idempotent; fills only
        NULLs, chained from the prior row)."""
        rows = await self._fetchall(
            "SELECT id, ts, actor, action, channel_id, detail, row_hash FROM audit_log ORDER BY id"
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
        if updates:
            async with self._acquire() as conn:
                cur = await conn.cursor()
                try:
                    for row_hash, rid in updates:
                        await cur.execute(
                            "UPDATE audit_log SET row_hash=? WHERE id=?", (row_hash, rid)
                        )
                    await conn.commit()
                except Exception:
                    await conn.rollback()
                    raise

    async def _encrypt_existing_rows(self) -> None:
        """Re-encrypt legacy plaintext bodies in place when encryption is enabled (STORE-1).

        Idempotent + batched: skips rows already carrying the ciphertext prefix."""
        if not self._cipher.encrypts:
            return
        like = f"{_ENC_PREFIX}%"
        total = 0
        for table, column in (("messages", "raw"), ("outbox", "payload")):
            while True:
                rows = await self._fetchall(
                    f"SELECT TOP (500) id, {column} FROM {table} WHERE {column} NOT LIKE ?", (like,)
                )
                if not rows:
                    break
                async with self._acquire() as conn:
                    cur = await conn.cursor()
                    try:
                        for r in rows:
                            await cur.execute(
                                f"UPDATE {table} SET {column}=? WHERE id=?",
                                (self._cipher.encrypt(r[column]), r["id"]),
                            )
                        await conn.commit()
                    except Exception:
                        await conn.rollback()
                        raise
                total += len(rows)
        if total:
            log.info("encrypted %d existing message/outbox row(s) at rest", total)

    async def _ensure_schema(self) -> None:
        async with self._acquire() as conn:
            cur = await conn.cursor()
            for statement in _SCHEMA:
                await cur.execute(statement)
            await conn.commit()

    async def close(self) -> None:
        self._pool.close()
        await self._pool.wait_closed()

    # --- helpers -------------------------------------------------------------

    @asynccontextmanager
    async def _acquire(self) -> AsyncIterator[Any]:
        """Acquire a pooled connection with the configured command (statement) timeout applied.

        ``Connection Timeout`` in the DSN is only the *login* timeout; the per-statement timeout is
        a connection attribute (STORE-3). Guarded so a driver that doesn't expose it degrades to the
        login timeout rather than failing."""
        async with self._pool.acquire() as conn:
            try:
                conn.timeout = self._settings.command_timeout  # seconds; 0 = no limit
            except Exception:  # pragma: no cover - driver without per-connection timeout support
                pass
            yield conn

    async def _fetchall(self, sql: str, params: tuple[Any, ...] = ()) -> list[dict[str, Any]]:
        async with self._acquire() as conn:
            cur = await conn.cursor()
            await cur.execute(sql, params) if params else await cur.execute(sql)
            columns = [c[0] for c in cur.description]
            rows = await cur.fetchall()
            await conn.commit()
        return [dict(zip(columns, row)) for row in rows]

    async def _fetchone(self, sql: str, params: tuple[Any, ...] = ()) -> dict[str, Any] | None:
        rows = await self._fetchall(sql, params)
        return rows[0] if rows else None

    async def _execute(self, sql: str, params: tuple[Any, ...] = ()) -> None:
        """Run a single write statement (or T-SQL batch) in its own committed transaction."""
        async with self._acquire() as conn:
            cur = await conn.cursor()
            try:
                await cur.execute(sql, params)
                await conn.commit()
            except Exception:
                await conn.rollback()
                raise

    @staticmethod
    async def _event(
        cur: Any,
        message_id: str,
        event: str,
        destination: str | None,
        detail: str | None,
        now: float,
    ) -> None:
        await cur.execute(
            "INSERT INTO message_events (message_id, ts, event, destination, detail)"
            " VALUES (?,?,?,?,?)",
            (message_id, now, event, destination, detail),
        )

    async def _maybe_finalize(self, cur: Any, message_id: str, now: float) -> None:
        await cur.execute(
            "SELECT status, COUNT(*) AS n FROM outbox WHERE message_id=? GROUP BY status",
            (message_id,),
        )
        counts = {row[0]: row[1] for row in await cur.fetchall()}
        non_terminal = counts.get(OutboxStatus.PENDING.value, 0) + counts.get(
            OutboxStatus.INFLIGHT.value, 0
        )
        if non_terminal:
            return
        status = (
            MessageStatus.ERROR.value
            if counts.get(OutboxStatus.DEAD.value)
            else MessageStatus.PROCESSED.value
        )
        await cur.execute("UPDATE messages SET status=? WHERE id=?", (status, message_id))

    @staticmethod
    def _message_filter(
        channel_id: str | None,
        status: str | None,
        message_type: str | None,
        control_id: str | None,
        allowed_channels: Sequence[str] | None = None,
    ) -> tuple[str, tuple[Any, ...]]:
        clauses: list[str] = []
        params: list[Any] = []
        for column, value in (
            ("channel_id", channel_id),
            ("status", status),
            ("message_type", message_type),
            ("control_id", control_id),
        ):
            if value is not None:
                clauses.append(f"{column}=?")
                params.append(value)
        _append_channel_scope(clauses, params, "channel_id", allowed_channels)
        where = f" WHERE {' AND '.join(clauses)}" if clauses else ""
        return where, tuple(params)

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
        now = time.time() if now is None else now
        mid = uuid4().hex
        status = MessageStatus.RECEIVED.value if deliveries else MessageStatus.UNROUTED.value
        async with self._acquire() as conn:
            cur = await conn.cursor()
            try:
                await cur.execute(
                    "INSERT INTO messages (id, channel_id, received_at, source_type, control_id,"
                    " message_type, raw, status, error, summary, metadata)"
                    " VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                    (
                        mid,
                        channel_id,
                        now,
                        source_type,
                        control_id,
                        message_type,
                        self._cipher.encrypt(raw),
                        status,
                        None,
                        summary,
                        metadata,
                    ),
                )
                for dest_name, payload in deliveries:
                    await cur.execute(
                        "INSERT INTO outbox (id, message_id, channel_id, destination_name, payload,"
                        " status, attempts, next_attempt_at, created_at, updated_at)"
                        " VALUES (?,?,?,?,?,?,0,?,?,?)",
                        (
                            uuid4().hex,
                            mid,
                            channel_id,
                            dest_name,
                            self._cipher.encrypt(payload),
                            OutboxStatus.PENDING.value,
                            now,
                            now,
                            now,
                        ),
                    )
                await self._event(
                    cur, mid, "received", None, f"{len(deliveries)} destination(s)", now
                )
                await conn.commit()
            except Exception:
                await conn.rollback()
                raise
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
        """Not implemented on the SQL Server backend: the staged-pipeline ingress stage (multi-writer
        per-stage durable queues on SQL Server) is gated on BACKLOG #1. Use the SQLite backend for the
        staged pipeline (ADR 0001 Step A)."""
        raise NotImplementedError(
            "staged ingress (enqueue_ingress) is not supported on the SQL Server backend yet "
            "(BACKLOG #1); use the SQLite backend"
        )

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
        """Not implemented on the SQL Server backend — see :meth:`enqueue_ingress` (BACKLOG #1)."""
        raise NotImplementedError(
            "staged handoff is not supported on the SQL Server backend yet (BACKLOG #1); "
            "use the SQLite backend"
        )

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
        """Not implemented on the SQL Server backend — see :meth:`enqueue_ingress` (BACKLOG #1).
        Unreachable at runtime: the engine refuses to start the staged runner on this backend
        (``supports_ingest_stage = False``); present only for ``Store`` protocol completeness."""
        raise NotImplementedError(
            "staged route_handoff is not supported on the SQL Server backend yet (BACKLOG #1); "
            "use the SQLite backend"
        )

    async def transform_handoff(
        self,
        *,
        routed_id: str,
        message_id: str,
        channel_id: str,
        deliveries: Sequence[tuple[str, str]],
        now: float | None = None,
    ) -> bool:
        """Not implemented on the SQL Server backend — see :meth:`route_handoff` (BACKLOG #1)."""
        raise NotImplementedError(
            "staged transform_handoff is not supported on the SQL Server backend yet (BACKLOG #1); "
            "use the SQLite backend"
        )

    async def dead_letter_missing_handlers(
        self, valid_names: set[str], now: float | None = None
    ) -> int:
        """Not implemented on the SQL Server backend — the routed stage is part of the staged pipeline
        (BACKLOG #1). Unreachable: the engine calls it only after the ``supports_ingest_stage`` gate,
        which this backend fails. Present for ``Store`` protocol completeness."""
        raise NotImplementedError(
            "dead_letter_missing_handlers is not supported on the SQL Server backend yet "
            "(BACKLOG #1); use the SQLite backend"
        )

    # --- retention / purge + maintenance (PHI.md §8) -------------------------
    # Retention is SQLite-only today. The engine never reaches these on SQL Server (it refuses to
    # start the staged runner here — ``supports_ingest_stage = False`` — so the RetentionRunner is
    # never started either); they exist for ``Store`` protocol completeness. SQL Server at-rest
    # retention is a DBA concern (TDE + a SQL Agent purge/shrink job), not the engine's.

    async def reencrypt_to_active(self, *, batch: int = 500) -> int:
        """Not supported on the SQL Server backend — the key-rotation re-encrypt loop is SQLite-only
        today. At-rest protection on SQL Server is TDE; rotate keys at the database. Present for
        ``Store`` protocol completeness."""
        raise NotImplementedError(
            "rotate-key (reencrypt_to_active) is not supported on the SQL Server backend; "
            "rotate at-rest keys via SQL Server TDE"
        )

    async def purge_message_bodies(self, *, older_than: float, now: float | None = None) -> int:
        """Not supported on the SQL Server backend — retention is SQLite-only (see class note)."""
        raise NotImplementedError(
            "purge_message_bodies is not supported on the SQL Server backend (retention is "
            "SQLite-only; use a TDE + SQL Agent purge job on SQL Server)"
        )

    async def purge_dead_letters(self, *, older_than: float, now: float | None = None) -> int:
        """Not supported on the SQL Server backend — retention is SQLite-only (see class note)."""
        raise NotImplementedError(
            "purge_dead_letters is not supported on the SQL Server backend (retention is "
            "SQLite-only; use a TDE + SQL Agent purge job on SQL Server)"
        )

    async def wal_checkpoint(self) -> None:
        """No-op on SQL Server — there is no SQLite WAL to checkpoint (the engine never calls this on
        this backend; present for ``Store`` protocol completeness)."""

    async def vacuum(self) -> None:
        """No-op on SQL Server — file compaction is a DBA operation here, not an engine concern (the
        engine never calls this on this backend; present for ``Store`` protocol completeness)."""

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
        now = time.time() if now is None else now
        mid = uuid4().hex
        event = "error" if status is MessageStatus.ERROR else "filtered"
        async with self._acquire() as conn:
            cur = await conn.cursor()
            try:
                await cur.execute(
                    "INSERT INTO messages (id, channel_id, received_at, source_type, control_id,"
                    " message_type, raw, status, error, summary, metadata)"
                    " VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                    (
                        mid,
                        channel_id,
                        now,
                        source_type,
                        control_id,
                        message_type,
                        self._cipher.encrypt(raw),
                        status.value,
                        error,
                        summary,
                        metadata,
                    ),
                )
                await self._event(cur, mid, event, None, error, now)
                await conn.commit()
            except Exception:
                await conn.rollback()
                raise
        return mid

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
        # The SQL Server backend predates the staged pipeline: its `outbox` table holds only
        # outbound rows, so `stage` is accepted for protocol compatibility but not filtered on
        # (ingress staging on SQL Server is gated on BACKLOG #1). All claimed rows are outbound.
        now = time.time() if now is None else now
        where = ["status=?", "next_attempt_at<=?"]
        filters: list[Any] = [OutboxStatus.PENDING.value, now]
        if channel_id is not None:
            where.append("channel_id=?")
            filters.append(channel_id)
        if destination_name is not None:
            where.append("destination_name=?")
            filters.append(destination_name)
        # Claim TOP-N due rows in order, locking them so concurrent workers skip (READPAST) rather
        # than block — and OUTPUT the claimed rows. This is the SQL Server queue-claim pattern.
        sql = (
            "WITH due AS (SELECT TOP (?) * FROM outbox WITH (READPAST, UPDLOCK, ROWLOCK)"
            f" WHERE {' AND '.join(where)} ORDER BY next_attempt_at)"
            " UPDATE due SET status=?, attempts=attempts+1, updated_at=?"
            " OUTPUT inserted.id, inserted.message_id, inserted.channel_id,"
            " inserted.destination_name, inserted.payload, inserted.attempts"
        )
        args = (limit, *filters, OutboxStatus.INFLIGHT.value, now)
        async with self._acquire() as conn:
            cur = await conn.cursor()
            try:
                await cur.execute(sql, args)
                columns = [c[0] for c in cur.description]
                rows = await cur.fetchall()
                await conn.commit()
            except Exception:
                await conn.rollback()
                raise
        items = []
        for row in rows:
            d = dict(zip(columns, row))
            # Contain an undecryptable payload (corrupt blob / a key not in the keyring): dead-letter
            # that row and drop it from the batch rather than raising and stranding the whole claim —
            # the SQLite backend's poison-row guard, mirrored here (WP-5).
            try:
                payload = self._cipher.decrypt(d["payload"])
            except CipherError as exc:
                log.warning("dead-lettering undecryptable outbox row %s: %s", d["id"], exc)
                await self.dead_letter_now(d["id"], f"undecryptable payload: {exc}")
                continue
            items.append(
                OutboxItem(
                    id=d["id"],
                    message_id=d["message_id"],
                    channel_id=d["channel_id"],
                    destination_name=d["destination_name"],
                    payload=payload,
                    attempts=d["attempts"],
                    stage=Stage.OUTBOUND.value,
                )
            )
        return items

    async def claim_next_fifo(
        self, name: str, now: float | None = None, *, stage: str = Stage.OUTBOUND.value
    ) -> OutboxItem | None:
        # SQL Server holds only outbound rows (see claim_ready); `name` is the destination lane and
        # `stage` is accepted for protocol compatibility. Ingress staging is gated on BACKLOG #1.
        destination_name = name
        now = time.time() if now is None else now
        # FIFO: lock + claim the single oldest pending row for this destination, but only if it is
        # due — the WHERE on the UPDATE means a backing-off head updates nothing (empty OUTPUT), so
        # the head blocks the lane (head-of-line) instead of being skipped. Order created_at, id.
        sql = (
            "WITH head AS (SELECT TOP (1) * FROM outbox WITH (UPDLOCK, ROWLOCK)"
            " WHERE destination_name=? AND status=? ORDER BY created_at, id)"
            " UPDATE head SET status=?, attempts=attempts+1, updated_at=?"
            " OUTPUT inserted.id, inserted.message_id, inserted.channel_id,"
            " inserted.destination_name, inserted.payload, inserted.attempts"
            " WHERE next_attempt_at<=?"
        )
        args = (destination_name, OutboxStatus.PENDING.value, OutboxStatus.INFLIGHT.value, now, now)
        async with self._acquire() as conn:
            cur = await conn.cursor()
            try:
                await cur.execute(sql, args)
                columns = [c[0] for c in cur.description] if cur.description else []
                row = await cur.fetchone()
                await conn.commit()
            except Exception:
                await conn.rollback()
                raise
        if row is None:
            return None
        d = dict(zip(columns, row))
        # Contain an undecryptable head (corrupt blob / missing key): dead-letter it and return None so
        # the lane advances on the next poll, rather than raising into the worker (WP-5; mirrors SQLite).
        try:
            payload = self._cipher.decrypt(d["payload"])
        except CipherError as exc:
            log.warning("dead-lettering undecryptable queue row %s: %s", d["id"], exc)
            await self.dead_letter_now(d["id"], f"undecryptable payload: {exc}")
            return None
        return OutboxItem(
            id=d["id"],
            message_id=d["message_id"],
            channel_id=d["channel_id"],
            destination_name=d["destination_name"],
            payload=payload,
            attempts=d["attempts"],
            stage=Stage.OUTBOUND.value,
        )

    async def mark_done(self, outbox_id: str, now: float | None = None) -> None:
        now = time.time() if now is None else now
        async with self._acquire() as conn:
            cur = await conn.cursor()
            try:
                await cur.execute(
                    "SELECT message_id, destination_name, attempts FROM outbox WHERE id=?",
                    (outbox_id,),
                )
                row = await cur.fetchone()
                if row is None:
                    await conn.commit()
                    return
                message_id, destination_name, attempts = row[0], row[1], row[2]
                await cur.execute(
                    "UPDATE outbox SET status=?, last_error=NULL, updated_at=? WHERE id=?",
                    (OutboxStatus.DONE.value, now, outbox_id),
                )
                await self._event(
                    cur, message_id, "delivered", destination_name, f"attempt {attempts}", now
                )
                await self._maybe_finalize(cur, message_id, now)
                await conn.commit()
            except Exception:
                await conn.rollback()
                raise

    async def mark_failed(
        self, outbox_id: str, error: str, retry: RetryPolicy, now: float | None = None
    ) -> None:
        now = time.time() if now is None else now
        async with self._acquire() as conn:
            cur = await conn.cursor()
            try:
                await cur.execute(
                    "SELECT message_id, destination_name, attempts FROM outbox WHERE id=?",
                    (outbox_id,),
                )
                row = await cur.fetchone()
                if row is None:
                    await conn.commit()
                    return
                message_id, destination_name, attempts = row[0], row[1], row[2]
                # max_attempts None = retry forever (never dead-letter here); a finite cap dead-letters
                # once exhausted (mirrors the SQLite backend's mark_failed).
                if retry.max_attempts is not None and attempts >= retry.max_attempts:
                    status, next_at, event = OutboxStatus.DEAD.value, now, "dead"
                else:
                    backoff = min(
                        retry.max_backoff_seconds,
                        retry.backoff_seconds * (retry.backoff_multiplier ** (attempts - 1)),
                    )
                    status, next_at, event = OutboxStatus.PENDING.value, now + backoff, "failed"
                await cur.execute(
                    "UPDATE outbox SET status=?, next_attempt_at=?, last_error=?, updated_at=? WHERE id=?",
                    (status, next_at, error, now, outbox_id),
                )
                await self._event(
                    cur, message_id, event, destination_name, f"attempt {attempts}: {error}", now
                )
                if status == OutboxStatus.DEAD.value:
                    await self._maybe_finalize(cur, message_id, now)
                await conn.commit()
            except Exception:
                await conn.rollback()
                raise

    # --- recovery / replay ---------------------------------------------------

    async def reset_stale_inflight(
        self, now: float | None = None, *, stage: str | None = None
    ) -> int:
        # SQL Server holds only outbound rows, so the all-stages reset is equivalent here; `stage` is
        # accepted for protocol compatibility (ingress staging is gated on BACKLOG #1).
        now = time.time() if now is None else now
        async with self._acquire() as conn:
            cur = await conn.cursor()
            try:
                await cur.execute(
                    "UPDATE outbox SET status=?, next_attempt_at=?, updated_at=? WHERE status=?",
                    (OutboxStatus.PENDING.value, now, now, OutboxStatus.INFLIGHT.value),
                )
                count = cur.rowcount
                await conn.commit()
            except Exception:
                await conn.rollback()
                raise
        return int(count)

    async def dead_letter_now(self, outbox_id: str, error: str, now: float | None = None) -> None:
        """Force one row terminal (``DEAD``) immediately — fail-fast, no retry consumed. See the
        :meth:`~messagefoundry.store.base.QueueStore.dead_letter_now` contract."""
        now = time.time() if now is None else now
        async with self._acquire() as conn:
            cur = await conn.cursor()
            try:
                await cur.execute(
                    "SELECT message_id, destination_name FROM outbox WHERE id=?", (outbox_id,)
                )
                row = await cur.fetchone()
                if row is None:
                    await conn.commit()
                    return
                message_id, destination_name = row[0], row[1]
                await cur.execute(
                    "UPDATE outbox SET status=?, next_attempt_at=?, last_error=?, updated_at=?"
                    " WHERE id=?",
                    (OutboxStatus.DEAD.value, now, error, now, outbox_id),
                )
                await self._event(cur, message_id, "dead", destination_name, error, now)
                await self._maybe_finalize(cur, message_id, now)
                await conn.commit()
            except Exception:
                await conn.rollback()
                raise

    async def pending_depth(
        self, name: str, *, stage: str = Stage.OUTBOUND.value
    ) -> tuple[int, float | None]:
        """``(pending_count, oldest_created_at)`` for one outbound lane (see the protocol). SQL Server
        holds only outbound rows; ``name`` is the destination lane and ``stage`` is accepted for
        protocol compatibility (ingress staging is gated on BACKLOG #1)."""
        destination_name = name
        async with self._acquire() as conn:
            cur = await conn.cursor()
            await cur.execute(
                "SELECT COUNT(*), MIN(created_at) FROM outbox WHERE destination_name=? AND status=?",
                (destination_name, OutboxStatus.PENDING.value),
            )
            row = await cur.fetchone()
        count = int(row[0]) if row is not None and row[0] is not None else 0
        oldest = row[1] if row is not None else None
        return count, (float(oldest) if oldest is not None else None)

    async def dead_letter_missing_destinations(
        self, valid_names: set[str], now: float | None = None
    ) -> int:
        """Dead-letter non-terminal outbox rows whose destination_name is no longer in the registry
        (a removed/renamed outbound) — they have no delivery worker and would strand forever (H-5)."""
        now = time.time() if now is None else now
        async with self._acquire() as conn:
            cur = await conn.cursor()
            try:
                await cur.execute(
                    "SELECT id, message_id, destination_name FROM outbox WHERE status IN (?, ?)",
                    (OutboxStatus.PENDING.value, OutboxStatus.INFLIGHT.value),
                )
                rows = await cur.fetchall()  # positional: (id, message_id, destination_name)
                orphans = [r for r in rows if r[2] not in valid_names]
                if not orphans:
                    return 0
                error = "destination removed from outbound registry"
                for row in orphans:
                    await cur.execute(
                        "UPDATE outbox SET status=?, next_attempt_at=?, last_error=?, updated_at=?"
                        " WHERE id=?",
                        (OutboxStatus.DEAD.value, now, error, now, row[0]),
                    )
                    await self._event(cur, row[1], "dead", row[2], error, now)
                    await self._maybe_finalize(cur, row[1], now)
                await conn.commit()
            except Exception:
                await conn.rollback()
                raise
        log.warning(
            "dead-lettered %d orphaned outbox row(s) at startup for missing destination(s): %s",
            len(orphans),
            ", ".join(sorted({r[2] for r in orphans})),
        )
        return len(orphans)

    async def replay(self, message_id: str, now: float | None = None) -> int:
        now = time.time() if now is None else now
        async with self._acquire() as conn:
            cur = await conn.cursor()
            try:
                await cur.execute(
                    "UPDATE outbox SET status=?, attempts=0, next_attempt_at=?, last_error=NULL,"
                    " updated_at=? WHERE message_id=?",
                    (OutboxStatus.PENDING.value, now, now, message_id),
                )
                count = cur.rowcount
                if (
                    count
                ):  # no rows => errored/filtered/unrouted: don't falsify it or strand it (M-2)
                    await cur.execute(
                        "UPDATE messages SET status=?, error=NULL WHERE id=?",
                        (MessageStatus.RECEIVED.value, message_id),
                    )
                    await self._event(
                        cur, message_id, "replayed", None, f"{count} destination(s)", now
                    )
                await conn.commit()
            except Exception:
                await conn.rollback()
                raise
        return int(count)

    async def replay_dead(
        self,
        *,
        channel_id: str | None = None,
        destination_name: str | None = None,
        now: float | None = None,
    ) -> int:
        now = time.time() if now is None else now
        where = ["status=?"]
        params: list[Any] = [OutboxStatus.DEAD.value]
        if channel_id is not None:
            where.append("channel_id=?")
            params.append(channel_id)
        if destination_name is not None:
            where.append("destination_name=?")
            params.append(destination_name)
        clause = " AND ".join(where)
        async with self._acquire() as conn:
            cur = await conn.cursor()
            try:
                await cur.execute(
                    f"SELECT DISTINCT message_id FROM outbox WHERE {clause}", tuple(params)
                )
                message_ids = [r[0] for r in await cur.fetchall()]
                if not message_ids:
                    await conn.commit()
                    return 0
                await cur.execute(
                    f"UPDATE outbox SET status=?, attempts=0, next_attempt_at=?, last_error=NULL,"
                    f" updated_at=? WHERE {clause}",
                    (OutboxStatus.PENDING.value, now, now, *params),
                )
                count = cur.rowcount
                for message_id in message_ids:
                    await cur.execute(
                        "UPDATE messages SET status=?, error=NULL WHERE id=? AND status=?",
                        (MessageStatus.RECEIVED.value, message_id, MessageStatus.ERROR.value),
                    )
                    await self._event(cur, message_id, "replayed", None, "dead-letter replay", now)
                await conn.commit()
            except Exception:
                await conn.rollback()
                raise
        return int(count)

    async def cancel_queued(
        self,
        channel_id: str | None,
        destination_name: str,
        *,
        top_only: bool = False,
        now: float | None = None,
    ) -> int:
        now = time.time() if now is None else now
        where = ["destination_name=?", "status=?"]
        params: list[Any] = [destination_name, OutboxStatus.PENDING.value]
        if channel_id is not None:
            where.insert(0, "channel_id=?")
            params.insert(0, channel_id)
        top = "TOP (1) " if top_only else ""
        async with self._acquire() as conn:
            cur = await conn.cursor()
            try:
                await cur.execute(
                    f"SELECT {top}id, message_id FROM outbox WHERE {' AND '.join(where)}"
                    " ORDER BY next_attempt_at, created_at",
                    tuple(params),
                )
                rows = [(r[0], r[1]) for r in await cur.fetchall()]
                if not rows:
                    await conn.commit()
                    return 0
                ids = [r[0] for r in rows]
                placeholders = ",".join("?" * len(ids))
                await cur.execute(
                    f"UPDATE outbox SET status=?, updated_at=? WHERE id IN ({placeholders})",
                    (OutboxStatus.CANCELLED.value, now, *ids),
                )
                for _id, message_id in rows:
                    await self._event(
                        cur, message_id, "cancelled", destination_name, "manual purge", now
                    )
                for message_id in {r[1] for r in rows}:
                    await self._maybe_finalize(cur, message_id, now)
                await conn.commit()
            except Exception:
                await conn.rollback()
                raise
        return len(ids)

    # --- read helpers --------------------------------------------------------

    async def get_message(self, message_id: str) -> dict[str, Any] | None:
        record = await self._fetchone("SELECT * FROM messages WHERE id=?", (message_id,))
        if record is not None:
            record["raw"] = self._cipher.decrypt(record["raw"])  # decrypt the body for display
        return record

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
        where, params = self._message_filter(
            channel_id, status, message_type, control_id, allowed_channels
        )
        return await self._fetchall(
            "SELECT id, channel_id, received_at, source_type, control_id, message_type,"
            " status, error, summary, metadata,"
            " (SELECT TOP 1 event FROM message_events e WHERE e.message_id = messages.id"
            "  ORDER BY e.id DESC) AS last_event"
            f" FROM messages{where}"
            " ORDER BY received_at DESC, id DESC OFFSET ? ROWS FETCH NEXT ? ROWS ONLY",
            (*params, offset, limit),
        )

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
        row = await self._fetchone(f"SELECT COUNT(*) AS n FROM messages{where}", params)
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
        where, params = self._dead_filter(channel_id, destination_name, allowed_channels)
        return await self._fetchall(
            "SELECT o.id AS outbox_id, o.message_id, o.channel_id, o.destination_name,"
            " o.attempts, o.last_error, o.updated_at,"
            " m.control_id, m.message_type, m.received_at, m.summary"
            f" FROM outbox o JOIN messages m ON m.id = o.message_id{where}"
            " ORDER BY o.updated_at DESC, o.id DESC OFFSET ? ROWS FETCH NEXT ? ROWS ONLY",
            (*params, offset, limit),
        )

    async def count_dead(
        self,
        *,
        channel_id: str | None = None,
        destination_name: str | None = None,
        allowed_channels: Sequence[str] | None = None,
    ) -> int:
        where, params = self._dead_filter(channel_id, destination_name, allowed_channels)
        row = await self._fetchone(f"SELECT COUNT(*) AS n FROM outbox o{where}", params)
        return int(row["n"]) if row else 0

    @staticmethod
    def _dead_filter(
        channel_id: str | None,
        destination_name: str | None,
        allowed_channels: Sequence[str] | None = None,
    ) -> tuple[str, tuple[Any, ...]]:
        clauses = ["o.status=?"]
        params: list[Any] = [OutboxStatus.DEAD.value]
        if channel_id is not None:
            clauses.append("o.channel_id=?")
            params.append(channel_id)
        if destination_name is not None:
            clauses.append("o.destination_name=?")
            params.append(destination_name)
        _append_channel_scope(clauses, params, "o.channel_id", allowed_channels)
        return f" WHERE {' AND '.join(clauses)}", tuple(params)

    async def outbox_for(self, message_id: str) -> list[dict[str, Any]]:
        return await self._fetchall(
            "SELECT * FROM outbox WHERE message_id=? ORDER BY destination_name", (message_id,)
        )

    async def events_for(self, message_id: str) -> list[dict[str, Any]]:
        return await self._fetchall(
            "SELECT * FROM message_events WHERE message_id=? ORDER BY id", (message_id,)
        )

    async def record_view(
        self, message_id: str, *, actor: str | None = None, now: float | None = None
    ) -> None:
        now = time.time() if now is None else now
        async with self._acquire() as conn:
            cur = await conn.cursor()
            try:
                await self._event(cur, message_id, "viewed", None, actor or "", now)
                await conn.commit()
            except Exception:
                await conn.rollback()
                raise

    async def record_audit(
        self,
        action: str,
        *,
        actor: str | None = None,
        channel_id: str | None = None,
        detail: str | None = None,
        now: float | None = None,
    ) -> None:
        now = time.time() if now is None else now
        async with self._acquire() as conn:
            cur = await conn.cursor()
            try:
                await cur.execute("SELECT TOP (1) row_hash FROM audit_log ORDER BY id DESC")
                last = await cur.fetchone()
                prev = last[0] if last and last[0] else ""
                row_hash = audit_row_hash(
                    prev, ts=now, actor=actor, action=action, channel_id=channel_id, detail=detail
                )
                await cur.execute(
                    "INSERT INTO audit_log (ts, actor, action, channel_id, detail, row_hash)"
                    " VALUES (?,?,?,?,?,?)",
                    (now, actor, action, channel_id, detail, row_hash),
                )
                await conn.commit()
            except Exception:
                await conn.rollback()
                raise

    async def audit_anchor(self) -> tuple[int, str]:
        """The audit log's external anchor — ``(row_count, head_hash)`` — see the SQLite store (low-1)."""
        rows = await self._fetchall(
            "SELECT COUNT(*) AS n, "
            "(SELECT TOP (1) row_hash FROM audit_log ORDER BY id DESC) AS head FROM audit_log"
        )
        if not rows:
            return 0, ""
        return int(rows[0]["n"]), (rows[0]["head"] or "")

    async def verify_audit_chain(
        self, *, expected_anchor: tuple[int, str] | None = None
    ) -> tuple[bool, str | None]:
        """Recompute the audit hash-chain in order; returns (ok, message) — see the SQLite store.

        Re-walking can't catch tail-truncation (the surviving prefix still verifies); pass
        ``expected_anchor`` from :meth:`audit_anchor`, held out-of-band, to detect it (review low-1)."""
        rows = await self._fetchall(
            "SELECT id, ts, actor, action, channel_id, detail, row_hash FROM audit_log ORDER BY id"
        )
        prev = ""
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
        if expected_anchor is not None:
            exp_count, exp_head = expected_anchor
            if len(rows) < exp_count or prev != exp_head:
                return (
                    False,
                    f"audit log diverges from recorded anchor (have {len(rows)} row(s) head "
                    f"{prev[:12]!r}, expected {exp_count} head {exp_head[:12]!r}) — truncated or rewritten",
                )
        return True, f"verified {len(rows)} audit row(s)"

    # --- auth: users / roles / sessions --------------------------------------

    async def list_audit(self, *, limit: int = 50) -> list[dict[str, Any]]:
        return await self._fetchall("SELECT TOP (?) * FROM audit_log ORDER BY id DESC", (limit,))

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
            " VALUES (?,?,?,?,?,0,?,?,NULL,?,?,?,0,NULL)",
            (
                user_id,
                username,
                auth_provider,
                display_name,
                email,
                now,
                now,
                password_hash,
                now if password_hash is not None else None,
                1 if must_change_password else 0,
            ),
        )

    async def get_user(self, user_id: str) -> UserRecord | None:
        d = await self._fetchone("SELECT * FROM users WHERE id=?", (user_id,))
        return UserRecord.from_mapping(d) if d else None

    async def get_user_by_username(self, username: str) -> UserRecord | None:
        d = await self._fetchone("SELECT * FROM users WHERE username=?", (username,))
        return UserRecord.from_mapping(d) if d else None

    async def list_users(self) -> list[UserRecord]:
        rows = await self._fetchall("SELECT * FROM users ORDER BY username")
        return [UserRecord.from_mapping(d) for d in rows]

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
            "UPDATE users SET password_hash=?, password_changed_at=?, must_change_password=?,"
            " failed_attempts=0, locked_until=NULL, updated_at=? WHERE id=?",
            (password_hash, now, 1 if must_change_password else 0, now, user_id),
        )

    async def set_user_disabled(
        self, user_id: str, *, disabled: bool, now: float | None = None
    ) -> None:
        now = time.time() if now is None else now
        await self._execute(
            "UPDATE users SET disabled=?, updated_at=? WHERE id=?",
            (1 if disabled else 0, now, user_id),
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
            "UPDATE users SET display_name=?, email=?, updated_at=? WHERE id=?",
            (display_name, email, now, user_id),
        )

    async def delete_user(self, user_id: str) -> None:
        async with self._acquire() as conn:
            cur = await conn.cursor()
            try:
                await cur.execute("DELETE FROM user_roles WHERE user_id=?", (user_id,))
                await cur.execute("DELETE FROM sessions WHERE user_id=?", (user_id,))
                await cur.execute("DELETE FROM users WHERE id=?", (user_id,))
                await conn.commit()
            except Exception:
                await conn.rollback()
                raise

    async def record_login_success(self, user_id: str, *, now: float | None = None) -> None:
        now = time.time() if now is None else now
        await self._execute(
            "UPDATE users SET last_login_at=?, failed_attempts=0, locked_until=NULL,"
            " updated_at=? WHERE id=?",
            (now, now, user_id),
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
            "UPDATE users SET failed_attempts=?, locked_until=?, updated_at=? WHERE id=?",
            (failed_attempts, locked_until, now, user_id),
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
            "UPDATE roles SET display_name=?, description=?, builtin=? WHERE id=?;"
            " IF @@ROWCOUNT=0 INSERT INTO roles (id, display_name, description, builtin)"
            " VALUES (?,?,?,?)",
            (
                display_name,
                description,
                1 if builtin else 0,
                role_id,
                role_id,
                display_name,
                description,
                1 if builtin else 0,
            ),
        )

    async def list_roles(self) -> list[dict[str, Any]]:
        return await self._fetchall("SELECT * FROM roles ORDER BY id")

    async def get_user_role_ids(self, user_id: str) -> list[str]:
        rows = await self._fetchall(
            "SELECT role_id FROM user_roles WHERE user_id=? ORDER BY role_id", (user_id,)
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
        async with self._acquire() as conn:
            cur = await conn.cursor()
            try:
                await cur.execute("DELETE FROM user_roles WHERE user_id=?", (user_id,))
                for role_id in role_ids:
                    await cur.execute(
                        "INSERT INTO user_roles (user_id, role_id, assigned_at, assigned_by)"
                        " VALUES (?,?,?,?)",
                        (user_id, role_id, now, assigned_by),
                    )
                await conn.commit()
            except Exception:
                await conn.rollback()
                raise

    async def set_user_channel_scope(
        self, user_id: str, scope_json: str | None, *, now: float | None = None
    ) -> None:
        now = time.time() if now is None else now
        await self._execute(
            "UPDATE users SET channel_scope=?, updated_at=? WHERE id=?",
            (scope_json, now, user_id),
        )

    async def roles_for_ad_groups(self, groups: Iterable[str]) -> set[str]:
        normalized = sorted({g.strip().lower() for g in groups if g.strip()})
        if not normalized:
            return set()
        placeholders = ",".join("?" * len(normalized))  # count-bound, not user text
        rows = await self._fetchall(
            f"SELECT DISTINCT role_id FROM ad_group_role_map WHERE ad_group IN ({placeholders})",
            tuple(normalized),
        )
        return {str(r["role_id"]) for r in rows}

    async def list_ad_group_role_map(self) -> list[dict[str, Any]]:
        return await self._fetchall(
            "SELECT ad_group, role_id FROM ad_group_role_map ORDER BY ad_group, role_id"
        )

    async def set_ad_group_role_map(self, entries: Iterable[tuple[str, str]]) -> None:
        pairs = sorted({(g.strip().lower(), r) for g, r in entries if g.strip()})
        async with self._acquire() as conn:
            cur = await conn.cursor()
            try:
                await cur.execute("DELETE FROM ad_group_role_map")
                for ad_group, role_id in pairs:
                    await cur.execute(
                        "INSERT INTO ad_group_role_map (ad_group, role_id) VALUES (?,?)",
                        (ad_group, role_id),
                    )
                await conn.commit()
            except Exception:
                await conn.rollback()
                raise

    async def channels_for_ad_groups(self, groups: Iterable[str]) -> set[str]:
        normalized = sorted({g.strip().lower() for g in groups if g.strip()})
        if not normalized:
            return set()
        placeholders = ",".join("?" * len(normalized))  # count-bound, not user text
        rows = await self._fetchall(
            f"SELECT DISTINCT channel FROM ad_group_scope_map WHERE ad_group IN ({placeholders})",
            tuple(normalized),
        )
        return {str(r["channel"]) for r in rows}

    async def list_ad_group_scope_map(self) -> list[dict[str, Any]]:
        return await self._fetchall(
            "SELECT ad_group, channel FROM ad_group_scope_map ORDER BY ad_group, channel"
        )

    async def set_ad_group_scope_map(self, entries: Iterable[tuple[str, str]]) -> None:
        pairs = sorted(
            {(g.strip().lower(), c.strip()) for g, c in entries if g.strip() and c.strip()}
        )
        async with self._acquire() as conn:
            cur = await conn.cursor()
            try:
                await cur.execute("DELETE FROM ad_group_scope_map")
                for ad_group, channel in pairs:
                    await cur.execute(
                        "INSERT INTO ad_group_scope_map (ad_group, channel) VALUES (?,?)",
                        (ad_group, channel),
                    )
                await conn.commit()
            except Exception:
                await conn.rollback()
                raise

    async def create_session(
        self,
        *,
        token_hash: str,
        user_id: str,
        expires_at: float,
        client: str | None = None,
        now: float | None = None,
    ) -> None:
        now = time.time() if now is None else now
        await self._execute(
            "INSERT INTO sessions (token_hash, user_id, created_at, expires_at, last_used_at,"
            " revoked_at, client) VALUES (?,?,?,?,?,NULL,?)",
            (token_hash, user_id, now, expires_at, now, client),
        )

    async def get_session(self, token_hash: str) -> SessionRecord | None:
        d = await self._fetchone("SELECT * FROM sessions WHERE token_hash=?", (token_hash,))
        return SessionRecord.from_mapping(d) if d else None

    async def list_sessions(self, user_id: str, *, now: float | None = None) -> list[SessionRecord]:
        """A user's active (not revoked/expired) sessions, most-recently-used first (WP-10)."""
        now = time.time() if now is None else now
        rows = await self._fetchall(
            "SELECT * FROM sessions WHERE user_id=? AND revoked_at IS NULL AND expires_at > ?"
            " ORDER BY last_used_at DESC",
            (user_id, now),
        )
        return [SessionRecord.from_mapping(r) for r in rows]

    async def touch_session(self, token_hash: str, *, now: float | None = None) -> None:
        now = time.time() if now is None else now
        await self._execute(
            "UPDATE sessions SET last_used_at=? WHERE token_hash=?", (now, token_hash)
        )

    async def revoke_session(self, token_hash: str, *, now: float | None = None) -> None:
        now = time.time() if now is None else now
        await self._execute(
            "UPDATE sessions SET revoked_at=? WHERE token_hash=? AND revoked_at IS NULL",
            (now, token_hash),
        )

    async def revoke_user_sessions(
        self, user_id: str, *, except_token_hash: str | None = None, now: float | None = None
    ) -> int:
        """Revoke a user's active sessions (all, or all but ``except_token_hash``). Returns the count."""
        now = time.time() if now is None else now
        sql = "UPDATE sessions SET revoked_at=? WHERE user_id=? AND revoked_at IS NULL"
        params: list[Any] = [now, user_id]
        if except_token_hash is not None:
            sql += " AND token_hash != ?"
            params.append(except_token_hash)
        async with self._acquire() as conn:
            cur = await conn.cursor()
            try:
                await cur.execute(sql, tuple(params))
                count = cur.rowcount
                await conn.commit()
            except Exception:
                await conn.rollback()
                raise
        return int(count) if count is not None else 0

    async def enforce_session_cap(
        self, user_id: str, *, keep: int, now: float | None = None
    ) -> None:
        """Revoke a user's active sessions beyond the ``keep`` most recently created (AUTH-SESS-CAP)."""
        if keep <= 0:
            return
        now = time.time() if now is None else now
        await self._execute(
            "UPDATE sessions SET revoked_at=? WHERE user_id=? AND revoked_at IS NULL"
            " AND token_hash NOT IN ("
            "  SELECT TOP (?) token_hash FROM sessions WHERE user_id=? AND revoked_at IS NULL"
            "  ORDER BY created_at DESC, token_hash DESC"
            ")",
            (now, user_id, keep, user_id),
        )

    async def purge_expired_sessions(self, *, now: float | None = None) -> int:
        now = time.time() if now is None else now
        async with self._acquire() as conn:
            cur = await conn.cursor()
            try:
                await cur.execute("DELETE FROM sessions WHERE expires_at < ?", (now,))
                count = cur.rowcount
                await conn.commit()
            except Exception:
                await conn.rollback()
                raise
        return int(count) if count is not None else 0

    async def stats(self) -> dict[str, int]:
        rows = await self._fetchall("SELECT status, COUNT(*) AS n FROM outbox GROUP BY status")
        return {r["status"]: int(r["n"]) for r in rows}

    async def db_status(self) -> DbStatus:
        recovery = await self._fetchone(
            "SELECT recovery_model_desc AS m FROM sys.databases WHERE name = DB_NAME()"
        )
        size = await self._fetchone(
            "SELECT CAST(SUM(size) AS BIGINT) * 8 * 1024 AS b FROM sys.database_files"
        )
        return DbStatus(
            path=self.path,
            size_bytes=int(size["b"]) if size and size["b"] is not None else 0,
            disk_free_bytes=0,  # not readily available for a remote SQL Server
            journal_mode=str(recovery["m"]) if recovery and recovery["m"] else "",
            messages=await self._count("messages"),
            events=await self._count("message_events"),
            audit=await self._count("audit_log"),
        )

    async def integrity_check(self) -> tuple[bool, str]:
        # A connectivity/consistency probe; deep checks (DBCC CHECKDB) are an out-of-band DBA task.
        await self._fetchone("SELECT 1 AS ok")
        return True, "ok (SQL Server: run DBCC CHECKDB out-of-band for deep checks)"

    async def _count(self, table: str) -> int:
        row = await self._fetchone(f"SELECT COUNT(*) AS n FROM {table}")  # table is a constant
        return int(row["n"]) if row else 0

    async def connection_metrics(
        self, *, since: float, now: float | None = None, rate_window: float = 60.0
    ) -> ConnectionMetrics:
        now = time.time() if now is None else now
        rate_since = now - rate_window

        count_rows = await self._fetchall(
            "SELECT channel_id, COUNT(*) AS [read],"
            " SUM(CASE WHEN status=? THEN 1 ELSE 0 END) AS errored"
            " FROM messages WHERE received_at>=? GROUP BY channel_id",
            (MessageStatus.ERROR.value, since),
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
            " SUM(CASE WHEN status IN (?,?) THEN 1 ELSE 0 END) AS queue_depth,"
            " SUM(CASE WHEN status=? AND updated_at>=? THEN 1 ELSE 0 END) AS written,"
            " SUM(CASE WHEN status=? AND updated_at>=? THEN 1 ELSE 0 END) AS dead,"
            " MIN(CASE WHEN status=? THEN created_at END) AS oldest_pending_at,"
            " SUM(CASE WHEN status=? AND updated_at>=? THEN 1 ELSE 0 END) AS recent_done,"
            " MAX(CASE WHEN status=? THEN updated_at END) AS last_done_at"
            " FROM outbox GROUP BY channel_id, destination_name",
            (
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
            ),
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
