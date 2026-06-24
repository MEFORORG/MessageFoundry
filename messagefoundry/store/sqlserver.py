# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Production SQL Server implementation of the :class:`~messagefoundry.store.base.Store` protocol.

Runs the full ADR-0001 staged pipeline (ingress -> routed -> outbound) + ADR-0013 query/response on a
unified ``queue`` table, mirroring the SQLite :class:`~messagefoundry.store.store.MessageStore`
semantics (at-least-once delivery, retries, replay, dead-lettering, retention, encryption-at-rest) in
T-SQL over ``aioodbc``. Concurrency uses SQL Server row-locking — ``claim_ready`` claims due rows with
``WITH (READPAST, UPDLOCK, ROWLOCK)`` so independent delivery workers don't block or double-claim — plus
RCSI and an ``sp_getapplock``-serialized finalizer, lifting SQLite's single-writer ceiling. Both
``supports_ingest_stage`` and ``supports_response_capture`` are True.

``aioodbc`` is an **optional extra** (``pip install 'messagefoundry[sqlserver]'``) and also needs the
Microsoft ODBC Driver 18 at the OS level. It's imported lazily in :meth:`SqlServerStore.open` so
SQLite-only installs never touch it. Verified against a real SQL Server by the CI service-container job
(the store suite + the SQL Server load smoke).
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from collections.abc import AsyncIterator, Iterable, Mapping, Sequence
from contextlib import asynccontextmanager
from types import MappingProxyType
from typing import Any
from uuid import uuid4

from messagefoundry.config.models import RetryPolicy
from messagefoundry.config.settings import (
    INSECURE_TLS_ESCAPE_ENV,
    SqlAuth,
    StoreSettings,
    insecure_tls_allowed,
)
from messagefoundry.redaction import safe_text
from messagefoundry.store.audit_tee import emit_audit_tee
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
    # Unified staged queue (ADR 0001) — ingress -> routed -> outbound, one row per stage-unit with a
    # `stage` discriminator. The SQL Server backend originally shipped only the flat `outbox`; the
    # staged pipeline (enqueue_ingress + the handoffs) and ALL delivery-side methods now read/write
    # this table (outbox is retained only for legacy read-compat). `seq` IDENTITY is the FIFO
    # insertion-order tiebreak (PG uses BIGSERIAL); owner/lease_expires_at are present for parity but
    # written NULL on this single-node backend (reset_stale_inflight is the recovery path).
    """IF OBJECT_ID('queue','U') IS NULL CREATE TABLE queue (
        id NVARCHAR(64) NOT NULL PRIMARY KEY, seq BIGINT IDENTITY(1,1) NOT NULL,
        message_id NVARCHAR(64) NOT NULL, stage NVARCHAR(16) NOT NULL,
        channel_id NVARCHAR(256) NOT NULL, destination_name NVARCHAR(256) NULL,
        handler_name NVARCHAR(256) NULL, payload NVARCHAR(MAX) NOT NULL, status NVARCHAR(32) NOT NULL,
        attempts INT NOT NULL DEFAULT 0, next_attempt_at FLOAT NOT NULL, last_error NVARCHAR(MAX) NULL,
        owner NVARCHAR(256) NULL, lease_expires_at FLOAT NULL,
        created_at FLOAT NOT NULL, updated_at FLOAT NOT NULL,
        CONSTRAINT fk_queue_message FOREIGN KEY (message_id) REFERENCES messages(id))""",
    """IF INDEXPROPERTY(OBJECT_ID('queue'),'ix_queue_ready','IndexID') IS NULL
        CREATE INDEX ix_queue_ready ON queue(stage, status, next_attempt_at)""",
    """IF INDEXPROPERTY(OBJECT_ID('queue'),'ix_queue_message','IndexID') IS NULL
        CREATE INDEX ix_queue_message ON queue(message_id)""",
    """IF INDEXPROPERTY(OBJECT_ID('queue'),'ix_queue_fifo_out','IndexID') IS NULL
        CREATE INDEX ix_queue_fifo_out ON queue(stage, destination_name, status, created_at, seq)""",
    """IF INDEXPROPERTY(OBJECT_ID('queue'),'ix_queue_fifo_in','IndexID') IS NULL
        CREATE INDEX ix_queue_fifo_in ON queue(stage, channel_id, status, created_at, seq)""",
    # LOCK_ESCALATION=DISABLE: `queue` is a hot multi-writer table; a depth-triggered escalation to a
    # TABLE X lock during a deep startup orphan sweep would block ALL claim/handoff workers. Degrade a
    # deep sweep to many row locks under RCSI instead. Idempotent (re-running re-sets the same option).
    # IF-guarded (like the indexes) so it fires at most once — a bare ALTER on every open() takes a
    # Sch-M lock on the hot queue table (review). lock_escalation 2 = DISABLE.
    """IF (SELECT lock_escalation FROM sys.tables WHERE object_id=OBJECT_ID('queue')) <> 2
        ALTER TABLE queue SET (LOCK_ESCALATION = DISABLE)""",
    """IF OBJECT_ID('message_events','U') IS NULL CREATE TABLE message_events (
        id INT IDENTITY(1,1) PRIMARY KEY, message_id NVARCHAR(64) NOT NULL, ts FLOAT NOT NULL,
        event NVARCHAR(64) NOT NULL, destination NVARCHAR(256) NULL, detail NVARCHAR(MAX) NULL)""",
    """IF INDEXPROPERTY(OBJECT_ID('message_events'),'ix_events_message','IndexID') IS NULL
        CREATE INDEX ix_events_message ON message_events(message_id, ts)""",
    # Transform-accessible state (ADR 0005). Written here via transform_handoff (parity with SQLite/
    # Postgres): the read-through cache is loaded at open and refreshed post-commit, so a Handler's
    # cross-message state_get(...) resolves in-process. Schema matches SQLite.
    """IF OBJECT_ID('state','U') IS NULL CREATE TABLE state (
        namespace NVARCHAR(256) NOT NULL, [key] NVARCHAR(256) NOT NULL, value NVARCHAR(MAX) NOT NULL,
        set_at FLOAT NOT NULL, message_id NVARCHAR(64) NULL,
        CONSTRAINT pk_state PRIMARY KEY (namespace, [key]))""",
    """IF INDEXPROPERTY(OBJECT_ID('state'),'ix_state_set_at','IndexID') IS NULL
        CREATE INDEX ix_state_set_at ON state(set_at)""",
    """IF OBJECT_ID('audit_log','U') IS NULL CREATE TABLE audit_log (
        id INT IDENTITY(1,1) PRIMARY KEY, ts FLOAT NOT NULL, actor NVARCHAR(256) NULL,
        action NVARCHAR(128) NOT NULL, channel_id NVARCHAR(256) NULL, detail NVARCHAR(MAX) NULL,
        row_hash NVARCHAR(64) NULL)""",
    """IF COL_LENGTH('audit_log','row_hash') IS NULL
        ALTER TABLE audit_log ADD row_hash NVARCHAR(64) NULL""",
    """IF INDEXPROPERTY(OBJECT_ID('audit_log'),'ix_audit_ts','IndexID') IS NULL
        CREATE INDEX ix_audit_ts ON audit_log(ts)""",
    """IF OBJECT_ID('pending_approvals','U') IS NULL CREATE TABLE pending_approvals (
        id NVARCHAR(64) NOT NULL PRIMARY KEY, operation NVARCHAR(128) NOT NULL,
        params NVARCHAR(MAX) NOT NULL, requester NVARCHAR(256) NOT NULL,
        requested_at FLOAT NOT NULL, status NVARCHAR(20) NOT NULL DEFAULT 'pending',
        approver NVARCHAR(256) NULL, decided_at FLOAT NULL, expires_at FLOAT NULL)""",
    """IF INDEXPROPERTY(OBJECT_ID('pending_approvals'),'ix_pending_approvals_status','IndexID') IS NULL
        CREATE INDEX ix_pending_approvals_status ON pending_approvals(status, requested_at)""",
    """IF OBJECT_ID('users','U') IS NULL CREATE TABLE users (
        id NVARCHAR(64) NOT NULL PRIMARY KEY, username NVARCHAR(256) NOT NULL UNIQUE,
        auth_provider NVARCHAR(16) NOT NULL, display_name NVARCHAR(256) NULL,
        email NVARCHAR(256) NULL, disabled BIT NOT NULL DEFAULT 0, created_at FLOAT NOT NULL,
        updated_at FLOAT NOT NULL, last_login_at FLOAT NULL, password_hash NVARCHAR(512) NULL,
        password_changed_at FLOAT NULL, must_change_password BIT NOT NULL DEFAULT 0,
        failed_attempts INT NOT NULL DEFAULT 0, locked_until FLOAT NULL,
        channel_scope NVARCHAR(MAX) NULL, totp_secret NVARCHAR(MAX) NULL,
        totp_enabled BIT NOT NULL DEFAULT 0, totp_enrolled_at FLOAT NULL,
        totp_recovery_codes NVARCHAR(MAX) NULL, last_totp_step INT NULL)""",
    """IF COL_LENGTH('users','channel_scope') IS NULL
        ALTER TABLE users ADD channel_scope NVARCHAR(MAX) NULL""",
    # MFA (WP-14): TOTP columns ALTER-ed in for a pre-existing users table (idempotent).
    """IF COL_LENGTH('users','totp_secret') IS NULL
        ALTER TABLE users ADD totp_secret NVARCHAR(MAX) NULL""",
    """IF COL_LENGTH('users','totp_enabled') IS NULL
        ALTER TABLE users ADD totp_enabled BIT NOT NULL DEFAULT 0""",
    """IF COL_LENGTH('users','totp_enrolled_at') IS NULL
        ALTER TABLE users ADD totp_enrolled_at FLOAT NULL""",
    """IF COL_LENGTH('users','totp_recovery_codes') IS NULL
        ALTER TABLE users ADD totp_recovery_codes NVARCHAR(MAX) NULL""",
    # Single-use TOTP within the step window (ASVS 6.5.1): highest consumed time-step.
    """IF COL_LENGTH('users','last_totp_step') IS NULL
        ALTER TABLE users ADD last_totp_step INT NULL""",
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
        revoked_at FLOAT NULL, client NVARCHAR(256) NULL, reauth_at FLOAT NULL,
        mfa_verified_at FLOAT NULL)""",
    """IF COL_LENGTH('sessions','reauth_at') IS NULL
        ALTER TABLE sessions ADD reauth_at FLOAT NULL""",
    """IF COL_LENGTH('sessions','mfa_verified_at') IS NULL
        ALTER TABLE sessions ADD mfa_verified_at FLOAT NULL""",
    """IF INDEXPROPERTY(OBJECT_ID('sessions'),'ix_sessions_user','IndexID') IS NULL
        CREATE INDEX ix_sessions_user ON sessions(user_id)""",
    """IF INDEXPROPERTY(OBJECT_ID('sessions'),'ix_sessions_expires','IndexID') IS NULL
        CREATE INDEX ix_sessions_expires ON sessions(expires_at)""",
    # Captured request/response replies (ADR 0013) — an IMMUTABLE ARTIFACT table (composite PK), NOT a
    # queue stage, so it is invisible to _maybe_finalize's `FROM queue` scan. response_seq is replay-
    # stable (1+MAX per (message_id,destination_name)). body + detail are BOTH ciphertext at rest for
    # cross-backend read-API parity with PG/SQLite (which encrypt+purge+rotate detail); outcome stays
    # plaintext. This is the ONE place this backend encrypts a "detail"-class column — queue.last_error,
    # messages.error and message_events.detail stay plaintext here. NOTE (#120): those columns are NOT
    # assumed non-PHI — every write goes through the safe_exc/safe_text PHI chokepoint (record_received /
    # mark_failed / dead_letter_now / _event) so HL7-shaped content can't land, and on read they gate on
    # messages:view_summary. Encrypting them at rest on this backend too is a tracked defense-in-depth
    # follow-up (docs/PHI.md); until then the read gate + the "no PHI in exceptions" convention are the
    # controls for any residual invented free-text. (Distinct from those detail-class columns,
    # messages.summary/metadata — direct MRN + patient name — ARE ciphered at rest on this backend, EF-3.)
    """IF OBJECT_ID('response','U') IS NULL CREATE TABLE response (
        message_id NVARCHAR(64) NOT NULL, destination_name NVARCHAR(256) NOT NULL,
        response_seq INT NOT NULL, body NVARCHAR(MAX) NULL, outcome NVARCHAR(64) NOT NULL,
        detail NVARCHAR(MAX) NULL, captured_at FLOAT NOT NULL,
        CONSTRAINT pk_response PRIMARY KEY (message_id, destination_name, response_seq),
        CONSTRAINT fk_response_message FOREIGN KEY (message_id) REFERENCES messages(id))""",
    """IF INDEXPROPERTY(OBJECT_ID('response'),'ix_response_message','IndexID') IS NULL
        CREATE INDEX ix_response_message ON response(message_id)""",
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

    # The staged ingress pipeline (enqueue_ingress + the ingress->routed->outbound handoffs) is
    # implemented on the unified ``queue`` table: atomic DELETE...OUTPUT claim-handoffs, an
    # sp_getapplock-serialized queue-aware finalizer, and RCSI for non-blocking claim/finalize
    # (ADR 0001; BACKLOG #1 closed). The engine runs the staged runner on this backend.
    supports_ingest_stage = True

    # Request/response capture + re-ingress (ADR 0013) IS supported on the SQL Server store: captured
    # replies persist to the `response` table (body + detail ciphertext, outcome plaintext) and
    # re-ingress rides a staged Stage.RESPONSE work-row. The runner may start a capturing outbound + the
    # re-ingress worker on this backend.
    supports_response_capture = True

    def __init__(self, pool: Any, settings: StoreSettings, *, cipher: Cipher | None = None) -> None:
        self._pool = pool
        self._settings = settings
        self._cipher: Cipher = cipher or IdentityCipher()
        self.path = f"{settings.server}/{settings.database}"  # descriptor for db_status
        # ADR 0005 transform-state read-through cache (parity with SQLite/PG): loaded at open, updated
        # post-commit by transform_handoff, surfaced via state_view() so a Handler's cross-message
        # state_get(...) resolves in-process.
        self._state_cache: dict[tuple[str, str], Any] = {}
        # Serializes audit-chain appends in-process (the store is the single audit writer per engine
        # process; active-passive = one active node) — see record_audit.
        self._audit_lock = asyncio.Lock()

    # --- PHI-at-rest cipher seam for nullable text columns (mirrors MessageStore._enc/_dec) -----
    # Used for summary/metadata (EF-3). null/empty-safe: a NULL or purged '' stays as-is, never turns
    # into ciphertext-of-empty; decrypt passes legacy plaintext / '' through unchanged on read.

    def _enc(self, value: str | None) -> str | None:
        if not value:  # None or "" → leave blank (covers purged/empty values)
            return value
        return self._cipher.encrypt(value)

    def _dec(self, value: str | None) -> str | None:
        if value is None:
            return value
        return self._cipher.decrypt(value)  # '' and legacy plaintext pass through unchanged

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
        # RCSI must be enabled BEFORE the pool exists: its one-time ALTER ... WITH ROLLBACK IMMEDIATE
        # takes momentary exclusivity, and with no MEFOR pool session open yet it has nothing of ours
        # to terminate (concurrency_fixes (a)).
        await cls._ensure_database_options(settings)
        pool = await aioodbc.create_pool(
            dsn=connection_string(settings),
            minsize=1,
            maxsize=max(1, settings.pool_size),
            autocommit=False,
        )
        store = cls(pool, settings, cipher=cipher)
        try:
            await store._ensure_schema()
            await store._encrypt_existing_rows()  # one-time PHI-at-rest migration when a key is set
            await store._backfill_audit_chain()  # chain any pre-existing (unhashed) audit rows
            await store._load_state_cache()  # ADR 0005 read-through cache warm-up
        except Exception:
            # Don't leak the pool if first-open initialization fails (M-6).
            pool.close()
            await pool.wait_closed()
            raise
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
            # Runs in open() before the store is returned, so no concurrent record_audit can race it.
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
        for table, column in (
            ("messages", "raw"),
            ("queue", "payload"),
            ("outbox", "payload"),
            (
                "users",
                "totp_secret",
            ),  # MFA secret (WP-14): id-keyed, NULL rows excluded by NOT LIKE
        ):
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
        # messages.summary/metadata (id PK, nullable PHI — EF-3): MRN + patient name. Own pass with the
        # nullable `<> '' AND IS NOT NULL` guard so a blank/purged '' is never turned into ciphertext-of-
        # empty (the id-keyed loop above omits that guard because raw/payload are never legitimately '').
        for mcol in ("summary", "metadata"):
            while True:
                rows = await self._fetchall(
                    f"SELECT TOP (500) id, {mcol} AS v FROM messages"
                    f" WHERE {mcol} NOT LIKE ? AND {mcol} <> '' AND {mcol} IS NOT NULL",
                    (like,),
                )
                if not rows:
                    break
                async with self._acquire() as conn:
                    cur = await conn.cursor()
                    try:
                        for r in rows:
                            await cur.execute(
                                f"UPDATE messages SET {mcol}=? WHERE id=?",
                                (self._cipher.encrypt(r["v"]), r["id"]),
                            )
                        await conn.commit()
                    except Exception:
                        await conn.rollback()
                        raise
                total += len(rows)
        # `response` body + detail (composite PK) — a separate pass (can't ride the id-keyed loop above).
        # PG/SQLite migrate these too; without it a no-key -> key -> restart leaves captured reply PHI as
        # plaintext at rest. body/detail are nullable, so guard `<> '' AND IS NOT NULL`.
        for rcol in ("body", "detail"):
            while True:
                rows = await self._fetchall(
                    f"SELECT TOP (500) message_id, destination_name, response_seq, {rcol} AS v"
                    f" FROM response WHERE {rcol} NOT LIKE ? AND {rcol} <> '' AND {rcol} IS NOT NULL",
                    (like,),
                )
                if not rows:
                    break
                async with self._acquire() as conn:
                    cur = await conn.cursor()
                    try:
                        for r in rows:
                            await cur.execute(
                                f"UPDATE response SET {rcol}=?"
                                " WHERE message_id=? AND destination_name=? AND response_seq=?",
                                (
                                    self._cipher.encrypt(r["v"]),
                                    r["message_id"],
                                    r["destination_name"],
                                    r["response_seq"],
                                ),
                            )
                        await conn.commit()
                    except Exception:
                        await conn.rollback()
                        raise
                total += len(rows)
        if total:
            log.info("encrypted %d existing message/outbox/response row(s) at rest", total)

    @staticmethod
    async def _ensure_database_options(settings: StoreSettings) -> None:
        """Enable READ_COMMITTED_SNAPSHOT (RCSI) so the staged claim/finalize paths read on a
        row-version snapshot rather than taking shared locks that deadlock writers under concurrent
        load (concurrency_fixes (a)). Runs on its OWN autocommit connection BEFORE the pool is
        created, so the momentary exclusivity of ``WITH ROLLBACK IMMEDIATE`` has no sibling MEFOR
        session to terminate; IF-guarded on the live state, so the disruptive ALTER fires at most ONCE
        (greenfield first boot) and every later open()/failover is a detect-and-skip no-op. Degrades
        to a warning (never fails open()) when the principal lacks ALTER DATABASE or the lock cannot
        be taken — emitting the exact statement for a DBA to run out-of-band."""
        import aioodbc

        db = settings.database
        try:
            conn = await aioodbc.connect(dsn=connection_string(settings), autocommit=True)
        except Exception as exc:  # noqa: BLE001 - the pool open below surfaces a real connect failure
            log.warning("skipping the RCSI check on %r (could not connect): %s", db, exc)
            return
        try:
            cur = await conn.cursor()
            await cur.execute(
                "SELECT is_read_committed_snapshot_on, snapshot_isolation_state "
                "FROM sys.databases WHERE name = DB_NAME()"
            )
            row = await cur.fetchone()
            # If we cannot read the state, do NOT attempt a disruptive ALTER.
            rcsi_on = bool(row[0]) if row else True
            snapshot_on = (row[1] in (1, 2)) if row else True
            if not rcsi_on:
                try:
                    await cur.execute(
                        "ALTER DATABASE CURRENT SET READ_COMMITTED_SNAPSHOT ON WITH ROLLBACK IMMEDIATE"
                    )
                    log.info("enabled READ_COMMITTED_SNAPSHOT on database %r", db)
                except Exception as exc:  # noqa: BLE001 - permission/lock: degrade to a DBA pointer
                    log.warning(
                        "could not enable READ_COMMITTED_SNAPSHOT on %r (%s); a DBA should run once: "
                        "ALTER DATABASE [%s] SET READ_COMMITTED_SNAPSHOT ON WITH ROLLBACK IMMEDIATE — "
                        "without it the staged claim/finalize paths are more deadlock-prone under load",
                        db,
                        exc,
                        db,
                    )
            if not snapshot_on:
                try:
                    # ALLOW_SNAPSHOT_ISOLATION is an online change (no exclusivity required).
                    await cur.execute("ALTER DATABASE CURRENT SET ALLOW_SNAPSHOT_ISOLATION ON")
                except Exception as exc:  # noqa: BLE001 - non-fatal
                    log.warning("could not enable ALLOW_SNAPSHOT_ISOLATION on %r: %s", db, exc)
        finally:
            await conn.close()

    async def _ensure_schema(self) -> None:
        async with self._acquire() as conn:
            cur = await conn.cursor()
            try:
                for statement in _SCHEMA:
                    await cur.execute(statement)
                await conn.commit()
            except Exception:
                await conn.rollback()  # roll back the partial DDL batch (M-6)
                raise

    async def close(self) -> None:
        self._pool.close()
        await self._pool.wait_closed()

    # --- helpers -------------------------------------------------------------

    @asynccontextmanager
    async def _acquire(self) -> AsyncIterator[Any]:
        """Acquire a pooled connection with the configured command (statement) timeout applied.

        ``Connection Timeout`` in the DSN is only the *login* timeout; the per-statement timeout is a
        pyodbc **connection** attribute (STORE-3). aioodbc's wrapper exposes ``timeout`` read-only, so
        we set it on the underlying ``pyodbc.Connection`` (``_conn``); aioodbc 0.5.0 has no creation
        hook (``after_created``), so we apply it per-acquire (an idempotent int assignment). The prior
        ``conn.timeout = ...`` raised AttributeError and was silently swallowed, so no statement
        timeout was ever applied — a hung statement then held its queue/messages row X-locks forever."""
        async with self._pool.acquire() as conn:
            raw = getattr(conn, "_conn", None)
            if raw is not None:
                raw.timeout = self._settings.command_timeout  # seconds; 0 = no limit
            yield conn

    async def _fetchall(self, sql: str, params: tuple[Any, ...] = ()) -> list[dict[str, Any]]:
        async with self._acquire() as conn:
            cur = await conn.cursor()
            try:
                await cur.execute(sql, params) if params else await cur.execute(sql)
                columns = [c[0] for c in cur.description]
                rows = await cur.fetchall()
                await conn.commit()
            except Exception:
                # autocommit=False: a failed read otherwise leaves the pooled connection mid-txn (and
                # under RCSI an open snapshot pins the version store / bloats tempdb). Roll back before
                # it returns to the pool so the next borrower starts clean (M-6).
                await conn.rollback()
                raise
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
        detail = (
            safe_text(detail) if detail else detail
        )  # PHI chokepoint (#120); SQL Server stores plaintext
        await cur.execute(
            "INSERT INTO message_events (message_id, ts, event, destination, detail)"
            " VALUES (?,?,?,?,?)",
            (message_id, now, event, destination, detail),
        )

    async def _applock(self, cur: Any, resource: str) -> None:
        """Take a transaction-scoped exclusive ``sp_getapplock`` — the T-SQL analog of PG's advisory
        lock. A NAMED lock in its own space: it never locks ``queue``/``messages`` rows, so it cannot
        invert the producers' queue->messages lock order (no AB/BA deadlock), and it is re-entrant per
        (resource, transaction). ``@LockOwner='Transaction'`` auto-releases it at the caller's commit/
        rollback, so the caller MUST be in an open (autocommit=False) transaction. Raises on a negative
        return code (timeout/deadlock/error) rather than proceeding unserialized — a swallowed timeout
        would fork the audit chain or double-finalize a message."""
        ct = self._settings.command_timeout
        timeout_ms = (
            int(ct * 1000) if ct else -1
        )  # ms; -1 = wait (the pyodbc query timeout backstops)
        await cur.execute(
            "SET NOCOUNT ON;"
            " DECLARE @rc INT;"
            " EXEC @rc = sp_getapplock @Resource=?, @LockMode='Exclusive',"
            " @LockOwner='Transaction', @LockTimeout=?;"
            " SELECT @rc",
            (resource, timeout_ms),
        )
        row = await cur.fetchone()
        rc = int(row[0]) if row and row[0] is not None else -999
        if rc < 0:  # -1 timeout, -2 cancelled, -3 deadlock victim, -999 bad param
            raise RuntimeError(f"sp_getapplock({resource!r}) failed: rc={rc}")

    async def _lock_finalize_batch(self, cur: Any, message_ids: Iterable[str]) -> None:
        """Pre-acquire the per-message finalize applock for every id in CANONICAL sorted order, so a
        multi-message finalizer (an orphan sweep / cancel_queued) can never deadlock another by taking
        the per-id locks in a different order. Re-entrant: a later ``_maybe_finalize`` re-take of the
        same (resource, transaction) is a no-op."""
        for mid in sorted(set(message_ids)):
            await self._applock(cur, f"mefor:finalize:{mid}")

    async def _fifo_created_at(
        self, cur: Any, stage: str, lane_col: str, lane_val: str, now: float
    ) -> float:
        """The ``created_at`` to stamp on a new ``stage`` row so per-lane FIFO order stays monotonic
        even if the wall clock regresses: ``max(now, the lane's current max created_at)``. ``lane_col``
        is a code-controlled literal (allow-listed below — never user input). One grouped MAX per lane
        bounds the lock-hold window under high fan-out; under RCSI it reads the committed snapshot
        without blocking writers."""
        if lane_col not in (
            "channel_id",
            "destination_name",
        ):  # injection guard (survives python -O)
            raise ValueError(f"invalid lane column: {lane_col!r}")
        await cur.execute(
            f"SELECT MAX(created_at) FROM queue WHERE stage=? AND {lane_col}=?", (stage, lane_val)
        )
        row = await cur.fetchone()
        prior = row[0] if row and row[0] is not None else None
        return max(now, prior) if prior is not None else now

    async def _maybe_finalize(self, cur: Any, message_id: str, now: float) -> None:
        """Recompute and persist a message's terminal disposition — the SOLE authority for it. Scans
        ALL stages of ``queue`` so a delivered handler can't finalize the message while a sibling
        handler's routed row is still in flight. Serialized per-message on the finalize applock so two
        concurrent finalizers (a delivery + a transform handoff) can't lost-update ``messages.status``.
        Precedence: any pending/inflight at any stage -> still moving (return); else any dead -> ERROR;
        else any outbound row -> PROCESSED; else no rows + messages.status='routed' -> FILTERED (every
        handler ran, delivered nothing); else leave (UNROUTED/ERROR/in-progress not clobbered)."""
        # A per-message NAMED lock — NOT a messages-row lock, which would invert the queue->messages
        # lock order the producers take and deadlock (error 1205). Re-entrant; released at commit.
        await self._applock(cur, f"mefor:finalize:{message_id}")
        await cur.execute(
            "SELECT stage, status, COUNT(*) AS n FROM queue WHERE message_id=? GROUP BY stage, status",
            (message_id,),
        )
        rows = await cur.fetchall()
        statuses = {r[1] for r in rows}
        if OutboxStatus.PENDING.value in statuses or OutboxStatus.INFLIGHT.value in statuses:
            return  # still moving through a stage
        if OutboxStatus.DEAD.value in statuses:
            status = MessageStatus.ERROR.value
        elif any(r[0] == Stage.OUTBOUND.value for r in rows):
            status = MessageStatus.PROCESSED.value
        elif not rows:
            # No queue rows remain: the router/handlers produced no delivery. FILTERED only if it was
            # actually routed; never clobber UNROUTED / ERROR / a status already set terminal.
            await cur.execute("SELECT status FROM messages WHERE id=?", (message_id,))
            mrow = await cur.fetchone()
            if not mrow or mrow[0] != MessageStatus.ROUTED.value:
                return
            status = MessageStatus.FILTERED.value
        else:
            return  # rows exist but all terminal, non-dead, non-outbound — leave as-is (rare)
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
                        self._enc(summary),  # EF-3: MRN/name is PHI — ciphered at rest
                        self._enc(metadata),
                    ),
                )
                for dest_name, payload in deliveries:
                    await cur.execute(
                        "INSERT INTO queue (id, message_id, stage, channel_id, destination_name,"
                        " handler_name, payload, status, attempts, next_attempt_at, owner,"
                        " lease_expires_at, created_at, updated_at)"
                        " VALUES (?,?,?,?,?,NULL,?,?,0,?,NULL,NULL,?,?)",
                        (
                            uuid4().hex,
                            mid,
                            Stage.OUTBOUND.value,
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

    async def _insert_outbound(
        self, cur: Any, message_id: str, channel_id: str, dest_name: str, payload: str, now: float
    ) -> None:
        """Insert one ``stage='outbound'`` queue row (lane = destination_name), FIFO-clamped."""
        created_at = await self._fifo_created_at(
            cur, Stage.OUTBOUND.value, "destination_name", dest_name, now
        )
        await cur.execute(
            "INSERT INTO queue (id, message_id, stage, channel_id, destination_name, handler_name,"
            " payload, status, attempts, next_attempt_at, owner, lease_expires_at, created_at,"
            " updated_at) VALUES (?,?,?,?,?,NULL,?,?,0,?,NULL,NULL,?,?)",
            (
                uuid4().hex,
                message_id,
                Stage.OUTBOUND.value,
                channel_id,
                dest_name,
                self._cipher.encrypt(payload),
                OutboxStatus.PENDING.value,
                now,
                created_at,
                now,
            ),
        )

    async def _insert_routed(
        self,
        cur: Any,
        message_id: str,
        channel_id: str,
        handler_name: str,
        payload: str,
        now: float,
    ) -> None:
        """Insert one ``stage='routed'`` queue row (lane = channel_id), FIFO-clamped."""
        created_at = await self._fifo_created_at(
            cur, Stage.ROUTED.value, "channel_id", channel_id, now
        )
        await cur.execute(
            "INSERT INTO queue (id, message_id, stage, channel_id, destination_name, handler_name,"
            " payload, status, attempts, next_attempt_at, owner, lease_expires_at, created_at,"
            " updated_at) VALUES (?,?,?,?,NULL,?,?,?,0,?,NULL,NULL,?,?)",
            (
                uuid4().hex,
                message_id,
                Stage.ROUTED.value,
                channel_id,
                handler_name,
                self._cipher.encrypt(payload),
                OutboxStatus.PENDING.value,
                now,
                created_at,
                now,
            ),
        )

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
        """Durably persist a freshly-received raw message to the ingress stage (status RECEIVED + one
        ``stage='ingress'`` queue row holding the raw) in ONE transaction — the staged pipeline's
        ACK-on-receipt boundary (ADR 0001). The inbound may be ACKed once this returns. Returns the
        message id."""
        now = time.time() if now is None else now
        mid = uuid4().hex
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
                        MessageStatus.RECEIVED.value,
                        None,
                        self._enc(summary),  # EF-3: MRN/name is PHI — ciphered at rest
                        self._enc(metadata),
                    ),
                )
                created_at = await self._fifo_created_at(
                    cur, Stage.INGRESS.value, "channel_id", channel_id, now
                )
                await cur.execute(
                    "INSERT INTO queue (id, message_id, stage, channel_id, destination_name,"
                    " handler_name, payload, status, attempts, next_attempt_at, owner,"
                    " lease_expires_at, created_at, updated_at)"
                    " VALUES (?,?,?,?,NULL,NULL,?,?,0,?,NULL,NULL,?,?)",
                    (
                        uuid4().hex,
                        mid,
                        Stage.INGRESS.value,
                        channel_id,
                        self._cipher.encrypt(raw),
                        OutboxStatus.PENDING.value,
                        now,
                        created_at,
                        now,
                    ),
                )
                await self._event(cur, mid, "received", None, "ingress", now)
                await conn.commit()
            except Exception:
                await conn.rollback()
                raise
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
        """Advance a message from ingress straight to outbound in ONE transaction (the Step-A combined
        primitive): consume the in-flight ingress row, insert one outbound row per delivery, set the
        post-router disposition under the finalize applock. Idempotent: returns False (no-op) if the
        ingress row was already consumed by a committed prior run."""
        now = time.time() if now is None else now
        async with self._acquire() as conn:
            cur = await conn.cursor()
            try:
                await cur.execute(
                    "DELETE FROM queue OUTPUT deleted.id WHERE id=? AND stage=? AND status=?",
                    (ingress_id, Stage.INGRESS.value, OutboxStatus.INFLIGHT.value),
                )
                if await cur.fetchone() is None:
                    await conn.rollback()
                    return False  # already handed off (crash-restart) — idempotent no-op
                for dest_name, payload in deliveries:
                    await self._insert_outbound(
                        cur, message_id, channel_id, dest_name, payload, now
                    )
                await self._applock(cur, f"mefor:finalize:{message_id}")
                await cur.execute(
                    "UPDATE messages SET status=? WHERE id=?", (disposition.value, message_id)
                )
                event = {
                    MessageStatus.ROUTED: "routed",
                    MessageStatus.FILTERED: "filtered",
                    MessageStatus.UNROUTED: "unrouted",
                }.get(disposition, "routed")
                await self._event(
                    cur, message_id, event, None, f"{len(deliveries)} destination(s)", now
                )
                await conn.commit()
            except Exception:
                await conn.rollback()
                raise
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
        """Advance a message from the ingress stage to the routed stage in ONE transaction (the router
        half of the split pipeline): consume the in-flight ingress row, insert one ``stage='routed'``
        row per selected handler (handler-list order; ``seq`` preserves it), set the intermediate
        disposition (ROUTED with handlers, UNROUTED with none) under the finalize applock. Idempotent:
        False if the ingress row was already consumed."""
        now = time.time() if now is None else now
        async with self._acquire() as conn:
            cur = await conn.cursor()
            try:
                await cur.execute(
                    "DELETE FROM queue OUTPUT deleted.id WHERE id=? AND stage=? AND status=?",
                    (ingress_id, Stage.INGRESS.value, OutboxStatus.INFLIGHT.value),
                )
                if await cur.fetchone() is None:
                    await conn.rollback()
                    return False  # already handed off (crash-restart) — idempotent no-op
                for handler_name, payload in handlers:
                    await self._insert_routed(
                        cur, message_id, channel_id, handler_name, payload, now
                    )
                await self._applock(cur, f"mefor:finalize:{message_id}")
                await cur.execute(
                    "UPDATE messages SET status=? WHERE id=?", (disposition.value, message_id)
                )
                event = "routed" if disposition is MessageStatus.ROUTED else "unrouted"
                await self._event(cur, message_id, event, None, f"{len(handlers)} handler(s)", now)
                await conn.commit()
            except Exception:
                await conn.rollback()
                raise
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
        """Advance one handler assignment from the routed stage to outbound in ONE transaction (the
        transform half): consume the in-flight routed row, apply each declared state write (ADR 0005),
        insert one outbound row per delivery, then let the finalizer recompute the terminal disposition
        (this method NEVER writes ``messages.status`` itself). State writes are applied in sorted
        (namespace, key) order under HOLDLOCK to bound MERGE range-deadlocks, and commit atomically
        with the outbound rows (exactly-once per re-run); the read-through cache is updated only AFTER
        commit. Idempotent: False if the routed row was already consumed."""
        now = time.time() if now is None else now
        applied: list[tuple[tuple[str, str], Any]] = []
        async with self._acquire() as conn:
            cur = await conn.cursor()
            try:
                await cur.execute(
                    "DELETE FROM queue OUTPUT deleted.id WHERE id=? AND stage=? AND status=?",
                    (routed_id, Stage.ROUTED.value, OutboxStatus.INFLIGHT.value),
                )
                if await cur.fetchone() is None:
                    await conn.rollback()
                    return False  # already handed off (crash-restart) — idempotent no-op
                for namespace, key, value in sorted(state_ops, key=lambda op: (op[0], op[1])):
                    enc = self._cipher.encrypt(json.dumps(value))
                    await cur.execute(
                        "MERGE state WITH (HOLDLOCK) AS t"
                        " USING (SELECT ? AS namespace, ? AS [key]) AS s"
                        " ON t.namespace=s.namespace AND t.[key]=s.[key]"
                        " WHEN MATCHED THEN UPDATE SET value=?, set_at=?, message_id=?"
                        " WHEN NOT MATCHED THEN INSERT (namespace, [key], value, set_at, message_id)"
                        " VALUES (?,?,?,?,?);",
                        (
                            namespace,
                            key,
                            enc,
                            now,
                            message_id,
                            namespace,
                            key,
                            enc,
                            now,
                            message_id,
                        ),
                    )
                    applied.append(((namespace, key), value))
                for dest_name, payload in deliveries:
                    await self._insert_outbound(
                        cur, message_id, channel_id, dest_name, payload, now
                    )
                await self._event(
                    cur, message_id, "transformed", None, f"{len(deliveries)} destination(s)", now
                )
                # Finalizer is the sole disposition authority here (no direct messages.status write).
                await self._maybe_finalize(cur, message_id, now)
                await conn.commit()
            except Exception:
                await conn.rollback()
                raise
        # Commit succeeded → publish the committed state writes to the read-through cache.
        for ck, cv in applied:
            self._state_cache[ck] = cv
        return True

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
        """Mark one outbound row delivered AND persist the partner's captured reply in ONE transaction
        (ADR 0013). ``response_seq`` is ``1 + MAX`` per (message_id, destination_name) so it is replay-
        stable; the ``response`` table is invisible to the finalizer (it scans ``queue`` only). When
        ``reingress_to`` is set the same transaction also inserts the drainable ``Stage.RESPONSE`` work-
        row (which holds the origin non-terminal until ``ingress_handoff`` consumes it). body + detail
        are ciphertext; outcome is plaintext."""
        now = time.time() if now is None else now
        async with self._acquire() as conn:
            cur = await conn.cursor()
            try:
                # Leading SELECT (also opens the txn so _maybe_finalize's applock is never first).
                await cur.execute(
                    "SELECT message_id, destination_name, attempts FROM queue WHERE id=?",
                    (outbox_id,),
                )
                row = await cur.fetchone()
                if row is None:
                    await conn.commit()
                    return
                message_id, destination_name, attempts = row[0], row[1], row[2]
                await cur.execute(
                    "UPDATE queue SET status=?, last_error=NULL, updated_at=?, owner=NULL,"
                    " lease_expires_at=NULL WHERE id=?",
                    (OutboxStatus.DONE.value, now, outbox_id),
                )
                await cur.execute(
                    "SELECT COALESCE(MAX(response_seq), 0) + 1 FROM response"
                    " WHERE message_id=? AND destination_name=?",
                    (message_id, destination_name),
                )
                seq = int((await cur.fetchone())[0])
                # Inline the PG _enc empty-guard: encrypt only a truthy value (never '' / None).
                enc_body = self._cipher.encrypt(body) if body else body
                enc_detail = self._cipher.encrypt(detail) if detail else detail
                await cur.execute(
                    "INSERT INTO response"
                    " (message_id, destination_name, response_seq, body, outcome, detail, captured_at)"
                    " VALUES (?,?,?,?,?,?,?)",
                    (message_id, destination_name, seq, enc_body, outcome, enc_detail, now),
                )
                if reingress_to is not None:
                    # ADR 0013 Increment 2: a drainable Stage.RESPONSE work-row in the SAME txn (orphan-
                    # free) — a token referencing the immutable artifact by PK, on the loopback lane.
                    artifact_ref = f"{message_id}\x1f{destination_name}\x1f{seq}"
                    work_created = await self._fifo_created_at(
                        cur, Stage.RESPONSE.value, "channel_id", reingress_to, now
                    )
                    await cur.execute(
                        "INSERT INTO queue (id, message_id, stage, channel_id, destination_name,"
                        " handler_name, payload, status, attempts, next_attempt_at, owner,"
                        " lease_expires_at, created_at, updated_at)"
                        " VALUES (?,?,?,?,NULL,NULL,?,?,0,?,NULL,NULL,?,?)",
                        (
                            uuid4().hex,
                            message_id,
                            Stage.RESPONSE.value,
                            reingress_to,
                            self._cipher.encrypt(artifact_ref),
                            OutboxStatus.PENDING.value,
                            now,
                            work_created,
                            now,
                        ),
                    )
                await self._event(
                    cur,
                    message_id,
                    "delivered",
                    destination_name,
                    f"attempt {attempts} (response {outcome})",
                    now,
                )
                # Finalizer last; preceded by the SELECT above so its applock is not the first statement.
                await self._maybe_finalize(cur, message_id, now)
                await conn.commit()
            except Exception:
                await conn.rollback()
                raise

    async def correlate_response(self, message_id: str) -> list[CapturedResponse]:
        """Captured replies for a message (ADR 0013), ordered by destination then ``response_seq`` ASC
        (so the latest reply per destination is last). ``body`` + ``detail`` are both decrypted (both
        ciphertext); a NULL (never-captured or purged) body/detail returns ``None`` while an empty ``''``
        round-trips as ``''`` — parity with PG/SQLite ``_dec``; ``outcome`` is plaintext."""
        rows = await self._fetchall(
            "SELECT message_id, destination_name, response_seq, body, outcome, detail, captured_at"
            " FROM response WHERE message_id=? ORDER BY destination_name, response_seq",
            (message_id,),
        )
        return [
            CapturedResponse(
                message_id=r["message_id"],
                destination_name=r["destination_name"],
                response_seq=int(r["response_seq"]),
                outcome=r["outcome"],
                detail=self._cipher.decrypt(r["detail"]) if r["detail"] is not None else None,
                captured_at=float(r["captured_at"]),
                body=self._cipher.decrypt(r["body"]) if r["body"] is not None else None,
            )
            for r in rows
        ]

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
        """Consume one in-flight ``Stage.RESPONSE`` work-row and re-ingress the captured reply as a new
        message on the loopback inbound (ADR 0013 Increment 2), in ONE transaction. Idempotent: returns
        ``False`` if the work-row was already consumed. A corrupt/unparseable ref or a re-ingress that
        would exceed ``correlation_depth_cap`` is dead-lettered (and the token still consumed). The
        re-ingress message id is content-addressed (deterministic), so a re-run never double-inserts the
        child."""
        now = time.time() if now is None else now
        async with self._acquire() as conn:
            cur = await conn.cursor()
            try:
                # (1) Guard-read the in-flight work-row (also opens the txn -> applock not first).
                await cur.execute(
                    "SELECT message_id, payload FROM queue WHERE id=? AND stage=? AND status=?",
                    (response_row_id, Stage.RESPONSE.value, OutboxStatus.INFLIGHT.value),
                )
                wr = await cur.fetchone()
                if wr is None:
                    await conn.rollback()
                    return False  # already consumed by a committed prior run (idempotent no-op)
                origin_id = wr[0]
                # (2) Decrypt + parse the artifact ref; ANY failure -> consume-and-dead-letter.
                try:
                    ref = self._cipher.decrypt(wr[1]) or ""
                    origin_msg_id, dest, seq_s = ref.split("\x1f")
                    seq = int(seq_s)
                except Exception:  # noqa: BLE001 - any decrypt/parse failure = an unrecoverable ref
                    await cur.execute(
                        "UPDATE queue SET status=?, last_error=?, next_attempt_at=?, updated_at=?"
                        " WHERE id=?",
                        (
                            OutboxStatus.DEAD.value,
                            "re-ingress work-row reference is corrupt/unparseable",
                            now,
                            now,
                            response_row_id,
                        ),
                    )
                    await self._event(cur, origin_id, "dead", None, "re-ingress ref corrupt", now)
                    await self._maybe_finalize(cur, origin_id, now)  # preceded by step-1 SELECT
                    await conn.commit()
                    return True  # CONSUME (status flipped), never re-loop
                # (3) Read the immutable artifact body.
                await cur.execute(
                    "SELECT body FROM response"
                    " WHERE message_id=? AND destination_name=? AND response_seq=?",
                    (origin_msg_id, dest, seq),
                )
                art = await cur.fetchone()
                body = (self._cipher.decrypt(art[0]) if (art and art[0]) else "") or ""
                # (4) Correlation lineage from the origin's metadata (parse once).
                await cur.execute("SELECT metadata FROM messages WHERE id=?", (origin_id,))
                mrow = await cur.fetchone()
                meta_json = self._dec(mrow[0]) if mrow else None  # EF-3: metadata ciphered at rest
                loaded = json.loads(meta_json) if meta_json else {}
                origin_meta = loaded if isinstance(loaded, dict) else {}
                child_depth = int(origin_meta.get("correlation_depth", 0) or 0) + 1
                root = origin_meta.get("correlation_root_id") or origin_id
                # (5) Depth-cap -> consume-and-dead-letter.
                if child_depth > correlation_depth_cap:
                    await cur.execute(
                        "UPDATE queue SET status=?, last_error=?, next_attempt_at=?, updated_at=?"
                        " WHERE id=?",
                        (
                            OutboxStatus.DEAD.value,
                            f"re-ingress correlation depth exceeded "
                            f"({child_depth} > {correlation_depth_cap})",
                            now,
                            now,
                            response_row_id,
                        ),
                    )
                    await self._event(
                        cur, origin_id, "dead", dest, f"re-ingress depth cap ({child_depth})", now
                    )
                    await self._maybe_finalize(cur, origin_id, now)  # preceded by step-1 SELECT
                    await conn.commit()
                    return True
                # (6) Deterministic child id + idempotent insert (the guarded DELETE is the real gate).
                new_mid = MessageStore._reingress_message_id(origin_id, dest, seq, body)
                await cur.execute("SELECT 1 FROM messages WHERE id=?", (new_mid,))
                if await cur.fetchone() is None:
                    child_meta = json.dumps(
                        {
                            "correlation_id": origin_id,
                            "correlation_root_id": root,
                            "correlation_depth": child_depth,
                            "reingress_of_seq": seq,
                        }
                    )
                    await cur.execute(
                        "INSERT INTO messages (id, channel_id, received_at, source_type, control_id,"
                        " message_type, raw, status, error, summary, metadata)"
                        " VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                        (
                            new_mid,
                            loopback_channel_id,
                            now,
                            "reingress",
                            control_id,
                            message_type,
                            self._cipher.encrypt(body),
                            MessageStatus.ERROR.value
                            if peek_failed
                            else MessageStatus.RECEIVED.value,
                            "re-ingress body failed HL7 peek" if peek_failed else None,
                            self._enc(summary),  # EF-3: MRN/name is PHI — ciphered at rest
                            self._enc(child_meta),
                        ),
                    )
                    if not peek_failed:
                        ingress_created = await self._fifo_created_at(
                            cur, Stage.INGRESS.value, "channel_id", loopback_channel_id, now
                        )
                        await cur.execute(
                            "INSERT INTO queue (id, message_id, stage, channel_id, destination_name,"
                            " handler_name, payload, status, attempts, next_attempt_at, owner,"
                            " lease_expires_at, created_at, updated_at)"
                            " VALUES (?,?,?,?,NULL,NULL,?,?,0,?,NULL,NULL,?,?)",
                            (
                                uuid4().hex,
                                new_mid,
                                Stage.INGRESS.value,
                                loopback_channel_id,
                                self._cipher.encrypt(body),
                                OutboxStatus.PENDING.value,
                                now,
                                ingress_created,
                                now,
                            ),
                        )
                    await self._event(
                        cur,
                        new_mid,
                        "received",
                        None,
                        f"reingress from {origin_id}/{dest}/seq{seq}",
                        now,
                    )
                    await self._event(
                        cur,
                        origin_id,
                        "reingressed",
                        dest,
                        f"-> {new_mid} depth {child_depth}",
                        now,
                    )
                # (7) Consume the token — exactly-once commit point (OUTPUT readback, never rowcount).
                await cur.execute(
                    "DELETE FROM queue OUTPUT deleted.id WHERE id=? AND stage=? AND status=?",
                    (response_row_id, Stage.RESPONSE.value, OutboxStatus.INFLIGHT.value),
                )
                if await cur.fetchone() is None:
                    await conn.rollback()
                    return False  # defensive; unreachable under single-owner claim
                # (8) Finalize the origin (its last RESPONSE row is now gone).
                await self._maybe_finalize(cur, origin_id, now)
                await conn.commit()
                return True
            except Exception:
                await conn.rollback()
                raise

    async def response_body_for_work_row(self, response_row_id: str) -> str | None:
        """The decrypted reply body behind a ``Stage.RESPONSE`` work-row (ADR 0013) — for the re-ingress
        worker's HL7 peek. ``None`` if the work-row is missing/consumed or its ref is unparseable; ``''``
        if the artifact body is missing/empty. Reads the SAME immutable artifact ``ingress_handoff``
        re-reads, so the peek and the persisted raw always agree."""
        row = await self._fetchone(
            "SELECT payload FROM queue WHERE id=? AND stage=?",
            (response_row_id, Stage.RESPONSE.value),
        )
        if row is None:
            return None
        ref = self._cipher.decrypt(row["payload"]) or ""
        try:
            mid, dest, seq_s = ref.split("\x1f")
        except ValueError:
            return None
        art = await self._fetchone(
            "SELECT body FROM response WHERE message_id=? AND destination_name=? AND response_seq=?",
            (mid, dest, int(seq_s)),
        )
        return self._cipher.decrypt(art["body"]) if (art and art["body"]) else ""

    def state_view(self) -> Mapping[tuple[str, str], Any]:
        """Read-only view of the ADR 0005 transform-state read-through cache (parity with SQLite/PG).
        The runner publishes it around each router/transform run so a Handler's ``state_get(...)``
        resolves cross-message; ``transform_handoff`` refreshes it post-commit."""
        return MappingProxyType(self._state_cache)

    async def _load_state_cache(self) -> None:
        """Warm the transform-state read-through cache from the ``state`` table at open (ADR 0005)."""
        rows = await self._fetchall("SELECT namespace, [key], value FROM state")
        cache: dict[tuple[str, str], Any] = {}
        for r in rows:
            try:
                cache[(r["namespace"], r["key"])] = json.loads(self._cipher.decrypt(r["value"]))
            except (CipherError, ValueError) as exc:  # skip a corrupt/undecryptable state row
                log.warning(
                    "skipping unreadable state row %r/%r: %s", r["namespace"], r["key"], exc
                )
        self._state_cache = cache

    def reference_view(self) -> Mapping[str, Mapping[str, Any]]:
        """Empty reference view on the SQL Server backend (ADR 0006). Reference snapshots live in the
        SQLite store; returning an empty read-only mapping keeps a Handler's ``reference("name")``
        call shaped correctly — though it will raise ``ReferenceError`` for any name (no set synced),
        which is the honest state on this backend (reference snapshots are SQLite/Postgres-only here)."""
        return MappingProxyType({})

    async def write_reference_snapshot(
        self, *, name: str, version: str, rows: Mapping[str, Any]
    ) -> None:
        """Not supported on the SQL Server backend — reference snapshots (ADR 0006) are SQLite/Postgres-
        only. NOTE: the engine DOES run on this backend now (staged pipeline + capture), so if a
        reference SET is configured against the SQL Server store the ReferenceSyncRunner logs a sync
        failure each interval until ADR 0006 lands here (the engine survives; the set never materializes
        and ``reference()`` raises). Present for ``Store`` protocol completeness."""
        raise NotImplementedError(
            "write_reference_snapshot is not supported on the SQL Server backend (ADR 0006 reference "
            "sets are SQLite/Postgres-only); use the SQLite or Postgres backend"
        )

    async def converge_reference_cache(self) -> list[str]:
        """No-op on the SQL Server backend (Track B Step 6). Reference snapshots are SQLite/Postgres-only
        here (write_reference_snapshot raises), so there is no shared snapshot to read through. Present
        for ``Store`` protocol completeness; returns ``[]``."""
        return []

    async def converge_state_cache(self) -> list[str]:
        """No-op on the SQL Server backend (Track B Step 6b): a single-node backend with no cross-node
        state convergence (transform state IS written here via transform_handoff, but never converged
        across nodes). Present for ``Store`` protocol completeness; returns ``[]``."""
        return []

    def enable_state_convergence(self) -> None:
        """No-op on the SQL Server backend (Track B Step 6b): there is no cross-node convergence here, so
        there is no per-namespace version to bump. Present for ``Store`` protocol completeness."""
        return None

    async def dead_letter_missing_handlers(
        self, valid_names: set[str], now: float | None = None
    ) -> int:
        """Dead-letter non-terminal routed queue rows whose handler_name is no longer in the registry
        (a removed/renamed handler) — no transform worker would drain them, so they'd strand forever.
        Call ONCE at startup, AFTER reset_stale_inflight. Per-message finalize applocks are pre-acquired
        in sorted id order to avoid multi-message deadlock; a killed routed row -> DEAD -> the finalizer
        resolves the message to ERROR."""
        now = time.time() if now is None else now
        async with self._acquire() as conn:
            cur = await conn.cursor()
            try:
                await cur.execute(
                    "SELECT id, message_id, handler_name FROM queue"
                    " WHERE stage=? AND status IN (?, ?)",
                    (Stage.ROUTED.value, OutboxStatus.PENDING.value, OutboxStatus.INFLIGHT.value),
                )
                rows = await cur.fetchall()  # positional: (id, message_id, handler_name)
                orphans = [r for r in rows if r[2] not in valid_names]
                if not orphans:
                    await conn.commit()
                    return 0
                error = "handler removed from registry"
                await self._lock_finalize_batch(cur, {r[1] for r in orphans})
                for row in orphans:
                    await cur.execute(
                        "UPDATE queue SET status=?, next_attempt_at=?, last_error=?, updated_at=?,"
                        " owner=NULL, lease_expires_at=NULL WHERE id=?",
                        (OutboxStatus.DEAD.value, now, error, now, row[0]),
                    )
                    await self._event(cur, row[1], "dead", None, error, now)
                    await self._maybe_finalize(cur, row[1], now)
                await conn.commit()
            except Exception:
                await conn.rollback()
                raise
        log.warning(
            "dead-lettered %d orphaned routed row(s) at startup for missing handler(s): %s",
            len(orphans),
            ", ".join(sorted({r[2] for r in orphans})),
        )
        return len(orphans)

    # --- retention / purge + maintenance (PHI.md §8) -------------------------
    # The RetentionRunner drives these once the staged pipeline is enabled. Bodies are blanked to ''
    # (not deleted) so cipher re-encrypt scans skip them and the FK to messages stays intact. SQL
    # Server TDE remains the at-rest baseline; this engine-side rotation/purge complements it.

    async def reencrypt_to_active(self, *, batch: int = 500) -> int:
        """Re-encrypt body columns sitting under a RETIRED key to the active key (key rotation),
        batched per (table, column). No-op (returns 0) unless an AES-GCM keyring cipher is configured.
        Each batch's re-encrypt list is built UP FRONT so an undecryptable value raises BEFORE any
        UPDATE (all-or-nothing; PHI never dropped). Skips rows already under the active key and
        blank/purged values."""
        if not isinstance(self._cipher, AesGcmCipher):
            return 0
        active_like = f"{_ENC_PREFIX}{self._cipher.active_key_id}:%"
        total = 0
        # summary/metadata (EF-3): MRN/name PHI on messages — rotated like raw. The `<> ''` + NOT LIKE
        # guard is null/empty-safe (NULL excluded by NOT LIKE; '' by <> '').
        for table, column in (
            ("messages", "raw"),
            ("queue", "payload"),
            ("users", "totp_secret"),
            ("messages", "summary"),
            ("messages", "metadata"),
        ):
            while True:
                rows = await self._fetchall(
                    f"SELECT TOP (?) id, {column} AS v FROM {table}"
                    f" WHERE {column} NOT LIKE ? AND {column} <> ''",
                    (batch, active_like),
                )
                if not rows:
                    break
                # Decrypt+re-encrypt UP FRONT: a CipherError aborts the batch before any write.
                updates = [
                    (self._cipher.encrypt(self._cipher.decrypt(r["v"])), r["id"]) for r in rows
                ]
                async with self._acquire() as conn:
                    cur = await conn.cursor()
                    try:
                        for enc, rid in updates:
                            await cur.execute(
                                f"UPDATE {table} SET {column}=? WHERE id=?", (enc, rid)
                            )
                        await conn.commit()
                    except Exception:
                        await conn.rollback()
                        raise
                total += len(rows)
        # `state` has a composite PK (namespace, [key]) — its own pass (can't ride the id-keyed loop
        # above). transform_handoff writes state.value encrypted, so a rotation MUST rotate it too or a
        # later retired-key drop silently loses all transform cross-message state (review HIGH).
        while True:
            rows = await self._fetchall(
                "SELECT TOP (?) namespace, [key], value FROM state"
                " WHERE value NOT LIKE ? AND value <> ''",
                (batch, active_like),
            )
            if not rows:
                break
            state_updates = [
                (self._cipher.encrypt(self._cipher.decrypt(r["value"])), r["namespace"], r["key"])
                for r in rows
            ]
            async with self._acquire() as conn:
                cur = await conn.cursor()
                try:
                    for enc, ns, skey in state_updates:
                        await cur.execute(
                            "UPDATE state SET value=? WHERE namespace=? AND [key]=?",
                            (enc, ns, skey),
                        )
                    await conn.commit()
                except Exception:
                    await conn.rollback()
                    raise
            total += len(rows)
        # `response` body + detail are ciphertext with a composite PK (message_id, destination_name,
        # response_seq) — their own passes. IS NOT NULL is explicit/defensive: NOT LIKE already excludes
        # NULLs (three-valued logic) and a NULL has no ciphertext to rotate — but these columns are
        # nullable (unlike state.value/messages.raw/queue.payload), so the guard documents that intent.
        for rcol in ("body", "detail"):
            while True:
                rows = await self._fetchall(
                    f"SELECT TOP (?) message_id, destination_name, response_seq, {rcol} AS v"
                    f" FROM response WHERE {rcol} NOT LIKE ? AND {rcol} <> '' AND {rcol} IS NOT NULL",
                    (batch, active_like),
                )
                if not rows:
                    break
                resp_updates = [
                    (
                        self._cipher.encrypt(self._cipher.decrypt(r["v"])),
                        r["message_id"],
                        r["destination_name"],
                        r["response_seq"],
                    )
                    for r in rows
                ]
                async with self._acquire() as conn:
                    cur = await conn.cursor()
                    try:
                        for enc, rmid, rdest, rseq in resp_updates:
                            await cur.execute(
                                f"UPDATE response SET {rcol}=?"
                                " WHERE message_id=? AND destination_name=? AND response_seq=?",
                                (enc, rmid, rdest, rseq),
                            )
                        await conn.commit()
                    except Exception:
                        await conn.rollback()
                        raise
                total += len(rows)
        if total:
            log.info("re-encrypted %d row(s) to the active key", total)
        return total

    async def purge_message_bodies(self, *, older_than: float, now: float | None = None) -> int:
        """Blank message bodies (and terminal outbound payloads + event details) for messages received
        before ``older_than`` whose queue rows are all terminal — retention (PHI.md §8). Bodies are
        blanked to '' (not deleted) so the cipher re-encrypt scans skip them and the FK to messages
        stays intact. The eligible set is materialized ONCE so all three tables purge exactly the same
        messages. Returns the number of message bodies blanked."""
        async with self._acquire() as conn:
            cur = await conn.cursor()
            try:
                # CREATE (no params) so the temp table lives at CONNECTION scope; a parameterized
                # SELECT...INTO runs under sp_executesql and would scope #eligible to that proc (gone
                # before the UPDATEs). The parameterized INSERT below still populates it.
                await cur.execute("CREATE TABLE #eligible (id NVARCHAR(64) PRIMARY KEY)")
                await cur.execute(
                    "INSERT INTO #eligible SELECT id FROM messages m WHERE m.received_at < ?"
                    " AND NOT EXISTS (SELECT 1 FROM queue q WHERE q.message_id=m.id"
                    " AND q.status IN (?, ?))",
                    (older_than, OutboxStatus.PENDING.value, OutboxStatus.INFLIGHT.value),
                )
                await cur.execute(
                    "UPDATE messages SET raw='', summary=NULL, error=NULL"
                    " WHERE raw <> '' AND id IN (SELECT id FROM #eligible)"
                )
                purged = cur.rowcount
                await cur.execute(
                    "UPDATE queue SET payload='', last_error=NULL"
                    " WHERE stage=? AND status IN (?, ?) AND payload <> ''"
                    " AND message_id IN (SELECT id FROM #eligible)",
                    (Stage.OUTBOUND.value, OutboxStatus.DONE.value, OutboxStatus.CANCELLED.value),
                )
                await cur.execute(
                    "UPDATE message_events SET detail=NULL"
                    " WHERE detail IS NOT NULL AND message_id IN (SELECT id FROM #eligible)"
                )
                # NULL captured response bodies/details for eligible messages (ADR 0013 retention) — to
                # NULL (matching PG/SQLite: correlate then reads None; reencrypt's IS NOT NULL skips them).
                await cur.execute(
                    "UPDATE response SET body=NULL, detail=NULL"
                    " WHERE (body IS NOT NULL OR detail IS NOT NULL)"
                    " AND message_id IN (SELECT id FROM #eligible)"
                )
                await cur.execute("DROP TABLE #eligible")
                await conn.commit()
            except Exception:
                await conn.rollback()
                raise
        return int(purged) if purged is not None else 0

    async def purge_state(self, *, older_than: float, now: float | None = None) -> int:
        """Delete transform-state rows last set before ``older_than`` (ADR 0005 retention), evicting
        them from the read-through cache post-commit. Returns the number deleted."""
        async with self._acquire() as conn:
            cur = await conn.cursor()
            try:
                await cur.execute(
                    "SELECT namespace, [key] FROM state WHERE set_at < ?", (older_than,)
                )
                purged_keys = [(r[0], r[1]) for r in await cur.fetchall()]
                if not purged_keys:
                    await conn.commit()
                    return 0
                await cur.execute("DELETE FROM state WHERE set_at < ?", (older_than,))
                await conn.commit()
            except Exception:
                await conn.rollback()
                raise
        for ck in purged_keys:
            self._state_cache.pop(ck, None)
        return len(purged_keys)

    async def purge_dead_letters(self, *, older_than: float, now: float | None = None) -> int:
        """Blank the payload of dead outbound rows updated before ``older_than`` (retention). Keeps the
        dead row + 'dead' status (counts/disposition) but frees the body; idempotent (payload <> '')."""
        async with self._acquire() as conn:
            cur = await conn.cursor()
            try:
                await cur.execute(
                    "UPDATE queue SET payload='', last_error=NULL"
                    " WHERE stage=? AND status=? AND payload <> '' AND updated_at < ?",
                    (Stage.OUTBOUND.value, OutboxStatus.DEAD.value, older_than),
                )
                purged = cur.rowcount
                await conn.commit()
            except Exception:
                await conn.rollback()
                raise
        return int(purged) if purged is not None else 0

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
        error = (
            safe_text(error) if error else error
        )  # PHI chokepoint (#120); SQL Server stores plaintext
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
                        self._enc(summary),  # EF-3: MRN/name is PHI — ciphered at rest
                        self._enc(metadata),
                    ),
                )
                await self._event(cur, mid, event, None, error, now)
                await conn.commit()
            except Exception:
                await conn.rollback()
                raise
        return mid

    # --- delivery worker path ------------------------------------------------

    @staticmethod
    def _lane_col(stage: str) -> str:
        """The FIFO/depth lane column for a stage (code-controlled literal): ``channel_id`` for
        ingress/routed/response, ``destination_name`` for outbound."""
        return (
            "channel_id"
            if stage in (Stage.INGRESS.value, Stage.ROUTED.value, Stage.RESPONSE.value)
            else "destination_name"
        )

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
        to drain others), flipping them to ``inflight`` and bumping ``attempts``. ``READPAST, UPDLOCK,
        ROWLOCK`` is the T-SQL ``FOR UPDATE SKIP LOCKED`` analog so concurrent workers skip rather than
        block or double-claim. An undecryptable payload is dead-lettered and dropped (poison-row
        containment), not raised."""
        now = time.time() if now is None else now
        where = ["stage=?", "status=?", "next_attempt_at<=?"]
        filters: list[Any] = [stage, OutboxStatus.PENDING.value, now]
        if channel_id is not None:
            where.append("channel_id=?")
            filters.append(channel_id)
        if destination_name is not None:
            where.append("destination_name=?")
            filters.append(destination_name)
        sql = (
            "WITH due AS (SELECT TOP (?) * FROM queue WITH (READPAST, UPDLOCK, ROWLOCK)"
            f" WHERE {' AND '.join(where)} ORDER BY next_attempt_at)"
            " UPDATE due SET status=?, attempts=attempts+1, updated_at=?,"
            " owner=NULL, lease_expires_at=NULL"
            " OUTPUT inserted.id, inserted.message_id, inserted.channel_id,"
            " inserted.destination_name, inserted.handler_name, inserted.payload,"
            " inserted.attempts"
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
            try:
                payload = self._cipher.decrypt(d["payload"])
            except CipherError as exc:
                log.warning("dead-lettering undecryptable queue row %s: %s", d["id"], exc)
                await self.dead_letter_now(d["id"], f"undecryptable payload: {exc}")
                continue
            items.append(
                OutboxItem(
                    id=d["id"],
                    message_id=d["message_id"],
                    channel_id=d["channel_id"],
                    destination_name=d["destination_name"],
                    handler_name=d["handler_name"],
                    payload=payload,
                    attempts=d["attempts"],
                    stage=stage,
                )
            )
        return items

    async def claim_next_fifo(
        self,
        name: str,
        now: float | None = None,
        *,
        stage: str = Stage.OUTBOUND.value,
    ) -> OutboxItem | None:
        """Claim the single oldest *due* pending row for one lane at ``stage`` (strict FIFO — the head
        blocks the lane while it backs off, via the WHERE on the UPDATE). The lane key is stage-aware
        (``destination_name`` outbound, ``channel_id`` ingress/routed); ordering is ``created_at, seq``
        (the IDENTITY tiebreak preserving same-txn insertion order — NOT the random uuid ``id``). This
        backend runs active-passive HA with one active node (the leader), so owner/lease stay NULL on
        the FIFO claim and the runner never owns lanes.

        NB: the head SELECT takes ``(UPDLOCK, ROWLOCK)`` but deliberately **NOT** ``READPAST``. With one
        serial consumer per lane, the only transaction that can hold a lock on the FIFO head is the
        *producer* (the ``transform_handoff``/finalizer that just inserted it, milliseconds from commit).
        ``READPAST`` would SKIP that locked head and claim the next-oldest row instead — delivering seq
        N+1 before N (a per-lane FIFO break; issue #285). Head-of-line *blocking* on a transiently-locked
        head is the correct FIFO semantic here — it briefly waits for the rightful head, matching Postgres'
        ``FOR UPDATE`` (no ``SKIP LOCKED`` skip of a producer-locked head). A pathologically long lock is
        bounded by ``command_timeout``. The UNORDERED :meth:`claim_ready` keeps ``READPAST`` (there,
        skipping a locked sibling to drain the lane is intended and order is explicitly not promised)."""
        now = time.time() if now is None else now
        lane_col = self._lane_col(stage)  # code-controlled literal
        sql = (
            "WITH head AS (SELECT TOP (1) * FROM queue WITH (UPDLOCK, ROWLOCK)"
            f" WHERE stage=? AND {lane_col}=? AND status=? ORDER BY created_at, seq)"
            " UPDATE head SET status=?, attempts=attempts+1, updated_at=?,"
            " owner=NULL, lease_expires_at=NULL"
            " OUTPUT inserted.id, inserted.message_id, inserted.channel_id,"
            " inserted.destination_name, inserted.handler_name, inserted.payload,"
            " inserted.attempts"
            " WHERE next_attempt_at<=?"
        )
        args = (stage, name, OutboxStatus.PENDING.value, OutboxStatus.INFLIGHT.value, now, now)
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
            handler_name=d["handler_name"],
            payload=payload,
            attempts=d["attempts"],
            stage=stage,
        )

    async def mark_done(self, outbox_id: str, now: float | None = None) -> None:
        now = time.time() if now is None else now
        async with self._acquire() as conn:
            cur = await conn.cursor()
            try:
                await cur.execute(
                    "SELECT message_id, destination_name, attempts FROM queue WHERE id=?",
                    (outbox_id,),
                )
                row = await cur.fetchone()
                if row is None:
                    await conn.commit()
                    return
                message_id, destination_name, attempts = row[0], row[1], row[2]
                await cur.execute(
                    "UPDATE queue SET status=?, last_error=NULL, updated_at=? WHERE id=?",
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
        error = safe_text(error)  # PHI chokepoint (#120); SQL Server stores plaintext
        now = time.time() if now is None else now
        async with self._acquire() as conn:
            cur = await conn.cursor()
            try:
                await cur.execute(
                    "SELECT message_id, destination_name, attempts FROM queue WHERE id=?",
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
                    "UPDATE queue SET status=?, next_attempt_at=?, last_error=?, updated_at=? WHERE id=?",
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
        """Return in-flight rows to ``pending`` (startup crash recovery) across ALL stages by default —
        an ingress/routed row left inflight by a crash MUST be re-pended or the message hangs forever
        (count-and-log invariant). ``stage`` optionally narrows it; owner/lease are cleared (single-node
        parity)."""
        now = time.time() if now is None else now
        clauses = ["status=?"]
        params: list[Any] = [OutboxStatus.INFLIGHT.value]
        if stage is not None:
            clauses.append("stage=?")
            params.append(stage)
        sql = (
            "UPDATE queue SET status=?, next_attempt_at=?, updated_at=?, owner=NULL,"
            f" lease_expires_at=NULL WHERE {' AND '.join(clauses)}"
        )
        async with self._acquire() as conn:
            cur = await conn.cursor()
            try:
                await cur.execute(sql, (OutboxStatus.PENDING.value, now, now, *params))
                count = cur.rowcount
                await conn.commit()
            except Exception:
                await conn.rollback()
                raise
        return int(count)

    async def dead_letter_now(self, outbox_id: str, error: str, now: float | None = None) -> None:
        """Force one row terminal (``DEAD``) immediately — fail-fast, no retry consumed. See the
        :meth:`~messagefoundry.store.base.QueueStore.dead_letter_now` contract."""
        error = safe_text(
            error
        )  # PHI chokepoint (#120) — incl. f"undecryptable payload: {exc}" callers
        now = time.time() if now is None else now
        async with self._acquire() as conn:
            cur = await conn.cursor()
            try:
                await cur.execute(
                    "SELECT message_id, destination_name FROM queue WHERE id=?", (outbox_id,)
                )
                row = await cur.fetchone()
                if row is None:
                    await conn.commit()
                    return
                message_id, destination_name = row[0], row[1]
                await cur.execute(
                    "UPDATE queue SET status=?, next_attempt_at=?, last_error=?, updated_at=?,"
                    " owner=NULL, lease_expires_at=NULL WHERE id=?",
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
        """``(pending_count, oldest_created_at)`` for one lane at ``stage`` (see the protocol). The lane
        key is stage-aware (``destination_name`` outbound, ``channel_id`` ingress/routed)."""
        lane_col = self._lane_col(stage)  # code-controlled literal
        # Route through _fetchone (which commits) so we never return the pooled connection mid read-txn
        # under RCSI (M-6 read hygiene; mirrors postgres.py).
        row = await self._fetchone(
            f"SELECT COUNT(*) AS c, MIN(created_at) AS m FROM queue"
            f" WHERE stage=? AND {lane_col}=? AND status=?",
            (stage, name, OutboxStatus.PENDING.value),
        )
        count = int(row["c"]) if row is not None and row["c"] is not None else 0
        oldest = row["m"] if row is not None else None
        return count, (float(oldest) if oldest is not None else None)

    async def dead_letter_missing_destinations(
        self, valid_names: set[str], now: float | None = None
    ) -> int:
        """Dead-letter non-terminal outbound queue rows whose destination_name is no longer in the
        registry (a removed/renamed outbound) — they have no delivery worker and would strand forever
        (H-5). The per-message finalize applocks are pre-acquired in sorted id order so two concurrent
        multi-message finalizers can't deadlock."""
        now = time.time() if now is None else now
        async with self._acquire() as conn:
            cur = await conn.cursor()
            try:
                await cur.execute(
                    "SELECT id, message_id, destination_name FROM queue"
                    " WHERE stage=? AND status IN (?, ?)",
                    (Stage.OUTBOUND.value, OutboxStatus.PENDING.value, OutboxStatus.INFLIGHT.value),
                )
                rows = await cur.fetchall()  # positional: (id, message_id, destination_name)
                orphans = [r for r in rows if r[2] not in valid_names]
                if not orphans:
                    await conn.commit()  # release the read txn cleanly (M-6)
                    return 0
                error = "destination removed from outbound registry"
                await self._lock_finalize_batch(cur, {r[1] for r in orphans})
                for row in orphans:
                    await cur.execute(
                        "UPDATE queue SET status=?, next_attempt_at=?, last_error=?, updated_at=?,"
                        " owner=NULL, lease_expires_at=NULL WHERE id=?",
                        (OutboxStatus.DEAD.value, now, error, now, row[0]),
                    )
                    await self._event(cur, row[1], "dead", row[2], error, now)
                    await self._maybe_finalize(cur, row[1], now)
                await conn.commit()
            except Exception:
                await conn.rollback()
                raise
        log.warning(
            "dead-lettered %d orphaned outbound row(s) at startup for missing destination(s): %s",
            len(orphans),
            ", ".join(sorted({r[2] for r in orphans})),
        )
        return len(orphans)

    async def replay(self, message_id: str, now: float | None = None) -> int:
        """Re-queue a message's stuck/dead deliveries — or, if none are stuck, re-send the delivered
        ones. Two-mode (M-2): if any row is dead/pending, replay ONLY those (never re-fire a DONE
        sibling); else replay the done rows. messages.status -> RECEIVED if a pending ingress/routed
        row remains (needs re-routing), else ROUTED."""
        now = time.time() if now is None else now
        async with self._acquire() as conn:
            cur = await conn.cursor()
            try:
                await cur.execute(
                    "SELECT COUNT(*) FROM queue WHERE message_id=? AND status IN (?, ?)",
                    (message_id, OutboxStatus.DEAD.value, OutboxStatus.PENDING.value),
                )
                row = await cur.fetchone()
                stuck = int(row[0]) if row and row[0] is not None else 0
                replay_from = (
                    (OutboxStatus.DEAD.value, OutboxStatus.PENDING.value)
                    if stuck
                    else (OutboxStatus.DONE.value,)
                )
                placeholders = ",".join("?" * len(replay_from))
                await cur.execute(
                    f"UPDATE queue SET status=?, attempts=0, next_attempt_at=?, last_error=NULL,"
                    f" updated_at=? WHERE message_id=? AND status IN ({placeholders})",
                    (OutboxStatus.PENDING.value, now, now, message_id, *replay_from),
                )
                count = cur.rowcount
                if (
                    count
                ):  # no rows => errored/filtered/unrouted: don't falsify it or strand it (M-2)
                    await cur.execute(
                        "SELECT 1 FROM queue WHERE message_id=? AND stage IN (?, ?) AND status=?",
                        (
                            message_id,
                            Stage.INGRESS.value,
                            Stage.ROUTED.value,
                            OutboxStatus.PENDING.value,
                        ),
                    )
                    new_status = (
                        MessageStatus.RECEIVED.value
                        if await cur.fetchone()
                        else MessageStatus.ROUTED.value
                    )
                    await cur.execute(
                        "UPDATE messages SET status=?, error=NULL WHERE id=?",
                        (new_status, message_id),
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
        where = ["stage=?", "status=?"]
        params: list[Any] = [Stage.OUTBOUND.value, OutboxStatus.DEAD.value]
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
                    f"SELECT DISTINCT message_id FROM queue WHERE {clause}", tuple(params)
                )
                message_ids = [r[0] for r in await cur.fetchall()]
                if not message_ids:
                    await conn.commit()
                    return 0
                await cur.execute(
                    f"UPDATE queue SET status=?, attempts=0, next_attempt_at=?, last_error=NULL,"
                    f" updated_at=? WHERE {clause}",
                    (OutboxStatus.PENDING.value, now, now, *params),
                )
                count = cur.rowcount
                for message_id in message_ids:
                    await cur.execute(
                        "UPDATE messages SET status=?, error=NULL WHERE id=? AND status=?",
                        (MessageStatus.ROUTED.value, message_id, MessageStatus.ERROR.value),
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
        where = ["stage=?", "destination_name=?", "status=?"]
        params: list[Any] = [Stage.OUTBOUND.value, destination_name, OutboxStatus.PENDING.value]
        if channel_id is not None:
            where.insert(1, "channel_id=?")
            params.insert(1, channel_id)
        top = "TOP (1) " if top_only else ""
        async with self._acquire() as conn:
            cur = await conn.cursor()
            try:
                await cur.execute(
                    f"SELECT {top}id, message_id FROM queue WHERE {' AND '.join(where)}"
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
                    f"UPDATE queue SET status=?, updated_at=? WHERE id IN ({placeholders})",
                    (OutboxStatus.CANCELLED.value, now, *ids),
                )
                for _id, message_id in rows:
                    await self._event(
                        cur, message_id, "cancelled", destination_name, "manual purge", now
                    )
                mids = {r[1] for r in rows}
                await self._lock_finalize_batch(cur, mids)
                for message_id in sorted(mids):
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
            record["summary"] = self._dec(record["summary"])  # EF-3: MRN/name PHI, ciphered at rest
            record["metadata"] = self._dec(record["metadata"])  # EF-3
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
        rows = await self._fetchall(
            "SELECT id, channel_id, received_at, source_type, control_id, message_type,"
            " status, error, summary, metadata,"
            " (SELECT TOP 1 event FROM message_events e WHERE e.message_id = messages.id"
            "  ORDER BY e.id DESC) AS last_event"
            f" FROM messages{where}"
            " ORDER BY received_at DESC, id DESC OFFSET ? ROWS FETCH NEXT ? ROWS ONLY",
            (*params, offset, limit),
        )
        for r in rows:  # EF-3: summary/metadata ciphered at rest
            r["summary"] = self._dec(r["summary"])
            r["metadata"] = self._dec(r["metadata"])
        return rows

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
        rows = await self._fetchall(
            "SELECT o.id AS outbox_id, o.message_id, o.channel_id, o.destination_name,"
            " o.attempts, o.last_error, o.updated_at,"
            " m.control_id, m.message_type, m.received_at, m.summary"
            f" FROM queue o JOIN messages m ON m.id = o.message_id{where}"
            " ORDER BY o.updated_at DESC, o.id DESC OFFSET ? ROWS FETCH NEXT ? ROWS ONLY",
            (*params, offset, limit),
        )
        for r in rows:  # EF-3: summary ciphered at rest
            r["summary"] = self._dec(r["summary"])
        return rows

    async def count_dead(
        self,
        *,
        channel_id: str | None = None,
        destination_name: str | None = None,
        allowed_channels: Sequence[str] | None = None,
    ) -> int:
        where, params = self._dead_filter(channel_id, destination_name, allowed_channels)
        row = await self._fetchone(f"SELECT COUNT(*) AS n FROM queue o{where}", params)
        return int(row["n"]) if row else 0

    @staticmethod
    def _dead_filter(
        channel_id: str | None,
        destination_name: str | None,
        allowed_channels: Sequence[str] | None = None,
    ) -> tuple[str, tuple[Any, ...]]:
        clauses = ["o.stage=?", "o.status=?"]
        params: list[Any] = [Stage.OUTBOUND.value, OutboxStatus.DEAD.value]
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
            "SELECT * FROM queue WHERE message_id=? AND stage=? ORDER BY destination_name",
            (message_id, Stage.OUTBOUND.value),
        )

    async def outbox_payloads_for(self, message_id: str) -> list[dict[str, Any]]:
        """Like :meth:`outbox_for`, but also decrypts the transformed ``payload`` (PHI body) per
        destination for the parity-comparison read path (#14). The outbound ``payload`` column is the
        encrypted body directly (no artifact indirection at this stage — cf. :meth:`claim_ready`); the
        API gates this on ``MESSAGES_VIEW_RAW`` and audits it."""
        rows = await self._fetchall(
            "SELECT * FROM queue WHERE message_id=? AND stage=? ORDER BY destination_name",
            (message_id, Stage.OUTBOUND.value),
        )
        for r in rows:
            r["payload"] = self._cipher.decrypt(r["payload"])
            if r["last_error"] is not None:
                r["last_error"] = self._cipher.decrypt(r["last_error"])
        return rows

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
        # Serialize the read-prev-then-insert append in-process so two concurrent audited actions can't
        # read the same prev hash and FORK the hash chain (H-7). The store is the single audit writer
        # per engine process (active-passive = one active node), so an in-process lock is sufficient and
        # reliable — unlike a txn-scoped sp_getapplock taken as the connection's first statement, which
        # does not release on commit and strands under concurrent contention.
        async with self._audit_lock:
            async with self._acquire() as conn:
                cur = await conn.cursor()
                try:
                    await cur.execute("SELECT TOP (1) row_hash FROM audit_log ORDER BY id DESC")
                    last = await cur.fetchone()
                    prev = last[0] if last and last[0] else ""
                    row_hash = audit_row_hash(
                        prev,
                        ts=now,
                        actor=actor,
                        action=action,
                        channel_id=channel_id,
                        detail=detail,
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
        # Tee off-box AFTER commit + outside the audit lock / pooled connection (only forward what
        # truly persisted; a synchronous syslog send must never hold the lock). Shared redaction path.
        emit_audit_tee(action=action, actor=actor, channel_id=channel_id, detail=detail, ts=now)

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

    async def security_events_for_user(
        self, username: str, *, limit: int = 100
    ) -> list[dict[str, Any]]:
        """A user's own security events (``auth.*``), most-recent-first — for ``GET
        /me/security-events`` (ASVS 6.3.5/6.3.7); admin-initiated changes go out-of-band by email."""
        return await self._fetchall(
            "SELECT TOP (?) ts, action, detail FROM audit_log "
            "WHERE actor = ? AND action LIKE 'auth.%' ORDER BY id DESC",
            (limit, username),
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
            "VALUES (?,?,?,?,?,'pending',?)",
            (approval_id, operation, params, requester, requested_at, expires_at),
        )

    async def get_pending_approval(self, approval_id: str) -> dict[str, Any] | None:
        return await self._fetchone(
            "SELECT id, operation, params, requester, requested_at, status, approver, decided_at,"
            " expires_at FROM pending_approvals WHERE id = ?",
            (approval_id,),
        )

    async def list_pending_approvals(self, *, now: float, limit: int = 100) -> list[dict[str, Any]]:
        """Open (still-``pending``, unexpired) approval requests, newest-first."""
        return await self._fetchall(
            "SELECT TOP (?) id, operation, params, requester, requested_at, status, approver,"
            " decided_at, expires_at FROM pending_approvals"
            " WHERE status = 'pending' AND (expires_at IS NULL OR expires_at > ?)"
            " ORDER BY requested_at DESC",
            (limit, now),
        )

    async def decide_pending_approval(
        self, approval_id: str, *, status: str, approver: str | None, decided_at: float
    ) -> bool:
        """Atomically move a still-``pending`` request to ``status`` (approved/rejected/expired).
        Returns ``True`` iff this call made the transition — guards against a double decision."""
        async with self._acquire() as conn:
            cur = await conn.cursor()
            try:
                await cur.execute(
                    "UPDATE pending_approvals SET status = ?, approver = ?, decided_at = ?"
                    " WHERE id = ? AND status = 'pending'",
                    (status, approver, decided_at, approval_id),
                )
                count = cur.rowcount
                await conn.commit()
            except Exception:
                await conn.rollback()
                raise
        return int(count) > 0

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

    # --- MFA: native TOTP second factor (local accounts, WP-14) --------------

    async def set_totp_secret(
        self, user_id: str, *, secret: str | None, now: float | None = None
    ) -> None:
        """Stage (or clear) a user's base32 TOTP secret, store-cipher encrypted. Does not enable MFA."""
        now = time.time() if now is None else now
        enc = self._cipher.encrypt(secret) if secret else None
        await self._execute(
            "UPDATE users SET totp_secret=?, updated_at=? WHERE id=?", (enc, now, user_id)
        )

    async def get_totp_secret(self, user_id: str) -> str | None:
        d = await self._fetchone("SELECT totp_secret FROM users WHERE id=?", (user_id,))
        if not d or d["totp_secret"] is None:
            return None
        return self._cipher.decrypt(d["totp_secret"])

    async def enable_totp(
        self, user_id: str, *, recovery_code_hashes: list[str], now: float | None = None
    ) -> None:
        now = time.time() if now is None else now
        await self._execute(
            "UPDATE users SET totp_enabled=1, totp_enrolled_at=?, totp_recovery_codes=?,"
            " updated_at=? WHERE id=?",
            (now, json.dumps(recovery_code_hashes), now, user_id),
        )

    async def disable_totp(self, user_id: str, *, now: float | None = None) -> None:
        now = time.time() if now is None else now
        await self._execute(
            "UPDATE users SET totp_secret=NULL, totp_enabled=0, totp_enrolled_at=NULL,"
            " totp_recovery_codes=NULL, updated_at=? WHERE id=?",
            (now, user_id),
        )

    async def get_recovery_code_hashes(self, user_id: str) -> list[str]:
        d = await self._fetchone("SELECT totp_recovery_codes FROM users WHERE id=?", (user_id,))
        if not d or d["totp_recovery_codes"] is None:
            return []
        return [str(h) for h in json.loads(d["totp_recovery_codes"])]

    async def consume_recovery_code_hash(
        self, user_id: str, code_hash: str, *, now: float | None = None
    ) -> bool:
        """Atomically remove one recovery-code hash; ``True`` iff present. The ``UPDLOCK`` SELECT +
        UPDATE run in one transaction, so concurrent verifications can't double-spend a single-use
        recovery code (WP-14)."""
        now = time.time() if now is None else now
        async with self._acquire() as conn:
            cur = await conn.cursor()
            try:
                await cur.execute(
                    "SELECT totp_recovery_codes FROM users WITH (UPDLOCK, ROWLOCK) WHERE id=?",
                    (user_id,),
                )
                row = await cur.fetchone()
                raw = row[0] if row else None
                if raw is None:
                    await conn.commit()
                    return False
                hashes = [str(h) for h in json.loads(raw)]
                if code_hash not in hashes:
                    await conn.commit()
                    return False  # already consumed by a concurrent caller
                hashes.remove(code_hash)
                await cur.execute(
                    "UPDATE users SET totp_recovery_codes=?, updated_at=? WHERE id=?",
                    (json.dumps(hashes), now, user_id),
                )
                await conn.commit()
                return True
            except Exception:
                await conn.rollback()
                raise

    async def consume_totp_step(self, user_id: str, step: int) -> bool:
        """Atomically record ``step`` as the user's highest consumed TOTP time-step; ``True`` iff newly
        consumed (strictly greater than any prior step). A code replayed inside its ±1-step verify
        window resolves to a non-greater step and returns ``False`` — single-use per ASVS 6.5.1. The
        ``UPDLOCK`` SELECT + UPDATE run in one transaction so concurrent verifications can't both win."""
        async with self._acquire() as conn:
            cur = await conn.cursor()
            try:
                await cur.execute(
                    "SELECT last_totp_step FROM users WITH (UPDLOCK, ROWLOCK) WHERE id=?",
                    (user_id,),
                )
                row = await cur.fetchone()
                if row is None:
                    await conn.commit()
                    return False
                last = row[0]
                if last is not None and last >= step:
                    await conn.commit()
                    return False  # already consumed (or an older step) — replay within the window
                await cur.execute("UPDATE users SET last_totp_step=? WHERE id=?", (step, user_id))
                await conn.commit()
                return True
            except Exception:
                await conn.rollback()
                raise

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
        # Single atomic MERGE under HOLDLOCK (range-locks the key) so two concurrent seeders can't both
        # find the row absent and both INSERT the same PK -> violation (the UPDATE-then-INSERT race).
        await self._execute(
            "MERGE roles WITH (HOLDLOCK) AS t"
            " USING (SELECT ? AS id, ? AS display_name, ? AS description, ? AS builtin) AS s"
            " ON t.id=s.id"
            " WHEN MATCHED THEN UPDATE SET display_name=s.display_name,"
            " description=s.description, builtin=s.builtin"
            " WHEN NOT MATCHED THEN INSERT (id, display_name, description, builtin)"
            " VALUES (s.id, s.display_name, s.description, s.builtin);",
            (role_id, display_name, description, 1 if builtin else 0),
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
        seed_reauth: bool = True,
        now: float | None = None,
    ) -> None:
        now = time.time() if now is None else now
        await self._execute(
            # reauth_at seeds the step-up window from login (ASVS 7.5.3); seed_reauth=False leaves it
            # NULL for an MFA-PENDING session (WP-14) so a stolen pre-MFA token can't enroll/step-up.
            "INSERT INTO sessions (token_hash, user_id, created_at, expires_at, last_used_at,"
            " revoked_at, client, reauth_at) VALUES (?,?,?,?,?,NULL,?,?)",
            (token_hash, user_id, now, expires_at, now, client, now if seed_reauth else None),
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

    async def mark_session_reauthed(
        self, token_hash: str, *, now: float | None = None, client: str | None = None
    ) -> None:
        now = time.time() if now is None else now
        # COALESCE keeps the stored client when none is supplied; a re-verify carrying the current
        # address re-anchors the session to it (WP-L3-13 new-client-IP step-up).
        await self._execute(
            "UPDATE sessions SET reauth_at=?, client=COALESCE(?, client) WHERE token_hash=?",
            (now, client, token_hash),
        )

    async def mark_session_mfa_verified(self, token_hash: str, *, now: float | None = None) -> None:
        now = time.time() if now is None else now
        await self._execute(
            "UPDATE sessions SET mfa_verified_at=? WHERE token_hash=?", (now, token_hash)
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
        rows = await self._fetchall(
            "SELECT status, COUNT(*) AS n FROM queue WHERE stage=? GROUP BY status",
            (Stage.OUTBOUND.value,),
        )
        return {r["status"]: int(r["n"]) for r in rows}

    async def in_pipeline_depth(self) -> int:
        rows = await self._fetchall(
            "SELECT COUNT(*) AS n FROM queue WHERE stage IN (?,?,?) AND status IN (?,?)",
            (
                Stage.INGRESS.value,
                Stage.ROUTED.value,
                Stage.OUTBOUND.value,
                OutboxStatus.PENDING.value,
                OutboxStatus.INFLIGHT.value,
            ),
        )
        return int(rows[0]["n"]) if rows else 0

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
            " FROM queue WHERE stage=? GROUP BY channel_id, destination_name",
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
                Stage.OUTBOUND.value,
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

    async def delivery_latency_histogram(
        self, *, buckets: Sequence[float], now: float | None = None
    ) -> Sequence[LatencyHistogram]:
        """Per-(channel_id, destination_name) delivery-latency histogram over outbound rows that
        reached status='done'. Latency = updated_at - created_at (seconds), clamped to >= 0 (clock-
        skew guard). bucket_counts are CUMULATIVE (Prometheus le semantics). Read-only; runs off the
        event loop."""
        # Only the NUMBER of CASE clauses (len(buckets)) is generated; each boundary is a BOUND
        # parameter (never string-interpolated), so this is injection-safe.
        bucket_cols = ", ".join(
            f"SUM(CASE WHEN (updated_at - created_at) <= ? THEN 1 ELSE 0 END) AS b{i}"
            for i in range(len(buckets))
        )
        select_cols = f"{bucket_cols}, " if bucket_cols else ""
        sql = (
            "SELECT channel_id, destination_name, "
            f"{select_cols}"
            "SUM(CASE WHEN updated_at >= created_at THEN updated_at - created_at ELSE 0 END)"
            " AS sum_seconds,"
            " COUNT(*) AS cnt"
            " FROM queue WHERE stage=? AND status=?"
            " GROUP BY channel_id, destination_name"
            " ORDER BY channel_id, destination_name"
        )
        params: tuple[Any, ...] = (*buckets, Stage.OUTBOUND.value, OutboxStatus.DONE.value)
        rows = await self._fetchall(sql, params)
        return [
            LatencyHistogram(
                channel_id=r["channel_id"],
                destination_name=r["destination_name"],
                bucket_counts=tuple(int(r[f"b{i}"] or 0) for i in range(len(buckets))),
                sum_seconds=float(r["sum_seconds"] or 0),
                count=int(r["cnt"] or 0),
            )
            for r in rows
        ]
