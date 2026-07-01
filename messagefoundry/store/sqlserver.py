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
from time import perf_counter
from types import MappingProxyType
from typing import Any
from uuid import uuid4

from messagefoundry.config.models import RetryPolicy
from messagefoundry.config.settings import (
    INSECURE_TLS_ESCAPE_ENV,
    SqlAuth,
    StoreBackend,
    StoreSettings,
    insecure_tls_allowed,
)
from messagefoundry.parsing.binary import strip_documents as _strip_documents
from messagefoundry.redaction import safe_text
from messagefoundry.store.audit_tee import emit_audit_tee
from messagefoundry.store.base import warm_pool_connections, warm_pool_target
from messagefoundry.store.content_search import SearchSpec, row_matches
from messagefoundry.store.crypto import MARKER_PREFIX as _ENC_MARKER_PREFIX
from messagefoundry.store.crypto import (
    AesGcmCipher,
    Cipher,
    CipherError,
    CipherInfo,
    IdentityCipher,
    cipher_info,
)
from messagefoundry.store.document_strip import StripResult, cutoff_for
from messagefoundry.store.pool_metrics import AcquireWaitHistogram, PoolStatus
from messagefoundry.store.store import (
    AlertInstance,
    ConnectionEvent,
    ConnectionMetrics,
    DbStatus,
    DestinationMetrics,
    InboundMetrics,
    LatencyHistogram,
    CapturedResponse,
    MessageSearchResult,
    MessageStatus,
    MessageStore,
    OutboxItem,
    OutboxStatus,
    SessionRecord,
    Stage,
    UserRecord,
    _append_channel_scope,
    _qmark_cutoff_case,
    audit_row_hash,
    delivery_key,
)

log = logging.getLogger(__name__)

# Schema (T-SQL). Idempotent: guarded by OBJECT_ID / IndexProperty so re-open is a no-op. Epoch
# timestamps are FLOAT; ids are NVARCHAR(64) (uuid4 hex); bodies NVARCHAR(MAX).
#
# Schema-init is serialized across concurrent opens by this named applock (the T-SQL analog of the
# Postgres store's ``pg_advisory_xact_lock("mefor_schema_init")`` — store/postgres.py). The OBJECT_ID
# guards below are check-then-create and do NOT serialize concurrent creators on a virgin DB — see
# _ensure_schema.
_SCHEMA_LOCK = "mefor:schema_init"
_SCHEMA: list[str] = [
    """IF OBJECT_ID('messages','U') IS NULL CREATE TABLE messages (
        id NVARCHAR(64) NOT NULL PRIMARY KEY, channel_id NVARCHAR(256) NOT NULL,
        received_at FLOAT NOT NULL, source_type NVARCHAR(64) NULL, control_id NVARCHAR(256) NULL,
        message_type NVARCHAR(64) NULL, raw NVARCHAR(MAX) NOT NULL, status NVARCHAR(32) NOT NULL,
        error NVARCHAR(MAX) NULL, summary NVARCHAR(MAX) NULL, metadata NVARCHAR(MAX) NULL,
        documents_pruned FLOAT NULL)""",
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
        handler_name NVARCHAR(256) NULL, payload NVARCHAR(MAX) NOT NULL, body_ref NVARCHAR(64) NULL,
        status NVARCHAR(32) NOT NULL,
        attempts INT NOT NULL DEFAULT 0, next_attempt_at FLOAT NOT NULL, last_error NVARCHAR(MAX) NULL,
        owner NVARCHAR(256) NULL, lease_expires_at FLOAT NULL,
        created_at FLOAT NOT NULL, updated_at FLOAT NOT NULL,
        CONSTRAINT fk_queue_message FOREIGN KEY (message_id) REFERENCES messages(id))""",
    # Store-once-deliver-many (L2b): the single shared copy of a body fanned out to N destinations.
    # SCHEMA PARITY here — SQLite implements the dedup/deref/GC; on SQL Server body_ref stays NULL today
    # (bodies inline, byte-identical), a follow-up wires insert/deref/GC without a second migration.
    """IF OBJECT_ID('shared_body','U') IS NULL CREATE TABLE shared_body (
        hash NVARCHAR(64) NOT NULL PRIMARY KEY, body NVARCHAR(MAX) NOT NULL,
        refcount INT NOT NULL, created_at FLOAT NOT NULL)""",
    """IF INDEXPROPERTY(OBJECT_ID('queue'),'ix_queue_ready','IndexID') IS NULL
        CREATE INDEX ix_queue_ready ON queue(stage, status, next_attempt_at)""",
    """IF INDEXPROPERTY(OBJECT_ID('queue'),'ix_queue_message','IndexID') IS NULL
        CREATE INDEX ix_queue_message ON queue(message_id)""",
    # FIFO covering indexes trail in `seq` alone (seq-only per-lane FIFO, ADR 0059) so the claim's
    # `... ORDER BY seq` is an index-ordered scan, NOT a sort. `created_at` was dropped from the key.
    # ADR 0060: the seq-trailing index is named ix_queue_fifo_*_seq (distinct from the old created_at-
    # trailing ix_queue_fifo_*), so an upgraded DB DROPs the stale old-named index and CREATEs the new
    # one under a name that name-existence guards tell apart. DROP-old then CREATE-new, all inside this
    # applock-serialized _SCHEMA batch → one atomic commit. (The batch's per-statement command timeout is
    # exempted in _ensure_schema so a large first-upgrade rebuild can't be killed → crash-loop startup.)
    """IF INDEXPROPERTY(OBJECT_ID('queue'),'ix_queue_fifo_out','IndexID') IS NOT NULL
        DROP INDEX ix_queue_fifo_out ON queue""",
    """IF INDEXPROPERTY(OBJECT_ID('queue'),'ix_queue_fifo_out_seq','IndexID') IS NULL
        CREATE INDEX ix_queue_fifo_out_seq ON queue(stage, destination_name, status, seq)""",
    """IF INDEXPROPERTY(OBJECT_ID('queue'),'ix_queue_fifo_in','IndexID') IS NOT NULL
        DROP INDEX ix_queue_fifo_in ON queue""",
    """IF INDEXPROPERTY(OBJECT_ID('queue'),'ix_queue_fifo_in_seq','IndexID') IS NULL
        CREATE INDEX ix_queue_fifo_in_seq ON queue(stage, channel_id, status, seq)""",
    # LOCK_ESCALATION=DISABLE: `queue` is a hot multi-writer table; a depth-triggered escalation to a
    # TABLE X lock during a deep startup orphan sweep would block ALL claim/handoff workers. Degrade a
    # deep sweep to many row locks under RCSI instead. Idempotent (re-running re-sets the same option).
    # IF-guarded (like the indexes) so it fires at most once — a bare ALTER on every open() takes a
    # Sch-M lock on the hot queue table (review). lock_escalation 2 = DISABLE.
    """IF (SELECT lock_escalation FROM sys.tables WHERE object_id=OBJECT_ID('queue')) <> 2
        ALTER TABLE queue SET (LOCK_ESCALATION = DISABLE)""",
    # #47/ADR 0042: messages.documents_pruned (the "embedded doc evicted vs never present" flag). NULL on
    # existing rows = never pruned; COL_LENGTH-gated like the others so a re-open is a no-op.
    """IF COL_LENGTH('messages','documents_pruned') IS NULL
        ALTER TABLE messages ADD documents_pruned FLOAT NULL""",
    # Store-once-deliver-many (L2b): body_ref on a pre-existing queue (NULL = body inline, byte-identical).
    """IF COL_LENGTH('queue','body_ref') IS NULL
        ALTER TABLE queue ADD body_ref NVARCHAR(64) NULL""",
    # The body_ref index is created AFTER the ALTER above so a pre-existing queue (no body_ref) doesn't
    # reference a not-yet-added column. Separate batch (the ALTER must commit first on SQL Server).
    """IF INDEXPROPERTY(OBJECT_ID('queue'),'ix_queue_body_ref','IndexID') IS NULL
        CREATE INDEX ix_queue_body_ref ON queue(body_ref)""",
    """IF OBJECT_ID('message_events','U') IS NULL CREATE TABLE message_events (
        id INT IDENTITY(1,1) PRIMARY KEY, message_id NVARCHAR(64) NOT NULL, ts FLOAT NOT NULL,
        event NVARCHAR(64) NOT NULL, destination NVARCHAR(256) NULL, detail NVARCHAR(MAX) NULL)""",
    """IF INDEXPROPERTY(OBJECT_ID('message_events'),'ix_events_message','IndexID') IS NULL
        CREATE INDEX ix_events_message ON message_events(message_id, ts)""",
    # Connection/transport event log (Corepoint-style #46) — METADATA-ONLY: inbound lifecycle +
    # pre-ingress failures + outbound lane transitions. id-keyed BIGINT IDENTITY (NOT a queue stage →
    # invisible to the finalizer's `FROM queue` scan); message_id is NULLABLE with NO FK (correlation
    # hint only). reason is safe_text-scrubbed and CIPHERED at rest (rides the id-keyed nullable cipher
    # loop, like message_events.detail — H4 retired the prior plaintext residual, so reason is encrypted
    # here too, NOT plaintext as the stale ADR 0021 §7.5 directs).
    """IF OBJECT_ID('connection_event','U') IS NULL CREATE TABLE connection_event (
        id BIGINT IDENTITY(1,1) PRIMARY KEY, ts FLOAT NOT NULL,
        connection NVARCHAR(256) NOT NULL, transport NVARCHAR(64) NOT NULL,
        direction NVARCHAR(16) NOT NULL, kind NVARCHAR(64) NOT NULL,
        peer_host NVARCHAR(256) NULL, message_id NVARCHAR(64) NULL, reason NVARCHAR(MAX) NULL)""",
    """IF INDEXPROPERTY(OBJECT_ID('connection_event'),'ix_connection_event_conn','IndexID') IS NULL
        CREATE INDEX ix_connection_event_conn ON connection_event(connection, ts)""",
    # Operator alert-state (ADR 0044, #56) — resolvable alert INSTANCES (open/acknowledged/resolved +
    # first/last_seen + count). METADATA-ONLY: type/connection/severity/scrubbed reason (CIPHERED at rest,
    # rides the id-keyed nullable cipher loop, like connection_event.reason). De-duped on ADR 0014's
    # (event_type, connection) throttle key via the FILTERED unique index (one LIVE instance per key;
    # resolved rows drop out so the key re-opens). id-keyed BIGINT IDENTITY (NOT a queue stage → invisible
    # to the finalizer's `FROM queue` scan). count is [count] (reserved-ish; bracket-quoted for parity).
    """IF OBJECT_ID('alert_instance','U') IS NULL CREATE TABLE alert_instance (
        id BIGINT IDENTITY(1,1) PRIMARY KEY, event_type NVARCHAR(64) NOT NULL,
        connection NVARCHAR(256) NOT NULL, severity NVARCHAR(16) NOT NULL,
        status NVARCHAR(16) NOT NULL, first_seen FLOAT NOT NULL, last_seen FLOAT NOT NULL,
        [count] BIGINT NOT NULL, reason NVARCHAR(MAX) NULL, acked_by NVARCHAR(256) NULL,
        acked_at FLOAT NULL, resolved_at FLOAT NULL)""",
    """IF INDEXPROPERTY(OBJECT_ID('alert_instance'),'ux_alert_instance_open','IndexID') IS NULL
        CREATE UNIQUE INDEX ux_alert_instance_open ON alert_instance(event_type, connection)
        WHERE status <> 'resolved'""",
    """IF INDEXPROPERTY(OBJECT_ID('alert_instance'),'ix_alert_instance_status','IndexID') IS NULL
        CREATE INDEX ix_alert_instance_status ON alert_instance(status, connection)""",
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
        description NVARCHAR(512) NULL, builtin BIT NOT NULL DEFAULT 1,
        permissions NVARCHAR(MAX) NULL)""",
    # Custom RBAC roles (ADR 0045): roles.permissions on a pre-existing DB. COL_LENGTH-gated; NULL on
    # existing built-in rows = resolves from code (byte-identical). Idempotent.
    """IF COL_LENGTH('roles','permissions') IS NULL
        ALTER TABLE roles ADD permissions NVARCHAR(MAX) NULL""",
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
    # plaintext. As of H4, queue.last_error, messages.error and message_events.detail are ALSO ciphered
    # at rest on this backend — full at-rest parity with SQLite/Postgres. Those columns still go through
    # the safe_exc/safe_text PHI chokepoint (record_received / mark_failed / dead_letter_now / _event) so
    # HL7-shaped content can't land in the first place, AND are now encrypted around that scrub (the prior
    # "plaintext residual" is retired). On read they gate on messages:view_summary. (Distinct from those
    # detail-class columns, messages.summary/metadata — direct MRN + patient name — are ciphered too, EF-3.)
    """IF OBJECT_ID('response','U') IS NULL CREATE TABLE response (
        message_id NVARCHAR(64) NOT NULL, destination_name NVARCHAR(256) NOT NULL,
        response_seq INT NOT NULL, body NVARCHAR(MAX) NULL, outcome NVARCHAR(64) NOT NULL,
        detail NVARCHAR(MAX) NULL, captured_at FLOAT NOT NULL,
        kind NVARCHAR(32) NOT NULL CONSTRAINT df_response_kind DEFAULT 'response',
        ack_code NVARCHAR(8) NULL, ack_phase NVARCHAR(16) NULL,
        CONSTRAINT pk_response PRIMARY KEY (message_id, destination_name, response_seq),
        CONSTRAINT fk_response_message FOREIGN KEY (message_id) REFERENCES messages(id))""",
    """IF INDEXPROPERTY(OBJECT_ID('response'),'ix_response_message','IndexID') IS NULL
        CREATE INDEX ix_response_message ON response(message_id)""",
    # ADR 0021 "Response Sent" columns on a pre-existing response table. Adding NOT NULL `kind` with a
    # CONSTANT default is metadata-only (no rewrite) on SQL Server 2016+ (CI 2022); a migration-timing
    # test on a pre-populated table guards this, with a batched NULLable-add → backfill → SET NOT NULL
    # fallback if any rewrite is observed. Mutually exclusive with the fresh CREATE above (one per DB).
    """IF COL_LENGTH('response','kind') IS NULL
        ALTER TABLE response ADD kind NVARCHAR(32) NOT NULL CONSTRAINT df_response_kind DEFAULT 'response'""",
    """IF COL_LENGTH('response','ack_code') IS NULL ALTER TABLE response ADD ack_code NVARCHAR(8) NULL""",
    """IF COL_LENGTH('response','ack_phase') IS NULL ALTER TABLE response ADD ack_phase NVARCHAR(16) NULL""",
    # Outbound idempotency ledger (H2) — one row per COMPLETED delivery, INSERTed in the SAME txn as the
    # outbound row's mark_done / complete_with_response. delivery_key = sha256 of non-PHI ids + a replay-
    # stable seq (delivery_key()); outbox_id is the queue row that delivered, the FIFO claim's
    # skip-and-complete dedup key. HASHES + IDS ONLY — no body/PHI — so it is NOT ciphered at rest.
    """IF OBJECT_ID('delivered_keys','U') IS NULL CREATE TABLE delivered_keys (
        delivery_key NVARCHAR(64) NOT NULL PRIMARY KEY, outbox_id NVARCHAR(64) NOT NULL,
        message_id NVARCHAR(64) NOT NULL, destination_name NVARCHAR(256) NOT NULL,
        delivery_seq INT NOT NULL, delivered_at FLOAT NOT NULL)""",
    """IF INDEXPROPERTY(OBJECT_ID('delivered_keys'),'ix_delivered_outbox','IndexID') IS NULL
        CREATE INDEX ix_delivered_outbox ON delivered_keys(outbox_id)""",
    """IF INDEXPROPERTY(OBJECT_ID('delivered_keys'),'ix_delivered_message','IndexID') IS NULL
        CREATE INDEX ix_delivered_message ON delivered_keys(message_id, destination_name)""",
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

    # Pass-through (PT) re-ingress (the `pt_deliveries` branch of transform_handoff, ADR 0013
    # generalized) is implemented at full SQLite parity: the atomic PT-child + parent-marker branch runs
    # inside transform_handoff's transaction (see _insert_passthrough_child_mssql / _insert_passthrough_
    # marker_mssql). A graph with a PT inbound is therefore accepted at engine startup on this backend.
    supports_pt_reingress = True
    backend = StoreBackend.SQLSERVER

    def __init__(self, pool: Any, settings: StoreSettings, *, cipher: Cipher | None = None) -> None:
        self._pool = pool
        self._settings = settings
        self._cipher: Cipher = cipher or IdentityCipher()
        self.path = f"{settings.server}/{settings.database}"  # descriptor for db_status
        # B11 connection-scale observability: a perf_counter-measured histogram of how long each
        # pooled-connection acquire() WAITS — the PRIMARY pool-wait wall signal (it grows monotonically
        # with worker contention once the pool saturates, where occupancy can't). Recorded on the single
        # _acquire() chokepoint below; read-only/additive, surfaced via pool_status() → the server-only
        # /status `pool` field; default-empty (all zeros) when nothing has contended.
        self._acquire_wait = AcquireWaitHistogram()
        # ADR 0005 transform-state read-through cache (parity with SQLite/PG): loaded at open, updated
        # post-commit by transform_handoff, surfaced via state_view() so a Handler's cross-message
        # state_get(...) resolves in-process.
        self._state_cache: dict[tuple[str, str], Any] = {}
        # Serializes audit-chain appends in-process (the store is the single audit writer per engine
        # process; active-passive = one active node) — see record_audit.
        self._audit_lock = asyncio.Lock()
        # H1 fencing token: the held leader epoch + the leader_lease row to validate it against, pushed
        # by the engine on promotion via set_leader_epoch() (the store NEVER imports the coordinator —
        # ARCH-6). None disables the claim's epoch guard, keeping claim_next_fifo byte-identical to pre-H1.
        self._leader_epoch: int | None = None
        self._lease_key: str | None = None

    # --- PHI-at-rest cipher seam for nullable text columns (mirrors MessageStore._enc/_dec) -----
    # Used for summary/metadata (EF-3) and error/last_error/event.detail (H4). null/empty-safe: a NULL
    # or purged '' stays as-is, never turns into ciphertext-of-empty; decrypt passes legacy plaintext /
    # '' through unchanged on read (so a no-key -> key restart reads pre-existing plaintext correctly).

    def _enc(self, value: str | None) -> str | None:
        if not value:  # None or "" → leave blank (covers purged/empty values)
            return value
        return self._cipher.encrypt(value)

    def _dec(self, value: str | None) -> str | None:
        if value is None:
            return value
        return self._cipher.decrypt(value)  # '' and legacy plaintext pass through unchanged

    def cipher_info(self) -> CipherInfo:
        """The non-secret at-rest cipher posture (M5): on/off + key fingerprint, never key bytes."""
        return cipher_info(self._cipher)

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
            async with self._acquire() as conn, self._cursor(conn) as cur:
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
        # Version-agnostic anchor (M9): `mfenc:%` matches BOTH v1 and v2 ciphertext, so a v2 row is
        # recognised as already-encrypted and skipped — never re-wrapped.
        like = f"{_ENC_MARKER_PREFIX}%"
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
                async with self._acquire() as conn, self._cursor(conn) as cur:
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
        # Nullable id-keyed PHI text columns — each migrated on its own pass with the nullable
        # `<> '' AND IS NOT NULL` guard so a blank/purged '' is never turned into ciphertext-of-empty
        # (the id-keyed loop above omits that guard because raw/payload are never legitimately '').
        #   messages.summary/metadata (id PK) — MRN + patient name (EF-3).
        #   messages.error / queue.last_error / message_events.detail (H4) — may embed raw HL7 fragments
        #     from exceptions; SQL Server at-rest parity with SQLite/Postgres. message_events keys on its
        #     own INT IDENTITY `id` (an integer literal in the UPDATE, like every other id-keyed table).
        for table, ncol in (
            ("messages", "summary"),
            ("messages", "metadata"),
            ("messages", "error"),
            ("queue", "last_error"),
            ("message_events", "detail"),
            ("connection_event", "reason"),  # #46: id-keyed (BIGINT IDENTITY), nullable — H4 parity
            ("alert_instance", "reason"),  # #56 (ADR 0044): id-keyed (BIGINT IDENTITY), nullable
        ):
            while True:
                rows = await self._fetchall(
                    f"SELECT TOP (500) id, {ncol} AS v FROM {table}"
                    f" WHERE {ncol} NOT LIKE ? AND {ncol} <> '' AND {ncol} IS NOT NULL",
                    (like,),
                )
                if not rows:
                    break
                async with self._acquire() as conn, self._cursor(conn) as cur:
                    try:
                        for r in rows:
                            await cur.execute(
                                f"UPDATE {table} SET {ncol}=? WHERE id=?",
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
                async with self._acquire() as conn, self._cursor(conn) as cur:
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
            # Standalone one-shot connection (NOT pooled) — `conn.close()` in the finally below frees
            # the cursor with it, so this site is exempt from the EF-6 pool-bleed race that `_cursor`
            # guards against on the pooled paths.
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
        async with self._acquire() as conn, self._cursor(conn) as cur:
            try:
                # B10/ADR 0060: exempt the schema DDL from the per-statement command timeout. The first-
                # upgrade FIFO index rebuild (DROP old + CREATE ix_queue_fifo_*_seq) over a large backlog
                # can exceed command_timeout (30s default); being killed mid-CREATE would roll back this
                # batch and re-fail on every restart — a startup crash-loop. raw.timeout=0 = no client
                # statement timeout for this connection; _acquire re-applies command_timeout on the next
                # borrow, so no restore is needed. (sp_getapplock below keeps its own server-side
                # @LockTimeout from command_timeout, so a peer's in-progress migration still bounds the
                # lock wait rather than hanging.)
                raw = getattr(conn, "_conn", None)
                if raw is not None:
                    raw.timeout = 0
                # Serialize schema-init across concurrent opens (e.g. a 2-node HA cold start against a
                # virgin DB) — the T-SQL analog of the Postgres store's schema advisory lock. Without it
                # the `IF OBJECT_ID(...) IS NULL CREATE` guards below are check-then-create: two nodes
                # both see NULL and both CREATE, and the loser dies on a 2714 "There is already an object
                # named ...". The applock is transaction-scoped (the autocommit=False pool means this
                # first statement opens the txn), so it auto-releases on the commit/rollback below; the
                # second node then runs the now-no-op guarded CREATEs cleanly.
                await self._applock(cur, _SCHEMA_LOCK)
                for statement in _SCHEMA:
                    await cur.execute(statement)
                await conn.commit()
            except Exception:
                await conn.rollback()  # roll back the partial DDL batch (M-6)
                raise

    async def close(self) -> None:
        self._pool.close()
        await self._pool.wait_closed()

    async def warm_pool(self) -> None:
        # Pre-open pooled ODBC connections so the post-promotion delivery burst (or a cold start) doesn't
        # pay cold connects (TCP + TLS + SQL login — the 340-958 ms acquires the dogfood box measured
        # stretching failover recovery) on the hot path. Gated by [store].warm_pool; the target is capped
        # so a warm never pins more than half the pool, leaving slots for the concurrent startup work
        # (reset_stale_inflight / reference materialize / the coordinator). See QueueStore.warm_pool.
        if not self._settings.warm_pool:
            return
        warmed = await warm_pool_connections(
            self._pool,
            target=warm_pool_target(self._pool.maxsize, self._settings.warm_pool_target),
            timeout=self._settings.warm_pool_timeout,
            backend="sqlserver",
        )
        if warmed:
            log.info("sqlserver: pre-warmed %d pooled connection(s)", warmed)

    # --- helpers -------------------------------------------------------------

    @asynccontextmanager
    async def _acquire(self) -> AsyncIterator[Any]:
        """Acquire a pooled connection with the configured command (statement) timeout applied.

        ``Connection Timeout`` in the DSN is only the *login* timeout; the per-statement timeout is a
        pyodbc **connection** attribute (STORE-3). aioodbc's wrapper exposes ``timeout`` read-only, so
        we set it on the underlying ``pyodbc.Connection`` (``_conn``); aioodbc 0.5.0 has no creation
        hook (``after_created``), so we apply it per-acquire (an idempotent int assignment). The prior
        ``conn.timeout = ...`` raised AttributeError and was silently swallowed, so no statement
        timeout was ever applied — a hung statement then held its queue/messages row X-locks forever.

        B11: the perf_counter pair records the acquire WAIT time (the PRIMARY pool-wait wall signal)
        into the acquire-wait histogram. Every store DB call funnels through here (the single _acquire
        chokepoint), so the connection-scale harness sees how long the per-lane workers wait for a
        pooled connection as the pool saturates. Read-only/additive — the timing never changes the
        acquired connection or its release."""
        t0 = perf_counter()
        async with self._pool.acquire() as conn:
            self._acquire_wait.record((perf_counter() - t0) * 1000.0)
            raw = getattr(conn, "_conn", None)
            if raw is not None:
                raw.timeout = self._settings.command_timeout  # seconds; 0 = no limit
            yield conn

    def pool_status(self) -> PoolStatus | None:
        """The aioodbc pool snapshot (B11): size/idle occupancy + the PRIMARY acquire-wait percentiles.

        ``size``/``freesize`` are the aioodbc ``Pool`` properties (verified against the pinned
        ``aioodbc==0.5.0``): ``size`` is the connections currently open, ``freesize`` the currently-free
        ones. Synchronous + cheap (cached counters + an in-process histogram snapshot — no DB
        round-trip)."""
        return PoolStatus(
            backend="sqlserver",
            max_size=self._pool.maxsize,
            size=self._pool.size,
            idle=self._pool.freesize,
            acquire_wait=self._acquire_wait.summary(),
        )

    @asynccontextmanager
    async def _cursor(self, conn: Any) -> AsyncIterator[Any]:
        """Yield a cursor that is ALWAYS closed before its connection returns to the pool (EF-6).

        Without MARS a SQL Server connection allows ONE active statement at a time. An
        ``UPDATE...OUTPUT`` claim (:meth:`claim_next_fifo`, :meth:`claim_ready`) leaves the statement
        handle *active* even after ``fetchall`` has drained its rows; if the connection is released to
        the aioodbc pool with that handle still open, the next borrower's first ``execute`` races a
        ``HY000 ... Connection is busy with results for another command``. ``fetchall`` drains the
        ROWS but does not free the STATEMENT — only closing the cursor (``SQLFreeStmt``/
        ``SQLCloseCursor``) does, deterministically (the v0.2.3 row-drain alone was insufficient: the
        box still reproduced EF-6 at every cold start). We deliberately do NOT use
        ``async with conn.cursor()``: aioodbc's ``conn.cursor()`` context manager commits on normal
        exit (when the connection is not autocommit) and rolls back on the exception path — either
        would override each caller's own explicit ``commit``/``rollback``, so we close the cursor
        directly here and let the caller own the transaction. A close failure is swallowed
        (best-effort) so it can never mask the real error already in flight."""
        cur = await conn.cursor()
        try:
            yield cur
        finally:
            try:
                await cur.close()
            except Exception:  # noqa: BLE001 - a close failure must not mask the in-flight error
                log.debug("cursor close on connection release failed", exc_info=True)

    async def _fetchall(self, sql: str, params: tuple[Any, ...] = ()) -> list[dict[str, Any]]:
        async with self._acquire() as conn, self._cursor(conn) as cur:
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
        async with self._acquire() as conn, self._cursor(conn) as cur:
            try:
                await cur.execute(sql, params)
                await conn.commit()
            except Exception:
                await conn.rollback()
                raise

    async def _event(
        self,
        cur: Any,
        message_id: str,
        event: str,
        destination: str | None,
        detail: str | None,
        now: float,
    ) -> None:
        # PHI chokepoint (#120): scrub HL7-shaped content out of the detail, THEN encrypt it at rest via
        # the store cipher (null/blank-safe) — SQL Server at-rest parity with SQLite/Postgres (H4). The
        # scrub is defense-in-depth kept *around* the cipher, exactly as SQLite does.
        detail = safe_text(detail) if detail else detail
        await cur.execute(
            "INSERT INTO message_events (message_id, ts, event, destination, detail)"
            " VALUES (?,?,?,?,?)",
            (message_id, now, event, destination, self._enc(detail)),
        )

    async def _record_delivered_key(
        self,
        cur: Any,
        *,
        outbox_id: str,
        message_id: str,
        destination_name: str | None,
        handler_name: str | None,
        now: float,
    ) -> None:
        """Write the H2 idempotency-ledger row for one just-completed outbound delivery, **inside the
        caller's open transaction** (SQL Server twin of :meth:`MessageStore._record_delivered_key`).

        Only outbound rows deliver; ingress/routed completions (``destination_name`` NULL) are skipped.
        ``delivery_seq`` is ``1 + COUNT`` of prior ledger rows for the pair (replay-stable, like
        ``response_seq``). Stored row carries hashes + ids only — never a body/PHI. One row per outbox
        row INSTANCE (a double mark_done must not accumulate a second entry); the ``NOT EXISTS`` insert
        is the belt-and-suspenders backstop on the content hash."""
        if destination_name is None:
            return
        await cur.execute("SELECT 1 FROM delivered_keys WHERE outbox_id=?", (outbox_id,))
        if await cur.fetchone() is not None:
            return
        await cur.execute("SELECT control_id FROM messages WHERE id=?", (message_id,))
        m = await cur.fetchone()
        control_id = m[0] if m is not None else None
        await cur.execute(
            "SELECT COUNT(*) FROM delivered_keys WHERE message_id=? AND destination_name=?",
            (message_id, destination_name),
        )
        seq = int((await cur.fetchone())[0]) + 1
        key = delivery_key(
            control_id=control_id,
            message_id=message_id,
            destination_name=destination_name,
            handler_name=handler_name,
            delivery_seq=seq,
        )
        await cur.execute(
            "INSERT INTO delivered_keys"
            " (delivery_key, outbox_id, message_id, destination_name, delivery_seq, delivered_at)"
            " SELECT ?,?,?,?,?,? WHERE NOT EXISTS"
            " (SELECT 1 FROM delivered_keys WHERE delivery_key=?)",
            (key, outbox_id, message_id, destination_name, seq, now, key),
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
            # fetchall (not a lone fetchone) reads the status AND drains the SELECT so the same-cursor
            # UPDATE on the FILTERED path below is clean. Deterministic close of this cursor before its
            # connection returns to the pool is handled by `_cursor` (EF-6) at the caller's block exit —
            # this just keeps the in-transaction cursor un-busy. The row-exists/non-ROUTED case returns.
            mrows = await cur.fetchall()
            if not mrows or mrows[0][0] != MessageStatus.ROUTED.value:
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
        async with self._acquire() as conn, self._cursor(conn) as cur:
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
        """Insert one ``stage='outbound'`` queue row (lane = destination_name)."""
        # ingest-time (ADR 0009) + metrics only; per-lane FIFO orders by seq (IDENTITY) — ADR 0059.
        created_at = now
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
        """Insert one ``stage='routed'`` queue row (lane = channel_id)."""
        # ingest-time (ADR 0009) + metrics only; per-lane FIFO orders by seq (IDENTITY) — ADR 0059.
        created_at = now
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

    async def _insert_passthrough_child_mssql(
        self,
        cur: Any,
        routed_id: str,
        parent_id: str,
        pt_channel: str,
        body: str,
        parent_meta: dict[str, Any],
        correlation_depth_cap: int,
        now: float,
    ) -> bool:
        """Produce one PT child INGRESS row + message inside the caller's transaction (ADR 0013, gen.).

        SQL Server twin of :meth:`MessageStore._insert_passthrough_child`. Returns ``True`` if a child
        was produced, ``False`` if the depth cap was breached (no child; the caller records the parent
        ``ERROR`` via a dead marker). The child is a new, independent message (``source_type=
        'passthrough'``, its own content-addressed id, status ``RECEIVED`` per count-and-log), correlated
        to the parent. Idempotent re-run: the content-addressed id is pre-checked so a partial-then-
        recovered run does not double-inject. Depth is computed purely from the parent's immutable
        metadata → re-run-stable."""
        child_depth = int(parent_meta.get("correlation_depth", 0) or 0) + 1
        root = parent_meta.get("correlation_root_id") or parent_id
        if child_depth > correlation_depth_cap:
            # Depth-cap breach: produce NO child, log the breach on the parent. The caller still consumes
            # the routed row (the Send is "handled" — dead-lettered) and the parent finalizes ERROR via
            # the dead marker the caller records. Mirrors the ingress depth-cap branch.
            await self._event(
                cur,
                parent_id,
                "passthrough_dropped",
                pt_channel,
                f"depth cap ({child_depth} > {correlation_depth_cap})",
                now,
            )
            return False
        new_mid = MessageStore._passthrough_message_id(routed_id, pt_channel, body)
        await cur.execute("SELECT 1 FROM messages WHERE id=?", (new_mid,))
        if await cur.fetchone() is None:
            child_meta = json.dumps(
                {
                    "correlation_id": parent_id,
                    "correlation_root_id": root,
                    "correlation_depth": child_depth,
                    "passthrough_from": parent_id,
                }
            )
            await cur.execute(
                "INSERT INTO messages (id, channel_id, received_at, source_type, control_id,"
                " message_type, raw, status, error, summary, metadata)"
                " VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                (
                    new_mid,
                    pt_channel,
                    now,
                    "passthrough",
                    None,
                    None,
                    self._cipher.encrypt(body),
                    MessageStatus.RECEIVED.value,
                    None,
                    None,
                    self._enc(child_meta),
                ),
            )
            # ingest-time (ADR 0009) + metrics only; per-lane FIFO orders by seq (IDENTITY) — ADR 0059.
            ingress_created = now
            await cur.execute(
                "INSERT INTO queue (id, message_id, stage, channel_id, destination_name,"
                " handler_name, payload, status, attempts, next_attempt_at, owner,"
                " lease_expires_at, created_at, updated_at)"
                " VALUES (?,?,?,?,NULL,NULL,?,?,0,?,NULL,NULL,?,?)",
                (
                    uuid4().hex,
                    new_mid,
                    Stage.INGRESS.value,
                    pt_channel,
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
                f"passthrough from {parent_id} -> {pt_channel}",
                now,
            )
            await self._event(
                cur,
                parent_id,
                "passthrough",
                pt_channel,
                f"-> {new_mid} depth {child_depth}",
                now,
            )
        return True

    async def _insert_passthrough_marker_mssql(
        self, cur: Any, parent_id: str, pt_name: str, produced: bool, now: float
    ) -> None:
        """Stamp the parent's terminal disposition row for a Send-into-PT (ADR 0013, generalized).

        SQL Server twin of :meth:`MessageStore._insert_passthrough_marker`. A single ``stage='outbound'``
        row keyed by the PT inbound name, inserted already-terminal: ``done`` when the child was produced
        (→ parent finalizes ``PROCESSED``), or ``dead`` when the depth cap was breached (→ parent
        finalizes ``ERROR``). Never claimed (no delivery worker for a PT name; claims take ``pending``
        rows only), so it is inert; it exists solely so the finalizer counts the Send's outcome. The
        payload is the empty-body sentinel; ``next_attempt_at`` is ``now`` (terminal, never due)."""
        status = OutboxStatus.DONE.value if produced else OutboxStatus.DEAD.value
        # ingest-time (ADR 0009) + metrics only; per-lane FIFO orders by seq (IDENTITY) — ADR 0059.
        created_at = now
        await cur.execute(
            "INSERT INTO queue (id, message_id, stage, channel_id, destination_name, handler_name,"
            " payload, status, attempts, next_attempt_at, owner, lease_expires_at, created_at,"
            " updated_at) VALUES (?,?,?,?,?,NULL,?,?,0,?,NULL,NULL,?,?)",
            (
                uuid4().hex,
                parent_id,
                Stage.OUTBOUND.value,
                pt_name,
                pt_name,
                self._cipher.encrypt(""),
                status,
                now,
                created_at,
                now,
            ),
        )
        if produced:
            await self._event(cur, parent_id, "delivered", pt_name, "passthrough re-ingress", now)
        else:
            await self._event(cur, parent_id, "dead", pt_name, "passthrough depth cap", now)

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
        async with self._acquire() as conn, self._cursor(conn) as cur:
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
                # ingest-time (ADR 0009) + metrics only; per-lane FIFO orders by seq (IDENTITY) — ADR 0059.
                created_at = now
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
        async with self._acquire() as conn, self._cursor(conn) as cur:
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
        async with self._acquire() as conn, self._cursor(conn) as cur:
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
        pt_deliveries: Sequence[tuple[str, str]] = (),
        correlation_depth_cap: int = 8,
        now: float | None = None,
    ) -> bool:
        """Advance one handler assignment from the routed stage to outbound in ONE transaction (the
        transform half): consume the in-flight routed row, apply each declared state write (ADR 0005),
        insert one outbound row per delivery, then let the finalizer recompute the terminal disposition
        (this method NEVER writes ``messages.status`` itself). State writes are applied in sorted
        (namespace, key) order under HOLDLOCK to bound MERGE range-deadlocks, and commit atomically
        with the outbound rows (exactly-once per re-run); the read-through cache is updated only AFTER
        commit. Idempotent: False if the routed row was already consumed.

        **Pass-through re-ingress (ADR 0013, generalized).** ``pt_deliveries`` are the handler's
        ``Send``\\ s whose target is an internal **pass-through (PT) inbound**. For each, this produces —
        **in this same transaction** — a new INGRESS-stage child message on the PT channel (a content-
        addressed id; ``RECEIVED`` per count-and-log; correlated to the parent), plus a single already-
        terminal outbound marker row on *this* (parent) message keyed by the PT inbound name, so the
        parent finalizes ``PROCESSED`` (delivered into the PT) rather than collapsing to ``FILTERED``. A
        ``correlation_depth`` breach drops the child and dead-letters the parent's marker (``ERROR``).
        Byte-identical to the pre-feature path when ``pt_deliveries`` is empty. Mirrors
        :class:`MessageStore` (SQLite) exactly."""
        now = time.time() if now is None else now
        applied: list[tuple[tuple[str, str], Any]] = []
        async with self._acquire() as conn, self._cursor(conn) as cur:
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
                # Pass-through re-ingress (ADR 0013, generalized): produce each PT child + the parent's
                # terminal marker IN THIS same transaction as the routed-row DELETE, so the handoff is
                # atomic and re-run-idempotent. Read the parent's correlation lineage once (absent →
                # depth 0).
                if pt_deliveries:
                    await cur.execute("SELECT metadata FROM messages WHERE id=?", (message_id,))
                    prow = await cur.fetchone()
                    parent_meta: dict[str, Any] = {}
                    pmeta_json = self._dec(prow[0]) if prow else None
                    if pmeta_json:
                        loaded = json.loads(pmeta_json)
                        if isinstance(loaded, dict):
                            parent_meta = loaded
                    for pt_name, body in pt_deliveries:
                        produced = await self._insert_passthrough_child_mssql(
                            cur,
                            routed_id,
                            message_id,
                            pt_name,
                            body,
                            parent_meta,
                            correlation_depth_cap,
                            now,
                        )
                        await self._insert_passthrough_marker_mssql(
                            cur, message_id, pt_name, produced, now
                        )
                total_targets = len(deliveries) + len(pt_deliveries)
                await self._event(
                    cur, message_id, "transformed", None, f"{total_targets} destination(s)", now
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
        async with self._acquire() as conn, self._cursor(conn) as cur:
            try:
                # Leading SELECT (also opens the txn so _maybe_finalize's applock is never first).
                await cur.execute(
                    "SELECT message_id, destination_name, handler_name, attempts FROM queue WHERE id=?",
                    (outbox_id,),
                )
                row = await cur.fetchone()
                if row is None:
                    await conn.commit()
                    return
                message_id, destination_name, handler_name, attempts = (
                    row[0],
                    row[1],
                    row[2],
                    row[3],
                )
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
                    # ingest-time (ADR 0009) + metrics only; per-lane FIFO orders by seq — ADR 0059.
                    work_created = now
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
                # H2: idempotency-ledger row joins this SAME txn as the DONE flip + the response artifact.
                await self._record_delivered_key(
                    cur,
                    outbox_id=outbox_id,
                    message_id=message_id,
                    destination_name=destination_name,
                    handler_name=handler_name,
                    now=now,
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
            "SELECT message_id, destination_name, response_seq, body, outcome, detail, captured_at,"
            " kind, ack_code, ack_phase"
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
                kind=r["kind"],
                ack_code=r["ack_code"],
                ack_phase=r["ack_phase"],
            )
            for r in rows
        ]

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
        # ADR 0021 "Response Sent" — see MessageStore.record_ack_sent for the contract. Leading SELECT
        # opens the txn; single commit. NAK body NULL; AA body only when encrypted; detail scrubbed+enc.
        now = time.time() if now is None else now
        dest = "\x1fack:" + inbound_name
        enc_body = self._enc(ack_body) if (ack_body and self._cipher.encrypts) else None
        enc_detail = self._enc(safe_text(detail)[:200]) if detail else None
        async with self._acquire() as conn, self._cursor(conn) as cur:
            try:
                await cur.execute(
                    "SELECT COALESCE(MAX(response_seq), 0) + 1 FROM response"
                    " WHERE message_id=? AND destination_name=? AND kind=?",
                    (message_id, dest, "ack_sent"),
                )
                seq = int((await cur.fetchone())[0])
                await cur.execute(
                    "INSERT INTO response"
                    " (message_id, destination_name, response_seq, body, outcome, detail,"
                    "  captured_at, kind, ack_code, ack_phase)"
                    " VALUES (?,?,?,?,?,?,?,?,?,?)",
                    (
                        message_id,
                        dest,
                        seq,
                        enc_body,
                        outcome,
                        enc_detail,
                        now,
                        "ack_sent",
                        ack_code,
                        ack_phase,
                    ),
                )
                await conn.commit()
            except Exception:
                await conn.rollback()
                raise

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
        # Pure observer: a single committed INSERT in its own txn (_execute) — no queue row, no
        # finalizer, never inside a handoff. reason rides safe_text (#120) + the cipher (H4 parity).
        now = time.time() if now is None else now
        reason_enc = self._enc(safe_text(reason)[:200]) if reason else None
        await self._execute(
            "INSERT INTO connection_event"
            " (ts, connection, transport, direction, kind, peer_host, message_id, reason)"
            " VALUES (?,?,?,?,?,?,?,?)",
            (now, connection, transport, direction, kind, peer_host, message_id, reason_enc),
        )

    async def list_connection_events(
        self,
        *,
        connection: str | None = None,
        kinds: Sequence[str] | None = None,
        since: float | None = None,
        limit: int = 100,
        allowed_channels: Sequence[str] | None = None,
    ) -> list[ConnectionEvent]:
        limit = max(1, min(limit, 1000))  # server-side clamp
        where: list[str] = []
        params: list[Any] = [limit]  # TOP (?) is the first placeholder
        if connection is not None:
            where.append("connection=?")
            params.append(connection)
        if kinds:
            placeholders = ",".join("?" for _ in kinds)
            where.append(f"kind IN ({placeholders})")
            params.extend(kinds)
        if since is not None:
            where.append("ts>=?")
            params.append(since)
        # Per-channel RBAC: a scoped caller sees ONLY their own inbound-direction events and never any
        # outbound row (which spans channels). Scope placeholders append after TOP/connection/kinds/since,
        # so positional order with the leading TOP(?) bind is preserved.
        if allowed_channels is not None:
            where.append("direction='inbound'")
            _append_channel_scope(where, params, "connection", allowed_channels)
        clause = (" WHERE " + " AND ".join(where)) if where else ""
        rows = await self._fetchall(
            "SELECT TOP (?) id, ts, connection, transport, direction, kind, peer_host, message_id, reason"
            f" FROM connection_event{clause} ORDER BY ts DESC, id DESC",
            tuple(params),
        )
        return [
            ConnectionEvent(
                id=int(r["id"]),
                ts=float(r["ts"]),
                connection=r["connection"],
                transport=r["transport"],
                direction=r["direction"],
                kind=r["kind"],
                peer_host=r["peer_host"],
                message_id=r["message_id"],
                reason=self._dec(r["reason"]),
            )
            for r in rows
        ]

    # --- operator alert-state (ADR 0044, #56) --------------------------------
    # >>> alert_instance block (#56) — self-contained; the coordinator integrates the store files <<<
    async def upsert_alert_instance(
        self,
        *,
        event_type: str,
        connection: str,
        severity: str,
        reason: str | None = None,
        now: float | None = None,
    ) -> None:
        # Pure observer (ADR 0044 D2): no queue row, no finalizer. De-dup grain = ADR 0014's
        # (event_type, connection) key. UPDATE-then-conditional-INSERT in one serializable transaction
        # (matching the SQLite path): the filtered unique index keeps it to one LIVE instance per key. The
        # caller wraps it fail-soft. reason rides safe_text + the cipher.
        now = time.time() if now is None else now
        reason_enc = self._enc(safe_text(reason)[:200]) if reason else None
        async with self._acquire() as conn, self._cursor(conn) as cur:
            try:
                await cur.execute(
                    "UPDATE alert_instance SET last_seen=?, [count]=[count]+1, severity=?, reason=?"
                    " WHERE event_type=? AND connection=? AND status<>'resolved'",
                    (now, severity, reason_enc, event_type, connection),
                )
                if cur.rowcount == 0:
                    await cur.execute(
                        "INSERT INTO alert_instance"
                        " (event_type, connection, severity, status, first_seen, last_seen,"
                        " [count], reason) VALUES (?,?,?,'open',?,?,1,?)",
                        (event_type, connection, severity, now, now, reason_enc),
                    )
                await conn.commit()
            except Exception:
                await conn.rollback()
                raise

    async def list_active_alert_instances(
        self,
        *,
        limit: int = 200,
        allowed_channels: Sequence[str] | None = None,
    ) -> list[AlertInstance]:
        limit = max(1, min(limit, 1000))  # server-side clamp
        where = ["status IN ('open','acknowledged')"]
        params: list[Any] = [limit]  # TOP (?) is the first placeholder
        if allowed_channels is not None:
            _append_channel_scope(where, params, "connection", allowed_channels)
        clause = " WHERE " + " AND ".join(where)
        rows = await self._fetchall(
            "SELECT TOP (?) id, event_type, connection, severity, status, first_seen, last_seen,"
            f" [count] AS count, reason, acked_by, acked_at, resolved_at FROM alert_instance{clause}"
            " ORDER BY last_seen DESC, id DESC",
            tuple(params),
        )
        return [self._alert_instance_row(r) for r in rows]

    async def get_alert_instance(
        self, alert_id: int, *, allowed_channels: Sequence[str] | None = None
    ) -> AlertInstance | None:
        where = ["id=?"]
        params: list[Any] = [alert_id]
        if allowed_channels is not None:
            _append_channel_scope(where, params, "connection", allowed_channels)
        clause = " WHERE " + " AND ".join(where)
        row = await self._fetchone(
            "SELECT id, event_type, connection, severity, status, first_seen, last_seen,"
            f" [count] AS count, reason, acked_by, acked_at, resolved_at FROM alert_instance{clause}",
            tuple(params),
        )
        return self._alert_instance_row(row) if row is not None else None

    def _alert_instance_row(self, r: dict[str, Any]) -> AlertInstance:
        return AlertInstance(
            id=int(r["id"]),
            event_type=r["event_type"],
            connection=r["connection"],
            severity=r["severity"],
            status=r["status"],
            first_seen=float(r["first_seen"]),
            last_seen=float(r["last_seen"]),
            count=int(r["count"]),
            reason=self._dec(r["reason"]),
            acked_by=r["acked_by"],
            acked_at=r["acked_at"],
            resolved_at=r["resolved_at"],
        )

    async def ack_alert_instance(
        self, alert_id: int, *, actor: str, now: float | None = None
    ) -> bool:
        now = time.time() if now is None else now
        async with self._acquire() as conn, self._cursor(conn) as cur:
            try:
                await cur.execute(
                    "UPDATE alert_instance SET status='acknowledged', acked_by=?, acked_at=?"
                    " WHERE id=? AND status<>'resolved'",
                    (actor, now, alert_id),
                )
                changed = cur.rowcount
                await conn.commit()
            except Exception:
                await conn.rollback()
                raise
        return int(changed) > 0

    async def resolve_alert_instance(self, alert_id: int, *, now: float | None = None) -> bool:
        now = time.time() if now is None else now
        async with self._acquire() as conn, self._cursor(conn) as cur:
            try:
                await cur.execute(
                    "UPDATE alert_instance SET status='resolved', resolved_at=?"
                    " WHERE id=? AND status<>'resolved'",
                    (now, alert_id),
                )
                changed = cur.rowcount
                await conn.commit()
            except Exception:
                await conn.rollback()
                raise
        return int(changed) > 0

    async def resolve_alert_instances_for(
        self, *, event_type: str, connection: str, now: float | None = None
    ) -> int:
        now = time.time() if now is None else now
        async with self._acquire() as conn, self._cursor(conn) as cur:
            try:
                await cur.execute(
                    "UPDATE alert_instance SET status='resolved', resolved_at=?"
                    " WHERE event_type=? AND connection=? AND status<>'resolved'",
                    (now, event_type, connection),
                )
                changed = cur.rowcount
                await conn.commit()
            except Exception:
                await conn.rollback()
                raise
        return int(changed)

    async def count_open_alerts_by_connection(self) -> dict[str, int]:
        rows = await self._fetchall(
            "SELECT connection, COUNT(*) AS n FROM alert_instance"
            " WHERE status='open' GROUP BY connection"
        )
        return {r["connection"]: int(r["n"]) for r in rows}

    async def purge_alert_instances(self, *, older_than: float, now: float | None = None) -> int:
        async with self._acquire() as conn, self._cursor(conn) as cur:
            try:
                await cur.execute(
                    "DELETE FROM alert_instance WHERE status='resolved' AND resolved_at IS NOT NULL"
                    " AND resolved_at < ?",
                    (older_than,),
                )
                purged = cur.rowcount
                await conn.commit()
            except Exception:
                await conn.rollback()
                raise
        return int(purged)

    # <<< end alert_instance block (#56) >>>

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
        async with self._acquire() as conn, self._cursor(conn) as cur:
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
                            self._enc("re-ingress work-row reference is corrupt/unparseable"),  # H4
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
                            self._enc(  # H4
                                f"re-ingress correlation depth exceeded "
                                f"({child_depth} > {correlation_depth_cap})"
                            ),
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
                        # ingest-time (ADR 0009) + metrics only; FIFO orders by seq — ADR 0059.
                        ingress_created = now
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
        async with self._acquire() as conn, self._cursor(conn) as cur:
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
                        (OutboxStatus.DEAD.value, now, self._enc(error), now, row[0]),  # H4
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
        # Active-format prefix through the active key's fingerprint (M9): `mfenc:v1:<kid>:` or, for a
        # v2-active cipher, `mfenc:v2:<alg>:<kid>:`. Built off the cipher (not a baked-in v1 prefix+keyid)
        # so a v2-active rotation matches v2 rows and the loop terminates.
        active_like = f"{self._cipher.active_marker_prefix}%"
        total = 0
        # summary/metadata (EF-3): MRN/name PHI on messages — rotated like raw. error/last_error/detail
        # (H4): exception text that may embed raw HL7 fragments — rotated too, or a later retired-key drop
        # silently loses them. message_events rides this id-keyed loop on its INT IDENTITY `id`. The
        # `<> ''` + NOT LIKE guard is null/empty-safe (NULL excluded by NOT LIKE; '' by <> '').
        for table, column in (
            ("messages", "raw"),
            ("queue", "payload"),
            ("users", "totp_secret"),
            ("messages", "summary"),
            ("messages", "metadata"),
            ("messages", "error"),
            ("queue", "last_error"),
            ("message_events", "detail"),
            ("connection_event", "reason"),  # #46: rotate the scrubbed event reason too (H4 parity)
            ("alert_instance", "reason"),  # #56 (ADR 0044): rotate the scrubbed alert reason too
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
                async with self._acquire() as conn, self._cursor(conn) as cur:
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
            async with self._acquire() as conn, self._cursor(conn) as cur:
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
                async with self._acquire() as conn, self._cursor(conn) as cur:
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

    async def purge_message_bodies(
        self,
        *,
        older_than: float,
        now: float | None = None,
        connection_cutoffs: Mapping[str, float] | None = None,
    ) -> int:
        """Blank message bodies (and terminal outbound payloads + event details) for messages received
        before ``older_than`` whose queue rows are all terminal — retention (PHI.md §8). Bodies are
        blanked to '' (not deleted) so the cipher re-encrypt scans skip them and the FK to messages
        stays intact. The eligible set is materialized ONCE so all three tables purge exactly the same
        messages. Returns the number of message bodies blanked.

        ``connection_cutoffs`` (#34, ADR 0027) optionally overrides the cutoff per ``channel_id``
        (``float('-inf')`` = keep forever); default empty ⇒ a single global cutoff, byte-identical to
        the prior behaviour. The per-connection cutoff only narrows the #eligible set (AND-ed with the
        unchanged in-flight guard), so the downstream UPDATEs are untouched."""
        # Per-connection cutoff (#34): bare "?" (global) when no override, else a CASE on m.channel_id.
        cutoff_sql, cutoff_params = _qmark_cutoff_case(
            "m.channel_id", older_than, connection_cutoffs
        )
        async with self._acquire() as conn, self._cursor(conn) as cur:
            try:
                # CREATE (no params) so the temp table lives at CONNECTION scope; a parameterized
                # SELECT...INTO runs under sp_executesql and would scope #eligible to that proc (gone
                # before the UPDATEs). The parameterized INSERT below still populates it.
                await cur.execute("CREATE TABLE #eligible (id NVARCHAR(64) PRIMARY KEY)")
                await cur.execute(
                    f"INSERT INTO #eligible SELECT id FROM messages m WHERE m.received_at < {cutoff_sql}"
                    " AND NOT EXISTS (SELECT 1 FROM queue q WHERE q.message_id=m.id"
                    " AND q.status IN (?, ?))",
                    (*cutoff_params, OutboxStatus.PENDING.value, OutboxStatus.INFLIGHT.value),
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

    async def strip_embedded_documents(
        self,
        *,
        older_than: float,
        now: float | None = None,
        connection_cutoffs: Mapping[str, float] | None = None,
        min_bytes: int = 0,
        content_types: Mapping[str, str] | None = None,
    ) -> StripResult:
        """Strip bulky base64 embedded documents in place (#47, ADR 0042 D2) — the SQL Server port of the
        select → codec-transform → write-back path. Replaces each ``mfb64:v1:`` carriage value / HL7
        OBX-5 ED embed with a self-describing tombstone, keeps the message parseable, and sets
        ``documents_pruned``. Eligibility mirrors :meth:`purge_message_bodies` (per-connection-or-global
        cutoff AND not in-flight). Returns a :class:`StripResult` (counts + bytes; no PHI)."""
        now = time.time() if now is None else now
        content_types = content_types or {}
        # Bound the candidate scan with the LOOSEST finite cutoff (a keep-forever -inf never widens it);
        # the precise per-connection cutoff is re-checked per row in Python (cutoff_for).
        finite = [
            c for c in [older_than, *(connection_cutoffs or {}).values()] if c != float("-inf")
        ]
        if not finite:
            return StripResult()  # everything keep-forever ⇒ nothing to scan
        scan_cutoff = max(finite)
        rows = await self._fetchall(
            "SELECT m.id, m.channel_id, m.raw, m.received_at FROM messages m"
            " WHERE m.raw <> '' AND m.documents_pruned IS NULL AND m.received_at < ?"
            " AND NOT EXISTS (SELECT 1 FROM queue q WHERE q.message_id=m.id"
            " AND q.status IN (?, ?))",
            (scan_cutoff, OutboxStatus.PENDING.value, OutboxStatus.INFLIGHT.value),
        )
        msgs = 0
        docs = 0
        reclaimed = 0
        updates: list[tuple[str, float, str]] = []
        for row in rows:
            cutoff = cutoff_for(row["channel_id"], older_than, connection_cutoffs)
            if row["received_at"] >= cutoff:
                continue
            raw = self._cipher.decrypt(row["raw"])
            new_raw, n_docs, n_bytes = _strip_documents(
                raw,
                pruned_at=now,
                min_bytes=min_bytes,
                content_type=content_types.get(row["channel_id"]),
            )
            if n_docs == 0:
                continue
            updates.append((self._cipher.encrypt(new_raw), now, row["id"]))
            msgs += 1
            docs += n_docs
            reclaimed += n_bytes
        if updates:
            async with self._acquire() as conn, self._cursor(conn) as cur:
                try:
                    for params in updates:
                        await cur.execute(
                            "UPDATE messages SET raw=?, documents_pruned=? WHERE id=?", params
                        )
                    await conn.commit()
                except Exception:
                    await conn.rollback()
                    raise
        return StripResult(
            messages_stripped=msgs, documents_stripped=docs, bytes_reclaimed=reclaimed
        )

    async def purge_connection_events(self, *, older_than: float, now: float | None = None) -> int:
        # #46: metadata-only rows (no body/FK) — age-DELETE on their own window (RetentionRunner-driven).
        async with self._acquire() as conn, self._cursor(conn) as cur:
            try:
                await cur.execute("DELETE FROM connection_event WHERE ts < ?", (older_than,))
                purged = cur.rowcount
                await conn.commit()
            except Exception:
                await conn.rollback()
                raise
        return int(purged) if purged is not None else 0

    async def purge_state(self, *, older_than: float, now: float | None = None) -> int:
        """Delete transform-state rows last set before ``older_than`` (ADR 0005 retention), evicting
        them from the read-through cache post-commit. Returns the number deleted."""
        async with self._acquire() as conn, self._cursor(conn) as cur:
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

    async def purge_dead_letters(
        self,
        *,
        older_than: float,
        now: float | None = None,
        connection_cutoffs: Mapping[str, float] | None = None,
    ) -> int:
        """Blank the payload of dead outbound rows updated before ``older_than`` (retention). Keeps the
        dead row + 'dead' status (counts/disposition) but frees the body; idempotent (payload <> '').

        ``connection_cutoffs`` (#34, ADR 0027) optionally overrides the cutoff per ``destination_name``
        (``float('-inf')`` = keep forever); default empty ⇒ a single global cutoff, byte-identical."""
        cutoff_sql, cutoff_params = _qmark_cutoff_case(
            "destination_name", older_than, connection_cutoffs
        )
        async with self._acquire() as conn, self._cursor(conn) as cur:
            try:
                await cur.execute(
                    "UPDATE queue SET payload='', last_error=NULL"
                    f" WHERE stage=? AND status=? AND payload <> '' AND updated_at < {cutoff_sql}",
                    (Stage.OUTBOUND.value, OutboxStatus.DEAD.value, *cutoff_params),
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

    async def snapshot_to(self, dest_path: str | object, *, method: str = "vacuum_into") -> None:
        """**DBA-delegated** on SQL Server (ADR 0049 / BACKLOG #52): the engine never takes a DB-tier
        backup of a server-DB store — native BACKUP DATABASE / Always On are infra-owned. Raises
        :class:`~messagefoundry.store.base.DbaDelegatedError`; the BackupRunner / ``backup`` CLI catch it
        and fall back to a config-only backup (or skip) per ``[backup].config_only_on_server_db``."""
        from messagefoundry.store.base import DbaDelegatedError

        raise DbaDelegatedError(
            "the SQL Server store backup is DBA-delegated (BACKUP DATABASE / Always On, BACKLOG #52); "
            "the engine backs up the config bundle only on a server-DB store (set "
            "[backup].config_only_on_server_db)"
        )

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
        )  # PHI chokepoint (#120): scrub first, then cipher the column write below (H4 parity)
        now = time.time() if now is None else now
        mid = uuid4().hex
        event = "error" if status is MessageStatus.ERROR else "filtered"
        async with self._acquire() as conn, self._cursor(conn) as cur:
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
                        self._enc(
                            error
                        ),  # H4: error may embed raw HL7 fragments — ciphered at rest
                        self._enc(summary),  # EF-3: MRN/name is PHI — ciphered at rest
                        self._enc(metadata),
                    ),
                )
                # `_event` re-scrubs + ciphers the plaintext `error` internally (parity with SQLite).
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
        async with self._acquire() as conn, self._cursor(conn) as cur:
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

    def set_leader_epoch(self, epoch: int | None, *, lease_key: str | None = None) -> None:
        # H1: the engine pushes the held leader epoch + lease key here on promotion/demotion (read from
        # the coordinator — the store never imports it, ARCH-6). Stamps cached state only; the next
        # claim_next_fifo validates it inside its single claim txn. epoch=None disables the guard.
        self._leader_epoch = epoch
        self._lease_key = lease_key

    async def claim_next_fifo(
        self,
        name: str,
        now: float | None = None,
        *,
        stage: str = Stage.OUTBOUND.value,
    ) -> OutboxItem | None:
        """Claim the single oldest *due* pending row for one lane at ``stage`` (strict FIFO — the head
        blocks the lane while it backs off, via the WHERE on the UPDATE). The lane key is stage-aware
        (``destination_name`` outbound, ``channel_id`` ingress/routed); ordering is ``seq`` alone
        (seq-only per-lane FIFO, ADR 0059): ``seq`` is a ``BIGINT IDENTITY`` the DB assigns
        monotonically at INSERT (never the random uuid ``id``), so among a lane's live pending rows
        ``ORDER BY seq`` is strict insert-commit order — **with zero wall-clock dependence**, immune to a
        skewed-standby clock across failover. This is correct **only because there is exactly ONE serial
        writer per (stage, lane-key)** (the per-inbound listener/router/transform worker; the
        destination_name fan-in is multi-writer but seq is still DB-assigned in commit order, so the
        first committer gets the lower seq). With ``created_at`` no longer an ordering backstop (ADR
        0059), a future second-writer-per-lane or delete+reinsert-on-retry (re-minting seq) would break
        FIFO — pin that assumption if either is ever added. This
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
        # H1 FENCING TOKEN (mirrors the Postgres guard). When the engine has pushed a held leader epoch,
        # gate the claim on it INSIDE the same txn: claim only while our held epoch is still current —
        # leader_lease.leader_epoch has NOT advanced past it. A standby that took over bumped the epoch on
        # its fresh acquire, so a paused/superseded ex-leader's held epoch is strictly older → the guard
        # is false → the UPDATE matches 0 rows. A missing lease row yields NULL and `NULL <= ?` is
        # unknown → no claim (fail-closed). The subquery is correlated-free (single-row lease) so it adds
        # one cheap seek under the same lock.
        epoch_guard = ""
        epoch_args: tuple[Any, ...] = ()
        if self._leader_epoch is not None:
            epoch_guard = (
                " AND (SELECT ll.leader_epoch FROM leader_lease ll WHERE ll.lease_key=?) <= ?"
            )
            epoch_args = (self._lease_key, self._leader_epoch)
        sql = (
            "WITH head AS (SELECT TOP (1) * FROM queue WITH (UPDLOCK, ROWLOCK)"
            f" WHERE stage=? AND {lane_col}=? AND status=? ORDER BY seq)"
            " UPDATE head SET status=?, attempts=attempts+1, updated_at=?,"
            " owner=NULL, lease_expires_at=NULL"
            " OUTPUT inserted.id, inserted.message_id, inserted.channel_id,"
            " inserted.destination_name, inserted.handler_name, inserted.payload,"
            " inserted.attempts"
            f" WHERE next_attempt_at<=?{epoch_guard}"
        )
        args = (
            stage,
            name,
            OutboxStatus.PENDING.value,
            OutboxStatus.INFLIGHT.value,
            now,
            now,
            *epoch_args,
        )
        async with self._acquire() as conn, self._cursor(conn) as cur:
            try:
                await cur.execute(sql, args)
                columns = [c[0] for c in cur.description] if cur.description else []
                # EF-6: read the claimed row with fetchall (not a lone fetchone) so the OUTPUT *rows*
                # are drained; the no-dedup (ingress/routed, destination_name NULL) path below has no
                # follow-on execute to discard the result set. NB the v0.2.3 row-drain alone did NOT
                # fix EF-6 — fetchall frees the rows but not the STATEMENT handle, so without MARS the
                # connection still returned to the pool "busy" for the next borrower. The deterministic
                # fix is `_cursor` closing the cursor (SQLFreeStmt) before release; this fetchall just
                # gets the row.
                rows = await cur.fetchall()
                row = rows[0] if rows else None
                d = dict(zip(columns, row)) if row is not None else None
                # H2 SKIP-AND-COMPLETE (SQL Server twin). If THIS just-claimed outbound row instance
                # already has a committed ledger row, a prior delivery completed but the row was re-pended
                # (a failover re-claim, or reset_stale_inflight after mark_done committed) — re-sending it
                # is the duplicate H2 prevents. Complete it DONE in THIS same claim txn WITHOUT handing it
                # to a worker; the lane advances to the next head with NO reorder (the head is consumed in
                # place). A deliberate `replay` DELETEs the ledger row, so a replayed re-send has no entry
                # here and is claimed normally (NOT deduped). The OUTPUT UPDATE already opened the txn, so
                # _maybe_finalize's applock is not the first statement.
                if d is not None and d["destination_name"] is not None:
                    await cur.execute("SELECT 1 FROM delivered_keys WHERE outbox_id=?", (d["id"],))
                    if await cur.fetchone() is not None:
                        await cur.execute(
                            "UPDATE queue SET status=?, last_error=NULL, updated_at=?, owner=NULL,"
                            " lease_expires_at=NULL WHERE id=?",
                            (OutboxStatus.DONE.value, now, d["id"]),
                        )
                        await self._event(
                            cur,
                            d["message_id"],
                            "delivered",
                            d["destination_name"],
                            "idempotent skip (already delivered)",
                            now,
                        )
                        await self._maybe_finalize(cur, d["message_id"], now)
                        d = None
                        row = None
                await conn.commit()
            except Exception:
                await conn.rollback()
                raise
        if row is None or d is None:
            return None
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

    async def claim_next_fifo_batch(
        self,
        name: str,
        now: float | None = None,
        *,
        stage: str,
        limit: int,
    ) -> list[OutboxItem]:
        """Claim the **contiguous DUE head-prefix** (up to ``limit`` rows) for one lane at ``stage`` in
        ONE commit — the batched cousin of :meth:`claim_next_fifo` (ADR 0058). SQL Server runs the full
        ingress -> routed -> outbound staged pipeline (module header; ``supports_ingest_stage = True``),
        so it is a real ingress/routed scale-path store and gets a REAL batch claim, not a delegation.

        **SELECT-then-UPDATE in ONE transaction** (the same shape the SQLite impl already uses), with the
        single claim's ``UPDLOCK, ROWLOCK`` **no-READPAST** lock providing the head-of-line *blocking* that
        SQLite gets from its global lock:

        1. **Lock the prefix candidates** — a plain ``SELECT TOP (@limit) id, next_attempt_at, seq FROM
           queue WITH (UPDLOCK, ROWLOCK) ... ORDER BY seq`` (seq-only per-lane FIFO, ADR 0059; **NO window
           function, NO READPAST**). Because there is no window function and no re-join to ``queue``, this acquires the
           U-locks *as it scans the rows in FIFO order* and **BLOCKS** on a producer-locked head exactly
           like the single claim's ``head`` SELECT — it cannot read past a locked interior head to a later
           seq (#285 preserved). The U-locks are held until this txn commits. ``LOCK_ESCALATION=DISABLE``
           on ``queue`` + the ``ROWLOCK`` hint + the bounded ``@limit`` (<= 64) keep it to at most N row
           locks, so no escalation to a TABLE lock.
        2. **Contiguous-due cutoff in Python** — iterate the rows (sorted by ``seq`` defensively, though the
           ``ORDER BY`` already returns them in lane order) and ``break`` at the first row whose
           ``next_attempt_at > now``; collect the due-prefix ids. A not-due *head* yields an empty prefix
           ⇒ ``[]`` ⇒ the lane blocks (== the single claim's ``None``); a not-due interior head truncates
           the prefix there, never reaching past it.
        3. **Claim the prefix** — ``UPDATE queue SET status=?, attempts=attempts+1, updated_at=? OUTPUT
           inserted.* WHERE id IN (<qmarks>) AND status=?`` (the ``AND status=?`` PENDING is a
           belt-and-suspenders guard; the held U-locks already prevent another claimer touching these rows).
           The H1 ``epoch_guard`` is appended verbatim so a fenced ex-leader claims 0 rows. OUTPUT projects
           the SAME fields as the single claim plus ``inserted.seq`` (the plaintext FIFO tiebreak, never
           PHI) — ``created_at`` is omitted, so the worker's ingest-time is ``None`` here, consistent with
           the single claim.

        Why NOT the earlier single-statement window-CTE: ``WITH locked AS (SELECT TOP(N) ..., SUM(...) OVER
        (...) FROM queue WITH(UPDLOCK,ROWLOCK)...), head AS (...) UPDATE q ... FROM queue q JOIN head``. The
        **window function** plus the **re-join to ``queue q``** let the optimizer satisfy the read from a
        version/index without holding the UPDLOCK *through the lock-wait* under the store's force-enabled
        RCSI — so it did **not** block on a producer-locked head and could claim a later seq ahead of it (a
        #285 violation caught by T6 on real SQL Server). The SELECT-then-UPDATE form operates the lock-wait
        directly on the candidate rows, matching the single claim's blocking exactly.

        Read with ``fetchall`` under the EF-6 ``_cursor`` close-before-release discipline (no-MARS), like
        the single claim. An undecryptable row is dead-lettered and DROPPED (poison containment); the
        surviving tail keeps its order. The outbound/delivery lane is never batched — callers pass an
        ingress/routed ``stage`` (the H2 skip-and-complete that the single outbound claim runs in-txn is
        deliberately absent here; ingress/routed rows have ``destination_name`` NULL and never hit it)."""
        now = time.time() if now is None else now
        lane_col = self._lane_col(stage)  # code-controlled literal
        # H1 FENCING TOKEN — identical to the single claim: gate the UPDATE on the held leader epoch still
        # being current so a paused/superseded ex-leader claims 0 rows. epoch=None disables the guard.
        epoch_guard = ""
        epoch_args: tuple[Any, ...] = ()
        if self._leader_epoch is not None:
            epoch_guard = (
                " AND (SELECT ll.leader_epoch FROM leader_lease ll WHERE ll.lease_key=?) <= ?"
            )
            epoch_args = (self._lease_key, self._leader_epoch)
        # STEP 1 — lock the TOP(N) oldest PENDING rows in FIFO order. A plain SELECT (no window function,
        # no re-join to `queue`) under WITH (UPDLOCK, ROWLOCK) takes its U-locks AS it scans the rows in
        # `seq` order (seq-only per-lane FIFO, ADR 0059 — one serial writer per lane assigns IDENTITY seq
        # in insert-commit order), so it BLOCKS on a producer-locked head — it cannot read past a locked
        # interior head to a later seq (the #285 no-skip guarantee). NO READPAST: blocking, not skipping,
        # is the correct FIFO semantic for a transiently producer-locked head (a long lock is bounded by
        # command_timeout). Mirrors the single claim's `head` SELECT, generalized to TOP(N).
        select_sql = (
            "SELECT TOP (?) id, next_attempt_at, seq FROM queue WITH (UPDLOCK, ROWLOCK)"
            f" WHERE stage=? AND {lane_col}=? AND status=? ORDER BY seq"
        )
        select_args = (limit, stage, name, OutboxStatus.PENDING.value)
        async with self._acquire() as conn, self._cursor(conn) as cur:
            try:
                await cur.execute(select_sql, select_args)
                lock_cols = [c[0] for c in cur.description] if cur.description else []
                locked = [dict(zip(lock_cols, r)) for r in await cur.fetchall()]
                # STEP 2 — contiguous-due truncation in Python. The SELECT already returns FIFO order; sort
                # by `seq` defensively, then STOP at the first not-due row (never skip past it: a not-due
                # head blocks the lane exactly as the single claim's None does — strict per-lane FIFO).
                due_ids: list[str] = []
                for d in sorted(locked, key=lambda d: d["seq"]):
                    if d["next_attempt_at"] > now:
                        break
                    due_ids.append(d["id"])
                if not due_ids:
                    # Head not due / nothing pending — block the lane (== single-claim None). Commit to
                    # release the U-locks held by the SELECT before the connection returns to the pool.
                    await conn.commit()
                    return []
                # STEP 3 — claim exactly the due prefix. The U-locks from STEP 1 are still held (same txn),
                # so no other claimer can race these rows; `AND status=?` (PENDING) is a belt-and-suspenders
                # guard. OUTPUT projects the single claim's fields + `seq` (the plaintext FIFO tiebreak).
                qmarks = ",".join("?" * len(due_ids))
                update_sql = (
                    "UPDATE queue SET status=?, attempts=attempts+1, updated_at=?"
                    " OUTPUT inserted.id, inserted.message_id, inserted.channel_id,"
                    " inserted.destination_name, inserted.handler_name, inserted.payload,"
                    " inserted.attempts, inserted.seq"
                    f" WHERE id IN ({qmarks}) AND status=?{epoch_guard}"
                )
                update_args = (
                    OutboxStatus.INFLIGHT.value,
                    now,  # updated_at
                    *due_ids,
                    OutboxStatus.PENDING.value,
                    *epoch_args,
                )
                await cur.execute(update_sql, update_args)
                columns = [c[0] for c in cur.description] if cur.description else []
                # EF-6: drain the OUTPUT rows with fetchall; _cursor closes the statement handle before
                # the connection returns to the pool (no-MARS).
                rows = await cur.fetchall()
                await conn.commit()
            except Exception:
                await conn.rollback()
                raise
        if not rows:
            # The epoch_guard matched 0 rows (a fenced ex-leader) — nothing claimed.
            return []
        # The OUTPUT clause does NOT guarantee row order; re-establish the lane's FIFO order in memory by
        # `seq` (seq-only per-lane FIFO, ADR 0059). A single serial writer per lane assigns the IDENTITY
        # `seq` in insert-commit order, and failover preserves seq (recovery/replay never re-stamp it), so
        # `ORDER BY seq` IS the lane's receive order with zero wall-clock dependence. `seq` is the only
        # extra OUTPUT field over the single claim; it is the plaintext FIFO key, never PHI, and is not
        # read as created_at. The worker then iterates strictly oldest-first (it never re-sorts).
        decoded = sorted((dict(zip(columns, r)) for r in rows), key=lambda d: d["seq"])
        items: list[OutboxItem] = []
        for d in decoded:
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

    async def mark_done(self, outbox_id: str, now: float | None = None) -> None:
        now = time.time() if now is None else now
        async with self._acquire() as conn, self._cursor(conn) as cur:
            try:
                await cur.execute(
                    "SELECT message_id, destination_name, handler_name, attempts FROM queue WHERE id=?",
                    (outbox_id,),
                )
                row = await cur.fetchone()
                if row is None:
                    await conn.commit()
                    return
                message_id, destination_name, handler_name, attempts = (
                    row[0],
                    row[1],
                    row[2],
                    row[3],
                )
                await cur.execute(
                    "UPDATE queue SET status=?, last_error=NULL, updated_at=? WHERE id=?",
                    (OutboxStatus.DONE.value, now, outbox_id),
                )
                # H2: record the idempotency-ledger row in THIS same txn as the DONE flip.
                await self._record_delivered_key(
                    cur,
                    outbox_id=outbox_id,
                    message_id=message_id,
                    destination_name=destination_name,
                    handler_name=handler_name,
                    now=now,
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
        error = safe_text(error)  # PHI chokepoint (#120): scrub first, then cipher last_error (H4)
        now = time.time() if now is None else now
        async with self._acquire() as conn, self._cursor(conn) as cur:
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
                    (status, next_at, self._enc(error), now, outbox_id),
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
        async with self._acquire() as conn, self._cursor(conn) as cur:
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
        )  # PHI chokepoint (#120) — incl. f"undecryptable payload: {exc}" callers; ciphered below (H4)
        now = time.time() if now is None else now
        async with self._acquire() as conn, self._cursor(conn) as cur:
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
                    (OutboxStatus.DEAD.value, now, self._enc(error), now, outbox_id),
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
        async with self._acquire() as conn, self._cursor(conn) as cur:
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
                        (OutboxStatus.DEAD.value, now, self._enc(error), now, row[0]),  # H4
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
        async with self._acquire() as conn, self._cursor(conn) as cur:
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
                if not stuck:
                    # RE-SEND branch (H2): drop the idempotency-ledger entries of THIS message's DONE rows
                    # (the exact set re-pended below) so a deliberate re-send is NOT skip-and-completed as
                    # a crash-re-run duplicate. Scoped to this message only.
                    await cur.execute(
                        "DELETE FROM delivered_keys WHERE outbox_id IN"
                        " (SELECT id FROM queue WHERE message_id=? AND status=?)",
                        (message_id, OutboxStatus.DONE.value),
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
        async with self._acquire() as conn, self._cursor(conn) as cur:
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
        async with self._acquire() as conn, self._cursor(conn) as cur:
            try:
                # `top_only` cancels the true FIFO head, so the tiebreak after next_attempt_at must match
                # the claim's seq-only order, NOT created_at (no longer the ordering key; ADR 0059).
                await cur.execute(
                    f"SELECT {top}id, message_id FROM queue WHERE {' AND '.join(where)}"
                    " ORDER BY next_attempt_at, seq",
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
            record["error"] = self._dec(record["error"])  # H4: error may embed raw HL7 fragments
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
        for r in rows:
            r["error"] = self._dec(r["error"])  # H4: error ciphered at rest
            r["summary"] = self._dec(r["summary"])  # EF-3: summary/metadata ciphered at rest
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
        """Scan-and-decrypt content search (ADR 0046 #51) — see ``MessageStore.search_messages``.
        Pre-filter on the indexed metadata, then decrypt + match each candidate body in memory off the
        event loop (the at-rest AES-GCM ciphertext can't be matched by a SQL ``LIKE``)."""
        where, params = self._message_filter(
            channel_id, status, message_type, control_id, allowed_channels
        )
        rows = await self._fetchall(
            "SELECT id, channel_id, received_at, source_type, control_id, message_type,"
            " status, error, summary, metadata, raw,"
            " (SELECT TOP 1 event FROM message_events e WHERE e.message_id = messages.id"
            "  ORDER BY e.id DESC) AS last_event"
            f" FROM messages{where}"
            " ORDER BY received_at DESC, id DESC",
            params,
        )
        return await asyncio.to_thread(self._scan_rows, spec, rows, limit)

    def _scan_rows(
        self, spec: SearchSpec, candidates: list[dict[str, Any]], limit: int
    ) -> MessageSearchResult:
        """Off-loop decrypt+match loop (mirrors ``MessageStore._scan_rows``). Bounded by
        ``spec.scan_limit`` decrypts and ``limit`` matches; returns metadata-only rows (the decrypted
        ``raw`` is dropped, so the PHI surface equals ``list_messages``)."""
        out: list[dict[str, Any]] = []
        scanned = 0
        truncated = False
        for cand in candidates:
            if scanned >= spec.scan_limit:
                truncated = True
                break
            scanned += 1
            raw = self._dec(cand.get("raw"))
            summary = self._dec(cand.get("summary"))
            if row_matches(spec, raw=raw, summary=summary):
                d = dict(cand)
                d["error"] = self._dec(d.get("error"))
                d["summary"] = self._dec(d.get("summary"))
                d["metadata"] = self._dec(d.get("metadata"))
                d.pop("raw", None)
                out.append(d)
                if len(out) >= limit:
                    break
        return MessageSearchResult(rows=out, scanned=scanned, matched=len(out), truncated=truncated)

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
        for r in rows:
            r["last_error"] = self._dec(r["last_error"])  # H4: last_error ciphered at rest
            r["summary"] = self._dec(r["summary"])  # EF-3: summary ciphered at rest
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
        rows = await self._fetchall(
            "SELECT * FROM queue WHERE message_id=? AND stage=? ORDER BY destination_name",
            (message_id, Stage.OUTBOUND.value),
        )
        for r in rows:
            r["last_error"] = self._dec(r["last_error"])  # H4: last_error ciphered at rest
        return rows

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
            r["last_error"] = self._dec(r["last_error"])  # H4: null/legacy-plaintext-safe decrypt
        return rows

    async def events_for(self, message_id: str) -> list[dict[str, Any]]:
        rows = await self._fetchall(
            "SELECT * FROM message_events WHERE message_id=? ORDER BY id", (message_id,)
        )
        for r in rows:
            r["detail"] = self._dec(r["detail"])  # H4: event detail ciphered at rest
        return rows

    async def record_view(
        self, message_id: str, *, actor: str | None = None, now: float | None = None
    ) -> None:
        now = time.time() if now is None else now
        async with self._acquire() as conn, self._cursor(conn) as cur:
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
            async with self._acquire() as conn, self._cursor(conn) as cur:
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
        async with self._acquire() as conn, self._cursor(conn) as cur:
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
        async with self._acquire() as conn, self._cursor(conn) as cur:
            try:
                await cur.execute(
                    "SELECT totp_recovery_codes FROM users WITH (UPDLOCK, ROWLOCK) WHERE id=?",
                    (user_id,),
                )
                # fetchall reads the codes AND drains the SELECT so the same-cursor UPDATE below is clean.
                # Deterministic close before the pooled connection is reused is `_cursor`'s job (EF-6);
                # the early-return commits below then release a cursor that gets closed on block exit.
                rows = await cur.fetchall()
                raw = rows[0][0] if rows else None
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
        async with self._acquire() as conn, self._cursor(conn) as cur:
            try:
                await cur.execute(
                    "SELECT last_totp_step FROM users WITH (UPDLOCK, ROWLOCK) WHERE id=?",
                    (user_id,),
                )
                # fetchall reads the step AND drains the SELECT so the same-cursor UPDATE below is clean;
                # `_cursor` closes the cursor before the pooled connection is reused (EF-6).
                rows = await cur.fetchall()
                if not rows:
                    await conn.commit()
                    return False
                last = rows[0][0]
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
        async with self._acquire() as conn, self._cursor(conn) as cur:
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
        permissions: str | None = None,
    ) -> None:
        # Single atomic MERGE under HOLDLOCK (range-locks the key) so two concurrent seeders can't both
        # find the row absent and both INSERT the same PK -> violation (the UPDATE-then-INSERT race).
        await self._execute(
            "MERGE roles WITH (HOLDLOCK) AS t"
            " USING (SELECT ? AS id, ? AS display_name, ? AS description, ? AS builtin,"
            " ? AS permissions) AS s"
            " ON t.id=s.id"
            " WHEN MATCHED THEN UPDATE SET display_name=s.display_name,"
            " description=s.description, builtin=s.builtin, permissions=s.permissions"
            " WHEN NOT MATCHED THEN INSERT (id, display_name, description, builtin, permissions)"
            " VALUES (s.id, s.display_name, s.description, s.builtin, s.permissions);",
            (role_id, display_name, description, 1 if builtin else 0, permissions),
        )

    async def list_roles(self) -> list[dict[str, Any]]:
        return await self._fetchall("SELECT * FROM roles ORDER BY id")

    async def get_role(self, role_id: str) -> dict[str, Any] | None:
        rows = await self._fetchall("SELECT * FROM roles WHERE id=?", (role_id,))
        return rows[0] if rows else None

    async def delete_custom_role(self, role_id: str) -> bool:
        """Delete a custom (``builtin=0``) role and its user/AD-group assignments in one transaction
        (ADR 0045 D4); never touches a built-in row. Returns ``True`` if removed."""
        async with self._acquire() as conn, self._cursor(conn) as cur:
            try:
                await cur.execute("SELECT builtin FROM roles WHERE id=?", (role_id,))
                row = await cur.fetchone()
                if row is None or int(row[0]) != 0:
                    await conn.rollback()
                    return False
                await cur.execute("DELETE FROM user_roles WHERE role_id=?", (role_id,))
                await cur.execute("DELETE FROM ad_group_role_map WHERE role_id=?", (role_id,))
                await cur.execute("DELETE FROM roles WHERE id=?", (role_id,))
                await conn.commit()
                return True
            except Exception:
                await conn.rollback()
                raise

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
        async with self._acquire() as conn, self._cursor(conn) as cur:
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
        async with self._acquire() as conn, self._cursor(conn) as cur:
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
        async with self._acquire() as conn, self._cursor(conn) as cur:
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
        async with self._acquire() as conn, self._cursor(conn) as cur:
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
        async with self._acquire() as conn, self._cursor(conn) as cur:
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
            synchronous=None,  # SQLite-only knob; SQL Server durability rides journal_mode (recovery model)
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
