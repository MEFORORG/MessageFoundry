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

import asyncio
import json
import hashlib
import logging
import os
import socket
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
    StoreBackend,
    StoreSettings,
    insecure_tls_allowed,
)
from messagefoundry.parsing.binary import strip_documents as _strip_documents
from messagefoundry.redaction import safe_text
from messagefoundry.store.audit_tee import emit_audit_tee
from messagefoundry.store.base import Row, warm_pool_connections, warm_pool_target
from messagefoundry.store.content_search import SearchSpec, row_matches
from messagefoundry.store.document_strip import StripResult, cutoff_for
from messagefoundry.store.pool_metrics import AcquireWaitHistogram, PoolStatus
from messagefoundry.store.crypto import MARKER_PREFIX as _ENC_MARKER_PREFIX
from messagefoundry.store.crypto import (
    AesGcmCipher,
    Cipher,
    CipherError,
    CipherInfo,
    IdentityCipher,
    cipher_info,
)
from messagefoundry.store.store import (
    AlertInstance,
    ClaimedHeads,
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
    WebAuthnCredential,
    audit_row_hash,
    delivery_key,
)

log = logging.getLogger(__name__)

# ADR 0066 §3.4: claim_fifo_heads lane-chunk clamp — bounds the lane array + per-txn row locks per
# claim call; the caller covers the remainder with a second call.
_FIFO_HEADS_LANE_CHUNK = 500
# ADR 0066 §3.1: release_claimed id-chunk bound (ids per UPDATE statement).
_RELEASE_CHUNK = 500

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
# ordering key that replaces SQLite's implicit rowid — seq-only per-lane FIFO (ADR 0059): one serial
# writer per lane gets monotonically increasing seq in insert-commit order, so handler-list order and
# receive order both survive ORDER BY seq, with zero wall-clock dependence.
_SCHEMA: list[str] = [
    # Single-row marker recording which shipped DDL batch (+ migration rev) was last applied — the
    # ADR 0064 fast-path discriminator. See _schema_hash; a hash match at open skips the whole batch
    # and the schema advisory lock (the WS-B co-start convoy).
    """CREATE TABLE IF NOT EXISTS schema_meta (
        id INT PRIMARY KEY CHECK (id = 1),
        schema_hash TEXT NOT NULL,
        applied_at DOUBLE PRECISION NOT NULL)""",
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
        metadata     TEXT,
        documents_pruned DOUBLE PRECISION
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
        body_ref         TEXT,
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
    # Per-stage FIFO covering indexes (ix_queue_fifo_in_seq / ix_queue_fifo_out_seq, seq-trailing per
    # ADR 0059) are built in _migrate_lease_columns, NOT here (ADR 0060): they were renamed from the old
    # created_at-trailing ix_queue_fifo_in/out, so an upgraded DB's stale same-named index is DROPped and
    # the seq-trailing one CREATEd there — both in this _ensure_schema txn (atomic) and each with
    # asyncpg's client command_timeout exempted (timeout=inf), which a large first-upgrade rebuild needs
    # and this generic _SCHEMA loop cannot give per-statement. Mirrors ix_queue_body_ref / ix_queue_lease.
    "CREATE INDEX IF NOT EXISTS ix_queue_message ON queue(message_id)",
    # ix_queue_body_ref is created in _migrate_lease_columns, AFTER body_ref is guaranteed present — on a
    # pre-existing queue without the column it'd reference a not-yet-added column (like ix_queue_lease).
    # Store-once-deliver-many (L2b): the single shared copy of a body fanned out to N destinations.
    # `hash` = sha256(plaintext); `body` is the one encrypted copy (cipher-covered, rides rotation);
    # `refcount` GC's the row at 0. SCHEMA PARITY here — the SQLite backend implements the dedup/deref/GC
    # behavior; on Postgres `body_ref` stays NULL today (bodies inline, byte-identical) and a follow-up
    # wires the insert/deref/GC without a second migration. CI-verified post-merge.
    """CREATE TABLE IF NOT EXISTS shared_body (
        hash       TEXT PRIMARY KEY,
        body       TEXT NOT NULL,
        refcount   INTEGER NOT NULL,
        created_at DOUBLE PRECISION NOT NULL
    )""",
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
        kind             TEXT NOT NULL DEFAULT 'response',  -- ADR 0021: 'response' | 'ack_sent'
        ack_code         TEXT,
        ack_phase        TEXT,
        PRIMARY KEY (message_id, destination_name, response_seq)
    )""",
    "CREATE INDEX IF NOT EXISTS ix_response_message ON response(message_id)",
    # Outbound idempotency ledger (H2) — one row per COMPLETED delivery, INSERTed in the SAME txn as the
    # outbound row's mark_done / complete_with_response. delivery_key = sha256 of non-PHI ids + a
    # replay-stable seq (delivery_key()); outbox_id is the queue row that delivered, the FIFO claim's
    # skip-and-complete dedup key. HASHES + IDS ONLY — no body/PHI — so it is NOT part of the cipher seam.
    """CREATE TABLE IF NOT EXISTS delivered_keys (
        delivery_key     TEXT PRIMARY KEY,
        outbox_id        TEXT NOT NULL,
        message_id       TEXT NOT NULL,
        destination_name TEXT NOT NULL,
        delivery_seq     INTEGER NOT NULL,
        delivered_at     DOUBLE PRECISION NOT NULL
    )""",
    "CREATE INDEX IF NOT EXISTS ix_delivered_outbox ON delivered_keys(outbox_id)",
    "CREATE INDEX IF NOT EXISTS ix_delivered_message ON delivered_keys(message_id, destination_name)",
    # Connection/transport event log (Corepoint-style #46) — METADATA-ONLY: inbound lifecycle +
    # pre-ingress failures + outbound lane transitions. id-keyed (NOT a queue stage → invisible to the
    # finalizer's `FROM queue` scan); message_id is NULLABLE with NO FK (correlation hint only) so a
    # pre-ingress event needs no messages row and can't inflate counts. reason is safe_text-scrubbed +
    # cipher-encrypted at rest (rides the id-keyed _CIPHER_COLUMNS loops).
    """CREATE TABLE IF NOT EXISTS connection_event (
        id          BIGSERIAL PRIMARY KEY,
        ts          DOUBLE PRECISION NOT NULL,
        connection  TEXT NOT NULL,
        transport   TEXT NOT NULL,
        direction   TEXT NOT NULL,
        kind        TEXT NOT NULL,
        peer_host   TEXT,
        message_id  TEXT,
        reason      TEXT
    )""",
    "CREATE INDEX IF NOT EXISTS ix_connection_event_conn ON connection_event(connection, ts)",
    # Operator alert-state (ADR 0044, #56) — resolvable alert INSTANCES (open/acknowledged/resolved +
    # first/last_seen + count). METADATA-ONLY: type/connection/severity/scrubbed reason (cipher-encrypted
    # at rest, rides the id-keyed _CIPHER_COLUMNS loops). De-duped on ADR 0014's (event_type, connection)
    # throttle key via the partial unique index (one LIVE instance per key; resolved rows drop out so the
    # key re-opens). id-keyed (NOT a queue stage → invisible to the finalizer's `FROM queue` scan).
    """CREATE TABLE IF NOT EXISTS alert_instance (
        id          BIGSERIAL PRIMARY KEY,
        event_type  TEXT NOT NULL,
        connection  TEXT NOT NULL,
        severity    TEXT NOT NULL,
        status      TEXT NOT NULL,
        first_seen  DOUBLE PRECISION NOT NULL,
        last_seen   DOUBLE PRECISION NOT NULL,
        count       BIGINT NOT NULL,
        reason      TEXT,
        acked_by    TEXT,
        acked_at    DOUBLE PRECISION,
        resolved_at DOUBLE PRECISION
    )""",
    """CREATE UNIQUE INDEX IF NOT EXISTS ux_alert_instance_open
        ON alert_instance(event_type, connection) WHERE status <> 'resolved'""",
    "CREATE INDEX IF NOT EXISTS ix_alert_instance_status ON alert_instance(status, connection)",
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
        builtin      BOOLEAN NOT NULL DEFAULT TRUE,
        permissions  TEXT
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
    # WebAuthn passkeys (WP-14b, ADR 0068 §4). credential_id_hash — sha256 hex of the raw credential
    # id (the sessions.token_hash precedent) — is the parity-safe PK on all 3 backends; sign_count is
    # BIGINT (a WebAuthn uint32 overflows signed INT); label is column-capped so ux_webauthn_label
    # stays bounded; public_key is COSE verification material, plaintext by design (not a secret).
    """CREATE TABLE IF NOT EXISTS webauthn_credentials (
        credential_id_hash VARCHAR(64) PRIMARY KEY,
        credential_id      TEXT NOT NULL,
        user_id            TEXT NOT NULL REFERENCES users(id),
        rp_id              VARCHAR(256) NOT NULL,
        public_key         TEXT NOT NULL,
        sign_count         BIGINT NOT NULL,
        transports         TEXT,
        device_type        VARCHAR(32) NOT NULL,
        backed_up          BOOLEAN NOT NULL DEFAULT FALSE,
        label              VARCHAR(100) NOT NULL,
        aaguid             VARCHAR(64),
        created_at         DOUBLE PRECISION NOT NULL,
        last_used_at       DOUBLE PRECISION
    )""",
    "CREATE INDEX IF NOT EXISTS ix_webauthn_credentials_user ON webauthn_credentials(user_id)",
    "CREATE UNIQUE INDEX IF NOT EXISTS ux_webauthn_label ON webauthn_credentials(user_id, label)",
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

# Bump when _migrate_lease_columns (the open-path migration code OUTSIDE _SCHEMA) changes behavior:
# unlike _SCHEMA edits — which change _schema_hash automatically — the migration function's Python
# body is invisible to the content hash, so this constant is its stand-in in the hash input.
_MIGRATION_REV = 1


def _schema_hash() -> str:
    """Content hash of the shipped DDL batch + the migration revision. The ``schema_meta`` marker
    stores it; a match at open means this exact batch (and migration pass) already ran, so both —
    and the schema advisory lock — are skipped (ADR 0064). Any edit to ``_SCHEMA`` changes the hash
    automatically; a change to ``_migrate_lease_columns`` must bump ``_MIGRATION_REV``."""
    payload = "\n".join(_SCHEMA) + f"\nmigration_rev={_MIGRATION_REV}"
    return hashlib.sha256(payload.encode()).hexdigest()


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
    if settings.ssl_root_cert:
        import ssl as _ssl

        # Pin a private / self-signed CA WITHOUT touching the OS trust store: verify the server cert
        # (+ hostname) against this PEM bundle. create_default_context() already sets CERT_REQUIRED +
        # check_hostname=True, so this stays a fully-verifying posture (a bad path raises at connect).
        return _ssl.create_default_context(cafile=settings.ssl_root_cert)
    return True  # verifying TLS against the system trust store (the secure default)


class PostgresStore:
    """PostgreSQL-backed durable queue (the :class:`Store` protocol). Open with :meth:`open`."""

    # Postgres implements the full staged ingress pipeline (enqueue_ingress/route_handoff/
    # transform_handoff), so the engine starts the staged runner on this backend.
    supports_ingest_stage = True

    # Postgres implements request/response capture (ADR 0013: the `response` table +
    # complete_with_response), with the same single-transaction atomicity as SQLite.
    supports_response_capture = True

    # Pass-through (PT) re-ingress (the `pt_deliveries` branch of transform_handoff, ADR 0013
    # generalized) is implemented at full SQLite parity: the atomic PT-child + parent-marker branch runs
    # inside transform_handoff's transaction (see _insert_passthrough_child_pg / _insert_passthrough_
    # marker_pg). A graph with a PT inbound is therefore accepted at engine startup on this backend.
    supports_pt_reingress = True

    # ADR 0071 B5: the synchronous fused-handoff twins are a SQL-Server-only lever. asyncpg is loop-
    # native and loop-bound — its statements never marshal through call_soon_threadsafe/_write_to_self,
    # so there is no store-call crossing to fuse and no synchronous asyncpg entry can exist. Kept False
    # by construction; the async path stays.
    supports_fused_sync_handoff = False
    backend = StoreBackend.POSTGRES

    #: Every (table, column) the store cipher covers — raw bodies plus the PHI-bearing nullable text
    #: columns (error/last_error/detail), and summary/metadata (MRN + patient name) added in EF-3.
    #: Used by the on-open migration and rotate-key (mirrors MessageStore._CIPHER_COLUMNS).
    _CIPHER_COLUMNS = (
        ("messages", "raw"),
        ("queue", "payload"),
        ("messages", "error"),
        ("queue", "last_error"),
        ("message_events", "detail"),
        ("messages", "summary"),  # EF-3: ingest-derived MRN/name — PHI, not just metadata
        ("messages", "metadata"),  # EF-3: code/operator-attached values
        ("users", "totp_secret"),  # MFA secret (WP-14) — id-keyed, rides the migration + rotation
        (
            "connection_event",
            "reason",
        ),  # #46: scrubbed event reason — id-keyed (BIGSERIAL), rides the loops
        (
            "alert_instance",
            "reason",
        ),  # #56 (ADR 0044): scrubbed alert reason — id-keyed (BIGSERIAL), rides the loops
        # NB: the `response` table (ADR 0013) is cipher-covered (body, detail) but has a COMPOSITE PK,
        # so it rides the composite helpers below, not this id-keyed list (like state/reference).
        # The `shared_body` table (store-once-deliver-many) is cipher-covered (`body`, hash-keyed) on the
        # SQLite backend; on Postgres it is schema-only this increment (body_ref stays NULL → the table is
        # always empty), so it needs no rotation pass here until the dedup insert is wired (CI-verified).
    )

    def __init__(self, pool: Any, settings: StoreSettings, *, cipher: Cipher | None = None) -> None:
        self._pool = pool
        self._settings = settings
        self._cipher: Cipher = cipher or IdentityCipher()
        self.path = f"{settings.server}/{settings.database}"  # descriptor for db_status
        # B11 connection-scale observability: a perf_counter-measured histogram of how long each
        # pooled-connection acquire() WAITS — the PRIMARY pool-wait wall signal (it grows monotonically
        # with worker contention once the pool saturates, where occupancy can't). Read-only/additive,
        # surfaced via pool_status() → the server-only /status `pool` field; default-empty (all zeros)
        # when nothing has contended, so it is byte-identical-when-unused.
        self._acquire_wait = AcquireWaitHistogram()
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
        # H1 fencing token: the leader epoch this node currently holds + the leader_lease row to validate
        # it against, both pushed by the engine on promotion via set_leader_epoch() (the store NEVER
        # imports the coordinator — ARCH-6). None disables the claim's epoch guard (single-node / not yet
        # leader), keeping claim_next_fifo byte-identical to pre-H1.
        self._leader_epoch: int | None = None
        self._lease_key: str | None = None

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

    async def _ensure_schema(self) -> bool:
        """Create the schema once, serialized across concurrent opens by a schema advisory lock so
        two processes can't race the DDL (the lock auto-releases at txn end) — or skip the whole
        batch when the ``schema_meta`` marker already records this exact batch (ADR 0064: re-running
        the guarded DDL + migrations under the exclusive lock on EVERY open made N concurrent opens
        convoy, WS-B Finding 2). Returns ``True`` iff the batch ran. Out-of-band drift (an operator
        hand-dropping an object) is no longer healed on every open — the remedy is
        ``DELETE FROM schema_meta``, which forces one full (idempotent) run."""
        expected = _schema_hash()
        async with self._timed_acquire() as conn:
            # FAST PATH: two cheap reads, no lock, no transaction. A virgin/pre-marker DB probes as
            # not-current and falls through to the full run.
            if await self._schema_marker_current(conn, expected):
                log.debug("postgres: schema current (%s…) — DDL batch skipped", expected[:12])
                return False
            async with conn.transaction():
                # B10/ADR 0060: disable any SERVER-side statement_timeout for this schema txn so a large
                # first-upgrade FIFO index rebuild (in _migrate_lease_columns) isn't killed by a
                # role/database-configured statement_timeout → txn abort → startup crash-loop. This covers
                # only the server side; asyncpg ALSO imposes a client-side command_timeout, exempted
                # per-statement with timeout=inf on the FIFO rebuild itself. SET LOCAL scopes to this txn
                # and auto-reverts at commit.
                await conn.execute("SET LOCAL statement_timeout = 0")
                await self._advisory_lock(conn, _LOCK_CLASS_SCHEMA, _SCHEMA_LOCK)
                # Double-check under the lock: the peer this open queued behind may have just applied
                # this exact batch and committed its marker — then there is nothing to do.
                if await self._schema_marker_current(conn, expected):
                    log.debug("postgres: schema applied by a peer (%s…) — skipped", expected[:12])
                    return False
                for statement in _SCHEMA:
                    await conn.execute(statement)
                await self._migrate_lease_columns(conn)
                await conn.execute(
                    "INSERT INTO schema_meta (id, schema_hash, applied_at) VALUES (1, $1, $2)"
                    " ON CONFLICT (id) DO UPDATE"
                    " SET schema_hash = EXCLUDED.schema_hash, applied_at = EXCLUDED.applied_at",
                    expected,
                    time.time(),
                )
        log.info("postgres: schema DDL batch applied (%s…)", expected[:12])
        return True

    @staticmethod
    async def _schema_marker_current(conn: Any, expected: str) -> bool:
        """True iff ``schema_meta`` exists and records exactly ``expected``. Existence is probed via
        ``to_regclass`` (NULL, never an exception) so a virgin DB falls through cleanly."""
        row = await conn.fetchrow("SELECT to_regclass('schema_meta') IS NOT NULL AS present")
        if row is None or not row["present"]:
            return False
        row = await conn.fetchrow("SELECT schema_hash FROM schema_meta WHERE id = 1")
        return bool(row is not None and row["schema_hash"] == expected)

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
                ["owner", "lease_expires_at", "body_ref"],
            )
        }
        if "owner" not in present:
            await conn.execute("ALTER TABLE queue ADD COLUMN owner TEXT")
        if "lease_expires_at" not in present:
            await conn.execute("ALTER TABLE queue ADD COLUMN lease_expires_at DOUBLE PRECISION")
        # Store-once-deliver-many (L2b): body_ref on a pre-existing queue (NULL = body inline, byte-
        # identical). shared_body is created by the _SCHEMA loop's CREATE TABLE IF NOT EXISTS.
        if "body_ref" not in present:
            await conn.execute("ALTER TABLE queue ADD COLUMN body_ref TEXT")
        # The deref index, created AFTER body_ref is guaranteed present (like ix_queue_lease above).
        await conn.execute("CREATE INDEX IF NOT EXISTS ix_queue_body_ref ON queue(body_ref)")
        # The reclaim sweep scans inflight rows by lease expiry (reclaim_expired_leases). Partial:
        # only inflight rows carry a lease, so the index needn't cover the pending/terminal majority.
        await conn.execute(
            "CREATE INDEX IF NOT EXISTS ix_queue_lease ON queue(lease_expires_at)"
            " WHERE status='inflight'"
        )
        # FIFO covering-index rename (ADR 0060). ADR 0059 re-keyed the per-lane FIFO indexes to trail in
        # `seq` but KEPT the names ix_queue_fifo_in/out with CREATE IF NOT EXISTS — so an upgraded DB
        # silently keeps its old created_at-trailing index and never adopts the seq-only claim's index.
        # DROP the old-named indexes and (re)build the seq-trailing ones under a NEW name so name-existence
        # is a correct discriminator. Both run in THIS _ensure_schema txn under the schema advisory lock,
        # so the swap is atomic (CREATE-new then DROP-old, one commit) and an upgraded DB adopts the
        # seq-trailing index. Plain CREATE (SHARE lock; NOT CONCURRENTLY, forbidden in a txn) — acceptable
        # at open, before serving. timeout=inf exempts each from asyncpg's client-side command_timeout
        # (the pool default, 30s): a SET LOCAL statement_timeout=0 (in _ensure_schema) covers only the
        # SERVER side, but asyncpg ALSO imposes a client cancel that a large first-upgrade rebuild would
        # trip → txn abort → startup crash-loop. Idempotent (IF NOT EXISTS / IF EXISTS); correctness-
        # neutral (the claim orders by seq and names no index, ADR 0059) — pure speed restoration.
        await conn.execute(
            "CREATE INDEX IF NOT EXISTS ix_queue_fifo_in_seq ON queue(stage, channel_id, status, seq)",
            timeout=float("inf"),
        )
        await conn.execute(
            "CREATE INDEX IF NOT EXISTS ix_queue_fifo_out_seq"
            " ON queue(stage, destination_name, status, seq)",
            timeout=float("inf"),
        )
        await conn.execute("DROP INDEX IF EXISTS ix_queue_fifo_in", timeout=float("inf"))
        await conn.execute("DROP INDEX IF EXISTS ix_queue_fifo_out", timeout=float("inf"))
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
        # ADR 0021 "Response Sent": the response table gains kind/ack_code/ack_phase. information_schema-
        # gated (a bare ADD COLUMN IF NOT EXISTS takes ACCESS EXCLUSIVE on every open). Existing rows
        # backfill kind='response' via the DEFAULT.
        response_cols = {
            r["column_name"]
            for r in await conn.fetch(
                "SELECT column_name FROM information_schema.columns"
                " WHERE table_name='response' AND column_name = ANY($1::text[])",
                ["kind", "ack_code", "ack_phase"],
            )
        }
        if "kind" not in response_cols:
            await conn.execute(
                "ALTER TABLE response ADD COLUMN kind TEXT NOT NULL DEFAULT 'response'"
            )
        if "ack_code" not in response_cols:
            await conn.execute("ALTER TABLE response ADD COLUMN ack_code TEXT")
        if "ack_phase" not in response_cols:
            await conn.execute("ALTER TABLE response ADD COLUMN ack_phase TEXT")
        # Active-active scale-out was dropped: drop the retired per-lane FIFO-ownership table from any DB
        # that was opened by an earlier build. Failover FIFO safety no longer depends on a lane lease —
        # claim_next_fifo reclaims a stranded head from the queue table directly. IF EXISTS is a no-op on
        # a fresh DB / a DB already migrated; runs under the schema advisory lock alongside the CREATEs.
        await conn.execute("DROP TABLE IF EXISTS lane_leases")
        # #47/ADR 0042: messages.documents_pruned (the "embedded doc evicted vs never present" flag) on a
        # pre-existing DB. information_schema-gated like the others; NULL on existing rows = never pruned.
        messages_has_pruned = await conn.fetch(
            "SELECT 1 FROM information_schema.columns"
            " WHERE table_name='messages' AND column_name='documents_pruned'"
        )
        if not messages_has_pruned:
            await conn.execute("ALTER TABLE messages ADD COLUMN documents_pruned DOUBLE PRECISION")
        # --- custom RBAC roles (ADR 0045): roles.permissions on a pre-existing DB. information_schema-
        # gated like the others; NULL on existing built-in rows = resolves from code (byte-identical).
        roles_has_perms = await conn.fetch(
            "SELECT 1 FROM information_schema.columns"
            " WHERE table_name='roles' AND column_name='permissions'"
        )
        if not roles_has_perms:
            await conn.execute("ALTER TABLE roles ADD COLUMN permissions TEXT")
        # --- end custom RBAC roles (ADR 0045) --------------------------------

    async def close(self) -> None:
        await self._pool.close()

    async def warm_pool(self) -> None:
        # Pre-open pooled connections so a connection burst (the post-promotion delivery workers, or a
        # cold start) finds them warm rather than paying asyncpg reconnects on the hot path. asyncpg
        # reconnects are cheaper than ODBC's TCP+TLS+login, so the win is smaller than on SQL Server, but
        # it still shaves the post-promotion drain. Gated by [store].warm_pool; the target is capped so a
        # warm never pins more than half the pool (leaving slots for the coordinator heartbeat,
        # on-promotion recovery, and the first delivery workers). See QueueStore.warm_pool.
        if not self._settings.warm_pool:
            return
        warmed = await warm_pool_connections(
            self._pool,
            target=warm_pool_target(self._pool.get_max_size(), self._settings.warm_pool_target),
            timeout=self._settings.warm_pool_timeout,
            backend="postgres",
        )
        if warmed:
            log.info("postgres: pre-warmed %d pooled connection(s)", warmed)

    async def require_rcsi_for_pooled(self) -> None:
        # No-op: Postgres always reads MVCC-consistent snapshots, so the pooled claim's STEP-1 discovery
        # (ADR 0066 §3.4) is non-blocking / never lock-skips with no toggle to verify — unlike SQL
        # Server's optional READ_COMMITTED_SNAPSHOT (ADR 0066 §3.3).
        return None

    # --- PHI-at-rest cipher seam for nullable text columns (WP-5) -------------

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

    @asynccontextmanager
    async def _timed_acquire(self) -> AsyncIterator[Any]:
        """Acquire a pooled connection, recording the **wait time** into the acquire-wait histogram
        (B11 pool-wait wall). Byte-equivalent to ``self._pool.acquire()`` except for the perf_counter
        pair around it — the connection yielded and the release on block-exit are unchanged. The
        transactional claim/handoff paths use this so the connection-scale harness can read how long
        the per-lane workers spend WAITING for a pooled connection as the pool saturates; the
        low-frequency convenience reads (``_fetchall``/``_fetchone``/``_execute``) acquire+release
        internally and are deliberately not timed, so a status poll never pollutes the worker curve."""
        t0 = perf_counter()
        pool_acquire = self._pool.acquire()
        async with pool_acquire as conn:
            self._acquire_wait.record((perf_counter() - t0) * 1000.0)
            yield conn

    def pool_status(self) -> PoolStatus | None:
        """The asyncpg pool snapshot (B11): size/idle occupancy + the PRIMARY acquire-wait percentiles.

        ``get_size()``/``get_idle_size()`` are the asyncpg ``Pool`` accessors (verified against the
        pinned ``asyncpg==0.31.0``). Synchronous + cheap (cached counters + an in-process histogram
        snapshot — no DB round-trip)."""
        return PoolStatus(
            backend="postgres",
            max_size=self._pool.get_max_size(),
            size=self._pool.get_size(),
            idle=self._pool.get_idle_size(),
            acquire_wait=self._acquire_wait.summary(),
        )

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
        async with self._timed_acquire() as conn:
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
        # Version-agnostic anchor (M9): `mfenc:%` matches BOTH v1 and v2 ciphertext, so a v2 row is
        # recognised as already-encrypted and skipped — never re-wrapped.
        like = f"{_ENC_MARKER_PREFIX}%"
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
                async with self._timed_acquire() as conn:
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
            async with self._timed_acquire() as conn:
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
        # Active-format prefix through the active key's fingerprint (M9): `mfenc:v1:<kid>:` or, for a
        # v2-active cipher, `mfenc:v2:<alg>:<kid>:`. Built off the cipher (not a baked-in v1 prefix+keyid)
        # so a v2-active rotation matches v2 rows and the loop terminates.
        active_like = f"{cipher.active_marker_prefix}%"
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
                async with self._timed_acquire() as conn:
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
            async with self._timed_acquire() as conn:
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

    async def _record_delivered_key(
        self,
        conn: Any,
        *,
        outbox_id: str,
        message_id: str,
        destination_name: str | None,
        handler_name: str | None,
        now: float,
    ) -> None:
        """Write the H2 idempotency-ledger row for one just-completed outbound delivery, **inside the
        caller's open transaction** (Postgres twin of :meth:`MessageStore._record_delivered_key`).

        Only outbound rows deliver; ingress/routed completions (``destination_name`` NULL) are skipped.
        ``delivery_seq`` is ``1 + COUNT`` of prior ledger rows for the pair (replay-stable, like
        ``response_seq``). Stored row carries hashes + ids only — never a body/PHI. One row per outbox
        row INSTANCE (a double mark_done must not accumulate a second entry); ``ON CONFLICT DO NOTHING``
        is the belt-and-suspenders backstop on the content hash."""
        if destination_name is None:
            return
        already = await conn.fetchval(
            "SELECT 1 FROM delivered_keys WHERE outbox_id=$1 LIMIT 1", outbox_id
        )
        if already is not None:
            return
        control_id = await conn.fetchval("SELECT control_id FROM messages WHERE id=$1", message_id)
        seq = await conn.fetchval(
            "SELECT COUNT(*) + 1 FROM delivered_keys WHERE message_id=$1 AND destination_name=$2",
            message_id,
            destination_name,
        )
        key = delivery_key(
            control_id=control_id,
            message_id=message_id,
            destination_name=destination_name,
            handler_name=handler_name,
            delivery_seq=int(seq),
        )
        await conn.execute(
            "INSERT INTO delivered_keys"
            " (delivery_key, outbox_id, message_id, destination_name, delivery_seq, delivered_at)"
            " VALUES ($1,$2,$3,$4,$5,$6) ON CONFLICT (delivery_key) DO NOTHING",
            key,
            outbox_id,
            message_id,
            destination_name,
            int(seq),
            now,
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
            self._enc(summary),  # EF-3: MRN/name is PHI — ciphered at rest like the body
            self._enc(metadata),
        )

    async def _insert_outbound_row(
        self, conn: Any, mid: str, channel_id: str, dest_name: str, payload: str, now: float
    ) -> None:
        """Insert one ``stage='outbound'`` queue row (one message→destination delivery)."""
        # ingest-time (ADR 0009) + metrics only; per-lane FIFO orders by seq (BIGSERIAL) — ADR 0059.
        created_at = now
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
        # ingest-time (ADR 0009) + metrics only; per-lane FIFO orders by seq (BIGSERIAL) — ADR 0059.
        created_at = now
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

    async def _insert_passthrough_child_pg(
        self,
        conn: Any,
        routed_id: str,
        parent_id: str,
        pt_channel: str,
        body: str,
        parent_meta: dict[str, Any],
        correlation_depth_cap: int,
        now: float,
    ) -> bool:
        """Produce one PT child INGRESS row + message inside the caller's transaction (ADR 0013, gen.).

        Postgres twin of :meth:`MessageStore._insert_passthrough_child`. Returns ``True`` if a child was
        produced, ``False`` if the depth cap was breached (no child; the caller records the parent
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
            # the dead marker the caller records. Mirrors the ingress_handoff depth-cap branch.
            await self._event(
                conn,
                parent_id,
                "passthrough_dropped",
                pt_channel,
                f"depth cap ({child_depth} > {correlation_depth_cap})",
                now,
            )
            return False
        new_mid = MessageStore._passthrough_message_id(routed_id, pt_channel, body)
        exists = await conn.fetchval("SELECT 1 FROM messages WHERE id=$1", new_mid)
        if exists is None:
            child_meta = json.dumps(
                {
                    "correlation_id": parent_id,
                    "correlation_root_id": root,
                    "correlation_depth": child_depth,
                    "passthrough_from": parent_id,
                }
            )
            await self._insert_message(
                conn,
                new_mid,
                channel_id=pt_channel,
                raw=body,
                status=MessageStatus.RECEIVED.value,
                control_id=None,
                message_type=None,
                source_type="passthrough",
                summary=None,
                metadata=child_meta,
                error=None,
                now=now,
            )
            # ingest-time (ADR 0009) + metrics only; per-lane FIFO orders by seq (BIGSERIAL) — ADR 0059.
            ingress_created = now
            await conn.execute(
                "INSERT INTO queue (id, message_id, stage, channel_id, destination_name,"
                " handler_name, payload, status, attempts, next_attempt_at, created_at,"
                " updated_at) VALUES ($1,$2,$3,$4,NULL,NULL,$5,$6,0,$7,$8,$9)",
                uuid4().hex,
                new_mid,
                Stage.INGRESS.value,
                pt_channel,
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
                f"passthrough from {parent_id} -> {pt_channel}",
                now,
            )
            await self._event(
                conn,
                parent_id,
                "passthrough",
                pt_channel,
                f"-> {new_mid} depth {child_depth}",
                now,
            )
        return True

    async def _insert_passthrough_marker_pg(
        self, conn: Any, parent_id: str, pt_name: str, produced: bool, now: float
    ) -> None:
        """Stamp the parent's terminal disposition row for a Send-into-PT (ADR 0013, generalized).

        Postgres twin of :meth:`MessageStore._insert_passthrough_marker`. A single ``stage='outbound'``
        row keyed by the PT inbound name, inserted already-terminal: ``done`` when the child was produced
        (→ parent finalizes ``PROCESSED``), or ``dead`` when the depth cap was breached (→ parent
        finalizes ``ERROR``). Never claimed (no delivery worker for a PT name; claims take ``pending``
        rows only), so it is inert; it exists solely so the finalizer counts the Send's outcome. The
        payload is the empty-body sentinel; ``next_attempt_at`` is ``now`` (terminal, never due)."""
        status = OutboxStatus.DONE.value if produced else OutboxStatus.DEAD.value
        # ingest-time (ADR 0009) + metrics only; per-lane FIFO orders by seq (BIGSERIAL) — ADR 0059.
        created_at = now
        await conn.execute(
            "INSERT INTO queue (id, message_id, stage, channel_id, destination_name, handler_name,"
            " payload, status, attempts, next_attempt_at, created_at, updated_at)"
            " VALUES ($1,$2,$3,$4,$5,NULL,$6,$7,0,$8,$9,$10)",
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
        )
        if produced:
            await self._event(conn, parent_id, "delivered", pt_name, "passthrough re-ingress", now)
        else:
            await self._event(conn, parent_id, "dead", pt_name, "passthrough depth cap", now)

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
        async with self._timed_acquire() as conn:
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
        async with self._timed_acquire() as conn:
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
        async with self._timed_acquire() as conn:
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
                # ingest-time (ADR 0009) + metrics only; FIFO orders by seq (BIGSERIAL) — ADR 0059.
                ingress_created_at = now
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
        async with self._timed_acquire() as conn:
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
        async with self._timed_acquire() as conn:
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
        pt_deliveries: Sequence[tuple[str, str]] = (),
        correlation_depth_cap: int = 8,
        now: float | None = None,
    ) -> bool:
        """Advance one handler assignment from the **routed** stage to outbound (the transform half of
        the split pipeline): consume the in-flight routed row, insert one outbound row per delivery,
        apply each declared state write (ADR 0005) atomically with them, then let the finalizer
        recompute the terminal disposition (this method never writes ``messages.status``). State
        exactly-once: each op upserts by (namespace,key) inside this same transaction; the read cache
        is updated only after commit. Idempotent: ``False`` if the routed row was already consumed.

        **Pass-through re-ingress (ADR 0013, generalized).** ``pt_deliveries`` are the handler's
        ``Send``\\ s whose target is an internal **pass-through (PT) inbound** (not an outbound). For
        each, this produces — **in this same transaction** — a new INGRESS-stage child message on the
        PT channel (a content-addressed id; ``RECEIVED`` per count-and-log; correlated to the parent),
        plus a single already-terminal outbound marker row on *this* (parent) message keyed by the PT
        inbound name, so the parent finalizes ``PROCESSED`` (the Send was delivered into the PT) rather
        than collapsing to ``FILTERED``. A ``correlation_depth`` breach drops the child and dead-letters
        the parent's marker (``ERROR``). Byte-identical to the pre-feature path when ``pt_deliveries`` is
        empty. Mirrors :class:`MessageStore` (SQLite) exactly."""
        now = time.time() if now is None else now
        applied: list[tuple[tuple[str, str], Any]] = []
        async with self._timed_acquire() as conn:
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
                # Pass-through re-ingress (ADR 0013, generalized): produce each PT child + the parent's
                # terminal marker IN THIS same transaction as the routed-row DELETE, so the handoff is
                # atomic and re-run-idempotent. Read the parent's correlation lineage once (absent →
                # depth 0).
                if pt_deliveries:
                    prow = await conn.fetchrow(
                        "SELECT metadata FROM messages WHERE id=$1", message_id
                    )
                    parent_meta: dict[str, Any] = {}
                    pmeta_json = self._dec(prow["metadata"]) if prow else None
                    if pmeta_json:
                        loaded = json.loads(pmeta_json)
                        if isinstance(loaded, dict):
                            parent_meta = loaded
                    for pt_name, body in pt_deliveries:
                        produced = await self._insert_passthrough_child_pg(
                            conn,
                            routed_id,
                            message_id,
                            pt_name,
                            body,
                            parent_meta,
                            correlation_depth_cap,
                            now,
                        )
                        await self._insert_passthrough_marker_pg(
                            conn, message_id, pt_name, produced, now
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
                total_targets = len(deliveries) + len(pt_deliveries)
                await self._event(
                    conn,
                    message_id,
                    "transformed",
                    None,
                    f"{total_targets} destination(s)",
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
        async with self._timed_acquire() as conn:
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
        blocks the lane while it backs off). Lane key is stage-aware (``destination_name`` outbound,
        ``channel_id`` ingress/routed). Ordering is ``seq`` alone (seq-only per-lane FIFO, ADR 0059):
        ``seq`` is a ``BIGSERIAL`` the DB assigns monotonically at INSERT, so among a lane's live pending
        rows ``ORDER BY seq`` is strict insert-commit order — **with zero wall-clock dependence**, immune
        to a skewed-standby clock across failover. This is correct **only because there is exactly ONE
        serial writer per (stage, lane-key)** (the per-inbound listener/router/transform worker; the
        destination_name fan-in is multi-writer but seq is still DB-assigned in commit order, so the
        first committer gets the lower seq, and ``FOR UPDATE SKIP LOCKED`` never skips the true locked
        head). With ``created_at`` no longer an ordering backstop, a future second-writer-per-lane or
        delete+reinsert-on-retry (re-minting seq) would break FIFO. ``FOR UPDATE SKIP LOCKED`` on the
        head keeps concurrent pollers non-blocking. ``None`` when nothing is pending or the head isn't due.

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
        # H1 FENCING TOKEN. When the engine has pushed a held leader epoch (this node is a fenced
        # leader), gate the claim on it INSIDE the same txn: claim only while our held epoch is still
        # current — i.e. the authoritative leader_lease.leader_epoch has NOT advanced past it. A standby
        # that took over bumped leader_epoch on its fresh acquire, so a paused/superseded ex-leader's
        # held epoch is strictly older → the guard `leader_lease.leader_epoch <= $held` is false → the
        # UPDATE matches 0 rows and the stale ex-leader claims nothing. The current leader's held epoch
        # equals leader_lease.leader_epoch (<= passes), so it claims normally. The subquery runs in the
        # claim txn (FOR UPDATE SKIP LOCKED on head is unaffected); a missing lease row yields NULL and
        # `NULL <= $held` is false → fail-closed (no claim) rather than racing without a fence.
        epoch_guard = ""
        if self._leader_epoch is not None:
            epoch_guard = (
                " AND (SELECT ll.leader_epoch FROM leader_lease ll WHERE ll.lease_key=$8) <= $9"
            )
        head_sql = (
            "WITH head AS ("
            f" SELECT id, next_attempt_at FROM queue WHERE stage=$1 AND {lane_col}=$2 AND status=$3"
            " ORDER BY seq LIMIT 1 FOR UPDATE SKIP LOCKED"
            ")"
            " UPDATE queue q SET status=$4, attempts=attempts+1, updated_at=$5,"
            " owner=$6, lease_expires_at=$7"
            f" FROM head WHERE q.id=head.id AND head.next_attempt_at<=$5{epoch_guard} RETURNING q.*"
        )
        async with self._timed_acquire() as conn:
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
                # When fenced, $8/$9 carry the lease key + held epoch the guard validates (H1).
                claim_args: list[Any] = [
                    stage,
                    name,
                    OutboxStatus.PENDING.value,
                    OutboxStatus.INFLIGHT.value,
                    now,
                    self._owner,
                    lease_until,
                ]
                if self._leader_epoch is not None:
                    claim_args.extend([self._lease_key, self._leader_epoch])
                row = await conn.fetchrow(head_sql, *claim_args)
                # H2 SKIP-AND-COMPLETE (Postgres twin). If THIS just-claimed outbound row instance
                # already has a committed ledger row, a prior delivery completed but the row was
                # re-pended (a failover re-claim, or reset_stale_inflight after mark_done committed) —
                # re-sending it is the duplicate H2 prevents. Complete it DONE in THIS same claim txn
                # WITHOUT handing it to a worker; the lane advances to the next head with NO reorder (the
                # head is consumed in place). A deliberate `replay` DELETEs the ledger row, so a replayed
                # re-send has no entry here and is claimed normally (NOT deduped). Runs INSIDE the same
                # transaction()/leader-epoch-fenced claim, so the fence still gates this completion.
                if row is not None and row["destination_name"] is not None:
                    already = await conn.fetchval(
                        "SELECT 1 FROM delivered_keys WHERE outbox_id=$1 LIMIT 1", row["id"]
                    )
                    if already is not None:
                        await conn.execute(
                            "UPDATE queue SET status=$1, last_error=NULL, updated_at=$2,"
                            " owner=NULL, lease_expires_at=NULL WHERE id=$3",
                            OutboxStatus.DONE.value,
                            now,
                            row["id"],
                        )
                        await self._event(
                            conn,
                            row["message_id"],
                            "delivered",
                            row["destination_name"],
                            "idempotent skip (already delivered)",
                            now,
                        )
                        await self._maybe_finalize_message(conn, row["message_id"], now)
                        row = None
        return await self._fifo_item_or_dead_letter(row)

    async def claim_next_fifo_batch(
        self,
        name: str,
        now: float | None = None,
        *,
        stage: str,
        limit: int,
    ) -> list[OutboxItem]:
        """Claim the **contiguous DUE head-prefix** (up to ``limit`` rows) for one lane at ``stage`` in
        ONE commit — the batched cousin of :meth:`claim_next_fifo` (ADR 0058), INGRESS/ROUTED only.

        The same-txn per-lane **stranded-head reclaim** runs FIRST (identical to the single claim) so a
        crashed/fenced predecessor's expired-lease inflight rows are re-pended before the window — the
        recovered head is reconsidered as the (due) prefix head and blocks the lane, preserving per-lane
        FIFO across failover.

        Then the prefix claim. ``FOR UPDATE`` does NOT combine with window functions, and ``SKIP LOCKED``
        at ``LIMIT N`` would skip a producer-locked interior head and pull a later row into the window (a
        #285 reorder), so the lock and the prefix-cut are split into two levels:

        * ``locked`` — an inner ``FOR UPDATE`` (NO ``SKIP LOCKED``) over the lane's ``LIMIT N`` oldest
          pending rows in ``seq`` order (seq-only per-lane FIFO, ADR 0059). No window function here (FOR
          UPDATE forbids it). A producer-locked interior head BLOCKS (matching the single claim's intent)
          rather than being skipped — strict per-lane FIFO. The ``LIMIT N`` bounds the lock to at most N
          rows (never the whole lane).
        * ``boundary``/``head`` — a NON-locking outer window over ``locked`` that truncates at the first
          not-due row (``rn < first-not-due rn``), the contiguous due prefix. A not-due head ⇒ empty
          ``head`` ⇒ 0 rows updated ⇒ empty batch ⇒ the lane blocks (== the single claim's ``None``).

        The UPDATE stamps ``owner``/``lease_expires_at`` on all claimed rows (failover-recovery parity)
        and appends the H1 ``epoch_guard`` exactly as the single claim, and ``RETURNING q.*`` carries
        ``created_at`` (Postgres surfaces it). Decode runs AFTER the claim txn: an undecryptable row is
        dead-lettered (its own txn) and dropped, mirroring the single claim. The outbound/delivery lane is
        never batched — callers pass an ingress/routed ``stage`` (ingress/routed rows have a NULL
        ``destination_name`` and never reach the H2 skip-and-complete the single outbound claim runs)."""
        now = time.time() if now is None else now
        lease_until = now + self._settings.lease_ttl_seconds  # Track B Step 2: stamp the lease
        lane_col = self._lane_col(stage)  # code-controlled literal
        # Positional args, in order. $1..$7 are fixed; the batch LIMIT and the optional H1 fence follow.
        claim_args: list[Any] = [
            stage,  # $1
            name,  # $2
            OutboxStatus.PENDING.value,  # $3
            OutboxStatus.INFLIGHT.value,  # $4
            now,  # $5 (updated_at + the not-due cutoff)
            self._owner,  # $6
            lease_until,  # $7
            limit,  # $8 (batch LIMIT)
        ]
        # H1 FENCING TOKEN — identical to the single claim: a fenced ex-leader's UPDATE matches 0 rows.
        # When fenced, the lease key + held epoch are $9/$10 (after the fixed args + the LIMIT $8).
        epoch_guard = ""
        if self._leader_epoch is not None:
            epoch_guard = (
                " AND (SELECT ll.leader_epoch FROM leader_lease ll WHERE ll.lease_key=$9) <= $10"
            )
            claim_args.extend([self._lease_key, self._leader_epoch])
        # Two-level CTE: the inner FOR UPDATE locks the N oldest pending rows (no window, no SKIP LOCKED ->
        # BLOCK on a producer-locked head, never skip — strict per-lane FIFO #285); the outer window
        # truncates at the first not-due row (the contiguous due prefix). 2147483647 = a sentinel "no
        # not-due row in the locked window" so an all-due window keeps the whole prefix. A not-due head ⇒
        # empty `head` ⇒ 0 rows updated ⇒ empty batch ⇒ the lane blocks (== the single claim's None).
        # ORDERING IS seq-ONLY (ADR 0059) and the THREE refs MUST stay in lockstep: the inner `locked`
        # ORDER BY (picks WHICH N rows), the row_number() window (drives the not-due cutoff `rn`), AND the
        # in-memory sort below. A partial edit type-checks but silently corrupts the contiguous-due cutoff.
        prefix_sql = (
            "WITH locked AS ("
            " SELECT id, created_at, seq, next_attempt_at FROM queue"
            f" WHERE stage=$1 AND {lane_col}=$2 AND status=$3"
            " ORDER BY seq LIMIT $8 FOR UPDATE"
            "), ordered AS ("
            " SELECT id, next_attempt_at,"
            " row_number() OVER (ORDER BY seq) AS rn FROM locked"
            "), head AS ("
            " SELECT id FROM ordered"
            " WHERE rn < COALESCE((SELECT min(rn) FROM ordered WHERE next_attempt_at > $5), 2147483647)"
            ")"
            " UPDATE queue q SET status=$4, attempts=attempts+1, updated_at=$5,"
            " owner=$6, lease_expires_at=$7"
            f" FROM head WHERE q.id=head.id{epoch_guard} RETURNING q.*"
        )
        async with self._timed_acquire() as conn:
            async with conn.transaction():
                # FIRST recover this lane's stranded head (identical to the single claim) so the oldest
                # recovered row is reconsidered as the (now-due) prefix head and blocks the lane.
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
                rows = await conn.fetch(prefix_sql, *claim_args)
        # Decode AFTER the claim txn. RETURNING does not guarantee order across the UPDATE, so sort by
        # `seq` (seq-only per-lane FIFO, ADR 0059 — one serial writer per lane assigns BIGSERIAL seq in
        # insert-commit order) to be certain the worker iterates oldest-first. This is the THIRD of the
        # three lockstep ordering refs (see the prefix_sql comment). An undecryptable interior row is
        # dead-lettered (its own txn) and dropped; the surviving tail keeps its order.
        ordered = sorted(rows, key=lambda r: r["seq"])
        items: list[OutboxItem] = []
        for row in ordered:
            item = await self._fifo_item_or_dead_letter(row)
            if item is not None:
                items.append(item)
        return items

    async def claim_fifo_heads(
        self,
        stage: str,
        lanes: Sequence[str],
        now: float | None = None,
        *,
        per_lane_limit: int = 1,
    ) -> ClaimedHeads:
        """Claim at most the contiguous DUE head-prefix of EACH requested lane in ONE transaction —
        statement-count parity with today's single claim (``BEGIN; lane-scoped reclaim; claim;
        [H2]; COMMIT`` — ADR 0066 §3.4; see the base protocol for the full contract).

        The **lane-array stranded-lease reclaim runs FIRST** in the txn (the multi-lane twin of the
        single claim's, generalized to ``= ANY($lanes)``): a crashed/fenced predecessor's
        expired-lease inflight rows re-pend so each lane's recovered oldest row is reconsidered as
        the (due) head and blocks the lane — failover FIFO preserved per lane. It must stay a
        SEPARATE statement before the claim (PG data-modifying-CTE snapshot rules: a later CTE
        cannot see an earlier CTE's writes through the table).

        Then the **chained MATERIALIZED CTE claim** (probe-then-claim, the #285 inversion): ``cand``
        snapshot-discovers each lane's min-seq PENDING rows regardless of due-ness (plain MVCC,
        non-locking); ``heads`` cuts each prefix at the first not-due row (a not-due HEAD empties
        the lane); ``locked`` probes ``FOR UPDATE SKIP LOCKED`` **confined to the discovered ID
        set** (a skip can only DROP a candidate — structurally never reach seq N+1); ``keep``
        head-pins the surviving prefix to the discovered head (the B1 head-agreement fix: a SKIP
        LOCKED drop of the visible head EMPTIES the lane instead of letting LIMIT fill with N+1) —
        which also closes the pre-existing admin-replay SKIP-LOCKED race to the same one-cycle EMPTY
        exposure the shipped single claim carries. The UPDATE claims exactly the kept prefixes,
        stamping ``owner`` + row lease per claimed row exactly as today (N-active-ready), with the
        H1 ``epoch_guard`` appended verbatim. ``MATERIALIZED`` pins evaluation; all CTEs share one
        snapshot; ``FOR UPDATE`` re-checks post-lock via EvalPlanQual; non-kept rows were
        locked-but-never-UPDATEd — their locks release at commit with ``attempts`` untouched.

        The H2 skip-and-complete runs per claimed outbound row in the SAME txn (code-identical to
        :meth:`claim_next_fifo`'s); decode runs AFTER the commit — an undecryptable row is
        dead-lettered (its own txn) and dropped, and a fully-consumed lane joins ``rearm``."""
        now = time.time() if now is None else now
        lease_until = now + self._settings.lease_ttl_seconds  # Track B Step 2: stamp the lease
        lane_col = self._lane_col(stage)  # code-controlled literal
        assert per_lane_limit >= 1, "per_lane_limit must be >= 1"  # nosec B101 — caller contract
        if stage not in (Stage.INGRESS.value, Stage.ROUTED.value):
            # HARD-1 for OUTBOUND/RESPONSE (ADR 0066 §3.2 STEP 6): H2 atomicity + the single-
            # outstanding-head retry semantics — exactly as ADR 0058 excludes them from batching.
            per_lane_limit = 1
        # Dedupe (preserving request order) + chunk clamp; the caller covers the remainder.
        lane_list = list(dict.fromkeys(lanes))[:_FIFO_HEADS_LANE_CHUNK]
        if not lane_list:
            return ClaimedHeads(by_lane={}, rearm=frozenset())
        # H1 FENCING TOKEN — identical to the single claim: a fenced ex-leader's UPDATE matches 0
        # rows across all lanes. When fenced, the lease key + held epoch ride as $9/$10.
        epoch_guard = ""
        claim_args: list[Any] = [
            stage,  # $1
            lane_list,  # $2 (lane array)
            OutboxStatus.PENDING.value,  # $3
            now,  # $4 (updated_at + the not-due cutoff)
            per_lane_limit,  # $5
            OutboxStatus.INFLIGHT.value,  # $6
            self._owner,  # $7
            lease_until,  # $8
        ]
        if self._leader_epoch is not None:
            epoch_guard = (
                " AND (SELECT ll.leader_epoch FROM leader_lease ll WHERE ll.lease_key=$9) <= $10"
            )
            claim_args.extend([self._lease_key, self._leader_epoch])
        claim_sql = (
            "WITH cand AS MATERIALIZED ("  # STEP 1: plain MVCC snapshot read, non-locking
            " SELECT l.lane, h.id, h.seq, h.next_attempt_at,"
            " row_number() OVER (PARTITION BY l.lane ORDER BY h.seq) AS rn"
            " FROM unnest($2::text[]) AS l(lane)"
            " CROSS JOIN LATERAL ("
            " SELECT id, seq, next_attempt_at FROM queue"
            f" WHERE stage=$1 AND {lane_col} = l.lane AND status=$3"
            " ORDER BY seq LIMIT $5) AS h"
            "), heads AS MATERIALIZED ("  # STEP 2: contiguous-due cutoff (not-due head => empty lane)
            " SELECT c.* FROM cand c"
            " WHERE NOT EXISTS (SELECT 1 FROM cand p"
            " WHERE p.lane = c.lane AND p.rn <= c.rn AND p.next_attempt_at > $4)"
            "), locked AS MATERIALIZED ("  # STEP 3: lock-probe confined to the discovered ID set
            " SELECT q.id FROM queue q"
            " WHERE q.id IN (SELECT id FROM heads)"
            " AND q.status=$3 AND q.next_attempt_at <= $4"
            " FOR UPDATE SKIP LOCKED"
            "), keep AS MATERIALIZED ("  # STEP 4: head-pin — the B1 head-agreement fix: a SKIP
            " SELECT h.id FROM heads h"  # LOCKED drop of the visible head (rn=1) empties the
            " WHERE NOT EXISTS ("  # lane instead of letting LIMIT fill with N+1.
            " SELECT 1 FROM heads p"
            " WHERE p.lane = h.lane AND p.rn <= h.rn"
            " AND NOT EXISTS (SELECT 1 FROM locked k WHERE k.id = p.id))"
            ")"
            " UPDATE queue q"  # STEP 5: claim exactly the kept prefixes
            " SET status=$6, attempts=attempts+1, updated_at=$4, owner=$7, lease_expires_at=$8"
            f" FROM keep WHERE q.id = keep.id{epoch_guard}"
            " RETURNING q.*"
        )
        rearm: set[str] = set()
        kept_rows: list[Any] = []
        async with self._timed_acquire() as conn:
            async with conn.transaction():
                # (i) multi-lane stranded-head lease reclaim, same txn, FIRST (the multi-lane twin
                # of the single claim's): bounded to the requested lanes and to already-expired
                # leases, so it never steals a live node's own actively-leased rows.
                await conn.execute(
                    f"UPDATE queue SET status=$3, owner=NULL, lease_expires_at=NULL,"
                    f" next_attempt_at=$4, updated_at=$4"
                    f" WHERE stage=$1 AND {lane_col} = ANY($2::text[]) AND status=$5"
                    f" AND lease_expires_at IS NOT NULL AND lease_expires_at < $4",
                    stage,
                    lane_list,
                    OutboxStatus.PENDING.value,
                    now,
                    OutboxStatus.INFLIGHT.value,
                )
                rows = await conn.fetch(claim_sql, *claim_args)
                # Iterate in CANONICAL message_id order: H2 may take the per-message finalize
                # advisory lock for SEVERAL messages in this one txn, and a monotone subsequence
                # of the sorted order can never form a lock cycle with _lock_finalize_batch
                # callers (or a sibling pooled claim) — RETURNING order is nondeterministic and
                # would re-open the multi-message deadlock the sorted discipline exists to
                # prevent. kept_rows are regrouped and seq-sorted per lane below, so iteration
                # order is otherwise immaterial.
                for row in sorted(rows, key=lambda r: r["message_id"]):
                    # H2 SKIP-AND-COMPLETE in the SAME claim txn — code-identical to
                    # claim_next_fifo's (the only _maybe_finalize call site in this primitive; the
                    # fence still gates this completion). The consumed head is completed DONE in
                    # place (NO reorder), dropped from the results, and its lane re-armed.
                    if row["destination_name"] is not None:
                        already = await conn.fetchval(
                            "SELECT 1 FROM delivered_keys WHERE outbox_id=$1 LIMIT 1", row["id"]
                        )
                        if already is not None:
                            await conn.execute(
                                "UPDATE queue SET status=$1, last_error=NULL, updated_at=$2,"
                                " owner=NULL, lease_expires_at=NULL WHERE id=$3",
                                OutboxStatus.DONE.value,
                                now,
                                row["id"],
                            )
                            await self._event(
                                conn,
                                row["message_id"],
                                "delivered",
                                row["destination_name"],
                                "idempotent skip (already delivered)",
                                now,
                            )
                            await self._maybe_finalize_message(conn, row["message_id"], now)
                            rearm.add(row[lane_col])
                            continue
                    kept_rows.append(row)
        # Group by lane and sort by `seq` in memory (RETURNING does not guarantee order), then
        # decode AFTER the claim txn: an undecryptable row is dead-lettered (its own txn) and
        # DROPPED; the surviving tail keeps its order.
        by_lane_rows: dict[str, list[Any]] = {}
        for row in kept_rows:
            by_lane_rows.setdefault(row[lane_col], []).append(row)
        by_lane: dict[str, list[OutboxItem]] = {}
        for lane, lane_rows in by_lane_rows.items():
            items: list[OutboxItem] = []
            for row in sorted(lane_rows, key=lambda r: r["seq"]):
                item = await self._fifo_item_or_dead_letter(row)
                if item is not None:
                    items.append(item)
            if items:
                by_lane[lane] = items
            else:
                rearm.add(lane)  # whole prefix consumed (poison) — re-arm the lane
        return ClaimedHeads(by_lane=by_lane, rearm=frozenset(rearm))

    async def list_fifo_lanes(
        self,
        stage: str,
        now: float | None = None,
        *,
        limit: int = 4096,
        after: str | None = None,
    ) -> list[tuple[str, float]]:
        """Read-only lane discovery (ADR 0066 §3.6; see the base protocol for the full contract):
        the recursive-CTE loose-index-scan analog of the SQL Server dialect — O(distinct lanes with
        pending rows) seeks over ``ix_queue_fifo_*_seq`` — pairing each lane with its HEAD row's
        ``next_attempt_at`` via a per-lane ``LATERAL ... ORDER BY seq LIMIT 1`` (head-of-line-aware
        by construction). Plain MVCC read: no locks, no writes."""
        lane_col = self._lane_col(stage)  # code-controlled literal
        sql = (
            "WITH RECURSIVE lanes AS ("
            f" SELECT MIN({lane_col}) AS lane FROM queue"
            f" WHERE stage=$1 AND status=$2 AND ($3::text IS NULL OR {lane_col} > $3)"
            " UNION ALL"
            f" SELECT (SELECT MIN({lane_col}) FROM queue"
            f" WHERE stage=$1 AND status=$2 AND {lane_col} > l.lane)"
            " FROM lanes l WHERE l.lane IS NOT NULL)"
            " SELECT l.lane, h.next_attempt_at"
            " FROM lanes l"
            " CROSS JOIN LATERAL (SELECT next_attempt_at FROM queue"
            f" WHERE stage=$1 AND {lane_col} = l.lane AND status=$2"
            " ORDER BY seq LIMIT 1) h"
            " WHERE l.lane IS NOT NULL"
            " ORDER BY l.lane"
            " LIMIT $4"
        )
        rows = await self._fetchall(sql, stage, OutboxStatus.PENDING.value, after, limit)
        return [(r["lane"], r["next_attempt_at"]) for r in rows]

    async def release_claimed(self, ids: Sequence[str], now: float | None = None) -> None:
        """Return never-dispatched INFLIGHT rows to ``pending``, undoing exactly the claim's
        ``attempts`` increment (ADR 0066 §3.1; see the base protocol for the full contract):
        ``attempts-1`` floored at 0 defensively, ``next_attempt_at`` UNCHANGED, owner/row-lease
        cleared. Guarded ``status='inflight'`` so an already-resolved row is left untouched —
        idempotent. Chunked <=500 ids per statement, one commit for the call (cross-backend
        parity: SQLite and SQL Server release all chunks in one transaction, so a mid-call crash
        never leaves a partially-released tail on this backend alone)."""
        now = time.time() if now is None else now
        id_list = list(dict.fromkeys(ids))
        if not id_list:
            return
        async with self._timed_acquire() as conn:
            async with conn.transaction():
                for i in range(0, len(id_list), _RELEASE_CHUNK):
                    chunk = id_list[i : i + _RELEASE_CHUNK]
                    await conn.execute(
                        "UPDATE queue SET status=$1, attempts=GREATEST(attempts - 1, 0),"
                        " updated_at=$2, owner=NULL, lease_expires_at=NULL"
                        " WHERE id = ANY($3::text[]) AND status=$4",
                        OutboxStatus.PENDING.value,
                        now,
                        chunk,
                        OutboxStatus.INFLIGHT.value,
                    )

    async def reschedule_claimed(
        self, ids: Sequence[str], next_attempt_at: float, now: float | None = None
    ) -> None:
        """Re-pend never-dispatched INFLIGHT rows with a DURABLE backoff — the pooled T17 head-fault
        path (ADR 0070 fix A; see the base protocol for the full contract). Identical to
        :meth:`release_claimed`'s attempts undo (``attempts=GREATEST(attempts-1,0)``, status inflight→
        pending, owner/lease cleared) but sets ``next_attempt_at`` to the supplied backoff deadline so
        the faulting head reads **not-due** and the sweep arms an exact timer instead of re-readying it
        ~4×/s. Guarded ``status='inflight'`` — idempotent. Chunked <=500 ids, one commit for the call."""
        now = time.time() if now is None else now
        id_list = list(dict.fromkeys(ids))
        if not id_list:
            return
        async with self._timed_acquire() as conn:
            async with conn.transaction():
                for i in range(0, len(id_list), _RELEASE_CHUNK):
                    chunk = id_list[i : i + _RELEASE_CHUNK]
                    await conn.execute(
                        "UPDATE queue SET status=$1, attempts=GREATEST(attempts - 1, 0),"
                        " next_attempt_at=$2, updated_at=$3, owner=NULL, lease_expires_at=NULL"
                        " WHERE id = ANY($4::text[]) AND status=$5",
                        OutboxStatus.PENDING.value,
                        next_attempt_at,
                        now,
                        chunk,
                        OutboxStatus.INFLIGHT.value,
                    )

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
        async with self._timed_acquire() as conn:
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
        async with self._timed_acquire() as conn:
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
                # H2: record the idempotency-ledger row in THIS same txn as the DONE flip.
                await self._record_delivered_key(
                    conn,
                    outbox_id=outbox_id,
                    message_id=row["message_id"],
                    destination_name=row["destination_name"],
                    handler_name=row["handler_name"],
                    now=now,
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
        async with self._timed_acquire() as conn:
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
                    # ingest-time (ADR 0009) + metrics only; per-lane FIFO orders by seq — ADR 0059.
                    work_created = now
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
                # H2: idempotency-ledger row joins this SAME txn as the DONE flip + the response artifact.
                await self._record_delivered_key(
                    conn,
                    outbox_id=outbox_id,
                    message_id=message_id,
                    destination_name=destination_name,
                    handler_name=row["handler_name"],
                    now=now,
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
            async with self._timed_acquire() as conn:
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
                    meta_json = self._dec(mrow["metadata"]) if mrow else None  # EF-3: ciphered
                    if meta_json:
                        loaded = json.loads(meta_json)
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
                            # ingest-time (ADR 0009) + metrics only; FIFO orders by seq — ADR 0059.
                            ingress_created = now
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
            "SELECT message_id, destination_name, response_seq, body, outcome, detail, captured_at,"
            " kind, ack_code, ack_phase"
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
        # ADR 0021 "Response Sent" — see MessageStore.record_ack_sent for the full contract. Own txn
        # (seq SELECT + INSERT); finalizer-invisible; NAK body NULL; AA body only when encrypted.
        now = time.time() if now is None else now
        dest = "\x1fack:" + inbound_name
        enc_body = self._enc(ack_body) if (ack_body and self._cipher.encrypts) else None
        enc_detail = self._enc(safe_text(detail)[:200]) if detail else None
        async with self._timed_acquire() as conn:
            async with conn.transaction():
                seq = await conn.fetchval(
                    "SELECT COALESCE(MAX(response_seq), 0) + 1 FROM response"
                    " WHERE message_id=$1 AND destination_name=$2 AND kind='ack_sent'",
                    message_id,
                    dest,
                )
                await conn.execute(
                    "INSERT INTO response"
                    " (message_id, destination_name, response_seq, body, outcome, detail,"
                    "  captured_at, kind, ack_code, ack_phase)"
                    " VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)",
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
                )

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
        # Pure observer: a single short INSERT in its own statement — no queue row, no finalizer, never
        # inside a handoff txn. reason rides the safe_text PHI chokepoint (#120) + the cipher.
        now = time.time() if now is None else now
        reason_enc = self._enc(safe_text(reason)[:200]) if reason else None
        await self._pool.execute(
            "INSERT INTO connection_event"
            " (ts, connection, transport, direction, kind, peer_host, message_id, reason)"
            " VALUES ($1,$2,$3,$4,$5,$6,$7,$8)",
            now,
            connection,
            transport,
            direction,
            kind,
            peer_host,
            message_id,
            reason_enc,
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
        params: list[Any] = []
        if connection is not None:
            params.append(connection)
            where.append(f"connection=${len(params)}")
        if kinds:
            placeholders = ",".join(f"${len(params) + i + 1}" for i in range(len(kinds)))
            params.extend(kinds)
            where.append(f"kind IN ({placeholders})")
        if since is not None:
            params.append(since)
            where.append(f"ts>=${len(params)}")
        # Per-channel RBAC: a scoped caller sees ONLY their own inbound-direction events and never any
        # outbound row (which spans channels), matching the SQLite path and the metadata/purge boundary.
        if allowed_channels is not None:
            where.append("direction='inbound'")
            _append_channel_scope_pg(where, params, "connection", allowed_channels)
        clause = (" WHERE " + " AND ".join(where)) if where else ""
        params.append(limit)
        rows = await self._pool.fetch(
            "SELECT id, ts, connection, transport, direction, kind, peer_host, message_id, reason"
            f" FROM connection_event{clause} ORDER BY ts DESC, id DESC LIMIT ${len(params)}",
            *params,
        )
        return [
            ConnectionEvent(
                id=r["id"],
                ts=r["ts"],
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
        # (event_type, connection) key. ON CONFLICT on the partial unique index folds a re-fire into the
        # live instance (bump last_seen + count, refresh severity/reason); an acknowledged instance stays
        # acknowledged (COALESCE keeps acked_*). Atomic upsert in one statement. reason rides safe_text +
        # the cipher. The caller wraps it fail-soft.
        now = time.time() if now is None else now
        reason_enc = self._enc(safe_text(reason)[:200]) if reason else None
        await self._pool.execute(
            "INSERT INTO alert_instance"
            " (event_type, connection, severity, status, first_seen, last_seen, count, reason)"
            " VALUES ($1,$2,$3,'open',$4,$4,1,$5)"
            " ON CONFLICT (event_type, connection) WHERE status <> 'resolved' DO UPDATE SET"
            " last_seen=EXCLUDED.last_seen, count=alert_instance.count+1,"
            " severity=EXCLUDED.severity, reason=EXCLUDED.reason",
            event_type,
            connection,
            severity,
            now,
            reason_enc,
        )

    async def list_active_alert_instances(
        self,
        *,
        limit: int = 200,
        allowed_channels: Sequence[str] | None = None,
    ) -> list[AlertInstance]:
        limit = max(1, min(limit, 1000))  # server-side clamp
        where = ["status IN ('open','acknowledged')"]
        params: list[Any] = []
        if allowed_channels is not None:
            _append_channel_scope_pg(where, params, "connection", allowed_channels)
        clause = " WHERE " + " AND ".join(where)
        params.append(limit)
        rows = await self._pool.fetch(
            "SELECT id, event_type, connection, severity, status, first_seen, last_seen, count,"
            f" reason, acked_by, acked_at, resolved_at FROM alert_instance{clause}"
            f" ORDER BY last_seen DESC, id DESC LIMIT ${len(params)}",
            *params,
        )
        return [self._alert_instance_row(r) for r in rows]

    async def get_alert_instance(
        self, alert_id: int, *, allowed_channels: Sequence[str] | None = None
    ) -> AlertInstance | None:
        where = ["id=$1"]
        params: list[Any] = [alert_id]
        if allowed_channels is not None:
            _append_channel_scope_pg(where, params, "connection", allowed_channels)
        clause = " WHERE " + " AND ".join(where)
        row = await self._pool.fetchrow(
            "SELECT id, event_type, connection, severity, status, first_seen, last_seen, count,"
            f" reason, acked_by, acked_at, resolved_at FROM alert_instance{clause}",
            *params,
        )
        return self._alert_instance_row(row) if row is not None else None

    def _alert_instance_row(self, r: Any) -> AlertInstance:
        return AlertInstance(
            id=r["id"],
            event_type=r["event_type"],
            connection=r["connection"],
            severity=r["severity"],
            status=r["status"],
            first_seen=r["first_seen"],
            last_seen=r["last_seen"],
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
        result = await self._pool.execute(
            "UPDATE alert_instance SET status='acknowledged', acked_by=$1, acked_at=$2"
            " WHERE id=$3 AND status<>'resolved'",
            actor,
            now,
            alert_id,
        )
        return _rowcount(result) > 0

    async def resolve_alert_instance(self, alert_id: int, *, now: float | None = None) -> bool:
        now = time.time() if now is None else now
        result = await self._pool.execute(
            "UPDATE alert_instance SET status='resolved', resolved_at=$1"
            " WHERE id=$2 AND status<>'resolved'",
            now,
            alert_id,
        )
        return _rowcount(result) > 0

    async def resolve_alert_instances_for(
        self, *, event_type: str, connection: str, now: float | None = None
    ) -> int:
        now = time.time() if now is None else now
        result = await self._pool.execute(
            "UPDATE alert_instance SET status='resolved', resolved_at=$1"
            " WHERE event_type=$2 AND connection=$3 AND status<>'resolved'",
            now,
            event_type,
            connection,
        )
        return _rowcount(result)

    async def count_open_alerts_by_connection(self) -> dict[str, int]:
        rows = await self._pool.fetch(
            "SELECT connection, COUNT(*) AS n FROM alert_instance"
            " WHERE status='open' GROUP BY connection"
        )
        return {r["connection"]: int(r["n"]) for r in rows}

    async def purge_alert_instances(self, *, older_than: float, now: float | None = None) -> int:
        result = await self._pool.execute(
            "DELETE FROM alert_instance WHERE status='resolved' AND resolved_at IS NOT NULL"
            " AND resolved_at < $1",
            older_than,
        )
        return _rowcount(result)

    # <<< end alert_instance block (#56) >>>

    async def mark_failed(
        self, outbox_id: str, error: str, retry: RetryPolicy, now: float | None = None
    ) -> float | None:
        """Reschedule with exponential backoff, or dead-letter if retries are exhausted. Returns the
        new ``next_attempt_at`` when rescheduled, ``None`` when dead-lettered/missing (the runner
        arms the per-lane retry wake on a float — WS-C; see the base contract)."""
        error = safe_text(error)  # PHI chokepoint (#120)
        now = time.time() if now is None else now
        async with self._timed_acquire() as conn:
            async with conn.transaction():
                row = await conn.fetchrow("SELECT * FROM queue WHERE id=$1", outbox_id)
                if row is None:
                    return None
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
                    return None
                return next_at

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
        in-flight rows until their leases expire, so single-node keeps the unconditional path.

        The all-stages case runs one UPDATE per :class:`Stage` in a single transaction: the plain
        ``(stage, status)`` equality pair seeks ``ix_queue_ready``, where the previous
        ``($4 IS NULL OR stage=$4)`` predicate was unsargable under a generic plan and full-scanned
        the queue on every open — a measured contributor to the WS-B co-start lock convoy.
        Iterating the enum keeps a future stage automatically covered."""
        now = time.time() if now is None else now
        stages = [stage] if stage is not None else [s.value for s in Stage]
        sql = (
            "UPDATE queue SET status=$1, next_attempt_at=$2, updated_at=$2,"
            " owner=NULL, lease_expires_at=NULL"
            " WHERE status=$3 AND stage=$4"
        )
        recovered = 0
        async with self._timed_acquire() as conn:
            async with conn.transaction():
                for st in stages:
                    result = await conn.execute(
                        sql, OutboxStatus.PENDING.value, now, OutboxStatus.INFLIGHT.value, st
                    )
                    recovered += _rowcount(result)
        return recovered

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
        async with self._timed_acquire() as conn:
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
        async with self._timed_acquire() as conn:
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
        async with self._timed_acquire() as conn:
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
        async with self._timed_acquire() as conn:
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
                if not stuck:
                    # RE-SEND branch (H2): drop the idempotency-ledger entries of THIS message's DONE
                    # rows (the exact set re-pended below) so a deliberate re-send is NOT skip-and-
                    # completed as a crash-re-run duplicate. Scoped to this message only.
                    await conn.execute(
                        "DELETE FROM delivered_keys WHERE outbox_id IN"
                        " (SELECT id FROM queue WHERE message_id=$1 AND status=$2)",
                        message_id,
                        OutboxStatus.DONE.value,
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
        async with self._timed_acquire() as conn:
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
        # `top_only` cancels the true FIFO head, so the tiebreak after next_attempt_at must match the
        # claim's seq-only order, NOT created_at (no longer the ordering key; ADR 0059).
        query = (
            "SELECT id, message_id FROM queue"
            " WHERE destination_name=$1 AND status=$2 AND ($3::text IS NULL OR channel_id=$3)"
            " ORDER BY next_attempt_at, seq"
        )
        if top_only:
            query += " LIMIT 1"
        async with self._timed_acquire() as conn:
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
        d["summary"] = self._dec(d["summary"])  # EF-3: MRN/name PHI, ciphered at rest
        d["metadata"] = self._dec(d["metadata"])  # EF-3
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
        return [self._decode_record(r, "error", "summary", "metadata") for r in rows]

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
        event loop (a plain SQL ``LIKE`` can't match the at-rest AES-GCM ciphertext)."""
        where, params = self._message_filter(
            channel_id, status, message_type, control_id, allowed_channels
        )
        rows = await self._fetchall(
            "SELECT id, channel_id, received_at, source_type, control_id, message_type,"
            " status, error, summary, metadata, raw,"
            " (SELECT event FROM message_events e WHERE e.message_id = messages.id"
            "  ORDER BY e.id DESC LIMIT 1) AS last_event"
            f" FROM messages{where}"
            " ORDER BY received_at DESC, id DESC",
            *params,
        )
        return await asyncio.to_thread(self._scan_rows, spec, rows, limit)

    def _scan_rows(
        self, spec: SearchSpec, candidates: Sequence[Any], limit: int
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
            raw = self._dec(cand["raw"])
            summary = self._dec(cand["summary"])
            if row_matches(spec, raw=raw, summary=summary):
                d = self._decode_record(cand, "error", "summary", "metadata")
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
        return [self._decode_record(r, "last_error", "summary") for r in rows]

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
        async with self._timed_acquire() as conn:
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
        async with self._timed_acquire() as conn:
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
        async with self._timed_acquire() as conn:
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
        async with self._timed_acquire() as conn:
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

    # --- WebAuthn credentials (WP-14b, ADR 0068) ------------------------------

    async def add_webauthn_credential(self, cred: WebAuthnCredential) -> None:
        """Persist one enrolled passkey. Public keys are plaintext by design (COSE verification
        material, not a secret — excluded from the store cipher). A duplicate ``(user_id, label)``
        raises asyncpg's UniqueViolationError — the caller renders it as the same "label already in
        use" error as its pre-check (the concurrent-enroll race, ADR 0068 §4)."""
        await self._execute(
            "INSERT INTO webauthn_credentials (credential_id_hash, credential_id, user_id,"
            " rp_id, public_key, sign_count, transports, device_type, backed_up, label,"
            " aaguid, created_at, last_used_at)"
            " VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)",
            cred.credential_id_hash,
            cred.credential_id,
            cred.user_id,
            cred.rp_id,
            cred.public_key,
            cred.sign_count,
            json.dumps(cred.transports) if cred.transports is not None else None,
            cred.device_type,
            cred.backed_up,
            cred.label,
            cred.aaguid,
            cred.created_at,
            cred.last_used_at,
        )

    async def list_webauthn_credentials(self, user_id: str) -> list[WebAuthnCredential]:
        """All of a user's enrolled passkeys, oldest first."""
        rows = await self._fetchall(
            "SELECT * FROM webauthn_credentials WHERE user_id=$1 ORDER BY created_at, label",
            user_id,
        )
        return [WebAuthnCredential.from_mapping(dict(r)) for r in rows]

    async def get_webauthn_credential(self, credential_id_hash: str) -> WebAuthnCredential | None:
        """One credential by its id-hash PK, or None."""
        d = await self._fetchone(
            "SELECT * FROM webauthn_credentials WHERE credential_id_hash=$1", credential_id_hash
        )
        return WebAuthnCredential.from_mapping(dict(d)) if d else None

    async def has_webauthn_credentials(self, user_id: str) -> bool:
        """True when the user has at least one enrolled passkey (the second-factor predicate)."""
        d = await self._fetchone(
            "SELECT 1 FROM webauthn_credentials WHERE user_id=$1 LIMIT 1", user_id
        )
        return d is not None

    async def any_webauthn_credentials(self) -> bool:
        """True when ANY passkey is enrolled — the L5b extra-less-install startup advisory's
        cheap probe (ADR 0068 decision 5)."""
        row = await self._fetchone("SELECT 1 AS present FROM webauthn_credentials LIMIT 1")
        return row is not None

    async def delete_webauthn_credential(self, user_id: str, credential_id_hash: str) -> bool:
        """Delete one credential; True iff a row was removed (rowcount-guarded — the ``user_id``
        predicate keeps the action self-scoped even if a foreign id-hash is submitted)."""
        result = await self._pool.execute(
            "DELETE FROM webauthn_credentials WHERE user_id=$1 AND credential_id_hash=$2",
            user_id,
            credential_id_hash,
        )
        return _rowcount(result) > 0

    async def delete_all_webauthn_credentials(self, user_id: str) -> int:
        """Remove every credential for a user (``admin_reset_mfa``); returns the count removed."""
        result = await self._pool.execute(
            "DELETE FROM webauthn_credentials WHERE user_id=$1", user_id
        )
        return _rowcount(result)

    async def update_webauthn_sign_count(
        self, credential_id_hash: str, *, expected: int, new: int, used_at: float
    ) -> bool:
        """Strict compare-and-set of the authenticator sign counter (the ``consume_totp_step``
        precedent): ``True`` iff the stored count still equalled ``expected``. A miss means a
        concurrent assertion consumed the same counter — the caller treats it as a clone signal
        (ADR 0068 §4). The ``SELECT ... FOR UPDATE`` + guarded ``UPDATE`` run in one transaction
        (no cross-node double-spend)."""
        async with self._timed_acquire() as conn:
            async with conn.transaction():
                row = await conn.fetchrow(
                    "SELECT sign_count FROM webauthn_credentials WHERE credential_id_hash=$1"
                    " FOR UPDATE",
                    credential_id_hash,
                )
                if row is None or row["sign_count"] != expected:
                    return False  # consumed by a concurrent assertion — clone signal
                await conn.execute(
                    "UPDATE webauthn_credentials SET sign_count=$1, last_used_at=$2"
                    " WHERE credential_id_hash=$3",
                    new,
                    used_at,
                    credential_id_hash,
                )
                return True

    async def delete_user(self, user_id: str) -> None:
        async with self._timed_acquire() as conn:
            async with conn.transaction():
                await conn.execute("DELETE FROM user_roles WHERE user_id=$1", user_id)
                await conn.execute("DELETE FROM sessions WHERE user_id=$1", user_id)
                await conn.execute("DELETE FROM webauthn_credentials WHERE user_id=$1", user_id)
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
        permissions: str | None = None,
    ) -> None:
        await self._execute(
            "INSERT INTO roles (id, display_name, description, builtin, permissions)"
            " VALUES ($1,$2,$3,$4,$5)"
            " ON CONFLICT (id) DO UPDATE SET display_name=excluded.display_name,"
            " description=excluded.description, builtin=excluded.builtin,"
            " permissions=excluded.permissions",
            role_id,
            display_name,
            description,
            builtin,
            permissions,
        )

    async def list_roles(self) -> Sequence[Row]:
        return await self._fetchall("SELECT * FROM roles ORDER BY id")

    async def get_role(self, role_id: str) -> Row | None:
        rows = await self._fetchall("SELECT * FROM roles WHERE id=$1", role_id)
        return rows[0] if rows else None

    async def delete_custom_role(self, role_id: str) -> bool:
        """Delete a custom (``builtin=FALSE``) role and its user/AD-group assignments in one
        transaction (ADR 0045 D4); never touches a built-in row. Returns ``True`` if removed."""
        async with self._timed_acquire() as conn:
            async with conn.transaction():
                row = await conn.fetchrow("SELECT builtin FROM roles WHERE id=$1", role_id)
                if row is None or bool(row["builtin"]):
                    return False
                await conn.execute("DELETE FROM user_roles WHERE role_id=$1", role_id)
                await conn.execute("DELETE FROM ad_group_role_map WHERE role_id=$1", role_id)
                await conn.execute("DELETE FROM roles WHERE id=$1", role_id)
                return True

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
        async with self._timed_acquire() as conn:
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
        async with self._timed_acquire() as conn:
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
        async with self._timed_acquire() as conn:
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

    async def purge_message_bodies(
        self,
        *,
        older_than: float,
        now: float | None = None,
        connection_cutoffs: Mapping[str, float] | None = None,
    ) -> int:
        """Null the PHI **bodies** of fully-resolved messages received before ``older_than`` while
        keeping their metadata rows (the Mirth Data-Pruner pattern). Eligible only when the message has
        no queue row still ``pending``/``inflight``. Ported, not stubbed — Postgres supports retention.
        Returns the number of messages whose body was nulled.

        ``connection_cutoffs`` (#34, ADR 0027) optionally overrides the cutoff per ``channel_id``
        (``float('-inf')`` = keep forever); default empty ⇒ a single global cutoff, byte-identical to
        the prior behaviour. AND-ed with the unchanged in-flight guard."""
        now = time.time() if now is None else now
        inflight = [OutboxStatus.PENDING.value, OutboxStatus.INFLIGHT.value]
        # Per-connection cutoff (#34): bare "$1" (global) when no override, else a CASE on
        # m.channel_id; the inflight[] array follows at the next free placeholder. The two together are
        # the LEADING binds (cutoff params then inflight) shared by every UPDATE below; each outer query
        # continues numbering from `nxt` for its own binds (stage/status arrays).
        cutoff_sql, cutoff_params, idx = _pg_cutoff_case(
            "m.channel_id", older_than, connection_cutoffs
        )
        inflight_ph = idx  # placeholder index for the inflight[] array
        nxt = idx + 1  # first free placeholder for an outer query's own binds
        # A message past its (per-connection-or-global) cutoff with nothing still in flight. Embedded in
        # the UPDATEs below; its binds (cutoff_params + inflight) lead, so each outer query passes them
        # FIRST and continues its own binds from $nxt.
        eligible = (
            f"SELECT id FROM messages m WHERE m.received_at < {cutoff_sql}"
            f" AND NOT EXISTS (SELECT 1 FROM queue q WHERE q.message_id = m.id"
            f" AND q.status = ANY(${inflight_ph}::text[]))"
        )
        lead = [*cutoff_params, inflight]
        async with self._timed_acquire() as conn:
            async with conn.transaction():
                result = await conn.execute(
                    f"UPDATE messages SET raw='', summary=NULL, error=NULL"
                    f" WHERE raw <> '' AND id IN ({eligible})",
                    *lead,
                )
                purged = _rowcount(result)
                await conn.execute(
                    f"UPDATE queue SET payload='', last_error=NULL"
                    f" WHERE stage=${nxt} AND status = ANY(${nxt + 1}::text[]) AND payload <> ''"
                    f" AND message_id IN ({eligible})",
                    *lead,
                    Stage.OUTBOUND.value,
                    [OutboxStatus.DONE.value, OutboxStatus.CANCELLED.value],
                )
                await conn.execute(
                    f"UPDATE message_events SET detail=NULL"
                    f" WHERE detail IS NOT NULL AND message_id IN ({eligible})",
                    *lead,
                )
                # Captured replies (ADR 0013) are PHI on the same window as the body; null in place
                # (row kept, FK to messages(id) never violated — purge keeps the messages row).
                await conn.execute(
                    f"UPDATE response SET body=NULL, detail=NULL"
                    f" WHERE (body IS NOT NULL OR detail IS NOT NULL) AND message_id IN ({eligible})",
                    *lead,
                )
        return purged

    async def strip_embedded_documents(
        self,
        *,
        older_than: float,
        now: float | None = None,
        connection_cutoffs: Mapping[str, float] | None = None,
        min_bytes: int = 0,
        content_types: Mapping[str, str] | None = None,
    ) -> StripResult:
        """Strip bulky base64 embedded documents in place (#47, ADR 0042 D2) — the Postgres port of the
        select → codec-transform → write-back path. Replaces each ``mfb64:v1:`` carriage value / HL7
        OBX-5 ED embed with a self-describing tombstone, keeps the message parseable, and sets
        ``documents_pruned``. Eligibility mirrors :meth:`purge_message_bodies` (per-connection-or-global
        cutoff AND not in-flight). Returns a :class:`StripResult` (counts + bytes; no PHI)."""
        now = time.time() if now is None else now
        content_types = content_types or {}
        inflight = [OutboxStatus.PENDING.value, OutboxStatus.INFLIGHT.value]
        # Bound the candidate scan with the LOOSEST finite cutoff (a keep-forever -inf never widens it);
        # the precise per-connection cutoff is re-checked per row in Python (cutoff_for).
        finite = [
            c for c in [older_than, *(connection_cutoffs or {}).values()] if c != float("-inf")
        ]
        if not finite:
            return StripResult()  # everything keep-forever ⇒ nothing to scan
        scan_cutoff = max(finite)
        async with self._timed_acquire() as conn:
            rows = await conn.fetch(
                "SELECT m.id, m.channel_id, m.raw, m.received_at FROM messages m"
                " WHERE m.raw <> '' AND m.documents_pruned IS NULL AND m.received_at < $1"
                " AND NOT EXISTS (SELECT 1 FROM queue q WHERE q.message_id = m.id"
                " AND q.status = ANY($2::text[]))",
                scan_cutoff,
                inflight,
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
                async with conn.transaction():
                    await conn.executemany(
                        "UPDATE messages SET raw=$1, documents_pruned=$2 WHERE id=$3", updates
                    )
        return StripResult(
            messages_stripped=msgs, documents_stripped=docs, bytes_reclaimed=reclaimed
        )

    async def purge_connection_events(self, *, older_than: float, now: float | None = None) -> int:
        # #46: metadata-only rows (no body/FK) — age-DELETE on their own window (RetentionRunner-driven).
        result = await self._pool.execute("DELETE FROM connection_event WHERE ts < $1", older_than)
        return _rowcount(result)

    async def purge_dead_letters(
        self,
        *,
        older_than: float,
        now: float | None = None,
        connection_cutoffs: Mapping[str, float] | None = None,
    ) -> int:
        """Null the bodies of dead-lettered **outbound** rows last updated before ``older_than`` (their
        own retention window). Keeps the row + ``dead`` status; blanks ``payload`` + ``last_error``.
        Ported, not stubbed. Returns the number of dead rows purged.

        ``connection_cutoffs`` (#34, ADR 0027) optionally overrides the cutoff per ``destination_name``
        (``float('-inf')`` = keep forever); default empty ⇒ a single global cutoff, byte-identical to
        the prior behaviour."""
        now = time.time() if now is None else now
        # stage/status are $1/$2; the cutoff CASE (#34) numbers from $3 onward.
        cutoff_sql, cutoff_params, _ = _pg_cutoff_case(
            "destination_name", older_than, connection_cutoffs, start=3
        )
        result = await self._pool.execute(
            "UPDATE queue SET payload='', last_error=NULL"
            f" WHERE stage=$1 AND status=$2 AND payload <> '' AND updated_at < {cutoff_sql}",
            Stage.OUTBOUND.value,
            OutboxStatus.DEAD.value,
            *cutoff_params,
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
        async with self._timed_acquire() as conn:
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

    async def snapshot_to(self, dest_path: str | object, *, method: str = "vacuum_into") -> None:
        """**DBA-delegated** on Postgres (ADR 0049 / BACKLOG #52): the engine never takes a DB-tier
        backup of a server-DB store — ``pg_dump`` / PITR are infra-owned. Raises
        :class:`~messagefoundry.store.base.DbaDelegatedError`; the BackupRunner / ``backup`` CLI catch it
        and fall back to a config-only backup (or skip) per ``[backup].config_only_on_server_db``."""
        from messagefoundry.store.base import DbaDelegatedError

        raise DbaDelegatedError(
            "the postgres store backup is DBA-delegated (pg_dump / PITR, BACKLOG #52); the engine backs "
            "up the config bundle only on a server-DB store (set [backup].config_only_on_server_db)"
        )

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
            synchronous=None,  # SQLite-only knob; Postgres WAL durability is not a per-store PRAGMA
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


def _pg_cutoff_case(
    column: str,
    global_cutoff: float,
    connection_cutoffs: Mapping[str, float] | None,
    start: int = 1,
) -> tuple[str, list[Any], int]:
    """Build a ``$N``-placeholder cutoff expression for the per-connection retention override (#34,
    ADR 0027) on Postgres, numbering its binds from ``$start``.

    With no override (``connection_cutoffs`` empty/None) this returns ``("$start", [global_cutoff],
    start + 1)`` — **byte-identical** to the single global ``$1`` cutoff today. With overrides it returns
    a ``CASE <column> WHEN $a THEN $b ... ELSE $z END`` whose per-connection ``THEN`` cutoffs come from
    the map and whose ``ELSE`` is the global cutoff (a connection absent from the map inherits the global
    window); a keep-forever override is carried as ``float('-inf')`` (``received_at < -inf`` always
    false). Returns ``(sql, params, next_index)`` where ``next_index`` is the first free placeholder so
    the caller can continue numbering its own binds after it."""
    if not connection_cutoffs:
        return f"${start}", [global_cutoff], start + 1
    whens: list[str] = []
    params: list[Any] = []
    idx = start
    for name, cutoff in connection_cutoffs.items():
        whens.append(f"WHEN ${idx} THEN ${idx + 1}")
        params.append(name)
        params.append(cutoff)
        idx += 2
    params.append(global_cutoff)  # ELSE — connections with no override use the global window
    sql = f"(CASE {column} {' '.join(whens)} ELSE ${idx} END)"
    return sql, params, idx + 1


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
