"""Durable message store + queue (SQLite WAL, transactional inbox/outbox).

The store *is* the queue. ``enqueue_message`` persists the inbound message and one
outbox row per destination **in a single transaction**, so once the source is ACKed the
work is guaranteed durable. Per-destination workers ``claim_ready`` rows, deliver, then
``mark_done`` or ``mark_failed`` (which reschedules with backoff or dead-letters).

Delivery semantics: **at-least-once**. A crash mid-delivery leaves a row ``inflight``;
``reset_stale_inflight`` (called on startup) returns those to ``pending`` so they are
retried. Destinations are expected to be idempotent — the inbound control id (MSH-10) is
persisted for de-duplication/correlation.

PHI note: message bodies are sensitive. Bodies pass through the store's ``_cipher``
(:mod:`messagefoundry.store.crypto`) on write/read — AES-256-GCM at rest when a key is configured,
identity otherwise — so encryption is transparent to callers (STORE-1).

Time is injected (``now`` params default to ``time.time()``) so retry scheduling and
dead-lettering are deterministically testable.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import shutil
import stat
import subprocess
import time
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Sequence
from uuid import uuid4

import aiosqlite

from messagefoundry.config.models import RetryPolicy
from messagefoundry.store.crypto import PREFIX as _ENC_PREFIX
from messagefoundry.store.crypto import AesGcmCipher, Cipher, IdentityCipher

log = logging.getLogger(__name__)


class MessageStatus(str, Enum):
    RECEIVED = "received"  # persisted at ingress, awaiting router+transform (staged pipeline)
    ROUTED = "routed"  # router produced ≥1 delivery; outbound rows queued, awaiting delivery
    PROCESSED = "processed"  # all destinations terminal (done or dead)
    ERROR = "error"  # parse/validation/processing failure (dead-lettered); logged, not routed
    FILTERED = "filtered"  # rejected by the channel filter; logged, intentionally not routed
    UNROUTED = "unrouted"  # accepted but no destination matched; logged, delivered nowhere


class OutboxStatus(str, Enum):
    PENDING = "pending"  # waiting, due at next_attempt_at
    INFLIGHT = "inflight"  # claimed by a worker, delivery in progress
    DONE = "done"  # delivered successfully
    DEAD = "dead"  # exhausted retries; needs manual replay
    CANCELLED = "cancelled"  # purged from the queue by an operator (terminal, non-error)


class Stage(str, Enum):
    """Which pipeline stage a ``queue`` row belongs to (the stage discriminator).

    The staged pipeline (ADR 0001 Step B) has **three persisted stages**, ``ingress`` → ``routed`` →
    ``outbound``:

    * ``ingress`` — the raw inbound message, durably committed before the ACK (ACK-on-receipt). The
      **router worker** drains it.
    * ``routed`` — **one row per handler the router selected** (carrying ``handler_name``), awaiting
      transform. Produced by the router worker's handoff; the **transform worker** drains it.
    * ``outbound`` — one row per destination delivery (the transformed payload). Produced by the
      transform worker's handoff; the per-outbound **delivery workers** drain it.

    Both ``ingress`` and ``routed`` rows hold the raw body and are *consumed* (deleted) at their
    handoff, so the raw is never kept twice at rest. Note ``Stage.ROUTED`` (a row's stage) is distinct
    from ``MessageStatus.ROUTED`` (a message's disposition)."""

    INGRESS = "ingress"
    ROUTED = "routed"
    OUTBOUND = "outbound"


@dataclass(frozen=True)
class OutboxItem:
    """A unit of staged work: a raw message at the ingress stage, one handler assignment at the routed
    stage, or one message→destination delivery at the outbound stage. ``stage`` tells a generalized
    worker which it is. ``destination_name`` is set only on outbound rows; ``handler_name`` only on
    routed rows (it names the handler the transform worker must run) — both ``None`` otherwise."""

    id: str
    message_id: str
    channel_id: str
    destination_name: str | None
    payload: str
    attempts: int
    stage: str
    handler_name: str | None = None

    @classmethod
    def from_row(cls, row: aiosqlite.Row, cipher: Cipher) -> "OutboxItem":
        return cls(
            id=row["id"],
            message_id=row["message_id"],
            channel_id=row["channel_id"],
            destination_name=row["destination_name"],
            payload=cipher.decrypt(row["payload"]),  # decrypt the body for processing/delivery
            attempts=row["attempts"],
            stage=row["stage"],
            # Plaintext metadata (the handler to run), not a body — never encrypted. NULL off-routed.
            handler_name=row["handler_name"],
        )


@dataclass(frozen=True)
class InboundMetrics:
    """Per-channel inbound aggregates for the connections dashboard."""

    read: int  # messages received since `since`
    errored: int  # messages that failed intake/validation since `since`
    last_at: float | None  # most recent inbound (all-time), for idle time


@dataclass(frozen=True)
class DestinationMetrics:
    """Per-(channel, destination) outbound aggregates for the connections dashboard."""

    queue_depth: int  # current pending + inflight
    written: int  # delivered since `since`
    dead: int  # dead-lettered since `since`
    oldest_pending_at: float | None  # created_at of oldest queued row (for delivered age)
    recent_done: int  # deliveries within rate_window (for backlog ETA)
    last_done_at: float | None  # most recent delivery (all-time), for idle time


@dataclass(frozen=True)
class ConnectionMetrics:
    inbound: dict[str, InboundMetrics]  # by channel_id
    destinations: dict[tuple[str, str], DestinationMetrics]  # by (channel_id, destination_name)


@dataclass(frozen=True)
class DbStatus:
    """Database health snapshot for the Engine Status page."""

    path: str
    size_bytes: int  # db file + -wal + -shm
    disk_free_bytes: int  # free space on the DB's drive
    journal_mode: str
    messages: int
    events: int
    audit: int


@dataclass(frozen=True)
class UserRecord:
    """A user account (local or AD). ``password_hash`` + lockout fields are NULL for AD users."""

    id: str
    username: str
    auth_provider: str  # 'local' | 'ad'
    display_name: str | None
    email: str | None
    disabled: bool
    created_at: float
    updated_at: float
    last_login_at: float | None
    password_hash: str | None
    password_changed_at: float | None
    must_change_password: bool
    failed_attempts: int
    locked_until: float | None
    channel_scope: str | None = (
        None  # JSON list of allowed connection names; None = all (per-channel RBAC)
    )

    @classmethod
    def from_mapping(cls, d: Mapping[str, Any]) -> "UserRecord":
        return cls(
            id=d["id"],
            username=d["username"],
            auth_provider=d["auth_provider"],
            display_name=d["display_name"],
            email=d["email"],
            disabled=bool(d["disabled"]),
            created_at=float(d["created_at"]),
            updated_at=float(d["updated_at"]),
            last_login_at=_opt_float(d["last_login_at"]),
            password_hash=d["password_hash"],
            password_changed_at=_opt_float(d["password_changed_at"]),
            must_change_password=bool(d["must_change_password"]),
            failed_attempts=int(d["failed_attempts"]),
            locked_until=_opt_float(d["locked_until"]),
            channel_scope=d.get("channel_scope"),
        )


@dataclass(frozen=True)
class SessionRecord:
    """A server-side session. The opaque token is never stored — only ``token_hash`` (sha256)."""

    token_hash: str
    user_id: str
    created_at: float
    expires_at: float
    last_used_at: float
    revoked_at: float | None
    client: str | None

    @classmethod
    def from_mapping(cls, d: Mapping[str, Any]) -> "SessionRecord":
        return cls(
            token_hash=d["token_hash"],
            user_id=d["user_id"],
            created_at=float(d["created_at"]),
            expires_at=float(d["expires_at"]),
            last_used_at=float(d["last_used_at"]),
            revoked_at=_opt_float(d["revoked_at"]),
            client=d["client"],
        )


# PHI-at-rest encryption is the store's `_cipher` (messagefoundry.store.crypto): identity when no
# key is configured, AES-256-GCM when MEFOR_STORE_ENCRYPTION_KEY is set. See STORE-1.


def audit_row_hash(
    prev_hash: str,
    *,
    ts: float,
    actor: str | None,
    action: str,
    channel_id: str | None,
    detail: str | None,
) -> str:
    """SHA-256 of (previous row's hash ‖ this row's content) — the audit-log tamper-evidence chain.

    Each row's hash folds in the prior row's, so editing, reordering, or deleting an *interior* row
    breaks verification from that point on (AUDIT-INTEGRITY). Deleting the *newest* rows is not caught
    by re-walking the chain (the surviving prefix still verifies) — that needs the external anchor; see
    :meth:`MessageStore.audit_anchor`. The chain is unkeyed, so it detects tampering, not a fully
    re-computed forgery by someone who can write rows. Shared by both store backends."""
    canonical = json.dumps(
        [prev_hash, ts, actor, action, channel_id, detail], sort_keys=True, default=str
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


_OWNER_ONLY = stat.S_IRUSR | stat.S_IWUSR  # 0o600


def _current_user() -> str | None:
    """The current OS user for an owner-only DACL, with a fallback when ``%USERNAME%`` is empty
    (some NSSM/service contexts) — ``getpass.getuser`` consults the process token, not just env."""
    user = os.environ.get("USERNAME")
    if user:
        return user
    try:
        import getpass

        return getpass.getuser() or None
    except Exception:  # getpass can raise if it can't resolve a name
        return None


def _secure_file(path: Path) -> None:
    """Restrict a store file to its owner — it holds PHI at rest.

    Best-effort and non-fatal: failing to tighten permissions must never stop the engine from
    starting (``docs/PHI.md``'s ops checklist covers directory-level ACLs as the backstop). On
    POSIX this is ``chmod 0600``; on Windows ``os.chmod`` only toggles the read-only bit, so we set
    an owner-only DACL via ``icacls`` (inheritance disabled) instead. A skipped or failed
    restriction is **logged** (STORE-2) so it isn't silently world-readable.
    """
    try:
        if os.name == "nt":
            user = _current_user()
            if not user:
                log.warning(
                    "could not determine current user; %s keeps its inherited (possibly broad) ACL "
                    "— set a directory ACL per docs/SERVICE.md",
                    path,
                )
                return
            # icacls is a fixed system tool, invoked without a shell; argv carries no user input (low-27).
            result = subprocess.run(  # nosec B603 B607
                ["icacls", str(path), "/inheritance:r", "/grant:r", f"{user}:F"],
                check=False,
                capture_output=True,
                text=True,
            )
            if result.returncode != 0:
                log.warning(
                    "icacls could not restrict %s (exit %s): %s",
                    path,
                    result.returncode,
                    (result.stderr or result.stdout or "").strip(),
                )
        else:
            os.chmod(path, _OWNER_ONLY)
    except OSError as exc:
        log.warning("could not restrict permissions on %s: %s", path, exc)


def _opt_float(value: Any) -> float | None:
    """Coerce a possibly-NULL epoch column to ``float | None`` (a backend may return int/Decimal)."""
    return None if value is None else float(value)


def _append_channel_scope(
    clauses: list[str],
    params: list[object],
    column: str,
    allowed_channels: Sequence[str] | None,
) -> None:
    """Restrict ``column`` to a per-channel RBAC scope (per-channel RBAC). ``None`` = no restriction
    (all channels); an empty set = match nothing. ``column`` is a code-controlled literal."""
    if allowed_channels is None:
        return
    if allowed_channels:
        placeholders = ",".join("?" * len(allowed_channels))  # count-bound, not user text
        clauses.append(f"{column} IN ({placeholders})")
        params.extend(allowed_channels)
    else:
        clauses.append("1=0")  # scoped to no channels


_SCHEMA = """
CREATE TABLE IF NOT EXISTS messages (
    id           TEXT PRIMARY KEY,
    channel_id   TEXT NOT NULL,
    received_at  REAL NOT NULL,
    source_type  TEXT,
    control_id   TEXT,             -- MSH-10, for dedup/correlation
    message_type TEXT,             -- MSH-9, e.g. ADT^A01
    raw          TEXT NOT NULL,    -- inbound body (encoded)
    status       TEXT NOT NULL,
    error        TEXT,
    summary      TEXT,             -- ingest-derived (MRN/name/order); kept out of raw for fast search
    metadata     TEXT              -- code/operator-attached values (mechanism TBD)
);
CREATE INDEX IF NOT EXISTS ix_messages_channel  ON messages(channel_id, received_at);
CREATE INDEX IF NOT EXISTS ix_messages_control  ON messages(channel_id, control_id);

-- Generic staged-queue table (staged pipeline, ADR 0001). One table for every stage; the `stage`
-- column discriminates ingress | routed | outbound rows. Supersedes the original `outbox` table
-- (legacy DBs migrate their rows in as stage='outbound' — see _migrate). `destination_name` is set
-- only on outbound rows; `handler_name` only on routed rows (the handler the transform worker runs).
-- Both are NULL otherwise. (The "set only on stage X" invariants are enforced in code — only the
-- stage's producer writes the column — not by a CHECK, which SQLite can't ADD to a live table.)
CREATE TABLE IF NOT EXISTS queue (
    id               TEXT PRIMARY KEY,
    message_id       TEXT NOT NULL REFERENCES messages(id),
    stage            TEXT NOT NULL,   -- 'ingress' | 'routed' | 'outbound'
    channel_id       TEXT NOT NULL,   -- inbound connection name
    destination_name TEXT,            -- outbound connection name; NULL for ingress/routed rows
    handler_name     TEXT,            -- handler to run; set only on routed rows, NULL otherwise
    payload          TEXT NOT NULL,   -- stage body (encoded): ingress/routed=raw, outbound=transformed
    status           TEXT NOT NULL,
    attempts         INTEGER NOT NULL DEFAULT 0,
    next_attempt_at  REAL NOT NULL,
    last_error       TEXT,
    created_at       REAL NOT NULL,
    updated_at       REAL NOT NULL
);
-- Claim hot path (claim_ready), per stage:
CREATE INDEX IF NOT EXISTS ix_queue_ready ON queue(stage, status, next_attempt_at);
-- Per-stage FIFO head-of-line: outbound lanes key on destination_name; ingress AND routed lanes on
-- channel_id (ix_queue_fifo_in serves both — `stage` is the leading column, so no separate routed
-- index is needed). (FIFO ORDER BY is created_at then the implicit rowid — rowid can't be indexed.)
CREATE INDEX IF NOT EXISTS ix_queue_fifo_out ON queue(stage, destination_name, status, created_at);
CREATE INDEX IF NOT EXISTS ix_queue_fifo_in  ON queue(stage, channel_id, status, created_at);
CREATE INDEX IF NOT EXISTS ix_queue_message  ON queue(message_id);

CREATE TABLE IF NOT EXISTS message_events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    message_id  TEXT NOT NULL REFERENCES messages(id),
    ts          REAL NOT NULL,
    event       TEXT NOT NULL,        -- received|delivered|failed|dead|replayed|viewed...
    destination TEXT,
    detail      TEXT
);
CREATE INDEX IF NOT EXISTS ix_events_message ON message_events(message_id, ts);

CREATE TABLE IF NOT EXISTS audit_log (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ts          REAL NOT NULL,
    actor       TEXT,                 -- who: a username or 'system' (auth is built; always populated)
    action      TEXT NOT NULL,        -- e.g. summary_search_display, message_view, export
    channel_id  TEXT,
    detail      TEXT,                 -- JSON: filter, counts, exposed ids, ...
    row_hash    TEXT                  -- sha256 chain over (prev_hash + this row): tamper-evidence
);
CREATE INDEX IF NOT EXISTS ix_audit_ts ON audit_log(ts);

CREATE TABLE IF NOT EXISTS users (
    id                   TEXT PRIMARY KEY,
    username             TEXT NOT NULL UNIQUE,
    auth_provider        TEXT NOT NULL,        -- 'local' | 'ad'
    display_name         TEXT,
    email                TEXT,
    disabled             INTEGER NOT NULL DEFAULT 0,
    created_at           REAL NOT NULL,
    updated_at           REAL NOT NULL,
    last_login_at        REAL,
    password_hash        TEXT,                 -- argon2id; NULL for AD users
    password_changed_at  REAL,
    must_change_password INTEGER NOT NULL DEFAULT 0,
    failed_attempts      INTEGER NOT NULL DEFAULT 0,
    locked_until         REAL,
    channel_scope        TEXT                  -- per-channel RBAC: JSON list of connections; NULL = all
);

CREATE TABLE IF NOT EXISTS roles (
    id           TEXT PRIMARY KEY,             -- Role value, e.g. 'administrator'
    display_name TEXT NOT NULL,
    description  TEXT,
    builtin      INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS user_roles (
    user_id     TEXT NOT NULL REFERENCES users(id),
    role_id     TEXT NOT NULL REFERENCES roles(id),
    assigned_at REAL NOT NULL,
    assigned_by TEXT,
    PRIMARY KEY (user_id, role_id)
);

CREATE TABLE IF NOT EXISTS ad_group_role_map (
    ad_group TEXT NOT NULL,                    -- AD group (lower-cased): DN or sAMAccountName
    role_id  TEXT NOT NULL REFERENCES roles(id),
    PRIMARY KEY (ad_group, role_id)
);

CREATE TABLE IF NOT EXISTS ad_group_scope_map (
    ad_group TEXT NOT NULL,                    -- AD group (lower-cased): DN or sAMAccountName
    channel  TEXT NOT NULL,                    -- inbound connection name, or '*' for all channels
    PRIMARY KEY (ad_group, channel)
);

CREATE TABLE IF NOT EXISTS sessions (
    token_hash   TEXT PRIMARY KEY,             -- sha256 hex of the opaque token (never the token)
    user_id      TEXT NOT NULL REFERENCES users(id),
    created_at   REAL NOT NULL,
    expires_at   REAL NOT NULL,
    last_used_at REAL NOT NULL,
    revoked_at   REAL,
    client       TEXT
);
CREATE INDEX IF NOT EXISTS ix_sessions_user    ON sessions(user_id);
CREATE INDEX IF NOT EXISTS ix_sessions_expires ON sessions(expires_at);
"""

# Columns added after the initial release; ALTER-ed in on open for existing DBs.
_MESSAGE_MIGRATIONS = {"summary": "TEXT", "metadata": "TEXT"}


class MessageStore:
    """Async SQLite-backed durable queue. Open with :meth:`open`."""

    # This backend implements the staged ingress pipeline (enqueue_ingress/handoff). The engine
    # refuses to start the staged runner on a backend that doesn't (see Engine.start).
    supports_ingest_stage = True

    def __init__(
        self,
        db: aiosqlite.Connection,
        *,
        path: str | Path = ":memory:",
        cipher: Cipher | None = None,
    ) -> None:
        self._db = db
        self.path = str(path)
        self._cipher: Cipher = cipher or IdentityCipher()
        # Serialise multi-statement transactions: aiosqlite serialises single
        # executes, but a txn spanning awaits could otherwise interleave.
        self._lock = asyncio.Lock()

    # --- PHI-at-rest cipher seam for nullable text columns (WP-5) -------------
    # error / last_error / detail can embed raw HL7 fragments from exceptions, so they go through the
    # cipher like raw/payload. They're nullable and may be blanked by retention, so encrypt is
    # null/empty-safe (a NULL or purged '' stays as-is — never turns into ciphertext-of-empty).

    def _enc(self, value: str | None) -> str | None:
        if not value:  # None or "" → leave blank (covers purged/empty values)
            return value
        return self._cipher.encrypt(value)

    def _dec(self, value: str | None) -> str | None:
        if value is None:
            return value
        return self._cipher.decrypt(value)  # '' and legacy plaintext pass through unchanged

    def _decode_row(self, row: aiosqlite.Row, *columns: str) -> dict[str, Any]:
        """Materialize a read-row as a dict and decrypt the named cipher-covered text columns. Returned
        as a plain dict (still satisfies the ``Row`` read contract: key access + ``keys()``)."""
        d = dict(row)
        for col in columns:
            if col in d:
                d[col] = self._dec(d[col])
        return d

    @classmethod
    async def open(
        cls, path: str | Path, *, synchronous: str = "NORMAL", cipher: Cipher | None = None
    ) -> "MessageStore":
        sync = synchronous.upper()
        if sync not in ("NORMAL", "FULL"):
            raise ValueError(
                f"invalid synchronous mode {synchronous!r}; expected 'NORMAL' or 'FULL'"
            )
        db = await aiosqlite.connect(str(path))
        db.row_factory = aiosqlite.Row
        await db.execute("PRAGMA journal_mode=WAL")
        # NORMAL is crash-safe under WAL (only risk is losing the last txn on OS crash/power loss,
        # never corruption) and avoids an fsync per commit — a large write-throughput win vs FULL.
        # `sync` is validated above, so this f-string can't inject. FULL is available for the
        # paranoid (every commit fsynced) via [store] synchronous = "full".
        await db.execute(f"PRAGMA synchronous={sync}")
        await db.execute("PRAGMA foreign_keys=ON")
        await db.execute("PRAGMA busy_timeout=5000")
        await db.executescript(_SCHEMA)
        await cls._migrate(db)
        await db.commit()
        # Tighten permissions now that the file (and its WAL siblings) exist — they hold PHI.
        if str(path) != ":memory:":
            main = Path(path)
            for f in (main, main.with_name(main.name + "-wal"), main.with_name(main.name + "-shm")):
                if f.exists():
                    _secure_file(f)
        store = cls(db, path=path, cipher=cipher)
        await store._encrypt_existing_rows()  # one-time PHI-at-rest migration when a key is set
        await store._backfill_audit_chain()  # chain any pre-existing (unhashed) audit rows
        return store

    async def _backfill_audit_chain(self) -> None:
        """Fill ``row_hash`` for audit rows written before hash-chaining (idempotent).

        Only rows missing a hash are filled, chained from the prior row — existing valid hashes are
        left untouched (so this can't silently re-bless a tampered row)."""
        cur = await self._db.execute(
            "SELECT id, ts, actor, action, channel_id, detail, row_hash FROM audit_log ORDER BY id"
        )
        prev = ""
        updates: list[tuple[str, int]] = []
        for r in await cur.fetchall():
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
            async with self._lock:
                await self._db.executemany("UPDATE audit_log SET row_hash=? WHERE id=?", updates)
                await self._db.commit()

    #: Every (table, column) the store cipher covers — raw bodies plus the PHI-bearing nullable text
    #: columns (error/last_error/detail) added in WP-5. Used by the on-open migration and rotate-key.
    _CIPHER_COLUMNS = (
        ("messages", "raw"),
        ("queue", "payload"),
        ("messages", "error"),
        ("queue", "last_error"),
        ("message_events", "detail"),
    )

    async def _encrypt_existing_rows(self) -> None:
        """Encrypt any legacy plaintext values in the cipher-covered columns in place when encryption
        is enabled (STORE-1 / WP-5).

        Idempotent and batched: skips rows already carrying the ciphertext prefix (and NULL / blank
        ``''`` values — the latter is a purged/empty marker we must not turn into ciphertext), so reads
        work throughout and re-running is a no-op. Bounded memory (processes in chunks)."""
        if not self._cipher.encrypts:
            return
        like = f"{_ENC_PREFIX}%"
        total = 0
        async with self._lock:
            for table, column in self._CIPHER_COLUMNS:
                while True:
                    # NOT LIKE / <> '' are both NULL (excluded) for NULL columns, so only non-null,
                    # non-blank, not-yet-encrypted values are selected.
                    cur = await self._db.execute(
                        f"SELECT id, {column} FROM {table}"
                        f" WHERE {column} NOT LIKE ? AND {column} <> '' LIMIT 500",
                        (like,),
                    )
                    rows = list(await cur.fetchall())
                    if not rows:
                        break
                    await self._db.executemany(
                        f"UPDATE {table} SET {column}=? WHERE id=?",
                        [(self._cipher.encrypt(r[column]), r["id"]) for r in rows],
                    )
                    await self._db.commit()
                    total += len(rows)
        if total:
            log.info("encrypted %d existing value(s) at rest", total)

    async def reencrypt_to_active(self, *, batch: int = 500) -> int:
        """Re-encrypt every cipher-covered value under the **active** key — the key-rotation re-encrypt
        path (ASVS 11.2.2), run offline via ``messagefoundry rotate-key``. Rewrites values that are
        plaintext or under a *retired* key; skips values already under the active key (idempotent) and
        NULL/blank ones. A value no configured key can decrypt raises (rotation needs the prior key
        supplied via ``MEFOR_STORE_ENCRYPTION_KEYS_RETIRED``) — it never silently drops PHI. Returns the
        number of values rewritten."""
        cipher = self._cipher
        if not isinstance(cipher, AesGcmCipher):
            return 0  # identity cipher (no key) — nothing to rotate
        active_like = f"{_ENC_PREFIX}{cipher.active_key_id}:%"
        total = 0
        async with self._lock:
            for table, column in self._CIPHER_COLUMNS:
                while True:
                    # Anything not already under the active key (plaintext or a retired-key blob),
                    # excluding NULL/blank. Rewritten rows match active_like next round, so this ends.
                    cur = await self._db.execute(
                        f"SELECT id, {column} FROM {table}"
                        f" WHERE {column} NOT LIKE ? AND {column} <> '' LIMIT ?",
                        (active_like, batch),
                    )
                    rows = list(await cur.fetchall())
                    if not rows:
                        break
                    # decrypt (via the keyring) → encrypt (active). A CipherError here means a prior key
                    # wasn't supplied; it propagates (the CLI surfaces it) before any UPDATE, so a batch
                    # is all-or-nothing and PHI is never dropped.
                    updates = [(cipher.encrypt(cipher.decrypt(r[column])), r["id"]) for r in rows]
                    await self._db.executemany(f"UPDATE {table} SET {column}=? WHERE id=?", updates)
                    await self._db.commit()
                    total += len(rows)
        if total:
            log.info("re-encrypted %d value(s) under the active key (rotation)", total)
        return total

    @staticmethod
    async def _migrate(db: aiosqlite.Connection) -> None:
        """Add columns introduced after the first release to pre-existing DBs (idempotent)."""
        cur = await db.execute("PRAGMA table_info(messages)")
        existing = {row["name"] for row in await cur.fetchall()}
        for column, decl in _MESSAGE_MIGRATIONS.items():
            if column not in existing:
                await db.execute(f"ALTER TABLE messages ADD COLUMN {column} {decl}")
        cur = await db.execute("PRAGMA table_info(audit_log)")
        if "row_hash" not in {row["name"] for row in await cur.fetchall()}:
            await db.execute("ALTER TABLE audit_log ADD COLUMN row_hash TEXT")
        cur = await db.execute("PRAGMA table_info(users)")
        if "channel_scope" not in {row["name"] for row in await cur.fetchall()}:
            await db.execute("ALTER TABLE users ADD COLUMN channel_scope TEXT")
        # Step B adds the routed stage, which carries the handler to run in queue.handler_name. A
        # Step-A DB's queue table predates the column — ALTER it in (NULL on existing ingress/outbound
        # rows is correct). The queue table always exists here (CREATE IF NOT EXISTS ran in _SCHEMA).
        cur = await db.execute("PRAGMA table_info(queue)")
        if "handler_name" not in {row["name"] for row in await cur.fetchall()}:
            await db.execute("ALTER TABLE queue ADD COLUMN handler_name TEXT")
        await MessageStore._migrate_outbox_to_queue(db)

    @staticmethod
    async def _migrate_outbox_to_queue(db: aiosqlite.Connection) -> None:
        """Fold a legacy ``outbox`` table into the generic ``queue`` table (staged pipeline, ADR 0001).

        Runs after ``_SCHEMA`` has already created the (empty) ``queue`` table with its nullable
        ``destination_name`` and ``stage`` column, so copying rows in is a plain INSERT…SELECT with no
        constraint-rebuild dance: every existing outbox row becomes a ``stage='outbound'`` queue row
        (its payload — possibly already encrypted — carried over verbatim, so encryption-at-rest is
        preserved). The old table is then dropped (taking its indexes with it). Idempotent: a no-op
        once ``outbox`` is gone.

        Orphan rows (a ``message_id`` with no surviving ``messages`` row — possible only if external
        tooling wrote with ``foreign_keys`` off) are **skipped** rather than allowed to abort the whole
        open() with an opaque ``FOREIGN KEY constraint failed``: ``queue.message_id`` is FK-enforced
        and this INSERT runs under ``foreign_keys=ON``. A skipped orphan was unreplayable anyway (no
        message to view/route); we log how many were dropped."""
        cur = await db.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='outbox'"
        )
        if await cur.fetchone() is None:
            return  # already migrated (or a fresh DB) — nothing to fold in
        cur = await db.execute("SELECT COUNT(*) FROM outbox")
        row = await cur.fetchone()
        total = int(row[0]) if row else 0
        # Copy only rows whose message still exists (the FK target) — see the orphan note above.
        await db.execute(
            "INSERT INTO queue (id, message_id, stage, channel_id, destination_name, payload,"
            " status, attempts, next_attempt_at, last_error, created_at, updated_at)"
            " SELECT id, message_id, ?, channel_id, destination_name, payload,"
            " status, attempts, next_attempt_at, last_error, created_at, updated_at FROM outbox"
            " WHERE message_id IN (SELECT id FROM messages)",
            (Stage.OUTBOUND.value,),
        )
        cur = await db.execute("SELECT COUNT(*) FROM queue WHERE stage=?", (Stage.OUTBOUND.value,))
        row = await cur.fetchone()
        migrated = int(row[0]) if row else 0
        await db.execute("DROP TABLE outbox")
        log.info("migrated %d legacy outbox row(s) into the staged queue table", migrated)
        if migrated < total:
            log.warning(
                "skipped %d orphaned outbox row(s) during migration (message_id with no messages "
                "row — likely written with foreign_keys off); they were unreplayable",
                total - migrated,
            )

    async def close(self) -> None:
        await self._db.close()

    # --- write path ----------------------------------------------------------

    async def enqueue_message(
        self,
        *,
        channel_id: str,
        raw: str,
        deliveries: Sequence[tuple[str, str]],  # (destination_name, payload)
        control_id: str | None = None,
        message_type: str | None = None,
        source_type: str | None = None,
        summary: str | None = None,
        metadata: str | None = None,
        now: float | None = None,
    ) -> str:
        """Atomically persist an inbound message and its per-destination outbound rows **directly** —
        the pre-staged-pipeline single-step write, kept for tests and any single-dispatcher path.

        The live engine no longer uses this: it persists raw to the ingress stage
        (:meth:`enqueue_ingress`), then routes and writes outbound rows in :meth:`handoff`. With
        ``deliveries`` the message is ``ROUTED`` (outbound rows queued); with none it is ``UNROUTED``
        (accepted, matched no destination, preserved and counted, delivered nowhere). Returns the new
        message id.
        """
        now = time.time() if now is None else now
        mid = uuid4().hex
        status = MessageStatus.ROUTED.value if deliveries else MessageStatus.UNROUTED.value
        async with self._lock:
            try:
                await self._db.execute("BEGIN")
                await self._insert_message(
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
                    await self._insert_outbound_row(mid, channel_id, dest_name, payload, now)
                await self._db.execute(
                    "INSERT INTO message_events (message_id, ts, event, detail) VALUES (?,?,?,?)",
                    (mid, now, "received", self._enc(f"{len(deliveries)} destination(s)")),
                )
                await self._db.commit()
            except Exception:
                await self._db.rollback()
                raise
        return mid

    async def _fifo_created_at(self, stage: str, lane_col: str, lane_val: str, now: float) -> float:
        """The ``created_at`` to stamp on a new ``stage`` row so per-lane FIFO order (``ORDER BY
        created_at, rowid`` in :meth:`claim_next_fifo`) survives a **backward wall-clock step**.

        FIFO ordering assumes ``created_at`` (``time.time()``) is monotonically non-decreasing within a
        lane; an NTP step-back / VM snapshot-revert could otherwise give a later-arriving row a smaller
        ``created_at`` and let it sort ahead of an earlier one. Clamp the new row's ordering timestamp
        up to the lane's current max so that can't happen (equal timestamps fall back to ``rowid`` =
        insertion order). Only ``created_at`` is clamped — ``next_attempt_at``/``updated_at`` keep the
        true ``now``. Logs once per actual clamp. ``lane_col`` is a code-controlled literal
        (``channel_id`` for ingress/routed, ``destination_name`` for outbound), never user input."""
        cur = await self._db.execute(
            f"SELECT MAX(created_at) AS m FROM queue WHERE stage=? AND {lane_col}=?",
            (stage, lane_val),
        )
        row = await cur.fetchone()
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
        self, mid: str, channel_id: str, dest_name: str, payload: str, now: float
    ) -> None:
        """Insert one ``stage='outbound'`` queue row (one message→destination delivery)."""
        created_at = await self._fifo_created_at(
            Stage.OUTBOUND.value, "destination_name", dest_name, now
        )
        await self._db.execute(
            "INSERT INTO queue"
            " (id, message_id, stage, channel_id, destination_name, payload,"
            "  status, attempts, next_attempt_at, created_at, updated_at)"
            " VALUES (?,?,?,?,?,?,?,0,?,?,?)",
            (
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
            ),
        )

    async def _insert_routed_row(
        self, mid: str, channel_id: str, handler_name: str, payload: str, now: float
    ) -> None:
        """Insert one ``stage='routed'`` queue row (one handler assignment awaiting transform).

        Carries the handler the transform worker must run (``handler_name``) and the raw body
        (``payload``, encrypted) it re-parses; ``destination_name`` is NULL until transform produces
        outbound rows. The raw is consumed (the row is DELETEd) at :meth:`transform_handoff`, so it is
        never kept twice at rest beyond the brief route→transform window (mirrors the ingress row)."""
        created_at = await self._fifo_created_at(Stage.ROUTED.value, "channel_id", channel_id, now)
        await self._db.execute(
            "INSERT INTO queue"
            " (id, message_id, stage, channel_id, destination_name, handler_name, payload,"
            "  status, attempts, next_attempt_at, created_at, updated_at)"
            " VALUES (?,?,?,?,NULL,?,?,?,0,?,?,?)",
            (
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
        """Durably persist a freshly-received raw message to the **ingress stage** — the staged
        pipeline's ACK-on-receipt boundary (ADR 0001 Step A).

        In one transaction: insert the message (status ``RECEIVED``) and a single ``stage='ingress'``
        queue row holding the raw body (no routing has happened yet, so there are no outbound rows and
        no destination). Once this returns the message is durable and the inbound may be ACKed; the
        ingress worker then routes+transforms it and calls :meth:`handoff`. Returns the message id."""
        now = time.time() if now is None else now
        mid = uuid4().hex
        async with self._lock:
            try:
                await self._db.execute("BEGIN")
                await self._insert_message(
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
                    Stage.INGRESS.value, "channel_id", channel_id, now
                )
                await self._db.execute(
                    "INSERT INTO queue"
                    " (id, message_id, stage, channel_id, destination_name, payload,"
                    "  status, attempts, next_attempt_at, created_at, updated_at)"
                    " VALUES (?,?,?,?,NULL,?,?,0,?,?,?)",
                    (
                        uuid4().hex,
                        mid,
                        Stage.INGRESS.value,
                        channel_id,
                        self._cipher.encrypt(raw),
                        OutboxStatus.PENDING.value,
                        now,
                        ingress_created_at,
                        now,
                    ),
                )
                await self._db.execute(
                    "INSERT INTO message_events (message_id, ts, event, detail) VALUES (?,?,?,?)",
                    (mid, now, "received", self._enc("ingress")),
                )
                await self._db.commit()
            except Exception:
                await self._db.rollback()
                raise
        return mid

    async def handoff(
        self,
        *,
        ingress_id: str,
        message_id: str,
        channel_id: str,
        deliveries: Sequence[tuple[str, str]],  # (destination_name, payload)
        disposition: MessageStatus,
        now: float | None = None,
    ) -> bool:
        """Atomically advance one message from the ingress stage to outbound (claim→produce→complete).

        In a single transaction: **consume** the in-flight ingress row (delete it — the raw is already
        the canonical ``messages.raw``, so keeping a second copy would only duplicate PHI at rest),
        insert one ``stage='outbound'`` row per delivery, set the message's post-router ``disposition``
        (``ROUTED`` with deliveries, else ``FILTERED``/``UNROUTED``), and log the routing event. A
        crash before commit rolls the whole step back, leaving the ingress row recoverable (it reverts
        to pending via :meth:`reset_stale_inflight`), so a message is never lost or partially handed off.

        Idempotency comes from that single committed transaction: a committed handoff has *deleted* the
        ingress row, so it can never be re-claimed and this method can never run again for it; an
        uncommitted one left the row ``inflight`` for ``reset_stale_inflight`` to revert and the worker
        to re-run cleanly. The ``status=inflight`` predicate on the DELETE (rowcount==0 → roll back,
        return ``False``) is defensive belt-and-suspenders on top of that — with one ingress worker per
        inbound and the per-call lock there is no concurrent or duplicate call to guard against, but it
        keeps the method a safe no-op if it is ever invoked for an already-consumed row. Returns
        ``True`` if this call performed the handoff, ``False`` if it was a no-op."""
        now = time.time() if now is None else now
        async with self._lock:
            try:
                await self._db.execute("BEGIN")
                cur = await self._db.execute(
                    "DELETE FROM queue WHERE id=? AND stage=? AND status=?",
                    (ingress_id, Stage.INGRESS.value, OutboxStatus.INFLIGHT.value),
                )
                if not cur.rowcount:
                    # Already handed off by a prior run (crash-restart) — idempotent no-op.
                    await self._db.rollback()
                    return False
                for dest_name, payload in deliveries:
                    await self._insert_outbound_row(message_id, channel_id, dest_name, payload, now)
                await self._db.execute(
                    "UPDATE messages SET status=? WHERE id=?", (disposition.value, message_id)
                )
                event = {
                    MessageStatus.ROUTED: "routed",
                    MessageStatus.FILTERED: "filtered",
                    MessageStatus.UNROUTED: "unrouted",
                }.get(disposition, "routed")
                await self._event(message_id, event, None, f"{len(deliveries)} destination(s)", now)
                await self._db.commit()
            except Exception:
                await self._db.rollback()
                raise
        return True

    async def route_handoff(
        self,
        *,
        ingress_id: str,
        message_id: str,
        channel_id: str,
        handlers: Sequence[tuple[str, str]],  # (handler_name, raw_payload) — one routed row each
        disposition: MessageStatus,  # ROUTED (>=1 handler) or UNROUTED (zero)
        now: float | None = None,
    ) -> bool:
        """Advance one message from the ingress stage to the **routed** stage — the router half of the
        split pipeline (ADR 0001 Step B): claim→produce-next→complete in one transaction.

        Consume the in-flight ingress row (DELETE — the raw is canonical in ``messages.raw``), insert
        one ``stage='routed'`` row **per selected handler** (each carrying its ``handler_name`` + the
        raw the transform re-parses), set the message's post-router ``disposition`` (``ROUTED`` with
        handlers, ``UNROUTED`` with none), and log the ``routed``/``unrouted`` event. INFLIGHT-guarded
        and single-transaction exactly like :meth:`handoff`: a crash before commit rolls back (the
        ingress row recovers via :meth:`reset_stale_inflight` and the router re-runs, re-deriving
        identical routed rows — routing is pure), and a committed run is an idempotent no-op on
        re-invocation (the ingress row is already gone → rowcount 0 → ``False``). Returns ``True`` if
        this call performed the handoff, ``False`` if it was a no-op.

        It sets only the **intermediate** ``ROUTED``/``UNROUTED`` disposition; the terminal
        ``PROCESSED``/``FILTERED``/``ERROR`` is owned entirely by :meth:`_maybe_finalize_message`."""
        now = time.time() if now is None else now
        async with self._lock:
            try:
                await self._db.execute("BEGIN")
                cur = await self._db.execute(
                    "DELETE FROM queue WHERE id=? AND stage=? AND status=?",
                    (ingress_id, Stage.INGRESS.value, OutboxStatus.INFLIGHT.value),
                )
                if not cur.rowcount:
                    # Already handed off by a prior run (crash-restart) — idempotent no-op.
                    await self._db.rollback()
                    return False
                # Insert in handler-list order: routed rows share this handoff's created_at, so the
                # transform worker's FIFO (created_at, rowid) falls back to rowid = insertion order,
                # preserving the router's handler order to a shared outbound (see the worker docs).
                for handler_name, payload in handlers:
                    await self._insert_routed_row(
                        message_id, channel_id, handler_name, payload, now
                    )
                await self._db.execute(
                    "UPDATE messages SET status=? WHERE id=?", (disposition.value, message_id)
                )
                event = "routed" if disposition is MessageStatus.ROUTED else "unrouted"
                await self._event(message_id, event, None, f"{len(handlers)} handler(s)", now)
                await self._db.commit()
            except Exception:
                await self._db.rollback()
                raise
        return True

    async def transform_handoff(
        self,
        *,
        routed_id: str,
        message_id: str,
        channel_id: str,
        deliveries: Sequence[tuple[str, str]],  # (destination_name, transformed_payload)
        now: float | None = None,
    ) -> bool:
        """Advance one handler assignment from the **routed** stage to outbound — the transform half of
        the split pipeline (ADR 0001 Step B): claim→produce-next→complete in one transaction.

        Consume the in-flight routed row (DELETE — its raw body is canonical in ``messages.raw``),
        insert one ``stage='outbound'`` row per delivery this handler produced, log the ``transformed``
        event, then call :meth:`_maybe_finalize_message`. It does **not** write ``messages.status``
        itself: the finalizer is the single disposition authority (it alone has the whole multi-stage
        row picture — a sibling handler's routed/outbound rows may still be in flight, so per-handoff
        disposition math would be order-dependent and wrong). INFLIGHT-guarded and single-transaction
        like :meth:`handoff`: a crash before commit rolls back (the routed row recovers and the
        transform re-runs, re-deriving identical outbound rows — transforms are pure), and a committed
        run is an idempotent no-op on re-invocation (routed row gone → ``False``). Returns ``True`` if
        this call performed the handoff, ``False`` if it was a no-op."""
        now = time.time() if now is None else now
        async with self._lock:
            try:
                await self._db.execute("BEGIN")
                cur = await self._db.execute(
                    "DELETE FROM queue WHERE id=? AND stage=? AND status=?",
                    (routed_id, Stage.ROUTED.value, OutboxStatus.INFLIGHT.value),
                )
                if not cur.rowcount:
                    # Already handed off by a prior run (crash-restart) — idempotent no-op.
                    await self._db.rollback()
                    return False
                for dest_name, payload in deliveries:
                    await self._insert_outbound_row(message_id, channel_id, dest_name, payload, now)
                await self._event(
                    message_id, "transformed", None, f"{len(deliveries)} destination(s)", now
                )
                # Finalizer owns the terminal disposition (incl. the ROUTED→FILTERED collapse when this
                # was the last handler and nothing delivered anywhere). Runs in this same transaction.
                await self._maybe_finalize_message(message_id, now)
                await self._db.commit()
            except Exception:
                await self._db.rollback()
                raise
        return True

    async def _insert_message(
        self,
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
        await self._db.execute(
            "INSERT INTO messages"
            " (id, channel_id, received_at, source_type, control_id,"
            "  message_type, raw, status, error, summary, metadata)"
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
                self._enc(error),
                summary,
                metadata,
            ),
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
        """Log an inbound message that isn't routed: rejected by the channel filter
        (``FILTERED``) or failed parse/validation (``ERROR``). Stored with no outbox rows so an
        operator still sees exactly what arrived (CLAUDE.md §8)."""
        now = time.time() if now is None else now
        mid = uuid4().hex
        event = "error" if status is MessageStatus.ERROR else "filtered"
        async with self._lock:
            try:
                await self._db.execute("BEGIN")
                await self._insert_message(
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
                await self._db.execute(
                    "INSERT INTO message_events (message_id, ts, event, detail) VALUES (?,?,?,?)",
                    (mid, now, event, self._enc(error)),
                )
                await self._db.commit()
            except Exception:
                await self._db.rollback()
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
        """Atomically claim up to ``limit`` due rows **at ``stage``**, marking them ``inflight`` and
        incrementing ``attempts``. Each returned item represents one processing/delivery attempt.

        ``channel_id`` / ``destination_name`` scope the claim so a per-lane worker only takes its own
        rows; omitting both claims across all lanes at the stage (tests / single-dispatcher). This is
        the UNORDERED claim — it skips a backing-off row to drain others; :meth:`claim_next_fifo` is
        the strict-order variant."""
        now = time.time() if now is None else now
        where = ["stage=?", "status=?", "next_attempt_at<=?"]
        params: list[object] = [stage, OutboxStatus.PENDING.value, now]
        if channel_id is not None:
            where.append("channel_id=?")
            params.append(channel_id)
        if destination_name is not None:
            where.append("destination_name=?")
            params.append(destination_name)
        async with self._lock:
            cur = await self._db.execute(
                f"SELECT id FROM queue WHERE {' AND '.join(where)}"
                " ORDER BY next_attempt_at LIMIT ?",
                (*params, limit),
            )
            ids = [r["id"] for r in await cur.fetchall()]
            if not ids:
                return []
            placeholders = ",".join("?" * len(ids))
            await self._db.execute(
                f"UPDATE queue SET status=?, attempts=attempts+1, updated_at=?"
                f" WHERE id IN ({placeholders})",
                (OutboxStatus.INFLIGHT.value, now, *ids),
            )
            cur = await self._db.execute(f"SELECT * FROM queue WHERE id IN ({placeholders})", ids)
            rows = await cur.fetchall()
            await self._db.commit()
        # Decrypt per row (outside the lock): a single undecryptable payload (corrupt blob, or a
        # rotated MEFOR_STORE_ENCRYPTION_KEY) must not blow up the whole claim — that would strand
        # the batch INFLIGHT and, with the worker re-raising, silently stop the destination from
        # draining (review H-1). Dead-letter the bad row and deliver the rest.
        items: list[OutboxItem] = []
        for row in rows:
            try:
                items.append(OutboxItem.from_row(row, self._cipher))
            except Exception as exc:
                log.warning("dead-lettering undecryptable outbox row %s: %s", row["id"], exc)
                await self.dead_letter_now(row["id"], f"undecryptable payload: {exc}")
        return items

    async def claim_next_fifo(
        self, name: str, now: float | None = None, *, stage: str = Stage.OUTBOUND.value
    ) -> OutboxItem | None:
        """Claim the **single oldest** pending row for one lane at ``stage`` — strict FIFO by enqueue
        time — but only if it is **due**.

        The lane key is **stage-aware**: outbound lanes are keyed by ``destination_name`` (per-outbound
        FIFO across all inbounds); ingress **and routed** lanes by ``channel_id`` (per-inbound FIFO —
        preserving arrival order into routing, and into transform) — those rows have a NULL
        ``destination_name``, so keying outbound's column there would match nothing and silently stall
        the lane. Ordering is ``created_at, rowid`` — the ``rowid`` tiebreak preserves insertion order
        among rows produced in the **same** transaction (e.g. one ``route_handoff``'s routed rows keep
        their handler-list order). Ordering across separate enqueues to a lane assumes ``created_at`` is
        monotonically non-decreasing within the lane; :meth:`_fifo_created_at` **clamps each new row's
        ``created_at`` up to the lane's current max at insert**, so a backward wall-clock step (NTP
        step-back, VM snapshot revert) can't make a later message sort ahead of an earlier one on this
        backend. (The SQL Server backend's ``outbox`` FIFO has no such clamp yet — its monotonic
        ordering is part of the SQL Server staged-backend work; see docs/BACKLOG.md.) If the head is
        still backing off (``next_attempt_at`` in
        the future) this returns ``None`` *without* skipping ahead — the head blocks the lane (head-of-
        line) until it succeeds, dead-letters, or is purged. Contrast :meth:`claim_ready`, which skips a
        backing-off row to drain others (unordered).
        """
        now = time.time() if now is None else now
        # Lane column is a code-controlled literal (chosen by stage), never user input.
        lane_col = (
            "channel_id"
            if stage in (Stage.INGRESS.value, Stage.ROUTED.value)
            else "destination_name"
        )
        async with self._lock:
            cur = await self._db.execute(
                f"SELECT * FROM queue WHERE stage=? AND {lane_col}=? AND status=?"
                " ORDER BY created_at, rowid LIMIT 1",
                (stage, name, OutboxStatus.PENDING.value),
            )
            row = await cur.fetchone()
            if row is None or row["next_attempt_at"] > now:
                return None  # nothing pending, or the head is backing off — block the lane
            await self._db.execute(
                "UPDATE queue SET status=?, attempts=attempts+1, updated_at=? WHERE id=?",
                (OutboxStatus.INFLIGHT.value, now, row["id"]),
            )
            cur = await self._db.execute("SELECT * FROM queue WHERE id=?", (row["id"],))
            claimed = await cur.fetchone()
            assert claimed is not None  # nosec B101 — just updated this row under the lock
            await self._db.commit()
        try:
            return OutboxItem.from_row(claimed, self._cipher)
        except Exception as exc:
            # Same as claim_ready: an undecryptable head must not stall the lane — dead-letter it and
            # let the next poll advance to the new head, rather than re-raising into the worker (H-1).
            # The dead-letter records the message ERROR (visible in the tracking view); a push alert
            # for a poison ingress row is a documented follow-up (the store can't reach the AlertSink).
            log.warning("dead-lettering undecryptable queue row %s: %s", claimed["id"], exc)
            await self.dead_letter_now(claimed["id"], f"undecryptable payload: {exc}")
            return None

    async def dead_letter_now(self, outbox_id: str, error: str, now: float | None = None) -> None:
        """Force a row terminal (``DEAD``) immediately without consuming a retry — **fail-fast**.

        For a delivery that can never succeed as-is and must not hold the FIFO lane: a permanent
        partner reject (``AR``), an internal/code error under the error-and-continue policy, or an
        undecryptable payload (corrupt blob / rotated key). Unlike :meth:`mark_failed`, there's no
        backoff/retry — such a row would just fail identically forever and stall its worker (H-1)."""
        now = time.time() if now is None else now
        async with self._lock:
            row = await self._row(outbox_id)
            if row is None:
                return
            await self._db.execute(
                "UPDATE queue SET status=?, next_attempt_at=?, last_error=?, updated_at=? WHERE id=?",
                (OutboxStatus.DEAD.value, now, self._enc(error), now, outbox_id),
            )
            await self._event(row["message_id"], "dead", row["destination_name"], error, now)
            await self._maybe_finalize_message(row["message_id"], now)
            await self._db.commit()

    async def mark_done(self, outbox_id: str, now: float | None = None) -> None:
        now = time.time() if now is None else now
        async with self._lock:
            row = await self._row(outbox_id)
            if row is None:
                return
            await self._db.execute(
                "UPDATE queue SET status=?, last_error=NULL, updated_at=? WHERE id=?",
                (OutboxStatus.DONE.value, now, outbox_id),
            )
            await self._event(
                row["message_id"],
                "delivered",
                row["destination_name"],
                f"attempt {row['attempts']}",
                now,
            )
            await self._maybe_finalize_message(row["message_id"], now)
            await self._db.commit()

    async def mark_failed(
        self, outbox_id: str, error: str, retry: RetryPolicy, now: float | None = None
    ) -> None:
        """Reschedule with exponential backoff, or dead-letter if retries are exhausted."""
        now = time.time() if now is None else now
        async with self._lock:
            row = await self._row(outbox_id)
            if row is None:
                return
            attempts = row["attempts"]
            # max_attempts None = retry forever (never dead-letter here); a finite cap dead-letters
            # once exhausted. attempts is post-increment (the claim bumped it before this send).
            if retry.max_attempts is not None and attempts >= retry.max_attempts:
                status, next_at, event = OutboxStatus.DEAD.value, now, "dead"
            else:
                backoff = min(
                    retry.max_backoff_seconds,
                    retry.backoff_seconds * (retry.backoff_multiplier ** (attempts - 1)),
                )
                status, next_at, event = OutboxStatus.PENDING.value, now + backoff, "failed"
            await self._db.execute(
                "UPDATE queue SET status=?, next_attempt_at=?, last_error=?, updated_at=?"
                " WHERE id=?",
                (status, next_at, self._enc(error), now, outbox_id),
            )
            await self._event(
                row["message_id"],
                event,
                row["destination_name"],
                f"attempt {attempts}: {error}",
                now,
            )
            if status == OutboxStatus.DEAD.value:
                await self._maybe_finalize_message(row["message_id"], now)
            await self._db.commit()

    async def pending_depth(
        self, name: str, *, stage: str = Stage.OUTBOUND.value
    ) -> tuple[int, float | None]:
        """``(pending_count, oldest_created_at)`` for one lane at ``stage`` (see the protocol).

        Lane key is stage-aware (mirrors :meth:`claim_next_fifo`): outbound lanes key on
        ``destination_name``; ingress and routed lanes on ``channel_id`` (their ``destination_name``
        is NULL)."""
        lane_col = (
            "channel_id"
            if stage in (Stage.INGRESS.value, Stage.ROUTED.value)
            else "destination_name"
        )
        async with self._lock:
            cur = await self._db.execute(
                f"SELECT COUNT(*) AS n, MIN(created_at) AS oldest FROM queue"
                f" WHERE stage=? AND {lane_col}=? AND status=?",
                (stage, name, OutboxStatus.PENDING.value),
            )
            row = await cur.fetchone()
        count = int(row["n"]) if row is not None else 0
        oldest = row["oldest"] if row is not None else None
        return count, (float(oldest) if oldest is not None else None)

    # --- recovery / replay ---------------------------------------------------

    async def reset_stale_inflight(
        self, now: float | None = None, *, stage: str | None = None
    ) -> int:
        """Return ``inflight`` rows (claimed before a crash) to ``pending``. Call once on startup.

        With ``stage=None`` (the default) it recovers **every** stage in one pass — the right startup
        behavior, since ingress, routed, and outbound inflight rows all need recovering. Pass a
        ``stage`` to scope recovery to one. Returns the number of rows recovered."""
        now = time.time() if now is None else now
        where = "status=?"
        params: list[object] = [OutboxStatus.INFLIGHT.value]
        if stage is not None:
            where += " AND stage=?"
            params.append(stage)
        async with self._lock:
            cur = await self._db.execute(
                f"UPDATE queue SET status=?, next_attempt_at=?, updated_at=? WHERE {where}",
                (OutboxStatus.PENDING.value, now, now, *params),
            )
            await self._db.commit()
            return cur.rowcount

    async def dead_letter_missing_destinations(
        self, valid_names: set[str], now: float | None = None
    ) -> int:
        """Dead-letter every non-terminal **outbound** row whose ``destination_name`` is no longer in
        the registry (a removed/renamed outbound). Call once at startup, after
        :meth:`reset_stale_inflight`: no delivery worker is spawned for an unknown destination, so
        such rows would otherwise sit ``pending`` forever — never delivered, never dead-lettered, and
        blocking their message from finalizing (review H-5). Scoped to ``stage='outbound'`` so the
        staged pipeline's ingress rows (which carry a NULL ``destination_name`` by design) are never
        swept up as orphans. Returns the rows killed; an operator can replay them via the dead-letter
        API once the outbound is restored."""
        now = time.time() if now is None else now
        async with self._lock:
            cur = await self._db.execute(
                "SELECT id, message_id, destination_name FROM queue"
                " WHERE stage=? AND status IN (?, ?)",
                (Stage.OUTBOUND.value, OutboxStatus.PENDING.value, OutboxStatus.INFLIGHT.value),
            )
            # Filter in Python: valid_names may be empty (NOT IN () is invalid SQL) and the
            # non-terminal backlog is small relative to the message history.
            orphans = [r for r in await cur.fetchall() if r["destination_name"] not in valid_names]
            if not orphans:
                return 0
            error = "destination removed from outbound registry"
            for row in orphans:
                await self._db.execute(
                    "UPDATE queue SET status=?, next_attempt_at=?, last_error=?, updated_at=?"
                    " WHERE id=?",
                    (OutboxStatus.DEAD.value, now, self._enc(error), now, row["id"]),
                )
                await self._event(row["message_id"], "dead", row["destination_name"], error, now)
                await self._maybe_finalize_message(row["message_id"], now)
            await self._db.commit()
            log.warning(
                "dead-lettered %d orphaned outbox row(s) at startup for missing destination(s): %s",
                len(orphans),
                ", ".join(sorted({r["destination_name"] for r in orphans})),
            )
            return len(orphans)

    async def dead_letter_missing_handlers(
        self, valid_names: set[str], now: float | None = None
    ) -> int:
        """Dead-letter every non-terminal **routed** row whose ``handler_name`` is no longer in the
        registry (a removed/renamed handler). The routed-stage parallel of
        :meth:`dead_letter_missing_destinations`: no transform worker can run a handler that's gone, so
        such a row would otherwise sit ``pending`` forever — never transformed, never dead-lettered,
        blocking its message from finalizing. Call once at startup, after :meth:`reset_stale_inflight`.
        Scoped to ``stage='routed'`` so ingress/outbound rows are never swept up. Returns the rows
        killed; the message shows ``ERROR`` and an operator replays it (per-message :meth:`replay`)
        once the handler is restored (a dead routed row, like a dead ingress row, is recovered there,
        not via the outbound-only dead-letter API)."""
        now = time.time() if now is None else now
        async with self._lock:
            cur = await self._db.execute(
                "SELECT id, message_id, handler_name FROM queue WHERE stage=? AND status IN (?, ?)",
                (Stage.ROUTED.value, OutboxStatus.PENDING.value, OutboxStatus.INFLIGHT.value),
            )
            # Filter in Python (valid_names may be empty → NOT IN () is invalid SQL); the non-terminal
            # routed backlog is small relative to message history.
            orphans = [r for r in await cur.fetchall() if r["handler_name"] not in valid_names]
            if not orphans:
                return 0
            error = "handler removed from registry"
            for row in orphans:
                await self._db.execute(
                    "UPDATE queue SET status=?, next_attempt_at=?, last_error=?, updated_at=?"
                    " WHERE id=?",
                    (OutboxStatus.DEAD.value, now, self._enc(error), now, row["id"]),
                )
                await self._event(row["message_id"], "dead", None, error, now)
                await self._maybe_finalize_message(row["message_id"], now)
            await self._db.commit()
            log.warning(
                "dead-lettered %d orphaned routed row(s) at startup for missing handler(s): %s",
                len(orphans),
                ", ".join(sorted({r["handler_name"] for r in orphans})),
            )
            return len(orphans)

    async def replay(self, message_id: str, now: float | None = None) -> int:
        """Re-queue a message for re-processing/re-delivery (attempts reset) — the message-level
        recovery path. **Two modes, by whether anything is stuck:**

        - **Recover** — if the message has any ``dead`` or ``pending`` row, re-queue **only** those.
          This re-runs a failed delivery, a dead-lettered ingress/routed row (a router/transform code
          error, an undecryptable raw, a removed handler), and kicks a backing-off head to retry now.
          Crucially it **never re-pends a ``done`` sibling** — a Step-B message can hold a delivered
          ``outbound`` row alongside a failed ``routed`` row at the same time, and re-delivering the
          done one (double delivery) while un-finalizing the message is the M-2 hazard the split
          introduces.
        - **Re-send** — if nothing is stuck (a fully-delivered message, only ``done`` rows), re-queue
          its ``done`` rows so an operator can deliberately re-transmit (outbounds are idempotent).

        ``cancelled`` rows are never touched (an operator purged them). A message with no re-queueable
        rows (parse/validation ERROR, FILTERED, or UNROUTED with no queue rows) returns 0, status
        untouched. Returns rows requeued."""
        now = time.time() if now is None else now
        async with self._lock:
            cur = await self._db.execute(
                "SELECT COUNT(*) AS n FROM queue WHERE message_id=? AND status IN (?, ?)",
                (message_id, OutboxStatus.DEAD.value, OutboxStatus.PENDING.value),
            )
            row = await cur.fetchone()
            stuck = int(row["n"]) if row else 0
            # Recover the stuck rows, or (nothing stuck) re-send the delivered ones.
            replay_from = (
                [OutboxStatus.DEAD.value, OutboxStatus.PENDING.value]
                if stuck
                else [OutboxStatus.DONE.value]
            )
            placeholders = ",".join("?" * len(replay_from))
            cur = await self._db.execute(
                "UPDATE queue SET status=?, attempts=0, next_attempt_at=?,"
                f" last_error=NULL, updated_at=? WHERE message_id=? AND status IN ({placeholders})",
                (OutboxStatus.PENDING.value, now, now, message_id, *replay_from),
            )
            if cur.rowcount:
                # Status reflects the earliest re-queued stage: a pending ingress/routed row → RECEIVED
                # (back in the route/transform path); else outbound only → ROUTED (awaiting delivery).
                pre = await self._db.execute(
                    "SELECT 1 FROM queue WHERE message_id=? AND stage IN (?, ?) AND status=? LIMIT 1",
                    (
                        message_id,
                        Stage.INGRESS.value,
                        Stage.ROUTED.value,
                        OutboxStatus.PENDING.value,
                    ),
                )
                status = (
                    MessageStatus.RECEIVED.value
                    if await pre.fetchone()
                    else MessageStatus.ROUTED.value
                )
                await self._db.execute(
                    "UPDATE messages SET status=?, error=NULL WHERE id=?",
                    (status, message_id),
                )
                await self._event(message_id, "replayed", None, f"{cur.rowcount} row(s)", now)
            await self._db.commit()
            return cur.rowcount

    async def replay_dead(
        self,
        *,
        channel_id: str | None = None,
        destination_name: str | None = None,
        now: float | None = None,
    ) -> int:
        """Re-queue **dead-lettered outbound deliveries** only (optionally scoped to a channel/
        destination): set them back to ``pending`` with attempts reset, revert each affected message
        from ``error`` to ``routed``, and log a ``replayed`` event. Scoped to ``stage='outbound'`` to
        match the dead-letter view (:meth:`list_dead` is outbound-only): this is the bulk DLQ replay,
        so it must only touch rows the operator can actually see. Dead **ingress** rows (processing
        failures) are recovered via the per-message :meth:`replay`, not here. Unlike :meth:`replay`
        this never touches rows that already delivered. Returns the number of dead rows requeued."""
        now = time.time() if now is None else now
        where = ["stage=?", "status=?"]
        params: list[object] = [Stage.OUTBOUND.value, OutboxStatus.DEAD.value]
        if channel_id is not None:
            where.append("channel_id=?")
            params.append(channel_id)
        if destination_name is not None:
            where.append("destination_name=?")
            params.append(destination_name)
        clause = " AND ".join(where)
        async with self._lock:
            cur = await self._db.execute(
                f"SELECT DISTINCT message_id FROM queue WHERE {clause}", tuple(params)
            )
            message_ids = [r["message_id"] for r in await cur.fetchall()]
            if not message_ids:
                return 0
            # Roll back the whole batch on any mid-loop failure so we never commit a partial replay
            # or leave the shared connection in an open transaction (which would break the next
            # write) — matching the SQL Server backend's atomicity.
            try:
                upd = await self._db.execute(
                    f"UPDATE queue SET status=?, attempts=0, next_attempt_at=?, last_error=NULL,"
                    f" updated_at=? WHERE {clause}",
                    (OutboxStatus.PENDING.value, now, now, *params),
                )
                for message_id in message_ids:
                    # Outbound-only replay → the message is routed again, awaiting delivery (ROUTED).
                    await self._db.execute(
                        "UPDATE messages SET status=?, error=NULL WHERE id=? AND status=?",
                        (MessageStatus.ROUTED.value, message_id, MessageStatus.ERROR.value),
                    )
                    await self._event(message_id, "replayed", None, "dead-letter replay", now)
                await self._db.commit()
            except Exception:
                await self._db.rollback()
                raise
            return upd.rowcount

    async def cancel_queued(
        self,
        channel_id: str | None,
        destination_name: str,
        *,
        top_only: bool = False,
        now: float | None = None,
    ) -> int:
        """Soft-cancel **pending** deliveries for a destination: mark them ``cancelled``, append
        a ``cancelled`` audit event each, and finalize any message whose deliveries are now all
        terminal. ``channel_id=None`` cancels across all producers (a code-first outbound
        connection fed by several inbounds); pass an id to scope to one. ``top_only`` cancels just
        the head of the queue (next due). Inflight/dead rows are left untouched (dead uses
        :meth:`replay`). Returns the number cancelled."""
        now = time.time() if now is None else now
        async with self._lock:
            where = ["destination_name=?", "status=?"]
            params: list[object] = [destination_name, OutboxStatus.PENDING.value]
            if channel_id is not None:
                where.insert(0, "channel_id=?")
                params.insert(0, channel_id)
            query = (
                "SELECT id, message_id FROM queue"
                f" WHERE {' AND '.join(where)} ORDER BY next_attempt_at, created_at"
            )
            if top_only:
                query += " LIMIT 1"
            cur = await self._db.execute(query, tuple(params))
            rows = await cur.fetchall()
            if not rows:
                return 0
            ids = [r["id"] for r in rows]
            placeholders = ",".join("?" * len(ids))
            await self._db.execute(
                f"UPDATE queue SET status=?, updated_at=? WHERE id IN ({placeholders})",
                (OutboxStatus.CANCELLED.value, now, *ids),
            )
            for r in rows:
                await self._event(
                    r["message_id"], "cancelled", destination_name, "manual purge", now
                )
            for message_id in {r["message_id"] for r in rows}:
                await self._maybe_finalize_message(message_id, now)
            await self._db.commit()
            return len(ids)

    # --- read helpers (for API / console / tests) ----------------------------

    async def get_message(self, message_id: str) -> dict[str, Any] | None:
        cur = await self._db.execute("SELECT * FROM messages WHERE id=?", (message_id,))
        row = await cur.fetchone()
        if row is None:
            return None
        record = dict(row)
        record["raw"] = self._cipher.decrypt(record["raw"])  # decrypt the body for display
        record["error"] = self._dec(record["error"])  # error may embed raw HL7 fragments (WP-5)
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
        """Most-recent-first message listing for the tracking view, with optional filters.

        Bodies (``raw``) are intentionally omitted here — the list view is metadata only,
        so PHI isn't fetched until a specific message is opened (and audited). ``allowed_channels``
        restricts the result to a caller's per-channel RBAC scope (None = all)."""
        where, params = self._message_filter(
            channel_id, status, message_type, control_id, allowed_channels
        )
        cur = await self._db.execute(
            "SELECT id, channel_id, received_at, source_type, control_id, message_type,"
            " status, error, summary, metadata,"
            " (SELECT event FROM message_events e WHERE e.message_id = messages.id"
            "  ORDER BY e.id DESC LIMIT 1) AS last_event"
            f" FROM messages{where}"
            " ORDER BY received_at DESC, id DESC LIMIT ? OFFSET ?",
            (*params, limit, offset),
        )
        return [self._decode_row(r, "error") for r in await cur.fetchall()]

    async def count_messages(
        self,
        *,
        channel_id: str | None = None,
        status: str | None = None,
        message_type: str | None = None,
        control_id: str | None = None,
        allowed_channels: Sequence[str] | None = None,
    ) -> int:
        """Total matching the same filters as :meth:`list_messages` (for pagination)."""
        where, params = self._message_filter(
            channel_id, status, message_type, control_id, allowed_channels
        )
        cur = await self._db.execute(f"SELECT COUNT(*) AS n FROM messages{where}", params)
        row = await cur.fetchone()
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
        with message metadata for the dead-letter view. Bodies (``raw``) are omitted (metadata only,
        no PHI until a message is opened + audited). ``allowed_channels`` restricts to a per-channel
        RBAC scope (None = all)."""
        where, params = self._dead_filter(channel_id, destination_name, allowed_channels)
        cur = await self._db.execute(
            "SELECT o.id AS outbox_id, o.message_id, o.channel_id, o.destination_name,"
            " o.attempts, o.last_error, o.updated_at,"
            " m.control_id, m.message_type, m.received_at, m.summary"
            f" FROM queue o JOIN messages m ON m.id = o.message_id{where}"
            " ORDER BY o.updated_at DESC, o.id DESC LIMIT ? OFFSET ?",
            (*params, limit, offset),
        )
        return [self._decode_row(r, "last_error") for r in await cur.fetchall()]

    async def count_dead(
        self,
        *,
        channel_id: str | None = None,
        destination_name: str | None = None,
        allowed_channels: Sequence[str] | None = None,
    ) -> int:
        """Total dead-lettered deliveries matching the same filters as :meth:`list_dead`."""
        where, params = self._dead_filter(channel_id, destination_name, allowed_channels)
        cur = await self._db.execute(f"SELECT COUNT(*) AS n FROM queue o{where}", params)
        row = await cur.fetchone()
        return int(row["n"]) if row else 0

    @staticmethod
    def _dead_filter(
        channel_id: str | None,
        destination_name: str | None,
        allowed_channels: Sequence[str] | None = None,
    ) -> tuple[str, tuple[object, ...]]:
        # Scoped to outbound rows: the dead-letter view is the per-destination delivery DLQ. Ingress
        # processing failures surface as ERROR messages in the tracking view and replay at the message
        # level (store.replay), not here.
        clauses = ["o.stage=?", "o.status=?"]
        params: list[object] = [Stage.OUTBOUND.value, OutboxStatus.DEAD.value]
        if channel_id is not None:
            clauses.append("o.channel_id=?")
            params.append(channel_id)
        if destination_name is not None:
            clauses.append("o.destination_name=?")
            params.append(destination_name)
        _append_channel_scope(clauses, params, "o.channel_id", allowed_channels)
        return f" WHERE {' AND '.join(clauses)}", tuple(params)

    @staticmethod
    def _message_filter(
        channel_id: str | None,
        status: str | None,
        message_type: str | None,
        control_id: str | None,
        allowed_channels: Sequence[str] | None = None,
    ) -> tuple[str, tuple[object, ...]]:
        clauses: list[str] = []
        params: list[object] = []
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

    async def outbox_for(self, message_id: str) -> list[dict[str, Any]]:
        """The outbound deliveries for a message (one row per destination), for the message-detail
        view. Scoped to ``stage='outbound'`` — the transient ingress row is an internal work item, not
        a delivery, so it never shows in the per-destination list."""
        cur = await self._db.execute(
            "SELECT * FROM queue WHERE message_id=? AND stage=? ORDER BY destination_name",
            (message_id, Stage.OUTBOUND.value),
        )
        return [self._decode_row(r, "last_error") for r in await cur.fetchall()]

    async def events_for(self, message_id: str) -> list[dict[str, Any]]:
        cur = await self._db.execute(
            "SELECT * FROM message_events WHERE message_id=? ORDER BY id", (message_id,)
        )
        return [self._decode_row(r, "detail") for r in await cur.fetchall()]

    async def record_view(
        self, message_id: str, *, actor: str | None = None, now: float | None = None
    ) -> None:
        """Append a ``viewed`` audit event. Called whenever a message body (PHI) is
        opened, satisfying the audit-log requirement for message views."""
        now = time.time() if now is None else now
        async with self._lock:
            await self._event(message_id, "viewed", None, actor or "", now)
            await self._db.commit()

    async def record_audit(
        self,
        action: str,
        *,
        actor: str | None = None,
        channel_id: str | None = None,
        detail: str | None = None,
        now: float | None = None,
    ) -> None:
        """Append a row to the general audit log — the seam for PHI-access auditing (summary
        displays, detail views, exports, …). ``detail`` is an opaque (JSON) string."""
        now = time.time() if now is None else now
        async with self._lock:
            cur = await self._db.execute("SELECT row_hash FROM audit_log ORDER BY id DESC LIMIT 1")
            last = await cur.fetchone()
            prev = last["row_hash"] if last and last["row_hash"] else ""
            row_hash = audit_row_hash(
                prev, ts=now, actor=actor, action=action, channel_id=channel_id, detail=detail
            )
            await self._db.execute(
                "INSERT INTO audit_log (ts, actor, action, channel_id, detail, row_hash)"
                " VALUES (?,?,?,?,?,?)",
                (now, actor, action, channel_id, detail, row_hash),
            )
            await self._db.commit()

    async def list_audit(self, *, limit: int = 50) -> list[aiosqlite.Row]:
        """Most-recent-first audit entries (for review tooling / tests)."""
        cur = await self._db.execute("SELECT * FROM audit_log ORDER BY id DESC LIMIT ?", (limit,))
        return list(await cur.fetchall())

    async def audit_anchor(self) -> tuple[int, str]:
        """The audit log's external anchor — ``(row_count, head_hash)`` (head ``""`` when empty).

        The hash chain links each row to its predecessor, but deleting the *newest* rows leaves a
        shorter chain that still verifies, so a within-DB check can't detect tail-truncation. Recording
        this anchor out-of-band (e.g. a compliance job snapshotting it elsewhere) and passing it back to
        :meth:`verify_audit_chain` is what makes truncation/rewrite detectable (review low-1)."""
        cur = await self._db.execute(
            "SELECT COUNT(*) AS n, "
            "(SELECT row_hash FROM audit_log ORDER BY id DESC LIMIT 1) AS head FROM audit_log"
        )
        row = await cur.fetchone()
        if row is None:
            return 0, ""
        return int(row["n"]), (row["head"] or "")

    async def verify_audit_chain(
        self, *, expected_anchor: tuple[int, str] | None = None
    ) -> tuple[bool, str | None]:
        """Recompute the audit hash-chain in order; returns ``(ok, message)``.

        A mismatch means a row was inserted, edited, or reordered out-of-band (AUDIT-INTEGRITY).
        Note: deleting the *newest* rows is NOT caught by the walk alone — the surviving prefix still
        chains cleanly. Pass ``expected_anchor`` (a ``(count, head_hash)`` previously returned by
        :meth:`audit_anchor` and held out-of-band) to also detect that tail-truncation (review low-1)."""
        cur = await self._db.execute(
            "SELECT id, ts, actor, action, channel_id, detail, row_hash FROM audit_log ORDER BY id"
        )
        prev = ""
        count = 0
        for r in await cur.fetchall():
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
        async with self._lock:
            await self._db.execute(
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
            await self._db.commit()

    async def get_user(self, user_id: str) -> UserRecord | None:
        cur = await self._db.execute("SELECT * FROM users WHERE id=?", (user_id,))
        row = await cur.fetchone()
        return UserRecord.from_mapping(dict(row)) if row else None

    async def get_user_by_username(self, username: str) -> UserRecord | None:
        cur = await self._db.execute("SELECT * FROM users WHERE username=?", (username,))
        row = await cur.fetchone()
        return UserRecord.from_mapping(dict(row)) if row else None

    async def list_users(self) -> list[UserRecord]:
        cur = await self._db.execute("SELECT * FROM users ORDER BY username")
        return [UserRecord.from_mapping(dict(r)) for r in await cur.fetchall()]

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
        async with self._lock:
            await self._db.execute(
                "UPDATE users SET password_hash=?, password_changed_at=?, must_change_password=?,"
                " failed_attempts=0, locked_until=NULL, updated_at=? WHERE id=?",
                (password_hash, now, 1 if must_change_password else 0, now, user_id),
            )
            await self._db.commit()

    async def set_user_disabled(
        self, user_id: str, *, disabled: bool, now: float | None = None
    ) -> None:
        now = time.time() if now is None else now
        async with self._lock:
            await self._db.execute(
                "UPDATE users SET disabled=?, updated_at=? WHERE id=?",
                (1 if disabled else 0, now, user_id),
            )
            await self._db.commit()

    async def update_user_profile(
        self,
        user_id: str,
        *,
        display_name: str | None,
        email: str | None,
        now: float | None = None,
    ) -> None:
        now = time.time() if now is None else now
        async with self._lock:
            await self._db.execute(
                "UPDATE users SET display_name=?, email=?, updated_at=? WHERE id=?",
                (display_name, email, now, user_id),
            )
            await self._db.commit()

    async def delete_user(self, user_id: str) -> None:
        async with self._lock:
            try:
                await self._db.execute("BEGIN")
                await self._db.execute("DELETE FROM user_roles WHERE user_id=?", (user_id,))
                await self._db.execute("DELETE FROM sessions WHERE user_id=?", (user_id,))
                await self._db.execute("DELETE FROM users WHERE id=?", (user_id,))
                await self._db.commit()
            except Exception:
                await self._db.rollback()
                raise

    async def record_login_success(self, user_id: str, *, now: float | None = None) -> None:
        now = time.time() if now is None else now
        async with self._lock:
            await self._db.execute(
                "UPDATE users SET last_login_at=?, failed_attempts=0, locked_until=NULL,"
                " updated_at=? WHERE id=?",
                (now, now, user_id),
            )
            await self._db.commit()

    async def record_login_failure(
        self,
        user_id: str,
        *,
        failed_attempts: int,
        locked_until: float | None,
        now: float | None = None,
    ) -> None:
        now = time.time() if now is None else now
        async with self._lock:
            await self._db.execute(
                "UPDATE users SET failed_attempts=?, locked_until=?, updated_at=? WHERE id=?",
                (failed_attempts, locked_until, now, user_id),
            )
            await self._db.commit()

    async def upsert_role(
        self,
        *,
        role_id: str,
        display_name: str,
        description: str | None = None,
        builtin: bool = True,
    ) -> None:
        async with self._lock:
            await self._db.execute(
                "INSERT INTO roles (id, display_name, description, builtin) VALUES (?,?,?,?)"
                " ON CONFLICT(id) DO UPDATE SET display_name=excluded.display_name,"
                " description=excluded.description, builtin=excluded.builtin",
                (role_id, display_name, description, 1 if builtin else 0),
            )
            await self._db.commit()

    async def list_roles(self) -> list[aiosqlite.Row]:
        cur = await self._db.execute("SELECT * FROM roles ORDER BY id")
        return list(await cur.fetchall())

    async def get_user_role_ids(self, user_id: str) -> list[str]:
        cur = await self._db.execute(
            "SELECT role_id FROM user_roles WHERE user_id=? ORDER BY role_id", (user_id,)
        )
        return [str(r["role_id"]) for r in await cur.fetchall()]

    async def set_user_roles(
        self,
        user_id: str,
        role_ids: Sequence[str],
        *,
        assigned_by: str | None = None,
        now: float | None = None,
    ) -> None:
        now = time.time() if now is None else now
        async with self._lock:
            try:
                await self._db.execute("BEGIN")
                await self._db.execute("DELETE FROM user_roles WHERE user_id=?", (user_id,))
                for role_id in role_ids:
                    await self._db.execute(
                        "INSERT INTO user_roles (user_id, role_id, assigned_at, assigned_by)"
                        " VALUES (?,?,?,?)",
                        (user_id, role_id, now, assigned_by),
                    )
                await self._db.commit()
            except Exception:
                await self._db.rollback()
                raise

    async def set_user_channel_scope(
        self, user_id: str, scope_json: str | None, *, now: float | None = None
    ) -> None:
        """Set a user's per-channel scope. ``scope_json`` is a JSON list of connection names, or
        ``None`` for all channels (per-channel RBAC)."""
        now = time.time() if now is None else now
        async with self._lock:
            await self._db.execute(
                "UPDATE users SET channel_scope=?, updated_at=? WHERE id=?",
                (scope_json, now, user_id),
            )
            await self._db.commit()

    async def roles_for_ad_groups(self, groups: Iterable[str]) -> set[str]:
        normalized = sorted({g.strip().lower() for g in groups if g.strip()})
        if not normalized:
            return set()
        placeholders = ",".join("?" * len(normalized))  # count-bound, not user text
        cur = await self._db.execute(
            f"SELECT DISTINCT role_id FROM ad_group_role_map WHERE ad_group IN ({placeholders})",
            tuple(normalized),
        )
        return {str(r["role_id"]) for r in await cur.fetchall()}

    async def list_ad_group_role_map(self) -> list[aiosqlite.Row]:
        cur = await self._db.execute(
            "SELECT ad_group, role_id FROM ad_group_role_map ORDER BY ad_group, role_id"
        )
        return list(await cur.fetchall())

    async def set_ad_group_role_map(self, entries: Iterable[tuple[str, str]]) -> None:
        pairs = sorted({(g.strip().lower(), r) for g, r in entries if g.strip()})
        async with self._lock:
            try:
                await self._db.execute("BEGIN")
                await self._db.execute("DELETE FROM ad_group_role_map")
                for ad_group, role_id in pairs:
                    await self._db.execute(
                        "INSERT INTO ad_group_role_map (ad_group, role_id) VALUES (?,?)",
                        (ad_group, role_id),
                    )
                await self._db.commit()
            except Exception:
                await self._db.rollback()
                raise

    async def channels_for_ad_groups(self, groups: Iterable[str]) -> set[str]:
        """Channels mapped to a user's AD groups (per-channel RBAC C3). May include the sentinel
        ``'*'`` (all). Empty = no group mapping matched (caller falls back to the per-user scope)."""
        normalized = sorted({g.strip().lower() for g in groups if g.strip()})
        if not normalized:
            return set()
        placeholders = ",".join("?" * len(normalized))  # count-bound, not user text
        cur = await self._db.execute(
            f"SELECT DISTINCT channel FROM ad_group_scope_map WHERE ad_group IN ({placeholders})",
            tuple(normalized),
        )
        return {str(r["channel"]) for r in await cur.fetchall()}

    async def list_ad_group_scope_map(self) -> list[aiosqlite.Row]:
        cur = await self._db.execute(
            "SELECT ad_group, channel FROM ad_group_scope_map ORDER BY ad_group, channel"
        )
        return list(await cur.fetchall())

    async def set_ad_group_scope_map(self, entries: Iterable[tuple[str, str]]) -> None:
        pairs = sorted(
            {(g.strip().lower(), c.strip()) for g, c in entries if g.strip() and c.strip()}
        )
        async with self._lock:
            try:
                await self._db.execute("BEGIN")
                await self._db.execute("DELETE FROM ad_group_scope_map")
                for ad_group, channel in pairs:
                    await self._db.execute(
                        "INSERT INTO ad_group_scope_map (ad_group, channel) VALUES (?,?)",
                        (ad_group, channel),
                    )
                await self._db.commit()
            except Exception:
                await self._db.rollback()
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
        async with self._lock:
            await self._db.execute(
                "INSERT INTO sessions (token_hash, user_id, created_at, expires_at, last_used_at,"
                " revoked_at, client) VALUES (?,?,?,?,?,NULL,?)",
                (token_hash, user_id, now, expires_at, now, client),
            )
            await self._db.commit()

    async def get_session(self, token_hash: str) -> SessionRecord | None:
        cur = await self._db.execute("SELECT * FROM sessions WHERE token_hash=?", (token_hash,))
        row = await cur.fetchone()
        return SessionRecord.from_mapping(dict(row)) if row else None

    async def list_sessions(self, user_id: str, *, now: float | None = None) -> list[SessionRecord]:
        """A user's currently-**active** sessions (not revoked, not expired), most-recently-used
        first — the self-service session inventory (WP-10, ASVS 7.5.2)."""
        now = time.time() if now is None else now
        cur = await self._db.execute(
            "SELECT * FROM sessions WHERE user_id=? AND revoked_at IS NULL AND expires_at > ?"
            " ORDER BY last_used_at DESC",
            (user_id, now),
        )
        return [SessionRecord.from_mapping(dict(r)) for r in await cur.fetchall()]

    async def touch_session(self, token_hash: str, *, now: float | None = None) -> None:
        now = time.time() if now is None else now
        async with self._lock:
            await self._db.execute(
                "UPDATE sessions SET last_used_at=? WHERE token_hash=?", (now, token_hash)
            )
            await self._db.commit()

    async def revoke_session(self, token_hash: str, *, now: float | None = None) -> None:
        now = time.time() if now is None else now
        async with self._lock:
            await self._db.execute(
                "UPDATE sessions SET revoked_at=? WHERE token_hash=? AND revoked_at IS NULL",
                (now, token_hash),
            )
            await self._db.commit()

    async def revoke_user_sessions(
        self, user_id: str, *, except_token_hash: str | None = None, now: float | None = None
    ) -> int:
        """Revoke a user's active sessions; with ``except_token_hash`` set, all **but** that one (the
        caller's current session — "sign out everywhere else"). Returns the number revoked."""
        now = time.time() if now is None else now
        sql = "UPDATE sessions SET revoked_at=? WHERE user_id=? AND revoked_at IS NULL"
        params: list[object] = [now, user_id]
        if except_token_hash is not None:
            sql += " AND token_hash != ?"
            params.append(except_token_hash)
        async with self._lock:
            cur = await self._db.execute(sql, params)
            await self._db.commit()
            return int(cur.rowcount)

    async def enforce_session_cap(
        self, user_id: str, *, keep: int, now: float | None = None
    ) -> None:
        """Revoke a user's active sessions beyond the ``keep`` most recently created (AUTH-SESS-CAP)."""
        if keep <= 0:
            return
        now = time.time() if now is None else now
        async with self._lock:
            await self._db.execute(
                "UPDATE sessions SET revoked_at=? WHERE user_id=? AND revoked_at IS NULL"
                " AND token_hash NOT IN ("
                "  SELECT token_hash FROM sessions WHERE user_id=? AND revoked_at IS NULL"
                "  ORDER BY created_at DESC, token_hash DESC LIMIT ?"
                ")",
                (now, user_id, user_id, keep),
            )
            await self._db.commit()

    async def purge_expired_sessions(self, *, now: float | None = None) -> int:
        now = time.time() if now is None else now
        async with self._lock:
            cur = await self._db.execute("DELETE FROM sessions WHERE expires_at < ?", (now,))
            await self._db.commit()
            return cur.rowcount if cur.rowcount is not None else 0

    async def db_status(self) -> DbStatus:
        """Database health snapshot (size, free space, journal mode, row counts)."""
        cur = await self._db.execute("PRAGMA journal_mode")
        row = await cur.fetchone()
        journal = str(row[0]) if row else ""
        return DbStatus(
            path=self.path,
            size_bytes=self._db_size_bytes(),
            disk_free_bytes=self._disk_free_bytes(),
            journal_mode=journal,
            messages=await self._count("messages"),
            events=await self._count("message_events"),
            audit=await self._count("audit_log"),
        )

    async def integrity_check(self) -> tuple[bool, str]:
        """Run ``PRAGMA quick_check`` (can be slow on a large DB — call on demand only)."""
        cur = await self._db.execute("PRAGMA quick_check")
        results = [str(r[0]) for r in await cur.fetchall()]
        ok = results == ["ok"]
        return ok, "ok" if ok else "; ".join(results)[:500]

    async def _count(self, table: str) -> int:
        cur = await self._db.execute(f"SELECT COUNT(*) AS n FROM {table}")  # table is a constant
        row = await cur.fetchone()
        return int(row["n"]) if row else 0

    def _db_size_bytes(self) -> int:
        total = 0
        for suffix in ("", "-wal", "-shm"):
            p = Path(self.path + suffix)
            if p.exists():
                total += p.stat().st_size
        return total

    def _disk_free_bytes(self) -> int:
        try:
            return shutil.disk_usage(Path(self.path).resolve().parent).free
        except OSError:
            return 0

    # --- retention / purge + maintenance (PHI.md §8, ASVS 14.2.x) -------------

    async def purge_message_bodies(self, *, older_than: float, now: float | None = None) -> int:
        """Null the PHI **bodies** of fully-resolved messages received before ``older_than`` while
        **keeping their metadata rows** — the Mirth Data-Pruner pattern (count-and-log + audit stay
        intact; nothing is accepted-and-dropped retroactively).

        A message is eligible only when it has **no queue row still ``pending``/``inflight``**: never
        purge a body that hasn't finished its pipeline, or at-least-once delivery would lose data. For
        each eligible message this blanks ``messages.raw``/``summary``/``error``, the ``done``/
        ``cancelled`` outbound payloads + their ``last_error`` (delivered/cancelled history), and any
        ``message_events.detail`` (all PHI-bearing). ``dead`` rows are intentionally left to
        :meth:`purge_dead_letters` (a dead row stays replayable until its own window) — and because
        replay re-queues a row's *own* payload, never ``messages.raw``, nulling the message body here
        can't break a later dead-row replay. Idempotent (guards on a non-blank body); returns the
        number of messages whose body was nulled."""
        now = time.time() if now is None else now
        inflight = (OutboxStatus.PENDING.value, OutboxStatus.INFLIGHT.value)
        # A message past the cutoff with nothing still in flight. Embedded in each UPDATE below so the
        # three tables are purged for exactly the same set, in one transaction.
        eligible = (
            "SELECT id FROM messages m WHERE m.received_at < ? "
            "AND NOT EXISTS (SELECT 1 FROM queue q WHERE q.message_id = m.id AND q.status IN (?, ?))"
        )
        async with self._lock:
            try:
                await self._db.execute("BEGIN")
                cur = await self._db.execute(
                    f"UPDATE messages SET raw='', summary=NULL, error=NULL "
                    f"WHERE raw <> '' AND id IN ({eligible})",
                    (older_than, *inflight),
                )
                purged = cur.rowcount
                # Blank the kept (delivered/cancelled) outbound payloads for the same eligible set.
                await self._db.execute(
                    f"UPDATE queue SET payload='', last_error=NULL "
                    f"WHERE stage=? AND status IN (?, ?) AND payload <> '' "
                    f"AND message_id IN ({eligible})",
                    (
                        Stage.OUTBOUND.value,
                        OutboxStatus.DONE.value,
                        OutboxStatus.CANCELLED.value,
                        older_than,
                        *inflight,
                    ),
                )
                await self._db.execute(
                    f"UPDATE message_events SET detail=NULL "
                    f"WHERE detail IS NOT NULL AND message_id IN ({eligible})",
                    (older_than, *inflight),
                )
                await self._db.commit()
            except Exception:
                await self._db.rollback()
                raise
        return int(purged)

    async def purge_dead_letters(self, *, older_than: float, now: float | None = None) -> int:
        """Null the bodies of dead-lettered **outbound** rows last updated before ``older_than`` —
        their own retention window, separate from :meth:`purge_message_bodies` because a dead row stays
        replayable (re-queueing its stored ``payload``) until purged. Keeps the row + ``dead`` status
        (counts/disposition intact) and blanks ``payload`` + ``last_error``; after this the row can no
        longer be meaningfully replayed (its body is gone — the intended retention trade-off).
        Idempotent (guards on a non-blank payload); returns the number of dead rows purged."""
        now = time.time() if now is None else now
        async with self._lock:
            cur = await self._db.execute(
                "UPDATE queue SET payload='', last_error=NULL "
                "WHERE stage=? AND status=? AND payload <> '' AND updated_at < ?",
                (Stage.OUTBOUND.value, OutboxStatus.DEAD.value, older_than),
            )
            await self._db.commit()
            return int(cur.rowcount)

    async def wal_checkpoint(self) -> None:
        """Force a full WAL checkpoint + truncate (``PRAGMA wal_checkpoint(TRUNCATE)``) so the ``-wal``
        sidecar — which holds recently-written PHI outside any app-level cipher — doesn't grow
        unbounded between SQLite's own ~1000-page auto-checkpoints. Runs outside a transaction."""
        async with self._lock:
            await self._db.commit()  # ensure no open transaction before checkpointing
            await self._db.execute("PRAGMA wal_checkpoint(TRUNCATE)")

    async def vacuum(self) -> None:
        """Rebuild the database file to reclaim space freed by purges (SQLite ``VACUUM``). VACUUM holds
        a write lock on the whole DB for its duration and serialises on the store lock, so the
        RetentionRunner schedules it at a daily off-peak time and it is off by default. Must run
        outside a transaction (VACUUM cannot run inside one)."""
        async with self._lock:
            await self._db.commit()  # VACUUM cannot run inside a transaction
            await self._db.execute("VACUUM")

    async def stats(self) -> dict[str, int]:
        """Outbound-queue depth by status — feeds the monitoring/queue-depth view. Scoped to outbound
        rows so the numbers match the pre-staged-pipeline meaning (delivery backlog)."""
        cur = await self._db.execute(
            "SELECT status, COUNT(*) AS n FROM queue WHERE stage=? GROUP BY status",
            (Stage.OUTBOUND.value,),
        )
        return {r["status"]: r["n"] for r in await cur.fetchall()}

    async def connection_metrics(
        self, *, since: float, now: float | None = None, rate_window: float = 60.0
    ) -> ConnectionMetrics:
        """Aggregate per-channel inbound and per-destination outbound metrics for the
        connections dashboard. Counts (read/errored/written/dead) cover activity at or after
        ``since`` (engine start); queue depth and ages reflect current state; ``recent_done``
        is completions within the last ``rate_window`` seconds (for backlog ETA)."""
        now = time.time() if now is None else now
        rate_since = now - rate_window

        # Inbound counts since `since`, plus all-time last-received (for idle time).
        cur = await self._db.execute(
            "SELECT channel_id, COUNT(*) AS read,"
            " SUM(CASE WHEN status=? THEN 1 ELSE 0 END) AS errored"
            " FROM messages WHERE received_at>=? GROUP BY channel_id",
            (MessageStatus.ERROR.value, since),
        )
        counts = {r["channel_id"]: (r["read"], r["errored"]) for r in await cur.fetchall()}
        cur = await self._db.execute(
            "SELECT channel_id, MAX(received_at) AS last_at FROM messages GROUP BY channel_id"
        )
        inbound: dict[str, InboundMetrics] = {}
        for r in await cur.fetchall():
            read, errored = counts.pop(r["channel_id"], (0, 0))
            inbound[r["channel_id"]] = InboundMetrics(
                read=int(read), errored=int(errored or 0), last_at=r["last_at"]
            )
        for cid, (read, errored) in counts.items():  # since-window rows w/o an all-time row
            inbound[cid] = InboundMetrics(read=int(read), errored=int(errored or 0), last_at=None)

        cur = await self._db.execute(
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
        for r in await cur.fetchall():
            destinations[(r["channel_id"], r["destination_name"])] = DestinationMetrics(
                queue_depth=int(r["queue_depth"] or 0),
                written=int(r["written"] or 0),
                dead=int(r["dead"] or 0),
                oldest_pending_at=r["oldest_pending_at"],
                recent_done=int(r["recent_done"] or 0),
                last_done_at=r["last_done_at"],
            )
        return ConnectionMetrics(inbound=inbound, destinations=destinations)

    # --- internals -----------------------------------------------------------

    async def _row(self, outbox_id: str) -> aiosqlite.Row | None:
        cur = await self._db.execute("SELECT * FROM queue WHERE id=?", (outbox_id,))
        return await cur.fetchone()

    async def _event(
        self, message_id: str, event: str, destination: str | None, detail: str, now: float
    ) -> None:
        await self._db.execute(
            "INSERT INTO message_events (message_id, ts, event, destination, detail)"
            " VALUES (?,?,?,?,?)",
            (message_id, now, event, destination, self._enc(detail)),
        )

    async def _maybe_finalize_message(self, message_id: str, now: float) -> None:
        """Drive a message to its terminal disposition from its queue rows across **all** stages — the
        single source of truth for the staged-pipeline count-and-log flow (ADR 0001 Step B). Called on
        every terminal transition: delivery done/dead, the transform handoff, cancel, and the orphan
        sweeps.

        The message is **not** finalized while ANY row at ANY stage is still pending/inflight — a
        delivered outbound row must not flip the message ``PROCESSED`` while a sibling handler's routed
        row still awaits transform (the premature-finalize hazard the split introduces). Once nothing
        is in flight, in strict precedence:

        - any **dead** row at any stage → ``ERROR`` — a failure anywhere is a real failure, even if a
          sibling handler delivered (the dead row is replayable via :meth:`replay`);
        - else any **outbound** row exists → ``PROCESSED`` — all delivered (or operator-cancelled);
        - else **no rows remain** and the message is still ``ROUTED`` → ``FILTERED`` — every selected
          handler ran and produced zero deliveries (the ROUTED→FILTERED collapse the transform handoff
          delegates here; a message that routed nowhere is ``UNROUTED``, already set, and untouched);
        - else leave the disposition the handoff set."""
        cur = await self._db.execute(
            "SELECT stage, status, COUNT(*) AS n FROM queue WHERE message_id=? GROUP BY stage, status",
            (message_id,),
        )
        rows = await cur.fetchall()
        # In flight at any stage (the ingress raw, a sibling's routed row, or an undelivered outbound)
        # → the message is still moving; do not finalize.
        if any(
            r["status"] in (OutboxStatus.PENDING.value, OutboxStatus.INFLIGHT.value) for r in rows
        ):
            return
        if any(r["status"] == OutboxStatus.DEAD.value for r in rows):
            status = MessageStatus.ERROR.value
        elif any(r["stage"] == Stage.OUTBOUND.value for r in rows):
            # Outbound rows, none dead, none in flight → delivered (or all operator-cancelled).
            status = MessageStatus.PROCESSED.value
        elif not rows:
            # No queue rows remain. If routing selected >=1 handler the message is ``ROUTED``; reaching
            # here means every handler's transform produced zero deliveries → collapse to ``FILTERED``.
            # A message that routed nowhere (``UNROUTED``) or was already ``FILTERED`` keeps its status.
            cur = await self._db.execute("SELECT status FROM messages WHERE id=?", (message_id,))
            msg = await cur.fetchone()
            if msg is None or msg["status"] != MessageStatus.ROUTED.value:
                return
            status = MessageStatus.FILTERED.value
        else:
            return  # only terminal non-dead non-outbound rows (shouldn't occur) — leave as-is
        await self._db.execute("UPDATE messages SET status=? WHERE id=?", (status, message_id))
