# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
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
from collections.abc import AsyncIterator, Awaitable, Callable, Iterable, Mapping
from contextlib import asynccontextmanager
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from types import MappingProxyType
from typing import Any, Sequence
from uuid import uuid4

import aiosqlite

from messagefoundry.config.models import RetryPolicy
from messagefoundry.config.settings import StoreBackend
from messagefoundry.parsing.binary import strip_documents as _strip_documents
from messagefoundry.redaction import safe_text
from messagefoundry.store.audit_tee import emit_audit_tee
from messagefoundry.store.content_search import SearchSpec, row_matches
from messagefoundry.store.document_strip import StripResult, cutoff_for
from messagefoundry.store.crypto import MARKER_PREFIX as _ENC_MARKER_PREFIX
from messagefoundry.store.crypto import (
    AesGcmCipher,
    Cipher,
    CipherError,
    CipherInfo,
    IdentityCipher,
    cipher_info,
)

log = logging.getLogger(__name__)

# Size of the dedicated read-only connection pool (lockfree-reads). Reads run on these connections
# instead of serializing behind the single writer's lock: WAL gives each reader a consistent snapshot
# concurrent with the writer, so a read takes no write lock and can't interleave mid-write-transaction.
# A small bounded pool — readers are short and SQLite reads scale poorly past a handful of connections;
# this is intentionally not a tunable setting (kept off config/settings.py while another lane owns it).
_READ_POOL_SIZE = 4


class _AbortMember(Exception):  # noqa: N818 — control-flow signal, not an error condition
    """Raised inside a grouped member body to short-circuit it WITHOUT failing the batch.

    A grouped stage-handoff returns early in its idempotent no-op cases (an INFLIGHT-guarded DELETE
    that matched 0 rows, a vanished row, an absent ``_row`` read) — in the inline path that does
    ``rollback(); return <sentinel>``. Under group-commit a single member cannot roll back the shared
    transaction, but every such early-exit runs **only read-only or zero-mutation** statements before it
    (the guarded DELETE matched nothing; the SELECT/``_row`` is a read), so the member contributes no net
    write and is safe to leave in the committing batch. The body raises this carrying its logical result;
    the committer/inline wrapper unwraps ``result`` and stops the body, leaving the batch intact."""

    __slots__ = ("result",)

    def __init__(self, result: Any) -> None:
        super().__init__("member aborted")
        self.result = result


@dataclass
class _Member:
    """One mutation enrolled in the open group-commit batch.

    ``run`` executes the member's prepared statements on the shared write connection between the
    committer's single ``BEGIN`` and ``COMMIT`` (it must NOT issue BEGIN/commit/rollback itself). Its
    return value (or an :class:`_AbortMember`'s ``result``) is delivered via ``future`` once the batch
    commits; on a group rollback every member's ``future`` is rejected so each caller re-runs."""

    run: "Callable[[], Awaitable[Any]]"
    future: "asyncio.Future[Any]"
    # Optional post-commit hook run synchronously in the COMMITTER's frame the instant the batch
    # commits, BEFORE the future resolves — used to publish a read-through cache delta atomically with
    # the durable write. Living here (not in the caller's frame after `await fut`) means a committed
    # write's cache publish can never be skipped by the caller being cancelled while parked on the
    # future (e.g. a transform worker cancelled on reload). Only ever invoked on commit success; a
    # rolled-back member's hook never runs, so an uncommitted delta never leaks into the cache.
    on_commit: "Callable[[Any], None] | None" = None


class _GroupCommitter:
    """App-side group-commit committer for the SQLite write connection (ADR 0055).

    Coalesces N grouped stage-handoff mutations into ONE ``COMMIT`` under the store's single writer
    lock, amortizing the per-commit fsync (a large win under ``synchronous=FULL``). A member is
    enrolled via :meth:`submit`; the committer coroutine drains the open batch under ``self._lock``,
    runs each member's statements inside one ``BEGIN`` … ``COMMIT``, then resolves every member's
    future. If ANY member raises (other than :class:`_AbortMember`), or the commit itself fails, the
    whole batch is rolled back and EVERY member's future is rejected — each caller re-runs (a
    coordinated form of the crash-re-run the INFLIGHT-guarded idempotent handoffs already tolerate).

    Enabled only when ``window_ms > 0``; otherwise the store never constructs one and each grouped
    method commits inline (byte-identical to the pre-feature path)."""

    def __init__(
        self,
        db: aiosqlite.Connection,
        lock: asyncio.Lock,
        *,
        window_ms: float,
        max_batch: int,
    ) -> None:
        self._db = db
        self._lock = lock
        self._window = max(window_ms, 0.0) / 1000.0
        self._max_batch = max(max_batch, 1)
        self._pending: list[_Member] = []
        self._wake = asyncio.Event()
        self._closed = False
        self._task: asyncio.Task[None] | None = None

    def start(self) -> None:
        if self._task is None:
            self._task = asyncio.create_task(self._run(), name="store-group-committer")

    async def aclose(self) -> None:
        """Stop the committer, flushing any enrolled members first so nothing is stranded."""
        self._closed = True
        self._wake.set()
        if self._task is not None:
            await self._task
            self._task = None

    async def submit(
        self,
        run: "Callable[[], Awaitable[Any]]",
        *,
        on_commit: "Callable[[Any], None] | None" = None,
    ) -> Any:
        """Enrol a member's statements in the open batch and await its committed result.

        The returned awaitable resolves to the member body's value once the batch commits, or raises
        whatever the body raised (group rollback re-raises the body's own exception in every member).

        ``on_commit`` (a read-through cache publish) runs in the COMMITTER's frame at commit, before the
        future resolves — so it cannot be skipped by this caller being cancelled while parked on the
        future, and it never runs for a rolled-back member (see :class:`_Member`)."""
        if self._closed:
            raise RuntimeError("group committer is closed")
        loop = asyncio.get_running_loop()
        fut: asyncio.Future[Any] = loop.create_future()
        self._pending.append(_Member(run=run, future=fut, on_commit=on_commit))
        self._wake.set()
        return await fut

    async def _run(self) -> None:
        while True:
            await self._wake.wait()
            self._wake.clear()
            if not self._pending:
                if self._closed:
                    return
                continue
            # Coalescing window: let siblings arrive (bounded by max_batch) before committing, so one
            # fsync covers several handoffs. A zero window degenerates to "commit what's here now".
            if self._window > 0 and len(self._pending) < self._max_batch and not self._closed:
                try:
                    await asyncio.wait_for(self._wake.wait(), timeout=self._window)
                    self._wake.clear()
                except TimeoutError:
                    pass
            await self._flush()
            if self._closed and not self._pending:
                return
            # A single _flush commits at most max_batch members; any remainder (a burst larger than
            # one batch, or members that enrolled while the batch ran) must NOT be stranded. Re-arm
            # _wake so the loop drains the next chunk immediately instead of blocking on _wake.wait()
            # until the next submit() — which, on the close path where no further submit arrives, would
            # deadlock aclose() and hang every awaiting member's future (the ACK gate). The window-wait
            # above re-clears _wake, so re-arming here is the sole guarantee the tail gets flushed.
            if self._pending:
                self._wake.set()

    async def _flush(self) -> None:
        # Claim the current batch (cap at max_batch; the remainder rides the next flush).
        batch = self._pending[: self._max_batch]
        if not batch:
            return
        self._pending = self._pending[len(batch) :]
        results: list[Any] = []
        async with self._lock:
            try:
                await self._db.execute("BEGIN")
                for member in batch:
                    try:
                        results.append((member, await member.run(), None))
                    except _AbortMember as abort:
                        # Zero-mutation early exit (idempotent no-op) — stays in the batch.
                        results.append((member, abort.result, None))
                    except Exception as exc:  # noqa: BLE001 — captured to fail the whole group
                        results.append((member, None, exc))
                # If ANY member raised a real error, the shared transaction is poisoned: roll the whole
                # batch back and reject EVERY member's future (each re-runs). We cannot selectively keep
                # the good members — they share one transaction with the failed mutation.
                first_error = next((e for _, _, e in results if e is not None), None)
                if first_error is not None:
                    await self._db.rollback()
                    self._reject_all(batch, results)
                    return
                await self._db.commit()
            except Exception as exc:  # noqa: BLE001 — commit/rollback failure fails the whole group
                try:
                    await self._db.rollback()
                except Exception:  # noqa: BLE001 — best-effort; the connection may be unusable
                    log.warning("group-commit rollback failed", exc_info=True)
                self._reject_all(batch, results, fallback=exc)
                return
        # Commit succeeded → publish each member's read-through cache delta (committer frame, durable
        # write in hand) then resolve its future, OUTSIDE the lock. The publish runs BEFORE the future
        # resolves so a co-batched sibling that wakes on its own result already sees this delta, and so
        # a caller cancelled while parked on the future never causes a committed write to skip the cache.
        # A failing hook must not strand siblings, so it is isolated per member (logged, never raised).
        for member, value, _ in results:
            if member.on_commit is not None:
                try:
                    member.on_commit(value)
                except Exception:  # noqa: BLE001 — a cache-publish fault must not strand the batch
                    log.warning("group-commit post-commit cache publish failed", exc_info=True)
            if not member.future.done():
                member.future.set_result(value)

    @staticmethod
    def _reject_all(
        batch: "list[_Member]",
        results: "list[tuple[_Member, Any, Exception | None]]",
        *,
        fallback: Exception | None = None,
    ) -> None:
        """Reject every member's future on a group rollback so each caller re-runs.

        A member that itself raised gets its OWN exception (so its caller sees the true cause); the
        rest get a coordinated rollback error (or the commit failure) and re-run idempotently."""
        own: dict[int, Exception | None] = {id(m): e for m, _, e in results}
        group_err = fallback or RuntimeError("group commit rolled back (sibling member failed)")
        for member in batch:
            if member.future.done():
                continue
            err = own.get(id(member)) or group_err
            member.future.set_exception(err)


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
    from ``MessageStatus.ROUTED`` (a message's disposition).

    ``response`` (ADR 0013 Increment 2) is a fourth, **optional** stage: a drainable "this captured reply
    still owes a re-ingress" token, produced beside the immutable ``response`` artifact only when the
    delivering outbound declares ``reingress_to``. Its ``destination_name`` is NULL (it keys by
    ``channel_id`` = the loopback inbound, like ingress/routed); the **re-ingress worker** drains it via
    ``ingress_handoff``. A row in this stage is *seen* by the finalizer (it legitimately holds the origin
    message in flight until its reply is handed off)."""

    INGRESS = "ingress"
    ROUTED = "routed"
    OUTBOUND = "outbound"
    RESPONSE = "response"  # ADR 0013 Increment 2: a "this reply owes a re-ingress" work-row token


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
    # The row's enqueue time (epoch seconds) — the engine-assigned, re-run-stable timestamp a Handler
    # reads via current_ingest_time() (ADR 0009 ingest-time provider). None when a backend doesn't
    # surface it (the SQL Server backend is outbound-only and runs no transforms, so it never reads it).
    created_at: float | None = None

    @classmethod
    def from_row(
        cls, row: aiosqlite.Row, cipher: Cipher, *, shared_ciphertext: str | None = None
    ) -> "OutboxItem":
        """Build an item from a claimed queue row, decrypting its body for processing/delivery.

        ``shared_ciphertext`` is the store-once deref seam: when a row carries a ``body_ref`` (its body
        lives once in ``shared_body``), the caller passes that shared copy's ciphertext here and it is
        decrypted in place of the row's empty inline ``payload``. ``None`` (no ref) decrypts the inline
        ``payload`` exactly as before — byte-identical."""
        ciphertext = shared_ciphertext if shared_ciphertext is not None else row["payload"]
        return cls(
            id=row["id"],
            message_id=row["message_id"],
            channel_id=row["channel_id"],
            destination_name=row["destination_name"],
            payload=cipher.decrypt(ciphertext),  # decrypt the body for processing/delivery
            attempts=row["attempts"],
            stage=row["stage"],
            # Plaintext metadata (the handler to run), not a body — never encrypted. NULL off-routed.
            handler_name=row["handler_name"],
            created_at=row["created_at"],  # SELECT * in claim_next_fifo returns it
        )


@dataclass(frozen=True)
class CapturedResponse:
    """One captured request/response reply (ADR 0013), as returned by ``correlate_response`` for the
    API/console read surface. ``body``/``detail`` are decrypted here; ``body`` is ``None`` once
    retention has nulled it (the row is kept, like a purged ``messages.raw``)."""

    message_id: str
    destination_name: str
    response_seq: int
    outcome: str
    detail: str | None
    captured_at: float
    body: str | None
    # ADR 0021 "Response Sent": 'response' (outbound reply, the default) | 'ack_sent' (inbound ACK we
    # returned). ack_code/ack_phase are non-PHI disposition metadata, populated only for ack_sent rows.
    kind: str = "response"
    ack_code: str | None = None
    ack_phase: str | None = None


@dataclass(frozen=True)
class ConnectionEvent:
    """One metadata-only connection event (Corepoint-style transport/lifecycle log, #46), as returned
    by ``list_connection_events`` for the ``GET /events`` read surface. Never carries a frame, message
    body, or HL7 field value — ``reason`` is ``safe_text``-scrubbed and decrypted here. ``message_id``
    is a nullable, non-FK correlation hint set only for outbound lane events."""

    id: int
    ts: float
    connection: str
    transport: str
    direction: str  # 'inbound' | 'outbound'
    kind: str
    peer_host: str | None
    message_id: str | None
    reason: str | None


@dataclass(frozen=True)
class AlertInstance:
    """One resolvable operator-alert instance (ADR 0044, #56), as returned by
    ``list_active_alert_instances`` for the ``GET /alerts/active`` read surface. De-duped on ADR 0014's
    ``(event_type, connection)`` throttle key, with an open → acknowledged → resolved lifecycle and a
    first_seen/last_seen window + occurrence ``count``. **Metadata only** — ``reason`` is
    ``safe_text``-scrubbed and decrypted here; it never carries a message body or HL7 field value."""

    id: int
    event_type: str
    connection: str
    severity: str
    status: str  # 'open' | 'acknowledged' | 'resolved'
    first_seen: float
    last_seen: float
    count: int
    reason: str | None
    acked_by: str | None
    acked_at: float | None
    resolved_at: float | None


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
class LatencyHistogram:
    """Per-(channel, destination) delivery-latency histogram over ``done`` outbound rows.

    ``bucket_counts`` are **cumulative** (Prometheus ``le`` semantics): ``bucket_counts[i]`` is the
    number of done outbound rows whose latency (``updated_at - created_at``, clamped to ``>= 0``) is
    ``<= buckets[i]``. ``count`` is the total number of done rows (== the ``+Inf`` bucket) and
    ``sum_seconds`` is the SUM of clamped latency over those rows.
    """

    channel_id: str
    destination_name: str
    # cumulative: count of done outbound rows with latency <= buckets[i]
    bucket_counts: tuple[int, ...]
    sum_seconds: float  # SUM of clamped latency over done outbound rows
    count: int  # total done outbound rows (== the +Inf bucket)


@dataclass(frozen=True)
class ConnectionMetrics:
    inbound: dict[str, InboundMetrics]  # by channel_id
    destinations: dict[tuple[str, str], DestinationMetrics]  # by (channel_id, destination_name)


@dataclass(frozen=True)
class MessageSearchResult:
    """The outcome of a scan-and-decrypt content search (ADR 0046 #51). ``rows`` are matched message
    summaries (the same metadata-only shape ``list_messages`` returns — never a decrypted body, so the
    PHI exposure equals the metadata list, gated by the same ``view_summary`` redaction). ``scanned``
    is how many candidate rows were decrypted; ``matched`` == ``len(rows)`` before the result cap;
    ``truncated`` is True when the scan stopped at ``scan_limit`` before exhausting the candidate set
    (so the caller should narrow filters) — the truncate-and-tell signal."""

    rows: list[dict[str, Any]]
    scanned: int
    matched: int
    truncated: bool


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
    # MFA (WP-14): whether a native TOTP second factor is enrolled+active, and when. The secret and
    # the recovery-code hashes are deliberately NOT carried here (least exposure) — they are read only
    # via the store's get_totp_secret / get_recovery_code_hashes accessors.
    totp_enabled: bool = False
    totp_enrolled_at: float | None = None

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
            totp_enabled=bool(d.get("totp_enabled", 0)),
            totp_enrolled_at=_opt_float(d.get("totp_enrolled_at")),
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
    #: When the session last proved the caller's credential — set at login and refreshed by
    #: ``POST /me/reauth``; gates step-up re-verification on sensitive operations (ASVS 7.5.3).
    reauth_at: float | None = None
    #: When the session satisfied its **second factor** (TOTP / recovery code, or set at issuance for
    #: an MFA-delegated AD/Kerberos login). NULL = the 2nd factor is unsatisfied (WP-14, ASVS 6.3.3).
    mfa_verified_at: float | None = None

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
            reauth_at=_opt_float(d.get("reauth_at")),
            mfa_verified_at=_opt_float(d.get("mfa_verified_at")),
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


def delivery_key(
    *,
    control_id: str | None,
    message_id: str,
    destination_name: str,
    handler_name: str | None,
    delivery_seq: int,
) -> str:
    """The idempotency-ledger key for one **completed** outbound delivery (H2) — a SHA-256 digest of
    re-run-stable, **non-PHI** identifiers only (ids + a counter; **never a body**).

    Folds in the inbound control id (MSH-10) when present, else the internal ``message_id`` (so two
    messages that happen to share a control id across channels stay distinct via the destination +
    seq), the destination, the handler that produced the delivery (NULL → empty), and ``delivery_seq``
    — ``1 + COUNT(prior ledger rows for this (message_id, destination))``, the same monotonic,
    replay-stable counter shape as ``response_seq`` (ADR 0013). The seq is what distinguishes an
    **operator replay** (a fresh, higher-seq delivery → a new key → re-sends, never deduped) from a
    **crash-re-run** (the same row instance recovered before its completion committed — its prior
    ledger row, if any, is keyed by ``outbox_id`` and caught at claim time, not by this hash).

    Shared verbatim by all three store backends so the digest is byte-identical across SQLite/Postgres/
    SQL Server. control_id is a peek-derived MSH field — included as an *operator-facing correlation
    aid* in the digest input only; it is hashed, never stored or logged in the clear here."""
    canonical = json.dumps(
        [
            control_id if control_id is not None else message_id,
            destination_name,
            handler_name or "",
            delivery_seq,
        ],
        sort_keys=True,
        default=str,
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


def _qmark_cutoff_case(
    column: str,
    global_cutoff: float,
    connection_cutoffs: Mapping[str, float] | None,
) -> tuple[str, list[Any]]:
    """Build a ``?``-placeholder cutoff expression for the per-connection retention override (#34,
    ADR 0027), shared by the SQLite and SQL Server backends (both use ``?`` binds).

    With no per-connection override (``connection_cutoffs`` empty/None) this returns the bare
    ``("?", [global_cutoff])`` — **byte-identical** to the single global cutoff today. With overrides it
    returns a ``CASE <column> WHEN ? THEN ? ... ELSE ? END`` whose per-connection ``THEN`` cutoffs come
    from the map and whose ``ELSE`` is the global cutoff (a connection absent from the map inherits the
    global window). A keep-forever override is carried as ``float('-inf')`` so ``received_at < -inf`` is
    always false → that connection is never purged. The returned fragment is meant to sit on the RIGHT of
    a ``received_at <`` / ``updated_at <`` comparison; the bind list is in placeholder order."""
    if not connection_cutoffs:
        return "?", [global_cutoff]
    whens: list[str] = []
    params: list[Any] = []
    for name, cutoff in connection_cutoffs.items():
        whens.append("WHEN ? THEN ?")
        params.append(name)
        params.append(cutoff)
    params.append(global_cutoff)  # ELSE — connections with no override use the global window
    return f"(CASE {column} {' '.join(whens)} ELSE ? END)", params


def _secure_file(path: Path, *, extra_read_grants: Sequence[str] | None = None) -> None:
    """Restrict a store file to its owner — it holds PHI at rest.

    Best-effort and non-fatal: failing to tighten permissions must never stop the engine from
    starting (``docs/PHI.md``'s ops checklist covers directory-level ACLs as the backstop). On
    POSIX this is ``chmod 0600``; on Windows ``os.chmod`` only toggles the read-only bit, so we set
    an owner-only DACL via ``icacls`` (inheritance disabled) instead. A skipped or failed
    restriction is **logged** (STORE-2) so it isn't silently world-readable.

    ``extra_read_grants`` (Windows only) names additional principals — a name like
    ``NT SERVICE\\MessageFoundry`` or a SID like ``*S-1-5-18`` — to grant **read** on the file. The
    DPAPI key file needs this so the engine's *service account* (not just the admin who minted it) can
    read the key at startup; the generic store DB/WAL files pass nothing and stay owner-only.
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
            # icacls is a fixed system tool, invoked without a shell; an extra-grant principal (if any)
            # is a single argv token, never a shell word, so it can't inject a flag (low-27/STORE-5).
            grants = [f"{user}:F", *(f"{p}:R" for p in extra_read_grants or ())]
            result = subprocess.run(  # nosec B603 B607
                ["icacls", str(path), "/inheritance:r", "/grant:r", *grants],
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
    summary      TEXT,             -- ingest-derived (MRN/name/order) — PHI, cipher-encrypted at rest (EF-3)
    metadata     TEXT,             -- code/operator-attached values — PHI, cipher-encrypted at rest (EF-3)
    documents_pruned REAL          -- #47/ADR 0042: epoch ts an embedded doc was stripped in place (NULL=never)
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
    body_ref         TEXT,            -- store-once-deliver-many: when set, the body lives ONCE in
                                      -- shared_body[body_ref] and payload is '' (deref'd at delivery);
                                      -- NULL = body is inline in payload (the default, byte-identical)
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
-- ix_queue_body_ref (store-once-deliver-many) is created in _migrate, AFTER body_ref is guaranteed
-- present — on a Step-A `queue` table (no body_ref) a body_ref index here would reference a missing
-- column (CREATE TABLE IF NOT EXISTS is a no-op on the pre-existing table). Mirrors handler_name.

-- Store-once-deliver-many (L2b): when one handler's transform produces an IDENTICAL transformed body
-- for N destinations (a high-fan-out feed), the body is stored ONCE here and the N outbound rows carry
-- a `body_ref` to it instead of each holding its own encrypted copy — cutting stored body bytes from
-- N× to ~1×. `hash` is the content address: SHA-256 of the PLAINTEXT body (hashing the plaintext, not
-- the ciphertext — AES-GCM uses a random nonce, so two encryptions of one plaintext differ). `body` is
-- the single encrypted copy (cipher-covered at rest exactly like queue.payload, and it rides the
-- key-rotation re-encrypt). `refcount` is the number of live queue rows referencing this body; a body
-- is GC-deleted the moment its refcount reaches 0 (decremented when a referencing row's body is purged
-- or the row is deleted), so retention can never orphan a body nor delete one an outbound row still
-- needs. Bodies are deduped only WITHIN one transform_handoff's deliveries (same transaction, same
-- plaintext in hand) — a conservative, well-bounded unit that captures the fan-out win without a
-- cross-message dedup race.
CREATE TABLE IF NOT EXISTS shared_body (
    hash       TEXT PRIMARY KEY,   -- sha256(plaintext body) — the content address
    body       TEXT NOT NULL,      -- the single encrypted copy (cipher-covered, like queue.payload)
    refcount   INTEGER NOT NULL,   -- live queue rows referencing this body; row GC'd at 0
    created_at REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS message_events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    message_id  TEXT NOT NULL REFERENCES messages(id),
    ts          REAL NOT NULL,
    event       TEXT NOT NULL,        -- received|delivered|failed|dead|replayed|viewed...
    destination TEXT,
    detail      TEXT
);
CREATE INDEX IF NOT EXISTS ix_events_message ON message_events(message_id, ts);

-- Transform-accessible state (ADR 0005): cross-message correlation values a Handler declares via
-- SetState and reads back via state_get. Upserted by (namespace,key) INSIDE the routed->outbound
-- handoff transaction, so a write is exactly-once with the message's processing (no double-apply on a
-- crash-re-run). `value` is JSON-encoded then cipher-encrypted at rest (it may carry PHI, e.g. an
-- MRN->anon mapping). `message_id` records which message last wrote it (audit/traceability); not an FK
-- (a state row outlives its writer's body purge). `set_at` drives the age-based retention purge.
CREATE TABLE IF NOT EXISTS state (
    namespace  TEXT NOT NULL,
    key        TEXT NOT NULL,
    value      TEXT NOT NULL,        -- json.dumps(value), encrypted at rest
    set_at     REAL NOT NULL,
    message_id TEXT,                 -- the message that last wrote this entry (audit; not an FK)
    PRIMARY KEY (namespace, key)
);
CREATE INDEX IF NOT EXISTS ix_state_set_at ON state(set_at);

-- Reference sets (ADR 0006 Tier 1): managed, versioned, read-only lookup snapshots materialized OFF
-- the message path (a provider directory, a DB-backed translation table) and read PURELY by a transform
-- via reference("name").get(key). Each sync writes a whole new (name, version) snapshot and atomically
-- flips it active, replacing the prior version — build-new-then-flip, so a reader sees the old or new
-- snapshot whole, never torn, and a failed sync leaves the last-good active. `value` is JSON-encoded
-- then cipher-encrypted at rest (it may carry PHI). reference_version records the active version per
-- name (synced_at drives the staleness guard; row_count is audit metadata).
CREATE TABLE IF NOT EXISTS reference (
    name       TEXT NOT NULL,
    version    TEXT NOT NULL,
    key        TEXT NOT NULL,
    value      TEXT NOT NULL,           -- json.dumps(value), encrypted at rest
    PRIMARY KEY (name, version, key)
);
CREATE INDEX IF NOT EXISTS ix_reference_name ON reference(name);

CREATE TABLE IF NOT EXISTS reference_version (
    name       TEXT NOT NULL,
    version    TEXT NOT NULL,
    synced_at  REAL NOT NULL,
    row_count  INTEGER NOT NULL,
    PRIMARY KEY (name)                  -- one row per set: the ACTIVE version
);

-- Captured request/response replies (ADR 0013 Increment 1): a partner's reply to one outbound
-- delivery, persisted INSIDE the same transaction that marks the outbound row done. This is an
-- immutable derived artifact (a sibling of `state`/`reference`), NOT a `queue` stage — so it is
-- invisible to _maybe_finalize_message's `FROM queue` disposition scan (a captured reply can never
-- pin a message out of PROCESSED or flip it to ERROR). `response_seq` is monotonic per
-- (message_id, destination_name) and is the PRIMARY KEY's discriminator, so each capture is a plain
-- INSERT that never overwrites a prior reply (immutability is a schema property). It is replay-stable:
-- `replay` resets queue.attempts=0, so an attempts-keyed row would collide — response_seq is assigned
-- 1+MAX(seq) at insert and a replay's re-delivery simply appends seq=N+1. `body`/`detail` are
-- cipher-encrypted at rest (PHI) and nulled in place by retention (kept row, like messages.raw).
CREATE TABLE IF NOT EXISTS response (
    message_id       TEXT    NOT NULL REFERENCES messages(id),
    destination_name TEXT    NOT NULL,
    response_seq     INTEGER NOT NULL,   -- 1+MAX per (message_id, destination_name); replay-stable
    body             TEXT,               -- partner reply, encrypted at rest; NULL once retention purges
    outcome          TEXT    NOT NULL,   -- 'accepted' | 'rejected' | 'unparseable' | 'no_reply'
    detail           TEXT,               -- short reason (MSA-1 / HTTP status), encrypted at rest
    captured_at      REAL    NOT NULL,
    -- ADR 0021 "Response Sent": the inbound ACK we returned rides this table via a `kind` discriminator.
    kind             TEXT    NOT NULL DEFAULT 'response',  -- 'response' (outbound reply) | 'ack_sent'
    ack_code         TEXT,               -- AA|AE|AR|CA|CE|CR for ack_sent; NULL for an outbound response
    ack_phase        TEXT,               -- decode|parse|strict|ingest for ack_sent; NULL for response
    PRIMARY KEY (message_id, destination_name, response_seq)
);
CREATE INDEX IF NOT EXISTS ix_response_message ON response(message_id);

-- Outbound idempotency ledger (H2): one row per COMPLETED delivery, INSERTed in the SAME transaction
-- as the outbound row's mark_done / complete_with_response. `delivery_key` is a SHA-256 of non-PHI ids
-- + a replay-stable seq (see delivery_key()); `outbox_id` is the queue row that delivered, used by the
-- FIFO claim's skip-and-complete to no-op a re-claimed already-delivered head (crash-re-run dedup)
-- WITHOUT re-sending. This table carries HASHES + IDS ONLY — never a message body or any PHI — so it
-- is stored in the clear (nothing to decrypt; it is not part of the `_cipher` seam). A deliberate
-- operator `replay` DELETEs the affected rows so the re-send is NOT deduped (replay-distinguishes).
CREATE TABLE IF NOT EXISTS delivered_keys (
    delivery_key     TEXT PRIMARY KEY,    -- sha256(control_id|message_id, dest, handler, seq) — no PHI
    outbox_id        TEXT NOT NULL,       -- the queue row that delivered (claim-time dedup lookup key)
    message_id       TEXT NOT NULL,
    destination_name TEXT NOT NULL,
    delivery_seq     INTEGER NOT NULL,    -- 1+COUNT prior rows for (message_id, destination_name)
    delivered_at     REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_delivered_outbox  ON delivered_keys(outbox_id);
CREATE INDEX IF NOT EXISTS ix_delivered_message ON delivered_keys(message_id, destination_name);

-- Connection/transport event log (Corepoint-style #46): inbound lifecycle (established/closed), the
-- pre-ingress failures that have no message_id (allowlist/capacity/oversize/peer-reset/framing), and
-- outbound lane transitions (connection_lost/restored). METADATA-ONLY — never a frame, body, or HL7
-- field value. id-keyed (so it is NOT a `queue` stage → invisible to _maybe_finalize_message's
-- `FROM queue` scan, exactly like `response`); `message_id` is a NULLABLE, deliberately NO-FK
-- correlation hint (outbound lane events only) so a pre-ingress event needs no messages row and can
-- never inflate received counts. `reason` is safe_text-scrubbed and encrypted at rest (_CIPHER_COLUMNS).
CREATE TABLE IF NOT EXISTS connection_event (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ts          REAL NOT NULL,
    connection  TEXT NOT NULL,        -- inbound/outbound connection name (config metadata, never payload)
    transport   TEXT NOT NULL,        -- ConnectorType.value, e.g. 'mllp'
    direction   TEXT NOT NULL,        -- 'inbound' | 'outbound' (code-enforced; SQLite can't ADD a CHECK)
    kind        TEXT NOT NULL,        -- bounded engine enum (lifecycle + failure kinds)
    peer_host   TEXT,                 -- peer IP from the socket (metadata); NULL for outbound/unknown
    message_id  TEXT,                 -- NULLABLE, NO FK — outbound lane correlation hint only
    reason      TEXT                  -- safe_text-scrubbed diagnostic, encrypted at rest
);
CREATE INDEX IF NOT EXISTS ix_connection_event_conn ON connection_event(connection, ts);

-- Operator alert-state (ADR 0044, #56) — resolvable alert INSTANCES with an open/acknowledged/resolved
-- lifecycle. METADATA-ONLY (no body, no HL7 field value): the row carries the alert's type, connection
-- label, effective severity, the first/last-seen window + occurrence count, and a safe_text-scrubbed
-- `reason` (encrypted at rest, _CIPHER_COLUMNS — like connection_event.reason). De-duped on ADR 0014's
-- (event_type, connection) throttle key: the partial unique index pins ONE non-resolved instance per
-- key so the upsert folds re-fires into it (resolved rows drop out of the index, leaving the key free to
-- re-open). id-keyed (NOT a `queue` stage → invisible to _maybe_finalize_message's `FROM queue` scan):
-- an alert-instance write is a pure side observer, never pinning a message disposition.
CREATE TABLE IF NOT EXISTS alert_instance (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    event_type  TEXT NOT NULL,        -- AlertSink event name (bounded engine enum)
    connection  TEXT NOT NULL,        -- connection/cert/db label (config metadata, never payload)
    severity    TEXT NOT NULL,        -- effective ADR 0014 severity (info|warning|critical), last write wins
    status      TEXT NOT NULL,        -- 'open' | 'acknowledged' | 'resolved'
    first_seen  REAL NOT NULL,
    last_seen   REAL NOT NULL,
    count       INTEGER NOT NULL,     -- occurrences folded into this open instance
    reason      TEXT,                 -- safe_text-scrubbed diagnostic, encrypted at rest
    acked_by    TEXT,                 -- operator who acknowledged (NULL until acked)
    acked_at    REAL,
    resolved_at REAL                  -- when it resolved (NULL while open/acknowledged)
);
-- One LIVE (non-resolved) instance per throttle key; resolved rows leave the index so the key re-opens.
CREATE UNIQUE INDEX IF NOT EXISTS ux_alert_instance_open
    ON alert_instance(event_type, connection) WHERE status != 'resolved';
CREATE INDEX IF NOT EXISTS ix_alert_instance_status ON alert_instance(status, connection);

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

CREATE TABLE IF NOT EXISTS pending_approvals (
    id           TEXT PRIMARY KEY,
    operation    TEXT NOT NULL,        -- registered op key, e.g. 'dead_letter_replay'
    params       TEXT NOT NULL,        -- JSON args captured at request time, replayed on approval
    requester    TEXT NOT NULL,        -- who initiated; can never self-approve (dual-control, 2.3.5)
    requested_at REAL NOT NULL,
    status       TEXT NOT NULL DEFAULT 'pending',  -- pending | approved | rejected | expired
    approver     TEXT,                 -- the distinct second user who released/declined it
    decided_at   REAL,
    expires_at   REAL                  -- NULL = never; past this a pending request can't be approved
);
CREATE INDEX IF NOT EXISTS ix_pending_approvals_status ON pending_approvals(status, requested_at);

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
    channel_scope        TEXT,                 -- per-channel RBAC: JSON list of connections; NULL = all
    totp_secret          TEXT,                 -- MFA (WP-14): base32 TOTP secret, store-cipher encrypted; NULL = none
    totp_enabled         INTEGER NOT NULL DEFAULT 0,  -- TOTP enrolled + confirmed active
    totp_enrolled_at     REAL,
    totp_recovery_codes  TEXT,                 -- JSON list of argon2id hashes of single-use recovery codes
    last_totp_step       INTEGER               -- highest TOTP time-step already consumed (single-use within window, ASVS 6.5.1); NULL = none yet
);

CREATE TABLE IF NOT EXISTS roles (
    id           TEXT PRIMARY KEY,             -- Role value, e.g. 'administrator' (or 'custom:<name>')
    display_name TEXT NOT NULL,
    description  TEXT,
    builtin      INTEGER NOT NULL DEFAULT 1,
    permissions  TEXT                          -- custom roles (ADR 0045): JSON array of Permission wire values; NULL = built-in (resolves from code)
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
    client       TEXT,
    reauth_at    REAL,                         -- last credential re-verification (login / /me/reauth)
    mfa_verified_at REAL                       -- when the 2nd factor was satisfied; NULL = unsatisfied (WP-14)
);
CREATE INDEX IF NOT EXISTS ix_sessions_user    ON sessions(user_id);
CREATE INDEX IF NOT EXISTS ix_sessions_expires ON sessions(expires_at);
"""

# Columns added after the initial release; ALTER-ed in on open for existing DBs.
# `documents_pruned` (#47, ADR 0042): a nullable epoch timestamp set when retention strips an embedded
# document in place (NULL = never pruned / no document was ever present). Orthogonal to `status` — it
# alters no disposition/count; it is the message-level "evicted vs never present" signal a raw-view reads.
_MESSAGE_MIGRATIONS = {"summary": "TEXT", "metadata": "TEXT", "documents_pruned": "REAL"}


class MessageStore:
    """Async SQLite-backed durable queue. Open with :meth:`open`."""

    # This backend implements the staged ingress pipeline (enqueue_ingress/handoff). The engine
    # refuses to start the staged runner on a backend that doesn't (see Engine.start).
    supports_ingest_stage = True

    # This backend can capture request/response replies (ADR 0013: the `response` table +
    # complete_with_response). The runner refuses to start a capturing outbound on a backend that
    # can't, failing closed rather than silently dropping captures.
    supports_response_capture = True

    # This backend implements pass-through (PT) re-ingress — the foundational slice of the
    # `pt_deliveries` branch of transform_handoff (ConnectorType.PT, ADR 0013 generalized) lands here.
    # The engine ALLOW-LISTS PT to this backend only: a graph with a PT inbound on any backend whose
    # `supports_pt_reingress` is False is rejected at startup (see Engine.start), so a Send into a PT
    # connector never trips the unimplemented branch at runtime.
    supports_pt_reingress = True
    backend = StoreBackend.SQLITE

    def __init__(
        self,
        db: aiosqlite.Connection,
        *,
        path: str | Path = ":memory:",
        cipher: Cipher | None = None,
        group_commit_window_ms: float = 0.0,
        group_commit_max_batch: int = 64,
    ) -> None:
        self._db = db
        self.path = str(path)
        self._cipher: Cipher = cipher or IdentityCipher()
        # Serialise multi-statement transactions: aiosqlite serialises single
        # executes, but a txn spanning awaits could otherwise interleave.
        self._lock = asyncio.Lock()
        # App-side group-commit committer (ADR 0055), SQLite only. Disabled (None) by default: with
        # window == 0 each grouped method commits inline under self._lock, byte-identical to the
        # pre-feature path. When enabled, the grouped stage-handoffs enrol their statements in this
        # committer (one BEGIN…COMMIT per batch); claim*/reference-snapshot/audit stay STANDALONE.
        # Created here but only STARTED by open() (which has a running loop); a bare cls() in a test
        # without open() therefore never spins a committer task it can't await on close.
        self._group_commit: _GroupCommitter | None = (
            _GroupCommitter(
                db,
                self._lock,
                window_ms=group_commit_window_ms,
                max_batch=group_commit_max_batch,
            )
            if group_commit_window_ms > 0
            else None
        )
        # Dedicated read-only connection pool (lockfree-reads). Populated by open() for a file-backed
        # WAL store; stays None for ":memory:" (a second connection to ":memory:" is a *different*
        # empty database and WAL doesn't apply), where reads fall back to the writer under self._lock.
        # _read_conns tracks every pooled connection so close() can shut them all down regardless of
        # pool checkout state. See _read() for the routing.
        self._read_pool: asyncio.Queue[aiosqlite.Connection] | None = None
        self._read_conns: list[aiosqlite.Connection] = []
        # Transform-accessible state (ADR 0005): an in-memory read-through mirror of the `state` table,
        # {(namespace, key): decoded_value}. The table is the source of truth; this is the synchronous
        # read path state_get() resolves against (loaded at open, updated by transform_handoff ONLY
        # after the handoff transaction commits — a rolled-back op must never leak into the cache).
        self._state_cache: dict[tuple[str, str], Any] = {}
        # Reference sets (ADR 0006 Tier 1): an in-memory read-through mirror of the ACTIVE snapshot per
        # set, {name: {key: decoded_value}}. Loaded at open; write_reference_snapshot swaps a set's
        # entry wholesale ONLY after its build-new-then-flip transaction commits (a rolled-back sync
        # never leaks into reference_view, so the last-good snapshot stays live). The synchronous read
        # path reference("name").get(key) resolves against this via reference_view().
        self._reference_cache: dict[str, dict[str, Any]] = {}

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

    def cipher_info(self) -> CipherInfo:
        """The non-secret at-rest cipher posture (M5): on/off + key fingerprint, never key bytes."""
        return cipher_info(self._cipher)

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
        cls,
        path: str | Path,
        *,
        synchronous: str = "NORMAL",
        cipher: Cipher | None = None,
        group_commit_window_ms: float = 0.0,
        group_commit_max_batch: int = 64,
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
        store = cls(
            db,
            path=path,
            cipher=cipher,
            group_commit_window_ms=group_commit_window_ms,
            group_commit_max_batch=group_commit_max_batch,
        )
        await store._encrypt_existing_rows()  # one-time PHI-at-rest migration when a key is set
        await store._backfill_audit_chain()  # chain any pre-existing (unhashed) audit rows
        await (
            store._load_state_cache()
        )  # populate the in-memory state read-through cache (ADR 0005)
        await store._load_reference_cache()  # populate the reference-snapshot read cache (ADR 0006)
        await store._open_read_pool(str(path))  # dedicated read-only WAL pool (lockfree-reads)
        if store._group_commit is not None:
            store._group_commit.start()  # spin the committer coroutine (needs the running loop)
        return store

    async def _open_read_pool(self, path: str) -> None:
        """Open the bounded read-only connection pool for a file-backed WAL store (lockfree-reads).

        A no-op for ``:memory:`` — a separate connection to ``:memory:`` is a *different* empty
        database and WAL snapshots don't apply, so reads there stay on the writer connection under
        ``self._lock`` (see :meth:`_read`). Each pooled connection is ``query_only`` (writes raise) and
        carries a ``busy_timeout`` so a reader waits out a transient lock (e.g. a WAL checkpoint) rather
        than erroring. Opened after schema/migrate commit so the file and its WAL sidecars already
        exist."""
        if path == ":memory:":
            return
        pool: asyncio.Queue[aiosqlite.Connection] = asyncio.Queue(maxsize=_READ_POOL_SIZE)
        for _ in range(_READ_POOL_SIZE):
            conn = await aiosqlite.connect(path)
            conn.row_factory = aiosqlite.Row
            await conn.execute("PRAGMA query_only=ON")  # defence in depth: a read conn never writes
            await conn.execute("PRAGMA busy_timeout=5000")
            self._read_conns.append(conn)
            pool.put_nowait(conn)
        self._read_pool = pool

    @asynccontextmanager
    async def _read(self) -> AsyncIterator[aiosqlite.Connection]:
        """Yield a connection to run a read on without taking the write lock (lockfree-reads).

        Pooled path (file-backed WAL): borrow a read-only connection and wrap the block in one deferred
        read transaction, so every statement in the block sees a single consistent WAL snapshot taken at
        ``BEGIN`` and concurrent writes can't interleave. The transaction is always closed
        (``COMMIT``/``ROLLBACK``) before the connection returns to the pool, so the next borrower starts
        a *fresh* snapshot (a read always reflects the latest committed write) and never pins the WAL.

        Fallback path (``:memory:``, no pool): reads share the single writer connection, serialized under
        ``self._lock`` — the pre-pool behaviour, required because ``:memory:`` can't be reached by a
        second connection. Callers must therefore never invoke a ``_read()`` method while already
        holding ``self._lock`` (none do)."""
        pool = self._read_pool
        if pool is None:
            async with self._lock:
                yield self._db
            return
        conn = await pool.get()
        try:
            await conn.execute("BEGIN")
            try:
                yield conn
                await conn.execute("COMMIT")
            except BaseException:
                await conn.execute("ROLLBACK")
                raise
        finally:
            pool.put_nowait(conn)

    async def _run_grouped(
        self,
        body: "Callable[[], Awaitable[Any]]",
        *,
        on_commit: "Callable[[Any], None] | None" = None,
    ) -> Any:
        """Run one grouped stage-handoff ``body`` (statements only — NO BEGIN/commit/rollback).

        Group-commit DISABLED (the default, ``window == 0``): run ``body`` inline under ``self._lock``
        inside its own ``BEGIN`` … ``commit`` with an except-rollback — byte-identical to the
        pre-feature path. An :class:`_AbortMember` (the idempotent no-op early-exit) rolls back and
        returns its carried result, exactly mirroring the old explicit ``rollback(); return <sentinel>``.

        Group-commit ENABLED: enrol ``body`` in the committer, which runs it between the batch's single
        ``BEGIN`` … ``COMMIT`` and resolves this caller's future post-commit (so an inbound ACK waiting on
        the returned value never releases before the data is durable — Hazard B). A group rollback
        rejects the future and the caller re-runs (licensed by the INFLIGHT-guarded idempotent handoffs).

        ``on_commit`` is an optional read-through cache publish run AFTER a successful commit and only
        then (a rolled-back/aborted body never runs it, so an uncommitted delta never leaks — AC-4). In
        the disabled path it runs in this frame after the lock is released (byte-identical to the old
        post-``_run_grouped`` publish in the caller); enabled, the committer runs it the instant the
        batch commits — so neither path can skip a committed write's publish if the caller is later
        cancelled (the disabled path never awaits between commit and publish; the enabled publish is
        detached into the committer)."""
        gc = self._group_commit
        if gc is None:
            async with self._lock:
                try:
                    await self._db.execute("BEGIN")
                    result = await body()
                    await self._db.commit()
                except _AbortMember as abort:
                    await self._db.rollback()
                    return abort.result  # zero-mutation no-op: nothing committed → no publish
                except Exception:
                    await self._db.rollback()
                    raise
            # Commit landed and the lock is released — publish the committed delta in this same frame,
            # with no await between commit and publish, so a cancel can't interpose and strand the cache.
            if on_commit is not None:
                on_commit(result)
            return result
        return await gc.submit(body, on_commit=on_commit)

    async def _load_state_cache(self) -> None:
        """Populate the in-memory transform-state cache from the ``state`` table (ADR 0005).

        Runs at open (and after the on-open encrypt migration, so values are decryptable under the
        current keyring). Each ``value`` is decrypted then JSON-decoded into its native Python value —
        the form :func:`messagefoundry.config.state.state_get` returns. Bounded by the table size (the
        ADR's documented v1 assumption; TTL/retention keeps it bounded)."""
        cur = await self._db.execute("SELECT namespace, key, value FROM state")
        cache: dict[tuple[str, Any], Any] = {}
        for r in await cur.fetchall():
            cache[(r["namespace"], r["key"])] = json.loads(self._cipher.decrypt(r["value"]))
        self._state_cache = cache

    async def _load_reference_cache(self) -> None:
        """Populate the in-memory reference cache from the ACTIVE snapshot of each set (ADR 0006).

        Runs at open (after the encrypt migration). ``reference_version`` holds one row per set naming
        its active ``version``; this joins to ``reference`` and loads only that version's rows,
        decrypting + JSON-decoding each value into the native form ``reference(name).get(key)``
        returns. Bounded by the active snapshots' size (the ADR's v1 in-memory assumption)."""
        # Drive from reference_version (the authoritative active-version list) with a LEFT JOIN, so a
        # set that synced to ZERO rows still loads as an empty {} (present, not absent) after a reopen.
        cur = await self._db.execute(
            "SELECT v.name AS name, r.key AS key, r.value AS value FROM reference_version v "
            "LEFT JOIN reference r ON r.name = v.name AND r.version = v.version"
        )
        cache: dict[str, dict[str, Any]] = {}
        for r in await cur.fetchall():
            entry = cache.setdefault(r["name"], {})
            if r["key"] is not None:  # NULL key = the LEFT-JOIN miss of an empty snapshot
                entry[r["key"]] = json.loads(self._cipher.decrypt(r["value"]))
        self._reference_cache = cache

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
    #: columns (error/last_error/detail) added in WP-5, and summary/metadata (MRN + patient name +
    #: operator-attached values) added in EF-3. Used by the on-open migration and rotate-key.
    _CIPHER_COLUMNS = (
        ("messages", "raw"),
        ("queue", "payload"),
        ("messages", "error"),
        ("queue", "last_error"),
        ("message_events", "detail"),
        ("messages", "summary"),  # EF-3: ingest-derived MRN/name — PHI, not just metadata
        ("messages", "metadata"),  # EF-3: code/operator-attached values
        (
            "users",
            "totp_secret",
        ),  # MFA secret (WP-14) — id-keyed, so it rides the migration + rotation
        (
            "connection_event",
            "reason",
        ),  # #46: scrubbed event reason — id-keyed, rides the loops below
        (
            "alert_instance",
            "reason",
        ),  # #56 (ADR 0044): scrubbed alert reason — id-keyed, rides the loops below
        # NB: the `response` table (ADR 0013) is cipher-covered too, but it has a COMPOSITE PK (no
        # `id`), so it can't ride the id-keyed loops below — it has its own passes, like state/reference.
        # The `shared_body` table (store-once-deliver-many) is likewise cipher-covered (`body`) but keyed
        # by `hash`, not `id`, so it has its own pass in _encrypt_existing_rows / reencrypt_to_active.
    )

    async def _encrypt_existing_rows(self) -> None:
        """Encrypt any legacy plaintext values in the cipher-covered columns in place when encryption
        is enabled (STORE-1 / WP-5).

        Idempotent and batched: skips rows already carrying the ciphertext prefix (and NULL / blank
        ``''`` values — the latter is a purged/empty marker we must not turn into ciphertext), so reads
        work throughout and re-running is a no-op. Bounded memory (processes in chunks)."""
        if not self._cipher.encrypts:
            return
        # Version-agnostic anchor (M9): `mfenc:%` matches BOTH v1 and v2 ciphertext, so a v2 row is
        # recognised as already-encrypted and skipped — never re-wrapped. Anchoring on a version-
        # specific prefix would miss the other version's rows.
        like = f"{_ENC_MARKER_PREFIX}%"
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
            # The `state` table (composite PK, ADR 0005) can't use the id-keyed loop — migrate it
            # separately so a key enabled on an existing DB encrypts any legacy plaintext state values.
            while True:
                cur = await self._db.execute(
                    "SELECT namespace, key, value FROM state"
                    " WHERE value NOT LIKE ? AND value <> '' LIMIT 500",
                    (like,),
                )
                rows = list(await cur.fetchall())
                if not rows:
                    break
                await self._db.executemany(
                    "UPDATE state SET value=? WHERE namespace=? AND key=?",
                    [(self._cipher.encrypt(r["value"]), r["namespace"], r["key"]) for r in rows],
                )
                await self._db.commit()
                total += len(rows)
            # The `reference` table (composite PK name,version,key — ADR 0006) likewise can't use the
            # id-keyed loop; migrate any legacy plaintext snapshot values separately.
            while True:
                cur = await self._db.execute(
                    "SELECT name, version, key, value FROM reference"
                    " WHERE value NOT LIKE ? AND value <> '' LIMIT 500",
                    (like,),
                )
                rows = list(await cur.fetchall())
                if not rows:
                    break
                await self._db.executemany(
                    "UPDATE reference SET value=? WHERE name=? AND version=? AND key=?",
                    [
                        (self._cipher.encrypt(r["value"]), r["name"], r["version"], r["key"])
                        for r in rows
                    ],
                )
                await self._db.commit()
                total += len(rows)
            # The `response` table (composite PK message_id,destination_name,response_seq — ADR 0013) has
            # TWO encrypted columns (body, detail) and no `id`; migrate each on its own pass. (A brand-new
            # table, so normally a no-op — present for parity with state/reference.)
            for column in ("body", "detail"):
                while True:
                    cur = await self._db.execute(
                        f"SELECT message_id, destination_name, response_seq, {column} FROM response"
                        f" WHERE {column} NOT LIKE ? AND {column} <> '' LIMIT 500",
                        (like,),
                    )
                    rows = list(await cur.fetchall())
                    if not rows:
                        break
                    await self._db.executemany(
                        f"UPDATE response SET {column}=?"
                        " WHERE message_id=? AND destination_name=? AND response_seq=?",
                        [
                            (
                                self._cipher.encrypt(r[column]),
                                r["message_id"],
                                r["destination_name"],
                                r["response_seq"],
                            )
                            for r in rows
                        ],
                    )
                    await self._db.commit()
                    total += len(rows)
            # The `shared_body` table (store-once-deliver-many) is keyed by `hash` (the plaintext content
            # address), not `id`; migrate any legacy plaintext body separately. (Normally a no-op — a
            # brand-new table — present for parity with state/reference/response.)
            while True:
                cur = await self._db.execute(
                    "SELECT hash, body FROM shared_body WHERE body NOT LIKE ? AND body <> '' LIMIT 500",
                    (like,),
                )
                rows = list(await cur.fetchall())
                if not rows:
                    break
                await self._db.executemany(
                    "UPDATE shared_body SET body=? WHERE hash=?",
                    [(self._cipher.encrypt(r["body"]), r["hash"]) for r in rows],
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
        # The active-format prefix THROUGH the active key's fingerprint (M9): `mfenc:v1:<kid>:` or, for a
        # v2-active cipher, `mfenc:v2:<alg>:<kid>:`. Rotation rewrites everything NOT already under this
        # prefix, so a value re-encrypted to the active key/format matches next round and the loop ends.
        # Built off the cipher (not a baked-in v1 prefix+keyid) so a v2-active rotation matches v2 rows.
        active_like = f"{cipher.active_marker_prefix}%"
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
            # The `state` table has a composite PK (namespace,key), not an `id`, so it can't ride the
            # generic id-keyed loop above — rotate it with its own pass (ADR 0005).
            total += await self._reencrypt_state_to_active(cipher, active_like, batch)
            # The `reference` table (composite PK name,version,key — ADR 0006) likewise rotates on its
            # own pass.
            total += await self._reencrypt_reference_to_active(cipher, active_like, batch)
            # The `response` table (composite PK + two PHI columns — ADR 0013) rotates on its own pass.
            total += await self._reencrypt_response_to_active(cipher, active_like, batch)
            # The `shared_body` table (store-once-deliver-many) is keyed by `hash`, not `id` — its own pass.
            total += await self._reencrypt_shared_body_to_active(cipher, active_like, batch)
        if total:
            log.info("re-encrypted %d value(s) under the active key (rotation)", total)
        return total

    async def _reencrypt_shared_body_to_active(
        self, cipher: AesGcmCipher, active_like: str, batch: int
    ) -> int:
        """Re-encrypt the ``shared_body`` table's ``body`` under the active key (caller holds the lock).

        Mirrors :meth:`_reencrypt_state_to_active` but keys on the content-address PK ``hash`` (store-
        once-deliver-many). The ``hash`` is over the PLAINTEXT, so re-encrypting under a new key never
        changes it — the content address is rotation-stable."""
        rotated = 0
        while True:
            cur = await self._db.execute(
                "SELECT hash, body FROM shared_body WHERE body NOT LIKE ? AND body <> '' LIMIT ?",
                (active_like, batch),
            )
            rows = list(await cur.fetchall())
            if not rows:
                break
            updates = [(cipher.encrypt(cipher.decrypt(r["body"])), r["hash"]) for r in rows]
            await self._db.executemany("UPDATE shared_body SET body=? WHERE hash=?", updates)
            await self._db.commit()
            rotated += len(rows)
        return rotated

    async def _reencrypt_state_to_active(
        self, cipher: AesGcmCipher, active_like: str, batch: int
    ) -> int:
        """Re-encrypt the ``state`` table's values under the active key (caller holds ``self._lock``).

        Mirrors the id-keyed loop in :meth:`reencrypt_to_active` but keys on the composite PK. Decrypt
        (via the keyring) → encrypt (active); a value no configured key can decrypt raises before any
        UPDATE (PHI is never dropped). Skips values already under the active key (idempotent)."""
        rotated = 0
        while True:
            cur = await self._db.execute(
                "SELECT namespace, key, value FROM state"
                " WHERE value NOT LIKE ? AND value <> '' LIMIT ?",
                (active_like, batch),
            )
            rows = list(await cur.fetchall())
            if not rows:
                break
            updates = [
                (cipher.encrypt(cipher.decrypt(r["value"])), r["namespace"], r["key"]) for r in rows
            ]
            await self._db.executemany(
                "UPDATE state SET value=? WHERE namespace=? AND key=?", updates
            )
            await self._db.commit()
            rotated += len(rows)
        return rotated

    async def _reencrypt_reference_to_active(
        self, cipher: AesGcmCipher, active_like: str, batch: int
    ) -> int:
        """Re-encrypt the ``reference`` table's values under the active key (caller holds ``self._lock``).

        Mirrors :meth:`_reencrypt_state_to_active` but keys on the composite PK (name,version,key)."""
        rotated = 0
        while True:
            cur = await self._db.execute(
                "SELECT name, version, key, value FROM reference"
                " WHERE value NOT LIKE ? AND value <> '' LIMIT ?",
                (active_like, batch),
            )
            rows = list(await cur.fetchall())
            if not rows:
                break
            updates = [
                (cipher.encrypt(cipher.decrypt(r["value"])), r["name"], r["version"], r["key"])
                for r in rows
            ]
            await self._db.executemany(
                "UPDATE reference SET value=? WHERE name=? AND version=? AND key=?", updates
            )
            await self._db.commit()
            rotated += len(rows)
        return rotated

    async def _reencrypt_response_to_active(
        self, cipher: AesGcmCipher, active_like: str, batch: int
    ) -> int:
        """Re-encrypt the ``response`` table's body+detail under the active key (caller holds the lock).

        Mirrors :meth:`_reencrypt_state_to_active` but keys on the composite PK
        (message_id,destination_name,response_seq) and covers BOTH PHI columns (ADR 0013)."""
        rotated = 0
        for column in ("body", "detail"):
            while True:
                cur = await self._db.execute(
                    f"SELECT message_id, destination_name, response_seq, {column} FROM response"
                    f" WHERE {column} NOT LIKE ? AND {column} <> '' LIMIT ?",
                    (active_like, batch),
                )
                rows = list(await cur.fetchall())
                if not rows:
                    break
                updates = [
                    (
                        cipher.encrypt(cipher.decrypt(r[column])),
                        r["message_id"],
                        r["destination_name"],
                        r["response_seq"],
                    )
                    for r in rows
                ]
                await self._db.executemany(
                    f"UPDATE response SET {column}=?"
                    " WHERE message_id=? AND destination_name=? AND response_seq=?",
                    updates,
                )
                await self._db.commit()
                rotated += len(rows)
        return rotated

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
        user_cols = {row["name"] for row in await cur.fetchall()}
        if "channel_scope" not in user_cols:
            await db.execute("ALTER TABLE users ADD COLUMN channel_scope TEXT")
        # --- custom RBAC roles (ADR 0045) ------------------------------------
        # roles.permissions: a custom role's JSON permission-subset. A pre-existing DB's roles predate
        # the column — ALTER it in (NULL on every existing built-in row is byte-identical to today:
        # built-ins resolve from BUILTIN_ROLE_PERMISSIONS, never this column). Idempotent.
        cur = await db.execute("PRAGMA table_info(roles)")
        if "permissions" not in {row["name"] for row in await cur.fetchall()}:
            await db.execute("ALTER TABLE roles ADD COLUMN permissions TEXT")
        # --- end custom RBAC roles (ADR 0045) --------------------------------
        # MFA (WP-14): a pre-existing DB's users predate the TOTP columns — ALTER them in (NULL/0 on
        # existing rows = "not enrolled", correct). Idempotent: skipped once present.
        for column, decl in (
            ("totp_secret", "TEXT"),
            ("totp_enabled", "INTEGER NOT NULL DEFAULT 0"),
            ("totp_enrolled_at", "REAL"),
            ("totp_recovery_codes", "TEXT"),
            ("last_totp_step", "INTEGER"),
        ):
            if column not in user_cols:
                await db.execute(f"ALTER TABLE users ADD COLUMN {column} {decl}")
        # Step B adds the routed stage, which carries the handler to run in queue.handler_name. A
        # Step-A DB's queue table predates the column — ALTER it in (NULL on existing ingress/outbound
        # rows is correct). The queue table always exists here (CREATE IF NOT EXISTS ran in _SCHEMA).
        cur = await db.execute("PRAGMA table_info(queue)")
        queue_cols = {row["name"] for row in await cur.fetchall()}
        if "handler_name" not in queue_cols:
            await db.execute("ALTER TABLE queue ADD COLUMN handler_name TEXT")
        # store-once-deliver-many (L2b): a pre-existing queue predates body_ref — ALTER it in (NULL on
        # existing rows = "body inline in payload", byte-identical to before). shared_body is created by
        # the CREATE TABLE IF NOT EXISTS in _SCHEMA, so a reopened DB gains it without a separate step.
        if "body_ref" not in queue_cols:
            await db.execute("ALTER TABLE queue ADD COLUMN body_ref TEXT")
        # The body_ref deref index lives here (not _SCHEMA) so it is created only AFTER the column is
        # guaranteed present — on a Step-A queue it'd otherwise reference a not-yet-added column.
        await db.execute("CREATE INDEX IF NOT EXISTS ix_queue_body_ref ON queue(body_ref)")
        # Step-up re-verification (ASVS 7.5.3) adds sessions.reauth_at. A pre-existing DB's rows get
        # NULL (treated as "never re-verified" — a sensitive op then requires /me/reauth).
        cur = await db.execute("PRAGMA table_info(sessions)")
        session_cols = {row["name"] for row in await cur.fetchall()}
        if "reauth_at" not in session_cols:
            await db.execute("ALTER TABLE sessions ADD COLUMN reauth_at REAL")
        # MFA (WP-14): the 2nd-factor timestamp; pre-existing rows get NULL (= unsatisfied, so an
        # MFA-required user must re-verify). A NULL on a non-MFA deployment is simply never consulted.
        if "mfa_verified_at" not in session_cols:
            await db.execute("ALTER TABLE sessions ADD COLUMN mfa_verified_at REAL")
        # ADR 0021 "Response Sent" rides the response table via a `kind` discriminator. A pre-existing
        # DB's response table predates the three columns — ALTER them in (existing rows backfill
        # kind='response' via the DEFAULT). Metadata-only on SQLite (no table rewrite). Idempotent.
        cur = await db.execute("PRAGMA table_info(response)")
        response_cols = {row["name"] for row in await cur.fetchall()}
        if "kind" not in response_cols:
            await db.execute(
                "ALTER TABLE response ADD COLUMN kind TEXT NOT NULL DEFAULT 'response'"
            )
        if "ack_code" not in response_cols:
            await db.execute("ALTER TABLE response ADD COLUMN ack_code TEXT")
        if "ack_phase" not in response_cols:
            await db.execute("ALTER TABLE response ADD COLUMN ack_phase TEXT")
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
        # Stop the group-commit committer FIRST (if enabled) so it flushes any enrolled members and
        # resolves their futures before the write connection is closed — otherwise an in-flight handoff
        # would hang forever on a future no committer will ever complete.
        if self._group_commit is not None:
            try:
                await self._group_commit.aclose()
            except Exception:  # noqa: BLE001 — shutdown best-effort; log and continue
                log.warning("error closing group-commit committer", exc_info=True)
        # Close every pooled read connection (tracked in _read_conns regardless of pool checkout
        # state), then the writer. Best-effort: one failing close must not strand the rest.
        for conn in self._read_conns:
            try:
                await conn.close()
            except Exception:  # noqa: BLE001 — shutdown best-effort; log and continue
                log.warning("error closing read-pool connection", exc_info=True)
        self._read_conns = []
        self._read_pool = None
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
                await self._insert_outbound_deliveries(mid, channel_id, deliveries, now)
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

    async def _insert_outbound_deliveries(
        self,
        mid: str,
        channel_id: str,
        deliveries: Sequence[tuple[str, str]],
        now: float,
    ) -> None:
        """Insert one ``stage='outbound'`` queue row per delivery, **storing-once any identical body**.

        Store-once-deliver-many (L2b): when ≥2 of *this* handler's deliveries carry a byte-identical
        transformed body (the high-fan-out case), the body is encrypted and stored a **single** time in
        ``shared_body`` (keyed by ``sha256(plaintext)``, ``refcount`` = how many of these rows reference
        it) and each of those outbound rows carries a ``body_ref`` with an empty inline ``payload`` —
        cutting stored body bytes from N× to ~1×. A body that appears exactly once stays **inline** in
        ``payload`` (NULL ``body_ref``), byte-identical to the pre-feature behavior — no shared_body row,
        no deref at delivery. Dedup is scoped to this single call's deliveries (one transaction), the
        conservative well-bounded unit. All inserts run inside the caller's transaction."""
        # Group destinations by plaintext body so we know each body's fan-out before inserting.
        by_body: dict[str, list[str]] = {}
        order: list[str] = []  # preserve first-seen body order for stable hashing/insert
        for dest_name, payload in deliveries:
            if payload not in by_body:
                by_body[payload] = []
                order.append(payload)
            by_body[payload].append(dest_name)
        # Pre-create each shared body that fans out to ≥2 destinations (refcount = that fan-out).
        body_ref_for: dict[str, str] = {}
        for payload in order:
            dests = by_body[payload]
            if len(dests) < 2:
                continue  # singleton → stays inline, byte-identical to before
            body_hash = hashlib.sha256(payload.encode("utf-8")).hexdigest()
            await self._reserve_shared_body(body_hash, payload, len(dests), now)
            body_ref_for[payload] = body_hash
        # Insert the rows in the original delivery order (FIFO stamping per destination lane).
        for dest_name, payload in deliveries:
            await self._insert_outbound_row(
                mid, channel_id, dest_name, payload, now, body_ref=body_ref_for.get(payload)
            )

    async def _reserve_shared_body(
        self, body_hash: str, payload: str, refs: int, now: float
    ) -> None:
        """Create (or bump the refcount of) the single shared copy of ``payload`` (store-once).

        Inserts a ``shared_body`` row holding ONE encrypted copy with ``refcount=refs``; if the content
        address already exists (an earlier handoff produced the same body, or a retried delivery), the
        refcount is incremented by ``refs`` instead so the existing copy is reused. Runs in the caller's
        transaction, so it commits or rolls back atomically with the referencing outbound rows."""
        await self._db.execute(
            "INSERT INTO shared_body (hash, body, refcount, created_at) VALUES (?,?,?,?) "
            "ON CONFLICT(hash) DO UPDATE SET refcount = refcount + excluded.refcount",
            (body_hash, self._cipher.encrypt(payload), refs, now),
        )

    async def _release_shared_body(self, body_hash: str, count: int = 1) -> None:
        """Drop ``count`` references to a shared body and GC it at refcount 0 (store-once retention).

        Called when a referencing outbound row's body is purged or the row is deleted. Decrements the
        refcount; when it reaches 0 the single encrypted copy is DELETEd, so a body is never orphaned and
        never kept past its last referrer. Clamped at 0 (a double-release can't drive it negative)."""
        await self._db.execute(
            "UPDATE shared_body SET refcount = MAX(0, refcount - ?) WHERE hash=?",
            (count, body_hash),
        )
        await self._db.execute("DELETE FROM shared_body WHERE hash=? AND refcount<=0", (body_hash,))

    async def _release_outbound_body_refs(self, where: str, params: tuple[object, ...]) -> None:
        """Release every shared body referenced by the outbound rows matching ``where`` (store-once GC).

        The retention seam: tally the ``body_ref`` of each matching row, decrement each shared body's
        refcount by how many of these rows reference it (GC at 0), then NULL ``body_ref`` on those rows so
        the release is exactly-once even if the purge re-runs (a re-run no longer matches). Runs in the
        caller's transaction. ``where`` is a code-controlled fragment (never user input) selecting
        ``stage='outbound'`` rows with a non-NULL ``body_ref``."""
        cur = await self._db.execute(
            f"SELECT body_ref, COUNT(*) AS n FROM queue WHERE {where} GROUP BY body_ref", params
        )
        releases = [(r["body_ref"], int(r["n"])) for r in await cur.fetchall()]
        if not releases:
            return
        for body_hash, count in releases:
            await self._release_shared_body(body_hash, count)
        # Null body_ref on the just-released rows so a re-run of the purge is a no-op (idempotent GC).
        await self._db.execute(f"UPDATE queue SET body_ref=NULL WHERE {where}", params)

    async def _insert_outbound_row(
        self,
        mid: str,
        channel_id: str,
        dest_name: str,
        payload: str,
        now: float,
        *,
        body_ref: str | None = None,
    ) -> None:
        """Insert one ``stage='outbound'`` queue row (one message→destination delivery).

        ``body_ref`` is the store-once seam: ``None`` (default) inlines the encrypted body in ``payload``
        (byte-identical to the pre-feature path); a non-``None`` content-address hash references the single
        copy in ``shared_body`` and stores an empty inline ``payload`` (dereferenced at delivery). The
        caller (:meth:`_insert_outbound_deliveries`) reserves the shared_body row before passing a ref."""
        created_at = await self._fifo_created_at(
            Stage.OUTBOUND.value, "destination_name", dest_name, now
        )
        # When the body is shared, the inline payload is empty ('' — never ciphertext-of-empty, so it
        # reads back as a blank that the deref replaces). NOT NULL is satisfied by the '' sentinel.
        stored_payload = "" if body_ref is not None else self._cipher.encrypt(payload)
        await self._db.execute(
            "INSERT INTO queue"
            " (id, message_id, stage, channel_id, destination_name, payload, body_ref,"
            "  status, attempts, next_attempt_at, created_at, updated_at)"
            " VALUES (?,?,?,?,?,?,?,?,0,?,?,?)",
            (
                uuid4().hex,
                mid,
                Stage.OUTBOUND.value,
                channel_id,
                dest_name,
                stored_payload,
                body_ref,
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

        async def _body() -> str:
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
            return mid

        # HAZARD B: the inbound ACK / HTTP-202 is built only after this returns, so under group-commit
        # _run_grouped must not return until the ingress member's batch is durably committed (the
        # committer resolves the future post-commit). We never ACK data a crash could still lose.
        result = await self._run_grouped(_body)
        assert isinstance(result, str)  # nosec B101 — _body returns mid (str)
        return result

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
                await self._insert_outbound_deliveries(message_id, channel_id, deliveries, now)
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

        async def _body() -> bool:
            cur = await self._db.execute(
                "DELETE FROM queue WHERE id=? AND stage=? AND status=?",
                (ingress_id, Stage.INGRESS.value, OutboxStatus.INFLIGHT.value),
            )
            if not cur.rowcount:
                # Already handed off by a prior run (crash-restart) — idempotent no-op. The guarded
                # DELETE matched nothing (zero net mutation), so under group-commit this member stays
                # in the batch harmlessly; _AbortMember just short-circuits the rest of the body.
                raise _AbortMember(False)
            # Insert in handler-list order: routed rows share this handoff's created_at, so the
            # transform worker's FIFO (created_at, rowid) falls back to rowid = insertion order,
            # preserving the router's handler order to a shared outbound (see the worker docs).
            for handler_name, payload in handlers:
                await self._insert_routed_row(message_id, channel_id, handler_name, payload, now)
            await self._db.execute(
                "UPDATE messages SET status=? WHERE id=?", (disposition.value, message_id)
            )
            event = "routed" if disposition is MessageStatus.ROUTED else "unrouted"
            await self._event(message_id, event, None, f"{len(handlers)} handler(s)", now)
            return True

        return bool(await self._run_grouped(_body))

    def state_view(self) -> Mapping[tuple[str, str], Any]:
        """A read-only view of the transform-state read-through cache (ADR 0005).

        ``{(namespace, key): decoded_value}`` — the synchronous read surface the runner publishes (via
        :func:`messagefoundry.config.state.activated`) around each router/transform run so a Handler's
        ``state_get(...)`` resolves. Returned as a ``MappingProxyType`` (a live, read-only window onto
        the cache): it reflects writes as they commit and can't be mutated through this handle."""
        return MappingProxyType(self._state_cache)

    def reference_view(self) -> Mapping[str, Mapping[str, Any]]:
        """A read-only view of the active reference snapshots (ADR 0006).

        ``{name: {key: decoded_value}}`` — the synchronous read surface the runner publishes (via
        :func:`messagefoundry.config.reference.activated`) around each router/transform run so a
        Handler's ``reference("name").get(key)`` resolves. Returned as a ``MappingProxyType`` (a live,
        read-only window onto the cache): it swaps in a new snapshot only after a sync commits and can't
        be mutated through this handle."""
        return MappingProxyType(self._reference_cache)

    async def write_reference_snapshot(
        self, *, name: str, version: str, rows: Mapping[str, Any]
    ) -> None:
        """Materialize a new reference snapshot and atomically make it the active one (ADR 0006 Tier 1).

        In ONE transaction: drop the set's prior rows, insert every ``(name, version, key, value)`` of
        the new snapshot (each ``value`` JSON-encoded then cipher-encrypted — it may carry PHI), and
        upsert the ``reference_version`` pointer to ``version``. Readers keep seeing the prior snapshot
        (served from the in-memory cache) until this commits; a **failed** sync rolls back wholesale, so
        the last-good snapshot stays active (graceful degradation). The cache is swapped **only after**
        commit — a rolled-back write never leaks into :meth:`reference_view`. Replaces the whole set
        (build-new-then-flip), so it is idempotent on a re-run with the same rows."""
        encrypted = [
            (name, version, k, self._cipher.encrypt(json.dumps(v))) for k, v in rows.items()
        ]
        async with self._lock:
            try:
                await self._db.execute("BEGIN")
                # Drop the set's prior version(s) — we keep only the active snapshot per name.
                await self._db.execute("DELETE FROM reference WHERE name=?", (name,))
                if encrypted:
                    await self._db.executemany(
                        "INSERT INTO reference (name, version, key, value) VALUES (?,?,?,?)",
                        encrypted,
                    )
                await self._db.execute(
                    "INSERT OR REPLACE INTO reference_version (name, version, synced_at, row_count)"
                    " VALUES (?,?,?,?)",
                    (name, version, time.time(), len(encrypted)),
                )
                await self._db.commit()
            except Exception:
                await self._db.rollback()
                raise
        # Commit succeeded → swap the active snapshot in the read cache (plaintext, decoded form).
        self._reference_cache[name] = dict(rows)

    async def converge_reference_cache(self) -> list[str]:
        """No-op on SQLite (Track B Step 6). SQLite is single-node: this handle is the SOLE writer of
        its reference snapshots, so :meth:`write_reference_snapshot` already keeps the in-process cache
        current. There is no other node whose newer snapshot we'd need to read through, so there is
        never anything to converge. Returns ``[]`` so the runner's always-converge pass is a free
        no-op, keeping single-node behaviour byte-identical."""
        return []

    async def converge_state_cache(self) -> list[str]:
        """No-op on SQLite (Track B Step 6b). SQLite is single-node: this handle is the SOLE writer of
        its transform state, so :meth:`transform_handoff` already keeps the in-process cache current.
        There is no other node whose newer write we'd need to read through, so there is never anything to
        converge. Returns ``[]`` so the runner's always-converge pass is a free no-op, keeping single-node
        behaviour byte-identical (same reasoning as :meth:`converge_reference_cache`)."""
        return []

    def enable_state_convergence(self) -> None:
        """No-op on SQLite (Track B Step 6b): there is no cross-node convergence on this backend, so there
        is no per-namespace version to bump. Present for ``Store`` protocol completeness."""
        return None

    async def _apply_state_op(
        self,
        namespace: str,
        key: str,
        value_json: str,
        message_id: str,
        now: float,
    ) -> None:
        """Upsert one state entry within the current transaction (caller holds the lock + an open txn).

        ``value_json`` is the already-JSON-encoded value; it is cipher-encrypted here so PHI never hits
        disk in the clear (mirrors ``messages.raw``). ``INSERT OR REPLACE`` makes the write idempotent
        by ``(namespace, key)`` — a re-run after a crash overwrites with the same value, never double-
        applies. The in-memory cache is **not** touched here (only after the txn commits — see
        :meth:`transform_handoff`), so a rolled-back op can't leak into the synchronous read path."""
        await self._db.execute(
            "INSERT OR REPLACE INTO state (namespace, key, value, set_at, message_id)"
            " VALUES (?,?,?,?,?)",
            (namespace, key, self._cipher.encrypt(value_json), now, message_id),
        )

    async def transform_handoff(
        self,
        *,
        routed_id: str,
        message_id: str,
        channel_id: str,
        deliveries: Sequence[tuple[str, str]],  # (destination_name, transformed_payload)
        state_ops: Sequence[tuple[str, str, Any]] = (),  # (namespace, key, value) — ADR 0005
        pt_deliveries: Sequence[tuple[str, str]] = (),  # (pt_inbound_name, body) — ADR 0013 gen.
        correlation_depth_cap: int = 8,  # bounds internal PT re-ingress loops
        now: float | None = None,
    ) -> bool:
        """Advance one handler assignment from the **routed** stage to outbound — the transform half of
        the split pipeline (ADR 0001 Step B): claim→produce-next→complete in one transaction.

        Consume the in-flight routed row (DELETE — its raw body is canonical in ``messages.raw``),
        insert one ``stage='outbound'`` row per delivery this handler produced, **apply each declared
        state write** (ADR 0005), log the ``transformed`` event, then call
        :meth:`_maybe_finalize_message`. It does **not** write ``messages.status`` itself: the finalizer
        is the single disposition authority (it alone has the whole multi-stage row picture — a sibling
        handler's routed/outbound rows may still be in flight, so per-handoff disposition math would be
        order-dependent and wrong). INFLIGHT-guarded and single-transaction like :meth:`handoff`: a
        crash before commit rolls back (the routed row recovers and the transform re-runs, re-deriving
        identical outbound rows **and** state writes — transforms are pure), and a committed run is an
        idempotent no-op on re-invocation (routed row gone → ``False``). Returns ``True`` if this call
        performed the handoff, ``False`` if it was a no-op.

        **Pass-through re-ingress (ADR 0013, generalized).** ``pt_deliveries`` are the handler's ``Send``\\ s
        whose target is an internal **pass-through (PT) inbound** (not an outbound). For each, this
        produces — **in this same transaction** — a new, independent INGRESS-stage child message on the
        PT channel (a content-addressed id; ``RECEIVED`` per count-and-log; correlated to this message),
        which the PT inbound's own router worker then re-routes. The Send-into-PT also stamps a single
        **already-``done`` outbound marker row** on *this* (parent) message keyed by the PT inbound name,
        so the parent finalizes ``PROCESSED`` (the Send was delivered — into the PT) and never collapses
        to ``FILTERED``. Atomicity makes "child produced" and "routed row consumed" one durable fact, so a
        crash/re-run is an idempotent no-op (the content-addressed child id + the guarded routed-row
        DELETE). A ``correlation_depth`` breach drops the child and dead-letters the parent's marker
        (``ERROR``), bounding internal loops. When ``pt_deliveries`` is empty this is byte-identical to
        the pre-feature path.

        **State exactly-once (ADR 0005):** each ``state_ops`` entry is upserted by ``(namespace, key)``
        **inside this same transaction** as the outbound rows, so it commits or rolls back atomically
        with them — a crash before commit leaves NO state row, and the committing attempt's value is the
        one that persists (exactly-once *per message*). The in-memory read cache is updated **only after
        ``commit()`` succeeds**, so a rolled-back op never leaks into a synchronous ``state_get``."""
        now = time.time() if now is None else now
        # The state delta to publish to the read-through cache — built INSIDE the body but published
        # in THIS frame only after the batch commits (see below). Captured via closure so the committer
        # (which can only touch the DB) never publishes it; a rolled-back member raises out of
        # _run_grouped and skips the publish, so an uncommitted state op never leaks (AC-4).
        applied: list[tuple[tuple[str, str], Any]] = []

        async def _body() -> bool:
            cur = await self._db.execute(
                "DELETE FROM queue WHERE id=? AND stage=? AND status=?",
                (routed_id, Stage.ROUTED.value, OutboxStatus.INFLIGHT.value),
            )
            if not cur.rowcount:
                # Already handed off by a prior run (crash-restart) — idempotent no-op (zero net
                # mutation; safe to leave in the batch). applied stays empty → nothing published.
                raise _AbortMember(False)
            await self._insert_outbound_deliveries(message_id, channel_id, deliveries, now)
            # Pass-through re-ingress (ADR 0013, generalized): produce each PT child + the parent's
            # done marker in THIS same transaction as the routed-row DELETE, so the handoff is atomic
            # and re-run-idempotent. Read the parent's correlation lineage once (absent → depth 0).
            if pt_deliveries:
                pcur = await self._db.execute(
                    "SELECT metadata FROM messages WHERE id=?", (message_id,)
                )
                prow = await pcur.fetchone()
                parent_meta: dict[str, Any] = {}
                pmeta_json = self._dec(prow["metadata"]) if prow else None
                if pmeta_json:
                    loaded = json.loads(pmeta_json)
                    if isinstance(loaded, dict):
                        parent_meta = loaded
                for pt_name, body in pt_deliveries:
                    produced = await self._insert_passthrough_child(
                        routed_id,
                        message_id,
                        pt_name,
                        body,
                        parent_meta,
                        correlation_depth_cap,
                        now,
                    )
                    # The parent's disposition for this Send: a marker outbound row keyed by the PT
                    # inbound, already terminal (DONE = delivered into the PT, or DEAD = depth-cap
                    # breach → parent ERROR). It is never claimed (no delivery worker for a PT name;
                    # claims take PENDING rows only), so it is inert; it exists solely so the
                    # finalizer counts the Send as delivered/errored rather than collapsing FILTERED.
                    await self._insert_passthrough_marker(message_id, pt_name, produced, now)
            # JSON-encode + apply each declared state write in the SAME transaction as the outbound
            # rows. Encoding is done up front so a (shouldn't-happen) serialization error aborts the
            # whole handoff cleanly rather than after some rows were inserted. SetState validated
            # JSON-serializability at construction, so this is belt-and-suspenders.
            for namespace, key, value in state_ops:
                value_json = json.dumps(value)
                await self._apply_state_op(namespace, key, value_json, message_id, now)
                applied.append(((namespace, key), value))
            total_targets = len(deliveries) + len(pt_deliveries)
            await self._event(
                message_id, "transformed", None, f"{total_targets} destination(s)", now
            )
            # Finalizer owns the terminal disposition (incl. the ROUTED→FILTERED collapse when this
            # was the last handler and nothing delivered anywhere). Runs in this same transaction.
            await self._maybe_finalize_message(message_id, now)
            return True

        # Publish the committed state delta to the read-through cache ONLY on commit success, via the
        # committer's post-commit hook (see _run_grouped on_commit). The hook runs in the committing
        # frame the instant the batch commits — never before (a rolled-back/aborted body skips it, so an
        # uncommitted op never leaks — AC-4) and never skipped (it is NOT in this caller's post-await
        # frame, so a transform worker cancelled while parked on the committer future can no longer leave
        # a committed write absent from _state_cache).
        #
        # NOTE (cross-lane staleness, ADR 0055): a sibling transform worker enrolled in the SAME batch
        # cannot observe this op via state_get until the batch commits and the hook runs. The SAFETY
        # property is unchanged from the pre-feature path: a sibling sees the OLD/absent value (stale,
        # never torn), never a leak of rolled-back state — a bounded widening of the pre-existing
        # "uncommitted state is invisible" property.
        def _publish(_committed: Any) -> None:
            for ck, cv in applied:
                self._state_cache[ck] = cv

        result = bool(await self._run_grouped(_body, on_commit=_publish))
        return result

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
                self._enc(summary),  # EF-3: MRN/name is PHI — ciphered at rest like the body
                self._enc(metadata),
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
        # PHI chokepoint (#120): scrub HL7-shaped content out of the caller's error text before it
        # reaches the error column / event detail. Idempotent if the caller already scrubbed.
        error = safe_text(error) if error else error
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
                items.append(await self._outbox_item_from_row(row))
            except Exception as exc:
                log.warning("dead-lettering undecryptable outbox row %s: %s", row["id"], exc)
                # STANDALONE: this runs post-claim-commit; force an immediate inline commit so it never
                # tries to join a group batch (Hazard A — a claim's dead-letter must not group).
                await self.dead_letter_now(
                    row["id"], f"undecryptable payload: {exc}", _standalone=True
                )
        return items

    async def _outbox_item_from_row(self, row: aiosqlite.Row) -> OutboxItem:
        """Build an :class:`OutboxItem` from a claimed queue row, dereferencing a shared body if any.

        Store-once-deliver-many deref: a row with a non-NULL ``body_ref`` holds its body once in
        ``shared_body`` (its inline ``payload`` is empty); fetch that single encrypted copy and decrypt it
        as the row's body. A row with no ``body_ref`` decrypts its inline ``payload`` directly — byte-
        identical to the pre-feature path (no shared_body read). A missing shared body (corruption /
        premature GC) raises like any undecryptable payload, so the caller dead-letters that one row
        rather than stalling the lane."""
        body_ref = row["body_ref"] if "body_ref" in row.keys() else None
        if body_ref is None:
            return OutboxItem.from_row(row, self._cipher)
        async with self._read() as db:
            cur = await db.execute("SELECT body FROM shared_body WHERE hash=?", (body_ref,))
            br = await cur.fetchone()
        if br is None:
            raise CipherError(f"shared body {body_ref} missing")
        return OutboxItem.from_row(row, self._cipher, shared_ciphertext=br["body"])

    def set_leader_epoch(self, epoch: int | None, *, lease_key: str | None = None) -> None:
        # SQLite is single active node: there is no second writer to fence, so the H1 epoch guard is a
        # no-op here and claim_next_fifo stays byte-identical. The engine never builds a DbCoordinator on
        # SQLite (build_coordinator returns the NullCoordinator, whose current_epoch() is None), so this
        # is only ever called with epoch=None in practice; accept and ignore any value for protocol
        # uniformity.
        return None

    async def warm_pool(self) -> None:
        # No-op: SQLite uses a single connection, so there is no pool to pre-establish (see
        # QueueStore.warm_pool). Single-node SQLite never goes through the active-passive promotion path
        # this optimizes anyway.
        return None

    async def claim_next_fifo(
        self,
        name: str,
        now: float | None = None,
        *,
        stage: str = Stage.OUTBOUND.value,
    ) -> OutboxItem | None:
        """Claim the **single oldest** pending row for one lane at ``stage`` — strict FIFO by enqueue
        time — but only if it is **due**.

        SQLite is single-node so there are no lane leases / failover residue — it always runs the
        single-node claim.

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
        backend. (The SQL Server backend applies the same clamp — ``store/sqlserver.py``'s own
        ``_fifo_created_at`` at its insert sites; its ``claim_next_fifo`` also omits ``READPAST`` on the
        FIFO head to preserve per-lane order, see #285.) If the head is
        still backing off (``next_attempt_at`` in
        the future) this returns ``None`` *without* skipping ahead — the head blocks the lane (head-of-
        line) until it succeeds, dead-letters, or is purged. Contrast :meth:`claim_ready`, which skips a
        backing-off row to drain others (unordered).
        """
        now = time.time() if now is None else now
        # Lane column is a code-controlled literal (chosen by stage), never user input.
        lane_col = (
            "channel_id"
            if stage in (Stage.INGRESS.value, Stage.ROUTED.value, Stage.RESPONSE.value)
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
            # H2 SKIP-AND-COMPLETE. If THIS outbound row instance already has a committed ledger row, a
            # prior delivery completed but the row was re-pended (a crash-re-run recovered via
            # reset_stale_inflight after mark_done committed, or a failover re-claim) — re-sending it is
            # the duplicate H2 prevents. Complete it DONE in THIS same claim txn WITHOUT handing it to a
            # worker and return None, so the lane advances to the next head with NO reorder (the head is
            # consumed in place, exactly as a delivered head would be). A deliberate `replay` DELETEs the
            # ledger row, so a replayed re-send has no entry here and is claimed normally (NOT deduped).
            if claimed["destination_name"] is not None:
                dk = await self._db.execute(
                    "SELECT 1 FROM delivered_keys WHERE outbox_id=? LIMIT 1", (row["id"],)
                )
                if await dk.fetchone() is not None:
                    await self._db.execute(
                        "UPDATE queue SET status=?, last_error=NULL, updated_at=? WHERE id=?",
                        (OutboxStatus.DONE.value, now, row["id"]),
                    )
                    await self._event(
                        claimed["message_id"],
                        "delivered",
                        claimed["destination_name"],
                        "idempotent skip (already delivered)",
                        now,
                    )
                    await self._maybe_finalize_message(claimed["message_id"], now)
                    await self._db.commit()
                    return None
            await self._db.commit()
        try:
            return await self._outbox_item_from_row(claimed)
        except Exception as exc:
            # Same as claim_ready: an undecryptable head must not stall the lane — dead-letter it and
            # let the next poll advance to the new head, rather than re-raising into the worker (H-1).
            # The dead-letter records the message ERROR (visible in the tracking view); a push alert
            # for a poison ingress row is a documented follow-up (the store can't reach the AlertSink).
            log.warning("dead-lettering undecryptable queue row %s: %s", claimed["id"], exc)
            # STANDALONE (Hazard A): post-claim-commit, force an immediate inline commit (no grouping).
            await self.dead_letter_now(
                claimed["id"], f"undecryptable payload: {exc}", _standalone=True
            )
            return None

    async def dead_letter_now(
        self,
        outbox_id: str,
        error: str,
        now: float | None = None,
        *,
        _standalone: bool = False,
    ) -> None:
        """Force a row terminal (``DEAD``) immediately without consuming a retry — **fail-fast**.

        For a delivery that can never succeed as-is and must not hold the FIFO lane: a permanent
        partner reject (``AR``), an internal/code error under the error-and-continue policy, or an
        undecryptable payload (corrupt blob / rotated key). Unlike :meth:`mark_failed`, there's no
        backoff/retry — such a row would just fail identically forever and stall its worker (H-1).

        ``_standalone`` (internal): force an IMMEDIATE inline commit rather than enrolling in the
        group-commit batch. It is set when this is called from inside a STANDALONE claim's
        undecryptable-row path (:meth:`claim_ready` / :meth:`claim_next_fifo`), which already holds its
        own commit and must NOT try to join a batch (and never shares a claim's rollback fate). Direct
        callers (a worker dead-lettering a permanent reject) leave it False so the write groups."""
        error = safe_text(
            error
        )  # PHI chokepoint (#120) — incl. the f"undecryptable payload: {exc}" callers
        now = time.time() if now is None else now

        async def _body() -> None:
            row = await self._row(outbox_id)
            if row is None:
                raise _AbortMember(None)
            await self._db.execute(
                "UPDATE queue SET status=?, next_attempt_at=?, last_error=?, updated_at=? WHERE id=?",
                (OutboxStatus.DEAD.value, now, self._enc(error), now, outbox_id),
            )
            await self._event(row["message_id"], "dead", row["destination_name"], error, now)
            await self._maybe_finalize_message(row["message_id"], now)

        if _standalone:
            # Inline immediate commit (mirrors the disabled path) — never enrol in the committer.
            async with self._lock:
                try:
                    await self._db.execute("BEGIN")
                    await _body()
                    await self._db.commit()
                except _AbortMember:
                    await self._db.rollback()
                except Exception:
                    await self._db.rollback()
                    raise
            return
        await self._run_grouped(_body)

    async def mark_done(self, outbox_id: str, now: float | None = None) -> None:
        now = time.time() if now is None else now

        async def _body() -> None:
            # _row is a read; under group-commit it runs inside the batch's BEGIN. A vanished row is an
            # idempotent no-op (zero mutation) — abort without failing the batch.
            row = await self._row(outbox_id)
            if row is None:
                raise _AbortMember(None)
            await self._db.execute(
                "UPDATE queue SET status=?, last_error=NULL, updated_at=? WHERE id=?",
                (OutboxStatus.DONE.value, now, outbox_id),
            )
            # H2: record the idempotency-ledger row in THIS same transaction as the DONE flip, so the
            # ledger and the row's terminal state commit or roll back together. (Previously this rode
            # aiosqlite's implicit txn; the committer now owns BEGIN/commit — same atomicity.)
            await self._record_delivered_key(
                outbox_id=outbox_id,
                message_id=row["message_id"],
                destination_name=row["destination_name"],
                handler_name=row["handler_name"],
                now=now,
            )
            await self._event(
                row["message_id"],
                "delivered",
                row["destination_name"],
                f"attempt {row['attempts']}",
                now,
            )
            await self._maybe_finalize_message(row["message_id"], now)

        await self._run_grouped(_body)

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
        """Mark one outbound row delivered **and** persist the partner's captured reply in **one
        transaction** (ADR 0013) — everything :meth:`mark_done` does, plus one ``INSERT INTO response``.

        The atomicity is the whole safety story: once this commits the row is ``DONE`` and never
        re-sends, so the reply is captured exactly once; a crash *before* commit leaves the row
        ``INFLIGHT`` and the worker re-sends (the residual at-least-once window, no worse than
        :meth:`mark_done`'s). ``response_seq`` is ``1 + MAX(seq)`` for the ``(message_id,
        destination_name)`` pair, assigned inside this transaction, so it is **replay-stable** (
        :meth:`replay` resets ``queue.attempts=0`` — an attempts-keyed row would collide) and each
        capture is a plain ``INSERT`` that never overwrites a prior reply (immutability is the PRIMARY
        KEY). Runs through :meth:`_run_grouped` (a single ``BEGIN`` … ``commit`` inline when group-commit
        is off; enrolled in the committer's batch when on); **no** intermediate commit. The ``response``
        table is invisible to :meth:`_maybe_finalize_message` (it scans ``queue`` only), so disposition
        is unaffected — a delivered row finalizes ``PROCESSED`` exactly as a non-capturing one does."""
        now = time.time() if now is None else now

        async def _body() -> None:
            cur = await self._db.execute(
                "SELECT message_id, destination_name, handler_name, attempts FROM queue WHERE id=?",
                (outbox_id,),
            )
            row = await cur.fetchone()
            if row is None:
                # Row vanished (cancelled mid-flight) — nothing to complete; no response written.
                # Zero-mutation read so far → idempotent no-op (safe to leave in a group batch).
                raise _AbortMember(None)
            message_id = row["message_id"]
            destination_name = row["destination_name"]
            await self._db.execute(
                "UPDATE queue SET status=?, last_error=NULL, updated_at=? WHERE id=?",
                (OutboxStatus.DONE.value, now, outbox_id),
            )
            cur = await self._db.execute(
                "SELECT COALESCE(MAX(response_seq), 0) AS m FROM response"
                " WHERE message_id=? AND destination_name=?",
                (message_id, destination_name),
            )
            seq_row = await cur.fetchone()
            # COALESCE(...,0) always returns one row, so seq_row is never None; guard for the type.
            seq = (int(seq_row["m"]) if seq_row else 0) + 1
            await self._db.execute(
                "INSERT INTO response"
                " (message_id, destination_name, response_seq, body, outcome, detail, captured_at)"
                " VALUES (?,?,?,?,?,?,?)",
                (
                    message_id,
                    destination_name,
                    seq,
                    self._enc(body),
                    outcome,
                    self._enc(detail),
                    now,
                ),
            )
            if reingress_to is not None:
                # ADR 0013 Increment 2: this reply is to be re-ingressed. Produce a drainable
                # Stage.RESPONSE work-row in the SAME transaction as the artifact (orphan-free): a
                # token referencing the immutable artifact by its (message_id, destination_name,
                # response_seq) PK, encrypted like any payload. channel_id = the loopback inbound (the
                # FIFO lane); message_id = the ORIGIN (so the finalizer holds it in flight until the
                # reply is handed off). The re-ingress worker drains it via ingress_handoff.
                artifact_ref = f"{message_id}\x1f{destination_name}\x1f{seq}"
                work_created = await self._fifo_created_at(
                    Stage.RESPONSE.value, "channel_id", reingress_to, now
                )
                await self._db.execute(
                    "INSERT INTO queue (id, message_id, stage, channel_id, destination_name,"
                    " handler_name, payload, status, attempts, next_attempt_at, created_at,"
                    " updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                    (
                        uuid4().hex,
                        message_id,
                        Stage.RESPONSE.value,
                        reingress_to,
                        None,
                        None,
                        self._enc(artifact_ref),
                        OutboxStatus.PENDING.value,
                        0,
                        now,
                        work_created,
                        now,
                    ),
                )
            # H2: the idempotency-ledger row joins this SAME transaction as the DONE flip + the
            # response artifact (single atomic completion — no second store).
            await self._record_delivered_key(
                outbox_id=outbox_id,
                message_id=message_id,
                destination_name=destination_name,
                handler_name=row["handler_name"],
                now=now,
            )
            await self._event(
                message_id,
                "delivered",
                destination_name,
                f"attempt {row['attempts']} (response {outcome})",
                now,
            )
            await self._maybe_finalize_message(message_id, now)

        await self._run_grouped(_body)

    @staticmethod
    def _passthrough_message_id(routed_id: str, pt_channel: str, body: str) -> str:
        """The content-addressed id of a pass-through (PT) child message (ADR 0013, generalized).

        A Handler's ``Send`` into a PT inbound re-ingresses ``body`` as a new INGRESS-stage message on
        ``pt_channel`` **inside** the parent's ``transform_handoff`` transaction. The id is a
        deterministic function of the **parent's routed row** (``routed_id``, the unit of work being
        consumed), the target PT channel, and the body — 32 hex chars wide to match ``uuid4().hex``. This
        is defense-in-depth: the guarded DELETE of the routed row is the exactly-once gate (a committed
        handoff can never re-run), but a content-addressed id makes a re-run after a *rolled-back partial*
        an idempotent no-op for the child message INSERT too. ``routed_id`` (not the parent message id)
        is the salt so two distinct routed rows of the *same* message that each Send the *same* body into
        the *same* PT inbound produce two distinct children (each is a real, separate unit of work)."""
        h = hashlib.sha256()
        h.update(b"passthrough:")
        h.update(routed_id.encode())
        h.update(b":")
        h.update(pt_channel.encode())
        h.update(b":")
        h.update(body.encode())
        return h.hexdigest()[:32]

    async def _insert_passthrough_child(
        self,
        routed_id: str,
        parent_id: str,
        pt_channel: str,
        body: str,
        parent_meta: dict[str, Any],
        correlation_depth_cap: int,
        now: float,
    ) -> bool:
        """Produce one PT child INGRESS row + message inside the caller's transaction (ADR 0013, gen.).

        Returns ``True`` if a child was produced, ``False`` if the depth cap was breached (no child; the
        caller records the parent ``ERROR`` instead). The child is a **new, independent** message
        (``source_type='passthrough'``, its own content-addressed id, status ``RECEIVED`` per
        count-and-log), correlated to the parent (``correlation_id``/``correlation_root_id``/
        ``correlation_depth``). The PT inbound's own router worker drains the INGRESS row and re-routes
        it. Idempotent re-run: the content-addressed id is pre-checked, so a partial-then-recovered run
        does not double-inject the message. Bounds internal loops by ``correlation_depth`` (mirrors
        ``ingress_handoff``'s cap), computed purely from the parent's immutable metadata → re-run-stable.
        """
        child_depth = int(parent_meta.get("correlation_depth", 0) or 0) + 1
        root = parent_meta.get("correlation_root_id") or parent_id
        if child_depth > correlation_depth_cap:
            # Depth-cap breach: produce NO child, log the breach on the parent. The caller's
            # transform_handoff still consumes the routed row (the Send is "handled" — dead-lettered),
            # and the parent finalizes ERROR via the dead marker the caller records. Mirrors the
            # ingress_handoff depth-cap branch (bound total work, not topology).
            await self._event(
                parent_id,
                "passthrough_dropped",
                pt_channel,
                f"depth cap ({child_depth} > {correlation_depth_cap})",
                now,
            )
            return False
        new_mid = self._passthrough_message_id(routed_id, pt_channel, body)
        cur = await self._db.execute("SELECT 1 FROM messages WHERE id=?", (new_mid,))
        if await cur.fetchone() is None:
            child_meta = json.dumps(
                {
                    "correlation_id": parent_id,
                    "correlation_root_id": root,
                    "correlation_depth": child_depth,
                    "passthrough_from": parent_id,
                }
            )
            await self._insert_message(
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
            ingress_created = await self._fifo_created_at(
                Stage.INGRESS.value, "channel_id", pt_channel, now
            )
            await self._db.execute(
                "INSERT INTO queue (id, message_id, stage, channel_id, destination_name,"
                " handler_name, payload, status, attempts, next_attempt_at, created_at,"
                " updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    uuid4().hex,
                    new_mid,
                    Stage.INGRESS.value,
                    pt_channel,
                    None,
                    None,
                    self._cipher.encrypt(body),
                    OutboxStatus.PENDING.value,
                    0,
                    now,
                    ingress_created,
                    now,
                ),
            )
            await self._event(
                new_mid, "received", None, f"passthrough from {parent_id} -> {pt_channel}", now
            )
            await self._event(
                parent_id, "passthrough", pt_channel, f"-> {new_mid} depth {child_depth}", now
            )
        return True

    async def _insert_passthrough_marker(
        self, parent_id: str, pt_name: str, produced: bool, now: float
    ) -> None:
        """Stamp the parent's terminal disposition row for a Send-into-PT (ADR 0013, generalized).

        A single ``stage='outbound'`` row keyed by the PT inbound name, inserted already-terminal: ``done``
        when the child was produced (the Send was *delivered* into the PT → the parent finalizes
        ``PROCESSED``, not ``FILTERED``), or ``dead`` when the depth cap was breached (→ the parent
        finalizes ``ERROR``). It is **never claimed** — there is no delivery worker for a PT inbound name,
        and FIFO/ready claims take ``pending`` rows only — so it is inert work-wise; it exists solely so
        the single finalizer authority counts the Send's outcome. The payload is the empty-body sentinel
        (no real egress body); ``next_attempt_at`` is ``now`` (terminal, never due). A ``delivered``/
        ``dead`` event mirrors a normal outbound's so the hop is visible in the per-message timeline."""
        status = OutboxStatus.DONE.value if produced else OutboxStatus.DEAD.value
        created_at = await self._fifo_created_at(
            Stage.OUTBOUND.value, "destination_name", pt_name, now
        )
        await self._db.execute(
            "INSERT INTO queue (id, message_id, stage, channel_id, destination_name, handler_name,"
            " payload, status, attempts, next_attempt_at, created_at, updated_at)"
            " VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                uuid4().hex,
                parent_id,
                Stage.OUTBOUND.value,
                pt_name,
                pt_name,
                None,
                self._cipher.encrypt(""),
                status,
                0,
                now,
                created_at,
                now,
            ),
        )
        if produced:
            await self._event(parent_id, "delivered", pt_name, "passthrough re-ingress", now)
        else:
            await self._event(parent_id, "dead", pt_name, "passthrough depth cap", now)

    @staticmethod
    def _reingress_message_id(origin_id: str, dest: str, seq: int, body: str) -> str:
        """The content-addressed id of a re-ingressed message (ADR 0013 Increment 2): a deterministic
        function of the origin + the immutable artifact, 32 hex chars wide to match ``uuid4().hex``. This
        is defense-in-depth (the guarded DELETE is the exactly-once gate); because the artifact body is
        immutable, the id is stable across re-runs of the *same* reply, while a genuinely different reply
        (a new ``response_seq``) is a different artifact → a legitimately distinct re-ingress."""
        h = hashlib.sha256()
        h.update(b"reingress:")
        h.update(origin_id.encode())
        h.update(b":")
        h.update(dest.encode())
        h.update(b":")
        h.update(str(seq).encode())
        h.update(b":")
        h.update(body.encode())
        return h.hexdigest()[:32]

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
        row in **one transaction** (ADR 0013 Increment 2; a clone of :meth:`route_handoff`).

        The work-row's existence **is** the token: a guarded ``DELETE`` (step 7) is the commit, so a
        committed run is an idempotent no-op (the row is gone → returns ``False``) and a crash rolls back.
        The new message id is **content-addressed** from the immutable artifact (re-run-stable). On a
        ``correlation_depth`` breach the work-row is dead-lettered and the origin flips ``ERROR`` (no
        child). On ``peek_failed`` the child is produced ``RECEIVED→ERROR`` with **no** ingress row (it
        owes no work) — count-and-log holds, the token is still consumed. The peek-derived
        ``control_id``/``message_type``/``summary`` are passed **in** so the store stays parsing-free.
        Returns ``True`` if this call performed the handoff, ``False`` if it was an already-consumed no-op."""
        now = time.time() if now is None else now
        async with self._lock:
            try:
                await self._db.execute("BEGIN")
                # 1. The work-row must still be INFLIGHT (the claim set it so); it carries the artifact ref.
                cur = await self._db.execute(
                    "SELECT message_id, payload FROM queue WHERE id=? AND stage=? AND status=?",
                    (response_row_id, Stage.RESPONSE.value, OutboxStatus.INFLIGHT.value),
                )
                wr = await cur.fetchone()
                if wr is None:
                    await self._db.rollback()  # already consumed by a committed prior run — no-op
                    return False
                origin_id = wr["message_id"]
                try:
                    ref = self._dec(wr["payload"]) or ""
                    origin_msg_id, dest, seq_s = ref.split("\x1f")
                    seq = int(seq_s)
                except Exception:  # noqa: BLE001 - any decrypt/parse failure = an unrecoverable ref
                    # A corrupt/undecryptable work-row reference (DB corruption, a cipher/key failure)
                    # can NEVER be re-ingressed. Dead-letter the token + ERROR the origin in THIS
                    # transaction and CONSUME it (return True) — never re-loop forever on a row that can't
                    # be parsed. Mirrors the depth-cap branch (a different unrecoverable-token case).
                    await self._db.execute(
                        "UPDATE queue SET status=?, last_error=?, next_attempt_at=?, updated_at=?"
                        " WHERE id=?",
                        (
                            OutboxStatus.DEAD.value,
                            self._enc("re-ingress work-row reference is corrupt/unparseable"),
                            now,
                            now,
                            response_row_id,
                        ),
                    )
                    await self._event(origin_id, "dead", None, "re-ingress ref corrupt", now)
                    await self._maybe_finalize_message(origin_id, now)
                    await self._db.commit()
                    return True
                # 2. The IMMUTABLE artifact body (same committed bytes every re-run → re-run-stable). NULL
                #    only if retention purged it — but an outstanding work-row makes the message
                #    purge-ineligible (Q8), so this is defensive: treat as empty, still consume.
                cur = await self._db.execute(
                    "SELECT body FROM response"
                    " WHERE message_id=? AND destination_name=? AND response_seq=?",
                    (origin_msg_id, dest, seq),
                )
                art = await cur.fetchone()
                body = self._dec(art["body"]) if (art and art["body"] is not None) else ""
                body = body or ""
                # 3. The origin's correlation lineage (absent keys → depth 0, origin is its own root).
                cur = await self._db.execute(
                    "SELECT metadata FROM messages WHERE id=?", (origin_id,)
                )
                mrow = await cur.fetchone()
                origin_meta: dict[str, Any] = {}
                meta_json = self._dec(mrow["metadata"]) if mrow else None  # EF-3: ciphered at rest
                if meta_json:
                    loaded = json.loads(meta_json)
                    if isinstance(loaded, dict):
                        origin_meta = loaded
                child_depth = int(origin_meta.get("correlation_depth", 0) or 0) + 1
                root = origin_meta.get("correlation_root_id") or origin_id
                if child_depth > correlation_depth_cap:
                    # Depth-cap breach: dead-letter the token, ERROR the origin (Q4). Consume (don't
                    # re-loop), produce NO child.
                    await self._db.execute(
                        "UPDATE queue SET status=?, last_error=?, next_attempt_at=?, updated_at=?"
                        " WHERE id=?",
                        (
                            OutboxStatus.DEAD.value,
                            self._enc(
                                f"re-ingress correlation depth exceeded "
                                f"({child_depth} > {correlation_depth_cap})"
                            ),
                            now,
                            now,
                            response_row_id,
                        ),
                    )
                    await self._event(
                        origin_id, "dead", dest, f"re-ingress depth cap ({child_depth})", now
                    )
                    await self._maybe_finalize_message(origin_id, now)
                    await self._db.commit()
                    return True
                # 4. Content-addressed child id (defense-in-depth; the guarded DELETE is the gate).
                new_mid = self._reingress_message_id(origin_id, dest, seq, body)
                cur = await self._db.execute("SELECT 1 FROM messages WHERE id=?", (new_mid,))
                already = await cur.fetchone() is not None
                if not already:
                    # 5. The re-ingressed message (RECEIVED, or RECEIVED→ERROR on a non-peekable HL7 body).
                    child_meta = json.dumps(
                        {
                            "correlation_id": origin_id,
                            "correlation_root_id": root,
                            "correlation_depth": child_depth,
                            "reingress_of_seq": seq,
                        }
                    )
                    await self._insert_message(
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
                    # 6. The ingress queue row — UNLESS peek_failed (an ERROR message owes no work).
                    if not peek_failed:
                        ingress_created = await self._fifo_created_at(
                            Stage.INGRESS.value, "channel_id", loopback_channel_id, now
                        )
                        await self._db.execute(
                            "INSERT INTO queue (id, message_id, stage, channel_id, destination_name,"
                            " handler_name, payload, status, attempts, next_attempt_at, created_at,"
                            " updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                            (
                                uuid4().hex,
                                new_mid,
                                Stage.INGRESS.value,
                                loopback_channel_id,
                                None,
                                None,
                                self._cipher.encrypt(body),
                                OutboxStatus.PENDING.value,
                                0,
                                now,
                                ingress_created,
                                now,
                            ),
                        )
                    await self._event(
                        new_mid,
                        "received",
                        None,
                        f"reingress from {origin_id}/{dest}/seq{seq}",
                        now,
                    )
                    await self._event(
                        origin_id, "reingressed", dest, f"-> {new_mid} depth {child_depth}", now
                    )
                # 7. CONSUME THE TOKEN — the guarded DELETE is the synchronization point (clone
                #    route_handoff). rowcount 0 (already consumed) → roll back, no-op.
                cur = await self._db.execute(
                    "DELETE FROM queue WHERE id=? AND stage=? AND status=?",
                    (response_row_id, Stage.RESPONSE.value, OutboxStatus.INFLIGHT.value),
                )
                if not cur.rowcount:
                    await self._db.rollback()
                    return False
                # 8. The origin may now finalize (its last outstanding RESPONSE row is gone).
                await self._maybe_finalize_message(origin_id, now)
                await self._db.commit()
            except Exception:
                await self._db.rollback()
                raise
        return True

    async def response_body_for_work_row(self, response_row_id: str) -> str | None:
        """The decrypted artifact body a ``Stage.RESPONSE`` work-row references (ADR 0013 Increment 2) —
        read by the re-ingress worker so it can HL7-peek the reply (in ``pipeline/``, keeping the store
        parsing-free) before calling :meth:`ingress_handoff`. ``None`` if the row or artifact is gone (a
        committed prior handoff). The ``ingress_handoff`` it precedes re-reads the same immutable artifact
        for the message raw, so the peek and the raw always agree."""
        async with self._read() as db:
            cur = await db.execute(
                "SELECT payload FROM queue WHERE id=? AND stage=?",
                (response_row_id, Stage.RESPONSE.value),
            )
            row = await cur.fetchone()
            if row is None:
                return None
            ref = self._dec(row["payload"]) or ""
            try:
                mid, dest, seq_s = ref.split("\x1f")
            except ValueError:
                return None
            cur = await db.execute(
                "SELECT body FROM response"
                " WHERE message_id=? AND destination_name=? AND response_seq=?",
                (mid, dest, int(seq_s)),
            )
            art = await cur.fetchone()
        return self._dec(art["body"]) if (art and art["body"] is not None) else ""

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
        # ADR 0021 "Response Sent": an immutable kind='ack_sent' response row under a sentinel dest
        # (\x1fack:<inbound>) — the leading \x1f can't occur in a real connection name, so the key is
        # provably disjoint from every outbound destination. Own transaction (seq SELECT + INSERT);
        # touches no queue row and calls no _maybe_finalize (response is finalizer-invisible). PHI
        # fail-safe: a NAK passes ack_body=None → body NULL; an AA body is stored ONLY when the store is
        # encrypted, else NULL — default-on never persists raw ACK PHI on an unencrypted store. detail
        # is safe_text-scrubbed (#120) + encrypted.
        now = time.time() if now is None else now
        dest = "\x1fack:" + inbound_name
        enc_body = self._enc(ack_body) if (ack_body and self._cipher.encrypts) else None
        enc_detail = self._enc(safe_text(detail)[:200]) if detail else None
        async with self._lock:
            try:
                await self._db.execute("BEGIN")
                cur = await self._db.execute(
                    "SELECT COALESCE(MAX(response_seq), 0) AS m FROM response"
                    " WHERE message_id=? AND destination_name=? AND kind='ack_sent'",
                    (message_id, dest),
                )
                seq_row = await cur.fetchone()
                seq = (int(seq_row["m"]) if seq_row else 0) + 1
                await self._db.execute(
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
                await self._db.commit()
            except Exception:
                await self._db.rollback()
                raise

    async def correlate_response(self, message_id: str) -> list[CapturedResponse]:
        """Every captured reply for ``message_id`` (ADR 0013) + the inbound ``ack_sent`` rows (ADR
        0021), ordered by destination then ``response_seq`` (so the **latest** ``response_seq`` per
        destination is the authoritative reply; ack rows sort under their sentinel name, disjoint from
        real destinations). A **PHI read surface**: ``body``/``detail`` are decrypted here, and the API
        route that exposes them is deny-by-default, body-gated, and audited (``response.read``)."""
        async with self._read() as db:
            cur = await db.execute(
                "SELECT message_id, destination_name, response_seq, body, outcome, detail,"
                " captured_at, kind, ack_code, ack_phase FROM response"
                " WHERE message_id=? ORDER BY destination_name, response_seq",
                (message_id,),
            )
            rows = await cur.fetchall()
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

    async def mark_failed(
        self, outbox_id: str, error: str, retry: RetryPolicy, now: float | None = None
    ) -> None:
        """Reschedule with exponential backoff, or dead-letter if retries are exhausted."""
        error = safe_text(error)  # PHI chokepoint (#120)
        now = time.time() if now is None else now

        async def _body() -> None:
            row = await self._row(outbox_id)
            if row is None:
                raise _AbortMember(None)
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

        await self._run_grouped(_body)

    async def pending_depth(
        self, name: str, *, stage: str = Stage.OUTBOUND.value
    ) -> tuple[int, float | None]:
        """``(pending_count, oldest_created_at)`` for one lane at ``stage`` (see the protocol).

        Lane key is stage-aware (mirrors :meth:`claim_next_fifo`): outbound lanes key on
        ``destination_name``; ingress and routed lanes on ``channel_id`` (their ``destination_name``
        is NULL)."""
        lane_col = (
            "channel_id"
            if stage in (Stage.INGRESS.value, Stage.ROUTED.value, Stage.RESPONSE.value)
            else "destination_name"
        )
        async with self._read() as db:
            cur = await db.execute(
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
            if not stuck:
                # RE-SEND branch (H2): an operator deliberately re-transmits already-DONE rows. Drop
                # their idempotency-ledger entries FIRST so the re-claimed rows are NOT skip-and-completed
                # as crash-re-run duplicates — a replay must actually re-deliver. Scoped to THIS message's
                # DONE rows (the exact set the UPDATE below re-pends), so no other message is affected.
                await self._db.execute(
                    "DELETE FROM delivered_keys WHERE outbox_id IN"
                    " (SELECT id FROM queue WHERE message_id=? AND status=?)",
                    (message_id, OutboxStatus.DONE.value),
                )
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
        async with self._read() as db:
            cur = await db.execute("SELECT * FROM messages WHERE id=?", (message_id,))
            row = await cur.fetchone()
        if row is None:
            return None
        record = dict(row)
        record["raw"] = self._cipher.decrypt(record["raw"])  # decrypt the body for display
        record["error"] = self._dec(record["error"])  # error may embed raw HL7 fragments (WP-5)
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
        """Most-recent-first message listing for the tracking view, with optional filters.

        Bodies (``raw``) are intentionally omitted here — the list view is metadata only,
        so PHI isn't fetched until a specific message is opened (and audited). ``allowed_channels``
        restricts the result to a caller's per-channel RBAC scope (None = all)."""
        where, params = self._message_filter(
            channel_id, status, message_type, control_id, allowed_channels
        )
        async with self._read() as db:
            cur = await db.execute(
                "SELECT id, channel_id, received_at, source_type, control_id, message_type,"
                " status, error, summary, metadata,"
                " (SELECT event FROM message_events e WHERE e.message_id = messages.id"
                "  ORDER BY e.id DESC LIMIT 1) AS last_event"
                f" FROM messages{where}"
                " ORDER BY received_at DESC, id DESC LIMIT ? OFFSET ?",
                (*params, limit, offset),
            )
            return [
                self._decode_row(r, "error", "summary", "metadata") for r in await cur.fetchall()
            ]

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
        async with self._read() as db:
            cur = await db.execute(f"SELECT COUNT(*) AS n FROM messages{where}", params)
            row = await cur.fetchone()
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
        """Scan-and-decrypt content search (ADR 0046 #51): pre-filter on the indexed metadata, then
        decrypt + match each candidate body **in memory** (a plain SQL ``LIKE`` is impossible while the
        cipher is on — the at-rest bytes are per-row random-nonced AES-GCM ciphertext).

        The metadata ``WHERE`` (``_message_filter`` + per-channel RBAC) narrows the candidate set before
        any decrypt; rows are walked newest-first and decrypt+match runs **off the event loop** (the
        per-row AES-GCM decrypt + HL7 parse is CPU work). The scan stops after ``spec.scan_limit``
        decrypts (``truncated=True``) or ``limit`` matches, whichever first — the hard cost ceiling that
        keeps this slow-by-construction read safe to expose."""
        where, params = self._message_filter(
            channel_id, status, message_type, control_id, allowed_channels
        )
        # Stream candidates newest-first under one read snapshot; decrypt+match each off the loop. We
        # select only id + the two cipher-covered columns we match on — never a whole detail row.
        async with self._read() as db:
            cur = await db.execute(
                "SELECT id, channel_id, received_at, source_type, control_id, message_type,"
                " status, error, summary, metadata, raw,"
                " (SELECT event FROM message_events e WHERE e.message_id = messages.id"
                "  ORDER BY e.id DESC LIMIT 1) AS last_event"
                f" FROM messages{where}"
                " ORDER BY received_at DESC, id DESC",
                params,
            )
            candidates = list(await cur.fetchall())
        return await asyncio.to_thread(self._scan_rows, spec, candidates, limit)

    def _scan_rows(
        self, spec: SearchSpec, candidates: Sequence[aiosqlite.Row], limit: int
    ) -> MessageSearchResult:
        """The off-loop decrypt+match loop (run via ``asyncio.to_thread``). Decrypts each candidate's
        ``raw``/``summary`` and tests the content predicate; bounded by ``spec.scan_limit`` decrypts and
        ``limit`` matches. The returned rows are metadata-only (the decrypted ``raw`` is dropped — the
        result has the same PHI surface as ``list_messages``)."""
        rows: list[dict[str, Any]] = []
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
                d = self._decode_row(cand, "error", "summary", "metadata")
                d.pop("raw", None)  # never return the decrypted body in a list-shaped result
                rows.append(d)
                if len(rows) >= limit:
                    break
        return MessageSearchResult(
            rows=rows, scanned=scanned, matched=len(rows), truncated=truncated
        )

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
        async with self._read() as db:
            cur = await db.execute(
                "SELECT o.id AS outbox_id, o.message_id, o.channel_id, o.destination_name,"
                " o.attempts, o.last_error, o.updated_at,"
                " m.control_id, m.message_type, m.received_at, m.summary"
                f" FROM queue o JOIN messages m ON m.id = o.message_id{where}"
                " ORDER BY o.updated_at DESC, o.id DESC LIMIT ? OFFSET ?",
                (*params, limit, offset),
            )
            return [self._decode_row(r, "last_error", "summary") for r in await cur.fetchall()]

    async def count_dead(
        self,
        *,
        channel_id: str | None = None,
        destination_name: str | None = None,
        allowed_channels: Sequence[str] | None = None,
    ) -> int:
        """Total dead-lettered deliveries matching the same filters as :meth:`list_dead`."""
        where, params = self._dead_filter(channel_id, destination_name, allowed_channels)
        async with self._read() as db:
            cur = await db.execute(f"SELECT COUNT(*) AS n FROM queue o{where}", params)
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
        async with self._read() as db:
            cur = await db.execute(
                "SELECT * FROM queue WHERE message_id=? AND stage=? ORDER BY destination_name",
                (message_id, Stage.OUTBOUND.value),
            )
            return [self._decode_row(r, "last_error") for r in await cur.fetchall()]

    async def outbox_payloads_for(self, message_id: str) -> list[dict[str, Any]]:
        """Like :meth:`outbox_for`, but **also decrypts the transformed ``payload``** (PHI body) for
        each outbound delivery — the parity-comparison read path (#14). Kept separate from
        ``outbox_for`` so the metadata-only message-detail view never materializes plaintext bodies;
        the API gates this behind ``MESSAGES_VIEW_RAW`` and audits the access."""
        # LEFT JOIN the single shared copy so a body_ref row's body is decrypted from shared_body.body;
        # an inline row (NULL body_ref) keeps its own queue.payload. COALESCE picks the right ciphertext
        # source per row so store-once is transparent to this PHI-body read (the #14 parity comparison).
        async with self._read() as db:
            cur = await db.execute(
                "SELECT q.*, "
                "COALESCE(sb.body, q.payload) AS _body_ciphertext "
                "FROM queue q LEFT JOIN shared_body sb ON sb.hash = q.body_ref "
                "WHERE q.message_id=? AND q.stage=? ORDER BY q.destination_name",
                (message_id, Stage.OUTBOUND.value),
            )
            out: list[dict[str, Any]] = []
            for r in await cur.fetchall():
                d = self._decode_row(r, "last_error")
                d["payload"] = self._dec(d.pop("_body_ciphertext"))
                out.append(d)
            return out

    async def events_for(self, message_id: str) -> list[dict[str, Any]]:
        async with self._read() as db:
            cur = await db.execute(
                "SELECT * FROM message_events WHERE message_id=? ORDER BY id", (message_id,)
            )
            return [self._decode_row(r, "detail") for r in await cur.fetchall()]

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
        # Pure observer: a single short INSERT under the write lock — NOT inside any handoff txn, no
        # queue row, no finalizer call (connection_event is invisible to _maybe_finalize_message, which
        # scans `FROM queue`). reason goes through the safe_text PHI chokepoint (#120) + the cipher.
        now = time.time() if now is None else now
        reason_enc = self._enc(safe_text(reason)[:200]) if reason else None
        async with self._lock:
            await self._db.execute(
                "INSERT INTO connection_event"
                " (ts, connection, transport, direction, kind, peer_host, message_id, reason)"
                " VALUES (?,?,?,?,?,?,?,?)",
                (now, connection, transport, direction, kind, peer_host, message_id, reason_enc),
            )
            await self._db.commit()

    async def list_connection_events(
        self,
        *,
        connection: str | None = None,
        kinds: Sequence[str] | None = None,
        since: float | None = None,
        limit: int = 100,
        allowed_channels: Sequence[str] | None = None,
    ) -> list[ConnectionEvent]:
        limit = max(
            1, min(limit, 1000)
        )  # server-side clamp (a flooded log can't drive an unbounded read)
        where: list[str] = []
        params: list[Any] = []
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
        # outbound row (which spans channels) — mirrors the connection_metadata/purge boundary that
        # hides shared-outbound topology. None leaves the read unrestricted.
        if allowed_channels is not None:
            where.append("direction='inbound'")
            _append_channel_scope(where, params, "connection", allowed_channels)
        clause = (" WHERE " + " AND ".join(where)) if where else ""
        params.append(limit)
        async with self._read() as db:
            cur = await db.execute(
                f"SELECT id, ts, connection, transport, direction, kind, peer_host, message_id, reason"
                f" FROM connection_event{clause} ORDER BY ts DESC, id DESC LIMIT ?",
                params,
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
                for r in await cur.fetchall()
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
        # Pure observer (ADR 0044 D2): a single short upsert under the write lock — NO queue row, NO
        # finalizer call (alert_instance is invisible to _maybe_finalize_message's `FROM queue` scan), so
        # it can never pin a message disposition. De-dup grain = ADR 0014's (event_type, connection)
        # throttle key. If a live (open/acknowledged) instance exists, fold the re-fire into it (bump
        # last_seen + count, refresh severity/reason; an acknowledged instance STAYS acknowledged — the
        # operator already owns it). Otherwise insert a fresh `open` row. reason rides safe_text (#120) +
        # the cipher. Never raises into the _emit caller (the caller wraps fail-soft).
        now = time.time() if now is None else now
        reason_enc = self._enc(safe_text(reason)[:200]) if reason else None
        async with self._lock:
            cur = await self._db.execute(
                "UPDATE alert_instance SET last_seen=?, count=count+1, severity=?, reason=?"
                " WHERE event_type=? AND connection=? AND status!='resolved'",
                (now, severity, reason_enc, event_type, connection),
            )
            if cur.rowcount == 0:
                await self._db.execute(
                    "INSERT INTO alert_instance"
                    " (event_type, connection, severity, status, first_seen, last_seen, count, reason)"
                    " VALUES (?,?,?,'open',?,?,1,?)",
                    (event_type, connection, severity, now, now, reason_enc),
                )
            await self._db.commit()

    async def list_active_alert_instances(
        self,
        *,
        limit: int = 200,
        allowed_channels: Sequence[str] | None = None,
    ) -> list[AlertInstance]:
        # The read accessor for GET /alerts/active: open + acknowledged instances, newest last_seen
        # first. Runs on the lockfree read path. `allowed_channels` applies the SAME per-channel RBAC
        # scope as list_connection_events (None = unrestricted; a set restricts to instances whose
        # connection is in the allow-set). limit is clamped server-side.
        limit = max(1, min(limit, 1000))
        where = ["status IN ('open','acknowledged')"]
        params: list[Any] = []
        if allowed_channels is not None:
            _append_channel_scope(where, params, "connection", allowed_channels)
        clause = " WHERE " + " AND ".join(where)
        params.append(limit)
        async with self._read() as db:
            cur = await db.execute(
                "SELECT id, event_type, connection, severity, status, first_seen, last_seen, count,"
                f" reason, acked_by, acked_at, resolved_at FROM alert_instance{clause}"
                " ORDER BY last_seen DESC, id DESC LIMIT ?",
                params,
            )
            return [self._alert_instance_row(r) for r in await cur.fetchall()]

    async def get_alert_instance(
        self, alert_id: int, *, allowed_channels: Sequence[str] | None = None
    ) -> AlertInstance | None:
        # Read one instance by id (any status) — the API echo for ack/resolve. RBAC-scoped exactly like
        # list_active_alert_instances (a scoped caller can't read an instance outside its channels).
        where = ["id=?"]
        params: list[Any] = [alert_id]
        if allowed_channels is not None:
            _append_channel_scope(where, params, "connection", allowed_channels)
        clause = " WHERE " + " AND ".join(where)
        async with self._read() as db:
            cur = await db.execute(
                "SELECT id, event_type, connection, severity, status, first_seen, last_seen, count,"
                f" reason, acked_by, acked_at, resolved_at FROM alert_instance{clause}",
                params,
            )
            row = await cur.fetchone()
            return self._alert_instance_row(row) if row is not None else None

    def _alert_instance_row(self, r: aiosqlite.Row) -> AlertInstance:
        return AlertInstance(
            id=r["id"],
            event_type=r["event_type"],
            connection=r["connection"],
            severity=r["severity"],
            status=r["status"],
            first_seen=r["first_seen"],
            last_seen=r["last_seen"],
            count=r["count"],
            reason=self._dec(r["reason"]),
            acked_by=r["acked_by"],
            acked_at=r["acked_at"],
            resolved_at=r["resolved_at"],
        )

    async def ack_alert_instance(
        self, alert_id: int, *, actor: str, now: float | None = None
    ) -> bool:
        # Operator ack: open|acknowledged → acknowledged, recording acked_by/acked_at. Idempotent (a
        # re-ack is a no-op update). Returns True iff a non-resolved instance with this id existed (so
        # the API can 404 a resolved/unknown id). Ack'ing a resolved instance is refused (no-op → False).
        now = time.time() if now is None else now
        async with self._lock:
            cur = await self._db.execute(
                "UPDATE alert_instance SET status='acknowledged', acked_by=?, acked_at=?"
                " WHERE id=? AND status!='resolved'",
                (actor, now, alert_id),
            )
            await self._db.commit()
            return cur.rowcount > 0

    async def resolve_alert_instance(self, alert_id: int, *, now: float | None = None) -> bool:
        # Operator resolve: open|acknowledged → resolved, recording resolved_at. Returns True iff a
        # non-resolved instance with this id existed.
        now = time.time() if now is None else now
        async with self._lock:
            cur = await self._db.execute(
                "UPDATE alert_instance SET status='resolved', resolved_at=?"
                " WHERE id=? AND status!='resolved'",
                (now, alert_id),
            )
            await self._db.commit()
            return cur.rowcount > 0

    async def resolve_alert_instances_for(
        self, *, event_type: str, connection: str, now: float | None = None
    ) -> int:
        # Auto-resolution (ADR 0044 D2): an inverse lifecycle signal (e.g. connection_restored) resolves
        # the matching live instance(s) for a (event_type, connection) key. Returns the count resolved.
        now = time.time() if now is None else now
        async with self._lock:
            cur = await self._db.execute(
                "UPDATE alert_instance SET status='resolved', resolved_at=?"
                " WHERE event_type=? AND connection=? AND status!='resolved'",
                (now, event_type, connection),
            )
            await self._db.commit()
            return int(cur.rowcount)

    async def count_open_alerts_by_connection(self) -> dict[str, int]:
        # Back ConnectionRow.alerts_active (ADR 0044 D4): the OPEN (not acknowledged, not resolved)
        # instance count per connection, joined to the dashboard rows by connection name. Lockfree read.
        async with self._read() as db:
            cur = await db.execute(
                "SELECT connection, COUNT(*) AS n FROM alert_instance"
                " WHERE status='open' GROUP BY connection"
            )
            return {r["connection"]: int(r["n"]) for r in await cur.fetchall()}

    async def purge_alert_instances(self, *, older_than: float, now: float | None = None) -> int:
        # Retention (ADR 0044 D5): age-DELETE RESOLVED instances whose resolved_at predates older_than —
        # metadata-only, on their own window, driven by the RetentionRunner. NEVER touches an
        # open/acknowledged instance. A single short transaction.
        async with self._lock:
            cur = await self._db.execute(
                "DELETE FROM alert_instance WHERE status='resolved' AND resolved_at IS NOT NULL"
                " AND resolved_at < ?",
                (older_than,),
            )
            await self._db.commit()
            return int(cur.rowcount)

    # <<< end alert_instance block (#56) >>>

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
        displays, detail views, exports, …). ``detail`` is an opaque (JSON) string.

        After the row is durably committed, a **PHI-safe metadata copy** is teed off-box via
        :func:`~messagefoundry.store.audit_tee.emit_audit_tee` (sec-offbox-log) so the audit trail
        survives a host/DB compromise — the same shared redaction path used by every backend."""
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
        # Tee off-box AFTER commit (only forward what truly persisted) and OUTSIDE the lock (a
        # synchronous syslog send must never hold the write lock or block the event loop under it).
        emit_audit_tee(action=action, actor=actor, channel_id=channel_id, detail=detail, ts=now)

    async def list_audit(self, *, limit: int = 50) -> list[aiosqlite.Row]:
        """Most-recent-first audit entries (for review tooling / tests)."""
        async with self._read() as db:
            cur = await db.execute("SELECT * FROM audit_log ORDER BY id DESC LIMIT ?", (limit,))
            return list(await cur.fetchall())

    async def security_events_for_user(
        self, username: str, *, limit: int = 100
    ) -> list[aiosqlite.Row]:
        """A user's own security events (the audited ``auth.*`` actions), most-recent-first — the
        source for ``GET /me/security-events`` (ASVS 6.3.5/6.3.7). Admin-initiated changes (whose audit
        ``actor`` is the admin) are delivered out-of-band by email, not shown in this self view."""
        async with self._read() as db:
            cur = await db.execute(
                "SELECT ts, action, detail FROM audit_log "
                "WHERE actor = ? AND action LIKE 'auth.%' ORDER BY id DESC LIMIT ?",
                (username, limit),
            )
            return list(await cur.fetchall())

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
        async with self._lock:
            await self._db.execute(
                "INSERT INTO pending_approvals "
                "(id, operation, params, requester, requested_at, status, expires_at) "
                "VALUES (?,?,?,?,?,'pending',?)",
                (approval_id, operation, params, requester, requested_at, expires_at),
            )
            await self._db.commit()

    async def get_pending_approval(self, approval_id: str) -> aiosqlite.Row | None:
        async with self._read() as db:
            cur = await db.execute(
                "SELECT id, operation, params, requester, requested_at, status, approver, decided_at,"
                " expires_at FROM pending_approvals WHERE id = ?",
                (approval_id,),
            )
            return await cur.fetchone()

    async def list_pending_approvals(self, *, now: float, limit: int = 100) -> list[aiosqlite.Row]:
        """Open (still-``pending``, unexpired) approval requests, newest-first."""
        async with self._read() as db:
            cur = await db.execute(
                "SELECT id, operation, params, requester, requested_at, status, approver, decided_at,"
                " expires_at FROM pending_approvals"
                " WHERE status = 'pending' AND (expires_at IS NULL OR expires_at > ?)"
                " ORDER BY requested_at DESC LIMIT ?",
                (now, limit),
            )
            return list(await cur.fetchall())

    async def decide_pending_approval(
        self, approval_id: str, *, status: str, approver: str | None, decided_at: float
    ) -> bool:
        """Atomically move a still-``pending`` request to ``status`` (approved/rejected/expired).
        Returns ``True`` iff this call made the transition — guards against a double decision."""
        async with self._lock:
            cur = await self._db.execute(
                "UPDATE pending_approvals SET status = ?, approver = ?, decided_at = ?"
                " WHERE id = ? AND status = 'pending'",
                (status, approver, decided_at, approval_id),
            )
            await self._db.commit()
            return cur.rowcount > 0

    async def audit_anchor(self) -> tuple[int, str]:
        """The audit log's external anchor — ``(row_count, head_hash)`` (head ``""`` when empty).

        The hash chain links each row to its predecessor, but deleting the *newest* rows leaves a
        shorter chain that still verifies, so a within-DB check can't detect tail-truncation. Recording
        this anchor out-of-band (e.g. a compliance job snapshotting it elsewhere) and passing it back to
        :meth:`verify_audit_chain` is what makes truncation/rewrite detectable (review low-1)."""
        async with self._read() as db:
            cur = await db.execute(
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
        async with self._read() as db:
            cur = await db.execute(
                "SELECT id, ts, actor, action, channel_id, detail, row_hash FROM audit_log ORDER BY id"
            )
            rows = await cur.fetchall()
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
        async with self._read() as db:
            cur = await db.execute("SELECT * FROM users WHERE id=?", (user_id,))
            row = await cur.fetchone()
        return UserRecord.from_mapping(dict(row)) if row else None

    async def get_user_by_username(self, username: str) -> UserRecord | None:
        async with self._read() as db:
            cur = await db.execute("SELECT * FROM users WHERE username=?", (username,))
            row = await cur.fetchone()
        return UserRecord.from_mapping(dict(row)) if row else None

    async def list_users(self) -> list[UserRecord]:
        async with self._read() as db:
            cur = await db.execute("SELECT * FROM users ORDER BY username")
            return [UserRecord.from_mapping(dict(r)) for r in await cur.fetchall()]

    async def count_users(self) -> int:
        async with self._read() as db:
            return await self._count(db, "users")

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

    # --- MFA: native TOTP second factor (local accounts, WP-14) --------------

    async def set_totp_secret(
        self, user_id: str, *, secret: str | None, now: float | None = None
    ) -> None:
        """Stage (or clear) a user's base32 TOTP secret, store-cipher encrypted at rest. Does **not**
        enable MFA — enrollment is confirmed by :meth:`enable_totp` after the user proves a live code.
        ``secret=None`` clears the staged secret."""
        now = time.time() if now is None else now
        async with self._lock:
            await self._db.execute(
                "UPDATE users SET totp_secret=?, updated_at=? WHERE id=?",
                (self._enc(secret), now, user_id),
            )
            await self._db.commit()

    async def get_totp_secret(self, user_id: str) -> str | None:
        """The user's decrypted base32 TOTP secret, or ``None`` when not enrolled/staged."""
        async with self._read() as db:
            cur = await db.execute("SELECT totp_secret FROM users WHERE id=?", (user_id,))
            row = await cur.fetchone()
        return self._dec(row["totp_secret"]) if row else None

    async def enable_totp(
        self, user_id: str, *, recovery_code_hashes: list[str], now: float | None = None
    ) -> None:
        """Activate TOTP for a user (post-confirm), storing the argon2id hashes of their one-time
        recovery codes."""
        now = time.time() if now is None else now
        async with self._lock:
            await self._db.execute(
                "UPDATE users SET totp_enabled=1, totp_enrolled_at=?, totp_recovery_codes=?,"
                " updated_at=? WHERE id=?",
                (now, json.dumps(recovery_code_hashes), now, user_id),
            )
            await self._db.commit()

    async def disable_totp(self, user_id: str, *, now: float | None = None) -> None:
        """Clear a user's TOTP enrollment entirely (secret, enabled flag, recovery codes)."""
        now = time.time() if now is None else now
        async with self._lock:
            await self._db.execute(
                "UPDATE users SET totp_secret=NULL, totp_enabled=0, totp_enrolled_at=NULL,"
                " totp_recovery_codes=NULL, updated_at=? WHERE id=?",
                (now, user_id),
            )
            await self._db.commit()

    async def get_recovery_code_hashes(self, user_id: str) -> list[str]:
        """The user's remaining single-use recovery-code hashes (argon2id), or ``[]``."""
        async with self._read() as db:
            cur = await db.execute("SELECT totp_recovery_codes FROM users WHERE id=?", (user_id,))
            row = await cur.fetchone()
        if not row or row["totp_recovery_codes"] is None:
            return []
        return [str(h) for h in json.loads(row["totp_recovery_codes"])]

    async def consume_recovery_code_hash(
        self, user_id: str, code_hash: str, *, now: float | None = None
    ) -> bool:
        """Atomically remove one recovery-code hash; return ``True`` iff it was present (the caller won
        the race). The re-read + membership check + write all happen under one ``self._lock``, so two
        concurrent verifications can't double-spend a single-use recovery code (WP-14)."""
        now = time.time() if now is None else now
        async with self._lock:
            cur = await self._db.execute(
                "SELECT totp_recovery_codes FROM users WHERE id=?", (user_id,)
            )
            row = await cur.fetchone()
            if not row or row["totp_recovery_codes"] is None:
                return False
            hashes = [str(h) for h in json.loads(row["totp_recovery_codes"])]
            if code_hash not in hashes:
                return False  # already consumed by a concurrent caller
            hashes.remove(code_hash)
            await self._db.execute(
                "UPDATE users SET totp_recovery_codes=?, updated_at=? WHERE id=?",
                (json.dumps(hashes), now, user_id),
            )
            await self._db.commit()
            return True

    async def consume_totp_step(self, user_id: str, step: int) -> bool:
        """Atomically record ``step`` as the user's highest consumed TOTP time-step; return ``True``
        iff it was newly consumed (strictly greater than any previously used step). A captured TOTP
        code replayed inside its ±1-step verify window resolves to a step that is no longer greater
        than the stored ``last_totp_step``, so this returns ``False`` — making each code single-use
        (ASVS 6.5.1). The re-read + compare + write run under one ``self._lock``, so two concurrent
        verifications of the same code can't both win."""
        async with self._lock:
            cur = await self._db.execute("SELECT last_totp_step FROM users WHERE id=?", (user_id,))
            row = await cur.fetchone()
            if row is None:
                return False
            last = row["last_totp_step"]
            if last is not None and last >= step:
                return False  # already consumed (or an older step) — replay within the window
            await self._db.execute("UPDATE users SET last_totp_step=? WHERE id=?", (step, user_id))
            await self._db.commit()
            return True

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
        permissions: str | None = None,
    ) -> None:
        async with self._lock:
            await self._db.execute(
                "INSERT INTO roles (id, display_name, description, builtin, permissions)"
                " VALUES (?,?,?,?,?)"
                " ON CONFLICT(id) DO UPDATE SET display_name=excluded.display_name,"
                " description=excluded.description, builtin=excluded.builtin,"
                " permissions=excluded.permissions",
                (role_id, display_name, description, 1 if builtin else 0, permissions),
            )
            await self._db.commit()

    async def list_roles(self) -> list[aiosqlite.Row]:
        async with self._read() as db:
            cur = await db.execute("SELECT * FROM roles ORDER BY id")
            return list(await cur.fetchall())

    async def get_role(self, role_id: str) -> aiosqlite.Row | None:
        async with self._read() as db:
            cur = await db.execute("SELECT * FROM roles WHERE id=?", (role_id,))
            return await cur.fetchone()

    async def delete_custom_role(self, role_id: str) -> bool:
        """Delete a custom (``builtin=0``) role and any user/AD-group assignments of it in one
        transaction (ADR 0045 D4); never touches a built-in row. Returns ``True`` if a custom role was
        removed. Idempotent."""
        async with self._lock:
            try:
                await self._db.execute("BEGIN")
                cur = await self._db.execute("SELECT builtin FROM roles WHERE id=?", (role_id,))
                row = await cur.fetchone()
                if row is None or int(row["builtin"]) != 0:
                    await self._db.rollback()
                    return False
                await self._db.execute("DELETE FROM user_roles WHERE role_id=?", (role_id,))
                await self._db.execute("DELETE FROM ad_group_role_map WHERE role_id=?", (role_id,))
                await self._db.execute("DELETE FROM roles WHERE id=?", (role_id,))
                await self._db.commit()
                return True
            except Exception:
                await self._db.rollback()
                raise

    async def get_user_role_ids(self, user_id: str) -> list[str]:
        async with self._read() as db:
            cur = await db.execute(
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
        async with self._read() as db:
            cur = await db.execute(
                f"SELECT DISTINCT role_id FROM ad_group_role_map WHERE ad_group IN ({placeholders})",
                tuple(normalized),
            )
            return {str(r["role_id"]) for r in await cur.fetchall()}

    async def list_ad_group_role_map(self) -> list[aiosqlite.Row]:
        async with self._read() as db:
            cur = await db.execute(
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
        async with self._read() as db:
            cur = await db.execute(
                f"SELECT DISTINCT channel FROM ad_group_scope_map WHERE ad_group IN ({placeholders})",
                tuple(normalized),
            )
            return {str(r["channel"]) for r in await cur.fetchall()}

    async def list_ad_group_scope_map(self) -> list[aiosqlite.Row]:
        async with self._read() as db:
            cur = await db.execute(
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
        seed_reauth: bool = True,
        now: float | None = None,
    ) -> None:
        now = time.time() if now is None else now
        async with self._lock:
            await self._db.execute(
                "INSERT INTO sessions (token_hash, user_id, created_at, expires_at, last_used_at,"
                " revoked_at, client, reauth_at) VALUES (?,?,?,?,?,NULL,?,?)",
                # reauth_at = now seeds the step-up window from login (ASVS 7.5.3). seed_reauth=False for
                # an MFA-PENDING session (WP-14) leaves it NULL, so enrollment/step-up needs an explicit
                # password re-verify — a stolen pre-MFA token can't ride the login's step-up freshness.
                (token_hash, user_id, now, expires_at, now, client, now if seed_reauth else None),
            )
            await self._db.commit()

    async def get_session(self, token_hash: str) -> SessionRecord | None:
        async with self._read() as db:
            cur = await db.execute("SELECT * FROM sessions WHERE token_hash=?", (token_hash,))
            row = await cur.fetchone()
        return SessionRecord.from_mapping(dict(row)) if row else None

    async def list_sessions(self, user_id: str, *, now: float | None = None) -> list[SessionRecord]:
        """A user's currently-**active** sessions (not revoked, not expired), most-recently-used
        first — the self-service session inventory (WP-10, ASVS 7.5.2)."""
        now = time.time() if now is None else now
        async with self._read() as db:
            cur = await db.execute(
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

    async def mark_session_reauthed(
        self, token_hash: str, *, now: float | None = None, client: str | None = None
    ) -> None:
        now = time.time() if now is None else now
        async with self._lock:
            # COALESCE keeps the stored client when none is supplied; a re-verify carrying the current
            # address re-anchors the session to it (WP-L3-13 new-client-IP step-up).
            await self._db.execute(
                "UPDATE sessions SET reauth_at=?, client=COALESCE(?, client) WHERE token_hash=?",
                (now, client, token_hash),
            )
            await self._db.commit()

    async def mark_session_mfa_verified(self, token_hash: str, *, now: float | None = None) -> None:
        """Stamp a session's second-factor as satisfied (WP-14): after a TOTP/recovery verify, or at
        issuance for an MFA-delegated AD/Kerberos login."""
        now = time.time() if now is None else now
        async with self._lock:
            await self._db.execute(
                "UPDATE sessions SET mfa_verified_at=? WHERE token_hash=?", (now, token_hash)
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
        """Database health snapshot (size, free space, journal mode, row counts).

        Runs on a pooled read-only connection (lockfree-reads): the dedicated connection has its own
        transaction state, so this can't interleave between a write's ``BEGIN`` and ``commit`` on the
        shared writer (the ``cannot commit - SQL statements in progress`` hazard the load harness hit
        polling ``/status`` during heavy delivery), and it no longer serializes behind the write lock."""
        async with self._read() as db:
            cur = await db.execute("PRAGMA journal_mode")
            row = await cur.fetchone()
            journal = str(row[0]) if row else ""
            return DbStatus(
                path=self.path,
                size_bytes=self._db_size_bytes(),
                disk_free_bytes=self._disk_free_bytes(),
                journal_mode=journal,
                messages=await self._count(db, "messages"),
                events=await self._count(db, "message_events"),
                audit=await self._count(db, "audit_log"),
            )

    async def integrity_check(self) -> tuple[bool, str]:
        """Run ``PRAGMA quick_check`` (can be slow on a large DB — call on demand only). Runs on a
        pooled read-only connection so a long check never blocks the writer (lockfree-reads)."""
        async with self._read() as db:
            cur = await db.execute("PRAGMA quick_check")
            results = [str(r[0]) for r in await cur.fetchall()]
        ok = results == ["ok"]
        return ok, "ok" if ok else "; ".join(results)[:500]

    async def _count(self, db: aiosqlite.Connection, table: str) -> int:
        cur = await db.execute(f"SELECT COUNT(*) AS n FROM {table}")  # table is a constant
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

    async def purge_message_bodies(
        self,
        *,
        older_than: float,
        now: float | None = None,
        connection_cutoffs: Mapping[str, float] | None = None,
    ) -> int:
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
        number of messages whose body was nulled.

        ``connection_cutoffs`` (#34, ADR 0027) is an optional ``{channel_id -> cutoff}`` map of
        per-connection retention overrides: a message received by a connection in the map is purged at
        that connection's own cutoff (``float('-inf')`` = keep forever) instead of the global
        ``older_than``; a connection absent from the map falls back to ``older_than``. Default empty ⇒
        a single global cutoff, byte-identical to the prior behaviour. The per-connection cutoff is
        AND-ed with the unchanged ``NOT EXISTS (pending/inflight)`` in-flight guard, so a body still in
        the pipeline is never purged regardless of its connection's window."""
        now = time.time() if now is None else now
        inflight = (OutboxStatus.PENDING.value, OutboxStatus.INFLIGHT.value)
        # Per-connection cutoff (#34): bare "?" (global) when no override, else a CASE keyed on
        # messages.channel_id. Embedded inside the `eligible` subquery, so its binds lead each UPDATE's
        # params in placeholder order (replacing the single leading `older_than` bind).
        cutoff_sql, cutoff_params = _qmark_cutoff_case(
            "m.channel_id", older_than, connection_cutoffs
        )
        # A message past its (per-connection-or-global) cutoff with nothing still in flight. Embedded in
        # each UPDATE below so the three tables are purged for exactly the same set, in one transaction.
        eligible = (
            f"SELECT id FROM messages m WHERE m.received_at < {cutoff_sql} "
            "AND NOT EXISTS (SELECT 1 FROM queue q WHERE q.message_id = m.id AND q.status IN (?, ?))"
        )
        async with self._lock:
            try:
                await self._db.execute("BEGIN")
                cur = await self._db.execute(
                    f"UPDATE messages SET raw='', summary=NULL, error=NULL "
                    f"WHERE raw <> '' AND id IN ({eligible})",
                    (*cutoff_params, *inflight),
                )
                purged = cur.rowcount
                # store-once: release the shared bodies the eligible delivered/cancelled rows reference
                # (decrement refcount, GC at 0, null body_ref) BEFORE blanking — so a shared body is freed
                # exactly when its last referrer is purged, never orphaned and never kept too long.
                await self._release_outbound_body_refs(
                    "stage=? AND status IN (?, ?) AND body_ref IS NOT NULL "
                    f"AND message_id IN ({eligible})",
                    (
                        Stage.OUTBOUND.value,
                        OutboxStatus.DONE.value,
                        OutboxStatus.CANCELLED.value,
                        *cutoff_params,
                        *inflight,
                    ),
                )
                # Blank the kept (delivered/cancelled) outbound payloads for the same eligible set. Inline
                # bodies have a non-blank payload; a store-once row's payload is already '' and its
                # body_ref was just nulled above, so this UPDATE simply clears its last_error.
                await self._db.execute(
                    f"UPDATE queue SET payload='', last_error=NULL "
                    f"WHERE stage=? AND status IN (?, ?) AND (payload <> '' OR last_error IS NOT NULL) "
                    f"AND message_id IN ({eligible})",
                    (
                        Stage.OUTBOUND.value,
                        OutboxStatus.DONE.value,
                        OutboxStatus.CANCELLED.value,
                        *cutoff_params,
                        *inflight,
                    ),
                )
                await self._db.execute(
                    f"UPDATE message_events SET detail=NULL "
                    f"WHERE detail IS NOT NULL AND message_id IN ({eligible})",
                    (*cutoff_params, *inflight),
                )
                # Captured request/response replies (ADR 0013) are PHI on the same window as the body:
                # null body+detail in place (the row is kept, like messages.raw). The FK to messages(id)
                # is never violated — purge keeps the messages row (Mirth Data-Pruner). Idempotent.
                await self._db.execute(
                    f"UPDATE response SET body=NULL, detail=NULL "
                    f"WHERE (body IS NOT NULL OR detail IS NOT NULL) AND message_id IN ({eligible})",
                    (*cutoff_params, *inflight),
                )
                await self._db.commit()
            except Exception:
                await self._db.rollback()
                raise
        return int(purged)

    async def strip_embedded_documents(
        self,
        *,
        older_than: float,
        now: float | None = None,
        connection_cutoffs: Mapping[str, float] | None = None,
        min_bytes: int = 0,
        content_types: Mapping[str, str] | None = None,
    ) -> StripResult:
        """Strip bulky base64 embedded documents from stored message bodies **in place** (#47, ADR 0042
        D2) — a sibling to :meth:`purge_message_bodies` that, instead of nulling the whole body, replaces
        only each embedded document with a small self-describing tombstone (size + content-type + pruned
        ts) and leaves the surrounding message byte-stable and parseable.

        Both carriage forms are targeted, codec-driven (never raw string-slicing, §8): a whole-body
        ``mfb64:v1:`` carriage value (ADR 0028) and HL7 OBX-5 ED embeds (edited via the parsed model and
        re-encoded). Each stripped message gets its ``documents_pruned`` timestamp set (the distinct
        "evicted vs never present" flag, D4) — orthogonal to ``status`` (no disposition/count changes,
        the row is never deleted). Idempotent: an already-tombstoned body is skipped.

        Eligibility mirrors the purge: a message is a candidate only when it is past its
        per-connection-or-global cutoff AND has **no** queue row still ``pending``/``inflight`` (never
        strip an in-flight body — at-least-once relies on a re-run re-deriving the body). ``min_bytes``
        skips an embed below the size threshold; ``content_types`` (channel_id -> declared content_type)
        labels a bare-mfb64 tombstone. Returns a :class:`StripResult` (counts + bytes reclaimed, no PHI).

        ``connection_cutoffs`` (#34/ADR 0027 plumbing reuse) overrides the cutoff per ``channel_id``
        (``float('-inf')`` = keep forever); empty ⇒ a single global cutoff."""
        now = time.time() if now is None else now
        content_types = content_types or {}
        inflight = (OutboxStatus.PENDING.value, OutboxStatus.INFLIGHT.value)
        # Bound the candidate scan with the LOOSEST finite cutoff (the global one OR the largest override
        # — a keep-forever -inf never widens it). The precise per-connection cutoff is re-checked in
        # Python per row via cutoff_for, so this SQL bound only narrows the set we materialize+decrypt.
        finite = [
            c for c in ([older_than, *(connection_cutoffs or {}).values()]) if c != float("-inf")
        ]
        scan_cutoff = max(finite) if finite else float("-inf")
        rows: list[aiosqlite.Row] = []
        if finite:  # nothing finite ⇒ everything is keep-forever ⇒ no candidate to scan
            async with self._read() as db:
                cur = await db.execute(
                    "SELECT m.id, m.channel_id, m.raw, m.received_at FROM messages m "
                    "WHERE m.raw <> '' AND m.documents_pruned IS NULL AND m.received_at < ? "
                    "AND NOT EXISTS (SELECT 1 FROM queue q WHERE q.message_id = m.id "
                    "AND q.status IN (?, ?))",
                    (scan_cutoff, *inflight),
                )
                rows = list(await cur.fetchall())
        return await self._apply_document_strips(
            rows, now, older_than, connection_cutoffs, min_bytes, content_types
        )

    async def _apply_document_strips(
        self,
        rows: Sequence[aiosqlite.Row],
        now: float,
        older_than: float,
        connection_cutoffs: Mapping[str, float] | None,
        min_bytes: int,
        content_types: Mapping[str, str],
    ) -> StripResult:
        """Codec-transform each candidate row and write back the stripped raw + ``documents_pruned``, in
        one transaction. The per-connection cutoff is re-checked here (cutoff_for) so a row past the loose
        scan bound but NOT past its own (tighter / keep-forever) cutoff is left intact."""
        msgs = 0
        docs = 0
        reclaimed = 0
        updates: list[tuple[str, float, str]] = []
        for row in rows:
            cutoff = cutoff_for(row["channel_id"], older_than, connection_cutoffs)
            if row["received_at"] >= cutoff:
                continue  # not past its own (per-connection) window — skip
            raw = self._cipher.decrypt(row["raw"])
            new_raw, n_docs, n_bytes = _strip_documents(
                raw,
                pruned_at=now,
                min_bytes=min_bytes,
                content_type=content_types.get(row["channel_id"]),
            )
            if n_docs == 0:
                continue  # no embedded document in this body — leave it (and its NULL flag) untouched
            updates.append((self._cipher.encrypt(new_raw), now, row["id"]))
            msgs += 1
            docs += n_docs
            reclaimed += n_bytes
        if updates:
            async with self._lock:
                try:
                    await self._db.execute("BEGIN")
                    await self._db.executemany(
                        "UPDATE messages SET raw=?, documents_pruned=? WHERE id=?", updates
                    )
                    await self._db.commit()
                except Exception:
                    await self._db.rollback()
                    raise
        return StripResult(
            messages_stripped=msgs, documents_stripped=docs, bytes_reclaimed=reclaimed
        )

    async def purge_connection_events(self, *, older_than: float, now: float | None = None) -> int:
        # #46: connection events are metadata-only (no body to null, no FK), so they are age-DELETEd on
        # their own window (driven by the RetentionRunner). A single short transaction.
        async with self._lock:
            cur = await self._db.execute("DELETE FROM connection_event WHERE ts < ?", (older_than,))
            await self._db.commit()
            return int(cur.rowcount)

    async def purge_dead_letters(
        self,
        *,
        older_than: float,
        now: float | None = None,
        connection_cutoffs: Mapping[str, float] | None = None,
    ) -> int:
        """Null the bodies of dead-lettered **outbound** rows last updated before ``older_than`` —
        their own retention window, separate from :meth:`purge_message_bodies` because a dead row stays
        replayable (re-queueing its stored ``payload``) until purged. Keeps the row + ``dead`` status
        (counts/disposition intact) and blanks ``payload`` + ``last_error``; after this the row can no
        longer be meaningfully replayed (its body is gone — the intended retention trade-off).
        Idempotent (guards on a non-blank payload); returns the number of dead rows purged.

        ``connection_cutoffs`` (#34, ADR 0027) is an optional ``{destination_name -> cutoff}`` map of
        per-connection overrides: a dead row is purged at its outbound's own cutoff (``float('-inf')`` =
        keep forever) instead of the global ``older_than``; an outbound absent from the map falls back to
        ``older_than``. Default empty ⇒ a single global cutoff, byte-identical to the prior behaviour."""
        now = time.time() if now is None else now
        cutoff_sql, cutoff_params = _qmark_cutoff_case(
            "destination_name", older_than, connection_cutoffs
        )
        async with self._lock:
            try:
                await self._db.execute("BEGIN")
                # store-once: release shared bodies these dead rows reference (refcount-/GC/null body_ref)
                # before blanking, so a shared body outlives its last dead referrer no longer than this.
                await self._release_outbound_body_refs(
                    f"stage=? AND status=? AND body_ref IS NOT NULL AND updated_at < {cutoff_sql}",
                    (Stage.OUTBOUND.value, OutboxStatus.DEAD.value, *cutoff_params),
                )
                cur = await self._db.execute(
                    "UPDATE queue SET payload='', last_error=NULL "
                    "WHERE stage=? AND status=? AND (payload <> '' OR last_error IS NOT NULL) "
                    f"AND updated_at < {cutoff_sql}",
                    (Stage.OUTBOUND.value, OutboxStatus.DEAD.value, *cutoff_params),
                )
                await self._db.commit()
            except Exception:
                await self._db.rollback()
                raise
            return int(cur.rowcount)

    async def purge_state(self, *, older_than: float, now: float | None = None) -> int:
        """Delete transform-state entries last written before ``older_than`` (ADR 0005 retention).

        Unlike the body purges, this **removes the row** (state is correlation data, not a logged
        message with counts/disposition to preserve) and drops it from the in-memory read cache after
        the commit succeeds, so a later ``state_get`` reflects the purge. A simple global age purge (by
        ``set_at``); per-namespace policy is a documented follow-up. Returns the number of entries
        purged. Off by default — the RetentionRunner calls it only when ``state_max_age_days`` is set."""
        now = time.time() if now is None else now
        async with self._lock:
            cur = await self._db.execute(
                "SELECT namespace, key FROM state WHERE set_at < ?", (older_than,)
            )
            purged_keys = [(r["namespace"], r["key"]) for r in await cur.fetchall()]
            if not purged_keys:
                return 0
            await self._db.execute("DELETE FROM state WHERE set_at < ?", (older_than,))
            await self._db.commit()
        # Commit succeeded → evict the purged keys from the read-through cache (after commit, mirroring
        # the write path: the table is the source of truth, the cache follows it only once durable).
        for ck in purged_keys:
            self._state_cache.pop(ck, None)
        return len(purged_keys)

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

    async def snapshot_to(self, dest_path: str | Path, *, method: str = "vacuum_into") -> None:
        """Write a consistent single-file snapshot of the store to ``dest_path`` for the DR backup
        (ADR 0049). **Non-mutating + read-only against the staged queue**: it checkpoints the WAL then
        copies the DB *as it is* — it never claims/mutates/resets/completes/dead-letters a queue row, and
        never touches the leader lease or audit chain. The result is a single file with no ``-wal``/
        ``-shm`` sidecars (on restore, the startup ``reset_stale_inflight`` + pure-stage replay recover
        any in-flight rows — at-least-once spans the restore).

        ``method``:

        * ``"vacuum_into"`` (default) — ``VACUUM INTO`` on the **writer** connection under the store
          lock (it is a WRITE statement and cannot run on a ``query_only`` read connection). It contends
          the store write lock for its duration, exactly like :meth:`vacuum`, so the BackupRunner must
          schedule it OFF-PEAK (mandatory, not advisory). Produces a fresh, fully-checkpointed,
          defragmented copy.
        * ``"online_backup"`` — SQLite's Online Backup API (``Connection.backup``), which copies pages
          incrementally and yields between batches, so it does NOT hold the write lock for the whole
          copy. The low-contention option for a large/busy store.

        ``VACUUM INTO`` and the Online Backup API both run on the aiosqlite connection's own worker
        thread (off the event loop). Refuses an existing destination file (a stale ``-wal``/``-shm`` next
        to it would corrupt the copy) and an in-memory store (nothing to snapshot)."""
        if self.path == ":memory:":
            raise ValueError("cannot snapshot an in-memory store (no file to copy)")
        dest = Path(dest_path)
        if dest.exists():
            raise FileExistsError(f"snapshot destination already exists: {dest}")
        if method not in ("vacuum_into", "online_backup"):
            raise ValueError(
                f"unknown snapshot method {method!r}; expected 'vacuum_into' or 'online_backup'"
            )
        async with self._lock:
            # Fold the latest committed WAL frames into the main DB so the snapshot is point-in-time and
            # the -wal sidecar is empty. Commit first so no open transaction blocks the checkpoint, and
            # fully drain the PRAGMA's result cursor (an open cursor would leave "SQL statements in
            # progress" and abort the VACUUM INTO below).
            await self._db.commit()
            cur = await self._db.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            await cur.fetchall()
            await cur.close()
            if method == "vacuum_into":
                # VACUUM INTO is a WRITE statement on the writer connection; it cannot run inside a
                # transaction or with another statement in progress. Parameter-bound so the path can't
                # inject. Holds the write lock for its duration (off-peak scheduling is the caller's job).
                await self._db.commit()
                await self._db.execute("VACUUM INTO ?", (str(dest),))
            else:
                # SQLite Online Backup API: open a fresh destination connection and copy pages into it,
                # page-batched + yielding, then close it. aiosqlite.Connection.backup runs the underlying
                # sqlite3 backup on the source connection's worker thread (off the event loop).
                target = await aiosqlite.connect(str(dest))
                try:
                    await self._db.backup(target)
                finally:
                    await target.close()
        # Tighten the snapshot file's permissions: it is a full copy of the (PHI-bearing) store. The
        # encrypted .mfbak the BackupRunner wraps it in is the at-rest protection, but the transient
        # plaintext snapshot must not be world-readable either.
        _secure_file(dest)

    async def stats(self) -> dict[str, int]:
        """Outbound-queue depth by status — feeds the monitoring/queue-depth view. Scoped to outbound
        rows so the numbers match the pre-staged-pipeline meaning (delivery backlog). Runs on a pooled
        read-only connection (lockfree-reads) — no write lock, no mid-write interleave (see
        :meth:`db_status`)."""
        async with self._read() as db:
            cur = await db.execute(
                "SELECT status, COUNT(*) AS n FROM queue WHERE stage=? GROUP BY status",
                (Stage.OUTBOUND.value,),
            )
            return {r["status"]: r["n"] for r in await cur.fetchall()}

    async def in_pipeline_depth(self) -> int:
        """NOT-DONE rows (``pending``|``inflight``) across **every** stage — the whole-pipeline drain
        gauge. Runs on a pooled read-only connection (lockfree-reads; see :meth:`stats`)."""
        async with self._read() as db:
            cur = await db.execute(
                "SELECT COUNT(*) AS n FROM queue WHERE stage IN (?,?,?) AND status IN (?,?)",
                (
                    Stage.INGRESS.value,
                    Stage.ROUTED.value,
                    Stage.OUTBOUND.value,
                    OutboxStatus.PENDING.value,
                    OutboxStatus.INFLIGHT.value,
                ),
            )
            row = await cur.fetchone()
            return int(row["n"]) if row else 0

    async def connection_metrics(
        self, *, since: float, now: float | None = None, rate_window: float = 60.0
    ) -> ConnectionMetrics:
        """Aggregate per-channel inbound and per-destination outbound metrics for the
        connections dashboard. Counts (read/errored/written/dead) cover activity at or after
        ``since`` (engine start); queue depth and ages reflect current state; ``recent_done``
        is completions within the last ``rate_window`` seconds (for backlog ETA). Runs on a pooled
        read-only connection (lockfree-reads; see :meth:`db_status`) — its single read transaction
        gives all three aggregate queries one consistent WAL snapshot, concurrent with the writer."""
        async with self._read() as db:
            return await self._collect_connection_metrics(
                db, since=since, now=now, rate_window=rate_window
            )

    async def _collect_connection_metrics(
        self,
        db: aiosqlite.Connection,
        *,
        since: float,
        now: float | None = None,
        rate_window: float = 60.0,
    ) -> ConnectionMetrics:
        now = time.time() if now is None else now
        rate_since = now - rate_window

        # Inbound counts since `since`, plus all-time last-received (for idle time).
        cur = await db.execute(
            "SELECT channel_id, COUNT(*) AS read,"
            " SUM(CASE WHEN status=? THEN 1 ELSE 0 END) AS errored"
            " FROM messages WHERE received_at>=? GROUP BY channel_id",
            (MessageStatus.ERROR.value, since),
        )
        counts = {r["channel_id"]: (r["read"], r["errored"]) for r in await cur.fetchall()}
        cur = await db.execute(
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

        cur = await db.execute(
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

    async def delivery_latency_histogram(
        self, *, buckets: Sequence[float], now: float | None = None
    ) -> Sequence[LatencyHistogram]:
        """Per-(channel_id, destination_name) delivery-latency histogram over outbound rows that
        reached status='done'. Latency = updated_at - created_at (seconds), clamped to >= 0 (clock-
        skew guard). bucket_counts are CUMULATIVE (Prometheus le semantics). Read-only; runs off the
        event loop on a pooled read-only connection (lockfree-reads; see :meth:`stats`)."""
        # Only the NUMBER of CASE clauses (len(buckets)) is generated; each boundary is a BOUND
        # parameter (never string-interpolated), so this is injection-safe and the count is
        # caller-fixed, not attacker-controlled.
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
        async with self._read() as db:
            cur = await db.execute(sql, params)
            rows = await cur.fetchall()
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

    # --- internals -----------------------------------------------------------

    async def _row(self, outbox_id: str) -> aiosqlite.Row | None:
        cur = await self._db.execute("SELECT * FROM queue WHERE id=?", (outbox_id,))
        return await cur.fetchone()

    async def _event(
        self, message_id: str, event: str, destination: str | None, detail: str, now: float
    ) -> None:
        detail = safe_text(detail) if detail else detail  # PHI chokepoint (#120)
        await self._db.execute(
            "INSERT INTO message_events (message_id, ts, event, destination, detail)"
            " VALUES (?,?,?,?,?)",
            (message_id, now, event, destination, self._enc(detail)),
        )

    async def _record_delivered_key(
        self,
        *,
        outbox_id: str,
        message_id: str,
        destination_name: str | None,
        handler_name: str | None,
        now: float,
    ) -> None:
        """Write the H2 idempotency-ledger row for one just-completed outbound delivery, **inside the
        caller's open transaction** (so it commits or rolls back atomically with the ``mark_done`` /
        ``complete_with_response`` it accompanies — no second store, no post-delivery side effect).

        Only outbound rows deliver; ingress/routed rows (``destination_name`` NULL) own no external send
        and are skipped. ``delivery_seq`` is ``1 + COUNT`` of this row's prior ledger entries for the
        ``(message_id, destination_name)`` pair — the same replay-stable counter shape as
        ``response_seq``. The stored row carries hashes + ids only — never a body/PHI. The INSERT keys on
        the content hash; a re-run that reaches here only after the prior completion rolled back finds
        ``COUNT=0`` again and re-derives the same key (idempotent), while the claim-time skip
        (:meth:`claim_next_fifo`) is what actually prevents the duplicate *send*."""
        if destination_name is None:
            return  # ingress/routed completions own no external delivery — nothing to dedupe
        # One ledger row per outbox row INSTANCE: a double mark_done of the same row (a re-completion, a
        # belt-and-suspenders re-call) must not accumulate a second entry. A deliberate replay re-send
        # DELETEs this row's entry first, so its re-delivery is recorded fresh (a new, higher seq).
        cur = await self._db.execute(
            "SELECT 1 FROM delivered_keys WHERE outbox_id=? LIMIT 1", (outbox_id,)
        )
        if await cur.fetchone() is not None:
            return
        cur = await self._db.execute("SELECT control_id FROM messages WHERE id=?", (message_id,))
        m = await cur.fetchone()
        control_id = m["control_id"] if m is not None else None
        cur = await self._db.execute(
            "SELECT COUNT(*) AS n FROM delivered_keys WHERE message_id=? AND destination_name=?",
            (message_id, destination_name),
        )
        seq_row = await cur.fetchone()
        seq = (int(seq_row["n"]) if seq_row else 0) + 1
        key = delivery_key(
            control_id=control_id,
            message_id=message_id,
            destination_name=destination_name,
            handler_name=handler_name,
            delivery_seq=seq,
        )
        await self._db.execute(
            "INSERT OR IGNORE INTO delivered_keys"
            " (delivery_key, outbox_id, message_id, destination_name, delivery_seq, delivered_at)"
            " VALUES (?,?,?,?,?,?)",
            (key, outbox_id, message_id, destination_name, seq, now),
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
