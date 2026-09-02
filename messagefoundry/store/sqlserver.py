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

H-8 LOCK ORDERING (multi-message finalizers). :meth:`_maybe_finalize` takes a per-message finalize
lock, so any primitive that finalizes MORE THAN ONE message in a single transaction holds N of them
at once and MUST acquire them in CANONICAL (sorted) message_id order — otherwise two such callers
with overlapping id sets can take the same two locks in opposite orders and deadlock (SQL Server
1205). ``cancel_queued`` and the dead-letter sweeps do this via :meth:`_lock_finalize_batch`;
``claim_fifo_heads``' H2 sorts its own. The ADR 0082 batch primitives (:meth:`mark_batch_done`,
:meth:`mark_batch_failed`, :meth:`dead_letter_batch`) are ALSO multi-message finalizers — they
originally iterated their finalize dict in *insertion* (caller ``outbox_ids``) order, which is a real
cycle: a fan-out message has one outbound row per destination and each destination lane batches
independently, so overlapping id sets are reachable in normal operation. They now sort.
**Adding a new multi-message finalizer? Sort, or use _lock_finalize_batch.**
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import inspect
import json
import logging
import queue
import time
from collections.abc import (
    AsyncIterator,
    Callable,
    Collection,
    Iterable,
    Iterator,
    Mapping,
    Sequence,
)
from concurrent.futures import ThreadPoolExecutor
from contextlib import AsyncExitStack, asynccontextmanager, contextmanager
from time import perf_counter
from types import MappingProxyType
from typing import Any, Final
from uuid import uuid4

from messagefoundry.config.models import RetryPolicy
from messagefoundry.config.settings import (
    INSECURE_TLS_ESCAPE_ENV,
    SqlAuth,
    StoreBackend,
    StoreSettings,
    weakened_tls_escape_permitted,
)
from messagefoundry.config.tls_policy import HopPosture
from messagefoundry.parsing.binary import strip_documents as _strip_documents
from messagefoundry.redaction import safe_text
from messagefoundry.store.audit_tee import emit_audit_tee
from messagefoundry.store.base import (
    UPLOAD_RESERVATION_STALE_AFTER,
    acquire_pooled,
    warm_pool_connections,
    warm_pool_target,
)
from messagefoundry.store.content_search import SearchSpec, row_matches
from messagefoundry.store.crypto import MARKER_PREFIX as _ENC_MARKER_PREFIX
from messagefoundry.store.crypto import (
    AesGcmCipher,
    AuditMacFn,
    Cipher,
    CipherError,
    CipherInfo,
    IdentityCipher,
    cell_aad,
    cipher_info,
    decrypt_json_cell,
    rotation_fingerprint_key,
)
from messagefoundry.store.document_strip import StripResult, cutoff_for
from messagefoundry.store.gcm_bound import checkpoint_invocations
from messagefoundry.store.metadata import (
    decode_response_headers,
    encode_reference_value,
    encode_response_headers,
    merge_user_metadata,
)
from messagefoundry.store.pool_metrics import AcquireWaitHistogram, ClaimPoolStatus, PoolStatus
from messagefoundry.store.store import (
    MESSAGE_EVENT_KINDS,
    NOT_DEPLOYED_EVENT,
    REINGRESS_TARGET_PREFIX,
    AlertInstance,
    CapturedResponse,
    ClaimAbortPhase,
    ClaimedHeads,
    ClaimLockTimeout,
    ClaimProcStatus,
    ConnectionEvent,
    ConnectionMetrics,
    DbStatus,
    DestinationMetrics,
    InboundMetrics,
    LatencyHistogram,
    MessageSearchResult,
    MessageStatus,
    MessageStore,
    OutboxItem,
    OutboxStatus,
    OwnedLanes,
    ReingressOriginMissing,
    ReingressOutcome,
    ReplyWaitState,
    ResendKeyConflict,
    ResendOutcome,
    ResendSourceAmbiguous,
    ResendSourceEmpty,
    ResendSourceNotFound,
    SecretRotationMetaRow,
    SessionRecord,
    Stage,
    UserRecord,
    WebAuthnCredential,
    _append_channel_scope,
    _qmark_cutoff_case,
    audit_mac_bytes,
    audit_row_hash,
    delivery_key,
    not_deployed_detail,
    owned_lane_scope,
    password_claim_set,
    should_record_event,
)

log = logging.getLogger(__name__)

# ADR 0066 §3.3: claim_fifo_heads lane-chunk clamp. Lane names are the only per-lane parameters (row
# ids live in table variables and never travel as parameters), so pyodbc's ~2,100-parameter bound is
# never approached; the clamp still bounds the VALUES list + per-txn row U-locks defensively.
_FIFO_HEADS_LANE_CHUNK = 500
# ADR 0066 §3.1: release_claimed id-chunk bound (ids per UPDATE statement).
_RELEASE_CHUNK = 500
# ADR 0073: ownership-scoped reset lane-chunk bound (lane names per UPDATE's IN list) — well under
# pyodbc's ~2,100-parameter bound with the fixed parameters; chunks run inside the reset's single
# transaction, so the all-or-nothing recovery pass is unchanged.
_RESET_LANE_CHUNK = 500

# BACKLOG #348 / ADR 0159: how long the quarantine of a cancellation-poisoned pooled connection waits
# for its off-loop close before giving up and leaving it to finish detached. A BOUND, not a deadline:
# the connection is already out of the pool before this wait starts, so expiring it costs nothing but
# a slower reclaim. It exists because the close runs on a worker thread that may still be occupied by
# the abandoned statement, which is bounded only by command_timeout (default 30s) — without a cap here
# an engine.stop()/demotion would block for that long, per lane.
_DIRTY_CLOSE_TIMEOUT = 5.0

# SQL Server native error 1222 = "Lock request time out period exceeded" — raised by SET LOCK_TIMEOUT 0
# in the pooled claim (ADR 0066 §9) when a probe cannot IMMEDIATELY acquire a contended head lock. It is
# the normal "head is contended, yield" signal, not an error, so it maps to the EMPTY-all fail-closed
# contract (see claim_fifo_heads). pyodbc surfaces the native code in the exception args (the ODBC
# diagnostic message embeds "(1222)"); match on the code without pinning to a specific SQLSTATE.
_LOCK_TIMEOUT_NATIVE_ERROR = 1222


def _is_lock_timeout(exc: BaseException) -> bool:
    """True iff ``exc`` is a SQL Server lock-request timeout (native error 1222).

    pyodbc raises ``pyodbc.Error`` (subclass) whose ``args`` are ``(sqlstate, message)``; the ODBC
    driver embeds the SQL Server native code in the message text (``... (1222) ...``). We match on the
    code substring rather than importing pyodbc (lazy extra) or pinning a SQLSTATE — the code is the
    stable identifier across driver versions."""
    return f"({_LOCK_TIMEOUT_NATIVE_ERROR})" in str(exc)


# The lane column is NVARCHAR(256); a longer requested lane name can never match a real lane. On
# the ADR 0114 proc path the lane list rides one JSON parameter through a server-side CAST — a
# TRUNCATING cast could make an oversized name's prefix match a REAL lane, a shard-safety contract
# break (the lane set is always explicit, base.py). So the client SKIPS oversized names loudly
# before json.dumps, preserving no-match parity (AC-11). The limit is 256 UTF-16 CODE UNITS —
# NVARCHAR capacity, NOT Python code points: a 200-emoji name is 200 code points but 400 code
# units, and CAST silently right-truncates at 256 units (possibly mid-surrogate), which is exactly
# the prefix-match hazard the skip exists to kill.
_CLAIM_PROC_LANE_MAX = 256


def _utf16_units(text: str) -> int:
    """The NVARCHAR length of ``text``: UTF-16 code units (astral chars count 2)."""
    return len(text.encode("utf-16-le")) // 2


def _keep_matchable_lanes(lanes: Sequence[str]) -> list[str]:
    """Drop requested lane names that exceed the NVARCHAR(256) lane column (AC-11).

    Such a lane can never equal a stored lane, so skipping it client-side is a pure no-op on the
    RESULT — but it is NOT optional, and it must run for EVERY dispatch path. The ad-hoc batch
    binds the lane list into a ``(VALUES (?),…)`` derived table that lands in a
    ``DECLARE @heads TABLE (lane NVARCHAR(256) NOT NULL`` — SQL Server evaluates that narrowing
    conversion on the outer constant scan BEFORE the CROSS APPLY filters it, and with ANSI_WARNINGS
    ON it raises 2628 ("String or binary data would be truncated") even when zero rows would have
    matched. So an unfiltered oversized lane makes the batch RAISE where the contract says it must
    claim nothing — no-match parity broken, and 2628 is not 1222 so it is not translated to
    EMPTY-all either: it rolls back and re-raises to the dispatcher.

    Applied once in ``claim_fifo_heads`` ahead of the dispatch-path split, so the proc, prepared and
    batch branches cannot disagree. (Before this, only the two flagged branches filtered, via
    ``_encode_proc_lanes`` — and the gap was unreachable in practice only because sub-lever A's
    startup gate never passed, so the parity test never reached its batch arm.)"""
    kept = []
    for lane in lanes:
        units = _utf16_units(lane)
        if units > _CLAIM_PROC_LANE_MAX:
            log.warning(
                "claim_fifo_heads: skipping %d-UTF-16-unit requested lane name (exceeds the"
                " NVARCHAR(%d) lane column — it can never match a real lane): %.64s…",
                units,
                _CLAIM_PROC_LANE_MAX,
                lane,
            )
            continue
        kept.append(lane)
    return kept


def _encode_proc_lanes(lanes: Sequence[str]) -> str:
    """Encode the (deduped, filtered, chunk-clamped) lane list as the proc's one JSON-array
    parameter. ``json.dumps`` default escaping — no delimiter contract is ever imposed on
    connection names. Oversized lanes are removed upstream by ``_keep_matchable_lanes``; the call
    here is idempotent and kept so this encoder is safe to use on an unfiltered list."""
    return json.dumps(_keep_matchable_lanes(lanes))


def _claim_proc_param_pins() -> list[tuple[int, int, int]]:
    """The 9 fixed parameter-descriptor pins for the claim procs' ``{CALL}``, in signature order
    (ADR 0114 §4): @now FLOAT, @stage NVARCHAR(16), @k INT, @pending/@inflight NVARCHAR(32),
    @lanes NVARCHAR(MAX), @lease_key NVARCHAR(256), @leader_epoch BIGINT, @fold_reset BIT.
    Lazy-imports pyodbc (the ``sqlserver`` extra) — called only on the gated proc path."""
    import pyodbc

    return [
        (pyodbc.SQL_DOUBLE, 0, 0),  # @now FLOAT (T-SQL FLOAT = 8-byte double)
        (pyodbc.SQL_WVARCHAR, 16, 0),  # @stage
        (pyodbc.SQL_INTEGER, 0, 0),  # @k
        (pyodbc.SQL_WVARCHAR, 32, 0),  # @pending
        (pyodbc.SQL_WVARCHAR, 32, 0),  # @inflight
        (pyodbc.SQL_WVARCHAR, 0, 0),  # @lanes NVARCHAR(MAX) (0 = MAX)
        (pyodbc.SQL_WVARCHAR, 256, 0),  # @lease_key (nullable — the pin defeats describe fallback)
        (pyodbc.SQL_BIGINT, 0, 0),  # @leader_epoch (nullable — ditto)
        (pyodbc.SQL_BIT, 0, 0),  # @fold_reset
    ]


# --- ADR 0071 B5 PR1: hoisted handoff SQL + pure param-builders (async/sync shared) --------------
#
# The staged-handoff SQL literals and their param tuples are hoisted to module scope so the async
# handoffs (route_handoff / transform_handoff + their helpers) AND the synchronous fused-hop twins
# (route_handoff_sync / transform_handoff_sync) emit the *identical* (sql, params) sequence for
# identical inputs — the anti-drift guarantee that lets a fused worker-thread hop (ADR 0071 §5.1) run a
# whole multi-statement handoff as ONE executor completion without diverging from the profiled async
# path. Both the async methods and the sync twins reference these same constants + builders; nothing
# below encrypts or generates ids (those stay in the methods, so the builders are pure and unit-
# testable). The builders take already-resolved values (row ids, ciphertext, epoch, enum ``.value``s).

_SQL_DELETE_GUARD: Final[str] = (
    "DELETE FROM queue OUTPUT deleted.id WHERE id=? AND stage=? AND status=?"
)
_SQL_INSERT_QUEUE_ROUTED: Final[str] = (
    "INSERT INTO queue (id, message_id, stage, channel_id, destination_name, handler_name,"
    " payload, status, attempts, next_attempt_at, owner, lease_expires_at, created_at,"
    " updated_at) VALUES (?,?,?,?,NULL,?,?,?,0,?,NULL,NULL,?,?)"
)
_SQL_INSERT_QUEUE_OUTBOUND: Final[str] = (
    "INSERT INTO queue (id, message_id, stage, channel_id, destination_name, handler_name,"
    " payload, status, attempts, next_attempt_at, owner, lease_expires_at, created_at,"
    " updated_at) VALUES (?,?,?,?,?,NULL,?,?,0,?,NULL,NULL,?,?)"
)
_SQL_INSERT_QUEUE_INGRESS: Final[str] = (
    "INSERT INTO queue (id, message_id, stage, channel_id, destination_name,"
    " handler_name, payload, status, attempts, next_attempt_at, owner,"
    " lease_expires_at, created_at, updated_at)"
    " VALUES (?,?,?,?,NULL,NULL,?,?,0,?,NULL,NULL,?,?)"
)
_SQL_INSERT_MESSAGE: Final[str] = (
    "INSERT INTO messages (id, channel_id, received_at, source_type, control_id,"
    " message_type, raw, status, error, summary, metadata)"
    " VALUES (?,?,?,?,?,?,?,?,?,?,?)"
)
_SQL_APPLOCK: Final[str] = (
    "SET NOCOUNT ON;"
    " DECLARE @rc INT;"
    " EXEC @rc = sp_getapplock @Resource=?, @LockMode='Exclusive',"
    " @LockOwner='Transaction', @LockTimeout=?;"
    " SELECT @rc"
)
_SQL_INSERT_EVENT: Final[str] = (
    "INSERT INTO message_events (message_id, ts, event, destination, detail) VALUES (?,?,?,?,?)"
)
_SQL_FINALIZE_COUNT: Final[str] = (
    "SELECT stage, status, COUNT(*) AS n FROM queue WHERE message_id=? GROUP BY stage, status"
)
# The finalizer's no-queue-rows read: the message's status AND (#233, ADR 0111) whether it carries a
# not_deployed event, folded into ONE round-trip via a correlated EXISTS so the FILTERED-branch read
# count is unchanged (the ADR 0075 round-trip gate pins it). Column 0 = status; column 1 = 1/0 flag.
# Params: (not_deployed event name, message id). A 0-flag row is byte-identical in effect to the old
# status-only read → FILTERED; a 1-flag row → NOT_DEPLOYED.
_SQL_SELECT_MESSAGE_STATUS: Final[str] = (
    "SELECT m.status,"
    " CASE WHEN EXISTS (SELECT 1 FROM message_events e"
    " WHERE e.message_id = m.id AND e.event = ?) THEN 1 ELSE 0 END"
    " FROM messages m WHERE m.id = ?"
)
_SQL_UPDATE_MESSAGE_STATUS: Final[str] = "UPDATE messages SET status=? WHERE id=?"
_SQL_SELECT_MESSAGE_EXISTS: Final[str] = "SELECT 1 FROM messages WHERE id=?"
_SQL_SELECT_METADATA: Final[str] = "SELECT metadata FROM messages WHERE id=?"
_SQL_UPDATE_METADATA: Final[str] = (
    "UPDATE messages SET metadata=? WHERE id=?"  # SetMeta merge (#150)
)
_SQL_STATE_MERGE: Final[str] = (
    "MERGE state WITH (HOLDLOCK) AS t"
    " USING (SELECT ? AS namespace, ? AS [key]) AS s"
    " ON t.namespace=s.namespace AND t.[key]=s.[key]"
    " WHEN MATCHED THEN UPDATE SET value=?, set_at=?, message_id=?"
    " WHEN NOT MATCHED THEN INSERT (namespace, [key], value, set_at, message_id)"
    " VALUES (?,?,?,?,?);"
)


def _applock_timeout_ms(command_timeout: int) -> int:
    """``@LockTimeout`` (ms) for :data:`_SQL_APPLOCK`: ``command_timeout*1000`` when set, else ``-1``
    (wait forever, the pyodbc query timeout backstops). ``0`` -> ``-1`` is why the SYNC handoff pool
    REFUSES to build when ``command_timeout==0`` (ADR 0071 invariant: a fused hop must never wait
    unboundedly on the applock)."""
    return int(command_timeout * 1000) if command_timeout else -1


def _applock_params(resource: str, timeout_ms: int) -> tuple[Any, ...]:
    return (resource, timeout_ms)


def _applock_result(row: Any, resource: str) -> None:
    """Raise on a negative ``sp_getapplock`` return code (timeout/cancel/deadlock/bad-param) rather than
    proceeding unserialized — a swallowed timeout would fork the audit chain or double-finalize."""
    rc = int(row[0]) if row and row[0] is not None else -999
    if rc < 0:  # -1 timeout, -2 cancelled, -3 deadlock victim, -999 bad param
        raise RuntimeError(f"sp_getapplock({resource!r}) failed: rc={rc}")


def _delete_guard_params(row_id: str, stage: str, status: str) -> tuple[Any, ...]:
    return (row_id, stage, status)


def _insert_routed_params(
    row_id: str, message_id: str, channel_id: str, handler_name: str, enc_payload: str, now: float
) -> tuple[Any, ...]:
    # next_attempt_at / created_at / updated_at all == now (ADR 0009 ingest-time; per-lane FIFO orders
    # by the seq IDENTITY, ADR 0059).
    return (
        row_id,
        message_id,
        Stage.ROUTED.value,
        channel_id,
        handler_name,
        enc_payload,
        OutboxStatus.PENDING.value,
        now,
        now,
        now,
    )


def _insert_outbound_params(
    row_id: str, message_id: str, channel_id: str, dest_name: str, enc_payload: str, now: float
) -> tuple[Any, ...]:
    return (
        row_id,
        message_id,
        Stage.OUTBOUND.value,
        channel_id,
        dest_name,
        enc_payload,
        OutboxStatus.PENDING.value,
        now,
        now,
        now,
    )


def _insert_queue_ingress_params(
    row_id: str, message_id: str, channel_id: str, enc_payload: str, now: float
) -> tuple[Any, ...]:
    return (
        row_id,
        message_id,
        Stage.INGRESS.value,
        channel_id,
        enc_payload,
        OutboxStatus.PENDING.value,
        now,
        now,
        now,
    )


def _insert_marker_params(
    row_id: str, parent_id: str, pt_name: str, enc_body: str, status: str, now: float
) -> tuple[Any, ...]:
    # The PT parent-marker row: an ALREADY-TERMINAL outbound-shaped row (lane = the PT inbound name),
    # never claimed. Reuses :data:`_SQL_INSERT_QUEUE_OUTBOUND` but carries its own terminal ``status``
    # (DONE when the child was produced, DEAD on a depth-cap breach) rather than PENDING.
    return (
        row_id,
        parent_id,
        Stage.OUTBOUND.value,
        pt_name,
        pt_name,
        enc_body,
        status,
        now,
        now,
        now,
    )


def _insert_message_params(
    message_id: str,
    channel_id: str,
    now: float,
    source_type: str | None,
    control_id: str | None,
    message_type: str | None,
    enc_raw: str,
    status: str,
    error: str | None,
    enc_summary: str | None,
    enc_metadata: str | None,
) -> tuple[Any, ...]:
    return (
        message_id,
        channel_id,
        now,
        source_type,
        control_id,
        message_type,
        enc_raw,
        status,
        error,
        enc_summary,
        enc_metadata,
    )


def _event_params(
    message_id: str, now: float, event: str, destination: str | None, enc_detail: str | None
) -> tuple[Any, ...]:
    return (message_id, now, event, destination, enc_detail)


def _passthrough_child_meta(parent_id: str, root: str, child_depth: int) -> str:
    """The PT child's ``metadata`` JSON (ADR 0013 correlation lineage) — deterministic given inputs, so
    the async + sync passthrough twins produce identical child metadata before encryption."""
    return json.dumps(
        {
            "correlation_id": parent_id,
            "correlation_root_id": root,
            "correlation_depth": child_depth,
            "passthrough_from": parent_id,
        }
    )


def _update_message_status_params(status: str, message_id: str) -> tuple[Any, ...]:
    return (status, message_id)


def _state_merge_params(
    namespace: str, key: str, enc: str, now: float, message_id: str
) -> tuple[Any, ...]:
    return (namespace, key, enc, now, message_id, namespace, key, enc, now, message_id)


def _finalize_from_queue_rows(rows: Sequence[Any]) -> tuple[str, str | None]:
    """Pure finalize precedence over the per-message ``queue`` GROUP BY rows (``(stage, status, n)``).

    Returns ``(action, status)`` where action is ``"return"`` (still moving / leave as-is),
    ``"update"`` (set ``messages.status`` to ``status``), or ``"check_message"`` (no queue rows remain
    -> the caller must read ``messages.status`` to decide FILTERED vs leave). Shared by the async and
    sync finalizer twins so the precedence can never drift between them."""
    statuses = {r[1] for r in rows}
    if OutboxStatus.PENDING.value in statuses or OutboxStatus.INFLIGHT.value in statuses:
        return ("return", None)  # still moving through a stage
    if OutboxStatus.DEAD.value in statuses:
        return ("update", MessageStatus.ERROR.value)
    if any(r[0] == Stage.OUTBOUND.value for r in rows):
        return ("update", MessageStatus.PROCESSED.value)
    if not rows:
        return ("check_message", None)
    return ("return", None)  # rows exist but all terminal, non-dead, non-outbound — leave (rare)


def _finalize_from_message_status(mrows: Sequence[Any]) -> tuple[str, str | None]:
    """FILTERED only if the message was actually ROUTED; never clobber UNROUTED / ERROR / terminal.

    ``mrows`` is the one-row result of :data:`_SQL_SELECT_MESSAGE_STATUS`: column 0 = status, column 1
    = the #233 not_deployed flag (1 iff the message carries a ``not_deployed`` event). When that
    zero-delivery ROUTED message carries the flag, its deliveries were declines to present-but-not-
    deployed targets, so it finalizes ``NOT_DEPLOYED`` rather than ``FILTERED``. Shared by all three
    finalize twins so the disposition logic can never drift."""
    if not mrows or mrows[0][0] != MessageStatus.ROUTED.value:
        return ("return", None)
    if mrows[0][1]:  # #233: the correlated-EXISTS not_deployed flag from _SQL_SELECT_MESSAGE_STATUS
        return ("update", MessageStatus.NOT_DEPLOYED.value)
    return ("update", MessageStatus.FILTERED.value)


def _parent_meta_from_row(pmeta_json: str | None) -> dict[str, Any]:
    """Decode a PT parent's ``metadata`` (already decrypted) into a dict for depth computation — absent
    / non-dict -> ``{}`` (depth 0). Shared by the async + sync transform twins so the lineage parse
    can never drift."""
    parent_meta: dict[str, Any] = {}
    if pmeta_json:
        loaded = json.loads(pmeta_json)
        if isinstance(loaded, dict):
            parent_meta = loaded
    return parent_meta


def _close_sync_cursor(cur: Any) -> None:
    """Best-effort close of a synchronous pyodbc cursor after a fused handoff (mirrors the async
    :meth:`SqlServerStore._cursor` EF-6 close). A close failure must never mask a caller's in-flight
    error, so it is swallowed to a debug log."""
    try:
        cur.close()
    except Exception:  # noqa: BLE001 - a close failure must not mask the in-flight error
        log.debug("sync handoff cursor close on release failed", exc_info=True)


# --- ADR 0075: per-hop SQL statement batching (fold non-result DML into fewer round-trips) ---------
#
# A "batch group" is a list of the SAME logical (sql, params) statements the unbatched handoff issues,
# grouped so consecutive non-result-returning DML folds into ONE pyodbc round-trip. A result-consuming
# (read) statement — whose value the client must read before building/deciding the next statement — is
# the LAST statement of its group and is read right after that group's single execute(). The single
# per-hop COMMIT is untouched (commits/msg stays 2.000). This is the _SQL_APPLOCK technique (a 4-
# statement T-SQL batch sent as one round-trip) generalized to the rest of the body; the batched form is
# a THIRD emission of the identical logical sequence (async + sync twin + batched), assembled from the
# SAME shared constants + param-builders so it can never drift.


def _render_batch(group: Sequence[tuple[str, tuple[Any, ...]]]) -> tuple[str, tuple[Any, ...]]:
    """Fold a >=2 statement group into ONE ``pyodbc.execute()`` payload: ``SET NOCOUNT ON`` prepended,
    each logical statement ``;``-terminated and concatenated in order, params concatenated in the same
    order (pyodbc binds ``?`` positionally across the whole batch).

    ``SET NOCOUNT ON`` is load-bearing, not cosmetic: it suppresses the rows-affected result a preceding
    INSERT/UPDATE/MERGE would otherwise stream, so a trailing read statement's result set (e.g. the
    finalize ``SELECT @rc``) is the FIRST — and only — rowset the client reads with ``fetchone`` /
    ``fetchall``. This is exactly why the shipped ``_SQL_APPLOCK`` opens with ``SET NOCOUNT ON``; batching
    extends the same guarantee to a group that has DML *before* its trailing read. Its failure mode is
    FAIL-CLOSED: if a positioning surprise made the read return no row, the applock rc reads ``None`` ->
    ``-999`` -> raise -> rollback -> re-pend (never a silent unserialized proceed).

    Two deliberate non-issues: (1) when the group's trailing read is the applock, the rendered batch
    carries TWO ``SET NOCOUNT ON`` (one prepended here, one inside ``_SQL_APPLOCK``) — idempotent and
    harmless, left as-is rather than string-surgery on a reliability-core constant. (2) ``SET NOCOUNT
    ON`` is a session setting that persists on the pooled connection, but it does NOT corrupt the store's
    ``cursor.rowcount``-dependent ops (mark_failed / purge / reset_stale_inflight): NOCOUNT suppresses the
    informational "rows affected" *token*, while ``SQLRowCount`` for a directly-executed DML statement is
    still populated — and the unbatched path already runs this same ``SET NOCOUNT ON`` (via the finalize
    applock) on every handoff, so batching adds no new exposure. The SS-gated NOCOUNT-parity test guards
    this."""
    parts = ["SET NOCOUNT ON;"]
    params: list[Any] = []
    for sql, p in group:
        stripped = sql.rstrip()
        parts.append(stripped if stripped.endswith(";") else stripped + ";")
        params.extend(p)
    return (" ".join(parts), tuple(params))


class _BatchAccumulator:
    """Groups a handoff body's (sql, params) into the fewest round-trips (ADR 0075). Consecutive
    non-result DML accumulates in ``_pending``; a result-consuming statement is appended as the group's
    LAST statement, the group is flushed as ONE ``execute()``, and its result is read right after.
    ``round_trips`` counts the ``execute()`` calls (ex-commit) so a gate can lock the reduction.

    The accumulator NEVER reorders or drops a statement: it appends in call order and every pending
    statement is flushed exactly once (at the next read boundary or the trailing :meth:`flush`), so the
    logical (sql, params) sequence it issues is identical to the unbatched body — only the round-trip
    grouping differs."""

    def __init__(self, store: SqlServerStore, cur: Any) -> None:
        self._store = store
        self._cur = cur
        self._pending: list[tuple[str, tuple[Any, ...]]] = []
        self.round_trips = 0

    def add(self, sql: str, params: tuple[Any, ...]) -> None:
        """Queue one NON-RESULT-RETURNING DML statement into the current group (no round-trip yet).

        The whole positioning-safety proof rests on this invariant: nothing folded via ``add`` may stream
        a rowset that could shadow a trailing read statement's result. So a leading SELECT, any DML with
        an ``OUTPUT`` clause, or the applock rc ``SELECT`` MUST go through :meth:`read_one` /
        :meth:`read_all` (which end the group and read the result) — never ``add``. Enforced here rather
        than trusted by convention."""
        upper = sql.lstrip().upper()
        assert not upper.startswith("SELECT"), (
            f"_BatchAccumulator.add is for non-result DML only; a leading SELECT must use "
            f"read_one/read_all: {sql[:80]!r}"
        )
        assert "OUTPUT" not in upper, (
            f"_BatchAccumulator.add statement carries an OUTPUT clause (streams rows); use "
            f"read_one/read_all so its result is read: {sql[:80]!r}"
        )
        assert "SP_GETAPPLOCK" not in upper, (
            f"_BatchAccumulator.add must not fold the applock rc (it must be read + validated); use "
            f"read_one: {sql[:80]!r}"
        )
        self._pending.append((sql, tuple(params)))

    async def read_one(self, sql: str, params: tuple[Any, ...]) -> Any:
        """Close the current group with a result-consuming statement, flush it as one round-trip, and
        return ``fetchone()`` of its result (the read statement is the group's LAST, so under the
        ``SET NOCOUNT ON`` framing its result set is the one the client reads)."""
        self._pending.append((sql, tuple(params)))
        await self._flush()
        return await self._cur.fetchone()

    async def read_all(self, sql: str, params: tuple[Any, ...]) -> Any:
        """As :meth:`read_one` but returns ``fetchall()`` (used for the finalize GROUP BY + status read,
        which also drains the SELECT so a same-cursor UPDATE afterwards is clean)."""
        self._pending.append((sql, tuple(params)))
        await self._flush()
        return await self._cur.fetchall()

    async def flush(self) -> None:
        """Flush any trailing non-result DML (e.g. the finalize UPDATE + event) as one round-trip."""
        if self._pending:
            await self._flush()

    async def _flush(self) -> None:
        group = self._pending
        self._pending = []
        self.round_trips += 1
        await self._store._execute_group(self._cur, group)


class SyncHandoffUnavailable(RuntimeError):
    """Raised at :meth:`SqlServerStore.open_sync_handoff_pool` when the synchronous fused-handoff pool
    cannot be built fail-closed — today only when ``[store].command_timeout == 0`` (which would make the
    finalize ``sp_getapplock`` wait forever on a worker thread, ADR 0071). The future fused-hop caller
    (PR2/PR3) catches this as 'fusion unavailable' and falls back to the async handoff path."""


class _SyncHandoffPool:
    """A tiny fixed-size pool of **synchronous** pyodbc connections dedicated to the fused handoff hop
    (ADR 0071 §5.1). Distinct from the aioodbc async pool — aioodbc's connections are bound to its own
    executor and are not synchronously drivable from a worker thread. ``autocommit=False`` (each handoff
    owns its transaction) with a FINITE per-statement ``conn.timeout`` so a fused hop can never block a
    worker unboundedly. A plain :class:`queue.Queue` so it is safe to acquire/release across worker
    threads. Built from a ``factory`` (opens one fresh finite-timeout pyodbc connection) so a
    connection broken mid-handoff (network blip / SQL Server restart / killed session) is **discarded
    and lazily replaced** rather than re-circulated to poison the next borrower. PR1 builds/tests it in
    isolation; no pipeline code opens it yet."""

    def __init__(self, factory: Callable[[], Any], size: int, *, conn_timeout: int) -> None:
        self.conn_timeout = conn_timeout
        self._factory = factory
        self._size = size
        self._free: queue.Queue[Any] = queue.Queue()
        opened: list[Any] = []
        try:
            for _ in range(size):
                conn = factory()
                opened.append(conn)
                self._free.put(conn)
        except Exception:
            for conn in opened:  # don't leak half-open connections on a mid-build failure
                try:
                    conn.close()
                except Exception:  # noqa: BLE001 - best-effort cleanup
                    log.debug("sync handoff connection close failed during build", exc_info=True)
            raise

    @property
    def size(self) -> int:
        return self._size

    @contextmanager
    def acquire(self, timeout: float | None = None) -> Iterator[Any]:
        conn = self._free.get(timeout=timeout)
        if conn is None:  # a slot discarded by an earlier fault — reconnect lazily on demand
            conn = self._factory()
        broken = False
        try:
            yield conn
        except Exception:
            # A raised handoff may have left the connection mid-transaction or dead. Mark it broken so
            # the finally discards it instead of returning a possibly-poisoned connection to the pool.
            broken = True
            raise
        finally:
            if broken:
                try:
                    conn.close()
                except Exception:  # noqa: BLE001 - best-effort discard
                    log.debug("sync handoff connection close on discard failed", exc_info=True)
                try:
                    self._free.put(self._factory())  # refill the slot with a fresh connection
                except Exception:  # noqa: BLE001 - reconnect may itself fail (server down)
                    # Keep the slot count stable with a None placeholder; the next acquire retries the
                    # factory. Never re-circulate the poisoned connection or silently shrink the pool.
                    log.debug(
                        "sync handoff reconnect failed; slot will lazily reconnect", exc_info=True
                    )
                    self._free.put(None)
            else:
                self._free.put(conn)

    def close(self) -> None:
        # Drain the free-list and close every live connection (best-effort; a close failure must not
        # mask a caller's error). Idempotent; None placeholders (a slot pending lazy reconnect) skip.
        while True:
            try:
                conn = self._free.get_nowait()
            except queue.Empty:
                break
            if conn is None:
                continue
            try:
                conn.close()
            except Exception:  # noqa: BLE001 - best-effort teardown
                log.debug("sync handoff connection close failed", exc_info=True)


# --- ADR 0114 sub-lever A: the pooled FIFO-heads claim body, shared batch/proc ------------------
#
# ONE source of truth for the claim's table variables + STEPs 1-5 + the sole result-set SELECT:
# the ad-hoc batch (claim_fifo_heads) renders it with a `(VALUES ...)` lane source and the spliced
# epoch guard; the two ADR 0114 stored-procedure bodies render it with the OPENJSON lane source and
# the fixed-nullable epoch guard. Rendering both copies from the same fragments makes in-repo drift
# structurally impossible (the ADR's dual-copy rule); the AC-1 golden-text tests pin the batch's
# absolute bytes, and the DDL lint tests pin the proc render. Every STEP's comments live here with
# the text they document.


def _fifo_heads_steps(*, lane_col: str, lane_source: str, epoch_guard: str) -> str:
    """The shared claim body (ADR 0066 §3.2 probe-then-claim, #285 inversion). ``lane_col`` is the
    code-controlled lane-column literal (``channel_id``/``destination_name``); ``lane_source`` the
    parenthesized derived table producing one ``lane`` column (``(VALUES (?),...)`` on the batch,
    the OPENJSON decode on the proc); ``epoch_guard`` the H1 fence predicate applied to the STEP-3
    probe AND the STEP-5 UPDATE (spliced-or-empty on the batch, fixed-nullable on the proc)."""
    return (
        " DECLARE @heads TABLE (lane NVARCHAR(256) NOT NULL,"
        " id NVARCHAR(64) NOT NULL PRIMARY KEY,"
        " seq BIGINT NOT NULL, rn INT NOT NULL, due BIT NOT NULL);"
        " DECLARE @locked TABLE (id NVARCHAR(64) NOT NULL PRIMARY KEY);"
        " DECLARE @keep TABLE (id NVARCHAR(64) NOT NULL PRIMARY KEY);"
        " DECLARE @claimed TABLE (id NVARCHAR(64) NOT NULL PRIMARY KEY,"
        " message_id NVARCHAR(64) NOT NULL, channel_id NVARCHAR(256) NOT NULL,"
        " destination_name NVARCHAR(256) NULL, handler_name NVARCHAR(256) NULL,"
        " payload NVARCHAR(MAX) NOT NULL, attempts INT NOT NULL, seq BIGINT NOT NULL,"
        " created_at FLOAT NOT NULL);"
        # STEP 1: snapshot discovery (plain RCSI read — no hints; non-blocking, never lock-skips;
        # min-seq REGARDLESS of due-ness, so a backing-off head is discovered, not skipped). One
        # index seek per lane on ix_queue_fifo_in_seq / ix_queue_fifo_out_seq.
        " INSERT INTO @heads (lane, id, seq, rn, due)"
        " SELECT l.lane, h.id, h.seq,"
        " ROW_NUMBER() OVER (PARTITION BY l.lane ORDER BY h.seq),"
        " IIF(h.next_attempt_at <= @now, 1, 0)"
        f" FROM {lane_source} AS l(lane)"
        " CROSS APPLY (SELECT TOP (@k) id, seq, next_attempt_at FROM queue"
        f" WHERE stage = @stage AND {lane_col} = l.lane AND status = @pending"
        " ORDER BY seq) AS h;"
        # STEP 2: contiguous-DUE cutoff. A not-due row truncates AT itself; a not-due HEAD
        # empties the lane (head-of-line preserved).
        " DELETE h FROM @heads h"
        " WHERE EXISTS (SELECT 1 FROM @heads p"
        " WHERE p.lane = h.lane AND p.rn <= h.rn AND p.due = 0);"
        # STEP 3: lock-probe confined to the discovered window via a PER-LANE ORDERED RANGE SCAN
        # (seq <= the lane's max discovered seq) over ix_queue_fifo_*_seq. The prior singleton
        # `q.id IN (SELECT id FROM @heads)` shape planned as a clustered-index seek per id, and
        # SQL Server READPAST does NOT skip an externally-locked row on a singleton key seek
        # (unlike Postgres FOR UPDATE SKIP LOCKED, which skips point lookups) — it WAITED, and
        # SET LOCK_TIMEOUT 0 turned the wait into 1222, a spurious EMPTY-all that nuked claimable
        # sibling lanes (1c) and the claimable head prefix (1e). A range scan is the canonical
        # READPAST skip pattern: UPDLOCK takes REAL row locks even under forced RCSI, READPAST
        # skips a locked row DURING the scan and advances to the next in-window row (structurally
        # never past seq N+1). seq<=maxseq confines the scan exactly as the old id-set did; every
        # pending row with seq<=maxseq in a lane is DUE (STEP 2 truncated the lane at the first
        # not-due row), so the next_attempt_at filter is dropped, keeping the scan index-covered.
        # The epoch guard decides the lockable set fail-closed.
        " INSERT INTO @locked (id)"
        " SELECT h.id FROM (SELECT lane, MAX(seq) AS maxseq FROM @heads GROUP BY lane) AS L"
        " CROSS APPLY (SELECT qq.id FROM queue qq WITH (UPDLOCK, ROWLOCK, READPAST)"
        f" WHERE qq.stage = @stage AND qq.{lane_col} = L.lane AND qq.status = @pending"
        f" AND qq.seq <= L.maxseq{epoch_guard}) AS h;"
        # STEP 4: head-pinned contiguity — keep, per lane, the longest prefix anchored at rn=1
        # whose EVERY member is locked; rn=1 missing drops the whole lane => EMPTY, never seq N+1.
        " INSERT INTO @keep (id)"
        " SELECT h.id FROM @heads h"
        " WHERE NOT EXISTS (SELECT 1 FROM @heads p"
        " WHERE p.lane = h.lane AND p.rn <= h.rn"
        " AND NOT EXISTS (SELECT 1 FROM @locked k WHERE k.id = p.id));"
        # STEP 5: claim exactly the kept prefixes (rows already U-locked from STEP 3; the
        # re-checks + verbatim epoch guard are belt-and-suspenders — plan-robust by the ID pin).
        " UPDATE q SET status = @inflight, attempts = attempts + 1, updated_at = @now,"
        " owner = NULL, lease_expires_at = NULL"
        " OUTPUT inserted.id, inserted.message_id, inserted.channel_id,"
        " inserted.destination_name, inserted.handler_name, inserted.payload,"
        " inserted.attempts, inserted.seq, inserted.created_at"
        " INTO @claimed (id, message_id, channel_id, destination_name, handler_name,"
        " payload, attempts, seq, created_at)"
        " FROM queue q JOIN @keep kp ON q.id = kp.id"
        f" WHERE q.status = @pending AND q.next_attempt_at <= @now{epoch_guard};"
        # The sole result set: every kept id LEFT-joined to its claimed row, so Python sees the
        # claimed rows AND the kept==claimed defensive signal (a NULL claimed twin) in one fetch.
        " SELECT kp.id AS keep_id, c.id, c.message_id, c.channel_id, c.destination_name,"
        " c.handler_name, c.payload, c.attempts, c.seq, c.created_at"
        " FROM @keep kp LEFT JOIN @claimed c ON c.id = kp.id;"
    )


# The two lane-family, name-versioned claim procedures (ADR 0114 §4). TWO procs, not one: the lane
# column is a code-controlled literal baked into the statement text (_lane_col), and a column name
# cannot be a T-SQL parameter; dynamic SQL is rejected (per-call parse + an injection surface at
# the reliability core). Name-versioned (_v1): engine sharding runs N builds against ONE unified
# store (ADR 0037/0063), so a rolling upgrade briefly runs two builds — each calls exactly the body
# it shipped; a retired version is dropped only by an explicit later _SCHEMA statement.
_CLAIM_PROC_CID = "mefor_claim_fifo_heads_cid_v1"  # channel_id lanes: ingress / routed / response
_CLAIM_PROC_DST = "mefor_claim_fifo_heads_dst_v1"  # destination_name lanes: outbound

# The OPENJSON lane decode (compat >= 130): one NVARCHAR(MAX) JSON-array parameter, so no delimiter
# contract is ever imposed on connection names (lane names are data, never concatenated into SQL).
# The explicit CAST keeps the `{lane_col} = l.lane` predicate seek-clean against the NVARCHAR(256)
# column; DISTINCT is belt-and-suspenders under the caller's preserved request-order dedupe.
_CLAIM_PROC_LANE_SOURCE = (
    "(SELECT DISTINCT CAST(j.[value] AS NVARCHAR(256)) FROM OPENJSON(@lanes) AS j)"
)
# The H1 epoch fence in its fixed nullable form, on BOTH sites (STEP-3 probe and STEP-5 UPDATE):
# @leader_epoch IS NULL reproduces epoch=None inertness exactly; with the fence enabled, a missing
# lease row yields NULL -> UNKNOWN -> zero rows (fail-closed on a missing lease, identical to the
# shipped spliced guard); the probe-to-UPDATE fence race (the legitimate kept!=claimed trigger) is
# unchanged.
_CLAIM_PROC_EPOCH_GUARD = (
    " AND (@leader_epoch IS NULL OR (SELECT ll.leader_epoch FROM leader_lease ll"
    " WHERE ll.lease_key = @lease_key) <= @leader_epoch)"
)

# The module head the shipped deploy path emits — the ONE place this literal lives in production
# code. ``_claim_proc_body`` renders it and ``_claim_proc_stored_forms`` anchors on it, so an edit
# to the head is mechanically an edit to BOTH sides of the gate's comparison. The anchor is
# load-bearing: a leading ``--`` comment or ``;`` in the body would otherwise blind the gate
# silently, so ``_claim_proc_stored_forms`` RAISES rather than falling through.
# tests/test_adr0114_claim_proc.py re-states this literal independently on purpose — do NOT
# collapse that assertion onto this constant, or the check stops being a check.
_CLAIM_PROC_HEAD: Final[str] = "CREATE OR ALTER PROCEDURE dbo."


def _claim_proc_body(proc_name: str, lane_col: str) -> str:
    """The full ``CREATE OR ALTER PROCEDURE`` statement for one lane family — the text inside the
    guarded ``EXEC(N'...')``. This is the text SUBMITTED, which is NOT the text
    ``OBJECT_DEFINITION()`` returns: the engine deletes the ``OR`` and ``ALTER`` tokens from the
    stored module, so the startup gate compares against ``_claim_proc_stored_forms()`` — never
    against this string directly. The body is the shipped batch verbatim (via ``_fifo_heads_steps``)
    with exactly the ADR 0114 §4 mechanical substitutions: the DECLARE block becomes the parameter
    list, the VALUES lane list becomes the one-JSON-parameter OPENJSON decode, the spliced epoch
    guard becomes the fixed nullable form, plus the conditional ``@fold_reset`` tail (sub-lever C's
    composition — OUTBOUND/RESPONSE callers never set it).

    HARD RULES (AC-8, lint-tested): no BEGIN/COMMIT/ROLLBACK (the proc runs inside the client's
    autocommit=False transaction; @@TRANCOUNT on exit equals entry), no TRY/CATCH (a client
    cancellation delivers an attention signal that aborts the batch — no CATCH runs; and a second
    partial owner of the session LOCK_TIMEOUT option is how the guard was tripped before), no
    SET XACT_ABORT, and no LOCK_TIMEOUT reset outside the @fold_reset tail — SET LOCK_TIMEOUT does
    NOT revert at proc exit, and that session persistence is LOAD-BEARING at OUTBOUND (the post-proc
    H2 DML deliberately runs under LOCK_TIMEOUT 0; the Python shielded guard remains the single
    reset authority on every non-clean path). SET NOCOUNT *is* exit-restored at proc exit — a real,
    honestly-stated delta from the batch (the outbound post-proc H2 statements may emit rowcount
    DONE tokens; harmless for the execute/fetchone consumers — ADR 0114 §3)."""
    return (
        f"{_CLAIM_PROC_HEAD}{proc_name}"
        " @now FLOAT, @stage NVARCHAR(16), @k INT,"
        " @pending NVARCHAR(32), @inflight NVARCHAR(32),"
        " @lanes NVARCHAR(MAX),"
        " @lease_key NVARCHAR(256) = NULL,"
        " @leader_epoch BIGINT = NULL,"
        " @fold_reset BIT = 0"
        " AS"
        " SET NOCOUNT ON;"
        " SET LOCK_TIMEOUT 0;"
        + _fifo_heads_steps(
            lane_col=lane_col,
            lane_source=_CLAIM_PROC_LANE_SOURCE,
            epoch_guard=_CLAIM_PROC_EPOCH_GUARD,
        )
        + " IF @fold_reset = 1 SET LOCK_TIMEOUT -1;"
    )


def _claim_proc_ddl(proc_name: str, lane_col: str) -> str:
    """The guarded, self-no-op'ing ``_SCHEMA`` statement deploying one claim proc (AC-10).

    ``_ensure_schema`` executes every ``_SCHEMA`` statement inside one must-succeed transaction, so
    this DDL can NEVER fail a flag-OFF open: the guard skips (leaving the proc uncreated — the
    flag-ON startup gate then degrades loudly to the batch, never a lane outage) unless the
    database can actually take it — compat >= 130 (OPENJSON is a per-database COMPATIBILITY_LEVEL
    property, not a server version), the principal holds CREATE PROCEDURE, and the engine ships
    CREATE OR ALTER (2016 SP1 = ProductVersion 13.0.4001; EngineEdition >= 5 is the Azure family,
    which always has it). The dynamic EXEC defers the body's parse (OPENJSON below compat 130 never
    parses) and satisfies CREATE OR ALTER's batch-initial rule. Riding ``_SCHEMA`` means the
    ADR 0064 content hash versions the body for free: ANY edit changes ``_schema_hash()`` and
    forces one guarded, applock-serialized re-apply — a forgotten version bump is impossible."""
    body = _claim_proc_body(proc_name, lane_col).replace("'", "''")
    version_check = (
        "CAST(SERVERPROPERTY('EngineEdition') AS INT) >= 5"
        " OR TRY_CAST(PARSENAME(CAST(SERVERPROPERTY('ProductVersion') AS NVARCHAR(128)), 4)"
        " AS INT) > 13"
        " OR (TRY_CAST(PARSENAME(CAST(SERVERPROPERTY('ProductVersion') AS NVARCHAR(128)), 4)"
        " AS INT) = 13"
        " AND TRY_CAST(PARSENAME(CAST(SERVERPROPERTY('ProductVersion') AS NVARCHAR(128)), 2)"
        " AS INT) >= 4001)"
    )
    return (
        "IF (SELECT compatibility_level FROM sys.databases WHERE name = DB_NAME()) >= 130"
        " AND HAS_PERMS_BY_NAME(DB_NAME(), 'DATABASE', 'CREATE PROCEDURE') = 1"
        # CREATE PROCEDURE alone is NOT sufficient: creating (or CREATE OR ALTER-ing) a proc in
        # dbo also requires ALTER on the schema — a least-privilege principal holding only the
        # database-level permission would pass a narrower guard and then FAIL the must-succeed
        # _ensure_schema transaction (a flag-OFF open outage, the exact failure this guard
        # exists to make impossible). Probing both closes it; ALTER ON SCHEMA::dbo also covers
        # the OR ALTER re-apply against an existing proc.
        " AND HAS_PERMS_BY_NAME('dbo', 'SCHEMA', 'ALTER') = 1"
        f" AND ({version_check})"
        f" EXEC(N'{body}')"
    )


def _normalize_tsql(text: str) -> str:
    """Whitespace-normalize a T-SQL module body for the startup gate's hash comparison: collapse
    every whitespace run to one space and strip — line endings and interior spacing differ across
    deployment paths and across the engine's own module rewrite.

    LOAD-BEARING, do not "simplify" to a line-ending normalizer: the engine deletes the ``OR`` and
    ``ALTER`` TOKENS from a ``CREATE OR ALTER`` head and KEEPS their separators, so the stored head
    comes back as ``CREATE`` + three spaces + ``PROCEDURE``. Collapsing runs is what folds that
    residual spacing away; without it the gate re-breaks even with the head expansion in place.

    Note this normalization is applied to the DEPLOYED text too, so it is semantically lossy inside
    string literals and comments. The compensating control is the AC-8 body lint
    (``test_ac8_proc_body_hard_rules``), which pins the shipped body free of quotes, ``--``, ``/*``
    and non-ASCII — keep those assertions."""
    return " ".join(text.split())


# Every module head a SQL Server may STORE for a module THIS code deployed as _CLAIM_PROC_HEAD.
#
# OBJECT_DEFINITION() does not return a CREATE OR ALTER module verbatim: the engine deletes the OR
# and ALTER keyword TOKENS and keeps their delimiting separators, so the submitted head comes back
# as "CREATE" + three spaces + "PROCEDURE" (char delta exactly 7). MEASURED on SQL Server 2022
# 16.0.4255.1 and 2025 17.0.4055.5, compat 130/160/170, across five deploy paths: fresh CREATE, the
# OR ALTER re-apply, a plain batch, the shipped guarded EXEC(N'...') wrapper, and an out-of-band
# ALTER PROCEDURE (which the engine ALSO rewrites, to a single-spaced CREATE PROCEDURE). Case is
# preserved, not folded. _normalize_tsql collapses the spacing, so the rewritten head is keyed here
# in its collapsed spelling. THIS GATE WAS INERT IN EVERY DEPLOYMENT since it shipped, because it
# compared only against the verbatim form — which no SQL Server can return.
#
# The VERBATIM head is retained as a second accepted form for an engine that does not rewrite. It
# is the text this code SUBMITTED, so accepting it asserts strictly LESS than accepting the rewrite
# does: an engine handing back our own bytes is zero drift, not a tamper event. Which form was
# observed is recorded and logged, so a non-rewriting engine stays DISCOVERABLE — it just is not
# alarmed on.
#
# RULE for any future entry — a head belongs here ONLY if a server can produce it from the text
# _claim_proc_body() renders. `CREATE PROC`, a lower-cased head, or any other spelling this deploy
# path cannot emit is positive evidence of an out-of-band hand deploy, which is precisely the AC-7
# signal, and MUST keep failing the gate. This is not a compatibility grab-bag.
_CLAIM_PROC_STORED_HEADS: Final[tuple[tuple[str, str], ...]] = (
    ("rewritten", "CREATE PROCEDURE dbo."),
    ("verbatim", _CLAIM_PROC_HEAD),
)


def _claim_proc_stored_forms(proc_name: str, lane_col: str) -> dict[str, str]:
    """label -> the normalized text ``OBJECT_DEFINITION()`` may return for OUR deployed module.

    SHIPPED-SIDE ONLY: the deployed text is still hashed as ``_normalize_tsql(deployed)``,
    untouched. The accepted set is therefore a small collection of code-controlled CONSTANTS rather
    than a preimage class of a lossy transform over server-supplied text — a wrong constant can only
    make the gate expect the wrong body (degrade loudly), never widen what it accepts.

    Raises ValueError if the shipped body no longer starts with the anchor; ``_gate_claim_proc``'s
    blanket ``except Exception`` turns that into a loud degrade, never an open() failure."""
    shipped = _claim_proc_body(proc_name, lane_col)
    if not shipped.startswith(_CLAIM_PROC_HEAD):
        raise ValueError(
            f"_claim_proc_body({proc_name!r}) no longer starts with {_CLAIM_PROC_HEAD!r}: the AC-7"
            " startup gate anchors its stored-head expansion on that literal, so a leading comment,"
            " semicolon or SET statement would silently blind the gate. Change _claim_proc_body,"
            " _CLAIM_PROC_HEAD and _CLAIM_PROC_STORED_HEADS together."
        )
    tail = shipped[len(_CLAIM_PROC_HEAD) :]
    return {label: _normalize_tsql(head + tail) for label, head in _CLAIM_PROC_STORED_HEADS}


def _claim_proc_shipped_hashes() -> dict[str, dict[str, str]]:
    """proc name -> {SHA-256 of an accepted normalized body: which stored head form it is}.

    Keyed PER PROC, deliberately: ONE flat set across both procs would accept the cid body served
    under the dst name (``sp_rename`` does not rewrite ``sys.sql_modules.definition``, so a rename
    or a botched blue/green swap reaches that state with no tampering intent) — a silent cross-lane
    predicate swap that claims zero rows forever. Do NOT flatten.

    NEVER memoize this at module scope. The ValueError from ``_claim_proc_stored_forms`` is caught
    by ``_gate_claim_proc`` and becomes a loud degrade; evaluated at import time it would be an
    ImportError for the whole module — a hard outage. (``_SCHEMA`` already calls ``_claim_proc_ddl``
    at import time, so that refactor is plausible; this one must not follow it.)"""
    return {
        proc_name: {
            hashlib.sha256(text.encode()).hexdigest(): label
            for label, text in _claim_proc_stored_forms(proc_name, lane_col).items()
        }
        for proc_name, lane_col in (
            (_CLAIM_PROC_CID, "channel_id"),
            (_CLAIM_PROC_DST, "destination_name"),
        )
    }


# ADR 0114 sub-lever B (fifo_claim_prepared): the STABLE claim text — the same _fifo_heads_steps
# render as the procs (one JSON lanes parameter via OPENJSON, the fixed-nullable H1 guard on both
# sites) but as a client-side batch, so a fleet whose DB principal can never hold CREATE PROCEDURE
# still gets one arity-invariant statement identity. INGRESS/ROUTED only (the channel_id family);
# OUTBOUND/RESPONSE always take the shipped batch. The trailing SET LOCK_TIMEOUT -1 rides INSIDE
# the stable text (§5 fail-closed coupling: B requires the fold — without it the finally-guard's
# separate reset would evict the retained cursor's one-slot prepare cache every call, silently
# zeroing B), so the whole scope has ONE statement identity: 8 parameters, every call.
_PREPARED_CLAIM_SQL = (
    "SET NOCOUNT ON;"
    " SET LOCK_TIMEOUT 0;"
    " DECLARE @now FLOAT = ?, @stage NVARCHAR(16) = ?, @k INT = ?,"
    " @pending NVARCHAR(32) = ?, @inflight NVARCHAR(32) = ?,"
    " @lanes NVARCHAR(MAX) = ?, @lease_key NVARCHAR(256) = ?, @leader_epoch BIGINT = ?;"
    + _fifo_heads_steps(
        lane_col="channel_id",
        lane_source=_CLAIM_PROC_LANE_SOURCE,
        epoch_guard=_CLAIM_PROC_EPOCH_GUARD,
    )
    + " SET LOCK_TIMEOUT -1;"
)


def _claim_prepared_param_pins() -> list[tuple[int, int, int]]:
    """The 8 fixed parameter-descriptor pins for the stable claim text, in DECLARE order (ADR 0114
    §5): the proc pins minus @fold_reset (the reset is unconditional inside the stable text). The
    lanes parameter is pinned to the long class so a 1-lane and a 500-lane call bind identically —
    no binding-class flip can silently force a re-prepare. Lazy-imports pyodbc (the ``sqlserver``
    extra) — called only on the gated prepared path."""
    import pyodbc

    return [
        (pyodbc.SQL_DOUBLE, 0, 0),  # @now FLOAT
        (pyodbc.SQL_WVARCHAR, 16, 0),  # @stage
        (pyodbc.SQL_INTEGER, 0, 0),  # @k
        (pyodbc.SQL_WVARCHAR, 32, 0),  # @pending
        (pyodbc.SQL_WVARCHAR, 32, 0),  # @inflight
        (pyodbc.SQL_WVARCHAR, 0, 0),  # @lanes NVARCHAR(MAX) (0 = MAX; the long class, always)
        (pyodbc.SQL_WVARCHAR, 256, 0),  # @lease_key (nullable — the pin defeats describe fallback)
        (pyodbc.SQL_BIGINT, 0, 0),  # @leader_epoch (nullable — ditto)
    ]


class _ClaimHolder:
    """One store-owned dedicated claim connection + its retained cursor (ADR 0114 §5). NEVER
    pooled: an aioodbc pool cannot retain a cursor across acquire/release, and pyodbc's prepare
    reuse is per-cursor and one-slot — only the same SQL re-executed on the SAME HSTMT skips
    SQLPrepare. Dedicated means the open handle can collide with nothing (EF-6: a drained
    UPDATE...OUTPUT still holds its statement handle active on a no-MARS connection; a sibling
    cursor's execute would race ``HY000 ... Connection is busy``)."""

    __slots__ = ("conn", "cur")

    def __init__(self, conn: Any, cur: Any) -> None:
        self.conn = conn
        self.cur = cur


# Schema (T-SQL). Idempotent: guarded by OBJECT_ID / IndexProperty so re-open is a no-op. Epoch
# timestamps are FLOAT; ids are NVARCHAR(64) (uuid4 hex); bodies NVARCHAR(MAX).
#
# Schema-init is serialized across concurrent opens by this named applock (the T-SQL analog of the
# Postgres store's ``pg_advisory_xact_lock("mefor_schema_init")`` — store/postgres.py). The OBJECT_ID
# guards below are check-then-create and do NOT serialize concurrent creators on a virgin DB — see
# _ensure_schema.
_SCHEMA_LOCK = "mefor:schema_init"
_SCHEMA: list[str] = [
    # Single-row marker recording which shipped DDL batch was last applied (the sha256 of this very
    # list — see _schema_hash). Lets a re-open of a current database SKIP the whole guarded batch +
    # the exclusive schema applock: re-running dozens of check-then-create statements under one
    # exclusive applock on EVERY open made N concurrent opens convoy (WS-B Finding 2 — a loser blows
    # the 30s lock timeout and the process fails startup). Content-addressing means a forgotten
    # "version bump" is impossible: ANY edit to this list changes the hash and forces a full run.
    """IF OBJECT_ID('schema_meta','U') IS NULL CREATE TABLE schema_meta (
        id INT NOT NULL PRIMARY KEY CHECK (id = 1),
        schema_hash NVARCHAR(64) NOT NULL, applied_at FLOAT NOT NULL)""",
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
    # Unified staged queue (ADR 0001) — ingress -> routed -> outbound, one row per stage-unit with a
    # `stage` discriminator. The SQL Server backend originally shipped a flat `outbox` table; it was
    # RECREATED by this very `_SCHEMA` on every open and read by nothing (the staged pipeline and every
    # delivery-side method read/write `queue`), so any legacy PHI body left in it was retained forever
    # with no purge on any backend — see the migrate-and-drop below, and docs/PHI.md §2. `seq` IDENTITY
    # is the FIFO insertion-order tiebreak (PG uses BIGSERIAL); owner/lease_expires_at are present for
    # parity but written NULL on this single-node backend (reset_stale_inflight is the recovery path).
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
    # Streaming very-large attachments (#149, ADR 0105 Phase 4 — SQL Server parity with the SQLite
    # substrate). A very-large OBX-5.5 document detached at ingress: `attachment.id` = sha256 of the
    # VERBATIM concatenated plaintext (content address → identical documents dedup), CHUNKED into
    # `attachment_chunk` rows each carrying ONE mfenc-sealed slice of the plaintext (cipher-covered at
    # rest exactly like queue.payload/shared_body.body — NVARCHAR(MAX) ciphertext, rides the key-rotation
    # re-seal). `refcount` GC's the header + all chunks the moment it hits 0. `message_attachment` records
    # which DISTINCT attachments a message holds (Phase 3a linkage) so retention decrefs exactly those on
    # purge. Logical refs — no FK (mirrors queue.body_ref → shared_body.hash), so a future incremental
    # writer can insert chunks then finalize the header, and the startup sweep reclaims header-less orphans.
    """IF OBJECT_ID('attachment','U') IS NULL CREATE TABLE attachment (
        id NVARCHAR(64) NOT NULL PRIMARY KEY, content_type NVARCHAR(256) NOT NULL,
        total_bytes BIGINT NOT NULL, refcount INT NOT NULL, created_at FLOAT NOT NULL)""",
    """IF OBJECT_ID('attachment_chunk','U') IS NULL CREATE TABLE attachment_chunk (
        attachment_id NVARCHAR(64) NOT NULL, seq INT NOT NULL, ciphertext NVARCHAR(MAX) NOT NULL,
        CONSTRAINT pk_attachment_chunk PRIMARY KEY (attachment_id, seq))""",
    """IF OBJECT_ID('message_attachment','U') IS NULL CREATE TABLE message_attachment (
        message_id NVARCHAR(64) NOT NULL, attachment_id NVARCHAR(64) NOT NULL,
        CONSTRAINT pk_message_attachment PRIMARY KEY (message_id, attachment_id))""",
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
    # ASVS 14.2.7 — fold the legacy flat `outbox` into `queue` (stage=outbound) and DROP it.
    #
    # WHY THIS IS A PHI FIX AND NOT A TIDY-UP. The table was recreated on every open and read by
    # nothing, so `outbox.payload` — a FULL transformed PHI body — was **purged by nothing on any
    # backend**: `purge_old_messages` and `purge_dead_letters` both scope to `queue`. A store upgraded
    # from the pre-staged-pipeline layout therefore kept every legacy body forever while `messages.raw`
    # blanked on its window, so the message READ as purged. Migrating the rows in puts them under
    # `[security].delete_message_bodies_after_days` / `[retention].dead_letter_days` like any other
    # outbound row; dropping the table is what makes the retirement true rather than merely documented.
    #
    # WHY IT LIVES IN `_SCHEMA` AND NOT AN OPEN-PATH METHOD (the SQLite backend uses a method,
    # `_migrate_outbox_to_queue`): on this backend `_schema_hash()` is the ONLY thing that decides
    # whether the DDL batch runs at all — a current marker skips it entirely — so migration code
    # outside `_SCHEMA` would be invisible to that decision. See `_schema_hash`'s docstring.
    #
    # WHY IT IS PLACED HERE, after the `queue` DDL rather than where the `outbox` DDL used to be:
    # SQL Server defers name resolution, so an earlier placement would PARSE fine and then fail at RUN
    # time against a legacy DB old enough to have `outbox` but not yet `queue` — a failed open, which
    # under the batch's single transaction is a startup crash-loop, not a degraded start.
    #
    # The two filters are each load-bearing:
    #   * EXISTS(messages) — `fk_queue_message` is enforced, and an orphan row (a `message_id` with no
    #     surviving message) would abort the whole batch with an opaque FK error. It was unreplayable
    #     anyway: nothing can view or route it. Same call the SQLite migration makes.
    #   * NOT EXISTS(queue) — `queue.id` is the PK. Ids are uuid4 so a collision is not a real
    #     expectation, but the cost of being wrong is a 2627 that rolls back the batch and re-fails on
    #     every restart. A cheap anti-join buys immunity from that, and also makes a partially-applied
    #     migration (rolled back after the INSERT, before the marker) safely re-runnable.
    # ORDER BY created_at feeds the `seq` IDENTITY in arrival order so a legacy backlog drains FIFO
    # (ADR 0059 orders a lane by `seq` alone). MEASURED, not assumed: against SQL Server 2022 CU25,
    # rows INSERTed into `outbox` in the exact reverse of their created_at order came out of the
    # migration with `seq` ascending by created_at. It is still not a documented guarantee — a parallel
    # plan over a large backlog may assign otherwise — so it is deliberately not asserted by a test
    # that would then be flaky. Each row's own created_at is carried over verbatim either way, so a
    # reorder costs ordering, never data.
    f"""IF OBJECT_ID('outbox','U') IS NOT NULL
    BEGIN
        INSERT INTO queue (id, message_id, stage, channel_id, destination_name, payload,
                           status, attempts, next_attempt_at, last_error, created_at, updated_at)
        SELECT o.id, o.message_id, '{Stage.OUTBOUND.value}', o.channel_id, o.destination_name,
               o.payload, o.status, o.attempts, o.next_attempt_at, o.last_error,
               o.created_at, o.updated_at
        FROM outbox o
        WHERE EXISTS (SELECT 1 FROM messages m WHERE m.id = o.message_id)
          AND NOT EXISTS (SELECT 1 FROM queue q WHERE q.id = o.id)
        ORDER BY o.created_at, o.id;
        DROP TABLE outbox;
    END""",
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
        acked_at FLOAT NULL, resolved_at FLOAT NULL, suspended_until FLOAT NULL,
        escalation_tier INT NOT NULL DEFAULT 0)""",
    # #143: windowed NOTIFICATION-mute end-epoch (NULL/past = not suspended). COL_LENGTH-gated ADD for a
    # pre-existing (from #56) alert_instance table; a no-op on a fresh DB (the CREATE above already has it).
    """IF COL_LENGTH('alert_instance','suspended_until') IS NULL
        ALTER TABLE alert_instance ADD suspended_until FLOAT NULL""",
    # #81 (ADR 0133): highest occurrence-driven escalation tier reached (0=base). COL_LENGTH-gated ADD for
    # a pre-existing alert_instance; NOT NULL DEFAULT 0 backfills existing rows. No-op on a fresh DB.
    """IF COL_LENGTH('alert_instance','escalation_tier') IS NULL
        ALTER TABLE alert_instance ADD escalation_tier INT NOT NULL DEFAULT 0""",
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
    # ADR 0006 reference snapshots (BACKLOG #235) — same tables + build-new-then-atomic-flip contract
    # as SQLite/Postgres. [key] is bracket-quoted (reserved word) like `state`'s. The width bounds are
    # this port's schema divergence: [key] is NVARCHAR(450), not unbounded TEXT, so the composite PK
    # fits SQL Server's 1700-byte nonclustered-index key cap (2*(256+64+450) = 1540 bytes) — hence
    # PRIMARY KEY NONCLUSTERED; write_reference_snapshot fail-closes on wider keys BEFORE its
    # transaction (the runtime rejector is the column width itself, via truncation). The explicit
    # binary collation (BIN2) makes key equality a byte comparison like SQLite/Postgres: under a
    # case-insensitive database default, externally-sourced keys differing only by case (or a trailing
    # space, per ANSI padding on index keys) would raise a PK duplicate MID-transaction — a perpetual
    # per-interval sync-failure alert. value is ciphertext at rest (snapshot values may carry PHI).
    # reference_version.name/version carry the same collation so the active-snapshot LEFT JOIN can
    # never hit a cross-column collation conflict.
    """IF OBJECT_ID('reference','U') IS NULL CREATE TABLE reference (
        name NVARCHAR(256) COLLATE Latin1_General_100_BIN2 NOT NULL,
        version NVARCHAR(64) COLLATE Latin1_General_100_BIN2 NOT NULL,
        [key] NVARCHAR(450) COLLATE Latin1_General_100_BIN2 NOT NULL,
        value NVARCHAR(MAX) NOT NULL,
        CONSTRAINT pk_reference PRIMARY KEY NONCLUSTERED (name, version, [key]))""",
    """IF INDEXPROPERTY(OBJECT_ID('reference'),'ix_reference_name','IndexID') IS NULL
        CREATE INDEX ix_reference_name ON reference(name)""",
    """IF OBJECT_ID('reference_version','U') IS NULL CREATE TABLE reference_version (
        name NVARCHAR(256) COLLATE Latin1_General_100_BIN2 NOT NULL PRIMARY KEY,
        version NVARCHAR(64) COLLATE Latin1_General_100_BIN2 NOT NULL,
        synced_at FLOAT NOT NULL, row_count INT NOT NULL)""",
    """IF OBJECT_ID('audit_log','U') IS NULL CREATE TABLE audit_log (
        id INT IDENTITY(1,1) PRIMARY KEY, ts FLOAT NOT NULL, actor NVARCHAR(256) NULL,
        action NVARCHAR(128) NOT NULL, channel_id NVARCHAR(256) NULL, detail NVARCHAR(MAX) NULL,
        client NVARCHAR(256) NULL, row_hash NVARCHAR(64) NULL)""",
    """IF COL_LENGTH('audit_log','row_hash') IS NULL
        ALTER TABLE audit_log ADD row_hash NVARCHAR(64) NULL""",
    # ADR 0150 client attribution for a pre-existing audit_log. NVARCHAR(256) mirrors sessions.client so
    # the two attribution columns share one width. NULL on every existing row is CORRECT (their address
    # was never captured) and is what preserves their row_hash: audit_row_hash omits the conditional 7th
    # element when client is None, so the legacy digest reproduces byte-for-byte across the upgrade.
    """IF COL_LENGTH('audit_log','client') IS NULL
        ALTER TABLE audit_log ADD client NVARCHAR(256) NULL""",
    """IF INDEXPROPERTY(OBJECT_ID('audit_log'),'ix_audit_ts','IndexID') IS NULL
        CREATE INDEX ix_audit_ts ON audit_log(ts)""",
    # Audit-chain keying watermark (#190) — single row (id=1). keyed_from_id = the first audit_log.id
    # hashed with the HMAC key; NULL/no row = the whole chain is keyless (byte-identical to pre-#190).
    """IF OBJECT_ID('audit_chain_meta','U') IS NULL CREATE TABLE audit_chain_meta (
        id INT NOT NULL PRIMARY KEY CHECK (id = 1), keyed_from_id BIGINT NULL)""",
    # Per-key AES-GCM invocation bound (ASVS 11.3.4) — see the SQLite `_SCHEMA` for the
    # reserve-then-spend rationale. One row per key_id; non-secret (a one-way fingerprint
    # plus a counter). BIN2 collation matches the other fingerprint-keyed tables.
    """IF OBJECT_ID('cipher_meta','U') IS NULL CREATE TABLE cipher_meta (
        key_id NVARCHAR(64) COLLATE Latin1_General_100_BIN2 NOT NULL PRIMARY KEY,
        invocations BIGINT NOT NULL DEFAULT 0, updated_at FLOAT NOT NULL)""",
    # Cross-process upload-quota reservation (ASVS 2.3.4, BACKLOG #1112) — see the SQLite `_SCHEMA`
    # for the in-flight-only rationale. One of the two backends a real sharded deployment runs
    # (`require_unified_store` makes a server DB mandatory past one shard). No PHI (an account id and
    # two counters). BIN2 collation matches the other id-keyed tables.
    """IF OBJECT_ID('upload_quota','U') IS NULL CREATE TABLE upload_quota (
        uploader_id NVARCHAR(64) COLLATE Latin1_General_100_BIN2 NOT NULL PRIMARY KEY,
        inflight_files BIGINT NOT NULL DEFAULT 0, inflight_bytes BIGINT NOT NULL DEFAULT 0,
        since FLOAT NOT NULL)""",
    """IF OBJECT_ID('pending_approvals','U') IS NULL CREATE TABLE pending_approvals (
        id NVARCHAR(64) NOT NULL PRIMARY KEY, operation NVARCHAR(128) NOT NULL,
        params NVARCHAR(MAX) NOT NULL, requester NVARCHAR(256) NOT NULL,
        requested_at FLOAT NOT NULL, status NVARCHAR(20) NOT NULL DEFAULT 'pending',
        approver NVARCHAR(256) NULL, decided_at FLOAT NULL, expires_at FLOAT NULL)""",
    """IF INDEXPROPERTY(OBJECT_ID('pending_approvals'),'ix_pending_approvals_status','IndexID') IS NULL
        CREATE INDEX ix_pending_approvals_status ON pending_approvals(status, requested_at)""",
    # BACKLOG #1268: `username` carries the same binary collation as every other identifier column in
    # this schema, and it is the one the engine authenticates against. Without it the column inherits
    # the DATABASE default -- case-INsensitive on a stock install (SQL_Latin1_General_CP1_CI_AS) --
    # while SQLite (BINARY) and Postgres (TEXT) are both case-SENSITIVE. That made `Admin` and `admin`
    # two accounts on two backends and one account on the third, under a UNIQUE constraint that reads
    # as if it had settled the question. Pinning it here makes account identity a property of the
    # ENGINE rather than of whichever collation an operator's database happened to be created with.
    """IF OBJECT_ID('users','U') IS NULL CREATE TABLE users (
        id NVARCHAR(64) NOT NULL PRIMARY KEY,
        username NVARCHAR(256) COLLATE Latin1_General_100_BIN2 NOT NULL UNIQUE,
        auth_provider NVARCHAR(16) NOT NULL, display_name NVARCHAR(256) NULL,
        email NVARCHAR(256) NULL, disabled BIT NOT NULL DEFAULT 0, created_at FLOAT NOT NULL,
        updated_at FLOAT NOT NULL, last_login_at FLOAT NULL, password_hash NVARCHAR(512) NULL,
        password_changed_at FLOAT NULL, must_change_password BIT NOT NULL DEFAULT 0,
        failed_attempts INT NOT NULL DEFAULT 0, locked_until FLOAT NULL,
        channel_scope NVARCHAR(MAX) NULL, totp_secret NVARCHAR(MAX) NULL,
        totp_enabled BIT NOT NULL DEFAULT 0, totp_enrolled_at FLOAT NULL,
        totp_recovery_codes NVARCHAR(MAX) NULL, last_totp_step INT NULL,
        -- BACKLOG #1256: SIZED, NOT MAX, BECAUSE A MAX COLUMN CANNOT BE AN INDEX KEY on SQL
        -- Server, and ux_users_federated_subject below is what makes the application guard's
        -- read-then-write atomic. 256 is this file's dominant width (55 uses); the composite
        -- key is then 2 x 256 x 2 bytes = 1024, inside the 1700-byte nonclustered limit.
        -- NVARCHAR(450), the other precedent here, would be 1800 across two columns and fail.
        oidc_issuer NVARCHAR(256) NULL, oidc_subject NVARCHAR(256) NULL,
        password_claimed_at FLOAT NULL)""",
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
    # Federated (issuer, sub) identity keying (BACKLOG #1015): COL_LENGTH-gated ADD on a pre-existing
    # users table. NULL on existing rows = "not yet federated" (username stays the sole key). Idempotent.
    """IF COL_LENGTH('users','oidc_issuer') IS NULL
        ALTER TABLE users ADD oidc_issuer NVARCHAR(256) NULL""",
    """IF COL_LENGTH('users','oidc_subject') IS NULL
        ALTER TABLE users ADD oidc_subject NVARCHAR(256) NULL""",
    # BACKLOG #1256: RE-TYPE A PRE-EXISTING MAX COLUMN, WHICH THE COL_LENGTH-GATED ADDs ABOVE CANNOT
    # REACH. They fire only when the column is ABSENT, so a users table created before this change
    # keeps NVARCHAR(MAX) -- and a MAX column CANNOT BE AN INDEX KEY, so the index below would fail
    # against exactly the databases that already exist. COL_LENGTH returns -1 for a MAX column, which
    # is how this tells "already sized" from "needs re-typing" without reading catalogue views.
    #
    # MUST RUN BEFORE the index. _SCHEMA is applied in order, so position here is load-bearing.
    """IF COL_LENGTH('users','oidc_issuer') = -1
        ALTER TABLE users ALTER COLUMN oidc_issuer NVARCHAR(256) NULL""",
    """IF COL_LENGTH('users','oidc_subject') = -1
        ALTER TABLE users ALTER COLUMN oidc_subject NVARCHAR(256) NULL""",
    # The atomicity the application guard cannot provide: auth/service.py reads the current holder and
    # writes the binding in two separate awaits, so two concurrent FIRST logins for one subject can
    # both observe "no holder" and both bind. FILTERED so unfederated rows coexist -- and on SQL Server
    # the filter is REQUIRED, not stylistic: unlike SQLite and Postgres it treats NULLs as EQUAL in a
    # unique index, so an unfiltered index would permit exactly ONE unfederated user in the table.
    """IF INDEXPROPERTY(OBJECT_ID('users'),'ux_users_federated_subject','IndexID') IS NULL
        CREATE UNIQUE INDEX ux_users_federated_subject ON users(oidc_issuer, oidc_subject)
        WHERE oidc_issuer IS NOT NULL AND oidc_subject IS NOT NULL""",
    # Claimed-ness of the bootstrap admin (BACKLOG #1245): NULL on an existing row would read as
    # "never claimed", which is what would retire an account whose holder claimed it long ago — this
    # defect, re-introduced by its own fix. So the ADD is paired with a one-time backfill: a local
    # account not flagged must_change_password already rotated its own credential, and
    # password_changed_at is when. The backfill MUST stay inside this COL_LENGTH guard. Split out into
    # its own _SCHEMA entry it becomes a permanent SECOND WRITER of the column (every schema re-apply
    # would re-run it), and single-writer monotonicity is the entire point — a second writer is
    # exactly the defect #1245 documents. The backfill goes through EXEC so its parse is DEFERRED:
    # a statement naming a column added earlier in the SAME batch fails to compile, which would fail
    # the must-succeed _ensure_schema transaction on every upgrading open.
    """IF COL_LENGTH('users','password_claimed_at') IS NULL
    BEGIN
        ALTER TABLE users ADD password_claimed_at FLOAT NULL;
        EXEC(N'UPDATE users SET password_claimed_at = password_changed_at
               WHERE must_change_password = 0 AND password_hash IS NOT NULL');
    END""",
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
    # WebAuthn passkeys (WP-14b, ADR 0068 §4). credential_id_hash — sha256 hex of the RAW credential
    # id (the sessions.token_hash precedent) — is the PK: raw WebAuthn ids may be up to 1023 bytes,
    # unboundable as an index key here (NVARCHAR(MAX) can't be a PK/index key), so the fixed-width
    # digest keys all 3 backends and the full base64url id rides as a body column. public_key is COSE
    # verification material, PLAINTEXT BY DESIGN (not a secret — excluded from cipher + rekey).
    # sign_count is BIGINT (WebAuthn uint32 overflows signed INT). label is capped at 100 so the
    # UNIQUE (user_id, label) index key stays bounded (64+100 chars).
    """IF OBJECT_ID('webauthn_credentials','U') IS NULL CREATE TABLE webauthn_credentials (
        credential_id_hash NVARCHAR(64) NOT NULL PRIMARY KEY, credential_id NVARCHAR(MAX) NOT NULL,
        user_id NVARCHAR(64) NOT NULL, rp_id NVARCHAR(256) NOT NULL,
        public_key NVARCHAR(MAX) NOT NULL, sign_count BIGINT NOT NULL,
        transports NVARCHAR(MAX) NULL, device_type NVARCHAR(32) NOT NULL,
        backed_up BIT NOT NULL DEFAULT 0, label NVARCHAR(100) NOT NULL,
        aaguid NVARCHAR(64) NULL, created_at FLOAT NOT NULL, last_used_at FLOAT NULL)""",
    """IF INDEXPROPERTY(OBJECT_ID('webauthn_credentials'),'ix_webauthn_credentials_user','IndexID') IS NULL
        CREATE INDEX ix_webauthn_credentials_user ON webauthn_credentials(user_id)""",
    """IF INDEXPROPERTY(OBJECT_ID('webauthn_credentials'),'ux_webauthn_label','IndexID') IS NULL
        CREATE UNIQUE INDEX ux_webauthn_label ON webauthn_credentials(user_id, label)""",
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
        detail NVARCHAR(MAX) NULL, resp_headers NVARCHAR(MAX) NULL, captured_at FLOAT NOT NULL,
        kind NVARCHAR(32) NOT NULL CONSTRAINT df_response_kind DEFAULT 'response',
        ack_code NVARCHAR(8) NULL, ack_phase NVARCHAR(16) NULL,
        CONSTRAINT pk_response PRIMARY KEY (message_id, destination_name, response_seq),
        CONSTRAINT fk_response_message FOREIGN KEY (message_id) REFERENCES messages(id))""",
    """IF INDEXPROPERTY(OBJECT_ID('response'),'ix_response_message','IndexID') IS NULL
        CREATE INDEX ix_response_message ON response(message_id)""",
    # BACKLOG #154: captured allow-listed HTTP response headers (JSON, encrypted) on a pre-existing
    # response table; COL_LENGTH-gated so a re-open is a no-op. NULL on existing rows = "no headers".
    """IF COL_LENGTH('response','resp_headers') IS NULL
        ALTER TABLE response ADD resp_headers NVARCHAR(MAX) NULL""",
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
    # Resend idempotency ledger (ADR 0090, BACKLOG #123) — one row per accepted resend-to-alternate,
    # keyed on the caller idempotency_key. IDS ONLY, no body/PHI (NOT ciphered). resend_to serializes
    # same-key inserts under a per-key applock, INSERTs here FIRST (WHERE NOT EXISTS), and creates the
    # outbound row only when rowcount==1 — so racing API nodes never double-send (ADR 0090 §4).
    """IF OBJECT_ID('resend_log','U') IS NULL CREATE TABLE resend_log (
        resend_key NVARCHAR(256) NOT NULL PRIMARY KEY, message_id NVARCHAR(64) NOT NULL,
        to_destination NVARCHAR(256) NOT NULL, from_destination NVARCHAR(256) NOT NULL,
        outbox_id NVARCHAR(64) NULL, created_at FLOAT NOT NULL)""",
    """IF INDEXPROPERTY(OBJECT_ID('resend_log'),'ix_resend_message','IndexID') IS NULL
        CREATE INDEX ix_resend_message ON resend_log(message_id)""",
    # Process-in-place dedup ledger (ADR 0129, BACKLOG #142) — one row per source file a leave-in-place
    # (after_read='leave') File/RemoteFile source has ALREADY ingested, so a read-only share can be
    # polled without moving/deleting files and a left file is ingested once. HASHES + IDS ONLY, no
    # body/PHI (NOT ciphered). file_key = sha256 of the file identity — a DERIVED id, NEVER a cleartext
    # filename (which can embed an MRN) and never logged at INFO+; channel_id (the inbound connection
    # name, non-PHI) scopes the dedup + the age/count prune. Recorded AFTER emit success (file = unit).
    """IF OBJECT_ID('processed_files','U') IS NULL CREATE TABLE processed_files (
        channel_id NVARCHAR(256) NOT NULL, file_key NVARCHAR(64) NOT NULL, processed_at FLOAT NOT NULL,
        CONSTRAINT pk_processed_files PRIMARY KEY (channel_id, file_key))""",
    """IF INDEXPROPERTY(OBJECT_ID('processed_files'),'ix_processed_files_channel','IndexID') IS NULL
        CREATE INDEX ix_processed_files_channel ON processed_files(channel_id, processed_at)""",
    # Saved-search presets (ADR 0136, BACKLOG #151): per-user; the `criteria` JSON is PHI-shaped and
    # AES-256-GCM-encrypted at rest (id-keyed cell-AAD, in the cipher registry). Adding this DDL moves
    # _schema_hash() — the ADR 0064 bump. NVARCHAR(MAX) body; owner/name capped for the unique index.
    """IF OBJECT_ID('search_presets','U') IS NULL CREATE TABLE search_presets (
        id NVARCHAR(64) NOT NULL PRIMARY KEY, owner_user_id NVARCHAR(256) NOT NULL, name NVARCHAR(256) NOT NULL,
        criteria NVARCHAR(MAX) NULL, created_at FLOAT NOT NULL, updated_at FLOAT NOT NULL,
        last_used_at FLOAT NULL)""",
    # #306: last RECALL stamp (get_search_preset), so the retention window keys on last-USED and not
    # only last-edited. COL_LENGTH-gated ADD for a pre-existing (from #151) search_presets table; a
    # no-op on a fresh DB (the CREATE above has it). NULLable with NO default = metadata-only (no table
    # rewrite), and NULL on every existing row is CORRECT: they were never recall-stamped, so the
    # purge's `last_used_at IS NULL` arm falls them back to `updated_at` and their window is
    # byte-identical to pre-#306. Adding this DDL moves _schema_hash() — the ADR 0064 bump.
    """IF COL_LENGTH('search_presets','last_used_at') IS NULL
        ALTER TABLE search_presets ADD last_used_at FLOAT NULL""",
    # UNIQUE(owner_user_id, name) covers the owner-scoped list + the upsert; get/delete use the id PK (no
    # separate owner index needed — ADR 0136, review follow-up).
    """IF INDEXPROPERTY(OBJECT_ID('search_presets'),'ux_search_presets_owner_name','IndexID') IS NULL
        CREATE UNIQUE INDEX ux_search_presets_owner_name ON search_presets(owner_user_id, name)""",
    # Secret-rotation watch state (ASVS 13.3.4, BACKLOG #282) — mirrors the SQLite `secret_rotation_meta`
    # table (store/store.py). One row per tracked secret CLASS. EVERY column is NON-SECRET: `fingerprint`
    # is a keyed MAC (DEK-derived HMAC subkey) OR the DEK's one-way key-id — never the value; the dates are
    # the tracked-since age floor + the auto-detected last-rotation stamp. Adding this DDL moves
    # _schema_hash() — the ADR 0064 bump — so the table is created at open on SQL Server too, engaging the
    # engine's `isinstance(store, SecretRotationMetaStore)` reconcile on the server backends (SQL Server / Postgres).
    """IF OBJECT_ID('secret_rotation_meta','U') IS NULL CREATE TABLE secret_rotation_meta (
        secret_key NVARCHAR(255) NOT NULL PRIMARY KEY, fingerprint NVARCHAR(255) NOT NULL,
        tracked_since NVARCHAR(32) NOT NULL, last_rotated NVARCHAR(32) NOT NULL)""",
    # ADR 0114 sub-lever A: the two lane-family claim procedures, deployed as guarded,
    # self-no-op'ing CREATE OR ALTER statements (see _claim_proc_ddl — a guard miss leaves the proc
    # uncreated, NEVER a failed open; the flag-ON startup gate then degrades loudly to the batch).
    # Their bodies render from the same _fifo_heads_steps fragments as the ad-hoc batch, so the
    # content hash re-applies them on any body edit (no version constant to forget).
    _claim_proc_ddl(_CLAIM_PROC_CID, "channel_id"),
    _claim_proc_ddl(_CLAIM_PROC_DST, "destination_name"),
]


def _schema_hash() -> str:
    """Content hash of the shipped DDL batch. The ``schema_meta`` marker stores it; a match at open
    means this exact batch already ran, so the batch (and its exclusive applock) is skipped. Any
    edit to ``_SCHEMA`` — new table, new index, a B10-style guarded migration — changes the hash and
    forces one full (idempotent) run, so there is no version constant to forget to bump. On-open
    migrations MUST therefore live in ``_SCHEMA`` itself, never in separate open-path code."""
    return hashlib.sha256("\n".join(_SCHEMA).encode()).hexdigest()


def _odbc_brace(value: str) -> str:
    """ODBC-quote a value in braces, doubling any internal ``}`` — neutralizes ``; { } =`` inside it
    so an attacker-influenced value (e.g. a password) can't inject extra connection keywords."""
    return "{" + value.replace("}", "}}") + "}"


def connection_string(settings: StoreSettings, *, posture: HopPosture | None = None) -> str:
    """Build an ODBC connection string for the Microsoft ODBC Driver 18 from store settings.

    Free-text values are brace-quoted to prevent connection-string injection (STORE-5), and the
    ``Encrypt``/``TrustServerCertificate`` security flags are emitted **last** so — ODBC being
    last-wins on duplicate keywords — nothing earlier can downgrade TLS. Identity fields are also
    validated up front (see ``StoreSettings._no_odbc_injection``).

    ``posture`` is the deriving instance's :class:`HopPosture` (threaded from ``open_store`` by the
    serve/engine caller). ``None`` (a backup/restore utility, embedding, or unit test) leaves the escape
    unclamped — byte-identical to pre-#200."""
    # A weakened TLS posture (TrustServerCertificate=yes, or Encrypt=no) is MITM-able, so it REFUSES
    # unless the explicit MEFOR_ALLOW_INSECURE_TLS dev escape is set (ASVS 12.3.2) — it can't be
    # silently turned on in production. #200 (ADR 0092 decision 2): the engine<->store hop routes the
    # escape through the ONE clamp (weakened_tls_escape_permitted) so the escape can NEVER relax a
    # production-PHI store hop (previously the escape crossed prod, violating decision 2). It stays a
    # STRICT verify-off cell (no gradient warn-and-cross) and keeps NO second escape.
    if (
        settings.trust_server_certificate or not settings.encrypt
    ) and not weakened_tls_escape_permitted(posture):
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
    # AOAG multi-subnet fast failover (BACKLOG #100). Not a TLS keyword, so it goes before the
    # Encrypt/TrustServerCertificate tail and cannot disturb the last-wins TLS posture.
    if settings.multi_subnet_failover:
        parts.append("MultiSubnetFailover=Yes")
    # Pin the DB server's certificate by file WITHOUT a machine-wide trust import (#45), via the ODBC
    # Driver 18.1+ `ServerCertificate` keyword — only on the SECURE posture (Encrypt=yes, verify on; the
    # weakened branch above already refused/escaped). Brace-quoted (STORE-5). It names a cert file to
    # match the server against; it can only tighten verification, never downgrade the last-wins
    # Encrypt/TrustServerCertificate tail that still follows.
    if settings.ssl_root_cert and settings.encrypt and not settings.trust_server_certificate:
        parts.append(f"ServerCertificate={_odbc_brace(settings.ssl_root_cert)}")
    parts.append(f"Encrypt={'yes' if settings.encrypt else 'no'}")
    parts.append(f"TrustServerCertificate={'yes' if settings.trust_server_certificate else 'no'}")
    return ";".join(parts) + ";"


def _build_pool_executor(settings: StoreSettings) -> ThreadPoolExecutor:
    """A thread pool wide enough that every pooled connection can hold a worker at once.

    WHY THE STORE NEEDS ITS OWN. aioodbc runs EVERY pyodbc call through
    ``loop.run_in_executor(self._executor, ...)`` and passes ``executor=None`` unless told otherwise, so
    by default every connection in this pool shares the event loop's DEFAULT ThreadPoolExecutor. CPython
    sizes that at ``min(32, cpu_count + 4)`` -- eight threads on a four-vCPU runner -- and that width is
    INDEPENDENT of ``[store].pool_size``. So the configured pool silently cannot exceed the loop default.

    WHY THAT DEADLOCKS RATHER THAN MERELY THROTTLING, which is the part worth keeping. A write like
    ``add_cipher_invocations`` needs FOUR sequential executor dispatches -- ``cursor()``, ``execute()``,
    ``fetchone()``, ``commit()`` -- and the pool is opened ``autocommit=False``, so the row locks taken by
    the MERGE in dispatch 2 are released only by the commit in dispatch 4. Once as many tasks as there
    are threads are parked inside a blocked ``execute``, the lock holder's own ``commit`` sits behind
    them in the executor's FIFO queue with no worker left to run it. Nothing progresses until an ODBC
    query timeout or the pool acquire bound breaks the tie, which surfaces as HYT00 or StoreAcquireTimeout
    rather than as a deadlock.

    HEADROOM, NOT AN EXACT BOUNDARY. ``maxsize + 4`` rather than ``maxsize``: threads spawn lazily, so
    unused headroom costs nothing, and the margin absorbs the pool's own in-flight ``connect()`` during
    growth and the window where a closing connection still holds a worker.
    """
    maxsize = max(1, settings.pool_size)
    return ThreadPoolExecutor(
        max_workers=maxsize + 4,
        thread_name_prefix="mefor-sqlserver",
    )


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

    # ADR 0071 B5: this backend ships the synchronous fused-handoff twins (route_handoff_sync /
    # transform_handoff_sync) + a dedicated synchronous pyodbc connection source, so a fused worker-
    # thread hop can collapse a multi-statement aioodbc handoff into ONE executor completion. The wall
    # is aioodbc's per-statement thread crossing — SQL-Server-specific — so this is True ONLY here;
    # Postgres (asyncpg loop-native) and SQLite (loop-affine handoff lock) keep the async path.
    supports_fused_sync_handoff = True

    # #149 / ADR 0105 Phase 4: the streaming-attachment substrate is now implemented on SQL Server at
    # byte-for-byte behavioral parity with the SQLite reference (content-addressed sha256 ref, per-chunk
    # mfenc seal, dedup, refcount + GC-at-0, two-object ingress commit, retention decref/dead-row split,
    # key-rotation re-seal). Go-live parity met — the production store is SQL Server.
    supports_streaming_attachments = True

    # ADR 0006 reference sets ARE implemented here (BACKLOG #235): the `reference` /
    # `reference_version` tables + write_reference_snapshot / _load_reference_cache / reference_view /
    # converge_reference_cache at SQLite/Postgres parity (build-new-then-atomic-flip, values encrypted
    # at rest incl. the key-rotation + no-key->key migration passes, multi-node follower read-through).
    # This port's two recorded divergences — the fail-closed UTF-16 width guard and the BIN2 collation —
    # are documented at the schema DDL (see _SCHEMA's reference comment) and in the ADR 0006 amendment
    # (2026-07-16). Flipped only after the T-SQL was proven by the sqlserver-store (2022+2025 matrix)
    # + postgres-store CI legs on PR #1078; the allow-list gate itself stays, for future backends.
    supports_reference_sets = True
    backend = StoreBackend.SQLSERVER

    def __init__(
        self,
        pool: Any,
        settings: StoreSettings,
        *,
        cipher: Cipher | None = None,
        audit_mac_key: bytes | None = None,
        audit_mac_fn: AuditMacFn | None = None,
        message_events: str = "all",
        posture: HopPosture | None = None,
    ) -> None:
        self._pool = pool
        # Set by open() when this store owns the pool. Stays None when a caller supplies a pool it
        # built itself, so close() never shuts down an executor it did not create.
        self._pool_executor: ThreadPoolExecutor | None = None
        self._settings = settings
        # #200 (ADR 0092): the deriving instance posture, so reconnect / sync-handoff-pool rebuilds re-run
        # the weakened-TLS clamp against the real production-PHI posture (not the unclamped escape).
        self._posture = posture
        self._cipher: Cipher = cipher or IdentityCipher()
        # #190 audit-chain HMAC key (HKDF-derived; None → keyless chain) + keying watermark.
        self._audit_mac_key = audit_mac_key
        # ADR 0138: an isolated-module MAC provider (Vault/OpenBao Transit ``generate_hmac``) keying the
        # audit chain WITHOUT an in-heap key — set only in `vault_transit` mode (from Cipher.audit_mac_fn),
        # where audit_mac_key() is None BY DESIGN. Before this was threaded here, a vault_transit +
        # server-DB deployment ran its audit chain fully UNKEYED under the posture meant to be the most
        # isolated one (ASVS 13.3.3).
        self._audit_mac_fn = audit_mac_fn
        self._audit_keyed_from: int | None = None
        # #63 message_events verbosity gate ("all"/"errors"/"off"); floor always retained.
        self._message_events = message_events
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
        # ADR 0006 reference-snapshot read cache (parity with SQLite/PG, BACKLOG #235): the active
        # snapshot of every set, {name: {key: decoded_value}}. Loaded at open; write_reference_snapshot
        # swaps a set's entry only AFTER its transaction commits (a rolled-back sync never leaks into
        # reference_view, so the last-good snapshot stays live).
        self._reference_cache: dict[str, dict[str, Any]] = {}
        # The active reference VERSION currently reflected in _reference_cache, per set (Track B
        # Step 6): converge_reference_cache compares the shared store's authoritative active version
        # against this and re-reads only the sets that differ. Seeded at open (_load_reference_cache)
        # and on every write_reference_snapshot.
        self._reference_versions: dict[str, str] = {}
        # Serializes audit-chain appends in-process (the store is the single audit writer per engine
        # process; active-passive = one active node) — see record_audit.
        self._audit_lock = asyncio.Lock()
        # H1 fencing token: the held leader epoch + the leader_lease row to validate it against, pushed
        # by the engine on promotion via set_leader_epoch() (the store NEVER imports the coordinator —
        # ARCH-6). None disables the claim's epoch guard, keeping claim_next_fifo byte-identical to pre-H1.
        self._leader_epoch: int | None = None
        self._lease_key: str | None = None
        # ADR 0071 B5: dedicated synchronous pyodbc pools for the fused handoff hop, keyed by stage
        # ("routed"/"outbound"). Empty until open_sync_handoff_pool() is called (no pipeline code opens
        # one in PR1); closed by close_sync_handoff_pool() at store teardown.
        self._sync_pools: dict[str, _SyncHandoffPool] = {}
        # ADR 0075 per-hop SQL statement batching. FROZEN intent, set ONCE by the runner at start via
        # set_batch_handoff_statements() when [pipeline].batch_handoff_statements is on (a /config/reload
        # never re-reads it). When True, route_handoff / transform_handoff dispatch to their batched forms
        # (fewer pyodbc round-trips, IDENTICAL logical (sql, params) sequence, one commit/hop). Default
        # False → the async path is byte-identical. SQL-Server-only is intrinsic: only this store class
        # ships the batched forms + this attribute (MessageStore/PostgresStore have neither), so the flag
        # is a provable no-op on the other backends.
        self._batch_handoff_statements = False
        # ADR 0114 sub-lever C (fifo_claim_fold_reset): fold the pooled claim's session LOCK_TIMEOUT
        # reset into the claim batch's CLEAN success path at INGRESS/ROUTED (commit#2 disappears; the
        # shielded finally-guard remains verbatim for every non-clean exit — see claim_fifo_heads).
        # Read ONCE at store open (restart to change, like claim_mode); default OFF = byte-identical.
        # SQL-Server-only by construction: only this class reads the flag (AC-6 sentinel).
        self._fifo_claim_fold_reset = bool(settings.fifo_claim_fold_reset)
        # ADR 0114 sub-lever A (fifo_claim_proc): execute the pooled claim via the two lane-family
        # versioned procs instead of the ad-hoc batch. Read ONCE at open; the flag alone is NOT
        # sufficient — open() runs the _gate_claim_proc startup gate (proc existence +
        # OBJECT_DEFINITION body hash + compat >= 130) and only a green gate sets
        # _claim_proc_effective. Any gate miss degrades LOUDLY to the shipped batch (never a lane
        # outage; the hot path carries no error-2812 handling). Default OFF = byte-identical.
        self._fifo_claim_proc = bool(settings.fifo_claim_proc)
        self._claim_proc_effective = False
        self._claim_proc_degraded_reason: str | None = None
        self._claim_proc_input_sizes: list[tuple[int, int, int]] | None = None
        # proc name -> which _CLAIM_PROC_STORED_HEADS form the deployed module actually matched
        # ("rewritten" on every engine measured to date; "verbatim" would mean this server does NOT
        # rewrite CREATE OR ALTER — an engine difference worth knowing about, not a tamper event).
        self._claim_proc_head_forms: dict[str, str] = {}
        self._claim_proc_setinputsizes_warned = False
        # ADR 0114 sub-lever B (fifo_claim_prepared): stable claim text + a retained prepared
        # cursor on store-owned dedicated connections (INGRESS/ROUTED). Read ONCE at open; the
        # _gate_claim_prepared startup gate enforces the §5 couplings — fail-closed to the fold
        # (logs + no-ops unless fifo_claim_fold_reset is ON), retired-not-stacked under a green
        # proc gate, compat >= 130 for OPENJSON. Holders are per-stage free lists, opened lazily
        # on the first flagged claim (sized by construction to the concurrent flagged-claim count
        # per stage — the pooled-claimer concurrency), kept on 1222/kept≠claimed (normal yield
        # signals), discarded ONLY on cancellation/unclassified errors (§5 — a contention burst
        # can never become a connect storm), closed at store teardown. Default OFF = byte-identical.
        self._fifo_claim_prepared = bool(settings.fifo_claim_prepared)
        self._claim_prepared_effective = False
        self._claim_prepared_degraded_reason: str | None = None
        self._claim_prepared_input_sizes: list[tuple[int, int, int]] | None = None
        self._claim_holders: dict[str, list[_ClaimHolder]] = {}
        self._claim_holders_closed = False  # set by teardown: returns then discard, never retain
        self._claim_holders_open = 0
        self._claim_holders_opened_total = 0
        self._claim_holders_discarded_total = 0
        # A1 live cost counters (always-on, additive): committed_txns = durable WRITE transactions committed
        # on this store (the 3+2H+2N-per-message cost-model currency ADR 0051 sizes capacity on) — read-
        # snapshot-release commits (RCSI hygiene on a pure SELECT) go through the non-counting _commit_read
        # so they never inflate it; body_copies = raw/payload body strings durably written (the 2+H+N-per-
        # message amplification — SQL Server does NOT dedup a fan-out body, so N deliveries = N copies). Both
        # are bare int increments funneled through the write-commit helpers (_commit/_commit_sync) and the
        # insert helpers; no new lock, no commit-boundary change. See tests/test_live_cost_counters.py.
        self.committed_txns = 0
        self.body_copies = 0
        # ADR 0157 C3: protocol/`/stats` uniformity only. SQL Server's terminal resolves are NOT yet
        # epoch-fenced (that is ADR 0157 Inc 3), so this stays 0 on this backend until then. Declared
        # because Store (base.py) requires it and open_store() returns this class as a Store.
        self.fenced_writes = 0

    async def _commit(self, conn: Any) -> None:
        """Commit a durable **write**-path transaction and count it (A1 live cost counters). A bare async
        wrapper over ``conn.commit()`` — every *staged-queue write* commit site (enqueue_ingress, the
        route/transform handoffs, the claim methods, mark_done, dead-letter, state ops) funnels its
        physical transaction through here so ``committed_txns`` reflects the ``3 + 2H + 2N``-per-message
        durable-write cost the model sizes on. Moves no boundary. Read-snapshot-release commits (the RCSI
        hygiene commit on a pure SELECT) use :meth:`_commit_read` instead so they are NOT counted — the
        counter is the write currency, not total physical commits."""
        await conn.commit()
        self.committed_txns += 1

    async def _commit_read(self, conn: Any) -> None:
        """Commit a **read-only** transaction WITHOUT counting it (A1). Under RCSI + autocommit=False a
        pure SELECT still opens a snapshot txn that must be committed to release the version-store snapshot
        before the pooled connection is reused (M-6 read hygiene). That physical commit carries no durable
        write, so it is deliberately excluded from ``committed_txns`` — otherwise every live ``db_lookup`` /
        stats / list read would inflate the counter into a superset of the ``3 + 2H + 2N`` write model it
        exists to validate."""
        await conn.commit()

    def _commit_sync(self, conn: Any) -> None:
        """Synchronous twin of :meth:`_commit` for the ADR 0071 B5 fused-hop sync handoffs (route/transform
        _sync), which run on a caller-supplied synchronous pyodbc connection. Write-path — counted."""
        conn.commit()
        self.committed_txns += 1

    def set_batch_handoff_statements(self, enabled: bool) -> bool:
        """Enable/disable ADR 0075 per-hop statement batching on this SQL Server store (called ONCE by
        the runner at start). Returns the EFFECTIVE decision. Fail-closed + SQL-Server-only by
        construction: this method exists only on :class:`SqlServerStore`, so a non-SS store can never be
        switched on; here it simply records the frozen intent. Batching never moves a commit boundary and
        emits the identical logical (sql, params) sequence — see :meth:`_route_handoff_batched`."""
        self._batch_handoff_statements = bool(enabled)
        return self._batch_handoff_statements

    @property
    def batch_handoff_statements(self) -> bool:
        """Whether ADR 0075 per-hop statement batching is EFFECTIVELY active this run (the /stats seam a
        batched-vs-unbatched A/B reads). False on every other backend and when the flag is off."""
        return self._batch_handoff_statements

    @property
    def claim_proc_effective(self) -> bool:
        """Whether the ADR 0114 proc claim path is EFFECTIVELY active this run: the
        ``fifo_claim_proc`` flag was ON at open AND the startup gate verified both deployed proc
        bodies + compat >= 130. False when the flag is off or the gate degraded (see
        :attr:`claim_proc_degraded_reason`)."""
        return self._claim_proc_effective

    @property
    def claim_proc_degraded_reason(self) -> str | None:
        """WHY the proc path is degraded to the batch (the AC-7 degraded gauge): None when the flag
        is off or the gate passed; the human-readable reason otherwise (missing proc, body-hash
        mismatch, compat < 130)."""
        return self._claim_proc_degraded_reason

    async def _gate_claim_proc(self) -> None:
        """ADR 0114 §4 startup gate — fail-safe to the batch, loudly (AC-7). With
        ``fifo_claim_proc`` ON, open() probes (a) both procs exist, (b) each deployed body's
        normalized SHA-256 (via OBJECT_DEFINITION — existence alone cannot catch a hand-edited
        body, and the proc IS the claim logic) matches one of ``_claim_proc_stored_forms()``, and
        (c) compatibility_level >= 130 (OPENJSON). Any miss records the reason, logs a WARNING, and
        leaves ``_claim_proc_effective`` False — the shipped batch runs; NEVER a lane outage.

        (a) and (b) are probed in ONE statement that returns ``OBJECT_ID`` beside the definition,
        because a NULL body has two very different causes: the proc is absent, or it is deployed
        and this principal simply cannot READ it (no ``VIEW DEFINITION``, or ``WITH ENCRYPTION``).
        Both degrade — the gate cannot hash a body it cannot see — but they need opposite remedies,
        and the second is the exact posture the sub-lever B design note above anticipates — a fleet
        whose DB principal can never hold CREATE PROCEDURE, i.e. DBA-provisioned procs plus a
        least-privilege app principal.

        The comparison is against the STORED forms, not against ``_claim_proc_body()`` directly:
        the engine rewrites the ``CREATE OR ALTER`` head when it stores the module, so comparing
        with the submitted text can never match (the defect that left this gate inert in every
        deployment from the feature shipping until this commit)."""
        reason: str | None = None
        head_forms: dict[str, str] = {}
        try:
            row = await self._fetchone(
                "SELECT compatibility_level FROM sys.databases WHERE name = DB_NAME()"
            )
            compat = int(row["compatibility_level"]) if row else 0
            if compat < 130:
                reason = f"database compatibility_level {compat} < 130 (OPENJSON unavailable)"
            else:
                expected = _claim_proc_shipped_hashes()
                for proc_name in (_CLAIM_PROC_CID, _CLAIM_PROC_DST):
                    # OBJECT_ID rides along so a NULL body can be told apart from an ABSENT proc.
                    # MEASURED: a principal holding only EXECUTE on the proc gets a non-NULL
                    # OBJECT_ID and a NULL OBJECT_DEFINITION — the module is deployed and working,
                    # and the compat probe above still passes. Without the id, that reads as
                    # "missing" and sends the operator to grant CREATE PROCEDURE, which is not the
                    # problem and does not fix it. WITH ENCRYPTION produces the identical NULL.
                    row = await self._fetchone(
                        "SELECT OBJECT_ID(?) AS oid, OBJECT_DEFINITION(OBJECT_ID(?)) AS body",
                        (f"dbo.{proc_name}", f"dbo.{proc_name}"),
                    )
                    deployed = row["body"] if row else None
                    if not deployed:
                        if (row["oid"] if row else None) is None:
                            reason = (
                                f"stored procedure dbo.{proc_name} is missing (guarded DDL skipped —"
                                " CREATE PROCEDURE / ALTER-on-schema denied, or a pre-2016-SP1"
                                " engine?)"
                            )
                        else:
                            reason = (
                                f"stored procedure dbo.{proc_name} is DEPLOYED but its definition is"
                                " unreadable (OBJECT_ID resolves, OBJECT_DEFINITION is NULL) — the"
                                " proc is not missing and CREATE PROCEDURE is not the fix. Either"
                                " this principal lacks VIEW DEFINITION on it (GRANT VIEW DEFINITION"
                                f" ON OBJECT::dbo.{proc_name} TO <the engine's principal>) or the"
                                " module was created WITH ENCRYPTION. The gate compares the body"
                                " hash, so it cannot pass on a body it cannot read"
                            )
                        break
                    got = hashlib.sha256(_normalize_tsql(deployed).encode()).hexdigest()
                    matched = expected[proc_name].get(got)
                    if matched is None:
                        reason = (
                            f"stored procedure dbo.{proc_name} body matches no form this build"
                            " deploys — an out-of-band edit, a hand deploy (a head spelling this"
                            " code cannot emit, e.g. CREATE PROC or a differing case), a renamed"
                            " proc (sp_rename does not rewrite the stored definition), or a build"
                            " whose body was changed without bumping the _v1 proc name. The"
                            " shipped batch runs. Compare OBJECT_DEFINITION(OBJECT_ID('dbo."
                            f"{proc_name}')) against this build's own definition to see the drift"
                        )
                        break
                    head_forms[proc_name] = matched
        except Exception as exc:  # noqa: BLE001 - §4: ANY gate failure degrades, never an outage
            # A transient probe failure (e.g. a hiccup on the metadata read) must not fail the
            # open — the ADR's rule is total: any gate miss runs the shipped batch, loudly.
            reason = f"startup-gate probe failed: {exc}"
        if reason is None:
            self._claim_proc_effective = True
            self._claim_proc_degraded_reason = None
            self._claim_proc_input_sizes = _claim_proc_param_pins()
            self._claim_proc_head_forms = head_forms
            log.info(
                "fifo_claim_proc: startup gate PASSED — pooled claims will use"
                " dbo.%s / dbo.%s (ADR 0114 sub-lever A); stored head forms: %s",
                _CLAIM_PROC_CID,
                _CLAIM_PROC_DST,
                head_forms,
            )
            if any(form == "verbatim" for form in head_forms.values()):
                # Not a fault: this engine stores CREATE OR ALTER as submitted rather than deleting
                # the tokens. Every engine measured to date rewrites, so this is worth surfacing —
                # it means the compatibility assumption in _CLAIM_PROC_STORED_HEADS has a live
                # counterexample and the ADR should record it.
                log.info(
                    "fifo_claim_proc: this server stored the CREATE OR ALTER head VERBATIM"
                    " (%s) — no engine measured to date does this; please report it, the gate"
                    " accepts it deliberately",
                    head_forms,
                )
        else:
            self._claim_proc_effective = False
            self._claim_proc_degraded_reason = reason
            log.warning(
                "fifo_claim_proc requested but DEGRADED to the shipped ad-hoc batch: %s"
                " (claims keep flowing on the batch path — no lane outage; fix the condition"
                " and restart to activate the proc path)",
                reason,
            )

    @staticmethod
    def _sync_setinputsizes(cur: Any) -> Any | None:
        """The SYNC ``setinputsizes`` callable for ``cur``, or None if unreachable. The surface
        matters: aioodbc 0.5.0 wraps ``setinputsizes`` as ``async def`` (cursor.py:148,
        executor-routed), so calling the WRAPPER synchronously merely creates a never-awaited
        coroutine that does NOTHING. So the underlying pyodbc cursor (``_impl``) is preferred
        FIRST; the wrapper attribute is used only when it is a plain sync callable (a bare pyodbc
        cursor, or a test fake). ``setinputsizes`` is pure client-side descriptor state (no I/O),
        so the sync call is loop-safe."""
        raw = getattr(cur, "_impl", None)
        target = getattr(raw, "setinputsizes", None)
        if target is None:
            candidate = getattr(cur, "setinputsizes", None)
            if candidate is not None and not inspect.iscoroutinefunction(candidate):
                target = candidate
        return target

    def _warn_setinputsizes_unreachable(self) -> None:
        if not self._claim_proc_setinputsizes_warned:
            self._claim_proc_setinputsizes_warned = True
            log.warning(
                "ADR 0114 claim path: no synchronous setinputsizes is reachable through this"
                " cursor stack — proceeding without parameter-descriptor pin/clear (NULL params"
                " may incur SQLDescribeParam round trips; the ADR 0114 G-A0/G-B0 preflights"
                " measure this)"
            )

    def _apply_claim_input_sizes(self, cur: Any, sizes: list[tuple[int, int, int]] | None) -> None:
        """Pin the claim-path parameter descriptors on ``cur`` (ADR 0114 §4/§5 NULL-typing
        hazard; 9 descriptors on the proc path, 8 on the prepared stable-text path). If no sync
        surface is reachable, warn ONCE and proceed unpinned (the G-A0 wire trace decides whether
        describe traffic appears — degraded observability, never an outage)."""
        if sizes is None:
            return
        target = self._sync_setinputsizes(cur)
        if target is None:
            self._warn_setinputsizes_unreachable()
            return
        target(sizes)

    def _clear_claim_input_sizes(self, cur: Any) -> None:
        """Clear the claim-CALL parameter pins on ``cur`` before it runs the H2 DELIVERY DML.

        ``setinputsizes`` is PERSISTENT cursor state. On the proc path the pooled claim cursor is
        pinned for the ``{CALL}`` (descriptor[0] = ``SQL_DOUBLE`` for ``@now FLOAT``) and then, at
        OUTBOUND, the SAME cursor runs the H2 ``SELECT 1 FROM delivered_keys WHERE outbox_id=?`` —
        binding the NVARCHAR ``d["id"]`` against the stale ``SQL_DOUBLE`` descriptor throws a
        client-side ``22018`` cast error, rolls the claim back, and collapses outbound delivery.
        The pins' only purpose was the CALL's NULL-fence describe-avoidance, so clear them the
        moment the CALL's result is drained.

        Only PARAMETERIZED statements are affected — a zero-parameter execute (notably the shielded
        ``SET LOCK_TIMEOUT -1;`` reset in this method's ``finally``) tolerates surplus descriptors,
        measured on pyodbc 5.3.0 / ODBC Driver 18. So the exposure is exactly the H2 bind chain and
        clearing here covers all of it.

        ``setinputsizes(None)`` reverts all params to default inference (pyodbc 5.3.0), on the SYNC
        ``_impl`` surface — a bare ``cur.setinputsizes(None)`` on the async wrapper is a
        never-awaited no-op, and ``_apply_claim_input_sizes(cur, None)`` early-returns on its None
        guard, so neither clears anything. Best-effort: if no sync surface is reachable the pins
        were never applied either, so there is nothing to clear."""
        target = self._sync_setinputsizes(cur)
        if target is None:
            self._warn_setinputsizes_unreachable()
            return
        target(None)

    @property
    def claim_prepared_effective(self) -> bool:
        """Whether the ADR 0114 prepared claim path is EFFECTIVELY active this run: the
        ``fifo_claim_prepared`` flag was ON at open AND the §5 couplings held (fold ON, not
        superseded by a green proc gate, compat >= 130)."""
        return self._claim_prepared_effective

    @property
    def claim_prepared_degraded_reason(self) -> str | None:
        """WHY the prepared path is inactive (the AC-13 gauge): None when the flag is off or the
        gate passed; otherwise the human-readable reason (fold coupling, superseded-by-proc,
        compat < 130, probe failure)."""
        return self._claim_prepared_degraded_reason

    async def _gate_claim_prepared(self) -> None:
        """ADR 0114 §5 startup gate for the prepared/stable-text lane — every miss records the
        reason, logs, and leaves the shipped path in place (never an outage). Runs AFTER
        _gate_claim_proc (the §5 compose-or-compete rule reads its outcome)."""
        reason: str | None = None
        level = logging.WARNING
        if not self._fifo_claim_fold_reset:
            # AC-13: fail-closed-coupled to the fold — on a clean call the finally-guard would
            # otherwise execute its reset SET on the retained cursor, evicting the one-slot
            # prepare cache every call (silently zeroing B).
            reason = (
                "requires fifo_claim_fold_reset=ON (without the fold, the finally-guard's reset"
                " would evict the retained cursor's one-slot prepare cache every call) — logging"
                " and no-op'ing per ADR 0114 AC-13"
            )
        elif self._claim_proc_effective:
            # §5 compose-or-compete: the retained handle competes with the proc's RPC for the
            # same bytes — if A is green, B is retired, not stacked (recorded superseded-for-now).
            reason = (
                "superseded-for-now by fifo_claim_proc (its startup gate is green; ADR 0114 §5"
                " retire-not-stack — two mechanisms holding the same bytes is double"
                " reliability-core surface for zero incremental bytes)"
            )
            level = logging.INFO
        else:
            try:
                row = await self._fetchone(
                    "SELECT compatibility_level FROM sys.databases WHERE name = DB_NAME()"
                )
                compat = int(row["compatibility_level"]) if row else 0
                if compat < 130:
                    reason = f"database compatibility_level {compat} < 130 (OPENJSON unavailable)"
            except Exception as exc:  # noqa: BLE001 - any gate failure degrades, never an outage
                reason = f"startup-gate probe failed: {exc}"
        if reason is None:
            self._claim_prepared_effective = True
            self._claim_prepared_degraded_reason = None
            self._claim_prepared_input_sizes = _claim_prepared_param_pins()
            log.info(
                "fifo_claim_prepared: startup gate PASSED — INGRESS/ROUTED pooled claims will"
                " use the stable text on store-owned dedicated claim connections (ADR 0114"
                " sub-lever B)"
            )
        else:
            self._claim_prepared_effective = False
            self._claim_prepared_degraded_reason = reason
            log.log(
                level,
                "fifo_claim_prepared requested but NOT activated: %s (claims keep flowing on"
                " the shipped path)",
                reason,
            )

    async def _open_claim_holder(self, stage: str) -> _ClaimHolder:
        """Open one dedicated claim connection + retained cursor (lazy, first flagged claim /
        first claim after a discard). STORE-3 explicitly: the per-statement timeout is applied at
        open AND therefore after every reopen (a reopen IS a fresh open — recycling is disabled;
        any recycle is an eviction event) — the holder bypasses ``_acquire``, which is where the
        per-borrow timeout normally lives, and a silently-unapplied statement timeout once let a
        hung statement hold row X-locks forever. The holder count is bounded by construction:
        only the pooled claimer tasks call the flagged claim, so the per-stage set grows to at
        most the concurrent flagged-claim count = ``pooled_claimers_per_stage`` (the §5 sizing
        function) and never beyond."""
        conn = await self._connect_claim_conn()
        try:
            raw = getattr(conn, "_conn", None)
            if raw is not None:
                raw.timeout = self._settings.command_timeout  # seconds; 0 = no limit (STORE-3)
            else:
                # The exact silently-unapplied-statement-timeout failure STORE-3 exists to kill:
                # never proceed quietly when the raw pyodbc surface is unreachable.
                log.warning(
                    "fifo_claim_prepared: cannot reach the raw pyodbc connection to apply"
                    " command_timeout on a dedicated claim connection (stage %s) — a hung"
                    " statement on it would hold its row locks until the server-side limits"
                    " intervene (STORE-3)",
                    stage,
                )
            cur = await conn.cursor()
        except BaseException:
            # Never leak the freshly-opened connection when the post-connect steps fail or are
            # cancelled — repeated transient failures must not accumulate dedicated connections.
            try:
                await conn.close()
            except Exception:  # noqa: BLE001 - best-effort; the real failure is propagating
                log.debug("claim holder connection close after failed open failed", exc_info=True)
            raise
        self._claim_holders_open += 1
        self._claim_holders_opened_total += 1
        log.info(
            "fifo_claim_prepared: opened dedicated claim connection #%d for stage %s",
            self._claim_holders_opened_total,
            stage,
        )
        return _ClaimHolder(conn, cur)

    async def _connect_claim_conn(self) -> Any:
        """The raw dedicated-connection factory (its own seam so tests can substitute a fake
        without touching the holder lifecycle logic). autocommit=False — the claim owns its
        transaction exactly as on the pooled path."""
        import aioodbc

        return await aioodbc.connect(
            dsn=connection_string(self._settings, posture=self._posture), autocommit=False
        )

    @asynccontextmanager
    async def _claim_holder_ctx(self, stage: str) -> AsyncIterator[_ClaimHolder]:
        """Borrow a dedicated claim holder for one claim call. The §5 eviction/discard policy maps
        EXACTLY onto the exit shape: a normal exit (clean success, the kept≠claimed EMPTY return,
        the 1222 EMPTY return — the normal contention-yield/fence-race signals, which do not
        poison the connection) RETURNS the holder to the free list (worst case one re-prepare
        from the guard's one-slot eviction); ANY raise (cancellation, unclassified error)
        DISCARDS it — defense-in-depth above the shielded guard, never a substitute (the guard's
        M-6 half is connection-topology-independent and runs verbatim either way).

        Sizing (§5 'a stated function of the pooled-claimer concurrency per stage'): the free
        list grows to at most the CONCURRENT flagged-claim count per stage — only the pooled
        claimer tasks call this, so steady state is ``pooled_claimers_per_stage`` holders per
        stage (typically 1); there is no unbounded growth to cap and no recycling (any recycle
        is an eviction event). A holder whose guard reset was swallowed on a kept-exit may
        return with a stale session — shipped-equivalent exposure (the pooled path returns such
        a connection to the aioodbc pool identically); the next claim's guard/commit self-heals.

        A holder that outlives teardown (borrowed while ``close()`` ran, or a straggler claim
        after it) is DISCARDED on return instead of re-retained — a closed store must leak no
        dedicated connection."""
        free = self._claim_holders.setdefault(stage, [])
        holder = free.pop() if free else await self._open_claim_holder(stage)
        try:
            yield holder
        except BaseException:
            await self._discard_claim_holder(stage, holder)
            raise
        else:
            if self._claim_holders_closed:
                # Teardown ran while this claim was in flight: never re-retain a live
                # connection into a closed store (the borrowed-at-teardown leak).
                await self._discard_claim_holder(stage, holder)
            else:
                self._claim_holders.setdefault(stage, []).append(holder)

    async def _discard_claim_holder(self, stage: str, holder: _ClaimHolder) -> None:
        """Close a poisoned (or teardown-orphaned) holder. Shielded like the finally-guard: a
        cancellation delivered at these awaits must not skip ``conn.close()`` (a leaked dedicated
        connection with consistent-looking counters); best-effort — the real outcome is already
        propagating. The next flagged claim opens a fresh holder (re-applying the STORE-3
        timeout)."""
        self._claim_holders_open -= 1
        self._claim_holders_discarded_total += 1
        log.warning(
            "fifo_claim_prepared: discarding dedicated claim connection for stage %s (%d"
            " discarded so far); the next claim reopens",
            stage,
            self._claim_holders_discarded_total,
        )

        async def _close_holder() -> None:
            try:
                await holder.cur.close()
            except Exception:  # noqa: BLE001 - best-effort teardown must not mask the outcome
                log.debug("claim holder cursor close failed", exc_info=True)
            try:
                await holder.conn.close()
            except Exception:  # noqa: BLE001 - best-effort teardown must not mask the outcome
                log.debug("claim holder connection close failed", exc_info=True)

        closer = asyncio.ensure_future(_close_holder())
        try:
            await asyncio.shield(closer)
        except asyncio.CancelledError:
            # The discard itself was cancelled (e.g. a second cancellation during shutdown):
            # let the shielded close finish so the connection never leaks, THEN re-raise.
            await closer
            raise

    async def _close_claim_holders(self) -> None:
        """Teardown: close every retained claim holder and mark the holder set CLOSED (idempotent;
        store close). A holder borrowed by an in-flight claim is not in the free lists — the
        closed flag makes its return path discard (close) it instead of re-retaining it."""
        self._claim_holders_closed = True
        holders = [h for lst in self._claim_holders.values() for h in lst]
        self._claim_holders.clear()
        for holder in holders:
            self._claim_holders_open -= 1
            try:
                await holder.cur.close()
            except Exception:  # noqa: BLE001 - best-effort teardown
                log.debug("claim holder cursor close failed at teardown", exc_info=True)
            try:
                await holder.conn.close()
            except Exception:  # noqa: BLE001 - best-effort teardown
                log.debug("claim holder connection close failed at teardown", exc_info=True)

    # --- PHI-at-rest cipher seam for nullable text columns (mirrors MessageStore._enc/_dec) -----
    # Used for summary/metadata (EF-3) and error/last_error/event.detail (H4). null/empty-safe: a NULL
    # or purged '' stays as-is, never turns into ciphertext-of-empty; decrypt passes legacy plaintext /
    # '' through unchanged on read (so a no-key -> key restart reads pre-existing plaintext correctly).

    # Cell-bound AAD (ASVS 11.3.3, ADR 0019): `aad` is REQUIRED so mypy-strict flags any un-threaded
    # site; the caller passes cell_aad(table, column, *pk). Bound on the shipped aad_bind=true default;
    # ignored when an operator sets aad_bind false (v1 writer + v1 dual-read), so passing it is always
    # safe either way. Mirrors MessageStore._enc/_dec.

    def _enc(self, value: str | None, *, aad: bytes) -> str | None:
        if not value:  # None or "" → leave blank (covers purged/empty values)
            return value
        return self._cipher.encrypt(value, aad=aad)

    def _dec(self, value: str | None, *, aad: bytes) -> str | None:
        if value is None:
            return value
        return self._cipher.decrypt(value, aad=aad)  # '' / legacy plaintext pass through unchanged

    def cipher_info(self) -> CipherInfo:
        """The non-secret at-rest cipher posture (M5): on/off + key fingerprint, never key bytes."""
        return cipher_info(self._cipher)

    def cipher(self) -> Cipher:
        """This store's LIVE at-rest cipher — see :meth:`messagefoundry.store.base.Store.cipher`."""
        return self._cipher

    # --- secret-rotation watch meta (ASVS 13.3.4, BACKLOG #282) ---------------
    # NON-SECRET at-rest state: keyed-MAC / DEK-key-id fingerprints + ISO dates only, never a value.
    # Implementing the narrow SecretRotationMetaStore protocol here engages the engine's structural
    # `isinstance(store, SecretRotationMetaStore)` reconcile on the SQL Server backend (mirrors
    # MessageStore's SQLite implementation).

    def secret_rotation_fingerprint_key(self) -> bytes | None:
        """The DEK-derived HMAC subkey the rotation watcher fingerprints tracked secret values with
        (ASVS 13.3.4). Derived off THIS store's live cipher; ``None`` when keyless / DEK not in heap, in
        which case the watcher tracks only the non-secret DEK key-id stamp. Never returns the DEK."""
        return rotation_fingerprint_key(self._cipher)

    async def get_secret_rotation_meta(self) -> dict[str, SecretRotationMetaRow]:
        """Every persisted secret-rotation watch record, keyed by ``secret_key`` (non-secret dates +
        keyed-MAC fingerprints)."""
        rows = await self._fetchall(
            "SELECT secret_key, fingerprint, tracked_since, last_rotated FROM secret_rotation_meta"
        )
        return {
            r["secret_key"]: SecretRotationMetaRow(
                secret_key=r["secret_key"],
                fingerprint=r["fingerprint"],
                tracked_since=r["tracked_since"],
                last_rotated=r["last_rotated"],
            )
            for r in rows
        }

    async def upsert_secret_rotation_meta(
        self, secret_key: str, *, fingerprint: str, tracked_since: str, last_rotated: str
    ) -> None:
        """Insert or replace one NON-SECRET watch record. Idempotent via a single atomic ``MERGE``
        under ``HOLDLOCK`` (range-locks the PK so two concurrent nodes can't both INSERT), so a re-run —
        or a second cluster node — writing an identical fingerprint/date is a no-op."""
        await self._execute(
            "MERGE secret_rotation_meta WITH (HOLDLOCK) AS t"
            " USING (SELECT ? AS secret_key) AS s ON t.secret_key=s.secret_key"
            " WHEN MATCHED THEN UPDATE SET fingerprint=?, tracked_since=?, last_rotated=?"
            " WHEN NOT MATCHED THEN INSERT (secret_key, fingerprint, tracked_since, last_rotated)"
            " VALUES (?,?,?,?);",
            (
                secret_key,
                fingerprint,
                tracked_since,
                last_rotated,
                secret_key,
                fingerprint,
                tracked_since,
                last_rotated,
            ),
        )

    @classmethod
    async def open(
        cls,
        settings: StoreSettings,
        *,
        cipher: Cipher | None = None,
        audit_mac_key: bytes | None = None,
        audit_mac_fn: AuditMacFn | None = None,
        message_events: str = "all",
        posture: HopPosture | None = None,
    ) -> SqlServerStore:
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
        await cls._ensure_database_options(settings, posture=posture)
        # A DEDICATED EXECUTOR, sized to this pool -- see _build_pool_executor for why sharing the
        # event loop's default one deadlocks rather than merely throttling.
        executor = _build_pool_executor(settings)
        pool = await aioodbc.create_pool(
            dsn=connection_string(settings, posture=posture),
            minsize=1,
            maxsize=max(1, settings.pool_size),
            autocommit=False,
            executor=executor,
        )
        store = cls(
            pool,
            settings,
            cipher=cipher,
            audit_mac_key=audit_mac_key,
            audit_mac_fn=audit_mac_fn,
            message_events=message_events,
            posture=posture,
        )
        store._pool_executor = executor
        try:
            await store._ensure_schema()
            if store._fifo_claim_proc:
                # ADR 0114 sub-lever A startup gate (AC-7): verify the deployed procs (existence +
                # body hash + compat) — a miss degrades LOUDLY to the shipped batch, never a failed
                # open and never a lane outage. Flag OFF skips the probe entirely (zero overhead).
                await store._gate_claim_proc()
            if store._fifo_claim_prepared:
                # ADR 0114 sub-lever B startup gate (AC-13 + the §5 couplings): fail-closed to the
                # fold, retired-not-stacked under a green proc gate, compat >= 130. Runs AFTER the
                # proc gate (it reads that outcome). A miss logs and no-ops — never an outage.
                await store._gate_claim_prepared()
            # ASVS 11.3.4: enable the PERSISTED per-key AES-GCM invocation bound and reserve the first
            # block BEFORE anything on this handle encrypts — the at-rest migration below included, since
            # on a store that is having a key enabled for the first time it is itself a large burst. A
            # no-op when the cipher carries no bound (keyless / `vault_transit`).
            await store.checkpoint_cipher_invocations()
            await store._encrypt_existing_rows()  # one-time PHI-at-rest migration when a key is set
            await store._backfill_audit_chain()  # chain any pre-existing (unhashed) audit rows
            await store._load_audit_chain_meta()  # load/auto-init the #190 keying watermark
            await store._load_state_cache()  # ADR 0005 read-through cache warm-up
            await store._load_reference_cache()  # ADR 0006 reference-snapshot read cache
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
            "SELECT id, ts, actor, action, channel_id, detail, client, row_hash"
            " FROM audit_log ORDER BY id"
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
                client=r["client"],
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
                    await self._commit(conn)
                except Exception:
                    await conn.rollback()
                    raise

    async def _load_audit_chain_meta(self) -> None:
        """Load the #190 audit-chain keying watermark; auto-enable keying from row 1 for a FRESH
        encrypted store (nothing to re-bless). An existing keyless chain stays keyless until the
        explicit :meth:`rekey_audit_chain` migration — never silent (see the SQLite twin)."""
        row = await self._fetchone("SELECT keyed_from_id FROM audit_chain_meta WHERE id=1")
        if row is not None and row["keyed_from_id"] is not None:
            self._audit_keyed_from = int(row["keyed_from_id"])
            return
        if not self._audit_keyed_capable():
            return  # keyless store — the chain stays byte-identical to pre-#190
        cnt = await self._fetchone("SELECT COUNT(*) AS n FROM audit_log")
        if cnt is not None and int(cnt["n"]) == 0:
            async with self._acquire() as conn, self._cursor(conn) as cur:
                try:
                    await cur.execute(
                        "INSERT INTO audit_chain_meta (id, keyed_from_id) VALUES (1, 1)"
                    )
                    await self._commit(conn)
                except Exception:
                    await conn.rollback()
                    raise
            self._audit_keyed_from = 1

    def _audit_append_mac(self) -> tuple[bytes | None, AuditMacFn | None]:
        """The ``(key, mac)`` a NEW ``audit_log`` row is hashed with (#190 / ADR 0138) — see the SQLite
        twin :meth:`~messagefoundry.store.store.MessageStore._audit_append_mac`.

        Prefers the isolated-module MAC (Vault/OpenBao Transit) when present, else the in-heap HMAC key.
        Fail-closed when the chain is keyed but NEITHER secret is in hand: appending a keyless row above
        the watermark would make a legitimately-written row read as tampered under a later keyed
        verify — a FALSE break defeating the #190 guarantee (review major-1; see the SQLite twin)."""
        if self._audit_keyed_from is None:
            return None, None  # keyless chain — byte-identical to pre-#190
        if self._audit_mac_fn is not None:
            return None, self._audit_mac_fn  # keyed inside the isolated module (Transit)
        if self._audit_mac_key is not None:
            return self._audit_mac_key, None  # keyed with the in-heap HMAC key
        raise RuntimeError(
            f"audit chain is keyed (from id={self._audit_keyed_from}) but no store encryption key or "
            "isolated-module MAC is configured; refusing to append a keyless audit row above the watermark"
        )

    def _audit_keyed_capable(self) -> bool:
        """Is a keying secret available? — an in-heap HMAC key (``aesgcm`` mode) OR an isolated-module MAC
        provider (``vault_transit`` mode, ADR 0138). Either keys the chain; neither leaves it keyless."""
        return self._audit_mac_key is not None or self._audit_mac_fn is not None

    async def rekey_audit_chain(
        self, *, expected_anchor: tuple[int, str] | None = None
    ) -> tuple[bool, str]:
        """Non-silent #190-D migration — enable HMAC keying on an existing keyless chain. Refuses
        without a DEK, no-op if already keyed, verifies the existing chain first (refusing on any break),
        then sets the watermark to the next id (never rewrites existing hashes). See the SQLite twin."""
        if not self._audit_keyed_capable():
            return False, "no store encryption key/MAC configured; cannot key the audit chain"
        if self._audit_keyed_from is not None:
            return True, f"audit chain already keyed from id={self._audit_keyed_from}"
        ok, msg = await self.verify_audit_chain(expected_anchor=expected_anchor)
        if not ok:
            return False, f"refusing to key a broken audit chain: {msg}"
        async with self._audit_lock, self._acquire() as conn, self._cursor(conn) as cur:
            try:
                await cur.execute("SELECT COALESCE(MAX(id), 0) AS m FROM audit_log")
                mrow = await cur.fetchone()
                watermark = (int(mrow[0]) if mrow is not None else 0) + 1
                # Single-row upsert (id=1 unique): update if present, else insert.
                await cur.execute(
                    "UPDATE audit_chain_meta SET keyed_from_id=? WHERE id=1", (watermark,)
                )
                if cur.rowcount == 0:
                    await cur.execute(
                        "INSERT INTO audit_chain_meta (id, keyed_from_id) VALUES (1, ?)",
                        (watermark,),
                    )
                await self._commit(conn)
            except Exception:
                await conn.rollback()
                raise
        self._audit_keyed_from = watermark
        return True, f"audit chain keyed from id={watermark}"

    async def _encrypt_existing_rows(self) -> None:
        """Re-encrypt legacy plaintext bodies in place when encryption is enabled (STORE-1).

        Idempotent + batched: skips rows already carrying the ciphertext prefix."""
        if not self._cipher.encrypts:
            return
        # Version-agnostic anchor (M9): `mfenc:%` matches BOTH v1 and v2 ciphertext, so a v2 row is
        # recognised as already-encrypted and skipped — never re-wrapped.
        like = f"{_ENC_MARKER_PREFIX}%"
        total = 0
        # `("outbox", "payload")` was here until the legacy table was migrated + DROPped (ASVS
        # 14.2.7). Leaving it would fail this pass with *Invalid object name 'outbox'* on EVERY keyed
        # open — and the keyed path does not run in CI (every SQL Server leg is keyless), so
        # `tests/test_sqlserver_encrypt_pass_tables.py` is the only mechanism that can catch a stale
        # entry here. Rows the migration folded in are covered by `("queue", "payload")` below: the
        # migration carries the payload over VERBATIM, so a legacy plaintext body arrives unencrypted
        # and this pass — which runs after `_ensure_schema` — seals it on the same open.
        for table, column in (
            ("messages", "raw"),
            ("queue", "payload"),
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
                                (
                                    self._cipher.encrypt(
                                        r[column], aad=cell_aad(table, column, r["id"])
                                    ),
                                    r["id"],
                                ),
                            )
                        await self._commit(conn)
                    except Exception:
                        await conn.rollback()
                        raise
                await self._charge_bound_batch()
                total += len(rows)
        # Nullable id-keyed PHI text columns — each migrated on its own pass with the nullable
        # `<> '' AND IS NOT NULL` guard so a blank/purged '' is never turned into ciphertext-of-empty
        # (the id-keyed loop above omits that guard because raw/payload are never legitimately '').
        #   messages.summary/metadata (id PK) — MRN + patient name (EF-3).
        #   messages.error / queue.last_error / message_events.detail (H4) — may embed raw HL7 fragments
        #     from exceptions; SQL Server at-rest parity with SQLite/Postgres. message_events keys on its
        #     own INT IDENTITY `id` (an integer literal in the UPDATE, like every other id-keyed table).
        # message_events.detail / connection_event.reason / alert_instance.reason have IDENTITY ids
        # (unknown at INSERT; alert_instance also upserts), so they bind cell_aad to insert-time-known
        # natural columns instead and migrate on their own composite passes below (ASVS 11.3.3, ADR 0019).
        for table, ncol in (
            ("messages", "summary"),
            ("messages", "metadata"),
            ("messages", "error"),
            ("queue", "last_error"),
            ("search_presets", "criteria"),  # saved-search preset (ADR 0136) — id-keyed, nullable
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
                                (
                                    self._cipher.encrypt(
                                        r["v"], aad=cell_aad(table, ncol, r["id"])
                                    ),
                                    r["id"],
                                ),
                            )
                        await self._commit(conn)
                    except Exception:
                        await conn.rollback()
                        raise
                await self._charge_bound_batch()
                total += len(rows)
        total += await self._encrypt_existing_identity_composite(
            "message_events", ("message_id", "ts", "event"), "detail", like
        )
        total += await self._encrypt_existing_identity_composite(
            "connection_event", ("connection", "ts", "kind"), "reason", like
        )
        total += await self._encrypt_existing_identity_composite(
            "alert_instance", ("event_type", "connection"), "reason", like
        )
        # `response` body + detail + resp_headers (#154, composite PK) — a separate pass (can't ride the
        # id-keyed loop above). PG/SQLite migrate these too; without it a no-key -> key -> restart leaves
        # captured reply PHI as plaintext at rest. All are nullable, so guard `<> '' AND IS NOT NULL`.
        for rcol in ("body", "detail", "resp_headers"):
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
                                    self._cipher.encrypt(
                                        r["v"],
                                        aad=cell_aad(
                                            "response",
                                            rcol,
                                            r["message_id"],
                                            r["destination_name"],
                                            r["response_seq"],
                                        ),
                                    ),
                                    r["message_id"],
                                    r["destination_name"],
                                    r["response_seq"],
                                ),
                            )
                        await self._commit(conn)
                    except Exception:
                        await conn.rollback()
                        raise
                await self._charge_bound_batch()
                total += len(rows)
        # `reference` snapshot values (#235, composite PK (name, version, [key])) — a separate pass
        # (can't ride the id-keyed loop). NOT "born encrypted": under a no-key deployment
        # IdentityCipher writes plaintext JSON, and the no-key -> key transition is exactly what this
        # method migrates — PG/SQLite migrate these too; values may carry PHI for patient-keyed sets.
        # value is NOT NULL and never legitimately '' (json.dumps is non-empty), so the raw/payload
        # non-null guard shape applies.
        while True:
            rows = await self._fetchall(
                "SELECT TOP (500) name, version, [key], value FROM reference"
                " WHERE value NOT LIKE ? AND value <> ''",
                (like,),
            )
            if not rows:
                break
            async with self._acquire() as conn, self._cursor(conn) as cur:
                try:
                    for r in rows:
                        await cur.execute(
                            "UPDATE reference SET value=? WHERE name=? AND version=? AND [key]=?",
                            (
                                self._cipher.encrypt(
                                    r["value"],
                                    aad=cell_aad(
                                        "reference", "value", r["name"], r["version"], r["key"]
                                    ),
                                ),
                                r["name"],
                                r["version"],
                                r["key"],
                            ),
                        )
                    await self._commit(conn)
                except Exception:
                    await conn.rollback()
                    raise
            await self._charge_bound_batch()
            total += len(rows)
        # `state` transform-state values (ADR 0005, composite PK (namespace, key)) — a separate pass
        # (can't ride the id-keyed loop). SQLite (`store.py`'s dedicated state pass) and Postgres
        # (`_encrypt_existing_composite("state", ...)`) both migrate `state.value`; without this pass a
        # no-key -> key transition on SQL Server alone left legacy state plaintext at rest (#241 F1). Not
        # "born encrypted": under a no-key deployment IdentityCipher writes plaintext JSON, and the
        # no-key -> key transition is exactly what this method migrates. value is NOT NULL and never
        # legitimately '' (json.dumps is non-empty), so the same `<> ''` guard the reference pass uses
        # keeps a purged '' from becoming ciphertext-of-empty.
        while True:
            rows = await self._fetchall(
                "SELECT TOP (500) namespace, [key], value FROM state"
                " WHERE value NOT LIKE ? AND value <> ''",
                (like,),
            )
            if not rows:
                break
            async with self._acquire() as conn, self._cursor(conn) as cur:
                try:
                    for r in rows:
                        await cur.execute(
                            "UPDATE state SET value=? WHERE namespace=? AND [key]=?",
                            (
                                self._cipher.encrypt(
                                    r["value"],
                                    aad=cell_aad("state", "value", r["namespace"], r["key"]),
                                ),
                                r["namespace"],
                                r["key"],
                            ),
                        )
                    await self._commit(conn)
                except Exception:
                    await conn.rollback()
                    raise
            await self._charge_bound_batch()
            total += len(rows)
        if total:
            log.info(
                "encrypted %d existing message/outbox/response/reference/state row(s) at rest",
                total,
            )

    async def _encrypt_existing_identity_composite(
        self, table: str, aad_cols: tuple[str, ...], value_col: str, like: str
    ) -> int:
        """One-time encrypt of a legacy plaintext IDENTITY-id table's ``value_col`` (message_events.detail
        / connection_event.reason / alert_instance.reason). The cell_aad comes from ``aad_cols`` (insert-
        time-known natural columns) while the UPDATE keys on ``id`` — so a natural-column collision can
        never re-write the wrong row (ASVS 11.3.3). Nullable, so the ``<> '' AND IS NOT NULL`` guard."""
        migrated = 0
        pk_select = ", ".join(f"[{c}]" for c in aad_cols)
        while True:
            rows = await self._fetchall(
                f"SELECT TOP (500) id, {pk_select}, {value_col} AS v FROM {table}"
                f" WHERE {value_col} NOT LIKE ? AND {value_col} <> '' AND {value_col} IS NOT NULL",
                (like,),
            )
            if not rows:
                break
            async with self._acquire() as conn, self._cursor(conn) as cur:
                try:
                    for r in rows:
                        aad = cell_aad(table, value_col, *[r[c] for c in aad_cols])
                        await cur.execute(
                            f"UPDATE {table} SET {value_col}=? WHERE id=?",
                            (self._cipher.encrypt(r["v"], aad=aad), r["id"]),
                        )
                    await self._commit(conn)
                except Exception:
                    await conn.rollback()
                    raise
            await self._charge_bound_batch()
            migrated += len(rows)
        return migrated

    @staticmethod
    async def _ensure_database_options(
        settings: StoreSettings, *, posture: HopPosture | None = None
    ) -> None:
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
            conn = await aioodbc.connect(
                dsn=connection_string(settings, posture=posture), autocommit=True
            )
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

    async def require_rcsi_for_pooled(self) -> None:
        """Hard-verify READ_COMMITTED_SNAPSHOT is ON — the pooled claim mode's startup gate (ADR 0066
        §3.3). :meth:`claim_fifo_heads`' STEP-1 discovery is a plain committed-snapshot read whose
        non-blocking guarantee (EMPTY-on-locked-head; a shared claimer connection never pinned in a
        lock-wait) DEPENDS on RCSI. :meth:`_ensure_database_options` force-enables it at open but
        deliberately degrades to a warning on a locked-down DB — acceptable for the per-lane claims
        (they block by design), NOT for pooled mode, which must **fail closed** here rather than
        silently claim with blocking discovery reads. Same state query as the open-time check. The
        runner awaits this at pooled ``start()`` (ADR 0066 §5): under
        ``[pipeline].require_rcsi_for_pooled`` a raise unwinds the start; false downgrades it to a
        loud warning + a ``/stats`` degraded gauge. Raises with the exact DBA remediation statement."""
        row = await self._fetchone(
            "SELECT is_read_committed_snapshot_on FROM sys.databases WHERE name = DB_NAME()"
        )
        if row is None or not row["is_read_committed_snapshot_on"]:
            db = self._settings.database
            raise RuntimeError(
                f"pooled claim mode requires READ_COMMITTED_SNAPSHOT on database {db!r} and it is"
                f" OFF; a DBA must run once: ALTER DATABASE [{db}] SET READ_COMMITTED_SNAPSHOT ON"
                " WITH ROLLBACK IMMEDIATE — refusing to start pooled claimers (fail closed)"
            )

    async def _ensure_schema(self) -> bool:
        """Apply the shipped DDL batch, or skip it entirely when the ``schema_meta`` marker already
        records this exact batch (ADR 0064). Returns ``True`` iff the batch ran."""
        expected = _schema_hash()
        async with self._acquire() as conn, self._cursor(conn) as cur:
            try:
                # FAST PATH (ADR 0064): the marker says this exact DDL batch already ran — skip the
                # batch AND the exclusive schema applock. Re-running the full guarded batch under one
                # exclusive applock on EVERY open made N concurrent opens convoy (WS-B Finding 2: a
                # loser blows the 30s lock timeout → startup failure). The probe is two cheap SELECTs
                # under the normal command timeout; a virgin/pre-marker DB falls through to the full
                # run. Out-of-band drift (an operator hand-dropping an object) is no longer healed on
                # every open — the remedy is `DELETE FROM schema_meta`, which forces one full run.
                if await self._schema_marker_current(cur, expected):
                    await self._commit(conn)  # close the probe's read txn (autocommit=False pool)
                    log.debug("sqlserver: schema current (%s…) — DDL batch skipped", expected[:12])
                    return False
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
                # Double-check under the lock: the peer we queued behind may have just applied this
                # exact batch and committed its marker — then this open has nothing to do.
                if await self._schema_marker_current(cur, expected):
                    await self._commit(conn)  # releases the txn-scoped applock
                    log.debug("sqlserver: schema applied by a peer (%s…) — skipped", expected[:12])
                    return False
                for statement in _SCHEMA:
                    await cur.execute(statement)
                await cur.execute("DELETE FROM schema_meta WHERE id=1")
                await cur.execute(
                    "INSERT INTO schema_meta (id, schema_hash, applied_at) VALUES (1, ?, ?)",
                    (expected, time.time()),
                )
                await self._commit(conn)
                log.info("sqlserver: schema DDL batch applied (%s…)", expected[:12])
                return True
            except Exception:
                await conn.rollback()  # roll back the partial DDL batch (M-6)
                raise

    @staticmethod
    async def _schema_marker_current(cur: Any, expected: str) -> bool:
        """True iff ``schema_meta`` exists and records exactly ``expected``. Existence is probed via
        ``OBJECT_ID`` (a NULL row, never an exception) so a virgin DB falls through cleanly."""
        await cur.execute("SELECT OBJECT_ID('schema_meta','U')")
        row = await cur.fetchone()
        if row is None or row[0] is None:
            return False
        await cur.execute("SELECT schema_hash FROM schema_meta WHERE id=1")
        row = await cur.fetchone()
        return bool(row is not None and row[0] == expected)

    async def close(self) -> None:
        # ASVS 11.3.4: charge whatever this process spent BEYOND its reserved block before the store
        # goes away, so a long burst that outran the refill cadence (`rotate-key` re-encrypting a whole
        # store in one offline process is the extreme case) is accounted rather than lost. Best-effort:
        # a failing settlement must never turn a clean shutdown into an error.
        try:
            await self.checkpoint_cipher_invocations(settle=True)
        except Exception:  # noqa: BLE001 — shutdown best-effort; log and continue
            log.warning("could not settle the AES-GCM invocation bound at close", exc_info=True)
        # Tear down any synchronous fused-handoff pools first (best-effort; a no-op when none were
        # opened, so it never affects the async path). ADR 0071 B5.
        self.close_sync_handoff_pool()
        # ADR 0114 sub-lever B: close the store-owned dedicated claim holders (a no-op when the
        # prepared path never opened one).
        await self._close_claim_holders()
        # THE EXECUTOR IS RELEASED IN A finally, and that ordering is the point. wait_closed() cannot
        # complete while the pool is wedged -- which is precisely the state these threads are stuck in --
        # so releasing them only on the success path would leak the whole pool's worth of threads in the
        # one case that matters. shutdown(wait=False) does not join: a wedged ODBC call is not
        # interruptible, and the process is going away regardless.
        try:
            self._pool.close()
            await self._pool.wait_closed()
        finally:
            if self._pool_executor is not None:
                self._pool_executor.shutdown(wait=False)
                self._pool_executor = None

    # --- ADR 0071 B5: synchronous fused-handoff connection source ------------
    def open_sync_handoff_pool(self, stage: str, size: int) -> _SyncHandoffPool:
        """Build (and register) a dedicated pool of ``size`` synchronous pyodbc connections for the
        fused handoff hop of ``stage`` (``"routed"`` or ``"outbound"``) — ADR 0071 §5.1. Distinct from
        the aioodbc async pool: these connections are ``autocommit=False`` and are driven synchronously
        from a worker thread by :meth:`route_handoff_sync` / :meth:`transform_handoff_sync`.

        **Fail-closed on ``command_timeout==0``** (raises :class:`SyncHandoffUnavailable`): a 0 command
        timeout maps the finalize ``sp_getapplock`` to ``@LockTimeout=-1`` (wait forever), which on a
        worker thread could pin a fused-executor slot indefinitely. Each connection is given a FINITE
        per-statement ``conn.timeout`` (independent of the pyodbc login timeout) so a fused hop can
        never block unboundedly. Re-opening the same ``stage`` closes the prior pool first. Blocking
        (opens real connections) — the future caller runs it off the loop at startup, not on the hot
        path."""
        ct = self._settings.command_timeout
        if ct == 0:
            raise SyncHandoffUnavailable(
                "synchronous fused handoff requires a finite [store].command_timeout (> 0); it is 0 "
                "(unbounded), which would let the finalize sp_getapplock wait forever on a worker "
                "thread — refusing to build the sync handoff pool (fusion unavailable)"
            )
        if size < 1:
            raise ValueError(f"sync handoff pool size must be >= 1 (got {size})")
        import pyodbc

        dsn = connection_string(self._settings, posture=self._posture)

        def _factory() -> Any:
            conn = pyodbc.connect(dsn, autocommit=False)
            conn.timeout = ct  # seconds; finite (ct==0 refused above) — per-statement bound
            return conn

        # Build the new pool FIRST (opens its connections; may raise). Only on success do we replace
        # the existing pool for this stage — a failed rebuild leaves the prior pool intact.
        pool = _SyncHandoffPool(_factory, size, conn_timeout=ct)
        old = self._sync_pools.pop(stage, None)
        if old is not None:
            old.close()
        self._sync_pools[stage] = pool
        return pool

    def sync_handoff_pool(self, stage: str) -> _SyncHandoffPool:
        """The synchronous fused-handoff pool for ``stage``. Raises ``KeyError`` if not yet opened."""
        return self._sync_pools[stage]

    def close_sync_handoff_pool(self) -> None:
        """Close and drop every synchronous fused-handoff pool (idempotent; safe when none exist)."""
        pools = list(self._sync_pools.values())
        self._sync_pools.clear()
        for pool in pools:
            pool.close()

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
        acquired connection or its release.

        BACKLOG #1052: that same chokepoint is where the borrow is BOUNDED. ``Connection Timeout``
        bounds the login and ``command_timeout`` the statement; neither bounds the wait for a free
        pooled connection, so a wedged pool blocked the acquiring task forever. ``acquire_pooled``
        raises :class:`~messagefoundry.store.base.StoreAcquireTimeout` at
        ``[store].acquire_timeout``, which every caller's ``except Exception`` already treats as a
        transient stage failure. The ``async with pool.acquire()`` became an explicit
        acquire/release only because the bound has to sit between the two; aioodbc's context manager
        does nothing on exit but ``await pool.release(conn)`` (0.5.0 ``utils.py:86-103``), and the
        ADR 0159 ordering below is preserved exactly — the quarantine still runs BEFORE the release,
        which is what makes a poisoned connection unlendable."""
        t0 = perf_counter()
        conn = await acquire_pooled(
            self._pool, timeout=self._settings.acquire_timeout, backend="sqlserver"
        )
        self._acquire_wait.record((perf_counter() - t0) * 1000.0)
        try:
            raw = getattr(conn, "_conn", None)
            if raw is not None:
                raw.timeout = self._settings.command_timeout  # seconds; 0 = no limit
            try:
                yield conn
            except BaseException as exc:
                # BACKLOG #348 / ADR 0159. Every caller's own handler is `except Exception` (90 of
                # the 91 _acquire sites), so an ordinary error has ALREADY rolled back by the time it
                # reaches here — leave that path exactly as it was, connection recycled. A
                # CancelledError derives from BaseException, so NONE of those handlers ran: the body
                # is unwinding with its transaction still open and its X locks still held, and
                # aioodbc's pool does not compensate (`Pool.release()` appends a non-closed
                # connection straight back onto the free deque — 0.5.0 pool.py:196-205 — and
                # `_ContextManager.__aexit__` releases identically on the exception path). Quarantine
                # it so the next borrower can never inherit it.
                if not isinstance(exc, Exception):
                    await self._release_dirty(conn)
                raise
        finally:
            await self._pool.release(conn)

    async def _release_dirty(self, conn: Any) -> None:
        """Quarantine a pooled connection whose transaction was abandoned by a cancellation, so it
        can never be lent to another caller (BACKLOG #348, ADR 0159).

        **The load-bearing line is the synchronous one.** aioodbc derives ``Connection.closed`` from
        ``self._conn`` (0.5.0 connection.py:89-93) and ``Pool.release()`` re-adds a connection to the
        free deque only ``if not conn.closed`` (pool.py:200-204) — so dropping the handle is a plain
        attribute write that makes the connection unlendable with **no await in front of it**. That
        matters: shutdown cancels the lane task and the gather can cancel it AGAIN, so any cleanup
        that awaits *before* containing the poison is defeated by the second cancellation and
        silently restores the bug. Ordering here is the guarantee; the close below is only hygiene.

        Closing the raw handle is then best-effort, off the event loop, and time-boxed. pyodbc's
        ``close()`` rolls back uncommitted work (DBAPI), which is what actually frees the X locks —
        but it runs on a worker thread that may still hold the abandoned statement, so it is never
        awaited unbounded on a shutdown/demotion path. On expiry the close finishes detached; the
        pool has already lost the connection and reopens on demand (``size`` is derived, so the pool
        simply shrinks). This costs one reconnect per cancelled call — paid only on a path that was
        previously corrupting the pool.
        """
        raw = getattr(conn, "_conn", None)
        if raw is None:  # already closed/quarantined — nothing lendable to contain
            return
        conn._conn = None  # ← MUST stay first, and MUST stay await-free
        closer = asyncio.ensure_future(asyncio.to_thread(raw.close))
        try:
            await asyncio.wait_for(asyncio.shield(closer), _DIRTY_CLOSE_TIMEOUT)
        except (TimeoutError, asyncio.CancelledError):
            # Expired, or a further cancellation landed while we waited. Either way the connection is
            # already out of the pool; let the close land on its own. Swallowed deliberately — the
            # caller re-raises the ORIGINAL cancellation, which is the outcome that must propagate.
            log.debug(
                "sqlserver: quarantined connection close did not complete within %.1fs; it will"
                " finish detached (the connection is already out of the pool)",
                _DIRTY_CLOSE_TIMEOUT,
            )
        except Exception:  # noqa: BLE001 - a close failure must not mask the cancellation
            log.debug("sqlserver: quarantined connection close failed", exc_info=True)

    def pool_status(self) -> PoolStatus | None:
        """The aioodbc pool snapshot (B11): size/idle occupancy + the PRIMARY acquire-wait percentiles.

        ``size``/``freesize`` are the aioodbc ``Pool`` properties (verified against the pinned
        ``aioodbc==0.5.0``): ``size`` is the connections currently open, ``freesize`` the currently-free
        ones. Synchronous + cheap (cached counters + an in-process histogram snapshot — no DB
        round-trip). With the ADR 0114 prepared claim path active, the additive ``claim_pool``
        sibling reports the store-owned dedicated claim holders (they live OUTSIDE this pool, so
        the B11 connection-budget arithmetic would otherwise under-count)."""
        claim_pool = None
        if self._claim_prepared_effective:
            claim_pool = ClaimPoolStatus(
                open=self._claim_holders_open,
                idle=sum(len(lst) for lst in self._claim_holders.values()),
                opened_total=self._claim_holders_opened_total,
                discarded_total=self._claim_holders_discarded_total,
            )
        return PoolStatus(
            backend="sqlserver",
            max_size=self._pool.maxsize,
            size=self._pool.size,
            idle=self._pool.freesize,
            acquire_wait=self._acquire_wait.summary(),
            claim_pool=claim_pool,
        )

    def claim_proc_status(self) -> ClaimProcStatus | None:
        """The ADR 0114 sub-lever A startup-gate verdict — AC-7's **degraded gauge** (``/status``,
        ``/metrics``, the console's store panel).

        ``None`` when ``fifo_claim_proc`` is off, so "not requested" stays distinguishable from
        "requested and degraded"; otherwise the gate's own recorded outcome. Synchronous and free —
        it copies three attributes ``open()`` set once, no DB round-trip. Read-only: nothing here
        feeds the claim path, and the accept/degrade decision is not re-evaluated."""
        if not self._fifo_claim_proc:
            return None
        return ClaimProcStatus(
            effective=self._claim_proc_effective,
            degraded_reason=self._claim_proc_degraded_reason,
            head_forms=dict(self._claim_proc_head_forms),
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
                # Read-snapshot release, NOT a durable write — commit without counting (A1). This is the
                # single read helper (_fetchone delegates here); routing every read through _commit was
                # what made committed_txns a superset of the write cost model on a live SQL Server.
                await self._commit_read(conn)
            except Exception:
                # autocommit=False: a failed read otherwise leaves the pooled connection mid-txn (and
                # under RCSI an open snapshot pins the version store / bloats tempdb). Roll back before
                # it returns to the pool so the next borrower starts clean (M-6).
                await conn.rollback()
                raise
        return [dict(zip(columns, row)) for row in rows]  # noqa: B905

    async def _fetchone(self, sql: str, params: tuple[Any, ...] = ()) -> dict[str, Any] | None:
        rows = await self._fetchall(sql, params)
        return rows[0] if rows else None

    async def _execute(self, sql: str, params: tuple[Any, ...] = ()) -> None:
        """Run a single write statement (or T-SQL batch) in its own committed transaction."""
        async with self._acquire() as conn, self._cursor(conn) as cur:
            try:
                await cur.execute(sql, params)
                await self._commit(conn)
            except Exception:
                await conn.rollback()
                raise

    def _event_stmt(
        self,
        message_id: str,
        event: str,
        destination: str | None,
        detail: str | None,
        now: float,
    ) -> tuple[str, tuple[Any, ...]]:
        """Build the ``(sql, params)`` for one message-event insert — the SINGLE source of the event
        statement shared by the async :meth:`_event`, the sync twin :meth:`_event_sync`, and the batched
        handoff (ADR 0075). PHI chokepoint (#120): scrub HL7-shaped content out of the detail, THEN
        encrypt it at rest via the store cipher (null/blank-safe) — SQL Server at-rest parity with
        SQLite/Postgres (H4). The scrub is defense-in-depth kept *around* the cipher, exactly as SQLite
        does. Centralizing it here means the three emissions can never drift in the scrub/encrypt of the
        detail."""
        detail = safe_text(detail) if detail else detail
        return (
            _SQL_INSERT_EVENT,
            _event_params(
                message_id,
                now,
                event,
                destination,
                self._enc(detail, aad=cell_aad("message_events", "detail", message_id, now, event)),
            ),
        )

    async def _event(
        self,
        cur: Any,
        message_id: str,
        event: str,
        destination: str | None,
        detail: str | None,
        now: float,
    ) -> None:
        if not should_record_event(event, self._message_events):
            return  # #63 verbosity gate — floor events always pass; routine ones thinnable
        sql, params = self._event_stmt(message_id, event, destination, detail, now)
        await cur.execute(sql, params)

    def _event_sync(
        self,
        cur: Any,
        message_id: str,
        event: str,
        destination: str | None,
        detail: str | None,
        now: float,
    ) -> None:
        """Synchronous twin of :meth:`_event` (ADR 0071 B5). Same scrub-then-encrypt chokepoint, same
        constant + param-builder (via :meth:`_event_stmt`), over a synchronous pyodbc cursor."""
        if not should_record_event(event, self._message_events):
            return  # #63 verbosity gate — floor events always pass; routine ones thinnable
        sql, params = self._event_stmt(message_id, event, destination, detail, now)
        cur.execute(sql, params)

    async def _execute_group(self, cur: Any, group: Sequence[tuple[str, tuple[Any, ...]]]) -> None:
        """Execute one ADR 0075 batch group as a SINGLE round-trip. A 1-statement group runs the raw
        statement (byte-identical to the unbatched execute); a >=2 statement group is rendered by
        :func:`_render_batch` (``SET NOCOUNT ON`` + ``;``-joined) and folds into one ``execute()``. A
        result-consuming group is arranged so its read statement is LAST, so the caller reads it right
        after with ``fetchone`` / ``fetchall`` exactly as on the unbatched path.

        The ``record_logical`` hook is a TEST-ONLY seam: a recording cursor may capture the pre-render
        logical statements so the golden-SQL test can compare the batched logical sequence against the
        unbatched one byte-for-byte (the rendered batch string cannot be safely re-split — statements
        such as ``_SQL_APPLOCK`` / ``_SQL_STATE_MERGE`` contain intra-statement ``;``). A real pyodbc
        cursor has no such attribute, so the branch is skipped in production."""
        rec = getattr(cur, "record_logical", None)
        if rec is not None:
            rec(list(group))
        if len(group) == 1:
            sql, params = group[0]
            await cur.execute(sql, params)
        else:
            sql, params = _render_batch(group)
            await cur.execute(sql, params)

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
        timeout_ms = _applock_timeout_ms(self._settings.command_timeout)
        await cur.execute(_SQL_APPLOCK, _applock_params(resource, timeout_ms))
        row = await cur.fetchone()
        _applock_result(row, resource)

    def _applock_sync(self, cur: Any, resource: str) -> None:
        """Synchronous twin of :meth:`_applock` (ADR 0071 B5). Same constant + timeout formula + rc
        check over a synchronous pyodbc cursor. The caller MUST be in an open (autocommit=False)
        transaction whose leading statement already opened it (the finalize applock is never a
        transaction's first statement)."""
        timeout_ms = _applock_timeout_ms(self._settings.command_timeout)
        cur.execute(_SQL_APPLOCK, _applock_params(resource, timeout_ms))
        row = cur.fetchone()
        _applock_result(row, resource)

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
        handler ran, delivered nothing) — or NOT_DEPLOYED (#233) when a not_deployed event shows those
        zero deliveries were declines to present-but-not-deployed targets; else leave (UNROUTED/ERROR/
        in-progress not clobbered)."""
        # A per-message NAMED lock — NOT a messages-row lock, which would invert the queue->messages
        # lock order the producers take and deadlock (error 1205). Re-entrant; released at commit.
        await self._applock(cur, f"mefor:finalize:{message_id}")
        await cur.execute(_SQL_FINALIZE_COUNT, (message_id,))
        rows = await cur.fetchall()
        action, status = _finalize_from_queue_rows(rows)
        if action == "check_message":
            # No queue rows remain: the router/handlers produced no delivery. FILTERED only if it was
            # actually routed (or NOT_DEPLOYED per the folded #233 flag); never clobber UNROUTED /
            # ERROR / a status already set terminal. fetchall (not a lone fetchone) reads the status
            # (+ flag) AND drains the SELECT so the same-cursor UPDATE below is clean; `_cursor` (EF-6)
            # closes the cursor at the caller's block exit. One read — the not_deployed presence is
            # folded into this SELECT (no extra round-trip).
            await cur.execute(_SQL_SELECT_MESSAGE_STATUS, (NOT_DEPLOYED_EVENT, message_id))
            mrows = await cur.fetchall()
            action, status = _finalize_from_message_status(mrows)
        if action == "update" and status is not None:
            await cur.execute(
                _SQL_UPDATE_MESSAGE_STATUS, _update_message_status_params(status, message_id)
            )

    def _maybe_finalize_sync(self, cur: Any, message_id: str, now: float) -> None:
        """Synchronous twin of :meth:`_maybe_finalize` (ADR 0071 B5). Same applock -> GROUP BY ->
        precedence -> UPDATE sequence over a synchronous pyodbc cursor, sharing the pure precedence
        helpers so the disposition logic can never drift from the async finalizer."""
        self._applock_sync(cur, f"mefor:finalize:{message_id}")
        cur.execute(_SQL_FINALIZE_COUNT, (message_id,))
        rows = cur.fetchall()
        action, status = _finalize_from_queue_rows(rows)
        if action == "check_message":
            cur.execute(_SQL_SELECT_MESSAGE_STATUS, (NOT_DEPLOYED_EVENT, message_id))
            mrows = cur.fetchall()  # #233 flag folded into column 1 (one read)
            action, status = _finalize_from_message_status(mrows)
        if action == "update" and status is not None:
            cur.execute(
                _SQL_UPDATE_MESSAGE_STATUS, _update_message_status_params(status, message_id)
            )

    async def _maybe_finalize_batched(
        self, acc: _BatchAccumulator, message_id: str, now: float
    ) -> None:
        """Batched form of :meth:`_maybe_finalize` (ADR 0075). Emits the IDENTICAL applock -> GROUP BY
        -> [status] -> UPDATE sequence through the accumulator, sharing the SAME constants + precedence
        helpers so the disposition logic can never drift.

        Round-trip structure (STRICT / applock_hard fold): the finalize ``sp_getapplock`` is kept a
        result-consuming GATE — it CLOSES the group that carries the preceding body DML (the ``transformed``
        event, etc.), and its rc is read + validated BEFORE any later statement is issued. So the finalize
        UPDATE is only ever SENT after the client has confirmed the lock is held (rc>=0) — identical
        ordering to today's unbatched finalize, with no unserialized write on the wire. The GROUP BY (and
        the no-rows status read) each stay their own read boundary because their result chooses the UPDATE
        target."""
        resource = f"mefor:finalize:{message_id}"
        timeout_ms = _applock_timeout_ms(self._settings.command_timeout)
        # applock ends the pending body group (read + validate rc; raise on rc<0 -> whole-txn rollback).
        arow = await acc.read_one(_SQL_APPLOCK, _applock_params(resource, timeout_ms))
        _applock_result(arow, resource)
        rows = await acc.read_all(_SQL_FINALIZE_COUNT, (message_id,))
        action, status = _finalize_from_queue_rows(rows)
        if action == "check_message":
            # One read; the #233 not_deployed flag is folded into column 1. A declined-only handler
            # stays on the unbatched path (transform_handoff excludes `declined` from batching), so on
            # this path the flag is 0 unless a SIBLING unbatched handler recorded a decline first — in
            # which case the batched finalize that runs last still reads it here and emits NOT_DEPLOYED.
            mrows = await acc.read_all(_SQL_SELECT_MESSAGE_STATUS, (NOT_DEPLOYED_EVENT, message_id))
            action, status = _finalize_from_message_status(mrows)
        if action == "update" and status is not None:
            acc.add(_SQL_UPDATE_MESSAGE_STATUS, _update_message_status_params(status, message_id))

    @staticmethod
    def _message_filter(
        channel_id: str | None,
        status: str | None,
        message_type: str | None,
        control_id: str | None,
        allowed_channels: Sequence[str] | None = None,
        received_from: float | None = None,
        received_to: float | None = None,
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
        # received_at epoch range: [received_from, received_to) — the message-log date filter (#4b).
        if received_from is not None:
            clauses.append("received_at >= ?")
            params.append(received_from)
        if received_to is not None:
            clauses.append("received_at < ?")
            params.append(received_to)
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
                        self._cipher.encrypt(raw, aad=cell_aad("messages", "raw", mid)),
                        status,
                        None,
                        # EF-3: MRN/name is PHI — ciphered at rest
                        self._enc(summary, aad=cell_aad("messages", "summary", mid)),
                        self._enc(metadata, aad=cell_aad("messages", "metadata", mid)),
                    ),
                )
                for dest_name, payload in deliveries:
                    # Hoist the row id so the payload binds to its own (queue, payload, id) cell.
                    row_id = uuid4().hex
                    await cur.execute(
                        "INSERT INTO queue (id, message_id, stage, channel_id, destination_name,"
                        " handler_name, payload, status, attempts, next_attempt_at, owner,"
                        " lease_expires_at, created_at, updated_at)"
                        " VALUES (?,?,?,?,?,NULL,?,?,0,?,NULL,NULL,?,?)",
                        (
                            row_id,
                            mid,
                            Stage.OUTBOUND.value,
                            channel_id,
                            dest_name,
                            self._cipher.encrypt(payload, aad=cell_aad("queue", "payload", row_id)),
                            OutboxStatus.PENDING.value,
                            now,
                            now,
                            now,
                        ),
                    )
                await self._event(
                    cur, mid, "received", None, f"{len(deliveries)} destination(s)", now
                )
                await self._commit(conn)
            except Exception:
                await conn.rollback()
                raise
        return mid

    async def _insert_outbound(
        self, cur: Any, message_id: str, channel_id: str, dest_name: str, payload: str, now: float
    ) -> None:
        """Insert one ``stage='outbound'`` queue row (lane = destination_name)."""
        row_id = uuid4().hex  # hoisted so the payload binds to its own (queue, payload, id) cell
        await cur.execute(
            _SQL_INSERT_QUEUE_OUTBOUND,
            _insert_outbound_params(
                row_id,
                message_id,
                channel_id,
                dest_name,
                self._cipher.encrypt(payload, aad=cell_aad("queue", "payload", row_id)),
                now,
            ),
        )
        self.body_copies += (
            1  # A1: one inline transformed-body copy per delivery (no fan-out dedup)
        )

    def _insert_outbound_sync(
        self, cur: Any, message_id: str, channel_id: str, dest_name: str, payload: str, now: float
    ) -> None:
        """Synchronous twin of :meth:`_insert_outbound` (ADR 0071 B5)."""
        row_id = uuid4().hex  # hoisted so the payload binds to its own (queue, payload, id) cell
        cur.execute(
            _SQL_INSERT_QUEUE_OUTBOUND,
            _insert_outbound_params(
                row_id,
                message_id,
                channel_id,
                dest_name,
                self._cipher.encrypt(payload, aad=cell_aad("queue", "payload", row_id)),
                now,
            ),
        )
        self.body_copies += 1  # A1: parity with the async _insert_outbound

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
        row_id = uuid4().hex  # hoisted so the payload binds to its own (queue, payload, id) cell
        await cur.execute(
            _SQL_INSERT_QUEUE_ROUTED,
            _insert_routed_params(
                row_id,
                message_id,
                channel_id,
                handler_name,
                self._cipher.encrypt(payload, aad=cell_aad("queue", "payload", row_id)),
                now,
            ),
        )
        self.body_copies += 1  # A1: each routed row carries a full raw copy (H copies per message)

    def _insert_routed_sync(
        self,
        cur: Any,
        message_id: str,
        channel_id: str,
        handler_name: str,
        payload: str,
        now: float,
    ) -> None:
        """Synchronous twin of :meth:`_insert_routed` (ADR 0071 B5)."""
        row_id = uuid4().hex  # hoisted so the payload binds to its own (queue, payload, id) cell
        cur.execute(
            _SQL_INSERT_QUEUE_ROUTED,
            _insert_routed_params(
                row_id,
                message_id,
                channel_id,
                handler_name,
                self._cipher.encrypt(payload, aad=cell_aad("queue", "payload", row_id)),
                now,
            ),
        )
        self.body_copies += 1  # A1: parity with the async _insert_routed

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
        await cur.execute(_SQL_SELECT_MESSAGE_EXISTS, (new_mid,))
        if await cur.fetchone() is None:
            child_meta = _passthrough_child_meta(parent_id, root, child_depth)
            await cur.execute(
                _SQL_INSERT_MESSAGE,
                _insert_message_params(
                    new_mid,
                    pt_channel,
                    now,
                    "passthrough",
                    None,
                    None,
                    self._cipher.encrypt(body, aad=cell_aad("messages", "raw", new_mid)),
                    MessageStatus.RECEIVED.value,
                    None,
                    None,
                    self._enc(child_meta, aad=cell_aad("messages", "metadata", new_mid)),
                ),
            )
            pt_ingress_id = uuid4().hex  # hoisted so the payload binds to its own queue cell
            await cur.execute(
                _SQL_INSERT_QUEUE_INGRESS,
                _insert_queue_ingress_params(
                    pt_ingress_id,
                    new_mid,
                    pt_channel,
                    self._cipher.encrypt(body, aad=cell_aad("queue", "payload", pt_ingress_id)),
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

    def _insert_passthrough_child_mssql_sync(
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
        """Synchronous twin of :meth:`_insert_passthrough_child_mssql` (ADR 0071 B5). Same depth math,
        same content-addressed child id, same constant + builder sequence over a synchronous cursor."""
        child_depth = int(parent_meta.get("correlation_depth", 0) or 0) + 1
        root = parent_meta.get("correlation_root_id") or parent_id
        if child_depth > correlation_depth_cap:
            self._event_sync(
                cur,
                parent_id,
                "passthrough_dropped",
                pt_channel,
                f"depth cap ({child_depth} > {correlation_depth_cap})",
                now,
            )
            return False
        new_mid = MessageStore._passthrough_message_id(routed_id, pt_channel, body)
        cur.execute(_SQL_SELECT_MESSAGE_EXISTS, (new_mid,))
        if cur.fetchone() is None:
            child_meta = _passthrough_child_meta(parent_id, root, child_depth)
            cur.execute(
                _SQL_INSERT_MESSAGE,
                _insert_message_params(
                    new_mid,
                    pt_channel,
                    now,
                    "passthrough",
                    None,
                    None,
                    self._cipher.encrypt(body, aad=cell_aad("messages", "raw", new_mid)),
                    MessageStatus.RECEIVED.value,
                    None,
                    None,
                    self._enc(child_meta, aad=cell_aad("messages", "metadata", new_mid)),
                ),
            )
            pt_ingress_id = uuid4().hex  # hoisted so the payload binds to its own queue cell
            cur.execute(
                _SQL_INSERT_QUEUE_INGRESS,
                _insert_queue_ingress_params(
                    pt_ingress_id,
                    new_mid,
                    pt_channel,
                    self._cipher.encrypt(body, aad=cell_aad("queue", "payload", pt_ingress_id)),
                    now,
                ),
            )
            self._event_sync(
                cur, new_mid, "received", None, f"passthrough from {parent_id} -> {pt_channel}", now
            )
            self._event_sync(
                cur, parent_id, "passthrough", pt_channel, f"-> {new_mid} depth {child_depth}", now
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
        marker_id = uuid4().hex  # hoisted so the (empty) marker payload binds to its own queue cell
        await cur.execute(
            _SQL_INSERT_QUEUE_OUTBOUND,
            _insert_marker_params(
                marker_id,
                parent_id,
                pt_name,
                self._cipher.encrypt("", aad=cell_aad("queue", "payload", marker_id)),
                status,
                now,
            ),
        )
        if produced:
            await self._event(cur, parent_id, "delivered", pt_name, "passthrough re-ingress", now)
        else:
            await self._event(cur, parent_id, "dead", pt_name, "passthrough depth cap", now)

    def _insert_passthrough_marker_mssql_sync(
        self, cur: Any, parent_id: str, pt_name: str, produced: bool, now: float
    ) -> None:
        """Synchronous twin of :meth:`_insert_passthrough_marker_mssql` (ADR 0071 B5)."""
        status = OutboxStatus.DONE.value if produced else OutboxStatus.DEAD.value
        marker_id = uuid4().hex  # hoisted so the (empty) marker payload binds to its own queue cell
        cur.execute(
            _SQL_INSERT_QUEUE_OUTBOUND,
            _insert_marker_params(
                marker_id,
                parent_id,
                pt_name,
                self._cipher.encrypt("", aad=cell_aad("queue", "payload", marker_id)),
                status,
                now,
            ),
        )
        if produced:
            self._event_sync(cur, parent_id, "delivered", pt_name, "passthrough re-ingress", now)
        else:
            self._event_sync(cur, parent_id, "dead", pt_name, "passthrough depth cap", now)

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
        """Durably persist a freshly-received raw message to the ingress stage (status RECEIVED + one
        ``stage='ingress'`` queue row holding the raw) in ONE transaction — the staged pipeline's
        ACK-on-receipt boundary (ADR 0001). The inbound may be ACKed once this returns. Returns the
        message id.

        ``attachment_refs`` (#149, ADR 0105 Phase 4) are the content addresses of documents the ingress
        detach lifted out of ``raw`` into the attachment substrate (``put_attachment``, which committed
        them at ``refcount=0``). Each distinct ref is **increffed in this same transaction** as the
        skeleton row — the two-object commit's second half — AND its ``message_attachment`` linkage row
        is inserted (Phase 3a). A missing ref fails loud → the whole ingress rolls back → no ACK for a
        body we couldn't reference (content-addressing dedups the sender's resend; the startup sweep
        reclaims the orphan). Empty/None → the byte-identical no-detach path."""
        now = time.time() if now is None else now
        mid = uuid4().hex
        # Distinct refs only: a skeleton naming the same content-addressed document twice increfs it once
        # (== its live join rows), so a later release decrefs by the same count.
        refs = list(dict.fromkeys(attachment_refs or ()))
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
                        self._cipher.encrypt(raw, aad=cell_aad("messages", "raw", mid)),
                        MessageStatus.RECEIVED.value,
                        None,
                        # EF-3: MRN/name is PHI — ciphered at rest
                        self._enc(summary, aad=cell_aad("messages", "summary", mid)),
                        self._enc(metadata, aad=cell_aad("messages", "metadata", mid)),
                    ),
                )
                # ingest-time (ADR 0009) + metrics only; per-lane FIFO orders by seq (IDENTITY) — ADR 0059.
                created_at = now
                # Hoist the row id so the ingress payload binds to its own (queue, payload, id) cell.
                ingress_row_id = uuid4().hex
                await cur.execute(
                    "INSERT INTO queue (id, message_id, stage, channel_id, destination_name,"
                    " handler_name, payload, status, attempts, next_attempt_at, owner,"
                    " lease_expires_at, created_at, updated_at)"
                    " VALUES (?,?,?,?,NULL,NULL,?,?,0,?,NULL,NULL,?,?)",
                    (
                        ingress_row_id,
                        mid,
                        Stage.INGRESS.value,
                        channel_id,
                        self._cipher.encrypt(raw, aad=cell_aad("queue", "payload", ingress_row_id)),
                        OutboxStatus.PENDING.value,
                        now,
                        created_at,
                        now,
                    ),
                )
                # A1: enqueue_ingress writes TWO durable raw copies — messages.raw (above) and the ingress
                # queue.payload (just now) — the 2 of the 2+H+N amplification.
                self.body_copies += 2
                await self._event(cur, mid, "received", None, "ingress", now)
                # #149 two-object commit: incref each detached attachment AND record its
                # message→attachment linkage row in THIS transaction (same commit as the skeleton row),
                # so the refcount that keeps the chunks alive — and the linkage retention releases from —
                # land atomically with the row that references them. put_attachment already committed the
                # chunks at refcount 0; a missing row here means it was GC'd/never stored, so fail loud
                # (the enclosing transaction rolls back → no ACK). `refs` is de-duplicated, so the
                # message_attachment PK never conflicts and the refcount is bumped once per distinct ref.
                for ref in refs:
                    await cur.execute(
                        "UPDATE attachment SET refcount = refcount + 1 WHERE id=?", (ref,)
                    )
                    if not cur.rowcount:
                        raise KeyError(f"attachment {ref!r} not found for ingress incref")
                    await cur.execute(
                        "INSERT INTO message_attachment (message_id, attachment_id) VALUES (?,?)",
                        (mid, ref),
                    )
                await self._commit(conn)
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
                await self._commit(conn)
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
        False if the ingress row was already consumed.

        ADR 0075: when ``batch_handoff_statements`` is active, dispatches to :meth:`_route_handoff_batched`
        (fewer round-trips, IDENTICAL logical (sql, params) sequence, one commit). Default-OFF path below
        is byte-identical to before ADR 0075. Note: only this ASYNC path batches — the ADR 0071 fused
        sync twins (:meth:`route_handoff_sync` / :meth:`transform_handoff_sync`) run UNBATCHED, so with
        ``fuse_thread_hops`` also on the fused hops issue serial round-trips (correct, non-additive; the
        runner logs a note when both flags are active)."""
        # getattr default keeps a bare store (object.__new__, the offline-test idiom) on the safe
        # unbatched path; a normally-constructed store always has the attribute set in __init__.
        if getattr(self, "_batch_handoff_statements", False):
            return await self._route_handoff_batched(
                ingress_id=ingress_id,
                message_id=message_id,
                channel_id=channel_id,
                handlers=handlers,
                disposition=disposition,
                now=now,
            )
        now = time.time() if now is None else now
        async with self._acquire() as conn, self._cursor(conn) as cur:
            try:
                await cur.execute(
                    _SQL_DELETE_GUARD,
                    _delete_guard_params(
                        ingress_id, Stage.INGRESS.value, OutboxStatus.INFLIGHT.value
                    ),
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
                    _SQL_UPDATE_MESSAGE_STATUS,
                    _update_message_status_params(disposition.value, message_id),
                )
                event = "routed" if disposition is MessageStatus.ROUTED else "unrouted"
                await self._event(cur, message_id, event, None, f"{len(handlers)} handler(s)", now)
                await self._commit(conn)
            except Exception:
                await conn.rollback()
                raise
        return True

    async def _route_handoff_batched(
        self,
        *,
        ingress_id: str,
        message_id: str,
        channel_id: str,
        handlers: Sequence[tuple[str, str]],
        disposition: MessageStatus,
        now: float | None = None,
    ) -> bool:
        """ADR 0075 batched form of :meth:`route_handoff`. Emits the IDENTICAL ordered (sql, params)
        sequence as the unbatched path (same constants + param-builders, same order) — it only groups the
        statements into fewer ``execute()`` round-trips, still committing exactly ONCE.

        Round-trips (STRICT / applock_hard, N=1 handler): [DELETE_GUARD] · [INSERT_ROUTED..., APPLOCK] ·
        [UPDATE_STATUS, INSERT_EVENT] · COMMIT = 4 (vs 6 unbatched, 33.3%). The guard DELETE opens the
        txn and is read to decide the idempotent no-op; the finalize applock CLOSES the inserts' group and
        its rc is validated (raise on rc<0 -> rollback) BEFORE the UPDATE+event group is issued — so the
        disposition UPDATE is only ever sent with the lock confirmed held (identical ordering to the
        unbatched path)."""
        now = time.time() if now is None else now
        resource = f"mefor:finalize:{message_id}"
        timeout_ms = _applock_timeout_ms(self._settings.command_timeout)
        async with self._acquire() as conn, self._cursor(conn) as cur:
            try:
                acc = _BatchAccumulator(self, cur)
                row = await acc.read_one(
                    _SQL_DELETE_GUARD,
                    _delete_guard_params(
                        ingress_id, Stage.INGRESS.value, OutboxStatus.INFLIGHT.value
                    ),
                )
                if row is None:
                    await conn.rollback()
                    return False  # already handed off (crash-restart) — idempotent no-op
                for handler_name, payload in handlers:
                    routed_row_id = (
                        uuid4().hex
                    )  # hoisted so the payload binds to its own queue cell
                    acc.add(
                        _SQL_INSERT_QUEUE_ROUTED,
                        _insert_routed_params(
                            routed_row_id,
                            message_id,
                            channel_id,
                            handler_name,
                            self._cipher.encrypt(
                                payload, aad=cell_aad("queue", "payload", routed_row_id)
                            ),
                            now,
                        ),
                    )
                    self.body_copies += 1  # A1: parity with the unbatched _insert_routed (H copies)
                # applock is a result-consuming GATE: it closes the inserts' group; rc<0 raises -> rollback.
                arow = await acc.read_one(_SQL_APPLOCK, _applock_params(resource, timeout_ms))
                _applock_result(arow, resource)
                acc.add(
                    _SQL_UPDATE_MESSAGE_STATUS,
                    _update_message_status_params(disposition.value, message_id),
                )
                event = "routed" if disposition is MessageStatus.ROUTED else "unrouted"
                # #63 verbosity gate — can't no-op inside _event_stmt (it always builds the statement),
                # so conditionally OMIT the batch member. The messages.status UPDATE above is unaffected
                # (count-and-log is separate).
                if should_record_event(event, self._message_events):
                    acc.add(
                        *self._event_stmt(
                            message_id, event, None, f"{len(handlers)} handler(s)", now
                        )
                    )
                await acc.flush()  # [UPDATE_STATUS, (INSERT_EVENT?)] as one round-trip
                await self._commit(conn)
            except Exception:
                await conn.rollback()
                raise
        return True

    def route_handoff_sync(
        self,
        conn: Any,
        *,
        ingress_id: str,
        message_id: str,
        channel_id: str,
        handlers: Sequence[tuple[str, str]],
        disposition: MessageStatus,
        now: float | None = None,
    ) -> bool:
        """Synchronous fused-hop twin of :meth:`route_handoff` (ADR 0071 B5). Runs the whole ingress ->
        routed handoff on a **caller-supplied synchronous pyodbc connection** (from
        :meth:`open_sync_handoff_pool`) in ONE committed transaction, so a fused worker-thread hop
        (route_only + this handoff) marshals back to the loop as a single executor completion. Emits the
        IDENTICAL (sql, params) sequence as :meth:`route_handoff` for identical inputs (shared constants
        + param-builders). Idempotent: ``False`` if the ingress row was already consumed. The leading
        guard-DELETE opens the transaction, so the finalize applock is never its first statement."""
        now = time.time() if now is None else now
        cur = conn.cursor()
        try:
            cur.execute(
                _SQL_DELETE_GUARD,
                _delete_guard_params(ingress_id, Stage.INGRESS.value, OutboxStatus.INFLIGHT.value),
            )
            if cur.fetchone() is None:
                conn.rollback()
                return False  # already handed off (crash-restart) — idempotent no-op
            for handler_name, payload in handlers:
                self._insert_routed_sync(cur, message_id, channel_id, handler_name, payload, now)
            self._applock_sync(cur, f"mefor:finalize:{message_id}")
            cur.execute(
                _SQL_UPDATE_MESSAGE_STATUS,
                _update_message_status_params(disposition.value, message_id),
            )
            event = "routed" if disposition is MessageStatus.ROUTED else "unrouted"
            self._event_sync(cur, message_id, event, None, f"{len(handlers)} handler(s)", now)
            self._commit_sync(conn)
        except Exception:
            conn.rollback()
            raise
        finally:
            _close_sync_cursor(cur)
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
        meta_ops: Sequence[tuple[str, str]] = (),
        declined: Sequence[str] = (),
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
        :class:`MessageStore` (SQLite) exactly.

        ``declined`` (#233, ADR 0111): destinations of each ``Send`` addressing a present-but-not-
        deployed connection. Each is recorded as a per-destination ``not_deployed`` event in this same
        transaction, before the finalizer, so it is the count-and-log record AND the persisted signal
        the finalizer reads to emit ``NOT_DEPLOYED`` (not ``FILTERED``). Empty ``declined`` is
        byte-identical to the pre-feature path.

        ADR 0075: when ``batch_handoff_statements`` is active AND there are no ``pt_deliveries``,
        dispatches to :meth:`_transform_handoff_batched` (fewer round-trips, IDENTICAL logical sequence,
        one commit). The rare PT re-ingress branch (extra interleaved reads via the passthrough helpers)
        stays on the proven unbatched path below — a bounded, deliberate scope for the prototype. Default-
        OFF path below is byte-identical to before ADR 0075."""
        # getattr default keeps a bare store (the offline-test idiom) on the safe unbatched path. The
        # SetMeta merge (#150), like PT re-ingress, needs an interleaved metadata read+update, so it
        # stays on the proven unbatched path — the same bounded exclusion as pt_deliveries. A `declined`
        # message (#233) also stays unbatched: it writes extra not_deployed events, so — like PT/meta —
        # it is kept off the batched round-trip path (a rare, bounded exclusion), and the batched form
        # never has to carry the decline.
        if (
            getattr(self, "_batch_handoff_statements", False)
            and not pt_deliveries
            and not meta_ops
            and not declined
        ):
            return await self._transform_handoff_batched(
                routed_id=routed_id,
                message_id=message_id,
                channel_id=channel_id,
                deliveries=deliveries,
                state_ops=state_ops,
                now=now,
            )
        now = time.time() if now is None else now
        applied: list[tuple[tuple[str, str], Any]] = []
        async with self._acquire() as conn, self._cursor(conn) as cur:
            try:
                await cur.execute(
                    _SQL_DELETE_GUARD,
                    _delete_guard_params(
                        routed_id, Stage.ROUTED.value, OutboxStatus.INFLIGHT.value
                    ),
                )
                if await cur.fetchone() is None:
                    await conn.rollback()
                    return False  # already handed off (crash-restart) — idempotent no-op
                for namespace, key, value in sorted(state_ops, key=lambda op: (op[0], op[1])):
                    enc = self._cipher.encrypt(
                        json.dumps(value), aad=cell_aad("state", "value", namespace, key)
                    )
                    await cur.execute(
                        _SQL_STATE_MERGE, _state_merge_params(namespace, key, enc, now, message_id)
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
                # Read the message's current metadata ONCE if either PT re-ingress or SetMeta needs it.
                pmeta_dec: str | None = None
                if pt_deliveries or meta_ops:
                    await cur.execute(_SQL_SELECT_METADATA, (message_id,))
                    prow = await cur.fetchone()
                    pmeta_dec = (
                        self._dec(prow[0], aad=cell_aad("messages", "metadata", message_id))
                        if prow
                        else None
                    )
                if pt_deliveries:
                    parent_meta = _parent_meta_from_row(pmeta_dec)
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
                # SetMeta (ADR 0081, #150): merge the user bag under messages.metadata."user" in THIS
                # same transaction — crash before commit leaves no metadata; a re-run re-derives it.
                if meta_ops:
                    merged = merge_user_metadata(pmeta_dec, meta_ops)
                    await cur.execute(
                        _SQL_UPDATE_METADATA,
                        (
                            self._enc(merged, aad=cell_aad("messages", "metadata", message_id)),
                            message_id,
                        ),
                    )
                total_targets = len(deliveries) + len(pt_deliveries)
                await self._event(
                    cur, message_id, "transformed", None, f"{total_targets} destination(s)", now
                )
                # #233 (ADR 0111): one not_deployed event per declined Send, in THIS transaction and
                # BEFORE the finalizer — the count-and-log record + the signal the finalizer reads to
                # emit NOT_DEPLOYED instead of FILTERED.
                for dest in declined:
                    await self._event(
                        cur, message_id, NOT_DEPLOYED_EVENT, dest, not_deployed_detail(dest), now
                    )
                # Finalizer is the sole disposition authority here (no direct messages.status write).
                await self._maybe_finalize(cur, message_id, now)
                await self._commit(conn)
            except Exception:
                await conn.rollback()
                raise
        # Commit succeeded → publish the committed state writes to the read-through cache.
        self.publish_state_cache(applied)
        return True

    async def _transform_handoff_batched(
        self,
        *,
        routed_id: str,
        message_id: str,
        channel_id: str,
        deliveries: Sequence[tuple[str, str]],
        state_ops: Sequence[tuple[str, str, Any]] = (),
        now: float | None = None,
    ) -> bool:
        """ADR 0075 batched form of :meth:`transform_handoff` for the non-PT hot path. Emits the IDENTICAL
        ordered (sql, params) sequence as the unbatched path (same constants + param-builders, same sorted
        state order, same delivery order) — only the round-trip grouping differs, and it commits once.

        Round-trips (STRICT / applock_hard, 1 delivery / 0 state): [DELETE_GUARD] · [INSERT_OUTBOUND,
        INSERT_EVENT, APPLOCK] · [FINALIZE_COUNT] · [UPDATE_STATUS] · COMMIT = 5 (vs 7 unbatched, 28.6%).
        The finalizer stays the sole disposition authority (:meth:`_maybe_finalize_batched`); its applock
        rc is validated before the finalize UPDATE is issued (strict gate). Callers with ``pt_deliveries``
        never reach here — :meth:`transform_handoff` keeps that branch on the unbatched path."""
        now = time.time() if now is None else now
        applied: list[tuple[tuple[str, str], Any]] = []
        async with self._acquire() as conn, self._cursor(conn) as cur:
            try:
                acc = _BatchAccumulator(self, cur)
                row = await acc.read_one(
                    _SQL_DELETE_GUARD,
                    _delete_guard_params(
                        routed_id, Stage.ROUTED.value, OutboxStatus.INFLIGHT.value
                    ),
                )
                if row is None:
                    await conn.rollback()
                    return False  # already handed off (crash-restart) — idempotent no-op
                for namespace, key, value in sorted(state_ops, key=lambda op: (op[0], op[1])):
                    enc = self._cipher.encrypt(
                        json.dumps(value), aad=cell_aad("state", "value", namespace, key)
                    )
                    acc.add(
                        _SQL_STATE_MERGE, _state_merge_params(namespace, key, enc, now, message_id)
                    )
                    applied.append(((namespace, key), value))
                for dest_name, payload in deliveries:
                    outbound_row_id = (
                        uuid4().hex
                    )  # hoisted so the payload binds to its own queue cell
                    acc.add(
                        _SQL_INSERT_QUEUE_OUTBOUND,
                        _insert_outbound_params(
                            outbound_row_id,
                            message_id,
                            channel_id,
                            dest_name,
                            self._cipher.encrypt(
                                payload, aad=cell_aad("queue", "payload", outbound_row_id)
                            ),
                            now,
                        ),
                    )
                    self.body_copies += (
                        1  # A1: parity with the unbatched _insert_outbound (N copies)
                    )
                # No pt_deliveries on this path, so total_targets == len(deliveries) — byte-identical
                # event detail to the unbatched path (which adds len(pt_deliveries)==0). #63 verbosity
                # gate: conditionally omit the batch member (can't no-op inside _event_stmt).
                if should_record_event("transformed", self._message_events):
                    acc.add(
                        *self._event_stmt(
                            message_id,
                            "transformed",
                            None,
                            f"{len(deliveries)} destination(s)",
                            now,
                        )
                    )
                # Finalizer is the sole disposition authority here (no direct messages.status write).
                await self._maybe_finalize_batched(acc, message_id, now)
                await acc.flush()  # flush the finalize UPDATE (+ any trailing DML)
                await self._commit(conn)
            except Exception:
                await conn.rollback()
                raise
        # Commit succeeded → publish the committed state writes to the read-through cache.
        self.publish_state_cache(applied)
        return True

    def transform_handoff_sync(
        self,
        conn: Any,
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
    ) -> tuple[bool, list[tuple[tuple[str, str], Any]]]:
        """Synchronous fused-hop twin of :meth:`transform_handoff` (ADR 0071 B5). Runs the whole routed
        -> outbound handoff (state MERGEs + outbound rows + PT re-ingress + finalize) on a caller-
        supplied synchronous pyodbc connection in ONE committed transaction. Emits the IDENTICAL
        (sql, params) sequence as :meth:`transform_handoff` for identical inputs.

        Unlike the async method it **does NOT touch** ``self._state_cache`` (that cache is loop-owned;
        a worker thread must never mutate it). It RETURNS ``(handed_off, applied)`` where ``applied`` is
        the ``[((namespace, key), value), ...]`` list of committed state writes; the loop then publishes
        them via :meth:`publish_state_cache` after the single completion. ``(False, [])`` if the routed
        row was already consumed (idempotent no-op)."""
        now = time.time() if now is None else now
        applied: list[tuple[tuple[str, str], Any]] = []
        cur = conn.cursor()
        try:
            cur.execute(
                _SQL_DELETE_GUARD,
                _delete_guard_params(routed_id, Stage.ROUTED.value, OutboxStatus.INFLIGHT.value),
            )
            if cur.fetchone() is None:
                conn.rollback()
                return (False, [])  # already handed off (crash-restart) — idempotent no-op
            for namespace, key, value in sorted(state_ops, key=lambda op: (op[0], op[1])):
                enc = self._cipher.encrypt(
                    json.dumps(value), aad=cell_aad("state", "value", namespace, key)
                )
                cur.execute(
                    _SQL_STATE_MERGE, _state_merge_params(namespace, key, enc, now, message_id)
                )
                applied.append(((namespace, key), value))
            for dest_name, payload in deliveries:
                self._insert_outbound_sync(cur, message_id, channel_id, dest_name, payload, now)
            pmeta_dec: str | None = None
            if pt_deliveries or meta_ops:
                cur.execute(_SQL_SELECT_METADATA, (message_id,))
                prow = cur.fetchone()
                pmeta_dec = (
                    self._dec(prow[0], aad=cell_aad("messages", "metadata", message_id))
                    if prow
                    else None
                )
            if pt_deliveries:
                parent_meta = _parent_meta_from_row(pmeta_dec)
                for pt_name, body in pt_deliveries:
                    produced = self._insert_passthrough_child_mssql_sync(
                        cur,
                        routed_id,
                        message_id,
                        pt_name,
                        body,
                        parent_meta,
                        correlation_depth_cap,
                        now,
                    )
                    self._insert_passthrough_marker_mssql_sync(
                        cur, message_id, pt_name, produced, now
                    )
            # SetMeta (ADR 0081, #150): merge the user bag under messages.metadata."user" in THIS txn.
            if meta_ops:
                merged = merge_user_metadata(pmeta_dec, meta_ops)
                cur.execute(
                    _SQL_UPDATE_METADATA,
                    (
                        self._enc(merged, aad=cell_aad("messages", "metadata", message_id)),
                        message_id,
                    ),
                )
            total_targets = len(deliveries) + len(pt_deliveries)
            self._event_sync(
                cur, message_id, "transformed", None, f"{total_targets} destination(s)", now
            )
            # #233 (ADR 0111): one not_deployed event per declined Send, in THIS transaction and BEFORE
            # the finalizer — sync twin of transform_handoff's decline record (identical (sql, params)).
            for dest in declined:
                self._event_sync(
                    cur, message_id, NOT_DEPLOYED_EVENT, dest, not_deployed_detail(dest), now
                )
            # Finalizer is the sole disposition authority here (no direct messages.status write).
            self._maybe_finalize_sync(cur, message_id, now)
            self._commit_sync(conn)
        except Exception:
            conn.rollback()
            raise
        finally:
            _close_sync_cursor(cur)
        return (True, applied)

    def publish_state_cache(self, applied: Sequence[tuple[tuple[str, str], Any]]) -> None:
        """Publish committed transform-state writes to the loop-owned read-through cache (ADR 0005).

        Called on the LOOP thread AFTER a handoff commits — by the async :meth:`transform_handoff`
        inline, and by the fused-hop caller (ADR 0071 PR2/PR3) with the ``applied`` list returned from
        :meth:`transform_handoff_sync` (which must never mutate ``self._state_cache`` from its worker
        thread). ``state_view()`` then reflects the new values in-process."""
        for ck, cv in applied:
            self._state_cache[ck] = cv

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
                    await self._commit(conn)
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
                # Inline the PG _enc empty-guard: encrypt only a truthy value (never '' / None). Bound to
                # the (message_id, dest, seq) response cell (ASVS 11.3.3).
                enc_body = (
                    self._cipher.encrypt(
                        body, aad=cell_aad("response", "body", message_id, destination_name, seq)
                    )
                    if body
                    else body
                )
                enc_detail = (
                    self._cipher.encrypt(
                        detail,
                        aad=cell_aad("response", "detail", message_id, destination_name, seq),
                    )
                    if detail
                    else detail
                )
                headers_json = encode_response_headers(response_headers)  # #154
                enc_headers = (
                    self._cipher.encrypt(
                        headers_json,
                        aad=cell_aad("response", "resp_headers", message_id, destination_name, seq),
                    )
                    if headers_json
                    else headers_json
                )
                await cur.execute(
                    "INSERT INTO response"
                    " (message_id, destination_name, response_seq, body, outcome, detail,"
                    " resp_headers, captured_at)"
                    " VALUES (?,?,?,?,?,?,?,?)",
                    (
                        message_id,
                        destination_name,
                        seq,
                        enc_body,
                        outcome,
                        enc_detail,
                        enc_headers,
                        now,
                    ),
                )
                if reingress_to is not None:
                    # ADR 0013 Increment 2: a drainable Stage.RESPONSE work-row in the SAME txn (orphan-
                    # free) — a token referencing the immutable artifact by PK, on the loopback lane.
                    artifact_ref = f"{message_id}\x1f{destination_name}\x1f{seq}"
                    # ingest-time (ADR 0009) + metrics only; per-lane FIFO orders by seq — ADR 0059.
                    work_created = now
                    # Hoist the row id so the artifact-ref payload binds to its own queue cell.
                    work_row_id = uuid4().hex
                    await cur.execute(
                        "INSERT INTO queue (id, message_id, stage, channel_id, destination_name,"
                        " handler_name, payload, status, attempts, next_attempt_at, owner,"
                        " lease_expires_at, created_at, updated_at)"
                        " VALUES (?,?,?,?,NULL,NULL,?,?,0,?,NULL,NULL,?,?)",
                        (
                            work_row_id,
                            message_id,
                            Stage.RESPONSE.value,
                            reingress_to,
                            self._cipher.encrypt(
                                artifact_ref, aad=cell_aad("queue", "payload", work_row_id)
                            ),
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
                await self._commit(conn)
            except Exception:
                await conn.rollback()
                raise

    async def correlate_response(self, message_id: str) -> list[CapturedResponse]:
        """Captured replies for a message (ADR 0013), ordered by destination then ``response_seq`` ASC
        (so the latest reply per destination is last). ``body`` + ``detail`` are both decrypted (both
        ciphertext); a NULL (never-captured or purged) body/detail returns ``None`` while an empty ``''``
        round-trips as ``''`` — parity with PG/SQLite ``_dec``; ``outcome`` is plaintext."""
        rows = await self._fetchall(
            "SELECT message_id, destination_name, response_seq, body, outcome, detail, resp_headers,"
            " captured_at, kind, ack_code, ack_phase"
            " FROM response WHERE message_id=? ORDER BY destination_name, response_seq",
            (message_id,),
        )
        return [
            CapturedResponse(
                message_id=r["message_id"],
                destination_name=r["destination_name"],
                response_seq=int(r["response_seq"]),
                outcome=r["outcome"],
                detail=self._cipher.decrypt(
                    r["detail"],
                    aad=cell_aad(
                        "response",
                        "detail",
                        r["message_id"],
                        r["destination_name"],
                        r["response_seq"],
                    ),
                )
                if r["detail"] is not None
                else None,
                captured_at=float(r["captured_at"]),
                body=self._cipher.decrypt(
                    r["body"],
                    aad=cell_aad(
                        "response",
                        "body",
                        r["message_id"],
                        r["destination_name"],
                        r["response_seq"],
                    ),
                )
                if r["body"] is not None
                else None,
                kind=r["kind"],
                ack_code=r["ack_code"],
                ack_phase=r["ack_phase"],
                headers=decode_response_headers(
                    self._cipher.decrypt(
                        r["resp_headers"],
                        aad=cell_aad(
                            "response",
                            "resp_headers",
                            r["message_id"],
                            r["destination_name"],
                            r["response_seq"],
                        ),
                    )
                    if r["resp_headers"] is not None
                    else None
                ),
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
        async with self._acquire() as conn, self._cursor(conn) as cur:
            try:
                await cur.execute(
                    "SELECT COALESCE(MAX(response_seq), 0) + 1 FROM response"
                    " WHERE message_id=? AND destination_name=? AND kind=?",
                    (message_id, dest, "ack_sent"),
                )
                seq = int((await cur.fetchone())[0])
                # Encrypt AFTER seq is known so body/detail bind to the (message_id, dest, seq) cell.
                enc_body = (
                    self._enc(ack_body, aad=cell_aad("response", "body", message_id, dest, seq))
                    if (ack_body and self._cipher.encrypts)
                    else None
                )
                enc_detail = (
                    self._enc(
                        safe_text(detail)[:200],
                        aad=cell_aad("response", "detail", message_id, dest, seq),
                    )
                    if detail
                    else None
                )
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
                await self._commit(conn)
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
        # Bound to (connection, ts, kind) — the id is IDENTITY, unknown here (ASVS 11.3.3).
        now = time.time() if now is None else now
        reason_enc = (
            self._enc(
                safe_text(reason)[:200],
                aad=cell_aad("connection_event", "reason", connection, now, kind),
            )
            if reason
            else None
        )
        await self._execute(
            "INSERT INTO connection_event"
            " (ts, connection, transport, direction, kind, peer_host, message_id, reason)"
            " VALUES (?,?,?,?,?,?,?,?)",
            (now, connection, transport, direction, kind, peer_host, message_id, reason_enc),
        )

    # --- process-in-place dedup ledger (ADR 0129, BACKLOG #142) --------------
    async def is_file_processed(self, *, channel_id: str, file_key: str) -> bool:
        row = await self._fetchone(
            "SELECT 1 AS present FROM processed_files WHERE channel_id=? AND file_key=?",
            (channel_id, file_key),
        )
        return row is not None

    async def record_processed_file(
        self, *, channel_id: str, file_key: str, now: float | None = None
    ) -> None:
        now = time.time() if now is None else now
        # Idempotent on the (channel_id, file_key) PK — the leave-in-place poller is single-writer per
        # connection (leader-gated), so NOT EXISTS + PK is the crash-re-run backstop (mirrors delivered_keys).
        await self._execute(
            "INSERT INTO processed_files (channel_id, file_key, processed_at)"
            " SELECT ?,?,? WHERE NOT EXISTS"
            " (SELECT 1 FROM processed_files WHERE channel_id=? AND file_key=?)",
            (channel_id, file_key, now, channel_id, file_key),
        )

    async def prune_processed_files(
        self,
        *,
        channel_id: str,
        older_than: float,
        keep_last: int,
        now: float | None = None,
    ) -> int:
        del now  # age/count-driven, not clock-arg (signature parity with the other writers)
        async with self._acquire() as conn, self._cursor(conn) as cur:
            try:
                await cur.execute(
                    "DELETE FROM processed_files WHERE channel_id=? AND processed_at < ?",
                    (channel_id, older_than),
                )
                deleted = cur.rowcount if cur.rowcount and cur.rowcount > 0 else 0
                # Count-cap: keep the newest `keep_last`; OFFSET n ROWS (no FETCH) returns the surplus.
                await cur.execute(
                    "DELETE FROM processed_files WHERE channel_id=? AND file_key IN ("
                    " SELECT file_key FROM processed_files WHERE channel_id=?"
                    " ORDER BY processed_at DESC, file_key DESC OFFSET ? ROWS)",
                    (channel_id, channel_id, max(0, keep_last)),
                )
                deleted += cur.rowcount if cur.rowcount and cur.rowcount > 0 else 0
                await self._commit(conn)
            except Exception:
                await conn.rollback()
                raise
        return deleted

    # --- saved-search presets (ADR 0136, BACKLOG #151) -----------------------

    async def upsert_search_preset(
        self,
        *,
        preset_id: str,
        owner_user_id: str,
        name: str,
        criteria: str,
        now: float | None = None,
    ) -> tuple[str, bool]:
        now = time.time() if now is None else now
        async with self._acquire() as conn, self._cursor(conn) as cur:
            try:
                await cur.execute(
                    "SELECT id FROM search_presets WHERE owner_user_id=? AND name=?",
                    (owner_user_id, name),
                )
                row = await cur.fetchone()
                effective_id = str(row[0]) if row is not None else preset_id
                enc = self._enc(criteria, aad=cell_aad("search_presets", "criteria", effective_id))
                if row is not None:
                    await cur.execute(
                        "UPDATE search_presets SET criteria=?, updated_at=? WHERE id=?",
                        (enc, now, effective_id),
                    )
                    replaced = True
                else:
                    await cur.execute(
                        "INSERT INTO search_presets"
                        " (id, owner_user_id, name, criteria, created_at, updated_at) VALUES (?,?,?,?,?,?)",
                        (effective_id, owner_user_id, name, enc, now, now),
                    )
                    replaced = False
                await self._commit(conn)
                return effective_id, replaced
            except Exception:
                await conn.rollback()
                raise

    async def list_search_presets(self, owner_user_id: str) -> list[dict[str, Any]]:
        return await self._fetchall(
            "SELECT id, name, created_at, updated_at FROM search_presets"
            " WHERE owner_user_id=? ORDER BY name",
            (owner_user_id,),
        )

    async def get_search_preset(
        self, *, preset_id: str, owner_user_id: str, now: float | None = None
    ) -> dict[str, Any] | None:
        row = await self._fetchone(
            "SELECT id, name, criteria, created_at, updated_at, last_used_at FROM search_presets"
            " WHERE id=? AND owner_user_id=?",
            (preset_id, owner_user_id),
        )
        if row is None:
            return None
        row["criteria"] = self._dec(
            row["criteria"], aad=cell_aad("search_presets", "criteria", preset_id)
        )
        # #306: stamp last-USED, best-effort and AFTER the read — a usage hint must never fail the
        # recall it annotates (SQLite parity). The returned dict carries the PRE-stamp value.
        try:
            await self._execute(
                "UPDATE search_presets SET last_used_at=? WHERE id=?",
                (time.time() if now is None else now, preset_id),
            )
        except Exception:  # noqa: BLE001 — a usage hint must never fail the recall it annotates
            log.warning("failed to stamp search-preset last_used_at", exc_info=True)
        return row

    async def delete_search_preset(self, *, preset_id: str, owner_user_id: str) -> bool:
        async with self._acquire() as conn, self._cursor(conn) as cur:
            try:
                await cur.execute(
                    "DELETE FROM search_presets WHERE id=? AND owner_user_id=?",
                    (preset_id, owner_user_id),
                )
                deleted = cur.rowcount if cur.rowcount and cur.rowcount > 0 else 0
                await self._commit(conn)
                return deleted > 0
            except Exception:
                await conn.rollback()
                raise

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
                reason=self._dec(
                    r["reason"],
                    aad=cell_aad("connection_event", "reason", r["connection"], r["ts"], r["kind"]),
                ),
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
        escalation_tier: int = 0,
        now: float | None = None,
    ) -> None:
        # Pure observer (ADR 0044 D2): no queue row, no finalizer. De-dup grain = ADR 0014's
        # (event_type, connection) key. UPDATE-then-conditional-INSERT in one serializable transaction
        # (matching the SQLite path): the filtered unique index keeps it to one LIVE instance per key. The
        # caller wraps it fail-soft. reason rides safe_text + the cipher. escalation_tier (#81, ADR 0133) is
        # kept monotonic within an open instance via a CASE (SQL Server has no 2-arg MAX scalar).
        now = time.time() if now is None else now
        # Bound to (event_type, connection) — the de-dup grain the upsert keys on, so the SAME AAD covers
        # both the UPDATE and the INSERT that never sees the IDENTITY id (ASVS 11.3.3).
        reason_enc = (
            self._enc(
                safe_text(reason)[:200],
                aad=cell_aad("alert_instance", "reason", event_type, connection),
            )
            if reason
            else None
        )
        async with self._acquire() as conn, self._cursor(conn) as cur:
            try:
                await cur.execute(
                    "UPDATE alert_instance SET last_seen=?, [count]=[count]+1, severity=?, reason=?,"
                    " escalation_tier=CASE WHEN escalation_tier < ? THEN ? ELSE escalation_tier END"
                    " WHERE event_type=? AND connection=? AND status<>'resolved'",
                    (
                        now,
                        severity,
                        reason_enc,
                        escalation_tier,
                        escalation_tier,
                        event_type,
                        connection,
                    ),
                )
                if cur.rowcount == 0:
                    await cur.execute(
                        "INSERT INTO alert_instance"
                        " (event_type, connection, severity, status, first_seen, last_seen,"
                        " [count], reason, escalation_tier) VALUES (?,?,?,'open',?,?,1,?,?)",
                        (event_type, connection, severity, now, now, reason_enc, escalation_tier),
                    )
                await self._commit(conn)
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
            f" [count] AS count, reason, acked_by, acked_at, resolved_at, suspended_until,"
            f" escalation_tier FROM alert_instance{clause}"
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
            f" [count] AS count, reason, acked_by, acked_at, resolved_at, suspended_until,"
            f" escalation_tier FROM alert_instance{clause}",
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
            reason=self._dec(
                r["reason"],
                aad=cell_aad("alert_instance", "reason", r["event_type"], r["connection"]),
            ),
            acked_by=r["acked_by"],
            acked_at=r["acked_at"],
            resolved_at=r["resolved_at"],
            suspended_until=(None if r["suspended_until"] is None else float(r["suspended_until"])),
            escalation_tier=int(r["escalation_tier"]),
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
                await self._commit(conn)
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
                await self._commit(conn)
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
                await self._commit(conn)
            except Exception:
                await conn.rollback()
                raise
        return int(changed)

    async def suspend_alert_instance(
        self, alert_id: int, *, until: float, now: float | None = None
    ) -> AlertInstance | None:
        # #143 windowed suspend (NOTIFICATION-only): set suspended_until on a live instance. Refuses a
        # resolved one; returns the updated row (for the API echo + seeding the sink cache) or None.
        async with self._acquire() as conn, self._cursor(conn) as cur:
            try:
                await cur.execute(
                    "UPDATE alert_instance SET suspended_until=? WHERE id=? AND status<>'resolved'",
                    (until, alert_id),
                )
                changed = cur.rowcount
                await self._commit(conn)
            except Exception:
                await conn.rollback()
                raise
        if int(changed) == 0:
            return None
        return await self.get_alert_instance(alert_id)

    async def resume_alert_instance(
        self, alert_id: int, *, now: float | None = None
    ) -> AlertInstance | None:
        # #143: clear a windowed suspend. Idempotent; returns the row or None (unknown/already resolved).
        async with self._acquire() as conn, self._cursor(conn) as cur:
            try:
                await cur.execute(
                    "UPDATE alert_instance SET suspended_until=NULL"
                    " WHERE id=? AND status<>'resolved'",
                    (alert_id,),
                )
                changed = cur.rowcount
                await self._commit(conn)
            except Exception:
                await conn.rollback()
                raise
        if int(changed) == 0:
            return None
        return await self.get_alert_instance(alert_id)

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
                await self._commit(conn)
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
                    ref = (
                        self._cipher.decrypt(
                            wr[1], aad=cell_aad("queue", "payload", response_row_id)
                        )
                        or ""
                    )
                    origin_msg_id, dest, seq_s = ref.split("\x1f")
                    seq = int(seq_s)
                except Exception:  # noqa: BLE001 - any decrypt/parse failure = an unrecoverable ref
                    await cur.execute(
                        "UPDATE queue SET status=?, last_error=?, next_attempt_at=?, updated_at=?"
                        " WHERE id=?",
                        (
                            OutboxStatus.DEAD.value,
                            self._enc(  # H4
                                "re-ingress work-row reference is corrupt/unparseable",
                                aad=cell_aad("queue", "last_error", response_row_id),
                            ),
                            now,
                            now,
                            response_row_id,
                        ),
                    )
                    await self._event(cur, origin_id, "dead", None, "re-ingress ref corrupt", now)
                    await self._maybe_finalize(cur, origin_id, now)  # preceded by step-1 SELECT
                    await self._commit(conn)
                    return True  # CONSUME (status flipped), never re-loop
                # (3) Read the immutable artifact body.
                await cur.execute(
                    "SELECT body FROM response"
                    " WHERE message_id=? AND destination_name=? AND response_seq=?",
                    (origin_msg_id, dest, seq),
                )
                art = await cur.fetchone()
                body = (
                    self._cipher.decrypt(
                        art[0], aad=cell_aad("response", "body", origin_msg_id, dest, seq)
                    )
                    if (art and art[0])
                    else ""
                ) or ""
                # (4) Correlation lineage from the origin's metadata (parse once).
                await cur.execute("SELECT metadata FROM messages WHERE id=?", (origin_id,))
                mrow = await cur.fetchone()
                # EF-3: metadata ciphered at rest, bound to the origin message's cell
                meta_json = (
                    self._dec(mrow[0], aad=cell_aad("messages", "metadata", origin_id))
                    if mrow
                    else None
                )
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
                                f"({child_depth} > {correlation_depth_cap})",
                                aad=cell_aad("queue", "last_error", response_row_id),
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
                    await self._commit(conn)
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
                            self._cipher.encrypt(body, aad=cell_aad("messages", "raw", new_mid)),
                            MessageStatus.ERROR.value
                            if peek_failed
                            else MessageStatus.RECEIVED.value,
                            "re-ingress body failed HL7 peek" if peek_failed else None,
                            # EF-3: MRN/name is PHI — ciphered at rest
                            self._enc(summary, aad=cell_aad("messages", "summary", new_mid)),
                            self._enc(child_meta, aad=cell_aad("messages", "metadata", new_mid)),
                        ),
                    )
                    if not peek_failed:
                        # ingest-time (ADR 0009) + metrics only; FIFO orders by seq — ADR 0059.
                        ingress_created = now
                        # Hoist the row id so the payload binds to its own queue cell.
                        reingress_row_id = uuid4().hex
                        await cur.execute(
                            "INSERT INTO queue (id, message_id, stage, channel_id, destination_name,"
                            " handler_name, payload, status, attempts, next_attempt_at, owner,"
                            " lease_expires_at, created_at, updated_at)"
                            " VALUES (?,?,?,?,NULL,NULL,?,?,0,?,NULL,NULL,?,?)",
                            (
                                reingress_row_id,
                                new_mid,
                                Stage.INGRESS.value,
                                loopback_channel_id,
                                self._cipher.encrypt(
                                    body, aad=cell_aad("queue", "payload", reingress_row_id)
                                ),
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
                await self._commit(conn)
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
        ref = (
            self._cipher.decrypt(row["payload"], aad=cell_aad("queue", "payload", response_row_id))
            or ""
        )
        try:
            mid, dest, seq_s = ref.split("\x1f")
        except ValueError:
            return None
        art = await self._fetchone(
            "SELECT body FROM response WHERE message_id=? AND destination_name=? AND response_seq=?",
            (mid, dest, int(seq_s)),
        )
        return (
            self._cipher.decrypt(
                art["body"], aad=cell_aad("response", "body", mid, dest, int(seq_s))
            )
            if (art and art["body"])
            else ""
        )

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
            # #241 F2: UN-MASK the former silent-skip of unreadable state rows — that quietly dropped
            # PHI-bearing transform state on a keyless/rotated open (worse than a crash). Fail closed
            # through the shared helper: a keyless open of an encrypted store raises the operator-facing
            # StoreKeylessError (table + remedy), and a keyed cipher that cannot decrypt a row raises
            # CipherError — neither is swallowed.
            cache[(r["namespace"], r["key"])] = decrypt_json_cell(
                self._cipher,
                r["value"],
                aad=cell_aad("state", "value", r["namespace"], r["key"]),
                table="state",
            )
        self._state_cache = cache

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
        follower :meth:`converge_reference_cache` (mirrors the Postgres port). Drives from
        ``reference_version`` (the authoritative active-version list) LEFT JOIN ``reference`` so a set
        synced to ZERO rows is still a present empty ``{}``. Returns
        ``({name: {key: value}}, {name: version})``."""
        rows = await self._fetchall(
            "SELECT v.name AS name, v.version AS version, r.[key] AS [key], r.value AS value"
            " FROM reference_version v"
            " LEFT JOIN reference r ON r.name = v.name AND r.version = v.version"
        )
        cache: dict[str, dict[str, Any]] = {}
        versions: dict[str, str] = {}
        for r in rows:
            entry = cache.setdefault(r["name"], {})
            versions[r["name"]] = r["version"]
            if r["key"] is not None:  # NULL key = the LEFT-JOIN miss of an empty snapshot
                # #241 F2: fail closed on a keyless open of an encrypted store (see _load_state_cache).
                entry[r["key"]] = decrypt_json_cell(
                    self._cipher,
                    r["value"],
                    aad=cell_aad("reference", "value", r["name"], r["version"], r["key"]),
                    table="reference",
                )
        return cache, versions

    def reference_view(self) -> Mapping[str, Mapping[str, Any]]:
        """A read-only, live window onto the active reference snapshots (ADR 0006).

        ``{name: {key: decoded_value}}`` — the synchronous read surface the runner publishes around
        each router/transform run so a Handler's ``reference("name").get(key)`` resolves (SQLite/PG
        parity, BACKLOG #235). A ``MappingProxyType``: it swaps in a new snapshot only after a sync
        commits and can't be mutated through this handle."""
        return MappingProxyType(self._reference_cache)

    def _guard_reference_widths(self, name: str, rows: Mapping[str, Any]) -> None:
        """Fail-closed width guard for the T-SQL reference schema, run BEFORE the snapshot transaction.

        This port bounds ``name`` at NVARCHAR(256) and ``[key]`` at NVARCHAR(450) (the composite PK
        must fit SQL Server's 1700-byte nonclustered-index key cap) where SQLite/Postgres take
        unbounded TEXT — an over-wide bind would truncate (or PK-collide) MID-transaction, failing the
        sync every interval. Raising here instead lets ``reference_sync``'s generic source-failure
        handler keep the last-good snapshot and alert. Widths are measured in **UTF-16 code units**
        (NVARCHAR's unit — a naive ``len()`` counts code points and passes astral-plane keys straight
        into that truncation). The error NEVER carries a raw key: keys may be PHI for a patient-keyed
        set (CLAUDE.md §9), so it names the set + the key's ordinal, code-unit length, and a truncated
        hash only."""
        if len(name.encode("utf-16-le")) // 2 > 256:
            raise ValueError(
                f"reference set name exceeds NVARCHAR(256) "
                f"({len(name.encode('utf-16-le')) // 2} UTF-16 code units); refusing the snapshot"
            )
        for ordinal, key in enumerate(rows):
            units = len(key.encode("utf-16-le")) // 2
            if units > 450:
                digest = hashlib.sha256(key.encode()).hexdigest()[:12]
                raise ValueError(
                    f"reference set {name!r}: key #{ordinal} exceeds NVARCHAR(450) "
                    f"({units} UTF-16 code units, sha256:{digest}); refusing the snapshot "
                    "(key value withheld: reference keys may be PHI)"
                )

    async def write_reference_snapshot(
        self, *, name: str, version: str, rows: Mapping[str, Any]
    ) -> None:
        """Materialize a new reference snapshot and atomically make it active (ADR 0006, BACKLOG #235).

        Fail-closed width guard first (see :meth:`_guard_reference_widths`), then ONE transaction:
        drop the set's prior rows, insert every ``(name, version, [key], value)`` of the new snapshot
        (each value JSON-encoded then cipher-encrypted — it may carry PHI), and upsert the
        ``reference_version`` pointer via ``MERGE WITH (HOLDLOCK)`` (the ``SqlServerCoordinator``
        idiom, ``pipeline/cluster_sqlserver.py``). Readers keep seeing the prior snapshot until this
        commits; a failed sync rolls back wholesale, so the last-good snapshot stays active. The cache
        (and its Track B Step 6 version token) swaps ONLY after commit — a rolled-back write never
        leaks into :meth:`reference_view`. Same build-new-then-flip contract as SQLite/Postgres, so it
        is idempotent on a re-run with the same rows."""
        self._guard_reference_widths(name, rows)
        encrypted = [
            (
                name,
                version,
                k,
                self._cipher.encrypt(
                    encode_reference_value(v),
                    aad=cell_aad("reference", "value", name, version, k),
                ),
            )
            for k, v in rows.items()
        ]
        now = time.time()
        async with self._acquire() as conn, self._cursor(conn) as cur:
            try:
                # Drop the set's prior version(s) — we keep only the active snapshot per name.
                await cur.execute("DELETE FROM reference WHERE name=?", (name,))
                for row in encrypted:
                    await cur.execute(
                        "INSERT INTO reference (name, version, [key], value) VALUES (?,?,?,?)",
                        row,
                    )
                await cur.execute(
                    "MERGE reference_version WITH (HOLDLOCK) AS t"
                    " USING (SELECT ? AS name) AS s ON t.name = s.name"
                    " WHEN MATCHED THEN UPDATE SET version=?, synced_at=?, row_count=?"
                    " WHEN NOT MATCHED THEN INSERT (name, version, synced_at, row_count)"
                    " VALUES (s.name, ?, ?, ?);",
                    (name, version, now, len(encrypted), version, now, len(encrypted)),
                )
                await self._commit(conn)
            except Exception:
                await conn.rollback()
                raise
        # Commit succeeded → swap the active snapshot in the read cache (plaintext, decoded form) AND
        # record the active version, so a follower's converge_reference_cache() (Track B Step 6) can
        # tell this node already reflects it (no needless re-load on the node that just wrote it).
        self._reference_cache[name] = dict(rows)
        self._reference_versions[name] = version

    async def converge_reference_cache(self) -> list[str]:
        """Pull any newer shared reference snapshot into this node's local cache (Track B Step 6).

        The FOLLOWER read-through (mirrors the Postgres port): read the authoritative active versions
        from the shared store and, for each set whose active version differs from the one this handle
        currently reflects, swap that set's freshly-read rows into :attr:`_reference_cache` — WITHOUT
        re-reading the external source. It issues a real read each call (a ``reference_version`` LEFT
        JOIN ``reference`` + per-row decrypt) but mutates nothing when the versions already match (the
        leader's own just-written sets). Returns the names refreshed (``[]`` when none advanced). The
        runner only calls this when clustered (``coordinator.is_clustered()``), so a single node never
        issues this read."""
        cache, versions = await self._read_active_reference_snapshots()
        refreshed: list[str] = []
        for name, version in versions.items():
            if self._reference_versions.get(name) != version:
                self._reference_cache[name] = cache[name]
                self._reference_versions[name] = version
                refreshed.append(name)
        return refreshed

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
                    await self._commit(conn)
                    return 0
                error = "handler removed from registry"
                await self._lock_finalize_batch(cur, {r[1] for r in orphans})
                for row in orphans:
                    await cur.execute(
                        "UPDATE queue SET status=?, next_attempt_at=?, last_error=?, updated_at=?,"
                        " owner=NULL, lease_expires_at=NULL WHERE id=?",
                        (
                            OutboxStatus.DEAD.value,
                            now,
                            self._enc(error, aad=cell_aad("queue", "last_error", row[0])),  # H4
                            now,
                            row[0],
                        ),
                    )
                    await self._event(cur, row[1], "dead", None, error, now)
                    await self._maybe_finalize(cur, row[1], now)
                await self._commit(conn)
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
        # summary/metadata (EF-3): MRN/name PHI on messages — rotated like raw. error/last_error (H4):
        # exception text that may embed raw HL7 fragments — rotated too, or a later retired-key drop
        # silently loses them. message_events/connection_event/alert_instance have IDENTITY ids so they
        # bind cell_aad to natural columns and rotate on their own composite passes below (ASVS 11.3.3).
        # The `<> ''` + NOT LIKE guard is null/empty-safe (NULL excluded by NOT LIKE; '' by <> '').
        for table, column in (
            ("messages", "raw"),
            ("queue", "payload"),
            ("users", "totp_secret"),
            ("messages", "summary"),
            ("messages", "metadata"),
            ("messages", "error"),
            ("queue", "last_error"),
            ("search_presets", "criteria"),  # saved-search preset (ADR 0136) — id-keyed
        ):
            while True:
                rows = await self._fetchall(
                    f"SELECT TOP (?) id, {column} AS v FROM {table}"
                    f" WHERE {column} NOT LIKE ? AND {column} <> ''",
                    (batch, active_like),
                )
                if not rows:
                    break
                # Decrypt+re-encrypt UP FRONT, rebinding the same cell AAD: a CipherError aborts the
                # batch before any write (ASVS 11.3.3).
                updates = [
                    (
                        self._reencrypt_value(r["v"], cell_aad(table, column, r["id"])),
                        r["id"],
                    )
                    for r in rows
                ]
                async with self._acquire() as conn, self._cursor(conn) as cur:
                    try:
                        for enc, rid in updates:
                            await cur.execute(
                                f"UPDATE {table} SET {column}=? WHERE id=?", (enc, rid)
                            )
                        await self._commit(conn)
                    except Exception:
                        await conn.rollback()
                        raise
                await self._charge_bound_batch()
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
                (
                    self._reencrypt_value(
                        r["value"], cell_aad("state", "value", r["namespace"], r["key"])
                    ),
                    r["namespace"],
                    r["key"],
                )
                for r in rows
            ]
            async with self._acquire() as conn, self._cursor(conn) as cur:
                try:
                    for enc, ns, skey in state_updates:
                        await cur.execute(
                            "UPDATE state SET value=? WHERE namespace=? AND [key]=?",
                            (enc, ns, skey),
                        )
                    await self._commit(conn)
                except Exception:
                    await conn.rollback()
                    raise
            await self._charge_bound_batch()
            total += len(rows)
        # `reference` has a composite PK (name, version, [key]) — its own pass (BACKLOG #235).
        # write_reference_snapshot writes reference.value encrypted (snapshot values may carry PHI for
        # patient-keyed sets), so a rotation MUST rotate it too or a later retired-key drop silently
        # loses every synced snapshot — same reasoning as the `state` pass above.
        while True:
            rows = await self._fetchall(
                "SELECT TOP (?) name, version, [key], value FROM reference"
                " WHERE value NOT LIKE ? AND value <> ''",
                (batch, active_like),
            )
            if not rows:
                break
            ref_updates = [
                (
                    self._reencrypt_value(
                        r["value"],
                        cell_aad("reference", "value", r["name"], r["version"], r["key"]),
                    ),
                    r["name"],
                    r["version"],
                    r["key"],
                )
                for r in rows
            ]
            async with self._acquire() as conn, self._cursor(conn) as cur:
                try:
                    for enc, rname, rver, rkey in ref_updates:
                        await cur.execute(
                            "UPDATE reference SET value=? WHERE name=? AND version=? AND [key]=?",
                            (enc, rname, rver, rkey),
                        )
                    await self._commit(conn)
                except Exception:
                    await conn.rollback()
                    raise
            await self._charge_bound_batch()
            total += len(rows)
        # `attachment_chunk` ciphertext (#149, ADR 0105) is cipher-covered with a composite PK
        # (attachment_id, seq) — its own pass. Decrypt (via the keyring) → encrypt (active), one chunk at
        # a time so the whole document is never materialized to re-seal it; the content-address id is over
        # the PLAINTEXT, so a re-seal never changes it (rotation-stable). Skips chunks already active.
        while True:
            rows = await self._fetchall(
                "SELECT TOP (?) attachment_id, seq, ciphertext FROM attachment_chunk"
                " WHERE ciphertext NOT LIKE ? AND ciphertext <> ''",
                (batch, active_like),
            )
            if not rows:
                break
            chunk_updates = [
                (
                    self._reencrypt_value(
                        r["ciphertext"],
                        cell_aad("attachment_chunk", "ciphertext", r["attachment_id"], r["seq"]),
                    ),
                    r["attachment_id"],
                    r["seq"],
                )
                for r in rows
            ]
            async with self._acquire() as conn, self._cursor(conn) as cur:
                try:
                    for enc, aid, aseq in chunk_updates:
                        await cur.execute(
                            "UPDATE attachment_chunk SET ciphertext=? WHERE attachment_id=? AND seq=?",
                            (enc, aid, aseq),
                        )
                    await self._commit(conn)
                except Exception:
                    await conn.rollback()
                    raise
            await self._charge_bound_batch()
            total += len(rows)
        # `response` body + detail are ciphertext with a composite PK (message_id, destination_name,
        # response_seq) — their own passes. IS NOT NULL is explicit/defensive: NOT LIKE already excludes
        # NULLs (three-valued logic) and a NULL has no ciphertext to rotate — but these columns are
        # nullable (unlike state.value/messages.raw/queue.payload), so the guard documents that intent.
        for rcol in ("body", "detail", "resp_headers"):  # #154
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
                        self._reencrypt_value(
                            r["v"],
                            cell_aad(
                                "response",
                                rcol,
                                r["message_id"],
                                r["destination_name"],
                                r["response_seq"],
                            ),
                        ),
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
                        await self._commit(conn)
                    except Exception:
                        await conn.rollback()
                        raise
                await self._charge_bound_batch()
                total += len(rows)
        # IDENTITY-id tables bind cell_aad to natural columns (see the id-keyed loop note) — their own
        # composite rotation passes rebind the same AAD across a v1→v2 / retired→active rotation.
        total += await self._reencrypt_identity_composite(
            "message_events", ("message_id", "ts", "event"), "detail", active_like, batch
        )
        total += await self._reencrypt_identity_composite(
            "connection_event", ("connection", "ts", "kind"), "reason", active_like, batch
        )
        total += await self._reencrypt_identity_composite(
            "alert_instance", ("event_type", "connection"), "reason", active_like, batch
        )
        if total:
            log.info("re-encrypted %d row(s) to the active key", total)
        return total

    def _reencrypt_value(self, stored: str, aad: bytes) -> str:
        """Decrypt (keyring — any key) then re-encrypt under the active key, rebinding the SAME cell AAD
        (ASVS 11.3.3) — the single seam every rotation loop funnels through so none can pair a mismatched
        decrypt/encrypt AAD. Mirrors MessageStore._reencrypt_value."""
        return self._cipher.encrypt(self._cipher.decrypt(stored, aad=aad), aad=aad)

    async def _reencrypt_identity_composite(
        self, table: str, aad_cols: tuple[str, ...], value_col: str, active_like: str, batch: int
    ) -> int:
        """Rotate an IDENTITY-id table's ``value_col`` under the active key, rebinding its natural-column
        cell AAD (the id-keyed loop can't reach it — the AAD isn't the id). UPDATE keys on ``id``; the
        AAD comes from ``aad_cols`` (ASVS 11.3.3). Decrypt→encrypt up front (all-or-nothing)."""
        rotated = 0
        pk_select = ", ".join(f"[{c}]" for c in aad_cols)
        while True:
            rows = await self._fetchall(
                f"SELECT TOP (?) id, {pk_select}, {value_col} AS v FROM {table}"
                f" WHERE {value_col} NOT LIKE ? AND {value_col} <> '' AND {value_col} IS NOT NULL",
                (batch, active_like),
            )
            if not rows:
                break
            updates = [
                (
                    self._reencrypt_value(
                        r["v"], cell_aad(table, value_col, *[r[c] for c in aad_cols])
                    ),
                    r["id"],
                )
                for r in rows
            ]
            async with self._acquire() as conn, self._cursor(conn) as cur:
                try:
                    for enc, rid in updates:
                        await cur.execute(
                            f"UPDATE {table} SET {value_col}=? WHERE id=?", (enc, rid)
                        )
                    await self._commit(conn)
                except Exception:
                    await conn.rollback()
                    raise
            await self._charge_bound_batch()
            rotated += len(rows)
        return rotated

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
        messages. ``metadata`` is NULLed in the SAME statement as the body (ASVS 14.2.7) — NULL is
        likewise invisible to the re-encrypt scans, which filter ``{column} <> ''`` under three-valued
        logic. The guard is ``raw <> '' OR metadata IS NOT NULL``, so rows purged by a pre-upgrade
        engine are swept — and counted — on the first pass after upgrade. Returns the number purged.

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
                    "UPDATE messages SET metadata=NULL, raw='', summary=NULL, error=NULL"
                    " WHERE (raw <> '' OR metadata IS NOT NULL)"
                    " AND id IN (SELECT id FROM #eligible)"
                )
                purged = cur.rowcount
                await cur.execute(
                    "UPDATE queue SET payload='', last_error=NULL"
                    " WHERE stage=? AND status IN (?, ?) AND payload <> ''"
                    " AND message_id IN (SELECT id FROM #eligible)",
                    (Stage.OUTBOUND.value, OutboxStatus.DONE.value, OutboxStatus.CANCELLED.value),
                )
                # #149 Phase 4 (mirrors SQLite Phase 3a): release the streaming attachment each eligible
                # message holds — but ONLY once the message has NO queue row that could still be
                # delivered/replayed (the negated live-holder predicate). The done/cancelled payloads were
                # just blanked above, so an all-done/cancelled message now has no live holder and its
                # attachment is decref'd (GC at 0) + its join rows DELETEd in THIS transaction. A message
                # whose outbound rows are all DEAD keeps its attachment (DEAD payloads stay replayable,
                # deferred to purge_dead_letters). Idempotent — a re-run finds the join rows gone and
                # decrefs nothing (no underflow, no premature GC of an attachment a SIBLING still holds).
                await self._release_message_attachments(
                    cur,
                    f"message_id IN (SELECT id FROM messages m WHERE m.received_at < {cutoff_sql}"
                    f" AND NOT {self._attachment_still_referenced_sql('m.id')})",
                    (
                        *cutoff_params,
                        OutboxStatus.PENDING.value,
                        OutboxStatus.INFLIGHT.value,
                        OutboxStatus.DEAD.value,
                    ),
                )
                await cur.execute(
                    "UPDATE message_events SET detail=NULL"
                    " WHERE detail IS NOT NULL AND message_id IN (SELECT id FROM #eligible)"
                )
                # NULL captured response bodies/details for eligible messages (ADR 0013 retention) — to
                # NULL (matching PG/SQLite: correlate then reads None; reencrypt's IS NOT NULL skips them).
                await cur.execute(
                    "UPDATE response SET body=NULL, detail=NULL, resp_headers=NULL"
                    " WHERE (body IS NOT NULL OR detail IS NOT NULL OR resp_headers IS NOT NULL)"
                    " AND message_id IN (SELECT id FROM #eligible)"
                )
                await cur.execute("DROP TABLE #eligible")
                await self._commit(conn)
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
            raw = self._cipher.decrypt(row["raw"], aad=cell_aad("messages", "raw", row["id"]))
            new_raw, n_docs, n_bytes = _strip_documents(
                raw,
                pruned_at=now,
                min_bytes=min_bytes,
                content_type=content_types.get(row["channel_id"]),
            )
            if n_docs == 0:
                continue
            updates.append(
                (
                    self._cipher.encrypt(new_raw, aad=cell_aad("messages", "raw", row["id"])),
                    now,
                    row["id"],
                )
            )
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
                    await self._commit(conn)
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
                await self._commit(conn)
            except Exception:
                await conn.rollback()
                raise
        return int(purged) if purged is not None else 0

    async def purge_search_presets(self, *, older_than: float, now: float | None = None) -> int:
        # ADR 0136 saved searches: `criteria` is a PHI-shaped needle (PHI.md §2) with no window until
        # ASVS 14.2.7. Whole-row DELETE — the criteria IS the payload and the row backs no count.
        # `updated_at`/`last_used_at` are FLOAT epochs here (as on SQLite/PG), so the comparison needs no
        # date handling. #306: key on the LATER of last-edited and last-used. T-SQL's GREATEST is SQL
        # Server 2022+ and this backend's floor is 2016 SP1 (see _SCHEMA's CREATE OR ALTER guard), so the
        # null-safe greatest-of-two is spelled as the equivalent PREDICATE pair — `MAX(a,b) < cutoff` is
        # exactly `a < cutoff AND (b IS NULL OR b < cutoff)`, and the NULL arm is what keeps a pre-#306
        # row (never recall-stamped) purging on `updated_at` alone. `older_than` is bound TWICE.
        async with self._acquire() as conn, self._cursor(conn) as cur:
            try:
                await cur.execute(
                    "DELETE FROM search_presets"
                    " WHERE updated_at < ? AND (last_used_at IS NULL OR last_used_at < ?)",
                    (older_than, older_than),
                )
                purged = cur.rowcount
                await self._commit(conn)
            except Exception:
                await conn.rollback()
                raise
        return int(purged) if purged is not None else 0

    async def purge_reference_snapshots(
        self, *, older_than: float, declared: Collection[str], now: float | None = None
    ) -> int:
        # See Store.purge_reference_snapshots for the full contract. ADR 0006 `reference.value` is PL-2
        # and had no purge path at all before ASVS 14.2.7. Orphan-scoped: a DECLARED set is never
        # touched however old its synced_at.
        if not declared:
            # Positive-signal guard — an empty `declared` reads as "every set is abandoned" and would
            # wipe the store. Never a legitimate instruction, so it raises rather than deleting.
            raise ValueError(
                "purge_reference_snapshots requires a non-empty `declared` set; an empty one would "
                "purge every snapshot in the store. A registry declaring zero reference sets cannot "
                "authorize purging any — the caller must skip the phase instead."
            )
        deleted = 0
        purged_names: list[str] = []
        async with self._acquire() as conn, self._cursor(conn) as cur:
            try:
                await cur.execute(
                    "SELECT name FROM reference_version WHERE synced_at < ?", (older_than,)
                )
                candidates = [r[0] for r in await cur.fetchall() if r[0] not in declared]
                for name in candidates:
                    # Eligibility RE-ASSERTED inside the delete. `declared` is computed by the caller
                    # outside any lock and write_reference_snapshot takes no applock here, so a config
                    # reload can commit a fresh patient-keyed snapshot between the SELECT above and
                    # this statement. This predicate is the only thing preventing a routine reload from
                    # destroying live data. `older_than` is bound TWICE (T-SQL has no named params).
                    await cur.execute(
                        "DELETE FROM reference WHERE name = ?"
                        " AND EXISTS (SELECT 1 FROM reference_version v"
                        "             WHERE v.name = ? AND v.synced_at < ?)",
                        (name, name, older_than),
                    )
                    count = int(cur.rowcount or 0)
                    if not count:
                        continue  # a concurrent re-sync won the race — leave it alone
                    deleted += count
                    # KEEP the pointer, BUMP the version — converge_reference_cache only reloads a set
                    # whose active version DIFFERS, so an unchanged version leaves every follower
                    # serving purged PHI from `_reference_cache` until restart, and deleting the
                    # pointer is worse (converge only adds/updates names present in a fresh read).
                    await cur.execute(
                        "UPDATE reference_version SET row_count = 0,"
                        " version = 'purged:' + version"
                        " WHERE name = ? AND version NOT LIKE 'purged:%'",
                        (name,),
                    )
                    purged_names.append(name)
                await self._commit(conn)
            except Exception:
                await conn.rollback()
                raise
        # Evict only AFTER the commit — a rolled-back purge must not leave the cache claiming rows the
        # store still holds (the same post-commit discipline purge_state follows below).
        for name in purged_names:
            self._reference_cache.pop(name, None)
            self._reference_versions.pop(name, None)
        return deleted

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
                    await self._commit(conn)
                    return 0
                await cur.execute("DELETE FROM state WHERE set_at < ?", (older_than,))
                await self._commit(conn)
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
                # #149 Phase 4 (mirrors SQLite Phase 3a): a dead row just lost its payload + body_ref, so
                # it can no longer be replayed. If that was the message's LAST replayable row (per the
                # negated live-holder predicate), release its streaming attachment here — the deferred half
                # of the per-MESSAGE dead-row split with purge_message_bodies. Runs in THIS transaction,
                # after the blank above, so the just-purged dead rows already read as non-replayable
                # (payload='' AND body_ref NULL). Idempotent join-row DELETE → a re-run decrefs nothing.
                await self._release_message_attachments(
                    cur,
                    "message_id IN (SELECT DISTINCT q0.message_id FROM queue q0"
                    f" WHERE q0.stage=? AND q0.status=? AND q0.updated_at < {cutoff_sql}"
                    f" AND NOT {self._attachment_still_referenced_sql('q0.message_id')})",
                    (
                        Stage.OUTBOUND.value,
                        OutboxStatus.DEAD.value,
                        *cutoff_params,
                        OutboxStatus.PENDING.value,
                        OutboxStatus.INFLIGHT.value,
                        OutboxStatus.DEAD.value,
                    ),
                )
                await self._commit(conn)
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
                        self._cipher.encrypt(raw, aad=cell_aad("messages", "raw", mid)),
                        status.value,
                        # H4: error may embed raw HL7 fragments — ciphered at rest
                        self._enc(error, aad=cell_aad("messages", "error", mid)),
                        # EF-3: MRN/name is PHI — ciphered at rest
                        self._enc(summary, aad=cell_aad("messages", "summary", mid)),
                        self._enc(metadata, aad=cell_aad("messages", "metadata", mid)),
                    ),
                )
                # `_event` re-scrubs + ciphers the plaintext `error` internally (parity with SQLite).
                await self._event(cur, mid, event, None, error, now)
                await self._commit(conn)
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
                await self._commit(conn)
            except Exception:
                await conn.rollback()
                raise
        items = []
        for row in rows:
            d = dict(zip(columns, row))  # noqa: B905
            try:
                payload = self._cipher.decrypt(
                    d["payload"], aad=cell_aad("queue", "payload", d["id"])
                )
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
            " inserted.attempts, inserted.created_at"
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
                d = dict(zip(columns, row)) if row is not None else None  # noqa: B905
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
                await self._commit(conn)
            except Exception:
                await conn.rollback()
                raise
        if row is None or d is None:
            return None
        try:
            payload = self._cipher.decrypt(d["payload"], aad=cell_aad("queue", "payload", d["id"]))
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
            # ADR 0082 (#134): the batch delivery body reads the head's created_at for the
            # deterministic BHS-7 (re-run-stable) and the max_wait_ms coalescing deadline. Previously
            # omitted from this claim's OUTPUT (ingest-time carried None here); now projected.
            created_at=d["created_at"],
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
                locked = [dict(zip(lock_cols, r)) for r in await cur.fetchall()]  # noqa: B905
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
                    await self._commit(conn)
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
                await self._commit(conn)
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
        decoded = sorted((dict(zip(columns, r)) for r in rows), key=lambda d: d["seq"])  # noqa: B905
        items: list[OutboxItem] = []
        for d in decoded:
            try:
                payload = self._cipher.decrypt(
                    d["payload"], aad=cell_aad("queue", "payload", d["id"])
                )
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

    async def claim_fifo_heads(
        self,
        stage: str,
        lanes: Sequence[str],
        now: float | None = None,
        *,
        per_lane_limit: int = 1,
    ) -> ClaimedHeads:
        """Claim at most the contiguous DUE head-prefix of EACH requested lane in ONE parameterized
        T-SQL batch — one ``cursor.execute`` + one commit, the same wire-op count as the single
        :meth:`claim_next_fifo` (ADR 0066 §3.3; see the base protocol for the full contract).

        **Never-block guarantee (ADR 0066 §9).** The batch opens with ``SET LOCK_TIMEOUT 0`` so NO
        statement ever WAITS on a row lock — a lock it cannot immediately acquire raises error 1222,
        which is caught and translated to the EMPTY-all fail-closed contract (head contended, yield).
        This makes EMPTY-on-a-producer-locked-head STRUCTURAL, independent of whether RCSI is enabled
        (the primitive is unwired here — the pooled-mode ``require_rcsi_for_pooled`` startup gate does
        not run in the store-primitive tests). Under RCSI-on with a working READPAST probe no statement
        waits, so 1222 never fires and behavior is byte-identical; 1222 only triggers in the degraded
        edge that would otherwise pin a pooled connection for ~command_timeout, converting that block
        to a correct immediate EMPTY.

        **Probe-then-claim (the #285 inversion).** STEP 1 discovers each lane's ``TOP(@k)`` min-seq
        PENDING rows with a **plain RCSI snapshot read** (no hints — non-blocking, never lock-skips;
        pooled mode hard-verifies RCSI at startup via :meth:`require_rcsi_for_pooled`). STEP 2 cuts
        each prefix at the first not-due row (a not-due HEAD empties the lane). STEP 3 lock-probes
        with ``(UPDLOCK, ROWLOCK, READPAST)`` — ``claim_ready``'s shipped hint set; UPDLOCK takes
        REAL row locks even under forced RCSI — **confined to the discovered ID set**, so a READPAST
        can only DROP a discovered candidate, structurally never reach seq N+1. STEP 4 keeps, per
        lane, only the longest prefix anchored at the discovered head (head lost => lane EMPTY —
        never ``[N+1, ...]``; the T6 window-CTE failure mode documented on
        :meth:`claim_next_fifo_batch` cannot recur because correctness lives in the explicit ID pin,
        not plan shape). STEP 5 claims exactly the kept prefixes (rows already U-locked; the
        ``status``/due re-checks and the verbatim H1 ``epoch_guard`` — applied to the probe AND the
        UPDATE — are belt-and-suspenders). Non-kept rows are never UPDATEd (``attempts`` untouched).

        The batch's single result set pairs every kept id with its claimed row (``SET NOCOUNT ON``
        keeps it the sole result set; ``fetchall`` drains it under the EF-6 ``_cursor``
        close-before-release discipline). A kept row with no claimed twin is the kept!=claimed
        signal, on which the whole call rolls back and returns EMPTY-all (fail closed). The probe's
        U-locks (held through the UPDATE) rule out a queue-row cause, but the epoch guard re-reads
        the UNLOCKED ``leader_lease`` row on a fresh RCSI statement snapshot, so a leader-epoch
        bump committed between the probe and the UPDATE legitimately zeroes the claim while the
        kept set is non-empty — the expected trigger is that fence race during failover (the
        row-uniform guard makes it all-or-nothing), not a store-invariant break. The H2
        skip-and-complete then runs per claimed outbound row in the SAME txn (mirrors
        :meth:`claim_next_fifo`'s, including the applock ordering — the batch already opened the
        txn); decryption happens after commit, undecryptable rows are dead-lettered and dropped,
        and fully-consumed lanes join ``rearm``.

        Documented semantic shift (ADR 0066 §3.2, verdict A4): on multi-writer fan-in
        ``destination_name`` lanes the snapshot discovery adopts Postgres visibility — a writer's
        *uncommitted* seq-N row is invisible and a committed N+1 is claimable, where the blocking
        per-lane claim would wait for N. Sanctioned by the "no honored cross-inbound receive order"
        doctrine; per-source order is preserved by the serial-writer argument. Single-writer
        ``channel_id`` lanes are unaffected (an uncommitted N implies no committed N+1 exists)."""
        now = time.time() if now is None else now
        lane_col = self._lane_col(stage)  # code-controlled literal
        assert per_lane_limit >= 1, "per_lane_limit must be >= 1"  # nosec B101 — caller contract
        if stage not in (Stage.INGRESS.value, Stage.ROUTED.value):
            # HARD-1 for OUTBOUND/RESPONSE (ADR 0066 §3.2 STEP 6): H2 atomicity + the single-
            # outstanding-head retry semantics — exactly as ADR 0058 excludes them from batching.
            per_lane_limit = 1
        # Dedupe (preserving request order; duplicate lanes would violate @heads' PRIMARY KEY) +
        # chunk clamp; the caller covers the remainder with a second call. THEN drop lanes too long
        # to ever match (AC-11). The clamp deliberately runs BEFORE the skip: an oversized lane
        # occupies a chunk slot it can never match, which is the pre-existing, tested contract
        # (test_prepared_lane_encoding_shares_the_proc_rules pins 499, not 500). Reordering these
        # would serve more lanes per call, but that is a separate decision and not part of this fix.
        #
        # The skip sits here, ahead of the dispatch-path split below, so the proc, prepared and
        # ad-hoc batch branches cannot disagree about it. Previously only the two flagged branches
        # filtered (inside _encode_proc_lanes) and the batch bound the raw list — where an oversized
        # lane is not merely useless but FATAL (2628 on the @heads narrowing conversion; see
        # _keep_matchable_lanes). That gap was unreachable in practice only because sub-lever A's
        # startup gate never passed, so the AC-11 parity test never reached its batch arm.
        # The existing empty guard then covers a request that was entirely oversized.
        lane_list = _keep_matchable_lanes(list(dict.fromkeys(lanes))[:_FIFO_HEADS_LANE_CHUNK])
        if not lane_list:
            return ClaimedHeads(by_lane={}, rearm=frozenset())
        # H1 FENCING TOKEN — identical to the single claim, applied to the probe AND the UPDATE so a
        # fenced ex-leader locks nothing and claims 0 rows across all lanes. epoch=None disables it.
        epoch_guard = ""
        epoch_args: tuple[Any, ...] = ()
        if self._leader_epoch is not None:
            epoch_guard = (
                " AND (SELECT ll.leader_epoch FROM leader_lease ll WHERE ll.lease_key=?) <= ?"
            )
            epoch_args = (self._lease_key, self._leader_epoch)
        # ADR 0114 sub-lever C (fifo_claim_fold_reset): fold the session LOCK_TIMEOUT reset into the
        # batch's clean success path — INGRESS/ROUTED ONLY. At those stages the post-batch H2 loop
        # executes no DML (the ingress/routed INSERT constants bind destination_name as literal NULL,
        # so the `destination_name is not None` gate below never opens — code-confirmed, 932 §9.3),
        # so nothing runs between the batch and commit#1 that needs LOCK_TIMEOUT 0. At OUTBOUND (and
        # RESPONSE) the H2 skip-and-complete + _maybe_finalize DML deliberately runs AFTER the batch
        # under the session's LOCK_TIMEOUT 0 so a contended finalize yields 1222 → EMPTY-all instead
        # of pinning the pooled connection — a trailing reset would flip that DML to wait-forever, so
        # those stages NEVER fold (their batches stay byte-identical). The runtime guard in the H2
        # loop (AC-5) enforces the no-DML premise at run time rather than trusting it silently.
        fold = self._fifo_claim_fold_reset and stage in (Stage.INGRESS.value, Stage.ROUTED.value)
        # ADR 0114 sub-lever A (fifo_claim_proc): with the flag ON and the startup gate green, the
        # claim crosses the driver as a fixed-arity 9-parameter {CALL} of the lane family's
        # versioned proc — one stable statement identity, ~60 chars instead of the ~3KB batch text,
        # one JSON lanes parameter instead of an arity-varying VALUES list. The proc body is the
        # SAME _fifo_heads_steps render (plus the conditional @fold_reset tail composing sub-lever
        # C without a third variant); everything after cur.execute — the drain, the kept==claimed
        # adjudication, the H2 loop, _commit, the 1222 translation, and the shielded finally-guard
        # — is the same code on both paths (AC-9). The gate degraded => the shipped batch, loudly.
        use_proc = self._fifo_claim_proc and self._claim_proc_effective
        # ADR 0114 sub-lever B (fifo_claim_prepared): the non-DDL fallback lane — the SAME stable
        # encoding as the proc (one JSON lanes parameter, fixed-nullable fence) as a client-side
        # batch with the trailing reset INSIDE the text, executed on a store-owned dedicated
        # connection whose RETAINED cursor holds the one-slot prepare (steady state per clean
        # claim: sp_execute + commit — no text, no prepare, no cursor create/free). INGRESS/ROUTED
        # only; the gate enforced fold-ON (so `fold` is True here) and retire-not-stack under a
        # green proc gate (so use_proc and use_prepared are mutually exclusive by construction).
        use_prepared = (
            not use_proc
            and self._fifo_claim_prepared
            and self._claim_prepared_effective
            and stage in (Stage.INGRESS.value, Stage.ROUTED.value)
            # The §5 fail-closed coupling, enforced LOCALLY (not just at the open()-time gate):
            # the stable text bakes the trailing reset in unconditionally, so use_prepared must
            # imply fold — otherwise reset_committed would stay False on clean calls and the
            # finally-guard would run its separate reset on the retained cursor EVERY call,
            # evicting the one-slot prepare cache (silently zeroing B) and double-committing.
            # The gate already refuses to activate without the fold; this belt makes the
            # invariant hold even against a future gate reorder or a hand-set effective flag.
            and fold
        )
        args: tuple[Any, ...]
        if use_proc:
            proc_name = _CLAIM_PROC_CID if lane_col == "channel_id" else _CLAIM_PROC_DST
            sql = f"{{CALL dbo.{proc_name} (?,?,?,?,?,?,?,?,?)}}"
            args = (
                now,
                stage,
                per_lane_limit,
                OutboxStatus.PENDING.value,
                OutboxStatus.INFLIGHT.value,
                # One JSON array parameter — lane names are data, never concatenated into SQL text;
                # >256-char names are skipped loudly client-side (no-match parity, AC-11).
                _encode_proc_lanes(lane_list),
                # The H1 fence in its fixed nullable form: None/None = fence off (epoch=None
                # inertness), bound explicitly every call so the arity never varies.
                self._lease_key,
                self._leader_epoch,
                # Sub-lever C's composition: the proc's conditional tail folds the reset for
                # exactly the calls the batch path would fold (OUTBOUND/RESPONSE never set it).
                1 if fold else 0,
            )
        elif use_prepared:
            # ONE statement identity for the whole INGRESS/ROUTED scope: arity-invariant (the
            # lanes ride the JSON parameter), chunk-preserving, the same text across both epoch
            # modes (the fence arms via the now-non-NULL parameter pair — no re-prepare on a
            # leader promotion). The trailing reset is part of the identity (§5 coupling).
            sql = _PREPARED_CLAIM_SQL
            args = (
                now,
                stage,
                per_lane_limit,
                OutboxStatus.PENDING.value,
                OutboxStatus.INFLIGHT.value,
                _encode_proc_lanes(lane_list),
                self._lease_key,
                self._leader_epoch,
            )
        else:
            lanes_values = ",".join("(?)" for _ in lane_list)
            # One batch, executed as a single parameterized statement. SET NOCOUNT ON suppresses the
            # per-statement rowcount results so the final SELECT is the SOLE result set (EF-6). Row
            # ids live in table variables server-side — they never travel as parameters. The table
            # variables + STEPs 1-5 + sole SELECT render from _fifo_heads_steps — the ONE source of
            # truth shared with the ADR 0114 proc bodies (see the module-level comment there).
            sql = (
                "SET NOCOUNT ON;"
                # ADR 0066 §9 (documented swap): SET LOCK_TIMEOUT 0 makes this claim STRUCTURALLY
                # never-block — no statement in the batch ever WAITS on a row lock; a lock it cannot
                # immediately acquire raises error 1222 (translated to EMPTY-all below), never a
                # command_timeout-length pin. Under RCSI-on with a working READPAST probe no statement
                # waits, so 1222 never fires and behavior is byte-identical; 1222 only triggers in the
                # degraded edge (e.g. RCSI off, the probe waits) that was pinning a pooled connection
                # for ~30s and segfaulting pyodbc on the torn-down connection. LOCK_TIMEOUT is
                # SESSION-scoped and persists on the pooled connection, so the finally-guard resets it
                # on EVERY exit path.
                " SET LOCK_TIMEOUT 0;"
                " DECLARE @now FLOAT = ?, @stage NVARCHAR(16) = ?, @k INT = ?,"
                " @pending NVARCHAR(32) = ?, @inflight NVARCHAR(32) = ?;"
                + _fifo_heads_steps(
                    lane_col=lane_col,
                    lane_source=f"(VALUES {lanes_values})",
                    epoch_guard=epoch_guard,
                )
                # LOCK_TIMEOUT is SESSION-scoped and persists on the pooled connection; the
                # finally-guard below (not a trailing batch statement) does the reset uniformly on
                # EVERY exit path — success, 1222, and any other error — and commits it, so no
                # connection returns to the pool with LOCK_TIMEOUT 0 or mid-transaction. (ADR 0114
                # fold exception: with fifo_claim_fold_reset ON at INGRESS/ROUTED the clean-success
                # reset instead rides the trailing batch statement appended below and is durably
                # committed by commit#1; the guard is then skipped on exactly that exit — see
                # reset_committed — and still runs verbatim on every non-clean exit.)
            )
            if fold:
                # Strictly additive (ADR 0114 §1): the trailing position means every shipped
                # statement above still executes under exactly the lock regime it executes under
                # today (STEPs 1-5 and the SELECT run under SET LOCK_TIMEOUT 0 — the ADR 0066 §9
                # never-block guarantee is untouched), and under SET NOCOUNT ON the trailing SET
                # emits no result set, so the EF-6 sole-result-set/fetchall discipline is unchanged.
                # commit#1 then durably commits the claim AND the reset in one transaction.
                sql += " SET LOCK_TIMEOUT -1;"
            args = (
                now,
                stage,
                per_lane_limit,
                OutboxStatus.PENDING.value,
                OutboxStatus.INFLIGHT.value,
                *lane_list,
                *epoch_args,  # STEP 3 probe guard
                *epoch_args,  # STEP 5 UPDATE guard
            )
        rearm: set[str] = set()
        claimed_rows: list[dict[str, Any]] = []
        # ADR 0114 AC-4: True ONLY once the folded reset is DURABLY committed (commit#1 returned).
        # The flag has exactly ONE assignment site besides this init — immediately after commit#1's
        # await, with no intervening await — so no suspension point can land between commit success
        # and the flag. Never derived from "the batch completed" on an error path: on 1222 the abort
        # point is client-side unknowable (statement- vs batch-abort semantics), and on kept≠claimed
        # the guard runs anyway (a doubled reset is idempotent).
        reset_committed = False
        # BACKLOG #1270: WHICH population a lock timeout aborted on. The try below spans two of them
        # — the claim batch over the lanes' queue heads, and the H2 skip-and-complete's finalize DML,
        # which runs in the SAME transaction under the same LOCK_TIMEOUT 0 and is not a queue head at
        # all. Both reach one handler, so without this marker any single label it prints is wrong for
        # one of the two. Reassigned at exactly one place: entering the H2 branch.
        abort_phase = ClaimAbortPhase.HEAD
        async with AsyncExitStack() as stack:
            if use_prepared:
                # §5: the dedicated holder — retained cursor, deliberately NOT closed per call
                # (retention IS the mechanism; the EF-6 close-before-release discipline is a
                # pooled-connection rule, and a dedicated claim connection is never lent to
                # another statement class, so its open handle can collide with nothing). The
                # holder context's exit shape drives keep-vs-discard (§5 eviction policy).
                holder = await stack.enter_async_context(self._claim_holder_ctx(stage))
                conn, cur = holder.conn, holder.cur
            else:
                conn = await stack.enter_async_context(self._acquire())
                cur = await stack.enter_async_context(self._cursor(conn))
            try:
                if use_proc:
                    # NULL-parameter typing (ADR 0114 §4): the fixed-nullable signature binds None
                    # for @lease_key/@leader_epoch whenever the fence is off, and pyodbc's
                    # None-typing can fall back to SQLDescribeParam — a server metadata round trip,
                    # never cached on the fresh-HSTMT lifecycle. Pin all 9 parameter descriptors so
                    # no describe traffic rides the claim path (G-A0 asserts this on the wire).
                    self._apply_claim_input_sizes(cur, self._claim_proc_input_sizes)
                elif use_prepared:
                    # §5: the 8 stable-text pins, re-applied per call — a cheap sync client-side
                    # assignment, so a guard eviction or driver hiccup can never leave descriptor
                    # drift on the retained cursor (a binding-class flip would silently force a
                    # re-prepare; G-B's wire proof catches a re-prepare storm regardless).
                    self._apply_claim_input_sizes(cur, self._claim_prepared_input_sizes)
                await cur.execute(sql, args)
                columns = [c[0] for c in cur.description] if cur.description else []
                # EF-6: drain the result set with fetchall; _cursor closes the statement handle
                # before the connection returns to the pool (no-MARS).
                rows = await cur.fetchall()
                decoded = [dict(zip(columns, r)) for r in rows]  # noqa: B905
                if use_proc:
                    # The proc CALL pinned 9 parameter descriptors on this POOLED cursor
                    # (descriptor[0] = SQL_DOUBLE for @now FLOAT); those pins are PERSISTENT cursor
                    # state, and the H2 delivery DML below runs on the SAME cursor at OUTBOUND —
                    # binding the NVARCHAR d["id"] against the stale SQL_DOUBLE descriptor throws a
                    # client 22018 cast error and collapses delivery. Clear the pins now, the moment
                    # the CALL's result is drained and before any H2 bind. (use_prepared is
                    # INGRESS/ROUTED-only, where the H2 branch is a no-op — its retained-cursor pins
                    # are never poisoned AND must persist for reuse across calls, so they are NOT
                    # cleared here. On ingress/routed the proc's own H2 branch is also a no-op, so
                    # this clear is simply harmless there.)
                    self._clear_claim_input_sizes(cur)
                if any(d["id"] is None for d in decoded):
                    # kept != claimed (ADR 0066 §3.2 STEP 5) — fail closed: roll the whole call
                    # back, claim nothing. Reachable via an ordinary fence race, not only a bug:
                    # the U-locks cover queue rows, but the epoch guard re-reads the unlocked
                    # leader_lease row on a FRESH RCSI statement snapshot, so an epoch bump
                    # committed between the probe and the UPDATE zeroes the claim (row-uniformly)
                    # while the kept set is non-empty.
                    await conn.rollback()
                    log.warning(
                        "claim_fifo_heads: kept/claimed mismatch at stage %s (%d kept, %d claimed)"
                        " — likely a leader-epoch fence between probe and claim; rolled back,"
                        " claiming nothing (fail closed)",
                        stage,
                        len(decoded),
                        sum(1 for d in decoded if d["id"] is not None),
                    )
                    return ClaimedHeads(by_lane={}, rearm=frozenset())
                # Iterate in CANONICAL message_id order: H2 may take the per-message finalize
                # applock for SEVERAL messages in this one txn, and a monotone subsequence of the
                # sorted order can never form a lock cycle with _lock_finalize_batch callers (or a
                # sibling pooled claim) — the LEFT-JOIN result order is not guaranteed and would
                # re-open the multi-message deadlock the sorted discipline exists to prevent.
                # claimed_rows are regrouped and seq-sorted per lane below, so iteration order is
                # otherwise immaterial.
                for d in sorted(decoded, key=lambda r: r["message_id"]):
                    # ADR 0114 AC-5 runtime guard on the fold's H2-noop premise: with the fold
                    # active, the trailing SET LOCK_TIMEOUT -1 already ran inside the batch, so any
                    # DML between here and commit#1 would run at LOCK_TIMEOUT -1 (wait-forever) and
                    # re-open the pooled-connection pinning hazard the never-block guarantee kills.
                    # The premise is structural today (ingress/routed INSERTs bind destination_name
                    # as literal NULL), but the fold converts a future producer regression from a
                    # loud 1222 into a silent hang — so a claimed row that WOULD enter the H2 DML
                    # branch at a folded stage is a contract violation: raise before the branch is
                    # entered (the except path rolls back, the shielded guard resets the session),
                    # never silent.
                    if fold and d["destination_name"] is not None:
                        log.error(
                            "claim_fifo_heads: contract violation at folded stage %s — claimed row"
                            " %s (message %s) carries destination_name %r where the ADR 0114 fold"
                            " requires the H2 branch to be a no-op; rolling back (fail closed)",
                            stage,
                            d["id"],
                            d["message_id"],
                            d["destination_name"],
                        )
                        raise RuntimeError(
                            f"ADR 0114 fold contract violation: claimed row {d['id']!r} at folded"
                            f" stage {stage!r} carries destination_name {d['destination_name']!r}"
                            " (H2 must no-op at INGRESS/ROUTED)"
                        )
                    # H2 SKIP-AND-COMPLETE in the SAME claim txn — mirrors claim_next_fifo's (the
                    # only _maybe_finalize call site in this primitive; the batch above already
                    # opened the txn, so the applock is not the first statement). The consumed head
                    # is completed DONE in place (NO reorder), dropped, and its lane re-armed.
                    # NB: this DML (and _maybe_finalize's messages UPDATE) still runs under the
                    # session LOCK_TIMEOUT 0 set above — the reset happens later in the finally — so
                    # a finalize row-lock contended by a concurrent finalizer / _lock_finalize_batch
                    # sweep raises 1222 here too, not only a producer-locked queue head. That path
                    # rolls the whole claim back and yields EMPTY-all, which is contract-legal and
                    # SAFE: no partial finalize, the heads stay PENDING for the next tick. (The
                    # per-message finalize applock uses its own @LockTimeout and is unaffected.)
                    if d["destination_name"] is not None:
                        await cur.execute(
                            "SELECT 1 FROM delivered_keys WHERE outbox_id=?", (d["id"],)
                        )
                        if await cur.fetchone() is not None:
                            # BACKLOG #1270: from here on, a 1222 reaching the handler below came
                            # from the FINALIZE population described above, not from a queue head.
                            # SITED AFTER THE PROBE, and that placement is the claim's whole
                            # warrant: the probe MISSES on every ordinary outbound claim (the row
                            # has not been delivered yet, which is why it is being claimed), and
                            # assigning above it labelled that common path FINALIZE with no
                            # finalize statement anywhere in the transaction. It still stays
                            # FINALIZE for the REST of the txn — once the DML below has run, its
                            # row locks are held, so a later row's abort really is finalize-caused.
                            abort_phase = ClaimAbortPhase.FINALIZE
                            await cur.execute(
                                "UPDATE queue SET status=?, last_error=NULL, updated_at=?,"
                                " owner=NULL, lease_expires_at=NULL WHERE id=?",
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
                            rearm.add(d[lane_col])
                            continue
                    claimed_rows.append(d)
                await self._commit(conn)
                # ADR 0114 AC-4 sentinel: reset_committed's SOLE assignment site — immediately after
                # commit#1's await returns, with NO intervening await. True only when this call
                # folded the reset into the batch (the reset is then durably committed, so the
                # finally-guard below is skipped on exactly this clean exit).
                reset_committed = fold
            except Exception as exc:
                await conn.rollback()
                if _is_lock_timeout(exc):
                    # SET LOCK_TIMEOUT 0 fired (error 1222): a probe could not IMMEDIATELY acquire a
                    # contended head lock. This IS the never-block guarantee working — the head is
                    # contended, so YIELD: return EMPTY-all (exactly the EMPTY-on-locked-head
                    # semantics; the head stays PENDING, attempts untouched, the sweep re-tries it).
                    # Contention is normal at scale, so log at DEBUG, not WARNING.
                    # BACKLOG #1270: the DEBUG line stays — it carries the mechanism, and contention
                    # at scale is normal and must not fill an operator's log. What changes is that the
                    # yield is no longer INDISTINGUISHABLE from "there was nothing to claim": the
                    # ATTEMPT rides out on `lock_timeout`, so the dispatcher can say WHY its claim was
                    # empty instead of dropping to IDLE with every observable reading "no work".
                    #
                    # ATTEMPT-LEVEL, AND THAT IS THE CEILING OF WHAT IS KNOWN. The rollback above just
                    # discarded the transaction and on the HEAD path the abort precedes `fetchall`, so
                    # NO ROW WAS EVER READ. `lane_list` is the caller's own request — returning it as
                    # a set of contended lanes (which #1270's first fix did) manufactures up to 256
                    # findings, at the default chunk, out of zero observations. What is true is "at
                    # least one row this claim needed was held", and which one is not knowable here.
                    log.debug(
                        "claim_fifo_heads: lock-timeout (1222) at stage %s on %d lane(s) — %s"
                        " contended, yielding EMPTY (never-block guarantee)",
                        stage,
                        len(lane_list),
                        abort_phase.value,
                    )
                    return ClaimedHeads(
                        by_lane={},
                        rearm=frozenset(),
                        lock_timeout=ClaimLockTimeout(
                            phase=abort_phase, lanes_in_claim=len(lane_list)
                        ),
                    )
                raise
            finally:
                # ADR 0114 sub-lever C: on the folded clean path (reset_committed True ⇔ commit#1
                # returned with the trailing reset inside the batch) the guard is SKIPPED — this
                # finally then contains no await at all. On EVERY other exit (fold off, OUTBOUND/
                # RESPONSE, 1222, kept≠claimed, commit#1 failure, cancellation at any body await) it
                # is False and the shipped shielded guard below runs VERBATIM. kept≠claimed nuance:
                # the folded reset DID execute server-side and, being session-scoped, survives the
                # rollback — the guard's re-SET is idempotent; running it anyway keeps the one rule
                # "reset_committed ⇔ commit#1 returned". On 1222 whether the trailing reset executed
                # before the abort is client-side unknowable (statement- vs batch-abort semantics) —
                # the design never relies on it.
                if not reset_committed:
                    # ===== ADR 0114 AC-4 review anchor: the shipped shielded guard, VERBATIM,
                    # gaining ONLY the skip condition above. B1 (cancellation leak) + M-6 (mid-txn
                    # release) territory — do not edit without a design review. =====
                    # Reset the SESSION-scoped LOCK_TIMEOUT on EVERY exit path (success, the mismatch
                    # early-return, 1222, any other error). A leaked LOCK_TIMEOUT 0 would make an
                    # unrelated next borrower spuriously fail with 1222. By this point the body has always
                    # committed or rolled back (the success commit; the mismatch/except rollback), so the
                    # connection is on a clean txn boundary; this SET opens a fresh implicit txn under
                    # autocommit=False, so it is COMMITTED here — never returning the connection mid-txn
                    # (M-6). -1 = wait forever (the SQL Server default). Best-effort: a reset/commit
                    # failure must not mask the real outcome already being returned/raised.
                    #
                    # The reset is shielded so a task cancellation (engine shutdown/quiesce) delivered at
                    # THIS finally's own await points cannot interrupt it half-done: the pool releases the
                    # connection back regardless of exit type (the async-with in `_acquire`), so a reset
                    # skipped by a cancellation would leak LOCK_TIMEOUT 0 (and possibly a mid-txn) onto the
                    # next borrower — the exact leak this guard exists to prevent. `shield` keeps the SET +
                    # commit running to completion even when the awaiting task is cancelled; we then await
                    # it to done (swallowing an ordinary reset failure) before re-raising any cancellation,
                    # so the connection is always LEFT with LOCK_TIMEOUT -1 on a clean txn boundary.
                    async def _reset_lock_timeout() -> None:
                        await cur.execute("SET LOCK_TIMEOUT -1;")
                        await self._commit(conn)

                    reset = asyncio.ensure_future(_reset_lock_timeout())
                    try:
                        await asyncio.shield(reset)
                    except Exception:  # noqa: BLE001 - a reset failure must not mask the real outcome
                        log.debug(
                            "claim_fifo_heads: LOCK_TIMEOUT reset failed on connection release",
                            exc_info=True,
                        )
                    except asyncio.CancelledError:
                        # The awaiting task was cancelled; `reset` is shielded, so it keeps running. Wait
                        # for it to finish the reset before the connection releases, THEN re-raise so
                        # shutdown proceeds — the connection never returns to the pool with LOCK_TIMEOUT 0.
                        try:
                            await reset
                        except Exception:  # noqa: BLE001 - reset failure must not mask the cancellation
                            log.debug(
                                "claim_fifo_heads: LOCK_TIMEOUT reset failed after cancellation",
                                exc_info=True,
                            )
                        raise
        # Group by lane and re-sort by `seq` in memory (OUTPUT order is not guaranteed — same as the
        # shipped batch claim), then decrypt AFTER the commit: an undecryptable row is dead-lettered
        # and DROPPED (poison containment); the surviving tail keeps its order.
        by_lane_rows: dict[str, list[dict[str, Any]]] = {}
        for d in claimed_rows:
            by_lane_rows.setdefault(d[lane_col], []).append(d)
        by_lane: dict[str, list[OutboxItem]] = {}
        for lane, lane_rows in by_lane_rows.items():
            items: list[OutboxItem] = []
            for d in sorted(lane_rows, key=lambda r: r["seq"]):
                try:
                    payload = self._cipher.decrypt(
                        d["payload"], aad=cell_aad("queue", "payload", d["id"])
                    )
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
                        # #134 (ADR 0082): the batch delivery body reads the head's created_at for the
                        # deterministic BHS-7 + the coalescing deadline. The single claim was patched to
                        # project it; the pooled multi-lane claim must too, else pooled-mode batches on
                        # SQL Server get an empty BHS-7 and a claim-time (not ingest-time) window.
                        created_at=d["created_at"],
                    )
                )
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
        every lane with >=1 PENDING row at ``stage``, paired with its HEAD row's (seq-min pending
        row's) ``next_attempt_at`` — head-of-line-aware by construction. A ``SELECT DISTINCT`` derived
        table enumerates the lanes and a per-lane ``CROSS APPLY (TOP (1) ... ORDER BY seq)`` reads each
        head's due time (the same head-select shape :meth:`claim_fifo_heads` uses; the T-SQL analog of
        the Postgres twin's ``CROSS JOIN LATERAL ... ORDER BY seq LIMIT 1``).

        **Non-recursive by necessity.** SQL Server forbids aggregates, subqueries, ``TOP``, and
        ``DISTINCT`` in the recursive member of a recursive CTE, so the loose-index-scan emulation the
        other dialects use (anchor ``MIN(lane)`` + recurse ``MIN(lane) WHERE lane > prev``) is invalid
        here (error 467) and has no legal recursive rewrite. This plain derived-table + ``CROSS APPLY``
        form is O(pending rows at ``stage``) rather than O(distinct lanes) — an index-only, ordered,
        ``TOP``-bounded stream-distinct that is ~free at idle; a true skip-scan is a later perf concern
        (SQL Server has no native skip-scan operator).

        Unlike :meth:`claim_fifo_heads`, this is a pure RCSI snapshot read with NO locking hints, so it
        can never WAIT on a row lock — it needs no ``SET LOCK_TIMEOUT 0`` never-block guard (ADR 0066
        §9)."""
        lane_col = self._lane_col(stage)  # code-controlled literal
        sql = (
            "SET NOCOUNT ON;"
            " DECLARE @stage NVARCHAR(16) = ?, @pending NVARCHAR(32) = ?, @limit INT = ?,"
            " @after NVARCHAR(256) = ?;"
            " SELECT TOP (@limit) d.lane, h.next_attempt_at"
            f" FROM (SELECT DISTINCT {lane_col} AS lane FROM queue"
            f" WHERE stage = @stage AND status = @pending"
            f" AND (@after IS NULL OR {lane_col} > @after)) d"
            " CROSS APPLY (SELECT TOP (1) next_attempt_at FROM queue"
            f" WHERE stage = @stage AND {lane_col} = d.lane AND status = @pending"
            " ORDER BY seq) h"
            " ORDER BY d.lane;"
        )
        rows = await self._fetchall(sql, (stage, OutboxStatus.PENDING.value, limit, after))
        return [(r["lane"], r["next_attempt_at"]) for r in rows]

    async def release_claimed(self, ids: Sequence[str], now: float | None = None) -> None:
        """Return never-dispatched INFLIGHT rows to ``pending``, undoing exactly the claim's
        ``attempts`` increment (ADR 0066 §3.1; see the base protocol for the full contract):
        ``attempts-1`` floored at 0 defensively, ``next_attempt_at`` UNCHANGED, owner/lease cleared.
        Guarded ``status='inflight'`` so an already-resolved row is left untouched — idempotent.
        Chunked <=500 ids per statement, one commit for the call."""
        now = time.time() if now is None else now
        id_list = list(dict.fromkeys(ids))
        if not id_list:
            return
        async with self._acquire() as conn, self._cursor(conn) as cur:
            try:
                for i in range(0, len(id_list), _RELEASE_CHUNK):
                    chunk = id_list[i : i + _RELEASE_CHUNK]
                    qmarks = ",".join("?" * len(chunk))
                    await cur.execute(
                        "UPDATE queue SET status=?, attempts=IIF(attempts > 0, attempts - 1, 0),"
                        " updated_at=?, owner=NULL, lease_expires_at=NULL"
                        f" WHERE id IN ({qmarks}) AND status=?",
                        (OutboxStatus.PENDING.value, now, *chunk, OutboxStatus.INFLIGHT.value),
                    )
                await self._commit(conn)
            except Exception:
                await conn.rollback()
                raise

    async def reschedule_claimed(
        self, ids: Sequence[str], next_attempt_at: float, now: float | None = None
    ) -> None:
        """Re-pend never-dispatched INFLIGHT rows with a DURABLE backoff — the pooled T17 head-fault
        path (ADR 0070 fix A; see the base protocol for the full contract). Identical to
        :meth:`release_claimed`'s attempts undo (``attempts=IIF(attempts>0,attempts-1,0)``, status
        inflight→pending, owner/lease cleared) but sets ``next_attempt_at`` to the supplied backoff
        deadline so the faulting head reads **not-due** and the sweep arms an exact timer instead of
        re-readying it ~4×/s. Guarded ``status='inflight'`` — idempotent. Chunked <=500 ids, one commit."""
        now = time.time() if now is None else now
        id_list = list(dict.fromkeys(ids))
        if not id_list:
            return
        async with self._acquire() as conn, self._cursor(conn) as cur:
            try:
                for i in range(0, len(id_list), _RELEASE_CHUNK):
                    chunk = id_list[i : i + _RELEASE_CHUNK]
                    qmarks = ",".join("?" * len(chunk))
                    await cur.execute(
                        "UPDATE queue SET status=?, attempts=IIF(attempts > 0, attempts - 1, 0),"
                        " next_attempt_at=?, updated_at=?, owner=NULL, lease_expires_at=NULL"
                        f" WHERE id IN ({qmarks}) AND status=?",
                        (
                            OutboxStatus.PENDING.value,
                            next_attempt_at,
                            now,
                            *chunk,
                            OutboxStatus.INFLIGHT.value,
                        ),
                    )
                await self._commit(conn)
            except Exception:
                await conn.rollback()
                raise

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
                    await self._commit(conn)
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
                await self._commit(conn)
            except Exception:
                await conn.rollback()
                raise

    async def mark_batch_done(self, outbox_ids: Sequence[str], now: float | None = None) -> None:
        """Complete N delivered outbound rows in ONE transaction — the batch counterpart of
        :meth:`mark_done` (ADR 0082). All N flip ``DONE`` together (one ``BHS``…``BTS`` envelope send);
        each writes its H2 idempotency-ledger row + ``delivered`` event, and the finalizer runs once per
        distinct ``message_id``. Sequential single-row statements on one cursor (EF-6 no-MARS). A
        vanished member is skipped; a crash before commit rolls all N back to ``INFLIGHT``."""
        now = time.time() if now is None else now
        async with self._acquire() as conn, self._cursor(conn) as cur:
            try:
                finalize: dict[str, None] = {}
                for outbox_id in outbox_ids:
                    await cur.execute(
                        "SELECT message_id, destination_name, handler_name, attempts"
                        " FROM queue WHERE id=?",
                        (outbox_id,),
                    )
                    row = await cur.fetchone()
                    if row is None:
                        continue  # vanished member — idempotent no-op
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
                    finalize[message_id] = None
                for message_id in sorted(finalize):  # H-8 canonical order (see below)
                    await self._maybe_finalize(cur, message_id, now)
                await self._commit(conn)
            except Exception:
                await conn.rollback()
                raise

    async def mark_failed(
        self, outbox_id: str, error: str, retry: RetryPolicy, now: float | None = None
    ) -> float | None:
        """See the base contract: returns ``next_attempt_at`` when rescheduled, ``None`` when
        dead-lettered/missing (the runner arms the per-lane retry wake on a float, WS-C)."""
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
                    await self._commit(conn)
                    return None
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
                    (
                        status,
                        next_at,
                        self._enc(error, aad=cell_aad("queue", "last_error", outbox_id)),
                        now,
                        outbox_id,
                    ),
                )
                await self._event(
                    cur, message_id, event, destination_name, f"attempt {attempts}: {error}", now
                )
                if status == OutboxStatus.DEAD.value:
                    await self._maybe_finalize(cur, message_id, now)
                    await self._commit(conn)
                    return None
                await self._commit(conn)
                return next_at
            except Exception:
                await conn.rollback()
                raise

    async def mark_batch_failed(
        self,
        outbox_ids: Sequence[str],
        error: str,
        retry: RetryPolicy,
        now: float | None = None,
    ) -> float | None:
        """Re-pend (or dead-letter) N outbound rows that failed **as a unit** — the batch counterpart of
        :meth:`mark_failed` (ADR 0082). One disposition, decided from the head member's attempts and
        applied identically to all N (same ``next_attempt_at`` → re-claimed as the identical prefix, or
        all dead-letter together). Returns the shared ``next_attempt_at`` or ``None`` on dead-letter."""
        error = safe_text(error)  # PHI chokepoint (#120)
        now = time.time() if now is None else now
        async with self._acquire() as conn, self._cursor(conn) as cur:
            try:
                present: list[tuple[str, Any, Any, Any]] = []
                for outbox_id in outbox_ids:
                    await cur.execute(
                        "SELECT message_id, destination_name, attempts FROM queue WHERE id=?",
                        (outbox_id,),
                    )
                    row = await cur.fetchone()
                    if row is not None:
                        present.append((outbox_id, row[0], row[1], row[2]))
                if not present:
                    await self._commit(conn)
                    return None
                head_attempts = present[0][3]
                if retry.max_attempts is not None and head_attempts >= retry.max_attempts:
                    status, next_at, event = OutboxStatus.DEAD.value, now, "dead"
                else:
                    backoff = min(
                        retry.max_backoff_seconds,
                        retry.backoff_seconds * (retry.backoff_multiplier ** (head_attempts - 1)),
                    )
                    status, next_at, event = OutboxStatus.PENDING.value, now + backoff, "failed"
                finalize: dict[str, None] = {}
                for outbox_id, message_id, destination_name, attempts in present:
                    await cur.execute(
                        "UPDATE queue SET status=?, next_attempt_at=?, last_error=?, updated_at=?"
                        " WHERE id=?",
                        (
                            status,
                            next_at,
                            self._enc(error, aad=cell_aad("queue", "last_error", outbox_id)),
                            now,
                            outbox_id,
                        ),
                    )
                    await self._event(
                        cur,
                        message_id,
                        event,
                        destination_name,
                        f"attempt {attempts}: {error}",
                        now,
                    )
                    if status == OutboxStatus.DEAD.value:
                        finalize[message_id] = None
                for message_id in sorted(finalize):  # H-8 canonical order (see below)
                    await self._maybe_finalize(cur, message_id, now)
                await self._commit(conn)
                return None if status == OutboxStatus.DEAD.value else next_at
            except Exception:
                await conn.rollback()
                raise

    async def dead_letter_batch(
        self, outbox_ids: Sequence[str], error: str, now: float | None = None
    ) -> None:
        """Force N outbound rows terminal (``DEAD``) in one transaction — the batch counterpart of
        :meth:`dead_letter_now` (ADR 0082 decision #1: a permanent envelope reject dead-letters all N)."""
        error = safe_text(error)  # PHI chokepoint (#120)
        now = time.time() if now is None else now
        async with self._acquire() as conn, self._cursor(conn) as cur:
            try:
                finalize: dict[str, None] = {}
                for outbox_id in outbox_ids:
                    await cur.execute(
                        "SELECT message_id, destination_name FROM queue WHERE id=?",
                        (outbox_id,),
                    )
                    row = await cur.fetchone()
                    if row is None:
                        continue
                    message_id, destination_name = row[0], row[1]
                    await cur.execute(
                        "UPDATE queue SET status=?, next_attempt_at=?, last_error=?, updated_at=?"
                        " WHERE id=?",
                        (
                            OutboxStatus.DEAD.value,
                            now,
                            self._enc(error, aad=cell_aad("queue", "last_error", outbox_id)),
                            now,
                            outbox_id,
                        ),
                    )
                    await self._event(cur, message_id, "dead", destination_name, error, now)
                    finalize[message_id] = None
                for message_id in sorted(finalize):  # H-8 canonical order (see below)
                    await self._maybe_finalize(cur, message_id, now)
                await self._commit(conn)
            except Exception:
                await conn.rollback()
                raise

    # --- recovery / replay ---------------------------------------------------

    async def reset_stale_inflight(
        self,
        now: float | None = None,
        *,
        stage: str | None = None,
        owned: OwnedLanes | None = None,
    ) -> int:
        """Return in-flight rows to ``pending`` (startup crash recovery) across ALL stages by default —
        an ingress/routed row left inflight by a crash MUST be re-pended or the message hangs forever
        (count-and-log invariant). ``stage`` optionally narrows it; owner/lease are cleared (single-node
        parity).

        ``owned=None`` (default) keeps the unconditional single-node recovery. Passing
        :class:`OwnedLanes` scopes recovery to the caller's config-graph lanes (ADR 0073) — each
        stage filtered by its lane key (``channel_id`` for ingress/routed/response,
        ``destination_name`` for outbound) — so a restarting engine shard on a shared store recovers
        exactly its own crash residue and never re-pends (or owner/lease-strips) a live sibling
        shard's rows. This matters doubly here: SQL Server has NO lease sweep, so the scoped reset
        is the ONLY recovery path for a sharded fleet. An empty owned set for a stage emits no
        statement (never ``IN ()``).

        The all-stages case runs one UPDATE per :class:`Stage` in a single transaction: the
        ``(stage, status)`` pair seeks ``ix_queue_ready``, where the bare ``status=?`` predicate
        matches no index and full-scanned the queue on every open — with N engines opening against
        one shared (ghost-bloated) store, a measured contributor to the WS-B co-start lock convoy
        (LCK_M_IX/X storms). The ownership filter rides that same seek as a residual chunked ``IN``
        predicate (no index hints). Iterating the enum keeps a future stage automatically covered."""
        now = time.time() if now is None else now
        stages = [stage] if stage is not None else [s.value for s in Stage]
        sql = (
            "UPDATE queue SET status=?, next_attempt_at=?, updated_at=?, owner=NULL,"
            " lease_expires_at=NULL WHERE status=? AND stage=?"
        )
        recovered = 0
        async with self._acquire() as conn, self._cursor(conn) as cur:
            try:
                for st in stages:
                    if owned is None:
                        await cur.execute(
                            sql,
                            (OutboxStatus.PENDING.value, now, now, OutboxStatus.INFLIGHT.value, st),
                        )
                        recovered += cur.rowcount
                        continue
                    lane_col, names = owned_lane_scope(st, owned)
                    ordered = sorted(names)
                    for i in range(0, len(ordered), _RESET_LANE_CHUNK):
                        chunk = ordered[i : i + _RESET_LANE_CHUNK]
                        marks = ",".join("?" * len(chunk))
                        await cur.execute(
                            f"{sql} AND {lane_col} IN ({marks})",
                            (
                                OutboxStatus.PENDING.value,
                                now,
                                now,
                                OutboxStatus.INFLIGHT.value,
                                st,
                                *chunk,
                            ),
                        )
                        recovered += cur.rowcount
                await self._commit(conn)
            except Exception:
                await conn.rollback()
                raise
        return int(recovered)

    # --- streaming attachments (#149, ADR 0105 Phase 4 — SQL Server parity) --------------------------
    # Byte-for-byte behavioral parity with the SQLite reference (store/store.py): content-addressed
    # sha256 ref, per-chunk mfenc seal, dedup, refcount + GC-at-0, two-object ingress commit (above),
    # retention decref + dead-row split (purge_message_bodies / purge_dead_letters), key-rotation re-seal.

    async def put_attachment(self, chunks: Iterable[str], content_type: str) -> str:
        """Store a detached document as content-addressed, per-chunk-sealed rows; return its ``ref`` (the
        sha256 of the VERBATIM concatenated plaintext). Each chunk is AES-GCM-sealed independently (a
        bounded plaintext window per seal). Identical content **dedups** to one copy (a re-put returns the
        same ref and writes nothing). The fresh attachment sits at ``refcount=0`` until increffed."""
        hasher = hashlib.sha256()
        total = 0
        # Cell-bound AAD (ASVS 11.3.3) binds each chunk to (attachment_id, seq), and the attachment_id is
        # the content hash — known only after the full plaintext is hashed. Buffer the verbatim slices,
        # hash, then seal each under (ref, seq); the source is an already-materialized OBX-5.5 value, so
        # this adds no order-of-magnitude memory and each seal still consumes one chunk. Mirrors SQLite.
        plaintext_chunks: list[str] = []
        for chunk in chunks:
            data = chunk.encode("utf-8")
            hasher.update(data)
            total += len(data)
            plaintext_chunks.append(chunk)
        ref = hasher.hexdigest()
        sealed: list[str] = [
            self._cipher.encrypt(c, aad=cell_aad("attachment_chunk", "ciphertext", ref, seq))
            for seq, c in enumerate(plaintext_chunks)
        ]
        now = time.time()
        async with self._acquire() as conn, self._cursor(conn) as cur:
            try:
                await cur.execute("SELECT 1 FROM attachment WHERE id=?", (ref,))
                if await cur.fetchone() is not None:
                    await self._commit_read(
                        conn
                    )  # dedup: identical content already stored — write nothing
                    return ref
                await cur.execute(
                    "INSERT INTO attachment (id, content_type, total_bytes, refcount, created_at)"
                    " VALUES (?,?,?,0,?)",
                    (ref, content_type, total, now),
                )
                for seq, ct in enumerate(sealed):
                    await cur.execute(
                        "INSERT INTO attachment_chunk (attachment_id, seq, ciphertext) VALUES (?,?,?)",
                        (ref, seq, ct),
                    )
                await self._commit(conn)
            except Exception:
                await conn.rollback()
                raise
        return ref

    async def read_attachment(self, ref: str) -> AsyncIterator[str]:
        """Yield the detached document's chunks back as decrypted plaintext, in ``seq`` order — the exact
        verbatim slices that were put (Approach B: concatenating them reconstructs OBX-5.5 byte-for-byte).
        Raises :class:`KeyError` if the attachment does not exist (corruption or already GC'd)."""
        exists = False
        rows: list[dict[str, Any]] = []
        async with self._acquire() as conn, self._cursor(conn) as cur:
            try:
                await cur.execute("SELECT 1 FROM attachment WHERE id=?", (ref,))
                exists = await cur.fetchone() is not None
                if exists:
                    await cur.execute(
                        "SELECT seq, ciphertext FROM attachment_chunk WHERE attachment_id=? ORDER BY seq",
                        (ref,),
                    )
                    cols = [c[0] for c in cur.description]
                    rows = [dict(zip(cols, r)) for r in await cur.fetchall()]  # noqa: B905
                await self._commit_read(conn)
            except Exception:
                await conn.rollback()
                raise
        if not exists:
            raise KeyError(f"attachment {ref!r} not found")
        for r in rows:
            yield self._cipher.decrypt(
                r["ciphertext"], aad=cell_aad("attachment_chunk", "ciphertext", ref, r["seq"])
            )

    async def attachments_for(self, message_id: str) -> list[dict[str, Any]]:
        """The distinct attachments ``message_id`` holds — the operator read surface (#149, ADR 0105
        Phase 3b, SQL Server parity). JOINs ``message_attachment`` to its ``attachment`` header and
        returns one row per attachment carrying ``attachment_id`` (the sha256 content address),
        ``content_type``, and ``total_bytes``. **Metadata only** — the chunk ciphertext is never
        touched/decrypted. Returns ``[]`` for a message with no detached document."""
        if not self.supports_streaming_attachments:
            return []
        async with self._acquire() as conn, self._cursor(conn) as cur:
            try:
                await cur.execute(
                    "SELECT a.id AS attachment_id, a.content_type, a.total_bytes "
                    "FROM message_attachment ma JOIN attachment a ON a.id = ma.attachment_id "
                    "WHERE ma.message_id=? ORDER BY a.id",
                    (message_id,),
                )
                cols = [c[0] for c in cur.description]
                rows = [dict(zip(cols, r)) for r in await cur.fetchall()]  # noqa: B905
                await self._commit_read(conn)
            except Exception:
                await conn.rollback()
                raise
        return rows

    async def attachment_incref(self, ref: str) -> None:
        """Add one live reference to an attachment (store-once refcount). Raises :class:`KeyError` if the
        attachment does not exist — an incref must name a real stored document."""
        async with self._acquire() as conn, self._cursor(conn) as cur:
            try:
                await cur.execute(
                    "UPDATE attachment SET refcount = refcount + 1 WHERE id=?", (ref,)
                )
                if not cur.rowcount:
                    await conn.rollback()
                    raise KeyError(f"attachment {ref!r} not found")
                await self._commit(conn)
            except Exception:
                await conn.rollback()
                raise

    async def _decref_attachment(self, cur: Any, ref: str, count: int = 1) -> None:
        """Drop ``count`` references to an attachment and **GC the attachment + all its chunks at
        refcount 0**, in the CALLER's transaction (no commit of its own — the transaction-participant
        sibling of :meth:`attachment_decref`). Clamped at 0 (a double-decref can't drive it negative).
        SQL Server has no scalar ``MAX(a,b)``; the CASE clamps to 0 when ``refcount <= count``."""
        await cur.execute(
            "UPDATE attachment SET refcount = CASE WHEN refcount <= ? THEN 0 ELSE refcount - ? END"
            " WHERE id=?",
            (count, count, ref),
        )
        # GC at 0: delete chunks (while the header still exists to gate on) then the header.
        await cur.execute(
            "DELETE FROM attachment_chunk WHERE attachment_id IN"
            " (SELECT id FROM attachment WHERE id=? AND refcount<=0)",
            (ref,),
        )
        await cur.execute("DELETE FROM attachment WHERE id=? AND refcount<=0", (ref,))

    async def attachment_decref(self, ref: str) -> None:
        """Drop one reference and **GC the attachment + all its chunks at refcount 0** (store-once
        retention). Clamped at 0; tolerant of a missing ref (a no-op), so a purge re-run is idempotent."""
        async with self._acquire() as conn, self._cursor(conn) as cur:
            try:
                await self._decref_attachment(cur, ref, 1)
                await self._commit(conn)
            except Exception:
                await conn.rollback()
                raise

    async def _release_message_attachments(
        self, cur: Any, where: str, params: tuple[object, ...]
    ) -> None:
        """Release every attachment held by the messages matching ``where`` (#149, ADR 0105 Phase 4 — the
        attachment sibling of the SQLite retention seam). Tally each distinct attachment the matching
        messages reference via the ``message_attachment`` linkage, decref each by how many of these
        messages reference it (GC at 0), then DELETE those join rows so the release is exactly-once even
        if the purge re-runs. Runs in the CALLER's transaction (the decref + join-row DELETE + body null
        commit atomically). **Re-run is a no-op:** a re-run finds the join rows gone and decrefs nothing —
        no double-decref, no refcount underflow, no premature GC of an attachment a SIBLING message still
        holds. ``where`` is a code-controlled fragment (never user input); ``params`` binds it identically
        in both statements."""
        await cur.execute(
            f"SELECT attachment_id, COUNT(*) AS n FROM message_attachment"
            f" WHERE {where} GROUP BY attachment_id",
            params,
        )
        cols = [c[0] for c in cur.description]
        releases = [dict(zip(cols, r)) for r in await cur.fetchall()]  # noqa: B905
        if not releases:
            return
        for row in releases:
            await self._decref_attachment(cur, row["attachment_id"], int(row["n"]))
        # Delete the just-released join rows so a re-run of the purge decrefs nothing (idempotent GC).
        await cur.execute(f"DELETE FROM message_attachment WHERE {where}", params)

    @staticmethod
    def _attachment_still_referenced_sql(msg_col: str) -> str:
        """A correlated ``EXISTS`` fragment true iff message ``msg_col`` still has a queue row that could
        be **delivered or replayed** and would therefore still need its streaming attachment when a send
        HYDRATES the ``mfdoc:v1:ref:`` handle. A row is a **live holder** when it is ``pending``/
        ``inflight`` OR it is ``dead`` but still replayable (its ``payload`` is kept OR its ``body_ref`` is
        not yet released). Callers negate it (``NOT EXISTS``) to release only when the LAST holder is gone
        — the per-MESSAGE analogue of the ``shared_body`` done/cancelled-vs-dead split (SQLite parity)."""
        return (
            "EXISTS (SELECT 1 FROM queue q WHERE q.message_id = "
            f"{msg_col} AND (q.status IN (?, ?) OR "
            "(q.status = ? AND (q.payload <> '' OR q.body_ref IS NOT NULL))))"
        )

    async def release_message_attachments(self, message_id: str) -> None:
        """Release (decref + delete the linkage rows for) every attachment a SINGLE message holds, in ONE
        transaction — the standalone form of the retention decref (#149, ADR 0105). Idempotent: a re-run
        finds the join rows gone and decrefs nothing (no underflow, no premature GC of an attachment a
        sibling message still references)."""
        async with self._acquire() as conn, self._cursor(conn) as cur:
            try:
                await self._release_message_attachments(cur, "message_id = ?", (message_id,))
                await self._commit(conn)
            except Exception:
                await conn.rollback()
                raise

    async def sweep_orphan_attachments(self) -> int:
        """Reclaim orphaned attachment storage at startup so **no PHI chunk accumulates at rest** (#149,
        ADR 0105). Two disjoint classes: refcount-0 attachments (header + chunks deleted) and header-less
        incomplete-write chunk groups (a future incremental writer that crashed before finalizing the
        header). Returns the number of attachments reclaimed. Idempotent: a second run finds nothing."""
        async with self._acquire() as conn, self._cursor(conn) as cur:
            try:
                # Count header-less chunk groups BEFORE any delete (while refcount-0 headers still exist,
                # so their chunks don't miscount as orphans — those are reclaimed as the refcount-0 class).
                await cur.execute(
                    "SELECT COUNT(DISTINCT attachment_id) AS n FROM attachment_chunk"
                    " WHERE attachment_id NOT IN (SELECT id FROM attachment)"
                )
                row = await cur.fetchone()
                incomplete = int(row[0]) if row is not None else 0
                # Reclaim refcount-0 attachments: chunks (gated on the header's refcount) then the header.
                await cur.execute(
                    "DELETE FROM attachment_chunk WHERE attachment_id IN"
                    " (SELECT id FROM attachment WHERE refcount<=0)"
                )
                await cur.execute("DELETE FROM attachment WHERE refcount<=0")
                headers = cur.rowcount or 0
                if headers < 0:
                    headers = 0
                # Reclaim any header-less orphan chunks (incomplete writes).
                await cur.execute(
                    "DELETE FROM attachment_chunk WHERE attachment_id NOT IN (SELECT id FROM attachment)"
                )
                await self._commit(conn)
            except Exception:
                await conn.rollback()
                raise
        reclaimed = headers + incomplete
        if reclaimed:
            log.info(
                "reclaimed %d orphaned attachment(s) at startup (%d refcount-0, %d incomplete-write)",
                reclaimed,
                headers,
                incomplete,
            )
        return reclaimed

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
                    await self._commit(conn)
                    return
                message_id, destination_name = row[0], row[1]
                await cur.execute(
                    "UPDATE queue SET status=?, next_attempt_at=?, last_error=?, updated_at=?,"
                    " owner=NULL, lease_expires_at=NULL WHERE id=?",
                    (
                        OutboxStatus.DEAD.value,
                        now,
                        self._enc(error, aad=cell_aad("queue", "last_error", outbox_id)),
                        now,
                        outbox_id,
                    ),
                )
                await self._event(cur, message_id, "dead", destination_name, error, now)
                await self._maybe_finalize(cur, message_id, now)
                await self._commit(conn)
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

    async def reply_wait_state(self, message_id: str, destination_name: str) -> ReplyWaitState:
        """Metadata-only state for one synchronous-reply wait tick (ADR 0154 D3).

        Three narrow indexed reads, decoding nothing — see :class:`ReplyWaitState` for why the
        message's own status is returned alongside the destination's row states."""
        message_row = await self._fetchone("SELECT status FROM messages WHERE id=?", (message_id,))
        queue_rows = await self._fetchall(
            "SELECT status FROM queue WHERE message_id=? AND stage=? AND destination_name=?",
            (message_id, Stage.OUTBOUND.value, destination_name),
        )
        # kind='response' excludes the ADR 0021 ack_sent row: the inbound ACK we returned must never
        # be mistaken for the partner's reply.
        response_row = await self._fetchone(
            "SELECT MAX(response_seq) AS seq FROM response"
            " WHERE message_id=? AND destination_name=? AND kind=?",
            (message_id, destination_name, "response"),
        )
        seq = response_row["seq"] if response_row is not None else None
        return ReplyWaitState(
            message_status=(str(message_row["status"]) if message_row is not None else None),
            row_states=tuple(str(r["status"]) for r in queue_rows),
            latest_response_seq=(int(seq) if seq is not None else None),
        )

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
                    await self._commit_read(conn)  # read-only release (M-6), uncounted (A1)
                    return 0
                error = "destination removed from outbound registry"
                await self._lock_finalize_batch(cur, {r[1] for r in orphans})
                for row in orphans:
                    await cur.execute(
                        "UPDATE queue SET status=?, next_attempt_at=?, last_error=?, updated_at=?,"
                        " owner=NULL, lease_expires_at=NULL WHERE id=?",
                        (
                            OutboxStatus.DEAD.value,
                            now,
                            self._enc(error, aad=cell_aad("queue", "last_error", row[0])),  # H4
                            now,
                            row[0],
                        ),
                    )
                    await self._event(cur, row[1], "dead", row[2], error, now)
                    await self._maybe_finalize(cur, row[1], now)
                await self._commit(conn)
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
                await self._commit(conn)
            except Exception:
                await conn.rollback()
                raise
        return int(count)

    async def resend_to(
        self,
        *,
        message_id: str,
        to: str,
        idempotency_key: str,
        from_: str | None = None,
        body_override: str | None = None,
        now: float | None = None,
    ) -> ResendOutcome:
        """Resend a message's stored transformed body to an ALTERNATE outbound ``to`` (ADR 0090).
        Mirrors :meth:`MessageStore.resend_to`. When ``body_override`` is set this is the edit-and-resend
        DIRECT path (ADR 0090 §9): the operator's EDITED body ships instead of a retained one (no source
        read/deref/ambiguity; channel from the origin row, which is read never written).

        **Per-lane FIFO, by claim path (ADR 0090 §3, review #123-1 correction).** The *serial* per-lane
        claim (:meth:`claim_next_fifo`) reads the head ``WITH (UPDLOCK, ROWLOCK)`` and deliberately NO
        ``READPAST`` — it head-of-line-**blocks** on any lower-``seq`` uncommitted row and ``IDENTITY``
        assigns ``seq`` in insert order, so under it this second writer can never be claimed ahead of an
        older in-flight row, no extra lock required. The *pooled* claim (:meth:`claim_fifo_heads`, the
        ADR 0066 SQL-Server scale-out delivery path) discovers heads with a plain RCSI **snapshot** read
        that adopts Postgres visibility — a producer's *uncommitted* seq-N row is invisible and a
        committed seq-N+1 is claimable — so a fast-committing resend CAN be delivered ahead of an
        unrelated, still-uncommitted producer row in a shared fan-in ``destination_name`` lane. That is
        the SAME weakly-ordered cross-source fan-in behavior ADR 0066 already sanctions (no honored
        cross-inbound receive order; per-source FIFO holds by the serial-writer argument), NOT a new
        break: the resend lands at the lane TAIL as a deliberate out-of-band act and never re-orders two
        rows from the SAME source. Unlike Postgres — which takes a per-lane advisory write-funnel here —
        SQL Server pooled mode relies on that fan-in doctrine rather than claim-side blocking; a stricter
        per-lane ``sp_getapplock`` on every outbound producer is a deliberately-declined option (it would
        add contention on the identified pooled-claim throughput wall). The 3-backend CI win2025 SQL-
        Server leg is the authoritative gate.

        Idempotency: a per-key ``sp_getapplock`` serializes same-key inserts, then the ``resend_log``
        ``INSERT … WHERE NOT EXISTS`` + ``rowcount`` is the atomic gate; the outbound row is created only
        when it made a row (ADR 0090 §4)."""
        now = time.time() if now is None else now
        async with self._acquire() as conn, self._cursor(conn) as cur:
            try:
                # Serialize concurrent same-key resends so the NOT-EXISTS gate is race-free (must-fix #5).
                await self._applock(cur, f"mefor:resend:{idempotency_key}")
                await cur.execute(
                    "INSERT INTO resend_log (resend_key, message_id, to_destination,"
                    " from_destination, outbox_id, created_at)"
                    " SELECT ?,?,?,?,NULL,? WHERE NOT EXISTS"
                    " (SELECT 1 FROM resend_log WHERE resend_key=?)",
                    (idempotency_key, message_id, to, from_ or "", now, idempotency_key),
                )
                if not cur.rowcount:
                    # Bind the key to its (message_id, to) request — a key reused for a DIFFERENT
                    # message/target is a conflict (raise -> 409), never a silent no-op (ADR 0090 §4,
                    # review #123-4).
                    await cur.execute(
                        "SELECT message_id, to_destination, from_destination, outbox_id FROM resend_log"
                        " WHERE resend_key=?",
                        (idempotency_key,),
                    )
                    pr = await cur.fetchone()
                    if pr is not None and (pr[0] != message_id or pr[1] != to):
                        raise ResendKeyConflict(
                            f"idempotency key {idempotency_key!r} was already used to resend message"
                            f" {pr[0]!r} to {pr[1]!r}; it cannot be reused for message {message_id!r}"
                            f" to {to!r}"
                        )
                    await self._commit(conn)
                    return ResendOutcome(
                        status="duplicate",
                        message_id=message_id,
                        to_destination=pr[1] if pr else to,
                        from_destination=pr[2] if pr else (from_ or ""),
                        outbox_id=pr[3] if pr else None,
                    )
                if body_override is not None:
                    # Edit-and-resend DIRECT power-path (ADR 0090 §9.1.3, BACKLOG #153): ship the
                    # operator's EDITED body to `to` as a NEW, correlated CHILD delivery; the ORIGIN row
                    # is only READ (channel/type + correlation metadata) and NEVER written (#153 "the
                    # original must NOT change"; review #153-1/#153-2). The outbound row hangs off the
                    # CHILD, so the finalizer recomputes the CHILD's disposition, never the origin's.
                    await cur.execute(
                        "SELECT channel_id, source_type, message_type, metadata"
                        " FROM messages WHERE id=?",
                        (message_id,),
                    )
                    mrow = await cur.fetchone()
                    if mrow is None:
                        raise ReingressOriginMissing(
                            f"message {message_id} no longer exists -- cannot edit-and-resend"
                        )
                    src_channel = mrow[0]
                    src_dest = from_ or ""
                    body = body_override
                    if not body:
                        raise ResendSourceEmpty(
                            f"message {message_id} edited body is empty -- cannot resend"
                        )
                    # Correlate the child to the origin (mirrors `reingress`).
                    raw_meta = self._dec(mrow[3], aad=cell_aad("messages", "metadata", message_id))
                    try:
                        parent_meta = json.loads(raw_meta) if raw_meta else {}
                    except (ValueError, TypeError):
                        parent_meta = {}
                    if not isinstance(parent_meta, dict):
                        parent_meta = {}
                    child_depth = int(parent_meta.get("correlation_depth", 0) or 0) + 1
                    root = parent_meta.get("correlation_root_id") or message_id
                    child_meta = json.dumps(
                        {
                            "correlation_id": message_id,
                            "correlation_root_id": root,
                            "correlation_depth": child_depth,
                            "edited_from": message_id,
                        }
                    )
                    # ROUTED child with its single outbound delivery already in flight (skips router/
                    # transform); the finalizer drives it. Idempotency is the resend_log gate above.
                    child_mid = uuid4().hex
                    await cur.execute(
                        _SQL_INSERT_MESSAGE,
                        (
                            child_mid,
                            src_channel,
                            now,
                            mrow[1],  # source_type
                            None,
                            mrow[2],  # message_type
                            self._cipher.encrypt(body, aad=cell_aad("messages", "raw", child_mid)),
                            MessageStatus.ROUTED.value,
                            None,
                            None,
                            self._enc(child_meta, aad=cell_aad("messages", "metadata", child_mid)),
                        ),
                    )
                    self.body_copies += 1  # A1: the child messages.raw copy
                    await self._event(
                        cur, child_mid, "received", None, f"edit-resend from {message_id}", now
                    )
                    await self._event(cur, message_id, "edit_resend", to, f"-> {child_mid}", now)
                    outbox_id = uuid4().hex
                    await cur.execute(
                        _SQL_INSERT_QUEUE_OUTBOUND,
                        _insert_outbound_params(
                            outbox_id,
                            child_mid,
                            src_channel,
                            to,
                            self._cipher.encrypt(body, aad=cell_aad("queue", "payload", outbox_id)),
                            now,
                        ),
                    )
                    self.body_copies += (
                        1  # A1: one inline transformed-body copy (parity with _insert_outbound)
                    )
                else:
                    # Resolve the source + its stored body (deref a shared body via COALESCE). ANY retained
                    # stage='outbound' row is an eligible source (done/cancelled/dead/pending) — the
                    # transform already produced its body; diverting a permanently-failed (dead) delivery to
                    # a standby is a marquee use case (ADR 0090 §1). `from_destination` names the source
                    # LANE, not a delivery claim (review #123-3).
                    src_where = "message_id=? AND stage=?"
                    src_params: list[Any] = [message_id, Stage.OUTBOUND.value]
                    if from_ is not None:
                        src_where += " AND destination_name=?"
                        src_params.append(from_)
                    await cur.execute(
                        "SELECT q.destination_name, q.channel_id,"
                        " COALESCE(sb.body, q.payload) AS body_ciphertext, q.id, q.body_ref"
                        " FROM queue q LEFT JOIN shared_body sb ON sb.hash = q.body_ref"
                        f" WHERE {src_where} ORDER BY q.destination_name",
                        tuple(src_params),
                    )
                    rows = await cur.fetchall()
                    if not rows:
                        raise ResendSourceNotFound(
                            f"message {message_id} has no delivered body"
                            + (f" for source {from_!r}" if from_ is not None else "")
                            + " to resend"
                        )
                    if from_ is None and len({r[0] for r in rows}) > 1:
                        raise ResendSourceAmbiguous(
                            f"message {message_id} was delivered to multiple destinations --"
                            " specify the source destination (from) to resend"
                        )
                    src_dest, src_channel, body_ciphertext = rows[0][0], rows[0][1], rows[0][2]
                    src_queue_id, src_body_ref = rows[0][3], rows[0][4]
                    # The body's cell depends on its source (store-once shared body vs inline payload).
                    src_body_aad = (
                        cell_aad("shared_body", "body", src_body_ref)
                        if src_body_ref is not None
                        else cell_aad("queue", "payload", src_queue_id)
                    )
                    decoded = self._dec(body_ciphertext, aad=src_body_aad)
                    if not decoded:
                        raise ResendSourceEmpty(
                            f"message {message_id} source body was purged by retention -- cannot resend"
                        )
                    body = decoded
                    # #123 stored-body path: another delivery of the SAME logged message — outbound row
                    # on the ORIGIN message_id + flip the ORIGIN to ROUTED (finalizer recomputes).
                    outbox_id = uuid4().hex
                    await cur.execute(
                        _SQL_INSERT_QUEUE_OUTBOUND,
                        _insert_outbound_params(
                            outbox_id,
                            message_id,
                            src_channel,
                            to,
                            self._cipher.encrypt(body, aad=cell_aad("queue", "payload", outbox_id)),
                            now,
                        ),
                    )
                    self.body_copies += (
                        1  # A1: one inline transformed-body copy (parity with _insert_outbound)
                    )
                    await cur.execute(
                        "UPDATE messages SET status=?, error=NULL WHERE id=?",
                        (MessageStatus.ROUTED.value, message_id),
                    )
                    await self._event(
                        cur, message_id, "resent", to, f"resend {src_dest or '?'}->{to}", now
                    )
                await cur.execute(
                    "UPDATE resend_log SET outbox_id=? WHERE resend_key=?",
                    (outbox_id, idempotency_key),
                )
                await self._commit(conn)
                return ResendOutcome(
                    status="resent",
                    message_id=message_id,
                    to_destination=to,
                    from_destination=str(src_dest),
                    outbox_id=outbox_id,
                )
            except Exception:
                await conn.rollback()
                raise

    async def reingress(
        self,
        *,
        origin_message_id: str,
        raw: str,
        idempotency_key: str,
        now: float | None = None,
    ) -> ReingressOutcome:
        """Edit-and-resubmit RE-ROUTE (ADR 0090 §9). Mirrors :meth:`MessageStore.reingress`: injects a
        fresh, correlated ``RECEIVED`` child message at the origin channel's ingress stage; the origin
        row is READ (channel + correlation metadata), never written. Idempotency: a per-key
        ``sp_getapplock`` serializes same-key inserts, then the ``resend_log`` ``INSERT … WHERE NOT
        EXISTS`` + ``rowcount`` gate (keyed to ``(origin, "@reingress:<channel>")``) admits exactly one;
        the deterministic content-addressed child id is the partial-rollback defense."""
        now = time.time() if now is None else now
        async with self._acquire() as conn, self._cursor(conn) as cur:
            try:
                await cur.execute(
                    "SELECT channel_id, source_type, message_type, metadata FROM messages WHERE id=?",
                    (origin_message_id,),
                )
                orow = await cur.fetchone()
                if orow is None:
                    raise ReingressOriginMissing(
                        f"message {origin_message_id} no longer exists -- cannot edit-and-resubmit"
                    )
                channel_id = str(orow[0])
                source_type, message_type, metadata_ciphertext = orow[1], orow[2], orow[3]
                target = f"{REINGRESS_TARGET_PREFIX}{channel_id}"
                await self._applock(cur, f"mefor:resend:{idempotency_key}")
                await cur.execute(
                    "INSERT INTO resend_log (resend_key, message_id, to_destination,"
                    " from_destination, outbox_id, created_at)"
                    " SELECT ?,?,?,'',NULL,? WHERE NOT EXISTS"
                    " (SELECT 1 FROM resend_log WHERE resend_key=?)",
                    (idempotency_key, origin_message_id, target, now, idempotency_key),
                )
                if not cur.rowcount:
                    await cur.execute(
                        "SELECT message_id, to_destination, outbox_id FROM resend_log WHERE resend_key=?",
                        (idempotency_key,),
                    )
                    pr = await cur.fetchone()
                    if pr is not None and (pr[0] != origin_message_id or pr[1] != target):
                        raise ResendKeyConflict(
                            f"idempotency key {idempotency_key!r} was already used for a different"
                            f" resubmit ({pr[0]!r} -> {pr[1]!r}); it cannot be reused for message"
                            f" {origin_message_id!r}"
                        )
                    await self._commit(conn)
                    return ReingressOutcome(
                        status="duplicate",
                        message_id=origin_message_id,
                        new_message_id=(pr[2] if pr else "") or "",
                        channel_id=channel_id,
                    )
                raw_meta = self._dec(
                    metadata_ciphertext, aad=cell_aad("messages", "metadata", origin_message_id)
                )
                try:
                    parent_meta = json.loads(raw_meta) if raw_meta else {}
                except (ValueError, TypeError):
                    parent_meta = {}
                if not isinstance(parent_meta, dict):
                    parent_meta = {}
                child_depth = int(parent_meta.get("correlation_depth", 0) or 0) + 1
                root = parent_meta.get("correlation_root_id") or origin_message_id
                child_meta = json.dumps(
                    {
                        "correlation_id": origin_message_id,
                        "correlation_root_id": root,
                        "correlation_depth": child_depth,
                        "edited_from": origin_message_id,
                    }
                )
                new_mid = MessageStore._edit_resubmit_message_id(idempotency_key, channel_id, raw)
                await cur.execute(_SQL_SELECT_MESSAGE_EXISTS, (new_mid,))
                if await cur.fetchone() is None:
                    await cur.execute(
                        _SQL_INSERT_MESSAGE,
                        (
                            new_mid,
                            channel_id,
                            now,
                            source_type,
                            None,
                            message_type,
                            self._cipher.encrypt(raw, aad=cell_aad("messages", "raw", new_mid)),
                            MessageStatus.RECEIVED.value,
                            None,
                            None,
                            self._enc(child_meta, aad=cell_aad("messages", "metadata", new_mid)),
                        ),
                    )
                    # Hoist the row id so the payload binds to its own queue cell.
                    resubmit_row_id = uuid4().hex
                    await cur.execute(
                        _SQL_INSERT_QUEUE_INGRESS,
                        (
                            resubmit_row_id,
                            new_mid,
                            Stage.INGRESS.value,
                            channel_id,
                            self._cipher.encrypt(
                                raw, aad=cell_aad("queue", "payload", resubmit_row_id)
                            ),
                            OutboxStatus.PENDING.value,
                            now,
                            now,
                            now,
                        ),
                    )
                    self.body_copies += 2
                    await self._event(
                        cur,
                        new_mid,
                        "received",
                        None,
                        f"edit-resubmit from {origin_message_id}",
                        now,
                    )
                    await self._event(
                        cur, origin_message_id, "edit_resubmit", None, f"-> {new_mid}", now
                    )
                await cur.execute(
                    "UPDATE resend_log SET outbox_id=? WHERE resend_key=?",
                    (new_mid, idempotency_key),
                )
                await self._commit(conn)
                return ReingressOutcome(
                    status="resubmitted",
                    message_id=origin_message_id,
                    new_message_id=new_mid,
                    channel_id=channel_id,
                )
            except Exception:
                await conn.rollback()
                raise

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
                    await self._commit(conn)
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
                await self._commit(conn)
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
                    await self._commit(conn)
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
                await self._commit(conn)
            except Exception:
                await conn.rollback()
                raise
        return len(ids)

    # --- read helpers --------------------------------------------------------

    async def get_message(self, message_id: str) -> dict[str, Any] | None:
        record = await self._fetchone("SELECT * FROM messages WHERE id=?", (message_id,))
        if record is not None:
            mid = record["id"]
            # decrypt the body for display, bound to the messages cell (ASVS 11.3.3)
            record["raw"] = self._cipher.decrypt(
                record["raw"], aad=cell_aad("messages", "raw", mid)
            )
            # H4: error may embed raw HL7 fragments
            record["error"] = self._dec(record["error"], aad=cell_aad("messages", "error", mid))
            # EF-3: MRN/name PHI, ciphered at rest
            record["summary"] = self._dec(
                record["summary"], aad=cell_aad("messages", "summary", mid)
            )
            record["metadata"] = self._dec(  # EF-3
                record["metadata"], aad=cell_aad("messages", "metadata", mid)
            )
        return record

    async def message_metadata_json(self, message_id: str) -> str | None:
        # #68: decrypt ONLY the metadata column (never the raw PHI body) for the delivery worker's
        # per-message dynamic headers. Off the perf-critical claim path; read only for opted-in outbounds.
        record = await self._fetchone("SELECT metadata FROM messages WHERE id=?", (message_id,))
        if record is None:
            return None
        return self._dec(record["metadata"], aad=cell_aad("messages", "metadata", message_id))

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
    ) -> list[dict[str, Any]]:
        where, params = self._message_filter(
            channel_id,
            status,
            message_type,
            control_id,
            allowed_channels,
            received_from,
            received_to,
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
            mid = r["id"]
            r["error"] = self._dec(r["error"], aad=cell_aad("messages", "error", mid))  # H4
            # EF-3: summary/metadata ciphered at rest
            r["summary"] = self._dec(r["summary"], aad=cell_aad("messages", "summary", mid))
            r["metadata"] = self._dec(r["metadata"], aad=cell_aad("messages", "metadata", mid))
        return rows

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
    ) -> int:
        where, params = self._message_filter(
            channel_id,
            status,
            message_type,
            control_id,
            allowed_channels,
            received_from,
            received_to,
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
            cid = cand["id"]
            raw = self._dec(cand.get("raw"), aad=cell_aad("messages", "raw", cid))
            summary = self._dec(cand.get("summary"), aad=cell_aad("messages", "summary", cid))
            if row_matches(spec, raw=raw, summary=summary):
                d = dict(cand)
                d["error"] = self._dec(d.get("error"), aad=cell_aad("messages", "error", cid))
                d["summary"] = self._dec(d.get("summary"), aad=cell_aad("messages", "summary", cid))
                d["metadata"] = self._dec(
                    d.get("metadata"), aad=cell_aad("messages", "metadata", cid)
                )
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
            # Mixed-table join: last_error is queue's (o.id → outbox_id), summary is the messages
            # row's (keyed by message_id) — each binds to its own cell (ASVS 11.3.3).
            r["last_error"] = self._dec(
                r["last_error"], aad=cell_aad("queue", "last_error", r["outbox_id"])
            )
            r["summary"] = self._dec(
                r["summary"], aad=cell_aad("messages", "summary", r["message_id"])
            )
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
            r["last_error"] = self._dec(
                r["last_error"], aad=cell_aad("queue", "last_error", r["id"])
            )  # H4: last_error ciphered at rest
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
            # SS keeps bodies inline (no shared_body deref on this path), so payload is queue.payload.
            r["payload"] = self._cipher.decrypt(
                r["payload"], aad=cell_aad("queue", "payload", r["id"])
            )
            r["last_error"] = self._dec(
                r["last_error"], aad=cell_aad("queue", "last_error", r["id"])
            )  # H4: null/legacy-plaintext-safe decrypt
        return rows

    async def events_for(self, message_id: str) -> list[dict[str, Any]]:
        rows = await self._fetchall(
            "SELECT * FROM message_events WHERE message_id=? ORDER BY id", (message_id,)
        )
        for r in rows:
            # H4: event detail ciphered at rest, bound to (message_id, ts, event) — id is IDENTITY.
            r["detail"] = self._dec(
                r["detail"],
                aad=cell_aad("message_events", "detail", r["message_id"], r["ts"], r["event"]),
            )
        return rows

    async def record_view(
        self, message_id: str, *, actor: str | None = None, now: float | None = None
    ) -> None:
        now = time.time() if now is None else now
        async with self._acquire() as conn, self._cursor(conn) as cur:
            try:
                await self._event(cur, message_id, "viewed", None, actor or "", now)
                await self._commit(conn)
            except Exception:
                await conn.rollback()
                raise

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

        See :meth:`MessageStore.record_message_event` — same contract, same runtime kind validation
        (the static literal-call-site guard cannot see a forwarded variable), same verbosity gate."""
        if event not in MESSAGE_EVENT_KINDS:
            raise ValueError(
                f"unknown message_events kind {event!r} — add it to MESSAGE_EVENT_KINDS and to the "
                "docs/PHI.md §7 row 6 vocabulary, which CI asserts against it"
            )
        now = time.time() if now is None else now
        async with self._acquire() as conn, self._cursor(conn) as cur:
            try:
                await self._event(cur, message_id, event, destination, detail or "", now)
                await self._commit(conn)
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
        client: str | None = None,
        now: float | None = None,
    ) -> None:
        """``client`` is the caller's network address (ADR 0150), NULL for engine-internal writes; see
        :meth:`~messagefoundry.store.base.AuditStore.record_audit`."""
        now = time.time() if now is None else now
        # Serialize the read-prev-then-insert append in-process so two concurrent audited actions can't
        # read the same prev hash and FORK the hash chain (H-7). The store is the single audit writer
        # per engine process (active-passive = one active node), so an in-process lock is sufficient and
        # reliable — unlike a txn-scoped sp_getapplock taken as the connection's first statement, which
        # does not release on commit and strands under concurrent contention.
        async with self._audit_lock:  # noqa: SIM117
            async with self._acquire() as conn, self._cursor(conn) as cur:
                try:
                    await cur.execute("SELECT TOP (1) row_hash FROM audit_log ORDER BY id DESC")
                    last = await cur.fetchone()
                    prev = last[0] if last and last[0] else ""
                    # Keyed (in-heap HMAC key or isolated-module Transit MAC) once the #190
                    # watermark is set, else keyless.
                    _key, _mac = self._audit_append_mac()
                    row_hash = audit_row_hash(
                        prev,
                        ts=now,
                        actor=actor,
                        action=action,
                        channel_id=channel_id,
                        detail=detail,
                        client=client,
                        key=_key,
                        mac=_mac,
                    )
                    await cur.execute(
                        "INSERT INTO audit_log"
                        " (ts, actor, action, channel_id, detail, client, row_hash)"
                        " VALUES (?,?,?,?,?,?,?)",
                        (now, actor, action, channel_id, detail, client, row_hash),
                    )
                    await self._commit(conn)
                except Exception:
                    await conn.rollback()
                    raise
        # Tee off-box AFTER commit + outside the audit lock / pooled connection (only forward what
        # truly persisted; a synchronous syslog send must never hold the lock). Shared redaction path.
        emit_audit_tee(
            action=action, actor=actor, channel_id=channel_id, detail=detail, client=client, ts=now
        )

    # --- per-key AES-GCM invocation bound (ASVS 11.3.4) ----------------------

    async def _charge_bound_batch(self) -> None:
        """Top the AES-GCM invocation reserve up mid-burst — called after EVERY committed batch of a
        rotation / at-rest-migration loop (ASVS 11.3.4; the SQLite twin documents why).

        Runs on its own pooled connection, OUTSIDE the batch transaction: the batch is already committed,
        and an accounting write must never be rolled back with a retried batch."""
        await self.checkpoint_cipher_invocations()

    async def add_cipher_invocations(self, key_id: str, count: int) -> int:
        """Atomically add ``count`` invocations to ``key_id``'s persisted total; return the new total (a
        NEGATIVE ``count`` refunds an unspent reserve at settlement). See the SQLite twin. MERGE with
        HOLDLOCK is the SQL Server upsert that is safe under the concurrent opens of an engine-shard
        fleet (a bare IF EXISTS/INSERT races)."""
        now = time.time()
        async with self._acquire() as conn, self._cursor(conn) as cur:
            try:
                await cur.execute(
                    "MERGE cipher_meta WITH (HOLDLOCK) AS t"
                    " USING (SELECT ? AS key_id, ? AS invocations, ? AS updated_at) AS s"
                    " ON t.key_id = s.key_id"
                    " WHEN MATCHED THEN UPDATE SET"
                    " t.invocations = t.invocations + s.invocations, t.updated_at = s.updated_at"
                    " WHEN NOT MATCHED THEN"
                    " INSERT (key_id, invocations, updated_at)"
                    " VALUES (s.key_id, s.invocations, s.updated_at)"
                    " OUTPUT INSERTED.invocations;",
                    (key_id, int(count), now),
                )
                row = await cur.fetchone()
                total = int(row[0]) if row is not None else int(count)
                await self._commit(conn)
            except Exception:
                await conn.rollback()
                raise
        return total

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
        """Atomically reserve (or release) an uploader's in-flight upload budget — see
        :meth:`messagefoundry.store.base.Store.reserve_upload_quota` for the contract, and the SQLite
        twin for the statement shape.

        MERGE with HOLDLOCK is the SQL Server upsert that is safe under the concurrent opens of an
        engine-shard fleet (a bare IF EXISTS/INSERT races) — the same pattern
        :meth:`add_cipher_invocations` uses. The budget predicate rides ``WHEN MATCHED AND``, so a
        refusal matches no rows and ``OUTPUT`` returns nothing."""
        now = time.time()
        if files <= 0:
            # RELEASE — unconditional, clamped at zero (a double release cannot mint budget).
            await self._execute(
                "UPDATE upload_quota SET"
                " inflight_files = CASE WHEN inflight_files + ? < 0 THEN 0 ELSE inflight_files + ? END,"
                " inflight_bytes = CASE WHEN inflight_bytes + ? < 0 THEN 0 ELSE inflight_bytes + ? END,"
                " since = ?"
                " WHERE uploader_id = ?",
                (
                    int(files),
                    int(files),
                    int(size_bytes),
                    int(size_bytes),
                    now,
                    uploader_id,
                ),
            )
            return True
        if files > max_files or size_bytes > max_total_bytes:
            # Fail closed before touching the row: WHEN NOT MATCHED inserts unconditionally.
            return False
        stale = now - max(0.0, stale_after)
        async with self._acquire() as conn, self._cursor(conn) as cur:
            try:
                await cur.execute(
                    "MERGE upload_quota WITH (HOLDLOCK) AS t"
                    " USING (SELECT ? AS uploader_id, ? AS files, ? AS size_bytes, ? AS now_ts,"
                    " ? AS stale_ts, ? AS max_files, ? AS max_total_bytes) AS s"
                    " ON t.uploader_id = s.uploader_id"
                    " WHEN MATCHED AND"
                    " (CASE WHEN t.since <= s.stale_ts THEN 0 ELSE t.inflight_files END)"
                    " + s.files <= s.max_files"
                    " AND (CASE WHEN t.since <= s.stale_ts THEN 0 ELSE t.inflight_bytes END)"
                    " + s.size_bytes <= s.max_total_bytes"
                    " THEN UPDATE SET"
                    " t.inflight_files ="
                    " (CASE WHEN t.since <= s.stale_ts THEN 0 ELSE t.inflight_files END) + s.files,"
                    " t.inflight_bytes ="
                    " (CASE WHEN t.since <= s.stale_ts THEN 0 ELSE t.inflight_bytes END)"
                    " + s.size_bytes,"
                    " t.since = CASE WHEN t.since <= s.stale_ts OR t.inflight_files <= 0"
                    " THEN s.now_ts ELSE t.since END"
                    " WHEN NOT MATCHED THEN"
                    " INSERT (uploader_id, inflight_files, inflight_bytes, since)"
                    " VALUES (s.uploader_id, s.files, s.size_bytes, s.now_ts)"
                    " OUTPUT INSERTED.inflight_files;",
                    (
                        uploader_id,
                        int(files),
                        int(size_bytes),
                        now,
                        stale,
                        int(max_files),
                        int(max_total_bytes),
                    ),
                )
                row = await cur.fetchone()
                await self._commit(conn)
            except Exception:
                await conn.rollback()
                raise
        return row is not None

    async def cipher_invocations(self, key_id: str) -> int:
        """``key_id``'s persisted cumulative invocation total (0 when the key has no row yet)."""
        row = await self._fetchone(
            "SELECT invocations FROM cipher_meta WHERE key_id = ?", (key_id,)
        )
        return int(row["invocations"]) if row is not None else 0

    async def checkpoint_cipher_invocations(self, *, settle: bool = False) -> int | None:
        """See :func:`messagefoundry.store.gcm_bound.checkpoint_invocations`."""
        return await checkpoint_invocations(
            self._cipher, self.add_cipher_invocations, settle=settle
        )

    async def audit_anchor(self) -> tuple[int, str]:
        """The audit log's external anchor — ``(row_count, head_hash)`` — see the SQLite store (low-1)."""
        rows = await self._fetchall(
            "SELECT COUNT(*) AS n, "
            "(SELECT TOP (1) row_hash FROM audit_log ORDER BY id DESC) AS head FROM audit_log"
        )
        if not rows:
            return 0, ""
        return int(rows[0]["n"]), (rows[0]["head"] or "")

    async def has_prior_backup_history(self) -> bool:
        """See :meth:`AuditStore.has_prior_backup_history` — ≥1 ``dr_backup`` audit row (the #102 server-DB
        DR-seed restored-not-bootstrapped signal). Read-only existence check."""
        rows = await self._fetchall(
            "SELECT TOP (1) 1 AS present FROM audit_log WHERE action = 'dr_backup'"
        )
        return bool(rows)

    async def verify_audit_chain(
        self, *, expected_anchor: tuple[int, str] | None = None
    ) -> tuple[bool, str | None]:
        """Recompute the audit hash-chain in order; returns (ok, message) — see the SQLite store.

        Re-walking can't catch tail-truncation (the surviving prefix still verifies); pass
        ``expected_anchor`` from :meth:`audit_anchor`, held out-of-band, to detect it (review low-1).

        Constant-time, full-walk (ASVS 11.2.4) — see the SQLite twin
        (:meth:`~messagefoundry.store.store.MessageStore.verify_audit_chain`): every row MAC and the
        anchor head are compared with :func:`hmac.compare_digest` over
        :func:`~messagefoundry.store.store.audit_mac_bytes`, and the walk always completes before the
        first divergent row id is reported. NOTE this backend counts rows with ``len(rows)`` where the
        SQLite/Postgres twins carry a ``count`` accumulator — a full walk makes the two equivalent, but
        do not copy-paste the accumulator form here."""
        if self._audit_keyed_from is not None and not self._audit_keyed_capable():
            return (
                False,
                "audit chain is keyed (from id="
                f"{self._audit_keyed_from}) but no store encryption key/MAC is configured to verify it",
            )
        rows = await self._fetchall(
            "SELECT id, ts, actor, action, channel_id, detail, client, row_hash"
            " FROM audit_log ORDER BY id"
        )
        prev = ""
        first_break: int | None = None
        for r in rows:
            # Per-row secret: keyless below the #190 watermark, keyed at/above it — in-heap HMAC key OR
            # isolated-module Transit MAC (ADR 0138), mirroring the SQLite twin so a keyless prefix and a
            # keyed suffix both verify across an enabled-keying migration.
            keyed_row = (
                self._audit_keyed_from is not None and int(r["id"]) >= self._audit_keyed_from
            )
            key = self._audit_mac_key if (keyed_row and self._audit_mac_fn is None) else None
            mac = self._audit_mac_fn if keyed_row else None
            expected = audit_row_hash(
                prev,
                ts=r["ts"],
                actor=r["actor"],
                action=r["action"],
                channel_id=r["channel_id"],
                detail=r["detail"],
                # NULL on every pre-ADR-0150 row → the conditional 7th element is omitted and the
                # legacy digest reproduces exactly, so a mixed old/new chain verifies end to end.
                client=r["client"],
                key=key,
                mac=mac,
            )
            # ASVS 11.2.4: constant-time compare, no data-dependent early return — record the first
            # divergent row and report it AFTER the full walk (see the SQLite twin).
            # Bind the compare first so it is ALWAYS evaluated: folding it behind the
            # `first_break is None` test would short-circuit the comparator once a break is known.
            row_ok = hmac.compare_digest(audit_mac_bytes(r["row_hash"]), audit_mac_bytes(expected))
            if not row_ok and first_break is None:
                first_break = int(r["id"])
            prev = r["row_hash"] or ""
        if first_break is not None:
            return False, f"audit chain broken at row id={first_break}"
        if expected_anchor is not None:
            exp_count, exp_head = expected_anchor
            head_ok = hmac.compare_digest(audit_mac_bytes(prev), audit_mac_bytes(exp_head))
            if len(rows) < exp_count or not head_ok:
                return (
                    False,
                    f"audit log diverges from recorded anchor (have {len(rows)} row(s) head "
                    f"{prev[:12]!r}, expected {exp_count} head {exp_head[:12]!r}) — truncated or rewritten",
                )
        return True, f"verified {len(rows)} audit row(s)"

    # --- auth: users / roles / sessions --------------------------------------

    async def list_audit(
        self,
        *,
        limit: int = 50,
        actor: str | None = None,
        action: str | None = None,
        since: float | None = None,
        until: float | None = None,
    ) -> list[dict[str, Any]]:
        """Most-recent-first audit entries, optionally filtered (BACKLOG #170).

        Filters are ANDed as bound ``?`` parameters (the ``TOP (?)`` limit is the first ``?``, so its
        value leads the tuple) — only the fixed column/operator template is formatted into the SQL,
        never a value — so a filter value cannot inject."""
        clauses: list[str] = []
        params: list[Any] = [limit]
        if actor is not None:
            clauses.append("actor = ?")
            params.append(actor)
        if action is not None:
            clauses.append("action = ?")
            params.append(action)
        if since is not None:
            clauses.append("ts >= ?")
            params.append(since)
        if until is not None:
            clauses.append("ts <= ?")
            params.append(until)
        where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
        sql = f"SELECT TOP (?) * FROM audit_log{where} ORDER BY id DESC"
        return await self._fetchall(sql, tuple(params))

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
        self,
        approval_id: str,
        *,
        status: str,
        approver: str | None,
        decided_at: float,
        from_status: str = "pending",
    ) -> bool:
        """Atomically move a request in ``from_status`` to ``status``.
        Returns ``True`` iff this call made the transition — guards against a double decision.
        The SQLite twin documents why the guard is a parameter (ASVS 2.3.3)."""
        async with self._acquire() as conn, self._cursor(conn) as cur:
            try:
                await cur.execute(
                    "UPDATE pending_approvals SET status = ?, approver = ?, decided_at = ?"
                    " WHERE id = ? AND status = ?",
                    (status, approver, decided_at, approval_id, from_status),
                )
                count = cur.rowcount
                await self._commit(conn)
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

    async def get_user_by_federated_subject(self, issuer: str, subject: str) -> UserRecord | None:
        # BACKLOG #1256. Both columns, never `subject` alone -- a subject is unique only within its
        # issuer. NOTE the comparison is the DATABASE's, and these columns carry no explicit COLLATE:
        # under a case-insensitive server default two subjects differing only in case would match
        # here, which is SAFE for this predicate (it can only refuse MORE) but is the opposite of the
        # byte-exact comparison SQLite and Postgres perform. The BIN2 remedy this file applies to
        # `reference_sets.[key]` is the fix if that divergence ever needs closing.
        d = await self._fetchone(
            "SELECT * FROM users WHERE oidc_issuer=? AND oidc_subject=?", (issuer, subject)
        )
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
        must_change_password: bool = True,
        now: float | None = None,
    ) -> None:
        now = time.time() if now is None else now
        claim_set = password_claim_set(must_change_password, "?")
        claim_args: tuple[float, ...] = () if must_change_password else (now,)
        await self._execute(
            "UPDATE users SET password_hash=?, password_changed_at=?, must_change_password=?,"
            f"{claim_set}"
            " failed_attempts=0, locked_until=NULL, updated_at=? WHERE id=?",
            (password_hash, now, 1 if must_change_password else 0, *claim_args, now, user_id),
        )

    # --- MFA: native TOTP second factor (local accounts, WP-14) --------------

    async def set_totp_secret(
        self, user_id: str, *, secret: str | None, now: float | None = None
    ) -> None:
        """Stage (or clear) a user's base32 TOTP secret, store-cipher encrypted. Does not enable MFA."""
        now = time.time() if now is None else now
        enc = (
            self._cipher.encrypt(secret, aad=cell_aad("users", "totp_secret", user_id))
            if secret
            else None
        )
        await self._execute(
            "UPDATE users SET totp_secret=?, updated_at=? WHERE id=?", (enc, now, user_id)
        )

    async def get_totp_secret(self, user_id: str) -> str | None:
        d = await self._fetchone("SELECT totp_secret FROM users WHERE id=?", (user_id,))
        if not d or d["totp_secret"] is None:
            return None
        return self._cipher.decrypt(d["totp_secret"], aad=cell_aad("users", "totp_secret", user_id))

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
                    await self._commit(conn)
                    return False
                hashes = [str(h) for h in json.loads(raw)]
                if code_hash not in hashes:
                    await self._commit(conn)
                    return False  # already consumed by a concurrent caller
                hashes.remove(code_hash)
                await cur.execute(
                    "UPDATE users SET totp_recovery_codes=?, updated_at=? WHERE id=?",
                    (json.dumps(hashes), now, user_id),
                )
                await self._commit(conn)
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
                    await self._commit(conn)
                    return False
                last = rows[0][0]
                if last is not None and last >= step:
                    await self._commit(conn)
                    return False  # already consumed (or an older step) — replay within the window
                await cur.execute("UPDATE users SET last_totp_step=? WHERE id=?", (step, user_id))
                await self._commit(conn)
                return True
            except Exception:
                await conn.rollback()
                raise

    # --- WebAuthn credentials (WP-14b, ADR 0068) ------------------------------

    async def add_webauthn_credential(self, cred: WebAuthnCredential) -> None:
        """Persist one enrolled passkey. Public keys are plaintext by design (COSE verification
        material, not a secret — excluded from cipher + rekey). A duplicate ``(user_id, label)``
        raises pyodbc's IntegrityError via ``ux_webauthn_label`` — the caller renders it as the
        same "label already in use" error as its pre-check (the concurrent-enroll race, ADR 0068
        §4)."""
        await self._execute(
            "INSERT INTO webauthn_credentials (credential_id_hash, credential_id, user_id,"
            " rp_id, public_key, sign_count, transports, device_type, backed_up, label,"
            " aaguid, created_at, last_used_at)"
            " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                cred.credential_id_hash,
                cred.credential_id,
                cred.user_id,
                cred.rp_id,
                cred.public_key,
                cred.sign_count,
                json.dumps(cred.transports) if cred.transports is not None else None,
                cred.device_type,
                1 if cred.backed_up else 0,
                cred.label,
                cred.aaguid,
                cred.created_at,
                cred.last_used_at,
            ),
        )

    async def list_webauthn_credentials(self, user_id: str) -> list[WebAuthnCredential]:
        """All of a user's enrolled passkeys, oldest first."""
        rows = await self._fetchall(
            "SELECT * FROM webauthn_credentials WHERE user_id=? ORDER BY created_at, label",
            (user_id,),
        )
        return [WebAuthnCredential.from_mapping(d) for d in rows]

    async def get_webauthn_credential(self, credential_id_hash: str) -> WebAuthnCredential | None:
        """One credential by its id-hash PK, or None."""
        d = await self._fetchone(
            "SELECT * FROM webauthn_credentials WHERE credential_id_hash=?",
            (credential_id_hash,),
        )
        return WebAuthnCredential.from_mapping(d) if d else None

    async def has_webauthn_credentials(self, user_id: str) -> bool:
        """True when the user has at least one enrolled passkey (the second-factor predicate)."""
        d = await self._fetchone(
            "SELECT TOP (1) 1 AS present FROM webauthn_credentials WHERE user_id=?", (user_id,)
        )
        return d is not None

    async def any_webauthn_credentials(self) -> bool:
        """True when ANY passkey is enrolled — the L5b extra-less-install startup advisory's
        cheap probe (ADR 0068 decision 5)."""
        row = await self._fetchone("SELECT TOP (1) 1 AS present FROM webauthn_credentials")
        return row is not None

    async def delete_webauthn_credential(self, user_id: str, credential_id_hash: str) -> bool:
        """Delete one credential; True iff a row was removed (rowcount-guarded — the ``user_id``
        predicate keeps the action self-scoped even if a foreign id-hash is submitted)."""
        async with self._acquire() as conn, self._cursor(conn) as cur:
            try:
                await cur.execute(
                    "DELETE FROM webauthn_credentials WHERE user_id=? AND credential_id_hash=?",
                    (user_id, credential_id_hash),
                )
                count = cur.rowcount
                await self._commit(conn)
            except Exception:
                await conn.rollback()
                raise
        return int(count) > 0

    async def delete_all_webauthn_credentials(self, user_id: str) -> int:
        """Remove every credential for a user (``admin_reset_mfa``); returns the count removed."""
        async with self._acquire() as conn, self._cursor(conn) as cur:
            try:
                await cur.execute("DELETE FROM webauthn_credentials WHERE user_id=?", (user_id,))
                count = cur.rowcount
                await self._commit(conn)
            except Exception:
                await conn.rollback()
                raise
        return max(int(count), 0)

    async def update_webauthn_sign_count(
        self, credential_id_hash: str, *, expected: int, new: int, used_at: float
    ) -> bool:
        """Strict compare-and-set of the authenticator sign counter (the ``consume_totp_step``
        precedent): ``True`` iff the stored count still equalled ``expected``. A miss means a
        concurrent assertion consumed the same counter — the caller treats it as a clone signal
        (ADR 0068 §4). The ``UPDLOCK`` SELECT + UPDATE run in one transaction so concurrent
        assertions can't both win."""
        async with self._acquire() as conn, self._cursor(conn) as cur:
            try:
                await cur.execute(
                    "SELECT sign_count FROM webauthn_credentials WITH (UPDLOCK, ROWLOCK)"
                    " WHERE credential_id_hash=?",
                    (credential_id_hash,),
                )
                # fetchall reads the counter AND drains the SELECT so the same-cursor UPDATE below
                # is clean; `_cursor` closes the cursor before the pooled connection is reused (EF-6).
                rows = await cur.fetchall()
                if not rows or int(rows[0][0]) != expected:
                    await self._commit(conn)
                    return False  # missing row, or a concurrent assertion moved the counter
                await cur.execute(
                    "UPDATE webauthn_credentials SET sign_count=?, last_used_at=?"
                    " WHERE credential_id_hash=?",
                    (new, used_at, credential_id_hash),
                )
                await self._commit(conn)
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
                await cur.execute("DELETE FROM webauthn_credentials WHERE user_id=?", (user_id,))
                # BACKLOG #1233, verbatim with the SQLite and Postgres bodies: presets are
                # owner-scoped by Identity.user_id (#1225) with no FK cascade, so without this the
                # rows outlive the account carrying PHI-shaped `criteria` (ADR 0136) that no owner can
                # reach or purge. This leg is CI-only, so an asymmetry between the three backends
                # surfaces first in CI rather than here.
                await cur.execute("DELETE FROM search_presets WHERE owner_user_id=?", (user_id,))
                await cur.execute("DELETE FROM users WHERE id=?", (user_id,))
                await self._commit(conn)
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
                await self._commit(conn)
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
                await self._commit(conn)
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

    async def set_user_federated_subject(
        self, user_id: str, issuer: str, subject: str, *, now: float | None = None
    ) -> None:
        """Bind a user's federated ``(issuer, sub)`` identity (BACKLOG #1015)."""
        now = time.time() if now is None else now
        await self._execute(
            "UPDATE users SET oidc_issuer=?, oidc_subject=?, updated_at=? WHERE id=?",
            (issuer, subject, now, user_id),
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
                await self._commit(conn)
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
                await self._commit(conn)
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

    async def rotate_session(self, token_hash: str, *, new_token_hash: str) -> bool:
        """Re-key a live session in place (ASVS 7.2.4). See :meth:`AuthStore.rotate_session`.

        Hand-rolled rather than via ``self._execute``, which discards the cursor: this op's whole
        contract is its rowcount. ``token_hash`` is ``NVARCHAR(64)`` and a hex digest is exactly 64
        chars, so the clustered-PK row move is width-safe."""
        async with self._acquire() as conn, self._cursor(conn) as cur:
            try:
                await cur.execute(
                    "UPDATE sessions SET token_hash=? WHERE token_hash=? AND revoked_at IS NULL",
                    (new_token_hash, token_hash),
                )
                count = cur.rowcount
                await self._commit(conn)
            except Exception:
                await conn.rollback()
                raise
        return bool(count)

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
                await self._commit(conn)
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
                await self._commit(conn)
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
