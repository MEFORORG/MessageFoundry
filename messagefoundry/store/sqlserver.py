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
import hashlib
import logging
import queue
import time
from collections.abc import AsyncIterator, Callable, Iterable, Iterator, Mapping, Sequence
from contextlib import asynccontextmanager, contextmanager
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
from messagefoundry.store.metadata import merge_user_metadata
from messagefoundry.store.pool_metrics import AcquireWaitHistogram, PoolStatus
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
    OwnedLanes,
    ReingressOriginMissing,
    ReingressOutcome,
    REINGRESS_TARGET_PREFIX,
    ResendKeyConflict,
    ResendOutcome,
    ResendSourceAmbiguous,
    ResendSourceEmpty,
    ResendSourceNotFound,
    SessionRecord,
    Stage,
    UserRecord,
    WebAuthnCredential,
    _append_channel_scope,
    _qmark_cutoff_case,
    audit_row_hash,
    delivery_key,
    owned_lane_scope,
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
_SQL_SELECT_MESSAGE_STATUS: Final[str] = "SELECT status FROM messages WHERE id=?"
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
    """FILTERED only if the message was actually ROUTED; never clobber UNROUTED / ERROR / terminal."""
    if not mrows or mrows[0][0] != MessageStatus.ROUTED.value:
        return ("return", None)
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
    # Audit-chain keying watermark (#190) — single row (id=1). keyed_from_id = the first audit_log.id
    # hashed with the HMAC key; NULL/no row = the whole chain is keyless (byte-identical to pre-#190).
    """IF OBJECT_ID('audit_chain_meta','U') IS NULL CREATE TABLE audit_chain_meta (
        id INT NOT NULL PRIMARY KEY CHECK (id = 1), keyed_from_id BIGINT NULL)""",
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
    backend = StoreBackend.SQLSERVER

    def __init__(
        self,
        pool: Any,
        settings: StoreSettings,
        *,
        cipher: Cipher | None = None,
        audit_mac_key: bytes | None = None,
        message_events: str = "all",
        posture: HopPosture | None = None,
    ) -> None:
        self._pool = pool
        self._settings = settings
        # #200 (ADR 0092): the deriving instance posture, so reconnect / sync-handoff-pool rebuilds re-run
        # the weakened-TLS clamp against the real production-PHI posture (not the unclamped escape).
        self._posture = posture
        self._cipher: Cipher = cipher or IdentityCipher()
        # #190 audit-chain HMAC key (HKDF-derived; None → keyless chain) + keying watermark.
        self._audit_mac_key = audit_mac_key
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
        # A1 live cost counters (always-on, additive): committed_txns = durable WRITE transactions committed
        # on this store (the 3+2H+2N-per-message cost-model currency ADR 0051 sizes capacity on) — read-
        # snapshot-release commits (RCSI hygiene on a pure SELECT) go through the non-counting _commit_read
        # so they never inflate it; body_copies = raw/payload body strings durably written (the 2+H+N-per-
        # message amplification — SQL Server does NOT dedup a fan-out body, so N deliveries = N copies). Both
        # are bare int increments funneled through the write-commit helpers (_commit/_commit_sync) and the
        # insert helpers; no new lock, no commit-boundary change. See tests/test_live_cost_counters.py.
        self.committed_txns = 0
        self.body_copies = 0

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
        cls,
        settings: StoreSettings,
        *,
        cipher: Cipher | None = None,
        audit_mac_key: bytes | None = None,
        message_events: str = "all",
        posture: HopPosture | None = None,
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
        await cls._ensure_database_options(settings, posture=posture)
        pool = await aioodbc.create_pool(
            dsn=connection_string(settings, posture=posture),
            minsize=1,
            maxsize=max(1, settings.pool_size),
            autocommit=False,
        )
        store = cls(
            pool,
            settings,
            cipher=cipher,
            audit_mac_key=audit_mac_key,
            message_events=message_events,
            posture=posture,
        )
        try:
            await store._ensure_schema()
            await store._encrypt_existing_rows()  # one-time PHI-at-rest migration when a key is set
            await store._backfill_audit_chain()  # chain any pre-existing (unhashed) audit rows
            await store._load_audit_chain_meta()  # load/auto-init the #190 keying watermark
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
        if self._audit_mac_key is None:
            return
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

    def _audit_append_key(self) -> bytes | None:
        """The key a NEW ``audit_log`` row is hashed with (#190): keyed once the watermark is set.

        Fail-closed when keyed but the DEK is absent — appending a keyless row above the watermark would
        read as tampered under a later keyed verify, a FALSE break (review major-1; see SQLite twin)."""
        if self._audit_keyed_from is None:
            return None
        if self._audit_mac_key is None:
            raise RuntimeError(
                f"audit chain is keyed (from id={self._audit_keyed_from}) but no store encryption key "
                "is configured; refusing to append a keyless audit row above the keying watermark"
            )
        return self._audit_mac_key

    async def rekey_audit_chain(
        self, *, expected_anchor: tuple[int, str] | None = None
    ) -> tuple[bool, str]:
        """Non-silent #190-D migration — enable HMAC keying on an existing keyless chain. Refuses
        without a DEK, no-op if already keyed, verifies the existing chain first (refusing on any break),
        then sets the watermark to the next id (never rewrites existing hashes). See the SQLite twin."""
        if self._audit_mac_key is None:
            return False, "no store encryption key configured; cannot key the audit chain"
        if self._audit_keyed_from is not None:
            return True, f"audit chain already keyed from id={self._audit_keyed_from}"
        ok, msg = await self.verify_audit_chain(expected_anchor=expected_anchor)
        if not ok:
            return False, f"refusing to key a broken audit chain: {msg}"
        async with self._audit_lock:
            async with self._acquire() as conn, self._cursor(conn) as cur:
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
                        await self._commit(conn)
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
                        await self._commit(conn)
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
                        await self._commit(conn)
                    except Exception:
                        await conn.rollback()
                        raise
                total += len(rows)
        if total:
            log.info("encrypted %d existing message/outbox/response row(s) at rest", total)

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
        # Tear down any synchronous fused-handoff pools first (best-effort; a no-op when none were
        # opened, so it never affects the async path). ADR 0071 B5.
        self.close_sync_handoff_pool()
        self._pool.close()
        await self._pool.wait_closed()

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
        return [dict(zip(columns, row)) for row in rows]

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
            _event_params(message_id, now, event, destination, self._enc(detail)),
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
        handler ran, delivered nothing); else leave (UNROUTED/ERROR/in-progress not clobbered)."""
        # A per-message NAMED lock — NOT a messages-row lock, which would invert the queue->messages
        # lock order the producers take and deadlock (error 1205). Re-entrant; released at commit.
        await self._applock(cur, f"mefor:finalize:{message_id}")
        await cur.execute(_SQL_FINALIZE_COUNT, (message_id,))
        rows = await cur.fetchall()
        action, status = _finalize_from_queue_rows(rows)
        if action == "check_message":
            # No queue rows remain: the router/handlers produced no delivery. FILTERED only if it was
            # actually routed; never clobber UNROUTED / ERROR / a status already set terminal. fetchall
            # (not a lone fetchone) reads the status AND drains the SELECT so the same-cursor UPDATE
            # below is clean; `_cursor` (EF-6) closes the cursor at the caller's block exit.
            await cur.execute(_SQL_SELECT_MESSAGE_STATUS, (message_id,))
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
            cur.execute(_SQL_SELECT_MESSAGE_STATUS, (message_id,))
            mrows = cur.fetchall()
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
            mrows = await acc.read_all(_SQL_SELECT_MESSAGE_STATUS, (message_id,))
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
                await self._commit(conn)
            except Exception:
                await conn.rollback()
                raise
        return mid

    async def _insert_outbound(
        self, cur: Any, message_id: str, channel_id: str, dest_name: str, payload: str, now: float
    ) -> None:
        """Insert one ``stage='outbound'`` queue row (lane = destination_name)."""
        await cur.execute(
            _SQL_INSERT_QUEUE_OUTBOUND,
            _insert_outbound_params(
                uuid4().hex, message_id, channel_id, dest_name, self._cipher.encrypt(payload), now
            ),
        )
        self.body_copies += (
            1  # A1: one inline transformed-body copy per delivery (no fan-out dedup)
        )

    def _insert_outbound_sync(
        self, cur: Any, message_id: str, channel_id: str, dest_name: str, payload: str, now: float
    ) -> None:
        """Synchronous twin of :meth:`_insert_outbound` (ADR 0071 B5)."""
        cur.execute(
            _SQL_INSERT_QUEUE_OUTBOUND,
            _insert_outbound_params(
                uuid4().hex, message_id, channel_id, dest_name, self._cipher.encrypt(payload), now
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
        await cur.execute(
            _SQL_INSERT_QUEUE_ROUTED,
            _insert_routed_params(
                uuid4().hex,
                message_id,
                channel_id,
                handler_name,
                self._cipher.encrypt(payload),
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
        cur.execute(
            _SQL_INSERT_QUEUE_ROUTED,
            _insert_routed_params(
                uuid4().hex,
                message_id,
                channel_id,
                handler_name,
                self._cipher.encrypt(payload),
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
                    self._cipher.encrypt(body),
                    MessageStatus.RECEIVED.value,
                    None,
                    None,
                    self._enc(child_meta),
                ),
            )
            await cur.execute(
                _SQL_INSERT_QUEUE_INGRESS,
                _insert_queue_ingress_params(
                    uuid4().hex, new_mid, pt_channel, self._cipher.encrypt(body), now
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
                    self._cipher.encrypt(body),
                    MessageStatus.RECEIVED.value,
                    None,
                    None,
                    self._enc(child_meta),
                ),
            )
            cur.execute(
                _SQL_INSERT_QUEUE_INGRESS,
                _insert_queue_ingress_params(
                    uuid4().hex, new_mid, pt_channel, self._cipher.encrypt(body), now
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
        await cur.execute(
            _SQL_INSERT_QUEUE_OUTBOUND,
            _insert_marker_params(
                uuid4().hex, parent_id, pt_name, self._cipher.encrypt(""), status, now
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
        cur.execute(
            _SQL_INSERT_QUEUE_OUTBOUND,
            _insert_marker_params(
                uuid4().hex, parent_id, pt_name, self._cipher.encrypt(""), status, now
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
                # A1: enqueue_ingress writes TWO durable raw copies — messages.raw (above) and the ingress
                # queue.payload (just now) — the 2 of the 2+H+N amplification.
                self.body_copies += 2
                await self._event(cur, mid, "received", None, "ingress", now)
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
                    acc.add(
                        _SQL_INSERT_QUEUE_ROUTED,
                        _insert_routed_params(
                            uuid4().hex,
                            message_id,
                            channel_id,
                            handler_name,
                            self._cipher.encrypt(payload),
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

        ADR 0075: when ``batch_handoff_statements`` is active AND there are no ``pt_deliveries``,
        dispatches to :meth:`_transform_handoff_batched` (fewer round-trips, IDENTICAL logical sequence,
        one commit). The rare PT re-ingress branch (extra interleaved reads via the passthrough helpers)
        stays on the proven unbatched path below — a bounded, deliberate scope for the prototype. Default-
        OFF path below is byte-identical to before ADR 0075."""
        # getattr default keeps a bare store (the offline-test idiom) on the safe unbatched path. The
        # SetMeta merge (#150), like PT re-ingress, needs an interleaved metadata read+update, so it
        # stays on the proven unbatched path — the same bounded exclusion as pt_deliveries.
        if getattr(self, "_batch_handoff_statements", False) and not pt_deliveries and not meta_ops:
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
                    enc = self._cipher.encrypt(json.dumps(value))
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
                    pmeta_dec = self._dec(prow[0]) if prow else None
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
                    await cur.execute(_SQL_UPDATE_METADATA, (self._enc(merged), message_id))
                total_targets = len(deliveries) + len(pt_deliveries)
                await self._event(
                    cur, message_id, "transformed", None, f"{total_targets} destination(s)", now
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
                    enc = self._cipher.encrypt(json.dumps(value))
                    acc.add(
                        _SQL_STATE_MERGE, _state_merge_params(namespace, key, enc, now, message_id)
                    )
                    applied.append(((namespace, key), value))
                for dest_name, payload in deliveries:
                    acc.add(
                        _SQL_INSERT_QUEUE_OUTBOUND,
                        _insert_outbound_params(
                            uuid4().hex,
                            message_id,
                            channel_id,
                            dest_name,
                            self._cipher.encrypt(payload),
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
                enc = self._cipher.encrypt(json.dumps(value))
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
                pmeta_dec = self._dec(prow[0]) if prow else None
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
                cur.execute(_SQL_UPDATE_METADATA, (self._enc(merged), message_id))
            total_targets = len(deliveries) + len(pt_deliveries)
            self._event_sync(
                cur, message_id, "transformed", None, f"{total_targets} destination(s)", now
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
                    await self._commit(conn)
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
                    await self._commit(conn)
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
                        await self._commit(conn)
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
                    await self._commit(conn)
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
                        await self._commit(conn)
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
                await self._commit(conn)
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
        # chunk clamp; the caller covers the remainder with a second call.
        lane_list = list(dict.fromkeys(lanes))[:_FIFO_HEADS_LANE_CHUNK]
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
        lanes_values = ",".join("(?)" for _ in lane_list)
        # One batch, executed as a single parameterized statement. SET NOCOUNT ON suppresses the
        # per-statement rowcount results so the final SELECT is the SOLE result set (EF-6). Row ids
        # live in table variables server-side — they never travel as parameters.
        sql = (
            "SET NOCOUNT ON;"
            # ADR 0066 §9 (documented swap): SET LOCK_TIMEOUT 0 makes this claim STRUCTURALLY
            # never-block — no statement in the batch ever WAITS on a row lock; a lock it cannot
            # immediately acquire raises error 1222 (translated to EMPTY-all below), never a
            # command_timeout-length pin. Under RCSI-on with a working READPAST probe no statement
            # waits, so 1222 never fires and behavior is byte-identical; 1222 only triggers in the
            # degraded edge (e.g. RCSI off, the probe waits) that was pinning a pooled connection for
            # ~30s and segfaulting pyodbc on the torn-down connection. LOCK_TIMEOUT is SESSION-scoped
            # and persists on the pooled connection, so the finally-guard resets it on EVERY exit path.
            " SET LOCK_TIMEOUT 0;"
            " DECLARE @now FLOAT = ?, @stage NVARCHAR(16) = ?, @k INT = ?,"
            " @pending NVARCHAR(32) = ?, @inflight NVARCHAR(32) = ?;"
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
            f" FROM (VALUES {lanes_values}) AS l(lane)"
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
            # LOCK_TIMEOUT is SESSION-scoped and persists on the pooled connection; the finally-guard
            # below (not a trailing batch statement) does the reset uniformly on EVERY exit path —
            # success, 1222, and any other error — and commits it, so no connection returns to the
            # pool with LOCK_TIMEOUT 0 or mid-transaction.
        )
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
        async with self._acquire() as conn, self._cursor(conn) as cur:
            try:
                await cur.execute(sql, args)
                columns = [c[0] for c in cur.description] if cur.description else []
                # EF-6: drain the result set with fetchall; _cursor closes the statement handle
                # before the connection returns to the pool (no-MARS).
                rows = await cur.fetchall()
                decoded = [dict(zip(columns, r)) for r in rows]
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
            except Exception as exc:
                await conn.rollback()
                if _is_lock_timeout(exc):
                    # SET LOCK_TIMEOUT 0 fired (error 1222): a probe could not IMMEDIATELY acquire a
                    # contended head lock. This IS the never-block guarantee working — the head is
                    # contended, so YIELD: return EMPTY-all (exactly the EMPTY-on-locked-head
                    # semantics; the head stays PENDING, attempts untouched, the sweep re-tries it).
                    # Contention is normal at scale, so log at DEBUG, not WARNING.
                    log.debug(
                        "claim_fifo_heads: lock-timeout (1222) at stage %s on %d lane(s) — head"
                        " contended, yielding EMPTY (never-block guarantee)",
                        stage,
                        len(lane_list),
                    )
                    return ClaimedHeads(by_lane={}, rearm=frozenset())
                raise
            finally:
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
                for message_id in finalize:
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
                    (status, next_at, self._enc(error), now, outbox_id),
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
                        (status, next_at, self._enc(error), now, outbox_id),
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
                for message_id in finalize:
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
                        (OutboxStatus.DEAD.value, now, self._enc(error), now, outbox_id),
                    )
                    await self._event(cur, message_id, "dead", destination_name, error, now)
                    finalize[message_id] = None
                for message_id in finalize:
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
                    (OutboxStatus.DEAD.value, now, self._enc(error), now, outbox_id),
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
                        (OutboxStatus.DEAD.value, now, self._enc(error), now, row[0]),  # H4
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
                    raw_meta = self._dec(mrow[3])
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
                            self._cipher.encrypt(body),
                            MessageStatus.ROUTED.value,
                            None,
                            None,
                            self._enc(child_meta),
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
                            outbox_id, child_mid, src_channel, to, self._cipher.encrypt(body), now
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
                        " COALESCE(sb.body, q.payload) AS body_ciphertext"
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
                    decoded = self._dec(body_ciphertext)
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
                            outbox_id, message_id, src_channel, to, self._cipher.encrypt(body), now
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
                raw_meta = self._dec(metadata_ciphertext)
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
                            self._cipher.encrypt(raw),
                            MessageStatus.RECEIVED.value,
                            None,
                            None,
                            self._enc(child_meta),
                        ),
                    )
                    await cur.execute(
                        _SQL_INSERT_QUEUE_INGRESS,
                        (
                            uuid4().hex,
                            new_mid,
                            Stage.INGRESS.value,
                            channel_id,
                            self._cipher.encrypt(raw),
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
            record["raw"] = self._cipher.decrypt(record["raw"])  # decrypt the body for display
            record["error"] = self._dec(record["error"])  # H4: error may embed raw HL7 fragments
            record["summary"] = self._dec(record["summary"])  # EF-3: MRN/name PHI, ciphered at rest
            record["metadata"] = self._dec(record["metadata"])  # EF-3
        return record

    async def message_metadata_json(self, message_id: str) -> str | None:
        # #68: decrypt ONLY the metadata column (never the raw PHI body) for the delivery worker's
        # per-message dynamic headers. Off the perf-critical claim path; read only for opted-in outbounds.
        record = await self._fetchone("SELECT metadata FROM messages WHERE id=?", (message_id,))
        if record is None:
            return None
        return self._dec(record["metadata"])

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
                        key=self._audit_append_key(),  # keyed once the #190 watermark is set, else keyless
                    )
                    await cur.execute(
                        "INSERT INTO audit_log (ts, actor, action, channel_id, detail, row_hash)"
                        " VALUES (?,?,?,?,?,?)",
                        (now, actor, action, channel_id, detail, row_hash),
                    )
                    await self._commit(conn)
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
        ``expected_anchor`` from :meth:`audit_anchor`, held out-of-band, to detect it (review low-1)."""
        if self._audit_keyed_from is not None and self._audit_mac_key is None:
            return (
                False,
                "audit chain is keyed (from id="
                f"{self._audit_keyed_from}) but no store encryption key is configured to verify it",
            )
        rows = await self._fetchall(
            "SELECT id, ts, actor, action, channel_id, detail, row_hash FROM audit_log ORDER BY id"
        )
        prev = ""
        for r in rows:
            key = (
                self._audit_mac_key
                if self._audit_keyed_from is not None and int(r["id"]) >= self._audit_keyed_from
                else None
            )
            expected = audit_row_hash(
                prev,
                ts=r["ts"],
                actor=r["actor"],
                action=r["action"],
                channel_id=r["channel_id"],
                detail=r["detail"],
                key=key,
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
