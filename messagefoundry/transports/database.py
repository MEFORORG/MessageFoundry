# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""DATABASE transport: a SQL destination that runs one parameterized statement per payload.

The **destination** executes the operator-declared ``statement`` (an INSERT/UPDATE or a stored-procedure
call) against an outbound database, binding the payload's fields to the statement's ``:name``
parameters. The first backend is **SQL Server over ``aioodbc``** (ADR 0003) — the ``[sqlserver]`` extra
(``pip install 'messagefoundry[sqlserver]'``) plus the Microsoft ODBC Driver 18, **lazily imported** so
SQLite-only installs never touch it. **Status: production / supported** — SQL Server only, via that
extra. The live aioodbc round-trip is exercised by the CI SQL Server service-container job
(``tests/test_database_connector_integration.py``); the connector logic is also unit-tested with a
faked driver. The SQL Server *store* backend is a **separate** (also production) layer — this
connector does not depend on it.

**Parameters.** The Handler produces a **JSON object** body; the connector binds its keys to the
``:name`` placeholders in ``statement`` (translated to positional ODBC ``?`` — always parameterized,
never string-built, so a value can't inject SQL). A ``:name`` must not appear inside a quoted string
literal in the statement (bind dynamic strings as parameters, which is the correct practice anyway).

**Error mapping.** A *transient* DB failure (connection drop / deadlock / timeout — SQLSTATE class
``08``/``40`` or ``HYTxx``) → :class:`DeliveryError` (the lane retries). A *permanent* failure
(constraint / data / syntax) and a payload that doesn't match the statement → :class:`NegativeAckError`
(``permanent=True``) → dead-letter, since a retry can't fix it.

**Idempotency.** Delivery is at-least-once, so a retry **re-executes** the statement. Use an idempotent
write (``MERGE``/upsert on a natural key, or a de-dup) so a retry doesn't double-apply. See
docs/CONNECTIONS.md.
"""

from __future__ import annotations

import asyncio
import base64
import json
import logging
import re
from collections.abc import Callable, Mapping
from datetime import date, datetime
from decimal import Decimal
from typing import Any

from messagefoundry.config.db_lookup import DbLookupError
from messagefoundry.config.models import ConnectorType, Destination, Source
from messagefoundry.config.settings import INSECURE_TLS_ESCAPE_ENV, insecure_tls_allowed
from messagefoundry.transports.base import (
    DeliveryError,
    DeliveryResponse,
    DestinationConnector,
    InboundHandler,
    NegativeAckError,
    SourceConnector,
    register_destination,
    register_source,
)

__all__ = ["DatabaseDestination", "DatabaseLookupExecutor", "DatabaseSource"]

logger = logging.getLogger(__name__)

# A `:name` parameter, but not `::` (a PostgreSQL-style cast) and not a `:` preceded by a word char
# (so a time literal like '12:30' inside the SQL is left alone). String-literal colons are otherwise
# the operator's responsibility — bind dynamic strings as parameters, not inline literals.
_PARAM_RE = re.compile(r"(?<![:\w]):(\w+)")

# SQLSTATE classes that are worth retrying: 08 = connection exception, 40 = transaction rollback /
# deadlock (40001); plus the ODBC connect/operation timeouts.
_TRANSIENT_PREFIXES = ("08", "40")
_TRANSIENT_STATES = frozenset({"HYT00", "HYT01"})


def _odbc_brace(value: str) -> str:
    """ODBC-quote a value in braces, doubling any internal ``}`` — neutralizes ``; { } =`` inside it so
    an attacker-influenced value (e.g. a password) can't inject extra connection keywords (mirrors the
    store's ``connection_string`` hardening)."""
    return "{" + value.replace("}", "}}") + "}"


def _build_dsn(s: dict[str, Any]) -> str:
    """Build the ODBC connection string for SQL Server from the connection settings.

    Free-text values are brace-quoted (injection guard) and the ``Encrypt``/``TrustServerCertificate``
    flags are emitted **last** (ODBC is last-wins, so nothing earlier can downgrade TLS). A weakened
    TLS posture is **refused** unless the explicit dev escape is set, exactly like the store backend."""
    encrypt = bool(s.get("encrypt", True))
    trust = bool(s.get("trust_server_certificate", False))
    if (trust or not encrypt) and not insecure_tls_allowed():
        raise ValueError(
            "DATABASE destination TLS is weakened (trust_server_certificate=true or encrypt=false), "
            f"which is MITM-able. Use a trusted server certificate, or set {INSECURE_TLS_ESCAPE_ENV}=1 "
            "to explicitly allow it for a trusted-network dev/test bind."
        )
    auth = str(s.get("auth", "sql")).lower()
    if auth not in ("sql", "integrated", "entra"):
        raise ValueError(f"DATABASE destination auth must be sql|integrated|entra, got {auth!r}")
    # SERVER must be emitted UNBRACED so the driver parses the ",port" suffix and resolves the host for
    # the TLS handshake — a brace-quoted "SERVER={host},port" is malformed ODBC (content after the
    # closing brace) and breaks certificate handling against a real SQL Server. So the host is
    # *validated* for connection-string metacharacters instead of brace-quoted (the guard used for every
    # other free-text value), exactly like the store backend's connection_string.
    server = str(s["server"])
    if any(ch in server for ch in ";{}=\r\n"):
        raise ValueError(
            "DATABASE server must not contain ';', '{', '}', '=', or newlines (ODBC injection risk)"
        )
    parts = [
        f"DRIVER={_odbc_brace(str(s.get('odbc_driver', 'ODBC Driver 18 for SQL Server')))}",
        f"SERVER={server},{int(s.get('port', 1433))}",
        f"DATABASE={_odbc_brace(str(s['database']))}",
        f"Connection Timeout={int(s.get('connect_timeout', 15))}",
        f"APP={_odbc_brace(str(s.get('app_name', 'messagefoundry')))}",
    ]
    if auth == "sql":
        parts.append(f"UID={_odbc_brace(str(s.get('username') or ''))}")
        parts.append(f"PWD={_odbc_brace(str(s.get('password') or ''))}")
    elif auth == "integrated":
        parts.append("Trusted_Connection=yes")
    else:  # entra
        parts.append("Authentication=ActiveDirectoryDefault")
    parts.append(f"Encrypt={'yes' if encrypt else 'no'}")
    parts.append(f"TrustServerCertificate={'yes' if trust else 'no'}")
    return ";".join(parts) + ";"


def _parse_named_params(statement: str) -> tuple[str, list[str]]:
    """Translate ``:name`` placeholders to positional ``?`` and return ``(sql, ordered_names)``."""
    names: list[str] = []

    def repl(m: re.Match[str]) -> str:
        names.append(m.group(1))
        return "?"

    return _PARAM_RE.sub(repl, statement), names


def _bind_params(payload: str, names: list[str]) -> tuple[Any, ...]:
    """Bind a JSON-object payload to the statement's ``names`` (positional order).

    A payload that isn't a JSON object, or that's missing a parameter, is a **permanent** data error
    (a retry can't fix it) → :class:`NegativeAckError`."""
    try:
        data = json.loads(payload)
    except json.JSONDecodeError as exc:
        raise NegativeAckError(
            f"DATABASE payload is not valid JSON: {exc}", code="payload", permanent=True
        ) from exc
    if not isinstance(data, dict):
        raise NegativeAckError(
            "DATABASE payload must be a JSON object mapping parameter names to values",
            code="payload",
            permanent=True,
        )
    try:
        return tuple(data[n] for n in names)
    except KeyError as exc:
        raise NegativeAckError(
            f"DATABASE payload is missing parameter {exc}", code="payload", permanent=True
        ) from exc


def _is_transient(sqlstate: str) -> bool:
    return sqlstate[:2] in _TRANSIENT_PREFIXES or sqlstate in _TRANSIENT_STATES


def _classify_db_error(sqlstate: str, message: str) -> DeliveryError:
    """Map a DB error's SQLSTATE to a transient :class:`DeliveryError` (retry) or a permanent
    :class:`NegativeAckError` (dead-letter)."""
    if _is_transient(sqlstate):
        return DeliveryError(f"database transient error [{sqlstate}]: {message}")
    return NegativeAckError(
        f"database rejected the statement [{sqlstate}]: {message}",
        code=sqlstate or "db",
        permanent=True,
    )


def _sqlstate(exc: BaseException) -> str | None:
    """The 5-character SQLSTATE a DB driver error carries in ``args[0]`` (pyodbc/aioodbc), or ``None``
    if ``exc`` isn't shaped like a DB error — letting a genuine bug propagate as an internal error
    rather than being misread as a transport failure."""
    args = getattr(exc, "args", ())
    if args and isinstance(args[0], str) and len(args[0]) == 5 and args[0].isalnum():
        return args[0]
    return None


def _import_aioodbc() -> Any:
    """Import the optional ``aioodbc`` driver, raising a clear install hint if the ``[sqlserver]`` extra
    isn't present — so a SQLite-only install never touches it until a DATABASE connector is actually used."""
    try:
        import aioodbc
    except ImportError as exc:  # pragma: no cover - exercised only without the extra
        raise RuntimeError(
            "DATABASE connector requires the 'sqlserver' extra: "
            "pip install 'messagefoundry[sqlserver]' (plus the Microsoft ODBC Driver 18)"
        ) from exc
    return aioodbc


async def _make_pool(dsn: str, pool_max: int, *, autocommit: bool) -> Any:
    """Create an aioodbc connection pool for ``dsn`` (lazy driver import). The destination wraps
    execute+commit itself (``autocommit=False``); the source marks each row in its own auto-committed
    statement (``autocommit=True``)."""
    aioodbc = _import_aioodbc()
    return await aioodbc.create_pool(
        dsn=dsn, minsize=1, maxsize=max(1, pool_max), autocommit=autocommit
    )


# WP-L3-07 (ASVS 13.1.2/13.2.6): bound a pooled-connection borrow. One delivery/poll worker per
# connection means pool_max is never legitimately exhausted, so an acquire that can't be satisfied
# within the timeout means the pool is wedged or the DB is unresponsive — fail it transiently rather
# than block the worker forever (which would let the queue back up unbounded). Override per connection
# with the ``acquire_timeout`` setting.
_DEFAULT_DB_ACQUIRE_TIMEOUT = 30.0


async def _acquire(pool: Any, timeout: float) -> Any:
    """Acquire a connection from ``pool`` within ``timeout`` seconds, or raise a transient
    :class:`DeliveryError` with a clear, PHI-free message. Wraps the driver's own ``acquire`` so a
    hung/exhausted pool surfaces as a retryable failure instead of an unbounded await."""
    try:
        return await asyncio.wait_for(pool.acquire(), timeout)
    except TimeoutError as exc:
        raise DeliveryError(
            f"DATABASE pool acquire timed out after {timeout:g}s (pool exhausted or DB unresponsive)"
        ) from exc


async def _probe_db(
    get_pool: Callable[[], Any], *, timeout: float = _DEFAULT_DB_ACQUIRE_TIMEOUT
) -> None:
    """Open the pool and run ``SELECT 1`` — a no-data, no-write reachability probe shared by the
    DATABASE source and destination's ``test_connection``. A driver error is mapped via
    :func:`_classify_db_error` (transient vs permanent); a non-driver failure (e.g. an unreachable host
    before any SQLSTATE) becomes a transient :class:`DeliveryError`. Triggers the connector's lazy pool;
    the caller closes it with ``aclose()``."""
    try:
        pool = await get_pool()
        conn = await _acquire(pool, timeout)
    except Exception as exc:
        state = _sqlstate(exc)
        raise (
            _classify_db_error(state, str(exc))
            if state
            else DeliveryError(f"DATABASE connect failed: {exc}")
        ) from exc
    try:
        cur = await conn.cursor()
        await cur.execute("SELECT 1")
    except Exception as exc:
        state = _sqlstate(exc)
        raise (
            _classify_db_error(state, str(exc))
            if state
            else DeliveryError(f"DATABASE probe failed: {exc}")
        ) from exc
    finally:
        await pool.release(conn)


def _json_default(value: Any) -> Any:
    """JSON-serialize DB column types ``json.dumps`` can't handle natively (dates, ``Decimal``, bytes),
    so a polled row becomes a JSON-object body. An unknown type raises ``TypeError`` (surfaced as a
    poll error and logged) rather than silently dropping data."""
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    if isinstance(value, Decimal):
        return str(value)
    if isinstance(value, (bytes, bytearray)):
        return base64.b64encode(bytes(value)).decode("ascii")
    raise TypeError(
        f"DATABASE source cannot serialize a {type(value).__name__} column value to JSON"
    )


class DatabaseDestination(DestinationConnector):
    """Execute one parameterized statement per payload against a SQL database (SQL Server today)."""

    def __init__(self, config: Destination) -> None:
        s = config.settings
        for req in ("server", "database", "statement"):
            if not s.get(req):
                raise ValueError(f"DATABASE destination requires a {req!r} setting")
        self._dsn = _build_dsn(s)  # fail fast on a weakened-TLS / bad-auth config
        self._sql, self._param_names = _parse_named_params(str(s["statement"]))
        self._pool_max = int(s.get("pool_max", 5))
        self._acquire_timeout = float(s.get("acquire_timeout", _DEFAULT_DB_ACQUIRE_TIMEOUT))
        self._pool: Any = None
        self._pool_lock = asyncio.Lock()
        # ADR 0013: capture the statement's result-set (its RETURNING/OUTPUT rows). Default False →
        # returns None, byte-identical. Capture MUST be a RETURNING/OUTPUT clause of the write itself
        # (fetched from the SAME cursor BEFORE commit) — a separate post-commit SELECT would re-run on a
        # crash-replay against changed state. Wiring rejects a capturing statement with no RETURNING/
        # OUTPUT. The result-set is JSON-serialized and bounded by row/byte caps (over-cap →
        # outcome='unparseable' with an empty body, never an unbounded blob).
        self.capture_response: bool = bool(s.get("capture_response", False))
        self._capture_max_rows = int(s.get("capture_max_rows", 100))
        self._capture_max_bytes = int(s.get("capture_max_bytes", 256 * 1024))

    async def _get_pool(self) -> Any:
        if self._pool is not None:
            return self._pool
        async with self._pool_lock:
            if self._pool is None:
                self._pool = await _make_pool(self._dsn, self._pool_max, autocommit=False)
        return self._pool

    async def send(self, payload: str) -> DeliveryResponse | None:
        params = _bind_params(payload, self._param_names)  # NegativeAckError(permanent) on bad data
        pool = await self._get_pool()
        conn = await _acquire(pool, self._acquire_timeout)
        try:
            cur = await conn.cursor()
            try:
                await cur.execute(self._sql, params)
                # Capture the RETURNING/OUTPUT rows from the SAME cursor BEFORE commit (re-run-stable:
                # a separate post-commit SELECT could read changed state on a crash-replay). _capture
                # never raises — a capture problem must not roll back an otherwise-successful write.
                captured = await self._capture(cur) if self.capture_response else None
                await conn.commit()
            except Exception as exc:
                await conn.rollback()
                state = _sqlstate(exc)
                if state is None:
                    raise  # not a DB driver error → an internal/code error, let the runner handle it
                raise _classify_db_error(state, str(exc)) from exc
        finally:
            await pool.release(conn)
        return captured

    async def _capture(self, cur: Any) -> DeliveryResponse:
        """Serialize the statement's RETURNING/OUTPUT result-set to a bounded JSON body (ADR 0013).

        Never raises (capture must not un-succeed a committed write): a missing result set / over-cap
        becomes ``no_reply`` / ``unparseable`` with an empty body. Generated ids in a RETURNING are
        only as stable as the write's idempotency — a non-idempotent INSERT re-derives a new id on a
        crash-re-send (the standing 'outbounds must be idempotent' requirement; see the connector docs)."""
        try:
            rows = await cur.fetchall()
        except Exception:  # noqa: BLE001 - statement produced no result set; capture nothing, keep the write
            return DeliveryResponse(body="", outcome="no_reply", detail="no result set")
        if not rows:
            return DeliveryResponse(body="", outcome="no_reply", detail="0 rows")
        if len(rows) > self._capture_max_rows:
            return DeliveryResponse(
                body="",
                outcome="unparseable",
                detail=f"result-set exceeded capture_max_rows={self._capture_max_rows}",
            )
        try:
            cols = [d[0] for d in cur.description] if cur.description else []
            data = [dict(zip(cols, tuple(row))) for row in rows]
            body = json.dumps(data, default=_json_default)
        except Exception as exc:  # noqa: BLE001 - an unserializable column type must NOT fail the write
            # _json_default raises TypeError on a column type it can't encode; serializing must never
            # propagate (it runs pre-commit and would roll back an otherwise-successful write).
            return DeliveryResponse(
                body="",
                outcome="unparseable",
                detail=f"result-set not serializable ({type(exc).__name__})",
            )
        if len(body.encode("utf-8")) > self._capture_max_bytes:
            return DeliveryResponse(
                body="",
                outcome="unparseable",
                detail=f"result-set exceeded capture_max_bytes={self._capture_max_bytes}",
            )
        return DeliveryResponse(body=body, outcome="accepted", detail=f"{len(rows)} row(s)")

    async def test_connection(self) -> None:
        await _probe_db(self._get_pool, timeout=self._acquire_timeout)

    async def aclose(self) -> None:
        if self._pool is not None:
            self._pool.close()
            await self._pool.wait_closed()
            self._pool = None


class DatabaseSource(SourceConnector):
    """Poll a SQL table on an interval, hand each row to the pipeline handler, then mark it processed.

    The File source's *process-then-mark-done* shape (at-least-once), with a query instead of a
    directory: a cooperatively-cancellable background loop runs the operator-declared ``poll_statement``
    (a ``SELECT`` of the next batch), hands each row to the handler as a body, and — **only after the
    handler returns** — runs the optional ``mark_statement`` (an ``UPDATE``/``DELETE`` bound from that
    row's columns) so the row isn't re-read. A crash before the mark re-emits the row next poll
    (at-least-once); the downstream pipeline must tolerate duplicates. Poll errors are logged-not-fatal
    (a bad poll never kills the poller, mirroring the File source).

    **Body shape (payload-agnostic ingress, ADR 0004).** With ``body_column`` set, the body is that one
    column's value verbatim (e.g. a queue column holding an HL7 message → pair with ``content_type``
    ``hl7v2`` and it flows through the full HL7 path); unset, the body is the whole row as a JSON object
    ``{column: value}`` (pair with ``content_type=json`` so the Handler can ``.json()`` it).

    **Under ``[cluster].enabled`` (multi-node)** this source is leader-gated (only the leader polls,
    Track B Step 4b) — but unlike the File/RemoteFile sources, where the engine owns the atomic rename
    that bounds the leadership-transition duplicate window, the engine can't enforce row claim/mark
    atomicity here: it's on the operator's SQL. Write ``poll_statement``/``mark_statement`` to claim
    rows atomically (a status flag, or ``UPDATE ... RETURNING`` that both selects and marks) so the
    brief transition window stays at the same at-least-once duplicate class as a crash mid-poll.
    """

    polls_shared_resource = True  # a DB table is a shared external resource — leader-gate it

    def __init__(self, config: Source) -> None:
        s = config.settings
        for req in ("server", "database", "poll_statement"):
            if not s.get(req):
                raise ValueError(f"DATABASE source requires a {req!r} setting")
        self._dsn = _build_dsn(s)  # fail fast on a weakened-TLS / bad-auth config
        self._poll_sql = str(s["poll_statement"])
        mark = s.get("mark_statement")
        # mark_statement is optional (a read-only/idempotent feed may omit it); its :name params bind
        # from the polled row's columns, reusing the destination's named-parameter translation.
        self._mark_sql: str | None
        self._mark_sql, self._mark_names = _parse_named_params(str(mark)) if mark else (None, [])
        self._body_column: str | None = s.get("body_column") or None
        self._poll_seconds = float(s.get("poll_seconds", 5.0))
        self._encoding: str = s.get("encoding", "utf-8")
        self._pool_max = int(s.get("pool_max", 5))
        self._acquire_timeout = float(s.get("acquire_timeout", _DEFAULT_DB_ACQUIRE_TIMEOUT))
        self._pool: Any = None
        self._pool_lock = asyncio.Lock()
        self._handler: InboundHandler | None = None
        # Leader-gate (Track B Step 4b): when set, the poll table (a shared external resource) is
        # polled/marked only while the gate returns True, so in a cluster exactly one node ingests
        # its rows. None = always poll (single-node / direct callers / tests) — byte-identical.
        self._leader_gate: Callable[[], bool] | None = None
        self._skipping = False  # whether the last tick was gated out (for a single transition log)
        self._stop = asyncio.Event()
        self._task: asyncio.Task[None] | None = None

    async def start(
        self, handler: InboundHandler, *, leader_gate: Callable[[], bool] | None = None
    ) -> None:
        self._handler = handler
        self._leader_gate = leader_gate
        self._stop.clear()
        self._task = asyncio.create_task(self._run())

    async def stop(self) -> None:
        self._stop.set()
        if self._task is not None:
            # return_exceptions: a faulted poll task must not re-raise here — stop() runs during reload
            # quiesce, outside its rollback (mirrors the File source's belt-and-suspenders).
            await asyncio.gather(self._task, return_exceptions=True)
            self._task = None
        await self.aclose()

    async def _get_pool(self) -> Any:
        if self._pool is not None:
            return self._pool
        async with self._pool_lock:
            if self._pool is None:
                # autocommit: each mark is its own committed statement, giving per-row mark durability.
                self._pool = await _make_pool(self._dsn, self._pool_max, autocommit=True)
        return self._pool

    async def _run(self) -> None:
        while not self._stop.is_set():
            try:
                if self._may_poll():
                    await self._poll_once()
            except asyncio.CancelledError:
                raise
            except Exception:
                # A poll error (connection drop, a bad poll_statement, an unserializable column) must
                # NOT kill the poller — that would silently stop the connection from receiving while it
                # still reports running. Log and retry on the next interval (mirrors the File source).
                logger.exception("DATABASE source poll failed; retrying next interval")
            try:
                await asyncio.wait_for(self._stop.wait(), self._poll_seconds)
            except asyncio.TimeoutError:
                pass  # poll interval elapsed; poll again

    def _may_poll(self) -> bool:
        """Whether this tick may run poll_statement (and mark rows). False on a follower (leader-
        gated, Step 4b): a non-leader must NOT execute poll_statement or mark any rows, since the
        table is shared and two nodes polling it would duplicate intake. The loop still ticks, so a
        node that becomes leader polls on its next tick (reactive-by-polling, no restart). When the
        gate is None or True, behaves exactly as before. Logged once on each transition (never per
        skipped tick — that would spam a follower's log every poll interval)."""
        if self._leader_gate is None or self._leader_gate():
            if self._skipping:
                self._skipping = False
                logger.debug("DATABASE source resuming polling (now leader)")
            return True
        if not self._skipping:
            self._skipping = True
            logger.debug("DATABASE source skipping polling (not leader; another node ingests it)")
        return False

    async def _poll_once(self) -> None:
        assert self._handler is not None
        columns, rows = await self._select()
        for row in rows:
            if self._stop.is_set():
                break  # shutting down — leave the rest unmarked for the next start (at-least-once)
            record = dict(zip(columns, row))
            try:
                body = self._body(record)
            except (ValueError, TypeError) as exc:
                # A row we can't turn into a body (missing body_column, unserializable value) is a
                # config/data error for that row — log and skip it rather than wedging the batch.
                logger.error("DATABASE source: %s; skipping row", exc)
                continue
            try:
                await self._handler(body.encode(self._encoding))
            except Exception as exc:
                # The handler records every message-level outcome itself (parse/route → ERROR) and
                # returns, so an exception here is an infrastructure failure (the durable store write
                # failed). Leave the row UNMARKED so the next poll re-emits it (at-least-once) — marking
                # it now would drop a received-but-unrecorded message (mirrors the File source's M-15).
                logger.warning(
                    "DATABASE source handler failed (row left unmarked, will retry): %s", exc
                )
                continue
            try:
                await self._mark(record)
            except Exception as exc:
                # The handler already ingested the message; a mark failure means the row re-emits next
                # poll (a duplicate — at-least-once). Log and move on rather than abort the batch tail.
                logger.warning(
                    "DATABASE source mark failed (row will re-emit, a duplicate): %s", exc
                )

    async def _select(self) -> tuple[list[str], list[Any]]:
        """Run ``poll_statement`` and return ``(column_names, rows)``. The connection is released before
        the rows are handed to the (possibly slow) handler, so a batch never holds a pool connection
        hostage to downstream store I/O."""
        pool = await self._get_pool()
        conn = await _acquire(pool, self._acquire_timeout)
        try:
            cur = await conn.cursor()
            await cur.execute(self._poll_sql)
            columns = [d[0] for d in cur.description]
            rows = list(await cur.fetchall())
        finally:
            await pool.release(conn)
        return columns, rows

    def _body(self, record: dict[str, Any]) -> str:
        """The body for one row: a single column verbatim (``body_column``) or the whole row as JSON."""
        if self._body_column is not None:
            try:
                value = record[self._body_column]
            except KeyError:
                raise ValueError(
                    f"body_column {self._body_column!r} is not in the poll_statement result columns"
                ) from None
            if isinstance(value, (bytes, bytearray)):
                return bytes(value).decode(self._encoding)
            return value if isinstance(value, str) else str(value)
        return json.dumps(record, default=_json_default)

    async def _mark(self, record: dict[str, Any]) -> None:
        if self._mark_sql is None:
            return
        try:
            params = tuple(record[n] for n in self._mark_names)
        except KeyError as exc:
            # mark_statement references a column the poll_statement didn't select — a static config
            # error. Log loudly and leave the row unmarked (it re-emits) rather than crash the poller.
            logger.error(
                "DATABASE source mark_statement references unknown column %s; row left unmarked",
                exc,
            )
            return
        pool = await self._get_pool()
        conn = await _acquire(pool, self._acquire_timeout)
        try:
            cur = await conn.cursor()
            await cur.execute(self._mark_sql, params)
        finally:
            await pool.release(conn)

    async def test_connection(self) -> None:
        await _probe_db(self._get_pool, timeout=self._acquire_timeout)

    async def aclose(self) -> None:
        if self._pool is not None:
            self._pool.close()
            await self._pool.wait_closed()
            self._pool = None


register_destination(ConnectorType.DATABASE, DatabaseDestination)
register_source(ConnectorType.DATABASE, DatabaseSource)


def _bind_lookup_params(
    params: Mapping[str, Any], names: list[str], connection: str
) -> tuple[Any, ...]:
    """Bind a params mapping to the statement's ordered ``:name`` placeholders (positional). A missing
    name is a permanent author error → :class:`DbLookupError` (PHI-free: names the key, never its value)."""
    try:
        return tuple(params[n] for n in names)
    except KeyError as exc:
        raise DbLookupError(f"db_lookup on {connection!r}: missing parameter {exc}") from exc


class DatabaseLookupExecutor:
    """Pooled executor for handler-callable **live** lookups (``db_lookup``, ADR 0010).

    Built by the :class:`~messagefoundry.pipeline.wiring_runner.RegistryRunner` from the graph's
    ``DatabaseLookup`` specs (``env()``-resolved + ``[egress].allowed_db``-checked by the runner). Lazily
    opens one read-only ``aioodbc`` pool per named connection; :meth:`query` runs on the engine loop,
    while ``db_lookup`` bridges to it from the handler's worker thread via ``run_coroutine_threadsafe``.
    Reuses the DATABASE connector's DSN build / named-parameter translation / SQLSTATE extraction. Pools
    are autocommit — a lookup is read-only, so each query is its own implicit transaction; nothing here
    writes. Production / supported (SQL Server via the ``[sqlserver]`` extra), like the DATABASE connector."""

    def __init__(self, connections: Mapping[str, Mapping[str, Any]]) -> None:
        # connections: name -> already-env-resolved settings (the runner substitutes env() first).
        self._dsn: dict[str, str] = {}
        self._pool_max: dict[str, int] = {}
        self._acquire_timeout: dict[str, float] = {}
        for cname, s in connections.items():
            for req in ("server", "database"):
                if not s.get(req):
                    raise ValueError(f"DatabaseLookup {cname!r} requires a {req!r} setting")
            self._dsn[cname] = _build_dsn(dict(s))  # fail fast on weakened-TLS / bad-auth config
            self._pool_max[cname] = int(s.get("pool_max", 5))
            self._acquire_timeout[cname] = float(
                s.get("acquire_timeout", _DEFAULT_DB_ACQUIRE_TIMEOUT)
            )
        self._pools: dict[str, Any] = {}
        self._locks: dict[str, asyncio.Lock] = {c: asyncio.Lock() for c in self._dsn}

    @property
    def connections(self) -> frozenset[str]:
        """The declared lookup connection names."""
        return frozenset(self._dsn)

    async def _get_pool(self, connection: str) -> Any:
        pool = self._pools.get(connection)
        if pool is not None:
            return pool
        async with self._locks[connection]:
            if connection not in self._pools:
                self._pools[connection] = await _make_pool(
                    self._dsn[connection], self._pool_max[connection], autocommit=True
                )
        return self._pools[connection]

    async def query(
        self, connection: str, statement: str, params: Mapping[str, Any] | None
    ) -> list[dict[str, Any]]:
        """Run ``statement`` against ``connection`` and return rows as ``{column: value}`` dicts.

        Always parameterized (``:name`` → positional ``?``, bound from ``params`` — a value can never
        inject SQL). Raises :class:`DbLookupError` (PHI-free) on an unknown connection, a missing
        parameter, or a DB/driver error — the transform worker turns it into that message's ``ERROR`` /
        dead-letter disposition. Runs on the engine loop (the handler thread bridges in via
        ``run_coroutine_threadsafe``), so a slow query never blocks the loop, only its own worker thread."""
        if connection not in self._dsn:
            known = ", ".join(sorted(self._dsn)) or "(none declared)"
            raise DbLookupError(
                f"db_lookup: no DatabaseLookup connection named {connection!r} (declared: {known})"
            )
        sql, names = _parse_named_params(statement)
        bound = _bind_lookup_params(params or {}, names, connection)
        pool = await self._get_pool(connection)
        try:
            conn = await _acquire(pool, self._acquire_timeout[connection])
        except DeliveryError as exc:
            # Map the transient pool-timeout onto the lookup's own PHI-free error type so the transform
            # worker dead-letters/errors this message consistently with other lookup failures.
            raise DbLookupError(f"db_lookup on {connection!r}: {exc}") from exc
        try:
            cur = await conn.cursor()
            await cur.execute(sql, bound)
            columns = [d[0] for d in cur.description] if cur.description else []
            rows = list(await cur.fetchall())
        except DbLookupError:
            raise
        except Exception as exc:
            state = _sqlstate(exc)
            # PHI-free: name the connection + SQLSTATE (if any) only — never the statement/params/rows.
            raise DbLookupError(
                f"db_lookup query on {connection!r} failed" + (f" [{state}]" if state else "")
            ) from exc
        finally:
            await pool.release(conn)
        return [dict(zip(columns, row)) for row in rows]

    async def aclose(self) -> None:
        """Close every opened pool (idempotent; safe if no pool was ever opened)."""
        for pool in self._pools.values():
            pool.close()
            await pool.wait_closed()
        self._pools.clear()
