"""DATABASE transport: a SQL destination that runs one parameterized statement per payload.

The **destination** executes the operator-declared ``statement`` (an INSERT/UPDATE or a stored-procedure
call) against an outbound database, binding the payload's fields to the statement's ``:name``
parameters. The first backend is **SQL Server over ``aioodbc``** (ADR 0003) — the ``[sqlserver]`` extra
(``pip install 'messagefoundry[sqlserver]'``) plus the Microsoft ODBC Driver 18, **lazily imported** so
SQLite-only installs never touch it. **Status: experimental**, like the SQL Server *store* backend —
the real round-trip is exercised only by the CI service-container job.

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
from datetime import date, datetime
from decimal import Decimal
from typing import Any

from messagefoundry.config.models import ConnectorType, Destination, Source
from messagefoundry.config.settings import INSECURE_TLS_ESCAPE_ENV, insecure_tls_allowed
from messagefoundry.transports.base import (
    DeliveryError,
    DestinationConnector,
    InboundHandler,
    NegativeAckError,
    SourceConnector,
    register_destination,
    register_source,
)

__all__ = ["DatabaseDestination", "DatabaseSource"]

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
    parts = [
        f"DRIVER={_odbc_brace(str(s.get('odbc_driver', 'ODBC Driver 18 for SQL Server')))}",
        f"SERVER={_odbc_brace(str(s['server']))},{int(s.get('port', 1433))}",
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
        self._pool: Any = None
        self._pool_lock = asyncio.Lock()

    async def _get_pool(self) -> Any:
        if self._pool is not None:
            return self._pool
        async with self._pool_lock:
            if self._pool is None:
                self._pool = await _make_pool(self._dsn, self._pool_max, autocommit=False)
        return self._pool

    async def send(self, payload: str) -> None:
        params = _bind_params(payload, self._param_names)  # NegativeAckError(permanent) on bad data
        pool = await self._get_pool()
        conn = await pool.acquire()
        try:
            cur = await conn.cursor()
            try:
                await cur.execute(self._sql, params)
                await conn.commit()
            except Exception as exc:
                await conn.rollback()
                state = _sqlstate(exc)
                if state is None:
                    raise  # not a DB driver error → an internal/code error, let the runner handle it
                raise _classify_db_error(state, str(exc)) from exc
        finally:
            await pool.release(conn)

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
    """

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
        self._pool: Any = None
        self._pool_lock = asyncio.Lock()
        self._handler: InboundHandler | None = None
        self._stop = asyncio.Event()
        self._task: asyncio.Task[None] | None = None

    async def start(self, handler: InboundHandler) -> None:
        self._handler = handler
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
        conn = await pool.acquire()
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
        conn = await pool.acquire()
        try:
            cur = await conn.cursor()
            await cur.execute(self._mark_sql, params)
        finally:
            await pool.release(conn)

    async def aclose(self) -> None:
        if self._pool is not None:
            self._pool.close()
            await self._pool.wait_closed()
            self._pool = None


register_destination(ConnectorType.DATABASE, DatabaseDestination)
register_source(ConnectorType.DATABASE, DatabaseSource)
