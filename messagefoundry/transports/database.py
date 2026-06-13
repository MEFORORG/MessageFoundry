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
import json
import logging
import re
from typing import Any

from messagefoundry.config.models import ConnectorType, Destination
from messagefoundry.config.settings import INSECURE_TLS_ESCAPE_ENV, insecure_tls_allowed
from messagefoundry.transports.base import (
    DeliveryError,
    DestinationConnector,
    NegativeAckError,
    register_destination,
)

__all__ = ["DatabaseDestination"]

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
                try:
                    import aioodbc
                except ImportError as exc:  # pragma: no cover - exercised only without the extra
                    raise RuntimeError(
                        "DATABASE destination requires the 'sqlserver' extra: "
                        "pip install 'messagefoundry[sqlserver]' (plus the Microsoft ODBC Driver 18)"
                    ) from exc
                self._pool = await aioodbc.create_pool(
                    dsn=self._dsn, minsize=1, maxsize=max(1, self._pool_max), autocommit=False
                )
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


register_destination(ConnectorType.DATABASE, DatabaseDestination)
