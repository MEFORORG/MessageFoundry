# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""What the database driver and sink share: the harness-owned tables, their SQL, and the connection.

The engine's DATABASE connector is ODBC-only (``messagefoundry/transports/database.py``): the
``sqlserver`` preset over the Microsoft ODBC Driver 18, or a ``generic`` operator-named ODBC driver,
both through ``aioodbc``/``pyodbc`` from the ``[sqlserver]`` extra. There is no SQLite path, so this
family targets the SQL Server preset only, and nothing here runs without a SQL Server, the extra and
the ODBC driver. :func:`unavailable` says which of those is missing, so a scenario can report
SKIPPED instead of passing or failing on a precondition.

Every statement is parameterized and every table name is a constant below, never built from message
data. ``pyodbc`` is imported inside the functions that use it, so harness discovery never needs the
extra. The graph in ``harness/config/database/`` carries the same statements as literals (a graph
imports nothing from ``harness``); ``tests/test_harness_database.py`` holds the two copies equal.

Credentials come only from the environment, under the names the engine's ``env()`` reads, so one
set of variables moves the served graph and the harness together. They are never endpoints: an
endpoint has a default, and a credential must not.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from harness.endpoints import ENV_PREFIX, Endpoints
from harness.endpoints.database import ENVIRONMENT_ONLY

#: The ODBC driver the engine's SQL Server preset names, and so the one the harness dials with.
ODBC_DRIVER = "ODBC Driver 18 for SQL Server"

#: The polled table (the DatabasePoll inbound reads it) and the written table (the Database
#: outbound writes it). Harness-owned constants; never derived from a message.
INBOX = "dbo.mf_harness_inbox"
OUTBOX = "dbo.mf_harness_outbox"

#: The connection names the graph declares, so a scenario can ask the engine whether it serves them.
INBOUND_NAME = "DB-IN_Harness"
OUTBOUND_NAME = "DB-OUT_Harness"

#: Values the environment must supply (``ENVIRONMENT_ONLY`` in ``harness/endpoints/database.py``):
#: the engine reads them as ``env("harness_database_<x>")`` and the harness reads the same variables.
REQUIRED_ENV: tuple[str, ...] = tuple(ENV_PREFIX + key.upper() for key in ENVIRONMENT_ONLY)
ENV_NAME = ENV_PREFIX + "DATABASE_NAME"
ENV_USERNAME = ENV_PREFIX + "DATABASE_USERNAME"
ENV_PASSWORD = ENV_PREFIX + "DATABASE_PASSWORD"  # noqa: S105  (a variable name, not a value)

# --- the SQL the served graph runs (copied there as literals; a test holds them equal) -----------

#: DatabasePoll needs a marker to take a handled row out of its own predicate, or every poll
#: re-emits it: ``status`` is that marker, 'NEW' until the engine has durably received the row (its
#: ingress commit). The mark says nothing about the row's later disposition.
POLL_STATEMENT = f"SELECT id, payload FROM {INBOX} WHERE status = 'NEW' ORDER BY id"
MARK_STATEMENT = f"UPDATE {INBOX} SET status = 'DONE' WHERE id = :id"
#: Delivery is at-least-once and a retry re-executes the write, so it is idempotent on control_id.
#: UPDLOCK + HOLDLOCK hold the range from the existence check to the insert, so two overlapping
#: executions of one delivery serialize instead of both passing NOT EXISTS.
WRITE_STATEMENT = (
    f"INSERT INTO {OUTBOX} (control_id, message_type, payload) "
    f"SELECT :control_id, :message_type, :payload "
    f"WHERE NOT EXISTS (SELECT 1 FROM {OUTBOX} WITH (UPDLOCK, HOLDLOCK) "
    f"WHERE control_id = :control_id)"
)

# --- the SQL the harness runs itself (pyodbc, ``?`` placeholders) ------------------------------

#: Two harness runs against a fresh database may both find a table absent; the loser's CREATE then
#: fails with error 2714 (the object exists), which is the outcome it wanted, so it is swallowed.
CREATE_TABLES = (
    f"IF OBJECT_ID(N'{INBOX}', N'U') IS NULL BEGIN TRY "
    f"CREATE TABLE {INBOX} ("
    "id INT IDENTITY(1,1) PRIMARY KEY, "
    "payload NVARCHAR(MAX) NOT NULL, "
    "status NVARCHAR(16) NOT NULL DEFAULT 'NEW') "
    "END TRY BEGIN CATCH IF ERROR_NUMBER() <> 2714 THROW; END CATCH; "
    f"IF OBJECT_ID(N'{OUTBOX}', N'U') IS NULL BEGIN TRY "
    f"CREATE TABLE {OUTBOX} ("
    "id INT IDENTITY(1,1) PRIMARY KEY, "
    "control_id NVARCHAR(64) NOT NULL, "
    "message_type NVARCHAR(32) NOT NULL, "
    "payload NVARCHAR(MAX) NOT NULL) "
    "END TRY BEGIN CATCH IF ERROR_NUMBER() <> 2714 THROW; END CATCH;"
)
INSERT_INBOX = f"INSERT INTO {INBOX} (payload) VALUES (?)"
OUTBOX_HIGH_WATER = f"SELECT COALESCE(MAX(id), 0) FROM {OUTBOX}"
SELECT_OUTBOX_AFTER = (
    f"SELECT id, control_id, message_type, payload FROM {OUTBOX} WHERE id > ? ORDER BY id"
)

#: Seconds a login may take before the harness gives up on the server.
LOGIN_TIMEOUT = 10
#: Seconds one statement may run: a held lock or a half-open session fails the call, rather than
#: blocking a scenario past its own timeout.
QUERY_TIMEOUT = 15

_ODBC_METACHARACTERS = frozenset(";{}=\r\n")


@dataclass(frozen=True)
class Target:
    """Where and as whom the harness connects. ``password`` is kept out of ``repr``."""

    server: str
    port: int
    database: str
    username: str
    password: str = field(repr=False)


def target(endpoints: Endpoints, environ: Mapping[str, str] | None = None) -> Target:
    """Resolve the connection: server and port from the endpoints, the rest from the environment.

    Raises :class:`KeyError` naming the first missing variable (never a value)."""
    env = os.environ if environ is None else environ
    missing = [name for name in REQUIRED_ENV if not env.get(name)]
    if missing:
        raise KeyError(missing[0])
    return Target(
        server=endpoints.value("database_server"),
        port=endpoints.port("database_port"),
        database=env[ENV_NAME],
        username=env[ENV_USERNAME],
        password=env[ENV_PASSWORD],
    )


def _brace(value: str) -> str:
    """ODBC-quote a value, doubling any ``}``, so a value cannot add a connection keyword."""
    return "{" + value.replace("}", "}}") + "}"


def build_dsn(t: Target) -> str:
    """The ODBC connection string for ``t``. TLS is always on and always verified: the harness
    never weakens a hop the engine itself would refuse to weaken."""
    if any(ch in _ODBC_METACHARACTERS for ch in t.server):
        raise ValueError("database_server must not contain ';', '{', '}', '=' or a newline")
    return (
        ";".join(
            [
                f"DRIVER={_brace(ODBC_DRIVER)}",
                f"SERVER={t.server},{t.port}",
                f"DATABASE={_brace(t.database)}",
                "APP={messagefoundry-harness}",
                f"UID={_brace(t.username)}",
                f"PWD={_brace(t.password)}",
                "Encrypt=yes",
                "TrustServerCertificate=no",
            ]
        )
        + ";"
    )


def unavailable(endpoints: Endpoints, environ: Mapping[str, str] | None = None) -> str:
    """Why this family cannot run here, or ``""`` when it can. Checks, in order: the ``pyodbc``
    module (the ``[sqlserver]`` extra), the ODBC driver, and the environment values. Reachability
    of the server itself is not checked here; an unreachable server is a failure, not a skip."""
    try:
        import pyodbc
    except ImportError:
        return "pyodbc is not installed (install the messagefoundry[sqlserver] extra)"
    try:
        drivers = list(pyodbc.drivers())
    except pyodbc.Error as exc:
        return f"the ODBC driver manager cannot list drivers ({type(exc).__name__})"
    if ODBC_DRIVER not in drivers:
        return f"the {ODBC_DRIVER!r} ODBC driver is not installed"
    env = os.environ if environ is None else environ
    missing = [name for name in REQUIRED_ENV if not env.get(name)]
    if missing:
        return f"{missing[0]} is not set (a server database and its credentials are required)"
    return ""


def connect(endpoints: Endpoints) -> Any:
    """An autocommit ``pyodbc`` connection to the target, with both harness tables present.

    Raises :class:`ConnectionError` for every way the database cannot be used -- the extra or a
    variable missing, a malformed ``database_server``, a refused login, a failed CREATE -- carrying
    the driver's message, never the DSN. A scenario reports it as a failure, never a skip."""
    try:
        import pyodbc
    except ImportError:
        raise ConnectionError("pyodbc is not installed") from None
    try:
        dsn = build_dsn(target(endpoints))
    except KeyError as exc:
        raise ConnectionError(f"{exc.args[0]} is not set") from None
    except ValueError as exc:
        raise ConnectionError(str(exc)) from None
    try:
        conn = pyodbc.connect(dsn, autocommit=True, timeout=LOGIN_TIMEOUT)
    except pyodbc.Error as exc:
        raise ConnectionError(f"cannot connect to the harness database: {exc}") from None
    conn.timeout = QUERY_TIMEOUT
    try:
        conn.cursor().execute(CREATE_TABLES)
    except pyodbc.Error as exc:
        conn.close()
        raise ConnectionError(f"cannot create the harness tables: {exc}") from None
    return conn


def driver_error() -> type[Exception]:
    """``pyodbc.Error``, imported lazily; a class nothing raises when the extra is absent."""
    try:
        import pyodbc
    except ImportError:
        return _NeverRaised
    error: type[Exception] = pyodbc.Error
    return error


class _NeverRaised(Exception):
    """Stands in for ``pyodbc.Error`` where ``pyodbc`` is absent, so an ``except`` still compiles."""
