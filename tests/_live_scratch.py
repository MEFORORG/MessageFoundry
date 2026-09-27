# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Per-invocation scratch principals and databases for the live server-DB legs.

The live legs in ``tests/test_store_privilege_preflight.py`` and
``tests/test_store_privilege_schema_split.py`` create logins, roles, users, schemas and whole
databases on a SHARED server: one CI service container, reused by every step of the job and by every
attempt of ``scripts/ci/retry-native-crash.sh``. They used fixed names (``mefor_privprobe_test``,
``mefor_split_runtime``, ``mefor_schema_split_test``) and an ``IF SUSER_ID(...) IS NULL CREATE LOGIN``
guard. A process that died before its teardown, or a teardown that failed quietly, left the principal
behind holding the OLD password. The next run skipped the CREATE and then failed to log in (18456,
"Password did not match") -- a red that names the fixture, not the code. Measured on PR 1444's
SQL Server 2022 leg: attempt 1 of the step aborted natively, and attempt 2 then failed exactly so.

So every name here is unique per call, every CREATE is unconditional (a collision fails loudly
instead of silently reusing someone else's principal), and teardown ends the principal's sessions
before it drops anything. Teardown is best-effort per statement, so one failure never skips the
rest, and it READS BACK the databases, users, logins, schemas and roles it dropped: one still
present is reported as a warning rather than swallowed.

**Every SQL Server cursor is closed before its connection.** An unclosed cursor whose connection was
closed first is freed later, by the garbage collector, from wherever the interpreter happens to be.
pyodbc then frees a statement handle whose connection handle is already gone. That is the shape of
both native symptoms on that leg: an abort inside ``libodbc`` ``free`` reached from a deallocation,
and a pyodbc ``"The cursor's connection was closed"`` surfacing inside the event loop's
``selector.poll`` with no test frame above it. The link is inferred from the stack, not reproduced.
"""

from __future__ import annotations

import asyncio
import contextlib
import re
import secrets
import sys
import warnings
from collections.abc import AsyncIterator, Awaitable, Sequence
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from typing import Any

from messagefoundry.config.settings import StoreSettings

#: The bound on one teardown statement. Short, because the leg's whole-test timeout is 60 s.
_TEARDOWN_STEP_S = 10.0


def scratch_name(prefix: str) -> str:
    """``prefix`` plus eight random hex digits: a lowercase identifier no other call, worker, retry
    attempt or earlier crashed run can share, and one that needs no quoting in SQL Server or
    PostgreSQL."""
    return f"{prefix}_{secrets.token_hex(4)}"


def throwaway_password() -> str:
    """Generated per call, never a literal: a hardcoded one would be a credential-shaped string in a
    public repository. ``token_urlsafe`` is ``[A-Za-z0-9_-]`` only, so it needs no quoting inside a SQL
    string literal, and the prefix keeps it complex enough for a password policy."""
    return "Px9_" + secrets.token_urlsafe(24)


def _leak_warning(kind: str, name: str, why: str) -> None:
    warnings.warn(f"live-leg teardown left {kind} {name!r} behind: {why}", stacklevel=3)


@dataclass
class SqlServerAdmin:
    """One AUTOCOMMIT admin connection (``CREATE DATABASE`` and ``KILL`` refuse a user transaction).

    It stays in the database its DSN names and never runs ``USE``: a session parked inside a scratch
    database is one more session the ``ROLLBACK IMMEDIATE`` teardown has to end."""

    conn: Any
    #: The admin principal's settings, which :func:`bounded` connects as for its blocking report.
    settings: StoreSettings

    async def run(self, sql: str) -> None:
        cur = await self.conn.cursor()
        try:
            await cur.execute(sql)
        finally:
            await cur.close()

    async def scalar(self, sql: str) -> Any:
        cur = await self.conn.cursor()
        try:
            await cur.execute(sql)
            row = await cur.fetchone()
        finally:
            await cur.close()
        return None if row is None else row[0]

    async def run_in(self, database: str, sql: str) -> None:
        """Run ``sql`` inside ``database`` without moving this session there. ``sql`` holds no single
        quote: the fixtures' names and passwords are hex and ``token_urlsafe``."""
        await self.run(f"EXEC [{database}].sys.sp_executesql N'{sql}'")

    async def kill_sessions(self, login: str) -> None:
        """End every session ``login`` holds, so ``DROP LOGIN`` does not refuse with 15434 ("currently
        logged in"). A pool the test closed can still hold a physical connection the driver has not
        released yet."""
        await self.run(
            "DECLARE @k nvarchar(max) = (SELECT STRING_AGG(CONCAT(N'KILL ', session_id), N'; ')"
            f" FROM sys.dm_exec_sessions WHERE login_name = N'{login}' AND session_id <> @@SPID);"
            " IF @k IS NOT NULL EXEC (@k);"
        )
        # KILL marks a session and returns; the server ends it asynchronously, so a DROP LOGIN sent at
        # once can still meet 15434. Wait, bounded, until the login holds no session.
        probe = (
            "SELECT COUNT(*) FROM sys.dm_exec_sessions"
            f" WHERE login_name = N'{login}' AND session_id <> @@SPID"
        )
        for _ in range(50):
            if not await self.scalar(probe):
                return
            await asyncio.sleep(0.1)

    async def teardown(
        self,
        *,
        databases: Sequence[str] = (),
        users: Sequence[str] = (),
        logins: Sequence[str] = (),
    ) -> None:
        """Drop what a live leg created: sessions first, then users in this connection's database,
        then scratch databases, then logins. Each statement runs even when an earlier one failed."""
        # Each step is BOUNDED as well as suppressed: a teardown that waits forever on a stalled
        # session turns one red into a whole-leg timeout that reports nothing.
        for login in logins:
            with contextlib.suppress(Exception):  # read back below; one failure skips nothing
                await asyncio.wait_for(self.kill_sessions(login), _TEARDOWN_STEP_S)
        drops = [f"IF USER_ID('{user}') IS NOT NULL DROP USER [{user}]" for user in users]
        drops += [
            f"IF DB_ID('{db}') IS NOT NULL BEGIN ALTER DATABASE [{db}] SET SINGLE_USER WITH "
            f"ROLLBACK IMMEDIATE; DROP DATABASE [{db}]; END"
            for db in databases
        ]
        drops += [f"IF SUSER_ID('{login}') IS NOT NULL DROP LOGIN [{login}]" for login in logins]
        for drop in drops:
            with contextlib.suppress(Exception):  # read back below; one failure skips nothing
                await asyncio.wait_for(self.run(drop), _TEARDOWN_STEP_S)
        for user in users:
            await self._report_leak("database user", user, f"SELECT USER_ID('{user}')")
        for db in databases:
            await self._report_leak("database", db, f"SELECT DB_ID('{db}')")
        for login in logins:
            await self._report_leak("login", login, f"SELECT SUSER_ID('{login}')")

    async def _report_leak(self, kind: str, name: str, probe: str) -> None:
        try:
            left = await asyncio.wait_for(self.scalar(probe), _TEARDOWN_STEP_S)
        except Exception as exc:  # noqa: BLE001 - the read-back itself failing is also worth saying
            _leak_warning(kind, name, f"could not read it back ({exc})")
            return
        if left is not None:
            _leak_warning(kind, name, "it still exists after the drop")


#: What a stalled live step is waiting on, read on a connection of its own: every user session with
#: its request and the session blocking it, every task waiting on another, and every lock someone is
#: waiting for or a session with an open transaction holds. Server-wide, because the stalls this was
#: written for crossed databases.
_BLOCKING_QUERIES: tuple[tuple[str, str], ...] = (
    (
        "sessions",
        "SELECT s.session_id, s.login_name, s.status, s.open_transaction_count AS open_tx,"
        " DB_NAME(s.database_id) AS db, r.command, r.status AS req_status, r.wait_type,"
        " r.wait_time, r.wait_resource, r.blocking_session_id AS blocked_by,"
        " LEFT(COALESCE(rt.text, ct.text), 300) AS sql_text"
        " FROM sys.dm_exec_sessions s"
        " LEFT JOIN sys.dm_exec_requests r ON r.session_id = s.session_id"
        " LEFT JOIN sys.dm_exec_connections c ON c.session_id = s.session_id"
        " OUTER APPLY sys.dm_exec_sql_text(r.sql_handle) rt"
        " OUTER APPLY sys.dm_exec_sql_text(c.most_recent_sql_handle) ct"
        " WHERE s.session_id <> @@SPID AND (s.is_user_process = 1 OR r.blocking_session_id > 0)"
        " ORDER BY s.session_id",
    ),
    (
        "waiting tasks",
        "SELECT TOP (50) session_id, wait_type, wait_duration_ms, blocking_session_id,"
        " LEFT(resource_description, 300) AS resource FROM sys.dm_os_waiting_tasks"
        " WHERE blocking_session_id IS NOT NULL ORDER BY wait_duration_ms DESC",
    ),
    (
        "locks waited for, or held inside an open transaction",
        "SELECT TOP (80) l.request_session_id AS sid, l.resource_type,"
        " DB_NAME(l.resource_database_id) AS db, l.request_mode, l.request_status,"
        " l.resource_associated_entity_id AS entity, LEFT(l.resource_description, 120) AS res"
        " FROM sys.dm_tran_locks l"
        " JOIN sys.dm_exec_sessions s ON s.session_id = l.request_session_id"
        " WHERE l.request_session_id <> @@SPID"
        " AND (l.request_status <> 'GRANT' OR s.open_transaction_count > 0)"
        " ORDER BY l.request_session_id",
    ),
)

_PASSWORD_LITERAL = re.compile(r"(PASSWORD\s*=\s*)'[^']*'", re.IGNORECASE)


def _blocking_report_sync(settings: StoreSettings) -> str:
    import pyodbc

    from messagefoundry.store.sqlserver import connection_string

    conn = pyodbc.connect(connection_string(settings), autocommit=True, timeout=10)
    try:
        conn.timeout = 10  # the per-statement bound: a report must not stall on what it reports
        lines: list[str] = []
        for title, sql in _BLOCKING_QUERIES:
            cur = conn.cursor()
            try:
                rows = cur.execute(sql).fetchall()
                columns = [column[0] for column in cur.description]
            finally:
                cur.close()
            lines.append(f"-- {title}: {len(rows)} row(s)")
            for row in rows:
                cells = ", ".join(f"{c}={v!r}" for c, v in zip(columns, row, strict=True))
                lines.append("   " + _PASSWORD_LITERAL.sub(r"\1'<redacted>'", cells))
        return "\n".join(lines)
    finally:
        conn.close()


async def sqlserver_blocking_report(settings: StoreSettings) -> str:
    """:data:`_BLOCKING_QUERIES`, read on a thread of its own. Never the loop's default executor: a
    stalled step may be holding the only thread it has spare. Never raises; a failed read says so."""
    executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="live-diag")
    try:
        future = asyncio.get_running_loop().run_in_executor(
            executor, _blocking_report_sync, settings
        )
        return await asyncio.wait_for(future, 30)
    except Exception as exc:  # noqa: BLE001 - the report is best-effort by design
        return f"(blocking report unavailable: {exc!r})"
    finally:
        executor.shutdown(wait=False)


def _emit(text: str) -> None:
    """Straight to the process's real stderr. pytest holds captured output until the run's summary,
    and a leg that pytest-timeout ends never prints one."""
    stream = sys.__stderr__
    if stream is not None:
        stream.write(text)
        stream.flush()


async def bounded[T](
    settings: StoreSettings, step: str, awaitable: Awaitable[T], *, seconds: float = 20.0
) -> T:
    """Await one live step with a bound. On a timeout or an error, write the server's blocking report
    to stderr at once, then re-raise, so a stall names what it waited on instead of running into the
    whole-test timeout with nothing said. ``settings`` names the principal the report connects as."""
    try:
        return await asyncio.wait_for(awaitable, seconds)
    except Exception as exc:
        what = f"did not finish within {seconds:g}s" if isinstance(exc, TimeoutError) else repr(exc)
        report = await sqlserver_blocking_report(settings)
        _emit(f"\n[live-leg] {step}: {what}\n{report}\n")
        raise


@contextlib.asynccontextmanager
async def sqlserver_admin(settings: StoreSettings) -> AsyncIterator[SqlServerAdmin]:
    """An autocommit admin connection as the configured store principal, closed on the way out."""
    import aioodbc

    from messagefoundry.store.sqlserver import connection_string

    conn = await aioodbc.connect(
        dsn=connection_string(settings), autocommit=True, timeout=settings.connect_timeout
    )
    try:
        yield SqlServerAdmin(conn, settings)
    finally:
        await conn.close()


async def postgres_teardown(
    admin: Any, *, database: str | None, schemas: Sequence[str] = (), roles: Sequence[str] = ()
) -> None:
    """The PostgreSQL twin of :meth:`SqlServerAdmin.teardown`, over a :class:`PostgresStore` admin.

    Backends first, so no session of a scratch role outlives it, then schemas (``CASCADE`` takes the
    objects a role owns), then the role's database grant, then the roles. Read back afterwards."""
    steps = [
        "SELECT pg_terminate_backend(pid) FROM pg_stat_activity"
        f" WHERE usename = '{role}' AND pid <> pg_backend_pid()"
        for role in roles
    ]
    steps += [f"DROP SCHEMA IF EXISTS {schema} CASCADE" for schema in schemas]
    if database:  # no database named: the roles were granted none, so there is nothing to revoke
        steps += [f"REVOKE ALL ON DATABASE {database} FROM {role}" for role in roles]
    steps += [f"DROP ROLE IF EXISTS {role}" for role in roles]
    for step in steps:
        with contextlib.suppress(Exception):  # read back below; one failure skips nothing
            await admin._execute(step)
    probes = [
        ("schema", name, "SELECT 1 AS n FROM pg_namespace WHERE nspname = $1") for name in schemas
    ]
    probes += [("role", name, "SELECT 1 AS n FROM pg_roles WHERE rolname = $1") for name in roles]
    for kind, name, probe in probes:
        try:
            row = await admin._fetchone(probe, name)
        except Exception as exc:  # noqa: BLE001 - the read-back itself failing is also worth saying
            _leak_warning(kind, name, f"could not read it back ({exc})")
            continue
        if row is not None:
            _leak_warning(kind, name, "it still exists after the drop")
