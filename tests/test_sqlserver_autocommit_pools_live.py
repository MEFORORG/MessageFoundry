# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Does an autocommit DATABASE pool hold autocommit on the SERVER session? Measured on a real SQL
Server, with ODBC driver-manager pooling off and on (BACKLOG #2148, step 1).

The row's suspicion: with driver-manager pooling on, a physical connection that a manual-commit
connection left in that mode comes back from the driver manager's pool still in it, while aioodbc
was asked for ``autocommit=True``. pyodbc sends ``SQL_ATTR_AUTOCOMMIT`` only to turn autocommit OFF,
so it would not correct it, and a poll source's mark would then run in an open transaction that
rolls back. ``tests/test_database_autocommit_confirmed.py`` pins the engine's answer with a fake
driver, and reads pyodbc's record of the mode, not the server's. This file asks the server.

For each of the three engine pools that ask for autocommit (the poll source's mark pool, the
``db_lookup`` pool and the ``DatabaseRef`` sync pool), and for an unwrapped aioodbc pool as the
mechanism's control, a child process:

1. opens a MANUAL-commit connection on the pool's own DSN and closes it, which is what would leave a
   physical connection in manual-commit mode in the driver manager's pool;
2. opens the pool, borrows a connection, writes one row to a scratch table, and reads the session's
   ``@@TRANCOUNT`` and ``@@OPTIONS & 2`` (``IMPLICIT_TRANSACTIONS``) on that same connection, and
   whether it reused step 1's session (same ``@@SPID`` and ``connect_time``);
3. closes the pool, then reads from a separate session whether the row was committed.

The child runs once with the shipped ``pyodbc.pooling = False`` and once with it on, each in its own
process, because pyodbc reads ``pooling`` once, when it allocates its environment handle.

**What is asserted, and what is only recorded.** The three engine pools must show no open
transaction, implicit transactions off and a committed row, in both modes: that is the guarantee
#2148 step 2 built (``_AutocommitPool``). The unwrapped pool is the mechanism itself. Its reading,
and whether the driver manager reused a session at all, are recorded as a warning in the test
output, not asserted. On Linux, unixODBC pools only where ``odbcinst.ini`` turns pooling on, so
``reused_session`` false in the pooling-on arm means the mechanism's precondition did not hold there.

The DatabaseRef pool is built as ``pipeline/reference_sync.py`` ``_load_database_source`` builds it
(a read-intent ``_build_dsn``, an autocommit ``_make_pool``, borrowed with ``acquire_pooled``),
without importing that module: the ``serverdb`` path gate in ``.github/workflows/ci.yml`` does not
admit it, and ``tests/test_serverdb_ci_coverage.py`` refuses a server-DB suite that imports a source
the gate does not admit.

**Gated**: skipped unless ``MEFOR_TEST_SQLSERVER`` is set (plus ``MEFOR_STORE_*``). The weakened TLS
the CI container needs is attested per hop in the child, since a child inherits no hop posture. The
scratch table is uuid-named and not dropped (ephemeral container), as the other live files do.
Synthetic data only.
"""

from __future__ import annotations

import json
import os
import secrets
import subprocess
import sys
import warnings
from pathlib import Path
from typing import Any

import pytest

pytestmark = pytest.mark.skipif(
    not os.getenv("MEFOR_TEST_SQLSERVER"),
    reason="set MEFOR_TEST_SQLSERVER=1 (+ MEFOR_STORE_* connection env) to measure the pools",
)

_REPO = Path(__file__).resolve().parent.parent
_RESULT_MARK = "MF2148-RESULT "
_ENGINE_POOLS = ("poll_mark", "db_lookup", "reference_sync")
_ATTESTED_REASON = "CI SQL Server container with a self-signed certificate"
#: Exit codes of a native crash (SIGSEGV, SIGABRT), which scripts/ci/retry-native-crash.sh retries.
_NATIVE_CRASH = frozenset({-11, -6, 139, 134})
_DB_TIMEOUT = 60.0


# --- the child process -----------------------------------------------------------------------------


def _conn(kind: str) -> dict[str, Any]:
    """Settings for the CI container. A distinct ``app_name`` per pool keeps each pool's DSN, and so
    its slot in the driver manager's pool, apart from the others'."""
    return {
        "server": os.environ.get("MEFOR_STORE_SERVER", "localhost"),
        "port": int(os.environ.get("MEFOR_STORE_PORT", "1433")),
        "database": os.environ.get("MEFOR_STORE_DATABASE", "MessageFoundry"),
        "username": os.environ.get("MEFOR_STORE_USERNAME", "sa"),
        "password": os.environ.get("MEFOR_STORE_PASSWORD", ""),
        "trust_server_certificate": True,
        "tls_hop_attested": True,
        "tls_hop_attested_reason": _ATTESTED_REASON,
        "app_name": f"mf2148-{kind}",
    }


_SESSION_SQL = (
    "SELECT @@TRANCOUNT, @@OPTIONS & 2, @@SPID,"
    " (SELECT CONVERT(varchar(30), connect_time, 126) FROM sys.dm_exec_connections"
    " WHERE session_id = @@SPID)"
)


async def _leave_a_manual_commit_connection(dsn: str, login_timeout: int) -> list[Any]:
    """Step 1: a manual-commit connection on ``dsn``, closed. Returns its session (spid, time)."""
    import aioodbc

    conn = await aioodbc.connect(dsn=dsn, autocommit=False, timeout=login_timeout)
    try:
        cur = await conn.cursor()
        try:
            await cur.execute(_SESSION_SQL)
            row = await cur.fetchone()
        finally:
            await cur.close()
        await conn.rollback()
    finally:
        await conn.close()
    return [row[2], row[3]]


async def _committed(table: str, key: str, login_timeout: int) -> str:
    """Step 3, from a session of its own (its own ``app_name``, so never a reused physical
    connection of the pool under test): ``yes`` committed, ``no`` absent, ``blocked`` held by an
    open transaction elsewhere."""
    import aioodbc

    from messagefoundry.transports.database import _build_dsn

    dsn = _build_dsn(_conn("verify"), attested=True)
    conn = await aioodbc.connect(dsn=dsn, autocommit=True, timeout=login_timeout)
    try:
        cur = await conn.cursor()
        try:
            await cur.execute("SET LOCK_TIMEOUT 5000")
            await cur.execute(f"SELECT COUNT(*) FROM [{table}] WHERE k = ?", (key,))
            row = await cur.fetchone()
        except Exception as exc:  # noqa: BLE001 - a lock timeout (1222) is a reading, not a failure
            return "blocked" if "1222" in str(exc) else f"error {type(exc).__name__}"
        finally:
            await cur.close()
    finally:
        await conn.close()
    return "yes" if row[0] == 1 else "no"


async def _measure(kind: str, table: str, mode: str) -> dict[str, Any]:
    """Steps 1 to 3 for one pool."""
    import asyncio

    import aioodbc

    from messagefoundry.config.models import ConnectorType, Source
    from messagefoundry.config.settings import EgressSettings
    from messagefoundry.store.base import acquire_pooled
    from messagefoundry.transports import database

    settings = _conn(kind)
    login_timeout = database._login_timeout(settings, "BACKLOG #2148 measurement")
    close: Any
    if kind == "poll_mark":
        source = database.DatabaseSource(
            Source(
                name="IB_MF2148",
                type=ConnectorType.DATABASE,
                tls_hop_attested=True,
                tls_hop_attested_reason=_ATTESTED_REASON,
                settings={k: v for k, v in settings.items() if not k.startswith("tls_hop_attested")}
                | {
                    "poll_statement": f"SELECT k, v FROM [{table}] WHERE v IS NULL",
                    "mark_statement": f"UPDATE [{table}] SET v = 1 WHERE k = :k",
                },
            )
        )
        dsn = source._dsn
        open_pool = source._get_pool
        close = source.aclose
    elif kind == "db_lookup":
        executor = database.DatabaseLookupExecutor(
            {"live": settings}, egress=EgressSettings(deny_by_default=False)
        )
        dsn = executor._dsn["live"]

        async def open_pool() -> Any:
            return await executor._get_pool("live")

        close = executor.aclose
    elif kind == "reference_sync":
        dsn = database._build_dsn(dict(settings), read_only=True, attested=True)
        holder: list[Any] = []

        async def open_pool() -> Any:
            holder.append(
                await database._make_pool(dsn, 5, autocommit=True, login_timeout=login_timeout)
            )
            return holder[0]

        async def close() -> None:
            await database._close_pool_bounded(holder[0], "DATABASE reference source")
    else:  # the mechanism's control: aioodbc's own autocommit=True pool, not wrapped
        dsn = database._build_dsn(dict(settings), attested=True)
        holder = []

        async def open_pool() -> Any:
            holder.append(
                await aioodbc.create_pool(
                    dsn=dsn, minsize=1, maxsize=1, autocommit=True, timeout=login_timeout
                )
            )
            return holder[0]

        async def close() -> None:
            holder[0].close()
            await holder[0].wait_closed()

    leaver = await asyncio.wait_for(
        _leave_a_manual_commit_connection(dsn, login_timeout), _DB_TIMEOUT
    )
    key = f"{kind}-{mode}"
    pool = await asyncio.wait_for(open_pool(), _DB_TIMEOUT)
    try:
        if kind == "reference_sync":
            conn = await acquire_pooled(pool, timeout=30.0, backend="reference:database")
        elif kind == "raw_aioodbc":
            conn = await asyncio.wait_for(pool.acquire(), 30.0)
        else:
            conn = await database._acquire(pool, 30.0)
        cur: Any = None
        try:
            cur = await conn.cursor()
            await asyncio.wait_for(
                cur.execute(f"INSERT INTO [{table}] (k) VALUES (?)", (key,)), _DB_TIMEOUT
            )
            await asyncio.wait_for(cur.execute(_SESSION_SQL), _DB_TIMEOUT)
            row = await cur.fetchone()
            driver_mode = bool(conn._conn.autocommit)
        finally:
            await database._close_and_release(pool, conn, cur)
    finally:
        await close()
    return {
        "trancount": int(row[0]),
        "implicit_transactions": bool(row[1]),
        "reused_session": [row[2], row[3]] == leaver,
        "pyodbc_autocommit": driver_mode,
        "committed": await asyncio.wait_for(_committed(table, key, login_timeout), _DB_TIMEOUT),
    }


async def _measure_all(mode: str) -> dict[str, Any]:
    import aioodbc

    from messagefoundry.transports import database

    settings = _conn("setup")
    table = f"mf2148_{secrets.token_hex(4)}"
    conn = await aioodbc.connect(
        dsn=database._build_dsn(settings, attested=True),
        autocommit=True,
        timeout=database._login_timeout(settings, "BACKLOG #2148 setup"),
    )
    try:
        cur = await conn.cursor()
        try:
            await cur.execute(
                f"CREATE TABLE [{table}] (k nvarchar(64) NOT NULL PRIMARY KEY, v int NULL)"
            )
        finally:
            await cur.close()
        await conn.commit()  # durable whichever mode this session is really in
    finally:
        await conn.close()
    out: dict[str, Any] = {}
    for kind in (*_ENGINE_POOLS, "raw_aioodbc"):
        out[kind] = await _measure(kind, table, mode)
    return out


def _child(mode: str) -> None:
    """Entry point of the child: set ``pyodbc.pooling`` before any ODBC use, then measure."""
    import asyncio

    import pyodbc

    pyodbc.pooling = mode == "on"
    from messagefoundry.transports import database

    if mode == "on":
        # The engine turns pooling off at every pool site (BACKLOG #2049); this arm measures it on.
        setattr(database, "disable_driver_manager_pooling", lambda: None)  # noqa: B010
    result = asyncio.run(_measure_all(mode))
    result["pyodbc_pooling"] = bool(pyodbc.pooling)
    print(_RESULT_MARK + json.dumps(result), flush=True)


# --- the test --------------------------------------------------------------------------------------


def _run_child(mode: str) -> dict[str, Any]:
    env = dict(os.environ)
    env["PYTHONPATH"] = os.pathsep.join(filter(None, [str(_REPO), env.get("PYTHONPATH")]))
    for _attempt in range(3):
        done = subprocess.run(  # noqa: S603 - our own interpreter and this file, no shell
            [sys.executable, "-P", str(Path(__file__).resolve()), "--child", mode],
            cwd=_REPO,
            env=env,
            capture_output=True,
            text=True,
            timeout=300,
            check=False,
        )
        if done.returncode not in _NATIVE_CRASH:
            break
    assert done.returncode == 0, f"the {mode} child failed ({done.returncode}):\n{done.stderr}"
    lines = [ln for ln in done.stdout.splitlines() if ln.startswith(_RESULT_MARK)]
    assert lines, f"the {mode} child printed no result:\n{done.stdout}\n{done.stderr}"
    result: dict[str, Any] = json.loads(lines[-1][len(_RESULT_MARK) :])
    return result


@pytest.mark.parametrize("mode", ["off", "on"])
def test_the_engine_autocommit_pools_hold_autocommit_on_the_server_session(mode: str) -> None:
    result = _run_child(mode)
    raw = result["raw_aioodbc"]
    reproduced = raw["trancount"] != 0 or raw["implicit_transactions"] or raw["committed"] != "yes"
    pooled = any(result[k]["reused_session"] for k in (*_ENGINE_POOLS, "raw_aioodbc"))
    warnings.warn(
        f"BACKLOG #2148 measurement, driver-manager pooling {mode}: the autocommit loss "
        f"{'REPRODUCED' if reproduced else 'did not reproduce'} on the unwrapped aioodbc pool; "
        f"the driver manager {'reused' if pooled else 'did not reuse'} a session. "
        f"Readings: {json.dumps(result, sort_keys=True)}",
        stacklevel=1,
    )
    for kind in _ENGINE_POOLS:
        reading = result[kind]
        assert reading["trancount"] == 0, (kind, reading)
        assert reading["implicit_transactions"] is False, (kind, reading)
        assert reading["committed"] == "yes", (kind, reading)
    assert result["pyodbc_pooling"] is (mode == "on"), result


if __name__ == "__main__" and sys.argv[1:2] == ["--child"]:
    _child(sys.argv[2])
