# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #1628: a SQL Server store refuses to open when READ_COMMITTED_SNAPSHOT is off and the
login cannot turn it on.

Under locking READ COMMITTED the finalizer deadlocks: a caller UPDATEs its own queue row, then
``_maybe_finalize`` takes the per-message applock and scans the message's rows, and the scan waits
for a shared lock on a sibling row that the sibling holds exclusively while it waits on the same
applock. Fable packet 4 (P4-05 / H-8) measured 29 of 30 concurrent fan-out finalizes fail that way.
``_ensure_database_options`` used to degrade to a warning in exactly that mode, which is the mode a
least-privilege login without ``ALTER DATABASE`` gets. It now fails the open.

These tests drive the real ``SqlServerStore.open()`` with a recording ``aioodbc`` stand-in, so they
run on every leg. The live counterpart, which opens a real least-privilege login against a real
RCSI-off database, is ``test_open_refuses_a_least_privilege_login_on_an_rcsi_off_database`` in
``tests/test_sqlserver_store.py`` and runs only on the gated SQL Server CI legs.
"""

from __future__ import annotations

import logging
import sys
import types
from typing import Any

import pytest

import messagefoundry.store.sqlserver as sqlserver_module
from messagefoundry.config.settings import StoreBackend, StoreSettings
from messagefoundry.store.sqlserver import SqlServerStore

_ALTER_RCSI = "ALTER DATABASE CURRENT SET READ_COMMITTED_SNAPSHOT ON WITH ROLLBACK IMMEDIATE"
_ALTER_SNAPSHOT = "ALTER DATABASE CURRENT SET ALLOW_SNAPSHOT_ISOLATION ON"


def _settings() -> StoreSettings:
    return StoreSettings(
        backend=StoreBackend.SQLSERVER, server="localhost", database="mefor_test", username="sa"
    )


class _PoolCreated(Exception):
    """Raised by the fake pool factory: reaching it means the RCSI check let the open continue."""


class _ProbeCursor:
    def __init__(self, row: tuple[int, int] | None, denied: set[str]) -> None:
        self._row = row
        self._denied = denied
        self.executed: list[str] = []

    async def execute(self, sql: str, *params: Any) -> None:
        self.executed.append(sql)
        if sql in self._denied:
            # The shape of SQL Server error 5011 for a principal without ALTER on the database.
            raise RuntimeError("User does not have permission to alter database 'mefor_test'.")

    async def fetchone(self) -> tuple[int, int] | None:
        return self._row


class _ProbeConn:
    def __init__(self, cursor: _ProbeCursor) -> None:
        self._cursor = cursor
        self.closed = False
        self.rereads: list[_ProbeConn] = []  # later connections, recorded on the first one

    async def cursor(self) -> _ProbeCursor:
        return self._cursor

    async def close(self) -> None:
        self.closed = True


@pytest.fixture(autouse=True)
def _no_reread_delay(monkeypatch: pytest.MonkeyPatch) -> None:
    """The re-read after a failed ALTER sleeps between attempts; the tests need no real clock."""
    monkeypatch.setattr(sqlserver_module, "_RCSI_REREAD_DELAY_S", 0.0)


def _install(
    monkeypatch: pytest.MonkeyPatch,
    *,
    row: tuple[int, int] | None,
    denied: frozenset[str] = frozenset(),
    connect_fails: bool = False,
    later_row: tuple[int, int] | None = None,
) -> tuple[_ProbeCursor, _ProbeConn, list[dict[str, Any]]]:
    """``later_row``, when given, is what every connection AFTER the first reads: the state a
    concurrent opener's ALTER left behind."""
    cursor = _ProbeCursor(row, set(denied))
    conn = _ProbeConn(cursor)
    pools: list[dict[str, Any]] = []
    connects = 0

    async def _connect(**kwargs: Any) -> _ProbeConn:
        nonlocal connects
        connects += 1
        if connect_fails:
            raise RuntimeError("login timeout expired")
        if connects > 1:
            # Every re-read gets its OWN connection, so ``conn.closed`` below proves the outer
            # finally closed the first one rather than a re-read closing a shared object.
            later = _ProbeConn(_ProbeCursor(later_row or row, set(denied)))
            conn.rereads.append(later)
            return later
        return conn

    async def _create_pool(**kwargs: Any) -> Any:
        pools.append(kwargs)
        raise _PoolCreated

    module = types.ModuleType("aioodbc")
    module.connect = _connect  # type: ignore[attr-defined]
    module.create_pool = _create_pool  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "aioodbc", module)
    return cursor, conn, pools


async def test_rcsi_off_and_alter_denied_refuses_the_open(monkeypatch: pytest.MonkeyPatch) -> None:
    """THE MUTATION THIS PINS: the pre-#1628 warning fallback. Red there: the open carried on to
    ``create_pool`` and the store would have run under locking READ COMMITTED."""
    cursor, conn, pools = _install(monkeypatch, row=(0, 0), denied=frozenset({_ALTER_RCSI}))
    with pytest.raises(RuntimeError, match="READ_COMMITTED_SNAPSHOT is OFF") as info:
        await SqlServerStore.open(_settings())
    # The operator gets the exact statement to hand a DBA, for the configured database.
    assert (
        "ALTER DATABASE [mefor_test] SET READ_COMMITTED_SNAPSHOT ON WITH ROLLBACK IMMEDIATE"
        in str(info.value)
    )
    assert pools == []  # refused BEFORE any pool (or its executor) exists
    assert _ALTER_RCSI in cursor.executed
    # It re-read the state on fresh connections (a peer might have won the ALTER) before refusing,
    # and closed every one of them as well as the first.
    assert len(conn.rereads) == sqlserver_module._RCSI_REREADS
    assert conn.closed and all(c.closed for c in conn.rereads)


async def test_a_concurrent_opener_that_enabled_rcsi_lets_the_open_proceed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Engine shards and cluster nodes open at once. On a greenfield database a peer's ALTER ...
    WITH ROLLBACK IMMEDIATE can make OURS fail while RCSI still ends up ON. That is not a denial, so
    the open must re-read and carry on rather than refuse a store that is correctly configured."""
    cursor, _conn, pools = _install(
        monkeypatch, row=(0, 1), denied=frozenset({_ALTER_RCSI}), later_row=(1, 1)
    )
    with pytest.raises(_PoolCreated):
        await SqlServerStore.open(_settings())
    assert len(pools) == 1
    assert _ALTER_RCSI in cursor.executed


async def test_unreadable_rcsi_state_refuses_the_open(monkeypatch: pytest.MonkeyPatch) -> None:
    """Red on the pre-fix code, which treated an unread state as ON and opened."""
    cursor, conn, pools = _install(monkeypatch, row=None)
    with pytest.raises(RuntimeError, match="unverified"):
        await SqlServerStore.open(_settings())
    assert pools == []
    assert _ALTER_RCSI not in cursor.executed  # never a disruptive ALTER on a state it cannot read
    assert conn.closed


async def test_probe_connect_failure_refuses_the_open(monkeypatch: pytest.MonkeyPatch) -> None:
    """Red on the pre-fix code, which logged "skipping the RCSI check" and let a pool open after a
    transient probe failure run with RCSI unverified."""
    _cursor, _conn, pools = _install(monkeypatch, row=(1, 1), connect_fails=True)
    with pytest.raises(RuntimeError, match="could not connect to verify READ_COMMITTED_SNAPSHOT"):
        await SqlServerStore.open(_settings())
    assert pools == []


async def test_rcsi_off_but_enable_succeeds_opens(monkeypatch: pytest.MonkeyPatch) -> None:
    """Positive control: a login that CAN alter the database still self-heals, so the refusal above
    is about the denied ALTER and not about RCSI having been off."""
    cursor, _conn, pools = _install(monkeypatch, row=(0, 1))
    with pytest.raises(_PoolCreated):
        await SqlServerStore.open(_settings())
    assert len(pools) == 1
    assert _ALTER_RCSI in cursor.executed


async def test_rcsi_already_on_opens_without_altering(monkeypatch: pytest.MonkeyPatch) -> None:
    """The DBA-pre-enabled path a least-privilege deployment takes: no ALTER is attempted at all."""
    cursor, _conn, pools = _install(
        monkeypatch, row=(1, 1), denied=frozenset({_ALTER_RCSI, _ALTER_SNAPSHOT})
    )
    with pytest.raises(_PoolCreated):
        await SqlServerStore.open(_settings())
    assert len(pools) == 1
    assert not any(sql.startswith("ALTER") for sql in cursor.executed)


async def test_snapshot_isolation_denied_still_only_warns(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """ALLOW_SNAPSHOT_ISOLATION stays a warning: no store path runs at SNAPSHOT isolation, so it is
    not a correctness premise the way RCSI is."""
    cursor, _conn, pools = _install(monkeypatch, row=(1, 0), denied=frozenset({_ALTER_SNAPSHOT}))
    with caplog.at_level(logging.WARNING), pytest.raises(_PoolCreated):
        await SqlServerStore.open(_settings())
    assert len(pools) == 1
    assert _ALTER_SNAPSHOT in cursor.executed
    assert "ALLOW_SNAPSHOT_ISOLATION" in caplog.text
