# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #1626: ``[store].connect_timeout`` must reach ODBC Driver 18 as the LOGIN timeout.

The store used to put ``Connection Timeout=<n>`` in the DSN. That is an ADO.NET keyword, and ODBC
Driver 18 ignores it: measured against a black-hole address, a DSN with ``Connection Timeout=2`` still
waited 15.1 s, exactly as long as with no timeout set at all, while ``pyodbc.connect(..., timeout=2)``
gave up in 2.1 s. pyodbc maps its ``timeout=`` argument to ``SQL_ATTR_LOGIN_TIMEOUT``, and aioodbc forwards
it to ``pyodbc.connect``. So the fix is to pass ``timeout=`` at every connect site.

**Why the fakes.** ``aioodbc``/``pyodbc`` are the optional ``sqlserver`` extra, not installed on every
CI leg, and a login timeout against a real server would need a black-hole network. Recording modules
stand in for both through ``sys.modules``, which the store's lazy imports resolve. What is pinned is
the argument each connect site hands the driver, which is the whole of the defect.

The four connect sites: the aioodbc pool (``open``), the RCSI probe (``_ensure_database_options``),
the dedicated claim connection (``_connect_claim_conn``) and the synchronous fused-handoff pool
(``open_sync_handoff_pool``). Each test fails on the pre-fix code, where no site passed ``timeout=``.
"""

from __future__ import annotations

import sys
import types
from typing import Any

import pytest

from messagefoundry.config.settings import StoreBackend, StoreSettings
from messagefoundry.store.sqlserver import SqlServerStore, connection_string

# Deliberately not the 15 s default, so a hardcoded literal cannot pass.
_LOGIN_TIMEOUT = 7


def _settings() -> StoreSettings:
    return StoreSettings(
        backend=StoreBackend.SQLSERVER,
        server="localhost",
        database="mefor_test",
        username="sa",
        connect_timeout=_LOGIN_TIMEOUT,
    )


class _StopOpen(Exception):
    """Raised by the fake pool factory once it has recorded its arguments, ending open() early."""


class _RcsiOnCursor:
    """Answers the RCSI probe's state read with RCSI and snapshot isolation both ON."""

    async def execute(self, sql: str, *params: Any) -> None:
        return None

    async def fetchone(self) -> tuple[int, int]:
        return (1, 1)


class _FakeAsyncConn:
    async def cursor(self) -> _RcsiOnCursor:
        return _RcsiOnCursor()

    async def close(self) -> None:
        return None


def _install_recording_aioodbc(monkeypatch: pytest.MonkeyPatch) -> dict[str, list[dict[str, Any]]]:
    calls: dict[str, list[dict[str, Any]]] = {"connect": [], "create_pool": []}

    async def _connect(**kwargs: Any) -> _FakeAsyncConn:
        calls["connect"].append(kwargs)
        return _FakeAsyncConn()

    async def _create_pool(**kwargs: Any) -> Any:
        calls["create_pool"].append(kwargs)
        raise _StopOpen

    module = types.ModuleType("aioodbc")
    module.connect = _connect  # type: ignore[attr-defined]
    module.create_pool = _create_pool  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "aioodbc", module)
    return calls


def test_dsn_carries_no_login_timeout_keyword() -> None:
    """The keyword the driver ignores must not be emitted: its presence reads as a control that is
    not there. Red on the pre-fix code, which emitted ``Connection Timeout=7``."""
    dsn = connection_string(_settings())
    assert "Connection Timeout" not in dsn
    assert "Timeout" not in dsn


async def test_open_passes_the_login_timeout_to_the_pool_and_the_rcsi_probe(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = _install_recording_aioodbc(monkeypatch)
    with pytest.raises(_StopOpen):
        await SqlServerStore.open(_settings())
    assert len(calls["create_pool"]) == 1
    assert calls["create_pool"][0].get("timeout") == _LOGIN_TIMEOUT
    assert len(calls["connect"]) == 1  # the RCSI probe's own autocommit connection
    assert calls["connect"][0].get("timeout") == _LOGIN_TIMEOUT
    assert calls["connect"][0].get("autocommit") is True


async def test_dedicated_claim_connection_passes_the_login_timeout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = _install_recording_aioodbc(monkeypatch)
    store = object.__new__(SqlServerStore)  # the offline-test idiom: no pool, no I/O
    store._settings = _settings()
    store._posture = None
    await store._connect_claim_conn()
    assert len(calls["connect"]) == 1
    assert calls["connect"][0].get("timeout") == _LOGIN_TIMEOUT
    assert calls["connect"][0].get("autocommit") is False


class _FakeSyncConn:
    def __init__(self) -> None:
        self.timeout = 0

    def close(self) -> None:
        return None


def test_sync_handoff_pool_passes_the_login_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    connects: list[dict[str, Any]] = []

    def _connect(dsn: str, **kwargs: Any) -> _FakeSyncConn:
        connects.append(kwargs)
        return _FakeSyncConn()

    module = types.ModuleType("pyodbc")
    module.connect = _connect  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "pyodbc", module)

    store = object.__new__(SqlServerStore)
    store._settings = _settings()
    store._posture = None
    store._sync_pools = {}
    pool = store.open_sync_handoff_pool("routed", 2)
    try:
        assert len(connects) == 2
        assert all(kw.get("timeout") == _LOGIN_TIMEOUT for kw in connects), connects
        assert all(kw.get("autocommit") is False for kw in connects)
        # The per-statement bound is still applied separately, and to the command timeout.
        with pool.acquire(timeout=1) as conn:
            assert conn.timeout == store._settings.command_timeout
    finally:
        store.close_sync_handoff_pool()
