# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #2049 - the engine turns ODBC driver-manager pooling off before it connects.

With pooling on (pyodbc's default), closing a connection parks its server session in the driver
manager's pool instead of ending it. On the sqlserver-store CI legs a connection the store had
quarantined and closed still had a live session with an open transaction. ADR 0159 assumes a close
ends the session, so the engine sets ``pyodbc.pooling = False`` at every connect site.

``pooling`` takes effect only at pyodbc's first connect in the process, so ONE connect site that
forgets the call can leave pooling on for everything after it. The scan below therefore covers every
ODBC connect call in the engine, not just the store's. It proves only that the call is made; that a
closed session really ends on a live server is proven by the sqlserver-store legs.
"""

from __future__ import annotations

import ast
import sys
import types
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

import pytest

from messagefoundry.odbc_env import disable_driver_manager_pooling

_ROOT = Path(__file__).resolve().parents[1]
_ENGINE = _ROOT / "messagefoundry"
_GUARD = "disable_driver_manager_pooling"
# The calls that allocate pyodbc's environment handle, which is when `pooling` is read: a connect,
# directly or through an aioodbc pool, and the driver-manager enumerations.
_CONNECTS = {
    ("aioodbc", "connect"),
    ("aioodbc", "create_pool"),
    ("pyodbc", "connect"),
    ("pyodbc", "drivers"),
    ("pyodbc", "dataSources"),
}


def _connect_sites_missing_the_guard() -> tuple[int, list[str]]:
    """Every ODBC connect call in the engine, and those with no guard call before them in an
    enclosing function. A nested connect (a pool factory) counts its enclosing function's call."""
    found = 0
    missing: list[str] = []
    for path in sorted(_ENGINE.rglob("*.py")):
        text = path.read_text(encoding="utf-8")
        if "odbc" not in text:  # cheap skip: a file that never names either driver cannot match
            continue
        tree = ast.parse(text)
        funcs = [
            n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
        ]
        for call in (n for n in ast.walk(tree) if isinstance(n, ast.Call)):
            f = call.func
            if not (isinstance(f, ast.Attribute) and isinstance(f.value, ast.Name)):
                continue
            if (f.value.id, f.attr) not in _CONNECTS:
                continue
            found += 1
            enclosing = [
                fn for fn in funcs if fn.lineno <= call.lineno <= (fn.end_lineno or fn.lineno)
            ]
            guarded = any(
                isinstance(c, ast.Call)
                and isinstance(c.func, ast.Name)
                and c.func.id == _GUARD
                and c.lineno < call.lineno
                for fn in enclosing
                for c in ast.walk(fn)
            )
            if not guarded:
                missing.append(f"{path.relative_to(_ROOT).as_posix()}:{call.lineno}")
    return found, missing


def test_every_odbc_connect_site_turns_pooling_off_first() -> None:
    found, missing = _connect_sites_missing_the_guard()
    # Positive control: at least the store's five connect calls, the DATABASE connector's pool and
    # the verifier's driver probe. A scan that finds fewer has a broken matcher.
    assert found >= 7, f"the scan found only {found} ODBC call(s); its matcher is broken"
    assert not missing, (
        f"ODBC connect call(s) with no {_GUARD}() before them: {missing}. If this site runs first in"
        " the process, driver-manager pooling stays on and a closed connection's server session"
        " outlives the close (BACKLOG #2049)."
    )


@pytest.fixture
def fake_pyodbc(monkeypatch: pytest.MonkeyPatch) -> types.ModuleType:
    mod = types.ModuleType("pyodbc")
    mod.pooling = True  # type: ignore[attr-defined]  # pyodbc's own default
    monkeypatch.setitem(sys.modules, "pyodbc", mod)
    return mod


def test_the_guard_turns_pooling_off(fake_pyodbc: types.ModuleType) -> None:
    disable_driver_manager_pooling()
    assert fake_pyodbc.pooling is False
    disable_driver_manager_pooling()  # idempotent
    assert fake_pyodbc.pooling is False


def test_the_guard_is_a_no_op_without_pyodbc(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setitem(sys.modules, "pyodbc", None)  # makes `import pyodbc` raise ImportError
    disable_driver_manager_pooling()


def _fake_aioodbc(monkeypatch: pytest.MonkeyPatch, pyodbc: types.ModuleType) -> list[bool]:
    """An aioodbc whose create_pool records what pyodbc.pooling was when it was called."""
    seen: list[bool] = []
    mod = types.ModuleType("aioodbc")

    async def create_pool(**_kwargs: Any) -> object:
        seen.append(pyodbc.pooling)
        return object()

    mod.create_pool = create_pool  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "aioodbc", mod)
    return seen


async def test_the_store_pool_is_created_with_pooling_off(
    monkeypatch: pytest.MonkeyPatch, fake_pyodbc: types.ModuleType
) -> None:
    from messagefoundry.store import sqlserver

    seen = _fake_aioodbc(monkeypatch, fake_pyodbc)
    monkeypatch.setattr(sqlserver, "connection_string", lambda *_a, **_k: "DSN=test")
    settings = types.SimpleNamespace(pool_size=2, connect_timeout=5)
    _pool, executor = await sqlserver.SqlServerStore._create_pool(
        settings,  # type: ignore[arg-type]
        posture=None,
        maxsize=2,
    )
    assert isinstance(executor, ThreadPoolExecutor)
    executor.shutdown(wait=False)
    assert seen == [False], "the store's pool connected with driver-manager pooling on"


async def test_the_database_connector_pool_is_created_with_pooling_off(
    monkeypatch: pytest.MonkeyPatch, fake_pyodbc: types.ModuleType
) -> None:
    from messagefoundry.transports import database

    seen = _fake_aioodbc(monkeypatch, fake_pyodbc)
    await database._make_pool("DSN=test", 2, autocommit=False, login_timeout=15)
    assert seen == [False], "the DATABASE connector connected with driver-manager pooling on"
