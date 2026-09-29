# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #2089: a DATABASE connection's ``connect_timeout`` must reach ODBC Driver 18 as the LOGIN
timeout, as ``[store].connect_timeout`` does since #1626.

Why the DSN keyword did nothing is stated in ``transports.database._login_timeout``; the fix is to
pass ``timeout=`` to the pool, which aioodbc forwards to every ``pyodbc.connect`` it makes.

**Why the fakes.** ``aioodbc``/``pyodbc`` are the optional ``sqlserver`` extra, not installed on every
CI leg. A recording ``aioodbc`` stands in through ``sys.modules``, which the connector's lazy import
resolves, and ``pyodbc`` is hidden so the #2049 pooling guard is a no-op. What is pinned is the
argument each pool site hands the driver, which is the whole of the defect.

The pool sites pinned here are at least the destination, the poll source, the ``db_lookup`` executor
and the reference-set sync, each through ``transports.database._make_pool``. Each SQL Server test here fails on the
pre-fix code, where no site passed ``timeout=``.

The value is also checked: ``connect_timeout`` must be a whole number of seconds, at least 1, and a
bad one is refused before any dial, naming the declaration and withholding the value.
"""

from __future__ import annotations

import sys
import types
from typing import Any

import pytest

from messagefoundry.config.models import (
    DEFAULT_DB_CONNECT_TIMEOUT,
    ConnectorType,
    Destination,
    Source,
)
from messagefoundry.config.wiring import DatabaseRef, WiringError, env
from messagefoundry.transports.database import (
    DatabaseDestination,
    DatabaseLookupExecutor,
    DatabaseSource,
    _build_dsn,
    _make_pool,
)

# Deliberately not the 15 s default, so a hardcoded literal cannot pass.
_LOGIN_TIMEOUT = 7

_SQLSERVER: dict[str, Any] = {
    "server": "db.example",
    "database": "d",
    "connect_timeout": _LOGIN_TIMEOUT,
}


class _StopPool(Exception):
    """Raised by the fake create_pool once it has recorded its arguments."""


@pytest.fixture
def pool_calls(monkeypatch: pytest.MonkeyPatch) -> list[dict[str, Any]]:
    calls: list[dict[str, Any]] = []
    module = types.ModuleType("aioodbc")

    async def _create_pool(**kwargs: Any) -> Any:
        calls.append(kwargs)
        raise _StopPool

    module.create_pool = _create_pool  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "aioodbc", module)
    monkeypatch.setitem(sys.modules, "pyodbc", None)  # the #2049 guard becomes a no-op
    return calls


def _dest(settings: dict[str, Any]) -> DatabaseDestination:
    return DatabaseDestination(
        Destination(
            name="OB_DB",
            type=ConnectorType.DATABASE,
            settings={**settings, "statement": "INSERT INTO t (x) VALUES (:x)"},
        )
    )


def test_dsn_carries_no_login_timeout_keyword() -> None:
    """The keyword the driver ignores must not be emitted: its presence reads as a control that is
    not there. Red on the pre-fix code, which emitted ``Connection Timeout=7``."""
    dsn = _build_dsn(dict(_SQLSERVER))
    assert "Connection Timeout" not in dsn
    assert "Timeout" not in dsn


async def test_destination_pool_passes_the_login_timeout(
    pool_calls: list[dict[str, Any]],
) -> None:
    with pytest.raises(_StopPool):
        await _dest(_SQLSERVER)._get_pool()
    assert len(pool_calls) == 1
    assert pool_calls[0].get("timeout") == _LOGIN_TIMEOUT
    assert pool_calls[0].get("autocommit") is False


async def test_destination_pool_defaults_to_the_declared_default(
    pool_calls: list[dict[str, Any]],
) -> None:
    """A mapping that omits ``connect_timeout`` gets the same default the factories declare, not
    none."""
    assert DEFAULT_DB_CONNECT_TIMEOUT == 15  # the documented value
    settings = {k: v for k, v in _SQLSERVER.items() if k != "connect_timeout"}
    with pytest.raises(_StopPool):
        await _dest(settings)._get_pool()
    assert pool_calls[0].get("timeout") == DEFAULT_DB_CONNECT_TIMEOUT


async def test_poll_source_pool_passes_the_login_timeout(
    pool_calls: list[dict[str, Any]],
) -> None:
    source = DatabaseSource(
        Source(
            name="IB_DB",
            type=ConnectorType.DATABASE,
            settings={**_SQLSERVER, "poll_statement": "SELECT 1"},
        )
    )
    with pytest.raises(_StopPool):
        await source._get_pool()
    assert len(pool_calls) == 1
    assert pool_calls[0].get("timeout") == _LOGIN_TIMEOUT
    assert pool_calls[0].get("autocommit") is True


async def test_db_lookup_pool_passes_the_login_timeout(
    pool_calls: list[dict[str, Any]],
) -> None:
    executor = DatabaseLookupExecutor({"clarity": dict(_SQLSERVER)})
    with pytest.raises(_StopPool):
        await executor._get_pool("clarity")
    assert len(pool_calls) == 1
    assert pool_calls[0].get("timeout") == _LOGIN_TIMEOUT


async def test_reference_sync_pool_passes_the_login_timeout(
    pool_calls: list[dict[str, Any]],
) -> None:
    from messagefoundry.pipeline.reference_sync import _load_database_source

    settings = {**_SQLSERVER, "statement": "SELECT code FROM t", "key_column": "code"}
    with pytest.raises(_StopPool):
        await _load_database_source(settings, None)
    assert len(pool_calls) == 1
    assert pool_calls[0].get("timeout") == _LOGIN_TIMEOUT


async def test_generic_dialect_passes_no_login_timeout(
    pool_calls: list[dict[str, Any]],
) -> None:
    """Scope pin: the generic dialect never carried a login timeout, and #2089 does not turn one on.
    Whether an arbitrary operator-named driver accepts ``SQL_ATTR_LOGIN_TIMEOUT`` is unmeasured."""
    settings = {
        "server": "db.example",
        "dialect": "generic",
        "odbc_driver": "PostgreSQL Unicode",
        "odbc_params": {"SSLmode": "verify-full"},
        "connect_timeout": _LOGIN_TIMEOUT,
    }
    with pytest.raises(_StopPool):
        await _dest(settings)._get_pool()
    assert "timeout" not in pool_calls[0]


async def test_make_pool_requires_the_login_timeout() -> None:
    """A new pool site cannot quietly go without a login timeout: the keyword has no default."""
    with pytest.raises(TypeError, match="login_timeout"):
        await _make_pool("DSN=x", 1, autocommit=True)  # type: ignore[call-arg]


@pytest.mark.parametrize("bad", [0, -1, True, 2.5, "0", "abc", "2.5", None])
def test_a_bad_connect_timeout_is_refused_at_construction(bad: object) -> None:
    """``connect_timeout`` must be a whole number of seconds, at least 1. The refusal names the
    connection and the setting, and withholds the value (it may be env()-resolved)."""
    with pytest.raises(ValueError, match="'OB_DB' connect_timeout") as info:
        _dest({**_SQLSERVER, "connect_timeout": bad})
    assert "value withheld" in str(info.value)
    if isinstance(bad, str):  # #1183/#1796: the value stays out of the message and the chain
        assert bad not in str(info.value).replace("'OB_DB'", "")
    assert info.value.__cause__ is None
    assert info.value.__context__ is None


async def test_an_env_resolved_string_connect_timeout_is_accepted(
    pool_calls: list[dict[str, Any]],
) -> None:
    """An env() ref without ``cast`` resolves to a string; a whole-number one is still honoured."""
    with pytest.raises(_StopPool):
        await _dest({**_SQLSERVER, "connect_timeout": "7"})._get_pool()
    assert pool_calls[0].get("timeout") == _LOGIN_TIMEOUT


def test_a_bad_connect_timeout_is_refused_on_the_generic_dialect_too() -> None:
    """The generic dialect ignores the value, but a malformed one is still a config error."""
    settings = {
        "server": "db.example",
        "dialect": "generic",
        "odbc_driver": "PostgreSQL Unicode",
        "odbc_params": {"SSLmode": "verify-full"},
        "connect_timeout": 0,
    }
    with pytest.raises(ValueError, match="connect_timeout"):
        _dest(settings)


def test_a_bad_connect_timeout_is_refused_by_the_lookup_executor() -> None:
    with pytest.raises(ValueError, match="DatabaseLookup 'clarity' connect_timeout"):
        DatabaseLookupExecutor({"clarity": {**_SQLSERVER, "connect_timeout": 0}})


def test_a_bad_connect_timeout_is_refused_when_a_database_ref_is_declared() -> None:
    """A reference set first dials at sync time, after start, so DatabaseRef checks at declaration."""
    with pytest.raises(WiringError, match="DatabaseRef connect_timeout"):
        DatabaseRef(
            server="db.example",
            database="d",
            statement="SELECT code FROM t",
            key_column="code",
            connect_timeout=0,
        )


def test_a_database_ref_accepts_an_env_ref_connect_timeout() -> None:
    """An env() ref has no value at declaration, so it is left to the sync-time check."""
    spec = DatabaseRef(
        server="db.example",
        database="d",
        statement="SELECT code FROM t",
        key_column="code",
        connect_timeout=env("ref_timeout", cast=int),  # type: ignore[arg-type]
    )
    assert spec.kind == "database"


async def test_lookup_pool_keeps_its_login_timeout_whatever_the_mapping_dialect(
    pool_calls: list[dict[str, Any]],
) -> None:
    """The lookup always builds the SQL Server DSN, so a stray `dialect` key must not drop the bound."""
    executor = DatabaseLookupExecutor({"clarity": {**_SQLSERVER, "dialect": "generic"}})
    with pytest.raises(_StopPool):
        await executor._get_pool("clarity")
    assert pool_calls[0].get("timeout") == _LOGIN_TIMEOUT


def test_a_poll_source_refusal_names_the_inbound_record() -> None:
    with pytest.raises(ValueError, match="DATABASE connection 'inbound:IB_DB' connect_timeout"):
        DatabaseSource(
            Source(
                name="IB_DB",
                type=ConnectorType.DATABASE,
                settings={**_SQLSERVER, "poll_statement": "SELECT 1", "connect_timeout": 0},
            )
        )


async def test_reference_sync_refuses_a_bad_resolved_connect_timeout(
    pool_calls: list[dict[str, Any]],
) -> None:
    """The env() case DatabaseRef defers: the resolved value is checked at sync, before any dial."""
    from messagefoundry.pipeline.reference_sync import _load_database_source

    settings = {
        **_SQLSERVER,
        "statement": "SELECT code FROM t",
        "key_column": "code",
        "connect_timeout": "0",
    }
    with pytest.raises(ValueError, match="reference source connect_timeout"):
        await _load_database_source(settings, None)
    assert pool_calls == []
