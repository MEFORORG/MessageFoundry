# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The Postgres and SQL Server session writers under the Transit sealer (ADR 0217 slice 1b-ii),
with no database. Synthetic data only.

Each store is built with ``__new__``, as ``test_session_sql_placeholders.py`` builds it, and its
borrow is replaced by a fake connection that answers the session read with one row sealed through
an in-memory Transit stand-in and records every statement. The writer must check and re-seal
through the awaitable seam on both backends, as SQLite's does: a Holds row is re-sealed under the
active key, an Outage or a Forged row writes nothing, and a session under a retired key is declined
as ``RowSealError``, as on ``main``. Only the session writer is covered here. No test yet runs the
rest of either server backend's sealed paths under the Transit sealer: the hosted Postgres and SQL
Server legs run them under the local sealer only.
"""

from __future__ import annotations

import dataclasses
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

import pytest

from messagefoundry.config.settings import StoreSettings
from messagefoundry.store.pool_metrics import AcquireWaitHistogram
from messagefoundry.store.row_seal import (
    RowSealError,
    RowSealKeyRetiredError,
    TransitRowSealer,
    TransitSealUnavailableError,
)
from messagefoundry.store.store import (
    GLOBAL_SESSION_EPOCH_SQL,
    SessionRecord,
    new_session_record,
    require_session_seal_for_write,
    seal_session_async,
)
from tests._transit_seal_fake import RETIRED, FakeBackend

_HASH = "c" * 64
_NOW = 1_000_000.0
_GLOBAL_EPOCH_READ = f"SELECT {GLOBAL_SESSION_EPOCH_SQL}"

Seen = list[tuple[str, tuple[Any, ...]]]


async def _sealed_row(sealer: TransitRowSealer) -> dict[str, Any]:
    record = new_session_record(
        token_hash=_HASH,
        user_id="u-1",
        now=_NOW - 60,
        expires_at=_NOW + 3600,
        client=None,
        seed_reauth=True,
        auth_mechanism="password",
        idp_auth_time=None,
        user_epoch=0,
        global_epoch=0,
    )
    return dataclasses.asdict(await seal_session_async(sealer, record))


def _reads_session(sql: str) -> bool:
    return sql.startswith("SELECT * FROM sessions")


def _pg_store(row: dict[str, Any], seen: Seen) -> Any:
    from messagefoundry.store.postgres import PostgresStore

    class _Conn:
        async def execute(self, sql: str, *args: Any) -> str:
            seen.append((sql, args))
            return "UPDATE 1"

        async def fetchrow(self, sql: str, *args: Any) -> Any:
            seen.append((sql, args))
            return dict(row) if _reads_session(sql) else None

        async def fetchval(self, sql: str, *args: Any) -> Any:
            seen.append((sql, args))
            return 0 if sql.startswith(_GLOBAL_EPOCH_READ) else None

        def transaction(self) -> Any:
            @asynccontextmanager
            async def _txn() -> AsyncIterator[None]:
                yield

            return _txn()

    store: Any = PostgresStore.__new__(PostgresStore)
    store._settings = StoreSettings()
    store._acquire_wait = AcquireWaitHistogram()

    @asynccontextmanager
    async def _borrow(*, record: bool = True) -> AsyncIterator[_Conn]:
        yield _Conn()

    store._timed_acquire = _borrow
    return store


def _mssql_store(row: dict[str, Any], seen: Seen) -> Any:
    from messagefoundry.store.sqlserver import SqlServerStore

    columns = list(row)

    class _Cursor:
        def __init__(self) -> None:
            self.rowcount = 1
            self.description: list[tuple[str]] = [("x",)]
            self._last = ""

        async def execute(self, sql: str, params: tuple[Any, ...] = ()) -> None:
            seen.append((sql, tuple(params)))
            self._last = sql
            if _reads_session(sql):
                self.description = [(c,) for c in columns]

        async def fetchall(self) -> list[Any]:
            if _reads_session(self._last):
                return [tuple(row[c] for c in columns)]
            if self._last.startswith(_GLOBAL_EPOCH_READ):
                return [(0,)]
            return [(_HASH,)]  # the OUTPUT rowset of a write that landed

        async def close(self) -> None:
            return None

    class _Conn:
        async def cursor(self) -> _Cursor:
            return _Cursor()

        async def commit(self) -> None:
            return None

        async def rollback(self) -> None:
            return None

    store: Any = SqlServerStore.__new__(SqlServerStore)
    store._settings = StoreSettings(command_timeout=0)
    store._acquire_wait = AcquireWaitHistogram()
    store.committed_txns = 0

    @asynccontextmanager
    async def _borrow() -> AsyncIterator[_Conn]:
        yield _Conn()

    store._acquire = _borrow
    store._acquire_after_commit = _borrow
    return store


_STORES = {"postgres": _pg_store, "sqlserver": _mssql_store}


def _writes(seen: Seen) -> list[tuple[str, tuple[Any, ...]]]:
    return [(sql, params) for sql, params in seen if sql.lstrip().upper().startswith("UPDATE")]


@pytest.mark.parametrize("backend", sorted(_STORES))
async def test_a_session_write_checks_and_reseals_through_transit(backend: str) -> None:
    """Holds: the stored seal is checked through Transit and the row re-sealed under the active
    key. The control for the refusals below: the same write, with Transit up, lands."""
    fake = FakeBackend()
    sealer = TransitRowSealer(fake)
    row = await _sealed_row(sealer)
    seen: Seen = []
    store = _STORES[backend](row, seen)
    store._row_sealer = TransitRowSealer(fake)  # nothing cached, so the check meets Transit
    fake.inputs.clear()
    fake.verify_calls = 0
    await store.mark_session_mfa_verified(_HASH, now=_NOW)
    (write,) = _writes(seen)
    new_seals = [
        p for p in write[1] if isinstance(p, str) and sealer.is_active(p) and p != row["seal"]
    ]
    assert len(new_seals) == 1 and row["seal"] in write[1]  # a new seal, and the old one compared
    assert fake.verify_calls == 1, "the stored seal was not checked through Transit"
    assert len(fake.inputs) == 2, "the check and the re-seal are each one Transit call"


@pytest.mark.parametrize("backend", sorted(_STORES))
async def test_an_outage_on_a_session_write_writes_nothing(backend: str) -> None:
    fake = FakeBackend()
    row = await _sealed_row(TransitRowSealer(fake))
    seen: Seen = []
    store = _STORES[backend](row, seen)
    store._row_sealer = TransitRowSealer(fake)
    fake.down = True
    with pytest.raises(TransitSealUnavailableError):
        await store.mark_session_mfa_verified(_HASH, now=_NOW)
    assert _writes(seen) == []


@pytest.mark.parametrize("backend", sorted(_STORES))
async def test_a_forged_session_is_refused_and_writes_nothing(backend: str) -> None:
    fake = FakeBackend()
    row = await _sealed_row(TransitRowSealer(fake))
    row["client"] = "192.0.2.7"  # a sealed column changed outside the writer
    seen: Seen = []
    store = _STORES[backend](row, seen)
    store._row_sealer = TransitRowSealer(fake)
    with pytest.raises(RowSealError):
        await store.mark_session_mfa_verified(_HASH, now=_NOW)
    assert _writes(seen) == []


@pytest.mark.parametrize("backend", sorted(_STORES))
async def test_a_session_under_a_retired_key_is_declined_as_on_main(backend: str) -> None:
    """The store's check names a retired-key session as its own type; the writer turns it back
    into ``RowSealError``, as on ``main`` and as SQLite's writer does (owner ruling 2026-11-07)."""
    row = await _sealed_row(TransitRowSealer(FakeBackend(active=RETIRED)))
    seen: Seen = []
    store = _STORES[backend](row, seen)
    store._row_sealer = TransitRowSealer(FakeBackend(), retired_key_names=[RETIRED])
    # The row is a retired-key session, not a Forged one: the check itself names it so.
    with pytest.raises(RowSealKeyRetiredError):
        await require_session_seal_for_write(store._row_sealer, SessionRecord(**row))
    with pytest.raises(RowSealError) as refused:
        await store.mark_session_mfa_verified(_HASH, now=_NOW)
    assert type(refused.value) is RowSealError
    assert _writes(seen) == []
