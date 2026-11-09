# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A revoke under the Transit sealer still ends every session (decisions
d20261109T165402853-83b348 and d20261109T165406730-2505f2 on ADR 0217). Synthetic data only.

The account-epoch raise a revoke runs first goes without the raise on a Forged, Unverifiable or
Outage answer, as it went without it on a Forged one before; an Outage pages
``authority-seal-transit``. A Transit refusal of the kept session's re-stamp declines it, so that
session is ended too. SQLite runs on a real store with an in-memory Transit stand-in; Postgres and
SQL Server run their twins with the write helpers replaced, since a live server is not needed to
see what each catch takes.
"""

from __future__ import annotations

import sqlite3
import time
from collections.abc import AsyncIterator, Iterator
from pathlib import Path
from typing import Any

import pytest

from messagefoundry.auth.tokens import hash_token, mint_token
from messagefoundry.store.crypto import generate_key, make_cipher
from messagefoundry.store.row_seal import (
    RowSealError,
    RowSealUnverifiableError,
    TransitRowSealer,
    TransitSealUnavailableError,
    TransitSealUnverifiableError,
    set_transit_outage_alert,
)
from messagefoundry.store.store import KeptSessionRestamp, MessageStore, SessionRecord
from tests._transit_seal_fake import FakeBackend, with_version


@pytest.fixture
def pages() -> Iterator[list[str]]:
    seen: list[str] = []
    set_transit_outage_alert(seen.append)
    try:
        yield seen
    finally:
        set_transit_outage_alert(None)


@pytest.fixture
async def transit(tmp_path: Path) -> AsyncIterator[tuple[MessageStore, FakeBackend, Path]]:
    path = tmp_path / "revoke.db"
    store = await MessageStore.open(path, cipher=make_cipher(generate_key(), write_v2=True))
    backend = FakeBackend()
    store._row_sealer = TransitRowSealer(backend)
    try:
        yield store, backend, path
    finally:
        await store.close()


def _sql(path: Path, sql: str, params: tuple[object, ...] = ()) -> list[tuple[object, ...]]:
    conn = sqlite3.connect(path)
    try:
        rows = conn.execute(sql, params).fetchall()
        conn.commit()
        return rows
    finally:
        conn.close()


def _plant(path: Path, table: str, column: str, key: str, value: str) -> None:
    """A well-formed seal naming version 5, which the stand-in does not hold: Unverifiable."""
    (seal,) = _sql(path, f"SELECT {column} FROM {table} WHERE {key}=?", (value,))[0]
    _sql(
        path, f"UPDATE {table} SET {column}=? WHERE {key}=?", (with_version(str(seal), "5"), value)
    )


async def _user(store: MessageStore, user_id: str) -> None:
    await store.create_user(
        user_id=user_id,
        username=f"name-{user_id}",
        auth_provider="local",
        password_hash="synthetic-hash",
        password_generated=False,
        audits=(),
    )


async def _session(store: MessageStore, user_id: str) -> str:
    token = mint_token()
    assert await store.create_session(
        token_hash=hash_token(token), user_id=user_id, expires_at=time.time() + 3600
    )
    return token


def _live(path: Path, user_id: str) -> int:
    ((n,),) = _sql(
        path, "SELECT COUNT(*) FROM sessions WHERE user_id=? AND revoked_at IS NULL", (user_id,)
    )
    return int(str(n))


# --- SQLite ---------------------------------------------------------------------------------------


async def test_an_unverifiable_account_still_has_every_session_ended(
    transit: tuple[MessageStore, FakeBackend, Path], pages: list[str]
) -> None:
    store, _, path = transit
    await _user(store, "u-1")
    for _ in range(2):
        await _session(store, "u-1")
    _plant(path, "users", "authz_seal", "id", "u-1")
    result = await store.revoke_user_sessions("u-1")
    assert result.count == 2 and _live(path, "u-1") == 0
    assert pages == []  # Unverifiable is no Outage, so no transit page


async def test_an_outage_at_the_epoch_raise_still_ends_every_session_and_pages(
    transit: tuple[MessageStore, FakeBackend, Path], pages: list[str]
) -> None:
    store, backend, path = transit
    await _user(store, "u-1")
    for _ in range(2):
        await _session(store, "u-1")
    store._row_sealer = TransitRowSealer(backend)  # nothing cached: the raise meets Transit
    backend.down = True
    try:
        result = await store.revoke_user_sessions("u-1")
    finally:
        backend.down = False
    assert result.count == 2 and _live(path, "u-1") == 0
    assert len(pages) == 1 and "transit outage" in pages[0]


async def test_revoke_all_with_one_unverifiable_account_ends_every_session(
    transit: tuple[MessageStore, FakeBackend, Path], pages: list[str]
) -> None:
    store, _, path = transit
    for user in ("u-1", "u-2"):
        await _user(store, user)
        await _session(store, user)
    _plant(path, "users", "authz_seal", "id", "u-1")
    result = await store.revoke_all_sessions()
    assert result.count == 2 and _live(path, "u-1") == 0 and _live(path, "u-2") == 0


async def test_an_unverifiable_kept_session_is_ended_too(
    transit: tuple[MessageStore, FakeBackend, Path], pages: list[str]
) -> None:
    """Control first: a kept session whose seal holds is kept."""
    store, _, path = transit
    await _user(store, "u-1")
    await _session(store, "u-1")
    kept = await _session(store, "u-1")
    result = await store.revoke_user_sessions("u-1", except_token_hash=hash_token(kept))
    assert result.kept and _live(path, "u-1") == 1
    other = await _session(store, "u-1")
    _plant(path, "sessions", "seal", "token_hash", hash_token(kept))
    result = await store.revoke_user_sessions("u-1", except_token_hash=hash_token(kept))
    assert not result.kept and result.ended_kept and _live(path, "u-1") == 0
    assert other


# --- Postgres and SQL Server twins ----------------------------------------------------------------


def _server(backend: str) -> Any:
    import importlib

    module = importlib.import_module(f"messagefoundry.store.{backend}")
    cls = getattr(module, "PostgresStore" if backend == "postgres" else "SqlServerStore")
    return cls.__new__(cls)


_REFUSALS: list[type[Exception]] = [
    RowSealError,
    RowSealUnverifiableError,
    TransitSealUnverifiableError,
    TransitSealUnavailableError,
]


def _raise(kind: type[Exception]) -> Exception:
    if kind is TransitSealUnavailableError:
        return TransitSealUnavailableError()
    if kind is TransitSealUnverifiableError:
        return TransitSealUnverifiableError("user", 5, 1)
    return kind("user", "")


@pytest.mark.parametrize("kind", _REFUSALS, ids=lambda k: k.__name__)
@pytest.mark.parametrize("backend", ["postgres", "sqlserver"])
async def test_a_server_epoch_raise_goes_without_on_every_refusal(
    backend: str, kind: type[Exception], pages: list[str]
) -> None:
    store = _server(backend)

    async def refused(*_args: Any, **_kwargs: Any) -> None:
        raise _raise(kind)

    store._write_user = refused
    assert await store._bump_session_epoch(object(), "u-1") is None
    assert len(pages) == (1 if kind is TransitSealUnavailableError else 0)


class _PgConn:
    async def execute(self, sql: str, *args: Any) -> str:
        return "UPDATE 1"


class _MssqlCur:
    async def execute(self, sql: str, params: tuple[Any, ...] = ()) -> None:
        return None

    async def fetchall(self) -> list[Any]:
        return [("x",)]


@pytest.mark.parametrize(
    "kind",
    [RowSealUnverifiableError, TransitSealUnverifiableError, TransitSealUnavailableError],
    ids=lambda k: k.__name__,
)
@pytest.mark.parametrize("backend", ["postgres", "sqlserver"])
async def test_a_server_kept_session_refused_by_transit_is_ended(
    backend: str, kind: type[Exception], pages: list[str]
) -> None:
    store = _server(backend)

    async def refused(*_args: Any, **_kwargs: Any) -> SessionRecord | None:
        raise _raise(kind)

    store._write_session = refused
    conn: Any = _PgConn() if backend == "postgres" else _MssqlCur()
    restamp = KeptSessionRestamp("u-1", None, None)
    result = await store._keep_or_end_session(conn, 3, "c" * 64, restamp, 1.0)
    assert not result.kept and result.ended_kept and result.count == 4


@pytest.mark.parametrize("backend", ["postgres", "sqlserver"])
async def test_a_server_forged_kept_session_still_raises_as_on_main(backend: str) -> None:
    store = _server(backend)

    async def forged(*_args: Any, **_kwargs: Any) -> SessionRecord | None:
        raise RowSealError("session", "")

    store._write_session = forged
    conn: Any = _PgConn() if backend == "postgres" else _MssqlCur()
    with pytest.raises(RowSealError):
        await store._keep_or_end_session(
            conn, 0, "c" * 64, KeptSessionRestamp("u", None, None), 1.0
        )
