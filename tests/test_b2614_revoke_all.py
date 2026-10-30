# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""``revoke_all_sessions`` ends every account's sessions in one call (BACKLOG #2614).

Before it, the store could end one session or one account's sessions, and nothing ended them all:
after a suspected compromise an operator had to walk every account. The contract below runs on
SQLite here and on the server backends when their gate is set (``MEFOR_TEST_POSTGRES``,
``MEFOR_TEST_SQLSERVER``), each on a keyed handle so the seal and epoch checks are live.

Every refusal has a control beside it: the same session resolves before the revoke.
"""

from __future__ import annotations

import os
import sqlite3
import time
import uuid
from collections.abc import AsyncIterator, Awaitable, Callable
from pathlib import Path
from typing import Any

import pytest

from messagefoundry.auth.service import AuthService
from messagefoundry.auth.tokens import hash_token, mint_token
from messagefoundry.config.settings import AuthSettings
from messagefoundry.store.crypto import generate_key, make_cipher
from messagefoundry.store.store import MessageStore, session_seal_ok

#: Runs one statement with ``?`` placeholders against the store's database, outside the store.
RawSql = Callable[[str, tuple[Any, ...]], Awaitable[None]]


async def _user(store: Any, user_id: str) -> None:
    await store.create_user(
        user_id=user_id,
        username=user_id,
        auth_provider="local",
        display_name=None,
        email=None,
        password_hash="h",
        now=time.time(),
        password_generated=False,
    )


async def _mint(store: Any, user_id: str) -> str:
    token = mint_token()
    await store.create_session(
        token_hash=hash_token(token),
        user_id=user_id,
        expires_at=time.time() + 3600,
        client="192.0.2.10",
        auth_mechanism="password",
    )
    return token


async def assert_revoke_all_contract(store: Any, raw: RawSql) -> None:
    """Drive ``revoke_all_sessions`` through its contract on ``store``'s backend. The account ids
    are fresh each run, so a shared server database's other rows do not change the outcome."""
    sealer = store.row_sealer()
    assert sealer is not None, "the contract needs a store opened with a store key"
    service = AuthService(store, AuthSettings())
    run = uuid.uuid4().hex[:8]
    alice, bob = f"b2614-a-{run}", f"b2614-b-{run}"
    await _user(store, alice)
    await _user(store, bob)

    kept = await _mint(store, alice)
    second = await _mint(store, alice)
    other = await _mint(store, bob)
    copy = await store.get_session(hash_token(other))
    assert copy is not None
    for token in (kept, second, other):  # control: each resolves before the revoke
        assert await service.identity_for_token(token) is not None

    # --- every account's sessions end, but the kept one ----------------------------------------
    revoked = await store.revoke_all_sessions(except_token_hash=hash_token(kept))
    assert revoked >= 2
    assert await service.identity_for_token(second) is None
    assert await service.identity_for_token(other) is None
    survivor = await store.get_session(hash_token(kept))
    assert survivor is not None and survivor.revoked_at is None
    assert session_seal_ok(sealer, survivor)  # re-sealed under the raised epoch...
    assert await service.identity_for_token(kept) is not None  # ...so it still resolves

    # --- the epoch of an account with no kept session was raised too ---------------------------
    await raw(
        "UPDATE sessions SET revoked_at=NULL, seal=? WHERE token_hash=?",
        (copy.seal, hash_token(other)),
    )
    restored = await store.get_session(hash_token(other))
    assert restored is not None and session_seal_ok(sealer, restored)  # the copy's seal holds...
    assert await service.identity_for_token(other) is None  # ...and its epoch is stale

    # --- with no exception, the kept session ends too ------------------------------------------
    fresh = await _mint(store, bob)
    assert await service.identity_for_token(fresh) is not None  # control
    assert await store.revoke_all_sessions() >= 2
    assert await service.identity_for_token(kept) is None
    assert await service.identity_for_token(fresh) is None

    # --- an exception naming no row excepts nothing ---------------------------------------------
    late = await _mint(store, alice)
    assert await store.revoke_all_sessions(except_token_hash=hash_token(mint_token())) >= 1
    assert await service.identity_for_token(late) is None


@pytest.fixture
async def keyed(tmp_path: Path) -> AsyncIterator[tuple[MessageStore, Path]]:
    path = tmp_path / "b2614.db"
    store = await MessageStore.open(path, cipher=make_cipher(generate_key(), write_v2=True))
    try:
        yield store, path
    finally:
        await store.close()


def _sqlite_raw(path: Path) -> RawSql:
    async def raw(sql: str, params: tuple[Any, ...]) -> None:
        conn = sqlite3.connect(path)
        try:
            conn.execute(sql, params)
            conn.commit()
        finally:
            conn.close()

    return raw


async def test_the_revoke_all_contract_holds_on_sqlite(
    keyed: tuple[MessageStore, Path],
) -> None:
    store, path = keyed
    await assert_revoke_all_contract(store, _sqlite_raw(path))


async def test_the_revoke_all_count_is_exact_on_sqlite(keyed: tuple[MessageStore, Path]) -> None:
    """On a store this test owns the count is exact, which the shared-database contract cannot
    assert: two accounts, three sessions, one kept."""
    store, _path = keyed
    await _user(store, "u1")
    await _user(store, "u2")
    kept = await _mint(store, "u1")
    await _mint(store, "u1")
    await _mint(store, "u2")
    assert await store.revoke_all_sessions(except_token_hash=hash_token(kept)) == 2
    assert await store.revoke_all_sessions(except_token_hash=hash_token(kept)) == 0
    assert await store.revoke_all_sessions() == 1
    assert await store.revoke_all_sessions() == 0


@pytest.mark.skipif(
    not os.getenv("MEFOR_TEST_POSTGRES"),
    reason="set MEFOR_TEST_POSTGRES=1 (+ MEFOR_STORE_* connection env) to run Postgres tests",
)
async def test_the_revoke_all_contract_holds_on_postgres() -> None:
    from messagefoundry.config.settings import load_settings
    from messagefoundry.store.postgres import PostgresStore
    from tests._session_seal_contract import dollar_placeholders

    store = await PostgresStore.open(
        load_settings(environ=os.environ).store, cipher=make_cipher(generate_key())
    )
    try:

        async def raw(sql: str, params: tuple[Any, ...]) -> None:
            async with store._pool.acquire() as conn:
                await conn.execute(dollar_placeholders(sql), *params)

        await assert_revoke_all_contract(store, raw)
    finally:
        await store.close()


@pytest.mark.skipif(
    not os.getenv("MEFOR_TEST_SQLSERVER"),
    reason="set MEFOR_TEST_SQLSERVER=1 (+ MEFOR_STORE_* connection env) to run SQL Server tests",
)
async def test_the_revoke_all_contract_holds_on_sqlserver() -> None:
    from messagefoundry.config.settings import load_settings
    from messagefoundry.store.sqlserver import SqlServerStore

    store = await SqlServerStore.open(
        load_settings(environ=os.environ).store, cipher=make_cipher(generate_key())
    )
    try:

        async def raw(sql: str, params: tuple[Any, ...]) -> None:
            async with store._pool.acquire() as conn:
                cur = await conn.cursor()
                await cur.execute(sql, params)
                await conn.commit()

        await assert_revoke_all_contract(store, raw)
    finally:
        await store.close()
