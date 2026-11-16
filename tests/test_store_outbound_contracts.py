# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""SQLite leg of the outbound-completion contracts (BACKLOG #5752).

The same bodies run on Postgres from ``tests/test_store_outbound_contracts_postgres.py`` and on SQL
Server from ``tests/test_store_outbound_contracts_sqlserver.py``, on their gated live legs.
"""

from __future__ import annotations

import pathlib
from typing import Any

import pytest

from messagefoundry.store import MessageStore
from messagefoundry.store.crypto import generate_key, make_cipher
from tests import _response_completion_contract as completion
from tests._queue_tag_contract import RawFetch, RawSql


@pytest.fixture(params=["keyless", "keyed"])
async def store(request: pytest.FixtureRequest, tmp_path: pathlib.Path) -> Any:
    cipher = make_cipher(generate_key(), write_v2=True) if request.param == "keyed" else None
    s = await MessageStore.open(tmp_path / "outbound_contracts.db", cipher=cipher)
    yield s
    await s.close()


def _fetch(store: MessageStore) -> RawFetch:
    async def fetch(sql: str, params: tuple[Any, ...]) -> list[dict[str, Any]]:
        cur = await store._db.execute(sql, params)
        return [dict(r) for r in await cur.fetchall()]

    return fetch


def _raw(store: MessageStore) -> RawSql:
    async def raw(sql: str, params: tuple[Any, ...]) -> None:
        await store._db.execute(sql, params)
        await store._db.commit()

    return raw


@pytest.mark.parametrize("case", completion.CASES)
async def test_response_completion_contract(store: MessageStore, case: Any) -> None:
    await case(store, _fetch(store), _raw(store))
