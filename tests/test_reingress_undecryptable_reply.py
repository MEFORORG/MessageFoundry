# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #4995: a captured reply whose body does not decrypt must not hold the loopback lane.

The contract in ``tests/_undecryptable_reply_contract.py`` runs here on SQLite and from
``tests/test_postgres_store.py`` and ``tests/test_sqlserver_store.py`` on their live legs. This file
adds the running worker loop, which is where the forever re-pend lived: the step raised, the fault
arm handed the token back, and the next claim took the same head again.
"""

from __future__ import annotations

import asyncio
import pathlib
from typing import Any

import pytest

from messagefoundry.store import MessageStatus, MessageStore, OutboxStatus
from messagefoundry.store.crypto import generate_key, make_cipher
from tests import _undecryptable_reply_contract as contract
from tests._erased_reply_contract import LOOP, children, status_of
from tests._queue_tag_contract import RawFetch, RawSql


@pytest.fixture
async def store(tmp_path: pathlib.Path) -> Any:
    s = await MessageStore.open(
        tmp_path / "undecryptable_reply.db", cipher=make_cipher(generate_key(), write_v2=True)
    )
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


@pytest.mark.parametrize("spoil", contract.SPOILS, ids=lambda s: s.__name__)
async def test_undecryptable_reply_contract(store: MessageStore, spoil: contract.Spoil) -> None:
    await contract.assert_lane_moves_past_an_undecryptable_reply(
        store, _fetch(store), _raw(store), spoil
    )


@pytest.mark.parametrize("spoil", contract.SPOILS, ids=lambda s: s.__name__)
async def test_the_running_worker_drains_past_an_undecryptable_reply(
    store: MessageStore, spoil: contract.Spoil
) -> None:
    """The worker loop itself, not one step: the bad head must not come back to the head of the
    lane. Before the fix this timed out with the good reply still waiting behind it."""
    fetch, raw = _fetch(store), _raw(store)
    bad = await contract.captured(store, control="UR-W-BAD", now=1.0)
    good = await contract.captured(store, control="UR-W-GOOD", now=2.0)
    await spoil(fetch, raw, bad, good)

    runner = contract.runner(store)
    task = asyncio.ensure_future(runner._response_worker(LOOP))
    try:
        async with asyncio.timeout(5.0):
            while await status_of(store, good) != MessageStatus.PROCESSED.value:
                await asyncio.sleep(0.02)
    finally:
        runner._stop.set()
        runner._response_work.set()
        await asyncio.wait_for(task, timeout=5.0)

    assert (await contract.token_of(fetch, bad))["status"] == OutboxStatus.DEAD.value
    assert await status_of(store, bad) == MessageStatus.ERROR.value
    assert len(await children(fetch)) == 1
