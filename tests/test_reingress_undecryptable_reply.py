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
import contextlib
import pathlib
import threading
from typing import Any

import pytest

from messagefoundry.config.models import BuildupThreshold
from messagefoundry.pipeline.alerts import LoggingAlertSink
from messagefoundry.store import MessageStatus, MessageStore, OutboxStatus, Stage
from messagefoundry.store.crypto import CipherUnavailableError, generate_key, make_cipher
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


@pytest.mark.parametrize("case", contract.HANDOFF_CASES, ids=lambda c: c.__name__)
async def test_handoff_containment_contract(
    store: MessageStore, case: contract.ContractCase
) -> None:
    """BACKLOG #5727: a cell that fails to decrypt dead-letters the token; a key service with no
    verdict, an engine fault on the reply cell and a failed seal do not."""
    await case(store, _fetch(store), _raw(store))


async def test_an_outage_re_pends_the_token_and_the_lane_resumes_in_order(
    store: MessageStore,
) -> None:
    """BACKLOG #5727: through the running worker, a key-service outage leaves the head PENDING with
    its attempt handed back and a future due time, dead-letters nothing, and passes no later row.
    Once the service answers, both replies re-ingress."""
    fetch = _fetch(store)
    head = await contract.captured(store, control="UR-O-HEAD", now=1.0)
    behind = await contract.captured(store, control="UR-O-BEHIND", now=2.0)
    [reply] = await fetch("SELECT body FROM response WHERE message_id=?", (head,))
    runner = contract.runner(store)
    with contract.faulting_cipher(store) as fault:
        fault.target, fault.open_error = reply["body"], CipherUnavailableError("synthetic")
        task = asyncio.ensure_future(runner._response_worker(LOOP))
        try:
            async with asyncio.timeout(5.0):
                while True:
                    [row] = await fetch(
                        "SELECT status, attempts, next_attempt_at, updated_at FROM queue"
                        " WHERE message_id=? AND stage='response'",
                        (head,),
                    )
                    # Past the capture's own due time (2.0 at most): the fault arm has re-pended it.
                    if row["status"] == OutboxStatus.PENDING.value and row["updated_at"] > 2:
                        break
                    await asyncio.sleep(0.005)
            assert row["attempts"] == 0
            assert row["next_attempt_at"] > row["updated_at"]  # a backoff, not a hot re-claim
            # A claim at a moment inside the head's backoff: the worker sleeps through that window,
            # so only a direct claim shows that the backed-off head still blocks the row behind it.
            assert (
                await store.claim_next_fifo(LOOP, now=row["updated_at"], stage=Stage.RESPONSE.value)
                is None
            )
            assert (await contract.token_of(fetch, behind))["status"] == OutboxStatus.PENDING.value
            assert await children(fetch) == []
            assert not [e for e in await store.events_for(head) if e["event"] == "dead"]
            fault.heal()
            async with asyncio.timeout(5.0):
                while await status_of(store, behind) != MessageStatus.PROCESSED.value:
                    await asyncio.sleep(0.02)
        finally:
            runner._stop.set()
            runner._response_work.set()
            await asyncio.wait_for(task, timeout=5.0)
    assert await status_of(store, head) == MessageStatus.PROCESSED.value
    assert len(await children(fetch)) == 2


async def test_an_outage_stalls_the_loop_on_no_retry_of_the_running_worker(
    store: MessageStore,
) -> None:
    """BACKLOG #5727: the running worker retries a token through a key-service outage, where before
    #5727 it dead-lettered it after one read (BACKLOG #4995). Under a cipher that blocks on I/O, as
    Transit does, no retry's read may block the event loop. The worker backs off 1 s between
    retries, so the wait covers at least two."""
    fetch = _fetch(store)
    head = await contract.captured(store, control="UR-S-HEAD", now=1.0)
    [reply] = await fetch("SELECT body FROM response WHERE message_id=?", (head,))
    runner = contract.runner(store)
    loop_thread = threading.get_ident()
    with contract.blocking_faulting_cipher(store) as fault:
        fault.target, fault.open_error = reply["body"], CipherUnavailableError("synthetic")
        async with contract.loop_stalls() as gaps:
            task = asyncio.ensure_future(runner._response_worker(LOOP))
            try:
                async with asyncio.timeout(10.0):
                    while len(fault.blocks) < 2:
                        await asyncio.sleep(0.02)
            finally:
                runner._stop.set()
                runner._response_work.set()
                await asyncio.wait_for(task, timeout=5.0)
        assert fault.loop_cost(loop_thread, gaps) == (0, 0), (fault.blocks, gaps)
    assert not [e for e in await store.events_for(head) if e["event"] == "dead"]


class _BuildupSink(LoggingAlertSink):
    def __init__(self) -> None:
        self.buildup: list[tuple[str, int]] = []

    def queue_buildup(self, name: str, *, depth: int, oldest_age_seconds: float) -> None:
        self.buildup.append((name, depth))


@pytest.mark.parametrize("leader", [True, False], ids=["leader", "not_leader"])
async def test_a_reply_lane_held_by_no_verdict_faults_raises_the_buildup_alert(
    store: MessageStore, leader: bool
) -> None:
    """BACKLOG #5727: the key service gives no verdict on the step's read of the reply, pass after
    pass, while the claim's open of the token still works, so the response worker never reaches
    its success path, and the token is re-pended between claims, so the in-flight watch never sees
    it held. The fault arm's build-up check is what pages it. The token was captured at epoch 1.0,
    so it is past the 60 s age on the first pass. An outage that also fails the claim's open sets
    the token aside at the claim, which this check does not reach. A node that does not lead pages
    nothing, since a successor may own the lane."""
    fetch = _fetch(store)
    head = await contract.captured(store, control="UR-B-HEAD", now=1.0)
    [reply] = await fetch("SELECT body FROM response WHERE message_id=?", (head,))
    runner = contract.runner(store)
    sink = _BuildupSink()
    runner._alert_sink = sink
    runner._buildup_default = BuildupThreshold(max_oldest_seconds=60.0)
    if not leader:
        runner._coordinator.is_leader = lambda: False  # type: ignore[method-assign]
    with contract.faulting_cipher(store) as fault:
        fault.target, fault.open_error = reply["body"], CipherUnavailableError("synthetic")
        task = asyncio.ensure_future(runner._response_worker(LOOP))
        try:
            with contextlib.suppress(TimeoutError):
                async with asyncio.timeout(4.0):
                    while not sink.buildup:
                        await asyncio.sleep(0.02)
        finally:
            runner._stop.set()
            runner._response_work.set()
            await asyncio.wait_for(task, timeout=5.0)
    # CONTROL: the lane really was held by the fault, with nothing dead-lettered.
    assert (await contract.token_of(fetch, head))["status"] == OutboxStatus.PENDING.value
    assert not [e for e in await store.events_for(head) if e["event"] == "dead"]
    assert sink.buildup == ([(LOOP, 1)] if leader else []), sink.buildup


@pytest.mark.parametrize("leader", [True, False], ids=["leader", "not_leader"])
async def test_a_whole_outage_set_aside_at_the_claim_raises_the_buildup_alert(
    store: MessageStore, leader: bool
) -> None:
    """BACKLOG #5727: when every open fails, the claim's own open of the token's payload gets no
    verdict, so the claim sets the token aside and returns None. The worker reaches only its
    empty-claim branch, and that branch's build-up check is what pages it, on the leader only: a
    fenced claim on a node that no longer leads returns None too."""
    fetch = _fetch(store)
    head = await contract.captured(store, control="UR-W-OUTAGE", now=1.0)
    runner = contract.runner(store)
    sink = _BuildupSink()
    runner._alert_sink = sink
    runner._buildup_default = BuildupThreshold(max_oldest_seconds=60.0)
    if not leader:
        runner._coordinator.is_leader = lambda: False  # type: ignore[method-assign]
    reached: list[str] = []
    real_step = runner._process_response_item

    async def step(name: str, item: Any) -> Any:
        reached.append(item.id)
        return await real_step(name, item)

    runner._process_response_item = step  # type: ignore[method-assign]
    with contract.faulting_cipher(store) as fault:
        fault.every, fault.open_error = True, CipherUnavailableError("synthetic")
        task = asyncio.ensure_future(runner._response_worker(LOOP))
        try:
            with contextlib.suppress(TimeoutError):
                async with asyncio.timeout(4.0):
                    while not sink.buildup:
                        await asyncio.sleep(0.02)
        finally:
            runner._stop.set()
            runner._response_work.set()
            await asyncio.wait_for(task, timeout=5.0)
    # CONTROL: the claim set the token aside, so the step never ran and nothing was dead-lettered.
    assert reached == []
    assert (await contract.token_of(fetch, head))["status"] == OutboxStatus.PENDING.value
    assert not [e for e in await store.events_for(head) if e["event"] == "dead"]
    assert sink.buildup == ([(LOOP, 1)] if leader else []), sink.buildup


@pytest.mark.parametrize("leader", [True, False], ids=["leader", "not_leader"])
async def test_a_reply_lane_backlog_raises_the_buildup_alert_from_the_success_path(
    store: MessageStore, leader: bool
) -> None:
    """BACKLOG #5727: the response worker checks its lane after a handed-off token, as the router
    and transform workers check theirs, on the leader only. Two tokens captured at epoch 1.0:
    after the first hands off, the second is pending past the 60 s age."""
    fetch = _fetch(store)
    await contract.captured(store, control="UR-S-ONE", now=1.0)
    await contract.captured(store, control="UR-S-TWO", now=2.0)
    runner = contract.runner(store)
    sink = _BuildupSink()
    runner._alert_sink = sink
    runner._buildup_default = BuildupThreshold(max_oldest_seconds=60.0)
    if not leader:
        runner._coordinator.is_leader = lambda: False  # type: ignore[method-assign]
    task = asyncio.ensure_future(runner._response_worker(LOOP))
    try:
        async with asyncio.timeout(5.0):
            while len(await children(fetch)) < 2:
                await asyncio.sleep(0.02)
    finally:
        runner._stop.set()
        runner._response_work.set()
        await asyncio.wait_for(task, timeout=5.0)
    assert sink.buildup == ([(LOOP, 1)] if leader else []), sink.buildup


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
