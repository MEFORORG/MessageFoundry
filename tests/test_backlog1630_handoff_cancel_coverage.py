# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A cancelled ``transform_handoff`` or ``enqueue_ingress`` leaves nothing for the next writer to commit.

BACKLOG #1630 measured three ways a cancellation inside a SQLite writer transaction lost work, back
when the store rolled back only on ``except Exception`` (``asyncio.CancelledError`` is a
``BaseException``). The writer connection stayed mid-transaction, and the next writer on that one
connection committed the half-body with its own work:

* a ``transform_handoff`` cancelled after one of two outbound rows was inserted delivered to one
  destination and finalized ``PROCESSED``;
* an ``enqueue_ingress`` cancelled between its two inserts left a phantom ``received`` message;
* on a keyed (AES-GCM) store, ``close()`` alone committed the half-body, because its first act is
  the invocation-bound settlement write.

The fix is :func:`messagefoundry.store.store._writer_txn`, which every grouped writer's inline path
takes. ``tests/test_backlog1548_writer_txn_cancel_unwind.py`` covers ``route_handoff`` and
``ingress_handoff``. This file adds the two handoffs that file does not drive, and the keyed
``close()`` case. It reuses that file's ``_Trap`` and its connection-clean probe rather than a second
copy of either.

Each failure arm reads the durable state through a SECOND, independent ``sqlite3`` connection. That
connection sees only committed rows, so it cannot be fooled by the writer connection's own view of
its uncommitted work.

The POSITIVE CONTROLS at the end matter. Both probes this file relies on, the next short writer and
``close()``'s settlement, are shown to commit a transaction deliberately left open. Without that, a
clean result could mean the probe never wrote at all.
"""

from __future__ import annotations

import asyncio
import sqlite3
from collections.abc import Callable, Coroutine
from pathlib import Path
from typing import Any

import pytest

from messagefoundry.store.crypto import AesGcmCipher, generate_key, make_cipher
from messagefoundry.store.gcm_bound import GCM_RESERVE_BLOCK
from messagefoundry.store.store import MessageStatus, MessageStore, OutboxStatus, Stage
from tests.test_backlog1548_writer_txn_cancel_unwind import (
    _assert_connection_clean,
    _Boom,
    _Trap,
)

# Synthetic data only.
RAW = "MSH|^~\\&|S|F|R|RF|20260101||ADT^A01|MSG1|P|2.5.1\rPID|1||100||DOE^JANE\r"
CH = "IB_TEST_ADT"
# Two destinations with DIFFERENT bodies, so each outbound row is inserted inline and on its own
# statement. The row's measured case needs the cancel to land between those two inserts.
DELIVERIES = [
    ("OB_TEST_A", RAW.replace("MSG1", "OUTA")),
    ("OB_TEST_B", RAW.replace("MSG1", "OUTB")),
]
STATE_KEY = ("test_ns", "last_seen")
WAIT = 5.0

# ``_Trap``'s own points: just after ``BEGIN``, just after the guarded ``DELETE FROM queue``, and
# just before ``COMMIT``. ``enqueue_ingress`` issues no ``DELETE``, so it never reaches ``body``.
BEGIN, BODY, COMMIT = "begin", "body", "commit"
# Added here: just after the FIRST statement starting with a given prefix. For ``transform_handoff``
# that is the first outbound ``INSERT INTO queue``; for ``enqueue_ingress`` the ``INSERT INTO
# messages`` that precedes its queue row. Both are the row's measured half-body states.
FIRST_INSERT = "first-insert"
ARMS = ["cancel", "control"]


class _InsertTrap(_Trap):
    """``_Trap`` plus one point: trip after the first statement starting with ``prefix``."""

    def __init__(self, db: Any, prefix: str) -> None:
        super().__init__(db)
        self._prefix = prefix

    async def _execute(self, sql: Any, *args: Any, **kwargs: Any) -> Any:
        cur = await super()._execute(sql, *args, **kwargs)
        if self.point == FIRST_INSERT and str(sql).startswith(self._prefix):
            await self._trip()
        return cur


def _durable(path: Path, sql: str, params: tuple[Any, ...] = ()) -> list[sqlite3.Row]:
    """Read committed state through a connection the store does not own."""
    con = sqlite3.connect(str(path))
    try:
        con.row_factory = sqlite3.Row
        return list(con.execute(sql, params).fetchall())
    finally:
        con.close()


def _count(path: Path, sql: str, params: tuple[Any, ...] = ()) -> int:
    return int(_durable(path, sql, params)[0][0])


async def _fail(call: Callable[[], Coroutine[Any, Any, Any]], trap: _Trap, arm: str) -> None:
    """Drive ``call`` into the armed trap, then cancel it (cancel arm) or let it raise (control)."""
    if arm == "cancel":
        task = asyncio.create_task(call())
        await asyncio.wait_for(trap.reached.wait(), WAIT)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
    else:
        with pytest.raises(_Boom):
            await call()


# --- transform_handoff (routed -> outbound) ------------------------------------------------------


async def _prepare_transform(store: MessageStore) -> tuple[str, str]:
    """One message routed to one handler, its routed row claimed and ready to transform."""
    mid = await store.enqueue_ingress(channel_id=CH, raw=RAW)
    ingress = await store.claim_next_fifo(CH, stage=Stage.INGRESS.value)
    assert ingress is not None
    assert await store.route_handoff(
        ingress_id=ingress.id,
        message_id=mid,
        channel_id=CH,
        handlers=[("h", RAW)],
        disposition=MessageStatus.ROUTED,
    )
    routed = await store.claim_next_fifo(CH, stage=Stage.ROUTED.value)
    assert routed is not None and routed.message_id == mid
    return mid, routed.id


async def _transform(store: MessageStore, mid: str, routed_id: str) -> bool:
    return bool(
        await store.transform_handoff(
            routed_id=routed_id,
            message_id=mid,
            channel_id=CH,
            deliveries=DELIVERIES,
            state_ops=[(*STATE_KEY, "v1")],
        )
    )


def _assert_transform_not_applied(path: Path, mid: str, routed_id: str) -> None:
    """Nothing of the failed transform is durable, and its claimed routed row survives INFLIGHT."""
    rows = _durable(path, "SELECT status FROM queue WHERE id=?", (routed_id,))
    assert rows, "the failed transform's guarded DELETE became durable -- work lost"
    assert rows[0]["status"] == OutboxStatus.INFLIGHT.value
    outbound = _count(
        path,
        "SELECT COUNT(*) FROM queue WHERE stage=? AND message_id=?",
        (Stage.OUTBOUND.value, mid),
    )
    assert outbound == 0, "an outbound row from the failed transform became durable"
    state = _count(path, "SELECT COUNT(*) FROM state WHERE namespace=? AND key=?", STATE_KEY)
    assert state == 0, "the failed transform's state write became durable"
    status = _durable(path, "SELECT status FROM messages WHERE id=?", (mid,))[0]["status"]
    assert status == MessageStatus.ROUTED.value, "the message finalized on an uncommitted handoff"


async def _assert_transform_recovers(store: MessageStore, path: Path, mid: str) -> None:
    """The routed row re-pends and the SAME transform re-runs to a full, finalized result."""
    assert await store.reset_stale_inflight(stage=Stage.ROUTED.value) >= 1
    again = await store.claim_next_fifo(CH, stage=Stage.ROUTED.value)
    assert again is not None and again.message_id == mid
    assert await _transform(store, mid, again.id)
    outbound = _count(
        path,
        "SELECT COUNT(*) FROM queue WHERE stage=? AND message_id=?",
        (Stage.OUTBOUND.value, mid),
    )
    assert outbound == len(DELIVERIES)
    assert store._state_cache[STATE_KEY] == "v1"


@pytest.mark.parametrize("arm", ARMS)
@pytest.mark.parametrize("point", [BEGIN, BODY, FIRST_INSERT, COMMIT])
async def test_transform_handoff_unwinds(tmp_path: Path, point: str, arm: str) -> None:
    """A cancellation at any cancel point inside ``transform_handoff`` unwinds its transaction, and
    an ordinary exception at the same await does the same. ``first-insert`` is the row's measured
    case: one of two outbound rows written, the other not."""
    path = tmp_path / f"transform-{point}-{arm}.db"
    store = await MessageStore.open(path)
    try:
        mid, routed_id = await _prepare_transform(store)
        trap = _InsertTrap(store._db, "INSERT INTO queue")
        trap.arm(point, raise_instead=arm == "control")

        await _fail(lambda: _transform(store, mid, routed_id), trap, arm)

        # The cache publish runs only after a commit, so a failed handoff must not have run it.
        assert STATE_KEY not in store._state_cache
        # One further write on the same connection. It issues no BEGIN, so it would carry an open
        # transaction's half-body with it.
        await _assert_connection_clean(store, probe=f"transform-{point}-{arm}")
        _assert_transform_not_applied(path, mid, routed_id)
        await _assert_transform_recovers(store, path, mid)
    finally:
        await store.close()


# --- enqueue_ingress (the ACK-on-receipt write) --------------------------------------------------


async def _ingress(store: MessageStore) -> str:
    return await store.enqueue_ingress(channel_id=CH, raw=RAW)


def _assert_nothing_received(path: Path) -> None:
    """No phantom message: the failed ingress left no messages, queue or event row behind."""
    assert _count(path, "SELECT COUNT(*) FROM messages") == 0, "a phantom received message"
    assert _count(path, "SELECT COUNT(*) FROM queue") == 0
    assert _count(path, "SELECT COUNT(*) FROM message_events") == 0


@pytest.mark.parametrize("arm", ARMS)
@pytest.mark.parametrize("point", [BEGIN, FIRST_INSERT, COMMIT])
async def test_enqueue_ingress_unwinds(tmp_path: Path, point: str, arm: str) -> None:
    """A cancellation at any cancel point inside ``enqueue_ingress`` unwinds its transaction, and an
    ordinary exception at the same await does the same. ``first-insert`` is the row's measured case:
    the message row written, its ingress queue row not yet."""
    path = tmp_path / f"ingress-{point}-{arm}.db"
    store = await MessageStore.open(path)
    try:
        trap = _InsertTrap(store._db, "INSERT INTO messages")
        trap.arm(point, raise_instead=arm == "control")

        await _fail(lambda: _ingress(store), trap, arm)

        await _assert_connection_clean(store, probe=f"ingress-{point}-{arm}")
        _assert_nothing_received(path)

        # Recovery is the sender's resend, since no ACK went out. It lands whole.
        mid = await _ingress(store)
        assert _count(path, "SELECT COUNT(*) FROM messages WHERE id=?", (mid,)) == 1
        assert (await store.pending_depth(CH, stage=Stage.INGRESS.value))[0] == 1
    finally:
        await store.close()


# --- a keyed store closing straight after a cancelled handoff ------------------------------------


async def _open_keyed(path: Path, key: str) -> MessageStore:
    cipher = make_cipher(key)
    assert isinstance(cipher, AesGcmCipher)
    return await MessageStore.open(path, cipher=cipher, audit_mac_key=cipher.audit_mac_key())


def _persisted_invocations(path: Path) -> int:
    rows = _durable(path, "SELECT invocations FROM cipher_meta")
    assert len(rows) == 1, "expected one key's invocation row"
    return int(rows[0]["invocations"])


async def _prepare_route(store: MessageStore) -> tuple[str, str]:
    mid = await store.enqueue_ingress(channel_id=CH, raw=RAW)
    item = await store.claim_next_fifo(CH, stage=Stage.INGRESS.value)
    assert item is not None
    return mid, item.id


async def _route(store: MessageStore, mid: str, ingress_id: str) -> bool:
    return bool(
        await store.route_handoff(
            ingress_id=ingress_id,
            message_id=mid,
            channel_id=CH,
            handlers=[("h", RAW)],
            disposition=MessageStatus.ROUTED,
        )
    )


@pytest.mark.parametrize("handoff", ["route", "transform", "ingress"])
async def test_keyed_close_after_a_cancelled_handoff_commits_nothing(
    tmp_path: Path, handoff: str
) -> None:
    """On a keyed store ``close()`` writes before it closes: it settles the AES-GCM invocation bound
    on the writer connection. Straight after a cancelled handoff, that settlement must find no open
    transaction to commit.

    The settlement is shown to have really committed: the persisted total drops from the reserved
    block to the actual spend. So a clean result here is not a probe that never wrote."""
    path = tmp_path / f"keyed-{handoff}.db"
    key = generate_key()
    store = await _open_keyed(path, key)
    mid = row_id = ""
    trap: _Trap
    call: Callable[[], Coroutine[Any, Any, Any]]
    closed = False
    try:
        if handoff == "route":
            mid, row_id = await _prepare_route(store)
            trap = _Trap(store._db)
            trap.arm(BODY)  # after the guarded ingress DELETE, before any routed row
            call = lambda: _route(store, mid, row_id)  # noqa: E731
        elif handoff == "transform":
            mid, row_id = await _prepare_transform(store)
            trap = _InsertTrap(store._db, "INSERT INTO queue")
            trap.arm(FIRST_INSERT)  # one of two outbound rows written
            call = lambda: _transform(store, mid, row_id)  # noqa: E731
        else:
            trap = _InsertTrap(store._db, "INSERT INTO messages")
            trap.arm(FIRST_INSERT)  # the message row written, its ingress row not yet
            call = lambda: _ingress(store)  # noqa: E731

        reserved = _persisted_invocations(path)
        assert reserved >= GCM_RESERVE_BLOCK, "the open did not reserve a block to settle"

        await _fail(call, trap, "cancel")
        await store.close()
        closed = True
    finally:
        if not closed:
            await store.close()

    settled = _persisted_invocations(path)
    assert settled < reserved, "close() did not settle, so this proves nothing about its write"

    if handoff == "route":
        rows = _durable(path, "SELECT status FROM queue WHERE id=?", (row_id,))
        assert rows, "close() committed the cancelled route's guarded DELETE -- work lost"
        assert rows[0]["status"] == OutboxStatus.INFLIGHT.value
        routed = _count(path, "SELECT COUNT(*) FROM queue WHERE stage=?", (Stage.ROUTED.value,))
        assert routed == 0
        status = _durable(path, "SELECT status FROM messages WHERE id=?", (mid,))[0]["status"]
        assert status == MessageStatus.RECEIVED.value
    elif handoff == "transform":
        _assert_transform_not_applied(path, mid, row_id)
    else:
        _assert_nothing_received(path)

    # Reopen under the same key: the surviving rows still decrypt, and the interrupted work re-runs.
    store = await _open_keyed(path, key)
    try:
        if handoff == "route":
            assert await store.reset_stale_inflight(stage=Stage.INGRESS.value) >= 1
            again = await store.claim_next_fifo(CH, stage=Stage.INGRESS.value)
            assert again is not None and again.message_id == mid
            assert await _route(store, mid, again.id)
            msg = await store.get_message(mid)
            assert msg is not None and msg["status"] == MessageStatus.ROUTED.value
        elif handoff == "transform":
            await _assert_transform_recovers(store, path, mid)
        else:
            mid = await _ingress(store)
            msg = await store.get_message(mid)
            assert msg is not None and msg["status"] == MessageStatus.RECEIVED.value
    finally:
        await store.close()


# --- positive controls: each probe really does commit an open transaction ------------------------


@pytest.mark.parametrize("probe", ["next-writer", "keyed-close"])
async def test_probe_commits_a_transaction_left_open(tmp_path: Path, probe: str) -> None:
    """Leave a transaction open by hand, the way an ``except Exception`` unwind used to, and show
    each probe above makes its half-body durable. This is the defect the tests above rule out; if a
    probe stopped writing, this test fails and the clean results above stop meaning anything."""
    path = tmp_path / f"control-{probe}.db"
    if probe == "keyed-close":
        store = await _open_keyed(path, generate_key())
    else:
        store = await MessageStore.open(path)
    closed = False
    try:
        _mid, ingress_id = await _prepare_route(store)
        # A route handoff's first statement, with no unwind after it.
        await store._db.execute("BEGIN")
        await store._db.execute("DELETE FROM queue WHERE id=?", (ingress_id,))
        assert store._db.in_transaction
        assert _count(path, "SELECT COUNT(*) FROM queue WHERE id=?", (ingress_id,)) == 1

        if probe == "next-writer":
            await store.record_connection_event(
                connection="control", transport="mllp", direction="inbound", kind="probe"
            )
        else:
            await store.close()
            closed = True
    finally:
        if not closed:
            await store.close()

    assert _count(path, "SELECT COUNT(*) FROM queue WHERE id=?", (ingress_id,)) == 0, (
        f"the {probe} probe did not commit the open transaction, so it cannot detect one"
    )
