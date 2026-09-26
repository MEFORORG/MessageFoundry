# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A cancelled ``transform_handoff``, ``handoff`` or ``enqueue_ingress`` leaves nothing for the next
writer to commit.

BACKLOG #1630 measured three ways a cancellation inside a SQLite writer transaction lost work, back
when the store rolled back only on ``except Exception`` (``asyncio.CancelledError`` is a
``BaseException``). The writer connection stayed mid-transaction, and the next writer on that one
connection committed the half-body with its own work:

* a ``transform_handoff`` cancelled after one of two outbound rows was inserted delivered to one
  destination and finalized ``PROCESSED``;
* an ``enqueue_ingress`` cancelled between its two inserts left a phantom ``received`` message;
* on a keyed (AES-GCM) store, ``close()`` alone committed the half-body, because its first act is
  the invocation-bound settlement write.

The fix is :func:`messagefoundry.store.store._writer_txn`.
``tests/test_backlog1548_writer_txn_cancel_unwind.py`` covers ``route_handoff`` and
``ingress_handoff``. This file adds ``transform_handoff``, the fused ADR 0057 ``handoff`` and
``enqueue_ingress``, plus the keyed ``close()`` case. It reuses that file's ``_Trap``, cancel-point
names, fixtures and connection-clean probe rather than a second copy of any of them.

What this file does NOT cover includes at least: the group-commit arms of ``transform_handoff`` and
``enqueue_ingress`` (the fused ``handoff`` takes ``_writer_txn`` directly, so it has none); a second
cancellation landing inside the rollback; ``enqueue_ingress``'s ``attachment_refs`` incref path;
``transform_handoff``'s pass-through, ``SetMeta`` and declined branches; and the delivery-side
grouped writers.

Each failure arm reads the durable state through a SECOND, read-only ``sqlite3`` connection. That
connection sees only committed rows, so it cannot be fooled by the writer connection's own view of
its uncommitted work.

The keyed POSITIVE CONTROL at the end is load-bearing. In the keyed-close test nothing checks
``in_transaction`` before ``close()``, so the durable read is the only check, and it means something
only if ``close()``'s settlement really would commit an open transaction. The control shows it does.
The next-writer control documents the same mechanism for the probe the unkeyed tests run; there the
``in_transaction`` assertion fails first, so that probe is a second line rather than the only one.
"""

from __future__ import annotations

import asyncio
import functools
import sqlite3
from collections.abc import Callable, Coroutine, Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

import pytest

from messagefoundry.store.crypto import AesGcmCipher, generate_key, make_cipher
from messagefoundry.store.gcm_bound import GCM_RESERVE_BLOCK
from messagefoundry.store.store import MessageStatus, MessageStore, OutboxStatus, Stage
from tests.test_backlog1548_writer_txn_cancel_unwind import (
    ARMS,
    BEGIN,
    BODY,
    CH,
    COMMIT,
    RAW,
    WAIT,
    _assert_connection_clean,
    _Boom,
    _prepare,
    _route,
    _Trap,
)

# Two destinations with DIFFERENT bodies, so each outbound row is inserted inline and on its own
# statement. The row's measured case needs the cancel to land between those two inserts.
DELIVERIES = [
    ("OB_TEST_A", RAW.replace("MSG1", "OUTA")),
    ("OB_TEST_B", RAW.replace("MSG1", "OUTB")),
]
STATE_KEY = ("test_ns", "last_seen")

# ``_Trap``'s own points are ``begin`` (just after ``BEGIN``), ``body`` (just after the guarded
# ``DELETE FROM queue``) and ``commit`` (just before ``COMMIT``). ``enqueue_ingress`` issues no
# ``DELETE``, so it never reaches ``body``. This point is added here: just after the FIRST statement
# starting with a given prefix. For the two outbound handoffs that is the first outbound ``INSERT INTO
# queue``; for ``enqueue_ingress`` the ``INSERT INTO messages`` before its queue row. Both are the
# row's measured half-body states.
FIRST_INSERT = "first-insert"


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


@contextmanager
def _durable(path: Path) -> Iterator[sqlite3.Connection]:
    """A read-only connection the store does not own: it sees only committed rows."""
    con = sqlite3.connect(f"{path.as_uri()}?mode=ro", uri=True)
    try:
        con.row_factory = sqlite3.Row
        yield con
    finally:
        con.close()


def _one(con: sqlite3.Connection, sql: str, params: tuple[Any, ...] = ()) -> Any:
    row = con.execute(sql, params).fetchone()
    return None if row is None else row[0]


async def _fail(call: Callable[[], Coroutine[Any, Any, Any]], trap: _Trap, arm: str) -> None:
    """Drive ``call`` into the armed trap, then cancel it (cancel arm) or let it raise (control)."""
    if arm == "control":
        with pytest.raises(_Boom):
            await call()
        return
    task = asyncio.create_task(call())
    reached = asyncio.create_task(trap.reached.wait())
    done, _ = await asyncio.wait({task, reached}, timeout=WAIT, return_when=asyncio.FIRST_COMPLETED)
    if task in done:
        # It finished (or failed) before the trap: surface that, not a misleading timeout.
        reached.cancel()
        await task
        pytest.fail("the call completed without reaching the armed cancel point")
    if reached not in done:
        # Timed out. Cancel both so a stuck call cannot keep the writer lock and hang close().
        for pending in (task, reached):
            pending.cancel()
        await asyncio.gather(task, reached, return_exceptions=True)
        pytest.fail("the call never reached the armed cancel point")
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task


# --- transform_handoff (routed -> outbound) ------------------------------------------------------


async def _prepare_transform(store: MessageStore) -> tuple[str, str]:
    """One message routed to one handler, its routed row claimed and ready to transform."""
    mid, ingress_id = await _prepare(store)
    assert await _route(store, mid, ingress_id)
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


def _outbound_rows(con: sqlite3.Connection, mid: str) -> int:
    return int(
        _one(
            con,
            "SELECT COUNT(*) FROM queue WHERE stage=? AND message_id=?",
            (Stage.OUTBOUND.value, mid),
        )
    )


def _state_rows(con: sqlite3.Connection) -> int:
    return int(_one(con, "SELECT COUNT(*) FROM state WHERE namespace=? AND key=?", STATE_KEY))


def _assert_claim_survived(con: sqlite3.Connection, row_id: str) -> None:
    status = _one(con, "SELECT status FROM queue WHERE id=?", (row_id,))
    assert status is not None, "the failed handoff's guarded DELETE became durable -- work lost"
    assert status == OutboxStatus.INFLIGHT.value


def _assert_transform_not_applied(path: Path, mid: str, routed_id: str) -> None:
    """Nothing of the failed transform is durable, and its claimed routed row survives INFLIGHT.

    The message status is deliberately not checked: with outbound rows pending the finalizer returns
    early, so ``ROUTED`` would hold even if the half-body had leaked and it discriminates nothing."""
    with _durable(path) as con:
        _assert_claim_survived(con, routed_id)
        assert _outbound_rows(con, mid) == 0, "an outbound row of the failed transform is durable"
        assert _state_rows(con) == 0, "the failed transform's state write became durable"


async def _assert_transform_recovers(store: MessageStore, path: Path, mid: str) -> None:
    """The routed row re-pends and the SAME transform re-runs, writing every outbound row and the
    state value durably."""
    assert await store.reset_stale_inflight(stage=Stage.ROUTED.value) >= 1
    again = await store.claim_next_fifo(CH, stage=Stage.ROUTED.value)
    assert again is not None and again.message_id == mid
    assert await _transform(store, mid, again.id)
    with _durable(path) as con:
        assert _outbound_rows(con, mid) == len(DELIVERIES)
        assert _state_rows(con) == 1
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


# --- handoff (the fused ingress -> outbound fast path, ADR 0057) ---------------------------------


async def _fused(store: MessageStore, mid: str, ingress_id: str) -> bool:
    return bool(
        await store.handoff(
            ingress_id=ingress_id,
            message_id=mid,
            channel_id=CH,
            deliveries=DELIVERIES,
            disposition=MessageStatus.ROUTED,
        )
    )


@pytest.mark.parametrize("arm", ARMS)
@pytest.mark.parametrize("point", [BEGIN, BODY, FIRST_INSERT, COMMIT])
async def test_fused_handoff_unwinds(tmp_path: Path, point: str, arm: str) -> None:
    """The fused ``handoff`` has the same half-body shape as ``transform_handoff``: a guarded
    ``DELETE``, then one outbound row per delivery. It also writes the disposition itself, so the
    status check here does discriminate: at ``commit`` the ``UPDATE`` to ``ROUTED`` has run."""
    path = tmp_path / f"fused-{point}-{arm}.db"
    store = await MessageStore.open(path)
    try:
        mid, ingress_id = await _prepare(store)
        trap = _InsertTrap(store._db, "INSERT INTO queue")
        trap.arm(point, raise_instead=arm == "control")

        await _fail(lambda: _fused(store, mid, ingress_id), trap, arm)

        await _assert_connection_clean(store, probe=f"fused-{point}-{arm}")
        with _durable(path) as con:
            _assert_claim_survived(con, ingress_id)
            assert _outbound_rows(con, mid) == 0, "an outbound row of the failed handoff is durable"
            status = _one(con, "SELECT status FROM messages WHERE id=?", (mid,))
            assert status == MessageStatus.RECEIVED.value, "the disposition of a failed handoff"

        assert await store.reset_stale_inflight(stage=Stage.INGRESS.value) >= 1
        again = await store.claim_next_fifo(CH, stage=Stage.INGRESS.value)
        assert again is not None and again.message_id == mid
        assert await _fused(store, mid, again.id)
        with _durable(path) as con:
            assert _outbound_rows(con, mid) == len(DELIVERIES)
    finally:
        await store.close()


# --- enqueue_ingress (the ACK-on-receipt write) --------------------------------------------------


async def _ingress(store: MessageStore) -> str:
    return await store.enqueue_ingress(channel_id=CH, raw=RAW)


def _assert_nothing_received(path: Path) -> None:
    """No phantom message: the failed ingress left no messages, queue or event row behind."""
    with _durable(path) as con:
        assert _one(con, "SELECT COUNT(*) FROM messages") == 0, "a phantom received message"
        assert _one(con, "SELECT COUNT(*) FROM queue") == 0
        assert _one(con, "SELECT COUNT(*) FROM message_events") == 0


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
        with _durable(path) as con:
            assert _one(con, "SELECT COUNT(*) FROM messages WHERE id=?", (mid,)) == 1
        assert (await store.pending_depth(CH, stage=Stage.INGRESS.value))[0] == 1
    finally:
        await store.close()


# --- a keyed store closing straight after a cancelled handoff ------------------------------------


async def _open_keyed(path: Path, key: str) -> MessageStore:
    cipher = make_cipher(key)
    assert isinstance(cipher, AesGcmCipher)
    return await MessageStore.open(path, cipher=cipher, audit_mac_key=cipher.audit_mac_key())


def _persisted_invocations(path: Path) -> int:
    with _durable(path) as con:
        rows = con.execute("SELECT invocations FROM cipher_meta").fetchall()
    assert len(rows) == 1, "expected one key's invocation row"
    return int(rows[0][0])


@pytest.mark.parametrize("handoff", ["route", "fused", "transform", "ingress"])
async def test_keyed_close_after_a_cancelled_handoff_commits_nothing(
    tmp_path: Path, handoff: str
) -> None:
    """On a keyed store ``close()`` writes before it closes: it settles the AES-GCM invocation bound
    on the writer connection. Straight after a cancelled handoff, that settlement must find no open
    transaction to commit.

    The settlement is shown to have really committed: the persisted total drops below the reserved
    block. So a clean result here is not a probe that never wrote."""
    path = tmp_path / f"keyed-{handoff}.db"
    key = generate_key()
    store = await _open_keyed(path, key)
    mid = row_id = ""
    trap: _Trap
    call: Callable[[], Coroutine[Any, Any, Any]]
    closed = False
    try:
        if handoff == "route":
            mid, row_id = await _prepare(store)
            trap = _Trap(store._db)
            trap.arm(COMMIT)  # the whole body written: DELETE, routed row, disposition
            call = functools.partial(_route, store, mid, row_id)
        elif handoff == "fused":
            mid, row_id = await _prepare(store)
            trap = _InsertTrap(store._db, "INSERT INTO queue")
            trap.arm(FIRST_INSERT)  # the DELETE and one of two outbound rows written
            call = functools.partial(_fused, store, mid, row_id)
        elif handoff == "transform":
            mid, row_id = await _prepare_transform(store)
            trap = _InsertTrap(store._db, "INSERT INTO queue")
            trap.arm(FIRST_INSERT)  # one of two outbound rows written
            call = functools.partial(_transform, store, mid, row_id)
        else:
            trap = _InsertTrap(store._db, "INSERT INTO messages")
            trap.arm(FIRST_INSERT)  # the message row written, its ingress row not yet
            call = functools.partial(_ingress, store)

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

    if handoff in ("route", "fused"):
        with _durable(path) as con:
            _assert_claim_survived(con, row_id)
            produced = _one(
                con, "SELECT COUNT(*) FROM queue WHERE message_id=? AND id<>?", (mid, row_id)
            )
            assert produced == 0, "close() committed a row the cancelled handoff produced"
            status = _one(con, "SELECT status FROM messages WHERE id=?", (mid,))
            assert status == MessageStatus.RECEIVED.value
    elif handoff == "transform":
        _assert_transform_not_applied(path, mid, row_id)
    else:
        _assert_nothing_received(path)

    # Reopen under the same key: the surviving rows still decrypt, and the interrupted work re-runs.
    store = await _open_keyed(path, key)
    try:
        if handoff in ("route", "fused"):
            assert await store.reset_stale_inflight(stage=Stage.INGRESS.value) >= 1
            again = await store.claim_next_fifo(CH, stage=Stage.INGRESS.value)
            assert again is not None and again.message_id == mid
            assert await (_route if handoff == "route" else _fused)(store, mid, again.id)
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
    probe stopped writing, this test fails and the clean results above stop meaning anything.

    Both probes depend on a writer that takes the lock and commits with NO ``BEGIN`` of its own:
    ``record_connection_event`` and, inside ``close()``, ``add_cipher_invocations``. If either is
    moved onto ``_writer_txn`` (ADR 0159's deferred work), its ``BEGIN`` raises on the open
    transaction and this control goes red. That means the PROBE needs replacing with another
    no-``BEGIN`` writer, not that the engine regressed."""
    path = tmp_path / f"control-{probe}.db"
    if probe == "keyed-close":
        store = await _open_keyed(path, generate_key())
    else:
        store = await MessageStore.open(path)
    closed = False
    try:
        _mid, ingress_id = await _prepare(store)
        # A route handoff's first statement, with no unwind after it.
        await store._db.execute("BEGIN")
        await store._db.execute("DELETE FROM queue WHERE id=?", (ingress_id,))
        assert store._db.in_transaction
        with _durable(path) as con:
            assert _one(con, "SELECT COUNT(*) FROM queue WHERE id=?", (ingress_id,)) == 1

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

    with _durable(path) as con:
        remaining = _one(con, "SELECT COUNT(*) FROM queue WHERE id=?", (ingress_id,))
    assert remaining == 0, f"the {probe} probe did not commit the open transaction"
