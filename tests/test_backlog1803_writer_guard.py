# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #1803: the SQLite short-writer guard, and what it closes.

The defect and the guard's three exits are described once, in
``messagefoundry.store.store._writer_guard``'s docstring.

The CONTRACT tests drive :func:`_writer_guard` on a bare connection, so they prove the helper itself
and not whichever writer happens to use it. The STORE tests drive the real writers the census found
reachable on an ordinary path, each through a refusal it can really hit, then check the two things
the defect broke: nothing is left open, and the next writer that opens its own transaction succeeds
on the first try. The last one is the torn write, where a cipher failing between two statements used
to leave a partial claim for an unrelated writer to commit.
"""

from __future__ import annotations

import asyncio
import logging
import sqlite3
from pathlib import Path

import aiosqlite
import pytest

from messagefoundry.store.crypto import CipherError, IdentityCipher
from messagefoundry.store.store import (
    MessageStatus,
    MessageStore,
    OutboxStatus,
    Stage,
    UncommittedWriteError,
    _writer_guard,
)
from tests._webauthn_store_contract import _cred

# Bound on every handshake with a parked writer, so a wedged case fails as a timeout, not a hang.
WAIT = 5.0


class _Boom(Exception):
    """An ordinary failure raised after the block's first DML."""


async def _fresh(tmp_path: Path) -> aiosqlite.Connection:
    db = await aiosqlite.connect(str(tmp_path / "guard.db"))
    await db.execute("CREATE TABLE t (k TEXT PRIMARY KEY)")
    await db.commit()
    return db


async def _keys(db: aiosqlite.Connection) -> list[str]:
    cur = await db.execute("SELECT k FROM t ORDER BY k")
    return [row[0] for row in await cur.fetchall()]


# --- the guard's own contract --------------------------------------------------------------------


async def test_clean_exit_with_an_uncommitted_write_raises_and_rolls_back(tmp_path: Path) -> None:
    db = await _fresh(tmp_path)
    lock = asyncio.Lock()
    try:
        with pytest.raises(UncommittedWriteError, match="without committing"):
            async with _writer_guard(db, lock):
                await db.execute("INSERT INTO t VALUES ('forgot-to-commit')")
        assert not db.in_transaction, "the guard let a block leave its write open"
        assert not lock.locked()
        assert await _keys(db) == []
    finally:
        await db.close()


async def test_a_read_only_early_exit_passes_and_opens_nothing(tmp_path: Path) -> None:
    """The reason the guard is not ``_writer_txn``: a block that only read must exit for free. A
    guard that BEGINs would leave this exit holding an open, empty transaction and raise on it."""
    db = await _fresh(tmp_path)
    lock = asyncio.Lock()

    async def consume(key: str) -> bool:
        async with _writer_guard(db, lock):
            cur = await db.execute("SELECT 1 FROM t WHERE k=?", (key,))
            if await cur.fetchone() is None:
                return False  # the early exit: nothing written, nothing to commit
            await db.execute("DELETE FROM t WHERE k=?", (key,))
            await db.commit()
            return True

    try:
        assert await consume("absent") is False
        assert not db.in_transaction
        # ... and the committing path is untouched by the clean-exit check.
        await db.execute("INSERT INTO t VALUES ('present')")
        await db.commit()
        assert await consume("present") is True
        assert not db.in_transaction
        assert await _keys(db) == []
    finally:
        await db.close()


async def test_an_ordinary_failure_after_a_write_rolls_back_and_propagates(tmp_path: Path) -> None:
    db = await _fresh(tmp_path)
    lock = asyncio.Lock()
    try:
        with pytest.raises(_Boom):
            async with _writer_guard(db, lock):
                await db.execute("INSERT INTO t VALUES ('half')")
                raise _Boom("the second statement's cipher call failed")
        assert not db.in_transaction
        assert await _keys(db) == []
    finally:
        await db.close()


async def test_a_cancellation_after_a_write_rolls_back(tmp_path: Path) -> None:
    db = await _fresh(tmp_path)
    lock = asyncio.Lock()
    wrote = asyncio.Event()

    async def writer() -> None:
        async with _writer_guard(db, lock):
            await db.execute("INSERT INTO t VALUES ('cancelled')")
            wrote.set()
            await asyncio.Event().wait()  # parked mid-block until cancelled

    try:
        task = asyncio.create_task(writer())
        await asyncio.wait_for(wrote.wait(), WAIT)
        assert db.in_transaction  # the write really is open at the cancel point
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await asyncio.wait_for(task, WAIT)
        assert not db.in_transaction
        assert not lock.locked()
        assert await _keys(db) == []
    finally:
        await db.close()


async def test_a_cancel_during_the_clean_exit_rollback_wins(tmp_path: Path) -> None:
    """The clean-exit rollback goes through the same shared unwind as a failure, so a cancellation
    landing inside it is honoured, and the uncommitted-write error rides along as its cause."""
    db = await _fresh(tmp_path)
    lock = asyncio.Lock()
    real_rollback = db.rollback
    rollback_started = asyncio.Event()
    release = asyncio.Event()

    async def slow_rollback() -> None:
        rollback_started.set()
        await release.wait()  # held open until the test has delivered its cancel
        await real_rollback()

    db.rollback = slow_rollback  # type: ignore[method-assign]

    async def writer() -> None:
        async with _writer_guard(db, lock):
            await db.execute("INSERT INTO t VALUES ('forgot-to-commit')")

    try:
        task = asyncio.create_task(writer())
        await asyncio.wait_for(rollback_started.wait(), WAIT)
        task.cancel()
        release.set()
        with pytest.raises(asyncio.CancelledError) as caught:
            await asyncio.wait_for(task, WAIT)
        assert isinstance(caught.value.__cause__, UncommittedWriteError)
        assert not db.in_transaction
        assert not lock.locked()
        assert await _keys(db) == []
    finally:
        db.rollback = real_rollback  # type: ignore[method-assign]
        await db.close()


async def test_a_transaction_left_open_by_another_block_is_rolled_back_on_entry(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """Defence in depth. A transaction open when the guard takes the lock was abandoned by a block
    that already let go. The guard must neither commit it with this writer's work nor fail this
    writer for it: it logs at ERROR and rolls the stranger's work back."""
    db = await _fresh(tmp_path)
    lock = asyncio.Lock()
    try:
        await db.execute("INSERT INTO t VALUES ('stranger')")  # left open, as a leaking block would
        assert db.in_transaction
        with caplog.at_level(logging.ERROR, logger="messagefoundry.store.store"):
            async with _writer_guard(db, lock):
                await db.execute("INSERT INTO t VALUES ('mine')")
                await db.commit()
        assert await _keys(db) == ["mine"], "the stranger's write rode out on this writer's COMMIT"
        assert any("still open" in r.getMessage() for r in caplog.records), caplog.text

        # A read-only exit after a leak must not raise on the stranger's behalf either.
        await db.execute("INSERT INTO t VALUES ('stranger-2')")
        async with _writer_guard(db, lock):
            await db.execute("SELECT 1 FROM t")
        assert not db.in_transaction
        assert await _keys(db) == ["mine"]
    finally:
        await db.close()


# --- the writers the census found reachable on an ordinary path ----------------------------------


async def _store(tmp_path: Path, cipher: IdentityCipher | None = None) -> MessageStore:
    # A file database, so reads go through the pooled read connections and never mask the writer.
    return await MessageStore.open(str(tmp_path / "store.db"), cipher=cipher)


async def _assert_writer_clean(store: MessageStore, bystander: str) -> None:
    """The two things the defect broke, checked in the order it broke them."""
    assert not store._db.in_transaction, "the refused write left the writer inside a transaction"
    # A writer that opens its OWN transaction. With the refusal's transaction left open, its BEGIN
    # failed with "cannot start a transaction within a transaction".
    await store.delete_user(bystander)
    assert await store.get_user(bystander) is None


async def test_a_duplicate_passkey_label_leaves_no_open_transaction(tmp_path: Path) -> None:
    """BACKLOG #1804: two enrolments, or a double-submit, of one label for one user."""
    store = await _store(tmp_path)
    try:
        for uid in ("alice", "bystander"):
            await store.create_user(user_id=uid, username=uid, auth_provider="local", now=1_000.0)
        await store.add_webauthn_credential(_cred("alice", "laptop", id_hash="h1"))
        # The refusal still reaches the caller: auth/service.py renders it as "label in use".
        with pytest.raises(sqlite3.IntegrityError, match="webauthn_credentials.label"):
            await store.add_webauthn_credential(_cred("alice", "laptop", id_hash="h2"))
        await _assert_writer_clean(store, "bystander")
        creds = await store.list_webauthn_credentials("alice")
        assert [c.credential_id_hash for c in creds] == ["h1"]
    finally:
        await store.close()


async def test_a_duplicate_username_leaves_no_open_transaction(tmp_path: Path) -> None:
    """A double-submit of POST /users, or two admins racing, past the endpoint's pre-check."""
    store = await _store(tmp_path)
    try:
        for uid in ("alice", "bystander"):
            await store.create_user(user_id=uid, username=uid, auth_provider="local", now=1_000.0)
        with pytest.raises(sqlite3.IntegrityError, match="UNIQUE"):
            await store.create_user(
                user_id="alice-2", username="alice", auth_provider="local", now=2_000.0
            )
        await _assert_writer_clean(store, "bystander")
        assert await store.get_user("alice-2") is None
    finally:
        await store.close()


async def test_a_session_for_a_deleted_user_leaves_no_open_transaction(tmp_path: Path) -> None:
    """A login between authentication and session issue, racing an admin deleting the account."""
    store = await _store(tmp_path)
    try:
        for uid in ("alice", "bystander"):
            await store.create_user(user_id=uid, username=uid, auth_provider="local", now=1_000.0)
        await store.delete_user("alice")
        with pytest.raises(sqlite3.IntegrityError, match="FOREIGN KEY"):
            await store.create_session(token_hash="t" * 64, user_id="alice", expires_at=9e9)
        await _assert_writer_clean(store, "bystander")
    finally:
        await store.close()


class _FlakyTransit(IdentityCipher):
    """Stands in for a Vault Transit cipher whose encrypt round trip fails mid-claim."""

    fail = False

    def encrypt(self, plaintext: str, *, aad: bytes | None = None) -> str:
        if self.fail:
            raise CipherError("Transit encrypt failed (key='k'): ConnectError")
        return super().encrypt(plaintext, aad=aad)


async def test_a_cipher_failure_mid_claim_leaves_no_torn_write(tmp_path: Path) -> None:
    """``claim_next_fifo``'s already-delivered skip path writes two UPDATEs, then encrypts the
    delivered event. A Transit failure there used to leave both UPDATEs open, and the next unrelated
    short writer committed them: queue row DONE, no delivered event, message stuck ROUTED."""
    cipher = _FlakyTransit()
    store = await _store(tmp_path, cipher)
    db = store._db
    try:
        now = 1_000.0
        await db.execute(
            "INSERT INTO messages (id, channel_id, received_at, raw, status) VALUES (?,?,?,?,?)",
            ("m1", "IB", now, "MSH|x", MessageStatus.ROUTED.value),
        )
        await db.execute(
            "INSERT INTO queue (id, message_id, stage, channel_id, destination_name, payload,"
            " status, attempts, next_attempt_at, created_at, updated_at)"
            " VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (
                "q1",
                "m1",
                Stage.OUTBOUND.value,
                "IB",
                "OB",
                "body",
                OutboxStatus.PENDING.value,
                0,
                now - 1,
                now,
                now,
            ),
        )
        # The ledger row that sends the claim down the skip path: this row was already delivered.
        await db.execute(
            "INSERT INTO delivered_keys (delivery_key, outbox_id, message_id, destination_name,"
            " delivery_seq, delivered_at) VALUES (?,?,?,?,?,?)",
            ("dk1", "q1", "m1", "OB", 1, now),
        )
        await db.commit()
        await store.create_user(user_id="bystander", username="b", auth_provider="local")

        cipher.fail = True
        with pytest.raises(CipherError):
            await store.claim_next_fifo("OB", stage="outbound", now=now)
        cipher.fail = False
        assert not db.in_transaction, "the failed claim left its partial write open"

        # An unrelated SHORT writer takes the lock next and commits.
        await store.record_login_success("bystander")

        async def state() -> tuple[str, int, int, str]:
            cur = await db.execute("SELECT status, attempts FROM queue WHERE id='q1'")
            queue = await cur.fetchone()
            cur = await db.execute("SELECT COUNT(*) FROM message_events WHERE message_id='m1'")
            events = await cur.fetchone()
            cur = await db.execute("SELECT status FROM messages WHERE id='m1'")
            message = await cur.fetchone()
            assert queue is not None and events is not None and message is not None
            return queue[0], queue[1], events[0], message[0]

        # Nothing of the failed claim became durable: the row is still pending and unclaimed.
        assert await state() == (OutboxStatus.PENDING.value, 0, 0, MessageStatus.ROUTED.value)

        # And the claim re-runs to the complete, consistent outcome (at-least-once).
        assert await store.claim_next_fifo("OB", stage="outbound", now=now) is None
        status, attempts, events, message_status = await state()
        assert (status, attempts, events) == (OutboxStatus.DONE.value, 1, 1)
        assert message_status == MessageStatus.PROCESSED.value, message_status
    finally:
        await store.close()
