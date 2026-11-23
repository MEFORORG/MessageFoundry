# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #3929: how SQL Server message-event statements use the Transit pool.

Under a cipher that blocks on I/O, :func:`~messagefoundry.store.row_seal.cipher_call` runs each
call on the bounded Transit pool. Two rules keep that from costing availability:

* a blank event ``detail`` has nothing to encrypt, so its statement makes no pool call, and a
  shut-down pool cannot roll back an event write that needs no cipher;
* in the transactions tested below, the message-event statement, and a startup sweep's sealed
  ``last_error``, are built before the per-message finalize applock. The lock is transaction-owned,
  so a build after it would hold it in the pool's queue, where a sibling finalizer times out.

That second rule does not cover every seal under the lock. At least ``complete_with_response``
still seals the reply body, detail, headers and re-ingress reference after taking the lock, since
each cell's associated data, or the reference's own text, holds the response sequence read under
it; ``claim_fifo_heads`` builds an idempotent-skip event after an earlier head's finalize; and an
audit append seals its MAC under the locks ``cancel_queued`` takes.

The startup sweeps read their orphans with no lock, so the last tests also pin that a sweep's DEAD
update touches only a row still in a status its read selected (Lander hold 7091043913).

Driven offline, against the recording cursors of :mod:`tests.adr0075_batch_harness`, with a stub
cipher that says it blocks on I/O.
"""

from __future__ import annotations

import threading
from typing import Any

import pytest

from messagefoundry.store import MessageStatus
from messagefoundry.store import sqlserver as ss
from messagefoundry.store.crypto import IdentityCipher
from messagefoundry.store.row_seal import cipher_call
from tests import adr0075_batch_harness as h


class _BlockingCipher(IdentityCipher):
    """An identity cipher that says it blocks on I/O, and records each encrypt: its thread, its
    associated data, and whether the cursor had already taken a finalize applock."""

    blocks_on_io = True

    def __init__(self) -> None:
        self.cursor: Any = None
        self.sealed: list[tuple[int, bytes | None, bool]] = []

    def encrypt(self, plaintext: str, *, aad: bytes | None = None) -> str:
        self.sealed.append((threading.get_ident(), aad, _finalize_lock_taken(self.cursor)))
        return super().encrypt(plaintext, aad=aad)


def _statements(cursor: Any) -> list[tuple[str, tuple[Any, ...]]]:
    # The batched recorder keeps the logical statements apart from its round trips.
    return list(getattr(cursor, "logical", None) or cursor.calls)


def _finalize_lock_taken(cursor: Any) -> bool:
    if cursor is None:
        return False
    return any(
        "sp_getapplock" in sql and any(str(p).startswith("mefor:finalize:") for p in params)
        for sql, params in _statements(cursor)
    )


def _counting_cipher_call(monkeypatch: pytest.MonkeyPatch) -> list[object]:
    """Count the store's cipher_call calls, each still made for real."""
    made: list[object] = []

    async def counted(cipher: object, call: Any, *args: Any, **kwargs: Any) -> Any:
        made.append(call)
        return await cipher_call(cipher, call, *args, **kwargs)

    monkeypatch.setattr(ss, "cipher_call", counted)
    return made


@pytest.mark.parametrize("detail", [None, ""])
async def test_a_blank_event_detail_makes_no_pool_call(
    monkeypatch: pytest.MonkeyPatch, detail: str | None
) -> None:
    store = h.bare_store()
    store._cipher = _BlockingCipher()
    made = _counting_cipher_call(monkeypatch)
    cur = h.AsyncRecCursor()
    await store._event(cur, "m-1", "dead", None, detail, 1.0)
    assert made == [], "a blank detail has nothing to encrypt, so its statement needs no pool call"
    assert [sql for sql, _ in cur.calls] == [ss._SQL_INSERT_EVENT]


async def test_a_detail_is_encrypted_on_the_pool(monkeypatch: pytest.MonkeyPatch) -> None:
    """Control: the same write with a detail does reach the pool, so the test above can fail."""
    store = h.bare_store()
    cipher = _BlockingCipher()
    store._cipher = cipher
    made = _counting_cipher_call(monkeypatch)
    cur = h.AsyncRecCursor()
    await store._event(cur, "m-1", "dead", None, "synthetic detail", 1.0)
    assert len(made) == 1
    assert [sql for sql, _ in cur.calls] == [ss._SQL_INSERT_EVENT]
    assert cipher.sealed and cipher.sealed[0][0] != threading.get_ident()


# --- the finalize applock never waits on the pool -----------------------------------------------


def _event_aad(aad: bytes | None) -> bool:
    return aad is not None and b"message_events" in aad


class _OrphanCursor(h.AsyncRecCursor):
    """Answers a startup sweep's orphan SELECT with two rows no registry names, and models the
    queue rows' status for its ``UPDATE ... OUTPUT inserted.id WHERE id=? [AND status IN (?, ?)]``.

    ``at_lock`` runs once, when the first applock is taken: after the sweep read and sealed its rows,
    before it writes, which is where another writer can move a row."""

    def __init__(self, at_lock: Any = None, names: tuple[Any, Any] = ("GONE_A", "GONE_B")) -> None:
        super().__init__()
        self.status: dict[str, str] = {"q-1": "pending", "q-2": "pending"}
        self.names = names
        self.at_lock = at_lock
        self._matched: list[tuple[str]] = []

    async def execute(self, sql: str, params: Any = ()) -> None:
        await super().execute(sql, params)
        if "sp_getapplock" in sql and self.at_lock is not None:
            self.at_lock(self.status)
            self.at_lock = None
        if sql.startswith("UPDATE queue SET status=?") and " OUTPUT inserted.id" in sql:
            row_id = params[4]
            allowed = params[5:7] if " AND status IN (?, ?)" in sql else None
            current = self.status.get(row_id)
            hit = current is not None and (allowed is None or current in allowed)
            if hit:
                self.status[row_id] = params[0]
            self._matched = [(row_id,)] if hit else []

    async def fetchall(self) -> Any:
        if self._last.startswith("SELECT id, message_id,"):
            return [("q-1", "m-1", self.names[0]), ("q-2", "m-2", self.names[1])]
        if self._last.startswith("UPDATE queue SET status=?"):
            return self._matched
        return await super().fetchall()


class _CompleteCursor(h.AsyncRecCursor):
    """Answers complete_with_response's leading row read and its response sequence read."""

    async def fetchone(self) -> Any:
        if "FROM queue WITH (UPDLOCK, ROWLOCK)" in self._last:
            return ("m-1", "OB_DEST", "H1", 1, "inflight")
        if "MAX(response_seq)" in self._last or "SELECT COUNT(*) FROM delivered_keys" in self._last:
            return (1,)
        return await super().fetchone()


_SWEEP: dict[str, Any] = {"valid_names": {"KEPT"}, "now": 100.0}

#: method, batched, cursor class (None for the plain recorder), keyword arguments.
_CASES: dict[str, tuple[str, bool, type[h.AsyncRecCursor] | None, dict[str, Any]]] = {
    "handoff": (
        "handoff",
        False,
        None,
        {
            "ingress_id": "ing-1",
            "message_id": "m-1",
            "channel_id": "IB",
            "deliveries": [("OB", "p1")],
            "disposition": MessageStatus.ROUTED,
            "now": 100.0,
        },
    ),
    "route_handoff": ("route_handoff", False, None, h.ROUTE_KWARGS),
    "route_handoff_batched": ("route_handoff", True, None, h.ROUTE_KWARGS),
    "dead_letter_missing_handlers": ("dead_letter_missing_handlers", False, _OrphanCursor, _SWEEP),
    "dead_letter_missing_inbounds": ("dead_letter_missing_inbounds", False, _OrphanCursor, _SWEEP),
    "dead_letter_missing_destinations": (
        "dead_letter_missing_destinations",
        False,
        _OrphanCursor,
        _SWEEP,
    ),
    "complete_with_response": (
        "complete_with_response",
        False,
        _CompleteCursor,
        {"outbox_id": "ob-1", "body": "synthetic reply", "outcome": "AA", "now": 100.0},
    ),
}


@pytest.mark.parametrize("case", sorted(_CASES))
async def test_no_event_statement_is_built_under_a_finalize_applock(case: str) -> None:
    """A statement built on the Transit pool is built before the finalize applock is taken. The
    lock is transaction-owned and held to the commit, so a build after it would hold it through the
    pool's queue, and a sibling finalizer would time out on it (BACKLOG #3929)."""
    method, batched, cursor_cls, kwargs = _CASES[case]
    store = h.bare_store(batch=batched)
    store._leader_epoch = None
    cipher = _BlockingCipher()
    store._cipher = cipher
    cur: Any = h.BatchRecCursor() if batched else (cursor_cls or h.AsyncRecCursor)()
    cipher.cursor = cur
    await h.drive_async(store, method, cursor=cur, conn=h.RecConn(), **kwargs)
    assert _finalize_lock_taken(cur), "the case never took a finalize applock; it proves nothing"
    events = [held for _thread, aad, held in cipher.sealed if _event_aad(aad)]
    assert events, "no event detail was encrypted, so the case measured nothing"
    assert all(thread != threading.get_ident() for thread, _aad, _held in cipher.sealed), (
        "an encrypt ran on the loop; the stub cipher did not reach the pool"
    )
    assert not any(events), f"{method} built an event statement under the finalize applock"
    if method.startswith("dead_letter_missing_"):
        # A sweep's sealed last_error is built with its event, before the locks too.
        assert not any(held for _thread, _aad, held in cipher.sealed)
    # Built early, still executed late: each event INSERT runs after the first finalize applock.
    executed = _statements(cur)
    statements = [sql for sql, _params in executed]
    first_lock = next(
        i
        for i, (sql, params) in enumerate(executed)
        if "sp_getapplock" in sql and any(str(p).startswith("mefor:finalize:") for p in params)
    )
    inserts = [i for i, sql in enumerate(statements) if sql == ss._SQL_INSERT_EVENT]
    assert len(inserts) == len(events), (inserts, len(events))
    assert all(i > first_lock for i in inserts), statements


@pytest.mark.parametrize("batched", [False, True])
async def test_a_thinned_event_is_built_and_written_nowhere(batched: bool) -> None:
    """Under ``message_events = "off"`` the routine ``routed`` event is dropped: no seal, no INSERT,
    and the handoff still commits its status UPDATE."""
    store = h.bare_store(batch=batched)
    store._message_events = "off"
    cipher = _BlockingCipher()
    store._cipher = cipher
    cur: Any = h.BatchRecCursor() if batched else h.AsyncRecCursor()
    cipher.cursor = cur
    conn = h.RecConn()
    assert await h.drive_async(store, "route_handoff", cursor=cur, conn=conn, **h.ROUTE_KWARGS)
    statements = [sql for sql, _params in _statements(cur)]
    assert ss._SQL_INSERT_EVENT not in statements
    assert ss._SQL_UPDATE_MESSAGE_STATUS in statements
    assert not [aad for _thread, aad, _held in cipher.sealed if _event_aad(aad)]
    assert conn.commits == 1


# --- a sweep leaves a row that moved after its unlocked read ------------------------------------


def _cancel_q1(status: dict[str, str]) -> None:
    status["q-1"] = "cancelled"


def _purge_q1(status: dict[str, str]) -> None:
    del status["q-1"]


_SWEEPS = (
    "dead_letter_missing_handlers",
    "dead_letter_missing_inbounds",
    "dead_letter_missing_destinations",
)


@pytest.mark.parametrize("move", [_cancel_q1, _purge_q1], ids=["cancelled", "purged"])
@pytest.mark.parametrize("sweep", _SWEEPS)
async def test_a_sweep_leaves_a_row_that_moved_after_its_read(sweep: str, move: Any) -> None:
    """The sweep reads its orphans with no lock, then seals each one on the pool before it locks.
    A row cancelled or purged in that window keeps its new state: no DEAD update lands on it, no
    ``dead`` event is written for it, and its message is not finalized. The untouched row is the
    control, and is still dead-lettered (Lander hold 7091043913)."""
    store = h.bare_store()
    store._leader_epoch = None
    cipher = _BlockingCipher()
    store._cipher = cipher
    cur = _OrphanCursor(at_lock=move)
    cipher.cursor = cur
    dead = await h.drive_async(store, sweep, cursor=cur, conn=h.RecConn(), **_SWEEP)

    # Its new state stands: still cancelled, or still gone.
    assert cur.status.get("q-1") == ("cancelled" if move is _cancel_q1 else None), cur.status
    assert cur.status["q-2"] == "dead", "the control row was not dead-lettered"
    assert dead == 1

    def for_message(sql: str, mid: str) -> list[tuple[Any, ...]]:
        return [p for s, p in cur.calls if s == sql and p and p[0] == mid]

    events_m1 = for_message(ss._SQL_INSERT_EVENT, "m-1")
    assert events_m1 == [], "a dead event was written for a row the sweep did not dead-letter"
    assert for_message(ss._SQL_FINALIZE_COUNT, "m-1") == [], "the moved row's message was finalized"
    assert [p[2] for p in for_message(ss._SQL_INSERT_EVENT, "m-2")] == ["dead"]
    assert for_message(ss._SQL_FINALIZE_COUNT, "m-2") != []


def _move_both(status: dict[str, str]) -> None:
    status["q-1"] = "cancelled"
    del status["q-2"]


@pytest.mark.parametrize("sweep", _SWEEPS)
async def test_a_sweep_whose_every_row_moved_writes_and_counts_nothing(
    sweep: str, caplog: pytest.LogCaptureFixture
) -> None:
    """Every orphan moved before the lock: nothing is dead-lettered, the sweep returns 0 and logs no
    warning, and its commit is a read-only release that A1 does not count."""
    store = h.bare_store()
    store._leader_epoch = None
    cur = _OrphanCursor(at_lock=_move_both)
    conn = h.RecConn()
    with caplog.at_level("WARNING", logger=ss.__name__):
        dead = await h.drive_async(store, sweep, cursor=cur, conn=conn, **_SWEEP)
    assert dead == 0
    assert cur.status == {"q-1": "cancelled"}
    assert not [s for s, _p in cur.calls if s in (ss._SQL_INSERT_EVENT, ss._SQL_FINALIZE_COUNT)]
    assert not [r for r in caplog.records if "dead-lettered" in r.getMessage()]
    assert conn.commits == 1 and store.committed_txns == 0


@pytest.mark.parametrize("sweep", _SWEEPS)
async def test_a_sweep_logs_only_what_it_dead_lettered(
    sweep: str, caplog: pytest.LogCaptureFixture
) -> None:
    """The warning counts and names the rows written, not the rows read, and survives a NULL lane
    name (both nullable columns on this backend)."""
    store = h.bare_store()
    store._leader_epoch = None
    cur = _OrphanCursor(at_lock=_cancel_q1, names=("GONE_A", None))
    with caplog.at_level("WARNING", logger=ss.__name__):
        dead = await h.drive_async(store, sweep, cursor=cur, conn=h.RecConn(), **_SWEEP)
    assert dead == 1
    (message,) = [r.getMessage() for r in caplog.records if "dead-lettered" in r.getMessage()]
    assert message.startswith("dead-lettered 1 ")
    assert message.endswith(": None") and "GONE_A" not in message, message
    assert store.committed_txns == 1
