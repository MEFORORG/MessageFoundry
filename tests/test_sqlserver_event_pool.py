# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #3929: how SQL Server message-event statements use the Transit pool.

Under a cipher that blocks on I/O, :func:`~messagefoundry.store.row_seal.cipher_call` runs each
call on the bounded Transit pool. Two rules keep that from costing availability:

* a blank event ``detail`` has nothing to encrypt, so its statement makes no pool call, and a
  shut-down pool cannot roll back an event write that needs no cipher;
* a statement built for a transaction that takes the per-message finalize applock is built before
  the lock, so the transaction-owned lock never waits in the pool's queue, where a sibling
  finalizer would time out on it.

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
    """Answers a startup sweep's orphan SELECT with two rows no registry names."""

    async def fetchall(self) -> Any:
        if self._last.startswith("SELECT id, message_id,"):
            return [("q-1", "m-1", "GONE_A"), ("q-2", "m-2", "GONE_B")]
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
