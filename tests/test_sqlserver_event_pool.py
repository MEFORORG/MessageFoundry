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
        self.encrypts: list[tuple[int, bytes | None, bool]] = []

    def encrypt(self, plaintext: str, *, aad: bytes | None = None) -> str:
        self.encrypts.append((threading.get_ident(), aad, _finalize_lock_taken(self.cursor)))
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
    assert cipher.encrypts and cipher.encrypts[0][0] != threading.get_ident()
