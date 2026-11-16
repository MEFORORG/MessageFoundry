# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A claim hands its rows back when opening them fails for a reason that is not the row (BACKLOG
#5735).

A key service that gave no verdict (a Vault Transit outage) or a failed read of the store says
nothing about the claimed row, so the claim must not dead-letter it: it returns every row it
claimed to ``pending`` and raises, and the worker backs off. A dead-letter write that itself fails
hands the rows back too, rather than stranding them ``inflight``. A real tag failure is still
dead-lettered and reported (the control). SQLite only; the server backends make the same change.
"""

from __future__ import annotations

import pathlib
import sqlite3
from collections.abc import Awaitable, Callable
from typing import Any

import pytest

from messagefoundry.store import MessageStore
from messagefoundry.store.crypto import (
    AesGcmCipher,
    CipherUnavailableError,
    generate_key,
    make_cipher,
)
from messagefoundry.store.queue_tag import QUEUE_TAG_FAILED_ACTION

_DEST = "OB_T"


class _OutageCipher:
    """An :class:`AesGcmCipher` whose decrypt raises a key-service outage while ``down`` is set."""

    def __init__(self, inner: AesGcmCipher) -> None:
        self._inner = inner
        self.down = False

    def __getattr__(self, name: str) -> Any:
        return getattr(self._inner, name)

    def decrypt(self, stored: str, *, aad: bytes | None = None) -> str:
        if self.down:
            raise CipherUnavailableError("Transit decrypt failed (key='k'): ConnectionError")
        return self._inner.decrypt(stored, aad=aad)


Claim = Callable[[MessageStore], Awaitable[list[Any]]]


async def _claim_ready(store: MessageStore) -> list[Any]:
    return await store.claim_ready(10, destination_name=_DEST)


async def _claim_next_fifo(store: MessageStore) -> list[Any]:
    one = await store.claim_next_fifo(_DEST)
    return [] if one is None else [one]


async def _claim_next_fifo_batch(store: MessageStore) -> list[Any]:
    return await store.claim_next_fifo_batch(_DEST, stage="outbound", limit=10)


async def _claim_fifo_heads(store: MessageStore) -> list[Any]:
    heads = await store.claim_fifo_heads("outbound", [_DEST], per_lane_limit=10)
    return [item for items in heads.by_lane.values() for item in items]


_CLAIMS = pytest.mark.parametrize(
    "claim",
    [_claim_ready, _claim_next_fifo, _claim_next_fifo_batch, _claim_fifo_heads],
    ids=["claim_ready", "claim_next_fifo", "claim_next_fifo_batch", "claim_fifo_heads"],
)


async def _open(tmp_path: pathlib.Path) -> tuple[MessageStore, _OutageCipher, pathlib.Path]:
    inner = make_cipher(generate_key(), write_v2=True)
    assert isinstance(inner, AesGcmCipher)
    cipher = _OutageCipher(inner)
    db = tmp_path / "claim.db"
    store = await MessageStore.open(db, cipher=cipher)  # type: ignore[arg-type]
    await store.enqueue_message(channel_id="IB", raw="MSH|r", deliveries=[(_DEST, "B1")])
    await store.enqueue_message(channel_id="IB", raw="MSH|r", deliveries=[(_DEST, "B2")])
    return store, cipher, db


def _rows(db: pathlib.Path) -> list[tuple[str, int]]:
    conn = sqlite3.connect(db, timeout=30)
    try:
        return [
            (r[0], r[1])
            for r in conn.execute(
                "SELECT status, attempts FROM queue WHERE destination_name=? ORDER BY rowid",
                (_DEST,),
            )
        ]
    finally:
        conn.close()


def _audited(db: pathlib.Path) -> int:
    conn = sqlite3.connect(db, timeout=30)
    try:
        row = conn.execute(
            "SELECT COUNT(*) FROM audit_log WHERE action=?", (QUEUE_TAG_FAILED_ACTION,)
        ).fetchone()
        return int(row[0])
    finally:
        conn.close()


@_CLAIMS
async def test_a_key_service_outage_hands_the_claim_back(
    tmp_path: pathlib.Path, claim: Claim
) -> None:
    store, cipher, db = await _open(tmp_path)
    try:
        cipher.down = True
        with pytest.raises(CipherUnavailableError):
            await claim(store)
        assert _rows(db) == [("pending", 0), ("pending", 0)]  # nothing dead-lettered or stranded
        assert _audited(db) == 0  # no false integrity report
        cipher.down = False
        items = await claim(store)  # control: the rows deliver once the service is back
        payloads = [i.payload for i in items]
        if claim is _claim_ready:  # orders by next_attempt_at, which ties here
            assert sorted(payloads) == ["B1", "B2"]
        else:  # a FIFO claim still starts at the lane's head
            assert payloads[:1] == ["B1"]
    finally:
        await store.close()


@_CLAIMS
async def test_a_store_read_error_hands_the_claim_back(
    tmp_path: pathlib.Path, claim: Claim, monkeypatch: pytest.MonkeyPatch
) -> None:
    store, _cipher, db = await _open(tmp_path)
    try:

        async def failing(_row: Any) -> Any:
            raise sqlite3.OperationalError("database is locked")

        monkeypatch.setattr(store, "_outbox_item_from_row", failing)
        with pytest.raises(sqlite3.OperationalError):
            await claim(store)
        assert _rows(db) == [("pending", 0), ("pending", 0)]
    finally:
        await store.close()


@_CLAIMS
async def test_a_failed_dead_letter_write_does_not_strand_the_claim(
    tmp_path: pathlib.Path, claim: Claim, monkeypatch: pytest.MonkeyPatch
) -> None:
    store, _cipher, db = await _open(tmp_path)
    try:
        side = sqlite3.connect(db, timeout=30)
        side.execute("UPDATE queue SET handler_name='MOVED' WHERE destination_name=?", (_DEST,))
        side.commit()
        side.close()

        async def failing(*_a: Any, **_kw: Any) -> None:
            raise RuntimeError("dead-letter write failed")

        monkeypatch.setattr(store, "dead_letter_now", failing)
        with pytest.raises(RuntimeError):
            await claim(store)
        assert _rows(db) == [("pending", 0), ("pending", 0)]  # handed back, not left inflight
    finally:
        await store.close()


@_CLAIMS
async def test_a_real_tag_failure_is_still_dead_lettered_and_reported(
    tmp_path: pathlib.Path, claim: Claim
) -> None:
    """The control: a row whose routing field changed outside the store fails its tag, and the
    claim dead-letters and reports it exactly as before."""
    store, _cipher, db = await _open(tmp_path)
    try:
        side = sqlite3.connect(db, timeout=30)
        side.execute(
            "UPDATE queue SET handler_name='MOVED' WHERE rowid=(SELECT MIN(rowid) FROM queue"
            " WHERE destination_name=?)",
            (_DEST,),
        )
        side.commit()
        side.close()
        items = await claim(store)
        assert all(i.payload != "B1" for i in items)
        assert _rows(db)[0][0] == "dead"
        assert _audited(db) == 1
    finally:
        await store.close()
