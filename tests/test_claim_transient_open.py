# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A claim sets a row aside when opening it fails for a reason that is not the row (BACKLOG #5735).

A key service that gave no verdict (a Vault Transit outage) or a failed read of the store says
nothing about the claimed row, so the claim must not dead-letter it. It puts the row back to
``pending`` with a durable backoff, and in a FIFO claim every later row of its lane with it, so the
lane never delivers past it. A dead-letter write that itself fails sets the row aside too, rather
than stranding it ``inflight``. A real tag failure is still dead-lettered and reported (the
control). SQLite only; the server backends make the same change.
"""

from __future__ import annotations

import pathlib
import sqlite3
import time
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
    """An :class:`AesGcmCipher` whose decrypt raises a key-service outage once ``healthy_opens``
    decrypts have run (``None``: never)."""

    def __init__(self, inner: AesGcmCipher) -> None:
        self._inner = inner
        self.healthy_opens: int | None = None

    def __getattr__(self, name: str) -> Any:
        return getattr(self._inner, name)

    def decrypt(self, stored: str, *, aad: bytes | None = None) -> str:
        if self.healthy_opens is not None:
            if self.healthy_opens <= 0:
                raise CipherUnavailableError("Transit decrypt failed (key='k'): ConnectionError")
            self.healthy_opens -= 1
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


_ALL = [_claim_ready, _claim_next_fifo, _claim_next_fifo_batch, _claim_fifo_heads]
_IDS = ["claim_ready", "claim_next_fifo", "claim_next_fifo_batch", "claim_fifo_heads"]
_CLAIMS = pytest.mark.parametrize("claim", _ALL, ids=_IDS)


async def _open(tmp_path: pathlib.Path) -> tuple[MessageStore, _OutageCipher, pathlib.Path]:
    inner = make_cipher(generate_key(), write_v2=True)
    assert isinstance(inner, AesGcmCipher)
    cipher = _OutageCipher(inner)
    db = tmp_path / "claim.db"
    store = await MessageStore.open(db, cipher=cipher)  # type: ignore[arg-type]
    await store.enqueue_message(channel_id="IB", raw="MSH|r", deliveries=[(_DEST, "B1")])
    await store.enqueue_message(channel_id="IB", raw="MSH|r", deliveries=[(_DEST, "B2")])
    return store, cipher, db


def _side(db: pathlib.Path, sql: str, params: tuple[Any, ...] = ()) -> list[tuple[Any, ...]]:
    conn = sqlite3.connect(db, timeout=30)
    try:
        rows = conn.execute(sql, params).fetchall()
        conn.commit()
        return rows
    finally:
        conn.close()


def _rows(db: pathlib.Path) -> list[tuple[str, int]]:
    return [
        (str(r[0]), int(r[1]))
        for r in _side(
            db,
            "SELECT status, attempts FROM queue WHERE destination_name=? ORDER BY rowid",
            (_DEST,),
        )
    ]


def _deferred(db: pathlib.Path) -> bool:
    """Whether the lane's head was set aside: its next attempt is in the future, not due now. (A
    claim that takes only the head leaves the row behind it as it was.)"""
    head = _side(
        db,
        "SELECT next_attempt_at FROM queue WHERE rowid=(SELECT MIN(rowid) FROM queue"
        " WHERE destination_name=?)",
        (_DEST,),
    )
    return float(head[0][0]) > time.time()


def _audited(db: pathlib.Path) -> int:
    rows = _side(db, "SELECT COUNT(*) FROM audit_log WHERE action=?", (QUEUE_TAG_FAILED_ACTION,))
    return int(rows[0][0])


def _tamper_head(db: pathlib.Path) -> None:
    _side(
        db,
        "UPDATE queue SET handler_name='MOVED' WHERE rowid=(SELECT MIN(rowid) FROM queue"
        " WHERE destination_name=?)",
        (_DEST,),
    )


@_CLAIMS
async def test_a_key_service_outage_sets_the_rows_aside(
    tmp_path: pathlib.Path, claim: Claim
) -> None:
    store, cipher, db = await _open(tmp_path)
    try:
        cipher.healthy_opens = 0
        assert await claim(store) == []
        assert _rows(db) == [("pending", 0), ("pending", 0)]  # nothing dead-lettered or stranded
        assert _deferred(db)  # a durable backoff, so a sweep does not re-claim at once
        assert _audited(db) == 0  # no false integrity report
        cipher.healthy_opens = None
        _side(db, "UPDATE queue SET next_attempt_at=0")  # the backoff has passed
        payloads = [i.payload for i in await claim(store)]  # control: they deliver once it is back
        if claim is _claim_ready:  # orders by next_attempt_at, which ties here
            assert sorted(payloads) == ["B1", "B2"]
        else:  # a FIFO claim still starts at the lane's head
            assert payloads[:1] == ["B1"]
    finally:
        await store.close()


@_CLAIMS
async def test_a_store_read_error_sets_the_rows_aside(
    tmp_path: pathlib.Path, claim: Claim, monkeypatch: pytest.MonkeyPatch
) -> None:
    store, _cipher, db = await _open(tmp_path)
    try:

        async def failing(_row: Any) -> Any:
            raise sqlite3.OperationalError("database is locked")

        monkeypatch.setattr(store, "_outbox_item_from_row", failing)
        assert await claim(store) == []
        assert _rows(db) == [("pending", 0), ("pending", 0)]
        assert _deferred(db)
    finally:
        await store.close()


@_CLAIMS
async def test_a_failed_dead_letter_write_does_not_strand_the_row(
    tmp_path: pathlib.Path, claim: Claim, monkeypatch: pytest.MonkeyPatch
) -> None:
    store, _cipher, db = await _open(tmp_path)
    try:
        _side(db, "UPDATE queue SET handler_name='MOVED' WHERE destination_name=?", (_DEST,))

        async def failing(*_a: Any, **_kw: Any) -> None:
            raise RuntimeError("dead-letter write failed")

        monkeypatch.setattr(store, "dead_letter_now", failing)
        assert await claim(store) == []
        assert _rows(db) == [("pending", 0), ("pending", 0)]  # set aside, not left inflight
    finally:
        await store.close()


@pytest.mark.parametrize("claim", _ALL[1:], ids=_IDS[1:])
async def test_a_fifo_claim_stops_at_the_row_it_sets_aside(
    tmp_path: pathlib.Path, claim: Claim
) -> None:
    """Row one fails its tag and is dead-lettered; the outage then hits row two, which is set
    aside. The dead-letter stands, and nothing past row two is delivered."""
    store, cipher, db = await _open(tmp_path)
    try:
        await store.enqueue_message(channel_id="IB", raw="MSH|r", deliveries=[(_DEST, "B3")])
        _tamper_head(db)
        cipher.healthy_opens = 1  # row one's open runs (and fails its tag), then the outage
        await claim(store)  # a single claim stops at the dead head; the batch claims go on
        if claim is _claim_next_fifo:
            assert await claim(store) == []  # the next claim meets the outage on row two
        assert _rows(db) == [("dead", 1), ("pending", 0), ("pending", 0)]
        assert _audited(db) == 1
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
        _tamper_head(db)
        items = await claim(store)
        assert all(i.payload != "B1" for i in items)
        assert _rows(db)[0][0] == "dead"
        assert _audited(db) == 1
    finally:
        await store.close()
