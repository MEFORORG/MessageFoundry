# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #5981, #5969: the message reads behind the API's message routes.

Two halves. First, under the ``vault_transit`` cipher every cell decrypt is a Transit HTTP round
trip, so the message list and the per-message sub-reads (``events_for``, ``outbox_for``,
``outbox_payloads_for``), as well as ``get_message``, make their Transit calls off the event loop on
all three backends. The SQLite store is driven for real; the Postgres and SQL Server stores have
their database calls faked, as in ``tests/test_store_transit_off_loop_servers.py``, whose measuring
helper and its negative controls these reuse. ``get_message`` hands its opens to
:func:`asyncio.to_thread` rather than the Transit pool, so its pool check is off.

Second, through a real keyed SQLite store, an out-of-scope by-id read decrypts no cell at all and
answers the audited uniform 404, while an in-scope read whose cells the key service could not open
answers 503 with Retry-After, never a 500. A key-service outage is the plain :class:`CipherError`
the store passes up as itself rather than as a tag failure. ``tests/test_cell_tag.py`` pins the
same order against a faked store, for the other plain refusals too.

Synthetic data only.
"""

from __future__ import annotations

import json
from collections.abc import Awaitable, Callable
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from fastapi import HTTPException
from starlette.requests import Request

from messagefoundry.api.message_scope import get_scoped_message
from messagefoundry.config.models import RetryPolicy
from messagefoundry.store.cell_tag import message_cell_aad
from messagefoundry.store.crypto import (
    CipherUnavailableError,
    cell_aad,
    generate_key,
    make_cipher,
)
from messagefoundry.store.crypto_transit import TransitCipher
from messagefoundry.store.postgres import PostgresStore
from messagefoundry.store.queue_tag import queue_row_aad
from messagefoundry.store.sqlserver import SqlServerStore
from messagefoundry.store.store import MessageStatus, MessageStore
from tests.test_store_transit_off_loop_servers import (
    _bare_store,
    _fake_sql_server_db,
    _measure,
    _transit,
)

_RAW = "MSH|^~\\&|A|B|C|D|20260101||ADT^A01|M1|P|2.5.1\r"
_OUT = "MSH|^~\\&|A|B|C|D|20260101||ADT^A01|M1|P|2.5.1\rPID|1||SYNTH\r"
_BACKENDS = [PostgresStore, SqlServerStore]
_CHANNEL = "IB_TEST"
#: Two rows per read, so a per-row path makes a second call while the loop is watched.
_IDS = ("m1", "m2")


def _message_row(cipher: TransitCipher, mid: str) -> dict[str, Any]:
    row: dict[str, Any] = {
        "id": mid,
        "channel_id": _CHANNEL,
        "received_at": 1.0,
        "source_type": "mllp",
        "control_id": "M1",
        "message_type": "ADT^A01",
        "status": "ERROR",
        "last_event": "received",
    }
    for column, value in (("raw", _RAW), ("error", "boom"), ("summary", "S"), ("metadata", "{}")):
        aad = message_cell_aad(column, message_id=mid, channel_id=_CHANNEL)
        row[column] = cipher.encrypt(value, aad=aad)
    return row


def _event_row(cipher: TransitCipher, n: int) -> dict[str, Any]:
    row: dict[str, Any] = {"id": n, "message_id": "m1", "ts": float(n), "event": "failed"}
    aad = cell_aad("message_events", "detail", "m1", float(n), "failed")
    row["detail"] = cipher.encrypt(f"detail-{n}", aad=aad)
    return row


def _queue_row(cipher: TransitCipher, n: int) -> dict[str, Any]:
    row: dict[str, Any] = {
        "id": f"q{n}",
        "message_id": "m1",
        "stage": "outbound",
        "channel_id": _CHANNEL,
        "destination_name": f"OB_{n}",
        "handler_name": "h",
        "body_ref": None,
        "status": "pending",
    }
    row["payload"] = cipher.encrypt(_OUT, aad=queue_row_aad(row))
    row["last_error"] = cipher.encrypt("refused", aad=cell_aad("queue", "last_error", f"q{n}"))
    return row


def _prepare(cls: type[Any], cipher: TransitCipher, rows: list[dict[str, Any]]) -> Any:
    store = _bare_store(cls, cipher)
    if cls is SqlServerStore:
        # outbox_payloads_for takes a cursor for a store-once body; none is read here.
        _fake_sql_server_db(store, [], [])

    # A fresh copy per read, since SQL Server opens its rows in place.
    async def fetchall(*_: Any, **__: Any) -> list[dict[str, Any]]:
        return [dict(r) for r in rows]

    async def fetchone(*_: Any, **__: Any) -> dict[str, Any]:
        return dict(rows[0])

    store._fetchall = fetchall
    store._fetchone = fetchone
    return store


@pytest.mark.parametrize("cls", _BACKENDS)
async def test_a_server_message_list_decrypts_off_the_loop(cls: type[Any]) -> None:
    transit, cipher = _transit()
    store = _prepare(cls, cipher, [_message_row(cipher, mid) for mid in _IDS])
    listed = await _measure(transit, lambda: store.list_messages(allowed_channels=None))
    assert [(r["id"], r["error"], r["summary"], r["metadata"]) for r in listed] == [
        (mid, "boom", "S", "{}") for mid in _IDS
    ]


@pytest.mark.parametrize("cls", _BACKENDS)
async def test_a_server_message_event_read_decrypts_off_the_loop(cls: type[Any]) -> None:
    transit, cipher = _transit()
    store = _prepare(cls, cipher, [_event_row(cipher, n) for n in (1, 2)])
    events = await _measure(transit, lambda: store.events_for("m1"))
    assert [e["detail"] for e in events] == ["detail-1", "detail-2"]


@pytest.mark.parametrize("cls", _BACKENDS)
async def test_a_server_outbox_read_decrypts_off_the_loop(cls: type[Any]) -> None:
    transit, cipher = _transit()
    store = _prepare(cls, cipher, [_queue_row(cipher, n) for n in (1, 2)])
    rows = await _measure(transit, lambda: store.outbox_for("m1"))
    assert [r["last_error"] for r in rows] == ["refused", "refused"]


@pytest.mark.parametrize("cls", _BACKENDS)
async def test_a_server_outbox_payload_read_decrypts_off_the_loop(cls: type[Any]) -> None:
    transit, cipher = _transit()
    store = _prepare(cls, cipher, [_queue_row(cipher, n) for n in (1, 2)])
    rows = await _measure(transit, lambda: store.outbox_payloads_for("m1"))
    assert [(r["payload"], r["last_error"]) for r in rows] == [(_OUT, "refused")] * 2


@pytest.mark.parametrize("cls", _BACKENDS)
async def test_a_server_get_message_decrypts_off_the_loop(cls: type[Any]) -> None:
    transit, cipher = _transit()
    store = _prepare(cls, cipher, [_message_row(cipher, "m1")])
    # get_message hands its opens to asyncio.to_thread, not the Transit pool.
    row = await _measure(transit, lambda: store.get_message("m1"), pool=False)
    assert (row["raw"], row["error"], row["summary"], row["metadata"]) == (_RAW, "boom", "S", "{}")


async def test_the_sqlite_message_reads_decrypt_off_the_loop(tmp_path: Path) -> None:
    transit, cipher = _transit()
    store = await MessageStore.open(tmp_path / "reads.db", cipher=cipher)
    try:
        mid = await store.enqueue_message(
            channel_id=_CHANNEL,
            raw=_RAW,
            deliveries=[("OB_1", _OUT)],
            control_id="M1",
            source_type="file",
            summary="S",
            metadata="{}",
        )
        [delivery] = await store.outbox_for(mid)
        # A failed attempt gives the outbound row a sealed last_error and the message an event
        # with a sealed detail, so each sub-read below has a cell to open.
        await store.mark_failed(delivery["id"], "refused", RetryPolicy(max_attempts=None))
        reads: list[tuple[Callable[[], Awaitable[Any]], bool]] = [
            (lambda: store.list_messages(allowed_channels=None), True),
            (lambda: store.events_for(mid), True),
            (lambda: store.outbox_for(mid), True),
            (lambda: store.outbox_payloads_for(mid), True),
            (lambda: store.get_message(mid), False),
        ]
        results = [await _measure(transit, read, pool=pool) for read, pool in reads]
        # The list is metadata only: it fetches no body, so it opens none.
        [listed] = results[0]
        assert "raw" not in listed and listed["summary"] == "S"
        [payload] = results[3]
        assert payload["payload"] == _OUT and payload["last_error"] == "refused"
    finally:
        await store.close()


class _RefusingCipher:
    """The store's real cipher, except that every decrypt is recorded and refused as a key service
    that gave no verdict: a plain :class:`CipherError` the store does not read as a tag failure."""

    def __init__(self, real: Any) -> None:
        self._real = real
        self.decrypts = 0

    def __getattr__(self, name: str) -> Any:
        return getattr(self._real, name)

    def decrypt(self, stored: str, **_: Any) -> str:
        self.decrypts += 1
        raise CipherUnavailableError("synthetic outage")


async def test_an_out_of_scope_read_of_a_real_store_decrypts_nothing(tmp_path: Path) -> None:
    """BACKLOG #5969, #5981 through a real keyed store: out of scope the read opens no cell, the
    raw body included, and answers the uniform 404 with the denial audited, the same answer as a
    missing id. In scope the refused cells answer 503, never a 500."""
    store = await MessageStore.open(
        tmp_path / "scope.db", cipher=make_cipher(generate_key(), write_v2=True)
    )
    real = store._cipher
    try:
        mid = await store.record_received(
            channel_id="IB_SECRET", raw=_RAW, status=MessageStatus.ERROR, summary="S"
        )
        refusing = _RefusingCipher(real)
        store._cipher = refusing
        engine: Any = SimpleNamespace(store=store)
        request = Request({"type": "http", "client": ("127.0.0.1", 1), "headers": []})
        outsider: Any = SimpleNamespace(
            username="outsider", can_access_channel=lambda c: c != "IB_SECRET"
        )
        insider: Any = SimpleNamespace(username="insider", can_access_channel=lambda c: True)

        with pytest.raises(HTTPException) as hidden:
            await get_scoped_message(engine, outsider, mid, request)
        assert (hidden.value.status_code, hidden.value.detail) == (404, f"no such message: {mid}")
        assert refusing.decrypts == 0, "an out-of-scope read opened a cell"
        with pytest.raises(HTTPException) as absent:
            await get_scoped_message(engine, insider, "no-such-id", request)
        assert (absent.value.status_code, absent.value.detail) == (
            404,
            "no such message: no-such-id",
        )
        assert refusing.decrypts == 0

        store._cipher = real
        async with store._read() as db:
            cur = await db.execute(
                "SELECT actor, channel_id, detail FROM audit_log WHERE action=?",
                ("auth.channel_denied",),
            )
            denied = [dict(r) for r in await cur.fetchall()]
        assert [(d["actor"], d["channel_id"]) for d in denied] == [("outsider", "IB_SECRET")]
        assert json.loads(denied[0]["detail"]) == {"channel": "IB_SECRET"}

        # Control: in scope the same cells are opened, refused, and answered 503, never 500.
        store._cipher = refusing
        with pytest.raises(HTTPException) as refused:
            await get_scoped_message(engine, insider, mid, request)
        assert refused.value.status_code == 503
        assert refused.value.headers is not None and "Retry-After" in refused.value.headers
        assert refusing.decrypts, (
            "the in-scope read opened no cell, so the control measured nothing"
        )
    finally:
        store._cipher = real
        await store.close()
