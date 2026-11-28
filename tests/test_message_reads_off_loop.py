# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #5981, #5969: the message reads behind the API's message routes.

Two halves. First, under the ``vault_transit`` cipher every cell decrypt is a Transit HTTP round
trip. So the message list, ``get_message`` and the per-message sub-reads make their Transit calls
on the Transit pool, never on the event loop. The sub-reads are ``events_for``, ``outbox_for`` and
``outbox_payloads_for``. All three backends are pinned. The SQLite store is driven for real. The
Postgres and SQL Server stores have their database calls faked, as in
``tests/test_store_transit_off_loop_servers.py``. That file holds the measuring helper these reuse,
and the negative controls that show its three checks fire; they run there, not here.

Second, a real keyed SQLite store pins the order of the by-id read. Out of scope it opens no cell
and answers the audited uniform 404, the same answer as a missing id. In scope, cells the key
service could not open answer 503 with Retry-After, never a 500. A key-service outage is a plain
:class:`CipherError`, which the store passes up as itself, not as a tag failure.
``tests/test_cell_tag.py`` pins the same order against a faked store, for the other plain refusals
too.

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
_DESTINATIONS = ("OB_1", "OB_2")


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
    rows = [_message_row(cipher, mid) for mid in _IDS]
    store = _prepare(cls, cipher, rows)
    listed = await _measure(transit, lambda: store.list_messages(allowed_channels=None))
    assert [(r["id"], r["error"], r["summary"], r["metadata"]) for r in listed] == [
        (mid, "boom", "S", "{}") for mid in _IDS
    ]
    # The list is metadata only. The real query selects no body; the fake serves the sealed one
    # anyway, so a list that opened it would show here.
    assert [r["raw"] for r in listed] == [r["raw"] for r in rows]


@pytest.mark.parametrize("cls", _BACKENDS)
async def test_a_server_message_event_read_decrypts_off_the_loop(cls: type[Any]) -> None:
    transit, cipher = _transit()
    store = _prepare(cls, cipher, [_event_row(cipher, n) for n in (1, 2)])
    events = await _measure(transit, lambda: store.events_for("m1"))
    assert [e["detail"] for e in events] == ["detail-1", "detail-2"]


@pytest.mark.parametrize("cls", _BACKENDS)
async def test_a_server_outbox_read_decrypts_off_the_loop(cls: type[Any]) -> None:
    transit, cipher = _transit()
    queued = [_queue_row(cipher, n) for n in (1, 2)]
    store = _prepare(cls, cipher, queued)
    rows = await _measure(transit, lambda: store.outbox_for("m1"))
    assert [r["last_error"] for r in rows] == ["refused", "refused"]
    # The metadata read leaves each body sealed; outbox_payloads_for is the gated body read.
    assert [r["payload"] for r in rows] == [q["payload"] for q in queued]


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
    row = await _measure(transit, lambda: store.get_message("m1"))
    assert (row["raw"], row["error"], row["summary"], row["metadata"]) == (_RAW, "boom", "S", "{}")


async def test_the_sqlite_message_reads_decrypt_off_the_loop(tmp_path: Path) -> None:
    transit, cipher = _transit()
    store = await MessageStore.open(tmp_path / "reads.db", cipher=cipher)
    try:
        mids = [
            await store.enqueue_message(
                channel_id=_CHANNEL,
                raw=_RAW,
                deliveries=[(name, _OUT) for name in _DESTINATIONS],
                control_id=f"M{n}",
                source_type="file",
                summary="S",
                metadata="{}",
                now=float(n),
            )
            for n in (1, 2)
        ]
        mid = mids[0]
        # A failed attempt gives each outbound row a sealed last_error and the message an event
        # with a sealed detail, so each sub-read below has a cell to open on every row.
        for delivery in await store.outbox_for(mid):
            await store.mark_failed(delivery["id"], "refused", RetryPolicy(max_attempts=None))
        reads: dict[str, Callable[[], Awaitable[Any]]] = {
            "list": lambda: store.list_messages(allowed_channels=None),
            "events": lambda: store.events_for(mid),
            "outbox": lambda: store.outbox_for(mid),
            "payloads": lambda: store.outbox_payloads_for(mid),
            "message": lambda: store.get_message(mid),
        }
        got = {name: await _measure(transit, read) for name, read in reads.items()}
        # The list is metadata only: it fetches no body, so it opens none.
        assert sorted(r["id"] for r in got["list"]) == sorted(mids)
        assert all("raw" not in r and r["summary"] == "S" for r in got["list"])
        assert [e["detail"] for e in got["events"] if e["event"] == "failed"] == [
            "attempt 0: refused"
        ] * len(_DESTINATIONS)
        assert [r["last_error"] for r in got["outbox"]] == ["refused"] * len(_DESTINATIONS)
        assert [(r["payload"], r["last_error"]) for r in got["payloads"]] == [
            (_OUT, "refused")
        ] * len(_DESTINATIONS)
        assert (got["message"]["raw"], got["message"]["summary"]) == (_RAW, "S")
    finally:
        await store.close()


class _RefusingCipher:
    """The store's real cipher, except that each decrypt is counted and refused as an outage.

    An outage is a key service that gave no verdict. The store raises it as itself, a plain
    :class:`CipherError`, not as a tag failure."""

    def __init__(self, real: Any) -> None:
        self._real = real
        self.decrypts = 0

    def __getattr__(self, name: str) -> Any:
        return getattr(self._real, name)

    def decrypt(self, stored: str, **_: Any) -> str:
        self.decrypts += 1
        raise CipherUnavailableError("synthetic outage")


async def _denials(store: MessageStore) -> list[dict[str, Any]]:
    async with store._read() as db:
        cur = await db.execute(
            "SELECT actor, channel_id, detail FROM audit_log WHERE action=?",
            ("auth.channel_denied",),
        )
        return [dict(r) for r in await cur.fetchall()]


async def test_an_out_of_scope_read_of_a_real_store_decrypts_nothing(tmp_path: Path) -> None:
    """BACKLOG #5969, #5981 through a real keyed store. Out of scope the read opens no cell, the
    raw body included. It answers the uniform 404 with the denial audited, and a missing id gets
    the same answer. In scope the refused cells answer 503, never a 500."""
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
        # The same caller asking for an id that does not exist gets the same answer.
        with pytest.raises(HTTPException) as absent:
            await get_scoped_message(engine, outsider, "no-such-id", request)
        assert (absent.value.status_code, absent.value.detail) == (
            404,
            "no such message: no-such-id",
        )
        assert refusing.decrypts == 0
        denied = await _denials(store)
        assert [(d["actor"], d["channel_id"]) for d in denied] == [("outsider", "IB_SECRET")]
        assert json.loads(denied[0]["detail"]) == {"channel": "IB_SECRET"}

        # Control: in scope the same cells are opened, refused, and answered 503, never 500.
        with pytest.raises(HTTPException) as refused:
            await get_scoped_message(engine, insider, mid, request)
        assert refused.value.status_code == 503
        assert refused.value.headers is not None and "Retry-After" in refused.value.headers
        assert refusing.decrypts, (
            "the in-scope read opened no cell, so the control measured nothing"
        )
        # An in-scope outage is not a channel denial.
        assert await _denials(store) == denied
    finally:
        store._cipher = real
        await store.close()
