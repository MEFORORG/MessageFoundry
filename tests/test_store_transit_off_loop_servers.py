# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #5757: the server stores open a ``vault_transit`` store's cells off the event loop.

Under the ``vault_transit`` cipher every cell decrypt is a Transit HTTP round trip. On SQL Server the
reference read, the state cache load and the claim decode once made those calls inline on the loop,
so a large reference set or a claim sweep held it for one round trip per row. These tests drive each
path through a real :class:`TransitCipher` over a fake Transit client that blocks every call, with
the database reads faked, and check that the loop kept serving and that no call ran on its thread.
``tests/test_store_transit_off_loop.py`` covers the SQLite store the same way (BACKLOG #3929).
"""

from __future__ import annotations

import asyncio
import importlib
import json
import threading
import time
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from typing import Any

import pytest

pytest.importorskip("hvac", reason="the Transit cipher tests need the [vault] extra")

from messagefoundry.store.crypto import cell_aad  # noqa: E402
from messagefoundry.store.crypto_transit import TransitCipher  # noqa: E402
from messagefoundry.store.queue_tag import queue_row_aad  # noqa: E402
from tests.test_crypto_transit import _FakeClient, _FakeTransit  # noqa: E402

_KEY = "mefor-store"
#: How long each Transit call holds its thread once armed: long against a loop tick.
_BLOCK = 0.2
#: Synthetic rows only, never PHI. Two of each, so a per-row hop and a one-call hop both count.
_KEYS = ("k1", "k2")
_RAW = "MSH|^~\\&|A|B|C|D|20260101||ADT^A01|M1|P|2.5.1\r"
_BACKENDS = ["postgres", "sqlserver"]


class _RecordingTransit(_FakeTransit):
    """A fake Transit that records the thread of each encrypt and decrypt, and blocks each once
    armed. Its own copy rather than the SQLite test's, so this file imports on a tree that predates
    BACKLOG #3929 and its failing run there can be shown."""

    def __init__(self) -> None:
        super().__init__()
        self.threads: list[int] = []
        self.block = 0.0

    def _note(self) -> None:
        self.threads.append(threading.get_ident())
        if self.block:
            time.sleep(self.block)

    def encrypt_data(self, **kw: Any) -> dict[str, Any]:
        self._note()
        return super().encrypt_data(**kw)

    def decrypt_data(self, **kw: Any) -> dict[str, Any]:
        self._note()
        return super().decrypt_data(**kw)


def _bare_store(backend: str, cipher: TransitCipher) -> Any:
    """A store object with no connection: each test fakes the reads its path makes."""
    module = importlib.import_module(f"messagefoundry.store.{backend}")
    cls = module.PostgresStore if backend == "postgres" else module.SqlServerStore
    store = object.__new__(cls)
    store._cipher = cipher
    return store


async def _measure(transit: _RecordingTransit, call: Callable[[], Awaitable[Any]]) -> Any:
    """Run ``call`` with every Transit call blocking, and check the loop kept serving meanwhile and
    that no Transit call ran on the loop's thread."""
    loop_thread = threading.get_ident()
    transit.threads.clear()
    transit.block = _BLOCK
    gaps: list[float] = []
    done = asyncio.Event()

    async def ticker() -> None:
        last = time.perf_counter()
        while not done.is_set():
            await asyncio.sleep(0.01)
            now = time.perf_counter()
            gaps.append(now - last)
            last = now

    task = asyncio.create_task(ticker())
    try:
        result = await call()
    finally:
        done.set()
        await task
        transit.block = 0.0
    # Controls: the path made the blocking calls this test exists to place.
    assert len(transit.threads) >= len(_KEYS), (
        "the path made no Transit call, so nothing was measured"
    )
    assert loop_thread not in transit.threads, "a Transit call ran on the event loop's thread"
    assert gaps and max(gaps) < _BLOCK / 2, f"the loop stalled for {max(gaps):.3f}s"
    return result


@pytest.mark.parametrize("backend", _BACKENDS)
async def test_the_reference_read_decrypts_off_the_loop(backend: str) -> None:
    transit = _RecordingTransit()
    cipher = TransitCipher(_FakeClient(transit), _KEY)
    rows = [
        {
            "name": "codes",
            "version": "v1",
            "key": key,
            "value": cipher.encrypt(
                json.dumps(f"value-{key}"), aad=cell_aad("reference", "value", "codes", "v1", key)
            ),
        }
        for key in _KEYS
    ]
    store = _bare_store(backend, cipher)

    async def fetchall(*_: Any, **__: Any) -> list[dict[str, Any]]:
        return rows

    store._fetchall = fetchall
    await _measure(transit, store._load_reference_cache)
    assert dict(store._reference_cache["codes"]) == {key: f"value-{key}" for key in _KEYS}
    assert store._reference_versions == {"codes": "v1"}


@pytest.mark.parametrize("backend", _BACKENDS)
async def test_the_state_cache_load_decrypts_off_the_loop(backend: str) -> None:
    transit = _RecordingTransit()
    cipher = TransitCipher(_FakeClient(transit), _KEY)
    rows = [
        {
            "namespace": "ns",
            "key": key,
            "value": cipher.encrypt(
                json.dumps({"n": key}), aad=cell_aad("state", "value", "ns", key)
            ),
        }
        for key in _KEYS
    ]
    store = _bare_store(backend, cipher)

    async def fetchall(sql: str, *_: Any, **__: Any) -> list[dict[str, Any]]:
        # Postgres reads the namespace versions first, then the rows; SQL Server reads the rows.
        return [{"namespace": "ns", "version": 1}] if "state_version" in sql else rows

    store._fetchall = fetchall
    await _measure(transit, store._load_state_cache)
    assert dict(store._state_cache) == {("ns", key): {"n": key} for key in _KEYS}


async def test_a_sql_server_claim_opens_its_rows_off_the_loop() -> None:
    transit = _RecordingTransit()
    cipher = TransitCipher(_FakeClient(transit), _KEY)
    columns = [
        "id",
        "message_id",
        "channel_id",
        "destination_name",
        "handler_name",
        "payload",
        "attempts",
    ]
    stage = "outbound"
    rows = []
    for n in range(len(_KEYS)):
        row = {
            "id": f"row{n}",
            "message_id": f"msg{n}",
            "channel_id": "IB_TEST",
            "destination_name": "OB_TEST",
            "handler_name": "h",
            "attempts": 1,
        }
        aad = queue_row_aad({**row, "stage": stage, "body_ref": None})
        rows.append(tuple({**row, "payload": cipher.encrypt(_RAW, aad=aad)}[c] for c in columns))
    store = _bare_store("sqlserver", cipher)
    store._leader_epoch = None

    class _Cursor:
        description = [(c,) for c in columns]

        async def execute(self, *_: Any) -> None:
            return None

        async def fetchall(self) -> list[tuple[Any, ...]]:
            return rows

    class _Conn:
        async def rollback(self) -> None:
            return None

    @asynccontextmanager
    async def acquire() -> AsyncIterator[_Conn]:
        yield _Conn()

    @asynccontextmanager
    async def cursor(_conn: Any) -> AsyncIterator[_Cursor]:
        yield _Cursor()

    async def commit(_conn: Any) -> None:
        return None

    store._acquire = acquire
    store._cursor = cursor
    store._commit = commit
    items = await _measure(transit, lambda: store.claim_ready(limit=10, stage=stage))
    assert [item.payload for item in items] == [_RAW] * len(_KEYS)
