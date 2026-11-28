# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #5757: named server store paths make a ``vault_transit`` store's cipher calls off the loop.

Under the ``vault_transit`` cipher every cell encrypt and decrypt is a Transit HTTP round trip.
Before BACKLOG #3929 at least the Postgres and SQL Server reference read and state cache load, and
the SQL Server claim decode and reference write, made those calls inline on the event loop, so a
large reference set or a claim sweep held it for one round trip per row. These tests pin the paths
they name, not every cipher call in either store. Each Transit test drives its path through a real
:class:`TransitCipher` over a fake Transit client that blocks every call, with the database faked,
and checks that no Transit call ran on the loop's thread, that the loop kept ticking, and, on every
path but SQL Server's ``reload_state_cache``, that each call ran on a Transit pool thread, named so
(BACKLOG #5757 item 2), so asyncio's default executor fails it too. Each of those three checks has
a negative control here. Under an in-process cipher, the reference read is pinned to stay inline on
the loop (item 3). ``tests/test_store_transit_off_loop.py`` covers the SQLite store.
"""

from __future__ import annotations

import asyncio
import json
import threading
import time
from collections.abc import AsyncIterator, Awaitable, Callable, Mapping, Sequence
from concurrent.futures import ThreadPoolExecutor
from contextlib import asynccontextmanager
from typing import Any

import pytest

from messagefoundry.store import row_seal
from messagefoundry.store.crypto import AesGcmCipher, cell_aad, generate_key, make_cipher
from messagefoundry.store.crypto_transit import TransitCipher
from messagefoundry.store.postgres import PostgresStore
from messagefoundry.store.queue_tag import queue_row_aad
from messagefoundry.store.sqlserver import SqlServerStore
from tests.test_crypto_transit import _FakeClient, _FakeTransit

_KEY = "mefor-store"
#: How long each Transit call holds its thread once armed: long against a loop tick. A call made
#: inline stalls the loop for at least this long, so a gap under it is the pass bound, which leaves
#: the whole of it as headroom for a slow runner. Every call blocks, not only the first: the stall
#: check is then the one check that sees a later call wait on the loop. So BACKLOG #5757 item 4's
#: cut to one sleep per test is not taken.
_BLOCK = 0.3
#: Every Transit pool thread's name starts with this, which ``row_seal._transit_pool`` passes as a
#: literal; there is no constant to import.
_POOL_PREFIX = "mefor-transit-seal"
#: Synthetic rows only, never PHI. Every test uses one row per key, two in all, so a per-row path
#: makes a second call, which the stall check also covers because every call blocks.
_KEYS = ("k1", "k2")
_RAW = "MSH|^~\\&|A|B|C|D|20260101||ADT^A01|M1|P|2.5.1\r"
_BACKENDS = [PostgresStore, SqlServerStore]


class _RecordingTransit(_FakeTransit):
    """A fake Transit that records the thread and its name for each call, and blocks each once
    armed. Its own copy rather than the SQLite test's, which imports a name BACKLOG #3929 added, so
    this file still imports on the tree before that fix and its failing run there can be shown
    again."""

    def __init__(self) -> None:
        super().__init__()
        self.threads: list[int] = []
        self.names: list[str] = []
        self.block = 0.0

    def _note(self) -> None:
        self.threads.append(threading.get_ident())
        self.names.append(threading.current_thread().name)
        if self.block:
            time.sleep(self.block)

    def encrypt_data(self, **kw: Any) -> dict[str, Any]:
        self._note()
        return super().encrypt_data(**kw)

    def decrypt_data(self, **kw: Any) -> dict[str, Any]:
        self._note()
        return super().decrypt_data(**kw)

    def generate_hmac(self, **kw: Any) -> dict[str, Any]:
        self._note()
        return super().generate_hmac(**kw)

    def verify_signed_data(self, **kw: Any) -> dict[str, Any]:
        self._note()
        return super().verify_signed_data(**kw)


def _transit() -> tuple[_RecordingTransit, TransitCipher]:
    transit = _RecordingTransit()
    return transit, TransitCipher(_FakeClient(transit), _KEY)


def _bare_store(cls: type[Any], cipher: Any) -> Any:
    """A store object with no connection and empty caches: each test fakes the database calls its
    path makes."""
    store = object.__new__(cls)
    store._cipher = cipher
    store._reference_cache = {}
    store._reference_versions = {}
    store._state_cache = {}
    store._state_versions = {}
    return store


def _serve_rows(store: Any, rows: Sequence[Mapping[str, Any]]) -> None:
    """Fake ``store._fetchall`` so every statement answers ``rows``."""

    async def fetchall(*_: Any, **__: Any) -> Sequence[Mapping[str, Any]]:
        return rows

    store._fetchall = fetchall


def _assert_reference_written(
    cipher: TransitCipher, store: Any, executed: Sequence[tuple[str, Sequence[Any]]]
) -> None:
    """Every ``INSERT INTO reference`` row in ``executed`` holds its key's value, sealed under its
    cell, and the store recorded the set's version."""
    inserted = {
        params[2]: params[3]
        for sql, params in executed
        if sql.startswith("INSERT INTO reference (")
    }
    assert set(inserted) == set(_KEYS)
    inserts = [sql for sql, _ in executed if sql.startswith("INSERT INTO reference (")]
    assert len(inserts) == len(_KEYS), inserts
    for key, sealed in inserted.items():
        aad = cell_aad("reference", "value", "codes", "v1", key)
        assert json.loads(cipher.decrypt(sealed, aad=aad)) == f"value-{key}"
    assert store._reference_versions == {"codes": "v1"}


def _fake_sql_server_db(
    store: Any, rows: Sequence[tuple[Any, ...]], columns: list[str]
) -> list[tuple[str, Any]]:
    """Fake the SQL Server connection, cursor and commit: every statement's ``fetchall`` answers
    ``rows`` under ``columns``. Returns the list each executed ``(sql, params)`` lands in."""
    executed: list[tuple[str, Any]] = []

    class _Cursor:
        description = [(c,) for c in columns]

        async def execute(self, sql: str, params: Any = None) -> None:
            executed.append((sql, params))

        async def fetchall(self) -> list[tuple[Any, ...]]:
            return list(rows)

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
    return executed


async def _measure(
    transit: _RecordingTransit, call: Callable[[], Awaitable[Any]], *, pool: bool = True
) -> Any:
    """Run ``call`` with every Transit call blocking, and check that it made a Transit call,
    that none ran on the loop's thread, that the loop kept ticking meanwhile, and, unless ``pool``
    is False, that every one ran on a Transit pool thread."""
    loop_thread = threading.get_ident()
    transit.threads.clear()
    transit.names.clear()
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
    await asyncio.sleep(0)  # the ticker takes its baseline before the path runs
    try:
        result = await call()
    finally:
        done.set()
        await task
        transit.block = 0.0
    # Control: the path made a blocked call, so the checks below measured something.
    assert transit.threads, "the path made no Transit call, so nothing was measured"
    assert loop_thread not in transit.threads, "a Transit call ran on the event loop's thread"
    # The ticker's last pass always records a gap, after ``done`` is set, so gaps is never empty.
    assert max(gaps) < _BLOCK, f"the loop stalled for {max(gaps):.3f}s"
    if pool:
        off_pool = [n for n in transit.names if not n.startswith(_POOL_PREFIX)]
        assert not off_pool, f"a Transit call ran off the Transit pool: {off_pool}"
    return result


async def test_the_stall_check_fires_on_a_hop_that_blocks_the_loop() -> None:
    """Negative control for :func:`_measure`'s stall check: a call that runs on a Transit pool
    thread name but waits for it synchronously would pass the thread and pool checks, so only the
    stall check, which runs before the pool check, can catch it."""
    transit, cipher = _transit()
    sealed = cipher.encrypt('"x"', aad=cell_aad("t", "c", "1"))

    async def blocking_hop() -> str:
        # A private pool whose threads carry the Transit pool's name, so the shared pool is left
        # alone and the name check would pass too.
        with ThreadPoolExecutor(max_workers=1, thread_name_prefix=_POOL_PREFIX) as pool:
            return pool.submit(cipher.decrypt, sealed, aad=cell_aad("t", "c", "1")).result()

    with pytest.raises(AssertionError, match="the loop stalled"):
        await _measure(transit, blocking_hop)


async def test_the_thread_check_fires_on_a_call_made_inline() -> None:
    """Negative control for :func:`_measure`'s loop-thread check, which runs first."""
    transit, cipher = _transit()
    sealed = cipher.encrypt('"x"', aad=cell_aad("t", "c", "1"))

    async def inline() -> str:
        return cipher.decrypt(sealed, aad=cell_aad("t", "c", "1"))

    with pytest.raises(AssertionError, match="event loop's thread"):
        await _measure(transit, inline)


async def test_the_pool_check_fires_on_the_default_executor() -> None:
    """Negative control for :func:`_measure`'s pool check (BACKLOG #5757 item 2): a call on
    asyncio's default executor is off the loop and leaves it ticking, so only that check can catch
    it."""
    transit, cipher = _transit()
    sealed = cipher.encrypt('"x"', aad=cell_aad("t", "c", "1"))

    async def default_executor() -> str:
        return await asyncio.to_thread(cipher.decrypt, sealed, aad=cell_aad("t", "c", "1"))

    with pytest.raises(AssertionError, match="off the Transit pool"):
        await _measure(transit, default_executor)


def _reference_rows(cipher: Any) -> list[dict[str, Any]]:
    return [
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


@pytest.mark.parametrize("cls", _BACKENDS)
async def test_the_reference_read_decrypts_off_the_loop(cls: type[Any]) -> None:
    transit, cipher = _transit()
    rows = _reference_rows(cipher)
    store = _bare_store(cls, cipher)

    _serve_rows(store, rows)
    await _measure(transit, store._load_reference_cache)
    assert dict(store._reference_cache["codes"]) == {key: f"value-{key}" for key in _KEYS}
    assert store._reference_versions == {"codes": "v1"}


def _state_rows(cipher: TransitCipher) -> list[dict[str, Any]]:
    return [
        {
            "namespace": "ns",
            "key": key,
            "value": cipher.encrypt(
                json.dumps({"n": key}), aad=cell_aad("state", "value", "ns", key)
            ),
        }
        for key in _KEYS
    ]


@pytest.mark.parametrize("cls", _BACKENDS)
async def test_the_state_cache_load_decrypts_off_the_loop(cls: type[Any]) -> None:
    transit, cipher = _transit()
    rows = _state_rows(cipher)
    store = _bare_store(cls, cipher)

    async def fetchall(sql: str, *_: Any, **__: Any) -> list[dict[str, Any]]:
        # Postgres reads the namespace versions first, then the rows; SQL Server reads the rows.
        return [{"namespace": "ns", "version": 1}] if "state_version" in sql else rows

    store._fetchall = fetchall
    await _measure(transit, store._load_state_cache)
    assert dict(store._state_cache) == {("ns", key): {"n": key} for key in _KEYS}
    if cls is PostgresStore:
        assert store._state_versions == {"ns": 1}


async def test_a_sql_server_promotion_reload_decrypts_off_the_loop() -> None:
    """The reload a promoted standby runs while its lease renewal is live. It used a worker thread
    before BACKLOG #3929 too, so this pins that control rather than that fix. It runs on asyncio's
    default executor, not the Transit pool, so the pool check is off here: whether a whole-table
    reload should hold a pool thread is open on BACKLOG #3929."""
    transit, cipher = _transit()
    rows = _state_rows(cipher)
    store = _bare_store(SqlServerStore, cipher)

    _serve_rows(store, rows)
    await _measure(transit, store.reload_state_cache, pool=False)
    assert dict(store._state_cache) == {("ns", key): {"n": key} for key in _KEYS}


async def test_a_sql_server_claim_opens_its_rows_off_the_loop() -> None:
    transit, cipher = _transit()
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
    for n, _key in enumerate(_KEYS):
        row = {
            "id": f"row{n}",
            "message_id": f"msg{n}",
            "channel_id": "IB_TEST",
            "destination_name": "OB_TEST",
            "handler_name": "h",
            "attempts": 1,
        }
        aad = queue_row_aad({**row, "stage": stage, "body_ref": None})
        full = {**row, "payload": cipher.encrypt(_RAW, aad=aad)}
        rows.append(tuple(full[c] for c in columns))
    store = _bare_store(SqlServerStore, cipher)
    _fake_sql_server_db(store, rows, columns)
    items = await _measure(transit, lambda: store.claim_ready(limit=10, stage=stage))
    assert [item.payload for item in items] == [_RAW] * len(_KEYS)


async def test_a_sql_server_reference_write_encrypts_off_the_loop() -> None:
    transit, cipher = _transit()
    store = _bare_store(SqlServerStore, cipher)
    executed = _fake_sql_server_db(store, [], [])
    snapshot = {key: f"value-{key}" for key in _KEYS}
    await _measure(
        transit, lambda: store.write_reference_snapshot(name="codes", version="v1", rows=snapshot)
    )
    _assert_reference_written(cipher, store, executed)


# --- BACKLOG #5757 added item 1: paths PR 3156 (BACKLOG #3929) fixed and PR 3241 did not pin ---
# Still not pinned here: at least SQL Server's claim_next_fifo, claim_next_fifo_batch and
# _open_claimed_heads, its pre-ACK record_received encrypt, and the Postgres claim_ready decode.
# Each needs a fake of its whole statement sequence, which this file does not have yet.


@pytest.mark.parametrize("cls", _BACKENDS)
async def test_a_reference_converge_decrypts_off_the_loop(cls: type[Any]) -> None:
    transit, cipher = _transit()
    rows = _reference_rows(cipher)
    store = _bare_store(cls, cipher)

    _serve_rows(store, rows)
    assert await _measure(transit, store.converge_reference_cache) == ["codes"]
    assert dict(store._reference_cache["codes"]) == {key: f"value-{key}" for key in _KEYS}


async def test_a_postgres_state_converge_decrypts_off_the_loop() -> None:
    transit, cipher = _transit()
    rows = _state_rows(cipher)
    store = _bare_store(PostgresStore, cipher)

    async def fetchall(sql: str, *_: Any, **__: Any) -> list[dict[str, Any]]:
        return [{"namespace": "ns", "version": 1}] if "state_version" in sql else rows

    store._fetchall = fetchall
    assert await _measure(transit, store.converge_state_cache) == ["ns"]
    assert dict(store._state_cache) == {("ns", key): {"n": key} for key in _KEYS}
    assert store._state_versions == {"ns": 1}


async def test_a_postgres_reference_write_encrypts_off_the_loop() -> None:
    transit, cipher = _transit()
    store = _bare_store(PostgresStore, cipher)
    executed: list[tuple[str, tuple[Any, ...]]] = []

    class _Conn:
        async def execute(self, sql: str, *params: Any) -> None:
            executed.append((sql, params))

        @asynccontextmanager
        async def transaction(self) -> AsyncIterator[None]:
            yield

    @asynccontextmanager
    async def timed_acquire(**_: Any) -> AsyncIterator[_Conn]:
        yield _Conn()

    store._timed_acquire = timed_acquire
    snapshot = {key: f"value-{key}" for key in _KEYS}
    await _measure(
        transit, lambda: store.write_reference_snapshot(name="codes", version="v1", rows=snapshot)
    )
    _assert_reference_written(cipher, store, executed)


# --- BACKLOG #5757 added item 3: an in-process cipher stays inline -----------------------------


@pytest.mark.parametrize("cls", _BACKENDS)
async def test_an_in_process_cipher_reads_the_reference_set_inline(
    cls: type[Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    """The same read as :func:`test_the_reference_read_decrypts_off_the_loop`, under the in-process
    cipher: ``cipher_call`` makes no thread hop, so every decrypt runs on the loop's thread."""
    cipher = make_cipher(generate_key())
    assert isinstance(cipher, AesGcmCipher)
    rows = _reference_rows(cipher)
    threads: list[int] = []
    real_decrypt = AesGcmCipher.decrypt

    def decrypt(self: AesGcmCipher, *args: Any, **kw: Any) -> str:
        threads.append(threading.get_ident())
        return real_decrypt(self, *args, **kw)

    async def refuse(*_: Any, **__: Any) -> Any:
        raise AssertionError("an in-process cipher call was handed to the Transit pool")

    monkeypatch.setattr(row_seal, "_in_transit_pool", refuse)
    monkeypatch.setattr(AesGcmCipher, "decrypt", decrypt)
    store = _bare_store(cls, cipher)

    _serve_rows(store, rows)
    await store._load_reference_cache()
    assert dict(store._reference_cache["codes"]) == {key: f"value-{key}" for key in _KEYS}
    assert threads, "the read made no cipher call, so nothing was measured"
    assert set(threads) == {threading.get_ident()}
