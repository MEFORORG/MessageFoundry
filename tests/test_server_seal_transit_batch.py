# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The PostgreSQL and SQL Server at-open seal encrypts many cells per Transit request (vault BACKLOG
#6706).

All three stores' seals now encrypt each page in chunks through ``row_seal.seal_chunks``. The two
server ``_seal_surface`` sweeps sealed each cell with its own ``cipher.encrypt``, so under
``vault_transit`` a surface of N legacy values cost N Transit requests. These tests drive the real
``_seal_surface`` of each server store against an in-memory stand-in for its connection, so no
server is needed, and count requests against the batch-answering fake Transit. Synthetic data only.
"""

from __future__ import annotations

import os
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

import pytest

pytest.importorskip("requests", reason="Transit batch tests need the [vault] extra")
pytest.importorskip("hvac", reason="Transit batch tests need the [vault] extra")

from hvac.exceptions import InvalidRequest, UnexpectedError  # type: ignore[import-untyped]

from messagefoundry.store import row_seal
from messagefoundry.store.crypto import BATCH_MAX_ITEMS, AesGcmCipher, cell_aad
from messagefoundry.store.postgres import PostgresStore
from messagefoundry.store.row_seal import seal_chunks
from messagefoundry.store.sqlserver import SqlServerStore
from messagefoundry.store.store import MessageStore
from tests.test_transit_batch import _BatchTransit, _cipher, _write_messages

_ROWS = 200
_LIKE = "mfenc:%"


def _legacy_rows() -> list[dict[str, Any]]:
    """``state`` rows holding legacy plaintext, keyed by (namespace, key)."""
    return [
        {"namespace": "ns", "key": f"k{i}", "value": f"synthetic value {i}"} for i in range(_ROWS)
    ]


def _pending(rows: list[dict[str, Any]], limit: int) -> list[dict[str, Any]]:
    return [
        {"namespace": r["namespace"], "key": r["key"], "v": r["value"]}
        for r in rows
        if r["value"] and not r["value"].startswith("mfenc:")
    ][:limit]


def _limit(sql: str, word: str) -> int:
    """The row limit a page SELECT names after ``word`` (``LIMIT 500`` or ``TOP (500)``)."""
    tail = sql.split(word, 1)[1].strip().lstrip("(")
    return int(tail.split(")")[0].split()[0])


def _tag(row: Any) -> bytes:
    """A row-built AAD, standing in for the queue payload's routing tag."""
    return f"tag/{row['namespace']}/{row['key']}".encode()


def _assert_sealed(
    rows: list[dict[str, Any]], transit: _BatchTransit, aad_of: Callable[[Any], bytes] | None
) -> None:
    opener = _cipher(transit)
    for i, r in enumerate(rows):
        assert r["value"].startswith("mfenc:")
        aad = aad_of(r) if aad_of else cell_aad("state", "value", r["namespace"], r["key"])
        assert opener.decrypt(r["value"], aad=aad) == f"synthetic value {i}"


#: (page size, row-built AAD, Transit requests). One request per cell before the batch path: 200.
#: One page of 500 holds all 200 rows, cut 128 + 72 into two batches; four pages of 50 are one
#: batch each.
_CASES = [(500, None, 2), (50, _tag, 4)]


class _PgConn:
    """The asyncpg connection calls the PostgreSQL seal makes, over a list of rows."""

    def __init__(self, rows: list[dict[str, Any]]) -> None:
        self.rows = rows

    @asynccontextmanager
    async def transaction(self) -> AsyncIterator[None]:
        yield

    async def fetchval(self, sql: str, *params: Any) -> Any:
        assert "keyed_surface" in sql
        return 1  # this open wrote the marker

    async def fetch(self, sql: str, *params: Any) -> list[dict[str, Any]]:
        return _pending(self.rows, _limit(sql, "LIMIT"))

    async def execute(self, sql: str, value: str, namespace: str, key: str) -> None:
        assert sql.startswith("UPDATE state SET value=$1")
        for r in self.rows:
            if (r["namespace"], r["key"]) == (namespace, key):
                r["value"] = value


def _pg_store(conn: _PgConn, transit: _BatchTransit) -> PostgresStore:
    store = object.__new__(PostgresStore)
    store._cipher = _cipher(transit)

    async def surface_keyed(table: str, column: str) -> bool:
        return False

    async def fetchval(sql: str, *params: Any) -> int:
        return len(_pending(conn.rows, _ROWS))

    async def holds_ciphertext(table: str, column: str, like: str) -> bool:
        return False

    async def noop(*args: Any, **kwargs: Any) -> None:
        return None

    @asynccontextmanager
    async def timed_acquire(*, record: bool = True) -> AsyncIterator[_PgConn]:
        yield conn

    store._surface_keyed = surface_keyed  # type: ignore[method-assign]
    store._fetchval = fetchval  # type: ignore[method-assign]
    store._surface_holds_ciphertext = holds_ciphertext  # type: ignore[method-assign]
    store._charge_bound_batch = noop  # type: ignore[method-assign]
    store._timed_acquire = timed_acquire  # type: ignore[method-assign]
    return store


@pytest.mark.parametrize(("batch", "aad_of", "requests"), _CASES)
async def test_the_postgres_seal_seals_many_cells_per_transit_request(
    batch: int, aad_of: Callable[[Any], bytes] | None, requests: int
) -> None:
    transit = _BatchTransit()
    conn = _PgConn(_legacy_rows())
    store = _pg_store(conn, transit)
    sealed = await store._seal_surface(
        "state", "value", _LIKE, aad_cols=("namespace", "key"), aad_of=aad_of, batch=batch
    )
    assert sealed == _ROWS
    assert transit.encrypt_requests == requests
    _assert_sealed(conn.rows, transit, aad_of)


class _MssqlCursor:
    """The aioodbc cursor calls the SQL Server seal makes, over a list of rows."""

    def __init__(self, rows: list[dict[str, Any]]) -> None:
        self.rows = rows
        self.description: list[tuple[str]] = []
        self._result: list[tuple[Any, ...]] = []

    async def execute(self, sql: str, params: tuple[Any, ...] = ()) -> None:
        if sql.startswith("SELECT TOP"):
            self.description = [("namespace",), ("key",), ("v",)]
            self._result = [
                (r["namespace"], r["key"], r["v"]) for r in _pending(self.rows, _limit(sql, "TOP"))
            ]
            return
        assert sql.startswith("UPDATE state SET [value]=?")
        value, namespace, key = params
        for r in self.rows:
            if (r["namespace"], r["key"]) == (namespace, key):
                r["value"] = value

    async def fetchall(self) -> list[tuple[Any, ...]]:
        return self._result


class _MssqlConn:
    async def rollback(self) -> None:
        raise AssertionError("the seal rolled back")


def _mssql_store(cur: _MssqlCursor, transit: _BatchTransit) -> SqlServerStore:
    store = object.__new__(SqlServerStore)
    store._cipher = _cipher(transit)
    conn = _MssqlConn()

    async def surface_keyed(table: str, column: str) -> bool:
        return False

    async def count_unmarked(count_sql: str, *params: str) -> int:
        return len(_pending(cur.rows, _ROWS))

    async def holds_ciphertext(table: str, column: str, like: str) -> bool:
        return False

    async def claim(conn: Any, cur: Any, table: str, column: str) -> bool:
        return True

    async def noop(*args: Any, **kwargs: Any) -> None:
        return None

    @asynccontextmanager
    async def acquire() -> AsyncIterator[_MssqlConn]:
        yield conn

    @asynccontextmanager
    async def cursor(conn: Any) -> AsyncIterator[_MssqlCursor]:
        yield cur

    store._surface_keyed = surface_keyed  # type: ignore[method-assign]
    store._count_unmarked = count_unmarked  # type: ignore[method-assign]
    store._surface_holds_ciphertext = holds_ciphertext  # type: ignore[method-assign]
    store._claim_keyed_surface = claim  # type: ignore[method-assign]
    store._commit = noop  # type: ignore[method-assign]
    store._charge_bound_batch = noop  # type: ignore[method-assign]
    store._acquire = acquire  # type: ignore[method-assign]
    store._cursor = cursor  # type: ignore[method-assign]
    return store


@pytest.mark.parametrize(("batch", "aad_of", "requests"), _CASES)
async def test_the_sqlserver_seal_seals_many_cells_per_transit_request(
    batch: int, aad_of: Callable[[Any], bytes] | None, requests: int
) -> None:
    transit = _BatchTransit()
    cur = _MssqlCursor(_legacy_rows())
    store = _mssql_store(cur, transit)
    sealed = await store._seal_surface(
        "state", "value", _LIKE, aad_cols=("namespace", "key"), aad_of=aad_of, batch=batch
    )
    assert sealed == _ROWS
    assert transit.encrypt_requests == requests
    _assert_sealed(cur.rows, transit, aad_of)


class _CountingBatchCipher:
    """A batch cipher recording how many values each ``encrypt_many`` call carries."""

    batches_now = True

    def __init__(self) -> None:
        self.calls: list[int] = []

    def encrypt(self, plaintext: str, *, aad: bytes | None = None) -> str:
        raise AssertionError("the page went value by value")

    def decrypt(self, stored: str, *, aad: bytes | None = None) -> str:
        raise AssertionError("unused")

    def decrypt_many(self, items: Any) -> list[Any]:
        raise AssertionError("unused")

    def encrypt_many(self, items: Any) -> list[str]:
        self.calls.append(len(items))
        return [f"mfenc:{plaintext}" for plaintext, _aad in items]


async def _chunks(
    cipher: Any, rows: list[dict[str, Any]], *, whole_page: bool = False
) -> list[tuple[int, list[str]]]:
    return [
        (len(chunk), sealed)
        async for chunk, sealed in seal_chunks(
            cipher,
            "state",
            "value",
            rows,
            aad_cols=("namespace", "key"),
            local_whole_page=whole_page,
        )
    ]


async def test_a_page_is_one_cipher_call_per_batch_bound() -> None:
    """One cipher call carries at most ``BATCH_MAX_ITEMS`` values: a page of 200 is two calls, 128
    then 72. This checks call sizes only; it neither reaches the Transit pool nor cancels a seal."""
    cipher = _CountingBatchCipher()
    rows = _pending(_legacy_rows(), _ROWS)
    chunks = await _chunks(cipher, rows)
    assert cipher.calls == [BATCH_MAX_ITEMS, _ROWS - BATCH_MAX_ITEMS]
    assert [n for n, _ in chunks] == cipher.calls
    assert [v for _, sealed in chunks for v in sealed] == [f"mfenc:{r['v']}" for r in rows]


async def test_chunks_cost_no_more_transit_requests_than_one_call_over_the_page() -> None:
    """Chunks cut by item count alone split the cipher's own character-bound runs twice: 500
    values of about 3 KB were 4 requests in one call and 7 when cut at 128 items."""
    rows = [{"namespace": "ns", "key": f"k{i}", "v": f"{i:04d}" + "x" * 3046} for i in range(500)]
    whole = _BatchTransit()
    _cipher(whole).encrypt_many(
        [(r["v"], cell_aad("state", "value", r["namespace"], r["key"])) for r in rows]
    )
    chunked = _BatchTransit()
    chunks = await _chunks(_cipher(chunked), rows)
    assert sum(n for n, _ in chunks) == len(rows)
    assert chunked.encrypt_requests == whole.encrypt_requests == len(chunks)


class _SingleValueCipher:
    """A cipher with no batch path whose calls wait on I/O, logging each encrypt into a log the
    writes share."""

    blocks_on_io = True

    def __init__(self, log: list[str]) -> None:
        self.log = log

    def encrypt(self, plaintext: str, *, aad: bytes | None = None) -> str:
        self.log.append("encrypt")
        return f"mfenc:{plaintext}"

    def decrypt(self, stored: str, *, aad: bytes | None = None) -> str:
        raise AssertionError("unused")


class _LoggedPgConn(_PgConn):
    def __init__(self, rows: list[dict[str, Any]], log: list[str]) -> None:
        super().__init__(rows)
        self.log = log

    async def execute(self, sql: str, value: str, namespace: str, key: str) -> None:
        self.log.append("write")
        await super().execute(sql, value, namespace, key)


class _LoggedMssqlCursor(_MssqlCursor):
    def __init__(self, rows: list[dict[str, Any]], log: list[str]) -> None:
        super().__init__(rows)
        self.log = log

    async def execute(self, sql: str, params: tuple[Any, ...] = ()) -> None:
        if sql.startswith("UPDATE"):
            self.log.append("write")
        await super().execute(sql, params)


@pytest.mark.parametrize("backend", ["postgres", "sqlserver"])
async def test_a_single_value_cipher_writes_each_value_before_the_next_call(backend: str) -> None:
    """A cipher with no batch path whose calls wait on I/O gets one value per chunk, so on the
    server stores each encrypt is followed by its write. An in-process cipher is not covered by
    this, and the real Transit cipher sending alone is covered only at the chunk level."""
    log: list[str] = []
    store: PostgresStore | SqlServerStore
    if backend == "postgres":
        conn = _LoggedPgConn(_legacy_rows(), log)
        store = _pg_store(conn, _BatchTransit())
    else:
        cur = _LoggedMssqlCursor(_legacy_rows(), log)
        store = _mssql_store(cur, _BatchTransit())
    store._cipher = _SingleValueCipher(log)  # type: ignore[assignment]
    sealed = await store._seal_surface("state", "value", _LIKE, aad_cols=("namespace", "key"))
    assert sealed == _ROWS
    assert log == ["encrypt", "write"] * _ROWS


async def test_an_aes_gcm_page_makes_no_sizing_copy(monkeypatch: pytest.MonkeyPatch) -> None:
    """Under AES-GCM the page is cut whole and none of the three ``row_seal`` sizing helpers is
    called. This watches those three names only, not an encode added anywhere else."""
    sized: list[object] = []

    def counted(*args: Any) -> int:
        sized.append(args)
        return 0

    for name in ("b64_chars", "batch_chars", "_batch_cost"):
        monkeypatch.setattr(row_seal, name, counted)
    cipher = AesGcmCipher(bytearray(os.urandom(32)), write_v2=True)
    rows = _pending(_legacy_rows(), _ROWS)
    chunks = await _chunks(cipher, rows, whole_page=True)
    assert sized == []
    assert [n for n, _ in chunks] == [_ROWS]
    # Control: a batch cipher's page is sized through the same patched names.
    await _chunks(_cipher(_BatchTransit()), rows)
    assert len(sized) >= _ROWS


def _refusing(transit: _BatchTransit, error: Exception) -> None:
    """Make ``transit`` answer every batch encrypt with ``error`` and serve single values."""
    real = transit.encrypt_data

    def answer(**kw: Any) -> dict[str, Any]:
        if kw.get("batch_input") is not None:
            transit.encrypt_requests += 1
            raise error
        return real(**kw)

    transit.encrypt_data = answer  # type: ignore[method-assign]


async def test_a_transit_cipher_sending_alone_gets_one_value_per_chunk() -> None:
    """Once Transit refuses a batch other than with a 400, the cipher sends values alone, and
    every later chunk is one value, so each request is followed by its write."""
    transit = _BatchTransit()
    _refusing(transit, UnexpectedError("413 Request Entity Too Large"))
    cipher = _cipher(transit)
    assert cipher.batches_now
    chunks = await _chunks(cipher, _pending(_legacy_rows(), _ROWS))
    assert not cipher.batches_now
    assert [n for n, _ in chunks] == [BATCH_MAX_ITEMS] + [1] * (_ROWS - BATCH_MAX_ITEMS)


async def test_a_vault_400_leaves_batching_on_and_chunks_batched() -> None:
    """Vault's 400 to a batch is sent value by value, but batching stays on, so later chunks are
    still cut as batches."""
    transit = _BatchTransit()
    _refusing(transit, InvalidRequest("synthetic batch 400"))
    cipher = _cipher(transit)
    chunks = await _chunks(cipher, _pending(_legacy_rows(), _ROWS))
    assert cipher.batches_now
    assert [n for n, _ in chunks] == [BATCH_MAX_ITEMS, _ROWS - BATCH_MAX_ITEMS]
    assert transit.encrypt_requests == 2 + _ROWS


class _LoggedAesGcm(AesGcmCipher):
    log: list[str]

    def encrypt(self, plaintext: str, *, aad: bytes | None = None) -> str:
        self.log.append("encrypt")
        return super().encrypt(plaintext, aad=aad)


@pytest.mark.parametrize("backend", ["postgres", "sqlserver"])
async def test_a_server_seal_under_aes_gcm_writes_after_each_encrypt(
    backend: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An in-process cipher keeps the server stores' shape from before batching: one value per
    chunk, its write awaited before the next encrypt. It checks that order, not memory held."""

    async def no_reservation(*args: Any) -> None:
        return None  # the bound's persisted total needs a real database; this test has none

    monkeypatch.setattr(f"messagefoundry.store.{backend}.reserve_invocations_ahead", no_reservation)
    log: list[str] = []
    store: PostgresStore | SqlServerStore
    if backend == "postgres":
        conn = _LoggedPgConn(_legacy_rows(), log)
        store = _pg_store(conn, _BatchTransit())
    else:
        cur = _LoggedMssqlCursor(_legacy_rows(), log)
        store = _mssql_store(cur, _BatchTransit())
    cipher = _LoggedAesGcm(bytearray(os.urandom(32)), write_v2=True)
    cipher.log = log
    store._cipher = cipher
    sealed = await store._seal_surface("state", "value", _LIKE, aad_cols=("namespace", "key"))
    assert sealed == _ROWS
    assert log == ["encrypt", "write"] * _ROWS


async def test_the_sqlite_seal_writes_a_whole_page_per_update_under_aes_gcm(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An in-process cipher keeps SQLite's shape from before batching: the whole page of up to
    500 rows in one ``_update_every_row`` call."""
    db = tmp_path / "store.db"
    await _write_messages(db, _ROWS)  # keyless: legacy plaintext the keyed open seals
    sizes: list[int] = []
    real = MessageStore._update_every_row

    async def counted(self: MessageStore, sql: str, params: Any, *args: Any, **kw: Any) -> None:
        sizes.append(len(params))
        await real(self, sql, params, *args, **kw)

    monkeypatch.setattr(MessageStore, "_update_every_row", counted)
    store = await MessageStore.open(db, cipher=AesGcmCipher(bytearray(os.urandom(32))))
    await store.close()
    assert sizes
    assert max(sizes) == _ROWS  # 200 messages: one page per surface
