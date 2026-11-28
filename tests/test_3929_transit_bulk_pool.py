# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #3929, vault BACKLOG #8331 item 2: bulk Transit walks run on their own bounded pool.

Before this, a store call that makes many Transit round trips in one go (an audit chain walk, a
reference cache decode, SQL Server's state cache load, an at-open seal batch) ran through
``cipher_call`` on the row seal pool of ``TRANSIT_SEAL_WORKERS`` threads, so a few of them held every
thread and the auth path's row seal checks queued behind them. They now go through
``cipher_bulk_call``, on a separate pool sized by ``[store].transit_bulk_workers``.

Every cipher here is a fake; no Vault is reached and no message is real."""

from __future__ import annotations

import asyncio
import inspect
import threading
from collections.abc import AsyncIterator, Iterator
from pathlib import Path
from typing import Any, cast

import pytest
from pydantic import ValidationError

from messagefoundry.config.settings import StoreSettings
from messagefoundry.store import row_seal
from messagefoundry.store import store as store_module
from messagefoundry.store.crypto import Cipher, CipherUnavailableError
from messagefoundry.store.crypto_transit import build_transit_cipher
from messagefoundry.store.row_seal import (
    TRANSIT_BULK_THREAD_PREFIX,
    TRANSIT_BULK_WORKERS_DEFAULT,
    TRANSIT_BULK_WORKERS_MAX,
    TRANSIT_SEAL_THREAD_PREFIX,
    TRANSIT_SEAL_WORKERS,
    USER_KIND,
    TransitRowSealer,
    checked_transit_bulk_workers,
    cipher_bulk_call,
    configure_transit_bulk_workers,
    seal_chunks,
    shutdown_transit_pools,
)
from messagefoundry.store.store import MessageStore
from tests._transit_seal_fake import Clock, FakeBackend
from tests.test_crypto_transit import _use_fake

FIELDS: list[tuple[str, object]] = [("user_id", "u-1"), ("n", 3)]
# How long a seal check may take while the bulk walks hold their threads. Far above a free pool's
# hand-off, far below the walks' own hold, which only the test's release ends.
_CHECK_DEADLINE = 3.0


@pytest.fixture(autouse=True)
async def _fresh_pools() -> AsyncIterator[None]:
    await shutdown_transit_pools()
    configure_transit_bulk_workers(TRANSIT_BULK_WORKERS_DEFAULT)
    yield
    await shutdown_transit_pools()
    configure_transit_bulk_workers(TRANSIT_BULK_WORKERS_DEFAULT)


class _Gate:
    """Counts the calls running at once and holds each until released."""

    def __init__(self) -> None:
        self.release = threading.Event()
        self.lock = threading.Lock()
        self.running = 0
        self.peak = 0
        self.thread_names: list[str] = []

    def hold(self) -> None:
        with self.lock:
            self.running += 1
            self.peak = max(self.peak, self.running)
            self.thread_names.append(threading.current_thread().name)
        try:
            if not self.release.wait(10):
                raise AssertionError("the test never released a held call")
        finally:
            with self.lock:
                self.running -= 1

    async def until_running(self, count: int) -> None:
        for _ in range(500):
            if self.running >= count:
                return
            await asyncio.sleep(0.01)
        raise AssertionError(f"{self.running} calls running, expected {count}")


class _HeldTransitCipher:
    """A cipher that says it blocks on I/O, as ``TransitCipher`` does, whose encrypts wait on a gate.
    It is no ``BatchCipher``, so :func:`seal_chunks` seals each value in a call of its own."""

    blocks_on_io = True
    encrypts = True

    def __init__(self, gate: _Gate) -> None:
        self._gate = gate

    def encrypt(self, plaintext: str, *, aad: bytes | None = None) -> str:
        self._gate.hold()
        return "mfenc:v3:sealed"

    def decrypt(self, stored: str, *, aad: bytes | None = None) -> str:
        raise AssertionError("not reached")


async def _seal_one(cipher: _HeldTransitCipher, n: int) -> None:
    rows = [{"id": n, "v": f"synthetic value {n}"}]
    async for _chunk, sealed in seal_chunks(
        cast("Cipher", cipher), "messages", "raw", rows, aad_cols=("id",), local_whole_page=False
    ):
        assert sealed == ["mfenc:v3:sealed"]


async def test_a_saturated_bulk_walk_does_not_starve_a_row_seal_check() -> None:
    """The defect, measured: more held at-open seal batches than the seal pool has threads, then a
    row seal check, the sign-in path's call. Before the bulk pool, the batches held all
    ``TRANSIT_SEAL_WORKERS`` seal threads and the check waited for one past its deadline."""
    gate = _Gate()
    cipher = _HeldTransitCipher(gate)
    walks = [asyncio.create_task(_seal_one(cipher, n)) for n in range(TRANSIT_SEAL_WORKERS + 2)]
    try:
        await gate.until_running(TRANSIT_BULK_WORKERS_DEFAULT)
        await asyncio.sleep(0.2)  # let any walk that could still start take its thread
        backend = FakeBackend()
        sealer = TransitRowSealer(backend, clock=Clock())
        stored = await asyncio.wait_for(sealer.seal_async(USER_KIND, FIELDS), _CHECK_DEADLINE)
        held = sealer.verify_held_async(USER_KIND, FIELDS, stored, fresh=True)
        assert await asyncio.wait_for(held, _CHECK_DEADLINE) is True
        assert all(n.startswith(TRANSIT_SEAL_THREAD_PREFIX) for n in backend.thread_names)
        # The walks are still held, so the check did not run after them.
        assert gate.running == TRANSIT_BULK_WORKERS_DEFAULT
    finally:
        gate.release.set()
        await asyncio.gather(*walks)
    assert gate.peak == TRANSIT_BULK_WORKERS_DEFAULT
    assert all(n.startswith(TRANSIT_BULK_THREAD_PREFIX) for n in gate.thread_names)


async def test_the_bulk_pool_takes_its_configured_size() -> None:
    configure_transit_bulk_workers(3)
    gate = _Gate()
    cipher = _HeldTransitCipher(gate)
    walks = [asyncio.create_task(cipher_bulk_call(cipher, gate.hold)) for _ in range(6)]
    try:
        await gate.until_running(3)
        await asyncio.sleep(0.2)
        assert gate.running == 3
    finally:
        gate.release.set()
        await asyncio.gather(*walks)
    assert gate.peak == 3
    assert all(n.startswith(TRANSIT_BULK_THREAD_PREFIX) for n in gate.thread_names)


async def test_an_in_process_cipher_runs_a_bulk_call_inline() -> None:
    class _InProcess:
        pass

    def where() -> int:
        return threading.get_ident()

    assert await cipher_bulk_call(_InProcess(), where) == threading.get_ident()


@pytest.mark.parametrize("value", [0, -1, TRANSIT_BULK_WORKERS_MAX + 1, True, 1.5, "2", None])
def test_a_nonsensical_bulk_pool_size_is_refused(value: object) -> None:
    with pytest.raises(ValueError):
        checked_transit_bulk_workers(value)
    with pytest.raises(ValueError):
        configure_transit_bulk_workers(value)
    assert row_seal._BULK_POOL.size == TRANSIT_BULK_WORKERS_DEFAULT  # a refusal changes nothing


@pytest.mark.parametrize("value", [1, TRANSIT_BULK_WORKERS_MAX])
def test_the_bounds_are_accepted(value: int) -> None:
    assert checked_transit_bulk_workers(value) == value


@pytest.mark.parametrize("value", [0, -1, TRANSIT_BULK_WORKERS_MAX + 1, True])
def test_the_setting_refuses_a_nonsensical_size(value: object) -> None:
    with pytest.raises(ValidationError):
        StoreSettings.model_validate({"transit_bulk_workers": value})


def test_the_setting_matches_the_pool_constants() -> None:
    assert StoreSettings().transit_bulk_workers == TRANSIT_BULK_WORKERS_DEFAULT
    assert StoreSettings(transit_bulk_workers=1).transit_bulk_workers == 1
    assert (
        StoreSettings(transit_bulk_workers=TRANSIT_BULK_WORKERS_MAX).transit_bulk_workers
        == TRANSIT_BULK_WORKERS_MAX
    )


def test_building_the_transit_cipher_sizes_the_bulk_pool(monkeypatch: pytest.MonkeyPatch) -> None:
    _use_fake(monkeypatch)
    build_transit_cipher(StoreSettings(transit_bulk_workers=5))
    assert row_seal._BULK_POOL.size == 5


async def test_shutdown_waits_for_a_running_call_off_the_loop_then_rebuilds() -> None:
    gate = _Gate()
    cipher = _HeldTransitCipher(gate)
    backend = FakeBackend()
    sealer = TransitRowSealer(backend, clock=Clock())
    await sealer.seal_async(USER_KIND, FIELDS)  # builds the seal pool
    seal_pool = row_seal._transit_pool()
    walk = asyncio.create_task(cipher_bulk_call(cipher, gate.hold))
    await gate.until_running(1)
    bulk_pool = row_seal._transit_bulk_pool()
    stopping = asyncio.create_task(shutdown_transit_pools())
    ticks = 0
    for _ in range(20):  # the loop keeps serving while the shutdown waits on the held call
        await asyncio.sleep(0.01)
        ticks += 1
    assert ticks == 20 and not stopping.done() and not walk.done()
    gate.release.set()
    await stopping
    await walk
    for pool in (seal_pool, bulk_pool):
        with pytest.raises(RuntimeError):
            pool.submit(int)
    # The next use builds a new pool of each.
    assert row_seal._transit_bulk_pool() is not bulk_pool
    assert row_seal._transit_pool() is not seal_pool
    await sealer.seal_async(USER_KIND, FIELDS)


async def test_a_shut_pool_refuses_a_bulk_call_as_an_outage(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from concurrent.futures import ThreadPoolExecutor

    closed = ThreadPoolExecutor(max_workers=1)
    closed.shutdown()
    monkeypatch.setattr(row_seal, "_transit_bulk_pool", lambda: closed)
    with pytest.raises(CipherUnavailableError):
        await cipher_bulk_call(_HeldTransitCipher(_Gate()), int)


async def test_the_sqlite_chain_walk_runs_on_the_bulk_pool(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class _BlockingMac:
        blocks_on_io = True

    names: list[str] = []
    real = store_module.verify_audit_rows

    def recording(rows: Any, **kwargs: Any) -> Any:
        names.append(threading.current_thread().name)
        return real(rows, **{**kwargs, "mac_fn": None})

    store = await MessageStore.open(tmp_path / "a.db")
    try:
        monkeypatch.setattr(store_module, "verify_audit_rows", recording)
        monkeypatch.setattr(store, "_audit_mac_fn", _BlockingMac())
        ok, msg = await store.verify_audit_chain()
        assert ok, msg
    finally:
        await store.close()
    assert len(names) == 1 and names[0].startswith(TRANSIT_BULK_THREAD_PREFIX)


def _source_lines(obj: Any) -> Iterator[str]:
    yield from inspect.getsource(obj).splitlines()


def test_the_server_backends_route_their_bulk_walks_to_the_bulk_pool() -> None:
    """The Postgres and SQL Server twins of the walks above, read from their source: none of these
    methods hands its walk to the seal pool's ``cipher_call``."""
    from messagefoundry.store.postgres import PostgresStore
    from messagefoundry.store.sqlserver import SqlServerStore

    walks = [
        (PostgresStore, "verify_audit_chain"),
        (PostgresStore, "_read_active_reference_snapshots"),
        (PostgresStore, "converge_reference_cache"),
        (SqlServerStore, "verify_audit_chain"),
        (SqlServerStore, "_load_state_cache"),
        (SqlServerStore, "_read_active_reference_snapshots"),
        (SqlServerStore, "converge_reference_cache"),
        (MessageStore, "verify_audit_chain"),
    ]
    for cls, name in walks:
        lines = list(_source_lines(getattr(cls, name)))
        assert any("await cipher_bulk_call(" in line for line in lines), (cls.__name__, name)
        assert not any("await cipher_call(" in line for line in lines), (cls.__name__, name)
    # The roll's walk: the call that opens before its verify_audit_rows argument is the bulk one.
    roll = inspect.getsource(store_module.roll_audit_key_range)
    before_walk = roll[: roll.index("verify_audit_rows,")]
    assert before_walk.rfind("await cipher_bulk_call(") > before_walk.rfind("await cipher_call(")


async def test_a_bounded_shutdown_leaves_a_running_walk_to_finish() -> None:
    gate = _Gate()
    walk = asyncio.create_task(cipher_bulk_call(_HeldTransitCipher(gate), gate.hold))
    await gate.until_running(1)
    pool = row_seal._transit_bulk_pool()
    try:
        assert await shutdown_transit_pools(0.05) is False
        assert not walk.done()
        with pytest.raises(RuntimeError):
            pool.submit(int)  # detached and shut: it takes nothing new
    finally:
        gate.release.set()
        await walk
    assert await shutdown_transit_pools(0.05) is True  # nothing left to wait for


async def _engine(path: Path) -> Any:
    from messagefoundry.config.settings import EgressSettings
    from messagefoundry.pipeline.engine import Engine

    return await Engine.create(path, egress_settings=EgressSettings(deny_by_default=False))


async def test_the_engine_stop_shuts_the_pools_down_after_the_store_closes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from messagefoundry.pipeline import engine as engine_module

    # Engines another test left unstopped hold leases of their own; this one must be the last.
    monkeypatch.setattr(row_seal, "_leases", 0)
    order: list[str] = []
    eng = await _engine(tmp_path / "s.db")
    real_close = eng.store.close

    async def close() -> None:
        order.append("store closed")
        await real_close()

    async def shutdown(timeout: float | None = None) -> bool:
        order.append(f"pools shut down within {timeout}")
        return False

    monkeypatch.setattr(eng.store, "close", close)
    monkeypatch.setattr(row_seal, "shutdown_transit_pools", shutdown)
    try:
        await eng.stop()
    finally:
        if order[:1] != ["store closed"]:
            await real_close()
    assert order == [
        "store closed",
        f"pools shut down within {engine_module._TRANSIT_POOL_DRAIN_SECONDS}",
    ]
    await eng.stop()  # a second stop releases nothing more
    assert row_seal._leases == 0


async def test_one_engine_stop_leaves_the_pools_another_engine_still_uses(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Two engines in one process share the seal pool. One stopping must not detach it: before
    the leases, it did, the other engine's next calls built a second pool, and more Transit calls
    than ``TRANSIT_SEAL_WORKERS`` ran at once."""
    monkeypatch.setattr(row_seal, "_leases", 0, raising=False)
    first = await _engine(tmp_path / "a.db")
    second = await _engine(tmp_path / "b.db")
    gate = _Gate()
    cipher = _HeldTransitCipher(gate)
    held = [
        asyncio.create_task(row_seal.cipher_call(cipher, gate.hold))
        for _ in range(TRANSIT_SEAL_WORKERS)
    ]
    later: list[asyncio.Task[None]] = []
    try:
        await gate.until_running(TRANSIT_SEAL_WORKERS)
        pool = row_seal._transit_pool()
        await first.stop()
        assert row_seal._transit_pool() is pool, "the stop detached a pool still in use"
        later = [asyncio.create_task(row_seal.cipher_call(cipher, gate.hold)) for _ in range(4)]
        await asyncio.sleep(0.3)  # time for a second pool, were there one, to start them
        assert gate.running == TRANSIT_SEAL_WORKERS
    finally:
        gate.release.set()
        await asyncio.gather(*held, *later)
        await second.stop()
    assert gate.peak == TRANSIT_SEAL_WORKERS


async def test_a_lease_shuts_the_pools_only_when_the_last_is_released(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(row_seal, "_leases", 0)
    one, two = row_seal.TransitPoolLease(), row_seal.TransitPoolLease()
    pool = row_seal._transit_bulk_pool()
    assert await one.release(1.0) is True
    assert await one.release(1.0) is True  # released once only
    assert row_seal._transit_bulk_pool() is pool
    assert await two.release(1.0) is True
    with pytest.raises(RuntimeError):
        pool.submit(int)  # the last release shut it
    assert row_seal._leases == 0


async def test_a_queued_call_is_cancelled_at_shutdown_and_never_runs() -> None:
    configure_transit_bulk_workers(1)
    gate = _Gate()
    cipher = _HeldTransitCipher(gate)
    ran: list[str] = []
    running = asyncio.create_task(cipher_bulk_call(cipher, gate.hold))
    await gate.until_running(1)
    queued = asyncio.create_task(cipher_bulk_call(cipher, ran.append, "queued"))
    await asyncio.sleep(0.05)
    try:
        assert await shutdown_transit_pools(0.05) is False  # the running call is still held
    finally:
        gate.release.set()
    await running
    with pytest.raises(asyncio.CancelledError):
        await queued
    assert ran == []
