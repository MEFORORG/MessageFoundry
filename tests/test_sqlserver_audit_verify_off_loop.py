# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""SQL Server ``verify_audit_chain`` walks the chain off the event loop (BACKLOG #5741).

Each row MAC can be a blocking Transit round trip, so a walk on the loop would stall that loop for
its whole length, during engine start or an ``audit-verify`` run. Only the walk moves: the rows are
still read whole and built on the loop, so nothing here says the verify is bounded.

Offline: the store has no connection and its ``_fetchall`` serves synthetic rows. What only the
hosted SQL Server leg can prove is the real query.
"""

from __future__ import annotations

import asyncio
import threading
from collections.abc import Callable, Iterator
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from typing import Any

import pytest

from messagefoundry.store.store import (
    AUDIT_KEY_EPOCH_ACTION,
    AUDIT_TRANSIT_KEY_ID,
    AuditVerdict,
    _AuditWalkStopped,
    audit_epoch_detail,
    audit_genesis_detail,
    verify_audit_rows,
)
from tests.test_asvs_transit_audit_mac_server_backends import (
    _bare,
    chained_rows,
    serve_rows,
    stub_transit_mac,
)
from tests.test_transit_client_threads import _cipher

#: Only stops a broken test hanging; no passing or failing verdict depends on it.
_HANG_GUARD_SECONDS = 30.0


def _chain() -> list[dict[str, Any]]:
    """A valid Transit-keyed chain: a genesis row, then ordinary rows."""
    genesis = (AUDIT_KEY_EPOCH_ACTION, audit_genesis_detail(AUDIT_TRANSIT_KEY_ID))
    return chained_rows(
        [genesis, ("act", "two"), ("act", "three"), ("act", "four")], mac=stub_transit_mac
    )


def _store(rows: list[dict[str, Any]], mac: Callable[[bytes], str]) -> Any:
    store = _bare("sqlserver", mac_fn=mac)
    serve_rows(store, rows)
    return store


def _facts(verdict: AuditVerdict) -> tuple[Any, ...]:
    """Everything a verdict carries: ``==`` on it alone ignores the flags and the row count."""
    return (
        verdict[0],
        verdict[1],
        verdict.key_unavailable,
        verdict.keyless_walk,
        verdict.prefix_break,
        verdict.rows,
    )


async def test_a_slow_mac_does_not_block_the_event_loop() -> None:
    """Each MAC needs the loop to run a coroutine. No clock: a walk on the loop fails at once."""
    loop = asyncio.get_running_loop()
    loop_thread = threading.get_ident()
    calls = 0

    def gated_mac(data: bytes, /) -> str:
        nonlocal calls
        assert threading.get_ident() != loop_thread, "the walk ran on the event loop"
        asyncio.run_coroutine_threadsafe(asyncio.sleep(0), loop).result()
        calls += 1
        return stub_transit_mac(data)

    rows = _chain()
    verdict = await _store(rows, gated_mac).verify_audit_chain()

    assert verdict[0] is True
    assert calls == len(rows)


class _GatedVerifier:
    """The shipped verifier, counting ``verify`` calls and holding the first until released."""

    def __init__(self, real: Any, loop: asyncio.AbstractEventLoop) -> None:
        self._real = real
        self._loop = loop
        self.calls = 0
        self.threads: set[int] = set()
        self.entered = asyncio.Event()
        self.proceed = threading.Event()

    def __call__(self, data: bytes, /) -> str:
        return str(self._real(data))

    def verify(self, data: bytes, stored: str, /) -> bool:
        self.calls += 1
        self.threads.add(threading.get_ident())
        self._loop.call_soon_threadsafe(self.entered.set)
        # A hang guard only: every test sets this as soon as it has acted.
        assert self.proceed.wait(_HANG_GUARD_SECONDS)
        return bool(self._real.verify(data, stored))


def _transit_setup(
    loop: asyncio.AbstractEventLoop, length: int = 20
) -> tuple[Any, Any, _GatedVerifier, list[dict[str, Any]]]:
    """A store over a real Transit cipher with a fake client, and a chain that cipher MACed."""
    cipher, built = _cipher()
    real = cipher.audit_mac_fn()
    actions: list[tuple[str, str | None]] = [
        (AUDIT_KEY_EPOCH_ACTION, audit_genesis_detail(AUDIT_TRANSIT_KEY_ID))
    ]
    actions += [("act", str(n)) for n in range(length - 1)]
    rows = chained_rows(actions, mac=real)
    gate = _GatedVerifier(real, loop)
    store = _store(rows, gate)
    store._cipher = cipher
    return store, built, gate, rows


@contextmanager
def _one_worker(loop: asyncio.AbstractEventLoop) -> Iterator[None]:
    """A one-thread default executor, so a later submit runs only after the walk has finished. The
    loop is shared between tests, so it gets a fresh default executor afterwards."""
    try:
        with ThreadPoolExecutor(max_workers=1) as executor:
            loop.set_default_executor(executor)
            yield
    finally:
        loop.set_default_executor(ThreadPoolExecutor())


async def _worker_done(loop: asyncio.AbstractEventLoop) -> None:
    """Returns once the one-worker executor has finished the walk, without reading a clock."""
    await loop.run_in_executor(None, lambda: None)


async def test_the_shipped_verifier_runs_off_the_loop_and_its_client_closes_after_the_walk() -> (
    None
):
    loop = asyncio.get_running_loop()
    store, built, gate, rows = _transit_setup(loop, length=4)
    gate.proceed.set()
    with _one_worker(loop):
        verdict = await store.verify_audit_chain()
        await _worker_done(loop)
        # Read while the worker thread is alive, so its exit cannot be what closed the client.
        assert [client.adapter.closed for client in built] == [0, 1]

    assert verdict[0] is True
    assert gate.calls == len(rows)
    assert threading.get_ident() not in gate.threads


async def test_cancel_and_close_stop_transit_calls_and_close_the_workers_client() -> None:
    loop = asyncio.get_running_loop()
    store, built, gate, rows = _transit_setup(loop)
    with _one_worker(loop):
        task = asyncio.create_task(store.verify_audit_chain())
        await gate.entered.wait()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        store._cipher.close_connections()  # what store.close() does next
        gate.proceed.set()
        await _worker_done(loop)
        # Every client the worker used, the one rebuilt for the in-flight call included.
        assert all(client.adapter.closed == 1 for client in built[1:])
        assert len(built) >= 2

    assert gate.calls == 1, f"{gate.calls} of {len(rows)} rows were verified after the cancel"


def test_a_stopped_walk_raises_and_makes_no_mac_call() -> None:
    calls = 0

    def counting_mac(data: bytes, /) -> str:
        nonlocal calls
        calls += 1
        return stub_transit_mac(data)

    with pytest.raises(_AuditWalkStopped):
        verify_audit_rows(
            _chain(), mac_keys={}, mac_fn=counting_mac, capable=True, should_stop=lambda: True
        )
    assert calls == 0


def test_a_stop_at_a_key_range_row_comes_before_its_handover_mac() -> None:
    """The handover tags are checked after the row loop, so the row check alone would miss them."""
    closes = {
        "key_id": AUDIT_TRANSIT_KEY_ID,
        "from_seq": 1,
        "to_seq": 2,
        "rows": 2,
        "digest": "0" * 64,
        "prev_hash": "",
    }
    detail = audit_epoch_detail("synthetic-next-key", closes, (None, stub_transit_mac))
    genesis = (AUDIT_KEY_EPOCH_ACTION, audit_genesis_detail(AUDIT_TRANSIT_KEY_ID))
    rows = chained_rows(
        [genesis, ("act", "two"), (AUDIT_KEY_EPOCH_ACTION, detail)], mac=stub_transit_mac
    )
    calls = 0
    checks = 0
    calls_at_stop = -1

    def counting_mac(data: bytes, /) -> str:
        nonlocal calls
        calls += 1
        return stub_transit_mac(data)

    def stop_after_the_rows() -> bool:
        nonlocal checks, calls_at_stop
        checks += 1
        if checks > len(rows):
            calls_at_stop = calls
            return True
        return False

    with pytest.raises(_AuditWalkStopped):
        verify_audit_rows(
            rows, mac_keys={}, mac_fn=counting_mac, capable=True, should_stop=stop_after_the_rows
        )
    assert calls == calls_at_stop


@pytest.mark.parametrize("tamper", [False, True], ids=["good-chain", "tampered-chain"])
def test_a_stop_check_that_never_fires_changes_nothing(tamper: bool) -> None:
    rows = _chain()
    if tamper:
        rows[2]["detail"] = "rewritten"
    plain = verify_audit_rows(rows, mac_keys={}, mac_fn=stub_transit_mac, capable=True)
    for should_stop in (None, lambda: False):
        checked = verify_audit_rows(
            rows, mac_keys={}, mac_fn=stub_transit_mac, capable=True, should_stop=should_stop
        )
        assert _facts(checked) == _facts(plain)


@pytest.mark.parametrize("tamper", [False, True], ids=["good-chain", "tampered-chain"])
async def test_the_verdict_is_the_shared_walks_verdict(tamper: bool) -> None:
    rows = _chain()
    if tamper:
        rows[2]["detail"] = "rewritten"

    verdict = await _store(rows, stub_transit_mac).verify_audit_chain()
    direct = verify_audit_rows(rows, mac_keys={}, mac_fn=stub_transit_mac, capable=True)

    assert verdict[0] is (not tamper)
    assert _facts(verdict) == _facts(direct)


async def test_every_comparator_argument_still_reaches_the_walk() -> None:
    rows = _chain()
    head = rows[-1]["row_hash"]
    store = _store(rows, stub_transit_mac)

    assert (await store.verify_audit_chain(expected_anchor=(len(rows), head)))[0] is True
    assert (await store.verify_audit_chain(expected_anchor=(len(rows) + 1, head)))[0] is False
    cut = await store.verify_audit_chain(expected_prefix=(len(rows) + 1, head))
    assert cut[0] is False and cut.prefix_break is True
    assert (await store.verify_audit_chain(expected_rows=[(2, "not-the-hash")]))[0] is False


async def test_a_mac_failure_still_raises_to_the_caller() -> None:
    """A walk that could not run must not turn into a verdict when it crosses the thread."""

    class _MacDown(RuntimeError):
        pass

    def failing_mac(data: bytes, /) -> str:
        raise _MacDown

    with pytest.raises(_MacDown):
        await _store(_chain(), failing_mac).verify_audit_chain()
