# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""BACKLOG #1052 (ASVS 13.2.6) — every store pooled-connection borrow is BOUNDED.

``[store].connect_timeout`` bounds the login and ``[store].command_timeout`` the statement. Neither
bounds the WAIT for a free pooled connection, and that wait was unbounded at three sites: the SQL
Server store's ``_acquire``, the Postgres store's ``_timed_acquire`` (and the three convenience
reads that bypassed it via ``self._pool.fetch``, which acquires internally with no timeout), and the
throwaway pool a ``DatabaseRef`` reference sync opens. On a first deployment against a server
backend, a pool-exhausted or unresponsive database would block the acquiring task forever with the
queue backing up behind it — unlike the DATABASE connector's borrow, which ``acquire_timeout``
already capped at 30 s.

**These tests need no database.** Both stores are built with ``__new__`` and handed a fake pool, the
existing driverless idiom in ``test_backlog348_cancel_dirty_release.py``. That matters here more than
usual: a local pytest silently skips the SQL Server and Postgres legs, so a bound proved only against
a live server would be a bound nobody local can verify.

The salvage arms are the ones worth reading. A bound that abandons a borrow mid-flight would be a
slow leak of the very resource it protects — the pool marks a connection in-use before handing it
over, so an abandoned borrow leaves a connection nobody holds and nobody can return, permanently
shrinking a pool that is already wedged. ``asyncio.wait_for`` alone cannot avoid that: on expiry it
cancels the borrow, and a cancellation landing in the same loop iteration the borrow resolves
discards the connection. Hence shield-then-cancel-then-salvage.
"""

from __future__ import annotations

import asyncio
import re
import types
from pathlib import Path
from typing import Any

import pytest

from messagefoundry.config.settings import StoreSettings
from messagefoundry.store.base import (
    DEFAULT_STORE_ACQUIRE_TIMEOUT,
    StoreAcquireTimeout,
    acquire_pooled,
)
from messagefoundry.store.pool_metrics import AcquireWaitHistogram

FAST = 0.05  # a timeout short enough to keep the suite quick, long enough not to be flaky


class _Conn:
    def __init__(self, name: str = "conn") -> None:
        self.name = name
        self._conn = types.SimpleNamespace(timeout=None)  # the pyodbc handle SqlServerStore pokes

    @property
    def closed(self) -> bool:
        return self._conn is None


class _HangingPool:
    """A pool whose acquire never returns — an exhausted pool or an unresponsive database."""

    def __init__(self) -> None:
        self.released: list[Any] = []

    async def acquire(self) -> Any:
        await asyncio.Event().wait()

    async def release(self, conn: Any) -> None:
        self.released.append(conn)


class _GatedPool:
    """A pool that hands its connection over only when the test opens the gate, and which honours the
    invariant both real drivers honour (and ``warm_pool_connections`` documents as relied upon): the
    connection is marked IN-USE atomically with being returned. ``checked_out`` is therefore the
    ground truth for "is a connection stranded outside the pool?"."""

    def __init__(self) -> None:
        self.gate = asyncio.Event()
        self.checked_out: list[Any] = []
        self.released: list[Any] = []
        self.conn = _Conn("gated")

    async def acquire(self) -> Any:
        await self.gate.wait()
        self.checked_out.append(self.conn)  # atomic with the return: no await between
        return self.conn

    async def release(self, conn: Any) -> None:
        self.released.append(conn)
        if conn in self.checked_out:
            self.checked_out.remove(conn)


class _ReadyPool:
    def __init__(self) -> None:
        self.released: list[Any] = []
        self.conn = _Conn("ready")

    async def acquire(self) -> Any:
        return self.conn

    async def release(self, conn: Any) -> None:
        self.released.append(conn)


def _sqlserver_store(pool: Any, timeout: float = FAST) -> Any:
    from messagefoundry.store.sqlserver import SqlServerStore

    store = SqlServerStore.__new__(SqlServerStore)
    store._pool = pool
    store._settings = types.SimpleNamespace(command_timeout=0, acquire_timeout=timeout)
    store._acquire_wait = AcquireWaitHistogram()
    store.committed_txns = 0
    store.body_copies = 0
    return store


def _postgres_store(pool: Any, timeout: float = FAST) -> Any:
    from messagefoundry.store.postgres import PostgresStore

    store = PostgresStore.__new__(PostgresStore)
    store._pool = pool
    store._settings = types.SimpleNamespace(acquire_timeout=timeout)
    store._acquire_wait = AcquireWaitHistogram()
    return store


# --- the helper itself -------------------------------------------------------


async def test_acquire_pooled_times_out_rather_than_waiting_forever() -> None:
    pool = _HangingPool()
    with pytest.raises(StoreAcquireTimeout, match="timed out after"):
        await acquire_pooled(pool, timeout=FAST, backend="sqlserver")


async def test_acquire_pooled_timeout_is_an_ordinary_exception_not_an_oserror() -> None:
    """The store's callers all handle ``except Exception``, so this must land there — and it must NOT
    be a ``TimeoutError``, which since 3.11 is an ``OSError`` and would be read as "the network
    moved" by connector-error handling that keys off ``OSError``."""
    assert issubclass(StoreAcquireTimeout, Exception)
    assert not issubclass(StoreAcquireTimeout, OSError)


async def test_acquire_pooled_message_names_the_knob_and_carries_no_phi() -> None:
    pool = _HangingPool()
    with pytest.raises(StoreAcquireTimeout) as caught:
        await acquire_pooled(pool, timeout=FAST, backend="postgres")
    text = str(caught.value)
    assert "postgres" in text and "[store].acquire_timeout" in text
    assert f"{FAST:g}s" in text


async def _settle() -> None:
    """Let any fire-and-forget salvage task run to completion."""
    for _ in range(50):
        await asyncio.sleep(0)


async def test_a_timed_out_borrow_strands_no_connection() -> None:
    """THE invariant, and it is deliberately stated as an outcome rather than a branch: after the
    bound fires, no connection is checked out of the pool. Which arm delivered that — the cancel won
    and nothing was ever handed over, or the borrow won and the salvage returned it — is a race, so
    asserting one branch would be asserting the scheduler."""
    pool = _GatedPool()
    with pytest.raises(StoreAcquireTimeout):
        await acquire_pooled(pool, timeout=FAST, backend="sqlserver")
    pool.gate.set()  # the pool becomes able to serve the borrow only now
    await _settle()
    assert pool.checked_out == [], (
        "a connection was left checked out after the borrow timed out — the bound is leaking the"
        " resource it exists to protect, and on a wedged pool it would leak one per retry"
    )


async def test_a_cancelled_borrow_strands_no_connection() -> None:
    """A shutdown landing mid-borrow takes the same path; otherwise ``stop()`` would strand a slot
    the pool never recovers, and the pool outlives a failover flap."""
    pool = _GatedPool()
    task = asyncio.create_task(acquire_pooled(pool, timeout=FAST * 100, backend="sqlserver"))
    await asyncio.sleep(0)  # let it reach the borrow
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    pool.gate.set()
    await _settle()
    assert pool.checked_out == []


async def test_salvage_returns_a_connection_that_arrived_too_late() -> None:
    """The salvage branch itself, driven directly because the race that reaches it cannot be
    scheduled deterministically. A borrow that RESOLVED before the giving-up cancel landed holds a
    connection the pool has already marked in-use — nobody else can ever return it."""
    from messagefoundry.store.base import _salvage_late_borrow

    pool = _GatedPool()
    borrow: asyncio.Future[Any] = asyncio.get_running_loop().create_future()
    pool.checked_out.append(pool.conn)  # the pool marked it in-use as it handed it over
    borrow.set_result(pool.conn)

    _salvage_late_borrow(pool, "sqlserver", borrow)
    await _settle()
    assert pool.released == [pool.conn] and pool.checked_out == []


async def test_salvage_does_nothing_when_the_cancel_won() -> None:
    """The other branch: no connection was handed over, so there is nothing to return and a release
    would be a double-release against the driver."""
    from messagefoundry.store.base import _salvage_late_borrow

    pool = _GatedPool()
    borrow: asyncio.Future[Any] = asyncio.get_running_loop().create_future()
    borrow.cancel()
    await asyncio.sleep(0)

    _salvage_late_borrow(pool, "sqlserver", borrow)
    await _settle()
    assert pool.released == []


async def test_salvage_swallows_a_release_failure() -> None:
    """It runs on the loop's callback path with no caller left to inform, so it must never raise."""
    from messagefoundry.store.base import _salvage_late_borrow

    class _BadPool(_GatedPool):
        async def release(self, conn: Any) -> None:
            raise RuntimeError("driver blew up on release")

    pool = _BadPool()
    borrow: asyncio.Future[Any] = asyncio.get_running_loop().create_future()
    borrow.set_result(pool.conn)
    _salvage_late_borrow(pool, "sqlserver", borrow)
    await _settle()  # no unhandled exception escapes


async def test_a_healthy_borrow_is_unaffected() -> None:
    """Positive control: the bound must not change the ordinary path."""
    pool = _ReadyPool()
    assert await acquire_pooled(pool, timeout=FAST, backend="sqlserver") is pool.conn
    assert pool.released == []  # the CALLER releases, not the helper


# --- the two store backends --------------------------------------------------


async def test_sqlserver_store_acquire_is_bounded() -> None:
    store = _sqlserver_store(_HangingPool())
    with pytest.raises(StoreAcquireTimeout):
        async with store._acquire():
            pytest.fail("the body must never run on a wedged pool")


async def test_postgres_store_acquire_is_bounded() -> None:
    store = _postgres_store(_HangingPool())
    with pytest.raises(StoreAcquireTimeout):
        async with store._timed_acquire():
            pytest.fail("the body must never run on a wedged pool")


@pytest.mark.parametrize("method", ["_fetchall", "_fetchone", "_execute"])
async def test_postgres_convenience_reads_are_bounded_too(method: str) -> None:
    """These called ``self._pool.fetch/fetchrow/execute``, each of which acquires internally with NO
    timeout (asyncpg 0.31.0 ``pool.py:613-634``). Bounding only ``_timed_acquire`` would have left
    the class of defect open on this backend while looking closed."""
    store = _postgres_store(_HangingPool())
    with pytest.raises(StoreAcquireTimeout):
        await getattr(store, method)("SELECT 1")


async def test_sqlserver_store_releases_a_healthy_borrow() -> None:
    """Positive control for the acquire/release restructure: the connection still goes back."""
    pool = _ReadyPool()
    store = _sqlserver_store(pool)
    async with store._acquire() as conn:
        assert conn is pool.conn
    assert pool.released == [pool.conn]


async def test_postgres_store_releases_a_healthy_borrow() -> None:
    pool = _ReadyPool()
    store = _postgres_store(pool)
    async with store._timed_acquire() as conn:
        assert conn is pool.conn
    assert pool.released == [pool.conn]


async def test_postgres_convenience_reads_stay_out_of_the_worker_acquire_wait_curve() -> None:
    """``record=False``: a low-frequency status poll must not pollute the B11 pool-wait signal the
    connection-scale harness reads."""

    class _P(_ReadyPool):
        async def acquire(self) -> Any:
            return _RowConn()

    class _RowConn:
        async def fetch(self, sql: str, *params: Any) -> list[Any]:
            return []

    store = _postgres_store(_P())
    await store._fetchall("SELECT 1")
    assert store._acquire_wait.summary().count == 0

    async with store._timed_acquire():
        pass
    assert store._acquire_wait.summary().count == 1  # the worker path IS still recorded


# --- the coverage boundary, pinned so the docs claim cannot rot --------------


_REPO = Path(__file__).resolve().parents[1]

# A borrow that happens INSIDE asyncpg rather than through the bounded helper: `pool.fetch` and its
# siblings each do `async with self.acquire()` (0.31.0 `pool.py:613-634`), and a bare
# `self._pool.acquire()` is the same thing spelled out.
#
# The `await`/`async with` prefix is load-bearing, not decoration: without it the scan also matched two
# DOCSTRING mentions of `self._pool.acquire()` / `self._pool.fetch(...)` inside `_timed_acquire` and
# reported 40 where there are 38. That is the instrument answering "does this text appear?" instead of
# "is a connection borrowed here?" — adjacent questions with different answers.
_UNBOUNDED_BORROW = re.compile(
    r"(?:await|async with) self\._pool\.(fetch|fetchrow|fetchval|execute|executemany|acquire)\("
)


def _unbounded_borrow_sites(relpath: str) -> list[str]:
    src = (_REPO / relpath).read_text(encoding="utf-8").splitlines()
    return [
        f"{relpath}:{n}: {line.strip()}"
        for n, line in enumerate(src, 1)
        if _UNBOUNDED_BORROW.search(line)
    ]


def test_sqlserver_acquire_really_is_the_sole_borrow_site() -> None:
    """The SQL Server claim in docs/CONNECTIONS.md — "every store call is bounded" — rests on
    ``_acquire`` being the ONLY place that borrows. Anything else touching ``self._pool`` must be
    lifecycle, metrics or the paired release; a new borrow added elsewhere would silently reopen
    BACKLOG #1052 on that backend. Reports the offending LINES, not a count."""
    allowed = re.compile(r"self\._pool\.(close|wait_closed|maxsize|size|freesize|release)\b")
    src = (_REPO / "messagefoundry/store/sqlserver.py").read_text(encoding="utf-8")
    stray = [
        f"sqlserver.py:{n}: {line.strip()}"
        for n, line in enumerate(src.splitlines(), 1)
        if "self._pool." in line and not allowed.search(line)
    ]
    assert stray == [], (
        "a new SQL Server pool borrow appeared outside _acquire, so it is no longer the sole bounded"
        " chokepoint the docs claim it is:\n" + "\n".join(stray)
    )


def test_postgres_borrows_outside_the_bounded_helper_are_pinned() -> None:
    """The counterpart, and the reason the docs' coverage note is written as a SCOPE rather than a
    completeness claim: on Postgres the bounded helper is not the only way a connection is borrowed,
    so "the pool acquire is bounded" would be a claim wider than the code supports.

    The boundary is a MEASUREMENT with a date rather than a sentence somebody wrote once: this fails
    if the population moves in EITHER direction. A drop means borrows were brought inside the helper
    — shrink the expectation and widen the CONNECTIONS.md scope note in the same commit. A rise means
    a new bypass landed and the note is now too generous."""
    store_sites = _unbounded_borrow_sites("messagefoundry/store/postgres.py")
    cluster_sites = _unbounded_borrow_sites("messagefoundry/pipeline/cluster.py")
    assert (len(store_sites), len(cluster_sites)) == (38, 10), (
        "the measured population of pool borrows OUTSIDE the bounded helper moved from 38 (store)"
        " + 10 (cluster), measured 2026-08-10. Re-read the CONNECTIONS.md scope note before changing"
        " this number. Sites scanned:\n" + "\n".join(store_sites + cluster_sites)
    )


# --- the setting -------------------------------------------------------------


def test_store_acquire_timeout_default_matches_the_connector_tier() -> None:
    from messagefoundry.transports.database import _DEFAULT_DB_ACQUIRE_TIMEOUT

    assert StoreSettings().acquire_timeout == DEFAULT_STORE_ACQUIRE_TIMEOUT
    assert DEFAULT_STORE_ACQUIRE_TIMEOUT == _DEFAULT_DB_ACQUIRE_TIMEOUT


@pytest.mark.parametrize("bad", [0.0, -1.0])
def test_store_acquire_timeout_must_be_positive(bad: float) -> None:
    """No "0 disables" escape hatch, unlike ``command_timeout``: an unbounded pool wait is the defect
    the setting exists to remove, so it must not be configurable back."""
    with pytest.raises(ValueError, match="acquire_timeout must be > 0"):
        StoreSettings(acquire_timeout=bad)
