# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Driver-free unit tests for the store pool pre-warm (Workstream A — failover drain).

No real aioodbc/asyncpg pool or DB driver is needed: a stub pool models ``acquire``/``release`` and
records the maximum number of connections held **concurrently** — which is what actually forces a real
pool to create connections — plus that every acquired connection is released. This locks the contract
the dogfood box's failover timing probe relies on: pre-warming forces ``target`` concurrent physical
connects and never strands a pooled connection (on partial connect failure, on timeout, on cancellation,
or when a release itself fails). The engine-level tests prove the lifecycle wiring: ``_fire_pool_warm``
creates exactly one named task, a re-promotion cancels the prior one (never orphans it), and ``stop()``
always cancels it.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from messagefoundry.config.settings import (
    ClusterSettings,
    ServiceSettings,
    StoreBackend,
    StoreSettings,
)
from messagefoundry.pipeline.engine import Engine
from messagefoundry.store.base import warm_pool_connections, warm_pool_target
from messagefoundry.store.store import MessageStore

# Minimal valid server-DB connection fields, so a Postgres StoreSettings constructs (the warm_pool
# validators are what these tests exercise, not the connection-field requirements).
_PG = {"backend": StoreBackend.POSTGRES, "server": "db", "database": "d", "username": "u"}


class StubPool:
    """A minimal stand-in for an aioodbc/asyncpg pool: tracks live + peak-concurrent connections.

    Optional knobs model the failure modes the warm-up must survive: ``fail_after`` makes connects
    beyond the Nth raise; ``block_after`` makes connects beyond the Nth hang (until cancelled) so the
    timeout/cancellation paths can be exercised; ``release_raises_first`` makes the first release raise.
    """

    def __init__(
        self,
        *,
        fail_after: int | None = None,
        block_after: int | None = None,
        release_raises_first: bool = False,
        release_blocks_until: asyncio.Event | None = None,
    ) -> None:
        self.total_acquired = 0
        self.live = 0
        self.max_concurrent = 0
        self.released = 0
        self.release_attempts = 0
        self._fail_after = fail_after
        self._block_after = block_after
        self._release_raises_first = release_raises_first
        self._release_blocks_until = release_blocks_until
        self._seq = 0
        # Never set in these tests: a "blocked" acquire waits on it forever and is unstuck only by the
        # warm-up's finally cancelling its task.
        self._never = asyncio.Event()

    async def acquire(self) -> str:
        self.total_acquired += 1
        ordinal = self.total_acquired  # this acquire's ordinal, fixed before we yield
        # Let sibling acquire tasks interleave so the concurrency we observe is real, not an artifact
        # of the helper holding connections until its finally.
        await asyncio.sleep(0)
        if self._fail_after is not None and ordinal > self._fail_after:
            raise RuntimeError("simulated connect failure")
        if self._block_after is not None and ordinal > self._block_after:
            # Hang BEFORE counting as live/returning a conn — so a connection blocked here is never
            # "acquired" and never needs releasing (it is cancelled in the warm-up's finally).
            await self._never.wait()
        self.live += 1
        self.max_concurrent = max(self.max_concurrent, self.live)
        self._seq += 1
        return f"conn-{self._seq}"

    async def release(self, conn: str) -> None:
        self.release_attempts += 1
        if self._release_blocks_until is not None:
            # A suspension point inside release() — lets a cancellation land while we are mid-release.
            await self._release_blocks_until.wait()
        if self._release_raises_first and self.release_attempts == 1:
            raise RuntimeError("simulated release failure")
        self.live -= 1
        self.released += 1


# --- warm_pool_connections: the shared helper -------------------------------


async def test_warm_forces_target_concurrent_connects_then_releases_all() -> None:
    pool = StubPool()
    warmed = await warm_pool_connections(pool, target=5, timeout=5.0, backend="stub")

    assert warmed == 5
    # Held all 5 at once (this is what grows a real pool) ...
    assert pool.max_concurrent == 5
    # ... and released every one (warming must never strand a pooled connection).
    assert pool.released == 5
    assert pool.live == 0


async def test_warm_with_zero_or_negative_target_is_a_noop() -> None:
    pool = StubPool()
    assert await warm_pool_connections(pool, target=0, timeout=5.0, backend="stub") == 0
    assert await warm_pool_connections(pool, target=-3, timeout=5.0, backend="stub") == 0
    assert pool.total_acquired == 0


async def test_warm_tolerates_partial_connect_failure_and_releases_what_it_got() -> None:
    # Only the first 3 connects succeed; the rest raise. The warm-up must absorb the failures, return
    # the number actually warmed, and release exactly those — leaving nothing stranded.
    pool = StubPool(fail_after=3)
    warmed = await warm_pool_connections(pool, target=6, timeout=5.0, backend="stub")

    assert warmed == 3
    assert pool.released == 3
    assert pool.live == 0


async def test_warm_times_out_and_releases_what_it_held() -> None:
    # Two connects succeed; the rest hang forever. The whole warm-up is bounded by ``timeout`` — on
    # expiry it returns (never raises), leaks nothing (live == 0), and releases exactly what it acquired.
    pool = StubPool(block_after=2)
    warmed = await warm_pool_connections(pool, target=5, timeout=0.05, backend="stub")

    assert warmed < 5  # the timeout cut the warm short — it did NOT warm the full target
    assert pool.live == 0  # nothing left checked out
    assert pool.released == warmed  # every connection acquired was released


async def test_warm_releases_everything_when_cancelled_mid_flight() -> None:
    # The warm-up must be safe to cancel: connections held when the cancellation arrives are still
    # released in its finally, so cancellation can never strand a pooled connection.
    pool = StubPool(block_after=2)  # 2 acquire, the rest hang so the warm sits in-flight
    task = asyncio.create_task(warm_pool_connections(pool, target=5, timeout=5.0, backend="stub"))
    for _ in range(1000):  # let the 2 non-blocked connects land (cooperative; no real-time wait)
        if pool.max_concurrent >= 2:
            break
        await asyncio.sleep(0)
    assert pool.max_concurrent == 2

    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass
    assert pool.live == 0  # the 2 held connections were released despite the cancellation
    assert pool.released == 2


async def test_warm_releases_everything_when_cancelled_during_the_release_loop() -> None:
    # The reliability-core guarantee: a cancellation delivered while the warm is SUSPENDED IN ITS RELEASE
    # LOOP (a re-fire/stop cancel landing mid-`pool.release`) must still release every held connection —
    # the cleanup is shielded and run to completion before the cancellation propagates.
    gate = asyncio.Event()  # holds release() open so the cancel lands while we are mid-release
    pool = StubPool(release_blocks_until=gate)
    task = asyncio.create_task(warm_pool_connections(pool, target=3, timeout=5.0, backend="stub"))
    for _ in range(1000):  # let all 3 acquire and the first release start (now blocked on the gate)
        if pool.release_attempts >= 1:
            break
        await asyncio.sleep(0)
    assert pool.release_attempts >= 1  # we are inside the release loop ...
    assert pool.live == 3 and pool.released == 0  # ... with everything still held

    task.cancel()  # cancel WHILE suspended mid-release
    gate.set()  # let the (shielded) releases proceed
    try:
        await task
    except asyncio.CancelledError:
        pass
    assert pool.live == 0  # every held connection was still released despite the cancellation
    assert pool.released == 3


async def test_warm_does_not_hang_when_a_release_is_stuck(monkeypatch: pytest.MonkeyPatch) -> None:
    # Reliability: a release stuck on a DEAD connection (failover to a gone node) must NOT hang the warm —
    # the cleanup is BOUNDED, so it gives up after _CLEANUP_TIMEOUT_SECONDS and lets the cancellation
    # propagate (a bounded partial strand), instead of hanging stop()/re-promotion forever.
    monkeypatch.setattr("messagefoundry.store.base._CLEANUP_TIMEOUT_SECONDS", 0.05)
    never = asyncio.Event()  # never set: this release hangs forever
    pool = StubPool(release_blocks_until=never)
    task = asyncio.create_task(warm_pool_connections(pool, target=3, timeout=5.0, backend="stub"))
    for _ in range(1000):  # let the acquires complete and the first (stuck) release begin
        if pool.release_attempts >= 1:
            break
        await asyncio.sleep(0)
    task.cancel()  # cancel while the release is stuck — must still unwind within the bound

    done, _pending = await asyncio.wait({task}, timeout=2.0)
    assert task in done  # unwound within the bound — NOT an infinite hang
    assert task.cancelled()  # ... and as a cancellation


async def test_warm_stuck_release_then_cancel_emits_no_loop_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The bounded cleanup must resolve cleanly on the dead-node + cancel path — no spurious loop-level
    # ERROR (e.g. a "TimeoutError exception in shielded future") polluting the service logs on exactly the
    # failover-during-stop scenario.
    monkeypatch.setattr("messagefoundry.store.base._CLEANUP_TIMEOUT_SECONDS", 0.05)
    loop = asyncio.get_running_loop()
    errors: list[dict[str, object]] = []
    loop.set_exception_handler(lambda _loop, context: errors.append(context))

    never = asyncio.Event()  # release hangs forever (dead connection)
    pool = StubPool(release_blocks_until=never)
    task = asyncio.create_task(warm_pool_connections(pool, target=3, timeout=5.0, backend="stub"))
    for _ in range(1000):
        if pool.release_attempts >= 1:
            break
        await asyncio.sleep(0)
    task.cancel()
    await asyncio.wait({task}, timeout=2.0)
    await asyncio.sleep(0.1)  # let any deferred loop callbacks (a shielded-future error) fire
    assert errors == [], f"unexpected loop-level error(s): {errors}"


async def test_warm_absorbs_a_release_error_and_releases_the_rest() -> None:
    # A release that itself raises must not propagate and must not abort the release loop — every held
    # connection still gets a release attempt.
    pool = StubPool(release_raises_first=True)
    warmed = await warm_pool_connections(pool, target=3, timeout=5.0, backend="stub")

    assert warmed == 3
    assert (
        pool.release_attempts == 3
    )  # the loop attempted release for all 3 (did not stop at the raise)


# --- warm_pool_target: headroom sizing --------------------------------------


def test_warm_pool_target_caps_at_half_the_pool_by_default() -> None:
    # Default (configured=None): never pin more than half the pool, and never warm a pool of <= 1.
    assert warm_pool_target(1, None) == 0  # a single-connection pool is never warmed
    assert warm_pool_target(2, None) == 1
    assert warm_pool_target(5, None) == 2  # min(4, 5//2) — leaves the other 3 for live work
    assert warm_pool_target(10, None) == 5


def test_warm_pool_target_honours_then_clamps_an_explicit_count() -> None:
    assert warm_pool_target(5, 3) == 3  # explicit count is used as-is when it leaves a free slot
    assert warm_pool_target(5, 9) == 4  # ... but is clamped to maxsize - 1 (always leave one free)
    assert warm_pool_target(1, 5) == 0  # a 1-slot pool is never warmed, even with an explicit count


# --- settings: the warm_pool knob + validators ------------------------------


def test_warm_pool_field_validators_reject_nonpositive() -> None:
    with pytest.raises(ValueError):
        StoreSettings(warm_pool_timeout=0)
    with pytest.raises(ValueError):
        StoreSettings(warm_pool_timeout=-1.0)
    with pytest.raises(ValueError):
        StoreSettings(warm_pool_target=0)
    with pytest.raises(ValueError):
        StoreSettings(warm_pool_target=-2)


def test_fence_validator_rejects_explicit_over_fence_when_clustered() -> None:
    # An EXPLICIT warm_pool_timeout >= [cluster].leader_fence_timeout_seconds is rejected on a clustered
    # server-DB config (a warm must finish within the leadership term that started it).
    with pytest.raises(ValueError, match="warm_pool_timeout must be <"):
        ServiceSettings(
            store=StoreSettings(**_PG, warm_pool_timeout=25.0),
            cluster=ClusterSettings(enabled=True),  # default fence 20
        )
    # The >= boundary (exactly equal to the fence) is rejected too.
    with pytest.raises(ValueError, match="warm_pool_timeout must be <"):
        ServiceSettings(
            store=StoreSettings(**_PG, warm_pool_timeout=20.0),
            cluster=ClusterSettings(enabled=True),
        )


def test_fence_validator_exempts_the_default_even_under_a_lowered_fence() -> None:
    # The DEFAULT warm_pool_timeout (absent from model_fields_set) must not break a config that merely
    # lowered the fence below it — the warm is best-effort/self-releasing, so this is safe by construction.
    s = ServiceSettings(
        store=StoreSettings(**_PG, pool_size=3),
        cluster=ClusterSettings(
            enabled=True,
            leader_fence_timeout_seconds=12.0,
            leader_lease_ttl_seconds=20.0,
            heartbeat_seconds=3.0,
        ),
    )
    assert s.store.warm_pool_timeout == 15.0  # default retained, no error


def test_fence_validator_exempt_when_warm_disabled_or_single_node() -> None:
    # warm_pool=false bypasses the fence check entirely ...
    ServiceSettings(
        store=StoreSettings(**_PG, warm_pool=False, warm_pool_timeout=99.0),
        cluster=ClusterSettings(enabled=True),
    )
    # ... and a single-node (cluster disabled) config has no fence, so even a long explicit warm is fine.
    ServiceSettings(store=StoreSettings(**_PG, warm_pool_timeout=99.0))


async def test_sqlite_warm_pool_is_a_noop(tmp_path: Path) -> None:
    # SQLite has no pool; warm_pool must be a harmless no-op and leave the store fully usable.
    store = await MessageStore.open(tmp_path / "warm.db")
    try:
        assert await store.warm_pool() is None
        await store.stats()  # still works afterward
    finally:
        await store.close()


# --- Engine wiring: _fire_pool_warm lifecycle (driver-free) -----------------


class _WarmSpyStore:
    """Store stand-in whose ``warm_pool`` signals entry then blocks, so the engine create/cancel/re-fire
    wiring is observable. Only ``warm_pool`` + ``close`` are exercised here."""

    def __init__(self) -> None:
        self.warm_entries = 0
        self.warm_cancelled = 0
        self.entered = asyncio.Event()
        self._release = asyncio.Event()  # never set: the warm blocks until cancelled

    async def warm_pool(self) -> None:
        self.warm_entries += 1
        self.entered.set()
        try:
            await self._release.wait()
        except asyncio.CancelledError:
            self.warm_cancelled += 1
            raise

    async def close(self) -> None:
        return None


async def test_engine_fire_pool_warm_creates_one_named_task() -> None:
    store = _WarmSpyStore()
    engine = Engine(store)  # type: ignore[arg-type]  # spy store; coordinator defaults to NullCoordinator
    await engine._fire_pool_warm()
    task = engine._warm_pool_task
    assert task is not None and not task.done()
    assert task.get_name() == "store-pool-warm"  # named for diagnosability
    await store.entered.wait()
    assert store.warm_entries == 1
    await engine.stop()  # tears the warm down cleanly
    assert task.cancelled()
    assert engine._warm_pool_task is None


async def test_engine_refire_cancels_prior_warm_instead_of_orphaning_it() -> None:
    # The MUST-FIX: _start_graph re-runs on every leadership acquire, so a promote->demote->re-promote
    # flap must cancel the prior term's warm (never orphan it from stop()) and keep at most one alive.
    store = _WarmSpyStore()
    engine = Engine(store)  # type: ignore[arg-type]
    await engine._fire_pool_warm()
    first = engine._warm_pool_task
    assert first is not None
    await store.entered.wait()  # the first warm is actually running
    store.entered.clear()

    await engine._fire_pool_warm()  # simulated re-promotion
    second = engine._warm_pool_task
    assert first.cancelled()  # the prior warm was cancelled, not left orphaned
    assert store.warm_cancelled == 1
    assert second is not None and second is not first and not second.done()
    await store.entered.wait()  # the replacement warm is now the one running
    assert store.warm_entries == 2

    second.cancel()
    await asyncio.gather(second, return_exceptions=True)


async def test_engine_fire_pool_warm_is_clean_on_sqlite(tmp_path: Path) -> None:
    # End-to-end with a real SQLite store: warm_pool returns immediately, so the task completes without
    # error and stop() gathers the already-done task cleanly.
    store = await MessageStore.open(tmp_path / "warm.db")
    engine = Engine(store)  # type: ignore[arg-type]
    try:
        await engine._fire_pool_warm()
        task = engine._warm_pool_task
        assert task is not None
        await asyncio.gather(task)
        assert task.done() and task.exception() is None
    finally:
        await engine.stop()
