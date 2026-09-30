# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Fairness baseline for the shared default thread pool (ASVS 15.4.4, BACKLOG #1195).

Sign-in's argon2 verify reaches the event loop's default executor through ``asyncio.to_thread``. At
least route and transform work share that executor too, unless ADR 0071 thread-hop fusion moves them
onto executors of their own. Nothing partitions the default executor, reserves a thread for sign-in,
or ranks work by priority. So when every thread is busy, a password verify waits behind all of it.
This file measures that, with no sleeps:

* ``_POOL`` workers form the default executor, reusing the connection-scale harness's instrumented
  pool so the queue depth is readable.
* ``parked`` tasks block on a ``threading.Event`` that only this test sets. Each one reports on the
  loop when its thread has started, so the test knows the threads are held before it goes on.
* One real argon2 verify then goes through :meth:`AuthService._argon2`, the seam every password
  verify uses. The stored hash uses the cheapest argon2 cost, because the cost is not under test.

The CONTROL parks one thread fewer than the pool holds, and the verify finishes. That shows the probe
can pass when one thread is free; its only bound is a backstop, so a slow runner cannot turn it red.
The BASELINE parks every thread, and the verify never starts. It is ``xfail(strict=True)`` and raises only :class:`Starved`, which requires
the verify to be still queued at the deadline. So a slow verify that did start is a real failure,
not an expected one. **The day a partition or reservation lets the verify through, the baseline
XPASSes, strict turns that red, and whoever built the partition must remove the marker** along with
the matching vault edit. Three limits bind whoever does that:

* An XPASS proves only that the verify got a thread. A local sign-in makes at least one more
  ``to_thread`` hop outside ``_argon2`` (the rehash check), and the directory and IdP paths make their
  own, so check those hops before closing the residual.
* The parkers submit straight to the default executor. A fix that caps the OTHER submitters will not
  XPASS until the parkers go through its cap.
* The test installs its own plain pool. A fix built as a partitioned default executor will not XPASS
  until the test installs that executor in place of the plain one.

This is a different pool from the one the ``async def`` request providers stopped using in the same
change. FastAPI runs a sync dependency through AnyIO's own worker threads, not the loop's default
executor, so that change does not touch the starvation measured here.

Each test runs on its own event loop through ``asyncio.run``. The suite shares one session loop, and
setting the default executor on it would leak a tiny pool into every later test.
"""

from __future__ import annotations

import asyncio
import inspect
import threading

import pytest
from argon2 import PasswordHasher

from messagefoundry.api.app import _get_engine, _get_gate
from messagefoundry.api.auth_routes import _service as api_service
from messagefoundry.auth.passwords import verify_password
from messagefoundry.auth.service import AuthService
from messagefoundry.config.settings import AuthSettings
from messagefoundry.pipeline.connscale_shim import InstrumentedThreadPoolExecutor
from messagefoundry.store.store import MessageStore
from messagefoundry_webconsole._service import _service as console_service

_POOL = 4
# The baseline's budget. A verify with no free thread cannot finish at any budget, so the value only
# matters the day a fix lands: a verify at the cheapest cost takes about a millisecond, and one at the
# pinned cost measured 0.51 s on a loaded workstation. The baseline waits the whole budget every run.
_BUDGET_SECONDS = 1.0
# A backstop, not a measurement. It bounds parking and the control, so a parker that never starts
# fails one test instead of hanging until pytest-timeout kills the whole worker.
_BACKSTOP_SECONDS = 30.0
_PASSWORD = "fairness-baseline-password"


class Starved(AssertionError):
    """The verify was still waiting for a pool thread when the budget ran out."""


async def _verify_with_parked_threads(parked: int, budget: float) -> None:
    loop = asyncio.get_running_loop()
    pool = InstrumentedThreadPoolExecutor(max_workers=_POOL)
    loop.set_default_executor(pool)

    # Runs inline on the loop thread; it never touches the pool.
    stored_hash = PasswordHasher(time_cost=1, memory_cost=8, parallelism=1).hash(_PASSWORD)
    release = threading.Event()
    all_parked = asyncio.Event()
    started = 0

    def _count_started() -> None:
        nonlocal started
        started += 1
        if started == parked:
            all_parked.set()

    def _park() -> None:
        loop.call_soon_threadsafe(_count_started)
        release.wait()

    verify_started = threading.Event()

    def _verify(stored: str, password: str) -> bool:
        verify_started.set()
        return verify_password(stored, password)

    parkers: list[asyncio.Future[None]] = []
    store = await MessageStore.open(":memory:")
    try:
        service = AuthService(store, AuthSettings())
        for _ in range(parked):
            parkers.append(loop.run_in_executor(None, _park))
        async with asyncio.timeout(_BACKSTOP_SECONDS):
            await all_parked.wait()
        verify = asyncio.ensure_future(service._argon2(_verify, stored_hash, _PASSWORD))
        done, _ = await asyncio.wait({verify}, timeout=budget)
        if verify not in done and not verify_started.is_set():
            raise Starved(
                f"argon2 verify got no thread in {budget}s: {parked} of {_POOL} "
                f"threads parked, {pool.queue_depth} work item(s) still queued"
            )
        assert verify in done, f"argon2 verify started but ran past {budget}s"
        assert verify.result() is True
    finally:
        # A verify left pending is cancelled by ``asyncio.run`` on the way out.
        release.set()
        await asyncio.gather(*parkers)
        await store.close()


def test_control_verify_finishes_with_one_thread_free() -> None:
    asyncio.run(_verify_with_parked_threads(_POOL - 1, _BACKSTOP_SECONDS))


@pytest.mark.xfail(
    strict=True,
    raises=Starved,
    reason=(
        "ASVS 15.4.4 residual (BACKLOG #1195): the default pool has no partition or reservation, so "
        "a saturated pool starves sign-in. Remove this marker when that lands."
    ),
)
def test_baseline_verify_is_starved_when_every_thread_is_parked() -> None:
    asyncio.run(_verify_with_parked_threads(_POOL, _BUDGET_SECONDS))


def test_request_providers_do_not_take_a_worker_thread() -> None:
    """FastAPI runs a sync ``Depends`` provider on an AnyIO worker thread and an ``async`` one on the
    loop. This pins only the four providers BACKLOG #1195 converted, which back most engine and console
    routes. It is not a general guard: ``bearer_token`` on ``POST /me/password`` is still sync."""
    for provider in (_get_engine, _get_gate, api_service, console_service):
        assert inspect.iscoroutinefunction(provider), provider.__qualname__
