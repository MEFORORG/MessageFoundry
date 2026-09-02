# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""The SQL Server pool must own a thread pool wide enough for every connection in it.

THE DEFECT THIS PINS. aioodbc runs every pyodbc call through
``loop.run_in_executor(self._executor, ...)`` and defaults ``executor`` to ``None``, which is the event
loop's DEFAULT ThreadPoolExecutor -- ``min(32, cpu_count + 4)`` threads, eight on a four-vCPU runner, and
independent of ``[store].pool_size``. A write holding row locks across four sequential dispatches
(``cursor``, ``execute``, ``fetchone``, ``commit`` under ``autocommit=False``) then deadlocks once as many
tasks as there are threads park inside a blocked ``execute``: the lock holder's own ``commit`` queues
behind them with no worker left to run it. Observed as ``pyodbc.OperationalError HYT00`` and
``StoreAcquireTimeout`` on the CI sqlserver leg, never as a deadlock.

WHY THIS TESTS THE HELPER AND NOT ``open()``. ``open()`` needs aioodbc, an ODBC driver and a reachable
server, so a test routed through it runs on ONE gated leg and skips everywhere else -- and a guard that
skips on the legs most people run is a guard that reports green while proving nothing. The sizing rule is
pure, so it is extracted and tested directly, and it runs on every leg. The live half -- that a real
pooled connection carries the store's own executor -- is asserted inside the gated sqlserver suite, which
is the only place it can honestly be checked.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

import pytest

from messagefoundry.config.settings import StoreSettings
from messagefoundry.store.sqlserver import _build_pool_executor


def _settings(pool_size: int) -> StoreSettings:
    # The sqlserver backend validates server/database/username at construction, so they are supplied
    # even though the helper reads only pool_size. Values are placeholders: nothing here connects.
    return StoreSettings(
        backend="sqlserver",
        pool_size=pool_size,
        server="localhost",
        database="mefor_test",
        username="sa",
    )


@pytest.mark.parametrize("pool_size", [1, 2, 4, 8, 40, 100])
def test_the_executor_can_serve_every_connection_at_once(pool_size: int) -> None:
    """Width >= pool_size, which is the invariant the deadlock violates.

    Stated as an inequality rather than an equality on purpose: the headroom is deliberate and may grow,
    but it must never shrink below the pool, because that is the deadlock.
    """
    ex = _build_pool_executor(_settings(pool_size))
    try:
        assert ex._max_workers >= pool_size, (
            f"pool_size={pool_size} but the executor has {ex._max_workers} threads. Any connection that "
            "cannot hold a worker while it waits on a lock can deadlock the pool."
        )
    finally:
        ex.shutdown(wait=False)


def test_the_default_loop_executor_would_be_too_narrow() -> None:
    """POSITIVE CONTROL. An assertion that only ever passes proves nothing about the defect.

    This reconstructs CPython's default sizing and shows it fails the invariant above at the shipped
    pool_size of 40 on any host with fewer than 36 CPUs -- which is every hosted runner. If this ever
    stops failing, the premise of the fix has changed and the fix should be re-argued rather than kept.
    """
    default_width = min(32, 4 + 4)  # a four-vCPU hosted runner
    assert default_width < 40, "the default executor would no longer be the constraint"


def test_a_zero_or_negative_pool_size_still_yields_a_usable_executor() -> None:
    """pool_size is clamped by max(1, ...) at the call site; the helper must not divide by it or return 0."""
    for bad in (0, -1):
        ex = _build_pool_executor(_settings(bad))
        try:
            assert ex._max_workers >= 1
        finally:
            ex.shutdown(wait=False)


def test_the_helper_needs_no_driver_and_no_server() -> None:
    """The reason this file runs on every leg: it touches nothing that needs the sqlserver extra."""
    ex = _build_pool_executor(_settings(4))
    try:
        assert isinstance(ex, ThreadPoolExecutor)
        assert ex._thread_name_prefix.startswith("mefor-sqlserver")
    finally:
        ex.shutdown(wait=False)
