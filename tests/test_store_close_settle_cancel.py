# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #5720: a cancel landing in a store close's AES-GCM settle skipped the pool's close, so
the PostgreSQL pool was left open. SQL Server and SQLite are unchanged here: on SQL Server a forced
executor shutdown could break a borrower's release and a sync pool close would block the loop, and
on SQLite a forced stop() can hang a later close().

The settle is a database write on a keyed store, so a cancel can land there; each test stands a
settle that blocks in for it. No real PostgreSQL or SQL Server is involved. Synthetic data only.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any

import pytest

from messagefoundry.config.settings import StoreBackend, StoreSettings
from messagefoundry.store.postgres import PostgresStore


async def _cancel_close_in_its_settle(store: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    """Run ``store.close()`` with a settle that blocks, cancel it there, and expect the cancel."""
    settling = asyncio.Event()

    async def blocked_settle(**_kwargs: object) -> int | None:
        settling.set()
        await asyncio.sleep(30)
        return None

    monkeypatch.setattr(store, "checkpoint_cipher_invocations", blocked_settle)
    task = asyncio.create_task(store.close())
    await asyncio.wait_for(settling.wait(), 5)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task


class _PgPool:
    def __init__(self) -> None:
        self.terminated = 0

    async def close(self) -> None:
        raise AssertionError("the pool's graceful close is not reached after the cancel")

    def terminate(self) -> None:
        self.terminated += 1


async def test_postgres_close_cancelled_in_its_settle_terminates_the_pool(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """Red before the fix: the pool is never terminated."""
    pool = _PgPool()
    settings = StoreSettings(
        backend=StoreBackend.POSTGRES, server="localhost", database="mefor_test", username="mefor"
    )
    store = PostgresStore(pool, settings)
    with caplog.at_level(logging.WARNING, logger="messagefoundry.store.store"):
        await _cancel_close_in_its_settle(store, monkeypatch)
    assert pool.terminated == 1
    assert "a store close cut short in its settle (CancelledError)" in caplog.text
    assert "a forced release ran without waiting for it" in caplog.text


async def test_a_settle_that_finishes_forces_nothing(monkeypatch: pytest.MonkeyPatch) -> None:
    """Control: a close whose settle finishes closes the pool gracefully and terminates nothing."""

    class _Pool(_PgPool):
        def __init__(self) -> None:
            super().__init__()
            self.closed = 0

        async def close(self) -> None:
            self.closed += 1

    pool = _Pool()
    settings = StoreSettings(
        backend=StoreBackend.POSTGRES, server="localhost", database="mefor_test", username="mefor"
    )
    await PostgresStore(pool, settings).close()
    assert (pool.closed, pool.terminated) == (1, 0)
