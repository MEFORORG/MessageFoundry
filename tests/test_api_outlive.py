# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""OutlivingOperations: an operation outlives a cancelled caller, and the shutdown drain bounds it
(vault BACKLOG #2751-#2753). The DR and reload routes are tested through it in
test_dr_outlive_deadline.py and test_reload_cancellation.py; this pins the helper itself."""

from __future__ import annotations

import asyncio

import pytest

from messagefoundry.api.outlive import OutlivingOperations


async def test_cancelling_the_caller_does_not_cancel_the_operation() -> None:
    ops = OutlivingOperations()
    release = asyncio.Event()
    finished: list[str] = []

    async def operation() -> str:
        await release.wait()
        finished.append("done")
        return "result"

    caller = asyncio.create_task(ops.run(operation(), "test operation"))
    await asyncio.sleep(0)
    await asyncio.sleep(0)
    assert ops.inflight == ["test operation"]
    caller.cancel()
    with pytest.raises(asyncio.CancelledError):
        await caller
    assert ops.inflight == ["test operation"]  # still running, and still held

    release.set()
    assert await ops.drain(timeout=5) == []
    assert finished == ["done"] and ops.inflight == []


async def test_the_result_and_the_error_reach_a_caller_that_waited() -> None:
    ops = OutlivingOperations()

    async def ok() -> int:
        return 7

    async def boom() -> int:
        raise ValueError("refused")

    assert await ops.run(ok(), "ok") == 7
    with pytest.raises(ValueError, match="refused"):
        await ops.run(boom(), "boom")
    assert ops.inflight == []


async def test_the_drain_cancels_what_outlasts_it_and_waits_for_its_rollback() -> None:
    ops = OutlivingOperations()
    rolled_back: list[bool] = []

    async def stuck() -> None:
        try:
            await asyncio.Event().wait()
        except asyncio.CancelledError:
            await asyncio.sleep(0.01)  # a rollback arm that awaits, as the DR and reload arms do
            rolled_back.append(True)
            raise

    caller = asyncio.create_task(ops.run(stuck(), "stuck operation"))
    await asyncio.sleep(0)
    caller.cancel()
    with pytest.raises(asyncio.CancelledError):
        await caller

    assert await ops.drain(timeout=0.05, grace=5) == ["stuck operation"]
    assert rolled_back == [True]
    assert ops.inflight == []
