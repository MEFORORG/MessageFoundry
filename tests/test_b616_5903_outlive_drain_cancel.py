# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #5903: a drain that cancels an outliving operation while its caller still waits.

The caller was never cancelled, so it must not get a bare ``CancelledError``: that would reach a
request as a cancellation nobody asked for, past the API's exception handlers. It gets
:class:`OperationInterrupted`, a 503. A caller that is cancelling still gets its
``CancelledError``."""

from __future__ import annotations

import asyncio
import contextlib
from collections.abc import AsyncIterator, Mapping
from pathlib import Path
from typing import Any

import httpx
import pytest

from messagefoundry.api import create_app
from messagefoundry.api.outlive import OperationInterrupted, OutlivingOperations
from messagefoundry.api.security import public_route
from messagefoundry.config.settings import EgressSettings
from messagefoundry.pipeline import Engine

_WAIT_S = 10.0


async def _hangs(started: asyncio.Event) -> None:
    started.set()
    await asyncio.Event().wait()


async def test_a_drain_cancel_reaches_a_waiting_caller_as_operation_interrupted() -> None:
    ops = OutlivingOperations()
    started = asyncio.Event()
    caller = asyncio.create_task(ops.run(_hangs(started), "DR activation"))
    await asyncio.wait_for(started.wait(), _WAIT_S)

    assert await ops.drain(timeout=0.0, grace=5.0) == ["DR activation"]
    with pytest.raises(OperationInterrupted, match="DR activation") as info:
        await asyncio.wait_for(caller, _WAIT_S)
    assert info.value.label == "DR activation"
    assert isinstance(info.value.__cause__, asyncio.CancelledError)
    assert not caller.cancelled()
    assert ops.inflight == []


async def test_a_cancelled_caller_still_gets_its_cancel_when_the_operation_is_cancelled_too() -> (
    None
):
    """Both cancelled in the same pass: the caller's own cancel wins, as cooperative cancellation
    requires."""
    ops = OutlivingOperations()
    started = asyncio.Event()
    caller = asyncio.create_task(ops.run(_hangs(started), "config reload"))
    await asyncio.wait_for(started.wait(), _WAIT_S)
    [operation] = list(ops._inflight)
    operation.cancel()
    caller.cancel()
    with pytest.raises(asyncio.CancelledError):
        await asyncio.wait_for(caller, _WAIT_S)
    assert caller.cancelled()


async def test_a_caller_already_cancelling_on_entry_keeps_its_cancel() -> None:
    """A caller that entered with a cancel in flight, as in a cleanup path, is never handed an
    ordinary exception in place of that cancel."""
    ops = OutlivingOperations()
    started = asyncio.Event()
    seen: list[BaseException] = []

    async def _caller() -> None:
        task = asyncio.current_task()
        assert task is not None
        task.cancel()
        # Absorbed without uncancel(), so cancelling() stays at 1 into the run.
        with contextlib.suppress(asyncio.CancelledError):
            await asyncio.sleep(1)
        try:
            await ops.run(_hangs(started), "upload delete")
        except BaseException as exc:  # noqa: BLE001 - the test records which one arrives
            seen.append(exc)

    caller = asyncio.create_task(_caller())
    await asyncio.wait_for(started.wait(), _WAIT_S)
    assert await ops.drain(timeout=0.0, grace=5.0) == ["upload delete"]
    await asyncio.wait_for(caller, _WAIT_S)
    assert [type(exc) for exc in seen] == [asyncio.CancelledError]


async def test_a_released_operation_the_drain_cancels_ends_interrupted() -> None:
    """The approval gate records a release whose operation was drained as ``interrupted``, never
    ``failed``: the outcome is as unknown as for a cancelled approve."""
    from messagefoundry.store.store import MessageStore
    from tests._pending_approval_store_contract import (
        _APPROVER,
        _APPROVER_ID,
        _audit_actions,
        _gate,
        _request,
        _status,
    )

    ops = OutlivingOperations()
    started = asyncio.Event()

    async def _execute(_p: Mapping[str, Any]) -> dict[str, Any]:
        await ops.run(_hangs(started), "released config reload")
        return {"ran": True}

    store = await MessageStore.open(":memory:")
    try:
        gate = _gate(store, _execute)
        approval_id = await _request(gate)
        approve = asyncio.create_task(
            gate.approve(approval_id, approver=_APPROVER, approver_user_id=_APPROVER_ID)
        )
        await asyncio.wait_for(started.wait(), _WAIT_S)
        assert await ops.drain(timeout=0.0, grace=5.0) == ["released config reload"]
        with pytest.raises(OperationInterrupted):
            await asyncio.wait_for(approve, _WAIT_S)
        assert await _status(store, approval_id) == "interrupted"
        actions = await _audit_actions(store, approval_id)
        assert actions.count("approval.interrupted") == 1
        assert "approval.failed" not in actions
    finally:
        await store.close()


@pytest.fixture
async def engine(tmp_path: Path) -> AsyncIterator[Engine]:
    eng = await Engine.create(
        tmp_path / "outlive.db",
        poll_interval=0.02,
        egress_settings=EgressSettings(deny_by_default=False),
    )
    yield eng
    await eng.stop()


async def test_a_route_whose_operation_is_drained_answers_503(engine: Engine) -> None:
    """Through the app's own stack: the request gets an answer, not a CancelledError out of it."""
    ops = OutlivingOperations()
    started = asyncio.Event()
    app = create_app(engine)

    @app.get("/healthz-5903-probe")
    @public_route("a test probe for BACKLOG #5903")
    async def _op() -> dict[str, str]:
        await ops.run(_hangs(started), "DR release")
        return {"ran": "yes"}

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://127.0.0.1") as client:
        sent = asyncio.create_task(client.get("/healthz-5903-probe"))
        await asyncio.wait_for(started.wait(), _WAIT_S)
        assert await ops.drain(timeout=0.0, grace=5.0) == ["DR release"]
        response = await asyncio.wait_for(sent, _WAIT_S)
    assert response.status_code == 503, response.text
    detail = response.json()["detail"]
    assert "DR release was interrupted" in detail and "outcome is unknown. Check" in detail
    # Conditional, because an ungated operation released no approval.
    assert (
        "If it ran as an approval's release, that approval is now interrupted; resolve it rather "
        "than approving it again." in detail
    )
