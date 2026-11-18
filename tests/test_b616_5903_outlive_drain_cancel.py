# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #5903: a drain that cancels an outliving operation while its caller still waits.

The caller was never cancelled, so it must not get a bare ``CancelledError``: that would reach a
request as a cancellation nobody asked for, past the API's exception handlers. It gets
:class:`OperationInterrupted`, which the API answers 503. A caller that WAS cancelled still gets
its ``CancelledError``."""

from __future__ import annotations

import asyncio
import contextlib
import inspect
import json
from collections.abc import AsyncIterator, Mapping
from pathlib import Path
from typing import Any

import pytest
from starlette.requests import Request
from starlette.responses import Response

from messagefoundry.api import create_app
from messagefoundry.api.outlive import OperationInterrupted, OutlivingOperations
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


async def test_a_caller_already_cancelling_on_entry_is_not_mistaken_for_a_fresh_cancel() -> None:
    """The baseline is the caller's cancelling() count on entry, so a cancel it had absorbed before
    the run does not make a drain's cancel read as the caller's."""
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
    assert [type(exc) for exc in seen] == [OperationInterrupted]


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


async def test_the_api_answers_an_interrupted_operation_503(engine: Engine) -> None:
    app = create_app(engine)
    handler = app.exception_handlers[OperationInterrupted]
    request = Request({"type": "http", "method": "POST", "path": "/dr/activate", "headers": []})
    answered = handler(request, OperationInterrupted("DR activation"))
    assert inspect.isawaitable(answered)
    response = await answered
    assert isinstance(response, Response)
    assert response.status_code == 503
    assert "interrupted" in json.loads(bytes(response.body))["detail"]
