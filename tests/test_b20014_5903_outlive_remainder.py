# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #5903 added steps 2 and 3: the gate's own ``_outlive_caller`` awaits, and the 503 text.

Step 2. ``OutlivingOperations.run`` already turned an operation cancelled under a caller that was
not cancelling into :class:`OperationInterrupted`. The approval gate's ``_shielded`` writes and its
claim await the same helper, ``_outlive_caller``, and still handed such a caller a bare
``CancelledError``. The helper now decides, so every user of it does. A caller that IS cancelling
keeps its ``CancelledError``, in both places.

Step 3. The 503 said "If it ran as an approval's release" to every caller, gated or not. The gate now
marks an interruption it raised out of a release, so only that answer names the approval."""

from __future__ import annotations

import asyncio
import contextlib
import logging
from collections.abc import AsyncIterator, Mapping
from pathlib import Path
from typing import Any

import httpx
import pytest

from messagefoundry.api import create_app
from messagefoundry.api.approvals import _outlive_caller
from messagefoundry.api.outlive import OperationInterrupted, OutlivingOperations
from messagefoundry.api.security import public_route
from messagefoundry.config.settings import EgressSettings
from messagefoundry.pipeline import Engine
from tests.test_b616_5903_outlive_drain_cancel import _WAIT_S, _hangs

# --- step 2: the helper itself, both directions ---------------------------------------------------


async def test_the_helper_turns_a_task_cancelled_under_a_waiting_caller_into_an_interruption() -> (
    None
):
    started = asyncio.Event()
    task = asyncio.ensure_future(_hangs(started))
    caller = asyncio.create_task(_outlive_caller(task, "a synthetic write"))
    await asyncio.wait_for(started.wait(), _WAIT_S)
    task.cancel()
    with pytest.raises(OperationInterrupted, match="a synthetic write") as info:
        await asyncio.wait_for(caller, _WAIT_S)
    assert isinstance(info.value.__cause__, asyncio.CancelledError)
    assert info.value.released is False
    assert not caller.cancelled()


async def test_the_helper_hands_a_cancelled_caller_its_cancel_and_leaves_the_task_running() -> None:
    started = asyncio.Event()
    task = asyncio.ensure_future(_hangs(started))
    caller = asyncio.create_task(_outlive_caller(task, "a synthetic write"))
    await asyncio.wait_for(started.wait(), _WAIT_S)
    caller.cancel()
    with pytest.raises(asyncio.CancelledError):
        await asyncio.wait_for(caller, _WAIT_S)
    assert caller.cancelled()
    assert not task.done()
    task.cancel()


async def test_the_helper_keeps_the_cancel_of_a_caller_cancelling_when_the_task_is_cancelled() -> (
    None
):
    """The helper's own re-raise branch: the task's CancelledError comes out of ``task.result()``
    while the caller is cancelling, as in a cancel arm. A cancel of the caller while it waits comes
    out of ``asyncio.wait`` instead and never reaches that branch."""
    started = asyncio.Event()
    task = asyncio.ensure_future(_hangs(started))
    seen: list[BaseException] = []

    async def _caller() -> None:
        me = asyncio.current_task()
        assert me is not None
        me.cancel()
        # Absorbed without uncancel(), so cancelling() stays at 1 into the helper.
        with contextlib.suppress(asyncio.CancelledError):
            await asyncio.sleep(1)
        try:
            await _outlive_caller(task, "a synthetic write")
        except BaseException as exc:  # noqa: BLE001 - the test records which one arrives
            seen.append(exc)

    caller = asyncio.create_task(_caller())
    await asyncio.wait_for(started.wait(), _WAIT_S)
    task.cancel()
    await asyncio.wait_for(caller, _WAIT_S)
    assert [type(exc) for exc in seen] == [asyncio.CancelledError]


# --- step 2: the gate's shielded write, both directions -------------------------------------------


@pytest.fixture
async def gate() -> AsyncIterator[Any]:
    from messagefoundry.store.store import MessageStore
    from tests._pending_approval_store_contract import _gate

    async def _execute(_p: Mapping[str, Any]) -> dict[str, Any]:
        return {"ran": True}

    store = await MessageStore.open(":memory:")
    try:
        yield _gate(store, _execute)
    finally:
        await store.close()


async def test_a_shielded_write_cancelled_on_its_own_reaches_its_caller_as_an_interruption(
    gate: Any, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.ERROR, logger="messagefoundry.api.approvals")
    started = asyncio.Event()
    caller = asyncio.create_task(gate._shielded(_hangs(started), "a" * 32))
    await asyncio.wait_for(started.wait(), _WAIT_S)
    [write] = list(gate._inflight)
    write.cancel()
    with pytest.raises(OperationInterrupted, match="a write for approval") as info:
        await asyncio.wait_for(caller, _WAIT_S)
    assert isinstance(info.value.__cause__, asyncio.CancelledError)
    assert not caller.cancelled()
    assert gate._inflight == {}
    # The gate's own ERROR line for a cancelled write is still written.
    assert f"approval {'a' * 32}: a shielded outcome write was cancelled" in caplog.text


async def test_a_shielded_write_whose_caller_is_cancelled_still_hands_it_the_cancel(
    gate: Any,
) -> None:
    started = asyncio.Event()
    caller = asyncio.create_task(gate._shielded(_hangs(started), "b" * 32))
    await asyncio.wait_for(started.wait(), _WAIT_S)
    [write] = list(gate._inflight)
    caller.cancel()
    with pytest.raises(asyncio.CancelledError):
        await asyncio.wait_for(caller, _WAIT_S)
    assert caller.cancelled()
    assert not write.done()  # the write outlives its cancelled caller, as before
    write.cancel()
    await asyncio.wait((write,), timeout=_WAIT_S)


# --- step 3: only a release names the approval ------------------------------------------------------


async def test_an_interrupted_release_is_marked_and_its_text_names_the_approval() -> None:
    from messagefoundry.store.store import MessageStore
    from tests._pending_approval_store_contract import _APPROVER, _APPROVER_ID, _gate, _request

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
        with pytest.raises(OperationInterrupted) as info:
            await asyncio.wait_for(approve, _WAIT_S)
    finally:
        await store.close()
    assert info.value.released is True
    detail = info.value.operator_detail
    assert detail.startswith("released config reload was interrupted before it answered")
    assert (
        "It ran as an approval's release, so resolve that approval rather than approving it again."
        in detail
    )


async def _cut_short(*_a: Any, **_k: Any) -> None:
    """A write whose own task ends cancelled, as a store closing under it would leave it."""
    raise asyncio.CancelledError


async def test_an_outcome_write_cut_off_after_the_release_ran_is_marked_too(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Review round 1: only the executor's interruption was marked. One from the approved-row
    write, after the operation ran, must name the approval as well."""
    from messagefoundry.store.store import MessageStore
    from tests._pending_approval_store_contract import _APPROVER, _APPROVER_ID, _gate, _request

    ran: list[bool] = []

    async def _execute(_p: Mapping[str, Any]) -> dict[str, Any]:
        ran.append(True)
        return {"ran": True}

    store = await MessageStore.open(":memory:")
    try:
        gate = _gate(store, _execute)
        approval_id = await _request(gate)
        monkeypatch.setattr(gate, "_record_approved_execution", _cut_short)
        with pytest.raises(OperationInterrupted, match="a write for approval") as info:
            await asyncio.wait_for(
                gate.approve(approval_id, approver=_APPROVER, approver_user_id=_APPROVER_ID),
                _WAIT_S,
            )
    finally:
        await store.close()
    assert ran == [True]
    assert info.value.released is True
    assert "resolve that approval" in info.value.operator_detail


async def test_a_claim_cut_off_under_an_approve_answers_its_own_503(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """Review round 1: a cancelled claim was answered as a store failure. It now names itself, and
    the executor never runs."""
    from messagefoundry.api.approvals import ApprovalError
    from messagefoundry.store.store import MessageStore
    from tests._pending_approval_store_contract import _APPROVER, _APPROVER_ID, _gate, _request

    ran: list[bool] = []

    async def _execute(_p: Mapping[str, Any]) -> dict[str, Any]:
        ran.append(True)
        return {"ran": True}

    caplog.set_level(logging.ERROR, logger="messagefoundry.api.approvals")
    store = await MessageStore.open(":memory:")
    try:
        gate = _gate(store, _execute)
        approval_id = await _request(gate)
        monkeypatch.setattr(gate._store, "decide_pending_approval", _cut_short)
        with pytest.raises(ApprovalError) as info:
            await asyncio.wait_for(
                gate.approve(approval_id, approver=_APPROVER, approver_user_id=_APPROVER_ID),
                _WAIT_S,
            )
    finally:
        await store.close()
    assert ran == []
    assert info.value.status == 503
    assert info.value.detail.startswith("the claim of this release was interrupted")
    assert isinstance(info.value.__cause__, OperationInterrupted)
    assert "the claim was cancelled before it answered" in caplog.text
    assert "the store failed to record the claim" not in caplog.text


@pytest.fixture
async def engine(tmp_path: Path) -> AsyncIterator[Engine]:
    eng = await Engine.create(
        tmp_path / "outlive-remainder.db",
        poll_interval=0.02,
        egress_settings=EgressSettings(deny_by_default=False),
    )
    yield eng
    await eng.stop()


async def test_an_ungated_route_whose_operation_is_drained_names_no_approval(
    engine: Engine,
) -> None:
    ops = OutlivingOperations()
    started = asyncio.Event()
    app = create_app(engine)

    @app.get("/healthz-5903-ungated-probe")
    @public_route("a test probe for BACKLOG #5903")
    async def _op() -> dict[str, str]:
        await ops.run(_hangs(started), "DR release")
        return {"ran": "yes"}

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://127.0.0.1") as client:
        sent = asyncio.create_task(client.get("/healthz-5903-ungated-probe"))
        await asyncio.wait_for(started.wait(), _WAIT_S)
        assert await ops.drain(timeout=0.0, grace=5.0) == ["DR release"]
        response = await asyncio.wait_for(sent, _WAIT_S)
    assert response.status_code == 503, response.text
    detail = response.json()["detail"]
    assert detail.startswith("DR release was interrupted before it answered")
    assert "Check the audit log and the state it changes before running it again." in detail
    assert "approval" not in detail
