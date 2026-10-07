# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Vault BACKLOG #2445, engine half: a repeat of an open request files nothing.

Before the fix every call to a gated route filed a new pending approval. A retried IDE promote, a
double click in the web console, a retrying API client, or two of those racing left an approver
several pending copies of one operation. Now ``ApprovalGate.guard`` answers a repeat with the open
request's id, the same 202, and an ``approval.request_repeated`` audit row.

The gate runs over a real SQLite store. The cross-backend half is
``_assert_repeat_request_contract``, which the Postgres and SQL Server legs run too.
"""

from __future__ import annotations

import asyncio
import json
import sqlite3
from collections.abc import AsyncIterator, Mapping
from pathlib import Path
from typing import Any

import pytest

from messagefoundry.api.approvals import ApprovalGate
from messagefoundry.auth import Role
from messagefoundry.auth.permissions import Permission
from messagefoundry.config.settings import ApprovalsSettings, EgressSettings
from messagefoundry.pipeline import Engine
from messagefoundry.pipeline.alerts import LoggingAlertSink
from messagefoundry.store.store import MessageStore
from tests._pending_approval_store_contract import (
    _REQUESTER_ID,
    _assert_repeat_request_contract,
    _resolve,
    _StandingStore,
)

_OP = "dead_letter_replay"


class _Clock:
    def __init__(self) -> None:
        self.now = 1_000.0

    def __call__(self) -> float:
        return self.now


class _Sink(LoggingAlertSink):
    def __init__(self) -> None:
        self.lost: list[tuple[str, str]] = []

    def audit_write_failed(self, name: str, *, action: str) -> None:
        self.lost.append((name, action))


@pytest.fixture
async def store(tmp_path: Path) -> AsyncIterator[MessageStore]:
    s = await MessageStore.open(tmp_path / "repeat.db")
    yield s
    await s.close()


def _gate(store: Any, clock: _Clock | None = None, sink: _Sink | None = None) -> ApprovalGate:
    settings = ApprovalsSettings(
        enabled=True, operations=[_OP], min_dwell_seconds=0.0, expiry_hours=1
    )
    gate = ApprovalGate(
        _StandingStore(store),
        settings,
        resolve_identity=_resolve,
        alert_sink=sink,
        clock=clock or _Clock(),
    )

    async def _execute(_p: Mapping[str, Any]) -> dict[str, Any]:
        return {"requeued": 0}

    gate.register(_OP, "op", _execute, permission=Permission.MESSAGES_REPLAY)
    return gate


async def _guard(
    gate: ApprovalGate,
    params: Mapping[str, Any] | None = None,
    *,
    requester: str = "maker",
    requester_user_id: str = _REQUESTER_ID,
) -> str:
    held = await gate.guard(
        _OP,
        {"channel_id": "IB_A"} if params is None else params,
        requester=requester,
        requester_user_id=requester_user_id,
    )
    assert held is not None
    return held


async def test_a_repeat_returns_the_open_request_and_files_nothing(store: MessageStore) -> None:
    gate = _gate(store)
    first = await _guard(gate)
    assert await _guard(gate) == first
    pending = await store.list_pending_approvals(now=0.0)
    assert [str(r["id"]) for r in pending] == [first]
    assert len(await store.list_audit(action="approval.requested")) == 1
    repeated = await store.list_audit(action="approval.request_repeated")
    assert len(repeated) == 1
    assert str(repeated[0]["actor"]) == "maker"
    assert json.loads(str(repeated[0]["detail"])) == {"approval_id": first, "operation": _OP}


async def test_concurrent_repeats_file_one_request(store: MessageStore) -> None:
    """The race the IDE and the console could both reach: several identical calls in flight."""
    gate = _gate(store)
    held = await asyncio.gather(*(_guard(gate) for _ in range(8)))
    assert len(set(held)) == 1
    assert len(await store.list_pending_approvals(now=0.0)) == 1
    assert len(await store.list_audit(action="approval.request_repeated")) == 7


async def test_a_different_requester_files_their_own_request(store: MessageStore) -> None:
    """The requester of record is whose authority the release re-checks, so a second person is
    never folded into the first one's request."""
    gate = _gate(store)
    first = await _guard(gate)
    other = await _guard(gate, requester="maker-2", requester_user_id="maker-2-id")
    assert other != first
    assert len(await store.list_pending_approvals(now=0.0)) == 2
    assert await store.list_audit(action="approval.request_repeated") == []


async def test_different_params_file_their_own_request(store: MessageStore) -> None:
    gate = _gate(store)
    first = await _guard(gate, {"channel_id": "IB_A"})
    assert await _guard(gate, {"channel_id": "IB_B"}) != first
    # Key order does not matter: the gate captures params with sorted keys.
    both = await _guard(gate, {"channel_id": "IB_C", "destination_name": "OB_X"})
    assert await _guard(gate, {"destination_name": "OB_X", "channel_id": "IB_C"}) == both


async def test_a_decided_or_expired_request_is_not_joined(store: MessageStore) -> None:
    clock = _Clock()
    gate = _gate(store, clock)
    first = await _guard(gate)
    await gate.reject(first, approver="checker")
    second = await _guard(gate)
    assert second != first
    clock.now += 3_601.0  # past expiry_hours=1
    third = await _guard(gate)
    assert third not in (first, second)


async def test_a_repeat_joins_the_original_and_releasing_it_runs_once(store: MessageStore) -> None:
    """The point of the fix for an approver: one request to release, and one run."""
    runs: list[str] = []
    gate = _gate(store)

    async def _execute(_p: Mapping[str, Any]) -> dict[str, Any]:
        runs.append("ran")
        return {"requeued": 0}

    gate.register(_OP, "op", _execute, permission=Permission.MESSAGES_REPLAY)
    first = await _guard(gate)
    await _guard(gate)
    await gate.approve(first, approver="checker", approver_user_id="checker-id")
    assert runs == ["ran"]
    assert await store.list_pending_approvals(now=0.0) == []


async def test_a_lost_repeat_row_pages_on_the_request_it_named(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The repeat's row is the record that someone asked again. If it cannot be written the call
    fails, nothing new is held, and the page is keyed on the open request, not on an id that was
    never filed."""
    sink = _Sink()
    gate = _gate(store, sink=sink)
    first = await _guard(gate)
    real = store._append_audit_row

    async def _append(action: str, **kwargs: Any) -> Any:
        if action == "approval.request_repeated":
            raise sqlite3.OperationalError("disk I/O error")
        return await real(action, **kwargs)

    monkeypatch.setattr(store, "_append_audit_row", _append)
    with pytest.raises(sqlite3.OperationalError):
        await _guard(gate)
    assert sink.lost == [(f"approval:{first}", "approval.request_repeated")]
    assert [str(r["id"]) for r in await store.list_pending_approvals(now=0.0)] == [first]


async def test_repeat_request_store_contract(store: MessageStore) -> None:
    """The SQLite leg of the cross-backend repeat contract."""
    await _assert_repeat_request_contract(store)


async def test_a_repeated_replay_post_answers_the_same_202(tmp_path: Path) -> None:
    """At the route: the second identical POST answers the same 202 shape with the same id. An
    IDE, the console or an API client reads it as held, exactly as it read the first."""
    from tests.test_approvals import ON, _add, _client, _request_replay, _service, _token

    engine = await Engine.create(
        tmp_path / "route.db",
        poll_interval=0.02,
        egress_settings=EgressSettings(deny_by_default=False),
    )
    try:
        service = await _service(engine)
        await _add(service, "op", Role.OPERATOR)
        async with _client(engine, service, ON) as c:
            headers = await _token(c, "op")
            first = await _request_replay(c, headers)
            second = await _request_replay(c, headers)
        assert first.status_code == second.status_code == 202
        assert second.json() == first.json()
        assert len(await engine.store.list_pending_approvals(now=0.0)) == 1
    finally:
        await engine.stop()
