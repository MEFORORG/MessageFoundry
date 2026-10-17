# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Vault BACKLOG #3192, engine half: the queue names a release the gate always refuses.

The console offered Approve on a row the gate refuses whoever approves it: one with no recorded
requester id, or whose operation is not registered. The queue now carries ``release_blocked``, read
from the same tests :meth:`ApprovalGate.approve` refuses on and in the same order, so the page can
offer only the reject. The tests here hold each kind of row and check the prediction against the
real refusal.

The unreadable-params refusal also wrote no audit row, unlike the gate's other refusals. It now
writes ``approval.params_unreadable``, soft like them.

A held purge whose params name no requester was refused by its executor only after the claim
(vault BACKLOG #3217), so the queue offered Approve and the release ended ``failed``. An operation
registered with ``requires_requester`` is now marked ``params_no_requester`` and refused before the
claim, audited as ``approval.params_no_requester``.

The gate runs over a real SQLite store. The odd rows are written through the store directly,
because no request through ``guard`` can produce them.
"""

from __future__ import annotations

import json
from collections.abc import AsyncIterator, Mapping
from pathlib import Path
from typing import Any, get_args
from uuid import uuid4

import pytest

from messagefoundry.api.approvals import ApprovalError, ApprovalGate
from messagefoundry.api.models import ReleaseBlocked
from messagefoundry.auth.permissions import Permission
from messagefoundry.config.settings import ApprovalsSettings
from messagefoundry.store.store import MessageStore
from tests._pending_approval_store_contract import _REQUESTER_ID, _resolve, _StandingStore
from tests.test_approval_audit_outage import _Faulty, _Sink

_REPLAY = "dead_letter_replay"
_PURGE = "connection_purge"
_RELOAD = "config_reload"
_APPROVER_ID = "blocked-approver-id"


@pytest.fixture
async def store(tmp_path: Path) -> AsyncIterator[MessageStore]:
    s = await MessageStore.open(tmp_path / "blocked.db")
    yield s
    await s.close()


def _gate(store: Any, runs: list[str], sink: _Sink | None = None) -> ApprovalGate:
    # The purge is registered but not gated; the reload is gated but not registered.
    settings = ApprovalsSettings(enabled=True, operations=[_REPLAY, _RELOAD], min_dwell_seconds=0.0)
    gate = ApprovalGate(_StandingStore(store), settings, resolve_identity=_resolve, alert_sink=sink)

    async def _execute(_p: Mapping[str, Any]) -> dict[str, Any]:
        runs.append("ran")
        return {"requeued": 0}

    # The replay stands in for an executor that needs the requester's name, as the real purge does
    # (vault BACKLOG #3217); only the replay is both registered and gated here.
    for key in (_REPLAY, _PURGE):
        # A requester is out of scope for a row whose params say so (BACKLOG #3189), standing in
        # for a held reload or purge whose requester has since been channel-scoped.
        gate.register(
            key,
            "op",
            _execute,
            permission=Permission.MESSAGES_REPLAY,
            in_scope=lambda _identity, p: not p.get("out_of_scope"),
            requires_requester=True,
        )
    return gate


_NAMED = json.dumps({"requester": "maker"})


async def _row(
    store: MessageStore,
    *,
    operation: str = _REPLAY,
    params: str = _NAMED,
    requester_user_id: str = _REQUESTER_ID,
) -> str:
    approval_id = uuid4().hex
    await store.create_pending_approval(
        approval_id=approval_id,
        operation=operation,
        params=params,
        requester="maker",
        requester_user_id=requester_user_id,
        requested_at=1.0,
        expires_at=None,
    )
    return approval_id


async def _rows(store: MessageStore) -> dict[str, ReleaseBlocked | None]:
    """One request per reason, and one the gate would release, mapped to the reason expected."""
    return {
        await _row(store, requester_user_id=""): "no_requester_id",
        await _row(store, operation=_RELOAD): "operation_unavailable",
        await _row(store, operation=_PURGE): "not_gated",
        await _row(store, params="[1]"): "params_unreadable",
        await _row(store, params="{}"): "params_no_requester",
        await _row(store, params=json.dumps({"requester": ""})): "params_no_requester",
        # Both reasons hold; the params test comes first, in the queue and in approve() alike.
        await _row(store, params=json.dumps({"out_of_scope": True})): "params_no_requester",
        await _row(
            store, params=json.dumps({"out_of_scope": True, "requester": "maker"})
        ): "requester_not_authorized",
        await _row(store): None,
    }


async def test_the_queue_names_each_release_the_gate_always_refuses(store: MessageStore) -> None:
    expected = await _rows(store)
    assert set(expected.values()) - {None} == set(get_args(ReleaseBlocked))  # every reason held
    listed = {e["id"]: e["release_blocked"] for e in await _gate(store, []).list_pending()}
    assert listed == expected


async def test_the_prediction_matches_the_refusal(store: MessageStore) -> None:
    """A row the queue marks blocked is refused with 409 and stays pending; the unmarked one is
    released. So the page hides Approve exactly where the gate refuses it."""
    expected = await _rows(store)
    runs: list[str] = []
    gate = _gate(store, runs)
    for approval_id, reason in expected.items():
        if reason is None:
            await gate.approve(approval_id, approver="checker", approver_user_id=_APPROVER_ID)
            continue
        with pytest.raises(ApprovalError) as caught:
            await gate.approve(approval_id, approver="checker", approver_user_id=_APPROVER_ID)
        assert caught.value.status == 409, reason
        row = await store.get_pending_approval(approval_id)
        assert row is not None and str(row["status"]) == "pending", reason
    assert runs == ["ran"]
    # The requester refusal is still the stale-requester refusal, with its own reason slug.
    [stale] = await store.list_audit(action="approval.stale_requester")
    assert json.loads(str(stale["detail"]))["reason"] == "requester_out_of_scope"
    # Each row predicted params_no_requester was refused on it, the combined row included.
    unnamed = await store.list_audit(action="approval.params_no_requester")
    assert sorted(json.loads(str(r["detail"]))["approval_id"] for r in unnamed) == sorted(
        k for k, v in expected.items() if v == "params_no_requester"
    )


async def test_an_unreadable_params_refusal_writes_its_audit_row(store: MessageStore) -> None:
    approval_id = await _row(store, params="[1]")
    with pytest.raises(ApprovalError) as caught:
        await _gate(store, []).approve(
            approval_id, approver="checker", approver_user_id=_APPROVER_ID
        )
    assert caught.value.status == 409
    [row] = await store.list_audit(action="approval.params_unreadable")
    assert str(row["actor"]) == "checker"
    detail = json.loads(str(row["detail"]))
    # The params are what could not be read, so the row carries none of them.
    assert detail == {"approval_id": approval_id, "operation": _REPLAY, "requester": "maker"}


async def test_a_lost_unreadable_params_row_still_answers_409_and_pages(
    store: MessageStore,
) -> None:
    approval_id = await _row(store, params="[1]")
    sink = _Sink()
    gate = _gate(_Faulty(store, audit_fails=("approval.params_unreadable",)), [], sink)
    with pytest.raises(ApprovalError) as caught:
        await gate.approve(approval_id, approver="checker", approver_user_id=_APPROVER_ID)
    assert caught.value.status == 409
    assert sink.lost == [(f"approval:{approval_id}", "approval.params_unreadable")]


async def test_a_no_requester_refusal_writes_its_audit_row(store: MessageStore) -> None:
    """Vault BACKLOG #3217 met at the gate: refused before the claim, so nothing ran and nothing
    was claimed, and the refusal is audited against the approver."""
    approval_id = await _row(store, params="{}")
    runs: list[str] = []
    with pytest.raises(ApprovalError) as caught:
        await _gate(store, runs).approve(
            approval_id, approver="checker", approver_user_id=_APPROVER_ID
        )
    assert caught.value.status == 409 and runs == []
    [row] = await store.list_audit(action="approval.params_no_requester")
    assert str(row["actor"]) == "checker"
    detail = json.loads(str(row["detail"]))
    assert detail == {"approval_id": approval_id, "operation": _REPLAY, "requester": "maker"}
    assert await store.list_audit(action="approval.release_attempted") == []


async def test_a_lost_no_requester_row_still_answers_409_and_pages(store: MessageStore) -> None:
    approval_id = await _row(store, params="{}")
    sink = _Sink()
    gate = _gate(_Faulty(store, audit_fails=("approval.params_no_requester",)), [], sink)
    with pytest.raises(ApprovalError) as caught:
        await gate.approve(approval_id, approver="checker", approver_user_id=_APPROVER_ID)
    assert caught.value.status == 409
    assert sink.lost == [(f"approval:{approval_id}", "approval.params_no_requester")]


async def test_an_operation_not_needing_the_requester_releases_without_one(
    store: MessageStore,
) -> None:
    """The negative control: the default, ``requires_requester=False``, leaves params naming no
    requester releasable, as the real replay is."""
    settings = ApprovalsSettings(enabled=True, operations=[_REPLAY], min_dwell_seconds=0.0)
    gate = ApprovalGate(_StandingStore(store), settings, resolve_identity=_resolve)
    runs: list[str] = []

    async def _execute(_p: Mapping[str, Any]) -> dict[str, Any]:
        runs.append("ran")
        return {"requeued": 0}

    gate.register(_REPLAY, "op", _execute, permission=Permission.MESSAGES_REPLAY)
    approval_id = await _row(store, params="{}")
    [entry] = await gate.list_pending()
    assert entry["release_blocked"] is None
    await gate.approve(approval_id, approver="checker", approver_user_id=_APPROVER_ID)
    assert runs == ["ran"]
