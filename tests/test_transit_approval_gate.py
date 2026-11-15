# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The approval gate under the Transit row sealer (ADR 0217): an Unverifiable request is denied as a
Forged one is, under its own audit action and page, and an Outage refuses the request with a 503,
pages under the Outage subject and records no seal failure. Synthetic data only."""

from __future__ import annotations

import sqlite3
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import pytest

from messagefoundry.api.approvals import ApprovalError, ApprovalGate
from messagefoundry.auth.permissions import Permission
from messagefoundry.auth.service import (
    AUTHORITY_SEAL_FAILED_ACTION,
    AUTHORITY_SEAL_UNVERIFIABLE_ACTION,
)
from messagefoundry.config.settings import ApprovalsSettings
from messagefoundry.store.crypto import generate_key, make_cipher
from messagefoundry.store.row_seal import (
    TRANSIT_OUTAGE_SUBJECT,
    UNVERIFIABLE_SUBJECT_PREFIX,
    TransitRowSealer,
)
from messagefoundry.store.store import MessageStore
from tests._pending_approval_store_contract import _resolve, _StandingStore
from tests._transit_seal_fake import FakeBackend, with_version


@pytest.fixture
async def transit(tmp_path: Path) -> AsyncIterator[tuple[MessageStore, FakeBackend, Path]]:
    path = tmp_path / "transit.db"
    store = await MessageStore.open(path, cipher=make_cipher(generate_key(), write_v2=True))
    backend = FakeBackend()
    store._row_sealer = TransitRowSealer(backend)
    try:
        yield store, backend, path
    finally:
        await store.close()


def _sql(path: Path, sql: str, params: tuple[object, ...] = ()) -> list[tuple[object, ...]]:
    conn = sqlite3.connect(path)
    try:
        rows = conn.execute(sql, params).fetchall()
        conn.commit()
        return rows
    finally:
        conn.close()


def _gate(store: MessageStore) -> ApprovalGate:
    async def run(_params: Any) -> dict[str, Any]:
        return {}

    gate = ApprovalGate(
        _StandingStore(store),
        ApprovalsSettings(enabled=True, operations=["dead_letter_replay"], min_dwell_seconds=0.0),
        resolve_identity=_resolve,
    )
    gate.register("dead_letter_replay", "op", run, permission=Permission.MESSAGES_REPLAY)
    return gate


async def _executing(store: MessageStore, path: Path, approval_id: str) -> None:
    """A release stranded in ``executing``, claimed by a node with no heartbeat. Its fields are
    moved outside the store, which only matters if Transit answers its seal at all."""
    await store.create_pending_approval(
        approval_id=approval_id,
        operation="dead_letter_replay",
        params='{"n": "synthetic"}',
        requester="r",
        requester_user_id="r-id",
        requested_at=1.0,
        expires_at=None,
    )
    _sql(
        path,
        "UPDATE pending_approvals SET status='executing', approver='ap', decided_at=2.0,"
        " claim_owner='node:gone' WHERE id=?",
        (approval_id,),
    )


def _plant_unverifiable(path: Path, approval_id: str) -> None:
    """Name version 5 in the stored seal, which the stand-in does not hold: Transit answers 400
    while its probe works, the Unverifiable answer."""
    (seal,) = _sql(path, "SELECT seal FROM pending_approvals WHERE id=?", (approval_id,))[0]
    _sql(
        path,
        "UPDATE pending_approvals SET seal=? WHERE id=?",
        (with_version(str(seal), "5"), approval_id),
    )


async def _rows(store: MessageStore, action: str, approval_id: str) -> list[Any]:
    return [
        r
        for r in await store.list_audit(action=action, limit=50)
        if approval_id in str(r["detail"])
    ]


def _arm(store: MessageStore) -> list[str]:
    pages: list[str] = []
    store.seal_pager().arm(lambda subject, _reason: pages.append(subject))
    return pages


async def test_an_unverifiable_executing_release_is_hidden_audited_and_paged(
    transit: tuple[MessageStore, FakeBackend, Path],
) -> None:
    store, _, path = transit
    await _executing(store, path, "a-1")
    _plant_unverifiable(path, "a-1")
    pages = _arm(store)
    gate = _gate(store)

    assert await gate.list_executing() == []  # left out, as a Forged row is, never a 500
    with pytest.raises(ApprovalError) as refused:
        await gate.interrupt_stranded("a-1", actor="op", actor_user_id="op-id")
    assert refused.value.status == 409

    audited = await _rows(store, AUTHORITY_SEAL_UNVERIFIABLE_ACTION, "a-1")
    assert len(audited) == 1  # throttled per request, as a Forged report is
    assert '"stored_version": 5' in str(audited[0]["detail"])
    assert await _rows(store, AUTHORITY_SEAL_FAILED_ACTION, "a-1") == []
    assert len(pages) == 1 and pages[0].startswith(f"{UNVERIFIABLE_SUBJECT_PREFIX}:approval:a-1:")
    assert _sql(path, "SELECT status FROM pending_approvals WHERE id=?", ("a-1",)) == [
        ("executing",)
    ]


@pytest.mark.parametrize("route", ["list_executing", "interrupt_stranded"])
async def test_an_outage_refuses_the_route_with_a_503_and_pages_without_an_audit_row(
    transit: tuple[MessageStore, FakeBackend, Path], route: str
) -> None:
    store, backend, path = transit
    await _executing(store, path, "a-1")
    store._row_sealer = TransitRowSealer(backend)  # nothing cached
    pages = _arm(store)
    gate = _gate(store)

    backend.down = True
    try:
        with pytest.raises(ApprovalError) as refused:
            if route == "list_executing":
                await gate.list_executing()
            else:
                await gate.interrupt_stranded("a-1", actor="op", actor_user_id="op-id")
    finally:
        backend.down = False
    assert refused.value.status == 503
    assert refused.value.headers is not None and "Retry-After" in refused.value.headers
    assert pages == [TRANSIT_OUTAGE_SUBJECT]
    assert await _rows(store, AUTHORITY_SEAL_UNVERIFIABLE_ACTION, "a-1") == []
    assert await _rows(store, AUTHORITY_SEAL_FAILED_ACTION, "a-1") == []
    assert _sql(path, "SELECT status FROM pending_approvals WHERE id=?", ("a-1",)) == [
        ("executing",)
    ]
