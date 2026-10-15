# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Cross-backend contract for sealed dual-control approval requests (BACKLOG #2592).

Deliberately **extra-free**, as ``tests/_role_seal_contract.py`` is: it imports nothing optional,
so the live Postgres and SQL Server suites import it inside their test functions and run the same
assertions on legs that install only their own driver extra.

The caller passes a store opened with a store key, and ``raw``: a way to run one SQL statement
against the same database without going through the store's helpers, written with ``?``
placeholders. Every refusal below has a control beside it: the same request is released, listed,
joined or moved before the change, or the same change made through the store takes effect.

The server legs share one ``pending_approvals`` table across tests, so every assertion here is
keyed on the ids this contract filed, and every alert and audit count names its request.
"""

from __future__ import annotations

import json
import time
from collections.abc import Mapping
from dataclasses import fields
from typing import Any
from uuid import uuid4

import pytest

from messagefoundry.api.approvals import ApprovalError, ApprovalGate
from messagefoundry.auth.permissions import Permission
from messagefoundry.auth.service import AUTHORITY_SEAL_FAILED_ACTION
from messagefoundry.config.settings import ApprovalsSettings
from messagefoundry.pipeline.alerts import AUTHORITY_SEAL_SUBJECT, LoggingAlertSink
from messagefoundry.store.row_seal import SEAL_PREFIX, RowSealError
from messagefoundry.store.store import ApprovalRow, approval_seal_ok
from tests._pending_approval_store_contract import _resolve, _StandingStore
from tests._session_seal_contract import RawSql

_OP = "dead_letter_replay"
_REQUESTER = "seal-contract-requester"
_REQUESTER_ID = "seal-contract-requester-id"
_APPROVER = "seal-contract-approver"
_APPROVER_ID = "seal-contract-approver-id"

#: Each sealed column, and a value that differs from what the gate writes for a fresh request.
_SEALED_CHANGES: tuple[tuple[str, Any], ...] = (
    ("operation", "config_reload"),
    ("params", json.dumps({"channel_id": "IB_OTHER"})),
    ("requester", "someone-else"),
    ("requester_user_id", "someone-else-id"),
    ("requested_at", 1.0),
    ("status", "interrupted"),
    ("approver", "someone-else"),
    ("decided_at", 2.0),
    ("expires_at", 4_000_000_000.0),
    ("claim_owner", "node:elsewhere"),
)


class _Sink(LoggingAlertSink):
    """Records each ``integrity_drift`` reason the authority-seal subject raises."""

    def __init__(self) -> None:
        super().__init__()
        self.reasons: list[str] = []

    def integrity_drift(self, name: str, *, reason: str, drift_count: int) -> None:
        if name == AUTHORITY_SEAL_SUBJECT:
            self.reasons.append(reason)


class _Harness:
    def __init__(self, store: Any, raw: RawSql) -> None:
        self.store = store
        self.raw = raw
        self.sink = _Sink()
        self.runs: list[Mapping[str, Any]] = []
        self.gate = ApprovalGate(
            _StandingStore(store),
            ApprovalsSettings(enabled=True, operations=[_OP], min_dwell_seconds=0.0),
            resolve_identity=_resolve,
            alert_sink=self.sink,
        )
        self.gate.register(_OP, "contract op", self._run, permission=Permission.MESSAGES_REPLAY)

    async def _run(self, params: Mapping[str, Any]) -> dict[str, Any]:
        self.runs.append(dict(params))
        return {"ran": True}

    async def request(self, *, requester_user_id: str = _REQUESTER_ID, **extra: Any) -> str:
        """A fresh request. The params carry a nonce, so it never joins a request another test left
        in a shared server table."""
        filed = await self.gate.guard(
            _OP,
            {"contract_nonce": uuid4().hex, **extra},
            requester=_REQUESTER,
            requester_user_id=requester_user_id,
        )
        assert filed is not None
        return str(filed)

    async def row(self, approval_id: str) -> ApprovalRow:
        found = await self.store.get_pending_approval(approval_id)
        assert found is not None, approval_id
        return ApprovalRow.from_mapping(found)

    async def approve(self, approval_id: str, *, approver_user_id: str = _APPROVER_ID) -> Any:
        return await self.gate.approve(
            approval_id, approver=_APPROVER, approver_user_id=approver_user_id
        )

    def alerted(self, approval_id: str) -> int:
        return sum(f"(approval {approval_id})" in r for r in self.sink.reasons)

    async def seal_failures(self, approval_id: str) -> int:
        rows = await self.store.list_audit(action=AUTHORITY_SEAL_FAILED_ACTION, limit=500)
        return sum(approval_id in str(r["detail"]) for r in rows)

    async def listed(self, approval_id: str) -> bool:
        return approval_id in {e["id"] for e in await self.gate.list_pending()}

    async def refused(self, approval_id: str) -> None:
        """Approve and reject both refuse the pending ``approval_id`` with the seal refusal."""
        for attempt in (
            self.approve(approval_id),
            self.gate.reject(approval_id, approver=_APPROVER),
        ):
            with pytest.raises(ApprovalError) as refusal:
                await attempt
            assert refusal.value.status == 409 and "integrity" in refusal.value.detail

    async def load(self, approval_id: str) -> ApprovalRow:
        return await self.gate._load(approval_id, status="pending", wrong=str)


async def assert_approval_seal_contract(store: Any, raw: RawSql) -> None:
    """Drive the sealed approval request through its contract on ``store``'s backend."""
    sealer = store.row_sealer()
    assert sealer is not None, "the contract needs a store opened with a store key"
    h = _Harness(store, raw)

    # --- a request the gate filed carries a seal, is listed, and releases ----------------------
    good = await h.request()
    row = await h.row(good)
    assert row.seal.startswith(SEAL_PREFIX) and approval_seal_ok(sealer, row)
    assert await h.listed(good)
    released = await h.approve(good)
    assert released["result"] == {"ran": True} and len(h.runs) == 1
    settled = await h.row(good)
    assert settled.status == "approved" and approval_seal_ok(sealer, settled)  # each move re-seals
    assert h.alerted(good) == 0 and await h.seal_failures(good) == 0  # control

    # --- held params changed outside the store run nothing, and the row is not re-sealed -------
    widened = await h.request(channel_id="IB_A")
    await raw(
        "UPDATE pending_approvals SET params=? WHERE id=?",
        (json.dumps({"channel_id": "IB_ALL"}), widened),
    )
    planted = await h.row(widened)
    assert not await h.listed(widened)
    await h.refused(widened)
    assert h.runs == [h.runs[0]]  # nothing new ran
    assert await h.row(widened) == planted  # every refusal wrote nothing: no status, no new seal
    assert h.alerted(widened) == 1  # reported once in the interval, however often it is read
    assert await h.seal_failures(widened) == 1

    # --- a requester id changed outside the store cannot open the self-approval refusal --------
    own = await h.request()
    with pytest.raises(ApprovalError) as self_approval:  # control: the refusal holds untouched
        await h.approve(own, approver_user_id=_REQUESTER_ID)
    assert self_approval.value.status == 403
    await raw(
        "UPDATE pending_approvals SET requester_user_id=? WHERE id=?", ("someone-else-id", own)
    )
    with pytest.raises(ApprovalError) as moved_requester:
        await h.approve(own, approver_user_id=_REQUESTER_ID)
    assert moved_requester.value.status == 409
    assert h.runs == [h.runs[0]]

    # --- every sealed column changed outside the store makes the request act on nothing --------
    for column, value in _SEALED_CHANGES:
        changed = await h.request()
        assert (await h.load(changed)).id == changed, column  # control
        await raw(f"UPDATE pending_approvals SET {column}=? WHERE id=?", (value, changed))
        with pytest.raises(ApprovalError) as refusal:
            await h.load(changed)
        assert refusal.value.status == 409, column

    # --- a request inserted outside the store, or given another's seal, is refused -------------
    inserted = uuid4().hex
    now = time.time()
    await raw(
        "INSERT INTO pending_approvals (id, operation, params, requester, requester_user_id,"
        " requested_at, status) VALUES (?,?,?,?,?,?,?)",
        (inserted, _OP, "{}", _REQUESTER, _REQUESTER_ID, now, "pending"),
    )
    assert not await h.listed(inserted)
    await h.refused(inserted)
    donor = await h.row(await h.request())
    await raw("UPDATE pending_approvals SET seal=? WHERE id=?", (donor.seal, inserted))
    with pytest.raises(ApprovalError):
        await h.approve(inserted)
    assert h.runs == [h.runs[0]]

    # --- a repeat never joins a request that fails; it joins one that holds ---------------------
    nonce = uuid4().hex

    async def repeat() -> str:
        filed = await h.gate.guard(
            _OP, {"contract_nonce": nonce}, requester=_REQUESTER, requester_user_id=_REQUESTER_ID
        )
        assert filed is not None
        return str(filed)

    first = await repeat()
    assert await repeat() == first  # control: an open request that holds is joined
    assert (
        await h.gate.rejoin(
            _OP, {"contract_nonce": nonce}, requester=_REQUESTER, requester_user_id=_REQUESTER_ID
        )
        == first
    )  # control, the proof-free path
    await raw("UPDATE pending_approvals SET requester=? WHERE id=?", ("someone-else", first))
    assert (
        await h.gate.rejoin(
            _OP, {"contract_nonce": nonce}, requester=_REQUESTER, requester_user_id=_REQUESTER_ID
        )
        is None
    )
    fresh = await repeat()
    assert fresh != first and approval_seal_ok(sealer, await h.row(fresh))
    assert await repeat() == fresh  # and the new request is the one later repeats join

    # --- the store's own move refuses a row that fails, and does not re-seal it ----------------
    moved = await h.request()
    assert await store.decide_pending_approval(  # control: an untouched row moves, re-sealed
        moved, status="rejected", approver=_APPROVER, decided_at=time.time()
    )
    assert approval_seal_ok(sealer, await h.row(moved))
    tampered = await h.request()
    await raw("UPDATE pending_approvals SET params=? WHERE id=?", ('{"x": 1}', tampered))
    before = await h.row(tampered)
    with pytest.raises(RowSealError):
        await store.decide_pending_approval(
            tampered, status="rejected", approver=_APPROVER, decided_at=time.time()
        )
    assert await h.row(tampered) == before

    # --- a row changed between the gate's read and its claim is refused at the claim -----------
    raced = await h.request()
    real_decide = store.decide_pending_approval

    async def tamper_then_claim(approval_id: str, **kw: Any) -> bool:
        if approval_id == raced and kw.get("status") == "executing":
            await raw("UPDATE pending_approvals SET params=? WHERE id=?", ('{"y": 2}', raced))
        return bool(await real_decide(approval_id, **kw))

    racing = _Harness(_Hooked(store, tamper_then_claim), raw)
    with pytest.raises(ApprovalError) as claim_refusal:
        await racing.approve(raced)
    assert claim_refusal.value.status == 409 and racing.runs == []
    assert (await h.row(raced)).status == "pending" and racing.alerted(raced) == 1

    # --- a row changed while its operation ran is left 'executing', and reported ---------------
    running = await h.request()

    async def tamper_while_running(params: Mapping[str, Any]) -> dict[str, Any]:
        await raw("UPDATE pending_approvals SET params=? WHERE id=?", ('{"z": 3}', running))
        return {"ran": True}

    mid = _Harness(store, raw)
    mid.gate.register(
        _OP, "contract op", tamper_while_running, permission=Permission.MESSAGES_REPLAY
    )
    result = await mid.approve(running)
    assert result["result"] == {"ran": True}  # the operation ran; its answer stands
    assert (await h.row(running)).status == "executing" and mid.alerted(running) == 1
    # A restart leaves it as it is, reported, while it moves this process's sound leftover.
    leftover = await h.request()
    assert await store.decide_pending_approval(
        leftover,
        status="executing",
        approver=_APPROVER,
        decided_at=time.time(),
        claim_owner=h.gate.claim_owner,
    )
    restarted = _Harness(store, raw)
    found = await restarted.gate.reconcile_after_restart()
    assert leftover in found.interrupted  # control
    assert running not in found.interrupted and running not in found.unsettled
    assert (await h.row(running)).status == "executing" and restarted.alerted(running) == 1

    # --- an interrupted release resolves while sound, and is refused once changed --------------
    resolvable = await h.request()
    for to, frm in (("executing", "pending"), ("interrupted", "executing")):
        assert await store.decide_pending_approval(
            resolvable, status=to, approver=_APPROVER, decided_at=time.time(), from_status=frm
        )
    assert resolvable in {e["id"] for e in await h.gate.list_interrupted()}
    cut = await h.request()
    for to, frm in (("executing", "pending"), ("interrupted", "executing")):
        assert await store.decide_pending_approval(
            cut, status=to, approver=_APPROVER, decided_at=time.time(), from_status=frm
        )
    await raw("UPDATE pending_approvals SET approver=? WHERE id=?", ("someone-else", cut))
    assert cut not in {e["id"] for e in await h.gate.list_interrupted()}
    with pytest.raises(ApprovalError) as resolve_refusal:
        await h.gate.resolve_interrupted(
            cut, outcome="effects_applied", resolver=_APPROVER, resolver_user_id=_APPROVER_ID
        )
    assert resolve_refusal.value.status == 409 and "integrity" in resolve_refusal.value.detail
    resolved = await h.gate.resolve_interrupted(  # control
        resolvable, outcome="effects_applied", resolver=_APPROVER, resolver_user_id=_APPROVER_ID
    )
    assert resolved["status"] == "resolved_applied"

    # --- a decided request answers 'already decided', and raises no alarm -------------------
    decided = await h.request()
    assert await store.decide_pending_approval(
        decided, status="rejected", approver=_APPROVER, decided_at=time.time()
    )
    await raw("UPDATE pending_approvals SET seal='' WHERE id=?", (decided,))
    with pytest.raises(ApprovalError) as stale:
        await h.approve(decided)
    assert stale.value.status == 409 and "already rejected" in stale.value.detail
    assert h.alerted(decided) == 0 and await h.seal_failures(decided) == 0

    # --- a request with no seal is counted at open ---------------------------------------------
    blank = await h.request()
    unsealed_before = await store.count_unsealed_approvals()
    await raw("UPDATE pending_approvals SET seal='' WHERE id=?", (blank,))
    assert await store.count_unsealed_approvals() == unsealed_before + 1
    await h.refused(blank)


class _Hooked:
    """``store``, except that ``decide_pending_approval`` runs ``decide`` instead."""

    def __init__(self, store: Any, decide: Any) -> None:
        self._store = store
        self.decide_pending_approval = decide

    def __getattr__(self, name: str) -> Any:
        return getattr(self._store, name)


def assert_approval_columns(columns: set[str]) -> None:
    """The ``pending_approvals`` table's columns are the record the seal covers."""
    assert columns == {f.name for f in fields(ApprovalRow)}
