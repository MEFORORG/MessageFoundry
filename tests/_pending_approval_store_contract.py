# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Cross-backend store contract for ``pending_approvals.requester_user_id`` (BACKLOG #1540).

The dual-control self-approval refusal keys on this column, so a backend that fails to carry it does
not degrade -- ``ApprovalGate.approve`` reads NULL and refuses EVERY release fail-closed, which turns
dual control off for that store while every request still returns a plausible 202.

``tests/test_store_schema_hash.py`` pins the DDL **text** on all three backends, and that is not the
same assertion. The DDL check cannot see a typo in the ``INSERT`` or ``SELECT`` column list, and this
change rewrote both on all three backends -- a column named correctly in ``CREATE TABLE`` and omitted
from the ``SELECT`` projection reads back as absent, which is indistinguishable from the migration
never having run. This body round-trips the value through the real store object instead, so the
PostgreSQL and SQL Server legs execute their own SQL rather than having it read.

Deliberately **extra-free**: it imports nothing outside the store object it is handed, so the live
server legs can import it inside a test function.
"""

from __future__ import annotations

from typing import Any

#: Distinct from the username on purpose. A backend that returned the name where the id belongs --
#: the exact confusion #1540 exists to remove -- would pass a check that let the two be equal.
_REQUESTER = "contract-requester-name"
_REQUESTER_ID = "contract-requester-id-0001"


async def _assert_pending_approval_contract(store: Any) -> None:
    """The behaviour every backend owes the requester-id column.

    Round-trips a request through ``create_pending_approval`` -> ``get_pending_approval`` and pins
    that the id survives, is surfaced under its own key, and is not conflated with the display name.
    """
    approval_id = "contractapproval0000000000000001"
    await store.create_pending_approval(
        approval_id=approval_id,
        operation="dead_letter_replay",
        params="{}",
        requester=_REQUESTER,
        requester_user_id=_REQUESTER_ID,
        requested_at=1_000.0,
        expires_at=None,
    )
    try:
        row = await store.get_pending_approval(approval_id)
        assert row is not None

        # The authorization key survived the write and the read. `is not None` alone would pass on a
        # backend that wrote the NAME into this column, so compare the value.
        assert str(row["requester_user_id"]) == _REQUESTER_ID
        # ...and the display label is still its own column, unchanged.
        assert str(row["requester"]) == _REQUESTER
        # The two must not be the same value; keying on an id that is really a name fixes nothing.
        assert str(row["requester_user_id"]) != str(row["requester"])

        # The pending queue projects the display label only -- the id is read on the approve path via
        # get_pending_approval. Pinned so a backend adding it to this projection is a deliberate act.
        listed = await store.list_pending_approvals(now=1_001.0)
        mine = [r for r in listed if str(r["id"]) == approval_id]
        assert len(mine) == 1
        assert str(mine[0]["requester"]) == _REQUESTER
    finally:
        # Leave the table as it was found; the server legs share one database across tests.
        await store.decide_pending_approval(
            approval_id, status="rejected", approver="contract-cleanup", decided_at=1_002.0
        )
