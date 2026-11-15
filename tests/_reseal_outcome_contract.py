# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Cross-backend contract for ``reencrypt_to_active``'s side result, ``reseal_outcome`` (vault
BACKLOG #5635).

Extra-free, as ``tests/_role_seal_contract.py`` is, so the live Postgres and SQL Server suites
import it inside their test functions. The caller passes a store opened with a store key, and
``raw``: one SQL statement run outside the store's helpers, written with ``?`` placeholders.

A seal naming a key the run does not hold is planted on a user, a role, an open approval and a
directory map, so each re-seal pass leaves it as it is and the outcome must count it ``unheld``.
A malformed seal on another role is the control: the pass refuses it too, and it must count
``refused`` instead. The server legs share ``pending_approvals`` across tests, so the counts are
read as the change from a first run over the same rows.
"""

from __future__ import annotations

import time
from typing import Any
from uuid import uuid4

import pytest

from messagefoundry.auth.permissions import Role
from messagefoundry.store.crypto import CipherError
from messagefoundry.store.row_seal import SEAL_PREFIX, ResealOutcome
from messagefoundry.store.store import AD_ROLE_MAP
from tests._session_seal_contract import RawSql
from tests._user_seal_contract import _Harness

#: A well-formed seal that names a key no store here holds, as a row a retired key sealed reads
#: to a run that was not given that key. Its id has the form a real seal key id has.
UNHELD_KEY_ID = "ab" * 8  # built, not a literal: a secret scanner reads an id as a key
UNHELD_SEAL = f"{SEAL_PREFIX}{UNHELD_KEY_ID}:{'0' * 64}"
#: A seal no key could have written: no key id and MAC separator.
MALFORMED_SEAL = f"{SEAL_PREFIX}not-a-seal"

_GROUP = "cn=reseal-outcome,dc=example,dc=test"


async def _role(h: _Harness, name: str) -> str:
    created = await h.service.create_custom_role(
        display_name=name, description=None, permissions=["messages:replay"], actor="t"
    )
    return created.id


async def assert_reseal_outcome_contract(store: Any, raw: RawSql) -> None:
    """Drive ``reseal_outcome`` through a run that leaves nothing new and a run that leaves both
    kinds."""
    assert store.row_sealer() is not None, "the contract needs a store opened with a store key"
    h = _Harness(store, raw)
    await h.service.initialize()
    assert store.reseal_outcome() == ResealOutcome()  # before any run

    unheld_role = await _role(h, f"unheld-{uuid4().hex[:8]}")
    forged_role = await _role(h, f"forged-{uuid4().hex[:8]}")
    user = await h.account("unheld")
    approval = await store.create_pending_approval(
        approval_id=f"reseal-{uuid4().hex}",
        operation="messages.replay",
        params="{}",
        requester=user,
        requester_user_id=user,
        requested_at=time.time(),
        expires_at=None,
    )
    # A map an earlier test left may carry a seal of its own; this one is written by the store.
    await raw("DELETE FROM authority_set_seal WHERE name=?", (AD_ROLE_MAP,))
    await store.set_ad_group_role_map([(_GROUP, Role.VIEWER.value)])

    # Control: every row this contract wrote is under the active key, so a run adds nothing.
    await store.reencrypt_to_active()
    base = store.reseal_outcome()

    await raw("UPDATE roles SET seal=? WHERE id=?", (UNHELD_SEAL, unheld_role))
    await raw("UPDATE users SET authz_seal=? WHERE id=?", (UNHELD_SEAL, user))
    await raw("UPDATE pending_approvals SET seal=? WHERE id=?", (UNHELD_SEAL, approval))
    await raw("UPDATE authority_set_seal SET seal=? WHERE name=?", (UNHELD_SEAL, AD_ROLE_MAP))
    await raw("UPDATE roles SET seal=? WHERE id=?", (MALFORMED_SEAL, forged_role))

    # A seal under a key the run does not hold stops the pass before any cell, naming where.
    with pytest.raises(CipherError, match=UNHELD_KEY_ID):
        await store.reencrypt_to_active()
    after = store.reseal_outcome()
    assert (after.unheld - base.unheld, after.refused - base.refused) == (4, 1)
    assert {"users", "roles", "pending_approvals", "authority_set_seal"} <= set(after.unheld_tables)
    assert UNHELD_KEY_ID in after.unheld_key_ids

    # A decided request releases nothing, so its seal is not counted at all.
    await raw("UPDATE pending_approvals SET status=? WHERE id=?", ("rejected", approval))
    with pytest.raises(CipherError):
        await store.reencrypt_to_active()
    decided = store.reseal_outcome()
    assert (decided.unheld, decided.refused) == (after.unheld - 1, after.refused)
