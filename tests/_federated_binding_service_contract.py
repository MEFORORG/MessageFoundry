# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Cross-backend contract for the admin federated bind (BACKLOG #1143 / #295, ADR 0184).

``AuthService.bind_federated_subject`` is the only path that creates a federated binding. It is
service code, but three of the things it relies on differ per backend, and none of them is visible
on SQLite alone:

- the integrity error a backend raises when ``ux_users_federated_subject`` refuses a second holder,
  which the bind maps to ``FederatedSubjectHeld`` by MRO NAME (``sqlite3.IntegrityError``, asyncpg's
  ``UniqueViolationError``, pyodbc's ``IntegrityError``). A name the mapping misses surfaces as a 500;
- the unbind transaction a rebind runs first, which must revoke the old identity's sessions;
- the audit writes, whose rows must name the administrator.

One shared body, run by the SQLite, PostgreSQL and SQL Server suites against the REAL store object.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any

import pytest

from messagefoundry.auth.service import AuthService, FederatedSubjectHeld
from messagefoundry.config.settings import AuthSettings

ISSUER = "https://idp.example/binding"
FIRST_SUB = "S-1-bind-first"
RACED_SUB = "S-1-bind-raced"
REBOUND_SUB = "S-1-bind-rebound"
_EXPIRES = 9_999_999_999.0


async def _audit(store: Any, action: str) -> list[Any]:
    return [a for a in await store.list_audit() if a["action"] == action]


async def _assert_federated_binding_service_contract(store: Any) -> None:
    service = AuthService(store, AuthSettings(require_mfa=False, oidc_issuer=ISSUER))
    for uid in ("bind-a", "bind-b", "bind-c"):
        await store.create_user(user_id=uid, username=uid, auth_provider="ad", now=1_000.0)
    await store.create_session(
        token_hash="t-bind-a", user_id="bind-a", expires_at=_EXPIRES, now=1_000.0
    )

    # 1. A first bind writes the pair and revokes nothing: it adds a way in.
    first = await service.bind_federated_subject("bind-a", FIRST_SUB, actor="admin")
    assert (first.previous_issuer, first.previous_subject, first.sessions_revoked) == (
        None,
        None,
        0,
    )
    holder = await store.get_user_by_federated_subject(ISSUER, FIRST_SUB)
    assert holder is not None and holder.id == "bind-a"
    live = await store.get_session("t-bind-a")
    assert live is not None and live.revoked_at is None
    [bound] = await _audit(store, "auth.federated_subject_bound")
    assert bound["actor"] == "admin"

    # 2. A second account asking for a held pair is refused before any write.
    with pytest.raises(FederatedSubjectHeld):
        await service.bind_federated_subject("bind-b", FIRST_SUB, actor="admin")

    # 3. THE RACE, and the part only a live server shows: both binds read "no holder", both write,
    #    and this backend's own integrity class must come back as FederatedSubjectHeld, not a 500.
    barrier = asyncio.Barrier(2)
    observed: list[bool] = []
    real_read = store.get_user_by_federated_subject

    async def read_then_wait(*args: Any, **kwargs: Any) -> Any:
        found = await real_read(*args, **kwargs)
        observed.append(found is None)
        await asyncio.wait_for(barrier.wait(), timeout=10)
        return found

    store.get_user_by_federated_subject = read_then_wait
    try:
        outcomes = await asyncio.gather(
            service.bind_federated_subject("bind-b", RACED_SUB, actor="admin"),
            service.bind_federated_subject("bind-c", RACED_SUB, actor="admin"),
            return_exceptions=True,
        )
    finally:
        del store.get_user_by_federated_subject
    assert observed == [True, True], (
        f"the binds serialised, so the index was not reached: {observed}"
    )
    lost = [o for o in outcomes if isinstance(o, BaseException)]
    assert len(lost) == 1 and isinstance(lost[0], FederatedSubjectHeld), outcomes
    winners = [u for u in await store.list_users() if u.oidc_subject == RACED_SUB]
    assert len(winners) == 1

    # 4. A rebind clears first, in the unbind's own transaction: the old identity's session ends and
    #    the audit row names the pair that transaction cleared.
    rebound = await service.bind_federated_subject("bind-a", REBOUND_SUB, actor="admin")
    assert (rebound.previous_issuer, rebound.previous_subject) == (ISSUER, FIRST_SUB)
    assert rebound.sessions_revoked == 1
    gone = await store.get_session("t-bind-a")
    assert gone is not None and gone.revoked_at is not None
    assert await store.get_user_by_federated_subject(ISSUER, FIRST_SUB) is None
    [row] = await _audit(store, "auth.federated_subject_rebound")
    assert row["actor"] == "admin"
    detail = json.loads(row["detail"])
    assert (detail["previous_subject"], detail["subject"]) == (FIRST_SUB, REBOUND_SUB)

    # 5. The same pair again is refused, so a no-op signs nobody out.
    with pytest.raises(ValueError, match="already bound to that identity"):
        await service.bind_federated_subject("bind-a", REBOUND_SUB, actor="admin")
