# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Cross-backend store contract: an account write commits its audit row, or neither lands.

BACKLOG #2221 and #3018 step 4. ``set_user_roles`` and ``remove_unless_last_admin`` take
``audits``, and ``revoke_user_sessions`` takes an ``audit`` built from its result. Each appends in
the write's own transaction, so a landed write leaves exactly one row and a failed append leaves
neither the change nor the row. ``remove_unless_last_admin`` appends only when it applies the
change, so its refusal leaves no row either.

``tests/test_account_write_audit.py`` runs this against SQLite; ``tests/test_postgres_store.py`` and
``tests/test_sqlserver_store.py`` run it against the server backends, which only the live-server CI
legs do. The failed append is the store's own ``_append_audits`` raising, the one append every one
of these writes goes through. Synthetic accounts only.
"""

from __future__ import annotations

import json
import time
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

import pytest

from messagefoundry.auth.tokens import hash_token, mint_token
from messagefoundry.store.store import AdminRemoval, AuditAppend, RevokeResult, no_audit_row
from tests._last_admin_store_contract import ADMIN, VIEWER, seed

_ACTION = "contract.account_write"


def _row(detail: str) -> AuditAppend:
    return AuditAppend(_ACTION, actor="contract-admin", detail=detail)


async def _rows(store: Any) -> list[str]:
    """The details of this contract's rows, oldest first."""
    rows = await store.list_audit(action=_ACTION, limit=100)
    return sorted(str(r["detail"]) for r in rows)


@contextmanager
def _refused_append(store: Any) -> Iterator[RuntimeError]:
    """Make every append of the write's rows raise, as a refusing audit chain would."""
    refusal = RuntimeError("synthetic: the audit chain refused the row")

    async def refuse(*_a: object, **_kw: object) -> list[object]:
        raise refusal

    store._append_audits = refuse
    try:
        yield refusal
    finally:
        del store._append_audits


async def sign_in(store: Any, user_id: str) -> None:
    await store.create_session(
        token_hash=hash_token(mint_token()),
        user_id=user_id,
        expires_at=time.time() + 3600,
        auth_mechanism="password",
    )


async def assert_account_write_audit_contract(store: Any) -> None:
    """Drive each audited account write through a landed write and a failed append."""
    await seed(store, ("a", "b"), ("c", "d", "e"))

    # --- set_user_roles ------------------------------------------------------------------------
    await store.set_user_roles("c", [ADMIN], audits=(_row("roles c"),))
    assert await store.get_user_role_ids("c") == [ADMIN]
    assert await _rows(store) == ["roles c"], "a landed role write did not leave exactly one row"
    with _refused_append(store) as refusal, pytest.raises(RuntimeError) as raised:
        await store.set_user_roles("c", [VIEWER], audits=(_row("roles lost"),))
    assert raised.value is refusal
    assert await store.get_user_role_ids("c") == [ADMIN], "the roles outlived their failed row"
    assert await _rows(store) == ["roles c"]

    # --- remove_unless_last_admin, applied --------------------------------------------------
    guard = store.remove_unless_last_admin
    assert await guard(
        "c", AdminRemoval.SET_ROLES, admin_role_id=ADMIN, role_ids=[VIEWER], audits=(_row("set"),)
    )
    assert await guard("d", AdminRemoval.DISABLE, admin_role_id=ADMIN, audits=(_row("disable"),))
    assert await guard("e", AdminRemoval.DELETE, admin_role_id=ADMIN, audits=(_row("delete"),))
    assert await store.get_user_role_ids("c") == [VIEWER]
    d = await store.get_user("d")
    assert d is not None and d.disabled
    assert await store.get_user("e") is None
    assert await _rows(store) == ["delete", "disable", "roles c", "set"]

    # --- remove_unless_last_admin, refused by the guard: no change and no row -----------------
    assert await guard("b", AdminRemoval.DISABLE, admin_role_id=ADMIN, audits=()) is True
    for change in (AdminRemoval.DISABLE, AdminRemoval.DELETE):
        assert not await guard("a", change, admin_role_id=ADMIN, audits=(_row("refused"),))
    assert not await guard(
        "a",
        AdminRemoval.SET_ROLES,
        admin_role_id=ADMIN,
        role_ids=[VIEWER],
        audits=(_row("refused"),),
    )
    assert await _rows(store) == ["delete", "disable", "roles c", "set"], "a refusal was audited"

    # --- remove_unless_last_admin, a failed append rolls the change back ---------------------
    await store.set_user_disabled("b", disabled=False)
    for change, role_ids in (
        (AdminRemoval.DISABLE, ()),
        (AdminRemoval.DELETE, ()),
        (AdminRemoval.SET_ROLES, (VIEWER,)),
    ):
        with _refused_append(store) as refusal, pytest.raises(RuntimeError) as raised:
            await guard("b", change, admin_role_id=ADMIN, role_ids=role_ids, audits=(_row("lost"),))
        assert raised.value is refusal, change
        b = await store.get_user("b")
        assert b is not None and not b.disabled, f"{change} outlived its failed row"
        assert await store.get_user_role_ids("b") == [ADMIN], f"{change} outlived its failed row"
    assert await _rows(store) == ["delete", "disable", "roles c", "set"]

    # --- revoke_user_sessions: the row is built from the count, in the revoke's transaction --
    await sign_in(store, "c")
    await sign_in(store, "c")

    def counted(result: RevokeResult) -> AuditAppend:
        return _row(json.dumps({"revoked": result.count}))

    with _refused_append(store) as refusal, pytest.raises(RuntimeError) as raised:
        await store.revoke_user_sessions("c", audit=counted)
    assert raised.value is refusal
    assert len(await store.list_sessions("c")) == 2, "the revoke outlived its failed row"
    assert await store.revoke_user_sessions("c", audit=counted) == RevokeResult(2)
    assert await store.list_sessions("c") == []
    assert json.dumps({"revoked": 2}) in await _rows(store)
    before = await _rows(store)
    await sign_in(store, "c")
    assert (await store.revoke_user_sessions("c", audit=no_audit_row)).count == 1
    assert await _rows(store) == before, "a revoke whose audit returned None wrote a row"
