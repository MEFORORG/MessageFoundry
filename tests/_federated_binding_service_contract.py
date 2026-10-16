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
        # Each carries its immutable directory id: a row without one cannot take a binding
        # (BACKLOG #1143 slice C).
        await store.create_user(
            user_id=uid,
            username=uid,
            auth_provider="ad",
            directory_object_id=f"guid-{uid}",
            now=1_000.0,
            password_generated=False,
        )
    await store.create_session(
        token_hash="t-bind-a", user_id="bind-a", expires_at=_EXPIRES, now=1_000.0
    )

    # 1. A first bind writes the pair and ends the account's sessions (vault BACKLOG #2609): the
    #    account moves behind its identity provider, so nothing minted before outlives the bind.
    first = await service.bind_federated_subject(
        "bind-a", FIRST_SUB, expected_issuer=None, expected_subject=None, actor="admin"
    )
    assert (first.previous_issuer, first.previous_subject, first.sessions_revoked) == (
        None,
        None,
        1,
    )
    holder = await store.get_user_by_federated_subject(ISSUER, FIRST_SUB)
    assert holder is not None and holder.id == "bind-a"
    ended = await store.get_session("t-bind-a")
    assert ended is not None and ended.revoked_at is not None
    [bound] = await _audit(store, "auth.federated_subject_bound")
    assert bound["actor"] == "admin"
    assert json.loads(bound["detail"])["sessions_revoked"] == 1

    # 2. A second account asking for a held pair is refused before any write.
    with pytest.raises(FederatedSubjectHeld):
        await service.bind_federated_subject(
            "bind-b", FIRST_SUB, expected_issuer=None, expected_subject=None, actor="admin"
        )

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
            service.bind_federated_subject(
                "bind-b", RACED_SUB, expected_issuer=None, expected_subject=None, actor="admin"
            ),
            service.bind_federated_subject(
                "bind-c", RACED_SUB, expected_issuer=None, expected_subject=None, actor="admin"
            ),
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
    #    the audit row names the pair that transaction cleared. The session is a new one, minted
    #    under the first binding, because the first bind ended the earlier one.
    await store.create_session(
        token_hash="t-bind-a2", user_id="bind-a", expires_at=_EXPIRES, now=1_000.0
    )
    rebound = await service.bind_federated_subject(
        "bind-a", REBOUND_SUB, expected_issuer=ISSUER, expected_subject=FIRST_SUB, actor="admin"
    )
    assert (rebound.previous_issuer, rebound.previous_subject) == (ISSUER, FIRST_SUB)
    assert rebound.sessions_revoked == 1
    gone = await store.get_session("t-bind-a2")
    assert gone is not None and gone.revoked_at is not None
    assert await store.get_user_by_federated_subject(ISSUER, FIRST_SUB) is None
    [row] = await _audit(store, "auth.federated_subject_rebound")
    assert row["actor"] == "admin"
    detail = json.loads(row["detail"])
    assert (detail["previous_subject"], detail["subject"]) == (FIRST_SUB, REBOUND_SUB)

    # 5. The same pair again is refused, so a no-op signs nobody out.
    with pytest.raises(ValueError, match="already holds that identity"):
        await service.bind_federated_subject(
            "bind-a",
            REBOUND_SUB,
            expected_issuer=ISSUER,
            expected_subject=REBOUND_SUB,
            actor="admin",
        )


#: The account the factor-state contract below binds, rebinds and unbinds, and its control.
FACTOR_USER = "bind-factors"
FACTORLESS_USER = "bind-factorless"
#: Holds TOTP and a passkey BEFORE its first bind, so the already-unbound arm of the clear is read.
PRE_ENROLLED_USER = "bind-pre-enrolled"


async def _factor_fields(store: Any, action: str, user_id: str) -> tuple[bool, bool]:
    rows = [json.loads(a["detail"]) for a in await _audit(store, action)]
    [detail] = [d for d in rows if d["user_id"] == user_id]
    return detail["totp_enrolled"], detail["webauthn_enrolled"]


async def _assert_bind_audit_names_factors_contract(store: Any) -> None:
    """The bind, rebind and unbind audit rows say whether the account holds an engine factor.

    Vault BACKLOG #2711 step 3: the row an operator reads after a binding change says whether the
    account holds engine factors. Read in the clear's own transaction on every backend.
    ``FACTORLESS_USER`` is the control: a row that always said ``True`` would fail there.
    """
    from tests._webauthn_store_contract import _cred

    service = AuthService(store, AuthSettings(require_mfa=False, oidc_issuer=ISSUER))
    for uid in (FACTOR_USER, FACTORLESS_USER, PRE_ENROLLED_USER):
        await store.create_user(
            user_id=uid,
            username=uid,
            auth_provider="ad",
            directory_object_id=f"guid-{uid}",
            now=1_000.0,
            password_generated=False,
        )

    # 1. A first bind of an account with no factor says so, on both fields.
    for uid in (FACTOR_USER, FACTORLESS_USER):
        await service.bind_federated_subject(
            uid, f"S-1-{uid}", expected_issuer=None, expected_subject=None, actor="admin"
        )
        assert await _factor_fields(store, "auth.federated_subject_bound", uid) == (False, False)

    # 1b. A first bind of an account that already holds both factors reads them in the clear's
    #     already-unbound arm. Without this, dropping the fields from that arm would still pass 1.
    await store.set_totp_secret(PRE_ENROLLED_USER, secret="JBSWY3DPEHPK3PXP")
    assert await store.enable_totp(PRE_ENROLLED_USER, recovery_code_hashes=["h1"])
    await store.add_webauthn_credential(_cred(PRE_ENROLLED_USER, "pre", id_hash="pre-passkey-hash"))
    await service.bind_federated_subject(
        PRE_ENROLLED_USER,
        f"S-1-{PRE_ENROLLED_USER}",
        expected_issuer=None,
        expected_subject=None,
        actor="admin",
    )
    assert await _factor_fields(store, "auth.federated_subject_bound", PRE_ENROLLED_USER) == (
        True,
        True,
    )

    # 2. The account enrols both factors; the rebind row reads them.
    await store.set_totp_secret(FACTOR_USER, secret="JBSWY3DPEHPK3PXP")
    assert await store.enable_totp(FACTOR_USER, recovery_code_hashes=["h1"])
    await store.add_webauthn_credential(_cred(FACTOR_USER, "mine", id_hash="factor-passkey-hash"))
    await service.bind_federated_subject(
        FACTOR_USER,
        "S-1-factors-rebound",
        expected_issuer=ISSUER,
        expected_subject=f"S-1-{FACTOR_USER}",
        actor="admin",
    )
    assert await _factor_fields(store, "auth.federated_subject_rebound", FACTOR_USER) == (
        True,
        True,
    )

    # 3. TOTP removed, passkey kept: the two fields are read apart, so the unbind row tells them apart.
    await store.disable_totp(FACTOR_USER)
    await service.unbind_federated_subject(
        FACTOR_USER, expected_issuer=ISSUER, expected_subject="S-1-factors-rebound", actor="admin"
    )
    await service.unbind_federated_subject(
        FACTORLESS_USER,
        expected_issuer=ISSUER,
        expected_subject=f"S-1-{FACTORLESS_USER}",
        actor="admin",
    )
    assert await _factor_fields(store, "auth.federated_subject_unbound", FACTOR_USER) == (
        False,
        True,
    )
    assert await _factor_fields(store, "auth.federated_subject_unbound", FACTORLESS_USER) == (
        False,
        False,
    )
