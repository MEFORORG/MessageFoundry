# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""What :meth:`AuthService._issue_session` does with the store's answer (BACKLOG #5624).

Two limbs. A sign-in that owes no second factor used to stamp ``mfa_verified_at`` with a SECOND
store write after the insert. That write did nothing on a row revoked in between and ended the row
when its seal was refused, and the method went on to supersede the caller's prior session and hand
back a dead token as a success. The stamp is now part of the insert, so there is no second write.

And the store's one ``False`` from ``create_session`` was always read as a binding change, so a
directory sign-in whose account was deleted under it was audited as ``federated_sign_in_required``.
It is now told apart and audited as ``account_deleted``.
"""

from __future__ import annotations

import copy
import json
import uuid
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any, NoReturn

import pytest

from messagefoundry.auth import service as service_module
from messagefoundry.auth.identity import SessionMechanism
from messagefoundry.auth.ldap import AdPrincipal
from messagefoundry.auth.service import ACCOUNT_DELETED, FEDERATED_SIGN_IN_REQUIRED, AuthService
from messagefoundry.auth.tokens import hash_token
from messagefoundry.config.settings import AuthSettings, EgressSettings
from messagefoundry.pipeline import Engine
from messagefoundry.store.row_seal import RowSealError
from messagefoundry.store.store import MessageStore
from tests._admin_account import create_admin


def _no_second_stamp(monkeypatch: pytest.MonkeyPatch, store: Any) -> list[str]:
    """Record every ``mark_session_mfa_verified`` call; the mint must make none."""
    calls: list[str] = []
    real = store.mark_session_mfa_verified

    async def spy(token_hash: str, **kwargs: Any) -> bool:
        calls.append(token_hash)
        answer: bool = await real(token_hash, **kwargs)
        return answer

    monkeypatch.setattr(store, "mark_session_mfa_verified", spy)
    return calls


async def test_a_sign_in_owing_no_factor_is_stamped_in_its_insert(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """RED when: the mint stamps the factor with a second write instead of in its INSERT."""
    store = await MessageStore.open(":memory:")
    try:
        service = AuthService(store, AuthSettings(require_mfa=False))
        admin = await create_admin(service)
        calls = _no_second_stamp(monkeypatch, store)

        outcome = await service.login(admin.username, admin.password)

        assert outcome.ok and outcome.token is not None and not outcome.mfa_required
        assert calls == [], "the mint stamped the factor in a second transaction"
        row = await store.get_session(hash_token(outcome.token))
        assert row is not None and row.revoked_at is None
        assert row.mfa_verified_at == row.created_at
        assert await service.mfa_satisfied(outcome.token)
    finally:
        await store.close()


async def test_a_refused_stamp_seal_cannot_end_the_new_session_under_a_success(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """RED when: the mint stamps through ``mark_session_mfa_verified``. The old second write read
    the row back, and a seal it refused ended the session; the mint then superseded the caller's
    prior session and returned the dead token as a success. Here every such stamp is refused, so
    a mint that still made one would return a revoked session."""
    store = await MessageStore.open(":memory:")
    try:
        service = AuthService(store, AuthSettings(require_mfa=False))
        admin = await create_admin(service)
        first = await service.login(admin.username, admin.password)
        assert first.ok and first.token is not None

        async def refused(_token_hash: str, **_kwargs: Any) -> NoReturn:
            raise RowSealError("seal refused")

        monkeypatch.setattr(store, "mark_session_mfa_verified", refused)

        outcome = await service.login(admin.username, admin.password, supersedes=first.token)

        assert outcome.ok and outcome.token is not None
        row = await store.get_session(hash_token(outcome.token))
        assert row is not None and row.revoked_at is None, "a success returned a dead token"
        assert row.mfa_verified_at is not None
        prior = await store.get_session(hash_token(first.token))
        assert prior is not None and prior.revoked_at is not None
    finally:
        await store.close()


async def test_issue_session_names_a_deleted_account_and_a_binding_change_apart() -> None:
    """RED when: every ``False`` from ``create_session`` reads as a binding change."""
    store = await MessageStore.open(":memory:")
    try:
        service = AuthService(store, AuthSettings())
        admin = await create_admin(service)
        user = await store.get_user_by_username(admin.username)
        assert user is not None

        # A present row whose pair does not match the guard: a binding change.
        with pytest.raises(service_module._BindingChangedMidLogin) as changed:
            await service._issue_session(
                user.id,
                None,
                mfa_verified=False,
                seed_reauth=False,
                mechanism=SessionMechanism.PASSWORD,
                idp_auth_time=None,
                require_federated_subject=("https://idp.test", "someone"),
            )
        assert changed.value.account_deleted is False

        await store.delete_user(user.id)
        with pytest.raises(service_module._BindingChangedMidLogin) as gone:
            await service._issue_session(
                user.id,
                None,
                mfa_verified=False,
                seed_reauth=False,
                mechanism=SessionMechanism.PASSWORD,
                idp_auth_time=None,
            )
        assert gone.value.account_deleted is True
        assert copy.copy(gone.value).account_deleted is True  # rebuilt from its args
    finally:
        await store.close()


# --- the Kerberos leg, end to end ----------------------------------------------------------------


@pytest.fixture
async def engine(tmp_path: Path) -> AsyncIterator[Engine]:
    eng = await Engine.create(
        tmp_path / "issue_session_5624.db",
        poll_interval=0.02,
        egress_settings=EgressSettings(deny_by_default=False),
    )
    yield eng
    await eng.stop()


class _FakeLdap:
    def resolve_principal(self, username: str, **_: object) -> AdPrincipal | None:
        return AdPrincipal(
            username=username,
            display_name="J Doe",
            email=None,
            dn=f"CN={username},DC=x",
            groups=frozenset(),
            directory_object_id=str(uuid.uuid5(uuid.NAMESPACE_URL, username)),
        )


async def _kerberos_service(engine: Engine, monkeypatch: pytest.MonkeyPatch) -> AuthService:
    monkeypatch.setattr("messagefoundry.auth.service.kerberos_principal", lambda _t, _s: "jdoe")
    settings = AuthSettings(
        ad_enabled=True,
        kerberos_enabled=True,
        kerberos_realm="EXAMPLE.COM",
        ad_server="ldaps://x",
        ad_user_search_base="DC=x",
        ad_bind_dn="CN=svc,DC=x",
        ad_bind_password="x",
        login_rate_limit_enabled=False,
        require_mfa=False,
    )
    service = AuthService(engine.store, settings, ldap=_FakeLdap())  # type: ignore[arg-type]
    await service.initialize()
    return service


def _race_the_insert(monkeypatch: pytest.MonkeyPatch, store: Any, landing: str) -> list[bool]:
    """Run ``landing`` (a delete or a bind of the account) inside ``create_session``, before its
    read: the race's losing order."""
    real = store.create_session
    issued: list[bool] = []

    async def racing(**kwargs: Any) -> bool:
        if landing == "delete":
            await store.delete_user(kwargs["user_id"])
        else:
            await store.set_user_federated_subject(kwargs["user_id"], "https://idp.test", "sub-1")
        result = await real(**kwargs)
        issued.append(result)
        return result

    monkeypatch.setattr(store, "create_session", racing)
    return issued


async def _refusal_reasons(store: Any) -> list[str]:
    rows = await store.list_audit(action="auth.login_failed")
    return [json.loads(r["detail"])["reason"] for r in rows]


@pytest.mark.parametrize(
    ("landing", "reason"),
    [("delete", ACCOUNT_DELETED), ("bind", FEDERATED_SIGN_IN_REQUIRED)],
)
async def test_a_kerberos_sign_in_refused_at_the_insert_names_its_cause(
    engine: Engine, monkeypatch: pytest.MonkeyPatch, landing: str, reason: str
) -> None:
    """RED when: an account deleted under a Windows SSO sign-in is audited as a binding change.
    The ``bind`` case is the control: a binding landing in the same window keeps its reason."""
    service = await _kerberos_service(engine, monkeypatch)
    issued = _race_the_insert(monkeypatch, engine.store, landing)

    outcome = await service.authenticate_kerberos(b"tok")

    assert issued == [False]
    assert not outcome.ok and outcome.token is None
    assert await _refusal_reasons(engine.store) == [reason]
    assert await engine.store.list_audit(action="auth.login_success") == []


async def test_a_contended_password_insert_is_not_an_unknown_account(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """BACKLOG #5653: a password sign-in whose insert found the session epoch raised on every
    attempt fails as a temporary failure under its own audit reason. RED on the head where the
    store returned ``False``, so the sign-in answered ``invalid credentials`` and wrote the
    unknown-account row for an account that exists and a password that was right."""
    from messagefoundry.auth.service import SESSION_MINT_CONTENDED
    from messagefoundry.store import SessionMintContended
    from messagefoundry.store import store as store_module
    from messagefoundry.store.store import SESSION_MINT_EPOCH_RAISED, no_audit_row

    store = await MessageStore.open(":memory:")
    try:
        service = AuthService(
            store, AuthSettings(require_mfa=False, login_rate_limit_enabled=False)
        )
        admin = await create_admin(service)
        user = await store.get_user_by_username(admin.username)
        assert user is not None
        real_seal = store_module.seal_session_async

        async def seal_then_revoke(sealer: Any, record: Any) -> Any:
            sealed = await real_seal(sealer, record)
            await store.revoke_user_sessions(user.id, audit=no_audit_row)
            return sealed

        monkeypatch.setattr(store_module, "seal_session_async", seal_then_revoke)
        with pytest.raises(SessionMintContended):
            await service._issue_session(
                user.id,
                None,
                mfa_verified=True,
                seed_reauth=False,
                mechanism=SessionMechanism.PASSWORD,
                idp_auth_time=None,
            )

        outcome = await service.login(admin.username, admin.password)

        assert not outcome.ok and outcome.token is None
        assert outcome.error != "invalid credentials"
        assert outcome.reason == SESSION_MINT_CONTENDED
        rows = [
            json.loads(r["detail"] or "{}")
            for r in await store.list_audit(action="auth.login_failed")
        ]
        stand_in = {"provider": "local", "reason": "bad_credentials"}
        true_row = {
            "provider": "local",
            "reason": SESSION_MINT_CONTENDED,
            "contention": SESSION_MINT_EPOCH_RAISED,
        }
        assert len(rows) == 2 and stand_in in rows and true_row in rows, rows
        # Only a right password reaches the insert, so a reader without users:manage reads only
        # the stand-in a wrong password writes, as the real writer stored it (#1131 pattern).
        from messagefoundry.auth.audit_visibility import HIDDEN_FROM_READERS_WITHOUT_USERS_MANAGE

        hidden = HIDDEN_FROM_READERS_WITHOUT_USERS_MANAGE
        shown = await store.list_audit(action="auth.login_failed", exclude=hidden)
        assert [json.loads(r["detail"] or "{}") for r in shown] == [stand_in]
        assert await store.list_sessions(user.id) == []
        again = await store.get_user(user.id)
        assert again is not None and again.failed_attempts == 0
    finally:
        await store.close()
