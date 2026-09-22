# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #1474: ``AuthService.unbind_federated_subject`` -- removing a federated binding.

Before this there was no way to spell "this account has no federated binding":
``set_user_federated_subject`` takes ``str`` for both halves. The unbind NULLs the pair, leaves
``auth_provider='ad'``, revokes the account's live sessions in the same transaction, and audits
the prior pair with the revoked count so the revocation is visible rather than inferred.

Two of the tests below are about what the transaction BOUNDARY buys, which is the part an unbind
that merely "works" gets wrong: the audited pair is read inside the same transaction that clears
it, and a federated login already in flight cannot mint a session after the revocation has run.

The bindings here are made by a REAL federated login through the shared OIDC helpers, so the state
being unbound is the state the login path writes, not a hand-built row that might differ from it.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from messagefoundry.auth.tokens import hash_token
from messagefoundry.store.store import MessageStore
from tests.test_auth_oidc_service import _oidc_login, _service


@pytest.fixture(scope="module")
def rsa_key() -> rsa.RSAPrivateKey:
    """Local rather than imported: a fixture resolves by name in the module that requests it, so
    importing the sibling suite's function would not register it here."""
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


async def _unbound_rows(store: MessageStore) -> list[Mapping[str, Any]]:
    return [a for a in await store.list_audit() if a["action"] == "auth.federated_subject_unbound"]


async def test_unbind_clears_the_pair_revokes_sessions_and_audits_the_count(
    rsa_key: rsa.RSAPrivateKey, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = await MessageStore.open(":memory:")
    try:
        service = await _service(store, rsa_key)
        login = await _oidc_login(service, monkeypatch, rsa_key, sub="S-1-alice")
        assert login.ok and login.token is not None
        account = await store.get_user_by_username("jdoe")
        assert account is not None and account.oidc_subject == "S-1-alice"
        issuer = account.oidc_issuer
        assert issuer is not None

        revoked = await service.unbind_federated_subject(account.id, actor="admin")

        assert revoked == 1, "the federated login's own session should have been revoked"
        session = await store.get_session(hash_token(login.token))
        assert session is not None and session.revoked_at is not None
        after = await store.get_user(account.id)
        assert after is not None
        assert after.oidc_issuer is None and after.oidc_subject is None
        assert after.auth_provider == "ad", "an unbound account is still a directory account"

        rows = await _unbound_rows(store)
        assert len(rows) == 1
        assert rows[0]["actor"] == "admin", "the audit row must name who unbound, not whose"
        detail = json.loads(rows[0]["detail"])
        assert detail == {
            "user_id": account.id,
            "username": "jdoe",
            "issuer": issuer,
            "subject": "S-1-alice",
            "sessions_revoked": 1,
        }
    finally:
        await store.close()


async def test_after_an_unbind_a_new_subject_binds_instead_of_conflicting(
    rsa_key: rsa.RSAPrivateKey, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The point of an unbind: the account can take a different subject afterwards.

    The CONTROL runs first. Before the unbind the new subject is refused as
    ``federated_subject_conflict``; without that, a pass below could mean the guard was never armed.
    """
    store = await MessageStore.open(":memory:")
    try:
        service = await _service(store, rsa_key)
        assert (await _oidc_login(service, monkeypatch, rsa_key, sub="S-1-alice")).ok

        refused = await _oidc_login(service, monkeypatch, rsa_key, sub="S-1-bob")
        assert not refused.ok and refused.reason == "federated_subject_conflict"

        account = await store.get_user_by_username("jdoe")
        assert account is not None
        await service.unbind_federated_subject(account.id, actor="admin")

        rebound = await _oidc_login(service, monkeypatch, rsa_key, sub="S-1-bob")
        assert rebound.ok, rebound.reason
        after = await store.get_user_by_username("jdoe")
        assert after is not None
        assert after.id == account.id, "the same account took the new subject"
        assert after.oidc_subject == "S-1-bob"
    finally:
        await store.close()


async def test_unbind_of_an_unbound_account_is_refused_and_revokes_nothing(
    rsa_key: rsa.RSAPrivateKey,
) -> None:
    """An unbind of nothing must not sign anybody out, so it raises before the store is touched."""
    store = await MessageStore.open(":memory:")
    try:
        service = await _service(store, rsa_key)
        await store.create_user(user_id="u-ad", username="plain", auth_provider="ad", now=1.0)
        await store.create_session(token_hash="t-plain", user_id="u-ad", expires_at=9e9, now=1.0)

        with pytest.raises(ValueError, match="no federated binding"):
            await service.unbind_federated_subject("u-ad", actor="admin")

        session = await store.get_session("t-plain")
        assert session is not None and session.revoked_at is None
        assert await _unbound_rows(store) == []
    finally:
        await store.close()


async def test_unbind_of_an_unknown_user_is_refused(rsa_key: rsa.RSAPrivateKey) -> None:
    store = await MessageStore.open(":memory:")
    try:
        service = await _service(store, rsa_key)
        with pytest.raises(ValueError, match="no such user"):
            await service.unbind_federated_subject("nobody", actor="admin")
        assert await _unbound_rows(store) == []
    finally:
        await store.close()


async def test_the_audit_row_names_the_pair_the_unbind_itself_cleared(
    rsa_key: rsa.RSAPrivateKey, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The audited pair comes out of the unbind's own transaction, not a read taken before it.

    A rebind is wedged in at the moment the service would previously have read the account -- so a
    ``get_user`` above the store call would see ``S-1-alice``, while the transaction that runs
    afterwards clears ``S-1-carol``. The row has to name what was cleared; naming the pair that was
    there a moment earlier is a false record of whose access was withdrawn.

    The wedge sits on ``get_user`` precisely BECAUSE the fixed code never calls it here: the test
    fails loudly if that read comes back, and passes only while the reported pair is the
    transaction's own.
    """
    store = await MessageStore.open(":memory:")
    try:
        service = await _service(store, rsa_key)
        assert (await _oidc_login(service, monkeypatch, rsa_key, sub="S-1-alice")).ok
        account = await store.get_user_by_username("jdoe")
        assert account is not None and account.oidc_subject == "S-1-alice"
        issuer = account.oidc_issuer
        assert issuer is not None

        # The state the unbind will actually meet: a different subject, bound after the read a
        # careless implementation would have taken.
        await store.clear_user_federated_subject(account.id, now=10.0)
        await store.set_user_federated_subject(account.id, issuer, "S-1-carol", now=11.0)

        async def unexpected_get_user(user_id: str) -> Any:
            raise AssertionError(
                "unbind_federated_subject read the account outside its transaction; the pair it"
                " audits can then be one a concurrent rebind has already replaced"
            )

        monkeypatch.setattr(store, "get_user", unexpected_get_user)
        await service.unbind_federated_subject(account.id, actor="admin")
        monkeypatch.undo()

        [row] = await _unbound_rows(store)
        detail = json.loads(row["detail"])
        assert detail["subject"] == "S-1-carol", "the audit row named a pair this unbind never saw"
        assert detail["issuer"] == issuer and detail["username"] == "jdoe"
    finally:
        await store.close()


async def test_an_unbind_racing_an_in_flight_login_refuses_the_session(
    rsa_key: rsa.RSAPrivateKey, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A login already past its checks must not mint a session the unbind's revocation cannot see.

    The unbind is fired at the last possible instant -- once the login has resolved the account and
    is about to persist its session -- which is the window the revocation cannot cover, because it
    revokes what is LIVE when it runs and this session is not live yet. The login has to come back
    refused, audited, with no session row of any kind for the account.

    The CONTROL is the first login in the body: the same helper, the same subject, unwedged, and it
    succeeds. Without it a refusal here could equally mean federated login is broken outright.
    """
    store = await MessageStore.open(":memory:")
    try:
        service = await _service(store, rsa_key)
        control = await _oidc_login(service, monkeypatch, rsa_key, sub="S-1-alice")
        assert control.ok and control.token is not None
        account = await store.get_user_by_username("jdoe")
        assert account is not None

        real_create = store.create_session
        fired = False

        async def unbinding_create_session(**kw: Any) -> bool:
            nonlocal fired
            if not fired:
                fired = True
                await service.unbind_federated_subject(account.id, actor="admin")
            return await real_create(**kw)

        monkeypatch.setattr(store, "create_session", unbinding_create_session)
        raced = await _oidc_login(service, monkeypatch, rsa_key, sub="S-1-alice")
        monkeypatch.undo()

        assert fired, "the wedge never ran, so no unbind raced this login"
        assert not raced.ok and raced.token is None
        assert raced.reason == "federated_subject_unbound"
        assert await store.list_sessions(account.id) == [], (
            "the racing login left a live session the unbind's revocation never saw"
        )
        failures = [
            a
            for a in await store.list_audit()
            if a["action"] == "auth.login_failed"
            and '"reason": "federated_subject_unbound"' in (a["detail"] or "")
        ]
        assert len(failures) == 1
    finally:
        await store.close()
