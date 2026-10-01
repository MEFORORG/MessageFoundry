# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""vault BACKLOG #2609: an account bound to a federated identity signs in through its identity
provider, and Windows SSO refuses it.

An administrator binds an account to a federated subject to put that account behind the identity
provider's own sign-in. Windows SSO mints at the minimum, one factor and nothing asserted. So a
bound account that could still use Windows SSO would keep a sign-in that never meets the identity
provider at all. The refusal lives where every directory sign-in decides whether a row may sign in
(``_directory_login_refusal``), at both of its call sites.

The second half is the session that Windows SSO minted BEFORE the bind. A first bind revokes no
session, so that session outlives it. It may not bind the account's first engine factor.

**What is and is not exercised.** No SPNEGO exchange runs here. ``kerberos_principal`` is replaced,
as the other Windows SSO suites replace it, so each test starts where the acceptor hands over a
resolved name. The store is real (SQLite) and so is ``AuthService``. Synthetic data only.
"""

from __future__ import annotations

import base64
import json
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from messagefoundry.api import create_app
from messagefoundry.auth.identity import SessionMechanism
from messagefoundry.auth.ldap import AdPrincipal
from messagefoundry.auth.service import (
    FEDERATED_SIGN_IN_REQUIRED,
    STEP_UP_ACTION_MFA_CONFIRM,
    STEP_UP_ACTION_MFA_ENROLL,
    STEP_UP_ACTION_SESSION_TERMINATE,
    STEP_UP_ACTION_WEBAUTHN_ENROLL,
    AuthService,
)
from messagefoundry.auth.tokens import hash_token
from messagefoundry.pipeline import Engine, security_notify
from messagefoundry.store.store import MessageStore
from tests.test_auth_oidc_service import (
    DEFAULT_SUB,
    PRINCIPAL,
    _bind,
    _FakeLdap,
    _oid,
    _oidc_login,
    _service,
)

#: The three actions that bind a factor. ``session_terminate`` rides the same gate and is not one.
FACTOR_BINDING_ACTIONS = (
    STEP_UP_ACTION_MFA_ENROLL,
    STEP_UP_ACTION_MFA_CONFIRM,
    STEP_UP_ACTION_WEBAUTHN_ENROLL,
)

NEGOTIATE = {"Authorization": "Negotiate " + base64.b64encode(b"spnego-token").decode()}


@pytest.fixture(scope="module")
def rsa_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=3072)


@pytest.fixture(autouse=True)
def pads(monkeypatch: pytest.MonkeyPatch) -> list[float]:
    """Replace the failure pad's one sleep site and record each call, so no test here waits.

    A failed sign-in is held to a deadline in real time. The list says how many failures were
    padded, which is how a test reads the timing class without reading a clock."""
    calls: list[float] = []

    async def _record(deadline: float) -> None:
        calls.append(deadline)

    monkeypatch.setattr("messagefoundry.auth.service._sleep_until", _record)
    return calls


def _as(monkeypatch: pytest.MonkeyPatch, username: str) -> None:
    """The acceptor's answer: the name a verified ticket carries."""
    monkeypatch.setattr("messagefoundry.auth.service.kerberos_principal", lambda _t, _s: username)


def _principal(username: str, *, object_id: str | None = None) -> AdPrincipal:
    return AdPrincipal(
        username=username,
        display_name=username.title(),
        email=f"{username}@corp.example",
        dn=f"CN={username},DC=corp,DC=example",
        groups=PRINCIPAL.groups,
        directory_object_id=object_id or _oid(username),
    )


class _Directory(_FakeLdap):
    """Answers the step-up re-bind per account. The shared fake answers one fixed principal there,
    which fails the re-bind's own-object check for every account but that one."""

    def authenticate(self, username: str, password: str, **_: object) -> AdPrincipal | None:
        return self.resolve_principal(username)


async def _login_failures(store: MessageStore, actor: str) -> list[dict[str, Any]]:
    rows = await store.list_audit(action="auth.login_failed", actor=actor)
    return [json.loads(str(dict(r)["detail"])) for r in rows]


async def _sso_service(
    store: MessageStore, rsa_key: rsa.RSAPrivateKey, *, bind: str | None = None, **over: Any
) -> AuthService:
    """Windows SSO and federated sign-in both on. ``bind`` binds ``jdoe`` before any sign-in."""
    ldap = _Directory(
        by_username={"jdoe": PRINCIPAL, "asmith": _principal("asmith"), "ghost": None}
    )
    return await _service(store, rsa_key, ldap=ldap, bind=bind, kerberos_enabled=True, **over)


# --- the sign-in refusal -----------------------------------------------------------------------


async def test_a_bound_account_is_refused_windows_sso_and_still_signs_in_at_its_identity_provider(
    rsa_key: rsa.RSAPrivateKey, monkeypatch: pytest.MonkeyPatch, pads: list[float]
) -> None:
    """RED when: ``_directory_login_refusal`` stops reading the federated binding, or a caller stops
    telling it which pathway is asking.

    One account, walked through both states. Unbound, Windows SSO signs it in: that is the control,
    and it is why the refusal below cannot be a broken fixture. Bound, the same ticket is refused,
    nothing is minted, the refusal is audited with its reason and padded like any failure. The
    federated sign-in still works, so the account is moved and not locked out."""
    store = await MessageStore.open(":memory:")
    try:
        service = await _sso_service(store, rsa_key)
        _as(monkeypatch, "jdoe")

        unbound = await service.authenticate_kerberos(b"spnego-token")
        assert unbound.ok and unbound.identity is not None, unbound.error
        user_id = unbound.identity.user_id
        assert pads == [], "a successful sign-in was padded"

        await _bind(service, store, DEFAULT_SUB)

        refused = await service.authenticate_kerberos(b"spnego-token")
        assert not refused.ok, "a bound account signed in by Windows SSO"
        assert refused.token is None and refused.identity is None
        assert refused.reason == FEDERATED_SIGN_IN_REQUIRED
        # The generic string every ineligible mirror row gets: nothing in it names the cause.
        assert refused.error == "invalid credentials"
        assert len(pads) == 1, "the refusal was not held to the failure deadline"
        assert await _login_failures(store, "jdoe") == [
            {"provider": "ad", "reason": FEDERATED_SIGN_IN_REQUIRED}
        ]
        successes = await store.list_audit(action="auth.login_success", actor="jdoe")
        assert len(successes) == 1, "the refused sign-in wrote a success row"
        mechanisms = [s.auth_mechanism for s in await store.list_sessions(user_id)]
        assert mechanisms == [SessionMechanism.KERBEROS.value], "the refusal minted a session"

        federated = await _oidc_login(service, monkeypatch, rsa_key)
        assert federated.ok and federated.identity is not None, federated.error
        assert federated.identity.user_id == user_id
    finally:
        await store.close()


async def test_binding_one_account_leaves_windows_sso_open_to_the_others(
    rsa_key: rsa.RSAPrivateKey, monkeypatch: pytest.MonkeyPatch
) -> None:
    """RED when: the refusal keys on federation being configured instead of on the row's binding.

    ``jdoe`` is bound and ``asmith`` is not, on one service. The refusal follows the binding.
    ``asmith`` signs in twice, because the first sign-in creates the row and only the second one
    puts an existing row in front of the refusal."""
    store = await MessageStore.open(":memory:")
    try:
        service = await _sso_service(store, rsa_key, bind=DEFAULT_SUB)

        _as(monkeypatch, "jdoe")
        assert not (await service.authenticate_kerberos(b"spnego-token")).ok

        _as(monkeypatch, "asmith")
        for attempt in ("first sight", "returning"):
            other = await service.authenticate_kerberos(b"spnego-token")
            assert other.ok, f"{attempt}: {other.error}"
    finally:
        await store.close()


async def test_unbinding_gives_the_account_windows_sso_back(
    rsa_key: rsa.RSAPrivateKey, monkeypatch: pytest.MonkeyPatch
) -> None:
    """RED when: the refusal outlives the binding. The remedy the documentation names is an
    administrator's unbind, so the unbind has to work as one."""
    store = await MessageStore.open(":memory:")
    try:
        service = await _sso_service(store, rsa_key, bind=DEFAULT_SUB)
        _as(monkeypatch, "jdoe")
        assert not (await service.authenticate_kerberos(b"spnego-token")).ok
        user = await store.get_user_by_username("jdoe")
        assert user is not None

        await service.unbind_federated_subject(
            user.id,
            expected_issuer=user.oidc_issuer,
            expected_subject=user.oidc_subject,
            actor="admin",
        )
        again = await service.authenticate_kerberos(b"spnego-token")
        assert again.ok, again.error
    finally:
        await store.close()


async def test_the_refusal_reaches_a_renamed_bound_row_before_anything_is_written(
    rsa_key: rsa.RSAPrivateKey, monkeypatch: pytest.MonkeyPatch
) -> None:
    """RED when: the refusal is checked only on the row read by NAME.

    The directory renamed the account, so the name the ticket carries matches no row and the row is
    found by its immutable id inside the resolver. That is the second call site. The refusal has to
    land there before the resolver's writes, so the cached name must still be the old one."""
    store = await MessageStore.open(":memory:")
    try:
        renamed = _principal("jdoe2", object_id=PRINCIPAL.directory_object_id)
        ldap = _FakeLdap(by_username={"jdoe2": renamed})
        service = await _service(store, rsa_key, ldap=ldap, kerberos_enabled=True)
        _as(monkeypatch, "jdoe2")

        refused = await service.authenticate_kerberos(b"spnego-token")
        assert not refused.ok and refused.reason == FEDERATED_SIGN_IN_REQUIRED
        assert await store.get_user_by_username("jdoe2") is None, "a second row was created"
        row = await store.get_user_by_username("jdoe")
        assert row is not None, "the refused sign-in renamed the bound row"
        assert await store.get_user_role_ids(row.id) == [], "the refused sign-in synced roles"
        assert await store.list_sessions(row.id) == []
    finally:
        await store.close()


@pytest.fixture
async def engine(tmp_path: Path) -> AsyncIterator[Engine]:
    eng = await Engine.create(tmp_path / "bound_pathway.db", poll_interval=0.02)
    yield eng
    await eng.stop()


def _store_of(engine: Engine) -> MessageStore:
    store = engine.store
    assert isinstance(store, MessageStore)
    return store


def _client(engine: Engine, service: AuthService) -> httpx.AsyncClient:
    transport = httpx.ASGITransport(app=create_app(engine, auth=service), client=("127.0.0.1", 123))
    return httpx.AsyncClient(transport=transport, base_url="http://t")


def _bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


async def test_the_route_answers_the_refusal_as_it_answers_any_failed_negotiate(
    engine: Engine,
    rsa_key: rsa.RSAPrivateKey,
    monkeypatch: pytest.MonkeyPatch,
    pads: list[float],
) -> None:
    """RED when: the refusal gets its own status, body, header or timing class, or stops drawing
    the sign-in window.

    The comparison is a ticket for a name the directory does not hold. Both answers are read off
    ``POST /auth/negotiate`` whole. Then the window: three attempts are allowed per address here,
    all three are spent on the refusal, and the fourth is throttled."""
    service = await _sso_service(
        _store_of(engine), rsa_key, bind=DEFAULT_SUB, login_rate_limit_per_ip=3
    )
    async with _client(engine, service) as c:
        _as(monkeypatch, "ghost")
        unknown = await c.post("/auth/negotiate", headers=NEGOTIATE)
        _as(monkeypatch, "jdoe")
        bound = await c.post("/auth/negotiate", headers=NEGOTIATE)

        assert unknown.status_code == bound.status_code == 401
        assert bound.content == unknown.content
        assert sorted(bound.headers.items()) == sorted(unknown.headers.items())
        assert len(pads) == 2, "one of the two failures was not padded"

        assert (await c.post("/auth/negotiate", headers=NEGOTIATE)).status_code == 401
        assert (await c.post("/auth/negotiate", headers=NEGOTIATE)).status_code == 429


# --- the session Windows SSO minted before the bind ----------------------------------------------


async def test_a_session_minted_before_the_bind_cannot_bind_the_accounts_first_factor(
    rsa_key: rsa.RSAPrivateKey, monkeypatch: pytest.MonkeyPatch
) -> None:
    """RED when: ``_factor_binding_is_blocked`` stops reading the binding beside the session's
    mechanism.

    The control is the same session one line earlier: unbound, it may ask for the grant. After the
    bind it is refused all three factor-binding actions, a good re-proof mints it no grant, and the
    audit row says so. Ending its own sessions is not a factor-binding action and stays open."""
    store = await MessageStore.open(":memory:")
    try:
        service = await _sso_service(store, rsa_key)
        _as(monkeypatch, "jdoe")
        minted = await service.authenticate_kerberos(b"spnego-token")
        assert minted.ok and minted.token is not None and minted.identity is not None
        assert minted.mfa_required, "the fixture session owes no factor, so the gate is not read"
        token = minted.token
        for action in FACTOR_BINDING_ACTIONS:
            assert await service.factor_binding_is_blocked(token, action) is False

        await _bind(service, store, DEFAULT_SUB)

        # A first bind revokes nothing, which is why this gate has anything to refuse.
        session = await store.get_session(hash_token(token))
        assert session is not None and session.revoked_at is None
        for action in FACTOR_BINDING_ACTIONS:
            assert await service.factor_binding_is_blocked(token, action) is True, action
        assert (
            await service.factor_binding_is_blocked(token, STEP_UP_ACTION_SESSION_TERMINATE)
            is False
        )

        elevation = await service.reauth(
            minted.identity, "directory-pw", token=token, purpose=STEP_UP_ACTION_MFA_ENROLL
        )
        assert elevation.ok and elevation.token is not None
        assert await service.has_action_step_up(elevation.token, STEP_UP_ACTION_MFA_ENROLL) is False
        [row] = await store.list_audit(action="auth.reauth", actor="jdoe")
        detail = json.loads(str(dict(row)["detail"]))
        assert detail["ok"] is True and detail["grant_refused"] is True
    finally:
        await store.close()


async def test_a_federated_session_on_the_bound_account_may_still_bind_a_factor(
    rsa_key: rsa.RSAPrivateKey, monkeypatch: pytest.MonkeyPatch
) -> None:
    """RED when: the refusal reads the binding alone and forgets the session's mechanism.

    With the claim gate off, a federated session is minted owing a factor, so it has to be able to
    enrol one or the account is locked out. Its proof came through the identity provider."""
    store = await MessageStore.open(":memory:")
    try:
        service = await _sso_service(store, rsa_key, bind=DEFAULT_SUB, oidc_require_mfa_claim=False)
        federated = await _oidc_login(service, monkeypatch, rsa_key)
        assert federated.ok and federated.token is not None, federated.error
        assert federated.mfa_required, "the fixture session owes no factor, so the gate is not read"
        for action in FACTOR_BINDING_ACTIONS:
            assert await service.factor_binding_is_blocked(federated.token, action) is False
    finally:
        await store.close()


async def test_the_enrolment_route_refuses_the_session_minted_before_the_bind(
    engine: Engine, rsa_key: rsa.RSAPrivateKey, monkeypatch: pytest.MonkeyPatch
) -> None:
    """RED when: the route gate and the service rule come apart.

    Two accounts on one service, each holding a Windows SSO session that owes a factor. The one
    that stays unbound re-proves and reaches the enrolment route. The one bound afterwards is
    refused there, with the multi-factor header and no step-up header, so a client is not sent to
    re-prove a credential that would mint it nothing."""
    store = _store_of(engine)
    service = await _sso_service(store, rsa_key)
    async with _client(engine, service) as c:
        tokens: dict[str, str] = {}
        for name in ("jdoe", "asmith"):
            _as(monkeypatch, name)
            r = await c.post("/auth/negotiate", headers=NEGOTIATE)
            assert r.status_code == 200, r.text
            assert r.json()["mfa_required"] is True
            tokens[name] = r.json()["token"]
        await _bind(service, store, DEFAULT_SUB)

        outcomes: dict[str, httpx.Response] = {}
        for name, token in tokens.items():
            r = await c.post(
                "/me/reauth",
                headers=_bearer(token),
                json={"password": "directory-pw", "purpose": STEP_UP_ACTION_MFA_ENROLL},
            )
            assert r.status_code == 200, r.text
            outcomes[name] = await c.post("/me/mfa/enroll", headers=_bearer(r.json()["token"]))

        assert outcomes["asmith"].status_code == 200, outcomes["asmith"].text
        refused = outcomes["jdoe"]
        assert refused.status_code == 403
        assert refused.headers.get("X-MFA-Required") == "1"
        assert "X-Step-Up-Required" not in refused.headers


async def test_a_passkey_ceremony_begun_before_the_bind_cannot_finish_after_it(
    rsa_key: rsa.RSAPrivateKey, monkeypatch: pytest.MonkeyPatch
) -> None:
    """RED when: ``finish_webauthn_registration`` stops asking the rule itself.

    The route in front of the passkey finish rides the session window and asks no action-bound gate,
    so the service is the only place the rule can stand for it. The control is the same call on the
    unbound account: it gets as far as the ceremony lookup, which is a different refusal."""
    store = await MessageStore.open(":memory:")
    try:
        service = await _sso_service(store, rsa_key)
        _as(monkeypatch, "jdoe")
        minted = await service.authenticate_kerberos(b"spnego-token")
        assert minted.token is not None and minted.identity is not None
        identity, token = minted.identity, minted.token

        async def finish() -> None:
            await service.finish_webauthn_registration(
                identity, "{}", label="key", token=token, rp_id="t", origin="https://t"
            )

        with pytest.raises(ValueError, match="passkey ceremony expired"):
            await finish()
        await _bind(service, store, DEFAULT_SUB)
        with pytest.raises(ValueError, match="signs in through its identity provider"):
            await finish()
        assert await store.list_webauthn_credentials(identity.user_id) == []
    finally:
        await store.close()


# --- the operator document ---------------------------------------------------------------------


def test_the_security_doc_names_the_reason_the_audit_row_carries() -> None:
    """RED when: the reason slug changes in the code and not in ``docs/SECURITY.md``, or the
    sentence leaves the document. An operator finds this refusal by searching the audit trail for
    the slug the document gives."""
    text = (Path(__file__).resolve().parents[1] / "docs" / "SECURITY.md").read_text(
        encoding="utf-8"
    )
    assert f"`reason={FEDERATED_SIGN_IN_REQUIRED}`" in text


def test_the_bind_notice_tells_the_holder_windows_sso_no_longer_signs_them_in() -> None:
    """RED when: the notice goes back to saying only that the provider can sign the holder in. The
    bind withdraws a sign-in, and the notice is the one place the holder hears of it."""
    from messagefoundry.auth.notifications import FEDERATED_IDENTITY_BOUND

    assert (
        "Windows single sign-on no longer"
        in security_notify._DESCRIPTIONS[FEDERATED_IDENTITY_BOUND]
    )
