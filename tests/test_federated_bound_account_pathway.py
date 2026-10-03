# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""vault BACKLOG #2609: an account bound to a federated identity signs in through its identity
provider, and Windows SSO refuses it.

An administrator binds an account to a federated subject to put that account behind the identity
provider's own sign-in. Windows SSO mints at the minimum, one factor and nothing asserted. So a
bound account that could still use Windows SSO would keep a sign-in that never meets the identity
provider at all. The refusal lives where every directory sign-in decides whether a row may sign in
(``_directory_login_refusal``), at both of its call sites.

The second half is what the bind does to sessions. Every bind ends every live session of the
account, in the transaction that writes the pair, so nothing minted before it outlives it. And a
Windows SSO session insert requires an unbound row, so a sign-in already in flight when a bind
lands leaves nothing behind either.

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
from messagefoundry.auth.ldap import AdPrincipal
from messagefoundry.auth.notifications import (
    FEDERATED_IDENTITY_BOUND,
    FEDERATED_IDENTITY_UNBOUND,
    SecurityEvent,
)
from messagefoundry.auth.service import FEDERATED_SIGN_IN_REQUIRED, AuthService
from messagefoundry.auth.tokens import hash_token
from messagefoundry.config.settings import EgressSettings
from messagefoundry.pipeline import Engine, security_notify
from messagefoundry.store.store import MessageStore
from tests._admin_account import create_local_user_chosen
from tests.test_auth_oidc_service import (
    DEFAULT_SUB,
    PRINCIPAL,
    _bind,
    _FakeLdap,
    _oid,
    _oidc_login,
    _service,
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


async def _audit_details(store: MessageStore, action: str, actor: str) -> list[dict[str, Any]]:
    rows = await store.list_audit(action=action, actor=actor)
    return [json.loads(str(dict(r)["detail"])) for r in rows]


async def _sso_service(
    store: MessageStore, rsa_key: rsa.RSAPrivateKey, *, bind: str | None = None, **over: Any
) -> AuthService:
    """Windows SSO and federated sign-in both on. ``bind`` binds ``jdoe`` before any sign-in."""
    ldap = _FakeLdap(by_username={"jdoe": PRINCIPAL, "asmith": _principal("asmith"), "ghost": None})
    return await _service(store, rsa_key, ldap=ldap, bind=bind, kerberos_enabled=True, **over)


async def _windows_sso(service: AuthService, monkeypatch: pytest.MonkeyPatch, name: str) -> str:
    """Sign ``name`` in by Windows SSO and return the session token."""
    _as(monkeypatch, name)
    out = await service.authenticate_kerberos(b"spnego-token")
    assert out.ok and out.token is not None, out.error
    return out.token


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
        assert await _audit_details(store, "auth.login_failed", "jdoe") == [
            {"provider": "ad", "reason": FEDERATED_SIGN_IN_REQUIRED}
        ]
        successes = await store.list_audit(action="auth.login_success", actor="jdoe")
        assert len(successes) == 1, "the refused sign-in wrote a success row"
        assert await store.list_sessions(user_id) == [], "the refusal minted a session"

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
    eng = await Engine.create(
        tmp_path / "bound_pathway.db",
        poll_interval=0.02,
        egress_settings=EgressSettings(deny_by_default=False),
    )
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


# --- a bind ends the account's sessions ----------------------------------------------------------


async def test_a_bind_ends_every_session_of_the_account_and_no_other(
    rsa_key: rsa.RSAPrivateKey, monkeypatch: pytest.MonkeyPatch
) -> None:
    """RED when: a first bind goes back to revoking nothing, or the sweep reaches another account.

    Binding moves the account behind its identity provider, so a session minted before the bind
    must not outlive it. Two sessions of the bound account end, and the count is reported and
    audited. Two controls on the same service stay signed in: another directory account, and the
    administrator who performs the bind."""
    store = await MessageStore.open(":memory:")
    try:
        service = await _sso_service(store, rsa_key)
        mine = [await _windows_sso(service, monkeypatch, "jdoe") for _ in range(2)]
        other = await _windows_sso(service, monkeypatch, "asmith")
        await create_local_user_chosen(
            service,
            username="root",
            password="a-strong-test-passphrase",
            display_name=None,
            email=None,
            roles=[],
            actor="test",
        )
        admin = (await service.login("root", "a-strong-test-passphrase")).token
        assert admin is not None
        for token in (*mine, other, admin):
            assert await service.identity_for_token(token) is not None

        user = await store.get_user_by_username("jdoe")
        assert user is not None
        binding = await service.bind_federated_subject(
            user.id, DEFAULT_SUB, expected_issuer=None, expected_subject=None, actor="root"
        )

        assert binding.sessions_revoked == 2
        for token in mine:
            assert await service.identity_for_token(token) is None, "a session outlived the bind"
            session = await store.get_session(hash_token(token))
            assert session is not None and session.revoked_at is not None
        assert await service.identity_for_token(other) is not None, "another account was signed out"
        assert await service.identity_for_token(admin) is not None, "the binder was signed out"
        [detail] = await _audit_details(store, "auth.federated_subject_bound", "root")
        assert detail["sessions_revoked"] == 2
    finally:
        await store.close()


async def test_a_session_that_owed_no_factor_does_not_outlive_the_bind_either(
    rsa_key: rsa.RSAPrivateKey, monkeypatch: pytest.MonkeyPatch
) -> None:
    """RED when: the bind leaves a session alone because it has nothing left to prove.

    With ``[security].require_mfa`` off a Windows SSO session owes no factor, so it acts in full
    from the moment it is minted. Nothing short of ending it takes that away. The control is the
    same session before the bind, which resolves and is satisfied."""
    store = await MessageStore.open(":memory:")
    try:
        service = await _sso_service(store, rsa_key, require_mfa=False)
        token = await _windows_sso(service, monkeypatch, "jdoe")
        assert await service.identity_for_token(token) is not None
        assert await service.mfa_satisfied(token) is True

        await _bind(service, store, DEFAULT_SUB)

        assert await service.identity_for_token(token) is None
        assert await service.mfa_satisfied(token) is False
    finally:
        await store.close()


async def test_a_session_windows_sso_minted_before_the_bind_no_longer_resolves_on_the_api(
    engine: Engine, rsa_key: rsa.RSAPrivateKey, monkeypatch: pytest.MonkeyPatch
) -> None:
    """RED when: the revoke stops reaching the request path.

    Read where a caller meets it: the bearer token ``POST /auth/negotiate`` handed out answers
    ``GET /auth/me`` before the bind and is refused after it. The unbound account's token is the
    control."""
    store = _store_of(engine)
    service = await _sso_service(store, rsa_key)
    async with _client(engine, service) as c:
        tokens: dict[str, str] = {}
        for name in ("jdoe", "asmith"):
            _as(monkeypatch, name)
            r = await c.post("/auth/negotiate", headers=NEGOTIATE)
            assert r.status_code == 200, r.text
            tokens[name] = r.json()["token"]
            assert (await c.get("/auth/me", headers=_bearer(tokens[name]))).status_code == 200

        await _bind(service, store, DEFAULT_SUB)

        assert (await c.get("/auth/me", headers=_bearer(tokens["jdoe"]))).status_code == 401
        assert (await c.get("/auth/me", headers=_bearer(tokens["asmith"]))).status_code == 200


async def test_a_bind_that_lands_during_a_windows_sso_sign_in_leaves_no_session(
    rsa_key: rsa.RSAPrivateKey, monkeypatch: pytest.MonkeyPatch
) -> None:
    """RED when: the Windows SSO session insert stops requiring an unbound row.

    The sign-in reads the row unbound and passes the refusal. The bind then commits, sweeping the
    account's sessions, and only after that does the sign-in insert its own, which that sweep could
    not see. The role lookup runs between the check and the insert, so the bind is fired from
    inside it, once. The sign-in must end as the refusal, with nothing minted.

    The control is the next sign-in through the same wrapper, now unarmed and with the bind already
    committed: it is refused at the check, so the first refusal came from the insert."""
    store = await MessageStore.open(":memory:")
    try:
        service = await _sso_service(store, rsa_key)
        await _windows_sso(service, monkeypatch, "jdoe")  # the row exists and is unbound
        user = await store.get_user_by_username("jdoe")
        assert user is not None
        real = store.roles_for_ad_groups
        armed = [True]
        checks_passed = 0

        async def lookup(groups: Any) -> set[str]:
            nonlocal checks_passed
            checks_passed += 1
            if armed.pop() if armed else False:
                await _bind(service, store, DEFAULT_SUB)
            return await real(groups)

        monkeypatch.setattr(store, "roles_for_ad_groups", lookup)
        raced = await service.authenticate_kerberos(b"spnego-token")

        assert checks_passed == 1, "the sign-in was refused before the bind could land"
        assert not raced.ok and raced.token is None
        assert raced.reason == FEDERATED_SIGN_IN_REQUIRED
        assert await store.list_sessions(user.id) == [], "the sign-in left a live session"
        successes = await store.list_audit(action="auth.login_success", actor="jdoe")
        assert len(successes) == 1, "the refused sign-in wrote a success row"

        control = await service.authenticate_kerberos(b"spnego-token")
        assert not control.ok and checks_passed == 1, "the control never reached the role lookup"
    finally:
        await store.close()


async def test_a_windows_sso_sign_in_inside_a_rebinds_gap_does_not_outlive_the_rebind(
    rsa_key: rsa.RSAPrivateKey, monkeypatch: pytest.MonkeyPatch
) -> None:
    """RED when: the write half of a rebind stops sweeping the account's sessions.

    A rebind is a clear and then a separate write, and between the two the row is unbound. A
    Windows SSO sign-in in that gap meets an unbound row and is admitted. The write that follows
    must end it. The sign-in is fired from inside the write, just before it runs.

    The control is the same sign-in before the rebind starts, which is refused."""
    store = await MessageStore.open(":memory:")
    try:
        service = await _sso_service(store, rsa_key, bind=DEFAULT_SUB)
        _as(monkeypatch, "jdoe")
        assert not (await service.authenticate_kerberos(b"spnego-token")).ok
        user = await store.get_user_by_username("jdoe")
        assert user is not None
        real = store.set_user_federated_subject
        in_gap: list[str] = []

        async def write(*args: Any, **kwargs: Any) -> int | None:
            if not in_gap:
                gap = await service.authenticate_kerberos(b"spnego-token")
                assert gap.ok and gap.token is not None, "the gap sign-in was not admitted"
                in_gap.append(gap.token)
            return await real(*args, **kwargs)

        monkeypatch.setattr(store, "set_user_federated_subject", write)
        rebound = await service.bind_federated_subject(
            user.id,
            "S-1-rebound",
            expected_issuer=user.oidc_issuer,
            expected_subject=user.oidc_subject,
            actor="admin",
        )

        [token] = in_gap
        assert await service.identity_for_token(token) is None, (
            "the gap session outlived the rebind"
        )
        assert await store.list_sessions(user.id) == []
        assert rebound.sessions_revoked == 1, "the count left out the session the write swept"
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


def test_the_bind_notice_tells_the_holder_what_the_bind_took_away() -> None:
    """RED when: the notice goes back to saying only that the provider can sign the holder in. The
    bind ends the holder's sessions and withdraws a sign-in, and the notice is the one place the
    holder hears of it."""
    notice = security_notify._DESCRIPTIONS[FEDERATED_IDENTITY_BOUND]
    assert "sessions were ended" in notice
    assert "Windows single sign-on no longer" in notice
    body = security_notify._build_body(
        SecurityEvent(
            event_type=FEDERATED_IDENTITY_BOUND,
            username="jdoe",
            email="jdoe@corp.example",
            detail={"issuer": "https://idp.example", "sessions_revoked": 2},
        )
    )
    assert "Sessions ended: 2" in body
    # An administrator did it, and the holder never can, so the "if this was you" closing is wrong.
    assert "If this was you" not in body
    assert "If you did not expect this change" in body
    # The unlink is an administrator's act for the same reason.
    unbound = security_notify._build_body(
        SecurityEvent(
            event_type=FEDERATED_IDENTITY_UNBOUND,
            username="jdoe",
            email="jdoe@corp.example",
            detail={"issuer": "https://idp.example"},
        )
    )
    assert "If this was you" not in unbound


def test_the_security_doc_states_the_limits_beside_the_session_claim() -> None:
    """RED when: the claim that nothing minted before a bind outlives it loses the limits written
    beside it. The claim is true of the sweep as designed, and the two limits are what a reader
    planning on it has to know."""
    text = (Path(__file__).resolve().parents[1] / "docs" / "SECURITY.md").read_text(
        encoding="utf-8"
    )
    assert "**Limits of the session sweep.**" in text
    assert "**A bind and a user delete can collide on the SQL Server and Postgres stores.**" in text


def test_the_security_doc_says_provision_admin_does_not_replace_a_local_administrator() -> None:
    """RED when: the recovery sentence leaves the document. A site that binds every Administrator
    has to read, before the outage, that the host command will refuse."""
    text = (Path(__file__).resolve().parents[1] / "docs" / "SECURITY.md").read_text(
        encoding="utf-8"
    )
    assert "`provision-admin` will not rescue the site" in text
