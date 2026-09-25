# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""``AuthService.authenticate_oidc`` — the federated login path (ADR 0142, BACKLOG #274).

Hermetic: no network. The ``id_token`` is minted with the shipped ``CompactJwtSigner`` over a
throwaway key, the JWKS is served from memory, and the token-endpoint exchange is stubbed at the
module seam ``auth/service.py`` actually calls (``oidc.exchange_code``).

These cover the acceptance criteria that live in the service rather than the ladder: AC-2 (roles come
from LDAP, never a token claim), AC-6 (the session is capped at the verified ``exp``), AC-8
(an unreachable IdP degrades and recovers without a restart) and AC-10 (no secret, code or token in
the logs).

**ADR 0184 (BACKLOG #1143 / #295): a federated login no longer binds.** The account is selected by
the verified ``(issuer, sub)`` pair, and a pair bound to nothing is refused. So ``_service`` binds the
default fixture account to the default subject through the admin path, the only path that may create
a binding. A test about first contact or about a different subject passes ``bind=None`` and binds
what it needs itself. ADR 0184's AC-1 to AC-4 are pinned in the section named for them below.
"""

from __future__ import annotations

import json
import logging
import time
import urllib.request
from collections.abc import Mapping
from typing import Any
from uuid import uuid4

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from messagefoundry.auth import oidc
from messagefoundry.auth.identity import AuthProvider
from messagefoundry.auth.ldap import AdPrincipal
from messagefoundry.auth.notifications import FEDERATED_IDENTITY_BOUND, FEDERATED_IDENTITY_UNBOUND
from messagefoundry.auth.service import (
    FEDERATED_SUBJECT_NOT_BOUND,
    AuthService,
    FederatedSubjectHeld,
    LoginOutcome,
)
from messagefoundry.auth.tokens import hash_token
from messagefoundry.config.models import SignatureAlgorithm
from messagefoundry.config.settings import AuthSettings
from messagefoundry.store.store import MessageStore
from messagefoundry.transports.signing import CompactJwtSigner

CLIENT_SECRET = "s3cr3t-client-value"
#: The ``sub`` the default ``_claims`` carry, and the one ``_service`` binds ``jdoe`` to by default.
DEFAULT_SUB = "S-1-5-21-federated"
AUTH_CODE = "authz-code-abcdef"
NONCE = "n-oidc-1"

# --- helpers ---------------------------------------------------------------------------------------


@pytest.fixture(scope="module")
def rsa_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=3072)


def _b64u_uint(value: int) -> str:
    import base64

    raw = value.to_bytes((value.bit_length() + 7) // 8, "big")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _jwks_bytes(key: rsa.RSAPrivateKey, kid: str = "k1") -> bytes:
    nums = key.public_key().public_numbers()
    jwk = {
        "kty": "RSA",
        "kid": kid,
        "use": "sig",
        "alg": "RS256",
        "n": _b64u_uint(nums.n),
        "e": _b64u_uint(nums.e),
    }
    return json.dumps({"keys": [jwk]}).encode()


def _mint(key: rsa.RSAPrivateKey, claims: Mapping[str, Any], kid: str = "k1") -> str:
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("ascii")
    signer = CompactJwtSigner(
        private_key=pem,
        algorithm=SignatureAlgorithm.RS256,
        key_id=kid,
        setting="test_idp_signing_key",
    )
    return signer.sign(dict(claims))


def _claims(**over: Any) -> dict[str, Any]:
    now = time.time()
    base: dict[str, Any] = {
        "iss": "https://idp.example",
        "aud": "mefor-console",
        "sub": DEFAULT_SUB,
        "exp": now + 3600,
        "iat": now,
        "auth_time": now,  # REQUIRED since BACKLOG #1150 (max_age is always requested)
        "nonce": NONCE,
        "preferred_username": "jdoe@corp.example",
        "amr": ["pwd", "mfa"],
    }
    base.update(over)
    return base


def _settings(**over: Any) -> AuthSettings:
    base: dict[str, Any] = {
        "ad_enabled": True,
        "ad_server": "ldaps://dc.corp.example",
        "ad_user_search_base": "DC=corp,DC=example",
        "ad_bind_dn": "CN=svc,DC=corp,DC=example",
        "ad_bind_password": "x",
        "ad_domain": "corp.example",  # the UPN suffix the username allow-list falls back to
        "oidc_enabled": True,
        "oidc_issuer": "https://idp.example",
        "oidc_client_id": "mefor-console",
        "oidc_client_secret": CLIENT_SECRET,
        "oidc_authorization_endpoint": "https://idp.example/authorize",
        "oidc_token_endpoint": "https://idp.example/token",
        "oidc_jwks_uri": "https://idp.example/jwks",
        "oidc_allowed_endpoints": ["idp.example"],
    }
    base.update(over)
    return AuthSettings(**base)


#: The AD object the federated username resolves to. Its groups are the ONLY role source.
PRINCIPAL = AdPrincipal(
    username="jdoe",
    display_name="J Doe",
    email="j@corp.example",
    dn="CN=jdoe,DC=corp,DC=example",
    groups=frozenset({"cn=mf-ops,dc=corp,dc=example"}),
)


class _FakeLdap:
    def __init__(
        self,
        principal: AdPrincipal | None = PRINCIPAL,
        *,
        by_username: dict[str, AdPrincipal | None] | None = None,
    ) -> None:
        # ``by_username`` maps a (domain-stripped) resolve key to the AD object it resolves to, so a test
        # can express a CHANGED OIDC display-username that still resolves to the same AD object (BACKLOG
        # #1015). When it is None (the default), the fixed ``principal`` is returned for any username, so
        # every pre-existing caller is unchanged.
        self._principal = principal
        self._by_username = by_username
        self.resolved: list[str] = []

    def authenticate(self, username: str, password: str) -> AdPrincipal | None:
        return self._principal

    def resolve_principal(
        self, username: str, *, object_id: str | None = None
    ) -> AdPrincipal | None:
        # ``object_id`` is accepted because the federated path hands over the bound row's id, as the
        # reconciler does (ADR 0184 part 2). None of these rows carries one, so it selects nothing.
        self.resolved.append(username)
        if self._by_username is not None:
            return self._by_username.get(username, self._principal)
        return self._principal


def _flow() -> oidc.PendingFlow:
    return oidc.PendingFlow(
        state="st",
        nonce=NONCE,
        code_verifier="verifier-value",
        return_to="/ui",
        client_ip="127.0.0.1",
        deadline=time.monotonic() + 300,
    )


async def _service(
    store: MessageStore,
    rsa_key: rsa.RSAPrivateKey,
    *,
    ldap: _FakeLdap | None = None,
    notifier: Any = None,
    bind: str | None = DEFAULT_SUB,
    **over: Any,
) -> AuthService:
    """A federated-enabled service. ``bind`` names the subject ``jdoe`` is bound to through the admin
    path before any login runs; ``None`` leaves every account unbound (ADR 0184 AC-4)."""
    service = AuthService(
        store,
        _settings(**over),
        ldap=ldap or _FakeLdap(),  # type: ignore[arg-type]
        security_notifier=notifier,
    )
    # Swap the real JWKS cache for an in-memory one. The service builds a genuine CA-verifying opener
    # at construction (which opens no socket), so this only replaces the fetch, not the policy.
    service._oidc_jwks = oidc.JwksCache(lambda: _jwks_bytes(rsa_key))
    await service.initialize()
    await service.set_ad_group_map([("cn=mf-ops,dc=corp,dc=example", "operator")], actor="admin")
    if bind is not None:
        await _bind(service, store, bind)
    return service


async def _bind(
    service: AuthService, store: MessageStore, subject: str, *, username: str = "jdoe"
) -> str:
    """Bind ``username`` to ``subject`` the way an operator must: through the admin path.

    The directory mirror row is created first when it is absent, standing in for the Kerberos sign-in
    that creates one on a real site. Returns the account id.
    """
    user = await store.get_user_by_username(username)
    if user is None:
        user_id = uuid4().hex
        await store.create_user(user_id=user_id, username=username, auth_provider="ad")
    else:
        user_id = user.id
    await service.bind_federated_subject(user_id, subject, actor="admin")
    return user_id


def _stub_exchange(monkeypatch: pytest.MonkeyPatch, id_token: str) -> list[dict[str, Any]]:
    """Stub the token-endpoint call at the seam service.py resolves at CALL time."""
    calls: list[dict[str, Any]] = []

    def fake(**kwargs: Any) -> Mapping[str, object]:
        calls.append(kwargs)
        return {"id_token": id_token, "access_token": "at-should-never-be-stored"}

    monkeypatch.setattr(oidc, "exchange_code", fake)
    return calls


async def _audit_rows(store: MessageStore, action: str) -> list[Mapping[str, Any]]:
    return [a for a in await store.list_audit() if a["action"] == action]


async def _oidc_login(
    service: AuthService,
    monkeypatch: pytest.MonkeyPatch,
    rsa_key: rsa.RSAPrivateKey,
    **claim_over: Any,
) -> LoginOutcome:
    """Run one federated login, stubbing the token exchange to return a freshly-minted id_token whose
    claims are ``_claims(**claim_over)`` (so a test can vary ``sub`` / ``preferred_username``)."""
    _stub_exchange(monkeypatch, _mint(rsa_key, _claims(**claim_over)))
    return await service.authenticate_oidc(
        AUTH_CODE, _flow(), redirect_uri="https://ops.example/ui/oidc/callback"
    )


# --- #285 (ASVS 6.7.1): the enforcement dial reaches the OIDC anchor's construction seam ------------


async def test_service_threads_enforcement_dial_and_pin_to_the_oidc_anchor(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """AuthService.__init__ must forward [security].enforcement (and the configured SHA-256 pin) to
    build_idp_opener, so the OIDC anchor's construction-site preflight honors warn vs enforce. The seam
    previously hardcoded enforce, making warn-mode startup unreachable for a group/world-writable OIDC
    anchor (the central preflight would warn+continue, then this build would refuse and abort startup)."""
    calls: list[dict[str, Any]] = []

    def spy(
        ca_cert_file: str | None,
        *,
        pin: str | None = None,
        enforcing: bool = True,
        crl_file: str | None = None,
    ) -> urllib.request.OpenerDirector:
        calls.append(
            {"ca": ca_cert_file, "pin": pin, "enforcing": enforcing, "crl": crl_file},
        )
        return urllib.request.build_opener()

    monkeypatch.setattr("messagefoundry.auth.service.build_idp_opener", spy)
    settings = _settings(
        oidc_tls_ca_cert_file="C:/anchors/idp-ca.pem",
        oidc_tls_ca_cert_pin="ab" * 32,
        oidc_tls_crl_file="C:/anchors/idp-crl.pem",
    )
    for enforcing in (False, True):
        store = await MessageStore.open(":memory:")
        try:
            AuthService(store, settings, ldap=_FakeLdap(), enforcing=enforcing)  # type: ignore[arg-type]
        finally:
            await store.close()
    # The dial is forwarded verbatim (warn then enforce), as is the pin and the CA path.
    assert [c["enforcing"] for c in calls] == [False, True]
    assert all(c["ca"] == "C:/anchors/idp-ca.pem" and c["pin"] == "ab" * 32 for c in calls)
    # BACKLOG #299: the CRL path is threaded on the same seam. Asserted here rather than only at
    # build_idp_opener, because a setting that never reaches the builder is a knob that does nothing.
    assert all(c["crl"] == "C:/anchors/idp-crl.pem" for c in calls)


# --- AC-2: roles come from LDAP, never from a token claim -------------------------------------------


async def test_roles_come_from_the_directory_not_the_token(
    rsa_key: rsa.RSAPrivateKey, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The load-bearing property of ADR 0142: a claims-parsing bug degrades to wrong-user login, not
    privilege escalation. The token screams "administrator"; the directory says operator."""
    store = await MessageStore.open(":memory:")
    try:
        ldap = _FakeLdap()
        service = await _service(store, rsa_key, ldap=ldap)
        id_token = _mint(
            rsa_key,
            _claims(groups=["Domain Admins"], roles=["administrator"], role="administrator"),
        )
        _stub_exchange(monkeypatch, id_token)

        out = await service.authenticate_oidc(
            AUTH_CODE, _flow(), redirect_uri="https://ops.example/ui/oidc/callback"
        )
        assert out.ok and out.identity is not None
        assert out.identity.auth_provider is AuthProvider.AD  # no new enum member (ADR 0142)
        assert {r.value for r in out.identity.roles} == {"operator"}
        assert ldap.resolved == ["jdoe"]  # the domain-stripped username, looked up password-free
    finally:
        await store.close()


# --- username binding: a federated principal may not CHOOSE its on-prem account --------------------


@pytest.mark.parametrize(
    "claimed",
    [
        "Administrator@attacker.example",  # the headline attack: a guest picks a privileged account
        "administrator@evil.co.uk@corp.example",  # suffix is everything after the FIRST '@'
        "Administrator",  # no suffix at all -- nothing to attest to
        "Administrator@",  # empty suffix
        "@corp.example",  # empty local part
    ],
)
async def test_a_foreign_upn_suffix_cannot_select_an_on_prem_account(
    rsa_key: rsa.RSAPrivateKey, monkeypatch: pytest.MonkeyPatch, claimed: str
) -> None:
    """`preferred_username` is neither unique nor stable (OIDC Core 5.7) and is self-editable on
    several IdPs. Without a suffix allow-list, the local part alone decides which AD object is
    resolved, so any principal the IdP will issue a token to could log in as the on-prem
    Administrator. That is CHOSEN escalation, not the accidental wrong-user login the
    roles-from-LDAP design bounds."""
    store = await MessageStore.open(":memory:")
    try:
        ldap = _FakeLdap()
        service = await _service(store, rsa_key, ldap=ldap)
        _stub_exchange(monkeypatch, _mint(rsa_key, _claims(preferred_username=claimed)))

        out = await service.authenticate_oidc(
            AUTH_CODE, _flow(), redirect_uri="https://ops.example/ui/oidc/callback"
        )
        assert not out.ok and out.token is None
        assert ldap.resolved == []  # refused BEFORE the directory is ever consulted
        rows = await _audit_rows(store, "auth.login_failed")
        assert any('"reason": "username_domain_not_allowed"' in (r["detail"] or "") for r in rows)
    finally:
        await store.close()


async def test_an_alternate_upn_suffix_is_accepted_when_allow_listed(
    rsa_key: rsa.RSAPrivateKey, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Multi-domain forests and alternate UPN suffixes are real, so the allow-list takes a list."""
    store = await MessageStore.open(":memory:")
    try:
        service = await _service(
            store,
            rsa_key,
            oidc_allowed_username_domains=["corp.example", "Contoso.Example"],
        )
        # Case-insensitive, matching AD's own UPN comparison.
        _stub_exchange(
            monkeypatch, _mint(rsa_key, _claims(preferred_username="jdoe@CONTOSO.example"))
        )

        out = await service.authenticate_oidc(
            AUTH_CODE, _flow(), redirect_uri="https://ops.example/ui/oidc/callback"
        )
        assert out.ok
    finally:
        await store.close()


# --- ADR 0184 (BACKLOG #1143 / #295): the account is SELECTED by (issuer, sub) ----------------------
#
# Before this, the federated leg reached its account through the token's username claim and bound the
# presented subject on the account's first federated login. The owner ruled on 2026-09-06 that the
# administrative binding surface is the only path that may create a binding, and ADR 0184 moved
# identification onto the pair. These tests pin its AC-1 to AC-4, plus the two continuity cases the
# #1015 and #1256 tests used to pin, restated for pair-keyed selection.


#: A DIFFERENT on-prem object from ``PRINCIPAL``, in a group mapped to administrator. A token that
#: claims this name must not reach it, and above all must not bring its groups onto another account.
OTHER = AdPrincipal(
    username="bsmith",
    display_name="B Smith",
    email="bsmith@corp.example",
    dn="CN=bsmith,DC=corp,DC=example",
    groups=frozenset({"cn=mf-admins,dc=corp,dc=example"}),
)


async def _sessions_for(store: MessageStore, username: str) -> list[Any]:
    user = await store.get_user_by_username(username)
    return [] if user is None else await store.list_sessions(user.id)


async def test_ac4_first_contact_is_refused_and_binds_nothing(
    rsa_key: rsa.RSAPrivateKey, monkeypatch: pytest.MonkeyPatch
) -> None:
    """AC-4: a verified ``(issuer, sub)`` bound to no account is refused, audited, binds nothing and
    mints nothing -- and the directory is never asked, so the refusal says nothing about it.

    THE CONTROL IS THE LAST LOGIN. The same token succeeds once an administrator binds the subject, so
    the refusal is about the binding and not a fixture that cannot log in at all.
    """
    store = await MessageStore.open(":memory:")
    try:
        ldap = _FakeLdap()
        service = await _service(store, rsa_key, ldap=ldap, bind=None)

        out = await _oidc_login(service, monkeypatch, rsa_key)

        assert not out.ok and out.token is None
        assert out.reason == FEDERATED_SUBJECT_NOT_BOUND
        assert ldap.resolved == [], "the directory was consulted for an unbound identity"
        assert await store.get_user_by_federated_subject("https://idp.example", DEFAULT_SUB) is None
        assert await store.get_user_by_username("jdoe") is None, "first contact created a row"
        assert await _audit_rows(store, "auth.login_success") == []
        assert await _audit_rows(store, "auth.federated_subject_bound") == []
        [row] = [
            r
            for r in await _audit_rows(store, "auth.login_failed")
            if FEDERATED_SUBJECT_NOT_BOUND in (r["detail"] or "")
        ]
        # A NEUTRAL actor: the claimed name selects nothing, so the row must not land in that
        # person's security-events feed. The presented pair is recorded, because binding it is the
        # only remedy and the operator needs the exact sub to do that.
        assert row["actor"] == "<oidc>"
        detail = json.loads(row["detail"])
        assert (detail["issuer"], detail["subject"]) == ("https://idp.example", DEFAULT_SUB)
        assert detail["claimed_username"] == "jdoe"  # the ladder strips the UPN suffix

        # CONTROL: bind through the admin path, and the same token now signs in.
        await _bind(service, store, DEFAULT_SUB)
        assert (await _oidc_login(service, monkeypatch, rsa_key)).ok
    finally:
        await store.close()


async def test_ac4_a_never_federated_directory_account_is_not_landed_on(
    rsa_key: rsa.RSAPrivateKey, monkeypatch: pytest.MonkeyPatch
) -> None:
    """ASVS 6.8.1's own case. ``jdoe`` exists as a directory account and has never federated -- the
    default state of every account. A token claiming that name under a subject nobody bound must not
    reach it, and must not bind that subject to it.

    Under bind-on-first-presentation this login succeeded and bound ``S-1-evil`` to ``jdoe``, which is
    what the #1015 guard's ``bound.oidc_subject is not None`` short-circuit let through.
    """
    store = await MessageStore.open(":memory:")
    try:
        service = await _service(store, rsa_key, bind=None)
        # The row a Kerberos sign-in creates: a directory account with no federated binding.
        assert (await service._complete_ad_login(PRINCIPAL, None, mfa_verified=True)).ok
        before = await store.get_user_by_username("jdoe")
        assert before is not None and before.oidc_subject is None
        kerberos_sessions = len(await _sessions_for(store, "jdoe"))

        out = await _oidc_login(
            service, monkeypatch, rsa_key, sub="S-1-evil", preferred_username="jdoe@corp.example"
        )

        assert not out.ok and out.token is None
        assert out.reason == FEDERATED_SUBJECT_NOT_BOUND
        after = await store.get_user_by_username("jdoe")
        assert after is not None
        assert (after.oidc_issuer, after.oidc_subject) == (None, None), "first contact bound"
        assert len(await _sessions_for(store, "jdoe")) == kerberos_sessions
    finally:
        await store.close()


async def test_ac1_the_pair_selects_the_account_whatever_name_the_token_claims(
    rsa_key: rsa.RSAPrivateKey, monkeypatch: pytest.MonkeyPatch
) -> None:
    """AC-1: the session is issued for the pair's account even when the token's username claim
    names a different directory principal. The claim selects nothing, so no row is made for it."""
    store = await MessageStore.open(":memory:")
    try:
        ldap = _FakeLdap(by_username={"jdoe": PRINCIPAL, "bsmith": OTHER})
        service = await _service(store, rsa_key, ldap=ldap, bind="S-1-alice")
        account = await store.get_user_by_username("jdoe")
        assert account is not None

        # POSITIVE CONTROL: the claimed name really resolves to a DIFFERENT directory object.
        assert ldap.resolve_principal("bsmith") is OTHER
        ldap.resolved.clear()

        out = await _oidc_login(
            service, monkeypatch, rsa_key, sub="S-1-alice", preferred_username="bsmith@corp.example"
        )

        assert out.ok and out.identity is not None and out.token is not None
        assert out.identity.user_id == account.id
        assert out.identity.username == "jdoe"
        session = await store.get_session(hash_token(out.token))
        assert session is not None and session.user_id == account.id
        assert await store.get_user_by_username("bsmith") is None, "the claimed name got a row"
    finally:
        await store.close()


async def test_ac2_roles_come_from_the_bound_rows_directory_entry(
    rsa_key: rsa.RSAPrivateKey, monkeypatch: pytest.MonkeyPatch
) -> None:
    """AC-2: the directory principal is re-resolved from the SELECTED ROW, and roles come only from
    it. The claimed name is never looked up, so its administrator group cannot reach the session.

    This is the half-done re-ordering ADR 0184 warns about: select the row by the pair, keep the
    principal resolved from the claim, and the claim's groups land on the bound account."""
    store = await MessageStore.open(":memory:")
    try:
        ldap = _FakeLdap(by_username={"jdoe": PRINCIPAL, "bsmith": OTHER})
        service = await _service(store, rsa_key, ldap=ldap, bind="S-1-alice")
        await service.set_ad_group_map(
            [
                ("cn=mf-ops,dc=corp,dc=example", "operator"),
                ("cn=mf-admins,dc=corp,dc=example", "administrator"),
            ],
            actor="admin",
        )

        out = await _oidc_login(
            service, monkeypatch, rsa_key, sub="S-1-alice", preferred_username="bsmith@corp.example"
        )

        assert out.ok and out.identity is not None
        assert {r.value for r in out.identity.roles} == {"operator"}
        assert ldap.resolved == ["jdoe"], "the directory was asked about the claimed name"
    finally:
        await store.close()


class _IdRecordingLdap(_FakeLdap):
    """Records the object id each resolve was handed."""

    def __init__(self, principal: AdPrincipal) -> None:
        super().__init__(principal)
        self.object_ids: list[str | None] = []

    def resolve_principal(
        self, username: str, *, object_id: str | None = None
    ) -> AdPrincipal | None:
        self.object_ids.append(object_id)
        return super().resolve_principal(username, object_id=object_id)


async def test_ac2_the_re_resolve_hands_over_the_bound_rows_object_id(
    rsa_key: rsa.RSAPrivateKey, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The re-resolve passes the row's ``directory_object_id``, as the reconciler does, so a
    directory-side rename still reaches the bound account (BACKLOG #1532)."""
    store = await MessageStore.open(":memory:")
    try:
        with_id = AdPrincipal(
            username="jdoe",
            display_name="J Doe",
            email="j@corp.example",
            dn="CN=jdoe,DC=corp,DC=example",
            groups=PRINCIPAL.groups,
            directory_object_id="guid-jdoe",
        )
        ldap = _IdRecordingLdap(with_id)
        service = await _service(store, rsa_key, ldap=ldap, bind=None)
        user_id = uuid4().hex
        await store.create_user(
            user_id=user_id, username="jdoe", auth_provider="ad", directory_object_id="guid-jdoe"
        )
        await service.bind_federated_subject(user_id, "S-1-alice", actor="admin")

        out = await _oidc_login(service, monkeypatch, rsa_key, sub="S-1-alice")

        assert out.ok and out.identity is not None and out.identity.user_id == user_id
        assert ldap.object_ids == ["guid-jdoe"]
    finally:
        await store.close()


async def test_ac3_a_binding_on_a_local_row_is_refused(
    rsa_key: rsa.RSAPrivateKey, monkeypatch: pytest.MonkeyPatch
) -> None:
    """AC-3: a pair that selects a LOCAL account is refused as ``local_account_conflict``, audited,
    with no session and no directory lookup.

    The admin bind refuses a LOCAL row, which is the control below, so the binding is PLANTED through
    the store. That is the state ADR 0184 part 3 keeps the guard for: a binding placed by any other
    means.
    """
    store = await MessageStore.open(":memory:")
    try:
        ldap = _FakeLdap()
        service = await _service(store, rsa_key, ldap=ldap, bind=None)
        local_id = await service.create_local_user(
            username="jlocal",
            password="Sup3rSecret!!-long-enough",
            display_name=None,
            email=None,
            roles=[],
            actor="test",
        )
        # CONTROL: the admin path refuses this row outright.
        with pytest.raises(ValueError, match="only a directory"):
            await service.bind_federated_subject(local_id, "S-1-local", actor="admin")
        await store.set_user_federated_subject(local_id, "https://idp.example", "S-1-local")

        out = await _oidc_login(service, monkeypatch, rsa_key, sub="S-1-local")

        assert not out.ok and out.token is None
        assert out.reason == "local_account_conflict"
        assert await store.list_sessions(local_id) == []
        assert ldap.resolved == []
        rows = await _audit_rows(store, "auth.login_failed")
        assert any('"reason": "local_account_conflict"' in (r["detail"] or "") for r in rows)
    finally:
        await store.close()


async def test_a_reassigned_username_presenting_a_new_subject_is_refused(
    rsa_key: rsa.RSAPrivateKey, monkeypatch: pytest.MonkeyPatch
) -> None:
    """BACKLOG #1015's case under pair-keyed selection. The IdP reassigns ``jdoe@corp.example`` to a
    new person with a new ``sub``. That subject is bound to nothing, so it is refused as unbound --
    not as ``federated_subject_conflict``, which this path no longer emits -- and the bound account
    is left exactly as it was."""
    store = await MessageStore.open(":memory:")
    try:
        service = await _service(store, rsa_key, bind="S-1-alice")
        first = await _oidc_login(service, monkeypatch, rsa_key, sub="S-1-alice")
        assert first.ok
        account = await store.get_user_by_username("jdoe")
        assert account is not None

        second = await _oidc_login(service, monkeypatch, rsa_key, sub="S-1-bob")

        assert not second.ok and second.token is None
        assert second.reason == FEDERATED_SUBJECT_NOT_BOUND
        after = await store.get_user_by_username("jdoe")
        assert after is not None and after.id == account.id
        assert after.oidc_subject == "S-1-alice"
        assert len(await store.list_sessions(account.id)) == 1, "only the first login's session"
        assert len([u for u in await store.list_users() if u.username == "jdoe"]) == 1
    finally:
        await store.close()


async def test_same_subject_under_a_changed_username_claim_is_the_same_account(
    rsa_key: rsa.RSAPrivateKey, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The same person (same ``sub``) whose ``preferred_username`` changed lands on the same account,
    and the directory is asked about the account's stored name both times, never the claim."""
    store = await MessageStore.open(":memory:")
    try:
        ldap = _FakeLdap()
        service = await _service(store, rsa_key, ldap=ldap, bind="S-1-alice")
        first = await _oidc_login(
            service, monkeypatch, rsa_key, sub="S-1-alice", preferred_username="jdoe@corp.example"
        )
        second = await _oidc_login(
            service, monkeypatch, rsa_key, sub="S-1-alice", preferred_username="jsmith@corp.example"
        )

        assert first.ok and second.ok
        assert first.identity is not None and second.identity is not None
        assert first.identity.user_id == second.identity.user_id
        assert ldap.resolved == ["jdoe", "jdoe"]
        assert await store.get_user_by_username("jsmith") is None, "no forked row"
    finally:
        await store.close()


class _CapturingNotifier:
    """Captures security events instead of emailing (BACKLOG #1248)."""

    def __init__(self) -> None:
        self.events: list[Any] = []

    async def notify(self, event: Any) -> None:
        self.events.append(event)


async def test_the_admin_bind_audits_and_notifies_and_a_login_never_does(
    rsa_key: rsa.RSAPrivateKey, monkeypatch: pytest.MonkeyPatch
) -> None:
    """BACKLOG #1248 moved with the binding. Binding decides WHO MAY SIGN IN as the account, so the
    admin bind emits an audit row naming the actor and the exact ``sub``, and notifies the holder
    naming the issuer only.

    THE TWO LOGINS ARE THE CONTROL. Neither may add a binding row or a notice: a login that did would
    be binding on presentation, which is the path ADR 0184 closes."""
    store = await MessageStore.open(":memory:")
    try:
        notifier = _CapturingNotifier()
        service = await _service(store, rsa_key, notifier=notifier, bind=None)
        user_id = await _bind(service, store, "S-1-alice")

        rows = await _audit_rows(store, "auth.federated_subject_bound")
        assert len(rows) == 1
        assert rows[0]["actor"] == "admin", "the row must name who bound, not whose"
        assert json.loads(rows[0]["detail"]) == {
            "user_id": user_id,
            "username": "jdoe",
            "issuer": "https://idp.example",
            "subject": "S-1-alice",
        }
        bound = [e for e in notifier.events if e.event_type == FEDERATED_IDENTITY_BOUND]
        assert len(bound) == 1 and bound[0].username == "jdoe"
        assert "S-1-alice" not in str(bound[0].detail)

        for _ in range(2):
            assert (await _oidc_login(service, monkeypatch, rsa_key, sub="S-1-alice")).ok
        assert len(await _audit_rows(store, "auth.federated_subject_bound")) == 1
        assert len([e for e in notifier.events if e.event_type == FEDERATED_IDENTITY_BOUND]) == 1
    finally:
        await store.close()


async def test_one_subject_cannot_be_bound_to_two_accounts(
    rsa_key: rsa.RSAPrivateKey,
) -> None:
    """BACKLOG #1256's rule, at the one path that binds now. A second account asking for a subject
    another account holds is refused, not moved, and neither account changes."""
    store = await MessageStore.open(":memory:")
    try:
        service = await _service(store, rsa_key, bind="S-1-alice")
        other_id = uuid4().hex
        await store.create_user(user_id=other_id, username="bsmith", auth_provider="ad")

        with pytest.raises(FederatedSubjectHeld):
            await service.bind_federated_subject(other_id, "S-1-alice", actor="admin")

        holder = await store.get_user_by_federated_subject("https://idp.example", "S-1-alice")
        assert holder is not None and holder.username == "jdoe"
        other = await store.get_user(other_id)
        assert other is not None and other.oidc_subject is None
    finally:
        await store.close()


async def test_a_directory_answer_leading_to_another_row_is_refused_before_roles(
    rsa_key: rsa.RSAPrivateKey, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The check left inside ``_complete_ad_login``. The pair selects ``jdoe``, but the directory,
    asked about ``jdoe``, answers with the ``bsmith`` object, whose mirror row exists unbound. That row
    must not be signed in, and must not take the session or any role.

    It is refused as ``federated_subject_already_bound``: the subject is held by a different account
    than the one this login reached."""
    store = await MessageStore.open(":memory:")
    try:
        ldap = _FakeLdap(by_username={"jdoe": OTHER})
        service = await _service(store, rsa_key, ldap=ldap, bind="S-1-alice")
        other_id = uuid4().hex
        await store.create_user(user_id=other_id, username="bsmith", auth_provider="ad")

        out = await _oidc_login(service, monkeypatch, rsa_key, sub="S-1-alice")

        assert not out.ok and out.token is None
        assert out.reason == "federated_subject_already_bound"
        assert await store.list_sessions(other_id) == []
        assert await store.get_user_role_ids(other_id) == []
        other = await store.get_user(other_id)
        assert other is not None and other.oidc_subject is None, "the reached row took the pair"
    finally:
        await store.close()


async def test_an_unbind_landing_mid_login_is_refused_and_binds_nothing(
    rsa_key: rsa.RSAPrivateKey, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The second bind site. The pair selects ``jdoe``; an administrator unbinds ``jdoe`` after that
    read and before the login reaches the row.

    That is exactly the state in which ``_complete_ad_login`` used to write the presented pair onto
    the row. It must refuse instead, as first contact is refused, and leave the row unbound: an
    unbind that the next login quietly undoes is not an unbind.

    The wedge sits on the pair lookup's SECOND call. The first is the selection in
    ``authenticate_oidc``; the unbind lands straight after it returns, so the row the login then
    reaches has no binding.
    """
    store = await MessageStore.open(":memory:")
    try:
        service = await _service(store, rsa_key, bind="S-1-alice")
        account = await store.get_user_by_username("jdoe")
        assert account is not None

        real_lookup = store.get_user_by_federated_subject
        fired = False

        async def unbinding_lookup(issuer: str, subject: str) -> Any:
            nonlocal fired
            found = await real_lookup(issuer, subject)
            if not fired:
                fired = True
                await service.unbind_federated_subject(account.id, actor="admin")
            return found

        monkeypatch.setattr(store, "get_user_by_federated_subject", unbinding_lookup)
        out = await _oidc_login(service, monkeypatch, rsa_key, sub="S-1-alice")
        monkeypatch.undo()

        assert fired, "the wedge never ran, so nothing raced this login"
        assert not out.ok and out.token is None
        assert out.reason == FEDERATED_SUBJECT_NOT_BOUND
        after = await store.get_user(account.id)
        assert after is not None
        assert (after.oidc_issuer, after.oidc_subject) == (None, None), "the login re-bound it"
        assert await store.list_sessions(account.id) == []
    finally:
        await store.close()


# --- AC-6: the session is capped at the verified id_token exp ---------------------------------------


async def test_session_is_capped_at_the_verified_id_token_exp(
    rsa_key: rsa.RSAPrivateKey, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = await MessageStore.open(":memory:")
    try:
        service = await _service(store, rsa_key)
        # Far shorter than the 12h local absolute lifetime, so the cap must bind.
        exp = time.time() + 300
        _stub_exchange(monkeypatch, _mint(rsa_key, _claims(exp=exp)))

        out = await service.authenticate_oidc(
            AUTH_CODE, _flow(), redirect_uri="https://ops.example/ui/oidc/callback"
        )
        assert out.ok and out.token is not None
        session = await store.get_session(hash_token(out.token))
        assert session is not None
        assert session.expires_at == pytest.approx(exp, abs=1)
    finally:
        await store.close()


async def test_a_long_lived_token_does_not_extend_the_local_lifetime(
    rsa_key: rsa.RSAPrivateKey, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The cap is a min(), never a max(): an IdP asserting a 30-day exp must not buy a 30-day session."""
    store = await MessageStore.open(":memory:")
    try:
        service = await _service(store, rsa_key)
        _stub_exchange(monkeypatch, _mint(rsa_key, _claims(exp=time.time() + 30 * 86400)))

        out = await service.authenticate_oidc(
            AUTH_CODE, _flow(), redirect_uri="https://ops.example/ui/oidc/callback"
        )
        assert out.ok and out.token is not None
        session = await store.get_session(hash_token(out.token))
        assert session is not None
        absolute = AuthSettings().session_absolute_hours * 3600
        assert session.expires_at - session.created_at == pytest.approx(absolute, abs=2)
    finally:
        await store.close()


async def test_token_inside_the_skew_grace_never_mints_a_dead_session(
    rsa_key: rsa.RSAPrivateKey, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The ladder accepts an exp up to clock_skew_seconds in the PAST. Capping to it would store an
    expires_at already behind now, so the user would 'log in' and be revoked on the next request with
    no audited reason. Refuse loudly instead."""
    store = await MessageStore.open(":memory:")
    try:
        service = await _service(store, rsa_key)
        _stub_exchange(monkeypatch, _mint(rsa_key, _claims(exp=time.time() - 10)))

        out = await service.authenticate_oidc(
            AUTH_CODE, _flow(), redirect_uri="https://ops.example/ui/oidc/callback"
        )
        assert not out.ok
        assert out.token is None
        rows = await _audit_rows(store, "auth.login_failed")
        assert any('"reason": "expired"' in (r["detail"] or "") for r in rows)
    finally:
        await store.close()


# --- AC-8: degradation is isolated and recovery needs no restart ------------------------------------


async def test_unreachable_idp_degrades_then_recovers_without_a_restart(
    rsa_key: rsa.RSAPrivateKey, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A raw URLError escapes validate_id_token (JwksCache does not wrap its injected fetch), so a
    narrow `except JwksError` would surface an unhandled 500. It must become a degraded login — and
    the next success must clear the flag on the SAME service instance."""
    import urllib.error

    store = await MessageStore.open(":memory:")
    try:
        service = await _service(store, rsa_key)
        assert service.oidc_available is True

        def boom(**kwargs: Any) -> Mapping[str, object]:
            raise urllib.error.URLError("idp down")

        monkeypatch.setattr(oidc, "exchange_code", boom)
        out = await service.authenticate_oidc(
            AUTH_CODE, _flow(), redirect_uri="https://ops.example/ui/oidc/callback"
        )
        assert not out.ok and out.token is None
        assert service.oidc_available is False
        errors = await _audit_rows(store, "auth.login_error")
        assert len(errors) == 1
        assert '"mech": "oidc"' in (errors[0]["detail"] or "")

        # Same instance, no restart: the IdP returns and the next login clears the flag (AC-8).
        _stub_exchange(monkeypatch, _mint(rsa_key, _claims()))
        recovered = await service.authenticate_oidc(
            AUTH_CODE, _flow(), redirect_uri="https://ops.example/ui/oidc/callback"
        )
        assert recovered.ok
        assert service.oidc_available is True
    finally:
        await store.close()


async def test_a_non_http_response_degrades_instead_of_escaping(
    rsa_key: rsa.RSAPrivateKey, monkeypatch: pytest.MonkeyPatch
) -> None:
    """http.client.HTTPException is neither an OSError nor a ValueError. A proxy answering the token
    POST with a non-HTTP status line raises BadStatusLine, which must not escape as an unhandled 500
    that renders the IdP's bytes into the traceback log and leaves oidc_available stale."""
    import http.client

    store = await MessageStore.open(":memory:")
    try:
        service = await _service(store, rsa_key)

        def bad_status(**kwargs: Any) -> Mapping[str, object]:
            raise http.client.BadStatusLine("<html>IdP proxy maintenance page</html>")

        monkeypatch.setattr(oidc, "exchange_code", bad_status)
        out = await service.authenticate_oidc(
            AUTH_CODE, _flow(), redirect_uri="https://ops.example/ui/oidc/callback"
        )
        assert not out.ok and out.token is None
        assert service.oidc_available is False
        errors = await _audit_rows(store, "auth.login_error")
        assert len(errors) == 1
        # The IdP's arbitrary text must not reach the audit row — only the exception type name.
        assert "maintenance page" not in (errors[0]["detail"] or "")
        assert "BadStatusLine" in (errors[0]["detail"] or "")
    finally:
        await store.close()


async def test_unreachable_idp_does_not_affect_local_or_ad_login(
    rsa_key: rsa.RSAPrivateKey, monkeypatch: pytest.MonkeyPatch
) -> None:
    import urllib.error

    store = await MessageStore.open(":memory:")
    try:
        service = await _service(store, rsa_key)
        await service.create_local_user(
            username="alice",
            password="Sup3rSecret!!",
            display_name=None,
            email=None,
            roles=[],
            actor="test",
        )

        def boom(**kwargs: Any) -> Mapping[str, object]:
            raise urllib.error.URLError("idp down")

        monkeypatch.setattr(oidc, "exchange_code", boom)
        assert not (
            await service.authenticate_oidc(
                AUTH_CODE, _flow(), redirect_uri="https://ops.example/ui/oidc/callback"
            )
        ).ok

        assert (await service.login("alice", "Sup3rSecret!!")).ok
        # The directory path is unaffected by the dead IdP. Minted through _complete_ad_login rather
        # than an AD password login, which is retired (BACKLOG #1137) -- this is the tail Kerberos
        # reaches, so it is the AD login that still exists.
        assert (await service._complete_ad_login(PRINCIPAL, None, mfa_verified=True)).ok
    finally:
        await store.close()


async def test_construction_succeeds_with_an_unreachable_idp() -> None:
    """Wiring must do NO network I/O: an engine whose IdP is down still starts and serves local login."""
    store = await MessageStore.open(":memory:")
    try:
        service = AuthService(store, _settings(), ldap=_FakeLdap())  # type: ignore[arg-type]
        assert service.oidc_enabled is True
        await service.initialize()
        await service.create_local_user(
            username="alice",
            password="Sup3rSecret!!",
            display_name=None,
            email=None,
            roles=[],
            actor="test",
        )
        assert (await service.login("alice", "Sup3rSecret!!")).ok
    finally:
        await store.close()


async def test_oidc_is_off_and_inert_by_default() -> None:
    store = await MessageStore.open(":memory:")
    try:
        service = AuthService(store, AuthSettings())
        assert service.oidc_enabled is False
        assert service.oidc_available is False
        out = await service.authenticate_oidc(
            AUTH_CODE, _flow(), redirect_uri="https://ops.example/ui/oidc/callback"
        )
        assert not out.ok
        rows = await _audit_rows(store, "auth.login_failed")
        assert any('"reason": "not_configured"' in (r["detail"] or "") for r in rows)
    finally:
        await store.close()


# --- hybrid-only: no on-prem object means no login --------------------------------------------------


async def test_principal_absent_from_the_directory_is_refused(
    rsa_key: rsa.RSAPrivateKey, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = await MessageStore.open(":memory:")
    try:
        service = await _service(store, rsa_key, ldap=_FakeLdap(principal=None))
        _stub_exchange(monkeypatch, _mint(rsa_key, _claims()))

        out = await service.authenticate_oidc(
            AUTH_CODE, _flow(), redirect_uri="https://ops.example/ui/oidc/callback"
        )
        assert not out.ok and out.token is None
        rows = await _audit_rows(store, "auth.login_failed")
        assert any('"reason": "not_in_directory"' in (r["detail"] or "") for r in rows)
    finally:
        await store.close()


async def test_mfa_claim_gate_refuses_with_a_closed_set_slug(
    rsa_key: rsa.RSAPrivateKey, monkeypatch: pytest.MonkeyPatch
) -> None:
    """AC-5 at the service layer: the reason reaching the audit is the ladder's closed-set slug."""
    store = await MessageStore.open(":memory:")
    try:
        service = await _service(store, rsa_key)
        _stub_exchange(monkeypatch, _mint(rsa_key, _claims(amr=["pwd"])))

        out = await service.authenticate_oidc(
            AUTH_CODE, _flow(), redirect_uri="https://ops.example/ui/oidc/callback"
        )
        assert not out.ok
        rows = await _audit_rows(store, "auth.login_failed")
        assert any('"reason": "mfa_claim_missing"' in (r["detail"] or "") for r in rows)
    finally:
        await store.close()


# --- the audit row + AC-10 --------------------------------------------------------------------------


async def test_success_audit_carries_mech_and_evidence(
    rsa_key: rsa.RSAPrivateKey, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = await MessageStore.open(":memory:")
    try:
        service = await _service(store, rsa_key)
        _stub_exchange(monkeypatch, _mint(rsa_key, _claims()))

        assert (
            await service.authenticate_oidc(
                AUTH_CODE, _flow(), redirect_uri="https://ops.example/ui/oidc/callback"
            )
        ).ok
        rows = await _audit_rows(store, "auth.login_success")
        assert len(rows) == 1
        detail = json.loads(rows[0]["detail"] or "{}")
        assert detail["provider"] == "ad"
        assert detail["mech"] == "oidc"
        assert detail["evidence"]["sub"] == "S-1-5-21-federated"
        assert "mfa" in detail["evidence"]["amr"]
        assert detail["roles"] == ["operator"]
    finally:
        await store.close()


async def test_no_secret_code_or_token_reaches_the_logs_or_the_audit(
    rsa_key: rsa.RSAPrivateKey, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """AC-10. The ADR forbids logging the client secret, the authorization code, or any token."""
    store = await MessageStore.open(":memory:")
    try:
        service = await _service(store, rsa_key)
        id_token = _mint(rsa_key, _claims())
        _stub_exchange(monkeypatch, id_token)

        with caplog.at_level(logging.DEBUG):
            out = await service.authenticate_oidc(
                AUTH_CODE, _flow(), redirect_uri="https://ops.example/ui/oidc/callback"
            )
        assert out.ok and out.token is not None

        haystack = "\n".join(r.getMessage() for r in caplog.records)
        haystack += "\n" + "\n".join(str(a["detail"] or "") for a in await store.list_audit())
        for secret in (CLIENT_SECRET, AUTH_CODE, id_token, out.token, "at-should-never-be-stored"):
            assert secret not in haystack
    finally:
        await store.close()


# --- BACKLOG #1637 / #1638: the OIDC leg of the mirror-row eligibility gate ------------------------


async def test_a_disabled_mirror_row_does_not_complete_a_federated_login(
    rsa_key: rsa.RSAPrivateKey, monkeypatch: pytest.MonkeyPatch
) -> None:
    """BACKLOG #1637's OIDC leg, driven end to end through ``authenticate_oidc``.

    The eligibility gate lives on the shared ``_complete_ad_login`` path, exercised directly in
    ``test_ad_directory_identity.py``. This test is what turns "the shared path refuses" into "the
    FEDERATED pathway refuses": everything above the gate -- the token exchange, the signature and
    nonce verification, the directory resolve -- succeeds, and the login still does not complete.

    The success-audit count is the assertion that matters. A refusal that still wrote
    ``auth.login_success`` would leave an operator reading a completed sign-in for a disabled
    account, which is the defect as the ledger row states it.
    """
    store = await MessageStore.open(":memory:")
    try:
        service = await _service(store, rsa_key)
        first = await _oidc_login(service, monkeypatch, rsa_key)
        assert first.ok and first.identity is not None
        await store.set_user_disabled(first.identity.user_id, disabled=True)

        out = await _oidc_login(service, monkeypatch, rsa_key)
        assert not out.ok, "a disabled mirror row completed a federated login"
        assert out.reason == "disabled"
        assert out.token is None
        assert len(await _audit_rows(store, "auth.login_success")) == 1, (
            "the refused federated login wrote a second auth.login_success row"
        )
        rows = await _audit_rows(store, "auth.login_failed")
        assert any('"reason": "disabled"' in (r["detail"] or "") for r in rows)
    finally:
        await store.close()


async def test_a_locked_mirror_row_does_not_complete_a_federated_login(
    rsa_key: rsa.RSAPrivateKey, monkeypatch: pytest.MonkeyPatch
) -> None:
    """BACKLOG #1638's OIDC leg: the re-login that used to clear a second-factor lock.

    Both halves again, because a fix that adds only the refusal leaves the clearing write in place on
    every path that still completes.
    """
    store = await MessageStore.open(":memory:")
    try:
        service = await _service(store, rsa_key)
        first = await _oidc_login(service, monkeypatch, rsa_key)
        assert first.ok and first.identity is not None
        user_id = first.identity.user_id
        locked_until = time.time() + 900.0
        await store.record_login_failure(user_id, failed_attempts=5, locked_until=locked_until)

        out = await _oidc_login(service, monkeypatch, rsa_key)
        assert not out.ok and out.reason == "locked"
        row = await store.get_user(user_id)
        assert row is not None
        assert row.locked_until == pytest.approx(locked_until), "the federated re-login cleared it"
        assert row.failed_attempts == 5
    finally:
        await store.close()


def test_the_browser_layer_gives_a_refused_account_no_distinguishing_code() -> None:
    """The DELIBERATE OMISSION, pinned so nobody "completes" the map (BACKLOG #1637 / #1638).

    ``disabled`` and ``locked`` describe the state of an account the visitor has not authenticated
    as. A distinct login-page code would confirm to an unauthenticated caller that the account exists
    and say which of the two states it is in, so both slugs are left out of ``_REASON_TO_CODE`` and
    collapse to the generic ``oidc_failed``.

    Pinned as a test rather than by comment alone, because the omission looks exactly like an
    oversight to the next reader of that map. The operator loses nothing: the precise reason is on
    the ``auth.login_failed`` audit row either way.
    """
    from messagefoundry_webconsole.routes.oidc import _REASON_TO_CODE

    for slug in ("disabled", "locked"):
        assert slug not in _REASON_TO_CODE, (
            f"{slug!r} gained a distinguishing login-page code; that tells an unauthenticated "
            "caller the account exists"
        )
        assert _REASON_TO_CODE.get(slug, "oidc_failed") == "oidc_failed"


async def test_a_pair_matching_only_under_a_case_blind_collation_selects_nothing(
    rsa_key: rsa.RSAPrivateKey, monkeypatch: pytest.MonkeyPatch
) -> None:
    """SQL Server compares the federated columns under the database default, usually
    case-insensitive, so its lookup for ``s-1-abc`` returns the row bound to ``S-1-ABC``. The lookup
    now SELECTS the account, so the service re-checks the pair byte for byte.

    SQLite is case-sensitive, so the case-blind lookup is modelled by wrapping it. The CONTROL is the
    exact-case login, which the same wrapped lookup lets through.
    """
    store = await MessageStore.open(":memory:")
    try:
        service = await _service(store, rsa_key, bind="S-1-ABC")
        real = store.get_user_by_federated_subject

        async def case_blind(issuer: str, subject: str) -> Any:
            for u in await store.list_users():
                if u.oidc_issuer == issuer and (u.oidc_subject or "").lower() == subject.lower():
                    return u
            return await real(issuer, subject)

        monkeypatch.setattr(store, "get_user_by_federated_subject", case_blind)
        other_case = await _oidc_login(service, monkeypatch, rsa_key, sub="s-1-abc")
        assert not other_case.ok and other_case.reason == FEDERATED_SUBJECT_NOT_BOUND
        exact = await _oidc_login(service, monkeypatch, rsa_key, sub="S-1-ABC")
        assert exact.ok, exact.reason
    finally:
        await store.close()


async def test_a_refusal_after_selection_is_filed_under_the_selected_account(
    rsa_key: rsa.RSAPrivateKey, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Once the pair has chosen ``jdoe``, a later refusal is about ``jdoe``, whatever name the token
    claimed. Filing it under the claimed name would put it in a stranger's security-events feed."""
    store = await MessageStore.open(":memory:")
    try:
        service = await _service(store, rsa_key, ldap=_FakeLdap(principal=None), bind="S-1-alice")
        out = await _oidc_login(
            service, monkeypatch, rsa_key, sub="S-1-alice", preferred_username="bsmith@corp.example"
        )
        assert not out.ok and out.reason == "not_in_directory"
        [row] = [
            r
            for r in await _audit_rows(store, "auth.login_failed")
            if "not_in_directory" in (r["detail"] or "")
        ]
        assert row["actor"] == "jdoe"
    finally:
        await store.close()


async def test_a_rebind_racing_another_bind_is_refused_and_audits_what_it_removed(
    rsa_key: rsa.RSAPrivateKey,
) -> None:
    """The admin bind clears and then sets, in two transactions. A second bind landing between them
    must not be overwritten, and the binding this call already removed must still be recorded.

    The wedge runs the second bind straight after the clear. The set is conditional on the row being
    unbound, so it writes nothing; the call is refused; the account keeps the SECOND bind's pair;
    and the first binding's removal is audited and its holder told.
    """
    store = await MessageStore.open(":memory:")
    try:
        notifier = _CapturingNotifier()
        service = await _service(store, rsa_key, notifier=notifier, bind="S-1-first")
        account = await store.get_user_by_username("jdoe")
        assert account is not None
        real_clear = store.clear_user_federated_subject

        async def clear_then_another_bind(user_id: str, **kw: Any) -> Any:
            outcome = await real_clear(user_id, **kw)
            await store.set_user_federated_subject(user_id, "https://idp.example", "S-1-other")
            return outcome

        store.clear_user_federated_subject = clear_then_another_bind  # type: ignore[method-assign]
        try:
            with pytest.raises(FederatedSubjectHeld, match="while this one ran"):
                await service.bind_federated_subject(account.id, "S-1-mine", actor="admin")
        finally:
            del store.clear_user_federated_subject

        after = await store.get_user(account.id)
        assert after is not None and after.oidc_subject == "S-1-other", "the other bind was lost"
        [unbound] = await _audit_rows(store, "auth.federated_subject_unbound")
        assert json.loads(unbound["detail"])["subject"] == "S-1-first"
        assert await _audit_rows(store, "auth.federated_subject_rebound") == []
        assert any(e.event_type == FEDERATED_IDENTITY_UNBOUND for e in notifier.events)
    finally:
        await store.close()


async def test_an_unbind_tells_the_holder(rsa_key: rsa.RSAPrivateKey) -> None:
    """ASVS 6.3.7, as on the bind: the holder's federated sign-in stopped working and their sessions
    ended. The notice names the issuer, never the subject."""
    store = await MessageStore.open(":memory:")
    try:
        notifier = _CapturingNotifier()
        service = await _service(store, rsa_key, notifier=notifier, bind="S-1-alice")
        account = await store.get_user_by_username("jdoe")
        assert account is not None
        await service.unbind_federated_subject(account.id, actor="admin")
        [notice] = [e for e in notifier.events if e.event_type == FEDERATED_IDENTITY_UNBOUND]
        assert notice.username == "jdoe"
        assert "S-1-alice" not in str(notice.detail)
    finally:
        await store.close()
