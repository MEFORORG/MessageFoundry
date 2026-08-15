# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""``AuthService.authenticate_oidc`` — the federated login path (ADR 0142, BACKLOG #274).

Hermetic: no network. The ``id_token`` is minted with the shipped ``CompactJwtSigner`` over a
throwaway key, the JWKS is served from memory, and the token-endpoint exchange is stubbed at the
module seam ``auth/service.py`` actually calls (``oidc.exchange_code``).

These cover the acceptance criteria that live in the service rather than the ladder: AC-2 (roles come
from LDAP, never a token claim), AC-6 (the session is capped at the verified ``exp``), AC-8
(an unreachable IdP degrades and recovers without a restart) and AC-10 (no secret, code or token in
the logs).
"""

from __future__ import annotations

import json
import logging
import time
import urllib.request
from collections.abc import Mapping
from typing import Any

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from messagefoundry.auth import oidc
from messagefoundry.auth.identity import AuthProvider
from messagefoundry.auth.ldap import AdPrincipal
from messagefoundry.auth.service import AuthService, LoginOutcome
from messagefoundry.auth.tokens import hash_token
from messagefoundry.config.models import SignatureAlgorithm
from messagefoundry.config.settings import AuthSettings
from messagefoundry.store.store import MessageStore
from messagefoundry.transports.signing import CompactJwtSigner

CLIENT_SECRET = "s3cr3t-client-value"
AUTH_CODE = "authz-code-abcdef"
NONCE = "n-oidc-1"

# --- helpers ---------------------------------------------------------------------------------------


@pytest.fixture(scope="module")
def rsa_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


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
    signer = CompactJwtSigner(private_key=pem, algorithm=SignatureAlgorithm.RS256, key_id=kid)
    return signer.sign(dict(claims))


def _claims(**over: Any) -> dict[str, Any]:
    now = time.time()
    base: dict[str, Any] = {
        "iss": "https://idp.example",
        "aud": "mefor-console",
        "sub": "S-1-5-21-federated",
        "exp": now + 3600,
        "iat": now,
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

    def resolve_principal(self, username: str) -> AdPrincipal | None:
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
    **over: Any,
) -> AuthService:
    service = AuthService(store, _settings(**over), ldap=ldap or _FakeLdap())  # type: ignore[arg-type]
    # Swap the real JWKS cache for an in-memory one. The service builds a genuine CA-verifying opener
    # at construction (which opens no socket), so this only replaces the fetch, not the policy.
    service._oidc_jwks = oidc.JwksCache(lambda: _jwks_bytes(rsa_key))
    await service.initialize()
    await service.set_ad_group_map([("cn=mf-ops,dc=corp,dc=example", "operator")], actor="admin")
    return service


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
        ca_cert_file: str | None, *, pin: str | None = None, enforcing: bool = True
    ) -> urllib.request.OpenerDirector:
        calls.append({"ca": ca_cert_file, "pin": pin, "enforcing": enforcing})
        return urllib.request.build_opener()

    monkeypatch.setattr("messagefoundry.auth.service.build_idp_opener", spy)
    settings = _settings(
        oidc_tls_ca_cert_file="C:/anchors/idp-ca.pem", oidc_tls_ca_cert_pin="ab" * 32
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


# --- #1015: the account is keyed on (issuer, sub), never the reassignable username -----------------


async def test_changed_subject_same_username_does_not_take_over(
    rsa_key: rsa.RSAPrivateKey, monkeypatch: pytest.MonkeyPatch
) -> None:
    """BACKLOG #1015, the P1 regression. A first federated login binds the local account to its verified
    subject. When the IdP later REASSIGNS the username to a different person (a new ``sub``, a normal IdP
    lifecycle operation), that new subject must NOT be handed the prior holder's account — that is account
    takeover with no credential compromise. The login is refused with a closed-set audit reason and the
    bound account is left untouched."""
    store = await MessageStore.open(":memory:")
    try:
        service = await _service(store, rsa_key)
        first = await _oidc_login(service, monkeypatch, rsa_key, sub="S-1-alice")
        assert first.ok and first.identity is not None
        account = await store.get_user_by_username("jdoe")
        assert account is not None
        assert account.oidc_subject == "S-1-alice"  # bound on the first federated login

        # The username is reassigned to a new person (new sub); they complete a federated login.
        second = await _oidc_login(service, monkeypatch, rsa_key, sub="S-1-bob")
        assert not second.ok and second.token is None
        assert second.reason == "federated_subject_conflict"

        after = await store.get_user_by_username("jdoe")
        assert after is not None
        assert after.id == account.id  # the same account, not taken over
        assert after.oidc_subject == "S-1-alice"  # still bound to the ORIGINAL subject
        rows = await _audit_rows(store, "auth.login_failed")
        assert any('"reason": "federated_subject_conflict"' in (r["detail"] or "") for r in rows)
    finally:
        await store.close()


async def test_same_subject_changed_username_is_same_account(
    rsa_key: rsa.RSAPrivateKey, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The converse of the takeover case: the SAME person (same ``sub``) whose display username changed
    but still resolves to the same on-prem AD object must land on the SAME local account, with the
    display refreshed — not be refused and not fork a second row."""
    store = await MessageStore.open(":memory:")
    try:
        renamed = AdPrincipal(
            username="jdoe",  # same AD object (stable sAMAccountName), new display name
            display_name="Jane Doe-Smith",
            email="jane@corp.example",
            dn="CN=jdoe,DC=corp,DC=example",
            groups=PRINCIPAL.groups,
        )
        ldap = _FakeLdap(by_username={"jdoe": PRINCIPAL, "jsmith": renamed})
        service = await _service(store, rsa_key, ldap=ldap)

        first = await _oidc_login(
            service, monkeypatch, rsa_key, sub="S-1-alice", preferred_username="jdoe@corp.example"
        )
        assert first.ok
        account = await store.get_user_by_username("jdoe")
        assert account is not None
        assert account.oidc_subject == "S-1-alice"
        assert account.display_name == "J Doe"

        # Same subject, a changed preferred_username that AD resolves to the same object.
        second = await _oidc_login(
            service, monkeypatch, rsa_key, sub="S-1-alice", preferred_username="jsmith@corp.example"
        )
        assert second.ok and second.identity is not None
        after = await store.get_user_by_username("jdoe")
        assert after is not None
        assert after.id == account.id  # same local account
        assert after.oidc_subject == "S-1-alice"  # binding stable
        assert after.display_name == "Jane Doe-Smith"  # refreshed from the resolved AD object
        assert await store.get_user_by_username("jsmith") is None  # no forked row
    finally:
        await store.close()


async def test_username_reused_across_two_subjects_does_not_collide(
    rsa_key: rsa.RSAPrivateKey, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Two distinct subjects present the same display username at different times. The second must be
    refused cleanly (no unhandled exception, a closed-set audit reason) and must not share the first
    subject's account or receive a session."""
    store = await MessageStore.open(":memory:")
    try:
        service = await _service(store, rsa_key)
        first = await _oidc_login(service, monkeypatch, rsa_key, sub="S-1-alice")
        assert first.ok

        second = await _oidc_login(service, monkeypatch, rsa_key, sub="S-1-carol")
        assert not second.ok and second.token is None
        assert second.reason == "federated_subject_conflict"

        account = await store.get_user_by_username("jdoe")
        assert account is not None
        assert account.oidc_subject == "S-1-alice"  # still the first subject's account
        assert len([u for u in await store.list_users() if u.username == "jdoe"]) == 1
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
        assert (await service.login("jdoe", "pw", provider=AuthProvider.AD)).ok
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


async def test_binding_a_federated_identity_is_audited_and_notified_ONCE(
    rsa_key: rsa.RSAPrivateKey, monkeypatch: pytest.MonkeyPatch
) -> None:
    """BACKLOG #1248. Binding an external identity is the most takeover-relevant write there is --
    after it, whoever controls the IdP subject controls the account -- and it was SILENT, while the
    role resync a few lines below it emitted both an audit row and a notification for a strictly less
    sensitive event. A role change alters what an account MAY DO; a binding alters WHO IT IS.

    THE SECOND LOGIN IS THE CONTROL AND IT CARRIES THE TEST. A bare "an audit row exists after a
    federated login" would pass against a writer that emits on EVERY login, which is a different and
    much noisier behaviour -- and it would also pass if the row belonged to some neighbouring event.
    Asserting the count is still ONE after a second successful login with the SAME subject pins the
    row to the BINDING rather than to the sign-in, which is the property the item is about.

    THE SUBJECT MUST NOT APPEAR. The issuer names which IdP was bound, which is the operator-actionable
    half; the `sub` is a stable per-user directory identifier and does not belong in a row read far
    more widely than the account it describes.
    """
    store = await MessageStore.open(":memory:")
    try:
        service = await _service(store, rsa_key)

        _stub_exchange(monkeypatch, _mint(rsa_key, _claims()))
        assert (
            await service.authenticate_oidc(
                AUTH_CODE, _flow(), redirect_uri="https://ops.example/ui/oidc/callback"
            )
        ).ok

        rows = await _audit_rows(store, "auth.federated_identity_bound")
        # The message covers BOTH directions deliberately: 0 means the binding was silent, and >1
        # means it is keyed on something firing more than once per binding. An earlier draft said
        # only "was not audited", which is FALSE in the over-firing case -- and a mutation that
        # duplicated the audit was caught by this line reporting exactly that wrong reason.
        assert len(rows) == 1, f"expected exactly one binding audit row, got {len(rows)}"
        detail = json.loads(rows[0]["detail"] or "{}")
        assert detail["provider"] == "oidc"
        assert detail["issuer"] == "https://idp.example"
        assert "S-1-5-21-federated" not in (rows[0]["detail"] or ""), (
            "the OIDC subject reached the audit row; the issuer is the actionable half"
        )

        # CONTROL: sign in again as the SAME subject. The binding already matches, so it is left
        # untouched -- and therefore must not be re-audited or re-notified.
        _stub_exchange(monkeypatch, _mint(rsa_key, _claims()))
        assert (
            await service.authenticate_oidc(
                AUTH_CODE, _flow(), redirect_uri="https://ops.example/ui/oidc/callback"
            )
        ).ok
        again = await _audit_rows(store, "auth.federated_identity_bound")
        assert len(again) == 1, (
            f"the binding audit fired {len(again)} times across two logins -- it is keyed on the "
            f"sign-in rather than on the binding"
        )
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
