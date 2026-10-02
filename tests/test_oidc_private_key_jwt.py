# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""``private_key_jwt`` client authentication on the OIDC token request (BACKLOG #296).

Hermetic: every key is generated here, no socket is opened, and the token endpoint is a fake opener
that records the request. What is pinned:

* the assertion's claims, and that its signature verifies with the public half of the configured key;
* that the token request under ``private_key_jwt`` carries the assertion and no ``client_secret``;
* that the default ``client_secret_post`` request is unchanged;
* that a bad configuration is refused at load or at service construction, before any sign-in.
"""

from __future__ import annotations

import base64
import json
import logging
import time
import urllib.parse
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from pydantic import ValidationError

from messagefoundry.auth import oidc
from messagefoundry.auth.oidc.client_auth import (
    CLIENT_ASSERTION_TTL_SECONDS,
    ClientSecretPost,
    PrivateKeyJwtClientAuth,
    client_auth_from_settings,
)
from messagefoundry.auth.service import AuthService
from messagefoundry.config.models import SignatureAlgorithm
from messagefoundry.config.settings import AuthSettings, ServiceSettings, _warn_file_secrets
from messagefoundry.config.static_credentials import resolved_secret_refs, static_credential_hops
from messagefoundry.store.store import MessageStore
from messagefoundry.transports.signing import (
    CLIENT_ASSERTION_TYPE,
    SigningError,
    client_assertion_claims,
    verify_compact_jws,
)
from messagefoundry.verify.federation import run_federation_checks
from messagefoundry.verify.model import Status

TOKEN_ENDPOINT = "https://idp.example/token"
ISSUER = "https://idp.example"
CLIENT_ID = "mefor-console"
SECRET = "s3cr3t-client-value"
#: Split so a secret scanner does not read the fake, keyless PEM bodies below as a key.
_BEGIN = "-----BEGIN " + "PRIVATE KEY-----"


def _pem(key: rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey) -> str:
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("ascii")


@pytest.fixture(scope="module")
def ec_key() -> ec.EllipticCurvePrivateKey:
    return ec.generate_private_key(ec.SECP256R1())


@pytest.fixture(scope="module")
def rsa_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=3072)


def _auth(**over: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "ad_enabled": True,
        "ad_server": "ldaps://dc.corp.example",
        "ad_user_search_base": "DC=corp,DC=example",
        "ad_bind_dn": "CN=svc,DC=corp,DC=example",
        "ad_bind_password": "x",
        "ad_domain": "corp.example",
        "oidc_enabled": True,
        "oidc_issuer": ISSUER,
        "oidc_client_id": CLIENT_ID,
        "oidc_authorization_endpoint": "https://idp.example/authorize",
        "oidc_token_endpoint": TOKEN_ENDPOINT,
        "oidc_jwks_uri": "https://idp.example/jwks",
        "oidc_allowed_endpoints": ["idp.example"],
        "oidc_callback_min_elapsed_seconds": 0,
    }
    base.update(over)
    return base


def _pkjwt(key_pem: str, **over: Any) -> dict[str, Any]:
    fields: dict[str, Any] = {
        "oidc_token_endpoint_auth_method": "private_key_jwt",
        "oidc_client_private_key": key_pem,
        "oidc_client_assertion_algorithm": "ES256",
    }
    return _auth(**{**fields, **over})


class _FakeResp:
    def __init__(self, body: bytes) -> None:
        self._body = body

    def read(self, _n: int = -1) -> bytes:
        return self._body

    def __enter__(self) -> _FakeResp:
        return self

    def __exit__(self, *_a: object) -> None:
        return None


class _FakeOpener:
    def __init__(self) -> None:
        self.requests: list[Any] = []

    def open(self, req: Any, timeout: float = 0.0) -> _FakeResp:
        self.requests.append(req)
        return _FakeResp(json.dumps({"id_token": "x.y.z"}).encode())

    def form(self, index: int = -1) -> dict[str, list[str]]:
        return urllib.parse.parse_qs(self.requests[index].data.decode("ascii"))


def _exchange(opener: _FakeOpener, **kw: Any) -> None:
    oidc.exchange_code(
        token_endpoint=TOKEN_ENDPOINT,
        client_id=CLIENT_ID,
        code="the-code",
        redirect_uri="https://ops.example/ui/oidc/callback",
        code_verifier="the-verifier",
        opener=opener,  # type: ignore[arg-type]
        **kw,
    )


# --- the assertion -----------------------------------------------------------------------------


@pytest.mark.parametrize("alg", ["RS256", "PS256", "ES256"])
def test_the_assertion_carries_the_rfc7523_claims_and_verifies(
    alg: str, ec_key: ec.EllipticCurvePrivateKey, rsa_key: rsa.RSAPrivateKey
) -> None:
    key = ec_key if alg == "ES256" else rsa_key
    client = PrivateKeyJwtClientAuth(
        client_id=CLIENT_ID,
        audience=TOKEN_ENDPOINT,
        private_key=_pem(key),
        algorithm=SignatureAlgorithm(alg),
        key_id="kid-1",
    )
    before = int(time.time())
    fields = client.form_fields()
    assert fields["client_assertion_type"] == CLIENT_ASSERTION_TYPE
    claims = verify_compact_jws(
        fields["client_assertion"], key.public_key(), allowed_algorithms=(SignatureAlgorithm(alg),)
    )
    assert claims["iss"] == claims["sub"] == CLIENT_ID
    assert claims["aud"] == TOKEN_ENDPOINT
    assert before <= claims["iat"] <= int(time.time())
    assert claims["exp"] == claims["iat"] + CLIENT_ASSERTION_TTL_SECONDS
    assert len(claims["jti"]) >= 32
    header = json.loads(base64.urlsafe_b64decode(fields["client_assertion"].split(".")[0] + "=="))
    assert header == {"alg": alg, "kid": "kid-1", "typ": "JWT"}


def test_each_assertion_is_fresh(ec_key: ec.EllipticCurvePrivateKey) -> None:
    client = PrivateKeyJwtClientAuth(
        client_id=CLIENT_ID,
        audience=TOKEN_ENDPOINT,
        private_key=_pem(ec_key),
        algorithm=SignatureAlgorithm.ES256,
    )
    jtis = {
        verify_compact_jws(
            client.form_fields()["client_assertion"],
            ec_key.public_key(),
            allowed_algorithms=(SignatureAlgorithm.ES256,),
        )["jti"]
        for _ in range(5)
    }
    assert len(jtis) == 5


def test_the_shared_claim_builder_keeps_smart_without_iat() -> None:
    """SMART reuses the builder with ``include_iat`` off, so its wire format did not move."""
    smart = client_assertion_claims("cid", TOKEN_ENDPOINT, ttl_seconds=240)
    assert set(smart) == {"iss", "sub", "aud", "exp", "jti"}
    oidc_claims = client_assertion_claims("cid", TOKEN_ENDPOINT, ttl_seconds=120, include_iat=True)
    assert set(oidc_claims) == set(smart) | {"iat"}


def test_a_wrong_curve_or_weak_key_is_refused_at_construction(
    rsa_key: rsa.RSAPrivateKey,
) -> None:
    with pytest.raises(SigningError, match="EC private key"):
        PrivateKeyJwtClientAuth(
            client_id=CLIENT_ID,
            audience=TOKEN_ENDPOINT,
            private_key=_pem(rsa_key),
            algorithm=SignatureAlgorithm.ES256,
        )
    weak = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    with pytest.raises(SigningError, match="3072"):
        PrivateKeyJwtClientAuth(
            client_id=CLIENT_ID,
            audience=TOKEN_ENDPOINT,
            private_key=_pem(weak),
            algorithm=SignatureAlgorithm.RS256,
        )


# --- the token request -------------------------------------------------------------------------


def test_private_key_jwt_sends_the_assertion_and_no_secret(
    ec_key: ec.EllipticCurvePrivateKey,
) -> None:
    client = client_auth_from_settings(AuthSettings(**_pkjwt(_pem(ec_key))), None)
    assert client is not None
    opener = _FakeOpener()
    _exchange(opener, client_auth=client)
    form = opener.form()
    assert "client_secret" not in form
    assert form["client_assertion_type"] == [CLIENT_ASSERTION_TYPE]
    assert form["client_id"] == [CLIENT_ID]
    assert form["grant_type"] == ["authorization_code"]
    claims = verify_compact_jws(
        form["client_assertion"][0],
        ec_key.public_key(),
        allowed_algorithms=(SignatureAlgorithm.ES256,),
    )
    assert claims["aud"] == TOKEN_ENDPOINT
    # No secret in a header either.
    assert "Authorization" not in dict(opener.requests[-1].header_items())


def test_the_default_client_secret_post_request_is_unchanged() -> None:
    """The control: with no ``client_auth`` the form holds exactly the pre-#296 fields."""
    opener = _FakeOpener()
    _exchange(
        opener,
        client_auth=client_auth_from_settings(
            AuthSettings(**_auth(oidc_client_secret=SECRET)), None
        ),
    )
    assert opener.form() == {
        "grant_type": ["authorization_code"],
        "code": ["the-code"],
        "redirect_uri": ["https://ops.example/ui/oidc/callback"],
        "client_id": [CLIENT_ID],
        "code_verifier": ["the-verifier"],
        "client_secret": [SECRET],
    }


def test_the_issuer_audience_option_addresses_the_pinned_issuer(
    ec_key: ec.EllipticCurvePrivateKey,
) -> None:
    client = client_auth_from_settings(
        AuthSettings(**_pkjwt(_pem(ec_key), oidc_client_assertion_audience="issuer")), None
    )
    assert isinstance(client, PrivateKeyJwtClientAuth) and client.audience == ISSUER


# --- configuration -----------------------------------------------------------------------------


def test_the_default_method_is_client_secret_post() -> None:
    settings = AuthSettings(**_auth(oidc_client_secret=SECRET))
    assert settings.oidc_token_endpoint_auth_method == "client_secret_post"
    credential = client_auth_from_settings(settings, None)
    assert isinstance(credential, ClientSecretPost)
    assert SECRET not in repr(credential)


@pytest.mark.parametrize("key", [None, "", "   "])
def test_private_key_jwt_without_a_key_is_refused(key: str | None) -> None:
    with pytest.raises(ValidationError, match="NON-EMPTY signing key"):
        AuthSettings(
            **_auth(oidc_token_endpoint_auth_method="private_key_jwt", oidc_client_private_key=key)
        )


def test_private_key_jwt_beside_a_secret_is_refused(ec_key: ec.EllipticCurvePrivateKey) -> None:
    with pytest.raises(ValidationError, match="never sends the client secret"):
        AuthSettings(**_pkjwt(_pem(ec_key), oidc_client_secret=SECRET))
    with pytest.raises(ValidationError, match="never sends the client secret"):
        AuthSettings(**_pkjwt(_pem(ec_key), oidc_client_secret_ref="kv/mf#oidc"))


def test_a_signing_key_under_client_secret_post_is_refused(
    ec_key: ec.EllipticCurvePrivateKey,
) -> None:
    with pytest.raises(ValidationError, match="apply only with"):
        AuthSettings(**_auth(oidc_client_secret=SECRET, oidc_client_private_key=_pem(ec_key)))


def test_the_secret_is_still_required_under_the_default_method() -> None:
    with pytest.raises(ValidationError, match="NON-EMPTY client secret"):
        AuthSettings(**_auth())


@pytest.mark.parametrize("alg", ["none", "HS256", "HS384", "HS512", "EdDSA"])
def test_none_and_hmac_algorithms_cannot_be_configured(
    alg: str, ec_key: ec.EllipticCurvePrivateKey
) -> None:
    with pytest.raises(ValidationError):
        AuthSettings(**_pkjwt(_pem(ec_key), oidc_client_assertion_algorithm=alg))


def test_an_unknown_method_is_refused() -> None:
    with pytest.raises(ValidationError):
        AuthSettings(
            **_auth(oidc_client_secret=SECRET, oidc_token_endpoint_auth_method="client_secret_jwt")
        )


def test_inline_pem_in_the_config_file_warns_and_a_path_does_not(
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.WARNING, logger="messagefoundry.config.settings")
    _warn_file_secrets({"auth": {"oidc_client_private_key": "C:/keys/oidc.pem"}}, Path("mf.toml"))
    assert "oidc_client_private_key" not in caplog.text
    _warn_file_secrets({"auth": {"oidc_client_private_key": _BEGIN + "\nAAAA"}}, Path("mf.toml"))
    assert "oidc_client_private_key" in caplog.text
    assert "AAAA" not in caplog.text


# --- the service -------------------------------------------------------------------------------


async def test_the_service_sends_the_assertion_and_resolves_no_secret(
    monkeypatch: pytest.MonkeyPatch, ec_key: ec.EllipticCurvePrivateKey
) -> None:
    store = await MessageStore.open(":memory:")
    try:
        service = AuthService(store, AuthSettings(**_pkjwt(_pem(ec_key))), ldap=object())  # type: ignore[arg-type]
        calls: list[dict[str, Any]] = []

        class _Stop(Exception):
            pass

        def fake(**kwargs: Any) -> Any:
            calls.append(kwargs)
            raise _Stop

        monkeypatch.setattr(oidc, "exchange_code", fake)
        flow = oidc.PendingFlow(
            state="st",
            nonce="n",
            code_verifier="v",
            return_to="/ui",
            client_ip="127.0.0.1",
            deadline=time.monotonic() + 300,
        )
        with pytest.raises(_Stop):
            service._exchange_and_validate("code", flow, "https://ops.example/ui/oidc/callback")
        assert "client_secret" not in calls[0]
        assert isinstance(calls[0]["client_auth"], PrivateKeyJwtClientAuth)
    finally:
        await store.close()


async def test_the_default_service_sends_the_secret(monkeypatch: pytest.MonkeyPatch) -> None:
    store = await MessageStore.open(":memory:")
    try:
        settings = AuthSettings(**_auth(oidc_client_secret=SECRET))
        service = AuthService(store, settings, ldap=object())  # type: ignore[arg-type]
        calls: list[dict[str, Any]] = []

        def fake(**kwargs: Any) -> Any:
            calls.append(kwargs)
            raise oidc.FlowError("stop")

        monkeypatch.setattr(oidc, "exchange_code", fake)
        flow = oidc.PendingFlow(
            state="st",
            nonce="n",
            code_verifier="v",
            return_to="/ui",
            client_ip="127.0.0.1",
            deadline=time.monotonic() + 300,
        )
        with pytest.raises(oidc.FlowError):
            service._exchange_and_validate("code", flow, "https://ops.example/ui/oidc/callback")
        assert calls[0]["client_auth"].form_fields() == {"client_secret": SECRET}
    finally:
        await store.close()


async def test_an_unreadable_key_refuses_service_construction(tmp_path: Path) -> None:
    missing = str(tmp_path / "no-such-key.pem")
    store = await MessageStore.open(":memory:")
    try:
        with pytest.raises(SigningError) as excinfo:
            AuthService(store, AuthSettings(**_pkjwt(missing)), ldap=object())  # type: ignore[arg-type]
        assert "oidc_client_private_key" in str(excinfo.value)
        assert missing not in str(excinfo.value)  # never echo the value
    finally:
        await store.close()


async def test_garbage_pem_refuses_service_construction() -> None:
    store = await MessageStore.open(":memory:")
    try:
        with pytest.raises(SigningError, match="could not load"):
            AuthService(
                store,
                AuthSettings(**_pkjwt(_BEGIN + "\nnot-a-key\n-----END PRIVATE KEY-----")),
                ldap=object(),  # type: ignore[arg-type]
            )
    finally:
        await store.close()


# --- verify and the static-credential inventory -------------------------------------------------


def _service_settings(auth: dict[str, Any], **sections: Any) -> ServiceSettings:
    return ServiceSettings.model_validate(
        {"auth": auth, "api": {"public_origin": "https://ops.example"}, **sections}
    )


def test_verify_loads_the_key_and_never_shows_it(ec_key: ec.EllipticCurvePrivateKey) -> None:
    pem = _pem(ec_key)
    rows = {r.id: r for r in run_federation_checks(_service_settings(_pkjwt(pem)))}
    assert "fed.client_secret" not in rows
    row = rows["fed.client_key"]
    assert row.status is Status.PASS
    assert "BEGIN" not in row.detail and pem.splitlines()[1] not in row.detail
    assert TOKEN_ENDPOINT in row.detail


def test_verify_fails_an_unloadable_key() -> None:
    rows = {
        r.id: r
        for r in run_federation_checks(
            _service_settings(_pkjwt(_BEGIN + "\nAAAA\n-----END PRIVATE KEY-----"))
        )
    }
    assert rows["fed.client_key"].status is Status.FAIL


def test_the_static_client_secret_hop_leaves_the_inventory_under_private_key_jwt(
    ec_key: ec.EllipticCurvePrivateKey,
) -> None:
    def names(auth: dict[str, Any]) -> set[str]:
        settings = _service_settings({**auth, "enabled": True})
        return {h.name for h in static_credential_hops(registry=None, settings=settings)}

    # The control: under the default method the hop is reported.
    assert "settings:auth.oidc" in names(_auth(oidc_client_secret=SECRET))
    assert "settings:auth.oidc" not in names(_pkjwt(_pem(ec_key)))


def test_the_key_reference_is_the_one_handed_to_the_secret_provider() -> None:
    auth = _auth(
        oidc_token_endpoint_auth_method="private_key_jwt",
        oidc_client_private_key_ref="kv/mf#oidc-key",
        oidc_client_assertion_algorithm="ES256",
        enabled=True,
    )
    settings = _service_settings(auth, secrets={"provider": "vault"})
    assert "kv/mf#oidc-key" in resolved_secret_refs(settings)
