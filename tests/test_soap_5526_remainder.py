# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #5526, the items left after engine PRs 2883 and 3144: one credential owns the
``Authorization`` header on SOAP, and a signing header does not replace it on SOAP or REST; the
static-credential census lists what is sent; and the SOAP Digest refusal names the connection.
Synthetic credentials only.

Items 2, 5, 6 and 9 are pinned here; each test names its item."""

from __future__ import annotations

from typing import Any

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from messagefoundry.config.models import ConnectorType, Destination
from messagefoundry.config.settings import EgressSettings
from messagefoundry.config.static_credentials import _http_hop, http_hop_credentials
from messagefoundry.config.tls_policy import MIRRORED_CONNECTION_SETTING
from messagefoundry.config.wiring import EnvRef, Rest, Soap
from messagefoundry.transports import build_destination
from messagefoundry.transports.http_auth import (
    HttpAuthError,
    is_authorization_header_name,
    with_http_digest,
    with_oauth2_client_credentials,
)
from messagefoundry.transports.soap import SoapDestination

URL = "https://api.example.com/svc"
_PW = "pw-synthetic"  # noqa: S105 -- a synthetic test credential, not a real secret
_TOKEN = "tok-synthetic"  # noqa: S105 -- a synthetic test credential, not a real secret


def _build(ctype: ConnectorType, settings: dict[str, Any], *, name: str = "OB_HTTP") -> Any:
    return build_destination(
        Destination(name=name, type=ctype, settings=settings),
        egress=EgressSettings(deny_by_default=False),
    )


def _oauth(spec: Any) -> Any:
    return with_oauth2_client_credentials(
        spec,
        token_url="https://auth.example.com/token",
        client_id="client-synthetic",
        client_secret=_PW,
    )


def _auth_keys(headers: dict[str, str]) -> list[str]:
    return [k for k in headers if is_authorization_header_name(k)]


# --- item 2: bearer_token beside a Basic pair -------------------------------------------------


def test_soap_refuses_a_bearer_token_beside_a_basic_pair() -> None:
    """Item 2: SOAP sent Basic and silently dropped the bearer_token, as REST and DICOMweb
    already refuse to. The refusal names settings, never a value."""
    settings = Soap(url=URL, basic_user="svc", basic_password=_PW, bearer_token=_TOKEN).settings
    with pytest.raises(HttpAuthError, match="bearer_token and basic_user") as ei:
        _build(ConnectorType.SOAP, settings, name="OB_SOAP")
    assert _PW not in str(ei.value) and _TOKEN not in str(ei.value)
    assert "OB_SOAP" in str(ei.value)


@pytest.mark.parametrize(
    "auth",
    [{"basic_user": "svc", "basic_password": _PW}, {"bearer_token": _TOKEN}],
    ids=["basic", "bearer"],
)
def test_control_soap_builds_on_either_credential_alone(auth: dict[str, str]) -> None:
    dest = _build(ConnectorType.SOAP, Soap(url=URL, **auth).settings)  # type: ignore[arg-type]
    assert _auth_keys(dest._headers) == ["Authorization"]


def test_the_census_lists_only_the_basic_pair_where_both_are_set() -> None:
    """Item 2: a connector that builds with both sends Basic (FHIR assigns it last), so the census
    lists HTTP Basic alone. Control: each alone is listed."""
    both = {"bearer_token": _TOKEN, "basic_user": "svc", "basic_password": _PW}
    assert http_hop_credentials(ConnectorType.FHIR, both) == ["HTTP Basic"]
    assert http_hop_credentials(ConnectorType.FHIR, {"bearer_token": _TOKEN}) == [
        "static bearer token"
    ]


# --- item 6: a signing header named Authorization beside a credential --------------------------


def _ec_pem() -> str:
    key = ec.generate_private_key(ec.SECP256R1())
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode("ascii")


def _signed(settings: dict[str, Any], header: str) -> dict[str, Any]:
    return {
        **settings,
        "sign_private_key": _ec_pem(),
        "sign_algorithm": "ES256",
        "sign_header": header,
    }


_CREDENTIALS: dict[str, Any] = {
    "basic": lambda f: f(url=URL, basic_user="svc", basic_password=_PW).settings,
    "bearer": lambda f: f(url=URL, bearer_token=_TOKEN).settings,
    "oauth2": lambda f: _oauth(f(url=URL)).settings,
    "static-header": lambda f: f(url=URL, headers={"authorization": "Bearer x"}).settings,
}


@pytest.mark.parametrize("header", ["Authorization", "authorization", "Authorization\t"])
@pytest.mark.parametrize("credential", list(_CREDENTIALS), ids=list(_CREDENTIALS))
@pytest.mark.parametrize(
    ("ctype", "factory"),
    [(ConnectorType.SOAP, Soap), (ConnectorType.REST, Rest)],
    ids=["soap", "rest"],
)
def test_a_signing_header_named_authorization_is_refused_beside_a_credential(
    ctype: ConnectorType, factory: Any, credential: str, header: str
) -> None:
    """Item 6 (and the filing review's finding 2): ``_post`` writes the detached JWS after the
    configured or minted credential, so under the Authorization name it replaced that credential
    on every send. Beside Digest it was already refused."""
    settings = _signed(_CREDENTIALS[credential](factory), header)
    with pytest.raises(HttpAuthError, match="signing header named Authorization") as ei:
        _build(ctype, settings)
    assert _PW not in str(ei.value)


@pytest.mark.parametrize(
    ("ctype", "factory"),
    [(ConnectorType.SOAP, Soap), (ConnectorType.REST, Rest)],
    ids=["soap", "rest"],
)
def test_control_signing_builds_alone_or_under_another_name(
    ctype: ConnectorType, factory: Any
) -> None:
    """An Authorization-named signature with no credential beside it, and a credential beside a
    signature under its own name, both build."""
    assert _build(ctype, _signed(factory(url=URL).settings, "Authorization"))._signer is not None
    beside = _signed(_CREDENTIALS["basic"](factory), "X-JWS-Signature")
    assert _build(ctype, beside)._signer is not None


# --- item 9: the census reads an unresolved env() http_auth as Digest ---------------------------


def test_the_census_reads_an_unresolved_env_http_auth_as_digest() -> None:
    """Item 9: the census reads settings before ``env()`` resolves. An unresolved ``http_auth``
    raised in the shared predicate and was read as no Digest, so a hop that may present one was
    not listed. It now lists it, as an unresolved OAuth2 flag reads as on. Control: a literal
    unrecognised mode is still not listed, since the connector refuses to build on it."""
    ref = EnvRef("MF_HTTP_AUTH_SYNTHETIC")
    assert "HTTP Digest" in http_hop_credentials(ConnectorType.REST, {"http_auth": ref})
    assert "HTTP Digest" not in http_hop_credentials(ConnectorType.REST, {"http_auth": "digset"})


@pytest.mark.parametrize(
    ("env_values", "listed"),
    [({"MF_HTTP_AUTH_SYNTHETIC": "digest"}, True), ({"MF_HTTP_AUTH_SYNTHETIC": ""}, False)],
    ids=["resolves-to-digest", "resolves-empty"],
)
def test_the_census_resolves_an_env_http_auth_against_the_values(
    env_values: dict[str, str], listed: bool
) -> None:
    """Item 9, review round 1: with the values the serve-time guard holds, the mode is read as
    the build resolves it, so an empty one lists no Digest and a SOAP mTLS hop is not listed."""
    settings = {
        "url": URL,
        "http_auth": EnvRef("MF_HTTP_AUTH_SYNTHETIC"),
        "client_cert_file": "client.pem",
    }
    hop = _http_hop("OB_SOAP", ConnectorType.SOAP, settings, "peer", env_values=env_values)
    assert (hop is not None and "HTTP Digest" in hop.detail) is listed
    if not listed:
        assert hop is None


def test_the_census_reads_no_digest_beside_a_minted_bearer() -> None:
    """Item 9, review round 1: Digest beside an OAuth2 or SMART provider refuses the build, so an
    unresolved ``env()`` ``http_auth`` there lists no Digest and the hop is not reported."""
    settings = _oauth(Rest(url=URL)).settings
    settings["http_auth"] = EnvRef("MF_HTTP_AUTH_SYNTHETIC")
    assert "HTTP Digest" not in http_hop_credentials(ConnectorType.REST, settings)
    assert _http_hop("OB_REST", ConnectorType.REST, settings, "peer") is None


def test_the_census_reads_digest_beside_a_bearer_whose_flag_is_from_env() -> None:
    """Item 9, review round 2: an ``env()`` ``oauth2_enabled`` may resolve off, so the provider
    may not be built and Digest may cross; an unresolved ``http_auth`` there still reads as
    Digest. Control: the literal flag in the test above lists none."""
    settings = _oauth(Rest(url=URL)).settings
    settings["http_auth"] = EnvRef("MF_HTTP_AUTH_SYNTHETIC")
    settings["oauth2_enabled"] = EnvRef("MF_OAUTH_ON_SYNTHETIC")
    assert "HTTP Digest" in http_hop_credentials(ConnectorType.REST, settings)


@pytest.mark.parametrize(
    "token_url_key", ["smart_token_url", "oauth2_token_url"], ids=["smart", "oauth2"]
)
def test_the_census_reads_digest_beside_a_bearer_whose_token_url_is_from_env(
    token_url_key: str,
) -> None:
    """Item 9, review round 3 finding 1: an ``env()`` token URL may resolve empty, which leaves
    the provider off at build, so Digest crosses; an unresolved ``http_auth`` there still reads
    as Digest. Control: a literal token URL with literal flags lists none (the test above)."""
    settings: dict[str, Any] = {
        "url": URL,
        "http_auth": EnvRef("MF_HTTP_AUTH_SYNTHETIC"),
        token_url_key: EnvRef("MF_TOKEN_URL_SYNTHETIC"),
    }
    assert "HTTP Digest" in http_hop_credentials(ConnectorType.FHIR, settings)
    assert _http_hop("OB_FHIR", ConnectorType.FHIR, settings, "peer") is not None


def test_the_census_honours_an_env_default_for_http_auth() -> None:
    """Item 9, review round 2: with no values, an ``env()`` ``default=`` is read, as the headers
    reader reads it, so a default of no auth lists no Digest on an mTLS SOAP hop."""
    settings = {
        "url": URL,
        "http_auth": EnvRef("MF_HTTP_AUTH_SYNTHETIC", default=""),
        "client_cert_file": "client.pem",
    }
    assert _http_hop("OB_SOAP", ConnectorType.SOAP, settings, "peer") is None


# --- item 5: the SOAP Digest refusal names the connection --------------------------------------


def test_a_soap_digest_refusal_names_the_connection_built_directly() -> None:
    """Item 5: the Digest refusals read the connection name the runner mirrors into the settings,
    while the rest of the SOAP build reads ``config.name``. A destination built without the runner
    had no mirror, so its Digest refusal named no connection. Control: a mirror the runner set
    is kept, so the refusal names it and not ``config.name``."""
    settings = with_http_digest(Soap(url=URL, bearer_token=_TOKEN), user="u", password=_PW).settings
    assert MIRRORED_CONNECTION_SETTING not in settings
    with pytest.raises(HttpAuthError, match="beside a static credential") as ei:
        _build(ConnectorType.SOAP, settings, name="OB_SOAP_DIRECT")
    assert "OB_SOAP_DIRECT" in str(ei.value)
    with pytest.raises(HttpAuthError) as mirrored:
        _build(
            ConnectorType.SOAP,
            {**settings, MIRRORED_CONNECTION_SETTING: "OB_SOAP_MIRRORED"},
            name="OB_SOAP_DIRECT",
        )
    assert "OB_SOAP_MIRRORED" in str(mirrored.value)
    assert "OB_SOAP_DIRECT" not in str(mirrored.value)


def test_control_the_soap_build_does_not_alter_its_settings() -> None:
    settings = Soap(url=URL, basic_user="svc", basic_password=_PW).settings
    before = dict(settings)
    _build(ConnectorType.SOAP, settings)
    assert settings == before


def test_soap_is_a_soap_destination() -> None:
    assert isinstance(_build(ConnectorType.SOAP, Soap(url=URL).settings), SoapDestination)
