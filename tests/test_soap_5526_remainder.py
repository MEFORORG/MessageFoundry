# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #5526, the items left after engine PRs 2883 and 3144: one credential owns the
``Authorization`` header on SOAP, and a signing header does not replace it on SOAP or REST; the
static-credential census lists what is sent; and the Digest refusal runs once per SOAP build and
names the connection. Synthetic credentials only.

Items 2, 4, 5, 6 and 9 are pinned here; each test names its item."""

from __future__ import annotations

from typing import Any

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from messagefoundry.config.models import ConnectorType, Destination
from messagefoundry.config.settings import EgressSettings
from messagefoundry.config.static_credentials import http_hop_credentials
from messagefoundry.config.tls_policy import MIRRORED_CONNECTION_SETTING
from messagefoundry.config.wiring import EnvRef, Rest, Soap
from messagefoundry.transports import build_destination, http_auth
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


# --- items 4 and 5: the Digest refusal runs once on SOAP and names the connection --------------


def test_the_digest_conflict_check_runs_once_per_soap_build(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Item 4: ``SoapDestination`` refused Digest conflicts at the top of its build and
    ``digest_handler_from_settings`` refused them again. Control: the handler is still built."""
    calls: list[object] = []
    original = http_auth.refuse_http_digest_conflicts

    def counting(s: Any) -> bool:
        calls.append(s)
        return original(s)

    monkeypatch.setattr(http_auth, "refuse_http_digest_conflicts", counting)
    settings = with_http_digest(Soap(url=URL), user="u", password=_PW).settings
    dest = _build(ConnectorType.SOAP, settings)
    assert any(type(h).__name__ == "_ApprovedDigestAuthHandler" for h in dest._opener.handlers)
    assert len(calls) == 1


def test_a_soap_digest_refusal_names_the_connection_built_directly() -> None:
    """Item 5: the Digest refusals read the connection name the runner mirrors into the settings,
    while the rest of the SOAP build reads ``config.name``. A destination built without the runner
    had no mirror, so its Digest refusal named no connection. Control: the mirror, where set,
    is what the refusal names."""
    settings = with_http_digest(Soap(url=URL, bearer_token=_TOKEN), user="u", password=_PW).settings
    assert MIRRORED_CONNECTION_SETTING not in settings
    with pytest.raises(HttpAuthError, match="beside a static credential") as ei:
        _build(ConnectorType.SOAP, settings, name="OB_SOAP_DIRECT")
    assert "OB_SOAP_DIRECT" in str(ei.value)
    with pytest.raises(HttpAuthError) as mirrored:
        _build(
            ConnectorType.SOAP,
            {**settings, MIRRORED_CONNECTION_SETTING: "OB_SOAP_DIRECT"},
            name="OB_SOAP_DIRECT",
        )
    assert "OB_SOAP_DIRECT" in str(mirrored.value)


def test_control_the_soap_build_does_not_alter_its_settings() -> None:
    settings = Soap(url=URL, basic_user="svc", basic_password=_PW).settings
    before = dict(settings)
    _build(ConnectorType.SOAP, settings)
    assert settings == before


def test_soap_is_a_soap_destination() -> None:
    assert isinstance(_build(ConnectorType.SOAP, Soap(url=URL).settings), SoapDestination)
