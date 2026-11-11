# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #5529: HTTP Digest either runs as configured or the connection does not build.

Limb 1: ``http_auth`` set to anything but ``digest`` (a typo, say) read as auth off, and the
posture reader agreed. It is refused now, through one predicate the reader shares.

Limb 2: a static ``bearer_token``, Basic pair or ``Authorization`` header rode beside Digest on
REST, SOAP and FHIR. urllib lets a request header override the Digest handler's own, so where the
static credential was sent it is what would have crossed; a lone Basic half sent nothing. All are
refused under one rule, beside Digest a connection configures exactly one HTTP credential, by
``refuse_http_digest_conflicts``. REST, SOAP and FHIR call it at the top of construction, and
``digest_handler_from_settings`` calls it again. A signing header named ``Authorization`` is
refused once REST or SOAP has built the signer, by ``refuse_authorization_signer_beside_digest``.

Limb 3 (also #2707 closing step 1): ``ech_egress`` replaced the opener that held the Digest
handler, so a REST connection built with no Digest auth. The pair is refused at construction; the
comment beside the refusal in ``RestDestination.__init__`` says why the handler cannot move.
"""

from __future__ import annotations

import logging
import urllib.request

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from messagefoundry.config.models import (
    ConnectorType,
    Destination,
    OutboundSigning,
    SignatureAlgorithm,
)
from messagefoundry.config.static_credentials import _http_static
from messagefoundry.config.tls_policy import MIRRORED_CONNECTION_SETTING
from messagefoundry.config.wiring import FHIR, Rest, Soap
from messagefoundry.transports import build_destination
from messagefoundry.transports.http_auth import (
    digest_handler_from_settings,
    http_digest_selected,
    is_authorization_header_name,
    refuse_http_digest_conflicts,
    with_http_digest,
    with_oauth2_client_credentials,
)
from messagefoundry.transports.rest import HttpAuthError, RestDestination
from tests._egress_policy import permitting

URL = "https://partner.example/ingest"
_PW = "digest-pw-synthetic"  # noqa: S105 -- a synthetic test credential, not a real secret
_SIDECAR = {"ech_egress": True, "ech_sidecar": "http://127.0.0.1:8123"}


def _build(ctype: ConnectorType, settings: dict[str, object]) -> object:
    return build_destination(
        Destination(name="OB_HTTP", type=ctype, settings=settings),
        egress=permitting(settings),
    )


def _digest_rest(**extra: object) -> dict[str, object]:
    settings = with_http_digest(Rest(url=URL), user="u", password=_PW).settings
    settings.update(extra)
    return settings


def _has_digest(dest: object) -> bool:
    handlers = dest._opener.handlers  # type: ignore[attr-defined]  # typeshed omits it
    return any(isinstance(h, urllib.request.HTTPDigestAuthHandler) for h in handlers)


# --- limb 3: ech_egress with Digest --------------------------------------------------------------


def test_ech_egress_with_digest_is_refused_at_construction() -> None:
    with pytest.raises(HttpAuthError, match="ech_egress and HTTP Digest") as ei:
        _build(ConnectorType.REST, _digest_rest(**_SIDECAR))
    assert _PW not in str(ei.value)


def test_control_ech_without_digest_builds() -> None:
    settings = Rest(url=URL).settings
    settings.update(_SIDECAR)
    dest = _build(ConnectorType.REST, settings)
    assert isinstance(dest, RestDestination)
    assert dest._ech_sidecar is not None


# --- limb 2: a static credential beside Digest ------------------------------------------------


_FACTORIES = {
    ConnectorType.REST: Rest,
    ConnectorType.SOAP: Soap,
    ConnectorType.FHIR: FHIR,
}

_STATIC: dict[str, dict[str, object]] = {
    "basic-pair": {"basic_user": "svc", "basic_password": _PW},
    "basic-user-only": {"basic_user": "svc"},
    "bearer": {"bearer_token": _PW},
    "header": {"headers": {"authorization": f"Basic {_PW}"}},
}


def _digest_spec(ctype: ConnectorType, **extra: object) -> dict[str, object]:
    return with_http_digest(
        _FACTORIES[ctype](url=URL, **extra),  # type: ignore[operator]
        user="u",
        password=_PW,
    ).settings


@pytest.mark.parametrize("static", list(_STATIC), ids=list(_STATIC))
@pytest.mark.parametrize("ctype", list(_FACTORIES), ids=[c.value for c in _FACTORIES])
def test_a_static_credential_beside_digest_is_refused(ctype: ConnectorType, static: str) -> None:
    # SOAP reads Digest before its half-pair rule (#5526), so a lone basic_user hears the Digest
    # rule on every connector, rather than being told to complete a pair Digest would then refuse.
    with pytest.raises(HttpAuthError, match="beside a static credential") as ei:
        _build(ctype, _digest_spec(ctype, **_STATIC[static]))
    assert _PW not in str(ei.value)


@pytest.mark.parametrize("ctype", list(_FACTORIES), ids=[c.value for c in _FACTORIES])
def test_control_digest_alone_builds_on_each_http_connector(ctype: ConnectorType) -> None:
    assert _has_digest(_build(ctype, _digest_spec(ctype)))


@pytest.mark.parametrize("ctype", list(_FACTORIES), ids=[c.value for c in _FACTORIES])
def test_control_basic_without_digest_builds(ctype: ConnectorType) -> None:
    settings = _FACTORIES[ctype](url=URL, basic_user="svc", basic_password=_PW).settings  # type: ignore[operator]
    assert not _has_digest(_build(ctype, settings))


def _ec_pem() -> str:
    key = ec.generate_private_key(ec.SECP256R1())
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode("ascii")


def _signed(ctype: ConnectorType, header: str, **over: object) -> dict[str, object]:
    settings = _digest_spec(ctype)
    settings.update(
        {"sign_private_key": _ec_pem(), "sign_algorithm": "ES256", "sign_header": header, **over}
    )
    return settings


@pytest.mark.parametrize("name", ["Authorization", "authorization", "Authorization\t"])
@pytest.mark.parametrize("ctype", [ConnectorType.REST, ConnectorType.SOAP])
def test_a_signing_header_named_authorization_is_refused_beside_digest(
    ctype: ConnectorType, name: str
) -> None:
    """``_post`` writes the detached JWS under ``sign_header`` per request, so under the
    Authorization name it would replace the Digest response."""
    with pytest.raises(HttpAuthError, match="signing header named Authorization") as ei:
        _build(ctype, _signed(ctype, name))
    assert _PW not in str(ei.value)


def test_the_typed_signing_config_is_read_by_the_same_rule() -> None:
    """The runner assembles ``Destination.sign``; the refusal reads the built signer, so the typed
    form is refused as the flat ``sign_*`` settings are."""
    sign = OutboundSigning(
        algorithm=SignatureAlgorithm.ES256, private_key=_ec_pem(), header_name="authorization"
    )
    dest = Destination(
        name="OB_HTTP",
        type=ConnectorType.REST,
        settings=_digest_spec(ConnectorType.REST),
        sign=sign,
    )
    with pytest.raises(HttpAuthError, match="signing header named Authorization"):
        build_destination(dest, egress=permitting(dest.settings))


def test_control_signing_beside_digest_builds_unless_it_writes_authorization() -> None:
    assert _has_digest(_build(ConnectorType.REST, _signed(ConnectorType.REST, "X-JWS-Signature")))
    # Signing switched off writes no header, so the Authorization name is no conflict then.
    off = _signed(ConnectorType.REST, "Authorization", sign_enabled=False)
    assert _has_digest(_build(ConnectorType.REST, off))
    assert refuse_http_digest_conflicts(off)


def test_control_a_non_auth_static_header_beside_digest_builds() -> None:
    assert _has_digest(
        _build(ConnectorType.REST, _digest_spec(ConnectorType.REST, headers={"X-Trace": "1"}))
    )


# --- limb 1: an unrecognised http_auth is refused, not read as "auth off" ------------------------

_CREDS = {"http_auth_user": "u", "http_auth_password": _PW}


@pytest.mark.parametrize("mode", ["digset", "basic", "ntlm", "true"])
def test_an_unrecognised_http_auth_mode_is_refused(mode: str) -> None:
    with pytest.raises(HttpAuthError, match="http_auth") as ei:
        digest_handler_from_settings({"http_auth": mode, **_CREDS}, url=URL)
    assert _PW not in str(ei.value)


def test_an_unrecognised_http_auth_mode_refuses_the_connector() -> None:
    settings = Rest(url=URL).settings
    settings.update({"http_auth": "digset", **_CREDS})
    # The runner mirrors the connection name into the settings (wiring_runner); a direct build does not.
    settings[MIRRORED_CONNECTION_SETTING] = "OB_HTTP"
    with pytest.raises(HttpAuthError, match="http_auth") as ei:
        _build(ConnectorType.REST, settings)
    assert "OB_HTTP" in str(ei.value)
    assert "digset" not in str(ei.value)


@pytest.mark.parametrize("unset", [None, "", "   ", False, 0])
def test_control_an_unset_http_auth_is_off(unset: object) -> None:
    """Every falsy value read as off before #5529 and still does; only a set, unknown mode raises."""
    assert digest_handler_from_settings({"http_auth": unset, **_CREDS}, url=URL) is None
    assert not http_digest_selected({"http_auth": unset})


def test_control_digest_is_read_whatever_its_case_and_padding() -> None:
    assert digest_handler_from_settings({"http_auth": " Digest ", **_CREDS}, url=URL) is not None


def test_the_census_shares_the_predicate_and_does_not_raise() -> None:
    """``_http_static`` reads the same predicate. A connector refuses to build on an unrecognised
    mode, so no Digest credential is reported, and the census itself does not raise."""
    assert "HTTP Digest" not in _http_static(ConnectorType.REST, {"http_auth": "digset"}, False)
    assert "HTTP Digest" in _http_static(ConnectorType.REST, {"http_auth": " DIGEST "}, False)


# --- review round 1: spelling-proof header names, and refusing before any hop gate logs ----------


@pytest.mark.parametrize(
    "name", ["Authorization\t", " authorization", "AUTHORIZATION\x00", "Authorization\x7f"]
)
def test_an_authorization_header_however_spelled_is_refused_beside_digest(name: str) -> None:
    """``http.client`` sends most such names as written, and a peer may read one as the plain
    header; a leading space makes it refuse the request instead. Each is refused here either way."""
    assert is_authorization_header_name(name)
    with pytest.raises(HttpAuthError, match="beside a static credential"):
        _build(ConnectorType.REST, _digest_spec(ConnectorType.REST, headers={name: "Basic x"}))


@pytest.mark.parametrize("name", ["Authorization-2", "X-Authorization", "Proxy-Authorization"])
def test_control_another_header_is_not_authorization(name: str) -> None:
    assert not is_authorization_header_name(name)


def test_an_unrecognised_mode_refuses_before_the_verify_off_gate_logs(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """The refusal runs first in construction, so a connection that never builds logs no DISABLED
    warning (the placement vault BACKLOG #2977 item 8 set for the ECH refusals)."""
    url = "https://127.0.0.1:8443/ingest"
    caplog.set_level(logging.DEBUG)
    settings = Rest(url=url, verify_tls=False).settings
    settings.update({"http_auth": "digset", **_CREDS})
    with pytest.raises(HttpAuthError, match="http_auth"):
        _build(ConnectorType.REST, settings)
    assert "DISABLED" not in caplog.text
    # Round 2: a bearer provider beside Digest, and a Digest pair with no password, refuse as early.
    provider = with_oauth2_client_credentials(
        with_http_digest(Rest(url=url, verify_tls=False), user="u", password=_PW),
        token_url="https://127.0.0.1:8443/token",
        client_id="cid",
        client_secret="cs-synthetic",  # noqa: S106 -- a synthetic test credential
    ).settings
    no_password = {**Rest(url=url, verify_tls=False).settings, "http_auth": "digest"}
    no_password["http_auth_user"] = "u"
    for conflicted, words in ((provider, "bearer-token provider"), (no_password, "requires")):
        caplog.clear()
        with pytest.raises(HttpAuthError, match=words):
            _build(ConnectorType.REST, conflicted)
        assert "DISABLED" not in caplog.text
    # CONTROL: the same loopback verify-off hop with no http_auth builds and logs the warning, so the
    # absence above is the refusal's placement and not a log this capture cannot see.
    caplog.clear()
    _build(ConnectorType.REST, Rest(url=url, verify_tls=False).settings)
    assert "DISABLED" in caplog.text
