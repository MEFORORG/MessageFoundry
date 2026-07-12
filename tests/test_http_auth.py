# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Generic outbound HTTP auth on the REST/SOAP/FHIR destinations (BACKLOG #65, ADR 0024 amendment).

Covers the two built modes: (1) OAuth2 client-credentials with a SYMMETRIC secret — fetches + caches a
bearer, injects ``Authorization: Bearer …`` per request, re-mints on invalidate, fails loud on a bad/
missing secret (redacted); (2) HTTP Digest — the connector folds a challenge-answering handler into a
per-connection opener. Plus the guardrails: default (no auth) is byte-identical, cleartext refusals, and
mutual exclusion. (NTLM/Negotiate is a documented follow-up — connection-bound; see the module docstring.)
"""

from __future__ import annotations

import urllib.request

import pytest

from messagefoundry.config.models import ConnectorType, Destination
from messagefoundry.config.settings import INSECURE_TLS_ESCAPE_ENV
from messagefoundry.config.tls_policy import HopPosture, active_hop_posture
from messagefoundry.config.wiring import Rest, Soap
from messagefoundry.transports import build_destination
from messagefoundry.transports.base import DeliveryError
from messagefoundry.transports.http_auth import (
    HttpAuthError,
    OAuth2ClientCredentialsProvider,
    bearer_provider_from_settings,
    digest_handler_from_settings,
    with_http_digest,
    with_oauth2_client_credentials,
)
from messagefoundry.transports.rest import RestDestination

URL = "https://api.example.com/ingest"
TOKEN_URL = "https://auth.example.com/token"


# --- OAuth2 client-credentials (symmetric) -----------------------------------


def _oauth_provider(**over: object) -> OAuth2ClientCredentialsProvider:
    kw: dict[str, object] = {
        "token_url": TOKEN_URL,
        "client_id": "cid",
        "client_secret": "s3cr3t",
    }
    kw.update(over)
    return OAuth2ClientCredentialsProvider(**kw)  # type: ignore[arg-type]


class _FakeTokenResp:
    def __init__(self, body: bytes) -> None:
        self._body = body

    def read(self) -> bytes:
        return self._body

    def __enter__(self) -> _FakeTokenResp:
        return self

    def __exit__(self, *a: object) -> bool:
        return False


class _RecordingOpener:
    def __init__(self, body: bytes) -> None:
        self._body = body
        self.requests: list[urllib.request.Request] = []

    def open(self, req: urllib.request.Request, timeout: float | None = None) -> _FakeTokenResp:
        self.requests.append(req)
        return _FakeTokenResp(self._body)


def test_oauth2_cc_fetches_and_caches_bearer_basic_style() -> None:
    p = _oauth_provider(scope="claims.write")
    opener = _RecordingOpener(b'{"access_token":"AT-123","expires_in":3600}')
    p._opener = opener  # type: ignore[assignment]
    assert p.access_token() == "AT-123"
    assert p.access_token() == "AT-123"  # cached — no second fetch
    assert len(opener.requests) == 1
    req = opener.requests[0]
    # client_secret_basic: the credential rides an Authorization: Basic header, NOT the body.
    assert req.get_header("Authorization", "").startswith("Basic ")
    body = req.data.decode() if isinstance(req.data, bytes) else ""
    assert "grant_type=client_credentials" in body and "scope=claims.write" in body
    assert "client_secret" not in body  # basic style keeps the secret out of the form


def test_oauth2_cc_post_style_puts_secret_in_form() -> None:
    p = _oauth_provider(auth_style="post")
    opener = _RecordingOpener(b'{"access_token":"AT","expires_in":3600}')
    p._opener = opener  # type: ignore[assignment]
    p.access_token()
    body = opener.requests[0].data.decode()  # type: ignore[union-attr]
    assert "client_id=cid" in body and "client_secret=s3cr3t" in body
    assert opener.requests[0].get_header("Authorization") is None


def test_oauth2_cc_invalidate_forces_refetch() -> None:
    p = _oauth_provider()
    opener = _RecordingOpener(b'{"access_token":"AT","expires_in":3600}')
    p._opener = opener  # type: ignore[assignment]
    p.access_token()
    p.invalidate()
    p.access_token()
    assert len(opener.requests) == 2  # re-minted after invalidate


def test_oauth2_cc_missing_secret_fails_loud_redacted() -> None:
    with pytest.raises(HttpAuthError) as ei:
        _oauth_provider(client_secret="")
    assert "s3cr3t" not in str(
        ei.value
    )  # never echo a secret (there is none here, but assert intent)
    assert "oauth2_client_secret" in str(ei.value)


def test_oauth2_cc_cleartext_token_endpoint_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(INSECURE_TLS_ESCAPE_ENV, raising=False)
    with pytest.raises(HttpAuthError) as ei:
        _oauth_provider(token_url="http://auth.example.com/token")
    assert "cleartext" in str(ei.value)


def test_oauth2_cc_unparseable_token_response_raises_delivery_error() -> None:
    p = _oauth_provider()
    p._opener = _RecordingOpener(b"not-json")  # type: ignore[assignment]
    with pytest.raises(DeliveryError):
        p.access_token()


# --- #200 posture-keyed cleartext refusal (the delivery-cell invariant now holds here too) ---------
#
# Before this fix both cleartext refusals gated on the blunt global MEFOR_ALLOW_INSECURE_TLS, so a
# prod-PHI operator who SET the escape could leak the client_secret (OAuth2) / digest credential over
# cleartext http to the token-endpoint / delivery host — a gap the delivery URL (re-keyed by #200) did
# not have. Both refusals now consume the SAME posture-keyed authority: prod-PHI REFUSES even with the
# escape set (the escape is inert for prod-PHI), non-prod / attested is permitted (as the delivery cells
# do), and the default (unstamped → fail-closed prod-PHI, e.g. the two tests above) still refuses.

_PROD_PHI = HopPosture(is_phi=True, production=True)
_STAGING_PHI = HopPosture(is_phi=True, production=False)  # non-prod PHI


def test_oauth2_cleartext_token_endpoint_refused_on_prod_phi_even_with_escape(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # THE fix: the global escape is INERT for a production-PHI hop — the cleartext token endpoint is
    # refused despite MEFOR_ALLOW_INSECURE_TLS being set, matching the delivery-cell semantics.
    monkeypatch.setenv(INSECURE_TLS_ESCAPE_ENV, "1")
    with active_hop_posture(_PROD_PHI), pytest.raises(HttpAuthError) as ei:
        _oauth_provider(token_url="http://auth.example.com/token")
    assert "cleartext" in str(ei.value)
    assert "s3cr3t" not in str(ei.value)  # never echo the secret in the refusal


def test_oauth2_cleartext_token_endpoint_allowed_non_prod_with_escape(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Non-prod (staging) PHI with the clamped escape set downgrades REFUSE→WARN — permitted (as-is).
    monkeypatch.setenv(INSECURE_TLS_ESCAPE_ENV, "1")
    with active_hop_posture(_STAGING_PHI):
        p = _oauth_provider(token_url="http://auth.example.com/token")
    assert isinstance(p, OAuth2ClientCredentialsProvider)


def test_oauth2_cleartext_token_endpoint_allowed_when_attested(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # A per-hop attestation crosses even a prod-PHI cleartext hop (no escape needed) — stays as-is.
    monkeypatch.delenv(INSECURE_TLS_ESCAPE_ENV, raising=False)
    with active_hop_posture(_PROD_PHI):
        p = _oauth_provider(token_url="http://auth.example.com/token", attested=True)
    assert isinstance(p, OAuth2ClientCredentialsProvider)


def test_digest_cleartext_refused_on_prod_phi_even_with_escape(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # THE fix, digest half: the escape can no longer silence a prod-PHI cleartext digest hop.
    monkeypatch.setenv(INSECURE_TLS_ESCAPE_ENV, "1")
    with active_hop_posture(_PROD_PHI), pytest.raises(HttpAuthError) as ei:
        digest_handler_from_settings(
            {"http_auth": "digest", "http_auth_user": "u", "http_auth_password": "p"},
            url="http://api.example.com/x",
        )
    assert "cleartext" in str(ei.value)


def test_digest_cleartext_allowed_non_prod_with_escape(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(INSECURE_TLS_ESCAPE_ENV, "1")
    with active_hop_posture(_STAGING_PHI):
        h = digest_handler_from_settings(
            {"http_auth": "digest", "http_auth_user": "u", "http_auth_password": "p"},
            url="http://api.example.com/x",
        )
    assert h is not None  # WARN, not REFUSE — the challenge-answering handler is still built


def test_digest_cleartext_allowed_when_attested(monkeypatch: pytest.MonkeyPatch) -> None:
    # tls_hop_attested (read from settings, as _dest_config threads it) crosses even a prod-PHI hop.
    monkeypatch.delenv(INSECURE_TLS_ESCAPE_ENV, raising=False)
    with active_hop_posture(_PROD_PHI):
        h = digest_handler_from_settings(
            {
                "http_auth": "digest",
                "http_auth_user": "u",
                "http_auth_password": "p",
                "tls_hop_attested": True,
            },
            url="http://api.example.com/x",
        )
    assert h is not None


# --- wiring the provider into a REST destination -----------------------------


def _rest_from(spec_settings: dict[str, object]) -> RestDestination:
    d = build_destination(
        Destination(name="OB_REST", type=ConnectorType.REST, settings=spec_settings)
    )
    assert isinstance(d, RestDestination)
    return d


def test_with_oauth2_wires_bearer_provider() -> None:
    spec = with_oauth2_client_credentials(
        Rest(url=URL),
        token_url=TOKEN_URL,
        client_id="cid",
        client_secret="s3cr3t",
    )
    dest = _rest_from(spec.settings)
    assert isinstance(dest._token_provider, OAuth2ClientCredentialsProvider)


def test_rest_oauth2_bearer_on_the_wire() -> None:
    spec = with_oauth2_client_credentials(
        Rest(url=URL), token_url=TOKEN_URL, client_id="cid", client_secret="s3cr3t"
    )
    dest = _rest_from(spec.settings)

    class _P:
        def access_token(self) -> str:
            return "AT-xyz"

        def invalidate(self) -> None:
            pass

    dest._token_provider = _P()  # type: ignore[assignment]

    class _Resp:
        headers: dict[str, str] = {}
        status = 200

        def read(self) -> bytes:
            return b"ok"

        def __enter__(self) -> _Resp:
            return self

        def __exit__(self, *a: object) -> bool:
            return False

    seen: dict[str, str] = {}

    class _Op:
        def open(self, req: urllib.request.Request, timeout: float | None = None) -> _Resp:
            seen["auth"] = req.get_header("Authorization", "")
            return _Resp()

    dest._opener = _Op()  # type: ignore[assignment]
    dest._post("payload")
    assert seen["auth"] == "Bearer AT-xyz"


# --- HTTP Digest -------------------------------------------------------------


def test_digest_handler_built_and_folded_into_opener() -> None:
    spec = with_http_digest(Rest(url=URL), user="u", password="p")
    dest = _rest_from(spec.settings)
    # The per-connection opener carries a digest handler (never the shared _NO_REDIRECT_OPENER).
    assert any(isinstance(h, urllib.request.HTTPDigestAuthHandler) for h in dest._opener.handlers)


def test_digest_handler_from_settings_off_by_default() -> None:
    assert digest_handler_from_settings(Rest(url=URL).settings, url=URL) is None


def test_digest_missing_credentials_fails_loud() -> None:
    with pytest.raises(HttpAuthError):
        digest_handler_from_settings({"http_auth": "digest", "http_auth_user": "u"}, url=URL)


def test_digest_cleartext_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(INSECURE_TLS_ESCAPE_ENV, raising=False)
    with pytest.raises(HttpAuthError) as ei:
        digest_handler_from_settings(
            {"http_auth": "digest", "http_auth_user": "u", "http_auth_password": "p"},
            url="http://api.example.com/x",
        )
    assert "cleartext" in str(ei.value)


# --- guardrails --------------------------------------------------------------


def test_default_no_auth_is_byte_identical() -> None:
    dest = _rest_from(Rest(url=URL).settings)
    assert dest._token_provider is None
    assert not any(
        isinstance(h, urllib.request.HTTPDigestAuthHandler) for h in dest._opener.handlers
    )


def test_bearer_and_digest_mutually_exclusive() -> None:
    spec = with_oauth2_client_credentials(
        with_http_digest(Rest(url=URL), user="u", password="p"),
        token_url=TOKEN_URL,
        client_id="cid",
        client_secret="s",
    )
    with pytest.raises(HttpAuthError):
        _rest_from(spec.settings)


def test_smart_and_oauth2_mutually_exclusive() -> None:
    s = {"smart_token_url": TOKEN_URL, "oauth2_token_url": TOKEN_URL}
    with pytest.raises(HttpAuthError):
        bearer_provider_from_settings(s)


def test_with_oauth2_rejects_non_http_connector() -> None:
    from messagefoundry.config.wiring import MLLP

    with pytest.raises(HttpAuthError):
        with_oauth2_client_credentials(
            MLLP(host="h", port=1), token_url=TOKEN_URL, client_id="c", client_secret="s"
        )


def test_oauth2_cc_on_soap_injects_bearer() -> None:
    from messagefoundry.transports.soap import SoapDestination

    spec = with_oauth2_client_credentials(
        Soap(url=URL), token_url=TOKEN_URL, client_id="cid", client_secret="s"
    )
    d = build_destination(
        Destination(name="OB_SOAP", type=ConnectorType.SOAP, settings=spec.settings)
    )
    assert isinstance(d, SoapDestination)
    assert isinstance(d._token_provider, OAuth2ClientCredentialsProvider)
