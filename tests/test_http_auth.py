# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Generic outbound HTTP auth on the REST/SOAP/FHIR destinations (BACKLOG #65, ADR 0024 amendment).

Covers the two built modes: (1) OAuth2 client-credentials with a SYMMETRIC secret — fetches + caches a
bearer, injects ``Authorization: Bearer …`` per request, re-mints on invalidate, fails loud on a bad/
missing secret (redacted); (2) HTTP Digest — the connector folds a challenge-answering handler into a
per-connection opener. Plus the guardrails: default (no auth) is byte-identical, cleartext refusals, and
mutual exclusion. (NTLM/Negotiate is a documented follow-up — connection-bound; see the module docstring.)
"""

from __future__ import annotations

import http.client
import json
import time
import urllib.request

import pytest

from messagefoundry.config.models import ConnectorType, Destination
from messagefoundry.config.settings import INSECURE_TLS_ESCAPE_ENV
from messagefoundry.config.tls_policy import HopPosture, active_hop_posture
from messagefoundry.config.wiring import Rest, Soap
from messagefoundry.transports import build_destination
from messagefoundry.transports.base import DeliveryError, NegativeAckError
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

    def read(self, amt: int = -1) -> bytes:
        return self._body if amt < 0 else (self._body)[:amt]

    def __enter__(self) -> _FakeTokenResp:
        return self

    def __exit__(self, *a: object) -> bool:
        return False


class _RecordingOpener:
    def __init__(self, body: bytes = b"", exc: BaseException | None = None) -> None:
        self._body = body
        self._exc = exc
        self.requests: list[urllib.request.Request] = []

    def open(self, req: urllib.request.Request, timeout: float | None = None) -> _FakeTokenResp:
        self.requests.append(req)
        if self._exc is not None:
            raise self._exc
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
    with pytest.raises(DeliveryError) as err:
        p.access_token()
    # BACKLOG #2048: the decode error holds the whole reply, bearer included, so it must not ride
    # the chain. The refusal is raised outside any handler.
    assert err.value.__cause__ is None and err.value.__context__ is None


@pytest.mark.parametrize(
    ("opener", "match"),
    [
        (_RecordingOpener(exc=http.client.BadStatusLine("garbage")), "malformed HTTP reply"),
        (_RecordingOpener(b"[" * 200_000), "unparseable"),
        (
            _RecordingOpener(b'{"access_token":"TOK","expires_in":' + b"9" * 400 + b"}"),
            "unparseable",
        ),
    ],
    ids=["bad-status-line", "deep-nesting", "huge-expires-in"],
)
def test_oauth2_cc_mint_failures_keep_the_delivery_error_contract(
    opener: _RecordingOpener, match: str
) -> None:
    # BACKLOG #2054: each of these escaped access_token() as a non-DeliveryError, the same three
    # #1980 closed in the SMART provider. The message names the redacted endpoint, never the reply.
    p = _oauth_provider()
    p._opener = opener  # type: ignore[assignment]
    with pytest.raises(DeliveryError, match=match) as err:
        p.access_token()
    assert "OAuth2 token endpoint" in str(err.value)
    assert "garbage" not in str(err.value)
    assert "s3cr3t" not in str(err.value)


@pytest.mark.parametrize(
    ("expires_in", "cached_for"),
    [
        # json.loads reads 1e999 as inf. Before BACKLOG #2054 that cached the token forever.
        (b"1e999", 3600.0),
        (b"Infinity", 3600.0),
        # A finite but absurd lifetime is clamped the same way.
        (b"1e300", 3600.0),
        # NaN is treated as a missing expires_in: 300 s less the 60 s skew.
        (b"NaN", 240.0),
        # A negative lifetime caches nothing, as it always did.
        (b"-1e999", 0.0),
        # An ordinary lifetime is untouched: 3600 s less the 60 s skew.
        (b"3600", 3540.0),
        # A JSON boolean is no lifetime: the 300 s fallback, not 1 s or 0 s.
        (b"true", 240.0),
    ],
    ids=["1e999", "inf", "1e300", "nan", "-1e999", "ordinary", "bool"],
)
def test_oauth2_cc_token_cache_is_bounded_whatever_expires_in_says(
    expires_in: bytes, cached_for: float
) -> None:
    p = _oauth_provider()
    p._opener = _RecordingOpener(  # type: ignore[assignment]
        b'{"access_token":"TOK","expires_in":' + expires_in + b"}"
    )
    before = time.monotonic()
    assert p.access_token() == "TOK"
    after = time.monotonic()
    # Both bounds, so a clamp that caches for zero seconds fails as surely as one that never clamps.
    assert before + cached_for <= p._cached_expiry_monotonic <= after + cached_for


def test_oauth2_cc_cache_ceiling_applies_after_the_skew() -> None:
    # A skew as large as the ceiling still caches a long-lived token for the full ceiling.
    p = _oauth_provider(expiry_skew_seconds=3600.0)
    p._opener = _RecordingOpener(  # type: ignore[assignment]
        b'{"access_token":"TOK","expires_in":86400}'
    )
    before = time.monotonic()
    p.access_token()
    after = time.monotonic()
    # Both bounds: the lower one fails if the skew eats the ceiling, the upper one if nothing clamps.
    assert before + 3600.0 <= p._cached_expiry_monotonic <= after + 3600.0


# --- BACKLOG #2114: a token an Authorization header cannot carry is refused at mint ---------------

#: CR, LF and non-latin-1 would be cached, then refused by http.client at send time on every
#: message until the cache lapsed. The rest go through putheader, and are refused because no RFC
#: 6750 bearer holds them.
UNSENDABLE_TOKENS = {
    "crlf": "AT\r\nX-Injected: 1",
    "bare-lf": "AT\nX",
    "bare-cr": "AT\rX",
    "nul": "AT\x00X",
    "tab": "AT\tX",
    "space": "AT X",
    "del": "AT\x7fX",
    "latin-1-letter": "AT-é",
    "non-latin-1": "AT-€",
}


def _token_body(token: str) -> bytes:
    return json.dumps({"access_token": token, "expires_in": 3600}).encode()


@pytest.mark.parametrize("token", list(UNSENDABLE_TOKENS.values()), ids=list(UNSENDABLE_TOKENS))
def test_oauth2_cc_refuses_a_token_a_header_cannot_carry(token: str) -> None:
    p = _oauth_provider()
    p._opener = _RecordingOpener(_token_body(token))  # type: ignore[assignment]
    with pytest.raises(DeliveryError, match="access_token an HTTP header cannot carry") as err:
        p.access_token()
    assert "OAuth2 token endpoint" in str(err.value)
    assert token not in str(err.value)
    assert err.value.__cause__ is None and err.value.__context__ is None
    # Nothing was cached, so the next mint asks again and a good reply is used at once.
    assert p._cached_token is None
    good = _RecordingOpener(_token_body("AT-good"))
    p._opener = good  # type: ignore[assignment]
    assert p.access_token() == "AT-good"
    assert len(good.requests) == 1


@pytest.mark.parametrize(
    "token",
    ["eyJhbGciOi.eyJzdWIi.c2ln-_", "abc+/def==", "opaque~token!#$%&'*"],
    ids=["jwt", "b64-padded", "other-visible-ascii"],
)
def test_oauth2_cc_still_accepts_a_visible_ascii_token(token: str) -> None:
    # The control: the refusal above is the character test and not a refusal of every token.
    p = _oauth_provider()
    p._opener = _RecordingOpener(_token_body(token))  # type: ignore[assignment]
    assert p.access_token() == token


def test_both_bearer_providers_share_one_token_hop_and_cache() -> None:
    """BACKLOG #2115: the token hop and the cache live once, on the shared base. A provider that
    overrode one of these would be the copy a later fix misses, as #1980 and #1498 each did."""
    from messagefoundry.transports.smart import SmartBackendTokenProvider, _TokenEndpointProvider

    shared = (
        "_check_token_url",
        "_open_token_hop",
        "_post_token",
        "access_token",
        "invalidate",
    )
    for provider in (SmartBackendTokenProvider, OAuth2ClientCredentialsProvider):
        assert issubclass(provider, _TokenEndpointProvider)
        assert [name for name in shared if name in vars(provider)] == []
        assert "_fetch_token" in vars(provider)


def test_the_refused_shapes_are_ones_http_client_refuses_at_send() -> None:
    """The premise of BACKLOG #2114, measured: http.client refuses these header values with a
    ValueError, which the destinations classify as a permanent bad-request-value."""
    conn = http.client.HTTPConnection("h.example.test")
    conn.putrequest("POST", "/")
    for shape in ("crlf", "bare-lf", "bare-cr", "non-latin-1"):
        with pytest.raises(ValueError):
            conn.putheader("Authorization", f"Bearer {UNSENDABLE_TOKENS[shape]}")


# --- #200 posture-keyed cleartext refusal (the delivery-cell invariant now holds here too) ---------
#
# Before this fix both cleartext refusals gated on the blunt global MEFOR_ALLOW_INSECURE_TLS, so a
# prod-PHI operator who SET the escape could leak the client_secret (OAuth2) / digest credential over
# cleartext http to the token-endpoint / delivery host — a gap the delivery URL (re-keyed by #200) did
# not have. Both refusals now consume the SAME posture-keyed authority: prod-PHI REFUSES even with the
# escape set (the escape is inert for prod-PHI), non-prod / attested is permitted (as the delivery cells
# do), and the default (unstamped → fail-closed prod-PHI, e.g. the two tests above) still refuses.

_PROD_PHI = HopPosture(enforcing=True)
_STAGING_PHI = HopPosture(enforcing=False)  # non-prod PHI


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


def test_oauth2_cleartext_token_endpoint_allowed_when_accepted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """ADR 0153: the token-endpoint hop takes the same per-connection declaration as its delivery hop.

    It replaces the escape this test used to rely on (decision 5 unhooked that). Threading the pair here
    is deliberate even though a credential is worse on the wire than a body: without it, an operator
    whose legacy peer needs OAuth2 over a cleartext segment would have to write a FALSE
    `tls_hop_attested`, which is the exact defect ADR 0153 exists to remove."""
    monkeypatch.delenv(INSECURE_TLS_ESCAPE_ENV, raising=False)
    with active_hop_posture(_PROD_PHI):
        p = _oauth_provider(
            token_url="http://auth.example.com/token",
            cleartext_accepted=True,
            cleartext_reason="legacy IdP has no TLS listener",
        )
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


def test_digest_cleartext_allowed_when_accepted(monkeypatch: pytest.MonkeyPatch) -> None:
    # ADR 0153: the declaration (mirrored into the resolved settings by _dest_config) replaces the
    # escape this test used to rely on. WARN + audit, not a silent crossing.
    monkeypatch.delenv(INSECURE_TLS_ESCAPE_ENV, raising=False)
    with active_hop_posture(_PROD_PHI):
        h = digest_handler_from_settings(
            {
                "http_auth": "digest",
                "http_auth_user": "u",
                "http_auth_password": "p",
                "cleartext_accepted": True,
                "cleartext_reason": "legacy device has no TLS listener",
            },
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

        def read(self, amt: int = -1) -> bytes:
            return b"ok" if amt < 0 else (b"ok")[:amt]

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


@pytest.mark.parametrize(
    "exc",
    [http.client.BadStatusLine("garbage"), http.client.LineTooLong("status line")],
    ids=["bad-status-line", "line-too-long"],
)
@pytest.mark.parametrize("call", ["_post", "_probe"])
def test_rest_oauth2_malformed_token_reply_is_a_delivery_error(
    exc: http.client.HTTPException, call: str
) -> None:
    # BACKLOG #2054: REST mints the OAuth2 bearer before its own try, so the provider must classify
    # a malformed token-endpoint reply itself. A raw HTTPException would escape the destination as
    # an internal error, not a retryable DeliveryError. The data hop must not be reached.
    spec = with_oauth2_client_credentials(
        Rest(url=URL), token_url=TOKEN_URL, client_id="cid", client_secret="s3cr3t"
    )
    dest = _rest_from(spec.settings)
    provider = dest._token_provider
    assert isinstance(provider, OAuth2ClientCredentialsProvider)
    provider._opener = _RecordingOpener(exc=exc)  # type: ignore[assignment]
    data_hop = _RecordingOpener(b"ok")
    dest._opener = data_hop  # type: ignore[assignment]
    with pytest.raises(DeliveryError, match="OAuth2 token endpoint .* malformed HTTP reply") as err:
        dest._post("payload") if call == "_post" else dest._probe()
    assert type(exc).__name__ in str(err.value)
    assert "garbage" not in str(err.value) and "status line" not in str(err.value)
    # The peer's bytes live in the HTTPException's own text, so it must not ride the chain either.
    assert err.value.__cause__ is None and err.value.__context__ is None
    assert data_hop.requests == []


def test_rest_oauth2_unsendable_token_is_a_retryable_failure_not_a_nak() -> None:
    """BACKLOG #2114 through a REST send: the mint is refused as a retryable DeliveryError and
    the data hop is never dialled. The fake data hop runs no putheader, so this does not replay the
    old NAK; test_the_refused_shapes_are_ones_http_client_refuses_at_send measures that premise."""
    spec = with_oauth2_client_credentials(
        Rest(url=URL), token_url=TOKEN_URL, client_id="cid", client_secret="s3cr3t"
    )
    dest = _rest_from(spec.settings)
    provider = dest._token_provider
    assert isinstance(provider, OAuth2ClientCredentialsProvider)
    provider._opener = _RecordingOpener(_token_body(UNSENDABLE_TOKENS["crlf"]))  # type: ignore[assignment]
    data_hop = _RecordingOpener(b"ok")
    dest._opener = data_hop  # type: ignore[assignment]
    with pytest.raises(DeliveryError, match="cannot carry") as err:
        dest._post("payload")
    assert not isinstance(err.value, NegativeAckError)
    assert data_hop.requests == []


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


# --- BACKLOG #1171 (ASVS 11.4.1): the server picks the digest hash, so refuse a disallowed one ------


def _digest_handler() -> urllib.request.HTTPDigestAuthHandler:
    handler = digest_handler_from_settings(
        {"http_auth": "digest", "http_auth_user": "u", "http_auth_password": "p"},
        url=URL,
    )
    assert handler is not None, "the factory returned no handler; the cases below would be vacuous"
    return handler


@pytest.mark.parametrize(
    ("chal", "why"),
    [
        ({"algorithm": "MD5"}, "an endpoint that names MD5 outright"),
        ({}, "an endpoint that names NOTHING -- urllib defaults the parameter to MD5"),
        ({"algorithm": "md5-sess"}, "a -sess form of a disallowed hash, in lowercase"),
        ({"algorithm": "SHA"}, "urllib's non-standard SHA is SHA-1"),
        # The next two were ADMITTED by name before #1171's ground 1 closed, and urllib cannot compute
        # either, so each escaped as a bare ValueError instead of this seam's HttpAuthError.
        ({"algorithm": "SHA-512-256"}, "urllib computes MD5, SHA and SHA-256 only"),
        ({"algorithm": "SHA-256-sess"}, "urllib does not implement any -sess variant"),
    ],
)
def test_a_disallowed_digest_algorithm_is_refused_loudly(chal: dict[str, str], why: str) -> None:
    """Appendix C marks MD5 **D** -- disallowed for any cryptographic purpose, no default-off escape.

    THE ABSENT CASE IS THE ONE THAT MATTERS. It needs no hostile server: a plain RFC 2617 endpoint
    omits ``algorithm``, and ``urllib`` reads ``chal.get('algorithm', 'MD5')``, so the engine answered
    with MD5 by default. The exposure was reachable through ordinary interoperability.

    LOUD, not ``return None``. Skipping the auth silently would surface as a bare 401, which an
    operator reads as bad credentials -- sending them to look in the wrong place entirely.
    """
    handler = _digest_handler()
    full = {"realm": "r", "nonce": "n", **chal}
    with pytest.raises(HttpAuthError) as ei:
        handler.get_authorization(urllib.request.Request(URL), full)
    assert "not an approved hash" in str(ei.value), why


def test_an_approved_digest_algorithm_is_still_answered() -> None:
    """POSITIVE CONTROL: the refusal above must not be "refuse everything".

    Without this, deleting the whole feature would satisfy every case above perfectly, and the tests
    would be reporting a working gate over a connector that can no longer authenticate at all.
    """
    handler = _digest_handler()
    chal = {"realm": "r", "nonce": "n", "algorithm": "SHA-256"}
    # Returns a header string rather than raising; the value itself is urllib's business, not ours.
    result = handler.get_authorization(urllib.request.Request(URL), chal)
    assert result, "an approved algorithm produced no authorization header"


def test_a_lowercase_sha256_challenge_is_answered_as_sha256() -> None:
    """RFC 7616's ABNF literals are case-insensitive, so ``sha-256`` IS SHA-256. urllib matches the
    name case-sensitively and would raise a bare ValueError on it; the handler hands urllib the
    canonical spelling instead, and the answer names the hash it was computed with."""
    handler = _digest_handler()
    chal = {"realm": "r", "nonce": "n", "algorithm": "sha-256"}
    result = handler.get_authorization(urllib.request.Request(URL), chal)
    assert result and 'algorithm="SHA-256"' in result
