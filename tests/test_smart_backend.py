# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""SMART Backend Services token provider (ADR 0024).

Covers the signer extension (RS384/ES384 sign+verify, P-384 curve enforcement, the attached compact
JWT shape), the token provider (assertion claims, token acquisition + expiry caching + invalidate,
PHI/secret-safe failures, cleartext refusal), the connector injection (a fresh bearer per request in
FHIR/REST ``_post`` + the 401 re-mint), the egress gate on the token endpoint, the ``with_smart_backend``
composer, and ``smart_private_key`` redaction. The HTTP opener is faked so nothing hits the network; the
async ``send`` tests construct fresh state per test (shared-loop safe, BACKLOG #17)."""

from __future__ import annotations

import email.message
import io
import json
import time
import urllib.error
import urllib.parse
import urllib.request

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from messagefoundry.config.models import ConnectorType, Destination, SignatureAlgorithm
from messagefoundry.config.settings import EgressSettings
from messagefoundry.config.wiring import FHIR, MLLP, Rest, WiringError, redacted_settings
from messagefoundry.pipeline.wiring_runner import check_egress_allowed
from messagefoundry.transports import build_destination
from messagefoundry.transports.base import DeliveryError
from messagefoundry.transports.fhir import FhirDestination
from messagefoundry.transports.rest import RestDestination
from messagefoundry.transports.signing import (
    CompactJwtSigner,
    SigningError,
    _b64u_decode,
    _verify,
)
from messagefoundry.transports.smart import (
    _CLIENT_ASSERTION_TYPE,
    SmartAuthError,
    SmartBackendTokenProvider,
    token_provider_from_destination,
    with_smart_backend,
)

TOKEN_URL = "https://auth.example/token"
FHIR_BASE = "https://fhir.example/fhir"
REST_URL = "https://partner.example/ingest"
PATIENT = json.dumps({"resourceType": "Patient", "id": "p-1", "name": [{"family": "X"}]})


# --- key fixtures (synthetic, per session) -----------------------------------


def _pem(key: object) -> str:
    return key.private_bytes(  # type: ignore[attr-defined]
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode("ascii")


@pytest.fixture(scope="session")
def rsa_pem() -> str:
    return _pem(rsa.generate_private_key(public_exponent=65537, key_size=2048))


@pytest.fixture(scope="session")
def ec256_pem() -> str:
    return _pem(ec.generate_private_key(ec.SECP256R1()))


@pytest.fixture(scope="session")
def ec384_pem() -> str:
    return _pem(ec.generate_private_key(ec.SECP384R1()))


# --- fake HTTP opener (mirrors test_fhir_transport / test_outbound_signing) ---


def _http_error(code: int, body: bytes = b"") -> urllib.error.HTTPError:
    return urllib.error.HTTPError(TOKEN_URL, code, "err", email.message.Message(), io.BytesIO(body))


class _FakeResp:
    def __init__(self, body: bytes = b"", status: int = 200) -> None:
        self._body = body
        self.status = status

    def read(self) -> bytes:
        return self._body

    def __enter__(self) -> _FakeResp:
        return self

    def __exit__(self, *a: object) -> bool:
        return False


class _FakeOpener:
    """Records each Request, then returns a chosen response or raises a chosen error."""

    def __init__(self, exc: Exception | None = None, body: bytes = b"", status: int = 200) -> None:
        self.exc = exc
        self.body = body
        self.status = status
        self.requests: list[urllib.request.Request] = []

    def open(self, req: urllib.request.Request, timeout: float | None = None) -> _FakeResp:
        self.requests.append(req)
        if self.exc is not None:
            raise self.exc
        return _FakeResp(self.body, self.status)


def _token_opener(token: str = "TOK", expires_in: int = 300) -> _FakeOpener:
    body = json.dumps(
        {"access_token": token, "token_type": "bearer", "expires_in": expires_in}
    ).encode()
    return _FakeOpener(body=body)


def _provider(pem: str, **over: object) -> SmartBackendTokenProvider:
    kwargs: dict[str, object] = {
        "token_url": TOKEN_URL,
        "client_id": "cid",
        "private_key": pem,
        "algorithm": SignatureAlgorithm.RS384,
        "scope": "system/*.rs",
    }
    kwargs.update(over)
    return SmartBackendTokenProvider(**kwargs)  # type: ignore[arg-type]


def _verify_compact(jwt: str, signer: CompactJwtSigner, alg: SignatureAlgorithm) -> None:
    header_b64, claims_b64, sig_b64 = jwt.split(".")
    signing_input = f"{header_b64}.{claims_b64}".encode("ascii")
    _verify(signer.public_key, alg, signing_input, _b64u_decode(sig_b64))  # raises on mismatch


# --- signer extension: RS384 / ES384 / compact JWT ---------------------------


def test_signature_algorithm_has_384_members() -> None:
    assert SignatureAlgorithm("RS384") is SignatureAlgorithm.RS384
    assert SignatureAlgorithm("ES384") is SignatureAlgorithm.ES384


def test_rs384_compact_roundtrip(rsa_pem: str) -> None:
    signer = CompactJwtSigner(private_key=rsa_pem, algorithm=SignatureAlgorithm.RS384, key_id="k1")
    jwt = signer.sign({"iss": "c", "exp": 1})
    assert len(jwt.split(".")) == 3
    _verify_compact(jwt, signer, SignatureAlgorithm.RS384)


def test_es384_compact_roundtrip(ec384_pem: str) -> None:
    signer = CompactJwtSigner(private_key=ec384_pem, algorithm=SignatureAlgorithm.ES384)
    jwt = signer.sign({"iss": "c", "exp": 1})
    _verify_compact(jwt, signer, SignatureAlgorithm.ES384)


def test_es384_signature_is_96_bytes(ec384_pem: str) -> None:
    # P-384 r||s is two 48-byte coordinates — the JOSE width the verifier expects.
    signer = CompactJwtSigner(private_key=ec384_pem, algorithm=SignatureAlgorithm.ES384)
    sig = _b64u_decode(signer.sign({"a": 1}).split(".")[2])
    assert len(sig) == 96


def test_es384_rejects_p256_key(ec256_pem: str) -> None:
    with pytest.raises(SigningError, match="secp384r1"):
        CompactJwtSigner(private_key=ec256_pem, algorithm=SignatureAlgorithm.ES384)


def test_rs384_is_deterministic(rsa_pem: str) -> None:
    signer = CompactJwtSigner(private_key=rsa_pem, algorithm=SignatureAlgorithm.RS384)
    claims = {"iss": "c", "exp": 1, "jti": "fixed"}
    assert signer.sign(claims) == signer.sign(claims)  # PKCS1-v1_5 is deterministic


def test_es384_is_randomized(ec384_pem: str) -> None:
    signer = CompactJwtSigner(private_key=ec384_pem, algorithm=SignatureAlgorithm.ES384)
    claims = {"iss": "c", "exp": 1, "jti": "fixed"}
    assert signer.sign(claims) != signer.sign(claims)  # ECDSA is randomized


def test_compact_header_has_typ_and_kid(rsa_pem: str) -> None:
    signer = CompactJwtSigner(private_key=rsa_pem, algorithm=SignatureAlgorithm.RS384, key_id="k9")
    header = json.loads(_b64u_decode(signer.sign({"a": 1}).split(".")[0]))
    assert header == {"alg": "RS384", "typ": "JWT", "kid": "k9"}


# --- token provider: acquisition, caching, claims ----------------------------


def test_token_acquired_and_cached(rsa_pem: str) -> None:
    provider = _provider(rsa_pem)
    opener = _token_opener()
    provider._opener = opener  # type: ignore[assignment]
    assert provider.access_token() == "TOK"
    assert provider.access_token() == "TOK"
    assert len(opener.requests) == 1  # cached, not re-fetched within expiry
    provider.invalidate()
    assert provider.access_token() == "TOK"
    assert len(opener.requests) == 2  # re-minted after invalidate


def test_token_re_minted_when_expired(rsa_pem: str) -> None:
    # expires_in below the skew → the token is already "expired" on return, so each call re-fetches.
    provider = _provider(rsa_pem, expiry_skew_seconds=60.0)
    opener = _token_opener(expires_in=1)
    provider._opener = opener  # type: ignore[assignment]
    provider.access_token()
    provider.access_token()
    assert len(opener.requests) == 2


def test_assertion_claims_and_form(rsa_pem: str) -> None:
    provider = _provider(rsa_pem)
    opener = _token_opener()
    provider._opener = opener  # type: ignore[assignment]
    provider.access_token()
    form = urllib.parse.parse_qs(opener.requests[0].data.decode())  # type: ignore[union-attr]
    assert form["grant_type"] == ["client_credentials"]
    assert form["client_assertion_type"] == [
        "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
    ]
    assert form["scope"] == ["system/*.rs"]
    claims = json.loads(_b64u_decode(form["client_assertion"][0].split(".")[1]))
    assert claims["iss"] == claims["sub"] == "cid"
    assert claims["aud"] == TOKEN_URL
    now = int(time.time())
    assert now < claims["exp"] <= now + 300  # SMART: exp is in the future, <= 5 min ceiling
    assert claims["jti"]


def test_token_http_error_is_secret_safe(rsa_pem: str) -> None:
    provider = _provider(rsa_pem)
    leaky = b'{"error":"invalid_client","access_token":"LEAKED-TOKEN"}'
    provider._opener = _FakeOpener(exc=_http_error(400, leaky))  # type: ignore[assignment]
    with pytest.raises(DeliveryError) as ei:
        provider.access_token()
    assert "LEAKED-TOKEN" not in str(ei.value)
    assert "400" in str(ei.value)


def test_asvs_191_smart_oauth_controls_exercised(rsa_pem: str) -> None:
    """BACKLOG #191 — drive the built SMART Backend Services outbound so the five ASVS L3 OAuth/JWS
    controls are demonstrably *effective*, not merely present: 9.1.2 (alg allowlist, no 'None'),
    9.2.4 (audience binding), 10.1.1 (token never leaked), 10.2.3 (only required scopes), 10.4.10
    (private_key_jwt backchannel, no shared secret). Evidence for the Partial→Pass flip in
    docs/security/ASVS-L3-ASSESSMENT-2026-07-09.md."""
    # 9.1.2 — the signing-algorithm allowlist has no 'None'/'none' and rejects it at the enum boundary.
    algs = {m.value for m in SignatureAlgorithm}
    assert "none" not in {a.lower() for a in algs}
    for bad in ("none", "None"):
        with pytest.raises(ValueError):
            SignatureAlgorithm(bad)

    provider = _provider(rsa_pem)
    opener = _token_opener()
    provider._opener = opener  # type: ignore[assignment]
    provider.access_token()
    form = urllib.parse.parse_qs(opener.requests[0].data.decode())  # type: ignore[union-attr]
    # …and the minted assertion's JOSE header carries an asymmetric alg, never 'none'.
    header = json.loads(_b64u_decode(form["client_assertion"][0].split(".")[0]))
    assert header["alg"] in {"RS384", "ES384"} and header["alg"].lower() != "none"

    # 10.4.10 — the confidential client authenticates the token backchannel with private_key_jwt and
    # carries NO shared secret in any form.
    assert form["grant_type"] == ["client_credentials"]
    assert form["client_assertion_type"] == [_CLIENT_ASSERTION_TYPE]
    assert len(form["client_assertion"][0].split(".")) == 3  # a compact JWS (header.claims.sig)
    assert not ({"client_secret", "client_secret_post", "client_secret_basic"} & form.keys())

    # 10.2.3 — request exactly the configured scope, and OMIT the field entirely when unset (the gap the
    # suite otherwise missed: it asserted scope PRESENCE when set, never its ABSENCE when unset).
    assert form["scope"] == ["system/*.rs"]
    unscoped = _provider(rsa_pem, scope=None)
    un_op = _token_opener()
    unscoped._opener = un_op  # type: ignore[assignment]
    unscoped.access_token()
    assert "scope" not in urllib.parse.parse_qs(un_op.requests[0].data.decode())  # type: ignore[union-attr]

    # 9.2.4 — every assertion carries an aud bound to the pinned token endpoint (anti-replay); a missing
    # endpoint is refused so aud can never be left unbound.
    claims = json.loads(_b64u_decode(form["client_assertion"][0].split(".")[1]))
    assert claims["aud"] == TOKEN_URL
    with pytest.raises(SmartAuthError):
        _provider(rsa_pem, token_url="")

    # 10.1.1 — the credential is sent only to the token endpoint and never leaked: a token-endpoint
    # failure surfaces no bearer/assertion bytes.
    leaky = _provider(rsa_pem)
    leaky._opener = _FakeOpener(exc=_http_error(401, b'{"access_token":"LEAK-TOK"}'))  # type: ignore[assignment]
    with pytest.raises(DeliveryError) as ei:
        leaky.access_token()
    assert "LEAK-TOK" not in str(ei.value)


def test_token_unparseable_response_is_secret_safe(rsa_pem: str) -> None:
    provider = _provider(rsa_pem)
    provider._opener = _FakeOpener(body=b"<html>SECRET-BODY</html>")  # type: ignore[assignment]
    with pytest.raises(DeliveryError) as ei:
        provider.access_token()
    assert "SECRET-BODY" not in str(ei.value)


def test_cleartext_token_url_refused(rsa_pem: str) -> None:
    with pytest.raises(SmartAuthError, match="cleartext"):
        SmartBackendTokenProvider(
            token_url="http://auth.example/token", client_id="c", private_key=rsa_pem
        )


def test_missing_client_id_refused(rsa_pem: str) -> None:
    with pytest.raises(SmartAuthError, match="client_id"):
        SmartBackendTokenProvider(token_url=TOKEN_URL, client_id="", private_key=rsa_pem)


def test_missing_private_key_refused() -> None:
    with pytest.raises(SmartAuthError, match="private_key"):
        SmartBackendTokenProvider(token_url=TOKEN_URL, client_id="c", private_key="")


# --- composer + provider-from-destination ------------------------------------


def test_composer_rejects_non_rest_fhir() -> None:
    with pytest.raises(SmartAuthError, match="REST/FHIR"):
        with_smart_backend(
            MLLP(host="h", port=1), token_url=TOKEN_URL, client_id="c", private_key="k"
        )


def test_provider_off_by_default() -> None:
    dest = Destination(name="OB", type=ConnectorType.FHIR, settings=FHIR(url=FHIR_BASE).settings)
    assert token_provider_from_destination(dest) is None


def test_provider_disabled_returns_none() -> None:
    spec = with_smart_backend(
        FHIR(url=FHIR_BASE), token_url=TOKEN_URL, client_id="c", private_key="k", enabled=False
    )
    dest = Destination(name="OB", type=ConnectorType.FHIR, settings=spec.settings)
    assert token_provider_from_destination(dest) is None


# --- connector injection (FHIR + REST), 401 re-mint --------------------------


def _smart_fhir(pem: str) -> FhirDestination:
    spec = with_smart_backend(
        FHIR(url=FHIR_BASE), token_url=TOKEN_URL, client_id="c", private_key=pem
    )
    dest = build_destination(
        Destination(name="OB", type=ConnectorType.FHIR, settings=spec.settings)
    )
    assert isinstance(dest, FhirDestination)
    return dest


async def test_fhir_injects_smart_bearer_per_request(rsa_pem: str) -> None:
    dest = _smart_fhir(rsa_pem)
    dest._token_provider._opener = _token_opener()  # type: ignore[union-attr,assignment]
    fhir_opener = _FakeOpener(body=b"", status=201)
    dest._opener = fhir_opener  # type: ignore[assignment]
    await dest.send(PATIENT)
    assert fhir_opener.requests[0].get_header("Authorization") == "Bearer TOK"


def test_cleartext_data_url_with_smart_refused(rsa_pem: str) -> None:
    # The SMART bearer is injected per-request, so the static-header cleartext check can't see it — the
    # connector must still refuse an http:// DATA url + SMART (the token would ship over cleartext).
    spec = with_smart_backend(
        FHIR(url="http://fhir.example/fhir"),
        token_url=TOKEN_URL,
        client_id="c",
        private_key=rsa_pem,
    )
    with pytest.raises(ValueError, match="cleartext http"):
        build_destination(Destination(name="OB", type=ConnectorType.FHIR, settings=spec.settings))


async def test_fhir_401_invalidates_token(rsa_pem: str) -> None:
    dest = _smart_fhir(rsa_pem)
    dest._token_provider._opener = _token_opener()  # type: ignore[union-attr,assignment]
    dest._opener = _FakeOpener(exc=_http_error(401))  # type: ignore[assignment]
    with pytest.raises(DeliveryError, match="refreshing SMART token"):
        await dest.send(PATIENT)
    assert dest._token_provider._cached_token is None  # type: ignore[union-attr]


async def test_rest_injects_smart_bearer(rsa_pem: str) -> None:
    spec = with_smart_backend(
        Rest(url=REST_URL), token_url=TOKEN_URL, client_id="c", private_key=rsa_pem
    )
    dest = build_destination(
        Destination(name="OB", type=ConnectorType.REST, settings=spec.settings)
    )
    assert isinstance(dest, RestDestination)
    dest._token_provider._opener = _token_opener()  # type: ignore[union-attr,assignment]
    rest_opener = _FakeOpener(body=b"", status=200)
    dest._opener = rest_opener  # type: ignore[assignment]
    await dest.send("{}")
    assert rest_opener.requests[0].get_header("Authorization") == "Bearer TOK"


async def test_plain_fhir_has_no_token_provider() -> None:
    dest = build_destination(
        Destination(name="OB", type=ConnectorType.FHIR, settings=FHIR(url=FHIR_BASE).settings)
    )
    assert isinstance(dest, FhirDestination)
    assert dest._token_provider is None


# --- egress gate on the token endpoint + secret redaction --------------------


def test_egress_gates_unlisted_token_endpoint(rsa_pem: str) -> None:
    spec = with_smart_backend(
        FHIR(url=FHIR_BASE), token_url="https://auth.evil/token", client_id="c", private_key=rsa_pem
    )
    dest = Destination(name="OB", type=ConnectorType.FHIR, settings=spec.settings)
    with pytest.raises(WiringError, match="SMART token endpoint"):
        check_egress_allowed(dest, EgressSettings(allowed_http=["fhir.example"]))


def test_egress_allows_listed_token_endpoint(rsa_pem: str) -> None:
    spec = with_smart_backend(
        FHIR(url=FHIR_BASE), token_url=TOKEN_URL, client_id="c", private_key=rsa_pem
    )
    dest = Destination(name="OB", type=ConnectorType.FHIR, settings=spec.settings)
    # both the FHIR base and the token endpoint are allow-listed → no raise
    check_egress_allowed(dest, EgressSettings(allowed_http=["fhir.example", "auth.example"]))


def test_smart_private_key_redacted(rsa_pem: str) -> None:
    spec = with_smart_backend(
        FHIR(url=FHIR_BASE),
        token_url=TOKEN_URL,
        client_id="c",
        private_key=rsa_pem,
        private_key_password="pw",
    )
    red = redacted_settings(spec.settings)
    assert red["smart_private_key"] == "***"
    assert red["smart_private_key_password"] == "***"
    assert "BEGIN" not in json.dumps(red)  # the PEM never appears in the metadata view


# --- S12 audit anchors (ADDED-1): aud==token endpoint + structural-only --------
# The S12 clinical-surface audit verdict for SMART/OAuth is CONFORMING. These regression tests PIN the
# load-bearing invariants so a refactor can't silently regress them. Per the audit scope they assert
# STRUCTURAL fields only — never a bearer/token/assertion-signature VALUE.


def test_audit_aud_defaults_to_token_endpoint(rsa_pem: str) -> None:
    # RFC 7523 / SMART Backend Services: the client_assertion `aud` MUST be the token endpoint unless the
    # server documents another audience. With no explicit audience, aud == token_url (per-mint, structural).
    provider = _provider(rsa_pem)
    assert provider.audience == TOKEN_URL
    claims = provider._assertion_claims()
    assert (
        claims["aud"] == TOKEN_URL
    )  # the value the SMART AS validates to bind the assertion to itself


def test_audit_explicit_audience_overrides_token_endpoint(rsa_pem: str) -> None:
    # When a server documents a distinct audience, it is honored verbatim (still structural, no secret).
    explicit = "https://auth.example/oauth2/aud"
    provider = _provider(rsa_pem, audience=explicit)
    assert provider.audience == explicit
    assert provider._assertion_claims()["aud"] == explicit


def test_audit_aud_tracks_a_distinct_token_url(rsa_pem: str) -> None:
    # The default-aud invariant must follow whatever token_url is configured (not a hardcoded constant) —
    # a mis-wired aud would let an assertion minted for one AS be replayed at another.
    other = "https://other-as.example/token"
    provider = _provider(rsa_pem, token_url=other)
    assert provider._assertion_claims()["aud"] == other


def test_audit_token_post_never_asserts_a_token_value(rsa_pem: str) -> None:
    # Structural-only contract: the assertion POST carries the SMART-mandated grant fields; the test
    # asserts their PRESENCE/shape, never the signed-assertion bytes or any returned bearer value.
    provider = _provider(rsa_pem)
    opener = _token_opener(token="MUST-NOT-BE-ASSERTED")
    provider._opener = opener  # type: ignore[assignment]
    token = provider.access_token()
    form = urllib.parse.parse_qs(opener.requests[0].data.decode())  # type: ignore[union-attr]
    # The assertion is PRESENT and compact (three dot-separated segments) — shape only, not its bytes.
    assert form["client_assertion_type"] == [_CLIENT_ASSERTION_TYPE]
    assert len(form["client_assertion"][0].split(".")) == 3
    # The bearer round-trips opaquely; we never pin its value beyond "non-empty str" (no value coupling).
    assert isinstance(token, str) and token


def test_audit_token_url_must_be_egress_listed(rsa_pem: str) -> None:
    # ADDED-1 requires the [egress].allowed_http gate to cover smart_token_url SPECIFICALLY (a second
    # egress host beyond the FHIR base). Listing only the data host but not the token host is refused.
    spec = with_smart_backend(
        FHIR(url=FHIR_BASE), token_url=TOKEN_URL, client_id="c", private_key=rsa_pem
    )
    dest = Destination(name="OB", type=ConnectorType.FHIR, settings=spec.settings)
    with pytest.raises(WiringError, match="SMART token endpoint"):
        check_egress_allowed(dest, EgressSettings(allowed_http=["fhir.example"]))
