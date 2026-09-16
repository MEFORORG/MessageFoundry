# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Byte bounds on every reply the engine reads back off an egress hop (ASVS 15.2.2, BACKLOG #1191).

Before this, each outbound HTTP connector called a bare ``resp.read()``, which reads to EOF. On a
first deployment a hostile or malfunctioning partner would therefore have been able to make the
engine buffer an arbitrarily large response body. No ingress bound reaches that surface: the engine
opened the connection itself and the reply is not a received message, so the count-and-log invariant
never sees it.

**The control is the fake.** :class:`_UnboundedResp` returns exactly as many bytes as it is asked
for, and raises ``AssertionError`` if it is asked for the whole body. A call site that regressed to a
bare ``read()`` therefore fails loudly here rather than passing quietly, and the same fake proves the
bound is enforced ON THE READ (peak buffer = limit + 1) and not after the fact.

**A ceiling is not a completeness check** (BACKLOG #1575). The bound above answered only "did the
peer send too much?", so a reply that stopped short of its own declared ``Content-Length`` came back
as an ordinary value and a deploying site would have had the delivery reported as successful. The
final sections drive REAL ``http.client.HTTPResponse`` objects over ``io.BytesIO`` across all three
reply framings, because accepting chunked and EOF-delimited replies -- neither of which declares a
length -- is what keeps that fix from becoming an outage on every streaming partner. The framing
rules themselves are stated once, in ``transports/bounded_read.py``; these arms measure them rather
than restating them.

Two further groups guard the ways the first cut of that fix went wrong: a body the caller DISCARDS
(a probe, a drain) has no answer to be wrong about and must not be failed for arriving short, and
every site that RETYPES a refusal into its own error class has to retype the whole family, not one
member of it.

Synthetic data only.
"""

from __future__ import annotations

import email.message
import http.client
import io
import json
import logging
import re
import urllib.error
import urllib.request
from pathlib import Path

import pytest

from messagefoundry.auth.oidc.flow import _MAX_TOKEN_RESPONSE_BYTES as _OIDC_TOKEN_BOUND
from messagefoundry.config.fhir_lookup import FhirLookupError
from messagefoundry.config.models import ConnectorType, Destination, SignatureAlgorithm
from messagefoundry.config.wiring import FHIR, DICOMweb, Rest, Soap
from messagefoundry.parsing.peek import DEFAULT_MAX_MESSAGE_BYTES
from messagefoundry.pipeline.alert_sinks import WebhookTransport
from messagefoundry.transports import build_destination
from messagefoundry.transports.ai_broker import AiBroker, AiBrokerError
from messagefoundry.transports.base import DeliveryError
from messagefoundry.transports.bounded_read import (
    DEFAULT_MAX_RESPONSE_BYTES,
    MAX_TOKEN_RESPONSE_BYTES,
    EgressReplyError,
    ResponseTooLargeError,
    TruncatedResponseError,
    drain_bounded,
    read_bounded,
    read_bounded_text,
)
from messagefoundry.transports.dicomweb import DicomWebDestination
from messagefoundry.transports.fhir import FhirDestination, FhirLookupExecutor
from messagefoundry.transports.http_auth import OAuth2ClientCredentialsProvider
from messagefoundry.transports.rest import RestDestination
from messagefoundry.transports.signing import (
    _MAX_KEY_FILE_BYTES,
    SigningError,
    _read_key_material,
)
from messagefoundry.transports.smart import SmartBackendTokenProvider
from messagefoundry.transports.soap import SoapDestination

REST_URL = "https://api.example.com/ingest"
SOAP_URL = "https://api.example.com/svc"
FHIR_BASE = "https://fhir.example.org/fhir"
DICOMWEB_BASE = "https://pacs.example.org/dicom-web"
TOKEN_URL = "https://auth.example.com/token"
AI_ENDPOINT = "https://ai.internal/v1/messages"


# --- the fakes ----------------------------------------------------------------------------------


class _UnboundedResp:
    """A peer whose body never ends: it answers ``read(amt)`` with exactly ``amt`` bytes.

    Asking without an amount (the pre-#1191 bare ``read()``) is an ``AssertionError``, so this fake
    cannot be satisfied by a call site that still reads to EOF. That is what makes it a control and
    not just a large body: an inert change fails it.
    """

    status = 200
    headers: email.message.Message = email.message.Message()

    def __init__(self) -> None:
        self.requested: list[int] = []

    def read(self, amt: int = -1) -> bytes:
        self.requested.append(amt)
        if amt < 0:
            raise AssertionError("unbounded read: the call site asked for the whole body")
        return b"\0" * amt

    def __enter__(self) -> _UnboundedResp:
        return self

    def __exit__(self, *a: object) -> bool:
        return False


class _ExactResp:
    """A well-behaved peer: returns ``body`` (or the first ``amt`` bytes of it)."""

    def __init__(self, body: bytes, status: int = 200) -> None:
        self._body = body
        self.status = status
        self.headers: email.message.Message = email.message.Message()

    def read(self, amt: int = -1) -> bytes:
        return self._body if amt < 0 else self._body[:amt]

    def __enter__(self) -> _ExactResp:
        return self

    def __exit__(self, *a: object) -> bool:
        return False


class _FakeOpener:
    def __init__(self, resp: object) -> None:
        self.resp = resp
        self.requests: list[urllib.request.Request] = []

    def open(self, req: urllib.request.Request, timeout: float | None = None) -> object:
        self.requests.append(req)
        return self.resp


# --- the helper itself --------------------------------------------------------------------------


def test_a_body_at_the_bound_comes_back_whole() -> None:
    """The control: the bound refuses nothing at or under itself, so it adds no dead-letter cause
    for an honest partner."""
    body = b"x" * 64
    assert read_bounded(_ExactResp(body), limit=64, connector="probe") == body


def test_a_body_one_byte_past_the_bound_is_refused() -> None:
    with pytest.raises(ResponseTooLargeError) as err:
        read_bounded(_ExactResp(b"x" * 65), limit=64, connector="OB_TEST")
    assert "OB_TEST" in str(err.value)
    assert "64-byte bound" in str(err.value)


def test_the_bound_is_enforced_on_the_read_not_after_it() -> None:
    """Peak buffer is limit + 1, whatever the peer intended to send."""
    resp = _UnboundedResp()
    with pytest.raises(ResponseTooLargeError):
        read_bounded(resp, limit=1024, connector="OB_TEST")
    assert resp.requested == [1025]


def test_the_refusal_is_a_delivery_error_not_a_permanent_nak() -> None:
    """A peer-side fault stays transient. Promoting it to NegativeAckError would add a new
    dead-letter cause, which #1191 rules out."""
    assert issubclass(ResponseTooLargeError, DeliveryError)
    from messagefoundry.transports.base import NegativeAckError

    assert not issubclass(ResponseTooLargeError, NegativeAckError)


def test_a_non_positive_limit_is_a_programming_error_not_a_disable_switch() -> None:
    """0 = unbounded is exactly the shape #1191 disqualifies, so it cannot be requested."""
    for bad in (0, -1):
        with pytest.raises(ValueError, match="positive limit"):
            read_bounded(_ExactResp(b""), limit=bad, connector="OB_TEST")


def test_text_variant_decodes_with_replacement() -> None:
    assert read_bounded_text(_ExactResp(b"\xff ok"), connector="c", encoding="utf-8").endswith("ok")


# --- the constants ------------------------------------------------------------------------------


def test_the_response_bound_is_the_engines_existing_one_message_ceiling() -> None:
    """Not a new number: it IS parsing/peek's 16 MiB, so nobody has to defend a fresh constant."""
    assert DEFAULT_MAX_RESPONSE_BYTES == DEFAULT_MAX_MESSAGE_BYTES == 16 * 1024 * 1024


def test_the_token_bound_matches_the_engines_own_oidc_token_bound() -> None:
    """``transports/`` must not import ``auth/``, so the two constants are separate. This pins them
    equal so they cannot drift apart unnoticed."""
    assert MAX_TOKEN_RESPONSE_BYTES == _OIDC_TOKEN_BOUND == 256 * 1024


def test_no_bound_ships_at_zero() -> None:
    """A regression gate: #1191 disqualifies buying the word 'bounded' with a 0 default."""
    assert DEFAULT_MAX_RESPONSE_BYTES > 0
    assert MAX_TOKEN_RESPONSE_BYTES > 0
    assert _MAX_KEY_FILE_BYTES > 0


# --- no bare egress read survives ----------------------------------------------------------------

_EGRESS_MODULES = (
    "messagefoundry/transports/ai_broker.py",
    "messagefoundry/transports/dicomweb.py",
    "messagefoundry/transports/fhir.py",
    "messagefoundry/transports/http_auth.py",
    "messagefoundry/transports/rest.py",
    "messagefoundry/transports/signing.py",
    "messagefoundry/transports/smart.py",
    "messagefoundry/transports/soap.py",
    "messagefoundry/pipeline/alert_sinks.py",
)
_BARE_READ = re.compile(r"^[^#]*\b\w+\.read\(\)")
_REPO_ROOT = Path(__file__).resolve().parents[1]


def test_no_egress_module_still_reads_to_eof() -> None:
    """The sweep that found the sixteen sites, run as a gate.

    ``ai_broker.py`` carries a COMMENT mentioning ``exc.read()``; the pattern skips comment lines,
    which is why the positive control below matters -- a pattern that matched nothing anywhere would
    be indistinguishable from a clean tree.
    """
    offenders = [
        f"{mod}:{n}"
        for mod in _EGRESS_MODULES
        for n, line in enumerate((_REPO_ROOT / mod).read_text(encoding="utf-8").splitlines(), 1)
        if _BARE_READ.match(line)
    ]
    assert offenders == []


def test_the_bare_read_pattern_can_still_find_one() -> None:
    """Positive control for the gate above."""
    assert _BARE_READ.match("                body = resp.read().decode('utf-8')")
    assert _BARE_READ.match("            resp.read()")
    assert not _BARE_READ.match("            # never echo exc.read() here")
    assert not _BARE_READ.match("            read_bounded(resp, connector='x')")


# --- the connectors -----------------------------------------------------------------------------


def _rest() -> RestDestination:
    d = build_destination(
        Destination(name="OB_REST", type=ConnectorType.REST, settings=Rest(url=REST_URL).settings)
    )
    assert isinstance(d, RestDestination)
    return d


def _soap() -> SoapDestination:
    d = build_destination(
        Destination(name="OB_SOAP", type=ConnectorType.SOAP, settings=Soap(url=SOAP_URL).settings)
    )
    assert isinstance(d, SoapDestination)
    return d


def _fhir() -> FhirDestination:
    d = build_destination(
        Destination(name="OB_FHIR", type=ConnectorType.FHIR, settings=FHIR(url=FHIR_BASE).settings)
    )
    assert isinstance(d, FhirDestination)
    return d


def _dicomweb() -> DicomWebDestination:
    d = build_destination(
        Destination(
            name="OB_DCMWEB",
            type=ConnectorType.DICOMWEB,
            settings=DICOMweb(url=DICOMWEB_BASE).settings,
        )
    )
    assert isinstance(d, DicomWebDestination)
    return d


def test_rest_post_refuses_an_unbounded_reply() -> None:
    dest = _rest()
    resp = _UnboundedResp()
    dest._opener = _FakeOpener(resp)  # type: ignore[assignment]
    with pytest.raises(ResponseTooLargeError, match="api.example.com"):
        dest._post("<payload/>")
    assert resp.requested == [DEFAULT_MAX_RESPONSE_BYTES + 1]


def test_rest_probe_refuses_an_unbounded_drain() -> None:
    """A discarded body is still buffered, so an unbounded drain turns 'test connection' into a
    memory exhaustion."""
    dest = _rest()
    dest._opener = _FakeOpener(_UnboundedResp())  # type: ignore[assignment]
    with pytest.raises(ResponseTooLargeError):
        dest._probe()


def test_soap_post_refuses_an_unbounded_reply() -> None:
    dest = _soap()
    dest._opener = _FakeOpener(_UnboundedResp())  # type: ignore[assignment]
    with pytest.raises(ResponseTooLargeError):
        dest._post("<env:Envelope/>")


def test_soap_probe_refuses_an_unbounded_drain() -> None:
    dest = _soap()
    dest._opener = _FakeOpener(_UnboundedResp())  # type: ignore[assignment]
    with pytest.raises(ResponseTooLargeError):
        dest._probe()


class _UnboundedHTTPError(urllib.error.HTTPError):
    """A non-2xx whose error body never ends -- the two ``exc.read()`` sites."""

    def __init__(self, url: str, code: int) -> None:
        super().__init__(url, code, "err", email.message.Message(), io.BytesIO(b""))
        self.requested: list[int] = []

    def read(self, amt: int = -1) -> bytes:  # type: ignore[override]
        self.requested.append(amt)
        if amt < 0:
            raise AssertionError("unbounded read: the call site asked for the whole error body")
        return b"\0" * amt


class _RaisingOpener:
    def __init__(self, exc: Exception) -> None:
        self.exc = exc

    def open(self, req: urllib.request.Request, timeout: float | None = None) -> object:
        raise self.exc


def test_soap_fault_body_is_bounded_and_the_status_still_classifies(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """An over-cap fault body is LOGGED and dropped, not raised: the delivery already fails on the
    status, and raising here would swap a classified failure for an unclassified one."""
    dest = _soap()
    err = _UnboundedHTTPError(SOAP_URL, 500)
    dest._opener = _RaisingOpener(err)  # type: ignore[assignment]
    with caplog.at_level(logging.WARNING), pytest.raises(DeliveryError) as raised:
        dest._post("<env:Envelope/>")
    assert not isinstance(raised.value, ResponseTooLargeError)
    assert "500" in str(raised.value)
    assert err.requested == [DEFAULT_MAX_RESPONSE_BYTES + 1]
    assert any("could not read whole" in r.getMessage() for r in caplog.records)


def test_fhir_post_refuses_an_unbounded_reply() -> None:
    dest = _fhir()
    dest._opener = _FakeOpener(_UnboundedResp())  # type: ignore[assignment]
    with pytest.raises(ResponseTooLargeError):
        dest._post(json.dumps({"resourceType": "Patient"}), "POST", f"{FHIR_BASE}/Patient", {})


def test_fhir_probe_refuses_an_unbounded_drain() -> None:
    dest = _fhir()
    dest._opener = _FakeOpener(_UnboundedResp())  # type: ignore[assignment]
    with pytest.raises(ResponseTooLargeError):
        dest._probe()


def test_fhir_error_body_is_bounded_and_the_status_still_classifies(
    caplog: pytest.LogCaptureFixture,
) -> None:
    dest = _fhir()
    err = _UnboundedHTTPError(FHIR_BASE, 500)
    dest._opener = _RaisingOpener(err)  # type: ignore[assignment]
    with caplog.at_level(logging.WARNING), pytest.raises(DeliveryError) as raised:
        dest._post(json.dumps({"resourceType": "Patient"}), "POST", f"{FHIR_BASE}/Patient", {})
    assert not isinstance(raised.value, ResponseTooLargeError)
    assert err.requested == [DEFAULT_MAX_RESPONSE_BYTES + 1]
    assert any("could not read whole" in r.getMessage() for r in caplog.records)


def test_dicomweb_post_refuses_an_unbounded_reply() -> None:
    dest = _dicomweb()
    dest._opener = _FakeOpener(_UnboundedResp())  # type: ignore[assignment]
    with pytest.raises(ResponseTooLargeError):
        dest._post(b"\x00" * 128 + b"DICM")


def test_dicomweb_probe_refuses_an_unbounded_drain() -> None:
    dest = _dicomweb()
    dest._opener = _FakeOpener(_UnboundedResp())  # type: ignore[assignment]
    with pytest.raises(ResponseTooLargeError):
        dest._probe()


# --- the live lookup (ADR 0043) ------------------------------------------------------------------


def test_fhir_lookup_read_is_byte_bounded_and_raises_to_the_handler() -> None:
    """The one egress read a Handler's own query shapes. It runs inside a transform, so there is no
    message to dead-letter: the Handler must see a FhirLookupError, not a DeliveryError."""
    ex = FhirLookupExecutor({"epic": {"url": FHIR_BASE}})
    resp = _UnboundedResp()
    ex._opener["epic"] = _FakeOpener(resp)  # type: ignore[assignment]
    with pytest.raises(FhirLookupError, match="bound"):
        ex._get("epic", f"{FHIR_BASE}/Patient?family=Synthetic")
    assert resp.requested == [DEFAULT_MAX_RESPONSE_BYTES + 1]


def test_fhir_lookup_probe_is_byte_bounded() -> None:
    ex = FhirLookupExecutor({"epic": {"url": FHIR_BASE}})
    ex._opener["epic"] = _FakeOpener(_UnboundedResp())  # type: ignore[assignment]
    with pytest.raises(FhirLookupError, match="bound"):
        ex._probe("epic")


def test_a_lookup_refusal_never_echoes_the_query() -> None:
    """A lookup URL can carry PHI, so the refusal names the redacted base and the bound only."""
    ex = FhirLookupExecutor({"epic": {"url": FHIR_BASE}})
    ex._opener["epic"] = _FakeOpener(_UnboundedResp())  # type: ignore[assignment]
    with pytest.raises(FhirLookupError) as err:
        ex._get("epic", f"{FHIR_BASE}/Patient?family=Synthetic&birthdate=1970-01-01")
    assert "Synthetic" not in str(err.value)
    assert "1970-01-01" not in str(err.value)


# --- the token endpoints ------------------------------------------------------------------------


def test_oauth2_token_response_is_bounded_at_the_tighter_token_ceiling() -> None:
    provider = OAuth2ClientCredentialsProvider(
        token_url=TOKEN_URL, client_id="cid", client_secret="s3cr3t"
    )
    resp = _UnboundedResp()
    provider._opener = _FakeOpener(resp)  # type: ignore[assignment]
    with pytest.raises(ResponseTooLargeError):
        provider.access_token()
    assert resp.requested == [MAX_TOKEN_RESPONSE_BYTES + 1]


def test_smart_token_response_is_bounded_at_the_tighter_token_ceiling(ec_pem: str) -> None:
    provider = SmartBackendTokenProvider(
        token_url=TOKEN_URL,
        client_id="cid",
        private_key=ec_pem,
        algorithm=SignatureAlgorithm.ES256,
        scope="system/*.rs",
    )
    resp = _UnboundedResp()
    provider._opener = _FakeOpener(resp)  # type: ignore[assignment]
    with pytest.raises(ResponseTooLargeError):
        provider.access_token()
    assert resp.requested == [MAX_TOKEN_RESPONSE_BYTES + 1]


@pytest.fixture(scope="module")
def ec_pem() -> str:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    key = ec.generate_private_key(ec.SECP256R1())
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("ascii")


# --- the AI broker ------------------------------------------------------------------------------


def test_ai_broker_maps_an_over_cap_reply_onto_its_own_error_type() -> None:
    """A DeliveryError escaping the broker would be unmapped at the API route, so the refusal is
    re-raised as AiBrokerError -- still naming only the redacted host and the bound."""
    broker = AiBroker(
        endpoint=AI_ENDPOINT, api_key="sk-secret-key-value", allowed_endpoints=["ai.internal"]
    )
    broker._opener = _FakeOpener(_UnboundedResp())  # type: ignore[assignment]
    with pytest.raises(AiBrokerError) as err:
        broker.chat("def handle(msg): ...")
    assert "sk-secret-key-value" not in str(err.value)
    assert "bound" in str(err.value)


# --- the alert webhook --------------------------------------------------------------------------


def test_alert_webhook_drain_is_bounded() -> None:
    transport = WebhookTransport("https://hooks.example/x", timeout=5.0)
    resp = _UnboundedResp()
    opener = _FakeOpener(resp)
    import messagefoundry.pipeline.alert_sinks as sinks

    original = sinks._NO_REDIRECT_OPENER.open
    sinks._NO_REDIRECT_OPENER.open = opener.open  # type: ignore[method-assign]
    try:
        with pytest.raises(ResponseTooLargeError):
            transport._post({"type": "queue_buildup", "connection": "OB_X"})
    finally:
        sinks._NO_REDIRECT_OPENER.open = original  # type: ignore[method-assign]
    assert resp.requested == [DEFAULT_MAX_RESPONSE_BYTES + 1]


# --- the signing key file (a LOCAL read, not an egress reply) -------------------------------------


def test_a_signing_key_file_past_the_bound_fails_at_construction(tmp_path: Path) -> None:
    """Not one of the egress response reads: the key file is local and operator-configured. Bounded
    on the same principle -- a bare read of a path that turns out to name a huge file buffers it."""
    big = tmp_path / "key.pem"
    big.write_bytes(b"\0" * (_MAX_KEY_FILE_BYTES + 1))
    with pytest.raises(SigningError, match="bound") as caught:
        _read_key_material("sign_private_key", str(big))
    # BACKLOG #1664: the over-cap arm names the setting, never the value. A value reaching this arm
    # is a real path rather than key material -- the open succeeded -- but the rule is one rule.
    assert str(big) not in str(caught.value)
    assert "sign_private_key" in str(caught.value)


def test_a_real_sized_key_file_still_reads(tmp_path: Path, ec_pem: str) -> None:
    """The control: a real PEM is a few kilobytes, so the bound refuses nothing an operator ships."""
    path = tmp_path / "ok.pem"
    path.write_bytes(ec_pem.encode("ascii"))  # bytes, so Windows does not translate the newlines
    assert _read_key_material("sign_private_key", str(path)) == ec_pem.encode("utf-8")


# --- a truncated reply is not an answer (BACKLOG #1575) -------------------------------------------
#
# These arms drive REAL ``http.client.HTTPResponse`` objects over ``io.BytesIO``, not a fake. The
# discriminator under test (``HTTPResponse.length``) is maintained by ``http.client`` itself, so a
# hand-written double would be asserting the test author's model of the stdlib rather than the
# stdlib. The wire bytes below are the entire input.


def _wire(raw: bytes, method: str = "POST") -> http.client.HTTPResponse:
    """A real parsed ``HTTPResponse`` over ``raw``, with no socket involved."""

    class _Sock:
        def makefile(self, *a: object, **k: object) -> io.BytesIO:
            return io.BytesIO(raw)

        def close(self) -> None:
            pass

    resp = http.client.HTTPResponse(_Sock(), method=method)  # type: ignore[arg-type]
    resp.begin()
    return resp


_FIXED_COMPLETE = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello"
_FIXED_TRUNCATED = b"HTTP/1.1 200 OK\r\nContent-Length: 50\r\n\r\nhello"
_CHUNKED_COMPLETE = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n"
_CHUNKED_TRUNCATED = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n50\r\nhello"
_EOF_DELIMITED = b"HTTP/1.1 200 OK\r\n\r\nhello"


def test_a_reply_that_stops_short_of_its_declared_length_is_refused() -> None:
    """The defect: the peer promised 50 bytes and sent 5, and the ceiling check cannot see it.

    Before this, ``read_bounded`` compared only against the byte ceiling, so the fragment came back
    as an ordinary value and a deploying site WOULD have had the delivery reported as successful.
    """
    with pytest.raises(TruncatedResponseError) as err:
        read_bounded(_wire(_FIXED_TRUNCATED), limit=1024, connector="OB_TEST")
    assert "OB_TEST" in str(err.value)
    assert "50 bytes long but sent 5" in str(err.value)


def test_a_declared_length_delivering_nothing_at_all_is_refused() -> None:
    """The empty limb of the same defect: an accepted zero-byte body would read as a legitimately
    empty reply, which several call sites treat as a successful no-content answer."""
    with pytest.raises(TruncatedResponseError):
        read_bounded(
            _wire(b"HTTP/1.1 200 OK\r\nContent-Length: 50\r\n\r\n"), limit=1024, connector="OB_TEST"
        )


def test_a_complete_fixed_length_reply_still_comes_back_whole() -> None:
    """The control for the arm above: the completeness check refuses nothing an honest peer sends."""
    assert read_bounded(_wire(_FIXED_COMPLETE), limit=1024, connector="OB_TEST") == b"hello"


def test_the_byte_ceiling_survives_the_completeness_check() -> None:
    """#1575 must not be paid for with #1191. An over-cap body still raises ResponseTooLargeError,
    and still buys the verdict with limit + 1 bytes rather than the peer's whole payload."""
    resp = _UnboundedResp()
    with pytest.raises(ResponseTooLargeError):
        read_bounded(resp, limit=1024, connector="OB_TEST")
    assert resp.requested == [1025]


def test_an_over_cap_reply_that_declared_a_length_is_reported_as_too_large_not_truncated() -> None:
    """ORDERING, and it is not cosmetic. A read that stops at the ceiling leaves the declared
    remainder positive, so testing completeness first would report a body that is too LARGE as one
    that is too SHORT -- and TruncatedResponseError would point an operator at the wrong peer."""
    raw = b"HTTP/1.1 200 OK\r\nContent-Length: 5000\r\n\r\n" + b"z" * 5000
    with pytest.raises(ResponseTooLargeError):
        read_bounded(_wire(raw), limit=10, connector="OB_TEST")


def test_a_chunked_reply_is_not_failed_for_declaring_no_length() -> None:
    """The first way this fix could break working peers. A chunked reply carries its framing in the
    stream, so it has no Content-Length to fall short of and must be accepted."""
    assert read_bounded(_wire(_CHUNKED_COMPLETE), limit=1024, connector="OB_TEST") == b"hello"


def test_an_eof_delimited_reply_is_not_failed_for_declaring_no_length() -> None:
    """The second way this fix could break working peers. The close IS the framing here, so a short
    body is the peer's whole reply."""
    assert read_bounded(_wire(_EOF_DELIMITED), limit=1024, connector="OB_TEST") == b"hello"


def test_a_truncated_chunked_reply_arrives_as_the_same_retryable_error() -> None:
    """http.client catches this shape itself, but raises IncompleteRead -- an HTTPException, which
    matches NONE of the connectors' except arms and would escape send() as an internal error.
    Translated so it reaches a connector as the same DeliveryError the length comparison raises.

    The message does not assert a framing this helper never checked: IncompleteRead is caught from
    any reader, so claiming 'chunked' would point a diagnosing operator at a Transfer-Encoding the
    peer may not have used."""
    with pytest.raises(TruncatedResponseError, match="part-way through the response body"):
        read_bounded(_wire(_CHUNKED_TRUNCATED), limit=1024, connector="OB_TEST")


def test_the_three_framings_are_actually_distinct_on_the_wire() -> None:
    """The positive control for the two acceptance arms above.

    A completeness check that silently never fired would pass them both while passing the truncation
    arms for some other reason. This pins WHY chunked and EOF-delimited are accepted: http.client
    reports no declared remainder for either, and a positive one for a truncated fixed-length body.
    """
    fixed_ok, fixed_short = _wire(_FIXED_COMPLETE), _wire(_FIXED_TRUNCATED)
    chunked, eof = _wire(_CHUNKED_COMPLETE), _wire(_EOF_DELIMITED)
    assert (chunked.chunked, eof.chunked, fixed_ok.chunked) == (True, False, False)
    for resp in (fixed_ok, fixed_short, chunked, eof):
        resp.read(1025)
    assert fixed_ok.length == 0  # complete: the declared remainder ran out
    assert fixed_short.length == 45  # truncated: 45 declared bytes never arrived
    assert chunked.length is None and eof.length is None  # neither declared a length at all


def test_a_bodyless_status_is_complete_not_truncated() -> None:
    """A 204/304/1xx, and any reply to a HEAD, is fixed-length-of-zero. http.client sets length = 0
    BEFORE the read, so an empty body here is complete. Failing these would break every probe."""
    assert read_bounded(_wire(b"HTTP/1.1 204 No Content\r\n\r\n"), connector="c") == b""
    assert read_bounded(_wire(b"HTTP/1.1 304 Not Modified\r\n\r\n"), connector="c") == b""
    head = _wire(b"HTTP/1.1 200 OK\r\nContent-Length: 50\r\n\r\n", method="HEAD")
    assert read_bounded(head, connector="c") == b""


def test_a_reader_with_no_declared_length_at_all_is_unaffected() -> None:
    """A plain binary file handle has no ``length`` attribute. The check reads it through getattr
    so such a reader keeps working -- the shape ``signing.py`` bounds on the same principle."""
    assert not hasattr(io.BytesIO(b"hi"), "length")
    assert read_bounded(io.BytesIO(b"hi"), limit=1024, connector="c") == b"hi"


def test_a_truncated_error_body_is_caught_on_the_non_2xx_path_too() -> None:
    """HTTPError DELEGATES ``length`` to the response it wraps, so the sites that read an error body
    are covered without naming the wrapper."""
    inner = _wire(_FIXED_TRUNCATED)
    err = urllib.error.HTTPError(REST_URL, 500, "err", inner.headers, inner)
    with pytest.raises(TruncatedResponseError):
        read_bounded(err, limit=1024, connector="OB_TEST")  # type: ignore[arg-type]


def test_the_refusal_is_a_delivery_error_not_a_permanent_nak_either() -> None:
    """A cut connection is a peer-side/network fault, so the next attempt may complete. Promoting it
    to NegativeAckError would dead-letter a message on a dropped socket."""
    from messagefoundry.transports.base import NegativeAckError

    assert issubclass(TruncatedResponseError, DeliveryError)
    assert not issubclass(TruncatedResponseError, NegativeAckError)


def test_the_text_variant_refuses_a_truncated_reply_before_decoding_it() -> None:
    """errors='replace' would otherwise turn a fragment into a plausible-looking string."""
    with pytest.raises(TruncatedResponseError):
        read_bounded_text(_wire(_FIXED_TRUNCATED), limit=1024, connector="c", encoding="utf-8")


def test_rest_post_does_not_report_success_on_a_truncated_reply() -> None:
    """The row's named symptom, end to end: ``REST._post`` returned ``('hello', 200, {})`` for a
    reply the peer never finished sending, and the delivery worker counts a returned status as
    delivered. It now raises a retryable DeliveryError instead."""
    dest = _rest()
    dest._opener = _FakeOpener(_wire(_FIXED_TRUNCATED))  # type: ignore[assignment]
    with pytest.raises(TruncatedResponseError, match="api.example.com"):
        dest._post("<payload/>")


def test_rest_post_still_returns_a_complete_reply() -> None:
    """The control: the connector is unchanged for an honest peer."""
    dest = _rest()
    dest._opener = _FakeOpener(_wire(_FIXED_COMPLETE))  # type: ignore[assignment]
    assert dest._post("<payload/>")[:2] == ("hello", 200)


def test_rest_post_still_accepts_a_chunked_reply() -> None:
    """The outage arm: chunked partners are ordinary traffic and must keep working."""
    dest = _rest()
    dest._opener = _FakeOpener(_wire(_CHUNKED_COMPLETE))  # type: ignore[assignment]
    assert dest._post("<payload/>")[:2] == ("hello", 200)


# --- a DISCARDED body has no answer to be wrong about ---------------------------------------------


def test_a_drain_refuses_no_reply_shape_on_any_framing() -> None:
    """BOTH truncation paths, which is the point of drain_bounded being a function and not a flag.

    A truncation is detected in two places -- the declared-length comparison and the IncompleteRead
    translation -- and the first cut of this gated only the first. A drain that still raised on a
    truncated CHUNKED reply would fail every probe and alert against a peer that answers that way,
    which is precisely the outcome the opt-out exists to prevent.
    """
    drain_bounded(_wire(_FIXED_TRUNCATED), limit=1024, connector="c")
    drain_bounded(_wire(_CHUNKED_TRUNCATED), limit=1024, connector="c")  # the half-applied case
    drain_bounded(_wire(_CHUNKED_COMPLETE), limit=1024, connector="c")
    drain_bounded(_wire(_EOF_DELIMITED), limit=1024, connector="c")


def test_a_drain_still_enforces_the_byte_bound() -> None:
    """It is not a disable switch for the cap: an unbounded drain is a memory exhaustion whether or
    not anyone reads the bytes."""
    resp = _UnboundedResp()
    with pytest.raises(ResponseTooLargeError):
        drain_bounded(resp, limit=1024, connector="c")
    assert resp.requested == [1025]


def test_a_probe_still_reports_reachable_when_the_peer_answers_short() -> None:
    """The peer ANSWERING is the whole question a probe asks, and the probe discards the body.
    Failing it on a short reply would report an unreachable partner that demonstrably replied."""
    dest = _rest()
    dest._opener = _FakeOpener(_wire(_FIXED_TRUNCATED))  # type: ignore[assignment]
    dest._probe()  # no raise


def test_an_alert_already_accepted_is_not_reported_as_a_failed_send() -> None:
    """The webhook POST is accepted before the drain runs, so raising here would tell an operator
    the alert failed when the host took it."""
    transport = WebhookTransport("https://hooks.example/x", timeout=5.0)
    import messagefoundry.pipeline.alert_sinks as sinks

    original = sinks._NO_REDIRECT_OPENER.open
    sinks._NO_REDIRECT_OPENER.open = _FakeOpener(_wire(_FIXED_TRUNCATED)).open  # type: ignore[method-assign]
    try:
        transport._post({"type": "queue_buildup", "connection": "OB_X"})  # no raise
    finally:
        sinks._NO_REDIRECT_OPENER.open = original  # type: ignore[method-assign]


# --- every site that RETYPES a refusal must retype the whole family -------------------------------


def test_the_two_refusals_share_a_base_so_a_translating_site_can_catch_the_family() -> None:
    """The first cut of #1575 added TruncatedResponseError beside ResponseTooLargeError and left
    three ``except ResponseTooLargeError`` translations matching only the older sibling. The base
    exists so the next refusal added here cannot repeat that."""
    assert issubclass(ResponseTooLargeError, EgressReplyError)
    assert issubclass(TruncatedResponseError, EgressReplyError)
    assert issubclass(EgressReplyError, DeliveryError)


def test_the_ai_broker_maps_a_truncated_reply_onto_its_own_error_type() -> None:
    """A DeliveryError escaping chat() is unmapped at the /ai/assist route, so it would surface as
    an unhandled 500 rather than the mapped 502."""
    broker = AiBroker(
        endpoint=AI_ENDPOINT, api_key="sk-secret-key-value", allowed_endpoints=["ai.internal"]
    )
    broker._opener = _FakeOpener(_wire(_FIXED_TRUNCATED))  # type: ignore[assignment]
    with pytest.raises(AiBrokerError) as err:
        broker.chat("def handle(msg): ...")
    assert "sk-secret-key-value" not in str(err.value)


def test_fhir_lookup_maps_a_truncated_reply_onto_fhir_lookup_error() -> None:
    """This read runs inside a Handler, and the sandbox worker catches only (DbLookupError,
    FhirLookupError) -- a raw DeliveryError is reclassified as a handler crash."""
    ex = FhirLookupExecutor({"epic": {"url": FHIR_BASE}})
    ex._opener["epic"] = _FakeOpener(_wire(_FIXED_TRUNCATED))  # type: ignore[assignment]
    # _get, not read: read is a coroutine, and calling it unawaited would build a coroutine object,
    # run nothing, and pass this arm for the wrong reason. _get is the sync body that reads.
    with pytest.raises(FhirLookupError):
        ex._get("epic", f"{FHIR_BASE}/Patient/123")


def test_a_truncated_error_body_still_warns_rather_than_going_silent(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """The error-body arms retype nothing, but they still have to catch the FAMILY.

    Catching only ResponseTooLargeError sent a truncated error body to the bare ``except Exception``
    that sets ``body = ''``, so the tailored warning never fired and an operator got no signal at
    all about the failing peer -- the classification silently degraded to status-only.
    """
    dest = _fhir()
    inner = _wire(_FIXED_TRUNCATED)
    err = urllib.error.HTTPError(FHIR_BASE, 500, "err", inner.headers, inner)
    dest._opener = _RaisingOpener(err)  # type: ignore[assignment]
    with caplog.at_level(logging.WARNING), pytest.raises(DeliveryError):
        dest._post(json.dumps({"resourceType": "Patient"}), "POST", f"{FHIR_BASE}/Patient", {})
    assert any("could not read whole" in r.getMessage() for r in caplog.records)


def test_a_truncated_reply_never_carries_the_partial_body_on_the_exception_chain() -> None:
    """PHI (CLAUDE.md section 9): IncompleteRead holds the fragment on ``.partial`` and in
    ``.args[0]``, and ``_read_chunked`` chains an inner IncompleteRead that holds it too.

    ``from None`` is NOT enough and this arm is why: it clears ``__cause__`` and leaves
    ``__context__``, so the bytes stayed reachable at ``__context__.__cause__.partial`` for any sink
    that walks the chain rather than calling the default formatter. Both links are asserted dead.
    """
    with pytest.raises(TruncatedResponseError) as err:
        read_bounded(_wire(_CHUNKED_TRUNCATED), limit=1024, connector="OB_TEST")
    assert err.value.__cause__ is None
    assert err.value.__context__ is None
    assert "hello" not in str(err.value)
