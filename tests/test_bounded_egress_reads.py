# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
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

Synthetic data only.
"""

from __future__ import annotations

import email.message
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
    ResponseTooLargeError,
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
    assert any("over the response bound" in r.getMessage() for r in caplog.records)


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
    assert any("over the response bound" in r.getMessage() for r in caplog.records)


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
    with pytest.raises(SigningError, match="bound"):
        _read_key_material(str(big))


def test_a_real_sized_key_file_still_reads(tmp_path: Path, ec_pem: str) -> None:
    """The control: a real PEM is a few kilobytes, so the bound refuses nothing an operator ships."""
    path = tmp_path / "ok.pem"
    path.write_bytes(ec_pem.encode("ascii"))  # bytes, so Windows does not translate the newlines
    assert _read_key_material(str(path)) == ec_pem.encode("utf-8")
