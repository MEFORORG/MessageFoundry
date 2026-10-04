# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""SOAP destination connector (ADR 0003): Fault classification, version headers, delivery, egress.

The opener is faked so nothing hits the network; SOAP Faults are exercised both as an HTTP-500 body and
as an HTTP-200 body (some servers do that).
"""

from __future__ import annotations

import email.message
import http.client
import io
import urllib.error
import urllib.request

import pytest

from messagefoundry.config.models import ConnectorType, Destination
from messagefoundry.config.settings import EgressSettings
from messagefoundry.config.tls_policy import HopPosture, active_hop_posture
from messagefoundry.config.wiring import Soap, WiringError
from messagefoundry.transports import build_destination
from messagefoundry.transports.base import DeliveryError, NegativeAckError
from messagefoundry.transports.egress import check_egress_allowed
from messagefoundry.transports.soap import SoapDestination, _classify_soap, _fault_code
from tests._malformed_reply import MALFORMED_REPLIES, RefusedAndMalformed

URL = "https://api.example.com/svc"
_SENDER_11 = "<soap:Fault><faultcode>soap:Client</faultcode></soap:Fault>"
_RECEIVER_11 = "<soap:Fault><faultcode>soap:Server</faultcode></soap:Fault>"
_SENDER_12 = "<soap:Fault><soap:Code><soap:Value>soap:Sender</soap:Value></soap:Code></soap:Fault>"


def _dest(**over: object) -> SoapDestination:
    settings = Soap(url=URL, **over).settings  # type: ignore[arg-type]
    d = build_destination(
        Destination(name="OB_SOAP", type=ConnectorType.SOAP, settings=settings),
        egress=EgressSettings(deny_by_default=False),
    )
    assert isinstance(d, SoapDestination)
    return d


# --- pure Fault classification -----------------------------------------------


def test_fault_code_extraction() -> None:
    assert "Client" in _fault_code(_SENDER_11)
    assert "Sender" in _fault_code(_SENDER_12)
    assert _fault_code("<soap:Body>ok</soap:Body>") == ""


@pytest.mark.parametrize(
    "prefix",
    ["soap", "soapenv", "SOAP-ENV", "S", "env", "soap.v11", ""],
    ids=["soap", "soapenv", "SOAP-ENV", "S", "env", "dotted", "unprefixed"],
)
def test_a_fault_is_recognised_under_any_legal_namespace_prefix(prefix: str) -> None:
    """A namespace prefix is an XML NCName: it may contain '-' and '.', not just ``\\w``.

    ``SOAP-ENV`` is the prefix the SOAP 1.1 specification uses in its own examples and what Apache Axis
    and much of the Java/.NET estate emit — so a ``\\w+:`` prefix class missed the single most canonical
    fault envelope there is. The consequence is not a cosmetic miss: with no fault recognised,
    ``_classify_soap`` falls through to the HTTP status, and SOAP endpoints routinely return a fault
    with **HTTP 200** — so a rejected message was recorded as delivered.
    """
    q = f"{prefix}:" if prefix else ""
    body = f"<{q}Fault><faultcode>{q}Client</faultcode></{q}Fault>"
    assert isinstance(_classify_soap(200, body), NegativeAckError), (
        f"a SOAP fault carrying the '{prefix or '(none)'}' namespace prefix was not recognised, so "
        f"an HTTP 200 fault response would be recorded as a successful delivery"
    )


def test_classify_no_fault_uses_http_status() -> None:
    assert _classify_soap(200, "<ok/>") is None
    assert type(_classify_soap(500, "<oops/>")) is DeliveryError  # transient
    assert isinstance(_classify_soap(400, "<bad/>"), NegativeAckError)  # permanent


def test_classify_sender_fault_is_permanent() -> None:
    for body in (_SENDER_11, _SENDER_12):
        failure = _classify_soap(500, body)
        assert isinstance(failure, NegativeAckError) and failure.permanent is True


def test_classify_receiver_fault_is_transient() -> None:
    assert type(_classify_soap(500, _RECEIVER_11)) is DeliveryError


def test_classify_unknown_fault_is_permanent() -> None:
    body = "<soap:Fault><faultcode>soap:VersionMismatch</faultcode></soap:Fault>"
    assert isinstance(_classify_soap(200, body), NegativeAckError)  # a fault, even on 200, fails


# --- version headers ---------------------------------------------------------


def test_soap_11_headers() -> None:
    h = _dest(soap_action="urn:DoIt")._headers
    assert h["Content-Type"] == "text/xml; charset=utf-8"
    assert h["SOAPAction"] == '"urn:DoIt"'


def test_soap_11_headers_no_action() -> None:
    assert _dest()._headers["SOAPAction"] == '""'


def test_soap_12_headers() -> None:
    h = _dest(soap_version="1.2", soap_action="urn:DoIt")._headers
    assert h["Content-Type"] == 'application/soap+xml; charset=utf-8; action="urn:DoIt"'
    assert "SOAPAction" not in h


# --- send() with a faked opener ----------------------------------------------


class _Resp:
    def __init__(self, status: int = 200, body: bytes = b"") -> None:
        self.status = status
        self._body = body

    def read(self, amt: int = -1) -> bytes:
        return self._body if amt < 0 else (self._body)[:amt]

    def __enter__(self) -> _Resp:
        return self

    def __exit__(self, *a: object) -> None:
        return None


class _Opener:
    def __init__(self, resp: _Resp | None = None, exc: Exception | None = None) -> None:
        self._resp = resp
        self._exc = exc
        self.requests: list[urllib.request.Request] = []

    def open(self, req: urllib.request.Request, timeout: float | None = None) -> _Resp:
        self.requests.append(req)
        if self._exc is not None:
            raise self._exc
        assert self._resp is not None
        return self._resp


def _http_error(status: int, body: bytes) -> urllib.error.HTTPError:
    return urllib.error.HTTPError(URL, status, "err", email.message.Message(), io.BytesIO(body))


async def test_send_posts_envelope_on_2xx() -> None:
    dest = _dest(soap_action="urn:DoIt")
    op = _Opener(resp=_Resp(200, b"<soap:Envelope><soap:Body>ok</soap:Body></soap:Envelope>"))
    dest._opener = op  # type: ignore[assignment]
    await dest.send("<env/>")
    assert op.requests[0].data == b"<env/>"
    assert op.requests[0].method == "POST"


async def test_send_200_with_sender_fault_dead_letters() -> None:
    dest = _dest()
    dest._opener = _Opener(resp=_Resp(200, _SENDER_11.encode()))  # type: ignore[assignment]
    with pytest.raises(NegativeAckError) as ei:
        await dest.send("<env/>")
    assert ei.value.permanent is True


async def test_send_500_receiver_fault_retries() -> None:
    dest = _dest()
    dest._opener = _Opener(exc=_http_error(500, _RECEIVER_11.encode()))  # type: ignore[assignment]
    with pytest.raises(DeliveryError) as ei:
        await dest.send("<env/>")
    assert not isinstance(ei.value, NegativeAckError)


async def test_send_400_no_fault_dead_letters() -> None:
    dest = _dest()
    dest._opener = _Opener(exc=_http_error(400, b"bad request"))  # type: ignore[assignment]
    with pytest.raises(NegativeAckError):
        await dest.send("<env/>")


async def test_send_connection_error_retries() -> None:
    dest = _dest()
    dest._opener = _Opener(exc=urllib.error.URLError("refused"))  # type: ignore[assignment]
    with pytest.raises(DeliveryError):
        await dest.send("<env/>")


# --- BACKLOG #2113: a malformed partner reply is a transport failure, not an internal error ------


async def _call_soap(dest: SoapDestination, call: str) -> None:
    if call == "send":
        await dest.send("<env/>")
    else:
        await dest.test_connection()


@pytest.mark.parametrize("exc", MALFORMED_REPLIES)
@pytest.mark.parametrize("call", ["send", "probe"])
async def test_a_malformed_soap_reply_is_a_retryable_failure(call: str, exc: Exception) -> None:
    """Mutation: delete the HTTPException arm from `_post` or `_probe`. Red: the exception escapes."""
    dest = _dest()
    dest._opener = _Opener(exc=exc)  # type: ignore[assignment]
    with pytest.raises(DeliveryError) as ei:
        await _call_soap(dest, call)
    assert not isinstance(ei.value, NegativeAckError)  # transient: it retries
    assert ei.value.__cause__ is exc
    # Pinned as an EQUALITY: the class name only, never the reply bytes the exception carries.
    assert str(ei.value) == f"SOAP {URL} sent a malformed HTTP reply ({type(exc).__name__})"


@pytest.mark.parametrize("call", ["send", "probe"])
async def test_the_soap_malformed_reply_arm_leaves_its_neighbours_alone(call: str) -> None:
    """Controls for the arm's placement. RemoteDisconnected is both an OSError and an
    HTTPException, so it keeps the OSError wording. InvalidURL is an HTTPException too, and keeps
    the arm #1793 gave it: a permanent dead-letter on send. Mutation: move the new arm above
    either neighbour. Red."""
    dest = _dest()
    dest._opener = _Opener(exc=http.client.RemoteDisconnected("closed"))  # type: ignore[assignment]
    with pytest.raises(DeliveryError) as ei:
        await _call_soap(dest, call)
    assert not isinstance(ei.value, NegativeAckError)
    assert str(ei.value) == f"SOAP {URL} failed: closed"
    dest._opener = _Opener(exc=http.client.InvalidURL("bad"))  # type: ignore[assignment]
    with pytest.raises(DeliveryError) as ei:
        await _call_soap(dest, call)
    assert str(ei.value) == f"SOAP {URL} rejected an invalid request value"
    assert isinstance(ei.value, NegativeAckError) == (call == "send")
    if isinstance(ei.value, NegativeAckError):
        assert ei.value.permanent is True


@pytest.mark.parametrize("call", ["send", "probe"])
async def test_a_soap_reply_refusal_that_is_also_an_httpexception_passes_through(
    call: str,
) -> None:
    """Mutation: delete the matching `except EgressReplyError: raise` arm. Red: the refusal is
    retyped as a plain malformed-reply DeliveryError and loses its own type and message."""
    refusal = RefusedAndMalformed("SOAP reply refused: synthetic reason")
    dest = _dest()
    dest._opener = _Opener(exc=refusal)  # type: ignore[assignment]
    with pytest.raises(DeliveryError) as ei:
        await _call_soap(dest, call)
    assert ei.value is refusal


# --- validation + egress -----------------------------------------------------


def test_rejects_non_http_scheme() -> None:
    with pytest.raises(ValueError):
        build_destination(
            Destination(name="x", type=ConnectorType.SOAP, settings=Soap(url="ftp://x/y").settings),
            egress=EgressSettings(deny_by_default=False),
        )


def test_rejects_bad_version() -> None:
    with pytest.raises(ValueError):
        _dest(soap_version="2.0")


def test_verify_tls_false_refused_without_escape(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("MEFOR_ALLOW_INSECURE_TLS", raising=False)
    with pytest.raises(ValueError):
        _dest(verify_tls=False)


def test_soap_credentials_over_cleartext_http_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    # SOAP reuses REST's cleartext-credential guard: bearer/basic over plain http is refused.
    monkeypatch.delenv("MEFOR_ALLOW_INSECURE_TLS", raising=False)
    with pytest.raises(ValueError, match="cleartext http"):
        build_destination(
            Destination(
                name="OB",
                type=ConnectorType.SOAP,
                settings=Soap(url="http://api.example.com/svc", bearer_token="tok").settings,
            ),
            egress=EgressSettings(deny_by_default=False),
        )


def test_soap_cleartext_http_nonloopback_refused_without_escape(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # ASVS 12.2.1: the SOAP envelope is PHI, so a cleartext http egress to a non-loopback host is
    # refused even with NO credentials, unless the explicit escape is set.
    monkeypatch.delenv("MEFOR_ALLOW_INSECURE_TLS", raising=False)
    with pytest.raises(ValueError, match="cleartext http to a non-loopback host"):
        build_destination(
            Destination(
                name="OB",
                type=ConnectorType.SOAP,
                settings=Soap(url="http://api.example.com/svc").settings,
            ),
            egress=EgressSettings(deny_by_default=False),
        )


def test_soap_cleartext_http_loopback_allowed() -> None:
    # On-box loopback cleartext egress is not a network exposure → allowed (byte-identical posture).
    dest = build_destination(
        Destination(
            name="OB",
            type=ConnectorType.SOAP,
            settings=Soap(url="http://127.0.0.1:8080/svc").settings,
        ),
        egress=EgressSettings(deny_by_default=False),
    )
    assert isinstance(dest, SoapDestination)


def test_soap_cleartext_http_nonloopback_allowed_when_accepted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # ADR 0153: the blunt MEFOR_ALLOW_INSECURE_TLS escape no longer influences a cleartext-hop
    # decision (decision 5). The per-connection declaration is what crosses it now — loudly, and
    # recorded in the audit trail, instead of a process-wide env var nobody sees in review.
    monkeypatch.delenv("MEFOR_ALLOW_INSECURE_TLS", raising=False)
    with active_hop_posture(HopPosture(enforcing=True)):
        dest = build_destination(
            Destination(
                name="OB",
                type=ConnectorType.SOAP,
                settings=Soap(url="http://api.example.com/svc").settings,
                cleartext_accepted=True,
                cleartext_reason="legacy partner endpoint has no TLS",
            ),
            egress=EgressSettings(deny_by_default=False),
        )
    assert isinstance(dest, SoapDestination)  # built (warns loudly + audits), not refused


def test_egress_shares_allowed_http() -> None:
    bad = Destination(
        name="x",
        type=ConnectorType.SOAP,
        settings=Soap(url="https://evil.example.net/svc").settings,
    )
    with pytest.raises(WiringError):
        check_egress_allowed(bad, EgressSettings(allowed_http=["api.example.com"]))
    good = Destination(name="x", type=ConnectorType.SOAP, settings=Soap(url=URL).settings)
    check_egress_allowed(good, EgressSettings(allowed_http=["api.example.com"]))  # no raise
