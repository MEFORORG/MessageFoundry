"""SOAP destination connector (ADR 0003): Fault classification, version headers, delivery, egress.

The opener is faked so nothing hits the network; SOAP Faults are exercised both as an HTTP-500 body and
as an HTTP-200 body (some servers do that).
"""

from __future__ import annotations

import email.message
import io
import urllib.error
import urllib.request

import pytest

from messagefoundry.config.models import ConnectorType, Destination
from messagefoundry.config.settings import EgressSettings
from messagefoundry.config.wiring import Soap, WiringError
from messagefoundry.pipeline.wiring_runner import check_egress_allowed
from messagefoundry.transports import build_destination
from messagefoundry.transports.base import DeliveryError, NegativeAckError
from messagefoundry.transports.soap import SoapDestination, _classify_soap, _fault_code

URL = "https://api.example.com/svc"
_SENDER_11 = "<soap:Fault><faultcode>soap:Client</faultcode></soap:Fault>"
_RECEIVER_11 = "<soap:Fault><faultcode>soap:Server</faultcode></soap:Fault>"
_SENDER_12 = "<soap:Fault><soap:Code><soap:Value>soap:Sender</soap:Value></soap:Code></soap:Fault>"


def _dest(**over: object) -> SoapDestination:
    settings = Soap(url=URL, **over).settings  # type: ignore[arg-type]
    d = build_destination(Destination(name="OB_SOAP", type=ConnectorType.SOAP, settings=settings))
    assert isinstance(d, SoapDestination)
    return d


# --- pure Fault classification -----------------------------------------------


def test_fault_code_extraction() -> None:
    assert "Client" in _fault_code(_SENDER_11)
    assert "Sender" in _fault_code(_SENDER_12)
    assert _fault_code("<soap:Body>ok</soap:Body>") == ""


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

    def read(self) -> bytes:
        return self._body

    def __enter__(self) -> _Resp:
        return self

    def __exit__(self, *a: object) -> bool:
        return False


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


# --- validation + egress -----------------------------------------------------


def test_rejects_non_http_scheme() -> None:
    with pytest.raises(ValueError):
        build_destination(
            Destination(name="x", type=ConnectorType.SOAP, settings=Soap(url="ftp://x/y").settings)
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
            )
        )


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
