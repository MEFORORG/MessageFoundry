# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""SOAP destination connector (ADR 0003): Fault classification, version headers, delivery, egress.

The opener is faked so nothing hits the network; SOAP Faults are exercised both as an HTTP-500 body and
as an HTTP-200 body (some servers do that).
"""

from __future__ import annotations

import contextlib
import email.message
import http.client
import io
import time
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
from messagefoundry.transports.http_auth import with_oauth2_client_credentials
from messagefoundry.transports.soap import (
    SoapDestination,
    _classify_soap,
    _fault_code,
    _names_expired_timestamp,
)
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


# --- BACKLOG #5798: an OAuth2 401 drops the cached bearer and retries ----------------------------


class _CountingProvider:
    def __init__(self) -> None:
        self.invalidations = 0

    def access_token(self) -> str:
        return "AT-synthetic"

    def invalidate(self) -> None:
        self.invalidations += 1


def _oauth2_dest(**over: object) -> tuple[SoapDestination, _CountingProvider]:
    spec = with_oauth2_client_credentials(
        Soap(url=URL, **over),  # type: ignore[arg-type]
        token_url="https://auth.example.com/token",
        client_id="cid",
        client_secret="cs-synthetic",  # noqa: S106 -- a synthetic test credential
    )
    d = build_destination(
        Destination(name="OB_SOAP", type=ConnectorType.SOAP, settings=spec.settings),
        egress=EgressSettings(deny_by_default=False),
    )
    assert isinstance(d, SoapDestination)
    provider = _CountingProvider()
    d._token_provider = provider
    return d, provider


@pytest.mark.parametrize("body", [b"", _SENDER_11.encode()], ids=["no-fault", "sender-fault"])
async def test_an_oauth2_401_invalidates_the_token_and_retries(body: bytes) -> None:
    """Mutation: delete the 401 arm in `_post`. Red: the 401 classifies as a permanent
    NegativeAckError, so the message dead-letters and the provider is never invalidated."""
    dest, provider = _oauth2_dest()
    dest._opener = _Opener(exc=_http_error(401, body))  # type: ignore[assignment]
    with pytest.raises(DeliveryError) as ei:
        await dest.send("<env/>")
    assert not isinstance(ei.value, NegativeAckError)  # transient: it retries with a fresh bearer
    assert provider.invalidations == 1
    assert str(ei.value) == f"SOAP {URL} returned HTTP 401; refreshing the bearer token"


_WSSE_401 = b"<soap:Fault><faultcode>wsse:FailedAuthentication</faultcode></soap:Fault>"
_INVALID_TOKEN_401 = b"<soap:Fault><faultcode>wsse:InvalidSecurityToken</faultcode></soap:Fault>"


async def test_an_oauth2_401_carrying_a_ws_security_fault_stays_permanent() -> None:
    """Round-one review: on a connection that sends a UsernameToken, the fault may name it, and a
    fresh bearer cannot fix it, so retrying would resend a wrong password for the whole budget. The
    bearer is still dropped. Mutation: raise the transient in the 401 arm whatever the body. Red:
    DeliveryError."""
    dest, provider = _oauth2_dest(
        soap_version="1.2", ws_security=True, ws_username="svc", ws_password="pw-synthetic"
    )
    dest._opener = _Opener(exc=_http_error(401, _WSSE_401))  # type: ignore[assignment]
    with pytest.raises(NegativeAckError) as ei:
        await dest.send("<op/>")
    assert ei.value.permanent is True and ei.value.code == "wssecurity"
    assert provider.invalidations == 1


@pytest.mark.parametrize(
    "over",
    [{}, {"soap_version": "1.2", "ws_security": True}],
    ids=["no-ws-security", "timestamp-only"],
)
@pytest.mark.parametrize("body", [_WSSE_401, _INVALID_TOKEN_401], ids=["failed-auth", "invalid"])
async def test_an_oauth2_only_401_with_a_ws_security_fault_still_retries(
    over: dict[str, object], body: bytes
) -> None:
    """Round-two review: with no UsernameToken sent, the bearer is the only credential such a fault
    can name, so it is dropped and the message retries. Mutation: drop the UsernameToken condition
    from the carve-out. Red: a permanent wssecurity NegativeAckError dead-letters the message."""
    dest, provider = _oauth2_dest(**over)
    dest._opener = _Opener(exc=_http_error(401, body))  # type: ignore[assignment]
    with pytest.raises(DeliveryError) as ei:
        await dest.send("<op/>")
    assert not isinstance(ei.value, NegativeAckError)
    assert provider.invalidations == 1


@pytest.mark.parametrize("body", [_WSSE_401, _INVALID_TOKEN_401], ids=["failed-auth", "invalid"])
async def test_a_ws_security_401_after_its_bearer_retry_is_a_credential_fault(body: bytes) -> None:
    """Manager repair pass: the engine cannot see every credential an envelope or a connection
    carries (a Handler's own UsernameToken from body_secrets, a client certificate). The first
    WS-Security 401 retries with a fresh bearer; the next is a credential fault, so the lane stops
    rather than spend a failed login on every queued row. The run stays open after it, so a resumed
    lane stops again on the same fault. Mutation: never set the retried flag. Red: the second send
    raises a transient DeliveryError and the wrong credential goes out for the whole budget."""
    dest, provider = _oauth2_dest()
    dest._opener = _Opener(exc=_http_error(401, body))  # type: ignore[assignment]
    with pytest.raises(DeliveryError) as first:
        await dest.send("<op/>")
    assert not isinstance(first.value, NegativeAckError)
    for _ in range(2):
        dest._opener = _Opener(exc=_http_error(401, body))  # type: ignore[assignment]
        with pytest.raises(NegativeAckError) as again:
            await dest.send("<op/>")
        assert again.value.permanent is True and again.value.credential_fault is True
        assert again.value.code == "wssecurity"
    assert provider.invalidations == 3


class _ResetDuringRead(_Resp):
    """A 2xx whose body read fails: an answer from the endpoint, then a transport failure."""

    def read(self, amt: int = -1) -> bytes:
        raise ConnectionResetError("reset mid-body")


class _CloseFails(_Resp):
    """A 2xx read whole whose close then fails (code-review round 3a1460c8)."""

    def __exit__(self, *a: object) -> None:
        raise ConnectionResetError("reset on close")


def _between(kind: str) -> _Opener:
    if kind == "2xx":
        return _Opener(resp=_Resp(200, b"<soap:Envelope><soap:Body>ok</soap:Body></soap:Envelope>"))
    if kind == "2xx-read-fails":
        return _Opener(resp=_ResetDuringRead(200))
    if kind == "2xx-close-fails":
        return _Opener(
            resp=_CloseFails(200, b"<soap:Envelope><soap:Body>ok</soap:Body></soap:Envelope>")
        )
    if kind == "2xx-sender-fault":
        return _Opener(resp=_Resp(200, _SENDER_11.encode()))
    if kind == "2xx-ws-security-fault":
        return _Opener(resp=_Resp(200, _WSSE_401))
    if kind == "plain-401":
        return _Opener(exc=_http_error(401, b""))
    if kind in ("500", "502", "407"):
        return _Opener(exc=_http_error(int(kind), b""))
    if kind == "unreachable":
        return _Opener(exc=urllib.error.URLError("refused"))
    if kind == "reset":
        return _Opener(exc=ConnectionResetError("reset"))
    assert kind == "malformed"
    return _Opener(exc=http.client.BadStatusLine("garbage"))


async def _ws_security_401_then(dest: SoapDestination, kind: str) -> None:
    dest._opener = _Opener(exc=_http_error(401, _WSSE_401))  # type: ignore[assignment]
    with pytest.raises(DeliveryError) as first:
        await dest.send("<op/>")
    assert not isinstance(first.value, NegativeAckError)  # the run is open
    dest._opener = _between(kind)  # type: ignore[assignment]
    with contextlib.suppress(DeliveryError):
        await dest.send("<op/>")
    dest._opener = _Opener(exc=_http_error(401, _WSSE_401))  # type: ignore[assignment]


@pytest.mark.parametrize(
    "kind", ["2xx", "2xx-read-fails", "2xx-close-fails", "2xx-sender-fault", "plain-401"]
)
async def test_control_a_2xx_or_a_plain_401_between_ends_the_ws_security_401_run(kind: str) -> None:
    """A 2xx that is not a WS-Security fault, a 2xx whose read fails, or a 401 that is not a
    WS-Security fault ends the run, so the next WS-Security 401 gets its retry again. Mutations:
    move the 2xx reset after the body read (red: "2xx-read-fails"), drop the reset on a plain 401
    (red: "plain-401"), or keep the run on any 2xx fault (red: "2xx-sender-fault")."""
    dest, _ = _oauth2_dest()
    await _ws_security_401_then(dest, kind)
    with pytest.raises(DeliveryError) as ei:
        await dest.send("<op/>")
    assert not isinstance(ei.value, NegativeAckError)


@pytest.mark.parametrize(
    "kind",
    ["500", "502", "407", "unreachable", "reset", "malformed", "2xx-ws-security-fault"],
)
async def test_another_status_or_no_answer_between_leaves_the_ws_security_401_run_open(
    kind: str,
) -> None:
    """A 5xx, a 407 (at least these can come from a gateway or proxy rather than the endpoint),
    or no answer at all leaves the run open, so the next WS-Security 401 is the second in a row:
    a credential fault. So does a 2xx carrying a WS-Security fault (BACKLOG #5798 added item 2).
    Mutation: reset the flag in the 401 arm for any other status, or in a transport-failure arm,
    or drop the restore in _post_and_classify (red: "2xx-ws-security-fault"). Red: the second
    WS-Security 401 is retried again."""
    dest, _ = _oauth2_dest()
    await _ws_security_401_then(dest, kind)
    with pytest.raises(NegativeAckError) as ei:
        await dest.send("<op/>")
    assert ei.value.permanent is True and ei.value.credential_fault is True


_EXPIRED_401 = b"<soap:Fault><faultcode>wsse:MessageExpired</faultcode></soap:Fault>"


@pytest.mark.parametrize(
    "over",
    [{}, {"soap_version": "1.2", "ws_security": True}],
    ids=["no-ws-security", "timestamp-only"],
)
async def test_an_oauth2_401_message_expired_stays_permanent_without_a_username_token(
    over: dict[str, object],
) -> None:
    """Round-three review: MessageExpired names the envelope's Timestamp, which a fresh bearer
    cannot fix, so it stays permanent as before #5798 even with no UsernameToken sent. The bearer
    is still dropped. Mutation: drop the MessageExpired test from the carve-out. Red: DeliveryError,
    and the message retries for the whole budget."""
    dest, provider = _oauth2_dest(**over)
    dest._opener = _Opener(exc=_http_error(401, _EXPIRED_401))  # type: ignore[assignment]
    with pytest.raises(NegativeAckError) as ei:
        await dest.send("<op/>")
    assert ei.value.permanent is True and ei.value.code == "wssecurity"
    assert provider.invalidations == 1


@pytest.mark.parametrize("body", [b"", _SENDER_11.encode()], ids=["no-fault", "sender-fault"])
async def test_a_username_token_connection_still_retries_a_non_ws_security_401(
    body: bytes,
) -> None:
    """Round-three review: the carve-out keys on the fault code, not on the connection alone, so a
    401 with no WS-Security fault retries with a fresh bearer even where a UsernameToken is sent.
    Mutation: test only the UsernameToken condition in the carve-out. Red: NegativeAckError."""
    dest, provider = _oauth2_dest(
        soap_version="1.2", ws_security=True, ws_username="svc", ws_password="pw-synthetic"
    )
    dest._opener = _Opener(exc=_http_error(401, body))  # type: ignore[assignment]
    with pytest.raises(DeliveryError) as ei:
        await dest.send("<op/>")
    assert not isinstance(ei.value, NegativeAckError)
    assert provider.invalidations == 1


async def test_control_a_2xx_ws_security_fault_does_not_open_a_ws_security_401_run() -> None:
    """BACKLOG #5798 added item 2: a 2xx WS-Security fault keeps the run as it was. With no run
    open, it opens none, so the next WS-Security 401 still gets its bearer retry. Mutation: set
    the flag on a 2xx WS-Security fault. Red: NegativeAckError."""
    dest, _ = _oauth2_dest()
    dest._opener = _Opener(resp=_Resp(200, _WSSE_401))  # type: ignore[assignment]
    with pytest.raises(NegativeAckError):
        await dest.send("<op/>")
    dest._opener = _Opener(exc=_http_error(401, _WSSE_401))  # type: ignore[assignment]
    with pytest.raises(DeliveryError) as ei:
        await dest.send("<op/>")
    assert not isinstance(ei.value, NegativeAckError)


_FAILED_AUTH_EXPIRED_ELSEWHERE = {
    "faultstring": (
        b"<soap:Fault><faultcode>wsse:FailedAuthentication</faultcode>"
        b"<faultstring>token rejected, not MessageExpired</faultstring></soap:Fault>"
    ),
    "detail-12": (
        b"<soap:Fault><soap:Code><soap:Value>soap:Sender</soap:Value><soap:Subcode>"
        b"<soap:Value>wsse:FailedAuthentication</soap:Value></soap:Subcode></soap:Code>"
        b"<soap:Detail><note>MessageExpired</note></soap:Detail></soap:Fault>"
    ),
    "attribute-names-expired": (
        b'<soap:Fault><faultcode a="MessageExpired">wsse:FailedAuthentication</faultcode>'
        b"</soap:Fault>"
    ),
    "after-the-fault": (
        b"<soap:Envelope><soap:Body><soap:Fault><faultcode>wsse:InvalidSecurityToken</faultcode>"
        b"</soap:Fault></soap:Body></soap:Envelope><!-- MessageExpired -->"
    ),
}


@pytest.mark.parametrize(
    "body", list(_FAILED_AUTH_EXPIRED_ELSEWHERE.values()), ids=list(_FAILED_AUTH_EXPIRED_ELSEWHERE)
)
async def test_message_expired_outside_the_fault_code_does_not_block_the_bearer_retry(
    body: bytes,
) -> None:
    """BACKLOG #5798 added item 3: only the fault code element decides MessageExpired, so a
    FailedAuthentication or InvalidSecurityToken fault whose faultstring, Detail or trailing
    text says MessageExpired still gets its bearer retry. Mutation: search from the Fault start
    to the reply's end again. Red: a permanent wssecurity NegativeAckError."""
    dest, provider = _oauth2_dest()
    dest._opener = _Opener(exc=_http_error(401, body))  # type: ignore[assignment]
    with pytest.raises(DeliveryError) as ei:
        await dest.send("<op/>")
    assert not isinstance(ei.value, NegativeAckError)
    assert provider.invalidations == 1


_EXPIRED_IN_THE_CODE = {
    "subcode-12": (
        b"<soap:Fault><soap:Code><soap:Value>soap:Sender</soap:Value><soap:Subcode>"
        b"<soap:Value>wsse:MessageExpired</soap:Value></soap:Subcode></soap:Code>"
        b"<soap:Reason><soap:Text>expired</soap:Text></soap:Reason></soap:Fault>"
    ),
    "no-code-element": (b"<soap:Fault><faultstring>wsse:MessageExpired</faultstring></soap:Fault>"),
    "client-code-expired-elsewhere": (
        b"<soap:Fault><faultcode>soap:Client</faultcode>"
        b"<faultstring>wsse:MessageExpired</faultstring></soap:Fault>"
    ),
    "client-code-credential-in-detail": (
        b"<soap:Fault><faultcode>soap:Client</faultcode>"
        b"<faultstring>wsse:MessageExpired</faultstring>"
        b"<detail>InvalidSecurityToken</detail></soap:Fault>"
    ),
    "credential-code-in-a-comment": (
        b"<soap:Fault><faultcode><!-- FailedAuthentication -->soap:Client</faultcode>"
        b"<faultstring>wsse:MessageExpired</faultstring></soap:Fault>"
    ),
    "cdata-code-reads-as-main": (
        b"<soap:Fault><faultcode><![CDATA[wsse:FailedAuthentication]]></faultcode>"
        b"<faultstring>MessageExpired</faultstring></soap:Fault>"
    ),
    "comment-in-the-faultcode": (
        b"<soap:Fault><faultcode><!-- </faultcode> -->wsse:MessageExpired</faultcode>"
        b"<faultstring>FailedAuthentication</faultstring></soap:Fault>"
    ),
}


@pytest.mark.parametrize(
    "body", list(_EXPIRED_IN_THE_CODE.values()), ids=list(_EXPIRED_IN_THE_CODE)
)
async def test_control_message_expired_in_the_code_or_with_no_code_stays_permanent(
    body: bytes,
) -> None:
    """A SOAP 1.2 Subcode is inside the Code element, so it decides. A Fault with no code
    element, or a reply whose only WS-Security code is MessageExpired, keeps the earlier search,
    as on main ("client-code-expired-elsewhere", review round 2c51ab65; mutation: read only the
    code element whenever it is found, red: a bearer retry, then a lane stop), even where a
    credential code sits outside the code element ("client-code-credential-in-detail", round
    4c3aa241). A faultcode close
    tag inside a comment does not end the element (mutation: a plain close-tag search, red: a
    bearer retry)."""
    dest, _ = _oauth2_dest()
    dest._opener = _Opener(exc=_http_error(401, body))  # type: ignore[assignment]
    with pytest.raises(NegativeAckError) as ei:
        await dest.send("<op/>")
    assert ei.value.permanent is True and ei.value.code == "wssecurity"


async def test_control_an_oauth2_403_stays_permanent_and_keeps_the_token() -> None:
    dest, provider = _oauth2_dest()
    dest._opener = _Opener(exc=_http_error(403, b""))  # type: ignore[assignment]
    with pytest.raises(NegativeAckError) as ei:
        await dest.send("<env/>")
    assert ei.value.permanent is True
    assert provider.invalidations == 0


async def test_control_a_401_without_a_token_provider_stays_permanent() -> None:
    dest = _dest(basic_user="svc", basic_password="pw-synthetic")  # noqa: S106 -- synthetic
    dest._opener = _Opener(exc=_http_error(401, b""))  # type: ignore[assignment]
    with pytest.raises(NegativeAckError) as ei:
        await dest.send("<env/>")
    assert ei.value.permanent is True


def _expired_read_seconds(run: int) -> float:
    body = (
        "<soap:Fault><faultcode>" + "<" * run + "</faultcode>"
        "<faultstring>wsse:FailedAuthentication</faultstring></soap:Fault>"
    )
    best = float("inf")
    for _ in range(3):
        started = time.perf_counter()
        _names_expired_timestamp(body)
        best = min(best, time.perf_counter() - started)
    return best


def test_the_401_expired_read_is_linear_in_a_run_of_open_angle_brackets() -> None:
    """Review round 64cd4c17: the code element's tag strip once took time quadratic in a run of
    '<' with no '>', holding the GIL, so one 401 near the 16 MiB fault-body cap could stall the
    event loop for hours. Mutation: _TAG_RE back to r"<[^>]*>". Red: the 4x input takes about 16x
    as long, and the large read over a second."""
    small = _expired_read_seconds(50_000)
    large = _expired_read_seconds(200_000)
    assert large < 2.0
    assert large < 8 * max(small, 1e-3)
