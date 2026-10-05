# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A Digest challenge refused at send time is an auth refusal, not a bad request value (BACKLOG #2323).

``HttpAuthError`` is a ``ValueError``. Each HTTP-family send caught it in its
``(ValueError, InvalidURL)`` arm and reported "rejected an invalid request value", code
``bad-request-value``: a permanent fault of one message. So a refused Digest challenge would
dead-letter every queued row in turn, and would send an operator looking for a bad header.

Two layers, because either alone can pass on a broken fix:

* **Ten arms, with the refusal injected.** ``_post`` and ``_probe`` on REST, SOAP, FHIR and
  DICOMweb, and ``_get`` and ``_probe`` on the ``FhirLookup`` read. Each has a control showing a
  genuine bad request value still reports as one. The token hop in ``smart.py`` has its own arm and
  its own test, in ``tests/test_outbound_forward_proxy.py``.
* **On the wire, through the real opener.** A loopback peer sends the challenge, so the refusal is
  the one the Digest handlers raise and not one a test invented. A SHA-256 challenge is the control:
  it is answered and the send succeeds, so the new arm does not swallow a working exchange.

The last test drives the delivery worker, since the classification is only worth having if the lane
stops and the queue stays.
"""

from __future__ import annotations

import http.client
import http.server
import threading
import urllib.request
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest

from messagefoundry.config.fhir_lookup import FhirLookupError
from messagefoundry.config.models import ConnectorType, Destination
from messagefoundry.config.settings import EgressSettings
from messagefoundry.config.tls_policy import HopPosture, active_hop_posture
from messagefoundry.config.wiring import FHIR, DICOMweb, Registry, Rest, Soap
from messagefoundry.pipeline.alerts import LoggingAlertSink
from messagefoundry.pipeline.wiring_runner import RegistryRunner, _ItemOutcome
from messagefoundry.store.store import MessageStatus, MessageStore, OutboxStatus, Stage
from messagefoundry.transports import build_destination
from messagefoundry.transports.base import DeliveryError, NegativeAckError
from messagefoundry.transports.fhir import FhirLookupExecutor
from messagefoundry.transports.http_auth import HttpAuthError, with_http_digest
from messagefoundry.transports.rest import (
    AUTH_CHALLENGE_REFUSED,
    AUTH_CHALLENGE_REFUSED_CODE,
    auth_challenge_refused,
)
from tests._egress_policy import permitting

#: The query string is there to be dropped: without one ``_redact_url`` returns its input, and a
#: text built from the raw URL would pass every equality below.
HTTPS_URL = "https://api.example.com/x?site=SITE-QUERY"
REDACTED_URL = "https://api.example.com/x"
#: Off-box and unresolvable, so a proxied test that dialled direct would fail fast.
PROXIED_URL = "http://api.partner.invalid/x"
_WARN_DIAL = HopPosture(enforcing=False)
_FACTORY: dict[ConnectorType, Callable[..., Any]] = {
    ConnectorType.REST: Rest,
    ConnectorType.SOAP: Soap,
    ConnectorType.FHIR: FHIR,
    ConnectorType.DICOMWEB: DICOMweb,
}
_LABEL = {
    ConnectorType.REST: "REST",
    ConnectorType.SOAP: "SOAP",
    ConnectorType.FHIR: "FHIR",
    ConnectorType.DICOMWEB: "DICOMweb",
}
#: The peer's own words, as the Digest handlers quote them. None of it may reach the raised text.
_PEER_WORDS = "the endpoint's HTTP Digest challenge names algorithm 'MD5-PEER-TOKEN'"


def _refusal() -> HttpAuthError:
    return HttpAuthError(_PEER_WORDS)


class _Raises:
    """An opener whose ``open`` raises ``exc``."""

    def __init__(self, exc: Exception) -> None:
        self._exc = exc

    def open(self, req: urllib.request.Request, timeout: float | None = None) -> Any:
        raise self._exc


def _build(ctype: ConnectorType, url: str, *, digest: bool = False, **over: object) -> Any:
    spec = _FACTORY[ctype](url=url, **over)
    if digest:
        spec = with_http_digest(spec, user="u", password="p")
    with active_hop_posture(_WARN_DIAL):
        return build_destination(
            Destination(
                name="OB",
                type=ctype,
                settings=spec.settings,
                cleartext_accepted=url.startswith("http://"),
                cleartext_reason="test peer has no TLS" if url.startswith("http://") else None,
                tls_revocation_attested=True,
                tls_revocation_attested_reason="revocation-checking PKI at the partner edge",
            ),
            egress=permitting(spec.settings),
        )


def _send(ctype: ConnectorType, dest: Any) -> Any:
    """Call ``dest._post`` with the arguments its own ``send`` would pass."""
    if ctype is ConnectorType.FHIR:
        body = '{"resourceType": "Patient"}'
        return dest._post(body, "POST", f"{dest.base_url}/Patient", {})
    if ctype is ConnectorType.DICOMWEB:
        return dest._post(b"DICM-synthetic-object")
    return dest._post("<x/>")


# --- every destination arm, with the refusal injected ---------------------------------------------


@pytest.mark.parametrize("ctype", list(_FACTORY), ids=lambda c: c.value)
def test_post_reports_a_refused_challenge_as_a_configuration_fault(ctype: ConnectorType) -> None:
    dest = _build(ctype, HTTPS_URL)
    refused = _refusal()
    dest._opener = _Raises(refused)
    with pytest.raises(NegativeAckError) as ei:
        _send(ctype, dest)
    err = ei.value
    assert err.code == AUTH_CHALLENGE_REFUSED_CODE == "auth-challenge-refused"
    assert (err.permanent, err.config_fault, err.credential_fault) == (True, True, False)
    # Pinned as an equality: the fixed text, the redacted URL, and nothing of the peer's.
    assert str(err) == f"{_LABEL[ctype]} {REDACTED_URL} {AUTH_CHALLENGE_REFUSED}"
    assert "MD5-PEER-TOKEN" not in str(err)
    assert err.__cause__ is refused


@pytest.mark.parametrize("ctype", list(_FACTORY), ids=lambda c: c.value)
@pytest.mark.parametrize(
    "bad_value",
    [ValueError("Invalid header value b'x\\n'"), http.client.InvalidURL("nonnumeric port")],
    ids=["ValueError", "InvalidURL"],
)
def test_post_still_reports_a_bad_request_value_as_one(
    ctype: ConnectorType, bad_value: Exception
) -> None:
    """THE CONTROL. An arm that caught every ``ValueError`` as an auth refusal would pass the test
    above. A genuine bad value is this message's fault, so it must not stop the lane."""
    dest = _build(ctype, HTTPS_URL)
    dest._opener = _Raises(bad_value)
    with pytest.raises(NegativeAckError) as ei:
        _send(ctype, dest)
    err = ei.value
    assert err.code == "bad-request-value"
    assert (err.permanent, err.config_fault, err.credential_fault) == (True, False, False)
    assert str(err) == f"{_LABEL[ctype]} {REDACTED_URL} rejected an invalid request value"


@pytest.mark.parametrize("ctype", list(_FACTORY), ids=lambda c: c.value)
def test_probe_reports_a_refused_challenge_with_the_fixed_text(ctype: ConnectorType) -> None:
    dest = _build(ctype, HTTPS_URL)
    refused = _refusal()
    dest._opener = _Raises(refused)
    with pytest.raises(DeliveryError) as ei:
        dest._probe()
    # A probe raises a plain DeliveryError: there is no lane to stop on a test-connection.
    assert type(ei.value) is DeliveryError
    assert str(ei.value) == f"{_LABEL[ctype]} {REDACTED_URL} {AUTH_CHALLENGE_REFUSED}"
    assert ei.value.__cause__ is refused


@pytest.mark.parametrize("ctype", list(_FACTORY), ids=lambda c: c.value)
def test_probe_still_reports_a_bad_request_value_as_one(ctype: ConnectorType) -> None:
    dest = _build(ctype, HTTPS_URL)
    dest._opener = _Raises(ValueError("Invalid header value b'x\\n'"))
    with pytest.raises(DeliveryError) as ei:
        dest._probe()
    assert str(ei.value) == f"{_LABEL[ctype]} {REDACTED_URL} rejected an invalid request value"


# --- the FhirLookup read: only the web proxy's Digest handler is on this opener --------------------

_LOOKUP_BASE = "https://fhir.example.org/fhir?site=SITE-QUERY"
_LOOKUP_REDACTED = "https://fhir.example.org/fhir"


def _lookup(exc: Exception) -> FhirLookupExecutor:
    ex = FhirLookupExecutor(
        {"epic": {"url": _LOOKUP_BASE}}, egress=EgressSettings(deny_by_default=False)
    )
    ex._opener["epic"] = _Raises(exc)  # type: ignore[assignment]
    return ex


_LOOKUP_ARMS: dict[str, tuple[Callable[[FhirLookupExecutor], Any], str]] = {
    "_get": (
        lambda ex: ex._get("epic", "https://fhir.example.org/fhir/Patient/1"),
        "fhir_lookup on 'epic'",
    ),
    "_probe": (lambda ex: ex._probe("epic"), "FhirLookup 'epic'"),
}


@pytest.mark.parametrize("arm", list(_LOOKUP_ARMS))
def test_fhir_lookup_reports_a_refused_challenge_with_the_fixed_text(arm: str) -> None:
    call, prefix = _LOOKUP_ARMS[arm]
    refused = _refusal()
    with pytest.raises(FhirLookupError) as ei:
        call(_lookup(refused))
    assert str(ei.value) == f"{prefix}: FHIR {_LOOKUP_REDACTED} {AUTH_CHALLENGE_REFUSED}"
    assert ei.value.__cause__ is refused


@pytest.mark.parametrize("arm", list(_LOOKUP_ARMS))
def test_fhir_lookup_still_reports_a_bad_request_value_as_one(arm: str) -> None:
    call, prefix = _LOOKUP_ARMS[arm]
    with pytest.raises(FhirLookupError) as ei:
        call(_lookup(ValueError("Invalid header value b'x\\n'")))
    assert str(ei.value) == f"{prefix}: FHIR {_LOOKUP_REDACTED} rejected an invalid request value"


# --- on the wire: the refusal the Digest handlers really raise -------------------------------------


class _Challenger:
    """A loopback peer. A request with no credential gets ``status`` and ``challenge``; one that
    carries a credential gets a 200. ``status`` 401 makes it an endpoint, 407 a web proxy. It records
    each credential it was shown, so a test can see that a refused challenge was never answered."""

    def __init__(self, status: int, challenge: str) -> None:
        self.answered: list[str] = []
        self.requests = 0
        ask, answer = (
            ("WWW-Authenticate", "Authorization")
            if status == 401
            else ("Proxy-Authenticate", "Proxy-Authorization")
        )
        outer = self

        class _Handler(http.server.BaseHTTPRequestHandler):
            def _serve(self) -> None:
                outer.requests += 1
                self.rfile.read(int(self.headers.get("Content-Length") or 0))
                credential = self.headers.get(answer)
                body = b""
                if credential is None:
                    self.send_response(status)
                    self.send_header(ask, challenge)
                else:
                    outer.answered.append(credential)
                    self.send_response(200)
                    body = b"{}" if self.command != "HEAD" else b""
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            do_GET = do_POST = do_HEAD = do_OPTIONS = _serve

            def log_message(self, format: str, *args: object) -> None:  # noqa: A002
                return

        self._server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        self.url = f"http://127.0.0.1:{self._server.server_address[1]}"
        # A short poll, so shutdown() does not wait out serve_forever's default half second.
        self._thread = threading.Thread(
            target=self._server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True
        )

    def __enter__(self) -> _Challenger:
        self._thread.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self._server.shutdown()
        self._server.server_close()
        self._thread.join(timeout=5)


_MD5 = 'Digest realm="r", nonce="n0nce", qop="auth", algorithm=MD5'
_SHA256 = 'Digest realm="r", nonce="n0nce", qop="auth", algorithm=SHA-256'
_ORIGIN_DIGEST = [ConnectorType.REST, ConnectorType.SOAP, ConnectorType.FHIR]


@pytest.fixture
def no_bypass(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Pin urllib's ``proxy_bypass`` off: on Windows it reads the registry's override list, which
    may name local addresses, and a bypassed request never reaches the proxy's 407."""
    monkeypatch.setattr(urllib.request, "proxy_bypass", lambda host: False)
    yield


@pytest.mark.parametrize("ctype", _ORIGIN_DIGEST, ids=lambda c: c.value)
def test_an_endpoints_md5_challenge_is_a_configuration_fault_on_the_wire(
    ctype: ConnectorType,
) -> None:
    with _Challenger(401, _MD5) as origin:
        dest = _build(ctype, f"{origin.url}/x", digest=True)
        with pytest.raises(NegativeAckError) as ei:
            _send(ctype, dest)
        assert ei.value.code == AUTH_CHALLENGE_REFUSED_CODE
        assert ei.value.config_fault is True
        assert "MD5" not in str(ei.value)
        assert isinstance(ei.value.__cause__, HttpAuthError)
        with pytest.raises(DeliveryError, match="will not answer") as probe:
            dest._probe()
        assert type(probe.value) is DeliveryError
    assert origin.answered == [], "the engine answered a challenge it reports as refused"
    assert origin.requests == 2  # one unanswered request per call, and no retry inside either


@pytest.mark.parametrize("ctype", _ORIGIN_DIGEST, ids=lambda c: c.value)
def test_an_endpoints_sha256_challenge_is_still_answered(ctype: ConnectorType) -> None:
    """THE CONTROL on the wire: the new arm must not turn a working Digest exchange into a stop."""
    with _Challenger(401, _SHA256) as origin:
        dest = _build(ctype, f"{origin.url}/x", digest=True)
        assert _send(ctype, dest)[1] == 200
        dest._probe()
    assert len(origin.answered) == 2
    assert all('algorithm="SHA-256"' in a for a in origin.answered)


def _through_digest_proxy(ctype: ConnectorType, proxy_url: str) -> Any:
    return _build(
        ctype,
        PROXIED_URL,
        proxy=proxy_url,
        proxy_user="pu",
        proxy_password="pw",
        proxy_auth_type="digest",
    )


@pytest.mark.usefixtures("no_bypass")
@pytest.mark.parametrize("ctype", list(_FACTORY), ids=lambda c: c.value)
def test_a_web_proxys_md5_challenge_is_a_configuration_fault_on_the_wire(
    ctype: ConnectorType,
) -> None:
    """DICOMweb has no origin Digest, so the proxy's 407 is the only way its arm is reached."""
    with _Challenger(407, _MD5) as proxy:
        dest = _through_digest_proxy(ctype, proxy.url)
        with pytest.raises(NegativeAckError) as ei:
            _send(ctype, dest)
        assert ei.value.code == AUTH_CHALLENGE_REFUSED_CODE
        assert ei.value.config_fault is True
        with pytest.raises(DeliveryError, match="will not answer") as probe:
            dest._probe()
        assert type(probe.value) is DeliveryError
    assert proxy.answered == []
    assert proxy.requests == 2


@pytest.mark.usefixtures("no_bypass")
@pytest.mark.parametrize("ctype", list(_FACTORY), ids=lambda c: c.value)
def test_a_web_proxys_sha256_challenge_is_still_answered(ctype: ConnectorType) -> None:
    with _Challenger(407, _SHA256) as proxy:
        dest = _through_digest_proxy(ctype, proxy.url)
        assert _send(ctype, dest)[1] == 200
        dest._probe()
    assert len(proxy.answered) == 2


def _proxied_lookup(proxy_url: str) -> FhirLookupExecutor:
    settings = {
        "url": "http://fhir.partner.invalid/fhir",
        "proxy_url": proxy_url,
        "proxy_user": "pu",
        "proxy_password": "pw",
        "proxy_auth_type": "digest",
        "cleartext_accepted": True,
        "cleartext_reason": "test peer has no TLS",
    }
    with active_hop_posture(_WARN_DIAL):
        return FhirLookupExecutor({"epic": settings}, egress=permitting(settings))


@pytest.mark.usefixtures("no_bypass")
def test_a_web_proxys_md5_challenge_fails_the_fhir_lookup_as_an_auth_refusal() -> None:
    with _Challenger(407, _MD5) as proxy:
        ex = _proxied_lookup(proxy.url)
        with pytest.raises(FhirLookupError, match="will not answer") as read:
            ex._get("epic", "http://fhir.partner.invalid/fhir/Patient/1")
        assert "MD5" not in str(read.value)
        with pytest.raises(FhirLookupError, match="will not answer"):
            ex._probe("epic")
    assert proxy.answered == []


@pytest.mark.usefixtures("no_bypass")
def test_a_web_proxys_sha256_challenge_still_lets_the_fhir_lookup_through() -> None:
    with _Challenger(407, _SHA256) as proxy:
        ex = _proxied_lookup(proxy.url)
        assert ex._get("epic", "http://fhir.partner.invalid/fhir/Patient/1") == ("{}", 200)
        ex._probe("epic")
    assert len(proxy.answered) == 2


# --- the delivery worker: the lane stops and the queue stays --------------------------------------

RAW = "MSH|^~\\&|S|F|R|RF|20260101||ADT^A01|MSG1|P|2.5.1\r"
CHANNEL = "IB_TEST"
DEST = "OB_REST"


class _Stops(LoggingAlertSink):
    def __init__(self) -> None:
        self.stopped: list[tuple[str, str]] = []

    def connection_stopped(self, name: str, *, detail: str) -> None:
        self.stopped.append((name, detail))


class _Refusing:
    """An outbound whose every send meets the refused challenge, or a bad request value."""

    capture_response = False

    def __init__(self, exc: NegativeAckError) -> None:
        self._exc = exc

    async def send(self, payload: str) -> None:
        raise self._exc

    async def aclose(self) -> None:  # pragma: no cover - not exercised
        pass


async def _deliver_one(tmp_path: Path, exc: NegativeAckError) -> tuple[Any, str, _Stops]:
    """Queue one outbound row, deliver it through ``exc``, and return the outcome, the row's
    status and the alert sink."""
    store = await MessageStore.open(tmp_path / "digest.db")
    try:
        mid = await store.enqueue_ingress(channel_id=CHANNEL, raw=RAW, now=0.0)
        ing = await store.claim_next_fifo(CHANNEL, stage=Stage.INGRESS.value, now=0.0)
        assert ing is not None
        await store.route_handoff(
            ingress_id=ing.id,
            message_id=mid,
            channel_id=CHANNEL,
            handlers=[("h1", RAW)],
            disposition=MessageStatus.ROUTED,
            now=0.0,
        )
        routed = await store.claim_next_fifo(CHANNEL, stage=Stage.ROUTED.value, now=0.0)
        assert routed is not None
        await store.transform_handoff(
            routed_id=routed.id,
            message_id=mid,
            channel_id=CHANNEL,
            deliveries=[(DEST, RAW)],
            now=0.0,
        )
        sink = _Stops()
        runner = RegistryRunner(
            Registry(),
            store,
            poll_interval=0.02,
            alert_sink=sink,
            egress=EgressSettings(deny_by_default=False),
        )
        runner._destinations[DEST] = _Refusing(exc)  # type: ignore[assignment]
        item = await store.claim_next_fifo(DEST, now=1.0)
        assert item is not None
        outcome = await runner._process_delivery_item(DEST, item)
        cur = await store._db.execute(
            "SELECT status FROM queue WHERE message_id=? AND stage=?", (mid, Stage.OUTBOUND.value)
        )
        row = await cur.fetchone()
        assert row is not None
        return outcome[0], str(row[0]), sink
    finally:
        await store.close()


async def test_a_refused_challenge_stops_the_lane_and_keeps_the_row(tmp_path: Path) -> None:
    outcome, status, sink = await _deliver_one(tmp_path, auth_challenge_refused("REST https://h/x"))
    assert outcome is _ItemOutcome.STOPPED
    assert status == OutboxStatus.PENDING.value, "the row was not kept for the operator"
    assert [name for name, _ in sink.stopped] == [DEST]
    assert "configuration fault (auth-challenge-refused)" in sink.stopped[0][1]


async def test_a_bad_request_value_still_dead_letters_one_row(tmp_path: Path) -> None:
    """THE CONTROL: what the refusal was reported as before, and what a real bad value still is."""
    bad = NegativeAckError(
        "REST https://h/x rejected an invalid request value",
        code="bad-request-value",
        permanent=True,
    )
    outcome, status, sink = await _deliver_one(tmp_path, bad)
    assert outcome is _ItemOutcome.PROCESSED
    assert status == OutboxStatus.DEAD.value
    assert sink.stopped == []
