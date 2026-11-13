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
  genuine bad request value still reports as one. The token hop in ``smart.py`` has its own arm,
  tested in ``tests/test_outbound_forward_proxy.py`` and, for its code, at the end of this file.
* **On the wire, through the real opener.** A loopback peer sends the challenge, so the refusal is
  the one the Digest handlers raise and not one a test invented. A SHA-256 challenge is the control:
  it is answered and the send succeeds, so the new arm does not swallow a working exchange.

The delivery-worker tests show the lane stops and the queue stays, since the classification is only
worth having if it does. The section at the end holds the follow-ups of BACKLOG #2989: an
unsupported ``qop``, a challenge with no nonce or realm, a 407 on a request that bypassed the proxy,
the token hop, and a send-time hop refusal that wins over a Digest refusal.
"""

from __future__ import annotations

import http.client
import http.server
import threading
import urllib.error
import urllib.request
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest

from messagefoundry.config.fhir_lookup import FhirLookupError
from messagefoundry.config.models import ConnectorType, Destination, SignatureAlgorithm
from messagefoundry.config.settings import EgressSettings
from messagefoundry.config.tls_policy import HopPosture, InsecureHopRefused, active_hop_posture
from messagefoundry.config.wiring import FHIR, DICOMweb, Registry, Rest, Soap
from messagefoundry.pipeline.alerts import LoggingAlertSink
from messagefoundry.pipeline.wiring_runner import RegistryRunner, _ItemOutcome
from messagefoundry.store.store import MessageStatus, MessageStore, OutboxStatus, Stage
from messagefoundry.transports import build_destination
from messagefoundry.transports.base import (
    INSECURE_HOP_REFUSED_CODE,
    DeliveryError,
    NegativeAckError,
)
from messagefoundry.transports.bounded_read import ProxyTunnelRefusedError
from messagefoundry.transports.fhir import FhirLookupExecutor
from messagefoundry.transports.http_auth import (
    HttpAuthError,
    OAuth2ClientCredentialsProvider,
    with_http_digest,
    with_oauth2_client_credentials,
)
from messagefoundry.transports.rest import (
    AUTH_CHALLENGE_REFUSED,
    AUTH_CHALLENGE_REFUSED_CODE,
    AUTH_CHALLENGE_REFUSED_ON_CONNECT,
    InsecureHopGuard,
    ProxyConfig,
    auth_challenge_refused,
    is_refused_proxy_digest_tunnel,
    proxy_config_from_settings,
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


def _build(
    ctype: ConnectorType,
    url: str,
    *,
    digest: bool = False,
    oauth2_token_url: str | None = None,
    **over: object,
) -> Any:
    spec = _FACTORY[ctype](url=url, **over)
    if digest:
        spec = with_http_digest(spec, user="u", password="p")
    if oauth2_token_url is not None:
        spec = with_oauth2_client_credentials(
            spec, token_url=oauth2_token_url, client_id="cid", client_secret="s3cr3t"
        )
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
    carries a credential gets a 200, or ``status`` again with ``refuse_answered``. ``status`` 401
    makes it an endpoint, 407 a web proxy. It records each credential it was shown, so a test can
    see that a refused challenge was never answered."""

    def __init__(self, status: int, challenge: str, *, refuse_answered: bool = False) -> None:
        # ``refuse_answered`` plays a peer that rejects the credential it was shown: it records the
        # credential and sends ``status`` again, as a proxy refusing a wrong password does.
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
                if credential is not None:
                    outer.answered.append(credential)
                if credential is None or refuse_answered:
                    self.send_response(status)
                    self.send_header(ask, challenge)
                else:
                    self.send_response(200)
                    # No body on a HEAD reply or a CONNECT 200. This peer relays no tunnel.
                    body = b"{}" if self.command not in ("HEAD", "CONNECT") else b""
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            # CONNECT is what an https target behind the proxy sends first (BACKLOG #2989).
            do_GET = do_POST = do_HEAD = do_OPTIONS = do_CONNECT = _serve

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


async def _deliver_one(tmp_path: Path, dest: Any) -> tuple[Any, str, _Stops]:
    """Queue one outbound row, deliver it through ``dest``, and return the outcome, the row's
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
        runner._destinations[DEST] = dest
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
    outcome, status, sink = await _deliver_one(
        tmp_path, _Refusing(auth_challenge_refused("REST https://h/x"))
    )
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
    outcome, status, sink = await _deliver_one(tmp_path, _Refusing(bad))
    assert outcome is _ItemOutcome.PROCESSED
    assert status == OutboxStatus.DEAD.value
    assert sink.stopped == []


# --- BACKLOG #2989: the follow-ups to engine PR 2013 ----------------------------------------------


def _assert_refused_challenge(err: NegativeAckError) -> None:
    assert err.code == AUTH_CHALLENGE_REFUSED_CODE
    assert (err.permanent, err.config_fault) == (True, True)
    assert isinstance(err.__cause__, HttpAuthError)


#: Finding 1. urllib raised ``URLError("qop ... is not supported")`` for both, which read as an
#: unreachable host and was retried. The second is a legal list, written with a space.
_AUTH_INT = 'Digest realm="r", nonce="n0nce", qop="auth-int", algorithm=SHA-256'
_AUTH_INT_THEN_AUTH = 'Digest realm="r", nonce="n0nce", qop="auth-int, auth", algorithm=SHA-256'
#: Finding 4. urllib returned None on the KeyError, so each read as a plain 401 or 407.
_NO_NONCE = 'Digest realm="r", qop="auth", algorithm=SHA-256'
_NO_REALM = 'Digest nonce="n0nce", qop="auth", algorithm=SHA-256'


@pytest.mark.parametrize(
    "challenge", [_AUTH_INT, _NO_NONCE, _NO_REALM], ids=["auth-int", "no-nonce", "no-realm"]
)
@pytest.mark.parametrize("ctype", _ORIGIN_DIGEST, ids=lambda c: c.value)
def test_an_unanswerable_endpoint_challenge_is_a_configuration_fault(
    ctype: ConnectorType, challenge: str
) -> None:
    with _Challenger(401, challenge) as origin:
        dest = _build(ctype, f"{origin.url}/x", digest=True)
        with pytest.raises(NegativeAckError) as ei:
            _send(ctype, dest)
        _assert_refused_challenge(ei.value)
    assert origin.answered == []
    assert origin.requests == 1


@pytest.mark.usefixtures("no_bypass")
@pytest.mark.parametrize(
    "challenge", [_AUTH_INT, _NO_NONCE, _NO_REALM], ids=["auth-int", "no-nonce", "no-realm"]
)
@pytest.mark.parametrize("ctype", list(_FACTORY), ids=lambda c: c.value)
def test_an_unanswerable_proxy_challenge_is_a_configuration_fault(
    ctype: ConnectorType, challenge: str
) -> None:
    with _Challenger(407, challenge) as proxy:
        dest = _through_digest_proxy(ctype, proxy.url)
        with pytest.raises(NegativeAckError) as ei:
            _send(ctype, dest)
        _assert_refused_challenge(ei.value)
    assert proxy.answered == []


@pytest.mark.parametrize("ctype", _ORIGIN_DIGEST, ids=lambda c: c.value)
def test_a_qop_list_that_offers_auth_is_answered_with_auth(ctype: ConnectorType) -> None:
    """THE CONTROL for the qop refusal, and the half of finding 1 that must SUCCEED: the peer
    offers ``auth`` after a space, so the engine answers with ``qop=auth`` and nothing else."""
    with _Challenger(401, _AUTH_INT_THEN_AUTH) as origin:
        dest = _build(ctype, f"{origin.url}/x", digest=True)
        assert _send(ctype, dest)[1] == 200
    (answer,) = origin.answered
    assert "qop=auth," in answer
    assert "auth-int" not in answer


@pytest.mark.usefixtures("no_bypass")
def test_a_proxy_qop_list_that_offers_auth_is_answered_with_auth() -> None:
    with _Challenger(407, _AUTH_INT_THEN_AUTH) as proxy:
        dest = _through_digest_proxy(ConnectorType.REST, proxy.url)
        assert _send(ConnectorType.REST, dest)[1] == 200
    (answer,) = proxy.answered
    assert "qop=auth," in answer


def test_a_bypassed_407_carrying_ntlm_surfaces_as_the_407() -> None:
    """Finding 5. The opener is built for an off-box destination behind a Digest proxy, so it
    carries the proxy Digest handler. A request to a loopback origin goes direct (vault BACKLOG
    #2579), and that origin answers 407 with NTLM. The 407 did not come from the proxy, so the
    proxy handler must not screen it: before the fix it raised ``HttpAuthError``, which a send
    reports as the proxy's refused challenge and which stops the lane."""
    dest = _through_digest_proxy(ConnectorType.REST, "http://127.0.0.1:3128")
    with _Challenger(407, 'NTLM realm="r"') as origin:
        with pytest.raises(urllib.error.HTTPError) as ei:
            dest._opener.open(urllib.request.Request(f"{origin.url}/x"), timeout=10)
        ei.value.close()
    assert ei.value.code == 407
    assert origin.answered == []


def test_the_token_hop_refusal_is_the_same_configuration_fault() -> None:
    """Finding 3. The token hop gave this refusal a retryable ``DeliveryError``, so a bearer
    connection behind a refusing proxy retried when the token had to be minted and stopped when
    it was cached."""
    from messagefoundry.transports.smart import request_token

    refused = _refusal()
    req = urllib.request.Request("http://127.0.0.1:9/token")
    opener: Any = _Raises(refused)
    with pytest.raises(NegativeAckError) as ei:
        request_token(
            opener,
            req,
            timeout=1,
            endpoint="SMART token endpoint",
            connector="c",
            digest_proxy=True,
        )
    err = ei.value
    assert err.code == AUTH_CHALLENGE_REFUSED_CODE
    assert (err.permanent, err.config_fault) == (True, True)
    assert str(err) == f"SMART token endpoint {AUTH_CHALLENGE_REFUSED}"
    assert "MD5-PEER-TOKEN" not in str(err)
    assert err.__cause__ is refused


#: Reserved and unresolvable: the CONNECT names it, and nothing may ever dial it.
_HTTPS_TOKEN_URL = "https://auth.partner.invalid/token?tenant=SITE-QUERY"
_HTTPS_TOKEN_LABEL = "OAuth2 token endpoint https://auth.partner.invalid/token"


def _digest_proxy_config(proxy_url: str, *, auth: str | None) -> ProxyConfig:
    """``proxy_url`` with no proxy credential, a pre-emptive Basic one, or a Digest one. Proxy
    Digest is refused for an https destination, so the proxy is built for an http one, as it must
    be."""
    settings: dict[str, object] = {"proxy_url": proxy_url}
    if auth is not None:
        settings |= {"proxy_user": "pu", "proxy_password": "pw", "proxy_auth_type": auth}
    with active_hop_posture(_WARN_DIAL):
        proxy = proxy_config_from_settings(
            settings,
            dest_scheme="http" if auth == "digest" else "https",
            cleartext_accepted=auth is not None,
            cleartext_reason="loopback test proxy has no TLS" if auth is not None else None,
            connection=None,
        )
    assert isinstance(proxy, ProxyConfig)
    return proxy


def _token_provider_via(proxy_url: str, *, auth: str | None) -> OAuth2ClientCredentialsProvider:
    """An OAuth2 provider whose https token endpoint is behind ``proxy_url``. The token hop is the
    shared ``smart._TokenEndpointProvider``, so the SMART provider takes the same path."""
    return OAuth2ClientCredentialsProvider(
        token_url=_HTTPS_TOKEN_URL,
        client_id="cid",
        client_secret="s3cr3t",
        proxy=_digest_proxy_config(proxy_url, auth=auth),
    )


@pytest.mark.usefixtures("no_bypass")
@pytest.mark.parametrize(
    "challenge", [_SHA256, 'Basic realm="proxy"'], ids=["sha256-digest", "basic"]
)
def test_an_https_token_endpoints_digest_proxy_407_is_the_same_configuration_fault(
    challenge: str,
) -> None:
    """Finding 3, the half engine PR 2280 left open (vault BACKLOG #3532 item 1). ADR 0095 B.1
    states the case. Before engine PR 2827 this was a plain ``DeliveryError``, retried. The text
    names the proxy's ``CONNECT``, not a challenge the engine screened (BACKLOG #2989 item 14)."""
    with _Challenger(407, challenge, refuse_answered=True) as proxy:
        provider = _token_provider_via(proxy.url, auth="digest")
        with pytest.raises(NegativeAckError) as ei:
            provider.access_token()
    err = ei.value
    assert err.code == AUTH_CHALLENGE_REFUSED_CODE
    assert (err.permanent, err.config_fault) == (True, True)
    assert str(err) == f"{_HTTPS_TOKEN_LABEL} {AUTH_CHALLENGE_REFUSED_ON_CONNECT}"
    cause = err.__cause__
    assert isinstance(cause, urllib.error.URLError)
    # The status the proxy's status line gave, read off the strict connection, not its text.
    assert isinstance(cause.reason, ProxyTunnelRefusedError)
    assert cause.reason.status == 407
    assert proxy.requests == 1
    assert proxy.answered == [], "Digest sends no pre-emptive credential"


class _NoHandlers:
    """An opener that passes every call to ``opener`` and has no ``handlers`` attribute."""

    def __init__(self, opener: urllib.request.OpenerDirector) -> None:
        self._opener = opener

    def open(self, req: urllib.request.Request, timeout: float | None = None) -> Any:
        return self._opener.open(req, timeout=timeout)


@pytest.mark.usefixtures("no_bypass")
def test_an_opener_without_handlers_still_meets_the_digest_connect_refusal() -> None:
    """BACKLOG #2989 item 15. The match once read the Digest handler off ``opener.handlers`` with a
    default of none, so an opener without that attribute silently read as "not this fault" and the
    mint retried. The hop's Digest setup is now decided when it is built. Fails on the code before
    that change: the same CONNECT 407 there is a retryable ``DeliveryError``."""
    with _Challenger(407, _SHA256, refuse_answered=True) as proxy:
        provider = _token_provider_via(proxy.url, auth="digest")
        provider._opener = _NoHandlers(provider._opener)  # type: ignore[assignment]
        with pytest.raises(NegativeAckError) as ei:
            provider.access_token()
    assert ei.value.code == AUTH_CHALLENGE_REFUSED_CODE
    assert proxy.requests == 1


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


@pytest.mark.usefixtures("no_bypass")
def test_a_smart_providers_digest_proxy_connect_407_is_the_same_configuration_fault(
    ec_pem: str,
) -> None:
    """BACKLOG #2989 item 17. The SMART provider shares the token hop with OAuth2, and this runs it
    on the wire rather than through OAuth2."""
    from messagefoundry.transports.smart import SmartBackendTokenProvider

    with _Challenger(407, _SHA256, refuse_answered=True) as proxy:
        provider = SmartBackendTokenProvider(
            token_url=_HTTPS_TOKEN_URL,
            client_id="cid",
            private_key=ec_pem,
            algorithm=SignatureAlgorithm.ES256,
            scope="system/*.rs",
            proxy=_digest_proxy_config(proxy.url, auth="digest"),
        )
        with pytest.raises(NegativeAckError) as ei:
            provider.access_token()
    err = ei.value
    assert err.code == AUTH_CHALLENGE_REFUSED_CODE
    assert (err.permanent, err.config_fault) == (True, True)
    assert str(err) == (
        f"SMART token endpoint https://auth.partner.invalid/token {AUTH_CHALLENGE_REFUSED_ON_CONNECT}"
    )
    assert proxy.requests == 1
    assert proxy.answered == []


def _bearer_rest_via(proxy_url: str) -> Any:
    """A REST destination on a loopback ``http://`` URL, whose OAuth2 token endpoint is ``https://``
    and behind a web proxy set up for Digest: the configuration this case needs (ADR 0095 B.1). The
    destination's own hop is loopback, so it is dialled direct; only the token request meets the
    proxy, and it fails before any delivery byte is sent."""
    return _build(
        ConnectorType.REST,
        "http://127.0.0.1:9/x",
        proxy=proxy_url,
        proxy_user="pu",
        proxy_password="pw",
        proxy_auth_type="digest",
        oauth2_token_url=_HTTPS_TOKEN_URL,
    )


@pytest.mark.usefixtures("no_bypass")
async def test_the_digest_connect_refusal_stops_the_lane_and_keeps_the_row(tmp_path: Path) -> None:
    """BACKLOG #2989 item 17: the delivery worker, not only the raised fault. A real REST
    destination mints its bearer through the proxy, meets the CONNECT 407, and the lane stops
    with the row kept, as for any refused challenge."""
    with _Challenger(407, _SHA256, refuse_answered=True) as proxy:
        dest = _bearer_rest_via(proxy.url)
        outcome, status, sink = await _deliver_one(tmp_path, dest)
    assert outcome is _ItemOutcome.STOPPED
    assert status == OutboxStatus.PENDING.value, "the row was not kept for the operator"
    assert [name for name, _ in sink.stopped] == [DEST]
    assert "configuration fault (auth-challenge-refused)" in sink.stopped[0][1]
    assert proxy.requests == 1


@pytest.mark.usefixtures("no_bypass")
def test_a_probe_that_mints_a_bearer_reports_the_digest_connect_refusal() -> None:
    """BACKLOG #2989 item 17: the test-connection probe mints the bearer first, so it meets the
    same refusal, with its marker and the text naming the proxy's CONNECT."""
    with _Challenger(407, _SHA256, refuse_answered=True) as proxy:
        dest = _bearer_rest_via(proxy.url)
        with pytest.raises(DeliveryError) as ei:
            dest._probe()
    assert isinstance(ei.value, NegativeAckError)
    assert ei.value.code == AUTH_CHALLENGE_REFUSED_CODE
    assert str(ei.value) == f"{_HTTPS_TOKEN_LABEL} {AUTH_CHALLENGE_REFUSED_ON_CONNECT}"
    assert proxy.requests == 1


@pytest.mark.usefixtures("no_bypass")
@pytest.mark.parametrize(
    ("status", "auth"),
    [(407, None), (407, "basic"), (403, "digest"), (502, "digest")],
    ids=["407-no-credential", "407-basic-rejected", "403-digest", "502-digest"],
)
def test_an_https_token_endpoints_other_tunnel_refusal_still_retries(
    status: int, auth: str | None
) -> None:
    """THE CONTROLS. With no Digest set up, a CONNECT 407 is the plain 407 an http token endpoint
    also retries (ADR 0095 B.1 keeps a Basic challenge a plain status). Any other CONNECT status
    is not a challenge."""
    with _Challenger(status, 'Basic realm="proxy"', refuse_answered=True) as proxy:
        provider = _token_provider_via(proxy.url, auth=auth)
        with pytest.raises(DeliveryError) as ei:
            provider.access_token()
    assert type(ei.value) is DeliveryError
    assert str(ei.value).startswith(
        f"{_HTTPS_TOKEN_LABEL} unreachable: Tunnel connection failed: {status} "
    )
    assert proxy.requests == 1
    # The Basic case is real only if the credential went out on the CONNECT.
    assert [a.split()[0] for a in proxy.answered] == (["Basic"] if auth == "basic" else [])


_TUNNEL_407 = "Tunnel connection failed: 407 x"


@pytest.mark.parametrize(
    ("reason", "digest_proxy"),
    [
        (ProxyTunnelRefusedError(_TUNNEL_407, status=407), False),
        (ProxyTunnelRefusedError("Tunnel connection failed: 403 x", status=403), True),
        (OSError(_TUNNEL_407), True),
        (ConnectionResetError(_TUNNEL_407), True),
        (_TUNNEL_407, True),
    ],
    ids=["no-digest-proxy", "status-403", "bare-oserror-text", "oserror-subclass", "string"],
)
def test_the_connect_407_match_reads_the_status_and_the_built_digest_setup(
    reason: object, digest_proxy: bool
) -> None:
    """The match takes the status from ``ProxyTunnelRefusedError`` and the Digest setup from the
    hop's build, and reads no text: a bare ``OSError`` carrying ``_tunnel``'s 407 text does not
    match, because every engine opener raises the typed error for a refused CONNECT."""
    match = ProxyTunnelRefusedError(_TUNNEL_407, status=407)
    assert is_refused_proxy_digest_tunnel(urllib.error.URLError(match), digest_proxy=True)
    refused = urllib.error.URLError(reason)  # type: ignore[arg-type]
    assert not is_refused_proxy_digest_tunnel(refused, digest_proxy=digest_proxy)


class _ConnectReply:
    """A socket whose reader holds the proxy's status line and nothing after it."""

    def __init__(self, status_line: bytes) -> None:
        self._status_line = status_line

    def makefile(self, mode: str) -> Any:
        import io

        return io.BytesIO(self._status_line)


@pytest.mark.parametrize(
    ("status_line", "raised", "typed"),
    [
        (b"HTTP/1.1 407 x\r\n", OSError("Tunnel connection failed: 407 x"), True),
        (b"HTTP/1.1 407 x\r\n", ConnectionResetError(104, "reset while reading the head"), False),
        (b"HTTP/1.1 407 x\r\n", OSError(113, "no route"), False),
        (b"HTTP/1.1 407 x\r\n", TimeoutError("timed out"), False),
        (b"HTTP/1.1 200 OK\r\n", OSError("closed after the tunnel opened"), False),
    ],
    ids=["tunnel-refusal", "reset-after-status", "errno-oserror", "timeout", "status-200"],
)
def test_the_strict_connection_types_only_its_own_tunnel_refusal(
    monkeypatch: pytest.MonkeyPatch, status_line: bytes, raised: OSError, typed: bool
) -> None:
    """The pass-through arms of ``_StrictHTTPSConnection._tunnel``. A socket error after the
    proxy's 407 status line was read keeps its own type, so it stays the transient it was rather
    than becoming the refusal that stops the lane. The stand-in reads the status as ``_tunnel``
    does, then raises."""
    from messagefoundry.transports import bounded_read

    def tunnel(self: http.client.HTTPConnection) -> None:
        response = self.response_class(_ConnectReply(status_line))  # type: ignore[arg-type]
        response._read_status()  # type: ignore[attr-defined]
        raise raised

    monkeypatch.setattr(http.client.HTTPConnection, "_tunnel", tunnel)
    conn = bounded_read._StrictHTTPSConnection("proxy.invalid")
    with pytest.raises(OSError) as ei:
        conn._tunnel()
    if typed:
        assert isinstance(ei.value, ProxyTunnelRefusedError)
        assert ei.value.status == 407
        assert str(ei.value) == str(raised)
    else:
        assert ei.value is raised
    assert "response_class" not in vars(conn), "the CONNECT reply hook outlived the tunnel"


def test_the_strict_tunnel_restores_an_instance_response_class(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A response class set on the connection itself reads the CONNECT reply and is put back."""
    from messagefoundry.transports import bounded_read

    seen: list[type] = []

    def tunnel(self: http.client.HTTPConnection) -> None:
        response = self.response_class(_ConnectReply(b"HTTP/1.1 403 x\r\n"))  # type: ignore[arg-type]
        seen.append(type(response))
        response._read_status()  # type: ignore[attr-defined]
        raise OSError("Tunnel connection failed: 403 x")

    class _Own(bounded_read.StrictHTTPResponse):
        pass

    monkeypatch.setattr(http.client.HTTPConnection, "_tunnel", tunnel)
    conn = bounded_read._StrictHTTPSConnection("proxy.invalid")
    conn.response_class = _Own
    with pytest.raises(ProxyTunnelRefusedError) as ei:
        conn._tunnel()
    assert ei.value.status == 403
    assert seen == [_Own]
    assert vars(conn)["response_class"] is _Own


def test_the_typed_tunnel_refusal_survives_a_copy() -> None:
    import copy
    import pickle

    err = ProxyTunnelRefusedError("Tunnel connection failed: 407 x", status=407)
    err.add_note("kept")
    for clone in (copy.copy(err), pickle.loads(pickle.dumps(err))):  # noqa: S301
        assert isinstance(clone, ProxyTunnelRefusedError)
        assert (clone.status, str(clone), clone.__notes__) == (407, str(err), ["kept"])


@pytest.mark.usefixtures("no_bypass")
def test_no_built_http_token_endpoint_reaches_the_web_proxy() -> None:
    """ADR 0095 B.1's ``http://`` token-endpoint case is overtaken. An off-box one is refused when
    the provider is built (vault BACKLOG #3533 item 4), and a loopback one is dialled direct, so
    the web proxy's Digest handler never sees its request."""
    with _Challenger(407, _MD5) as proxy:
        proxy_config = _digest_proxy_config(proxy.url, auth="digest")
        with active_hop_posture(_WARN_DIAL), pytest.raises(HttpAuthError):
            OAuth2ClientCredentialsProvider(
                token_url="http://auth.partner.invalid/token",
                client_id="cid",
                client_secret="s3cr3t",
                proxy=proxy_config,
            )
        provider = OAuth2ClientCredentialsProvider(
            token_url="http://127.0.0.1:9/token",
            client_id="cid",
            client_secret="s3cr3t",
            proxy=proxy_config,
            timeout_seconds=2,
        )
        with pytest.raises(DeliveryError, match=" unreachable: ") as ei:
            provider.access_token()
    assert type(ei.value) is DeliveryError
    assert proxy.requests == 0


@pytest.mark.usefixtures("no_bypass")
@pytest.mark.parametrize(("auth", "expected"), [("digest", True), ("basic", False), (None, False)])
def test_the_hop_decides_its_digest_setup_when_it_is_built(
    auth: str | None, expected: bool
) -> None:
    # Bypass pinned off, so the Basic hop is credentialed and lacks Digest for that reason alone.
    provider = _token_provider_via("http://127.0.0.1:3128", auth=auth)
    assert provider._digest_proxy is expected


class _CountingRefuser:
    """An opener that counts its calls and meets a refused Digest challenge on each."""

    def __init__(self) -> None:
        self.calls = 0

    def open(self, req: urllib.request.Request, timeout: float | None = None) -> Any:
        self.calls += 1
        raise _refusal()


@pytest.mark.parametrize("ctype", list(_FACTORY), ids=lambda c: c.value)
def test_a_send_time_hop_refusal_wins_over_a_digest_refusal(
    ctype: ConnectorType, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Finding 10, and the interaction the review of engine PR 2013 measured with no test. The hop
    re-check runs before the opener, so a refused hop is what the send reports, and the opener is
    never called. Before the fix the refusal left ``_post`` as a raw ``InsecureHopRefused``."""
    monkeypatch.delenv("MEFOR_ALLOW_INSECURE_TLS", raising=False)
    # Through a Digest web proxy, the one Digest every destination has. Origin Digest over an
    # off-box cleartext hop is refused when the destination is built.
    dest = _through_digest_proxy(ctype, "http://127.0.0.1:3128")
    opener = _CountingRefuser()
    dest._opener = opener
    # Control: with the permitting guard the destination was built with, the send reaches the
    # opener and meets the Digest refusal.
    with pytest.raises(NegativeAckError) as control:
        _send(ctype, dest)
    assert control.value.code == AUTH_CHALLENGE_REFUSED_CODE
    assert opener.calls == 1

    dest._hop_guard = InsecureHopGuard(
        posture=HopPosture(enforcing=True),
        attested=False,
        cell="HTTP cleartext egress",
        connection="OB",
    )
    with pytest.raises(NegativeAckError) as ei:
        _send(ctype, dest)
    err = ei.value
    assert err.code == INSECURE_HOP_REFUSED_CODE == "insecure-hop-refused"
    assert (err.permanent, err.config_fault, err.credential_fault) == (True, True, False)
    assert str(err).startswith(f"{_LABEL[ctype]} send refused: ")
    assert isinstance(err.__cause__, InsecureHopRefused)
    assert opener.calls == 1, "the opener was called after the hop was refused"
