# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Tests for the ECH SNI-hiding send-path (transports/rest.py, ADR 0139, ASVS 12.1.5).

An `ech_egress` REST connection re-addresses each request to a loopback **terminating** sidecar
(operator-supplied; contract in `samples/ech-sidecar/README.md`) over cleartext http with the real
destination in the `Host` header; the sidecar re-originates the https + ECH connection (hiding the
SNI). These tests cover the resolver
(`ech_sidecar_url_from_settings`), the fail-closed refusal on non-REST connectors
(`egress_route_from_settings`), the connector wiring (`_ech_request` / opener / mutual exclusion), and a
**stub-sidecar `_post` behavioral test** proving the request actually lands on the sidecar naming the
upstream in `Host`.

Scope limit, stated so it is not mistaken for more: **nothing here originates or observes ECH.** The
far end is always a stub. A Go re-originator was proven by hand against a live ECH endpoint and then
retired from the tree on 2026-08-10 (`git show 62fd628d:tools/ech-sidecar/`, ADR 0139); no automated
check has ever re-run that proof, before or after the retirement.
"""

from __future__ import annotations

import io
import json
import threading
import urllib.request
from collections.abc import Callable
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from messagefoundry.config.models import ConnectorType, Destination, Source
from messagefoundry.config.wiring import (
    DICOM,
    MLLP,
    X12,
    ConnectionSpec,
    Email,
    File,
    Rest,
    Soap,
    Tcp,
)
from messagefoundry.transports import build_destination, build_source
from messagefoundry.transports.base import (
    ECH_UNSUPPORTED_DESTINATION_MSG,
    ECH_UNSUPPORTED_SOURCE_MSG,
    DestinationConnector,
)
from messagefoundry.transports.rest import (
    ProxyConfig,
    RestDestination,
    ech_sidecar_url_from_settings,
    egress_route_from_settings,
)


@pytest.fixture(scope="module")
def rsa_pem() -> str:
    """A synthetic signing key for the SMART token-provider tests (generated per run, never a real one)."""
    return (
        rsa.generate_private_key(public_exponent=65537, key_size=2048)
        .private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        .decode("ascii")
    )


def _rest(url: str = "https://partner.example/ingest", **extra: object) -> RestDestination:
    settings = Rest(url=url).settings
    settings.update(extra)
    d = build_destination(Destination(name="OB_REST", type=ConnectorType.REST, settings=settings))
    assert isinstance(d, RestDestination)
    return d


# --- resolver: ech_sidecar_url_from_settings ------------------------------------------------------


def test_no_ech_egress_is_none_byte_identical() -> None:
    assert ech_sidecar_url_from_settings({}) is None
    assert ech_sidecar_url_from_settings({"ech_egress": False}) is None


def test_ech_sidecar_url_normalized() -> None:
    assert (
        ech_sidecar_url_from_settings({"ech_egress": True, "ech_sidecar": "http://127.0.0.1:8123/"})
        == "http://127.0.0.1:8123"
    )


def test_ech_egress_without_sidecar_fails_closed() -> None:
    with pytest.raises(ValueError, match="ech_sidecar is empty"):
        ech_sidecar_url_from_settings({"ech_egress": True})


def test_ech_sidecar_must_be_loopback() -> None:
    with pytest.raises(ValueError, match="loopback"):
        ech_sidecar_url_from_settings(
            {"ech_egress": True, "ech_sidecar": "http://ech.example.com:8123"}
        )


def test_ech_sidecar_bad_scheme_fails_closed() -> None:
    with pytest.raises(ValueError, match="http"):
        ech_sidecar_url_from_settings(
            {"ech_egress": True, "ech_sidecar": "socks5://127.0.0.1:8123"}
        )


@pytest.mark.parametrize("host", ["127.0.0.1", "localhost", "[::1]", "127.9.9.9"])
def test_loopback_forms_accepted(host: str) -> None:
    assert (
        ech_sidecar_url_from_settings({"ech_egress": True, "ech_sidecar": f"http://{host}:8123"})
        is not None
    )


# --- egress_route_from_settings fails closed on ech_egress (non-REST connectors) ------------------


def test_egress_route_refuses_ech_egress() -> None:
    # fhir/soap/dicomweb route through this resolver; ech_egress there would silently NOT hide the SNI.
    with pytest.raises(ValueError, match="only on the REST destination"):
        egress_route_from_settings(
            {"ech_egress": True, "ech_sidecar": "http://127.0.0.1:8123"}, dest_scheme="https"
        )


def test_egress_route_returns_proxy() -> None:
    route = egress_route_from_settings({"proxy_url": "http://127.0.0.1:3128"}, dest_scheme="https")
    assert isinstance(route, ProxyConfig)


def test_egress_route_none_when_neither() -> None:
    assert egress_route_from_settings({}, dest_scheme="https") is None


# --- connector wiring -----------------------------------------------------------------------------


def test_rest_without_ech_is_unchanged() -> None:
    d = _rest()
    assert d._ech_sidecar is None


def test_rest_ech_sets_sidecar_and_no_proxy() -> None:
    d = _rest(ech_egress=True, ech_sidecar="http://127.0.0.1:8123")
    assert d._ech_sidecar == "http://127.0.0.1:8123"
    assert d._proxy is None  # ECH is the egress path, not a forward proxy


def test_ech_request_readdresses_to_sidecar_with_host() -> None:
    d = _rest(
        url="https://partner.example/fhir/Patient?x=1",
        ech_egress=True,
        ech_sidecar="http://127.0.0.1:8123",
    )
    req = d._ech_request(b"body", {"Content-Type": "application/json"}, "POST")
    assert (
        req.full_url == "http://127.0.0.1:8123/fhir/Patient?x=1"
    )  # sent to the sidecar over loopback
    assert req.get_header("Host") == "partner.example"  # sidecar learns the real upstream
    assert req.get_method() == "POST"


def test_ech_and_proxy_mutually_exclusive_at_construction() -> None:
    with pytest.raises(ValueError, match="mutually exclusive"):
        _rest(
            ech_egress=True, ech_sidecar="http://127.0.0.1:8123", proxy_url="http://127.0.0.1:3128"
        )


# --- behavioral: _post actually routes through the (stub) sidecar ---------------------------------


def _make_stub_sidecar(body: str = "ok") -> tuple[HTTPServer, list[dict[str, str]]]:
    """A loopback stub standing in for the ECH sidecar: records the origin-form path + the Host header
    (the real upstream the engine handed it) and returns 200 with ``body``."""
    seen: list[dict[str, str]] = []
    payload = body.encode()

    class _Handler(BaseHTTPRequestHandler):
        def _record_and_reply(self) -> None:
            length = int(self.headers.get("Content-Length", 0) or 0)
            if length:
                self.rfile.read(length)
            seen.append({"path": self.path, "host": self.headers.get("Host", "")})
            self.send_response(200)
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def do_POST(self) -> None:  # noqa: N802
            self._record_and_reply()

        def log_message(self, *args: object) -> None:
            return

    srv = HTTPServer(("127.0.0.1", 0), _Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, seen


def test_ech_post_routes_through_the_sidecar() -> None:
    srv, seen = _make_stub_sidecar()
    try:
        port = srv.server_address[1]
        d = _rest(
            url="https://partner.example/ingest?q=1",
            ech_egress=True,
            ech_sidecar=f"http://127.0.0.1:{port}",
        )
        body, status, _ = d._post("hello-phi")
        assert status == 200 and body == "ok"
        # The delivery reached the SIDECAR (loopback), re-addressed with the real upstream in Host —
        # the engine never opened a direct SNI-leaking TLS connection to partner.example.
        assert seen and seen[0]["path"] == "/ingest?q=1"
        assert seen[0]["host"] == "partner.example"
    finally:
        srv.shutdown()


# --- BACKLOG #1176: no connector may SILENTLY ACCEPT ech_egress ------------------------------------
#
# The routing half is implemented on REST only. Before #1176 every other connector BUILT with
# `ech_egress = True` and ignored it, so on a first deployment an operator could believe the SNI was
# hidden while the hop stayed an ordinary SNI-leaking handshake. The refusal now lives in the shared
# construction seam (`transports/base.py`), not copied per connector.


_SIDECAR = "http://127.0.0.1:8123"

_NON_ECH_OUTBOUND: list[tuple[str, Callable[[], ConnectionSpec]]] = [
    ("mllp", lambda: MLLP(host="partner.example", port=2575)),
    ("tcp", lambda: Tcp(host="partner.example", port=9100, framing="mllp")),
    ("x12", lambda: X12(host="partner.example", port=9200)),
    ("file", lambda: File(directory="./out")),
    (
        "email",
        lambda: Email(
            host="smtp.example",
            port=587,
            sender="engine@example.org",
            recipients=["ops@example.org"],
            use_tls=True,
        ),
    ),
    (
        "dicom",
        lambda: DICOM(ae_title="MEFOR", host="partner.example", port=104, called_ae_title="PEER"),
    ),
]
_NON_ECH_IDS = [label for label, _ in _NON_ECH_OUTBOUND]


def _dest(spec: ConnectionSpec, label: str, **extra: object) -> DestinationConnector:
    settings = dict(spec.settings)
    settings.update(extra)
    return build_destination(
        Destination(name=f"OB_{label.upper()}", type=spec.type, settings=settings)
    )


@pytest.mark.parametrize(("label", "make"), _NON_ECH_OUTBOUND, ids=_NON_ECH_IDS)
def test_outbound_builds_without_any_ech_key(
    label: str, make: Callable[[], ConnectionSpec]
) -> None:
    """Negative control for the refusal below: each spec is COMPLETE on its own, so the paired
    refusal is attributable to the ech key and to nothing else about the settings."""
    assert _dest(make(), label) is not None


@pytest.mark.parametrize(("label", "make"), _NON_ECH_OUTBOUND, ids=_NON_ECH_IDS)
def test_outbound_that_cannot_hide_the_sni_refuses_ech_egress(
    label: str, make: Callable[[], ConnectionSpec]
) -> None:
    with pytest.raises(ValueError, match="only on the REST destination"):
        _dest(make(), label, ech_egress=True, ech_sidecar=_SIDECAR)


def test_rest_is_the_one_exempt_outbound() -> None:
    """Positive control for the parametrized refusal: the connector that DOES implement the routing
    half still builds, so the shared refusal is keyed on the connector and not on the key alone."""
    d = _rest(ech_egress=True, ech_sidecar=_SIDECAR)
    assert d._ech_sidecar == _SIDECAR


def test_both_refusal_sites_carry_the_same_message() -> None:
    """A connector can reach BOTH refusals (SOAP/DICOMweb/FHIR route through the resolver and are also
    built through the shared seam). They must not offer an operator two different explanations for one
    key, so both raise the one constant."""
    spec = Soap(url="https://partner.example/svc", soap_action="urn:x")
    with pytest.raises(ValueError) as from_seam:
        _dest(spec, "soap", ech_egress=True, ech_sidecar=_SIDECAR)
    with pytest.raises(ValueError) as from_resolver:
        egress_route_from_settings(
            {"ech_egress": True, "ech_sidecar": _SIDECAR}, dest_scheme="https"
        )
    assert str(from_seam.value) == ECH_UNSUPPORTED_DESTINATION_MSG
    assert str(from_resolver.value) == ECH_UNSUPPORTED_DESTINATION_MSG


def test_inbound_builds_without_any_ech_key() -> None:
    """Negative control for the inbound refusal below."""
    spec = MLLP(port=2575)
    src = build_source(Source(name="IB_MLLP", type=spec.type, settings=dict(spec.settings)))
    assert src is not None


def test_inbound_refuses_ech_egress() -> None:
    spec = MLLP(port=2575)
    settings = dict(spec.settings)
    settings.update(ech_egress=True, ech_sidecar=_SIDECAR)
    with pytest.raises(ValueError) as exc:
        build_source(Source(name="IB_MLLP", type=spec.type, settings=settings))
    assert str(exc.value) == ECH_UNSUPPORTED_SOURCE_MSG


# --- BACKLOG #1176: the token-endpoint hop must follow the same egress route as the payload hop ----
#
# ADR 0126 already rules that the token-endpoint POST traverses the connection's forward proxy. The
# ECH path did not follow that precedent: `ech_egress` forced `_proxy = None` and the bearer provider
# fell back to a direct opener, so an `ech_egress` REST connection with OAuth2 or SMART auth still put
# the AUTHORIZATION SERVER's hostname in a cleartext outer ClientHello.


class _RecordingOpener:
    """Stands in for the provider's opener and records the Request it was handed. No network in
    either direction, so this measures where the request was ADDRESSED, not whether a host answers."""

    def __init__(self) -> None:
        self.req: urllib.request.Request | None = None

    def open(self, req: urllib.request.Request, timeout: float | None = None) -> io.BytesIO:
        self.req = req
        return io.BytesIO(json.dumps({"access_token": "t0k", "expires_in": 3600}).encode())


_TOKEN_URL = "https://auth.partner.example/token"


def _oauth2_rest(**extra: object) -> RestDestination:
    return _rest(
        oauth2_token_url=_TOKEN_URL,
        oauth2_client_id="cid",
        oauth2_client_secret="s3cret",
        **extra,
    )


def _minted_request(d: RestDestination) -> urllib.request.Request:
    provider = d._token_provider
    assert provider is not None
    rec = _RecordingOpener()
    provider._opener = rec  # type: ignore[attr-defined,assignment]
    assert provider.access_token() == "t0k"
    assert rec.req is not None
    return rec.req


def test_oauth2_token_request_goes_direct_without_ech() -> None:
    """Control for the two tests below: with no egress route the token POST is addressed straight at
    the authorization server and carries no Host override. This is what the ech case must NOT look
    like."""
    req = _minted_request(_oauth2_rest())
    assert req.full_url == _TOKEN_URL
    assert req.get_header("Host") is None


def test_oauth2_token_request_routes_through_the_ech_sidecar() -> None:
    req = _minted_request(_oauth2_rest(ech_egress=True, ech_sidecar=_SIDECAR))
    assert req.full_url == f"{_SIDECAR}/token"
    assert req.get_header("Host") == "auth.partner.example"


def test_smart_token_request_routes_through_the_ech_sidecar(rsa_pem: str) -> None:
    d = _rest(
        ech_egress=True,
        ech_sidecar=_SIDECAR,
        smart_token_url=_TOKEN_URL,
        smart_client_id="cid",
        smart_private_key=rsa_pem,
    )
    req = _minted_request(d)
    assert req.full_url == f"{_SIDECAR}/token"
    assert req.get_header("Host") == "auth.partner.example"


def test_smart_token_request_goes_direct_without_ech(rsa_pem: str) -> None:
    """Control for the SMART case, mirroring the OAuth2 one."""
    d = _rest(smart_token_url=_TOKEN_URL, smart_client_id="cid", smart_private_key=rsa_pem)
    req = _minted_request(d)
    assert req.full_url == _TOKEN_URL
    assert req.get_header("Host") is None


def test_ech_token_mint_lands_on_the_stub_sidecar() -> None:
    """End-to-end through the real opener: the token POST arrives at the loopback sidecar naming the
    authorization server in Host, so no direct TLS connection to that host is ever opened."""
    srv, seen = _make_stub_sidecar(body=json.dumps({"access_token": "t0k", "expires_in": 3600}))
    try:
        port = srv.server_address[1]
        d = _oauth2_rest(ech_egress=True, ech_sidecar=f"http://127.0.0.1:{port}")
        assert d._token_provider is not None
        assert d._token_provider.access_token() == "t0k"
        assert seen and seen[0]["path"] == "/token"
        assert seen[0]["host"] == "auth.partner.example"
    finally:
        srv.shutdown()
