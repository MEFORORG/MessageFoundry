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

import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from messagefoundry.config.models import ConnectorType, Destination
from messagefoundry.config.wiring import Rest
from messagefoundry.transports import build_destination
from messagefoundry.transports.rest import (
    ProxyConfig,
    RestDestination,
    ech_sidecar_url_from_settings,
    egress_route_from_settings,
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


def _make_stub_sidecar() -> tuple[HTTPServer, list[dict[str, str]]]:
    """A loopback stub standing in for the ECH sidecar: records the origin-form path + the Host header
    (the real upstream the engine handed it) and returns 200 'ok'."""
    seen: list[dict[str, str]] = []

    class _Handler(BaseHTTPRequestHandler):
        def _record_and_reply(self) -> None:
            length = int(self.headers.get("Content-Length", 0) or 0)
            if length:
                self.rfile.read(length)
            seen.append({"path": self.path, "host": self.headers.get("Host", "")})
            self.send_response(200)
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"ok")

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
