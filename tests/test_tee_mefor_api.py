# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Unit tests for the MEFOR engine API client (tee/mefor_api.py)."""

from __future__ import annotations

import json
import ssl
import threading
import urllib.request
from collections.abc import Iterator
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any

import pytest

from messagefoundry import pki
from messagefoundry.transports.bounded_read import is_never_proxied_host
from tee import mefor_api
from tee.mefor_api import JsonGetter, MeforApiError, fetch_mefor_outputs, make_getter


def test_fetch_assembles_outputs_with_pagination_and_since() -> None:
    pages: dict[str, dict[str, Any]] = {
        "/messages?limit=50&offset=0": {
            "messages": [
                {"id": "m1", "control_id": "C1", "received_at": 100.0},
                {"id": "m2", "control_id": "C2", "received_at": 50.0},  # before --since -> dropped
            ]
        },
        "/messages?limit=50&offset=50": {"messages": []},
        "/messages/m1/outbound": {
            "payloads": [
                {"destination_name": "OB_A", "status": "done", "payload": "MSH|1"},
                {"destination_name": "OB_B", "status": "done", "payload": "MSH|2"},
            ]
        },
        "/messages/m2/outbound": {"payloads": [{"destination_name": "OB", "payload": "MSH|x"}]},
    }
    calls: list[str] = []

    def fake_get(path: str) -> dict[str, Any]:
        calls.append(path)
        return pages[path]

    outputs = fetch_mefor_outputs(fake_get, since=75.0)
    # m2 is before --since, so it is filtered AND its /outbound is never fetched.
    assert "/messages/m2/outbound" not in calls
    assert [
        (o.message_id, o.source_control_id, o.destination_name, o.payload) for o in outputs
    ] == [
        ("m1", "C1", "OB_A", "MSH|1"),
        ("m1", "C1", "OB_B", "MSH|2"),
    ]


def test_fetch_stops_at_limit() -> None:
    full_page: dict[str, Any] = {
        "messages": [
            {"id": f"m{i}", "control_id": f"C{i}", "received_at": 100.0} for i in range(50)
        ]
    }

    def fake_get(path: str) -> dict[str, Any]:
        if path.startswith("/messages?"):
            return full_page
        return {"payloads": [{"destination_name": "OB", "payload": "P"}]}

    outputs = fetch_mefor_outputs(fake_get, limit=3, page=50)
    assert len(outputs) == 3  # only 3 messages scanned despite a full page


def test_make_getter_connection_error_is_meforapierror() -> None:
    # Nothing listens here -> URLError -> wrapped as MeforApiError (not a raw urllib error).
    get: JsonGetter = make_getter("http://127.0.0.1:1", "tok", timeout=0.5)
    with pytest.raises(MeforApiError):
        get("/messages?limit=1&offset=0")


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *args: Any) -> None:  # silence the test server
        pass

    def do_GET(self) -> None:  # noqa: N802 — BaseHTTPRequestHandler API
        if self.path != "/messages?limit=1&offset=0":
            self.send_response(404)
            self.end_headers()
            return
        if self.headers.get("Authorization") != "Bearer tok":
            self.send_response(401)
            self.end_headers()
            return
        body = json.dumps({"messages": []}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def test_make_getter_real_roundtrip_and_404() -> None:
    server = HTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        get = make_getter(f"http://127.0.0.1:{server.server_port}", "tok", timeout=2.0)
        assert get("/messages?limit=1&offset=0") == {"messages": []}  # auth header accepted + JSON
        with pytest.raises(MeforApiError):
            get("/missing")  # 404 -> MeforApiError
    finally:
        server.shutdown()
        thread.join(timeout=2.0)


# --- An environment proxy never carries the token to a loopback engine (BACKLOG #2708) -----------
#
# Each test runs a real proxy listener and, where it needs one, a real engine listener, then reads
# which socket the request reached. No DNS is needed for the off-box control: the proxy receives
# the absolute-form request line and answers it itself. The token is a synthetic literal.

_TOKEN = "tok"
_PATH = "/messages?limit=1&offset=0"
_PROXY_VARS = (
    "http_proxy",
    "https_proxy",
    "all_proxy",
    "no_proxy",
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "ALL_PROXY",
    "NO_PROXY",
    "REQUEST_METHOD",  # urllib ignores HTTP_PROXY when this is set
)


def _recording_handler(
    seen: list[tuple[str, str | None]], reply: bytes, redirect_to: str | None
) -> type[BaseHTTPRequestHandler]:
    """A handler that records each request line with its Authorization header, then answers
    ``reply`` as JSON, or a 302 to ``redirect_to`` when set. A CONNECT is recorded and refused, so
    a tunnel attempt fails fast."""

    class _Recorder(BaseHTTPRequestHandler):
        def log_message(self, *args: Any) -> None:
            pass

        def do_GET(self) -> None:  # noqa: N802 -- BaseHTTPRequestHandler API
            seen.append((self.requestline, self.headers.get("Authorization")))
            if redirect_to is not None:
                self.send_response(302)
                self.send_header("Location", redirect_to)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(reply)))
            self.end_headers()
            self.wfile.write(reply)

        def do_CONNECT(self) -> None:  # noqa: N802 -- BaseHTTPRequestHandler API
            seen.append((self.requestline, self.headers.get("Authorization")))
            self.send_response(502)
            self.end_headers()

    return _Recorder


@contextmanager
def _serving(
    reply: bytes, *, tls: ssl.SSLContext | None = None, redirect_to: str | None = None
) -> Iterator[tuple[int, list[tuple[str, str | None]]]]:
    """A listener on 127.0.0.1 answering every GET with ``reply``; yields its port and what it saw."""
    seen: list[tuple[str, str | None]] = []
    server = HTTPServer(("127.0.0.1", 0), _recording_handler(seen, reply, redirect_to))
    if tls is not None:
        server.socket = tls.wrap_socket(server.socket, server_side=True)
    # A short poll, so shutdown() does not wait out the default half second.
    thread = threading.Thread(target=server.serve_forever, args=(0.05,), daemon=True)
    thread.start()
    try:
        yield server.server_port, seen
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2.0)


def _set_env_proxy(monkeypatch: pytest.MonkeyPatch, proxy_port: int) -> None:
    # Delete every spelling before setting any: Windows environment names ignore case, so a delete
    # after the set would remove it again.
    for name in _PROXY_VARS:
        monkeypatch.delenv(name, raising=False)
    proxy = f"http://127.0.0.1:{proxy_port}"
    monkeypatch.setenv("HTTP_PROXY", proxy)
    monkeypatch.setenv("HTTPS_PROXY", proxy)
    # urlopen caches one opener per process, with the proxies it read when first built. Drop it, so
    # a regression back to plain urlopen reads this proxy and fails here, whatever ran earlier.
    monkeypatch.setattr(urllib.request, "_opener", None)


_ENGINE_REPLY = json.dumps({"messages": [], "from": "engine"}).encode()
_PROXY_REPLY = json.dumps({"messages": [], "from": "proxy"}).encode()


def test_loopback_engine_is_dialled_direct_past_an_env_proxy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with (
        _serving(_PROXY_REPLY) as (proxy_port, proxy_seen),
        _serving(_ENGINE_REPLY) as (engine_port, engine_seen),
    ):
        _set_env_proxy(monkeypatch, proxy_port)
        base = f"http://127.0.0.1:{engine_port}"
        assert make_getter(base, _TOKEN, timeout=5.0)(_PATH)["from"] == "engine"
        assert proxy_seen == []  # the proxy never saw the request, so never saw the token
        # The control: a stock opener under the same environment sends this host to the proxy,
        # so the empty list above is the handler's doing, not a proxy nobody read.
        with urllib.request.build_opener().open(base + _PATH, timeout=5.0) as resp:
            assert json.loads(resp.read())["from"] == "proxy"
    assert [line for line, _ in proxy_seen] == [f"GET {base}{_PATH} HTTP/1.1"]
    assert engine_seen == [(f"GET {_PATH} HTTP/1.1", f"Bearer {_TOKEN}")]


def test_off_box_engine_still_goes_through_the_env_proxy(monkeypatch: pytest.MonkeyPatch) -> None:
    # The control: the handler narrows the proxy to off-box hosts, it does not switch it off.
    with _serving(_PROXY_REPLY) as (proxy_port, proxy_seen):
        _set_env_proxy(monkeypatch, proxy_port)
        get = make_getter("http://engine.example.invalid:8765", _TOKEN, timeout=5.0)
        assert get(_PATH)["from"] == "proxy"
    assert [line for line, _ in proxy_seen] == [
        f"GET http://engine.example.invalid:8765{_PATH} HTTP/1.1"
    ]


def test_a_redirect_off_the_box_is_refused_not_followed(monkeypatch: pytest.MonkeyPatch) -> None:
    # urllib copies Authorization onto a redirect, and the new host is off-box, so following it
    # would hand the token to the proxy after all.
    off_box = "http://elsewhere.example.invalid/messages"
    with (
        _serving(_PROXY_REPLY) as (proxy_port, proxy_seen),
        _serving(_ENGINE_REPLY, redirect_to=off_box) as (engine_port, engine_seen),
    ):
        _set_env_proxy(monkeypatch, proxy_port)
        get = make_getter(f"http://127.0.0.1:{engine_port}", _TOKEN, timeout=5.0)
        with pytest.raises(MeforApiError, match="HTTP 302 .*redirects are not followed"):
            get(_PATH)
    assert proxy_seen == []
    assert len(engine_seen) == 1


def _engine_tls(tmp_path: Path) -> tuple[ssl.SSLContext, ssl.SSLContext]:
    """A server context with a fresh self-signed pair for 127.0.0.1, and a client context whose
    only trust anchor is that certificate."""
    cert_pem, key_pem = pki.make_self_signed("127.0.0.1", [], 1)
    cert, key = tmp_path / "engine-cert.pem", tmp_path / "engine-key.pem"
    cert.write_bytes(cert_pem)
    key.write_bytes(key_pem)
    server = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server.load_cert_chain(cert, key)
    return server, ssl.create_default_context(cafile=str(cert))


def test_https_loopback_engine_is_direct_and_keeps_the_callers_tls_context(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A hand-built opener drops the caller's context unless it is handed to an HTTPSHandler. The
    # engine's certificate is trusted only by `client`, so a success proves the context was used.
    server_tls, client = _engine_tls(tmp_path)
    with (
        _serving(_PROXY_REPLY) as (proxy_port, proxy_seen),
        _serving(_ENGINE_REPLY, tls=server_tls) as (engine_port, engine_seen),
    ):
        _set_env_proxy(monkeypatch, proxy_port)
        base = f"https://127.0.0.1:{engine_port}"
        got = make_getter(base, _TOKEN, timeout=5.0, ssl_context=client)(_PATH)
        assert got["from"] == "engine"
        # The control for the claim above: without that context the certificate is refused.
        with pytest.raises(MeforApiError, match="CERTIFICATE_VERIFY_FAILED"):
            make_getter(base, _TOKEN, timeout=5.0)(_PATH)
    assert proxy_seen == []  # no CONNECT either
    assert engine_seen == [(f"GET {_PATH} HTTP/1.1", f"Bearer {_TOKEN}")]


@pytest.mark.parametrize(
    ("host", "expected"),
    [
        ("127.0.0.1", True),
        ("127.8.9.10", True),  # all of 127.0.0.0/8, not just the one literal
        ("::1", True),
        ("::ffff:127.0.0.1", True),  # IPv4-mapped; ipaddress calls it loopback from Python 3.13
        ("localhost", True),
        ("LocalHost", True),
        ("", False),  # no host is not on-box
        (None, False),
        ("engine.example.invalid", False),
        ("localhost.example.invalid", False),  # never resolved, so never proven on-box
        ("127.0.0.1.example.invalid", False),
        ("10.0.0.1", False),
        ("2001:db8::1", False),
        ("::", False),
    ],
)
def test_loopback_rule_matches_the_engines(host: str | None, expected: bool) -> None:
    # The tee carries a copy because it may not import the engine. Comparing against the engine's
    # own predicate is what turns a change on either side into a red here.
    assert mefor_api._is_loopback_host(host) is expected
    assert is_never_proxied_host(host) is expected
