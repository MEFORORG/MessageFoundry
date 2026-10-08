# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The engine client never sends through a proxy the environment names (BACKLOG #2318).

httpx reads ``HTTP_PROXY``, ``HTTPS_PROXY``, ``ALL_PROXY`` and the Windows system proxy by default.
The client carries a bearer token and the operator's password at sign-in, so a proxy from the
environment would see both, and an https proxy's TLS leg would run on httpcore's own context rather
than the one the client built. Measured on the wire: a recording proxy and a recording engine, both
on loopback. The control shows that a stock httpx client does go through that proxy, so the
assertion below can fail.
"""

from __future__ import annotations

import http.server
import threading
from collections.abc import Iterator

import httpx
import pytest

from messagefoundry.apiclient import EngineClient

_PROXY_VARS = (
    "HTTP_PROXY",
    "http_proxy",
    "HTTPS_PROXY",
    "https_proxy",
    "ALL_PROXY",
    "all_proxy",
    "NO_PROXY",
    "no_proxy",
)


class _Recorder(http.server.ThreadingHTTPServer):
    def __init__(self) -> None:
        self.seen: list[str] = []
        super().__init__(("127.0.0.1", 0), _Handler)

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.server_address[1]}"


class _Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        assert isinstance(self.server, _Recorder)
        self.server.seen.append(self.path)
        body = b"{}"
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:  # quiet test output
        pass


@pytest.fixture
def servers(monkeypatch: pytest.MonkeyPatch) -> Iterator[tuple[_Recorder, _Recorder]]:
    for name in _PROXY_VARS:
        monkeypatch.delenv(name, raising=False)
    engine, proxy = _Recorder(), _Recorder()
    threads = [threading.Thread(target=s.serve_forever, daemon=True) for s in (engine, proxy)]
    for thread in threads:
        thread.start()
    for name in ("HTTP_PROXY", "ALL_PROXY"):
        monkeypatch.setenv(name, proxy.url)
    try:
        yield engine, proxy
    finally:
        for server in (engine, proxy):
            server.shutdown()
            server.server_close()


def test_control_a_stock_httpx_client_goes_through_the_environment_proxy(
    servers: tuple[_Recorder, _Recorder],
) -> None:
    engine, proxy = servers
    with httpx.Client(base_url=engine.url, timeout=5) as stock:
        stock.get("/api/health")
    assert proxy.seen, (
        "control: the environment proxy was not used, so the test below proves nothing"
    )
    assert engine.seen == []


def test_the_engine_client_ignores_the_environment_proxy(
    servers: tuple[_Recorder, _Recorder],
) -> None:
    """Mutation: drop ``trust_env=False`` from ``EngineClient._open_transport``. Red: the request
    reaches the proxy, not the engine."""
    engine, proxy = servers
    client = EngineClient(engine.url)
    try:
        client._http.get("/api/health")
    finally:
        client.close()
    assert engine.seen == ["/api/health"]
    assert proxy.seen == [], "the engine client sent through the environment proxy"
