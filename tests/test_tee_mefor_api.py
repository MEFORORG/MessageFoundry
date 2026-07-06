# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Unit tests for the MEFOR engine API client (tee/mefor_api.py)."""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any

import pytest

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
        host, port = server.server_address
        get = make_getter(f"http://{host}:{port}", "tok", timeout=2.0)
        assert get("/messages?limit=1&offset=0") == {"messages": []}  # auth header accepted + JSON
        with pytest.raises(MeforApiError):
            get("/missing")  # 404 -> MeforApiError
    finally:
        server.shutdown()
        thread.join(timeout=2.0)
