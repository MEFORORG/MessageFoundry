# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""The extracted Qt-free / FastAPI-free engine-client library (ADR 0088).

This is the canonical engine-client entrypoint (:mod:`messagefoundry.apiclient`) — the desktop
console and its ``messagefoundry.console.client`` shim were retired (BACKLOG #103). Here we assert the
public entrypoint works and — critically — that importing it drags in neither PySide6 nor FastAPI, so
the harness / any future client can depend on it headlessly.
"""

from __future__ import annotations

import json
import subprocess
import sys

import httpx
import pytest

from messagefoundry.apiclient import ApiError, EngineClient


def test_public_surface_is_reexported() -> None:
    # The package re-exports the two public names from the client module (same objects).
    from messagefoundry.apiclient.client import ApiError as ClientApiError
    from messagefoundry.apiclient.client import EngineClient as ClientEngineClient

    assert EngineClient is ClientEngineClient
    assert ApiError is ClientApiError


def test_import_pulls_in_no_pyside6_or_fastapi() -> None:
    """Import-integrity (ADR 0088): a fresh interpreter that imports messagefoundry.apiclient must not
    load PySide6 or FastAPI. Run in a subprocess so an already-imported GUI/server from another test
    can't mask a real regression."""
    code = (
        "import sys, json, messagefoundry.apiclient\n"
        "loaded = {\n"
        "  'pyside6': any(m == 'PySide6' or m.startswith('PySide6.') for m in sys.modules),\n"
        "  'fastapi': any(m == 'fastapi' or m.startswith('fastapi.') for m in sys.modules),\n"
        "  'has_client': hasattr(messagefoundry.apiclient, 'EngineClient'),\n"
        "}\n"
        "print(json.dumps(loaded))\n"
    )
    proc = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, timeout=60)
    assert proc.returncode == 0, proc.stderr
    loaded = json.loads(proc.stdout.strip())
    assert loaded["has_client"] is True
    assert loaded["pyside6"] is False, "importing apiclient must not load PySide6"
    assert loaded["fastapi"] is False, "importing apiclient must not load FastAPI"


def test_transport_guard_refuses_remote_plaintext_http() -> None:
    with pytest.raises(ApiError, match="cleartext"):
        EngineClient("http://engine.example.com:8765")


def test_loopback_http_constructs() -> None:
    EngineClient("http://127.0.0.1:8765").close()


def test_request_maps_non_2xx_to_apierror(monkeypatch: pytest.MonkeyPatch) -> None:
    client = EngineClient("http://127.0.0.1:8765")

    class _Resp:
        status_code = 500
        headers: dict[str, str] = {}
        text = "boom"
        reason_phrase = "Server Error"

        def json(self) -> dict[str, object]:
            return {"detail": "kaboom"}

    monkeypatch.setattr(client._http, "request", lambda *a, **k: _Resp())
    with pytest.raises(ApiError) as excinfo:
        client.health()
    assert excinfo.value.status == 500


def test_decode_helpers_map_bad_body_to_apierror() -> None:
    from messagefoundry.api.models import ChannelInfo, EngineInfo
    from messagefoundry.apiclient.client import _decode, _decode_list

    with pytest.raises(ApiError, match="invalid response"):
        _decode(httpx.Response(200, json={"unexpected": "shape"}), EngineInfo)
    with pytest.raises(ApiError):
        _decode_list(httpx.Response(200, json={"not": "a list"}), ChannelInfo)
