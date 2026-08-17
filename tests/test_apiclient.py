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

    # `_request` builds the request (so the #1047 length bound can measure the RESOLVED url) and
    # dispatches it through `send`, so `send` is the transport seam a stub replaces.
    monkeypatch.setattr(client._http, "send", lambda *a, **k: _Resp())
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


# --- ASVS 4.2.5: the client's own outbound length bound --------------------------------------------


def test_apiclient_length_bounds_match_the_transport_constants() -> None:
    """The constants are DUPLICATED in apiclient rather than imported, because ADR 0088 keeps this
    package engine-free — a GUI/harness process must not pull `transports/` in just to make an HTTP
    call. This test is where the duplication is kept honest: it imports both sides in a TEST process,
    where the coupling is harmless, and reds if either drifts.

    Mutation: change either constant on either side. Red: the assertion names both values."""
    from messagefoundry.apiclient.client import (
        MAX_REQUEST_HEADER_VALUE_LEN,
        MAX_REQUEST_URL_LEN,
    )
    from messagefoundry.transports.rest import (
        MAX_OUTBOUND_HEADER_VALUE_LEN,
        MAX_OUTBOUND_URL_LEN,
    )

    assert MAX_REQUEST_URL_LEN == MAX_OUTBOUND_URL_LEN, (
        f"apiclient bounds the URL at {MAX_REQUEST_URL_LEN} but the transports bound it at "
        f"{MAX_OUTBOUND_URL_LEN}; the duplication has drifted"
    )
    assert MAX_REQUEST_HEADER_VALUE_LEN == MAX_OUTBOUND_HEADER_VALUE_LEN, (
        f"apiclient bounds a header value at {MAX_REQUEST_HEADER_VALUE_LEN} but the transports "
        f"bound it at {MAX_OUTBOUND_HEADER_VALUE_LEN}; the duplication has drifted"
    )


def test_apiclient_refuses_an_over_length_request_path() -> None:
    """`_request` builds `base_url + path`; nothing measured it before. Mutation: delete the URL
    check in `_request`. Red: DID NOT RAISE (the request reaches httpx instead)."""
    from messagefoundry.apiclient.client import ApiError, EngineClient

    client = EngineClient("http://127.0.0.1:8765")
    with pytest.raises(ApiError, match="over the 8192-char limit"):
        client._request("GET", "/messages?q=" + "a" * 9000)


def test_apiclient_measures_the_query_string_httpx_appends(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """BACKLOG #1047: the bound must measure the URL httpx actually sends, not the one the caller
    typed. Every read the console/harness/tray makes goes through ``_get``, which hands its filters
    to httpx as ``params=`` — appended to the URL AFTER any length measured from ``base_url`` and
    ``path`` alone. A long filter value (a search needle, a control id) therefore built an over-long
    request line with nothing refusing it.

    The transport is replaced by a tripwire rather than a stub response: the claim is that the
    request is refused *before* it reaches the wire, and a stub 200 could not tell that apart from a
    request that went out and came back. ``httpx.Client.request`` dispatches through
    ``self.send``, so this one patch covers both the pre-fix (``_http.request``) and post-fix
    (``build_request`` + ``_http.send``) call shapes.

    Mutation: measure ``len(self.base_url) + len(path)`` again. Red: AssertionError from the
    tripwire — the over-long request reached the transport."""
    from messagefoundry.apiclient.client import ApiError, EngineClient

    client = EngineClient("http://127.0.0.1:8765")

    def _tripwire(*args: object, **kwargs: object) -> object:
        raise AssertionError("an over-length request reached the transport")

    monkeypatch.setattr(client._http, "send", _tripwire)
    # base_url + path is 33 chars; the query httpx appends is what breaches the limit.
    with pytest.raises(ApiError, match="over the 8192-char limit"):
        client._get("/messages", control_id="a" * 9000)


def test_apiclient_still_sends_a_query_that_fits(monkeypatch: pytest.MonkeyPatch) -> None:
    """Positive control for the test above: the same call shape with a short query MUST reach the
    transport. Without this, a bound that refused every query-bearing GET would look identical to a
    correct one."""
    from messagefoundry.apiclient.client import EngineClient

    client = EngineClient("http://127.0.0.1:8765")
    sent: list[str] = []

    def _capture(request: httpx.Request, *args: object, **kwargs: object) -> httpx.Response:
        sent.append(str(request.url))
        return httpx.Response(200, json={}, request=request)

    monkeypatch.setattr(client._http, "send", _capture)
    client._get("/messages", control_id="MSG1")
    assert sent == ["http://127.0.0.1:8765/messages?control_id=MSG1"], (
        "the resolved URL (query included) is what the bound measures, so it is what must go out"
    )
