# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Freeze the tokenless ``/health`` contract the tray depends on (ADR 0113 §2, AC-2).

The Windows tray service-manager polls ``GET /health`` with **no** ``Authorization`` header — that is
its entire liveness signal and the reason it needs no credentials. If a future auth-hardening change
were to put ``/health`` behind ``require()``, every deployed tray would silently go dark. This test is
that guardrail (the tray analogue of the IDE's frozen ``POLL_PLAN``): ``/health`` must stay 200 and
tokenless even in the fail-closed default where every ``require()`` route returns 503.
"""

from __future__ import annotations

import warnings

from starlette.testclient import TestClient

from messagefoundry.api import create_app


def _client() -> TestClient:
    # The starlette↔httpx TestClient deprecation warning is noise here; silence it locally.
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        return TestClient(create_app())


def test_health_is_tokenless_200() -> None:
    with _client() as c:
        response = c.get("/health")  # no Authorization header
        assert response.status_code == 200
        assert response.json().get("status") == "ok"


def test_health_stays_open_while_require_routes_are_locked() -> None:
    # Proves /health is genuinely exempt: with no auth service attached, a require()-gated route is
    # locked (503 fail-closed / 401), yet /health still answers 200 with no token.
    with _client() as c:
        assert c.get("/health").status_code == 200
        assert c.get("/status").status_code in (401, 403, 503)


def test_health_needs_no_authorization_header() -> None:
    # Explicitly assert the request carries no Authorization header and still succeeds.
    with _client() as c:
        request = c.build_request("GET", "/health")
        assert "authorization" not in {k.lower() for k in request.headers}
        assert c.send(request).status_code == 200
