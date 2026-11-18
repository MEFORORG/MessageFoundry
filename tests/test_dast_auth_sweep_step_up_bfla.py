# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Vault BACKLOG #5580, through ``run_sweep`` end to end, on entry points older than the fix.

``tests/test_dast_auth_sweep.py`` pins the fix with names the fix introduced
(``STEP_UP_REQUIRED_HEADER``, ``is_bfla_refused``, ``_bfla_probe``), so against the pre-fix sweep
that module fails at import rather than on the defect. This module imports only what the sweep and
the engine had before the fix: ``run_sweep``, ``route_gates`` and the engine's own
``_step_up_refusal``. Against the pre-fix sweep it fails on the defect itself: a step-up 403 to the
low-privilege caller scored as a refusal, with no finding.

The target is an ``httpx.MockTransport``, not a live engine, because no shipped route lets the
viewer through RBAC to a step-up gate; building one would be the canary's job, and this test is
about the scoring loop, so the route table and the target are stubs and only the sweep is real.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from types import SimpleNamespace
from typing import Any

import httpx
import pytest

import scripts.security.dast_auth_sweep as sweep
from messagefoundry.api import security
from scripts.security import route_gates

_ADMIN = "dast-test-admin-token"
_VIEWER = "dast-test-viewer-token"

#: A GET the viewer role's permission set does not cover, so the BFLA pass probes it.
_ROW = route_gates.RouteRow(
    method="GET",
    path="/dast-test/step-up/{item_id}",
    permissions=("dast-test:not-a-viewer-permission",),
    gates=("require_step_up",),
    kind=route_gates.KIND_GATED,
)


class _Auth:
    """Enough of ``AuthService`` for ``_step_up_refusal`` to pick its wording."""

    async def session_steps_up_at_idp(self, _token: str | None) -> bool:
        return False


async def _engine_step_up_headers() -> dict[str, str]:
    """The headers the engine's own step-up refusal carries, so a renamed header moves this test."""
    refusal = await security._step_up_refusal(_Auth(), "t")  # type: ignore[arg-type]
    assert refusal.status_code == 403
    return dict(refusal.headers or {})


async def test_a_step_up_403_to_the_low_privilege_caller_is_a_bfla_finding(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The administrator reaches the row, an anonymous or forged caller gets 401, and the viewer
    gets the engine's step-up 403: RBAC let it through to the step-up gate. That is a BFLA
    violation. Pre-fix, the sweep kept the status only and scored the 403 as refused."""
    step_up = await _engine_step_up_headers()

    def handler(request: httpx.Request) -> httpx.Response:
        bearer = request.headers.get("Authorization", "")
        if bearer == f"Bearer {_ADMIN}":
            return httpx.Response(200)
        if bearer == f"Bearer {_VIEWER}":
            return httpx.Response(403, headers=step_up)
        return httpx.Response(401)

    transport = httpx.MockTransport(handler)
    real_client = httpx.AsyncClient

    def _client(**kwargs: Any) -> httpx.AsyncClient:
        return real_client(transport=transport, **kwargs)

    async def _no_session_work(*_args: object) -> str:
        raise AssertionError("no row here needs a re-login or a re-proof")

    @asynccontextmanager
    async def _target(**_kwargs: Any) -> AsyncIterator[Any]:
        yield SimpleNamespace(
            app=None,
            base_url="http://dast.test",
            admin_token=_ADMIN,
            viewer_token=_VIEWER,
            posture={},
            identities={},
            relogin=_no_session_work,
            reprove=_no_session_work,
        )

    def _rows(_app: object = None) -> list[route_gates.RouteRow]:
        return [_ROW]

    def _no_rows(_app: object = None) -> list[route_gates.RouteRow]:
        return []

    monkeypatch.setattr(sweep, "dast_target", _target)
    monkeypatch.setattr(httpx, "AsyncClient", _client)
    monkeypatch.setattr(route_gates, "route_rows", _rows)
    monkeypatch.setattr(route_gates, "gated_http_rows", _rows)
    monkeypatch.setattr(route_gates, "ungated_http_rows", _no_rows)

    receipt = await sweep.run_sweep(
        {
            "unreachable_allowlist": [],
            "low_privilege_role": "viewer",
            "max_write_session_rebuilds": 0,
        }
    )

    # The controls: the row was measured as the stub intends, so the BFLA result below is not an
    # artefact of a target that refused or reached everyone.
    assert receipt["negative_non_401"] == 0, receipt["findings"]
    assert receipt["reached"] == 1, receipt["findings"]
    assert receipt["bfla_probes"] == 1, receipt
    # The defect: the step-up 403 must be a finding, not a refusal.
    bfla = [f for f in receipt["findings"] if f["pass_name"] == "bfla"]
    assert [(f["method"], f["path"], f["observed_status"]) for f in bfla] == [
        ("GET", _ROW.path, 403)
    ], receipt["findings"]
    assert receipt["bfla_violations"] == 1, receipt
