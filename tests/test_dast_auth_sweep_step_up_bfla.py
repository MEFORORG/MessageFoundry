# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Vault BACKLOG #5580, through ``run_sweep`` end to end, on entry points older than the fix.

``tests/test_dast_auth_sweep.py`` pins the fix with names the fix introduced
(``STEP_UP_REQUIRED_HEADER``, ``is_bfla_refused``, ``_bfla_probe``), so against the pre-fix sweep
that module fails at import rather than on the defect. This module imports only what the sweep and
the engine had before the fix: ``run_sweep``, ``route_gates``, ``dast_target.PREFLIGHT_PATH`` and
the engine's own ``_step_up_refusal``. Against the pre-fix sweep it fails on the defect itself: a
step-up 403 to the low-privilege caller scored as a refusal, with no finding.

The target is an ``httpx.MockTransport``, not a live engine. On a live engine only the ``bfla``
canary, which provisions the viewer as an administrator, lets it through RBAC to a step-up gate,
and then every row is over-granted at once. A stub route table puts a step-up row beside a plain
refusal on each pass, so the scoring loop is measured on both answers; only the sweep is real.
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
from scripts.security.dast_target import PREFLIGHT_PATH

_ADMIN = "dast-test-admin-token"
_VIEWER = "dast-test-viewer-token"
_NOT_A_VIEWER_PERMISSION = ("dast-test:not-a-viewer-permission",)


def _row(method: str, path: str) -> route_gates.RouteRow:
    """A gated row the viewer role's permission set does not cover, so a BFLA pass probes it."""
    return route_gates.RouteRow(
        method=method,
        path=path,
        permissions=_NOT_A_VIEWER_PERMISSION,
        gates=("require_step_up",),
        kind=route_gates.KIND_GATED,
    )


#: The viewer meets the step-up gate here: RBAC let it through.
_STEP_UP_GET = _row("GET", "/dast-test/step-up/{item_id}")
#: The same, on the write pass.
_STEP_UP_POST = _row("POST", "/dast-test/step-up-write/{item_id}")
#: The negative controls: the viewer gets a plain 403, a real permission refusal, on each pass.
_PLAIN_GET = _row("GET", "/dast-test/plain/{item_id}")
_PLAIN_POST = _row("POST", "/dast-test/plain-write/{item_id}")


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
    """The administrator reaches every row and an anonymous or forged caller gets 401. The viewer
    gets the engine's step-up 403 on one GET and one POST, where RBAC let it through to the step-up
    gate, and a plain 403 on a control GET and a control POST. The two step-up rows are BFLA
    violations, one per pass; the control rows are not. Pre-fix, both passes kept the status only and scored every 403
    as refused, so neither step-up row was a finding."""
    step_up = await _engine_step_up_headers()

    def handler(request: httpx.Request) -> httpx.Response:
        bearer = request.headers.get("Authorization", "")
        if bearer not in (f"Bearer {_ADMIN}", f"Bearer {_VIEWER}"):
            return httpx.Response(401)
        # The write pass's session-liveness probe: both sessions stay alive throughout.
        if bearer == f"Bearer {_ADMIN}" or request.url.path == PREFLIGHT_PATH:
            return httpx.Response(200)
        if request.url.path.startswith(("/dast-test/plain/", "/dast-test/plain-write/")):
            return httpx.Response(403)
        return httpx.Response(403, headers=step_up)

    transport = httpx.MockTransport(handler)

    # A subclass rather than a factory, so the patched name is still a class an isinstance check
    # accepts.
    class _MockClient(httpx.AsyncClient):
        def __init__(self, **kwargs: Any) -> None:
            super().__init__(transport=transport, **kwargs)

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
        return [_STEP_UP_GET, _PLAIN_GET, _STEP_UP_POST, _PLAIN_POST]

    def _no_rows(_app: object = None) -> list[route_gates.RouteRow]:
        return []

    monkeypatch.setattr(sweep, "dast_target", _target)
    monkeypatch.setattr(httpx, "AsyncClient", _MockClient)
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

    # The controls: every row was measured as the stub intends, so the BFLA result below is not an
    # artefact of a target that refused or reached everyone.
    assert receipt["negative_non_401"] == 0, receipt["findings"]
    assert receipt["reached"] == 2, receipt["findings"]
    assert receipt["write_reached"] == 2, receipt["findings"]
    assert receipt["bfla_probes"] == 2, receipt
    assert receipt["write_bfla_probes"] == 2, receipt
    assert receipt["write_session_rebuilds"] == 0, receipt
    # The defect: each step-up 403 is a finding, and each plain 403 is not.
    bfla = [f for f in receipt["findings"] if f["pass_name"] in ("bfla", "bfla-write")]
    assert sorted((f["pass_name"], f["method"], f["path"], f["observed_status"]) for f in bfla) == [
        ("bfla", "GET", _STEP_UP_GET.path, 403),
        ("bfla-write", "POST", _STEP_UP_POST.path, 403),
    ], receipt["findings"]
    assert receipt["bfla_violations"] == 1, receipt
    assert receipt["write_bfla_violations"] == 1, receipt
    # A step-up 403 finding names the step-up, so "answered 403; expected 401, 403 or 429" does not
    # read as a scanner bug.
    assert all("step-up" in f["expected"] for f in bfla), bfla
