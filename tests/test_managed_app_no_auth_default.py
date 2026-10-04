# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The managed app factory denies by default (vault BACKLOG #2611).

``create_managed_app`` reaches the open mode through ``allow_no_auth=True`` and nothing else, the
rule its sibling ``create_app`` already had. Each refusal below has a control that answers on the
same route, so a 503 is a reading of the gate and never of an app that failed to start.
"""

from __future__ import annotations

from pathlib import Path

import httpx
import pytest
from fastapi import FastAPI
from starlette.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from messagefoundry.api import create_managed_app
from messagefoundry.auth import Role
from messagefoundry.config.settings import AuthSettings, EgressSettings

# The account helpers and the peer address the API auth tests pin, imported rather than copied.
from tests.test_api_auth import _DEFAULT_PEER, _add, _auth, _login

#: A route behind ``require(...)``. ``/health`` is the control beside it: it answers a tokenless
#: caller through ``optional_identity`` in every mode, so it shows the app is up.
_PROTECTED = "/stats"
_ALWAYS_ANSWERS = "/health"


def _client(app: FastAPI) -> httpx.AsyncClient:
    return httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app, client=_DEFAULT_PEER), base_url="http://t"
    )


@pytest.mark.parametrize(
    ("auth_settings", "allow_no_auth", "status"),
    [
        pytest.param(None, False, 503, id="no-settings"),
        pytest.param(None, True, 200, id="no-settings-opted-in"),
        # Settings that say sign-in is off describe the instance. They are not the opt-in.
        pytest.param(AuthSettings(enabled=False), False, 503, id="disabled-settings"),
        pytest.param(AuthSettings(enabled=False), True, 200, id="disabled-settings-opted-in"),
    ],
)
async def test_only_the_opt_in_opens_an_app_with_no_enabled_auth(
    tmp_path: Path, auth_settings: AuthSettings | None, allow_no_auth: bool, status: int
) -> None:
    """The opt-in decides, and the settings do not: each refusal sits beside its own control."""
    app = create_managed_app(
        db_path=tmp_path / "managed.db",
        poll_interval=0.05,
        auth_settings=auth_settings,
        allow_no_auth=allow_no_auth,
        egress_settings=EgressSettings(deny_by_default=False),
    )
    async with app.router.lifespan_context(app), _client(app) as c:
        health = await c.get(_ALWAYS_ANSWERS)
        answer = await c.get(_PROTECTED)
    assert health.status_code == 200, "control: the app is serving"
    assert answer.status_code == status
    if status == 503:
        assert answer.json()["detail"] == "authentication is not configured"
    # The same flag feeds ``optional_identity``: the build version goes only to an identified caller.
    assert (health.json()["version"] is not None) is allow_no_auth


async def test_a_caller_that_passes_nothing_is_refused(tmp_path: Path) -> None:
    """The default itself: the rows above name ``allow_no_auth``, and an embedder may not."""
    app = create_managed_app(
        db_path=tmp_path / "default.db",
        poll_interval=0.05,
        egress_settings=EgressSettings(deny_by_default=False),
    )
    async with app.router.lifespan_context(app), _client(app) as c:
        assert (await c.get(_PROTECTED)).status_code == 503


def test_the_stats_socket_follows_the_same_opt_in(tmp_path: Path) -> None:
    """``authorize_ws`` reads the same flag, so the socket is refused by default and opens on the
    opt-in. The sync client drives the lifespan, as the other WebSocket tests do."""
    refused = create_managed_app(
        db_path=tmp_path / "ws-deny.db",
        poll_interval=0.05,
        egress_settings=EgressSettings(deny_by_default=False),
    )
    with (
        TestClient(refused) as tc,
        pytest.raises(WebSocketDisconnect),
        tc.websocket_connect("/ws/stats") as ws,
    ):
        ws.receive_json()

    opened = create_managed_app(
        db_path=tmp_path / "ws-open.db",
        poll_interval=0.05,
        allow_no_auth=True,
        egress_settings=EgressSettings(deny_by_default=False),
    )
    with TestClient(opened) as tc, tc.websocket_connect("/ws/stats") as ws:
        assert "outbox_by_status" in ws.receive_json(), "control: the opt-in opens the socket"


async def test_enabled_auth_settings_refuse_an_anonymous_call_and_answer_a_signed_in_one(
    tmp_path: Path,
) -> None:
    """The second control: with sign-in on, the same route asks for a session and honours one."""
    app = create_managed_app(
        db_path=tmp_path / "auth.db",
        poll_interval=0.05,
        # Notices off skips the ADR 0167 deliverability gate, which would refuse an empty store.
        auth_settings=AuthSettings(require_mfa=False, notify_security_events=False),
        egress_settings=EgressSettings(deny_by_default=False),
    )
    async with app.router.lifespan_context(app), _client(app) as c:
        await _add(app.state.auth, "root", Role.ADMINISTRATOR)
        assert (await c.get(_PROTECTED)).status_code == 401
        signed_in = await _login(c, "root")
        assert signed_in.status_code == 200, signed_in.text
        token = signed_in.json()["token"]
        assert (await c.get(_PROTECTED, headers=_auth(token))).status_code == 200


def test_the_opt_in_beside_enabled_auth_settings_is_refused(tmp_path: Path) -> None:
    """Asking for sign-in and for the open mode at once is a mistake, so the factory says so."""
    with pytest.raises(ValueError, match="allow_no_auth"):
        create_managed_app(
            db_path=tmp_path / "both.db",
            auth_settings=AuthSettings(),
            allow_no_auth=True,
            egress_settings=EgressSettings(deny_by_default=False),
        )
