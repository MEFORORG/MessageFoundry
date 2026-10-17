# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The managed app factory denies by default (vault BACKLOG #2611).

``create_managed_app`` reaches the open mode through ``allow_no_auth=True`` and nothing else, the
rule its sibling ``create_app`` already had. Each refusal below has a control that answers on the
same route, so a 503 is a reading of the gate and never of an app that failed to start.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from pathlib import Path

import httpx
import pytest
from fastapi import FastAPI
from starlette.testclient import TestClient, WebSocketDenialResponse

from messagefoundry.api import create_app, create_managed_app
from messagefoundry.api.security import AUTH_NOT_CONFIGURED
from messagefoundry.auth import Role
from messagefoundry.config.settings import AuthSettings, EgressSettings, ServiceSettings
from messagefoundry.pipeline import Engine

# The account helpers and the peer address the API auth tests pin, imported rather than copied.
from tests.test_api_auth import _DEFAULT_PEER, _add, _auth, _login, _service

#: A route behind ``require(...)``. ``/health`` is the control beside it: it answers a tokenless
#: caller through ``optional_identity`` in every mode, so it shows the app is up.
_PROTECTED = "/stats"
_ALWAYS_ANSWERS = "/health"


def _client(app: FastAPI) -> httpx.AsyncClient:
    return httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app, client=_DEFAULT_PEER), base_url="http://t"
    )


@pytest.mark.parametrize(
    ("allow_no_auth", "status"),
    [
        pytest.param(False, 503, id="no-settings"),
        pytest.param(True, 200, id="no-settings-opted-in"),
    ],
)
async def test_only_the_opt_in_opens_an_app_with_no_auth_settings(
    tmp_path: Path, allow_no_auth: bool, status: int
) -> None:
    """The opt-in decides: the refusal sits beside its own control."""
    app = create_managed_app(
        db_path=tmp_path / "managed.db",
        poll_interval=0.05,
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
    # The refusal is the handshake's HTTP answer, sent before accept (refuse_websocket), so the test
    # client raises the denial itself; a bare WebSocketDisconnect would also pass a socket that
    # accepted and then dropped (vault BACKLOG #2731 item 6).
    with (
        TestClient(refused) as tc,
        pytest.raises(WebSocketDenialResponse) as denied,
        tc.websocket_connect("/ws/stats"),
    ):
        pass
    assert denied.value.status_code == 403
    assert denied.value.json() == {"detail": "not authenticated or not permitted"}

    opened = create_managed_app(
        db_path=tmp_path / "ws-open.db",
        poll_interval=0.05,
        allow_no_auth=True,
        egress_settings=EgressSettings(deny_by_default=False),
    )
    with TestClient(opened) as tc, tc.websocket_connect("/ws/stats") as ws:
        assert "outbox_by_status" in ws.receive_json(), "control: the opt-in opens the socket"


#: The factory's own logger, read off the function so a module move cannot leave the filter empty.
_FACTORY_LOGGER = create_managed_app.__module__


def _factory_warnings(caplog: pytest.LogCaptureFixture) -> list[logging.LogRecord]:
    """Every WARNING the factory's logger wrote, so a second line worded differently counts too."""
    return [r for r in caplog.records if r.name == _FACTORY_LOGGER and r.levelno >= logging.WARNING]


@pytest.mark.parametrize(
    ("auth_settings", "allow_no_auth", "expected"),
    [
        pytest.param(None, False, 1, id="nothing-passed"),
        pytest.param(None, True, 0, id="opted-in"),
        pytest.param(
            AuthSettings(require_mfa=False, notify_security_events=False),
            False,
            0,
            id="auth-settings",
        ),
    ],
)
def test_a_deny_all_build_says_so_once(
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
    auth_settings: AuthSettings | None,
    allow_no_auth: bool,
    expected: int,
) -> None:
    """Vault BACKLOG #2731 item 1: the deny-all default fails closed, and the build logs one WARNING
    naming it. The opt-in and enabled settings are the controls: neither denies everything, and
    neither warns. The factory is called and not started, so the line is the build's own."""
    caplog.set_level(logging.WARNING, logger=_FACTORY_LOGGER)
    create_managed_app(
        db_path=tmp_path / "warn.db",
        poll_interval=0.05,
        auth_settings=auth_settings,
        allow_no_auth=allow_no_auth,
        egress_settings=EgressSettings(deny_by_default=False),
    )
    warnings = _factory_warnings(caplog)
    assert len(warnings) == expected
    assert all(AUTH_NOT_CONFIGURED in r.getMessage() for r in warnings)


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


def test_the_opt_in_beside_auth_settings_is_refused(tmp_path: Path) -> None:
    """Asking for sign-in and for the open mode at once is a mistake, so the factory says so."""
    with pytest.raises(ValueError, match="allow_no_auth"):
        create_managed_app(
            db_path=tmp_path / "both.db",
            auth_settings=AuthSettings(),
            allow_no_auth=True,
            egress_settings=EgressSettings(deny_by_default=False),
        )


# --- vault BACKLOG #2825: the opt-in with no service is the ONLY way into the open mode -------


@pytest.mark.parametrize(
    "build",
    [
        pytest.param(lambda: AuthSettings.model_validate({"enabled": False}), id="auth-settings"),
        pytest.param(
            lambda: ServiceSettings.model_validate({"auth": {"enabled": False}}),
            id="service-settings",
        ),
    ],
)
def test_settings_built_in_code_refuse_the_removed_sign_in_switch(
    build: Callable[[], object],
) -> None:
    """No settings object can say sign-in is off, whether it came from a file or from code.

    The loader already refuses ``[auth].enabled`` from a file or the environment (vault BACKLOG
    #2719). Before vault BACKLOG #2825 settings built in code took ``enabled=False``; now they refuse
    it loudly rather than drop it, and assigning the attribute is refused too."""
    assert "enabled" not in AuthSettings.model_fields
    with pytest.raises(ValueError, match=r"\[auth\]\.enabled was REMOVED"):
        build()
    with pytest.raises(ValueError, match="enabled"):
        setattr(AuthSettings(), "enabled", False)  # noqa: B010 -- the name is the subject


async def test_an_attached_service_cannot_be_opened(tmp_path: Path) -> None:
    """An auth service, once built, always asks for a session; nothing an embedder sets turns it off.

    So ``allow_no_auth=True`` opens an app only when no service is attached, and ``create_app``
    refuses the opt-in beside one. Before vault BACKLOG #2825 a service built from settings with
    ``enabled=False`` answered as disabled, and beside the opt-in the app served ``/stats`` to anyone
    (200); the property was a plain attribute anyone could set. Vault BACKLOG #3062 removed the
    property, so no guard reads one."""
    engine = await Engine.create(
        tmp_path / "attached.db",
        poll_interval=0.05,
        egress_settings=EgressSettings(deny_by_default=False),
    )
    try:
        service = await _service(engine, AuthSettings(require_mfa=False))
        # Vault BACKLOG #3062: the class has no `enabled` switch, so a stand-in that sets one
        # reporting false is read by nothing, and every check below still refuses.
        setattr(service, "enabled", False)  # noqa: B010 -- the name is the subject
        with pytest.raises(ValueError, match="allow_no_auth"):
            create_app(engine, auth=service, allow_no_auth=True)
        async with _client(create_app(engine, auth=service)) as c:
            assert (await c.get(_PROTECTED)).status_code == 401
        # Past both factory refusals: the flag set after a service is attached, as an embedder's own
        # lifespan could. The request-time checks still answer a tokenless caller with no identity.
        flagged = create_app(engine, auth=service)
        flagged.state.allow_no_auth = True
        async with _client(flagged) as c:
            assert (await c.get(_PROTECTED)).status_code == 401
            assert (await c.get(_ALWAYS_ANSWERS)).json()["version"] is None
        # The control: the opt-in with no service attached is the open mode.
        async with _client(create_app(engine, allow_no_auth=True)) as c:
            assert (await c.get(_PROTECTED)).status_code == 200
    finally:
        await engine.stop()
