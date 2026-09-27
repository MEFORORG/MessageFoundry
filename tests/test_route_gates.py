# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""WebSocket gates in ``scripts/security/route_gates.py`` are read from the code (BACKLOG #2057).

The walk used to write every WebSocket row's gate as ``authorize_ws`` and to find its permissions by
searching the endpoint source for ``Permission.<NAME>``. So ``/ws/stats`` on an app with the web
console mounted read as header-gated only, while every same-origin browser passed through the cookie
gate ``authorize_ui_ws``. A route with no gate at all would still have read as ``authorize_ws``, and a
permission named only in a comment counted.

The live-app tests below drive the SHIPPED ``route_rows`` against both app shapes. The planted routes
drive the same function against endpoints written to fail each old shortcut, so each rule is shown to
bite and not only to agree with today's tree.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Any

import pytest
from fastapi import Depends, FastAPI, WebSocket

from messagefoundry.api.app import create_app
from messagefoundry.api.security import authorize_ws
from messagefoundry.auth.permissions import Permission
from scripts.security import route_gates

# --- the live app ------------------------------------------------------------------------------------


@pytest.fixture(scope="module")
def json_only_app() -> FastAPI:
    return create_app()


@pytest.fixture(scope="module")
def ui_app() -> FastAPI:
    return create_app(serve_ui=True)


def _ws_rows(app: FastAPI) -> list[route_gates.RouteRow]:
    return [r for r in route_gates.route_rows(app) if r.method == route_gates.WS_METHOD]


def test_ws_stats_reports_the_cookie_gate_when_the_web_console_is_mounted(ui_app: FastAPI) -> None:
    """The positive control. With ``serve_ui=True``, ``mount_ui`` fills ``app.state.ui_ws_authorize``
    with ``authorize_ui_ws``, and ``/ws/stats`` calls it before the header gate. The old hard-coding
    reported ``authorize_ws`` here, so this is the assertion it fails."""
    rows = _ws_rows(ui_app)
    assert [r.path for r in rows] == ["/ws/stats"], rows
    (row,) = rows
    assert row.gate == "authorize_ui_ws", row
    assert row.gates == ("authorize_ui_ws", "authorize_ws"), row
    assert row.permissions == (Permission.MONITORING_READ.value,), row


def test_ws_stats_reports_only_the_header_gate_on_a_json_only_app(json_only_app: FastAPI) -> None:
    """With the console absent the hook slot is empty, so the cookie gate never runs and must not be
    reported."""
    (row,) = _ws_rows(json_only_app)
    assert row.gate == "authorize_ws", row
    assert row.gates == ("authorize_ws",), row
    assert row.permissions == (Permission.MONITORING_READ.value,), row


@pytest.mark.parametrize("shape", ["json_only_app", "ui_app"])
def test_every_shipped_websocket_route_has_a_derived_gate(
    shape: str, request: pytest.FixtureRequest
) -> None:
    """The walk reads bare-name calls only, so a gate reached another way would read as absent. The
    ungated-set helpers exclude WebSocket rows, so this floor is what turns that into a red run."""
    rows = _ws_rows(request.getfixturevalue(shape))
    assert rows, "the app serves no WebSocket route; this floor is scanning nothing"
    ungated = [r for r in rows if r.gate is None or not r.permissions]
    assert not ungated, f"WebSocket routes with no derived gate or permission: {ungated}"


# --- planted routes ----------------------------------------------------------------------------------
# Module-level on purpose, bar one: the walk finds each endpoint in this module's parsed source, and
# these must resolve authorize_ws and Permission through this module's globals exactly as ws_stats does
# through app.py's. _nested_endpoint is nested because ws_stats is.


async def _commented_permission(websocket: WebSocket) -> None:
    # Permission.USERS_MANAGE is named here only, in a comment, and must not count.
    await authorize_ws(websocket, Permission.AUDIT_READ)


async def _no_gate(websocket: WebSocket) -> None:
    await websocket.accept()


async def authorize_probe(websocket: WebSocket, *permissions: Permission) -> tuple[None, None]:
    """A stand-in for the web console's cookie gate, installed into an app.state hook slot."""
    return None, None


async def _hooked(websocket: WebSocket) -> None:
    probe_hook = getattr(websocket.app.state, "probe_hook", None)
    if probe_hook is not None:
        await probe_hook(websocket, Permission.LOGS_VIEW)
    await authorize_ws(websocket, Permission.LOGS_VIEW)


async def _check(websocket: WebSocket, permission: Permission) -> None:
    """Named outside the ``authorize*`` convention, so the walk cannot recognise it."""


async def _unrecognised_gate(websocket: WebSocket) -> None:
    await _check(websocket, Permission.USERS_READ)


async def _keyword_permission(websocket: WebSocket) -> None:
    await _check(websocket, permission=Permission.USERS_READ)


async def _in_body_check(websocket: WebSocket) -> None:
    identity = await authorize_ws(websocket)
    if identity is None or not identity.has(Permission.USERS_MANAGE):
        return


async def authorized_channels(websocket: WebSocket) -> list[str]:
    """Shares the ``authorize`` prefix without being a gate."""
    return []


async def _prefix_lookalike(websocket: WebSocket) -> None:
    await authorize_ws(websocket, Permission.USERS_READ)
    await authorized_channels(websocket)


async def _rebound_hook(websocket: WebSocket) -> None:
    hook = getattr(websocket.app.state, "probe_hook", None)
    hook, _other = authorize_ws, 1
    await hook(websocket, Permission.LOGS_VIEW)


async def _same_permission_unrecognised(websocket: WebSocket) -> None:
    await authorize_ws(websocket, Permission.LOGS_VIEW)
    await _check(websocket, Permission.LOGS_VIEW)


async def _defaulted_hook(websocket: WebSocket) -> None:
    hook = getattr(websocket.app.state, "probe_hook", authorize_ws)
    await hook(websocket, Permission.LOGS_VIEW)


def authorize_url(value: str) -> str:
    """A synchronous helper that shares the gate prefix."""
    return value


async def _sync_lookalike(websocket: WebSocket) -> None:
    await authorize_ws(websocket, Permission.USERS_READ)
    authorize_url("x")


def _nested_endpoint() -> Callable[[WebSocket], Awaitable[None]]:
    """A nested endpoint, as ``ws_stats`` is, holding what a dedented snippet cannot parse: a
    multi-line string with a line at column 0. Its nested helper calls a gate after the handshake."""

    async def nested(websocket: WebSocket) -> None:
        note = """
at column zero
"""
        await authorize_ws(websocket, Permission.LOGS_VIEW)

        async def _later() -> None:
            await authorize_ws(websocket, Permission.LOGS_VIEW)

        del note, _later

    return nested


_PERMS = (Permission.USERS_READ,)


async def _non_literal_permission(websocket: WebSocket) -> None:
    await authorize_ws(websocket, *_PERMS)


async def _mixed_chain(websocket: WebSocket) -> None:
    await authorize_ws(websocket, Permission.USERS_READ)
    await authorize_ws(websocket, Permission.USERS_MANAGE)


def require_ws_probe(*permissions: Permission) -> Callable[[WebSocket], Awaitable[None]]:
    """A ``require*`` factory in the closure shape :func:`route_gates.gate_of` reads."""

    async def dependency(websocket: WebSocket) -> None:
        assert permissions  # read, so the closure captures ``permissions`` as gate_of expects

    return dependency


async def _dependency_gated(websocket: WebSocket) -> None:
    await websocket.accept()


def _app_with(endpoint: Callable[..., Any], **kwargs: Any) -> FastAPI:
    app = FastAPI()
    app.add_api_websocket_route("/ws/planted", endpoint, **kwargs)
    return app


def _planted_row(endpoint: Callable[..., Any], **kwargs: Any) -> route_gates.RouteRow:
    (row,) = _ws_rows(_app_with(endpoint, **kwargs))
    return row


def test_a_permission_named_only_in_a_comment_does_not_count() -> None:
    row = _planted_row(_commented_permission)
    assert row.permissions == (Permission.AUDIT_READ.value,), row
    assert row.gates == ("authorize_ws",), row


def test_a_websocket_route_with_no_gate_reads_as_ungated() -> None:
    row = _planted_row(_no_gate)
    assert row.gate is None and row.gates == () and row.permissions == (), row


def test_a_hook_gate_is_read_from_the_live_app_state() -> None:
    app = _app_with(_hooked)
    (without_hook,) = _ws_rows(app)
    assert without_hook.gates == ("authorize_ws",), without_hook
    app.state.probe_hook = authorize_probe
    (with_hook,) = _ws_rows(app)
    assert with_hook.gates == ("authorize_probe", "authorize_ws"), with_hook
    assert with_hook.gate == "authorize_probe", with_hook
    assert with_hook.permissions == (Permission.LOGS_VIEW.value,), with_hook


def test_a_dependency_gate_on_a_websocket_route_is_read_like_http() -> None:
    row = _planted_row(
        _dependency_gated, dependencies=[Depends(require_ws_probe(Permission.FILES_BROWSE))]
    )
    assert row.gates == ("require_ws_probe",), row
    assert row.permissions == (Permission.FILES_BROWSE.value,), row


def test_a_nested_endpoint_is_read_from_its_module_and_its_nested_calls_are_not_gates() -> None:
    row = _planted_row(_nested_endpoint())
    assert row.gates == ("authorize_ws",), row
    assert row.permissions == (Permission.LOGS_VIEW.value,), row


@pytest.mark.parametrize("endpoint", [_prefix_lookalike, _sync_lookalike], ids=["prefix", "sync"])
def test_a_helper_sharing_the_authorize_prefix_is_not_a_gate(
    endpoint: Callable[..., Any],
) -> None:
    row = _planted_row(endpoint)
    assert row.gates == ("authorize_ws",), row


def test_a_wrapped_hook_raises_even_when_it_repeats_a_read_permission() -> None:
    """A hook the walk cannot name (here a lambda) must not vanish behind a gate it did read."""
    app = _app_with(_hooked)
    app.state.probe_hook = lambda websocket, *permissions: authorize_probe(websocket, *permissions)
    with pytest.raises(ValueError, match="not demanded by any gate"):
        route_gates.route_rows(app)


@pytest.mark.parametrize(
    ("endpoint", "needle"),
    [
        (_unrecognised_gate, "not demanded by any gate"),
        (_keyword_permission, "not demanded by any gate"),
        (_in_body_check, "not demanded by any gate"),
        (_rebound_hook, "not demanded by any gate"),
        (_same_permission_unrecognised, "not demanded by any gate"),
        (_defaulted_hook, "not demanded by any gate"),
        (_non_literal_permission, "not a Permission.X literal"),
        (_mixed_chain, "demand different permissions"),
    ],
    ids=[
        "unrecognised-callee",
        "keyword-permission",
        "in-body-check",
        "rebound-hook",
        "same-permission-unrecognised",
        "defaulted-hook",
        "non-literal-permission",
        "mixed-chain",
    ],
)
def test_a_gate_the_walk_cannot_read_raises_rather_than_under_reports(
    endpoint: Callable[..., Any], needle: str
) -> None:
    with pytest.raises(ValueError, match=needle):
        route_gates.route_rows(_app_with(endpoint))
