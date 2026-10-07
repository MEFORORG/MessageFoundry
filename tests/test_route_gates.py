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

import contextlib
import importlib.util
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Any

import fastapi
import fastapi.routing
import pytest
from fastapi import APIRouter, Depends, FastAPI, Request, WebSocket
from fastapi.routing import APIWebSocketRoute
from starlette.middleware import Middleware
from starlette.responses import PlainTextResponse
from starlette.routing import Mount, Route
from starlette.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from messagefoundry.api.app import create_app
from messagefoundry.api.security import (
    authorize_ws,
    authorizes_in_body,
    mark_route_gate,
    public_route,
    require,
)
from messagefoundry.auth.permissions import Permission
from scripts.security import route_gates

# --- the live app ------------------------------------------------------------------------------------


@pytest.fixture(scope="module")
def json_only_app() -> FastAPI:
    return create_app()


@pytest.fixture(scope="module")
def ui_app() -> FastAPI:
    return create_app(serve_ui=True)


@pytest.fixture(scope="module")
def full_app() -> FastAPI:
    return route_gates.full_surface_app()


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

    return mark_route_gate(dependency)


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


# --- vault BACKLOG #2604: the walk's blind spots ------------------------------------------------------
# Each of the first, third and fourth tests below failed on the walk before #2604: the first read a
# dependency NAMED require_* as a gate, and the other two never reported the planted route at all.


def require_lookalike(*permissions: Permission) -> Callable[[Request], Awaitable[None]]:
    """Named like a gate factory and capturing ``permissions`` as one does, but carrying no gate mark."""

    async def dependency(request: Request) -> None:
        assert permissions is not None

    return dependency


async def _ok() -> dict[str, str]:
    return {"ok": "reached"}


def _rows_by_key(app: FastAPI) -> dict[tuple[str, str], route_gates.RouteRow]:
    return {(r.method, r.path): r for r in route_gates.route_rows(app)}


def test_a_dependency_named_like_a_gate_is_not_read_as_one() -> None:
    app = FastAPI()
    app.add_api_route(
        "/planted",
        _ok,
        dependencies=[Depends(require_lookalike(Permission.MESSAGES_VIEW_RAW))],
    )
    row = _rows_by_key(app)[("GET", "/planted")]
    assert row.gate is None and row.permissions == (), row


def test_a_marked_gate_is_read_whatever_its_name() -> None:
    gate = mark_route_gate(require_lookalike(Permission.MESSAGES_VIEW_RAW))
    app = FastAPI()
    app.add_api_route("/planted", _ok, dependencies=[Depends(gate)])
    row = _rows_by_key(app)[("GET", "/planted")]
    assert row.gate == "require_lookalike", row
    assert row.permissions == (Permission.MESSAGES_VIEW_RAW.value,), row


def test_the_walk_descends_into_an_included_router() -> None:
    sub = APIRouter(prefix="/sub")
    sub.add_api_route("/open", _ok)
    sub.add_api_route("/gated", _ok, dependencies=[Depends(require(Permission.MONITORING_READ))])
    gated_by_include = APIRouter()
    gated_by_include.add_api_route("/by-include", _ok)
    app = FastAPI()
    app.include_router(sub)
    app.include_router(gated_by_include, dependencies=[Depends(require(Permission.AUDIT_READ))])
    rows = _rows_by_key(app)
    assert rows[("GET", "/sub/open")].gate is None
    assert rows[("GET", "/sub/gated")].permissions == (Permission.MONITORING_READ.value,)
    # A gate the include call adds is not the route's own, and the engine refuses such a route, so
    # the walk must read it as no gate rather than vouch for it.
    assert rows[("GET", "/by-include")].gate is None
    assert not [key for key in rows if key[1] == ""], rows


def test_an_included_websocket_reads_the_gate_its_include_adds() -> None:
    """FastAPI serves an included WebSocket through a rebuilt route that carries the include's
    dependencies, and the engine's refusal reads that rebuilt route, so the walk reads it too."""
    sub = APIRouter()
    sub.add_api_websocket_route("/ws/included", _dependency_gated)
    app = FastAPI()
    app.include_router(sub, dependencies=[Depends(require_ws_probe(Permission.FILES_BROWSE))])
    (row,) = _ws_rows(app)
    assert row.path == "/ws/included"
    assert row.gates == ("require_ws_probe",), row


def test_the_walk_descends_into_a_mounted_application_with_routes() -> None:
    inner = FastAPI(openapi_url=None)
    inner.add_api_route("/inner", _ok)
    app = FastAPI()
    app.mount("/mounted", inner)
    rows = _rows_by_key(app)
    assert rows[("GET", "/mounted/inner")].gate is None
    assert (route_gates.MOUNT_METHOD, "/mounted") not in rows


@pytest.mark.parametrize("hook_on", ["outer", "inner"])
def test_a_mounted_apps_socket_hooks_are_read_from_that_app(hook_on: str) -> None:
    """Vault BACKLOG #2846. A socket inside a mounted application sees that application as
    ``websocket.app``, because Starlette sets ``scope["app"]`` as a request enters each app. The walk
    read its hook slots from the OUTER app, so it reported a hook the socket never runs and missed
    one it does. Each case fails on that walk."""
    inner = FastAPI(openapi_url=None)
    inner.add_api_websocket_route("/ws", _hooked)
    outer = FastAPI()
    outer.mount("/mounted", inner)
    (outer if hook_on == "outer" else inner).state.probe_hook = authorize_probe
    (row,) = _ws_rows(outer)
    assert row.path == "/mounted/ws"
    expected = ("authorize_ws",) if hook_on == "outer" else ("authorize_probe", "authorize_ws")
    assert row.gates == expected, row


class _PassThrough:
    """An ASGI middleware that changes nothing, so a mount wraps its app in one layer."""

    def __init__(self, app: Any) -> None:
        self.app = app

    async def __call__(self, scope: Any, receive: Any, send: Any) -> None:
        await self.app(scope, receive, send)


def test_a_mounted_app_beneath_mount_middleware_is_still_the_state_owner() -> None:
    """``_mounted_app`` reads Starlette's private ``Mount._base_app``. This pins that it still
    exists and is what the walk reads, so a Starlette rename reds a run here."""
    inner = FastAPI(openapi_url=None)
    inner.add_api_websocket_route("/ws", _hooked)
    inner.state.probe_hook = authorize_probe
    outer = FastAPI()
    outer.routes.append(Mount("/mw", app=inner, middleware=[Middleware(_PassThrough)]))
    (mount,) = [r for r in outer.routes if isinstance(r, Mount)]
    assert getattr(mount, "_base_app", None) is inner
    (row,) = _ws_rows(outer)
    assert row.gates == ("authorize_probe", "authorize_ws"), row


def test_a_plain_route_outside_the_refusal_still_reports_its_declaration() -> None:
    app = FastAPI()

    @public_route("a synthetic plain route")
    async def plain(request: Request) -> PlainTextResponse:
        return PlainTextResponse("ok")

    app.routes.append(Route("/plain", plain))
    row = _rows_by_key(app)[("GET", "/plain")]
    assert (row.kind, row.declaration) == (route_gates.KIND_OUTSIDE, "a synthetic plain route")


def test_a_socket_in_a_mounted_app_runs_the_mounted_apps_hook_at_request_time() -> None:
    """The premise of ``test_a_mounted_apps_socket_hooks_are_read_from_that_app``, measured on a
    live handshake rather than assumed."""
    ran: list[str] = []

    def recorder(name: str) -> Callable[..., Awaitable[tuple[None, None]]]:
        async def hook(websocket: WebSocket, *permissions: Permission) -> tuple[None, None]:
            ran.append(name)
            await websocket.close()
            return None, None

        return hook

    inner = FastAPI(openapi_url=None)
    inner.add_api_websocket_route("/ws", _hooked)
    inner.state.probe_hook = recorder("inner")
    outer = FastAPI()
    outer.state.probe_hook = recorder("outer")
    outer.mount("/mounted", inner)
    with (
        TestClient(outer) as client,
        contextlib.suppress(WebSocketDisconnect, RuntimeError),
        client.websocket_connect("/mounted/ws"),
    ):
        pass
    assert ran[:1] == ["inner"], ran


def test_a_mount_of_bare_routes_reads_socket_hooks_from_the_outer_app() -> None:
    """A mount with no app of its own sets no ``scope["app"]``, so its socket sees the outer app."""
    outer = FastAPI()
    outer.routes.append(Mount("/bare", routes=[APIWebSocketRoute("/ws", _hooked)]))
    outer.state.probe_hook = authorize_probe
    (row,) = _ws_rows(outer)
    assert row.path == "/bare/ws"
    assert row.gates == ("authorize_probe", "authorize_ws"), row


def test_a_mount_with_no_routes_stays_one_ungated_row(ui_app: FastAPI) -> None:
    rows = _rows_by_key(ui_app)
    assert rows[(route_gates.MOUNT_METHOD, "/ui/static")].gate is None


# --- vault BACKLOG #2846: what the refusal makes of each row --------------------------------------------
# Before #2846 a row carried no kind and no declaration, so a route public by design and one the engine
# refuses to every caller both read as "no gate". Each test below fails on that walk.


def test_each_row_says_whether_the_route_is_gated_public_in_body_refused_or_outside() -> None:
    app = create_app()

    @app.get("/zz/public")
    @public_route("a synthetic public route")
    async def zz_public() -> dict[str, str]:
        return {"ok": "reached"}

    @app.get("/zz/undeclared")
    async def zz_undeclared() -> dict[str, str]:
        return {"ok": "reached"}

    @app.get("/zz/in-body-on-http")
    @authorizes_in_body("only a WebSocket may say this")
    async def zz_in_body_on_http() -> dict[str, str]:
        return {"ok": "reached"}

    app.add_api_websocket_route("/zz/ws-undeclared", _hooked)
    sub = APIRouter()
    sub.add_api_route("/zz/included", _ok)
    app.include_router(sub)
    inner = FastAPI(openapi_url=None)
    inner.add_api_route("/inner", _ok)
    app.mount("/zz/mounted", inner)

    rows = _rows_by_key(app)
    assert rows[("GET", "/zz/public")].kind == route_gates.KIND_PUBLIC
    assert rows[("GET", "/zz/public")].declaration == "a synthetic public route"
    assert rows[("GET", "/zz/undeclared")].kind == route_gates.KIND_REFUSED
    assert rows[("GET", "/zz/undeclared")].declaration is None
    # An HTTP route may not authorize in its body, so the engine refuses it; the reason still shows.
    in_body = rows[("GET", "/zz/in-body-on-http")]
    assert (in_body.kind, in_body.declaration) == (
        route_gates.KIND_REFUSED,
        "only a WebSocket may say this",
    )
    # Gates read from a socket's body do not declare it, so the engine refuses this one too.
    socket = rows[(route_gates.WS_METHOD, "/zz/ws-undeclared")]
    assert socket.gates and socket.kind == route_gates.KIND_REFUSED, socket
    assert rows[("GET", "/zz/included")].kind == route_gates.KIND_REFUSED
    # The outer app's refusal never runs inside a mount, so that row is outside it.
    assert rows[("GET", "/zz/mounted/inner")].kind == route_gates.KIND_OUTSIDE
    assert rows[("GET", "/messages")].kind == route_gates.KIND_GATED
    assert rows[(route_gates.WS_METHOD, "/ws/stats")].kind == route_gates.KIND_IN_BODY
    assert rows[(route_gates.WS_METHOD, "/ws/stats")].declaration


def test_a_bare_app_with_no_refusal_reads_as_outside_it() -> None:
    """The kind is what the refusal does, so an app that does not install it has no refused row."""
    app = FastAPI()
    app.add_api_route("/planted", _ok)
    assert _rows_by_key(app)[("GET", "/planted")].kind == route_gates.KIND_OUTSIDE


def test_the_shipped_surface_refuses_nothing_and_every_ungated_row_is_declared_public(
    full_app: FastAPI,
) -> None:
    """On the app with every route-registering flag on, a row with no gate is public by design with
    a reason, or sits outside the refusal (the docs and the static mount). None is refused."""
    rows = route_gates.route_rows(full_app)
    by_kind: dict[str, list[route_gates.RouteRow]] = {}
    for row in rows:
        by_kind.setdefault(row.kind, []).append(row)
    assert not by_kind.get(route_gates.KIND_REFUSED), by_kind.get(route_gates.KIND_REFUSED)
    assert len(by_kind[route_gates.KIND_GATED]) > 150, "the walk classified too few rows as gated"
    public = by_kind[route_gates.KIND_PUBLIC]
    assert ("POST", "/auth/login") in {(r.method, r.path) for r in public}
    assert all(r.declaration and r.declaration.strip() for r in public), public
    outside = {(r.method, r.path) for r in by_kind[route_gates.KIND_OUTSIDE]}
    assert outside == {
        (route_gates.MOUNT_METHOD, "/ui/static"),
        ("GET", "/docs"),
        ("GET", "/docs/oauth2-redirect"),
        ("GET", "/openapi.json"),
        ("GET", "/redoc"),
    }, outside


def test_the_full_surface_app_walks_the_flag_registered_routes(
    ui_app: FastAPI, full_app: FastAPI
) -> None:
    """The OIDC console routes register only with ``oidc_enabled`` on, so neither the default app nor
    a plain ``serve_ui`` app shows them. The full-surface app does."""
    rows = _rows_by_key(full_app)
    for key in [("GET", "/ui/oidc/callback"), ("GET", "/docs"), ("GET", "/ui/login")]:
        assert key in rows, key
    assert ("GET", "/ui/oidc/callback") not in _rows_by_key(ui_app)


# --- FastAPI names the walk reads (vault BACKLOG #3055) ----------------------------------------------


async def _plain(request: Request) -> PlainTextResponse:  # pragma: no cover - never called
    return PlainTextResponse("")


def _app_with_an_included_plain_route() -> FastAPI:
    sub = APIRouter()
    sub.add_route("/plain", _plain)
    app = FastAPI(openapi_url=None)
    app.include_router(sub, prefix="/inc")
    return app


def test_an_included_plain_route_is_walked_under_its_include_prefix() -> None:
    """THE CONTROL for the two tests below: with the rebuilt route readable, the included plain
    route reports the include's prefix rather than its own bare path."""
    rows = _rows_by_key(_app_with_an_included_plain_route())
    assert ("GET", "/inc/plain") in rows, sorted(rows)
    assert ("GET", "/plain") not in rows


def _route_context_hiding(
    monkeypatch: pytest.MonkeyPatch, name: str, *, empty: bool = False
) -> None:
    """Make every ``RouteContext`` answer ``name`` as a FastAPI that renamed it would, by raising
    AttributeError, or as one that left it empty, by returning ``None``."""
    original = fastapi.routing.RouteContext.__getattr__

    def patched(self: Any, attr: str) -> Any:
        if attr != name:
            return original(self, attr)
        if empty:
            return None
        raise AttributeError(attr)

    monkeypatch.setattr(fastapi.routing.RouteContext, "__getattr__", patched)


def test_a_renamed_rebuilt_route_fails_the_walk_by_name(monkeypatch: pytest.MonkeyPatch) -> None:
    """The walk read the rebuilt route with a silent ``None`` default, so a FastAPI that renamed the
    field would have walked the route under ``/plain`` and passed. Now it names the field and the
    installed FastAPI."""
    app = _app_with_an_included_plain_route()
    _route_context_hiding(monkeypatch, "starlette_route")
    with pytest.raises(route_gates.MissingFastAPISymbol) as caught:
        route_gates.route_rows(app)
    assert "RouteContext.starlette_route" in str(caught.value)
    assert f"FastAPI {fastapi.__version__}" in str(caught.value)


def test_an_empty_rebuilt_route_fails_the_walk(monkeypatch: pytest.MonkeyPatch) -> None:
    app = _app_with_an_included_plain_route()
    _route_context_hiding(monkeypatch, "starlette_route", empty=True)
    with pytest.raises(ValueError, match="no rebuilt route"):
        route_gates.route_rows(app)


def test_a_fastapi_without_iter_route_contexts_fails_the_import_by_name(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """FastAPI 0.137.0 and 0.137.1 have no ``iter_route_contexts``, and the module must refuse to
    import there rather than walk without it. A fresh copy is loaded under its own name, so the
    module every other test imported stays as it was."""
    monkeypatch.delattr(fastapi.routing, "iter_route_contexts")
    spec = importlib.util.spec_from_file_location(
        "route_gates_without_iter_route_contexts", route_gates.__file__
    )
    assert spec is not None and spec.loader is not None
    with pytest.raises(ImportError) as caught:
        spec.loader.exec_module(importlib.util.module_from_spec(spec))
    assert "fastapi.routing.iter_route_contexts" in str(caught.value)
    assert f"FastAPI {fastapi.__version__}" in str(caught.value)


def _frontend_on_the_app(app: FastAPI, directory: str) -> None:
    app.frontend("/app", directory=directory, check_dir=False)


def _frontend_in_an_include(app: FastAPI, directory: str) -> None:
    sub = APIRouter()
    sub.frontend("/", directory=directory, check_dir=False)
    app.include_router(sub, prefix="/inc")


def _frontend_in_a_mounted_app(app: FastAPI, directory: str) -> None:
    inner = FastAPI(openapi_url=None)
    inner.add_api_route("/inner", _ok)
    inner.frontend("/", directory=directory, check_dir=False)
    app.mount("/mounted", inner)


def _frontend_alone_in_a_mounted_app(app: FastAPI, directory: str) -> None:
    inner = FastAPI(openapi_url=None, docs_url=None, redoc_url=None)
    inner.frontend("/", directory=directory, check_dir=False)
    app.mount("/spa", inner)


def _frontend_alone_in_a_mounted_router(app: FastAPI, directory: str) -> None:
    inner = APIRouter()
    inner.frontend("/", directory=directory, check_dir=False)
    app.router.routes.append(Mount("/spa", app=inner))


def _frontend_alone_in_an_included_mount(app: FastAPI, directory: str) -> None:
    inner = FastAPI(openapi_url=None, docs_url=None, redoc_url=None)
    inner.frontend("/", directory=directory, check_dir=False)
    sub = APIRouter()
    sub.mount("/spa", inner)
    app.include_router(sub, prefix="/inc")


@pytest.mark.parametrize(
    "register",
    [
        _frontend_on_the_app,
        _frontend_in_an_include,
        _frontend_in_a_mounted_app,
        # A mount whose only content is the group has no routes, so a walk never descends into it.
        _frontend_alone_in_a_mounted_app,
        _frontend_alone_in_a_mounted_router,
        _frontend_alone_in_an_included_mount,
    ],
)
def test_a_frontend_group_fails_the_walk_rather_than_passing_unvisited(
    register: Callable[[FastAPI, str], None], tmp_path: Path
) -> None:
    """FastAPI keeps a ``frontend`` group in a list ``iter_route_contexts`` never yields, so the walk
    would serve it unseen. None is registered today; one that is reds every consumer of the walk."""
    app = FastAPI(openapi_url=None)
    app.add_api_route("/ordinary", _ok)
    assert ("GET", "/ordinary") in _rows_by_key(app)  # the control: no group, no refusal
    register(app, str(tmp_path))
    with pytest.raises(ValueError, match="low-priority route"):
        route_gates.route_rows(app)


def test_a_renamed_low_priority_list_fails_the_walk_by_name(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delattr(APIRouter, "_iter_low_priority_routes")
    with pytest.raises(route_gates.MissingFastAPISymbol, match="_iter_low_priority_routes"):
        route_gates.route_rows(FastAPI(openapi_url=None))


def test_a_route_registered_directly_and_through_an_include_reports_both_paths() -> None:
    """The rebuilt route is read before the registered-here test, so a shared route object still
    reports the prefixed path FastAPI serves through the include."""
    shared = Route("/plain", _plain)
    sub = APIRouter()
    sub.routes.append(shared)
    app = FastAPI(openapi_url=None)
    app.router.routes.append(shared)
    app.include_router(sub, prefix="/inc")
    rows = _rows_by_key(app)
    assert ("GET", "/plain") in rows and ("GET", "/inc/plain") in rows, sorted(rows)
