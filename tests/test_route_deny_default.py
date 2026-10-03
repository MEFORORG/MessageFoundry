# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Every route declares its authorization, and the engine refuses one that does not (vault BACKLOG #2604).

``create_app`` installs ``refuse_undeclared_route`` as an app-level dependency. A matched route passes
it only with a gate dependency carrying the gate mark, or with an endpoint marked ``public_route``
(``authorizes_in_body`` for a WebSocket). These tests prove two things about that control:

* It changes nothing the shipped app serves. Every route of the app built with every route-registering
  flag on answers an anonymous caller exactly as it did without the control, gated and public alike,
  including the ``/ui`` sign-in pages and ``/ui/static``.
* It refuses a route that declares nothing, including one whose dependency is only NAMED like a gate,
  and one reached through an included router.

The route walk's own tests for the same blind spots are in ``tests/test_route_gates.py``.
"""

from __future__ import annotations

import inspect
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import httpx
import pytest
from fastapi import APIRouter, Depends, FastAPI, Request, WebSocket
from fastapi.routing import APIRoute, APIWebSocketRoute
from pydantic import BaseModel
from starlette.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

import messagefoundry.api.app as app_module
from messagefoundry.api.app import create_app, create_managed_app
from messagefoundry.api.security import (
    UNDECLARED_ROUTE_DETAIL,
    authorizes_in_body,
    public_route,
    require,
    route_is_declared,
)
from messagefoundry.auth.permissions import Permission
from messagefoundry.auth.service import AuthService
from messagefoundry.config.settings import AuthSettings
from messagefoundry.pipeline import Engine
from scripts.security import route_gates

pytest.importorskip("messagefoundry_webconsole")


def _route_keys(app: FastAPI) -> set[tuple[str, str]]:
    return {(r.method, r.path) for r in route_gates.route_rows(app)}


def _without_refusal(monkeypatch: pytest.MonkeyPatch) -> None:
    """Make every app built after this call carry a no-op in place of the refusal: the "before"."""

    async def allow_everything() -> None:
        return None

    monkeypatch.setattr(app_module, "refuse_undeclared_route", allow_everything)


@pytest.fixture(scope="module")
def full_app() -> FastAPI:
    return route_gates.full_surface_app()


# --- the shipped surface -----------------------------------------------------------------------------


def test_every_route_the_full_surface_app_serves_declares_its_authorization(
    full_app: FastAPI,
) -> None:
    app = full_app
    api_routes = [r for r in app.routes if isinstance(r, (APIRoute, APIWebSocketRoute))]
    assert len(api_routes) > 200, f"only {len(api_routes)} routes; the app did not build whole"
    undeclared = [
        r.path
        for r in api_routes
        if not route_is_declared(r, websocket=isinstance(r, APIWebSocketRoute))
    ]
    assert not undeclared, f"routes the engine would refuse to every caller: {undeclared}"


def test_the_only_routes_outside_the_refusal_are_the_docs_and_the_static_mount(
    full_app: FastAPI,
) -> None:
    """A mount and a plain Starlette route carry no dependencies, so the refusal never runs on them.
    The rule is that ``/ui/static`` is the only mount, and the docs are the only plain routes."""
    outside = [
        (type(r).__name__, getattr(r, "path", None))
        for r in full_app.routes
        if not isinstance(r, (APIRoute, APIWebSocketRoute))
    ]
    assert sorted(outside) == [
        ("Mount", "/ui/static"),
        ("Route", "/docs"),
        ("Route", "/docs/oauth2-redirect"),
        ("Route", "/openapi.json"),
        ("Route", "/redoc"),
    ]
    # With no flag on there is no docs route and no mount at all.
    assert all(isinstance(r, (APIRoute, APIWebSocketRoute)) for r in create_app().routes)


def test_no_create_app_flag_registers_a_route_the_full_surface_app_lacks(full_app: FastAPI) -> None:
    """``full_surface_app`` turns on every flag in ``ROUTE_REGISTERING_FLAGS``. Flipping any other
    boolean ``create_app`` takes must add no route, or the walk would never see it."""
    full = _route_keys(full_app)
    flipped = 0
    for name, param in inspect.signature(create_app).parameters.items():
        if not isinstance(param.default, bool) or name in route_gates.ROUTE_REGISTERING_FLAGS:
            continue
        flipped_app = route_gates.full_surface_app(**{name: not param.default})
        extra = _route_keys(flipped_app) - full
        assert not extra, f"create_app({name}={not param.default}) registers {sorted(extra)}"
        flipped += 1
    assert flipped >= 5, f"only {flipped} boolean flags were flipped; the signature read went wrong"


@pytest.fixture
async def engine(tmp_path: Path) -> AsyncIterator[Engine]:
    eng = await Engine.create(tmp_path / "deny.db", poll_interval=0.05)
    yield eng
    await eng.stop()


async def _answers(app: FastAPI) -> dict[tuple[str, str], tuple[int, str]]:
    """``(status, body)`` an anonymous caller gets from every HTTP row of ``app``."""
    answers: dict[tuple[str, str], tuple[int, str]] = {}
    rows = [r for r in route_gates.route_rows(app) if r.method != route_gates.WS_METHOD]
    transport = httpx.ASGITransport(app=app, raise_app_exceptions=False)
    async with httpx.AsyncClient(transport=transport, base_url="http://127.0.0.1") as client:
        for row in rows:
            if row.method == route_gates.MOUNT_METHOD:
                method, path = "GET", f"{row.path}/app.css"
            else:
                method, path = row.method, route_gates.concrete_path(row.path)
            response = await client.request(method, path)
            answers[(row.method, row.path)] = (response.status_code, response.text)
    return answers


async def test_every_shipped_route_answers_an_anonymous_caller_as_it_did_before(
    engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The same app, built with and without the refusal, gives every anonymous request the same
    answer. Gated routes answer with their gate, and public ones, the /ui sign-in pages and
    /ui/static among them, stay public."""
    service = AuthService(engine.store, AuthSettings())
    await service.initialize()
    after = await _answers(route_gates.full_surface_app(engine=engine, auth=service))
    _without_refusal(monkeypatch)
    before = await _answers(route_gates.full_surface_app(engine=engine, auth=service))

    assert len(after) > 200
    assert after.keys() == before.keys()
    changed = {key: (before[key][0], after[key][0]) for key in after if after[key] != before[key]}
    assert not changed, f"the refusal changed these answers (before, after): {changed}"
    assert not [k for k, (_s, body) in after.items() if UNDECLARED_ROUTE_DETAIL in body]
    # Spot checks, so "nothing changed" cannot pass on an app where nothing answers.
    assert after[("GET", "/health")][0] == 200
    assert after[("GET", "/ui/login")][0] == 200
    assert after[("MOUNT", "/ui/static")][0] == 200
    assert after[("GET", "/messages")][0] == 401
    assert after[("GET", "/ui/messages")][0] in (303, 401)


@pytest.mark.parametrize("allow_no_auth", [False, True])
def test_the_stats_websocket_answers_as_it_did_before(
    allow_no_auth: bool, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Refused with no session and no ``allow_no_auth``; streaming on the embedding path. The
    managed app runs its lifespan under the test client, so the feed has an engine to read."""

    def streams(name: str) -> bool:
        app = create_managed_app(
            db_path=tmp_path / name, poll_interval=0.05, allow_no_auth=allow_no_auth, serve_ui=True
        )
        with TestClient(app) as client:
            try:
                with client.websocket_connect("/ws/stats") as socket:
                    return "outbox_by_status" in socket.receive_json()
            except WebSocketDisconnect:
                return False

    after = streams("after.db")
    _without_refusal(monkeypatch)
    before = streams("before.db")
    assert after == before == allow_no_auth


# --- synthetic routes the refusal must catch ---------------------------------------------------------


def require_nothing(*permissions: Permission) -> Any:
    """Named like a gate and capturing its permissions, but enforcing nothing and carrying no mark."""

    async def dependency(request: Request) -> None:
        assert permissions is not None

    return dependency


class _Body(BaseModel):
    value: int


def _planted_app(**kwargs: Any) -> FastAPI:
    app = create_app(**kwargs)

    @app.get("/zz/undeclared")
    async def undeclared() -> dict[str, str]:
        return {"ok": "reached"}

    @app.get("/zz/named-like-a-gate")
    async def named_like_a_gate(
        _u: None = Depends(require_nothing(Permission.MESSAGES_VIEW_RAW)),
    ) -> dict[str, str]:
        return {"ok": "reached"}

    async def wrapper(identity: object = Depends(require(Permission.MONITORING_READ))) -> object:
        return identity

    @app.get("/zz/gate-only-nested")
    async def gate_only_nested(_u: object = Depends(wrapper)) -> dict[str, str]:
        return {"ok": "reached"}

    @app.get("/zz/declared-public")
    @public_route("a synthetic public route")
    async def declared_public() -> dict[str, str]:
        return {"ok": "reached"}

    @app.get("/zz/in-body-on-http")
    @authorizes_in_body("only a WebSocket may say this")
    async def in_body_on_http() -> dict[str, str]:
        return {"ok": "reached"}

    @app.post("/zz/undeclared-with-body")
    async def undeclared_with_body(body: _Body) -> dict[str, str]:
        return {"ok": "reached"}

    sub = APIRouter()

    @sub.get("/zz/included")
    async def included() -> dict[str, str]:
        return {"ok": "reached"}

    app.include_router(sub)

    gated_only_by_include = APIRouter()

    @gated_only_by_include.get("/zz/gated-by-include")
    async def gated_by_include() -> dict[str, str]:
        return {"ok": "reached"}

    app.include_router(
        gated_only_by_include, dependencies=[Depends(require(Permission.MONITORING_READ))]
    )
    return app


@pytest.fixture(scope="module", params=[False, True], ids=["auth-required", "allow-no-auth"])
def planted_app(request: pytest.FixtureRequest) -> FastAPI:
    return _planted_app(allow_no_auth=request.param)


@pytest.mark.parametrize(
    "path",
    [
        "/zz/undeclared",
        "/zz/named-like-a-gate",
        "/zz/gate-only-nested",
        "/zz/in-body-on-http",
        "/zz/included",
        "/zz/gated-by-include",
    ],
)
async def test_a_route_that_declares_no_authorization_is_refused(
    path: str, planted_app: FastAPI
) -> None:
    """Refused even on the embedding path, where every real gate admits the caller. A gate that
    only an include call adds is not the route's own, so that route is refused too, and the walk
    reads it as no gate."""
    walked = {(r.method, r.path): r for r in route_gates.route_rows(planted_app)}
    assert walked[("GET", path)].gate is None, "the walk and the refusal disagree about this route"
    transport = httpx.ASGITransport(app=planted_app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as client:
        response = await client.get(path)
    assert response.status_code == 403, response.text
    assert response.json() == {"detail": UNDECLARED_ROUTE_DETAIL}


@pytest.mark.parametrize("content", [b"{not json", b'{"value": 1}', b""])
async def test_an_undeclared_route_with_a_body_is_refused_before_the_body_is_read(
    content: bytes, planted_app: FastAPI
) -> None:
    """A malformed body gets the same refusal as a good one, so the parser never answers first."""
    transport = httpx.ASGITransport(app=planted_app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as client:
        response = await client.post(
            "/zz/undeclared-with-body",
            content=content,
            headers={"Content-Type": "application/json"},
        )
    assert response.status_code == 403, response.text
    assert response.json() == {"detail": UNDECLARED_ROUTE_DETAIL}


async def test_a_declared_public_route_is_served(planted_app: FastAPI) -> None:
    transport = httpx.ASGITransport(app=planted_app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as client:
        response = await client.get("/zz/declared-public")
    assert response.status_code == 200 and response.json() == {"ok": "reached"}


def test_a_websocket_that_declares_nothing_is_refused_and_one_that_declares_is_served() -> None:
    app = create_app(allow_no_auth=True)

    @app.websocket("/zz/ws-undeclared")
    async def ws_undeclared(websocket: WebSocket) -> None:
        await websocket.accept()
        await websocket.close()

    @app.websocket("/zz/ws-declared")
    @authorizes_in_body("a synthetic socket")
    async def ws_declared(websocket: WebSocket) -> None:
        await websocket.accept()
        await websocket.close()

    with TestClient(app) as client:
        with (
            pytest.raises(WebSocketDisconnect) as refused,
            client.websocket_connect("/zz/ws-undeclared"),
        ):
            pass
        # The refusal comes before accept, so a server that supports it answers the handshake with
        # an HTTP 403; one that does not closes with policy violation.
        refusal = refused.value
        assert getattr(refusal, "status_code", None) == 403 or refusal.code == 1008, refusal
        with client.websocket_connect("/zz/ws-declared"):
            pass


def test_a_declaration_needs_a_reason() -> None:
    with pytest.raises(ValueError, match="reason"):
        public_route("  ")
    with pytest.raises(ValueError, match="reason"):
        authorizes_in_body("")
