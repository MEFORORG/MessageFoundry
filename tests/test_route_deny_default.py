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

import contextlib
import inspect
import logging
from collections.abc import AsyncIterator, Mapping
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
import messagefoundry.api.security as security_module
from messagefoundry.api.app import create_app, create_managed_app
from messagefoundry.api.security import (
    UNDECLARED_ROUTE_DETAIL,
    authorizes_in_body,
    public_route,
    require,
    route_is_declared,
    undeclared_route_refusals,
)
from messagefoundry.auth.permissions import Permission
from messagefoundry.auth.service import AuthService
from messagefoundry.config.settings import (
    AiSettings,
    AlertsSettings,
    ApprovalsSettings,
    AuthSettings,
    EgressSettings,
    SecuritySettings,
    ServiceStatusSettings,
    StoreSettings,
)
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
    for name, param in inspect.signature(route_gates.create_app).parameters.items():
        if not isinstance(param.default, bool) or name in route_gates.ROUTE_REGISTERING_FLAGS:
            continue
        flipped_app = route_gates.full_surface_app(**{name: not param.default})
        extra = _route_keys(flipped_app) - full
        assert not extra, f"create_app({name}={not param.default}) registers {sorted(extra)}"
        flipped += 1
    assert flipped >= 5, f"only {flipped} boolean flags were flipped; the signature read went wrong"


# Vault BACKLOG #2846: the test above flips only a parameter whose default is a bool, so a parameter
# defaulting to None, a string or a tuple was never tried. Each such parameter is listed here with
# the values to try in its place. A new one fails the signature pin below until it is listed, which is
# the point at which someone decides whether it registers a route.


@contextlib.asynccontextmanager
async def _noop_lifespan(app: FastAPI) -> AsyncIterator[None]:
    yield


#: Every non-bool ``create_app`` parameter, and the non-default values to build the full-surface app
#: with. ``engine`` and ``auth`` need a live store, so the async test below covers them.
_NON_BOOL_VALUES: dict[str, tuple[Any, ...]] = {
    "lifespan": (_noop_lifespan,),
    "ai_settings": (AiSettings(),),
    "store_settings": (StoreSettings(),),
    "security_settings": (SecuritySettings(),),
    "approvals": (ApprovalsSettings(),),
    "alerts_settings": (AlertsSettings(),),
    "service_settings": (ServiceStatusSettings(),),
    "ws_allowed_origins": (("https://console.example.test",),),
    "public_origin": ("https://console.example.test",),
    "oidc_authorization_endpoint": ("https://idp.example.test/authorize",),
    "webauthn_rp_from_request": (True, False),
    "tls_client_cert_identities": ({"CN=Example Issuer": {"CN=svc.example.test": "svc"}},),
    "trusted_proxies": (("10.0.0.1",),),
    "log_dir": ("synthetic-log-dir",),
    "configured_log_level": ("INFO",),
}
_NON_BOOL_BUILT_BY_FIXTURE = frozenset({"engine", "auth"})


def _unlisted_non_bool_parameters() -> set[str]:
    signature = inspect.signature(route_gates.create_app)
    non_bool = {n for n, p in signature.parameters.items() if not isinstance(p.default, bool)}
    return non_bool - _NON_BOOL_VALUES.keys() - _NON_BOOL_BUILT_BY_FIXTURE


def _routes_added_by(
    tries: Mapping[str, tuple[Any, ...]], full: set[tuple[str, str]]
) -> dict[str, list[tuple[str, str]]]:
    """The routes each listed value adds to the full-surface app, keyed ``name=value``."""
    added: dict[str, list[tuple[str, str]]] = {}
    for name, values in tries.items():
        for value in values:
            extra = _route_keys(route_gates.full_surface_app(**{name: value})) - full
            if extra:
                added[f"{name}={value!r}"] = sorted(extra)
    return added


def test_every_non_bool_create_app_parameter_is_listed() -> None:
    unlisted = _unlisted_non_bool_parameters()
    assert not unlisted, (
        f"create_app gained non-bool parameter(s) {sorted(unlisted)}. List each in _NON_BOOL_VALUES "
        "with a value to try, so the test below checks whether it registers a route."
    )
    signature = inspect.signature(route_gates.create_app)
    stale = (_NON_BOOL_VALUES.keys() | _NON_BOOL_BUILT_BY_FIXTURE) - signature.parameters.keys()
    assert not stale, f"listed but no longer a create_app parameter: {sorted(stale)}"


def test_no_non_bool_create_app_parameter_registers_a_route_the_full_surface_app_lacks(
    full_app: FastAPI,
) -> None:
    added = _routes_added_by(_NON_BOOL_VALUES, _route_keys(full_app))
    assert not added, f"these create_app values register routes the walk never sees: {added}"


def _create_app_with(new_parameter: inspect.Parameter) -> Any:
    """``create_app`` with one more keyword parameter, which registers ``/zz/new`` when set."""
    real = route_gates.create_app

    def planted(*args: Any, **kwargs: Any) -> FastAPI:
        value = kwargs.pop(new_parameter.name, new_parameter.default)
        app = real(*args, **kwargs)
        if value != new_parameter.default:

            @app.get("/zz/new")
            @public_route("a synthetic route a new parameter registers")
            async def new() -> dict[str, str]:
                return {"ok": "reached"}

        return app

    signature = inspect.signature(real)
    planted.__signature__ = signature.replace(  # type: ignore[attr-defined]
        parameters=[*signature.parameters.values(), new_parameter]
    )
    return planted


def test_a_new_non_bool_parameter_fails_the_pin_and_one_that_registers_a_route_is_caught(
    full_app: FastAPI, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The control for the two tests above: each one bites on a parameter planted to break it."""
    parameter = inspect.Parameter(
        "extra_routes_from", inspect.Parameter.KEYWORD_ONLY, default=None, annotation="str | None"
    )
    monkeypatch.setattr(route_gates, "create_app", _create_app_with(parameter))
    assert _unlisted_non_bool_parameters() == {"extra_routes_from"}
    added = _routes_added_by({"extra_routes_from": ("synthetic",)}, _route_keys(full_app))
    assert added == {"extra_routes_from='synthetic'": [("GET", "/zz/new")]}, added


async def test_the_engine_and_auth_arguments_register_no_route_the_full_surface_app_lacks(
    engine: Engine, full_app: FastAPI
) -> None:
    service = AuthService(engine.store, AuthSettings())
    await service.initialize()
    built = route_gates.full_surface_app(engine=engine, auth=service)
    assert not _route_keys(built) - _route_keys(full_app)


@pytest.fixture
async def engine(tmp_path: Path) -> AsyncIterator[Engine]:
    eng = await Engine.create(
        tmp_path / "deny.db", poll_interval=0.05, egress_settings=EgressSettings()
    )
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
            db_path=tmp_path / name,
            poll_interval=0.05,
            allow_no_auth=allow_no_auth,
            serve_ui=True,
            egress_settings=EgressSettings(),
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


async def test_every_refusal_is_counted_and_the_log_is_throttled_not_silenced(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """Vault BACKLOG #2846. The refusal used to log only the first time it worked a route out, so
    every later refusal of that route wrote nothing. Now each one is counted, and a line is written
    at most once per interval, carrying how many refusals it stands for. The line names the route
    template and never the request, so a query string a caller sent does not reach the log."""
    app = _planted_app()
    route = next(r for r in app.routes if getattr(r, "path", None) == "/zz/undeclared")
    refusals = "messagefoundry.api.security"
    monkeypatch.setattr(security_module, "REFUSAL_LOG_INTERVAL_SECONDS", 3600.0)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as client:
        with caplog.at_level(logging.ERROR, logger=refusals):
            for _ in range(3):
                assert (await client.get("/zz/undeclared?mrn=SECRET-MRN")).status_code == 403
        throttled = [r.getMessage() for r in caplog.records if r.name == refusals]
        assert undeclared_route_refusals(route) == 3
        assert len(throttled) == 1, throttled
        assert "(1 refusals since the last log line, 1 in all)" in throttled[0]

        caplog.clear()
        monkeypatch.setattr(security_module, "REFUSAL_LOG_INTERVAL_SECONDS", 0.0)
        with caplog.at_level(logging.ERROR, logger=refusals):
            assert (await client.get("/zz/undeclared?mrn=SECRET-MRN")).status_code == 403
        (line,) = [r.getMessage() for r in caplog.records if r.name == refusals]
    assert undeclared_route_refusals(route) == 4
    assert line.startswith("refused route /zz/undeclared:"), line
    assert "(3 refusals since the last log line, 4 in all)" in line, line
    assert "mrn" not in "".join(throttled + [line])


def test_a_declaration_needs_a_reason() -> None:
    with pytest.raises(ValueError, match="reason"):
        public_route("  ")
    with pytest.raises(ValueError, match="reason"):
        authorizes_in_body("")
