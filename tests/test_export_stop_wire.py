# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A stopped export, measured ON THE WIRE through a real uvicorn (BACKLOG #3907).

A running bulk message export or audit export that its re-check stops raises
:class:`~messagefoundry.api.security.ExportStopped` after the 200 has started (BACKLOG #1154,
#3381). The raise is meant to reach the client as a failed transfer. While the engine's
security-header and body-limit layers were Starlette ``BaseHTTPMiddleware``, it did not: that class
sends the final body message before it re-raises, so the client got a cleanly ended 200 holding
the rows streamed before the stop, a short file that looked complete.

In-process ``httpx.ASGITransport`` tests cannot see this, since they read ASGI messages, not what
the server writes. So this suite serves the app with uvicorn on a loopback socket, under both HTTP
parsers the lock ships (h11 and httptools), and reads the download as a client does.

**Every stop is paired with a control in the same parser.** The same export with nothing withdrawn
must read to a clean end, so a probe that failed every download cannot pass. A structural guard
beside them refuses any ``BaseHTTPMiddleware`` in the app's stack, console mounted, so the property
does not rest on a reviewer noticing a new ``@app.middleware("http")``.
"""

from __future__ import annotations

import json
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

import httpx
import pytest
from fastapi import FastAPI
from starlette.middleware.base import BaseHTTPMiddleware

from messagefoundry.api import create_app
from messagefoundry.auth import Role
from messagefoundry.auth.service import AuthService
from messagefoundry.config.settings import EgressSettings
from messagefoundry.pipeline import Engine
from messagefoundry.store.crypto import generate_key, make_cipher
from messagefoundry.store.store import MessageStore
from tests._bound_proof import ReprovingTransport
from tests.test_header_floor_wire import _served
from tests.test_message_export import PW, _add_user, _seed, _service

_PARSERS = [pytest.param("h11", id="h11"), pytest.param("httptools", id="httptools")]

Act = Callable[[AuthService, str], Awaitable[None]]
#: What a probe returns: the status, the data rows, the transport error that ended the read (if
#: one did), and the export's stop audit rows.
Outcome = tuple[int, list[str], Exception | None, list[dict[str, object]]]


@pytest.fixture
async def engine(tmp_path: Path) -> AsyncIterator[Engine]:
    store = await MessageStore.open(tmp_path / "wire.db", cipher=make_cipher(generate_key()))
    eng = Engine(store, egress_settings=EgressSettings(deny_by_default=False))
    yield eng
    await eng.stop()


@asynccontextmanager
async def _client(app: FastAPI, http: str) -> AsyncIterator[httpx.AsyncClient]:
    """A client for ``app`` served by uvicorn's ``http`` parser, answering an action-bound step-up
    the way the console does."""
    async with _served(app, http=http) as port:
        transport = ReprovingTransport(httpx.AsyncHTTPTransport(), PW)
        async with httpx.AsyncClient(
            transport=transport, base_url=f"http://127.0.0.1:{port}", timeout=30.0
        ) as client:
            yield client


async def _revoke(service: AuthService, uid: str) -> None:
    await service.revoke_sessions_for_user(uid, actor="admin")


async def _nothing(_service: AuthService, _uid: str) -> None:
    return None


async def _probe(
    engine: Engine,
    monkeypatch: pytest.MonkeyPatch,
    http: str,
    *,
    username: str,
    role: Role,
    read: str,
    fire: Callable[[dict[str, Any]], bool],
    act: Act,
    url: str,
    params: dict[str, Any],
    stopped: str,
) -> tuple[int, str, Exception | None, list[dict[str, object]]]:
    """Run one export over the wire, running ``act`` once, right after the first store ``read``
    call whose keywords ``fire`` accepts. Returns the status, the body text, the transport error
    that ended the read (if one did), and the ``stopped`` audit rows."""
    service = await _service(engine)
    uid = await _add_user(service, username, [role.value])
    real = getattr(engine.store, read)
    fired = False

    async def wrapped(*args: Any, **kw: Any) -> Any:
        nonlocal fired
        result = await real(*args, **kw)
        if not fired and fire(kw):
            fired = True
            await act(service, uid)
        return result

    async with _client(create_app(engine, auth=service, serve_ui=True), http) as c:
        r = await c.post(
            "/auth/login", json={"username": username, "password": PW, "provider": "local"}
        )
        assert r.status_code == 200, r.text
        monkeypatch.setattr(engine.store, read, wrapped)
        body, error = b"", None
        headers = {"Authorization": f"Bearer {r.json()['token']}"}
        async with c.stream("GET", url, headers=headers, params=params) as resp:
            try:
                async for chunk in resp.aiter_raw():
                    body += chunk
            except httpx.TransportError as exc:
                error = exc
        monkeypatch.setattr(engine.store, read, real)
    stops = [json.loads(a["detail"]) for a in await engine.store.list_audit(action=stopped)]
    return resp.status_code, body.decode(), error, stops


async def _bulk_export(
    engine: Engine, monkeypatch: pytest.MonkeyPatch, http: str, act: Act
) -> Outcome:
    """Export two messages by id, running ``act`` right after the stream reads the first."""
    mid_a, mid_b = await _seed(engine)
    status, text, error, stops = await _probe(
        engine,
        monkeypatch,
        http,
        username="op",
        role=Role.OPERATOR,
        read="get_message",
        fire=lambda _kw: True,
        act=act,
        url="/messages/export",
        params={"ids": [mid_a, mid_b]},
        stopped="messages_export.stopped",
    )
    ids = [str(json.loads(line)["id"]) for line in text.splitlines() if line.strip()]
    assert ids == [mid_a, mid_b][: len(ids)]
    return status, ids, error, stops


async def _audit_export(
    engine: Engine, monkeypatch: pytest.MonkeyPatch, http: str, act: Act
) -> Outcome:
    """Export seven audit rows at a page of two, running ``act`` right after the second page is
    read: the first page has been sent, the second not yet."""
    from messagefoundry.api import auth_routes

    monkeypatch.setattr(auth_routes, "_AUDIT_EXPORT_PAGE", 2)
    for i in range(7):
        await engine.store.record_audit("message_view", actor="alice", detail="{}", now=100.0 + i)
    status, text, error, stops = await _probe(
        engine,
        monkeypatch,
        http,
        username="exporter",
        role=Role.AUDITOR,
        read="list_audit",
        fire=lambda kw: kw.get("before_id") is not None,
        act=act,
        url="/audit/export",
        params={"format": "csv", "actor": "alice"},
        stopped="audit.export.stopped",
    )
    lines = [ln for ln in text.splitlines() if ln]
    assert lines[0] == "ts,actor,action,channel_id,client,detail"
    return status, lines[1:], error, stops


@pytest.mark.parametrize("http", _PARSERS)
async def test_a_stopped_bulk_export_ends_as_a_failed_transfer(
    engine: Engine, monkeypatch: pytest.MonkeyPatch, http: str
) -> None:
    """A revoke after row one stops the export. The client must see the transfer FAIL after row
    one, not a cleanly ended 200 that reads as a complete one-row file."""
    status, ids, error, stops = await _bulk_export(engine, monkeypatch, http, _revoke)
    assert status == 200  # the response had started before the stop
    assert len(ids) == 1
    assert stops == [{"selected": 2, "streamed": 1, "reason": "standing_changed"}]
    # RemoteProtocolError on an incomplete chunked body; ReadError if the close lands as a reset.
    assert isinstance(error, httpx.TransportError), "the download ended cleanly"


@pytest.mark.parametrize("http", _PARSERS)
async def test_an_unstopped_bulk_export_ends_cleanly(
    engine: Engine, monkeypatch: pytest.MonkeyPatch, http: str
) -> None:
    """The control: the same probe with nothing withdrawn reads both rows to a clean end."""
    status, ids, error, stops = await _bulk_export(engine, monkeypatch, http, _nothing)
    assert (status, len(ids), error, stops) == (200, 2, None, [])


@pytest.mark.parametrize("http", _PARSERS)
async def test_a_stopped_audit_export_ends_as_a_failed_transfer(
    engine: Engine, monkeypatch: pytest.MonkeyPatch, http: str
) -> None:
    """A revoke after page one is sent stops the audit export before page two. The client must see
    the transfer FAIL, not a cleanly ended 200 holding two of seven rows."""
    status, rows, error, stops = await _audit_export(engine, monkeypatch, http, _revoke)
    assert status == 200
    assert [float(ln.split(",")[0]) for ln in rows] == [106.0, 105.0]
    assert stops == [{"count": 7, "streamed": 2, "reason": "standing_changed"}]
    # RemoteProtocolError on an incomplete chunked body; ReadError if the close lands as a reset.
    assert isinstance(error, httpx.TransportError), "the download ended cleanly"


@pytest.mark.parametrize("http", _PARSERS)
async def test_an_unstopped_audit_export_ends_cleanly(
    engine: Engine, monkeypatch: pytest.MonkeyPatch, http: str
) -> None:
    """The control: the same probe with nothing withdrawn reads all seven rows to a clean end."""
    status, rows, error, stops = await _audit_export(engine, monkeypatch, http, _nothing)
    assert (status, len(rows), error, stops) == (200, 7, None, [])


def test_no_layer_in_the_app_is_a_base_http_middleware() -> None:
    """The wire tests hold only while every middleware in the response path is pure ASGI: one
    ``BaseHTTPMiddleware`` anywhere, the web console's included, turns a stop back into a clean
    short file. So refuse one structurally, over the BUILT stack ``serve_ui`` makes, so a factory
    that returns one is seen as well as a class. The walk follows each layer's ``app``, or a
    factory closure's ``inner``, down to the router; the mounted ``/ui`` sub-app is not walked.
    The control: an ``@app.middleware("http")`` added to the same app is found."""

    def layers(app: FastAPI) -> list[Any]:
        node: Any = app.build_middleware_stack()
        out: list[Any] = []
        while node is not None and len(out) < 100:
            out.append(node)
            nxt = getattr(node, "app", None)
            code = getattr(node, "__code__", None)
            if nxt is None and code is not None and "inner" in code.co_freevars:
                nxt = node.__closure__[code.co_freevars.index("inner")].cell_contents
            node = nxt
        return out

    def is_base(app: FastAPI) -> bool:
        return any(isinstance(layer, BaseHTTPMiddleware) for layer in layers(app))

    app = create_app(serve_ui=True)
    walked = [type(layer).__name__ for layer in layers(app)]
    # Non-vacuity: the walk got past the engine's own factories to the innermost Starlette layer.
    assert "ExceptionMiddleware" in walked, walked
    assert not is_base(app), walked

    @app.middleware("http")
    async def _probe_layer(request: Any, call_next: Any) -> Any:
        return await call_next(request)

    assert is_base(app)
