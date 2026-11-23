# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The request body limit counts a body with neither framing header (BACKLOG #5345); the reason is
on ``_run_counting_body`` in ``messagefoundry/api/app.py``.

The scopes are hand-built because the shape cannot be sent to ``serve`` on a socket. The probe
routes are inserted ahead of the app's own so each test reads what actually reached a route.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from types import SimpleNamespace
from typing import Any

import pytest
from starlette.requests import Request
from starlette.responses import PlainTextResponse
from starlette.routing import Route
from starlette.types import Message, Receive, Scope, Send

from messagefoundry.api.app import _MAX_REQUEST_BODY_BYTES, create_app
from tests.test_api_security_header_floor import _DNS_HOST

_CHUNK = 64 * 1024
#: Chunks that together hold exactly the default cap.
_CHUNKS_AT_CAP = _MAX_REQUEST_BODY_BYTES // _CHUNK


def _chunks(count: int, fill: bytes = b"x") -> list[bytes]:
    return [fill * _CHUNK] * count


@dataclass
class _Run:
    """What one request did: the responses sent, and how much of the body was pulled."""

    sent: list[Message] = field(default_factory=list)
    pulled: int = 0

    @property
    def starts(self) -> list[Message]:
        return [m for m in self.sent if m["type"] == "http.response.start"]

    @property
    def status(self) -> int:
        assert len(self.starts) == 1, f"expected one response, got {len(self.starts)}"
        status: int = self.starts[0]["status"]
        return status

    @property
    def closes(self) -> bool:
        return (b"connection", b"close") in self.starts[0]["headers"]

    @property
    def text(self) -> str:
        return b"".join(
            m.get("body", b"") for m in self.sent if m["type"] == "http.response.body"
        ).decode()


async def _drive(
    app: Any, chunks: list[bytes], *, path: str = "/probe", method: str = "POST"
) -> _Run:
    """Send ``chunks`` as a body with neither framing header, one ``receive`` each."""
    scope: Scope = {
        "type": "http",
        "asgi": {"version": "3.0", "spec_version": "2.3"},
        "http_version": "2",
        "method": method,
        "scheme": "http",
        "path": path,
        "raw_path": path.encode(),
        "query_string": b"",
        "root_path": "",
        "headers": [(b"host", _DNS_HOST.encode()), (b"content-type", b"application/json")],
        "client": ("127.0.0.1", 50000),
        "server": ("127.0.0.1", 8765),
    }
    run = _Run()
    pending = list(chunks) or [b""]

    async def receive() -> Message:
        if not pending:
            return {"type": "http.disconnect"}
        run.pulled += 1
        body = pending.pop(0)
        return {"type": "http.request", "body": body, "more_body": bool(pending)}

    async def send(message: Message) -> None:
        run.sent.append(message)

    await app(scope, receive, send)
    return run


def _app_with_probe(path: str = "/probe") -> tuple[Any, list[int]]:
    """The real app with a route at ``path`` that reads the whole body and reports its length."""
    app = create_app(allow_no_auth=True)
    reads: list[int] = []

    async def probe(request: Request) -> PlainTextResponse:
        body = await request.body()
        reads.append(len(body))
        return PlainTextResponse(str(len(body)))

    app.router.routes.insert(0, Route(path, probe, methods=["POST", "PUT", "DELETE"]))
    return app, reads


async def test_an_over_cap_body_is_refused_at_the_cap_without_reading_the_rest() -> None:
    app, reads = _app_with_probe()
    run = await _drive(app, _chunks(_CHUNKS_AT_CAP * 4))
    assert run.status == 413
    assert run.closes
    # The chunks that fit, plus the one that crossed: the other three quarters were never pulled.
    assert run.pulled == _CHUNKS_AT_CAP + 1
    assert reads == []  # the route never held a body


async def test_one_byte_past_the_cap_in_a_single_chunk_is_refused() -> None:
    app, reads = _app_with_probe()
    run = await _drive(app, [b"x" * (_MAX_REQUEST_BODY_BYTES + 1)])
    assert run.status == 413
    assert run.closes
    assert reads == []


async def test_a_body_exactly_at_the_cap_reaches_the_route() -> None:
    app, reads = _app_with_probe()
    run = await _drive(app, _chunks(_CHUNKS_AT_CAP))
    assert run.status == 200
    assert not run.closes
    assert reads == [_MAX_REQUEST_BODY_BYTES]


async def test_an_under_cap_body_reaches_the_route_whole() -> None:
    app, reads = _app_with_probe()
    run = await _drive(app, [b"abc", b"", b"defg"])
    assert run.status == 200
    assert run.text == "7"
    assert reads == [7]


@pytest.mark.parametrize("method", ["POST", "PUT", "DELETE"])
async def test_a_bodyless_call_is_admitted(method: str) -> None:
    """Refusing a missing length with 411 would refuse these real calls."""
    app, reads = _app_with_probe()
    run = await _drive(app, [], method=method)
    assert run.status == 200
    assert reads == [0]


async def test_an_over_cap_body_on_a_real_body_route_gets_one_413() -> None:
    """FastAPI turns the disconnect into its own 400, which must not follow the 413."""
    run = await _drive(
        create_app(allow_no_auth=True),
        _chunks(_CHUNKS_AT_CAP + 2, fill=b"{"),
        path="/auth/login",
    )
    assert run.status == 413
    assert run.closes


async def test_an_under_cap_body_on_a_real_body_route_is_read() -> None:
    run = await _drive(create_app(allow_no_auth=True), [b"{"], path="/auth/login")
    assert run.status == 422  # the route's own answer to a body it read and could not decode


@pytest.mark.parametrize("path", ["/uploads", "/ui/uploaded-logs/upload"])
async def test_the_upload_routes_keep_their_larger_cap(path: str) -> None:
    upload_cap = _MAX_REQUEST_BODY_BYTES * 2
    app, reads = _app_with_probe(path)
    app.state.upload_store = SimpleNamespace(max_bytes=upload_cap)

    admitted = await _drive(app, _chunks(_CHUNKS_AT_CAP * 2), path=path)
    assert admitted.status == 200
    assert reads == [upload_cap]

    refused = await _drive(app, _chunks(_CHUNKS_AT_CAP * 2 + 1), path=path)
    assert refused.status == 413
    assert refused.closes
    assert reads == [upload_cap]  # the refused body never reached the route


async def test_the_larger_cap_is_only_the_upload_routes() -> None:
    app, reads = _app_with_probe()
    app.state.upload_store = SimpleNamespace(max_bytes=_MAX_REQUEST_BODY_BYTES * 2)
    run = await _drive(app, _chunks(_CHUNKS_AT_CAP + 1))
    assert run.status == 413
    assert reads == []


async def test_a_refusal_is_logged(caplog: pytest.LogCaptureFixture) -> None:
    app, _ = _app_with_probe()
    with caplog.at_level(logging.WARNING, logger="messagefoundry.api.app"):
        await _drive(app, [b"x" * (_MAX_REQUEST_BODY_BYTES + 1)])
    assert any("oversized request body" in r.getMessage() for r in caplog.records)


async def test_a_response_already_started_is_not_given_a_second_start() -> None:
    """Past its first byte a response cannot become a 413, so the route sees a disconnect."""
    app = create_app(allow_no_auth=True)

    class _StartsThenReads:
        async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
            await send({"type": "http.response.start", "status": 200, "headers": []})
            while (await receive())["type"] != "http.disconnect":
                pass
            await send({"type": "http.response.body", "body": b"done"})

    app.router.routes.insert(0, Route("/probe", _StartsThenReads()))
    run = await _drive(app, _chunks(_CHUNKS_AT_CAP * 4))
    assert run.status == 200
    assert run.pulled == _CHUNKS_AT_CAP + 1  # the disconnect came at the cap, not at the body's end
