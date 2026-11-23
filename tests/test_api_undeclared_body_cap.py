# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The request body limit counts every HTTP request body (BACKLOG #5345); the reason is on
``_run_counting_body`` in ``messagefoundry/api/app.py``.

The scopes are hand-built because a body past the cap cannot reach a route under ``serve``. The probe
routes are inserted ahead of the app's own so each test reads what actually reached a route.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from types import SimpleNamespace
from typing import Any

import pytest
from starlette.requests import ClientDisconnect, Request
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


async def _drive(
    app: Any,
    chunks: list[bytes],
    *,
    path: str = "/probe",
    method: str = "POST",
    http_version: str = "1.1",
    ends_early: bool = False,
    headers: tuple[tuple[bytes, bytes], ...] = (),
    send_fails: bool = False,
    query_string: bytes = b"",
) -> _Run:
    """Send ``chunks`` as a body, one ``receive`` each, with neither framing header by default.

    ``ends_early`` is a client that goes away with the body unfinished. ``headers`` adds request
    headers. ``send_fails`` is a client gone by the time a response starts. ``query_string`` is
    the raw query, which an ASGI host passes through undecoded."""
    scope: Scope = {
        "type": "http",
        "asgi": {"version": "3.0", "spec_version": "2.3"},
        "http_version": http_version,
        "method": method,
        "scheme": "http",
        "path": path,
        "raw_path": path.encode(),
        "query_string": query_string,
        "root_path": "",
        "headers": [
            (b"host", _DNS_HOST.encode()),
            (b"content-type", b"application/json"),
            *headers,
        ],
        "client": ("127.0.0.1", 50000),
        "server": ("127.0.0.1", 8765),
    }
    run = _Run()
    pending = list(chunks) or [b""]

    async def receive() -> Message:
        await asyncio.sleep(0)  # a real server's receive yields, so concurrent readers interleave
        if not pending:
            return {"type": "http.disconnect"}
        run.pulled += 1
        body = pending.pop(0)
        return {"type": "http.request", "body": body, "more_body": bool(pending) or ends_early}

    async def send(message: Message) -> None:
        if send_fails:
            raise OSError("client gone")
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


@pytest.mark.parametrize(
    "headers", [(), ((b"content-length", b"2"),)], ids=["undeclared", "small-declared-length"]
)
async def test_an_over_cap_body_is_refused_at_the_cap_without_reading_the_rest(
    headers: tuple[tuple[bytes, bytes], ...],
) -> None:
    """A host need not hold a body to its Content-Length, so the count does not trust the header."""
    app, reads = _app_with_probe()
    run = await _drive(app, _chunks(_CHUNKS_AT_CAP * 4), headers=headers)
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


@pytest.mark.parametrize(
    "headers",
    [(), ((b"content-length", str(_MAX_REQUEST_BODY_BYTES).encode()),)],
    ids=["undeclared", "declared"],
)
async def test_a_body_exactly_at_the_cap_reaches_the_route(
    headers: tuple[tuple[bytes, bytes], ...],
) -> None:
    app, reads = _app_with_probe()
    run = await _drive(app, _chunks(_CHUNKS_AT_CAP), headers=headers)
    assert run.status == 200
    assert not run.closes
    assert reads == [_MAX_REQUEST_BODY_BYTES]


async def test_an_under_cap_body_reaches_the_route_whole() -> None:
    app, reads = _app_with_probe()
    run = await _drive(app, [b"abc", b"", b"defg"])
    assert run.status == 200
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


@pytest.mark.parametrize("declares", [False, True], ids=["undeclared", "declared"])
@pytest.mark.parametrize("path", ["/uploads", "/ui/uploaded-logs/upload"])
async def test_the_upload_routes_keep_their_larger_cap(path: str, declares: bool) -> None:
    upload_cap = _MAX_REQUEST_BODY_BYTES * 2
    app, reads = _app_with_probe(path)
    app.state.upload_store = SimpleNamespace(max_bytes=upload_cap)
    headers = ((b"content-length", str(upload_cap).encode()),) if declares else ()

    admitted = await _drive(app, _chunks(_CHUNKS_AT_CAP * 2), path=path, headers=headers)
    assert admitted.status == 200
    assert reads == [upload_cap]

    refused = await _drive(app, _chunks(_CHUNKS_AT_CAP * 2 + 1), path=path, headers=headers)
    assert refused.status == 413
    assert refused.closes
    assert reads == [upload_cap]  # the refused body never reached the route


async def test_the_larger_cap_is_only_the_upload_routes() -> None:
    app, reads = _app_with_probe()
    app.state.upload_store = SimpleNamespace(max_bytes=_MAX_REQUEST_BODY_BYTES * 2)
    run = await _drive(app, _chunks(_CHUNKS_AT_CAP + 1))
    assert run.status == 413
    assert reads == []


@pytest.mark.parametrize("declares", [False, True], ids=["undeclared", "declared"])
@pytest.mark.parametrize(
    "path",
    ["/up\tloads", "/uploads\n", "/ui/uploaded-logs/up\rload"],
    ids=["tab", "lf", "cr"],
)
async def test_a_path_that_only_normalizes_to_an_upload_route_keeps_the_default_cap(
    path: str, declares: bool
) -> None:
    """URL parsing drops a decoded TAB, CR or LF, so the cap must read the scope's path."""
    body_size = _MAX_REQUEST_BODY_BYTES * 2
    app, reads = _app_with_probe(path)
    app.state.upload_store = SimpleNamespace(max_bytes=body_size)
    headers = ((b"content-length", str(body_size).encode()),) if declares else ()
    run = await _drive(app, _chunks(_CHUNKS_AT_CAP * 2), path=path, headers=headers)
    assert run.status == 413
    assert reads == []


@pytest.mark.parametrize(
    ("chunk_count", "headers"),
    [
        (_CHUNKS_AT_CAP + 1, ()),
        (1, ((b"content-length", str(_MAX_REQUEST_BODY_BYTES + 1).encode()),)),
    ],
    ids=["counted", "declared"],
)
async def test_a_non_utf8_query_string_does_not_stop_the_413(
    chunk_count: int,
    headers: tuple[tuple[bytes, bytes], ...],
    caplog: pytest.LogCaptureFixture,
) -> None:
    """The refusal reads the path from the scope: ``request.url`` would decode this query and raise."""
    app, reads = _app_with_probe()
    with caplog.at_level(logging.WARNING, logger="messagefoundry.api.app"):
        run = await _drive(app, _chunks(chunk_count), headers=headers, query_string=b"a=\xff")
    assert run.status == 413
    assert reads == []
    assert any(
        "rejected oversized request body on /probe" in r.getMessage() for r in caplog.records
    )


async def test_a_refusal_is_logged(caplog: pytest.LogCaptureFixture) -> None:
    app, _ = _app_with_probe()
    with caplog.at_level(logging.WARNING, logger="messagefoundry.api.app"):
        await _drive(app, [b"x" * (_MAX_REQUEST_BODY_BYTES + 1)])
    assert any("oversized request body" in r.getMessage() for r in caplog.records)


async def test_two_concurrent_reads_past_the_cap_send_one_refusal() -> None:
    app = create_app(allow_no_auth=True)

    class _ReadsTwice:
        async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
            await asyncio.gather(receive(), receive())

    app.router.routes.insert(0, Route("/probe", _ReadsTwice()))
    over_cap = b"x" * (_MAX_REQUEST_BODY_BYTES + 1)
    run = await _drive(app, [over_cap, over_cap])
    assert run.status == 413  # the property asserts exactly one response start


async def test_a_real_disconnect_under_the_cap_is_not_absorbed() -> None:
    app, reads = _app_with_probe()
    with pytest.raises(ClientDisconnect):
        await _drive(app, [b"abc"], ends_early=True)
    assert reads == []


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


@pytest.mark.parametrize("scope_type", ["websocket", "lifespan"])
async def test_a_non_http_scope_keeps_its_own_channels(scope_type: str) -> None:
    """The counter wraps only an HTTP request's ``receive`` and ``send``."""
    calls: list[tuple[Receive, Send]] = []

    async def inner(scope: Scope, receive: Receive, send: Send) -> None:
        calls.append((receive, send))

    async def receive() -> Message:
        raise AssertionError("the body limit must not read a non-HTTP scope")

    async def send(message: Message) -> None:
        raise AssertionError("the body limit must not answer a non-HTTP scope")

    limit = next(
        m.cls
        for m in create_app(allow_no_auth=True).user_middleware
        if getattr(m.cls, "__name__", "") == "_limit_request_body"
    )
    await limit(inner)({"type": scope_type}, receive, send)  # type: ignore[call-arg]
    assert calls == [(receive, send)]


async def test_a_read_past_the_cap_after_the_response_started_ends_quietly(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """The route's ClientDisconnect is this refusal's, and the log must not claim a sent 413."""
    app = create_app(allow_no_auth=True)

    class _StartsThenReadsBody:
        async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
            await send({"type": "http.response.start", "status": 200, "headers": []})
            await Request(scope, receive).body()
            await send({"type": "http.response.body", "body": b"never sent"})

    app.router.routes.insert(0, Route("/probe", _StartsThenReadsBody()))
    with caplog.at_level(logging.WARNING, logger="messagefoundry.api.app"):
        run = await _drive(app, _chunks(_CHUNKS_AT_CAP * 4))
    assert run.status == 200
    # The app leaves it unfinished; ending it is the host's.
    assert not [m for m in run.sent if m["type"] == "http.response.body"]
    messages = [r.getMessage() for r in caplog.records]
    assert any("no 413 was sent" in m for m in messages)
    assert not any(m.startswith("rejected oversized request body") for m in messages)


async def test_a_message_that_is_not_a_response_start_does_not_forfeit_the_413() -> None:
    app = create_app(allow_no_auth=True)

    class _SendsDebugThenReads:
        async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
            await send({"type": "http.response.debug", "info": {}})
            await Request(scope, receive).body()

    app.router.routes.insert(0, Route("/probe", _SendsDebugThenReads()))
    run = await _drive(app, [b"x" * (_MAX_REQUEST_BODY_BYTES + 1)])
    assert run.status == 413


async def test_a_413_that_cannot_be_sent_does_not_escape_into_the_routes_read(
    caplog: pytest.LogCaptureFixture,
) -> None:
    app, reads = _app_with_probe()
    with caplog.at_level(logging.WARNING, logger="messagefoundry.api.app"):
        run = await _drive(app, [b"x" * (_MAX_REQUEST_BODY_BYTES + 1)], send_fails=True)
    assert run.sent == []
    assert reads == []
    assert any("could not send the 413" in r.getMessage() for r in caplog.records)


@pytest.mark.parametrize("http_version", ["2", "3"])
@pytest.mark.parametrize(
    ("headers", "status"),
    [
        ((), 413),
        (((b"content-length", b"1"), (b"content-length", b"2")), 400),
        (((b"transfer-encoding", b"chunked"),), 411),
        (((b"content-length", str(_MAX_REQUEST_BODY_BYTES + 1).encode()),), 413),
    ],
    ids=["counted-413", "declared-400", "declared-411", "declared-413"],
)
async def test_a_refusal_over_http_2_or_3_carries_no_connection_field(
    http_version: str, headers: tuple[tuple[bytes, bytes], ...], status: int
) -> None:
    """RFC 9113 8.2.2 and RFC 9114 4.2: a response with this field is malformed there."""
    app, reads = _app_with_probe()
    over_cap = b"x" * (_MAX_REQUEST_BODY_BYTES + 1)
    run = await _drive(app, [over_cap], http_version=http_version, headers=headers)
    assert run.status == status
    assert all(name != b"connection" for name, _ in run.starts[0]["headers"])
    assert reads == []
