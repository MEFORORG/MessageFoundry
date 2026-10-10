# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Request framing on the API plane, measured on a real socket (BACKLOG #1125, ASVS 4.2.1).

Every other framing assertion for the API drives a hand-built ASGI scope, which never reaches a
wire parser. This suite serves the real app through the HTTP protocol class ``serve`` builds (the
pinned llhttp parser, floored), writes raw bytes to a loopback socket, and reads every response.

**Each probe carries a smuggled second request.** A well-framed request leaves that second request
on the connection, and the server answers it. A refused one closes the connection with one ``400``,
so the second request is never answered. Counting the responses is what tells a refusal from a
desync, where the server would answer bytes the sender meant as body.

**The probe is shown to see acceptance.** The well-framed controls get two answers. The same
ambiguous shapes sent through uvicorn's h11 protocol, the one ``http="auto"`` falls back to, are
answered twice where llhttp refuses them. That is the gap the pin closes.

Measured on uvicorn 0.54.0 and httptools 0.8.0; ``tests/test_header_floor_wire.py`` pins uvicorn.
"""

from __future__ import annotations

import asyncio
import re
from collections.abc import AsyncIterator
from pathlib import Path

import pytest
from uvicorn.protocols.http.h11_impl import H11Protocol
from uvicorn.protocols.http.httptools_impl import HttpToolsProtocol

from messagefoundry.api import create_app
from messagefoundry.api.protocol_headers import floored_http_protocol_class
from messagefoundry.config.settings import EgressSettings
from messagefoundry.pipeline import Engine
from tests.test_header_floor_wire import _served

#: The request each probe smuggles behind its first. ``/health`` answers it tokenless with a 200.
_SMUGGLED = b"GET /health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
_POST = b"POST /health HTTP/1.1\r\nHost: localhost\r\n"
#: uvicorn's body for the 400 it writes itself when its parser refuses a request.
_PARSER_400_BODY = b"Invalid HTTP request received."

#: Ambiguous or malformed framing that llhttp refuses before the app runs.
_REFUSED: dict[str, bytes] = {
    "content-length with transfer-encoding": _POST
    + b"Content-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
    "transfer-encoding repeated": _POST
    + b"Transfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
    "transfer-encoding not ending in chunked": _POST
    + b"Transfer-Encoding: chunked, gzip\r\n\r\n0\r\n\r\n",
    "transfer-encoding identity": _POST
    + b"Transfer-Encoding: identity\r\nContent-Length: 2\r\n\r\n{}",
    "transfer-encoding list with an empty last element": _POST
    + b"Transfer-Encoding: chunked,\r\n\r\n0\r\n\r\n",
    "content-length repeated, different": _POST
    + b"Content-Length: 2\r\nContent-Length: 3\r\n\r\n{}x",
    "content-length repeated, same": _POST + b"Content-Length: 2\r\nContent-Length: 2\r\n\r\n{}",
    "content-length as a list": _POST + b"Content-Length: 2, 2\r\n\r\n{}",
    "whitespace before the colon": _POST + b"Content-Length : 2\r\n\r\n{}",
    "content-length with a plus sign": _POST + b"Content-Length: +2\r\n\r\n{}",
    "content-length with an underscore": _POST + b"Content-Length: 0_2\r\n\r\n{}",
    "obs-folded transfer-encoding": _POST + b"Transfer-Encoding:\r\n chunked\r\n\r\n0\r\n\r\n",
    "head ended by bare LFs": b"POST /health HTTP/1.1\nHost: localhost\nContent-Length: 2\n\n{}",
    "bare CR inside a header line": _POST
    + b"X-A: a\rContent-Length: 9\r\nContent-Length: 2\r\n\r\n{}",
    "chunk size not hex digits": _POST
    + b"Transfer-Encoding: chunked\r\n\r\n0x2\r\n{}\r\n0\r\n\r\n",
    "chunk lines ended by bare LF": _POST + b"Transfer-Encoding: chunked\r\n\r\n2\n{}\n0\n\n",
}

#: Shapes that frame one way only. The answers name what the app said about the first request and
#: then the smuggled one, so the second answer proves the parser consumed the body exactly.
_FRAMED: dict[str, tuple[bytes, list[int]]] = {
    # Controls: plainly framed, so both requests are answered. POST /health is a 405.
    "content-length alone": (_POST + b"Content-Length: 2\r\n\r\n{}", [405, 200]),
    "content-length on a GET": (
        b"GET /health HTTP/1.1\r\nHost: localhost\r\nContent-Length: 5\r\n\r\nhello",
        [200, 200],
    ),
    # Legal chunked framing. The app refuses chunked bodies with a 411 (review M-19); the 200 after
    # it shows the chunked body was read to its last chunk, not to Content-Length or to EOF.
    "transfer-encoding gzip, chunked": (
        _POST + b"Transfer-Encoding: gzip, chunked\r\n\r\n2\r\n{}\r\n0\r\n\r\n",
        [411, 200],
    ),
    "transfer-encoding with case and whitespace": (
        _POST + b"Transfer-Encoding:  CHUNKED \r\n\r\n0\r\n\r\n",
        [411, 200],
    ),
    # Not a framing header at all, so Content-Length frames the request.
    "transfer_encoding with an underscore": (
        _POST + b"Transfer_Encoding: chunked\r\nContent-Length: 2\r\n\r\n{}",
        [405, 200],
    ),
    # RFC 9112 6.1: Transfer-Encoding in HTTP/1.0 is faulty framing, and the connection closes
    # after the message, so the smuggled request is never read.
    "transfer-encoding on HTTP/1.0": (
        b"POST /health HTTP/1.0\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
        [411],
    ),
}

#: Shapes llhttp refuses and h11 accepts: the vacuity control for the pin.
_H11_ACCEPTS = (
    "content-length repeated, same",
    "content-length as a list",
    "obs-folded transfer-encoding",
    "head ended by bare LFs",
)


@pytest.fixture
async def engine(tmp_path: Path) -> AsyncIterator[Engine]:
    eng = await Engine.create(
        tmp_path / "framing.db",
        poll_interval=0.02,
        egress_settings=EgressSettings(deny_by_default=False),
    )
    yield eng
    await eng.stop()


async def _answers(port: int, request: bytes) -> tuple[list[int], bytes]:
    """Send ``request`` then the smuggled one; return every status answered, and the raw bytes."""
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    try:
        writer.write(request + _SMUGGLED)
        await writer.drain()
        raw = await asyncio.wait_for(reader.read(), 10.0)
    finally:
        writer.close()
    return [int(s) for s in re.findall(rb"HTTP/1\.[01] (\d{3}) ", raw)], raw


def test_serve_builds_its_protocol_on_the_pinned_parser() -> None:
    """The suite drives the class ``serve`` builds; this ties that class to llhttp."""
    served = floored_http_protocol_class()
    assert issubclass(served, HttpToolsProtocol)
    assert not issubclass(served, H11Protocol)


async def test_the_api_refuses_ambiguous_request_framing(engine: Engine) -> None:
    # One server for every shape: each probe has its own connection, so a refusal or a desync
    # stays inside it. Every mismatch is collected, so one run names them all.
    misses = []
    async with _served(create_app(engine), http=floored_http_protocol_class()) as port:
        for shape, request in _REFUSED.items():
            statuses, raw = await _answers(port, request)
            if statuses != [400] or not raw.endswith(_PARSER_400_BODY):
                misses.append(f"{shape}: {raw!r}")
    assert not misses, "\n".join(misses)


async def test_the_api_frames_unambiguous_requests_exactly(engine: Engine) -> None:
    misses = []
    async with _served(create_app(engine), http=floored_http_protocol_class()) as port:
        for shape, (request, expected) in _FRAMED.items():
            statuses, raw = await _answers(port, request)
            if statuses != expected:
                misses.append(f"{shape}: expected {expected}, got {statuses}: {raw!r}")
    assert not misses, "\n".join(misses)


async def test_the_probe_sees_the_shapes_h11_would_accept(engine: Engine) -> None:
    """The vacuity control. If ``serve`` followed ``http="auto"`` onto h11, these four shapes would
    reach the app and the smuggled request would be answered too."""
    h11 = floored_http_protocol_class(base=H11Protocol)
    async with _served(create_app(engine), http=h11) as port:
        for shape in _H11_ACCEPTS:
            statuses, raw = await _answers(port, _REFUSED[shape])
            # Two answers: the first request reached the app (a 405, or a 411 for the unfolded
            # chunked one), and the request behind it was read too.
            assert len(statuses) == 2 and statuses[0] != 400, f"{shape}: {raw!r}"
