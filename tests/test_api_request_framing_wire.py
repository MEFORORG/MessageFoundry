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

Measured on uvicorn 0.54.0 and httptools 0.8.0. This suite pins httptools, and
``tests/test_header_floor_wire.py`` pins uvicorn.
"""

from __future__ import annotations

import asyncio
import logging
import re
import tomllib
from asyncio import proactor_events
from collections.abc import AsyncIterator
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import httptools
import pytest
from packaging.requirements import Requirement
from packaging.utils import canonicalize_name
from uvicorn.protocols.http.h11_impl import H11Protocol

from messagefoundry.api import create_app, protocol_headers
from messagefoundry.api.protocol_headers import (
    floored_http_protocol_class,
    pinned_http_protocol_base,
)
from messagefoundry.config.settings import EgressSettings
from messagefoundry.pipeline import Engine
from tests.test_header_floor_wire import _ROOT, _served

#: The httptools this suite was measured against. See its test before moving it.
_MEASURED_HTTPTOOLS = "0.8.0"
#: The request each probe smuggles behind its first. ``/health`` answers it tokenless with a 200.
_SMUGGLED = b"GET /health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
_POST = b"POST /health HTTP/1.1\r\nHost: localhost\r\n"
#: uvicorn's body for the 400 it writes itself when its parser refuses a request.
_PARSER_400_BODY = b"Invalid HTTP request received."

#: Ambiguous or malformed framing that llhttp refuses with one 400. Most shapes fail in the head,
#: before the app runs. The two chunk shapes fail in the body, after uvicorn has started the app
#: at the end of the head; the app may already be answering, and nothing it writes goes out after
#: the 400 (``test_nothing_follows_the_parser_400_when_a_late_write_could_still_go_out``).
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
    """Send ``request`` then the smuggled one; return every status answered, and the raw bytes.

    A refusal closes the server side while the smuggled bytes may still be in flight, and some
    stacks answer that with a reset. Reading stops there and keeps what already arrived, so a reset
    is scored on the answers it left, not raised as an error."""
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    raw = b""
    try:
        writer.write(request + _SMUGGLED)
        await writer.drain()
        while chunk := await asyncio.wait_for(reader.read(65536), 10.0):
            raw += chunk
    except ConnectionResetError:
        pass
    finally:
        writer.close()
    return [int(s) for s in re.findall(rb"HTTP/1\.[01] (\d{3}) ", raw)], raw


def test_the_suite_is_measuring_the_httptools_it_was_written_against() -> None:
    """llhttp, vendored in httptools, decides which shapes are refused. A new release turns this
    red until the shapes above are re-driven and the pin moves."""
    assert httptools.__version__ == _MEASURED_HTTPTOOLS, (
        f"httptools is {httptools.__version__}, and this suite measured {_MEASURED_HTTPTOOLS}. "
        "Re-run the framing shapes against it, then move the pin."
    )


def test_pyproject_pins_the_httptools_this_suite_measured() -> None:
    """The base dependencies pin httptools exactly, to the version measured here, on every
    platform. The installed-version test above cannot see a range that still resolves to the
    measured version in the lock, though a fresh install could take a release nobody drove."""
    pyproject = tomllib.loads((_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    deps = list(map(Requirement, pyproject["project"]["dependencies"]))
    same = [r for r in deps if canonicalize_name(r.name) == "httptools"]
    assert len(same) == 1, f"httptools has {len(same)} entries in [project].dependencies, not one"
    (req,) = same
    assert req.marker is None, f"httptools is pinned on some platforms only: {req}"
    assert str(req.specifier) == f"=={_MEASURED_HTTPTOOLS}", (
        f"httptools is not pinned to {_MEASURED_HTTPTOOLS}: {req}"
    )


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


#: Requests whose 400 comes after the app has started: llhttp fails in the body. The pipelined case
#: is a well-framed chunked request, answered from its head, with the refused one behind it. Its
#: answer comes from a cycle that ``protocol.cycle`` no longer names, since the refused request's
#: cycle replaced it.
_LATE_ANSWERS: dict[str, bytes] = {
    "chunk size not hex digits": _REFUSED["chunk size not hex digits"],
    "chunk lines ended by bare LF": _REFUSED["chunk lines ended by bare LF"],
    "a pipelined chunked request ahead of a refused one": _POST
    + b"Transfer-Encoding: chunked\r\n\r\n0\r\n\r\n"
    + _REFUSED["chunk size not hex digits"],
}
#: What uvicorn's own protocol puts on the wire for each of them when the transport lets a write
#: made after ``close()`` go out: its 400, then the app's late 411.
_LATE_STATUSES = [400, 411]
#: How long the selector stand-in below keeps a closed transport writable.
_SELECTOR_LATE_CLOSE_S = 0.5


def _proactor_close_as_in_cpython_3_14_9(self: Any) -> None:
    """CPython 3.14.9's ``_ProactorBasePipeTransport.close``, run beside the installed release's
    ``_loop_writing``. The connection is marked lost only when no write is pending. So a write
    made after ``close()`` while the 400 is still in flight is sent. Earlier releases marked it lost
    at once and dropped that write. This matches 3.14.9 only while the 400 is still pending, which
    is the window the late 411 lands in."""
    if self._closing:
        return
    self._closing = True
    if not self._buffer and self._write_fut is None:
        self._conn_lost += 1
        self._loop.call_soon(self._call_connection_lost, None)
    if self._read_fut is not None:
        self._read_fut.cancel()
        self._read_fut = None


def _selector_close_with_the_400_unsent(self: Any) -> None:
    """``_SelectorTransport.close`` as it behaves when the 400 did not go out in one send: the
    connection stays writable until the buffer drains. Held open for a fixed time instead, since
    a loopback send of a short 400 always completes at once."""
    if self._closing:
        return
    self._closing = True
    self._loop._remove_reader(self._sock_fd)

    def finish() -> None:
        # A reset may have closed it meanwhile, or the write handler may have, once buffered bytes
        # drained on a closing transport (that path clears _sock without bumping _conn_lost). With
        # bytes still buffered, the write handler closes it once they drain.
        if self._conn_lost or self._sock is None or self._buffer:
            return
        self._conn_lost += 1
        self._loop._remove_writer(self._sock_fd)
        self._call_connection_lost(None)

    self._loop.call_later(_SELECTOR_LATE_CLOSE_S, finish)


def _let_a_write_after_close_go_out(monkeypatch: pytest.MonkeyPatch) -> float:
    """Make the running loop's socket transports send a write made after ``close()``, on any
    CPython: the proactor the way 3.14.9 does, the selector the way it does for a 400 that did not
    fit in one send. Returns how long a close may still be pending once the test is done."""
    # By dotted name: typeshed does not declare the selector's private base transport.
    if isinstance(asyncio.get_running_loop(), proactor_events.BaseProactorEventLoop):
        monkeypatch.setattr(
            "asyncio.proactor_events._ProactorBasePipeTransport.close",
            _proactor_close_as_in_cpython_3_14_9,
        )
        return 0.0
    monkeypatch.setattr(
        "asyncio.selector_events._SelectorTransport.close", _selector_close_with_the_400_unsent
    )
    return _SELECTOR_LATE_CLOSE_S


async def test_nothing_follows_the_parser_400_when_a_late_write_could_still_go_out(
    engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The response-desync shape CPython 3.14.9 exposed. The app answers a refused request from
    its head, with a chunked body's 411. llhttp then fails on the body, and uvicorn writes its 400
    with ``connection: close``. A transport that still sends a write made after ``close()`` put
    the app's answer on the wire behind that 400. The floor marks the cycles disconnected, so
    exactly one 400 goes out.

    The control is uvicorn's own protocol under the same patch. It must show the late answer, or
    the patch reproduced nothing in this run and the floored leg proves nothing."""
    pending_close = _let_a_write_after_close_go_out(monkeypatch)
    async with _served(create_app(engine), http=pinned_http_protocol_base()) as port:
        for shape, request in _LATE_ANSWERS.items():
            statuses, raw = await _answers(port, request)
            assert statuses == _LATE_STATUSES, f"control reproduced nothing, {shape}: {raw!r}"
    misses = []
    async with _served(create_app(engine), http=floored_http_protocol_class()) as port:
        for shape, request in _LATE_ANSWERS.items():
            statuses, raw = await _answers(port, request)
            if statuses != [400] or not raw.endswith(_PARSER_400_BODY):
                misses.append(f"{shape}: {raw!r}")
    # Let the stand-in's delayed closes run here, not inside the next test on the shared loop.
    await asyncio.sleep(pending_close)
    assert not misses, "\n".join(misses)


class _Cycle:
    """Just the cycle fields the 400 step reads and sets."""

    def __init__(self, *, complete: bool = False) -> None:
        self.response_complete = complete
        self.disconnected = False
        self.message_event = asyncio.Event()


class _BrokenCycle:
    @property
    def response_complete(self) -> bool:
        raise RuntimeError("torn down")


def test_one_broken_cycle_does_not_leave_the_others_unmarked(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    monkeypatch.setattr(protocol_headers, "_WARNED", set())
    caplog.set_level(logging.WARNING, logger=protocol_headers.__name__)
    open_cycle, done = _Cycle(), _Cycle(complete=True)
    protocol_headers._end_the_open_cycles([_BrokenCycle(), open_cycle, done])
    assert open_cycle.disconnected and open_cycle.message_event.is_set()
    # A completed response stays as it was; only its waiters are woken.
    assert not done.disconnected and done.message_event.is_set()
    hits = [r.getMessage() for r in caplog.records if r.name == protocol_headers.__name__]
    assert len(hits) == 1 and "http-400: cycle end" in hits[0] and "RuntimeError" in hits[0], hits


def test_a_cycle_that_cannot_be_recorded_degrades(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    monkeypatch.setattr(protocol_headers, "_WARNED", set())
    caplog.set_level(logging.WARNING, logger=protocol_headers.__name__)
    protocol_headers._remember_the_cycle(SimpleNamespace(), object())  # object() takes no weakref
    hits = [r.getMessage() for r in caplog.records if r.name == protocol_headers.__name__]
    assert len(hits) == 1 and "http-400: cycle record" in hits[0], hits


def test_a_400_writer_that_raises_still_ends_the_open_cycles() -> None:
    class _RaisingBase:
        def send_400_response(self, msg: str) -> None:
            raise RuntimeError("writer failed")

    floored = protocol_headers._build_floored_http(_RaisingBase)
    protocol: Any = floored()
    protocol.transport = SimpleNamespace()
    cycle = _Cycle()
    protocol_headers._remember_the_cycle(protocol, cycle)
    with pytest.raises(RuntimeError, match="writer failed"):
        protocol.send_400_response("Invalid HTTP request received.")
    assert cycle.disconnected and cycle.message_event.is_set()


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
