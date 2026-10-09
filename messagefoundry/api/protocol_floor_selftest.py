# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The startup self-test for the protocol header floor (BACKLOG #1120; ASVS 3.4.4 and 3.4.6).

:mod:`messagefoundry.api.protocol_headers` checks the SHAPE of the server classes it overrides: a
method is there, an attribute is assigned. A shape can hold while the behaviour moves, and the wire
suite drives one uvicorn and one websockets version out of the range ``pyproject.toml`` allows. This
module closes that gap by measuring behaviour on whatever is installed. It hands the floored classes
the bytes that make the server answer on its own, reads what the server wrote, and refuses the start
when a header is missing.

**What it drives.** One request per response family the floor covers, each through the floored HTTP
protocol, the way uvicorn itself would receive it:

* a request line the parser rejects, for the server's own ``400``;
* a well-formed request to an app that raises, for the server's own ``500``;
* a WebSocket upgrade with no ``Sec-WebSocket-Key``, for the handshake rejection the WebSocket
  library writes;
* a complete WebSocket upgrade to an app that raises, for the pre-handshake ``500``;
* a complete WebSocket upgrade to an app that closes before it accepts, for the ``403`` the server
  writes for it; and
* a WebSocket upgrade whose request line is longer than the WebSocket library reads, for the
  answer its parser queues before the server sees a request.

The last four are skipped when there is no WebSocket protocol, which uvicorn reads as WebSockets
off. They run against whichever WebSocket class is handed in: the sans-I/O protocol uvicorn 0.50 and
later resolve ``ws="auto"`` to, or the legacy server before it. Each must be answered by that class.

**No socket, and nothing that can block.** The transport is an in-memory buffer. The event loop is a
private one with no selector and no self-pipe, so the test opens no socket of any kind; a stock
asyncio loop opens a loopback socket pair for its own wake-up. Nothing here waits: the drive
yields with a zero sleep, so every loop turn is a zero-timeout turn, and ``_MAX_TURNS`` is what ends a
drive whose response never comes. The loop's selector also raises if it is ever asked to wait. That
is a backstop for a later edit to this module, and no drive reaches it today.

**Fail closed.** A missing header, an unexpected status, a response that never arrives and an
exception from the drive itself all raise
:class:`~messagefoundry.api.protocol_headers.ProtocolFloorUnavailable`, which ``serve`` and
``supervise`` already refuse to start on. The message names each response and each header it lacked.
It never quotes the bytes written, and it names an exception by type only.

**What it does not prove.** At least these are outside it:

* A response family other than the six above. One a new server version adds is outside it, as it is
  outside the floor.
* The settings ``serve`` runs with. The drives use a plain ``uvicorn.Config``: no TLS, no server-wide
  default headers, one worker, and nothing read from the environment. A header merge that depended
  on those would not show here.
* Any class other than the two it is handed. ``serve`` and ``supervise`` run it a second time on
  the client-certificate shim when the settings ask for one, because the shim is then the class
  served.

The header set comes from
:data:`~messagefoundry.api.protocol_headers.PROTOCOL_SECURITY_HEADERS`, the floor's one definition.

**It leans on CPython internals.** The private loop subclasses ``asyncio.BaseEventLoop`` and supplies
the ``_selector`` and ``_process_events`` that class expects. A Python release that moves either
makes every drive raise, and the engine then refuses to start, naming this module as a possible
cause. The test suite drives the real self-test, so such a release turns CI red first.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Container, Iterator
from contextlib import contextmanager
from pathlib import PurePath
from typing import Any, NamedTuple

from messagefoundry.api.protocol_headers import PROTOCOL_SECURITY_HEADERS, floor_unavailable

__all__ = ["selftest_protocol_floor"]

_log = logging.getLogger(__name__)

#: Loop turns one drive may take before its response counts as missing. Each turn is a zero-timeout
#: pass, so this bounds work, never time. Measured at uvicorn 0.54.0 and websockets 17.1: the six
#: drives take 3 turns between them on the sans-I/O protocol and 9 on the legacy server.
_MAX_TURNS = 200

#: Turns given to the driven connections to close, and again to their cancelled tasks, before the
#: private loop is discarded.
_TEARDOWN_TURNS = 8

#: The loggers the driven server writes to. The drives provoke its own warnings and one traceback on
#: purpose, and at this point in startup an unconfigured root logger would print them to stderr.
_SERVER_LOGGERS = ("uvicorn.error", "uvicorn.access")

#: The path the stand-in app refuses a WebSocket on, by closing before it accepts.
_REFUSED_PATH = "/selftest/refused"

#: The sample nonce from RFC 6455 section 1.3. It is public and protects nothing.
_UPGRADE_KEY = b"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"


def _upgrade(path: str = "/selftest", *, key: bool = True) -> bytes:
    return (
        b"GET " + path.encode("ascii") + b" HTTP/1.1\r\n"
        b"Host: selftest\r\n"
        b"Upgrade: websocket\r\n"
        b"Connection: Upgrade\r\n"
        b"Sec-WebSocket-Version: 13\r\n" + (_UPGRADE_KEY if key else b"") + b"\r\n"
    )


#: What ``ProtocolFloorUnavailable.hook`` holds for a refusal from here. No one hook failed.
_HOOK = "startup self-test"


class _Drive(NamedTuple):
    """One response family: what to send, and which statuses mean the intended path answered."""

    response: str
    request: bytes
    statuses: Container[int]
    websocket: bool


_DRIVES = (
    _Drive("malformed-request 400", b"NOT A REQUEST LINE\r\n\r\n", (400,), False),
    _Drive("app-error 500", b"GET /selftest HTTP/1.1\r\nHost: selftest\r\n\r\n", (500,), False),
    # Any 4xx: which one the library picks for a bad handshake is its own choice.
    _Drive("WebSocket handshake rejection", _upgrade(key=False), range(400, 500), True),
    _Drive("WebSocket pre-handshake 500", _upgrade(), (500,), True),
    _Drive("WebSocket refusal 403", _upgrade(_REFUSED_PATH), (403,), True),
    # Longer than the 8192 bytes websockets reads for one line, and well inside what the HTTP
    # protocols accept, so it is the WebSocket library's parser that rejects it.
    _Drive(
        "WebSocket parser rejection", _upgrade("/selftest/" + "a" * 9000), range(400, 500), True
    ),
)


class _SelfTestAppError(Exception):
    """Raised by the stand-in app so the server answers for it."""


async def _failing_app(scope: Any, receive: Any, send: Any) -> None:
    """Raise, so the server answers for the app. One WebSocket path closes before accepting
    instead, so the server writes its own 403."""
    if scope["type"] == "websocket" and scope["path"] == _REFUSED_PATH:
        await send({"type": "websocket.close"})
        return
    raise _SelfTestAppError


class _NeverWaits:
    """The private loop's selector. There is no I/O to wait for, so being asked to wait means
    this module awaited something that cannot finish. Raising ends that instead of hanging the
    start. No drive reaches it as written; ``_MAX_TURNS`` is the bound they hit."""

    def select(self, timeout: float | None = None) -> list[Any]:
        if timeout is None or timeout > 0:
            raise RuntimeError("the self-test loop was asked to wait")
        return []


class _NoIOLoop(asyncio.BaseEventLoop):
    """An event loop with no selector, no self-pipe and so no socket. It runs callbacks, tasks and
    timers, which is all the driven protocols ask of it."""

    def __init__(self) -> None:
        super().__init__()
        self._selector = _NeverWaits()
        # The loop is thrown away with whatever the driven connections left on it. Their teardown
        # errors are not this check's result, so they are recorded quietly and never raised.
        self.set_exception_handler(_note_loop_error)

    def _process_events(self, event_list: Any) -> None:
        pass

    def _write_to_self(self) -> None:
        pass


def _note_loop_error(loop: asyncio.AbstractEventLoop, context: dict[str, Any]) -> None:
    _log.debug("protocol floor self-test: discarded loop reported: %s", context.get("message"))


class _CapturingTransport(asyncio.Transport):
    """Keeps what the server writes. Closing tells the current protocol, as a real transport does."""

    def __init__(self) -> None:
        super().__init__()
        self.written = bytearray()
        self._closing = False
        #: The protocol now holding this transport. uvicorn's upgrade hand-over replaces it.
        self.protocol: Any = None

    def write(self, data: bytes | bytearray | memoryview) -> None:
        self.written += data

    def close(self) -> None:
        if self._closing:
            return
        self._closing = True
        if self.protocol is not None:
            asyncio.get_running_loop().call_soon(self.protocol.connection_lost, None)

    def abort(self) -> None:
        self.close()

    def is_closing(self) -> bool:
        return self._closing

    def set_protocol(self, protocol: asyncio.BaseProtocol) -> None:
        self.protocol = protocol

    def pause_reading(self) -> None:
        pass

    def resume_reading(self) -> None:
        pass

    def set_write_buffer_limits(self, high: int | None = None, low: int | None = None) -> None:
        pass

    def can_write_eof(self) -> bool:
        return False


@contextmanager
def _server_logs_muted() -> Iterator[None]:
    """Drop the driven server's own log records for the length of the test. Only its loggers: a
    warning from the floor's own header path still comes out."""

    def drop(record: logging.LogRecord) -> bool:
        return False

    loggers = [logging.getLogger(name) for name in _SERVER_LOGGERS]
    for logger in loggers:
        logger.addFilter(drop)
    try:
        yield
    finally:
        for logger in loggers:
            logger.removeFilter(drop)


def _missing(drive: _Drive, written: bytes) -> list[str]:
    """What is wrong with one driven response, as phrases naming it. Empty when it is floored."""
    head, complete, _ = written.partition(b"\r\n\r\n")
    lines = head.split(b"\r\n")
    status_line = lines[0].split()
    if not complete or len(status_line) < 2 or not status_line[1].isdigit():
        return [f"the {drive.response} was never written"]
    status = int(status_line[1])
    if status not in drive.statuses:
        return [f"the {drive.response} drive was answered with status {status}"]
    sent = []
    for line in lines[1:]:
        got, _, text = line.partition(b":")
        sent.append((got.strip().lower(), text.strip()))
    problems = []
    for name, value in PROTOCOL_SECURITY_HEADERS:
        wanted = name.lower().encode("latin-1")
        if (wanted, value.encode("latin-1")) not in sent:
            problems.append(f"the {drive.response} lacked {name}")
        elif sum(got == wanted for got, _ in sent) > 1:
            # The floor adds each header once. A second copy means two paths now write it.
            problems.append(f"the {drive.response} carried {name} more than once")
    return problems


async def _turns(count: int) -> None:
    for _ in range(count):
        await asyncio.sleep(0)


async def _drive_all(http_class: type[Any], ws_class: type[Any] | None) -> list[str]:
    # Imported here like every other uvicorn import in this package: the floor must stay importable
    # where uvicorn is not, and the caller has already built the classes from it.
    import uvicorn
    from uvicorn.server import ServerState

    # workers and proxy_headers are spelled out so Config reads neither WEB_CONCURRENCY nor
    # FORWARDED_ALLOW_IPS: a bad value there is not a header floor failure and must not read as one.
    config = uvicorn.Config(
        _failing_app,
        http=http_class,
        ws=ws_class if ws_class is not None else "none",
        lifespan="off",
        log_config=None,
        workers=1,
        proxy_headers=False,
    )
    state = ServerState()
    problems: list[str] = []
    transports: list[_CapturingTransport] = []
    for drive in _DRIVES:
        if drive.websocket and ws_class is None:
            continue
        transport = _CapturingTransport()
        transports.append(transport)
        # Built and fed the way uvicorn's server does it: keyword arguments, then the two
        # asyncio.Protocol calls. An upgrade request reaches the WebSocket class through the HTTP
        # protocol's own hand-over, so that path is driven too.
        protocol = http_class(config=config, server_state=state, app_state={})
        transport.set_protocol(protocol)
        protocol.connection_made(transport)
        protocol.data_received(drive.request)
        for _ in range(_MAX_TURNS):
            if b"\r\n\r\n" in transport.written:
                break
            await asyncio.sleep(0)
        if (
            ws_class is not None
            and drive.websocket
            and not isinstance(transport.protocol, ws_class)
        ):
            # A floored answer from the HTTP protocol would otherwise pass for the WebSocket one.
            problems.append(f"the {drive.response} drive never reached the WebSocket protocol")
        else:
            problems += _missing(drive, bytes(transport.written))

    # Hang up as a client would, then cancel whatever is still waiting, so the loop is discarded
    # with nothing pending on it.
    for transport in transports:
        transport.close()
    await _turns(_TEARDOWN_TURNS)
    for task in asyncio.all_tasks() - {asyncio.current_task()}:
        task.cancel()
    await _turns(_TEARDOWN_TURNS)
    return problems


def _raised_at(exc: BaseException) -> str:
    """Where ``exc`` was raised, as ``file.py:line``. A place and no text, so the refusal can tell
    a server fault from one in this module without carrying the exception's message."""
    frame = exc.__traceback__
    if frame is None:
        return "an unknown place"
    while frame.tb_next is not None:
        frame = frame.tb_next
    return f"{PurePath(frame.tb_frame.f_code.co_filename).name}:{frame.tb_lineno}"


def selftest_protocol_floor(http_class: type[Any], ws_class: type[Any] | None) -> None:
    """Drive the floored classes' own responses and raise unless every one carries the headers.

    ``http_class`` and ``ws_class`` are what ``floored_http_protocol_class`` and
    ``floored_ws_protocol_class`` returned. Call it from synchronous startup code: it runs its own
    loop, and a loop already running in the calling thread is reported as a failed drive.

    Raises :class:`~messagefoundry.api.protocol_headers.ProtocolFloorUnavailable`; see the module
    docstring for what counts."""
    problems: list[str] = []
    try:
        loop = _NoIOLoop()
        drives = _drive_all(http_class, ws_class)
        try:
            with _server_logs_muted():
                problems = loop.run_until_complete(drives)
        finally:
            drives.close()  # a no-op once it ran; it never starts when a loop is already running
            loop.close()
    except Exception as exc:
        # Only the type is kept, and the refusal is raised after this handler ends, so the caught
        # exception is not on its chain. The cause may be this harness and not the server, so the
        # message points here as well.
        problems = [
            f"the drive raised {type(exc).__name__} at {_raised_at(exc)} before a response could be "
            "read, in the server or in messagefoundry/api/protocol_floor_selftest.py itself"
        ]
    if problems:
        found = "; ".join(problems)
        raise floor_unavailable(f"failed its {_HOOK}: {found}", _HOOK)
