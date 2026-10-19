# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The protocol header floor's startup self-test (BACKLOG #1120; ASVS 3.4.4 and 3.4.6).

The self-test drives the floored classes' own responses in memory and refuses the start when one
lacks a header. **Every refusal here is paired with a control in the same run:** the same classes,
with nothing knocked out, pass. A check that cannot report presence proves nothing by reporting
absence, and the reverse.

Each knock-out removes ONE of the floor's hooks from a class built for that test, so the server's
own writer answers bare. The refusal must then name that response and no other.

The serve and supervise entry-path tests live in ``tests/test_header_floor_wire.py``, beside the
fixture they share with the structural refusals.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import platform
import re
import socket
from collections.abc import Callable
from typing import Any

import pytest
from uvicorn.protocols.http.h11_impl import H11Protocol
from uvicorn.protocols.http.httptools_impl import HttpToolsProtocol
from uvicorn.protocols.websockets.websockets_impl import WebSocketProtocol
from uvicorn.protocols.websockets.websockets_sansio_impl import WebSocketsSansIOProtocol

from messagefoundry.api import protocol_floor_selftest, protocol_headers
from messagefoundry.api.protocol_floor_selftest import selftest_protocol_floor
from messagefoundry.api.protocol_headers import (
    PROTOCOL_SECURITY_HEADERS,
    ProtocolFloorUnavailable,
    floored_http_protocol_class,
    floored_ws_protocol_class,
)

_HTTP_BASES = [HttpToolsProtocol, H11Protocol]
#: Both WebSocket protocols the floor covers. The sans-I/O one is what ``ws="auto"`` resolves to
#: at the locked uvicorn, so it is the default every test below uses unless it names the other.
_WS_BASES = [WebSocketsSansIOProtocol, WebSocketProtocol]
_ALL_RESPONSES = [drive.response for drive in protocol_floor_selftest._DRIVES]
_WS_RESPONSES = {drive.response for drive in protocol_floor_selftest._DRIVES if drive.websocket}


def _floored(
    http_base: type[Any] = HttpToolsProtocol, ws_base: type[Any] = WebSocketsSansIOProtocol
) -> tuple[type[Any], type[Any]]:
    ws = floored_ws_protocol_class(base=ws_base)
    assert ws is not None
    return floored_http_protocol_class(base=http_base), ws


def _refusal(http: type[Any], ws: type[Any] | None) -> str:
    with pytest.raises(ProtocolFloorUnavailable) as refused:
        selftest_protocol_floor(http, ws)
    message = str(refused.value)
    assert "failed its startup self-test" in message, message
    assert refused.value.hook == "startup self-test"
    # Raised outside any handler, so nothing the drive raised rides on the refusal's chain.
    assert refused.value.__context__ is None and refused.value.__cause__ is None
    return message


def _frames(message: str) -> list[str]:
    """The ``module:line`` places a refusal for a raising drive lists, outermost first."""
    places = message.partition("its frames, outermost first: ")[2].partition(" (uvicorn ")[0]
    assert places, message
    return places.split(" > ")


def _names(message: str, response: str) -> None:
    for name, _ in PROTOCOL_SECURITY_HEADERS:
        assert f"the {response} lacked {name}" in message, message


def _names_only(message: str, *responses: str) -> None:
    """The refusal names each of ``responses`` with every header it lacked, and no other."""
    for response in responses:
        _names(message, response)
    for other in _ALL_RESPONSES:
        if other not in responses:
            assert other not in message, message


# --- the controls: nothing knocked out ------------------------------------------------------------


@pytest.mark.parametrize("ws_base", _WS_BASES)
@pytest.mark.parametrize("http_base", _HTTP_BASES)
def test_the_real_classes_pass(http_base: type[Any], ws_base: type[Any]) -> None:
    selftest_protocol_floor(*_floored(http_base, ws_base))


def test_the_classes_serve_resolves_pass() -> None:
    """The pinned HTTP protocol (BACKLOG #1125) and what ``ws="auto"`` resolves to: what ``serve``
    builds."""
    selftest_protocol_floor(floored_http_protocol_class(), floored_ws_protocol_class())


def test_no_websocket_protocol_drives_the_http_families_alone() -> None:
    selftest_protocol_floor(floored_http_protocol_class(), None)


@pytest.mark.parametrize("ws_base", _WS_BASES)
def test_the_unfloored_classes_are_refused_for_every_response(ws_base: type[Any]) -> None:
    """The vacuity control for the whole check: uvicorn's own classes, with no floor, fail every
    drive."""
    assert len(_ALL_RESPONSES) == 6 and len(_WS_RESPONSES) == 4
    message = _refusal(HttpToolsProtocol, ws_base)
    # uvicorn's own sans-I/O protocol never writes the answer its parser queued, so that drive
    # fails as unwritten there. Every other drive, on either protocol, is written bare.
    unwritten = ["WebSocket parser rejection"] if ws_base is WebSocketsSansIOProtocol else []
    for response in _ALL_RESPONSES:
        if response in unwritten:
            assert f"the {response} was never written" in message, message
        else:
            _names(message, response)


# --- one hook knocked out per response -----------------------------------------------------------


@pytest.mark.parametrize("http_base", _HTTP_BASES)
def test_a_bare_400_is_refused(http_base: type[Any]) -> None:
    http, ws = _floored(http_base)
    selftest_protocol_floor(http, ws)
    del http.send_400_response  # the server's own writer answers
    _names_only(_refusal(http, ws), "malformed-request 400")


@pytest.mark.parametrize("http_base", _HTTP_BASES)
def test_a_bare_500_is_refused(http_base: type[Any], monkeypatch: pytest.MonkeyPatch) -> None:
    http, ws = _floored(http_base)
    selftest_protocol_floor(http, ws)
    monkeypatch.setattr(protocol_headers, "_floor_the_cycle_500", lambda cycle: None)
    _names_only(_refusal(http, ws), "app-error 500")


@pytest.mark.parametrize(
    ("ws_base", "hook", "responses"),
    [
        # The sans-I/O protocol has ONE hook: every handshake answer goes through its conn.
        pytest.param(WebSocketsSansIOProtocol, "conn", sorted(_WS_RESPONSES), id="sansio-conn"),
        # The legacy server has two. Its library writes the rejection and the 403 through one.
        pytest.param(
            WebSocketProtocol,
            "write_http_response",
            [
                "WebSocket handshake rejection",
                "WebSocket refusal 403",
                "WebSocket parser rejection",
            ],
            id="legacy-write_http_response",
        ),
        pytest.param(
            WebSocketProtocol,
            "send_500_response",
            ["WebSocket pre-handshake 500"],
            id="legacy-send_500_response",
        ),
    ],
)
def test_a_bare_websocket_answer_is_refused(
    ws_base: type[Any], hook: str, responses: list[str]
) -> None:
    http, ws = _floored(ws_base=ws_base)
    selftest_protocol_floor(http, ws)
    delattr(ws, hook)  # the server's own behaviour answers
    _names_only(_refusal(http, ws), *responses)


def test_a_conn_whose_hook_does_nothing_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    """The shape holds and the behaviour does not: the conn property is in place and its hook adds
    nothing. Only driving the class can see this."""
    http, ws = _floored()
    selftest_protocol_floor(http, ws)
    monkeypatch.setattr(protocol_headers, "_floor_the_conn_responses", lambda conn: None)
    _names_only(_refusal(http, ws), *sorted(_WS_RESPONSES))


def test_a_parser_rejection_uvicorn_leaves_unwritten_is_refused() -> None:
    """The floor's one written answer, knocked out: with the class's data_received removed, the
    answer the websockets parser queued is never written, as on the bare class, and the self-test
    says so for that drive alone."""
    http, ws = _floored()
    selftest_protocol_floor(http, ws)
    del ws.data_received
    message = _refusal(http, ws)
    assert "the WebSocket parser rejection was never written" in message, message
    assert "lacked" not in message, message


def test_one_missing_header_is_named_alone(monkeypatch: pytest.MonkeyPatch) -> None:
    """The check reads each header, not the set as a whole: the floor writes one, the check wants
    two, and only the absent one is named."""
    http, ws = _floored()
    wanted = (*PROTOCOL_SECURITY_HEADERS, ("X-Selftest-Control", "absent"))
    monkeypatch.setattr(protocol_floor_selftest, "PROTOCOL_SECURITY_HEADERS", wanted)
    message = _refusal(http, ws)
    assert "lacked X-Selftest-Control" in message
    for name, _ in PROTOCOL_SECURITY_HEADERS:
        assert f"lacked {name}" not in message, message


def test_a_wrong_header_value_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    http, ws = _floored()
    name, value = PROTOCOL_SECURITY_HEADERS[0]
    wanted = ((name, value + "-changed"), *PROTOCOL_SECURITY_HEADERS[1:])
    monkeypatch.setattr(protocol_floor_selftest, "PROTOCOL_SECURITY_HEADERS", wanted)
    assert f"lacked {name}" in _refusal(http, ws)


def test_a_header_written_twice_is_refused() -> None:
    """Flooring a floored class stamps the 400 twice. Two writers for one header is drift the
    check names, not a pass."""
    http, ws = _floored(H11Protocol)
    twice = floored_http_protocol_class(base=http)
    message = _refusal(twice, ws)
    for name, _ in PROTOCOL_SECURITY_HEADERS:
        assert f"the malformed-request 400 carried {name} more than once" in message, message


# --- a drive that does not reach its response fails closed ---------------------------------------


@pytest.mark.parametrize("http_base", _HTTP_BASES)
def test_an_upgrade_the_http_protocol_keeps_is_refused(
    http_base: type[Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    """The WebSocket drives must be answered by the WebSocket class. Here the HTTP protocol never
    hands the upgrade over and answers with its own floored 500, which would pass on headers."""
    http, ws = _floored(http_base)
    monkeypatch.setattr(http, "_should_upgrade", lambda self: False)
    message = _refusal(http, ws)
    for response in ("WebSocket handshake rejection", "WebSocket pre-handshake 500"):
        assert f"the {response} drive never reached the WebSocket protocol" in message, message
    assert "lacked" not in message, message


def test_the_environment_uvicorn_reads_does_not_reach_the_drive(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """uvicorn's Config reads these two when left to. A bad value is not a header floor failure."""
    monkeypatch.setenv("WEB_CONCURRENCY", "not-a-number")
    monkeypatch.setenv("FORWARDED_ALLOW_IPS", "not-an-address")
    selftest_protocol_floor(*_floored())


def test_an_unexpected_status_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    """The malformed request must be answered by the 400 writer. Any other status means the drive no
    longer reaches the response it was written to measure, so its headers prove nothing."""
    http, ws = _floored()
    drives = protocol_floor_selftest._DRIVES
    moved = (drives[0]._replace(statuses=(499,)), *drives[1:])
    monkeypatch.setattr(protocol_floor_selftest, "_DRIVES", moved)
    message = _refusal(http, ws)
    assert "the malformed-request 400 drive was answered with status 400" in message, message


def test_a_response_that_never_arrives_is_refused() -> None:
    http, ws = _floored(H11Protocol)
    http.send_400_response = lambda self, *args, **kwargs: None
    assert "the malformed-request 400 was never written" in _refusal(http, ws)


def test_a_drive_that_raises_is_refused_by_type_and_places(monkeypatch: pytest.MonkeyPatch) -> None:
    """The refusal names the type, the Python version and each frame's module and line, outermost
    first, and never the exception's message."""
    http, ws = _floored()

    def _raises(self: Any, data: bytes) -> None:
        raise ValueError("synthetic text that must not reach the refusal")

    monkeypatch.setattr(http, "data_received", _raises)
    message = _refusal(http, ws)
    assert f"the drive raised ValueError on Python {platform.python_version()} " in message, message
    # The self-test's own frame first, the raising frame in this module last.
    frames = _frames(message)
    assert frames[0].startswith("messagefoundry.api.protocol_floor_selftest:"), message
    assert re.fullmatch(r"(\w+\.)*test_protocol_floor_selftest:\d+", frames[-1]), message
    assert "synthetic text" not in message


def test_a_loop_internal_python_stops_supplying_is_a_clean_refusal(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The private loop supplies CPython internals ``asyncio.BaseEventLoop`` calls. One it stops
    supplying, as a later Python could make it, is a refusal naming the asyncio frame, not a
    traceback out of ``serve``."""
    monkeypatch.delattr(protocol_floor_selftest._NoIOLoop, "_process_events")
    message = _refusal(*_floored())
    assert "the drive raised NotImplementedError on Python " in message, message
    assert re.fullmatch(r"asyncio\.base_events:\d+", _frames(message)[-1]), message


def test_the_private_loop_raises_when_asked_to_wait() -> None:
    """The backstop no drive reaches: awaiting real time on the no-I/O loop ends at once."""
    loop = protocol_floor_selftest._NoIOLoop()
    try:
        waits = loop.create_task(asyncio.sleep(60))
        with pytest.raises(RuntimeError, match="asked to wait"):
            loop.run_until_complete(waits)
        # This test finishes its own task, so nothing it made is left pending on a closed loop. A
        # cancelled sleep needs only zero-timeout turns.
        waits.cancel()
        with pytest.raises(asyncio.CancelledError):
            loop.run_until_complete(waits)
        assert waits.cancelled()
    finally:
        loop.close()


#: Stands for an exception's message, which can carry what a driven connection held.
_LOOP_ERROR_TEXT = "synthetic loop error text that must not be logged"


_LoopHandler = Callable[[asyncio.AbstractEventLoop, dict[str, Any]], object]


def _logged_loop_error(
    caplog: pytest.LogCaptureFixture, handler: _LoopHandler | None = None
) -> tuple[list[logging.LogRecord], str]:
    """Hand the private loop's exception handler a context carrying an exception, as asyncio does
    for a task that failed or was destroyed pending. ``handler`` replaces the one the loop installs.
    Returns the records and their rendered text, traceback included, so text logged through
    ``exc_info`` counts as well."""
    loop = protocol_floor_selftest._NoIOLoop()
    try:
        if handler is not None:
            loop.set_exception_handler(handler)
        caplog.clear()
        with caplog.at_level(logging.DEBUG, logger=protocol_floor_selftest._log.name):
            try:
                raise ValueError(_LOOP_ERROR_TEXT)
            except ValueError as exc:
                loop.call_exception_handler(
                    {"message": "a discarded task failed", "exception": exc}
                )
    finally:
        loop.close()
    records = list(caplog.records)
    return records, "\n".join(logging.Formatter().format(record) for record in records)


def test_the_private_loops_error_handler_logs_no_exception_text(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """The handler the private loop installs logs the context's message and nothing of its
    exception (BACKLOG #1789's exemption, pinned in ``tests/test_last_resort.py``). Read off the
    captured log, so a second log line that printed ``context["exception"]`` fails it."""
    records, text = _logged_loop_error(caplog)
    assert [r.name for r in records] == [protocol_floor_selftest._log.name], text
    assert "a discarded task failed" in text, text
    assert _LOOP_ERROR_TEXT not in text and "ValueError" not in text, text

    # The controls: the instrument sees exception text when a handler logs it.
    def _also_logs_the_exception(loop: Any, context: dict[str, Any]) -> None:
        protocol_floor_selftest._note_loop_error(loop, context)
        protocol_floor_selftest._log.debug("%s", context["exception"])

    def _logs_its_traceback(loop: Any, context: dict[str, Any]) -> None:
        protocol_floor_selftest._log.debug(context["message"], exc_info=context["exception"])

    def _asyncios_own(loop: Any, context: dict[str, Any]) -> None:
        loop.default_exception_handler(context)

    for leaky in (_also_logs_the_exception, _logs_its_traceback, _asyncios_own):
        _, leaked = _logged_loop_error(caplog, leaky)
        assert _LOOP_ERROR_TEXT in leaked, (leaky, leaked)


async def test_a_loop_already_running_is_a_failed_drive() -> None:
    """The self-test is for synchronous startup code. Inside a running loop it refuses, and says
    why by type, instead of blocking that loop or passing unmeasured."""
    assert "the drive raised RuntimeError" in _refusal(*_floored())


# --- what the self-test must not do --------------------------------------------------------------


def test_it_opens_no_socket(monkeypatch: pytest.MonkeyPatch) -> None:
    def _no_socket(*args: Any, **kwargs: Any) -> Any:
        raise AssertionError("the self-test opened a socket")

    http, ws = _floored()
    with monkeypatch.context() as patched:
        patched.setattr(socket, "socket", _no_socket)
        patched.setattr(socket, "socketpair", _no_socket)
        selftest_protocol_floor(http, ws)
        with pytest.raises(AssertionError, match="opened a socket"):
            socket.socketpair()  # the control: the patch was live while the self-test ran


def _server_records(caplog: pytest.LogCaptureFixture) -> int:
    return sum(r.name.startswith(("uvicorn", "websockets", "asyncio")) for r in caplog.records)


def test_the_driven_servers_own_logging_stays_quiet(
    caplog: pytest.LogCaptureFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The drives provoke uvicorn's own warnings and a traceback. At this point in startup an
    unconfigured root logger would print them, on every start."""
    caplog.set_level(logging.DEBUG)
    with monkeypatch.context() as patched:
        patched.setattr(protocol_floor_selftest, "_server_logs_muted", contextlib.nullcontext)
        selftest_protocol_floor(*_floored())
    assert _server_records(caplog) > 0, "the control: unmuted, the drives do log"
    caplog.clear()
    selftest_protocol_floor(*_floored())
    assert _server_records(caplog) == 0, [r.getMessage() for r in caplog.records]
    # CRITICAL, so the record gets through whatever level an earlier test left on this logger.
    logging.getLogger("uvicorn.error").critical("the mute is lifted once the self-test returns")
    assert _server_records(caplog) == 1


def test_it_leaves_no_loop_running() -> None:
    with pytest.raises(RuntimeError):
        asyncio.get_running_loop()
    selftest_protocol_floor(*_floored())
    with pytest.raises(RuntimeError):
        asyncio.get_running_loop()
