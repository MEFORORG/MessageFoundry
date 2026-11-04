# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""One peer reset must not stop a listener on the Windows Proactor loop.

On the stdlib ``ProactorEventLoop``, the accept loop ``asyncio.start_server`` and
``loop.create_server`` run closes its listening socket on the first failed AcceptEx. A connection
its peer resets while it waits in the backlog fails AcceptEx with ERROR_NETNAME_DELETED (winerror
64), so one such peer stopped every listener for good, while the server still read as serving.
``messagefoundry.proactor_accept`` guards it.

The fault is real, not faked: :func:`_reset_one_in_the_backlog` blocks the loop while one client
takes the single pending AcceptEx and a second waits in the backlog and resets there with
``SO_LINGER`` 0. The controls run the same steps without the guard and show the listening socket
closed, so the fault demonstrably fired. Each loop test runs on a fresh ``ProactorEventLoop``,
because the suite's session loop may already carry the guard from another test.

Synthetic HL7 only, never real PHI.
"""

from __future__ import annotations

import asyncio
import contextlib
import errno
import logging
import socket
import struct
import sys
import time
from collections.abc import AsyncIterator, Callable, Coroutine, Iterator
from typing import Any

import pytest

from messagefoundry import proactor_accept
from messagefoundry.proactor_accept import _guarded, _peer_dropped, guard_accepts
from messagefoundry.transports.base import SourceConnector
from messagefoundry.transports.mllp import CR, EB, frame
from messagefoundry.transports.receipt import receipt_handler
from tests.test_listener_admission import _ack_handler, _build, _Events, _until

_ADT = "MSH|^~\\&|S|F|R|RF|20260101||ADT^A01|MSG1|P|2.5.1\rPID|1||100^^^H^MR||DOE^JANE\r"

windows_only = pytest.mark.skipif(
    sys.platform != "win32", reason="the Proactor loop is Windows-only"
)


def _on_fresh_proactor[T](make: Callable[[], Coroutine[Any, Any, T]]) -> T:
    """Run ``make()`` on a new stdlib ``ProactorEventLoop`` that no earlier test has guarded."""
    with asyncio.Runner(loop_factory=asyncio.ProactorEventLoop) as runner:  # type: ignore[attr-defined,unused-ignore]
        return runner.run(make())


def _block_and_reset(port: int) -> socket.socket:
    """Connect twice while the loop is blocked, and reset the second connection in the backlog.

    The first connection completes the one AcceptEx the listener has posted. The loop cannot post
    the next until it runs again, so the second waits in the backlog, and its reset lands there.
    The next AcceptEx then fails with winerror 64. Returns the first connection."""
    first = socket.create_connection(("127.0.0.1", port))
    second = socket.create_connection(("127.0.0.1", port))
    second.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("hh", 1, 0))
    second.close()
    time.sleep(0.2)  # let the reset reach the listener's backlog before the loop runs again
    return first


@contextlib.asynccontextmanager
async def _reset_one_in_the_backlog(listening: socket.socket) -> AsyncIterator[None]:
    """:func:`_block_and_reset` on ``listening``'s port, once its first AcceptEx is posted, and
    the first connection closed on exit."""
    await asyncio.sleep(0.1)  # the accept loop posts its first AcceptEx on the next iteration
    first = _block_and_reset(listening.getsockname()[1])
    try:
        yield
    finally:
        first.close()


@contextlib.asynccontextmanager
async def _bare_listener(
    guard: bool,
) -> AsyncIterator[tuple[list[object], list[dict[str, Any]], socket.socket]]:
    """A bare ``asyncio.start_server`` listener after one backlog reset: what it accepted, what the
    loop's exception handler was given, and its listening socket."""
    loop = asyncio.get_running_loop()
    reported: list[dict[str, Any]] = []
    loop.set_exception_handler(lambda _loop, context: reported.append(context))
    if guard:
        guard_accepts()
    accepted: list[object] = []

    async def on_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        accepted.append(writer.get_extra_info("peername"))
        writer.close()

    server = await asyncio.start_server(on_client, "127.0.0.1", 0)
    listening = server.sockets[0]
    try:
        async with _reset_one_in_the_backlog(listening):
            yield accepted, reported, listening
    finally:
        server.close()


@windows_only
def test_control_one_backlog_reset_closes_an_unguarded_stdlib_listener() -> None:
    # Pins the stdlib defect the guard exists for, and that the reset above really fires it.
    async def run() -> None:
        async with _bare_listener(guard=False) as (accepted, reported, listening):
            assert await _until(lambda: listening.fileno() == -1, timeout=5.0)
            failed = [c for c in reported if c.get("message") == "Accept failed on a socket"]
            assert failed, reported
            assert getattr(failed[0]["exception"], "winerror", None) == 64
            assert len(accepted) == 1  # only the connection that took the first AcceptEx

    _on_fresh_proactor(run)


@windows_only
def test_a_guarded_listener_skips_the_reset_connection_and_accepts_the_next(
    caplog: pytest.LogCaptureFixture,
) -> None:
    async def run() -> None:
        with caplog.at_level(logging.DEBUG, logger=proactor_accept.__name__):
            async with _bare_listener(guard=True) as (accepted, reported, listening):
                assert await _until(lambda: "peer dropped before the accept" in caplog.text, 5.0)
                assert listening.fileno() != -1
                _reader, writer = await asyncio.open_connection(
                    "127.0.0.1", listening.getsockname()[1]
                )
                assert await _until(lambda: len(accepted) == 2, timeout=5.0), accepted
                writer.close()
                assert reported == [], reported  # nothing reported the skipped accept again

    _on_fresh_proactor(run)


_SOURCES = ("http", "mllp", "tcp", "x12")


@contextlib.asynccontextmanager
async def _source_after_a_reset(
    name: str, monkeypatch: pytest.MonkeyPatch, guard: bool
) -> AsyncIterator[tuple[SourceConnector, _Events, socket.socket]]:
    source = _build(name)
    if not guard:
        monkeypatch.setattr(sys.modules[type(source).__module__], "guard_accepts", lambda: None)
    events = _Events()
    source.on_connection_event = events
    # Marked as a receipt handler, so the HTTP listener starts with it too; it never sees a request.
    await source.start(receipt_handler(_ack_handler))
    try:
        listening = source._server.sockets[0]  # type: ignore[attr-defined]
        async with _reset_one_in_the_backlog(listening):
            yield source, events, listening
    finally:
        await asyncio.wait_for(source.stop(), timeout=10.0)


@windows_only
@pytest.mark.parametrize("name", _SOURCES)
def test_control_an_engine_listener_without_the_guard_dies_on_one_reset(
    name: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def run() -> None:
        async with _source_after_a_reset(name, monkeypatch, guard=False) as (_s, _e, listening):
            assert await _until(lambda: listening.fileno() == -1, timeout=5.0)

    _on_fresh_proactor(run)


@windows_only
@pytest.mark.parametrize("name", _SOURCES)
def test_an_engine_listener_survives_one_reset_and_takes_the_next_connection(
    name: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def run() -> None:
        async with _source_after_a_reset(name, monkeypatch, guard=True) as (
            source,
            events,
            listening,
        ):
            reader, writer = await asyncio.open_connection("127.0.0.1", source.sockport)  # type: ignore[attr-defined]
            # The first connection and this one; the reset one never became a connection.
            assert await _until(lambda: events.count("established") == 2, 5.0), events.events
            assert listening.fileno() != -1
            if name == "mllp":
                writer.write(frame(_ADT))
                await writer.drain()
                reply = await asyncio.wait_for(reader.readuntil(bytes([EB, CR])), 5.0)
                assert b"MSA|AA|MSG1" in reply
            writer.close()

    _on_fresh_proactor(run)


async def _api_survives_a_reset(guard: bool) -> bool:
    """uvicorn, as ``serve`` runs it, after one backlog reset: whether it still answers. The ASGI
    lifespan installs the guard where the engine API's lifespan does, before uvicorn binds."""
    import uvicorn

    async def app(scope: dict[str, Any], receive: Any, send: Any) -> None:
        if scope["type"] == "lifespan":
            while True:
                message = await receive()
                if message["type"] == "lifespan.startup":
                    if guard:
                        guard_accepts()
                    await send({"type": "lifespan.startup.complete"})
                elif message["type"] == "lifespan.shutdown":
                    await send({"type": "lifespan.shutdown.complete"})
                    return
        await send({"type": "http.response.start", "status": 204, "headers": []})
        await send({"type": "http.response.body", "body": b""})

    server = uvicorn.Server(
        uvicorn.Config(app, host="127.0.0.1", port=0, log_level="critical", lifespan="on")
    )
    task = asyncio.create_task(server.serve())
    try:
        assert await _until(lambda: server.started, timeout=20.0)
        listening = server.servers[0].sockets[0]
        async with _reset_one_in_the_backlog(listening):
            await asyncio.sleep(0.3)  # let the loop take the failed accept
            if listening.fileno() == -1:
                return False
            reader, writer = await asyncio.open_connection("127.0.0.1", listening.getsockname()[1])
            writer.write(b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
            await writer.drain()
            assert (await asyncio.wait_for(reader.read(), 5.0)).startswith(b"HTTP/1.1 204")
            writer.close()
            return True
    finally:
        server.should_exit = True
        await asyncio.wait_for(task, timeout=20.0)


@windows_only
def test_control_the_api_listener_uvicorn_runs_dies_on_one_reset_without_the_guard() -> None:
    assert _on_fresh_proactor(lambda: _api_survives_a_reset(guard=False)) is False


@windows_only
def test_the_api_listener_survives_one_reset_with_the_guard_installed_in_its_lifespan() -> None:
    assert _on_fresh_proactor(lambda: _api_survives_a_reset(guard=True)) is True


# The guard's own logic, with a fake accept: these run on every platform.


class _FakeAccept:
    """An ``accept`` whose every call returns a future the test settles."""

    def __init__(
        self, loop: asyncio.AbstractEventLoop, *, raise_on_call: int | None = None
    ) -> None:
        self.loop = loop
        self.futures: list[asyncio.Future[tuple[socket.socket, Any]]] = []
        self.raise_on_call = raise_on_call

    def __call__(self, listener: socket.socket) -> asyncio.Future[tuple[socket.socket, Any]]:
        if self.raise_on_call is not None and len(self.futures) + 1 == self.raise_on_call:
            raise OSError(errno.EBADF, "listener gone")
        future: asyncio.Future[tuple[socket.socket, Any]] = self.loop.create_future()
        self.futures.append(future)
        return future


@contextlib.contextmanager
def _guarded_fake(
    raise_on_call: int | None = None,
) -> Iterator[tuple[_FakeAccept, socket.socket, asyncio.Future[tuple[socket.socket, Any]]]]:
    """A guarded accept on an open loopback socket: yields the fake, the listener and the future."""
    loop = asyncio.get_running_loop()
    fake = _FakeAccept(loop, raise_on_call=raise_on_call)
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        yield fake, listener, _guarded(loop, fake)(listener)


def _winerror(code: int) -> OSError:
    exc = OSError(errno.EINVAL, "synthetic accept failure")
    exc.winerror = code  # type: ignore[attr-defined,unused-ignore]  # win32 declares it
    return exc


def test_peer_dropped_reads_the_windows_codes_and_connection_errors() -> None:
    assert _peer_dropped(_winerror(64))
    assert _peer_dropped(_winerror(1236))
    assert _peer_dropped(ConnectionResetError())
    assert _peer_dropped(ConnectionAbortedError())
    assert not _peer_dropped(_winerror(10038))  # WSAENOTSOCK: the listener itself
    assert not _peer_dropped(OSError(errno.EINVAL, "no winerror"))
    assert not _peer_dropped(RuntimeError())


async def test_a_peer_dropped_accept_is_posted_again_and_the_next_result_returned() -> None:
    with _guarded_fake() as (fake, _listener, outer):
        fake.futures[0].set_exception(_winerror(64))
        assert await _until(lambda: len(fake.futures) == 2)
        assert not outer.done()
        fake.futures[1].set_exception(ConnectionResetError())
        assert await _until(lambda: len(fake.futures) == 3)
        sentinel: tuple[Any, Any] = (object(), ("127.0.0.1", 1))
        fake.futures[2].set_result(sentinel)
        assert await asyncio.wait_for(outer, 1.0) is sentinel


async def test_any_other_accept_failure_reaches_the_caller_unchanged() -> None:
    with _guarded_fake() as (fake, _listener, outer):
        fault = _winerror(10038)
        fake.futures[0].set_exception(fault)
        with pytest.raises(OSError) as raised:
            await asyncio.wait_for(outer, 1.0)
        assert raised.value is fault
        assert len(fake.futures) == 1  # not posted again


async def test_a_peer_drop_on_a_closed_listener_is_not_retried() -> None:
    with _guarded_fake() as (fake, listener, outer):
        listener.close()
        fake.futures[0].set_exception(_winerror(64))
        with pytest.raises(OSError):
            await asyncio.wait_for(outer, 1.0)
        assert len(fake.futures) == 1


async def test_a_repost_that_fails_synchronously_fails_the_accept() -> None:
    with _guarded_fake(raise_on_call=2) as (fake, _listener, outer):
        fake.futures[0].set_exception(_winerror(64))
        with pytest.raises(OSError) as raised:
            await asyncio.wait_for(outer, 1.0)
        assert raised.value.errno == errno.EBADF


async def test_the_first_post_raises_synchronously_as_the_unguarded_call_does() -> None:
    with pytest.raises(OSError), _guarded_fake(raise_on_call=1):
        pass


async def test_cancelling_the_accept_cancels_the_try_in_flight() -> None:
    with _guarded_fake() as (fake, _listener, outer):
        fake.futures[0].set_exception(_winerror(64))
        assert await _until(lambda: len(fake.futures) == 2)
        outer.cancel()
        assert await _until(lambda: fake.futures[1].cancelled())


async def test_a_cancelled_try_cancels_the_accept() -> None:
    with _guarded_fake() as (fake, _listener, outer):
        fake.futures[0].cancel()
        assert await _until(outer.cancelled)


@windows_only
def test_the_guard_is_idempotent() -> None:
    async def run() -> None:
        proactor = asyncio.get_running_loop()._proactor  # type: ignore[attr-defined]
        unguarded = proactor.accept
        guard_accepts()
        wrapped = proactor.accept
        assert wrapped is not unguarded
        guard_accepts()
        assert proactor.accept is wrapped

    _on_fresh_proactor(run)


def test_the_guard_leaves_a_selector_loop_alone() -> None:
    async def run() -> None:
        loop = asyncio.get_running_loop()
        guard_accepts()  # must not raise on a loop with no proactor
        assert type(loop) is asyncio.SelectorEventLoop

    with asyncio.Runner(loop_factory=asyncio.SelectorEventLoop) as runner:
        runner.run(run())
