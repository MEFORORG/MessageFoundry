# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The ``/ws/stats`` socket cap holds when handshakes arrive together (vault BACKLOG #2775).

``ws_stats`` used to check its count, await ``websocket.accept()``, and only then add one. uvicorn's
accept waits for the handshake to finish, so every handshake that reached the check before any
accept returned passed it. These tests hold every accept open at once, which is that window made
deterministic, and drive the real ASGI callable with a hand-built scope, as
``tests/test_ws_handshake_header_floor.py`` does.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator, Awaitable, Callable
from pathlib import Path

import pytest
from starlette.types import Message, Scope

from messagefoundry.api import app as api_app
from messagefoundry.api import create_app
from messagefoundry.api.header_floor import WEBSOCKET_DENIAL_EXTENSION
from messagefoundry.config.settings import EgressSettings
from messagefoundry.pipeline import Engine


@pytest.fixture
async def engine(tmp_path: Path) -> AsyncIterator[Engine]:
    eng = await Engine.create(
        tmp_path / "wscap.db",
        poll_interval=0.02,
        egress_settings=EgressSettings(deny_by_default=False),
    )
    yield eng
    await eng.stop()


def _scope(port: int) -> Scope:
    return {
        "type": "websocket",
        "asgi": {"version": "3.0"},
        "path": "/ws/stats",
        "raw_path": b"/ws/stats",
        "root_path": "",
        "headers": [(b"host", b"ops.example.com")],
        "query_string": b"",
        "subprotocols": [],
        "client": ("127.0.0.1", port),
        "server": ("127.0.0.1", 8765),
        "scheme": "ws",
        "extensions": {WEBSOCKET_DENIAL_EXTENSION: {}},
    }


async def _receive() -> Message:
    return {"type": "websocket.connect"}


async def test_concurrent_handshakes_cannot_pass_the_cap(
    engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Five handshakes against a cap of two, every accept held open until all five are decided.
    Exactly two may reach accept and three must be refused with the 503. Before the fix all five
    reached accept, because none had added to the count yet."""
    monkeypatch.setattr(api_app, "_MAX_WS_CONNECTIONS", 2)
    app = create_app(engine, allow_no_auth=True)
    release = asyncio.Event()
    accepted: list[int] = []
    refused: list[int] = []
    decided = asyncio.Event()
    total = 5

    def _decide() -> None:
        if len(accepted) + len(refused) == total:
            decided.set()

    def make_send(port: int) -> Callable[[Message], Awaitable[None]]:
        async def send(message: Message) -> None:
            if message["type"] == "websocket.accept":
                accepted.append(port)
                _decide()
                await release.wait()  # the handshake is still completing
            elif message["type"] == "websocket.http.response.start":
                refused.append(message["status"])
                _decide()
            elif message["type"] == "websocket.send":
                raise OSError("the peer went away")  # ends the push loop as a disconnect

        return send

    runs = [
        asyncio.create_task(app(_scope(port), _receive, make_send(port)))
        for port in range(40000, 40000 + total)
    ]
    try:
        await asyncio.wait_for(decided.wait(), 5.0)
        assert len(accepted) == 2 and refused == [503, 503, 503], (accepted, refused)
        assert app.state.ws_count == 2
    finally:
        # Let every held accept finish even when an assertion above failed, so no task is leaked.
        release.set()
        await asyncio.wait_for(asyncio.gather(*runs, return_exceptions=True), 5.0)
    assert app.state.ws_count == 0


async def test_an_accept_that_raises_gives_the_slot_back(
    engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The slot is taken before ``accept()``, so a failed accept must return it: three failed
    handshakes against a cap of one leave the count at zero, and a fourth is still admitted. A
    guard for the new ``finally`` path: the old code passes it too, because it counted only after
    a successful accept."""
    monkeypatch.setattr(api_app, "_MAX_WS_CONNECTIONS", 1)
    app = create_app(engine, allow_no_auth=True)

    async def failing_send(message: Message) -> None:
        if message["type"] == "websocket.accept":
            raise OSError("the handshake failed")

    for port in range(41000, 41003):
        with pytest.raises(OSError):
            await asyncio.wait_for(app(_scope(port), _receive, failing_send), 5.0)
        assert app.state.ws_count == 0

    sent: list[str] = []

    async def send(message: Message) -> None:
        sent.append(message["type"])
        if message["type"] == "websocket.send":
            raise OSError("the peer went away")

    await asyncio.wait_for(app(_scope(41003), _receive, send), 5.0)
    assert sent[0] == "websocket.accept", sent
    assert app.state.ws_count == 0
