# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #1725 act 3: ``max_inflight_frames`` bounds the MLLP listener's pre-ACK handling path.

A complete frame waits for one of the listener's in-flight slots before it enters the inbound
handler, and gives the slot back when the handler returns. These drive real sockets against a real
listener and instrument the handler itself, so "in the handling path" means exactly what the
handler sees. Every wait polls a condition under a bounded deadline rather than sleeping, so a slow
runner makes them slower, not red.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import time
from collections.abc import Callable

import pytest

from messagefoundry.config.models import ConnectorType, Source
from messagefoundry.config.wiring import MLLP
from messagefoundry.transports import mllp as mllp_mod
from messagefoundry.transports.mllp import MLLPSource, build_ack, frame

ADT = "MSH|^~\\&|S|F|R|RF|20260101||ADT^A01|MSG{n}|P|2.5.1\rPID|1||100^^^H^MR||DOE^JANE\r"


def _mllp(**extra: object) -> MLLPSource:
    return MLLPSource(
        Source(type=ConnectorType.MLLP, settings={"host": "127.0.0.1", "port": 0, **extra})
    )


async def _until(predicate: Callable[[], bool], what: str, *, within: float = 5.0) -> None:
    deadline = time.monotonic() + within
    while not predicate():
        if time.monotonic() > deadline:
            pytest.fail(what)
        await asyncio.sleep(0.01)


def _waiters(source: MLLPSource) -> int:
    """Frames queued for a slot. ``Semaphore._waiters`` is CPython-private; a rename fails the
    tests that read it loudly rather than letting them pass vacuously."""
    slots = getattr(source, "_inflight", None)
    if slots is None:
        return 0
    return len(slots._waiters or ())


class _GatedHandler:
    """An inbound handler that records every frame it is handed and holds the first until released,
    counting how many frames are inside it at once."""

    def __init__(self) -> None:
        self.entered: list[bytes] = []
        self.inside = 0
        self.peak = 0
        self.release_first = asyncio.Event()

    async def __call__(self, raw: bytes) -> str:
        self.entered.append(raw)
        self.inside += 1
        self.peak = max(self.peak, self.inside)
        try:
            if len(self.entered) == 1:
                await self.release_first.wait()
            return build_ack(raw, code="AA")
        finally:
            self.inside -= 1


async def _send(port: int, n: int) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    writer.write(frame(ADT.format(n=n)))
    await writer.drain()
    return reader, writer


async def _close(writer: asyncio.StreamWriter) -> None:
    writer.close()
    with contextlib.suppress(ConnectionError, TimeoutError):
        await asyncio.wait_for(writer.wait_closed(), timeout=5.0)


async def test_a_second_frame_waits_for_the_only_slot() -> None:
    handler = _GatedHandler()
    source = _mllp(max_inflight_frames=1)
    await source.start(handler)
    writers: list[asyncio.StreamWriter] = []
    try:
        r1, w1 = await _send(source.sockport, 1)
        writers.append(w1)
        await _until(lambda: len(handler.entered) == 1, "the first frame never reached the handler")
        r2, w2 = await _send(source.sockport, 2)
        writers.append(w2)
        # Either the second frame queues for the slot, or (before the fix) it walks straight in.
        await _until(
            lambda: _waiters(source) == 1 or len(handler.entered) == 2,
            "the second frame neither waited nor reached the handler",
        )
        assert len(handler.entered) == 1, "a second frame entered handling while the first held it"
        assert handler.peak == 1
        handler.release_first.set()
        # Both are then handled and acknowledged, in order, never two at once.
        assert b"MSA|AA" in await asyncio.wait_for(r1.read(4096), 5.0)
        assert b"MSA|AA" in await asyncio.wait_for(r2.read(4096), 5.0)
        assert handler.peak == 1
        assert [b"MSG1" in m for m in handler.entered] == [True, False]
        # The slot came back: nothing waits and nothing is held.
        assert source._inflight is not None and not source._inflight.locked()
        assert _waiters(source) == 0
    finally:
        for w in writers:
            await _close(w)
        await asyncio.wait_for(source.stop(), timeout=10.0)


async def test_stop_while_a_frame_waits_exits_cleanly(caplog: pytest.LogCaptureFixture) -> None:
    """A frame waiting for a slot gives up as soon as stop() begins. It is not handled and gets no
    ACK, so the sender retries it; stop() does not sit behind the slow handler to get there. The
    give-up is logged, since the connection's own `closed` event reads as a plain end."""
    handler = _GatedHandler()
    source = _mllp(max_inflight_frames=1)
    await source.start(handler)
    writers: list[asyncio.StreamWriter] = []
    stopper: asyncio.Task[None] | None = None
    try:
        _r1, w1 = await _send(source.sockport, 1)
        writers.append(w1)
        await _until(lambda: len(handler.entered) == 1, "the first frame never reached the handler")
        r2, w2 = await _send(source.sockport, 2)
        writers.append(w2)
        await _until(lambda: _waiters(source) == 1, "the second frame never queued for the slot")
        with caplog.at_level(logging.WARNING, logger="messagefoundry.transports.mllp"):
            stopper = asyncio.create_task(source.stop())
            # The waiter leaves at once, while the first frame still holds the only slot.
            await _until(lambda: _waiters(source) == 0, "the waiting frame did not give up")
            assert await asyncio.wait_for(r2.read(4096), 5.0) == b""  # closed, and no ACK
            assert len(handler.entered) == 1
            handler.release_first.set()
            await asyncio.wait_for(stopper, timeout=10.0)
        assert not source._client_tasks
        assert len(handler.entered) == 1  # the waiting frame was never handled
        assert "listener began stopping" in caplog.text
        assert "MSH" not in caplog.text  # socket metadata only, never frame bytes
    finally:
        handler.release_first.set()
        for w in writers:
            await _close(w)
        if stopper is None:
            await asyncio.wait_for(source.stop(), timeout=10.0)
        elif not stopper.done():
            await asyncio.wait_for(stopper, timeout=10.0)


async def test_a_waiting_frame_whose_sender_hung_up_is_not_handled(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """A sender that gives up waiting for its ACK resends on a new connection. Handling the copy that
    was still queued would commit a duplicate, so a waiter whose own connection closed leaves the
    queue instead, and the slot goes to the next frame."""
    monkeypatch.setattr(mllp_mod, "_INFLIGHT_POLL_SECONDS", 0.05)
    handler = _GatedHandler()
    source = _mllp(max_inflight_frames=1)
    await source.start(handler)
    writers: list[asyncio.StreamWriter] = []
    try:
        r1, w1 = await _send(source.sockport, 1)
        writers.append(w1)
        await _until(lambda: len(handler.entered) == 1, "the first frame never reached the handler")
        _r2, w2 = await _send(source.sockport, 2)
        await _until(lambda: _waiters(source) == 1, "the second frame never queued for the slot")
        with caplog.at_level(logging.WARNING, logger="messagefoundry.transports.mllp"):
            await _close(w2)  # the sender hangs up while its frame waits
            await _until(lambda: _waiters(source) == 0, "the hung-up frame kept its place")
        assert "connection closed" in caplog.text
        handler.release_first.set()
        assert b"MSA|AA" in await asyncio.wait_for(r1.read(4096), 5.0)
        # The next frame gets the slot; the hung-up one was never handled.
        r3, w3 = await _send(source.sockport, 3)
        writers.append(w3)
        assert b"MSA|AA" in await asyncio.wait_for(r3.read(4096), 5.0)
        assert [m.split(b"|")[9] for m in handler.entered] == [b"MSG1", b"MSG3"]
        assert source._inflight is not None and not source._inflight.locked()
    finally:
        handler.release_first.set()
        for w in writers:
            await _close(w)
        await asyncio.wait_for(source.stop(), timeout=10.0)


async def test_a_frame_that_finds_a_slot_free_is_handled_as_with_the_bound_off() -> None:
    """Only a frame that must WAIT gives up at stop(). One that finds a slot free takes it with no
    stop check, exactly as the listener behaves with the bound off, so stop semantics do not change
    with a memory setting."""
    source = _mllp(max_inflight_frames=4)
    received: list[bytes] = []

    async def handler(raw: bytes) -> str:
        received.append(raw)
        return build_ack(raw, code="AA")

    await source.start(handler)
    try:
        slots = source._inflight
        assert slots is not None
        source._stopping = True  # as stop() leaves it, without closing anything yet
        reader = asyncio.StreamReader()
        assert await source._take_inflight_slot(slots, reader, None) is None  # type: ignore[arg-type]
        slots.release()
    finally:
        source._stopping = False
        await asyncio.wait_for(source.stop(), timeout=10.0)


async def test_a_handler_fault_gives_its_slot_back() -> None:
    """The slot is released however the handler ends, or one fault would wedge a one-slot listener."""
    calls: list[bytes] = []

    async def faulty(raw: bytes) -> str:
        calls.append(raw)
        if len(calls) == 1:
            raise RuntimeError("store outage")
        return build_ack(raw, code="AA")

    source = _mllp(max_inflight_frames=1)
    await source.start(faulty)
    try:
        r1, w1 = await _send(source.sockport, 1)
        await asyncio.wait_for(r1.read(4096), 5.0)  # the fixed-text NAK, then the close
        await _close(w1)
        r2, w2 = await _send(source.sockport, 2)
        assert b"MSA|AA" in await asyncio.wait_for(r2.read(4096), 5.0)
        await _close(w2)
        assert source._inflight is not None and not source._inflight.locked()
    finally:
        await asyncio.wait_for(source.stop(), timeout=10.0)


def test_the_default_ships_on_and_every_off_spelling_turns_it_off() -> None:
    assert _mllp().max_inflight_frames == mllp_mod.DEFAULT_MAX_INFLIGHT_FRAMES == 32
    # An eighth of the socket cap, the ratio the per-host cap uses.
    assert mllp_mod.DEFAULT_MAX_INFLIGHT_FRAMES * 8 == mllp_mod.DEFAULT_MAX_CONNECTIONS
    settings = MLLP(port=2575).settings
    assert settings["max_inflight_frames"] == mllp_mod.DEFAULT_MAX_INFLIGHT_FRAMES
    for off in (None, 0, "0"):
        assert _mllp(max_inflight_frames=off).max_inflight_frames is None
    with pytest.raises(ValueError, match="max_inflight_frames"):
        _mllp(max_inflight_frames=-1)


async def test_off_means_no_slots_at_all() -> None:
    source = _mllp(max_inflight_frames=0)
    await source.start(lambda raw: asyncio.sleep(0, build_ack(raw, code="AA")))
    try:
        assert source._inflight is None
    finally:
        await asyncio.wait_for(source.stop(), timeout=10.0)


def test_the_setting_is_marked_inbound_only_for_the_gui() -> None:
    from messagefoundry.config.connection_schema import build_schema

    param = build_schema()["transports"]["mllp"]["params"]["max_inflight_frames"]
    assert param["direction"] == "inbound"
    assert param["default"] == mllp_mod.DEFAULT_MAX_INFLIGHT_FRAMES
