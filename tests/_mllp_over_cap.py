# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Send MLLP frames past a frame cap, for the harness sink tests.

Shared by ``tests/test_load_sink.py`` and ``tests/test_reconcile_capture.py`` (ASVS 5.1.1, BACKLOG
#1127). Synthetic only: the caller supplies a made-up message header, padded with filler.
"""

from __future__ import annotations

import asyncio
import contextlib

from messagefoundry.transports.mllp import DEFAULT_MAX_FRAME_BYTES, frame


async def send_over_cap(port: int, message: str) -> bytes:
    """Send ``message`` padded to ``DEFAULT_MAX_FRAME_BYTES + 1`` in one frame, then read until the
    peer closes the connection or 10 s pass. Returns every byte the peer sent back."""
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    got = b""
    with contextlib.suppress(ConnectionError, OSError):  # TimeoutError is an OSError
        writer.write(frame(message + "X" * (DEFAULT_MAX_FRAME_BYTES + 1 - len(message))))
        await writer.drain()
        while chunk := await asyncio.wait_for(reader.read(65536), timeout=10.0):
            got += chunk
    writer.close()
    with contextlib.suppress(ConnectionError, OSError):
        await writer.wait_closed()
    return got


def valid_then_over_cap(message: str, cap: int) -> bytes:
    """Two pipelined frames in one buffer: ``message`` (at most ``cap`` bytes), then one a byte
    over ``cap``. Sent in one write, a sink reads both in one chunk, so the refusal lands in the
    same read as a frame it has already accepted."""
    assert len(message.encode()) <= cap
    return frame(message) + frame(message + "X" * (cap + 1 - len(message.encode())))


async def send_valid_then_over_cap(port: int, message: str, cap: int) -> tuple[bytes, bool]:
    """Send :func:`valid_then_over_cap` in one write, then read until the peer closes or 10 s pass.
    Returns every byte the peer sent back and whether it closed. A close is seen only after every
    byte sent before it, so an ACK in the bytes arrived before the close."""
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    got = b""
    closed = False
    try:
        writer.write(valid_then_over_cap(message, cap))
        await writer.drain()
        while chunk := await asyncio.wait_for(reader.read(65536), timeout=10.0):
            got += chunk
        closed = True
    except ConnectionError:
        closed = True  # a reset is a close too
    except TimeoutError:
        pass
    writer.close()
    with contextlib.suppress(ConnectionError, OSError):
        await writer.wait_closed()
    return got, closed
