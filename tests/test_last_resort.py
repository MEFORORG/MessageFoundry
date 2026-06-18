# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""WP-L3-19: process-level last-resort error handling (ASVS 16.5.4).

Verifies the asyncio loop handler + sys.excepthook route an otherwise-unhandled exception through
``safe_exc`` (PHI-redacted, type-preserving) → the log, and that a framed listener (MLLP) survives a
handler that raises — the error is logged redacted, the connection drops, the server stays up.
"""

from __future__ import annotations

import asyncio
import logging

import pytest

from messagefoundry.config.models import ConnectorType, Source
from messagefoundry.last_resort import (
    _excepthook,
    install_excepthook,
    install_loop_exception_handler,
)
from messagefoundry.transports.mllp import MLLPSource, frame

# A PHI-bearing HL7 fragment to embed in raised exceptions; must never reach a log line.
PHI = "PID|1||100^^^H^MR||DOE^JANE"


async def test_loop_handler_logs_unhandled_exception_redacted(
    caplog: pytest.LogCaptureFixture,
) -> None:
    loop = asyncio.get_running_loop()
    original = loop.get_exception_handler()
    install_loop_exception_handler()
    try:

        def boom() -> None:
            raise ValueError(PHI)  # a callback that raises → the loop calls our exception handler

        with caplog.at_level(logging.ERROR):
            loop.call_soon(boom)
            await asyncio.sleep(0.05)  # let the callback run and the handler fire
    finally:
        loop.set_exception_handler(original)
    logged = " ".join(r.getMessage() for r in caplog.records)
    assert "last-resort" in logged and "ValueError" in logged  # type kept
    assert "DOE" not in logged and "JANE" not in logged  # PHI redacted by safe_exc


def test_excepthook_redacts_and_passes_keyboard_interrupt(
    caplog: pytest.LogCaptureFixture,
) -> None:
    err = RuntimeError(PHI)
    with caplog.at_level(logging.CRITICAL):
        _excepthook(type(err), err, err.__traceback__)
    logged = " ".join(r.getMessage() for r in caplog.records)
    assert "uncaught exception" in logged and "RuntimeError" in logged
    assert "DOE" not in logged  # PHI redacted

    # KeyboardInterrupt delegates to the default hook (clean Ctrl-C), not our redacted-error path.
    caplog.clear()
    ki = KeyboardInterrupt()
    with caplog.at_level(logging.CRITICAL):
        _excepthook(type(ki), ki, None)
    assert not caplog.records  # nothing logged as an error for a clean interrupt


def test_install_excepthook_sets_sys_hook() -> None:
    import sys

    original = sys.excepthook
    try:
        install_excepthook()
        assert sys.excepthook is _excepthook
    finally:
        sys.excepthook = original


async def test_mllp_handler_exception_is_caught_and_redacted(
    caplog: pytest.LogCaptureFixture,
) -> None:
    async def boom(raw: bytes) -> str:
        raise ValueError(PHI)  # an unexpected handler failure carrying PHI

    source = MLLPSource(Source(type=ConnectorType.MLLP, settings={"host": "127.0.0.1", "port": 0}))
    await source.start(boom)
    try:
        with caplog.at_level(logging.ERROR):
            reader, writer = await asyncio.open_connection("127.0.0.1", source.sockport)
            writer.write(frame("MSH|^~\\&|s|f|r|rf|20260616||ADT^A01|1|P|2.5.1\rPID|1||x"))
            await writer.drain()
            # the listener catches the handler error, logs it, and drops the connection → EOF
            assert await asyncio.wait_for(reader.read(), timeout=5) == b""
            writer.close()
            await writer.wait_closed()
        # the server survived — it still accepts a fresh connection
        r2, w2 = await asyncio.open_connection("127.0.0.1", source.sockport)
        w2.close()
        await w2.wait_closed()
    finally:
        await source.stop()
    logged = " ".join(r.getMessage() for r in caplog.records)
    assert "failed unexpectedly" in logged and "ValueError" in logged  # caught + type kept
    assert "DOE" not in logged and "JANE" not in logged  # PHI redacted
