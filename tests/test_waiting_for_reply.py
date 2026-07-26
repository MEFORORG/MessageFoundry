# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""'Waiting for Reply' per-message outbound display state + cosmetic display delay (BACKLOG #136,
ADR 0065 amendment).

DISPLAY ONLY: the MLLP outbound connector stamps a side-band ``_waiting_since`` marker AROUND its ACK
read (no framing/retry/ACK/delivery-path change), and reports ``waiting_for_reply(now)`` True only once
``waiting_display_delay`` has elapsed. The state surfaces through
``RegistryRunner.outbound_waiting_for_reply`` onto ``ConnectionRow.waiting_for_reply``. The marker is
stamped ONLY around an ACK read that actually happens, so it is inapplicable in no-ack mode (#136×#117).
SYNTHETIC HL7 only — no PHI."""

from __future__ import annotations

import asyncio
import time
from pathlib import Path

import pytest

from messagefoundry.config.models import ConnectorType, Destination, Source
from messagefoundry.config.wiring import (
    ConnectionSpec,
    Registry,
    WiringError,
    build_outbound_connection,
)
from messagefoundry.pipeline import Engine
from messagefoundry.pipeline.wiring_runner import _dest_config
from messagefoundry.transports.mllp import MLLPDestination, MLLPSource, build_ack

ADT = (
    "MSH|^~\\&|SENDINGAPP|SENDINGFAC|RECV|RFAC|20260604||ADT^A01|MSG1|P|2.5.1\r"
    "PID|1||100^^^H^MR||DOE^JANE\r"
)


def _mllp_dest(*, waiting_display_delay: float = 0.0, port: int = 2700) -> MLLPDestination:
    return MLLPDestination(
        Destination(
            name="OB",
            type=ConnectorType.MLLP,
            settings={"host": "127.0.0.1", "port": port, "timeout_seconds": 5},
            waiting_display_delay=waiting_display_delay,
        )
    )


# --- AC-10: the side-band marker + the display delay ------------------------------------------


def test_waiting_marker_respects_display_delay() -> None:
    """``waiting_for_reply(now)`` is True only while a reply is being awaited AND the display delay has
    elapsed — the cosmetic pre-display window, independent of any timeout."""
    conn = _mllp_dest(waiting_display_delay=2.0)
    assert conn.waiting_for_reply(100.0) is False  # not awaiting a reply
    conn._waiting_since = 100.0  # begin the ACK-read window
    assert conn.waiting_for_reply(101.0) is False  # 1.0s < 2.0s display delay → not yet shown
    assert conn.waiting_for_reply(102.0) is True  # delay elapsed → shown waiting
    assert conn.waiting_for_reply(105.0) is True
    conn._waiting_since = None  # reply resolved
    assert conn.waiting_for_reply(200.0) is False


def test_zero_delay_shows_immediately() -> None:
    conn = _mllp_dest(waiting_display_delay=0.0)
    conn._waiting_since = 500.0
    assert conn.waiting_for_reply(500.0) is True  # 0s delay → shown at once


async def test_send_stamps_and_clears_waiting_marker() -> None:
    """A real send stamps the marker while blocked on the ACK read and clears it once the reply
    resolves (the finally), proving the wrap is around the ACK read only and never leaks the state."""
    release = asyncio.Event()

    async def handler(raw: bytes) -> str:
        await release.wait()  # hold the ACK so the sender sits in its ACK-read window
        return build_ack(raw, code="AA")

    source = MLLPSource(Source(type=ConnectorType.MLLP, settings={"host": "127.0.0.1", "port": 0}))
    await source.start(handler)
    dest = _mllp_dest(port=source.sockport, waiting_display_delay=0.0)
    try:
        send_task = asyncio.create_task(dest.send(ADT))
        for _ in range(300):  # wait until the connector enters the ACK-read window (bounded)
            if dest.waiting_for_reply(time.monotonic()):
                break
            await asyncio.sleep(0.01)
        assert dest.waiting_for_reply(time.monotonic()) is True  # stamped while awaiting the ACK
        release.set()
        await send_task
        assert dest.waiting_for_reply(time.monotonic()) is False  # cleared once the reply resolved
    finally:
        release.set()
        await dest.aclose()
        await source.stop()


# --- config plumbing (factory → _dest_config → connector) --------------------------------------


def test_waiting_display_delay_threads_through_config() -> None:
    spec = ConnectionSpec(ConnectorType.MLLP, {"host": "127.0.0.1", "port": 2700})
    oc = build_outbound_connection("OB", spec, waiting_display_delay=3.0)
    assert oc.waiting_display_delay == 3.0
    dest = _dest_config(oc, {})
    assert dest.waiting_display_delay == 3.0
    assert MLLPDestination(dest).waiting_display_delay == 3.0


def test_negative_waiting_display_delay_rejected() -> None:
    spec = ConnectionSpec(ConnectorType.MLLP, {"host": "127.0.0.1", "port": 2700})
    with pytest.raises(WiringError, match="waiting_display_delay must be >= 0"):
        build_outbound_connection("OB", spec, waiting_display_delay=-1.0)


# --- the RegistryRunner probe (duck-typed) -----------------------------------------------------


async def test_runner_outbound_waiting_for_reply_duck_typed(tmp_path: Path) -> None:
    """``outbound_waiting_for_reply`` reads the live connector's marker; a connector without the method
    (File/REST/…) and an unknown name both report False (never raises)."""
    eng = await Engine.create(tmp_path / "w.db", poll_interval=0.02)
    try:
        runner = eng.add_registry(Registry())

        class _Waiter:
            def waiting_for_reply(self, now: float) -> bool:
                return True

            async def aclose(self) -> None:  # engine.stop() drains _destinations
                return None

        class _NoWaiter:
            async def aclose(self) -> None:
                return None

        runner._destinations["W"] = _Waiter()  # type: ignore[assignment]
        runner._destinations["N"] = _NoWaiter()  # type: ignore[assignment]
        assert runner.outbound_waiting_for_reply("W") is True
        assert runner.outbound_waiting_for_reply("N") is False  # no marker method → False
        assert runner.outbound_waiting_for_reply("missing") is False  # unknown → False
    finally:
        await eng.stop()
