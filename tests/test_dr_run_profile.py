# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The DR run-profile (#61, ADR 0048 half (b)): under a threshold X the engine binds only inbound
listeners and builds only outbound connectors whose resolved priority rank >= X (AC-2); the below-
threshold connections report status:"filtered" — a fifth status distinct from ADR 0031's "failed" — and
their router/transform workers still spawn so a crash-recovered backlog drains (AC-3). A normal
deployment (no DR threshold) is byte-identical: every connection starts subject only to ADR 0031."""

from __future__ import annotations

import asyncio
import socket
from pathlib import Path

import pytest

from messagefoundry.config.models import ConnectorType, Priority
from messagefoundry.config.wiring import (
    MLLP,
    ConnectionSpec,
    Registry,
    Send,
    build_inbound_connection,
    build_outbound_connection,
)
from messagefoundry.pipeline.wiring_runner import RegistryRunner
from messagefoundry.store import MessageStatus, MessageStore

ADT = (
    "MSH|^~\\&|S|F|R|RF|20260604||ADT^A01|MSG1|P|2.5.1\r"
    "EVN|A01|20260604\r"
    "PID|1||100^^^H^MR||DOE^JANE\r"
)


def _free_port() -> int:
    s = socket.socket()
    try:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])
    finally:
        s.close()


@pytest.fixture
async def store(tmp_path: Path):
    s = await MessageStore.open(tmp_path / "dr.db")
    yield s
    await s.close()


async def test_startup_filters_below_threshold(store: MessageStore, tmp_path: Path) -> None:
    # AC-2: with threshold=CRITICAL, only the critical inbound binds + the critical outbound builds; the
    # normal/low ones are parked status:"filtered". AC-4: filtered is distinct from failed.
    crit_port, norm_port = _free_port(), _free_port()
    reg = Registry()
    reg.add_inbound(
        build_inbound_connection(
            "in_crit", MLLP(port=crit_port), router="r", priority=Priority.CRITICAL
        )
    )
    reg.add_inbound(
        build_inbound_connection(
            "in_norm", MLLP(port=norm_port), router="r", priority=Priority.NORMAL
        )
    )
    reg.add_outbound(
        build_outbound_connection(
            "out_crit",
            ConnectionSpec(
                ConnectorType.FILE, {"directory": str(tmp_path), "filename": "{MSH-10}.hl7"}
            ),
            priority=Priority.CRITICAL,
        )
    )
    reg.add_outbound(
        build_outbound_connection(
            "out_low",
            ConnectionSpec(
                ConnectorType.FILE, {"directory": str(tmp_path), "filename": "{MSH-10}.hl7"}
            ),
            priority=Priority.LOW,
        )
    )
    reg.add_router("r", lambda m: [])
    runner = RegistryRunner(reg, store, poll_interval=0.02, dr_threshold=Priority.CRITICAL)
    await runner.start()
    try:
        assert runner.running
        # The critical inbound is listening; the normal one is parked (filtered), NOT listening, NOT failed.
        assert runner.inbound_running("in_crit")
        assert not runner.inbound_running("in_norm")
        assert "in_norm" in runner.filtered_inbound()
        assert runner.inbound_filtered("in_norm") is not None
        assert runner.inbound_failed("in_norm") is None  # filtered != failed (AC-4)
        assert "in_crit" not in runner.filtered_inbound()
        # The critical outbound built (a live connector); the low one is parked.
        assert "out_low" in runner.filtered_outbound()
        assert "out_crit" not in runner.filtered_outbound()
        # No connection is recorded as a fault (filtered is a deliberate skip, not a failure).
        assert not runner.degraded_inbound() and not runner.degraded_outbound()
    finally:
        await runner.stop()


async def test_no_dr_threshold_starts_everything(store: MessageStore, tmp_path: Path) -> None:
    # Without a DR run-profile (dr_threshold=None — the normal deployment), EVERY connection starts
    # subject only to ADR 0031, regardless of its priority tier. Byte-identical to before this seam.
    low_port = _free_port()
    reg = Registry()
    reg.add_inbound(
        build_inbound_connection("in_low", MLLP(port=low_port), router="r", priority=Priority.LOW)
    )
    reg.add_router("r", lambda m: [])
    runner = RegistryRunner(reg, store, poll_interval=0.02)  # dr_threshold defaults to None
    await runner.start()
    try:
        assert runner.inbound_running("in_low")  # a low-priority feed runs normally (no DR profile)
        assert not runner.filtered_inbound() and not runner.filtered_outbound()
    finally:
        await runner.stop()


async def test_filtered_inbound_drains_backlog(store: MessageStore, tmp_path: Path) -> None:
    # AC-3: a DR-filtered inbound's listener is NOT bound, but its router + transform workers still spawn,
    # so a crash-recovered ingress backlog (a row already committed at ingress before the DR restart) is
    # drained to delivery — the DR box still processes what it was already holding for that feed.
    outdir = tmp_path / "out"
    outdir.mkdir()
    norm_port = _free_port()
    reg = Registry()
    reg.add_inbound(
        build_inbound_connection(
            "in_norm", MLLP(port=norm_port), router="r", priority=Priority.NORMAL
        )
    )
    reg.add_outbound(
        build_outbound_connection(
            "out",
            ConnectionSpec(
                ConnectorType.FILE, {"directory": str(outdir), "filename": "{MSH-10}.hl7"}
            ),
            priority=Priority.CRITICAL,  # the destination is critical so it delivers under the profile
        )
    )
    reg.add_router("r", lambda m: ["h"])
    reg.add_handler("h", lambda m: Send("out", m))

    # Pre-seed an ingress row for the (about-to-be-filtered) inbound, simulating a backlog carried in the
    # cold-restored store from before the DR restart.
    await store.enqueue_ingress(
        channel_id="in_norm",
        raw=ADT,
        control_id="MSG1",
        message_type="ADT^A01",
        summary="DOE^JANE",
        now=1.0,
    )

    runner = RegistryRunner(reg, store, poll_interval=0.02, dr_threshold=Priority.CRITICAL)
    await runner.start()
    try:
        # The listener is parked (filtered), but the workers run and drain the pre-seeded backlog to the
        # (critical) outbound, finalizing the message — proving the dark feed's residue is not stranded.
        assert not runner.inbound_running("in_norm")
        assert "in_norm" in runner.filtered_inbound()

        async def _processed() -> bool:
            return bool(
                await store.list_messages(
                    channel_id="in_norm", status=MessageStatus.PROCESSED.value
                )
            )

        elapsed = 0.0
        while not await _processed():
            await asyncio.sleep(0.05)
            elapsed += 0.05
            assert elapsed < 10.0, "filtered inbound's backlog did not drain"
        # The delivered file exists too.
        assert (outdir / "MSG1.hl7").exists()
    finally:
        await runner.stop()


async def test_same_name_inbound_and_outbound_park_independently(
    store: MessageStore, tmp_path: Path
) -> None:
    # The DR park marker is keyed by DIRECTION, for the same reason the ADR 0031 failure marker is: a
    # name may be both an inbound and an outbound (Registry._add is per-table), and here the two halves
    # resolve against the threshold INDEPENDENTLY - each reads its own priority - so they can genuinely
    # disagree. start() builds every outbound before any inbound, so under a bare-name key the
    # at/above-threshold inbound's clear-the-marker pop ERASED its below-threshold outbound namesake's
    # park: the parked destination reported no status:"filtered" and no reason, and rows routed to it
    # queued behind a connector-less lane with nothing saying it was parked on purpose.
    port = _free_port()
    reg = Registry()
    reg.add_inbound(
        build_inbound_connection("SHARED", MLLP(port=port), router="r", priority=Priority.CRITICAL)
    )
    reg.add_outbound(
        build_outbound_connection(
            "SHARED",
            ConnectionSpec(
                ConnectorType.FILE, {"directory": str(tmp_path), "filename": "{MSH-10}.hl7"}
            ),
            priority=Priority.LOW,
        )
    )
    reg.add_router("r", lambda m: [])
    runner = RegistryRunner(reg, store, poll_interval=0.02, dr_threshold=Priority.CRITICAL)
    await runner.start()
    try:
        # The critical inbound binds; the low outbound is parked, and says so.
        assert runner.inbound_running("SHARED")
        assert runner.inbound_filtered("SHARED") is None
        assert runner.filtered_inbound() == {}
        reason = runner.outbound_filtered("SHARED")
        assert reason and "below" in reason
        assert runner.filtered_outbound() == {"SHARED": reason}
        # Parked is not failed, in either direction (AC-4).
        assert not runner.degraded_inbound() and not runner.degraded_outbound()
        # A parked outbound has no live connector, and the inbound namesake must not make one appear.
        assert "SHARED" not in runner._destinations
    finally:
        await runner.stop()
