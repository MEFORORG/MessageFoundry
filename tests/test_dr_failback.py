# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""DR fail-back (#61, ADR 0048 AC-11): POST /dr/release is drain-then-hand-back — it releases the VIP,
unbinds all inbound listeners, and drains the staged queue to completion before returning success (no
dual-accept window). Within the DR store at-least-once + idempotency are preserved across the hand-back
(every queued row is delivered, none dropped); cross-store reconciliation is operator-verified (not an
engine guarantee). Driven through the real Engine callbacks the DR coordinator invokes."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from pathlib import Path

import pytest

from messagefoundry.config.models import ConnectorType, Priority
from messagefoundry.config.settings import DrSettings, StoreSettings
from messagefoundry.config.wiring import (
    MLLP,
    ConnectionSpec,
    Registry,
    Send,
    build_inbound_connection,
    build_outbound_connection,
)
from messagefoundry.pipeline import Engine
from messagefoundry.store import MessageStatus, MessageStore

ADT = (
    "MSH|^~\\&|S|F|R|RF|20260604||ADT^A01|FBMSG1|P|2.5.1\r"
    "EVN|A01|20260604\r"
    "PID|1||100^^^H^MR||DOE^JANE\r"
)


@pytest.fixture
async def engine(tmp_path: Path) -> AsyncIterator[Engine]:
    # A DR box: dr.enabled so the coordinator builds; activate=false so it starts un-activated (the box
    # comes up serving its full graph; the test activates it, then fails it back). store_settings present
    # so the cold-seed key seam exists.
    store = await MessageStore.open(tmp_path / "fb.db")
    eng = Engine(
        store,
        poll_interval=0.02,
        config_dir=None,
        store_settings=StoreSettings(path=str(tmp_path / "fb.db")),
        dr_settings=DrSettings(enabled=True, activate=False),
    )
    yield eng
    await eng.stop()


async def _wait(predicate, timeout: float = 10.0) -> None:  # type: ignore[no-untyped-def]
    elapsed = 0.0
    while not await predicate():
        await asyncio.sleep(0.05)
        elapsed += 0.05
        if elapsed > timeout:
            raise AssertionError("condition not met within timeout")


async def test_release_drains_then_hands_back(engine: Engine, tmp_path: Path) -> None:
    outdir = tmp_path / "out"
    outdir.mkdir()
    reg = Registry()
    reg.add_inbound(
        build_inbound_connection(
            "in_crit", MLLP(port=19501), router="r", priority=Priority.CRITICAL
        )
    )
    reg.add_outbound(
        build_outbound_connection(
            "out",
            ConnectionSpec(
                ConnectorType.FILE, {"directory": str(outdir), "filename": "{MSH-10}.hl7"}
            ),
            priority=Priority.CRITICAL,
        )
    )
    reg.add_router("r", lambda m: ["h"])
    reg.add_handler("h", lambda m: Send("out", m))
    engine.add_registry(reg)
    await engine.start()

    rr = engine.registry_runner
    assert rr is not None and rr.inbound_running("in_crit")

    # Enqueue a message at ingress (as a received inbound message would) — the worker routes + delivers.
    await engine.store.enqueue_ingress(
        channel_id="in_crit",
        raw=ADT,
        control_id="FBMSG1",
        message_type="ADT^A01",
        summary="DOE^JANE",
        now=1.0,
    )

    # Fail back: drain-then-hand-back via the engine's DR-release callback (what POST /dr/release runs).
    # It unbinds intake + drains the staged queue to completion before returning.
    engine._dr_active = True  # simulate "currently serving under the DR profile"
    await engine._dr_release_drain()

    # No listener is bound after the hand-back (no dual-accept window while the VIP moves).
    assert not rr.inbound_running("in_crit")
    # The staged queue drained to completion — the message was DELIVERED (at-least-once within the store
    # held across the hand-back; nothing dropped).
    assert await engine.store.in_pipeline_depth() == 0
    assert (outdir / "FBMSG1.hl7").exists()
    processed = await engine.store.list_messages(
        channel_id="in_crit", status=MessageStatus.PROCESSED.value
    )
    assert len(processed) == 1  # delivered exactly the once (idempotent outbound, no dup-drop)
    assert engine.dr_active is False  # the run-profile is latched off after a clean hand-back
