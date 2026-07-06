# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""ADR 0066 — the pooled StageDispatcher wired into RegistryRunner behind ``[pipeline].claim_mode``.

Since issue #744 the default is ``pooled``; ``per_lane`` is the byte-identical opt-out. Three proofs
(the exhaustive §8 rider matrix is a later commit):

* ``test_default_mode_constructs_pooled_dispatchers`` — the default-flip sentinel: with ``claim_mode``
  unset the runner now builds one StageDispatcher per core stage and NO per-lane workers.
* ``test_explicit_per_lane_constructs_zero_pooled_objects`` — the opt-out sentinel (unregressed by the
  flip): an EXPLICIT ``claim_mode="per_lane"`` builds today's per-lane worker topology and constructs
  ZERO pooled objects (``_dispatchers`` stays empty), before AND after start/stop.
* the pooled SQLite end-to-end smoke — a small inbound→router→handler→outbound graph flows a message
  all the way to the outbound with the correct disposition under ``claim_mode="pooled"`` (one
  StageDispatcher per core stage; NO per-lane workers), proving the wiring works + the sentinel holds.

No hashlib/hmac/secrets/ssl here (crypto-inventory gate)."""

from __future__ import annotations

import asyncio
import time
from pathlib import Path

import pytest

from messagefoundry.config.wiring import (
    ConnectionSpec,
    ConnectorType,
    InboundConnection,
    OutboundConnection,
    Registry,
    Send,
)
from messagefoundry.pipeline.wiring_runner import RegistryRunner
from messagefoundry.store import MessageStatus, MessageStore, OutboxStatus, Stage

ADT = (
    "MSH|^~\\&|SENDINGAPP|SENDINGFAC|RECV|RFAC|20260604||ADT^A01|MSG1|P|2.5.1\r"
    "EVN|A01|20260604\r"
    "PID|1||100^^^H^MR||DOE^JANE\r"
)


@pytest.fixture
async def store(tmp_path: Path):
    s = await MessageStore.open(tmp_path / "pooled.db")
    yield s
    await s.close()


def _reg(inbox: Path, outdir: Path) -> Registry:
    """One FILE inbound → router → handler → one FILE outbound (the outbound is swapped for a
    collector in the smoke test, so nothing actually touches ``outdir``)."""
    reg = Registry()
    reg.add_inbound(
        InboundConnection(
            "file_in",
            ConnectionSpec(
                ConnectorType.FILE,
                {"directory": str(inbox), "pattern": "*.hl7", "poll_seconds": 0.05},
            ),
            router="r",
        )
    )
    reg.add_outbound(
        OutboundConnection(
            "file_out",
            ConnectionSpec(
                ConnectorType.FILE, {"directory": str(outdir), "filename": "{MSH-10}.hl7"}
            ),
        )
    )
    reg.add_router("r", lambda m: ["h"])
    reg.add_handler("h", lambda m: Send("file_out", m))
    return reg


class _Collector:
    """A test outbound connector that records the payloads it 'delivered' (non-capturing → mark_done)."""

    def __init__(self) -> None:
        self.deliveries: list[str] = []

    async def send(self, payload: str) -> None:
        self.deliveries.append(payload)
        return None

    async def aclose(self) -> None:
        return None


async def _until(pred, *, timeout: float = 5.0) -> None:  # type: ignore[no-untyped-def]
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if await pred():
            return
        await asyncio.sleep(0.02)
    raise AssertionError("timed out waiting for condition")


async def test_default_mode_constructs_pooled_dispatchers(
    store: MessageStore, tmp_path: Path
) -> None:
    # THE DEFAULT-FLIP sentinel (#744): claim_mode unset now defaults to "pooled" — the runner builds
    # one StageDispatcher per core stage and NO per-lane router/transform/delivery workers.
    inbox = tmp_path / "in"
    inbox.mkdir()
    runner = RegistryRunner(_reg(inbox, tmp_path / "out"), store, poll_interval=0.02)
    assert runner._claim_mode == "pooled"
    assert runner._dispatchers == {}  # not built until start()
    await runner.start()
    try:
        # Pooled topology: one dispatcher for the three core stages (no RESPONSE — file_in is not a
        # loopback), and NO per-lane workers were spawned.
        assert set(runner._dispatchers) == {Stage.INGRESS, Stage.ROUTED, Stage.OUTBOUND}
        assert runner._router_workers == {}
        assert runner._transform_workers == {}
        assert runner._response_workers == {}
        assert runner._workers == {}
    finally:
        await runner.stop()
    assert runner._dispatchers == {}  # torn down cleanly


async def test_explicit_per_lane_constructs_zero_pooled_objects(
    store: MessageStore, tmp_path: Path
) -> None:
    # THE OPT-OUT sentinel: the #744 default flip must NOT regress the per_lane path — an EXPLICIT
    # claim_mode="per_lane" still builds today's exact worker topology and constructs ZERO pooled
    # objects (no dispatcher is ever instantiated), byte-identical to the pre-ADR-0066 engine.
    inbox = tmp_path / "in"
    inbox.mkdir()
    runner = RegistryRunner(
        _reg(inbox, tmp_path / "out"), store, poll_interval=0.02, claim_mode="per_lane"
    )
    assert runner._claim_mode == "per_lane"
    assert runner._dispatchers == {}  # before start
    await runner.start()
    try:
        assert runner._dispatchers == {}  # NO pooled objects constructed
        # The per-lane topology: one router + one transform worker per inbound, one delivery worker
        # per outbound (no response worker — file_in is not a loopback).
        assert set(runner._router_workers) == {"file_in"}
        assert set(runner._transform_workers) == {"file_in"}
        assert runner._response_workers == {}
        assert set(runner._workers) == {"file_out"}
    finally:
        await runner.stop()
    assert runner._dispatchers == {}  # and still empty after teardown


async def test_pooled_sqlite_end_to_end_smoke(store: MessageStore, tmp_path: Path) -> None:
    # A message flows inbound→router→handler→outbound under claim_mode="pooled": one StageDispatcher
    # per core stage drives the whole path (NO per-lane workers), delivery lands, disposition is
    # PROCESSED — proving PR4's wiring works and the sentinel (no per_lane workers in pooled) holds.
    inbox, outdir = tmp_path / "in", tmp_path / "out"
    inbox.mkdir()
    outdir.mkdir()
    runner = RegistryRunner(
        _reg(inbox, outdir),
        store,
        claim_mode="pooled",
        pooled_sweep_interval=0.05,
    )
    await runner.start()
    collector = _Collector()
    runner._destinations["file_out"] = (
        collector  # swap in the recording connector before any traffic
    )
    try:
        # Pooled topology: one dispatcher for the three core stages, no RESPONSE (no loopback), and
        # NO per-lane router/transform/delivery workers were spawned.
        assert set(runner._dispatchers) == {Stage.INGRESS, Stage.ROUTED, Stage.OUTBOUND}
        assert runner._router_workers == {}
        assert runner._transform_workers == {}
        assert runner._workers == {}

        # Inject one message through the real inbound path (commits to ingress + marks the INGRESS lane
        # ready on its dispatcher), then let the dispatchers carry it to the outbound.
        await runner._handle_inbound(runner.registry.inbound["file_in"], ADT.encode("utf-8"))

        async def _delivered() -> bool:
            return (await store.stats()).get(OutboxStatus.DONE.value, 0) >= 1

        await _until(_delivered)

        # The handler's Send reached the (swapped) outbound exactly once, and the message finalized
        # PROCESSED (all destinations delivered).
        assert len(collector.deliveries) == 1

        async def _processed() -> bool:
            msgs = await store.list_messages()
            return len(msgs) == 1 and msgs[0]["status"] == MessageStatus.PROCESSED.value

        await _until(_processed)
    finally:
        await runner.stop()
    assert runner._dispatchers == {}  # torn down cleanly
