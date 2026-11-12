# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A reload that replaces an outbound's connector cancels a send in flight on the old one
(BACKLOG #5718, the runner half).

``_close_replaced`` only awaited the old connector's ``aclose()``. A send still in flight on it
either ran on against a connector the lane no longer used, or, where the close failed it (the X12
transport's fix), came back as a transport fault and charged its row an attempt and a backoff for
a reload. The reload now cancels and awaits that send first, and the delivery path releases the row
un-errored, so the lane sends it at once through the new connector.

The old connector here is a double whose send waits until it is cancelled or closed, and whose
close fails a send in flight, as a transport that closes its socket under a send would.
"""

from __future__ import annotations

import asyncio
import time as _time
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import pytest

from messagefoundry.config.models import BatchConfig, ConnectorType
from messagefoundry.config.settings import EgressSettings
from messagefoundry.config.wiring import (
    ConnectionSpec,
    InboundConnection,
    OutboundConnection,
    Registry,
    Send,
)
from messagefoundry.pipeline.wiring_runner import RegistryRunner
from messagefoundry.store import MessageStore
from messagefoundry.transports.base import DeliveryError, DestinationConnector
from tests._mllp_recorder import run_one_batch
from tests.test_connection_scheduler import _wait_until
from tests.test_outbound_batch import DEST as BATCH_DEST
from tests.test_outbound_batch import _enqueue as enqueue_batch
from tests.test_outbound_batch import _runner as batch_runner
from tests.test_outbound_batch import _wire_batch as wire_batch
from tests.test_shard_lane_ownership import ADT

_OB = "OB_RELOAD"


class _HangingDestination(DestinationConnector):
    """A send that waits until it is cancelled or its connector closed. The close fails it."""

    def __init__(self) -> None:
        self.started = asyncio.Event()
        self.closed = asyncio.Event()
        self.cancelled = False
        self.closed_after_cancel = False

    async def send(self, payload: str, *, metadata: Mapping[str, str] | None = None) -> None:
        self.started.set()
        try:
            await self.closed.wait()
        except asyncio.CancelledError:
            self.cancelled = True
            raise
        raise DeliveryError("connection closed under the send")

    async def aclose(self) -> None:
        self.closed_after_cancel = self.cancelled
        self.closed.set()


@pytest.fixture
async def store(tmp_path: Path):
    s = await MessageStore.open(tmp_path / "reload.db")
    yield s
    await s.close()


def _registry(tmp_path: Path, outdir: Path) -> Registry:
    inbox = tmp_path / "in"
    inbox.mkdir(exist_ok=True)
    outdir.mkdir(exist_ok=True)
    reg = Registry()
    reg.add_inbound(
        InboundConnection(
            "IB_RELOAD",
            ConnectionSpec(
                ConnectorType.FILE,
                {"directory": str(inbox), "pattern": "*.hl7", "poll_seconds": 0.05},
            ),
            router="r",
        )
    )
    reg.add_outbound(
        OutboundConnection(
            _OB,
            ConnectionSpec(
                ConnectorType.FILE, {"directory": str(outdir), "filename": "{MSH-10}.hl7"}
            ),
        )
    )
    reg.add_router("r", lambda m: [])
    reg.add_handler("h", lambda m: Send(_OB, m))
    return reg


async def _settled_row(store: MessageStore, message_id: str) -> dict[str, Any]:
    """The message's one outbox row once it is no longer in flight (the file lands before the
    row is marked done)."""
    async with asyncio.timeout(10):
        while True:
            (row,) = await store.outbox_for(message_id)
            if row["status"] != "inflight":
                return row
            await asyncio.sleep(0.01)


@pytest.mark.parametrize("claim_mode", ["per_lane", "pooled"])
async def test_a_reload_cancels_the_send_on_the_connector_it_replaces(
    store: MessageStore, tmp_path: Path, claim_mode: str
) -> None:
    runner = RegistryRunner(
        _registry(tmp_path, tmp_path / "out_old"),
        store,
        claim_mode=claim_mode,
        poll_interval=0.02,
        pooled_sweep_interval=0.05,
        egress=EgressSettings(deny_by_default=False),
    )
    await runner.start()
    try:
        old = _HangingDestination()
        runner._destinations[_OB] = old
        message_id = await store.enqueue_message(
            channel_id="IB_RELOAD", raw=ADT, deliveries=[(_OB, ADT)], now=_time.time()
        )
        await asyncio.wait_for(old.started.wait(), timeout=10)
        new_dir = tmp_path / "out_new"
        # A changed directory is a changed spec, so the reload builds a new connector in place.
        await runner.reload(_registry(tmp_path, new_dir))
        assert old.cancelled and old.closed_after_cancel
        await _wait_until(lambda: any(new_dir.iterdir()))
        row = await _settled_row(store, message_id)
        assert row["status"] == "done"
        # The cancelled claim spent nothing: one attempt in all, the one that delivered.
        assert row["attempts"] == 1
        assert not row["last_error"]
    finally:
        await runner.stop()


async def test_a_reload_releases_every_member_of_a_batch_whose_send_it_cancelled(
    store: MessageStore,
) -> None:
    """The batch body's twin: every member of the envelope goes back un-errored."""
    runner = batch_runner(store)
    old = _HangingDestination()
    wire_batch(runner, old, BatchConfig(max_count=5, max_wait_ms=1))
    message_ids = await enqueue_batch(store, 2)
    run = asyncio.create_task(run_one_batch(runner, BATCH_DEST))
    await asyncio.wait_for(old.started.wait(), timeout=10)
    await runner._close_replaced(BATCH_DEST, old, [])
    await asyncio.wait_for(run, timeout=10)
    assert old.cancelled
    for message_id in message_ids:
        (row,) = await store.outbox_for(message_id)
        assert row["status"] == "pending" and row["attempts"] == 0 and not row["last_error"]


async def test_a_teardown_cancel_still_cancels_the_delivery_task(
    store: MessageStore, tmp_path: Path
) -> None:
    """Only a cancelled send in a task that is not itself cancelled reads as a reload's. A
    cancellation of the delivery task, as a teardown's, reaches the send and propagates."""
    runner = RegistryRunner(
        _registry(tmp_path, tmp_path / "out"), store, egress=EgressSettings(deny_by_default=False)
    )
    old = _HangingDestination()
    delivery = asyncio.create_task(runner._send_on(old, ADT))
    await asyncio.wait_for(old.started.wait(), timeout=10)
    delivery.cancel()
    with pytest.raises(asyncio.CancelledError):
        await delivery
    assert old.cancelled and not runner._sends
