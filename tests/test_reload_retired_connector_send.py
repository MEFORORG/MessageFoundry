# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A send on a connector a reload retired is not charged for the reload (BACKLOG #5718, the
runner half).

``_close_replaced`` closes the old connector without waiting for a send in flight on it. Where the
close fails that send, as a transport that closes its socket under a send does, the delivery path
read the failure as a transport fault and charged the row an attempt and a backoff, for a reload.
A delivery that read the connector before the swap and reached its send after it sent on the old,
closed connector, with the same charge or a delivery the reload had just retargeted.

The delivery path now asks whether the reload retired its connector (``_connector_retired``):
before the send, a retired connector is not sent on; after it, a failed send hands its rows back
un-errored, and the lane sends them through the new connector. A send that completed keeps its
result. The send is never cancelled: one running on a thread would go on regardless, and a resend
beside it would deliver twice.
"""

from __future__ import annotations

import asyncio
import sqlite3
import time as _time
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import pytest

from messagefoundry.config.models import BatchConfig, ConnectorType, RetryPolicy
from messagefoundry.config.settings import EgressSettings
from messagefoundry.config.wiring import (
    ConnectionSpec,
    InboundConnection,
    OutboundConnection,
    Registry,
    Send,
)
from messagefoundry.pipeline.wiring_runner import RegistryRunner, _ItemOutcome
from messagefoundry.store import MessageStore
from messagefoundry.transports import NegativeAckError
from messagefoundry.transports.base import DeliveryError, DestinationConnector
from tests._mllp_recorder import run_one_batch
from tests.test_connection_scheduler import _wait_until
from tests.test_outbound_batch import DEST as BATCH_DEST
from tests.test_outbound_batch import _enqueue as enqueue_batch
from tests.test_outbound_batch import _runner as bare_runner
from tests.test_outbound_batch import _wire_batch as wire_batch
from tests.test_shard_lane_ownership import ADT

_OB = "OB_RELOAD"


class _HeldDestination(DestinationConnector):
    """A send that waits for ``finish`` (then succeeds) or for its connector's close (then fails,
    as a transport that closes its socket under a send does)."""

    def __init__(self, *, close_fails_send: bool = True, fault: Exception | None = None) -> None:
        self.started = asyncio.Event()
        self.finish = asyncio.Event()
        self.closed = asyncio.Event()
        self.close_fails_send = close_fails_send
        # What the close makes the send raise: a transport fault unless a test names another.
        self.fault = fault or DeliveryError("connection closed under the send")
        self.sent: list[str] = []

    async def send(self, payload: str, *, metadata: Mapping[str, str] | None = None) -> None:
        self.started.set()
        closed = asyncio.ensure_future(self.closed.wait())
        finish = asyncio.ensure_future(self.finish.wait())
        try:
            await asyncio.wait({closed, finish}, return_when=asyncio.FIRST_COMPLETED)
        finally:
            closed.cancel()
            finish.cancel()
        if self.finish.is_set():
            self.sent.append(payload)
            return
        raise self.fault

    async def aclose(self) -> None:
        if self.close_fails_send:
            self.closed.set()


class _Recorder(DestinationConnector):
    def __init__(self) -> None:
        self.sent: list[str] = []

    async def send(self, payload: str, *, metadata: Mapping[str, str] | None = None) -> None:
        self.sent.append(payload)


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
    """The message's one outbox row once it is no longer in flight."""
    async with asyncio.timeout(10):
        while True:
            (row,) = await store.outbox_for(message_id)
            if row["status"] != "inflight":
                return row
            await asyncio.sleep(0.01)


async def _reload_under_a_send(
    store: MessageStore, tmp_path: Path, claim_mode: str, old: _HeldDestination
) -> tuple[RegistryRunner, str, Path]:
    """Start a runner, hold a send on ``old``, then reload with a changed spec, which builds a
    new File connector in place and closes ``old``."""
    runner = RegistryRunner(
        _registry(tmp_path, tmp_path / "out_old"),
        store,
        claim_mode=claim_mode,
        poll_interval=0.02,
        pooled_sweep_interval=0.05,
        egress=EgressSettings(deny_by_default=False),
    )
    await runner.start()
    await runner._destinations[_OB].aclose()  # the one start built, which `old` stands in for
    runner._destinations[_OB] = old
    message_id = await store.enqueue_message(
        channel_id="IB_RELOAD", raw=ADT, deliveries=[(_OB, ADT)], now=_time.time()
    )
    await asyncio.wait_for(old.started.wait(), timeout=10)
    new_dir = tmp_path / "out_new"
    await runner.reload(_registry(tmp_path, new_dir))
    return runner, message_id, new_dir


@pytest.mark.parametrize("claim_mode", ["per_lane", "pooled"])
async def test_a_send_the_reload_close_fails_is_not_charged(
    store: MessageStore, tmp_path: Path, claim_mode: str
) -> None:
    old = _HeldDestination()
    runner, message_id, new_dir = await _reload_under_a_send(store, tmp_path, claim_mode, old)
    try:
        assert old.closed.is_set()  # the premise: the close failed the send
        await _wait_until(lambda: any(new_dir.iterdir()))
        row = await _settled_row(store, message_id)
        assert row["status"] == "done"
        # The failed send spent nothing: one attempt in all, the one that delivered.
        assert row["attempts"] == 1
        assert not row["last_error"]
    finally:
        await runner.stop()


async def test_a_send_that_completes_on_the_retired_connector_keeps_its_result(
    store: MessageStore, tmp_path: Path
) -> None:
    """A send the close does not interrupt runs to the end, and is recorded once, with no resend."""
    old = _HeldDestination(close_fails_send=False)
    runner, message_id, new_dir = await _reload_under_a_send(store, tmp_path, "pooled", old)
    try:
        old.finish.set()
        row = await _settled_row(store, message_id)
        assert row["status"] == "done" and row["attempts"] == 1
        assert len(old.sent) == 1
        assert list(new_dir.iterdir()) == []
    finally:
        await runner.stop()


def _swap_during_hydration(runner: RegistryRunner, lane: str, new: DestinationConnector) -> None:
    """Make the re-attach read, an await before the send, the moment a reload swaps ``lane``."""
    hydrate = runner._hydrate_payload

    async def swapping(payload: str, message_id: str) -> str:
        runner._destinations[lane] = new
        return await hydrate(payload, message_id)

    runner._hydrate_payload = swapping  # type: ignore[method-assign]


async def test_a_row_is_not_sent_on_a_connector_retired_before_its_send(
    store: MessageStore,
) -> None:
    runner = bare_runner(store)
    old, new = _Recorder(), _Recorder()
    runner._destinations[BATCH_DEST] = old
    runner._retry[BATCH_DEST] = RetryPolicy()
    (message_id,) = await enqueue_batch(store, 1)
    _swap_during_hydration(runner, BATCH_DEST, new)
    item = await store.claim_next_fifo(BATCH_DEST)
    assert item is not None
    await runner._process_delivery_item(BATCH_DEST, item)
    assert old.sent == [] and new.sent == []
    (row,) = await store.outbox_for(message_id)
    assert row["status"] == "pending" and row["attempts"] == 0 and not row["last_error"]


async def test_a_batch_is_not_sent_on_a_connector_retired_before_its_send(
    store: MessageStore,
) -> None:
    runner = bare_runner(store)
    old, new = _Recorder(), _Recorder()
    wire_batch(runner, old, BatchConfig(max_count=5, max_wait_ms=1))
    message_ids = await enqueue_batch(store, 2)
    _swap_during_hydration(runner, BATCH_DEST, new)
    await run_one_batch(runner, BATCH_DEST)
    assert old.sent == [] and new.sent == []
    for message_id in message_ids:
        (row,) = await store.outbox_for(message_id)
        assert row["status"] == "pending" and row["attempts"] == 0 and not row["last_error"]


@pytest.mark.parametrize(
    "fault",
    [
        NegativeAckError("bad password", code="remotefile", permanent=True, credential_fault=True),
        RuntimeError("client is closed"),
    ],
    ids=["credential-fault", "internal-error"],
)
async def test_a_retired_connector_fault_neither_stops_nor_charges(
    store: MessageStore, fault: Exception
) -> None:
    """A credential fault from a retired connector does not STOP the lane, since the reload may be
    its fix, and an internal error its close raised is not dead-lettered."""
    runner = bare_runner(store)
    old = _HeldDestination(fault=fault)
    runner._destinations[BATCH_DEST] = old
    runner._retry[BATCH_DEST] = RetryPolicy()
    (message_id,) = await enqueue_batch(store, 1)
    item = await store.claim_next_fifo(BATCH_DEST)
    assert item is not None
    run = asyncio.ensure_future(runner._process_delivery_item(BATCH_DEST, item))
    await asyncio.wait_for(old.started.wait(), timeout=10)
    runner._destinations[BATCH_DEST] = _Recorder()  # the reload's swap, then its close
    await runner._close_replaced(BATCH_DEST, old, [])
    outcome, _ = await asyncio.wait_for(run, timeout=10)
    assert outcome is _ItemOutcome.PROCESSED  # not STOPPED
    assert ("outbound", BATCH_DEST) not in runner._stop_held
    (row,) = await store.outbox_for(message_id)
    assert row["status"] == "pending" and row["attempts"] == 0 and not row["last_error"]


async def test_a_transient_refusal_from_a_retired_connector_is_still_charged(
    store: MessageStore,
) -> None:
    """A transient refusal is the partner's answer about the message, not the reload's."""
    runner = bare_runner(store)
    old = _HeldDestination(fault=NegativeAckError("busy", code="AE", permanent=False))
    runner._destinations[BATCH_DEST] = old
    runner._retry[BATCH_DEST] = RetryPolicy()
    (message_id,) = await enqueue_batch(store, 1)
    item = await store.claim_next_fifo(BATCH_DEST)
    assert item is not None
    run = asyncio.ensure_future(runner._process_delivery_item(BATCH_DEST, item))
    await asyncio.wait_for(old.started.wait(), timeout=10)
    runner._destinations[BATCH_DEST] = _Recorder()
    await runner._close_replaced(BATCH_DEST, old, [])
    await asyncio.wait_for(run, timeout=10)
    (row,) = await store.outbox_for(message_id)
    assert row["status"] == "pending" and row["attempts"] == 1 and row["last_error"]


async def test_a_store_fault_handing_back_before_the_send_is_not_an_internal_error(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The hand-back runs outside the send path's arms: its store fault goes to the caller's
    backoff, and the never-sent row is not dead-lettered as an internal error."""
    runner = bare_runner(store)
    runner._destinations[BATCH_DEST] = _Recorder()
    runner._retry[BATCH_DEST] = RetryPolicy()
    (message_id,) = await enqueue_batch(store, 1)
    _swap_during_hydration(runner, BATCH_DEST, _Recorder())
    item = await store.claim_next_fifo(BATCH_DEST)
    assert item is not None

    async def locked(ids: Any, now: float | None = None) -> None:
        raise sqlite3.OperationalError("database is locked")

    monkeypatch.setattr(store, "release_claimed", locked)
    with pytest.raises(sqlite3.OperationalError):
        await runner._process_delivery_item(BATCH_DEST, item)
    (row,) = await store.outbox_for(message_id)
    assert row["status"] == "inflight" and not row["last_error"]


async def test_a_batch_send_the_reload_close_fails_is_not_charged(store: MessageStore) -> None:
    runner = bare_runner(store)
    old = _HeldDestination()
    wire_batch(runner, old, BatchConfig(max_count=5, max_wait_ms=1))
    message_ids = await enqueue_batch(store, 2)
    run = asyncio.create_task(run_one_batch(runner, BATCH_DEST))
    await asyncio.wait_for(old.started.wait(), timeout=10)
    runner._destinations[BATCH_DEST] = _Recorder()  # the reload's swap, then its close
    await runner._close_replaced(BATCH_DEST, old, [])
    await asyncio.wait_for(run, timeout=10)
    for message_id in message_ids:
        (row,) = await store.outbox_for(message_id)
        assert row["status"] == "pending" and row["attempts"] == 0 and not row["last_error"]
