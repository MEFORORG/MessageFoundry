# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Invalid-credential sender auto-stop (#109, ADR 0095): on a PERMANENT credential/auth fault an
outbound File/FTP/SFTP sender STOPs the lane IMMEDIATELY (not after a streak) and RETAINS the queued
rows UN-ERRORED (pending/claimable, never dead-lettered) so a backlog can't repeatedly re-authenticate
and lock out the partner account. A TRANSIENT infra fault still follows the retry/backoff path; a
CONTENT-permanent reject still dead-letters just that one message. The ``credential_fault_policy``
knob (``stop`` default | ``dead_letter``) selects the behaviour."""

from __future__ import annotations

from pathlib import Path

import pytest

from messagefoundry.config.wiring import Registry
from messagefoundry.pipeline.alerts import LoggingAlertSink
from messagefoundry.pipeline.wiring_runner import _ItemOutcome, RegistryRunner
from messagefoundry.store.store import MessageStatus, MessageStore, OutboxStatus, Stage
from messagefoundry.transports.base import DeliveryError, NegativeAckError

RAW = "MSH|^~\\&|S|F|R|RF|20260101||ADT^A01|MSG1|P|2.5.1\r"
BODY = "MSH|^~\\&|XFORM|||||20260101||ADT^A01|OUT1|P|2.5.1\r"
CHANNEL = "IB_TEST"
DEST = "OB_REMOTE"


@pytest.fixture
async def store(tmp_path: Path):  # type: ignore[no-untyped-def]
    s = await MessageStore.open(tmp_path / "cred.db")
    yield s
    await s.close()


class _RaisingConnector:
    """A stub outbound connector whose ``send`` always raises the configured exception."""

    capture_response = False

    def __init__(self, exc: Exception) -> None:
        self._exc = exc
        self.sends = 0

    async def send(self, payload: str) -> None:
        self.sends += 1
        raise self._exc

    async def aclose(self) -> None:  # pragma: no cover - not exercised
        pass


class _RecordingSink(LoggingAlertSink):
    def __init__(self) -> None:
        self.stopped: list[tuple[str, str]] = []

    def connection_stopped(self, name: str, *, detail: str) -> None:
        self.stopped.append((name, detail))


async def _seed_outbound(store: MessageStore) -> str:
    """Drive one message ingress→routed→outbound and return the DEST outbound row id."""
    mid = await store.enqueue_ingress(channel_id=CHANNEL, raw=RAW, now=0.0)
    ing = await store.claim_next_fifo(CHANNEL, stage=Stage.INGRESS.value, now=0.0)
    assert ing is not None
    await store.route_handoff(
        ingress_id=ing.id,
        message_id=mid,
        channel_id=CHANNEL,
        handlers=[("h1", RAW)],
        disposition=MessageStatus.ROUTED,
        now=0.0,
    )
    routed = await store.claim_next_fifo(CHANNEL, stage=Stage.ROUTED.value, now=0.0)
    assert routed is not None
    await store.transform_handoff(
        routed_id=routed.id,
        message_id=mid,
        channel_id=CHANNEL,
        deliveries=[(DEST, BODY)],
        now=0.0,
    )
    return mid


async def _row_state(store: MessageStore, mid: str) -> tuple[str, int, str | None]:
    cur = await store._db.execute(
        "SELECT status, attempts, last_error FROM queue WHERE message_id=? AND stage=?",
        (mid, Stage.OUTBOUND.value),
    )
    row = await cur.fetchone()
    assert row is not None
    return str(row[0]), int(row[1]), (None if row[2] is None else str(row[2]))


def _runner(store: MessageStore, sink: _RecordingSink, *, policy: str = "stop") -> RegistryRunner:
    reg = Registry()
    return RegistryRunner(
        reg, store, poll_interval=0.02, alert_sink=sink, credential_fault_policy=policy
    )


async def test_credential_fault_stops_and_retains(store: MessageStore) -> None:
    # A PERMANENT credential/auth fault under the default "stop" policy STOPs the lane immediately and
    # leaves the queued row UN-ERRORED (pending, no last_error) — not dead-lettered.
    await _seed_outbound(store)
    sink = _RecordingSink()
    runner = _runner(store, sink)
    connector = _RaisingConnector(
        NegativeAckError("bad password", code="remotefile", permanent=True, credential_fault=True)
    )
    runner._destinations[DEST] = connector  # type: ignore[assignment]

    item = await store.claim_next_fifo(DEST, now=1.0)
    assert item is not None
    outcome = await runner._process_delivery_item(DEST, item)

    assert outcome[0] is _ItemOutcome.STOPPED  # the lane STOPs (reuses the STOP muscle)
    status, attempts, last_error = await _row_state(store, item.message_id)
    assert status == OutboxStatus.PENDING.value  # retained, claimable — NOT "dead"
    assert last_error is None  # un-errored (release_claimed, not mark_failed/dead_letter)
    assert attempts == 0  # the claim's +1 was undone
    assert connector.sends == 1  # a SINGLE attempt — stopped immediately, not after a streak
    # Alerted with a legible credential-fault reason (distinct from a content STOP / schedule park).
    assert sink.stopped and sink.stopped[0][0] == DEST
    assert "credential fault" in sink.stopped[0][1]


async def test_transient_fault_still_retries(store: MessageStore) -> None:
    # A TRANSIENT transport failure keeps the existing retry/backoff path — no lane stop.
    await _seed_outbound(store)
    sink = _RecordingSink()
    runner = _runner(store, sink)
    runner._destinations[DEST] = _RaisingConnector(DeliveryError("connection reset"))  # type: ignore[assignment]

    item = await store.claim_next_fifo(DEST, now=1.0)
    assert item is not None
    outcome = await runner._process_delivery_item(DEST, item)

    assert outcome[0] is _ItemOutcome.PROCESSED  # NOT stopped
    assert outcome[1] is not None  # re-pended with a backoff deadline
    status, _attempts, last_error = await _row_state(store, item.message_id)
    assert status == OutboxStatus.PENDING.value  # re-pended, not dead
    assert (
        last_error is not None
    )  # a transient failure IS recorded (errored, unlike a credential fault)
    assert not sink.stopped  # no connection_stopped alert


async def test_content_permanent_still_dead_letters(store: MessageStore) -> None:
    # A CONTENT-permanent reject (permanent, but NOT a credential fault) dead-letters just that one
    # message — the historical fail-fast behaviour is unchanged.
    await _seed_outbound(store)
    sink = _RecordingSink()
    runner = _runner(store, sink)
    runner._destinations[DEST] = _RaisingConnector(  # type: ignore[assignment]
        NegativeAckError("no such directory", code="remotefile", permanent=True)
    )

    item = await store.claim_next_fifo(DEST, now=1.0)
    assert item is not None
    outcome = await runner._process_delivery_item(DEST, item)

    assert outcome[0] is _ItemOutcome.PROCESSED  # lane advances (not stopped)
    status, _attempts, _last_error = await _row_state(store, item.message_id)
    assert status == OutboxStatus.DEAD.value  # dead-lettered, replayable
    assert not sink.stopped


async def test_dead_letter_policy_dead_letters_the_credential_fault(store: MessageStore) -> None:
    # credential_fault_policy="dead_letter" opts back into the historical fail-fast: a credential fault
    # dead-letters the row instead of stopping the lane.
    await _seed_outbound(store)
    sink = _RecordingSink()
    runner = _runner(store, sink, policy="dead_letter")
    runner._destinations[DEST] = _RaisingConnector(  # type: ignore[assignment]
        NegativeAckError("bad password", code="remotefile", permanent=True, credential_fault=True)
    )

    item = await store.claim_next_fifo(DEST, now=1.0)
    assert item is not None
    outcome = await runner._process_delivery_item(DEST, item)

    assert outcome[0] is _ItemOutcome.PROCESSED
    status, _attempts, _last_error = await _row_state(store, item.message_id)
    assert status == OutboxStatus.DEAD.value
    assert not sink.stopped


def test_credential_fault_policy_validated_at_construction(store: MessageStore) -> None:
    with pytest.raises(AssertionError):
        RegistryRunner(Registry(), store, credential_fault_policy="bogus")
