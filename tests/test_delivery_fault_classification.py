# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Delivery fault classification and bounded retry backoff (vault BACKLOG #2756, #2770, #2761).

* #2756: the store reads a send needs (the document re-attach, the ``dynamic_headers`` metadata bag)
  sat inside the send ``try``, so a transient driver error from either reached the internal-error arm
  and dead-lettered (or STOPped the lane on) a message that was never sent. They now run before it,
  so the fault propagates to the caller's re-pend. Controls: a missing attachment is still a
  retryable ``DeliveryError``, and a real internal error from the connector still dead-letters.
* #2770: the buildup and stall checks after a failed delivery read ``pending_depth`` unguarded, so a
  read error there escaped the delivery body, which the pooled dispatcher counts as a T17 infra
  fault. It is now logged and the delivery's outcome stands.
* #2761: ``backoff * multiplier ** (attempts - 1)`` raised ``OverflowError`` at attempt 1025 under
  retry-forever, from inside the delivery failure arm, and the backoff fields had no bounds.

Synthetic HL7 only.
"""

from __future__ import annotations

import base64
import logging
import math
import sqlite3
import time
from collections.abc import AsyncIterator
from pathlib import Path

import pytest
from pydantic import ValidationError

from messagefoundry.config.models import BatchConfig, RetryPolicy
from messagefoundry.config.settings import DeliverySettings, EgressSettings
from messagefoundry.config.wiring import Registry
from messagefoundry.parsing.binary import DOC_REF_MARKER, chunk_b64, make_doc_ref
from messagefoundry.pipeline.stage_dispatcher import LaneResultKind
from messagefoundry.pipeline.wiring_runner import RegistryRunner, _ItemOutcome
from messagefoundry.store import MessageStore, OutboxStatus
from messagefoundry.store.crypto import CipherError
from messagefoundry.transports.base import DeliveryError

DEST = "OB_TEST_ORU"


@pytest.fixture
async def store(tmp_path: Path) -> AsyncIterator[MessageStore]:
    s = await MessageStore.open(tmp_path / "faults.db")
    try:
        yield s
    finally:
        await s.close()


def _hl7(obx5_5: str, control_id: str = "MSG1") -> str:
    return (
        f"MSH|^~\\&|APP|FAC|RCV|RCVF|20260101120000||MDM^T02|{control_id}|P|2.5\r"
        "PID|1||TESTMRN1^^^FAC||TEST^PATIENT\r"
        f"OBX|1|ED|PDF^Report||^Application^PDF^Base64^{obx5_5}||||||F\r"
    )


async def _skeleton(store: MessageStore, control_id: str = "MSG1") -> str:
    """A delivery row whose OBX-5.5 is a detached-document handle, so delivery must read the
    attachment back from the store. Returns the message id."""
    b64 = base64.b64encode(b"P" * 600).decode("ascii")
    ref = await store.put_attachment(chunk_b64(b64), "application/pdf")
    await store.attachment_incref(ref)
    skeleton = _hl7(make_doc_ref(ref, "application/pdf"), control_id)
    return await store.enqueue_message(
        channel_id="IB", raw=skeleton, deliveries=[(DEST, skeleton)], now=100.0
    )


class _Sender:
    """A non-framing outbound. ``fail`` is raised from every send; otherwise the payload is kept."""

    def __init__(self, fail: Exception | None = None, *, consumes_metadata: bool = False) -> None:
        self.sent: list[str] = []
        self.metadata: list[dict[str, str] | None] = []
        self._fail = fail
        self.consumes_metadata = consumes_metadata

    async def send(self, payload: str, metadata: dict[str, str] | None = None) -> None:
        if self._fail is not None:
            raise self._fail
        self.sent.append(payload)
        self.metadata.append(metadata)

    async def aclose(self) -> None:
        return None


def _runner(
    store: MessageStore, sender: _Sender, *, retry: RetryPolicy | None = None
) -> RegistryRunner:
    runner = RegistryRunner(Registry(), store, egress=EgressSettings(deny_by_default=False))
    runner._destinations[DEST] = sender  # type: ignore[assignment]
    runner._retry[DEST] = retry or RetryPolicy()
    runner._simulate[DEST] = False
    return runner


def _flaky_attachment_reads(store: MessageStore, monkeypatch: pytest.MonkeyPatch) -> list[int]:
    """Make the store's first ``read_attachment`` raise a driver error; later reads are real."""
    real = store.read_attachment
    calls: list[int] = []

    async def _locked() -> AsyncIterator[str]:
        raise sqlite3.OperationalError("database is locked")
        yield ""  # pragma: no cover - makes this an async generator

    def flaky(sha256: str) -> AsyncIterator[str]:
        calls.append(1)
        return _locked() if len(calls) == 1 else real(sha256)

    monkeypatch.setattr(store, "read_attachment", flaky)
    return calls


async def _status(store: MessageStore, message_id: str) -> str:
    return str((await store.outbox_for(message_id))[0]["status"])


# --- vault BACKLOG #2756: a store read fault is an infrastructure fault, not a delivery failure -----


async def test_an_attachment_read_fault_propagates_and_the_row_is_retried(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    mid = await _skeleton(store)
    sender = _Sender()
    runner = _runner(store, sender)
    calls = _flaky_attachment_reads(store, monkeypatch)

    item = await store.claim_next_fifo(DEST)
    assert item is not None
    with pytest.raises(sqlite3.OperationalError):
        await runner._process_delivery_item(DEST, item)
    assert calls == [1]
    # Not dead-lettered and not sent: the row is still the caller's to re-pend.
    assert await store.count_dead() == 0
    assert await _status(store, mid) == OutboxStatus.INFLIGHT.value
    assert sender.sent == []

    # The caller's fault arm (per_lane #1611, the same re-pend T17 makes) hands it back, and the
    # next attempt reads the attachment and delivers.
    await runner._repend_claimed_on_fault("delivery", DEST, [item.id])
    again = await store.claim_next_fifo(DEST, now=time.time() + 60)
    assert again is not None and again.id == item.id
    await runner._process_delivery_item(DEST, again)
    assert len(sender.sent) == 1
    assert await _status(store, mid) == OutboxStatus.DONE.value


async def test_a_metadata_read_fault_propagates_instead_of_dead_lettering(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    raw = _hl7("plain")
    mid = await store.enqueue_message(channel_id="IB", raw=raw, deliveries=[(DEST, raw)], now=100.0)
    sender = _Sender(consumes_metadata=True)
    runner = _runner(store, sender)
    real = store.message_metadata_json
    calls: list[int] = []

    async def flaky(message_id: str) -> str | None:
        calls.append(1)
        if len(calls) == 1:
            raise sqlite3.OperationalError("database is locked")
        return await real(message_id)

    monkeypatch.setattr(store, "message_metadata_json", flaky)

    item = await store.claim_next_fifo(DEST)
    assert item is not None
    with pytest.raises(sqlite3.OperationalError):
        await runner._process_delivery_item(DEST, item)
    assert await store.count_dead() == 0
    assert await _status(store, mid) == OutboxStatus.INFLIGHT.value
    assert sender.sent == []

    await runner._repend_claimed_on_fault("delivery", DEST, [item.id])
    again = await store.claim_next_fifo(DEST, now=time.time() + 60)
    assert again is not None
    await runner._process_delivery_item(DEST, again)
    assert sender.sent == [raw] and sender.metadata == [None]
    assert await _status(store, mid) == OutboxStatus.DONE.value


async def test_control_a_missing_attachment_is_still_a_retryable_delivery_error(
    store: MessageStore,
) -> None:
    """A content fault from the re-attach keeps its old arm: mark_failed with backoff."""
    skeleton = _hl7(make_doc_ref("0" * 64, "application/pdf"))
    mid = await store.enqueue_message(
        channel_id="IB", raw=skeleton, deliveries=[(DEST, skeleton)], now=100.0
    )
    sender = _Sender()
    runner = _runner(store, sender)
    item = await store.claim_next_fifo(DEST)
    assert item is not None

    outcome, retry_until = await runner._process_delivery_item(DEST, item)

    assert outcome is _ItemOutcome.PROCESSED and retry_until is not None
    assert await _status(store, mid) == OutboxStatus.PENDING.value
    assert await store.count_dead() == 0
    assert sender.sent == []


async def test_control_an_internal_error_from_the_send_still_dead_letters(
    store: MessageStore,
) -> None:
    """The internal-error arm is unchanged for what it exists for: a code fault, not a store read."""
    mid = await _skeleton(store)
    runner = _runner(store, _Sender(fail=ValueError("a bug in the connector")))
    item = await store.claim_next_fifo(DEST)
    assert item is not None

    outcome, retry_until = await runner._process_delivery_item(DEST, item)

    assert outcome is _ItemOutcome.PROCESSED and retry_until is None
    assert await _status(store, mid) == OutboxStatus.DEAD.value


async def test_control_a_payload_that_will_not_parse_still_dead_letters(
    store: MessageStore,
) -> None:
    """Classified by type, not by position: a non-HL7 payload carrying the document marker fails to
    parse inside the re-attach, now before the send try, and still reaches the internal-error policy
    (dead-letter under the default CONTINUE) instead of re-pending as an infra fault forever."""
    raw = '{"note": "' + DOC_REF_MARKER + 'not-a-handle"}'
    mid = await store.enqueue_message(channel_id="IB", raw=raw, deliveries=[(DEST, raw)], now=100.0)
    sender = _Sender()
    runner = _runner(store, sender)
    item = await store.claim_next_fifo(DEST)
    assert item is not None

    outcome, retry_until = await runner._process_delivery_item(DEST, item)

    assert outcome is _ItemOutcome.PROCESSED and retry_until is None
    assert await _status(store, mid) == OutboxStatus.DEAD.value
    assert sender.sent == []


async def test_control_a_metadata_cell_that_fails_decryption_still_dead_letters(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    raw = _hl7("plain")
    mid = await store.enqueue_message(channel_id="IB", raw=raw, deliveries=[(DEST, raw)], now=100.0)
    sender = _Sender(consumes_metadata=True)
    runner = _runner(store, sender)

    async def tampered(message_id: str) -> str | None:
        raise CipherError("authentication tag did not verify")

    monkeypatch.setattr(store, "message_metadata_json", tampered)
    item = await store.claim_next_fifo(DEST)
    assert item is not None

    outcome, retry_until = await runner._process_delivery_item(DEST, item)

    assert outcome is _ItemOutcome.PROCESSED and retry_until is None
    assert await _status(store, mid) == OutboxStatus.DEAD.value
    assert sender.sent == []


async def test_control_a_batch_member_that_will_not_parse_still_dead_letters(
    store: MessageStore,
) -> None:
    raw = '{"note": "' + DOC_REF_MARKER + 'not-a-handle"}'
    mid = await store.enqueue_message(channel_id="IB", raw=raw, deliveries=[(DEST, raw)], now=100.0)
    runner = _runner(store, _Sender())
    cfg = runner._batch[DEST] = BatchConfig(max_count=5, max_wait_ms=1)
    head = await store.claim_next_fifo(DEST)
    assert head is not None

    outcome, retry_until = await runner._process_delivery_batch(DEST, head, cfg)

    assert outcome is _ItemOutcome.PROCESSED and retry_until is None
    assert await _status(store, mid) == OutboxStatus.DEAD.value


async def test_a_batch_member_read_fault_propagates_and_dead_letters_nothing(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    first = await _skeleton(store, "MSG1")
    second = await _skeleton(store, "MSG2")
    sender = _Sender()
    runner = _runner(store, sender)
    cfg = runner._batch[DEST] = BatchConfig(max_count=5, max_wait_ms=1)
    _flaky_attachment_reads(store, monkeypatch)

    head = await store.claim_next_fifo(DEST)
    assert head is not None
    with pytest.raises(sqlite3.OperationalError):
        await runner._process_delivery_batch(DEST, head, cfg)

    assert await store.count_dead() == 0
    assert sender.sent == []
    # The head is the caller's to re-pend; the coalesced extra was handed back by the #1579 guard.
    assert await _status(store, first) == OutboxStatus.INFLIGHT.value
    assert await _status(store, second) == OutboxStatus.PENDING.value


# --- vault BACKLOG #2770: an alert-check read error never reclassifies the delivery ---------------


async def test_a_raising_depth_read_after_a_failed_send_is_logged_not_raised(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    raw = _hl7("plain")
    mid = await store.enqueue_message(channel_id="IB", raw=raw, deliveries=[(DEST, raw)], now=100.0)
    runner = _runner(store, _Sender(fail=DeliveryError("partner unreachable")))
    reads: list[str] = []

    async def broken_depth(name: str, *, stage: str = "outbound") -> tuple[int, float | None]:
        reads.append(name)
        raise sqlite3.OperationalError("database is locked")

    monkeypatch.setattr(store, "pending_depth", broken_depth)
    item = await store.claim_next_fifo(DEST)
    assert item is not None

    with caplog.at_level(logging.ERROR, logger="messagefoundry.pipeline.wiring_runner"):
        result = await runner._dispatch_delivery(DEST, item)

    assert reads == [DEST]  # the buildup check really ran, and really failed
    # The pooled dispatcher sees the delivery's own outcome, a RETRY park, never a raise to count as
    # a T17 infra fault.
    assert result.kind is LaneResultKind.RETRY and result.retry_until is not None
    assert await _status(store, mid) == OutboxStatus.PENDING.value
    assert "delivery buildup check failed" in caplog.text


async def test_a_raising_depth_read_after_a_failed_batch_is_logged_not_raised(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    raw = _hl7("plain")
    mid = await store.enqueue_message(channel_id="IB", raw=raw, deliveries=[(DEST, raw)], now=100.0)
    runner = _runner(store, _Sender(fail=DeliveryError("partner unreachable")))
    cfg = runner._batch[DEST] = BatchConfig(max_count=5, max_wait_ms=1)

    async def broken_depth(name: str, *, stage: str = "outbound") -> tuple[int, float | None]:
        raise sqlite3.OperationalError("database is locked")

    monkeypatch.setattr(store, "pending_depth", broken_depth)
    head = await store.claim_next_fifo(DEST)
    assert head is not None

    outcome, retry_until = await runner._process_delivery_batch(DEST, head, cfg)

    assert outcome is _ItemOutcome.PROCESSED and retry_until is not None
    assert await _status(store, mid) == OutboxStatus.PENDING.value


# --- vault BACKLOG #2761: bounded backoff, and no overflow at any attempt count -------------------


def _old_formula(retry: RetryPolicy, attempts: int) -> float:
    return min(
        retry.max_backoff_seconds,
        retry.backoff_seconds * (retry.backoff_multiplier ** max(attempts - 1, 0)),
    )


def test_the_shipped_formula_overflowed_at_attempt_1025() -> None:
    """The positive control: the expression the stores used raises exactly where the row says."""
    retry = RetryPolicy(max_attempts=None)
    assert _old_formula(retry, 1024) == 300.0
    with pytest.raises(OverflowError):
        _old_formula(retry, 1025)


@pytest.mark.parametrize("attempts", [1025, 1026, 5000, 10**9])
def test_backoff_for_holds_the_cap_past_the_overflow_point(attempts: int) -> None:
    assert RetryPolicy(max_attempts=None).backoff_for(attempts) == 300.0


@pytest.mark.parametrize(
    "retry",
    [
        RetryPolicy(),
        RetryPolicy(backoff_seconds=0.5, backoff_multiplier=1.0, max_backoff_seconds=2.0),
        RetryPolicy(backoff_seconds=2.5, backoff_multiplier=3.0, max_backoff_seconds=120.0),
        RetryPolicy(backoff_seconds=500.0, backoff_multiplier=2.0, max_backoff_seconds=300.0),
        RetryPolicy(backoff_seconds=0.001, backoff_multiplier=10.0, max_backoff_seconds=1e6),
        # A cap the delay reaches exactly, where a log-space shortcut is off by one ulp.
        RetryPolicy(
            backoff_seconds=71.97, backoff_multiplier=2.0, max_backoff_seconds=71.97 * 2**16
        ),
    ],
)
def test_backoff_for_matches_the_old_formula_wherever_that_did_not_raise(
    retry: RetryPolicy,
) -> None:
    for attempts in range(0, 300):
        assert retry.backoff_for(attempts) == _old_formula(retry, attempts), attempts


async def test_mark_failed_at_attempt_1025_under_retry_forever_keeps_the_cap_pace(
    store: MessageStore,
) -> None:
    raw = _hl7("plain")
    await store.enqueue_message(channel_id="IB", raw=raw, deliveries=[(DEST, raw)], now=100.0)
    item = await store.claim_next_fifo(DEST, now=100.0)
    assert item is not None
    await store._db.execute("UPDATE queue SET attempts=? WHERE id=?", (1025, item.id))
    await store._db.commit()
    retry = RetryPolicy(max_attempts=None)

    assert await store.mark_failed(item.id, "partner down", retry, now=1000.0) == 1300.0
    claimed = await store.claim_next_fifo(DEST, now=1300.0)
    assert claimed is not None and claimed.attempts == 1026
    assert await store.mark_batch_failed([claimed.id], "partner down", retry, now=2000.0) == 2300.0


async def test_a_failed_send_at_attempt_1025_parks_the_lane_for_the_cap(
    store: MessageStore,
) -> None:
    """End to end through the delivery body: the DeliveryError arm returns a 300 s park rather than
    letting an OverflowError escape it (which a pooled lane counted toward a T17 STOP)."""
    raw = _hl7("plain")
    mid = await store.enqueue_message(channel_id="IB", raw=raw, deliveries=[(DEST, raw)], now=100.0)
    runner = _runner(
        store,
        _Sender(fail=DeliveryError("partner unreachable")),
        retry=RetryPolicy(max_attempts=None),
    )
    item = await store.claim_next_fifo(DEST)
    assert item is not None
    await store._db.execute("UPDATE queue SET attempts=? WHERE id=?", (1025, item.id))
    await store._db.commit()

    before = time.time()
    result = await runner._dispatch_delivery(DEST, item)
    after = time.time()

    assert result.kind is LaneResultKind.RETRY and result.retry_until is not None
    assert before + 300.0 <= result.retry_until <= after + 300.0
    assert await _status(store, mid) == OutboxStatus.PENDING.value


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("backoff_seconds", 0.0),
        ("backoff_seconds", -1.0),
        ("backoff_seconds", math.nan),
        ("backoff_seconds", math.inf),
        ("backoff_multiplier", 0.0),
        ("backoff_multiplier", 0.5),
        ("backoff_multiplier", math.nan),
        ("backoff_multiplier", math.inf),
        ("max_backoff_seconds", 0.0),
        ("max_backoff_seconds", -5.0),
        ("max_backoff_seconds", math.nan),
        ("max_backoff_seconds", math.inf),
    ],
)
def test_retry_policy_refuses_an_unbounded_backoff(field: str, value: float) -> None:
    with pytest.raises(ValidationError):
        RetryPolicy.model_validate({field: value})
    with pytest.raises(ValidationError):
        DeliverySettings.model_validate({f"retry_{field}": value})


def test_an_assignment_cannot_step_around_the_bounds() -> None:
    retry = RetryPolicy()
    with pytest.raises(ValidationError):
        retry.backoff_seconds = 0.0
    with pytest.raises(ValidationError):
        retry.max_backoff_seconds = math.inf
    assert retry.backoff_seconds == 5.0 and retry.max_backoff_seconds == 300.0


def test_the_bounds_leave_the_edges_that_are_legal() -> None:
    """A multiplier of exactly 1 (constant backoff) is legal, and ``max_attempts`` stays unfloored on
    the model: 0 is the internal no-retry idiom."""
    retry = RetryPolicy(max_attempts=0, backoff_seconds=0.01, backoff_multiplier=1.0)
    assert retry.backoff_for(50) == 0.01
    settings = DeliverySettings(retry_backoff_multiplier=1.0, retry_backoff_seconds=0.01)
    assert settings.retry_policy().backoff_multiplier == 1.0
