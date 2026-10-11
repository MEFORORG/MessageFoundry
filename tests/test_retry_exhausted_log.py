# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #3108: a transient failure that runs out a finite ``max_attempts`` writes one WARNING.

``store.mark_failed`` and ``mark_batch_failed`` dead-letter such a row inside the store, and the
runner wrote nothing. #3043 closed the same silence for a permanent refusal. These tests drive the
real runner against the real SQLite store and check three things: the line fires on the attempt
that dead-letters the row and not one attempt sooner, it never fires under ``max_attempts=None``,
and it carries no payload text. The connectors here echo a planted token in their error text, as a
partner's reject reason can, so logging ``str(exc)`` or ``safe_exc(exc)`` would fail them.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import AsyncIterator, Iterable
from pathlib import Path
from typing import Any, cast

import pytest

from messagefoundry.config.models import (
    BatchConfig,
    ConnectorType,
    InternalErrorPolicy,
    RetryPolicy,
)
from messagefoundry.config.settings import EgressSettings
from messagefoundry.config.wiring import (
    ConnectionSpec,
    InboundConnection,
    OutboundConnection,
    Registry,
    Send,
)
from messagefoundry.pipeline import wiring_runner
from messagefoundry.pipeline.wiring_runner import RegistryRunner, _RefusalLog
from messagefoundry.store import FailOutcome, MessageStatus, MessageStore, OutboxItem, OutboxStatus
from messagefoundry.transports.base import DeliveryError, DestinationConnector, NegativeAckError
from tests._refusal_log_capture import TOKEN, assert_no_token, until

OUT = "file_out"
LOGGER = "messagefoundry.pipeline.wiring_runner"
EXHAUSTED = "the retry cap"
# Tiny backoff, so the real worker's retry comes due at once.
FAST = {"backoff_seconds": 0.01, "max_backoff_seconds": 0.01}
_TRANSPORT_TEXT = f"connection reset sending {TOKEN}"


def _adt(n: int) -> str:
    return (
        f"MSH|^~\\&|SENDINGAPP|SENDINGFAC|RECV|RFAC|20260604||ADT^A01|MSG{n}|P|2.5.1\r"
        "EVN|A01|20260604\r"
        f"PID|1||{n}00^^^H^MR||{TOKEN}^JANE\r"
    )


@pytest.fixture
async def store(tmp_path: Path) -> AsyncIterator[MessageStore]:
    s = await MessageStore.open(tmp_path / "engine.db")
    yield s
    await s.close()


class _Fails:
    """A connector whose every send fails transiently, with the payload's token in the error text.
    ``before_raise`` runs first, so a test can change the store under the in-flight send, as a lease
    sweep or an operator can (vault BACKLOG #3211)."""

    def __init__(self, transient_nak: bool = False, before_raise: Any = None) -> None:
        self.transient_nak = transient_nak
        self.before_raise = before_raise
        self.calls = 0

    async def send(self, payload: str) -> None:
        self.calls += 1
        assert TOKEN in payload
        if self.before_raise is not None:
            await self.before_raise()
        if self.transient_nak:
            raise NegativeAckError(f"try later, patient {TOKEN}", code="AE", permanent=False)
        raise DeliveryError(_TRANSPORT_TEXT)

    async def aclose(self) -> None:
        return None


# Not this item's line: the DeliveryError arm's edge-triggered connection_lost alert logs
# safe_exc(exc), which leaves _TRANSPORT_TEXT's token in place. That predates #3108 and is not filed
# yet; the #3108 exit report hands it to the Manager. Skipped by its WHOLE message, so any other
# record, that alert with any other text included, is still scanned.
_PRE_EXISTING_ALERT = (
    f"ALERT connection_error: outbound 'file_out' connection_lost: DeliveryError: {_TRANSPORT_TEXT}"
)


def _assert_no_token(records: Iterable[logging.LogRecord]) -> None:
    assert_no_token(records, skip_message=_PRE_EXISTING_ALERT)


def _exhausted_lines(caplog: pytest.LogCaptureFixture) -> list[logging.LogRecord]:
    return [
        r
        for r in caplog.records
        if r.name == LOGGER and r.levelno == logging.WARNING and EXHAUSTED in r.getMessage()
    ]


async def test_the_real_worker_logs_once_when_max_attempts_dead_letters_a_row(
    store: MessageStore, tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    # Engine loggers at DEBUG, so every record they write is scanned. Not the root: aiosqlite's DEBUG
    # lines echo SQL parameters, payloads included, and they are not the engine's own log.
    caplog.set_level(logging.DEBUG, logger="messagefoundry")
    inbox = tmp_path / "in"
    inbox.mkdir()
    reg = Registry()
    reg.add_inbound(
        InboundConnection(
            "file_in",
            ConnectionSpec(
                ConnectorType.FILE,
                {"directory": str(inbox), "pattern": "*.hl7", "poll_seconds": 0.02},
            ),
            router="r",
        )
    )
    reg.add_outbound(
        OutboundConnection(
            OUT,
            ConnectionSpec(
                ConnectorType.FILE, {"directory": str(tmp_path / "out"), "filename": "x.hl7"}
            ),
            retry=RetryPolicy(max_attempts=2, **FAST),
        )
    )
    reg.add_router("r", lambda m: ["h"])
    reg.add_handler("h", lambda m: Send(OUT, m))
    runner = RegistryRunner(
        reg, store, poll_interval=0.02, egress=EgressSettings(deny_by_default=False)
    )
    await runner.start()
    dest = _Fails()
    await runner._destinations[OUT].aclose()  # the File connector start() built
    runner._destinations[OUT] = cast(DestinationConnector, dest)
    (inbox / "a.hl7").write_bytes(_adt(1).encode("utf-8"))
    try:
        # Wait on the line, not the DEAD row: the line follows the dead-letter write.
        await until(lambda: len(_exhausted_lines(caplog)) == 1, "the retry-cap line")
    finally:
        await runner.stop()

    assert dest.calls == 2
    assert await store.count_dead(allowed_channels=None) == 1
    (msg,) = await store.list_messages(channel_id="file_in", allowed_channels=None)
    assert msg["status"] == MessageStatus.ERROR.value  # the dead-letter itself is unchanged
    (line,) = _exhausted_lines(caplog)
    text = line.getMessage()
    assert repr(OUT) in text and str(msg["id"]) in text
    assert "DeliveryError" in text and "code '?'" in text
    assert "dead-lettered at the retry cap, after 2 attempt(s)" in text
    _assert_no_token(caplog.records)


def _stepped_runner(
    store: MessageStore, connector: object | None, retry: RetryPolicy
) -> RegistryRunner:
    runner = RegistryRunner(
        Registry(), store, poll_interval=0.02, egress=EgressSettings(deny_by_default=False)
    )
    if connector is not None:  # None: an outbound with no running connector
        runner._destinations[OUT] = cast(DestinationConnector, connector)
    runner._retry[OUT] = retry
    runner._simulate[OUT] = False
    return runner


async def _enqueue(store: MessageStore, count: int) -> None:
    for n in range(1, count + 1):
        body = _adt(n)
        await store.enqueue_message(
            channel_id="c1", raw=body, deliveries=[(OUT, body)], now=100.0 + n
        )


@pytest.mark.parametrize("transient_nak", [False, True], ids=["delivery_error", "transient_nak"])
async def test_the_line_fires_on_the_attempt_that_dead_letters_and_not_one_sooner(
    store: MessageStore, caplog: pytest.LogCaptureFixture, transient_nak: bool
) -> None:
    # The runner decides with the store's own rule (attempts >= max_attempts). Each step claims the
    # row and runs the real per-item body; a clock far ahead makes every backoff due.
    caplog.set_level(logging.DEBUG, logger="messagefoundry")
    runner = _stepped_runner(store, _Fails(transient_nak), RetryPolicy(max_attempts=3, **FAST))
    await _enqueue(store, 1)
    for attempt in (1, 2, 3):
        item = await store.claim_next_fifo(OUT, now=1e12)
        assert item is not None and item.attempts == attempt
        await runner._process_delivery_item(OUT, item)
        dead = await store.count_dead(allowed_channels=None)
        assert dead == (1 if attempt == 3 else 0)
        assert len(_exhausted_lines(caplog)) == dead  # the line and the DEAD write move together
    (line,) = _exhausted_lines(caplog)
    text = line.getMessage()
    assert "dead-lettered at the retry cap, after 3 attempt(s)" in text
    expected = "(NegativeAckError, code 'AE')" if transient_nak else "(DeliveryError, code '?')"
    assert expected in text
    _assert_no_token(caplog.records)


async def test_retry_forever_never_writes_the_line(
    store: MessageStore, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.DEBUG, logger="messagefoundry")
    runner = _stepped_runner(store, _Fails(), RetryPolicy(max_attempts=None, **FAST))
    await _enqueue(store, 1)
    for _ in range(5):
        item = await store.claim_next_fifo(OUT, now=1e12)
        assert item is not None
        await runner._process_delivery_item(OUT, item)
    assert await store.count_dead(allowed_channels=None) == 0
    assert _exhausted_lines(caplog) == []


async def test_a_batch_that_runs_out_its_attempts_logs_one_line(
    store: MessageStore, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.DEBUG, logger="messagefoundry")
    runner = _stepped_runner(store, _Fails(), RetryPolicy(max_attempts=2, **FAST))
    cfg = BatchConfig(max_count=5, max_wait_ms=1)
    runner._batch[OUT] = cfg
    await _enqueue(store, 3)
    head_ids = []
    for attempt in (1, 2):
        await asyncio.sleep(0.05)  # the batch loop claims the other members on the real clock
        head = await store.claim_next_fifo(OUT, now=1e12)
        assert head is not None and head.attempts == attempt
        head_ids.append(head.id)
        await runner._process_delivery_batch(OUT, head, cfg)
        assert len(_exhausted_lines(caplog)) == (1 if attempt == 2 else 0)
    assert await store.count_dead(allowed_channels=None) == 3
    (line,) = _exhausted_lines(caplog)
    text = line.getMessage()
    assert repr(OUT) in text and "a batch of 3" in text and head_ids[-1] in text
    assert "DeliveryError" in text and "dead-lettered at the retry cap, after 2 attempt(s)" in text
    _assert_no_token(caplog.records)


def test_an_exhausted_line_does_not_share_a_window_with_a_permanent_refusal(
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.WARNING, logger=LOGGER)
    now = [0.0]
    log = _RefusalLog(window=60.0, clock=lambda: now[0])
    refusal = NegativeAckError("x", code="AE", permanent=True)
    transient = NegativeAckError("x", code="AE", permanent=False)
    log.warning("a", refusal, 1, "refused")
    log.warning("a", transient, 1, "exhausted", exhausted=True)  # its own key: still logs
    log.warning("a", transient, 4, "exhausted", exhausted=True)  # same key: held
    assert [r.getMessage().split(" (")[0] for r in caplog.records] == ["refused", "exhausted"]
    now[0] = 60.0
    log.warning("a", transient, 1, "exhausted", exhausted=True)
    assert "(4 more row(s) dead-lettered at the retry cap with this code" in (
        caplog.records[-1].getMessage()
    )
    # The exhausted flag is a key field, not a code prefix (vault BACKLOG #3211): a peer's permanent
    # code spelled "exhausted:AE" keeps its own window.
    log.warning("a", NegativeAckError("x", code="exhausted:AE", permanent=True), 1, "spelled")
    assert caplog.records[-1].getMessage().split(" (")[0] == "spelled"


def test_an_outcome_with_nothing_dead_writes_nothing(caplog: pytest.LogCaptureFixture) -> None:
    # The store's outcome decides the line (vault BACKLOG #3211). A re-pend, a vanished row, an
    # empty batch and a final write the H1 fence rolled back all report nothing dead, so none logs.
    caplog.set_level(logging.WARNING, logger=LOGGER)
    runner = _stepped_runner(cast(MessageStore, None), _Fails(), RetryPolicy(max_attempts=2))
    exc = DeliveryError("x")
    for outcome in (FailOutcome(retry_at=123.0, head_id="r", attempts=1), FailOutcome()):
        runner._note_retry_exhausted(OUT, exc, outcome, message_id="m")
        runner._note_retry_exhausted(OUT, exc, outcome)
    assert _exhausted_lines(caplog) == []
    runner._note_retry_exhausted(
        OUT, exc, FailOutcome(dead=1, head_id="r", attempts=2), message_id="m"
    )
    (line,) = _exhausted_lines(caplog)
    assert "outbox row r (message m)" in line.getMessage()
    assert "after 2 attempt(s)" in line.getMessage()


# --- vault BACKLOG #3211: the line follows the outcome the store returns ----------------------------
# mark_failed and mark_batch_failed return a FailOutcome. Before, they returned float | None, and the
# runner guessed a dead-letter from the claimed head's attempts, then read the row back. The guess and
# the read missed real dead-letters and mislabelled others: one case per miss below.


class _Crashes:
    """A connector with a bug: an internal error, not a delivery failure."""

    async def send(self, payload: str) -> None:
        raise RuntimeError("bug")

    async def aclose(self) -> None:
        return None


async def _claim(store: MessageStore) -> OutboxItem:
    item = await store.claim_next_fifo(OUT, now=1e12)
    assert item is not None
    return item


async def _status(store: MessageStore, outbox_id: str) -> str:
    row = await store._row(outbox_id)
    assert row is not None
    return str(row["status"])


async def test_the_store_contract_on_sqlite(store: MessageStore) -> None:
    from tests._fail_outcome_contract import assert_fail_outcomes

    await assert_fail_outcomes(store)


async def test_the_line_needs_no_status_read_after_the_write(
    store: MessageStore, caplog: pytest.LogCaptureFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Item 2: a failed read-back used to mark the line "unconfirmed", and a throttled line lost
    # that note. The outcome comes from the write itself, so there is no read to fail.
    caplog.set_level(logging.DEBUG, logger="messagefoundry")
    runner = _stepped_runner(store, _Fails(), RetryPolicy(max_attempts=1, **FAST))
    await _enqueue(store, 1)

    async def broken(message_id: str) -> object:
        raise RuntimeError("read failed")

    monkeypatch.setattr(store, "outbox_for", broken)
    await runner._process_delivery_item(OUT, await _claim(store))
    (line,) = _exhausted_lines(caplog)
    assert "unconfirmed" not in line.getMessage()
    _assert_no_token(caplog.records)


async def test_a_batch_whose_first_member_vanished_still_logs(
    store: MessageStore, caplog: pytest.LogCaptureFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Item 3: the store decides from the first member still present; the runner read rows[0].
    caplog.set_level(logging.WARNING, logger=LOGGER)
    await _enqueue(store, 2)
    claimed = await store.claim_ready(limit=2, now=1e12, destination_name=OUT)
    (head,) = [i for i in claimed if i.payload == _adt(1)]
    (second,) = [i for i in claimed if i is not head]

    async def drop_head() -> None:
        await store._db.execute("DELETE FROM queue WHERE id=?", (head.id,))
        await store._db.commit()

    runner = _stepped_runner(
        store, _Fails(before_raise=drop_head), RetryPolicy(max_attempts=1, **FAST)
    )
    cfg = BatchConfig(max_count=2, max_wait_ms=1)
    runner._batch[OUT] = cfg
    members = [second]  # the batch loop's one further claim hands in the second member

    async def next_member(name: str, **_: object) -> OutboxItem | None:
        return members.pop() if members else None

    monkeypatch.setattr(store, "claim_next_fifo", next_member)
    await runner._process_delivery_batch(OUT, head, cfg)
    assert await _status(store, second.id) == OutboxStatus.DEAD.value
    (line,) = _exhausted_lines(caplog)
    assert second.id in line.getMessage() and "a batch of 1" in line.getMessage()


async def test_attempts_a_lease_reclaim_moved_still_log(
    store: MessageStore, caplog: pytest.LogCaptureFixture
) -> None:
    # Item 3: the claim's attempts can be stale. Here a reclaim and a second claim spent an attempt
    # under the in-flight send, so the store dead-letters a row the claim saw below the cap.
    caplog.set_level(logging.WARNING, logger=LOGGER)
    await _enqueue(store, 1)
    item = await _claim(store)

    async def reclaimed() -> None:
        await store._db.execute("UPDATE queue SET attempts=attempts+1 WHERE id=?", (item.id,))
        await store._db.commit()

    runner = _stepped_runner(
        store, _Fails(before_raise=reclaimed), RetryPolicy(max_attempts=2, **FAST)
    )
    await runner._process_delivery_item(OUT, item)
    assert await _status(store, item.id) == OutboxStatus.DEAD.value
    (line,) = _exhausted_lines(caplog)
    assert "after 2 attempt(s)" in line.getMessage()


async def test_a_replay_right_after_the_dead_letter_does_not_hide_the_line(
    store: MessageStore, caplog: pytest.LogCaptureFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Item 3: an operator replay between the DEAD write and the read-back made the read see PENDING.
    caplog.set_level(logging.WARNING, logger=LOGGER)
    await _enqueue(store, 1)
    item = await _claim(store)
    real = store.mark_failed

    async def then_replay(*args: Any, **kwargs: Any) -> Any:
        outcome = await real(*args, **kwargs)
        assert await store.replay_dead(audit=None) == 1
        return outcome

    monkeypatch.setattr(store, "mark_failed", then_replay)
    runner = _stepped_runner(store, _Fails(), RetryPolicy(max_attempts=1, **FAST))
    await runner._process_delivery_item(OUT, item)
    assert len(_exhausted_lines(caplog)) == 1


@pytest.mark.parametrize("batch", [False, True], ids=["single", "batch"])
async def test_an_outbound_that_never_started_logs_its_dead_letter(
    store: MessageStore, caplog: pytest.LogCaptureFixture, batch: bool
) -> None:
    # Item 4: the connector-None arms dead-lettered at the cap with no line.
    caplog.set_level(logging.DEBUG, logger="messagefoundry")
    runner = _stepped_runner(store, None, RetryPolicy(max_attempts=1, **FAST))
    await _enqueue(store, 1)
    item = await _claim(store)
    if batch:
        cfg = BatchConfig(max_count=2, max_wait_ms=1)
        runner._batch[OUT] = cfg
        await runner._process_delivery_batch(OUT, item, cfg)
    else:
        await runner._process_delivery_item(OUT, item)
    assert await _status(store, item.id) == OutboxStatus.DEAD.value
    (line,) = _exhausted_lines(caplog)
    assert "no running connector" in line.getMessage() and item.id in line.getMessage()
    assert_no_token(caplog.records)


@pytest.mark.parametrize("batch", [False, True], ids=["single", "batch"])
async def test_the_stop_policy_keeps_the_row_queued_at_the_cap(
    store: MessageStore, batch: bool
) -> None:
    # Item 5: STOP promises to leave the message queued for replay. At the cap, mark_failed with
    # the lane's finite policy dead-lettered it instead.
    runner = _stepped_runner(store, _Crashes(), RetryPolicy(max_attempts=1, **FAST))
    runner._internal_error[OUT] = InternalErrorPolicy.STOP
    await _enqueue(store, 1)
    item = await _claim(store)
    if batch:
        cfg = BatchConfig(max_count=2, max_wait_ms=1)
        runner._batch[OUT] = cfg
        outcome, _ = await runner._process_delivery_batch(OUT, item, cfg)
    else:
        outcome, _ = await runner._process_delivery_item(OUT, item)
    assert outcome is wiring_runner._ItemOutcome.STOPPED
    assert await _status(store, item.id) == OutboxStatus.PENDING.value


@pytest.mark.parametrize("stage", ["router", "transform"])
async def test_the_stop_policy_keeps_an_ingest_row_queued_at_the_cap(
    store: MessageStore, stage: str
) -> None:
    # Item 5, the same promise on the router and transform STOP arms, which used the finite
    # delivery defaults.
    runner = RegistryRunner(
        Registry(),
        store,
        egress=EgressSettings(deny_by_default=False),
        delivery_defaults=RetryPolicy(max_attempts=1, **FAST),
        internal_error_default=InternalErrorPolicy.STOP,
    )
    await _enqueue(store, 1)
    item = await _claim(store)
    apply = (
        runner._apply_router_internal_error
        if stage == "router"
        else runner._apply_transform_internal_error
    )
    outcome, _ = await apply("c1", item, RuntimeError("bug"))
    assert outcome is wiring_runner._ItemOutcome.STOPPED
    assert await _status(store, item.id) == OutboxStatus.PENDING.value


async def test_a_store_read_fault_on_a_vanished_row_does_not_claim_a_dead_letter(
    store: MessageStore, caplog: pytest.LogCaptureFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Item 5: _note_store_read_fault read any None as "dead-lettered at the cap".
    caplog.set_level(logging.WARNING, logger=LOGGER)
    runner = _stepped_runner(store, _Fails(), RetryPolicy(max_attempts=1, **FAST))
    await _enqueue(store, 1)
    item = await _claim(store)

    async def fault(payload: str) -> str:
        await store._db.execute("DELETE FROM queue WHERE id=?", (item.id,))
        await store._db.commit()
        raise wiring_runner._StoreReadFault("attachment read failed")

    monkeypatch.setattr(runner, "_hydrate_payload", fault)
    await runner._process_delivery_item(OUT, item)
    (line,) = [r for r in caplog.records if "before sending" in r.getMessage()]
    assert "dead-lettered" not in line.getMessage()
    assert "no retry scheduled" in line.getMessage()


@pytest.mark.parametrize("batch", [False, True], ids=["single", "batch"])
async def test_a_store_read_fault_that_reaches_the_cap_writes_the_retry_cap_line(
    store: MessageStore,
    caplog: pytest.LogCaptureFixture,
    monkeypatch: pytest.MonkeyPatch,
    batch: bool,
) -> None:
    # The store-read-fault arm's own line goes through a FailureRun, whose backoff drops most passes
    # of a long run. A dead-letter there also writes the throttled retry-cap line.
    caplog.set_level(logging.WARNING, logger=LOGGER)
    runner = _stepped_runner(store, _Fails(), RetryPolicy(max_attempts=1, **FAST))
    await _enqueue(store, 1)
    item = await _claim(store)

    async def fault(payload: str) -> str:
        raise wiring_runner._StoreReadFault("attachment read failed")

    monkeypatch.setattr(runner, "_hydrate_payload", fault)
    if batch:
        cfg = BatchConfig(max_count=2, max_wait_ms=1)
        runner._batch[OUT] = cfg
        await runner._process_delivery_batch(OUT, item, cfg)
    else:
        await runner._process_delivery_item(OUT, item)
    assert await _status(store, item.id) == OutboxStatus.DEAD.value
    (line,) = _exhausted_lines(caplog)
    assert "could not be read from the store" in line.getMessage() and item.id in line.getMessage()


def test_held_reports_the_rows_a_pair_holds() -> None:
    # Item 7: the tests read the held count through a public method, not the private table.
    log = _RefusalLog(window=60.0, clock=lambda: 0.0)
    refusal = NegativeAckError("x", code="AR", permanent=True)
    log.warning("a", refusal, 1, "refused")
    log.warning("a", refusal, 3, "refused")
    log.warning("a", refusal, 2, "ran out", exhausted=True)
    log.warning("a", refusal, 4, "ran out", exhausted=True)
    assert log.held("a", "AR") == 3
    assert log.held("a", "AR", exhausted=True) == 4
    assert log.held("b", "AR") == 0
