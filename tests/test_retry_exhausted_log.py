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
from typing import cast

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
from messagefoundry.pipeline.wiring_runner import RegistryRunner, _RefusalLog
from messagefoundry.store import MessageStatus, MessageStore, OutboxItem
from messagefoundry.transports.base import DeliveryError, DestinationConnector, NegativeAckError
from tests._refusal_log_capture import TOKEN, assert_no_token

OUT = "file_out"
LOGGER = "messagefoundry.pipeline.wiring_runner"
EXHAUSTED = "the retry cap"
# Tiny backoff, so the real worker's retry comes due at once.
FAST = {"backoff_seconds": 0.01, "max_backoff_seconds": 0.01}


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
    """A connector whose every send fails transiently, with the payload's token in the error text."""

    def __init__(self, transient_nak: bool = False) -> None:
        self.transient_nak = transient_nak
        self.calls = 0

    async def send(self, payload: str) -> None:
        self.calls += 1
        assert TOKEN in payload
        if self.transient_nak:
            raise NegativeAckError(f"try later, patient {TOKEN}", code="AE", permanent=False)
        raise DeliveryError(f"connection reset sending {TOKEN}")

    async def aclose(self) -> None:
        return None


# Not this item's line: the DeliveryError arm's edge-triggered connection_lost alert logs
# safe_exc(exc), which leaves this plain-text token in place. That predates #3108 and is reported
# with it, so it is skipped here by its exact shape rather than by its logger.
_PRE_EXISTING_ALERT = "ALERT connection_error: outbound 'file_out' connection_lost: DeliveryError:"


def _assert_no_token(records: Iterable[logging.LogRecord]) -> None:
    assert_no_token(records, skip_prefix=_PRE_EXISTING_ALERT)


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
        loop = asyncio.get_running_loop()
        deadline = loop.time() + 5.0
        while await store.count_dead() != 1:
            assert loop.time() < deadline, "the row never dead-lettered"
            await asyncio.sleep(0.02)
    finally:
        await runner.stop()

    assert dest.calls == 2
    (msg,) = await store.list_messages(channel_id="file_in")
    assert msg["status"] == MessageStatus.ERROR.value  # the dead-letter itself is unchanged
    (line,) = _exhausted_lines(caplog)
    text = line.getMessage()
    assert repr(OUT) in text and str(msg["id"]) in text
    assert "DeliveryError" in text and "code '?'" in text
    assert "dead-lettered after 2 attempt(s)" in text
    _assert_no_token(caplog.records)


def _stepped_runner(store: MessageStore, connector: object, retry: RetryPolicy) -> RegistryRunner:
    runner = RegistryRunner(
        Registry(), store, poll_interval=0.02, egress=EgressSettings(deny_by_default=False)
    )
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
        dead = await store.count_dead()
        assert dead == (1 if attempt == 3 else 0)
        assert len(_exhausted_lines(caplog)) == dead  # the line and the DEAD write move together
    (line,) = _exhausted_lines(caplog)
    text = line.getMessage()
    assert "dead-lettered after 3 attempt(s)" in text
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
    assert await store.count_dead() == 0
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
    assert await store.count_dead() == 3
    (line,) = _exhausted_lines(caplog)
    text = line.getMessage()
    assert repr(OUT) in text and "a batch of 3" in text and head_ids[-1] in text
    assert "DeliveryError" in text and "dead-lettered after 2 attempt(s)" in text
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


async def test_a_none_from_the_store_below_the_cap_is_a_vanished_row_and_writes_nothing(
    store: MessageStore, caplog: pytest.LogCaptureFixture
) -> None:
    # mark_failed returns None for a dead-lettered row AND for one that no longer exists. The
    # store's own rule (attempts >= max_attempts) on the claimed attempts tells the two apart.
    caplog.set_level(logging.WARNING, logger=LOGGER)
    retry = RetryPolicy(max_attempts=2, **FAST)
    runner = _stepped_runner(store, _Fails(), retry)
    exc = DeliveryError("x")

    def row(attempts: int) -> OutboxItem:
        return OutboxItem("r1", "m1", "c1", OUT, "payload", attempts, "outbound")

    runner._note_retry_exhausted(OUT, exc, retry, None, [row(1)])  # one below the cap: vanished
    runner._note_retry_exhausted(OUT, exc, retry, None, [], batch=True)  # an empty batch
    runner._note_retry_exhausted(OUT, exc, retry, 123.0, [row(2)])  # re-pended: the store's word
    assert _exhausted_lines(caplog) == []
    runner._note_retry_exhausted(OUT, exc, retry, None, [row(2)])  # at the cap: dead-lettered
    assert len(_exhausted_lines(caplog)) == 1
