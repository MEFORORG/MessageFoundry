# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""ADR 0157 Amendment D (BACKLOG #5724): a dead-letter that declines a resolved row reports that.

``dead_letter_now`` says whether it wrote and ``dead_letter_batch`` how many rows it wrote, so a
caller's log line and integrity alert describe a write that happened. Each decline test has its
positive control beside it. The Postgres and SQL Server returns are pinned offline in
``tests/test_adr0157_fence_scope.py`` and ``tests/test_adr0157_sqlserver_fence_offline.py``.
"""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any, cast

import pytest

from messagefoundry.config.models import BatchConfig, RetryPolicy
from messagefoundry.config.settings import EgressSettings
from messagefoundry.config.wiring import Registry
from messagefoundry.pipeline import wiring_runner
from messagefoundry.pipeline.wiring_runner import RegistryRunner
from messagefoundry.store import MessageStore, OutboxStatus
from messagefoundry.store import store as store_module
from messagefoundry.store.queue_tag import QueueTagError
from messagefoundry.transports.base import DestinationConnector, NegativeAckError
from tests._mllp_recorder import run_one_batch

OUT = "OB1"
RUNNER_LOG = "messagefoundry.pipeline.wiring_runner"
STORE_LOG = "messagefoundry.store.store"


@pytest.fixture(params=[0.0, 2.0], ids=["inline", "group-commit"])
async def store(tmp_path: Path, request: pytest.FixtureRequest) -> AsyncIterator[MessageStore]:
    s = await MessageStore.open(tmp_path / "t.db", group_commit_window_ms=request.param)
    try:
        yield s
    finally:
        await s.close()


async def _claimed(store: MessageStore, *dests: str) -> list[str]:
    await store.enqueue_message(
        channel_id="IB", raw="MSH|x", deliveries=[(d, "p") for d in dests], now=100.0
    )
    items = await store.claim_ready(now=100.0)
    return [i.id for i in sorted(items, key=lambda i: i.destination_name or "")]


async def test_dead_letter_now_says_whether_it_wrote(store: MessageStore) -> None:
    (open_row, done) = await _claimed(store, "OB1", "OB2")
    await store.mark_done(done, now=101.0)

    assert await store.dead_letter_now(open_row, "late", now=102.0) is True
    assert await store.dead_letter_now(open_row, "again", now=103.0) is False  # now DEAD
    assert await store.dead_letter_now(done, "late", now=102.0) is False
    assert await store.dead_letter_now("no-such-row", "late", now=102.0) is False


async def test_the_standalone_dead_letter_says_so_too(store: MessageStore) -> None:
    (open_row, done) = await _claimed(store, "OB1", "OB2")
    await store.mark_done(done, now=101.0)

    assert await store.dead_letter_now(open_row, "late", now=102.0, _standalone=True) is True
    assert await store.dead_letter_now(done, "late", now=102.0, _standalone=True) is False


async def test_dead_letter_batch_counts_what_it_wrote(store: MessageStore) -> None:
    done, first, second = await _claimed(store, "OB1", "OB2", "OB3")
    await store.mark_done(done, now=101.0)

    assert await store.dead_letter_batch([done, first, "gone", second], "late", now=102.0) == 2
    assert await store.dead_letter_batch([done, first, second], "late", now=103.0) == 0


@pytest.mark.parametrize("resolved", [True, False], ids=["declined", "written"])
async def test_an_unopenable_row_is_reported_only_when_it_was_written(
    store: MessageStore,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    resolved: bool,
) -> None:
    caplog.set_level(logging.WARNING, logger=STORE_LOG)
    reports: list[str] = []

    async def report(_store: Any, _cipher: Any, row: Any, **_kw: Any) -> None:
        reports.append(str(row["id"]))

    monkeypatch.setattr(store_module, "report_queue_tag_failure", report)
    (oid,) = await _claimed(store, "OB1")
    row = await store._row(oid)
    assert row is not None
    if resolved:
        await store.mark_done(oid, now=101.0)

    assert await store._dead_letter_unopenable(row, QueueTagError("refused")) is None

    lines = [r for r in caplog.records if "dead-lettering undecryptable" in r.getMessage()]
    assert (reports, len(lines)) == (([], 0) if resolved else ([oid], 1))


def _runner(store: MessageStore, connector: object | None = None) -> RegistryRunner:
    runner = RegistryRunner(
        Registry(), store, poll_interval=0.02, egress=EgressSettings(deny_by_default=False)
    )
    if connector is not None:
        runner._batch[OUT] = BatchConfig(max_count=5, max_wait_ms=1)
        runner._destinations[OUT] = cast(DestinationConnector, connector)
        runner._retry[OUT] = RetryPolicy()
        runner._simulate[OUT] = False
    return runner


@pytest.mark.parametrize(
    ("arm", "resolved"),
    [
        ("_apply_router_internal_error", True),
        ("_apply_router_internal_error", False),
        ("_apply_transform_internal_error", True),
        ("_apply_transform_internal_error", False),
    ],
)
async def test_an_internal_error_arm_logs_a_dead_letter_only_when_written(
    store: MessageStore, caplog: pytest.LogCaptureFixture, arm: str, resolved: bool
) -> None:
    caplog.set_level(logging.WARNING, logger=RUNNER_LOG)
    (oid,) = await _claimed(store, "OB1")
    item = cast(Any, type("Item", (), {"id": oid, "stage": "outbound"})())
    if resolved:
        await store.mark_done(oid, now=101.0)

    await getattr(_runner(store), arm)("IB", item, ValueError("boom"))

    lines = [r for r in caplog.records if "dead-lettering" in r.getMessage()]
    assert len(lines) == (0 if resolved else 1)


async def test_a_refused_member_already_resolved_logs_no_dead_letter(
    store: MessageStore, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.WARNING, logger=RUNNER_LOG)
    done, open_row = await _claimed(store, "OB1", "OB2")
    await store.mark_done(done, now=101.0)
    exc = NegativeAckError("refused", code="framing", permanent=True)

    await _runner(store)._dead_letter_refused(OUT, [(done, "e", exc), (open_row, "e", exc)])

    lines = [r.getMessage() for r in caplog.records if "dead-lettered" in r.getMessage()]
    assert len(lines) == 1 and open_row in lines[0] and done not in lines[0]


class _RefusesAfter:
    """Refuses the envelope permanently, after ``resolve`` settled members mid-send."""

    def __init__(self, store: MessageStore) -> None:
        self.store = store
        self.resolve: list[str] = []

    async def send(self, _payload: str) -> None:
        for oid in self.resolve:
            await self.store.mark_done(oid)
        raise NegativeAckError("refused", code="AR", permanent=True)

    async def aclose(self) -> None:
        return None


def _adt(n: int) -> str:
    return (
        f"MSH|^~\\&|APP|FAC|RECV|RFAC|20260604||ADT^A01|MSG{n}|P|2.5.1\r"
        f"PID|1||{n}00^^^H^MR||DOE^JANE\r"
    )


@pytest.mark.parametrize(("settled", "line"), [(0, "3 dead-lettered"), (1, "2 dead-lettered")])
async def test_a_refused_batch_line_counts_what_was_written(
    store: MessageStore, caplog: pytest.LogCaptureFixture, settled: int, line: str
) -> None:
    caplog.set_level(logging.WARNING, logger=RUNNER_LOG)
    connector = _RefusesAfter(store)
    ids = [
        await _enqueue(store, n)
        for n in (1, 2, 3)  # in lane order
    ]
    connector.resolve = ids[:settled]

    await run_one_batch(_runner(store, connector), OUT)

    assert await store.count_dead(allowed_channels=None) == 3 - settled
    (record,) = [r for r in caplog.records if "refused permanently" in r.msg]
    assert line in record.getMessage()


async def test_a_refused_batch_all_resolved_logs_no_dead_letter(
    store: MessageStore, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.WARNING, logger=RUNNER_LOG)
    connector = _RefusesAfter(store)
    connector.resolve = [await _enqueue(store, n) for n in (1, 2)]

    await run_one_batch(_runner(store, connector), OUT)

    assert await store.count_dead(allowed_channels=None) == 0
    assert not [r for r in caplog.records if "refused permanently" in r.msg]


async def _enqueue(store: MessageStore, n: int) -> str:
    mid = await store.enqueue_message(
        channel_id="IB", raw=_adt(n), deliveries=[(OUT, _adt(n))], now=100.0 + n
    )
    return str((await store.outbox_for(mid))[0]["id"])


def test_the_stop_line_names_the_first_member_still_open(
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.WARNING, logger=RUNNER_LOG)
    outcome = store_module.FailOutcome(dead=2, head_id="h", attempts=5, dead_messages=("a", "b"))

    wiring_runner._note_stop_dead_letter("delivery worker", OUT, outcome, OutboxStatus.DEAD.value)

    assert "batch row h, the first one still open, had made 5" in caplog.records[0].getMessage()
