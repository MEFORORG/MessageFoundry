# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Outbound batch aggregation — BACKLOG #134 / ADR 0082 acceptance criteria.

A batching outbound coalesces its contiguous FIFO head-prefix into one ``BHS``…``BTS`` envelope on a
single send (``_process_delivery_batch``), completing all N atomically. These drive the shared batch
delivery body through a minimal ``RegistryRunner`` + a recording connector, on **both** SQLite and
(gated) SQL Server, and cover every ADR 0082 acceptance criterion.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, AsyncIterator

import pytest

from messagefoundry.config.models import BatchConfig, RetryPolicy
from messagefoundry.config.wiring import Registry
from messagefoundry.parsing.split import split_batch
from messagefoundry.pipeline.wiring_runner import RegistryRunner
from messagefoundry.store import MessageStore, Stage
from messagefoundry.transports.base import DeliveryError, NegativeAckError

DEST = "OB_ADT"


def _msg(n: int) -> str:
    return f"MSH|^~\\&|A|B|C|D|2026010100000{n}||ADT^A0{n}|MSG{n}|P|2.5.1\rPID|1||{n}00||DOE^P{n}\r"


# --- store fixture: SQLite always, SQL Server when MEFOR_TEST_SQLSERVER is set --------------------


async def _open_sqlserver() -> Any:
    from messagefoundry.config.settings import load_settings
    from messagefoundry.store.sqlserver import SqlServerStore

    store = await SqlServerStore.open(load_settings(environ=os.environ).store)
    async with store._pool.acquire() as conn:
        cur = await conn.cursor()
        for table in ("message_events", "state", "queue", "response", "outbox", "messages"):
            await cur.execute(f"DELETE FROM {table}")
        await conn.commit()
    return store


@pytest.fixture(params=["sqlite", "sqlserver"])
async def store(request: Any, tmp_path: Path) -> AsyncIterator[Any]:
    if request.param == "sqlserver":
        if not os.getenv("MEFOR_TEST_SQLSERVER"):
            pytest.skip("set MEFOR_TEST_SQLSERVER=1 (+ MEFOR_STORE_* env) for the SQL Server leg")
        s = await _open_sqlserver()
    else:
        s = await MessageStore.open(tmp_path / "batch.db")
    yield s
    await s.close()


class _Recorder:
    """A fake outbound connector that records each sent envelope (or fails, per `fail`)."""

    def __init__(self, fail: Exception | None = None) -> None:
        self.sent: list[str] = []
        self.fail = fail

    async def send(self, payload: str) -> None:
        if self.fail is not None:
            raise self.fail
        self.sent.append(payload)

    async def aclose(self) -> None:
        return None


def _runner(store: Any, *, claim_mode: str = "per_lane") -> RegistryRunner:
    return RegistryRunner(Registry(), store, poll_interval=0.02, claim_mode=claim_mode)


def _wire_batch(
    runner: RegistryRunner, connector: Any, cfg: BatchConfig, *, retry: RetryPolicy | None = None
) -> None:
    runner._batch[DEST] = cfg
    runner._destinations[DEST] = connector
    runner._retry[DEST] = retry or RetryPolicy()
    runner._simulate[DEST] = False


async def _enqueue(store: Any, n: int, *, now0: float = 100.0) -> list[str]:
    """Enqueue N single-delivery messages to DEST (seq/FIFO order). Returns message ids."""
    mids = []
    for i in range(1, n + 1):
        mids.append(
            await store.enqueue_message(
                channel_id="c1", raw=_msg(i), deliveries=[(DEST, _msg(i))], now=now0 + i
            )
        )
    return mids


# --- AC1: N rows → one BHS…BTS envelope on a single send ------------------------------------------


async def test_n_rows_one_envelope(store: Any) -> None:
    await _enqueue(store, 3)
    runner = _runner(store)
    rec = _Recorder()
    _wire_batch(runner, rec, BatchConfig(max_count=5, max_wait_ms=1))  # 1ms → head ages out at once
    head = await store.claim_next_fifo(DEST)
    outcome, _ = await runner._process_delivery_batch(DEST, head, runner._batch[DEST])
    assert len(rec.sent) == 1  # ONE send for all three rows
    env = rec.sent[0]
    assert env.startswith("BHS") and "BTS|3" in env
    members = split_batch(env)
    assert [m.split("|")[9] for m in members] == ["MSG1", "MSG2", "MSG3"]  # in FIFO order
    # every message finalized PROCESSED, nothing left pending
    depth, _ = await store.pending_depth(DEST)
    assert depth == 0 and await store.count_dead() == 0


# --- AC2: a crash mid-batch loses no message and reorders none -----------------------------------


async def test_crash_midbatch_no_loss_no_reorder(store: Any) -> None:
    # Part A — a TRUE crash: claim the whole batch INFLIGHT, then die before completing. Nothing is
    # completed; reset_stale_inflight (restart recovery) returns all three to PENDING in seq order.
    await _enqueue(store, 3)
    for _ in range(3):
        assert await store.claim_next_fifo(DEST) is not None  # all three now INFLIGHT
    depth, _ = await store.pending_depth(DEST)
    assert depth == 0  # in flight, not pending
    await store.reset_stale_inflight()  # as if after a restart (recovered rows become due now)
    depth, _ = await store.pending_depth(DEST)
    assert depth == 3 and await store.count_dead() == 0  # all three recovered, none lost

    # Part B — atomic failure: a transient transport failure re-pends ALL three together (never a split
    # batch); a re-delivery then frames them in the identical prefix order. Zero backoff so the re-pended
    # rows are immediately re-claimable within the test.
    runner = _runner(store)
    zero_backoff = RetryPolicy(backoff_seconds=0.0, backoff_multiplier=1.0)
    _wire_batch(
        runner,
        _Recorder(fail=DeliveryError("partner unreachable")),
        BatchConfig(max_count=5, max_wait_ms=1),
        retry=zero_backoff,
    )
    head = await store.claim_next_fifo(DEST)
    _outcome, retry_until = await runner._process_delivery_batch(DEST, head, runner._batch[DEST])
    assert retry_until is not None  # rescheduled, not dead-lettered
    depth, _ = await store.pending_depth(DEST)
    assert depth == 3 and await store.count_dead() == 0  # all three back, none lost

    ok = _Recorder()
    runner._destinations[DEST] = ok
    head2 = await store.claim_next_fifo(DEST)
    await runner._process_delivery_batch(DEST, head2, runner._batch[DEST])
    assert len(ok.sent) == 1  # one envelope
    assert [m.split("|")[9] for m in split_batch(ok.sent[0])] == [
        "MSG1",
        "MSG2",
        "MSG3",
    ]  # order held
    assert (await store.pending_depth(DEST))[0] == 0


# --- AC3: a re-run produces the byte-identical envelope (deterministic) ---------------------------


async def test_rerun_identical_envelope(store: Any, tmp_path: Path) -> None:
    # Deliver the same logical batch (identical raws + identical ingest times) against two fresh stores;
    # the envelope must be byte-identical — the at-least-once re-run guarantee at the delivery level.
    async def deliver_once(s: Any) -> str:
        await _enqueue(s, 3, now0=500.0)
        r = _runner(s)
        rec = _Recorder()
        _wire_batch(r, rec, BatchConfig(max_count=5, max_wait_ms=1))
        head = await s.claim_next_fifo(DEST)
        await r._process_delivery_batch(DEST, head, r._batch[DEST])
        return rec.sent[0]

    env1 = await deliver_once(store)
    s2 = await MessageStore.open(tmp_path / "rerun.db")
    try:
        env2 = await deliver_once(s2)
    finally:
        await s2.close()
    assert (
        env1 == env2
    )  # byte-identical: BHS-7 from created_at, BHS-11 from head control id, no clock


# --- AC4a: a permanent envelope reject dead-letters all N (ADR 0082 decision #1) ------------------


async def test_permanent_reject_deadletters_all(store: Any) -> None:
    await _enqueue(store, 3)
    runner = _runner(store)
    reject = _Recorder(fail=NegativeAckError("partner rejected batch", code="AR", permanent=True))
    _wire_batch(runner, reject, BatchConfig(max_count=5, max_wait_ms=1))
    head = await store.claim_next_fifo(DEST)
    _outcome, retry_until = await runner._process_delivery_batch(DEST, head, runner._batch[DEST])
    assert retry_until is None
    assert await store.count_dead() == 3  # all three dead-lettered atomically
    depth, _ = await store.pending_depth(DEST)
    assert depth == 0


# --- AC4b: a graceful stop flushes the partial batch (decision #4) --------------------------------


async def test_graceful_stop_flushes_partial(store: Any) -> None:
    await _enqueue(store, 2)  # only 2 rows, but max_count=5 and a long wait
    runner = _runner(store)
    rec = _Recorder()
    _wire_batch(runner, rec, BatchConfig(max_count=5, max_wait_ms=60000))  # 60s wait
    runner._stop.set()  # a graceful stop is in progress
    head = await store.claim_next_fifo(DEST)
    # Must NOT wait 60s: it drains the 2 instantly-available rows and flushes them at once.
    outcome, _ = await runner._process_delivery_batch(DEST, head, runner._batch[DEST])
    assert len(rec.sent) == 1
    assert "BTS|2" in rec.sent[0]  # the partial of two was flushed, not stranded
    depth, _ = await store.pending_depth(DEST)
    assert depth == 0


# --- AC5: batching runs within the pooled claim; the default claim_mode is unchanged --------------


async def test_batch_within_pooled_claim(store: Any) -> None:
    # In pooled mode the dispatcher claims one head per lane; _dispatch_delivery routes a batching lane
    # to the same batch body, which coalesces its own tail — so batching works with NO per_lane forcing.
    await _enqueue(store, 3)
    runner = _runner(store, claim_mode="pooled")
    assert runner._claim_mode == "pooled"  # the DEFAULT mode, not forced to per_lane
    rec = _Recorder()
    _wire_batch(runner, rec, BatchConfig(max_count=5, max_wait_ms=1))
    head = await store.claim_next_fifo(DEST)
    result = await runner._dispatch_delivery(DEST, head)  # the pooled dispatch adapter
    assert result.kind.name == "RESOLVED"
    assert len(rec.sent) == 1 and "BTS|3" in rec.sent[0]
    depth, _ = await store.pending_depth(DEST)
    assert depth == 0


# --- fix: claim_fifo_heads (the POOLED claim) projects created_at on every backend ---------------


async def test_pooled_claim_projects_created_at(store: Any) -> None:
    # The pooled dispatcher claims the batch head via claim_fifo_heads; it MUST carry created_at, else a
    # pooled-mode batch on SQL Server frames an empty BHS-7 and measures the window from claim-time.
    await _enqueue(store, 1, now0=700.0)
    result = await store.claim_fifo_heads(Stage.OUTBOUND.value, [DEST], per_lane_limit=1)
    items = result.by_lane[DEST]
    assert len(items) == 1
    assert items[0].created_at == 701.0  # the enqueue ingest time, not None / not claim-time


# --- fix: an unparseable / non-HL7 head DEAD-LETTERS the batch, never strands it INFLIGHT ----------


async def test_unparseable_head_dead_letters_not_strands(store: Any) -> None:
    # An MLLP outbound is payload-agnostic (ADR 0004): a non-HL7 body can reach the batch framer. It must
    # dead-letter (framing inside the try) — NOT leave every claimed row INFLIGHT forever.
    bad = "MSH|^~|X\r"  # MSH-2 has < 4 encoding chars → _encoding_chars raises at frame time
    await store.enqueue_message(channel_id="c1", raw=bad, deliveries=[(DEST, bad)], now=101.0)
    await store.enqueue_message(channel_id="c1", raw=bad, deliveries=[(DEST, bad)], now=102.0)
    runner = _runner(store)
    rec = _Recorder()
    _wire_batch(runner, rec, BatchConfig(max_count=5, max_wait_ms=1))
    head = await store.claim_next_fifo(DEST)
    await runner._process_delivery_batch(DEST, head, runner._batch[DEST])
    assert rec.sent == []  # nothing framed/sent
    assert (
        await store.count_dead() == 2
    )  # both dead-lettered (CONTINUE policy), none stranded INFLIGHT
    depth, _ = await store.pending_depth(DEST)
    assert depth == 0


# --- fix: the head is carried VERBATIM (parsed only for separators/control-id, never re-encoded) ---


async def test_head_carried_verbatim(store: Any) -> None:
    await _enqueue(store, 2)
    runner = _runner(store)
    rec = _Recorder()
    _wire_batch(runner, rec, BatchConfig(max_count=5, max_wait_ms=1))
    head = await store.claim_next_fifo(DEST)
    await runner._process_delivery_batch(DEST, head, runner._batch[DEST])
    env = rec.sent[0]
    # The head member's exact segments (incl its PID) appear verbatim in the envelope body.
    assert "PID|1||100||DOE^P1" in env and "MSG1" in env


# --- count trigger: max_count caps a batch even when more are available --------------------------


async def test_max_count_caps_the_batch(store: Any) -> None:
    await _enqueue(store, 5)
    runner = _runner(store)
    rec = _Recorder()
    _wire_batch(runner, rec, BatchConfig(max_count=2, max_wait_ms=1))
    # First batch: exactly 2 (the count trigger caps it, leaving 3 pending).
    head = await store.claim_next_fifo(DEST)
    await runner._process_delivery_batch(DEST, head, runner._batch[DEST])
    assert "BTS|2" in rec.sent[0]
    depth, _ = await store.pending_depth(DEST)
    assert depth == 3
