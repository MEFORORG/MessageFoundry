# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The executor gauges take the worst engine shard, as their own comment says (BACKLOG #5950 item 1).

``executor_queue_depth`` and ``executor_busy`` are per-process gauges: each engine shard runs its own
default executor. ``EnginePoller._sample_sync`` read the first engine shard that reported one, so a
saturated executor on any other engine shard read as the first one's figure. Only the per-shard read
is faked here; the real aggregation runs.
"""

from __future__ import annotations

import asyncio
import time
from typing import Any

import pytest

from harness.load import enginepoll
from harness.load.enginepoll import EnginePoller, _ShardSample


def _shard(*, queue_depth: int | None, busy: int | None) -> _ShardSample:
    return _ShardSample(
        pending=0,
        inflight=0,
        done=0,
        dead=0,
        read=0,
        written=0,
        out_dead=0,
        queue_depth=0,
        in_pipeline=0,
        db_size_bytes=0,
        uptime_s=1.0,
        journal_mode="wal",
        synchronous="normal",
        executor_queue_depth=queue_depth,
        executor_busy=busy,
    )


def _sample(shards: list[_ShardSample], monkeypatch: pytest.MonkeyPatch) -> Any:
    poller = EnginePoller(
        [f"http://shard-{i}" for i in range(len(shards))], None, origin=time.perf_counter()
    )
    poller._clients = list(range(len(shards)))  # type: ignore[arg-type]  # stand-ins, never called

    def fake_sample_shard(self: EnginePoller, index: int, client: object) -> _ShardSample:
        return shards[index]

    monkeypatch.setattr(enginepoll.EnginePoller, "_sample_shard", fake_sample_shard)
    sample = asyncio.run(poller.sample_once())
    assert sample is not None
    return sample


def test_a_saturated_executor_on_a_later_engine_shard_is_reported(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sample = _sample(
        [
            _shard(queue_depth=0, busy=1),
            _shard(queue_depth=7, busy=4),
            _shard(queue_depth=2, busy=2),
        ],
        monkeypatch,
    )
    assert sample.executor_queue_depth == 7
    assert sample.executor_busy == 4


def test_an_engine_shard_without_the_shim_does_not_mask_one_with_it(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sample = _sample(
        [_shard(queue_depth=None, busy=None), _shard(queue_depth=3, busy=5)], monkeypatch
    )
    assert sample.executor_queue_depth == 3
    assert sample.executor_busy == 5


def test_no_shim_anywhere_still_reads_none(monkeypatch: pytest.MonkeyPatch) -> None:
    sample = _sample(
        [_shard(queue_depth=None, busy=None), _shard(queue_depth=None, busy=None)], monkeypatch
    )
    assert sample.executor_queue_depth is None
    assert sample.executor_busy is None


def test_a_single_engine_reading_is_unchanged(monkeypatch: pytest.MonkeyPatch) -> None:
    sample = _sample([_shard(queue_depth=6, busy=3)], monkeypatch)
    assert sample.executor_queue_depth == 6
    assert sample.executor_busy == 3
