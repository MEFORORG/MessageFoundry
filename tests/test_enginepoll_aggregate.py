# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Cluster-wide aggregation in :class:`~harness.load.enginepoll.EnginePoller`.

A ``supervise`` cluster spreads inbounds across several shard APIs; the poller must poll EVERY shard
and SUM their /stats so the no-loss reconcile + drain see true cluster totals. These drive the poller
with FAKE per-shard samples (no live engine) and assert: (1) a cluster sample is the per-field sum
across shards; (2) one shard being briefly unreachable skips the whole sample (no too-low aggregate);
(3) ``await_drain`` only completes once ALL shards report ``in_pipeline == 0`` and an empty backlog.

The real :meth:`EnginePoller._sample_sync` aggregation is exercised end-to-end — only the per-shard
read (``_sample_shard``, the one method that touches the HTTP client) is faked, by scripting each fake
"client" object with the sequence of per-tick samples it should return.
"""

from __future__ import annotations

import asyncio
import time

import pytest

from harness.load import enginepoll
from harness.load.enginepoll import EnginePoller, _ShardSample


def _shard(
    *,
    pending: int = 0,
    inflight: int = 0,
    done: int = 0,
    dead: int = 0,
    read: int = 0,
    written: int = 0,
    out_dead: int = 0,
    queue_depth: int = 0,
    in_pipeline: int = 0,
    db_size_bytes: int = 0,
    uptime_s: float = 1.0,
    journal_mode: str = "wal",
) -> _ShardSample:
    return _ShardSample(
        pending=pending,
        inflight=inflight,
        done=done,
        dead=dead,
        read=read,
        written=written,
        out_dead=out_dead,
        queue_depth=queue_depth,
        in_pipeline=in_pipeline,
        db_size_bytes=db_size_bytes,
        uptime_s=uptime_s,
        journal_mode=journal_mode,
    )


class _FakeClient:
    """A scripted stand-in for an opened EngineClient: pops the next per-tick sample on each read."""

    def __init__(self, samples: list[_ShardSample | None]) -> None:
        self._samples = iter(samples)

    def next_sample(self) -> _ShardSample | None:
        return next(self._samples)


def _poller_over(
    per_shard_scripts: list[list[_ShardSample | None]], monkeypatch: pytest.MonkeyPatch
) -> EnginePoller:
    """A 3-URL poller whose ``_sample_shard`` reads from each fake client's script (one list per shard,
    indexed by tick). The REAL ``_sample_sync`` aggregation runs over those per-shard reads."""
    poller = EnginePoller(
        ["http://shard-a", "http://shard-b", "http://shard-c"], None, origin=time.perf_counter()
    )
    poller._clients = [_FakeClient(s) for s in per_shard_scripts]  # type: ignore[list-item]

    def fake_sample_shard(client: object) -> _ShardSample | None:
        assert isinstance(client, _FakeClient)
        return client.next_sample()

    monkeypatch.setattr(enginepoll.EnginePoller, "_sample_shard", staticmethod(fake_sample_shard))
    return poller


def test_duplicate_engine_urls_are_deduped() -> None:
    # Footgun guard: passing the primary --engine ALSO as a --shard-engine would double-count that
    # shard's read/written/backlog and mask real loss. Constructor de-dups, order-preserving.
    poller = EnginePoller(
        ["http://shard-a", "http://shard-b", "http://shard-a"], None, origin=time.perf_counter()
    )
    assert poller._urls == ["http://shard-a", "http://shard-b"]


def test_sample_is_per_field_sum_across_shards(monkeypatch: pytest.MonkeyPatch) -> None:
    poller = _poller_over(
        [
            [_shard(read=100, written=90, pending=3, inflight=2, in_pipeline=5, queue_depth=5)],
            [_shard(read=50, written=40, pending=1, inflight=0, in_pipeline=1, queue_depth=1)],
            [_shard(read=10, written=10, pending=0, inflight=0, in_pipeline=0, queue_depth=0)],
        ],
        monkeypatch,
    )
    sample = asyncio.run(poller.sample_once())
    assert sample is not None
    assert sample.read == 160  # 100 + 50 + 10
    assert sample.written == 140  # 90 + 40 + 10
    assert sample.backlog == 6  # (3+2) + (1+0) + 0
    assert sample.in_pipeline == 6  # 5 + 1 + 0
    assert sample.queue_depth == 6  # 5 + 1 + 0


def test_one_unreachable_shard_skips_the_whole_sample(monkeypatch: pytest.MonkeyPatch) -> None:
    # Shard B unreachable on this tick → no aggregate recorded (a too-low sum would poison the
    # baseline/final no-loss math). Single-shard semantics: skip this tick, keep polling.
    poller = _poller_over([[_shard(read=100)], [None], [_shard(read=10)]], monkeypatch)
    sample = asyncio.run(poller.sample_once())
    assert sample is None
    assert poller.samples == []


def test_await_drain_waits_for_every_shard_to_empty(monkeypatch: pytest.MonkeyPatch) -> None:
    # Drain needs the AGGREGATE in_pipeline==0. Tick layout (prev + 2 polls), per shard:
    #   shard A: empty, empty, empty
    #   shard B: empty, empty, empty
    #   shard C: empty, busy(in_pipeline=2), empty
    # → poll 1 (tick 2) is NOT drained (C busy); poll 2 (tick 3) all empty + stable → drained.
    empty = _shard(read=160, written=160, in_pipeline=0, pending=0, inflight=0, queue_depth=0)
    c_busy = _shard(read=160, written=160, in_pipeline=2, pending=0, inflight=0, queue_depth=0)
    poller = _poller_over(
        [
            [empty, empty, empty],
            [empty, empty, empty],
            [empty, c_busy, empty],
        ],
        monkeypatch,
    )
    drain = asyncio.run(poller.await_drain(timeout=5.0, interval=0.01))
    assert drain is not None
    assert len(poller.samples) == 3  # prev/baseline + the busy poll + the drained poll


def test_await_drain_times_out_if_a_shard_never_empties(monkeypatch: pytest.MonkeyPatch) -> None:
    busy = _shard(read=10, written=8, in_pipeline=2)
    empty = _shard(read=10, written=10, in_pipeline=0)
    # Shard C is perpetually busy → the aggregate never drains within the timeout.
    poller = _poller_over(
        [[empty] * 50, [empty] * 50, [busy] * 50],
        monkeypatch,
    )
    drain = asyncio.run(poller.await_drain(timeout=0.1, interval=0.01))
    assert drain is None
