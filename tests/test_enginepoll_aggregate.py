# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Cluster-wide aggregation in :class:`~harness.load.enginepoll.EnginePoller`.

A ``supervise`` cluster spreads inbounds across several engine shard APIs over one store; the poller
must poll EVERY engine shard, sum the per-engine-shard counters and read the store-wide gauges once
(BACKLOG #5950), so the no-loss reconcile + drain see true cluster totals. These drive the poller
with FAKE per-shard samples (no live engine) and assert: (1) a cluster sample aggregates each field
that way; (2) one shard being briefly unreachable skips the whole sample (no too-low aggregate);
(3) ``await_drain`` only completes once ALL shards report ``in_pipeline == 0`` and an empty backlog.

The real :meth:`EnginePoller._sample_sync` aggregation is exercised end-to-end — only the per-shard
read (``_sample_shard``, the one method that touches the HTTP client) is faked, by scripting each fake
"client" object with the sequence of per-tick samples it should return.
"""

from __future__ import annotations

import asyncio
import time
from pathlib import Path
from typing import Any

import httpx
import pytest

from harness.load import enginepoll
from harness.load.enginepoll import EnginePoller, _ShardSample
from messagefoundry.api import create_app
from messagefoundry.api.models import (
    DbInfo,
    EngineInfo,
    EngineKpis,
    StatsResponse,
    SystemStatus,
)
from messagefoundry.config.models import ConnectorType
from messagefoundry.config.settings import EgressSettings, StoreBackend
from messagefoundry.config.wiring import (
    ConnectionSpec,
    InboundConnection,
    OutboundConnection,
    Registry,
    Send,
)
from messagefoundry.pipeline import Engine
from messagefoundry.pipeline.sharding import filter_registry_for_shard, require_unified_store

_SYNTHETIC_HL7 = "MSH|^~\\&|SYNTH|SYNTH|||20260101000000||ADT^A01|C1|P|2.5.1\rPID|1||000000^^^SYN\r"


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
    synchronous: str | None = "normal",
    committed_txns: int = 0,
    claim_lock_timeouts: int = 0,
    claim_head_skips: int = 0,
    store_path: str = "srv/unified",
) -> _ShardSample:
    return _ShardSample(
        store_path=store_path,
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
        synchronous=synchronous,
        committed_txns=committed_txns,
        claim_lock_timeouts=claim_lock_timeouts,
        claim_head_skips=claim_head_skips,
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
    fakes: list[Any] = [_FakeClient(s) for s in per_shard_scripts]  # duck-typed EngineClients
    poller._clients = fakes

    def fake_sample_shard(self: EnginePoller, index: int, client: object) -> _ShardSample | None:
        assert isinstance(client, _FakeClient)
        return client.next_sample()

    monkeypatch.setattr(enginepoll.EnginePoller, "_sample_shard", fake_sample_shard)
    return poller


def test_duplicate_engine_urls_are_deduped() -> None:
    # Footgun guard: passing the primary --engine ALSO as a --shard-engine would double-count that
    # shard's read/written/backlog and mask real loss. Constructor de-dups, order-preserving.
    poller = EnginePoller(
        ["http://shard-a", "http://shard-b", "http://shard-a"], None, origin=time.perf_counter()
    )
    assert poller._urls == ["http://shard-a", "http://shard-b"]


def test_sample_sums_per_engine_shard_counters_and_not_store_wide_gauges(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """BACKLOG #5950: on one store every engine shard reports the SAME store-wide gauges.

    Mutation: sum any of the six gauges again. Red, at three times the true value."""
    store: dict[str, Any] = {
        "pending": 4,
        "inflight": 2,
        "done": 40,
        "dead": 1,
        "in_pipeline": 6,
        "db_size_bytes": 4096,
    }
    poller = _poller_over(
        [
            [_shard(read=100, written=90, out_dead=3, queue_depth=5, **store)],
            [_shard(read=50, written=40, out_dead=1, queue_depth=1, **store)],
            [_shard(read=10, written=10, out_dead=0, queue_depth=0, **store)],
        ],
        monkeypatch,
    )
    sample = asyncio.run(poller.sample_once())
    assert sample is not None
    # Per engine shard: each reports only its own inbounds' rows, so the sum is the cluster total.
    assert sample.read == 160
    assert sample.written == 140
    assert sample.out_dead == 4
    assert sample.queue_depth == 6
    # Store-wide: one reading of the one store.
    assert (sample.pending, sample.inflight, sample.done, sample.dead) == (4, 2, 40, 1)
    assert (sample.in_pipeline, sample.db_size_bytes) == (6, 4096)
    assert sample.outbound_backlog == 6
    assert sample.backlog == 6


def test_a_residual_below_the_engine_shard_count_is_not_read_as_drained(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """BACKLOG #5950, the fail-closed case. The engine shards read the store one after another, so
    the last rows can be visible to one of them only. The old sum-then-floor-divide read that as 0:
    ``(2 + 0 + 0) // 3 == 0``. Mutation: restore the sum and the division. Red."""
    poller = _poller_over(
        [[_shard(in_pipeline=2)], [_shard(in_pipeline=0)], [_shard(in_pipeline=0)]],
        monkeypatch,
    )
    sample = asyncio.run(poller.sample_once())
    assert sample is not None
    assert sample.in_pipeline == 2
    assert sample.backlog == 2


def test_engine_shards_on_different_stores_still_add_up(monkeypatch: pytest.MonkeyPatch) -> None:
    """BACKLOG #5950: ``max`` holds only within one store (ADR 0063).

    ``--shard-engine`` and ``connscale-remote`` take URLs from the operator, and nothing makes those
    engines share a store. A plain max there could hide a new dead letter: store A at 5 and store B
    going 0 to 1 reads 5 both times, a delta of 0. Mutation: take a plain max. Red."""

    def dead_with(store_b_dead: int) -> int:
        store_a = _shard(dead=5, store_path="srv/a")
        store_b = _shard(dead=store_b_dead, store_path="srv/b")
        poller = _poller_over([[store_a], [store_b], [store_a]], monkeypatch)
        sample = asyncio.run(poller.sample_once())
        assert sample is not None
        return sample.dead

    assert (dead_with(0), dead_with(1)) == (5, 6)  # A counted once, B added


def test_the_one_store_premise_is_enforced_for_engine_shards() -> None:
    """ADR 0063, the premise the max rests on: more than one engine shard needs a server store that
    they all share, and a single-file store is refused."""
    with pytest.raises(ValueError, match="ONE"):
        require_unified_store(StoreBackend.SQLITE, ["a", "b"])
    require_unified_store(StoreBackend.POSTGRES, ["a", "b"])


async def test_connection_rows_are_per_engine_shard_over_one_store(tmp_path: Path) -> None:
    """BACKLOG #5950: what makes the SUM right for read/written/queue_depth, on the real route.

    Two engine shards over one store, run in turn. Each ``/connections`` must carry only its own
    inbound's source and edge rows. Mutation: drop the ``cid not in reg.inbound`` skip in
    ``_connection_rows``. Red, because each edge would then appear on both engine shards."""
    (tmp_path / "out").mkdir()
    reg = Registry()
    for name in ("a", "b"):
        inbox = tmp_path / f"in_{name}"
        inbox.mkdir()
        reg.add_inbound(
            InboundConnection(
                f"IB_{name.upper()}",
                ConnectionSpec(
                    ConnectorType.FILE,
                    {"directory": str(inbox), "pattern": "*.hl7", "poll_seconds": 0.05},
                ),
                router="r",
                shard=name,
            )
        )
    reg.add_outbound(
        OutboundConnection(
            "out1", ConnectionSpec(ConnectorType.FILE, {"directory": str(tmp_path / "out")})
        )
    )
    reg.add_router("r", lambda m: ["h"])
    reg.add_handler("h", lambda m: Send("out1", m))

    db = tmp_path / "unified.db"
    reads: dict[str, int] = {}
    edges: dict[str, set[object]] = {}
    for shard in ("a", "b"):
        engine = await Engine.create(
            db, poll_interval=0.02, egress_settings=EgressSettings(deny_by_default=False)
        )
        try:
            engine.add_registry(filter_registry_for_shard(reg, shard))
            await engine.start()
            # Seeded after start because `read` counts from the engine's start. Both inbounds' rows
            # are in the one store each time, so only the route's filter can tell them apart.
            for channel, copies in (("IB_A", 2), ("IB_B", 3)):
                for i in range(copies):
                    await engine.store.enqueue_message(
                        channel_id=channel,
                        raw=_SYNTHETIC_HL7,
                        deliveries=[("out1", _SYNTHETIC_HL7)],
                        control_id=f"{shard}-{channel}-{i}",
                    )
            transport = httpx.ASGITransport(app=create_app(engine, allow_no_auth=True))
            async with httpx.AsyncClient(transport=transport, base_url="http://t") as client:
                rows = (await client.get("/connections")).json()
        finally:
            await engine.stop()
        reads[shard] = sum(r["read"] for r in rows if r["read"] is not None)
        edges[shard] = {
            r["channel_id"]
            for r in rows
            if r["role"] == "destination" and r["destination"] == "out1"
        }

    assert reads == {"a": 2, "b": 3}  # each engine shard counts its own, so the sum is 5
    assert edges == {"a": {"IB_A"}, "b": {"IB_B"}}


def test_committed_txns_sums_across_shards(monkeypatch: pytest.MonkeyPatch) -> None:
    # #207: the live committed_txns cost counter must aggregate like read/written — each shard runs
    # its own workers, so the cluster's durable-write cost is the sum. A per-shard read that dropped
    # a shard's txns would understate the measured txn/msg the report divides.
    poller = _poller_over(
        [
            [_shard(read=100, committed_txns=700)],
            [_shard(read=50, committed_txns=350)],
            [_shard(read=10, committed_txns=70)],
        ],
        monkeypatch,
    )
    sample = asyncio.run(poller.sample_once())
    assert sample is not None
    assert sample.committed_txns == 1120  # 700 + 350 + 70


def test_claim_lock_timeouts_sums_across_shards(monkeypatch: pytest.MonkeyPatch) -> None:
    """BACKLOG #1270: the lock-timeout counter aggregates like the other live counters.

    THIS COVERS THE SUM, AND ONLY THE SUM. ``_poller_over`` monkeypatches ``_sample_shard`` away, so
    this arm starts from a ``_ShardSample`` that ALREADY carries the value and never executes the
    line that reads it off ``/stats``. The sibling test below drives that line; the two are kept
    separate because they fail separately. Distinct per-shard values so a dropped shard cannot be
    masked by a coincidental sum.

    THE UNIT SURVIVES THE SUM. These are ROUND-TRIPS, not lanes: summing shards is right (each shard
    runs its own claimers), dividing by ``empty_claims`` would not be.
    """
    poller = _poller_over(
        [
            [_shard(read=100, claim_lock_timeouts=7, claim_head_skips=4)],
            [_shard(read=50, claim_lock_timeouts=2, claim_head_skips=0)],
            [_shard(read=10, claim_lock_timeouts=0, claim_head_skips=11)],
        ],
        monkeypatch,
    )
    sample = asyncio.run(poller.sample_once())
    assert sample is not None
    assert sample.claim_lock_timeouts == 9  # 7 + 2 + 0
    assert sample.claim_head_skips == 15  # 4 + 0 + 11 (lanes; the #1270 head-of-line skip)


def _stats(
    *,
    claim_lock_timeouts: int,
    in_pipeline: int,
    committed_txns: int,
    claim_head_skips: int = 0,
) -> StatsResponse:
    """A real ``/stats`` body. The REAL model, not a stand-in: the reader under test is a
    ``getattr(stats, "<name>", 0)``, so the field NAME is the contract, and only the real model can
    fail this test when that name moves. Named parameters rather than a ``**kwargs`` splat for the
    same reason — a typo'd field name here would be silently accepted by the splat."""
    return StatsResponse(
        outbox_by_status={"pending": 3, "inflight": 2, "done": 40, "dead": 1},
        claim_lock_timeouts=claim_lock_timeouts,
        claim_head_skips=claim_head_skips,
        in_pipeline=in_pipeline,
        committed_txns=committed_txns,
    )


def _status(path: str = ":memory:") -> SystemStatus:
    return SystemStatus(
        engine=EngineInfo(
            version="0",
            uptime_seconds=12.5,
            pid=1,
            channels_total=1,
            channels_running=1,
            channels_stopped=0,
            outbox_by_status={},
        ),
        kpis=EngineKpis(),
        db=DbInfo(
            path=path,
            size_bytes=4096,
            disk_free_bytes=1,
            disk_free_status="observed",
            journal_mode="wal",
            messages=0,
            events=0,
            audit=0,
        ),
    )


class _StatsClient:
    """A stand-in for an opened ``EngineClient``: the three reads ``_sample_shard`` performs."""

    def __init__(self, stats: StatsResponse, store_path: str = ":memory:") -> None:
        self._stats = stats
        self._store_path = store_path

    def stats(self) -> StatsResponse:
        return self._stats

    def connections(self) -> list[object]:
        return []

    def status(self) -> SystemStatus:
        return _status(self._store_path)


@pytest.mark.parametrize(
    ("paths", "done", "size"),
    [(("srv/one", "srv/one"), 40, 4096), (("srv/one", "srv/two"), 80, 8192)],
)
def test_store_identity_is_read_off_the_status_body(
    paths: tuple[str, str], done: int, size: int
) -> None:
    """BACKLOG #5950: the real ``_sample_shard`` carries ``/status`` ``db.path`` into the aggregate.

    Every other arm here fakes that read. Mutation: stop passing ``store_path``. Red on the
    two-store row, which would then read one store's figures."""
    poller = EnginePoller(["http://a", "http://b"], None, origin=time.perf_counter())
    stats = _stats(claim_lock_timeouts=0, in_pipeline=0, committed_txns=0)
    poller._clients = [_StatsClient(stats, path) for path in paths]  # type: ignore[misc]
    sample = asyncio.run(poller.sample_once())
    assert sample is not None
    assert (sample.done, sample.db_size_bytes) == (done, size)


def test_sample_shard_reads_claim_lock_timeouts_off_the_stats_body() -> None:
    """BACKLOG #1270: the ONE line in the repo that reads the ``/stats`` field actually runs.

    THE DEFECT THIS PINS, and it is a coverage hole rather than a wrong answer. Every other test in
    this file monkeypatches ``_sample_shard`` away, so ``enginepoll.py``'s
    ``getattr(stats, "claim_lock_timeouts", 0)`` — the field's only reader anywhere — never executed.
    Measured: misspelling that key to ``"claim_lock_timeout"`` left this suite at 7 passed, byte for
    byte, while the harness would have reported 0 lock timeouts forever.

    A ``getattr``-WITH-DEFAULT IS THE SHAPE THAT CANNOT FAIL LOUDLY, which is exactly why it is the
    line that most needed a test. It is there for a real reason — an older engine's ``/stats`` has no
    such field and must read as 0, not raise — so it cannot be replaced with a plain attribute read.
    That makes a test the only way the name is checked at all.

    NO MONKEYPATCH, deliberately: ``_sample_shard`` runs as shipped, over the REAL ``StatsResponse``.
    A stand-in object with the field spelled by hand would pass just as well against a renamed model,
    which would make this test agree with the defect instead of catching it.

    THE OTHER FIELDS ARE ASSERTED TOO, as a non-vacuousness control: if the read were failing wholesale
    the lock-timeout zero would be indistinguishable from a correctly-read zero."""
    poller = EnginePoller(["http://shard-a"], None, origin=time.perf_counter())
    client = _StatsClient(
        _stats(claim_lock_timeouts=7, in_pipeline=5, committed_txns=88, claim_head_skips=6)
    )
    poller._clients = [client]  # type: ignore[list-item]

    sample = asyncio.run(poller.sample_once())

    assert sample is not None
    assert sample.claim_lock_timeouts == 7, (
        "the /stats lock-timeout field did not reach the sample — the harness's only reader of it"
        " looked up a name the engine does not publish, and the getattr default made that silent"
    )
    assert sample.claim_head_skips == 6, "the /stats head-skip field did not reach the sample"
    assert (sample.in_pipeline, sample.committed_txns) == (5, 88), (
        "control: the shard read is working generally, so the assertion above is about THIS field"
    )
    assert (sample.pending, sample.inflight, sample.done, sample.dead) == (3, 2, 40, 1)


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


def test_await_drain_ends_at_once_when_stop_is_set(monkeypatch: pytest.MonkeyPatch) -> None:
    """BACKLOG #5977: a set ``stop`` ends the poll with ``None`` before its next sample, so a caller
    can end it early without cancelling a sample in flight. Mutation: ignore ``stop``. Red: the
    poll runs past the outer 5s bound (its own timeout is 30s)."""
    busy = _shard(read=10, written=8, in_pipeline=2)
    poller = _poller_over([[busy] * 50, [busy] * 50, [busy] * 50], monkeypatch)

    async def run() -> float | None:
        stop = asyncio.Event()
        stop.set()
        return await asyncio.wait_for(
            poller.await_drain(timeout=30.0, interval=0.01, stop=stop), timeout=5.0
        )

    assert asyncio.run(run()) is None
    assert len(poller.samples) == 1  # only the baseline sample
