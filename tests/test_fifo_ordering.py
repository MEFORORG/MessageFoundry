"""FIFO-per-outbound delivery (ordering Phase 1, layer 2).

Store-level: ``claim_next_fifo`` returns the oldest *due* head per destination and **blocks the lane**
while that head backs off (head-of-line), so a failing message is never overtaken. Runner-level: the
ordering mode resolves global-default → per-connection override, defaulting to FIFO.
"""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from messagefoundry import OrderingMode, RetryPolicy
from messagefoundry.config.wiring import load_config
from messagefoundry.pipeline import Engine
from messagefoundry.store import MessageStore


@pytest.fixture
async def store(tmp_path: Path):
    s = await MessageStore.open(tmp_path / "fifo.db")
    yield s
    await s.close()


async def test_claim_next_fifo_returns_oldest_then_next(store: MessageStore) -> None:
    for i, now in enumerate((100.0, 101.0, 102.0), start=1):
        await store.enqueue_message(channel_id="c1", raw="x", deliveries=[("d1", f"p{i}")], now=now)
    first = await store.claim_next_fifo("d1", now=200.0)
    assert first is not None and first.payload == "p1"  # oldest enqueued goes first
    await store.mark_done(first.id, now=200.0)
    second = await store.claim_next_fifo("d1", now=200.0)
    assert second is not None and second.payload == "p2"  # then the next oldest, in order


async def test_claim_next_fifo_blocks_head_on_backoff(store: MessageStore) -> None:
    await store.enqueue_message(channel_id="c1", raw="x", deliveries=[("d1", "p1")], now=100.0)
    await store.enqueue_message(channel_id="c1", raw="x", deliveries=[("d1", "p2")], now=101.0)
    head = await store.claim_next_fifo("d1", now=100.0)
    assert head is not None and head.payload == "p1"
    # Head fails → backs off 5s (next_attempt_at = 105).
    await store.mark_failed(
        head.id, "boom", RetryPolicy(max_attempts=9, backoff_seconds=5), now=100.0
    )
    # While the head backs off, FIFO returns NOTHING — it must NOT skip ahead to p2 (head-of-line).
    assert await store.claim_next_fifo("d1", now=102.0) is None
    # Once due again, it re-offers the SAME head (p1), still ahead of p2.
    again = await store.claim_next_fifo("d1", now=105.0)
    assert again is not None and again.payload == "p1"


async def test_claim_next_fifo_is_per_destination(store: MessageStore) -> None:
    await store.enqueue_message(
        channel_id="c1", raw="x", deliveries=[("d1", "a"), ("d2", "b")], now=100.0
    )
    a = await store.claim_next_fifo("d1", now=100.0)
    b = await store.claim_next_fifo("d2", now=100.0)
    assert a is not None and a.payload == "a"
    assert b is not None and b.payload == "b"
    assert await store.claim_next_fifo("d1", now=100.0) is None  # d1's only row is now inflight


async def test_claim_next_fifo_none_when_empty(store: MessageStore) -> None:
    assert await store.claim_next_fifo("nope", now=100.0) is None


async def test_runner_resolves_ordering_override_over_default(tmp_path: Path) -> None:
    for d in ("in", "a", "b"):
        (tmp_path / d).mkdir()
    cfgdir = tmp_path / "cfg"
    cfgdir.mkdir()
    (cfgdir / "c.py").write_text(
        textwrap.dedent(
            f"""
            from messagefoundry import outbound, inbound, router, File, OrderingMode
            outbound("ob_default", File(directory={str(tmp_path / "a")!r}, filename="{{MSH-10}}.hl7"))
            outbound("ob_override", File(directory={str(tmp_path / "b")!r}, filename="{{MSH-10}}.hl7"),
                     ordering=OrderingMode.UNORDERED)
            inbound("in", File(directory={str(tmp_path / "in")!r}, pattern="*.hl7", poll_seconds=0.05),
                    router="r")

            @router("r")
            def route(msg):
                return []
            """
        )
    )
    engine = await Engine.create(tmp_path / "mf.db", ordering_default=OrderingMode.FIFO)
    engine.add_registry(load_config(cfgdir))
    await engine.start()
    try:
        ordering = engine._registry_runner._ordering  # type: ignore[union-attr]
        assert ordering["ob_default"] is OrderingMode.FIFO  # inherited the global default
        assert ordering["ob_override"] is OrderingMode.UNORDERED  # per-connection override wins
    finally:
        await engine.stop()
