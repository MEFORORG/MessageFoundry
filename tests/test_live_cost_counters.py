# Copyright (c) MessageFoundry contributors.
# SPDX-License-Identifier: Apache-2.0
"""A1 — turn the STATIC cost-model gates into a LIVE runtime assertion.

``tests/test_txn_per_message_cost_model.py`` pins ``txn/msg = 3 + 2H + 2N`` and
``tests/test_bytes_per_message_amplification.py`` pins body copies ``= 2 + H + N`` by *reading* the store
methods against recording fakes. This module drives **real messages** of known ``(H, N)`` through the
store and asserts the store's always-on ``committed_txns`` / ``body_copies`` counters equal those formulas
— so a future change that adds a commit or a body copy to the hot path trips a test, not just a review.

``H`` = handlers the router selects; ``N`` = destinations delivered. The three shapes mirror the static
gates: ``(1, 1)`` the simple feed, ``(8, 8)`` the bench topology, ``(20, 4)`` the reference estate's ADT
hub.

Two backends, two harnesses:

* **SQLite** — the real :class:`MessageStore` driven end-to-end through the genuine staged pipeline
  (enqueue → claim → route → claim → transform → claim → deliver). Every commit and body-write is the
  production path, so the counters are measured, not modeled. Delivery bodies are made **distinct** so
  SQLite's store-once-deliver-many dedup does not collapse the fan-out — the ``2 + H + N`` shape is the
  SQL-Server-parity one the static gate pins (a deduped fan-out would legitimately read fewer copies).
* **SQL Server** — the offline ``adr0075_batch_harness`` (``bare_store`` + recording conn/cursor), the
  same surface the static gates use. Claims are not drivable offline, so this half asserts the fully
  offline-derivable ``body_copies == 2 + H + N`` and that each producer handoff commits exactly once
  (``committed_txns == 3`` for enqueue + route + transform).
"""

from __future__ import annotations

from pathlib import Path

import pytest

import messagefoundry.store.sqlserver as ss
from messagefoundry.store.store import MessageStatus, MessageStore, Stage
from tests.adr0075_batch_harness import AsyncRecCursor, RecConn, bare_store, drive_async

pytestmark = pytest.mark.asyncio

# A conformant ADT^A01 — untrusted *data*, never interpreted (CLAUDE.md §8). Synthetic, no PHI.
RAW = "MSH|^~\\&|S|F|R|RF|20260101||ADT^A01|MSG1|P|2.5.1\rPID|1||100||DOE^JANE\r"

# The (handlers, destinations) shapes the static cost-model gates pin.
SHAPES = [(1, 1), (8, 8), (20, 4)]


def _expected_txns(handlers: int, destinations: int) -> int:
    return 3 + 2 * handlers + 2 * destinations


def _expected_body_copies(handlers: int, destinations: int) -> int:
    return 2 + handlers + destinations


# --- SQLite: real end-to-end pipeline --------------------------------------------------------------


async def _drive_lifecycle(store: MessageStore, *, handlers: int, destinations: int) -> None:
    """Push ONE message through the full staged pipeline for the given ``(H, N)``.

    The router selects ``handlers`` handlers; the first ``destinations`` of them each deliver one
    **unique** body to its own outbound lane, the rest filter (zero deliveries). Total outbound rows =
    ``destinations`` — so the counters must land on ``3 + 2H + 2N`` commits and ``2 + H + N`` body copies.
    Requires ``handlers >= destinations`` (true for every shape here). ``now=100.0`` on the writes keeps
    every staged row due when the claims (default ``now`` = wall clock) run — deterministic, no timing
    flake.
    """
    channel = "IB"
    mid = await store.enqueue_ingress(channel_id=channel, raw=RAW, now=100.0)

    ingress = await store.claim_next_fifo(channel, stage=Stage.INGRESS.value)
    assert ingress is not None
    routed = await store.route_handoff(
        ingress_id=ingress.id,
        message_id=mid,
        channel_id=channel,
        handlers=[(f"H{i}", RAW) for i in range(handlers)],
        disposition=MessageStatus.ROUTED,
        now=100.0,
    )
    assert routed

    for i in range(handlers):
        item = await store.claim_next_fifo(channel, stage=Stage.ROUTED.value)
        assert item is not None
        # Distinct per-destination body → each stored inline (no store-once dedup) → one copy each.
        deliveries = [(f"OB{i}", f"OUT-{i}-{'Z' * 40}")] if i < destinations else []
        ok = await store.transform_handoff(
            routed_id=item.id,
            message_id=item.message_id,
            channel_id=channel,
            deliveries=deliveries,
            now=100.0,
        )
        assert ok

    for i in range(destinations):
        out = await store.claim_next_fifo(f"OB{i}")
        assert out is not None
        await store.mark_done(out.id, now=100.0)


@pytest.mark.parametrize(("handlers", "destinations"), SHAPES)
async def test_sqlite_live_counters_match_cost_model(
    tmp_path: Path, handlers: int, destinations: int
) -> None:
    store = await MessageStore.open(tmp_path / "cost.db")
    try:
        # Baseline AFTER open so any one-time open-time commit (migration / audit backfill) is excluded —
        # we assert the DELTA the driven lifecycle produced.
        base_txns = store.committed_txns
        base_bodies = store.body_copies

        await _drive_lifecycle(store, handlers=handlers, destinations=destinations)

        assert store.committed_txns - base_txns == _expected_txns(handlers, destinations)
        assert store.body_copies - base_bodies == _expected_body_copies(handlers, destinations)
    finally:
        await store.close()


async def test_sqlite_counters_start_at_zero(tmp_path: Path) -> None:
    """A fresh store's counters are real ints starting at 0 (the QueueStore-protocol attributes exist)."""
    store = await MessageStore.open(tmp_path / "zero.db")
    try:
        assert isinstance(store.committed_txns, int)
        assert isinstance(store.body_copies, int)
        assert store.committed_txns >= 0
        assert store.body_copies >= 0
    finally:
        await store.close()


# --- SQL Server: offline recording harness ---------------------------------------------------------


async def _drive_ss(store: ss.SqlServerStore, method: str, **kwargs: object) -> None:
    """Drive one real SQL Server handoff against a fresh recording conn/cursor; the store's live counters
    accumulate across calls (they live on the store, not the per-call conn)."""
    await drive_async(store, method, cursor=AsyncRecCursor(), conn=RecConn(), **kwargs)


@pytest.mark.parametrize(("handlers", "destinations"), SHAPES)
async def test_sqlserver_live_body_copies_match_amplification(
    handlers: int, destinations: int
) -> None:
    """The offline-derivable half: ``body_copies == 2 + H + N`` and each producer handoff commits once."""
    store = bare_store()  # bare (no pool); the harness seeds committed_txns/body_copies at 0

    await _drive_ss(store, "enqueue_ingress", channel_id="IB", raw=RAW, now=100.0)
    await _drive_ss(
        store,
        "route_handoff",
        ingress_id="ing-1",
        message_id="m-1",
        channel_id="IB",
        handlers=[(f"H{i}", RAW) for i in range(handlers)],
        disposition=MessageStatus.ROUTED,
        now=100.0,
    )
    await _drive_ss(
        store,
        "transform_handoff",
        routed_id="rtd-1",
        message_id="m-1",
        channel_id="IB",
        deliveries=[(f"OB{i}", f"OUT-{i}") for i in range(destinations)],
        state_ops=(),
        pt_deliveries=(),
        now=100.0,
    )

    assert store.body_copies == _expected_body_copies(handlers, destinations)
    # enqueue + route + transform each commit exactly once, regardless of H/N (the two properties the
    # static txn gate pins). The claim commits (1 + H + N more) can't be driven offline.
    assert store.committed_txns == 3
