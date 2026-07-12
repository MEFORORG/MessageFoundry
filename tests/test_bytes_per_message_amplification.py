# Copyright (c) MessageFoundry contributors.
# SPDX-License-Identifier: Apache-2.0
"""A2 (part 1) — pin the BODY-COPY amplification factor per ingress message.

The incumbent's qualified spec budgets **~10.9 KB of storage per message** (500 GB/day over 45M). Nothing
in this project has ever measured what a message actually costs on disk. This module pins the part that is
*exactly derivable from the code* — how many copies of the body are written — and deliberately stops short
of publishing a bytes-vs-budget verdict, which needs a live measurement.

## What is pinned here (measured against the real store methods)

Per ingress message, with `H` handlers selected and `N` destinations delivered:

| write                              | body copies |
|------------------------------------|-------------|
| `enqueue_ingress` -> `messages.raw`| 1           |
| `enqueue_ingress` -> ingress `queue.payload` | 1 |
| `route_handoff` -> `H` routed rows | `H`         |
| `transform_handoff` -> outbound rows | `N` (SQL Server) |

Total: **`2 + H + N`**.

The 2026-07-10 audit estimated `(1 + H + N)` — it omitted the `messages.raw` copy, which is written in the
same transaction as the ingress queue row and is retained for the message's whole lifetime. The ADT hub
(`H=20, N=4`) therefore writes **26** body copies, not 25.

## The SQL Server / SQLite asymmetry, which matters because the rig and production run SQL Server

SQLite implements store-once-deliver-many: when >=2 of a handler's deliveries carry a byte-identical
transformed body, it stores the body **once** in `shared_body` and each outbound row carries a `body_ref`
with an empty inline `payload`. **SQL Server does not** — `sqlserver.py` creates the `shared_body` table
for schema parity and its own comment records that "on SQL Server `body_ref` stays NULL today". So a
fan-out of `N` identical bodies costs `1` copy on SQLite and `N` copies on SQL Server.

## What is NOT concluded here, and why

Converting copies to durable bytes requires three multipliers this module does not measure:

1. **Character width.** `queue.payload` / `messages.raw` are `NVARCHAR(MAX)` on SQL Server with no UTF-8
   collation, i.e. UTF-16: **2 bytes per ASCII character.** SQLite `TEXT` is UTF-8: 1.
2. **Cipher expansion.** With `MEFOR_STORE_ENCRYPTION_KEY` set, each copy becomes
   `mfenc:v1:<key_id>:<base64(nonce||ct||tag)>` — roughly `4/3 * raw + ~64` bytes. Default is identity.
3. **Everything the database writes that is not the body**: row and page overhead, indexes, and above all
   the **transaction log**, which durably records each of the `3 + 2H + 2N` transactions.

Multiplying (1) and (2) by the copy count gives a *lower bound* on body bytes, not durable bytes. A
confident `bytes/msg` published from that product would be exactly the kind of plausible-but-wrong number
this programme keeps producing. The real figure is a `db.size_bytes` delta over a live run at a known
message count — which the harness already samples as `EngineSample.db_size_bytes`.
"""

from __future__ import annotations

import pytest

from tests.adr0075_batch_harness import AsyncRecCursor, RecConn, bare_store, drive_async

pytestmark = pytest.mark.asyncio

BODY = "M" * 512


def _copies_of(cur: AsyncRecCursor, *bodies: str) -> int:
    """How many times a body string was handed to the driver as a bound parameter."""
    wanted = set(bodies)
    return sum(1 for _, params in cur.calls for p in params if isinstance(p, str) and p in wanted)


async def _drive(method: str, **kwargs: object) -> AsyncRecCursor:
    conn, cur = RecConn(), AsyncRecCursor()
    await drive_async(bare_store(), method, cursor=cur, conn=conn, **kwargs)
    return cur


async def test_enqueue_ingress_writes_TWO_copies_of_the_raw() -> None:
    """`messages.raw` (retained for the message's lifetime) AND the ingress `queue.payload`.

    The audit's `(1 + H + N)` estimate counted one. This is the missing copy.
    """
    cur = await _drive("enqueue_ingress", channel_id="IB", raw=BODY, now=100.0)
    assert _copies_of(cur, BODY) == 2


@pytest.mark.parametrize("handlers", [1, 4, 20])
async def test_route_handoff_writes_one_raw_copy_per_selected_handler(handlers: int) -> None:
    """Every routed row carries the full raw body — so `H` is a storage amplifier, not just a txn one.

    `H=20` is the reference estate's ADT hub.
    """
    import messagefoundry.store.sqlserver as ss

    cur = await _drive(
        "route_handoff",
        ingress_id="i",
        message_id="m",
        channel_id="IB",
        handlers=[(f"H{i}", BODY) for i in range(handlers)],
        disposition=ss.MessageStatus.ROUTED,
        now=100.0,
    )
    assert _copies_of(cur, BODY) == handlers


@pytest.mark.parametrize("deliveries", [1, 2, 4])
async def test_sqlserver_does_not_dedup_identical_fanout_bodies(deliveries: int) -> None:
    """The rig's and production's backend writes `N` inline copies of an identical fan-out body.

    SQLite stores it once (`shared_body` + `body_ref`). SQL Server keeps `body_ref` NULL — its own schema
    comment says so. This asymmetry means a storage figure measured on SQLite understates SQL Server.
    """
    cur = await _drive(
        "transform_handoff",
        routed_id="r",
        message_id="m",
        channel_id="IB",
        deliveries=[(f"OB{i}", BODY) for i in range(deliveries)],
        state_ops=(),
        pt_deliveries=(),
        now=100.0,
    )
    assert _copies_of(cur, BODY) == deliveries


def body_copies_per_message(handlers: int, destinations: int) -> int:
    """Body copies durably written per ingress message on SQL Server: `2 + H + N`."""
    return 2 + handlers + destinations


@pytest.mark.parametrize(
    ("handlers", "destinations", "expected"),
    [
        (1, 1, 4),  # simple feed
        (8, 8, 18),  # bench topology
        (20, 4, 26),  # the reference estate's ADT hub
    ],
)
async def test_body_copies_per_message(handlers: int, destinations: int, expected: int) -> None:
    assert body_copies_per_message(handlers, destinations) == expected


async def test_the_audit_estimate_was_short_by_exactly_one_copy() -> None:
    """Regression guard on the correction itself, so it cannot silently revert.

    `docs/benchmarks/THROUGHPUT-STATUS-2026-07-10.md` states bytes scale as `(1 + H + N)`. Measured, it is
    `(2 + H + N)`: `enqueue_ingress` writes `messages.raw` as well as the ingress queue row.
    """
    for h, n in ((1, 1), (8, 8), (20, 4)):
        assert body_copies_per_message(h, n) == (1 + h + n) + 1


async def test_a_high_fanout_hub_is_storage_bound_by_H_not_by_N() -> None:
    """Why `H` is the lever for storage as well as for transactions.

    The hub selects 20 handlers and delivers to ~4. Its routed rows — one full raw copy each — dominate.
    Declining the 16 self-filtering handlers in the router stage (an `accepts=` seam) would cut body copies
    from 26 to 10.
    """
    hub = body_copies_per_message(20, 4)
    if_filtered_in_router = body_copies_per_message(4, 4)

    assert hub == 26
    assert if_filtered_in_router == 10
    assert hub / if_filtered_in_router == pytest.approx(2.6)

    # The routed rows alone are 20 of the 26 copies: 77% of the body bytes this message writes.
    assert 20 / hub == pytest.approx(0.769, abs=0.001)
