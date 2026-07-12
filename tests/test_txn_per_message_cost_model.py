# Copyright (c) MessageFoundry contributors.
# SPDX-License-Identifier: Apache-2.0
"""A1 — pin the durable-write cost model: ``txn/msg = 3 + 2H + 2N``.

`H` = handlers the router SELECTS. `N` = outbound destinations. ADR 0051 states this model and the whole
capacity argument rests on it — the incumbent's own spec names *"the speed of the disk of the database
server's data drive"* as the leading performance driver, so **committed transactions per message, not
messages per second, is the currency the disk actually serves.** Until now the model was asserted, never
checked: the existing gates pin `commits/msg == 2.000` for the route+transform *pair* at `H = N = 1` only,
and never vary `H` or `N`.

The model is composed from five primitives, each measured here against the **real** `SqlServerStore`
methods driven over a recording connection:

| step                                    | commits | occurrences per ingress message |
|-----------------------------------------|---------|---------------------------------|
| `enqueue_ingress`                       | 1       | 1                               |
| claim the ingress row                   | 1       | 1                               |
| `route_handoff` (emits **all** `H` rows)| 1       | 1                               |
| claim a routed row                      | 1       | `H`                             |
| `transform_handoff` (emits `N` rows)    | 1       | `H`                             |
| claim an outbound row                   | 1       | `N`                             |
| `mark_done`                             | 1       | `N`                             |

Summing: `1 + 1 + 1 + H(1 + 1) + N(1 + 1) = 3 + 2H + 2N`.

Two properties carry the whole result, and both are tested directly:

1. **`route_handoff` commits ONCE regardless of `H`** — it emits all `H` routed rows in one transaction.
   If it committed per row the model would be `3 + 3H + 2N` and the ADT hub's cost would be far worse.
2. **`transform_handoff` commits ONCE regardless of `N`** — likewise for the `N` outbound rows.

And the corollary that decides a lever (execution-plan step A5(i)): a **batched ROUTED claim** collapses
the `H` claim commits to one, but the dispatcher still calls `transform_handoff` once per routed row, so
`2H -> H + 1` — **not** to ~1. `fifo_claim_batch` is therefore a claim-commit reduction, not a `2H`
collapse. That distinction is the difference between a ~38% cut and a fictional one.
"""

from __future__ import annotations

import pytest

from tests.adr0075_batch_harness import AsyncRecCursor, RecConn, bare_store, drive_async

pytestmark = pytest.mark.asyncio


async def _drive(method: str, **kwargs: object) -> tuple[int, int]:
    """(commits, statements) performed by one real store-method call."""
    conn, cur = RecConn(), AsyncRecCursor()
    await drive_async(bare_store(), method, cursor=cur, conn=conn, **kwargs)
    assert conn.rollbacks == 0, f"{method} rolled back"
    return conn.commits, len(cur.calls)


async def _commits(method: str, **kwargs: object) -> int:
    commits, _ = await _drive(method, **kwargs)
    return commits


# --- the two properties that make 3 + 2H + 2N come out ---------------------------------------------


@pytest.mark.parametrize("handlers", [1, 2, 5, 20])
async def test_route_handoff_commits_once_regardless_of_handler_count(handlers: int) -> None:
    """The `2H` term is `2`, not `3`: all `H` routed rows land in ONE transaction.

    `H = 20` is the reference estate's ADT hub — the single hottest, highest-fan-out feed measured.
    """
    import messagefoundry.store.sqlserver as ss

    commits, statements = await _drive(
        "route_handoff",
        ingress_id="ing-1",
        message_id="m-1",
        channel_id="IB",
        handlers=[(f"H{i}", f"p{i}") for i in range(handlers)],
        disposition=ss.MessageStatus.ROUTED,
        now=100.0,
    )
    assert commits == 1
    # Non-vacuity: the rows really are emitted — statements scale 1:1 with H while commits stay pinned
    # at 1. Without this, a short-circuiting method would satisfy `commits == 1` trivially.
    assert statements == 4 + handlers


@pytest.mark.parametrize("deliveries", [1, 2, 4, 8])
async def test_transform_handoff_commits_once_regardless_of_destination_count(
    deliveries: int,
) -> None:
    """Likewise the `2N` term: all `N` outbound rows land in ONE transaction."""
    commits, statements = await _drive(
        "transform_handoff",
        routed_id="rtd-1",
        message_id="m-1",
        channel_id="IB",
        deliveries=[(f"OB{i}", f"b{i}") for i in range(deliveries)],
        state_ops=(),
        pt_deliveries=(),
        now=100.0,
    )
    assert commits == 1
    assert statements == 5 + deliveries  # non-vacuity, as above


async def test_every_staged_queue_method_commits_exactly_once() -> None:
    """No method in the staged queue commits twice, and none commits zero times. A method that committed
    twice would double the term it sits in; one that committed zero times would mean the handoff is not
    durable and the at-least-once invariant is broken."""
    import messagefoundry.store.sqlserver as ss

    assert await _commits("enqueue_ingress", channel_id="IB", raw="MSH|...", now=100.0) == 1
    assert await _commits("mark_done", outbox_id="ob-1", now=100.0) == 1
    assert (
        await _commits(
            "route_handoff",
            ingress_id="ing-1",
            message_id="m-1",
            channel_id="IB",
            handlers=[("H1", "p1")],
            disposition=ss.MessageStatus.ROUTED,
            now=100.0,
        )
        == 1
    )


# --- the composed model ----------------------------------------------------------------------------


def txn_per_message(handlers: int, destinations: int, *, fifo_claim_batch: int = 1) -> int:
    """The cost model, composed from the per-method commit counts pinned above.

    `fifo_claim_batch > 1` batches the ROUTED *claim* into one commit for the whole contiguous due
    prefix, but the dispatcher then loops `for item in items:` and calls `transform_handoff` once per
    routed row — each its own transaction. So the `H` claim commits collapse to `1`; the `H` handoff
    commits do not. `2H -> H + 1`.
    """
    ingest = 1
    ingress_claim = 1
    route = 1
    routed_claims = 1 if fifo_claim_batch > 1 else handlers
    routed_handoffs = handlers
    outbound = 2 * destinations  # claim + mark_done, never batched
    return ingest + ingress_claim + route + routed_claims + routed_handoffs + outbound


@pytest.mark.parametrize(
    ("handlers", "destinations", "expected"),
    [
        (1, 1, 7),  # the simple feed. ADR 0051 quotes exactly this.
        (8, 8, 35),  # the bench topology (dests=8, one handler per destination)
        (20, 4, 51),  # the reference estate's ADT hub: routes to 20, delivers to ~4
    ],
)
async def test_txn_per_message_matches_adr_0051(
    handlers: int, destinations: int, expected: int
) -> None:
    assert txn_per_message(handlers, destinations) == expected
    assert txn_per_message(handlers, destinations) == 3 + 2 * handlers + 2 * destinations


async def test_the_hub_spends_most_of_its_transactions_on_handlers_that_filter() -> None:
    """Why `H` is the lever. The ADT hub's router SELECTS 20 handlers and delivers to ~4, and the `2H`
    term is charged BEFORE a handler runs — so it cannot be avoided by filtering inside the handler.

    A Router filter costs 0 transactions. A Handler filter costs 2. Same conceptual act.
    """
    selects, delivers = 20, 4
    total = txn_per_message(selects, delivers)
    # If the 16 self-filtering handlers were declined in the ROUTER stage instead (an `accepts=` seam),
    # they would never materialise a routed row.
    if_filtered_in_router = txn_per_message(delivers, delivers)
    wasted = total - if_filtered_in_router

    assert total == 51
    assert if_filtered_in_router == 19
    assert wasted == 32  # 63% of the hub's durable writes buy no delivered message
    assert total / if_filtered_in_router == pytest.approx(2.68, abs=0.01)


async def test_accepts_declines_before_routed_row() -> None:
    """ADR 0084 AC-1 — the `accepts=` seam turns `H` (handlers SELECTED) into `H_accepted` (handlers
    that actually take the message), recovering exactly the `wasted == 32` the gate above computes.

    The mechanism, pinned against the **real** store method: the seam filters the handler list inside
    `route_only`, so `route_handoff` is *called* with only the survivors — it never emits a routed row
    for a declining handler, and each row it doesn't emit is the `2` transactions (routed claim +
    `transform_handoff`) that handler would have cost. The engine-side proof that the 16 decliners
    never reach the store is `tests/test_accepts_seam.py::test_accepts_declines_before_a_routed_row_exists`;
    this closes the loop on the cost model.
    """
    import messagefoundry.store.sqlserver as ss

    selects, accepts, delivers = 20, 4, 4

    # The handoff emits rows for the SURVIVORS only — statements scale with H_accepted, not H_selected.
    commits, statements = await _drive(
        "route_handoff",
        ingress_id="ing-1",
        message_id="m-1",
        channel_id="IB",
        handlers=[(f"H{i}", f"p{i}") for i in range(accepts)],
        disposition=ss.MessageStatus.ROUTED,
        now=100.0,
    )
    assert commits == 1
    assert statements == 4 + accepts  # 4 rows emitted, NOT 20 (same shape as the H-scaling gate)

    # So the hub's cost is the `H_accepted` model, and the recovered writes are exactly `wasted`.
    before = txn_per_message(selects, delivers)
    after = txn_per_message(accepts, delivers)
    assert before == 51 and after == 19
    assert before - after == 32
    # Each declined handler is worth precisely 2 transactions — the asymmetry ADR 0084 removes.
    assert (before - after) == 2 * (selects - accepts)


async def test_fifo_claim_batch_collapses_2H_to_H_plus_1_not_to_1() -> None:
    """Execution-plan step A5(i), settled by reading the dispatcher rather than extrapolating.

    A batched claim is one commit for the whole due prefix. The handoff is NOT batched: the routed worker
    loops over the claimed items and calls `transform_handoff` per row. So the claim half of `2H`
    collapses and the handoff half is irreducible by this knob.

    `batch_handoff_statements` (ADR 0075, default ON) is a different thing entirely — it batches
    *statements within* one transaction and explicitly moves no commit boundary.
    """
    h, n = 20, 4
    unbatched = txn_per_message(h, n, fifo_claim_batch=1)
    batched = txn_per_message(h, n, fifo_claim_batch=64)

    assert unbatched == 3 + 2 * h + 2 * n == 51
    assert batched == 3 + (h + 1) + 2 * n == 32
    # A real ~37% cut — but emphatically NOT the collapse to ~1 that "batched claim" suggests.
    assert batched > 3 + 1 + 2 * n
    assert (unbatched - batched) / unbatched == pytest.approx(0.373, abs=0.005)


# --- the BENCH's self-report, welded to the model above (BACKLOG #209) ------------------------------


@pytest.mark.parametrize(
    ("dests", "handlers", "delivering", "expected_txn"),
    [
        (8, 8, 8, 35),  # the bench DEFAULT: H = D = dests. Byte-identical to the pre-#209 graph.
        (
            4,
            20,
            4,
            51,
        ),  # the reference ADT hub: 4 destination connections, routes to 20, delivers to 4.
        (1, 1, 1, 7),  # the simple feed. ADR 0051 quotes exactly this.
    ],
)
async def test_shardcert_shape_agrees_with_the_store_measured_model(
    monkeypatch: pytest.MonkeyPatch,
    dests: int,
    handlers: int,
    delivering: int,
    expected_txn: int,
) -> None:
    """The shardcert bench's SELF-REPORTED cost must equal the model this file pins against the REAL store.

    Before #209 the bench could not even express a shape where `H != D` (`graph.py` hardwired one handler
    per destination and the router selected them all), so its "txn/msg" was structurally `3 + 4·dests` —
    it could not report the hub. Welding the two here means a future edit that re-conflates `handlers`
    with `dests` breaks a test instead of quietly re-fabricating a number.
    """
    from harness.config.shardcert._shape import load_shape

    monkeypatch.setenv("MEFOR_SHARDCERT_DESTS", str(dests))
    monkeypatch.setenv("MEFOR_SHARDCERT_HANDLERS", str(handlers))
    monkeypatch.setenv("MEFOR_SHARDCERT_DELIVERING", str(delivering))
    shape = load_shape()

    assert shape.txn_per_message == expected_txn
    assert shape.txn_per_message == txn_per_message(handlers, delivering)
    assert shape.txn_per_message == 3 + 2 * handlers + 2 * delivering
    # Events are keyed on the FAN-OUT (D), never the destination-CONNECTION count. At the hub shape those
    # differ from `1 + dests` only when dests != D — pinned explicitly by the ladder's B10 guard.
    assert shape.events_per_message == 1 + delivering


async def test_the_bench_default_shape_cannot_see_the_accepts_benefit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """WHY #209 exists. At the bench DEFAULT (`H = D = dests = 8`) every selected handler delivers, so the
    `accepts=` seam (ADR 0084) has nothing to decline and the recovered `wasted` is exactly ZERO.

    The gate above (`test_the_hub_spends_most_of_its_transactions_on_handlers_that_filter`) computes
    `wasted == 32` for the hub — 63% of its durable writes. The bench, as shipped, would have measured a
    0% improvement from #213 and reported it as a real result. That is not a missing feature; it is an
    instrument that reads zero on the quantity it is pointed at.
    """
    from harness.config.shardcert._shape import load_shape

    monkeypatch.delenv("MEFOR_SHARDCERT_HANDLERS", raising=False)
    monkeypatch.delenv("MEFOR_SHARDCERT_DELIVERING", raising=False)
    monkeypatch.setenv("MEFOR_SHARDCERT_DESTS", "8")
    default = load_shape()

    assert (default.handlers, default.delivering) == (8, 8)  # both DEFAULT to dests
    wasted = default.txn_per_message - txn_per_message(default.delivering, default.delivering)
    assert wasted == 0  # nothing to decline ⇒ the seam is invisible to this shape
    assert default.txn_per_message == 35

    # With the shape split, the same bench CAN be pointed at the hub — and then it sees the whole 32.
    monkeypatch.setenv("MEFOR_SHARDCERT_DESTS", "4")
    monkeypatch.setenv("MEFOR_SHARDCERT_HANDLERS", "20")
    monkeypatch.setenv("MEFOR_SHARDCERT_DELIVERING", "4")
    hub = load_shape()
    hub_wasted = hub.txn_per_message - txn_per_message(hub.delivering, hub.delivering)
    assert hub.txn_per_message == 51
    assert hub_wasted == 32  # exactly the gate's number, now MEASURABLE by the bench


async def test_shape_invariants_fail_loud(monkeypatch: pytest.MonkeyPatch) -> None:
    """A clamped D or H would silently serve a different graph than the one reported — a fabricated
    result, which is this harness's B1-B10 defect class. Both invariants RAISE."""
    from harness.config.shardcert._shape import load_shape

    monkeypatch.setenv("MEFOR_SHARDCERT_DESTS", "4")
    monkeypatch.setenv("MEFOR_SHARDCERT_HANDLERS", "20")
    monkeypatch.setenv("MEFOR_SHARDCERT_DELIVERING", "8")  # D > dests
    with pytest.raises(ValueError, match="DELIVERING"):
        load_shape()

    monkeypatch.setenv("MEFOR_SHARDCERT_DELIVERING", "4")
    monkeypatch.setenv("MEFOR_SHARDCERT_HANDLERS", "2")  # H < D
    with pytest.raises(ValueError, match="HANDLERS"):
        load_shape()


async def test_txn_per_event_reweights_the_estate_mix() -> None:
    """Events are not fungible, which is why capacity must be sized in transactions, not messages.

    One ingress message with `N` destinations produces `1 + N` counted message events (the 45M/day
    currency). Dividing the durable-write cost by that gives the cost of an *event*.
    """

    def txn_per_event(h: int, n: int) -> float:
        return txn_per_message(h, n) / (1 + n)

    simple = txn_per_event(1, 1)  # 7 / 2
    bench = txn_per_event(8, 8)  # 35 / 9
    hub = txn_per_event(20, 4)  # 51 / 5

    assert simple == pytest.approx(3.50)
    assert bench == pytest.approx(3.89, abs=0.01)
    assert hub == pytest.approx(10.20)

    # An ADT hub event costs ~2.9x the durable work of a simple-feed event. Counting messages/s
    # over-weights cheap traffic; the bench topology is ~19% cheaper per event than the estate's mix.
    assert hub / simple == pytest.approx(2.91, abs=0.01)
