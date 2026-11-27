# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Property tests: a staged-queue handoff re-run is a no-op (ADR 0001, the reliability invariant).

The invariant is CLAUDE.md section 2's, and :meth:`MessageStore.route_handoff`,
:meth:`MessageStore.transform_handoff` and the fused ingress to outbound :meth:`MessageStore.handoff`
state their own halves. This file exercises the guarded DELETE that makes a re-run or a premature
call a no-op. Not exercised, at least: a crash before the commit rolling back and the re-claimed row
re-deriving the same output; and a transform re-run carrying state, metadata or pass-through
operations.

These tests generate the traffic instead of hand-picking it: several inbound connections, zero to
three handlers per message (so both ``ROUTED`` and ``UNROUTED``), zero to two deliveries per
handler, each handoff tried before its row was claimed and on a claimed row of the wrong stage,
and every committed handoff re-run, in a generated order, at a later ``now``, and with a different
handler or delivery list and payload than the first run. Each re-run must return ``False`` and leave
every row of every table as it was.

SQLite is the reference backend. Every message is a fixed synthetic body, never PHI.
"""

from __future__ import annotations

import dataclasses
import itertools
import random
from collections.abc import AsyncIterator, Awaitable, Callable
from dataclasses import dataclass
from typing import Any

import pytest
from hypothesis import given
from hypothesis import strategies as st

from messagefoundry.store.store import MessageStatus, MessageStore, Stage
from tests._hypothesis_settings import property_settings

_SETTINGS = property_settings(max_examples=30)

_RAW = "MSH|^~\\&|SND|FAC|RCV|RFAC|20260101||ADT^A01|{n}|P|2.5.1\rPID|1||{n}||SYNTH^TEST\r"
_CHANNELS = ("IB_A", "IB_B")
# Opening a store costs most of a second, so every example shares one and takes its own channel
# names from this counter. A re-run must then leave the whole store unchanged, earlier examples'
# rows included, which is a stronger check than a store per example.
_EXAMPLE = itertools.count()
_HANDLERS = ("h1", "h2", "h3")
_DESTINATIONS = ("OB_X", "OB_Y")
_NOW = 1000.0


@dataclass(frozen=True)
class Spec:
    """One generated message: where it arrives and what the router and transforms make of it."""

    channel: str
    handlers: tuple[str, ...]  # the router's selection; empty means UNROUTED
    deliveries: tuple[tuple[str, ...], ...]  # per handler, the destinations its transform sends to


@st.composite
def specs(draw: st.DrawFn) -> Spec:
    handlers = tuple(draw(st.lists(st.sampled_from(_HANDLERS), unique=True, max_size=3)))
    deliveries = tuple(
        tuple(draw(st.lists(st.sampled_from(_DESTINATIONS), unique=True, max_size=2)))
        for _ in handlers
    )
    return Spec(channel=draw(st.sampled_from(_CHANNELS)), handlers=handlers, deliveries=deliveries)


async def _snapshot(store: MessageStore) -> dict[str, list[str]]:
    """Every row of every table in the store, each column included, keyed by table name.

    Rows are compared by ``repr`` in sorted order, so a table without a rowid needs no special
    case. Reading every column is what lets the re-runs at a later ``now`` catch a write that only
    moves a timestamp or an error text.
    """
    tables = await store._db.execute_fetchall(
        "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
    )
    snap: dict[str, list[str]] = {}
    for (name,) in tables:
        quoted = '"' + str(name).replace('"', '""') + '"'  # SQLite identifier quoting
        rows = await store._db.execute_fetchall(f"SELECT * FROM {quoted}")
        snap[name] = sorted(repr(tuple(r)) for r in rows)
    return snap


async def _row_ids(store: MessageStore, message_id: str, stage: Stage) -> list[str]:
    rows = await store._db.execute_fetchall(
        "SELECT id FROM queue WHERE message_id=? AND stage=? ORDER BY rowid",
        (message_id, stage.value),
    )
    return [str(r[0]) for r in rows]


@pytest.fixture(scope="module")
async def store(tmp_path_factory: pytest.TempPathFactory) -> AsyncIterator[MessageStore]:
    s = await MessageStore.open(tmp_path_factory.mktemp("handoff") / "prop.db")
    yield s
    await s.close()


def _route_kwargs(ingress_id: str, mid: str, spec: Spec, raw: str) -> dict[str, Any]:
    return {
        "ingress_id": ingress_id,
        "message_id": mid,
        "channel_id": spec.channel,
        "handlers": [(h, raw) for h in spec.handlers],
        "disposition": MessageStatus.ROUTED if spec.handlers else MessageStatus.UNROUTED,
    }


@_SETTINGS
@given(
    batch=st.lists(specs(), min_size=1, max_size=6),
    rng=st.randoms(use_true_random=False),
)
async def test_handoff_rerun_is_a_no_op(
    store: MessageStore, batch: list[Spec], rng: random.Random
) -> None:
    suffix = f"_{next(_EXAMPLE)}"
    batch = [dataclasses.replace(s, channel=s.channel + suffix) for s in batch]
    raws = [_RAW.format(n=f"{suffix}{i}") for i in range(len(batch))]
    mids = [
        await store.enqueue_ingress(channel_id=s.channel, raw=raw, now=_NOW)
        for s, raw in zip(batch, raws, strict=True)
    ]

    # A handoff for a row nobody claimed matches nothing: the INFLIGHT guard makes it a no-op.
    before = await _snapshot(store)
    # The instrument can see the tables the handoffs write, or every equality below is vacuous.
    assert {"queue", "messages", "message_events"} <= before.keys()
    for mid, spec, raw in zip(mids, batch, raws, strict=True):
        (ingress_id,) = await _row_ids(store, mid, Stage.INGRESS)
        kwargs = _route_kwargs(ingress_id, mid, spec, raw)
        assert not await store.route_handoff(**kwargs, now=_NOW)
    assert await _snapshot(store) == before

    # Each committed handoff, paired with a re-run of it that is handed a different selection than
    # the first run made: a re-run must not re-derive anything, whatever it is handed.
    reruns: list[tuple[Callable[..., Awaitable[bool]], dict[str, Any]]] = []

    # Ingress -> routed. Claims are FIFO per channel, so they come back in generated order.
    for mid, spec, raw in zip(mids, batch, raws, strict=True):
        item = await store.claim_next_fifo(spec.channel, now=_NOW, stage=Stage.INGRESS.value)
        assert item is not None and item.message_id == mid
        # The stage guard: a claimed ingress row is not a routed row, so transforming it is a no-op.
        claimed = await _snapshot(store)
        assert not await store.transform_handoff(
            routed_id=item.id, message_id=mid, channel_id=spec.channel, deliveries=[], now=_NOW
        )
        assert await _snapshot(store) == claimed
        kwargs = _route_kwargs(item.id, mid, spec, raw)
        assert await store.route_handoff(**kwargs, now=_NOW)
        # The positive control for every snapshot equality: a committed handoff, which consumes the
        # ingress row and logs an event, must show in the snapshot.
        assert await _snapshot(store) != claimed, "the snapshot did not see a committed handoff"
        # A payload the first run never wrote, so the re-run always differs from it.
        every_handler = [(h, "RERUN") for h in _HANDLERS]
        rerun = {**kwargs, "handlers": every_handler, "disposition": MessageStatus.ROUTED}
        reruns.append((store.route_handoff, rerun))

    # The same INFLIGHT guard on the routed stage: no routed row is claimed yet.
    routed = await _snapshot(store)
    for mid, spec in zip(mids, batch, strict=True):
        # The first run wrote one routed row per selected handler and consumed the ingress row.
        assert await _row_ids(store, mid, Stage.INGRESS) == []
        assert len(await _row_ids(store, mid, Stage.ROUTED)) == len(spec.handlers)
        for routed_id in await _row_ids(store, mid, Stage.ROUTED):
            assert not await store.transform_handoff(
                routed_id=routed_id,
                message_id=mid,
                channel_id=spec.channel,
                deliveries=[],
                now=_NOW,
            )
    assert await _snapshot(store) == routed

    # Routed -> outbound, one claim per routed row, FIFO per channel in handler order: route_handoff
    # inserts the routed rows in handler-list order and the routed lane claims by rowid.
    for mid, spec, raw in zip(mids, batch, raws, strict=True):
        for handler, dests in zip(spec.handlers, spec.deliveries, strict=True):
            item = await store.claim_next_fifo(spec.channel, now=_NOW, stage=Stage.ROUTED.value)
            assert item is not None and item.message_id == mid
            assert item.handler_name == handler
            # The stage guard: a claimed routed row is not an ingress row, so routing it, or handing
            # it straight to outbound with the fused handoff, is a no-op.
            claimed = await _snapshot(store)
            assert not await store.route_handoff(**_route_kwargs(item.id, mid, spec, raw), now=_NOW)
            assert not await store.handoff(
                ingress_id=item.id,
                message_id=mid,
                channel_id=spec.channel,
                deliveries=[(d, "FUSED") for d in dests],
                disposition=MessageStatus.ROUTED,
                now=_NOW,
            )
            assert await _snapshot(store) == claimed
            kwargs = {
                "routed_id": item.id,
                "message_id": mid,
                "channel_id": spec.channel,
                "deliveries": [(d, f"OUT-{mid}-{d}") for d in dests],
            }
            assert await store.transform_handoff(**kwargs, now=_NOW)
            every_dest = [(d, "RERUN") for d in _DESTINATIONS]
            reruns.append((store.transform_handoff, {**kwargs, "deliveries": every_dest}))

    # Every re-run, in a generated order, leaves the whole store as the first runs left it.
    settled = await _snapshot(store)
    for mid, spec in zip(mids, batch, strict=True):
        # The first runs consumed every routed row and wrote one outbound row per delivery.
        assert await _row_ids(store, mid, Stage.ROUTED) == []
        outbound = len(await _row_ids(store, mid, Stage.OUTBOUND))
        assert outbound == sum(len(dests) for dests in spec.deliveries)
    rng.shuffle(reruns)
    for handoff, kwargs in reruns:
        assert not await handoff(**kwargs, now=_NOW + 1)
        assert await _snapshot(store) == settled


@_SETTINGS
@given(spec=specs())
async def test_fused_handoff_rerun_is_a_no_op(store: MessageStore, spec: Spec) -> None:
    """The fused ingress to outbound :meth:`MessageStore.handoff` keeps the same guard."""
    suffix = f"_{next(_EXAMPLE)}"
    channel = spec.channel + suffix
    mid = await store.enqueue_ingress(channel_id=channel, raw=_RAW.format(n=suffix), now=_NOW)
    deliveries = [(d, f"OUT-{mid}-{d}") for dests in spec.deliveries for d in dests]
    kwargs: dict[str, Any] = {
        "message_id": mid,
        "channel_id": channel,
        "deliveries": deliveries,
        "disposition": MessageStatus.ROUTED if deliveries else MessageStatus.FILTERED,
    }

    # Before the claim, the INFLIGHT guard makes the call a no-op.
    (ingress_id,) = await _row_ids(store, mid, Stage.INGRESS)
    before = await _snapshot(store)
    assert not await store.handoff(ingress_id=ingress_id, **kwargs, now=_NOW)
    assert await _snapshot(store) == before

    item = await store.claim_next_fifo(channel, now=_NOW, stage=Stage.INGRESS.value)
    assert item is not None and item.id == ingress_id
    assert await store.handoff(ingress_id=ingress_id, **kwargs, now=_NOW)
    assert await _row_ids(store, mid, Stage.INGRESS) == []
    assert len(await _row_ids(store, mid, Stage.OUTBOUND)) == len(deliveries)

    settled = await _snapshot(store)
    rerun = {**kwargs, "deliveries": [(d, "RERUN") for d in _DESTINATIONS]}
    assert not await store.handoff(ingress_id=ingress_id, **rerun, now=_NOW + 1)
    assert await _snapshot(store) == settled
