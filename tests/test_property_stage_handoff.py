# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Property tests: a staged-queue handoff re-run is a no-op (ADR 0001, the reliability invariant).

CLAUDE.md section 2 states the invariant: each stage handoff (ingress to routed, routed to outbound)
is one committed transaction, and a re-run of a handoff that already committed is an idempotent
no-op, because the consumed row is gone. That re-run is the defensive half of at-least-once: the
guarded DELETE that makes it a no-op. The other half, a crash BEFORE the commit rolling back and the
re-claimed row re-deriving the same output, is not exercised here, nor is the fused ingress to
outbound ``MessageStore.handoff``.

These tests generate the traffic instead of hand-picking it: several inbound connections, zero to
three handlers per message (so both ``ROUTED`` and ``UNROUTED``), zero to two deliveries per
handler, a handoff tried before its row was ever claimed, and every committed handoff re-run, in a
generated order, at a later ``now``, and with a different handler or delivery list and payload than
the first run. Each re-run must return ``False`` and leave every row of every table as it was.

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
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from messagefoundry.store.store import MessageStatus, MessageStore, Stage

# derandomize fixes the seed; tests/test_property_hl7_roundtrip.py says what that does not promise.
# database=None keeps examples out of the checkout.
_SETTINGS = settings(
    derandomize=True,
    database=None,
    max_examples=50,
    deadline=None,  # store I/O varies with disk contention; the example cap bounds the total
    suppress_health_check=[HealthCheck.too_slow],
)

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
        rows = await store._db.execute_fetchall(
            f'SELECT * FROM "{name}"'
        )  # names from sqlite_master
        snap[name] = sorted(repr(tuple(r)) for r in rows)
    return snap


async def _ingress_row_id(store: MessageStore, message_id: str) -> str:
    rows = list(
        await store._db.execute_fetchall(
            "SELECT id FROM queue WHERE message_id=? AND stage=?",
            (message_id, Stage.INGRESS.value),
        )
    )
    assert len(rows) == 1
    return str(rows[0][0])


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
    for mid, spec, raw in zip(mids, batch, raws, strict=True):
        kwargs = _route_kwargs(await _ingress_row_id(store, mid), mid, spec, raw)
        assert not await store.route_handoff(**kwargs, now=_NOW)
    assert await _snapshot(store) == before

    # Each committed handoff, paired with a re-run of it that is handed a different selection than
    # the first run made: a re-run must not re-derive anything, whatever it is handed.
    reruns: list[tuple[Callable[..., Awaitable[bool]], dict[str, Any]]] = []

    # Ingress -> routed. Claims are FIFO per channel, so they come back in generated order.
    for mid, spec, raw in zip(mids, batch, raws, strict=True):
        item = await store.claim_next_fifo(spec.channel, now=_NOW, stage=Stage.INGRESS.value)
        assert item is not None and item.message_id == mid
        kwargs = _route_kwargs(item.id, mid, spec, raw)
        assert await store.route_handoff(**kwargs, now=_NOW)
        # A payload the first run never wrote, so the re-run always differs from it.
        every_handler = [(h, "RERUN") for h in _HANDLERS]
        rerun = {**kwargs, "handlers": every_handler, "disposition": MessageStatus.ROUTED}
        reruns.append((store.route_handoff, rerun))

    # Routed -> outbound, one claim per routed row, FIFO per channel in handler order.
    for mid, spec in zip(mids, batch, strict=True):
        for dests in spec.deliveries:
            item = await store.claim_next_fifo(spec.channel, now=_NOW, stage=Stage.ROUTED.value)
            assert item is not None and item.message_id == mid
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
    rng.shuffle(reruns)
    for handoff, kwargs in reruns:
        assert not await handoff(**kwargs, now=_NOW + 1)
        assert await _snapshot(store) == settled
