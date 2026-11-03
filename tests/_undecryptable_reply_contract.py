# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Cross-backend contract: a captured reply whose body does not decrypt (BACKLOG #4995).

A reply owed to a loopback is a ``Stage.RESPONSE`` token whose ``payload`` references the
``response`` artifact. The re-ingress step reads that artifact's body before the handoff, and a
body that failed to decrypt raised ``CipherError`` out of the step. The worker's fault arm then
re-pended the token at the head of the loopback lane, where it failed again on every pass, so no
later reply on that lane would ever have re-ingressed.

Each case drives the real re-ingress step over a keyed store, with a bad reply at the head of the
lane and a good one behind it. The good one is the control: "the token went DEAD" is also what a
step that dead-letters everything looks like.

Extra-free on the ``_erased_reply_contract`` precedent, so the gated Postgres and SQL Server suites
run the same bodies. ``fetch`` and ``raw`` run one query with ``?`` placeholders outside the store.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Any

from messagefoundry.config.models import ContentType
from messagefoundry.config.settings import EgressSettings
from messagefoundry.config.wiring import Loopback, Registry, build_inbound_connection
from messagefoundry.pipeline.wiring_runner import RegistryRunner
from messagefoundry.store import MessageStatus, OutboxStatus, Stage
from messagefoundry.store.crypto import cell_aad, generate_key, make_cipher
from tests._erased_reply_contract import BODY, LOOP, RAW, REPLY, children, status_of
from tests._queue_tag_contract import RawFetch, RawSql
from tests._store_audit import no_operator_audit

#: Rewrites the bad origin's ``response.body`` cell so it no longer opens. Takes ``(fetch, raw,
#: bad_mid, good_mid)``.
Spoil = Callable[[RawFetch, RawSql, str, str], Awaitable[None]]


def runner(store: Any) -> RegistryRunner:
    reg = Registry()
    reg.add_inbound(
        build_inbound_connection(
            LOOP, Loopback(), router="route_loop", content_type=ContentType.HL7V2
        )
    )
    reg.add_router("route_loop", lambda msg: [])
    return RegistryRunner(
        reg, store, poll_interval=0.02, egress=EgressSettings(deny_by_default=False)
    )


async def captured(store: Any, *, control: str, now: float) -> str:
    """A delivered message whose captured reply owes a re-ingress to the loopback. Returns its id."""
    mid = await store.enqueue_message(
        channel_id="IB_REAL", raw=RAW, deliveries=[("OB_X", BODY)], control_id=control, now=now
    )
    [item] = await store.claim_ready(destination_name="OB_X", now=now)
    await store.complete_with_response(
        item.id, body=REPLY, outcome="accepted", reingress_to=LOOP, now=now
    )
    return str(mid)


async def token_of(fetch: RawFetch, message_id: str) -> dict[str, Any]:
    rows = await fetch(
        "SELECT id, status, payload FROM queue WHERE message_id=? AND stage=?",
        (message_id, Stage.RESPONSE.value),
    )
    assert len(rows) == 1, rows
    return rows[0]


async def spoil_with_a_wrong_cell(fetch: RawFetch, raw: RawSql, bad: str, good: str) -> None:
    """The good reply's sealed body, planted in the bad reply's cell: its tag fails under a key
    this store holds, the shape a tampered or misplaced cell takes."""
    [row] = await fetch("SELECT body FROM response WHERE message_id=?", (good,))
    await raw("UPDATE response SET body=? WHERE message_id=?", (row["body"], bad))


async def spoil_with_a_foreign_key(_fetch: RawFetch, raw: RawSql, bad: str, _good: str) -> None:
    """The right cell, sealed under a key this store was never given: the shape a rotated key
    that was not supplied at start takes."""
    foreign = make_cipher(generate_key(), write_v2=True)
    sealed = foreign.encrypt(REPLY, aad=cell_aad("response", "body", bad, "OB_X", 1))
    await raw("UPDATE response SET body=? WHERE message_id=?", (sealed, bad))


async def spoil_with_a_corrupt_marker(_fetch: RawFetch, raw: RawSql, bad: str, _good: str) -> None:
    """A marked value in a format no reader knows: the cipher's plain ``CipherError``, not the
    unauthenticated subclass the other two raise."""
    await raw("UPDATE response SET body=? WHERE message_id=?", ("mfenc:v9:not-a-cell", bad))


async def assert_lane_moves_past_an_undecryptable_reply(
    store: Any, fetch: RawFetch, raw: RawSql, spoil: Spoil
) -> None:
    bad = await captured(store, control="UR-BAD", now=1.0)
    good = await captured(store, control="UR-GOOD", now=2.0)
    await spoil(fetch, raw, bad, good)
    before = await token_of(fetch, bad)

    step = runner(store)
    for _ in range(2):
        item = await store.claim_next_fifo(LOOP, now=3.0, stage=Stage.RESPONSE.value)
        assert item is not None
        await step._process_response_item(LOOP, item)  # the bad head must not raise
    assert await store.claim_next_fifo(LOOP, now=3.0, stage=Stage.RESPONSE.value) is None

    # The bad token: dead with its reference kept, and ERROR on its origin. No child.
    after = await token_of(fetch, bad)
    assert after["status"] == OutboxStatus.DEAD.value
    assert after["payload"] == before["payload"] and after["payload"] != ""
    assert await status_of(store, bad) == MessageStatus.ERROR.value
    events = await store.events_for(bad)
    assert [e for e in events if e["event"] == "dead" and "undecryptable" in str(e["detail"])]

    # The control behind it re-ingressed: the lane moved.
    assert await status_of(store, good) == MessageStatus.PROCESSED.value
    [child] = await children(fetch)
    message = await store.get_message(child["id"])
    assert message is not None and message["raw"] == REPLY

    # The kept reference leaves the token replayable once the cause is fixed. Here it is not, so
    # the replayed token dead-letters again rather than holding the lane.
    assert await store.replay(bad, now=4.0, audit=no_operator_audit) == 1
    item = await store.claim_next_fifo(LOOP, now=5.0, stage=Stage.RESPONSE.value)
    assert item is not None
    await step._process_response_item(LOOP, item)
    assert (await token_of(fetch, bad))["status"] == OutboxStatus.DEAD.value
    assert len(await children(fetch)) == 1


SPOILS: list[Spoil] = [
    spoil_with_a_wrong_cell,
    spoil_with_a_foreign_key,
    spoil_with_a_corrupt_marker,
]
