# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Cross-backend store contract: a replayed routed row whose Handler now sends nothing SETTLES.

Vault BACKLOG #2723. A single-handler message's transform raised, so its routed row is dead and the
message is ``ERROR``. The operator fixes the Handler, which now filters the message (or declines every
Send as not-deployed), and replays it. ``replay`` used to write ``RECEIVED`` whenever a pending routed
row resulted, while every finalizer collapses a no-rows message to ``FILTERED`` / ``NOT_DEPLOYED`` only
from ``ROUTED``. So the message stayed ``RECEIVED`` with no queue rows, and a second replay had nothing
to re-queue. Per ADR 0001 a routed row exists only because the router already ran, so the replay
writes ``ROUTED`` and only a re-pended INGRESS row earns ``RECEIVED``.

Extra-free on the ``_finalize_race_contract`` precedent: nothing optional is imported, so the gated
Postgres / SQL Server suites can run the same body on legs that install only their own extra.
"""

from __future__ import annotations

from typing import Any

import pytest

from messagefoundry.store import MessageStatus, Stage

RAW = "MSH|^~\\&|S|F|R|RF|20260101||ADT^A01|MSG1|P|2.5.1\rPID|1||100||DOE^JANE\r"

#: ``(declined, expected)`` cases for ``pytest.mark.parametrize``: an intentional filter, then every
#: Send declined to a present-but-not-deployed target (#233).
CASES = [
    pytest.param((), MessageStatus.FILTERED, id="filtered"),
    pytest.param(("OB_OFF",), MessageStatus.NOT_DEPLOYED, id="not_deployed"),
]


async def _status(store: Any, mid: str) -> str:
    msg = await store.get_message(mid)
    assert msg is not None
    return str(msg["status"])


async def assert_replayed_routed_row_settles(
    store: Any, declined: tuple[str, ...], expected: MessageStatus
) -> None:
    """Dead routed row -> replay (``ROUTED``) -> transform with no Send -> ``expected``, no rows."""
    mid = await store.enqueue_ingress(channel_id="IB", raw=RAW, now=100.0)
    ingress = await store.claim_next_fifo("IB", now=110.0, stage=Stage.INGRESS.value)
    assert ingress is not None
    await store.route_handoff(
        ingress_id=ingress.id,
        message_id=mid,
        channel_id="IB",
        handlers=[("H1", RAW)],
        disposition=MessageStatus.ROUTED,
        now=120.0,
    )
    routed = await store.claim_next_fifo("IB", now=130.0, stage=Stage.ROUTED.value)
    assert routed is not None
    await store.dead_letter_now(routed.id, "transform error", now=140.0)
    assert await _status(store, mid) == MessageStatus.ERROR.value

    assert await store.replay(mid, now=150.0) == 1
    assert await _status(store, mid) == MessageStatus.ROUTED.value
    routed = await store.claim_next_fifo("IB", now=160.0, stage=Stage.ROUTED.value)
    assert routed is not None
    await store.transform_handoff(
        routed_id=routed.id,
        message_id=mid,
        channel_id="IB",
        deliveries=[],
        declined=declined,
        now=170.0,
    )
    assert await _status(store, mid) == expected.value
    assert await store.outbox_for(mid) == []


async def assert_replayed_ingress_row_is_received(store: Any) -> None:
    """The other branch of the same status pick: a re-pended INGRESS row still earns ``RECEIVED``,
    because the router has not run for it. Without this arm a status query that never matched would
    write ``ROUTED`` for every replay and the routed-row arm above would still pass."""
    mid = await store.enqueue_ingress(channel_id="IB", raw=RAW, now=100.0)
    ingress = await store.claim_next_fifo("IB", now=110.0, stage=Stage.INGRESS.value)
    assert ingress is not None
    await store.dead_letter_now(ingress.id, "router error", now=120.0)
    assert await _status(store, mid) == MessageStatus.ERROR.value

    assert await store.replay(mid, now=130.0) == 1
    assert await _status(store, mid) == MessageStatus.RECEIVED.value
    again = await store.claim_next_fifo("IB", now=140.0, stage=Stage.INGRESS.value)
    assert again is not None and again.message_id == mid
