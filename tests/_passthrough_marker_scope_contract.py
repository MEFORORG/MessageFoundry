# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Cross-backend contract: a pass-through marker is scoped to its PARENT's channel (BACKLOG #5614).

A Send into a pass-through inbound stamps an already-terminal outbound marker row on the parent.
Before #5614 every backend wrote the pass-through inbound's name into that row's ``channel_id``, so a
dead marker (a depth-cap breach) was listed and counted in the dead-letter view under the
pass-through channel's RBAC scope. A user scoped to that channel would have seen the parent's
metadata and summary, and the parent channel's user would not have seen its own dead letter. Every
other outbound row the handoff writes carries the parent's inbound, and so does the marker now.

Seeded through the public queue API only, so the gated Postgres and SQL Server suites run the same
body. Each case needs a clean store. Synthetic bodies only; no real PHI.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from messagefoundry.store import MessageStatus, Stage

PARENT = "IB_PT_PARENT"
PT = "PT_SCOPE_NEXT"
RAW = "MSH|^~\\&|SYNTH|F|R|RF|20260101||ADT^A01|PTS1|P|2.5.1\rPID|1||SYNTH-200||DOE^JANE\r"


async def _seed_routed(store: Any, *, metadata: str | None, now: float) -> tuple[str, str]:
    """A message on ``PARENT`` holding one claimed routed row, ready for a transform handoff."""
    mid = await store.enqueue_ingress(channel_id=PARENT, raw=RAW, metadata=metadata, now=now)
    ingress = await store.claim_next_fifo(PARENT, now=now + 1, stage=Stage.INGRESS.value)
    assert ingress is not None
    await store.route_handoff(
        ingress_id=ingress.id,
        message_id=mid,
        channel_id=PARENT,
        handlers=[("h1", RAW)],
        disposition=MessageStatus.ROUTED,
        now=now + 2,
    )
    routed = await store.claim_next_fifo(PARENT, now=now + 3, stage=Stage.ROUTED.value)
    assert routed is not None
    return mid, routed.id


async def assert_a_dead_marker_is_scoped_to_the_parent_channel(store: Any) -> None:
    """A depth-capped Send dead-letters the marker. It is listed and counted under the parent's
    channel, and a caller scoped to the pass-through channel sees none of it."""
    cap = 2
    parent, routed = await _seed_routed(
        store,
        metadata=json.dumps({"correlation_depth": cap, "correlation_root_id": "root-pts"}),
        now=100.0,
    )
    assert await store.transform_handoff(
        routed_id=routed,
        message_id=parent,
        channel_id=PARENT,
        deliveries=[],
        pt_deliveries=[(PT, RAW)],
        correlation_depth_cap=cap,
        now=110.0,
    )
    pmsg = await store.get_message(parent)
    assert pmsg is not None and pmsg["status"] == MessageStatus.ERROR.value
    dead = await store.list_dead(allowed_channels=[PARENT])
    assert [(d["message_id"], d["channel_id"], d["destination_name"]) for d in dead] == [
        (parent, PARENT, PT)
    ]
    assert await store.count_dead(allowed_channels=[PARENT]) == 1
    assert await store.count_dead(channel_id=PARENT, allowed_channels=None) == 1
    # The pass-through channel's scope holds nothing of the parent's.
    assert await store.list_dead(allowed_channels=[PT]) == []
    assert await store.count_dead(allowed_channels=[PT]) == 0
    assert await store.count_dead(channel_id=PT, allowed_channels=None) == 0


async def assert_a_done_marker_still_finalizes_the_parent(store: Any) -> None:
    """The control: a produced child marks the parent delivered, so it finalizes PROCESSED, and the
    child is still recorded on the pass-through channel."""
    parent, routed = await _seed_routed(store, metadata=None, now=200.0)
    assert await store.transform_handoff(
        routed_id=routed,
        message_id=parent,
        channel_id=PARENT,
        deliveries=[],
        pt_deliveries=[(PT, RAW)],
        now=210.0,
    )
    pmsg = await store.get_message(parent)
    assert pmsg is not None and pmsg["status"] == MessageStatus.PROCESSED.value
    children = await store.list_messages(channel_id=PT, allowed_channels=None)
    assert len(children) == 1 and children[0]["status"] == MessageStatus.RECEIVED.value
    assert await store.count_dead(allowed_channels=None) == 0


#: Every case, for ``pytest.mark.parametrize``. Each takes ``(store,)``.
CASES = [
    pytest.param(assert_a_dead_marker_is_scoped_to_the_parent_channel, id="dead-marker-scope"),
    pytest.param(assert_a_done_marker_still_finalizes_the_parent, id="done-marker"),
]
