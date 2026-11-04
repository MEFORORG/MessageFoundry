# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Cross-backend contract: a refused loopback re-ingress is bounded by the refused-body allowance
(vault BACKLOG #4796).

A captured reply that fails its peek or size check on re-ingress is recorded as an ``ERROR`` child of
its origin. Before #4796 every backend's ``ingress_handoff`` stored that child's body whole, outside
the per-inbound allowance a listener's refusal is charged to, so a partner answering with refused
replies could grow the store unmetered on a first deployment. These cases drive the real re-ingress
step (``RegistryRunner._process_response_item``) over each backend and read the child it records.

Extra-free on the ``_erased_reply_contract`` precedent, so the gated Postgres and SQL Server suites run
the same body. Each case scopes its reads to the messages it made, so it needs no clean store.

Synthetic bodies only; no real PHI.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from messagefoundry.config.models import ContentType
from messagefoundry.config.settings import EgressSettings
from messagefoundry.config.wiring import Loopback, Registry, build_inbound_connection
from messagefoundry.pipeline.refused_body import (
    METADATA_KEY,
    RefusedBodyAllowance,
    RefusedBodyPolicy,
    head_only_resubmit_refusal,
)
from messagefoundry.pipeline.wiring_runner import RegistryRunner
from messagefoundry.store import MessageStatus, Stage
from messagefoundry.store.crypto import refused_body_digest
from messagefoundry.store.store import REINGRESS_PEEK_FAILED, MessageStore

LOOP = "IB_LOOP_RB"
DEST = "OB_RB"
RAW = "MSH|^~\\&|SYNTH|F|R|RF|20260101||ADT^A01|RB1|P|2.5.1\rPID|1||SYNTH-100||DOE^JANE\r"
REPLY = "MSH|^~\\&|PARTNER|||||20260101||ACK^A01|RSP1|P|2.5.1\rMSA|AA|RB1\r"
HEAD = 256
BODY_BYTES = 1000


class _FrozenClock:
    """A clock that never moves, so the allowance never refills during a flood."""

    def __call__(self) -> float:
        return 1000.0


def _allowance(allowance_bytes: int) -> RefusedBodyAllowance:
    return RefusedBodyAllowance(
        RefusedBodyPolicy(allowance_bytes=allowance_bytes, head_bytes=HEAD), clock=_FrozenClock()
    )


def _runner(store: Any, allowance: RefusedBodyAllowance) -> RegistryRunner:
    reg = Registry()
    reg.add_inbound(
        build_inbound_connection(
            LOOP, Loopback(), router="route_loop", content_type=ContentType.HL7V2
        )
    )
    reg.add_router("route_loop", lambda msg: [])
    return RegistryRunner(
        reg, store, egress=EgressSettings(deny_by_default=False), refused_body_allowance=allowance
    )


def _refused_reply(i: int) -> str:
    """A reply of ``BODY_BYTES`` ASCII bytes that fails the HL7 peek: it has no MSH."""
    lead = f"NOT-HL7 {i:04d} "
    return lead + "A" * (BODY_BYTES - len(lead))


async def _reingress(store: Any, runner: RegistryRunner, body: str, now: float) -> dict[str, Any]:
    """Capture ``body`` as a reply owed to the loopback, run the re-ingress step once, and return the
    child it recorded, with its decoded metadata under ``"meta"``."""
    origin = await store.enqueue_message(
        channel_id="IB_REAL", raw=RAW, deliveries=[(DEST, "q")], now=now
    )
    [item] = await store.claim_ready(destination_name=DEST, now=now)
    await store.complete_with_response(
        item.id, body=body, outcome="accepted", reingress_to=LOOP, now=now
    )
    work = await store.claim_next_fifo(LOOP, now=now, stage=Stage.RESPONSE.value)
    assert work is not None and work.message_id == origin
    await runner._process_response_item(LOOP, work)
    child_id = MessageStore._reingress_message_id(origin, DEST, 1, body)
    child = await store.get_message(child_id)
    assert child is not None  # count-and-log: the child is recorded whichever way it went
    meta = await store.message_metadata_json(child_id)
    child = dict(child)
    child["meta"] = json.loads(meta) if meta else {}
    # The token was consumed, so the origin still finalizes.
    origin_row = await store.get_message(origin)
    assert origin_row is not None and origin_row["status"] == MessageStatus.PROCESSED.value
    return child


async def assert_a_refused_reply_flood_stores_heads_past_the_allowance(store: Any) -> None:
    """Six refused replies against room for two and a half: two stored whole, then four heads. The
    bytes stored stay under ``allowance + count * head``, and every refusal is still one ERROR row."""
    allowance_bytes = 2 * BODY_BYTES + BODY_BYTES // 2
    runner = _runner(store, _allowance(allowance_bytes))
    bodies = [_refused_reply(i) for i in range(6)]
    children = [
        await _reingress(store, runner, body, now=100.0 + i) for i, body in enumerate(bodies)
    ]
    note = f"[refused-body allowance spent: stored only the head of a {BODY_BYTES:,}-byte body] "
    stored = 0
    for i, (body, child) in enumerate(zip(bodies, children, strict=True)):
        assert child["status"] == MessageStatus.ERROR.value
        record = child["meta"][METADATA_KEY]
        assert record["bytes"] == BODY_BYTES
        assert record["body_hmac"] == refused_body_digest(store.cipher(), body.encode())
        # The lineage the re-ingress child always carried is still there beside the record.
        assert child["meta"]["reingress_of_seq"] == 1
        if i < 2:
            assert child["raw"] == body
            assert record["stored"] == "whole" and "head_bytes" not in record
            assert child["error"] == REINGRESS_PEEK_FAILED
        else:
            assert child["raw"] == body[:HEAD]
            assert record["stored"] == "head" and record["head_bytes"] == HEAD
            assert child["error"] == note + REINGRESS_PEEK_FAILED
            # Edit-and-resubmit refuses the cut child and points at the whole reply's origin.
            refusal = head_only_resubmit_refusal(child["id"], json.dumps(child["meta"]))
            origin = child["meta"]["correlation_id"]
            assert refusal is not None and f"origin message {origin} " in refusal
        stored += len(child["raw"].encode())
    assert stored <= allowance_bytes + len(bodies) * HEAD
    # No refused reply became ingress work on the loopback.
    assert await store.claim_next_fifo(LOOP, now=200.0, stage=Stage.INGRESS.value) is None


async def assert_a_refused_reply_inside_the_allowance_is_stored_whole(store: Any) -> None:
    """The control: with the allowance unspent the refused reply is stored whole, with the same
    wording as before #4796, and its length and digest are still recorded."""
    runner = _runner(store, _allowance(10 * BODY_BYTES))
    body = _refused_reply(9000)
    child = await _reingress(store, runner, body, now=300.0)
    assert child["status"] == MessageStatus.ERROR.value
    assert child["raw"] == body
    assert child["error"] == REINGRESS_PEEK_FAILED
    record = child["meta"][METADATA_KEY]
    assert record == {
        "bytes": BODY_BYTES,
        "body_hmac": refused_body_digest(store.cipher(), body.encode()),
        "stored": "whole",
    }


async def assert_an_admitted_reply_is_never_bounded(store: Any) -> None:
    """A reply that peeks is routed, not refused: a spent allowance neither cuts it nor records a
    refused-body entry for it."""
    runner = _runner(store, _allowance(0))
    child = await _reingress(store, runner, REPLY, now=400.0)
    assert child["status"] == MessageStatus.RECEIVED.value
    assert child["raw"] == REPLY
    assert METADATA_KEY not in child["meta"]


#: Every case, for ``pytest.mark.parametrize``. Each takes ``(store,)``.
CASES = [
    pytest.param(assert_a_refused_reply_flood_stores_heads_past_the_allowance, id="flood"),
    pytest.param(assert_a_refused_reply_inside_the_allowance_is_stored_whole, id="whole"),
    pytest.param(assert_an_admitted_reply_is_never_bounded, id="admitted"),
]
