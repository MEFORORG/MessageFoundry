# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""The shipped outbound-delivery retry cap is FINITE (BACKLOG #1051).

``RetryPolicy.max_attempts`` shipped as ``None`` = retry forever, which contradicted two things the
engine itself already said:

* ``docs/CONNECTIONS.md`` (the ASVS 13.1.3 artifact) discloses the default and, two lines later,
  mandates a finite ``retry_max_attempts`` plus a short ``timeout_seconds`` for synchronous HTTP;
* :func:`~messagefoundry.pipeline.wiring_runner.check_http_sync_reply` **refuses to start** a
  ``reply_from`` inbound whose effective ``max_attempts`` resolves to ``None`` — so the engine
  refused the very default it shipped.

A finite cap is safe because of two properties, and this module **asserts both** rather than
restating them:

1. **Attempts are counted per ROW, not per lane.** Only the claimed head accrues attempts, so a long
   outage burns the cap on roughly the lane heads and leaves the backlog at zero.
2. **A dead-lettered row stays replayable.** Exhaustion parks a row in the DLQ operators already
   see; it is not a discard.

The wall-clock the cap buys is measured here by DRIVING the real ``mark_failed`` with an injected
clock, not by re-deriving the backoff formula in the test (a re-derivation would agree with itself
if the implementation changed underneath it).
"""

from __future__ import annotations

import pytest

from messagefoundry.config.models import ContentType, OrderingMode, RetryPolicy
from messagefoundry.config.settings import DeliverySettings
from messagefoundry.config.wiring import (
    Http,
    Registry,
    Rest,
    WiringError,
    apply_sync_reply_capture_implication,
    build_inbound_connection,
    build_outbound_connection,
)
from messagefoundry.pipeline.wiring_runner import check_http_sync_reply
from messagefoundry.store import MessageStatus, MessageStore, OutboxStatus

#: The ruled default (BACKLOG #1051). Stated once here; every assertion below reads it.
SHIPPED_CAP = 100


@pytest.fixture
async def store(tmp_path):
    s = await MessageStore.open(tmp_path / "retrycap.db")
    yield s
    await s.close()


def test_the_shipped_retry_default_is_finite() -> None:
    # Both tiers, because either one left at None would resurrect retry-forever: the per-outbound
    # built-in (an outbound that declares `retry=RetryPolicy(backoff_seconds=1)` and nothing else)
    # and the [delivery] global an outbound with no retry= inherits.
    assert RetryPolicy().max_attempts == SHIPPED_CAP
    assert DeliverySettings().retry_max_attempts == SHIPPED_CAP
    assert DeliverySettings().retry_policy().max_attempts == SHIPPED_CAP


def test_retry_forever_is_still_expressible_as_an_explicit_choice() -> None:
    # The cap is a DEFAULT, not a removal. A partner that must never lose a message can still opt
    # into retry-forever; it is now a written decision rather than what you get by saying nothing.
    assert RetryPolicy(max_attempts=None).max_attempts is None


async def test_the_cap_bounds_the_outage_window_it_buys(store: MessageStore) -> None:
    """Drive the REAL ``mark_failed`` 100 times and measure the elapsed wall clock to dead-letter.

    Under the shipped backoff (5 s base, x2, capped at 300 s) the row re-pends at 5, 10, 20, 40, 80,
    160 then 300 s for every remaining attempt, and the 100th failure dead-letters with no further
    wait: 315 + 93 * 300 = 28,215 s = 7 h 50 m 15 s. Asserted as a NUMBER, so shortening the cap or
    changing the backoff has to restate the window rather than quietly shrink it.
    """
    retry = RetryPolicy()  # the shipped policy, verbatim — cap AND backoff
    assert retry.max_attempts == SHIPPED_CAP
    mid = await store.enqueue_message(channel_id="c1", raw="x", deliveries=[("d1", "p1")], now=0.0)

    t = 0.0
    attempts = 0
    while True:
        claimed = await store.claim_ready(now=t, destination_name="d1")
        assert claimed, f"the lane stalled at t={t} after {attempts} attempts"
        attempts += 1
        next_at = await store.mark_failed(claimed[0].id, "partner unreachable", retry, now=t)
        if next_at is None:  # dead-lettered: the cap is exhausted
            break
        t = next_at
        assert attempts < SHIPPED_CAP * 2, "the cap never fired — the loop is not converging"

    assert attempts == SHIPPED_CAP
    assert t == pytest.approx(28215.0)  # 7 h 50 m 15 s
    row = (await store.outbox_for(mid))[0]
    assert row["status"] == OutboxStatus.DEAD.value
    assert row["attempts"] == SHIPPED_CAP


async def test_a_long_outage_burns_the_cap_on_the_head_not_the_backlog(store: MessageStore) -> None:
    """PROPERTY 1: attempts are per ROW.

    Three messages queued to one FIFO lane; the partner is down throughout. The head exhausts a
    (deliberately tiny) cap and dead-letters, while the two rows behind it never left ``pending`` and
    still carry ``attempts == 0`` — so an outage costs roughly one dead row per cap-window, not the
    whole backlog. The successor then inherits a FULL budget, which is the same statement viewed from
    the other side.
    """
    retry = RetryPolicy(max_attempts=3, backoff_seconds=1, backoff_multiplier=1)
    ids = [
        await store.enqueue_message(
            channel_id="c1", raw=f"m{i}", deliveries=[("d1", f"p{i}")], now=0.0
        )
        for i in range(3)
    ]

    t = 0.0
    for _ in range(retry.max_attempts):
        head = await store.claim_next_fifo("d1", now=t)
        assert head is not None, f"the FIFO head was not claimable at t={t}"
        await store.mark_failed(head.id, "partner unreachable", retry, now=t)
        t += 10  # past the 1 s backoff

    head_row = (await store.outbox_for(ids[0]))[0]
    assert head_row["status"] == OutboxStatus.DEAD.value
    assert head_row["attempts"] == 3

    for mid in ids[1:]:
        row = (await store.outbox_for(mid))[0]
        assert row["status"] == OutboxStatus.PENDING.value, "the backlog was charged for the outage"
        assert row["attempts"] == 0, "attempts leaked from the head onto a row never claimed"

    # The successor is now the head and starts from zero, not from the exhausted head's count.
    successor = await store.claim_next_fifo("d1", now=t)
    assert successor is not None and successor.id == (await store.outbox_for(ids[1]))[0]["id"]
    assert successor.attempts == 1  # this claim's own first attempt


async def test_a_dead_lettered_row_stays_replayable(store: MessageStore) -> None:
    """PROPERTY 2: exhaustion parks a row in the DLQ; it does not discard it.

    After replay the row is ``pending`` with ``attempts`` reset (a full budget again) and the message
    is back to ``routed`` — the same operator affordance an ``AR`` fail-fast dead-letter already has.
    """
    retry = RetryPolicy(max_attempts=2, backoff_seconds=1, backoff_multiplier=1)
    mid = await store.enqueue_message(channel_id="c1", raw="x", deliveries=[("d1", "p1")], now=0.0)
    t = 0.0
    for _ in range(2):
        claimed = await store.claim_ready(now=t, destination_name="d1")
        assert claimed
        await store.mark_failed(claimed[0].id, "partner unreachable", retry, now=t)
        t += 10

    assert (await store.outbox_for(mid))[0]["status"] == OutboxStatus.DEAD.value
    assert (await store.get_message(mid))["status"] == MessageStatus.ERROR.value
    assert len(await store.list_dead(channel_id="c1")) == 1  # visible to the operator

    assert await store.replay_dead(channel_id="c1", now=t) == 1

    row = (await store.outbox_for(mid))[0]
    assert row["status"] == OutboxStatus.PENDING.value
    assert row["attempts"] == 0  # a full budget again, not a row wedged at the cap
    assert row["last_error"] is None
    assert (await store.get_message(mid))["status"] == MessageStatus.ROUTED.value
    # Claimable again — the strongest form of "replayable" is that a worker can actually take it.
    assert await store.claim_next_fifo("d1", now=t) is not None


def _sync_reply_graph() -> tuple[Registry, object]:
    """A ``reply_from`` graph that declares NO retry policy — the shape whose effective cap comes
    entirely from ``[delivery]``, which is what the startup refusal reads."""
    reg = Registry()
    ic = build_inbound_connection(
        "IB_HTTP",
        Http(port=0, reply_from="OB_PARTNER"),
        router="r",
        content_type=ContentType.JSON,
    )
    reg.add_inbound(ic)
    reg.add_outbound(
        build_outbound_connection(
            "OB_PARTNER",
            Rest(url="https://partner.example/ingest", capture_response=True),
            ordering=OrderingMode.UNORDERED,  # the OTHER refusal arm, satisfied so it cannot mask this one
        )
    )
    apply_sync_reply_capture_implication(reg)
    return reg, ic


def test_the_engine_no_longer_refuses_the_default_it_ships() -> None:
    # The contradiction #1051 names, stated as a test: a reply_from graph that declares nothing and
    # inherits the SHIPPED [delivery] defaults must now start. Before the cap landed this raised.
    reg, ic = _sync_reply_graph()
    assert reg.outbound["OB_PARTNER"].retry is None, "the test lost its own premise"
    check_http_sync_reply(ic, reg, delivery=DeliverySettings(ordering=OrderingMode.UNORDERED))


def test_the_refusal_still_fires_on_an_explicit_retry_forever() -> None:
    # ...and the refusal is not gone, only no longer self-inflicted: an operator who deliberately
    # configures retry-forever under a synchronous reply is still refused at start.
    reg, ic = _sync_reply_graph()
    with pytest.raises(WiringError, match="EFFECTIVE max_attempts"):
        check_http_sync_reply(
            ic,
            reg,
            delivery=DeliverySettings(ordering=OrderingMode.UNORDERED, retry_max_attempts=None),
        )
