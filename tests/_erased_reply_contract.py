# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Cross-backend contract: replay of a re-ingress token whose reply retention erased (BACKLOG #1560).

A captured reply owed to a loopback is a ``Stage.RESPONSE`` work-row. Its ``payload`` is a reference
to the ``response`` artifact, not a body, so it stayed non-blank after retention erased the artifact.
``replay`` then re-pended the row, and ``ingress_handoff`` turned the missing artifact into a child
message with an empty body.

Extra-free on the ``_finalize_race_contract`` precedent: nothing optional is imported, so the gated
Postgres and SQL Server suites run the same body on legs that install only their own extra.

``fetch`` runs one query with ``?`` placeholders outside the store and returns its rows as dicts, and
``raw`` runs one statement the same way. Each backend's adapter respells the placeholders.

**Every refused token has an unpurged control beside it.** "0 rows requeued" is what a broken replay
looks like too.
"""

from __future__ import annotations

import asyncio
from typing import Any

import pytest

from messagefoundry.store import MessageStatus, OutboxStatus, Stage
from tests._queue_tag_contract import RawFetch, RawSql
from tests._store_audit import no_operator_audit

DAY = 86_400.0
LOOP = "IB_LOOP"
RAW = "MSH|^~\\&|SYNTH|F|R|RF|20260101||ADT^A01|ER1|P|2.5.1\rPID|1||SYNTH-100||DOE^JANE\r"
BODY = "MSH|^~\\&|XFORM|||||20260101||ADT^A01|OUT1|P|2.5.1\r"
REPLY = "MSH|^~\\&|PARTNER|||||20260101||ACK^A01|RSP1|P|2.5.1\rMSA|AA|OUT1\r"


async def status_of(store: Any, message_id: str) -> str:
    msg = await store.get_message(message_id)
    assert msg is not None
    return str(msg["status"])


async def token_row(fetch: RawFetch, token_id: str) -> dict[str, Any]:
    rows = await fetch("SELECT status, payload FROM queue WHERE id=?", (token_id,))
    assert len(rows) == 1, rows
    return rows[0]


async def children(fetch: RawFetch) -> list[dict[str, Any]]:
    """Every message re-ingressed onto the loopback. An erased reply must never add one."""
    return await fetch("SELECT id, status FROM messages WHERE channel_id=?", (LOOP,))


async def dead_token(
    store: Any,
    *,
    now: float,
    control: str,
    extra: tuple[tuple[str, str], ...] = (),
) -> tuple[str, str]:
    """A delivered message whose captured reply owes a re-ingress that dead-lettered.

    Returns ``(message_id, token_id)``. ``extra`` adds sibling deliveries, left pending."""
    mid = await store.enqueue_message(
        channel_id="IB_REAL",
        raw=RAW,
        deliveries=[("OB_X", BODY), *extra],
        control_id=control,
        now=now,
    )
    return mid, await kill_reply(store, now=now)


async def kill_reply(store: Any, *, now: float) -> str:
    """Deliver the pending ``OB_X`` row, capture its reply, and dead-letter the re-ingress token.
    Returns the token's id."""
    [item] = await store.claim_ready(destination_name="OB_X", now=now)
    await store.complete_with_response(
        item.id, body=REPLY, outcome="accepted", reingress_to=LOOP, now=now
    )
    token = await store.claim_next_fifo(LOOP, now=now, stage=Stage.RESPONSE.value)
    assert token is not None
    await store.dead_letter_now(token.id, "loopback refused", now=now)
    return str(token.id)


async def run_reingress(store: Any, *, now: float) -> bool:
    """One pass of the re-ingress worker's store calls. Returns whether a token was claimed."""
    token = await store.claim_next_fifo(LOOP, now=now, stage=Stage.RESPONSE.value)
    if token is None:
        return False
    body = await store.response_body_for_work_row(token.id) or ""
    await store.ingress_handoff(
        response_row_id=token.id,
        loopback_channel_id=LOOP,
        correlation_depth_cap=8,
        control_id=None,
        message_type="ACK^A01",
        summary=None,
        peek_failed=not body,
        peek_error=None,
        now=now,
    )
    return True


async def assert_replay_refuses_an_erased_reply(store: Any, fetch: RawFetch, _raw: RawSql) -> None:
    """A dead token whose reply is erased is not replayed; the unpurged control is."""
    erased_mid, erased = await dead_token(store, now=0.0, control="ER-PURGED")
    kept_mid, kept = await dead_token(store, now=100 * DAY, control="ER-KEPT")
    assert await status_of(store, erased_mid) == MessageStatus.ERROR.value

    await store.purge_message_bodies(older_than=10 * DAY, now=50 * DAY)

    row = await token_row(fetch, erased)
    assert row["status"] == OutboxStatus.DEAD.value and row["payload"] == ""
    # Positive control: the purge is selective, and a retained token keeps its reference.
    assert (await token_row(fetch, kept))["payload"] != ""

    # The purged arm: nothing moves, the disposition stands, and no replayed event is written.
    assert await store.replay(erased_mid, now=60 * DAY, audit=no_operator_audit) == 0
    assert (await token_row(fetch, erased))["status"] == OutboxStatus.DEAD.value
    assert await status_of(store, erased_mid) == MessageStatus.ERROR.value
    events = await store.events_for(erased_mid)
    assert not [e for e in events if e["event"] == "replayed"]

    # The control: replay still re-queues and re-ingresses the retained reply.
    assert await store.replay(kept_mid, now=60 * DAY, audit=no_operator_audit) == 1
    assert await status_of(store, kept_mid) == MessageStatus.ROUTED.value
    assert await run_reingress(store, now=60 * DAY)
    assert await status_of(store, kept_mid) == MessageStatus.PROCESSED.value

    # Exactly the control's child exists. The erased token produced none.
    assert await run_reingress(store, now=60 * DAY) is False
    assert len(await children(fetch)) == 1


async def assert_mixed_message_recovers_only_what_remains(
    store: Any, fetch: RawFetch, _raw: RawSql
) -> None:
    """A message with an erased reply and a retained dead delivery, through ordinary replay and bulk
    dead-letter replay. The delivery comes back; the token does not; the message never reads
    PROCESSED, because the reply it owed no longer exists."""
    for bulk in (False, True):
        sibling = f"OB_DEAD_{int(bulk)}"
        mid, token = await dead_token(
            store, now=0.0, control=f"ER-MIXED-{bulk}", extra=((sibling, BODY),)
        )
        [row] = await store.claim_ready(destination_name=sibling, now=0.0)
        await store.dead_letter_now(row.id, "permanent reject", now=0.0)
        await store.purge_message_bodies(older_than=10 * DAY, now=50 * DAY)
        assert (await token_row(fetch, token))["payload"] == ""

        requeued = (
            await store.replay_dead(destination_name=sibling, now=60 * DAY, audit=no_operator_audit)
            if bulk
            else await store.replay(mid, now=60 * DAY, audit=no_operator_audit)
        )
        assert requeued == 1, bulk
        assert (await token_row(fetch, token))["status"] == OutboxStatus.DEAD.value

        [item] = await store.claim_ready(destination_name=sibling, now=60 * DAY)
        assert item.payload == BODY  # the retained delivery is the true body
        await store.mark_done(item.id, now=60 * DAY)
        assert await status_of(store, mid) == MessageStatus.ERROR.value, bulk
    assert await children(fetch) == []


async def assert_erased_after_replay_is_dead_lettered(
    store: Any, fetch: RawFetch, raw: RawSql
) -> None:
    """The window a row predicate cannot see: the token was re-pended, then the reply was erased.

    SQL Server materializes its eligible set once, so a replay can commit between that read and the
    artifact's erasure. This builds the result of that race directly."""
    gone_mid, gone = await dead_token(store, now=0.0, control="ER-RACE")
    kept_mid, _ = await dead_token(store, now=0.0, control="ER-RACE-KEPT")
    assert await store.replay(gone_mid, now=1.0, audit=no_operator_audit) == 1
    assert await store.replay(kept_mid, now=1.0, audit=no_operator_audit) == 1
    await raw("UPDATE response SET body=NULL WHERE message_id=?", (gone_mid,))

    assert await run_reingress(store, now=2.0)
    assert await run_reingress(store, now=2.0)

    # The erased arm: consumed, dead, blank, and ERROR on the origin. No child.
    row = await token_row(fetch, gone)
    assert row["status"] == OutboxStatus.DEAD.value and row["payload"] == ""
    assert await status_of(store, gone_mid) == MessageStatus.ERROR.value
    events = await store.events_for(gone_mid)
    assert [e for e in events if e["event"] == "dead" and "erased" in str(e["detail"])]
    # The blank makes the dead-letter final: a second replay is refused, not re-run forever.
    assert await store.replay(gone_mid, now=3.0, audit=no_operator_audit) == 0

    # The unpurged control: its child carries the true reply.
    assert await status_of(store, kept_mid) == MessageStatus.PROCESSED.value
    [child] = await children(fetch)
    message = await store.get_message(child["id"])
    assert message is not None and message["raw"] == REPLY


#: How a server backend reports that it chose this statement as the loser of a lock race: a deadlock
#: victim (SQL Server 1205, Postgres 40P01), a lock timeout (SQL Server 1222, Postgres 55P03) or a
#: serialization failure (Postgres 40001). Matched on text, so the contract needs no driver import.
_LOCK_RACE_MARKERS = (
    "deadlock",
    "lock request time out",
    "could not obtain lock",
    "lock timeout",
    "could not serialize",
)


def _lost_a_lock_race(outcome: BaseException) -> bool:
    text = repr(outcome).lower()
    return any(marker in text for marker in _LOCK_RACE_MARKERS)


async def assert_purge_concurrent_with_replay_keeps_the_invariant(
    store: Any, fetch: RawFetch, _raw: RawSql
) -> None:
    """Replay and purge raced, in both start orders. Either may win, and a server backend may also
    pick one as the loser of a lock race, because they take ``queue`` and ``messages`` in opposite
    orders.
    What may never happen is a child with an empty body, or a PROCESSED origin whose reply was erased."""
    for first in ("replay", "purge"):
        mid, token = await dead_token(store, now=0.0, control=f"ER-CONC-{first}")
        replay = store.replay(mid, now=60 * DAY, audit=no_operator_audit)
        purge = store.purge_message_bodies(older_than=10 * DAY, now=60 * DAY)
        ordered = (replay, purge) if first == "replay" else (purge, replay)
        for outcome in await asyncio.gather(*ordered, return_exceptions=True):
            if isinstance(outcome, BaseException) and not _lost_a_lock_race(outcome):
                raise outcome
        await run_reingress(store, now=61 * DAY)

        final = await status_of(store, mid)
        if final == MessageStatus.PROCESSED.value:
            # The replay won: the reply stayed, so the token became a child holding it.
            assert not await fetch("SELECT id FROM queue WHERE id=?", (token,)), first
        else:
            assert final == MessageStatus.ERROR.value, (first, final)
            assert (await token_row(fetch, token))["payload"] == "", first
        for child in await children(fetch):
            message = await store.get_message(child["id"])
            assert message is not None and message["raw"] == REPLY, first


async def assert_missing_artifact_row_is_a_corrupt_reference(
    store: Any, fetch: RawFetch, raw: RawSql
) -> None:
    """Retention keeps the ``response`` row and NULLs its body, so a row that is gone is damage, not
    an erasure. It dead-letters as a corrupt reference and is NOT blanked: its sealed reference is
    the evidence of which row went missing. A later replay re-queues it into the same dead end once,
    and the worker does not loop on it."""
    mid, token = await dead_token(store, now=0.0, control="ER-MISSING")
    assert await store.replay(mid, now=1.0, audit=no_operator_audit) == 1
    reference = (await token_row(fetch, token))["payload"]
    await raw("DELETE FROM response WHERE message_id=?", (mid,))

    assert await run_reingress(store, now=2.0)

    row = await token_row(fetch, token)
    assert row["status"] == OutboxStatus.DEAD.value and row["payload"] == reference != ""
    assert await status_of(store, mid) == MessageStatus.ERROR.value
    events = await store.events_for(mid)
    assert [e for e in events if e["event"] == "dead" and "corrupt" in str(e["detail"])]
    assert await children(fetch) == []

    # One dead end per replay, not a loop.
    assert await store.replay(mid, now=3.0, audit=no_operator_audit) == 1
    assert await run_reingress(store, now=4.0)
    assert await run_reingress(store, now=5.0) is False
    row = await token_row(fetch, token)
    assert row["status"] == OutboxStatus.DEAD.value and row["payload"] == reference
    assert await children(fetch) == []


async def assert_dead_letter_purge_clears_the_blanked_token(
    store: Any, fetch: RawFetch, _raw: RawSql
) -> None:
    """The message purge blanks a dead token and leaves its ``last_error`` for the dead-letter window.
    That window must still reach a row whose payload is already blank, or the error outlives it."""
    mid, token = await dead_token(store, now=0.0, control="ER-DLQ")
    await store.purge_message_bodies(older_than=10 * DAY, now=50 * DAY)
    errors = "SELECT last_error FROM queue WHERE id=?"
    assert (await fetch(errors, (token,)))[0]["last_error"] is not None
    assert await status_of(store, mid) == MessageStatus.ERROR.value

    assert await store.purge_dead_letters(older_than=10 * DAY, now=50 * DAY) == 1

    assert (await fetch(errors, (token,)))[0]["last_error"] is None
    row = await token_row(fetch, token)
    assert row["status"] == OutboxStatus.DEAD.value and row["payload"] == ""
    assert await store.purge_dead_letters(older_than=10 * DAY, now=50 * DAY) == 0  # idempotent


#: Every case, for ``pytest.mark.parametrize``. Each takes ``(store, fetch, raw)`` and needs a store
#: with no loopback messages yet, so each runs on its own clean store.
CASES = [
    pytest.param(assert_replay_refuses_an_erased_reply, id="replay"),
    pytest.param(assert_mixed_message_recovers_only_what_remains, id="mixed"),
    pytest.param(assert_erased_after_replay_is_dead_lettered, id="erased_after_replay"),
    pytest.param(assert_purge_concurrent_with_replay_keeps_the_invariant, id="concurrent"),
    pytest.param(assert_missing_artifact_row_is_a_corrupt_reference, id="missing_artifact"),
    pytest.param(assert_dead_letter_purge_clears_the_blanked_token, id="dead_letter_purge"),
]
