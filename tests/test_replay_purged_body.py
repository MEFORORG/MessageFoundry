# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #1560 — replay must not re-queue a delivery whose body retention has erased.

Retention blanks a delivered (or dead-lettered) outbound body to ``payload=''``. Before this fix
:meth:`replay` and :meth:`replay_dead` re-pended that row anyway: the delivery worker handed the
connector an empty string and the finalizer recorded the send as a success. On the dead-letter leg a
message flipped from ``ERROR`` to ``PROCESSED`` on the strength of a zero-byte frame.

**The discriminator already exists in the data — there is no schema change here.** Three facts make
``payload = '' AND body_ref IS NULL`` exact:

1. all three purge paths write a *literal* ``payload=''``;
2. a real body goes through ``self._cipher.encrypt``, so on a keyed store it is never ``''``;
3. a store-once row carries a non-NULL ``body_ref`` — its ``''`` inline payload is a deref sentinel,
   not an erasure, and the purge nulls the ref before it blanks the row.

The store already agreed with that predicate in one place: ``_attachment_still_referenced_sql`` calls a
row a *live holder* when ``payload <> '' OR body_ref IS NOT NULL``, and releases the streaming
attachment when the last such row is gone. So the attachment GC believed a purged row could no longer
be replayed while ``replay`` replayed it anyway — the two are now consistent.

**Every behavioural test here keeps an UNPURGED SIBLING CONTROL.** A test that only proves the erased
row is skipped cannot tell you the fix broke replay outright, and "0 rows requeued" is what both
outcomes look like.

**Keyless limitation, stated because it is real.** On a store with no encryption key
``IdentityCipher.encrypt('')`` returns ``''``, so a *legitimately* empty body that has already been
delivered is indistinguishable at rest from a purged one and its re-send is refused. The first
delivery is unaffected — the guard is on replay only — and a keyed store separates the two exactly
(``test_encrypted_store_keeps_a_legitimately_empty_body_replayable``). Refusing a re-send of nothing is
the safe side of that trade.
"""

from __future__ import annotations

import asyncio
import os
from pathlib import Path

import pytest

from messagefoundry.store import MessageStore, OutboxStatus, Stage
from messagefoundry.store.crypto import generate_key, make_cipher
from messagefoundry.store.store import MessageStatus

DAY = 86_400.0
RAW = "MSH|^~\\&|S|F|R|RF|20260101||ADT^A01|MSG1|P|2.5.1\rPID|1||100||DOE^JANE\r"
BODY = "MSH|^~\\&|XFORM|||||20260101||ADT^A01|OUT1|P|2.5.1\r"


@pytest.fixture
async def store(tmp_path: Path):
    s = await MessageStore.open(tmp_path / "replay_purged.db")
    yield s
    await s.close()


@pytest.fixture
async def enc_store(tmp_path: Path):
    """A keyed store: a real body is ciphertext at rest, so ``''`` can only be an erasure."""
    s = await MessageStore.open(
        tmp_path / "replay_purged_enc.db", cipher=make_cipher(generate_key())
    )
    yield s
    await s.close()


# --- helpers ------------------------------------------------------------------


async def _delivered(
    store: MessageStore, *, now: float, body: str, control: str
) -> tuple[str, str]:
    """Enqueue one delivery and drive it to DONE. Returns ``(message_id, outbox_id)``."""
    mid = await store.enqueue_message(
        channel_id="c1", raw=RAW, deliveries=[("d1", body)], control_id=control, now=now
    )
    [row] = await store.outbox_for(mid)
    await store.claim_ready(now=now)
    await store.mark_done(row["id"], now=now)
    return mid, row["id"]


async def _dead(
    store: MessageStore, *, now: float, body: str, control: str, dest: str = "d1"
) -> tuple[str, str]:
    """Enqueue one delivery and drive it to DEAD. Returns ``(message_id, outbox_id)``."""
    mid = await store.enqueue_message(
        channel_id="c1", raw=RAW, deliveries=[(dest, body)], control_id=control, now=now
    )
    [row] = await store.outbox_for(mid)
    await store.claim_ready(now=now)
    await store.dead_letter_now(row["id"], "permanent reject", now=now)
    return mid, row["id"]


async def _row(store: MessageStore, outbox_id: str) -> dict:
    cur = await store._db.execute(
        "SELECT status, payload, body_ref FROM queue WHERE id=?", (outbox_id,)
    )
    return dict(await cur.fetchone())


async def _status(store: MessageStore, message_id: str) -> str:
    msg = await store.get_message(message_id)
    assert msg is not None
    return str(msg["status"])


async def _has_delivery_key(store: MessageStore, outbox_id: str) -> bool:
    cur = await store._db.execute(
        "SELECT 1 FROM delivered_keys WHERE outbox_id=? LIMIT 1", (outbox_id,)
    )
    return await cur.fetchone() is not None


# --- replay: the re-send branch (a delivered body retention then erased) -------


async def test_replay_refuses_an_erased_delivered_body_and_keeps_the_disposition(
    store: MessageStore,
) -> None:
    """The purged arm is skipped whole; the unpurged control still re-sends.

    Both halves matter. Without the control a green test is equally consistent with replay having been
    broken outright. Three things must survive on the purged arm: the queue row stays ``done``, the
    message stays ``PROCESSED`` (never flipped back to ``ROUTED`` for a send that cannot happen), and
    its ``delivered_keys`` ledger entry is NOT dropped — dropping it would leave the crash-re-run
    duplicate guard disarmed for a row nobody is going to re-deliver.
    """
    purged_mid, purged_row = await _delivered(store, now=0.0, body=BODY, control="CID-PURGED")
    kept_mid, kept_row = await _delivered(store, now=100 * DAY, body=BODY, control="CID-KEPT")

    assert await store.purge_message_bodies(older_than=10 * DAY, now=50 * DAY) == 1
    assert (await _row(store, purged_row))["payload"] == ""
    # Positive control: the purge was selective, not a blanket blank of every row.
    assert (await _row(store, kept_row))["payload"] != ""

    # Purged arm: nothing requeued, nothing changed.
    assert await store.replay(purged_mid, now=60 * DAY) == 0
    assert (await _row(store, purged_row))["status"] == OutboxStatus.DONE.value
    assert await _status(store, purged_mid) == MessageStatus.PROCESSED.value
    assert await _has_delivery_key(store, purged_row) is True

    # Unpurged control: replay still works exactly as before.
    assert await store.replay(kept_mid, now=60 * DAY) == 1
    assert (await _row(store, kept_row))["status"] == OutboxStatus.PENDING.value
    assert await _status(store, kept_mid) == MessageStatus.ROUTED.value
    assert await _has_delivery_key(store, kept_row) is False  # re-send drops its own ledger entry


async def test_replay_logs_no_replayed_event_for_a_fully_erased_message(
    store: MessageStore,
) -> None:
    """A refusal must not leave a ``replayed`` audit event claiming rows moved. The count-and-log
    record has to agree with what happened, or an operator reading the timeline sees a replay that
    never occurred."""
    mid, _ = await _delivered(store, now=0.0, body=BODY, control="CID-EVT")
    await store.purge_message_bodies(older_than=10 * DAY, now=50 * DAY)

    assert await store.replay(mid, now=60 * DAY) == 0

    cur = await store._db.execute(
        "SELECT COUNT(*) AS n FROM message_events WHERE message_id=? AND event='replayed'", (mid,)
    )
    assert int((await cur.fetchone())["n"]) == 0


# --- replay: a MIXED batch skips, it does not raise ---------------------------


async def test_replay_of_a_mixed_message_requeues_the_kept_row_and_skips_the_erased_one(
    store: MessageStore,
) -> None:
    """Ruling 4: a mixed batch SKIPS the erased rows rather than aborting the whole call.

    ``purge_dead_letters`` is per-ROW (its cutoff reads ``queue.updated_at``), so one message can hold
    an erased dead row beside a kept one. The operator's replay must recover what is recoverable.
    """
    # Distinct bodies on purpose: an identical pair would take the store-once path and land as two
    # ``''`` payloads behind one ``body_ref``, which is the OTHER case (covered separately below).
    mid = await store.enqueue_message(
        channel_id="c1",
        raw=RAW,
        deliveries=[("d_old", BODY + "OBX|1|ST|OLD\r"), ("d_new", BODY + "OBX|1|ST|NEW\r")],
        control_id="CID-MIXED",
        now=0.0,
    )
    rows = {r["destination_name"]: r["id"] for r in await store.outbox_for(mid)}
    await store.claim_ready(now=0.0)
    await store.dead_letter_now(rows["d_old"], "permanent reject", now=0.0)
    await store.dead_letter_now(rows["d_new"], "permanent reject", now=100 * DAY)

    # Only the older dead row falls inside the window.
    assert await store.purge_dead_letters(older_than=10 * DAY, now=50 * DAY) == 1
    assert (await _row(store, rows["d_old"]))["payload"] == ""
    assert (await _row(store, rows["d_new"]))["payload"] != ""

    requeued = await store.replay(mid, now=110 * DAY)

    assert requeued == 1  # the kept row only — no exception, no all-or-nothing abort
    assert (await _row(store, rows["d_old"]))["status"] == OutboxStatus.DEAD.value
    assert (await _row(store, rows["d_new"]))["status"] == OutboxStatus.PENDING.value
    assert await _status(store, mid) == MessageStatus.ROUTED.value


async def test_replay_resend_keeps_the_delivery_key_of_the_row_it_did_not_requeue(
    store: MessageStore,
) -> None:
    """Ruling 3, re-send half: the ``delivered_keys`` DELETE carries the same predicate as the UPDATE.

    An unscoped DELETE would drop the idempotency-ledger entry of an erased row that is NOT being
    re-pended, disarming the crash-re-run duplicate guard for a delivery that will never run again.
    Two messages, one purged, so the DELETE's scope is observable per row.
    """
    purged_mid, purged_row = await _delivered(store, now=0.0, body=BODY, control="CID-DK-P")
    kept_mid, kept_row = await _delivered(store, now=100 * DAY, body=BODY, control="CID-DK-K")
    await store.purge_message_bodies(older_than=10 * DAY, now=50 * DAY)

    await store.replay(purged_mid, now=60 * DAY)
    await store.replay(kept_mid, now=60 * DAY)

    assert await _has_delivery_key(store, purged_row) is True  # untouched
    assert await _has_delivery_key(store, kept_row) is False  # deliberately cleared for the re-send


# --- replay_dead: the bulk dead-letter leg ------------------------------------


async def test_replay_dead_skips_erased_rows_and_leaves_their_message_in_error(
    store: MessageStore,
) -> None:
    """Ruling 3: the predicate goes in BOTH statements, not only the UPDATE.

    ``replay_dead`` computes its affected message set with a separate ``SELECT DISTINCT message_id``
    before the UPDATE. Guarding only the UPDATE would flip the erased message from ``ERROR`` to
    ``ROUTED`` with nothing re-queued — a NEW false disposition, worse than the one being fixed. The
    ``error`` assertion below is the one that catches that mistake; the ``rowcount`` assertion does not.
    """
    purged_mid, purged_row = await _dead(store, now=0.0, body=BODY, control="CID-DL-P")
    kept_mid, kept_row = await _dead(store, now=100 * DAY, body=BODY, control="CID-DL-K")

    assert await store.purge_dead_letters(older_than=10 * DAY, now=50 * DAY) == 1
    assert await _status(store, purged_mid) == MessageStatus.ERROR.value
    assert await _status(store, kept_mid) == MessageStatus.ERROR.value

    requeued = await store.replay_dead(now=110 * DAY)

    assert requeued == 1  # the control only
    assert (await _row(store, purged_row))["status"] == OutboxStatus.DEAD.value
    assert await _status(store, purged_mid) == MessageStatus.ERROR.value  # NOT flipped
    assert (await _row(store, kept_row))["status"] == OutboxStatus.PENDING.value
    assert await _status(store, kept_mid) == MessageStatus.ROUTED.value


async def test_replay_dead_returns_zero_when_every_dead_row_is_erased(store: MessageStore) -> None:
    """An all-erased batch is a no-op, not a partial commit: no message leaves ``ERROR`` and no
    ``replayed`` event is written."""
    mid, row_id = await _dead(store, now=0.0, body=BODY, control="CID-DL-ALL")
    await store.purge_dead_letters(older_than=10 * DAY, now=50 * DAY)

    assert await store.replay_dead(now=60 * DAY) == 0
    assert (await _row(store, row_id))["status"] == OutboxStatus.DEAD.value
    assert await _status(store, mid) == MessageStatus.ERROR.value
    cur = await store._db.execute(
        "SELECT COUNT(*) AS n FROM message_events WHERE message_id=? AND event='replayed'", (mid,)
    )
    assert int((await cur.fetchone())["n"]) == 0


# --- the store-once arm: ``payload=''`` with a live ``body_ref`` is NOT erased --


async def test_a_store_once_row_still_replays_because_its_body_ref_is_live(
    store: MessageStore,
) -> None:
    """The ``body_ref IS NOT NULL`` arm is load-bearing, and dropping it breaks EVERY fanned-out feed.

    A store-once delivery keeps its single body in ``shared_body`` and stores ``payload=''`` inline as a
    deref sentinel. On ``payload=''`` alone the guard would refuse every one of them. The purge nulls
    ``body_ref`` *before* it blanks the row, so the two states stay distinguishable.
    """
    mid = await store.enqueue_ingress(channel_id="IB", raw=RAW, now=0.0)
    item = await store.claim_next_fifo("IB", stage=Stage.INGRESS.value, now=0.0)
    assert item is not None
    await store.route_handoff(
        ingress_id=item.id,
        message_id=mid,
        channel_id="IB",
        handlers=[("h1", RAW)],
        disposition=MessageStatus.ROUTED,
        now=0.0,
    )
    routed = await store.claim_next_fifo("IB", stage=Stage.ROUTED.value, now=0.0)
    assert routed is not None
    # One identical body to two destinations => one shared_body row, two body_refs, two '' payloads.
    await store.transform_handoff(
        routed_id=routed.id,
        message_id=mid,
        channel_id="IB",
        deliveries=[("OB_A", BODY), ("OB_B", BODY)],
        now=0.0,
    )
    rows = {r["destination_name"]: r["id"] for r in await store.outbox_for(mid)}
    await store.claim_ready(now=0.0)
    for outbox_id in rows.values():
        await store.mark_done(outbox_id, now=0.0)
    for outbox_id in rows.values():
        state = await _row(store, outbox_id)
        assert state["payload"] == "" and state["body_ref"] is not None  # the trap state

    # Unpurged: both store-once rows are still replayable.
    assert await store.replay(mid, now=1.0) == 2
    for outbox_id in rows.values():
        assert (await _row(store, outbox_id))["status"] == OutboxStatus.PENDING.value

    # Purge them (the rows must be terminal again first) and the same rows become unreplayable.
    for outbox_id in rows.values():
        await store.claim_ready(now=2.0)
        await store.mark_done(outbox_id, now=2.0)
    assert await store.purge_message_bodies(older_than=10 * DAY, now=50 * DAY) == 1
    for outbox_id in rows.values():
        state = await _row(store, outbox_id)
        assert state["payload"] == "" and state["body_ref"] is None  # ref released by the purge
    assert await store.replay(mid, now=60 * DAY) == 0


# --- encryption: the discriminator survives a keyed store ---------------------


async def test_encrypted_store_keeps_a_legitimately_empty_body_replayable(
    enc_store: MessageStore,
) -> None:
    """Ruling 6: ``_insert_outbound_row`` encrypts directly rather than through ``_enc``, and that is
    what makes this case work. ``_enc`` short-circuits a falsy value to itself, so an empty body routed
    through it would land as ``''`` and be indistinguishable from an erasure. The direct
    ``self._cipher.encrypt('')`` produces a real ``mfenc:`` cell instead, so on a keyed store an empty
    body stays replayable while a purged one does not.
    """
    empty_mid, empty_row = await _delivered(enc_store, now=0.0, body="", control="CID-EMPTY")
    purged_mid, purged_row = await _delivered(enc_store, now=0.0, body=BODY, control="CID-ENC-P")

    stored = (await _row(enc_store, empty_row))["payload"]
    assert stored != ""  # positive control: an empty body is ciphertext, not a blank
    assert stored.startswith("mfenc:")

    await enc_store.purge_message_bodies(older_than=10 * DAY, now=50 * DAY)
    assert (await _row(enc_store, purged_row))["payload"] == ""  # the purge writes a LITERAL ''
    assert (await _row(enc_store, empty_row))["payload"] == ""  # ...to every eligible row

    # Both are erased now, so both are refused. The discriminator is proven by the pre-purge state
    # above: before the purge the empty body was ciphertext and therefore replayable.
    assert await enc_store.replay(empty_mid, now=60 * DAY) == 0
    assert await enc_store.replay(purged_mid, now=60 * DAY) == 0


async def test_encrypted_store_replays_an_empty_body_that_retention_has_not_touched(
    enc_store: MessageStore,
) -> None:
    """The keyed-store control for the case above, isolated from any purge: an empty delivered body
    re-sends normally. This is the case Ruling 5 protects — the guard must never refuse a legitimately
    empty body — and on a keyed store it holds for replay too, not only for the first delivery."""
    empty_mid, empty_row = await _delivered(enc_store, now=0.0, body="", control="CID-EMPTY-OK")

    assert await enc_store.replay(empty_mid, now=1.0) == 1
    assert (await _row(enc_store, empty_row))["status"] == OutboxStatus.PENDING.value
    assert await _status(enc_store, empty_mid) == MessageStatus.ROUTED.value


# --- a purge concurrent with a replay -----------------------------------------


async def test_purge_concurrent_with_replay_yields_one_of_the_two_serial_orders(
    store: MessageStore,
) -> None:
    """Scoped per the brief to ONE SQLite test plus the argument, which is structural.

    The guard is a WHERE-clause predicate inside statements that already run under ``self._lock`` and
    inside the transaction that does the re-pend. ``purge_message_bodies`` holds the same lock for its
    own ``BEGIN``..commit. SQLite here is a single writer behind one asyncio lock, so the two calls
    TOTALLY ORDER: there is no window in which the predicate reads a payload the purge is midway
    through blanking. That is why no concurrency harness is needed to pin this — the only two
    reachable outcomes are the two serial ones, and both are safe:

    - **replay first** -> the row is ``pending``, which makes the message fail the purge's
      ``NOT EXISTS (pending/inflight)`` eligibility test, so the purge skips it and the body survives
      for the re-delivery that is now in flight;
    - **purge first** -> the payload is ``''`` with a NULL ``body_ref``, so replay matches nothing and
      returns 0.

    The state this asserts can never appear is the torn one: a ``pending`` row with an erased body,
    which is exactly the delivery that would put a zero-byte frame on the wire.
    """
    mid, outbox_id = await _delivered(store, now=0.0, body=BODY, control="CID-RACE")

    purged, requeued = await asyncio.gather(
        store.purge_message_bodies(older_than=10 * DAY, now=50 * DAY),
        store.replay(mid, now=60 * DAY),
    )

    state = await _row(store, outbox_id)
    if requeued:
        # replay won the lock: the row is back in flight and its body was protected from the purge.
        assert (purged, requeued) == (0, 1)
        assert state["status"] == OutboxStatus.PENDING.value
        assert state["payload"] != ""
    else:
        # the purge won: the body is gone and replay correctly declined it.
        assert (purged, requeued) == (1, 0)
        assert state["status"] == OutboxStatus.DONE.value
        assert state["payload"] == ""
    # The torn state, asserted unconditionally: never pending with an erased body.
    assert not (state["status"] == OutboxStatus.PENDING.value and state["payload"] == "")


# --- backend parity: Postgres ------------------------------------------------


@pytest.mark.skipif(
    not os.getenv("MEFOR_TEST_POSTGRES"),
    reason="set MEFOR_TEST_POSTGRES=1 (+ MEFOR_STORE_* connection env) to run Postgres tests",
)
class TestPostgresParity:
    """The same two refusals on ``PostgresStore``. Gated, so a laptop run skips this whole class —
    ``tests/test_replay_erased_body_scope.py`` is the ungated structural cover for that gap."""

    @pytest.fixture
    async def pg(self):
        from messagefoundry.config.settings import load_settings
        from messagefoundry.store.postgres import PostgresStore

        s = await PostgresStore.open(load_settings(environ=os.environ).store)
        async with s._pool.acquire() as conn:
            for table in ("message_events", "delivered_keys", "response", "queue", "messages"):
                await conn.execute(f"DELETE FROM {table}")
        yield s
        await s.close()

    async def test_replay_refuses_an_erased_delivered_body(self, pg) -> None:
        purged_mid, purged_row = await _delivered(pg, now=0.0, body=BODY, control="PG-P")
        kept_mid, kept_row = await _delivered(pg, now=100 * DAY, body=BODY, control="PG-K")
        assert await pg.purge_message_bodies(older_than=10 * DAY, now=50 * DAY) == 1

        assert await pg.replay(purged_mid, now=60 * DAY) == 0
        assert (await pg.get_message(purged_mid))["status"] == MessageStatus.PROCESSED.value
        assert await pg.replay(kept_mid, now=60 * DAY) == 1  # unpurged control
        assert (await pg.get_message(kept_mid))["status"] == MessageStatus.ROUTED.value
        assert purged_row and kept_row  # ids are bound for symmetry with the SQLite arm

    async def test_replay_dead_skips_erased_rows_and_leaves_their_message_in_error(
        self, pg
    ) -> None:
        purged_mid, _ = await _dead(pg, now=0.0, body=BODY, control="PG-DL-P")
        kept_mid, _ = await _dead(pg, now=100 * DAY, body=BODY, control="PG-DL-K")
        assert await pg.purge_dead_letters(older_than=10 * DAY, now=50 * DAY) == 1

        assert await pg.replay_dead(now=110 * DAY) == 1
        assert (await pg.get_message(purged_mid))["status"] == MessageStatus.ERROR.value
        assert (await pg.get_message(kept_mid))["status"] == MessageStatus.ROUTED.value


# --- backend parity: SQL Server ----------------------------------------------


@pytest.mark.skipif(
    not os.getenv("MEFOR_TEST_SQLSERVER"),
    reason="set MEFOR_TEST_SQLSERVER=1 (+ MEFOR_STORE_* connection env) to run SQL Server tests",
)
class TestSqlServerParity:
    """The same two refusals on ``SqlServerStore``. Gated; see the note on the Postgres class."""

    @pytest.fixture
    async def ss(self):
        from messagefoundry.config.settings import load_settings
        from messagefoundry.store.sqlserver import SqlServerStore

        s = await SqlServerStore.open(load_settings(environ=os.environ).store)
        async with s._acquire() as conn, s._cursor(conn) as cur:
            for table in ("message_events", "delivered_keys", "response", "queue", "messages"):
                await cur.execute(f"DELETE FROM {table}")
            await s._commit(conn)
        yield s
        await s.close()

    async def test_replay_refuses_an_erased_delivered_body(self, ss) -> None:
        purged_mid, _ = await _delivered(ss, now=0.0, body=BODY, control="SS-P")
        kept_mid, _ = await _delivered(ss, now=100 * DAY, body=BODY, control="SS-K")
        assert await ss.purge_message_bodies(older_than=10 * DAY, now=50 * DAY) == 1

        assert await ss.replay(purged_mid, now=60 * DAY) == 0
        assert (await ss.get_message(purged_mid))["status"] == MessageStatus.PROCESSED.value
        assert await ss.replay(kept_mid, now=60 * DAY) == 1  # unpurged control
        assert (await ss.get_message(kept_mid))["status"] == MessageStatus.ROUTED.value

    async def test_replay_dead_skips_erased_rows_and_leaves_their_message_in_error(
        self, ss
    ) -> None:
        purged_mid, _ = await _dead(ss, now=0.0, body=BODY, control="SS-DL-P")
        kept_mid, _ = await _dead(ss, now=100 * DAY, body=BODY, control="SS-DL-K")
        assert await ss.purge_dead_letters(older_than=10 * DAY, now=50 * DAY) == 1

        assert await ss.replay_dead(now=110 * DAY) == 1
        assert (await ss.get_message(purged_mid))["status"] == MessageStatus.ERROR.value
        assert (await ss.get_message(kept_mid))["status"] == MessageStatus.ROUTED.value
