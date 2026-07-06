# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Store-once-deliver-many (L2b): when one handler's transform produces an IDENTICAL transformed body
for N destinations, the body is stored ONCE in ``shared_body`` and the N outbound rows reference it via
``body_ref`` (dereferenced at delivery). Covers the dedup, the per-destination deref, the inline
fall-through for a singleton body, encryption-at-rest of the shared copy, the refcount + GC retention
safety (a shared body is never orphaned nor purged while an outbound row still references it), and the
key-rotation re-encrypt pass. SQLite is the reference backend; PG/SQL Server carry the schema only this
increment (CI-verified post-merge).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from messagefoundry.store.crypto import MARKER_PREFIX, generate_key, make_cipher
from messagefoundry.store.store import MessageStatus, MessageStore, Stage

RAW = "MSH|^~\\&|S|F|R|RF|20260101||ADT^A01|MSG1|P|2.5.1\rPID|1||100||DOE^JANE\r"
BODY = "MSH|^~\\&|XFORM|||||20260101||ADT^A01|OUT1|P|2.5.1\r"  # the shared transformed body


@pytest.fixture
async def store(tmp_path: Path):
    s = await MessageStore.open(tmp_path / "once.db")
    yield s
    await s.close()


@pytest.fixture
async def enc_store(tmp_path: Path):
    """An encrypted store so the shared body is exercised through the at-rest cipher."""
    s = await MessageStore.open(tmp_path / "once_enc.db", cipher=make_cipher(generate_key()))
    yield s
    await s.close()


async def _route_one(
    store: MessageStore, channel: str, handler: str = "h1", *, now: float = 0.0
) -> str:
    mid = await store.enqueue_ingress(channel_id=channel, raw=RAW, now=now)
    item = await store.claim_next_fifo(channel, stage=Stage.INGRESS.value, now=now)
    assert item is not None
    await store.route_handoff(
        ingress_id=item.id,
        message_id=mid,
        channel_id=channel,
        handlers=[(handler, RAW)],
        disposition=MessageStatus.ROUTED,
        now=now,
    )
    return mid


async def _transform(
    store: MessageStore, channel: str, deliveries: list[tuple[str, str]], *, now: float = 0.0
) -> None:
    item = await store.claim_next_fifo(channel, stage=Stage.ROUTED.value, now=now)
    assert item is not None
    await store.transform_handoff(
        routed_id=item.id,
        message_id=item.message_id,
        channel_id=channel,
        deliveries=deliveries,
        now=now,
    )


async def _outbound_rows(store: MessageStore, mid: str) -> list[dict]:
    cur = await store._db.execute(
        "SELECT destination_name, payload, body_ref FROM queue"
        " WHERE message_id=? AND stage=? ORDER BY destination_name",
        (mid, Stage.OUTBOUND.value),
    )
    return [dict(r) for r in await cur.fetchall()]


async def _shared_count(store: MessageStore) -> int:
    cur = await store._db.execute("SELECT COUNT(*) AS n FROM shared_body")
    return int((await cur.fetchone())["n"])


# --- dedup: identical body across N destinations is stored ONCE -------------------------------------


async def test_identical_body_to_many_destinations_stored_once(store: MessageStore) -> None:
    mid = await _route_one(store, "IB")
    dests = ["OB_A", "OB_B", "OB_C"]
    await _transform(store, "IB", [(d, BODY) for d in dests])

    rows = await _outbound_rows(store, mid)
    assert [r["destination_name"] for r in rows] == dests
    # Every outbound row references the ONE shared copy (same hash) and stores no inline payload.
    refs = {r["body_ref"] for r in rows}
    assert len(refs) == 1 and None not in refs
    assert all(r["payload"] == "" for r in rows)
    # Exactly one shared body, refcount == fan-out.
    assert await _shared_count(store) == 1
    cur = await store._db.execute("SELECT refcount FROM shared_body")
    assert int((await cur.fetchone())["refcount"]) == len(dests)


async def test_singleton_body_stays_inline(store: MessageStore) -> None:
    # One destination → no fan-out → the body stays inline in payload (byte-identical to before).
    mid = await _route_one(store, "IB")
    await _transform(store, "IB", [("OB_A", BODY)])
    rows = await _outbound_rows(store, mid)
    assert len(rows) == 1
    assert rows[0]["body_ref"] is None
    assert rows[0]["payload"] != ""  # inline ciphertext/plaintext, not blanked
    assert await _shared_count(store) == 0  # no shared row created for a singleton


async def test_distinct_bodies_each_inline(store: MessageStore) -> None:
    # Two destinations with DIFFERENT bodies → neither shared (each fans out to exactly one dest).
    mid = await _route_one(store, "IB")
    await _transform(store, "IB", [("OB_A", BODY), ("OB_B", BODY + "X")])
    rows = await _outbound_rows(store, mid)
    assert all(r["body_ref"] is None for r in rows)
    assert await _shared_count(store) == 0


async def test_mixed_shared_and_inline_in_one_handoff(store: MessageStore) -> None:
    # Two dests share BODY (deduped), a third has a unique body (inline).
    mid = await _route_one(store, "IB")
    await _transform(store, "IB", [("OB_A", BODY), ("OB_B", BODY), ("OB_C", "UNIQUE")])
    rows = {r["destination_name"]: r for r in await _outbound_rows(store, mid)}
    assert rows["OB_A"]["body_ref"] is not None
    assert rows["OB_B"]["body_ref"] == rows["OB_A"]["body_ref"]
    assert rows["OB_C"]["body_ref"] is None and rows["OB_C"]["payload"] != ""
    assert await _shared_count(store) == 1


# --- deref: each destination's delivery sees the correct body ---------------------------------------


async def test_claim_dereferences_shared_body_for_each_destination(store: MessageStore) -> None:
    await _route_one(store, "IB")
    dests = ["OB_A", "OB_B", "OB_C"]
    await _transform(store, "IB", [(d, BODY) for d in dests])
    # Each per-destination FIFO claim resolves the SAME shared body back to the original plaintext.
    for d in dests:
        item = await store.claim_next_fifo(d, now=1000.0)
        assert item is not None
        assert (
            item.payload == BODY
        )  # dereferenced, decrypted, byte-identical to the transformed body


async def test_claim_ready_dereferences_shared_body(store: MessageStore) -> None:
    await _route_one(store, "IB")
    await _transform(store, "IB", [("OB_A", BODY), ("OB_B", BODY)])
    items = await store.claim_ready(limit=10, now=1000.0)
    assert len(items) == 2
    assert {i.payload for i in items} == {BODY}


async def test_outbox_payloads_for_dereferences_shared_body(store: MessageStore) -> None:
    mid = await _route_one(store, "IB")
    await _transform(store, "IB", [("OB_A", BODY), ("OB_B", BODY)])
    rows = await store.outbox_payloads_for(mid)
    assert len(rows) == 2
    assert all(
        r["payload"] == BODY for r in rows
    )  # the parity/PHI read path deref's the shared copy


# --- encryption at rest ------------------------------------------------------------------------------


async def test_shared_body_encrypted_at_rest(enc_store: MessageStore) -> None:
    await _route_one(enc_store, "IB")
    await _transform(enc_store, "IB", [("OB_A", BODY), ("OB_B", BODY)])
    cur = await enc_store._db.execute("SELECT body FROM shared_body")
    stored = (await cur.fetchone())["body"]
    assert stored.startswith(MARKER_PREFIX)  # the single copy is ciphertext, not plaintext
    assert BODY not in stored
    # And it still dereferences back to plaintext on delivery.
    item = await enc_store.claim_next_fifo("OB_A", now=1000.0)
    assert item is not None and item.payload == BODY


# --- retention: refcount + GC safety -----------------------------------------------------------------


async def test_purge_releases_shared_body_only_after_all_referrers(store: MessageStore) -> None:
    mid = await _route_one(store, "IB")
    dests = ["OB_A", "OB_B"]
    await _transform(store, "IB", [(d, BODY) for d in dests])
    # Deliver only OB_A; OB_B is still pending (in flight in the pipeline sense for retention).
    a = await store.claim_next_fifo("OB_A", now=10.0)
    assert a is not None
    await store.mark_done(a.id, now=11.0)
    # A purge now must NOT touch the body: OB_B still has a pending row, so the message isn't eligible.
    purged = await store.purge_message_bodies(older_than=10_000.0, now=10_000.0)
    assert purged == 0
    assert await _shared_count(store) == 1  # body preserved — a live referrer remains

    # Deliver OB_B, then the message is fully resolved and eligible for body purge.
    b = await store.claim_next_fifo("OB_B", now=12.0)
    assert b is not None
    await store.mark_done(b.id, now=13.0)
    purged = await store.purge_message_bodies(older_than=10_000.0, now=10_000.0)
    assert purged == 1
    # Both referrers purged → refcount hit 0 → the shared body is GC-deleted (no orphan).
    assert await _shared_count(store) == 0
    rows = await _outbound_rows(store, mid)
    assert all(r["body_ref"] is None and r["payload"] == "" for r in rows)


async def test_purge_is_idempotent_for_shared_bodies(store: MessageStore) -> None:
    mid = await _route_one(store, "IB")
    await _transform(store, "IB", [("OB_A", BODY), ("OB_B", BODY)])
    for d in ("OB_A", "OB_B"):
        it = await store.claim_next_fifo(d, now=10.0)
        assert it is not None
        await store.mark_done(it.id, now=11.0)
    assert await store.purge_message_bodies(older_than=10_000.0, now=10_000.0) == 1
    assert await _shared_count(store) == 0
    # Re-running the purge is a clean no-op (body_ref already NULL → no double-release into negatives).
    assert await store.purge_message_bodies(older_than=10_000.0, now=10_000.0) == 0
    assert await _shared_count(store) == 0
    _ = mid


async def test_purge_dead_letters_releases_shared_body(store: MessageStore) -> None:
    await _route_one(store, "IB")
    await _transform(store, "IB", [("OB_A", BODY), ("OB_B", BODY)])
    assert await _shared_count(store) == 1
    # Dead-letter both deliveries (a permanent reject), then purge dead bodies past their window.
    for d in ("OB_A", "OB_B"):
        it = await store.claim_next_fifo(d, now=10.0)
        assert it is not None
        await store.dead_letter_now(it.id, "permanent reject", now=11.0)
    purged = await store.purge_dead_letters(older_than=10_000.0, now=10_000.0)
    assert purged == 2
    assert await _shared_count(store) == 0  # both dead referrers released → GC'd


async def test_partial_dead_letter_keeps_shared_body(store: MessageStore) -> None:
    # OB_A dead-lettered, OB_B delivered: purging dead letters releases ONE ref but the body survives
    # for the delivered row (and is only GC'd once that row is purged too).
    mid = await _route_one(store, "IB")
    await _transform(store, "IB", [("OB_A", BODY), ("OB_B", BODY)])
    a = await store.claim_next_fifo("OB_A", now=10.0)
    assert a is not None
    await store.dead_letter_now(a.id, "reject", now=11.0)
    b = await store.claim_next_fifo("OB_B", now=10.0)
    assert b is not None
    await store.mark_done(b.id, now=11.0)

    await store.purge_dead_letters(older_than=10_000.0, now=10_000.0)
    assert await _shared_count(store) == 1  # OB_B still references it
    cur = await store._db.execute("SELECT refcount FROM shared_body")
    assert int((await cur.fetchone())["refcount"]) == 1
    # The delivered OB_B row still dereferences correctly until its own message-body purge.
    rows = await store.outbox_payloads_for(mid)
    ob_b = next(r for r in rows if r["destination_name"] == "OB_B")
    assert ob_b["payload"] == BODY


# --- key rotation ------------------------------------------------------------------------------------


async def test_rotation_reencrypts_shared_body(tmp_path: Path) -> None:
    db = tmp_path / "rotate.db"
    key_a, key_b = generate_key(), generate_key()
    s = await MessageStore.open(db, cipher=make_cipher(key_a))
    try:
        await _route_one(s, "IB")
        await _transform(s, "IB", [("OB_A", BODY), ("OB_B", BODY)])
    finally:
        await s.close()
    # Reopen with a new active key, the old key retired, and rotate: the shared body must re-encrypt.
    s2 = await MessageStore.open(db, cipher=make_cipher(key_b, [key_a]))
    try:
        rewritten = await s2.reencrypt_to_active()
        assert rewritten >= 1  # the shared body (among other rows) was re-encrypted
        # The content address is over the PLAINTEXT, so it is rotation-stable, and delivery still works.
        item = await s2.claim_next_fifo("OB_A", now=1000.0)
        assert item is not None and item.payload == BODY
    finally:
        await s2.close()
