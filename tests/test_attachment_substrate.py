# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Streaming-attachment substrate (#149, ADR 0105 Phase 0). A very-large document (e.g. a base64 PDF in
OBX-5.5 too large for the frame cap) is DETACHED from its message into a content-addressed, chunked,
per-chunk-sealed in-store attachment. This generalizes the ``shared_body`` store-once model (content
address + refcount + GC-at-0) to a payload too large to hold whole. Covers the verbatim chunked
round-trip (Approach B — the exact bytes, byte-for-byte), per-chunk sealing at rest, content-address
dedup, the refcount incref/decref + GC, the startup orphan/incomplete sweep (no PHI chunk left at rest),
the key-rotation re-seal, and the capability flag gating the not-yet-supported server backends. SQLite is
the reference backend (Phases 3/4 are separate); mirrors ``test_store_once_deliver_many.py`` +
``test_store_encryption.py``.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from messagefoundry.store.crypto import MARKER_PREFIX, generate_key, make_cipher
from messagefoundry.store.store import (
    MessageStatus,
    MessageStore,
    Stage,
)

DAY = 86_400.0

# A "document" split into verbatim slices, as a streaming detach would hand it chunk-by-chunk. ASCII
# base64-like content (Approach B keeps the OBX-5.5 value verbatim — already ASCII base64 on the wire).
CHUNKS = ["QUJDRA==part0::", "RUZHSA==part1::", "SUpLTA==part2::"]
DOC = "".join(CHUNKS)
REF = hashlib.sha256(DOC.encode("utf-8")).hexdigest()


@pytest.fixture
async def store(tmp_path: Path):
    s = await MessageStore.open(tmp_path / "attach.db")
    yield s
    await s.close()


@pytest.fixture
async def enc_store(tmp_path: Path):
    s = await MessageStore.open(tmp_path / "attach_enc.db", cipher=make_cipher(generate_key()))
    yield s
    await s.close()


async def _read(s: MessageStore, ref: str) -> list[str]:
    return [c async for c in s.read_attachment(ref)]


async def _chunk_count(s: MessageStore, ref: str) -> int:
    cur = await s._db.execute(
        "SELECT COUNT(*) AS n FROM attachment_chunk WHERE attachment_id=?", (ref,)
    )
    row = await cur.fetchone()
    return int(row["n"])


async def _refcount(s: MessageStore, ref: str) -> int | None:
    cur = await s._db.execute("SELECT refcount FROM attachment WHERE id=?", (ref,))
    row = await cur.fetchone()
    return None if row is None else int(row["refcount"])


async def test_put_read_roundtrip_verbatim_chunked(store: MessageStore) -> None:
    ref = await store.put_attachment(CHUNKS, "application/pdf")
    # Content-addressed by the sha256 of the VERBATIM concatenated plaintext.
    assert ref == REF
    # One chunk row per input slice, stored in order.
    assert await _chunk_count(store, ref) == len(CHUNKS)
    # Read yields the EXACT slices back — concatenation reconstructs the document byte-for-byte.
    assert await _read(store, ref) == CHUNKS
    assert "".join(await _read(store, ref)) == DOC
    # Fresh attachment sits at refcount 0 until the caller increfs (Phase 1).
    assert await _refcount(store, ref) == 0


async def test_reading_missing_attachment_raises(store: MessageStore) -> None:
    with pytest.raises(KeyError):
        await _read(store, REF)  # never stored


async def test_chunks_sealed_at_rest_and_decrypt(enc_store: MessageStore) -> None:
    ref = await enc_store.put_attachment(CHUNKS, "application/pdf")
    cur = await enc_store._db.execute(
        "SELECT ciphertext FROM attachment_chunk WHERE attachment_id=? ORDER BY seq", (ref,)
    )
    rows = list(await cur.fetchall())
    assert len(rows) == len(CHUNKS)
    for r in rows:
        # Each chunk is independently mfenc-sealed at rest (not plaintext on disk).
        assert r["ciphertext"].startswith(MARKER_PREFIX)
    # And it decrypts back to the exact verbatim slices.
    assert await _read(enc_store, ref) == CHUNKS


async def test_put_dedups_identical_content(store: MessageStore) -> None:
    ref1 = await store.put_attachment(CHUNKS, "application/pdf")
    ref2 = await store.put_attachment(CHUNKS, "application/pdf")
    assert ref1 == ref2 == REF
    # Dedup: one physical copy, not two — the re-put wrote nothing new.
    assert await _chunk_count(store, ref1) == len(CHUNKS)
    cur = await store._db.execute("SELECT COUNT(*) AS n FROM attachment WHERE id=?", (ref1,))
    assert int((await cur.fetchone())["n"]) == 1
    # Different content → a different content address.
    other = await store.put_attachment(["totally different"], "text/plain")
    assert other != ref1


async def test_incref_decref_gc_at_zero(store: MessageStore) -> None:
    ref = await store.put_attachment(CHUNKS, "application/pdf")
    await store.attachment_incref(ref)
    await store.attachment_incref(ref)
    assert await _refcount(store, ref) == 2
    # One decref leaves it live and readable.
    await store.attachment_decref(ref)
    assert await _refcount(store, ref) == 1
    assert await _read(store, ref) == CHUNKS
    # The last decref GCs the attachment AND all its chunks.
    await store.attachment_decref(ref)
    assert await _refcount(store, ref) is None
    assert await _chunk_count(store, ref) == 0
    with pytest.raises(KeyError):
        await _read(store, ref)
    # A double-decref past zero is a tolerant no-op (idempotent GC).
    await store.attachment_decref(ref)


async def test_incref_missing_raises(store: MessageStore) -> None:
    with pytest.raises(KeyError):
        await store.attachment_incref("f" * 64)


async def test_startup_sweep_reclaims_orphans_and_incomplete(store: MessageStore) -> None:
    # (a) a refcount-0 attachment (fully written, never increffed) — reclaimable.
    zero_ref = await store.put_attachment(CHUNKS, "application/pdf")
    assert await _refcount(store, zero_ref) == 0
    # (b) an incomplete-write attachment: chunks with NO header row (a future incremental writer that
    # crashed before finalizing the header) — no PHI chunk may be left at rest.
    orphan_id = "a" * 64
    await store._db.execute(
        "INSERT INTO attachment_chunk (attachment_id, seq, ciphertext) VALUES (?,?,?)",
        (orphan_id, 0, store._cipher.encrypt("orphaned pdf bytes")),
    )
    await store._db.commit()
    # (c) a LIVE (increffed) attachment must SURVIVE the sweep.
    live_ref = await store.put_attachment(["a live document"], "text/plain")
    await store.attachment_incref(live_ref)

    reclaimed = await store.sweep_orphan_attachments()
    assert reclaimed == 2  # the refcount-0 header + the header-less orphan-chunk group

    # Both orphans gone — no chunk rows left at rest for either.
    assert await _refcount(store, zero_ref) is None
    assert await _chunk_count(store, zero_ref) == 0
    assert await _chunk_count(store, orphan_id) == 0
    # The live attachment is untouched and still readable.
    assert await _refcount(store, live_ref) == 1
    assert "".join(await _read(store, live_ref)) == "a live document"
    # Idempotent: a second sweep finds nothing.
    assert await store.sweep_orphan_attachments() == 0


async def test_key_rotation_reseals_chunks(tmp_path: Path) -> None:
    path = tmp_path / "rotate.db"
    k1 = generate_key()
    k2 = generate_key()

    s1 = await MessageStore.open(path, cipher=make_cipher(k1))
    ref = await s1.put_attachment(CHUNKS, "application/pdf")
    await s1.close()

    # Rotate: active = k2, k1 kept decrypt-only for the re-encrypt pass.
    s2 = await MessageStore.open(path, cipher=make_cipher(k2, [k1]))
    rotated = await s2.reencrypt_to_active()
    assert rotated >= len(CHUNKS)  # every chunk re-sealed under the active key
    assert await _read(s2, ref) == CHUNKS
    await s2.close()

    # Reopen with ONLY k2 (no retired key): reading proves the chunks are now sealed under k2 — if any
    # chunk were still under k1 the keyring couldn't decrypt it.
    s3 = await MessageStore.open(path, cipher=make_cipher(k2))
    assert await _read(s3, ref) == CHUNKS
    assert ref == REF  # the content address is over plaintext — rotation-stable
    await s3.close()


def test_capability_flag_sqlite_supported() -> None:
    assert MessageStore.supports_streaming_attachments is True


async def test_capability_flag_postgres_supported() -> None:
    # #149 Phase 4 (ADR 0105): the streaming-attachment substrate is now implemented on Postgres, so the
    # capability flag is True (go-live parity). The real round-trip is exercised against a live backend
    # by the gated tests/test_postgres_store.py suite; here we only pin the flag flip.
    mod = pytest.importorskip(
        "messagefoundry.store.postgres", reason="requires the postgres extra (asyncpg)"
    )

    assert mod.PostgresStore.supports_streaming_attachments is True


async def test_capability_flag_sqlserver_supported() -> None:
    # #149 Phase 4 (ADR 0105): the streaming-attachment substrate is now implemented on SQL Server, so
    # the capability flag is True (go-live parity — the production store is SQL Server). The real
    # round-trip is exercised against a live backend by the gated tests/test_sqlserver_store.py suite.
    mod = pytest.importorskip(
        "messagefoundry.store.sqlserver", reason="requires the sqlserver extra (aioodbc)"
    )

    assert mod.SqlServerStore.supports_streaming_attachments is True


# --- two-object commit: enqueue_ingress increfs in the SAME transaction (#149 Phase 1a) --------------


async def test_enqueue_ingress_increfs_attachment_in_same_transaction(store: MessageStore) -> None:
    # put_attachment commits the chunks at refcount 0; enqueue_ingress(attachment_refs=…) commits the
    # skeleton row AND increfs the attachment together — the second half of the two-object commit.
    ref = await store.put_attachment(CHUNKS, "application/pdf")
    assert await _refcount(store, ref) == 0  # fresh attachment: not yet referenced

    mid = await store.enqueue_ingress(channel_id="IB", raw="MSH|skeleton", attachment_refs=[ref])
    assert mid
    assert await _refcount(store, ref) == 1  # increffed by the ingress commit
    # The skeleton message row is durable RECEIVED alongside the incref (one message = one ingress row).
    cur = await store._db.execute("SELECT COUNT(*) AS n FROM messages WHERE id=?", (mid,))
    assert dict(await cur.fetchone())["n"] == 1


async def test_enqueue_ingress_dedups_duplicate_refs(store: MessageStore) -> None:
    # A skeleton naming the same attachment twice increfs it ONCE (distinct refs), so a later release
    # decrefs by the same count.
    ref = await store.put_attachment(CHUNKS, "application/pdf")
    await store.enqueue_ingress(channel_id="IB", raw="skeleton", attachment_refs=[ref, ref])
    assert await _refcount(store, ref) == 1


async def test_enqueue_ingress_missing_ref_rolls_back(store: MessageStore) -> None:
    # A ref naming no stored attachment (GC'd / never stored) fails loud and rolls back the whole ingress
    # commit — no half-written skeleton row, no ACK for a body we couldn't reference.
    bogus = "0" * 64
    with pytest.raises(KeyError):
        await store.enqueue_ingress(channel_id="IB", raw="skeleton", attachment_refs=[bogus])
    cur = await store._db.execute("SELECT COUNT(*) AS n FROM messages")
    assert dict(await cur.fetchone())["n"] == 0  # rolled back — no skeleton row


# --- Phase 3a: message->attachment linkage + retention decref (#149, ADR 0105) -----------------------
# Closes the Phase-1b over-retention gap: enqueue_ingress persists a message_attachment join row per
# detached attachment (atomic with the incref), and retention (purge_message_bodies) decrefs + deletes
# those rows in ONE transaction so a purged message's document is reclaimed at its last referrer — and a
# crash-re-run of the purge never double-decrefs / underflows / GCs a SHARED attachment a sibling holds.


async def _join_count(s: MessageStore, mid: str) -> int:
    cur = await s._db.execute(
        "SELECT COUNT(*) AS n FROM message_attachment WHERE message_id=?", (mid,)
    )
    return int((await cur.fetchone())["n"])


async def _detach_and_settle(
    s: MessageStore, *, now: float, ref: str, raw: str = "MSH|skeleton"
) -> str:
    """Ingest a detached-attachment message, then consume its ingress row (handoff, no deliveries) so it
    has no pending/inflight queue row and is retention-eligible when now < the purge cutoff."""
    mid = await s.enqueue_ingress(channel_id="IB", raw=raw, attachment_refs=[ref], now=now)
    item = await s.claim_next_fifo("IB", stage=Stage.INGRESS.value)
    assert item is not None
    await s.handoff(
        ingress_id=item.id,
        message_id=mid,
        channel_id="IB",
        deliveries=[],
        disposition=MessageStatus.FILTERED,
        now=now,
    )
    return mid


async def test_ingress_detach_creates_join_row_and_refcount(store: MessageStore) -> None:
    ref = await store.put_attachment(CHUNKS, "application/pdf")
    mid = await store.enqueue_ingress(channel_id="IB", raw="MSH|skel", attachment_refs=[ref])
    # One live reference == one join row naming the attachment.
    assert await _refcount(store, ref) == 1
    assert await _join_count(store, mid) == 1
    cur = await store._db.execute(
        "SELECT attachment_id FROM message_attachment WHERE message_id=?", (mid,)
    )
    assert (await cur.fetchone())["attachment_id"] == ref


async def test_purge_decrefs_and_deletes_linkage_atomically(store: MessageStore) -> None:
    ref = await store.put_attachment(CHUNKS, "application/pdf")
    mid = await _detach_and_settle(store, now=0.0, ref=ref)
    assert await _refcount(store, ref) == 1
    assert await _join_count(store, mid) == 1

    purged = await store.purge_message_bodies(older_than=10 * DAY)

    assert purged == 1
    # Body nulled (the mfdoc:v1:ref: handle is gone) AND the attachment reclaimed at its last referrer.
    assert (await store.get_message(mid))["raw"] == ""
    assert await _refcount(store, ref) is None  # decref'd to 0 → GC'd
    assert await _chunk_count(store, ref) == 0  # chunks reclaimed too
    assert await _join_count(store, mid) == 0  # linkage released


async def test_shared_attachment_refcount_two_purge_each(store: MessageStore) -> None:
    # Two messages carry the SAME content-addressed document → one attachment, refcount 2, two join rows.
    ref = await store.put_attachment(CHUNKS, "application/pdf")
    m1 = await _detach_and_settle(store, now=0.0, ref=ref)
    m2 = await _detach_and_settle(store, now=20 * DAY, ref=ref)
    assert await _refcount(store, ref) == 2
    assert await _join_count(store, m1) == 1 and await _join_count(store, m2) == 1

    # Purge only m1 (m2 is not past this cutoff): one holder released, the SIBLING keeps the document.
    assert await store.purge_message_bodies(older_than=10 * DAY) == 1
    assert await _refcount(store, ref) == 1
    assert await _chunk_count(store, ref) == len(CHUNKS)  # chunks intact — m2 still references them
    assert await _join_count(store, m1) == 0 and await _join_count(store, m2) == 1
    assert "".join(await _read(store, ref)) == DOC  # m2 can still read the exact bytes

    # Purge m2 (its own window): now the last referrer is gone → refcount 0 → GC.
    assert await store.purge_message_bodies(older_than=30 * DAY) == 1
    assert await _refcount(store, ref) is None
    assert await _chunk_count(store, ref) == 0


async def test_double_purge_idempotent_no_underflow_or_sibling_loss(store: MessageStore) -> None:
    # THE crux: a purge is crash-re-runnable. If a re-run double-decref'd a SHARED attachment, its refcount
    # would underflow and GC the document a sibling still references = silent DATA LOSS. The join-row DELETE
    # ordered inside the same transaction makes a re-run a no-op.
    ref = await store.put_attachment(CHUNKS, "application/pdf")
    m1 = await _detach_and_settle(store, now=0.0, ref=ref)
    m2 = await _detach_and_settle(store, now=20 * DAY, ref=ref)  # sibling, NOT yet eligible
    assert await _refcount(store, ref) == 2

    # Purge m1 only — TWICE (the re-run models a crash between decref and a lost commit acknowledgement).
    assert await store.purge_message_bodies(older_than=10 * DAY) == 1
    assert (
        await store.purge_message_bodies(older_than=10 * DAY) == 0
    )  # re-run: nothing left to null

    # Refcount stayed at 1 (no double-decref) — the sibling m2's document SURVIVES, byte-for-byte.
    assert await _refcount(store, ref) == 1
    assert await _chunk_count(store, ref) == len(CHUNKS)
    assert "".join(await _read(store, ref)) == DOC
    assert await _join_count(store, m1) == 0 and await _join_count(store, m2) == 1


async def test_fanout_delivered_twice_single_decref_at_purge(store: MessageStore) -> None:
    # A detached message fans out to two outbounds. Delivery is a pure READ (never an incref/decref), so
    # the refcount is 1 throughout delivery and drops by exactly ONE at purge — never per-delivery.
    ref = await store.put_attachment(CHUNKS, "application/pdf")
    mid = await store.enqueue_ingress(
        channel_id="IB", raw="MSH|skel", attachment_refs=[ref], now=0.0
    )
    item = await store.claim_next_fifo("IB", stage=Stage.INGRESS.value)
    assert item is not None
    await store.handoff(
        ingress_id=item.id,
        message_id=mid,
        channel_id="IB",
        deliveries=[("OB_A", "pa"), ("OB_B", "pb")],
        disposition=MessageStatus.ROUTED,
        now=0.0,
    )
    assert await _refcount(store, ref) == 1  # routing/handoff did not incref
    assert await _join_count(store, mid) == 1  # still one linkage row (one distinct attachment)

    rows = await store.outbox_for(mid)
    assert len(rows) == 2
    await store.claim_ready(now=0.0)
    for r in rows:
        await store.mark_done(r["id"], now=0.0)
    assert await _refcount(store, ref) == 1  # both delivered — delivery NEVER touches the refcount

    assert await store.purge_message_bodies(older_than=10 * DAY) == 1
    assert await _refcount(store, ref) is None  # exactly one decref at purge → GC
    assert await _join_count(store, mid) == 0


async def test_no_attachment_retention_byte_identical(store: MessageStore) -> None:
    # A message with no detached attachment has NO join rows; retention nulls its body exactly as before
    # and never touches the message_attachment table.
    mid = await store.enqueue_ingress(channel_id="IB", raw="MSH|plain", now=0.0)
    item = await store.claim_next_fifo("IB", stage=Stage.INGRESS.value)
    assert item is not None
    await store.handoff(
        ingress_id=item.id,
        message_id=mid,
        channel_id="IB",
        deliveries=[],
        disposition=MessageStatus.FILTERED,
        now=0.0,
    )
    assert await _join_count(store, mid) == 0

    assert await store.purge_message_bodies(older_than=10 * DAY) == 1
    assert (await store.get_message(mid))["raw"] == ""
    cur = await store._db.execute("SELECT COUNT(*) AS n FROM message_attachment")
    assert int((await cur.fetchone())["n"]) == 0  # linkage table untouched


async def test_release_message_attachments_standalone_and_idempotent(store: MessageStore) -> None:
    ref = await store.put_attachment(CHUNKS, "application/pdf")
    mid = await store.enqueue_ingress(channel_id="IB", raw="MSH|skel", attachment_refs=[ref])
    assert await _refcount(store, ref) == 1

    await store.release_message_attachments(mid)
    assert await _refcount(store, ref) is None  # decref'd to 0 → GC'd
    assert await _join_count(store, mid) == 0

    # Idempotent: a re-run finds the join rows gone and decrefs nothing (no underflow, no error).
    await store.release_message_attachments(mid)
    assert await _refcount(store, ref) is None


# --- Phase 3a regression: a DEAD (still-replayable) outbound row must KEEP the attachment -------------
# The over-release gap: purge_message_bodies is body-eligible for a message whose outbound rows are all
# DEAD (neither pending nor inflight), but a DEAD row stays REPLAYABLE — its payload is deliberately kept
# (deferred to purge_dead_letters) and a later replay HYDRATES the mfdoc:v1:ref: handle from the stored
# attachment. Releasing the attachment at the body purge GCs the document out from under that replay =
# permanent PHI-document loss. The attachment is instead released by whichever purge blanks the LAST
# replayable row (the per-MESSAGE analogue of the shared_body done/cancelled-vs-dead split).


async def _row_payload(s: MessageStore, outbox_id: str) -> str:
    cur = await s._db.execute("SELECT payload FROM queue WHERE id=?", (outbox_id,))
    return str((await cur.fetchone())["payload"])


async def _dead_deliver(
    s: MessageStore,
    *,
    now: float,
    ref: str,
    dest: str = "OB_D",
    payload: str = "MSH|dead|mfdoc:v1:ref:doc",
) -> tuple[str, str]:
    """Ingest a detached message, route it to ONE outbound, then claim + dead-letter that row — leaving a
    single DEAD, still-replayable outbound row that HOLDS the attachment (its payload is kept)."""
    mid = await s.enqueue_ingress(channel_id="IB", raw="MSH|skel", attachment_refs=[ref], now=now)
    item = await s.claim_next_fifo("IB", stage=Stage.INGRESS.value)
    assert item is not None
    await s.handoff(
        ingress_id=item.id,
        message_id=mid,
        channel_id="IB",
        deliveries=[(dest, payload)],
        disposition=MessageStatus.ROUTED,
        now=now,
    )
    [row] = await s.outbox_for(mid)
    await s.claim_ready(now=now)
    await s.dead_letter_now(row["id"], "permanent reject (AR)", now=now)
    return mid, row["id"]


async def test_dead_row_keeps_attachment_through_body_purge(store: MessageStore) -> None:
    # A message whose sole outbound row is DEAD is body-eligible, but that DEAD row is still replayable —
    # purge_message_bodies must NULL the body yet KEEP the attachment (a later replay needs the document).
    ref = await store.put_attachment(CHUNKS, "application/pdf")
    mid, oid = await _dead_deliver(store, now=0.0, ref=ref)
    assert await _refcount(store, ref) == 1
    assert await _join_count(store, mid) == 1

    purged = await store.purge_message_bodies(older_than=10 * DAY)

    assert purged == 1
    assert (await store.get_message(mid))[
        "raw"
    ] == ""  # body nulled (the mfdoc handle left messages.raw)
    # The DEAD row stays replayable AND its attachment SURVIVES — no premature GC / data loss.
    assert await _row_payload(store, oid) == "MSH|dead|mfdoc:v1:ref:doc"
    assert await _refcount(store, ref) == 1
    assert await _chunk_count(store, ref) == len(CHUNKS)
    assert await _join_count(store, mid) == 1
    assert "".join(await _read(store, ref)) == DOC  # the document is still readable for the replay


async def test_dead_letter_purge_releases_attachment_after_body_purge(store: MessageStore) -> None:
    # Once the DEAD row's own window elapses, purge_dead_letters blanks it AND releases the last-held
    # attachment — the deferred half of the split.
    ref = await store.put_attachment(CHUNKS, "application/pdf")
    mid, oid = await _dead_deliver(store, now=0.0, ref=ref)
    assert await store.purge_message_bodies(older_than=10 * DAY) == 1
    assert await _refcount(store, ref) == 1  # kept: the dead row is still replayable

    assert await store.purge_dead_letters(older_than=10 * DAY) == 1
    assert await _row_payload(store, oid) == ""  # dead row no longer replayable
    assert await _refcount(store, ref) is None  # last replayable holder gone → decref'd → GC
    assert await _chunk_count(store, ref) == 0
    assert await _join_count(store, mid) == 0


async def test_dead_letter_purge_releases_attachment_when_run_first(store: MessageStore) -> None:
    # Purge ORDER-independence: purge_dead_letters may run BEFORE purge_message_bodies and must still
    # release the attachment when it blanks the message's last replayable row (guards the interleaving
    # where a status-only gate would leak the attachment forever).
    ref = await store.put_attachment(CHUNKS, "application/pdf")
    mid, oid = await _dead_deliver(store, now=0.0, ref=ref)

    assert await store.purge_dead_letters(older_than=10 * DAY) == 1
    assert await _row_payload(store, oid) == ""
    assert await _refcount(store, ref) is None  # released here — the dead row was the last holder
    assert await _join_count(store, mid) == 0

    # A subsequent body purge nulls the (still-present) message row and is a no-op on the linkage.
    assert await store.purge_message_bodies(older_than=10 * DAY) == 1
    assert (await store.get_message(mid))["raw"] == ""
    assert await _refcount(store, ref) is None  # no double-decref / underflow


async def test_fanout_done_plus_dead_keeps_attachment_until_dead_purged(
    store: MessageStore,
) -> None:
    # One message fans out to a DELIVERED (done) and a DEAD outbound. The body purge blanks the done
    # payload but the DEAD sibling keeps the attachment alive; only purging the dead row releases it.
    ref = await store.put_attachment(CHUNKS, "application/pdf")
    mid = await store.enqueue_ingress(
        channel_id="IB", raw="MSH|skel", attachment_refs=[ref], now=0.0
    )
    item = await store.claim_next_fifo("IB", stage=Stage.INGRESS.value)
    assert item is not None
    await store.handoff(
        ingress_id=item.id,
        message_id=mid,
        channel_id="IB",
        deliveries=[("OB_OK", "p-ok|mfdoc:v1:ref:doc"), ("OB_BAD", "p-bad|mfdoc:v1:ref:doc")],
        disposition=MessageStatus.ROUTED,
        now=0.0,
    )
    rows = {r["destination_name"]: r["id"] for r in await store.outbox_for(mid)}
    await store.claim_ready(now=0.0)
    await store.mark_done(rows["OB_OK"], now=0.0)
    await store.dead_letter_now(rows["OB_BAD"], "reject", now=0.0)

    assert await store.purge_message_bodies(older_than=10 * DAY) == 1
    assert await _row_payload(store, rows["OB_OK"]) == ""  # done payload blanked
    assert await _refcount(store, ref) == 1  # the dead sibling keeps the attachment
    assert await _join_count(store, mid) == 1

    assert await store.purge_dead_letters(older_than=10 * DAY) == 1
    assert await _refcount(store, ref) is None  # last holder purged → GC
    assert await _join_count(store, mid) == 0


async def test_dead_letter_purge_idempotent_no_attachment_underflow(store: MessageStore) -> None:
    # A shared attachment across two messages, each held ONLY by a DEAD row. Purging one message's dead
    # row TWICE must decref exactly once — the sibling's document must survive (crash-re-run guard).
    ref = await store.put_attachment(CHUNKS, "application/pdf")
    m1, _ = await _dead_deliver(store, now=0.0, ref=ref, dest="OB_1")
    m2, _ = await _dead_deliver(store, now=20 * DAY, ref=ref, dest="OB_2")
    assert await _refcount(store, ref) == 2

    assert (
        await store.purge_dead_letters(older_than=10 * DAY) == 1
    )  # only m1's dead row is past cutoff
    assert await store.purge_dead_letters(older_than=10 * DAY) == 0  # re-run: nothing left to blank

    # m1 released exactly once; m2's document SURVIVES byte-for-byte at refcount 1 (no underflow / GC).
    assert await _refcount(store, ref) == 1
    assert await _chunk_count(store, ref) == len(CHUNKS)
    assert "".join(await _read(store, ref)) == DOC
    assert await _join_count(store, m1) == 0
    assert await _join_count(store, m2) == 1
