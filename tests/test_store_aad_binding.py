# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""ASVS 11.3.3 — cell-bound at-rest AAD, end-to-end through the SQLite store (ADR 0019).

The crypto core (``cell_aad`` + the v2 writer) is unit-tested in ``test_store_encryption.py``. This
module proves the *backend threading*: with ``[store].aad_bind`` ON (``make_cipher(..., write_v2=True)``)
every real write→read path round-trips, a ciphertext relocated to a **different cell** fails closed
(``CipherError``), legacy ``v1`` rows still decrypt (dual-read), and a ``rotate-key`` upgrades ``v1→v2``
in place. The broad round-trip net (every existing store suite re-run with the AAD forced on) lives in
the ``MEFOR_TEST_FORCE_AAD_BIND`` conftest fixture; these are the targeted, always-on cases.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from messagefoundry.store import MessageStatus
from messagefoundry.store.crypto import PREFIX, CipherError, generate_key, make_cipher
from messagefoundry.store.store import MessageStore, Stage

RAW = "MSH|^~\\&|S|F|R|RF|20260101||ADT^A01|MSG1|P|2.5.1\rPID|1||100||DOE^JANE\r"
BODY = "MSH|^~\\&|S|F|R|RF|20260101||ADT^A01|OUT1|P|2.5.1\rPID|1||200||ROE^RICH\r"


async def _open_bound(path: Path, key: str, retired: list[str] | None = None) -> MessageStore:
    """Open a store whose cipher writes the cell-bound ``mfenc:v2`` marker (``aad_bind`` ON)."""
    return await MessageStore.open(path, cipher=make_cipher(key, retired or [], write_v2=True))


@pytest.fixture
async def aad_store(tmp_path: Path):
    store = await _open_bound(tmp_path / "aad.db", generate_key())
    yield store
    await store.close()


# --- round-trips: every cell writes v2-with-AAD and reads back -----------------------------------


async def test_messages_cells_roundtrip_under_aad_bind(aad_store: MessageStore) -> None:
    mid = await aad_store.enqueue_message(
        channel_id="IB",
        raw=RAW,
        deliveries=[("OB", BODY)],
        summary="MRN=100 DOE^JANE",
        metadata='{"k": "v"}',
    )
    rec = await aad_store.get_message(mid)
    assert rec is not None
    assert rec["raw"] == RAW  # messages.raw bound to (messages, raw, mid)
    assert rec["summary"] == "MRN=100 DOE^JANE"
    assert rec["metadata"] == '{"k": "v"}'
    # And the at-rest bytes are the v2 cell-bound marker, not v1 and not plaintext.
    async with aad_store._read() as db:
        cur = await db.execute("SELECT raw FROM messages WHERE id=?", (mid,))
        on_disk = (await cur.fetchone())["raw"]
    assert on_disk.startswith("mfenc:v2:") and "DOE" not in on_disk


async def test_queue_payload_roundtrip_and_claim(aad_store: MessageStore) -> None:
    await aad_store.enqueue_message(channel_id="IB", raw=RAW, deliveries=[("OB", BODY)])
    item = await aad_store.claim_next_fifo("OB")
    assert item is not None
    assert item.payload == BODY  # queue.payload deref'd + decrypted under its cell AAD


async def test_store_once_deref_roundtrip_under_aad_bind(aad_store: MessageStore) -> None:
    # Two identical delivery bodies → one shared_body row; both outbound rows carry a body_ref.
    mid = await aad_store.enqueue_message(
        channel_id="IB", raw=RAW, deliveries=[("D1", BODY), ("D2", BODY)]
    )
    # The COALESCE + shared_body deref read path decrypts under the shared_body content-address cell.
    payloads = await aad_store.outbox_payloads_for(mid)
    assert [p["payload"] for p in payloads] == [BODY, BODY]
    # And the claim path (OutboxItem.from_row deref) resolves the same shared copy.
    for dest in ("D1", "D2"):
        claimed = await aad_store.claim_next_fifo(dest)
        assert claimed is not None and claimed.payload == BODY


async def test_state_and_reference_roundtrip_under_aad_bind(tmp_path: Path) -> None:
    key = generate_key()
    store = await _open_bound(tmp_path / "sr.db", key)
    try:
        mid, routed_id = await _route_one(store)
        await store.transform_handoff(
            routed_id=routed_id,
            message_id=mid,
            channel_id="IB",
            deliveries=[],
            state_ops=[("ns", "k", "sekret")],
        )
        await store.write_reference_snapshot(name="prov", version="1", rows={"NPI1": "Dr Who"})
        assert store.state_view()[("ns", "k")] == "sekret"
        assert store.reference_view()["prov"]["NPI1"] == "Dr Who"
    finally:
        await store.close()
    # Reopen: the state/reference caches decrypt every value at open under its composite cell AAD.
    store2 = await _open_bound(tmp_path / "sr.db", key)
    try:
        assert store2.state_view()[("ns", "k")] == "sekret"
        assert store2.reference_view()["prov"]["NPI1"] == "Dr Who"
    finally:
        await store2.close()


async def test_response_and_events_roundtrip_under_aad_bind(aad_store: MessageStore) -> None:
    await aad_store.enqueue_message(channel_id="IB", raw=RAW, deliveries=[("OB", BODY)])
    item = await aad_store.claim_next_fifo("OB")
    assert item is not None
    await aad_store.complete_with_response(
        item.id, body="MSA|AA|OUT1", outcome="delivered", detail="ack ok"
    )
    caps = await aad_store.correlate_response(item.message_id)
    assert any(c.body == "MSA|AA|OUT1" and c.detail == "ack ok" for c in caps)
    # message_events.detail (composite (message_id, ts, event) cell) reads back too.
    events = await aad_store.events_for(item.message_id)
    assert events and all("detail" in e for e in events)


async def test_totp_connection_event_alert_roundtrip(tmp_path: Path) -> None:
    key = generate_key()
    store = await _open_bound(tmp_path / "misc.db", key)
    try:
        await store._db.execute(
            "INSERT INTO users (id, username, auth_provider, created_at, updated_at) "
            "VALUES ('u1','alice','local',0,0)"
        )
        await store._db.commit()
        await store.set_totp_secret("u1", secret="JBSWY3DPEHPK3PXP")
        assert await store.get_totp_secret("u1") == "JBSWY3DPEHPK3PXP"
        await store.record_connection_event(
            connection="IB",
            transport="mllp",
            direction="inbound",
            kind="framing_error",
            reason="bad MLLP frame",
        )
        evs = await store.list_connection_events(connection="IB")
        assert evs and evs[0].reason == "bad MLLP frame"
        await store.upsert_alert_instance(
            event_type="connection_error",
            connection="IB",
            severity="warning",
            reason="connect refused",
        )
        alerts = await store.list_active_alert_instances()
        assert alerts and alerts[0].reason == "connect refused"
    finally:
        await store.close()


# --- fail-closed: a ciphertext moved to a DIFFERENT cell fails the tag ----------------------------


async def test_wrong_row_relocation_rejected(aad_store: MessageStore) -> None:
    """messages.raw ciphertext cut from message A and pasted into message B's raw fails closed."""
    a = await aad_store.enqueue_message(channel_id="IB", raw=RAW, deliveries=[("OB", BODY)])
    b = await aad_store.enqueue_message(channel_id="IB", raw=BODY, deliveries=[("OB", RAW)])
    async with aad_store._read() as db:
        cur = await db.execute("SELECT raw FROM messages WHERE id=?", (a,))
        a_ct = (await cur.fetchone())["raw"]
    async with aad_store._lock:
        await aad_store._db.execute("UPDATE messages SET raw=? WHERE id=?", (a_ct, b))
        await aad_store._db.commit()
    with pytest.raises(CipherError):
        await aad_store.get_message(b)  # A's ciphertext bound to (messages, raw, a) != (…, b)


async def test_wrong_column_relocation_rejected(aad_store: MessageStore) -> None:
    """messages.raw ciphertext read as messages.summary (same row) fails closed — column is bound too."""
    mid = await aad_store.enqueue_message(channel_id="IB", raw=RAW, deliveries=[("OB", BODY)])
    async with aad_store._read() as db:
        cur = await db.execute("SELECT raw FROM messages WHERE id=?", (mid,))
        raw_ct = (await cur.fetchone())["raw"]
    async with aad_store._lock:
        await aad_store._db.execute("UPDATE messages SET summary=? WHERE id=?", (raw_ct, mid))
        await aad_store._db.commit()
    with pytest.raises(CipherError):
        await aad_store.get_message(mid)  # raw-cell ciphertext in the summary column fails the tag


async def test_queue_payload_wrong_row_relocation_rejected(aad_store: MessageStore) -> None:
    """A queue.payload blob moved to another outbound row fails closed at claim/deref."""
    await aad_store.enqueue_message(channel_id="IB", raw=RAW, deliveries=[("D1", BODY)])
    await aad_store.enqueue_message(channel_id="IB", raw=BODY, deliveries=[("D2", RAW)])
    async with aad_store._read() as db:
        cur = await db.execute(
            "SELECT id, payload FROM queue WHERE destination_name=? AND stage=?",
            ("D1", Stage.OUTBOUND.value),
        )
        d1 = await cur.fetchone()
        cur = await db.execute(
            "SELECT id FROM queue WHERE destination_name=? AND stage=?",
            ("D2", Stage.OUTBOUND.value),
        )
        d2_id = (await cur.fetchone())["id"]
    async with aad_store._lock:
        await aad_store._db.execute("UPDATE queue SET payload=? WHERE id=?", (d1["payload"], d2_id))
        await aad_store._db.commit()
    # D2's row now holds D1's ciphertext (bound to D1's queue id) → deref/decrypt fails the tag. The
    # claim path dead-letters an undecryptable row rather than raising, so assert it never delivers D1's
    # body as D2 — the fail-closed contract (a wrong-cell blob is never silently accepted).
    item = await aad_store.claim_next_fifo("D2")
    assert item is None or item.payload != BODY


# --- v1 dual-read + rotate v1→v2 upgrade ---------------------------------------------------------


async def test_v1_rows_still_read_under_aad_bind(tmp_path: Path) -> None:
    """A store written under the frozen v1 writer, reopened with aad_bind ON, still decrypts (dual-read)."""
    db = tmp_path / "v1dual.db"
    key = generate_key()
    v1 = await MessageStore.open(db, cipher=make_cipher(key))  # write_v2 defaults False → v1
    mid = await v1.enqueue_message(
        channel_id="IB", raw=RAW, deliveries=[("OB", BODY)], summary="s", metadata="m"
    )
    async with v1._read() as conn:
        cur = await conn.execute("SELECT raw FROM messages WHERE id=?", (mid,))
        assert (await cur.fetchone())["raw"].startswith(PREFIX)  # frozen v1 marker
    await v1.close()
    bound = await _open_bound(db, key)
    try:
        rec = await bound.get_message(mid)  # v1 marker → decrypt with None AAD (dual-read)
        assert rec is not None and rec["raw"] == RAW and rec["summary"] == "s"
    finally:
        await bound.close()


async def test_rotate_key_upgrades_v1_to_v2_in_place(tmp_path: Path) -> None:
    """rotate-key under aad_bind rewrites legacy v1 rows to cell-bound v2 and reads still resolve."""
    db = tmp_path / "rot.db"
    old = generate_key()
    v1 = await MessageStore.open(db, cipher=make_cipher(old))
    mid = await v1.enqueue_message(channel_id="IB", raw=RAW, deliveries=[("OB", BODY)], summary="s")
    await v1.close()
    new = generate_key()
    # Reopen with a NEW active key (old retired) AND aad_bind ON — the rotation scenario.
    store = await _open_bound(db, new, retired=[old])
    try:
        assert (await store.get_message(mid))["raw"] == RAW  # keyring read before rotation
        rotated = await store.reencrypt_to_active()
        assert rotated >= 1
        async with store._read() as conn:
            cur = await conn.execute("SELECT raw FROM messages WHERE id=?", (mid,))
            on_disk = (await cur.fetchone())["raw"]
        assert on_disk.startswith("mfenc:v2:")  # upgraded v1 → cell-bound v2
        rec = await store.get_message(mid)  # and it still round-trips under the new key + AAD
        assert rec is not None and rec["raw"] == RAW and rec["summary"] == "s"
    finally:
        await store.close()


# --- helpers -------------------------------------------------------------------------------------


async def _route_one(store: MessageStore) -> tuple[str, str]:
    """Ingress a message and route it to one handler, returning (message_id, routed_row_id)."""
    mid = await store.enqueue_ingress(channel_id="IB", raw=RAW)
    ingress = await store.claim_next_fifo("IB", stage=Stage.INGRESS.value)
    assert ingress is not None
    await store.route_handoff(
        ingress_id=ingress.id,
        message_id=mid,
        channel_id="IB",
        handlers=[("H", RAW)],
        disposition=MessageStatus.ROUTED,
    )
    routed = await store.claim_next_fifo("IB", stage=Stage.ROUTED.value)
    assert routed is not None
    return mid, routed.id
