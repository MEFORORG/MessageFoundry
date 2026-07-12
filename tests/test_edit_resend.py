# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Edit a stored message and resubmit the edited body (ADR 0090 §9, BACKLOG #153).

Stacked on #123's resend seam. The SQLite invariant matrix for the RE-ROUTE re-ingress
(``store.reingress``) and the DIRECT edited-body path (``store.resend_to(body_override=...)``) plus the
``POST /messages/{id}/edit-resend`` endpoint: the ORIGINAL stays byte-identical (count-and-log), the
resubmit is a NEW correlated message, a retry under the same idempotency key delivers exactly ONCE (no
enqueue_ingress double-deliver), the edited body is never echoed in a 422 or an audit record, and both
re-route and direct work. Postgres/SQL Server parity + the offscreen-Qt console are CI's job."""

from __future__ import annotations

import json
from collections.abc import AsyncIterator
from pathlib import Path

import httpx
import pytest

from messagefoundry.config.models import ConnectorType
from messagefoundry.config.wiring import (
    ConnectionSpec,
    InboundConnection,
    OutboundConnection,
    Registry,
    Send,
)
from messagefoundry.pipeline import Engine
from messagefoundry.store import MessageStatus, OutboxStatus
from messagefoundry.store.base import ReingressOriginMissing, ResendKeyConflict, ResendSourceEmpty
from messagefoundry.store.store import REINGRESS_TARGET_PREFIX, MessageStore, Stage

ADT = "MSH|^~\\&|S|F|R|RF|20260101||ADT^A01|MSG1|P|2.5.1\rPID|1||100^^^H^MR||DOE^JANE\r"
EDITED = "MSH|^~\\&|S|F|R|RF|20260101||ADT^A01|MSG1|P|2.5.1\rPID|1||200^^^H^MR||DOE^JOHN\r"
TRANSFORMED = "MSH|^~\\&|MEFOR|RF|R|RF|20260101||ADT^A01|MSG1|P|2.5.1\rZXF|sent\r"


@pytest.fixture
async def store(tmp_path: Path) -> AsyncIterator[MessageStore]:
    s = await MessageStore.open(tmp_path / "editresend.db")
    try:
        yield s
    finally:
        await s.close()


async def _seed(store: MessageStore, *, channel: str = "in1") -> str:
    return await store.enqueue_message(
        channel_id=channel,
        raw=ADT,
        deliveries=[("OB1", TRANSFORMED)],
        control_id="MSG1",
        source_type="file",
    )


async def _ingress_rows(store: MessageStore, mid: str) -> list[dict[str, object]]:
    async with store._read() as db:
        cur = await db.execute(
            "SELECT id, stage, status FROM queue WHERE message_id=? AND stage=?",
            (mid, Stage.INGRESS.value),
        )
        return [dict(r) for r in await cur.fetchall()]


async def _outbound_rows(store: MessageStore, dest: str) -> list[dict[str, object]]:
    """Every stage='outbound' queue row for a destination, ACROSS all messages (origin + children)."""
    async with store._read() as db:
        cur = await db.execute(
            "SELECT id, message_id FROM queue WHERE stage=? AND destination_name=?",
            (Stage.OUTBOUND.value, dest),
        )
        return [dict(r) for r in await cur.fetchall()]


async def _seed_error(store: MessageStore, mid: str, error: str) -> None:
    """Force a seeded origin into a terminal ERROR disposition with a recorded error (ciphered at
    rest), to prove a direct edit-resend never reopens or overwrites it."""
    async with store._lock:
        await store._db.execute(
            "UPDATE messages SET status=?, error=? WHERE id=?",
            (MessageStatus.ERROR.value, store._enc(error), mid),
        )
        await store._db.commit()


# --- store: RE-ROUTE re-ingress (the default path) ---------------------------


async def test_reingress_creates_correlated_received_child(store: MessageStore) -> None:
    origin = await _seed(store)
    out = await store.reingress(origin_message_id=origin, raw=EDITED, idempotency_key="k1")
    assert out.status == "resubmitted"
    assert out.message_id == origin and out.new_message_id != origin
    assert out.channel_id == "in1"

    child = await store.get_message(out.new_message_id)
    assert child is not None
    assert child["raw"] == EDITED  # the EDITED body, decrypted at rest
    assert child["status"] == MessageStatus.RECEIVED.value  # a fresh receipt (count-and-log)
    assert child["channel_id"] == "in1"  # re-entered on the ORIGIN channel
    meta = json.loads(child["metadata"])
    assert meta["correlation_id"] == origin  # the logs LINK the child to the original
    assert meta["correlation_root_id"] == origin
    assert meta["edited_from"] == origin  # the edit provenance

    # the child carries a pending INGRESS row so the router worker re-routes it normally
    rows = await _ingress_rows(store, out.new_message_id)
    assert len(rows) == 1 and rows[0]["status"] == OutboxStatus.PENDING.value


async def test_reingress_leaves_original_byte_identical(store: MessageStore) -> None:
    origin = await _seed(store)
    before = await store.get_message(origin)
    assert before is not None
    await store.reingress(origin_message_id=origin, raw=EDITED, idempotency_key="k1")
    after = await store.get_message(origin)
    assert after is not None
    # The ORIGINAL row is never opened for write: raw + status + metadata unchanged.
    assert after["raw"] == before["raw"] == ADT
    assert after["status"] == before["status"]
    assert after["metadata"] == before["metadata"]
    # and it did NOT gain an ingress row of its own (the child owns the new ingress row)
    assert await _ingress_rows(store, origin) == []


async def test_reingress_same_key_delivers_once(store: MessageStore) -> None:
    origin = await _seed(store)
    first = await store.reingress(origin_message_id=origin, raw=EDITED, idempotency_key="k1")
    second = await store.reingress(origin_message_id=origin, raw=EDITED, idempotency_key="k1")
    assert first.status == "resubmitted" and second.status == "duplicate"
    # the retry reports the SAME child — never a second re-ingress (no double-deliver)
    assert second.new_message_id == first.new_message_id
    async with store._read() as db:
        cur = await db.execute(
            "SELECT COUNT(*) AS n FROM messages WHERE id=?", (first.new_message_id,)
        )
        assert (await cur.fetchone())["n"] == 1
    assert len(await _ingress_rows(store, first.new_message_id)) == 1  # exactly ONE ingress row


async def test_reingress_new_key_is_a_second_child(store: MessageStore) -> None:
    origin = await _seed(store)
    a = await store.reingress(origin_message_id=origin, raw=EDITED, idempotency_key="k1")
    b = await store.reingress(origin_message_id=origin, raw=EDITED, idempotency_key="k2")
    assert a.status == "resubmitted" and b.status == "resubmitted"
    assert a.new_message_id != b.new_message_id  # a NEW key IS a genuine second resubmit


async def test_reingress_key_reused_across_messages_is_a_conflict(store: MessageStore) -> None:
    m1 = await _seed(store)
    m2 = await _seed(store)
    await store.reingress(origin_message_id=m1, raw=EDITED, idempotency_key="k1")
    with pytest.raises(ResendKeyConflict):
        await store.reingress(origin_message_id=m2, raw=EDITED, idempotency_key="k1")


async def test_reingress_missing_origin_raises(store: MessageStore) -> None:
    with pytest.raises(ReingressOriginMissing):
        await store.reingress(origin_message_id="nope", raw=EDITED, idempotency_key="k1")


async def test_reingress_records_a_disjoint_target_key(store: MessageStore) -> None:
    # The re-ingress idempotency key binds to (origin, "@reingress:<channel>") — disjoint from a
    # resend-to-alternate's (message_id, <outbound>) — so a resend and a reingress can share the ledger
    # without a target collision.
    origin = await _seed(store)
    out = await store.reingress(origin_message_id=origin, raw=EDITED, idempotency_key="k1")
    async with store._read() as db:
        cur = await db.execute("SELECT to_destination FROM resend_log WHERE resend_key=?", ("k1",))
        row = await cur.fetchone()
    assert row is not None
    assert row["to_destination"] == f"{REINGRESS_TARGET_PREFIX}in1"
    assert out.new_message_id != ""


# --- store: DIRECT edited-body path (resend_to body_override) -----------------


async def test_direct_edit_ships_edited_body_to_a_correlated_child(store: MessageStore) -> None:
    # ADR 0090 §9.1.3 (review #153-1/#153-2): the DIRECT path delivers the EDITED body as a NEW,
    # correlated CHILD; the ORIGIN is only READ (its disposition + error stay byte-identical), and the
    # edited outbound row hangs off the child, NEVER the origin (the finalizer would otherwise flip the
    # origin ERROR->PROCESSED). Seed the origin in a terminal ERROR state — the marquee "divert a
    # permanently-failed delivery to a standby" scenario the finding's failure case describes.
    origin = await _seed(store)
    await _seed_error(store, origin, "connection refused: partner down")
    before = await store.get_message(origin)
    assert before is not None

    out = await store.resend_to(
        message_id=origin, to="OB2", idempotency_key="k1", body_override=EDITED
    )
    assert out.status == "resent" and out.to_destination == "OB2"
    assert out.message_id == origin  # the outcome names the ORIGIN the operator acted on

    # The ORIGINAL row is byte-identical — raw + status + ERROR text + metadata all preserved (the
    # #153 "the original must NOT change" invariant; the pre-fix code cleared error + flipped ROUTED).
    after = await store.get_message(origin)
    assert after is not None
    assert after["raw"] == before["raw"] == ADT
    assert after["status"] == before["status"] == MessageStatus.ERROR.value
    assert after["error"] == before["error"] == "connection refused: partner down"
    assert after["metadata"] == before["metadata"]
    # The origin's OWN outbox is untouched: only its original OB1 delivery, never the edited OB2.
    origin_payloads = {
        p["destination_name"]: p["payload"] for p in await store.outbox_payloads_for(origin)
    }
    assert origin_payloads == {"OB1": TRANSFORMED}

    # The edited OB2 delivery hangs off a NEW correlated child (located via the outbox row it created).
    ob2 = await _outbound_rows(store, "OB2")
    assert len(ob2) == 1 and ob2[0]["id"] == out.outbox_id
    child_id = ob2[0]["message_id"]
    assert child_id != origin
    child = await store.get_message(child_id)
    assert child is not None
    assert child["raw"] == EDITED  # the child carries the EDITED body
    assert (
        child["status"] == MessageStatus.ROUTED.value
    )  # delivery in flight; finalizer resolves it
    meta = json.loads(child["metadata"])
    assert meta["correlation_id"] == origin and meta["edited_from"] == origin
    child_payloads = {
        p["destination_name"]: p["payload"] for p in await store.outbox_payloads_for(child_id)
    }
    assert child_payloads == {"OB2": EDITED}


async def test_direct_edit_empty_body_is_rejected(store: MessageStore) -> None:
    origin = await _seed(store)
    with pytest.raises(ResendSourceEmpty):
        await store.resend_to(message_id=origin, to="OB2", idempotency_key="k1", body_override="")
    # no partial mutation: no OB2 row was created anywhere (origin or a child)
    assert await _outbound_rows(store, "OB2") == []


async def test_direct_edit_is_idempotent(store: MessageStore) -> None:
    origin = await _seed(store)
    first = await store.resend_to(
        message_id=origin, to="OB2", idempotency_key="k1", body_override=EDITED
    )
    second = await store.resend_to(
        message_id=origin, to="OB2", idempotency_key="k1", body_override=EDITED
    )
    assert first.status == "resent" and second.status == "duplicate"
    # exactly ONE OB2 delivery total (on the single child), never a second child/send on retry
    ob2 = await _outbound_rows(store, "OB2")
    assert len(ob2) == 1 and ob2[0]["id"] == first.outbox_id
    # and exactly ONE correlated child message was minted
    children = [
        r
        for r in await store.list_messages(limit=100)
        if r["id"] != origin and r["channel_id"] == "in1"
    ]
    assert len(children) == 1


# --- API: endpoint (psutil-gated; CI runs the API leg) -----------------------

ROUTER = "r"


def _registry(tmp_path: Path) -> Registry:
    for d in ("in", "o1", "o2"):
        (tmp_path / d).mkdir(exist_ok=True)
    reg = Registry()
    reg.add_inbound(
        InboundConnection(
            "in1",
            ConnectionSpec(
                ConnectorType.FILE,
                {"directory": str(tmp_path / "in"), "pattern": "*.hl7", "poll_seconds": 0.05},
            ),
            router=ROUTER,
        )
    )
    reg.add_outbound(
        OutboundConnection(
            "OB1", ConnectionSpec(ConnectorType.FILE, {"directory": str(tmp_path / "o1")})
        )
    )
    reg.add_outbound(
        OutboundConnection(
            "OB2", ConnectionSpec(ConnectorType.FILE, {"directory": str(tmp_path / "o2")})
        )
    )
    reg.add_router(ROUTER, lambda m: ["h"])
    reg.add_handler("h", lambda m: Send("OB1", m))
    return reg


async def test_edit_resend_reroute_endpoint_resubmits_and_audits(tmp_path: Path) -> None:
    pytest.importorskip("psutil")
    from messagefoundry.api import create_app

    engine = await Engine.create(tmp_path / "api.db", poll_interval=0.02)
    engine.add_registry(_registry(tmp_path))
    await engine.start()
    try:
        mid = await engine.store.enqueue_message(
            channel_id="in1", raw=ADT, deliveries=[("OB1", TRANSFORMED)], source_type="file"
        )
        transport = httpx.ASGITransport(app=create_app(engine, allow_no_auth=True))
        async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
            r = await c.post(
                f"/messages/{mid}/edit-resend",
                json={"raw": EDITED, "idempotency_key": "k1"},
            )
            assert r.status_code == 200, r.text
            body = r.json()
            assert body["status"] == "resubmitted" and body["reroute"] is True
            new_mid = body["new_message_id"]
            assert new_mid and new_mid != mid
            # retry same key -> duplicate, no second child
            again = await c.post(
                f"/messages/{mid}/edit-resend", json={"raw": EDITED, "idempotency_key": "k1"}
            )
            assert again.status_code == 200 and again.json()["status"] == "duplicate"
            assert again.json()["new_message_id"] == new_mid
        # ORIGINAL byte-identical; child correlated
        orig = await engine.store.get_message(mid)
        assert orig is not None and orig["raw"] == ADT
        child = await engine.store.get_message(new_mid)
        assert child is not None and child["raw"] == EDITED
        assert json.loads(child["metadata"])["edited_from"] == mid
        # audited (original->new), NEVER the body
        rec = [a for a in await engine.store.list_audit() if a["action"] == "message_edit_resend"]
        assert len(rec) == 1
        detail = str(rec[0]["detail"] or "")
        assert '"mode": "reroute"' in detail and "PID|" not in detail and "DOE^JOHN" not in detail
    finally:
        await engine.stop()


async def test_edit_resend_direct_endpoint_delivers_edited_body(tmp_path: Path) -> None:
    pytest.importorskip("psutil")
    from messagefoundry.api import create_app

    engine = await Engine.create(tmp_path / "api.db", poll_interval=0.02)
    engine.add_registry(_registry(tmp_path))
    await engine.start()
    try:
        mid = await engine.store.enqueue_message(
            channel_id="in1", raw=ADT, deliveries=[("OB1", TRANSFORMED)], source_type="file"
        )
        transport = httpx.ASGITransport(app=create_app(engine, allow_no_auth=True))
        async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
            r = await c.post(
                f"/messages/{mid}/edit-resend",
                json={"raw": EDITED, "idempotency_key": "k1", "to": "OB2"},
            )
            assert r.status_code == 200, r.text
            body = r.json()
            assert body["status"] == "resent" and body["reroute"] is False and body["to"] == "OB2"
            outbox_id = body["outbox_id"]
        # The edited OB2 delivery hangs off a NEW correlated child, NOT the origin (§9.1.3).
        ob2 = await _outbound_rows(engine.store, "OB2")
        assert len(ob2) == 1 and ob2[0]["id"] == outbox_id
        child_id = ob2[0]["message_id"]
        assert child_id != mid
        child_payloads = {
            p["destination_name"]: p["payload"]
            for p in await engine.store.outbox_payloads_for(child_id)
        }
        assert child_payloads["OB2"] == EDITED  # the edited body was delivered on the child
        orig = await engine.store.get_message(mid)
        assert orig is not None and orig["raw"] == ADT  # ORIGINAL byte-identical
        origin_dests = {p["destination_name"] for p in await engine.store.outbox_payloads_for(mid)}
        assert origin_dests == {"OB1"}  # origin keeps its original delivery, gained NO edited OB2
        rec = [a for a in await engine.store.list_audit() if a["action"] == "message_edit_resend"]
        assert len(rec) == 1 and '"mode": "direct"' in str(rec[0]["detail"] or "")
    finally:
        await engine.stop()


async def test_edit_resend_malformed_body_422_does_not_echo_the_body(tmp_path: Path) -> None:
    # PHI-safe 422 (ADR 0090 §9): a request-validation failure must NOT echo the offending value (the
    # ``input``) — for a body-carrying route that would surface the edited PHI in the 4xx + any log. A
    # wrong-typed ``raw`` carrying a unique PHI marker stands in for a malformed body.
    pytest.importorskip("psutil")
    from messagefoundry.api import create_app

    engine = await Engine.create(tmp_path / "api.db", poll_interval=0.02)
    engine.add_registry(_registry(tmp_path))
    await engine.start()
    marker = "MRN9999SECRET"
    try:
        mid = await engine.store.enqueue_message(
            channel_id="in1", raw=ADT, deliveries=[("OB1", TRANSFORMED)], source_type="file"
        )
        transport = httpx.ASGITransport(app=create_app(engine, allow_no_auth=True))
        async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
            r = await c.post(
                f"/messages/{mid}/edit-resend",
                json={"raw": {"leak": marker}, "idempotency_key": "k1"},
            )
            assert r.status_code == 422
            assert marker not in r.text  # the offending value is stripped from the 422
    finally:
        await engine.stop()
