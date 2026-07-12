# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Resend a stored message to an ALTERNATE outbound connection (ADR 0090, BACKLOG #123).

The SQLite invariant matrix for ``store.resend_to`` + the API ``POST /messages/{id}/resend``:
tail placement on the origin message, at-least-once (a real new outbound row), idempotency (same key
-> same row; new key -> a second resend), the retention-nulled-source 409, shared-body deref, the
ambiguous/missing-source rejects, the ROUTED re-open (finalizer stays terminal-authority), and the
RBAC / step-up / cross-channel + audit-has-no-body guards. Postgres/SQL Server parity is CI's job."""

from __future__ import annotations

from collections.abc import AsyncIterator
from pathlib import Path

import httpx
import pytest

from messagefoundry.auth import Role
from messagefoundry.auth.service import AuthService
from messagefoundry.config.models import ConnectorType, RetryPolicy
from messagefoundry.config.settings import AuthSettings
from messagefoundry.config.wiring import (
    ConnectionSpec,
    InboundConnection,
    OutboundConnection,
    Registry,
    Send,
)
from messagefoundry.pipeline import Engine
from messagefoundry.store import MessageStatus, OutboxStatus
from messagefoundry.store.base import (
    ResendKeyConflict,
    ResendSourceAmbiguous,
    ResendSourceEmpty,
    ResendSourceNotFound,
)
from messagefoundry.store.store import MessageStore

ADT = "MSH|^~\\&|S|F|R|RF|20260101||ADT^A01|MSG1|P|2.5.1\rPID|1||100^^^H^MR||DOE^JANE\r"
# A transformed outbound body, distinct from the raw, so a test can prove resend ships the TRANSFORMED
# (retained) body and that it decrypts at rest.
TRANSFORMED = "MSH|^~\\&|MEFOR|RF|R|RF|20260101||ADT^A01|MSG1|P|2.5.1\rPID|1||100^^^H^MR||DOE^JANE\rZXF|sent\r"


# --- store-level fixtures/helpers --------------------------------------------


@pytest.fixture
async def store(tmp_path: Path) -> AsyncIterator[MessageStore]:
    s = await MessageStore.open(tmp_path / "resend.db")
    try:
        yield s
    finally:
        await s.close()


async def _seed(
    store: MessageStore,
    *,
    channel: str = "in1",
    deliveries: list[tuple[str, str]] | None = None,
) -> str:
    return await store.enqueue_message(
        channel_id=channel,
        raw=ADT,
        deliveries=deliveries if deliveries is not None else [("OB1", TRANSFORMED)],
        control_id="MSG1",
        source_type="file",
    )


async def _deliver_all(store: MessageStore, mid: str) -> None:
    for r in await store.outbox_for(mid):
        await store.mark_done(r["id"])


async def _rows_to(store: MessageStore, mid: str, dest: str) -> list[dict[str, object]]:
    return [r for r in await store.outbox_for(mid) if r["destination_name"] == dest]


# --- store: tail placement + at-least-once -----------------------------------


async def test_resend_creates_pending_tail_row_on_origin(store: MessageStore) -> None:
    mid = await _seed(store)
    before = {r["id"] for r in await store.outbox_for(mid)}
    outcome = await store.resend_to(message_id=mid, to="OB2", idempotency_key="k1")
    assert outcome.status == "resent"
    assert outcome.to_destination == "OB2" and outcome.from_destination == "OB1"

    ob2 = await _rows_to(store, mid, "OB2")
    assert len(ob2) == 1
    new_row = ob2[0]
    assert new_row["id"] not in before  # a genuine NEW row (at-least-once), same message_id
    assert new_row["status"] == OutboxStatus.PENDING.value
    assert new_row["id"] == outcome.outbox_id
    # ships the retained TRANSFORMED body, decrypted at rest
    payloads = {p["destination_name"]: p["payload"] for p in await store.outbox_payloads_for(mid)}
    assert payloads["OB2"] == TRANSFORMED
    # TAIL: the resend row has the greatest rowid (seq) of the lane, so the FIFO claim orders it last.
    ids = [r["id"] for r in await store.outbox_for(mid)]
    seqs = {}
    async with store._read() as db:  # rowid IS the seq (ADR 0059)
        for i in ids:
            cur = await db.execute("SELECT rowid FROM queue WHERE id=?", (i,))
            seqs[i] = (await cur.fetchone())["rowid"]
    assert seqs[new_row["id"]] == max(seqs.values())


async def test_resend_reopens_processed_to_routed(store: MessageStore) -> None:
    # must-fix #4: the ROUTED write is the replay re-queue exception (finalizer stays terminal-authority).
    mid = await _seed(store)
    await _deliver_all(store, mid)
    msg = await store.get_message(mid)
    assert msg is not None and msg["status"] == MessageStatus.PROCESSED.value
    await store.resend_to(message_id=mid, to="OB2", idempotency_key="k1")
    msg = await store.get_message(mid)
    assert msg is not None and msg["status"] == MessageStatus.ROUTED.value
    # and the finalizer re-drives it PROCESSED once the resend row delivers
    ob2 = (await _rows_to(store, mid, "OB2"))[0]
    await store.mark_done(str(ob2["id"]))
    msg = await store.get_message(mid)
    assert msg is not None and msg["status"] == MessageStatus.PROCESSED.value


# --- store: idempotency ------------------------------------------------------


async def test_resend_same_key_is_duplicate_no_second_row(store: MessageStore) -> None:
    mid = await _seed(store)
    first = await store.resend_to(message_id=mid, to="OB2", idempotency_key="k1")
    second = await store.resend_to(message_id=mid, to="OB2", idempotency_key="k1")
    assert first.status == "resent" and second.status == "duplicate"
    assert second.outbox_id == first.outbox_id  # reports the prior outcome
    assert len(await _rows_to(store, mid, "OB2")) == 1  # exactly ONE row, never a double-send


async def test_resend_new_key_is_a_genuine_second_resend(store: MessageStore) -> None:
    mid = await _seed(store)
    # source=OB1 pins the copy to the original delivery (after the first resend the message also has an
    # OB2 row, so an unqualified source would be genuinely ambiguous — the caller names it).
    await store.resend_to(message_id=mid, to="OB2", idempotency_key="k1", from_="OB1")
    out2 = await store.resend_to(message_id=mid, to="OB2", idempotency_key="k2", from_="OB1")
    assert out2.status == "resent"
    assert len(await _rows_to(store, mid, "OB2")) == 2  # a new key IS a second resend


async def test_resend_key_reused_across_messages_is_a_conflict(store: MessageStore) -> None:
    # review #123-4: an idempotency key is bound to its (message_id, to) request. Reusing it for a
    # DIFFERENT message must NOT silently no-op (which would drop a legitimately-distinct resend and
    # report the unrelated first outcome) — it raises a conflict (the API maps it to 409).
    m1 = await _seed(store)
    m2 = await _seed(store)  # a distinct message (fresh uuid)
    first = await store.resend_to(message_id=m1, to="OB2", idempotency_key="k1")
    assert first.status == "resent"
    with pytest.raises(ResendKeyConflict):
        await store.resend_to(message_id=m2, to="OB2", idempotency_key="k1")
    assert await _rows_to(store, m2, "OB2") == []  # m2 was NOT silently dropped


async def test_resend_key_reused_for_different_target_is_a_conflict(store: MessageStore) -> None:
    # Same key, same message, but a DIFFERENT alternate target -> conflict (not an idempotent no-op).
    mid = await _seed(store)
    await store.resend_to(message_id=mid, to="OB2", idempotency_key="k1")
    with pytest.raises(ResendKeyConflict):
        await store.resend_to(message_id=mid, to="OB3", idempotency_key="k1")
    assert await _rows_to(store, mid, "OB3") == []
    # the genuine repeat (same message, same target, same key) is STILL an idempotent duplicate
    dup = await store.resend_to(message_id=mid, to="OB2", idempotency_key="k1")
    assert dup.status == "duplicate" and len(await _rows_to(store, mid, "OB2")) == 1


# --- store: retention + source resolution ------------------------------------


async def test_resend_retention_nulled_source_is_rejected(store: MessageStore) -> None:
    # must-fix #2: a retention-nulled source body must NOT be shipped as a zero-length PROCESSED body.
    mid = await _seed(store)
    await _deliver_all(store, mid)
    purged = await store.purge_message_bodies(older_than=9_999_999_999.0)
    assert purged == 1  # the delivered body is nulled in place
    with pytest.raises(ResendSourceEmpty):
        await store.resend_to(message_id=mid, to="OB2", idempotency_key="k1")
    # nothing was created and no partial mutation
    assert await _rows_to(store, mid, "OB2") == []


async def test_resend_no_delivered_body_is_not_found(store: MessageStore) -> None:
    mid = await store.record_received(
        channel_id="in1", raw=ADT, status=MessageStatus.ERROR, error="parse boom"
    )
    with pytest.raises(ResendSourceNotFound):
        await store.resend_to(message_id=mid, to="OB2", idempotency_key="k1")


async def test_resend_from_a_dead_source_is_allowed(store: MessageStore) -> None:
    # review #123-3 + ADR 0090 §1 marquee use case: divert a PERMANENTLY-FAILED (dead-lettered)
    # delivery to a standby. A dead source row still carries valid transformed bytes, so it is an
    # eligible source — NOT ResendSourceNotFound. `from` names the source lane, not a delivery claim.
    mid = await _seed(store)
    src = (await _rows_to(store, mid, "OB1"))[0]
    # exhaust retries on a never-claimed (attempts=0) row -> dead-letter it in place
    await store.mark_failed(str(src["id"]), "permanent AR", RetryPolicy(max_attempts=0))
    src_after = (await _rows_to(store, mid, "OB1"))[0]
    assert src_after["status"] == OutboxStatus.DEAD.value
    out = await store.resend_to(message_id=mid, to="OB2", idempotency_key="k1")
    assert out.status == "resent" and out.from_destination == "OB1"
    payloads = {p["destination_name"]: p["payload"] for p in await store.outbox_payloads_for(mid)}
    assert (
        payloads["OB2"] == TRANSFORMED
    )  # the dead lane's transformed bytes, shipped to the standby


async def test_resend_ambiguous_source_requires_from(store: MessageStore) -> None:
    b1, b3 = TRANSFORMED, TRANSFORMED.replace("sent", "other")
    mid = await _seed(store, deliveries=[("OB1", b1), ("OB3", b3)])
    with pytest.raises(ResendSourceAmbiguous):
        await store.resend_to(message_id=mid, to="OB2", idempotency_key="k1")
    # naming the source resolves it, and ships THAT source's body
    out = await store.resend_to(message_id=mid, to="OB2", idempotency_key="k2", from_="OB3")
    assert out.status == "resent" and out.from_destination == "OB3"
    payloads = {p["destination_name"]: p["payload"] for p in await store.outbox_payloads_for(mid)}
    assert payloads["OB2"] == b3


async def test_resend_derefs_a_shared_body(store: MessageStore) -> None:
    # A fanned-out identical body is stored ONCE in shared_body (body_ref set, inline payload ''). The
    # resend must DEREF it, not ship the '' sentinel (must-fix: deref the shared body).
    mid = await _seed(store, deliveries=[("OB1", TRANSFORMED), ("OB3", TRANSFORMED)])
    # confirm the source is genuinely a shared-body row (empty inline payload)
    async with store._read() as db:
        cur = await db.execute(
            "SELECT body_ref, payload FROM queue WHERE message_id=? AND destination_name=?",
            (mid, "OB1"),
        )
        src = await cur.fetchone()
    assert src["body_ref"] is not None and src["payload"] == ""
    out = await store.resend_to(message_id=mid, to="OB2", idempotency_key="k1", from_="OB1")
    assert out.status == "resent"
    payloads = {p["destination_name"]: p["payload"] for p in await store.outbox_payloads_for(mid)}
    assert payloads["OB2"] == TRANSFORMED  # non-empty, deref'd body


async def test_resend_event_carries_no_body(store: MessageStore) -> None:
    mid = await _seed(store)
    await store.resend_to(message_id=mid, to="OB2", idempotency_key="k1")
    details = [str(e["detail"] or "") for e in await store.events_for(mid)]
    assert any("resend OB1->OB2" in d for d in details)  # the resent event exists
    # never the body: no HL7 segment marker from the transformed payload leaks into an event detail
    assert all("ZXF|" not in d and "PID|" not in d for d in details)


# --- API: running-engine happy path + idempotency + audit --------------------


ROUTER = "r"


def _running_registry(tmp_path: Path) -> Registry:
    (tmp_path / "in").mkdir(exist_ok=True)
    (tmp_path / "o1").mkdir(exist_ok=True)
    (tmp_path / "o2").mkdir(exist_ok=True)
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


async def test_resend_endpoint_resent_then_duplicate_and_audited(tmp_path: Path) -> None:
    pytest.importorskip("psutil")  # the API pulls metrics -> psutil (an extra); skip if absent
    from messagefoundry.api import create_app

    engine = await Engine.create(tmp_path / "api.db", poll_interval=0.02)
    engine.add_registry(_running_registry(tmp_path))
    await engine.start()
    try:
        mid = await engine.store.enqueue_message(
            channel_id="in1", raw=ADT, deliveries=[("OB1", TRANSFORMED)], source_type="file"
        )
        transport = httpx.ASGITransport(app=create_app(engine, allow_no_auth=True))
        async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
            r = await c.post(
                f"/messages/{mid}/resend",
                json={"to": "OB2", "idempotency_key": "k1", "source": "OB1"},
            )
            assert r.status_code == 200, r.text
            assert r.json()["status"] == "resent" and r.json()["to"] == "OB2"
            # same key again -> duplicate, no new row
            again = await c.post(
                f"/messages/{mid}/resend",
                json={"to": "OB2", "idempotency_key": "k1", "source": "OB1"},
            )
            assert again.status_code == 200 and again.json()["status"] == "duplicate"
        # audited (from->to), and the body NEVER appears in the audit detail
        rec = [a for a in await engine.store.list_audit() if a["action"] == "message_resend"]
        assert len(rec) == 1
        detail = str(rec[0]["detail"] or "")
        assert '"to": "OB2"' in detail and "ZXF|" not in detail and "PID|" not in detail
    finally:
        await engine.stop()


async def test_resend_endpoint_unknown_target_and_not_running(tmp_path: Path) -> None:
    # A registered-but-not-running outbound -> 409; an unregistered one -> 404. (No engine.start().)
    pytest.importorskip("psutil")
    from messagefoundry.api import create_app

    engine = await Engine.create(tmp_path / "api.db", poll_interval=0.02)
    engine.add_registry(_running_registry(tmp_path))
    try:
        mid = await engine.store.enqueue_message(
            channel_id="in1", raw=ADT, deliveries=[("OB1", TRANSFORMED)], source_type="file"
        )
        transport = httpx.ASGITransport(app=create_app(engine, allow_no_auth=True))
        async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
            not_running = await c.post(
                f"/messages/{mid}/resend",
                json={"to": "OB2", "idempotency_key": "k1", "source": "OB1"},
            )
            assert not_running.status_code == 409  # registered but engine not running
            unknown = await c.post(
                f"/messages/{mid}/resend",
                json={"to": "NOPE", "idempotency_key": "k2", "source": "OB1"},
            )
            assert unknown.status_code == 404
            missing = await c.post(
                "/messages/nope/resend", json={"to": "OB2", "idempotency_key": "k3"}
            )
            assert missing.status_code == 404
    finally:
        await engine.stop()


async def test_resend_endpoint_retention_nulled_source_is_409(tmp_path: Path) -> None:
    pytest.importorskip("psutil")
    from messagefoundry.api import create_app

    engine = await Engine.create(tmp_path / "api.db", poll_interval=0.02)
    engine.add_registry(_running_registry(tmp_path))
    await engine.start()
    try:
        mid = await engine.store.enqueue_message(
            channel_id="in1", raw=ADT, deliveries=[("OB1", TRANSFORMED)], source_type="file"
        )
        # drive the OB1 row done, then purge its body
        for r in await engine.store.outbox_for(mid):
            await engine.store.mark_done(str(r["id"]))
        await engine.store.purge_message_bodies(older_than=9_999_999_999.0)
        transport = httpx.ASGITransport(app=create_app(engine, allow_no_auth=True))
        async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
            r = await c.post(
                f"/messages/{mid}/resend",
                json={"to": "OB2", "idempotency_key": "k1", "source": "OB1"},
            )
            assert r.status_code == 409
    finally:
        await engine.stop()


# --- API: RBAC / cross-channel authorization ---------------------------------


PW = "Sup3rSecret!!"


async def test_resend_requires_access_to_the_alternate_outbound_channel(tmp_path: Path) -> None:
    # A channel-scoped operator scoped to the ORIGIN channel but NOT the alternate outbound must be
    # refused (403) BEFORE any resend — PHI can't be pushed to a partner the caller can't reach.
    pytest.importorskip("psutil")
    from messagefoundry.api import create_app

    engine = await Engine.create(tmp_path / "rbac.db", poll_interval=0.02)
    try:
        service = AuthService(engine.store, AuthSettings(require_mfa=False))
        await service.initialize()
        uid = await service.create_local_user(
            username="op",
            password=PW,
            display_name=None,
            email=None,
            roles=[Role.OPERATOR.value],
            actor="test",
        )
        user = await service.store.get_user(uid)
        assert user is not None and user.password_hash is not None
        await service.store.set_password(
            uid, password_hash=user.password_hash, must_change_password=False
        )
        await service.set_channel_scope(uid, ["in1"], actor="admin")  # origin only, NOT OB2
        mid = await engine.store.enqueue_message(
            channel_id="in1", raw=ADT, deliveries=[("OB1", TRANSFORMED)], source_type="file"
        )
        transport = httpx.ASGITransport(app=create_app(engine, auth=service))
        async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
            login = await c.post(
                "/auth/login", json={"username": "op", "password": PW, "provider": "local"}
            )
            h = {"Authorization": f"Bearer {login.json()['token']}"}
            r = await c.post(
                f"/messages/{mid}/resend",
                json={"to": "OB2", "idempotency_key": "k1", "source": "OB1"},
                headers=h,
            )
            assert r.status_code == 403  # cross-channel target denied
            assert any(
                a["action"] == "auth.channel_denied" for a in await engine.store.list_audit()
            )
    finally:
        await engine.stop()


async def test_resend_denied_without_the_resend_permission(tmp_path: Path) -> None:
    # A VIEWER holds neither messages:resend nor a step-up path -> denied.
    pytest.importorskip("psutil")
    from messagefoundry.api import create_app

    engine = await Engine.create(tmp_path / "perm.db", poll_interval=0.02)
    try:
        service = AuthService(engine.store, AuthSettings(require_mfa=False))
        await service.initialize()
        uid = await service.create_local_user(
            username="v",
            password=PW,
            display_name=None,
            email=None,
            roles=[Role.VIEWER.value],
            actor="test",
        )
        user = await service.store.get_user(uid)
        assert user is not None and user.password_hash is not None
        await service.store.set_password(
            uid, password_hash=user.password_hash, must_change_password=False
        )
        mid = await engine.store.enqueue_message(
            channel_id="in1", raw=ADT, deliveries=[("OB1", TRANSFORMED)], source_type="file"
        )
        transport = httpx.ASGITransport(app=create_app(engine, auth=service))
        async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
            login = await c.post(
                "/auth/login", json={"username": "v", "password": PW, "provider": "local"}
            )
            h = {"Authorization": f"Bearer {login.json()['token']}"}
            r = await c.post(
                f"/messages/{mid}/resend",
                json={"to": "OB2", "idempotency_key": "k1", "source": "OB1"},
                headers=h,
            )
            assert r.status_code == 403
    finally:
        await engine.stop()


async def test_resend_grant_is_audited_even_when_it_fails_downstream(tmp_path: Path) -> None:
    # review #123-2: MESSAGES_RESEND is in _GRANT_AUDIT_PERMISSIONS, so an AUTHORIZED resend attempt
    # records the authorization grant at authz time regardless of the downstream outcome — here the
    # target is registered-but-not-running (409), yet the who-was-allowed trail must still exist
    # (parity with MESSAGES_REPLAY). Without the grant in the set this attempt would leave no trail.
    pytest.importorskip("psutil")
    from messagefoundry.api import create_app

    engine = await Engine.create(tmp_path / "grant.db", poll_interval=0.02)
    engine.add_registry(
        _running_registry(tmp_path)
    )  # registered but engine NOT started -> not running
    try:
        service = AuthService(engine.store, AuthSettings(require_mfa=False))
        await service.initialize()
        uid = await service.create_local_user(
            username="op",
            password=PW,
            display_name=None,
            email=None,
            roles=[Role.OPERATOR.value],
            actor="test",
        )
        user = await service.store.get_user(uid)
        assert user is not None and user.password_hash is not None
        await service.store.set_password(
            uid, password_hash=user.password_hash, must_change_password=False
        )
        await service.set_channel_scope(uid, ["in1", "OB2"], actor="admin")  # BOTH origin + target
        mid = await engine.store.enqueue_message(
            channel_id="in1", raw=ADT, deliveries=[("OB1", TRANSFORMED)], source_type="file"
        )
        transport = httpx.ASGITransport(app=create_app(engine, auth=service))
        async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
            login = await c.post(
                "/auth/login", json={"username": "op", "password": PW, "provider": "local"}
            )
            h = {"Authorization": f"Bearer {login.json()['token']}"}
            r = await c.post(
                f"/messages/{mid}/resend",
                json={"to": "OB2", "idempotency_key": "k1", "source": "OB1"},
                headers=h,
            )
            assert r.status_code == 409  # authorized, but the target isn't running
        grants = [
            a
            for a in await engine.store.list_audit()
            if a["action"] == "auth.permission_granted"
            and "messages:resend" in str(a["detail"] or "")
        ]
        assert len(grants) == 1  # the grant is audited even though the resend itself did not happen
    finally:
        await engine.stop()
