# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Request/response capture (ADR 0013 Increment 1).

Covers the store seam (the atomic ``complete_with_response`` XOR ``mark_done``, the immutable
``response`` artifact, finalizer-invisibility, ``response_seq`` replay-stability, retention), the
run-context ``response`` provider (transform-only, registration order, ``response_get``), the
per-transport capture semantics (MLLP ACK matrix + read/parse split, REST, SOAP, DATABASE), the
wiring-time validation, and the fail-closed runner-start capture-support gate.
"""

from __future__ import annotations

from typing import Any

import pytest

from messagefoundry.config.models import ConnectorType, Destination
from messagefoundry.config.response import activated, response_get
from messagefoundry.config.run_context import ROUTER, TRANSFORM, RunContext, run_contexts
from messagefoundry.config.wiring import (
    MLLP,
    ConnectionSpec,
    Database,
    Registry,
    Rest,
    Soap,
    WiringError,
    build_outbound_connection,
)
from messagefoundry.pipeline.wiring_runner import RegistryRunner
from messagefoundry.store import MessageStatus, MessageStore, OutboxStatus
from messagefoundry.transports import build_destination
from messagefoundry.transports.base import DeliveryError, DeliveryResponse, NegativeAckError
from messagefoundry.transports.mllp import MLLPDestination


@pytest.fixture
async def store(tmp_path: Any) -> Any:
    s = await MessageStore.open(tmp_path / "resp.db")
    yield s
    await s.close()


async def _enqueue_and_claim(store: MessageStore, *, dest: str = "OB_Q", now: float = 100.0) -> Any:
    """Enqueue one message→dest outbound row and claim it (→ inflight, attempts bumped), returning the
    (message_id, claimed OutboxItem)."""
    mid = await store.enqueue_message(
        channel_id="c1", raw="MSH|payload", deliveries=[(dest, "MSH|payload")], now=now
    )
    items = await store.claim_ready(destination_name=dest, now=now)
    assert len(items) == 1
    return mid, items[0]


async def _response_rows(store: MessageStore, message_id: str) -> list[dict[str, Any]]:
    cur = await store._db.execute(
        "SELECT * FROM response WHERE message_id=? ORDER BY response_seq", (message_id,)
    )
    return [dict(r) for r in await cur.fetchall()]


# --- store: the atomic capture + correlate -----------------------------------


async def test_complete_with_response_persists_and_marks_done(store: MessageStore) -> None:
    mid, item = await _enqueue_and_claim(store)
    await store.complete_with_response(
        item.id, body="MSA|AA|1", outcome="accepted", detail="MSA-1=AA", now=101.0
    )
    # The outbound row is DONE and the message finalized PROCESSED (the response table is invisible to
    # _maybe_finalize_message, which scans `queue` only).
    cur = await store._db.execute("SELECT status FROM queue WHERE id=?", (item.id,))
    assert (await cur.fetchone())["status"] == OutboxStatus.DONE.value
    msg = await store.get_message(mid)
    assert msg["status"] == MessageStatus.PROCESSED.value
    # correlate_response returns the decrypted reply.
    caps = await store.correlate_response(mid)
    assert len(caps) == 1
    c = caps[0]
    assert (c.destination_name, c.response_seq, c.outcome, c.detail, c.body) == (
        "OB_Q",
        1,
        "accepted",
        "MSA-1=AA",
        "MSA|AA|1",
    )


async def test_mark_done_writes_no_response_row_xor(store: MessageStore) -> None:
    mid, item = await _enqueue_and_claim(store)
    await store.mark_done(item.id, now=101.0)  # non-capturing delivery
    assert await store.correlate_response(mid) == []
    assert (await store.get_message(mid))["status"] == MessageStatus.PROCESSED.value


async def test_complete_with_response_writes_ledger_row_same_txn(store: MessageStore) -> None:
    # H2: complete_with_response writes the idempotency-ledger row in the SAME txn as the response
    # artifact + the DONE flip (hash + ids only; the reply body never lands in the ledger).
    mid, item = await _enqueue_and_claim(store)
    await store.complete_with_response(
        item.id, body="MSA|AA|secret", outcome="accepted", detail="MSA-1=AA", now=101.0
    )
    cur = await store._db.execute("SELECT * FROM delivered_keys WHERE outbox_id=?", (item.id,))
    rows = [dict(r) for r in await cur.fetchall()]
    assert len(rows) == 1
    assert rows[0]["message_id"] == mid and rows[0]["destination_name"] == "OB_Q"
    assert "MSA" not in str(rows[0].values()) and "secret" not in str(rows[0].values())


async def test_replay_resend_after_capture_appends_response_and_reseeds_ledger(
    store: MessageStore,
) -> None:
    # An operator re-send after a captured reply must actually re-deliver (NOT be deduped): replay
    # clears the ledger entry, the re-claimed row is delivered normally, a 2nd response is captured,
    # and a fresh ledger row is written for the re-delivery.
    mid, item = await _enqueue_and_claim(store)
    await store.complete_with_response(item.id, body="R1", outcome="accepted", now=101.0)
    requeued = await store.replay(mid, now=102.0)  # re-send → ledger entry dropped
    assert requeued == 1
    cur = await store._db.execute("SELECT COUNT(*) AS n FROM delivered_keys")
    assert (await cur.fetchone())["n"] == 0  # ledger cleared for the re-sent row (NOT deduped)
    again = await store.claim_next_fifo("OB_Q", now=103.0)
    assert again is not None and again.id == item.id  # claimed normally, not skip-and-completed
    await store.complete_with_response(again.id, body="R2", outcome="accepted", now=104.0)
    caps = await store.correlate_response(mid)
    assert [(c.response_seq, c.body) for c in caps] == [(1, "R1"), (2, "R2")]
    cur = await store._db.execute("SELECT COUNT(*) AS n FROM delivered_keys")
    assert (await cur.fetchone())["n"] == 1  # one fresh ledger row for the re-delivery


async def test_response_seq_is_replay_stable(store: MessageStore) -> None:
    # replay() resets queue.attempts=0, so an attempts-keyed artifact would collide on the next
    # delivery. response_seq is 1+MAX, so a replayed re-delivery appends seq=N+1 with no PK clash.
    mid, item = await _enqueue_and_claim(store)
    await store.complete_with_response(item.id, body="R1", outcome="accepted", now=101.0)
    assert item.attempts == 1
    requeued = await store.replay(mid, now=102.0)  # re-send (only done rows) → attempts reset to 0
    assert requeued == 1
    items2 = await store.claim_ready(destination_name="OB_Q", now=103.0)
    assert items2[0].attempts == 1  # same attempts value as the first delivery
    await store.complete_with_response(items2[0].id, body="R2", outcome="accepted", now=104.0)
    caps = await store.correlate_response(mid)
    assert [(c.response_seq, c.body) for c in caps] == [(1, "R1"), (2, "R2")]


async def test_retention_nulls_response_body_keeps_row(store: MessageStore) -> None:
    mid, item = await _enqueue_and_claim(store)
    await store.complete_with_response(
        item.id, body="secret-reply", outcome="accepted", detail="MSA-3=ok", now=101.0
    )
    purged = await store.purge_message_bodies(older_than=200.0, now=300.0)
    assert purged == 1  # the message body was purged
    caps = await store.correlate_response(mid)
    assert len(caps) == 1  # the response ROW is kept (count-and-log)
    assert caps[0].body is None and caps[0].detail is None  # body/detail nulled in place
    assert await store.get_message(mid) is not None  # FK to messages(id) never violated (row kept)


async def test_crash_between_send_and_commit_leaves_no_partial(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The residual at-least-once window (ADR 0013 §Testing strategy): a crash AFTER send() returns a
    # reply but BEFORE complete_with_response commits must leave the row INFLIGHT with NO partial
    # response row (the txn rolled back); recovery re-sends and commits EXACTLY ONE response.
    mid, item = await _enqueue_and_claim(store)
    real_commit = store._db.commit
    state = {"crashed": False}

    async def flaky_commit() -> None:
        if not state["crashed"]:  # fail the very first commit = complete_with_response's
            state["crashed"] = True
            raise RuntimeError("simulated crash before commit")
        await real_commit()

    monkeypatch.setattr(store._db, "commit", flaky_commit)
    with pytest.raises(RuntimeError):
        await store.complete_with_response(item.id, body="R1", outcome="accepted", now=101.0)
    # Rolled back: the row is still INFLIGHT and there is NO partial response row.
    cur = await store._db.execute("SELECT status FROM queue WHERE id=?", (item.id,))
    assert (await cur.fetchone())["status"] == OutboxStatus.INFLIGHT.value
    assert await store.correlate_response(mid) == []
    # Recovery: reset_stale_inflight → pending; re-claim; re-send commits exactly one response (seq=1).
    await store.reset_stale_inflight(now=102.0)
    items2 = await store.claim_ready(destination_name="OB_Q", now=103.0)
    await store.complete_with_response(items2[0].id, body="R2", outcome="accepted", now=104.0)
    caps = await store.correlate_response(mid)
    assert [(c.response_seq, c.body) for c in caps] == [(1, "R2")]  # exactly one committed capture
    assert (await store.get_message(mid))["status"] == MessageStatus.PROCESSED.value


async def test_response_body_encrypted_at_rest(tmp_path: Any) -> None:
    # With a cipher configured, the stored body is ciphertext, not the plaintext reply.
    from messagefoundry.store.crypto import generate_key, make_cipher

    s = await MessageStore.open(tmp_path / "enc.db", cipher=make_cipher(generate_key()))
    try:
        mid, item = await _enqueue_and_claim(s)
        await s.complete_with_response(item.id, body="PHI-REPLY", outcome="accepted", now=101.0)
        rows = await _response_rows(s, mid)
        assert "PHI-REPLY" not in (rows[0]["body"] or "")  # encrypted at rest
        assert (await s.correlate_response(mid))[0].body == "PHI-REPLY"  # decrypts on read
    finally:
        await s.close()


# --- run-context: the `response` provider ------------------------------------


def test_response_get_default_without_active_view() -> None:
    assert response_get("OB_Q") is None
    assert response_get("OB_Q", "fallback") == "fallback"


def test_response_get_resolves_active_view() -> None:
    with activated({"OB_Q": "the-reply"}):
        assert response_get("OB_Q") == "the-reply"
        assert response_get("OB_OTHER", "def") == "def"
    assert response_get("OB_Q") is None  # restored after the block


def test_response_provider_is_transform_only() -> None:
    ctx = RunContext(response_view={"OB_Q": "x"})
    with run_contexts(ctx, phase=ROUTER):
        assert response_get("OB_Q") is None  # not activated in the router phase
    with run_contexts(ctx, phase=TRANSFORM):
        assert response_get("OB_Q") == "x"  # activated in the transform phase


# --- transports: MLLP ACK matrix + read/parse split -------------------------


def _ack(code: str, msa3: str = "") -> bytes:
    return f"MSH|^~\\&|R|R|S|S|20240101||ACK|1|P|2.5\rMSA|{code}|1|{msa3}".encode()


def _mllp(capture: bool) -> MLLPDestination:
    settings = MLLP(host="h", port=1, capture_response=capture).settings
    d = build_destination(Destination(name="OB_M", type=ConnectorType.MLLP, settings=settings))
    assert isinstance(d, MLLPDestination)
    return d


def test_mllp_capture_accepts_positive_ack() -> None:
    r = _mllp(True)._check_ack(_ack("AA", "ok"))
    assert isinstance(r, DeliveryResponse)
    assert r.outcome == "accepted" and r.detail == "MSA-1=AA" and "MSA|AA" in r.body


def test_mllp_noncapture_returns_none_on_positive_ack() -> None:
    assert _mllp(False)._check_ack(_ack("AA")) is None


@pytest.mark.parametrize(
    "code,permanent", [("AR", True), ("CR", True), ("AE", False), ("CE", False)]
)
def test_mllp_negative_ack_still_raises_in_both_modes(code: str, permanent: bool) -> None:
    for capture in (
        True,
        False,
    ):  # a negative ACK is NOT captured — it routes through NegativeAckError
        with pytest.raises(NegativeAckError) as ei:
            _mllp(capture)._check_ack(_ack(code))
        assert ei.value.permanent is permanent


def test_mllp_unparseable_reply_capture_vs_retry() -> None:
    garbage = b"NOT-AN-HL7-FRAME"
    r = _mllp(True)._check_ack(garbage)  # a frame arrived but won't parse → captured 'unparseable'
    assert isinstance(r, DeliveryResponse) and r.outcome == "unparseable"
    with pytest.raises(DeliveryError):  # non-capturing keeps today's retryable DeliveryError
        _mllp(False)._check_ack(garbage)


async def test_mllp_read_failure_is_delivery_error_not_capture() -> None:
    # A failure to READ a reply frame (peer closed) is a delivery failure that retries — never captured,
    # even for a capturing outbound.
    class _EmptyReader:
        async def read(self, _n: int) -> bytes:
            return b""

    with pytest.raises(DeliveryError):
        await _mllp(True)._read_ack(_EmptyReader())


# --- transports: REST / SOAP / DATABASE capture (faked openers/cursors) ------


class _Resp:
    def __init__(self, body: bytes = b"", status: int = 200) -> None:
        self._body, self.status = body, status

    def read(self) -> bytes:
        return self._body

    def __enter__(self) -> "_Resp":
        return self

    def __exit__(self, *a: object) -> bool:
        return False


class _Opener:
    def __init__(self, resp: _Resp) -> None:
        self.resp = resp

    def open(self, req: object, timeout: float | None = None) -> _Resp:
        return self.resp


def _rest(capture: bool) -> Any:
    s = Rest(url="https://api.example.com/x", capture_response=capture).settings
    return build_destination(Destination(name="OB_R", type=ConnectorType.REST, settings=s))


async def test_rest_capture_2xx_body_and_empty() -> None:
    d = _rest(True)
    d._opener = _Opener(_Resp(b'{"id":7}', 201))  # type: ignore[assignment]
    r = await d.send("{}")
    assert (
        r is not None
        and r.outcome == "accepted"
        and r.body == '{"id":7}'
        and r.detail == "HTTP 201"
    )
    d._opener = _Opener(_Resp(b"", 204))  # type: ignore[assignment]
    r2 = await d.send("{}")
    assert r2 is not None and r2.outcome == "no_reply"


async def test_rest_noncapture_returns_none() -> None:
    d = _rest(False)
    d._opener = _Opener(_Resp(b"anything", 200))  # type: ignore[assignment]
    assert await d.send("{}") is None


_SOAP_FAULT = (
    '<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body>'
    "<soap:Fault><faultcode>soap:Client</faultcode><faultstring>bad</faultstring></soap:Fault>"
    "</soap:Body></soap:Envelope>"
)
_SOAP_OK = (
    '<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body>'
    "<Result>42</Result></soap:Body></soap:Envelope>"
)


def _soap(capture: bool) -> Any:
    s = Soap(url="https://api.example.com/svc", capture_response=capture).settings
    return build_destination(Destination(name="OB_S", type=ConnectorType.SOAP, settings=s))


async def test_soap_capture_clean_and_fault() -> None:
    d = _soap(True)
    d._opener = _Opener(_Resp(_SOAP_OK.encode(), 200))  # type: ignore[assignment]
    r = await d.send("<req/>")
    assert r is not None and r.outcome == "accepted" and "Result" in r.body
    # A 2xx <Fault> is CAPTURED as 'rejected' (not raised) for a capturing outbound.
    d._opener = _Opener(_Resp(_SOAP_FAULT.encode(), 200))  # type: ignore[assignment]
    r2 = await d.send("<req/>")
    assert r2 is not None and r2.outcome == "rejected"


async def test_soap_noncapture_fault_still_raises() -> None:
    d = _soap(False)
    d._opener = _Opener(_Resp(_SOAP_FAULT.encode(), 200))  # type: ignore[assignment]
    with pytest.raises((DeliveryError, NegativeAckError)):
        await d.send("<req/>")


def _db(capture: bool, statement: str = "INSERT INTO t VALUES (:x) RETURNING id") -> Any:
    s = Database(server="s", database="d", statement=statement, capture_response=capture).settings
    return build_destination(Destination(name="OB_D", type=ConnectorType.DATABASE, settings=s))


class _Cur:
    def __init__(
        self, rows: list[tuple[Any, ...]] | None, desc: list[tuple[Any, ...]] | None
    ) -> None:
        self._rows, self.description = rows, desc

    async def fetchall(self) -> list[tuple[Any, ...]]:
        if self._rows is None:
            raise RuntimeError("No results.  Previous SQL was not a query.")
        return self._rows


async def test_database_capture_result_set_caps_and_no_result() -> None:
    d = _db(True)
    r = await d._capture(_Cur([(7,)], [("id",)]))
    assert r.outcome == "accepted" and '"id": 7' in r.body
    # over the row cap → unparseable, empty body (never an unbounded blob)
    d._capture_max_rows = 1
    r2 = await d._capture(_Cur([(1,), (2,)], [("id",)]))
    assert r2.outcome == "unparseable" and r2.body == ""
    # a statement that produced no result set → no_reply (never raised — capture must not fail a write)
    r3 = await d._capture(_Cur(None, None))
    assert r3.outcome == "no_reply"


async def test_database_capture_unserializable_column_does_not_raise() -> None:
    # A column value _json_default can't encode must NOT propagate (that would roll back an
    # otherwise-successful write) — it degrades to outcome='unparseable' with an empty body.
    d = _db(True)

    class _Weird:
        pass

    r = await d._capture(_Cur([(_Weird(),)], [("col",)]))
    assert r.outcome == "unparseable" and r.body == ""


# --- wiring-time validation --------------------------------------------------


def test_wiring_accepts_capturing_outbounds() -> None:
    build_outbound_connection("OB_M", MLLP(host="h", port=1, capture_response=True))
    build_outbound_connection("OB_R", Rest(url="https://x/y", capture_response=True))
    build_outbound_connection(
        "OB_D",
        Database(
            server="s", database="d", statement="INSERT ... RETURNING id", capture_response=True
        ),
    )


@pytest.mark.parametrize(
    "spec",
    [
        ConnectionSpec(ConnectorType.FILE, {"directory": "d", "capture_response": True}),
        ConnectionSpec(ConnectorType.REMOTEFILE, {"remote_dir": "d", "capture_response": True}),
        ConnectionSpec(
            ConnectorType.TCP,
            {"host": "h", "port": 1, "capture_response": True, "expect_reply": False},
        ),
        ConnectionSpec(
            ConnectorType.DATABASE,
            {
                "server": "s",
                "database": "d",
                "statement": "INSERT INTO t VALUES (1)",
                "capture_response": True,
            },
        ),
    ],
)
def test_wiring_rejects_invalid_capture(spec: ConnectionSpec) -> None:
    with pytest.raises(WiringError):
        build_outbound_connection("OB", spec)


# --- runner-start fail-closed capture-support gate ---------------------------


async def test_runner_start_isolates_capture_on_unsupporting_backend(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Simulate a backend that can't persist captures (the SQL Server preview). The runner must not
    # deliver via a capturing outbound it can't capture for (ADR 0013 fail-closed lane), but per
    # ADR 0031 it ISOLATES that one lane instead of crashing the engine: start() succeeds, the lane is
    # reported failed (so rows routed to it retry, never silently dropped), and the engine runs.
    monkeypatch.setattr(store, "supports_response_capture", False, raising=False)
    reg = Registry()
    reg.add_outbound(
        build_outbound_connection("OB_Q", MLLP(host="h", port=1, capture_response=True))
    )
    runner = RegistryRunner(reg, store)
    try:
        await runner.start()  # does NOT raise — the capturing lane is isolated, not fatal
        assert runner.running
        reason = runner.connection_failed("OB_Q")
        assert reason and "capture" in reason
        assert "OB_Q" not in runner._destinations  # no live connector → routed rows retry, not drop
    finally:
        await runner.stop()


# --- API read surface: RBAC body-gating + audit ------------------------------


async def test_responses_route_rbac_and_audit(tmp_path: Any) -> None:
    import httpx

    from messagefoundry.api import create_app
    from messagefoundry.auth import Role
    from messagefoundry.auth.service import AuthService
    from messagefoundry.config.settings import AuthSettings
    from messagefoundry.pipeline import Engine

    pw = "a-strong-test-passphrase"
    engine = await Engine.create(tmp_path / "resp_api.db", poll_interval=0.02)
    try:
        service = AuthService(engine.store, AuthSettings())
        await service.initialize()
        for user, role in [("op", Role.OPERATOR), ("vw", Role.VIEWER), ("aud", Role.AUDITOR)]:
            uid = await service.create_local_user(
                username=user,
                password=pw,
                display_name=None,
                email=None,
                roles=[role.value],
                actor="test",
            )
            # Admin-created accounts force first-login rotation (WP-L3-12); clear it (keep the hash).
            u = await service.store.get_user(uid)
            assert u is not None and u.password_hash is not None
            await service.store.set_password(
                uid, password_hash=u.password_hash, must_change_password=False
            )
        # Seed a message with one captured reply.
        mid = await engine.store.enqueue_message(
            channel_id="ch1", raw="MSH|x", deliveries=[("OB_Q", "MSH|x")], message_type="ADT^A01"
        )
        items = await engine.store.claim_ready(destination_name="OB_Q")
        await engine.store.complete_with_response(
            items[0].id, body="MSA|AA", outcome="accepted", detail="MSA-1=AA"
        )

        transport = httpx.ASGITransport(app=create_app(engine, auth=service))
        async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:

            async def login(user: str) -> dict[str, str]:
                r = await c.post(
                    "/auth/login", json={"username": user, "password": pw, "provider": "local"}
                )
                return {"Authorization": f"Bearer {r.json()['token']}"}

            op, vw, aud = await login("op"), await login("vw"), await login("aud")

            # OPERATOR holds messages:view_raw → the PHI body is included.
            r = await c.get(f"/messages/{mid}/responses", headers=op)
            assert r.status_code == 200
            data = r.json()
            assert data["message_id"] == mid and len(data["responses"]) == 1
            got = data["responses"][0]
            assert (
                got["outcome"] == "accepted"
                and got["detail"] == "MSA-1=AA"
                and got["body"] == "MSA|AA"
            )

            # VIEWER holds messages:read but NOT view_summary/view_raw → outcome (non-PHI) yes, but
            # `detail` (which can embed a reply fragment) now gates on view_summary (#120) and the PHI
            # `body` on view_raw — both redacted to None.
            r2 = await c.get(f"/messages/{mid}/responses", headers=vw)
            assert r2.status_code == 200
            got2 = r2.json()["responses"][0]
            assert got2["outcome"] == "accepted" and got2["detail"] is None and got2["body"] is None

            # AUDITOR lacks messages:read → deny-by-default (403).
            assert (await c.get(f"/messages/{mid}/responses", headers=aud)).status_code == 403
            # Unknown id → 404 (don't reveal existence).
            assert (
                await c.get("/messages/does-not-exist/responses", headers=op)
            ).status_code == 404

        # Reading captured replies emits the response.read audit event.
        actions = [dict(a)["action"] for a in await engine.store.list_audit(limit=50)]
        assert "response.read" in actions
    finally:
        await engine.stop()
