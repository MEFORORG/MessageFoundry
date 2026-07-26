# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""ADR 0016 — synchronous X12 request/response (real-time eligibility 270/271, TA1 classification).

Covers the TA1 classification matrix (TA1*A/E/R, business-response-instead-of-TA1, unparseable, the
capturing-vs-non-capturing branch), a real-socket capture round-trip, byte-identical-when-off,
ta1_required, and the X12 wiring-validation arm.
"""

from __future__ import annotations

import logging
import os
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import pytest

import messagefoundry.parsing.x12.message as x12_message_mod
from messagefoundry.config.models import ConnectorType, ContentType, Destination, Source
from messagefoundry.config.wiring import (
    X12,
    Loopback,
    Registry,
    Rest,
    Soap,
    WiringError,
    build_inbound_connection,
    build_outbound_connection,
)
from messagefoundry.parsing.x12.peek import X12Peek
from messagefoundry.store import MessageStatus, MessageStore, OutboxStatus, Stage
from messagefoundry.transports import build_destination
from messagefoundry.transports.base import DeliveryError, DeliveryResponse, NegativeAckError
from messagefoundry.transports.x12 import X12Destination, X12Source


def _isa(*, control: str = "000000001") -> str:
    el = "*"
    segment = (
        "ISA"
        + el
        + "00"
        + el
        + " " * 10
        + el
        + "00"
        + el
        + " " * 10
        + el
        + "ZZ"
        + el
        + "SENDERID".ljust(15)
        + el
        + "ZZ"
        + el
        + "RECEIVERID".ljust(15)
        + el
        + "240101"
        + el
        + "1200"
        + el
        + "^"
        + el
        + "00501"
        + el
        + control
        + el
        + "0"
        + el
        + "P"
        + el
        + ":"
    )
    assert len(segment) == 105
    return segment + "~"


def _270() -> str:
    return (
        _isa()
        + "GS*HS*SAPP*RAPP*20240101*1200*1*X*005010X279A1~"
        + "ST*270*0001~BHT*0022*13*10001234*20240101*1200~HL*1**20*1~SE*4*0001~GE*1*1~"
        + "IEA*1*000000001~"
    )


def _271() -> bytes:
    return (
        _isa()
        + "GS*HB*SAPP*RAPP*20240101*1200*1*X*005010X279A1~"
        + "ST*271*0001~BHT*0022*11*10001234*20240101*1200~SE*3*0001~GE*1*1~"
        + "IEA*1*000000001~"
    ).encode()


def _ta1(code: str) -> bytes:
    """A TA1-only interchange with TA1-04 = ``code`` (A/E/R)."""
    return (_isa() + f"TA1*000000001*240101*1200*{code}*000~" + "IEA*1*000000001~").encode()


EDI = _270()


def _dest(port: int = 9, **settings: object) -> X12Destination:
    base: dict[str, object] = {"host": "127.0.0.1", "port": port, "timeout_seconds": 5}
    base.update(settings)
    return X12Destination(Destination(name="out", type=ConnectorType.X12, settings=base))


def _source() -> X12Source:
    return X12Source(Source(type=ConnectorType.X12, settings={"host": "127.0.0.1", "port": 0}))


# --- TA1 classification matrix (direct _check_ta1 unit tests) ----------------


def test_ta1_accepted_capturing() -> None:
    r = _dest(capture_response=True)._check_ta1(_ta1("A"))
    assert isinstance(r, DeliveryResponse) and r.outcome == "accepted" and r.detail == "TA1*A"


def test_ta1_accepted_non_capturing_returns_none() -> None:
    assert _dest(capture_response=False)._check_ta1(_ta1("A")) is None


def test_ta1_reject_is_permanent_both_modes() -> None:
    for capturing in (True, False):
        with pytest.raises(NegativeAckError) as ei:
            _dest(capture_response=capturing)._check_ta1(_ta1("R"))
        assert ei.value.permanent is True and ei.value.code == "AR"


def test_ta1_error_is_accepted_with_warning_not_retried() -> None:
    # Resolved decision (ADR 0016): TA1*E = accepted-with-warning, NOT a retry (the interchange WAS
    # accepted). Capturing → accepted reply; non-capturing → None. Never a NegativeAckError.
    r = _dest(capture_response=True)._check_ta1(_ta1("E"))
    assert isinstance(r, DeliveryResponse) and r.outcome == "accepted"
    assert "E" in (r.detail or "")
    assert _dest(capture_response=False)._check_ta1(_ta1("E")) is None


def test_business_response_instead_of_ta1_is_accepted() -> None:
    r = _dest(capture_response=True)._check_ta1(_271())
    assert isinstance(r, DeliveryResponse) and r.outcome == "accepted"
    assert "271" in r.body  # the application response is carried back for re-ingress


def test_unparseable_reply_capturing_vs_not() -> None:
    r = _dest(capture_response=True)._check_ta1(b"NOT-AN-INTERCHANGE~")
    assert isinstance(r, DeliveryResponse) and r.outcome == "unparseable"
    with pytest.raises(DeliveryError):  # non-capturing: a retryable transport error
        _dest(capture_response=False)._check_ta1(b"NOT-AN-INTERCHANGE~")


# --- real-socket integration -------------------------------------------------


async def _round_trip(reply: bytes | None, **dest_kw: object) -> DeliveryResponse | None:
    async def handler(raw: bytes) -> str | None:
        return reply.decode() if reply is not None else None

    source = _source()
    await source.start(handler)
    try:
        return await _dest(source.sockport, **dest_kw).send(EDI)
    finally:
        await source.stop()


async def test_capture_271_round_trip() -> None:
    resp = await _round_trip(_271(), capture_response=True)
    assert resp is not None and resp.outcome == "accepted" and "ST*271" in resp.body


async def test_send_returns_none_when_not_capturing() -> None:
    # Byte-identical when off: fire-and-forget returns None even though a reply is sent.
    assert await _round_trip(_271()) is None


async def test_ta1_required_reject_fails_fast() -> None:
    with pytest.raises(NegativeAckError) as ei:
        await _round_trip(_ta1("R"), ta1_required=True)
    assert ei.value.permanent is True


async def test_ta1_required_no_reply_retries() -> None:
    with pytest.raises(DeliveryError):
        await _round_trip(None, ta1_required=True, timeout_seconds=0.3)


# --- wiring validation (check / dry-run, no store) ---------------------------


def test_x12_capture_requires_expect_reply() -> None:
    with pytest.raises(WiringError, match="expect_reply"):
        build_outbound_connection("OB", X12(host="h", port=5, capture_response=True))


def test_x12_reingress_forces_capture_still_requires_expect_reply() -> None:
    with pytest.raises(WiringError, match="expect_reply"):
        build_outbound_connection("OB", X12(host="h", port=5, reingress_to="IB_LOOP"))


def test_x12_capture_with_expect_reply_ok() -> None:
    oc = build_outbound_connection(
        "OB", X12(host="h", port=5, capture_response=True, expect_reply=True)
    )
    assert oc.spec.settings["capture_response"] is True


def test_x12_reingress_with_expect_reply_forces_capture() -> None:
    oc = build_outbound_connection(
        "OB", X12(host="h", port=5, reingress_to="IB_LOOP", expect_reply=True)
    )
    assert oc.spec.settings["capture_response"] is True  # forced by reingress_to (ADR 0013)


# --- codec purity ------------------------------------------------------------


def test_x12_codec_stays_pure() -> None:
    # ADR 0016: _check_ta1 lives in transports/x12.py and uses the existing X12Message API; the codec
    # gains nothing and imports no engine module (parsing/ purity carve-out, CLAUDE.md §4).
    src = Path(x12_message_mod.__file__).read_text(encoding="utf-8")
    for banned in ("messagefoundry.transports", "messagefoundry.pipeline", "messagefoundry.store"):
        assert banned not in src


# --- X12-16: TA1 classifier PHI-in-log guard + the both-present TA1+271 rule --------------------
#
# _check_ta1 is a transport-level retry gate that MUST NOT leak the interchange body (PHI) into a log
# line or an exception message — only the non-PHI control identifiers (TA1-04 + ISA-13). These build a
# single interchange whose first functional segment is a TA1 followed by a co-present 271 carrying a
# PHI-shaped subscriber name, so "the body is excluded" is a real assertion, not vacuous.

_PHI_TOKEN = "SUBSCRIBERPHI"  # a distinctive marker for a name that must never reach a log/exc line


def _ta1_with_271_phi(code: str) -> bytes:
    """A single interchange: ISA, then a TA1*``code`` (the first functional segment), then a co-present
    271 whose NM1 carries a PHI-shaped subscriber name. Models a partner that returns a TA1 ack ahead of
    the business response in one interchange — the classifier must treat it as the TA1 (first wins)."""
    return (
        _isa()
        + f"TA1*000000001*240101*1200*{code}*000~"
        + "GS*HB*SAPP*RAPP*20240101*1200*1*X*005010X279A1~"
        + "ST*271*0001~BHT*0022*11*10001234*20240101*1200~"
        + f"NM1*IL*1*{_PHI_TOKEN}*JANE~"
        + "SE*4*0001~GE*1*1~IEA*1*000000001~"
    ).encode()


def test_ta1_present_with_271_classifies_as_ta1_not_business_response() -> None:
    # The first functional segment wins: a TA1*A ahead of a 271 in one interchange is the interchange
    # ACK (detail "TA1*A"), NOT a "business response". The whole interchange still rides re-ingress.
    r = _dest(capture_response=True)._check_ta1(_ta1_with_271_phi("A"))
    assert isinstance(r, DeliveryResponse) and r.outcome == "accepted"
    assert r.detail == "TA1*A"  # classified as the TA1 ack, not the co-present 271
    assert (
        "ST*271" in r.body
    )  # ...yet the full reply (incl. the 271) is carried back for re-ingress


def test_ta1_reject_message_carries_only_control_ids_not_body() -> None:
    # A TA1*R reject is a permanent NAK; its message names ONLY TA1-04 + ISA-13, never the co-present
    # 271's PHI (count-and-log: operators reconcile from the control id + disposition, not a leaked body).
    with pytest.raises(NegativeAckError) as ei:
        _dest(capture_response=True)._check_ta1(_ta1_with_271_phi("R"))
    text = str(ei.value)
    assert "TA1-04=R" in text and "ISA-13=000000001" in text
    assert ei.value.permanent is True and ei.value.code == "AR"
    assert _PHI_TOKEN not in text and "271" not in text and "NM1" not in text


def test_ta1_error_warning_carries_only_control_ids_not_body(
    caplog: pytest.LogCaptureFixture,
) -> None:
    # TA1*E (accepted-with-errors) emits an operator warning; it must name ONLY TA1-04 + ISA-13, never
    # the co-present 271 body. caplog proves the emitted record excludes the segment/PHI content.
    with caplog.at_level(logging.WARNING, logger="messagefoundry.transports.x12"):
        r = _dest(capture_response=True)._check_ta1(_ta1_with_271_phi("E"))
    assert isinstance(r, DeliveryResponse) and r.outcome == "accepted"
    warnings = [rec for rec in caplog.records if rec.levelno == logging.WARNING]
    assert warnings, "TA1*E must emit an operator warning"
    for rec in warnings:
        msg = rec.getMessage()
        assert "TA1-04=E" in msg and "ISA-13=000000001" in msg
        assert _PHI_TOKEN not in msg and "271" not in msg and "NM1" not in msg


def test_unparseable_reply_detail_is_safe_exc_scrubbed() -> None:
    # #120: a captured unparseable reply records outcome='unparseable' with a safe_exc-scrubbed detail.
    # safe_exc renders "<ExcType>: <redacted msg>", so the exception TYPE survives while a malformed
    # reply's content is redacted — the type prefix is proof the detail is routed through safe_exc (the
    # non-capturing path uses a raw {exc} render, which would NOT carry the type name).
    r = _dest(capture_response=True)._check_ta1(b"NOT-AN-INTERCHANGE~")
    assert isinstance(r, DeliveryResponse) and r.outcome == "unparseable"
    assert r.detail is not None and r.detail.startswith("unparseable X12 reply: ")
    assert "X12PeekError" in r.detail  # safe_exc's "<type>: <msg>" signature — the scrub ran


# --- X12-18: RTE end-to-end composition (capture -> RESPONSE stage -> re-ingress) ----------------
#
# The ADR-0016/0013 loop through the store: a captured reply becomes one immutable `response` artifact +
# a Stage.RESPONSE work-row on the loopback lane; the RegistryRunner's response worker re-ingresses it
# into a content_type=x12 Loopback where a pure Router peeks it with the parsing/x12 codec. Exercised
# over all three carriers an RTE partner can use (raw-TCP X12, X12-over-REST bare body, X12-over-SOAP
# envelope), plus the crash-window response_seq append and the SOAP-into-x12 contrapositive.


@pytest.fixture
async def store(tmp_path: Any) -> Any:
    s = await MessageStore.open(tmp_path / "x12rte.db")
    yield s
    await s.close()


_SQLSERVER_ON = bool(os.getenv("MEFOR_TEST_SQLSERVER"))
_POSTGRES_ON = bool(os.getenv("MEFOR_TEST_POSTGRES"))


# --- the RTE loop's store, on EVERY production backend (mirrors test_stage_dispatcher.py) ---------
#
# ADR 0013 capture + PT re-ingress are STORE capabilities, and SQL Server / Postgres both declare
# supports_response_capture + supports_pt_reingress True — so the connector->runner loop that rides
# them must be proven on the real backends, not only on SQLite. The module's `store` fixture above
# stays SQLite-only: a sibling test reaches into `_db` to model the crash window (aiosqlite-specific).


async def _open_rte_sqlite(tmp_path: Path) -> Any:
    return await MessageStore.open(tmp_path / "x12rte_be.db")


async def _open_rte_sqlserver(tmp_path: Path) -> Any:
    from messagefoundry.config.settings import load_settings
    from messagefoundry.store.sqlserver import SqlServerStore

    s = await SqlServerStore.open(load_settings(environ=os.environ).store)
    async with s._pool.acquire() as conn:  # clean slate — the container DB persists across a run
        cur = await conn.cursor()
        for table in (
            "message_events",
            "queue",
            "response",
            "delivered_keys",
            "outbox",
            "messages",
        ):
            await cur.execute(f"DELETE FROM {table}")
        await conn.commit()
    return s


async def _open_rte_postgres(tmp_path: Path) -> Any:
    from messagefoundry.config.settings import load_settings
    from messagefoundry.store.postgres import PostgresStore

    s = await PostgresStore.open(load_settings(environ=os.environ).store)
    async with s._pool.acquire() as conn:
        await conn.execute(
            "TRUNCATE message_events, queue, response, delivered_keys, messages"
            " RESTART IDENTITY CASCADE"
        )
    await s._load_state_cache()
    await s._load_reference_cache()
    return s


@pytest.fixture(params=["sqlite", "sqlserver", "postgres"])
async def rte_store(request: pytest.FixtureRequest, tmp_path: Path) -> AsyncIterator[Any]:
    backend = request.param
    if backend == "sqlserver" and not _SQLSERVER_ON:
        pytest.skip("set MEFOR_TEST_SQLSERVER=1 (+ MEFOR_STORE_* env) to run the SQL Server case")
    if backend == "postgres" and not _POSTGRES_ON:
        pytest.skip("set MEFOR_TEST_POSTGRES=1 (+ MEFOR_STORE_* env) to run the Postgres case")
    opener = {
        "sqlite": _open_rte_sqlite,
        "sqlserver": _open_rte_sqlserver,
        "postgres": _open_rte_postgres,
    }[backend]
    s = await opener(tmp_path)
    try:
        yield s
    finally:
        await s.close()


class _Resp:
    """A faked urllib response for the REST/SOAP openers (no socket) — mirrors test_soap_transport."""

    def __init__(self, status: int = 200, body: bytes = b"") -> None:
        self.status = status
        self._body = body
        self.headers = None

    def read(self) -> bytes:
        return self._body

    def __enter__(self) -> _Resp:
        return self

    def __exit__(self, *a: object) -> bool:
        return False


class _Opener:
    def __init__(self, resp: _Resp) -> None:
        self._resp = resp

    def open(self, req: object, timeout: float | None = None) -> _Resp:
        return self._resp


def _x12_loopback_registry(router_name: str, router: Any) -> Registry:
    """A Registry with one content_type=x12 Loopback inbound wired to ``router`` -> a filtering handler
    (the re-ingressed reply becomes FILTERED when routed OK, ERROR when the router raises)."""
    reg = Registry()
    reg.add_inbound(
        build_inbound_connection(
            "IB_LOOP", Loopback(), router=router_name, content_type=ContentType.X12
        )
    )
    reg.add_router(router_name, router)
    reg.add_handler("h_loop", lambda msg: None)  # filter -> FILTERED on a clean route
    return reg


async def _seed_captured_reply(
    store: MessageStore, *, dest: str, body: str, now: float = 100.0
) -> str:
    """Enqueue an origin request, deliver its one outbound row, and capture ``body`` as the reply with
    reingress_to=IB_LOOP — the exact state complete_with_response leaves after a captured RTE delivery.
    Returns the origin message id."""
    origin = await store.enqueue_message(
        channel_id="IB_RTE", raw="ISA-request", deliveries=[(dest, "ISA-request")], now=now
    )
    item = (await store.claim_ready(destination_name=dest, now=now))[0]
    await store.complete_with_response(
        item.id, body=body, outcome="accepted", reingress_to="IB_LOOP", now=now + 1
    )
    return origin


async def _drain_reingress(
    store: Any, reg: Registry, child_mid: str, target: str, *, timeout: float = 4.0
) -> Any:
    """Run a RegistryRunner over ``reg`` until the re-ingressed child reaches ``target`` status (or
    ``timeout`` elapses), then stop it and return the child message row."""
    import asyncio
    import time

    from messagefoundry.pipeline.wiring_runner import RegistryRunner

    runner = RegistryRunner(reg, store, poll_interval=0.02)
    await runner.start()
    try:
        # A WALL-CLOCK deadline, not a fixed iteration count: a server backend pays network
        # round-trips per poll, so N iterations is a SQLite-sized budget. A pass still exits on the
        # first match, so the SQLite callers below pay nothing for the wider ceiling.
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            await asyncio.sleep(0.02)
            child = await store.get_message(child_mid)
            if child is not None and child["status"] == target:
                break
    finally:
        await runner.stop()
    return await store.get_message(child_mid)


async def test_x12_rte_raw_tcp_271_capture_reingresses_and_routes(rte_store: Any) -> None:
    # The full RTE loop over raw-TCP X12: a real socket round-trip captures the 271 (a business response
    # returned instead of a TA1), complete_with_response persists it + a Stage.RESPONSE work-row, and the
    # response worker re-ingresses it into the x12 Loopback where the Router X12-peeks it. Origin
    # finalizes PROCESSED; the child carries the correlation and is the byte-identical captured 271.
    # Runs on EVERY production backend (`rte_store`): SQLite always, SQL Server / Postgres on the CI
    # server-DB legs — the connector->runner half of ADR 0013 the store-seam suites cannot reach.
    seen: dict[str, Any] = {}
    store = rte_store  # the module's `store` fixture is SQLite-only (a sibling reaches into `_db`)
    partner = _source()
    reply = _271()

    async def partner_handler(raw: bytes) -> str:
        return reply.decode()

    await partner.start(partner_handler)
    try:
        resp = await _dest(partner.sockport, capture_response=True).send(EDI)
        assert resp is not None and resp.outcome == "accepted" and "ST*271" in resp.body

        def route_271(msg: Any) -> list[str]:
            seen["txn"] = X12Peek.parse(msg.raw).transaction_ids()  # real codec peek on the 271
            return ["h_loop"]

        reg = _x12_loopback_registry("route_271", route_271)
        origin = await store.enqueue_message(
            channel_id="IB_RTE", raw=EDI, deliveries=[("OB_PAYER_RTE", EDI)], now=100.0
        )
        item = (await store.claim_ready(destination_name="OB_PAYER_RTE", now=100.0))[0]
        await store.complete_with_response(
            item.id, body=resp.body, outcome=resp.outcome, reingress_to="IB_LOOP", now=101.0
        )
        # A pure staticmethod — SqlServerStore/PostgresStore call it too but NEITHER SUBCLASSES
        # MessageStore, so it must be reached on the CLASS to survive the non-sqlite params.
        child_mid = MessageStore._reingress_message_id(origin, "OB_PAYER_RTE", 1, resp.body)

        child = await _drain_reingress(
            store, reg, child_mid, MessageStatus.FILTERED.value, timeout=20.0
        )
        assert child is not None and child["status"] == MessageStatus.FILTERED.value
        assert child["raw"] == resp.body  # the captured 271, re-ingressed verbatim
        import json

        assert json.loads(child["metadata"])["correlation_id"] == origin
        assert seen.get("txn") == ["271"]  # the Router peeked the re-ingressed reply as X12
        assert (await store.get_message(origin))["status"] == MessageStatus.PROCESSED.value
        assert await store.pending_depth("IB_LOOP", stage=Stage.RESPONSE.value) == (0, None)
    finally:
        await partner.stop()  # the rte_store fixture closes the store


async def test_x12_rte_crash_window_redelivery_appends_response_seq(store: MessageStore) -> None:
    # The residual at-least-once window (ADR 0013): a crash after the 271 is read but before
    # complete_with_response commits leaves the outbound row re-deliverable; a recovered re-delivery
    # captures the reply AGAIN, appending response_seq=N+1 (replay-stable immutable append — never a PK
    # collision). Each seq is a DISTINCT immutable artifact, so each yields a legitimately distinct
    # content-addressed re-ingress (a redelivery is never a lost or collided re-ingress).
    reply = _271().decode()
    origin = await store.enqueue_message(
        channel_id="IB_RTE", raw=EDI, deliveries=[("OB_PAYER_RTE", EDI)], now=100.0
    )
    item = (await store.claim_ready(destination_name="OB_PAYER_RTE", now=100.0))[0]
    await store.complete_with_response(
        item.id, body=reply, outcome="accepted", reingress_to="IB_LOOP", now=101.0
    )
    # Model the crash-window: the SAME row is recovered to pending and re-delivered (its ledger entry is
    # kept, so _record_delivered_key is a no-op — no double ledger row — while a 2nd reply is captured).
    await store._db.execute(
        "UPDATE queue SET status=? WHERE id=?", (OutboxStatus.PENDING.value, item.id)
    )
    await store._db.commit()
    again = (await store.claim_ready(destination_name="OB_PAYER_RTE", now=102.0))[0]
    await store.complete_with_response(
        again.id, body=reply, outcome="accepted", reingress_to="IB_LOOP", now=103.0
    )

    caps = await store.correlate_response(origin)
    assert [c.response_seq for c in caps] == [1, 2]  # N+1 immutable append, no collision
    # two Stage.RESPONSE work-rows (one per seq); their content-addressed child ids DIFFER by seq
    child1 = store._reingress_message_id(origin, "OB_PAYER_RTE", 1, reply)
    child2 = store._reingress_message_id(origin, "OB_PAYER_RTE", 2, reply)
    assert child1 != child2  # seq N+1 => a legitimately distinct re-ingress artifact
    assert (await store.pending_depth("IB_LOOP", stage=Stage.RESPONSE.value))[0] == 2


async def test_x12_over_rest_bare_body_reingresses_and_routes(store: MessageStore) -> None:
    # X12-over-REST bare-body composition: an RTE partner reachable over HTTP returns a BARE X12 271 as
    # the response body. The real RestDestination captures it; re-ingressed into the x12 Loopback, the
    # Router peeks it as X12 and routes it (FILTERED). Nothing X12-specific in the transport — the
    # interchange rides as the opaque HTTP body and is un-wrapped only by the codec at the Router.
    rest = build_destination(
        Destination(
            name="OB_REST_RTE",
            type=ConnectorType.REST,
            settings=Rest(url="http://127.0.0.1:9/eligibility", capture_response=True).settings,
        )
    )
    rest._opener = _Opener(_Resp(200, _271()))  # type: ignore[attr-defined]
    resp = await rest.send(EDI)
    assert resp is not None and resp.outcome == "accepted" and "ST*271" in resp.body

    def route_271(msg: Any) -> list[str]:
        return ["h_loop"] if "271" in X12Peek.parse(msg.raw).transaction_ids() else []

    reg = _x12_loopback_registry("route_271", route_271)
    origin = await _seed_captured_reply(store, dest="OB_REST_RTE", body=resp.body)
    child_mid = store._reingress_message_id(origin, "OB_REST_RTE", 1, resp.body)

    child = await _drain_reingress(store, reg, child_mid, MessageStatus.FILTERED.value)
    assert child is not None and child["status"] == MessageStatus.FILTERED.value
    assert child["raw"] == resp.body  # the bare 271 body, re-ingressed verbatim
    assert (await store.get_message(origin))["status"] == MessageStatus.PROCESSED.value


async def test_x12_over_soap_envelope_into_x12_loopback_errors_not_dropped(
    store: MessageStore,
) -> None:
    # X12-over-SOAP composition + the SOAP-into-x12 contrapositive: a SOAP RTE partner returns the reply
    # inside a SOAP envelope (NOT a bare interchange). The real SoapDestination captures the envelope;
    # re-ingressed into a content_type=x12 Loopback whose Router assumes an X12 interchange, the X12 peek
    # fails -> the child is ERROR (dead-lettered), NOT silently dropped (count-and-log). The un-wrap
    # contract's negative: a SOAP body must be un-wrapped to the embedded 271 before it can route as x12.
    envelope = (
        "<?xml version='1.0'?>"
        "<soap:Envelope xmlns:soap='http://www.w3.org/2003/05/soap-envelope'>"
        "<soap:Body><CORE271>eligibility</CORE271></soap:Body></soap:Envelope>"
    )
    soap = build_destination(
        Destination(
            name="OB_SOAP_RTE",
            type=ConnectorType.SOAP,
            settings=Soap(url="http://127.0.0.1:9/CORE", capture_response=True).settings,
        )
    )
    soap._opener = _Opener(_Resp(200, envelope.encode()))  # type: ignore[attr-defined]
    resp = await soap.send("<env/>")
    assert resp is not None and resp.outcome == "accepted" and "soap:Envelope" in resp.body

    def route_x12(msg: Any) -> list[str]:
        X12Peek.parse(
            msg.raw
        )  # a SOAP envelope has no ISA -> X12PeekError -> the child dead-letters
        return ["h_loop"]

    reg = _x12_loopback_registry("route_x12", route_x12)
    origin = await _seed_captured_reply(store, dest="OB_SOAP_RTE", body=resp.body)
    child_mid = store._reingress_message_id(origin, "OB_SOAP_RTE", 1, resp.body)

    child = await _drain_reingress(store, reg, child_mid, MessageStatus.ERROR.value)
    assert child is not None and child["status"] == MessageStatus.ERROR.value  # NOT dropped
    assert child["raw"] == resp.body  # the raw SOAP envelope is preserved for the operator
    # the origin's reply WAS handled (its Stage.RESPONSE token was consumed) -> PROCESSED
    assert (await store.get_message(origin))["status"] == MessageStatus.PROCESSED.value
    assert await store.pending_depth("IB_LOOP", stage=Stage.RESPONSE.value) == (0, None)
