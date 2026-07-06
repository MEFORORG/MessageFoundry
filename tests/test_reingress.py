# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Re-ingress orchestration (ADR 0013 Increment 2).

Built in the design's order; this file grows per build step. Step 1 pins the stage-model edits — the
new ``Stage.RESPONSE`` keys by ``channel_id`` in the FIFO/depth lanes, the stage-generic recovery +
finalizer primitives handle it with no change, and a pending response row legitimately holds the origin
message in flight.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from messagefoundry.config.models import AckMode, ConnectorType, ContentType, Source
from messagefoundry.config.settings import EgressSettings
from messagefoundry.config.wiring import (
    MLLP,
    ConnectionSpec,
    Loopback,
    Registry,
    WiringError,
    build_inbound_connection,
    build_outbound_connection,
)
from messagefoundry.pipeline.wiring_runner import build_check_registry
from messagefoundry.store import MessageStatus, MessageStore, OutboxStatus, Stage
from messagefoundry.transports.loopback import LoopbackSource


@pytest.fixture
async def store(tmp_path: Any) -> Any:
    s = await MessageStore.open(tmp_path / "reingress.db")
    yield s
    await s.close()


async def _seed_message(store: MessageStore, *, dest: str = "OB_X", now: float = 100.0) -> str:
    """A real message with one pending outbound row (gives the FK target for a response work-row)."""
    return await store.enqueue_message(
        channel_id="IB_REAL", raw="MSH|payload", deliveries=[(dest, "MSH|payload")], now=now
    )


async def _insert_response_row(
    store: MessageStore,
    *,
    message_id: str,
    loopback: str = "IB_LOOP",
    row_id: str = "resp-1",
    seq: int = 1,
    status: str = OutboxStatus.PENDING.value,
    now: float = 100.0,
) -> str:
    """Insert one Stage.RESPONSE work-row directly (Step 1 has no producer yet — that is Step 3). The
    payload is the encrypted artifact reference, exactly as complete_with_response will write it."""
    ref = store._enc(f"{message_id}\x1fOB_X\x1f{seq}")
    await store._db.execute(
        "INSERT INTO queue (id, message_id, stage, channel_id, destination_name, handler_name,"
        " payload, status, attempts, next_attempt_at, created_at, updated_at)"
        " VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
        (
            row_id,
            message_id,
            Stage.RESPONSE.value,
            loopback,
            None,
            None,
            ref,
            status,
            0,
            now,
            now,
            now,
        ),
    )
    await store._db.commit()
    return row_id


async def test_response_stage_lanes_by_channel_id(store: MessageStore) -> None:
    # A Stage.RESPONSE row has NULL destination_name and keys by channel_id (the loopback inbound),
    # exactly like ingress/routed — so claim_next_fifo / pending_depth find it by the loopback name.
    mid = await _seed_message(store)
    await _insert_response_row(store, message_id=mid, loopback="IB_LOOP", now=100.0)
    # depth keyed by channel_id
    assert await store.pending_depth("IB_LOOP", stage=Stage.RESPONSE.value) == (1, 100.0)
    # the lane is NOT keyed by destination_name (the row's is NULL) — a wrong key finds nothing
    assert await store.pending_depth("OB_X", stage=Stage.RESPONSE.value) == (0, None)
    # claim by the loopback channel_id → the row (now inflight, attempts bumped)
    item = await store.claim_next_fifo("IB_LOOP", now=101.0, stage=Stage.RESPONSE.value)
    assert item is not None and item.stage == Stage.RESPONSE.value and item.attempts == 1
    # the work-row's channel_id IS the loopback lane (the origin's own channel lives on the messages row)
    assert item.destination_name is None and item.channel_id == "IB_LOOP"
    assert item.message_id == mid  # but it groups under the ORIGIN message (FK + finalizer)


async def test_reset_stale_inflight_recovers_response(store: MessageStore) -> None:
    # The stage-generic crash-recovery sweep must return an inflight RESPONSE row to pending (no branch).
    mid = await _seed_message(store)
    await _insert_response_row(store, message_id=mid, now=100.0)
    claimed = await store.claim_next_fifo("IB_LOOP", now=101.0, stage=Stage.RESPONSE.value)
    assert claimed is not None  # now INFLIGHT
    recovered = await store.reset_stale_inflight(now=102.0)  # stage=None recovers EVERY stage
    assert recovered >= 1
    # claimable again after recovery
    again = await store.claim_next_fifo("IB_LOOP", now=103.0, stage=Stage.RESPONSE.value)
    assert again is not None and again.id == claimed.id


async def test_finalizer_sees_pending_response_row(store: MessageStore) -> None:
    # A pending Stage.RESPONSE row legitimately holds the ORIGIN message in flight: the answer still
    # owes a route. Once the row is gone (handed off), the origin finalizes PROCESSED.
    mid = await _seed_message(store)
    await _insert_response_row(store, message_id=mid, now=100.0)
    item = (await store.claim_ready(destination_name="OB_X", now=100.0))[0]
    await store.mark_done(item.id, now=101.0)  # outbound delivered, but the response row is pending
    assert (await store.get_message(mid))["status"] != MessageStatus.PROCESSED.value
    # consume the response row (simulating ingress_handoff) and finalize
    await store._db.execute(
        "DELETE FROM queue WHERE stage=? AND message_id=?", (Stage.RESPONSE.value, mid)
    )
    async with store._lock:
        await store._maybe_finalize_message(mid, 102.0)
        await store._db.commit()
    assert (await store.get_message(mid))["status"] == MessageStatus.PROCESSED.value


# --- Step 2: Loopback connector + reingress_to declaration surface + validation ---


def _check(reg: Registry) -> None:
    build_check_registry(reg, inbound_bind_host="127.0.0.1", env_values={}, egress=EgressSettings())


def test_loopback_inbound_builds_with_ack_none() -> None:
    ic = build_inbound_connection(
        "IB_LOOP", Loopback(), router="route_x", content_type=ContentType.HL7V2
    )
    assert ic.spec.type is ConnectorType.LOOPBACK
    assert ic.ack_mode is AckMode.NONE  # forced/defaulted to NONE (no external peer)


def test_loopback_rejects_strict_bind_and_nonnone_ack() -> None:
    with pytest.raises(WiringError, match="strict"):
        build_inbound_connection("IB", Loopback(), router="r", strict=True)
    with pytest.raises(WiringError, match="bind_address"):
        build_inbound_connection("IB", Loopback(), router="r", bind_address="0.0.0.0")
    with pytest.raises(WiringError, match="ack_mode must be NONE"):
        build_inbound_connection("IB", Loopback(), router="r", ack_mode=AckMode.ENHANCED)


def test_reingress_to_forces_capture_and_validates_string() -> None:
    oc = build_outbound_connection("OB", MLLP(host="h", port=1, reingress_to="IB_LOOP"))
    assert oc.spec.settings["capture_response"] is True  # reingress_to implies capture
    assert oc.spec.settings["reingress_to"] == "IB_LOOP"
    # empty/blank reingress_to is a wiring error
    with pytest.raises(WiringError, match="non-empty"):
        build_outbound_connection(
            "OB", ConnectionSpec(ConnectorType.MLLP, {"host": "h", "port": 1, "reingress_to": "  "})
        )
    # reingress_to on a no-response transport fails (forced capture → no synchronous response). Via raw
    # settings (the connections.toml shape) since File() has no reingress_to kwarg.
    with pytest.raises(WiringError, match="no synchronous response"):
        build_outbound_connection(
            "OB", ConnectionSpec(ConnectorType.FILE, {"directory": "d", "reingress_to": "IB_LOOP"})
        )


def test_cross_registry_reingress_to_must_name_a_loopback() -> None:
    # unknown target
    reg = Registry()
    reg.add_outbound(
        build_outbound_connection("OB_Q", MLLP(host="h", port=1, reingress_to="IB_LOOP"))
    )
    with pytest.raises(WiringError, match="unknown/non-loopback"):
        _check(reg)
    # target exists but is NOT a Loopback
    reg2 = Registry()
    reg2.add_inbound(build_inbound_connection("IB_LOOP", MLLP(port=2575), router="r"))
    reg2.add_outbound(
        build_outbound_connection("OB_Q", MLLP(host="h", port=1, reingress_to="IB_LOOP"))
    )
    with pytest.raises(WiringError, match="unknown/non-loopback"):
        _check(reg2)
    # valid: reingress_to → a real Loopback inbound
    reg3 = Registry()
    reg3.add_inbound(build_inbound_connection("IB_LOOP", Loopback(), router="r"))
    reg3.add_outbound(
        build_outbound_connection("OB_Q", MLLP(host="h", port=1, reingress_to="IB_LOOP"))
    )
    _check(reg3)  # no raise


def test_inert_loopback_logs_not_errors(caplog: pytest.LogCaptureFixture) -> None:
    import logging

    reg = Registry()
    reg.add_inbound(
        build_inbound_connection("IB_LOOP", Loopback(), router="r")
    )  # nothing points at it
    with caplog.at_level(logging.WARNING):
        _check(reg)  # legal, no raise
    assert any("no reingress_to source" in r.message for r in caplog.records)


async def test_loopback_source_never_invokes_handler() -> None:
    called: list[bytes] = []

    async def handler(b: bytes) -> None:
        called.append(b)
        return None

    src = LoopbackSource(Source(type=ConnectorType.LOOPBACK, settings={}))
    await src.start(handler)
    await src.stop()
    assert called == []  # re-ingress NEVER flows through the source/listener seam


# --- Step 3: work-row production (complete_with_response reingress_to) ---


async def _claim_outbound(store: MessageStore, *, dest: str = "OB_X", now: float = 100.0) -> Any:
    """Enqueue + claim one outbound row (the target of complete_with_response)."""
    mid = await store.enqueue_message(
        channel_id="IB_REAL", raw="MSH|payload", deliveries=[(dest, "MSH|payload")], now=now
    )
    item = (await store.claim_ready(destination_name=dest, now=now))[0]
    return mid, item


async def test_complete_with_response_reingress_produces_work_row(store: MessageStore) -> None:
    mid, item = await _claim_outbound(store)
    await store.complete_with_response(
        item.id, body="RSP^K11", outcome="accepted", reingress_to="IB_LOOP", now=101.0
    )
    # the immutable artifact is written (Increment 1 behavior, unchanged)
    caps = await store.correlate_response(mid)
    assert len(caps) == 1 and caps[0].body == "RSP^K11"
    # AND a drainable Stage.RESPONSE work-row on the loopback lane, referencing the artifact by PK
    work = await store.claim_next_fifo("IB_LOOP", now=102.0, stage=Stage.RESPONSE.value)
    assert work is not None
    assert work.message_id == mid and work.channel_id == "IB_LOOP" and work.destination_name is None
    assert work.payload == f"{mid}\x1fOB_X\x1f1"  # decrypted artifact ref (message_id, dest, seq)


async def test_complete_with_response_no_reingress_writes_no_work_row(store: MessageStore) -> None:
    # Byte-identical to Increment 1: a capturing delivery with no reingress_to writes the artifact and
    # NO Stage.RESPONSE work-row.
    mid, item = await _claim_outbound(store)
    await store.complete_with_response(item.id, body="ACK", outcome="accepted", now=101.0)
    assert len(await store.correlate_response(mid)) == 1
    assert await store.pending_depth("IB_LOOP", stage=Stage.RESPONSE.value) == (0, None)
    assert await store.claim_next_fifo("IB_LOOP", now=102.0, stage=Stage.RESPONSE.value) is None


async def test_reingress_work_row_holds_origin_then_releases(store: MessageStore) -> None:
    # The real path: complete_with_response(reingress_to=...) produces the work-row; the finalizer keeps
    # the origin out of PROCESSED until the work-row is consumed (the answer still owes a route).
    mid, item = await _claim_outbound(store)
    await store.complete_with_response(
        item.id, body="RSP", outcome="accepted", reingress_to="IB_LOOP", now=101.0
    )
    assert (await store.get_message(mid))["status"] != MessageStatus.PROCESSED.value
    # consume the work-row (Step 4's ingress_handoff does this atomically) and finalize
    await store._db.execute(
        "DELETE FROM queue WHERE stage=? AND message_id=?", (Stage.RESPONSE.value, mid)
    )
    async with store._lock:
        await store._maybe_finalize_message(mid, 103.0)
        await store._db.commit()
    assert (await store.get_message(mid))["status"] == MessageStatus.PROCESSED.value


# --- Step 4: ingress_handoff (the atomic re-ingress edge) ---


async def _seed_reingress(
    store: MessageStore, *, body: str = "RSP^K11", loopback: str = "IB_LOOP", now: float = 100.0
) -> Any:
    """Produce + claim a Stage.RESPONSE work-row (INFLIGHT) via the real path, ready for ingress_handoff.
    Returns (origin_message_id, claimed work-row)."""
    mid, item = await _claim_outbound(store, now=now)
    await store.complete_with_response(
        item.id, body=body, outcome="accepted", reingress_to=loopback, now=now + 1
    )
    work = await store.claim_next_fifo(loopback, now=now + 2, stage=Stage.RESPONSE.value)
    assert work is not None  # now INFLIGHT
    return mid, work


async def test_ingress_handoff_produces_child_and_finalizes_origin(store: MessageStore) -> None:
    origin, work = await _seed_reingress(store)
    ok = await store.ingress_handoff(
        response_row_id=work.id,
        loopback_channel_id="IB_LOOP",
        correlation_depth_cap=8,
        control_id="RSP1",
        message_type="RSP^K11",
        summary="elig result",
        now=110.0,
    )
    assert ok is True
    # the work-row is consumed; the origin finalizes PROCESSED (its last outstanding row is gone)
    assert await store.claim_next_fifo("IB_LOOP", now=111.0, stage=Stage.RESPONSE.value) is None
    assert (await store.get_message(origin))["status"] == MessageStatus.PROCESSED.value
    # a re-ingressed child message + one ingress queue row on the loopback lane
    assert (await store.pending_depth("IB_LOOP", stage=Stage.INGRESS.value))[0] == 1
    child_ing = await store.claim_next_fifo("IB_LOOP", now=112.0, stage=Stage.INGRESS.value)
    assert child_ing is not None
    child = await store.get_message(child_ing.message_id)
    assert child["status"] == MessageStatus.RECEIVED.value and child["raw"] == "RSP^K11"
    meta = json.loads(child["metadata"])
    assert meta["correlation_id"] == origin and meta["correlation_root_id"] == origin
    assert meta["correlation_depth"] == 1 and meta["reingress_of_seq"] == 1


async def test_ingress_handoff_is_idempotent_no_double_child(store: MessageStore) -> None:
    origin, work = await _seed_reingress(store)
    kw = dict(
        loopback_channel_id="IB_LOOP",
        correlation_depth_cap=8,
        control_id="C",
        message_type="RSP^K11",
        summary=None,
    )
    assert await store.ingress_handoff(response_row_id=work.id, now=110.0, **kw) is True
    # the token is gone → a second call is an idempotent no-op (no second child)
    assert await store.ingress_handoff(response_row_id=work.id, now=111.0, **kw) is False
    assert (await store.pending_depth("IB_LOOP", stage=Stage.INGRESS.value))[0] == 1


async def test_ingress_handoff_depth_cap_dead_letters_and_errors_origin(
    store: MessageStore,
) -> None:
    origin, work = await _seed_reingress(store)
    # cap=0 → child_depth=1 > 0 → breach: dead-letter the token, ERROR the origin, NO child.
    ok = await store.ingress_handoff(
        response_row_id=work.id,
        loopback_channel_id="IB_LOOP",
        correlation_depth_cap=0,
        control_id=None,
        message_type="x12",
        summary=None,
        now=110.0,
    )
    assert ok is True  # token consumed (must not re-loop)
    assert (await store.get_message(origin))["status"] == MessageStatus.ERROR.value
    assert (await store.pending_depth("IB_LOOP", stage=Stage.INGRESS.value)) == (0, None)
    # the work-row is DEAD, not re-claimable
    assert await store.claim_next_fifo("IB_LOOP", now=111.0, stage=Stage.RESPONSE.value) is None


async def test_ingress_handoff_peek_failed_errors_child_with_no_ingress_row(
    store: MessageStore,
) -> None:
    origin, work = await _seed_reingress(store, body="NOT-AN-HL7-BODY")
    ok = await store.ingress_handoff(
        response_row_id=work.id,
        loopback_channel_id="IB_LOOP",
        correlation_depth_cap=8,
        control_id=None,
        message_type=None,
        summary=None,
        peek_failed=True,
        now=110.0,
    )
    assert ok is True
    # the origin's reply was handled (token gone) → PROCESSED; the child is ERROR with NO ingress row
    assert (await store.get_message(origin))["status"] == MessageStatus.PROCESSED.value
    assert (await store.pending_depth("IB_LOOP", stage=Stage.INGRESS.value)) == (0, None)
    child_mid = store._reingress_message_id(origin, "OB_X", 1, "NOT-AN-HL7-BODY")
    child = await store.get_message(child_mid)
    assert child is not None and child["status"] == MessageStatus.ERROR.value


# --- Step 4: re-ingress worker end-to-end (reply -> re-ingress -> route) ---


async def test_response_worker_reingresses_and_routes_end_to_end(tmp_path: Any) -> None:
    import asyncio

    from messagefoundry.pipeline.wiring_runner import RegistryRunner

    store = await MessageStore.open(tmp_path / "rw.db")
    try:
        reg = Registry()
        reg.add_inbound(build_inbound_connection("IB_LOOP", Loopback(), router="route_loop"))
        reg.add_router("route_loop", lambda msg: ["h_loop"])
        reg.add_handler(
            "h_loop", lambda msg: None
        )  # filter → the re-ingressed child becomes FILTERED

        # Seed a captured reply that owes a re-ingress (origin + artifact + Stage.RESPONSE work-row).
        origin = await store.enqueue_message(
            channel_id="IB_REAL", raw="MSH|q", deliveries=[("OB_X", "q")], now=100.0
        )
        item = (await store.claim_ready(destination_name="OB_X", now=100.0))[0]
        reply = "MSH|^~\\&|P|F|R|RF|20260101||RSP^K11|R1|P|2.5.1\r"  # valid HL7 → peek succeeds
        await store.complete_with_response(
            item.id, body=reply, outcome="accepted", reingress_to="IB_LOOP", now=101.0
        )

        runner = RegistryRunner(reg, store, poll_interval=0.02)
        await runner.start()  # spawns IB_LOOP's response + router + transform workers
        try:
            child_mid = store._reingress_message_id(origin, "OB_X", 1, reply)
            for _ in range(200):
                await asyncio.sleep(0.02)
                child = await store.get_message(child_mid)
                if child is not None and child["status"] == MessageStatus.FILTERED.value:
                    break
        finally:
            await runner.stop()

        # the origin finalized PROCESSED (its response work-row was handed off + consumed)
        assert (await store.get_message(origin))["status"] == MessageStatus.PROCESSED.value
        # the re-ingressed child exists, was routed by route_loop, transformed by h_loop → FILTERED,
        # and carries the correlation back to the origin
        child = await store.get_message(child_mid)
        assert child is not None and child["status"] == MessageStatus.FILTERED.value
        assert json.loads(child["metadata"])["correlation_id"] == origin
        # the token is gone (re-ingress done)
        assert await store.pending_depth("IB_LOOP", stage=Stage.RESPONSE.value) == (0, None)
    finally:
        await store.close()


# --- Step 5: run-context live feed (a re-ingressed handler reads the origin's reply) ---


async def test_reingressed_handler_reads_origin_reply_via_response_get(tmp_path: Any) -> None:
    import asyncio

    from messagefoundry import response_get
    from messagefoundry.pipeline.wiring_runner import RegistryRunner

    store = await MessageStore.open(tmp_path / "rv.db")
    seen: dict[str, Any] = {}
    try:
        reg = Registry()
        reg.add_inbound(build_inbound_connection("IB_LOOP", Loopback(), router="route_loop"))
        reg.add_router("route_loop", lambda msg: ["h_loop"])

        def h_loop(msg: Any) -> None:
            # Increment 2: the re-ingressed answer's Handler can read the ORIGIN request's captured reply.
            seen["reply"] = response_get("OB_X")
            return None  # filter

        reg.add_handler("h_loop", h_loop)

        await store.enqueue_message(
            channel_id="IB_REAL", raw="MSH|q", deliveries=[("OB_X", "q")], now=100.0
        )
        item = (await store.claim_ready(destination_name="OB_X", now=100.0))[0]
        reply = "MSH|^~\\&|P|F|R|RF|20260101||RSP^K11|R1|P|2.5.1\r"
        await store.complete_with_response(
            item.id, body=reply, outcome="accepted", reingress_to="IB_LOOP", now=101.0
        )
        runner = RegistryRunner(reg, store, poll_interval=0.02)
        await runner.start()
        try:
            for _ in range(200):
                await asyncio.sleep(0.02)
                if "reply" in seen:
                    break
        finally:
            await runner.stop()
        assert "reply" in seen and seen["reply"] is not None
        assert seen["reply"].body == reply  # the origin's captured reply, by its destination
    finally:
        await store.close()


async def test_ingress_handoff_corrupt_ref_dead_letters_not_loops(store: MessageStore) -> None:
    # A corrupt/unparseable work-row reference must dead-letter the token + ERROR the origin + CONSUME it
    # (return True) — never infinite-loop on a row that can't be parsed (review finding).
    origin, work = await _seed_reingress(store)
    await store._db.execute(
        "UPDATE queue SET payload=? WHERE id=?", (store._enc("not-a-valid-ref"), work.id)
    )
    await store._db.commit()
    ok = await store.ingress_handoff(
        response_row_id=work.id,
        loopback_channel_id="IB_LOOP",
        correlation_depth_cap=8,
        control_id=None,
        message_type=None,
        summary=None,
        now=110.0,
    )
    assert ok is True  # token consumed, NOT re-looped
    assert (await store.get_message(origin))["status"] == MessageStatus.ERROR.value
    assert await store.claim_next_fifo("IB_LOOP", now=111.0, stage=Stage.RESPONSE.value) is None
    assert (await store.pending_depth("IB_LOOP", stage=Stage.INGRESS.value)) == (0, None)


async def test_max_correlation_depth_threads_from_engine_to_runner(tmp_path: Any) -> None:
    # The [pipeline] max_correlation_depth setting flows Engine.create → RegistryRunner (review minor).
    from messagefoundry.pipeline import Engine

    eng = await Engine.create(tmp_path / "cap.db", max_correlation_depth=3)
    try:
        runner = eng.add_registry(Registry())
        assert runner._max_correlation_depth == 3
    finally:
        await eng.stop()
