# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Internal pass-through (PT) connector — generalized re-ingress (ADR 0013, generalized).

A Handler ``Send``\\ s its transformed message *into* a PT inbound (an internal inbound with its OWN
router). The engine re-ingresses that body as a NEW, INDEPENDENT child message on the PT channel — in
the SAME ``transform_handoff`` transaction that consumes the parent's routed row — and the PT inbound's
own router re-routes it deeper. This is the Corepoint ``PT_*`` 1:N internal fan-out, vs. ADR 0013's 1:1
``Loopback()`` response capture.

These tests pin: the wiring guards + ``transform_one`` PT-target validation (no store); the atomic store
handoff (child produced + parent finalized PROCESSED, not FILTERED); content-addressed idempotent
re-run; the depth-cap loop guard; and the inert PT source.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from messagefoundry.config.models import AckMode, ConnectorType, ContentType, Source
from messagefoundry.config.settings import EgressSettings, StoreBackend
from messagefoundry.config.wiring import (
    MLLP,
    File,
    PassThrough,
    Registry,
    Send,
    WiringError,
    build_inbound_connection,
    build_outbound_connection,
)
from messagefoundry.pipeline.dryrun import transform_one
from messagefoundry.pipeline.engine import Engine
from messagefoundry.pipeline.wiring_runner import build_check_registry
from messagefoundry.store import MessageStatus, MessageStore, OutboxStatus, Stage
from messagefoundry.store.crypto import generate_key, make_cipher
from messagefoundry.store.store import (
    _NOT_PT_MARKER,
    PASSTHROUGH_MARKER_HANDLER,
    ResendSourceNotFound,
)
from messagefoundry.transports.passthrough import PassThroughSource


@pytest.fixture
async def store(tmp_path: Any) -> Any:
    s = await MessageStore.open(tmp_path / "passthrough.db")
    yield s
    await s.close()


async def _seed_routed(
    store: MessageStore,
    *,
    channel_id: str = "IB_REAL",
    raw: str = "MSH|payload",
    routed_id: str = "routed-1",
    handler: str = "h1",
    metadata: str | None = None,
    now: float = 100.0,
) -> tuple[str, str]:
    """A message at the ROUTED stage with a single INFLIGHT routed row (as the transform worker would
    have claimed it), ready for a ``transform_handoff``. Returns (message_id, routed_id)."""
    mid = await store.enqueue_message(
        channel_id=channel_id, raw=raw, deliveries=[], now=now, metadata=metadata
    )
    # UNROUTED → ROUTED (the router selected this handler); add the INFLIGHT routed row by hand.
    await store._db.execute(
        "UPDATE messages SET status=? WHERE id=?", (MessageStatus.ROUTED.value, mid)
    )
    await store._db.execute(
        "INSERT INTO queue (id, message_id, stage, channel_id, destination_name, handler_name,"
        " payload, status, attempts, next_attempt_at, created_at, updated_at)"
        " VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
        (
            routed_id,
            mid,
            Stage.ROUTED.value,
            channel_id,
            None,
            handler,
            store._cipher.encrypt(raw),
            OutboxStatus.INFLIGHT.value,
            1,
            now,
            now,
            now,
        ),
    )
    await store._db.commit()
    return mid, routed_id


# --------------------------------------------------------------------------- wiring validation


def test_passthrough_factory_and_enum() -> None:
    spec = PassThrough()
    assert spec.type is ConnectorType.PT
    assert spec.settings == {}


def test_passthrough_inbound_forces_ack_none_and_rejects_strict() -> None:
    # ack_mode defaults to NONE (no external peer); strict is meaningless (no untrusted intake).
    ic = build_inbound_connection("PT_X", PassThrough(), router="r")
    assert ic.ack_mode is AckMode.NONE
    with pytest.raises(WiringError, match="meaningless for a PassThrough"):
        build_inbound_connection("PT_X", PassThrough(), router="r", strict=True)
    with pytest.raises(WiringError, match="takes no ACK"):
        build_inbound_connection("PT_X", PassThrough(), router="r", ack_mode=AckMode.ENHANCED)


def test_passthrough_inbound_rejects_bind_address() -> None:
    with pytest.raises(WiringError, match="bind_address is only valid"):
        build_inbound_connection("PT_X", PassThrough(), router="r", bind_address="0.0.0.0")


def test_transform_one_accepts_pt_target_and_tags_it() -> None:
    reg = Registry()
    reg.add_inbound(build_inbound_connection("PT_NEXT", PassThrough(), router="r2"))
    reg.add_outbound(build_outbound_connection("OB_REAL", MLLP(host="127.0.0.1", port=2575)))

    def h(_msg: Any) -> list[Send]:
        return [Send(to="OB_REAL", message="A"), Send(to="PT_NEXT", message="B")]

    reg.add_handler("h", h)
    deliveries, _, _, _ = transform_one(reg, "h", "MSH|x", ContentType.HL7V2.value)
    by_to = {d.to: d for d in deliveries}
    assert by_to["OB_REAL"].is_passthrough is False
    assert by_to["PT_NEXT"].is_passthrough is True


def test_transform_one_unknown_target_fails() -> None:
    reg = Registry()

    def h(_msg: Any) -> list[Send]:
        return [Send(to="NOPE", message="A")]

    reg.add_handler("h", h)
    with pytest.raises(ValueError, match="unknown outbound/pass-through connection 'NOPE'"):
        transform_one(reg, "h", "MSH|x", ContentType.HL7V2.value)


def test_transform_one_non_pt_inbound_is_not_a_valid_target() -> None:
    # A normal (socket) inbound is NOT a Send target — only an outbound or a PT inbound.
    reg = Registry()
    reg.add_inbound(build_inbound_connection("IB_REAL", MLLP(port=2575), router="r"))

    def h(_msg: Any) -> list[Send]:
        return [Send(to="IB_REAL", message="A")]

    reg.add_handler("h", h)
    with pytest.raises(ValueError, match="unknown outbound/pass-through"):
        transform_one(reg, "h", "MSH|x", ContentType.HL7V2.value)


def test_build_check_registry_allows_pt_inbound() -> None:
    reg = Registry()
    reg.add_inbound(build_inbound_connection("PT_X", PassThrough(), router="r"))
    # A PT inbound builds its inert source and passes the egress allowlist (no dial-out) — no error.
    build_check_registry(reg, inbound_bind_host="127.0.0.1", env_values={}, egress=EgressSettings())


# --------------------------------------------------------------------------- inert source


async def test_passthrough_source_never_invokes_handler() -> None:
    src = PassThroughSource(Source(type=ConnectorType.PT, settings={}))
    invoked = False

    async def handler(*_a: Any, **_k: Any) -> Any:
        nonlocal invoked
        invoked = True

    await src.start(handler)  # records the handler; the run loop never fires
    await src.stop()
    assert invoked is False


# --------------------------------------------------------------------------- store handoff


async def test_passthrough_handoff_produces_child_and_parent_processed(
    store: MessageStore,
) -> None:
    # A handler Sends ONLY into a PT inbound: the parent must finalize PROCESSED (the Send was
    # delivered into the PT), NOT FILTERED, and a new independent child message must exist on the PT
    # channel at the INGRESS stage (RECEIVED), correlated to the parent.
    parent, routed = await _seed_routed(store, now=100.0)
    ok = await store.transform_handoff(
        routed_id=routed,
        message_id=parent,
        channel_id="IB_REAL",
        deliveries=[],
        pt_deliveries=[("PT_NEXT", "MSH|child")],
        now=101.0,
    )
    assert ok is True

    # Parent: PROCESSED (a done PT marker row, no in-flight rows).
    pmsg = await store.get_message(parent)
    assert pmsg is not None and pmsg["status"] == MessageStatus.PROCESSED.value

    # Child: a distinct message on the PT channel, RECEIVED, correlated, with a pending INGRESS row.
    msgs = await store.list_messages(channel_id="PT_NEXT")
    assert len(msgs) == 1
    child = msgs[0]
    assert child["id"] != parent
    assert child["status"] == MessageStatus.RECEIVED.value
    assert child["source_type"] == "passthrough"
    full = await store.get_message(child["id"])
    assert full is not None
    meta = json.loads(full["metadata"])
    assert meta["correlation_id"] == parent
    assert meta["correlation_root_id"] == parent
    assert meta["correlation_depth"] == 1
    assert full["raw"] == "MSH|child"
    # The child's INGRESS row keys by the PT channel → the PT inbound's router worker will drain it.
    depth, _ = await store.pending_depth("PT_NEXT", stage=Stage.INGRESS.value)
    assert depth == 1


async def test_passthrough_plus_outbound_in_one_handler(store: MessageStore) -> None:
    # A handler returns BOTH a real outbound delivery AND a PT Send: both are produced in ONE
    # transform_handoff (one routed-row consume). The parent stays in flight (the real outbound row is
    # pending), and the PT child exists independently.
    parent, routed = await _seed_routed(store, now=100.0)
    ok = await store.transform_handoff(
        routed_id=routed,
        message_id=parent,
        channel_id="IB_REAL",
        deliveries=[("OB_REAL", "MSH|out")],
        pt_deliveries=[("PT_NEXT", "MSH|child")],
        now=101.0,
    )
    assert ok is True
    # Parent has a pending real outbound row → not yet finalized (stays ROUTED until delivery).
    depth_out, _ = await store.pending_depth("OB_REAL", stage=Stage.OUTBOUND.value)
    assert depth_out == 1
    # PT child produced.
    assert len(await store.list_messages(channel_id="PT_NEXT")) == 1


async def test_passthrough_child_routes_onward_to_outbound(store: MessageStore) -> None:
    # End-to-end at the store layer: the PT child's own transform_handoff to a real outbound makes the
    # child PROCESSED — proving the child is a normal message its router re-routes deeper.
    parent, routed = await _seed_routed(store, now=100.0)
    await store.transform_handoff(
        routed_id=routed,
        message_id=parent,
        channel_id="IB_REAL",
        deliveries=[],
        pt_deliveries=[("PT_NEXT", "MSH|child")],
        now=101.0,
    )
    child_id = (await store.list_messages(channel_id="PT_NEXT"))[0]["id"]
    # Simulate the PT inbound's router+transform: consume the child's INGRESS row, route to a handler,
    # then transform_handoff that handler's routed row to a real outbound.
    ingress = await store.claim_next_fifo("PT_NEXT", stage=Stage.INGRESS.value)
    assert ingress is not None and ingress.message_id == child_id
    assert await store.route_handoff(
        ingress_id=ingress.id,
        message_id=child_id,
        channel_id="PT_NEXT",
        handlers=[("h_child", "MSH|child")],
        disposition=MessageStatus.ROUTED,
    )
    crouted = await store.claim_next_fifo("PT_NEXT", stage=Stage.ROUTED.value)
    assert crouted is not None
    await store.transform_handoff(
        routed_id=crouted.id,
        message_id=child_id,
        channel_id="PT_NEXT",
        deliveries=[("OB_FINAL", "MSH|final")],
    )
    # Deliver the child's outbound row → child PROCESSED.
    item = await store.claim_next_fifo("OB_FINAL", stage=Stage.OUTBOUND.value)
    assert item is not None
    await store.mark_done(item.id)
    cmsg = await store.get_message(child_id)
    assert cmsg is not None and cmsg["status"] == MessageStatus.PROCESSED.value


async def test_passthrough_handoff_idempotent_rerun(store: MessageStore) -> None:
    # Re-invoking transform_handoff on an already-consumed routed row is a no-op (the guarded DELETE),
    # and the content-addressed child id means even a forced re-insert produces exactly ONE child.
    parent, routed = await _seed_routed(store, now=100.0)
    assert await store.transform_handoff(
        routed_id=routed,
        message_id=parent,
        channel_id="IB_REAL",
        deliveries=[],
        pt_deliveries=[("PT_NEXT", "MSH|child")],
        now=101.0,
    )
    # Routed row is gone → second call returns False, writes nothing.
    assert (
        await store.transform_handoff(
            routed_id=routed,
            message_id=parent,
            channel_id="IB_REAL",
            deliveries=[],
            pt_deliveries=[("PT_NEXT", "MSH|child")],
            now=102.0,
        )
        is False
    )
    assert len(await store.list_messages(channel_id="PT_NEXT")) == 1


async def test_passthrough_child_id_is_content_addressed(store: MessageStore) -> None:
    # The child id is a deterministic function of (routed_id, pt_channel, body) — re-deriving it twice
    # is stable, and the produce path pre-checks it so a partial-then-recovered run can't double-inject.
    mid1 = store._passthrough_message_id("r-1", "PT_NEXT", "MSH|child")
    mid2 = store._passthrough_message_id("r-1", "PT_NEXT", "MSH|child")
    assert mid1 == mid2 and len(mid1) == 32
    # A different routed row / body / channel → a different child.
    assert store._passthrough_message_id("r-2", "PT_NEXT", "MSH|child") != mid1
    assert store._passthrough_message_id("r-1", "PT_OTHER", "MSH|child") != mid1
    assert store._passthrough_message_id("r-1", "PT_NEXT", "MSH|other") != mid1


async def test_passthrough_depth_cap_drops_child_and_errors_parent(
    store: MessageStore,
) -> None:
    # A parent already at the depth cap (its metadata says correlation_depth == cap) Sends into a PT:
    # child_depth = cap + 1 > cap → NO child is produced, and the parent finalizes ERROR (the dead PT
    # marker). This bounds internal PT->PT loops.
    cap = 3
    parent, routed = await _seed_routed(
        store,
        metadata=json.dumps({"correlation_depth": cap, "correlation_root_id": "root-1"}),
        now=100.0,
    )
    ok = await store.transform_handoff(
        routed_id=routed,
        message_id=parent,
        channel_id="IB_REAL",
        deliveries=[],
        pt_deliveries=[("PT_NEXT", "MSH|child")],
        correlation_depth_cap=cap,
        now=101.0,
    )
    assert ok is True
    # No child produced.
    assert await store.list_messages(channel_id="PT_NEXT") == []
    # Parent ERROR (the dead marker row).
    pmsg = await store.get_message(parent)
    assert pmsg is not None and pmsg["status"] == MessageStatus.ERROR.value


async def test_passthrough_correlation_root_propagates(store: MessageStore) -> None:
    # A parent that is itself a re-ingress (carries correlation_root_id) propagates the SAME root to the
    # child, and bumps depth — so the whole chain shares one root and depth grows monotonically.
    parent, routed = await _seed_routed(
        store,
        metadata=json.dumps(
            {"correlation_depth": 2, "correlation_root_id": "ROOT", "correlation_id": "mid-prev"}
        ),
        now=100.0,
    )
    await store.transform_handoff(
        routed_id=routed,
        message_id=parent,
        channel_id="IB_REAL",
        deliveries=[],
        pt_deliveries=[("PT_NEXT", "MSH|child")],
        now=101.0,
    )
    child_id = (await store.list_messages(channel_id="PT_NEXT"))[0]["id"]
    full = await store.get_message(child_id)
    assert full is not None
    meta = json.loads(full["metadata"])
    assert meta["correlation_root_id"] == "ROOT"
    assert meta["correlation_depth"] == 3
    assert meta["correlation_id"] == parent


async def test_transform_handoff_no_pt_is_byte_identical(store: MessageStore) -> None:
    # Regression: empty pt_deliveries leaves the pre-feature path unchanged (no PT marker row, normal
    # FILTERED collapse when a handler delivers nothing).
    parent, routed = await _seed_routed(store, now=100.0)
    assert await store.transform_handoff(
        routed_id=routed, message_id=parent, channel_id="IB_REAL", deliveries=[]
    )
    pmsg = await store.get_message(parent)
    # No deliveries, no PT → the routed handler produced nothing → FILTERED.
    assert pmsg is not None and pmsg["status"] == MessageStatus.FILTERED.value


# --------------------------------------------- completion markers stay out of replay (BACKLOG #1580)
#
# A Send into a PT inbound leaves an already-terminal outbound MARKER row on the parent. It is
# bookkeeping: its lane is an INBOUND name, so no delivery worker drains it. Replay used to re-pend it
# like real work. On a mixed parent the real redelivery then finished while the marker sat pending, the
# parent stayed ROUTED, and the startup sweep later dead-lettered the marker and recorded a DELIVERED
# message as ERROR.
#
# Every test runs keyless AND keyed. The keyed arm is the one that reproduces the defect: a keyless
# store writes the marker's empty body as a literal '' and the #1560 erased-body predicate already
# skipped it by accident, while a keyed store encrypts '' into a real cell that looks replayable. The
# keyless arm is the control that the fix does not break the path that already worked.


@pytest.fixture(params=["keyless", "keyed"])
async def pt_store(request: Any, tmp_path: Any) -> Any:
    cipher = make_cipher(generate_key()) if request.param == "keyed" else None
    s = await MessageStore.open(tmp_path / f"pt_replay_{request.param}.db", cipher=cipher)
    yield s
    await s.close()


async def _deliver(store: MessageStore, dest: str, *, now: float) -> int:
    """Claim and complete every due outbound row on ``dest``, as its delivery worker would."""
    items = await store.claim_ready(now=now, stage=Stage.OUTBOUND.value, destination_name=dest)
    for item in items:
        await store.mark_done(item.id, now=now)
    return len(items)


async def _fail(store: MessageStore, dest: str, *, now: float) -> int:
    """Claim and dead-letter every due outbound row on ``dest`` (a permanent delivery failure)."""
    items = await store.claim_ready(now=now, stage=Stage.OUTBOUND.value, destination_name=dest)
    for item in items:
        await store.dead_letter_now(item.id, "permanent reject", now=now)
    return len(items)


async def _pending_on(store: MessageStore, lane: str) -> int:
    """Non-terminal queue rows on ``lane`` at any stage. A marker lane must always read zero."""
    cur = await store._db.execute(
        "SELECT COUNT(*) AS n FROM queue WHERE destination_name=? AND status IN (?, ?)",
        (lane, OutboxStatus.PENDING.value, OutboxStatus.INFLIGHT.value),
    )
    row = await cur.fetchone()
    assert row is not None
    return int(row["n"])


async def _status(store: MessageStore, message_id: str) -> str:
    msg = await store.get_message(message_id)
    assert msg is not None
    return str(msg["status"])


async def _handoff(
    store: MessageStore,
    *,
    outbound: bool,
    depth_capped: bool = False,
    routed_id: str = "routed-1",
) -> str:
    """A parent whose one handler Sends into ``PT_NEXT`` and, when ``outbound``, also to ``OB_REAL``.
    ``depth_capped`` puts the parent at the correlation cap, so its marker lands DEAD. Returns the id."""
    metadata = json.dumps({"correlation_depth": 3}) if depth_capped else None
    parent, routed = await _seed_routed(store, metadata=metadata, routed_id=routed_id, now=100.0)
    assert await store.transform_handoff(
        routed_id=routed,
        message_id=parent,
        channel_id="IB_REAL",
        deliveries=[("OB_REAL", "MSH|out")] if outbound else [],
        pt_deliveries=[("PT_NEXT", "MSH|child")],
        correlation_depth_cap=3,
        now=101.0,
    )
    return parent


async def test_passthrough_marker_carries_the_explicit_stamp(pt_store: MessageStore) -> None:
    # The discriminator every replay path keys on. The real outbound sibling is the control: it must
    # NOT carry the stamp, or replay would skip real work too.
    parent = await _handoff(pt_store, outbound=True)
    rows = {r["destination_name"]: r for r in await pt_store.outbox_for(parent)}
    assert rows["PT_NEXT"]["handler_name"] == PASSTHROUGH_MARKER_HANDLER
    assert rows["OB_REAL"]["handler_name"] is None


def test_the_marker_predicate_names_the_stamp_and_the_outbound_stage() -> None:
    # _NOT_PT_MARKER is a literal so the AST gate can read it; this is what keeps it honest.
    assert f"'{PASSTHROUGH_MARKER_HANDLER}'" in _NOT_PT_MARKER
    assert f"'{Stage.OUTBOUND.value}'" in _NOT_PT_MARKER
    assert "COALESCE(handler_name" in _NOT_PT_MARKER


async def test_replay_of_a_passthrough_only_parent_creates_no_work(pt_store: MessageStore) -> None:
    parent = await _handoff(pt_store, outbound=False)
    assert await _status(pt_store, parent) == MessageStatus.PROCESSED.value

    # Nothing to re-send: the marker has no body and nothing could drain it.
    assert await pt_store.replay(parent, now=200.0) == 0
    assert await _pending_on(pt_store, "PT_NEXT") == 0
    assert await _status(pt_store, parent) == MessageStatus.PROCESSED.value
    # And a restart's orphan sweep finds nothing to kill, so the parent stays truthful.
    assert await pt_store.dead_letter_missing_destinations({"OB_REAL"}, now=300.0) == 0
    assert await _status(pt_store, parent) == MessageStatus.PROCESSED.value


async def test_replay_of_a_mixed_parent_ends_processed_across_a_restart(
    pt_store: MessageStore,
) -> None:
    parent = await _handoff(pt_store, outbound=True)
    assert await _deliver(pt_store, "OB_REAL", now=110.0) == 1
    assert await _status(pt_store, parent) == MessageStatus.PROCESSED.value

    # RE-SEND mode: only the real delivery goes back into flight.
    assert await pt_store.replay(parent, now=200.0) == 1
    assert await _pending_on(pt_store, "PT_NEXT") == 0
    assert await _status(pt_store, parent) == MessageStatus.ROUTED.value
    assert await _deliver(pt_store, "OB_REAL", now=210.0) == 1
    assert await _status(pt_store, parent) == MessageStatus.PROCESSED.value

    # The restart sweep registers outbound names only. It must find no marker to dead-letter.
    assert await pt_store.dead_letter_missing_destinations({"OB_REAL"}, now=300.0) == 0
    assert await _status(pt_store, parent) == MessageStatus.PROCESSED.value


async def test_recover_replay_of_a_mixed_parent_redelivers_and_ends_processed(
    pt_store: MessageStore,
) -> None:
    # RECOVER mode: the real delivery failed; the marker is DONE and must stay untouched.
    parent = await _handoff(pt_store, outbound=True)
    assert await _fail(pt_store, "OB_REAL", now=110.0) == 1
    assert await _status(pt_store, parent) == MessageStatus.ERROR.value

    assert await pt_store.replay(parent, now=200.0) == 1
    assert await _deliver(pt_store, "OB_REAL", now=210.0) == 1
    assert await _pending_on(pt_store, "PT_NEXT") == 0
    assert await _status(pt_store, parent) == MessageStatus.PROCESSED.value


async def test_replay_leaves_a_depth_capped_marker_dead_and_the_parent_truthfully_errored(
    pt_store: MessageStore,
) -> None:
    # The depth-cap breach is a real failure no replay can repair: there is no child body to resend.
    # Replay recovers the real delivery and leaves the DEAD marker as it is, so the parent ends ERROR
    # rather than stuck ROUTED behind a pending marker nothing drains.
    parent = await _handoff(pt_store, outbound=True, depth_capped=True)
    assert await _fail(pt_store, "OB_REAL", now=110.0) == 1

    assert await pt_store.replay(parent, now=200.0) == 1
    assert await _pending_on(pt_store, "PT_NEXT") == 0
    assert await _deliver(pt_store, "OB_REAL", now=210.0) == 1
    assert await _status(pt_store, parent) == MessageStatus.ERROR.value

    # A parent whose ONLY row is the dead marker: nothing is replayable, and it stays ERROR.
    alone = await _handoff(pt_store, outbound=False, depth_capped=True, routed_id="routed-2")
    assert await _status(pt_store, alone) == MessageStatus.ERROR.value
    assert await pt_store.replay(alone, now=300.0) == 0
    assert await _pending_on(pt_store, "PT_NEXT") == 0
    assert await _status(pt_store, alone) == MessageStatus.ERROR.value


async def test_bulk_dead_replay_skips_a_depth_capped_marker(pt_store: MessageStore) -> None:
    capped = await _handoff(pt_store, outbound=False, depth_capped=True)
    # Control: an ordinary dead delivery on another message, which bulk replay must still recover.
    control = await pt_store.enqueue_message(
        channel_id="IB_REAL", raw="MSH|c", deliveries=[("OB_REAL", "MSH|c-out")], now=100.0
    )
    assert await _fail(pt_store, "OB_REAL", now=110.0) == 1

    assert await pt_store.replay_dead(now=200.0) == 1
    assert await _pending_on(pt_store, "PT_NEXT") == 0
    # The capped parent is not reverted to ROUTED with nothing re-queued behind it.
    assert await _status(pt_store, capped) == MessageStatus.ERROR.value
    assert await _status(pt_store, control) == MessageStatus.ROUTED.value
    # Scoped to the marker's own lane, it re-queues nothing and changes nothing.
    assert await pt_store.replay_dead(destination_name="PT_NEXT", now=300.0) == 0
    assert await _status(pt_store, capped) == MessageStatus.ERROR.value


async def test_a_dead_marker_does_not_hold_the_parents_attachments(pt_store: MessageStore) -> None:
    # The attachment clean-up keeps a streaming attachment while any row could still be delivered or
    # replayed. A dead marker can never be replayed, so it must not pin the parent's attachment.
    capped = await _handoff(pt_store, outbound=False, depth_capped=True)
    # Control: an ordinary dead delivery IS replayable and must still hold its message's attachment.
    control = await pt_store.enqueue_message(
        channel_id="IB_REAL", raw="MSH|c", deliveries=[("OB_REAL", "MSH|c-out")], now=100.0
    )
    assert await _fail(pt_store, "OB_REAL", now=110.0) == 1
    fragment = pt_store._attachment_still_referenced_sql("?")
    statuses = (OutboxStatus.PENDING.value, OutboxStatus.INFLIGHT.value, OutboxStatus.DEAD.value)

    async def held(message_id: str) -> bool:
        cur = await pt_store._db.execute(f"SELECT {fragment} AS held", (message_id, *statuses))
        row = await cur.fetchone()
        assert row is not None
        return bool(row["held"])

    assert await held(control) is True
    assert await held(capped) is False


async def test_resend_to_never_takes_a_marker_as_its_source(pt_store: MessageStore) -> None:
    # Mixed parent, no `from_`: the one real delivered body is the only source. Counting the marker
    # as a second source made this ambiguous.
    parent = await _handoff(pt_store, outbound=True)
    assert await _deliver(pt_store, "OB_REAL", now=110.0) == 1
    outcome = await pt_store.resend_to(
        message_id=parent, to="OB_STANDBY", idempotency_key="k-mixed", now=200.0
    )
    assert outcome.status == "resent" and outcome.from_destination == "OB_REAL"
    assert await _pending_on(pt_store, "PT_NEXT") == 0

    # A pass-through-only parent has no delivered body at all, which is what the refusal must say.
    alone = await _handoff(pt_store, outbound=False, routed_id="routed-2")
    with pytest.raises(ResendSourceNotFound):
        await pt_store.resend_to(
            message_id=alone, to="OB_STANDBY", idempotency_key="k-alone", now=300.0
        )


# --------------------------------------------------------- backend allow-list (fail-fast at start)
#
# PT re-ingress (the pt_deliveries branch of transform_handoff) ships on ALL THREE backends today —
# SQLite, Postgres, and SQL Server each set supports_pt_reingress=True. The gate is an ALLOW-LIST, not a
# block-list: the engine permits PT only on a backend that opts in, and rejects a graph with a PT inbound
# on any other backend at startup, BEFORE any listener accepts — so a runtime NotImplementedError (after
# the inbound was already ACKed) can never surface on a FUTURE backend that hasn't implemented the branch.
# No shipped backend is PT-incapable, so these tests SIMULATE one: they monkeypatch supports_pt=False onto
# a real SQLite store. What is under test is the GUARD, not any real backend's limits.


def _pt_graph() -> Registry:
    """A graph with a PT inbound (the offending element) plus a normal inbound + outbound."""
    reg = Registry()
    reg.add_inbound(build_inbound_connection("IB_REAL", MLLP(port=2575), router="r"))
    reg.add_inbound(build_inbound_connection("PT_FOO", PassThrough(), router="r2"))
    reg.add_outbound(build_outbound_connection("OB_REAL", MLLP(host="127.0.0.1", port=2576)))
    return reg


async def _engine_on_backend(
    tmp_path: Any,
    *,
    backend: StoreBackend,
    supports_pt: bool,
    registry: Registry,
) -> tuple[Engine, MessageStore]:
    """A SQLite-backed Engine whose store is monkeypatched to *report* ``backend`` + the PT capability,
    so the start-time allow-list can be exercised without a real Postgres/SQL Server."""
    s = await MessageStore.open(tmp_path / "pt_backend.db")
    s.backend = backend  # fake the reported backend for the guard
    s.supports_pt_reingress = supports_pt
    engine = Engine(s)
    engine.add_registry(registry)
    return engine, s


@pytest.mark.parametrize("backend", [StoreBackend.POSTGRES, StoreBackend.SQLSERVER])
async def test_engine_rejects_pt_on_backend_without_pt_support(
    tmp_path: Any, backend: StoreBackend
) -> None:
    # A PT inbound on a backend that doesn't implement PT re-ingress is rejected at start with a clear
    # config error naming the PT connection AND the backend — before any inbound listener binds.
    #
    # The parametrized backends are COUNTERFACTUAL: real Postgres/SQL Server both support PT today, so
    # supports_pt=False fakes a backend that does not. The name says "without PT support", not "non-
    # SQLite", because the gate keys on the CAPABILITY, never on which backend it is.
    engine, s = await _engine_on_backend(
        tmp_path, backend=backend, supports_pt=False, registry=_pt_graph()
    )
    try:
        with pytest.raises(WiringError) as exc:
            await engine.start()
        msg = str(exc.value)
        assert "'PT_FOO'" in msg  # names the offending PT connection
        assert backend.value in msg  # ...and the backend
        # Assert the CAPABILITY is named, not a backend. The old `"SQLite" in msg` assert silently froze
        # the error message into "PT requires the SQLite store backend" — a claim that was false the day
        # Postgres and SQL Server shipped PT, and that this assert would have kept true forever.
        assert "PT re-ingress" in msg
    finally:
        await s.close()


async def test_engine_rejects_pt_on_unknown_future_backend(tmp_path: Any) -> None:
    # ALLOW-LIST (not block-list): a backend that simply never set supports_pt_reingress (a future
    # backend that hasn't implemented PT) is rejected too, exactly like Postgres/SQL Server.
    s = await MessageStore.open(tmp_path / "pt_future.db")
    # Simulate a backend that left the base default (False) and exposes no StoreBackend value (so the
    # guard falls back to naming the store class) — yet PT is still rejected (allow-list, not block-list).
    s.supports_pt_reingress = False
    s.backend = None  # type: ignore[assignment]  # not a StoreBackend → class-name fallback
    engine = Engine(s)
    engine.add_registry(_pt_graph())
    try:
        with pytest.raises(WiringError) as exc:
            await engine.start()
        assert "'PT_FOO'" in str(exc.value)
    finally:
        await s.close()


async def test_guard_accepts_pt_on_sqlite_backend(tmp_path: Any) -> None:
    # The real SQLite store opts in (supports_pt_reingress=True): the guard is a no-op, a PT graph is
    # permitted. Pins that the SQLite path is unchanged. (Exercises the guard directly so the test does
    # not bind real listener sockets — mirrors test_engine_refuses_backend_without_ingest_stage, which
    # only drives the decision, not the full socket bring-up.)
    s = await MessageStore.open(tmp_path / "pt_sqlite.db")
    assert s.supports_pt_reingress is True and s.backend is StoreBackend.SQLITE
    engine = Engine(s)
    engine.add_registry(_pt_graph())
    try:
        engine._check_pt_backend_supported()  # no raise — PT permitted on SQLite
    finally:
        await s.close()


@pytest.mark.parametrize("backend", [StoreBackend.POSTGRES, StoreBackend.SQLSERVER])
async def test_guard_allows_non_pt_graph_on_non_sqlite_backend(
    tmp_path: Any, backend: StoreBackend
) -> None:
    # A graph with NO PT inbound is unaffected on a non-SQLite backend — the guard only fires when a PT
    # connector is actually present (no over-blocking of ordinary graphs).
    reg = Registry()
    reg.add_inbound(build_inbound_connection("IB_REAL", MLLP(port=2575), router="r"))
    reg.add_outbound(build_outbound_connection("OB_REAL", MLLP(host="127.0.0.1", port=2576)))
    engine, s = await _engine_on_backend(tmp_path, backend=backend, supports_pt=False, registry=reg)
    try:
        engine._check_pt_backend_supported()  # no PT inbound → no-op even on a non-SQLite backend
    finally:
        await s.close()


# ----------------------------------------- backend allow-list on RELOAD + DRY-RUN (config-apply paths)
#
# The start-time guard above is necessary but not sufficient: a non-PT graph can start clean on a non-
# SQLite backend, then a hot-reload (API /config/reload, cluster convergence) — or a promote pre-flight
# (dry_run=True) — could introduce a PT inbound and bring it live ungated. The gate is folded into the
# COMMON build-check (RegistryRunner.build_check) that every config-apply path runs (the live-runner
# swap, the runner-None bring-up, and dry_run), so all of them reject a PT-on-non-SQLite graph BEFORE
# any swap/start, leaving any already-running graph untouched. These fake the backend on a real SQLite
# store and drive engine.reload() with a registry returned by a patched load_config (no Python config
# files, no socket binds).


def _file_graph(inbox: Any, outdir: Any, *, with_pt: bool) -> Registry:
    """A code-first graph using FILE connectors (no socket binds): a file inbound routed to a file
    outbound, optionally PLUS a PT inbound (the offending element)."""
    reg = Registry()
    reg.add_outbound(
        build_outbound_connection(
            "OB_FILE", File(directory=str(outdir), filename="{MSH-10}.hl7", overwrite=True)
        )
    )
    reg.add_inbound(
        build_inbound_connection(
            "IB_FILE",
            File(directory=str(inbox), pattern="*.hl7", poll_seconds=0.05),
            router="r",
        )
    )
    reg.add_router("r", lambda _m: ["h"])
    reg.add_handler("h", lambda m: [Send(to="OB_FILE", message=m)])
    if with_pt:
        reg.add_inbound(build_inbound_connection("PT_FOO", PassThrough(), router="r2"))
        reg.add_router("r2", lambda _m: [])
    return reg


def _patch_load_config(monkeypatch: Any, registry: Registry) -> None:
    """Make engine.reload()'s ``load_config(path)`` return ``registry`` (it runs in a thread, so the
    target imported into the engine module is what we patch)."""
    monkeypatch.setattr(
        "messagefoundry.pipeline.engine.load_config", lambda _path: registry, raising=True
    )


@pytest.mark.parametrize("backend", [StoreBackend.POSTGRES, StoreBackend.SQLSERVER])
async def test_reload_live_rejects_introduced_pt_inbound(
    tmp_path: Any, monkeypatch: Any, backend: StoreBackend
) -> None:
    # PRIMARY exploit: a non-PT graph starts clean on a non-SQLite backend; a hot-reload that introduces
    # a PT inbound must be REJECTED (WiringError) BEFORE the swap, and the PT inbound must NOT go live —
    # the previously-running (non-PT) graph stays intact.
    inbox, outdir = tmp_path / "in", tmp_path / "out"
    inbox.mkdir()
    outdir.mkdir()
    s = await MessageStore.open(tmp_path / "reload_pt.db")
    s.backend = backend
    s.supports_pt_reingress = False
    engine = Engine(s)
    engine.add_registry(_file_graph(inbox, outdir, with_pt=False))
    try:
        await engine.start()  # non-PT graph on a non-SQLite backend → starts clean
        assert engine.registry_runner is not None and engine.registry_runner.running
        assert "PT_FOO" not in engine.registry_runner.registry.inbound

        _patch_load_config(monkeypatch, _file_graph(inbox, outdir, with_pt=True))
        with pytest.raises(WiringError) as exc:
            await engine.reload(tmp_path)  # live-runner branch: runner.reload → build_check gate
        assert "'PT_FOO'" in str(exc.value) and backend.value in str(exc.value)

        # The running graph is UNTOUCHED: still running, still no PT inbound (it never went live).
        assert engine.registry_runner.running
        assert "PT_FOO" not in engine.registry_runner.registry.inbound
    finally:
        await engine.stop()
        await s.close()


@pytest.mark.parametrize("backend", [StoreBackend.POSTGRES, StoreBackend.SQLSERVER])
async def test_reload_bringup_rejects_pt_graph_when_started_graphless(
    tmp_path: Any, monkeypatch: Any, backend: StoreBackend
) -> None:
    # STARTLESS-GRAPH bring-up: an engine started WITHOUT a graph (runner is None), then a reload that
    # introduces a first-ever PT graph on a non-SQLite backend must be rejected — the PT graph never
    # starts, and the engine is left with no runner (so a corrected retry re-enters cleanly).
    inbox, outdir = tmp_path / "in", tmp_path / "out"
    inbox.mkdir()
    outdir.mkdir()
    s = await MessageStore.open(tmp_path / "bringup_pt.db")
    s.backend = backend
    s.supports_pt_reingress = False
    engine = Engine(s)  # no add_registry → runner is None
    try:
        await engine.start()  # graphless start
        assert engine.registry_runner is None
        _patch_load_config(monkeypatch, _file_graph(inbox, outdir, with_pt=True))
        with pytest.raises(WiringError) as exc:
            await engine.reload(tmp_path)  # runner-None bring-up: build_check gate before start
        assert "'PT_FOO'" in str(exc.value)
        # The failed bring-up cleared the half-started runner — PT never went live.
        assert engine.registry_runner is None
    finally:
        await engine.stop()
        await s.close()


@pytest.mark.parametrize("backend", [StoreBackend.POSTGRES, StoreBackend.SQLSERVER])
async def test_reload_dry_run_rejects_pt_graph(
    tmp_path: Any, monkeypatch: Any, backend: StoreBackend
) -> None:
    # PROMOTE PRE-FLIGHT: reload(dry_run=True) on a PT graph + non-SQLite backend must now raise
    # WiringError (the false-green is closed) — validating without swapping. Exercise the runner-None
    # variant (throwaway checker carrying the store) — the harshest, since no live runner exists.
    inbox, outdir = tmp_path / "in", tmp_path / "out"
    inbox.mkdir()
    outdir.mkdir()
    s = await MessageStore.open(tmp_path / "dryrun_pt.db")
    s.backend = backend
    s.supports_pt_reingress = False
    engine = Engine(s)  # runner is None → dry_run builds a throwaway checker carrying this store
    try:
        _patch_load_config(monkeypatch, _file_graph(inbox, outdir, with_pt=True))
        with pytest.raises(WiringError) as exc:
            await engine.reload(tmp_path, dry_run=True)
        assert "'PT_FOO'" in str(exc.value) and backend.value in str(exc.value)
        assert engine.registry_runner is None  # dry-run never wires a runner
    finally:
        await s.close()


async def test_reload_paths_succeed_on_sqlite_backend(tmp_path: Any, monkeypatch: Any) -> None:
    # SANITY: the same PT-introducing reloads SUCCEED on the real SQLite backend (supports_pt_reingress
    # True) — the gate is a no-op there. Covers the live-runner swap, the bring-up, and dry_run.
    inbox, outdir = tmp_path / "in", tmp_path / "out"
    inbox.mkdir()
    outdir.mkdir()

    # (a) live-runner swap: start a non-PT graph, reload-in a PT inbound → it goes live.
    s = await MessageStore.open(tmp_path / "sqlite_live.db")
    assert s.supports_pt_reingress is True and s.backend is StoreBackend.SQLITE
    engine = Engine(s)
    engine.add_registry(_file_graph(inbox, outdir, with_pt=False))
    try:
        await engine.start()
        _patch_load_config(monkeypatch, _file_graph(inbox, outdir, with_pt=True))
        await engine.reload(tmp_path)
        assert engine.registry_runner is not None
        assert "PT_FOO" in engine.registry_runner.registry.inbound  # PT went live on SQLite
    finally:
        await engine.stop()
        await s.close()

    # (b) dry_run on SQLite + PT graph: returns the registry, no raise.
    s2 = await MessageStore.open(tmp_path / "sqlite_dry.db")
    engine2 = Engine(s2)
    try:
        _patch_load_config(monkeypatch, _file_graph(inbox, outdir, with_pt=True))
        reg = await engine2.reload(tmp_path, dry_run=True)
        assert "PT_FOO" in reg.inbound and engine2.registry_runner is None
    finally:
        await s2.close()


@pytest.mark.parametrize("backend", [StoreBackend.POSTGRES, StoreBackend.SQLSERVER])
async def test_reload_non_pt_graph_unaffected_on_non_sqlite(
    tmp_path: Any, monkeypatch: Any, backend: StoreBackend
) -> None:
    # SANITY: a non-PT graph reload on a non-SQLite backend is unaffected (the gate only fires on PT).
    inbox, outdir = tmp_path / "in", tmp_path / "out"
    inbox.mkdir()
    outdir.mkdir()
    s = await MessageStore.open(tmp_path / "nonpt_reload.db")
    s.backend = backend
    s.supports_pt_reingress = False
    engine = Engine(s)
    engine.add_registry(_file_graph(inbox, outdir, with_pt=False))
    try:
        await engine.start()
        _patch_load_config(monkeypatch, _file_graph(inbox, outdir, with_pt=False))
        await engine.reload(tmp_path)  # non-PT reload on Postgres/SQL Server → no raise
        assert engine.registry_runner is not None and engine.registry_runner.running
    finally:
        await engine.stop()
        await s.close()
