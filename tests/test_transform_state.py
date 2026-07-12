# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Transform-accessible state (ADR 0005): the SetState write contract + state_get read side.

Adversarial focus — the exactly-once / pure-re-run invariant the staged pipeline depends on:
a state write is committed **inside the routed→outbound handoff transaction**, so a crash before
commit leaves NO state (table or cache) and a replay applies it exactly once. Also covers atomicity
with the outbound rows, at-rest encryption + key rotation, the read-through cache, retention purge,
backward compatibility, and dry-run resolution + PHI gating.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

from messagefoundry.config.models import ConnectorType, Validation
from messagefoundry.config.state import activated as state_activated
from messagefoundry.config.state import set_active, reset, state_get
from messagefoundry.config.settings import RetentionSettings
from messagefoundry.config.wiring import (
    ConnectionSpec,
    InboundConnection,
    OutboundConnection,
    Registry,
    Send,
    SetState,
    WiringError,
)
from messagefoundry.parsing.message import Message
from messagefoundry.pipeline.dryrun import dry_run, transform_one
from messagefoundry.pipeline.retention import RetentionRunner
from messagefoundry.store.crypto import PREFIX, generate_key, make_cipher
from messagefoundry.store.store import MessageStatus, MessageStore, Stage

RAW = "MSH|^~\\&|S|F|R|RF|20260101||ADT^A01|MSG1|P|2.5.1\rPID|1||100||DOE^JANE\r"


@pytest.fixture
async def store(tmp_path: Path):
    s = await MessageStore.open(tmp_path / "state.db")
    yield s
    await s.close()


async def _route_one_handler(store: MessageStore, channel: str = "IB") -> tuple[str, str]:
    """Drive a message to a single claimed **routed** row, ready for transform_handoff. Returns
    ``(message_id, routed_row_id)``."""
    mid = await store.enqueue_ingress(channel_id=channel, raw=RAW)
    ingress = await store.claim_next_fifo(channel, stage=Stage.INGRESS.value)
    assert ingress is not None
    await store.route_handoff(
        ingress_id=ingress.id,
        message_id=mid,
        channel_id=channel,
        handlers=[("h", RAW)],
        disposition=MessageStatus.ROUTED,
    )
    routed = await store.claim_next_fifo(channel, stage=Stage.ROUTED.value)
    assert routed is not None
    return mid, routed.id


def _state_at_rest(db_path: Path, namespace: str, key: str) -> str:
    """Read state.value straight from the DB file, bypassing the store's decryption."""
    con = sqlite3.connect(db_path)
    try:
        row = con.execute(
            "SELECT value FROM state WHERE namespace=? AND key=?", (namespace, key)
        ).fetchone()
        return str(row[0]) if row else ""
    finally:
        con.close()


# --- SetState construction-time validation -----------------------------------


def test_setstate_accepts_json_serializable_values() -> None:
    SetState("ns", "k", "v")
    SetState("ns", "k", 1)
    SetState("ns", "k", {"a": [1, 2, 3]})
    SetState("ns", "k", None)


def test_setstate_rejects_non_serializable_value() -> None:
    with pytest.raises(WiringError, match="JSON-serializable"):
        SetState("ns", "k", object())


def test_setstate_rejects_empty_namespace_or_key() -> None:
    with pytest.raises(WiringError, match="namespace"):
        SetState("", "k", "v")
    with pytest.raises(WiringError, match="key"):
        SetState("ns", "", "v")


# --- write side: applied in the handoff transaction --------------------------


async def test_state_write_persists_and_loads_into_cache(store: MessageStore) -> None:
    mid, routed_id = await _route_one_handler(store)
    ok = await store.transform_handoff(
        routed_id=routed_id,
        message_id=mid,
        channel_id="IB",
        deliveries=[("OB_A", "payload")],
        state_ops=[("patient_anon", "MRN1", "ANON-7")],
    )
    assert ok is True
    # Persisted (decodes back to the native value) and visible in the synchronous read view.
    assert store.state_view()[("patient_anon", "MRN1")] == "ANON-7"
    with state_activated(store.state_view()):
        assert state_get("patient_anon", "MRN1") == "ANON-7"
    # The outbound row was produced in the same handoff.
    assert {r["destination_name"] for r in await store.outbox_for(mid)} == {"OB_A"}


async def test_state_upsert_overwrites_same_key(store: MessageStore) -> None:
    mid1, routed1 = await _route_one_handler(store)
    await store.transform_handoff(
        routed_id=routed1,
        message_id=mid1,
        channel_id="IB",
        deliveries=[],
        state_ops=[("ns", "k", "first")],
    )
    mid2, routed2 = await _route_one_handler(store)
    await store.transform_handoff(
        routed_id=routed2,
        message_id=mid2,
        channel_id="IB",
        deliveries=[],
        state_ops=[("ns", "k", "second")],
    )
    assert store.state_view()[("ns", "k")] == "second"
    cur = await store._db.execute("SELECT COUNT(*) FROM state WHERE namespace='ns' AND key='k'")
    assert (await cur.fetchone())[0] == 1  # upsert, not a second row


# --- ADVERSARIAL: re-run safety (crash-before-commit) ------------------------


async def test_rollback_leaves_no_state_row_and_no_cache_entry(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Simulate a crash mid-handoff AFTER the state op is applied, BEFORE commit: the whole txn rolls
    # back, so NO state row persists and the cache is untouched (a rolled-back write must not leak).
    mid, routed_id = await _route_one_handler(store)

    async def boom(*a: object, **k: object) -> None:
        raise RuntimeError("crash before commit")

    monkeypatch.setattr(store, "_event", boom)  # raises after _apply_state_op, before commit
    with pytest.raises(RuntimeError):
        await store.transform_handoff(
            routed_id=routed_id,
            message_id=mid,
            channel_id="IB",
            deliveries=[("OB_A", "p")],
            state_ops=[("ns", "k", "leaked?")],
        )
    monkeypatch.undo()
    # No state row, no outbound row, and nothing in the read-through cache.
    cur = await store._db.execute("SELECT COUNT(*) FROM state")
    assert (await cur.fetchone())[0] == 0
    assert ("ns", "k") not in store.state_view()
    assert await store.outbox_for(mid) == []
    # The routed row is recoverable so the transform re-runs (pure re-derivation).
    recovered = await store.reset_stale_inflight(stage=Stage.ROUTED.value)
    assert recovered == 1


async def test_replay_applies_state_write_exactly_once(store: MessageStore) -> None:
    # A committed handoff has consumed (DELETEd) the routed row, so re-invoking transform_handoff for
    # the same routed id is a no-op: the state value is the committed one, never double-applied.
    mid, routed_id = await _route_one_handler(store)
    assert await store.transform_handoff(
        routed_id=routed_id,
        message_id=mid,
        channel_id="IB",
        deliveries=[("OB_A", "p")],
        state_ops=[("counter", "c", 1)],
    )
    # A second call for the same routed row (the "replay after the worker already committed" case).
    again = await store.transform_handoff(
        routed_id=routed_id,
        message_id=mid,
        channel_id="IB",
        deliveries=[("OB_A", "p")],
        state_ops=[("counter", "c", 999)],  # would double-apply if not idempotent
    )
    assert again is False  # routed row already gone → no-op
    assert store.state_view()[("counter", "c")] == 1  # the committed value, not the replay's 999
    assert len(await store.outbox_for(mid)) == 1  # no duplicate outbound row either


async def test_rerun_after_recovery_reapplies_identically(store: MessageStore) -> None:
    # Full crash→recover→re-run cycle: a rolled-back handoff leaves the routed row inflight; recovery
    # reverts it; the worker re-runs the (pure) transform and the state write lands exactly once.
    mid, routed_id = await _route_one_handler(store)

    calls = {"n": 0}
    real_event = store._event

    async def fail_once(*a: object, **k: object) -> None:
        calls["n"] += 1
        if calls["n"] == 1:
            raise RuntimeError("crash on first attempt")
        await real_event(*a, **k)

    store._event = fail_once  # type: ignore[method-assign]
    with pytest.raises(RuntimeError):
        await store.transform_handoff(
            routed_id=routed_id,
            message_id=mid,
            channel_id="IB",
            deliveries=[("OB_A", "p")],
            state_ops=[("ns", "k", "v")],
        )
    assert ("ns", "k") not in store.state_view()  # first (rolled-back) attempt left nothing
    # Recover the inflight routed row and re-run (same routed id — the worker re-derives identically).
    assert await store.reset_stale_inflight(stage=Stage.ROUTED.value) == 1
    routed = await store.claim_next_fifo("IB", stage=Stage.ROUTED.value)
    assert routed is not None and routed.id == routed_id
    assert await store.transform_handoff(
        routed_id=routed.id,
        message_id=mid,
        channel_id="IB",
        deliveries=[("OB_A", "p")],
        state_ops=[("ns", "k", "v")],
    )
    assert store.state_view()[("ns", "k")] == "v"
    cur = await store._db.execute("SELECT COUNT(*) FROM state")
    assert (await cur.fetchone())[0] == 1  # exactly once


# --- ADVERSARIAL: atomicity (state + outbound commit together) ---------------


async def test_outbound_and_state_commit_together(store: MessageStore) -> None:
    mid, routed_id = await _route_one_handler(store)
    await store.transform_handoff(
        routed_id=routed_id,
        message_id=mid,
        channel_id="IB",
        deliveries=[("OB_A", "p1"), ("OB_B", "p2")],
        state_ops=[("ns", "k1", "v1"), ("ns", "k2", "v2")],
    )
    # Both outbound rows and both state ops present after commit.
    assert {r["destination_name"] for r in await store.outbox_for(mid)} == {"OB_A", "OB_B"}
    assert store.state_view()[("ns", "k1")] == "v1"
    assert store.state_view()[("ns", "k2")] == "v2"


# --- encryption at rest + round-trip + key rotation --------------------------


async def test_state_value_encrypted_at_rest_and_read_back(tmp_path: Path) -> None:
    db = tmp_path / "enc.db"
    store = await MessageStore.open(db, cipher=make_cipher(generate_key()))
    try:
        mid, routed_id = await _route_one_handler(store)
        await store.transform_handoff(
            routed_id=routed_id,
            message_id=mid,
            channel_id="IB",
            deliveries=[],
            state_ops=[("patient_anon", "MRN-DOE", "ANON-XYZ")],
        )
    finally:
        await store.close()
    # On disk: ciphertext (prefix present, plaintext value not visible).
    at_rest = _state_at_rest(db, "patient_anon", "MRN-DOE")
    assert at_rest.startswith(PREFIX)
    assert "ANON-XYZ" not in at_rest


async def test_state_round_trip_across_reopen(tmp_path: Path) -> None:
    db = tmp_path / "rt.db"
    k = generate_key()
    store = await MessageStore.open(db, cipher=make_cipher(k))
    mid, routed_id = await _route_one_handler(store)
    await store.transform_handoff(
        routed_id=routed_id,
        message_id=mid,
        channel_id="IB",
        deliveries=[],
        state_ops=[("ns", "k", {"anon": "A1", "n": 3})],
    )
    await store.close()
    # Reopen with the same key: the on-open cache load decrypts + JSON-decodes the value.
    store2 = await MessageStore.open(db, cipher=make_cipher(k))
    try:
        assert store2.state_view()[("ns", "k")] == {"anon": "A1", "n": 3}
    finally:
        await store2.close()


async def test_key_rotation_reencrypts_state_and_reads_still_work(tmp_path: Path) -> None:
    db = tmp_path / "rotate.db"
    old = generate_key()
    store = await MessageStore.open(db, cipher=make_cipher(old))
    mid, routed_id = await _route_one_handler(store)
    await store.transform_handoff(
        routed_id=routed_id,
        message_id=mid,
        channel_id="IB",
        deliveries=[],
        state_ops=[("ns", "k", "secret")],
    )
    old_id = make_cipher(old).active_key_id  # type: ignore[attr-defined]
    await store.close()
    # Reopen with a NEW active key, old kept as retired (decrypt-only) — the rotation scenario.
    new = generate_key()
    store2 = await MessageStore.open(db, cipher=make_cipher(new, [old]))
    try:
        # Before rotation the value is still under the old key but reads work (keyring).
        assert store2.state_view()[("ns", "k")] == "secret"
        rotated = await store2.reencrypt_to_active()
        assert rotated >= 1  # the state value (among others) re-encrypted
        # On disk it is now under the NEW key id, and reads still resolve.
        new_id = make_cipher(new).active_key_id  # type: ignore[attr-defined]
        at_rest = _state_at_rest(db, "ns", "k")
        assert at_rest.startswith(f"{PREFIX}{new_id}:")
        assert old_id not in at_rest
        assert store2.state_view()[("ns", "k")] == "secret"
    finally:
        await store2.close()


# --- read-through cache + state_get default ----------------------------------


async def test_state_get_reflects_committed_write_and_default_on_miss(store: MessageStore) -> None:
    with state_activated(store.state_view()):
        assert state_get("ns", "missing") is None
        assert state_get("ns", "missing", "fallback") == "fallback"
    mid, routed_id = await _route_one_handler(store)
    await store.transform_handoff(
        routed_id=routed_id,
        message_id=mid,
        channel_id="IB",
        deliveries=[],
        state_ops=[("ns", "k", "now-set")],
    )
    with state_activated(store.state_view()):
        assert state_get("ns", "k") == "now-set"


def test_state_get_returns_default_with_no_active_view() -> None:
    # Called outside any run/dry-run (no published view) → default, never an error.
    assert state_get("ns", "k") is None
    assert state_get("ns", "k", "d") == "d"


def test_set_active_and_reset_restore_cleanly() -> None:
    token = set_active({("ns", "k"): "v"})
    try:
        assert state_get("ns", "k") == "v"
    finally:
        reset(token)
    assert state_get("ns", "k") is None  # restored to "no active view"


# --- retention purge ---------------------------------------------------------


async def test_purge_state_removes_aged_entries_keeps_fresh(store: MessageStore) -> None:
    # Write two entries at distinct timestamps via two handoffs.
    mid1, r1 = await _route_one_handler(store)
    await store.transform_handoff(
        routed_id=r1,
        message_id=mid1,
        channel_id="IB",
        deliveries=[],
        state_ops=[("ns", "old", "x")],
        now=1_000.0,
    )
    mid2, r2 = await _route_one_handler(store)
    await store.transform_handoff(
        routed_id=r2,
        message_id=mid2,
        channel_id="IB",
        deliveries=[],
        state_ops=[("ns", "new", "y")],
        now=2_000.0,
    )
    purged = await store.purge_state(older_than=1_500.0)
    assert purged == 1
    assert ("ns", "old") not in store.state_view()  # evicted from cache too
    assert store.state_view()[("ns", "new")] == "y"  # fresh one kept
    cur = await store._db.execute("SELECT namespace, key FROM state")
    assert [(r["namespace"], r["key"]) for r in await cur.fetchall()] == [("ns", "new")]


async def test_retention_runner_purges_state(tmp_path: Path) -> None:
    store = await MessageStore.open(tmp_path / "ret.db")
    try:
        mid, routed_id = await _route_one_handler(store)
        await store.transform_handoff(
            routed_id=routed_id,
            message_id=mid,
            channel_id="IB",
            deliveries=[],
            state_ops=[("ns", "k", "v")],
            now=0.0,
        )
        settings = RetentionSettings(state_max_age_days=1)
        runner = RetentionRunner(store, settings)
        # 'now' two days later → the 1-day-old entry is past the cutoff.
        result = await runner.run_once(now=2 * 86_400.0)
        assert result.state_purged == 1
        assert ("ns", "k") not in store.state_view()
    finally:
        await store.close()


# --- backward compatibility (Send-only handlers) -----------------------------


def _registry_with_handler(handle):  # type: ignore[no-untyped-def]
    reg = Registry()
    reg.add_inbound(
        InboundConnection(
            "in",
            ConnectionSpec(ConnectorType.MLLP, {"host": "0.0.0.0", "port": 2575}),
            router="r",
            validation=Validation(strict=False, hl7_version="2.5.1"),
        )
    )
    reg.add_outbound(
        OutboundConnection("out", ConnectionSpec(ConnectorType.FILE, {"directory": "./out"}))
    )
    reg.add_router("r", lambda m: ["h"])
    reg.add_handler("h", handle)
    return reg


def test_send_only_handler_yields_empty_state_ops() -> None:
    def handle(msg: Message) -> Send:
        return Send("out", msg)

    reg = _registry_with_handler(handle)
    deliveries, state_ops, _meta = transform_one(reg, "h", RAW)
    assert len(deliveries) == 1 and state_ops == []


def test_handler_returning_none_yields_no_deliveries_no_state() -> None:
    reg = _registry_with_handler(lambda m: None)
    deliveries, state_ops, _meta = transform_one(reg, "h", RAW)
    assert deliveries == [] and state_ops == []


def test_mixed_send_and_setstate_list_is_partitioned() -> None:
    def handle(msg: Message) -> list:  # type: ignore[type-arg]
        return [Send("out", msg), SetState("ns", "k", "v")]

    reg = _registry_with_handler(handle)
    deliveries, state_ops, _meta = transform_one(reg, "h", RAW)
    assert len(deliveries) == 1
    assert len(state_ops) == 1 and state_ops[0].namespace == "ns"


# --- dry-run resolution + PHI gating -----------------------------------------


def test_dry_run_resolves_state_get_and_captures_ops() -> None:
    def handle(msg: Message) -> list:  # type: ignore[type-arg]
        prior = state_get("patient_anon", "MRN1")  # no active store cache in dry-run
        assert prior is None  # nothing written yet this simulation
        return [Send("out", msg), SetState("patient_anon", "MRN1", "ANON-1")]

    reg = _registry_with_handler(handle)
    result = dry_run(reg, RAW)
    assert result.disposition is MessageStatus.RECEIVED
    assert len(result.state_ops) == 1
    op = result.state_ops[0]
    assert (op.namespace, op.key, op.value) == ("patient_anon", "MRN1", "ANON-1")


def test_dry_run_state_get_sees_earlier_handler_write() -> None:
    # Two handlers, second reads what the first declared (self-consistent simulation).
    def h1(msg: Message) -> SetState:
        return SetState("ns", "k", "from-h1")

    def h2(msg: Message):  # type: ignore[no-untyped-def]
        assert state_get("ns", "k") == "from-h1"
        return Send("out", msg)

    reg = Registry()
    reg.add_inbound(
        InboundConnection(
            "in",
            ConnectionSpec(ConnectorType.MLLP, {"host": "0.0.0.0", "port": 2575}),
            router="r",
            validation=Validation(strict=False, hl7_version="2.5.1"),
        )
    )
    reg.add_outbound(
        OutboundConnection("out", ConnectionSpec(ConnectorType.FILE, {"directory": "./out"}))
    )
    reg.add_router("r", lambda m: ["h1", "h2"])
    reg.add_handler("h1", h1)
    reg.add_handler("h2", h2)
    result = dry_run(reg, RAW)
    assert [op.value for op in result.state_ops] == ["from-h1"]
    assert len(result.deliveries) == 1


async def test_state_op_value_serializes_through_handoff(store: MessageStore) -> None:
    # A dict value round-trips through json.dumps in the handoff and json.loads on read.
    mid, routed_id = await _route_one_handler(store)
    payload = {"mrn": "100", "tags": [1, 2], "active": True, "note": None}
    await store.transform_handoff(
        routed_id=routed_id,
        message_id=mid,
        channel_id="IB",
        deliveries=[],
        state_ops=[("ns", "rec", payload)],
    )
    assert store.state_view()[("ns", "rec")] == payload
    # And the on-disk JSON (identity cipher here) is well-formed.
    cur = await store._db.execute("SELECT value FROM state WHERE namespace='ns' AND key='rec'")
    assert json.loads((await cur.fetchone())[0]) == payload
