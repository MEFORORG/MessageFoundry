# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""B12 / ADR 0061 — per-lane wake events (targeted worker wakeup, DEFAULT-OFF).

The per-stage wake events were engine-wide singletons: one committed message set the whole-stage event
and woke every worker of that stage (the thundering herd). B12 wakes only the committed lane's worker.
It is default-OFF and byte-identical when off (the four singleton events stay the OFF path); when on, a
per-(stage, lane) ``asyncio.Event`` registry with strict get-or-create targets the wake. The 0.25s poll
backstop is unchanged in both arms, so a missed/mis-targeted wake self-heals — at-least-once holds.

Coverage: the wake helpers (OFF singleton / ON target-only / get-or-create identity / _wake_all
stage-selection + all-lanes), the ingress producer targeting (herd killed), end-to-end correctness
PARITY between the OFF and ON arms (incl. fan-out to two outbounds and multi-message FIFO order), and the
env-flag plumbing. The full existing pipeline suite re-run with the flag OFF is the byte-identity proof.
"""

from __future__ import annotations

import asyncio
import os
from pathlib import Path
from typing import Any

import pytest

from messagefoundry.config.models import ConnectorType, ContentType
from messagefoundry.config.wiring import (
    ConnectionSpec,
    InboundConnection,
    OutboundConnection,
    Registry,
    Send,
)
from messagefoundry.parsing.message import Message
from messagefoundry.pipeline.wiring_runner import RegistryRunner
from messagefoundry.store import MessageStatus, MessageStore, Stage

ADT = (
    "MSH|^~\\&|SENDINGAPP|SENDINGFAC|RECV|RFAC|20260604||ADT^A01|{cid}|P|2.5.1\r"
    "EVN|A01|20260604\r"
    "PID|1||100^^^H^MR||DOE^JANE\r"
)


@pytest.fixture
async def store(tmp_path: Path) -> Any:
    s = await MessageStore.open(tmp_path / "plw.db")
    yield s
    await s.close()


# Backend-parametrized store for the store-agnostic end-to-end test. Per-lane wake is ENGINE-side — the
# store sees byte-identical claim/handoff/transform_handoff calls whether the flag is on or off — so this
# is a belt-and-suspenders "delivery works on a real staged store" check. SQLite runs everywhere; Postgres
# is gated like the other server-DB suites (the CI leg sets MEFOR_TEST_POSTGRES).
#
# SQL Server is DELIBERATELY excluded: this is the first test to drive the FULL concurrent-worker pipeline
# with a rapid start()/stop() against a real SQL Server, which non-deterministically SEGFAULTS the
# aioodbc/pyodbc C-extension during teardown-under-cancellation (observed exit 139 on one CI SQL Server
# leg, passing on another). That is a driver issue, NOT a B12 concern — B12 touches no store code, and SQL
# Server's handling of the identical claim/handoff calls is covered by the gated test_sqlserver_store /
# test_seq_only_fifo[sqlserver] suites.
_POSTGRES_ON = bool(os.getenv("MEFOR_TEST_POSTGRES"))


async def _open_sqlite(tmp_path: Path) -> Any:
    return await MessageStore.open(tmp_path / "plw_be.db")


async def _open_postgres(_: Path) -> Any:
    from messagefoundry.config.settings import load_settings
    from messagefoundry.store.postgres import PostgresStore

    s = await PostgresStore.open(load_settings(environ=os.environ).store)
    async with s._pool.acquire() as conn:
        await conn.execute(
            "TRUNCATE message_events, queue, response, delivered_keys, messages RESTART IDENTITY CASCADE"
        )
    await s._load_state_cache()
    await s._load_reference_cache()
    return s


@pytest.fixture(params=["sqlite", "postgres"])
async def pw_store(request: pytest.FixtureRequest, tmp_path: Path) -> Any:
    backend = request.param
    if backend == "postgres" and not _POSTGRES_ON:
        pytest.skip("set MEFOR_TEST_POSTGRES=1 (+ MEFOR_STORE_* env) to run the Postgres case")
    opener = {"sqlite": _open_sqlite, "postgres": _open_postgres}[backend]
    s = await opener(tmp_path)
    try:
        yield s
    finally:
        await s.close()


def _json_inbounds(*names: str) -> Registry:
    """A registry with N non-HL7 (JSON) file inbounds routing nowhere — enough to drive the ingress
    producer (_handle_inbound) and register per-lane events without any delivery machinery."""
    reg = Registry()
    for n in names:
        reg.add_inbound(
            InboundConnection(
                n,
                ConnectionSpec(ConnectorType.FILE, {"directory": "x"}),
                router="r",
                content_type=ContentType.JSON,
            )
        )
    reg.add_router("r", lambda m: [])
    return reg


# --- wake-helper semantics --------------------------------------------------


def test_lane_event_get_or_create_returns_the_same_object(store: MessageStore) -> None:
    """Get-or-create MUST return the SAME Event for a (stage, lane) — never replace it. A replace between
    a producer's set() and the worker's first wait() would drop the sticky set (lost wakeup)."""
    r = RegistryRunner(_json_inbounds("A"), store, per_lane_wake=True)
    e1 = r._lane_event(Stage.INGRESS, "A")
    e2 = r._lane_event(Stage.INGRESS, "A")
    assert e1 is e2
    # A sticky set on the first handle is visible via the second (no replacement dropped it).
    e1.set()
    assert r._lane_event(Stage.INGRESS, "A").is_set()


def test_wake_lane_off_sets_singleton_and_never_populates_registry(store: MessageStore) -> None:
    r = RegistryRunner(_json_inbounds("A"), store, per_lane_wake=False)
    r._wake_lane(Stage.INGRESS, "A")
    assert r._ingress_work.is_set()  # OFF path = the historical singleton
    assert all(len(d) == 0 for d in r._lane_events.values())  # registry never touched when OFF


def test_wake_lane_on_targets_only_that_lane(store: MessageStore) -> None:
    r = RegistryRunner(_json_inbounds("A", "B"), store, per_lane_wake=True)
    r._wake_lane(Stage.INGRESS, "A")
    assert r._lane_event(Stage.INGRESS, "A").is_set()
    assert not r._lane_event(
        Stage.INGRESS, "B"
    ).is_set()  # sibling lane NOT woken — the herd is gone
    assert not r._ingress_work.is_set()  # the singleton is unused when ON


def test_wake_all_on_wakes_every_registered_lane_of_the_stages(store: MessageStore) -> None:
    r = RegistryRunner(_json_inbounds("A"), store, per_lane_wake=True)
    for k in ("d1", "d2", "d3"):
        r._lane_event(Stage.OUTBOUND, k)  # register three idle outbound lanes
    r._lane_event(Stage.INGRESS, "A")
    r._wake_all(Stage.OUTBOUND)  # only OUTBOUND requested
    assert all(r._lane_event(Stage.OUTBOUND, k).is_set() for k in ("d1", "d2", "d3"))
    assert not r._lane_event(Stage.INGRESS, "A").is_set()  # a non-requested stage is untouched


def test_wake_all_off_sets_only_the_passed_stage_singletons(store: MessageStore) -> None:
    """The reload tail passes (INGRESS, ROUTED, OUTBOUND) when OFF (byte-identical to the pre-B12 tail,
    which has always OMITTED _response_work); the RESPONSE-lane wake is an ON-only promptness fix."""
    r = RegistryRunner(_json_inbounds("A"), store, per_lane_wake=False)
    r._wake_all(Stage.INGRESS, Stage.ROUTED, Stage.OUTBOUND)
    assert r._ingress_work.is_set() and r._routed_work.is_set() and r._work.is_set()
    assert not r._response_work.is_set()  # RESPONSE omitted → byte-identical reload tail


def test_wake_all_snapshots_the_registry(store: MessageStore) -> None:
    """_wake_all must snapshot each stage's Event list before iterating (await-free) so a concurrent
    reload/producer mutating _lane_events can't raise 'dict changed size during iteration'."""
    r = RegistryRunner(_json_inbounds("A"), store, per_lane_wake=True)
    for i in range(200):
        r._lane_event(Stage.OUTBOUND, f"d{i}")
    r._wake_all(Stage.OUTBOUND)  # a large registry — must not raise
    assert all(r._lane_event(Stage.OUTBOUND, f"d{i}").is_set() for i in range(200))


# --- ingress producer targeting (via _handle_inbound) -----------------------


async def test_ingress_producer_on_wakes_only_target_lane(store: MessageStore) -> None:
    """Committing an ingress row for inbound A wakes A's router lane and NOT B's (the herd collapse)."""
    reg = _json_inbounds("A", "B")
    r = RegistryRunner(reg, store, per_lane_wake=True)
    await r._handle_inbound(reg.inbound["A"], b'{"n": 1}')
    assert r._lane_event(Stage.INGRESS, "A").is_set()
    assert not r._lane_event(Stage.INGRESS, "B").is_set()
    assert not r._ingress_work.is_set()


async def test_ingress_producer_off_sets_singleton_only(store: MessageStore) -> None:
    reg = _json_inbounds("A", "B")
    r = RegistryRunner(reg, store, per_lane_wake=False)
    await r._handle_inbound(reg.inbound["A"], b'{"n": 1}')
    assert r._ingress_work.is_set()
    assert all(len(d) == 0 for d in r._lane_events.values())


# --- end-to-end correctness PARITY (OFF vs ON) ------------------------------


def _delivery_registry(inbox: Path, out_a: Path, out_b: Path) -> Registry:
    """file_in → router → handler that fans out to TWO file outbounds. Exercises the ingress wake, the
    router→transform ROUTED wake, and the transform→delivery OUTBOUND fan-out (two destinations)."""
    reg = Registry()
    reg.add_outbound(
        OutboundConnection(
            "out_a",
            ConnectionSpec(
                ConnectorType.FILE, {"directory": str(out_a), "filename": "{MSH-10}.hl7"}
            ),
        )
    )
    reg.add_outbound(
        OutboundConnection(
            "out_b",
            ConnectionSpec(
                ConnectorType.FILE, {"directory": str(out_b), "filename": "{MSH-10}.hl7"}
            ),
        )
    )
    reg.add_inbound(
        InboundConnection(
            "file_in",
            ConnectionSpec(
                ConnectorType.FILE,
                {"directory": str(inbox), "pattern": "*.hl7", "poll_seconds": 0.02},
            ),
            router="r",
        )
    )
    reg.add_router("r", lambda m: ["h"])

    def handle(msg: Message) -> list[Send]:
        return [Send("out_a", msg), Send("out_b", msg)]

    reg.add_handler("h", handle)
    return reg


async def _until(predicate: Any, timeout: float = 3.0) -> None:
    elapsed = 0.0
    while not await predicate():
        await asyncio.sleep(0.02)
        elapsed += 0.02
        if elapsed > timeout:
            raise AssertionError("condition not met within timeout")


@pytest.mark.parametrize("per_lane_wake", [False, True])
async def test_end_to_end_fanout_delivers_both_arms(
    pw_store: Any, tmp_path: Path, per_lane_wake: bool
) -> None:
    """A message fanned out to two outbounds is PROCESSED and delivered to BOTH — identically with the
    flag OFF and ON, on every backend. Proves the per-lane fan-out wakes (or the poll backstop drains)
    every destination lane; correctness is unchanged by the wake strategy or the store."""
    inbox, out_a, out_b = tmp_path / "in", tmp_path / "a", tmp_path / "b"
    inbox.mkdir()
    (inbox / "m.hl7").write_bytes(ADT.format(cid="MSG1").encode("utf-8"))
    reg = _delivery_registry(inbox, out_a, out_b)
    r = RegistryRunner(reg, pw_store, poll_interval=0.02, per_lane_wake=per_lane_wake)
    await r.start()
    try:
        await _until(lambda: _processed(pw_store))
    finally:
        await r.stop()
    assert (out_a / "MSG1.hl7").exists() and (out_b / "MSG1.hl7").exists()  # both destinations
    msgs = await pw_store.list_messages(channel_id="file_in")
    assert len(msgs) == 1 and msgs[0]["status"] == MessageStatus.PROCESSED.value


async def _processed(store: MessageStore) -> bool:
    return bool(
        await store.list_messages(channel_id="file_in", status=MessageStatus.PROCESSED.value)
    )


async def test_multi_message_fifo_order_preserved_under_per_lane_wake(
    store: MessageStore, tmp_path: Path
) -> None:
    """Three messages into one inbound, delivered in strict arrival (seq) order under per-lane wake —
    B12 changes only WHEN a worker wakes, never the FIFO claim (#285 / ADR 0059)."""
    inbox, out_a, out_b = tmp_path / "in", tmp_path / "a", tmp_path / "b"
    inbox.mkdir()
    reg = _delivery_registry(inbox, out_a, out_b)
    r = RegistryRunner(reg, store, poll_interval=0.02, per_lane_wake=True)
    await r.start()
    try:
        for i in range(3):
            (inbox / f"m{i}.hl7").write_bytes(ADT.format(cid=f"MSG{i}").encode("utf-8"))
            await asyncio.sleep(0.05)  # keep arrival order deterministic
        # Poll the ACTUAL asserted condition — all 3 messages finalized to PROCESSED — not a proxy like
        # "N outbound rows DONE" (each message fans out to 2, so that proxy trips at 1.5 messages; it
        # false-greened on a fast runner and flaked on a slow one — mf-ci-test-flakes).
        await _until(lambda: _n_processed(store, 3))
    finally:
        await r.stop()
    # Every message reached PROCESSED under per-lane wake, in arrival (ingest = rowid = seq) order —
    # B12 leaves the FIFO claim untouched; only the wake timing differs (#285 / ADR 0059).
    msgs = await store.list_messages(channel_id="file_in")
    assert len(msgs) == 3 and all(m["status"] == MessageStatus.PROCESSED.value for m in msgs)
    cur = await store._db.execute(
        "SELECT control_id FROM messages WHERE channel_id=? ORDER BY rowid", ("file_in",)
    )
    assert [row["control_id"] for row in await cur.fetchall()] == ["MSG0", "MSG1", "MSG2"]


async def _n_processed(store: MessageStore, n: int) -> bool:
    return (
        len(await store.list_messages(channel_id="file_in", status=MessageStatus.PROCESSED.value))
        >= n
    )


# --- env-flag plumbing (AC-12) ----------------------------------------------


def test_env_flag_parses_and_defaults_off() -> None:
    from messagefoundry.config.settings import load_settings

    assert load_settings(environ={}).pipeline.per_lane_wake is False
    assert (
        load_settings(environ={"MEFOR_PIPELINE_PER_LANE_WAKE": "true"}).pipeline.per_lane_wake
        is True
    )
