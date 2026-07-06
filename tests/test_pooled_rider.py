# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""ADR 0066 §8 pooled-mode MERGE RIDER — the end-to-end ``RegistryRunner``-through-pooled proofs.

These are the merge oracle for ``claim_mode=pooled`` (default-OFF). Pooled mode's correctness can
only be proven on a **server DB**: SQLite's process-wide write lock serializes away the concurrent
stage interleavings pooled mode introduces (many lanes multiplexed onto one claimer pool + a
clock-driven sweep/park-timer + ephemeral per-lane serializers). So every test here runs under the
SHARED backend-parametrized ``store`` fixture (sqlite always; sqlserver / postgres gated on
``MEFOR_TEST_*``) — the CI SS + PG legs are where these actually bite. Each drives a real
``RegistryRunner`` built with ``claim_mode="pooled"`` (``require_rcsi_for_pooled=False`` so the SS
leg exercises functional correctness even where the CI DB lacks RCSI — the RCSI fail-closed gate is
tested elsewhere), so the pooled StageDispatchers, the pooled finalizer, and the per-lane serializer
carry the whole path — no ``StageDispatcher`` unit stubs.

Rows covered (ADR 0066 §8):

* **Row 8** (fan-out finalize, BOTH modes) — a message routed to >=2 outbounds must WITHHOLD
  ``PROCESSED`` until ALL destinations resolve. A GATED, IN-BAND oracle: one lane is held INFLIGHT in
  a gate while the other delivers, and the test asserts — WITH the gate still held — that the message
  is still ``ROUTED`` (a finalizer that finalized on the delivered lane alone would show ``PROCESSED``
  here; the held gate stops that premature ``PROCESSED`` from self-healing). Run identical under
  ``claim_mode="per_lane"`` AND ``"pooled"``. The most important row: it drives the pooled finalizer
  (single store authority) + the per-lane serializer end-to-end on a server DB, and the same gated
  shape proves the single OUTBOUND dispatcher multiplexes both lanes without head-of-line block or
  starving the parked one.
* **Row 2** (crash / cancel-replay, at-least-once) — a pooled runner strands an OUTBOUND head
  INFLIGHT at ``stop()`` (crash), then a FRESH pooled runner + ``reset_stale_inflight`` replays it:
  NO loss, NO duplicate, and NO per-lane FIFO overtake (the reclaimed head delivers before its lane
  successors).
* **Row 3** (retry-schedule e2e, REAL clock) — a transient delivery failure on an otherwise-idle
  lane retries ON the backoff schedule under pooled mode. Pooled mode has NO per-lane armed retry
  wake (``_mark_failed_and_arm`` skips it); the pooled dispatcher's own clock-driven mechanism (the
  per-lane PARK timer armed at the row's ``next_attempt_at``, backstopped by the sweep) re-drives the
  due-but-idle lane. No ManualClock — the store computes ``next_attempt_at`` on its own real clock.
* **Row 6** (sharding shard-filter, mandatory today) — two dispatchers over disjoint lane sets on ONE
  shared store: every claimed row's lane stays in the claiming engine's set, neither engine's sweep
  readies the other shard's lanes, and foreign-lane ``attempts`` are never touched.
* **Row 7** (H1 fencing pooled) — a paused ex-leader's pooled claim matches 0 rows across ALL its
  lanes (the epoch guard rides ``claim_fifo_heads``' probe AND UPDATE); after promotion it drains
  every lane.

**Altitude — rows 6/7 are DISPATCHER-level, not full-``RegistryRunner``.** Rows 2/3/8 exercise the
finalizer + per-lane serializer end-to-end, so they drive a real runner. Rows 6/7 instead target two
seams that live entirely in the ``StageDispatcher`` + ``claim_fifo_heads``, not the finalizer: the
**explicit-lane-set shard filter** (ADR 0066 §3.1 — the claim only ever sees the caller's lane subset)
and the **sweep's registry intersection** (§4.4 — ``list_fifo_lanes`` is store-wide, the dispatcher
filters). Two ``StageDispatcher``s with disjoint ``lane_provider``s over one store isolate both seams
deterministically; two full runners would add listeners/finalizer machinery that never touch the
shard-scoping/fence seam and whose concurrency is nondeterministic. So rows 6/7 inject a tiny recording
``process_item`` stub (like ``test_stage_dispatcher.py``) and drive discovery explicitly with a huge
``sweep_interval`` + awaited ``_run_sweep_once`` — which also keeps them SS-teardown-safe (the only
``list_fifo_lanes``/``claim_fifo_heads`` executes are ones the test awaits to completion, so ``stop()``
never cancels one mid-``cur.execute``; every dispatcher task is parked on a pure-asyncio Event at stop).
The H1 fence is a **no-op on SQLite** (single active node — ``set_leader_epoch`` ignores its argument),
so row 7's SQLite parametrization is a structural check (fence correctly disabled → drains normally);
the authoritative fencing coverage is the SS + PG CI legs (which seed the ``leader_lease`` epoch).

**SQL Server teardown discipline (load-bearing).** ``runner.stop()`` HARD-CANCELS its workers; on the
aioodbc backend a task cancelled mid-``cur.execute`` (the pooled clock-driven sweep does a periodic
``list_fifo_lanes`` read; a per_lane worker does periodic empty claims) tears the connection down while
the pyodbc call runs on its executor thread — the documented exit-139 / access-violation teardown
crash — and a cancel mid-WRITE-transaction additionally strands locks on a poisoned pooled connection
(the next statement then blocks to a query-timeout). Two disciplines defuse this, both no-ops off SQL
Server:

1. **Quiesce before stopping** — every test polls to a settled state (the OUTBOUND rows exist / all
   PROCESSED), so nothing is mid-write-transaction when stop lands; at that quiescence the pooled
   sweep's only activity is a READ that claims nothing (no write lock to strand), so a crash-strand's
   ``reset_stale_inflight`` never blocks on a poisoned connection.
2. **Graceful stop** (``_stop_quiesced``) — SET the shared ``_stop`` and wait past one poll/sweep
   interval FIRST, so every ``while not self._stop.is_set()`` loop finishes its in-flight execute and
   EXITS on its own rather than being cancelled mid-call; only then ``runner.stop()`` (which now cancels
   already-exited loops and Event-parked tasks — a clean cancel), plus a short trailing executor drain.

No hashlib/hmac/secrets/ssl here (crypto-inventory gate)."""

from __future__ import annotations

import asyncio
import os
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Any, AsyncIterator

import pytest

from messagefoundry.config.models import ConnectorType, RetryPolicy
from messagefoundry.config.wiring import (
    ConnectionSpec,
    InboundConnection,
    OutboundConnection,
    Registry,
    Send,
)
from messagefoundry.pipeline.stage_dispatcher import (
    LaneItemResult,
    LaneResultKind,
    StageDispatcher,
)
from messagefoundry.pipeline.wiring_runner import RegistryRunner
from messagefoundry.store import MessageStatus, MessageStore, OutboxItem, OutboxStatus, Stage
from messagefoundry.transports.base import DeliveryError, DestinationConnector

ADT = (
    "MSH|^~\\&|SENDINGAPP|SENDINGFAC|RECV|RFAC|20260604||ADT^A01|{cid}|P|2.5.1\r"
    "EVN|A01|20260604\r"
    "PID|1||100^^^H^MR||DOE^JANE\r"
)

_SQLSERVER_ON = bool(os.getenv("MEFOR_TEST_SQLSERVER"))
_POSTGRES_ON = bool(os.getenv("MEFOR_TEST_POSTGRES"))


# --- backend-parametrized store fixture (verbatim from test_stage_dispatcher.py) ------------------


async def _open_sqlite(tmp_path: Path) -> MessageStore:
    return await MessageStore.open(tmp_path / "pooled_rider.db")


async def _open_sqlserver(tmp_path: Path) -> Any:
    from messagefoundry.config.settings import load_settings
    from messagefoundry.store.sqlserver import SqlServerStore

    settings = load_settings(environ=os.environ).store
    s = await SqlServerStore.open(settings)
    async with s._pool.acquire() as conn:
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


async def _open_postgres(tmp_path: Path) -> Any:
    from messagefoundry.config.settings import load_settings
    from messagefoundry.store.postgres import PostgresStore

    settings = load_settings(environ=os.environ).store
    s = await PostgresStore.open(settings)
    async with s._pool.acquire() as conn:
        await conn.execute(
            "TRUNCATE message_events, queue, response, delivered_keys, messages"
            " RESTART IDENTITY CASCADE"
        )
    await s._load_state_cache()
    await s._load_reference_cache()
    return s


@pytest.fixture(params=["sqlite", "sqlserver", "postgres"])
async def store(request: pytest.FixtureRequest, tmp_path: Path) -> AsyncIterator[Any]:
    backend = request.param
    if backend == "sqlserver" and not _SQLSERVER_ON:
        pytest.skip("set MEFOR_TEST_SQLSERVER=1 (+ MEFOR_STORE_* env) to run the SQL Server case")
    if backend == "postgres" and not _POSTGRES_ON:
        pytest.skip("set MEFOR_TEST_POSTGRES=1 (+ MEFOR_STORE_* env) to run the Postgres case")
    opener = {"sqlite": _open_sqlite, "sqlserver": _open_sqlserver, "postgres": _open_postgres}[
        backend
    ]
    s = await opener(tmp_path)
    s._test_backend = backend  # tag so a test can branch on backend-specific access
    try:
        yield s
    finally:
        await s.close()


# --- recording connectors + a real-clock poller ---------------------------------------------------


class _Recorder(DestinationConnector):
    """A test outbound that records the payloads it 'delivered' (non-capturing -> the row is
    marked done). Overriding ``send`` with a narrower ``-> None`` return is a valid override of the
    base ``-> DeliveryResponse | None``."""

    def __init__(self) -> None:
        self.payloads: list[str] = []

    async def send(self, payload: str) -> None:
        self.payloads.append(payload)
        return None

    async def aclose(self) -> None:
        return None


class _GateConnector(DestinationConnector):
    """Parks EVERY send on a ``release`` Event, signalling ``entered`` when the OUTBOUND head reaches
    ``send`` (so the row is INFLIGHT). It records the first payload BEFORE parking (so a test can
    assert which row is stranded). Two consumers:

    * **Row 8** SETS ``release`` once it has asserted the gated intermediate state — the parked send
      then returns (delivered → the outbox row goes DONE), so the finalizer can advance to PROCESSED.
    * **Row 2** never sets ``release``, so the send parks until ``runner.stop()`` CANCELS it — a
      faithful crash-with-inflight-head that strands the row INFLIGHT via the store's already-committed
      claim.

    The park is a PURE-PYTHON await (no open store transaction), so cancelling it neither loses the
    claim nor poisons the SS connection."""

    def __init__(self) -> None:
        self.entered = asyncio.Event()
        # set() -> the parked send delivers (Row 8); left unset -> parks until cancelled (Row 2 crash).
        self.release = asyncio.Event()
        self.first_payload: str | None = None

    async def send(self, payload: str) -> None:
        if self.first_payload is None:
            self.first_payload = payload
        self.entered.set()
        # park INFLIGHT: Row 8 releases -> delivered; Row 2 cancels the parked task -> crash-strand.
        await self.release.wait()
        return None

    async def aclose(self) -> None:
        return None


class _FlakyConnector(DestinationConnector):
    """Fails ``fail_times`` sends with a transient DeliveryError, then delivers. Drives the retry
    path — each failure re-pends the row with backoff, and (pooled) the dispatcher's park timer /
    sweep re-drives the due-but-idle lane."""

    def __init__(self, fail_times: int) -> None:
        self.fail_times = fail_times
        self.calls = 0
        self.payloads: list[str] = []
        # Loop-clock timestamp of each send attempt (fail or success) — lets Row 3 assert the retry
        # honored the backoff schedule (the gap from the last failing attempt to success >= backoff).
        self.call_times: list[float] = []

    async def send(self, payload: str) -> None:
        self.calls += 1
        self.call_times.append(asyncio.get_running_loop().time())
        if self.calls <= self.fail_times:
            raise DeliveryError("transient partner outage (pooled rider test)")
        self.payloads.append(payload)
        return None

    async def aclose(self) -> None:
        return None


async def _until(pred: Callable[[], Awaitable[bool]], *, timeout: float = 30.0) -> None:
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    while loop.time() < deadline:
        if await pred():
            return
        await asyncio.sleep(0.02)
    raise AssertionError("timed out waiting for condition")


async def _ready(event: asyncio.Event) -> bool:
    return event.is_set()


def _make_runner(
    reg: Registry, store: Any, *, mode: str, sweep: float = 0.05, **extra: Any
) -> RegistryRunner:
    """Construct a RegistryRunner in ``per_lane`` or ``pooled`` mode. Pooled passes
    ``require_rcsi_for_pooled=False`` (functional correctness, not the RCSI gate). ``sweep`` is small
    (the pooled dispatchers still need the sweep to drive a STATIC backlog / retry backstop and to
    keep forward progress snappy). The SQL Server teardown safety does NOT rest on the sweep interval
    — it rests on QUIESCING before ``stop()`` (so no worker is cancelled mid-write-transaction: at a
    quiescent stop the only sweep activity is a read that claims nothing) plus ``_stop_quiesced``'s
    executor-thread drain."""
    if mode == "pooled":
        return RegistryRunner(
            reg,
            store,
            claim_mode="pooled",
            pooled_sweep_interval=sweep,
            require_rcsi_for_pooled=False,
            **extra,
        )
    return RegistryRunner(reg, store, claim_mode="per_lane", **extra)


async def _stop_quiesced(runner: RegistryRunner, store: Any) -> None:
    """Stop a runner whose pipeline is already QUIESCENT, WITHOUT the aioodbc cancel-mid-execute crash.

    ``runner.stop()`` hard-CANCELS its tasks; on aioodbc a task cancelled mid-``cur.execute`` (the
    pooled clock-driven sweep does a periodic ``list_fifo_lanes`` read; a per_lane worker does periodic
    empty claims) tears the connection down while the pyodbc call runs on its executor thread — the
    documented exit-139 / access-violation teardown crash. So first SET the shared ``_stop`` (the same
    Event the dispatchers/workers were built with) and wait past one poll/sweep interval: every loop is
    ``while not self._stop.is_set()``, so each finishes any in-flight execute and EXITS gracefully
    rather than being cancelled mid-call. ``stop()`` then only cancels already-exited loops and tasks
    parked on an Event (a clean cancel). A trailing SS settle drains any last executor thread before
    the fixture closes the pool. All no-ops off SQL Server (SQLite/asyncpg don't have this hazard)."""
    runner._stop.set()
    await asyncio.sleep(0.35)  # > pooled sweep interval AND the per_lane idle backstop
    await runner.stop()
    if getattr(store, "_test_backend", None) == "sqlserver":
        await asyncio.sleep(0.2)


def _assert_rcsi_not_degraded(runner: RegistryRunner, store: Any) -> None:
    """Guard the merge oracle on a SERVER DB: the pooled path must run under the concurrent
    snapshot-read semantics it exists to prove — SQL Server's ``READ_COMMITTED_SNAPSHOT`` — NOT
    silently degraded to ``READ_COMMITTED``.

    The runner is built with ``require_rcsi_for_pooled=False`` so the SS leg does not fail-close on a
    CI DB that lacks RCSI. But if the DB actually had RCSI OFF, the pooled dispatchers would run under
    ``READ_COMMITTED``, whose blocking read serializes away the concurrent stage interleavings the
    rider asserts (much like SQLite's write lock) — and the whole suite would still report GREEN
    without ever exercising them. ``RegistryRunner._rcsi_off_degraded`` is set True exactly in that
    downgrade (see :meth:`RegistryRunner._start_pooled_dispatchers`); assert it stayed False so a
    future RCSI-off server box can never silently hollow out these proofs.

    A no-op on SQLite (RCSI is not a concept; the fail-closed gate never runs). On Postgres it is
    trivially satisfied (plain MVCC snapshots, the gate is a no-op) but kept as a cheap regression
    guard."""
    if getattr(store, "_test_backend", None) == "sqlite":
        return
    assert runner._rcsi_off_degraded is False, (
        "pooled mode fell back to RCSI-off-degraded: the merge oracle would run under READ_COMMITTED "
        "and serialize away the concurrent interleavings it exists to prove"
    )


# =================================================================================================
# ROW 8 — fan-out finalize (BOTH modes): >=2 handlers/outbounds, finalize once ALL resolve
# =================================================================================================


def _fanout_registry(inbox: Path, out_a_dir: Path, out_b_dir: Path) -> Registry:
    """One FILE inbound -> a router selecting TWO handlers -> each handler sends to its OWN outbound.
    The FILE outbounds are swapped for recording collectors before any traffic, so the dirs are never
    touched; they only need to build at start()."""
    reg = Registry()
    reg.add_inbound(
        InboundConnection(
            "file_in",
            ConnectionSpec(
                ConnectorType.FILE,
                {"directory": str(inbox), "pattern": "*.hl7", "poll_seconds": 0.05},
            ),
            router="r",
        )
    )
    reg.add_outbound(
        OutboundConnection(
            "out_a",
            ConnectionSpec(
                ConnectorType.FILE, {"directory": str(out_a_dir), "filename": "{MSH-10}.hl7"}
            ),
        )
    )
    reg.add_outbound(
        OutboundConnection(
            "out_b",
            ConnectionSpec(
                ConnectorType.FILE, {"directory": str(out_b_dir), "filename": "{MSH-10}.hl7"}
            ),
        )
    )
    reg.add_router("r", lambda m: ["h_a", "h_b"])  # fan-out to BOTH handlers
    reg.add_handler("h_a", lambda m: Send("out_a", m))
    reg.add_handler("h_b", lambda m: Send("out_b", m))
    return reg


@pytest.mark.parametrize("mode", ["per_lane", "pooled"])
async def test_row8_fanout_finalize_both_modes(store: Any, tmp_path: Path, mode: str) -> None:
    """A single message fans out to two outbound lanes; the finalizer must WITHHOLD ``PROCESSED``
    until BOTH lanes resolve. This is a GATED, IN-BAND oracle for that withhold-until-all-resolve
    invariant — not just an end-state check.

    ``out_a`` is a fast recorder; ``out_b`` is a gate whose delivery PARKS the row INFLIGHT until the
    test releases it. Once ``out_a`` is DONE and ``out_b`` is INFLIGHT, the test asserts — WHILE the
    gate is still held — that the message is still ``ROUTED`` (NOT ``PROCESSED``). THIS is the
    assertion that catches a broken/premature finalizer: the store finalizer re-derives disposition on
    every terminal transition with NO terminal latch, so a premature ``PROCESSED`` would self-heal on
    the next transition and an end-state-only check would miss it — but the held gate FREEZES the
    intermediate state, so a finalizer that wrongly finalized on ``out_a`` alone would show
    ``PROCESSED`` here and this assertion fails. (The single-authority :meth:`_maybe_finalize_message`
    returns early while any row is PENDING/INFLIGHT, so a correct finalizer leaves it ``ROUTED``.)

    Then the gate is released and the message must reach ``PROCESSED`` with both outbox rows DONE.

    Pooled-specific property proven by the SAME gated shape: the two lanes are drained by ONE OUTBOUND
    StageDispatcher (multiplexed, not one worker per outbound). Reaching the gated state at all
    requires the dispatcher to deliver ``out_a`` WHILE ``out_b``'s lane is parked (no head-of-line
    block), and reaching ``PROCESSED`` after release requires it to re-serve the parked lane without
    dropping/starving it — else the two bounded ``_until`` waits time out. On SQLite the single write
    lock never lets the two lanes drain concurrently, so only the SS/PG legs prove that.

    Runs under BOTH claim modes so the pooled fan-out finalize is proven identical to per_lane.
    """
    inbox, out_a_dir, out_b_dir = tmp_path / "in", tmp_path / "a", tmp_path / "b"
    for d in (inbox, out_a_dir, out_b_dir):
        d.mkdir()
    runner = _make_runner(_fanout_registry(inbox, out_a_dir, out_b_dir), store, mode=mode)
    await runner.start()
    # Non-vacuity sentinel: pooled builds one dispatcher per core stage (the fan-out delivery + finalize
    # really run through the pooled path); per_lane builds none (byte-identical to today's topology).
    if mode == "pooled":
        assert set(runner._dispatchers) == {Stage.INGRESS, Stage.ROUTED, Stage.OUTBOUND}
    else:
        assert runner._dispatchers == {}
    # Server DB: the oracle must run under RCSI, not silently degraded to READ_COMMITTED.
    _assert_rcsi_not_degraded(runner, store)
    col_a = _Recorder()  # out_a = fast recorder (delivers immediately)
    gate = _GateConnector()  # out_b = gate (delivery parks INFLIGHT until released)
    runner._destinations["out_a"] = col_a  # swap in before any traffic
    runner._destinations["out_b"] = gate
    try:
        await runner._handle_inbound(
            runner.registry.inbound["file_in"], ADT.format(cid="MID8").encode()
        )

        async def _gated() -> bool:
            # out_a delivered (DONE) AND out_b claimed + parked in the gate (INFLIGHT).
            msgs = await store.list_messages()
            if len(msgs) != 1:
                return False
            rows = await store.outbox_for(msgs[0]["id"])
            by_dest = {r["destination_name"]: r["status"] for r in rows}
            return by_dest == {
                "out_a": OutboxStatus.DONE.value,
                "out_b": OutboxStatus.INFLIGHT.value,
            }

        await _until(_gated)  # out_a DONE, out_b parked INFLIGHT (the frozen intermediate state)

        try:
            # IN-BAND ORACLE: with out_a DONE and out_b still INFLIGHT the message MUST NOT yet be
            # finalized — a finalizer that declared PROCESSED on out_a alone would already show
            # PROCESSED here (the held gate stops that premature PROCESSED from self-healing). It must
            # still be ROUTED.
            msgs = await store.list_messages()
            mid = msgs[0]["id"]
            assert msgs[0]["status"] == MessageStatus.ROUTED.value, msgs[0]["status"]
            rows = await store.outbox_for(mid)
            by_dest = {r["destination_name"]: r["status"] for r in rows}
            assert by_dest == {
                "out_a": OutboxStatus.DONE.value,
                "out_b": OutboxStatus.INFLIGHT.value,
            }, by_dest
        finally:
            # Release even on assert-failure so the parked gate-send can never leak and hang the live
            # SS pool teardown (the gate parks on a pure-Python Event, so this simply lets it deliver).
            gate.release.set()

        async def _processed() -> bool:
            msgs = await store.list_messages()
            return len(msgs) == 1 and msgs[0]["status"] == MessageStatus.PROCESSED.value

        await _until(_processed)  # gate released -> both lanes resolve -> finalize PROCESSED

        msgs = await store.list_messages()
        mid = msgs[0]["id"]
        # Both lanes delivered exactly once (out_a via the recorder, out_b via the released gate).
        assert len(col_a.payloads) == 1, col_a.payloads
        assert gate.first_payload is not None and "MID8" in gate.first_payload, gate.first_payload
        # Exactly one outbox row per destination, BOTH terminal-done — the finalizer waited for the
        # WHOLE fan-out before PROCESSED (the withhold-until-all-resolve invariant, end state).
        rows = await store.outbox_for(mid)
        by_dest = {r["destination_name"]: r["status"] for r in rows}
        assert by_dest == {
            "out_a": OutboxStatus.DONE.value,
            "out_b": OutboxStatus.DONE.value,
        }, by_dest
    finally:
        gate.release.set()  # idempotent backstop: never leave the gate parked into teardown
        await _stop_quiesced(runner, store)


# =================================================================================================
# ROW 2 — crash / cancel-replay (at-least-once): strand an OUTBOUND head, replay on a fresh runner
# =================================================================================================


def _single_out_registry(inbox: Path, out_dir: Path) -> Registry:
    reg = Registry()
    reg.add_inbound(
        InboundConnection(
            "file_in",
            ConnectionSpec(
                ConnectorType.FILE,
                {"directory": str(inbox), "pattern": "*.hl7", "poll_seconds": 0.05},
            ),
            router="r",
        )
    )
    reg.add_outbound(
        OutboundConnection(
            "out_a",
            ConnectionSpec(
                ConnectorType.FILE, {"directory": str(out_dir), "filename": "{MSH-10}.hl7"}
            ),
        )
    )
    reg.add_router("r", lambda m: ["h"])
    reg.add_handler("h", lambda m: Send("out_a", m))
    return reg


async def test_row2_pooled_crash_replay_no_loss_no_fifo_overtake(
    store: Any, tmp_path: Path
) -> None:
    """Three messages on ONE outbound lane. A pooled runner claims the head (MID001) into delivery,
    which BLOCKS (INFLIGHT); ``stop()`` simulates a crash mid-delivery, leaving that head INFLIGHT
    (pooled ``stop`` never ``release_claimed``s a cancelled serializer — crash-safety). A FRESH pooled
    runner + the engine's startup ``reset_stale_inflight`` replays it.

    Assert at-least-once with NO loss / NO duplicate (exactly 3 deliveries on the fresh recorder) and
    NO per-lane FIFO overtake (the reclaimed head MID001 delivers BEFORE its lane successors MID002,
    MID003).

    Pooled-specific interleaving: the OUTBOUND lane's head is stranded INFLIGHT under the pooled
    dispatcher; on restart the pooled claimer's ``claim_fifo_heads`` (seq-ordered, head-first) plus
    the reset re-pend (which restores the head's due-now, lowest-seq position) must re-serve MID001
    ahead of the PENDING MID002/MID003 that sit behind it. Under a broken pooled reclaim (head skipped
    / a successor pulled forward) the delivered order would not equal [MID001, MID002, MID003]. On
    SQLite the single writer never lets a successor race the head, so only SS/PG prove the ordered
    failover reclaim.
    """
    cids = ["MID001", "MID002", "MID003"]
    inbox, out_dir = tmp_path / "in", tmp_path / "out"
    inbox.mkdir()
    out_dir.mkdir()

    # --- run 1: strand the head INFLIGHT, then "crash" -------------------------------------------
    runner1 = _make_runner(_single_out_registry(inbox, out_dir), store, mode="pooled")
    await runner1.start()
    try:
        assert set(runner1._dispatchers) == {
            Stage.INGRESS,
            Stage.ROUTED,
            Stage.OUTBOUND,
        }  # pooled engaged
        # Server DB: the crash-replay proof must run under RCSI, not degraded.
        _assert_rcsi_not_degraded(runner1, store)
        gate = _GateConnector()
        runner1._destinations["out_a"] = gate  # blocks the head's delivery
        ic = runner1.registry.inbound["file_in"]
        for cid in cids:
            await runner1._handle_inbound(ic, ADT.format(cid=cid).encode())

        # Quiesce to the crash state: all three transforms have COMMITTED their OUTBOUND rows (so no
        # ROUTED->OUTBOUND handoff is mid-write-transaction — a cancel there would strand an X lock and
        # block the reset below to a query-timeout) AND the head is INFLIGHT in delivery (blocked in a
        # pure-Python send). Message status alone (ROUTED) is set at INGRESS->ROUTED and does NOT prove
        # the later transform committed, so poll the actual OUTBOUND rows. At that quiescence the
        # OUTBOUND lane is PROCESSING (the sweep only marks it dirty, claims nothing), so stop() is a
        # clean cancel that strands exactly the head — no write transaction to poison the reset.
        async def _all_outbound_rows_exist() -> bool:
            msgs = await store.list_messages()
            if len(msgs) != 3:
                return False
            total = 0
            for m in msgs:
                total += len(await store.outbox_for(m["id"]))
            return total == 3

        await _until(_all_outbound_rows_exist)
        await _until(lambda: _ready(gate.entered))
        assert gate.first_payload is not None and "MID001" in gate.first_payload
    finally:
        # Guarded start..stop: if any assert above raised, run-1's tasks (incl. the parked gate-send)
        # must not leak into the live SS pool teardown. On the success path this IS the "crash" that
        # strands the OUTBOUND head INFLIGHT (the gate is never released, so stop() cancels it).
        await _stop_quiesced(runner1, store)

    # --- restart recovery: what the Engine runs before runner.start() ----------------------------
    recovered = await store.reset_stale_inflight()
    assert recovered >= 1  # at least the stranded OUTBOUND head was re-pended

    # --- run 2: a fresh pooled runner replays the recovered backlog to the REAL outbound ----------
    # No connector swap here: the runner already has pending OUTBOUND rows, so its claimer can deliver
    # the head DURING start() — before any post-start swap could land (a race). Instead let the built
    # FILE outbound deliver all three and verify the replay from the STORE (race-free + deterministic).
    # The recovered rows are a STATIC backlog (no producer wakes them), so draining the tail after each
    # head is the SWEEP's job — the pooled at-least-once backstop after a crash; the small default sweep
    # drains it.
    runner2 = _make_runner(_single_out_registry(inbox, out_dir), store, mode="pooled")
    await runner2.start()
    try:
        _assert_rcsi_not_degraded(runner2, store)  # server DB: the replay proof must run under RCSI

        async def _all_processed() -> bool:
            msgs = await store.list_messages(status=MessageStatus.PROCESSED.value)
            return len(msgs) == 3

        await _until(_all_processed)
    finally:
        await _stop_quiesced(runner2, store)

    # No loss / no duplicate: every message finalized PROCESSED with EXACTLY ONE delivered OUTBOUND row.
    msgs = await store.list_messages()
    assert {m["control_id"] for m in msgs} == set(cids), msgs
    delivered_event_id: dict[str, int] = {}
    for m in msgs:
        rows = await store.outbox_for(m["id"])
        assert len(rows) == 1 and rows[0]["status"] == OutboxStatus.DONE.value, rows
        delivered = [e for e in await store.events_for(m["id"]) if e["event"] == "delivered"]
        assert len(delivered) == 1, delivered  # delivered exactly once — no duplicate
        delivered_event_id[m["control_id"]] = delivered[0]["id"]
    # Per-lane FIFO preserved across failover: the reclaimed head delivered BEFORE its lane successors.
    # ``message_events.id`` is monotonic in delivery order (autoincrement/IDENTITY/SERIAL), so a
    # successor overtaking the reclaimed head would invert this ordering.
    assert (
        delivered_event_id["MID001"] < delivered_event_id["MID002"] < delivered_event_id["MID003"]
    ), delivered_event_id
    # The real outbound actually received all three (one file per control id).
    assert {p.stem for p in out_dir.glob("*.hl7")} == set(cids)


# =================================================================================================
# ROW 3 — retry-schedule e2e (REAL clock): the pooled clock-driven backstop re-drives an idle lane
# =================================================================================================


async def test_row3_pooled_retry_schedule_real_clock(store: Any, tmp_path: Path) -> None:
    """A delivery fails twice transiently on an otherwise-idle lane; under pooled mode the message
    must still deliver on the ~0.2 s backoff schedule and finalize PROCESSED. There is NO ManualClock:
    the store computes ``next_attempt_at`` on its own real clock. Pooled mode has NO per-lane armed
    retry wake (``_mark_failed_and_arm`` skips arming under pooled), so the retry is re-driven by the
    pooled dispatcher's OWN clock-driven mechanism — the per-lane PARK timer armed at the row's
    ``next_attempt_at`` (backstopped by the ``pooled_sweep_interval`` sweep) — not by a per-lane wake.

    Pooled-specific interleaving: after each transient failure the OUTBOUND lane PARKs on the row's
    re-pended ``next_attempt_at``; the clock-driven timer/sweep unparks + re-claims the head when the
    backoff elapses. If that clock-driven backstop were broken, the retry would never fire and this
    test would time out (pooled mode has no short idle re-poll to mask it). SQLite serializes the
    sweep against the idle writer, so only SS/PG prove the concurrent clock-driven backstop.
    """
    inbox, out_dir = tmp_path / "in", tmp_path / "out"
    inbox.mkdir()
    out_dir.mkdir()
    runner = _make_runner(
        _single_out_registry(inbox, out_dir),
        store,
        mode="pooled",  # small default sweep exercises the clock-driven retry backstop
        delivery_defaults=RetryPolicy(backoff_seconds=0.2, backoff_multiplier=1.0),
    )
    await runner.start()
    assert set(runner._dispatchers) == {
        Stage.INGRESS,
        Stage.ROUTED,
        Stage.OUTBOUND,
    }  # pooled engaged
    # Server DB: the retry-schedule proof must run under RCSI, not degraded.
    _assert_rcsi_not_degraded(runner, store)
    flaky = _FlakyConnector(fail_times=2)
    runner._destinations["out_a"] = flaky
    try:
        await runner._handle_inbound(
            runner.registry.inbound["file_in"], ADT.format(cid="MID3").encode()
        )

        async def _processed() -> bool:
            msgs = await store.list_messages(status=MessageStatus.PROCESSED.value)
            return len(msgs) == 1

        await _until(_processed)  # quiescent once delivered
    finally:
        await _stop_quiesced(runner, store)

    # failed, failed, delivered — driven by the pooled clock-driven retry on the real backoff clock.
    assert flaky.calls == 3, flaky.calls
    assert len(flaky.payloads) == 1 and "MID3" in flaky.payloads[0]
    # Timing lower bound: the successful retry fired NO EARLIER than the row's re-pended
    # ``next_attempt_at`` = (failure time) + backoff, so the gap from the last failing attempt to the
    # delivering attempt is >= the backoff. (The store sets ``next_attempt_at`` AFTER the send raised,
    # and claim/park overhead only adds to the gap, so this bound is not tight — it just proves the
    # retry honored the schedule rather than busy-re-driving immediately.) The ISOLATED park-timer
    # behavior (unpark exactly at ``next_attempt_at`` with the sweep quiesced) is unit-tested in
    # tests/test_stage_dispatcher.py::test_park_then_unpark_on_timer; here we assert only the e2e bound.
    assert len(flaky.call_times) == 3, flaky.call_times
    backoff = 0.2  # RetryPolicy(backoff_seconds=0.2, backoff_multiplier=1.0) above
    assert flaky.call_times[-1] - flaky.call_times[-2] >= backoff, flaky.call_times


# =================================================================================================
# ROWS 6/7 — dispatcher-level shard filter + H1 fence (see the module docstring "Altitude" note)
# =================================================================================================


class _LaneRecorder:
    """The injected pooled ``process_item`` body for rows 6/7: record each ``(lane, item.id)`` dispatch
    and RESOLVE. RESOLVED leaves the just-claimed row INFLIGHT (``claim_fifo_heads`` only claims
    PENDING, so it is never re-claimed) — the faithful "the body took ownership" stand-in used by
    ``test_stage_dispatcher.py``'s stub. A claimed lane therefore shows up in ``records``; an unclaimed
    (foreign / fenced) lane never does, and its store row stays PENDING with ``attempts`` untouched."""

    def __init__(self) -> None:
        self.records: list[tuple[str, str]] = []  # (lane, item.id) in dispatch order

    async def __call__(self, lane: str, item: OutboxItem) -> LaneItemResult:
        self.records.append((lane, item.id))
        return LaneItemResult(LaneResultKind.RESOLVED)

    @property
    def lanes(self) -> set[str]:
        return {lane for lane, _ in self.records}


def _make_dispatcher(
    stage: Stage, store: Any, recorder: _LaneRecorder, lanes: set[str], *, sweep: float = 3600.0
) -> StageDispatcher:
    """A ``StageDispatcher`` over ``lanes`` with discovery driven EXPLICITLY (huge ``sweep_interval`` ->
    the periodic sweep never fires on its own; the test awaits ``_run_sweep_once`` where it wants one).
    That is what keeps these SS-teardown-safe: the only ``list_fifo_lanes`` / ``claim_fifo_heads``
    executes are ones the test awaits to completion, so ``stop()`` never cancels one mid-``cur.execute``
    (every dispatcher task is parked on a pure-asyncio Event at stop). Real clock: seeded rows carry a
    small past ``next_attempt_at`` (100.0), due against ``time.time()``."""
    return StageDispatcher(
        stage,
        store,
        process_item=recorder,
        lane_provider=lambda: set(lanes),
        per_lane_limit=1,
        sweep_interval=sweep,
    )


async def _seed_outbound(store: Any, dest: str, cid: str) -> str:
    """Enqueue one message with a single delivery to ``dest`` — a PENDING OUTBOUND-stage row on lane
    ``dest`` (``enqueue_message`` writes the outbound rows directly). Returns the message id."""
    mid: str = await store.enqueue_message(
        channel_id="IB_SHARD", raw=ADT.format(cid=cid), deliveries=[(dest, "p")], now=100.0
    )
    return mid


async def _outbox_row(store: Any, mid: str) -> dict[str, Any]:
    rows = await store.outbox_for(mid)
    assert len(rows) == 1, rows
    return dict(rows[0])


async def _recorded(rec: _LaneRecorder, lanes: set[str]) -> bool:
    """``_until`` predicate: every lane in ``lanes`` has been dispatched (the lane set drained)."""
    return rec.lanes == lanes


async def _empty_at_least(d: StageDispatcher, n: int) -> bool:
    """``_until`` predicate: the dispatcher has booked at least ``n`` empty claims (the claimer really
    ran and its claims returned nothing — used to make a fenced "nothing dispatched" non-vacuous)."""
    return d.empty_claims[0] >= n


async def _seed_lease_epoch(store: Any, epoch: int) -> str | None:
    """Upsert the single ``leader_lease`` row to ``epoch`` (the authoritative current-leader epoch a
    standby's fresh-acquire bump left behind) and return the backend's ``lease_key`` for
    ``set_leader_epoch``. Mirrors the store-suite fence helpers (``test_sqlserver_store.py`` /
    ``test_postgres_store.py``). **No-op on SQLite** (the H1 fence is a no-op there — single active node),
    returning ``None`` so ``set_leader_epoch(None)`` stays byte-identical (unfenced)."""
    backend = getattr(store, "_test_backend", None)
    if backend == "sqlite":
        return None
    if backend == "sqlserver":
        lease_key = "dbo:mefor_cluster_leader"
        await store._execute(
            "IF OBJECT_ID(N'leader_lease', N'U') IS NULL"
            " CREATE TABLE leader_lease ("
            " lease_key NVARCHAR(256) NOT NULL PRIMARY KEY, owner NVARCHAR(256) NULL,"
            " lease_expires_at FLOAT NOT NULL,"
            " leader_epoch BIGINT NOT NULL CONSTRAINT DF_leader_lease_epoch DEFAULT 0);"
        )
        await store._execute(
            "MERGE leader_lease WITH (HOLDLOCK) AS t USING (SELECT ? AS lease_key) AS s"
            " ON t.lease_key = s.lease_key"
            " WHEN MATCHED THEN UPDATE SET leader_epoch = ?"
            " WHEN NOT MATCHED THEN INSERT (lease_key, owner, lease_expires_at, leader_epoch)"
            " VALUES (?, 'live', 9e18, ?);",
            (lease_key, epoch, lease_key, epoch),
        )
        return lease_key
    # postgres
    lease_key = "public:mefor_cluster_leader"
    async with store._pool.acquire() as conn:
        await conn.execute(
            "CREATE TABLE IF NOT EXISTS leader_lease ("
            " lease_key TEXT PRIMARY KEY, owner TEXT, lease_expires_at DOUBLE PRECISION NOT NULL,"
            " leader_epoch BIGINT NOT NULL DEFAULT 0)"
        )
        await conn.execute(
            "INSERT INTO leader_lease (lease_key, owner, lease_expires_at, leader_epoch)"
            " VALUES ($1, 'live', 9e18, $2)"
            " ON CONFLICT (lease_key) DO UPDATE SET leader_epoch = EXCLUDED.leader_epoch",
            lease_key,
            epoch,
        )
    return lease_key


# =================================================================================================
# ROW 6 — sharding shard-filter: 2 dispatchers, disjoint lane sets, ONE store
# =================================================================================================


async def test_row6_pooled_sharding_shard_filter(store: Any) -> None:
    """Two ``StageDispatcher``s over DISJOINT lane sets share ONE store (the ADR 0063 disjoint-inbound
    sharding topology, and the bench's own 2-engine/1-store validation shape). Row 6 asserts the shard
    filter holds on BOTH the claim seam (§3.1: the claim only ever sees the caller's explicit lane set)
    and the sweep seam (§4.4: ``list_fifo_lanes`` is store-WIDE, the dispatcher intersects with its
    registry lanes):

    * every claimed row's lane stays in the claiming engine's set (shard A's records ⊆ shard A);
    * neither engine's sweep readies the other shard's lanes;
    * foreign-lane ``attempts`` are never touched.

    Built at the dispatcher level (see the module "Altitude" note): a recording ``process_item`` RESOLVES
    each claimed head (-> INFLIGHT), so a claimed lane appears in ``records`` and an unclaimed foreign
    lane stays PENDING with ``attempts == 0`` — the crisp discriminator.

    The A-direction proves the SWEEP filter non-vacuously: shard-B rows are PENDING and therefore
    store-wide-visible to ``list_fifo_lanes`` while dispatcher A sweeps, yet A never readies them. On
    SQLite the process-wide write lock serializes cross-shard concurrency away, so the two claimers never
    actually race — the SQLite param still runs as a structural check; the authoritative concurrent
    coverage is the SS + PG CI legs.
    """
    a_lanes = {"OB_SHARD_A1", "OB_SHARD_A2"}
    b_lanes = {"OB_SHARD_B1", "OB_SHARD_B2"}
    a_mids = {dest: await _seed_outbound(store, dest, f"A_{dest}") for dest in sorted(a_lanes)}
    b_mids = {dest: await _seed_outbound(store, dest, f"B_{dest}") for dest in sorted(b_lanes)}

    # Sanity: the store-level lane discovery is UNSCOPED — it returns BOTH shards. The shard filter is
    # the dispatcher's job (the caller's explicit lane set + the sweep's registry intersection), which is
    # exactly what this test then pins.
    store_wide = {lane for lane, _ in await store.list_fifo_lanes(Stage.OUTBOUND.value)}
    assert a_lanes <= store_wide and b_lanes <= store_wide, store_wide

    # --- dispatcher A over shard A only ----------------------------------------------------------
    rec_a = _LaneRecorder()
    d_a = _make_dispatcher(Stage.OUTBOUND, store, rec_a, a_lanes)
    await d_a.start()
    try:
        await _until(lambda: _recorded(rec_a, a_lanes))
        # An EXPLICIT sweep with shard-B rows PENDING and store-wide-visible: A's sweep must filter them.
        await d_a._run_sweep_once()
        await asyncio.sleep(0.05)  # let any claimer follow-up settle before asserting
        # (i) every claimed lane ∈ shard A; each shard-A row claimed exactly once (no foreign claim).
        assert rec_a.lanes == a_lanes, rec_a.records
        assert len(rec_a.records) == len(a_lanes), rec_a.records
        # (ii) shard-B lanes NEVER entered A's state machine — the claim §3.1 + sweep §4.4 shard filter.
        for bl in b_lanes:
            assert d_a.phase(bl) is None, (bl, d_a.phase(bl))
        # (iii) foreign-lane (shard-B) rows untouched: still PENDING, attempts never incremented by A.
        for dest, mid in b_mids.items():
            row = await _outbox_row(store, mid)
            assert row["status"] == OutboxStatus.PENDING.value, (dest, row)
            assert row["attempts"] == 0, (dest, row)
        # Non-vacuity: shard-A rows really were claimed by A (INFLIGHT, one attempt).
        for dest, mid in a_mids.items():
            row = await _outbox_row(store, mid)
            assert row["status"] == OutboxStatus.INFLIGHT.value, (dest, row)
            assert row["attempts"] == 1, (dest, row)
    finally:
        await d_a.stop()

    # --- dispatcher B over shard B only (symmetry + "2 runners, one store, no lost work") ---------
    rec_b = _LaneRecorder()
    d_b = _make_dispatcher(Stage.OUTBOUND, store, rec_b, b_lanes)
    await d_b.start()
    try:
        await _until(lambda: _recorded(rec_b, b_lanes))
        await d_b._run_sweep_once()
        await asyncio.sleep(0.05)
        assert rec_b.lanes == b_lanes, rec_b.records
        assert len(rec_b.records) == len(b_lanes), rec_b.records
        # B never touched shard A: a_lanes never entered B's state, and A's rows are UNCHANGED by B
        # (still INFLIGHT with the single attempt A gave them — B neither re-claimed nor incremented).
        for al in a_lanes:
            assert d_b.phase(al) is None, (al, d_b.phase(al))
        for dest, mid in a_mids.items():
            row = await _outbox_row(store, mid)
            assert row["status"] == OutboxStatus.INFLIGHT.value, (dest, row)
            assert row["attempts"] == 1, (dest, row)
        # And shard B was actually delivered by B (INFLIGHT, one attempt) — no work lost across the split.
        for dest, mid in b_mids.items():
            row = await _outbox_row(store, mid)
            assert row["status"] == OutboxStatus.INFLIGHT.value, (dest, row)
            assert row["attempts"] == 1, (dest, row)
    finally:
        await d_b.stop()


# =================================================================================================
# ROW 7 — H1 fencing pooled: a paused ex-leader's pooled claim matches 0 rows across ALL lanes
# =================================================================================================


async def test_row7_pooled_h1_fence_zero_across_all_lanes(store: Any) -> None:
    """A superseded ex-leader's POOLED claim matches 0 rows across ALL its lanes in one shot — the H1
    epoch guard rides ``claim_fifo_heads``' probe AND UPDATE (ADR 0066 §3.2 STEP 5). Driven through the
    dispatcher: with a STALE held epoch the pooled claimer dispatches nothing on any lane (every head
    stays PENDING, ``attempts`` untouched — the probe locked nothing, the UPDATE matched nothing); after
    promotion (held == the live lease epoch) the SAME dispatcher drains every lane.

    ``set_leader_epoch`` is a **no-op on SQLite** (single active node — nothing to fence), so the SQLite
    param is a STRUCTURAL check: a "stale" epoch does not fence, and the dispatcher drains normally. The
    authoritative fencing coverage is the SS + PG CI legs, which seed the ``leader_lease`` epoch row and
    prove the guard rejects the ex-leader's claim across all lanes. (On SQLite the process-wide write
    lock also serializes the pooled path, as in the sibling rider rows.)
    """
    lanes = {"OB_FENCE1", "OB_FENCE2", "OB_FENCE3"}
    mids = {dest: await _seed_outbound(store, dest, f"F_{dest}") for dest in sorted(lanes)}
    backend = getattr(store, "_test_backend", None)

    # The authoritative current leader epoch in the DB is 5 (a standby took over + bumped it).
    lease_key = await _seed_lease_epoch(store, 5)

    rec = _LaneRecorder()
    d = _make_dispatcher(Stage.OUTBOUND, store, rec, lanes)

    if backend == "sqlite":
        # STRUCTURAL check: the fence is a no-op here. A "stale" epoch is ignored, so the dispatcher
        # simply drains every lane. (set_leader_epoch accepts and discards the value on SQLite.)
        store.set_leader_epoch(3, lease_key=lease_key)  # ignored — single active node
        await d.start()
        try:
            await _until(lambda: _recorded(rec, lanes))
            assert rec.lanes == lanes, rec.records
        finally:
            await d.stop()
        return

    # --- SS / PG: the fence bites -----------------------------------------------------------------
    store.set_leader_epoch(
        3, lease_key=lease_key
    )  # this node is a superseded ex-leader (held 3 < 5)
    await d.start()
    try:
        # The claimer DID attempt a claim for every lane and was rejected: each fenced lane books an
        # EMPTY claim, so total empty claims >= the lane count. This makes "nothing dispatched"
        # non-vacuous (the claimer really ran and the fence rejected it, vs. never having claimed).
        await _until(lambda: _empty_at_least(d, len(lanes)))
        # A second explicit sweep re-readies the (still-PENDING) heads and the claimer tries again —
        # every repeat is fenced too.
        await d._run_sweep_once()
        await _until(lambda: _empty_at_least(d, 2 * len(lanes)))
        # FENCED: 0 rows dispatched on ANY lane; every head PENDING with attempts untouched.
        assert rec.records == [], rec.records
        for dest, mid in mids.items():
            row = await _outbox_row(store, mid)
            assert row["status"] == OutboxStatus.PENDING.value, (dest, row)
            assert row["attempts"] == 0, (dest, row)

        # PROMOTION: this node is now the current leader (held == the live lease epoch 5). The fence
        # lifts; re-ready every lane (mark_ready, not notify_work — no _sweep_now, so no async periodic
        # sweep to race teardown) and the SAME dispatcher now claims + dispatches every lane.
        store.set_leader_epoch(5, lease_key=lease_key)
        for lane in lanes:
            d.mark_ready(lane)
        await _until(lambda: _recorded(rec, lanes))
        assert rec.lanes == lanes, rec.records
        for dest, mid in mids.items():
            row = await _outbox_row(store, mid)
            assert row["status"] == OutboxStatus.INFLIGHT.value, (dest, row)
            assert row["attempts"] == 1, (dest, row)
    finally:
        # Disable the guard before teardown so any last claimer/sweep execute isn't fenced mid-shutdown,
        # and so a leftover leader_lease row can't fence an unrelated later test (which never calls
        # set_leader_epoch anyway, but be explicit).
        store.set_leader_epoch(None)
        await d.stop()
