"""ADR 0114 sub-lever A — live SQL Server legs (env-gated: MEFOR_TEST_SQLSERVER=1 + MEFOR_STORE_*).

The offline suite (test_adr0114_claim_proc.py) freezes the DDL text, the gate logic, and the
dispatch; these legs verify what only a real server can:

- the guarded DDL actually deploys both procs on open (and a flag-OFF open leaves them inert);
- the startup gate accepts the deployed bodies (OBJECT_DEFINITION round-trip);
- **AC-8**: @@TRANCOUNT on proc exit equals entry (no BEGIN/COMMIT/ROLLBACK inside);
- the live differential: proc-path vs batch-path claims over the same enqueued rows return
  identical ClaimedHeads (the store-primitive differential the ADR §8 battery scales up);
- a hand-tampered body degrades the next open loudly (AC-7);
- **AC-12**: a fenced ex-leader (stale epoch vs the leader_lease row) claims ZERO rows on BOTH
  dispatch paths (the fixed-nullable proc fence == the spliced batch guard);
- **AC-11**: an oversized requested lane whose 256-unit prefix equals a REAL lane claims zero on
  both paths (no-match parity — the truncating-CAST shard-safety hazard stays closed).

The §8 bench-gate battery (G-A0 plan shape, describe-traffic traces, forced 1222/cancellation
storms, the pool assay) runs on the bench box per WO-0114-GATES — not here.
"""

from __future__ import annotations

import asyncio
import os
from collections.abc import AsyncIterator
from typing import Any

import pytest

from messagefoundry.config.settings import load_settings
from messagefoundry.store import sqlserver as ss
from messagefoundry.store.sqlserver import SqlServerStore
from messagefoundry.store.store import Stage

pytestmark = pytest.mark.skipif(
    not os.getenv("MEFOR_TEST_SQLSERVER"),
    reason="set MEFOR_TEST_SQLSERVER=1 (+ MEFOR_STORE_* env) to run the live SQL Server legs",
)


# claim_fifo_heads' SQL Server dispatch — BOTH the batch path and the proc path (_claim_proc_body also
# emits SET LOCK_TIMEOUT 0, ADR 0066 §9 never-block) — can transiently fail-close the whole claim to
# EMPTY-all: by_lane AND rearm both empty, rolled back, nothing consumed. That yield is contract-legal
# but flakes a single-shot assertion. _claim_until re-issues past a transient EMPTY-all for the sites
# that assert a NON-empty outcome; a successful claim never retries, and a genuinely-unclaimable head
# stays EMPTY-all every pass and still fails after the cap (masks nothing). Sites that assert EMPTY-all
# itself (fenced ex-leader, no-match/oversized lane) call claim_fifo_heads directly — immune to the yield.
# Mirrors _claim_heads in test_claim_fifo_heads.py (the fix for this same never-block flake class).
async def _claim_until(store: Any, *args: Any, **kwargs: Any) -> Any:
    res = await store.claim_fifo_heads(*args, **kwargs)
    for _ in range(16):
        if res.by_lane or res.rearm:
            break
        await asyncio.sleep(0.01)
        res = await store.claim_fifo_heads(*args, **kwargs)
    return res


async def _open(**flag_overrides: Any) -> SqlServerStore:
    settings = load_settings(environ=os.environ).store
    settings = settings.model_copy(update=flag_overrides)
    return await SqlServerStore.open(settings)


async def _clean(store: SqlServerStore) -> None:
    # The canonical live-suite cleanup order (test_claim_fifo_heads._open_sqlserver): children
    # before messages (response FKs it), so no 547 on a shared live DB.
    for table in ("message_events", "queue", "response", "delivered_keys", "outbox", "messages"):
        await store._execute(f"DELETE FROM {table}")  # noqa: S608 - test cleanup, fixed names


@pytest.fixture
async def proc_store() -> AsyncIterator[SqlServerStore]:
    store = await _open(fifo_claim_proc=True)
    try:
        await _clean(store)
        yield store
    finally:
        await store.close()


async def test_open_deploys_procs_and_gate_passes(proc_store: SqlServerStore) -> None:
    assert proc_store.claim_proc_effective is True
    assert proc_store.claim_proc_degraded_reason is None
    for proc in (ss._CLAIM_PROC_CID, ss._CLAIM_PROC_DST):
        row = await proc_store._fetchone(
            "SELECT OBJECT_DEFINITION(OBJECT_ID(?)) AS body", (f"dbo.{proc}",)
        )
        assert row is not None and row["body"], f"dbo.{proc} not deployed"


async def test_a_deployed_proc_can_return_a_null_definition(proc_store: SqlServerStore) -> None:
    """The premise the gate's missing-vs-unreadable split rests on, and the one thing no offline
    stub can show: on a real engine ``OBJECT_ID`` and ``OBJECT_DEFINITION`` genuinely disagree — a
    procedure can be DEPLOYED and its definition still come back NULL.

    Before the gate probed the id it read that NULL as "the proc is missing" and sent the operator
    to grant ``CREATE PROCEDURE`` — neither the cause nor the cure.

    ``WITH ENCRYPTION`` is used because it needs no security principal, so this leg creates no login
    or user and impersonates nobody; it drops its own proc. The OTHER cause the reason string names
    — a principal with ``EXECUTE`` but no ``VIEW DEFINITION`` — produces the byte-identical NULL and
    is deferred with AC-10's other permission scenarios to a purpose-configured server.
    """
    name = "mefor_gate_null_definition_probe"
    await proc_store._execute(f"CREATE PROCEDURE dbo.{name} WITH ENCRYPTION AS SELECT 1;")  # noqa: S608
    try:
        probe = await proc_store._fetchone(
            "SELECT OBJECT_ID(?) AS oid, OBJECT_DEFINITION(OBJECT_ID(?)) AS body",
            (f"dbo.{name}", f"dbo.{name}"),
        )
        assert probe is not None
        assert probe["oid"] is not None, "the proc is deployed — this is the PRESENT half"
        assert probe["body"] is None, "and its definition is unreadable — the NULL half"
    finally:
        await proc_store._execute(f"DROP PROCEDURE IF EXISTS dbo.{name};")  # noqa: S608


async def test_ac8_trancount_on_exit_equals_entry(proc_store: SqlServerStore) -> None:
    # Execute the proc inside an open transaction and read @@TRANCOUNT before/after: the proc
    # must not BEGIN/COMMIT/ROLLBACK (it runs inside the client's autocommit=False txn).
    async with proc_store._acquire() as conn, proc_store._cursor(conn) as cur:
        try:
            await cur.execute("SELECT @@TRANCOUNT")
            before = (await cur.fetchone())[0]
            await cur.execute(
                f"{{CALL dbo.{ss._CLAIM_PROC_CID} (?,?,?,?,?,?,?,?,?)}}",
                (0.0, Stage.INGRESS.value, 1, "pending", "inflight", "[]", None, None, 0),
            )
            await cur.fetchall()  # drain the sole (empty) result set
            await cur.execute("SELECT @@TRANCOUNT")
            after = (await cur.fetchone())[0]
            assert after == before, "the proc changed the transaction nesting (AC-8)"
            # Leave the session clean: the CALL ran SET LOCK_TIMEOUT 0 (session-scoped).
            await cur.execute("SET LOCK_TIMEOUT -1;")
            await conn.commit()
        except Exception:
            await conn.rollback()
            raise


async def test_live_differential_proc_vs_batch(proc_store: SqlServerStore) -> None:
    # Same DB state, both dispatch paths: identical ClaimedHeads (ids, order, lanes).
    lanes = ["IB_DIFF_A", "IB_DIFF_B"]
    for lane in lanes:
        for _ in range(3):
            await proc_store.enqueue_ingress(channel_id=lane, raw=f"MSH|^~\\&|DIFF|{lane}")
    assert proc_store.claim_proc_effective
    proc_result = await _claim_until(proc_store, Stage.INGRESS.value, lanes)
    # Release and reclaim on the batch path.
    ids = [i.id for items in proc_result.by_lane.values() for i in items]
    assert ids, "the proc path claimed nothing"
    await proc_store.release_claimed(ids)
    proc_store._claim_proc_effective = False  # force the batch path (same store, same rows)
    batch_result = await _claim_until(proc_store, Stage.INGRESS.value, lanes)
    proc_store._claim_proc_effective = True
    assert {lane: [i.id for i in items] for lane, items in proc_result.by_lane.items()} == {
        lane: [i.id for i in items] for lane, items in batch_result.by_lane.items()
    }
    # attempts differ by exactly the second claim's increment — same rows, same order.
    await proc_store.release_claimed(ids)


async def test_ac7_tampered_body_degrades_next_open(proc_store: SqlServerStore) -> None:
    # Hand-edit one proc body out-of-band, then re-open: the gate must degrade loudly (the
    # OBJECT_DEFINITION hash mismatch), and the tampered store must still claim on the batch.
    #
    # POSITIVE CONTROL FIRST — this is not optional. Until the head-form fix landed, the gate
    # rejected EVERY body on every server, so this test's degrade assertions were satisfied by a
    # gate that had never matched anything: it passed while proving nothing. Pinning "the gate is
    # green on the untampered proc" in the same test is what makes the degrade below evidence.
    assert proc_store.claim_proc_effective is True, (
        "positive control: the gate must ACCEPT the correctly deployed proc, else the tamper"
        " assertions below are vacuous"
    )
    await proc_store._execute(
        f"ALTER PROCEDURE dbo.{ss._CLAIM_PROC_CID} @now FLOAT, @stage NVARCHAR(16), @k INT,"
        " @pending NVARCHAR(32), @inflight NVARCHAR(32), @lanes NVARCHAR(MAX),"
        " @lease_key NVARCHAR(256) = NULL, @leader_epoch BIGINT = NULL, @fold_reset BIT = 0"
        " AS SELECT 1 WHERE 1=0;"
    )
    try:
        tampered = await _open(fifo_claim_proc=True)
        try:
            assert tampered.claim_proc_effective is False
            assert tampered.claim_proc_degraded_reason is not None
            assert "matches no form this build deploys" in tampered.claim_proc_degraded_reason
            # Still claims (batch path — never a lane outage).
            result = await tampered.claim_fifo_heads(Stage.INGRESS.value, ["IB_NONE"])
            assert result.by_lane == {}
        finally:
            await tampered.close()
    finally:
        # Heal UNCONDITIONALLY (exception-safe): force a full schema re-apply (re-creates the
        # shipped body) so a mid-test failure never poisons the shared DB for later suites.
        await proc_store._execute("DELETE FROM schema_meta")
        healed = await _open(fifo_claim_proc=True)
        try:
            assert healed.claim_proc_effective is True
        finally:
            await healed.close()


async def test_ac12_fenced_ex_leader_claims_zero_on_both_paths(
    proc_store: SqlServerStore,
) -> None:
    # AC-12: the fenced ex-leader claims 0 rows across all lanes — live, on BOTH dispatch paths
    # (the fixed-nullable proc fence and the spliced batch guard must agree).
    lane = "IB_FENCE"
    await proc_store.enqueue_ingress(channel_id=lane, raw="MSH|^~\\&|FENCE")
    lease_key = "adr0114-fence-test"
    # leader_lease is coordinator-created (cluster_sqlserver._ensure_tables), not store-schema —
    # create it if this bench DB never ran clustered, with the coordinator's exact shape.
    await proc_store._execute(
        "IF OBJECT_ID(N'leader_lease', N'U') IS NULL"
        " CREATE TABLE leader_lease ("
        " lease_key NVARCHAR(256) NOT NULL PRIMARY KEY, owner NVARCHAR(256) NULL,"
        " lease_expires_at FLOAT NOT NULL,"
        " leader_epoch BIGINT NOT NULL"
        " CONSTRAINT DF_leader_lease_epoch DEFAULT 0);"
    )
    await proc_store._execute(
        "IF NOT EXISTS (SELECT 1 FROM leader_lease WHERE lease_key=?)"
        " INSERT INTO leader_lease (lease_key, owner, lease_expires_at, leader_epoch)"
        " VALUES (?, 'adr0114-test', 4102444800, 99)",
        (lease_key, lease_key),
    )
    try:
        proc_store.set_leader_epoch(1, lease_key=lease_key)  # stale epoch: 1 < the lease's 99
        assert proc_store.claim_proc_effective
        fenced_proc = await proc_store.claim_fifo_heads(Stage.INGRESS.value, [lane])
        assert fenced_proc.by_lane == {}, "a fenced ex-leader must claim ZERO rows (proc path)"
        proc_store._claim_proc_effective = False
        fenced_batch = await proc_store.claim_fifo_heads(Stage.INGRESS.value, [lane])
        proc_store._claim_proc_effective = True
        assert fenced_batch.by_lane == {}, "a fenced ex-leader must claim ZERO rows (batch path)"
        # Non-stale control: the same store with the current epoch claims the row.
        proc_store.set_leader_epoch(99, lease_key=lease_key)
        current = await _claim_until(proc_store, Stage.INGRESS.value, [lane])
        assert sum(len(v) for v in current.by_lane.values()) == 1
    finally:
        proc_store.set_leader_epoch(None)
        await proc_store._execute("DELETE FROM leader_lease WHERE lease_key=?", (lease_key,))


async def test_ac11_no_match_parity_oversized_lane_lives(proc_store: SqlServerStore) -> None:
    # AC-11 live: an oversized (>256 UTF-16 units) requested lane whose 256-unit PREFIX equals a
    # REAL lane claims ZERO rows on both paths — the client-side skip prevents the server-side
    # CAST truncation from prefix-matching the real lane (the §4 shard-safety hazard).
    real_lane = "P" * 256
    oversized = "P" * 300  # its 256-unit prefix == real_lane
    await proc_store.enqueue_ingress(channel_id=real_lane, raw="MSH|^~\\&|PARITY")
    assert proc_store.claim_proc_effective
    via_proc = await proc_store.claim_fifo_heads(Stage.INGRESS.value, [oversized])
    assert via_proc.by_lane == {}, "the skipped oversized lane must claim nothing (proc path)"
    proc_store._claim_proc_effective = False
    via_batch = await proc_store.claim_fifo_heads(Stage.INGRESS.value, [oversized])
    proc_store._claim_proc_effective = True
    assert via_batch.by_lane == {}, "the oversized lane can never match (batch path)"
    # Control: the real lane itself claims its row on the proc path.
    control = await _claim_until(proc_store, Stage.INGRESS.value, [real_lane])
    assert sum(len(v) for v in control.by_lane.values()) == 1
