# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""ADR 0114 sub-lever B (``fifo_claim_prepared``): stable claim text + retained prepared cursor
on store-owned dedicated connections.

Offline (no SQL Server; aioodbc never imported — the dedicated-connection factory is a seam the
tests substitute). Every wire op carries a connection-identity tag (``@ded`` = the dedicated
holder, ``@pool`` = the pooled fakes), so "the guard ran ON THE RETAINED CURSOR" is a falsifiable
assertion, not a comment. What this file freezes:

- **the stable text**: ONE statement identity for the whole INGRESS/ROUTED scope — the shared
  ``_fifo_heads_steps`` render (OPENJSON lane source + fixed-nullable fence, same as the procs)
  behind an 8-parameter DECLARE, with the trailing ``SET LOCK_TIMEOUT -1;`` INSIDE the text (the
  §5 fail-closed coupling to the fold); arity-invariant across lane counts and epoch modes.
- **AC-13** couplings at the startup gate AND at the dispatch site (the ``and fold`` belt): logs
  + no-ops unless ``fifo_claim_fold_reset`` is ON; retired-not-stacked when the proc gate is
  green (§5 compose-or-compete); compat >= 130; a raising probe degrades, never an outage.
- **the holder lifecycle** (§5 eviction policy, mapped onto exit shape): KEPT on clean success,
  kept≠claimed, and 1222 (normal yield signals — worst case one re-prepare from the guard's
  one-slot eviction); DISCARDED only on cancellation/unclassified errors; per-stage free lists
  (no cross-stage sharing); concurrent claims each get their OWN holder (no EF-6 busy race);
  reopened lazily with the STORE-3 per-statement timeout re-applied at every (re)open (and a
  WARNING when the raw pyodbc surface is unreachable); the open path never leaks a connection
  when the post-connect steps fail; teardown closes idle holders AND marks the set closed so a
  borrowed/straggler holder is discarded on return, never re-retained past close().
- **AC-13** observability: the additive ``claim_pool`` sibling in ``pool_status()`` (and its
  /status ``PoolInfo.claim_pool`` mapping) so the B11 connection-budget arithmetic sees the
  out-of-pool dedicated connections — including the mid-claim borrowed state (open=1, idle=0).

Deferred to the ADR §8 G-B0/G-B battery (live wire traces): the SQLPrepare-once/sp_execute-
per-call reuse proof, the describe-traffic assertion, the re-prepare-storm kill, the mid-run
leader-epoch flip, the cancellation storm + pool assay, and the hung-statement (STORE-3) leg —
feasibility itself is gate question G-B0 ("infeasible-on-this-driver" is a licensed outcome).
The real ``_claim_prepared_param_pins`` table needs pyodbc — exercised on live/gated runs,
substituted here.
"""

from __future__ import annotations

import asyncio
import hashlib
import inspect
import json
import logging
from types import SimpleNamespace
from typing import Any

import pytest

from messagefoundry.config.settings import StoreSettings
from messagefoundry.store import sqlserver as ss
from messagefoundry.store.pool_metrics import AcquireWaitHistogram
from messagefoundry.store.sqlserver import SqlServerStore
from messagefoundry.store.store import ClaimedHeads
from tests.test_adr0114_claim_fold import (
    _GOLDEN_SQL_SHA256,
    _NOW,
    _FakeConn,
    _FakeCursor,
    _lock_timeout_error,
    _null_twin,
    _op_kinds,
    _Ops,
    _row,
    _wire,
)
from tests.test_adr0114_claim_proc import _FAKE_PINS as _FAKE_PROC_PINS
from tests.test_adr0114_claim_proc import _proc_store

_FAKE_PINS_8 = [(2, 0, 0)] * 8  # stands in for _claim_prepared_param_pins() (pyodbc-free CI)


class _GateableCursor(_FakeCursor):
    """The dedicated cursor, with an optional event gate on the BATCH execute (for concurrency
    and teardown-during-in-flight choreography; the base class's gate covers the reset)."""

    def __init__(
        self,
        ops: _Ops,
        *,
        batch_started: asyncio.Event | None = None,
        batch_release: asyncio.Event | None = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(ops, **kwargs)
        self._batch_started = batch_started
        self._batch_release = batch_release

    async def execute(self, sql: str, params: Any = ()) -> None:
        if (
            not sql.startswith("SET LOCK_TIMEOUT -1")
            and "delivered_keys" not in sql
            and self._batch_started is not None
        ):
            self._batch_started.set()
            if self._batch_release is not None:
                await self._batch_release.wait()
        await super().execute(sql, params)


class _FakeDedicatedConn:
    """An aioodbc-shaped dedicated connection: async cursor()/commit()/rollback()/close(), plus
    the raw pyodbc surface (``_conn``) the STORE-3 timeout is applied to. Ops are tagged ``@ded``
    so the rig can prove WHICH connection an op ran on."""

    def __init__(self, ops: _Ops, cur: _FakeCursor, *, raw: bool = True) -> None:
        self.ops = ops
        self._cur = cur
        if raw:
            self._conn = SimpleNamespace(timeout=None)  # raw pyodbc conn (STORE-3 target)
        self.closed = False
        self.fail_cursor: BaseException | None = None

    async def cursor(self) -> _FakeCursor:
        if self.fail_cursor is not None:
            raise self.fail_cursor
        return self._cur

    async def commit(self) -> None:
        self.ops.append(("commit@ded",))

    async def rollback(self) -> None:
        self.ops.append(("rollback@ded",))

    async def close(self) -> None:
        self.closed = True


def _prepared_store(
    *,
    prepared: bool = True,
    effective: bool = True,
    fold: bool = True,
    epoch: bool = False,
    pins: list[tuple[int, int, int]] | None = None,
) -> SqlServerStore:
    store = _proc_store(proc=False, effective=False, fold=fold, epoch=epoch)
    store._fifo_claim_prepared = prepared
    store._claim_prepared_effective = effective
    store._claim_prepared_input_sizes = pins
    return store


class _Rig:
    """One claim rig: shared op list with per-connection tags (dedicated=@ded, pooled=@pool), a
    dedicated-connection factory (fresh conn + cursor per open, mirroring a reopen-after-discard),
    and the pooled fakes for non-prepared stages."""

    def __init__(
        self,
        store: SqlServerStore,
        *,
        rows: list[tuple[Any, ...]] | None = None,
        fail_batch: BaseException | None = None,
        raw_conn: bool = True,
        reset_started: asyncio.Event | None = None,
        reset_release: asyncio.Event | None = None,
        batch_started: asyncio.Event | None = None,
        batch_release: asyncio.Event | None = None,
    ) -> None:
        self.ops: _Ops = []
        self.store = store
        self.conns: list[_FakeDedicatedConn] = []
        self.cursors: list[_FakeCursor] = []
        self._rows = rows
        self._fail_batch = fail_batch
        self._raw_conn = raw_conn
        self._reset_started = reset_started
        self._reset_release = reset_release
        self._batch_started = batch_started
        self._batch_release = batch_release
        _wire(
            store,
            _FakeCursor(self.ops, rows=rows, fail_batch=fail_batch, tag="pool"),
            _FakeConn(self.ops, tag="pool"),
        )

        async def connect() -> _FakeDedicatedConn:
            cur = _GateableCursor(
                self.ops,
                rows=self._rows,
                fail_batch=self._fail_batch,
                tag="ded",
                reset_started=self._reset_started,
                reset_release=self._reset_release,
                batch_started=self._batch_started,
                batch_release=self._batch_release,
            )
            conn = _FakeDedicatedConn(self.ops, cur, raw=self._raw_conn)
            self.conns.append(conn)
            self.cursors.append(cur)
            return conn

        store._connect_claim_conn = connect  # type: ignore[method-assign]

    async def claim(self, stage: str = "ingress", lanes: list[str] | None = None) -> ClaimedHeads:
        return await self.store.claim_fifo_heads(
            stage, lanes if lanes is not None else ["lane-0"], now=_NOW
        )


# --- the stable text ------------------------------------------------------------------------------


def test_stable_text_is_header_plus_fragments_plus_inline_reset() -> None:
    expected = (
        "SET NOCOUNT ON;"
        " SET LOCK_TIMEOUT 0;"
        " DECLARE @now FLOAT = ?, @stage NVARCHAR(16) = ?, @k INT = ?,"
        " @pending NVARCHAR(32) = ?, @inflight NVARCHAR(32) = ?,"
        " @lanes NVARCHAR(MAX) = ?, @lease_key NVARCHAR(256) = ?, @leader_epoch BIGINT = ?;"
        + ss._fifo_heads_steps(
            lane_col="channel_id",
            lane_source=ss._CLAIM_PROC_LANE_SOURCE,
            epoch_guard=ss._CLAIM_PROC_EPOCH_GUARD,
        )
        + " SET LOCK_TIMEOUT -1;"
    )
    assert expected == ss._PREPARED_CLAIM_SQL
    # The trailing reset is INSIDE the one identity (§5 coupling); exactly the opener + the tail.
    assert ss._PREPARED_CLAIM_SQL.count("SET LOCK_TIMEOUT") == 2
    assert ss._PREPARED_CLAIM_SQL.endswith(" SET LOCK_TIMEOUT -1;")
    # channel_id family only (INGRESS/ROUTED scope); the parameter count is 8 (no @fold_reset —
    # the reset is unconditional in the stable text).
    assert "destination_name = l.lane" not in ss._PREPARED_CLAIM_SQL
    assert ss._PREPARED_CLAIM_SQL.count("?") == 8


async def test_one_statement_identity_across_lane_counts_and_epoch_modes() -> None:
    texts = set()
    for epoch in (False, True):
        for n in (1, 4, 64):
            rig = _Rig(_prepared_store(epoch=epoch))
            await rig.claim(lanes=[f"lane-{i:03d}" for i in range(n)])
            kind, sql, params = rig.ops[0]
            assert kind == "execute-batch@ded"
            texts.add(sql)
            assert len(params) == 8
    assert len(texts) == 1, "the stable text must be ONE identity across N and epoch modes"
    assert texts == {ss._PREPARED_CLAIM_SQL}


@pytest.mark.parametrize("stage", ["ingress", "routed"])
@pytest.mark.parametrize("epoch", [False, True])
async def test_dispatch_args_shape(stage: str, epoch: bool) -> None:
    rig = _Rig(_prepared_store(epoch=epoch))
    await rig.claim(stage=stage, lanes=["a", "b"])
    _, sql, params = rig.ops[0]
    assert sql == ss._PREPARED_CLAIM_SQL
    assert params[0] == _NOW and params[1] == stage and params[2] == 1
    assert params[3] == "pending" and params[4] == "inflight"
    assert json.loads(params[5]) == ["a", "b"]
    if epoch:
        assert params[6] == "lease-key-golden" and params[7] == 7
    else:
        assert params[6] is None and params[7] is None


async def test_prepared_lane_encoding_shares_the_proc_rules() -> None:
    # AC-11 on the PREPARED dispatch: hostile names round-trip, oversized (UTF-16 units) skipped,
    # request-order dedupe + the 500 chunk clamp — the same _encode_proc_lanes as the proc path.
    hostile = ['lane "q"', "läne-⚕", "a" * 256]
    oversized = "\U0001f3e5" * 129  # 258 UTF-16 units
    dupes_and_bulk = ["b", "a", "b"] + [f"bulk-{i:04d}" for i in range(600)]
    rig = _Rig(_prepared_store())
    await rig.claim(lanes=[*hostile, oversized, *dupes_and_bulk])
    encoded = json.loads(rig.ops[0][2][5])
    assert encoded[:5] == [*hostile, "b", "a"]
    assert oversized not in encoded
    # Dedupe + the 500 chunk clamp run BEFORE the encode (identical to the batch path, where the
    # oversized lane occupies a VALUES slot it can never match); the skip then removes it from
    # the JSON — hence 499, not 500.
    assert len(encoded) == 499


@pytest.mark.parametrize(("stage", "family"), [("outbound", "dst"), ("response", "cid")])
async def test_outbound_response_stay_on_the_shipped_batch(stage: str, family: str) -> None:
    # The prepared scope is INGRESS/ROUTED only; the other stages take the shipped batch
    # byte-identically (golden hash) on the POOLED connection (no holder is ever opened).
    rig = _Rig(_prepared_store())
    await rig.claim(stage=stage, lanes=[f"lane-{i:03d}" for i in range(4)])
    kind, sql, _params = rig.ops[0]
    assert kind == "execute-batch@pool"
    assert hashlib.sha256(sql.encode()).hexdigest() == _GOLDEN_SQL_SHA256[(family, 4, False)]
    assert rig.conns == [], "no dedicated holder may be opened for a non-prepared stage"
    assert _op_kinds(rig.ops) == [
        "execute-batch@pool",
        "commit@pool",
        "execute-reset@pool",
        "commit@pool",
    ]


async def test_flag_on_but_not_effective_stays_on_shipped_path() -> None:
    rig = _Rig(_prepared_store(effective=False))
    await rig.claim()
    assert rig.ops[0][0] == "execute-batch@pool"
    assert rig.ops[0][1] != ss._PREPARED_CLAIM_SQL
    assert rig.conns == []


async def test_dispatch_belt_hostile_state_effective_without_fold_falls_to_batch() -> None:
    # The §5 fail-closed coupling at the DISPATCH site (not just the gate): even if
    # _claim_prepared_effective were hand-set/regressed to True with the fold flag OFF, the
    # `and fold` belt keeps the prepared path unreachable — otherwise every clean call would run
    # the guard's separate reset on the retained cursor (per-call one-slot eviction, silently
    # zeroing B) plus a doubled commit.
    store = _prepared_store(fold=False)  # hostile: effective=True but fold flag OFF
    rig = _Rig(store)
    await rig.claim()
    assert rig.ops[0][0] == "execute-batch@pool"
    assert rig.ops[0][1] != ss._PREPARED_CLAIM_SQL
    assert rig.conns == [], "the belt must keep the holder path unreachable without the fold"


# --- clean path: folded semantics + holder retention ----------------------------------------------


async def test_clean_path_two_wire_ops_one_commit_holder_kept() -> None:
    store = _prepared_store()
    rig = _Rig(store, rows=[_row("r1")])
    result = await rig.claim()
    assert [i.id for items in result.by_lane.values() for i in items] == ["r1"]
    # The reset rides INSIDE the stable text; commit#1 covers it; the guard is skipped
    # (reset_committed = fold = True at a prepared stage — gate + dispatch belt enforce fold-ON).
    assert _op_kinds(rig.ops) == ["execute-batch@ded", "commit@ded"]
    assert store.committed_txns == 1
    # Holder KEPT: back on the free list, ready for reuse.
    assert len(store._claim_holders["ingress"]) == 1
    assert store._claim_holders_opened_total == 1
    assert store._claim_holders_discarded_total == 0


async def test_holder_reused_across_claims_same_retained_cursor() -> None:
    store = _prepared_store()
    rig = _Rig(store)
    await rig.claim()
    await rig.claim()
    await rig.claim()
    assert store._claim_holders_opened_total == 1, "steady state = ONE dedicated connection"
    assert len(rig.cursors) == 1
    executes = [op for op in rig.ops if op[0] == "execute-batch@ded"]
    assert len(executes) == 3  # all three claims rode the SAME retained cursor


async def test_per_stage_free_lists_no_cross_stage_sharing() -> None:
    # §5 "one small set per stage": an ingress holder is never lent to a routed claim — the
    # per-stage partition keeps each stage's worst-case re-prepare and discard blast radius
    # independent.
    store = _prepared_store()
    rig = _Rig(store)
    await rig.claim(stage="ingress")
    await rig.claim(stage="routed")
    assert store._claim_holders_opened_total == 2
    assert len(store._claim_holders["ingress"]) == 1
    assert len(store._claim_holders["routed"]) == 1
    await rig.claim(stage="ingress")  # reuses the ingress holder, not routed's
    assert store._claim_holders_opened_total == 2


async def test_concurrent_claims_get_distinct_holders() -> None:
    # Two overlapping prepared claims: the second finds the free list empty and OPENS its own
    # holder — never a shared one (a shared holder would be the EF-6 'Connection is busy' race
    # on the real driver, plus interleaved transaction state). Sizing by construction: the set
    # grows exactly to the concurrent flagged-claim count.
    store = _prepared_store()
    started1 = asyncio.Event()
    release1 = asyncio.Event()
    rig = _Rig(store, batch_started=started1, batch_release=release1)
    task1 = asyncio.ensure_future(rig.claim())
    await asyncio.wait_for(started1.wait(), timeout=5)  # claim 1 mid-execute, holder borrowed
    # Mid-claim observability: one holder open, none idle (open vs idle are distinguishable).
    store._pool = SimpleNamespace(maxsize=40, size=1, freesize=1)
    store._acquire_wait = AcquireWaitHistogram()
    status = store.pool_status()
    assert status is not None and status.claim_pool is not None
    assert status.claim_pool.open == 1 and status.claim_pool.idle == 0
    # Claim 2 overlaps: must open holder #2 (fresh, ungated).
    rig._batch_started = None
    rig._batch_release = None
    await rig.claim()
    assert store._claim_holders_opened_total == 2
    release1.set()
    await asyncio.wait_for(task1, timeout=5)
    assert len(store._claim_holders["ingress"]) == 2  # both returned, both retained
    assert len({id(c) for c in rig.conns}) == 2, "no holder sharing between concurrent claims"


async def test_store3_timeout_applied_at_open_and_after_reopen() -> None:
    store = _prepared_store()
    rig = _Rig(store)
    await rig.claim()
    assert rig.conns[0]._conn.timeout == 30  # command_timeout at open (STORE-3)
    # Poison the RETAINED cursor (an unclassified error on the next execute) -> the borrow
    # discards the holder -> the claim after that REOPENS and re-applies the timeout.
    rig.cursors[0]._fail_batch = RuntimeError("boom")
    with pytest.raises(RuntimeError, match="boom"):
        await rig.claim()
    assert store._claim_holders_discarded_total == 1
    assert rig.conns[0].closed is True
    await rig.claim()
    assert store._claim_holders_opened_total == 2  # the reopen IS a fresh open
    assert rig.conns[1]._conn.timeout == 30  # the SECOND connection got the timeout too


async def test_store3_missing_raw_conn_warns_loudly(caplog: pytest.LogCaptureFixture) -> None:
    # The exact silently-unapplied-statement-timeout failure STORE-3 narrates: when the raw
    # pyodbc surface is unreachable the open must WARN, never proceed quietly.
    store = _prepared_store()
    rig = _Rig(store, raw_conn=False)
    with caplog.at_level(logging.WARNING, logger="messagefoundry.store.sqlserver"):
        await rig.claim()
    assert any("cannot reach the raw pyodbc connection" in r.getMessage() for r in caplog.records)


async def test_open_failure_never_leaks_the_connection() -> None:
    # cursor() failing after connect: the freshly-opened connection is closed, the error
    # propagates, and the counters never claim a holder that doesn't exist.
    store = _prepared_store()
    rig = _Rig(store)

    async def connect_then_fail_cursor() -> _FakeDedicatedConn:
        cur = _FakeCursor(rig.ops, tag="ded")
        conn = _FakeDedicatedConn(rig.ops, cur)
        conn.fail_cursor = RuntimeError("cursor open failed")
        rig.conns.append(conn)
        return conn

    store._connect_claim_conn = connect_then_fail_cursor  # type: ignore[method-assign]
    with pytest.raises(RuntimeError, match="cursor open failed"):
        await rig.claim()
    assert rig.conns[0].closed is True, "the half-opened connection must be closed, not leaked"
    assert store._claim_holders_open == 0
    assert store._claim_holders_opened_total == 0


# --- the §5 eviction/discard policy ---------------------------------------------------------------


async def test_1222_yields_empty_guard_runs_on_retained_cursor_holder_kept() -> None:
    store = _prepared_store()
    rig = _Rig(store, fail_batch=_lock_timeout_error())
    result = await rig.claim()
    # BACKLOG #1270: the EMPTY-all contract is unchanged -- `by_lane` and `rearm` are still
    # empty and no row moves. What is new is that the yield is ATTRIBUTED: the lanes ride out
    # on `contended`, so a caller can tell this apart from a genuinely empty lane. Asserting
    # the exact set rather than truthiness -- a bare `if result.contended` would pass on any
    # non-empty set, including a wrong one.
    assert result.by_lane == {} and result.rearm == frozenset()
    assert result.contended, "the 1222 yield must name the lanes it gave up on (BACKLOG #1270)"
    # The shielded guard ran ON THE RETAINED CURSOR — the @ded tags prove the reset+commit hit
    # the DEDICATED session (the one that set LOCK_TIMEOUT 0), not a pooled connection (which
    # would leave the holder poisoned with spurious 1222s for every later claim — B1/M-6).
    assert _op_kinds(rig.ops) == [
        "execute-batch@ded",
        "rollback@ded",
        "execute-reset@ded",
        "commit@ded",
    ]
    assert len(store._claim_holders["ingress"]) == 1  # KEPT: a normal contention-yield signal
    assert store._claim_holders_discarded_total == 0


async def test_kept_ne_claimed_rolls_back_holder_kept() -> None:
    store = _prepared_store()
    rig = _Rig(store, rows=[_row("a1"), _null_twin("a2")])
    result = await rig.claim(lanes=["a", "b"])
    assert result == ClaimedHeads(by_lane={}, rearm=frozenset())
    kinds = _op_kinds(rig.ops)
    assert "rollback@ded" in kinds and "execute-reset@ded" in kinds
    assert len(store._claim_holders["ingress"]) == 1
    assert store._claim_holders_discarded_total == 0


async def test_unclassified_error_discards_holder_and_closes_it(
    caplog: pytest.LogCaptureFixture,
) -> None:
    store = _prepared_store()
    rig = _Rig(store, fail_batch=RuntimeError("driver exploded"))
    with (
        caplog.at_level(logging.WARNING, logger="messagefoundry.store.sqlserver"),
        pytest.raises(RuntimeError, match="driver exploded"),
    ):
        await rig.claim()
    assert store._claim_holders.get("ingress", []) == []
    assert store._claim_holders_discarded_total == 1
    assert rig.conns[0].closed is True
    assert any("discarding dedicated claim connection" in r.getMessage() for r in caplog.records)
    # The guard still ran before the discard, on the dedicated session (defense-in-depth ABOVE
    # the guard, never instead).
    assert "execute-reset@ded" in _op_kinds(rig.ops)


async def test_cancellation_discards_holder_after_shielded_reset() -> None:
    store = _prepared_store()
    rig = _Rig(store, fail_batch=asyncio.CancelledError())
    with pytest.raises(asyncio.CancelledError):
        await rig.claim()
    kinds = _op_kinds(rig.ops)
    assert "rollback@ded" not in kinds  # the shipped no-rollback-on-cancellation nuance
    assert kinds == ["execute-batch@ded", "execute-reset@ded", "commit@ded"]  # shield completed
    assert store._claim_holders_discarded_total == 1
    assert rig.conns[0].closed is True


async def test_cancel_during_guard_on_retained_cursor_shield_completes_then_discard() -> None:
    # The prepared-path twin of the fold suite's cancellation-during-finally leg: force the guard
    # (via 1222), cancel while its reset is in flight ON THE RETAINED CURSOR — the shield must
    # complete the reset+commit on the dedicated session before the CancelledError re-raises,
    # and the holder is then DISCARDED (closed), never returned half-reset to the free list.
    store = _prepared_store()
    started = asyncio.Event()
    release = asyncio.Event()
    rig = _Rig(
        store,
        fail_batch=_lock_timeout_error(),
        reset_started=started,
        reset_release=release,
    )
    task = asyncio.ensure_future(rig.claim())
    await asyncio.wait_for(started.wait(), timeout=5)  # the guard's reset started on @ded
    task.cancel()
    await asyncio.sleep(0)
    release.set()
    with pytest.raises(asyncio.CancelledError):
        await asyncio.wait_for(task, timeout=5)
    assert _op_kinds(rig.ops) == [
        "execute-batch@ded",
        "rollback@ded",
        "execute-reset@ded",
        "commit@ded",
    ]
    assert store._claim_holders_discarded_total == 1
    assert rig.conns[0].closed is True, "the discard's shielded close must finish despite cancel"


async def test_ac5_contract_violation_discards_holder() -> None:
    # The AC-5 H2-noop runtime guard fires on the prepared path too (fold is ON by coupling);
    # its RuntimeError is an unclassified error -> the holder is discarded.
    store = _prepared_store()
    rig = _Rig(store, rows=[_row("r1", destination_name="OB_SNEAK")])
    with pytest.raises(RuntimeError, match="fold contract violation"):
        await rig.claim()
    assert store._claim_holders_discarded_total == 1


# --- teardown lifecycle ----------------------------------------------------------------------------


async def test_close_claim_holders_closes_retained_connections() -> None:
    store = _prepared_store()
    rig = _Rig(store)
    await rig.claim()
    assert rig.conns[0].closed is False
    await store._close_claim_holders()
    assert rig.conns[0].closed is True
    assert store._claim_holders == {}
    assert store._claim_holders_open == 0


async def test_teardown_during_in_flight_claim_discards_on_return() -> None:
    # The borrowed-at-teardown leak (an adversarial-review find): close() runs while a claim
    # holds a borrowed holder — the holder must be DISCARDED (closed) when the claim returns,
    # never re-retained into the closed store's cleared dict.
    store = _prepared_store()
    started = asyncio.Event()
    release = asyncio.Event()
    rig = _Rig(store, batch_started=started, batch_release=release)
    task = asyncio.ensure_future(rig.claim())
    await asyncio.wait_for(started.wait(), timeout=5)  # claim in flight, holder borrowed
    await store._close_claim_holders()  # teardown with the free list empty
    release.set()
    await asyncio.wait_for(task, timeout=5)  # the claim completes NORMALLY (clean exit)
    assert rig.conns[0].closed is True, "the borrowed holder must be closed on return"
    assert store._claim_holders.get("ingress", []) == []
    assert store._claim_holders_open == 0


async def test_straggler_claim_after_close_discards_its_holder() -> None:
    # A straggler flagged claim AFTER close(): it may open a fresh holder (the engine cancels
    # claim workers before store close, so this is a should-never-happen), but the closed flag
    # guarantees the holder is discarded on return — a closed store leaks no dedicated connection.
    store = _prepared_store()
    rig = _Rig(store)
    await store._close_claim_holders()
    await rig.claim()
    assert rig.conns[0].closed is True
    assert store._claim_holders.get("ingress", []) == []
    assert store._claim_holders_open == 0


# --- pins (8 descriptors, via the sync _impl surface) ----------------------------------------------


async def test_prepared_pins_applied_via_impl_before_execute() -> None:
    store = _prepared_store(pins=_FAKE_PINS_8)
    rig = _Rig(store)

    pinned: list[Any] = []

    async def connect() -> _FakeDedicatedConn:
        cur = _FakeCursor(rig.ops, tag="ded")
        cur._impl = SimpleNamespace(setinputsizes=lambda sizes: pinned.append(sizes))  # type: ignore[attr-defined]
        conn = _FakeDedicatedConn(rig.ops, cur)
        rig.conns.append(conn)
        return conn

    store._connect_claim_conn = connect  # type: ignore[method-assign]
    await rig.claim()
    assert pinned == [_FAKE_PINS_8]


# --- AC-13: the startup-gate couplings -------------------------------------------------------------


async def _gate_prepared(
    store: SqlServerStore, monkeypatch: pytest.MonkeyPatch, *, compat: int = 150
) -> SqlServerStore:
    async def fake_fetchone(sql: str, params: tuple[Any, ...] = ()) -> dict[str, Any] | None:
        assert sql == "SELECT compatibility_level FROM sys.databases WHERE name = DB_NAME()"
        return {"compatibility_level": compat}

    store._fetchone = fake_fetchone  # type: ignore[method-assign]
    monkeypatch.setattr(ss, "_claim_prepared_param_pins", lambda: _FAKE_PINS_8)
    await store._gate_claim_prepared()
    return store


async def test_ac13_gate_noop_without_the_fold(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    store = _prepared_store(effective=False, fold=False, pins=None)
    store._fifo_claim_fold_reset = False
    with caplog.at_level(logging.WARNING, logger="messagefoundry.store.sqlserver"):
        await _gate_prepared(store, monkeypatch)
    assert store.claim_prepared_effective is False
    assert store.claim_prepared_degraded_reason is not None
    assert "requires fifo_claim_fold_reset=ON" in store.claim_prepared_degraded_reason
    assert any("NOT activated" in r.getMessage() for r in caplog.records)
    # And the claim stays on the shipped fold-less batch.
    rig = _Rig(store)
    await rig.claim()
    assert rig.ops[0][0] == "execute-batch@pool"
    assert rig.conns == []


async def test_ac13_gate_superseded_by_green_proc_gate(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    # §5 compose-or-compete: A green -> B retired, not stacked (recorded superseded-for-now).
    store = _prepared_store(effective=False, pins=None)
    store._fifo_claim_proc = True
    store._claim_proc_effective = True
    store._claim_proc_input_sizes = _FAKE_PROC_PINS
    with caplog.at_level(logging.INFO, logger="messagefoundry.store.sqlserver"):
        await _gate_prepared(store, monkeypatch)
    assert store.claim_prepared_effective is False
    assert store.claim_prepared_degraded_reason is not None
    assert "superseded-for-now by fifo_claim_proc" in store.claim_prepared_degraded_reason
    # The claim rides the proc path, never the stable text — proven by the CALL going to the
    # pooled connection with the proc's 9-arg shape.
    rig = _Rig(store)
    await rig.claim()
    kind, sql, params = rig.ops[0]
    assert kind == "execute-batch@pool"
    assert sql.startswith("{CALL dbo.mefor_claim_fifo_heads_cid_v1")
    assert len(params) == 9
    assert rig.conns == []


async def test_ac13_gate_accepts_fold_on_no_proc_compat_ok(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = _prepared_store(effective=False, pins=None)
    await _gate_prepared(store, monkeypatch)
    assert store.claim_prepared_effective is True
    assert store.claim_prepared_degraded_reason is None
    assert store._claim_prepared_input_sizes == _FAKE_PINS_8


async def test_ac13_gate_degrades_below_compat_130(monkeypatch: pytest.MonkeyPatch) -> None:
    store = _prepared_store(effective=False, pins=None)
    await _gate_prepared(store, monkeypatch, compat=120)
    assert store.claim_prepared_effective is False
    assert store.claim_prepared_degraded_reason is not None
    assert "compatibility_level 120 < 130" in store.claim_prepared_degraded_reason


async def test_ac13_gate_probe_failure_degrades(monkeypatch: pytest.MonkeyPatch) -> None:
    store = _prepared_store(effective=False, pins=None)

    async def boom(sql: str, params: tuple[Any, ...] = ()) -> dict[str, Any] | None:
        raise RuntimeError("transient metadata failure")

    store._fetchone = boom  # type: ignore[method-assign]
    monkeypatch.setattr(ss, "_claim_prepared_param_pins", lambda: _FAKE_PINS_8)
    await store._gate_claim_prepared()  # must NOT raise
    assert store.claim_prepared_effective is False
    assert store.claim_prepared_degraded_reason is not None
    assert "startup-gate probe failed" in store.claim_prepared_degraded_reason


# --- observability ---------------------------------------------------------------------------------


async def test_pool_status_reports_claim_pool_when_effective() -> None:
    store = _prepared_store()
    store._pool = SimpleNamespace(maxsize=40, size=2, freesize=1)
    store._acquire_wait = AcquireWaitHistogram()
    rig = _Rig(store)
    await rig.claim()
    status = store.pool_status()
    assert status is not None and status.claim_pool is not None
    assert status.claim_pool.open == 1
    assert status.claim_pool.idle == 1
    assert status.claim_pool.opened_total == 1
    assert status.claim_pool.discarded_total == 0


def test_pool_status_claim_pool_none_when_inactive() -> None:
    store = _prepared_store(effective=False)
    store._pool = SimpleNamespace(maxsize=40, size=2, freesize=1)
    store._acquire_wait = AcquireWaitHistogram()
    status = store.pool_status()
    assert status is not None and status.claim_pool is None


def test_status_api_maps_claim_pool() -> None:
    # The /status surface: PoolInfo carries the additive claim_pool field (the B11 honesty fix
    # from the adversarial review) — model-level round-trip.
    from messagefoundry.api.models import ClaimPoolInfo, PoolInfo, PoolWaitInfo

    info = PoolInfo(
        backend="sqlserver",
        max_size=40,
        size=2,
        idle=1,
        acquire_wait=PoolWaitInfo(count=0, p50_ms=0, p95_ms=0, p99_ms=0, max_ms=0, mean_ms=0),
        claim_pool=ClaimPoolInfo(open=1, idle=1, opened_total=2, discarded_total=1),
    )
    assert info.claim_pool is not None and info.claim_pool.opened_total == 2
    # Additive: omitting it (older payloads / non-prepared runs) still validates.
    info2 = PoolInfo(
        backend="sqlserver",
        max_size=40,
        size=2,
        idle=1,
        acquire_wait=PoolWaitInfo(count=0, p50_ms=0, p95_ms=0, p99_ms=0, max_ms=0, mean_ms=0),
    )
    assert info2.claim_pool is None


# --- wiring ----------------------------------------------------------------------------------------


@pytest.mark.parametrize("flag", [False, True])
def test_init_snapshots_the_prepared_flag(flag: bool) -> None:
    store = SqlServerStore(object(), StoreSettings(fifo_claim_prepared=flag, command_timeout=30))
    assert store._fifo_claim_prepared is flag
    assert store.claim_prepared_effective is False  # only the open()-time gate can activate it


def test_sqlserver_reads_the_prepared_flag() -> None:
    source = inspect.getsource(ss)
    assert "settings.fifo_claim_prepared" in source
