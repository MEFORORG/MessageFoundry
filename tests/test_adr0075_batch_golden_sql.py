# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""ADR 0075 AC-1 — golden-SQL test: the batched and unbatched handoff forms emit the IDENTICAL logical
``(sql, params)`` sequence (same statements, same order, same params), grouped into fewer round-trips.

The comparison is reconstructed from the recording cursors: the unbatched run records one statement per
``execute`` (logical == round-trips); the batched run records the per-statement logical sequence via the
``record_logical`` seam and the grouped executes separately. A negative control proves the equality has
teeth — a reordered or dropped grouping does NOT equal the unbatched sequence.
"""

from __future__ import annotations

import pytest

from messagefoundry.store import sqlserver as ss

import adr0075_batch_harness as h


async def _run_pair(
    method: str, batched_method: str, *, scenario: str = "processed", **kwargs: object
) -> tuple[list, list, list, int, int]:
    """Drive the unbatched and batched forms with deterministic uuids; return
    (unbatched_calls, batched_logical, batched_round_trips, unbatched_commits, batched_commits).
    ``scenario`` steers the finalize disposition branch (both arms walk the SAME branch)."""
    det = h.DetUUID()

    # Unbatched (flag OFF): logical sequence == recorded executes.
    det.reset()
    ss.uuid4 = det  # type: ignore[assignment]
    un_cur, un_conn = h.AsyncRecCursor(scenario), h.RecConn()
    ok = await h.drive_async(
        h.bare_store(batch=False), method, cursor=un_cur, conn=un_conn, **kwargs
    )
    assert ok is True or ok == (True, []) or (isinstance(ok, tuple) and ok[0] is True)

    # Batched (flag ON): logical sequence via record_logical, round-trips via .calls.
    det.reset()
    ss.uuid4 = det  # type: ignore[assignment]
    ba_cur, ba_conn = h.BatchRecCursor(scenario), h.RecConn()
    ok2 = await h.drive_async(
        h.bare_store(batch=True), method, cursor=ba_cur, conn=ba_conn, **kwargs
    )
    assert ok2 is True or (isinstance(ok2, tuple) and ok2[0] is True)

    return un_cur.calls, ba_cur.logical, ba_cur.calls, un_conn.commits, ba_conn.commits


@pytest.fixture(autouse=True)
def _restore_uuid() -> object:
    saved = ss.uuid4
    yield
    ss.uuid4 = saved  # type: ignore[assignment]


async def test_route_batched_matches_unbatched_sequence() -> None:
    un_calls, ba_logical, ba_rt, un_commits, ba_commits = await _run_pair(
        "route_handoff", "_route_handoff_batched", **h.ROUTE_KWARGS
    )
    # AC-1: identical logical (sql, params) sequence, byte-for-byte.
    assert ba_logical == un_calls
    assert len(un_calls) > 0
    # ... grouped into strictly fewer round-trips (N=1 handler: 5 executes -> 3 executes).
    assert len(ba_rt) < len(un_calls)
    # commits/msg unchanged: exactly one per hop.
    assert un_commits == 1 and ba_commits == 1
    # The leading guard-DELETE opens the txn; the finalize applock is never first.
    assert un_calls[0][0] == ss._SQL_DELETE_GUARD
    applock_idx = next(i for i, (s, _) in enumerate(un_calls) if "sp_getapplock" in s)
    assert applock_idx > 0


async def test_transform_batched_matches_unbatched_sequence() -> None:
    un_calls, ba_logical, ba_rt, un_commits, ba_commits = await _run_pair(
        "transform_handoff", "_transform_handoff_batched", **h.TRANSFORM_KWARGS
    )
    assert ba_logical == un_calls
    assert len(ba_rt) < len(un_calls)
    assert un_commits == 1 and ba_commits == 1
    seq = [s for s, _ in un_calls]
    assert seq[0] == ss._SQL_DELETE_GUARD
    assert ss._SQL_INSERT_QUEUE_OUTBOUND in seq
    assert ss._SQL_FINALIZE_COUNT in seq
    assert ss._SQL_UPDATE_MESSAGE_STATUS in seq  # finalizer wrote PROCESSED


async def test_transform_batched_with_state_and_multi_delivery_matches() -> None:
    # State MERGEs + 2 deliveries: the loops fold into the group ending at the finalize applock. Proves
    # the batched form preserves the shared sorted((namespace,key)) order and delivery order.
    kwargs = dict(
        routed_id="rtd-9",
        message_id="m-9",
        channel_id="IB",
        deliveries=[("OB2", "b2"), ("OB1", "b1")],
        state_ops=[("zeta", "k2", {"v": 2}), ("alpha", "k1", {"v": 1})],
        pt_deliveries=(),
        now=222.0,
    )
    un_calls, ba_logical, ba_rt, un_commits, ba_commits = await _run_pair(
        "transform_handoff", "_transform_handoff_batched", **kwargs
    )
    assert ba_logical == un_calls
    assert len(ba_rt) < len(un_calls)
    assert un_commits == 1 and ba_commits == 1
    seq = [s for s, _ in un_calls]
    assert seq.count(ss._SQL_STATE_MERGE) == 2
    assert seq.count(ss._SQL_INSERT_QUEUE_OUTBOUND) == 2


async def test_route_batch_applies_nocount_framing_on_the_read_group() -> None:
    # The multi-statement group that ENDS with the applock must carry SET NOCOUNT ON so the preceding
    # INSERT does not shadow the SELECT @rc the client reads (the _SQL_APPLOCK precedent). Assert the
    # rendered round-trip that contains sp_getapplock also contains SET NOCOUNT ON.
    det = h.DetUUID()
    det.reset()
    ss.uuid4 = det  # type: ignore[assignment]
    cur, conn = h.BatchRecCursor(), h.RecConn()
    await h.drive_async(
        h.bare_store(batch=True), "route_handoff", cursor=cur, conn=conn, **h.ROUTE_KWARGS
    )
    applock_batches = [sql for sql, _ in cur.calls if "sp_getapplock" in sql]
    assert len(applock_batches) == 1
    rendered = applock_batches[0]
    assert "SET NOCOUNT ON" in rendered
    assert ss._SQL_INSERT_QUEUE_ROUTED.rstrip(";") in rendered  # the insert folded in ahead of it
    # positional params concatenate across the batch (insert params THEN applock params).
    applock_call = next(p for sql, p in cur.calls if "sp_getapplock" in sql)
    assert applock_call[-1] == ss._applock_timeout_ms(30)  # applock @LockTimeout is the last param


async def test_negative_control_reordered_or_dropped_grouping_fails() -> None:
    # Proves the golden equality is a REAL check: a reconstruction that reorders or drops a statement
    # does NOT equal the unbatched sequence (so the passing assertions above are non-vacuous).
    un_calls, ba_logical, _rt, _uc, _bc = await _run_pair(
        "route_handoff", "_route_handoff_batched", **h.ROUTE_KWARGS
    )
    assert ba_logical == un_calls  # baseline: they match

    # Reorder two adjacent statements -> must differ.
    reordered = list(ba_logical)
    reordered[1], reordered[2] = reordered[2], reordered[1]
    assert reordered != un_calls

    # Drop one statement -> must differ.
    dropped = ba_logical[:-1]
    assert dropped != un_calls

    # Mutate a single param -> must differ (params are compared, not just SQL text).
    mutated = list(ba_logical)
    sql0, params0 = mutated[0]
    mutated[0] = (sql0, params0 + ("EXTRA",))
    assert mutated != un_calls


class _AsyncEmptyGuard(h.AsyncRecCursor):
    async def fetchone(self) -> object:
        return None  # guard finds nothing -> idempotent no-op


class _BatchEmptyGuard(h.BatchRecCursor):
    async def fetchone(self) -> object:
        return None


async def test_batched_idempotent_noop_matches_unbatched() -> None:
    # When the guard-DELETE finds nothing (already consumed), BOTH forms must roll back and return False
    # after emitting ONLY the guard DELETE — one round-trip, no commit, identical no-op sequence.
    ss.uuid4 = h.DetUUID()  # type: ignore[assignment]
    un_cur, un_conn = _AsyncEmptyGuard(), h.RecConn()
    ok = await h.drive_async(
        h.bare_store(batch=False), "route_handoff", cursor=un_cur, conn=un_conn, **h.ROUTE_KWARGS
    )
    assert ok is False

    ss.uuid4 = h.DetUUID()  # type: ignore[assignment]
    ba_cur, ba_conn = _BatchEmptyGuard(), h.RecConn()
    ok2 = await h.drive_async(
        h.bare_store(batch=True), "route_handoff", cursor=ba_cur, conn=ba_conn, **h.ROUTE_KWARGS
    )
    assert ok2 is False

    assert ba_cur.logical == un_cur.calls
    assert [s for s, _ in un_cur.calls] == [ss._SQL_DELETE_GUARD]
    # No commit on either path; each rolled back exactly once.
    assert un_conn.commits == 0 and ba_conn.commits == 0
    assert un_conn.rollbacks == 1 and ba_conn.rollbacks == 1


# --- route_handoff fan-out coverage: N>1 handlers and 0 handlers (UNROUTED) -----------------------


async def test_route_batched_multi_handler_matches() -> None:
    kwargs = dict(
        ingress_id="ing-2",
        message_id="m-2",
        channel_id="IB",
        handlers=[("H1", "p1"), ("H2", "p2"), ("H3", "p3")],
        disposition=ss.MessageStatus.ROUTED,
        now=100.0,
    )
    un_calls, ba_logical, ba_rt, un_commits, ba_commits = await _run_pair(
        "route_handoff", "_route_handoff_batched", **kwargs
    )
    assert ba_logical == un_calls
    assert len(ba_rt) < len(un_calls)
    assert un_commits == 1 and ba_commits == 1
    # All three routed inserts folded into ONE group ahead of the applock.
    assert [s for s, _ in un_calls].count(ss._SQL_INSERT_QUEUE_ROUTED) == 3


async def test_route_batched_unrouted_zero_handlers_matches() -> None:
    kwargs = dict(
        ingress_id="ing-3",
        message_id="m-3",
        channel_id="IB",
        handlers=[],
        disposition=ss.MessageStatus.UNROUTED,
        now=100.0,
    )
    un_calls, ba_logical, ba_rt, un_commits, ba_commits = await _run_pair(
        "route_handoff", "_route_handoff_batched", **kwargs
    )
    assert ba_logical == un_calls
    assert len(ba_rt) < len(un_calls)
    assert un_commits == 1 and ba_commits == 1
    # No inserts: the applock group is a lone statement -> executed RAW (== _SQL_APPLOCK, no extra
    # render framing), so it carries exactly ONE SET NOCOUNT ON (the constant's own, not doubled).
    # UNROUTED disposition written by the finalizer UPDATE.
    seq = [s for s, _ in un_calls]
    assert seq.count(ss._SQL_INSERT_QUEUE_ROUTED) == 0
    assert ss._SQL_UPDATE_MESSAGE_STATUS in seq
    applock_rt = [sql for sql, _ in ba_rt if "sp_getapplock" in sql]
    assert len(applock_rt) == 1
    assert applock_rt[0] == ss._SQL_APPLOCK  # lone group -> raw constant, byte-identical
    assert applock_rt[0].count("SET NOCOUNT ON") == 1  # not doubled


# --- transform_handoff finalize disposition branches (FILTERED / still-moving / ERROR) ------------


async def test_transform_batched_filtered_disposition_matches() -> None:
    # FILTERED: the transform delivered nothing and no queue rows remain -> the finalizer takes the
    # check_message branch and issues the EXTRA _SQL_SELECT_MESSAGE_STATUS read, then UPDATE=FILTERED.
    kwargs = dict(
        routed_id="rtd-f",
        message_id="m-f",
        channel_id="IB",
        deliveries=[],
        state_ops=(),
        pt_deliveries=(),
        now=100.0,
    )
    un_calls, ba_logical, ba_rt, un_commits, ba_commits = await _run_pair(
        "transform_handoff", "_transform_handoff_batched", scenario="filtered", **kwargs
    )
    assert ba_logical == un_calls
    assert len(ba_rt) < len(un_calls)
    assert un_commits == 1 and ba_commits == 1
    seq = [s for s, _ in un_calls]
    # The extra status read fired in BOTH forms (the check_message branch), then the FILTERED UPDATE.
    assert seq.count(ss._SQL_SELECT_MESSAGE_STATUS) == 1
    assert ss._SQL_UPDATE_MESSAGE_STATUS in seq
    # The status read is its OWN round-trip in the batched form (a read boundary).
    assert any(sql == ss._SQL_SELECT_MESSAGE_STATUS for sql, _ in ba_rt)


async def test_transform_batched_still_moving_disposition_matches() -> None:
    # still-moving: a PENDING queue row remains -> the finalizer returns WITHOUT an UPDATE (one fewer
    # statement). Batched must emit the identical (shorter) sequence.
    kwargs = dict(
        routed_id="rtd-s",
        message_id="m-s",
        channel_id="IB",
        deliveries=[("OB1", "b1")],
        state_ops=(),
        pt_deliveries=(),
        now=100.0,
    )
    un_calls, ba_logical, ba_rt, un_commits, ba_commits = await _run_pair(
        "transform_handoff", "_transform_handoff_batched", scenario="still_moving", **kwargs
    )
    assert ba_logical == un_calls
    assert len(ba_rt) < len(un_calls)
    assert un_commits == 1 and ba_commits == 1
    seq = [s for s, _ in un_calls]
    assert ss._SQL_UPDATE_MESSAGE_STATUS not in seq  # still moving -> no finalize UPDATE
    assert ss._SQL_SELECT_MESSAGE_STATUS not in seq  # not the check_message branch


async def test_transform_batched_error_disposition_matches() -> None:
    # ERROR: a DEAD queue row -> finalizer UPDATE=ERROR (no extra status read).
    kwargs = dict(
        routed_id="rtd-e",
        message_id="m-e",
        channel_id="IB",
        deliveries=[("OB1", "b1")],
        state_ops=(),
        pt_deliveries=(),
        now=100.0,
    )
    un_calls, ba_logical, ba_rt, un_commits, ba_commits = await _run_pair(
        "transform_handoff", "_transform_handoff_batched", scenario="error", **kwargs
    )
    assert ba_logical == un_calls
    assert len(ba_rt) < len(un_calls)
    assert un_commits == 1 and ba_commits == 1
    seq = [s for s, _ in un_calls]
    assert ss._SQL_UPDATE_MESSAGE_STATUS in seq
    assert ss._SQL_SELECT_MESSAGE_STATUS not in seq
