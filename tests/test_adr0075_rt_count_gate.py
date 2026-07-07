# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""ADR 0075 AC-5 — living statement/round-trip-count gate for per-hop statement batching.

Drives the REAL shipped handoffs through the recording cursors and pins BOTH:
  * the UNBATCHED round-trip baseline (executes + the single commit), and
  * the BATCHED round-trip count of the SHIPPED (STRICT / ``applock_hard``) fold,

so the reduction cannot silently regress, and asserts ``commits/msg == 2.000`` for both flag states
(no commit boundary moves). It also pins the ``applock_soft`` reference floor and asserts the shipped
strict count does NOT reach it — the shipped fold keeps the finalize ``sp_getapplock`` rc a client-side
gate, so the ``>=40%`` (soft) figure can NEVER be quoted as achieved from this build.

Honest headline (ADR 0075 §Evidence): per-hop round-trip opportunity is 27-50%; ``>=40%`` holds ONLY
under the applock-fold; the strict interpretation shipped here is 27-33% and clears no 40% bar. A real
throughput GO/NO-GO needs the live-rig A/B — this gate proves the round-trip ARITHMETIC only.
"""

from __future__ import annotations

import pytest

from messagefoundry.store import sqlserver as ss

import adr0075_batch_harness as h

# Round-trips = executes + the one commit. UNBATCHED baseline (hot path, N=1 handler / 1 delivery).
ROUTE_RT_UNBATCHED = 6  # DELETE, INSERT_ROUTED, APPLOCK, UPDATE, EVENT (5) + commit
TRANSFORM_RT_UNBATCHED = (
    7  # DELETE, INSERT_OUTBOUND, EVENT, APPLOCK, FINALIZE_COUNT, UPDATE (6) + commit
)

# SHIPPED strict (applock_hard) fold.
ROUTE_RT_STRICT = 4  # [DELETE] [INSERT_ROUTED,APPLOCK] [UPDATE,EVENT] (3) + commit  -> 33.3%
TRANSFORM_RT_STRICT = (
    5  # [DELETE] [OUTBOUND,EVENT,APPLOCK] [FINALIZE_COUNT] [UPDATE] (4) + commit -> 28.6%
)

# Reference-only (NOT shipped): the applock_soft fold would fold the finalize rc into the trailing batch.
ROUTE_RT_SOFT = 3  # 50.0%
TRANSFORM_RT_SOFT = 4  # 42.9%


@pytest.fixture(autouse=True)
def _restore_uuid() -> object:
    saved = ss.uuid4
    yield
    ss.uuid4 = saved  # type: ignore[assignment]


async def _round_trips(
    method: str, *, batch: bool, scenario: str = "processed", **kwargs: object
) -> tuple[int, int]:
    """Return (executes, commits) for one hop run at the given flag state."""
    det = h.DetUUID()
    det.reset()
    ss.uuid4 = det  # type: ignore[assignment]
    cur = h.BatchRecCursor(scenario) if batch else h.AsyncRecCursor(scenario)
    conn = h.RecConn()
    await h.drive_async(h.bare_store(batch=batch), method, cursor=cur, conn=conn, **kwargs)
    return len(cur.calls), conn.commits


async def test_route_round_trip_floor() -> None:
    un_exec, un_commit = await _round_trips("route_handoff", batch=False, **h.ROUTE_KWARGS)
    ba_exec, ba_commit = await _round_trips("route_handoff", batch=True, **h.ROUTE_KWARGS)
    assert un_exec + un_commit == ROUTE_RT_UNBATCHED
    assert ba_exec + ba_commit == ROUTE_RT_STRICT
    # 33.3% strict drop, pinned.
    assert (ROUTE_RT_UNBATCHED - ROUTE_RT_STRICT) / ROUTE_RT_UNBATCHED == pytest.approx(
        1 / 3, abs=1e-9
    )
    # The shipped strict count does NOT reach the soft floor -> the >=40% (soft) figure is unachieved here.
    assert ROUTE_RT_STRICT > ROUTE_RT_SOFT


async def test_transform_round_trip_floor() -> None:
    un_exec, un_commit = await _round_trips("transform_handoff", batch=False, **h.TRANSFORM_KWARGS)
    ba_exec, ba_commit = await _round_trips("transform_handoff", batch=True, **h.TRANSFORM_KWARGS)
    assert un_exec + un_commit == TRANSFORM_RT_UNBATCHED
    assert ba_exec + ba_commit == TRANSFORM_RT_STRICT
    # 28.6% strict drop, pinned.
    assert (TRANSFORM_RT_UNBATCHED - TRANSFORM_RT_STRICT) / TRANSFORM_RT_UNBATCHED == pytest.approx(
        2 / 7, abs=1e-9
    )
    assert TRANSFORM_RT_STRICT > TRANSFORM_RT_SOFT


async def test_commits_per_msg_is_2000_both_flag_states() -> None:
    # commits/msg identity: exactly one commit per hop, so the route+transform pair is 2.000 — for BOTH
    # flag states (batching moves no commit boundary; this is the covert-transaction-fusion guard).
    for batch in (False, True):
        _e1, route_commits = await _round_trips("route_handoff", batch=batch, **h.ROUTE_KWARGS)
        _e2, transform_commits = await _round_trips(
            "transform_handoff", batch=batch, **h.TRANSFORM_KWARGS
        )
        assert route_commits == 1, f"route commits!=1 (batch={batch})"
        assert transform_commits == 1, f"transform commits!=1 (batch={batch})"
        assert route_commits + transform_commits == 2  # 2.000 per msg


async def test_both_floors_are_pinned_and_ordered() -> None:
    # Guard the reference constants themselves: strict is a real reduction from unbatched, and soft would
    # be an even deeper cut — so neither floor can be silently swapped or the soft one quoted as shipped.
    assert ROUTE_RT_SOFT < ROUTE_RT_STRICT < ROUTE_RT_UNBATCHED
    assert TRANSFORM_RT_SOFT < TRANSFORM_RT_STRICT < TRANSFORM_RT_UNBATCHED


# FILTERED transform (0 deliveries): the finalizer's check_message branch adds the extra
# _SQL_SELECT_MESSAGE_STATUS read as its OWN round-trip.
#   unbatched: DELETE, EVENT, APPLOCK, FINALIZE_COUNT, SELECT_STATUS, UPDATE (6) + commit = 7
#   batched:   [DELETE] [EVENT,APPLOCK] [FINALIZE_COUNT] [SELECT_STATUS] [UPDATE] (5) + commit = 6
FILTERED_RT_UNBATCHED = 7
FILTERED_RT_BATCHED = 6

_FILTERED_KWARGS: dict[str, object] = dict(
    routed_id="rtd-f",
    message_id="m-f",
    channel_id="IB",
    deliveries=[],
    state_ops=(),
    pt_deliveries=(),
    now=100.0,
)


async def test_transform_filtered_branch_round_trip_floor() -> None:
    un_exec, un_commit = await _round_trips(
        "transform_handoff", batch=False, scenario="filtered", **_FILTERED_KWARGS
    )
    ba_exec, ba_commit = await _round_trips(
        "transform_handoff", batch=True, scenario="filtered", **_FILTERED_KWARGS
    )
    assert un_exec + un_commit == FILTERED_RT_UNBATCHED
    assert ba_exec + ba_commit == FILTERED_RT_BATCHED
    # The extra status read is still a distinct round-trip in the batched form (it's a read boundary):
    # the reduction (1 RT) comes only from folding EVENT into the applock group, not from dropping reads.
    assert FILTERED_RT_UNBATCHED - FILTERED_RT_BATCHED == 1
    assert un_commit == 1 and ba_commit == 1  # commits/msg unchanged on the FILTERED branch too
