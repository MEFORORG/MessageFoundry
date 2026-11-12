# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #5710: a slow non-lease statement must not delay the lease renew.

Both coordinators' maintenance loops used to run the heartbeat, the renew and the config-version
refresh in series and then sleep a fixed interval, so a stalled heartbeat or refresh pushed the next
renew back by its own bound plus the whole interval, and the fence watchdog counted that gap. These
drive each coordinator's real ``_heartbeat_loop`` with its statements replaced, so they need no
database and run on every ordinary leg.
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from typing import Any

import pytest

from messagefoundry.pipeline import cluster, cluster_sqlserver
from messagefoundry.pipeline.cluster import DbCoordinator, run_maintenance_loop
from messagefoundry.pipeline.cluster_sqlserver import SqlServerCoordinator
from tests._pool_lend import LendsItself

# The SQL Server loop refreshes through the clamped method, the Postgres loop through the public
# read (test_adr0157_b1497_sqlserver_renew_clamp pins the SQL Server choice).
_COORDINATORS: list[tuple[str, Callable[[float], Any], str]] = [
    ("postgres", lambda hb: DbCoordinator(object(), "A", heartbeat_seconds=hb), "config_version"),
    (
        "sqlserver",
        lambda hb: SqlServerCoordinator(object(), "A", heartbeat_seconds=hb),
        "_refresh_config_version",
    ),
]


def _ids() -> list[str]:
    return [name for name, _, _ in _COORDINATORS]


async def _wait_until(predicate: Callable[[], bool], timeout: float = 5.0) -> None:
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    while not predicate():
        if loop.time() > deadline:
            raise AssertionError("condition not reached in time")
        await asyncio.sleep(0.005)


@pytest.mark.parametrize(("_name", "make", "refresh"), _COORDINATORS, ids=_ids())
async def test_a_hung_heartbeat_does_not_stop_the_renews(
    _name: str, make: Callable[[float], Any], refresh: str, caplog: pytest.LogCaptureFixture
) -> None:
    """A heartbeat that never returns used to hold the whole tick, so no renew ran behind it and a
    leader self-fenced over a statement that is not the lease. Before the fix this timed out with
    no renew at all, because the heartbeat ran first."""
    coord = make(0.01)
    claims = 0
    beats_started = 0
    beat_cancelled = asyncio.Event()
    never = asyncio.Event()

    async def claim() -> None:
        nonlocal claims
        claims += 1

    async def hung_beat() -> None:
        nonlocal beats_started
        beats_started += 1
        try:
            await never.wait()
        except asyncio.CancelledError:
            beat_cancelled.set()
            raise

    async def noop() -> int:
        return 0

    coord._maintain_leadership = claim
    coord.heartbeat_once = hung_beat
    setattr(coord, refresh, noop)
    task = asyncio.create_task(coord._heartbeat_loop())
    try:
        await _wait_until(lambda: claims >= 5)
        # The hung pass is still running, so no tick started a second one beside it.
        assert beats_started == 1
        # And each skipped tick says so, so a pass that never ends is visible.
        assert "the previous pass is still running" in caplog.text
    finally:
        coord._stop.set()
        await asyncio.wait_for(task, timeout=5.0)
    # The loop cancelled the hung pass and waited for it, so stop()'s bounded wait covers it.
    assert beat_cancelled.is_set()


@pytest.mark.parametrize(("_name", "make", "refresh"), _COORDINATORS, ids=_ids())
async def test_the_renew_runs_first_and_the_others_follow_it(
    _name: str, make: Callable[[float], Any], refresh: str
) -> None:
    """The first statement of the first tick is the renew, and the heartbeat and refresh follow in
    that order. Before the fix the heartbeat ran first."""
    coord = make(60.0)
    calls: list[str] = []

    async def claim() -> None:
        calls.append("renew")

    async def beat() -> None:
        calls.append("heartbeat")

    async def read() -> int:
        calls.append("refresh")
        coord._stop.set()
        return 0

    coord._maintain_leadership = claim
    coord.heartbeat_once = beat
    setattr(coord, refresh, read)
    await asyncio.wait_for(coord._heartbeat_loop(), timeout=5.0)
    assert calls == ["renew", "heartbeat", "refresh"]


async def test_ticks_are_paced_from_their_start_not_their_end() -> None:
    """A tick that costs most of the interval shortens the wait instead of adding to it. Before the
    fix the loop slept the full interval after every tick, so these renews started 0.7 s apart."""
    loop = asyncio.get_running_loop()
    stop = asyncio.Event()
    starts: list[float] = []

    async def slow_renew() -> None:
        starts.append(loop.time())
        if len(starts) >= 3:
            stop.set()
        await asyncio.sleep(0.3)

    async def noop() -> None:
        pass

    await asyncio.wait_for(
        run_maintenance_loop(
            stop=stop,
            interval=0.4,
            lease_step=("renew", slow_renew),
            side_steps=(("heartbeat", noop),),
            side_step_timeout=5.0,
            node_id="A",
        ),
        timeout=5.0,
    )
    gaps = [b - a for a, b in zip(starts, starts[1:], strict=False)]
    assert len(gaps) == 2
    # 0.4 s apart on the fix, 0.7 s on the old pacing; the threshold leaves room for a slow runner.
    assert all(gap < 0.6 for gap in gaps), gaps


async def test_a_failing_step_is_logged_and_the_loop_goes_on(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """A raise in any step is logged under its label and the next tick still runs, as before."""
    stop = asyncio.Event()
    renews = 0

    async def renew() -> None:
        nonlocal renews
        renews += 1
        if renews >= 3:
            stop.set()
        raise RuntimeError("renew down")

    async def beat() -> None:
        raise RuntimeError("beat down")

    await asyncio.wait_for(
        run_maintenance_loop(
            stop=stop,
            interval=0.01,
            lease_step=("leadership maintenance", renew),
            side_steps=(("heartbeat", beat),),
            side_step_timeout=5.0,
            node_id="A",
        ),
        timeout=5.0,
    )
    assert renews == 3
    assert "cluster: leadership maintenance failed for node A; will retry" in caplog.text


# --- a side pass that never ends (BACKLOG #5710, review round 3) -------------------------------


@pytest.mark.parametrize(("_name", "make", "refresh"), _COORDINATORS, ids=_ids())
async def test_a_hung_heartbeat_is_cancelled_at_its_bound_and_the_next_one_runs(
    _name: str,
    make: Callable[[float], Any],
    refresh: str,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """A heartbeat that never returns, as a SQL Server COMMIT nothing bounds can, is cancelled once
    it has run its bound, and a fresh one follows. Before the fix the loop only skipped ticks
    behind it, so ``last_seen`` stayed frozen for good while the node kept leading."""
    # Shrink the bound (SIDE_STEP_CLAMPS renew clamps) so the test waits milliseconds, not seconds.
    monkeypatch.setattr(cluster, "SIDE_STEP_CLAMPS", 0.01)
    monkeypatch.setattr(cluster_sqlserver, "SIDE_STEP_CLAMPS", 0.01)
    coord = make(0.01)
    beats = 0
    first_cancelled = asyncio.Event()
    never = asyncio.Event()

    async def claim() -> None:
        pass

    async def beat() -> None:
        nonlocal beats
        beats += 1
        if beats == 1:
            try:
                await never.wait()
            except asyncio.CancelledError:
                first_cancelled.set()
                raise

    async def noop() -> int:
        return 0

    coord._maintain_leadership = claim
    coord.heartbeat_once = beat
    setattr(coord, refresh, noop)
    task = asyncio.create_task(coord._heartbeat_loop())
    try:
        await _wait_until(lambda: beats >= 2)
    finally:
        coord._stop.set()
        await asyncio.wait_for(task, timeout=5.0)
    assert first_cancelled.is_set()
    assert "did not finish within" in caplog.text


async def test_a_deferred_pass_runs_as_soon_as_the_slow_one_ends() -> None:
    """A tick that finds the side pass still running owes one more, run the moment it ends, rather
    than waiting for the next tick to find the lane free. Without it, one heartbeat slower than the
    interval cost a whole extra interval of ``last_seen``, which the lapse check counts."""
    loop = asyncio.get_running_loop()
    stop = asyncio.Event()
    starts: list[float] = []
    ends: list[float] = []

    async def renew() -> None:
        pass

    async def beat() -> None:
        starts.append(loop.time())
        if len(starts) == 1:
            await asyncio.sleep(0.5)  # past the next tick, which defers
        else:
            stop.set()
        ends.append(loop.time())

    await asyncio.wait_for(
        run_maintenance_loop(
            stop=stop,
            interval=0.4,
            lease_step=("renew", renew),
            side_steps=(("heartbeat", beat),),
            side_step_timeout=5.0,
            node_id="A",
        ),
        timeout=5.0,
    )
    assert len(starts) == 2
    # The second beat followed the first at once (the next tick, at 0.8 s, would be 0.3 s later).
    assert starts[1] - ends[0] < 0.2, (starts, ends)


class _BeatPool(LendsItself):
    """The heartbeat UPDATE on Postgres; the claim is replaced, so nothing else arrives."""

    async def execute(self, sql: str, *args: object) -> str:
        assert "UPDATE nodes SET last_seen" in sql, sql
        return "UPDATE 1"


class _BeatStore:
    """The heartbeat UPDATE on SQL Server."""

    async def _execute_clamped(self, sql: str, params: object, *, timeout_clamp: float) -> int:
        assert "UPDATE nodes SET last_seen" in sql, sql
        return 1


class _Clock:
    def __init__(self) -> None:
        self.t = 1000.0

    def __call__(self) -> float:
        return self.t


_LAPSE_COORDINATORS: list[tuple[str, Callable[[_Clock], Any]]] = [
    ("postgres", lambda clock: DbCoordinator(_BeatPool(), "A", monotonic=clock)),
    ("sqlserver", lambda clock: SqlServerCoordinator(_BeatStore(), "A", monotonic=clock)),
]
_LAPSE_IDS = [name for name, _ in _LAPSE_COORDINATORS]


def _leading(coord: Any) -> list[str]:
    """Replace the claim with a fast hold, and record each claim and each leadership-lost reason."""
    events: list[str] = []

    async def claim() -> bool:
        events.append("claim")
        coord._leader_epoch = 7
        return True

    coord._claim_or_renew_lease = claim
    coord._alert_leadership_lost = lambda reason: events.append(f"lost: {reason}")
    return events


@pytest.mark.parametrize(("_name", "make"), _LAPSE_COORDINATORS, ids=_LAPSE_IDS)
async def test_a_leader_whose_heartbeat_lapsed_stands_down_and_does_not_claim(
    _name: str, make: Callable[[_Clock], Any]
) -> None:
    """The renew lands but the heartbeat has not for longer than node_timeout_seconds (30 s), so
    siblings read this node as dead. The watchdog demotes it, the tick sends no claim, and once a
    heartbeat lands the node claims again. Before the fix it kept leading on a frozen heartbeat."""
    clock = _Clock()
    coord = make(clock)
    events = _leading(coord)
    await coord.heartbeat_once()
    await coord._maintain_leadership()
    assert coord.is_leader() is True
    clock.t += 15.0
    await coord._maintain_leadership()  # the renew still lands; the heartbeats do not
    clock.t += 15.5  # 30.5 s since the last heartbeat landed, 15.5 s since the renew
    coord._check_fence()
    assert coord.is_leader() is False
    assert coord.current_epoch() is None
    assert events == ["claim", "claim", "lost: heartbeat lapsed"]
    # The row is still this node's on the DB clock, so a stepdown must still send its write.
    assert coord.may_own_lease_row() is True
    await coord._maintain_leadership()
    assert events.count("claim") == 2, "a node whose heartbeat lapsed sent a claim"
    await coord.heartbeat_once()
    await coord._maintain_leadership()
    assert events.count("claim") == 3
    assert coord.is_leader() is True


@pytest.mark.parametrize(("_name", "make"), _LAPSE_COORDINATORS, ids=_LAPSE_IDS)
async def test_a_heartbeat_inside_node_timeout_costs_the_leader_nothing(
    _name: str, make: Callable[[_Clock], Any]
) -> None:
    """The lapse check is the siblings' own freshness rule, so a leader whose last heartbeat landed
    exactly node_timeout_seconds ago still leads, and the renew still goes out: one slow heartbeat
    must not demote a healthy leader (the #5710 defect, in another place)."""
    clock = _Clock()
    coord = make(clock)
    events = _leading(coord)
    await coord.heartbeat_once()
    await coord._maintain_leadership()
    clock.t += 15.0
    await coord._maintain_leadership()
    clock.t += 15.0  # exactly node_timeout_seconds since the heartbeat
    coord._check_fence()
    await coord._maintain_leadership()
    assert coord.is_leader() is True
    assert events == ["claim", "claim", "claim"]
