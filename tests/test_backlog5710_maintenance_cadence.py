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

from messagefoundry.pipeline.cluster import DbCoordinator, run_maintenance_loop
from messagefoundry.pipeline.cluster_sqlserver import SqlServerCoordinator

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
    _name: str, make: Callable[[float], Any], refresh: str
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
            node_id="A",
        ),
        timeout=5.0,
    )
    assert renews == 3
    assert "cluster: leadership maintenance failed for node A; will retry" in caplog.text
