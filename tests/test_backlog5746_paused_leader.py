# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #5746: a leader whose claim holds at an epoch other than the one it led on demotes,
so the engine gets the demotion and promotion edges.

After a process pause longer than the lease TTL every due timer fires at once, so the tick can run
before the fence watchdog. Its claim may then hold because another node took the row and lost it,
which moved the epoch, and the node used to lead on with no demotion edge and no promotion edge: the
engine never tore down the frozen graph and never ran the promotion recovery. Driven with a
controlled monotonic clock and the claim replaced, so no database is needed. The path where a claim
itself returns past the fence is BACKLOG #5711's, tested in test_backlog5711_late_claim.py.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import pytest

from messagefoundry.pipeline.cluster import DbCoordinator
from messagefoundry.pipeline.cluster_sqlserver import SqlServerCoordinator

_FENCE = 20.0
_TTL = 30.0


class _Clock:
    def __init__(self) -> None:
        self.t = 1000.0

    def __call__(self) -> float:
        return self.t


_COORDINATORS: list[tuple[str, Callable[[_Clock], Any]]] = [
    (
        "postgres",
        lambda clock: DbCoordinator(
            object(), "A", leader_fence_timeout_seconds=_FENCE, monotonic=clock
        ),
    ),
    (
        "sqlserver",
        lambda clock: SqlServerCoordinator(
            object(), "A", leader_fence_timeout_seconds=_FENCE, monotonic=clock
        ),
    ),
]
_IDS = [name for name, _ in _COORDINATORS]


def _claim_holding(coord: Any, epoch: int, calls: list[int]) -> None:
    """Replace the claim with one that holds the lease at once, at ``epoch``."""

    async def claim() -> bool:
        calls.append(epoch)
        coord._leader_epoch = epoch
        return True

    coord._claim_or_renew_lease = claim


def _edges(coord: Any) -> list[str]:
    edges: list[str] = []
    coord.set_on_demote(lambda: edges.append("demote"))
    coord._alert_leadership_acquired = lambda: edges.append("acquire")
    return edges


@pytest.mark.parametrize(("_name", "make"), _COORDINATORS, ids=_IDS)
async def test_a_hold_at_a_moved_epoch_demotes_then_promotes(
    _name: str, make: Callable[[_Clock], Any]
) -> None:
    """Before the fix the node stayed leader at the other node's epoch, and no edge fired."""
    clock = _Clock()
    coord = make(clock)
    calls: list[int] = []
    _claim_holding(coord, 5, calls)
    await coord._maintain_leadership()
    assert coord.is_leader() is True
    edges = _edges(coord)

    clock.t += _TTL + 5.0  # the process was paused; the watchdog has not run yet
    _claim_holding(coord, 7, calls)  # another node led at epoch 6; this claim took the row back
    await coord._maintain_leadership()
    assert coord.is_leader() is False
    assert coord.current_epoch() is None
    assert edges == ["demote"]
    assert coord.may_own_lease_row() is True  # the row is this node's again

    await coord._maintain_leadership()
    assert coord.is_leader() is True
    assert coord.current_epoch() == 7
    assert edges == ["demote", "acquire"]  # the promotion edge the recovery runs on


@pytest.mark.parametrize(("_name", "make"), _COORDINATORS, ids=_IDS)
async def test_one_failed_renew_does_not_demote(_name: str, make: Callable[[_Clock], Any]) -> None:
    """The shipped cadence: one renew fails, and the next tick runs two heartbeats plus jitter after
    the last good one, past the fence. A check on the renew's age would demote there; the epoch did
    not move, so the leader renews and keeps leading."""
    clock = _Clock()
    coord = make(clock)
    calls: list[int] = []
    _claim_holding(coord, 5, calls)
    await coord._maintain_leadership()
    edges = _edges(coord)

    async def failing() -> bool:
        raise TimeoutError

    coord._claim_or_renew_lease = failing
    clock.t += 10.0
    with pytest.raises(TimeoutError):
        await coord._maintain_leadership()
    clock.t += 10.002
    _claim_holding(coord, 5, calls)
    await coord._maintain_leadership()
    assert coord.is_leader() is True
    assert coord.current_epoch() == 5
    assert edges == []


@pytest.mark.parametrize(("_name", "make"), _COORDINATORS, ids=_IDS)
async def test_a_hold_at_the_same_epoch_after_a_pause_keeps_leading(
    _name: str, make: Callable[[_Clock], Any]
) -> None:
    """An unchanged epoch means no other node took the row while this one was paused, so there is
    no other node's work to recover, and the leader renews without an edge."""
    clock = _Clock()
    coord = make(clock)
    calls: list[int] = []
    _claim_holding(coord, 5, calls)
    await coord._maintain_leadership()
    edges = _edges(coord)
    clock.t += _TTL + 5.0
    await coord._maintain_leadership()
    assert coord.is_leader() is True
    assert edges == []
    assert calls == [5, 5]


@pytest.mark.parametrize(("_name", "make"), _COORDINATORS, ids=_IDS)
async def test_a_standby_acquiring_at_any_epoch_promotes(
    _name: str, make: Callable[[_Clock], Any]
) -> None:
    """The check binds leaders only: a standby whose stale cached epoch differs still promotes."""
    clock = _Clock()
    coord = make(clock)
    coord._leader_epoch = 2
    calls: list[int] = []
    _claim_holding(coord, 3, calls)
    edges = _edges(coord)
    await coord._maintain_leadership()
    assert coord.is_leader() is True
    assert edges == ["acquire"]
