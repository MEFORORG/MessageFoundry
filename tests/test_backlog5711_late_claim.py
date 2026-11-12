# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #5711: a lease claim that returns past the fence timeout must not promote.

The tick stamps its fence baseline before the claim is issued (ADR 0157 Inc 0). A claim that
returned more than the fence timeout later used to stamp that already-expired baseline and promote
anyway, so the watchdog demoted the node again on its next tick: a false acquire edge each time, and,
where the return was late enough for a standby to have taken the row, a two-leader window for that
tick. The SQL Server claim is the row's case, because its clamp leaves the COMMIT unbounded; the
Postgres twin takes the same check in lockstep. Driven with a controlled monotonic clock and the
claim replaced, so no database is needed.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import pytest

from messagefoundry.pipeline.cluster import DbCoordinator
from messagefoundry.pipeline.cluster_sqlserver import SqlServerCoordinator

_FENCE = 20.0


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


def _claim_taking(coord: Any, clock: _Clock, seconds: float, epoch: int = 7) -> None:
    """Replace the claim with one that holds the lease and returns ``seconds`` after it was issued."""

    async def claim() -> bool:
        clock.t += seconds
        coord._leader_epoch = epoch
        return True

    coord._claim_or_renew_lease = claim


@pytest.mark.parametrize(("_name", "make"), _COORDINATORS, ids=_IDS)
async def test_a_late_claim_does_not_promote_a_standby(
    _name: str, make: Callable[[_Clock], Any]
) -> None:
    """Before the fix the node promoted here, and its fence fired on the next watchdog tick."""
    clock = _Clock()
    coord = make(clock)
    issued_at = clock.t
    _claim_taking(coord, clock, _FENCE + 0.5)
    await coord._maintain_leadership()
    assert coord.is_leader() is False
    assert coord.current_epoch() is None
    # The row is ours on the DB clock, so a stepdown must still send the expiring write.
    assert coord.may_own_lease_row() is True
    assert coord._last_renew_ok == issued_at


@pytest.mark.parametrize(("_name", "make"), _COORDINATORS, ids=_IDS)
async def test_a_late_renew_fences_a_leader_at_once(
    _name: str, make: Callable[[_Clock], Any]
) -> None:
    """A leader whose renew returned past the fence is fenced by the tick itself, and the demotion
    edge fires, rather than waiting for the watchdog to notice the stale baseline."""
    clock = _Clock()
    coord = make(clock)
    _claim_taking(coord, clock, 0.1)
    await coord._maintain_leadership()
    assert coord.is_leader() is True
    demoted: list[bool] = []
    coord.set_on_demote(lambda: demoted.append(True))
    _claim_taking(coord, clock, _FENCE + 0.5)
    await coord._maintain_leadership()
    assert coord.is_leader() is False
    assert coord.current_epoch() is None
    assert demoted == [True]


@pytest.mark.parametrize(("_name", "make"), _COORDINATORS, ids=_IDS)
async def test_a_late_hold_after_the_watchdog_fenced_raises_no_second_edge(
    _name: str, make: Callable[[_Clock], Any]
) -> None:
    """The usual order: the watchdog fences the leader while its renew is in flight, then the renew
    returns held. The node stays demoted, and neither an acquire edge nor a second demotion fires."""
    clock = _Clock()
    coord = make(clock)
    _claim_taking(coord, clock, 0.1)
    await coord._maintain_leadership()
    edges: list[str] = []
    coord.set_on_demote(lambda: edges.append("demote"))
    coord._alert_leadership_acquired = lambda: edges.append("acquire")

    async def claim() -> bool:
        clock.t += _FENCE + 0.5
        coord._check_fence()  # the watchdog's tick, while the claim is still in flight
        coord._leader_epoch = 7
        return True

    coord._claim_or_renew_lease = claim
    await coord._maintain_leadership()
    assert coord.is_leader() is False
    assert coord.current_epoch() is None
    assert edges == ["demote"]


@pytest.mark.parametrize(("_name", "make"), _COORDINATORS, ids=_IDS)
async def test_a_late_hold_pauses_this_nodes_claims_past_the_ttl(
    _name: str, make: Callable[[_Clock], Any]
) -> None:
    """Without the pause, the undelayed renew arm would renew the row on every tick, so a node
    whose claims keep returning late would hold it for ever without leading, and no standby could
    take it. The pause outlasts the TTL the refused claim stamped; it lifts early once a read
    shows another owner, as the stepdown pause does."""
    clock = _Clock()
    coord = make(clock)
    _claim_taking(coord, clock, _FENCE + 0.5)
    await coord._maintain_leadership()
    assert coord._no_claim_until == clock.t + 30.0 + 2 * 10.0  # TTL + two heartbeats, defaults


@pytest.mark.parametrize(("_name", "make"), _COORDINATORS, ids=_IDS)
async def test_a_claim_returning_at_the_fence_still_promotes(
    _name: str, make: Callable[[_Clock], Any]
) -> None:
    """The check is the watchdog's own strict test, so a claim that returns exactly at the fence
    timeout promotes, as the watchdog would not yet fence it."""
    clock = _Clock()
    coord = make(clock)
    _claim_taking(coord, clock, _FENCE)
    await coord._maintain_leadership()
    assert coord.is_leader() is True
    assert coord.current_epoch() == 7
    assert coord._no_claim_until == 0.0
