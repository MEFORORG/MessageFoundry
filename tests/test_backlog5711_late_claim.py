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

import time
from collections.abc import Callable
from typing import Any

import pytest

from messagefoundry.pipeline.cluster import DbCoordinator
from messagefoundry.pipeline.cluster_sqlserver import SqlServerCoordinator
from tests._pool_lend import LendsItself

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
    shows another owner, as the stepdown pause does. Here the membership read fails (the stand-in
    has no pool), so the pause assumes a sibling with no delay could take the lease."""
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


def _node(node_id: str, *, promotable: bool = True, delay: float = 0.0) -> dict[str, object]:
    """A fresh, active ``nodes`` row, as the membership read returns it."""
    now = time.time()
    return {
        "node_id": node_id,
        "host": "h",
        "pid": 1,
        "started_at": now,
        "last_seen": now,
        "status": "active",
        "is_leader": False,
        "acquire_delay_seconds": delay,
        "promotable": promotable,
    }


class _MembersPool(LendsItself):
    """Postgres: answers the membership read a refused late hold sends."""

    def __init__(self, rows: list[dict[str, object]]) -> None:
        self.rows = rows

    async def fetch(self, sql: str, *args: object) -> list[dict[str, object]]:
        assert "FROM nodes" in sql, sql
        return self.rows


class _MembersStore:
    """SQL Server: answers the same read through the store's clamped fetch."""

    def __init__(self, rows: list[dict[str, object]]) -> None:
        self.rows = rows
        self.clamps: list[float | None] = []

    async def _fetch_rows(
        self, sql: str, params: tuple[object, ...], timeout_clamp: float | None = None
    ) -> list[dict[str, object]]:
        assert "FROM nodes" in sql, sql
        self.clamps.append(timeout_clamp)
        return self.rows


_WITH_MEMBERS: list[tuple[str, Callable[[_Clock, list[dict[str, object]]], Any]]] = [
    (
        "postgres",
        lambda clock, rows: DbCoordinator(
            _MembersPool(rows), "A", leader_fence_timeout_seconds=_FENCE, monotonic=clock
        ),
    ),
    (
        "sqlserver",
        lambda clock, rows: SqlServerCoordinator(
            _MembersStore(rows), "A", leader_fence_timeout_seconds=_FENCE, monotonic=clock
        ),
    ),
]


@pytest.mark.parametrize(("_name", "make"), _WITH_MEMBERS, ids=_IDS)
async def test_a_late_hold_with_no_promotable_sibling_does_not_pause(
    _name: str, make: Callable[[_Clock, list[dict[str, object]]], Any]
) -> None:
    """Nobody else could take the row, so a pause would only leave the cluster leaderless, for the
    TTL plus two heartbeats, about 50 s at the defaults. Before the fix it paused that long; now the
    next tick claims, as it did before the refusal existed. A non-promotable sibling, a stale one
    and a cleanly stopped one do not count."""
    clock = _Clock()
    stale = _node("C")
    stale["last_seen"] = time.time() - 3600.0
    left = _node("D")
    left["status"] = "left"
    coord = make(clock, [_node("A"), _node("B", promotable=False), stale, left])
    _claim_taking(coord, clock, _FENCE + 0.5)
    await coord._maintain_leadership()
    assert coord.is_leader() is False
    assert coord._no_claim_until <= clock.t


@pytest.mark.parametrize(("_name", "make"), _WITH_MEMBERS, ids=_IDS)
async def test_a_late_hold_pause_does_not_wait_out_a_sibling_delay(
    _name: str, make: Callable[[_Clock, list[dict[str, object]]], Any]
) -> None:
    """With a promotable sibling the pause is the TTL plus two heartbeats, and a sibling's
    acquire delay is not added: waiting out a DR node's delay after one slow claim would leave the
    cluster leaderless that long and then hand the lease to the least-preferred node."""
    clock = _Clock()
    coord = make(clock, [_node("A"), _node("B", delay=600.0)])
    _claim_taking(coord, clock, _FENCE + 0.5)
    await coord._maintain_leadership()
    assert coord._no_claim_until == clock.t + 30.0 + 2 * 10.0


class _LeasePool(LendsItself):
    """The lease statements a paused Postgres tick can send: the claim, which holds and runs
    ``claim_seconds`` on the node's clock, and the pause's owner read, which reports ``owner``; and
    the membership read a refused late hold sends, which reports ``members``."""

    def __init__(self, clock: _Clock) -> None:
        self._clock = clock
        self.owner = "A"
        self.claim_seconds = 0.0
        self.claims = 0
        self.owner_reads = 0
        self.members = [_node("A"), _node("B")]

    async def fetch(self, sql: str, *args: object) -> list[dict[str, object]]:
        assert "FROM nodes" in sql, sql
        return self.members

    async def fetchrow(self, sql: str, *args: object) -> dict[str, object]:
        if "INSERT INTO leader_lease" in sql:
            self.claims += 1
            self._clock.t += self.claim_seconds
            return {"owner": "A", "leader_epoch": 1}
        assert "SELECT owner FROM leader_lease" in sql, sql
        self.owner_reads += 1
        return {"owner": self.owner}


async def test_the_paused_tick_sends_no_claim_and_lifts_once_another_node_holds_the_row() -> None:
    """End to end on Postgres: after a refused late hold the next tick sends only the owner read,
    not the undelayed renew; once that read names a standby the pause lifts and the stale baseline
    is cleared, so the node no longer reads as owning the row; and the tick after that claims."""
    clock = _Clock()
    pool = _LeasePool(clock)
    coord = DbCoordinator(pool, "A", leader_fence_timeout_seconds=_FENCE, monotonic=clock)
    pool.claim_seconds = _FENCE + 0.5
    await coord._maintain_leadership()
    assert (pool.claims, coord.is_leader()) == (1, False)

    pool.claim_seconds = 0.0
    clock.t += 10.0
    await coord._maintain_leadership()
    assert (pool.claims, pool.owner_reads) == (1, 1)
    assert coord.may_own_lease_row() is True  # the row still names this node

    pool.owner = "B"
    clock.t += 10.0
    await coord._maintain_leadership()
    assert (pool.claims, pool.owner_reads) == (1, 2)
    assert coord._no_claim_until == 0.0
    assert coord.may_own_lease_row() is False

    await coord._maintain_leadership()
    assert pool.claims == 2


async def test_with_no_promotable_sibling_the_next_tick_claims_and_leads_again() -> None:
    """End to end on Postgres: a lone promotable node refuses one late renew, and its next tick
    claims and leads again, as it did before this item. Before the fix that tick sent only the
    paused owner read, for about 50 s."""
    clock = _Clock()
    pool = _LeasePool(clock)
    pool.members = [_node("A"), _node("B", promotable=False)]
    coord = DbCoordinator(pool, "A", leader_fence_timeout_seconds=_FENCE, monotonic=clock)
    pool.claim_seconds = _FENCE + 0.5
    await coord._maintain_leadership()
    assert (pool.claims, coord.is_leader()) == (1, False)

    pool.claim_seconds = 0.0
    clock.t += 10.0
    await coord._maintain_leadership()
    assert (pool.claims, pool.owner_reads) == (2, 0)
    assert coord.is_leader() is True


class _LeaseStore:
    """The SQL Server twin of :class:`_LeasePool`: the MERGE claim, the paused owner read, and the
    membership read, each through the store's clamped calls."""

    def __init__(self, clock: _Clock) -> None:
        self._clock = clock
        self.owner = "A"
        self.claim_seconds = 0.0
        self.claims = 0
        self.owner_reads = 0
        self.members = [_node("A"), _node("B")]

    async def _fetchone_clamped(
        self, sql: str, params: tuple[object, ...], *, timeout_clamp: float
    ) -> dict[str, object]:
        if "MERGE leader_lease" in sql:
            self.claims += 1
            self._clock.t += self.claim_seconds
            return {"owner": "A", "leader_epoch": 1}
        assert "SELECT owner FROM leader_lease" in sql, sql
        self.owner_reads += 1
        return {"owner": self.owner}

    async def _fetch_rows(
        self, sql: str, params: tuple[object, ...], timeout_clamp: float | None = None
    ) -> list[dict[str, object]]:
        assert "FROM nodes" in sql, sql
        return self.members


async def test_sqlserver_with_no_promotable_sibling_the_next_tick_claims_and_leads_again() -> None:
    """The SQL Server twin of the Postgres test above."""
    clock = _Clock()
    store = _LeaseStore(clock)
    store.members = [_node("A")]
    coord = SqlServerCoordinator(store, "A", leader_fence_timeout_seconds=_FENCE, monotonic=clock)
    store.claim_seconds = _FENCE + 0.5
    await coord._maintain_leadership()
    assert (store.claims, coord.is_leader()) == (1, False)

    store.claim_seconds = 0.0
    clock.t += 10.0
    await coord._maintain_leadership()
    assert (store.claims, store.owner_reads) == (2, 0)
    assert coord.is_leader() is True


async def test_sqlserver_the_pause_lift_clears_the_baseline_once_another_node_holds_the_row() -> (
    None
):
    """The SQL Server twin of the Postgres pause-lift test: a paused tick sends only the owner read,
    and once that read names another node the pause lifts and the baseline the refused hold left
    is cleared, so the node no longer reads as owning the row; the tick after that claims."""
    clock = _Clock()
    store = _LeaseStore(clock)
    coord = SqlServerCoordinator(store, "A", leader_fence_timeout_seconds=_FENCE, monotonic=clock)
    store.claim_seconds = _FENCE + 0.5
    await coord._maintain_leadership()
    assert (store.claims, coord.is_leader()) == (1, False)

    store.claim_seconds = 0.0
    clock.t += 10.0
    await coord._maintain_leadership()
    assert (store.claims, store.owner_reads) == (1, 1)
    assert coord.may_own_lease_row() is True  # the row still names this node

    store.owner = "B"
    clock.t += 10.0
    await coord._maintain_leadership()
    assert (store.claims, store.owner_reads) == (1, 2)
    assert coord._no_claim_until == 0.0
    assert coord._last_renew_ok is None
    assert coord.may_own_lease_row() is False

    await coord._maintain_leadership()
    assert store.claims == 2
