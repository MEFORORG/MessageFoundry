# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #1986: a planned stepdown and a clean stop honour leader preference (ADR 0096 AC-2).

Owner ruling 2026-09-30. The release used to write ``lease_expires_at = 0``. The take-over predicate
adds a sibling's ``acquire_delay_seconds`` to that stored expiry, and ``0 + delay`` is before any real
DB clock, so every sibling could take a released lease at once and whichever ticked first won. The
release now stamps the DB clock's own now, so each sibling waits its own delay past the release,
exactly as it does past a lease that expired on its own.

That alone would reopen BACKLOG #1507. The drained node reclaims through the renew arm, which has no
delay term, so with only delayed siblings its two-heartbeat pause ended first and it took its own lease
back. The pause now adds the longest promotable sibling's delay, which the endpoint reads from the
membership read it already takes.

Every scenario runs on both coordinators, against the in-memory stand-ins from
``tests/test_cluster_lease.py``, which assert each statement's SQL text before they touch the shared
row. The DB clock is a realistic epoch (``_EPOCH_NOW``): against a clock that starts at 0.0, "the
release wrote now" and "the release wrote the epoch" are the same number, and these tests could not
tell the fix from the defect.
"""

from __future__ import annotations

import inspect
import math
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from messagefoundry.pipeline.cluster import (
    ClusterCoordinator,
    ClusterMember,
    DbCoordinator,
    NullCoordinator,
    StepdownOutcome,
    has_promotable_sibling,
    longest_promotable_sibling_delay,
    stepdown_pause_seconds,
)
from messagefoundry.pipeline.cluster_sqlserver import SqlServerCoordinator
from tests.test_api_cluster_stepdown import _admin, _auth, _member, _StandinCoordinator
from tests.test_cluster_lease import (
    _EPOCH_NOW,
    _Clock,
    _FakeLeaseDB,
    _FakeLeasePool,
    _FakeSqlLeaseStore,
)

_HEARTBEAT = 10.0
_TTL = 30.0
_Coord = DbCoordinator | SqlServerCoordinator
BACKENDS = pytest.mark.parametrize("backend", ["postgres", "sqlserver"])


class _PgStopPool(_FakeLeasePool):
    """The Postgres stand-in plus the ``nodes`` tombstone ``stop()`` sends after the release. The
    lease statement still goes through the parent, which asserts its SQL text."""

    async def execute(self, sql: str, *args: object) -> str:
        if sql.startswith("UPDATE nodes"):
            return "UPDATE 1"  # the tombstone; no lease semantics
        return await super().execute(sql, *args)


class _SqlStopStore(_FakeSqlLeaseStore):
    """The SQL Server stand-in plus the ``nodes`` tombstone ``stop()`` sends after the release."""

    async def _execute(self, sql: str, params: tuple[object, ...]) -> int:
        if sql.startswith("UPDATE nodes"):
            return 1
        return await super()._execute(sql, params)


def _node(backend: str, db: _FakeLeaseDB, name: str, mono: _Clock, delay: float = 0.0) -> _Coord:
    """One node of ``backend`` over the shared row, at the shipped heartbeat/fence/TTL ratios."""
    if backend == "postgres":
        return DbCoordinator(
            _PgStopPool(db),
            name,
            heartbeat_seconds=_HEARTBEAT,
            leader_lease_ttl_seconds=_TTL,
            leader_fence_timeout_seconds=20.0,
            acquire_delay_seconds=delay,
            monotonic=mono,
        )
    return SqlServerCoordinator(
        _SqlStopStore(db),
        name,
        heartbeat_seconds=_HEARTBEAT,
        leader_lease_ttl_seconds=_TTL,
        leader_fence_timeout_seconds=20.0,
        acquire_delay_seconds=delay,
        monotonic=mono,
    )


class _Cluster:
    """A shared DB clock and one monotonic clock per node, all advanced together."""

    def __init__(self, backend: str) -> None:
        self.backend = backend
        self.db_clock = _Clock(_EPOCH_NOW)
        self.db = _FakeLeaseDB(self.db_clock)
        self._clocks: list[_Clock] = [self.db_clock]

    def node(self, name: str, delay: float = 0.0) -> _Coord:
        mono = _Clock(0.0)
        self._clocks.append(mono)
        return _node(self.backend, self.db, name, mono, delay)

    def advance(self, seconds: float) -> None:
        for clock in self._clocks:
            clock.t += seconds

    def owner(self) -> object:
        return None if self.db.row is None else self.db.row["owner"]


async def _lead(node: _Coord) -> None:
    await node._maintain_leadership()
    assert node.is_leader() is True, "the scenario needs this node to lead first"


# --- a planned stepdown -----------------------------------------------------------------------


@BACKENDS
async def test_after_a_stepdown_the_preferred_sibling_wins_over_a_delayed_one(backend: str) -> None:
    # ADR 0096 AC-2 for a planned handover. The delayed sibling ticks FIRST at every step, so it gets
    # every chance the old release gave it. It is refused while its delay runs, and the preferred
    # sibling takes the lease on its first tick and keeps it by renewing.
    #
    # MUTATION ARM, measured: make the release write the epoch again (`= 0` in both the SQL and the
    # stand-in's row) and this fails at the first step: the delayed sibling takes the released lease,
    # which is the defect #1986 names.
    cluster = _Cluster(backend)
    a = cluster.node("A")
    preferred = cluster.node("P")
    delayed = cluster.node("D", delay=60.0)
    await _lead(a)

    outcome = await a.step_down_leadership(sibling_acquire_delay_seconds=60.0)
    assert outcome == StepdownOutcome(True, outcome.released_at, True)

    for _step in range(10):  # 100 s, past A's 80 s pause and D's 60 s delay
        cluster.advance(_HEARTBEAT)
        await delayed._maintain_leadership()
        await preferred._maintain_leadership()
        await a._maintain_leadership()
        assert delayed.is_leader() is False, "the delayed sibling took a released lease"
        assert preferred.is_leader() is True
        assert a.is_leader() is False, "the drained node took its lease back"
        assert cluster.owner() == "P"


@BACKENDS
async def test_with_only_delayed_siblings_the_drained_node_does_not_reclaim(backend: str) -> None:
    # BACKLOG #1507, reopened by the release fix unless the pause grows. The drained node is the
    # preferred one and every sibling is delayed past its two-heartbeat pause. The drained node must
    # stay out until the delayed sibling has had its chance, and the sibling then takes the lease.
    cluster = _Cluster(backend)
    a = cluster.node("A")
    delayed = cluster.node("D", delay=60.0)
    await _lead(a)

    await a.step_down_leadership(sibling_acquire_delay_seconds=60.0)
    assert a._no_claim_until == stepdown_pause_seconds(_HEARTBEAT, 60.0) == 80.0

    for step in range(1, 11):
        cluster.advance(_HEARTBEAT)
        await a._maintain_leadership()  # A ticks FIRST: past 20 s this is where #1507 fired
        await delayed._maintain_leadership()
        assert a.is_leader() is False, f"the drained node reclaimed its lease at +{step * 10} s"
        # Refused while its delay runs (the lease was released at +0), then it takes the lease.
        assert delayed.is_leader() is (step * _HEARTBEAT > 60.0), f"+{step * 10} s"


@BACKENDS
async def test_without_the_delay_term_the_drained_node_reclaims(backend: str) -> None:
    # NEGATIVE CONTROL for the test above: the same cluster, stepped down with no sibling delay, so the
    # pause is the bare two heartbeats. The drained node's renew arm matches when that ends, before the
    # delayed sibling may claim. If this stops reproducing, the test above no longer measures the pause.
    cluster = _Cluster(backend)
    a = cluster.node("A")
    delayed = cluster.node("D", delay=60.0)
    await _lead(a)

    await a.step_down_leadership(sibling_acquire_delay_seconds=0.0)
    cluster.advance(2 * _HEARTBEAT + 1.0)
    await delayed._maintain_leadership()
    await a._maintain_leadership()
    assert (a.is_leader(), delayed.is_leader()) == (True, False)


@BACKENDS
async def test_the_pause_lifts_once_a_successor_holds_the_row(backend: str) -> None:
    # The pause guards only the drained node's undelayed renew of its own released row. Once the row
    # names a successor that arm cannot match, so a long delay term must not also bar the drained node
    # from taking over a successor that crashes inside the pause.
    #
    # MUTATION ARM, measured: drop the lift (return not-held for the whole pause, as before this
    # change) and this fails at +50: nothing leads until A's 320 s pause ends.
    cluster = _Cluster(backend)
    a = cluster.node("A")
    successor = cluster.node("P")
    dr = cluster.node("DR", delay=300.0)
    await _lead(a)

    await a.step_down_leadership(sibling_acquire_delay_seconds=300.0)
    assert a._no_claim_until == 320.0
    cluster.advance(_HEARTBEAT)
    await successor._maintain_leadership()
    assert successor.is_leader() is True
    await a._maintain_leadership()  # reads the row naming P, so the pause ends; P's lease is live
    assert a.is_leader() is False
    assert a._no_claim_until == 0.0

    # P crashes: it stops renewing, and its lease (taken at +10, TTL 30) has expired by +50.
    cluster.advance(4 * _HEARTBEAT)
    await dr._maintain_leadership()
    assert dr.is_leader() is False  # 300 s delay
    await a._maintain_leadership()
    assert a.is_leader() is True, "the drained node was barred from taking over a crashed successor"


@BACKENDS
async def test_a_missing_lease_row_keeps_the_pause(backend: str) -> None:
    # Only a row naming ANOTHER node lifts the pause. With no row at all the claim would take the
    # INSERT arm, which has no delay term, and the drained node would jump every delayed sibling.
    cluster = _Cluster(backend)
    a = cluster.node("A")
    await _lead(a)
    await a.step_down_leadership(sibling_acquire_delay_seconds=60.0)

    cluster.db.row = None  # e.g. the table was recreated during the pause
    cluster.advance(_HEARTBEAT)
    await a._maintain_leadership()
    assert a.is_leader() is False and cluster.db.row is None
    assert a._no_claim_until == 80.0


@BACKENDS
async def test_a_release_never_moves_an_aged_out_expiry_later(backend: str) -> None:
    # A node whose lease has already aged out (a hung pool, a self-fence) is then stopped. Its forced
    # release must not restart the siblings' delays by stamping a later expiry. The row expired at
    # +30, so a 60 s sibling may take it after +90 whatever the stop wrote at +85.
    #
    # MUTATION ARM, measured: write the DB now without LEAST / CASE (and the stand-in to match) and
    # this fails at +95: the expiry moved to +85 and the sibling must wait until +145.
    cluster = _Cluster(backend)
    a = cluster.node("A")
    delayed = cluster.node("D", delay=60.0)
    await _lead(a)  # expires at +30; A never renews again

    cluster.advance(85.0)
    await a.stop()
    assert cluster.db.row is not None and cluster.db.row["lease_expires_at"] == _EPOCH_NOW + _TTL

    cluster.advance(10.0)
    await delayed._maintain_leadership()
    assert delayed.is_leader() is True


@BACKENDS
async def test_a_delayed_only_cluster_gets_a_leader_after_the_delay(backend: str) -> None:
    # The accepted cost (ADR 0096, 2026-09-30 amendment): a handover to delayed-only siblings is
    # leaderless for about the smallest delay, and then it gets a leader. Both halves are pinned.
    cluster = _Cluster(backend)
    a = cluster.node("A", delay=30.0)
    b = cluster.node("B", delay=30.0)
    await _lead(a)

    await a.step_down_leadership(sibling_acquire_delay_seconds=30.0)
    leaders: list[tuple[bool, bool]] = []
    for _step in range(5):
        cluster.advance(_HEARTBEAT)
        await b._maintain_leadership()
        await a._maintain_leadership()
        leaders.append((a.is_leader(), b.is_leader()))
    assert leaders == [(False, False)] * 3 + [(False, True)] * 2


# --- a clean stop -------------------------------------------------------------------------------


@BACKENDS
async def test_stop_honours_leader_preference(backend: str) -> None:
    # stop() sends the same release. A stopped node has no maintenance task, so it cannot reclaim and
    # needs no pause; what matters is that the siblings meet the lease in preference order.
    cluster = _Cluster(backend)
    a = cluster.node("A")
    preferred = cluster.node("P")
    delayed = cluster.node("D", delay=60.0)
    await _lead(a)

    await a.stop()
    assert cluster.db.row is not None and cluster.db.row["lease_expires_at"] == _EPOCH_NOW

    cluster.advance(_HEARTBEAT)
    await delayed._maintain_leadership()
    assert delayed.is_leader() is False, "the delayed sibling took a lease released by stop()"
    await preferred._maintain_leadership()
    assert preferred.is_leader() is True


@BACKENDS
async def test_stop_with_only_a_delayed_sibling_hands_over_after_the_delay(backend: str) -> None:
    cluster = _Cluster(backend)
    a = cluster.node("A")
    delayed = cluster.node("D", delay=60.0)
    await _lead(a)

    await a.stop()
    cluster.advance(60.0)
    await delayed._maintain_leadership()
    assert delayed.is_leader() is False  # exactly at the delay: the predicate is strict
    cluster.advance(1.0)
    await delayed._maintain_leadership()
    assert delayed.is_leader() is True


# --- the arithmetic and the endpoint ------------------------------------------------------------


def test_the_pause_adds_the_sibling_delay_and_never_shortens() -> None:
    assert stepdown_pause_seconds(10.0) == 20.0
    assert stepdown_pause_seconds(10.0, 45.0) == 65.0
    assert stepdown_pause_seconds(10.0, -5.0) == 20.0
    # A non-finite delay would make the pause endless and the cluster leaderless until a restart.
    assert stepdown_pause_seconds(10.0, math.inf) == 20.0
    assert stepdown_pause_seconds(10.0, math.nan) == 20.0


def _with_delay(member: ClusterMember, delay: float) -> ClusterMember:
    return replace(member, acquire_delay_seconds=delay)


def test_the_longest_delay_counts_only_the_siblings_that_could_take_the_lease() -> None:
    members = [
        _with_delay(_member("node-a", is_leader=True), 500.0),  # this node: never counted
        _with_delay(_member("node-b"), 15.0),
        _with_delay(_member("node-c"), 45.0),
        _with_delay(_member("node-d", promotable=False), 90.0),
        _with_delay(_member("node-e", fresh=False), 120.0),
        _with_delay(_member("node-f", status="left"), 150.0),
        # Can never take over an expired lease, so there is nothing to wait for.
        _with_delay(_member("node-g"), math.inf),
    ]
    assert longest_promotable_sibling_delay(members, "node-a") == 45.0
    assert longest_promotable_sibling_delay(members[:1], "node-a") == 0.0
    # The same set decides the 412: a sibling that can never take over does not count as one.
    only_endless = [members[0], _with_delay(_member("node-g"), math.inf)]
    assert has_promotable_sibling(only_endless, "node-a") is False
    assert has_promotable_sibling(members, "node-a") is True


class _RecordingCoordinator(_StandinCoordinator):
    """Records the sibling delay the endpoint hands the coordinator."""

    def __init__(self, members: list[ClusterMember]) -> None:
        super().__init__(members=members)
        self.sibling_delays: list[float] = []

    async def step_down_leadership(
        self, *, sibling_acquire_delay_seconds: float
    ) -> StepdownOutcome:
        self.sibling_delays.append(sibling_acquire_delay_seconds)
        return await super().step_down_leadership(
            sibling_acquire_delay_seconds=sibling_acquire_delay_seconds
        )


async def test_the_endpoint_passes_the_longest_promotable_sibling_delay(tmp_path: Path) -> None:
    # The coordinator cannot size the pause on its own; the endpoint's membership read is where the
    # sibling delays are. Pinned at the HTTP boundary, so a handler that dropped the argument (and so
    # fell back to the bare two-heartbeat pause) fails here.
    coord = _RecordingCoordinator(
        [
            _member("node-a", is_leader=True),
            _with_delay(_member("node-b"), 15.0),
            _with_delay(_member("node-c"), 45.0),
            _with_delay(_member("node-d", promotable=False), 90.0),
        ]
    )
    async with _admin(tmp_path, coord) as (_engine, c, boss):
        r = await c.post("/cluster/stepdown", headers=_auth(boss))
        assert r.status_code == 200, r.text
    assert coord.sibling_delays == [45.0]


@pytest.mark.parametrize(
    "cls", [ClusterCoordinator, NullCoordinator, DbCoordinator, SqlServerCoordinator]
)
def test_the_sibling_delay_is_a_required_argument(cls: type[Any]) -> None:
    # BACKLOG #2539. With a 0.0 default, a caller that forgot the argument got the bare
    # two-heartbeat pause with nothing failing, and that is the BACKLOG #1507 reclaim the argument
    # exists to stop. Pinned on the Protocol and every coordinator, so a default added back to any
    # one of them fails here.
    param = inspect.signature(cls.step_down_leadership).parameters["sibling_acquire_delay_seconds"]
    assert param.default is inspect.Parameter.empty, cls.__name__
    assert param.kind is inspect.Parameter.KEYWORD_ONLY, cls.__name__


async def test_a_call_without_the_sibling_delay_is_refused() -> None:
    # The behaviour the signature check above stands for, on the one coordinator that needs no DB.
    with pytest.raises(TypeError, match="sibling_acquire_delay_seconds"):
        await NullCoordinator().step_down_leadership()  # type: ignore[call-arg]
