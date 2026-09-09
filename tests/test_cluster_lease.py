# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Self-fencing leadership lease (Workstream A2) — the always-run unit tests (no DB needed).

These prove the active-passive leadership primitive without a real Postgres, against an in-memory
stand-in that emulates ONLY the ``leader_lease`` semantics the :class:`DbCoordinator` uses (the
acquire/renew ``INSERT ... ON CONFLICT`` and the release ``UPDATE``). Two coordinators share one
:class:`_FakeLeaseDB` so they contend on the same single-row lease exactly as they would against a
shared table. Both clocks are injectable:

* the **DB clock** (``clock_timestamp()`` epoch) the lease compares expiry against — advanced to
  simulate time passing on the database, the single clock that decides who may hold the lease; and
* each coordinator's **monotonic clock** the fence watchdog measures elapsed-since-renew against.

The split-brain guarantee — a partitioned old leader self-fences BEFORE a standby can acquire — is
proven directly in :func:`test_fence_fires_before_standby_can_acquire`. The live behaviour against a
real Postgres lands with the failover suite (Increment 3).

The last section covers the SQL Server twin, against its own stand-in over the same shared lease row.
It is here rather than in the gated SQL Server failover suite because the defect it pins is an asyncio
ordering one, not a T-SQL one: the ``MERGE`` carries the identical unfenced ``t.owner = ?`` renew
branch, so the same interleaving re-promotes a drained node there, and a test that only runs when
``MEFOR_TEST_SQLSERVER`` is set would leave the twin unguarded on every ordinary run.
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import Callable

import pytest

from messagefoundry.pipeline.cluster import (
    DbCoordinator,
    StepdownLockTimeout,
    StepdownReleaseUnconfirmed,
    StepdownUnavailable,
)
from messagefoundry.pipeline.cluster_sqlserver import SqlServerCoordinator


class _Clock:
    """A mutable clock: call it for the current value, set ``.t`` to advance. Used for both the shared
    DB clock and each node's monotonic clock so a test drives time deterministically (no real sleeps)."""

    def __init__(self, t: float = 0.0) -> None:
        self.t = t

    def __call__(self) -> float:
        return self.t


class _FakeLeaseDB:
    """The shared single-row ``leader_lease`` table, the DB clock the lease arithmetic uses, and the
    two row mutations both backends' claim/release statements perform.

    The mutations live HERE rather than in each stand-in because the two backends run the same lease
    semantics through different SQL — PG's ``INSERT ... ON CONFLICT``, T-SQL's ``MERGE ... HOLDLOCK`` —
    and a per-stand-in copy is two models of one lease that can drift apart while both keep passing.
    Each stand-in still asserts its OWN statement's shape; only the row arithmetic is shared.
    """

    def __init__(self, db_clock: _Clock) -> None:
        self._db_clock = db_clock
        # {"owner": str, "lease_expires_at": float, "leader_epoch": int}
        self.row: dict[str, object] | None = None

    def claim(self, owner: object, ttl: float, delay: float) -> dict[str, object] | None:
        """Acquire-or-renew, returning the ``(owner, leader_epoch)`` the statement would OUTPUT, or
        ``None`` when another node holds a live lease.

        The H1 epoch: 1 on a fresh insert, +1 on a take-over of an expired/foreign lease, UNCHANGED on
        a renew (``owner == me``). The ADR 0096 ``delay`` handicaps the take-over predicate only — it is
        added to the expiry side, so a renew is never delayed.
        """
        now = self._db_clock()
        row = self.row
        if row is None:
            self.row = {"owner": owner, "lease_expires_at": now + ttl, "leader_epoch": 1}
            return {"owner": owner, "leader_epoch": 1}
        expired = float(row["lease_expires_at"]) + delay < now  # type: ignore[arg-type]
        if row["owner"] == owner or expired:
            if row["owner"] != owner:
                row["leader_epoch"] = int(row["leader_epoch"]) + 1  # type: ignore[arg-type]
            row["owner"] = owner
            row["lease_expires_at"] = now + ttl
            return {"owner": owner, "leader_epoch": row["leader_epoch"]}
        return None  # another node holds a live lease

    def release(self, owner: object) -> None:
        """Expire our own lease row (the release ``UPDATE ... WHERE lease_key AND owner``)."""
        row = self.row
        if row is not None and row["owner"] == owner:
            row["lease_expires_at"] = 0.0


class _FakeLeasePool:
    """One node's view of the pool over a shared :class:`_FakeLeaseDB`. Emulates the two statements the
    coordinator issues for the lease; ``fail=True`` makes every call raise to simulate this node being
    partitioned from (or the DB hung for) THIS node only — the other node's pool keeps working.

    ``yield_in_fetchrow`` / ``yield_in_execute`` make the named statement SUSPEND before it touches the
    row, which a real pool does at every round trip and this stand-in otherwise never does. They are
    opt-in per test because a stand-in that never yields quietly hides every ordering defect in the code
    under test: without one of these set, an ``await`` on these methods returns without ever handing
    control back to the loop, so two coroutines that genuinely interleave in production run to
    completion one after the other here and every concurrency test passes by construction.

    ``on_execute`` is a synchronous probe called at the instant the release statement runs. It exists
    because every other test here reads ``is_leader()`` only after the whole call has returned, which is
    blind to WHEN inside the call the demotion happened.

    ``hang_in_execute`` suspends the release statement on an event the test owns, BEFORE the row is
    touched. ``fail`` cannot stand in for it: a raise is caught by the coordinator's ``except
    Exception`` and a CANCELLATION is not, which is the whole distinction the cancellation tests pin.
    """

    def __init__(self, db: _FakeLeaseDB) -> None:
        self._db = db
        self.fail = False
        self.yield_in_fetchrow = False
        self.yield_in_execute = False
        self.hang_in_execute: asyncio.Event | None = None
        self.on_execute: Callable[[], None] | None = None
        # Records the ARGUMENTS of each release statement, which ``on_execute`` cannot: the
        # release-retry tests ask "was a second UPDATE sent at all", and a row that already reads
        # released cannot distinguish a re-sent write from a write that never happened twice.
        self.on_execute_args: Callable[[tuple[object, ...]], None] | None = None

    async def fetchrow(self, sql: str, *args: object) -> dict[str, object] | None:
        if self.yield_in_fetchrow:
            await asyncio.sleep(0)  # the claim round trip is in flight; let another task run
        if self.fail:
            raise RuntimeError("partitioned from db")
        # Mirrors _claim_or_renew_lease's INSERT ... ON CONFLICT ... WHERE owner OR expired RETURNING.
        # The 4th arg is the ADR-0096 acquire_delay.
        assert "leader_lease" in sql and "INSERT" in sql
        assert "leader_epoch" in sql, "claim SQL must maintain the H1 fencing epoch"
        assert "$4" in sql, "claim SQL must carry the acquire_delay handicap param"
        _lease_key, owner, ttl, delay = args
        return self._db.claim(owner, float(ttl), float(delay))  # type: ignore[arg-type]

    async def execute(self, sql: str, *args: object) -> None:
        if self.yield_in_execute:
            await asyncio.sleep(0)  # the release round trip is in flight; let another task run
        if self.hang_in_execute is not None:
            # Suspended INSIDE the write and before the row moves, which is where a request deadline
            # cancels a real one. Nothing sets this event; the test cancels the awaiting task instead.
            await self.hang_in_execute.wait()
        if self.on_execute is not None:
            self.on_execute()  # a reader observing the coordinator DURING the release window
        if self.on_execute_args is not None:
            self.on_execute_args(args)  # a counter of the statements actually SENT
        if self.fail:
            raise RuntimeError("partitioned from db")
        # Mirrors _release_leadership's UPDATE ... SET lease_expires_at=0 WHERE lease_key AND owner.
        assert "leader_lease" in sql and "UPDATE" in sql
        _lease_key, owner = args
        self._db.release(owner)


async def _cancel_once_suspended(task: asyncio.Task[object]) -> None:
    """Let ``task`` reach its suspended write, then cancel it there and absorb the CancelledError.

    The loop is why this is a helper rather than a bare ``cancel()``: cancelling after a single
    scheduler pass would cancel a coroutine that had not yet reached the pool, which proves nothing
    about a write cancelled mid-flight. The ``done()`` check is the control — without it a test that
    cancelled too early, or too late, would still pass.
    """
    for _ in range(5):
        await asyncio.sleep(0)
    assert not task.done(), "the call never reached the suspended write, so nothing was cancelled"
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task


def _coord(
    pool: _FakeLeasePool,
    mono: _Clock,
    *,
    node: str = "A",
    ttl: float = 30.0,
    fence: float = 20.0,
    heartbeat: float = 10.0,
    acquire_delay_seconds: float = 0.0,
    promotable: bool = True,
) -> DbCoordinator:
    return DbCoordinator(
        pool,
        node,
        heartbeat_seconds=heartbeat,
        leader_lease_ttl_seconds=ttl,
        leader_fence_timeout_seconds=fence,
        acquire_delay_seconds=acquire_delay_seconds,
        promotable=promotable,
        monotonic=mono,
    )


# --- acquire / renew --------------------------------------------------------


async def test_acquire_lease_on_empty_table() -> None:
    db_clock = _Clock(0.0)
    db = _FakeLeaseDB(db_clock)
    a = _coord(_FakeLeasePool(db), _Clock(0.0), node="A")
    await a._maintain_leadership()
    assert a.is_leader() is True
    assert a._last_renew_ok == 0.0
    # now(0) + ttl(30); leader_epoch 1 on the first fresh acquire (H1).
    assert db.row == {"owner": "A", "lease_expires_at": 30.0, "leader_epoch": 1}


async def test_renew_extends_expiry_and_keeps_leadership() -> None:
    db_clock = _Clock(0.0)
    db = _FakeLeaseDB(db_clock)
    mono = _Clock(0.0)
    a = _coord(_FakeLeasePool(db), mono, node="A")
    await a._maintain_leadership()  # acquire at db=0 → expiry 30
    db_clock.t = 10.0
    mono.t = 10.0
    await a._maintain_leadership()  # renew at db=10 → expiry 40
    assert a.is_leader() is True
    assert db.row is not None and db.row["lease_expires_at"] == 40.0
    assert a._last_renew_ok == 10.0  # fence baseline advanced on the successful renew


# --- contention: a standby must wait out the TTL ----------------------------


async def test_standby_cannot_acquire_while_lease_is_live() -> None:
    db_clock = _Clock(0.0)
    db = _FakeLeaseDB(db_clock)
    a = _coord(_FakeLeasePool(db), _Clock(0.0), node="A")
    b = _coord(_FakeLeasePool(db), _Clock(0.0), node="B")
    await a._maintain_leadership()  # A acquires (expiry 30)
    db_clock.t = 10.0
    await b._maintain_leadership()  # B tries at db=10 — lease still live, owned by A
    assert b.is_leader() is False
    assert a.is_leader() is True
    assert db.row is not None and db.row["owner"] == "A"  # untouched


async def test_standby_acquires_after_lease_expires_and_old_leader_demotes() -> None:
    db_clock = _Clock(0.0)
    db = _FakeLeaseDB(db_clock)
    a = _coord(_FakeLeasePool(db), _Clock(0.0), node="A")
    b = _coord(_FakeLeasePool(db), _Clock(0.0), node="B")
    await a._maintain_leadership()  # A acquires (expiry 30)
    db_clock.t = 31.0  # A's lease has expired (A presumed dead/partitioned)
    await b._maintain_leadership()  # B takes over the expired lease
    assert b.is_leader() is True
    assert db.row is not None and db.row["owner"] == "B"
    await a._maintain_leadership()  # A, if it ever runs again, finds B owns a live lease → demotes
    assert a.is_leader() is False


# --- the self-fence watchdog ------------------------------------------------


async def test_self_fence_demotes_when_renew_stalls() -> None:
    # A is leader; its DB renews stop (partition). The watchdog's pure-in-memory check demotes it once
    # the monotonic elapsed-since-renew passes the fence timeout — with NO DB call.
    db = _FakeLeaseDB(_Clock(0.0))
    mono = _Clock(0.0)
    a = _coord(_FakeLeasePool(db), mono, node="A", fence=20.0)
    await a._maintain_leadership()  # leader, _last_renew_ok = 0
    a._pool.fail = True  # type: ignore[attr-defined]  # partition: no more renews land
    mono.t = 20.0
    a._check_fence()
    assert a.is_leader() is True  # exactly at the timeout: not yet (strict >)
    mono.t = 20.1
    a._check_fence()
    assert a.is_leader() is False  # fenced


def test_check_fence_is_noop_when_not_leader() -> None:
    db = _FakeLeaseDB(_Clock(0.0))
    a = _coord(_FakeLeasePool(db), _Clock(1000.0), node="A")
    assert a.is_leader() is False
    a._check_fence()  # never held the lease → nothing to fence
    assert a.is_leader() is False


async def test_maintain_does_not_demote_on_db_error_watchdog_does() -> None:
    # A transient/persistent DB error during renew must NOT itself demote (it propagates to the loop,
    # which logs + retries); only the fence watchdog demotes, and only after the fence timeout. This is
    # what keeps a brief DB blip from causing a needless failover while still fencing a real partition.
    db = _FakeLeaseDB(_Clock(0.0))
    mono = _Clock(0.0)
    a = _coord(_FakeLeasePool(db), mono, node="A", fence=20.0)
    await a._maintain_leadership()  # leader
    a._pool.fail = True  # type: ignore[attr-defined]
    with pytest.raises(RuntimeError, match="partitioned"):
        await a._maintain_leadership()
    assert a.is_leader() is True  # the error alone did not demote
    assert a._last_renew_ok == 0.0  # and did not advance the fence baseline
    mono.t = 21.0
    a._check_fence()
    assert a.is_leader() is False  # the watchdog fences it


async def test_fence_fires_before_standby_can_acquire() -> None:
    # The split-brain guarantee, end to end. ttl=30 > fence=20. Both clocks track real time. A acquires
    # at t=0; A is then partitioned (its renews stop). The old leader must STOP (self-fence) strictly
    # before the standby can acquire — so there is never an instant where both consider themselves
    # leader.
    db_clock = _Clock(0.0)
    db = _FakeLeaseDB(db_clock)
    a_mono = _Clock(0.0)
    a = _coord(_FakeLeasePool(db), a_mono, node="A", ttl=30.0, fence=20.0)
    b = _coord(_FakeLeasePool(db), _Clock(0.0), node="B", ttl=30.0, fence=20.0)

    await a._maintain_leadership()  # A leader (lease expiry 30)
    a._pool.fail = True  # type: ignore[attr-defined]  # A partitioned: no more renews

    # t = 20+: A self-fences. The standby, querying the (still-live until 30) lease, cannot acquire yet.
    a_mono.t = 20.1
    a._check_fence()
    assert a.is_leader() is False  # OLD LEADER HAS STOPPED
    db_clock.t = 20.1
    await b._maintain_leadership()
    assert (
        b.is_leader() is False
    )  # standby still cannot acquire — lease not expired (live until 30)

    # t = 31: only now, well after A stopped, can the standby take over. No overlap ⇒ no split-brain.
    db_clock.t = 31.0
    await b._maintain_leadership()
    assert b.is_leader() is True
    assert a.is_leader() is False


# --- clean release: fast failover on graceful shutdown ----------------------


async def test_clean_release_lets_standby_take_over_immediately() -> None:
    # On a CLEAN stop the leader expires its own lease row, so a standby acquires on its next tick
    # without waiting out the TTL — graceful-shutdown failover is fast (unlike a crash, which waits TTL).
    db_clock = _Clock(0.0)
    db = _FakeLeaseDB(db_clock)
    a = _coord(_FakeLeasePool(db), _Clock(0.0), node="A")
    b = _coord(_FakeLeasePool(db), _Clock(0.0), node="B")
    await a._maintain_leadership()  # A leader (expiry 30)
    await a._release_leadership()  # clean stop → lease expired now
    assert a.is_leader() is False
    db_clock.t = 1.0  # far before the TTL would have expired
    await b._maintain_leadership()
    assert b.is_leader() is True  # standby took over at once


# --- H1: monotonic leader epoch (fencing token) -----------------------------


async def test_epoch_is_one_on_first_acquire() -> None:
    # The very first leader on an empty lease table holds epoch 1 (the DB DEFAULT 0 baseline + 1).
    db = _FakeLeaseDB(_Clock(0.0))
    a = _coord(_FakeLeasePool(db), _Clock(0.0), node="A")
    assert a.current_epoch() is None  # not yet a leader
    await a._maintain_leadership()
    assert a.is_leader() is True
    assert a.current_epoch() == 1
    assert db.row is not None and db.row["leader_epoch"] == 1


async def test_epoch_unchanged_on_renew() -> None:
    # A renew (the same node holding its live lease) must NOT bump the epoch — only a fresh acquire does.
    db_clock = _Clock(0.0)
    db = _FakeLeaseDB(db_clock)
    mono = _Clock(0.0)
    a = _coord(_FakeLeasePool(db), mono, node="A")
    await a._maintain_leadership()  # acquire → epoch 1
    assert a.current_epoch() == 1
    for t in (5.0, 10.0, 15.0):  # several renews, lease stays live (ttl 30)
        db_clock.t = t
        mono.t = t
        await a._maintain_leadership()
        assert a.current_epoch() == 1  # held epoch never moves on a renew
    assert db.row is not None and db.row["leader_epoch"] == 1


async def test_epoch_bumps_on_takeover_and_supersedes_old_leader() -> None:
    # The fencing invariant: when a standby takes over an EXPIRED lease it bumps the epoch, so the new
    # leader holds a STRICTLY GREATER epoch than the superseded old leader ever held. This is exactly the
    # comparison the store guard relies on (held >= leader_lease.leader_epoch): the live leader's held
    # epoch == the row epoch (passes); the old leader's held epoch is now strictly LESS (rejected).
    db_clock = _Clock(0.0)
    db = _FakeLeaseDB(db_clock)
    a = _coord(_FakeLeasePool(db), _Clock(0.0), node="A")
    b = _coord(_FakeLeasePool(db), _Clock(0.0), node="B")
    await a._maintain_leadership()  # A acquires → epoch 1
    assert a.current_epoch() == 1
    db_clock.t = 31.0  # A's lease expires (A presumed paused/partitioned)
    await b._maintain_leadership()  # B takes over the expired lease → epoch 2
    assert b.is_leader() is True
    assert b.current_epoch() == 2  # STRICTLY greater than A's held epoch (1)
    assert db.row is not None and db.row["leader_epoch"] == 2
    # The authoritative row epoch (2) is now greater than A's still-held epoch (1): the store guard
    # `1 >= 2` is False, so a paused A's claim would match 0 rows — the fence. (A also self-fences /
    # demotes on its next maintain tick, clearing its held epoch.)
    assert a.current_epoch() == 1  # A has not run since; it still believes it holds epoch 1
    await a._maintain_leadership()  # A, if it runs again, finds B owns a live lease → demotes
    assert a.is_leader() is False
    assert a.current_epoch() is None  # demotion clears the stale token


async def test_epoch_cleared_on_self_fence() -> None:
    # A self-fenced leader must drop its held epoch so current_epoch() never reports a stale token.
    db = _FakeLeaseDB(_Clock(0.0))
    mono = _Clock(0.0)
    a = _coord(_FakeLeasePool(db), mono, node="A", fence=20.0)
    await a._maintain_leadership()  # leader, epoch 1
    assert a.current_epoch() == 1
    a._pool.fail = True  # type: ignore[attr-defined]  # partition: renews stop
    mono.t = 20.1
    a._check_fence()
    assert a.is_leader() is False
    assert a.current_epoch() is None  # fenced → no token


async def test_epoch_cleared_on_clean_release() -> None:
    db = _FakeLeaseDB(_Clock(0.0))
    a = _coord(_FakeLeasePool(db), _Clock(0.0), node="A")
    await a._maintain_leadership()
    assert a.current_epoch() == 1
    await a._release_leadership()
    assert a.current_epoch() is None


# --- ADR 0096: leader preference (acquire_delay_seconds) ---------------------


async def test_default_delay_zero_is_byte_identical_takeover() -> None:
    # delay=0.0 (the default) must behave exactly like the pre-knob `expires_at < now` take-over: a
    # standby claims the instant the lease has expired.
    db_clock = _Clock(0.0)
    db = _FakeLeaseDB(db_clock)
    a = _coord(_FakeLeasePool(db), _Clock(0.0), node="A")
    b = _coord(_FakeLeasePool(db), _Clock(0.0), node="B", acquire_delay_seconds=0.0)
    await a._maintain_leadership()  # A leader, expiry 30
    db_clock.t = 30.1  # just past expiry
    await b._maintain_leadership()
    assert b.is_leader() is True  # no handicap → claims at once


async def test_delayed_node_cannot_claim_within_the_delay_window() -> None:
    # A node with acquire_delay=5 must NOT take over an expired lease until now > expiry + 5.
    db_clock = _Clock(0.0)
    db = _FakeLeaseDB(db_clock)
    a = _coord(_FakeLeasePool(db), _Clock(0.0), node="A")
    b = _coord(_FakeLeasePool(db), _Clock(0.0), node="B", acquire_delay_seconds=5.0)
    await a._maintain_leadership()  # A leader, expiry 30
    db_clock.t = 31.0  # lease expired 1s ago — but < delay of 5s past expiry
    await b._maintain_leadership()
    assert b.is_leader() is False  # still handicapped out
    db_clock.t = 35.1  # now > expiry(30) + delay(5)
    await b._maintain_leadership()
    assert b.is_leader() is True  # handicap elapsed → B takes over


async def test_preferred_node_wins_routine_expired_lease_race() -> None:
    # The core scenario: a preferred node (delay=0) and a delayed DR node (delay=5) both eligible after
    # the leader's lease expires. The preferred node may claim the instant the lease expires, so it wins
    # the routine transition and the delayed node — finding a fresh lease on its next tick — never takes
    # over.
    db_clock = _Clock(0.0)
    db = _FakeLeaseDB(db_clock)
    leader = _coord(_FakeLeasePool(db), _Clock(0.0), node="L")
    preferred = _coord(_FakeLeasePool(db), _Clock(0.0), node="P", acquire_delay_seconds=0.0)
    dr = _coord(_FakeLeasePool(db), _Clock(0.0), node="DR", acquire_delay_seconds=5.0)
    await leader._maintain_leadership()  # L leader, expiry 30
    db_clock.t = 30.5  # lease expired; preferred is eligible, DR is still handicapped (needs > 35)
    await preferred._maintain_leadership()  # P wins the race
    assert preferred.is_leader() is True
    db_clock.t = 40.0  # even well past DR's handicap window, the lease is now fresh (owned by P)
    await dr._maintain_leadership()
    assert dr.is_leader() is False  # DR never wins — P holds a live lease
    assert db.row is not None and db.row["owner"] == "P"


async def test_delay_does_not_delay_the_current_leaders_renew() -> None:
    # A delay must NEVER handicap a RENEWAL by the current leader — even a delayed leader renews at `now`.
    db_clock = _Clock(0.0)
    db = _FakeLeaseDB(db_clock)
    mono = _Clock(0.0)
    a = _coord(_FakeLeasePool(db), mono, node="A", acquire_delay_seconds=5.0)
    await a._maintain_leadership()  # A acquires on the empty table (delay irrelevant to INSERT)
    assert a.is_leader() is True
    for t in (10.0, 20.0):  # renews while the lease is still live — no delay term on owner=me
        db_clock.t = t
        mono.t = t
        await a._maintain_leadership()
        assert a.is_leader() is True
        assert db.row is not None and db.row["lease_expires_at"] == t + 30.0


# --- ADR 0096: non-promotable standby (promotable=false) ---------------------


async def test_non_promotable_never_acquires_empty_lease() -> None:
    # A non-promotable node must not even INSERT a fresh lease on an empty table.
    db = _FakeLeaseDB(_Clock(0.0))
    n = _coord(_FakeLeasePool(db), _Clock(0.0), node="N", promotable=False)
    await n._maintain_leadership()
    assert n.is_leader() is False
    assert db.row is None  # touched no DB row


async def test_non_promotable_never_takes_over_expired_lease() -> None:
    # Even with the lease long expired, a non-promotable node must never take over — a promotable node
    # would. This is the warm-DR guarantee: the DR node stays passive.
    db_clock = _Clock(0.0)
    db = _FakeLeaseDB(db_clock)
    a = _coord(_FakeLeasePool(db), _Clock(0.0), node="A")
    dr = _coord(_FakeLeasePool(db), _Clock(0.0), node="DR", promotable=False)
    await a._maintain_leadership()  # A leader, expiry 30
    db_clock.t = 1000.0  # lease long expired (A dead)
    await dr._maintain_leadership()
    assert dr.is_leader() is False  # never promotes
    assert db.row is not None and db.row["owner"] == "A"  # untouched — DR wrote nothing


async def test_non_promotable_already_leader_steps_down() -> None:
    # If a non-promotable node somehow already holds leadership (e.g. a config flip), its next maintenance
    # tick must demote it cleanly — it stops renewing and returns not-held.
    db = _FakeLeaseDB(_Clock(0.0))
    n = _coord(_FakeLeasePool(db), _Clock(0.0), node="N", promotable=False)
    # Simulate "somehow already leader": force the cached gate + fence baseline as if it had acquired.
    n._is_leader = True
    n._last_renew_ok = 0.0
    n._leader_epoch = 1
    await n._maintain_leadership()  # non-promotable → claim returns not-held → demote
    assert n.is_leader() is False
    assert n.current_epoch() is None  # demotion clears the held token


async def test_promotable_standby_takes_over_from_non_promotable_gap() -> None:
    # A cluster with one non-promotable DR node + one promotable node: the promotable node is the only one
    # that ever leads. (An ALL-non-promotable cluster would elect no leader — the documented caveat.)
    db_clock = _Clock(0.0)
    db = _FakeLeaseDB(db_clock)
    dr = _coord(_FakeLeasePool(db), _Clock(0.0), node="DR", promotable=False)
    ha = _coord(_FakeLeasePool(db), _Clock(0.0), node="HA", promotable=True)
    await dr._maintain_leadership()  # DR never acquires
    assert dr.is_leader() is False and db.row is None
    await ha._maintain_leadership()  # HA acquires the empty lease
    assert ha.is_leader() is True
    assert db.row is not None and db.row["owner"] == "HA"


# --- ADR 0056 slice 1: planned failover (step_down_leadership) ---------------


async def test_step_down_returns_the_release_and_expires_the_lease() -> None:
    # The public seam reports what it actually did — (was_leader, released_at) — and expires the lease
    # row exactly as the clean-stop release does. released_at is wall-clock (the audit trail's units),
    # not the injected monotonic clock, so it is only bracketed here.
    db_clock = _Clock(0.0)
    db = _FakeLeaseDB(db_clock)
    a = _coord(_FakeLeasePool(db), _Clock(0.0), node="A")
    await a._maintain_leadership()
    assert a.is_leader() is True

    before = time.time()
    was_leader, released_at = await a.step_down_leadership()
    after = time.time()

    assert was_leader is True
    assert released_at is not None and before <= released_at <= after
    assert a.is_leader() is False
    assert a.current_epoch() is None  # released: no longer a fenced leader (H1)
    assert db.row is not None and db.row["lease_expires_at"] == 0.0


async def test_step_down_on_a_non_leader_releases_nothing() -> None:
    # The endpoint's 409 rests on this: a node that never held the lease reports (False, None) and
    # leaves a live sibling's lease untouched. This is what makes the pre-read unnecessary.
    db_clock = _Clock(0.0)
    db = _FakeLeaseDB(db_clock)
    a = _coord(_FakeLeasePool(db), _Clock(0.0), node="A")
    b = _coord(_FakeLeasePool(db), _Clock(0.0), node="B")
    await a._maintain_leadership()  # A leads

    assert await b.step_down_leadership() == (False, None)
    assert a.is_leader() is True
    assert db.row is not None and db.row["owner"] == "A"
    assert db.row["lease_expires_at"] == 30.0  # untouched


async def test_step_down_pauses_this_node_so_a_standby_wins_the_expired_lease() -> None:
    # THE REGRESSION THIS PAUSE EXISTS FOR. _release_leadership expires lease_expires_at but leaves
    # `owner` naming us, and the claim statement's renew branch (owner = me) carries NO expiry test —
    # so without the pause the drained node's very next maintenance tick renews and takes leadership
    # straight back, whichever node happens to tick first. The negative control below proves the fake
    # pool really would hand it back, so this is not a vacuous pass.
    db_clock = _Clock(0.0)
    db = _FakeLeaseDB(db_clock)
    mono_a = _Clock(0.0)
    a = _coord(_FakeLeasePool(db), mono_a, node="A", heartbeat=10.0)
    b = _coord(_FakeLeasePool(db), _Clock(0.0), node="B", heartbeat=10.0)
    await a._maintain_leadership()

    await a.step_down_leadership()
    assert a._no_claim_until == 20.0  # two heartbeats on the injected monotonic clock

    # A's own next tick, inside the window: it declines rather than renewing itself back in.
    db_clock.t = mono_a.t = 10.0
    await a._maintain_leadership()
    assert a.is_leader() is False
    assert db.row is not None and db.row["owner"] == "A"  # row untouched, still expired
    assert db.row["lease_expires_at"] == 0.0

    # The standby's tick inside the same window wins the expired lease and bumps the epoch (H1).
    await b._maintain_leadership()
    assert b.is_leader() is True
    assert db.row["owner"] == "B" and db.row["leader_epoch"] == 2

    # And the pause is bounded: past it, A contends normally again (it just cannot beat a live lease).
    mono_a.t = 21.0
    await a._maintain_leadership()
    assert a.is_leader() is False  # B's lease is live, so the ordinary predicate refuses A


async def test_without_the_pause_the_drained_node_renews_itself_back_in() -> None:
    # NEGATIVE CONTROL for the test above: clear the pause and the same sequence hands leadership
    # straight back to the node that was just drained. If this ever stops reproducing, the pause is no
    # longer measuring what it claims to.
    db_clock = _Clock(0.0)
    db = _FakeLeaseDB(db_clock)
    mono_a = _Clock(0.0)
    a = _coord(_FakeLeasePool(db), mono_a, node="A", heartbeat=10.0)
    await a._maintain_leadership()
    await a.step_down_leadership()

    a._no_claim_until = 0.0  # the pause removed
    db_clock.t = mono_a.t = 10.0
    await a._maintain_leadership()
    assert a.is_leader() is True  # re-armed itself; the planned failover did nothing


async def test_step_down_fires_the_demotion_edge_and_leaves_the_node_running() -> None:
    # A stepdown is a demotion the node SURVIVES, so the engine must learn about it on the same edge
    # every other True->False transition uses (ADR 0157 Inc 5) rather than waiting out a reconcile
    # poll. And the coordinator's background tasks are untouched — this is not a stop().
    db = _FakeLeaseDB(_Clock(0.0))
    a = _coord(_FakeLeasePool(db), _Clock(0.0), node="A")
    fired: list[int] = []
    a.set_on_demote(lambda: fired.append(1))
    await a._maintain_leadership()

    await a.step_down_leadership()
    assert fired == [1]
    assert a._stop.is_set() is False  # still running; the maintenance loop keeps heartbeating

    # A second stepdown on the now-demoted node releases nothing and fires nothing more.
    assert await a.step_down_leadership() == (False, None)
    assert fired == [1]


async def test_a_tick_inside_the_release_window_cannot_re_promote_the_drained_node() -> None:
    # THE TWO-LEADER WINDOW. A stepdown runs from an API handler with the maintenance loop LIVE, and
    # _release_leadership() SUSPENDS at its UPDATE. A tick that starts in that window matches the claim
    # statement's unfenced `owner = me` renew branch, takes the lease back, and flips _is_leader on
    # again — after which the release's own UPDATE expires the row it just renewed. The node then
    # reports leader while a sibling can take the expired lease, so BOTH consider themselves leader,
    # and the endpoint answered 200.
    #
    # THIS TEST DOES NOT ISOLATE THE LOCK, and an earlier comment here claiming "the lock is what
    # closes it" read a conjunction as one term. Measured by reverting one mechanism at a time:
    # removing the claim pause kills this test, removing the mutual exclusion does NOT. The pause is
    # armed before the release, and it is the first thing the tick checks, so a tick that STARTS in the
    # release window is turned away by the pause and never reaches the lock at all.
    # The test below is the one that isolates the lock: it puts the claim in flight BEFORE the pause is
    # armed, so the pause cannot close it and only mutual exclusion can.
    db_clock = _Clock(0.0)
    db = _FakeLeaseDB(db_clock)
    mono_a = _Clock(0.0)
    pool_a = _FakeLeasePool(db)
    a = _coord(pool_a, mono_a, node="A", heartbeat=10.0)
    b = _coord(_FakeLeasePool(db), _Clock(0.0), node="B", heartbeat=10.0)
    await a._maintain_leadership()
    assert a.is_leader() is True

    pool_a.yield_in_execute = True  # the release suspends mid-UPDATE, as a real pool does
    await asyncio.gather(a.step_down_leadership(), a._maintain_leadership())

    assert a.is_leader() is False, "a tick in the release window re-promoted the drained node"
    assert db.row is not None and db.row["lease_expires_at"] == 0.0  # the release still won the row

    # And the drain actually transfers: the standby takes the expired lease and is the ONLY leader.
    db_clock.t = 1.0
    await b._maintain_leadership()
    assert b.is_leader() is True
    assert a.is_leader() is False, "two leaders at once"


async def test_a_claim_already_in_flight_cannot_re_promote_after_the_release() -> None:
    # The OTHER interleaving, and the one that decides the fix. Here the maintenance tick is already
    # suspended inside its claim round trip when the stepdown begins, so it has ALREADY passed the
    # _no_claim_until check. The pause IS now armed before the release, and it still changes nothing
    # here: the claim returns "held" afterwards and _maintain_leadership promotes on that stale result,
    # leaving the node leader with a LIVE lease no sibling can take for a full TTL. Only mutual
    # exclusion orders these two, and removing it is measured to kill this test and no other.
    db_clock = _Clock(0.0)
    db = _FakeLeaseDB(db_clock)
    mono_a = _Clock(0.0)
    pool_a = _FakeLeasePool(db)
    a = _coord(pool_a, mono_a, node="A", heartbeat=10.0)
    b = _coord(_FakeLeasePool(db), _Clock(0.0), node="B", heartbeat=10.0)
    await a._maintain_leadership()
    assert a.is_leader() is True

    pool_a.yield_in_fetchrow = True  # the claim is in flight when the stepdown arrives
    await asyncio.gather(a._maintain_leadership(), a.step_down_leadership())

    assert a.is_leader() is False, "an in-flight claim re-promoted the drained node"
    assert db.row is not None and db.row["lease_expires_at"] == 0.0, (
        "the release must win the row; a renew landing after it leaves the lease live for a full TTL"
    )

    db_clock.t = 1.0
    await b._maintain_leadership()
    assert b.is_leader() is True
    assert a.is_leader() is False, "two leaders at once"


async def test_a_failed_release_write_reports_failure_instead_of_a_drain() -> None:
    # REPLACES test_step_down_survives_a_failed_release_write, which asserted the DEFECT as correct.
    # That test read the release write as "best-effort — the lease ages out on its own", which is true
    # of stop() (the node is leaving) and false of a stepdown (the node stays up). With the pool
    # partitioned the UPDATE never lands, so the lease row stays LIVE and still owned by this node: no
    # sibling can take it, and when the pause ends this node renews itself back in through the unfenced
    # `owner = me` branch. The old test asserted (True, released_at), which the endpoint turned into a
    # 200 reading "drained" — telling an operator to start maintenance on the node that is still leader.
    #
    # Arithmetic on the shipped defaults, which is why the pause does not save it: heartbeat 10, fence
    # 20, ttl 30, so the pause ends at 20 while the lease lives to 30. The settings validator pins
    # heartbeat < fence < ttl and never compares the pause to the ttl.
    db = _FakeLeaseDB(_Clock(0.0))
    pool = _FakeLeasePool(db)
    mono = _Clock(0.0)
    a = _coord(pool, mono, node="A", heartbeat=10.0)
    await a._maintain_leadership()

    pool.fail = True
    with pytest.raises(StepdownReleaseUnconfirmed):
        await a.step_down_leadership()

    # The conservative half still holds: this node stops CALLING itself leader either way, and the
    # pause is armed, because a lost response to a committed UPDATE is indistinguishable from an
    # UPDATE that never ran and the possibly-released reading is the safe one.
    assert a.is_leader() is False
    assert a._no_claim_until == 20.0
    # ...and the fact the caller must be told: the lease row was NOT expired.
    assert db.row is not None and db.row["lease_expires_at"] == 30.0

    # The consequence a 200 would have hidden. The lease outlives the pause, so past it this node takes
    # its own leadership back and the "drained" node is the leader again.
    pool.fail = False
    mono.t = 21.0
    await a._maintain_leadership()
    assert a.is_leader() is True


async def test_a_retry_re_sends_the_write_the_first_stepdown_could_not_confirm() -> None:
    # THE REFUSAL THE PREVIOUS TEST PINS IS ONLY HALF AN ANSWER: it tells the operator to retry, and
    # the retry has to work. _release_leadership demotes the in-memory gate BEFORE the write, so on the
    # second call `was_leader` reads False and its not-a-leader early return fired — the UPDATE was
    # never re-sent, the caller got (False, None), and the endpoint turned that into a 409 "this node
    # is not the current leader" over a lease row still live and still owned by that very node. The
    # 409's own documented remedy (resolve the leader from GET /cluster/nodes) then pointed straight
    # back here, because this node IS what that API still names as lease owner.
    db_clock = _Clock(0.0)
    db = _FakeLeaseDB(db_clock)
    pool = _FakeLeasePool(db)
    mono = _Clock(0.0)
    a = _coord(pool, mono, node="A", heartbeat=10.0)
    await a._maintain_leadership()

    pool.fail = True
    with pytest.raises(StepdownReleaseUnconfirmed):
        await a.step_down_leadership()
    assert db.row is not None and db.row["lease_expires_at"] == 30.0  # live, and ours

    # THE MEASUREMENT. Count the release statements the pool sees, so "the retry re-sent it" is read
    # off the wire rather than inferred from the row. Reverting force_write leaves this at 1 and the
    # row at 30.0 — the vacuity control for this test.
    releases: list[tuple[object, ...]] = []
    pool.fail = False
    pool.on_execute_args = releases.append
    assert await a.step_down_leadership() == (False, None)
    assert len(releases) == 1, "the retry did not re-send the release write"
    assert db.row["lease_expires_at"] == 0.0, "the retry did not expire the lease it still owned"

    # And the pause is re-armed on the retry, for the same reason it is armed on the first call: the
    # release expires the lease but leaves `owner` naming us, so the unfenced `owner = me` renew branch
    # would otherwise hand leadership straight back on this node's very next tick.
    assert a._no_claim_until == 20.0
    await a._maintain_leadership()
    assert a.is_leader() is False

    # A sibling can now take it, which is the whole point of retrying.
    db_clock.t = 1.0  # the expired lease is only takeable once the DB clock is past it
    b = _coord(_FakeLeasePool(db), _Clock(0.0), node="B")
    await b._maintain_leadership()
    assert b.is_leader() is True


async def test_a_retry_that_fails_again_refuses_rather_than_answering_not_the_leader() -> None:
    # The same early return also SWALLOWED a second failure. With the write forced but still failing,
    # the retry must raise again — not return (False, None), which the endpoint renders as a 409
    # meaning "you addressed the wrong node" for a node that may still hold a live lease.
    db = _FakeLeaseDB(_Clock(0.0))
    pool = _FakeLeasePool(db)
    a = _coord(pool, _Clock(0.0), node="A", heartbeat=10.0)
    await a._maintain_leadership()

    pool.fail = True
    with pytest.raises(StepdownReleaseUnconfirmed):
        await a.step_down_leadership()
    with pytest.raises(StepdownReleaseUnconfirmed):
        await a.step_down_leadership()
    assert db.row is not None and db.row["lease_expires_at"] == 30.0


async def test_a_cancelled_release_still_owes_the_write_so_the_retry_re_sends_it() -> None:
    # THE HOLE THE TWO TESTS ABOVE DID NOT COVER. They partition the pool, so the write RAISES and the
    # coordinator's `except Exception` arm records the owed write. A CANCELLATION takes neither arm:
    # asyncio.CancelledError derives from BaseException, so `except Exception` never sees it and the
    # method unwound with _is_leader already cleared and _lease_release_owed still False. The next
    # stepdown then read owed=False, took the not-a-leader early return, sent NO write, and answered
    # 409 "not the current leader" over a lease row still live and still ours — the exact defect the
    # retry mechanism exists to prevent, reached by a different door and with no audit row either way.
    #
    # Not hypothetical in the shipped configuration: RequestTimeoutMiddleware is registered
    # unconditionally and its asyncio.timeout cancels the handler at DEFAULT_REQUEST_TIMEOUT_SECONDS
    # (120.0), over a pool acquire the stepdown docstring documents as unbounded.
    #
    # VACUITY CONTROL, both legs MEASURED rather than reasoned: move the `self._lease_release_owed =
    # True` in _release_leadership back into its `except Exception` arm and this test fails at the
    # owed assertion (`False is True`); silence that one line as well and it fails at the release
    # count instead (`0 == 1`), which is the leg that proves the retry really did send nothing.
    db_clock = _Clock(0.0)
    db = _FakeLeaseDB(db_clock)
    pool = _FakeLeasePool(db)
    mono = _Clock(0.0)
    a = _coord(pool, mono, node="A", heartbeat=10.0)
    await a._maintain_leadership()
    assert a.is_leader() is True

    pool.hang_in_execute = (
        asyncio.Event()
    )  # never set: the write suspends until the task is cancelled
    await _cancel_once_suspended(asyncio.create_task(a.step_down_leadership()))

    # The in-memory demotion happened (it precedes the write) and the row never moved, which is exactly
    # the state the owed flag exists to record.
    assert a.is_leader() is False
    assert db.row is not None and db.row["lease_expires_at"] == 30.0, "the cancelled write landed"
    assert a._lease_release_owed is True, "a cancelled write left nothing owed"

    # THE MEASUREMENT: the retry re-sends the write, counted off the wire rather than inferred.
    releases: list[tuple[object, ...]] = []
    pool.hang_in_execute = None
    pool.on_execute_args = releases.append
    assert await a.step_down_leadership() == (False, None)
    assert len(releases) == 1, "the retry after a cancelled release sent no write"
    assert db.row["lease_expires_at"] == 0.0, "the retry did not expire the lease it still owned"
    assert a._lease_release_owed is False, "a write that returned must clear the owed flag"

    # And the pause is armed on that retry too, so the released lease is not re-taken by this node on
    # its next tick — the same reason the raise-path retry arms it.
    assert a._no_claim_until == 20.0
    db_clock.t = 1.0
    b = _coord(_FakeLeasePool(db), _Clock(0.0), node="B")
    await b._maintain_leadership()
    assert b.is_leader() is True


async def test_a_stepdown_on_a_node_that_never_led_sends_nothing_and_arms_no_pause() -> None:
    # The counterweight to the two tests above: forcing the write is scoped to a release this node
    # OWES, never to every stepdown. A caller who addresses a standby by mistake must not cost that
    # standby a DB round trip or two heartbeats of declining to claim — that would delay the very
    # failover they are trying to perform.
    db = _FakeLeaseDB(_Clock(0.0))
    a = _coord(_FakeLeasePool(db), _Clock(0.0), node="A", heartbeat=10.0)
    b_pool = _FakeLeasePool(db)
    b = _coord(b_pool, _Clock(0.0), node="B", heartbeat=10.0)
    await a._maintain_leadership()  # A leads; B never has

    releases: list[tuple[object, ...]] = []
    b_pool.on_execute_args = releases.append
    assert await b.step_down_leadership() == (False, None)
    assert releases == [], "a stepdown on a node that owes no release still wrote to the lease row"
    assert b._no_claim_until == 0.0, "an innocent standby was handicapped by someone else's mistake"
    assert a.is_leader() is True


async def test_the_release_demotes_before_it_writes() -> None:
    # ORDERING GUARD. _release_leadership's first line is the SYNCHRONOUS `self._is_leader = False`,
    # ahead of the awaited lease write, so no reader can see a stale True while the release is in
    # flight — is_leader() gates listener binding and the whole graph. Moving that assignment after the
    # await passes every other test in this file and on both backends, because they all read
    # is_leader() only once the call has returned; only a probe INSIDE the release window sees it.
    db = _FakeLeaseDB(_Clock(0.0))
    pool = _FakeLeasePool(db)
    a = _coord(pool, _Clock(0.0), node="A")
    await a._maintain_leadership()
    assert a.is_leader() is True

    seen: list[bool] = []
    pool.on_execute = lambda: seen.append(a.is_leader())
    await a.step_down_leadership()
    assert seen == [False], "a reader inside the release window saw the node still reporting leader"


async def test_a_cancelled_stepdown_still_arms_the_claim_pause() -> None:
    # The pause is armed BEFORE the release's await, not after it. Cancel the request task while the
    # release is suspended in the pool write and `async with` unwinds correctly — but an assignment
    # placed after that await never runs, leaving _no_claim_until at 0.0 on a node whose lease row may
    # already be expired. The endpoint's handler is a bare await with no shield and no timeout, so any
    # client disconnect or server shutdown lands exactly there.
    db = _FakeLeaseDB(_Clock(0.0))
    pool = _FakeLeasePool(db)
    a = _coord(pool, _Clock(0.0), node="A", heartbeat=10.0)
    await a._maintain_leadership()

    pool.yield_in_execute = True  # suspend inside the release, then cancel there
    task = asyncio.ensure_future(a.step_down_leadership())
    await asyncio.sleep(0)  # let the task reach the suspension point
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task

    assert a._no_claim_until == 20.0, "a cancelled stepdown skipped the pause"
    assert a.is_leader() is False
    # And the pause does its job: this node's own next tick declines rather than renewing itself in.
    await a._maintain_leadership()
    assert a.is_leader() is False


async def test_the_lock_wait_is_bounded_and_refuses_rather_than_demoting() -> None:
    # The lock puts the in-memory demote behind a DB round trip: a maintenance tick suspended in
    # fetchrow holds it, and step_down_leadership blocks BEFORE _release_leadership's first line. That
    # wait was unbounded — [store].command_timeout is the only ceiling and PostgresStore passes
    # `command_timeout or None`, so the documented zero-disables value removes even that, while the raw
    # pool acquire() carries no timeout at all. It is bounded here at the fence timeout, and a timeout
    # REFUSES: it must not demote a node whose release it never ran.
    db = _FakeLeaseDB(_Clock(0.0))
    pool = _FakeLeasePool(db)
    a = _coord(pool, _Clock(0.0), node="A", fence=0.05)
    await a._maintain_leadership()

    await a._leadership_lock.acquire()  # stand in for a tick suspended mid-round-trip
    try:
        with pytest.raises(StepdownLockTimeout) as caught:
            await a.step_down_leadership()
    finally:
        a._leadership_lock.release()

    assert a.is_leader() is True, "a refused stepdown must leave leadership exactly as it found it"
    assert a._no_claim_until == 0.0
    assert db.row is not None and db.row["lease_expires_at"] == 30.0
    # ITS OWN TYPE, not the write-failure one. Both used to be StepdownUnavailable, so the endpoint's
    # single `except` arm gave both the same body ("could not release leadership; it is still the
    # leader") and the same audit reason — a sentence that is false here twice over: nothing was
    # released, and this branch runs before any leader check, so it fires on a node that leads nothing.
    assert not isinstance(caught.value, StepdownReleaseUnconfirmed)
    assert isinstance(caught.value, StepdownUnavailable)  # still one family for a catch-all caller
    text = str(caught.value)
    assert "maintenance tick" not in text, (
        "the message names a maintenance tick as the holder; both coordinators take this lock in "
        "_maintain_leadership AND in step_down_leadership, so the holder is not knowable from here"
    )
    assert "leadership lock" in text and "still the leader" not in text


async def test_a_stepdown_refused_by_the_lock_can_come_from_a_node_that_leads_nothing() -> None:
    # WHY THE LOCK-TIMEOUT WORDING MAY NOT ASSERT LEADERSHIP. The endpoint deliberately takes no
    # is_leader() pre-read, so this refusal reaches a caller who addressed a standby whose lock happens
    # to be busy. Nothing in that path ever read who the leader is.
    db = _FakeLeaseDB(_Clock(0.0))
    a = _coord(_FakeLeasePool(db), _Clock(0.0), node="A")
    await a._maintain_leadership()
    b = _coord(_FakeLeasePool(db), _Clock(0.0), node="B", fence=0.05)
    assert b.is_leader() is False

    await b._leadership_lock.acquire()
    try:
        with pytest.raises(StepdownLockTimeout) as caught:
            await b.step_down_leadership()
    finally:
        b._leadership_lock.release()

    assert "still the leader" not in str(caught.value)
    assert a.is_leader() is True and b.is_leader() is False


# --- ADR 0056 slice 1: the SQL Server twin ----------------------------------


class _FakeSqlLeaseStore:
    """The SQL Server sibling of :class:`_FakeLeasePool` over the SAME :class:`_FakeLeaseDB`.

    Emulates only the two statements ``SqlServerCoordinator`` issues for the lease: the
    ``MERGE ... WHEN MATCHED AND (t.owner = ? OR t.lease_expires_at + ? < @now)`` acquire/renew
    (``_fetchone``) and the release ``UPDATE`` (``_execute``), with the same opt-in suspension and
    release-window probe the Postgres stand-in carries and for the same reasons — a stand-in that never
    yields cannot exhibit an ordering defect, and a test that reads state only after the call cannot see
    where inside it the demotion landed.

    **``_execute`` carries the same hooks as its Postgres sibling on purpose.** Without them the
    release-window interleaving simply cannot be EXPRESSED against this backend, so a claim that both
    interleavings are pinned on both coordinators would have been half true with nothing failing.
    """

    _settings = None

    def __init__(self, db: _FakeLeaseDB) -> None:
        self._db = db
        self.fail = False
        self.yield_in_fetchone = False
        self.yield_in_execute = False
        self.on_execute: Callable[[], None] | None = None
        # Read _FakeLeasePool.hang_in_execute: a raise and a cancellation take different arms.
        self.hang_in_execute: asyncio.Event | None = None

    async def _fetchone(self, sql: str, params: tuple[object, ...]) -> dict[str, object] | None:
        if self.yield_in_fetchone:
            await asyncio.sleep(0)  # the MERGE round trip is in flight; let another task run
        if self.fail:
            raise RuntimeError("partitioned from db")
        assert "MERGE leader_lease" in sql, "not the claim statement"
        assert "leader_epoch" in sql, "claim SQL must maintain the H1 fencing epoch"
        # Positional params of the MERGE: (lease_key, owner, delay, owner, ttl, owner, ...).
        owner, delay, ttl = params[1], params[2], params[4]
        return self._db.claim(owner, float(ttl), float(delay))  # type: ignore[arg-type]

    async def _execute(self, sql: str, params: tuple[object, ...]) -> None:
        if self.yield_in_execute:
            await asyncio.sleep(0)  # the release round trip is in flight; let another task run
        if self.hang_in_execute is not None:
            await self.hang_in_execute.wait()  # suspended inside the write, before the row moves
        if self.on_execute is not None:
            self.on_execute()  # a reader observing the coordinator DURING the release window
        if self.fail:
            raise RuntimeError("partitioned from db")
        assert "leader_lease" in sql and "UPDATE" in sql, "not the release statement"
        _lease_key, owner = params
        self._db.release(owner)


def _sql_coord(
    store: _FakeSqlLeaseStore, node: str, mono: _Clock | None = None
) -> SqlServerCoordinator:
    # Same timings as _coord above, so the two backends' tests are comparable at a glance. `mono` is
    # passed in when a test needs to move this node's monotonic clock past its own stepdown pause.
    return SqlServerCoordinator(
        store,  # type: ignore[arg-type]
        node,
        heartbeat_seconds=10.0,
        leader_lease_ttl_seconds=30.0,
        leader_fence_timeout_seconds=20.0,
        monotonic=mono or _Clock(0.0),
    )


async def test_sqlserver_step_down_is_serialized_against_an_in_flight_claim() -> None:
    # The twin carries the identical unfenced `t.owner = ?` renew branch, so the same interleaving
    # re-promotes the drained node — and the consequence is worse here than on Postgres: only the three
    # FIFO claim paths are epoch-fenced on SQL Server, so claim_ready and every terminal resolve would
    # still accept writes from the ex-leader this endpoint just drained.
    db_clock = _Clock(0.0)
    db = _FakeLeaseDB(db_clock)
    store = _FakeSqlLeaseStore(db)
    a = _sql_coord(store, "A")
    b = _sql_coord(_FakeSqlLeaseStore(db), "B")
    await a._maintain_leadership()
    assert a.is_leader() is True

    store.yield_in_fetchone = True  # the claim is in flight when the stepdown arrives
    await asyncio.gather(a._maintain_leadership(), a.step_down_leadership())

    assert a.is_leader() is False, "an in-flight claim re-promoted the drained node"
    assert db.row is not None and db.row["lease_expires_at"] == 0.0

    db_clock.t = 1.0
    await b._maintain_leadership()
    assert b.is_leader() is True
    assert a.is_leader() is False, "two leaders at once"


async def test_sqlserver_a_tick_inside_the_release_window_cannot_re_promote() -> None:
    # The OTHER interleaving on the twin, which the committed suite could not express: its stand-in had
    # a hook on the MERGE only, so a tick STARTING inside the release's await window had nowhere to
    # start. Now that _execute suspends too, the Postgres half's release-window case has its sibling
    # here, and "both interleavings are pinned on both backends" is a claim the suite actually carries.
    db_clock = _Clock(0.0)
    db = _FakeLeaseDB(db_clock)
    store = _FakeSqlLeaseStore(db)
    a = _sql_coord(store, "A")
    b = _sql_coord(_FakeSqlLeaseStore(db), "B")
    await a._maintain_leadership()
    assert a.is_leader() is True

    store.yield_in_execute = True  # the release suspends mid-UPDATE, as a real driver does
    await asyncio.gather(a.step_down_leadership(), a._maintain_leadership())

    assert a.is_leader() is False, "a tick in the release window re-promoted the drained node"
    assert db.row is not None and db.row["lease_expires_at"] == 0.0

    db_clock.t = 1.0
    await b._maintain_leadership()
    assert b.is_leader() is True
    assert a.is_leader() is False, "two leaders at once"


async def test_sqlserver_release_demotes_before_it_writes_and_reports_a_failed_write() -> None:
    # The twin's half of the two defects the Postgres tests above pin: the demotion is synchronous and
    # lands before the awaited write, and a write that raises is reported rather than dressed up as a
    # drain. Same reasoning, same consequences — the T-SQL release carries the same owner-scoped UPDATE.
    db = _FakeLeaseDB(_Clock(0.0))
    store = _FakeSqlLeaseStore(db)
    mono = _Clock(0.0)
    a = _sql_coord(store, "A", mono)
    await a._maintain_leadership()

    seen: list[bool] = []
    store.on_execute = lambda: seen.append(a.is_leader())
    await a.step_down_leadership()
    assert seen == [False], "a reader inside the release window saw the node still reporting leader"

    # And a partitioned release refuses instead of reporting the drain it did not achieve.
    mono.t = 21.0  # past this node's own stepdown pause, so it may claim again
    await a._maintain_leadership()  # take leadership back (the row is expired and owned by A)
    assert a.is_leader() is True
    store.fail = True
    with pytest.raises(StepdownReleaseUnconfirmed):
        await a.step_down_leadership()
    assert a.is_leader() is False

    # And the twin's half of the retry: the forced re-send lands on this backend too, so the operator
    # the refusal tells to retry gets the same outcome on SQL Server as on Postgres.
    store.fail = False
    assert db.row is not None and db.row["lease_expires_at"] != 0.0
    assert await a.step_down_leadership() == (False, None)
    assert db.row["lease_expires_at"] == 0.0, (
        "the SQL Server retry did not re-send the release write"
    )


async def test_sqlserver_cancelled_release_still_owes_the_write() -> None:
    # The twin of test_a_cancelled_release_still_owes_the_write_so_the_retry_re_sends_it. It is here
    # for the reason the module docstring gives for the other SQL Server tests: the defect is an
    # asyncio one, not a T-SQL one — `except Exception` cannot catch CancelledError on either backend —
    # so pinning it only on Postgres would leave the twin unguarded on every ordinary run.
    #
    # VACUITY CONTROL, both legs MEASURED: move `self._lease_release_owed = True` back into the
    # `except Exception` arm of SqlServerCoordinator._release_leadership and this test fails at the
    # owed assertion (`False is True`); silence that one line too and it fails at the row instead
    # (`30.0 == 0.0`), the retry having sent nothing.
    db = _FakeLeaseDB(_Clock(0.0))
    store = _FakeSqlLeaseStore(db)
    a = _sql_coord(store, "A", _Clock(0.0))
    await a._maintain_leadership()
    assert a.is_leader() is True

    store.hang_in_execute = asyncio.Event()  # never set
    await _cancel_once_suspended(asyncio.create_task(a.step_down_leadership()))

    assert a.is_leader() is False
    assert db.row is not None and db.row["lease_expires_at"] == 30.0, "the cancelled write landed"
    assert a._lease_release_owed is True, "a cancelled write left nothing owed"

    store.hang_in_execute = None
    assert await a.step_down_leadership() == (False, None)
    assert db.row["lease_expires_at"] == 0.0, "the retry after a cancelled release sent no write"
    assert a._lease_release_owed is False
