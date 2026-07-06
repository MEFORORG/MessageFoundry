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
"""

from __future__ import annotations

import pytest

from messagefoundry.pipeline.cluster import DbCoordinator


class _Clock:
    """A mutable clock: call it for the current value, set ``.t`` to advance. Used for both the shared
    DB clock and each node's monotonic clock so a test drives time deterministically (no real sleeps)."""

    def __init__(self, t: float = 0.0) -> None:
        self.t = t

    def __call__(self) -> float:
        return self.t


class _FakeLeaseDB:
    """The shared single-row ``leader_lease`` table + the DB clock the lease arithmetic uses."""

    def __init__(self, db_clock: _Clock) -> None:
        self._db_clock = db_clock
        # {"owner": str, "lease_expires_at": float, "leader_epoch": int}
        self.row: dict[str, object] | None = None


class _FakeLeasePool:
    """One node's view of the pool over a shared :class:`_FakeLeaseDB`. Emulates the two statements the
    coordinator issues for the lease; ``fail=True`` makes every call raise to simulate this node being
    partitioned from (or the DB hung for) THIS node only — the other node's pool keeps working."""

    def __init__(self, db: _FakeLeaseDB) -> None:
        self._db = db
        self.fail = False

    async def fetchrow(self, sql: str, *args: object) -> dict[str, object] | None:
        if self.fail:
            raise RuntimeError("partitioned from db")
        # Mirrors _claim_or_renew_lease's INSERT ... ON CONFLICT ... WHERE owner OR expired RETURNING,
        # INCLUDING the H1 leader_epoch maintenance: epoch 1 on a fresh INSERT, +1 on a take-over of an
        # expired/foreign lease, UNCHANGED on a renew (owner == me). RETURNS owner + leader_epoch.
        assert "leader_lease" in sql and "INSERT" in sql
        assert "leader_epoch" in sql, "claim SQL must maintain the H1 fencing epoch"
        _lease_key, owner, ttl = args
        now = self._db._db_clock()
        row = self._db.row
        if row is None:
            self._db.row = {
                "owner": owner,
                "lease_expires_at": now + float(ttl),  # type: ignore[arg-type]
                "leader_epoch": 1,  # fresh acquire on an empty table
            }
            return {"owner": owner, "leader_epoch": 1}
        if row["owner"] == owner or float(row["lease_expires_at"]) < now:  # type: ignore[arg-type]
            # Renew (owner == me) keeps the epoch; a take-over of an expired/foreign lease bumps it.
            if row["owner"] != owner:
                row["leader_epoch"] = int(row["leader_epoch"]) + 1  # type: ignore[arg-type]
            row["owner"] = owner
            row["lease_expires_at"] = now + float(ttl)  # type: ignore[arg-type]
            return {"owner": owner, "leader_epoch": row["leader_epoch"]}
        return None  # another node holds a live lease

    async def execute(self, sql: str, *args: object) -> None:
        if self.fail:
            raise RuntimeError("partitioned from db")
        # Mirrors _release_leadership's UPDATE ... SET lease_expires_at=0 WHERE lease_key AND owner.
        assert "leader_lease" in sql and "UPDATE" in sql
        _lease_key, owner = args
        row = self._db.row
        if row is not None and row["owner"] == owner:
            row["lease_expires_at"] = 0.0


def _coord(
    pool: _FakeLeasePool,
    mono: _Clock,
    *,
    node: str = "A",
    ttl: float = 30.0,
    fence: float = 20.0,
) -> DbCoordinator:
    return DbCoordinator(
        pool,
        node,
        leader_lease_ttl_seconds=ttl,
        leader_fence_timeout_seconds=fence,
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
