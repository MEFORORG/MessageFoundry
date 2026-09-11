# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""ADR 0157 Increment 0 — make the demotion detection margin real.

Three things ship together here and each is pinned below.

1. **The fence baseline is stamped BEFORE the renew is issued.** It used to be stamped after the round
   trip returned, which put the node's own baseline later than the DB clock's ``lease_expires_at``
   stamp by the return leg of that trip. The margin ``_fence_ordering`` appears to guarantee was short
   by an amount nothing measured.
2. **The renew carries its own statement timeout** instead of inheriting ``[store].command_timeout``
   (30 s — the stock lease TTL itself, and unbounded when an operator takes the documented
   ``command_timeout = 0``).
3. **A config-load check on the margin**, which ``_fence_ordering`` never made: it establishes
   ``fence < ttl`` and stops, so it accepts a pair whose remaining margin is a fraction of a second.

**Both arms, or the checks prove nothing.** A stock configuration must load CLEANLY — a check that
fires on every install trains operators to ignore it, and an ignored check withdraws the caution its
absence would have preserved. So each refusal here is paired with the stock config passing, and the
baseline test carries an executed control arm that reproduces the pre-Inc-0 stamp and shows the
two-leader window it left open.

Severity, per CLAUDE.md section 0: **zero deployments**. Nothing is failing over anywhere today. This
is what a first deployment running active-passive HA would have hit.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from messagefoundry.config.settings import (
    ClusterSettings,
    _fence_tick_seconds,
    load_settings,
)
from messagefoundry.pipeline.cluster import (
    DbCoordinator,
    build_coordinator,
    fence_tick_seconds,
)
from messagefoundry.pipeline.cluster_sqlserver import SqlServerCoordinator

# A clustered node needs a server-DB store, so every [cluster] config below carries one.
_PG = '[store]\nbackend = "postgres"\nserver = "pg"\ndatabase = "d"\nusername = "u"\n'


def _write(path: Path, body: str) -> Path:
    path.write_text(body, encoding="utf-8")
    return path


# --- the fence tick, defined once and copied once ---------------------------


def test_the_settings_copy_of_the_fence_tick_matches_the_definition() -> None:
    """``config/`` is the leaf layer and cannot import ``pipeline/``, so the margin validator carries
    its own copy of the fence-tick formula. A copied safety constant drifts silently — two files that
    can be retuned independently with nothing failing — so pin them equal here.

    The range spans both clamps (the 0.05 floor and the 1.0 ceiling) and the linear stretch between,
    because two formulas that agree only on the default agree by luck."""
    for fence in (0.01, 0.1, 0.25, 1.0, 2.0, 4.9, 5.0, 5.1, 12.0, 20.0, 600.0):
        assert _fence_tick_seconds(fence) == fence_tick_seconds(fence), fence


# --- the new default, and the stock config that must pass cleanly -----------


def test_the_renew_clamp_default_is_five_seconds() -> None:
    assert ClusterSettings().lease_renew_timeout_seconds == 5.0


def test_a_stock_clustered_config_loads_cleanly(tmp_path: Path) -> None:
    """The paired arm of every refusal below. At the shipped 10/20/30 the margin is
    30 - 20 - 1.0 = 9.0 s and the 5.0 default sits inside it with room, so an operator who changed
    nothing sees no error and no warning."""
    cfg = _write(tmp_path / "messagefoundry.toml", _PG + "[cluster]\nenabled = true\n")
    s = load_settings(config_path=cfg, environ={})
    assert s.cluster.lease_renew_timeout_seconds == 5.0
    # The margin the default is being held against, spelled out so a defaults change has to move this
    # number too rather than quietly consuming the slack.
    margin = (
        s.cluster.leader_lease_ttl_seconds
        - s.cluster.leader_fence_timeout_seconds
        - _fence_tick_seconds(s.cluster.leader_fence_timeout_seconds)
    )
    assert margin == 9.0
    assert s.cluster.lease_renew_timeout_seconds < margin


# --- the margin check fires on a genuinely unsafe configuration -------------


def test_a_renew_clamp_wider_than_the_margin_is_refused(tmp_path: Path) -> None:
    """heartbeat/fence/ttl of 1/2/3 passes ``_fence_ordering`` — fence is below the TTL — and leaves a
    0.6 s margin against a 5.0 s renew clamp. That is the configuration the ordering check accepts and
    this one must not."""
    cfg = _write(
        tmp_path / "messagefoundry.toml",
        _PG + "[cluster]\nenabled = true\nheartbeat_seconds = 1\n"
        "leader_fence_timeout_seconds = 2\nleader_lease_ttl_seconds = 3\n",
    )
    with pytest.raises(ValidationError, match="lease_renew_timeout_seconds"):
        load_settings(config_path=cfg, environ={})


def test_the_same_tightened_pair_passes_once_the_clamp_fits(tmp_path: Path) -> None:
    """The negative control for the test above: same fence/TTL, a clamp inside the 0.6 s margin. It
    must LOAD — otherwise the refusal is about tightening the fence at all, not about the margin."""
    cfg = _write(
        tmp_path / "messagefoundry.toml",
        _PG + "[cluster]\nenabled = true\nheartbeat_seconds = 1\n"
        "leader_fence_timeout_seconds = 2\nleader_lease_ttl_seconds = 3\n"
        "lease_renew_timeout_seconds = 0.5\n",
    )
    s = load_settings(config_path=cfg, environ={})
    assert s.cluster.lease_renew_timeout_seconds == 0.5


def test_a_clamp_exactly_equal_to_the_margin_is_refused(tmp_path: Path) -> None:
    """The boundary, because an off-by-one in a comparison operator is invisible at the default. With
    fence 20 / TTL 30 the margin is exactly 9.0, and the rule is strict: a renew allowed to run for
    the whole margin leaves nothing for detection itself."""
    at_margin = _write(
        tmp_path / "at.toml",
        _PG + "[cluster]\nenabled = true\nlease_renew_timeout_seconds = 9.0\n",
    )
    with pytest.raises(ValidationError, match="lease_renew_timeout_seconds"):
        load_settings(config_path=at_margin, environ={})
    just_under = _write(
        tmp_path / "under.toml",
        _PG + "[cluster]\nenabled = true\nlease_renew_timeout_seconds = 8.9\n",
    )
    assert (
        load_settings(config_path=just_under, environ={}).cluster.lease_renew_timeout_seconds == 8.9
    )


def test_a_non_positive_renew_clamp_is_refused(tmp_path: Path) -> None:
    """There is deliberately no "0 disables" escape hatch. An unbounded renew is the defect this knob
    removes, so there is no way to configure it back."""
    cfg = _write(
        tmp_path / "messagefoundry.toml",
        _PG + "[cluster]\nenabled = true\nlease_renew_timeout_seconds = 0\n",
    )
    with pytest.raises(ValidationError, match="lease_renew_timeout_seconds"):
        load_settings(config_path=cfg, environ={})


# --- the clamp reaches the statement ----------------------------------------


class _Clock:
    """A mutable clock: call it for the current value, set ``.t`` to advance."""

    def __init__(self, t: float = 0.0) -> None:
        self.t = t

    def __call__(self) -> float:
        return self.t


class _RecordingPool:
    """A lease pool that records the per-statement timeout and can advance either clock mid-flight.

    ``db_advance_before`` moves the DB clock to the instant the statement EXECUTES (which is where a
    real server stamps ``lease_expires_at``); ``mono_advance_after`` moves this node's monotonic clock
    to the instant the response RETURNS. The gap between them is the return leg, and it is the term
    that decides whether the detection margin survives.
    """

    def __init__(
        self,
        db_clock: _Clock,
        mono: _Clock,
        *,
        db_advance_before: float | None = None,
        mono_advance_after: float | None = None,
    ) -> None:
        self._db_clock = db_clock
        self._mono = mono
        self._db_advance_before = db_advance_before
        self._mono_advance_after = mono_advance_after
        self.last_timeout: float | None = None
        self.calls = 0
        self.lease_expires_at: float | None = None

    async def fetchrow(
        self, sql: str, *args: object, timeout: float | None = None
    ) -> dict[str, object] | None:
        self.last_timeout = timeout
        self.calls += 1
        if self._db_advance_before is not None:
            self._db_clock.t = self._db_advance_before
        _lease_key, owner, ttl, _delay = args
        self.lease_expires_at = self._db_clock() + float(ttl)  # type: ignore[arg-type]
        if self._mono_advance_after is not None:
            self._mono.t = self._mono_advance_after
        return {"owner": owner, "leader_epoch": 1}


def _coord(pool: Any, mono: _Clock, **kw: Any) -> DbCoordinator:
    return DbCoordinator(
        pool,
        kw.pop("node", "A"),
        heartbeat_seconds=kw.pop("heartbeat", 10.0),
        leader_lease_ttl_seconds=kw.pop("ttl", 30.0),
        leader_fence_timeout_seconds=kw.pop("fence", 20.0),
        monotonic=mono,
        **kw,
    )


async def test_the_claim_carries_the_configured_statement_timeout() -> None:
    """Not merely "a timeout keyword arrived": the VALUE has to be the configured one, because a
    coordinator that passed its own unrelated constant would satisfy a shape assertion and leave the
    operator's setting doing nothing."""
    mono = _Clock(0.0)
    pool = _RecordingPool(_Clock(0.0), mono)
    a = _coord(pool, mono, lease_renew_timeout_seconds=2.5)
    await a._maintain_leadership()
    assert pool.calls == 1
    assert pool.last_timeout == 2.5


async def test_the_claim_never_falls_back_to_the_inherited_command_timeout() -> None:
    """``None`` is the value that means "inherit the pool's ``command_timeout``" — the pre-Inc-0
    behaviour. It must not be what the default sends."""
    mono = _Clock(0.0)
    pool = _RecordingPool(_Clock(0.0), mono)
    a = _coord(pool, mono)
    await a._maintain_leadership()
    assert pool.last_timeout == 5.0
    assert pool.last_timeout is not None


class _FakeSettings:
    def __init__(self) -> None:
        self.db_schema = None
        self.backend = "postgres"


class _FakeStore:
    def __init__(self, pool: Any) -> None:
        self._pool = pool
        self._owner = "host:1:abcd"
        self._settings = _FakeSettings()


def test_build_coordinator_threads_the_clamp_from_settings() -> None:
    """The seam a setting most often dies at: configured, validated, and never passed on. Pin it with
    a non-default value so a hard-coded 5.0 anywhere in the chain fails here."""
    mono = _Clock(0.0)
    store = _FakeStore(_RecordingPool(_Clock(0.0), mono))
    settings = ClusterSettings(enabled=True, lease_renew_timeout_seconds=3.25)
    coord = build_coordinator(store, settings)
    assert isinstance(coord, DbCoordinator)
    assert coord._renew_timeout == 3.25


# --- the baseline is stamped before the renew is issued ---------------------


async def test_the_fence_baseline_is_stamped_before_the_renew_not_after_it() -> None:
    """The slow-renew fixture ADR 0157 Inc 0 names, with its control arm.

    The DB executes the claim at DB-clock 1.0 and stamps ``lease_expires_at = 31.0``. The response
    does not reach this node until monotonic 20.0 — a 19 s return leg, which a hung pool or a
    saturated link makes ordinary. Both clocks then run together.

    * **Shipped:** the baseline is 0.0, the instant the claim was ISSUED. Fence (20.0) plus one tick
      (1.0) puts detection at 21.0, which is 10 s before the lease can expire. The margin is positive.
    * **Control — the pre-Inc-0 stamp:** the baseline is 20.0, the instant the response returned.
      Detection lands at 41.0, ten seconds AFTER a standby may take the lease. That is the two-leader
      window, and it is reproduced here with the same production ``_check_fence`` so the assertion
      above is known to be able to fail.
    """
    db_clock = _Clock(0.0)
    mono = _Clock(0.0)
    pool = _RecordingPool(db_clock, mono, db_advance_before=1.0, mono_advance_after=20.0)
    a = _coord(pool, mono)
    await a._maintain_leadership()

    assert a.is_leader() is True
    assert a._last_renew_ok == 0.0, "the baseline must be the ISSUE instant, not the return instant"
    assert pool.lease_expires_at == 31.0

    # Shipped: fenced one tick past the fence timeout, comfortably before the lease can expire.
    mono.t = 21.0
    a._check_fence()
    assert a.is_leader() is False
    assert mono.t < pool.lease_expires_at

    # Control: the same coordinator, the same _check_fence, the baseline the old code would have
    # stamped. At the instant the lease expires this node is STILL reporting leader.
    a._is_leader = True
    a._last_renew_ok = 20.0
    mono.t = 31.0
    a._check_fence()
    assert a.is_leader() is True, (
        "the control arm did not reproduce the defect, so the assertion above proves nothing"
    )


async def test_the_sqlserver_twin_stamps_the_baseline_from_the_same_instant() -> None:
    """Lockstep, and it matters MORE on this backend. ``DbCoordinator`` also clamps its round trip;
    the SQL Server renew still inherits ``[store].command_timeout`` from the ODBC connection, because
    a per-statement override lives in ``store/sqlserver.py`` (an open ADR 0157 Inc 0 residual). So the
    baseline stamp is, for now, the only thing keeping this backend's margin real."""
    mono = _Clock(0.0)

    class _Store:
        async def _fetchone(self, sql: str, params: tuple[object, ...]) -> dict[str, object]:
            mono.t = 20.0  # the response returns 20 s after the claim was issued
            return {"owner": "A", "leader_epoch": 1}

    a = SqlServerCoordinator(
        _Store(),
        "A",
        leader_lease_ttl_seconds=30.0,
        leader_fence_timeout_seconds=20.0,
        monotonic=mono,
    )
    await a._maintain_leadership()
    assert a.is_leader() is True
    assert a._last_renew_ok == 0.0


async def test_a_failed_renew_leaves_the_baseline_where_it_was() -> None:
    """The clamp adds a bound, not a new path: a renew that raises (a timeout included) must not
    advance the baseline, or a node whose DB is unreachable would refresh its own fence forever."""

    class _FailingPool(_RecordingPool):
        async def fetchrow(
            self, sql: str, *args: object, timeout: float | None = None
        ) -> dict[str, object] | None:
            self.last_timeout = timeout
            raise TimeoutError("statement timeout")

    mono = _Clock(0.0)
    pool = _RecordingPool(_Clock(0.0), mono)
    a = _coord(pool, mono)
    await a._maintain_leadership()
    assert a._last_renew_ok == 0.0

    a._pool = _FailingPool(_Clock(0.0), mono)
    mono.t = 10.0
    with pytest.raises(TimeoutError):
        await a._maintain_leadership()
    assert a._last_renew_ok == 0.0, "a failed renew must not refresh the fence baseline"
