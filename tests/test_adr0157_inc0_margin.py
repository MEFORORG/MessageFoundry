# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
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
   The clamp's default is DERIVED from that margin, between a floor and a ceiling, and is then held
   to the same comparison as an operator's own value rather than trusted.

**Both arms, or the checks prove nothing.** A check that refuses a legitimate configuration gets
turned off by whoever hits it first, and an ignored check withdraws the caution its absence would
have preserved. So each refusal here is paired with a load that must SUCCEED, and the baseline test
carries an executed control arm that reproduces the pre-Inc-0 stamp and shows the two-leader window
it left open.

**"A stock install loads cleanly" is not a wide enough passing arm, and this module learned that the
hard way.** The first cut of the increment shipped a fixed 5.0 clamp, met that condition, and refused
this repository's OWN failover configurations — both engine subprocesses of a failover load run would
have aborted at config load. One point in a two-dimensional space is not coverage of the space. The
passing arm is therefore a CENSUS of every failover configuration the repository ships, driven
through the harness's real environment export rather than a hand-built settings object.

Severity, per CLAUDE.md section 0: **zero deployments**. Nothing is failing over anywhere today. This
is what a first deployment running active-passive HA would have hit.
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from _failover_load_support import failover_test_profile
from pydantic import ValidationError

from harness.load.failover import FailoverPorts, _node_env
from harness.load.profile import PROFILES_DIR, Failover, LoadProfileError, load_profile
from messagefoundry.config.settings import (
    _RENEW_CLAMP_CEILING_SECONDS,
    _RENEW_CLAMP_FLOOR_SECONDS,
    ClusterSettings,
    _detection_margin_seconds,
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


def test_the_renew_clamp_default_is_derived_from_the_margin() -> None:
    """Unset means DERIVED, not a constant. At the shipped 10/20/30 the margin is 9.0 s, so the clamp
    resolves to half of it. The 5.0 s ceiling does not bind here -- it binds only past a 10 s margin."""
    assert ClusterSettings().lease_renew_timeout_seconds == 4.5


def test_a_stock_clustered_config_loads_cleanly(tmp_path: Path) -> None:
    """The paired arm of every refusal below. At the shipped 10/20/30 the margin is
    30 - 20 - 1.0 = 9.0 s and the derived clamp sits inside it with room, so an operator who changed
    nothing sees no error and no warning."""
    cfg = _write(tmp_path / "messagefoundry.toml", _PG + "[cluster]\nenabled = true\n")
    s = load_settings(config_path=cfg, environ={})
    assert s.cluster.lease_renew_timeout_seconds == 4.5
    # The margin the default is being held against, spelled out so a defaults change has to move this
    # number too rather than quietly consuming the slack.
    margin = (
        s.cluster.leader_lease_ttl_seconds
        - s.cluster.leader_fence_timeout_seconds
        - _fence_tick_seconds(s.cluster.leader_fence_timeout_seconds)
    )
    assert margin == 9.0
    assert s.cluster.lease_renew_timeout_seconds < margin


def test_the_derived_clamp_fits_every_margin_it_is_reachable_with() -> None:
    """The derived clamp lands inside the margin, and above the floor, across the reachable range.

    A FIXED default cannot hold the first half. The first cut of this increment shipped a constant 5.0
    and it refused this repository's own failover profiles at config load -- two of the pairs below.

    **Not a by-construction property, and it used to be described as one.** Adding the floor means the
    derivation CAN exceed a small margin, and such a pair is refused rather than run; that case is its
    own test below. The grid here covers the margins where a clamp does fit, and spans both the floor
    and the ceiling, because a rule verified only where one branch is taken is verified on one
    branch."""
    pairs = [
        (2.0, 3.6),  # margin 1.2 -- the floor binds
        (3.0, 5.0),  # the CI failover pair
        (4.0, 6.0),  # the shipped failover profile's pair
        (12.0, 20.0),
        (20.0, 30.0),  # the shipped pair
        (20.0, 45.0),  # margin 24.0 -- past the ceiling, so the ceiling binds
        (99.0, 400.0),  # margin 300.0 -- far past it
    ]
    saw_ceiling_bind = False
    saw_floor_bind = False
    for fence, ttl in pairs:
        s = ClusterSettings(
            heartbeat_seconds=min(1.0, fence / 2.0),
            leader_fence_timeout_seconds=fence,
            leader_lease_ttl_seconds=ttl,
        )
        margin = ttl - fence - _fence_tick_seconds(fence)
        clamp = s.lease_renew_timeout_seconds
        assert clamp is not None
        assert 0 < clamp < margin, (fence, ttl, clamp, margin)
        # The floor is a LIVENESS bound: below it the clamp would time out renews a healthy-but-loaded
        # database would have completed, and a leader that cannot renew self-fences.
        assert clamp >= _RENEW_CLAMP_FLOOR_SECONDS, (fence, ttl, clamp)
        saw_ceiling_bind |= clamp == _RENEW_CLAMP_CEILING_SECONDS
        saw_floor_bind |= clamp == _RENEW_CLAMP_FLOOR_SECONDS
    # Without these the grid could be all mid-range margins and still pass, proving nothing about
    # either clamp of the derivation.
    assert saw_ceiling_bind, "no pair in the grid exercised the derived clamp's ceiling"
    assert saw_floor_bind, "no pair in the grid exercised the derived clamp's floor"


def test_a_margin_too_small_for_the_floor_is_refused_rather_than_run_at_a_fencing_clamp() -> None:
    """The floor's refusal arm, and the reason the derivation is CHECKED rather than trusted.

    A pair whose margin cannot fit the floor has no safe clamp: anything inside the margin is short
    enough to time out renews a merely-slow database would have completed, and a leader that cannot
    renew self-fences. Refusing at config load beats running it and failing over spuriously.

    This is where the derived value genuinely fails the comparison below it -- so the fall-through is
    load-bearing, not a backstop against a hypothetical."""
    for fence, ttl in [(4.0, 5.2), (4.0, 5.8), (2.0, 2.8)]:
        with pytest.raises(ValidationError, match="lease_renew_timeout_seconds"):
            ClusterSettings(
                enabled=True,
                heartbeat_seconds=1.0,
                leader_fence_timeout_seconds=fence,
                leader_lease_ttl_seconds=ttl,
            )


def test_the_derived_clamp_clears_the_liveness_limit_at_both_shipped_failover_profiles() -> None:
    """The finding the floor exists for, pinned as a number rather than left to the comment.

    A renew is retried every ``heartbeat_seconds`` and the fence baseline advances only on success, so
    a configuration tolerates a renew latency of roughly ``(fence - heartbeat) / 2`` before it fences
    a leader whose database is merely slow -- with or without any clamp. A clamp BELOW that limit
    narrows the operating envelope the configuration already has; a clamp at or above it never fences
    a node that would otherwise have survived.

    Without the floor the derivation returned 0.6 s and 0.7 s here, both below the limit. With it,
    neither profile's clamp binds first."""
    for hb, fence, ttl in [(2.0, 4.0, 6.0), (1.5, 3.0, 5.0)]:
        s = ClusterSettings(
            enabled=True,
            heartbeat_seconds=hb,
            leader_fence_timeout_seconds=fence,
            leader_lease_ttl_seconds=ttl,
        )
        clamp = s.lease_renew_timeout_seconds
        assert clamp is not None
        assert clamp >= (fence - hb) / 2.0, (hb, fence, ttl, clamp)


# --- the margin check fires on a genuinely unsafe configuration -------------


def test_a_renew_clamp_wider_than_the_margin_is_refused(tmp_path: Path) -> None:
    """heartbeat/fence/ttl of 1/2/3 passes ``_fence_ordering`` — fence is below the TTL — and leaves a
    0.6 s margin against the 5.0 s renew clamp pinned here. That is the configuration the ordering
    check accepts and this one must not.

    The clamp is set EXPLICITLY because that is now the only way to reach this refusal: left unset it
    would be derived to 0.3 and fit. An explicit value is never silently shrunk to fit — a check that
    rewrites its subject to pass accepts everything, which is the same as not checking."""
    cfg = _write(
        tmp_path / "messagefoundry.toml",
        _PG + "[cluster]\nenabled = true\nheartbeat_seconds = 1\n"
        "leader_fence_timeout_seconds = 2\nleader_lease_ttl_seconds = 3\n"
        "lease_renew_timeout_seconds = 5.0\n",
    )
    with pytest.raises(ValidationError, match="lease_renew_timeout_seconds"):
        load_settings(config_path=cfg, environ={})


def test_a_fence_ttl_pair_with_no_margin_at_all_is_refused(tmp_path: Path) -> None:
    """The refusal no clamp can escape, and the one the derived default must NOT paper over.

    fence 4.0 / TTL 4.5 orders fine, so ``_fence_ordering`` passes it, but the fence tick is 0.8 and
    the margin is -0.3: detection can land at or after the moment the lease expires and a standby
    acquires. Deriving the clamp cannot fix that — there is no positive number below -0.3 — so this
    refuses BEFORE the clamp is resolved, and names the fence/TTL pair rather than blaming the clamp.

    **This arm changes the MESSAGE, not the verdict, and an earlier version of this docstring claimed
    otherwise.** It said the branch stopped a refusal becoming a silent pass. That was false and was
    measured false: with ``if not margin > 0:`` mutated to ``if False:`` this pair is still refused,
    because the derived clamp off a -0.3 margin is itself negative and fails the comparison below. The
    only thing that goes red under that mutation is this test's own ``match=`` regex. The branch earns
    its place by telling the operator their fence/TTL pair has no margin, instead of telling them to
    lower a clamp they never set — which is worth having, and is not the same as catching something."""
    cfg = _write(
        tmp_path / "messagefoundry.toml",
        _PG + "[cluster]\nenabled = true\nheartbeat_seconds = 1\n"
        "leader_fence_timeout_seconds = 4.0\nleader_lease_ttl_seconds = 4.5\n",
    )
    with pytest.raises(ValidationError, match="NO demotion detection margin"):
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


# --- the repository's OWN failover configurations still load ----------------
#
# The arm the first cut of this increment did not have, and the one that would have caught it. A fixed
# 5.0 default refused BOTH configurations below at config load, so both `messagefoundry serve`
# subprocesses of a failover load run would have aborted before the scenario started. Nothing in the
# suite noticed, because nothing drove the real settings path with the real profile timings.


def _failover_timings() -> dict[str, Failover]:
    """Every failover configuration this repository ships, read from the shipped files.

    Enumerated rather than listed, so a profile added later is covered without editing this test.
    ``load_profile`` refuses the profiles carrying other harness entry points' top-level tables
    (``connscale``, ``estate``), which are not failover profiles — but skipping on a raised error
    would also skip a failover profile that failed to load for a real reason, so the set is
    cross-checked against a raw text scan below."""
    declares = {
        path.name
        for path in sorted(PROFILES_DIR.glob("*.toml"))
        if "[load.failover]" in path.read_text(encoding="utf-8")
    }
    found: dict[str, Failover] = {}
    for path in sorted(PROFILES_DIR.glob("*.toml")):
        try:
            profile = load_profile(path)
        except LoadProfileError:
            continue
        if profile.failover is not None:
            found[path.name] = profile.failover
    # The negative control on the enumeration: a file that DECLARES the table but did not survive the
    # load would otherwise vanish from this census silently, and a census that cannot report a miss is
    # not a census.
    assert declares == set(found), (declares, set(found))

    ci = failover_test_profile()
    assert ci.failover is not None
    found["tests/_failover_load_support.py"] = ci.failover
    return found


def test_the_census_of_shipped_failover_configurations_is_not_empty() -> None:
    """The positive control for the test below. A glob that matches nothing makes a parametrized test
    vacuously green, and a zero is a fact about the pattern, not about the repository."""
    timings = _failover_timings()
    assert "failover.toml" in timings
    assert "tests/_failover_load_support.py" in timings
    assert len(timings) >= 2


@pytest.mark.parametrize("source", sorted(_failover_timings()))
def test_a_shipped_failover_configuration_loads_through_the_real_node_env(
    source: str, tmp_path: Path
) -> None:
    """Drive the REAL settings path with the REAL exported environment, not a hand-built object.

    ``harness/load/failover.py::_node_env`` is what actually configures the two engine subprocesses,
    and it exports the fence timeout and the lease TTL but no renew clamp — so whatever the clamp
    defaults to is what those nodes get. Building a ``ClusterSettings`` by hand here would test the
    validator against numbers a human retyped; going through ``_node_env`` + ``load_settings`` tests it
    against the numbers the harness will really export.

    The fence/TTL assertions are the aim check: if ``_node_env`` stopped exporting the timings, the
    settings would silently fall back to the stock 20/30, the clamp would fit, and this test would pass
    while covering nothing."""
    fo = _failover_timings()[source]
    ports = FailoverPorts(
        inbound_adt=2600,
        inbound_results=2601,
        inbound_other=2602,
        sink=2700,
        sink_count=2,
        api_a=2800,
        api_b=2801,
    )
    env = _node_env({}, node_id="fo-a", ports=ports, fo=fo, sink_host="127.0.0.1")
    cfg = _write(tmp_path / "messagefoundry.toml", _PG)

    s = load_settings(config_path=cfg, environ=env)

    assert s.cluster.enabled
    assert s.cluster.leader_fence_timeout_seconds == fo.leader_fence_timeout_seconds
    assert s.cluster.leader_lease_ttl_seconds == fo.leader_lease_ttl_seconds
    margin = _detection_margin_seconds(
        s.cluster.leader_fence_timeout_seconds, s.cluster.leader_lease_ttl_seconds
    )
    clamp = s.cluster.lease_renew_timeout_seconds
    assert clamp is not None
    assert 0 < clamp < margin, (source, clamp, margin)


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


def test_build_coordinator_threads_the_DERIVED_clamp_from_settings() -> None:
    """The same seam for the value an operator actually gets, which the test above does not cover.

    Pinning only an EXPLICIT 3.25 leaves the derived path unasserted, and ``build_coordinator``'s
    duck-typed fallback is a literal 5.0 -- so a validator regression that stopped filling the field
    in would be absorbed silently and the coordinator would run on a constant nobody chose. This says
    the stock config's 4.5 reaches the coordinator, and it is a different number from that fallback on
    purpose."""
    mono = _Clock(0.0)
    store = _FakeStore(_RecordingPool(_Clock(0.0), mono))
    settings = ClusterSettings(enabled=True)  # unset -> derived
    assert settings.lease_renew_timeout_seconds == 4.5
    coord = build_coordinator(store, settings)
    assert isinstance(coord, DbCoordinator)
    assert coord._renew_timeout == 4.5


def test_the_duck_typed_fallback_does_not_swallow_a_zero() -> None:
    """``is None``, not ``or``. A falsy-test would turn a duck-typed 0.0 into the 5.0 fallback -- a
    value ClusterSettings refuses outright, substituted at the one seam feeding the live coordinator,
    where nothing downstream would report it."""
    mono = _Clock(0.0)
    store = _FakeStore(_RecordingPool(_Clock(0.0), mono))
    stand_in = SimpleNamespace(enabled=True, lease_renew_timeout_seconds=0.0)
    coord = build_coordinator(store, stand_in)
    assert isinstance(coord, DbCoordinator)
    assert coord._renew_timeout == 0.0


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
