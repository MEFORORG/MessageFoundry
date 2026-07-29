# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""ADR 0079 mechanism 2 — directory session reconciliation.

Disabling an account in AD does not terminate its live engine session; this reconciler re-resolves
directory-backed principals holding live sessions and revokes those the directory no longer has.
The tests that matter are the FAILURE modes, not the happy path:

* a directory outage revokes **nothing** (fail-open) and does not even accrue a strike;
* one ambiguous "not found" never revokes — it takes ``ad_session_recheck_strikes`` in a row;
* a pass that would revoke the whole estate ABORTS, writes nothing, and alerts (the bad-search-base
  case, which is indistinguishable from "everyone was disabled");
* at the default ``ad_session_recheck_seconds = 0`` the feature is inert.

All directory data here is synthetic.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from messagefoundry.auth import reconcile
from messagefoundry.auth.identity import AuthProvider
from messagefoundry.auth.ldap import AdPrincipal, LdapError
from messagefoundry.auth.service import AuthService
from messagefoundry.config.settings import AuthSettings
from messagefoundry.store.store import MessageStore

PW = "Sup3rSecret!!"


def _ad_settings(**over: object) -> AuthSettings:
    base: dict[str, object] = {
        "ad_enabled": True,
        "ad_server": "ldaps://dc.test.invalid",
        "ad_user_search_base": "OU=Staff,DC=test,DC=invalid",
        "ad_bind_dn": "CN=svc-mefor,OU=Service,DC=test,DC=invalid",
        "ad_bind_password": "synthetic",
        "ad_session_recheck_seconds": 60,
    }
    base.update(over)
    return AuthSettings(**base)  # type: ignore[arg-type]


def _principal(username: str, *groups: str) -> AdPrincipal:
    return AdPrincipal(
        username=username,
        display_name=username.title(),
        email=f"{username}@test.invalid",
        dn=f"CN={username},OU=Staff,DC=test,DC=invalid",
        groups=frozenset(groups),
    )


class _FakeLdap:
    """A directory whose answers the test drives. ``present`` maps username -> principal; a username
    in ``unreachable`` raises :class:`LdapError` (the connectivity signal); anything else resolves to
    ``None`` — the real ``resolve_principal``'s ambiguous disabled/deleted/wrong-search-base answer."""

    def __init__(
        self, present: dict[str, AdPrincipal] | None = None, unreachable: set[str] | None = None
    ) -> None:
        self.present = present or {}
        self.unreachable = unreachable or set()
        self.probes: list[str] = []

    def authenticate(self, username: str, password: str) -> AdPrincipal | None:
        # Login/step-up binds are deliberately NOT counted in ``probes``; that list measures the
        # reconciler's directory load only.
        return self._lookup(username)

    def resolve_principal(self, username: str) -> AdPrincipal | None:
        self.probes.append(username)
        return self._lookup(username)

    def _lookup(self, username: str) -> AdPrincipal | None:
        if username in self.unreachable:
            raise LdapError("synthetic: LDAP socket closed")
        return self.present.get(username)


async def _signed_in_ad_user(
    service: AuthService, store: MessageStore, username: str
) -> str | None:
    """Log ``username`` in over the AD path and return the minted token."""
    return (await service.login(username, "pw", provider=AuthProvider.AD)).token


# --- the pure decision layer -------------------------------------------------
#
# These carry the circuit-breaker arithmetic, so they are asserted without a store or a directory.


@pytest.mark.parametrize(
    ("revoke_count", "probed", "tripped", "why"),
    [
        (3, 3, False, "a 3-person estate fully offboarded: absolute floor not exceeded"),
        (5, 5, False, "exactly at the absolute floor — the AND form keeps a tiny estate working"),
        (6, 6, True, "one past the floor AND 100% of the estate: a bad search base"),
        (4, 300, False, "a handful of genuine offboardings in a large estate"),
        (50, 300, False, "a real batch offboarding (17%) is large but not broad — must apply"),
        (300, 300, True, "the whole estate at once: the case the breaker exists for"),
        (0, 300, False, "nothing to revoke never trips"),
        (7, 0, False, "no probes means no denominator — never trip on a vacuous pass"),
    ],
)
def test_breaker_requires_both_thresholds(
    revoke_count: int, probed: int, tripped: bool, why: str
) -> None:
    assert (
        reconcile.breaker_tripped(
            revoke_count=revoke_count, probed=probed, max_absolute=5, max_fraction=0.34
        )
        is tripped
    ), why


def test_plan_strikes_before_it_revokes() -> None:
    probes = [reconcile.Probe("u1", "alice", reconcile.ProbeOutcome.ABSENT)]
    first = reconcile.plan_pass(
        probes,
        prior_strikes={},
        current_roles={},
        target_roles={},
        strike_threshold=2,
        max_absolute=5,
        max_fraction=0.34,
    )
    assert first.revocations == ()  # one ambiguous answer must never revoke
    assert first.strikes == {"u1": 1}

    second = reconcile.plan_pass(
        probes,
        prior_strikes=first.strikes,
        current_roles={},
        target_roles={},
        strike_threshold=2,
        max_absolute=5,
        max_fraction=0.34,
    )
    assert [r.user_id for r in second.revocations] == ["u1"]
    assert second.revocations[0].reason == "directory_absent"


def test_plan_aborts_when_every_probe_failed() -> None:
    probes = [
        reconcile.Probe(f"u{i}", f"user{i}", reconcile.ProbeOutcome.UNAVAILABLE) for i in range(4)
    ]
    plan = reconcile.plan_pass(
        probes,
        prior_strikes={"u0": 1},
        current_roles={},
        target_roles={},
        strike_threshold=2,
        max_absolute=5,
        max_fraction=0.34,
    )
    assert plan.aborted == "directory_unavailable"
    assert plan.revocations == () and plan.strikes == {}


def test_plan_abort_drops_every_revocation_but_keeps_the_strikes() -> None:
    """A tripped breaker performs NO store write. The strikes are process-local bookkeeping, not
    store state, and are kept so a standing misconfiguration trips on every subsequent pass instead
    of oscillating (accrue, trip, reset, accrue...) and flickering the operator alert."""
    probes = [
        reconcile.Probe(f"u{i}", f"user{i}", reconcile.ProbeOutcome.ABSENT) for i in range(20)
    ]
    prior = {f"u{i}": 1 for i in range(20)}
    plan = reconcile.plan_pass(
        probes,
        prior_strikes=prior,
        current_roles={},
        target_roles={},
        strike_threshold=2,
        max_absolute=5,
        max_fraction=0.34,
    )
    assert plan.aborted == "mass_revoke_breaker"
    assert plan.revocations == ()
    assert plan.strikes == {f"u{i}": 2 for i in range(20)}
    assert plan.probed == 20


def test_plan_resets_a_strike_when_the_principal_comes_back() -> None:
    plan = reconcile.plan_pass(
        [reconcile.Probe("u1", "alice", reconcile.ProbeOutcome.PRESENT, groups=frozenset())],
        prior_strikes={"u1": 1},
        current_roles={"u1": frozenset()},
        target_roles={"u1": frozenset()},
        strike_threshold=2,
        max_absolute=5,
        max_fraction=0.34,
    )
    assert plan.strikes == {"u1": 0} and plan.revocations == ()


def test_candidate_selection_bounds_the_pass_and_rotates() -> None:
    candidates = [(f"u{i}", f"user{i}") for i in range(5)]
    # u0/u1 were probed recently; the rest never have been and must go first.
    picked = reconcile.select_candidates(
        candidates, last_probed={"u0": 100.0, "u1": 50.0}, budget=2
    )
    assert [c[0] for c in picked] == ["u2", "u3"]
    # A budget wider than the estate simply takes everyone.
    assert len(reconcile.select_candidates(candidates, last_probed={}, budget=99)) == 5


def test_prune_ledger_drops_departed_users() -> None:
    ledger = {"u1": 2, "u2": 1}
    reconcile.prune_ledger(ledger, ["u1"])
    assert ledger == {"u1": 2}


def test_breaker_ceiling_reports_the_larger_of_the_two_thresholds() -> None:
    assert reconcile.breaker_ceiling(probed=10, max_absolute=5, max_fraction=0.34) == 5
    assert reconcile.breaker_ceiling(probed=300, max_absolute=5, max_fraction=0.34) == 102


# --- settings --------------------------------------------------------------------


def test_reconciler_is_on_by_default() -> None:
    """The shipped default runs the reconciler (ADR 0148 GIVEN 1), and every safety knob has a default.

    300 s, not 0: the hardened path is the shipped path. It stays INERT without AD — `should_reconcile`
    also requires an LDAP client — so a non-AD deployment creates no task and issues no bind."""
    defaults = AuthSettings()
    assert defaults.ad_session_recheck_seconds == 300
    assert defaults.ad_session_recheck_strikes == 2
    assert defaults.ad_session_revoke_max == 5
    assert defaults.ad_session_revoke_max_fraction == pytest.approx(0.34)


@pytest.mark.parametrize(
    "override",
    [
        {"ad_session_recheck_seconds": 5},  # below the 60s DC-protection floor
        {"ad_session_recheck_seconds": -1},
        {"ad_session_recheck_strikes": 0},  # would revoke on the first ambiguous probe
        {"ad_session_recheck_max_users": 0},
        {"ad_session_revoke_max": -1},
        {"ad_session_revoke_max_fraction": 0.0},  # silently disables the proportional half
        {"ad_session_revoke_max_fraction": 1.5},
    ],
)
def test_unsafe_reconciler_settings_are_refused(override: dict[str, object]) -> None:
    with pytest.raises(ValidationError):
        _ad_settings(**override)


def test_recheck_without_ad_is_refused_rather_than_silently_dead() -> None:
    with pytest.raises(ValidationError, match="requires ad_enabled"):
        AuthSettings(ad_session_recheck_seconds=300)


# --- service integration ---------------------------------------------------------


async def test_disabled_account_is_revoked_after_the_configured_strikes() -> None:
    store = await MessageStore.open(":memory:")
    try:
        ldap = _FakeLdap({"jdoe": _principal("jdoe")})
        service = AuthService(store, _ad_settings(), ldap=ldap)  # type: ignore[arg-type]
        await service.initialize()
        token = await _signed_in_ad_user(service, store, "jdoe")
        assert token is not None and await service.identity_for_token(token) is not None

        ldap.present.clear()  # the account is disabled in AD

        plan = await service.reconcile_directory_sessions()
        assert plan.revocations == ()  # strike 1: never revoke on one ambiguous answer
        assert await service.identity_for_token(token) is not None

        plan = await service.reconcile_directory_sessions()
        assert [r.username for r in plan.revocations] == ["jdoe"]
        assert await service.identity_for_token(token) is None  # strike 2: session is gone
        audit = await store.list_audit()
        assert any(a["action"] == "auth.ad_session_revoked" for a in audit)
    finally:
        await store.close()


async def test_directory_outage_revokes_nothing() -> None:
    """THE fail-open property: an unreachable DC must never sign the estate out. A fail-closed
    re-check would turn a directory blip into a console outage during exactly the incident when
    operators need the console."""
    store = await MessageStore.open(":memory:")
    try:
        ldap = _FakeLdap({"jdoe": _principal("jdoe"), "asmith": _principal("asmith")})
        service = AuthService(store, _ad_settings(), ldap=ldap)  # type: ignore[arg-type]
        await service.initialize()
        tokens = [await _signed_in_ad_user(service, store, u) for u in ("jdoe", "asmith")]

        ldap.unreachable = {"jdoe", "asmith"}  # the DC goes away
        for _ in range(5):  # far more passes than the strike threshold
            plan = await service.reconcile_directory_sessions()
            assert plan.aborted == "directory_unavailable"
            assert plan.revocations == ()

        for token in tokens:
            assert token is not None and await service.identity_for_token(token) is not None
        assert not any(a["action"] == "auth.ad_session_revoked" for a in await store.list_audit())
    finally:
        await store.close()


async def test_an_outage_does_not_erase_an_accrued_strike() -> None:
    """An UNAVAILABLE probe contributes nothing — it must neither add a strike nor clear one, or a
    flapping DC would indefinitely reset the counter for a genuinely disabled account."""
    store = await MessageStore.open(":memory:")
    try:
        ldap = _FakeLdap({"jdoe": _principal("jdoe")})
        service = AuthService(store, _ad_settings(), ldap=ldap)  # type: ignore[arg-type]
        await service.initialize()
        token = await _signed_in_ad_user(service, store, "jdoe")

        ldap.present.clear()
        await service.reconcile_directory_sessions()  # strike 1
        ldap.unreachable = {"jdoe"}
        await service.reconcile_directory_sessions()  # outage: no strike, no reset
        assert token is not None and await service.identity_for_token(token) is not None

        ldap.unreachable.clear()
        plan = await service.reconcile_directory_sessions()  # strike 2 -> revoke
        assert [r.username for r in plan.revocations] == ["jdoe"]
        assert await service.identity_for_token(token) is None
    finally:
        await store.close()


async def test_mass_revoke_breaker_aborts_the_pass_and_alerts() -> None:
    """The bad-search-base case: the directory answers "not found" for EVERY user, which is
    indistinguishable from "everyone was disabled". The pass must revoke nothing and shout."""
    store = await MessageStore.open(":memory:")
    try:
        names = [f"user{i:02d}" for i in range(12)]
        ldap = _FakeLdap({n: _principal(n) for n in names})
        service = AuthService(store, _ad_settings(), ldap=ldap)  # type: ignore[arg-type]
        await service.initialize()
        tokens = [await _signed_in_ad_user(service, store, n) for n in names]

        ldap.present.clear()  # e.g. ad_user_search_base now points at the wrong OU
        first = await service.reconcile_directory_sessions()
        assert first.aborted is None and first.revocations == ()  # strike 1: nothing to abort yet
        for _ in range(4):  # from strike 2 on, the breaker must hold pass after pass
            plan = await service.reconcile_directory_sessions()
            assert plan.aborted == "mass_revoke_breaker"
            assert plan.revocations == ()

        for token in tokens:
            assert token is not None and await service.identity_for_token(token) is not None
        assert service.directory_reconcile_alert is not None
        assert "circuit breaker TRIPPED" in service.directory_reconcile_alert
        assert any(a["action"] == "auth.ad_reconcile_aborted" for a in await store.list_audit())
    finally:
        await store.close()


async def test_a_small_genuine_offboarding_still_revokes() -> None:
    """The breaker must not become a blanket "never revoke": below the absolute floor a real
    offboarding still takes effect, which is the whole point of the AND-form threshold."""
    store = await MessageStore.open(":memory:")
    try:
        names = [f"user{i:02d}" for i in range(12)]
        ldap = _FakeLdap({n: _principal(n) for n in names})
        service = AuthService(store, _ad_settings(), ldap=ldap)  # type: ignore[arg-type]
        await service.initialize()
        tokens = {n: await _signed_in_ad_user(service, store, n) for n in names}

        del ldap.present["user00"], ldap.present["user01"]  # 2 of 12 — under the floor
        await service.reconcile_directory_sessions()
        plan = await service.reconcile_directory_sessions()
        assert sorted(r.username for r in plan.revocations) == ["user00", "user01"]
        assert service.directory_reconcile_alert is None

        for name, token in tokens.items():
            assert token is not None
            gone = name in ("user00", "user01")
            assert (await service.identity_for_token(token) is None) is gone
    finally:
        await store.close()


async def test_the_breaker_alert_clears_on_a_clean_pass() -> None:
    store = await MessageStore.open(":memory:")
    try:
        names = [f"user{i:02d}" for i in range(12)]
        ldap = _FakeLdap({n: _principal(n) for n in names})
        service = AuthService(store, _ad_settings(), ldap=ldap)  # type: ignore[arg-type]
        await service.initialize()
        for name in names:
            await _signed_in_ad_user(service, store, name)

        present = dict(ldap.present)
        ldap.present.clear()
        await service.reconcile_directory_sessions()  # strike 1
        await service.reconcile_directory_sessions()  # strike 2 -> the breaker trips
        assert service.directory_reconcile_alert is not None

        # An empty pass learns NOTHING about the directory, so it must not clear a standing alarm.
        for name in names:
            user = await store.get_user_by_username(name)
            assert user is not None
            await store.revoke_user_sessions(user.id)
        await service.reconcile_directory_sessions()
        assert service.directory_reconcile_alert is not None

        ldap.present.update(present)  # the operator fixed the search base; people sign back in
        for name in names:
            await _signed_in_ad_user(service, store, name)
        await service.reconcile_directory_sessions()
        assert service.directory_reconcile_alert is None
    finally:
        await store.close()


async def test_role_demotion_in_the_directory_takes_effect_on_the_same_pass() -> None:
    """The free win: ``resolve_principal`` already returns the group set, so a demotion costs no
    extra bind. It rides the SAME breaker budget as an absence."""
    store = await MessageStore.open(":memory:")
    try:
        ldap = _FakeLdap({"jdoe": _principal("jdoe", "cn=mf-admins,dc=test,dc=invalid")})
        service = AuthService(store, _ad_settings(), ldap=ldap)  # type: ignore[arg-type]
        await service.initialize()
        await service.set_ad_group_map(
            [("cn=mf-admins,dc=test,dc=invalid", "administrator")], actor="admin"
        )
        token = await _signed_in_ad_user(service, store, "jdoe")
        assert token is not None
        identity = await service.identity_for_token(token)
        assert identity is not None and "administrator" in {r.value for r in identity.roles}

        # Removed from the admin group in AD; the session must not keep the elevated role.
        ldap.present["jdoe"] = _principal("jdoe")
        plan = await service.reconcile_directory_sessions()
        assert [(r.username, r.reason) for r in plan.revocations] == [("jdoe", "roles_changed")]
        assert await service.identity_for_token(token) is None

        user = await store.get_user_by_username("jdoe")
        assert user is not None
        assert await store.get_user_role_ids(user.id) == []  # the demotion is persisted
    finally:
        await store.close()


async def test_local_sessions_and_signed_out_users_are_never_probed() -> None:
    """Local accounts have no directory to coordinate with, and probing a directory user with no
    live session would be pure DC load for nothing."""
    store = await MessageStore.open(":memory:")
    try:
        ldap = _FakeLdap({"jdoe": _principal("jdoe"), "dormant": _principal("dormant")})
        service = AuthService(store, _ad_settings(), ldap=ldap)  # type: ignore[arg-type]
        await service.initialize()
        await service.create_local_user(
            username="alice", password=PW, display_name=None, email=None, roles=[], actor="test"
        )
        await store.create_user(user_id="dormant", username="dormant", auth_provider="ad")
        await _signed_in_ad_user(service, store, "jdoe")

        await service.reconcile_directory_sessions()
        assert ldap.probes == ["jdoe"]  # not alice (local), not dormant (no live session)
    finally:
        await store.close()


async def test_a_pass_never_exceeds_its_bind_budget() -> None:
    """Directory-load bound: a pass costs one bind per probed principal, so a large estate must
    degrade to a longer effective interval rather than a bind storm."""
    store = await MessageStore.open(":memory:")
    try:
        names = [f"user{i:02d}" for i in range(10)]
        ldap = _FakeLdap({n: _principal(n) for n in names})
        service = AuthService(
            store,
            _ad_settings(ad_session_recheck_max_users=3),
            ldap=ldap,  # type: ignore[arg-type]
        )
        await service.initialize()
        for name in names:
            await _signed_in_ad_user(service, store, name)

        plan = await service.reconcile_directory_sessions()
        assert plan.probed == 3 and len(ldap.probes) == 3
        # The next pass rotates onto users the first one did not reach.
        await service.reconcile_directory_sessions()
        assert len(set(ldap.probes)) == 6
    finally:
        await store.close()


async def test_disabled_by_default_does_nothing_at_all() -> None:
    store = await MessageStore.open(":memory:")
    try:
        ldap = _FakeLdap({"jdoe": _principal("jdoe")})
        service = AuthService(
            store,
            _ad_settings(ad_session_recheck_seconds=0),
            ldap=ldap,  # type: ignore[arg-type]
        )
        await service.initialize()
        token = await _signed_in_ad_user(service, store, "jdoe")
        ldap.present.clear()  # even a disabled account is left alone when the control is off

        assert service.directory_reconcile_enabled is False
        for _ in range(3):
            assert await service.reconcile_directory_sessions() == reconcile.ReconcilePlan()
        assert ldap.probes == []  # not one directory round trip: the reconciler never ran
        assert token is not None and await service.identity_for_token(token) is not None
    finally:
        await store.close()


async def test_reconcile_is_inert_without_a_directory() -> None:
    """A local-only deployment can never reach the reconciler, even if a knob were set."""
    store = await MessageStore.open(":memory:")
    try:
        service = AuthService(store, AuthSettings())
        await service.initialize()
        assert service.directory_reconcile_enabled is False
        assert await service.reconcile_directory_sessions() == reconcile.ReconcilePlan()
    finally:
        await store.close()
