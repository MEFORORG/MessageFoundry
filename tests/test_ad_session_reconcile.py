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

import json
import sqlite3
import uuid
from dataclasses import replace
from typing import Any

import pytest
from pydantic import ValidationError

from messagefoundry.auth import reconcile
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


def _object_id_for(username: str) -> str:
    """A stable synthetic ``objectGUID`` per account name, so a fixture need not carry one by hand.

    Derived from the name only for the fixture's convenience. **The engine must never do this** --
    the whole point of the id is that it does NOT move with the name (BACKLOG #1471). Where a test
    renames an account it passes the ORIGINAL account's id explicitly, which is what makes the rename
    a rename rather than a new account.
    """
    return str(uuid.uuid5(uuid.NAMESPACE_DNS, f"{username}.test.invalid"))


def _principal(username: str, *groups: str, object_id: str | None = None) -> AdPrincipal:
    """A directory principal, bound by default to this name's synthetic id.

    Pass ``object_id`` to model a RENAME -- the ORIGINAL account's id under a new name. For the
    directory that returns no readable ``objectGUID`` at all, use
    ``replace(_principal(...), directory_object_id=None)``: an explicit ``None`` here would be
    indistinguishable from the caller saying nothing, and that case has its own test.
    """
    return AdPrincipal(
        username=username,
        display_name=username.title(),
        email=f"{username}@test.invalid",
        dn=f"CN={username},OU=Staff,DC=test,DC=invalid",
        groups=frozenset(groups),
        directory_object_id=object_id or _object_id_for(username),
    )


class _FakeLdap:
    """A directory whose answers the test drives. ``present`` maps username -> principal; a username
    in ``unreachable`` raises :class:`LdapError` (the connectivity signal); anything else resolves to
    ``None`` — the real ``resolve_principal``'s ambiguous disabled/deleted/wrong-search-base answer.

    **``present`` is keyed on the directory's CURRENT name**, which is what makes a rename expressible:
    re-key the entry and keep the principal's ``directory_object_id``, and the name-keyed lookup misses
    exactly as a real directory's would while the id-keyed one still resolves.

    ``probes`` records the account each probe was ABOUT (the stored username), not the key it was
    issued on, so assertions about *which* accounts a pass reached read the same whichever key the
    reconciler used. ``probe_keys`` records the key, for the tests whose subject is the key itself
    (BACKLOG #1532).
    """

    def __init__(
        self, present: dict[str, AdPrincipal] | None = None, unreachable: set[str] | None = None
    ) -> None:
        self.present = present or {}
        self.unreachable = unreachable or set()
        self.probes: list[str] = []
        self.probe_keys: list[tuple[str, str]] = []

    def authenticate(self, username: str, password: str) -> AdPrincipal | None:
        # Login/step-up binds are deliberately NOT counted in ``probes``; that list measures the
        # reconciler's directory load only.
        return self._lookup(username)

    def resolve_principal(
        self, username: str, *, object_id: str | None = None
    ) -> AdPrincipal | None:
        self.probes.append(username)
        self.probe_keys.append(("object_id", object_id) if object_id else ("username", username))
        if username in self.unreachable:
            raise LdapError("synthetic: LDAP socket closed")
        if object_id is None:
            return self.present.get(username)
        return next((p for p in self.present.values() if p.directory_object_id == object_id), None)

    def _lookup(self, username: str) -> AdPrincipal | None:
        if username in self.unreachable:
            raise LdapError("synthetic: LDAP socket closed")
        return self.present.get(username)


async def _signed_in_ad_user(
    service: AuthService, store: MessageStore, username: str
) -> str | None:
    """Mint an AD-stamped session for ``username`` and return the token.

    These tests need an AD SESSION, never the simple-bind pathway that used to produce one -- that
    pathway is retired (BACKLOG #1137) and ``login(provider=AD)`` now refuses. They go through
    ``_complete_ad_login``, which is the shared tail of the surviving paths: Kerberos and OIDC both
    end here, and it is what stamps the session ``AuthProvider.AD``. Calling it directly avoids
    faking a SPNEGO token for a test whose subject is the reconciler, not the login mechanism.
    """
    ldap = service._ldap
    principal = ldap.resolve_principal(username)  # type: ignore[union-attr]
    assert principal is not None, f"the fake directory holds no principal for {username!r}"
    token = (await service._complete_ad_login(principal, None, mfa_verified=True)).token
    # Forget the SETUP probe. Several tests assert on `probes` to prove the reconciler did or did
    # not reach the directory, and a fixture that leaves its own round trip in that list makes the
    # instrument read the fixture instead of the subject.
    ldap.probes.clear()  # type: ignore[union-attr]
    return token


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


# --- BACKLOG #1532: a directory-side rename must not read as an offboarding ------------------------


async def test_a_directory_rename_keeps_the_account_its_sessions_and_its_single_row() -> None:
    """THE acceptance test for BACKLOG #1532, driven end to end over a real store.

    **The defect this pins, stated as a deploying site would have met it.** BACKLOG #1471 made a
    directory login resolve its row by the immutable ``objectGUID``, so a renamed person kept signing
    in. The reconciler went on probing ``resolve_principal(<the stored name>)``, which a renamed
    account no longer answers to, so every pass read ABSENT -- the same answer a deleted or disabled
    account gives. After ``ad_session_recheck_strikes`` passes the sessions were revoked and the holder
    was emailed a security notice; they signed back in, re-entered the candidate set, and were revoked
    again about five minutes later, with no administrative escape because nothing in the engine could
    write ``users.username``.

    Three assertions, because no two of them together are enough:

    1. the sessions survive an arbitrary number of passes (the revocation cycle is gone);
    2. exactly one directory row exists and its ``user_id`` never moved (uploads, the per-uploader
       quota and saved search presets stay pointed at the same person);
    3. the cached username follows the directory (what stops the probe going stale again).

    The loop runs well past the strike threshold on purpose: a fix that merely delayed the revocation
    would pass a single-pass assertion.
    """
    store = await MessageStore.open(":memory:")
    try:
        ldap = _FakeLdap({"jdoe": _principal("jdoe")})
        settings = _ad_settings()
        service = AuthService(store, settings, ldap=ldap)  # type: ignore[arg-type]
        await service.initialize()
        token = await _signed_in_ad_user(service, store, "jdoe")
        assert token is not None and await service.identity_for_token(token) is not None
        before = await store.get_user_by_username("jdoe")
        assert before is not None

        # THE RENAME. One account object: same objectGUID, new sAMAccountName. The directory stops
        # answering to the old name, which is exactly what re-keying the entry models.
        ldap.present = {
            "jdoe-married": _principal("jdoe-married", object_id=_object_id_for("jdoe"))
        }

        for _ in range(settings.ad_session_recheck_strikes + 3):
            plan = await service.reconcile_directory_sessions()
            assert plan.revocations == (), "a rename was read as an offboarding"
            assert plan.aborted is None

        assert await service.identity_for_token(token) is not None, "the session was revoked"

        ad_rows = [u for u in await store.list_users() if u.auth_provider == "ad"]
        assert len(ad_rows) == 1, "the rename minted a second row"
        assert ad_rows[0].id == before.id, "the account's user_id moved"
        assert ad_rows[0].username == "jdoe-married", (
            "the cached username did not follow the rename"
        )
        assert ad_rows[0].directory_object_id == _object_id_for("jdoe")
    finally:
        await store.close()


async def test_the_probe_is_keyed_on_the_immutable_id_when_the_row_carries_one() -> None:
    """The mechanism behind the test above, asserted directly rather than inferred from its effect.

    Without this, a fix that special-cased renames somewhere downstream would pass the acceptance test
    while leaving the probe keyed on a name -- so the next reader would not know which key the engine
    actually asks on.
    """
    store = await MessageStore.open(":memory:")
    try:
        ldap = _FakeLdap({"jdoe": _principal("jdoe")})
        service = AuthService(store, _ad_settings(), ldap=ldap)  # type: ignore[arg-type]
        await service.initialize()
        await _signed_in_ad_user(service, store, "jdoe")
        ldap.probe_keys.clear()

        await service.reconcile_directory_sessions()
        assert ldap.probe_keys == [("object_id", _object_id_for("jdoe"))]
    finally:
        await store.close()


async def test_a_row_with_no_immutable_id_still_probes_by_name() -> None:
    """The residual path, and it is a DIRECTORY's property rather than a choice here.

    A directory that returns no readable ``objectGUID`` leaves every row unbound, and the engine
    cannot key on an identifier it is never given. Such a site keeps the pre-#1471 behaviour, rename
    wart included; ``auth/ldap.py`` warns once per shape so an operator can find out. Asserted so the
    fallback is a stated arm rather than something a later change silently deletes.
    """
    store = await MessageStore.open(":memory:")
    try:
        ldap = _FakeLdap({"jdoe": replace(_principal("jdoe"), directory_object_id=None)})
        service = AuthService(store, _ad_settings(), ldap=ldap)  # type: ignore[arg-type]
        await service.initialize()
        await _signed_in_ad_user(service, store, "jdoe")
        row = await store.get_user_by_username("jdoe")
        assert row is not None and row.directory_object_id is None
        ldap.probe_keys.clear()

        await service.reconcile_directory_sessions()
        assert ldap.probe_keys == [("username", "jdoe")]
    finally:
        await store.close()


async def test_a_genuinely_absent_account_is_still_revoked_under_the_id_keyed_probe() -> None:
    """THE CONTROL ON THE FIX. Re-keying the probe must not disarm the security control it sits in.

    A fix that made every probe resolve -- by falling back to the name, or by treating a miss as
    PRESENT -- would pass every rename assertion above and quietly end ADR 0079 mechanism 2, so an AD
    disable would no longer terminate a live session inside one interval. This is the arm that fails
    if that happens, and it is the same shape as
    ``test_disabled_account_is_revoked_after_the_configured_strikes`` with the id-keyed probe named.
    """
    store = await MessageStore.open(":memory:")
    try:
        ldap = _FakeLdap({"jdoe": _principal("jdoe")})
        service = AuthService(store, _ad_settings(), ldap=ldap)  # type: ignore[arg-type]
        await service.initialize()
        token = await _signed_in_ad_user(service, store, "jdoe")
        assert token is not None

        ldap.present.clear()  # disabled in AD: the id resolves to nothing either

        assert (await service.reconcile_directory_sessions()).revocations == ()  # strike 1
        plan = await service.reconcile_directory_sessions()
        assert [r.username for r in plan.revocations] == ["jdoe"]
        assert await service.identity_for_token(token) is None
    finally:
        await store.close()


async def test_an_aborted_pass_applies_no_rename() -> None:
    """The plan-then-apply invariant covers renames too: an aborted pass writes nothing at all.

    The breaker exists because a mass ABSENT reading is indistinguishable from a bad search base. A
    pass that aborted its revocations but still wrote its renames would be applying half a plan built
    from evidence it had just decided not to trust.

    ``ad_session_recheck_strikes = 1`` so the abort and the rename land on the SAME pass. At the
    default of 2 the first pass revokes nothing, does not abort, and legitimately applies the rename --
    which is correct behaviour and tests nothing about the abort.
    """
    store = await MessageStore.open(":memory:")
    try:
        names = [f"u{i}" for i in range(8)]
        ldap = _FakeLdap({n: _principal(n) for n in names})
        settings = _ad_settings(ad_session_recheck_strikes=1)
        service = AuthService(store, settings, ldap=ldap)  # type: ignore[arg-type]
        await service.initialize()
        for n in names:
            await _signed_in_ad_user(service, store, n)

        # One account is renamed; every other account vanishes, which trips the breaker.
        ldap.present = {"u0-married": _principal("u0-married", object_id=_object_id_for("u0"))}
        plan = await service.reconcile_directory_sessions()
        assert plan.aborted == "mass_revoke_breaker"
        assert plan.renames == ()

        assert await store.get_user_by_username("u0") is not None, "an aborted pass wrote a rename"
        assert await store.get_user_by_username("u0-married") is None
    finally:
        await store.close()


async def test_a_rename_onto_a_name_another_row_holds_leaves_both_rows_alone() -> None:
    """``username`` is NOT NULL UNIQUE, so the reconciler cannot force a rename onto a taken name.

    This is BACKLOG #1471's recycle case arriving through the reconciler: a **departed** operator's
    MessageFoundry row was never deleted and still holds the name, and the directory has since given
    that name to somebody else, who is now renamed into it. The stale row holds no live session, so it
    is not even a candidate this pass -- the collision is with the store, not with the probe set.

    The refusal is audited and costs the renamed person nothing: they were identified by their
    immutable id, so the probe found them PRESENT and their sessions and roles are untouched. Only the
    display label stays stale, which is a display defect rather than a lockout.

    **The login path never reaches this branch**, because ``_complete_ad_login``'s #1471 conflict guard
    refuses first -- see the matching test in ``tests/test_ad_directory_identity.py``. The reconciler
    has no such guard, because it probes an account it has already identified, which is why the branch
    exists and is covered here.
    """
    store = await MessageStore.open(":memory:")
    try:
        ldap = _FakeLdap({"jdoe": _principal("jdoe")})
        service = AuthService(store, _ad_settings(), ldap=ldap)  # type: ignore[arg-type]
        await service.initialize()
        token = await _signed_in_ad_user(service, store, "jdoe")
        jdoe = await store.get_user_by_username("jdoe")
        assert jdoe is not None
        # The departed operator's row: still in the store, holding the name, with no live session.
        await store.create_user(user_id="departed-row", username="jbloggs", auth_provider="ad")

        # The directory renames jdoe onto the departed operator's name.
        ldap.present = {"jbloggs": _principal("jbloggs", object_id=_object_id_for("jdoe"))}
        plan = await service.reconcile_directory_sessions()
        assert plan.aborted is None
        assert plan.revocations == (), "a name collision must not revoke anybody"
        assert [(r.old_username, r.new_username) for r in plan.renames] == [("jdoe", "jbloggs")]

        # jdoe keeps its row, its id and its session; only the label stayed behind.
        still_jdoe = await store.get_user_by_directory_object_id(_object_id_for("jdoe"))
        assert still_jdoe is not None and still_jdoe.id == jdoe.id
        assert still_jdoe.username == "jdoe", "the refresh forced a name another row holds"
        assert await service.identity_for_token(token) is not None
        # The departed row is untouched.
        departed = await store.get_user_by_username("jbloggs")
        assert departed is not None and departed.id == "departed-row"
        audit = await store.list_audit()
        assert any(a["action"] == "auth.ad_username_refresh_conflict" for a in audit)
    finally:
        await store.close()


class _CapturingNotifier:
    """Collects the out-of-band security notices a pass sends, so a test can read WHO they named.

    The engine's notifier is ``None`` unless alerts are configured, and a swallowed notification is
    indistinguishable from one that named the wrong account -- which is exactly the failure under
    test here.
    """

    def __init__(self) -> None:
        self.sent: list[Any] = []

    async def notify(self, event: Any) -> None:
        self.sent.append(event)


async def test_a_rename_and_a_role_change_in_one_pass_record_one_consistent_name() -> None:
    """The apply ORDER, pinned: revocations run before renames, so one pass names an account once.

    ``_apply_reconcile_revocation`` audits with the name the PLAN captured and notifies with the name
    it RE-READS from the row. Those are the same string only while nothing has renamed the row in
    between -- so applying renames first would put the OLD name in the audit row and the NEW one in
    the security notice, for the same account, in the same pass.

    It is reachable whenever a directory renames an account and changes its group membership together,
    which is one administrative action at many sites (a marriage, a transfer between departments).
    Both records are read by a human reconstructing what happened to one person, and two names is
    exactly the evidence that makes that reconstruction wrong.

    The rename still lands on this pass -- only its position moved.
    """
    store = await MessageStore.open(":memory:")
    try:
        ldap = _FakeLdap({"jdoe": _principal("jdoe", "cn=mf-admins,dc=test,dc=invalid")})
        service = AuthService(store, _ad_settings(), ldap=ldap)  # type: ignore[arg-type]
        notifier = _CapturingNotifier()
        service._security_notifier = notifier  # type: ignore[assignment]
        await service.initialize()
        await service.set_ad_group_map([("cn=mf-admins,dc=test,dc=invalid", "operator")], actor="t")
        token = await _signed_in_ad_user(service, store, "jdoe")
        assert token is not None
        before = await store.get_user_by_username("jdoe")
        assert before is not None and await store.get_user_role_ids(before.id) != []

        # One directory action: renamed AND dropped out of the role-granting group.
        ldap.present = {
            "jdoe-married": _principal("jdoe-married", object_id=_object_id_for("jdoe"))
        }
        plan = await service.reconcile_directory_sessions()
        assert [(r.username, r.reason) for r in plan.revocations] == [("jdoe", "roles_changed")]
        assert [(r.old_username, r.new_username) for r in plan.renames] == [
            ("jdoe", "jdoe-married")
        ]

        revoked = [a for a in await store.list_audit() if a["action"] == "auth.ad_session_revoked"]
        assert len(revoked) == 1
        # THE ASSERTION THIS TEST EXISTS FOR: the audit row and the notice agree. Both say the name
        # the account had when the pass began, because the rename had not been applied yet.
        assert revoked[0]["actor"] == "jdoe"
        # Every notice this pass sent names the SAME account the audit row named. A count is the
        # wrong instrument here -- the login and the group-map change send their own notices, and
        # asserting "exactly one" would fail for a reason that has nothing to do with the ordering.
        assert {e.username for e in notifier.sent} == {"jdoe"}, (
            "a security notice named a different account than the audit row"
        )

        # And the rename still landed on this same pass.
        after = await store.get_user(before.id)
        assert after is not None and after.username == "jdoe-married"
    finally:
        await store.close()


# --- BACKLOG #1532: the residual race the store's in-statement guard cannot close ------------------


def _driver_integrity_errors() -> list[tuple[str, Exception]]:
    """One real integrity exception per installed backend driver, for the absorb's MRO predicate.

    **Constructed from the ACTUAL driver classes, never a stand-in.** The predicate is a string test
    over the MRO, so a hand-rolled `class FakeIntegrityError(Exception)` would pass it by virtue of
    its own name and prove nothing about asyncpg or pyodbc. Missing extras are skipped rather than
    faked -- a skipped arm is honest, a faked one is a green that means nothing.
    """
    out: list[tuple[str, Exception]] = [("sqlite3", sqlite3.IntegrityError("dup"))]
    try:
        import asyncpg

        # THE ONE THAT MATTERS. asyncpg's hierarchy contains NO class named `IntegrityError` -- it is
        # UniqueViolationError -> IntegrityConstraintViolationError -> PostgresError. A predicate
        # tightened from "Integrity" to "IntegrityError" would miss PostgreSQL, which is the backend
        # where the race was measured firing 60% of contended pairs.
        out.append(("asyncpg", asyncpg.UniqueViolationError("dup")))
    except ImportError:  # pragma: no cover - the postgres extra is not installed
        pass
    try:
        import pyodbc

        out.append(("pyodbc", pyodbc.IntegrityError("23000", "dup")))
    except ImportError:  # pragma: no cover - the sqlserver extra is not installed
        pass
    return out


@pytest.mark.parametrize(
    ("driver", "error"), _driver_integrity_errors(), ids=lambda v: v if isinstance(v, str) else ""
)
async def test_every_backend_integrity_class_is_absorbed(driver: str, error: Exception) -> None:
    """The absorb's predicate, against EVERY installed driver's real integrity class.

    The handler tests `"Integrity" in mro or "UniqueViolation" in mro`. Those two strings were chosen
    from measurement, not taste, and the choice is invisible in the code: `"IntegrityError"` reads
    like the obvious tightening and would silently drop PostgreSQL. This is the arm that reddens if
    anyone makes it.

    It matters beyond this method: the same two strings are the predicate at the ADR 0068 section 4
    duplicate-label race and the BACKLOG #1256 federated-subject bind, so a tightening "fix" applied
    across all three would break PostgreSQL coverage at every one of them.
    """
    store = await MessageStore.open(":memory:")
    try:
        ldap = _FakeLdap({"jdoe": _principal("jdoe")})
        service = AuthService(store, _ad_settings(), ldap=ldap)  # type: ignore[arg-type]
        await service.initialize()
        token = await _signed_in_ad_user(service, store, "jdoe")
        assert token is not None

        async def _raise_driver_error(*a: object, **kw: object) -> None:
            await store.create_user(user_id="winner", username="jbloggs", auth_provider="ad")
            raise error

        store.set_user_username = _raise_driver_error  # type: ignore[method-assign]

        ldap.present = {"jbloggs": _principal("jbloggs", object_id=_object_id_for("jdoe"))}
        plan = await service.reconcile_directory_sessions()

        assert plan.aborted is None, f"{driver}'s integrity class was not absorbed"
        assert await service.identity_for_token(token) is not None
        rows = [
            a
            for a in await store.list_audit()
            if a["action"] == "auth.ad_username_refresh_conflict"
        ]
        assert len(rows) == 1 and json.loads(rows[0]["detail"])["detected"] == "write_race"
    finally:
        await store.close()


async def test_a_lost_username_race_is_absorbed_and_does_not_kill_the_pass() -> None:
    """The store guard NARROWS the check-then-act window; it does not close it, so this absorbs it.

    **Measured on live PostgreSQL 16 by another session, not reasoned about here.** Under READ
    COMMITTED the guard's ``NOT EXISTS`` subquery evaluates against the snapshot at its own statement
    start, so it cannot see a concurrent UNCOMMITTED claim on the same name: the guard passes, the
    write blocks on ``UNIQUE(username)``, and it raises the moment the other transaction commits. An
    earlier version of this code claimed a single statement made that impossible, in five separate
    comments. It does not -- a statement is atomic against COMMITTED data, which is weaker.

    **Why absorbing it matters more here than at the two sibling sites.** ADR 0068 section 4's
    duplicate-label race and BACKLOG #1256's federated-subject bind each cost ONE request a 500. This
    caller is the reconciler's apply loop, so an unabsorbed integrity error aborts the whole pass --
    and every OTHER account's revocation in it. A cosmetic label collision would become a missed
    directory disable, which is the security control this subsystem exists to provide.

    The raise is a REAL ``sqlite3.IntegrityError``, so the MRO-by-name test in the handler is
    exercised against a genuine integrity class rather than a stand-in that happens to match.
    """
    store = await MessageStore.open(":memory:")
    try:
        ldap = _FakeLdap({"jdoe": _principal("jdoe")})
        service = AuthService(store, _ad_settings(), ldap=ldap)  # type: ignore[arg-type]
        await service.initialize()
        token = await _signed_in_ad_user(service, store, "jdoe")
        assert token is not None
        jdoe = await store.get_user_by_username("jdoe")
        assert jdoe is not None

        # THE INTERLEAVE, modelled where it actually happens: the holder must NOT exist when the
        # caller's pre-check runs, and must exist by the time the write lands. Creating it up front
        # instead makes the pre-check fire and the write path is never reached -- which is how the
        # first draft of this test passed for the wrong reason.
        async def _raise_integrity(*a: object, **kw: object) -> None:
            await store.create_user(user_id="winner", username="jbloggs", auth_provider="ad")
            raise sqlite3.IntegrityError("UNIQUE constraint failed: users.username")

        store.set_user_username = _raise_integrity  # type: ignore[method-assign]

        ldap.present = {"jbloggs": _principal("jbloggs", object_id=_object_id_for("jdoe"))}
        plan = await service.reconcile_directory_sessions()

        # THE PASS SURVIVED. This is the assertion the whole absorb exists for.
        assert plan.aborted is None
        assert plan.revocations == ()
        assert [(r.old_username, r.new_username) for r in plan.renames] == [("jdoe", "jbloggs")]

        # The renamed account is untouched: same row, same session, stale label only.
        still = await store.get_user(jdoe.id)
        assert still is not None and still.username == "jdoe"
        assert await service.identity_for_token(token) is not None

        # Audited as the SAME outcome the pre-check produces, with the discriminator recorded.
        rows = [
            a
            for a in await store.list_audit()
            if a["action"] == "auth.ad_username_refresh_conflict"
        ]
        assert len(rows) == 1
        detail = json.loads(rows[0]["detail"])
        assert detail["detected"] == "write_race"
        assert detail["held_by_user_id"] == "winner", "the audit did not name the race winner"
    finally:
        await store.close()


async def test_a_store_fault_that_is_not_an_integrity_violation_still_propagates() -> None:
    """THE NEGATIVE CONTROL on the absorb, and without it the handler is a bare except.

    Swallowing every exception from the write would turn a real store fault -- a closed connection, a
    disk error, a driver bug -- into a silent no-op that audits `refresh_conflict` and reports a
    healthy pass. The MRO test is what keeps the absorb narrow, and this is the arm that fails if
    someone widens it.
    """
    store = await MessageStore.open(":memory:")
    try:
        ldap = _FakeLdap({"jdoe": _principal("jdoe")})
        service = AuthService(store, _ad_settings(), ldap=ldap)  # type: ignore[arg-type]
        await service.initialize()
        await _signed_in_ad_user(service, store, "jdoe")

        async def _raise_other(*a: object, **kw: object) -> None:
            raise RuntimeError("synthetic: the store connection died")

        store.set_user_username = _raise_other  # type: ignore[method-assign]

        ldap.present = {
            "jdoe-married": _principal("jdoe-married", object_id=_object_id_for("jdoe"))
        }
        with pytest.raises(RuntimeError, match="the store connection died"):
            await service.reconcile_directory_sessions()
    finally:
        await store.close()


async def test_a_name_keyed_probe_never_plans_a_rename() -> None:
    """A NAME-keyed probe must not report a rename, because its question can name another principal.

    **This is a takeover, not a tidiness rule.** On the residual path -- a directory whose
    ``objectGUID`` the bind account cannot read, so every row is unbound -- ``_find_user`` searches
    ``(|(sAMAccountName=<name>)(userPrincipalName=<name>@<domain>))`` and takes ``entries[0]``. An
    account that can set its own ``userPrincipalName`` to the victim's ``<name>@<domain>`` matches the
    same filter, so on a pass where the directory returns that entry first the probe reports the
    ATTACKER's ``sAMAccountName`` as this row's new name.

    Without this gate the refresh would write that name onto the victim's row -- moving the only key
    an unbound login path has onto the attacker's label. The attacker's next sign-in then resolves to
    the victim's ``user_id``: both ids are NULL, so BACKLOG #1471's conflict guard compares ``None``
    to ``None``, passes, and hands over the victim's uploaded files, quota and saved presets. That is
    the privilege transfer #1471 exists to close, arriving on the rows #1471 could not bind.

    The UPN ambiguity is older than #1532 and is not fixed here. What #1532 must not do is make the
    wrong answer PERSISTENT, so an unbound row is left on genuinely unchanged behaviour.
    """
    store = await MessageStore.open(":memory:")
    try:
        # Unbound: the directory returns no readable objectGUID, so the row carries none.
        ldap = _FakeLdap({"jdoe": replace(_principal("jdoe"), directory_object_id=None)})
        service = AuthService(store, _ad_settings(), ldap=ldap)  # type: ignore[arg-type]
        await service.initialize()
        token = await _signed_in_ad_user(service, store, "jdoe")
        assert token is not None
        victim = await store.get_user_by_username("jdoe")
        assert victim is not None and victim.directory_object_id is None

        # The name-keyed probe now resolves to a DIFFERENT principal -- what a UPN collision does.
        ldap.present = {"jdoe": replace(_principal("mallory"), directory_object_id=None)}
        plan = await service.reconcile_directory_sessions()

        assert plan.renames == (), "a name-keyed probe planned a rename"
        still = await store.get_user(victim.id)
        assert still is not None and still.username == "jdoe", (
            "the victim's row took the name the ambiguous probe reported"
        )
    finally:
        await store.close()


async def test_an_unchanged_name_plans_no_rename() -> None:
    """THE MUST-NOT-FIRE ARM. Every other rename test asserts a refresh HAPPENED.

    Without this, an implementation that planned a `UsernameRefresh` on every PRESENT probe -- whether
    or not the name moved -- would pass all of them, and would write to `users.username` once per
    account per pass forever, audit `auth.ad_username_refreshed` every 300 seconds per signed-in user,
    and bury any real rename in the noise. A control that fires on everything reports nothing.
    """
    store = await MessageStore.open(":memory:")
    try:
        ldap = _FakeLdap({"jdoe": _principal("jdoe")})
        service = AuthService(store, _ad_settings(), ldap=ldap)  # type: ignore[arg-type]
        await service.initialize()
        await _signed_in_ad_user(service, store, "jdoe")

        for _ in range(3):  # the directory says the same name every pass
            plan = await service.reconcile_directory_sessions()
            assert plan.renames == (), "an unchanged name planned a refresh"

        assert not [
            a for a in await store.list_audit() if a["action"] == "auth.ad_username_refreshed"
        ], "an unchanged name audited a refresh"
    finally:
        await store.close()
