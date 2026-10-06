# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
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

import asyncio
import json
import logging
import sqlite3
import uuid
from dataclasses import replace
from typing import Any

import pytest
from pydantic import ValidationError

from messagefoundry.auth import channel_scope, reconcile
from messagefoundry.auth.identity import SessionMechanism
from messagefoundry.auth.ldap import AdPrincipal, DirectoryAnswer, DirectoryProbe, LdapError
from messagefoundry.auth.notifications import USERNAME_CHANGED
from messagefoundry.auth.permissions import Role
from messagefoundry.auth.service import AuthService, DirectoryObjectIdMissing
from messagefoundry.config.settings import AuthSettings
from messagefoundry.store.crypto import CipherError
from messagefoundry.store.store import (
    SCOPE_SOURCE_AD,
    SCOPE_SOURCE_MANUAL,
    MessageStore,
    UserRecord,
)
from tests._admin_account import create_local_user_chosen

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

    def authenticate(self, username: str, password: str, **_: object) -> AdPrincipal | None:
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

    def probe_principal(self, username: str, *, object_id: str | None = None) -> DirectoryProbe:
        # The reconciler's lookup (ADR 0195). This double models no disabled or unreadable entry, so
        # every refusal is a search that matched nothing; tests/test_ad_user_account_control.py drives
        # the other answers through the REAL authenticator.
        principal = self.resolve_principal(username, object_id=object_id)
        if principal is None:
            return DirectoryProbe(DirectoryAnswer.NOT_FOUND)
        return DirectoryProbe(DirectoryAnswer.FOUND, principal)

    def _lookup(self, username: str) -> AdPrincipal | None:
        if username in self.unreachable:
            raise LdapError("synthetic: LDAP socket closed")
        return self.present.get(username)


async def _clear_directory_object_id(store: MessageStore, username: str) -> None:
    """Plant the legacy state: a directory row whose ``directory_object_id`` is NULL.

    No engine path writes one any more (BACKLOG #2027), so the store is edited directly."""
    await store._db.execute(
        "UPDATE users SET directory_object_id = NULL WHERE username = ?", (username,)
    )
    await store._db.commit()


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
    # A row that holds a federated binding signs in the federated way: Windows SSO refuses it,
    # and a bind ends the sessions it held (vault BACKLOG #2609). Same shared tail, minted as the
    # federated caller mints it.
    row = await store.get_user_by_username(username)
    how: dict[str, Any] = {}
    if row is not None and row.oidc_issuer is not None and row.oidc_subject is not None:
        how = {
            "session_mechanism": SessionMechanism.OIDC,
            "mech": "oidc",
            "federated_subject": (row.oidc_issuer, row.oidc_subject),
        }
    if principal.directory_object_id is None:
        # BACKLOG #2027: a sign-in no longer mints a row with no id, so a principal with none is
        # refused. The id-less row these tests need is one made before that refusal, or planted in
        # the store. So sign in with the name's synthetic id and then clear the column, which leaves
        # exactly that row behind a live session. A row already planted id-less is keyed for the
        # sign-in first, or the sign-in would refuse it: the fixture wants a session, not a login.
        object_id = _object_id_for(username)
        await store._db.execute(
            "UPDATE users SET directory_object_id = ? WHERE username = ?", (object_id, username)
        )
        await store._db.commit()
        keyed = replace(principal, directory_object_id=object_id)
        token = (await service._complete_ad_login(keyed, None, mfa_verified=True, **how)).token
        await _clear_directory_object_id(store, username)
        ldap.probes.clear()  # type: ignore[union-attr]
        return token
    token = (await service._complete_ad_login(principal, None, mfa_verified=True, **how)).token
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
    reconcile.prune_ledger(ledger, ["u1"], rank=float)
    assert ledger == {"u1": 2}


# --- ADR 0195: the undetermined-wave hold, in the pure layer -----------------------------------

U = reconcile.ProbeOutcome.UNDETERMINED
P = reconcile.ProbeOutcome.PRESENT


def _plan(
    probes: list[reconcile.Probe],
    *,
    prior_strikes: dict[str, int] | None = None,
    prior_outcomes: dict[str, reconcile.ProbeOutcome] | None = None,
    latched: bool = False,
) -> reconcile.ReconcilePlan:
    return reconcile.plan_pass(
        probes,
        prior_strikes=prior_strikes or {},
        current_roles={},
        target_roles={},
        strike_threshold=2,
        max_absolute=5,
        max_fraction=0.34,
        prior_outcomes=prior_outcomes,
        latched=latched,
    )


@pytest.mark.parametrize(
    ("u", "r", "latched", "held", "latches"),
    [
        (0, 5, False, False, False),
        (1, 5, False, False, False),  # the one case a single undetermined answer may revoke
        (1, 0, False, True, False),  # a lone one with nothing readable beside it: held, not latched
        (2, 5, False, True, True),  # the count of one is exceeded: a wave, which latches
        (1, 5, True, True, True),  # hysteresis: once a wave latched, one is still held
        (0, 0, True, False, False),  # released only at zero
    ],
)
def test_the_hold_rule(u: int, r: int, latched: bool, held: bool, latches: bool) -> None:
    assert reconcile.hold_engaged(undetermined=u, readable=r, latched=latched) is held
    assert reconcile.hold_latches(undetermined=u, latched=latched) is latches


def test_a_lone_account_held_for_want_of_a_readable_answer_strikes_once_one_appears() -> None:
    """ADR 0195: a lone undetermined account "starts striking once a pass also reads a readable
    account". Here one pass reads nothing else (the directory answered for that account alone), and
    the next reads the others again. The lone hold must not latch, or the genuine single would be
    held to the absolute session cap."""
    others = [reconcile.Probe(f"ok{i}", f"ok{i}", P) for i in range(4)]
    flapped = [replace(p, outcome=reconcile.ProbeOutcome.UNAVAILABLE) for p in others]
    x = reconcile.Probe("x", "x", U)
    held = _plan([x, *flapped], prior_strikes={"x": 1})
    assert held.hold and not held.latched and held.strikes["x"] == 0
    struck = _plan([x, *others], prior_strikes=dict(held.strikes), latched=held.latched)
    assert not struck.hold and struck.strikes["x"] == 1
    revoked = _plan([x, *others], prior_strikes=dict(struck.strikes), latched=struck.latched)
    assert [(r.user_id, r.reason) for r in revoked.revocations] == [("x", "directory_undetermined")]


def test_while_held_an_undetermined_accounts_strike_count_does_not_accrue() -> None:
    """AC-6, with rule item 7's reset. A held account's strike never climbs toward revocation: a
    count it carried in from before the hold goes back to 0, and one at 0 stays at 0."""
    probes = [
        reconcile.Probe("u1", "a", U),
        reconcile.Probe("u2", "b", U),
        reconcile.Probe("ok", "c", P),
    ]
    strikes = {"u1": 1}
    for _ in range(5):
        plan = _plan(probes, prior_strikes=strikes, latched=True)
        assert plan.hold and sorted(plan.held) == ["u1", "u2"] and plan.revocations == ()
        assert plan.strikes == {"u1": 0, "u2": 0, "ok": 0}
        strikes = dict(plan.strikes)


def test_an_unavailable_probe_leaves_the_prior_outcome_in_place() -> None:
    """Rule item 4: a directory blip on one held account must not make the other look single."""
    probes = [
        reconcile.Probe("u1", "a", U),
        reconcile.Probe("u2", "b", reconcile.ProbeOutcome.UNAVAILABLE),
        reconcile.Probe("ok", "c", P),
    ]
    plan = _plan(probes, prior_outcomes={"u1": U, "u2": U})
    assert plan.hold and plan.undetermined == 2 and plan.held == ("u1",)
    assert "u2" not in plan.outcomes and plan.outcomes["u1"] is U


def test_held_probes_are_left_out_of_the_breakers_count() -> None:
    """Rule item 7. Six absent accounts beside 94 held ones: counted over all 100 the breaker would
    pass six (not over 34). Counted over the six it could revoke, it trips."""
    held = [reconcile.Probe(f"h{i}", f"h{i}", U) for i in range(94)]
    gone = [reconcile.Probe(f"g{i}", f"g{i}", reconcile.ProbeOutcome.ABSENT) for i in range(6)]
    plan = _plan(held + gone, prior_strikes={p.user_id: 1 for p in gone})
    assert plan.aborted == "mass_revoke_breaker" and plan.hold and len(plan.held) == 94
    assert plan.outcomes and plan.undetermined == 94  # the hold survives the abort


def test_an_outage_carries_the_hold_state_and_judges_nothing() -> None:
    down = [reconcile.Probe("u1", "a", reconcile.ProbeOutcome.UNAVAILABLE)]
    for latched in (True, False):
        plan = _plan(down, prior_outcomes={"u1": U, "u2": U}, latched=latched)
        assert plan.directory_outage and not plan.hold and plan.latched is latched


def test_the_outcome_record_caps_undetermined_entries_last() -> None:
    assert reconcile.outcome_rank(U) > reconcile.outcome_rank(P)
    ledger = {"u1": U, "u2": P}
    reconcile.prune_ledger(ledger, ["u1"], rank=reconcile.outcome_rank)
    assert ledger == {"u1": U}


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
        await create_local_user_chosen(
            service,
            username="alice",
            password=PW,
            display_name=None,
            email=None,
            roles=[],
            actor="test",
        )
        await store.create_user(
            user_id="dormant", username="dormant", auth_provider="ad", password_generated=False
        )
        await _signed_in_ad_user(service, store, "jdoe")

        await service.reconcile_directory_sessions()
        assert ldap.probes == ["jdoe"]  # not alice (local), not dormant (no live session)
    finally:
        await store.close()


async def test_a_map_edit_revokes_rows_the_clock_calls_expired() -> None:
    """BACKLOG #2283: an AD map edit revokes directory sessions so it applies at once. It used to
    revoke only an account that ``list_sessions`` found a row for, and that read filters on the
    wall clock, so after a forward step past the absolute lifetime it revoked nothing. Those rows
    would validate again on the OLD mapping once the clock was set right. Here the row is past its
    expiry by the clock and still unrevoked; the edit must revoke it."""
    import time

    store = await MessageStore.open(":memory:")
    try:
        service = AuthService(store, _ad_settings(), ldap=_FakeLdap())  # type: ignore[arg-type]
        await service.initialize()
        now = time.time()
        await store.create_user(
            user_id="stepped", username="stepped", auth_provider="ad", password_generated=False
        )
        await store.create_session(
            token_hash="stepped-hash", user_id="stepped", expires_at=now - 60, now=now - 120
        )

        await service.set_ad_group_map([("cn=ops", Role.OPERATOR.value)], actor="test")

        row = await store.get_session("stepped-hash")
        assert row is not None and row.revoked_at is not None, (
            "a map edit left a row unrevoked because the clock said it had expired"
        )
    finally:
        await store.close()


async def test_a_user_whose_only_session_is_idle_is_still_probed() -> None:
    """BACKLOG #2283: an idle session can come back, after a backward clock step or a raised idle
    setting, so the reconciler keeps probing its account. Skipping it would let a disabled account
    escape the strikes until its session revived. A session inside the idle window is the control."""
    import time

    store = await MessageStore.open(":memory:")
    try:
        ldap = _FakeLdap({"idler": _principal("idler"), "active": _principal("active")})
        service = AuthService(store, _ad_settings(), ldap=ldap)  # type: ignore[arg-type]
        await service.initialize()
        idle = service.session_idle_seconds
        now = time.time()
        for username, last_used in (("idler", now - idle - 60), ("active", now - idle + 60)):
            await store.create_user(
                user_id=username, username=username, auth_provider="ad", password_generated=False
            )
            await store.create_session(
                token_hash=f"{username}-hash",
                user_id=username,
                expires_at=now + 3600,
                now=last_used,
            )

        await service.reconcile_directory_sessions()
        assert sorted(ldap.probes) == ["active", "idler"], (
            "an account holding only an idle session was skipped, though that session can revive"
        )
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

    The loop runs past the strike threshold because a fix that merely DELAYED the revocation would
    pass a single-pass assertion. **But the loop count is not what makes this hold, and no finite
    count could be.** The mechanism is: ``plan_pass`` sets ``strikes[user_id] = 0`` for every PRESENT
    probe, so an account the directory keeps answering for can never accrue a strike at all. The loop
    is a check that the mechanism is wired, not the evidence that it works -- which is the difference
    between "I ran five passes and nothing happened" and "nothing can happen".

    Worth stating because the alternative reading invites raising the count when someone gets nervous,
    and a bigger number would look like more rigour while proving exactly as much.
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

    A row with no ``objectGUID`` gives the engine no identifier to key on. No sign-in mints such a
    row since BACKLOG #2027, which refuses a principal with no id, so this is a row made before that
    or planted in the store (the fixture plants it). The pass keeps the pre-#1471 behaviour for it,
    rename wart included. Asserted so the fallback is a stated arm rather than something a later
    change silently deletes.
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


async def test_ac5_a_federated_binding_only_lands_on_a_row_the_probe_keys_by_id() -> None:
    """ADR 0184 AC-5, held by construction (BACKLOG #1143 slice C).

    A bound row must never be re-resolved from its username, or a reissued name would hand the
    pair's holder the new person's groups. The name-keyed probe above is still there for a row with
    no id, so AC-5 holds only if no such row can be bound. One row is made by a real directory
    sign-in through a directory answering with objectGUID. The other is id-less, which no sign-in
    makes since BACKLOG #2027, so the fixture plants it. The id-less row refuses the bind. Then one pass: the bound row is probed by
    its id, and the only name-keyed probe is the unbound row's.

    The pass assertion is the one that discriminates: without the refusal the second bind lands,
    and the pass then probes a BOUND row by name. So the refusal is caught rather than asserted
    first, which lets that assertion be reached either way.
    """
    store = await MessageStore.open(":memory:")
    try:
        ldap = _FakeLdap(
            {
                "jdoe": _principal("jdoe"),
                "nobody": replace(_principal("nobody"), directory_object_id=None),
            }
        )
        settings = _ad_settings(oidc_issuer="https://idp.test.invalid")
        service = AuthService(store, settings, ldap=ldap)  # type: ignore[arg-type]
        await service.initialize()
        await _signed_in_ad_user(service, store, "jdoe")
        await _signed_in_ad_user(service, store, "nobody")
        jdoe = await store.get_user_by_username("jdoe")
        nobody = await store.get_user_by_username("nobody")
        assert jdoe is not None and jdoe.directory_object_id == _object_id_for("jdoe")
        assert nobody is not None and nobody.directory_object_id is None

        await service.bind_federated_subject(
            jdoe.id, "S-1-jdoe", expected_issuer=None, expected_subject=None, actor="admin"
        )
        refused = False
        try:
            await service.bind_federated_subject(
                nobody.id, "S-1-nobody", expected_issuer=None, expected_subject=None, actor="admin"
            )
        except DirectoryObjectIdMissing:
            refused = True
        # The bind ended jdoe's session, and the pass asks only about accounts that hold one.
        assert await _signed_in_ad_user(service, store, "jdoe") is not None

        ldap.probe_keys.clear()
        await service.reconcile_directory_sessions()

        bound = {u.username for u in await store.list_users() if u.oidc_subject is not None}
        # AC-5 ITSELF: no bound row was asked about by name.
        assert [key for key in ldap.probe_keys if key[0] == "username" and key[1] in bound] == []
        # CONTROL: the pass did probe by name -- the unbound id-less row -- so the check above had
        # a name-keyed probe to find, and the bound row was probed by its id.
        assert sorted(ldap.probe_keys) == [
            ("object_id", _object_id_for("jdoe")),
            ("username", "nobody"),
        ]
        assert refused and bound == {"jdoe"}
    finally:
        await store.close()


async def test_ac5_a_bound_row_with_no_id_is_skipped_not_probed_by_name() -> None:
    """ADR 0184 AC-5 for the binding slice C does not reach (BACKLOG #2027).

    ``legacy`` is bound while carrying no id, the state a binding made before slice C is in; it is
    planted through the store, because the bind now refuses it. Its only directory key is its
    name, so the pass must not ask about it at all. It is skipped the way an account the pass cannot
    ask about is skipped: its session is left alone, not revoked, and the skip is audited once.

    Two controls share the pass. An id-bearing bound row is still probed by its id, and an UNBOUND
    id-less row is still probed by name, so the name-keyed arm is narrowed to exactly the bound
    rows rather than switched off.
    """
    store = await MessageStore.open(":memory:")
    try:
        ldap = _FakeLdap(
            {
                "jdoe": _principal("jdoe"),
                "nobody": replace(_principal("nobody"), directory_object_id=None),
                "legacy": replace(_principal("legacy"), directory_object_id=None),
            }
        )
        settings = _ad_settings(oidc_issuer="https://idp.test.invalid")
        service = AuthService(store, settings, ldap=ldap)  # type: ignore[arg-type]
        await service.initialize()
        await _signed_in_ad_user(service, store, "jdoe")
        await _signed_in_ad_user(service, store, "nobody")
        await _signed_in_ad_user(service, store, "legacy")
        jdoe = await store.get_user_by_username("jdoe")
        legacy = await store.get_user_by_username("legacy")
        assert jdoe is not None and legacy is not None and legacy.directory_object_id is None
        await service.bind_federated_subject(
            jdoe.id, "S-1-jdoe", expected_issuer=None, expected_subject=None, actor="admin"
        )
        with pytest.raises(DirectoryObjectIdMissing):
            await service.bind_federated_subject(
                legacy.id, "S-1-legacy", expected_issuer=None, expected_subject=None, actor="admin"
            )
        assert (
            await store.set_user_federated_subject(
                legacy.id, "https://idp.test.invalid", "S-1-legacy"
            )
            is not None
        )
        # Each bind ended its account's session, so both sign in again, as bound accounts do.
        assert await _signed_in_ad_user(service, store, "jdoe") is not None
        token = await _signed_in_ad_user(service, store, "legacy")
        ldap.present.pop("legacy")  # gone from the directory: a name probe would strike it

        ldap.probe_keys.clear()
        for _ in range(3):  # past the strike threshold, so a name probe would have revoked
            plan = await service.reconcile_directory_sessions()
            assert plan.aborted is None and plan.revocations == ()

        assert ("username", "legacy") not in ldap.probe_keys
        assert sorted(set(ldap.probe_keys)) == [
            ("object_id", _object_id_for("jdoe")),
            ("username", "nobody"),
        ]
        assert token is not None and await service.identity_for_token(token) is not None
        skipped = [
            json.loads(a["detail"])
            for a in await store.list_audit()
            if a["action"] == "auth.ad_reconcile_binding_unkeyed"
        ]
        assert skipped == [
            {"reason": "directory_object_id_missing", "user_id": legacy.id, "username": "legacy"}
        ], "the skip was not audited, or was audited on every pass"
    finally:
        await store.close()


async def test_a_pass_whose_only_candidate_is_a_bound_id_less_row_is_not_an_outage() -> None:
    """The skipped row is filtered before probing, not answered as UNAVAILABLE (BACKLOG #2027).

    As an UNAVAILABLE probe it would be the pass's only probe, and a pass whose every probe failed
    aborts as ``directory_unavailable`` and audits an outage the directory is not having.
    """
    store = await MessageStore.open(":memory:")
    try:
        ldap = _FakeLdap({"legacy": replace(_principal("legacy"), directory_object_id=None)})
        service = AuthService(store, _ad_settings(), ldap=ldap)  # type: ignore[arg-type]
        await service.initialize()
        await _signed_in_ad_user(service, store, "legacy")
        legacy = await store.get_user_by_username("legacy")
        assert legacy is not None
        assert (
            await store.set_user_federated_subject(
                legacy.id, "https://idp.test.invalid", "S-1-legacy"
            )
            is not None
        )
        # The bind ended the session above, so the bound row signs in again.
        assert await _signed_in_ad_user(service, store, "legacy") is not None
        ldap.probe_keys.clear()

        plan = await service.reconcile_directory_sessions()

        assert plan.aborted is None and plan.probed == 0
        assert ldap.probe_keys == []
        details = [
            json.loads(a["detail"])
            for a in await store.list_audit()
            if a["action"] == "auth.ad_reconcile_binding_unkeyed"
        ]
        assert [d["reason"] for d in details] == ["directory_object_id_missing"]
        assert not any(a["action"] == "auth.ad_reconcile_skipped" for a in await store.list_audit())
    finally:
        await store.close()


async def test_an_unkeyed_binding_is_reported_once_per_process_across_sign_ins() -> None:
    """The once-per-process mark survives a gap with no session, and ends with the binding.

    A mark kept only for signed-in rows would drop whenever the sessions lapse, and the account
    would be reported again on its next sign-in. After the unbind the row is ordinary again, so its
    mark goes, and the pass probes it by name like any unbound id-less row.
    """
    store = await MessageStore.open(":memory:")
    try:
        ldap = _FakeLdap({"legacy": replace(_principal("legacy"), directory_object_id=None)})
        settings = _ad_settings(oidc_issuer="https://idp.test.invalid")
        service = AuthService(store, settings, ldap=ldap)  # type: ignore[arg-type]
        await service.initialize()
        await _signed_in_ad_user(service, store, "legacy")
        legacy = await store.get_user_by_username("legacy")
        assert legacy is not None
        assert (
            await store.set_user_federated_subject(
                legacy.id, "https://idp.test.invalid", "S-1-legacy"
            )
            is not None
        )
        # The bind ended the session above, so the bound row signs in again.
        assert await _signed_in_ad_user(service, store, "legacy") is not None

        async def reported() -> int:
            return sum(
                a["action"] == "auth.ad_reconcile_binding_unkeyed" for a in await store.list_audit()
            )

        await service.reconcile_directory_sessions()
        await store.revoke_user_sessions(legacy.id)
        await service.reconcile_directory_sessions()  # no session: not a candidate at all
        assert await _signed_in_ad_user(service, store, "legacy") is not None
        await service.reconcile_directory_sessions()
        assert await reported() == 1, "the account was reported again after a sign-in"

        await service.unbind_federated_subject(
            legacy.id,
            expected_issuer="https://idp.test.invalid",
            expected_subject="S-1-legacy",
            actor="admin",
        )
        await _signed_in_ad_user(service, store, "legacy")
        ldap.probe_keys.clear()
        await service.reconcile_directory_sessions()
        assert ldap.probe_keys == [("username", "legacy")]
        assert await reported() == 1
    finally:
        await store.close()


async def test_a_failed_skip_report_neither_stops_the_pass_nor_is_forgotten(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """The skip report runs after the pass's work, and is marked only once written (BACKLOG #2027).

    One failed audit write must not stop the probes of every other account, which is what a report
    made before probing would do on every pass while the write kept failing. And the failed report
    must be retried, not recorded as done.

    **Changed on purpose by BACKLOG #2137.** This test used to assert that the pass RAISED on the
    failed write. A pass that raises returns no plan, so the lifespan task raised no alert for the
    revocations it had already applied. The failure is now logged at ERROR, naming the action, and
    the pass returns. The retry half is unchanged.
    """
    store = await MessageStore.open(":memory:")
    try:
        ldap = _FakeLdap(
            {
                "jdoe": _principal("jdoe"),
                "legacy": replace(_principal("legacy"), directory_object_id=None),
            }
        )
        service = AuthService(store, _ad_settings(), ldap=ldap)  # type: ignore[arg-type]
        await service.initialize()
        await _signed_in_ad_user(service, store, "jdoe")
        await _signed_in_ad_user(service, store, "legacy")
        legacy = await store.get_user_by_username("legacy")
        assert legacy is not None
        assert (
            await store.set_user_federated_subject(
                legacy.id, "https://idp.test.invalid", "S-1-legacy"
            )
            is not None
        )
        # The bind ended the session above, so the bound row signs in again.
        assert await _signed_in_ad_user(service, store, "legacy") is not None
        real_record = store.record_audit

        async def failing(action: str, **kwargs: Any) -> None:
            if action == "auth.ad_reconcile_binding_unkeyed":
                raise sqlite3.OperationalError("synthetic: disk I/O error")
            await real_record(action, **kwargs)

        monkeypatch.setattr(store, "record_audit", failing)
        ldap.probe_keys.clear()
        with caplog.at_level(logging.ERROR, logger="messagefoundry.auth.service"):
            plan = await service.reconcile_directory_sessions()
        assert plan.aborted is None, "the failed report ended the pass"
        assert ldap.probe_keys == [("object_id", _object_id_for("jdoe"))], "the pass never probed"
        assert any(
            r.levelno == logging.ERROR and "auth.ad_reconcile_binding_unkeyed" in r.getMessage()
            for r in caplog.records
        ), "the failed write was not logged at ERROR with its action name"

        monkeypatch.setattr(store, "record_audit", real_record)
        await service.reconcile_directory_sessions()
        assert [
            a
            for a in await store.list_audit()
            if a["action"] == "auth.ad_reconcile_binding_unkeyed"
        ], "the failed report was marked done and never retried"
    finally:
        await store.close()


async def _two_unkeyed_bindings(store: MessageStore) -> AuthService:
    """Two signed-in accounts bound to a federated subject with no directory object id, beside one
    ordinary account, so a pass has two skip reports to write."""
    ldap = _FakeLdap(
        {
            "jdoe": _principal("jdoe"),
            "legacy1": replace(_principal("legacy1"), directory_object_id=None),
            "legacy2": replace(_principal("legacy2"), directory_object_id=None),
        }
    )
    service = AuthService(store, _ad_settings(), ldap=ldap)  # type: ignore[arg-type]
    await service.initialize()
    await _signed_in_ad_user(service, store, "jdoe")
    for name in ("legacy1", "legacy2"):
        await _signed_in_ad_user(service, store, name)
        user = await store.get_user_by_username(name)
        assert user is not None
        bound = await store.set_user_federated_subject(
            user.id, "https://idp.test.invalid", f"S-1-{name}"
        )
        assert bound is not None
        # The bind ended the session above, so the bound row signs in again.
        assert await _signed_in_ad_user(service, store, name) is not None
    return service


async def _reported(store: MessageStore) -> list[str]:
    return sorted(
        json.loads(a["detail"])["username"]
        for a in await store.list_audit()
        if a["action"] == "auth.ad_reconcile_binding_unkeyed"
    )


@pytest.mark.parametrize(
    "refusal",
    [sqlite3.OperationalError("synthetic: disk I/O error"), CipherError("synthetic: Transit down")],
    ids=["driver", "transit-mac"],
)
async def test_a_refused_skip_report_logs_once_per_pass_and_tries_the_next_account_next(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture, refusal: Exception
) -> None:
    """While the store refuses every write, the pass logs one ERROR per pass. Before BACKLOG #2137
    the first failure ended the pass; now the report stops at the first refusal, which also keeps
    a pool that times out each write to one timeout per pass. The
    account it refused goes last next pass, so the next account is tried. Both are reported once the
    store accepts the write. A Transit outage refuses like a driver error (ADR 0138)."""
    store = await MessageStore.open(":memory:")
    try:
        service = await _two_unkeyed_bindings(store)
        real_record = store.record_audit
        attempts: list[str] = []

        async def failing(action: str, **kwargs: Any) -> None:
            if action == "auth.ad_reconcile_binding_unkeyed":
                attempts.append(json.loads(kwargs["detail"])["username"])
                raise refusal
            await real_record(action, **kwargs)

        monkeypatch.setattr(store, "record_audit", failing)
        for _ in range(2):
            caplog.clear()
            with caplog.at_level(logging.WARNING, logger="messagefoundry.auth.service"):
                assert (await service.reconcile_directory_sessions()).aborted is None
            messages = [r.getMessage() for r in caplog.records]
            assert sum("auth.ad_reconcile_binding_unkeyed" in m for m in messages) == 1
            assert sum("carries a federated binding" in m for m in messages) == 1
        assert sorted(attempts) == ["legacy1", "legacy2"], "the refused account was tried first"

        monkeypatch.setattr(store, "record_audit", real_record)
        await service.reconcile_directory_sessions()
        assert await _reported(store) == ["legacy1", "legacy2"]
    finally:
        await store.close()


async def test_one_skip_report_the_store_keeps_refusing_does_not_starve_the_rest(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A refusal tied to one row: the account behind it goes last, so the others are reported on
    the next pass and only it is retried after them."""
    store = await MessageStore.open(":memory:")
    try:
        service = await _two_unkeyed_bindings(store)
        real_record = store.record_audit
        attempts: list[str] = []

        async def failing(action: str, **kwargs: Any) -> None:
            if action == "auth.ad_reconcile_binding_unkeyed":
                name = json.loads(kwargs["detail"])["username"]
                attempts.append(name)
                if name == attempts[0]:
                    raise sqlite3.OperationalError("synthetic: this row is refused")
            await real_record(action, **kwargs)

        monkeypatch.setattr(store, "record_audit", failing)
        await service.reconcile_directory_sessions()
        await service.reconcile_directory_sessions()
        refused = attempts[0]
        assert await _reported(store) == sorted({"legacy1", "legacy2"} - {refused})
        assert attempts == [refused, *sorted({"legacy1", "legacy2"} - {refused}), refused]
    finally:
        await store.close()


async def test_two_skip_reports_the_store_keeps_refusing_take_turns(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Both accounts stay refused. Once both have been refused, the one refused longest ago goes
    first, so neither is starved: list order alone would retry the same account every pass."""
    store = await MessageStore.open(":memory:")
    try:
        service = await _two_unkeyed_bindings(store)
        real_record = store.record_audit
        attempts: list[str] = []

        async def failing(action: str, **kwargs: Any) -> None:
            if action == "auth.ad_reconcile_binding_unkeyed":
                attempts.append(json.loads(kwargs["detail"])["username"])
                raise sqlite3.OperationalError("synthetic: these rows are refused")
            await real_record(action, **kwargs)

        monkeypatch.setattr(store, "record_audit", failing)
        for _ in range(6):
            await service.reconcile_directory_sessions()
        first, second = attempts[:2]
        assert {first, second} == {"legacy1", "legacy2"}
        assert attempts == [first, second] * 3, "one refused account starved the other"
    finally:
        await store.close()


@pytest.mark.parametrize("defect", [NotImplementedError, RecursionError, sqlite3.ProgrammingError])
async def test_a_defect_in_a_reconciler_audit_write_is_raised_not_passed_over(
    monkeypatch: pytest.MonkeyPatch, defect: type[Exception]
) -> None:
    """BACKLOG #2137. The catch keeps ``RuntimeError`` because the store raises
    it for its own refusals. Its two subclasses that mean a defect in the code, not a refused write,
    still end the pass, and so does a bad statement on SQLite."""
    store = await MessageStore.open(":memory:")
    try:
        service = await _two_unkeyed_bindings(store)
        real_record = store.record_audit

        async def broken(action: str, **kwargs: Any) -> None:
            if action == "auth.ad_reconcile_binding_unkeyed":
                raise defect("synthetic defect")
            await real_record(action, **kwargs)

        monkeypatch.setattr(store, "record_audit", broken)
        with pytest.raises(defect):
            await service.reconcile_directory_sessions()
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
        await store.create_user(
            user_id="departed-row", username="jbloggs", auth_provider="ad", password_generated=False
        )

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
        service._security_notifier = notifier
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
        #
        # The rename's own notice (BACKLOG #2017) is paired with the rename's own audit row, not with
        # the revocation's, so it is checked against that row below rather than excluded silently.
        renames = [e for e in notifier.sent if e.event_type == USERNAME_CHANGED]
        assert {e.username for e in notifier.sent if e not in renames} == {"jdoe"}, (
            "a security notice named a different account than the audit row"
        )
        refreshed = [
            a for a in await store.list_audit() if a["action"] == "auth.ad_username_refreshed"
        ]
        assert [e.username for e in renames] == [a["actor"] for a in refreshed] == ["jdoe-married"]

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

        async def _raise_driver_error(*a: object, **kw: object) -> bool:
            await store.create_user(
                user_id="winner", username="jbloggs", auth_provider="ad", password_generated=False
            )
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
        async def _raise_integrity(*a: object, **kw: object) -> bool:
            await store.create_user(
                user_id="winner", username="jbloggs", auth_provider="ad", password_generated=False
            )
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

        async def _raise_other(*a: object, **kw: object) -> bool:
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


# --- BACKLOG #2017: the holder is told of a directory rename (ASVS 6.3.7) --------------------------


async def _renamed_service() -> tuple[
    MessageStore, _FakeLdap, AuthService, _CapturingNotifier, str
]:
    """A signed-in ``jdoe`` with a known notification address and a capturing notifier, and the
    directory already renaming it to ``jdoe-married`` for the next pass. Returns the row's id."""
    store = await MessageStore.open(":memory:")
    ldap = _FakeLdap({"jdoe": _principal("jdoe")})
    service = AuthService(store, _ad_settings(), ldap=ldap)  # type: ignore[arg-type]
    notifier = _CapturingNotifier()
    service._security_notifier = notifier
    await service.initialize()
    await _signed_in_ad_user(service, store, "jdoe")
    jdoe = await store.get_user_by_username("jdoe")
    assert jdoe is not None
    # Set explicitly, so the address assertion below cannot pass on whatever the birth chose.
    await store.set_user_notify_email(jdoe.id, email="holder@example.org")
    ldap.present = {"jdoe-married": _principal("jdoe-married", object_id=_object_id_for("jdoe"))}
    return store, ldap, service, notifier, jdoe.id


async def test_a_reconciled_rename_sends_the_holder_one_notice_naming_both_names() -> None:
    """ASVS 6.3.7 names username changes. The refresh already audited one; the holder was not told.

    Exactly one notice, to the engine-owned ``notify_email``, carrying the old and the new name. Its
    ``username`` is the NEW name, the same account its ``auth.ad_username_refreshed`` row names.
    """
    store, _ldap, service, notifier, user_id = await _renamed_service()
    try:
        plan = await service.reconcile_directory_sessions()
        assert [(r.old_username, r.new_username) for r in plan.renames] == [
            ("jdoe", "jdoe-married")
        ]
        after = await store.get_user(user_id)
        assert after is not None and after.username == "jdoe-married"

        [notice] = [e for e in notifier.sent if e.event_type == USERNAME_CHANGED]
        assert notice.email == "holder@example.org"
        assert notice.username == "jdoe-married"
        assert notice.detail == {
            "old_username": "jdoe",
            "new_username": "jdoe-married",
            "source": "directory",
        }
    finally:
        await store.close()


@pytest.mark.parametrize("shape", ["pre_check", "write_race", "write_noop", "row_gone"])
async def test_a_rename_that_writes_nothing_sends_no_notice(shape: str) -> None:
    """THE MUST-NOT-FIRE ARM. A refresh that loses to another row writes nothing, so it must not
    tell the holder their name changed: that would be a false statement in a security notice.

    One case per way the refresh refuses. ``pre_check``: the name is already held. ``write_race``:
    another writer claims it between the check and the write, which raises. ``write_noop``: the
    store's guard holds and the write matches no row, which raises nothing and is caught only by the
    re-read after the write returns ``False``. ``row_gone``: the row is deleted before the write
    lands. Each is asserted to have refused, so none passes by never reaching the branch.
    """
    store, _ldap, service, notifier, user_id = await _renamed_service()
    try:
        if shape == "pre_check":
            await store.create_user(
                user_id="holder-row",
                username="jdoe-married",
                auth_provider="ad",
                password_generated=False,
            )
        elif shape == "write_race":

            async def _lose(*a: object, **kw: object) -> bool:
                await store.create_user(
                    user_id="winner",
                    username="jdoe-married",
                    auth_provider="ad",
                    password_generated=False,
                )
                raise sqlite3.IntegrityError("UNIQUE constraint failed: users.username")

            store.set_user_username = _lose  # type: ignore[method-assign]
        elif shape == "write_noop":

            async def _match_nothing(*a: object, **kw: object) -> bool:
                # Another row took the name after the pre-check, and the store's guard held.
                await store.create_user(
                    user_id="squatter",
                    username="jdoe-married",
                    auth_provider="ad",
                    password_generated=False,
                )
                return False

            store.set_user_username = _match_nothing  # type: ignore[method-assign]
        else:
            delete_user = store.delete_user

            async def _row_deleted(*a: object, **kw: object) -> bool:
                await delete_user(user_id)
                return False

            store.set_user_username = _row_deleted  # type: ignore[method-assign]

        plan = await service.reconcile_directory_sessions()
        assert plan.aborted is None

        still = await store.get_user(user_id)
        if shape == "row_gone":
            assert still is None
        else:
            assert still is not None and still.username == "jdoe"
        [conflict] = [
            a
            for a in await store.list_audit()
            if a["action"] == "auth.ad_username_refresh_conflict"
        ]
        assert json.loads(conflict["detail"])["detected"] == shape
        if shape == "write_noop":
            # The operator has to remove the holder, so the audit names it (BACKLOG #2290).
            assert json.loads(conflict["detail"])["held_by_user_id"] == "squatter"
        assert not [e for e in notifier.sent if e.event_type == USERNAME_CHANGED], (
            f"a {shape} refresh wrote nothing and still told the holder their name changed"
        )
    finally:
        await store.close()


async def test_a_rename_already_applied_by_another_caller_is_not_told_twice(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """The reconciler plans a rename, a directory sign-in applies it first, then the plan applies.

    The pre-read finds the new name already in place and returns before any write, so the holder
    gets no second notice and the audit no second ``auth.ad_username_refreshed`` row. This is the
    case in sequence. When both refreshes read the old name at once, the store's compare-and-set
    stops the second one instead (BACKLOG #2290,
    ``test_two_refreshes_of_one_rename_at_once_write_audit_and_notify_once``).
    Driven on the method directly, with ``held`` set as the reconciler reads it, because the pass
    offers no hook between its plan and its apply.
    """
    store, _ldap, service, notifier, user_id = await _renamed_service()
    try:
        await store.set_user_username(
            user_id, "jdoe-married", expected_username="jdoe"
        )  # the sign-in got there first
        held = await store.get_user_by_username("jdoe-married")
        assert held is not None and held.id == user_id

        caplog.set_level(logging.INFO, logger="messagefoundry.auth.service")
        await service._refresh_cached_username(
            user_id=user_id, old_username="jdoe", new_username="jdoe-married", held=held
        )

        assert not [e for e in notifier.sent if e.event_type == USERNAME_CHANGED]
        assert not [
            a for a in await store.list_audit() if a["action"] == "auth.ad_username_refreshed"
        ]
        # BACKLOG #2291: the skip says why at INFO, so it is visible without reading as a fault.
        skipped = [
            r
            for r in caplog.records
            if r.name == "messagefoundry.auth.service" and "BACKLOG #2291" in r.getMessage()
        ]
        assert [r.levelno for r in skipped] == [logging.INFO], "the skipped rename was silent"
    finally:
        await store.close()


async def test_the_notice_names_the_name_the_row_had_not_the_plans() -> None:
    """The reconciler's ``old_username`` is the name at PLAN time. A sign-in can rename the row
    before the plan applies, and the notice must then name what the row was actually called."""
    store, _ldap, service, notifier, user_id = await _renamed_service()
    try:
        assert await store.set_user_username(user_id, "jdoe-interim", expected_username="jdoe")

        await service._refresh_cached_username(
            user_id=user_id, old_username="jdoe", new_username="jdoe-married", held=None
        )

        [notice] = [e for e in notifier.sent if e.event_type == USERNAME_CHANGED]
        assert notice.detail["old_username"] == "jdoe-interim"
        assert notice.detail["new_username"] == "jdoe-married"
    finally:
        await store.close()


async def test_a_row_deleted_before_the_apply_is_refused_without_a_write_or_a_notice() -> None:
    """The ``row_gone`` case in the parametrized test deletes the row DURING the write, after the
    pre-read. This one deletes it between the plan and the apply, so the pre-read finds nothing: the
    refresh refuses as ``row_gone``, never calls the write, and tells nobody."""
    store, _ldap, service, notifier, user_id = await _renamed_service()
    try:
        await store.delete_user(user_id)
        writes: list[object] = []

        async def _record_write(*a: object, **kw: object) -> bool:
            writes.append(a)
            return True

        store.set_user_username = _record_write  # type: ignore[method-assign]

        await service._refresh_cached_username(
            user_id=user_id, old_username="jdoe", new_username="jdoe-married", held=None
        )

        assert writes == [], "the refresh wrote to a row it had just read as gone"
        [conflict] = [
            a
            for a in await store.list_audit()
            if a["action"] == "auth.ad_username_refresh_conflict"
        ]
        assert json.loads(conflict["detail"])["detected"] == "row_gone"
        # No row is left to hold a name, so the caller's is the last one known (BACKLOG #2291).
        assert conflict["actor"] == "jdoe"
        assert not [e for e in notifier.sent if e.event_type == USERNAME_CHANGED]
    finally:
        await store.close()


@pytest.mark.parametrize("shape", ["pre_check", "write_race", "write_noop", "row_gone"])
async def test_a_refused_rename_is_audited_under_the_name_the_row_holds(shape: str) -> None:
    """BACKLOG #2291. The caller's ``old_username`` is the reconciler's plan-time name, and a
    sign-in can rename the row before the plan applies. A refusal audited under the plan's name
    would name an account that no longer exists, so every refusal names what the row holds.

    The row is renamed to ``jdoe-interim`` first and the refresh is passed the stale ``jdoe``.
    One case per way the refresh refuses after it has read the row; each is asserted to have
    refused, so none passes by never reaching the branch."""
    store, _ldap, service, notifier, user_id = await _renamed_service()
    try:
        assert await store.set_user_username(user_id, "jdoe-interim", expected_username="jdoe")
        held: UserRecord | None = None
        if shape == "pre_check":
            await store.create_user(
                user_id="holder-row",
                username="jdoe-married",
                auth_provider="ad",
                password_generated=False,
            )
            held = await store.get_user_by_username("jdoe-married")
        elif shape == "write_race":

            async def _lose(*a: object, **kw: object) -> bool:
                await store.create_user(
                    user_id="winner",
                    username="jdoe-married",
                    auth_provider="ad",
                    password_generated=False,
                )
                raise sqlite3.IntegrityError("UNIQUE constraint failed: users.username")

            store.set_user_username = _lose  # type: ignore[method-assign]
        elif shape == "write_noop":

            async def _match_nothing(*a: object, **kw: object) -> bool:
                await store.create_user(
                    user_id="squatter",
                    username="jdoe-married",
                    auth_provider="ad",
                    password_generated=False,
                )
                return False

            store.set_user_username = _match_nothing  # type: ignore[method-assign]
        else:
            delete_user = store.delete_user

            async def _row_deleted(*a: object, **kw: object) -> bool:
                await delete_user(user_id)
                return False

            store.set_user_username = _row_deleted  # type: ignore[method-assign]

        await service._refresh_cached_username(
            user_id=user_id, old_username="jdoe", new_username="jdoe-married", held=held
        )

        [conflict] = [
            a
            for a in await store.list_audit()
            if a["action"] == "auth.ad_username_refresh_conflict"
        ]
        assert json.loads(conflict["detail"])["detected"] == shape
        assert conflict["actor"] == "jdoe-interim", (
            f"a {shape} refusal audited the caller's stale name, not the one the row held"
        )
        assert not [e for e in notifier.sent if e.event_type == USERNAME_CHANGED]
    finally:
        await store.close()


async def test_a_stale_held_row_is_not_a_conflict_when_this_row_already_has_the_name(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """The reconciler reads ``held`` just before it calls the refresh, so ``held`` is older than
    the refresh's own pre-read, by a short window. If the holder let the name go in that window
    and a sign-in gave it to this row, the pre-read wins: the name is unique, so this row holding
    it means ``held`` is stale. The refresh logs the no-op and files no conflict (BACKLOG #2291)."""
    store, _ldap, service, notifier, user_id = await _renamed_service()
    try:
        row = await store.get_user(user_id)
        assert row is not None
        # A record of another row that held the name when the caller read it, and holds it no more.
        stale_held = replace(row, id="gone-holder", username="jdoe-married")
        assert await store.set_user_username(user_id, "jdoe-married", expected_username="jdoe")

        caplog.set_level(logging.INFO, logger="messagefoundry.auth.service")
        caplog.clear()  # only the refresh's own records, not the sign-in setup's
        await service._refresh_cached_username(
            user_id=user_id, old_username="jdoe", new_username="jdoe-married", held=stale_held
        )

        assert not [
            a
            for a in await store.list_audit()
            if a["action"] == "auth.ad_username_refresh_conflict"
        ], "a stale held row filed a conflict for a rename already in place"
        assert not [e for e in notifier.sent if e.event_type == USERNAME_CHANGED]
        assert not [r for r in caplog.records if r.levelno >= logging.WARNING]
    finally:
        await store.close()


async def test_a_row_gone_refusal_does_not_warn_of_a_lockout(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """A deleted row is not a taken name: nobody is locked out and there is no stale holder to
    remove. Its warning must not send an operator looking for one (BACKLOG #2291). The audit row
    still records it, as the other refusals are recorded."""
    store, _ldap, service, _notifier, user_id = await _renamed_service()
    try:
        await store.delete_user(user_id)
        caplog.set_level(logging.WARNING, logger="messagefoundry.auth.service")
        caplog.clear()  # only the refresh's own records, not the sign-in setup's
        await service._refresh_cached_username(
            user_id=user_id, old_username="jdoe", new_username="jdoe-married", held=None
        )
        [warning] = [r for r in caplog.records if r.name == "messagefoundry.auth.service"]
        assert "removed" in warning.getMessage()
        assert "directory_identity_conflict" not in warning.getMessage()
        assert "already held" not in warning.getMessage()
        [conflict] = [
            a
            for a in await store.list_audit()
            if a["action"] == "auth.ad_username_refresh_conflict"
        ]
        detail = json.loads(conflict["detail"])
        assert detail["detected"] == "row_gone"
        # No other row holds the name, so the audit names no holder (BACKLOG #2291).
        assert detail["held_by_user_id"] is None
    finally:
        await store.close()


async def test_a_lost_write_with_no_holder_left_does_not_warn_of_a_lockout(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """The write raises a unique violation, but by the re-read no row holds the name. Nobody is
    locked out and the next sign-in retries, so the warning must not tell an operator to remove a
    stale row that is not there (BACKLOG #2291)."""
    store, _ldap, service, _notifier, user_id = await _renamed_service()
    try:

        async def _lose_to_nobody(*a: object, **kw: object) -> bool:
            raise sqlite3.IntegrityError("UNIQUE constraint failed: users.username")

        store.set_user_username = _lose_to_nobody  # type: ignore[method-assign]
        caplog.set_level(logging.WARNING, logger="messagefoundry.auth.service")
        caplog.clear()  # only the refresh's own records, not the sign-in setup's
        await service._refresh_cached_username(
            user_id=user_id, old_username="jdoe", new_username="jdoe-married", held=None
        )
        [warning] = [r for r in caplog.records if r.name == "messagefoundry.auth.service"]
        assert "no row holds the new name" in warning.getMessage()
        assert "directory_identity_conflict" not in warning.getMessage()
        [conflict] = [
            a
            for a in await store.list_audit()
            if a["action"] == "auth.ad_username_refresh_conflict"
        ]
        assert json.loads(conflict["detail"])["detected"] == "write_race"
    finally:
        await store.close()


# --- BACKLOG #2290: two refreshes of one rename at once write, audit and notify once ------------


async def test_two_refreshes_of_one_rename_at_once_write_audit_and_notify_once(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """A sign-in and a reconciler pass rename one row at the same moment. One of them wins.

    **The barrier is what makes this test the race.** ``asyncio.gather`` alone can run one refresh
    to completion before the other starts, and then the second one's pre-read sees the new name and
    returns early, so the test would pass with no compare-and-set at all. Here neither refresh may
    write until both have finished their pre-read, so both read the old name and both reach the
    write. Only the write's compare on the old name can then stop the second one.
    """
    store, _ldap, service, notifier, user_id = await _renamed_service()
    try:
        barrier = asyncio.Barrier(2)
        pre_reads = 0
        get_user = store.get_user

        async def _pre_read_then_wait(user_id: str) -> UserRecord | None:
            # Only the two pre-reads wait. A later read, such as the loser's re-read after its
            # write matched nothing, must not block on a barrier with one party.
            nonlocal pre_reads
            row = await get_user(user_id)
            pre_reads += 1
            if pre_reads <= 2:
                await barrier.wait()
            return row

        store.get_user = _pre_read_then_wait  # type: ignore[method-assign]
        writes: list[bool] = []
        set_user_username = store.set_user_username

        async def _count_write(
            user_id: str, username: str, *, expected_username: str, now: float | None = None
        ) -> bool:
            wrote = await set_user_username(
                user_id, username, expected_username=expected_username, now=now
            )
            writes.append(wrote)
            return wrote

        store.set_user_username = _count_write  # type: ignore[method-assign]

        caplog.set_level(logging.INFO, logger="messagefoundry.auth.service")
        # A timeout, so a refresh that skips its pre-read fails here instead of leaving the other
        # one waiting on the barrier for ever. A task group, so if one refresh raises the other is
        # cancelled rather than left pending on the barrier.
        async with asyncio.timeout(10), asyncio.TaskGroup() as tg:
            for _ in range(2):
                tg.create_task(
                    service._refresh_cached_username(
                        user_id=user_id, old_username="jdoe", new_username="jdoe-married", held=None
                    )
                )

        # Both reached the write, which is the proof the barrier made them race.
        assert sorted(writes) == [False, True], f"expected one winning write, got {writes}"
        after = await get_user(user_id)
        assert after is not None and after.username == "jdoe-married"
        refreshed = [
            a for a in await store.list_audit() if a["action"] == "auth.ad_username_refreshed"
        ]
        assert len(refreshed) == 1, f"one rename audited {len(refreshed)} times"
        assert not [
            a
            for a in await store.list_audit()
            if a["action"] == "auth.ad_username_refresh_conflict"
        ], "a lost race to the same rename was audited as a conflict"
        notices = [e for e in notifier.sent if e.event_type == USERNAME_CHANGED]
        assert len(notices) == 1, f"the holder was told of one rename {len(notices)} times"
        assert notices[0].detail["old_username"] == "jdoe"
        # The losing refresh says why it did nothing, at INFO, rather than vanishing.
        assert any(
            r.name == "messagefoundry.auth.service"
            and r.levelno == logging.INFO
            and "BACKLOG #2290" in r.getMessage()
            for r in caplog.records
        ), "the losing refresh logged nothing"
    finally:
        await store.close()


# --- ADR 0198: the scope re-diff ----------------------------------------------
#
# The owner's 2026-09-26 ruling (BACKLOG #1957): the pass ends a principal's sessions when the
# directory would withdraw or narrow its channel scope, and never writes the scope itself. The next
# login writes it, through the SAME decision the planner used.

_GRP_A = "cn=grp-a,dc=test,dc=invalid"
_GRP_B = "cn=grp-b,dc=test,dc=invalid"
_GRP_ALL = "cn=grp-all,dc=test,dc=invalid"


async def _scope_of(store: MessageStore, username: str) -> tuple[str | None, str | None]:
    user = await store.get_user_by_username(username)
    assert user is not None
    return user.channel_scope, user.channel_scope_source


async def _scoped_service(
    *groups: str, names: tuple[str, ...] = ("jdoe",)
) -> tuple[MessageStore, _FakeLdap, AuthService, dict[str, str]]:
    """A service whose accounts signed in holding ``groups``, under a map giving grp-a IB_A and
    IB_B, grp-b IB_B, and grp-all every channel. The map is written through the STORE, not the
    service: the service's map edit revokes every session, and these tests model a change made in
    the directory."""
    store = await MessageStore.open(":memory:")
    await store.set_ad_group_scope_map(
        [(_GRP_A, "IB_A"), (_GRP_A, "IB_B"), (_GRP_B, "IB_B"), (_GRP_ALL, "*")]
    )
    try:
        ldap = _FakeLdap({n: _principal(n, *groups) for n in names})
        service = AuthService(store, _ad_settings(), ldap=ldap)  # type: ignore[arg-type]
        await service.initialize()
        tokens: dict[str, str] = {}
        for name in names:
            token = await _signed_in_ad_user(service, store, name)
            assert token is not None
            tokens[name] = token
    except BaseException:
        # The caller's try/finally starts only once this returns, so close here on a failed setup.
        await store.close()
        raise
    return store, ldap, service, tokens


def _scope_input(
    stored: list[str] | None,
    mapped: set[str],
    *,
    source: str | None = "ad",
    administrator: bool = False,
) -> channel_scope.ScopeInput:
    return channel_scope.ScopeInput(
        stored_scope=None if stored is None else json.dumps(stored, sort_keys=True),
        stored_source=source,
        mapped=frozenset(mapped),
        administrator=administrator,
    )


@pytest.mark.parametrize(
    ("stored", "source", "mapped", "administrator", "write", "narrows"),
    [
        (["IB_A"], "ad", set(), False, True, True),  # withdrawn
        (["IB_A", "IB_B"], "ad", {"IB_B"}, False, True, True),  # narrowed
        (["*"], "ad", {"IB_A"}, False, True, True),  # all channels to a list narrows
        (["IB_A"], "ad", {"IB_B"}, False, True, True),  # a swap drops IB_A, so it narrows
        (["IB_A"], "ad", {"IB_A"}, False, False, False),  # unchanged
        (["IB_A"], "ad", {"IB_A", "IB_B"}, False, True, False),  # widened: login writes, no revoke
        (["IB_A"], "ad", {"*"}, False, True, False),  # widened to all
        (["IB_A"], "manual", set(), False, False, False),  # an administrator's scope survives
        (["IB_A"], "manual", {"IB_A"}, False, True, False),  # provenance moves, access does not
        (["IB_A"], None, set(), False, True, True),  # unvouched: withdrawn (BACKLOG #1927)
        (None, "ad", set(), False, False, False),  # already denies
        ([], "ad", set(), False, False, False),  # already denies
        (["IB_A"], "ad", set(), True, False, False),  # an Administrator keeps what is stored
    ],
)
def test_login_and_the_planner_share_one_scope_decision(
    stored: list[str] | None,
    source: str | None,
    mapped: set[str],
    administrator: bool,
    write: bool,
    narrows: bool,
) -> None:
    """AC-9. ONE rule decides login's write and the pass's revocation, and ``narrows`` implies a
    write that changes the value. That implication is the #1532 loop guard in one line: whatever the
    pass revokes for, the next login writes, so the pass after it has nothing left to revoke."""
    scope = _scope_input(stored, mapped, source=source, administrator=administrator)
    decision = channel_scope.decide_ad_channel_scope(scope)
    assert (decision.write, decision.narrows) == (write, narrows)
    if decision.narrows:
        assert decision.write and decision.changes
    # The planner reads the very same answer.
    plan = reconcile.plan_pass(
        [reconcile.Probe("u1", "jdoe", P)],
        prior_strikes={},
        current_roles={},
        target_roles={},
        strike_threshold=2,
        max_absolute=5,
        max_fraction=0.34,
        scopes={"u1": scope},
    )
    expected = [("jdoe", reconcile.SCOPE_CHANGED)] if narrows else []
    assert [(r.username, r.reason) for r in plan.revocations] == expected


async def test_requests_parse_a_stored_scope_with_the_planners_parser() -> None:
    """The planner decides "narrowed" by parsing the stored value, and every request's scope comes
    from ``_allowed_channels``. One parser, so a malformed value cannot read as a deny to one and a
    grant to the other."""
    from messagefoundry.auth.service import _allowed_channels

    store = await MessageStore.open(":memory:")
    try:
        await store.create_user(
            user_id="u", username="u", auth_provider="ad", password_generated=False
        )
        user = await store.get_user("u")
        assert user is not None
        cases: list[tuple[str | None, frozenset[str] | None]] = [
            (None, frozenset()),  # absent denies (BACKLOG #1152)
            ("not json", frozenset()),  # malformed denies
            ('{"a": 1}', frozenset()),  # not a list denies
            ("[]", frozenset()),
            ('["*"]', None),  # the deliberate all-channels grant
            ('["IB_A","IB_B"]', frozenset({"IB_A", "IB_B"})),
        ]
        for raw, expected in cases:
            assert channel_scope.scope_channels(raw) == expected, raw
            got = _allowed_channels(replace(user, channel_scope=raw), frozenset())
            assert got == expected, raw
    finally:
        await store.close()


async def _login_writes(
    stored: list[str] | None,
    source: str,
    mapped: set[str],
    administrator: bool,
) -> tuple[str | None, str | None, str | None, str | None]:
    """Seed one account's scope, run the LOGIN sync against groups mapping to ``mapped``, and return
    (scope before, source before, scope after, source after).

    ``source`` is ``"ad"`` or ``"manual"``. An unvouched (NULL-source) scope cannot be written
    through the store's API, which requires a source; ``tests/test_ad_group_scope.py`` drives that
    login case, and the pure test above covers its decision."""
    assert source in (SCOPE_SOURCE_AD, SCOPE_SOURCE_MANUAL)
    store = await MessageStore.open(":memory:")
    try:
        # One group per channel, so any ``mapped`` set is reachable from a group set.
        await store.set_ad_group_scope_map([(f"cn=ch-{c}", c) for c in ("IB_A", "IB_B", "*")])
        await store.create_user(
            user_id="u", username="u", auth_provider="ad", password_generated=False
        )
        if stored is not None:
            await store.set_user_channel_scope(
                "u",
                None if stored is None else json.dumps(stored, sort_keys=True),
                source=SCOPE_SOURCE_MANUAL if source == "manual" else SCOPE_SOURCE_AD,
            )
        service = AuthService(store, _ad_settings(), ldap=_FakeLdap())  # type: ignore[arg-type]
        await service.initialize()
        user = await store.get_user("u")
        assert user is not None
        roles = frozenset({Role.ADMINISTRATOR}) if administrator else frozenset()
        after = await service._sync_ad_channel_scope(user, roles, [f"cn=ch-{c}" for c in mapped])
        return (
            user.channel_scope,
            user.channel_scope_source,
            after.channel_scope,
            (after.channel_scope_source),
        )
    finally:
        await store.close()


@pytest.mark.parametrize(
    ("stored", "source", "mapped", "administrator"),
    [
        (["IB_A"], "ad", set(), False),
        (["IB_A", "IB_B"], "ad", {"IB_B"}, False),
        (["*"], "ad", {"IB_A"}, False),
        (["IB_A"], "ad", {"IB_B"}, False),
        (["IB_A"], "ad", {"IB_A"}, False),
        (["IB_A"], "ad", {"IB_A", "IB_B"}, False),
        (["IB_A"], "ad", {"*"}, False),
        (["IB_A"], "manual", set(), False),
        (["IB_A"], "manual", {"IB_A"}, False),
        ([], "ad", set(), False),
        (["IB_A"], "ad", set(), True),
    ],
)
async def test_login_writes_exactly_what_the_shared_decision_says(
    stored: list[str] | None, source: str, mapped: set[str], administrator: bool
) -> None:
    """AC-9, from the LOGIN side. The pure test above cannot see login drift from the rule, since it
    never runs login. This one does, for each case: login writes the decision's value or nothing,
    and the decision on what login left is KEEP. That last step is the #1532 loop guard for every
    case, not only the two the service-level loop test drives."""
    before, source_before, after, source_after = await _login_writes(
        stored, source, mapped, administrator
    )
    decision = channel_scope.decide_ad_channel_scope(
        channel_scope.ScopeInput(before, source_before, frozenset(mapped), administrator)
    )
    if decision.write:
        assert (after, source_after) == (decision.scope_json, "ad")
    else:
        assert (after, source_after) == (before, source_before)
    settled = channel_scope.decide_ad_channel_scope(
        channel_scope.ScopeInput(after, source_after, frozenset(mapped), administrator)
    )
    assert settled == channel_scope.KEEP_SCOPE, "login left a scope the decision would change again"


def test_a_role_and_scope_delta_count_once_against_the_breaker() -> None:
    """AC-5. Four of twelve principals lose a role AND a scope channel. One count each is four,
    under the floor of five, so the pass applies. Two counts each would be eight, past both the
    floor and 0.34 of twelve, and would abort a pass the owner ruled must apply."""
    probes = [reconcile.Probe(f"u{i:02d}", f"user{i:02d}", P) for i in range(12)]
    changed = {f"u{i:02d}" for i in range(4)}
    plan = reconcile.plan_pass(
        probes,
        prior_strikes={},
        current_roles={p.user_id: frozenset({"operator"}) for p in probes},
        target_roles={
            p.user_id: frozenset() if p.user_id in changed else frozenset({"operator"})
            for p in probes
        },
        strike_threshold=2,
        max_absolute=5,
        max_fraction=0.34,
        scopes={
            p.user_id: _scope_input(
                ["IB_A", "IB_B"], {"IB_B"} if p.user_id in changed else {"IB_A", "IB_B"}
            )
            for p in probes
        },
    )
    assert plan.aborted is None
    assert sorted((r.user_id, r.reason, r.scope_changed) for r in plan.revocations) == [
        (uid, "roles_changed", True) for uid in sorted(changed)
    ]


def test_an_aborted_pass_drops_scope_revocations_and_writes_nothing() -> None:
    """AC-6. A pass whose scope revocations trip the breaker plans no write at all, so ADR 0079's
    byte-identical abort holds with the scope re-diff in it."""
    probes = [reconcile.Probe(f"u{i:02d}", f"user{i:02d}", P) for i in range(12)]
    plan = reconcile.plan_pass(
        probes,
        prior_strikes={},
        current_roles={},
        target_roles={},
        strike_threshold=2,
        max_absolute=5,
        max_fraction=0.34,
        scopes={p.user_id: _scope_input(["IB_A"], set()) for p in probes},
    )
    assert plan.aborted == "mass_revoke_breaker"
    assert plan.revocations == () and plan.renames == ()


async def test_a_withdrawn_directory_scope_revokes_on_the_next_pass() -> None:
    """AC-1. The user leaves their last scope-mapped group in the directory. The pass revokes, with
    ``scope_changed``, and leaves the scope exactly as it was: the reconciler is not a scope writer."""
    store, ldap, service, tokens = await _scoped_service(_GRP_A)
    try:
        before = await _scope_of(store, "jdoe")
        assert before == (json.dumps(["IB_A", "IB_B"]), "ad")

        ldap.present["jdoe"] = _principal("jdoe")  # removed from grp-a
        plan = await service.reconcile_directory_sessions()

        assert [(r.username, r.reason) for r in plan.revocations] == [
            ("jdoe", reconcile.SCOPE_CHANGED)
        ]
        assert await service.identity_for_token(tokens["jdoe"]) is None
        assert await _scope_of(store, "jdoe") == before, "the reconciler wrote channel_scope"
        rows = [a for a in await store.list_audit() if a["action"] == "auth.ad_session_revoked"]
        assert [json.loads(r["detail"])["reason"] for r in rows] == [reconcile.SCOPE_CHANGED]
    finally:
        await store.close()


async def test_a_narrowed_directory_scope_revokes() -> None:
    """AC-2. grp-a (IB_A and IB_B) is swapped for grp-b (IB_B alone): IB_A is taken away."""
    store, ldap, service, tokens = await _scoped_service(_GRP_A)
    try:
        ldap.present["jdoe"] = _principal("jdoe", _GRP_B)
        plan = await service.reconcile_directory_sessions()
        assert [(r.username, r.reason) for r in plan.revocations] == [
            ("jdoe", reconcile.SCOPE_CHANGED)
        ]
        assert await service.identity_for_token(tokens["jdoe"]) is None
    finally:
        await store.close()


@pytest.mark.parametrize(
    ("start", "now"),
    [((_GRP_A,), (_GRP_A,)), ((_GRP_B,), (_GRP_A,)), ((_GRP_B,), (_GRP_ALL,))],
    ids=["unchanged", "widened", "widened-to-all"],
)
async def test_an_unchanged_or_wider_directory_scope_does_not_revoke(
    start: tuple[str, ...], now: tuple[str, ...]
) -> None:
    """AC-3. THE MUST-NOT-FIRE ARM. A pass that revoked on every PRESENT probe would pass every
    revoking test above; this is what catches it. A wider scope leaves the live token
    under-privileged, which is safe, and waits for the next login."""
    store, ldap, service, tokens = await _scoped_service(*start)
    try:
        ldap.present["jdoe"] = _principal("jdoe", *now)
        for _ in range(3):
            plan = await service.reconcile_directory_sessions()
            assert plan.revocations == ()
        assert await service.identity_for_token(tokens["jdoe"]) is not None
    finally:
        await store.close()


async def test_a_manual_scope_with_no_mapped_group_survives() -> None:
    """AC-4. An administrator's scope on a user in no scope-mapped group is kept by login, so the
    pass must not revoke for it either. Otherwise it would revoke on every pass: login never
    withdraws a manual scope, which is exactly the #1532 loop."""
    store, _ldap, service, _ = await _scoped_service()
    try:
        user = await store.get_user_by_username("jdoe")
        assert user is not None
        await service.set_channel_scope(user.id, ["MANUAL"], actor="admin")
        token = await _signed_in_ad_user(service, store, "jdoe")
        assert token is not None
        for _ in range(3):
            plan = await service.reconcile_directory_sessions()
            assert plan.revocations == ()
        assert await service.identity_for_token(token) is not None
        assert await _scope_of(store, "jdoe") == (json.dumps(["MANUAL"]), "manual")
    finally:
        await store.close()


async def test_a_lost_memberof_read_trips_the_breaker_rather_than_revoking_everyone() -> None:
    """AC-7, the hazard the owner's ruling names. A bind account that loses read on ``memberOf``
    returns every principal PRESENT with no groups, so each one's scope reads as withdrawn on the
    same pass. The breaker is the brake: the pass aborts, nobody is signed out, nothing is written."""
    names = tuple(f"user{i:02d}" for i in range(12))
    store, ldap, service, tokens = await _scoped_service(_GRP_A, names=names)
    try:
        users_before = [
            (u.id, u.channel_scope, u.channel_scope_source) for u in await store.list_users()
        ]
        for name in names:
            ldap.present[name] = _principal(name)  # PRESENT, but every group is gone
        plan = await service.reconcile_directory_sessions()

        assert plan.aborted == "mass_revoke_breaker"
        assert plan.revocations == ()
        for token in tokens.values():
            assert await service.identity_for_token(token) is not None
        users_after = [
            (u.id, u.channel_scope, u.channel_scope_source) for u in await store.list_users()
        ]
        assert users_after == users_before
        assert not [a for a in await store.list_audit() if a["action"] == "auth.ad_session_revoked"]
    finally:
        await store.close()


def test_a_lost_memberof_read_below_the_breakers_fraction_still_revokes() -> None:
    """The breaker is only a PARTIAL brake on a memberOf read loss, and this pins the part it does
    not cover so the documents cannot claim more. It aborts only past BOTH its floor (5) and its
    fraction (0.34 of the judged probes). Here 9 of 30 principals hold a directory scope; the rest
    hold an administrator's scope, which a group loss does not touch. 9 is past the floor but under
    0.34 x 30 = 10.2, so the pass applies all 9. Their next logins read the same empty groups and
    withdraw the scope, which is what login would have done without this ADR."""
    probes = [reconcile.Probe(f"u{i:02d}", f"user{i:02d}", P) for i in range(30)]
    plan = reconcile.plan_pass(
        probes,
        prior_strikes={},
        current_roles={},
        target_roles={},
        strike_threshold=2,
        max_absolute=5,
        max_fraction=0.34,
        scopes={
            p.user_id: _scope_input(["IB_A"], set(), source="ad" if i < 9 else "manual")
            for i, p in enumerate(probes)
        },
    )
    assert plan.aborted is None
    assert len(plan.revocations) == 9


async def test_a_scope_revocation_audits_what_the_directory_took_away() -> None:
    """The reconciler writes no scope, so the audit row is the only record of the withdrawn grant
    until the next login. It carries the stored scope and the directory's, on a scope-only
    revocation and on a role revocation that carried a scope delta too."""
    store, ldap, service, _ = await _scoped_service(_GRP_A, names=("jdoe", "asmith"))
    try:
        await store.set_ad_group_role_map([(_GRP_A, "operator")])
        await _signed_in_ad_user(service, store, "asmith")  # picks up the operator role
        ldap.present["jdoe"] = _principal("jdoe")  # scope only: jdoe held no mapped role
        ldap.present["asmith"] = _principal("asmith")  # role AND scope
        plan = await service.reconcile_directory_sessions()
        assert sorted((r.username, r.reason) for r in plan.revocations) == [
            ("asmith", "roles_changed"),
            ("jdoe", reconcile.SCOPE_CHANGED),
        ]
        rows = {
            r["actor"]: json.loads(r["detail"])
            for r in await store.list_audit()
            if r["action"] == "auth.ad_session_revoked"
        }
        wide = json.dumps(["IB_A", "IB_B"])
        for name in ("jdoe", "asmith"):
            assert rows[name]["scope_changed"] is True
            assert (rows[name]["scope_from"], rows[name]["scope_to"]) == (wide, None)
        assert rows["asmith"]["roles"] == []
    finally:
        await store.close()


async def test_a_principal_becoming_an_administrator_is_not_revoked_for_scope() -> None:
    """The Administrator short-circuit reads the TARGET roles, as login does. jdoe held grp-a's scope,
    then moves in the directory to an administrator-mapped group and out of grp-a. Read from the
    CURRENT roles, the scope would look withdrawn; read from the target, as login will, the
    Administrator keeps what is stored. So the one revocation is the role change, with no scope
    delta on it."""
    store, ldap, service, _ = await _scoped_service(_GRP_A)
    try:
        admins = "cn=mf-admins,dc=test,dc=invalid"
        await store.set_ad_group_role_map([(admins, "administrator")])
        ldap.present["jdoe"] = _principal("jdoe", admins)
        plan = await service.reconcile_directory_sessions()
        assert [(r.reason, r.scope_changed) for r in plan.revocations] == [("roles_changed", False)]
    finally:
        await store.close()


async def test_the_pass_judges_the_scope_stored_after_its_probes() -> None:
    """ADR 0198 Decision item 6. A login that lands while the pass is probing has already written
    the new scope. Judging the row listed before the probes would revoke the session that login just
    minted. The pass re-reads the row after probing, so it finds nothing to revoke."""
    store, ldap, service, _ = await _scoped_service(_GRP_A)
    try:
        ldap.present["jdoe"] = _principal("jdoe", _GRP_B)
        probe = service._probe_principal

        async def probe_then_login(user: Any) -> reconcile.Probe:
            result = await probe(user)
            # The login's own write, landing between the candidate listing and the re-read.
            await store.set_user_channel_scope(
                user.id, json.dumps(["IB_B"]), source=SCOPE_SOURCE_AD
            )
            return result

        service._probe_principal = probe_then_login  # type: ignore[method-assign]
        # The apply-time check would also stop this revocation, so watch the PLAN, not the result:
        # a revocation planned from the stale row reaches the apply step, and none may.
        planned: list[reconcile.SessionRevocation] = []
        apply = service._apply_reconcile_revocation

        async def spy(revocation: reconcile.SessionRevocation) -> bool:
            planned.append(revocation)
            return await apply(revocation)

        service._apply_reconcile_revocation = spy  # type: ignore[method-assign]
        plan = await service.reconcile_directory_sessions()
        assert planned == [], "the pass planned from the row listed before its probes"
        assert plan.revocations == ()
    finally:
        await store.close()


async def test_a_scope_revocation_is_skipped_when_the_scope_moved_before_it_applied() -> None:
    """ADR 0198 Decision item 6, the apply half. A login can also land after the re-read, while
    earlier revocations in the pass await their audit writes. The apply step re-reads the row and
    skips a scope revocation whose stored scope has moved. The returned plan says what the pass did,
    so the skipped revocation is not alerted either. A role revocation is never skipped."""
    store, ldap, service, _ = await _scoped_service(_GRP_A)
    try:
        ldap.present["jdoe"] = _principal("jdoe", _GRP_B)
        apply = service._apply_reconcile_revocation

        async def login_then_apply(revocation: reconcile.SessionRevocation) -> bool:
            await store.set_user_channel_scope(
                revocation.user_id, json.dumps(["IB_B"]), source=SCOPE_SOURCE_AD
            )
            return await apply(revocation)

        service._apply_reconcile_revocation = login_then_apply  # type: ignore[method-assign]
        plan = await service.reconcile_directory_sessions()
        assert plan.revocations == ()
        assert not [a for a in await store.list_audit() if a["action"] == "auth.ad_session_revoked"]
    finally:
        await store.close()


@pytest.mark.parametrize("now", [(), (_GRP_B,)], ids=["withdrawn", "narrowed"])
async def test_after_the_next_login_writes_the_new_scope_the_pass_does_not_revoke_again(
    now: tuple[str, ...],
) -> None:
    """AC-8, the #1532 loop guard. The pass revokes once; the user signs in again and login writes
    the scope the pass revoked for; every later pass finds nothing to revoke."""
    store, ldap, service, _ = await _scoped_service(_GRP_A)
    try:
        ldap.present["jdoe"] = _principal("jdoe", *now)
        first = await service.reconcile_directory_sessions()
        assert [r.reason for r in first.revocations] == [reconcile.SCOPE_CHANGED]

        token = await _signed_in_ad_user(service, store, "jdoe")
        assert token is not None
        expected = (json.dumps(["IB_B"]), "ad") if now else (None, "ad")
        assert await _scope_of(store, "jdoe") == expected
        for _ in range(3):
            plan = await service.reconcile_directory_sessions()
            assert plan.revocations == (), "the pass revoked again after login wrote the scope"
        assert await service.identity_for_token(token) is not None
    finally:
        await store.close()


async def test_a_scope_revocation_sends_no_account_disabled_notice() -> None:
    """The account is not disabled, so the notice that says it is would be false. Login's own scope
    re-sync sends no notice either; the audit row and the alert carry the event."""
    store, ldap, service, _ = await _scoped_service(_GRP_A)
    try:
        notifier = _CapturingNotifier()
        service._security_notifier = notifier
        ldap.present["jdoe"] = _principal("jdoe")
        plan = await service.reconcile_directory_sessions()
        assert [r.reason for r in plan.revocations] == [reconcile.SCOPE_CHANGED]
        assert notifier.sent == []
    finally:
        await store.close()
