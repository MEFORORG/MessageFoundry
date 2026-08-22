# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""BACKLOG #1137 layer 1 -- ``ad_enabled`` carried two unrelated meanings on one switch.

A single flag answered both "can this engine BIND to the directory" (which Kerberos SSO, federated
OIDC and the session reconciler all need) and "may a user type an AD password into our login form"
(a credential-accepting surface). Those are not the same decision, and fusing them meant an operator
who wanted federated login had to also expose AD password login, because ``oidc_enabled`` refuses to
validate without ``ad_enabled``.

The split: ``ad_enabled`` keeps the BIND meaning unchanged, and the new
``ad_password_login_enabled`` gates the login pathway alone. Default ``True``, so the split is
behaviour-preserving on its own -- whether AD password login should SURVIVE is layer 2, an owner
decision, deliberately not made here.

THE HAZARD THESE TESTS EXIST TO PIN is that the AD password re-bind is not only used by AD password
users. ``AuthProvider`` has exactly two members, so a Kerberos and an OIDC login are both stamped
``AD`` by the shared ``_complete_ad_login``, and ``reauth`` dispatches to ``_reauth_ad`` on that
stamp. Gating the re-bind on this new flag would therefore silently remove step-up for THREE
pathways while looking like it touched one.

All directory data here is synthetic.
"""

from __future__ import annotations

import pytest

from messagefoundry.auth.identity import AuthProvider
from messagefoundry.auth.ldap import AdPrincipal, LdapError
from messagefoundry.auth.service import AuthService
from messagefoundry.config.settings import AuthSettings
from messagefoundry.store.store import MessageStore


def _ad_settings(**over: object) -> AuthSettings:
    base: dict[str, object] = {
        "ad_enabled": True,
        "ad_server": "ldaps://dc.test.invalid",
        "ad_user_search_base": "OU=Staff,DC=test,DC=invalid",
        "ad_bind_dn": "CN=svc-mefor,OU=Service,DC=test,DC=invalid",
        "ad_bind_password": "synthetic",
    }
    base.update(over)
    return AuthSettings(**base)  # type: ignore[arg-type]


def _principal(username: str) -> AdPrincipal:
    return AdPrincipal(
        username=username,
        display_name=username.title(),
        email=f"{username}@test.invalid",
        dn=f"CN={username},OU=Staff,DC=test,DC=invalid",
        groups=frozenset({"CN=mf-operators,OU=Groups,DC=test,DC=invalid"}),
    )


class _FakeLdap:
    """A directory that accepts one synthetic credential. ``binds`` records password binds so a test
    can assert the pathway was not merely refused downstream but never reached the directory."""

    def __init__(self) -> None:
        self.binds: list[str] = []

    def authenticate(self, username: str, password: str) -> AdPrincipal | None:
        self.binds.append(username)
        if password == "synthetic-good":
            return _principal(username)
        return None

    def resolve_principal(self, username: str) -> AdPrincipal | None:
        return _principal(username)


# --- the two meanings are now separately expressible --------------------------


def test_ad_password_login_defaults_on_so_the_split_changes_no_behaviour() -> None:
    """Layer 1 is a SPLIT, not a policy change: a config that worked before works identically."""
    assert AuthSettings().ad_password_login_enabled is True
    assert _ad_settings().ad_password_login_enabled is True


def test_directory_bind_can_be_enabled_without_exposing_ad_password_login() -> None:
    """The combination that was previously inexpressible, which is the whole point of the item."""
    settings = _ad_settings(ad_password_login_enabled=False)
    assert settings.ad_enabled is True
    assert settings.ad_password_login_enabled is False


@pytest.mark.parametrize(
    ("dependent", "value"),
    [
        ("kerberos_enabled", True),
        ("ad_session_recheck_seconds", 60),
    ],
)
def test_bind_dependents_do_not_require_the_login_pathway(dependent: str, value: object) -> None:
    """Kerberos and the reconciler need the BIND, never the password form. With the meanings split
    they validate against a directory whose login pathway is off -- a configuration that could not
    be expressed at all before the split."""
    settings = _ad_settings(ad_password_login_enabled=False, **{dependent: value})
    assert settings.ad_password_login_enabled is False
    assert getattr(settings, dependent) == value


# --- the service-level view ---------------------------------------------------


async def test_service_reports_the_login_pathway_not_the_bind_capability() -> None:
    """``/auth/providers`` advertises what a client may OFFER. With the pathway off the AD affordance
    must disappear even though the directory connector is very much alive."""
    store = await MessageStore.open(":memory:")
    try:
        service = AuthService(
            store,
            _ad_settings(ad_password_login_enabled=False),
            ldap=_FakeLdap(),  # type: ignore[arg-type]
        )
        await service.initialize()
        assert service.ad_enabled is True  # the bind capability is unchanged
        assert service.ad_password_login_enabled is False  # the offered pathway is not
    finally:
        await store.close()


async def test_ad_login_is_refused_and_never_reaches_the_directory() -> None:
    """A refusal that still bound would leak whether a directory account exists, and would keep the
    credential-accepting surface the flag exists to remove."""
    store = await MessageStore.open(":memory:")
    try:
        ldap = _FakeLdap()
        service = AuthService(
            store,
            _ad_settings(ad_password_login_enabled=False),
            ldap=ldap,  # type: ignore[arg-type]
        )
        await service.initialize()
        outcome = await service.login("ad-user", "synthetic-good", provider=AuthProvider.AD)
        assert outcome.ok is False
        assert outcome.token is None
        assert ldap.binds == []  # never asked the directory
    finally:
        await store.close()


async def test_ad_login_still_works_when_the_pathway_is_left_on() -> None:
    """The negative control for the test above: same fixture, flag on, login succeeds. Without this
    a refusal caused by an unrelated misconfiguration would read as the flag working."""
    store = await MessageStore.open(":memory:")
    try:
        ldap = _FakeLdap()
        service = AuthService(store, _ad_settings(), ldap=ldap)  # type: ignore[arg-type]
        await service.initialize()
        outcome = await service.login("ad-user", "synthetic-good", provider=AuthProvider.AD)
        assert outcome.ok is True
        assert ldap.binds == ["ad-user"]
    finally:
        await store.close()


# --- the hazard --------------------------------------------------------------


async def test_step_up_re_bind_survives_the_login_pathway_being_disabled() -> None:
    """DO NOT "FINISH THE JOB" BY GATING ``_reauth_ad`` ON THIS FLAG.

    ``AuthProvider`` has two members, so ``_complete_ad_login`` stamps Kerberos and OIDC logins
    ``AD`` exactly as it stamps a password login, and ``reauth`` dispatches to ``_reauth_ad`` on that
    stamp. A Kerberos or OIDC user therefore re-proves a sensitive action through this same re-bind.
    Gating it here would look like a one-pathway change and would in fact remove step-up from three,
    which is the kind of total loss nobody would accept if it were stated out loud.

    The re-bind is a decision for layer 2, which must first say what a Kerberos identity re-proves
    WITH. Until then it stays reachable, and this test fails if someone closes it.
    """
    store = await MessageStore.open(":memory:")
    try:
        ldap = _FakeLdap()
        service = AuthService(
            store,
            _ad_settings(ad_password_login_enabled=False),
            ldap=ldap,  # type: ignore[arg-type]
        )
        await service.initialize()
        assert await service._reauth_ad("sso-user", "synthetic-good") is True
        assert ldap.binds == ["sso-user"]
    finally:
        await store.close()


async def test_step_up_re_bind_still_rejects_a_bad_credential() -> None:
    """Keeping the re-bind reachable must not make it permissive."""
    store = await MessageStore.open(":memory:")
    try:
        service = AuthService(
            store,
            _ad_settings(ad_password_login_enabled=False),
            ldap=_FakeLdap(),  # type: ignore[arg-type]
        )
        await service.initialize()
        assert await service._reauth_ad("sso-user", "synthetic-wrong") is False
    finally:
        await store.close()


async def test_step_up_re_bind_treats_a_directory_outage_as_a_refusal() -> None:
    """Fail-closed on the step-up path: an unreachable directory must not grant the action."""

    class _Down(_FakeLdap):
        def authenticate(self, username: str, password: str) -> AdPrincipal | None:
            raise LdapError("synthetic: LDAP socket closed")

    store = await MessageStore.open(":memory:")
    try:
        service = AuthService(
            store,
            _ad_settings(ad_password_login_enabled=False),
            ldap=_Down(),  # type: ignore[arg-type]
        )
        await service.initialize()
        assert await service._reauth_ad("sso-user", "synthetic-good") is False
    finally:
        await store.close()
