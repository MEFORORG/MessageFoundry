# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""BACKLOG #1137 -- the directory simple-bind LOGIN pathway is retired; the BIND is not.

``ad_enabled`` used to answer two unrelated questions on one switch: "can this engine BIND to the
directory" (which Kerberos SSO, federated OIDC and the session reconciler all need) and "may a user
type an AD password into our login form" (a credential-accepting surface). Layer 1 split them.
Layer 2, on the owner's ruling of 2026-08-22, RETIRED the second: supporting AD is not supporting
simple bind, every real AD deployment already provides Kerberos, and current good practice is that
an application does not collect directory credentials.

Retired rather than defaulted off, because an off-by-default control is one edit from being on --
removal is what makes it a property of the engine.

THE HAZARD THESE TESTS EXIST TO PIN is that the AD password re-bind is not only used by AD password
users. ``AuthProvider`` has exactly two members, so a Kerberos and an OIDC login are both stamped
``AD`` by the shared ``_complete_ad_login``, and ``reauth`` dispatches to ``_reauth_ad`` on that
stamp. **So the step-up re-bind deliberately SURVIVES the login pathway.** Removing both together
would silently take step-up from three pathways while looking like it touched one -- see
docs/research/ad-step-up-after-simple-bind-retirement.md.

The unmeasured cost the ruling carries: a client that cannot obtain a Kerberos ticket loses AD login
with no fallback, and nobody has measured how common that is.

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


# --- the pathway is gone, the bind is not -------------------------------------


def test_the_login_pathway_setting_no_longer_exists() -> None:
    """Layer 2 RETIRED the pathway rather than defaulting it off.

    An off-by-default control is still a control an operator can switch on, so leaving the setting
    would leave the credential-collecting surface one edit away. Removing it is what makes the
    retirement a property of the engine instead of a default.
    """
    assert not hasattr(AuthSettings(), "ad_password_login_enabled")
    assert not hasattr(_ad_settings(), "ad_password_login_enabled")


@pytest.mark.parametrize(
    ("dependent", "value"),
    [
        ("kerberos_enabled", True),
        ("ad_session_recheck_seconds", 60),
    ],
)
def test_the_bind_dependents_are_untouched_by_the_retirement(dependent: str, value: object) -> None:
    """Kerberos and the session reconciler need the BIND, never the password form. Retiring the
    login pathway must leave them configurable and valid -- they are the replacement, so breaking
    them would remove the thing the ruling relies on."""
    settings = _ad_settings(**{dependent: value})
    assert settings.ad_enabled is True
    assert getattr(settings, dependent) == value


# --- the service-level view ---------------------------------------------------


async def test_the_service_still_reports_the_bind_capability(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """``ad_enabled`` survives the retirement and that is CORRECT, not a leftover.

    It answers "can this engine bind to the directory", which Kerberos SSO, federated OIDC and the
    step-up re-bind all still need. A retirement that switched it off would take those three with
    it.
    """
    store = await MessageStore.open(":memory:")
    try:
        service = AuthService(
            store,
            _ad_settings(),
            ldap=_FakeLdap(),  # type: ignore[arg-type]
        )
        await service.initialize()
        assert service.ad_enabled is True
        # And the retired pathway is not reachable through the service surface either.
        assert not hasattr(service, "ad_password_login_enabled")
    finally:
        await store.close()


async def test_ad_login_is_refused_and_never_reaches_the_directory() -> None:
    """A refusal that still bound would leak whether a directory account exists, and would keep the
    credential-accepting surface the flag exists to remove."""
    store = await MessageStore.open(":memory:")
    try:
        ldap = _FakeLdap()
        service = AuthService(store, _ad_settings(), ldap=ldap)  # type: ignore[arg-type]
        await service.initialize()
        outcome = await service.login("ad-user", "synthetic-good", provider=AuthProvider.AD)
        assert outcome.ok is False
        assert outcome.token is None
        assert ldap.binds == []  # never asked the directory
    finally:
        await store.close()


async def test_the_refusal_is_the_retirement_and_not_a_broken_fixture() -> None:
    """THE CONTROL for the refusal above, rebuilt for a world where the login can never succeed.

    Previously this asserted the same fixture logging in with the flag on. That control is gone with
    the pathway, and dropping it would leave the refusal indistinguishable from a misconfigured fake
    -- a test that passes because nothing works at all.

    So the control moves to the credential path that SURVIVES: the same service, the same fake
    directory and the same synthetic password still bind successfully through the step-up re-bind.
    A working bind beside a refused login is what makes the refusal mean the pathway was retired.
    """
    store = await MessageStore.open(":memory:")
    try:
        ldap = _FakeLdap()
        service = AuthService(store, _ad_settings(), ldap=ldap)  # type: ignore[arg-type]
        await service.initialize()

        refused = await service.login("ad-user", "synthetic-good", provider=AuthProvider.AD)
        assert refused.ok is False
        assert ldap.binds == []  # never reached the directory

        # CONTROL: the identical credential still binds on the surviving path.
        assert await service._reauth_ad("ad-user", "synthetic-good") is True
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
        service = AuthService(store, _ad_settings(), ldap=ldap)  # type: ignore[arg-type]
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
