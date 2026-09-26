# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""ASVS 6.3.2 (BACKLOG #1136) -- what a fresh install's user table actually holds.

The pinned verb asks that default user accounts *"are not present in the application or are
disabled"*. ADR 0183 Amendment A takes the first arm: ``AuthService.initialize()`` seeds the built-in
roles and creates no account, so a fresh store holds none until an operator runs
``messagefoundry provision-admin`` at the host. These tests pin that end state (AC-10).

They used to pin the opposite, on purpose: before Wave 2 a fresh store got an ENABLED account named
``admin`` holding Administrator, and these tests were written to turn red when that changed.

Severity is conditional (CLAUDE.md section 0): MessageFoundry has **zero deployments**, so this is
what a deploying site would get on first run, never a live exposure.

The persisted ``disabled`` column and the cross-backend contract below still matter: the disabled
arm stays unexpressible, which is why the "not present" arm is the one taken.
"""

from __future__ import annotations

import inspect
import re
from pathlib import Path

from messagefoundry.api import create_managed_app
from messagefoundry.auth.ldap import AdPrincipal
from messagefoundry.auth.permissions import Role
from messagefoundry.auth.service import AuthService
from messagefoundry.config.settings import AuthSettings
from messagefoundry.store.base import Store
from messagefoundry.store.store import MessageStore

# The three store classes, reused rather than re-derived — that module's docstring establishes the
# property this file depends on: the drivers are imported method-locally, so all three classes import
# on a bare venv and neither test below needs an ``importorskip`` gate.
from tests.test_store_capability_matrix import _BACKENDS

#: A bound parameter in any of the three dialects. Anything else in a VALUES slot is a literal.
_PLACEHOLDER = re.compile(r"\A(\?|\$\d+|%s)\Z")


async def _directory_signed_in(store: Store) -> str:
    """Complete one directory sign-in against ``store`` and return the username.

    Shared with ``tests/test_provision_first_administrator.py``, which builds on this measurement:
    a completed sign-in leaves a non-empty table with no administrator, so the provisioning guard
    cannot ask "is the table empty". Extracted rather than copied because two copies of one
    precondition can drift apart silently -- the same reason ``_BACKENDS`` is imported above.

    Driven through ``_complete_ad_login``, the shared tail every directory mechanism (Kerberos,
    simple bind, OIDC) ends at, which is the seam the neighbouring AD tests use.
    """
    principal = AdPrincipal(
        username="dana",
        display_name="Dana Example",
        email="dana@example.invalid",
        dn="cn=dana,ou=people,dc=example,dc=invalid",
        groups=frozenset({"cn=everyone,ou=groups,dc=example,dc=invalid"}),
    )
    outcome = await AuthService(store, AuthSettings())._complete_ad_login(
        principal, None, mfa_verified=True
    )
    assert outcome.ok, "the directory sign-in itself succeeds"
    return principal.username


async def test_a_fresh_store_gets_no_account(tmp_path: Path) -> None:
    """AC-10: ``serve`` on a store with no users creates no account, so neither arm needs a knob.

    Asserted at both altitudes. The service call is the unit; the lifespan is what ``serve`` runs,
    and it is where the account used to be minted and written to ``bootstrap-admin.txt``. The
    lifespan runs with sign-in required and the ADR 0167 gate skipped (notices off), so it starts on
    the empty store rather than refusing, and the assertion is about what the start wrote.
    """
    store = await MessageStore.open(":memory:")
    try:
        await AuthService(store, AuthSettings()).initialize()
        assert await store.count_users() == 0, "initialize() created an account"
        assert await store.get_user_by_username("admin") is None
        # Positive control: initialize() really ran, so the zero is not an untouched store.
        assert Role.ADMINISTRATOR.value in {r["id"] for r in await store.list_roles()}
    finally:
        await store.close()

    db = tmp_path / "fresh.db"
    app = create_managed_app(
        db_path=db,
        poll_interval=0.05,
        auth_settings=AuthSettings(enabled=True, notify_security_events=False),
    )
    async with app.router.lifespan_context(app):
        pass
    served = await MessageStore.open(db)
    try:
        assert await served.count_users() == 0, "the serve lifespan created an account"
    finally:
        await served.close()


def _disabled_values_slot(func: object) -> str:
    """The VALUES entry that ``create_user``'s INSERT puts in the ``disabled`` column.

    Read positionally off the statement's own column list rather than by a fixed index, so
    reordering the columns cannot make this silently inspect the wrong slot.
    """
    src = " ".join(inspect.getsource(func).replace('"', "").split())
    match = re.search(r"INSERT INTO users \((.*?)\) VALUES \((.*?)\)", src)
    assert match is not None, f"no INSERT INTO users found in {func!r}"
    columns = [c.strip() for c in match.group(1).split(",")]
    values = [v.strip() for v in match.group(2).split(",")]
    assert len(columns) == len(values), f"{len(columns)} columns against {len(values)} values"
    return values[columns.index("disabled")]


def test_no_store_backend_can_be_asked_to_create_a_disabled_account() -> None:
    """The 'disabled' arm is not merely unused — it is **unexpressible**, at two altitudes.

    ``create_user`` carries no ``disabled`` parameter on the :class:`Store` protocol, so no caller
    can request one; and each backend hardcodes the column rather than binding it, so the absent
    parameter is not merely unplumbed. Both are asserted because the signature alone would not catch
    an INSERT that started deciding the column for itself. Reaching the disabled arm of 6.3.2 is
    therefore a protocol change across three backends, not a keyword at the one call site — a cost
    the redesign has to price rather than discover.
    """
    signatures = {"protocol": Store.create_user} | {
        name: cls.create_user for name, cls in _BACKENDS.items()
    }
    for name, func in signatures.items():
        params = inspect.signature(func).parameters
        assert "disabled" not in params, f"{name}.create_user grew a 'disabled' parameter"
        # Positive control: the signature was really read. Without it a moved attribute or an empty
        # parameter mapping would satisfy the assertion above for the wrong reason.
        assert "username" in params, f"{name}.create_user signature did not read as expected"

    for name, cls in _BACKENDS.items():
        slot = _disabled_values_slot(cls.create_user)
        assert not _PLACEHOLDER.match(slot), (
            f"{name} now binds 'disabled' rather than hardcoding it"
        )
        assert slot.upper() in {"0", "FALSE"}, f"{name} hardcodes 'disabled' as {slot!r}, not false"


async def test_a_directory_sign_in_creates_a_roleless_row() -> None:
    """A completed directory sign-in makes ``count_users()`` non-zero and grants no role.

    This is the measurement behind the correction to #1136's researched work list. That research
    proposed provisioning the first administrator from an offline CLI command guarded by
    ``count_users() == 0``. The guard is only safe while nothing else can put the first row in the
    table, and a directory sign-in can. So the refusal guard asks whether an **enabled
    administrator** exists, not whether the table is empty.

    Since Wave 2 nothing seeds an administrator at startup, so this is the state an install with a
    directory wired can reach before anyone provisions. ``provision-admin`` still proceeds there;
    ``tests/test_provision_first_administrator.py`` pins that half.
    """
    store = await MessageStore.open(":memory:")
    try:
        service = AuthService(store, AuthSettings())
        username = await _directory_signed_in(store)

        user = await store.get_user_by_username(username)
        assert user is not None
        assert await store.count_users() == 1, "the table is no longer empty"
        assert await store.get_user_role_ids(user.id) == [], "and the row holds no role"

        # A start after the sign-in adds nothing and grants nothing.
        await service.initialize()
        assert await store.count_users() == 1
        assert await service.has_enabled_administrator() is False
    finally:
        await store.close()

    # Control arm, on a separate fixture: the assertions above must be able to tell the two store
    # states apart. Provisioned the one way an Administrator now comes to exist, the same role read
    # DOES return Administrator, so the empty role list above is a finding about the directory path
    # rather than about how this test reads roles.
    control = await MessageStore.open(":memory:")
    try:
        service = AuthService(control, AuthSettings())
        outcome = await service.provision_first_administrator(
            username="site-admin", password="a-long-enough-operator-passphrase", actor="test"
        )
        assert Role.ADMINISTRATOR.value in await control.get_user_role_ids(outcome.user_id)
        assert await service.has_enabled_administrator() is True
    finally:
        await control.close()
