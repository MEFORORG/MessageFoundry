# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""ASVS 6.3.2 (BACKLOG #1136) — what a fresh install's user table actually holds.

The pinned verb asks that default user accounts *"are not present in the application or are
disabled"*. These tests pin the shipped answer rather than assert the desired one: on a fresh store
the engine creates an **enabled** account named ``admin`` holding Administrator, so neither arm of
the verb holds at creation. The first-run redesign is expected to turn them red — that is what they
are for, and nothing here is a compensating control.

Severity is conditional (CLAUDE.md §0): MessageFoundry has **zero deployments**, so this is what a
deploying site would inherit on first run, never a live exposure. It is also not a default
*credential* — the password is per-install CSPRNG and must-change.

See also ``tests/test_auth_service.py::test_bootstrap_admin_created_once_and_can_log_in``, which
pins that the seeding happens once and the account can sign in. This module is complementary, not a
duplicate: it adds the persisted ``disabled`` column, the cross-backend contract, and the directory
precondition below.
"""

from __future__ import annotations

import inspect
import re

from messagefoundry.auth.ldap import AdPrincipal
from messagefoundry.auth.permissions import Role
from messagefoundry.auth.service import BOOTSTRAP_USERNAME, AuthService
from messagefoundry.config.settings import AuthSettings
from messagefoundry.store.base import Store
from messagefoundry.store.store import MessageStore

# The three store classes, reused rather than re-derived — that module's docstring establishes the
# property this file depends on: the drivers are imported method-locally, so all three classes import
# on a bare venv and neither test below needs an ``importorskip`` gate.
from tests.test_store_capability_matrix import _BACKENDS

#: A bound parameter in any of the three dialects. Anything else in a VALUES slot is a literal.
_PLACEHOLDER = re.compile(r"\A(\?|\$\d+|%s)\Z")


async def test_fresh_store_gets_an_enabled_account_named_admin() -> None:
    """Neither arm of 6.3.2 holds at creation: the account is present AND enabled.

    Pins all three halves the cell turns on — the well-known name, the persisted ``disabled``
    column, and the Administrator role — in one place, so a redesign cannot satisfy one and quietly
    drop another.
    """
    store = await MessageStore.open(":memory:")
    try:
        created = await AuthService(store, AuthSettings()).initialize()

        assert created is not None, "a fresh store must have produced a bootstrap credential"
        assert created.username == BOOTSTRAP_USERNAME == "admin"

        row = await store.get_user_by_username(BOOTSTRAP_USERNAME)
        assert row is not None, "the bootstrap account is PRESENT"
        assert row.disabled is False, "and ENABLED — so the 'disabled' arm does not hold either"
        assert Role.ADMINISTRATOR.value in await store.get_user_role_ids(row.id)

        # It is the ONLY account, so "a default account exists" describes the whole population.
        assert await store.count_users() == 1
    finally:
        await store.close()


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
    proposes provisioning the first administrator from an offline CLI command guarded by
    ``count_users() == 0``, on the ground that reusing the existing bootstrap guard widens no
    authority. The guard is only safe while nothing else can put the first row in the table, and a
    directory sign-in can. So the refusal guard has to ask whether an **enabled administrator**
    exists, not whether the table is empty.

    Today this strands nothing, because ``initialize()`` seeds the bootstrap admin at startup before
    any login can run. Removing the auto-create is what would open the window.
    """
    store = await MessageStore.open(":memory:")
    try:
        service = AuthService(store, AuthSettings())
        principal = AdPrincipal(
            username="dana",
            display_name="Dana Example",
            email="dana@example.invalid",
            dn="cn=dana,ou=people,dc=example,dc=invalid",
            groups=frozenset({"cn=everyone,ou=groups,dc=example,dc=invalid"}),
        )

        # The shared tail every directory mechanism ends at (Kerberos, simple bind, OIDC), driven at
        # the seam the neighbouring AD tests use. Deliberately NOT preceded by initialize(): this is
        # the store state the redesign creates, where nothing seeded an administrator first.
        outcome = await service._complete_ad_login(principal, None, mfa_verified=True)
        assert outcome.ok, "the directory sign-in itself succeeds"

        user = await store.get_user_by_username("dana")
        assert user is not None
        assert await store.count_users() == 1, "the table is no longer empty"
        assert await store.get_user_role_ids(user.id) == [], "and the row holds no role"

        # The sharp end. Run the shipped seeding path against this store and it declines, because its
        # guard asks the same "is the table empty" question the directory row already answered.
        assert await service.initialize() is None
        assert await store.get_user_by_username(BOOTSTRAP_USERNAME) is None
    finally:
        await store.close()

    # Control arm, on a separate fixture — the assertions above must be able to tell the two store
    # states apart. Against an untouched store the same calls DO yield an enabled administrator, so
    # the empty role list and the None above are findings about the directory path rather than about
    # how this test reads roles. It cannot be folded into the test above without losing that, nor
    # into the first test, which would leave this one uninterpretable when run alone.
    control = await MessageStore.open(":memory:")
    try:
        assert await AuthService(control, AuthSettings()).initialize() is not None
        seeded = await control.get_user_by_username(BOOTSTRAP_USERNAME)
        assert seeded is not None
        assert Role.ADMINISTRATOR.value in await control.get_user_role_ids(seeded.id)
    finally:
        await control.close()
