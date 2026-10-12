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

import ast
import inspect
import re
import textwrap
from collections.abc import Callable
from dataclasses import fields
from pathlib import Path
from typing import Any

from messagefoundry.api import create_managed_app
from messagefoundry.auth.ldap import AdPrincipal
from messagefoundry.auth.permissions import Role
from messagefoundry.auth.service import AuthService
from messagefoundry.config.settings import AuthSettings, EgressSettings
from messagefoundry.store.base import Store
from messagefoundry.store.store import MessageStore, UserRow, new_user_record
from tests._admin_account import provision_totp

# The three store classes, reused rather than re-derived — that module's docstring establishes the
# property this file depends on: the drivers are imported method-locally, so all three classes import
# on a bare venv and neither test below needs an ``importorskip`` gate.
from tests.test_store_capability_matrix import _BACKENDS


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
        directory_object_id="a79c897c-1793-5458-bd1b-b3ae0642c0e3",
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
        auth_settings=AuthSettings(notify_security_events=False),
        egress_settings=EgressSettings(deny_by_default=False),
    )
    async with app.router.lifespan_context(app):
        pass
    served = await MessageStore.open(db)
    try:
        assert await served.count_users() == 0, "the serve lifespan created an account"
    finally:
        await served.close()


def test_no_store_backend_can_be_asked_to_create_a_disabled_account() -> None:
    """The 'disabled' arm is not merely unused — it is **unexpressible**, at two altitudes.

    ``create_user`` carries no ``disabled`` parameter on the :class:`Store` protocol, so no caller
    can request one. Since BACKLOG #2592 every backend writes the whole sealed row through one
    INSERT that binds every column, ``disabled`` included, from :func:`new_user_record`. So the
    second altitude moved there: that builder takes no ``disabled`` parameter either, it sets the
    column to a literal False rather than deciding it from its inputs, and each backend's
    ``create_user`` calls it once. Both altitudes are asserted because the signature alone would
    not catch a row builder that started deciding the column for itself. Reaching the disabled arm
    of 6.3.2 is therefore a protocol change across three backends and the shared builder, not a
    keyword at the one call site — a cost the redesign has to price rather than discover. The call
    is read off each ``create_user``'s syntax tree, which does not show where its row goes;
    :func:`test_every_backend_binds_disabled_false_in_its_user_insert` checks the value each
    backend's INSERT really binds.
    """
    signatures = {"protocol": Store.create_user, "new_user_record": new_user_record} | {
        name: cls.create_user for name, cls in _BACKENDS.items()
    }
    for name, func in signatures.items():
        params = inspect.signature(func).parameters
        assert "disabled" not in params, f"{name} grew a 'disabled' parameter"
        # Positive control: the signature was really read. Without it a moved attribute or an empty
        # parameter mapping would satisfy the assertion above for the wrong reason.
        assert "username" in params, f"{name} signature did not read as expected"

    # The builder hardcodes the column. Read off its syntax tree, so a docstring or comment cannot
    # count, and a computed value (`disabled=password_hash is None`) is not a constant.
    keywords = [
        kw
        for node in ast.walk(_function_tree(new_user_record))
        if isinstance(node, ast.Call)
        for kw in node.keywords
    ]
    # Positive control: the walk reached the row's own keyword arguments, one per column.
    assert len(keywords) >= len(fields(UserRow)), f"read {len(keywords)} keyword arguments"
    disabled = [kw.value for kw in keywords if kw.arg == "disabled"]
    assert len(disabled) == 1, [ast.unparse(v) for v in disabled]
    assert isinstance(disabled[0], ast.Constant) and disabled[0].value is False, (
        f"new_user_record sets disabled={ast.unparse(disabled[0])}"
    )
    # A `**mapping` argument could set the column without naming it.
    assert all(kw.arg is not None for kw in keywords), "new_user_record passes a ** mapping"

    for name, cls in _BACKENDS.items():
        builds = [
            node
            for node in ast.walk(_function_tree(cls.create_user))
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "new_user_record"
        ]
        assert len(builds) == 1, f"{name}.create_user calls new_user_record {len(builds)} times"


def _function_tree(func: Callable[..., object]) -> ast.AST:
    """``func``'s own syntax tree, dedented so a method parses on its own."""
    return ast.parse(textwrap.dedent(inspect.getsource(func)))


#: Two account shapes, a local one with a credential and a directory one without, differing in the
#: provider, credential, profile and time inputs. Not every input: ``notify_email`` and ``audits``
#: stay at their defaults in both. The static test above is what rules out a derived value; these
#: check what the INSERT binds.
_ACCOUNT_SHAPES: list[dict[str, Any]] = [
    {
        "user_id": "u-local",
        "username": "local-op",
        "auth_provider": "local",
        "display_name": "Local Operator",
        "email": "local@example.invalid",
        "password_hash": "not-a-real-hash",
        "must_change_password": True,
        "password_generated": True,
        "now": 1_700_000_000.0,
    },
    {
        "user_id": "u-dir",
        "username": "dir-op",
        "auth_provider": "ad",
        "directory_object_id": "a79c897c-1793-5458-bd1b-b3ae0642c0e3",
        "password_generated": False,
        "adopt_notify_email": False,
        "now": 1_700_000_100.0,
    },
]


async def test_every_backend_binds_disabled_false_in_its_user_insert() -> None:
    """The behavioural half of the test above: what each backend's ``create_user`` really writes.

    SQLite runs for real and the row is read back. The two server backends need a live database, so
    their one write call, ``_execute_with_audits``, is captured instead, and the bound ``disabled``
    value is read off the captured statement's own column list. That list must equal the
    :class:`UserRow` field order the parameters are built in, so every slot lines up, and slots on
    both sides of ``disabled`` are checked against the inputs as the positive control.
    """
    sqlite = await MessageStore.open(":memory:")
    try:
        for shape in _ACCOUNT_SHAPES:
            await sqlite.create_user(**shape)
            user = await sqlite.get_user(str(shape["user_id"]))
            assert user is not None and user.username == shape["username"]
            assert user.disabled is False, f"SQLite created {shape['username']} disabled"
    finally:
        await sqlite.close()

    row_columns = [f.name for f in fields(UserRow)]
    exercised: list[str] = []
    for name, cls in _BACKENDS.items():
        if cls is MessageStore:
            continue
        exercised.append(name)
        store: Any = object.__new__(cls)  # the offline idiom: no pool, no I/O
        store._row_sealer = None  # what the constructor sets on a keyless store
        captured: list[tuple[str, tuple[object, ...]]] = []

        async def _capture(
            sql: str,
            params: tuple[object, ...],
            audits: object,
            *,
            now: float,
            _into: list[tuple[str, tuple[object, ...]]] = captured,
        ) -> None:
            _into.append((sql, tuple(params)))

        store._execute_with_audits = _capture
        for shape in _ACCOUNT_SHAPES:
            await store.create_user(**shape)
        assert len(captured) == len(_ACCOUNT_SHAPES), f"{name} wrote {len(captured)} statements"
        for (sql, params), shape in zip(captured, _ACCOUNT_SHAPES, strict=True):
            match = re.search(r"INSERT INTO users \((.*?)\) VALUES", " ".join(sql.split()))
            assert match is not None, f"{name}.create_user did not write an INSERT INTO users"
            columns = [c.strip() for c in match.group(1).split(",")]
            assert columns == row_columns, f"{name}'s INSERT columns are not in UserRow order"
            assert len(columns) == len(params), (
                f"{name}: {len(columns)} columns, {len(params)} params"
            )
            bound = dict(zip(columns, params, strict=True))
            assert bound["username"] == shape["username"], f"{name} slots misread"
            assert bound["created_at"] == shape["now"], f"{name} slots misread"
            assert bound["password_generated"] is shape["password_generated"], name
            assert bound["disabled"] is False, (
                f"{name} bound disabled={bound['disabled']!r} for {shape['username']}"
            )
    assert exercised == ["Postgres", "SQL Server"], exercised


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
            username="site-admin",
            password="a-long-enough-operator-passphrase",
            actor="test",
            **provision_totp(),
        )
        assert Role.ADMINISTRATOR.value in await control.get_user_role_ids(outcome.user_id)
        assert await service.has_enabled_administrator() is True
    finally:
        await control.close()
