# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""ASVS 6.3.2 (BACKLOG #1136, ADR 0183) -- the offline first-administrator provisioning command.

``tests/test_first_run_default_account.py`` pins what the SHIPPED DEFAULT still does: run ``serve``
against an empty store and the engine mints an enabled account named ``admin``. This module pins the
route out of it. An operator who runs ``messagefoundry provision-admin`` before the first ``serve``
gets an install whose user table is non-empty, so the seeding path declines and no default account
is ever present.

That is the "not present" arm of the verb, reached by an operator action. The two files are
complementary and both must stay: the default is still what it was, and retiring the auto-create is
the remaining half of the item.

Severity is conditional (CLAUDE.md section 0): MessageFoundry has zero deployments, so everything
here describes what a deploying site would inherit, never a live exposure.
"""

from __future__ import annotations

import asyncio
import json
import sys
import time
import types
from pathlib import Path

import pytest

from messagefoundry.__main__ import main
from messagefoundry.auth.identity import AuthProvider
from messagefoundry.auth.permissions import Role
from messagefoundry.auth.service import (
    BOOTSTRAP_USERNAME,
    AuthService,
    FirstAdministratorRefused,
)
from messagefoundry.config.settings import AuthSettings
from messagefoundry.store.store import MessageStore

# The directory-sign-in precondition, imported rather than re-derived: that module is where it is
# measured, and this one only builds on it. Same convention as its own `_BACKENDS` import.
from tests.test_first_run_default_account import _directory_signed_in

# Low-entropy on purpose, matching the passphrases in tests/test_auth_service.py: a high-entropy
# literal here trips the gitleaks generic-api-key rule, and the honest fix is a synthetic value that
# does not look like a secret rather than an allowlist entry that teaches the scanner to skip one.
_PASSWORD = "a-long-enough-operator-passphrase"


async def test_provisioning_first_means_no_default_account_is_ever_present() -> None:
    """The headline: provision, then start, and the account named ``admin`` never exists.

    Both halves are asserted, because either alone would be satisfied for the wrong reason -- the
    provisioned administrator has to be usable, AND the seeding path has to decline.
    """
    store = await MessageStore.open(":memory:")
    try:
        service = AuthService(store, AuthSettings())
        outcome = await service.provision_first_administrator(
            username="site-admin", password=_PASSWORD, actor="test"
        )
        assert outcome.repaired is False

        row = await store.get_user_by_username("site-admin")
        assert row is not None and row.disabled is False
        assert Role.ADMINISTRATOR.value in await store.get_user_role_ids(row.id)
        assert row.auth_provider == AuthProvider.LOCAL.value

        # Usable, which is the anti-stranding half. Not must-change: the operator typed it.
        out = await service.login("site-admin", _PASSWORD)
        assert out.ok and out.must_change_password is False
        assert out.identity is not None and Role.ADMINISTRATOR in out.identity.roles

        # CLAIMED AT BIRTH. `password_claimed_at` is what keeps this account out of the WP-3
        # retirement sweep, and it is why there is no half-claimed state to restart into.
        claimed = await store.get_user_by_username("site-admin")
        assert claimed is not None and claimed.password_claimed_at is not None

        # And the sharp end: startup declines, so no default account is present.
        assert await service.initialize() is None
        assert await store.get_user_by_username(BOOTSTRAP_USERNAME) is None
    finally:
        await store.close()


async def test_it_refuses_once_an_enabled_administrator_exists() -> None:
    """Not a standing account-creation surface: with an administrator in place it declines."""
    store = await MessageStore.open(":memory:")
    try:
        service = AuthService(store, AuthSettings())
        assert await service.initialize() is not None  # the shipped default seeds one
        assert await service.has_enabled_administrator() is True

        with pytest.raises(FirstAdministratorRefused, match="already has an enabled Administrator"):
            await service.provision_first_administrator(
                username="second", password=_PASSWORD, actor="test"
            )
        assert await store.get_user_by_username("second") is None
    finally:
        await store.close()


async def test_the_guard_asks_for_an_administrator_not_an_empty_table() -> None:
    """The correction this command is built on: a directory sign-in fills the table with no admin.

    ``_upsert_ad_user`` creates a roleless row, so ``count_users() == 0`` -- the guard the 2026-08-20
    research proposed -- would refuse in exactly the state where the install has no way in. Once the
    auto-create is retired that refusal is a stranded install, which is this item's own named risk.
    """
    store = await MessageStore.open(":memory:")
    try:
        service = AuthService(store, AuthSettings())
        # The precondition is consumed from the module that measures it, not re-derived here.
        await _directory_signed_in(store)
        assert await store.count_users() == 1, "the table is no longer empty"
        assert await service.has_enabled_administrator() is False

        # The empty-table guard would have refused here. This one proceeds.
        await service.provision_first_administrator(
            username="site-admin", password=_PASSWORD, actor="test"
        )
        row = await store.get_user_by_username("site-admin")
        assert row is not None
        assert Role.ADMINISTRATOR.value in await store.get_user_role_ids(row.id)
    finally:
        await store.close()


@pytest.mark.parametrize("crashed_after", ["create", "set_password"])
async def test_an_interrupted_provision_is_completed_by_re_running(crashed_after: str) -> None:
    """A crash between the command's writes must not strand the install -- at EITHER crash point.

    The writes are create (no hash) -> set_password -> set_user_roles, so there are exactly two
    half-written states: an account that cannot be signed into, and one that can but holds no role.
    Both are parametrized here because the second is the one an earlier draft got wrong: it also
    refused a stamped ``password_claimed_at``, which ``set_password`` writes, so the second state
    was permanently un-repairable AND permanently exempt from WP-3 -- a stranded install.

    Driven through the store rather than by faking an exception, so each assertion is about the
    persisted row rather than about how the failure was simulated.
    """
    store = await MessageStore.open(":memory:")
    try:
        service = AuthService(store, AuthSettings())
        await store.create_user(
            user_id="halfwritten",
            username="site-admin",
            auth_provider=AuthProvider.LOCAL.value,
            display_name=None,
            email=None,
            password_hash=None,
            must_change_password=True,
        )
        if crashed_after == "set_password":
            await store.set_password(
                "halfwritten", password_hash="not-the-operators", must_change_password=False
            )
            row = await store.get_user_by_username("site-admin")
            assert row is not None and row.password_claimed_at is not None, "the state under test"
        # Either way the account is unusable to its intended holder: no credential at all, or one
        # they did not choose.
        assert (await service.login("site-admin", _PASSWORD)).ok is False

        outcome = await service.provision_first_administrator(
            username="site-admin", password=_PASSWORD, actor="test"
        )
        assert outcome.repaired is True and outcome.user_id == "halfwritten"
        # The operator's just-typed credential is authoritative, which matters on the second arm:
        # completing without rewriting it would leave them believing a password that does not work.
        assert (await service.login("site-admin", _PASSWORD)).ok
        assert Role.ADMINISTRATOR.value in await store.get_user_role_ids("halfwritten")
    finally:
        await store.close()


async def test_it_refuses_to_take_over_an_account_somebody_is_using() -> None:
    """The repair is narrow: it completes a ROLELESS local account and nothing else.

    Roleless is the one signal true at both interruption points, and it is also what makes the
    takeover safe -- such an account holds no permission to inherit. The three refusals below are
    the three shapes that are somebody's account rather than a half-written provision.
    """
    store = await MessageStore.open(":memory:")
    try:
        service = AuthService(store, AuthSettings())
        await service._seed_roles()

        await store.create_user(
            user_id="roled",
            username="bob",
            auth_provider=AuthProvider.LOCAL.value,
            password_hash=None,
            must_change_password=True,
        )
        await store.set_user_roles("roled", [Role.OPERATOR.value], assigned_by="test")
        with pytest.raises(FirstAdministratorRefused, match="holds roles"):
            await service.provision_first_administrator(
                username="bob", password=_PASSWORD, actor="test"
            )

        # Disabled is refused rather than silently revived -- and refusing rather than re-enabling
        # is what keeps a provision from reporting success on an account that cannot sign in.
        await store.create_user(
            user_id="off",
            username="carol",
            auth_provider=AuthProvider.LOCAL.value,
            password_hash=None,
        )
        await store.set_user_disabled("off", disabled=True)
        with pytest.raises(FirstAdministratorRefused, match="is disabled"):
            await service.provision_first_administrator(
                username="carol", password=_PASSWORD, actor="test"
            )

        # A directory row is never promoted, whatever its role state: its authority comes from the
        # directory, and this command has no standing to grant it engine roles.
        await store.create_user(
            user_id="dir",
            username="dana",
            auth_provider=AuthProvider.AD.value,
            password_hash=None,
        )
        with pytest.raises(FirstAdministratorRefused, match="provision a separate"):
            await service.provision_first_administrator(
                username="dana", password=_PASSWORD, actor="test"
            )
    finally:
        await store.close()


async def test_a_weak_password_is_refused_and_writes_nothing() -> None:
    """The credential is held to the active policy, and a refusal leaves no partial row behind."""
    store = await MessageStore.open(":memory:")
    try:
        service = AuthService(store, AuthSettings(password_min_length=20))
        with pytest.raises(FirstAdministratorRefused):
            await service.provision_first_administrator(
                username="site-admin", password="short", actor="test"
            )
        assert await store.count_users() == 0
    finally:
        await store.close()


async def test_provisioning_an_account_named_admin_survives_a_restart_past_the_expiry() -> None:
    """An operator may legitimately choose the name ``admin``, and it must not be auto-retired.

    ``_unclaimed_bootstrap`` matches on the username, so an unclaimed row under that name would be
    disabled once ``bootstrap_expiry_hours`` lapsed -- disabling the deployment's only administrator,
    headless, on the next boot. Stamping the claim at creation is what closes that.

    Driven through the operator-facing trigger the way the neighbouring WP-3 tests are: age
    ``created_at`` past the window, then run ``initialize()`` as a restart would, rather than calling
    the private sweep. That also proves the second half -- the restart does not re-bootstrap.
    """
    store = await MessageStore.open(":memory:")
    try:
        settings = AuthSettings(bootstrap_expiry_hours=72)
        outcome = await AuthService(store, settings).provision_first_administrator(
            username=BOOTSTRAP_USERNAME, password=_PASSWORD, actor="test"
        )
        await store._db.execute(  # arm the expiry arm: older than the window
            "UPDATE users SET created_at=? WHERE id=?",
            (time.time() - 99 * 3600, outcome.user_id),
        )
        await store._db.commit()

        restarted = AuthService(store, settings)
        assert await restarted.initialize() is None, "a non-empty store must not re-bootstrap"
        row = await store.get_user_by_username(BOOTSTRAP_USERNAME)
        assert row is not None and row.disabled is False
        assert (await restarted.login(BOOTSTRAP_USERNAME, _PASSWORD)).ok
    finally:
        await store.close()


async def test_a_supplied_address_lands_on_the_engine_owned_column() -> None:
    """``notify_email`` is what the PHI security-notice start gate reads. On the fresh path it
    arrives via ``create_user``'s seeding."""
    store = await MessageStore.open(":memory:")
    try:
        service = AuthService(store, AuthSettings())
        await service.provision_first_administrator(
            username="site-admin",
            password=_PASSWORD,
            notify_email="ops@example.invalid",
            actor="test",
        )
        fresh = await store.get_user_by_username("site-admin")
        assert fresh is not None and fresh.notify_email == "ops@example.invalid"
    finally:
        await store.close()


async def test_a_supplied_address_also_lands_on_a_repaired_row() -> None:
    """The repaired arm is separate because only the fresh one gets the column for free.

    A repaired row was created by an earlier run, so the seeding already happened without an address
    and the explicit write is the only thing that carries one.
    """
    store = await MessageStore.open(":memory:")
    try:
        service = AuthService(store, AuthSettings())
        await store.create_user(
            user_id="halfwritten",
            username="site-admin",
            auth_provider=AuthProvider.LOCAL.value,
            password_hash=None,
            must_change_password=True,
        )
        row = await store.get_user_by_username("site-admin")
        assert row is not None and row.notify_email is None, "control: it starts without one"

        await service.provision_first_administrator(
            username="site-admin",
            password=_PASSWORD,
            notify_email="ops@example.invalid",
            actor="test",
        )
        row = await store.get_user_by_username("site-admin")
        assert row is not None and row.notify_email == "ops@example.invalid"
    finally:
        await store.close()


async def test_a_blank_address_is_no_address_in_every_column_and_in_the_audit() -> None:
    """Normalized once, so the mirror, the notification column and the audit cannot disagree.

    A whitespace-only ``--email`` used to reach ``users.email`` untrimmed while auditing as though a
    notice target had been set -- three readers of one argument, each with its own idea of "supplied".
    """
    store = await MessageStore.open(":memory:")
    try:
        service = AuthService(store, AuthSettings())
        await service.provision_first_administrator(
            username="site-admin", password=_PASSWORD, notify_email="   ", actor="test"
        )
        row = await store.get_user_by_username("site-admin")
        assert row is not None and row.notify_email is None and row.email is None

        rows = [dict(r) for r in await store.list_audit(limit=50)]
        detail = next(
            json.loads(r["detail"])
            for r in rows
            if r["action"] == "auth.first_administrator_provisioned"
        )
        assert detail["notified"] is False
    finally:
        await store.close()


async def test_the_provision_is_audited() -> None:
    """Creating the most privileged account on the deployment is a control an attacker wants."""
    store = await MessageStore.open(":memory:")
    try:
        service = AuthService(store, AuthSettings())
        await service.provision_first_administrator(
            username="site-admin", password=_PASSWORD, actor="cli:tester"
        )
        rows = [dict(r) for r in await store.list_audit(limit=50)]
        provisioned = [r for r in rows if r["action"] == "auth.first_administrator_provisioned"]
        assert len(provisioned) == 1
        assert provisioned[0]["actor"] == "cli:tester"
        assert json.loads(provisioned[0]["detail"])["username"] == "site-admin"
    finally:
        await store.close()


# --- the CLI surface ---------------------------------------------------------------------------


def _tty(monkeypatch: pytest.MonkeyPatch, *entries: str) -> None:
    """Present a terminal and queue the prompt answers ``getpass`` will return."""
    monkeypatch.setattr(sys, "stdin", types.SimpleNamespace(isatty=lambda: True))
    queued = list(entries)
    monkeypatch.setattr("getpass.getpass", lambda *_a, **_k: queued.pop(0))


def test_cli_refuses_without_a_terminal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The unattended-install escape hatch is refused in terms rather than left to be added later.

    pytest's captured stdin is already not a terminal, so this runs against the real condition. The
    store must not be created either: a refusal that leaves a database behind would make the next
    ``serve`` see a non-empty directory and read as if something happened.
    """
    monkeypatch.chdir(tmp_path)
    db = tmp_path / "provision.db"
    assert main(["provision-admin", "--username", "site-admin", "--db", str(db), "--json"]) == 1
    assert "no --password" in json.loads(capsys.readouterr().out)["error"]
    assert not db.exists()


def test_cli_has_no_password_flag(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A negative control on the parser, not on the docstring above it."""
    monkeypatch.chdir(tmp_path)
    for flag in ("--password", "--password-file"):
        with pytest.raises(SystemExit) as exc:
            main(["provision-admin", "--username", "site-admin", flag, "x"])
        assert exc.value.code == 2


def test_cli_refuses_a_mismatched_confirmation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """A typo in a credential nobody can read back is exactly how an install gets stranded."""
    monkeypatch.chdir(tmp_path)
    _tty(monkeypatch, _PASSWORD, _PASSWORD + "typo")
    db = tmp_path / "provision.db"
    assert main(["provision-admin", "--username", "site-admin", "--db", str(db), "--json"]) == 1
    assert "did not match" in json.loads(capsys.readouterr().out)["error"]


def test_cli_provisions_and_names_the_store_it_wrote_to(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """End to end, and the resolved store path is in the output.

    Unlike ``admin-unlock`` this command legitimately CREATES the SQLite store, so it cannot carry
    M-31's "refuse a missing store" guard. Naming the path is the substitute: a mistyped ``--db``
    would otherwise provision into a store ``serve`` never opens, and ``serve`` would then mint the
    default account anyway -- with the command having reported success.
    """
    monkeypatch.chdir(tmp_path)
    _tty(monkeypatch, _PASSWORD, _PASSWORD)
    db = tmp_path / "provision.db"
    assert (
        main(
            [
                "provision-admin",
                "--username",
                "site-admin",
                "--email",
                "ops@example.invalid",
                "--db",
                str(db),
            ]
        )
        == 0
    )
    out = capsys.readouterr().out
    assert str(db) in out
    assert "WARNING" not in out, "an address was supplied, so the PHI warning must not fire"

    async def check() -> None:
        store = await MessageStore.open(db)
        try:
            row = await store.get_user_by_username("site-admin")
            assert row is not None
            assert Role.ADMINISTRATOR.value in await store.get_user_role_ids(row.id)
            # The seeding path declines against this store, which is the whole point.
            assert await AuthService(store, AuthSettings()).initialize() is None
            assert await store.get_user_by_username(BOOTSTRAP_USERNAME) is None
        finally:
            await store.close()

    asyncio.run(check())


def test_cli_warns_when_no_notification_address_is_given(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The address is optional here and the PHI start gate stays the single authority on it.

    Duplicating that gate's rule in the CLI would be a second, silently different copy of it, so the
    command warns and names the flag instead of inventing its own refusal.
    """
    monkeypatch.chdir(tmp_path)
    _tty(monkeypatch, _PASSWORD, _PASSWORD)
    assert (
        main(["provision-admin", "--username", "site-admin", "--db", str(tmp_path / "p.db")]) == 0
    )
    assert "WARNING: no notification address" in capsys.readouterr().out
