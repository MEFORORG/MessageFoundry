# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""``messagefoundry admin-create`` — the operator route to the FIRST administrator (BACKLOG #1020).

The implicit first-run bootstrap account was retired because ASVS 6.3.2 wants no default account to
exist, and an engine nobody can sign into is not the stricter end state — it is a broken one. So the
removal and this command are one change, and these are the tests that hold the pair together:

* the OLD behaviour is gone — a fresh store reaches ``serve`` with zero users and no privileged
  account appears by itself; and
* the NEW route works end to end — the command drives that same fresh store to an account that can
  authenticate against the real API and reach an authorization-gated route.

Both directions matter. Either one alone would pass while the product was unusable or unsafe.

The command is driven in-process through ``main()`` (the CLI-dispatch precedent in
``tests/test_cli_backup_dispatch.py``) rather than as a subprocess: there is then no ambient PATH,
interpreter or venv the result could silently depend on. ``_admin_create`` calls ``asyncio.run``, so
every test here is deliberately SYNC — an async test would already own the session event loop.
"""

from __future__ import annotations

import asyncio
import io
import os
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import httpx
import pytest

from messagefoundry.__main__ import main
from messagefoundry.api import create_app
from messagefoundry.auth import Role
from messagefoundry.auth.service import AuthService
from messagefoundry.config.settings import AuthSettings
from messagefoundry.pipeline import Engine
from messagefoundry.store.store import MessageStore

PW = "a-strong-operator-passphrase"

#: The env keys the CLI's own settings load would honour. Left ambient, `MEFOR_STORE_PATH` sends the
#: command at a DIFFERENT database than the one the test asserts on, and `MEFOR_AUTH_*` moves the
#: password policy out from under it — measured 2026-08-10: with those two set, 7 of these 9 tests
#: fail. They fail loudly rather than passing falsely, but a green that depends on the developer's
#: shell is not a green either way, so the env is pinned and `test_the_env_pin_holds_under_a_hostile_
#: ambient_value` is the positive control proving the pin is what makes it so.
_ENV_PREFIX = "MEFOR_"
#: Set by tests/conftest.py for per-process test isolation (slot, port base, Qt org) — these are not
#: settings the CLI reads, and clearing them would break the isolation they exist for.
_KEEP = ("MEFOR_TEST_",)


@pytest.fixture(autouse=True)
def _pinned_env(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    for key in list(os.environ):
        if key.startswith(_ENV_PREFIX) and not key.startswith(_KEEP):
            monkeypatch.delenv(key, raising=False)
    yield


def _service_toml(tmp_path: Path, db: Path) -> str:
    toml = tmp_path / "messagefoundry.toml"
    toml.write_text(f'[store]\npath = "{db.as_posix()}"\n', encoding="utf-8")
    return str(toml)


def _run_admin_create(
    monkeypatch: pytest.MonkeyPatch, toml: str, *args: str, password: str = PW
) -> int:
    """Invoke the command with ``password`` on stdin. The password is never an argv element — see
    ``_read_new_password``: argv is readable by other accounts on the box."""
    monkeypatch.setattr("sys.stdin", io.StringIO(password + "\n"))
    return main(["admin-create", "--service-config", toml, "--password-stdin", *args])


async def _users(db: Path) -> list[tuple[str, bool, list[str]]]:
    store = await MessageStore.open(str(db))
    try:
        out = []
        for user in await store.list_users():
            out.append(
                (user.username, user.must_change_password, await store.get_user_role_ids(user.id))
            )
        return out
    finally:
        await store.close()


# --- the OLD behaviour is gone ------------------------------------------------------------------


def test_a_fresh_store_gets_no_account_from_starting_the_engine(tmp_path: Path) -> None:
    """RED when an implicit first-run account comes back.

    This is the half that is easy to lose: a reintroduced bootstrap would leave every other test in
    the suite green, because a working admin account is what they all want."""

    async def run() -> tuple[int, Any]:
        store = await MessageStore.open(str(tmp_path / "fresh.db"))
        try:
            service = AuthService(store, AuthSettings())
            await service.initialize()  # what the API lifespan calls on every start
            await service.initialize()  # ...and again on the next start
            return await store.count_users(), await store.get_user_by_username("admin")
        finally:
            await store.close()

    count, admin = asyncio.run(run())
    assert count == 0
    assert admin is None


# --- the NEW route works ------------------------------------------------------------------------


def test_admin_create_makes_an_administrator_on_a_fresh_store(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    db = tmp_path / "mf.db"
    rc = _run_admin_create(monkeypatch, _service_toml(tmp_path, db), "--username", "alice")
    assert rc == 0
    out = capsys.readouterr()
    # The resolved store path is named back, so a --db/[store].path typo shows up here rather than as
    # a login failure against the engine's real database much later.
    assert "alice" in out.out and db.name in out.out
    assert PW not in out.out and PW not in out.err  # the credential is never echoed

    assert asyncio.run(_users(db)) == [("alice", False, ["administrator"])]


def test_admin_create_then_the_api_authenticates_that_account(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The behavioural acceptance test: a FRESH store, the new route, then a real authenticated
    session over the engine's own API reaching an authorization-gated route."""
    db = tmp_path / "mf.db"
    assert _run_admin_create(monkeypatch, _service_toml(tmp_path, db), "--username", "alice") == 0

    async def run() -> tuple[int, int, str]:
        engine = await Engine.create(db, poll_interval=0.02)
        try:
            # require_mfa=False keeps this test about PROVISIONING; the second factor an operator
            # then enrolls is covered by tests/test_mfa.py.
            service = AuthService(engine.store, AuthSettings(require_mfa=False))
            await service.initialize()
            transport = httpx.ASGITransport(app=create_app(engine, auth=service))
            async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
                login = await c.post(
                    "/auth/login",
                    json={"username": "alice", "password": PW, "provider": "local"},
                )
                token = login.json().get("token", "")
                h = {"Authorization": f"Bearer {token}"}
                me = await c.get("/auth/me", headers=h)
                gated = await c.get("/users", headers=h)
                return login.status_code, gated.status_code, me.json().get("username", "")
        finally:
            await engine.stop()

    login_status, gated_status, username = asyncio.run(run())
    assert login_status == 200 and username == "alice"
    # /users is USERS_MANAGE-gated, so a 200 proves the account carries real administrator authority
    # — not merely that some session was minted. No password rotation stood in the way.
    assert gated_status == 200


# --- refusals -----------------------------------------------------------------------------------


def test_admin_create_refuses_a_duplicate_username(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    toml = _service_toml(tmp_path, tmp_path / "mf.db")
    assert _run_admin_create(monkeypatch, toml, "--username", "alice") == 0
    capsys.readouterr()
    assert _run_admin_create(monkeypatch, toml, "--username", "alice") == 2
    assert "already exists" in capsys.readouterr().err


def test_admin_create_holds_the_password_to_the_deployments_own_policy(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # The policy comes from the resolved [auth] settings, not a CLI-local default: the command must
    # not be a second, laxer way into the same account store.
    db = tmp_path / "mf.db"
    toml = tmp_path / "messagefoundry.toml"
    toml.write_text(
        f'[store]\npath = "{db.as_posix()}"\n\n[auth]\npassword_min_length = 40\n', encoding="utf-8"
    )
    rc = _run_admin_create(monkeypatch, str(toml), "--username", "alice")
    assert rc == 2
    assert "password must" in capsys.readouterr().err
    assert not db.exists() or asyncio.run(_users(db)) == []


def test_admin_create_refuses_an_empty_password(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    toml = _service_toml(tmp_path, tmp_path / "mf.db")
    assert _run_admin_create(monkeypatch, toml, "--username", "alice", password="") == 2
    assert "no password supplied" in capsys.readouterr().err


def test_admin_create_warns_when_no_email_is_set(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # BACKLOG #1020's original finding was that the first administrator had no deliverable address,
    # so the out-of-band security notices for the most privileged account silently no-opped. The
    # account is gone, but the hole it exposed is a property of ANY privileged account with no
    # address — so the operator route says so at the moment the account is made, and takes one.
    toml = _service_toml(tmp_path, tmp_path / "mf.db")
    assert _run_admin_create(monkeypatch, toml, "--username", "alice") == 0
    assert "no --email" in capsys.readouterr().err

    toml2 = _service_toml(tmp_path, tmp_path / "mf2.db")
    assert (
        _run_admin_create(monkeypatch, toml2, "--username", "bob", "--email", "bob@example.org")
        == 0
    )
    assert "no --email" not in capsys.readouterr().err

    async def email_of(db: Path, username: str) -> str | None:
        store = await MessageStore.open(str(db))
        try:
            user = await store.get_user_by_username(username)
            assert user is not None
            return user.email
        finally:
            await store.close()

    assert asyncio.run(email_of(tmp_path / "mf2.db", "bob")) == "bob@example.org"


def test_admin_create_audits_the_account_it_made(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    db = tmp_path / "mf.db"
    assert _run_admin_create(monkeypatch, _service_toml(tmp_path, db), "--username", "alice") == 0

    async def actions() -> list[str]:
        store = await MessageStore.open(str(db))
        try:
            return [row["action"] for row in await store.list_audit()]
        finally:
            await store.close()

    # The most privileged account on the box must not be creatable without a durable record of it.
    assert "user.created" in asyncio.run(actions())


def test_the_env_pin_is_load_bearing_and_the_hazard_is_real(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Two halves, because either alone would be a claim rather than a measurement.

    1. The pin is OBSERVABLE: inside a pinned test no ``MEFOR_`` setting key survives, whatever the
       developer's shell exported. RED when ``_pinned_env`` stops clearing the prefix.
    2. The hazard it pins against is REAL: with ``MEFOR_STORE_PATH`` deliberately set, the command
       follows it and writes somewhere the test never named. That is the behaviour every other test
       in this file would otherwise be exposed to.
    """
    assert not [k for k in os.environ if k.startswith(_ENV_PREFIX) and not k.startswith(_KEEP)], (
        "the autouse env pin did not clear the MEFOR_ settings prefix"
    )

    named = tmp_path / "named.db"
    hostile = tmp_path / "hostile.db"
    monkeypatch.setenv("MEFOR_STORE_PATH", str(hostile))
    assert (
        _run_admin_create(monkeypatch, _service_toml(tmp_path, named), "--username", "alice") == 0
    )
    assert hostile.exists() and not named.exists()  # it went where the ENV said, not the config


def test_the_created_account_holds_the_administrator_role_object(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    db = tmp_path / "mf.db"
    assert _run_admin_create(monkeypatch, _service_toml(tmp_path, db), "--username", "alice") == 0

    async def roles() -> frozenset[Role]:
        store = await MessageStore.open(str(db))
        try:
            service = AuthService(store, AuthSettings(require_mfa=False))
            out = await service.login("alice", PW)
            assert out.ok and out.identity is not None
            return out.identity.roles
        finally:
            await store.close()

    assert Role.ADMINISTRATOR in asyncio.run(roles())
