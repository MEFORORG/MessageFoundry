# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #2697: the ``create_user`` username race at its last two unguarded call sites.

BACKLOG #1808 made a lost race on ``POST /users`` answer 409. Two other sites read the name, then
INSERT, with nothing between them: a directory account's first sign-in (``_upsert_ad_user``) and
``provision_first_administrator``. On a first deployment, two concurrent first sign-ins of one
directory user, or two provisioning runs, would have ended in the driver's integrity error -- a 500
on the sign-in, and on the CLI a "cannot open the store" report about a store that opened fine.

The race is made deterministic the way ``tests/test_auth_service.py`` makes #1808's: a rival row
takes the name between the read and the INSERT. Synthetic directory data only: invented names, DNs
and object ids.
"""

from __future__ import annotations

import asyncio
import json
import sqlite3
import sys
import time
import types
from pathlib import Path
from typing import Any

import pytest

from messagefoundry.__main__ import main
from messagefoundry.auth.identity import AuthProvider
from messagefoundry.auth.ldap import AdPrincipal
from messagefoundry.auth.permissions import Role
from messagefoundry.auth.service import (
    DIRECTORY_IDENTITY_CONFLICT,
    AuthService,
    FirstAdministratorRefused,
    _directory_login_refusal,
)
from messagefoundry.config.settings import AuthSettings
from messagefoundry.store.crypto import generate_key
from messagefoundry.store.store import MessageStore
from tests._admin_account import provision_totp

_OBJECT_ID = "0b6f2c1e-4d7a-4c55-9a1e-2f3d4c5b6a70"
_OTHER_OBJECT_ID = "9e8d7c6b-5a49-4382-a1b0-c9d8e7f6a5b4"
_PASSWORD = "a-long-enough-operator-passphrase"


def _principal(*, email: str = "pat.fielding@example.org") -> AdPrincipal:
    return AdPrincipal(
        username="pfielding",
        display_name="Pat Fielding",
        email=email,
        dn="CN=pfielding,OU=Staff,DC=example,DC=test",
        groups=frozenset(),
        directory_object_id=_OBJECT_ID,
    )


def _ad_settings() -> AuthSettings:
    return AuthSettings(
        ad_enabled=True,
        ad_server="ldaps://dc.example.test",
        ad_user_search_base="DC=example,DC=test",
        ad_bind_dn="CN=svc,DC=example,DC=test",
        ad_bind_password="x",
    )


async def _service() -> tuple[MessageStore, AuthService]:
    store = await MessageStore.open(":memory:")
    service = AuthService(store, _ad_settings())
    await service.initialize()
    return store, service


def _rival_takes_the_name(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch, **rival: Any
) -> None:
    """Make the next ``create_user`` lose the race: a rival row takes the name first, then the real
    insert runs and meets the UNIQUE index, as a concurrent create would. ``disabled`` and ``locked``
    are applied to the rival after its insert; every other keyword goes to the rival's
    ``create_user``."""
    original = store.create_user
    disabled = bool(rival.pop("disabled", False))
    locked = bool(rival.pop("locked", False))

    async def racing(**kwargs: Any) -> None:
        monkeypatch.setattr(store, "create_user", original)
        await original(
            user_id="rival", username=kwargs["username"], password_generated=False, **rival
        )
        if disabled:
            await store.set_user_disabled("rival", disabled=True)
        if locked:
            await store.record_login_failure(
                "rival", failed_attempts=5, locked_until=time.time() + 3600
            )
        await original(**kwargs)

    monkeypatch.setattr(store, "create_user", racing)


async def _failed_reasons(store: MessageStore) -> list[str]:
    return [
        json.loads(row["detail"])["reason"]
        for row in await store.list_audit()
        if row["action"] == "auth.login_failed"
    ]


# --- the directory first sign-in -----------------------------------------------------------------


async def test_two_concurrent_first_sign_ins_of_one_account_make_one_row_and_both_sign_in(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Both logins are held after their id-keyed read until both have made it, so each has seen no
    # row before either inserts. That is the race itself, with no rival planted by hand.
    store, service = await _service()
    try:
        original = store.get_user_by_directory_object_id
        arrived = 0
        both_read = asyncio.Event()

        async def held(directory_object_id: str) -> Any:
            nonlocal arrived
            found = await original(directory_object_id)
            arrived += 1
            if arrived >= 2:
                both_read.set()
            await asyncio.wait_for(both_read.wait(), timeout=5)
            return found

        monkeypatch.setattr(store, "get_user_by_directory_object_id", held)
        first, second = await asyncio.gather(
            service._complete_ad_login(_principal(), None, mfa_verified=True),
            service._complete_ad_login(_principal(), None, mfa_verified=True),
        )
        assert arrived == 2, "the barrier must have held both logins at the read"
        assert first.ok and second.ok
        assert first.identity is not None and second.identity is not None
        assert first.identity.user_id == second.identity.user_id
        # Signed in means a live session each, not only an ok outcome. The groups map to no role,
        # so the role resync revokes nothing; the mapped-role case is a race the service names.
        assert first.token is not None and second.token is not None
        assert await service.identity_for_token(first.token) is not None
        assert await service.identity_for_token(second.token) is not None
        assert await store.count_users() == 1
        row = await store.get_user_by_username("pfielding")
        assert row is not None and row.directory_object_id == _OBJECT_ID
        assert await _failed_reasons(store) == []
    finally:
        await store.close()


async def test_a_lost_race_to_the_same_account_adopts_the_winners_row(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store, service = await _service()
    try:
        _rival_takes_the_name(
            store,
            monkeypatch,
            auth_provider=AuthProvider.AD.value,
            directory_object_id=_OBJECT_ID,
        )
        out = await service._complete_ad_login(_principal(), None, mfa_verified=True)
        assert out.ok and out.identity is not None
        assert out.identity.user_id == "rival"
        assert await store.count_users() == 1
        # The adopted row then takes the existing-row path: the profile is refreshed onto it.
        row = await store.get_user("rival")
        assert row is not None and row.display_name == "Pat Fielding"
    finally:
        await store.close()


async def test_a_lost_race_to_a_different_directory_identity_is_refused_as_a_conflict(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # A recycled name: the row that won the INSERT carries another object's immutable id. Adopting
    # it would hand this person that row, its user_id and its roles (BACKLOG #1471).
    store, service = await _service()
    try:
        _rival_takes_the_name(
            store,
            monkeypatch,
            auth_provider=AuthProvider.AD.value,
            directory_object_id=_OTHER_OBJECT_ID,
            email="kept@example.org",
        )
        out = await service._complete_ad_login(_principal(), "10.0.0.7", mfa_verified=True)
        assert not out.ok and out.token is None
        assert out.error == "account conflict"
        assert out.reason == DIRECTORY_IDENTITY_CONFLICT
        assert await _failed_reasons(store) == [DIRECTORY_IDENTITY_CONFLICT]
        assert await store.list_sessions("rival") == []
        # Refused before any write: the rival's profile is untouched.
        row = await store.get_user("rival")
        assert row is not None and row.email == "kept@example.org"
        assert row.directory_object_id == _OTHER_OBJECT_ID
    finally:
        await store.close()


async def test_a_lost_race_to_a_directory_row_with_no_object_id_is_refused_not_adopted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # THE TAKEOVER SHAPE. A directory row with no immutable id proves nothing about whose it is, so
    # a guard that read a missing id as a match would hand this principal the winner's row, its
    # user_id and its roles.
    store, service = await _service()
    try:
        _rival_takes_the_name(
            store,
            monkeypatch,
            auth_provider=AuthProvider.AD.value,
            directory_object_id=None,
            email="kept@example.org",
        )
        out = await service._complete_ad_login(_principal(), "10.0.0.7", mfa_verified=True)
        assert not out.ok and out.token is None and out.identity is None
        assert out.error == "account conflict"
        assert out.reason == DIRECTORY_IDENTITY_CONFLICT
        assert await store.list_sessions("rival") == []
        assert await store.count_users() == 1
        # Refused before any write: the rival keeps its profile and its missing id.
        row = await store.get_user("rival")
        assert row is not None and row.email == "kept@example.org"
        assert row.directory_object_id is None
        # The conflict row names who asked, from where, and through which provider.
        failed = [row for row in await store.list_audit() if row["action"] == "auth.login_failed"]
        assert len(failed) == 1
        assert failed[0]["actor"] == "pfielding"
        assert failed[0]["client"] == "10.0.0.7"
        assert json.loads(failed[0]["detail"]) == {
            "provider": "ad",
            "reason": DIRECTORY_IDENTITY_CONFLICT,
        }
    finally:
        await store.close()


async def test_a_lost_race_to_a_locked_row_of_the_same_account_is_refused_as_locked(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # BACKLOG #1638 on the adopted row: a lock set on the winner is not cleared by the loser's
    # sign-in, and the refusal comes before the profile write.
    store, service = await _service()
    try:
        _rival_takes_the_name(
            store,
            monkeypatch,
            auth_provider=AuthProvider.AD.value,
            directory_object_id=_OBJECT_ID,
            email="kept@example.org",
            locked=True,
        )
        out = await service._complete_ad_login(_principal(), None, mfa_verified=True)
        assert not out.ok and out.token is None
        assert out.reason == "locked"
        assert await _failed_reasons(store) == ["locked"]
        row = await store.get_user("rival")
        assert row is not None and row.email == "kept@example.org"
        assert row.locked_until is not None and row.locked_until > time.time()
        assert await store.list_sessions("rival") == []
    finally:
        await store.close()


async def test_a_lost_race_to_a_local_account_is_refused_as_a_local_conflict(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store, service = await _service()
    try:
        _rival_takes_the_name(store, monkeypatch, auth_provider=AuthProvider.LOCAL.value)
        out = await service._complete_ad_login(_principal(), None, mfa_verified=True)
        assert not out.ok and out.error == "account conflict"
        assert out.reason == "local_account_conflict"
        assert await _failed_reasons(store) == ["local_account_conflict"]
        row = await store.get_user("rival")
        assert row is not None and row.auth_provider == AuthProvider.LOCAL.value
    finally:
        await store.close()


async def test_an_adopted_row_that_is_not_eligible_is_refused_before_any_write(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # BACKLOG #1637: the eligibility gate stays ahead of the first write for an adopted row too.
    store, service = await _service()
    try:
        _rival_takes_the_name(
            store,
            monkeypatch,
            auth_provider=AuthProvider.AD.value,
            directory_object_id=_OBJECT_ID,
            email="kept@example.org",
            disabled=True,
        )
        out = await service._complete_ad_login(_principal(), None, mfa_verified=True)
        row = await store.get_user("rival")
        assert row is not None
        expected = _directory_login_refusal(row, time.time(), federated=False)
        assert expected == "disabled"
        assert not out.ok and out.reason == expected
        assert await _failed_reasons(store) == [expected]
        assert row.email == "kept@example.org", "the profile write must not have run"
        assert await store.list_sessions("rival") == []
    finally:
        await store.close()


async def test_a_directory_integrity_refusal_with_no_holder_re_raises(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Control: only a row now holding the name makes this a lost race.
    store, service = await _service()
    try:

        async def refused(**_kwargs: object) -> None:
            raise sqlite3.IntegrityError("some other constraint")

        monkeypatch.setattr(store, "create_user", refused)
        with pytest.raises(sqlite3.IntegrityError, match="some other constraint"):
            await service._complete_ad_login(_principal(), None, mfa_verified=True)
    finally:
        await store.close()


# --- first-administrator provisioning ------------------------------------------------------------


async def test_a_lost_provisioning_race_is_refused_and_a_re_run_completes_the_row(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = await MessageStore.open(":memory:")
    try:
        service = AuthService(store, AuthSettings())
        _rival_takes_the_name(store, monkeypatch, auth_provider=AuthProvider.LOCAL.value)
        with pytest.raises(FirstAdministratorRefused, match="let it finish") as raised:
            await service.provision_first_administrator(
                username="site-admin", password=_PASSWORD, actor="test", **provision_totp()
            )
        assert isinstance(raised.value.__cause__, sqlite3.IntegrityError)
        # This run wrote nothing: the rival is as it was, roleless and with no credential.
        rival = await store.get_user("rival")
        assert rival is not None and rival.password_hash is None
        assert await store.get_user_role_ids("rival") == []
        assert await service.has_enabled_administrator() is False

        # The message's own instruction, followed: the re-run takes the repair branch.
        outcome = await service.provision_first_administrator(
            username="site-admin", password=_PASSWORD, actor="test", **provision_totp()
        )
        assert outcome.repaired is True and outcome.user_id == "rival"
        assert Role.ADMINISTRATOR.value in await store.get_user_role_ids("rival")
    finally:
        await store.close()


async def test_a_provisioning_integrity_refusal_with_no_holder_re_raises(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = await MessageStore.open(":memory:")
    try:
        service = AuthService(store, AuthSettings())

        async def refused(**_kwargs: object) -> None:
            raise sqlite3.IntegrityError("some other constraint")

        monkeypatch.setattr(store, "create_user", refused)
        with pytest.raises(sqlite3.IntegrityError, match="some other constraint"):
            await service.provision_first_administrator(
                username="site-admin", password=_PASSWORD, actor="test", **provision_totp()
            )
    finally:
        await store.close()


# --- the provision-admin CLI ---------------------------------------------------------------------


def _cli_ready(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """A terminal with the password typed twice, a store key in the shell, and the store's path.
    The suite-wide stub in ``tests/conftest.py`` answers the TOTP enrolment."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("MEFOR_STORE_ENCRYPTION_KEY", generate_key())
    monkeypatch.setattr(sys, "stdin", types.SimpleNamespace(isatty=lambda: True))
    queued = [_PASSWORD, _PASSWORD]
    monkeypatch.setattr("getpass.getpass", lambda *_a, **_k: queued.pop(0))
    return tmp_path / "provision.db"


def test_the_cli_reports_a_lost_race_as_the_refusal_not_as_a_bad_store(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # sqlite3.IntegrityError subclasses sqlite3.DatabaseError, so before this item the race reached
    # the CLI's store-open arm and was reported as "cannot open the store" with exit 2.
    db = _cli_ready(tmp_path, monkeypatch)
    original = MessageStore.create_user

    async def racing(self: MessageStore, **kwargs: Any) -> None:
        monkeypatch.setattr(MessageStore, "create_user", original)
        await original(
            self,
            user_id="rival",
            username=kwargs["username"],
            auth_provider=AuthProvider.LOCAL.value,
            password_generated=False,
        )
        await original(self, **kwargs)

    monkeypatch.setattr(MessageStore, "create_user", racing)
    rc = main(["provision-admin", "--username", "site-admin", "--db", str(db), "--json"])
    error = json.loads(capsys.readouterr().out)["error"]
    assert rc == 1
    assert "was created while this command ran" in error
    assert "cannot open the store" not in error


def test_the_cli_reports_an_unnamed_integrity_refusal_as_a_refused_write(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    db = _cli_ready(tmp_path, monkeypatch)

    async def refused(self: MessageStore, **_kwargs: object) -> None:
        raise sqlite3.IntegrityError("some other constraint")

    monkeypatch.setattr(MessageStore, "create_user", refused)
    rc = main(["provision-admin", "--username", "site-admin", "--db", str(db), "--json"])
    error = json.loads(capsys.readouterr().out)["error"]
    assert rc == 1
    assert error.startswith("the store refused one of this command's writes")
    assert "cannot open the store" not in error


class UniqueViolationError(Exception):
    """Stands in for asyncpg's class of that name, which shares no base with sqlite3's errors."""


def test_the_cli_reports_a_server_backends_integrity_refusal_as_a_refused_write(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    db = _cli_ready(tmp_path, monkeypatch)

    async def refused(self: MessageStore, **_kwargs: object) -> None:
        raise UniqueViolationError("duplicate key value violates unique constraint")

    monkeypatch.setattr(MessageStore, "create_user", refused)
    rc = main(["provision-admin", "--username", "site-admin", "--db", str(db), "--json"])
    error = json.loads(capsys.readouterr().out)["error"]
    assert rc == 1
    assert error.startswith("the store refused one of this command's writes")


# Driver-shaped text, one per backend family. Each fragment names schema or a key value the CLI must
# not print: the constraint, the table and column, and the duplicate value itself. The value is a
# synthetic marker rather than the username, so its absence cannot be confused with the username
# simply not being echoed anywhere else.
_SQLITE_DRIVER_TEXT = "UNIQUE constraint failed: users.username"
_SERVER_DRIVER_TEXT = (
    'duplicate key value violates unique constraint "users_username_key"\n'
    "DETAIL:  Key (username)=(zz-dup-key-value-7731) already exists."
)
_DRIVER_FRAGMENTS = (
    "UNIQUE constraint failed",
    "users.username",
    "users_username_key",
    "Key (username)",
    "zz-dup-key-value-7731",
    "duplicate key value",
)


@pytest.mark.parametrize("as_json", [True, False], ids=["json", "text"])
@pytest.mark.parametrize(
    ("raised", "class_name"),
    [
        (sqlite3.IntegrityError(_SQLITE_DRIVER_TEXT), "IntegrityError"),
        (UniqueViolationError(_SERVER_DRIVER_TEXT), "UniqueViolationError"),
    ],
    ids=["sqlite", "server"],
)
def test_the_cli_refused_write_names_the_class_and_never_the_driver_text(
    raised: Exception,
    class_name: str,
    as_json: bool,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    # The refused-write arm sits ahead of the CLI's redaction floor, which never formats the
    # exception. So it must not print what that floor would not: the arm once interpolated the
    # exception, and safe_exc would not help, because it keeps schema names and key values.
    db = _cli_ready(tmp_path, monkeypatch)

    async def refused(self: MessageStore, **_kwargs: object) -> None:
        raise raised

    monkeypatch.setattr(MessageStore, "create_user", refused)
    argv = ["provision-admin", "--username", "site-admin", "--db", str(db)]
    rc = main(argv + (["--json"] if as_json else []))
    captured = capsys.readouterr()
    assert rc == 1
    error = json.loads(captured.out)["error"] if as_json else captured.err.rsplit("error: ", 1)[1]
    assert error.startswith(f"the store refused one of this command's writes ({class_name})")
    for fragment in _DRIVER_FRAGMENTS:
        assert fragment not in captured.out, fragment
        assert fragment not in captured.err, fragment
