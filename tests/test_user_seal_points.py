# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The user seal's follow-ups (vault BACKLOG #3510).

1. Every TOTP check after the checked load takes the secret from the record the seal covered, so a
   secret swapped into the store after that load is never the one a code is checked against.
2. A sign-in whose write meets a record that stopped passing its seal after the load answers the
   sign-in's fixed refusal, and the loader reports the record.
3. ``admin-unlock`` and ``admin-reset-totp`` refuse such a record with a fixed message.
"""

from __future__ import annotations

import base64
import json
import time
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import pytest
from _totp_clock import pin_totp_clock

from messagefoundry.__main__ import main
from messagefoundry.auth import totp
from messagefoundry.auth.identity import Identity
from messagefoundry.auth.passwords import hash_password
from messagefoundry.auth.service import AUTHORITY_SEAL_FAILED_ACTION, AuthService
from messagefoundry.config.settings import AuthSettings
from messagefoundry.store.crypto import generate_key, make_cipher
from messagefoundry.store.row_seal import USER_KIND, RowSealError
from messagefoundry.store.store import MessageStore
from tests._admin_account import ADMIN_USERNAME, login_admin
from tests.test_user_seal import _raw_for

#: A secret the attacker controls, swapped in after the checked load. Derived, so a secret scanner
#: reading the source sees no key-shaped literal.
_ATTACKER = base64.b32encode(b"attacker-chosen-seed").decode("ascii")
_SETTINGS = AuthSettings(mfa_verify_min_elapsed_seconds=0, mfa_recovery_code_count=1)


@pytest.fixture
async def keyed(tmp_path: Path) -> AsyncIterator[tuple[MessageStore, Path]]:
    path = tmp_path / "sealed.db"
    store = await MessageStore.open(path, cipher=make_cipher(generate_key(), write_v2=True))
    try:
        yield store, path
    finally:
        await store.close()


class _Clock:
    """Pins the TOTP clock and moves it one step for every code, since a spent step is refused."""

    def __init__(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self._monkeypatch = monkeypatch
        self.now = 2_000_000.0

    def code(self, secret: str) -> str:
        self.now += totp.DEFAULT_PERIOD
        pin_totp_clock(self._monkeypatch, self.now)
        return totp.totp(secret, now=self.now)


def _swap_the_stored_secret(monkeypatch: pytest.MonkeyPatch, store: MessageStore) -> None:
    """Every later read of the TOTP cell returns the attacker's secret, which is what a swap after
    the load, undone before the next write, looks like to a second read."""

    async def swapped(user_id: str) -> str | None:
        return _ATTACKER

    monkeypatch.setattr(store, "get_totp_secret", swapped)


async def _enrolled(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> tuple[AuthService, Identity, str, str, _Clock]:
    """An Administrator with TOTP active: ``(service, identity, password, secret, clock)``."""
    service = AuthService(store, _SETTINGS)
    identity, token, password = await login_admin(service)
    enroll = await service.begin_mfa_enrollment(identity)
    clock = _Clock(monkeypatch)
    confirmed = await service.confirm_mfa_enrollment(
        identity, clock.code(enroll.secret), token=token
    )
    assert confirmed.ok
    return service, identity, password, enroll.secret, clock


# --- 1. the secret comes from the checked record ----------------------------------------------


async def test_the_second_step_checks_the_secret_the_seal_covered(
    keyed: tuple[MessageStore, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    store, _ = keyed
    service, identity, _, secret, clock = await _enrolled(store, monkeypatch)
    user = await service._load_user(identity.user_id)
    assert user is not None
    _swap_the_stored_secret(monkeypatch, store)
    assert await store.get_totp_secret(identity.user_id) == _ATTACKER  # the swap is live
    assert not await service._verify_second_factor(user, clock.code(_ATTACKER))
    assert await service._verify_second_factor(user, clock.code(secret))  # control


async def test_the_combined_sign_in_checks_the_secret_the_seal_covered(
    keyed: tuple[MessageStore, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    store, _ = keyed
    service, _, password, secret, clock = await _enrolled(store, monkeypatch)
    _swap_the_stored_secret(monkeypatch, store)
    refused = await service.login(ADMIN_USERNAME, password, totp_code=clock.code(_ATTACKER))
    assert not refused.ok and refused.error == "invalid credentials"
    signed_in = await service.login(ADMIN_USERNAME, password, totp_code=clock.code(secret))
    assert signed_in.ok and not signed_in.mfa_required  # control


async def test_the_enrolment_confirm_checks_the_secret_the_seal_covered(
    keyed: tuple[MessageStore, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    store, _ = keyed
    service = AuthService(store, _SETTINGS)
    identity, token, _ = await login_admin(service)
    enroll = await service.begin_mfa_enrollment(identity)
    clock = _Clock(monkeypatch)
    _swap_the_stored_secret(monkeypatch, store)
    refused = await service.confirm_mfa_enrollment(identity, clock.code(_ATTACKER), token=token)
    assert not refused.ok
    confirmed = await service.confirm_mfa_enrollment(
        identity, clock.code(enroll.secret), token=token
    )
    assert confirmed.ok  # control


# --- 2. a tamper between the load and a write -------------------------------------------------


async def _local_account(store: MessageStore, password: str) -> None:
    await store.create_user(
        user_id="u",
        username="u",
        auth_provider="local",
        password_hash=hash_password(password),
        password_generated=False,
    )


def _tamper_after_the_load(
    monkeypatch: pytest.MonkeyPatch, service: AuthService, path: Path
) -> None:
    """Change the row outside the store right after the sign-in's checked load, once."""
    real = service._load_user_by_username
    raw = _raw_for(path)
    tampered = False

    async def load_then_tamper(username: str) -> Any:
        nonlocal tampered
        user = await real(username)
        if not tampered:
            tampered = True
            await raw("UPDATE users SET display_name='forged' WHERE id=?", ("u",))
        return user

    monkeypatch.setattr(service, "_load_user_by_username", load_then_tamper)


@pytest.mark.parametrize("right_password", [True, False])
async def test_a_tamper_between_the_load_and_a_write_gives_the_sign_in_refusal(
    keyed: tuple[MessageStore, Path], monkeypatch: pytest.MonkeyPatch, right_password: bool
) -> None:
    """The right password reaches ``record_login_success`` and a wrong one the failure count; both
    are writes the store refuses on the changed record. Either way the caller gets the fixed
    refusal, not an exception, and the record is reported once."""
    store, path = keyed
    alerts: list[str] = []
    service = AuthService(store, AuthSettings(require_mfa=False), integrity_alert=alerts.append)
    await _local_account(store, "a-strong-passphrase-here")
    _tamper_after_the_load(monkeypatch, service, path)
    password = "a-strong-passphrase-here" if right_password else "wrong-passphrase-entirely"
    out = await service.login("u", password)
    assert not out.ok and out.error == "invalid credentials" and out.token is None
    assert len(alerts) == 1 and "u" in alerts[0]
    assert len(await store.list_audit(action=AUTHORITY_SEAL_FAILED_ACTION)) == 1


async def test_the_control_without_a_tamper_signs_in(keyed: tuple[MessageStore, Path]) -> None:
    store, _ = keyed
    service = AuthService(store, AuthSettings(require_mfa=False))
    await _local_account(store, "a-strong-passphrase-here")
    assert (await service.login("u", "a-strong-passphrase-here")).ok


# --- 3. the host commands ---------------------------------------------------------------------


def _refuse_with_a_seal_error(monkeypatch: pytest.MonkeyPatch, method: str) -> None:
    async def refuse(*_a: object, **_k: object) -> object:
        raise RowSealError(USER_KIND)

    monkeypatch.setattr(MessageStore, method, refuse)


def test_admin_unlock_refuses_a_record_that_fails_its_seal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from tests._phi_gate_provisions import setenv_at_rest_opt_out
    from tests.test_cli import _read_lock, _seed_locked

    monkeypatch.chdir(tmp_path)
    setenv_at_rest_opt_out(monkeypatch)
    db = tmp_path / "unlock.db"
    _seed_locked(db, locked_until=time.time() + 86_400)
    _refuse_with_a_seal_error(monkeypatch, "clear_lockout")
    assert main(["admin-unlock", "--username", "admin", "--db", str(db), "--json"]) == 1
    error = json.loads(capsys.readouterr().out)["error"]
    assert "integrity seal" in error and "nothing was written" in error.lower()
    assert "store key" in error and "outside the engine" in error  # both causes named
    monkeypatch.undo()
    locked_until, _ = _read_lock(db)
    assert locked_until is not None  # the lock stands


def test_admin_reset_totp_refuses_a_record_that_fails_its_seal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from tests.test_admin_reset_totp import _ADMIN, _CMD, _live_terminal, _seed, _state

    monkeypatch.chdir(tmp_path)
    db = tmp_path / "reset.db"
    _seed(db)
    before = _state(db)
    shown = _live_terminal(monkeypatch)
    _refuse_with_a_seal_error(monkeypatch, "replace_totp_enrolment")
    assert main([_CMD, "--username", _ADMIN, "--db", str(db), "--json"]) == 1
    error = json.loads(capsys.readouterr().out)["error"]
    assert "integrity seal" in error and "nothing was written" in error.lower()
    assert "store key" in error and "outside the engine" in error  # both causes named
    assert "delete it" in error  # the hint for the unused authenticator entry
    monkeypatch.undo()
    assert _state(db) == before
    assert shown == []


def test_admin_set_notify_email_refuses_a_record_that_fails_its_seal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The third host command that writes a user record refuses through its own write-failed
    path, not the dispatch floor."""
    from tests.test_admin_reset_totp import _ADMIN, _seed

    monkeypatch.chdir(tmp_path)
    db = tmp_path / "notify.db"
    _seed(db)
    _refuse_with_a_seal_error(monkeypatch, "set_user_notify_email")
    argv = ["admin-set-notify-email", "--username", _ADMIN, "--email", "ops@example.org"]
    assert main([*argv, "--db", str(db), "--json"]) == 1
    error = json.loads(capsys.readouterr().out)["error"]
    # The command's own refusal, which names the compensating row; the dispatch floor's does not.
    assert "integrity seal" in error and "_failed audit row was appended" in error


async def test_a_seal_refusal_of_another_kind_is_not_taken_for_the_account(
    keyed: tuple[MessageStore, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    """Only the account's own record is answered as a refused sign-in; another kind reaches its
    own handler, as it did before."""
    from messagefoundry.store.row_seal import SESSION_KIND

    store, _ = keyed
    service = AuthService(store, AuthSettings(require_mfa=False))
    await _local_account(store, "a-strong-passphrase-here")

    async def refuse(*_a: object, **_k: object) -> None:
        raise RowSealError(SESSION_KIND)

    monkeypatch.setattr(store, "record_login_success", refuse)
    with pytest.raises(RowSealError):
        await service.login("u", "a-strong-passphrase-here")
