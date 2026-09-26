# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""ADR 0183 Amendment A, Wave 1c (BACKLOG #1136): the offline notification-address setter.

``provision-admin`` without ``--email`` succeeds with a warning, and under the shipped posture the
next start is then refused by the ADR 0167 gate, because no enabled Administrator carries a
notification address. Before this command nothing offline fixed that: ``provision-admin`` refuses
once an enabled Administrator exists, the web console cannot be reached while the engine refuses
to start, and the only exits traded a control away (the audited waiver, or ``warn``).

``admin-set-notify-email`` is that offline fix, on the same host gate as ``admin-unlock`` (ADR 0171).
It is deliberately narrow: it FILLS an absent address on an enabled Administrator, and it can neither
clear an address nor repoint one. Repointing offline would move where notices go with no
``EMAIL_CHANGED`` notice to the old address, because no notifier runs here; the web console is
where an address is changed.

Severity is conditional (CLAUDE.md section 0): zero deployments, so everything here describes what a
deploying site would hit, never a live exposure. All addresses are synthetic ``.invalid`` domains.
"""

from __future__ import annotations

import asyncio
import json
import sqlite3
from pathlib import Path

import pytest

from messagefoundry.__main__ import main
from messagefoundry.api import create_managed_app
from messagefoundry.auth.permissions import Role
from messagefoundry.auth.service import AuthService
from messagefoundry.config.settings import (
    AlertsSettings,
    AuthSettings,
    SecurityEnforcement,
    SecuritySettings,
    StoreSettings,
)
from messagefoundry.store.crypto import generate_key, make_cipher
from messagefoundry.store.store import MessageStore

# provision-admin's prompt stub and passphrase, imported rather than copied, as
# tests/test_audit_keyless_chain_flagged.py does: that module is where the prompt is pinned.
from tests.test_provision_first_administrator import _PASSWORD, _tty

_CMD = "admin-set-notify-email"
_ADMIN = "site-admin"
_ADDRESS = "ops@example.invalid"
_ACTION = "auth.admin_notify_email_set"


# --- seeding -----------------------------------------------------------------------------------


def _seed(
    db: Path,
    *,
    admin_email: str | None = None,
    admin_disabled: bool = False,
    viewer: bool = False,
) -> None:
    """A keyless store holding one Administrator, provisioned the way the command does it.

    Built through ``provision_first_administrator`` rather than ``initialize()``, so no bootstrap
    account is minted and the Administrator here is the only one. ``viewer`` adds a second, enabled,
    non-Administrator account with no address.
    """

    async def run() -> None:
        store = await MessageStore.open(db)
        try:
            service = AuthService(store, AuthSettings())
            outcome = await service.provision_first_administrator(
                username=_ADMIN, password=_PASSWORD, notify_email=admin_email, actor="test"
            )
            if admin_disabled:
                await store.set_user_disabled(outcome.user_id, disabled=True)
            if viewer:
                await store.create_user(
                    user_id="u-viewer",
                    username="viewer",
                    auth_provider="local",
                    password_hash=None,
                )
                await store.set_user_roles("u-viewer", [Role.VIEWER.value], assigned_by="test")
        finally:
            await store.close()

    asyncio.run(run())


def _notify_email(db: Path, username: str) -> str | None:
    async def read() -> str | None:
        store = await MessageStore.open(db)
        try:
            user = await store.get_user_by_username(username)
            assert user is not None
            return user.notify_email
        finally:
            await store.close()

    return asyncio.run(read())


def _audit_rows(db: Path, action: str = _ACTION) -> list[dict[str, object]]:
    async def read() -> list[dict[str, object]]:
        store = await MessageStore.open(db)
        try:
            return [dict(r) for r in await store.list_audit(limit=100, action=action)]
        finally:
            await store.close()

    return asyncio.run(read())


def _error(capsys: pytest.CaptureFixture[str]) -> str:
    return str(json.loads(capsys.readouterr().out)["error"])


# --- 1. the strand this exists for ------------------------------------------------------------


def _shipped_posture_app(db: Path, key: str) -> object:
    """The engine a site gets at the shipped PHI posture, pointed at ``db``.

    ``enforce``, notices on and required, an SMTP transport configured -- so the ADR 0167 gate is
    live and the only question left is whether an enabled Administrator carries an address.
    """
    return create_managed_app(
        store_settings=StoreSettings(path=str(db), encryption_key=key),
        poll_interval=0.05,
        auth_settings=AuthSettings(enabled=True, notify_security_events=True),
        alerts_settings=AlertsSettings(
            security_notifications_required=True,
            email_smtp_host="smtp.example.invalid",
            email_from="alerts@example.invalid",
        ),
        security_settings=SecuritySettings(enforcement=SecurityEnforcement.ENFORCE),
    )


async def _start(app: object) -> None:
    from fastapi import FastAPI

    assert isinstance(app, FastAPI)
    async with app.router.lifespan_context(app):
        pass


def test_the_setter_unstrands_an_administrator_provisioned_without_an_address(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """THE WAVE'S ACCEPTANCE CHECK, end to end through the real lifespan.

    Provision with no ``--email``; the next start is refused. Run the setter; the next start passes.
    The refusal half is the control: without it, a passing second start is equally consistent with
    an app that starts whatever the store holds.
    """
    monkeypatch.chdir(tmp_path)
    key = generate_key()
    monkeypatch.setenv("MEFOR_STORE_ENCRYPTION_KEY", key)
    _tty(monkeypatch, _PASSWORD, _PASSWORD)
    db = tmp_path / "strand.db"
    assert main(["provision-admin", "--username", _ADMIN, "--db", str(db)]) == 0
    warned = capsys.readouterr().out
    assert "WARNING: no notification address" in warned
    # The warning points at the exit that works, not at a re-run provision-admin refuses.
    assert _CMD in warned

    with pytest.raises(RuntimeError) as refused:
        asyncio.run(_start(_shipped_posture_app(db, key)))
    assert "no enabled Administrator has a notification address" in str(refused.value)

    # provision-admin cannot fix it: an enabled Administrator now exists.
    _tty(monkeypatch, _PASSWORD, _PASSWORD)
    assert (
        main(["provision-admin", "--username", _ADMIN, "--email", _ADDRESS, "--db", str(db)]) == 1
    )
    capsys.readouterr()

    assert main([_CMD, "--username", _ADMIN, "--email", _ADDRESS, "--db", str(db)]) == 0
    assert "OK" in capsys.readouterr().out

    asyncio.run(_start(_shipped_posture_app(db, key)))  # must not raise

    async def read_back() -> str | None:
        cipher = make_cipher(key)
        store = await MessageStore.open(db, cipher=cipher, audit_mac_key=cipher.audit_mac_key())
        try:
            user = await store.get_user_by_username(_ADMIN)
            assert user is not None
            return user.notify_email
        finally:
            await store.close()

    assert asyncio.run(read_back()) == _ADDRESS


# --- 2. a blank value --------------------------------------------------------------------------


@pytest.mark.parametrize("blank", ["", "   ", "\t"])
def test_a_blank_address_is_refused_and_writes_nothing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    blank: str,
) -> None:
    monkeypatch.chdir(tmp_path)
    db = tmp_path / "blank.db"
    _seed(db)
    assert main([_CMD, "--username", _ADMIN, "--email", blank, "--db", str(db), "--json"]) == 1
    assert "non-empty" in _error(capsys)
    assert _notify_email(db, _ADMIN) is None
    assert _audit_rows(db) == []


def test_the_address_flag_is_required(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """No --email is a parser refusal, so there is no spelling that means "set it to nothing"."""
    monkeypatch.chdir(tmp_path)
    with pytest.raises(SystemExit) as exc:
        main([_CMD, "--username", _ADMIN, "--db", str(tmp_path / "x.db")])
    assert exc.value.code == 2


# --- 3. who it may be set on -------------------------------------------------------------------


def test_a_non_administrator_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """An addressed Viewer does not make any Administrator notice deliverable, so it would clear
    nothing the gate asks about -- and it is not this command's business to address other roles."""
    monkeypatch.chdir(tmp_path)
    db = tmp_path / "viewer.db"
    _seed(db, viewer=True)
    assert main([_CMD, "--username", "viewer", "--email", _ADDRESS, "--db", str(db), "--json"]) == 1
    assert "not an Administrator" in _error(capsys)
    assert _notify_email(db, "viewer") is None
    assert _audit_rows(db) == []


def test_a_disabled_administrator_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """A disabled account receives nothing and does not count at the gate, so addressing it would
    report success and leave the start refused."""
    monkeypatch.chdir(tmp_path)
    db = tmp_path / "disabled.db"
    _seed(db, admin_disabled=True)
    assert main([_CMD, "--username", _ADMIN, "--email", _ADDRESS, "--db", str(db), "--json"]) == 1
    error = _error(capsys)
    assert "disabled" in error
    # The console is unreachable while the start is refused, so the way out must be one that works.
    assert "provision-admin" in error
    assert _notify_email(db, _ADMIN) is None
    assert _audit_rows(db) == []


def test_an_unknown_account_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.chdir(tmp_path)
    db = tmp_path / "ghost.db"
    _seed(db)
    assert main([_CMD, "--username", "ghost", "--email", _ADDRESS, "--db", str(db), "--json"]) == 1
    assert "ghost" in _error(capsys)
    assert _audit_rows(db) == []


def test_a_missing_store_is_refused_rather_than_created(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The same M-31 guard ``admin-unlock`` carries: a typo'd --db is a wrong DATABASE, not a wrong
    username, and must not leave an empty store behind."""
    monkeypatch.chdir(tmp_path)
    missing = tmp_path / "nope.db"
    assert (
        main([_CMD, "--username", _ADMIN, "--email", _ADDRESS, "--db", str(missing), "--json"]) == 1
    )
    assert "refusing to create one" in _error(capsys)
    assert not missing.exists()


# --- 4. it cannot clear, or move, an address ---------------------------------------------------


def test_it_cannot_clear_an_address(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.chdir(tmp_path)
    db = tmp_path / "clear.db"
    _seed(db, admin_email=_ADDRESS)
    assert main([_CMD, "--username", _ADMIN, "--email", " ", "--db", str(db), "--json"]) == 1
    capsys.readouterr()
    assert _notify_email(db, _ADMIN) == _ADDRESS
    assert _audit_rows(db) == []


def test_it_will_not_repoint_an_existing_address(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Repointing offline would move where notices go with no EMAIL_CHANGED notice to the old
    address, because no notifier runs here. The web console is where an address is changed."""
    monkeypatch.chdir(tmp_path)
    db = tmp_path / "repoint.db"
    _seed(db, admin_email=_ADDRESS)
    other = "someone-else@example.invalid"
    assert main([_CMD, "--username", _ADMIN, "--email", other, "--db", str(db), "--json"]) == 1
    assert "already has a notification address" in _error(capsys)
    assert _notify_email(db, _ADMIN) == _ADDRESS
    assert _audit_rows(db) == []


# --- 5. the audit row --------------------------------------------------------------------------


def test_it_audits_the_os_user_and_keeps_the_address_out_of_the_detail(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Follows ``admin-unlock``: actor ``cli:<OS user>``. The address itself is not audited, as
    ``provision-admin`` records only whether one was set."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr("getpass.getuser", lambda: "host-operator")
    db = tmp_path / "audit.db"
    _seed(db)
    assert main([_CMD, "--username", _ADMIN, "--email", _ADDRESS, "--db", str(db), "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["ok"] is True and payload["username"] == _ADMIN
    assert _ADDRESS not in json.dumps(payload)

    rows = _audit_rows(db)
    assert len(rows) == 1
    assert rows[0]["actor"] == "cli:host-operator"
    detail = str(rows[0]["detail"])
    assert json.loads(detail) == {"username": _ADMIN}
    assert _ADDRESS not in detail
    assert _notify_email(db, _ADMIN) == _ADDRESS


def test_a_keyed_store_opened_without_its_key_writes_nothing_unaudited(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The ordinary operator trap: the key is in the service's NSSM environment, not this shell.

    The store opens, but its keyed audit chain refuses a keyless append. If the address were written
    first, it would land with no audit row and the command would die with a traceback. So the audit
    row goes first, and the refusal is a clean error that leaves the column untouched.
    """
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("MEFOR_STORE_ENCRYPTION_KEY", raising=False)
    key = generate_key()
    db = tmp_path / "keyed.db"

    async def seed() -> None:
        cipher = make_cipher(key)
        store = await MessageStore.open(db, cipher=cipher, audit_mac_key=cipher.audit_mac_key())
        try:
            await AuthService(store, AuthSettings()).provision_first_administrator(
                username=_ADMIN, password=_PASSWORD, actor="test"
            )
        finally:
            await store.close()

    asyncio.run(seed())
    assert main([_CMD, "--username", _ADMIN, "--email", _ADDRESS, "--db", str(db), "--json"]) == 1
    assert "keyed" in _error(capsys)

    async def read_back() -> str | None:
        cipher = make_cipher(key)
        store = await MessageStore.open(db, cipher=cipher, audit_mac_key=cipher.audit_mac_key())
        try:
            user = await store.get_user_by_username(_ADMIN)
            assert user is not None
            return user.notify_email
        finally:
            await store.close()

    assert asyncio.run(read_back()) is None


def test_the_address_is_stored_trimmed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Validated by the same ``require_notify_email`` every other write of the column uses."""
    monkeypatch.chdir(tmp_path)
    db = tmp_path / "trim.db"
    _seed(db)
    assert main([_CMD, "--username", _ADMIN, "--email", f"  {_ADDRESS} ", "--db", str(db)]) == 0
    capsys.readouterr()
    assert _notify_email(db, _ADMIN) == _ADDRESS


def test_the_username_is_stripped_as_provision_admin_strips_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The argv that created the account must also find it."""
    monkeypatch.chdir(tmp_path)
    db = tmp_path / "strip.db"
    _seed(db)
    assert main([_CMD, "--username", f" {_ADMIN} ", "--email", _ADDRESS, "--db", str(db)]) == 0
    capsys.readouterr()
    assert _notify_email(db, _ADMIN) == _ADDRESS


def test_success_names_the_store_it_wrote_to(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """As ``provision-admin`` does: a mistyped --db or config shows on screen, not only in a later
    refused start."""
    monkeypatch.chdir(tmp_path)
    db = tmp_path / "named.db"
    _seed(db)
    assert main([_CMD, "--username", _ADMIN, "--email", _ADDRESS, "--db", str(db)]) == 0
    assert str(db) in capsys.readouterr().out


def test_a_disabled_non_administrator_is_named_as_a_non_administrator(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.chdir(tmp_path)
    db = tmp_path / "disabled-viewer.db"
    _seed(db, viewer=True)

    async def disable() -> None:
        store = await MessageStore.open(db)
        try:
            await store.set_user_disabled("u-viewer", disabled=True)
        finally:
            await store.close()

    asyncio.run(disable())
    assert main([_CMD, "--username", "viewer", "--email", _ADDRESS, "--db", str(db), "--json"]) == 1
    assert "not an Administrator" in _error(capsys)


def test_a_failed_write_after_the_audit_row_is_reported_not_ok(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The cost of audit-first: the row can precede a write that fails. The command must say so,
    and append a matching ``_failed`` row so the log does not read as a completed change."""
    monkeypatch.chdir(tmp_path)
    db = tmp_path / "locked.db"
    _seed(db)

    async def locked(*_a: object, **_k: object) -> None:
        raise sqlite3.OperationalError("database is locked")

    with monkeypatch.context() as m:
        m.setattr(MessageStore, "set_user_notify_email", locked)
        assert (
            main([_CMD, "--username", _ADMIN, "--email", _ADDRESS, "--db", str(db), "--json"]) == 1
        )
    assert "NOT set" in _error(capsys)
    assert _notify_email(db, _ADMIN) is None
    assert len(_audit_rows(db)) == 1
    assert len(_audit_rows(db, f"{_ACTION}_failed")) == 1


def test_a_re_run_with_the_same_address_succeeds_and_writes_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """An automated install step can be repeated; the no-repoint rule still holds for a new value."""
    monkeypatch.chdir(tmp_path)
    db = tmp_path / "rerun.db"
    _seed(db)
    argv = [_CMD, "--username", _ADMIN, "--email", _ADDRESS, "--db", str(db), "--json"]
    assert main(argv) == 0
    assert json.loads(capsys.readouterr().out)["changed"] is True
    assert main(argv) == 0
    assert json.loads(capsys.readouterr().out)["changed"] is False
    assert len(_audit_rows(db)) == 1


def test_an_address_longer_than_the_console_allows_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Not looser than the web console's user form, which bounds the field at 256 characters."""
    monkeypatch.chdir(tmp_path)
    db = tmp_path / "long.db"
    _seed(db)
    long_address = "a" * 250 + "@example.invalid"
    assert (
        main([_CMD, "--username", _ADMIN, "--email", long_address, "--db", str(db), "--json"]) == 1
    )
    assert "256" in _error(capsys)
    assert _notify_email(db, _ADMIN) is None
    assert _audit_rows(db) == []


def test_a_keyed_store_with_encrypted_rows_is_refused_at_open(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """An engine that has run feeds holds encrypted rows the store reads at open, so a keyless open
    refuses there, before the audit append. That refusal must be a clean error too."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("MEFOR_STORE_ENCRYPTION_KEY", raising=False)
    key = generate_key()
    db = tmp_path / "keyed-rows.db"
    _seed(db)
    # A plaintext state row, sealed by the keyed open below -- the migration path the store's own
    # encryption tests use. Synthetic value, no message content.
    con = sqlite3.connect(db)
    con.execute(
        "INSERT INTO state (namespace, key, value, set_at, message_id) VALUES (?,?,?,?,?)",
        ("ns", "k", json.dumps({"v": 1}), 0.0, "m1"),
    )
    con.commit()
    con.close()

    async def seal() -> None:
        cipher = make_cipher(key)
        store = await MessageStore.open(db, cipher=cipher, audit_mac_key=cipher.audit_mac_key())
        await store.close()

    asyncio.run(seal())
    assert main([_CMD, "--username", _ADMIN, "--email", _ADDRESS, "--db", str(db), "--json"]) == 1
    error = _error(capsys)
    assert "Nothing was written" in error
    # The OPEN refused, not the later audit append: the store's own text names the key variable,
    # and the append branch's wording is absent.
    assert "MEFOR_STORE_ENCRYPTION_KEY" in error
    assert "audit row goes first" not in error


# --- 6. a server backend's driver errors (BACKLOG #1983) ----------------------------------------
#
# The command opens its store through `open_store`, so it also runs on PostgreSQL and SQL Server.
# Their drivers raise asyncpg's and pyodbc's own classes, which subclass neither `sqlite3.Error` nor
# `RuntimeError`. Before #1983 such a refusal escaped every `except` arm, so a failed address write
# after the audit row landed would never append the matching `_failed` row. The drivers are optional
# extras, so each test installs a stand-in module of the same name; the store is a double whose
# methods raise it. `test_a_failed_write_after_the_audit_row_is_reported_not_ok` is the SQLite control.


class _DriverStore:
    """A store double for a server backend: one enabled Administrator with no address."""

    path = "db.example.invalid/messagefoundry"

    def __init__(
        self,
        *,
        audit: BaseException | None = None,
        write: BaseException | None = None,
        failed_audit: BaseException | None = None,
    ) -> None:
        self._audit, self._write, self._failed_audit = audit, write, failed_audit
        self.audited: list[str] = []
        self.written = False

    async def get_user_by_username(self, username: str) -> object:
        from types import SimpleNamespace

        return SimpleNamespace(id="u-admin", username=username, disabled=False, notify_email=None)

    async def get_user_role_ids(self, _user_id: str) -> list[str]:
        return [Role.ADMINISTRATOR.value]

    async def record_audit(self, action: str, **_k: object) -> None:
        raise_this = self._failed_audit if action.endswith("_failed") else self._audit
        if raise_this is not None:
            raise raise_this
        self.audited.append(action)

    async def set_user_notify_email(self, *_a: object, **_k: object) -> None:
        if self._write is not None:
            raise self._write
        self.written = True

    async def close(self) -> None:
        return None


def _fake_drivers(monkeypatch: pytest.MonkeyPatch) -> dict[str, type[Exception]]:
    """Stand-ins for the asyncpg and pyodbc modules, carrying the classes the store layer names."""
    import sys
    from types import ModuleType

    asyncpg, pyodbc = ModuleType("asyncpg"), ModuleType("pyodbc")
    classes: dict[str, type[Exception]] = {
        "asyncpg.PostgresError": type("PostgresError", (Exception,), {}),
        "asyncpg.InterfaceError": type("InterfaceError", (Exception,), {}),
        "asyncpg.InternalClientError": type("InternalClientError", (Exception,), {}),
        "pyodbc.Error": type("Error", (Exception,), {}),
    }
    for dotted, cls in classes.items():
        module, name = dotted.split(".")
        setattr(asyncpg if module == "asyncpg" else pyodbc, name, cls)
    monkeypatch.setitem(sys.modules, "asyncpg", asyncpg)
    monkeypatch.setitem(sys.modules, "pyodbc", pyodbc)
    return classes


def _run_on(
    store: _DriverStore, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, *, name: str
) -> int:
    """Run the command against ``store``. The SQLite file exists only to pass the host gate."""
    monkeypatch.chdir(tmp_path)
    db = tmp_path / f"{name}.db"
    _seed(db)

    async def opened(*_a: object, **_k: object) -> _DriverStore:
        return store

    monkeypatch.setattr("messagefoundry.store.base.open_store", opened)
    return main([_CMD, "--username", _ADMIN, "--email", _ADDRESS, "--db", str(db), "--json"])


@pytest.mark.parametrize(
    "driver",
    [
        "asyncpg.PostgresError",
        "asyncpg.InterfaceError",
        "asyncpg.InternalClientError",
        "pyodbc.Error",
        "OSError",
    ],
)
def test_a_server_backend_write_failure_is_reported_and_audited(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], driver: str
) -> None:
    classes = _fake_drivers(monkeypatch)
    error = ConnectionResetError if driver == "OSError" else classes[driver]
    store = _DriverStore(write=error("refused by the server"))
    assert _run_on(store, tmp_path, monkeypatch, name="write") == 1
    message = _error(capsys)
    assert "NOT set" in message and "refused by the server" in message
    assert "a matching _failed audit row was appended" in message
    assert store.audited == [_ACTION, f"{_ACTION}_failed"]
    assert store.written is False


def test_a_server_backend_failed_row_that_also_fails_is_said(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The one case where the log can still read as a completed change, so it must be named."""
    postgres = _fake_drivers(monkeypatch)["asyncpg.PostgresError"]
    store = _DriverStore(write=postgres("write refused"), failed_audit=postgres("append refused"))
    assert _run_on(store, tmp_path, monkeypatch, name="both") == 1
    message = _error(capsys)
    assert "NOT set" in message
    assert "appending the matching _failed audit row also failed (append refused)" in message
    assert store.audited == [_ACTION]


def test_a_server_backend_audit_refusal_writes_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    store = _DriverStore(audit=_fake_drivers(monkeypatch)["pyodbc.Error"]("audit refused"))
    assert _run_on(store, tmp_path, monkeypatch, name="audit") == 1
    assert "audit row goes first" in _error(capsys)
    assert store.audited == [] and store.written is False


def test_a_server_backend_that_cannot_be_reached_is_an_error_not_a_traceback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The outer catch stays SQLite's #1670 arm on purpose. It wraps the reads and ``close()`` too,
    so widening it would name any late driver error "cannot open the store". A server that cannot be
    reached reaches the dispatch floor instead (BACKLOG #1863): exit 1, a redacted error object."""
    interface = _fake_drivers(monkeypatch)["asyncpg.InterfaceError"]
    monkeypatch.chdir(tmp_path)
    db = tmp_path / "unreachable.db"
    _seed(db)

    async def unreachable(*_a: object, **_k: object) -> _DriverStore:
        raise interface("connection refused")

    monkeypatch.setattr("messagefoundry.store.base.open_store", unreachable)
    assert main([_CMD, "--username", _ADMIN, "--email", _ADDRESS, "--db", str(db), "--json"]) == 1
    assert "InterfaceError" in _error(capsys)


def test_a_write_error_that_is_not_a_store_error_is_still_audited_but_not_reported_as_one(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The compensating row does not depend on recognising the error, since a class this command
    misses would otherwise leave a false log. The message does: a bug is not a store refusal, so it
    is re-raised to the dispatch floor rather than dressed as one."""
    _fake_drivers(monkeypatch)
    store = _DriverStore(write=KeyError("a bug, not a refusal"))
    assert _run_on(store, tmp_path, monkeypatch, name="bug") == 1
    assert "NOT set" not in _error(capsys)
    assert store.audited == [_ACTION, f"{_ACTION}_failed"]
    assert store.written is False


def test_store_driver_errors_names_each_installed_driver(monkeypatch: pytest.MonkeyPatch) -> None:
    import sys

    from messagefoundry.store.base import store_driver_errors

    classes = _fake_drivers(monkeypatch)
    assert set(store_driver_errors()) == {sqlite3.Error, *classes.values()}
    # An absent extra is left out rather than failing the import. `None` in sys.modules makes the
    # import raise ImportError, as a missing package does.
    monkeypatch.setitem(sys.modules, "asyncpg", None)
    monkeypatch.setitem(sys.modules, "pyodbc", None)
    assert store_driver_errors() == (sqlite3.Error,)


@pytest.mark.parametrize(
    ("driver", "roots"),
    [
        ("asyncpg", ("PostgresError", "InterfaceError", "InternalClientError")),
        ("pyodbc", ("Error",)),
    ],
)
def test_store_driver_errors_names_the_real_driver_roots(
    driver: str, roots: tuple[str, ...]
) -> None:
    """Against the real driver, where its extra is installed: the stand-ins above cannot catch a
    renamed class. Skipped where the extra is absent."""
    from messagefoundry.store.base import store_driver_errors

    module = pytest.importorskip(driver)
    named = store_driver_errors()
    for root in roots:
        assert getattr(module, root) in named


def test_help_names_the_host_gate(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exc:
        main([_CMD, "--help"])
    assert exc.value.code == 0
    out = " ".join(capsys.readouterr().out.split())
    assert "--username" in out and "--email" in out
    assert "same host gate as admin-unlock" in out
    assert "engine stopped" in out
