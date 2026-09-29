# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""ASVS 6.3.2 (BACKLOG #1136, ADR 0183) -- the offline first-administrator provisioning command.

``tests/test_first_run_default_account.py`` pins that the engine creates no account on its own (ADR
0183 Amendment A, Wave 2). This module pins the one way an install gets its first administrator:
``messagefoundry provision-admin`` at the host, before the first ``serve`` or after a refused one.

Severity is conditional (CLAUDE.md section 0): MessageFoundry has zero deployments, so everything
here describes what a deploying site would inherit, never a live exposure.
"""

from __future__ import annotations

import asyncio
import io
import json
import sys
import time
import types
from pathlib import Path

import pytest

from messagefoundry.__main__ import main
from messagefoundry.auth.identity import AuthProvider
from messagefoundry.auth.notifications import FIRST_ADMINISTRATOR_TAKEOVER, SecurityEvent
from messagefoundry.auth.passwords import hash_password
from messagefoundry.auth.permissions import Role
from messagefoundry.auth.service import (
    HOLDER_NOTICE_DISPATCHED,
    HOLDER_NOTICE_NO_CHANNEL,
    HOLDER_NOTICE_NO_PRIOR_ADDRESS,
    AuthService,
    FirstAdministratorRefused,
)
from messagefoundry.config.settings import AlertsSettings, AuthSettings
from messagefoundry.pipeline.security_notify import _SUBJECTS, _build_body
from messagefoundry.store.crypto import generate_key, make_cipher
from messagefoundry.store.store import MessageStore, WebAuthnCredential
from tests._admin_account import PROVISION_TOTP_SECRET, provision_totp

# The directory-sign-in precondition, imported rather than re-derived: that module is where it is
# measured, and this one only builds on it. Same convention as its own `_BACKENDS` import.
from tests.test_first_run_default_account import _directory_signed_in

# Low-entropy on purpose, matching the passphrases in tests/test_auth_service.py: a high-entropy
# literal here trips the gitleaks generic-api-key rule, and the honest fix is a synthetic value that
# does not look like a secret rather than an allowlist entry that teaches the scanner to skip one.
_PASSWORD = "a-long-enough-operator-passphrase"


async def test_a_provisioned_administrator_is_usable_and_a_start_adds_no_account() -> None:
    """AC-1, reworded at Wave 2: provision, then start, and the store holds exactly that account.

    Before Wave 2 this was the only way to avoid the default account, so it asserted the seeding path
    declined. Nothing seeds now, so the second half is that a start adds nothing beside it.
    """
    store = await MessageStore.open(":memory:")
    try:
        service = AuthService(store, AuthSettings())
        outcome = await service.provision_first_administrator(
            username="site-admin", password=_PASSWORD, actor="test", **provision_totp()
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

        # CLAIMED AT BIRTH, so there is no half-claimed state to restart into.
        claimed = await store.get_user_by_username("site-admin")
        assert claimed is not None and claimed.password_claimed_at is not None

        # A start after it adds no account beside it.
        await service.initialize()
        assert await store.count_users() == 1
        assert await store.get_user_by_username("admin") is None
    finally:
        await store.close()


async def test_it_refuses_once_an_enabled_administrator_exists() -> None:
    """Not a standing account-creation surface: with an administrator in place it declines."""
    store = await MessageStore.open(":memory:")
    try:
        service = AuthService(store, AuthSettings())
        await service.provision_first_administrator(
            username="site-admin", password=_PASSWORD, actor="test", **provision_totp()
        )
        assert await service.has_enabled_administrator() is True

        with pytest.raises(FirstAdministratorRefused, match="already has an enabled Administrator"):
            await service.provision_first_administrator(
                username="second", password=_PASSWORD, actor="test", **provision_totp()
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
            username="site-admin", password=_PASSWORD, actor="test", **provision_totp()
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
            password_generated=False,
        )
        if crashed_after == "set_password":
            await store.set_password(
                "halfwritten",
                password_hash="not-the-operators",
                must_change_password=False,
                password_generated=False,
            )
            row = await store.get_user_by_username("site-admin")
            assert row is not None and row.password_claimed_at is not None, "the state under test"
        # Either way the account is unusable to its intended holder: no credential at all, or one
        # they did not choose.
        assert (await service.login("site-admin", _PASSWORD)).ok is False

        outcome = await service.provision_first_administrator(
            username="site-admin", password=_PASSWORD, actor="test", **provision_totp()
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
            password_generated=False,
        )
        await store.set_user_roles("roled", [Role.OPERATOR.value], assigned_by="test")
        with pytest.raises(FirstAdministratorRefused, match="holds roles"):
            await service.provision_first_administrator(
                username="bob", password=_PASSWORD, actor="test", **provision_totp()
            )

        # Disabled is refused rather than silently revived -- and refusing rather than re-enabling
        # is what keeps a provision from reporting success on an account that cannot sign in.
        await store.create_user(
            user_id="off",
            username="carol",
            auth_provider=AuthProvider.LOCAL.value,
            password_hash=None,
            password_generated=False,
        )
        await store.set_user_disabled("off", disabled=True)
        with pytest.raises(FirstAdministratorRefused, match="is disabled"):
            await service.provision_first_administrator(
                username="carol", password=_PASSWORD, actor="test", **provision_totp()
            )

        # A directory row is never promoted, whatever its role state: its authority comes from the
        # directory, and this command has no standing to grant it engine roles.
        await store.create_user(
            user_id="dir",
            username="dana",
            auth_provider=AuthProvider.AD.value,
            password_hash=None,
            password_generated=False,
        )
        with pytest.raises(FirstAdministratorRefused, match="provision a separate"):
            await service.provision_first_administrator(
                username="dana", password=_PASSWORD, actor="test", **provision_totp()
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
                username="site-admin", password="short", actor="test", **provision_totp()
            )
        assert await store.count_users() == 0
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
            **provision_totp(),
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
            password_generated=False,
        )
        row = await store.get_user_by_username("site-admin")
        assert row is not None and row.notify_email is None, "control: it starts without one"

        await service.provision_first_administrator(
            username="site-admin",
            password=_PASSWORD,
            notify_email="ops@example.invalid",
            actor="test",
            **provision_totp(),
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
            username="site-admin",
            password=_PASSWORD,
            notify_email="   ",
            actor="test",
            **provision_totp(),
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
            username="site-admin", password=_PASSWORD, actor="cli:tester", **provision_totp()
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


def _key_in_this_shell(monkeypatch: pytest.MonkeyPatch) -> str:
    """Put a store key in the environment the command runs in, and return it.

    Since BACKLOG #1905 the command refuses a keyless open exactly as ``serve`` does, so a test about
    anything else has to supply the key the documented order now requires. The keyless refusal
    itself is pinned in ``tests/test_audit_keyless_chain_flagged.py``.
    """
    key = generate_key()
    monkeypatch.setenv("MEFOR_STORE_ENCRYPTION_KEY", key)
    return key


def test_cli_refuses_without_a_terminal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The unattended-install escape hatch is refused in terms rather than left to be added later.

    pytest's captured stdin is already not a terminal, so this runs against the real condition. The
    store must not be created either: a refusal that leaves a database behind would make the next
    ``serve`` see a non-empty directory and read as if something happened.
    """
    monkeypatch.chdir(tmp_path)
    _key_in_this_shell(monkeypatch)
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
    _key_in_this_shell(monkeypatch)
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
    would otherwise provision into a store ``serve`` never opens, and ``serve`` would then start with
    no Administrator -- with the command having reported success.
    """
    monkeypatch.chdir(tmp_path)
    key = _key_in_this_shell(monkeypatch)
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
        cipher = make_cipher(key)
        store = await MessageStore.open(db, cipher=cipher, audit_mac_key=cipher.audit_mac_key())
        try:
            row = await store.get_user_by_username("site-admin")
            assert row is not None
            assert Role.ADMINISTRATOR.value in await store.get_user_role_ids(row.id)
            # A start adds nothing beside it.
            await AuthService(store, AuthSettings()).initialize()
            assert await store.count_users() == 1
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
    _key_in_this_shell(monkeypatch)
    _tty(monkeypatch, _PASSWORD, _PASSWORD)
    assert (
        main(["provision-admin", "--username", "site-admin", "--db", str(tmp_path / "p.db")]) == 0
    )
    assert "WARNING: no notification address" in capsys.readouterr().out


@pytest.mark.parametrize(
    ("username", "printed"),
    [("site-admin", '--username="site-admin"'), ("site admin", '--username="site admin"')],
)
def test_the_warning_prints_a_username_every_shell_reads_the_same(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    username: str,
    printed: str,
) -> None:
    """BACKLOG #1985. The command used to print ``--username 'site admin'``, Python's repr. cmd.exe
    does not read single quotes as quoting, so a pasted name kept its quotes, or split at the space,
    and the setter answered that no such user exists. Double quotes are read by cmd.exe, PowerShell
    and POSIX shells alike. The printed command is then run as a POSIX shell would split it, and on
    Windows it must split the same way under the Windows argv rules.

    The printed command names no store, as before; ``--db`` is added here by hand, so this test
    says nothing about whether a pasted command finds the store ``provision-admin`` wrote to."""
    import shlex

    monkeypatch.chdir(tmp_path)
    _key_in_this_shell(monkeypatch)
    _tty(monkeypatch, _PASSWORD, _PASSWORD)
    db = str(tmp_path / "p.db")
    assert main(["provision-admin", "--username", username, "--db", db]) == 0
    out = capsys.readouterr().out
    assert f"admin-set-notify-email {printed} --email <address>" in out
    assert "type it quoted" not in out

    command = next(part for part in out.split("`") if part.startswith("messagefoundry "))
    posix = shlex.split(command)
    if sys.platform == "win32":
        assert _windows_argv(command) == posix
    argv = [arg.replace("<address>", "ops@example.invalid") for arg in posix[1:]]
    assert main([*argv, "--db", db]) == 0
    assert "OK" in capsys.readouterr().out


def _windows_argv(command: str) -> list[str]:
    """``command`` split by ``CommandLineToArgvW``, the rules a Windows process reads argv by."""
    if sys.platform != "win32":  # also tells mypy on another platform to skip the rest
        raise AssertionError("CommandLineToArgvW exists only on Windows")
    import ctypes
    from ctypes import wintypes

    split = ctypes.windll.shell32.CommandLineToArgvW
    split.restype = ctypes.POINTER(wintypes.LPWSTR)
    split.argtypes = [wintypes.LPCWSTR, ctypes.POINTER(ctypes.c_int)]
    count = ctypes.c_int()
    argv = split(command, ctypes.byref(count))
    try:
        return [argv[i] for i in range(count.value)]
    finally:
        ctypes.windll.kernel32.LocalFree(argv)


def test_a_username_no_one_quoting_reads_the_same_is_not_printed_as_if_it_were(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """``%`` expands inside cmd.exe's double quotes, so no single spelling works everywhere. The
    warning prints a placeholder and says to quote the name for the shell in use."""
    monkeypatch.chdir(tmp_path)
    _key_in_this_shell(monkeypatch)
    _tty(monkeypatch, _PASSWORD, _PASSWORD)
    assert main(["provision-admin", "--username", "ops%team", "--db", str(tmp_path / "p.db")]) == 0
    out = capsys.readouterr().out
    assert "admin-set-notify-email --username <username> --email <address>" in out
    assert "type it quoted for the shell in use" in out


@pytest.mark.parametrize(
    "value",
    [
        'a"b',
        "a$b",
        "a`b",
        "%USERNAME%",
        "a!b",
        "a\u201cb",
        "caf\u00e9",
        "/ops",
        "a\\\\b",
        "trail\\",
        "tab\tname",
    ],
)
def test_paste_safe_option_refuses_a_value_some_shell_would_change(value: str) -> None:
    from messagefoundry.__main__ import _paste_safe_option

    assert _paste_safe_option("--username", value) is None


@pytest.mark.parametrize(
    "value", ["site admin", "DOMAIN\\user", "o'brien", "a&b|c<d>e^f", "-leading", "a=b"]
)
def test_paste_safe_option_double_quotes_a_value_every_shell_passes_unchanged(value: str) -> None:
    """Checked by hand on cmd.exe, PowerShell 7.6, Windows PowerShell 5.1 and bash for this set.
    ``=`` keeps ``-leading`` from being read as a flag."""
    from messagefoundry.__main__ import _paste_safe_option

    assert _paste_safe_option("--username", value) == f'--username="{value}"'


# --- AC-15: refuse before prompting where it can, and leave no new store file ------------------


def _no_prompt(monkeypatch: pytest.MonkeyPatch) -> None:
    """Present a terminal whose prompt fails the test if it is ever read.

    A terminal is present on purpose: without one, the no-terminal refusal would fire first and
    every assertion below would pass for that reason instead.
    """

    def prompted(*_a: object, **_k: object) -> str:
        raise AssertionError("provision-admin prompted for a password it was going to refuse")

    monkeypatch.setattr(sys, "stdin", types.SimpleNamespace(isatty=lambda: True))
    monkeypatch.setattr("getpass.getpass", prompted)


@pytest.mark.parametrize(
    ("argv", "needle"),
    [
        pytest.param(["--username", "   "], "username", id="blank-username"),
        pytest.param(["--username", "u" * 257], "256", id="over-long-username"),
        pytest.param(
            ["--username", "site-admin", "--email", "a" * 241 + "@example.invalid"],
            "256",
            id="over-long-address",
        ),
        pytest.param(
            ["--username", "site-admin", "--display-name", "d" * 257], "256", id="over-long-name"
        ),
    ],
)
def test_an_argument_it_will_refuse_is_refused_before_the_prompt_and_the_open(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    argv: list[str],
    needle: str,
) -> None:
    """AC-15. The limits are the web console's, so this offline surface admits nothing it refuses.

    The address limit is the one ``admin-set-notify-email`` applies (a Manager decision carried from
    Wave 1c), and a blank address is still no address rather than a refusal (AC-9).
    """
    monkeypatch.chdir(tmp_path)
    _key_in_this_shell(monkeypatch)
    _no_prompt(monkeypatch)
    db = tmp_path / "never.db"
    assert main(["provision-admin", *argv, "--db", str(db), "--json"]) == 1
    assert needle in json.loads(capsys.readouterr().out)["error"]
    assert not db.exists(), "a refused provision left a store behind"


def test_a_password_the_policy_refuses_leaves_no_store(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """AC-15, password half. The prompt cannot be skipped for this one, but the open can.

    Before Wave 2 the store was opened with ``create=True`` first, so a refused password left an
    empty store secured to the operator, which a service started later could not open.
    """
    monkeypatch.chdir(tmp_path)
    _key_in_this_shell(monkeypatch)
    _tty(monkeypatch, "short", "short")
    db = tmp_path / "never.db"
    assert main(["provision-admin", "--username", "site-admin", "--db", str(db), "--json"]) == 1
    error = json.loads(capsys.readouterr().out)["error"]
    # Pin the REFUSAL, not just the key. Since BACKLOG #1863 `main`'s dispatch floor also answers
    # an escaped exception with exit 1 and an `error` key, so the key alone no longer proves the
    # policy refused the password rather than something crashing.
    assert "at least 15 characters" in error, error
    assert not db.exists(), "a refused password left a store behind"


def test_an_existing_administrator_is_refused_before_the_prompt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """AC-15, and the answer the IDE Start flow reads as go-ahead (ADR 0183, Wave 5).

    Asking for a password it is about to refuse would make a scripted "provision, then serve" step
    type a credential for nothing, and leave an operator unsure whether it was used.
    """
    monkeypatch.chdir(tmp_path)
    _key_in_this_shell(monkeypatch)
    db = tmp_path / "provisioned.db"
    _tty(monkeypatch, _PASSWORD, _PASSWORD)
    assert main(["provision-admin", "--username", "site-admin", "--db", str(db)]) == 0
    capsys.readouterr()

    _no_prompt(monkeypatch)
    assert main(["provision-admin", "--username", "other", "--db", str(db), "--json"]) == 1
    assert "already has an enabled Administrator" in json.loads(capsys.readouterr().out)["error"]


def test_an_existing_store_with_no_administrator_still_prompts_and_provisions(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The control on the test above: the early answer is about an ADMINISTRATOR, not about a store.

    A store that exists but holds none, the state a refused start leaves, must still get the prompt.
    Without this arm, a probe that refused every existing store would pass the test above.
    """
    monkeypatch.chdir(tmp_path)
    key = _key_in_this_shell(monkeypatch)
    db = tmp_path / "empty.db"

    async def create_empty() -> None:
        cipher = make_cipher(key)
        store = await MessageStore.open(db, cipher=cipher, audit_mac_key=cipher.audit_mac_key())
        await store.close()

    asyncio.run(create_empty())
    assert db.exists()
    _tty(monkeypatch, _PASSWORD, _PASSWORD)
    assert main(["provision-admin", "--username", "site-admin", "--db", str(db)]) == 0


# --- BACKLOG #2034: the trust-anchor enforcement dial reaches this command -----------------------


def _anchored_service_config(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, hop: str, enforcement: str
) -> Path:
    """A service config whose AD (over LDAPS) or OIDC block names a real CA file.

    ``AuthService`` checks that anchor when it is built, and this command builds one. The CA comes
    from the byte-binding module's tiny PKI rather than a second copy of it here. Imported here, not
    at module scope, so a collection error in that module does not take this whole file down.
    """
    from tests.test_trust_anchor_byte_binding import _make_ca

    anchor = tmp_path / f"{hop}-ca.pem"
    anchor.write_bytes(_make_ca(tmp_path, f"{hop}-ca").pem)
    # A TOML literal string, so a Windows path needs no escaping. The secrets go in the environment,
    # where the settings loader wants them. OIDC needs AD enabled too; there the AD block names no CA,
    # so the OIDC anchor is the only one checked.
    monkeypatch.setenv("MEFOR_AUTH_AD_BIND_PASSWORD", "not-a-real-password")
    security = ""
    auth = (
        "ad_enabled = true\n"
        'ad_server = "ldaps://dc1.example.test:636"\n'
        'ad_user_search_base = "DC=example,DC=test"\n'
        'ad_bind_dn = "CN=svc,DC=example,DC=test"\n'
        'ad_domain = "example.test"\n'
    )
    if hop == "ad":
        auth += f"ad_tls_ca_cert_file = '{anchor.as_posix()}'\n"
    else:
        monkeypatch.setenv("MEFOR_AUTH_OIDC_CLIENT_SECRET", "not-a-real-secret")
        security = 'web_console_public_address = "https://ops.example"\n'
        auth += (
            "oidc_enabled = true\n"
            'oidc_issuer = "https://idp.example"\n'
            'oidc_client_id = "mefor-console"\n'
            'oidc_authorization_endpoint = "https://idp.example/authorize"\n'
            'oidc_token_endpoint = "https://idp.example/token"\n'
            'oidc_jwks_uri = "https://idp.example/jwks"\n'
            'oidc_allowed_endpoints = ["idp.example"]\n'
            f"oidc_tls_ca_cert_file = '{anchor.as_posix()}'\n"
        )
    cfg = tmp_path / "service.toml"
    cfg.write_text(
        f'[security]\nenforcement = "{enforcement}"\n{security}[auth]\n{auth}', encoding="utf-8"
    )
    return cfg


def _pin_verdict(monkeypatch: pytest.MonkeyPatch, *, owner_only: bool) -> None:
    """Pin the anchor's ACL verdict with the byte-binding module's helper, so the result does not
    depend on this machine's ACLs. Imported lazily for the reason given above."""
    from tests.test_trust_anchor_byte_binding import _verdicts

    _verdicts(monkeypatch, acl=owner_only, path=True)


def _existing_empty_store(db: Path, key: str) -> None:
    """A keyed store holding no Administrator: the state a refused start leaves behind. The command
    then builds ``AuthService`` early, to ask whether an Administrator exists, before any prompt."""

    async def create_empty() -> None:
        cipher = make_cipher(key)
        store = await MessageStore.open(db, cipher=cipher, audit_mac_key=cipher.audit_mac_key())
        await store.close()

    asyncio.run(create_empty())


_HOPS = [pytest.param("ad", id="ad-ldaps"), pytest.param("oidc", id="oidc")]
_STORES = ["fresh", "existing"]


@pytest.mark.parametrize("hop", _HOPS)
@pytest.mark.parametrize("store", _STORES)
@pytest.mark.parametrize(
    ("enforcement", "owner_only"),
    [
        pytest.param("warn", False, id="weak-anchor-at-warn"),
        pytest.param("enforce", True, id="control-clean-anchor-at-enforce"),
    ],
)
def test_the_command_provisions_where_serve_would_start(
    hop: str,
    store: str,
    enforcement: str,
    owner_only: bool,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    caplog: pytest.LogCaptureFixture,
) -> None:
    """At ``warn``, ``serve`` warns about an anchor others can write and starts. So must this.

    The command built ``AuthService`` with no dial, which enforces, so it refused where ``serve``
    only warned. The control is a clean anchor at ``enforce``: it provisions with no anchor warning,
    so the refusal below comes from the verdict and not from the config. Text mode, not ``--json``:
    ``--json`` replaces the root handler caplog reads. Both stores, because each builds
    ``AuthService`` at a different point and each build must carry the dial.
    """
    monkeypatch.chdir(tmp_path)
    key = _key_in_this_shell(monkeypatch)
    _pin_verdict(monkeypatch, owner_only=owner_only)
    cfg = _anchored_service_config(tmp_path, monkeypatch, hop, enforcement)
    db = tmp_path / "p.db"
    if store == "existing":
        _existing_empty_store(db, key)
    _tty(monkeypatch, _PASSWORD, _PASSWORD)
    argv = ["provision-admin", "--username", "site-admin", "--service-config", str(cfg)]
    assert main([*argv, "--db", str(db)]) == 0
    assert "OK: created Administrator" in capsys.readouterr().out
    warned = [r.getMessage() for r in caplog.records if "writable by a non-owner" in r.getMessage()]
    if owner_only:
        assert warned == []
    else:
        assert warned and all("enforcement=warn, starting anyway" in m for m in warned)


@pytest.mark.parametrize("hop", _HOPS)
@pytest.mark.parametrize("store", _STORES)
def test_a_weak_anchor_is_refused_cleanly_at_enforce(
    hop: str,
    store: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """At ``enforce`` the command refuses, in words and with exit 1, never as a traceback.

    Both arms that build ``AuthService`` are covered. On an existing store the early "is there an
    Administrator" answer builds it, before the prompt. On a fresh one nothing is built until the
    write, after the prompt.
    """
    monkeypatch.chdir(tmp_path)
    key = _key_in_this_shell(monkeypatch)
    _pin_verdict(monkeypatch, owner_only=False)
    cfg = _anchored_service_config(tmp_path, monkeypatch, hop, "enforce")
    db = tmp_path / "p.db"
    if store == "existing":
        _existing_empty_store(db, key)
        _no_prompt(monkeypatch)
    else:
        _tty(monkeypatch, _PASSWORD, _PASSWORD)
    argv = ["provision-admin", "--username", "site-admin", "--service-config", str(cfg)]
    assert main([*argv, "--db", str(db), "--json"]) == 1
    captured = capsys.readouterr()
    error = json.loads(captured.out)["error"]
    # The anchor's own refusal, and this command's line after it: not the dispatch floor's report.
    assert "writable by a non-owner" in error and "enforcement=enforce refuses" in error
    assert "provisioned nothing" in error
    assert "Traceback" not in captured.out + captured.err


# --- BACKLOG #2019: the repair branch tells the earlier holder of an account it takes over ---------


class _Recorder:
    """Captures notices instead of mailing them, and records the drain the CLI owes before exit."""

    def __init__(self) -> None:
        self.events: list[SecurityEvent] = []
        self.started = False
        # How many notices were queued when the drain ran: a drain before the notice loses it.
        self.queued_at_close: int | None = None

    async def notify(self, event: SecurityEvent) -> None:
        self.events.append(event)

    def start(self) -> None:
        self.started = True

    async def aclose(self) -> None:
        # The FIRST drain counts: the real dispatcher stops its task there, so a later one is a no-op.
        if self.queued_at_close is None:
            self.queued_at_close = len(self.events)


async def _roleless_account(store: MessageStore, *, email: str | None) -> None:
    """A roleless local account with its holder's address: what a console create with no role
    leaves, and a row the repair can still take over."""
    await store.create_user(
        user_id="roleless",
        username="site-admin",
        auth_provider=AuthProvider.LOCAL.value,
        email=email,
        password_hash=None,
        must_change_password=True,
        password_generated=False,
    )


async def _provision_audit(store: MessageStore) -> dict[str, object]:
    rows = [dict(r) for r in await store.list_audit(limit=50)]
    detail: dict[str, object] = next(
        json.loads(r["detail"])
        for r in rows
        if r["action"] == "auth.first_administrator_provisioned"
    )
    return detail


@pytest.mark.parametrize(
    ("new_email", "moved"),
    [
        pytest.param("operator@example.invalid", True, id="email-moved"),
        pytest.param(None, False, id="no-email-given"),
        pytest.param("holder@example.invalid", False, id="same-email-given"),
    ],
)
async def test_a_takeover_notifies_the_address_the_account_held_before(
    new_email: str | None, moved: bool
) -> None:
    """The notice goes to the address read BEFORE the repair wrote anything.

    ``--email`` may replace it, and the new address belongs to the operator doing the takeover, so a
    notice sent after the write would tell the one person who already knows.
    """
    store = await MessageStore.open(":memory:")
    try:
        notifier = _Recorder()
        service = AuthService(store, AuthSettings(), security_notifier=notifier)
        await _roleless_account(store, email="holder@example.invalid")

        outcome = await service.provision_first_administrator(
            username="site-admin",
            password=_PASSWORD,
            notify_email=new_email,
            actor="test",
            **provision_totp(),
        )
        assert outcome.repaired is True
        assert outcome.holder_notice == HOLDER_NOTICE_DISPATCHED

        assert [e.event_type for e in notifier.events] == [FIRST_ADMINISTRATOR_TAKEOVER]
        (event,) = notifier.events
        assert event.email == "holder@example.invalid"
        assert event.username == "site-admin"
        if moved:
            assert event.detail == {"new_notify_email": new_email}
        else:
            assert "new_notify_email" not in event.detail

        detail = await _provision_audit(store)
        assert detail["holder_notice"] == HOLDER_NOTICE_DISPATCHED
        assert detail["notify_email_moved"] is moved
        # `notified` keeps its meaning: an address was supplied with --email.
        assert detail["notified"] is (new_email is not None)
    finally:
        await store.close()


@pytest.mark.parametrize("stored", [None, "   "], ids=["null", "blank"])
async def test_a_takeover_of_an_account_with_no_address_sends_nothing_and_says_so(
    stored: str | None,
) -> None:
    """There is nobody to tell, and the audit row must not read as though somebody was told.

    ``--email`` is given here on purpose: it is the operator's own address, and a notice to it would
    be the wrong recipient dressed up as a holder notice. The blank arm is a legacy row the notifier
    would drop, so recording it as dispatched would be false.
    """
    store = await MessageStore.open(":memory:")
    try:
        notifier = _Recorder()
        service = AuthService(store, AuthSettings(), security_notifier=notifier)
        await _roleless_account(store, email=None)
        if stored is not None:
            # No store API writes a blank address, so the legacy shape is written directly.
            await store._db.execute(
                "UPDATE users SET notify_email = ? WHERE id = 'roleless'", (stored,)
            )
            await store._db.commit()

        outcome = await service.provision_first_administrator(
            username="site-admin",
            password=_PASSWORD,
            notify_email="operator@example.invalid",
            actor="test",
            **provision_totp(),
        )
        assert outcome.repaired is True
        assert outcome.holder_notice == HOLDER_NOTICE_NO_PRIOR_ADDRESS
        assert notifier.events == []
        detail = await _provision_audit(store)
        assert detail["holder_notice"] == HOLDER_NOTICE_NO_PRIOR_ADDRESS
        assert detail["notified"] is True
    finally:
        await store.close()


async def test_a_fresh_provision_sends_no_takeover_notice() -> None:
    """A fresh create has no earlier holder, so no notice and a null ``holder_notice``."""
    store = await MessageStore.open(":memory:")
    try:
        notifier = _Recorder()
        service = AuthService(store, AuthSettings(), security_notifier=notifier)
        outcome = await service.provision_first_administrator(
            username="site-admin",
            password=_PASSWORD,
            notify_email="operator@example.invalid",
            actor="test",
            **provision_totp(),
        )
        assert outcome.repaired is False and outcome.holder_notice is None
        assert notifier.events == []
        detail = await _provision_audit(store)
        assert detail["holder_notice"] is None
        assert detail["notified"] is True
    finally:
        await store.close()


async def test_a_takeover_with_no_channel_records_that_nothing_was_sent(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """An address and no notifier: the audit row says so, and the drop is logged like any other."""
    store = await MessageStore.open(":memory:")
    try:
        service = AuthService(store, AuthSettings())
        await _roleless_account(store, email="holder@example.invalid")
        with caplog.at_level("WARNING", logger="messagefoundry.auth.service"):
            outcome = await service.provision_first_administrator(
                username="site-admin", password=_PASSWORD, actor="test", **provision_totp()
            )
        assert outcome.holder_notice == HOLDER_NOTICE_NO_CHANNEL
        assert (await _provision_audit(store))["holder_notice"] == HOLDER_NOTICE_NO_CHANNEL
        assert any(
            FIRST_ADMINISTRATOR_TAKEOVER in r.getMessage() and "dropped" in r.getMessage()
            for r in caplog.records
        )
    finally:
        await store.close()


async def test_a_notifier_that_raises_is_recorded_as_no_hand_off() -> None:
    """The row is written after the notice, so a notifier failure cannot be recorded as dispatched."""

    class _Raising(_Recorder):
        async def notify(self, event: SecurityEvent) -> None:
            raise RuntimeError("synthetic notifier failure")

    store = await MessageStore.open(":memory:")
    try:
        service = AuthService(store, AuthSettings(), security_notifier=_Raising())
        await _roleless_account(store, email="holder@example.invalid")
        outcome = await service.provision_first_administrator(
            username="site-admin", password=_PASSWORD, actor="test", **provision_totp()
        )
        assert outcome.holder_notice == HOLDER_NOTICE_NO_CHANNEL
        assert (await _provision_audit(store))["holder_notice"] == HOLDER_NOTICE_NO_CHANNEL
    finally:
        await store.close()


def test_a_moved_address_with_a_line_break_is_not_printed_into_the_notice() -> None:
    """The address is operator-typed, so it must not write its own lines into the holder's notice."""
    body = _build_body(
        SecurityEvent(
            event_type=FIRST_ADMINISTRATOR_TAKEOVER,
            username="site-admin",
            email="holder@example.invalid",
            detail={"new_notify_email": "x@example.invalid\nAll is well, ignore this notice."},
        )
    )
    assert "ignore this notice" not in body
    assert "The notification address for this account was changed." in body


def test_the_takeover_notice_says_what_happened_and_where_later_notices_go() -> None:
    """The renderer has its own subject, and names the moved address when there is one."""
    moved = _build_body(
        SecurityEvent(
            event_type=FIRST_ADMINISTRATOR_TAKEOVER,
            username="site-admin",
            email="holder@example.invalid",
            detail={"new_notify_email": "operator@example.invalid"},
        )
    )
    assert "provision-admin" in moved and "Administrator role" in moved
    assert "New notification address: operator@example.invalid" in moved
    assert "tell whoever operates the MessageFoundry host" in moved
    # The generic closing would send the holder to an administrator the install does not have.
    assert "contact your MessageFoundry administrator" not in moved
    assert FIRST_ADMINISTRATOR_TAKEOVER in _SUBJECTS

    kept = _build_body(
        SecurityEvent(
            event_type=FIRST_ADMINISTRATOR_TAKEOVER,
            username="site-admin",
            email="holder@example.invalid",
        )
    )
    assert "New notification address" not in kept


def _keyed_store_with_roleless_account(db: Path, key: str, *, email: str | None) -> None:
    async def create() -> None:
        cipher = make_cipher(key)
        store = await MessageStore.open(db, cipher=cipher, audit_mac_key=cipher.audit_mac_key())
        try:
            await _roleless_account(store, email=email)
        finally:
            await store.close()

    asyncio.run(create())


def test_cli_wires_the_notifier_drains_it_and_reports_the_takeover(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The command is the only production caller, so the notice has to reach a notifier from here.

    Without the wiring the service's notice lands on no channel and is dropped. The drain matters
    too: the event loop ends with the command, and an undrained queue loses what it holds.
    """
    monkeypatch.chdir(tmp_path)
    key = _key_in_this_shell(monkeypatch)
    db = tmp_path / "p.db"
    _keyed_store_with_roleless_account(db, key, email="holder@example.invalid")
    recorder = _Recorder()
    monkeypatch.setattr(
        "messagefoundry.__main__._offline_security_notifier", lambda _settings: recorder
    )
    _tty(monkeypatch, _PASSWORD, _PASSWORD)
    assert main(["provision-admin", "--username", "site-admin", "--db", str(db)]) == 0
    out = capsys.readouterr().out

    assert recorder.started and recorder.queued_at_close == 1
    assert [e.email for e in recorder.events] == ["holder@example.invalid"]
    assert "completed the existing roleless account" in out
    assert "Queued a takeover notice" in out
    # The account keeps an address, so the "no notification address" warning would be false here.
    assert "WARNING: no notification address" not in out
    assert "WARNING: the account keeps its earlier notification address" in out


def test_cli_says_nobody_was_told_when_the_account_had_no_address(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The control on the test above: no earlier address, no notice, and the missing-address
    warning still fires, because the account really has none."""
    monkeypatch.chdir(tmp_path)
    key = _key_in_this_shell(monkeypatch)
    db = tmp_path / "p.db"
    _keyed_store_with_roleless_account(db, key, email=None)
    recorder = _Recorder()
    monkeypatch.setattr(
        "messagefoundry.__main__._offline_security_notifier", lambda _settings: recorder
    )
    _tty(monkeypatch, _PASSWORD, _PASSWORD)
    assert main(["provision-admin", "--username", "site-admin", "--db", str(db)]) == 0
    out = capsys.readouterr().out
    assert "there was nobody to tell" in out
    assert "WARNING: no notification address" in out
    assert recorder.events == []


def test_cli_sends_through_the_real_notifier_before_it_exits(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """End to end through the real ``SecurityEventNotifier``: built from a service config, started,
    fed, and drained before the command's loop ends. Only the SMTP send itself is stubbed."""
    monkeypatch.chdir(tmp_path)
    key = _key_in_this_shell(monkeypatch)
    db = tmp_path / "p.db"
    _keyed_store_with_roleless_account(db, key, email="holder@example.invalid")
    cfg = tmp_path / "service.toml"
    cfg.write_text(
        '[alerts]\nemail_smtp_host = "smtp.example.invalid"\nemail_from = "mefor@example.invalid"\n',
        encoding="utf-8",
    )
    sent: list[tuple[list[str], str]] = []

    def fake_send(**kwargs: object) -> None:
        recipients = kwargs["recipients"]
        assert isinstance(recipients, list)
        sent.append((recipients, str(kwargs["subject"])))

    monkeypatch.setattr("messagefoundry.pipeline.security_notify.send_plain_email", fake_send)
    _tty(monkeypatch, _PASSWORD, _PASSWORD)
    argv = ["provision-admin", "--username", "site-admin", "--service-config", str(cfg)]
    assert main([*argv, "--db", str(db), "--json"]) == 0
    assert sent == [(["holder@example.invalid"], _SUBJECTS[FIRST_ADMINISTRATOR_TAKEOVER])]


def test_cli_warns_when_the_holder_had_an_address_and_no_channel_is_wired(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The real builder with no [alerts] relay: the holder is not told, and the output says so."""
    monkeypatch.chdir(tmp_path)
    key = _key_in_this_shell(monkeypatch)
    db = tmp_path / "p.db"
    _keyed_store_with_roleless_account(db, key, email="holder@example.invalid")
    _tty(monkeypatch, _PASSWORD, _PASSWORD)
    assert main(["provision-admin", "--username", "site-admin", "--db", str(db), "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["holder_notice"] == HOLDER_NOTICE_NO_CHANNEL


def _smtp(*, use_tls: bool = True, verify: bool = True) -> AlertsSettings:
    """An [alerts] block with a relay configured, so the notifier can be built."""
    return AlertsSettings(
        email_smtp_host="smtp.example.invalid",
        email_from="mefor@example.invalid",
        email_use_tls=use_tls,
        email_tls_verify=verify,
    )


def test_the_offline_notifier_is_built_on_the_conditions_serve_uses() -> None:
    """``serve`` wires the notifier only with sign-in on, notices on, and an SMTP host and sender."""
    from messagefoundry.__main__ import _offline_security_notifier
    from messagefoundry.config.settings import ServiceSettings
    from messagefoundry.pipeline.security_notify import SecurityEventNotifier

    smtp = _smtp()
    assert _offline_security_notifier(ServiceSettings()) is None
    built = _offline_security_notifier(ServiceSettings(alerts=smtp))
    assert isinstance(built, SecurityEventNotifier)
    off = ServiceSettings(alerts=smtp, auth=AuthSettings(notify_security_events=False))
    assert _offline_security_notifier(off) is None
    disabled = ServiceSettings(alerts=smtp, auth=AuthSettings(enabled=False))
    assert _offline_security_notifier(disabled) is None


@pytest.mark.parametrize(
    ("use_tls", "verify"),
    [
        pytest.param(False, True, id="cleartext"),
        pytest.param(True, False, id="unverified"),
    ],
)
def test_the_offline_notifier_refuses_an_unauthenticated_hop_unless_acknowledged(
    use_tls: bool, verify: bool, capsys: pytest.CaptureFixture[str]
) -> None:
    """The SMTP password must not cross a hop that authenticates no relay, which ``serve`` refuses
    on a PHI instance under enforce. This command refuses it everywhere unless acknowledged."""
    from messagefoundry.__main__ import _offline_security_notifier
    from messagefoundry.config.settings import SecuritySettings, ServiceSettings
    from messagefoundry.pipeline.security_notify import SecurityEventNotifier

    alerts = _smtp(use_tls=use_tls, verify=verify)
    assert _offline_security_notifier(ServiceSettings(alerts=alerts)) is None
    assert "does not authenticate the relay" in capsys.readouterr().err
    acked = ServiceSettings(
        alerts=alerts, security=SecuritySettings(allow_unverified_alert_smtp_tls=True)
    )
    assert isinstance(_offline_security_notifier(acked), SecurityEventNotifier)


def test_a_channel_that_fails_to_build_costs_the_notice_not_the_recovery(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Any build error is warned and yields no channel; it must not escape into the command."""
    from messagefoundry.__main__ import _offline_security_notifier
    from messagefoundry.config.settings import ServiceSettings

    def boom(*_a: object, **_k: object) -> None:
        raise ValueError("synthetic build failure")

    monkeypatch.setattr(
        "messagefoundry.pipeline.security_notify.security_notifier_from_settings", boom
    )
    assert _offline_security_notifier(ServiceSettings(alerts=_smtp())) is None
    assert "synthetic build failure" in capsys.readouterr().err


# --- ADR 0197 Amendment A, N-A (AC-A5): the first Administrator enrols TOTP at the terminal --------

#: The secret ``totp.generate_secret`` is pinned to in these tests, so the terminal stub can compute
#: the code the operator would read off the authenticator. Synthetic; not a secret.
_TERMINAL_SECRET = PROVISION_TOTP_SECRET


class _Terminal:
    """A console for the TOTP prompt: ``isatty`` True, ``readline`` answers the queued codes, and
    ``shown`` records what reached the console device (``_show_on_terminal``)."""

    def __init__(self, codes: list[str]) -> None:
        self._codes = codes
        self.asked = 0
        self.shown: list[str] = []

    def show(self, text: str) -> None:
        self.shown.append(text)

    def fileno(self) -> int:
        # A stand-in stream names no device, as a replaced real stdin would not either.
        raise io.UnsupportedOperation("fileno")

    def isatty(self) -> bool:
        return True

    def readline(self) -> str:
        self.asked += 1
        return self._codes.pop(0) + "\n" if self._codes else ""


def _drive_the_real_prompt(
    monkeypatch: pytest.MonkeyPatch, codes: list[str] | None = None
) -> _Terminal:
    """Replace the suite-wide stub with the REAL ``_enrol_totp_at_terminal``, pin the generated
    secret so a correct code can be computed, and present a terminal that answers ``codes`` (one
    live code by default). ``getpass`` answers the two password prompts."""
    import messagefoundry.__main__ as cli
    from messagefoundry.auth import totp

    real = cli._enrol_totp_at_terminal.__wrapped__  # type: ignore[attr-defined]
    monkeypatch.setattr(cli, "_enrol_totp_at_terminal", real)
    monkeypatch.setattr(totp, "generate_secret", lambda: _TERMINAL_SECRET)
    terminal = _Terminal(codes if codes is not None else [totp.totp(_TERMINAL_SECRET)])
    monkeypatch.setattr(sys, "stdin", terminal)
    monkeypatch.setattr(cli, "_show_on_terminal", terminal.show)
    queued = [_PASSWORD, _PASSWORD]
    monkeypatch.setattr("getpass.getpass", lambda *_a, **_k: queued.pop(0))
    return terminal


def test_the_cli_enrols_totp_and_the_administrator_passes_a_live_lock_with_a_combined_sign_in(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """AC-A5: provision-admin under the shipped require_mfa leaves TOTP ON before the role, and the
    new Administrator has option E's way past: with the sign-in lock live, a combined sign-in works.
    The key and the recovery codes went to the console device once each, and to neither stream: not
    stdout, which carries the --json body, and not stderr, which a redirect can put in a log (CodeQL
    alert 228). RED against the stderr print this replaced."""
    from messagefoundry.auth import totp

    monkeypatch.chdir(tmp_path)
    key = _key_in_this_shell(monkeypatch)
    terminal = _drive_the_real_prompt(monkeypatch)
    db = tmp_path / "provision.db"
    assert main(["provision-admin", "--username", "site-admin", "--db", str(db), "--json"]) == 0
    captured = capsys.readouterr()
    body = json.loads(captured.out.strip().splitlines()[-1])
    assert body["ok"] is True and body["totp_enrolled"] is True
    assert body["recovery_codes_shown"] is True
    streams = captured.out + captured.err
    assert _TERMINAL_SECRET not in streams
    # The key, the code prompt and the codes, in that order, all on the console device.
    assert len(terminal.shown) == 3, terminal.shown
    key_text, prompt_text, codes_text = terminal.shown
    assert _TERMINAL_SECRET in key_text and "otpauth://" in key_text
    assert prompt_text == "Authenticator code: "
    assert "Authenticator code" not in streams, "the prompt went to a stream"
    assert "Recovery codes" in codes_text
    codes = [
        line.strip()
        for line in codes_text.split("Recovery codes", 1)[1].splitlines()[1:]
        if line.startswith("  ") and line.strip()
    ]
    assert codes, codes_text
    assert not any(code in streams for code in codes)

    async def check() -> None:
        cipher = make_cipher(key)
        store = await MessageStore.open(db, cipher=cipher, audit_mac_key=cipher.audit_mac_key())
        try:
            row = await store.get_user_by_username("site-admin")
            assert row is not None and row.totp_enabled and not row.password_generated
            assert Role.ADMINISTRATOR.value in await store.get_user_role_ids(row.id)
            assert await store.get_totp_secret(row.id) == _TERMINAL_SECRET
            assert len(await store.get_recovery_code_hashes(row.id)) == len(codes)
            service = AuthService(store, AuthSettings(lockout_threshold=3, lockout_minutes=15))
            for _ in range(3):
                assert not (await service.login("site-admin", "a-wrong-guess-for-the-lock")).ok
            row = await store.get_user_by_username("site-admin")
            assert row is not None and row.locked_until is not None, "the sign-in lock is live"
            later = time.time() + 2 * totp.DEFAULT_PERIOD
            code = totp.totp(_TERMINAL_SECRET, now=later)
            monkeypatch.setattr(totp, "time", types.SimpleNamespace(time=lambda: later))
            out = await service.login("site-admin", _PASSWORD, totp_code=code)
            assert out.ok, out.error
        finally:
            await store.close()

    asyncio.run(check())


def test_a_wrong_code_at_the_prompt_writes_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """N-A: the code is checked in memory before any store write. Five wrong codes stop the
    command, and the store is not even created."""
    monkeypatch.chdir(tmp_path)
    _key_in_this_shell(monkeypatch)
    terminal = _drive_the_real_prompt(
        monkeypatch, ["000000", "111111", "222222", "333333", "444444"]
    )
    db = tmp_path / "provision.db"
    assert main(["provision-admin", "--username", "site-admin", "--db", str(db)]) != 0
    assert terminal.asked == 5
    assert "nothing was written" in capsys.readouterr().err
    assert not db.exists()


def test_the_key_goes_to_the_console_device_and_nowhere_else(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """CodeQL alert 228: the real ``_show_on_terminal`` writes to the device
    ``_controlling_terminal_path`` names, here pointed at a file, and prints nothing to either
    stream."""
    import messagefoundry.__main__ as cli

    real = cli._show_on_terminal.__wrapped__  # type: ignore[attr-defined]
    device = tmp_path / "console"
    device.write_text("")  # a device exists before anything writes to it; open() never creates one
    monkeypatch.setattr(cli, "_controlling_terminal_path", lambda: str(device))
    real("  key: SYNTHETICKEY\n")
    assert device.read_text(encoding="utf-8") == "  key: SYNTHETICKEY\n"
    captured = capsys.readouterr()
    assert captured.out == "" and captured.err == ""


def test_with_no_console_the_key_is_not_shown_and_nothing_is_written(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """No console device to open: the command refuses before any store write, and the key does not
    fall back to a stream."""
    import messagefoundry.__main__ as cli

    monkeypatch.chdir(tmp_path)
    _key_in_this_shell(monkeypatch)
    real = cli._show_on_terminal.__wrapped__  # type: ignore[attr-defined]
    terminal = _drive_the_real_prompt(monkeypatch)
    monkeypatch.setattr(cli, "_show_on_terminal", real)
    missing = tmp_path / "no-such-dir" / "console"
    monkeypatch.setattr(cli, "_controlling_terminal_path", lambda: str(missing))
    db = tmp_path / "provision.db"
    assert main(["provision-admin", "--username", "site-admin", "--db", str(db)]) != 0
    captured = capsys.readouterr()
    assert "could not open the console" in captured.err
    assert _TERMINAL_SECRET not in captured.out + captured.err
    assert terminal.asked == 0
    assert not db.exists()


def test_recovery_codes_that_cannot_be_shown_are_not_printed_instead(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The console fails after the write, at the recovery codes: the command warns, still succeeds
    (the account is written and has its authenticator), prints no code to either stream, and says
    so in the --json body, for a caller that reads nothing else."""
    import messagefoundry.__main__ as cli

    monkeypatch.chdir(tmp_path)
    _key_in_this_shell(monkeypatch)
    terminal = _drive_the_real_prompt(monkeypatch)

    def show_the_key_only(text: str) -> None:
        if "Recovery codes" in text:
            raise OSError("synthetic console loss")
        terminal.show(text)

    monkeypatch.setattr(cli, "_show_on_terminal", show_the_key_only)
    db = tmp_path / "provision.db"
    assert main(["provision-admin", "--username", "site-admin", "--db", str(db), "--json"]) == 0
    captured = capsys.readouterr()
    assert json.loads(captured.out.strip().splitlines()[-1])["recovery_codes_shown"] is False
    assert "recovery codes could not be shown" in captured.err
    assert "Recovery codes, shown once" not in captured.out + captured.err
    assert len(terminal.shown) == 2 and _TERMINAL_SECRET in terminal.shown[0]


def test_a_console_that_accepts_no_bytes_raises_rather_than_spins(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A stalled terminal can return 0 from write(2) without raising. The writer raises then, so
    the caller refuses or warns instead of looping forever."""
    import os

    import messagefoundry.__main__ as cli

    real = cli._show_on_terminal.__wrapped__  # type: ignore[attr-defined]
    device = tmp_path / "console"
    device.write_text("")
    monkeypatch.setattr(cli, "_controlling_terminal_path", lambda: str(device))
    monkeypatch.setattr(os, "write", lambda _fd, _data: 0)
    with pytest.raises(OSError, match="accepted no bytes"):
        real("  key: SYNTHETICKEY\n")


def test_no_totp_is_refused_while_mfa_is_required(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """N-A: --no-totp is refused under the shipped require_mfa, before the store is created."""
    monkeypatch.chdir(tmp_path)
    _key_in_this_shell(monkeypatch)
    _tty(monkeypatch, _PASSWORD, _PASSWORD)
    db = tmp_path / "provision.db"
    rc = main(["provision-admin", "--username", "site-admin", "--db", str(db), "--no-totp"])
    assert rc != 0
    assert "--no-totp is refused" in capsys.readouterr().err
    assert not db.exists()


async def test_the_service_refuses_no_totp_while_mfa_is_required_and_a_wrong_code() -> None:
    """The service holds both lines too, and writes nothing on either refusal."""
    store = await MessageStore.open(":memory:")
    try:
        service = AuthService(store, AuthSettings())
        with pytest.raises(FirstAdministratorRefused, match="require_mfa"):
            await service.provision_first_administrator(
                username="site-admin", password=_PASSWORD, actor="test"
            )
        kw = provision_totp()
        kw["totp_code"] = "000000" if kw["totp_code"] != "000000" else "111111"
        with pytest.raises(FirstAdministratorRefused, match="nothing was written"):
            await service.provision_first_administrator(
                username="site-admin", password=_PASSWORD, actor="test", **kw
            )
        assert await store.count_users() == 0
        # With the requirement off, the service provisions without TOTP.
        off = AuthService(store, AuthSettings(require_mfa=False))
        outcome = await off.provision_first_administrator(
            username="site-admin", password=_PASSWORD, actor="test"
        )
        assert outcome.recovery_codes == ()
    finally:
        await store.close()


async def test_the_repair_branch_clears_the_earlier_holders_factors_and_sessions() -> None:
    """AC-A5, and the ADR 0183 defect it fixes: a roleless row somebody else held must not carry
    their TOTP, recovery codes, passkeys or a live session onto the new Administrator. Before this,
    a session they kept became an Administrator session when the role was written."""
    store = await MessageStore.open(":memory:")
    try:
        service = AuthService(store, AuthSettings(require_mfa=False))
        await service.initialize()
        await store.create_user(
            user_id="earlier",
            username="site-admin",
            auth_provider="local",
            password_hash=None,
            must_change_password=True,
            password_generated=False,
        )
        await store.set_password(
            "earlier",
            password_hash=await asyncio.to_thread(hash_password, "the-earlier-holders-passphrase"),
            must_change_password=False,
            password_generated=False,
        )
        await store.set_totp_secret("earlier", secret="JBSWY3DPEHPK3PXP")
        await store.enable_totp("earlier", recovery_code_hashes=["h1", "h2"])
        await store.add_webauthn_credential(
            WebAuthnCredential(
                credential_id_hash="earlier-passkey-hash",
                credential_id="earlier-passkey-id",
                user_id="earlier",
                rp_id="t",
                public_key="cose-public-key-b64url",
                sign_count=0,
                transports=None,
                device_type="multi_device",
                backed_up=True,
                label="theirs",
                aaguid=None,
                created_at=1.0,
            )
        )
        kept = await service.login("site-admin", "the-earlier-holders-passphrase")
        assert kept.ok and kept.token is not None

        on = AuthService(store, AuthSettings())
        outcome = await on.provision_first_administrator(
            username="site-admin", password=_PASSWORD, actor="test", **provision_totp()
        )
        assert outcome.repaired and outcome.recovery_codes
        # The earlier holder's session is gone: it never becomes an Administrator session.
        assert await on.identity_for_token(kept.token) is None
        assert await store.list_webauthn_credentials("earlier") == []
        row = await store.get_user("earlier")
        assert row is not None and row.totp_enabled
        assert await store.get_totp_secret("earlier") == PROVISION_TOTP_SECRET
        assert "h1" not in await store.get_recovery_code_hashes("earlier")
    finally:
        await store.close()


async def test_a_re_run_in_the_same_step_is_not_blocked_by_the_rows_old_step_mark() -> None:
    """Review rounds 1 and 2. The row already spent this step (an interrupted earlier run, or an
    earlier holder signing in with a code of their own). The repair clears the row's factors, and
    since round 2 ``disable_totp`` forgets the old secret's step mark, so the operator's code for the
    same 30 seconds is accepted rather than refused -- an earlier holder cannot block the repair by
    spending each step first."""
    store = await MessageStore.open(":memory:")
    try:
        service = AuthService(store, AuthSettings())
        await service.initialize()
        await store.create_user(
            user_id="half",
            username="site-admin",
            auth_provider="local",
            password_hash=None,
            must_change_password=True,
            password_generated=False,
        )
        kw = provision_totp()
        from messagefoundry.auth import totp

        spent = totp.verify_totp_step(
            kw["totp_secret"], kw["totp_code"], now=kw["totp_code_read_at"]
        )
        assert spent is not None and await store.consume_totp_step("half", spent)
        outcome = await service.provision_first_administrator(
            username="site-admin", password=_PASSWORD, actor="test", **kw
        )
        assert outcome.repaired and outcome.recovery_codes
        row = await store.get_user("half")
        assert row is not None and row.totp_enabled
        assert Role.ADMINISTRATOR.value in await store.get_user_role_ids("half")
    finally:
        await store.close()


async def test_a_sign_in_during_the_repair_does_not_survive_into_the_administrator_role() -> None:
    """Review round 2: the earlier holder's password works until the repair writes the new one. A
    session minted in that window must not outlive the repair, so the sessions are revoked again
    after the role is written."""
    store = await MessageStore.open(":memory:")
    try:
        service = AuthService(store, AuthSettings(require_mfa=False))
        await service.initialize()
        await store.create_user(
            user_id="earlier",
            username="site-admin",
            auth_provider="local",
            password_hash=None,
            must_change_password=True,
            password_generated=False,
        )
        await store.set_password(
            "earlier",
            password_hash=await asyncio.to_thread(hash_password, "the-earlier-holders-passphrase"),
            must_change_password=False,
            password_generated=False,
        )
        minted: list[str] = []
        real_set_password = store.set_password

        async def sign_in_just_before_the_new_password(*a: object, **k: object) -> bool:
            if not minted:
                out = await service.login("site-admin", "the-earlier-holders-passphrase")
                assert out.ok and out.token is not None
                minted.append(out.token)
            return await real_set_password(*a, **k)  # type: ignore[arg-type]

        store.set_password = sign_in_just_before_the_new_password  # type: ignore[method-assign]
        outcome = await service.provision_first_administrator(
            username="site-admin", password=_PASSWORD, actor="test"
        )
        assert outcome.repaired and minted
        assert await service.identity_for_token(minted[0]) is None
    finally:
        await store.close()


def test_the_cli_refuses_a_username_it_would_not_complete_before_any_prompt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Review round 2: an account that holds roles is refused before the password prompt and before
    an authenticator key is shown for it."""
    monkeypatch.chdir(tmp_path)
    key = _key_in_this_shell(monkeypatch)
    db = tmp_path / "provision.db"

    async def seed() -> None:
        cipher = make_cipher(key)
        store = await MessageStore.open(db, cipher=cipher, audit_mac_key=cipher.audit_mac_key())
        try:
            svc = AuthService(store, AuthSettings())
            await svc.initialize()
            await store.create_user(
                user_id="bob",
                username="bob",
                auth_provider="local",
                password_hash="h",
                password_generated=False,
            )
            await store.set_user_roles("bob", [Role.VIEWER.value], assigned_by="test")
        finally:
            await store.close()

    asyncio.run(seed())
    _no_prompt(monkeypatch)
    import messagefoundry.__main__ as cli

    def no_enrolment(**_k: object) -> tuple[str, str, float]:
        raise AssertionError("an authenticator key was shown for an account the store refuses")

    monkeypatch.setattr(cli, "_enrol_totp_at_terminal", no_enrolment)
    assert main(["provision-admin", "--username", "bob", "--db", str(db)]) != 0
    assert "holds roles" in capsys.readouterr().err


class _FakeStdin:
    """A stdin that names descriptor 0, for the POSIX console fallback."""

    def isatty(self) -> bool:
        return True

    def fileno(self) -> int:
        return 0


def _no_controlling_terminal(monkeypatch: pytest.MonkeyPatch) -> list[tuple[str, int]]:
    """POSIX with no controlling terminal (``setsid``): /dev/tty refuses with ENXIO. Returns the
    record of every path the writer then tries to open."""
    import errno
    import os

    opened: list[tuple[str, int]] = []

    def fake_open(path: str, flags: int, *_a: object) -> int:
        opened.append((path, flags))
        if path == "/dev/tty":
            raise OSError(errno.ENXIO, "No such device or address")
        if path == "/dev/pts/9":
            raise PermissionError(errno.EACCES, "the operator's tty")
        raise AssertionError(f"unexpected open {path}")

    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.setattr(sys, "stdin", _FakeStdin())
    monkeypatch.setattr(os, "open", fake_open)
    monkeypatch.setattr(os, "isatty", lambda fd: fd == 0)
    return opened


def test_without_a_controlling_terminal_the_writer_duplicates_stdin(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``su <user> -c``: /dev/tty gives ENXIO and the operator's pts refuses the target user by path,
    so the writer duplicates the inherited stdin descriptor, which is already open to that tty."""
    import os

    import messagefoundry.__main__ as cli

    opened = _no_controlling_terminal(monkeypatch)
    monkeypatch.setattr(os, "ttyname", lambda fd: "/dev/pts/9", raising=False)
    monkeypatch.setattr(os, "dup", lambda fd: 4242 if fd == 0 else -1)
    assert cli._open_terminal() == 4242
    assert [p for p, _ in opened] == ["/dev/tty", "/dev/pts/9"]


def test_the_writer_prefers_reopening_stdin_tty_by_path(monkeypatch: pytest.MonkeyPatch) -> None:
    """When the tty CAN be opened by name (same user), a fresh write-only descriptor is used rather
    than stdin's own, which may be read-only or non-blocking."""
    import os

    import messagefoundry.__main__ as cli

    opened = _no_controlling_terminal(monkeypatch)
    real_open = os.open  # already the fake; wrap it so /dev/pts/5 opens

    def open_same_user_tty(path: str, flags: int, *a: int) -> int:
        if path == "/dev/pts/5":
            opened.append((path, flags))
            return 777
        return real_open(path, flags, *a)

    monkeypatch.setattr(os, "open", open_same_user_tty)
    monkeypatch.setattr(os, "ttyname", lambda fd: "/dev/pts/5", raising=False)
    monkeypatch.setattr(os, "dup", lambda fd: pytest.fail("dup used although the path opened"))
    assert cli._open_terminal() == 777
    assert opened[-1] == ("/dev/pts/5", os.O_WRONLY)


def test_a_console_lost_at_the_code_prompt_refuses_and_writes_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The key is shown, then the console goes away at the prompt: a refusal, and no store."""
    import messagefoundry.__main__ as cli

    monkeypatch.chdir(tmp_path)
    _key_in_this_shell(monkeypatch)
    terminal = _drive_the_real_prompt(monkeypatch)

    def lose_it_at_the_prompt(text: str) -> None:
        if text.startswith("Authenticator code"):
            raise OSError("synthetic console loss")
        terminal.show(text)

    monkeypatch.setattr(cli, "_show_on_terminal", lose_it_at_the_prompt)
    db = tmp_path / "provision.db"
    assert main(["provision-admin", "--username", "site-admin", "--db", str(db)]) != 0
    err = capsys.readouterr().err
    assert "console went away" in err and "nothing was written" in err
    assert terminal.asked == 0
    assert not db.exists()


def test_the_last_wrong_code_is_not_told_to_try_again(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Five wrong codes: four retry messages, never a fifth, since no attempt is left after it."""
    monkeypatch.chdir(tmp_path)
    _key_in_this_shell(monkeypatch)
    terminal = _drive_the_real_prompt(
        monkeypatch, ["000000", "111111", "222222", "333333", "444444"]
    )
    assert (
        main(["provision-admin", "--username", "site-admin", "--db", str(tmp_path / "p.db")]) != 0
    )
    assert sum("did not match" in text for text in terminal.shown) == 4
