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
import json
import sys
import types
from pathlib import Path

import pytest

from messagefoundry.__main__ import main
from messagefoundry.auth.identity import AuthProvider
from messagefoundry.auth.permissions import Role
from messagefoundry.auth.service import AuthService, FirstAdministratorRefused
from messagefoundry.config.settings import AuthSettings
from messagefoundry.store.crypto import generate_key, make_cipher
from messagefoundry.store.store import MessageStore

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
            username="site-admin", password=_PASSWORD, actor="test"
        )
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
