# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #5067: ``provision-admin`` and ``admin-reset-totp`` say only what a refused store open
left behind.

Both said "nothing was written" for a server store whose live schema falls short of this build's
DDL batch (``ServerSchemaMismatchError``, BACKLOG #1720). The open rolls that batch back and writes
no schema marker. But on SQL Server under ``[store].schema_management = auto`` a writable open first
switches the database's READ_COMMITTED_SNAPSHOT option on, outside the batch, so the database may
already have changed. Each refusal now says the batch was rolled back, and there, that the setting
may have changed. ``provision-admin``'s refusal at the write, after the key was shown, also says the
entry the operator may have added has no seed, as ``admin-reset-totp`` already did. Severity is
conditional (CLAUDE.md section 0): this is what a first deployment would have read.

Not server-gated: the store open is replaced, so no driver or server runs.
"""

from __future__ import annotations

import os
import sys
import types
from collections.abc import Iterator
from pathlib import Path

import pytest

from messagefoundry.__main__ import main
from messagefoundry.store.crypto import generate_key
from messagefoundry.store.server_schema_verify import ServerSchemaMismatchError

_DIFFERENCE = "table 'messages' lacks column 'lease_owner'"
_PASSWORD = "a-long-enough-operator-passphrase"
_RCSI = "READ_COMMITTED_SNAPSHOT"
_ROLLED_BACK = "rolled its schema batch back and wrote no schema marker"
_UNUSED_ENTRY = "If you added the entry this run showed to the authenticator app, delete it"

#: ``(backend, schema_management)`` -> whether the refusal names the database setting.
_STORES = {
    ("sqlserver", "auto"): True,
    ("sqlserver", "external"): False,
    ("postgres", "auto"): False,
}


@pytest.fixture
def shell(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Path]:
    """A shell holding a store key and nothing else that decides these tests (as
    ``tests/test_b1720_cli_schema_refusal_exit.py`` sets one up)."""
    from messagefoundry.config.tls_policy import active_hop_posture

    monkeypatch.chdir(tmp_path)
    for name in list(os.environ):
        if name.startswith(("MEFOR_STORE_", "MEFOR_SECURITY_", "MEFOR_TLS_", "MEFOR_ALLOW_")):
            monkeypatch.delenv(name)
    monkeypatch.setenv("MEFOR_STORE_ENCRYPTION_KEY", generate_key())
    with active_hop_posture(None):
        yield tmp_path


def _settings(tmp: Path, backend: str, management: str, *, require_mfa: bool = True) -> Path:
    """A loopback server store at ``enforce``, so the revocation guard that runs before the open at
    ``warn`` does nothing."""
    auth = "integrated" if backend == "sqlserver" else "sql"
    settings = tmp / "service.toml"
    settings.write_text(
        "[store]\n"
        f'backend = "{backend}"\n'
        'server = "127.0.0.1"\n'
        'database = "mefor"\n'
        'username = "mefor"\n'
        f'auth = "{auth}"\n'
        f'schema_management = "{management}"\n'
        "\n"
        "[security]\n"
        f"require_mfa = {'true' if require_mfa else 'false'}\n"
        'enforcement = "enforce"\n',
        encoding="utf-8",
    )
    return settings


def _refusal(backend: str) -> ServerSchemaMismatchError:
    return ServerSchemaMismatchError(backend, "mefor", [_DIFFERENCE])


def _provision(settings: Path, *extra: str) -> list[str]:
    return [
        "provision-admin",
        "--username",
        "site-admin",
        "--email",
        "ops@example.invalid",
        *extra,
        "--service-config",
        str(settings),
    ]


def _at_a_terminal(monkeypatch: pytest.MonkeyPatch) -> None:
    """A console that types the password and proves an enrolment, so the command reaches the
    write."""
    from messagefoundry import __main__ as cli

    monkeypatch.setattr(sys, "stdin", types.SimpleNamespace(isatty=lambda: True))
    monkeypatch.setattr("getpass.getpass", lambda *_a, **_k: _PASSWORD)
    monkeypatch.setattr(
        cli, "_enrol_totp_at_terminal", lambda **_k: ("JBSWY3DPEHPK3PXP", "123456", 0.0)
    )


def _assert_left_behind(out: str, *, names_the_setting: bool) -> None:
    assert _DIFFERENCE in out, out
    assert _ROLLED_BACK in out, out
    assert "nothing was written" not in out.lower(), out
    assert (_RCSI in out) is names_the_setting, out
    assert "Traceback" not in out, out


@pytest.mark.parametrize(("backend", "management"), _STORES)
def test_provision_admin_pre_check_says_what_the_open_left(
    backend: str,
    management: str,
    shell: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The pre-check open, before the prompt. Exit 2 as before (#1720).

    Mutation: print ``_NOTHING_PROVISIONED`` again in the pre-check's arm."""
    from messagefoundry.store import base

    async def refusing(*_args: object, **_kwargs: object) -> object:
        raise _refusal(backend)

    monkeypatch.setattr(base, "open_store", refusing)
    code = main(_provision(_settings(shell, backend, management)))
    captured = capsys.readouterr()
    out = captured.out + captured.err
    assert code == 2, out
    assert "Refusing to provision" in out, out
    _assert_left_behind(out, names_the_setting=_STORES[backend, management])
    assert _UNUSED_ENTRY not in out, "no key was shown before the pre-check"


@pytest.mark.parametrize(("backend", "management"), _STORES)
def test_provision_admin_write_says_what_the_open_left_and_names_the_entry(
    backend: str,
    management: str,
    shell: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The write's ``create=True`` open, after the key was shown: the text also names the unused
    authenticator entry.

    Mutation: drop ``before_the_write`` from the write's open-refusal arm."""
    from messagefoundry.config.settings import StoreBackend
    from messagefoundry.store import base

    async def opening(*_args: object, create: bool = False, **_kwargs: object) -> object:
        if not create:
            raise base.StoreNotFoundError.server_schema(StoreBackend(backend), "mefor")
        raise _refusal(backend)

    monkeypatch.setattr(base, "open_store", opening)
    _at_a_terminal(monkeypatch)
    code = main(_provision(_settings(shell, backend, management)))
    captured = capsys.readouterr()
    out = captured.out + captured.err
    assert code == 2, out
    _assert_left_behind(out, names_the_setting=_STORES[backend, management])
    assert _UNUSED_ENTRY in out, out


def test_provision_admin_write_names_no_entry_under_no_totp(
    shell: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The control on the entry: with ``--no-totp`` no key was shown, so no entry is named, and
    the hint above is not printed on every refusal."""
    from messagefoundry.config.settings import StoreBackend
    from messagefoundry.store import base

    async def opening(*_args: object, create: bool = False, **_kwargs: object) -> object:
        if not create:
            raise base.StoreNotFoundError.server_schema(StoreBackend.SQLSERVER, "mefor")
        raise _refusal("sqlserver")

    monkeypatch.setattr(base, "open_store", opening)
    _at_a_terminal(monkeypatch)
    settings = _settings(shell, "sqlserver", "auto", require_mfa=False)
    code = main(_provision(settings, "--no-totp"))
    captured = capsys.readouterr()
    out = captured.out + captured.err
    assert code == 2, out
    _assert_left_behind(out, names_the_setting=True)
    assert _UNUSED_ENTRY not in out, out


def test_provision_admin_keyless_refusal_at_the_write_names_the_entry(
    shell: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """A keyless refusal at the write comes after the key was shown too, and before any write.

    Mutation: drop ``before_the_write`` from the keyless arm."""
    from messagefoundry.config.settings import StoreBackend
    from messagefoundry.store import base

    async def opening(*_args: object, create: bool = False, **_kwargs: object) -> object:
        if not create:
            raise base.StoreNotFoundError.server_schema(StoreBackend.SQLSERVER, "mefor")
        raise base.KeylessAuditChainRefused("mefor", "[store].synthetic_setting")

    monkeypatch.setattr(base, "open_store", opening)
    _at_a_terminal(monkeypatch)
    code = main(_provision(_settings(shell, "sqlserver", "auto")))
    captured = capsys.readouterr()
    out = captured.out + captured.err
    assert code == 2, out
    assert "[store].synthetic_setting" in out, out
    assert _UNUSED_ENTRY in out, out


@pytest.mark.parametrize(("backend", "management"), _STORES)
def test_admin_reset_totp_says_what_the_open_left(
    backend: str,
    management: str,
    shell: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """``admin-reset-totp``'s first open, wrapped by ``_open_store_or_refuse``, so the schema
    refusal arrives as the cause of a ``_StoreOpenRefused``.

    Mutation: print "Nothing was written." again in ``open_refused``'s could-not-start arm."""
    from messagefoundry.store import base

    async def refusing(*_args: object, **_kwargs: object) -> object:
        raise _refusal(backend)

    monkeypatch.setattr(base, "open_store", refusing)
    settings = _settings(shell, backend, management)
    code = main(["admin-reset-totp", "--username", "ops", "--service-config", str(settings)])
    captured = capsys.readouterr()
    out = captured.out + captured.err
    assert code == 2, out
    _assert_left_behind(out, names_the_setting=_STORES[backend, management])


def test_any_other_open_refusal_still_says_nothing_was_written() -> None:
    """The control on the helper: only the schema refusal changes its text."""
    from messagefoundry.__main__ import _open_refusal_left_behind, _StoreOpenRefused
    from messagefoundry.config.settings import SchemaManagement, StoreBackend, StoreSettings

    store = StoreSettings(
        backend=StoreBackend.SQLSERVER,
        server="127.0.0.1",
        database="mefor",
        username="mefor",
        schema_management=SchemaManagement.AUTO,
    )
    assert _open_refusal_left_behind(RuntimeError("a hop refusal"), store) == (
        "nothing was written"
    )
    wrapped = _StoreOpenRefused("short")
    wrapped.__cause__ = _refusal("sqlserver")
    assert _RCSI in _open_refusal_left_behind(wrapped, store)
