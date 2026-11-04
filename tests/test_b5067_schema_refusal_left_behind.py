# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #5067: ``provision-admin`` and ``admin-reset-totp`` say only what a refused store open
left behind.

Both said "nothing was written" for a server store whose live schema falls short of this build's
DDL batch (``ServerSchemaMismatchError``, BACKLOG #1720). The open rolls that batch back and writes
no schema marker. But on SQL Server under ``[store].schema_management = auto`` a writable open first
switches database options on, outside the batch (``_open_refusal_left_behind`` names them), so the
database may already have changed. Each refusal now says the batch was rolled back, and there, that the setting
may have changed. ``provision-admin``'s refusal at the write, after the key was shown, also says the
entry the operator may have added has no seed, as ``admin-reset-totp`` already did. Severity is
conditional (CLAUDE.md section 0): this is what a first deployment would have read.

Not server-gated: the store open is replaced, so no driver or server runs.
"""

from __future__ import annotations

import sys
import types
from pathlib import Path

import pytest

from messagefoundry.__main__ import main
from messagefoundry.store.server_schema_verify import ServerSchemaMismatchError

# The shell, the difference and the password the #1720 tests use, shared rather than copied.
from tests.test_b1720_cli_schema_refusal_exit import _DIFFERENCE, _PASSWORD
from tests.test_b1720_cli_schema_refusal_exit import shell as shell  # noqa: F401

_RCSI = "READ_COMMITTED_SNAPSHOT and ALLOW_SNAPSHOT_ISOLATION options"
_ROLLED_BACK = "rolled its schema batch back and wrote no schema marker"
_UNUSED_ENTRY = "If you added the entry this run showed to the authenticator app, delete it"

#: ``(backend, schema_management)`` -> whether the refusal names the database setting.
_STORES = {
    ("sqlserver", "auto"): True,
    ("postgres", "auto"): False,
}


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


def _every_open_refuses(monkeypatch: pytest.MonkeyPatch, backend: str) -> None:
    """Every store open refuses as a server store with a short schema does."""
    from messagefoundry.store import base

    async def refusing(*_args: object, **_kwargs: object) -> object:
        raise _refusal(backend)

    monkeypatch.setattr(base, "open_store", refusing)


def _refused_at_the_write(
    monkeypatch: pytest.MonkeyPatch, backend: str, refusal: Exception
) -> None:
    """The pre-check finds no store, so ``provision-admin`` prompts, shows the key and reaches the
    write's ``create=True`` open, which raises ``refusal``. A console types the password and proves
    the enrolment."""
    from messagefoundry import __main__ as cli
    from messagefoundry.config.settings import StoreBackend
    from messagefoundry.store import base

    async def opening(*_args: object, create: bool = False, **_kwargs: object) -> object:
        if not create:
            raise base.StoreNotFoundError.server_schema(StoreBackend(backend), "mefor")
        raise refusal

    monkeypatch.setattr(base, "open_store", opening)
    monkeypatch.setattr(sys, "stdin", types.SimpleNamespace(isatty=lambda: True))
    monkeypatch.setattr("getpass.getpass", lambda *_a, **_k: _PASSWORD)
    monkeypatch.setattr(
        cli, "_enrol_totp_at_terminal", lambda **_k: ("JBSWY3DPEHPK3PXP", "123456", 0.0)
    )


def _run(argv: list[str], capsys: pytest.CaptureFixture[str]) -> str:
    """Run the command; its output, once it exited 2, could not start."""
    code = main(argv)
    captured = capsys.readouterr()
    out = captured.out + captured.err
    assert code == 2, out
    return out


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
    _every_open_refuses(monkeypatch, backend)
    out = _run(_provision(_settings(shell, backend, management)), capsys)
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

    Mutation: drop ``after_the_key`` from the write's open-refusal arm."""
    _refused_at_the_write(monkeypatch, backend, _refusal(backend))
    out = _run(_provision(_settings(shell, backend, management)), capsys)
    _assert_left_behind(out, names_the_setting=_STORES[backend, management])
    assert _UNUSED_ENTRY in out, out


def test_provision_admin_write_names_no_entry_under_no_totp(
    shell: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The control on the entry: with ``--no-totp`` no key was shown, so no entry is named, and
    the hint above is not printed on every refusal."""
    _refused_at_the_write(monkeypatch, "sqlserver", _refusal("sqlserver"))
    settings = _settings(shell, "sqlserver", "auto", require_mfa=False)
    out = _run(_provision(settings, "--no-totp"), capsys)
    _assert_left_behind(out, names_the_setting=True)
    assert _UNUSED_ENTRY not in out, out


def test_provision_admin_keyless_refusal_at_the_write_names_the_entry(
    shell: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """A keyless refusal at the write comes after the key was shown too, and before any write.

    Mutation: drop ``after_the_key`` from the keyless arm."""
    from messagefoundry.store import base

    refusal = base.KeylessAuditChainRefused("mefor", "[store].synthetic_setting")
    _refused_at_the_write(monkeypatch, "sqlserver", refusal)
    out = _run(_provision(_settings(shell, "sqlserver", "auto")), capsys)
    assert "[store].synthetic_setting" in out, out
    assert _UNUSED_ENTRY in out, out


@pytest.mark.parametrize("kind", ["keyless", "cipher"])
def test_provision_admin_key_refusal_at_the_write_open_names_the_entry(
    kind: str, shell: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """A key or cipher refusal at the write's ``create=True`` open comes after the key was shown
    and before any write: could not start, exit 2, with the pre-check's text and the entry named.
    It escaped to the CLI floor's exit 1 with no hint.

    Mutation: drop the write's ``(StoreKeylessError, CipherError)`` arm; the exit is then 1."""
    from messagefoundry.store.crypto import CipherError, StoreKeylessError

    refusal: Exception = (
        StoreKeylessError("table synthetic_table holds an encrypted value")
        if kind == "keyless"
        else CipherError("table synthetic_table holds a value no key opens")
    )
    _refused_at_the_write(monkeypatch, "sqlserver", refusal)
    out = _run(_provision(_settings(shell, "sqlserver", "auto")), capsys)
    assert "synthetic_table" in out, out
    assert "nothing was written" in out, out
    assert _UNUSED_ENTRY in out, out
    assert "Traceback" not in out, out


def test_provision_admin_names_no_entry_once_the_write_has_started(
    shell: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """A refusal the write's arms catch, raised once the service's write has started, names no
    entry: the seed may then be stored, and deleting the entry would leave the Administrator
    without its factor. A real SQLite store, so the open succeeds and the write is reached.

    Mutation: drop the ``write_started`` branch from ``after_the_key``; the hint is then
    printed."""
    from messagefoundry.auth.service import AuthService
    from messagefoundry.config.tls_policy import InsecureHopRefused

    async def refusing(*_args: object, **_kwargs: object) -> object:
        raise InsecureHopRefused("synthetic hop refusal inside the write")

    monkeypatch.setattr(AuthService, "provision_first_administrator", refusing)
    monkeypatch.setattr(sys, "stdin", types.SimpleNamespace(isatty=lambda: True))
    monkeypatch.setattr("getpass.getpass", lambda *_a, **_k: _PASSWORD)
    argv = [
        "provision-admin",
        "--username",
        "site-admin",
        "--email",
        "ops@example.invalid",
        "--db",
        str(shell / "provision.db"),
    ]
    out = _run(argv, capsys)
    assert "synthetic hop refusal inside the write" in out, out
    assert _UNUSED_ENTRY not in out, out
    assert "nothing was written" not in out.lower(), out
    assert "may be missing or incomplete" in out, out


def test_provision_admin_pre_check_cipher_refusal_quotes_no_key_byte(
    shell: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The pre-check's key or cipher arm prints through ``codec_safe_str`` too (BACKLOG #2532).

    Mutation: print ``_sentence(exc)`` again in that arm; the byte is then quoted."""
    from messagefoundry.store import base
    from messagefoundry.store.crypto import CipherError

    async def refusing(*_args: object, **_kwargs: object) -> object:
        try:
            b"\xe9".decode("ascii")
        except UnicodeDecodeError as exc:
            raise CipherError(exc) from exc
        raise AssertionError("unreachable")

    monkeypatch.setattr(base, "open_store", refusing)
    out = _run(_provision(_settings(shell, "sqlserver", "auto")), capsys)
    assert "xe9" not in out.lower(), out
    assert "Nothing was written" in out, out


def test_provision_admin_names_the_os_user_before_the_key_is_shown(
    shell: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """A shell whose OS user cannot be named is refused before the key is shown, so no entry is
    left for a seed never stored. It was named after the key was shown, and an ``OSError`` there
    escaped with no hint.

    Mutation: name the OS user after ``_enrol_totp_at_terminal`` again; the enrolment then runs."""
    from messagefoundry import __main__ as cli

    _refused_at_the_write(monkeypatch, "sqlserver", _refusal("sqlserver"))
    shown: list[object] = []

    def enrol(**_k: object) -> tuple[str, str, float]:
        shown.append(_k)
        return ("JBSWY3DPEHPK3PXP", "123456", 0.0)

    def no_user() -> str:
        raise OSError("no user name for this shell")

    monkeypatch.setattr(cli, "_enrol_totp_at_terminal", enrol)
    monkeypatch.setattr("getpass.getuser", no_user)
    code = main(_provision(_settings(shell, "sqlserver", "auto")))
    captured = capsys.readouterr()
    out = captured.out + captured.err
    assert code != 0, out
    assert not shown, "the key was shown before the OS user was named"
    assert "cannot name the OS user" in out and "nothing was written" in out, out
    assert "Traceback" not in out, out


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
    _every_open_refuses(monkeypatch, backend)
    settings = _settings(shell, backend, management)
    out = _run(["admin-reset-totp", "--username", "ops", "--service-config", str(settings)], capsys)
    _assert_left_behind(out, names_the_setting=_STORES[backend, management])


def test_any_other_open_refusal_keeps_its_text() -> None:
    """The control on the helper: only the schema refusal, raised or as a cause, has more to say."""
    from messagefoundry.__main__ import _open_refusal_left_behind, _StoreOpenRefused
    from messagefoundry.config.settings import SchemaManagement, StoreBackend, StoreSettings

    store = StoreSettings(
        backend=StoreBackend.SQLSERVER,
        server="127.0.0.1",
        database="mefor",
        username="mefor",
        schema_management=SchemaManagement.AUTO,
    )
    assert _open_refusal_left_behind(RuntimeError("a hop refusal"), store) is None
    wrapped_other = _StoreOpenRefused("a key refusal")
    wrapped_other.__cause__ = RuntimeError("a key refusal")
    assert _open_refusal_left_behind(wrapped_other, store) is None
    wrapped = _StoreOpenRefused("short")
    wrapped.__cause__ = _refusal("sqlserver")
    assert _RCSI in (_open_refusal_left_behind(wrapped, store) or "")


def test_provision_admin_open_refusal_quotes_no_key_byte(
    shell: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """A key source's codec error at provision-admin's open does not print the byte it quotes,
    as no other store command does (BACKLOG #2532).

    Mutation: build ``_provision_open_refusal``'s text from ``str(exc)``."""
    from messagefoundry.store import base
    from messagefoundry.store.keyprovider import KeyProviderError

    async def refusing(*_args: object, **_kwargs: object) -> object:
        try:
            b"\xe9".decode("ascii")
        except UnicodeDecodeError as exc:
            raise KeyProviderError(exc) from exc
        raise AssertionError("unreachable")

    monkeypatch.setattr(base, "open_store", refusing)
    out = _run(_provision(_settings(shell, "sqlserver", "auto")), capsys)
    assert "xe9" not in out.lower(), out
    assert "nothing was written" in out, out
