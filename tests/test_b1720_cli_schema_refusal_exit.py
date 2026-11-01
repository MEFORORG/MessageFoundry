# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #1720: a server store whose live schema falls short refuses its open with
``ServerSchemaMismatchError``, and at least the CLI commands in :data:`_COMMANDS` report that as
could not start, exit 2.

The error is a ``RuntimeError``, not SQLite's ``sqlite3.DatabaseError``, so no command's SQLite arm
caught it. Through ``_open_store_or_refuse`` it reached the dispatch floor's exit 1, which
``rotate-key`` gives an aborted rotation and ``provision-admin`` a refusal about the account,
though the open had rolled its DDL batch back and written no store row. Severity is conditional
(CLAUDE.md section 0): this is what a first deployment would have hit.

Only a writable open runs the DDL batch and the check, so the stand-in open refuses only those, and
a command that opened read-only would fail :func:`test_a_short_server_schema_is_could_not_start`
for never reaching the refusal. ``audit-verify`` and ``audit-anchor`` open read-only and are not
listed.

Not server-gated: the store open is replaced, so no driver or server runs, and this file imports
nothing the ``serverdb`` change-detection regex must admit.
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

#: Each command that opens the store, with the smallest arguments that reach the open.
#: ``store withdraw-transit-bound`` exited 2 before the fix, through its own arm; it is the
#: regression pin for a command that does not use the shared wrapper.
_COMMANDS: dict[str, list[str]] = {
    "rotate-key": ["rotate-key"],
    "backup": ["backup"],
    "admin-unlock": ["admin-unlock", "--username", "ops"],
    "admin-set-notify-email": [
        "admin-set-notify-email",
        "--username",
        "ops",
        "--email",
        "ops@example.org",
    ],
    "admin-reset-totp": ["admin-reset-totp", "--username", "ops"],
    "admin-revoke-sessions": ["admin-revoke-sessions"],
    "provision-admin": [
        "provision-admin",
        "--username",
        "site-admin",
        "--email",
        "ops@example.invalid",
    ],
    "store withdraw-transit-bound": ["store", "withdraw-transit-bound"],
}

_DIFFERENCE = "table 'messages' lacks column 'lease_owner'"
_PASSWORD = "a-long-enough-operator-passphrase"


@pytest.fixture
def shell(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Path]:
    """A shell holding a store key and nothing else that decides these tests. The server-store legs
    set ``MEFOR_STORE_*`` for their own container, and an environment value outranks the settings
    file written here."""
    from messagefoundry.config.tls_policy import active_hop_posture

    monkeypatch.chdir(tmp_path)
    for name in list(os.environ):
        if name.startswith(("MEFOR_STORE_", "MEFOR_SECURITY_", "MEFOR_TLS_", "MEFOR_ALLOW_")):
            monkeypatch.delenv(name)
    monkeypatch.setenv("MEFOR_STORE_ENCRYPTION_KEY", generate_key())
    with active_hop_posture(None):
        yield tmp_path


def _refusal() -> ServerSchemaMismatchError:
    return ServerSchemaMismatchError("postgres", "mefor", [_DIFFERENCE], schema="public")


@pytest.fixture
def short_schema(monkeypatch: pytest.MonkeyPatch) -> list[bool]:
    """Every writable store open refuses as a PostgreSQL store with a short schema does; a
    read-only one, which runs no DDL batch, fails the test. Returns one entry per refused open, so
    a test can tell the command reached the refusal."""
    from messagefoundry.store import base

    refused: list[bool] = []

    async def refusing(*_args: object, read_only: bool = False, **_kwargs: object) -> object:
        assert not read_only, "a read-only open runs no DDL batch, so it never meets this refusal"
        refused.append(True)
        raise _refusal()

    monkeypatch.setattr(base, "open_store", refusing)
    return refused


def _argv(command: str, tmp: Path) -> list[str]:
    """``command`` pointed at a settings file for a loopback PostgreSQL store at ``enforce``, so the
    revocation guard that runs before the open at ``warn`` does nothing."""
    settings = tmp / "service.toml"
    settings.write_text(
        "[store]\n"
        'backend = "postgres"\n'
        'server = "127.0.0.1"\n'
        'database = "mefor"\n'
        'username = "mefor"\n'
        "\n"
        "[security]\n"
        'enforcement = "enforce"\n',
        encoding="utf-8",
    )
    argv = [*_COMMANDS[command], "--service-config", str(settings)]
    if command == "backup":
        config = tmp / "cfg"
        config.mkdir(exist_ok=True)
        return [*argv, "--config", str(config), "--destination", str(tmp / "dest"), "--no-verify"]
    return argv


@pytest.mark.parametrize("command", _COMMANDS)
def test_a_short_server_schema_is_could_not_start(
    command: str,
    shell: Path,
    short_schema: list[bool],
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Exit 2 with the refusal's text, never the dispatch floor's 1.

    Mutation: drop ``ServerSchemaMismatchError`` from ``_open_store_or_refuse``'s caught tuple;
    every command but ``provision-admin`` and ``store withdraw-transit-bound`` then exits 1. Drop
    it from ``provision-admin``'s pre-check arm and that command exits 1."""
    code = main(_argv(command, shell))
    captured = capsys.readouterr()
    out = captured.out + captured.err
    assert short_schema, "the command never reached the refusal"
    assert code == 2, (captured.out, captured.err)
    # The differences and the remedy the error carries, so the operator reads what to fix.
    assert "postgres schema differs" in out, out
    assert _DIFFERENCE in out, out
    assert "use an empty database or schema" in out, out
    assert "Traceback" not in out, out


def test_provision_admin_refuses_at_the_write_open_too(
    shell: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A database with no ``schema_meta`` table reads to the pre-check as no store, so only the
    ``create=True`` write open runs the DDL batch, after the prompts. That refusal is could not
    start too, exit 2, with nothing provisioned.

    Mutation: drop ``ServerSchemaMismatchError`` from the write's arm; the refusal then reaches
    ``except Exception``, is not an integrity refusal, and the dispatch floor exits 1."""
    from messagefoundry import __main__ as cli
    from messagefoundry.config.settings import StoreBackend
    from messagefoundry.store import base

    opens: list[bool] = []

    async def opening(*_args: object, create: bool = False, **_kwargs: object) -> object:
        opens.append(create)
        if not create:
            raise base.StoreNotFoundError.server_schema(StoreBackend.POSTGRES, "mefor")
        raise _refusal()

    monkeypatch.setattr(base, "open_store", opening)
    monkeypatch.setattr(sys, "stdin", types.SimpleNamespace(isatty=lambda: True))
    monkeypatch.setattr("getpass.getpass", lambda *_a, **_k: _PASSWORD)
    monkeypatch.setattr(
        cli, "_enrol_totp_at_terminal", lambda **_k: ("JBSWY3DPEHPK3PXP", "123456", 0.0)
    )
    code = main(_argv("provision-admin", shell))
    captured = capsys.readouterr()
    out = captured.out + captured.err
    assert opens == [False, True], "the refusal did not arrive at the write open"
    assert code == 2, (captured.out, captured.err)
    assert _DIFFERENCE in out, out
    assert "Traceback" not in out, out


def test_the_wrapper_keeps_the_refusal_as_its_cause() -> None:
    """The wrapped refusal keeps the error as its cause and its text whole, so a caller that reads
    the cause (``backup`` does, for a key error) still can."""
    import asyncio

    from messagefoundry.__main__ import _open_store_or_refuse, _StoreOpenRefused
    from messagefoundry.store.base import Store

    refusal = ServerSchemaMismatchError("sqlserver", None, [_DIFFERENCE])

    async def opening() -> Store:
        raise refusal

    with pytest.raises(_StoreOpenRefused) as caught:
        asyncio.run(_open_store_or_refuse(opening()))
    assert caught.value.__cause__ is refusal
    assert str(caught.value) == str(refusal)
