# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #2532: every command that opens the store passes the instance's hop posture.

``serve`` and ``provision-admin`` open a server store with the posture ``hop_posture_from_ai`` derives.
The commands below opened it with none. ``None`` is the strict answer for a weakened-TLS check and
for a Vault hop, but not for the PostgreSQL revocation guard, which is a no-op with no posture. So
on a first deployment at ``enforce`` each of them would have crossed an off-box store hop with no
revocation check, one ``serve`` itself refuses.

The tests drive each command through ``main`` to the real ``PostgresStore._create_pool``. Only the
driver module is a stand-in, so what is proved is whether the guard let the command dial:

* :func:`test_a_hop_serve_refuses_is_refused` refuses, exit 2, and dials nothing;
* :func:`test_a_loopback_hop_is_accepted` is the control at the hop ``serve`` accepts;
* :func:`test_warn_crosses_the_same_hop` is the control on the dial: the same hop crosses at
  ``warn``, so the refusal above is the instance's posture and not a constant.

Severity is conditional (CLAUDE.md section 0): zero deployments, so this is what a first deployment
would have inherited.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

from messagefoundry.__main__ import main
from messagefoundry.store.crypto import generate_key
from tests.test_store_ssl import _FakeAsyncpg

_REMOTE = "db.example.invalid"
_LOOPBACK = "127.0.0.1"

#: Each command that opens the store, with the smallest arguments that reach the open. ``store
#: withdraw-transit-bound`` stands for its twin, which shares the open and needs a Transit cipher.
_COMMANDS: dict[str, list[str]] = {
    "admin-unlock": ["admin-unlock", "--username", "ops"],
    "admin-set-notify-email": [
        "admin-set-notify-email",
        "--username",
        "ops",
        "--email",
        "ops@example.org",
    ],
    "admin-reset-totp": ["admin-reset-totp", "--username", "ops"],
    "store withdraw-transit-bound": ["store", "withdraw-transit-bound"],
    "audit-verify": ["audit-verify"],
    "audit-anchor": ["audit-anchor"],
    "rotate-key": ["rotate-key"],
    "backup": ["backup"],
}


class _RefusingAsyncpg(_FakeAsyncpg):
    """The shared stand-in, with the error classes ``store_driver_errors`` reads off the module. It
    records the pool request, then refuses it as a server that is not there would, so a command that
    got past the guard stops at the dial."""

    PostgresError = type("PostgresError", (Exception,), {})
    InterfaceError = type("InterfaceError", (Exception,), {})
    InternalClientError = type("InternalClientError", (Exception,), {})

    async def create_pool(self, **kwargs: object) -> object:
        await super().create_pool(**kwargs)
        raise ConnectionRefusedError("no server in this test")


@pytest.fixture
def asyncpg(monkeypatch: pytest.MonkeyPatch) -> _RefusingAsyncpg:
    fake = _RefusingAsyncpg()
    monkeypatch.setitem(sys.modules, "asyncpg", fake)
    return fake


@pytest.fixture
def shell(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """A shell holding a store key and nothing else that decides these tests. The server-store legs
    set ``MEFOR_STORE_*`` and the TLS escape for their own container, and an environment value
    outranks the settings file these tests write."""
    monkeypatch.chdir(tmp_path)
    for name in list(os.environ):
        if name.startswith(("MEFOR_STORE_", "MEFOR_SECURITY_", "MEFOR_TLS_", "MEFOR_ALLOW_")):
            monkeypatch.delenv(name)
    monkeypatch.setenv("MEFOR_STORE_ENCRYPTION_KEY", generate_key())
    return tmp_path


def _argv(command: str, tmp: Path, *, server: str, enforcement: str) -> list[str]:
    """``command`` pointed at a settings file for a PostgreSQL store on ``server``, verified TLS and
    no CRL, at ``enforcement``."""
    settings = tmp / "service.toml"
    settings.write_text(
        "[store]\n"
        'backend = "postgres"\n'
        f'server = "{server}"\n'
        'database = "mefor"\n'
        'username = "mefor"\n'
        "\n"
        "[security]\n"
        f'enforcement = "{enforcement}"\n',
        encoding="utf-8",
    )
    argv = [*_COMMANDS[command], "--service-config", str(settings)]
    if command == "backup":
        config = tmp / "cfg"
        config.mkdir(exist_ok=True)
        return [*argv, "--config", str(config), "--destination", str(tmp / "dest"), "--no-verify"]
    return argv


@pytest.mark.parametrize("command", _COMMANDS)
def test_a_hop_serve_refuses_is_refused(
    command: str, shell: Path, asyncpg: _RefusingAsyncpg, capsys: pytest.CaptureFixture[str]
) -> None:
    """Exit 2, could not start, and never the dispatch floor's 1: in the audit family that is a
    broken chain's code, and on ``rotate-key`` an aborted rotation's.

    Mutation: drop ``posture=posture`` from the command's ``open_store`` call."""
    code = main(_argv(command, shell, server=_REMOTE, enforcement="enforce"))
    captured = capsys.readouterr()
    assert not asyncpg.pool_kwargs, "the command crossed a hop serve refuses"
    assert code == 2, (captured.out, captured.err)
    assert "revocation" in captured.out + captured.err


@pytest.mark.parametrize("command", _COMMANDS)
def test_a_loopback_hop_is_accepted(command: str, shell: Path, asyncpg: _RefusingAsyncpg) -> None:
    """The control: at the same dial the guard lets an on-box store through, so the test above is
    refused for its hop. The stand-in then refuses the connection, whose exit is not the question."""
    main(_argv(command, shell, server=_LOOPBACK, enforcement="enforce"))
    assert asyncpg.pool_kwargs["host"] == _LOOPBACK


@pytest.mark.parametrize("command", _COMMANDS)
def test_warn_crosses_the_same_hop(command: str, shell: Path, asyncpg: _RefusingAsyncpg) -> None:
    """The control on the dial: the refused hop crosses at ``warn``, as it does for ``serve``, so
    the posture is the instance's own. A hard-coded enforcing posture would pass the test above."""
    main(_argv(command, shell, server=_REMOTE, enforcement="warn"))
    assert asyncpg.pool_kwargs["host"] == _REMOTE
