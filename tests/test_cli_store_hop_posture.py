# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #2532: the commands in :data:`_COMMANDS` pass the instance's hop posture to the store at
``enforce``, and none at ``warn``.

``serve`` and ``provision-admin`` open a server store with the posture ``hop_posture_from_ai`` derives.
The BACKLOG #2532 commands opened it with none. ``admin-revoke-sessions`` (BACKLOG #2614) came
later, follows the same rule and is listed with them. ``None`` is the strict answer for a
weakened-TLS check and for a Vault hop, but not for the PostgreSQL revocation guard, which is a
no-op with no posture. So on a first deployment at ``enforce`` each #2532 command would have
crossed an off-box store hop with no revocation check, one ``serve`` itself refuses. At least ``support-bundle`` and ``verify`` still pass
none; ``tests/test_vault_posture_census.py`` lists what each caller passes.

The tests drive each command through ``main`` to the real ``PostgresStore._create_pool``. Only the
driver module is a stand-in, so what is proved is whether the guard let the command dial:

* :func:`test_a_hop_serve_refuses_is_refused` refuses, exit 2, and dials nothing;
* :func:`test_a_loopback_hop_is_accepted` is the control at the hop ``serve`` accepts;
* :func:`test_warn_crosses_the_same_hop` is the control on the dial: the same hop crosses at
  ``warn`` with ``serve``'s WARNING, so the refusal above is the instance's posture and not a
  constant;
* :func:`test_a_weakened_hop_is_refused` is the weakened-TLS check, which a SQL Server store has
  too, beside the pin's anchor checks, which these tests do not drive;
* :func:`test_warn_keeps_refusing_a_weakened_hop_with_the_escape` and
  :func:`test_warn_keeps_refusing_an_unattested_off_box_vault` hold the no-loosening rule (Manager
  decision d20261031T021248404-699a64): at ``warn`` each command still refuses what it refused with
  no posture, where ``serve`` would cross.

Severity is conditional (CLAUDE.md section 0): zero deployments, so this is what a first deployment
would have inherited.
"""

from __future__ import annotations

import os
import sys
from collections.abc import Iterator
from pathlib import Path

import pytest

from messagefoundry.__main__ import main
from messagefoundry.config.settings import INSECURE_TLS_ESCAPE_ENV
from messagefoundry.store.crypto import generate_key
from tests._extras_probe import OPTIONAL_EXTRAS, extra_is_installed
from tests.test_store_ssl import _FakeAsyncpg

_REMOTE = "db.example.invalid"
_LOOPBACK = "127.0.0.1"

#: Each command that opens the store, with the smallest arguments that reach the open. ``store
#: withdraw-transit-bound`` stands for its twin, which shares the open and needs a Transit cipher.
_COMMANDS: dict[str, list[str]] = {
    "admin-unlock": ["admin-unlock", "--username", "ops"],
    "admin-revoke-sessions": ["admin-revoke-sessions"],  # BACKLOG #2614
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
def shell(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Path]:
    """A shell holding a store key and nothing else that decides these tests. The server-store legs
    set ``MEFOR_STORE_*`` and the TLS escape for their own container, and an environment value
    outranks the settings file these tests write. They also stamp an ambient ``warn`` posture
    (``tests/conftest.py``), which a ``None`` posture reads; no CLI path stamps one, so it is
    cleared here, as a real shell has none."""
    from messagefoundry.config.tls_policy import active_hop_posture

    monkeypatch.chdir(tmp_path)
    for name in list(os.environ):
        if name.startswith(("MEFOR_STORE_", "MEFOR_SECURITY_", "MEFOR_TLS_", "MEFOR_ALLOW_")):
            monkeypatch.delenv(name)
    monkeypatch.setenv("MEFOR_STORE_ENCRYPTION_KEY", generate_key())
    with active_hop_posture(None):
        yield tmp_path


def _argv(
    command: str, tmp: Path, *, server: str, enforcement: str, weakened: bool = False
) -> list[str]:
    """``command`` pointed at a settings file for a PostgreSQL store on ``server``, verified TLS and
    no CRL, or with verification off when ``weakened``, at ``enforcement``."""
    settings = tmp / "service.toml"
    settings.write_text(
        "[store]\n"
        'backend = "postgres"\n'
        f'server = "{server}"\n'
        'database = "mefor"\n'
        'username = "mefor"\n'
        f"trust_server_certificate = {'true' if weakened else 'false'}\n"
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
def test_warn_crosses_the_same_hop(
    command: str,
    shell: Path,
    asyncpg: _RefusingAsyncpg,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """The control on the dial: the refused hop crosses at ``warn``, as it does for ``serve``, so
    the posture is the instance's own. A hard-coded enforcing posture would pass the test above.
    It crosses with the WARNING that is the only record of the crossing."""
    with caplog.at_level("WARNING"):
        main(_argv(command, shell, server=_REMOTE, enforcement="warn"))
    assert asyncpg.pool_kwargs["host"] == _REMOTE
    assert any("insecure transport hop permitted" in r.getMessage() for r in caplog.records)


@pytest.mark.parametrize("command", _COMMANDS)
def test_a_weakened_hop_is_refused(
    command: str,
    shell: Path,
    asyncpg: _RefusingAsyncpg,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    caplog: pytest.LogCaptureFixture,
) -> None:
    """The escape is inert at ``enforce``, with a posture as it was with none. The exit is not
    pinned: this refusal is a bare ``ValueError``, so it reaches the dispatch floor's 1. The reason
    is pinned, so a refusal for any other cause before the dial does not pass for this one."""
    monkeypatch.setenv(INSECURE_TLS_ESCAPE_ENV, "1")
    code = main(_argv(command, shell, server=_REMOTE, enforcement="enforce", weakened=True))
    captured = capsys.readouterr()
    assert not asyncpg.pool_kwargs, "the command crossed a hop serve refuses"
    assert code != 0
    assert "weakened" in (captured.out + captured.err + caplog.text).lower(), (
        captured.out,
        captured.err,
    )


@pytest.mark.parametrize("command", _COMMANDS)
def test_warn_keeps_refusing_a_weakened_hop_with_the_escape(
    command: str,
    shell: Path,
    asyncpg: _RefusingAsyncpg,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    caplog: pytest.LogCaptureFixture,
) -> None:
    """No command loosens (Manager decision 2026-10-31). With no posture these commands refused a
    weakened store whatever the dial said, so at ``warn`` they still refuse it with the escape set,
    where ``serve`` would cross.

    Mutation: return the ``warn`` posture from ``_command_hop_posture``; the command then dials."""
    monkeypatch.setenv(INSECURE_TLS_ESCAPE_ENV, "1")
    code = main(_argv(command, shell, server=_REMOTE, enforcement="warn", weakened=True))
    captured = capsys.readouterr()
    assert not asyncpg.pool_kwargs, "the command crossed a weakened hop it refused before"
    assert code != 0
    assert "weakened" in (captured.out + captured.err + caplog.text).lower(), (
        captured.out,
        captured.err,
    )


@pytest.mark.skipif(
    not extra_is_installed(OPTIONAL_EXTRAS["vault"]),
    reason="the [vault] extra (hvac + requests + urllib3) is not installed in this interpreter",
)
@pytest.mark.parametrize("command", _COMMANDS)
def test_warn_keeps_refusing_an_unattested_off_box_vault(
    command: str,
    shell: Path,
    asyncpg: _RefusingAsyncpg,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """With no posture the Vault store-key hop counted as enforcing, so an unattested off-box
    Vault was refused. At ``warn`` it still is, where ``serve`` would cross it with a WARNING. The
    refusal is decided before the client dials, so the proof is that nothing was dialled.

    Mutation: return the ``warn`` posture from ``_command_hop_posture``; the client then dials."""
    import urllib.request

    import urllib3.util.connection

    for name in (
        "HTTPS_PROXY",
        "https_proxy",
        "HTTP_PROXY",
        "http_proxy",
        "ALL_PROXY",
        "all_proxy",
    ):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(urllib.request, "getproxies_registry", dict, raising=False)
    monkeypatch.setattr(urllib.request, "proxy_bypass_registry", lambda host: False, raising=False)
    dialled: list[object] = []

    def record(address: object, *args: object, **kwargs: object) -> object:
        dialled.append(address)
        raise OSError("synthetic: this test dials nothing")

    monkeypatch.setattr(urllib3.util.connection, "create_connection", record)
    monkeypatch.delenv("MEFOR_STORE_ENCRYPTION_KEY", raising=False)
    monkeypatch.setenv("MEFOR_STORE_KEY_PROVIDER", "vault")
    monkeypatch.setenv("MEFOR_STORE_VAULT_ADDR", "https://vault.synthetic.test:8200")
    monkeypatch.setenv("MEFOR_STORE_VAULT_TOKEN", "s.synthetic-token")
    monkeypatch.setenv("MEFOR_STORE_VAULT_TRANSIT_KEY", "synthetic-kek")
    monkeypatch.setenv("MEFOR_STORE_VAULT_WRAPPED_DEK", "vault:v1:c3ludGhldGlj")
    code = main(_argv(command, shell, server=_LOOPBACK, enforcement="warn"))
    assert not dialled, "the command dialled an unattested off-box Vault it refused before"
    assert not asyncpg.pool_kwargs, "the store opened without its key"
    assert code != 0


def test_the_open_refusal_quotes_no_key_byte() -> None:
    """Review R2-7: every caller prints the refusal's text, so it goes through ``codec_safe_str``.
    A key source's codec error names the byte it could not decode; the wrapped text must not.

    Mutation: ``raise _StoreOpenRefused(str(exc))`` in ``_open_store_or_refuse`` turns this red."""
    import asyncio

    from messagefoundry.__main__ import _open_store_or_refuse, _StoreOpenRefused
    from messagefoundry.store.keyprovider import KeyProviderError

    key_byte = b"\xe9"

    async def opening() -> None:
        try:
            key_byte.decode("ascii")
        except UnicodeDecodeError as exc:
            raise KeyProviderError(exc) from exc

    with pytest.raises(_StoreOpenRefused) as caught:
        asyncio.run(_open_store_or_refuse(opening()))  # type: ignore[arg-type]
    assert "xe9" not in str(caught.value).lower()
    assert isinstance(caught.value.__cause__, KeyProviderError)


@pytest.mark.parametrize("command", _COMMANDS)
def test_no_command_prints_a_key_byte_from_its_open(
    command: str,
    shell: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Review R2-7 and its round-3 follow-up: a key source's codec error at the open is "could not
    start", exit 2, and no command prints the byte it quotes. ``store withdraw-transit-bound`` and
    ``admin-reset-totp`` classify their open refusals by hand, so each is driven here too.

    Mutation: print ``str(exc)`` in any of their key arms, or in ``_open_store_or_refuse``."""
    from messagefoundry.store import base
    from messagefoundry.store.keyprovider import KeyProviderError

    async def refusing(*_args: object, **_kwargs: object) -> object:
        try:
            b"\xe9".decode("ascii")
        except UnicodeDecodeError as exc:
            raise KeyProviderError(exc) from exc
        raise AssertionError("unreachable")

    monkeypatch.setattr(base, "open_store", refusing)
    code = main(_argv(command, shell, server=_REMOTE, enforcement="enforce"))
    captured = capsys.readouterr()
    assert code == 2, (captured.out, captured.err)
    assert "xe9" not in (captured.out + captured.err).lower(), (captured.out, captured.err)
