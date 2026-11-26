# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The IDE's Start plan reads ``provision-admin``'s words, so pin them from both sides (BACKLOG #1136).

ADR 0183 Amendment A, Wave 5. The IDE starts a local engine only after asking ``provision-admin``,
run with no terminal, whether the store already has an enabled Administrator. It tells the two
answers apart by two fragments of the engine's refusal text, declared in
``ide/src/engineControlModel.ts``. The IDE's mocha suite checks its classifier against a COPY of that
text, so a rewording here would leave the mocha suite green while the IDE misread the engine: every
Start would report a refusal, or worse, provision over a store that needs nothing.

This file closes that gap. It reads the fragments and the probe username out of the TypeScript, runs
the probe the IDE runs with ``messagefoundry.serviceConfig`` at its default -- the same argv, no
``--db``, no ``--service-config``, no terminal -- and checks each answer carries the
fragment the IDE looks for, in the ``--json`` error object on stdout, the only place the IDE reads
an answer from. Both arms set the IDE's condition, stdin not a terminal, explicitly, so the result
does not depend on how pytest was started.
"""

from __future__ import annotations

import asyncio
import json
import re
import sys
import types
from pathlib import Path

import pytest

from messagefoundry.__main__ import main
from messagefoundry.auth.identity import AuthProvider
from messagefoundry.auth.permissions import Role
from messagefoundry.auth.service import AuthService
from messagefoundry.config.settings import AuthSettings
from messagefoundry.store.crypto import make_cipher
from messagefoundry.store.store import MessageStore
from scripts.security.js_lexer import blank_js_comments
from tests.test_provision_first_administrator import _PASSWORD, _key_in_this_shell, _tty

_MODEL = Path(__file__).resolve().parents[1] / "ide" / "src" / "engineControlModel.ts"
# The probe argv ``buildAdminProbeInvocation`` builds, held as data: the mocha suite
# ide/src/test/suite/provision-admin-argv.test.ts pins the builder's whole output against
# ``probeDefault``, and this file runs that same list, so the two sides cannot pin different argv.
_ARGV_FIXTURE = _MODEL.parent / "test" / "fixtures" / "provision-admin-argv.json"
# The IDE runs `python -P -X disable-remote-debug -m messagefoundry <command> ...`.
_PREFIX = ["-P", "-X", "disable-remote-debug", "-m", "messagefoundry"]


def _ts_string_const(name: str, text: str | None = None) -> str:
    """The value of ``export const <name> = "...";`` in the IDE's control model (or ``text``), with
    comments blanked so a comment quoting the constant cannot supply it. Whitespace is NOT
    collapsed: the value is read byte for byte, so a doubled space or a tab inside the literal
    changes it."""
    raw = _MODEL.read_text(encoding="utf-8") if text is None else text
    code = blank_js_comments(raw)
    m = re.search(rf'export const {name} = "([^"]+)";', code)
    assert m, f"{name} is not a plain string constant in {_MODEL.name}"
    return m.group(1)


def _no_terminal(monkeypatch: pytest.MonkeyPatch) -> None:
    """The IDE's condition, set explicitly: under ``pytest -s`` stdin would otherwise be a console."""
    monkeypatch.setattr(sys, "stdin", types.SimpleNamespace(isatty=lambda: False))


def _fixture() -> dict[str, list[str]]:
    data: dict[str, list[str]] = json.loads(_ARGV_FIXTURE.read_text(encoding="utf-8"))
    return data


def _probe_argv() -> list[str]:
    """The fixture's ``probeDefault``, the argv ``buildAdminProbeInvocation`` builds with
    ``messagefoundry.serviceConfig`` at its default, after ``python -m messagefoundry``."""
    argv = _fixture()["probeDefault"]
    assert argv[: len(_PREFIX)] == _PREFIX, argv
    return argv[len(_PREFIX) :]


def test_the_probe_argv_here_is_the_one_the_ide_builds() -> None:
    """The argv the tests below run is the fixture the mocha suite pins ``buildAdminProbeInvocation``
    against, so a change to the IDE's default probe argv reds one side or the other.

    The mocha pin compares the builder's whole output, element for element, with ``probeDefault``.
    Here the fixture's account must be the one ``engineControlModel.ts`` declares, read byte for
    byte, and the fixture must carry no ``--db`` and no ``--service-config``, the default the
    tests below describe.
    """
    assert _probe_argv() == [
        "provision-admin",
        f"--username={_ts_string_const('PROBE_USERNAME')}",
        f"--email={_ts_string_const('PROBE_EMAIL')}",
        "--json",
    ]
    # Control: the fixture's probe with serviceConfig set is this argv with only the flag added,
    # before --json, so the two entries cannot drift apart either.
    fixture = _fixture()
    with_flag = fixture["probe"]
    flag = [a for a in with_flag if a.startswith("--service-config=")]
    assert len(flag) == 1
    assert [a for a in with_flag if a not in flag] == fixture["probeDefault"]
    assert with_flag[-2:] == [*flag, "--json"]


def test_a_store_with_no_administrator_answers_with_the_no_terminal_fragment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The ``needsAdmin`` answer, and the probe leaves no store behind for asking."""
    monkeypatch.chdir(tmp_path)
    _key_in_this_shell(monkeypatch)
    _no_terminal(monkeypatch)
    assert main(_probe_argv()) == 1
    error = json.loads(capsys.readouterr().out)["error"]
    assert _ts_string_const("NO_TERMINAL_REFUSAL") in error
    assert _ts_string_const("ADMIN_EXISTS_REFUSAL") not in error
    assert list(tmp_path.glob("*.db")) == [], "the probe must not create a store"


def test_a_store_with_an_administrator_answers_with_the_exists_fragment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The ``adminExists`` answer, which the IDE reads as go-ahead, given with no terminal attached."""
    monkeypatch.chdir(tmp_path)
    _key_in_this_shell(monkeypatch)
    with monkeypatch.context() as m:
        _tty(m, _PASSWORD, _PASSWORD)
        assert (
            main(["provision-admin", "--username", "site-admin", "--email", "a@example.org"]) == 0
        )
    capsys.readouterr()

    _no_terminal(monkeypatch)
    assert main(_probe_argv()) == 1
    error = json.loads(capsys.readouterr().out)["error"]
    assert _ts_string_const("ADMIN_EXISTS_REFUSAL") in error
    assert _ts_string_const("NO_TERMINAL_REFUSAL") not in error


def test_a_store_run_only_by_directory_administrators_answers_with_the_no_terminal_fragment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Vault BACKLOG #2711 step 1 (ADR 0183 Amendment E): a directory Administrator no longer
    blocks ``provision-admin``, so the probe gets past the Administrator check and asks for a
    terminal. The IDE then reads the store as ``needsAdmin``. Before step 1 this answered with the
    exists fragment."""
    monkeypatch.chdir(tmp_path)
    key = _key_in_this_shell(monkeypatch)

    async def seed() -> None:
        cipher = make_cipher(key)
        store = await MessageStore.open(
            tmp_path / "messagefoundry.db", cipher=cipher, audit_mac_key=cipher.audit_mac_key()
        )
        try:
            await store.create_user(
                user_id="dir-a",
                username="dir-a",
                auth_provider=AuthProvider.AD.value,
                password_generated=False,
                audits=(),
            )
            await AuthService(store, AuthSettings()).initialize()
            await store.set_user_roles(
                "dir-a", [Role.ADMINISTRATOR.value], assigned_by="test", audits=()
            )
        finally:
            await store.close()

    asyncio.run(seed())
    _no_terminal(monkeypatch)
    assert main(_probe_argv()) == 1
    error = json.loads(capsys.readouterr().out)["error"]
    assert _ts_string_const("NO_TERMINAL_REFUSAL") in error
    assert _ts_string_const("ADMIN_EXISTS_REFUSAL") not in error


def test_a_whitespace_change_inside_the_fragment_is_read_and_reds_the_check(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Negative control for the constant reader: a doubled space inside ``NO_TERMINAL_REFUSAL``
    changes what the IDE matches on, so the reader must return the changed value and the
    fragment check above must fail against it. A reader that collapsed whitespace would hand back
    the original value and pass wrongly."""
    raw = _MODEL.read_text(encoding="utf-8")
    original = _ts_string_const("NO_TERMINAL_REFUSAL")
    assert " " in original
    mutated_value = original.replace(" ", "  ", 1)
    decl = f'export const NO_TERMINAL_REFUSAL = "{original}";'
    assert raw.count(decl) == 1
    mutated = raw.replace(decl, f'export const NO_TERMINAL_REFUSAL = "{mutated_value}";')
    assert _ts_string_const("NO_TERMINAL_REFUSAL", mutated) == mutated_value

    monkeypatch.chdir(tmp_path)
    _key_in_this_shell(monkeypatch)
    _no_terminal(monkeypatch)
    assert main(_probe_argv()) == 1
    error = json.loads(capsys.readouterr().out)["error"]
    # The real fragment is in the answer and the mutated one is not, so the check would red.
    assert original in error
    assert mutated_value not in error
