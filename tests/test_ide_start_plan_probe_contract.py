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
_WIZARD = _MODEL.with_name("connectionWizardModel.ts")


def _code_view(text: str) -> str:
    """TypeScript with its comments blanked and its whitespace collapsed, for the source pins."""
    return " ".join(blank_js_comments(text).split())


def _ts_string_const(name: str) -> str:
    """The value of ``export const <name> = "...";`` in the IDE's control model."""
    m = re.search(rf'export const {name} = "([^"]+)";', _MODEL.read_text(encoding="utf-8"))
    assert m, f"{name} is not a plain string constant in {_MODEL.name}"
    return m.group(1)


def _no_terminal(monkeypatch: pytest.MonkeyPatch) -> None:
    """The IDE's condition, set explicitly: under ``pytest -s`` stdin would otherwise be a console."""
    monkeypatch.setattr(sys, "stdin", types.SimpleNamespace(isatty=lambda: False))


def _probe_argv() -> list[str]:
    """The argv ``buildAdminProbeInvocation`` builds, after ``python -m messagefoundry``."""
    return [
        "provision-admin",
        f"--username={_ts_string_const('PROBE_USERNAME')}",
        f"--email={_ts_string_const('PROBE_EMAIL')}",
        "--json",
    ]


def test_the_probe_argv_here_is_the_one_the_ide_builds() -> None:
    """If the TypeScript stops building this argv, the three tests below stop describing the IDE.

    The probe gets ``--service-config`` only when ``connectionServiceConfig`` gives it a value, which
    it does not with ``messagefoundry.serviceConfig`` at its default; this file's probe runs there,
    where ``serviceConfigFlag`` (an alias of ``connectionWizardModel.ts``'s ``serviceConfigArgs``)
    is handed undefined and adds nothing. Comments are blanked first in both files, so a comment
    quoting the code cannot satisfy a pin (a string literal still could), and the pin ends at the
    array's close, so an element added after the flag reds it. The array is handed to ``cliArgv``
    (BACKLOG #5409), so its body is pinned too: the interpreter options, then ``-m messagefoundry``,
    then this array, and nothing after it.
    """
    raw = _MODEL.read_text(encoding="utf-8")
    src = _code_view(raw)
    # Control: the JSDoc right above the pinned array is in the file and is blanked from the code.
    assert "Each value is bound with" in raw
    assert "Each value is bound with" not in src
    assert re.search(
        re.escape(
            'const args = cliArgv("messagefoundry", [ "provision-admin", '
            "`--username=${opts.username}`, `--email=${opts.email.trim()}`, "
            "...serviceConfigFlag(opts.serviceConfig)"
        )
        + r",? \]\);",
        src,
    )
    assert (
        "function cliArgv(module: string, args: readonly string[]): string[] { "
        'return [...INTERPRETER_OPTIONS, "-m", module, ...args]; }' in src
    )
    # serviceConfigFlag is an alias of connectionWizardModel's serviceConfigArgs, so follow it there:
    # the alias and its import here, and the body there, where undefined (this probe) adds nothing.
    # Every other mention of either name here must be a call: a second declaration, a parameter, an
    # `as` rename or a local serviceConfigArgs would each add a mention that is not one.
    assert re.search(
        r'import \{[^}]*\bserviceConfigArgs\b(?! as\b)[^}]*\} from "\./connectionWizardModel";',
        src,
    )
    assert "const serviceConfigFlag = serviceConfigArgs;" in src
    assert len(re.findall(r"\bserviceConfigArgs\b", src)) == 2, "only the import and the alias"
    assert len(re.findall(r"\bserviceConfigFlag\b(?!\()", src)) == 1, "only the alias declares it"
    wizard_raw = _WIZARD.read_text(encoding="utf-8")
    wizard = _code_view(wizard_raw)
    # Control: the JSDoc right above serviceConfigArgs is in the file and is blanked from the code.
    assert "so a value that starts with" in wizard_raw
    assert "so a value that starts with" not in wizard
    assert (
        "export function serviceConfigArgs(serviceConfig: string | undefined): string[] { "
        "return serviceConfig === undefined ? [] :" in wizard
    )
    assert "username: PROBE_USERNAME, email: PROBE_EMAIL" in src
    assert '[...inv.args, "--json"]' in src


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
