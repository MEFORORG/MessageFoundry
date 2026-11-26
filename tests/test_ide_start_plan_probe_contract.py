# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The IDE's Start plan reads ``provision-admin``'s words, so pin them from both sides (BACKLOG #1136).

ADR 0183 Amendment A, Wave 5. The IDE starts a local engine only after asking ``provision-admin``,
run with no terminal, whether the store already has an enabled Administrator. It tells the two
answers apart by two fragments of the engine's refusal text, declared in
``ide/src/engineControlModel.ts``. The IDE's mocha suite checks its classifier against a COPY of that
text, so a rewording here would leave the mocha suite green while the IDE misread the engine: every
Start would report a refusal, or worse, provision over a store that needs nothing.

This file closes that gap. It reads the two fragments out of the TypeScript. The probe argv it runs
is ``probeDefault`` in ``ide/src/test/fixtures/provision-admin-argv.json``, the probe with
``messagefoundry.serviceConfig`` at its default: no ``--db``, no ``--service-config``. It hands that
list, minus the interpreter options and ``-m messagefoundry``, to the engine's ``main`` in-process,
in a temporary working directory, with no terminal. One arm has no store there at all; the others
seed one first. Each checks the answer carries the fragment the IDE looks for, in the ``--json``
error object on stdout, the only place the IDE reads an answer from. Every arm sets the IDE's
condition, stdin not a terminal, explicitly, so the result does not depend on how pytest was
started. Whether ``probeDefault`` is the argv the IDE builds is checked from two sides, neither
whole on its own: the mocha suite ``ide/src/test/suite/provision-admin-argv.test.ts`` pins the
builder's output against it, and the tests below compare it with the argv built from the
TypeScript constants and pin how the builder's source is written.
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
from tests.test_ide_provision_admin_argv import FIXTURE as ARGV_FIXTURE
from tests.test_ide_provision_admin_argv import _cli_args
from tests.test_provision_first_administrator import _PASSWORD, _key_in_this_shell, _tty

_MODEL = Path(__file__).resolve().parents[1] / "ide" / "src" / "engineControlModel.ts"
_WIZARD = _MODEL.with_name("connectionWizardModel.ts")


def _code_view(text: str) -> str:
    """TypeScript with its comments blanked and its whitespace collapsed, for the source pins."""
    return " ".join(blank_js_comments(text).split())


# A declaration of ``name`` in the code view: a function, const, let or var of that name.
_DECLARES = r"\b(?:function|const|let|var)\s+{name}\b"


def _ts_string_const(name: str, text: str | None = None) -> str:
    """The value of ``export const <name> = "...";`` in the IDE's control model (or ``text``), with
    comments blanked so a comment quoting the constant cannot supply it. Whitespace is NOT
    collapsed here, unlike ``_code_view``: the value is read byte for byte, so a doubled space or a
    tab inside the literal changes it."""
    raw = _MODEL.read_text(encoding="utf-8") if text is None else text
    code = blank_js_comments(raw)
    m = re.search(rf'export const {name} = "([^"]+)";', code)
    assert m, f"{name} is not a plain string constant in {_MODEL.name}"
    return m.group(1)


def _no_terminal(monkeypatch: pytest.MonkeyPatch) -> None:
    """The IDE's condition, set explicitly: under ``pytest -s`` stdin would otherwise be a console."""
    monkeypatch.setattr(sys, "stdin", types.SimpleNamespace(isatty=lambda: False))


def _ts_string_list(name: str, text: str | None = None) -> list[str]:
    """The elements of ``export const <name>: readonly string[] = [...];`` in the IDE's control model
    (or ``text``), comments blanked. The body must be double-quoted string literals with no
    backslash, comma-separated, and nothing else: a single-quoted or template literal, a spread, an
    identifier or any other element fails the assertion here instead of being skipped."""
    raw = _MODEL.read_text(encoding="utf-8") if text is None else text
    m = re.search(
        rf"export const {name}: readonly string\[\] = \[([^\]]*)\];", blank_js_comments(raw)
    )
    assert m, f"{name} is not a plain string-array constant in {_MODEL.name}"
    body = m.group(1)
    literal = r'"[^"\\\n]*"'
    assert re.fullmatch(rf"\s*(?:{literal}\s*(?:,\s*{literal}\s*)*,?\s*)?", body), (
        f"{name} holds an element that is not a double-quoted string literal: [{body}]"
    )
    return re.findall(r'"([^"]*)"', body)


def _expected_probe_argv(text: str | None = None) -> list[str]:
    """The whole default probe argv, from the TypeScript constants: the interpreter options,
    ``-m messagefoundry``, then the probe account and ``--json``. The email is trimmed, as the
    builder trims it."""
    return [
        *_ts_string_list("INTERPRETER_OPTIONS", text),
        "-m",
        "messagefoundry",
        "provision-admin",
        f"--username={_ts_string_const('PROBE_USERNAME', text)}",
        f"--email={_ts_string_const('PROBE_EMAIL', text).strip()}",
        "--json",
    ]


def _probe_argv() -> list[str]:
    """The fixture's ``probeDefault``, the argv ``buildAdminProbeInvocation`` builds with
    ``messagefoundry.serviceConfig`` at its default, after ``python -m messagefoundry``. The mocha
    suite ``ide/src/test/suite/provision-admin-argv.test.ts`` pins the builder's whole output against
    the same entry."""
    return _cli_args(ARGV_FIXTURE["probeDefault"])


def test_the_shared_fixture_default_probe_is_the_argv_the_source_pin_reads() -> None:
    """The fixture's ``probeDefault`` equals, whole, the argv built from the TypeScript constants.

    What reds this test: an ``INTERPRETER_OPTIONS`` element changed, added, removed or reordered, or
    a changed ``PROBE_USERNAME`` or ``PROBE_EMAIL``, unless the fixture moves with it; and an
    ``INTERPRETER_OPTIONS`` element that is not a double-quoted string literal, which
    ``_ts_string_list`` refuses. The gap: the source pin below checks how ``cliArgv`` and the
    probe's ``provision-admin`` array are written, and that ``--json`` is appended, but not the
    value ``buildProvisionInvocation`` returns, so an element added to that return passes every
    test in this file. Only the mocha pin in ``provision-admin-argv.test.ts``, which compares the
    builder's output with this entry, catches it, and that pin runs in the ``ide build`` job, which
    was neither a required context nor in the ``CI gate`` roll-up when this was written
    (branch protection and ``ci.yml`` read 2026-11-26)."""
    raw = _MODEL.read_text(encoding="utf-8")
    assert ARGV_FIXTURE["probeDefault"] == _expected_probe_argv()
    # Negative control: a moved TypeScript constant reds the comparison, so the expected argv is
    # read from the TypeScript and not from the fixture.
    for decl, moved in (
        ('export const PROBE_USERNAME = "probe";', 'export const PROBE_USERNAME = "probe2";'),
        ('"-P", "-X", "disable-remote-debug"]', '"-I", "-P", "-X", "disable-remote-debug"]'),
    ):
        assert raw.count(decl) == 1, decl
        assert ARGV_FIXTURE["probeDefault"] != _expected_probe_argv(raw.replace(decl, moved)), moved
    # The fixture's probe with serviceConfig set is probeDefault with only the flag added, before
    # --json, so the two entries cannot drift apart.
    with_flag = ARGV_FIXTURE["probe"]
    flag = [a for a in with_flag if a.startswith("--service-config=")]
    assert len(flag) == 1
    assert [a for a in with_flag if a not in flag] == ARGV_FIXTURE["probeDefault"]
    assert with_flag[-2:] == [*flag, "--json"]


@pytest.mark.parametrize(
    "moved",
    [
        '\'-I\', "-P", "-X", "disable-remote-debug"]',
        '...EXTRA_OPTIONS, "-P", "-X", "disable-remote-debug"]',
        '"-P", "-X", "disable-remote-debug", `-I`]',
        '"-P", "-X", EXTRA_OPTION, "disable-remote-debug"]',
    ],
    ids=["single-quoted", "spread", "template", "identifier"],
)
def test_an_interpreter_option_the_list_reader_cannot_read_reds_it(moved: str) -> None:
    """Negative control for ``_ts_string_list``: an element it cannot read as a double-quoted string
    literal fails the read instead of being skipped, so the comparison above cannot pass on a list
    that dropped it."""
    raw = _MODEL.read_text(encoding="utf-8")
    decl = '"-P", "-X", "disable-remote-debug"]'
    assert raw.count(decl) == 1, decl
    # Control: the unmutated list reads, as the three options.
    assert _ts_string_list("INTERPRETER_OPTIONS", raw) == ["-P", "-X", "disable-remote-debug"]
    with pytest.raises(AssertionError, match="not a double-quoted string literal"):
        _ts_string_list("INTERPRETER_OPTIONS", raw.replace(decl, moved))


def test_the_probe_argv_here_is_the_one_the_ide_builds() -> None:
    """If the TypeScript stops building this argv, the tests below that run the probe stop describing the IDE.

    The probe forwards the ``serviceConfig`` it is handed, which the mocha suite pins as undefined
    with ``messagefoundry.serviceConfig`` at its default; this file's probe runs there, where
    ``serviceConfigFlag`` (an alias of ``connectionWizardModel.ts``'s ``serviceConfigArgs``) is
    handed undefined and adds nothing. Comments are blanked first in both files, so a comment
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
    assert len(re.findall(_DECLARES.format(name="cliArgv"), src)) == 1, "a second cliArgv"
    # serviceConfigFlag is an alias of connectionWizardModel's serviceConfigArgs, so follow it there:
    # the alias and its import here, and the body there, where undefined (this probe) adds nothing.
    # serviceConfigArgs appears only in the import, unrenamed in either direction, and the alias;
    # serviceConfigFlag is declared once, by the alias, and is otherwise only called. These catch at
    # least a const or function shadow, a parameter of that name and a local serviceConfigArgs.
    assert re.search(
        r"import \{[^}]*(?<!\bas )\bserviceConfigArgs\b(?! as\b)[^}]*\} "
        r'from "\./connectionWizardModel";',
        src,
    )
    assert "const serviceConfigFlag = serviceConfigArgs;" in src
    assert len(re.findall(r"\bserviceConfigArgs\b", src)) == 2, "only the import and the alias"
    assert len(re.findall(_DECLARES.format(name="serviceConfigFlag"), src)) == 1, "a second one"
    assert len(re.findall(r"\bserviceConfigFlag\b(?!\()", src)) == 1, "a non-call mention"
    wizard_raw = _WIZARD.read_text(encoding="utf-8")
    wizard = _code_view(wizard_raw)
    # Control: the wizard has comments, and comment blanking removed them from the code view.
    assert "/**" in wizard_raw
    assert "/**" not in wizard
    assert (
        "export function serviceConfigArgs(serviceConfig: string | undefined): string[] { "
        "return serviceConfig === undefined ? [] :" in wizard
    )
    assert "serviceConfig: opts.serviceConfig, username: PROBE_USERNAME, email: PROBE_EMAIL" in src
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
