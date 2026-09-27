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
the probe the IDE runs -- the same argv, no ``--db``, no terminal -- and checks each answer carries the
fragment the IDE looks for, in the ``--json`` error object on stdout, the only place the IDE reads
an answer from. Both arms set the IDE's condition, stdin not a terminal, explicitly, so the result
does not depend on how pytest was started.
"""

from __future__ import annotations

import json
import re
import sys
import types
from pathlib import Path

import pytest

from messagefoundry.__main__ import main
from tests.test_provision_first_administrator import _PASSWORD, _key_in_this_shell, _tty

_MODEL = Path(__file__).resolve().parents[1] / "ide" / "src" / "engineControlModel.ts"


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
    return ["provision-admin", f"--username={_ts_string_const('PROBE_USERNAME')}", "--json"]


def test_the_probe_argv_here_is_the_one_the_ide_builds() -> None:
    """If the TypeScript stops building this argv, the two tests below stop describing the IDE."""
    src = _MODEL.read_text(encoding="utf-8")
    assert '"provision-admin", `--username=${opts.username}`' in src
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
        assert main(["provision-admin", "--username", "site-admin"]) == 0
    capsys.readouterr()

    _no_terminal(monkeypatch)
    assert main(_probe_argv()) == 1
    error = json.loads(capsys.readouterr().out)["error"]
    assert _ts_string_const("ADMIN_EXISTS_REFUSAL") in error
    assert _ts_string_const("NO_TERMINAL_REFUSAL") not in error
