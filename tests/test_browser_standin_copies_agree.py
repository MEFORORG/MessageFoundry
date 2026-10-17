# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The two copies of the in-process browser stand-in must stay one rule (vault BACKLOG #3316).

Both ``tests/conftest.py`` and the web console suite's ``conftest.py`` wrap
``httpx.ASGITransport`` so an in-process ``/ui`` write that names no provenance carries the
``Sec-Fetch-Site: same-origin`` a browser sends. There are two copies because the console suite is
separately versioned and does not inherit the engine's conftest. One run collects both suites, and
the two wrappers then stack, so a copy that drifted (another method set, another opt-out key) would
change what the other suite's refusal tests measure with nothing reporting it.

Read from source, not imported: two modules named ``conftest`` cannot both be imported here, and
the console suite's resolves its opt-out key through a sibling module of its own.
"""

from __future__ import annotations

import ast
from pathlib import Path

from tests._ast_sites import named_func

_REPO = Path(__file__).resolve().parents[1]
_ENGINE_CONFTEST = _REPO / "tests" / "conftest.py"
_CONSOLE_TESTS = _REPO / "packaging" / "messagefoundry-webconsole" / "tests"
_CONSOLE_CONFTEST = _CONSOLE_TESTS / "conftest.py"
_CONSOLE_CLIENTS = _CONSOLE_TESTS / "_ui_clients.py"

_FIXTURE = "_in_process_ui_clients_send_what_a_browser_sends"
_WRAPPER = "as_a_browser"


def _module(path: Path) -> ast.Module:
    return ast.parse(path.read_text(encoding="utf-8"), filename=str(path))


def _wrapper(path: Path) -> str:
    """The stand-in's inner wrapper, as an AST dump (comments and docstrings do not count)."""
    wrapper = named_func(named_func(_module(path), _FIXTURE), _WRAPPER)
    return ast.dump(wrapper, include_attributes=False)


def _constant(path: Path, name: str) -> object:
    """The literal value a module-level ``name = <literal>`` assigns in ``path``."""
    for node in _module(path).body:
        if (
            isinstance(node, ast.Assign)
            and len(node.targets) == 1
            and isinstance(node.targets[0], ast.Name)
            and node.targets[0].id == name
        ):
            value = node.value
            if (
                isinstance(value, ast.Call)
                and isinstance(value.func, ast.Name)
                and value.func.id == "frozenset"
            ):
                return frozenset(ast.literal_eval(value.args[0]))
            return ast.literal_eval(value)
    raise AssertionError(f"{path} assigns no module-level {name}")


def test_the_two_stand_in_wrappers_are_the_same_code() -> None:
    engine, console = _wrapper(_ENGINE_CONFTEST), _wrapper(_CONSOLE_CONFTEST)
    # positive control: the dump holds the rule, so an empty extraction cannot pass as agreement
    assert "sec-fetch-site" in engine and "_SAFE_METHODS" in engine, engine[:200]
    assert engine == console, (
        "tests/conftest.py and the console suite's conftest.py no longer wrap ASGITransport the "
        "same way; change both together"
    )


def test_the_two_copies_name_the_same_methods_and_opt_out_key() -> None:
    methods = _constant(_ENGINE_CONFTEST, "_SAFE_METHODS")
    assert methods == frozenset({"GET"}), methods
    assert methods == _constant(_CONSOLE_CONFTEST, "_SAFE_METHODS")
    key = _constant(_ENGINE_CONFTEST, "HEADERLESS_UI_REQUEST")
    assert isinstance(key, str) and key, key
    assert key == _constant(_CONSOLE_CLIENTS, "HEADERLESS_UI_REQUEST")
