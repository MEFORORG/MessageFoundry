# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Every CLI subcommand has exactly one tier in ``messagefoundry.cli_surface`` (BACKLOG #1192).

The test builds the REAL parser with ``messagefoundry.__main__._build_parser``, the builder ADR 0201
slice 1 took out of ``main()``. Building runs nothing: no hook, no stream change, no dispatch.
Two tests below hold that builder to what ``main()`` really parses with, which is the guarantee the
earlier workaround got by catching the parser at ``main()``'s own ``parse_args`` call.

All the table's rules live in one function, :func:`_table_problems`. The real test asserts it finds
nothing. Each planted test breaks the real data one way and asserts that the same function names the
break, so a rule that stopped checking goes red instead of passing everything.
"""

from __future__ import annotations

import argparse
import ast
import logging
import subprocess
import sys
import threading
from collections.abc import Mapping
from pathlib import Path

import pytest

import messagefoundry.__main__ as cli_module
import messagefoundry.cli_surface as cli_surface
from messagefoundry.cli_common import Dispatch
from messagefoundry.cli_surface import Tier

# The toolkit per the owner ruling of 2026-09-28: eight rows by name, and the three `lens` children
# and the `import` group by rule. Every other row is production, but the owner did not rule on each
# of those one by one; the module docstring of messagefoundry/cli_surface.py says which is which.
# Pinned here in full, so a later edit that moves a command between tiers has to change this test
# too, in plain sight of review.
_RULED_TOOLKIT = frozenset(
    {
        "impact",
        "generate",
        "lens",
        "lens parse",
        "lens rewrite",
        "lens schema",
        "import",
        "import corepoint",
        "adr-analyze",
        "hl7schema",
        "hl7structures",
        "init",
    }
)

# The item's title requires `dryrun` to stay on the operator's box, and the deployment docs lean on
# `check`'s security lint. The ruling pin above already implies both are production; this names them
# so a failure says why.
_MUST_BE_PRODUCTION = ("dryrun", "check")


def _command_paths(parser: argparse.ArgumentParser, prefix: str = "") -> dict[str, set[str]]:
    """Map every subcommand's full path to the full paths of its direct children."""
    paths: dict[str, set[str]] = {}
    for action in parser._actions:
        if not isinstance(action, argparse._SubParsersAction):
            continue
        for name, child in action.choices.items():
            path = f"{prefix} {name}".lstrip()
            nested = _command_paths(child, path)
            paths[path] = {p for p in nested if p.count(" ") == path.count(" ") + 1}
            paths.update(nested)
    return paths


def _table_problems(paths: Mapping[str, set[str]], tiers: Mapping[str, Tier]) -> list[str]:
    """Every way ``tiers`` disagrees with the parser's ``paths`` or with the owner ruling."""
    problems = [f"no tier: {p}" for p in sorted(set(paths) - set(tiers))]
    problems += [f"no such subcommand: {p}" for p in sorted(set(tiers) - set(paths))]
    for group, children in sorted(paths.items()):
        if not children or group not in tiers or not children <= set(tiers):
            continue
        # A production install must carry a group to reach any production child in it.
        want = "production" if any(tiers[c] == "production" for c in children) else "toolkit"
        if tiers[group] != want:
            problems.append(f"group {group} should be {want}")
    problems += [
        f"{c} must be production" for c in _MUST_BE_PRODUCTION if tiers.get(c) != "production"
    ]
    toolkit = {p for p, tier in tiers.items() if tier == "toolkit"}
    if toolkit != _RULED_TOOLKIT:
        problems.append(f"toolkit differs from the ruling by {sorted(toolkit ^ _RULED_TOOLKIT)}")
    return problems


@pytest.fixture(scope="module")
def real_paths() -> dict[str, set[str]]:
    parser, _dispatch = cli_module._build_parser()
    return _command_paths(parser)


def test_the_table_matches_the_parser_and_the_ruling(real_paths: dict[str, set[str]]) -> None:
    problems = _table_problems(real_paths, cli_surface.CLI_TIERS)
    assert not problems, (
        "CLI_TIERS in messagefoundry/cli_surface.py disagrees with the parser or the owner ruling "
        f"(BACKLOG #1192): {problems}"
    )


def test_dispatch_keys_are_the_top_level_subcommands(real_paths: dict[str, set[str]]) -> None:
    assert set(cli_module._DISPATCH) == {p for p in real_paths if " " not in p}


# --- The builder is what main() parses with, and building changes nothing. ---------------------


def test_the_builder_returns_the_dispatch_map_main_uses() -> None:
    """The very object, not a copy, so a test that patches an entry in ``_DISPATCH`` still reaches
    ``main()``. At least ``tests/test_cli.py`` relies on that."""
    _parser, dispatch = cli_module._build_parser()
    assert dispatch is cli_module._DISPATCH


def test_main_parses_with_the_builder(monkeypatch: pytest.MonkeyPatch) -> None:
    """``main()`` must call ``_build_parser`` rather than build a parser of its own. Otherwise the
    table test above would read one surface while the engine exposes another. The planted builder
    registers one command nothing else has, and ``main()`` must parse and dispatch it."""
    ran: list[str] = []

    def handler(args: argparse.Namespace) -> int:
        ran.append(args.command)
        return 7

    def planted() -> tuple[argparse.ArgumentParser, Dispatch]:
        parser = argparse.ArgumentParser(prog="planted")
        parser.add_subparsers(dest="command", required=True).add_parser("only-in-the-plant")
        return parser, {"only-in-the-plant": handler}

    # main() installs both process-wide exception hooks. Setting each to its current value makes
    # the context put it back afterwards, so nothing leaks into later tests.
    monkeypatch.setattr(sys, "excepthook", sys.excepthook)
    monkeypatch.setattr(threading, "excepthook", threading.excepthook)
    monkeypatch.setattr(cli_module, "_build_parser", planted)
    assert cli_module.main(["only-in-the-plant"]) == 7
    assert ran == ["only-in-the-plant"]


def test_building_the_parser_installs_nothing() -> None:
    """Reading the surface must not change the process: the hooks and the root log handlers are
    what ``main()`` sets, and the builder must leave all of them alone."""
    before = (sys.excepthook, threading.excepthook, list(logging.getLogger().handlers))
    cli_module._build_parser()
    assert (sys.excepthook, threading.excepthook, list(logging.getLogger().handlers)) == before


# --- Planted breaks. Each must be named by the same function the real test uses. ----------------


def test_the_walk_descends_into_nested_subcommands() -> None:
    parser = argparse.ArgumentParser(prog="synthetic")
    sub = parser.add_subparsers(dest="command")
    sub.add_parser("serve")
    sub.add_parser("cert").add_subparsers(dest="cert_command").add_parser("inventory")
    assert _command_paths(parser) == {
        "serve": set(),
        "cert": {"cert inventory"},
        "cert inventory": set(),
    }


def test_a_new_subcommand_without_a_tier_is_named(real_paths: dict[str, set[str]]) -> None:
    paths = {**real_paths, "brand-new": set()}
    assert _table_problems(paths, cli_surface.CLI_TIERS) == ["no tier: brand-new"]


def test_an_orphaned_tier_is_named(real_paths: dict[str, set[str]]) -> None:
    tiers: dict[str, Tier] = {**cli_surface.CLI_TIERS, "retired-command": "production"}
    assert _table_problems(real_paths, tiers) == ["no such subcommand: retired-command"]


def test_dryrun_moved_to_the_toolkit_is_named(real_paths: dict[str, set[str]]) -> None:
    tiers: dict[str, Tier] = {**cli_surface.CLI_TIERS, "dryrun": "toolkit"}
    assert _table_problems(real_paths, tiers) == [
        "dryrun must be production",
        "toolkit differs from the ruling by ['dryrun']",
    ]


def test_check_moved_to_the_toolkit_is_named(real_paths: dict[str, set[str]]) -> None:
    tiers: dict[str, Tier] = {**cli_surface.CLI_TIERS, "check": "toolkit"}
    assert _table_problems(real_paths, tiers) == [
        "check must be production",
        "toolkit differs from the ruling by ['check']",
    ]


def test_a_toolkit_command_moved_to_production_is_named(real_paths: dict[str, set[str]]) -> None:
    tiers: dict[str, Tier] = {**cli_surface.CLI_TIERS, "generate": "production"}
    assert _table_problems(real_paths, tiers) == ["toolkit differs from the ruling by ['generate']"]


def test_a_group_with_the_wrong_tier_is_named(real_paths: dict[str, set[str]]) -> None:
    tiers: dict[str, Tier] = {**cli_surface.CLI_TIERS, "cert": "toolkit"}
    assert _table_problems(real_paths, tiers) == [
        "group cert should be production",
        "toolkit differs from the ruling by ['cert']",
    ]


def test_an_all_toolkit_group_marked_production_is_named(real_paths: dict[str, set[str]]) -> None:
    tiers: dict[str, Tier] = {**cli_surface.CLI_TIERS, "lens": "production"}
    assert _table_problems(real_paths, tiers) == [
        "group lens should be toolkit",
        "toolkit differs from the ruling by ['lens']",
    ]


def test_a_mixed_group_must_be_production(real_paths: dict[str, set[str]]) -> None:
    tiers: dict[str, Tier] = {**cli_surface.CLI_TIERS, "lens parse": "production"}
    assert _table_problems(real_paths, tiers) == [
        "group lens should be production",
        "toolkit differs from the ruling by ['lens parse']",
    ]


# --- The module stays cheap to import -----------------------------------------------------------

_ALLOWED_IMPORTS = frozenset({"__future__", "collections.abc", "types", "typing"})


def _imported_modules(source: str) -> set[str]:
    found: set[str] = set()
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            found.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            found.add("." * node.level + (node.module or ""))
        elif (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "__import__"
        ):
            # `importlib.import_module` needs `import importlib`, which the branches above see.
            found.add("__import__")
    return found


def test_cli_surface_imports_only_standard_library_typing_helpers() -> None:
    source = Path(cli_surface.__file__).read_text(encoding="utf-8")
    assert _imported_modules(source) <= _ALLOWED_IMPORTS


def _engine_modules_loaded_by(module: str) -> set[str]:
    """The ``messagefoundry`` modules a fresh interpreter holds after importing ``module``.

    A fresh process, because the source scan above cannot see what ``messagefoundry/__init__.py``
    pulls in, and that runs on every import of the table too.
    """
    probe = (
        f"import sys, {module}\n"
        "print('\\n'.join(m for m in sys.modules if m.split('.')[0] == 'messagefoundry'))\n"
    )
    out = subprocess.run(
        [sys.executable, "-c", probe], capture_output=True, text=True, check=True, timeout=120
    ).stdout
    return set(out.split())


def test_importing_cli_surface_loads_no_other_engine_module() -> None:
    assert _engine_modules_loaded_by("messagefoundry.cli_surface") == {
        "messagefoundry",
        "messagefoundry.cli_surface",
    }


def test_the_import_probe_sees_an_engine_import() -> None:
    assert "messagefoundry.config" in _engine_modules_loaded_by("messagefoundry.__main__")


def test_an_engine_import_in_cli_surface_is_named() -> None:
    planted = (
        "import argparse\n"
        "from messagefoundry.__main__ import main\n"
        "from . import pki\n"
        "import importlib\n"
        "cli = __import__('messagefoundry.__main__')\n"
    )
    assert _imported_modules(planted) - _ALLOWED_IMPORTS == {
        "argparse",
        "messagefoundry.__main__",
        ".",
        "importlib",
        "__import__",
    }
