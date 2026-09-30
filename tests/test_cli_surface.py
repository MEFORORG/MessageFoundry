# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Every CLI subcommand has exactly one tier in ``messagefoundry.cli_surface`` (BACKLOG #1192).

The test builds the two REAL parsers: the engine's, with ``messagefoundry.__main__._build_parser``,
the builder ADR 0201 slice 1 took out of ``main()``, and the toolkit's, with
``messagefoundry_toolkit.__main__._build_parser`` (slice 2). Building runs nothing: no hook, no
stream change, no dispatch. Two tests below hold the engine's builder to what ``main()`` really
parses with, which is the guarantee the earlier workaround got by catching the parser at
``main()``'s own ``parse_args`` call.

The table is checked against the UNION of the two parsers' rows. ADR 0201 AC-1 adds that the two
are disjoint and that the toolkit parser registers no production row. That rule holds in every
slice, so a slice can move some toolkit rows and not others without a hand-kept transition list.

All the table's rules live in one function, :func:`_table_problems`. The real test asserts it finds
nothing. Each planted test breaks the real data one way and asserts that the same function names the
break, so a rule that stopped checking goes red instead of passing everything.
"""

from __future__ import annotations

import argparse
import ast
import json
import logging
import subprocess
import sys
import threading
from collections.abc import Mapping
from pathlib import Path

import pytest

import messagefoundry.__main__ as cli_module
import messagefoundry.cli_common as cli_common
import messagefoundry.cli_surface as cli_surface
import messagefoundry_toolkit.__main__ as toolkit_cli
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


def _split_problems(
    engine: Mapping[str, set[str]], toolkit: Mapping[str, set[str]], tiers: Mapping[str, Tier]
) -> list[str]:
    """Every way the engine and toolkit parsers break ADR 0201 AC-1 against ``tiers``.

    The union is not checked here: :func:`_table_problems` checks it, over the merged paths."""
    problems = [f"on both commands: {p}" for p in sorted(set(engine) & set(toolkit))]
    problems += [
        f"production row on the toolkit command: {p}"
        for p in sorted(toolkit)
        if tiers.get(p) == "production"
    ]
    return problems


@pytest.fixture(scope="module")
def engine_paths() -> dict[str, set[str]]:
    parser, _dispatch = cli_module._build_parser()
    return _command_paths(parser)


@pytest.fixture(scope="module")
def toolkit_paths() -> dict[str, set[str]]:
    parser, _dispatch = toolkit_cli._build_parser()
    return _command_paths(parser)


@pytest.fixture(scope="module")
def real_paths(
    engine_paths: dict[str, set[str]], toolkit_paths: dict[str, set[str]]
) -> dict[str, set[str]]:
    return {**engine_paths, **toolkit_paths}


def test_the_table_matches_the_parsers_and_the_ruling(real_paths: dict[str, set[str]]) -> None:
    problems = _table_problems(real_paths, cli_surface.CLI_TIERS)
    assert not problems, (
        "CLI_TIERS in messagefoundry/cli_surface.py disagrees with the parsers or the owner ruling "
        f"(BACKLOG #1192): {problems}"
    )


def test_the_two_commands_split_the_rows_between_them(
    engine_paths: dict[str, set[str]], toolkit_paths: dict[str, set[str]]
) -> None:
    """ADR 0201 AC-1: disjoint, and no production row on the toolkit command. The union half is the
    test above, which reads the merged paths."""
    problems = _split_problems(engine_paths, toolkit_paths, cli_surface.CLI_TIERS)
    assert not problems, f"the engine and toolkit parsers break ADR 0201 AC-1: {problems}"
    # Control: slice 2 moved adr-analyze, so the toolkit parser is not empty and the split is real.
    assert "adr-analyze" in toolkit_paths and "adr-analyze" not in engine_paths


def test_dispatch_keys_are_the_top_level_subcommands(engine_paths: dict[str, set[str]]) -> None:
    assert set(cli_module._DISPATCH) == {p for p in engine_paths if " " not in p}


def test_toolkit_dispatch_keys_are_its_top_level_subcommands(
    toolkit_paths: dict[str, set[str]],
) -> None:
    assert set(toolkit_cli._DISPATCH) == {p for p in toolkit_paths if " " not in p}


def test_the_toolkit_builder_returns_the_dispatch_map_its_main_uses() -> None:
    _parser, dispatch = toolkit_cli._build_parser()
    assert dispatch is toolkit_cli._DISPATCH


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

    monkeypatch.setattr(cli_module, "_build_parser", planted)
    assert _run_engine(monkeypatch, ["only-in-the-plant"]) == 7
    assert ran == ["only-in-the-plant"]


def test_building_the_parser_installs_nothing(monkeypatch: pytest.MonkeyPatch) -> None:
    """Reading the surface must not change the process. The hooks, the stream hardening and the log
    sink are what ``main()`` sets, and the builder must call none of them.

    Recorders, not before-and-after state. Under pytest's capture the streams already use
    ``errors="replace"``, and an earlier ``main()`` call in the same worker has already installed
    the hooks, so a state comparison would stay green on exactly the regression it is for."""
    called: list[str] = []

    def recorder(name: str) -> object:
        return lambda *_a, **_kw: called.append(name)

    import messagefoundry.console_streams as console_streams
    import messagefoundry.last_resort as last_resort
    import messagefoundry.logging_setup as logging_setup

    for module, name in (
        (console_streams, "harden_console_streams"),
        (cli_module, "harden_console_streams"),
        (cli_common, "harden_console_streams"),
        (last_resort, "install_excepthook"),
        (last_resort, "install_thread_excepthook"),
        (logging_setup, "configure_stderr_logging"),
        (cli_common, "configure_stderr_logging"),
    ):
        monkeypatch.setattr(module, name, recorder(f"{module.__name__}.{name}"))
    handlers = list(logging.getLogger().handlers)
    cli_module._build_parser()
    assert called == []
    assert list(logging.getLogger().handlers) == handlers
    # Control: the recorders are live, so an empty list above means nothing was called.
    console_streams.harden_console_streams()
    assert called == ["messagefoundry.console_streams.harden_console_streams"]


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


def test_a_row_on_both_commands_is_named(
    engine_paths: dict[str, set[str]], toolkit_paths: dict[str, set[str]]
) -> None:
    engine = {**engine_paths, "adr-analyze": set()}
    assert _split_problems(engine, toolkit_paths, cli_surface.CLI_TIERS) == [
        "on both commands: adr-analyze"
    ]


def test_a_production_row_on_the_toolkit_command_is_named(
    engine_paths: dict[str, set[str]], toolkit_paths: dict[str, set[str]]
) -> None:
    engine = {p: c for p, c in engine_paths.items() if p != "dryrun"}
    toolkit = {**toolkit_paths, "dryrun": set()}
    assert _split_problems(engine, toolkit, cli_surface.CLI_TIERS) == [
        "production row on the toolkit command: dryrun"
    ]


# --- A moved toolkit command is refused by name, before parsing (ADR 0201 AC-3). -----------------


def _run_engine(monkeypatch: pytest.MonkeyPatch, argv: list[str]) -> int:
    """Run the engine's ``main()`` without leaking its process-wide changes into later tests.

    main() installs both process-wide exception hooks. Setting each to its current value makes the
    context put it back afterwards. The stream hardening cannot be undone, so it is skipped at both
    of its call sites, main() and run_cli()."""
    monkeypatch.setattr(sys, "excepthook", sys.excepthook)
    monkeypatch.setattr(threading, "excepthook", threading.excepthook)
    monkeypatch.setattr(cli_module, "harden_console_streams", lambda **_kw: None)
    monkeypatch.setattr(cli_common, "harden_console_streams", lambda **_kw: None)
    return cli_module.main(argv)


def test_a_moved_command_is_refused_on_stderr_alone(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # Arguments the toolkit's adr-analyze accepts. A refusal from argparse would read "invalid
    # choice"; this one names the toolkit command.
    assert _run_engine(monkeypatch, ["adr-analyze", "--adr-dir", "docs/adr"]) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert len(captured.err.splitlines()) == 1, captured.err
    assert "messagefoundry-toolkit adr-analyze" in captured.err
    assert "invalid choice" not in captured.err


def test_a_moved_command_under_json_is_refused_on_stdout_alone(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    assert _run_engine(monkeypatch, ["adr-analyze", "--json"]) == 2
    captured = capsys.readouterr()
    assert captured.err == ""
    payload = json.loads(captured.out)
    assert set(payload) == {"error"}
    assert "messagefoundry-toolkit adr-analyze" in payload["error"]


def test_lens_rewrite_takes_json_mode_without_a_flag(capsys: pytest.CaptureFixture[str]) -> None:
    """``lens rewrite`` has no ``--json`` flag and answers in JSON; ``lens schema`` prints JSON with
    or without its flag. ``lens parse`` reports an error as text without its flag. ``lens`` is still
    registered on the engine in slice 2, so the refusal is driven directly, not through ``main()``."""
    for argv in (["lens", "rewrite", "x.py"], ["lens", "schema"]):
        assert cli_module._refuse_toolkit_command("lens", argv) == 2
        captured = capsys.readouterr()
        assert captured.err == "", argv
        assert "messagefoundry-toolkit lens" in json.loads(captured.out)["error"]
    # Control: the sibling whose errors are text without --json answers as text.
    assert cli_module._refuse_toolkit_command("lens", ["lens", "parse", "x.py"]) == 2
    captured = capsys.readouterr()
    assert captured.out == "" and "messagefoundry-toolkit lens" in captured.err


@pytest.mark.parametrize("builder", ["engine", "toolkit"])
def test_help_never_splits_the_toolkit_command_at_its_hyphen(
    builder: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """argparse's default formatter breaks lines at hyphens, which printed ``messagefoundry-`` and
    ``toolkit`` on two lines at some widths, so a reader who copied the command got half of it.
    Every width a terminal plausibly has, because the break moves with the width."""
    module = cli_module if builder == "engine" else toolkit_cli
    # argparse reads COLUMNS when format_help() makes its formatter, so one parser serves every width.
    parser = module._build_parser()[0]
    for columns in range(50, 161):
        monkeypatch.setenv("COLUMNS", str(columns))
        help_text = parser.format_help()
        assert "messagefoundry-toolkit" in help_text, columns
        assert "messagefoundry-\n" not in help_text, f"split at COLUMNS={columns}"


def test_help_or_version_before_a_moved_command_still_answers(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """argparse answers a top-level ``--help`` or ``--version`` before it reads a subcommand, so a
    moved command name after one must not turn it into a refusal."""
    for flag in ("--help", "--version"):
        with pytest.raises(SystemExit) as exc:
            _run_engine(monkeypatch, [flag, "adr-analyze"])
        assert exc.value.code == 0, flag
        assert "is not a messagefoundry command" not in capsys.readouterr().err
    # An abbreviation is not one of those flags, so argparse must refuse it too rather than read
    # it as --version while the pre-parse reads a moved command (allow_abbrev=False).
    with pytest.raises(SystemExit) as exc:
        _run_engine(monkeypatch, ["--vers"])
    assert exc.value.code == 2


def test_only_a_toolkit_row_the_engine_does_not_register_is_refused() -> None:
    assert cli_module._moved_toolkit_commands() == {"adr-analyze"}
    # Still registered on the engine in slice 2, so the engine runs it rather than refusing it.
    assert cli_module._moved_toolkit_command(["generate", "--type", "ADT"]) is None
    # A production command is never refused, and an option before the command is skipped.
    assert cli_module._moved_toolkit_command(["--version"]) is None
    assert cli_module._moved_toolkit_command(["serve", "adr-analyze"]) is None
    assert cli_module._moved_toolkit_command(["--json", "adr-analyze"]) == "adr-analyze"


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
