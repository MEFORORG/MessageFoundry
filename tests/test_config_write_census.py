# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Every code path that writes a config file, and that none of them runs in the engine (vault
BACKLOG #2945, BACKLOG #2623).

A start compares the digest of its config directory with the newest baseline row in the store
(vault BACKLOG #2597): a start or an applied reload. The running engine writes no file in that
directory, so it needs no write access to the directory it executes code from, and it has no write
of its own to record. The one such write it had, the connection flag, moved to the store.

:data:`CENSUS` is the record. Each call into a function that writes a config file is keyed by its
file and the def it sits in, and must be listed with a verdict. A new call site fails
:func:`test_every_config_write_call_site_is_in_the_census` until someone classifies it, and
:func:`test_only_the_cli_writes_config` refuses any site outside the CLI module: an engine write
would bring back the write access, and a baseline row with it.

Scope, stated rather than implied. The census finds references to the writer functions in
:data:`WRITERS`, by name, whether called or handed on as a callable, across :data:`PACKAGES`. A
writer reached under another name (an alias, or a wrapper outside :data:`LIBRARY`) is not seen. A
direct ``write_text`` or ``os.replace`` into a config directory is a different shape:
:func:`test_no_engine_code_writes_a_config_path_directly` catches one whose target expression names
the config directory, and cannot follow a path that reached it through a variable of another name.
The IDE extension and the PySide6 harness are not engine code and are not read.
"""

from __future__ import annotations

import ast
from collections.abc import Mapping

import pytest

from messagefoundry.api import app as app_module
from tests._ast_sites import outermost_def_sites, package_trees

#: The functions that write a file in a config directory, matched by name at the call. The first
#: group writes a file the config digest covers (``config/fingerprint.py``): config modules,
#: ``connections.toml``, ``codesets/`` and ``environments/``. The last three write the service
#: settings file, which the digest does not cover; they are here so the census names them.
WRITERS: frozenset[str] = frozenset(
    {
        "upsert_connection",
        "remove_connection",
        "upsert_code_set",
        "rename_code_set",
        "remove_code_set",
        "apply_rename",
        "replace_validated",
        "scaffold",
        "import_corepoint",
        "run_restore",
        "add_rule",
        "remove_rule",
        "set_security",
    }
)

#: The modules that implement the writers. Their calls into one another are the writers' own
#: internals; the call that decides whether a write moves the baseline is the one into the module.
LIBRARY: frozenset[str] = frozenset(
    {
        "messagefoundry/config/atomic_edit.py",
        "messagefoundry/config/connections_edit.py",
        "messagefoundry/config/codeset_edit.py",
        "messagefoundry/config/alerts_edit.py",
        "messagefoundry/config/security_edit.py",
        "messagefoundry/config/impact.py",
    }
)

#: Each entry says why the site is outside the engine. A CLI subcommand runs in its own process and
#: records no row. Its edit does not move the baseline, by decision: no engine loaded it, and nothing
#: in that process can say which engine would. A reload that loads it records a ``config_reload`` row
#: with the new digest, which moves the baseline then. A start that loads it first raises
#: ``config_changed``, and that alert is the record of an edit no engine made. The service settings
#: file is outside the config digest, so its two writers have no baseline to move.
CENSUS: dict[tuple[str, str], str] = {
    ("messagefoundry/__main__.py", "_connection"): (
        "the `connection` CLI upserts or removes a connections.toml entry, in its own process"
    ),
    ("messagefoundry/__main__.py", "_codeset"): (
        "the `codeset` CLI writes, renames or removes a codesets/ table, and a rename rewrites the "
        "config modules that name it"
    ),
    ("messagefoundry/__main__.py", "_impact"): (
        "the `impact` CLI's rename rewrites string literals in config modules"
    ),
    ("messagefoundry/__main__.py", "_init"): "`init` scaffolds a new config directory",
    ("messagefoundry/__main__.py", "_import"): (
        "`import` writes config modules generated from a Corepoint export"
    ),
    ("messagefoundry/__main__.py", "_restore"): (
        "`dr restore` writes an archived config bundle into an empty directory, beside a restored "
        "store whose rows already baseline those bytes"
    ),
    ("messagefoundry/__main__.py", "_alert"): (
        "the `alert` CLI writes [[alerts]] rules into the service settings file"
    ),
    ("messagefoundry/__main__.py", "_security"): (
        "the `security` CLI writes the service settings file"
    ),
}


def _names_writer(node: ast.expr) -> bool:
    if isinstance(node, ast.Attribute):
        return node.attr in WRITERS
    return isinstance(node, ast.Name) and node.id in WRITERS


def _is_writer_ref(node: ast.AST) -> bool:
    """A call that uses a writer: calls one, or hands one on as a callable, as ``asyncio.to_thread(
    connections_edit.upsert_connection, ...)`` or ``functools.partial`` would. Only the callee and
    the arguments count, so a local of the same name used as a receiver (``__main__``'s argparse
    ``import_corepoint.add_argument``) is not a writer."""
    return isinstance(node, ast.Call) and any(
        _names_writer(part) for part in [node.func, *node.args, *(k.value for k in node.keywords)]
    )


def _found_sites(trees: Mapping[str, ast.Module]) -> set[tuple[str, str]]:
    """Every ``(path, def)`` in ``trees`` (relative path to parsed module) that calls a writer."""
    return {
        (path, site)
        for path, tree in trees.items()
        if path not in LIBRARY
        for site in outermost_def_sites(tree, _is_writer_ref)
    }


def _unlisted(trees: Mapping[str, ast.Module]) -> list[str]:
    """A writer call in a def the census does not list."""
    return [
        f"{path}: {site} writes a config file and is not in CENSUS; the engine writes no config "
        "file, so classify a CLI write or keep the value out of the config directory"
        for path, site in sorted(_found_sites(trees) - set(CENSUS))
    ]


def test_every_config_write_call_site_is_in_the_census() -> None:
    found = _found_sites(package_trees())
    assert found == set(CENSUS), (
        "unlisted: " + repr(sorted(found - set(CENSUS))),
        "listed but gone: " + repr(sorted(set(CENSUS) - found)),
    )


def test_only_the_cli_writes_config() -> None:
    """Only the CLI module's subcommands run in their own process, so the engine writes no config
    file at all."""
    for path, site in CENSUS:
        assert path == "messagefoundry/__main__.py", (path, site)


def test_the_guard_refuses_an_unlisted_writer() -> None:
    """Positive controls, so the passes above are the census holding and not a scan that found
    nothing. An engine function calling a writer is refused, called or handed on."""
    for rogue in (
        "def toggle(d, obj):\n    connections_edit.upsert_connection(d, obj, validate=None)\n",
        # Handed on as a callable rather than called: the usual way off the event loop.
        "async def toggle(d, obj):\n"
        "    await asyncio.to_thread(connections_edit.upsert_connection, d, obj, validate=None)\n",
    ):
        assert _unlisted({"messagefoundry/pipeline/rogue.py": ast.parse(rogue)}) == [
            "messagefoundry/pipeline/rogue.py: toggle writes a config file and is not in CENSUS; "
            "the engine writes no config file, so classify a CLI write or keep the value out of "
            "the config directory"
        ]


def test_a_flag_row_is_no_start_baseline() -> None:
    """A toggle's ``connection_flag_set`` row carries no digest (BACKLOG #2623). As a baseline it
    would read as degraded, and the start after every toggle would compare nothing."""
    assert app_module._CONFIG_BASELINE_ACTIONS == ("config_loaded", "config_reload")


#: Names that, in a write's target expression, put the target in a config directory.
_CONFIG_PATH_NAMES = (
    "config_dir",
    "cfg_dir",
    "CONNECTIONS_FILE_NAME",
    "connections.toml",
    "codesets",
    "environments",
)


def _write_targets(call: ast.Call) -> list[ast.expr]:
    """The path expressions ``call`` writes to, for the shapes this guard knows: ``x.write_text``,
    ``x.write_bytes``, ``x.open("w")`` and ``open(x, "w")`` with the mode positional or keyword
    (any of ``w``/``a``/``x``/``+``), the destination of ``os.replace``/``os.rename`` and the
    ``shutil`` copies and move, and of the one-argument ``Path.replace``/``Path.rename``."""
    func = call.func

    def mode_writes(mode: ast.expr | None) -> bool:
        return (
            isinstance(mode, ast.Constant)
            and isinstance(mode.value, str)
            and bool(set(mode.value) & set("wax+"))
        )

    def mode_of(position: int) -> ast.expr | None:
        if len(call.args) > position:
            return call.args[position]
        return next((k.value for k in call.keywords if k.arg == "mode"), None)

    if isinstance(func, ast.Attribute):
        if func.attr in {"write_text", "write_bytes"}:
            return [func.value]
        if func.attr == "open" and mode_writes(mode_of(0)):
            return [func.value]
        module = func.value.id if isinstance(func.value, ast.Name) else None
        destination_writers = {
            "os": {"replace", "rename"},
            "shutil": {"copy", "copy2", "copyfile", "copytree", "move"},
        }
        if module and func.attr in destination_writers.get(module, set()) and len(call.args) > 1:
            return [call.args[1]]
        # Path.replace(target) and Path.rename(target). str.replace takes two arguments, so one
        # argument and no keywords keeps it out.
        if func.attr in {"replace", "rename"} and len(call.args) == 1 and not call.keywords:
            return [call.args[0]]
    if isinstance(func, ast.Name) and func.id == "open" and call.args and mode_writes(mode_of(1)):
        return [call.args[0]]
    return []


def _direct_config_writes(trees: Mapping[str, ast.Module]) -> list[str]:
    hits: list[str] = []
    for path, tree in sorted(trees.items()):
        if path in LIBRARY or path == "messagefoundry/__main__.py":
            continue
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            for target in _write_targets(node):
                expr = ast.unparse(target)
                if any(name in expr for name in _CONFIG_PATH_NAMES):
                    hits.append(f"{path}:{node.lineno} writes {expr}")
    return hits


def test_no_engine_code_writes_a_config_path_directly() -> None:
    assert _direct_config_writes(package_trees()) == []


@pytest.mark.parametrize(
    "line",
    [
        "(cfg_dir / 'connections.toml').write_text(text)",
        "os.replace(tmp, self.running_config_dir / CONNECTIONS_FILE_NAME)",
        "open(config_dir / 'codesets' / 'x.csv', 'w')",
        "(config_dir / 'environments' / 'dev.toml').open('a')",
        "(config_dir / 'environments' / 'dev.toml').open(mode='r+')",
        "candidate.replace(cfg_dir / CONNECTIONS_FILE_NAME)",
        "tmp.rename(config_dir / 'codesets' / 'x.csv')",
    ],
)
def test_the_direct_write_scan_sees_each_shape(line: str) -> None:
    """Positive control for the scan above: each shape it claims to see is reported."""
    hits = _direct_config_writes({"messagefoundry/pipeline/rogue.py": ast.parse(line)})
    assert len(hits) == 1, hits
