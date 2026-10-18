# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Every code path that writes a config file, and whether it moves the config-change baseline
(vault BACKLOG #2945).

A start compares the digest of its config directory with the newest baseline row in the store
(vault BACKLOG #2597): a start, an applied reload, or an engine write of a file the digest covers.
An engine write that recorded no row would leave the baseline behind, and the next start would
raise ``config_changed`` for a change the engine made itself. So every engine write goes through
``Engine.write_baseline_config``, which writes, takes the digest and records the row, and whose
action names the start reads (``CONFIG_WRITE_ACTIONS``).

:data:`CENSUS` is the record. Each call into a function that writes a config file is keyed by its
file and the def it sits in, and must be listed with a verdict. A new call site fails
:func:`test_every_config_write_call_site_is_in_the_census` until someone classifies it, and a site
classified ``helper`` fails :func:`test_every_engine_config_write_goes_through_the_helper` unless
it calls the helper.

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
import functools
from collections.abc import Mapping
from pathlib import Path
from typing import Literal

import pytest

from messagefoundry.api import app as app_module
from messagefoundry.pipeline import engine as engine_module
from tests._ast_sites import call_sites

REPO = Path(__file__).resolve().parents[1]
#: The packages that run in the engine process or ship beside it: the engine, the web console
#: mounted in it at /ui, and the toolkit split out of it.
PACKAGES = tuple(
    REPO / name
    for name in ("messagefoundry", "messagefoundry_webconsole", "messagefoundry_toolkit")
)

#: The helper every engine config write goes through.
HELPER = "write_baseline_config"

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

type Verdict = Literal["helper", "undo", "cli", "settings"]

#: ``helper``: an engine write of a covered file; it moves the baseline through the helper.
#: ``cli``: a CLI subcommand, which runs in its own process and records no row. Its edit does not
#: move the baseline, by decision: no engine loaded it, and nothing in that process can say which
#: engine would. A reload that loads it records a ``config_reload`` row with the new digest, which
#: moves the baseline then. A start that loads it first raises ``config_changed``, and that alert is
#: the record of an edit no engine made. ``settings``: writes the service settings file, which the
#: config digest does not cover, so there is no baseline for it to move. ``undo``: the helper's own
#: put-back of the bytes a write changed when its row fails, so it moves no baseline: the files go
#: back to the bytes the newest row names, unless the store committed the failed row after all,
#: which ``Engine.write_baseline_config`` says the next start reports. Only the helper may call it.
CENSUS: dict[tuple[str, str], tuple[Verdict, str]] = {
    ("messagefoundry/pipeline/engine.py", "Engine.set_connection_flag"): (
        "helper",
        "POST /connections/{name}/flag rewrites connections.toml in the running engine. Refused "
        "on a cluster node (vault BACKLOG #2933).",
    ),
    ("messagefoundry/pipeline/engine.py", "_undo_write"): (
        "undo",
        "write_baseline_config puts back what a write changed when its row fails, times out or "
        "is cancelled, so a refused write does not stay on disk (vault BACKLOG #2945)",
    ),
    ("messagefoundry/__main__.py", "_connection"): (
        "cli",
        "the `connection` CLI upserts or removes a connections.toml entry, in its own process",
    ),
    ("messagefoundry/__main__.py", "_codeset"): (
        "cli",
        "the `codeset` CLI writes, renames or removes a codesets/ table, and a rename rewrites the "
        "config modules that name it",
    ),
    ("messagefoundry/__main__.py", "_impact"): (
        "cli",
        "the `impact` CLI's rename rewrites string literals in config modules",
    ),
    ("messagefoundry/__main__.py", "_init"): (
        "cli",
        "`init` scaffolds a new config directory",
    ),
    ("messagefoundry/__main__.py", "_import"): (
        "cli",
        "`import` writes config modules generated from a Corepoint export",
    ),
    ("messagefoundry/__main__.py", "_restore"): (
        "cli",
        "`dr restore` writes an archived config bundle into an empty directory, beside a restored "
        "store whose rows already baseline those bytes",
    ),
    ("messagefoundry/__main__.py", "_alert"): (
        "settings",
        "the `alert` CLI writes [[alerts]] rules into the service settings file",
    ),
    ("messagefoundry/__main__.py", "_security"): (
        "settings",
        "the `security` CLI writes the service settings file",
    ),
}


def _rel(path: Path) -> str:
    return path.relative_to(REPO).as_posix()


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


def _writer_sites(tree: ast.Module) -> set[str]:
    """The defs in ``tree`` that reference a writer: class names down to the outermost function,
    so a call in a nested ``_write`` closure is charged to the method that defines it."""
    sites: set[str] = set()

    def walk(node: ast.AST, owner: list[str], in_function: bool) -> None:
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                if in_function:
                    walk(child, owner, True)
                else:
                    is_def = not isinstance(child, ast.ClassDef)
                    walk(child, [*owner, child.name], is_def)
                continue
            if _is_writer_ref(child):
                sites.add(".".join(owner) or "<module>")
            walk(child, owner, in_function)

    walk(tree, [], False)
    return sites


def _unrouted_writer_refs(node: ast.AST) -> list[int]:
    """The lines in def ``node`` that reference a writer outside every nested def handed to the
    helper as its ``write`` argument, so a ``helper`` def cannot route one write through it and
    make another beside it, or in what it hands over as ``reflect``. The helper takes ``write``
    second, after ``action``, or by keyword."""
    routed = {
        arg.id
        for call in call_sites(node, HELPER)
        for arg in [*call.args[1:2], *(k.value for k in call.keywords if k.arg == "write")]
        if isinstance(arg, ast.Name)
    }
    lines: list[int] = []

    def walk(current: ast.AST) -> None:
        for child in ast.iter_child_nodes(current):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)) and child.name in routed:
                continue
            if isinstance(child, ast.Call) and _is_writer_ref(child):
                lines.append(child.lineno)
            walk(child)

    walk(node)
    return lines


def _def_node(tree: ast.Module, qualname: str) -> ast.AST:
    """The def node at ``qualname`` in ``tree``."""
    node: ast.AST = tree
    for part in qualname.split("."):
        node = next(
            child
            for child in ast.iter_child_nodes(node)
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
            and child.name == part
        )
    return node


def _found_sites(trees: Mapping[str, ast.Module]) -> set[tuple[str, str]]:
    """Every ``(path, def)`` in ``trees`` (relative path to parsed module) that calls a writer."""
    return {
        (path, site)
        for path, tree in trees.items()
        if path not in LIBRARY
        for site in _writer_sites(tree)
    }


def _unlisted(trees: Mapping[str, ast.Module]) -> list[str]:
    """A writer call in a def the census does not list."""
    return [
        f"{path}: {site} writes a config file and is not in CENSUS; classify it, and if it runs "
        f"in the engine, route the write through Engine.{HELPER}"
        for path, site in sorted(_found_sites(trees) - set(CENSUS))
    ]


def _helper_bypasses(trees: Mapping[str, ast.Module]) -> list[str]:
    """A census ``helper`` def, present in ``trees``, with a writer reference outside the defs it
    hands to the helper (including one that never calls the helper at all)."""
    problems: list[str] = []
    for (path, site), (verdict, _why) in CENSUS.items():
        if verdict != "helper" or path not in trees:
            continue
        lines = _unrouted_writer_refs(_def_node(trees[path], site))
        if lines:
            problems.append(f"{path}: {site} writes a config file without Engine.{HELPER}")
    return problems


@functools.cache
def _package_trees() -> dict[str, ast.Module]:
    """Every module in :data:`PACKAGES`, parsed once for the whole file: a full pass costs
    seconds."""
    return {
        _rel(path): ast.parse(path.read_text(encoding="utf-8"))
        for package in PACKAGES
        for path in package.rglob("*.py")
    }


def test_every_config_write_call_site_is_in_the_census() -> None:
    found = _found_sites(_package_trees())
    assert found == set(CENSUS), (
        "unlisted: " + repr(sorted(found - set(CENSUS))),
        "listed but gone: " + repr(sorted(set(CENSUS) - found)),
    )


def test_every_engine_config_write_goes_through_the_helper() -> None:
    assert _helper_bypasses(_package_trees()) == []


def test_only_the_cli_writes_config_outside_the_helper() -> None:
    """A ``cli`` or ``settings`` verdict says the write runs in its own process. Only the CLI
    module's subcommands can earn one; engine code that writes a config file uses the helper, or is
    the helper's own undo."""
    for (path, site), (verdict, _why) in CENSUS.items():
        if verdict in ("cli", "settings"):
            assert path == "messagefoundry/__main__.py", (path, site)
        elif verdict == "undo":
            assert path == "messagefoundry/pipeline/engine.py", (path, site)


def _undo_callers(tree: ast.Module) -> set[str]:
    """The defs in ``tree`` that name an ``undo`` site, charged to the outermost def as
    :func:`_writer_sites` charges a writer call."""
    undo = {site for (_path, site), (verdict, _why) in CENSUS.items() if verdict == "undo"}
    callers: set[str] = set()

    def walk(node: ast.AST, owner: list[str], in_function: bool) -> None:
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                if in_function:
                    walk(child, owner, True)
                else:
                    walk(child, [*owner, child.name], not isinstance(child, ast.ClassDef))
                continue
            if isinstance(child, ast.Name) and child.id in undo:
                callers.add(".".join(owner) or "<module>")
            walk(child, owner, in_function)

    walk(tree, [], False)
    return callers


def test_only_the_helper_calls_the_undo() -> None:
    """The undo rewrites covered files and records no row. The helper calls it only once its own
    row has failed; any other caller would be a config write with no baseline row."""
    tree = _package_trees()["messagefoundry/pipeline/engine.py"]
    assert _undo_callers(tree) == {"Engine.write_baseline_config"}
    # Positive control: a second caller is seen.
    rogue = ast.parse("def toggle(d):\n    _undo_write(d, {})\n")
    assert _undo_callers(rogue) == {"toggle"}


def test_the_guard_refuses_an_unlisted_writer_and_a_helper_bypass() -> None:
    """Positive controls, so the passes above are the census holding and not a scan that found
    nothing. An unlisted engine function calling a writer is refused, and so is the real flag
    toggle with its helper call taken out."""
    for rogue in (
        "def toggle(d, obj):\n    connections_edit.upsert_connection(d, obj, validate=None)\n",
        # Handed on as a callable rather than called: the usual way off the event loop.
        "async def toggle(d, obj):\n"
        "    await asyncio.to_thread(connections_edit.upsert_connection, d, obj, validate=None)\n",
    ):
        assert _unlisted({"messagefoundry/pipeline/rogue.py": ast.parse(rogue)}) == [
            "messagefoundry/pipeline/rogue.py: toggle writes a config file and is not in CENSUS; "
            f"classify it, and if it runs in the engine, route the write through Engine.{HELPER}"
        ]

    engine_path = "messagefoundry/pipeline/engine.py"
    real = (REPO / engine_path).read_text(encoding="utf-8")
    refused = [
        f"{engine_path}: Engine.set_connection_flag writes a config file without Engine.{HELPER}"
    ]
    assert f"self.{HELPER}(" in real
    bypassed = ast.parse(real.replace(f"self.{HELPER}(", "self._not_the_helper("))
    assert _helper_bypasses({engine_path: bypassed}) == refused
    # Still calling the helper, but also writing beside it, outside the def it hands over.
    anchor = "        def _reflect() -> None:\n"
    assert anchor in real
    beside = real.replace(
        anchor,
        "        connections_edit.remove_connection(cfg, name, validate=None)\n\n" + anchor,
    )
    assert _helper_bypasses({engine_path: ast.parse(beside)}) == refused
    # Inside the def handed over as `reflect`, which runs outside the edit lock and after the digest.
    reflect_anchor = "            rr = self._registry_runner\n"
    assert reflect_anchor in real
    in_reflect = real.replace(
        reflect_anchor,
        "            connections_edit.remove_connection(cfg, name, validate=None)\n"
        + reflect_anchor,
        1,
    )
    assert _helper_bypasses({engine_path: ast.parse(in_reflect)}) == refused


def test_the_start_reads_every_action_the_helper_records() -> None:
    """The start's baseline list is built from the helper's action names (``*CONFIG_WRITE_ACTIONS``),
    so a write recorded under a new name is a baseline with no second list to keep in step."""
    # Holds by construction today; it fails if the splat is ever replaced by a literal tuple.
    assert set(engine_module.CONFIG_WRITE_ACTIONS) <= set(app_module._CONFIG_BASELINE_ACTIONS)
    assert {"config_loaded", "config_reload"} <= set(app_module._CONFIG_BASELINE_ACTIONS)
    # The helper marks an unchecked row with the key the start-row comparison skips.
    assert engine_module.CONFIG_BASELINE_UNCHECKED_KEY == app_module._BASELINE_UNCHECKED


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
    assert _direct_config_writes(_package_trees()) == []


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
