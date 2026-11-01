# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The connection flag stays a display marker: every reader of it is named here (BACKLOG #2623).

The flag moved to the store with no seal, and that rests on one fact: it decides nothing. A database
writer can move a marker on the console and no more. A reader that branched on it would change that
without a word in any diff, and the seal question would be open again. So a new reader fails here
until someone has looked at it. If the new reader acts on the value, seal it first.

``auto_start`` and ``deployed`` sit beside where this flag used to, and both act. They stayed in
``connections.toml`` and this file says nothing about them.

The flag is off the :class:`Registry`, so there is one road to the value: the store's
``list_connection_flags``, or SQL on its table. Past that road it travels only as the ``flagged``
field of the dashboard row. So the census has three arms: who calls the read, who names the table,
and who loads a ``flagged`` attribute or key.

Scope, stated rather than implied. It reads :data:`PACKAGES` by name. A read through an alias, or a
bare local such as ``if flagged:``, is not seen, and a local of that name means nothing by itself:
at least the sign-in code keeps one of its own. The arms above catch the value at the road in, so a
bare local is still downstream of a read this file lists. The IDE extension and the PySide6 harness
are not read. Neither reads the flag today, and neither shares this process.
"""

from __future__ import annotations

import ast
import re
from collections.abc import Mapping

import pytest

from tests._ast_sites import code_strings, outermost_def_sites, package_trees

#: The store's read, by name.
READ = "list_connection_flags"
#: The table, as whole words in a string, so ``connection_flag_set`` (the audit action) stays out.
TABLE = re.compile(r"\bconnection_flag\b")

#: The one caller of the read. Display, and it fails soft: see its docstring.
READ_CALLERS: frozenset[tuple[str, str]] = frozenset(
    {("messagefoundry/api/app.py", "_connection_flags")}
)

#: The modules whose SQL may name the table: the three backends, and nothing else.
TABLE_MODULES: frozenset[str] = frozenset(
    {
        "messagefoundry/store/store.py",
        "messagefoundry/store/postgres.py",
        "messagefoundry/store/sqlserver.py",
    }
)

#: Who loads ``.flagged``, ``["flagged"]`` or ``.get("flagged")``, and why that is only display.
#: A site is charged to its outermost def, as ``tests/test_config_write_census.py`` charges a
#: writer, so a route counts under the function that registers it.
FIELD_READERS: dict[tuple[str, str], str] = {
    ("messagefoundry/api/app.py", "create_app"): (
        "POST /connections/{name}/flag hands req.flagged to the engine and echoes it"
    ),
    ("messagefoundry_webconsole/pages/connections.py", "_selection_checkbox"): (
        "the row's data-flagged attribute, which the client-side filter reads"
    ),
    ("messagefoundry_webconsole/pages/connections.py", "_flag_cell"): "the flag cell's glyph",
    ("messagefoundry_webconsole/routes/connection_writes.py", "register"): (
        "POST /ui/connections/{name}/flag reads its form into the request the JSON handler takes"
    ),
    # Not this flag: an upload entry's own marker that an ERROR named it, listed so the scan stays
    # a scan by name with no exceptions in its code.
    ("messagefoundry/uploads.py", "UploadStore._remove_and_report_sync"): "an unrelated field",
}


def _is_read_call(node: ast.AST) -> bool:
    """A reference to the store's read, called or handed on, outside its own definitions."""
    return isinstance(node, ast.Attribute) and node.attr == READ


def _loads_field(node: ast.AST) -> bool:
    """``x.flagged``, ``x["flagged"]`` or ``x.get("flagged")``, read rather than written."""
    if isinstance(node, ast.Attribute):
        return node.attr == "flagged" and isinstance(node.ctx, ast.Load)
    if isinstance(node, ast.Subscript):
        return (
            isinstance(node.ctx, ast.Load)
            and isinstance(node.slice, ast.Constant)
            and node.slice.value == "flagged"
        )
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
        return (
            node.func.attr == "get"
            and bool(node.args)
            and isinstance(node.args[0], ast.Constant)
            and node.args[0].value == "flagged"
        )
    return False


def _read_callers(trees: Mapping[str, ast.Module]) -> set[tuple[str, str]]:
    return {
        (path, site)
        for path, tree in trees.items()
        for site in outermost_def_sites(tree, _is_read_call)
    }


def _field_readers(trees: Mapping[str, ast.Module]) -> set[tuple[str, str]]:
    return {
        (path, site)
        for path, tree in trees.items()
        for site in outermost_def_sites(tree, _loads_field)
    }


def _table_modules(trees: Mapping[str, ast.Module]) -> set[str]:
    """The modules whose code holds a string naming the table. A docstring is no code."""
    return {
        path
        for path, tree in trees.items()
        if any(TABLE.search(text) for text in code_strings(tree))
    }


def test_the_store_read_has_one_caller() -> None:
    found = _read_callers(package_trees())
    assert found == READ_CALLERS, (
        "a new reader of the connection flag. It was moved to the store unsealed because it "
        f"decides nothing; if this one acts on it, seal it first: {sorted(found - READ_CALLERS)}"
    )


def test_only_the_backends_name_the_table() -> None:
    found = _table_modules(package_trees())
    assert found == TABLE_MODULES, sorted(found ^ TABLE_MODULES)


def test_every_load_of_the_field_is_display() -> None:
    found = _field_readers(package_trees())
    assert found == set(FIELD_READERS), (
        "unlisted: " + repr(sorted(found - set(FIELD_READERS))),
        "listed but gone: " + repr(sorted(set(FIELD_READERS) - found)),
    )


@pytest.mark.parametrize(
    "line",
    [
        "async def alerting(store):\n    return await store.list_connection_flags()\n",
        "async def alerting(store):\n    return await asyncio.to_thread(store.list_connection_flags)\n",
    ],
)
def test_the_read_scan_sees_a_rogue_caller(line: str) -> None:
    """Positive control: a new caller is seen, called or handed on."""
    trees = {"messagefoundry/pipeline/rogue.py": ast.parse(line)}
    assert _read_callers(trees) == {("messagefoundry/pipeline/rogue.py", "alerting")}


@pytest.mark.parametrize(
    "line",
    [
        "def route(row):\n    if row.flagged:\n        return 1\n",
        "def route(row):\n    return row['flagged']\n",
        "def route(row):\n    return row.get('flagged')\n",
    ],
)
def test_the_field_scan_sees_each_shape(line: str) -> None:
    trees = {"messagefoundry/pipeline/rogue.py": ast.parse(line)}
    assert _field_readers(trees) == {("messagefoundry/pipeline/rogue.py", "route")}


def test_the_field_scan_passes_over_a_write() -> None:
    assert not _field_readers({"m.py": ast.parse("def f(row):\n    row.flagged = True\n")})


def test_the_table_scan_sees_raw_sql_and_skips_the_audit_action_and_a_docstring() -> None:
    rogue = "def f(db):\n    return db.execute('SELECT 1 FROM connection_flag')\n"
    assert _table_modules({"rogue.py": ast.parse(rogue)}) == {"rogue.py"}
    action = "def f():\n    return 'connection_flag_set'\n"
    documented = 'def f():\n    """Reads the connection_flag table."""\n'
    assert not _table_modules({"a.py": ast.parse(action), "b.py": ast.parse(documented)})
