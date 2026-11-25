# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""An AST census of every line pynetdicom and pydicom can log (BACKLOG #6637 item 10).

:mod:`messagefoundry.transports._dicom_log_lines` pins the lines an operator may read, and everything
else is withheld. A library upgrade that adds or rewords a line is safe without this, since the new
line is withheld, but it would change what an operator reads with nothing saying so. This scans the
installed libraries so a test fails on such a change.

Run ``python -P tests/_dicom_log_census.py --write`` from the repository root, after reading the
difference, to accept a new library version's lines. It rewrites the census and the generated block
of value-free lines; run ``ruff format`` on that module after it.
"""

from __future__ import annotations

import ast
import functools
import importlib
import re
import sys
from collections.abc import Iterator
from pathlib import Path

#: The pinned result of :func:`census`, one call per line.
CENSUS_FILE = Path(__file__).with_name("_dicom_log_census.txt")
_LINES_MODULE = Path(__file__).parents[1] / "messagefoundry" / "transports" / "_dicom_log_lines.py"

#: A whole line a library builds with ``+=``, so the scan sees it only as a variable.
_BUILT_LINES = frozenset({"Association Aborted (A-P-ABORT)"})

LIBRARIES = ("pynetdicom", "pydicom")

#: Not part of what the engine runs: the libraries' own tests, command line apps and examples.
_SKIPPED_PARTS = frozenset({"tests", "apps", "examples", "benchmarks"})

_LEVELS = {
    "debug": "DEBUG",
    "info": "INFO",
    "warning": "WARNING",
    "warn": "WARNING",
    "error": "ERROR",
    "exception": "ERROR",
    "critical": "CRITICAL",
    "fatal": "CRITICAL",
}


def skeleton(node: ast.expr) -> str:
    """A log call's message with each interpolated field as ``{}``, or ``<expr>`` of a variable."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.JoinedStr):
        parts: list[str] = []
        for value in node.values:
            if isinstance(value, ast.Constant):
                parts.append(str(value.value))
            elif isinstance(value, ast.FormattedValue) and isinstance(value.value, ast.Constant):
                spec = ""
                if isinstance(value.format_spec, ast.JoinedStr):
                    spec = "".join(
                        str(v.value)
                        for v in value.format_spec.values
                        if isinstance(v, ast.Constant)
                    )
                parts.append(format(value.value.value, spec))
            else:
                parts.append("{}")
        return "".join(parts)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return skeleton(node.left) + skeleton(node.right)
    return f"<{ast.unparse(node)}>"


def _level(node: ast.Call) -> str | None:
    function = node.func
    if isinstance(function, ast.Name):
        return "WARNING" if function.id == "warn_and_log" else None
    if not isinstance(function, ast.Attribute):
        return None
    if function.attr == "warn_and_log":
        return "WARNING"
    base = function.value
    name = base.id if isinstance(base, ast.Name) else getattr(base, "attr", "")
    if not isinstance(name, str) or "log" not in name.lower():
        return None
    return _LEVELS.get(function.attr)


def _strings_in(node: ast.AST) -> Iterator[str]:
    """Each string a dump in ``_handlers`` builds into the list it logs line by line."""
    if isinstance(node, ast.Assign) and isinstance(node.value, ast.List):
        for element in node.value.elts:
            if isinstance(element, (ast.Constant, ast.JoinedStr)):
                yield skeleton(element)
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "append"
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == "s"
        and node.args
    ):
        yield skeleton(node.args[0])
    if isinstance(node, ast.ListComp) and isinstance(node.elt, (ast.Constant, ast.JoinedStr)):
        yield skeleton(node.elt)


@functools.cache
def library_sources() -> tuple[tuple[str, str, str], ...]:
    """Each module of both libraries the engine can run: its name, logger name and source."""
    return tuple(_read_sources())


def _read_sources() -> Iterator[tuple[str, str, str]]:
    for library in LIBRARIES:
        package = importlib.import_module(library)
        root = Path(str(package.__file__)).parent
        for path in sorted(root.rglob("*.py")):
            relative = path.relative_to(root)
            if _SKIPPED_PARTS.intersection(relative.parts):
                continue
            stem = ".".join(relative.with_suffix("").parts)
            module = library if stem == "__init__" else f"{library}.{stem}"
            source = path.read_text(encoding="utf-8")
            # Most of pydicom logs on the one "pydicom" logger; its pixels package logs by module.
            by_module = library != "pydicom" or "getLogger(__name__)" in source
            yield module, module if by_module else "pydicom", source


def _is_text(node: ast.expr) -> bool:
    if isinstance(node, ast.BinOp):
        return isinstance(node.op, ast.Add)
    return isinstance(node, ast.JoinedStr) or (
        isinstance(node, ast.Constant) and isinstance(node.value, str)
    )


def _assigned_text(tree: ast.AST) -> dict[int, set[str]]:
    """For each variable read inside a function, by node id, the text assigned to that name there,
    so a line logged through ``msg`` is in the census by its words. ``+=`` is marked, since what it
    adds is not a whole line."""
    assigned: dict[int, set[str]] = {}
    for function in ast.walk(tree):
        if not isinstance(function, ast.FunctionDef | ast.AsyncFunctionDef):
            continue
        values: dict[str, set[str]] = {}
        for node in ast.walk(function):
            if (
                isinstance(node, ast.Assign)
                and len(node.targets) == 1
                and isinstance(node.targets[0], ast.Name)
                and _is_text(node.value)
            ):
                values.setdefault(node.targets[0].id, set()).add(skeleton(node.value))
            elif (
                isinstance(node, ast.AugAssign)
                and isinstance(node.target, ast.Name)
                and _is_text(node.value)
            ):
                values.setdefault(node.target.id, set()).add(f"<+= {skeleton(node.value)}>")
        for node in ast.walk(function):
            if isinstance(node, ast.Name) and node.id in values:
                assigned.setdefault(id(node), set()).update(values[node.id])
    return assigned


def rows_in(module: str, logger: str, source: str) -> set[str]:
    """The census rows of one module's source."""
    found: set[str] = set()
    tree = ast.parse(source)
    assigned = _assigned_text(tree)
    for node in ast.walk(tree):
        if module == "pynetdicom._handlers":
            for text in _strings_in(node):
                found.add(_row(logger, "DEBUG", text))
        if isinstance(node, ast.Call) and node.args:
            level = _level(node)
            if level is not None:
                found.add(_row(logger, level, skeleton(node.args[0])))
                for text in assigned.get(id(node.args[0]), ()):
                    found.add(_row(logger, level, text))
    return found


def census() -> list[str]:
    """Every log call of both libraries, as ``<logger> <LEVEL> <message skeleton>``, sorted and
    without repeats, the line breaks in a message escaped. ``pynetdicom._handlers``' dumps are
    included line by line, since it logs each through a variable."""
    found: set[str] = set()
    for module, logger, source in library_sources():
        found |= rows_in(module, logger, source)
    return sorted(found)


def string_fragments() -> set[str]:
    """Every string literal in both libraries, and each literal part of every f-string."""
    fragments: set[str] = set()
    for _module, _logger, source in library_sources():
        for node in ast.walk(ast.parse(source)):
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                fragments.add(node.value)
    return fragments


def _row(logger: str, level: str, text: str) -> str:
    escaped = text.replace("\\", "\\\\").replace("\n", "\\n").replace("\r", "\\r")
    return f"{logger} {level} {escaped}"


def read_pinned() -> list[str]:
    """The census as it was last accepted."""
    return CENSUS_FILE.read_text(encoding="utf-8").splitlines()


def value_free_lines(rows: list[str]) -> frozenset[str]:
    """The census rows with nothing interpolated, as the text a library writes."""
    found = set(_BUILT_LINES)
    for row in rows:
        text = row.split(" ", 2)[2] if row.count(" ") >= 2 else ""
        if "{}" in text or re.search(r"<.*>|%[-0-9]*[sdxXri]", text):
            continue
        found.add(text.replace("\\n", "\n").replace("\\r", "\r").replace("\\\\", "\\"))
    return frozenset(found)


def _write_value_free_lines(rows: list[str]) -> None:
    body = "".join(f"        {text!r},\n" for text in sorted(value_free_lines(rows)))
    source = _LINES_MODULE.read_text(encoding="utf-8")
    written, count = re.subn(
        r"(# BEGIN GENERATED\n).*?( *# END GENERATED)",
        lambda found: found.group(1) + body + found.group(2),
        source,
        flags=re.DOTALL,
    )
    if count != 1:
        raise SystemExit(f"no generated block in {_LINES_MODULE}")
    _LINES_MODULE.write_text(written, encoding="utf-8", newline="\n")


if __name__ == "__main__":
    if sys.argv[1:] != ["--write"]:
        raise SystemExit("usage: python -P tests/_dicom_log_census.py --write")
    rows = census()
    CENSUS_FILE.write_text("\n".join(rows) + "\n", encoding="utf-8", newline="\n")
    _write_value_free_lines(rows)
    print(f"{len(rows)} lines written to {CENSUS_FILE}")
