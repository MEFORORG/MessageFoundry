# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Pin ``docs/DANGEROUS-FUNCTIONALITY.md`` against the code it describes (BACKLOG #1934).

That page is the in-tree highlight for ASVS 15.1.5, and until this file existed nothing read it.
It said fourteen modules used ``ctypes`` while the tree had fifteen, named two that imported none,
and listed a process start in a module whose own docstring says it never runs one (BACKLOG #1933).
The nearest guard, ``tests/test_threat_model_doc_drift.py``, reads the vault-only threat model, so
its page half skips in every engine checkout.

This file derives two inventories from ``messagefoundry/**`` by AST and holds the page to both:

* **Native library calls (section 5).** Every module that imports ``ctypes``, at any depth, must be
  in the section's list, and the list must name nothing else. The counts in the section and in the
  short-version table must match. Every library load must name its library with a literal, which is
  what the section's "never a path from configuration" sentence claims.
* **Process starts (section 4).** Every module that starts a process must have a table row, and each
  row's Form cell must equal the forms the code uses. A form is how the start reaches the OS:
  ``argument list``, ``shell string``, ``ShellExecute``, ``os.startfile``, ``browser`` or
  ``multiprocessing``. So a new ``shell=True`` in a module the page lists as argument-list only
  fails here, not just a new module.

The start detector covers at least the forms in ``_START_FORMS`` and the ``ShellExecute`` and
``CreateProcess`` names. It cannot see a start hidden behind ``getattr`` with a computed name, or one
made inside a third-party library. The review checklist carries that half.

Every detector has a positive control below that must fire, because a scan that finds nothing
anywhere looks the same as a clean tree.
"""

from __future__ import annotations

import ast
import functools
import re
from collections.abc import Mapping
from pathlib import Path

import pytest

from tests.test_threat_model_doc_drift import _ALLOWED_SUBPROCESS_SITES

_ROOT = Path(__file__).resolve().parents[1]
_PKG = _ROOT / "messagefoundry"
_DOC = _ROOT / "docs" / "DANGEROUS-FUNCTIONALITY.md"

_ARGV = "argument list"
_SHELL = "shell string"
_SHELLEXECUTE = "ShellExecute"
_STARTFILE = "os.startfile"
_BROWSER = "browser"
_MULTIPROCESSING = "multiprocessing"
_CREATEPROCESS = "CreateProcess"

#: Every form token the page may use. A token outside this set is a typo or a new form, and both need
#: a decision here rather than a silent pass.
_FORMS = frozenset(
    {_ARGV, _SHELL, _SHELLEXECUTE, _STARTFILE, _BROWSER, _MULTIPROCESSING, _CREATEPROCESS}
)

#: ``subprocess`` entry points. Each is ``argument list`` unless the call passes ``shell=True``.
_SUBPROCESS_FUNCS = frozenset(
    f"subprocess.{name}"
    for name in (
        "run",
        "Popen",
        "call",
        "check_call",
        "check_output",
        "getoutput",
        "getstatusoutput",
    )
)

#: Fully resolved names that start a process, and the form each one is.
_START_FORMS: dict[str, str] = {
    "os.system": _SHELL,
    "os.popen": _SHELL,
    "asyncio.create_subprocess_shell": _SHELL,
    "asyncio.subprocess.create_subprocess_shell": _SHELL,
    "asyncio.create_subprocess_exec": _ARGV,
    "asyncio.subprocess.create_subprocess_exec": _ARGV,
    "os.posix_spawn": _ARGV,
    "os.posix_spawnp": _ARGV,
    "pty.spawn": _ARGV,
    "os.startfile": _STARTFILE,
    "webbrowser.open": _BROWSER,
    "webbrowser.open_new": _BROWSER,
    "webbrowser.open_new_tab": _BROWSER,
    "multiprocessing.Process": _MULTIPROCESSING,
    "multiprocessing.Pool": _MULTIPROCESSING,
    "multiprocessing.get_context": _MULTIPROCESSING,
    "concurrent.futures.ProcessPoolExecutor": _MULTIPROCESSING,
}

#: ``os.execv``, ``os.spawnlp`` and the rest of both families.
_OS_EXEC_RE = re.compile(r"^os\.(?:exec|spawn)[lv]p?e?$")

#: Win32 process starts reached through ``ctypes``, matched on the attribute name alone because the
#: object in front of it (``shell32``, ``ctypes.windll.shell32``) varies.
_WIN32_START_RE = re.compile(
    r"^(?:(?P<se>ShellExecute(?:Ex)?[AW]?)|(?P<cp>CreateProcess(?:AsUser|WithLogon|WithToken)?[AW]?))$"
)

#: ``ctypes`` library loaders. The first argument names the library.
_LIBRARY_LOADERS = frozenset({"CDLL", "WinDLL", "OleDLL", "PyDLL", "LoadLibrary"})


# --- reading the tree ----------------------------------------------------------------------------


@functools.cache
def _package_sources() -> dict[str, str]:
    return {
        path.relative_to(_PKG).as_posix(): path.read_text(encoding="utf-8")
        for path in sorted(_PKG.rglob("*.py"))
    }


def _parse(source: str) -> ast.Module:
    return ast.parse(source)


# The per-module readers below are cached by source text, because every test re-reads the same
# few hundred modules. Each returns an immutable value so a caller cannot change the cache.


@functools.cache
def _imports_ctypes(source: str) -> bool:
    for node in ast.walk(_parse(source)):
        if isinstance(node, ast.Import):
            names = [alias.name for alias in node.names]
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module is not None:
            names = [node.module]
        else:
            continue
        if any(name == "ctypes" or name.startswith("ctypes.") for name in names):
            return True
    return False


def _ctypes_modules(sources: Mapping[str, str]) -> set[str]:
    return {rel for rel, source in sources.items() if _imports_ctypes(source)}


def _aliases(tree: ast.Module) -> dict[str, str]:
    """Local name to the dotted name it stands for, from every import in the module."""
    names: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.asname is not None:
                    names[alias.asname] = alias.name
                else:
                    root = alias.name.split(".", 1)[0]
                    names.setdefault(root, root)
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module is not None:
            for alias in node.names:
                names[alias.asname or alias.name] = f"{node.module}.{alias.name}"
    return names


def _dotted(node: ast.expr, aliases: Mapping[str, str]) -> str | None:
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if not isinstance(node, ast.Name) or node.id not in aliases:
        return None
    return ".".join([aliases[node.id], *reversed(parts)])


def _annotation_nodes(tree: ast.Module) -> set[int]:
    """ids of every node inside a type annotation. ``proc: subprocess.Popen[bytes]`` names the class
    without starting anything, so a reference there must not count as a start."""
    roots: list[ast.expr] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.arg) and node.annotation is not None:
            roots.append(node.annotation)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.returns is not None:
            roots.append(node.returns)
        elif isinstance(node, ast.AnnAssign):
            roots.append(node.annotation)
    return {id(inner) for root in roots for inner in ast.walk(root)}


def _passes_shell_true(call: ast.Call) -> bool:
    for keyword in call.keywords:
        if keyword.arg == "shell":
            # A non-literal ``shell=`` could be True at run time, so it counts as a shell.
            return not (isinstance(keyword.value, ast.Constant) and not keyword.value.value)
    return False


@functools.cache
def _start_forms(source: str) -> frozenset[str]:
    """The process-start forms one module uses."""
    tree = _parse(source)
    aliases = _aliases(tree)
    skip = _annotation_nodes(tree)
    forms: set[str] = set()
    handled: set[int] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and _dotted(node.func, aliases) in _SUBPROCESS_FUNCS:
            forms.add(_SHELL if _passes_shell_true(node) else _ARGV)
            handled.add(id(node.func))
    for node in ast.walk(tree):
        if id(node) in skip or id(node) in handled:
            continue
        if isinstance(node, ast.Attribute):
            match = _WIN32_START_RE.match(node.attr)
            if match is not None:
                forms.add(_SHELLEXECUTE if match.group("se") else _CREATEPROCESS)
                continue
        if not isinstance(node, (ast.Attribute, ast.Name)):
            continue
        if not isinstance(node.ctx, ast.Load):
            continue
        dotted = _dotted(node, aliases)
        if dotted is None:
            continue
        if dotted in _SUBPROCESS_FUNCS:
            forms.add(_ARGV)  # passed as a callable, so the call site cannot be read for shell=True
        elif dotted in _START_FORMS:
            forms.add(_START_FORMS[dotted])
        elif _OS_EXEC_RE.match(dotted):
            forms.add(_ARGV)
    return frozenset(forms)


def _start_sites(sources: Mapping[str, str]) -> dict[str, frozenset[str]]:
    sites = {rel: _start_forms(source) for rel, source in sources.items()}
    return {rel: forms for rel, forms in sites.items() if forms}


@functools.cache
def _non_literal_library_loads(source: str) -> tuple[int, ...]:
    """Lines where a ``ctypes`` loader is handed anything but a string literal or ``None``."""
    lines: list[int] = []
    for node in ast.walk(_parse(source)):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        name = (
            func.attr
            if isinstance(func, ast.Attribute)
            else func.id
            if isinstance(func, ast.Name)
            else None
        )
        if name not in _LIBRARY_LOADERS:
            continue
        first = node.args[0] if node.args else None
        if not (
            isinstance(first, ast.Constant)
            and (first.value is None or isinstance(first.value, str))
        ):
            lines.append(node.lineno)
    return tuple(lines)


# --- reading the page ----------------------------------------------------------------------------


def _doc_text() -> str:
    return _DOC.read_text(encoding="utf-8")


def _section(text: str, number: int) -> str:
    match = re.search(rf"^## {number}\. .*?(?=^## |\Z)", text, re.M | re.S)
    assert match is not None, f"section {number} is missing from {_DOC.name}"
    return match.group(0)


def _short_table_count(text: str, number: int) -> int:
    match = re.search(rf"^\| {number} \|[^|]*\| (\d+) modules\b", text, re.M)
    assert match is not None, f"the short-version row {number} does not state '<N> modules'"
    return int(match.group(1))


def _section_count(section: str, lead: str) -> int:
    match = re.search(rf"^(\d+) modules {lead}", section, re.M)
    assert match is not None, f"the section does not open with '<N> modules {lead}'"
    return int(match.group(1))


_TICKED_PY_RE = re.compile(r"`([\w/]+\.py)`")


def _ctypes_listed(text: str) -> set[str]:
    bullets = [line for line in _section(text, 5).splitlines() if line.startswith(("- ", "  "))]
    return set(_TICKED_PY_RE.findall("\n".join(bullets)))


def _start_rows(text: str) -> dict[str, set[str]]:
    rows: dict[str, set[str]] = {}
    for line in _section(text, 4).splitlines():
        cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
        module = re.fullmatch(r"`([\w/]+\.py)`", cells[0]) if line.startswith("|") else None
        if module is None:
            continue
        rows[module.group(1)] = {form.strip() for form in cells[-1].split(",")}
    return rows


def _defined_forms(text: str) -> set[str]:
    return set(re.findall(r"^- \*\*([^*]+)\*\* -- ", _section(text, 4), re.M))


# --- the drift reports, shared by the real tests and their controls ------------------------------


def _ctypes_drift(text: str, live: set[str]) -> list[str]:
    problems: list[str] = []
    listed = _ctypes_listed(text)
    if listed != live:
        problems.append(
            f"section 5 lists {sorted(listed - live)} which import no ctypes, and omits "
            f"{sorted(live - listed)} which do"
        )
    for where, count in (
        ("section 5", _section_count(_section(text, 5), "import `ctypes`")),
        ("the short-version row 5", _short_table_count(text, 5)),
    ):
        if count != len(live):
            problems.append(f"{where} says {count} modules; the code has {len(live)}")
    return problems


def _start_drift(text: str, live: Mapping[str, frozenset[str]]) -> list[str]:
    problems: list[str] = []
    rows = _start_rows(text)
    for module in sorted(set(rows) | set(live)):
        page, code = rows.get(module), live.get(module)
        if page is None:
            problems.append(f"{module} starts a process ({sorted(code or ())}) and has no row")
        elif code is None:
            problems.append(f"{module} has a row but starts no process")
        elif page != code:
            problems.append(f"{module}: the row says {sorted(page)}, the code uses {sorted(code)}")
    unknown = {form for forms in rows.values() for form in forms} - _FORMS
    if unknown:
        problems.append(f"unknown form token(s) in the table: {sorted(unknown)}")
    undefined = {form for forms in rows.values() for form in forms} - _defined_forms(text)
    if undefined:
        problems.append(f"form(s) used in the table but not defined below it: {sorted(undefined)}")
    for where, count in (
        ("section 4", _section_count(_section(text, 4), "start a process")),
        ("the short-version row 4", _short_table_count(text, 4)),
    ):
        if count != len(live):
            problems.append(f"{where} says {count} modules; the code has {len(live)}")
    return problems


# --- the guards ----------------------------------------------------------------------------------


def test_the_ctypes_list_matches_the_code() -> None:
    problems = _ctypes_drift(_doc_text(), _ctypes_modules(_package_sources()))
    assert not problems, (
        "docs/DANGEROUS-FUNCTIONALITY.md section 5 has drifted from the code:\n  "
        + "\n  ".join(problems)
    )


def test_the_process_start_table_matches_the_code() -> None:
    problems = _start_drift(_doc_text(), _start_sites(_package_sources()))
    assert not problems, (
        "docs/DANGEROUS-FUNCTIONALITY.md section 4 has drifted from the code:\n  "
        + "\n  ".join(problems)
    )


def test_every_library_load_names_its_library_with_a_literal() -> None:
    """Section 5 says no library is loaded from a path in configuration. A literal name is the
    mechanical form of that claim."""
    found = {
        rel: lines
        for rel, source in _package_sources().items()
        if (lines := _non_literal_library_loads(source))
    }
    assert not found, f"ctypes library loads with a computed name: {found}"


def test_the_two_process_start_inventories_agree() -> None:
    """``tests/test_threat_model_doc_drift.py`` keeps its own register of process-start modules for
    the vault threat model. Two registers of one fact drift apart unless something compares them."""
    assert set(_start_sites(_package_sources())) == set(_ALLOWED_SUBPROCESS_SITES)


# --- positive controls: each detector must fire ---------------------------------------------------

_CTYPES_CONTROL = '''
"""import ctypes is mentioned here and must not count."""
# from ctypes import wintypes
NOTE = "import ctypes"
'''


def test_the_ctypes_detector_fires_and_ignores_mentions() -> None:
    assert not _imports_ctypes(_CTYPES_CONTROL)
    assert _imports_ctypes("def f():\n    import ctypes\n")
    assert _imports_ctypes("from ctypes import wintypes\n")
    assert _imports_ctypes("import ctypes.wintypes as w\n")
    assert _ctypes_modules(_package_sources()), "no ctypes importer found at all: the scan is dead"


_START_CONTROLS: list[tuple[str, set[str]]] = [
    ("import subprocess\nsubprocess.run(['x'])\n", {_ARGV}),
    ("import subprocess\nsubprocess.run('x', shell=True)\n", {_SHELL}),
    ("import subprocess\nsubprocess.run('x', shell=flag)\n", {_SHELL}),
    ("import subprocess\nsubprocess.run(['x'], shell=False)\n", {_ARGV}),
    ("import subprocess as sp\nsp.Popen(['x'])\n", {_ARGV}),
    ("from subprocess import check_output as co\nco('x', shell=True)\n", {_SHELL}),
    ("import subprocess\ndef f(run=subprocess.run): ...\n", {_ARGV}),
    ("import asyncio\nasync def f():\n    await asyncio.create_subprocess_shell('x')\n", {_SHELL}),
    ("import asyncio\nasync def f():\n    await asyncio.create_subprocess_exec('x')\n", {_ARGV}),
    ("import os\nos.system('x')\n", {_SHELL}),
    ("import os\nos.execvp('x', ['x'])\n", {_ARGV}),
    ("import os\nos.startfile(p)\n", {_STARTFILE}),
    ("import webbrowser\n(opener or webbrowser.open)(url)\n", {_BROWSER}),
    (
        "import ctypes\nctypes.windll.shell32.ShellExecuteW(None, 'runas', f, p, d, 0)\n",
        {_SHELLEXECUTE},
    ),
    ("k.CreateProcessW(None, line)\n", {_CREATEPROCESS}),
    (
        "from concurrent.futures import ProcessPoolExecutor\nProcessPoolExecutor()\n",
        {_MULTIPROCESSING},
    ),
]


@pytest.mark.parametrize(("source", "expected"), _START_CONTROLS)
def test_the_start_detector_fires_on_each_form(source: str, expected: set[str]) -> None:
    assert _start_forms(source) == expected


def test_the_start_detector_ignores_mentions_and_annotations() -> None:
    quiet = (
        "from __future__ import annotations\n"
        "import subprocess\n"
        '"""Runs subprocess.Popen(argv), never os.system or ShellExecuteW."""\n'
        "# os.startfile(path)\n"
        "LINT = ('os.system', 'subprocess.run')\n"
        "def f(proc: subprocess.Popen[bytes]) -> subprocess.CompletedProcess[str]: ...\n"
        "held: subprocess.Popen[bytes] | None = None\n"
        "flags = subprocess.CREATE_NEW_PROCESS_GROUP\n"
    )
    assert _start_forms(quiet) == set()
    assert _start_sites(_package_sources()), "no process start found at all: the scan is dead"


def test_the_library_load_check_fires() -> None:
    assert _non_literal_library_loads("import ctypes\nctypes.WinDLL(path)\n") == (2,)
    assert _non_literal_library_loads("import ctypes\nctypes.cdll.LoadLibrary(name)\n") == (2,)
    assert _non_literal_library_loads("import ctypes\nctypes.WinDLL('kernel32')\n") == ()
    assert _non_literal_library_loads("import ctypes\nctypes.CDLL(None)\n") == ()


def _drop_line(text: str, needle: str) -> str:
    lines = text.splitlines(keepends=True)
    hits = [i for i, line in enumerate(lines) if needle in line]
    assert len(hits) == 1, f"expected one line containing {needle!r}, found {len(hits)}"
    del lines[hits[0]]
    return "".join(lines)


def test_page_drift_is_reported() -> None:
    """Break the real page in memory, one way at a time, and each break must be reported."""
    text = _doc_text()
    ctypes_live = _ctypes_modules(_package_sources())
    starts_live = _start_sites(_package_sources())
    assert not _ctypes_drift(text, ctypes_live) and not _start_drift(text, starts_live)

    assert _ctypes_drift(text.replace("`crashdump.py`", "`crashdumps.py`"), ctypes_live)
    assert _ctypes_drift(text.replace("15 modules import", "14 modules import"), ctypes_live)
    assert _start_drift(_drop_line(text, "| `tray/app.py` |"), starts_live)
    assert _start_drift(text.replace("| shell string |", "| argument list |"), starts_live)
    assert _start_drift(text.replace("| 11 modules |", "| 10 modules |"), starts_live)
    assert _start_drift(_drop_line(text, "- **browser** -- "), starts_live)


def test_code_drift_is_reported() -> None:
    """Change the code in memory, and the unchanged page must be reported as stale."""
    text = _doc_text()
    sources = dict(_package_sources())
    sources["pipeline/new_native.py"] = "import ctypes\n"
    assert _ctypes_drift(text, _ctypes_modules(sources))

    sources = dict(_package_sources())
    sources["tray/branding.py"] += "\nimport os\nos.system('x')\n"
    assert _start_drift(text, _start_sites(sources))
