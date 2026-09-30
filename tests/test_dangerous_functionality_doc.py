# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Pin ``docs/DANGEROUS-FUNCTIONALITY.md`` against the code it describes (BACKLOG #1934).

That page is the in-tree highlight for ASVS 15.1.5, and until this file existed nothing read it.
It said fourteen modules used ``ctypes`` while the tree had fifteen, named two that imported none,
and listed a process start in a module whose own docstring says it never runs one (BACKLOG #1933).
The nearest guard, ``tests/test_threat_model_doc_drift.py``, reads the vault-only threat model, so
its page half skips in every engine checkout.

This file derives two inventories from ``messagefoundry/**`` and ``messagefoundry_toolkit/**`` by
AST and holds the page to both:

* **Native library calls (section 5).** Every module that imports ``ctypes``, at any depth, must be
  in the section's list, and the list must name nothing else. The counts in the section and in the
  short-version table must match. Every library load must name its library with a literal, which is
  what the section's "never a path from configuration" sentence claims, except the reviewed loads
  in ``_REVIEWED_COMPUTED_LOADS``, which the section names.
* **Process starts (section 4).** Every module that starts a process must have a table row, and each
  row's Form cell must equal the forms the code uses. A form is how the call reaches the OS:
  ``argument list``, ``shell string``, ``ShellExecute``, ``os.startfile``, ``browser``,
  ``multiprocessing`` or ``CreateProcess``. So a new ``shell=True`` in a module the page lists as
  argument-list only fails here, not just a new module.

Four more checks hold the page's later lists and counts to the tree (BACKLOG #1190): the section 7
archive readers, the section 8 service-script table, the section 9 extension counts over ``ide/src``,
and the section 10 count of HTML writes in the web console's scripts, plus the claim that
the console's Python holds none of the engine's classes. The TypeScript and JavaScript checks read
by pattern, not by parser, and skip whole-line comments only.

Section 7's parser tables are held to a scan too (BACKLOG #1190): every parse site the six patterns
the page names find, over the engine, the toolkit and the web console's Python, must sit in exactly
one of the first two tables, and neither may name a site the scan does not find. The third table
names parsers found by reading the code; each must exist and must not be a site the scan finds, and
nothing here says it is complete. The VS Code extension's TypeScript under ``ide/src`` has a
four-pattern scan and three tables of its own, held the same way. The patterns the page states must
be the ones each detector uses. Which table a site belongs in is a judgement about where its input
comes from, and no check here reads that.
Section 9's claim about which extension file builds markup with ``innerHTML`` is pinned to a file
that exists and does.

The start detector covers at least the names in ``_SUBPROCESS_FUNCS``, ``_START_FORMS``,
``_OS_EXEC_RE`` and ``_ATTRIBUTE_STARTS``. Its known limits: it cannot see a start hidden behind
``getattr`` with a computed name, or one made inside a third-party library; it takes a ``subprocess``
function passed as a value, rather than called, as an argument list; and the form names the call,
not what the OS does next, so an argument-list start of a ``.cmd`` file, which Windows hands to
``cmd.exe``, is still ``argument list`` here and needs the page's prose to say so. The review
checklist carries what a scan cannot.

Every detector has a positive control below that must fire, because a scan that finds nothing
anywhere looks the same as a clean tree.
"""

from __future__ import annotations

import ast
import functools
import re
from collections.abc import Callable, Mapping
from pathlib import Path

import pytest

from messagefoundry.redaction import json_loads_or_refusal
from tests.test_threat_model_doc_drift import _ALLOWED_SUBPROCESS_SITES

_ROOT = Path(__file__).resolve().parents[1]
_PKG = _ROOT / "messagefoundry"
_TOOLKIT = _ROOT / "messagefoundry_toolkit"
_TOOLKIT_PREFIX = "messagefoundry_toolkit/"
_DOC = _ROOT / "docs" / "DANGEROUS-FUNCTIONALITY.md"

_ARGV = "argument list"
_SHELL = "shell string"
_SHELLEXECUTE = "ShellExecute"
_STARTFILE = "os.startfile"
_BROWSER = "browser"
_MULTIPROCESSING = "multiprocessing"
_CREATEPROCESS = "CreateProcess"

#: ``subprocess`` entry points that take ``shell=``. Each is ``argument list`` unless the call
#: passes ``shell=True``, a ``shell=`` that is not a literal, or ``**kwargs`` that could carry one.
_SUBPROCESS_FUNCS = frozenset(
    f"subprocess.{name}" for name in ("run", "Popen", "call", "check_call", "check_output")
)

#: Fully resolved names that start a process, and the form each one is.
_START_FORMS: dict[str, str] = {
    "os.system": _SHELL,
    "os.popen": _SHELL,
    "subprocess.getoutput": _SHELL,
    "subprocess.getstatusoutput": _SHELL,
    "os.posix_spawn": _ARGV,
    "os.posix_spawnp": _ARGV,
    "pty.spawn": _ARGV,
    "os.startfile": _STARTFILE,
    "webbrowser.open": _BROWSER,
    "webbrowser.open_new": _BROWSER,
    "webbrowser.open_new_tab": _BROWSER,
    "webbrowser.get": _BROWSER,
    "multiprocessing.Process": _MULTIPROCESSING,
    "multiprocessing.Pool": _MULTIPROCESSING,
    "multiprocessing.pool.Pool": _MULTIPROCESSING,
    "multiprocessing.get_context": _MULTIPROCESSING,
    "concurrent.futures.ProcessPoolExecutor": _MULTIPROCESSING,
}

#: ``os.execv``, ``os.spawnlp`` and the rest of both families.
_OS_EXEC_RE = re.compile(r"^os\.(?:exec|spawn)[lv]p?e?$")

#: Starts matched on the attribute name alone, because the object in front of it varies: an event
#: loop (``loop.subprocess_shell``), ``asyncio`` or ``asyncio.subprocess``, or a ``ctypes`` handle
#: such as ``shell32`` or ``ctypes.windll.shell32``.
_ATTRIBUTE_STARTS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"^(?:create_)?subprocess_shell$"), _SHELL),
    (re.compile(r"^(?:create_)?subprocess_exec$"), _ARGV),
    (re.compile(r"^ShellExecute(?:Ex)?[AW]?$"), _SHELLEXECUTE),
    (
        re.compile(r"^(?:CreateProcess(?:AsUser|WithLogon|WithToken)?[AW]?|WinExec)$"),
        _CREATEPROCESS,
    ),
)

#: ``ctypes`` library loaders. The first argument names the library.
_LIBRARY_LOADER_RE = re.compile(r"^(?:CDLL|WinDLL|OleDLL|PyDLL|LoadLibrary(?:Ex)?[AW]?)$")

#: Reviewed library loads whose name is computed, by module, each as ``Loader(<first argument>)``.
#: Section 5's "What holds them" paragraph names each module.
_REVIEWED_COMPUTED_LOADS: dict[str, tuple[str, ...]] = {
    # ``_existing_version_langs`` opens the tray's own launcher with ``LoadLibraryExW`` and the
    # data-file flags, to read its version resource. Loaded as data, none of its code runs.
    "tray/branding.py": ("LoadLibraryExW(str(exe))",),
}


# --- reading the tree ----------------------------------------------------------------------------


def _python_under(root: Path, prefix: str = "") -> dict[str, str]:
    return {
        f"{prefix}{path.relative_to(root).as_posix()}": path.read_text(encoding="utf-8")
        for path in sorted(root.rglob("*.py"))
    }


@functools.cache
def _engine_sources() -> dict[str, str]:
    """The engine's modules alone, for the threat-model register, which reads only the engine."""
    return _python_under(_PKG)


@functools.cache
def _package_sources() -> dict[str, str]:
    """The engine's modules, and the toolkit's under its package name, as the page names them.

    ADR 0201 moved the authoring commands out of ``messagefoundry/`` into ``messagefoundry_toolkit/``,
    which ships as its own distribution. A module that moves must not leave the scans, so every
    inventory here reads both roots (BACKLOG #1190). Engine keys carry no prefix, so the toolkit's
    ``__main__.py`` cannot collide with the engine's."""
    return {**_engine_sources(), **_python_under(_TOOLKIT, _TOOLKIT_PREFIX)}


def _parse(source: str) -> ast.Module:
    return ast.parse(source)


# The per-module readers below are cached by source text, because every test re-reads the same
# few hundred modules. Each returns an immutable value so a caller cannot change the cache.


@functools.cache
def _imports_any(source: str, libs: tuple[str, ...], attr: str | None = None) -> bool:
    """Whether a module imports one of ``libs`` or a submodule of one, at any depth, or reads an
    attribute named ``attr``. A source that never spells any of those names is not parsed."""
    if not any(name in source for name in (*libs, *(() if attr is None else (attr,)))):
        return False
    return _tree_imports_any(_parse(source), libs, attr)


def _tree_imports_any(tree: ast.Module, libs: tuple[str, ...], attr: str | None = None) -> bool:
    """:func:`_imports_any` over a tree already parsed, for a caller that walks it again."""
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names = [alias.name for alias in node.names]
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module is not None:
            if attr is not None and any(alias.name == attr for alias in node.names):
                return True
            # ``from email import parser`` imports ``email.parser``, so a dotted lib must see it.
            names = [node.module, *(f"{node.module}.{alias.name}" for alias in node.names)]
        elif attr is not None and isinstance(node, ast.Attribute) and node.attr == attr:
            return True
        else:
            continue
        if any(name == lib or name.startswith(f"{lib}.") for name in names for lib in libs):
            return True
    return False


def _imports_ctypes(source: str) -> bool:
    return _imports_any(source, ("ctypes",))


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
    """Whether the call may run through a shell. A non-literal ``shell=``, or ``**kwargs`` that could
    carry one, counts as a shell: the page must then say why it is not, rather than the guard
    assuming it."""
    for keyword in call.keywords:
        if keyword.arg == "shell":
            return not (isinstance(keyword.value, ast.Constant) and not keyword.value.value)
    return any(keyword.arg is None for keyword in call.keywords)


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
        if not isinstance(node, (ast.Attribute, ast.Name)) or not isinstance(node.ctx, ast.Load):
            continue
        dotted = _dotted(node, aliases)
        # The last name part, whether written as an attribute or imported bare with ``from``.
        last = node.attr if isinstance(node, ast.Attribute) else (dotted or "").rpartition(".")[2]
        by_name = [form for pattern, form in _ATTRIBUTE_STARTS if last and pattern.match(last)]
        if by_name:
            forms.update(by_name)
        elif dotted is None:
            continue
        elif dotted in _SUBPROCESS_FUNCS:
            # Passed as a value, not called here, so no call site can be read for ``shell=``. It is
            # taken as an argument list; the module docstring names this limit.
            forms.add(_ARGV)
        elif dotted in _START_FORMS:
            forms.add(_START_FORMS[dotted])
        elif _OS_EXEC_RE.match(dotted):
            forms.add(_ARGV)
    return frozenset(forms)


def _start_sites(sources: Mapping[str, str]) -> dict[str, frozenset[str]]:
    sites = {rel: _start_forms(source) for rel, source in sources.items()}
    return {rel: forms for rel, forms in sites.items() if forms}


@functools.cache
def _non_literal_library_loads(source: str) -> tuple[str, ...]:
    """Each ``ctypes`` load handed anything but a string literal or ``None``, as
    ``Loader(<first argument source>)``, so swapping one computed load for another is visible."""
    loads: list[str] = []
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
        if name is None or not _LIBRARY_LOADER_RE.match(name):
            continue
        first = node.args[0] if node.args else None
        if not (
            isinstance(first, ast.Constant)
            and (first.value is None or isinstance(first.value, str))
        ):
            loads.append(f"{name}({'' if first is None else ast.unparse(first)})")
    return tuple(loads)


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


def _computed_loads(sources: Mapping[str, str]) -> dict[str, tuple[str, ...]]:
    return {
        rel: loads
        for rel, source in sources.items()
        if (loads := _non_literal_library_loads(source))
    }


def _unnamed_computed_loads(text: str) -> list[str]:
    """Registered modules the section 5 "What holds them" paragraph does not name. Only that
    paragraph counts: every such module is also in the bullet list, so the whole section would
    always pass."""
    holds = _section(text, 5).partition("**What holds them.**")[2]
    return sorted(rel for rel in _REVIEWED_COMPUTED_LOADS if f"`{rel}`" not in holds)


def test_every_library_load_names_its_library_with_a_literal() -> None:
    """Section 5 says no library is loaded from a path in configuration. A literal name is the
    mechanical form of that claim, and each reviewed exception is registered and named on the page."""
    found = _computed_loads(_package_sources())
    assert found == _REVIEWED_COMPUTED_LOADS, (
        f"ctypes library loads with a computed name changed: {found}. Review each new one, register "
        "it in _REVIEWED_COMPUTED_LOADS and name it in docs/DANGEROUS-FUNCTIONALITY.md section 5."
    )
    unnamed = _unnamed_computed_loads(_doc_text())
    assert not unnamed, f"reviewed computed loads not named under 'What holds them': {unnamed}"


def _register_gap(live: Mapping[str, object], register: Mapping[str, object]) -> set[str]:
    return set(live) ^ set(register)


def test_the_two_process_start_inventories_agree() -> None:
    """``tests/test_threat_model_doc_drift.py`` keeps its own register of process-start modules for
    the vault threat model. Two registers of one fact drift apart unless something compares them."""
    gap = _register_gap(_start_sites(_engine_sources()), _ALLOWED_SUBPROCESS_SITES)
    assert not gap, f"the two process-start inventories disagree on {sorted(gap)}"


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
    ("k.WinExec(line, 0)\n", {_CREATEPROCESS}),
    (
        "from concurrent.futures import ProcessPoolExecutor\nProcessPoolExecutor()\n",
        {_MULTIPROCESSING},
    ),
    ("import subprocess\nsubprocess.getoutput('x')\n", {_SHELL}),
    ("import subprocess\nsubprocess.run(['x'], **opts)\n", {_SHELL}),
    ("import subprocess\nsubprocess.run(['x'], **opts, shell=False)\n", {_ARGV}),
    ("async def f(loop):\n    await loop.subprocess_shell(factory, 'x')\n", {_SHELL}),
    ("async def f(loop):\n    await loop.subprocess_exec(factory, 'x')\n", {_ARGV}),
    ("from asyncio import create_subprocess_shell as css\ncss('x')\n", {_SHELL}),
    ("import webbrowser\nwebbrowser.get('firefox').open(url)\n", {_BROWSER}),
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
    assert _non_literal_library_loads("import ctypes\nctypes.WinDLL(path)\n") == ("WinDLL(path)",)
    assert _non_literal_library_loads("ctypes.cdll.LoadLibrary(name)\n") == ("LoadLibrary(name)",)
    assert _non_literal_library_loads("import ctypes\nctypes.WinDLL('kernel32')\n") == ()
    assert _non_literal_library_loads("import ctypes\nctypes.CDLL(None)\n") == ()
    assert _non_literal_library_loads("k.LoadLibraryExW(str(exe), None, 2)\n") == (
        "LoadLibraryExW(str(exe))",
    )
    grown = dict(_package_sources())
    grown["tray/branding.py"] += "\nk.LoadLibraryW(path)\n"
    assert _computed_loads(grown) != _REVIEWED_COMPUTED_LOADS
    # One reviewed load swapped for a different one keeps the count, and must still be caught.
    swapped = dict(_package_sources())
    reviewed = "kernel32.LoadLibraryExW(str(exe), None, load_as_data)"
    assert swapped["tray/branding.py"].count(reviewed) == 1, "fixture drifted from tray/branding.py"
    swapped["tray/branding.py"] = swapped["tray/branding.py"].replace(
        reviewed, "kernel32.LoadLibraryW(cfg_path)"
    )
    assert _computed_loads(swapped) != _REVIEWED_COMPUTED_LOADS


def test_the_computed_load_naming_check_fires() -> None:
    text = _doc_text()
    assert not _unnamed_computed_loads(text)
    needle = "`tray/branding.py` opens the tray's own"
    assert text.count(needle) == 1, "fixture drifted from the page"
    assert _unnamed_computed_loads(text.replace(needle, "the tray opens its own")) == [
        "tray/branding.py"
    ]


def test_the_register_comparison_fires() -> None:
    live = _start_sites(_engine_sources())
    short = {rel: why for rel, why in _ALLOWED_SUBPROCESS_SITES.items() if rel != "tray/app.py"}
    assert _register_gap(live, short) == {"tray/app.py"}


def _drop_line(text: str, needle: str) -> str:
    lines = text.splitlines(keepends=True)
    hits = [i for i, line in enumerate(lines) if needle in line]
    assert len(hits) == 1, f"expected one line containing {needle!r}, found {len(hits)}"
    del lines[hits[0]]
    return "".join(lines)


def _replace_once(text: str, old: str, new: str) -> str:
    """Replace ``old``, asserting it is present, so a break that no longer applies fails loudly.

    A bare ``str.replace`` that finds nothing returns the page unchanged, and the control then
    fails on a correct page for a reason that reads like a guard defect.
    """
    assert text.count(old) == 1, f"expected {old!r} exactly once, found {text.count(old)}"
    return text.replace(old, new)


def test_page_drift_is_reported() -> None:
    """Break the real page in memory, one way at a time, and each break must be reported."""
    text = _doc_text()
    ctypes_live = _ctypes_modules(_package_sources())
    starts_live = _start_sites(_package_sources())
    assert not _ctypes_drift(text, ctypes_live) and not _start_drift(text, starts_live)
    # The counts come from the code, so a correct count change on the page does not turn these
    # breaks into no-ops that then fail for the wrong reason.
    n_ctypes, n_starts = len(ctypes_live), len(starts_live)

    assert _ctypes_drift(_replace_once(text, "`crashdump.py`", "`crashdumps.py`"), ctypes_live)
    assert _ctypes_drift(
        _replace_once(text, f"{n_ctypes} modules import", f"{n_ctypes - 1} modules import"),
        ctypes_live,
    )
    assert _ctypes_drift(
        _replace_once(text, f"| {n_ctypes} modules,", f"| {n_ctypes - 1} modules,"), ctypes_live
    )
    assert _start_drift(_drop_line(text, "| `tray/app.py` |"), starts_live)
    assert _start_drift(_replace_once(text, "| shell string |", "| argument list |"), starts_live)
    assert _start_drift(
        _replace_once(text, f"| {n_starts} modules |", f"| {n_starts - 1} modules |"), starts_live
    )
    assert _start_drift(
        _replace_once(text, f"{n_starts} modules start", f"{n_starts - 1} modules start"),
        starts_live,
    )
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


def test_the_scans_read_the_toolkit() -> None:
    """The toolkit holds no site today, so a scan that skipped it would pass the same way. It must be
    read, keyed by its package name, and a site planted in it must reach at least the five checks
    below. The real tests hold each unplanted map to the page, so only the plant is checked here."""
    analyzer = f"{_TOOLKIT_PREFIX}adr_analyze.py"
    assert analyzer in _package_sources(), "the toolkit is not scanned"
    scan = _parser_scan_sources()
    assert analyzer in scan, "the parser scan does not read the toolkit"
    assert _unit_exists(analyzer)
    text = _doc_text()
    new_tool = f"{_TOOLKIT_PREFIX}new_tool.py"
    source = (
        "import ctypes, subprocess, tarfile, json\n"
        "ctypes.CDLL(cfg_path)\nsubprocess.run(['x'])\njson.loads(b)\n"
    )
    # Each plant goes into a copy of the map its real test reads, never into the cached map itself.
    planted = {**_package_sources(), new_tool: source}
    assert _ctypes_drift(text, _ctypes_modules(planted))
    assert _start_drift(text, _start_sites(planted))
    assert _computed_loads(planted) != _REVIEWED_COMPUTED_LOADS
    assert _archive_drift(text, _archive_modules(planted))
    assert _parser_drift(text, _parse_sites({**scan, new_tool: source}))


# --- sections 7 to 10: archives, service scripts, the extension, the web console (BACKLOG #1190) ---

_SERVICE_DIR = _ROOT / "scripts" / "service"
_IDE_SRC = _ROOT / "ide" / "src"
_CONSOLE = _ROOT / "messagefoundry_webconsole"

#: Standard-library modules that read or write an archive or a compressed stream. ``compression`` is
#: the 3.14 package that holds ``compression.zstd``.
_ARCHIVE_LIBS = ("tarfile", "zipfile", "gzip", "zlib", "bz2", "lzma", "compression")

_ARCHIVES_LEAD = "**Archives and compressed streams are parsed too.**"


def _imports_archive_lib(source: str) -> bool:
    """Whether a module imports an archive or compression library, or calls ``unpack_archive``."""
    return _imports_any(source, _ARCHIVE_LIBS, "unpack_archive")


def _archive_modules(sources: Mapping[str, str]) -> set[str]:
    return {rel for rel, source in sources.items() if _imports_archive_lib(source)}


def _set_drift(where: str, page: set[str], live: set[str]) -> list[str]:
    if page == live:
        return []
    return [
        f"{where} names {sorted(page - live)}, which the tree lacks, and omits {sorted(live - page)}"
    ]


def _archives_listed(text: str) -> set[str]:
    """The module each bullet under the section 7 archives paragraph opens with."""
    region = _section(text, 7).partition(_ARCHIVES_LEAD)[2]
    assert region, f"section 7 has no {_ARCHIVES_LEAD!r} paragraph"
    return {
        first.group(1)
        for line in region.splitlines()
        if line.startswith("- ") and (first := _TICKED_PY_RE.search(line))
    }


def _archive_drift(text: str, live: set[str]) -> list[str]:
    return _set_drift("section 7's archive list", _archives_listed(text), live)


def _service_scripts() -> set[str]:
    return {path.name for path in _SERVICE_DIR.glob("*.ps1")}


def _service_rows(text: str) -> set[str]:
    """The script each section 8 table row names in its first cell."""
    return set(re.findall(r"^\|\s*`([\w.-]+\.ps1)`\s*\|", _section(text, 8), re.M))


_ADMIN_CHECK_RE = re.compile(
    r"\.IsInRole\(\s*\[Security\.Principal\.WindowsBuiltInRole\]::Administrator\s*\)"
)


def _unchecked_scripts(scripts: Mapping[str, str]) -> list[str]:
    """Section 8 says every script stops at once without administrator rights."""
    return [
        f"{name} has no administrator check"
        for name, source in sorted(scripts.items())
        if not _ADMIN_CHECK_RE.search(source)
    ]


def _service_sources() -> dict[str, str]:
    return {path.name: path.read_text(encoding="utf-8") for path in _SERVICE_DIR.glob("*.ps1")}


def _service_drift(text: str, live: set[str]) -> list[str]:
    return _set_drift("section 8's table", _service_rows(text), live)


def _script_code_lines(source: str) -> list[str]:
    """Lines of a TypeScript or JavaScript file that are not whole-line comments, by the rule
    ``_is_comment_only`` in ``scripts/security/crypto_inventory_check.py`` uses. A trailing comment
    stays on its line, so a call named inside one counts, and so does a line inside a block comment
    that does not start with ``*``. The page says so. Code after a closing ``*/`` on a comment line
    is kept, so ``/* reviewed */ execFile(...)`` still counts."""
    kept: list[str] = []
    for line in source.splitlines():
        stripped = line.lstrip()
        if stripped.startswith("//"):
            continue
        if stripped.startswith(("*", "/*")):
            line = line.partition("*/")[2]
        kept.append(line)
    return kept


@functools.cache
def _ide_sources() -> dict[str, str]:
    """``ide/src`` TypeScript, without its ``test`` folder."""
    return {
        path.relative_to(_IDE_SRC).as_posix(): path.read_text(encoding="utf-8")
        for path in sorted(_IDE_SRC.rglob("*.ts"))
        if path.relative_to(_IDE_SRC).parts[0] != "test" and not path.name.endswith(".test.ts")
    }


#: Section 9's table rows, keyed by the Call cell, and the pattern that counts that call.
_IDE_CALLS: dict[str, re.Pattern[str]] = {
    "execFile": re.compile(r"\bexecFile\("),
    "createTerminal": re.compile(r"\.createTerminal\("),
    "sendText": re.compile(r"\.sendText\("),
    "startDebugging": re.compile(r"\.startDebugging\("),
    "openExternal": re.compile(r"\.openExternal\("),
    "enableScripts: true": re.compile(r"\benableScripts:\s*true\b"),
}


@functools.cache
def _ide_file_counts(source: str) -> tuple[int, ...]:
    """How many times one file makes each ``_IDE_CALLS`` call, in that order."""
    lines = _script_code_lines(source)
    return tuple(
        sum(len(pattern.findall(line)) for line in lines) for pattern in _IDE_CALLS.values()
    )


def _ide_counts(sources: Mapping[str, str]) -> dict[str, tuple[int, int]]:
    """For each call, how many sites and how many files."""
    per_file = [_ide_file_counts(source) for source in sources.values()]
    return {
        call: (sum(n[i] for n in per_file), sum(1 for n in per_file if n[i]))
        for i, call in enumerate(_IDE_CALLS)
    }


def _ide_rows(text: str) -> dict[str, tuple[int, int]]:
    found = re.findall(
        r"^\|[^|]*\|\s*`([^`]+)`\s*\|\s*(\d+)\s*\|\s*(\d+)\s*\|\s*$", _section(text, 9), re.M
    )
    return {call: (int(sites), int(files)) for call, sites, files in found}


def _ide_drift(text: str, live: Mapping[str, tuple[int, int]]) -> list[str]:
    rows = _ide_rows(text)
    return [
        f"section 9 says `{call}` is at {rows.get(call)} (sites, files); the code has {live[call]}"
        for call in sorted(live)
        if rows.get(call) != live[call]
    ]


_CHILD_PROCESS_IMPORT_RE = re.compile(
    r"""^\s*import\s*\{([^}]*)\}\s*from\s*["'](?:node:)?child_process["'];?\s*$"""
)


#: Other ways to start or load code that section 9 has no row for: VS Code tasks, Node's
#: ``cluster`` and ``worker_threads``, and ``process.dlopen``. Any use must fail until it gets one.
_UNLISTED_START_RE = re.compile(
    r"\b(?:ShellExecution|ProcessExecution|executeTask|worker_threads)\b"
    r"""|["'](?:node:)?cluster["']|\bprocess\.dlopen\("""
)


def _other_start_problems(sources: Mapping[str, str]) -> list[str]:
    """Starts section 9's table has no row for. Every code line naming ``child_process`` must be a
    named import of ``execFile`` alone, so a ``spawn``, an ``exec``, a namespace import or a
    ``require`` fails here; so does anything ``_UNLISTED_START_RE`` matches."""
    problems: list[str] = []
    for rel, source in sources.items():
        for line in _script_code_lines(source):
            if "child_process" in line:
                match = _CHILD_PROCESS_IMPORT_RE.match(line)
                names = {name.strip() for name in match.group(1).split(",")} if match else set()
                if names != {"execFile"}:
                    problems.append(f"{rel}: {line.strip()}")
            if _UNLISTED_START_RE.search(line):
                problems.append(f"{rel}: {line.strip()}")
    return problems


@functools.cache
def _console_scripts() -> dict[str, str]:
    return {
        path.name: path.read_text(encoding="utf-8")
        for path in sorted((_CONSOLE / "static").glob("*.js"))
    }


@functools.cache
def _console_python() -> dict[str, str]:
    return _python_under(_CONSOLE)


#: Ways to turn an HTML string into page content, at least: assignment (plain, ``+=`` or logical) to
#: ``innerHTML`` or ``outerHTML`` by dot or by bracket, ``insertAdjacentHTML``, ``document.write``,
#: ``DOMParser.parseFromString``, ``createContextualFragment``, ``srcdoc`` and ``setHTML``.
_HTML_SINK_RE = re.compile(
    r"""(?:\.|\[\s*["'])(?:inner|outer)HTML(?:["']\s*\])?\s*(?:\+|\|\||&&|\?\?)?=(?!=)"""
    r"|\.insertAdjacentHTML\(|\bdocument\.write(?:ln)?\(|\.parseFromString\("
    r"|\.createContextualFragment\(|\.srcdoc\s*=(?!=)|\.setHTML(?:Unsafe)?\("
)


def _console_sink_count(scripts: Mapping[str, str]) -> int:
    return sum(
        len(_HTML_SINK_RE.findall(line))
        for source in scripts.values()
        for line in _script_code_lines(source)
    )


def _console_drift(text: str, live: int) -> list[str]:
    match = re.search(r"writes HTML\s+into the page in (\d+) places", _section(text, 10))
    assert match is not None, "section 10 does not state 'writes HTML into the page in <N> places'"
    page = int(match.group(1))
    return [] if page == live else [f"section 10 says {page} HTML writes; the code has {live}"]


#: Calls that import or run a module named at run time.
_DYNAMIC_IMPORTS = frozenset(
    {"import_module", "__import__", "exec_module", "spec_from_file_location"}
)


def _called_name(call: ast.Call) -> str | None:
    if isinstance(call.func, ast.Attribute):
        return call.func.attr
    return call.func.id if isinstance(call.func, ast.Name) else None


def _console_python_problems(sources: Mapping[str, str]) -> list[str]:
    """Section 10 says the console's Python makes no process start, native call, archive read or
    import by name. The first three reuse the engine inventories above. Its inline scripts live in
    Python strings, so an HTML write in any non-comment line is reported too: section 10's count
    covers only ``static/``."""
    problems = [
        f"{rel}:{number} writes HTML into the page"
        for rel, source in sorted(sources.items())
        for number, line in enumerate(source.splitlines(), start=1)
        if not line.lstrip().startswith("#") and _HTML_SINK_RE.search(line)
    ]
    problems += [f"{rel} imports ctypes" for rel in sorted(_ctypes_modules(sources))]
    problems += [f"{rel} starts a process" for rel in sorted(_start_sites(sources))]
    problems += [f"{rel} reads an archive" for rel in sorted(_archive_modules(sources))]
    for rel, source in sorted(sources.items()):
        if not any(name in source for name in _DYNAMIC_IMPORTS):
            continue
        problems += [
            f"{rel} imports by name ({_called_name(node)})"
            for node in ast.walk(_parse(source))
            if isinstance(node, ast.Call) and _called_name(node) in _DYNAMIC_IMPORTS
        ]
    return problems


def _assert_no_drift(section: int, problems: list[str]) -> None:
    assert not problems, f"docs/DANGEROUS-FUNCTIONALITY.md section {section} has drifted:\n  " + (
        "\n  ".join(problems)
    )


def test_the_archive_readers_match_the_code() -> None:
    _assert_no_drift(7, _archive_drift(_doc_text(), _archive_modules(_package_sources())))


def test_every_service_script_has_a_row() -> None:
    problems = _service_drift(_doc_text(), _service_scripts())
    _assert_no_drift(8, problems + _unchecked_scripts(_service_sources()))


def test_the_extension_counts_match_the_code() -> None:
    problems = _ide_drift(_doc_text(), _ide_counts(_ide_sources()))
    _assert_no_drift(9, problems + _other_start_problems(_ide_sources()))


def test_the_console_matches_the_code() -> None:
    problems = _console_drift(_doc_text(), _console_sink_count(_console_scripts()))
    _assert_no_drift(10, problems + _console_python_problems(_console_python()))


def test_the_later_section_detectors_fire() -> None:
    """Each scan must find something on the real tree, and must see a planted site."""
    assert _imports_archive_lib("import tarfile\n")
    assert _imports_archive_lib("from compression import zstd\n")
    assert _imports_archive_lib("import shutil\nshutil.unpack_archive(p, d)\n")
    assert _imports_archive_lib("from shutil import unpack_archive\nunpack_archive(p, d)\n")
    assert not _imports_archive_lib('"""import tarfile"""\nNOTE = "zipfile"\n')
    assert "install-service.ps1" in _service_scripts()
    elevated = "if (-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {}"
    assert not _unchecked_scripts({"a.ps1": elevated})
    assert _unchecked_scripts({"a.ps1": "# needs IsInRole Administrator\n"})
    assert _script_code_lines("/* reviewed */ execFile(bin, args)\n") == [" execFile(bin, args)"]
    live = _ide_counts(_ide_sources())
    assert all(sites and files for sites, files in live.values()), (
        f"an IDE scan found nothing: {live}"
    )
    quiet = (
        "// vscode.window.createTerminal(x)\n * execFile(a, b)\nconst s = 'enableScripts: false';\n"
    )
    assert _ide_counts({"a.ts": quiet}) == dict.fromkeys(_IDE_CALLS, (0, 0))
    assert _console_sink_count(_console_scripts()), "no HTML write found: the scan is dead"
    assert _console_sink_count({"a.js": "// el.innerHTML = x\nif (el.innerHTML == y) {}\n"}) == 0
    for sink in (
        "el.innerHTML = x; // server-built",
        "el.innerHTML += x;",
        "el.outerHTML = x;",
        "el.insertAdjacentHTML('beforeend', x);",
        "document.write(x);",
        "el['innerHTML'] = x;",
        "el.innerHTML ||= x;",
        "new DOMParser().parseFromString(x, 'text/html');",
        "range.createContextualFragment(x);",
        "frame.srcdoc = x;",
        "el.setHTMLUnsafe(x);",
    ):
        assert _console_sink_count({"a.js": sink}) == 1, sink
    assert not _other_start_problems({"a.ts": 'import { execFile } from "node:child_process";'})
    for planted in (
        'import { spawn } from "node:child_process";',
        'import { execFile, exec } from "child_process";',
        'import * as cp from "node:child_process";',
        'const cp = require("child_process");',
        "await vscode.tasks.executeTask(task);",
        "const run = new vscode.ShellExecution(cmd);",
        'import cluster from "node:cluster";',
        'import { Worker } from "worker_threads";',
        "process.dlopen(module, path);",
    ):
        assert _other_start_problems({"a.ts": planted}), planted
    assert _console_python(), "no console Python found: the scan is dead"
    assert not _console_python_problems({"a.py": '"""subprocess.run, import ctypes"""\n'})
    for planted in (
        "import ctypes\n",
        "import subprocess\nsubprocess.run(['x'])\n",
        "import zipfile\n",
        "import importlib\nimportlib.import_module(name)\n",
        "__import__(name)\n",
        "JS = 'el.innerHTML = x;'\n",
    ):
        assert _console_python_problems({"a.py": planted}), planted


def test_later_section_drift_is_reported() -> None:
    """Break the page and the tree in memory, one way at a time, and each break must be reported."""
    text = _doc_text()
    archives = _archive_modules(_package_sources())
    scripts = _service_scripts()
    ide = _ide_counts(_ide_sources())
    sinks = _console_sink_count(_console_scripts())
    assert not (
        _archive_drift(text, archives)
        or _service_drift(text, scripts)
        or _ide_drift(text, ide)
        or _console_drift(text, sinks)
    )

    assert _archive_drift(_drop_line(text, "- `support/bundle.py` only writes"), archives)
    assert _archive_drift(text, archives | {"pipeline/new_restore.py"})

    assert _service_drift(_drop_line(text, "| `import-db-ca.ps1` |"), scripts)
    assert _service_drift(text, scripts | {"install-other.ps1"})

    n_sites, n_files = ide["createTerminal"]
    row = f"| `createTerminal` | {n_sites} | {n_files} |"
    assert _ide_drift(
        _replace_once(text, row, f"| `createTerminal` | {n_sites + 1} | {n_files} |"), ide
    )
    grown = dict(_ide_sources())
    grown["newPanel.ts"] = "panel.webview.options = { enableScripts: true };\n"
    assert _ide_drift(text, _ide_counts(grown))

    claim = f"into the page in {sinks} places"
    assert _console_drift(_replace_once(text, claim, f"into the page in {sinks + 1} places"), sinks)
    assert _console_drift(text, sinks + 1)


# --- section 7: the parser tables, and section 9's innerHTML file (BACKLOG #1190) ------------------

#: Pattern 1 on the page: format libraries whose import, at any depth, makes a module a parse site.
_PARSER_LIBS = (
    "hl7",
    "hl7apy",
    "lxml",
    "defusedxml",
    "xml",
    "xmlschema",
    "signxml",
    "pydicom",
    "pynetdicom",
    "pyx12",
    "fhir.resources",
    "fhirpathpy",
    "cbor2",
    "webauthn",
    "spnego",
    "csv",
    "email.parser",
    "email.feedparser",
    "pickle",
    "marshal",
    "shelve",
)

#: Pattern 2: JSON decodes, by resolved name. The engine's helper and a ``.json()`` method are
#: matched by the called name instead, because the object in front of them varies.
_JSON_DECODES = frozenset({"json.loads", "json.load"})
_JSON_HELPER = json_loads_or_refusal.__name__
_JSON_METHOD = "json"

#: Pattern 3: form, header and mail decodes, by the called name.
_FORM_DECODES = frozenset(
    {
        "parse_qs",
        "parse_qsl",
        "parse_http_list",
        "parse_keqv_list",
        "message_from_bytes",
        "message_from_string",
    }
)

#: Pattern 4: a bytes method that tokenizes, when its first argument is a bytes literal, and any
#: ``unpack`` family call. ``startswith`` and ``endswith`` test bytes without splitting them, so they
#: are left out.
_BYTE_TOKENIZERS = frozenset(
    {"split", "rsplit", "partition", "rpartition", "find", "rfind", "index", "rindex"}
)
_UNPACKS = frozenset({"unpack", "unpack_from", "iter_unpack"})

#: Pattern 5: an inbound connector, which reads whatever a sender chooses.
_SOURCE_REGISTRAR = "register_source"

#: Pattern 6: a certificate or key decode. ``cryptography`` names most decoders by encoding, so a
#: name prefix reaches every ``load_pem_*``, ``load_der_*`` and ``load_ssh_*`` loader. Its two
#: PKCS #12 decoders are named by format instead.
_KEY_DECODE_PREFIXES = ("load_pem_", "load_der_", "load_ssh_")
_PKCS12_DECODES = frozenset({"load_key_and_certificates", "load_pkcs12"})

#: Patterns 2, 3, 4, 5 and 6 matched by the called name alone, bare or as an attribute.
_CALLS_BY_NAME = frozenset(
    {_JSON_HELPER, *_FORM_DECODES, *_UNPACKS, _SOURCE_REGISTRAR, *_PKCS12_DECODES}
)

_CONSOLE_PREFIX = "messagefoundry_webconsole/"
_OUTSIDE_HEADER = "| Input | Where it comes from | Modules |"
_LEFT_OUT_HEADER = "| Why it is left out | Modules |"
_BY_HAND_HEADER = "| What it parses | Modules |"
#: Every backticked name in a table's last cell, which holds only file and package names. A name
#: the scan cannot produce, such as a misspelling or a file of another type, is then reported rather
#: than silently read as no name at all.
_UNIT_RE = re.compile(r"`([^`]+)`")


def _is_parse_call(node: ast.Call, aliases: Mapping[str, str]) -> bool:
    """Whether one call matches pattern 2, 3, 4, 5 or 6."""
    name = _called_name(node)
    if name in _CALLS_BY_NAME or _dotted(node.func, aliases) in _JSON_DECODES:
        return True
    if name is not None and name.startswith(_KEY_DECODE_PREFIXES):
        return True
    if not isinstance(node.func, ast.Attribute):
        return False
    if name == _JSON_METHOD:
        return True
    first = node.args[0] if node.args else None
    return (
        name in _BYTE_TOKENIZERS
        and isinstance(first, ast.Constant)
        and isinstance(first.value, bytes)
    )


@functools.cache
def _is_parse_site(source: str) -> bool:
    """Whether a module matches any of the six patterns section 7 names. One parse feeds both the
    import check and the call walk."""
    tree = _parse(source)
    if _tree_imports_any(tree, _PARSER_LIBS):
        return True
    aliases = _aliases(tree)
    return any(
        isinstance(node, ast.Call) and _is_parse_call(node, aliases) for node in ast.walk(tree)
    )


def _parse_unit(rel: str) -> str:
    """A hit inside a codec package under ``parsing/`` counts for the whole package."""
    parts = rel.split("/")
    return f"parsing/{parts[1]}/" if len(parts) > 2 and parts[0] == "parsing" else rel


def _parse_sites(sources: Mapping[str, str]) -> set[str]:
    return {_parse_unit(rel) for rel, source in sources.items() if _is_parse_site(source)}


def _parser_scan_sources() -> dict[str, str]:
    """The engine's and the toolkit's modules, and the web console's under their package name, as
    the page names them."""
    console = {f"{_CONSOLE_PREFIX}{rel}": source for rel, source in _console_python().items()}
    return {**_package_sources(), **console}


def _table_units(section: str, header: str) -> set[str]:
    """Every module, package or file the table under ``header`` names in its last cell."""
    lines = section.splitlines()
    assert header in lines, f"section 7 has no table headed {header!r}"
    units: set[str] = set()
    for line in lines[lines.index(header) + 2 :]:
        if not line.startswith("|"):
            break
        units.update(_UNIT_RE.findall(line.rstrip().rstrip("|").rpartition("|")[2]))
    return units


def _unit_exists(unit: str) -> bool:
    # A prefixed unit names its own top-level package, so it resolves from the repository root.
    prefixed = unit.startswith((_CONSOLE_PREFIX, _TOOLKIT_PREFIX))
    return (_ROOT / unit if prefixed else _PKG / unit).exists()


def _three_table_drift(
    text: str,
    where: str,
    headers: tuple[str, str, str],
    live: set[str],
    unit_of: Callable[[str], str],
    exists: Callable[[str], bool],
) -> list[str]:
    """``headers`` name an outside-input table, a left-out table and a hand-read table. The first
    two together must name exactly the sites the scan finds, and no site may be in both; a site may
    sit in several rows of one table. The third names parsers found by reading the code: each must
    exist, and none may be a site the scan finds, or it belongs in the first two."""
    section = _section(text, 7)
    outside, left_out, by_hand = (_table_units(section, header) for header in headers)
    problems: list[str] = []
    if unfound := sorted((outside | left_out) - live):
        problems.append(
            f"{where} name {unfound}, which the scan does not find; a real parser it cannot see "
            "belongs in their hand-read table"
        )
    if unlisted := sorted(live - outside - left_out):
        problems.append(f"the scan finds {unlisted}, which {where} omit")
    if both := sorted(outside & left_out):
        problems.append(f"{where} name {both} both as outside input and as left out")
    if found := sorted(unit for unit in by_hand if unit_of(unit) in live):
        problems.append(f"{where} list {found} as hand-read, but the scan finds them")
    if missing := sorted(unit for unit in by_hand if not exists(unit)):
        problems.append(f"{where} list {missing} as hand-read, and they do not exist")
    return problems


def _parser_drift(text: str, live: set[str]) -> list[str]:
    return _three_table_drift(
        text,
        "section 7's engine parser tables",
        (_OUTSIDE_HEADER, _LEFT_OUT_HEADER, _BY_HAND_HEADER),
        live,
        _parse_unit,
        _unit_exists,
    )


_PATTERNS_LEAD = "**How the parser list is found.**"
_PATTERNS_END = "A hit inside"
_TS_PATTERNS_LEAD = "**How the extension's parser list is found.**"
_TS_PATTERNS_END = "Every file this scan finds"
_PATTERN_ITEM_RE = re.compile(r"^(\d+)\. ")


def _page_patterns(
    text: str, lead: str = _PATTERNS_LEAD, end: str = _PATTERNS_END
) -> list[set[str]]:
    """The backticked names in each numbered pattern section 7 states after ``lead``, in order."""
    region = _section(text, 7).partition(lead)[2].partition(end)[0]
    assert region, f"section 7 has no {lead!r} paragraph"
    items: list[list[str]] = []
    for line in region.splitlines():
        if _PATTERN_ITEM_RE.match(line):
            items.append([line])
        elif items and line.startswith("   "):
            items[-1].append(line)
    return [set(re.findall(r"`([^`]+)`", " ".join(item))) for item in items]


#: What the detector matches, pattern by pattern, as the page must state it.
_DETECTOR_PATTERNS = [
    set(_PARSER_LIBS),
    {*_JSON_DECODES, _JSON_HELPER, f".{_JSON_METHOD}()"},
    set(_FORM_DECODES),
    {*_BYTE_TOKENIZERS, *_UNPACKS},
    {_SOURCE_REGISTRAR},
    {*_KEY_DECODE_PREFIXES, *_PKCS12_DECODES},
]


def _innerhtml_file_problems(text: str, sources: Mapping[str, str]) -> list[str]:
    """Each file section 9 names as building markup with ``innerHTML`` must exist under ``ide/src``
    and write ``innerHTML``, by the sink pattern section 10 uses."""
    claim = re.search(r"markup with `innerHTML`, at least in (.+?)\.\s", _section(text, 9), re.S)
    assert claim is not None, "section 9 no longer names the files that build markup with innerHTML"
    names = re.findall(r"`([\w/]+\.ts)`", claim.group(1))
    if not names:
        return ["section 9's innerHTML sentence names no file"]
    problems: list[str] = []
    for name in names:
        source = sources.get(name)
        if source is None:
            problems.append(f"section 9 names {name}, which is not in ide/src")
        elif not any(
            "innerHTML" in sink
            for line in _script_code_lines(source)
            for sink in (match.group(0) for match in _HTML_SINK_RE.finditer(line))
        ):
            problems.append(f"section 9 names {name}, which writes no innerHTML")
    return problems


def test_the_parser_tables_match_the_code() -> None:
    _assert_no_drift(7, _parser_drift(_doc_text(), _parse_sites(_parser_scan_sources())))


def test_the_page_states_the_patterns_the_detector_uses() -> None:
    """The page tells a reader how to re-run the scan, so its patterns must be the detector's."""
    assert _page_patterns(_doc_text()) == _DETECTOR_PATTERNS


def test_the_parse_site_scan_reaches_the_sites_it_must() -> None:
    # The multipart parser is the site that first showed the page's list was not derived. It is
    # hand-written, so only pattern 4 reaches it. The HTTP listener is reached only by pattern 5,
    # and the HL7 fast path is the product's main parser.
    must = {
        "api/multipart.py",
        "transports/http_listener.py",
        "parsing/peek.py",
        "parsing/fhir/",
        f"{_CONSOLE_PREFIX}routes/core.py",
    }
    assert must <= _parse_sites(_parser_scan_sources()), (
        "the parse-site scan no longer finds a site it must: the scan is dead or a pattern broke"
    )


def test_the_innerhtml_file_section_9_names_holds_the_sink() -> None:
    _assert_no_drift(9, _innerhtml_file_problems(_doc_text(), _ide_sources()))


_PARSE_SITE_CONTROLS = [
    "import hl7\n",
    "from defusedxml.ElementTree import fromstring\n",
    "from email import parser\n",
    "import email.parser\n",
    "from fhir.resources import get_fhir_model_class\n",
    "def f():\n    import pyx12.x12n_document\n",
    "import json\njson.loads(x)\n",
    "import json as j\nj.load(fh)\n",
    "from json import loads\nloads(x)\n",
    "value, refused = json_loads_or_refusal(raw)\n",
    "async def f(request):\n    return await request.json()\n",
    "from urllib.parse import parse_qsl\nparse_qsl(body)\n",
    "head, _, rest = body.partition(b'\\r\\n\\r\\n')\n",
    "at = data.find(b'-->', 4)\n",
    "(length,) = struct.unpack('>I', data[:4])\n",
    "from struct import unpack_from\nunpack_from('>I', data, 0)\n",
    "import pickle\n",
    "import email\nemail.message_from_bytes(raw)\n",
    "body = response.json(strict=True)\n",
    "register_source(ConnectorType.TCP, TcpSource)\n",
    "def f(token):\n    import spnego\n",
    "from cryptography import x509\nx509.load_pem_x509_certificate(data)\n",
    "from cryptography.hazmat.primitives.serialization import load_der_private_key\n"
    "load_der_private_key(data, None)\n",
    "pkcs12.load_key_and_certificates(pfx, password)\n",
    "pkcs12.load_pkcs12(pfx, password)\n",
    "serialization.load_ssh_public_key(data)\n",
]


@pytest.mark.parametrize("source", _PARSE_SITE_CONTROLS)
def test_the_parse_site_detector_fires_on_each_pattern(source: str) -> None:
    assert _is_parse_site(source)


def test_the_parse_site_detector_ignores_mentions_and_non_parses() -> None:
    quiet = (
        '"""import hl7, json.loads(x), parse_qsl(body) and data.find(b"x")."""\n'
        "# import lxml\n"
        "import json\n"
        "from email.message import EmailMessage\n"
        "text = json.dumps(value)\n"
        "ok = data.startswith(b'MSH') and data.endswith(b'\\r')\n"
        "parts = text.split(',')\n"
        "def register_source(kind, cls): ...\n"
        "ctx.load_verify_locations(cafile=path)\n"
        "pem = cert.public_bytes(encoding)\n"
    )
    assert not _is_parse_site(quiet)
    assert _parse_sites(
        {"parsing/xml/_deps.py": "import lxml\n", "parsing/peek.py": "import hl7\n"}
    ) == {
        "parsing/xml/",
        "parsing/peek.py",
    }


def test_parser_table_drift_is_reported() -> None:
    """Break the page and the tree in memory, one way at a time, and each break must be reported."""
    text = _doc_text()
    sources = _parser_scan_sources()
    live = _parse_sites(sources)
    assert not _parser_drift(text, live)
    # A pattern the page states that the detector does not use, or one it drops.
    assert _page_patterns(_replace_once(text, "`cbor2`, ", "`cbor2`, `msgpack`, ")) != (
        _DETECTOR_PATTERNS
    )
    assert _page_patterns(_replace_once(text, "`parse_qs`, `parse_qsl`, ", "`parse_qs`, ")) != (
        _DETECTOR_PATTERNS
    )

    # An omitted site: the page drops one the scan finds.
    assert _parser_drift(
        _replace_once(text, "`api/app.py`, `api/multipart.py`, ", "`api/app.py`, "), live
    )
    # An orphaned listing: the page names a module the scan does not find.
    assert _parser_drift(
        _replace_once(text, "| `corepoint_import.py` |", "| `corepoint_import.py`, `nope.py` |"),
        live,
    )
    # One site in both tables.
    assert _parser_drift(
        _replace_once(
            text, "`phi_log_silencer.py` |", "`phi_log_silencer.py`, `api/multipart.py` |"
        ),
        live,
    )
    # A planted parser the page does not name.
    sources["pipeline/new_parser.py"] = (
        "import json\n\ndef read(raw):\n    return json.loads(raw)\n"
    )
    assert _parser_drift(text, _parse_sites(sources))
    # A table the reader can no longer find is an error, not an empty set.
    with pytest.raises(AssertionError):
        _parser_drift(_replace_once(text, _LEFT_OUT_HEADER, "| Why | Modules |"), live)
    # The hand-read table may not name a site the scan finds, or a file that does not exist.
    hand_row = "| `parsing/split.py` |"
    for extra in ("`api/multipart.py`", "`parsing/x12/interchange.py`", "`nope.py`"):
        broken = _replace_once(text, hand_row, f"| `parsing/split.py`, {extra} |")
        assert _parser_drift(broken, live), extra


def test_innerhtml_file_drift_is_reported() -> None:
    text = _doc_text()
    sources = _ide_sources()
    assert not _innerhtml_file_problems(text, sources)
    named = "at least in `testBenchWebview.ts`."
    # The file the sentence named before BACKLOG #1190 exists and holds no innerHTML write.
    assert _innerhtml_file_problems(
        _replace_once(text, named, "at least in `testBench.ts`."), sources
    )
    assert _innerhtml_file_problems(_replace_once(text, named, "at least in `nope.ts`."), sources)
    # A file that writes HTML another way no longer backs the sentence's innerHTML claim.
    other_sink = {**sources, "testBenchWebview.ts": "el.insertAdjacentHTML('beforeend', x);\n"}
    assert _innerhtml_file_problems(text, other_sink)


# --- section 7: the extension's parser tables (BACKLOG #1190) -------------------------------------

#: Extension pattern 1: a JSON decode. A ``.json()`` call shares the Python scan's method name.
_TS_JSON_PARSE = "JSON.parse"
#: Extension pattern 2: a ``split`` on a string or regular-expression literal holding a line break.
_TS_SPLIT = "split"
_TS_LINE_BREAKS = (r"\r", r"\n")
#: Extension pattern 3: a character read.
_TS_CHAR_READS = ("charAt", "charCodeAt", "codePointAt")
#: Extension pattern 4: an import of a Node network module, with or without the ``node:`` prefix,
#: or a call to a global that reads the network with no import.
_TS_NET_MODULES = ("http", "https", "http2", "net", "tls", "dgram")
_TS_NODE_PREFIX = "node:"
_TS_NET_GLOBALS = ("fetch", "WebSocket")

# A literal body is escapes and other characters up to the closing quote. The part before the first
# break escape may not hold one, so the match is linear rather than trying every break in turn.
_TS_BREAK = "|".join(re.escape(escape) for escape in _TS_LINE_BREAKS)
_TS_PARSE_RE = re.compile(
    "|".join(
        (
            rf"\b{re.escape(_TS_JSON_PARSE)}\(|\.{_JSON_METHOD}\(",
            rf"\.{_TS_SPLIT}\(\s*(?P<q>[/\"'`])(?:(?!(?P=q))[^\\\n]|\\[^rn])*(?:{_TS_BREAK})"
            r"(?:(?!(?P=q))[^\\\n]|\\.)*(?P=q)",
            rf"\.(?:{'|'.join(_TS_CHAR_READS)})\(",
            rf"""(?<![\w.$])(?:from|import|require)\s*\(?\s*["'](?:{_TS_NODE_PREFIX})?"""
            rf"""(?:{"|".join(_TS_NET_MODULES)})["']""",
            rf"(?:(?<![\w.$])|\bglobalThis\.)(?:{'|'.join(_TS_NET_GLOBALS)})\s*(?:\?\.)?\(",
        )
    )
)

#: What the extension detector matches, pattern by pattern, as the page must state it.
_TS_DETECTOR_PATTERNS = [
    {_TS_JSON_PARSE, f".{_JSON_METHOD}()"},
    {_TS_SPLIT, *_TS_LINE_BREAKS},
    set(_TS_CHAR_READS),
    {*_TS_NET_MODULES, _TS_NODE_PREFIX, *_TS_NET_GLOBALS},
]

_TS_OUTSIDE_HEADER = "| Input | Where it comes from | Files |"
_TS_LEFT_OUT_HEADER = "| Why it is left out | Files |"
_TS_BY_HAND_HEADER = "| What it reads | Files |"


def _ts_page_patterns(text: str) -> list[set[str]]:
    return _page_patterns(text, _TS_PATTERNS_LEAD, _TS_PATTERNS_END)


@functools.cache
def _is_ts_parse_site(source: str) -> bool:
    """Whether a code line of one extension file matches any of the four patterns section 7 names
    for the extension. Whole-line comments are skipped by the rule section 9's counts use."""
    return any(_TS_PARSE_RE.search(line) for line in _script_code_lines(source))


def _ts_parse_sites(sources: Mapping[str, str]) -> set[str]:
    return {rel for rel, source in sources.items() if _is_ts_parse_site(source)}


def _ts_parser_drift(text: str, live: set[str], sources: Mapping[str, str]) -> list[str]:
    """The extension's tables, held as the engine's are. A hand-read file must be in ``sources``."""
    return _three_table_drift(
        text,
        "section 7's extension parser tables",
        (_TS_OUTSIDE_HEADER, _TS_LEFT_OUT_HEADER, _TS_BY_HAND_HEADER),
        live,
        str,
        sources.__contains__,
    )


def test_the_extension_parser_tables_match_the_code() -> None:
    sources = _ide_sources()
    _assert_no_drift(7, _ts_parser_drift(_doc_text(), _ts_parse_sites(sources), sources))


def test_the_page_states_the_extension_patterns_the_detector_uses() -> None:
    assert _ts_page_patterns(_doc_text()) == _TS_DETECTOR_PATTERNS


def test_the_extension_scan_reaches_the_sites_it_must() -> None:
    # The engine client parses whatever answers at the engine URL, and hl7diff.ts is a hand-written
    # HL7 parser that only the character-read pattern reaches: it splits on a named constant.
    must = {"engineClient.ts", "hl7diff.ts"}
    assert must <= _ts_parse_sites(_ide_sources()), (
        "the extension parse-site scan no longer finds a site it must: it is dead or a pattern broke"
    )


_TS_PARSE_SITE_CONTROLS = [
    "const parsed: unknown = JSON.parse(text);",
    "const body = await response.json();",
    r"for (const line of text.split(/\r?\n/)) {}",
    r"const segments = raw.split(/\r\n|\r|\n/);",
    r'const head = (markdown.split("\n")[0] ?? "");',
    r"const rows = text.split('\r\n');",
    r"const rows = text.split(`\n`);",
    "const field = line.charAt(3);",
    "const code = text.charCodeAt(0);",
    "const point = text.codePointAt(0);",
    'import * as http from "node:http";',
    "import { Socket } from 'net';",
    'const tls = require("node:tls");',
    'const dgram = await import("dgram");',
    "const response = await fetch(url);",
    "const socket = new WebSocket(url);",
    "const response = await globalThis.fetch(url);",
    "const response = await fetch?.(url);",
]


@pytest.mark.parametrize("source", _TS_PARSE_SITE_CONTROLS)
def test_the_extension_detector_fires_on_each_pattern(source: str) -> None:
    assert _is_ts_parse_site(source)


def test_the_extension_detector_ignores_mentions_and_non_parses() -> None:
    quiet = "\n".join(
        (
            "// const parsed = JSON.parse(text);",
            " * const field = line.charAt(3);",
            "/* import * as http from 'node:http'; */",
            "const text = JSON.stringify(value);",
            'const parts = name.split("_");',
            r"const base = fsPath.split(/[\\/]/).pop();",
            "const lines = text.split(SEG_SEP);",
            'import * as path from "node:path";',
            'import { getJson } from "./http";',
            'const url = "https://127.0.0.1:8765";',
            r'const escaped = text.split("\\n");',
            "await repo.fetch(remote);",
            "const prefetched = prefetch(url);",
            'const bytes = Buffer.from("http");',
            "const chars = Array.from('net');",
        )
    )
    assert not _is_ts_parse_site(quiet)


def test_extension_parser_table_drift_is_reported() -> None:
    """Break the page and the tree in memory, one way at a time, and each break must be reported."""
    text = _doc_text()
    sources = _ide_sources()
    live = _ts_parse_sites(sources)
    assert not _ts_parser_drift(text, live, sources)
    # A planted JSON decode in a file the page does not name.
    grown = {**sources, "newPanel.ts": "const reply = JSON.parse(text);\n"}
    assert _ts_parser_drift(text, _ts_parse_sites(grown), grown)
    # An omitted site, an orphaned listing, one site in both tables, a hand-read file the scan
    # finds, and a hand-read file that does not exist.
    for old, new in (
        ("| `hl7diff.ts`, `hl7scope.ts` |", "| `hl7diff.ts` |"),
        ("| `connectionForm.ts` |", "| `connectionForm.ts`, `nope.ts` |"),
        ("| `engineClient.ts` |", "| `engineClient.ts`, `cli.ts` |"),
        ("| `completion.ts` |", "| `completion.ts`, `cli.ts` |"),
        ("| `completion.ts` |", "| `completion.ts`, `nope.ts` |"),
    ):
        assert _ts_parser_drift(_replace_once(text, old, new), live, sources), new
    # A table the reader can no longer find is an error, not an empty set.
    with pytest.raises(AssertionError):
        _ts_parser_drift(
            _replace_once(text, _TS_OUTSIDE_HEADER, "| Input | Files |"), live, sources
        )
    # A pattern the page states that the detector does not use, or one it drops.
    for old, new in (("`tls` or `dgram`", "`tls`"), ("`charAt`, ", "`charAt`, `at`, ")):
        assert _ts_page_patterns(_replace_once(text, old, new)) != _TS_DETECTOR_PATTERNS, new
