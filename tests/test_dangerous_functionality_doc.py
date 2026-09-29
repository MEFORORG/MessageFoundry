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
  what the section's "never a path from configuration" sentence claims, except the reviewed loads
  in ``_REVIEWED_COMPUTED_LOADS``, which the section names.
* **Process starts (section 4).** Every module that starts a process must have a table row, and each
  row's Form cell must equal the forms the code uses. A form is how the call reaches the OS:
  ``argument list``, ``shell string``, ``ShellExecute``, ``os.startfile``, ``browser``,
  ``multiprocessing`` or ``CreateProcess``. So a new ``shell=True`` in a module the page lists as
  argument-list only fails here, not just a new module.

Four more checks hold the page's later lists and counts to the tree (BACKLOG #1190): the section 7
archive readers, the section 8 service-script table, the section 9 extension counts over ``ide/src``,
and the section 10 count of ``innerHTML`` writes in the web console's scripts, plus the claim that
the console's Python holds none of the engine's classes. The TypeScript and JavaScript checks read
by pattern, not by parser, and skip whole-line comments only.

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
def _imports_any(source: str, libs: tuple[str, ...], attr: str | None = None) -> bool:
    """Whether a module imports one of ``libs`` or a submodule of one, at any depth, or reads an
    attribute named ``attr``. A source that never spells any of those names is not parsed."""
    if not any(name in source for name in (*libs, *(() if attr is None else (attr,)))):
        return False
    for node in ast.walk(_parse(source)):
        if isinstance(node, ast.Import):
            names = [alias.name for alias in node.names]
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module is not None:
            names = [node.module]
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
    gap = _register_gap(_start_sites(_package_sources()), _ALLOWED_SUBPROCESS_SITES)
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
    live = _start_sites(_package_sources())
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


def _service_drift(text: str, live: set[str]) -> list[str]:
    return _set_drift("section 8's table", _service_rows(text), live)


def _script_code_lines(source: str) -> list[str]:
    """Lines of a TypeScript or JavaScript file that are not whole-line comments, by the rule
    ``_is_comment_only`` in ``scripts/security/crypto_inventory_check.py`` uses. A trailing comment
    stays on its line; the patterns below never match inside one that follows a real call."""
    return [line for line in source.splitlines() if not line.lstrip().startswith(("//", "*", "/*"))]


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


def _child_process_problems(sources: Mapping[str, str]) -> list[str]:
    """Section 9 says every process start uses ``execFile``. So every code line naming
    ``child_process`` must be a named import of ``execFile`` alone; a ``spawn``, an ``exec``, a
    namespace import or a ``require`` fails here."""
    problems: list[str] = []
    for rel, source in sources.items():
        for line in _script_code_lines(source):
            if "child_process" not in line:
                continue
            match = _CHILD_PROCESS_IMPORT_RE.match(line)
            names = {name.strip() for name in match.group(1).split(",")} if match else set()
            if names != {"execFile"}:
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
    return {
        path.relative_to(_CONSOLE).as_posix(): path.read_text(encoding="utf-8")
        for path in sorted(_CONSOLE.rglob("*.py"))
    }


_INNER_HTML_RE = re.compile(r"\.innerHTML\s*=(?!=)")


def _console_sink_count(scripts: Mapping[str, str]) -> int:
    return sum(
        len(_INNER_HTML_RE.findall(line))
        for source in scripts.values()
        for line in _script_code_lines(source)
    )


def _console_drift(text: str, live: int) -> list[str]:
    match = re.search(r"into `innerHTML` in (\d+) places", _section(text, 10))
    assert match is not None, "section 10 does not state 'into `innerHTML` in <N> places'"
    page = int(match.group(1))
    return [] if page == live else [f"section 10 says {page} innerHTML writes; the code has {live}"]


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
    import by name. The first three reuse the engine inventories above."""
    problems = [f"{rel} imports ctypes" for rel in sorted(_ctypes_modules(sources))]
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
    _assert_no_drift(8, _service_drift(_doc_text(), _service_scripts()))


def test_the_extension_counts_match_the_code() -> None:
    problems = _ide_drift(_doc_text(), _ide_counts(_ide_sources()))
    _assert_no_drift(9, problems + _child_process_problems(_ide_sources()))


def test_the_console_matches_the_code() -> None:
    problems = _console_drift(_doc_text(), _console_sink_count(_console_scripts()))
    _assert_no_drift(10, problems + _console_python_problems(_console_python()))


def test_the_later_section_detectors_fire() -> None:
    """Each scan must find something on the real tree, and must see a planted site."""
    assert _imports_archive_lib("import tarfile\n")
    assert _imports_archive_lib("from compression import zstd\n")
    assert _imports_archive_lib("import shutil\nshutil.unpack_archive(p, d)\n")
    assert not _imports_archive_lib('"""import tarfile"""\nNOTE = "zipfile"\n')
    assert "install-service.ps1" in _service_scripts()
    live = _ide_counts(_ide_sources())
    assert all(sites and files for sites, files in live.values()), (
        f"an IDE scan found nothing: {live}"
    )
    quiet = (
        "// vscode.window.createTerminal(x)\n * execFile(a, b)\nconst s = 'enableScripts: false';\n"
    )
    assert _ide_counts({"a.ts": quiet}) == dict.fromkeys(_IDE_CALLS, (0, 0))
    assert _console_sink_count(_console_scripts()), "no innerHTML write found: the scan is dead"
    assert _console_sink_count({"a.js": "// el.innerHTML = x\nif (el.innerHTML == y) {}\n"}) == 0
    assert _console_sink_count({"a.js": "el.innerHTML = x; // server-built\n"}) == 1
    for planted in (
        'import { spawn } from "node:child_process";',
        'import { execFile, exec } from "child_process";',
        'import * as cp from "node:child_process";',
        'const cp = require("child_process");',
    ):
        assert _child_process_problems({"a.ts": planted}), planted
    assert _console_python(), "no console Python found: the scan is dead"
    assert not _console_python_problems({"a.py": '"""subprocess.run, import ctypes"""\n'})
    for planted in (
        "import ctypes\n",
        "import subprocess\nsubprocess.run(['x'])\n",
        "import zipfile\n",
        "import importlib\nimportlib.import_module(name)\n",
        "__import__(name)\n",
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

    claim = f"into `innerHTML` in {sinks} places"
    assert _console_drift(
        _replace_once(text, claim, f"into `innerHTML` in {sinks + 1} places"), sinks
    )
    assert _console_drift(text, sinks + 1)
