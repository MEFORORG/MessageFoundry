# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Architectural boundary guards (CLAUDE.md §4): the engine stays GUI/web-framework free, and
importing the api package's pure models must not drag the server into a GUI process."""

from __future__ import annotations

import ast
import subprocess
import sys
from pathlib import Path

# CLAUDE.md §4: the engine packages never import the API, the console, or their frameworks.
_ENGINE_PACKAGES = ["pipeline", "transports", "parsing", "store", "config"]
#: ``messagefoundry_webconsole`` replaced ``messagefoundry.console`` here (BACKLOG #1615). The old
#: name went with the PySide6 desktop console (BACKLOG #103, ADR 0032 retired) and no package
#: answers to it any more, so that entry could not match anything -- while the live web console,
#: which is a TOP-LEVEL package and not a submodule, was not on the list at all. The boundary read
#: as enforced and was not. ``test_forbidden_engine_imports_all_name_something_real`` below is what
#: stops the next retirement doing this again.
_FORBIDDEN = ("fastapi", "pyside6", "messagefoundry.api", "messagefoundry_webconsole")

# ADR 0154 AC-17: `transports/` additionally stays free of the store and the pipeline. A connector
# reaches either only through runner-injected callables (the `ConnectionEventSink` shape), which is
# what lets intake auth write an audit row without the listener ever holding a store handle. True of
# the tree already — nothing enforced it, so it was one careless import from silently becoming false.
_PACKAGE_FORBIDDEN: dict[str, tuple[str, ...]] = {
    "transports": ("messagefoundry.store", "messagefoundry.pipeline"),
}


def _package_of(path: Path, root: Path) -> str:
    """Dotted package containing `path`, a file under `root` (the `messagefoundry` package dir)."""
    rel = path.parent.relative_to(root)
    return ".".join([root.name, *rel.parts])


def _imported_modules(path: Path, root: Path) -> set[str]:
    """Absolute dotted names `path` imports, with relative imports resolved to absolute.

    Resolved rather than skipped: a boundary test that `from ..store import ...` walks straight
    through is not a boundary test. The tree uses absolute imports throughout today, so this changes
    no current verdict — it closes the bypass before someone finds it.
    """
    mods: set[str] = set()
    package = _package_of(path, root)
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if isinstance(node, ast.Import):
            mods.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            if node.level == 0:
                if node.module:
                    mods.add(node.module)
                continue
            # `from . import x` -> the package itself; `from ..store import x` -> one level up.
            base = package.rsplit(".", node.level - 1)[0]
            mods.add(f"{base}.{node.module}" if node.module else base)
    return mods


def _is_forbidden(module: str, forbidden: tuple[str, ...]) -> bool:
    """True iff `module` is one of `forbidden` or a submodule of one, case-insensitively.

    A prefix match on the dotted name and not on the raw string: `messagefoundry_webconsole_shim`
    must not read as `messagefoundry_webconsole`."""
    low = module.lower()
    return any(low == f or low.startswith(f + ".") for f in forbidden)


def test_forbidden_engine_imports_all_name_something_real() -> None:
    """Every in-tree entry in the forbidden lists must name a package that EXISTS (BACKLOG #1615).

    A retired name on this list is worse than a short list: the test still passes, the boundary
    still reads as enforced, and nothing reports that it now guards nothing. That is what
    `messagefoundry.console` did after the desktop console was retired.

    Third-party names (`fastapi`, `pyside6`) are exempt -- they are import names, not paths in this
    tree, and the suite would not run at all if they were absent."""
    repo = Path(__file__).resolve().parents[1]
    for entry in _FORBIDDEN + tuple(m for v in _PACKAGE_FORBIDDEN.values() for m in v):
        if not entry.startswith("messagefoundry"):
            continue
        target = repo / Path(*entry.split("."))
        assert target.is_dir() or target.with_suffix(".py").is_file(), (
            f"{entry!r} is on a forbidden-import list but names nothing in the tree, "
            f"so it forbids nothing (looked for {target})"
        )


def test_the_forbidden_matcher_can_actually_fail() -> None:
    """A positive control for the matcher itself -- a guard nothing can trip is not a guard.

    The engine tree is clean, so the boundary test passes whether or not the matcher works. These
    are the cases that separate the two."""
    assert _is_forbidden("messagefoundry_webconsole", _FORBIDDEN)
    assert _is_forbidden("messagefoundry_webconsole.app", _FORBIDDEN)
    assert _is_forbidden("MessageFoundry_WebConsole", _FORBIDDEN)  # the match is case-insensitive
    assert _is_forbidden("fastapi.responses", _FORBIDDEN)
    # ...and the near misses it must NOT flag, or the boundary test starts failing on innocent code.
    assert not _is_forbidden("messagefoundry", _FORBIDDEN)
    assert not _is_forbidden("messagefoundry_webconsole_shim", _FORBIDDEN)
    assert not _is_forbidden("messagefoundry.store", _FORBIDDEN)


def test_engine_packages_never_import_api_console_or_gui() -> None:
    # low-30: automated enforcement of the one-way dependency rule (the governing invariant for
    # parallel agent work) — a `from fastapi import ...` slipping into transports/ would be caught.
    root = Path(__file__).resolve().parents[1] / "messagefoundry"
    violations: list[str] = []
    for package in _ENGINE_PACKAGES:
        forbidden = _FORBIDDEN + _PACKAGE_FORBIDDEN.get(package, ())
        for py in (root / package).rglob("*.py"):
            for module in _imported_modules(py, root):
                if _is_forbidden(module, forbidden):
                    violations.append(f"{py.relative_to(root)} imports {module}")
    assert not violations, violations


def test_relative_imports_are_resolved_not_skipped(tmp_path: Path) -> None:
    # Guards the guard: the arm above is only worth anything if a relative import cannot evade it.
    root = tmp_path / "messagefoundry"
    (root / "transports").mkdir(parents=True)
    module = root / "transports" / "leaky.py"
    module.write_text(
        "from ..store import base\nfrom . import sibling\nfrom messagefoundry.parsing import peek\n",
        encoding="utf-8",
    )
    assert _imported_modules(module, root) == {
        "messagefoundry.store",
        "messagefoundry.transports",
        "messagefoundry.parsing",
    }


def test_importing_api_does_not_eagerly_pull_fastapi() -> None:
    # low-17: importing `messagefoundry.api` (e.g. for its pure Pydantic models, as the console does)
    # must NOT eagerly import FastAPI / the engine — api/__init__ exposes create_app lazily (PEP 562).
    # Run in a fresh interpreter so an unrelated test that already imported fastapi can't mask it.
    code = (
        "import sys\n"
        "import messagefoundry.api.models\n"
        "assert 'fastapi' not in sys.modules, sorted(m for m in sys.modules if m.startswith('fastapi'))\n"
        "import messagefoundry.api\n"
        "assert callable(messagefoundry.api.create_app)  # lazy export still resolves\n"
    )
    result = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
