# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Architectural boundary guards (CLAUDE.md §4): the engine stays GUI/web-framework free, and
importing the api package's pure models must not drag the server into a GUI process."""

from __future__ import annotations

import ast
import subprocess
import sys
from pathlib import Path

# CLAUDE.md §4: the engine packages never import the API, the console, or their frameworks.
_ENGINE_PACKAGES = ["pipeline", "transports", "parsing", "store", "config"]
_FORBIDDEN = ("fastapi", "pyside6", "messagefoundry.api", "messagefoundry.console")

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


def test_engine_packages_never_import_api_console_or_gui() -> None:
    # low-30: automated enforcement of the one-way dependency rule (the governing invariant for
    # parallel agent work) — a `from fastapi import ...` slipping into transports/ would be caught.
    root = Path(__file__).resolve().parents[1] / "messagefoundry"
    violations: list[str] = []
    for package in _ENGINE_PACKAGES:
        forbidden = _FORBIDDEN + _PACKAGE_FORBIDDEN.get(package, ())
        for py in (root / package).rglob("*.py"):
            for module in _imported_modules(py, root):
                low = module.lower()
                if any(low == f or low.startswith(f + ".") for f in forbidden):
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
