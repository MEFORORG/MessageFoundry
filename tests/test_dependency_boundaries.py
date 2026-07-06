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


def _imported_modules(path: Path) -> set[str]:
    mods: set[str] = set()
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if isinstance(node, ast.Import):
            mods.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            mods.add(node.module)
    return mods


def test_engine_packages_never_import_api_console_or_gui() -> None:
    # low-30: automated enforcement of the one-way dependency rule (the governing invariant for
    # parallel agent work) — a `from fastapi import ...` slipping into transports/ would be caught.
    root = Path(__file__).resolve().parents[1] / "messagefoundry"
    violations: list[str] = []
    for package in _ENGINE_PACKAGES:
        for py in (root / package).rglob("*.py"):
            for module in _imported_modules(py):
                low = module.lower()
                if any(low == f or low.startswith(f + ".") for f in _FORBIDDEN):
                    violations.append(f"{py.relative_to(root)} imports {module}")
    assert not violations, violations


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
