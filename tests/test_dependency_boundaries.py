# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Architectural boundary guards (CLAUDE.md §4): the engine stays GUI/web-framework free, and
importing the api package's pure models must not drag the server into a GUI process."""

from __future__ import annotations

import ast
import json
import os
import subprocess
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import NamedTuple

import pytest

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

_ENGINE_ROOT = Path(__file__).resolve().parents[1] / "messagefoundry"

# BACKLOG #1747 walk floor: the fewest `*.py` files the walk must reach in each engine package
# before a clean verdict over that package means anything. Pinned WELL UNDER the census taken at
# 909a38549 (pipeline 33, transports 26, parsing 43, store 17, config 33) — roughly half — so
# deleting or merging modules never reds this, while a walk collapsing toward empty does.
_MIN_FILES_WALKED: dict[str, int] = {
    "pipeline": 15,
    "transports": 12,
    "parsing": 20,
    "store": 8,
    "config": 15,
}


class _Scan(NamedTuple):
    """What one boundary walk found: the violations, and how many files it actually opened."""

    violations: list[str]
    walked: dict[str, int]


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


def _scan(root: Path, packages: Sequence[str]) -> _Scan:
    """Walk `packages` under `root` for forbidden imports, counting the files reached.

    Extracted from the boundary test so the guards below can drive the SAME walk over a planted
    tree (BACKLOG #1747). A guard that re-implements the walk proves nothing about the walk that
    actually grades the engine. The per-package file count rides along for the same reason the
    violations do: an empty walk is otherwise indistinguishable from a clean one.
    """
    violations: list[str] = []
    walked: dict[str, int] = {}
    for package in packages:
        forbidden = _FORBIDDEN + _PACKAGE_FORBIDDEN.get(package, ())
        seen = 0
        for py in sorted((root / package).rglob("*.py")):
            seen += 1
            for module in _imported_modules(py, root):
                low = module.lower()
                if any(low == f or low.startswith(f + ".") for f in forbidden):
                    violations.append(f"{py.relative_to(root)} imports {module}")
        walked[package] = seen
    return _Scan(violations, walked)


def test_engine_packages_never_import_api_console_or_gui() -> None:
    # low-30: automated enforcement of the one-way dependency rule (the governing invariant for
    # parallel agent work) — a `from fastapi import ...` slipping into transports/ would be caught.
    violations = _scan(_ENGINE_ROOT, _ENGINE_PACKAGES).violations
    assert not violations, violations


def test_the_boundary_walk_reaches_every_engine_package() -> None:
    # BACKLOG #1747: `Path.rglob` over a directory that is not there raises nothing and yields
    # nothing, so the walk above would return a clean verdict having opened no file at all. A
    # renamed package, a typo in `_ENGINE_PACKAGES`, or a root resolved one level off would each
    # leave the guard green while it graded nothing — measured on this file at 909a38549, with all
    # five names misspelled, it still passed. Two assertions close that, because either alone has
    # a hole: `is_dir` catches a name resolving nowhere, and the floor catches a directory that
    # exists but has gone all but empty under the walk.
    missing = [p for p in _ENGINE_PACKAGES if not (_ENGINE_ROOT / p).is_dir()]
    assert not missing, f"engine packages not found under {_ENGINE_ROOT}: {missing}"

    walked = _scan(_ENGINE_ROOT, _ENGINE_PACKAGES).walked
    assert sorted(walked) == sorted(_MIN_FILES_WALKED), (walked, _MIN_FILES_WALKED)
    short = {p: n for p, n in walked.items() if n < _MIN_FILES_WALKED[p]}
    assert not short, f"boundary walk fell under its floor: {short} (floors {_MIN_FILES_WALKED})"


@pytest.mark.parametrize(
    ("package", "line", "flagged"),
    [
        # Every entry in `_FORBIDDEN`, planted one at a time, in an engine package.
        ("pipeline", "from fastapi import FastAPI\n", True),
        ("pipeline", "import PySide6.QtWidgets\n", True),
        ("pipeline", "from messagefoundry.api import models\n", True),
        ("pipeline", "import messagefoundry.console.view\n", True),
        # The `_PACKAGE_FORBIDDEN` inward rules, which bind transports/ only.
        ("transports", "from messagefoundry.store import base\n", True),
        ("transports", "from messagefoundry.pipeline import engine\n", True),
        # ...and the negative arm: that same import is legitimate outside transports/, so a guard
        # flagging it here would be reporting the rule as broader than it is.
        ("store", "from messagefoundry.pipeline import engine\n", False),
    ],
)
def test_the_walk_sees_a_planted_forbidden_import(
    tmp_path: Path, package: str, line: str, flagged: bool
) -> None:
    # BACKLOG #1747: prove the walk can SEE the thing it is written to catch. Without this, the
    # boundary test's green says only that nothing was reported — which is also what a walk with a
    # broken matcher, an unreadable tree, or an empty glob reports.
    root = tmp_path / "messagefoundry"
    (root / package).mkdir(parents=True)
    (root / package / "clean.py").write_text("import json\n", encoding="utf-8")
    (root / package / "planted.py").write_text(line, encoding="utf-8")

    scan = _scan(root, [package])
    assert scan.walked == {package: 2}, scan.walked
    if not flagged:
        assert scan.violations == [], scan.violations
        return
    assert len(scan.violations) == 1, scan.violations
    # `clean.py` must not be the file reported: a matcher that flags everything sees nothing.
    assert "planted.py imports " in scan.violations[0], scan.violations


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


# --- BACKLOG #1716: the tray's layering claim, checked in a FRESH interpreter -----------------------
#
# `messagefoundry/tray/__init__.py` states the ADR 0113 §1 rule in prose: the package may import only
# `messagefoundry.apiclient` and the stdlib-only NSSM helpers, and never PySide6, FastAPI, or the
# api/store/pipeline/transports packages. Nothing enforced it. `test_tray_windows_modules_import_and
# _build_structs` in `tests/test_tray_shell.py` does import the tray shell, but INSIDE the pytest
# process, where a sibling test may already have imported fastapi or PySide6 — so it certifies that
# the ctypes structs load and says nothing at all about what the tray drags in behind them.
#
# THIS IS AN ABSENCE LIST, NOT AN ALLOWLIST, and the difference is load-bearing. Importing
# `messagefoundry.tray.app` also loads `messagefoundry.config` and ALL of `messagefoundry.parsing`
# (and so `hl7` and `pydantic`) — from the PACKAGE ROOT, not from tray code: `messagefoundry/
# __init__.py` imports `actions`, which imports `parsing.message`. Measured at baf53b3ae: config 14
# modules, parsing 41, hl7 8, pydantic 42, against zero for every name below. An allowlist would
# therefore red on arrival over a pull-in no tray module causes; whether the package root should be
# that eager is a separate question with its own cost, and not one this guard may decide by failing.
#
# THE API ENTRY IS THE SERVER MODULE, NOT THE PACKAGE, and that is a correction rather than a
# nicety. ADR 0113 §1 PERMITS the tray `messagefoundry.apiclient`, and importing apiclient loads
# `messagefoundry.api.models` and `messagefoundry.api.auth_models` by design -- they are the pure
# pydantic response models this file's own opening docstring exists to keep separable from the
# server (ADR 0088). Measured: `import messagefoundry.apiclient` puts `messagefoundry.api` and four
# of its submodules in `sys.modules` and pulls neither `messagefoundry.api.app` nor `fastapi`. A bare
# `messagefoundry.api` here would therefore red the day the tray takes the import the ADR invites,
# which is a guard that punishes the compliant change. `messagefoundry.api.app` is the FastAPI
# application, so it still reds on a tray reaching for the server.
#
# WHAT THIS GUARD DOES NOT COVER, NAMED RATHER THAN IMPLIED, because a reader who takes it for the
# whole ADR rule gets a stronger control than the one that exists. Three limits, all measured here:
#
# 1. SIX OF THE SEVEN NAMES, one of them narrowed. `messagefoundry/tray/__init__.py` also forbids
#    `config`, which cannot be listed for the package-root reason just given, and `api` is carried
#    as `api.app` for the reason just above.
# 2. FOURTEEN OF THE SEVENTEEN TRAY MODULES. This reaches what `tray.app` imports; `branding`,
#    `instance` and `__main__` -- the actual entrypoint -- are never loaded, so a forbidden import in
#    one of those is invisible.
# 3. IMPORTS THAT RUN AT IMPORT TIME. A deferred `def _show(): import PySide6`, the ordinary shape
#    for an optional GUI dependency, never reaches `sys.modules` here.
#
# All three are closed by a STATIC walk rather than a runtime probe, which is a complement and not a
# replacement: an AST walk cannot see a forbidden package arriving TRANSITIVELY behind an allowed
# import, which is the one thing this probe is for. Measured on this tree: a walk over all 17 tray
# files for all seven names finds zero hits, so it would pass on arrival. It is not built here
# because the walk helper it would reuse (`_imported_modules` above) does not record the
# `from messagefoundry import config` spelling, and repairing that belongs to the walk's own change,
# not to this one. Unfiled; named by subject rather than by a number nobody has allocated.
_TRAY_FORBIDDEN = (
    "PySide6",
    "fastapi",
    "messagefoundry.api.app",
    "messagefoundry.store",
    "messagefoundry.pipeline",
    "messagefoundry.transports",
)


def _tray_import_probe(plant: str = "", *, path_head: Path | None = None) -> set[str]:
    """Import the tray shell in a fresh interpreter; return which `_TRAY_FORBIDDEN` names landed.

    Fresh, because `sys.modules` inside the pytest process already carries most of this tree — the
    same reason `test_importing_api_does_not_eagerly_pull_fastapi` above spawns one.

    `plant` is executed BEFORE the tray import, so it stands in for the MATCHER's input rather than
    for a tray module: it proves the probe resolves a forbidden name, including the dotted-prefix
    case, and not that the tray reached it. `path_head` is prepended to `PYTHONPATH` so a control can
    supply a name this environment may not have installed.
    """
    code = (
        "import json, sys\n"
        f"{plant}\n"
        "import messagefoundry.tray.app\n"
        f"forbidden = {_TRAY_FORBIDDEN!r}\n"
        "found = {f for f in forbidden for m in sys.modules\n"
        "         if m.lower() == f.lower() or m.lower().startswith(f.lower() + '.')}\n"
        "print(json.dumps({'found': sorted(found),\n"
        "                  'tray': 'messagefoundry.tray.app' in sys.modules}))\n"
    )
    env = dict(os.environ)
    if path_head is not None:
        inherited = env.get("PYTHONPATH")
        env["PYTHONPATH"] = f"{path_head}{os.pathsep}{inherited}" if inherited else str(path_head)
    result = subprocess.run(
        [sys.executable, "-c", code], capture_output=True, text=True, env=env, timeout=300
    )
    assert result.returncode == 0, result.stderr
    # Read the LAST line only. The child loads config, parsing, hl7 and pydantic, and a deprecation
    # banner from any of them on stdout would otherwise raise JSONDecodeError -- which reads as a bug
    # in this parse rather than as "the probe could not run".
    payload = json.loads(result.stdout.strip().splitlines()[-1])
    # The tray import is the whole subject, and a plant runs BEFORE it, so without this line deleting
    # `import messagefoundry.tray.app` would leave every positive control below passing on the plant
    # alone. Asserting it here makes the tray import load-bearing in every call.
    assert payload["tray"], "the probe never imported messagefoundry.tray.app"
    return set(payload["found"])


def test_the_tray_pulls_in_no_gui_toolkit_web_framework_or_engine_runtime() -> None:
    # All six are absent today, so this is a regression guard rather than a fix: it fails the day a
    # tray module reaches for the server, the store, the pipeline, a connector or a GUI toolkit.
    found = _tray_import_probe()
    assert found == set(), f"importing messagefoundry.tray.app pulled in {sorted(found)}"


@pytest.mark.parametrize("name", _TRAY_FORBIDDEN)
def test_the_tray_probe_sees_a_planted_forbidden_import(tmp_path: Path, name: str) -> None:
    # Prove the probe can SEE what it is looking for. A fresh-interpreter check that cannot detect
    # the import it names returns the same clean answer as a tray that is genuinely clean, and the
    # two are indistinguishable from the green alone.
    path_head = None
    if "." not in name:
        # A third-party name may not be installed on every leg, and a control that SKIPS is a control
        # that did not run. Plant an importable stub on the path instead: what is under test is that
        # the probe sees the name arrive in `sys.modules`, and a stub arrives there through the same
        # import machinery the real package would use.
        (tmp_path / name).mkdir()
        (tmp_path / name / "__init__.py").write_text("", encoding="utf-8")
        path_head = tmp_path

    found = _tray_import_probe(f"import {name}", path_head=path_head)
    assert name in found, f"planted `import {name}` and the probe reported {sorted(found)}"
    # ...and it must not be answering yes to everything. `messagefoundry.pipeline` legitimately
    # brings the store and transports with it, so those cannot be pinned; nothing at all brings a GUI
    # toolkit, so PySide6 is the name that discriminates a real match from a blanket one.
    if name != "PySide6":
        assert "PySide6" not in found, sorted(found)


def test_the_tray_probe_passes_the_import_adr_0113_permits() -> None:
    """The negative control: the ADR-PERMITTED import must trip nothing (BACKLOG #1716).

    ADR 0113 §1 allows the tray `messagefoundry.apiclient`, and the tray does not take that import
    today -- its only non-tray engine imports are `messagefoundry.service_status` and
    `messagefoundry.service`. So nothing else in this file would notice if the forbidden set were
    drawn to red on a legal import, and the guard would fail the first compliant change instead of
    the first violation.

    This is not hypothetical, which is why it is a test and not a comment: it FAILED when written,
    against a set naming a bare `messagefoundry.api`. Importing apiclient loads that package's pure
    response models by design, so the entry was narrowed to `messagefoundry.api.app`, the server.
    """
    assert _tray_import_probe("import messagefoundry.apiclient") == set()
