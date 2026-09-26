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
from collections.abc import Mapping, Sequence
from functools import cache
from pathlib import Path
from types import MappingProxyType
from typing import NamedTuple

import pytest

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

# No floor may be lowered far enough to disarm the thing it is for. A red floor invites the obvious
# "fix" of editing the number down, and a floor of 0 or 1 passes a walk that reached nothing.
# Deliberately an absolute bound rather than a fraction of the live census: a fraction reds whenever
# a package legitimately grows, which is the brittleness the floors sit under the census to avoid.
_MIN_FLOOR = 5


class _Scan(NamedTuple):
    """What one boundary walk found: the violations, and how many files it actually opened.

    Both fields are read-only. `_engine_scan` hands the SAME object to every caller, so a list
    appended to or a count reassigned would rewrite what every later caller reads — including the
    floor guard's own input. A NamedTuple reads as a frozen value; these fields make it one.
    """

    violations: tuple[str, ...]
    walked: Mapping[str, int]


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

    Third-party names (`fastapi`, `pyside6`, `PySide6`) are exempt -- they are import names, not
    paths in this tree, and the suite would not run at all if they were absent.

    `_TRAY_FORBIDDEN` is covered here too (BACKLOG #1716). Its positive control plants an importable
    stub for any name without a dot, so a misspelled third-party entry there passes its own control
    by construction; this is what catches a misspelled in-tree one."""
    repo = Path(__file__).resolve().parents[1]
    for entry in (
        _FORBIDDEN + _TRAY_FORBIDDEN + tuple(m for v in _PACKAGE_FORBIDDEN.values() for m in v)
    ):
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


def _scan(root: Path, packages: Sequence[str]) -> _Scan:
    """Walk `packages` under `root` for forbidden imports, counting the files opened.

    Extracted from the boundary test so the guards below can drive the SAME walk over a planted
    tree (BACKLOG #1747). A guard that re-implements the walk proves nothing about the walk that
    actually grades the engine.

    THE FACT THIS FILE IS BUILT AROUND, stated here and not restated: a walk that opened no file
    reports exactly what a clean walk reports. `Path.rglob` over a directory that is not there
    raises nothing and yields nothing, so a renamed package, a typo in `_ENGINE_PACKAGES`, or a
    root resolved one level off each buy a green verdict over nothing at all. Both answers to that
    live in the walk rather than in a caller, because a caller is skippable: a missing directory
    raises here, and `walked` rides back beside `violations` so a caller over the real tree can
    hold it to a floor.

    Only STATIC `import` statements are seen — `_imported_modules` reads the AST. An
    `importlib.import_module("fastapi")`, a `__import__(...)`, or a re-export through a permitted
    module all pass untouched. Green here means the static-import boundary holds, NOT that no
    forbidden module can be reached.
    """
    violations: list[str] = []
    walked: dict[str, int] = {}
    for package in packages:
        directory = root / package
        if not directory.is_dir():
            raise AssertionError(f"walk target is not a directory: {directory}")
        forbidden = _FORBIDDEN + _PACKAGE_FORBIDDEN.get(package, ())
        seen = 0
        for py in sorted(directory.rglob("*.py")):
            modules = _imported_modules(py, root)
            seen += 1  # after the parse, so `walked` counts files opened, not files globbed
            for module in modules:
                if _is_forbidden(module, forbidden):
                    violations.append(f"{py.relative_to(root)} imports {module}")
        walked[package] = seen
    return _Scan(tuple(violations), MappingProxyType(walked))


def _guarded_scan(root: Path, packages: Sequence[str], floors: Mapping[str, int]) -> _Scan:
    """`_scan` over `root`, refusing every shape in which its clean verdict would mean nothing.

    Takes its targets as ARGUMENTS so each refusal below can be driven over a planted tree and
    shown to fire. A guard branch reachable only when the real engine tree is already broken is
    exactly the unproven matcher this file exists to rule out.

    The four refusals, in the order a failure is easiest to read:

    1. `packages` and `floors` must name the same set. Without it, emptying or shortening the
       package list walks fewer packages and still returns clean — the top-level way back into the
       defect — and adding a package with no floor dies on a bare `KeyError` at step 4 instead.
       KNOWN LIMIT, measured: this catches an UNCOORDINATED edit only. Dropping a package from the
       list AND its floor together leaves the two consistent and walks one package fewer in
       silence. Nothing here can close that, because the package list IS the policy — there is no
       second source naming the engine packages to check it against. That edit is a deliberate
       narrowing of CLAUDE.md §4's rule, and review is what catches it.
    2. No floor below `_MIN_FLOOR`. Editing the numbers down is the obvious response to a red.
    3. Every package resolves to an importable one. `__init__.py` rather than `is_dir`: a directory
       left behind by a rename, or a package emptied down to loose scripts, satisfies `is_dir` and
       is no longer the package being graded.
    4. Every package's walk meets its floor.
    """
    disagree = set(packages) ^ set(floors)
    if disagree:
        raise AssertionError(f"package list and floor table disagree on: {sorted(disagree)}")

    weak = {p: n for p, n in floors.items() if n < _MIN_FLOOR}
    if weak:
        raise AssertionError(
            f"floors low enough to disarm the guard: {weak} (minimum {_MIN_FLOOR})"
        )

    missing = [p for p in packages if not (root / p / "__init__.py").is_file()]
    if missing:
        raise AssertionError(f"packages missing or not importable under {root}: {missing}")

    scan = _scan(root, packages)
    short = {p: n for p, n in scan.walked.items() if n < floors[p]}
    if short:
        raise AssertionError(f"walk fell under its floor: {short} (floors {dict(floors)})")
    return scan


@cache
def _engine_scan() -> _Scan:
    """The one guarded boundary walk over the real engine tree.

    The guard sits in the walk rather than in a sibling test because a sibling is skippable.
    Measured on this file at 909a38549, with all five names in `_ENGINE_PACKAGES` misspelled: the
    boundary test passed. Measured again at baf53b3ae, with the reach check in a sibling:
    `pytest -k never_import` passed, 10 deselected. A `-x` short-circuit, a deselect, or deleting
    the sibling all did the same. Guarding inside the walk makes every caller inherit it.

    Cached because the tree does not move mid-session and the walk parses about 150 files; both
    engine-facing tests below read this one result.
    """
    return _guarded_scan(_ENGINE_ROOT, _ENGINE_PACKAGES, _MIN_FILES_WALKED)


def test_engine_packages_never_import_api_console_or_gui() -> None:
    # low-30: automated enforcement of the one-way dependency rule (the governing invariant for
    # parallel agent work) — a `from fastapi import ...` slipping into transports/ would be caught.
    violations = _engine_scan().violations
    assert not violations, violations


def test_the_boundary_walk_reaches_every_engine_package() -> None:
    # BACKLOG #1747: gives the reach guard a test of its own to fail by name. `_guarded_scan` has
    # already refused every shape that would make the walk meaningless, so this reports what the
    # walk actually reached; the refusals themselves are proven over planted trees below.
    walked = _engine_scan().walked
    assert set(walked) == set(_MIN_FILES_WALKED), sorted(set(walked) ^ set(_MIN_FILES_WALKED))
    short = {p: n for p, n in walked.items() if n < _MIN_FILES_WALKED[p]}
    assert not short, f"{short} against floors {_MIN_FILES_WALKED}"


def _plant_package(root: Path, package: str, files: int) -> None:
    """An importable package under `root` holding `files` parseable modules, `__init__.py` included."""
    (root / package).mkdir(parents=True)
    (root / package / "__init__.py").write_text("", encoding="utf-8")
    for i in range(files - 1):
        (root / package / f"m{i}.py").write_text("import json\n", encoding="utf-8")


def test_the_engine_guard_passes_a_tree_that_meets_every_check(tmp_path: Path) -> None:
    # The positive control for the four refusals below. Without it they show only that SOMETHING
    # raises, not that the checks discriminate between a good tree and a bad one.
    root = tmp_path / "messagefoundry"
    _plant_package(root, "pipeline", 6)
    scan = _guarded_scan(root, ["pipeline"], {"pipeline": 5})
    assert scan.violations == (), scan.violations
    assert scan.walked == {"pipeline": 6}, scan.walked


def test_the_engine_guard_refuses_a_package_list_that_disagrees_with_the_floors(
    tmp_path: Path,
) -> None:
    # The guard reads its targets from the package list, so an emptied or shortened list would
    # otherwise walk fewer packages and still return clean — the defect, one level up.
    root = tmp_path / "messagefoundry"
    _plant_package(root, "pipeline", 6)
    with pytest.raises(AssertionError, match="disagree"):
        _guarded_scan(root, [], {"pipeline": 5})
    # And the other direction: a package added with no floor, which would otherwise be a KeyError.
    with pytest.raises(AssertionError, match="disagree"):
        _guarded_scan(root, ["pipeline", "auth"], {"pipeline": 5})


def test_the_engine_guard_refuses_a_floor_low_enough_to_disarm_it(tmp_path: Path) -> None:
    root = tmp_path / "messagefoundry"
    _plant_package(root, "pipeline", 6)
    with pytest.raises(AssertionError, match="disarm"):
        _guarded_scan(root, ["pipeline"], {"pipeline": 1})


def test_the_engine_guard_refuses_a_directory_that_is_not_an_importable_package(
    tmp_path: Path,
) -> None:
    root = tmp_path / "messagefoundry"
    _plant_package(root, "pipeline", 6)
    (root / "pipeline" / "__init__.py").unlink()
    with pytest.raises(AssertionError, match="not importable"):
        _guarded_scan(root, ["pipeline"], {"pipeline": 5})


def test_the_engine_guard_refuses_a_walk_that_fell_under_its_floor(tmp_path: Path) -> None:
    root = tmp_path / "messagefoundry"
    _plant_package(root, "pipeline", 6)
    with pytest.raises(AssertionError, match="under its floor"):
        _guarded_scan(root, ["pipeline"], {"pipeline": 9})


# (package, the rule the row proves, the planted import line, whether the walk must flag it).
# `rule` is empty on the negative rows, which prove no rule — they prove the matcher does not
# over-reach. `test_every_forbidden_rule_has_a_planted_case` holds the positive rows to the
# constants, so a rule added without a planted case reds instead of shipping as an unproven matcher.
_PLANTED: list[tuple[str, str, str, bool]] = [
    # Every entry in `_FORBIDDEN`, planted one at a time, in an engine package.
    ("pipeline", "fastapi", "from fastapi import FastAPI\n", True),
    ("pipeline", "pyside6", "import PySide6.QtWidgets\n", True),
    ("pipeline", "messagefoundry.api", "from messagefoundry.api import models\n", True),
    ("pipeline", "messagefoundry_webconsole", "import messagefoundry_webconsole.mount\n", True),
    # The `_PACKAGE_FORBIDDEN` inward rules, which bind transports/ only.
    ("transports", "messagefoundry.store", "from messagefoundry.store import base\n", True),
    (
        "transports",
        "messagefoundry.pipeline",
        "from messagefoundry.pipeline import engine\n",
        True,
    ),
    # Negative arm 1, rule scoping: the transports-only rules must not bind elsewhere, or the guard
    # reports the rule as broader than it is. `pipeline` importing `store` is the engine's own
    # direction of travel — pipeline/engine.py does it today.
    ("pipeline", "", "from messagefoundry.store import base\n", False),
    # Negative arm 2, the prefix boundary — the matcher's one subtle line, `startswith(f + ".")`.
    # Dropping that `.` passes every row above while reporting these two as violations:
    # `messagefoundry.apiclient` is a real package (CLAUDE.md §3) and is not the api package, and
    # `fastapi_utils` is not fastapi.
    ("pipeline", "", "from messagefoundry.apiclient import client\n", False),
    ("pipeline", "", "import fastapi_utils\n", False),
]


def test_every_forbidden_rule_has_a_planted_case() -> None:
    # BACKLOG #1747, and CLAUDE.md §11 / SDS-3.6: the rows above are an enumeration, and an
    # enumeration nobody checks rots. Measured at baf53b3ae — appending a rule to `_FORBIDDEN` with
    # no planted row left the whole file green, so the new rule shipped unproven.
    planted = {rule for _, rule, _, flagged in _PLANTED if flagged}
    rules = set(_FORBIDDEN) | {r for rs in _PACKAGE_FORBIDDEN.values() for r in rs}
    assert planted == rules, f"planted {sorted(planted)} against rules {sorted(rules)}"


def test_the_forbidden_rules_are_written_lowercase() -> None:
    # `_scan` lowercases the MODULE it read and not the RULE, so a rule spelled `PySide6` or
    # `FastAPI` can never match: present in the table, reading as enforced, catching nothing.
    # `_FORBIDDEN` honours that by convention only — this states the convention.
    rules = [*_FORBIDDEN, *(r for rs in _PACKAGE_FORBIDDEN.values() for r in rs)]
    mixed = [r for r in rules if r != r.lower()]
    assert not mixed, f"the matcher never lowercases a rule, so these match nothing: {mixed}"


@pytest.mark.parametrize(("package", "rule", "line", "flagged"), _PLANTED)
def test_the_walk_sees_a_planted_forbidden_import(
    tmp_path: Path, package: str, rule: str, line: str, flagged: bool
) -> None:
    # BACKLOG #1747: prove the walk can SEE the thing it is written to catch, and that it sees only
    # that. See `_scan`'s docstring for why its green would otherwise report nothing.
    root = tmp_path / "messagefoundry"
    (root / package).mkdir(parents=True)
    (root / package / "clean.py").write_text("import json\n", encoding="utf-8")
    (root / package / "planted.py").write_text(line, encoding="utf-8")

    scan = _scan(root, [package])
    assert scan.walked == {package: 2}, scan.walked
    if not flagged:
        assert scan.violations == (), scan.violations
        return
    assert len(scan.violations) == 1, scan.violations
    # `clean.py` must not be the file reported: a matcher that flags everything sees nothing.
    assert "planted.py imports " in scan.violations[0], scan.violations
    # ...and the module reported must be the one THIS row claims to prove. Without this, a row can
    # plant one rule's import under another rule's name: the coverage test above compares rule
    # strings and would still pass, leaving the named rule wholly unexercised while reading proven.
    flagged_module = scan.violations[0].split(" imports ", 1)[1].lower()
    assert flagged_module == rule or flagged_module.startswith(rule + "."), (
        f"row claims to prove {rule!r}, but the walk flagged {flagged_module!r}"
    )


def test_the_walk_recurses_into_subpackages(tmp_path: Path) -> None:
    # BACKLOG #1747: every planted tree above is flat, and so is most of the engine — measured at
    # 909a38549, only `parsing` nests (14 top-level against 43 recursive). So regressing `rglob` to
    # `glob` leaves the rows above green and reds one floor with six files of margin. Planting a
    # level down is what makes losing recursion loud.
    root = tmp_path / "messagefoundry"
    (root / "pipeline" / "sub").mkdir(parents=True)
    (root / "pipeline" / "clean.py").write_text("import json\n", encoding="utf-8")
    (root / "pipeline" / "sub" / "deep.py").write_text(
        "from fastapi import FastAPI\n", encoding="utf-8"
    )

    scan = _scan(root, ["pipeline"])
    assert scan.walked == {"pipeline": 2}, scan.walked
    assert len(scan.violations) == 1, scan.violations
    assert "deep.py imports fastapi" in scan.violations[0], scan.violations


def test_the_walk_refuses_a_package_that_is_not_there(tmp_path: Path) -> None:
    # The missing-directory refusal in `_scan` itself, which every caller inherits — see that
    # function's docstring for the fact it exists to answer.
    (tmp_path / "messagefoundry").mkdir()
    with pytest.raises(AssertionError, match="not a directory"):
        _scan(tmp_path / "messagefoundry", ["pipeline"])


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
# CONFIG IS FORBIDDEN OUTRIGHT, AND THAT IS A CHANGE OF FACT RATHER THAN OF POLICY. This block once
# omitted `messagefoundry.config` because the PACKAGE ROOT dragged it in: `messagefoundry/
# __init__.py` imported `actions`, which imports `parsing.message`, so any `import messagefoundry.*`
# paid for config, parsing, hl7 and pydantic whatever the tray itself asked for. `3005dd073` (BACKLOG
# #1675) made that root lazy -- a PEP 562 `__getattr__` importing an export's owning module on first
# touch -- and the pull-in is gone. Re-measured on this tree: a fresh interpreter that imports
# `messagefoundry.tray.app` holds 0 `messagefoundry.config`, 0 `messagefoundry.parsing`, 0 `hl7` and
# 0 `pydantic` modules, against 14, 41, 8 and 42 at baf53b3ae. The omission bought tolerance for a
# pull-in no tray module caused; nothing causes it now, so config is named like any other package.
#
# `messagefoundry.tray.config` is a DIFFERENT module and the matcher does not reach it: the match is
# exact or on a dotted prefix, and the tray's own config module is neither `messagefoundry.config`
# nor anything under `messagefoundry.config.`. It loads on every probe call, so the main guard
# ASSERTS it is in the run rather than leaving that to this paragraph. BE EXACT ABOUT WHAT THAT
# CATCHES, because the near-miss is narrower than it looks: a matcher loosened to compare LAST
# SEGMENTS reds on it, and a matcher loosened to a plain substring test does NOT -- measured,
# `"messagefoundry.config" in "messagefoundry.tray.config"` is False, the `tray.` segment sits
# between. So the assertion pins one loosening, not every one.
#
# THIS IS AN ABSENCE LIST, NOT AN ALLOWLIST, and the difference is load-bearing. Every name below
# must be missing; nothing here says what the tray MAY import, so a package no entry names arrives
# silently.
#
# THE API ENTRY IS THE SERVER MODULE, NOT THE PACKAGE, and that is a correction rather than a
# nicety. ADR 0113 §1 PERMITS the tray `messagefoundry.apiclient`, and importing apiclient loads
# `messagefoundry.api.models` and `messagefoundry.api.auth_models` by design -- they are the pure
# pydantic response models this file's own opening docstring exists to keep separable from the
# server (ADR 0088). Measured: `import messagefoundry.apiclient` puts `messagefoundry.api` and five
# of its submodules in `sys.modules` and pulls neither `messagefoundry.api.app` nor `fastapi`. A bare
# `messagefoundry.api` here would therefore red the day the tray takes the import the ADR invites,
# which is a guard that punishes the compliant change. `messagefoundry.api.app` is the FastAPI
# application, so it still reds on a tray reaching for the server.
#
# THAT PERMITTED IMPORT REACHES CONFIG TOO, SO THE TOLERANCE IS CONDITIONAL AND NOT STANDING.
# `messagefoundry/api/models.py` imports `messagefoundry.config.ai_policy`, which brings the
# `messagefoundry.config` package plus its `models` and `tls_policy` siblings -- measured, exactly
# those four config modules and no other. `_APICLIENT_CARRIES` names that pull-in, and both tests
# below allow it ONLY when the child actually loaded `messagefoundry.apiclient`. The tray takes no
# apiclient import today, so config still reds outright here. Each unconditional answer is wrong in
# one direction: forbidding it flat reds the first compliant change, which is the defect the
# `api` -> `api.app` narrowing above exists to avoid, and allowing it flat blinds the direct import
# the entry was added for.
#
# WHAT THIS GUARD DOES NOT COVER, NAMED RATHER THAN IMPLIED, because a reader who takes it for the
# whole ADR rule gets a stronger control than the one that exists. Four limits, all measured here:
#
# 1. THE API ENTRY IS A SUBMODULE, NOT THE PACKAGE, for the reason just above. Measured: a tray
#    importing `messagefoundry.api.auth_models` directly -- rather than through the apiclient the
#    ADR permits -- brings no config and no `api.app`, so it passes this guard. `api.models` does
#    not slip through the same way: it reaches config, which reds.
# 2. A TRAY THAT TAKES THE APICLIENT IMPORT LOSES THE CONFIG SIGNAL. With `messagefoundry.apiclient`
#    in the child's `sys.modules`, a DIRECT `import messagefoundry.config` beside it is
#    indistinguishable from the one apiclient brings. Inherent to a runtime probe, and the reason
#    the static walk below is a complement rather than a nicety.
# 3. FOURTEEN OF THE SEVENTEEN TRAY MODULES. This reaches what `tray.app` imports; `branding`,
#    `instance` and `__main__` -- the actual entrypoint -- are never loaded, so a forbidden import in
#    one of those is invisible.
# 4. IMPORTS THAT RUN AT IMPORT TIME. A deferred `def _show(): import PySide6`, the ordinary shape
#    for an optional GUI dependency, never reaches `sys.modules` here.
#
# All four are closed by a STATIC walk rather than a runtime probe, which is a complement and not a
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
    "messagefoundry.config",
    "messagefoundry.store",
    "messagefoundry.pipeline",
    "messagefoundry.transports",
)

#: The one forbidden name `messagefoundry.apiclient` legitimately brings, through
#: `messagefoundry/api/models.py`'s `messagefoundry.config.ai_policy` import. Pinned as a constant so
#: the tests below and the paragraph above cannot drift apart.
_APICLIENT_CARRIES = frozenset({"messagefoundry.config"})

#: Prefix on the child's one JSON line, so the parse SELECTS it rather than taking the last line.
#: Last-line reading defends only against output written BEFORE the print; a ResourceWarning at
#: interpreter shutdown, an `atexit` writer or `-X dev` all land AFTER it, and a child that exits 0
#: printing nothing gives an IndexError before any assertion here can say what went wrong.
_PROBE_MARK = "MEFOR-TRAY-PROBE:"


class _TrayProbe(NamedTuple):
    """What one fresh-interpreter tray import saw."""

    #: The `_TRAY_FORBIDDEN` names that landed in the child's `sys.modules`.
    found: frozenset[str]
    #: Every `messagefoundry` name in it, so a caller can ask its own question of the same run.
    loaded: frozenset[str]


def _tray_import_probe(plant: str = "", *, path_head: Path | None = None) -> _TrayProbe:
    """Import the tray shell in a fresh interpreter and report what landed in `sys.modules`.

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
        "loaded = [m for m in sys.modules\n"
        "          if m == 'messagefoundry' or m.startswith('messagefoundry.')]\n"
        f"print({_PROBE_MARK!r} + json.dumps("
        "{'found': sorted(found), 'loaded': sorted(loaded)}))\n"
    )
    env = dict(os.environ)
    if path_head is not None:
        inherited = env.get("PYTHONPATH")
        env["PYTHONPATH"] = f"{path_head}{os.pathsep}{inherited}" if inherited else str(path_head)
    result = subprocess.run(
        [sys.executable, "-c", code], capture_output=True, text=True, env=env, timeout=300
    )
    assert result.returncode == 0, result.stderr
    marked = [ln for ln in result.stdout.splitlines() if ln.startswith(_PROBE_MARK)]
    assert len(marked) == 1, f"the probe printed {len(marked)} marked lines: {result.stdout!r}"
    payload = json.loads(marked[0].removeprefix(_PROBE_MARK))
    loaded = frozenset(payload["loaded"])
    # The tray import is the whole subject, and a plant runs BEFORE it, so without this line deleting
    # `import messagefoundry.tray.app` would leave every positive control below passing on the plant
    # alone. Asserting it here makes the tray import load-bearing in every call.
    assert "messagefoundry.tray.app" in loaded, "the probe never imported messagefoundry.tray.app"
    return _TrayProbe(frozenset(payload["found"]), loaded)


def test_the_tray_pulls_in_no_gui_toolkit_web_framework_or_engine_runtime() -> None:
    # All seven are absent today, so this is a regression guard rather than a fix: it fails the day a
    # tray module reaches for the server, engine config, the store, the pipeline, a connector or a
    # GUI toolkit.
    probe = _tray_import_probe()
    # The config tolerance is CONDITIONAL on the tray having taken the apiclient import ADR 0113 §1
    # permits, which it has not; `expected` is therefore empty here and a direct
    # `import messagefoundry.config` reds. See the paragraph above for why neither unconditional
    # answer works.
    expected = _APICLIENT_CARRIES if "messagefoundry.apiclient" in probe.loaded else frozenset()
    assert probe.found == expected, (
        f"importing messagefoundry.tray.app pulled in {sorted(probe.found)}, expected "
        f"{sorted(expected)}"
    )
    # The green above is only discriminating while the tray's OWN `config` module is in the run: it
    # is the near-miss the exact/dotted-prefix match has to keep clear of `messagefoundry.config`.
    # A last-segment comparison reds here; a plain substring test does not. See the paragraph above.
    assert "messagefoundry.tray.config" in probe.loaded, (
        "the tray shell no longer loads its own `config` module, so this green stops proving the "
        "matcher holds `messagefoundry.tray.config` apart from `messagefoundry.config`"
    )


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
        #
        # THE RESIDUE, because a stub is importable BY CONSTRUCTION: this leg cannot tell a real
        # third-party name from a misspelled one, so `pysides6` in the set above would plant, match
        # and pass while the main guard looked for a package that does not exist -- the shape
        # `test_forbidden_engine_imports_all_name_something_real` above exists to stop. That test now
        # covers `_TRAY_FORBIDDEN`'s in-tree names; the two third-party ones are not reachable that
        # way, for the same reason it exempts them from `_FORBIDDEN`.
        (tmp_path / name).mkdir()
        (tmp_path / name / "__init__.py").write_text("", encoding="utf-8")
        path_head = tmp_path

    probe = _tray_import_probe(f"import {name}", path_head=path_head)
    assert name in probe.found, (
        f"planted `import {name}` and the probe reported {sorted(probe.found)}"
    )
    # ...and it must not be answering yes to everything. `messagefoundry.pipeline` legitimately
    # brings the store and transports with it, so those cannot be pinned; nothing at all brings a GUI
    # toolkit, so PySide6 discriminates a real match from a blanket one. The PySide6 leg needs a
    # discriminator of its own, or `assert name in probe.found` is the whole of it and a matcher
    # answering yes to everything passes: `fastapi` serves, being absent from a PySide6 plant.
    discriminator = "fastapi" if name == "PySide6" else "PySide6"
    assert discriminator not in probe.found, sorted(probe.found)


def test_the_tray_probe_passes_the_import_adr_0113_permits() -> None:
    """The negative control: the ADR-PERMITTED import must trip nothing else (BACKLOG #1716).

    ADR 0113 §1 allows the tray `messagefoundry.apiclient`, and the tray does not take that import
    today -- its non-tray engine imports are the stdlib-only `messagefoundry.service_status`,
    `messagefoundry.service`, `messagefoundry.api_tls_source` and `messagefoundry.log_backoff`
    (measured 2026-09-26, BACKLOG #1844). So nothing else in this file would notice if the
    forbidden set were drawn to red on a legal import, and the guard would fail the first compliant
    change instead of the first violation.

    This is not hypothetical, which is why it is a test and not a comment: it FAILED when written,
    against a set naming a bare `messagefoundry.api`. Importing apiclient loads that package's pure
    response models by design, so the entry was narrowed to `messagefoundry.api.app`, the server.

    `messagefoundry.config` is the one name apiclient still brings, so it is EXEMPTED here rather
    than dropped from the forbidden set: the tray must not reach config on its own, and the day it
    takes the apiclient import this control says which forbidden name that is allowed to carry.
    Asserted in BOTH directions -- an apiclient that stops pulling config should retire
    `_APICLIENT_CARRIES`, not keep a tolerance that no longer tolerates anything.
    """
    assert _tray_import_probe("import messagefoundry.apiclient").found == _APICLIENT_CARRIES


def test_the_tray_probe_resolves_a_forbidden_package_by_its_dotted_prefix() -> None:
    """The matcher's PREFIX branch, which no other control here reaches (BACKLOG #1716).

    Importing `a.b.c` registers `a` and `a.b` too, so every plant above is satisfied by the matcher's
    EXACT-equality branch alone. Measured: delete `m.startswith(f + '.')` and all of them stay green,
    while `_tray_import_probe`'s own docstring tells the next reader the dotted-prefix case was
    proven. It matters because the real defect this guard is for arrives that way -- a tray reaching
    `messagefoundry.store.queue`, never bare `messagefoundry.store`.

    Planting straight into `sys.modules` rather than importing, because a real import would register
    the parent package and satisfy the exact branch, which is the case this test exists to exclude.
    """
    probe = _tray_import_probe(
        "import types\n"
        "sys.modules['messagefoundry.store.queue'] = types.ModuleType('messagefoundry.store.queue')"
    )
    assert probe.found == {"messagefoundry.store"}, sorted(probe.found)
    assert "messagefoundry.store" not in probe.loaded, (
        "the parent package is in the run, so the EXACT branch could have produced that match and "
        "this test no longer isolates the prefix branch"
    )
