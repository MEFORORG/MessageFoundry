# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Meta-test: a server-DB suite that no workflow runs is dead coverage.

A module gated at import time on ``MEFOR_TEST_SQLSERVER`` / ``MEFOR_TEST_POSTGRES`` contributes
**zero executed tests** anywhere the gate is unset — every developer machine, and every CI leg that
does not export it. So a gated module that no workflow step names does not fail, does not error,
and does not surface as a skip anywhere a human looks: it silently never runs. Sixteen such modules
holding 83 tests accumulated before this test existed, including engine-shard crash recovery on
both server backends, the PostgreSQL failover suite, and the DR seed-gate and backup suites.

The mechanical invariants, at least these:

1. **Every module-gated suite is named by at least one workflow step.** Adding one without wiring
   it reds this test, so the wiring decision is forced at authoring time rather than discovered
   during an incident.
2. **The ``serverdb`` change-detection alternation admits every file the server-DB steps run.**
   ``ci.yml``'s ``changes`` job decides whether the SQL Server / PostgreSQL legs run on a PR at all.
   A file a leg runs but the alternation does not match does not pull the leg on its pull request:
   the leg first runs on it in the merge queue (``merge_group``) or on the nightly cron, after
   review rather than beside it. The regex's own comment already demands this
   ("Keep this in sync with those steps"); nothing enforced it.
3. **It also admits the ``tests/`` helpers those suites import, and the engine SOURCES the suites
   and those helpers import** (BACKLOG #1322, and #5472's S31-23 for the helpers), as far as a
   static read of their import statements finds them; the scan's docstring names at least four
   routes it does not follow. Invariant 2 binds the
   ASSERTING file and not the ASSERTED-ON file, so it is structurally blind to a source change that
   breaks a server-DB assertion. That is not hypothetical: a PR added a key to the ``summary_access``
   audit detail built in ``messagefoundry/api/app.py``, touched ``api/`` only, so ``serverdb`` was
   false, the legs never ran on it, and it merged green leaving both server-DB store suites asserting
   the old shape. Eighteen of the thirty-six imported modules were unmatched when this was measured.
4. **And it still refuses something.** A regex widened until it matches everything satisfies 2 and 3
   vacuously while running the container legs on every pull request, so that is asserted separately
   rather than assumed.

**Scope — module-gated only.** A module whose gate sits on individual tests or on one fixture
parametrization still executes its ungated (SQLite) cases, so it is not invisible in the same way;
its *server arm* not running is a real but weaker gap, tracked separately by the master test plan's
``STORE`` rows rather than pinned here. This test deliberately asserts the sharp invariant only, so
that a failure always means "this file runs nowhere" and never needs an allow-list to stay useful.

Pure text/AST analysis of the repo: no database, no network, and no gate of its own.
"""

from __future__ import annotations

import ast
import functools
import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
TESTS_DIR = REPO_ROOT / "tests"
WORKFLOWS_DIR = REPO_ROOT / ".github" / "workflows"
CI_YML = WORKFLOWS_DIR / "ci.yml"

#: The env gates that make a suite server-DB-only.
GATE_ENV_VARS = ("MEFOR_TEST_SQLSERVER", "MEFOR_TEST_POSTGRES")

#: Module-gated suites that are deliberately not wired to any leg. Each entry needs a reason.
#: An empty mapping is the healthy state — do NOT add a file here to silence a wiring gap.
UNWIRED_ALLOWED: dict[str, str] = {}


def _is_module_gated(path: Path) -> bool:
    """True when the whole module skips at collection unless a gate env var is set.

    Two shapes count: a module-level ``pytestmark`` carrying a skipif on a gate var, and a
    module-level ``pytest.skip(..., allow_module_level=True)`` guarded by one. Both yield zero
    executed tests when the gate is unset; a decorator on an individual test does not.

    A file whose text names no gate var is skipped before the parse. Since this test left the
    tooling tier for the engine legs (vault BACKLOG #3652), parsing every test file cost about ten
    seconds there, against a step-duration gate. The cost of the skip: a gate var spelled only by
    implicit string concatenation is no longer seen. The AST check already missed one built at run
    time.
    """
    text = path.read_text(encoding="utf-8")
    if not any(var in text for var in GATE_ENV_VARS):
        return False
    try:
        tree = ast.parse(text)
    except SyntaxError:  # pragma: no cover - a broken test file fails elsewhere, loudly
        return False
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(
            isinstance(t, ast.Name) and t.id == "pytestmark" for t in node.targets
        ):
            dumped = ast.dump(node)
            if "skipif" in dumped and any(var in dumped for var in GATE_ENV_VARS):
                return True
        dumped = ast.dump(node)
        if "allow_module_level" in dumped and any(var in dumped for var in GATE_ENV_VARS):
            return True
    return False


def _module_gated_suites() -> list[Path]:
    return [p for p in sorted(TESTS_DIR.glob("test_*.py")) if _is_module_gated(p)]


def _workflow_text() -> str:
    """All workflow YAML plus the CI helper scripts a step may delegate to."""
    parts = [p.read_text(encoding="utf-8") for p in sorted(WORKFLOWS_DIR.glob("*.yml"))]
    ci_scripts = REPO_ROOT / "scripts" / "ci"
    if ci_scripts.is_dir():
        parts += [
            p.read_text(encoding="utf-8")
            for p in sorted(ci_scripts.rglob("*"))
            if p.is_file() and p.suffix in {".sh", ".ps1", ".py"}
        ]
    return "\n".join(parts)


def test_every_module_gated_suite_is_named_by_a_workflow() -> None:
    """A module-gated file no workflow names produces zero tests, everywhere. Wire it."""
    gated = _module_gated_suites()
    assert gated, (
        "found no module-gated server-DB suites — the AST detection in _is_module_gated has "
        "drifted from how these suites gate themselves"
    )

    haystack = _workflow_text()
    unwired = sorted(
        p.name for p in gated if p.name not in haystack and p.name not in UNWIRED_ALLOWED
    )

    assert not unwired, (
        f"{len(unwired)} module-gated server-DB suite(s) are named by no workflow step or CI "
        "script, so they execute nowhere — not on a PR, not on push-to-main, not on the nightly "
        "cron:\n  "
        + "\n  ".join(unwired)
        + "\n\nAdd each to the sqlserver-store or postgres-store "
        "job in .github/workflows/ci.yml, and extend the `serverdb` change-detection alternation "
        "so editing the file pulls the leg that proves it."
    )


def _serverdb_alternation() -> re.Pattern[str]:
    """The ``tests/test_(...)`` alternation inside the ``serverdb`` change-detection regex."""
    for line in CI_YML.read_text(encoding="utf-8").splitlines():
        if "grep -qE" in line and "tests/test_(" in line:
            match = re.search(r"tests/test_\(([^)]*)\)", line)
            if match:
                return re.compile(rf"^test_({match.group(1)})")
    pytest.fail(
        "could not locate the `serverdb` change-detection alternation (a `grep -qE` line "
        "containing `tests/test_(...)`) in .github/workflows/ci.yml"
    )


def _files_run_by_server_db_steps() -> set[str]:
    """Test filenames a ci.yml step actually *runs* under a server-DB gate env var.

    Comment lines are stripped first: a step's prose may legitimately name a test file (this
    module names itself in the steps it motivated) without that step running it.
    """
    found: set[str] = set()
    for block in re.split(r"\n      - name:", CI_YML.read_text(encoding="utf-8")):
        if not any(f"{var}: " in block for var in GATE_ENV_VARS):
            continue
        executable = "\n".join(
            line for line in block.splitlines() if not line.lstrip().startswith("#")
        )
        found.update(re.findall(r"tests/(test_[A-Za-z0-9_]+)\.py", executable))
    return found


def test_serverdb_path_gate_admits_every_file_those_legs_run() -> None:
    """A file a server-DB leg runs must also pull that leg when it is edited."""
    alternation = _serverdb_alternation()
    run_by_legs = _files_run_by_server_db_steps()
    assert run_by_legs, (
        "found no test files inside server-DB-gated ci.yml steps — the step parsing in "
        "_files_run_by_server_db_steps has drifted"
    )

    unmatched = sorted(name for name in run_by_legs if not alternation.match(name))

    assert not unmatched, (
        f"{len(unmatched)} test file(s) run by a SQL Server / PostgreSQL step are not matched by "
        "the `serverdb` change-detection alternation in .github/workflows/ci.yml, so editing one "
        "does NOT pull the leg that proves it on the PR — it first runs in the merge queue or on "
        "the nightly cron:\n  "
        + "\n  ".join(unmatched)
        + "\n\nExtend the `tests/test_(...)` alternation to cover them."
    )


def _serverdb_full_pattern() -> re.Pattern[str]:
    """The WHOLE ``serverdb`` change-detection regex, source arms included.

    ``_serverdb_alternation`` above deliberately extracts only the ``tests/test_(...)`` group,
    because the invariant IT guards is about test files. This one keeps every arm, because BACKLOG
    #1322's invariant is about the SOURCES those suites assert against.
    """
    for line in CI_YML.read_text(encoding="utf-8").splitlines():
        if "grep -qE" in line and "tests/test_(" in line:
            match = re.search(r"grep -qE '(\^\(.*\))'", line)
            if match:
                return re.compile(match.group(1))
    pytest.fail(
        "could not locate the `serverdb` change-detection regex (a `grep -qE` line containing "
        "`tests/test_(...)`) in .github/workflows/ci.yml"
    )


def _module_path(module: str) -> str | None:
    """The repo-relative file a dotted ``messagefoundry*`` module name resolves to, if any.

    A PACKAGE maps to ``pkg/__init__.py``, never ``pkg.py``. Getting that wrong reports a package as
    unmatched while the directory arm plainly admits it -- a FALSE ALARM, which is the failure that
    trains readers to discount this test. The first draft of this measurement made exactly that
    mistake and over-reported the hole. The package is tried first, as Python's import system
    does when both exist.

    Matched against a listing rather than probed with ``is_file()``: on a case-insensitive
    filesystem ``from messagefoundry.pipeline import Engine`` would probe ``pipeline/Engine.py`` and
    find ``pipeline/engine.py``, recording a path no regex arm spells.
    """
    base = module.replace(".", "/")
    for candidate in (f"{base}/__init__.py", f"{base}.py"):
        if candidate in _repo_package_sources():
            return candidate
    return None


@functools.cache
def _repo_package_sources() -> frozenset[str]:
    """Every source under a ``messagefoundry*`` package, repo-relative, case as the tree spells it."""
    return frozenset(
        p.relative_to(REPO_ROOT).as_posix()
        for top in REPO_ROOT.glob("messagefoundry*")
        if (top / "__init__.py").is_file()
        for p in top.rglob("*.py")
    )


def test_module_path_is_case_exact() -> None:
    """A name that differs from a file only in case resolves to nothing, on every filesystem.

    An ``is_file()`` probe on Windows or macOS resolved ``messagefoundry.pipeline.Engine`` (the
    class) to ``pipeline/Engine.py``, a path the tree does not spell and no regex arm matches.
    """
    assert _module_path("messagefoundry.pipeline.engine") == "messagefoundry/pipeline/engine.py"
    assert _module_path("messagefoundry.pipeline.Engine") is None


def _engine_modules_imported_by(text: str) -> dict[str, str]:
    """Each ``messagefoundry*`` module one source's imports reach, mapped to its repo-relative path.

    ``import a.b.c`` records ``a.b.c``. ``from pkg import name`` records ``pkg``'s own file, which
    Python runs for that statement (for the top-level package, its ``__getattr__`` is consulted for
    ``name`` too), and also ``pkg.name`` when that is itself a module, as in
    ``from messagefoundry import sqlserver_roles``. So that spelling reaches
    ``messagefoundry/__init__.py`` as well as the submodule, and the gate reds while the ``serverdb``
    regex does not admit that init.

    Not recorded, by at least these routes, though Python runs or reaches the source: the ancestor
    packages' ``__init__`` files above the one a statement names, which run for every spelling; the
    modules an imported engine module itself imports; a re-exported attribute's defining module; and
    ``importlib.import_module``. The ``tests/`` helpers a suite imports are not followed HERE: this
    reads one source, and ``_helpers_reached_by_server_db_suites`` hands it each helper. Measured
    2026-11-23: ``messagefoundry/__init__.py``, ``messagefoundry/auth/__init__.py`` and
    ``messagefoundry/config/__init__.py`` run in server-DB suites by the first route; the
    ``serverdb`` regex admits all three since #5472, and ``messagefoundry_toolkit/__init__.py``,
    reached the same way. CORRECTED 2026-11-26: this read "admits none of them".
    """
    modules: list[str] = []
    for node in ast.walk(ast.parse(text)):
        if isinstance(node, ast.ImportFrom):
            if node.level or not (node.module or "").startswith("messagefoundry"):
                continue
            package = str(node.module)
            modules.append(package)
            modules += [f"{package}.{alias.name}" for alias in node.names]
        elif isinstance(node, ast.Import):
            modules += [a.name for a in node.names if a.name.startswith("messagefoundry")]
    return {module: path for module in modules if (path := _module_path(module)) is not None}


def _server_db_suite_files() -> set[str]:
    """The repo-relative files of the suites the server-DB steps run."""
    return {
        f"tests/{name}.py"
        for name in _files_run_by_server_db_steps()
        if (TESTS_DIR / f"{name}.py").is_file()
    }


#: The repo trees whose modules a server-DB suite may import beside the engine: its own test
#: helpers, and the load drivers the failover and connscale suites run.
_HELPER_ROOTS = ("tests", "harness")


@functools.cache
def _repo_helper_sources() -> frozenset[str]:
    """Every source under ``tests/`` and ``harness/``, repo-relative, case as the tree spells it."""
    return frozenset(
        p.relative_to(REPO_ROOT).as_posix()
        for root in _HELPER_ROOTS
        for p in (REPO_ROOT / root).rglob("*.py")
    )


def _helpers_imported_by(text: str) -> set[str]:
    """The ``tests/`` and ``harness/`` files one source's imports name, as repo-relative paths.

    ``from tests.pkg import name`` names ``pkg`` and, when it is a file, ``pkg.name``, as the
    engine scan above does, and the same for ``harness.*``. A bare name that is a root ``tests/``
    file, as in ``from _totp_clock import ...``, is that file: ``tests/`` is on ``sys.path`` when
    the suites run. Not followed, at least: a relative import (no file under ``tests/`` uses one),
    and ``importlib.import_module``.
    """
    names: list[str] = []
    for node in ast.walk(ast.parse(text)):
        if isinstance(node, ast.ImportFrom):
            if node.level or not node.module:
                continue
            names += [node.module] + [f"{node.module}.{alias.name}" for alias in node.names]
        elif isinstance(node, ast.Import):
            names += [a.name for a in node.names]
    found: set[str] = set()
    sources = _repo_helper_sources()
    for module in names:
        base = module.replace(".", "/")
        if base.split("/")[0] not in _HELPER_ROOTS:
            base = f"tests/{base}"
            if "/" in base.removeprefix("tests/"):
                continue
        found.update(c for c in (f"{base}.py", f"{base}/__init__.py") if c in sources)
    return found


@functools.cache
def _helpers_reached_by_server_db_suites() -> frozenset[str]:
    """The helper files the server-DB suites import, and the files those import, to a fixed point.

    Seeded with the step-run suites and ``tests/conftest.py``, which runs in every leg. A suite
    itself is left out of the result: invariant 2 already binds it. A helper runs inside the leg as
    surely as the suite does, so an edit to one alone must pull the leg too (#5472, S31-23).
    """
    suites = _server_db_suite_files()
    seeds = suites | {"tests/conftest.py"}
    reached: set[str] = {"tests/conftest.py"}
    todo = sorted(seeds)
    while todo:
        path = todo.pop()
        text = (REPO_ROOT / path).read_text(encoding="utf-8")
        new = _helpers_imported_by(text) - reached - suites
        reached |= new
        todo.extend(sorted(new))
    return frozenset(reached)


def _engine_modules_imported_by_server_db_suites() -> dict[str, str]:
    """Each ``messagefoundry`` module those suites, or the helpers they reach, import, by path.

    A fresh dict over one memoised scan, so a caller may change what it gets.
    """
    return dict(_engine_scan())


@functools.cache
def _engine_scan() -> tuple[tuple[str, str], ...]:
    paths: dict[str, str] = {}
    for path in sorted(_server_db_suite_files() | _helpers_reached_by_server_db_suites()):
        text = (REPO_ROOT / path).read_text(encoding="utf-8")
        paths.update(_engine_modules_imported_by(text))
    return tuple(paths.items())


@pytest.mark.parametrize(
    ("source", "expected"),
    [
        ("from tests._session_seal_contract import run", {"tests/_session_seal_contract.py"}),
        ("from tests import _session_seal_contract", {"tests/_session_seal_contract.py"}),
        ("import tests._live_scratch as scratch", {"tests/_live_scratch.py"}),
        ("from tests.test_alert_sinks import _sink", {"tests/test_alert_sinks.py"}),
        ("from messagefoundry import pki\nimport os", set()),
        ("from ._session_seal_contract import run", set()),
        ("from _totp_clock import FakeClock", {"tests/_totp_clock.py"}),
        ("import _failover_load_support", {"tests/_failover_load_support.py"}),
        (
            "from harness.load import failover",
            {"harness/load/__init__.py", "harness/load/failover.py"},
        ),
        ("import json, os.path", set()),
    ],
)
def test_the_helper_scan_resolves_tests_imports(source: str, expected: set[str]) -> None:
    assert _helpers_imported_by(source) == expected


def test_serverdb_path_gate_admits_every_tests_helper_those_suites_import() -> None:
    """A ``tests/`` helper a server-DB suite imports must pull the leg when edited (S31-23).

    Before #5472's S31-23 fix the gate named eight such helpers by file and missed at least 41
    others and 12 ``tests/test_*.py`` modules the suites import, among them
    ``tests/_session_seal_contract.py``, through which the suites reach ``auth/tokens``.
    """
    pattern = _serverdb_full_pattern()
    helpers = _helpers_reached_by_server_db_suites()
    assert len(helpers) >= 100, (
        f"the helper scan reached {len(helpers)} files, under the 107 measured on 2026-11-26; "
        "either it or the step parsing in _files_run_by_server_db_steps has drifted"
    )
    # One sentinel per route the scan follows: a tests.* import, a bare sys.path name, a harness.*
    # import, and the conftest seed. Dropping any one route reds here, whatever the count.
    sentinels = {
        "tests/_session_seal_contract.py",
        "tests/_failover_load_support.py",
        "harness/load/failover.py",
        "tests/conftest.py",
    }
    assert sentinels <= helpers, f"the scan lost a route: {sorted(sentinels - helpers)}"
    missed = sorted(path for path in helpers if not pattern.match(path))
    assert not missed, (
        f"{len(missed)} tests/ file(s) a SQL Server / PostgreSQL suite imports are not matched by "
        "the `serverdb` regex in .github/workflows/ci.yml, so editing one does NOT pull the leg "
        "that runs it on the PR:\n  " + "\n  ".join(missed)
    )


@pytest.mark.parametrize(
    ("source", "expected"),
    [
        # A submodule named through its package: the package's init, which runs, and the submodule.
        (
            "from messagefoundry import sqlserver_roles",
            {
                "messagefoundry": "messagefoundry/__init__.py",
                "messagefoundry.sqlserver_roles": "messagefoundry/sqlserver_roles.py",
            },
        ),
        (
            "from messagefoundry.store import postgres as pg, sqlserver",
            {
                "messagefoundry.store": "messagefoundry/store/__init__.py",
                "messagefoundry.store.postgres": "messagefoundry/store/postgres.py",
                "messagefoundry.store.sqlserver": "messagefoundry/store/sqlserver.py",
            },
        ),
        (
            "from messagefoundry import __main__ as cli",
            {
                "messagefoundry": "messagefoundry/__init__.py",
                "messagefoundry.__main__": "messagefoundry/__main__.py",
            },
        ),
        # An attribute of a module or package: that module or package's own file.
        (
            "from messagefoundry.sqlserver_roles import probed_grant",
            {"messagefoundry.sqlserver_roles": "messagefoundry/sqlserver_roles.py"},
        ),
        (
            "from messagefoundry import Message",
            {"messagefoundry": "messagefoundry/__init__.py"},
        ),
        # A class whose name matches a submodule's but for case is an attribute, on every OS.
        (
            "from messagefoundry.pipeline import Engine",
            {"messagefoundry.pipeline": "messagefoundry/pipeline/__init__.py"},
        ),
        # Both on one line: each name resolves on its own, beside the package.
        (
            "from messagefoundry import sqlserver_roles, Message",
            {
                "messagefoundry.sqlserver_roles": "messagefoundry/sqlserver_roles.py",
                "messagefoundry": "messagefoundry/__init__.py",
            },
        ),
        # The forms that already resolved stay resolved.
        (
            "import messagefoundry.sqlserver_roles as sqlserver_roles",
            {"messagefoundry.sqlserver_roles": "messagefoundry/sqlserver_roles.py"},
        ),
        # Other packages named messagefoundry* resolve by the same rule.
        (
            "from messagefoundry_toolkit import anon",
            {
                "messagefoundry_toolkit": "messagefoundry_toolkit/__init__.py",
                "messagefoundry_toolkit.anon": "messagefoundry_toolkit/anon/__init__.py",
            },
        ),
        ("from messagefoundry import *", {"messagefoundry": "messagefoundry/__init__.py"}),
        # A relative import is never an engine import, whatever it names.
        ("from .messagefoundry import sqlserver_roles", {}),
        ("import os; from pathlib import Path", {}),
    ],
)
def test_import_scan_resolves_from_imports_to_the_module_path(
    source: str, expected: dict[str, str]
) -> None:
    """A ``from`` import records the package it names, and also each name that is a submodule."""
    assert _engine_modules_imported_by(source) == expected


def _package_only_paths(text: str) -> set[str]:
    """The scan origin/main ran before 2026-11-23: ``from pkg import ...`` recorded ``pkg`` alone."""
    paths: set[str] = set()
    for node in ast.walk(ast.parse(text)):
        if isinstance(node, ast.ImportFrom) and not node.level:
            names = [node.module] if (node.module or "").startswith("messagefoundry") else []
        elif isinstance(node, ast.Import):
            names = [a.name for a in node.names if a.name.startswith("messagefoundry")]
        else:
            continue
        paths.update(path for m in names if (path := _module_path(str(m))) is not None)
    return paths


def test_the_scan_records_at_least_what_the_package_only_scan_did() -> None:
    """Resolving submodules may only ADD sources to the gate, never drop one.

    The 62 is a floor: the count both scans recorded on 2026-11-23, not a property of the gate. A
    drop below it means either the scan or the step parsing that feeds it lost sources, or a suite
    legitimately stopped importing a module it alone imported. In the second case, lower the floor
    to the new count in the same change.
    """
    recorded = set(_engine_modules_imported_by_server_db_suites().values())
    before: set[str] = set()
    for name in _files_run_by_server_db_steps():
        source = REPO_ROOT / "tests" / f"{name}.py"
        if source.is_file():
            before |= _package_only_paths(source.read_text(encoding="utf-8"))
    assert before <= recorded, f"dropped: {sorted(before - recorded)}"
    assert len(recorded) >= 62, (
        f"the scan recorded {len(recorded)} engine sources, below the floor of 62 measured on "
        "2026-11-23. If a server-DB suite legitimately stopped importing a module, lower the floor "
        "to the new count in the same change; otherwise the scan or the step parsing lost sources."
    )


def test_serverdb_path_gate_admits_every_source_those_suites_import() -> None:
    """Editing a SOURCE those suites assert against must pull the legs that prove it (#1322).

    The older invariant bound the ASSERTING file and not the ASSERTED-ON file, and could not see
    this class. It has already fired: a PR added a key to the ``summary_access`` audit detail built
    in ``messagefoundry/api/app.py``, touched ``api/`` only, so ``serverdb`` was false, the DB legs
    never ran on that PR, and it merged green leaving both server-DB store suites asserting the old
    shape.

    IMPORT-REACHABILITY IS A PROXY FOR "ASSERTS AGAINST". It is what a machine can check without
    running anything. It is wider than the assertion set in some ways, for example a module a suite
    imports and asserts nothing about, which costs extra leg-runs. It is NARROWER in others: it
    reads only the static import statements in the suites and the ``tests/`` helpers they reach,
    and
    ``_engine_modules_imported_by`` names at least four routes to a source it does not record. A
    green here does not show that every source a server-DB leg exercises pulls that leg.
    """
    pattern = _serverdb_full_pattern()
    imported = _engine_modules_imported_by_server_db_suites()
    assert imported, (
        "found no messagefoundry imports in the server-DB-gated suites — either the step parsing "
        "in _files_run_by_server_db_steps or the AST walk here has drifted"
    )

    unmatched = sorted(
        f"{module}  ({path})" for module, path in imported.items() if not pattern.match(path)
    )

    assert not unmatched, (
        f"{len(unmatched)} engine source(s) imported by a SQL Server / PostgreSQL suite are not "
        "matched by the `serverdb` change-detection regex in .github/workflows/ci.yml, so editing "
        "one does NOT pull the leg that would catch a regression in it on the PR — the leg first "
        "runs on it in the merge queue or on the nightly cron:\n  "
        + "\n  ".join(unmatched)
        + "\n\nExtend the SOURCE arms of that regex to cover them."
    )


def test_the_serverdb_gate_still_refuses_unrelated_paths() -> None:
    """Guard the guard: an alternation widened to match EVERYTHING passes the test above vacuously.

    That is the specific way the #1322 fix could go wrong -- a gate that admits every path is not a
    gate, and it would buy a green here while running the container legs on every pull request.
    """
    pattern = _serverdb_full_pattern()

    never_engine = [
        path
        for path in (
            "README.md",
            "docs/BACKLOG.md",
            # SHAPE probes for the helper arms #5472 added: each matches only if an arm loses its
            # `$`, or widens to the whole of tests/ or harness/.
            "tests/_live_scratch.py.orig",
            "tests/fixtures/_x.py",
            "tests/test_retention.py",
            "harness/window.py",
        )
        if pattern.match(path)
    ]
    assert not never_engine, (
        f"the `serverdb` regex admits {never_engine}, which no server-DB leg asserts against — the "
        "source arms have over-widened"
    )

    # And SOME engine source must still be refused. Derived rather than hard-coded, so this keeps
    # working as the tree grows: a named file could legitimately become imported one day.
    engine = {path for path in _repo_package_sources() if path.startswith("messagefoundry/")}
    assert engine, "found no engine sources — the rglob has drifted"
    assert any(not pattern.match(path) for path in engine), (
        "the `serverdb` regex admits EVERY file under messagefoundry/, so it selects nothing and "
        "the SQL Server / PostgreSQL legs would run on every pull request"
    )


@pytest.mark.parametrize("var", GATE_ENV_VARS)
def test_gate_env_var_is_still_exported_by_ci(var: str) -> None:
    """Guard the guard: a renamed gate var would make both tests above pass vacuously."""
    assert f"{var}: " in CI_YML.read_text(encoding="utf-8"), (
        f"{var} is exported by no ci.yml step. Either it was renamed — update GATE_ENV_VARS in "
        "this file — or the server-DB legs no longer run at all."
    )
