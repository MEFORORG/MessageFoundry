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
3. **It also admits the engine SOURCES those suites import** (BACKLOG #1322), as far as a
   static read of the suites' own import statements finds them; the scan's docstring names at
   least four routes it does not follow. Invariant 2 binds the
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
    modules an imported engine module itself imports; a re-exported attribute's defining module; the
    helper modules a suite imports from ``tests/``; and ``importlib.import_module``. Measured
    2026-11-23: ``messagefoundry/__init__.py``, ``messagefoundry/auth/__init__.py`` and
    ``messagefoundry/config/__init__.py`` run in server-DB suites by the first route, and the
    ``serverdb`` regex admits none of them. Closing that is a ``ci.yml`` edit, not made here.
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


def _engine_modules_imported_by_server_db_suites() -> dict[str, str]:
    """Each ``messagefoundry`` module those suites import, mapped to its repo-relative path."""
    paths: dict[str, str] = {}
    for name in sorted(_files_run_by_server_db_steps()):
        source = REPO_ROOT / "tests" / f"{name}.py"
        if source.is_file():
            paths.update(_engine_modules_imported_by(source.read_text(encoding="utf-8")))
    return paths


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

    The floor is the 62 sources both scans recorded on 2026-11-23. A drop below it means the scan,
    or the step parsing that feeds it, lost sources.
    """
    recorded = set(_engine_modules_imported_by_server_db_suites().values())
    before: set[str] = set()
    for name in _files_run_by_server_db_steps():
        source = REPO_ROOT / "tests" / f"{name}.py"
        if source.is_file():
            before |= _package_only_paths(source.read_text(encoding="utf-8"))
    assert before <= recorded, f"dropped: {sorted(before - recorded)}"
    assert len(recorded) >= 62, f"recorded only {len(recorded)} sources"


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
    reads only the static import statements in the suites themselves, and
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

    never_engine = [path for path in ("README.md", "docs/BACKLOG.md") if pattern.match(path)]
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
