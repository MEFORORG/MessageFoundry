# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Unit tests for the acceptance harness framework — JUnit aggregation, runner mapping, reporting.

The aggregation/mapping/report logic is driven through an injected fake ``pytest_runner``, and
``default_pytest_runner`` through a faked ``subprocess.run``. One test runs a real pytest child on a
small suite, because only a real run shows what pytest's JUnit actually carries.
"""

from __future__ import annotations

import ast
import re
import subprocess
from collections.abc import Sequence
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from harness.acceptance.matrix import (
    MATRIX,
    ONCE,
    PER_DB,
    SERVER_SUITE_GATES,
    Coverage,
    MatrixRow,
    Status,
)
from harness.acceptance.report import (
    exit_code,
    render_console,
    render_csv,
    render_markdown,
)
from harness.acceptance.runner import (
    FileCounts,
    PytestRun,
    RowResult,
    _aggregate,
    _parse_junit_by_file,
    _pytest_row_result,
    default_pytest_runner,
    run_matrix,
)
from messagefoundry.terminal_text import escape_for_markdown_cell

_JUNIT = """<?xml version="1.0" encoding="utf-8"?>
<testsuites><testsuite name="pytest" tests="4">
  <testcase classname="tests.test_a" name="test_one" file="tests/test_a.py" time="0.1"/>
  <testcase classname="tests.test_a" name="test_two" file="tests/test_a.py" time="0.1">
    <skipped message="gated"/></testcase>
  <testcase classname="tests.test_b" name="test_three" file="tests/test_b.py" time="0.1">
    <failure message="boom">trace</failure></testcase>
  <testcase classname="tests.test_c" name="test_four" file="tests/test_c.py" time="0.1">
    <skipped message="gated"/></testcase>
</testsuite></testsuites>
"""


def test_parse_junit_aggregates_per_file(tmp_path: Path) -> None:
    junit = tmp_path / "junit.xml"
    junit.write_text(_JUNIT, encoding="utf-8")
    status, unattributed, counts = _parse_junit_by_file(junit)
    assert unattributed == []
    assert counts["tests/test_a.py"] == FileCounts(passed=1, skipped=1)
    assert counts["tests/test_b.py"] == FileCounts(failed=1)
    assert status["tests/test_a.py"] is Status.PASS  # one pass + one skip -> PASS
    assert status["tests/test_b.py"] is Status.FAIL
    assert status["tests/test_c.py"] is Status.SKIP  # all skipped


def test_parse_junit_missing_file_is_empty(tmp_path: Path) -> None:
    assert _parse_junit_by_file(tmp_path / "nope.xml") == ({}, [], {})


def test_aggregate_precedence() -> None:
    assert _aggregate([Status.PASS, Status.SKIP]) is Status.PASS
    assert _aggregate([Status.FAIL, Status.PASS]) is Status.FAIL
    assert _aggregate([Status.ERROR, Status.PASS]) is Status.ERROR
    assert _aggregate([Status.FAIL, Status.ERROR]) is Status.FAIL  # FAIL beats ERROR
    assert _aggregate([Status.SKIP]) is Status.SKIP
    assert _aggregate([]) is None


def test_aggregate_per_db_ranks_skip_above_pass() -> None:
    assert _aggregate([Status.PASS, Status.SKIP, Status.SKIP], per_db=True) is Status.SKIP
    assert _aggregate([Status.PASS, Status.PASS], per_db=True) is Status.PASS
    assert _aggregate([Status.SKIP, Status.ERROR], per_db=True) is Status.ERROR
    assert _aggregate([Status.SKIP, Status.FAIL], per_db=True) is Status.FAIL


def _fake_runner(node_ids: Sequence[str]) -> PytestRun:
    mapping = {
        "tests/test_store_backend.py": Status.PASS,
        "tests/test_sqlserver_store.py": Status.SKIP,
        "tests/test_postgres_store.py": Status.SKIP,
        "tests/test_settings.py": Status.PASS,
        "tests/test_store_encryption.py": Status.PASS,
        # test_keyprovider.py deliberately omitted -> the row should ERROR (requested, not collected)
        "tests/test_audit_offbox_tee.py": Status.PASS,
        "tests/test_task_resilience.py": Status.PASS,
        "tests/test_connection_resilience.py": Status.PASS,
    }
    return PytestRun({k: v for k, v in mapping.items() if k in set(node_ids)})


def test_run_matrix_maps_pytest_rows() -> None:
    results = {r.row.id: r for r in run_matrix(include_sections=["B"], pytest_runner=_fake_runner)}
    # B1 is Per-DB: SQLite passing while both server-DB suites skip leaves it unverified, not PASS.
    assert results["B1"].status is Status.SKIP
    assert results["B4"].status is Status.ERROR  # keyprovider not collected -> ERROR
    assert results["B5"].status is Status.PASS
    assert results["B6"].status is Status.PASS


def _fake_pytest(
    monkeypatch: pytest.MonkeyPatch, junit_text: str, code: pytest.ExitCode
) -> dict[str, Any]:
    """Stand in for the pytest subprocess: write ``junit_text`` where ``--junitxml`` points.

    Returns a dict that receives the keyword arguments the runner passed to ``subprocess.run``.
    """
    seen: dict[str, Any] = {}

    def fake_run(cmd: list[str], **kwargs: Any) -> Any:
        seen.update(kwargs)
        target = next(a for a in cmd if a.startswith("--junitxml=")).split("=", 1)[1]
        Path(target).write_text(junit_text, encoding="utf-8")
        return subprocess.CompletedProcess(cmd, int(code))

    monkeypatch.setattr(subprocess, "run", fake_run)
    return seen


_PASSING = """<?xml version="1.0" encoding="utf-8"?>
<testsuites><testsuite name="pytest" tests="1">
  <testcase classname="tests.test_a" name="test_one" file="tests/test_a.py" time="0.1"/>
</testsuite></testsuites>
"""


def _passing_plus(case: str) -> str:
    """``_PASSING`` with one more ``<testcase>`` element appended to its suite."""
    return _PASSING.replace("</testsuite>", f"  {case}\n</testsuite>")


def test_default_runner_flags_a_failure_with_no_file(monkeypatch: pytest.MonkeyPatch) -> None:
    fileless = '<testcase classname="" name="tests.conftest"><error message="boom"/></testcase>'
    _fake_pytest(monkeypatch, _passing_plus(fileless), pytest.ExitCode.TESTS_FAILED)
    run = default_pytest_runner(["tests/test_a.py"])
    assert run.by_file == {"tests/test_a.py": Status.PASS}
    assert "outside the row files" in run.run_error and "tests.conftest" in run.run_error


def test_default_runner_flags_a_failure_in_a_file_no_row_asked_for(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    junit = _passing_plus(
        '<testcase name="t" file="tests/helper.py"><failure message="x"/></testcase>'
    )
    _fake_pytest(monkeypatch, junit, pytest.ExitCode.TESTS_FAILED)
    assert "tests/helper.py" in default_pytest_runner(["tests/test_a.py"]).run_error


@pytest.mark.parametrize(
    "code",
    [
        pytest.ExitCode.INTERRUPTED,
        pytest.ExitCode.INTERNAL_ERROR,
        pytest.ExitCode.USAGE_ERROR,
        pytest.ExitCode.NO_TESTS_COLLECTED,
    ],
)
def test_default_runner_flags_a_broken_run_exit(
    monkeypatch: pytest.MonkeyPatch, code: pytest.ExitCode
) -> None:
    _fake_pytest(monkeypatch, _PASSING, code)
    assert default_pytest_runner(["tests/test_a.py"]).run_error == f"pytest exited {int(code)}"


def test_collection_error_in_a_row_file_reads_error_not_fail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    broken = '<testcase classname="" name="tests.test_b" file="tests/test_b.py">'
    broken += '<error message="collection failure">ImportError</error></testcase>'
    _fake_pytest(monkeypatch, _passing_plus(broken), pytest.ExitCode.TESTS_FAILED)
    run = default_pytest_runner(["tests/test_a.py", "tests/test_b.py"])
    assert run == PytestRun(
        {"tests/test_a.py": Status.PASS, "tests/test_b.py": Status.ERROR},
        counts={"tests/test_a.py": FileCounts(passed=1), "tests/test_b.py": FileCounts(errored=1)},
    )


def test_broken_run_exit_leads_the_run_error(monkeypatch: pytest.MonkeyPatch) -> None:
    fileless = '<testcase classname="" name="internal"><error message="x"/></testcase>'
    _fake_pytest(monkeypatch, _passing_plus(fileless), pytest.ExitCode.INTERNAL_ERROR)
    assert default_pytest_runner(["tests/test_a.py"]).run_error == "pytest exited 3"


def test_default_runner_flags_exit_1_that_no_row_file_explains(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _fake_pytest(monkeypatch, _PASSING, pytest.ExitCode.TESTS_FAILED)
    assert "no row file recorded a failure" in default_pytest_runner(["tests/test_a.py"]).run_error


def test_default_runner_accepts_exit_1_a_row_file_explains(monkeypatch: pytest.MonkeyPatch) -> None:
    _fake_pytest(monkeypatch, _JUNIT, pytest.ExitCode.TESTS_FAILED)
    run = default_pytest_runner(["tests/test_a.py", "tests/test_b.py", "tests/test_c.py"])
    assert run.run_error == ""
    assert run.by_file["tests/test_b.py"] is Status.FAIL


def test_default_runner_clean_exit_has_no_run_error(monkeypatch: pytest.MonkeyPatch) -> None:
    _fake_pytest(monkeypatch, _PASSING, pytest.ExitCode.OK)
    assert default_pytest_runner(["tests/test_a.py"]) == PytestRun(
        {"tests/test_a.py": Status.PASS}, counts={"tests/test_a.py": FileCounts(passed=1)}
    )


def test_default_runner_drops_pytest_addopts_from_the_child_env(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # An inherited partial deselect (``-k``/``-m``) would drop a failing test and keep its passing
    # siblings, so the row would read PASS.
    seen = _fake_pytest(monkeypatch, _PASSING, pytest.ExitCode.OK)
    monkeypatch.setenv("PYTEST_ADDOPTS", "-k 'not test_failing'")
    monkeypatch.setenv("MEFOR_TEST_SENTINEL", "kept")  # the scrub must not drop the rest of the env
    default_pytest_runner(["tests/test_a.py"])
    env = seen["env"]
    assert "PYTEST_ADDOPTS" not in env
    assert env["MEFOR_TEST_SENTINEL"] == "kept"


def test_default_runner_reports_truncated_junit_instead_of_crashing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _fake_pytest(monkeypatch, _PASSING[:80], pytest.ExitCode.TESTS_FAILED)
    run = default_pytest_runner(["tests/test_a.py"])
    assert run.by_file == {}
    assert run.run_error.startswith("unreadable JUnit XML")


def test_run_error_turns_every_pytest_row_to_error_but_keeps_fail() -> None:
    def broken(node_ids: Sequence[str]) -> PytestRun:
        statuses = dict.fromkeys(node_ids, Status.PASS)
        statuses["tests/test_audit_offbox_tee.py"] = Status.FAIL
        return PytestRun(statuses, "pytest exited 3")

    results = {r.row.id: r for r in run_matrix(include_sections=["B"], pytest_runner=broken)}
    assert results["B1"].status is Status.ERROR
    assert "run error: pytest exited 3" in results["B1"].detail
    assert results["B5"].status is Status.FAIL  # a real failure is not downgraded to ERROR


def test_per_db_row_passes_only_when_every_backend_suite_passed() -> None:
    def all_pass(node_ids: Sequence[str]) -> PytestRun:
        return PytestRun(dict.fromkeys(node_ids, Status.PASS))

    results = {r.row.id: r for r in run_matrix(include_sections=["B"], pytest_runner=all_pass)}
    assert results["B1"].status is Status.PASS


def test_once_row_still_passes_with_a_skipped_suite() -> None:
    once = MatrixRow("Z1", "Z", "t", ONCE, Coverage.PYTEST, ("tests/a.py", "tests/b.py"))
    mixed = PytestRun({"tests/a.py": Status.PASS, "tests/b.py": Status.SKIP})
    assert _pytest_row_result(once, mixed).status is Status.PASS
    per_db = replace(once, per_db=PER_DB)
    assert _pytest_row_result(per_db, mixed).status is Status.SKIP


_REPO_ROOT = Path(__file__).resolve().parents[1]
#: Any ``MEFOR_TEST_*`` name, in any case (Windows reads environment names case-insensitively), and
#: the bare prefix a name built at run time starts from (``f"MEFOR_TEST_{db}"``). Not derived from
#: the registry, so a gate the registry has never heard of is still found.
_TEST_GATE_NAME = re.compile(r"MEFOR_TEST\w*", re.IGNORECASE)


def _strip_docstrings(tree: ast.AST) -> None:
    """Drop every docstring, so a gate named only in prose (tests/test_cluster_lease.py) reads none."""
    for node in ast.walk(tree):
        body = getattr(node, "body", None)
        if (
            isinstance(body, list)
            and body
            and isinstance(body[0], ast.Expr)
            and isinstance(body[0].value, ast.Constant)
            and isinstance(body[0].value.value, str)
        ):
            body[0] = ast.Pass()


def server_gates(source: str) -> list[tuple[int, str]]:
    """Each ``MEFOR_TEST`` name in a string of ``source`` outside a docstring, as (line, name).

    Any mention counts, not only a skip condition, so at least these gate shapes are found: a
    ``skipif`` or ``xfail`` mark, ``pytest.skip`` or a raised ``SkipTest`` under an ``if``, and a
    local, class attribute or module name bound to the read, in any letter case, and a name built at
    run time from the whole ``MEFOR_TEST`` prefix. Not found: a gate in an imported helper or a
    conftest fixture, a prefix split across strings (``"MEFOR_" + "TEST_"``), and a gate on some
    other variable.
    """
    tree = ast.parse(source)
    _strip_docstrings(tree)
    hits: list[tuple[int, str]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            hits.extend((node.lineno, name) for name in _TEST_GATE_NAME.findall(node.value))
    return hits


def _callee(call: ast.Call) -> str:
    func = call.func
    return func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", "")


def _is_unset_test(cond: ast.expr, var: str) -> bool:
    """Whether ``cond`` is true exactly when ``var`` is unset, in one of the shapes the suites use.

    ``not os.getenv(VAR)``, ``not os.environ.get(VAR)`` and ``VAR not in os.environ``. Anything else
    reads as not proven, so an inverted or diluted condition fails the check.
    """
    if isinstance(cond, ast.UnaryOp) and isinstance(cond.op, ast.Not):
        call = cond.operand
        return (
            isinstance(call, ast.Call)
            and ast.unparse(call.func) in ("os.getenv", "os.environ.get")
            and len(call.args) == 1
            and not call.keywords
            and isinstance(call.args[0], ast.Constant)
            and call.args[0].value == var
        )
    return (
        isinstance(cond, ast.Compare)
        and isinstance(cond.left, ast.Constant)
        and cond.left.value == var
        and len(cond.ops) == 1
        and isinstance(cond.ops[0], ast.NotIn)
        and ast.unparse(cond.comparators[0]) == "os.environ"
    )


def skips_whole_unless(source: str, var: str) -> bool:
    """Whether the module's one ``pytestmark`` binding carries a skipif on ``var`` being unset.

    The name must appear exactly once in the module, at that top-level binding, so a rebinding in
    an ``if``, a ``for``, an import, or a mutation such as ``pytestmark.clear()`` reads as not proven.
    """
    tree = ast.parse(source)
    uses = sum(isinstance(n, ast.Name) and n.id == "pytestmark" for n in ast.walk(tree))
    uses += sum(
        "pytestmark" in (alias.name, alias.asname)
        for n in ast.walk(tree)
        if isinstance(n, (ast.Import, ast.ImportFrom))
        for alias in n.names
    )
    if uses != 1:
        return False
    value: ast.expr | None = None
    for stmt in tree.body:
        if (
            isinstance(stmt, ast.Assign)
            and any(isinstance(t, ast.Name) and t.id == "pytestmark" for t in stmt.targets)
            or (
                isinstance(stmt, ast.AnnAssign)
                and isinstance(stmt.target, ast.Name)
                and stmt.target.id == "pytestmark"
                and stmt.value is not None
            )
        ):
            value = stmt.value
    if value is None:
        return False
    marks = value.elts if isinstance(value, (ast.List, ast.Tuple)) else [value]
    return any(
        isinstance(mark, ast.Call)
        and ast.unparse(mark.func) == "pytest.mark.skipif"
        and len(mark.args) >= 1
        and _is_unset_test(mark.args[0], var)
        for mark in marks
    )


def _per_db_pytest_refs() -> set[str]:
    return {
        ref
        for row in MATRIX
        if row.is_per_db and row.coverage is Coverage.PYTEST
        for ref in row.refs
    }


@pytest.mark.parametrize("ref", sorted(SERVER_SUITE_GATES))
def test_every_server_suite_skips_whole_on_its_own_gate(ref: str) -> None:
    assert ref in _per_db_pytest_refs(), f"{ref} is registered but no Per-DB row names it"
    source = (_REPO_ROOT / ref).read_text(encoding="utf-8")
    own = SERVER_SUITE_GATES[ref]
    assert skips_whole_unless(source, own)
    # Gated whole on one backend, the file must not gate some tests on another backend too. Its own
    # variants (MEFOR_TEST_SQLSERVER_STRICT) only narrow a file that already skips whole.
    assert [hit for hit in server_gates(source) if not hit[1].upper().startswith(own)] == []


def test_no_other_per_db_file_gates_a_test_on_a_server_backend() -> None:
    # The no-mixed-file invariant: a file outside the registry that gated some tests on a server
    # backend would read PASS on its SQLite tests alone, with the server tests skipped.
    unregistered = sorted(_per_db_pytest_refs() - SERVER_SUITE_GATES.keys())
    # A floor, so an empty scan cannot read as no offenders: 15 unregistered Per-DB pytest refs
    # when this was written. Lower it only when a ref moves into SERVER_SUITE_GATES.
    assert len(unregistered) >= 15, unregistered
    offenders = {
        ref: hits
        for ref in unregistered
        if (hits := server_gates((_REPO_ROOT / ref).read_text(encoding="utf-8")))
    }
    assert offenders == {}


_MIXED_SOURCES = {
    "decorator": """
import os, pytest
def test_sqlite(): pass
@pytest.mark.skipif(not os.getenv("MEFOR_TEST_SQLSERVER"), reason="server")
def test_server(): pass
""",
    "skip under if": """
import os, pytest
@pytest.fixture
def server():
    if "MEFOR_TEST_POSTGRES" not in os.environ:
        pytest.skip("no server")
""",
    "through a local": """
import os, unittest
def test_server():
    on = os.getenv("MEFOR_TEST_SQLSERVER")
    if not on:
        raise unittest.SkipTest("no server")
""",
    "xfail mark": """
import os, pytest
@pytest.mark.xfail(not os.getenv("MEFOR_TEST_POSTGRES"), run=False, reason="server")
def test_server(): pass
""",
    "built at run time": """
import os, pytest
@pytest.fixture(params=["sqlite", "postgres"])
def backend(request):
    if request.param != "sqlite" and not os.getenv(f"MEFOR_TEST_{request.param.upper()}"):
        pytest.skip("no server")
""",
    "lower case": """
import os, pytest
@pytest.mark.skipif(not os.getenv("mefor_test_sqlserver"), reason="server")
def test_server(): pass
""",
    "a variant of a registered gate": """
import os, pytest
@pytest.mark.skipif(os.getenv("MEFOR_TEST_SQLSERVER_STRICT") != "1", reason="strict")
def test_strict(): pass
""",
    "a backend the registry does not name": """
import os, pytest
@pytest.mark.skipif(not os.getenv("MEFOR_TEST_ORACLE"), reason="server")
def test_server(): pass
""",
}


@pytest.mark.parametrize("shape", sorted(_MIXED_SOURCES))
def test_the_mixed_file_check_catches_a_per_test_server_gate(shape: str) -> None:
    # Negative control: each shape is a SQLite-plus-server file the invariant must refuse.
    source = _MIXED_SOURCES[shape]
    assert server_gates(source) != []
    assert not skips_whole_unless(source, "MEFOR_TEST_SQLSERVER")
    assert not skips_whole_unless(source, "MEFOR_TEST_POSTGRES")


_GATED = 'pytest.mark.skipif(not os.getenv("MEFOR_TEST_SQLSERVER"), reason="server")'


@pytest.mark.parametrize(
    ("pytestmark", "whole"),
    [
        (f"pytestmark = {_GATED}", True),
        (f"pytestmark = [pytest.mark.asyncio, {_GATED}]", True),
        (f"pytestmark: object = {_GATED}", True),
        (
            'pytestmark = pytest.mark.skipif(bool(os.getenv("MEFOR_TEST_SQLSERVER")), reason="x")',
            False,
        ),
        (
            'pytestmark = pytest.mark.skipif(not os.getenv("MEFOR_TEST_SQLSERVER") and False, reason="x")',
            False,
        ),
        (f"pytestmark = {_GATED}\npytestmark = pytest.mark.asyncio", False),
        (f"pytestmark = pytest.mark.asyncio({_GATED})", False),
        ("pytestmark: object", False),
        (f"pytestmark = {_GATED}\nif True:\n    pytestmark = pytest.mark.asyncio", False),
        (f"pytestmark = {_GATED}\npytestmark.args = ()", False),
        (f"pytestmark = {_GATED}\nfrom other import pytestmark", False),
    ],
)
def test_the_whole_file_check_reads_the_condition_not_a_mention(
    pytestmark: str, whole: bool
) -> None:
    source = f"import os, pytest\n{pytestmark}\n"
    assert skips_whole_unless(source, "MEFOR_TEST_SQLSERVER") is whole


def test_the_mixed_file_check_ignores_prose_and_other_settings() -> None:
    source = '''
"""Gated elsewhere on ``MEFOR_TEST_SQLSERVER``; this module is not."""
import os, pytest
def test_doc():
    """Mentions MEFOR_TEST_POSTGRES in prose only."""
    assert os.getenv("MEFOR_STORE_BACKEND", "sqlite")
'''
    assert server_gates(source) == []


_MIXED_JUNIT = """<?xml version="1.0" encoding="utf-8"?>
<testsuites><testsuite name="pytest" tests="3">
  <testcase classname="tests.test_mixed" name="test_sqlite" file="tests/test_mixed.py" time="0.1"/>
  <testcase classname="tests.test_mixed" name="test_sqlserver" file="tests/test_mixed.py" time="0.1">
    <skipped message="set MEFOR_TEST_SQLSERVER"/></testcase>
  <testcase classname="tests.test_mixed" name="test_postgres" file="tests/test_mixed.py" time="0.1">
    <skipped message="set MEFOR_TEST_POSTGRES"/></testcase>
</testsuite></testsuites>
"""


def test_a_mixed_file_reads_pass_with_its_counts(monkeypatch: pytest.MonkeyPatch) -> None:
    # Why the no-mixed-file invariant exists: within a file PASS outranks SKIP, so a Per-DB row whose
    # file mixed SQLite tests with skipped server tests would read PASS. The counts show the skips.
    _fake_pytest(monkeypatch, _MIXED_JUNIT, pytest.ExitCode.OK)
    run = default_pytest_runner(["tests/test_mixed.py"])
    assert run.counts["tests/test_mixed.py"] == FileCounts(passed=1, skipped=2)
    row = MatrixRow("Z2", "Z", "t", PER_DB, Coverage.PYTEST, ("tests/test_mixed.py",))
    result = _pytest_row_result(row, run)
    assert result.status is Status.PASS
    assert result.detail == "test_mixed.py=PASS (1 passed, 2 skipped)"


def test_an_xfail_is_not_counted_as_a_skip(tmp_path: Path) -> None:
    xfail = '<testcase name="t" file="tests/test_a.py"><skipped type="pytest.xfail"/></testcase>'
    junit = tmp_path / "junit.xml"
    junit.write_text(_passing_plus(xfail), encoding="utf-8")
    status, _, counts = _parse_junit_by_file(junit)
    assert status["tests/test_a.py"] is Status.PASS
    assert counts["tests/test_a.py"] == FileCounts(passed=1, xfailed=1)
    row = MatrixRow("Z3", "Z", "t", PER_DB, Coverage.PYTEST, ("tests/test_a.py",))
    run = PytestRun(status, counts=counts)
    assert _pytest_row_result(row, run).detail == "test_a.py=PASS"  # no skip to show


def test_default_runner_flags_a_report_that_attributes_nothing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The xunit2 shape: a clean exit whose testcases carry no ``file``.
    xunit2 = _PASSING.replace(' file="tests/test_a.py"', "")
    _fake_pytest(monkeypatch, xunit2, pytest.ExitCode.OK)
    assert "attributed no testcase" in default_pytest_runner(["tests/test_a.py"]).run_error


def test_default_runner_attributes_a_real_pytest_run(monkeypatch: pytest.MonkeyPatch) -> None:
    # The runner must shield the child from this: inherited, it would deselect everything, the child
    # would exit 5, and run_error would be set.
    monkeypatch.setenv("PYTEST_ADDOPTS", "-k nothing_matches")
    # One real child run: the hand-written JUnit above carries ``file=``, which pytest's default
    # JUnit family omits, so only a real run proves the argv lets results reach their rows.
    ref = "tests/test_win2025_acceptance.py"
    run = default_pytest_runner([ref])
    assert run.run_error == ""
    assert ref in run.by_file  # attributed; its own verdict is that suite's business


def test_run_matrix_no_pytest_skips_pytest_rows() -> None:
    results = {r.row.id: r for r in run_matrix(include_sections=["D"], run_pytest=False)}
    assert results["D1"].status is Status.SKIP  # PYTEST row, suites not run
    assert "pytest not run" in results["D1"].detail
    assert results["D3"].status is Status.MANUAL  # MANUAL row (SFTP endpoint)
    assert results["D9"].status is Status.MANUAL  # HARNESS row reported as MANUAL w/ command
    assert "harness" in results["D9"].detail


def test_run_matrix_section_filter_and_probes() -> None:
    results = run_matrix(include_sections=["A"], run_pytest=False)
    assert results, "section A produced no rows"
    assert all(r.row.section == "A" for r in results)
    # Probes must not ERROR in this environment.
    assert all(r.status is not Status.ERROR for r in results)


def test_reports_render(tmp_path: Path) -> None:
    results = run_matrix(include_sections=["A"], run_pytest=False)
    md = render_markdown(results)
    assert "## A." in md and "| A1 |" in md
    csv_text = render_csv(results)
    assert csv_text.splitlines()[0] == "id,section,title,per_db,coverage,status,detail,evidence"
    assert any(line.startswith("A1,") for line in csv_text.splitlines())
    console = render_console(results)
    assert "A1" in console and "exit" in console


def _md_data_rows(md: str) -> list[str]:
    # Every line starting with a pipe, whatever follows it, but the header and the rule. A forged
    # row spelled "|A9|..." still counts, so a regression cannot hide by dropping a space.
    return [
        line
        for line in md.splitlines()
        if line.startswith("|") and not line.startswith(("| ID |", "|---|"))
    ]


def test_render_markdown_keeps_a_hostile_detail_in_one_row() -> None:
    # BACKLOG #2897: the report escaped only the pipe, so a newline in a detail ended the row and
    # the peer's next line read as a forged one. Every cell now takes the verify report's rule.
    hostile = "boom\n| A9 | forged | x | PASS | all good |\r<img src=x>`c`$x$\x1b[2J"
    row = replace(MATRIX[0], id="A1|x", title=f"t{hostile}", per_db="p|q\nr")
    md = render_markdown([RowResult(row, Status.FAIL, hostile)])
    rows = _md_data_rows(md)
    assert len(rows) == 1  # the newline did not start a forged row
    assert rows[0].count("|") == 6  # five cells, every pipe the peer sent inert
    assert rows[0].startswith("| A1&#124;x | t")
    assert "| p&#124;q\\x0ar |" in rows[0]
    assert "\\x0a&#124; A9 &#124; forged" in rows[0]
    assert "\\x0d&lt;img src=x&gt;&#96;c&#96;&#36;x&#36;\\x1b[2J" in rows[0]
    assert not any(ch in md for ch in "\x1b\r<")


def test_render_markdown_uses_the_verify_reports_cell_rule() -> None:
    from messagefoundry.verify.model import CheckResult
    from messagefoundry.verify.model import Status as VerifyStatus
    from messagefoundry.verify.report import render_markdown as render_verify_markdown

    detail = "C:\\Users\\svc \u2014 see [store].path; a\\|b & `x`"
    row = RowResult(MATRIX[0], Status.FAIL, detail)
    acceptance = _md_data_rows(render_markdown([row]))
    verify = render_verify_markdown([CheckResult("a", "t", VerifyStatus.FAIL, detail)])
    assert len(acceptance) == 1
    cell = escape_for_markdown_cell(detail)
    assert acceptance[0].endswith(f"| {cell} |")
    assert f"| {cell} |" in verify
    assert cell == "C:\\Users\\svc \u2014 see [store].path; a\\\\&#124;b &amp; &#96;x&#96;"


def test_render_csv_neutralizes_formula_injection() -> None:
    # ASVS 1.2.10 / CWE-1236: a free-text cell (detail/evidence) beginning with a formula trigger is
    # prefixed with a literal "'", so opening the report CSV in Excel/Sheets can't execute it.
    results = [
        RowResult(MATRIX[0], Status.FAIL, "=cmd|'/c calc'!A1", evidence="@SUM(1)"),
    ]
    csv_text = render_csv(results)
    data_line = csv_text.splitlines()[1]
    assert "'=cmd" in data_line  # detail neutralized
    assert "'@SUM(1)" in data_line  # evidence neutralized
    # No cell in the data row reaches the file starting with a bare formula trigger. Asserted against
    # the SHARED constant, never a local copy: this line used to hardcode "=+-@\t\r\x00" — the old
    # four-writer set, missing LF — so an LF-leading cell reaching the CSV unescaped passed it. A
    # re-copied literal here is exactly the drift tests/test_csv_formula_consistency.py exists to stop.
    import csv

    from harness._spreadsheet import SPREADSHEET_FORMULA_TRIGGERS

    cells = next(csv.reader([data_line]))
    assert not any(cell[:1] in SPREADSHEET_FORMULA_TRIGGERS for cell in cells)


def test_exit_code() -> None:
    ok = [RowResult(MATRIX[0], Status.PASS, "ok"), RowResult(MATRIX[1], Status.MANUAL, "later")]
    assert exit_code(ok) == 0
    bad = ok + [RowResult(MATRIX[2], Status.FAIL, "boom")]
    assert exit_code(bad) == 1
    errored = ok + [RowResult(MATRIX[2], Status.ERROR, "broke")]
    assert exit_code(errored) == 1


def test_xlsx_write_back(tmp_path: Path) -> None:
    openpyxl = pytest.importorskip("openpyxl")  # not a project dep — only run where it's available
    from harness.acceptance.report import write_xlsx_status

    wb = openpyxl.Workbook()
    ws = wb.active
    ws.append(["ID", "Test item", "Per-DB?", "Status", "Result / evidence"])
    ws.append(["A1", "python runtime", "once", "", ""])
    ws.append(["A2", "extras", "once", "", ""])
    path = tmp_path / "matrix.xlsx"
    wb.save(path)

    results = run_matrix(include_sections=["A"], run_pytest=False)
    updated = write_xlsx_status(results, path)
    assert updated >= 2

    reloaded = openpyxl.load_workbook(path).active
    assert reloaded.cell(row=2, column=4).value  # A1 Status filled
    by_id = {r.row.id: r for r in results}
    assert reloaded.cell(row=2, column=4).value == by_id["A1"].status.value
