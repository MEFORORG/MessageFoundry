# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Unit tests for the acceptance harness framework — JUnit aggregation, runner mapping, reporting.

The aggregation/mapping/report logic is driven through an injected fake ``pytest_runner``, and
``default_pytest_runner`` through a faked ``subprocess.run``. One test runs a real pytest child on a
small suite, because only a real run shows what pytest's JUnit actually carries.
"""

from __future__ import annotations

import subprocess
from collections.abc import Sequence
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from harness.acceptance.matrix import MATRIX, ONCE, PER_DB, Coverage, MatrixRow, Status
from harness.acceptance.report import (
    exit_code,
    render_console,
    render_csv,
    render_markdown,
)
from harness.acceptance.runner import (
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
    status, unattributed = _parse_junit_by_file(junit)
    assert unattributed == []
    assert status["tests/test_a.py"] is Status.PASS  # one pass + one skip -> PASS
    assert status["tests/test_b.py"] is Status.FAIL
    assert status["tests/test_c.py"] is Status.SKIP  # all skipped


def test_parse_junit_missing_file_is_empty(tmp_path: Path) -> None:
    assert _parse_junit_by_file(tmp_path / "nope.xml") == ({}, [])


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


def _fake_pytest(monkeypatch: pytest.MonkeyPatch, junit_text: str, code: pytest.ExitCode) -> None:
    """Stand in for the pytest subprocess: write ``junit_text`` where ``--junitxml`` points."""

    def fake_run(cmd: list[str], **_: Any) -> Any:
        target = next(a for a in cmd if a.startswith("--junitxml=")).split("=", 1)[1]
        Path(target).write_text(junit_text, encoding="utf-8")
        return subprocess.CompletedProcess(cmd, int(code))

    monkeypatch.setattr(subprocess, "run", fake_run)


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
    assert run == PytestRun({"tests/test_a.py": Status.PASS, "tests/test_b.py": Status.ERROR})


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
    assert default_pytest_runner(["tests/test_a.py"]) == PytestRun({"tests/test_a.py": Status.PASS})


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


def test_default_runner_flags_a_report_that_attributes_nothing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The xunit2 shape: a clean exit whose testcases carry no ``file``.
    xunit2 = _PASSING.replace(' file="tests/test_a.py"', "")
    _fake_pytest(monkeypatch, xunit2, pytest.ExitCode.OK)
    assert "attributed no testcase" in default_pytest_runner(["tests/test_a.py"]).run_error


def test_default_runner_attributes_a_real_pytest_run(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("PYTEST_ADDOPTS", raising=False)  # an outer -k or -m would empty the child
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
