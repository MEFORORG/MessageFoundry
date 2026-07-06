# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Unit tests for the acceptance harness framework — JUnit aggregation, runner mapping, reporting.

These never nest pytest: the suite-execution seam is injected (a fake ``pytest_runner``), so the
deterministic aggregation/mapping/report logic is exercised in isolation.
"""

from __future__ import annotations

from pathlib import Path
from typing import Sequence

from harness.acceptance.matrix import MATRIX, Status
from harness.acceptance.report import (
    exit_code,
    render_console,
    render_csv,
    render_markdown,
)
from harness.acceptance.runner import (
    RowResult,
    _aggregate,
    _parse_junit_by_file,
    run_matrix,
)

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
    status = _parse_junit_by_file(junit)
    assert status["tests/test_a.py"] is Status.PASS  # one pass + one skip -> PASS
    assert status["tests/test_b.py"] is Status.FAIL
    assert status["tests/test_c.py"] is Status.SKIP  # all skipped


def test_parse_junit_missing_file_is_empty(tmp_path: Path) -> None:
    assert _parse_junit_by_file(tmp_path / "nope.xml") == {}


def test_aggregate_precedence() -> None:
    assert _aggregate([Status.PASS, Status.SKIP]) is Status.PASS
    assert _aggregate([Status.FAIL, Status.PASS]) is Status.FAIL
    assert _aggregate([Status.ERROR, Status.PASS]) is Status.ERROR
    assert _aggregate([Status.FAIL, Status.ERROR]) is Status.FAIL  # FAIL beats ERROR
    assert _aggregate([Status.SKIP]) is Status.SKIP
    assert _aggregate([]) is None


def _fake_runner(node_ids: Sequence[str]) -> dict[str, Status]:
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
    return {k: v for k, v in mapping.items() if k in set(node_ids)}


def test_run_matrix_maps_pytest_rows() -> None:
    results = {r.row.id: r for r in run_matrix(include_sections=["B"], pytest_runner=_fake_runner)}
    assert results["B1"].status is Status.PASS  # PASS + SKIP + SKIP -> PASS
    assert results["B4"].status is Status.ERROR  # keyprovider not collected -> ERROR
    assert results["B5"].status is Status.PASS
    assert results["B6"].status is Status.PASS


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


def test_exit_code() -> None:
    ok = [RowResult(MATRIX[0], Status.PASS, "ok"), RowResult(MATRIX[1], Status.MANUAL, "later")]
    assert exit_code(ok) == 0
    bad = ok + [RowResult(MATRIX[2], Status.FAIL, "boom")]
    assert exit_code(bad) == 1
    errored = ok + [RowResult(MATRIX[2], Status.ERROR, "broke")]
    assert exit_code(errored) == 1


def test_xlsx_write_back(tmp_path: Path) -> None:
    import pytest

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
