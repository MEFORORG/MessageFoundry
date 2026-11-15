# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Execute the matrix: probes run in-process; ``PYTEST`` rows run the real suites once via subprocess.

The existing suites are run through a single ``python -m pytest … --junitxml`` subprocess (stdlib
JUnit parsing — no extra dependency, no pytest re-entrancy) and each row's verdict is aggregated from
its file(s). Server-DB suites self-skip off-server via their ``MEFOR_TEST_*`` gates, so a row backed
by ``test_postgres_store.py`` reports ``SKIP`` on a box without Postgres rather than failing.

``HARNESS`` and ``MANUAL`` rows are reported ``MANUAL`` with the command / instruction — never
auto-passed.
"""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path
from xml.etree import ElementTree

from harness.acceptance.matrix import MATRIX, Coverage, MatrixRow, Status
from harness.acceptance.probes import run_probe

_REPO_ROOT = Path(__file__).resolve().parents[2]

#: pytest's own "some tests failed" exit code; any other non-zero code means the run itself broke.
_PYTEST_TESTS_FAILED = 1


@dataclass(frozen=True)
class PytestRun:
    """What one pytest run reported: each requested file's :class:`Status`, plus a run-level error.

    ``run_error`` is non-empty when pytest reported a failure the per-file map cannot carry -- a
    non-zero exit no row file explains, a failing testcase outside the row files, unreadable JUnit,
    a timeout. Every ``PYTEST`` row is then ``ERROR`` (or ``FAIL``), never ``PASS``.
    """

    by_file: dict[str, Status]
    run_error: str = ""


#: A pytest runner runs the requested node-ids (files) once and reports a :class:`PytestRun`.
PytestRunner = Callable[[Sequence[str]], PytestRun]


@dataclass
class RowResult:
    """A matrix row paired with its executed outcome."""

    row: MatrixRow
    status: Status
    detail: str
    evidence: str = ""


def _normalize(path: str) -> str:
    return path.replace("\\", "/")


def _parse_junit_by_file(junit_path: Path) -> tuple[dict[str, Status], list[str]]:
    """Aggregate a pytest JUnit XML into one :class:`Status` per source file.

    Also returns the names of failing testcases that carry no ``file`` attribute (a collection or
    conftest error), which no row can own. Raises :class:`ElementTree.ParseError` on truncated XML.
    """
    if not junit_path.is_file():
        return {}, []
    tree = ElementTree.parse(junit_path)
    # Collect each file's testcase outcomes; precedence within a file: fail/error > pass > skip.
    per_file: dict[str, set[Status]] = {}
    unattributed: list[str] = []
    for case in tree.iter("testcase"):
        failed = case.find("failure") is not None or case.find("error") is not None
        file_attr = case.get("file")
        if not file_attr:
            if failed:
                unattributed.append(case.get("name") or case.get("classname") or "(unnamed)")
            continue
        key = _normalize(file_attr)
        if failed:
            outcome = Status.FAIL
        elif case.find("skipped") is not None:
            outcome = Status.SKIP
        else:
            outcome = Status.PASS
        per_file.setdefault(key, set()).add(outcome)

    result: dict[str, Status] = {}
    for key, outcomes in per_file.items():
        if Status.FAIL in outcomes:
            result[key] = Status.FAIL
        elif Status.PASS in outcomes:
            result[key] = Status.PASS
        else:  # only skips collected
            result[key] = Status.SKIP
    return result, unattributed


def _judge_run(
    node_ids: Sequence[str], returncode: int, by_file: dict[str, Status], unattributed: list[str]
) -> str:
    """Return the run-level error a per-file map would hide, or ``""`` when the map tells it all."""
    requested = {_normalize(n) for n in node_ids}
    outside = unattributed + sorted(
        k for k, s in by_file.items() if s is Status.FAIL and k not in requested
    )
    if outside:
        return f"pytest reported failures outside the row files: {', '.join(outside[:3])}"
    if returncode not in (0, _PYTEST_TESTS_FAILED):
        return f"pytest exited {returncode}"
    if returncode == _PYTEST_TESTS_FAILED and not any(
        by_file.get(k) is Status.FAIL for k in requested
    ):
        return f"pytest exited {returncode} but no row file recorded a failure"
    return ""


def default_pytest_runner(node_ids: Sequence[str], *, timeout: float = 1800.0) -> PytestRun:
    """Run the given pytest node-ids once and report a per-file :class:`Status` map.

    Files requested but absent from the result (collection error, missing path) are left out so the
    caller can mark their rows ``ERROR``. pytest's exit code is checked against that map, so a
    failure the map cannot carry becomes ``run_error`` rather than a silent ``PASS``.
    """
    if not node_ids:
        return PytestRun({})
    env = dict(os.environ)
    env.setdefault("QT_QPA_PLATFORM", "offscreen")  # console suites need a headless Qt platform
    with tempfile.TemporaryDirectory(prefix="mefor_accept_") as td:
        junit = Path(td) / "junit.xml"
        cmd = [
            sys.executable,
            "-m",
            "pytest",
            *node_ids,
            f"--junitxml={junit}",
            "-p",
            "no:cacheprovider",
            "-q",
            "--no-header",
        ]
        try:
            # Output is captured only to keep the console quiet; results come from the JUnit file.
            # Left as bytes, so no child line can fail a decode.
            proc = subprocess.run(  # noqa: S603 — fixed argv, no shell
                cmd, cwd=_REPO_ROOT, env=env, capture_output=True, timeout=timeout
            )
        except subprocess.TimeoutExpired:
            return PytestRun({}, f"pytest timed out after {timeout:g}s")
        try:
            by_file, unattributed = _parse_junit_by_file(junit)
        except ElementTree.ParseError as exc:
            return PytestRun({}, f"unreadable JUnit XML ({exc})")
        return PytestRun(by_file, _judge_run(node_ids, proc.returncode, by_file, unattributed))


def _aggregate(statuses: Iterable[Status]) -> Status | None:
    """Combine a row's per-file statuses. Precedence: FAIL > ERROR > PASS > SKIP. ``None`` if empty."""
    seen = list(statuses)
    if not seen:
        return None
    for level in (Status.FAIL, Status.ERROR, Status.PASS, Status.SKIP):
        if level in seen:
            return level
    return None


def _pytest_row_result(row: MatrixRow, run: PytestRun) -> RowResult:
    parts: list[str] = []
    statuses: list[Status] = []
    for ref in row.refs:
        key = _normalize(ref)
        status = run.by_file.get(key)
        if status is None:
            status = Status.ERROR  # requested but not collected (missing file / collection error)
        statuses.append(status)
        parts.append(f"{Path(key).name}={status.value}")
    agg = _aggregate(statuses) or Status.ERROR
    if run.run_error:
        # The run broke somewhere the per-file map cannot show, so no row of it may PASS or SKIP.
        if agg is not Status.FAIL:
            agg = Status.ERROR
        parts.append(f"run error: {run.run_error}")
    return RowResult(row, agg, ", ".join(parts), evidence=row.notes)


def run_matrix(
    rows: Sequence[MatrixRow] = MATRIX,
    *,
    run_pytest: bool = True,
    pytest_runner: PytestRunner = default_pytest_runner,
    include_sections: Sequence[str] | None = None,
) -> list[RowResult]:
    """Execute the matrix and return one :class:`RowResult` per row (in matrix order).

    ``include_sections`` (e.g. ``["A", "B"]``) restricts the run. ``run_pytest=False`` skips the
    suite subprocess (probe-only fast pass) — ``PYTEST`` rows then report ``SKIP``. ``pytest_runner``
    is injectable so tests can drive the aggregation without nesting pytest.
    """
    selected = [r for r in rows if include_sections is None or r.section in set(include_sections)]

    pytest_files = [ref for r in selected if r.coverage is Coverage.PYTEST for ref in r.refs]
    pytest_run = PytestRun({})
    if run_pytest and pytest_files:
        # de-dup preserving order
        ordered = list(dict.fromkeys(pytest_files))
        pytest_run = pytest_runner(ordered)

    results: list[RowResult] = []
    for row in selected:
        if row.coverage is Coverage.PROBE:
            probe = run_probe(row.refs[0]) if row.refs else None
            if probe is None:
                results.append(RowResult(row, Status.ERROR, "no probe key on a PROBE row"))
            else:
                results.append(RowResult(row, probe.status, probe.detail, probe.evidence))
        elif row.coverage is Coverage.PYTEST:
            if not run_pytest:
                results.append(RowResult(row, Status.SKIP, "pytest not run (--no-pytest)"))
            else:
                results.append(_pytest_row_result(row, pytest_run))
        elif row.coverage is Coverage.HARNESS:
            cmd = row.refs[0] if row.refs else "(see notes)"
            results.append(RowResult(row, Status.MANUAL, f"run: {cmd}", evidence=row.notes))
        else:  # Coverage.MANUAL
            results.append(RowResult(row, Status.MANUAL, row.notes or "manual on-box step"))
    return results
