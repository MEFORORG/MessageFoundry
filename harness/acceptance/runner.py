# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
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
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable, Sequence
from xml.etree import ElementTree

from harness.acceptance.matrix import MATRIX, Coverage, MatrixRow, Status
from harness.acceptance.probes import run_probe

_REPO_ROOT = Path(__file__).resolve().parents[2]

#: A pytest runner maps each requested node-id (file) to its aggregated :class:`Status`.
PytestRunner = Callable[[Sequence[str]], "dict[str, Status]"]


@dataclass
class RowResult:
    """A matrix row paired with its executed outcome."""

    row: MatrixRow
    status: Status
    detail: str
    evidence: str = ""


def _normalize(path: str) -> str:
    return path.replace("\\", "/")


def _parse_junit_by_file(junit_path: Path) -> dict[str, Status]:
    """Aggregate a pytest JUnit XML into one :class:`Status` per source file."""
    if not junit_path.is_file():
        return {}
    tree = ElementTree.parse(junit_path)
    # Collect each file's testcase outcomes; precedence within a file: fail/error > pass > skip.
    per_file: dict[str, set[Status]] = {}
    for case in tree.iter("testcase"):
        file_attr = case.get("file")
        if not file_attr:
            continue
        key = _normalize(file_attr)
        if case.find("failure") is not None or case.find("error") is not None:
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
    return result


def default_pytest_runner(node_ids: Sequence[str], *, timeout: float = 1800.0) -> dict[str, Status]:
    """Run the given pytest node-ids once and return a per-file :class:`Status` map.

    Files requested but absent from the result (collection error, missing path) are left out so the
    caller can mark their rows ``ERROR``.
    """
    if not node_ids:
        return {}
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
            subprocess.run(  # noqa: S603 — fixed argv, no shell
                cmd, cwd=_REPO_ROOT, env=env, capture_output=True, text=True, timeout=timeout
            )
        except subprocess.TimeoutExpired:
            return {}  # caller marks all requested rows ERROR (nothing parsed back)
        return _parse_junit_by_file(junit)


def _aggregate(statuses: Iterable[Status]) -> Status | None:
    """Combine a row's per-file statuses. Precedence: FAIL > ERROR > PASS > SKIP. ``None`` if empty."""
    seen = list(statuses)
    if not seen:
        return None
    for level in (Status.FAIL, Status.ERROR, Status.PASS, Status.SKIP):
        if level in seen:
            return level
    return None


def _pytest_row_result(row: MatrixRow, file_status: dict[str, Status]) -> RowResult:
    parts: list[str] = []
    statuses: list[Status] = []
    for ref in row.refs:
        key = _normalize(ref)
        status = file_status.get(key)
        if status is None:
            status = Status.ERROR  # requested but not collected (missing file / collection error)
        statuses.append(status)
        parts.append(f"{Path(key).name}={status.value}")
    agg = _aggregate(statuses) or Status.ERROR
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
    file_status: dict[str, Status] = {}
    if run_pytest and pytest_files:
        # de-dup preserving order
        ordered = list(dict.fromkeys(pytest_files))
        file_status = pytest_runner(ordered)

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
                results.append(_pytest_row_result(row, file_status))
        elif row.coverage is Coverage.HARNESS:
            cmd = row.refs[0] if row.refs else "(see notes)"
            results.append(RowResult(row, Status.MANUAL, f"run: {cmd}", evidence=row.notes))
        else:  # Coverage.MANUAL
            results.append(RowResult(row, Status.MANUAL, row.notes or "manual on-box step"))
    return results
