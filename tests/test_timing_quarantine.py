# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Pin the timing quarantine against the tree and against ci.yml (BACKLOG #4773).

The owner ruling of 2026-10-29 that authorises it is quoted in tests/timing_quarantine.txt.

``tests/timing_quarantine.txt`` takes tests off the engine legs, so it can fail in the two ways the
tooling manifest can, plus one of its own:

* an entry that names no test in the tree quarantines nothing, while the list reads as if it did;
* a marker the engine legs do not deselect, or a job that does not select it, is half a partition:
  the tests either still gate the merge or run nowhere;
* the quarantine job becoming a required context, a need of ci-gate, or a failed job, would put
  back the merge gate the ruling removed, or a false red signal on the PR.

Every check here runs in-process and reads files, with no child pytest: this file runs on the
engine legs (see ``_STAYS_WITHOUT_IMPORTING`` in tests/test_tooling_partition.py), because an edit
to the list alone does not trip the tooling job's path gate, and a guard there must not be a timing
risk of its own.
"""

from __future__ import annotations

import ast
import re
import tomllib
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from tests import _timing_quarantine as timing_quarantine
from tests import _tooling_manifest as tooling_manifest
from tests._workflow_contexts import jobs_of, needs_of, required_contexts, resolve

_ROOT = Path(__file__).resolve().parents[1]
_TESTS = _ROOT / "tests"
_JOB = "timing-quarantine"
_ENGINE_EXPRESSION = "not tooling and not timing_quarantine"
_RETIRE = (
    "tests/timing_quarantine.txt lists nothing. Its exit rule says to retire the mechanism in the "
    "change that empties it: the file, the marker, the ci.yml job and this test file"
)


def _ci_jobs() -> dict[str, dict[str, Any]]:
    return jobs_of("ci.yml")


def _engine_marker_expression() -> str:
    """The `-m` expression on the engine `Tests (pytest)` step's run line."""
    step = next(s for s in _ci_jobs()["test"]["steps"] if s.get("name") == "Tests (pytest)")
    found = re.findall(r"-m '([^']*)'", str(step.get("run", "")))
    assert len(found) == 1, f"expected one quoted -m expression on the engine step, found {found}"
    return found[0]


def _defines(path: Path, qualname: tuple[str, ...]) -> bool:
    """True when ``path`` defines ``qualname`` at module level: a function, or a class method."""
    body: list[ast.stmt] = ast.parse(path.read_text(encoding="utf-8")).body
    *owners, leaf = qualname
    for owner in owners:
        cls = next((n for n in body if isinstance(n, ast.ClassDef) and n.name == owner), None)
        if cls is None:
            return False
        body = cls.body
    return any(
        isinstance(n, ast.FunctionDef | ast.AsyncFunctionDef) and n.name == leaf for n in body
    )


def test_every_entry_resolves() -> None:
    """An entry naming a test that does not exist quarantines nothing.

    Read by AST, not by a collection run, so it stays cheap and untimed on the engine legs.
    Falsified by renaming one entry's function: RED, naming it. Restored.
    """
    entries = timing_quarantine.entries()
    print(f"[timing-quarantine] entries scanned: {len(entries)}")
    assert entries, _RETIRE
    missing = [
        e.node_id
        for e in entries
        if not (_ROOT / e.path).is_file() or not _defines(_ROOT / e.path, e.qualname)
    ]
    assert not missing, f"these quarantine entries name no test in the tree: {missing}"


class _Item(SimpleNamespace):
    """The three attributes the conftest hook reads off a collected item."""

    def add_marker(self, marker: pytest.MarkDecorator) -> None:
        self.marks.append(marker.name)


def _item(path: Path, nodeid: str) -> _Item:
    return _Item(path=path, nodeid=nodeid, marks=[])


def test_the_marking_function_marks_exactly_the_listed_tests() -> None:
    """The function the conftest hook calls, driven over one stand-in item per entry plus controls.

    The controls are a sibling test in a listed file (unmarked), a parametrized case of a listed
    test (marked: the suffix is dropped), and a same-named file outside tests/ (unmarked: the hook
    is scoped to files directly in tests/, as the tooling partition is).

    Falsified by deleting the `add_marker(pytest.mark.timing_quarantine)` line: RED. Restored.
    """
    entries = timing_quarantine.entries()
    assert entries, _RETIRE
    listed = [_item(_ROOT / e.path, e.node_id) for e in entries]
    first = entries[0]
    sibling = _item(_ROOT / first.path, f"{first.path}::not_{first.qualname[-1]}")
    param = _item(_ROOT / first.path, f"{first.node_id}[case-1]")
    elsewhere = _item(_ROOT / "packaging" / Path(first.path).name, first.node_id)
    timing_quarantine.mark_quarantined([*listed, sibling, param, elsewhere], _TESTS)
    unmarked = [i.nodeid for i in listed if "timing_quarantine" not in i.marks]
    assert not unmarked, f"the hook left these listed tests unmarked: {unmarked}"
    assert "timing_quarantine" not in sibling.marks, "the hook marked an unlisted sibling test"
    assert "timing_quarantine" in param.marks, "a parametrized case of a listed test went unmarked"
    assert "timing_quarantine" not in elsewhere.marks, "the hook marked a file outside tests/"


def test_the_conftest_hook_calls_the_marking_function() -> None:
    """Read by AST: importing tests/conftest.py a second time has side effects (see
    tests/test_conftest_name_collision_guard.py). Falsified by deleting the call: RED. Restored."""
    tree = ast.parse((_TESTS / "conftest.py").read_text(encoding="utf-8"))
    hook = next(
        n
        for n in tree.body
        if isinstance(n, ast.FunctionDef) and n.name == "pytest_collection_modifyitems"
    )
    calls = [
        n.func.attr
        for n in ast.walk(hook)
        if isinstance(n, ast.Call)
        and isinstance(n.func, ast.Attribute)
        and isinstance(n.func.value, ast.Name)
        and n.func.value.id == "timing_quarantine"
    ]
    assert calls == ["mark_quarantined"], calls


def test_the_engine_legs_deselect_the_marker() -> None:
    """Read off the run line, not the whole file, so a YAML comment cannot satisfy it."""
    assert _engine_marker_expression() == _ENGINE_EXPRESSION


def test_the_marker_is_registered() -> None:
    cfg = tomllib.loads((_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    markers = cfg["tool"]["pytest"]["ini_options"]["markers"]
    assert any(m.startswith("timing_quarantine:") for m in markers)


def test_the_quarantine_job_runs_the_marker_on_the_engine_legs_own_matrix() -> None:
    """The `test` job's matrix carries ubuntu-latest and windows-2025 (and windows-2022) here, so
    reading the same output runs the list wherever the engine legs ran it, with the same per-test
    caps. tests/test_ci_step_margin.py pins what those legs are."""
    jobs = _ci_jobs()
    job = jobs[_JOB]
    assert job["strategy"]["matrix"] == jobs["test"]["strategy"]["matrix"]
    assert job["runs-on"] == jobs["test"]["runs-on"]
    step = next(s for s in job["steps"] if "-m timing_quarantine " in str(s.get("run", "")))
    env = step.get("env") or {}
    assert env.get("PYTEST_TIMEOUT") == "${{ matrix.pytest_timeout }}", env
    assert env.get("FAULT_TIMEOUT") == "${{ matrix.fault_timeout }}", env


def test_the_quarantine_job_gates_no_merge_and_cannot_fail_the_run() -> None:
    """The ruling removed these tests from the merge gate; this keeps the job from putting it back.

    A failed job fails the whole CI run, and failure-signal.yml keys on the run's conclusion, so the
    pytest step must be `continue-on-error` and report through a warning instead.

    Falsified by adding the job to ci-gate's needs, and separately by dropping `continue-on-error`:
    RED both times. Restored.
    """
    jobs = _ci_jobs()
    assert _JOB not in needs_of(jobs["ci-gate"]), "ci-gate must not need the quarantine job"
    required = required_contexts()
    print(f"[timing-quarantine] required contexts scanned: {len(required)}")
    assert required, "required-contexts.txt parsed to nothing, so this check proves nothing"
    reporting = [c for c in required if resolve(c) == ("ci.yml", _JOB)]
    assert not reporting, f"{reporting} resolve to the quarantine job; the ruling keeps it advisory"
    step = next(s for s in jobs[_JOB]["steps"] if "-m timing_quarantine " in str(s.get("run", "")))
    assert step.get("continue-on-error") is True
    assert "::warning" in str(step["run"]) and "GITHUB_STEP_SUMMARY" in str(step["run"])


def test_no_quarantined_test_is_in_the_tooling_tier() -> None:
    """A tooling-tier file is already off the engine legs, and the tooling job does not deselect the
    quarantine, so listing one here would run it twice and quarantine nothing."""
    tooling = set(tooling_manifest.entries())
    both = sorted({e.path for e in timing_quarantine.entries()} & tooling)
    assert not both, f"quarantined tests in tooling-tier files: {both}"


@pytest.mark.parametrize(
    ("text", "complaint"),
    [
        ("tests/test_x.py::test_y\n", "an entry is"),
        ("tests/test_x.py::test_y  flaky, no row\n", "names no #<row>"),
        ("tests/test_x.py::test_y[a]  #1\n", "an entry is"),
        ("tests/test_x.py::test_y  #1\ntests/test_x.py::test_y  #2\n", "listed twice"),
    ],
)
def test_the_reader_refuses_a_malformed_list(text: str, complaint: str) -> None:
    with pytest.raises(ValueError, match=re.escape(complaint)):
        timing_quarantine.entries_from(text)


def test_the_reader_keeps_a_class_method_and_tolerates_a_bom_and_crlf() -> None:
    text = "﻿# header\r\n\r\ntests/test_x.py::TestA::test_b  timing; row #12\r\n"
    [entry] = timing_quarantine.entries_from(text)
    assert entry.path == "tests/test_x.py"
    assert entry.qualname == ("TestA", "test_b")
