# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Pin the timing quarantine against the tree and against ci.yml (BACKLOG #4773).

Owner ruling 2026-10-29, verbatim: "Go on fix 1: make the Step margin guard advisory in merge_group
until #3515 re-measures the cap, and quarantine the recurring timing tests under #4773."

``tests/timing_quarantine.txt`` takes tests off the engine legs, so it can fail in the two ways the
tooling manifest can, plus one of its own:

* an entry that names no collected test quarantines nothing, while the list reads as if it did;
* a marker the engine legs do not deselect, or a job that does not select it, is half a partition:
  the tests either still gate the merge or run nowhere;
* the quarantine job becoming a required context, or a need of ci-gate, would put back the merge
  gate the ruling removed.

This file stays on the engine legs (see ``_STAYS_WITHOUT_IMPORTING`` in
tests/test_tooling_partition.py), because an edit to the list alone does not trip the tooling job's
path gate.
"""

from __future__ import annotations

import ast
import re
import subprocess
import sys
import tomllib
from pathlib import Path
from typing import Any

import pytest

from tests import _timing_quarantine as timing_quarantine
from tests import _tooling_manifest as tooling_manifest

_ROOT = Path(__file__).resolve().parents[1]
_CI = _ROOT / ".github" / "workflows" / "ci.yml"
_REQUIRED = _ROOT / ".github" / "required-contexts.txt"
_JOB = "timing-quarantine"
_ENGINE_EXPRESSION = "not tooling and not timing_quarantine"


def _jobs() -> dict[str, Any]:
    yaml = pytest.importorskip("yaml")
    doc = yaml.safe_load(_CI.read_text(encoding="utf-8"))
    jobs: dict[str, Any] = doc["jobs"]
    return jobs


def _engine_marker_expression() -> str:
    """The `-m` expression on the engine `Tests (pytest)` step's run line."""
    step = next(s for s in _jobs()["test"]["steps"] if s.get("name") == "Tests (pytest)")
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


def test_the_list_is_not_empty_and_every_entry_resolves() -> None:
    """An entry naming a test that does not exist quarantines nothing.

    Read by AST, not by a collection run, so this stays cheap enough for the engine legs.
    Falsified by renaming one entry's function: RED, naming it. Restored.
    """
    entries = timing_quarantine.entries()
    print(f"[timing-quarantine] entries scanned: {len(entries)}")
    assert entries, "tests/timing_quarantine.txt lists nothing, so this scan proves nothing"
    missing = [
        e.node_id
        for e in entries
        if not (_ROOT / e.path).is_file() or not _defines(_ROOT / e.path, e.qualname)
    ]
    assert not missing, f"these quarantine entries name no test in the tree: {missing}"


def test_the_marker_selects_the_list_and_the_engine_expression_leaves_it_out() -> None:
    """The hook, end to end: collect the listed files with the job's `-m` and the engine legs' `-m`.

    The engine expression is read out of ci.yml rather than restated, so a ci.yml edit that drops
    the deselection reds here. The control is that the engine expression still collects the other
    tests of those files, so an empty collection cannot pass for a correct one.
    """
    ids = timing_quarantine.node_ids()
    files = sorted({node.split("::", 1)[0] for node in ids})

    def collect(expression: str) -> set[str]:
        done = subprocess.run(
            [sys.executable, "-m", "pytest", "--collect-only", "-q", "-p", "no:cacheprovider"]
            + ["-m", expression, *files],
            cwd=_ROOT,
            capture_output=True,
            text=True,
            timeout=300,
            check=False,
        )
        assert done.returncode in (0, 5), done.stdout[-2000:] + done.stderr[-2000:]
        # Only the node-id lines: the warnings summary also prints `Test: tests/...::...` lines.
        lines = done.stdout.splitlines()
        return {line.partition("[")[0] for line in lines if line.startswith("tests/")}

    selected = collect("timing_quarantine")
    engine = collect(_engine_marker_expression())
    print(f"[timing-quarantine] -m timing_quarantine: {len(selected)}; engine: {len(engine)}")
    assert selected == ids, f"selected {sorted(selected ^ ids)} differently from the list"
    assert not (engine & ids), f"the engine legs still collect {sorted(engine & ids)}"
    assert engine, "the engine expression collected nothing from these files: the control failed"


def test_the_engine_legs_deselect_the_marker() -> None:
    assert _engine_marker_expression() == _ENGINE_EXPRESSION


def test_the_marker_is_registered() -> None:
    cfg = tomllib.loads((_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    markers = cfg["tool"]["pytest"]["ini_options"]["markers"]
    assert any(m.startswith("timing_quarantine:") for m in markers)


def test_the_quarantine_job_selects_the_marker_on_ubuntu_and_windows_2025() -> None:
    job = _jobs()[_JOB]
    oses = set(job["strategy"]["matrix"]["os"])
    assert {"ubuntu-latest", "windows-2025"} <= oses, oses
    runs = " ".join(str(s.get("run", "")) for s in job["steps"])
    assert "-m timing_quarantine " in runs, "the quarantine job no longer selects the marker"


def test_the_quarantine_job_gates_no_merge() -> None:
    """The ruling removed these tests from the merge gate; this keeps the job from putting it back.

    Falsified by adding the job to ci-gate's needs, and separately by appending its check name to
    a copy of required-contexts.txt: RED both times. Restored.
    """
    jobs = _jobs()
    needs = jobs["ci-gate"]["needs"]
    assert _JOB not in needs, "ci-gate must not need the quarantine job"
    check_name = str(jobs[_JOB]["name"]).split("(", 1)[0].strip()
    required = [
        line.strip()
        for line in _REQUIRED.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]
    print(f"[timing-quarantine] required contexts scanned: {len(required)}")
    assert required, "required-contexts.txt parsed to nothing, so this check proves nothing"
    assert not [c for c in required if c.startswith(check_name)], (
        f"{check_name!r} is a required context; the ruling keeps it advisory"
    )


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


def test_the_reader_keeps_a_class_method_and_drops_comments() -> None:
    text = "# header\n\ntests/test_x.py::TestA::test_b  timing; row #12\r\n"
    [entry] = timing_quarantine.entries_from(text)
    assert entry.path == "tests/test_x.py"
    assert entry.qualname == ("TestA", "test_b")
