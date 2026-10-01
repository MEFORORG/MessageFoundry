# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""``scripts/release/wheel_license_files.py``: what it refuses, and that both workflows run it.

BACKLOG #1192 and #2513. The toolkit and harness wheels shipped no LICENSE or NOTICE. The
declarations are checked in tests/test_packaging.py; this script checks each BUILT wheel, in
ci.yml's packaging-build job and in the release.yml job that builds it.
"""

from __future__ import annotations

import re
import zipfile
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import pytest
import yaml

from scripts.release.wheel_license_files import main, problems

_REPO = Path(__file__).resolve().parents[1]

_WHEEL = "messagefoundry_toolkit-0.4.0-py3-none-any.whl"
_DIST_INFO = "messagefoundry_toolkit-0.4.0.dist-info"
_GOOD = (
    "messagefoundry_toolkit/__init__.py",
    f"{_DIST_INFO}/licenses/LICENSE",
    f"{_DIST_INFO}/licenses/NOTICE",
)


def _wheel(path: Path, members: Sequence[str]) -> Path:
    with zipfile.ZipFile(path, "w") as zf:
        for member in members:
            zf.writestr(member, "x\n")
    return path


def test_a_wheel_with_both_files_in_its_own_dist_info_passes(tmp_path: Path) -> None:
    """POSITIVE CONTROL: every refusal below is evidence only while this passes."""
    assert problems(_wheel(tmp_path / _WHEEL, _GOOD)) == []


@pytest.mark.parametrize(
    ("members", "expected"),
    [
        (_GOOD[:2], f"{_DIST_INFO}/licenses/NOTICE is missing"),
        # The shape hatchling writes for a `../../LICENSE` entry, refused even beside a good copy.
        ((*_GOOD, f"{_DIST_INFO}/licenses/../../LICENSE"), "has a '..' component"),
        # A nested dist-info under the package tree must not stand in for the wheel's own.
        (
            (
                "messagefoundry_toolkit/__init__.py",
                "messagefoundry_toolkit/_vendor/x-1.0.dist-info/licenses/LICENSE",
                "messagefoundry_toolkit/_vendor/x-1.0.dist-info/licenses/NOTICE",
            ),
            f"{_DIST_INFO}/licenses/LICENSE is missing",
        ),
    ],
    ids=["missing-notice", "parent-path-member", "nested-dist-info-only"],
)
def test_the_check_refuses(tmp_path: Path, members: Sequence[str], expected: str) -> None:
    found = problems(_wheel(tmp_path / _WHEEL, members))
    assert any(expected in p for p in found), found


def test_a_pattern_that_matches_nothing_fails(tmp_path: Path) -> None:
    """An empty match is "nothing was checked", never a pass."""
    assert main([str(tmp_path / "*.whl")]) == 1


def test_main_passes_a_good_wheel_and_refuses_a_bad_one(tmp_path: Path) -> None:
    good = tmp_path / "good"
    good.mkdir()
    _wheel(good / _WHEEL, _GOOD)
    bad = tmp_path / "bad"
    bad.mkdir()
    _wheel(bad / _WHEEL, _GOOD[:1])
    assert main([str(good / "*.whl")]) == 0
    assert main([str(bad / "*.whl")]) == 1


def _jobs(workflow: str) -> dict[str, Any]:
    data = yaml.safe_load((_REPO / ".github" / "workflows" / workflow).read_text(encoding="utf-8"))
    jobs: dict[str, Any] = data["jobs"]
    return jobs


def _step_runs(job: dict[str, Any]) -> list[str]:
    return [str(s.get("run") or "") for s in job["steps"] if isinstance(s, dict)]


_SCRIPT = "python scripts/release/wheel_license_files.py "

#: Every separate distribution under packaging/, derived so a new one is checked on arrival.
_DISTRIBUTIONS = sorted(p.parent.name for p in _REPO.glob("packaging/*/pyproject.toml"))

_BUILD = re.compile(
    r"python -m build --wheel \./packaging/(?P<dist>[\w-]+) --outdir (?P<out>[\w-]+)"
)


def _builds(workflow: str) -> list[tuple[str, str, str]]:
    """Every separate-wheel build in ``workflow``, as ``(job, distribution, output directory)``."""
    return [
        (name, m["dist"], m["out"])
        for name, job in _jobs(workflow).items()
        for run in _step_runs(job)
        for m in _BUILD.finditer(run)
    ]


@pytest.mark.parametrize("workflow", ["ci.yml", "release.yml"])
def test_every_wheel_a_workflow_builds_is_checked_in_the_job_that_built_it(workflow: str) -> None:
    """The script guards nothing unless each job that builds a separate wheel runs it on that wheel.

    The builds are read from the workflow, not listed here, and every distribution under
    packaging/ must be among them, so a fourth wheel cannot ship unchecked. The toolkit is
    BACKLOG #1192; the web console and harness are BACKLOG #2513.
    """
    builds = _builds(workflow)
    # At least the three distributions known today, so an empty glob cannot pass this vacuously.
    assert len(_DISTRIBUTIONS) >= 3, _DISTRIBUTIONS
    built = {dist for _, dist, _ in builds}
    assert set(_DISTRIBUTIONS) <= built, (
        f"{workflow} never builds {sorted(set(_DISTRIBUTIONS) - built)}"
    )
    unchecked = []
    for job, dist, out in builds:
        calls = [
            line.strip()
            for run in _step_runs(_jobs(workflow)[job])
            for line in run.splitlines()
            if line.strip().startswith(_SCRIPT)
        ]
        if sum(f"'{out}/*.whl'" in call for call in calls) != 1:
            unchecked.append(f"{job}: {dist} -> {out}/ ({calls})")
    assert not unchecked, f"{workflow}: these wheels are not checked exactly once: {unchecked}"
