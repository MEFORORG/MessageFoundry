# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""``scripts/release/wheel_license_files.py``: what it refuses, and that both workflows run it.

BACKLOG #1192 and #2513. The toolkit and harness wheels shipped no LICENSE or NOTICE. The
declarations are checked in tests/test_packaging.py; this script checks each BUILT wheel, in
ci.yml's packaging-build job and in the release.yml job that builds it.
"""

from __future__ import annotations

import zipfile
from collections.abc import Sequence
from pathlib import Path

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


def _step_runs(workflow: str, job: str) -> list[str]:
    data = yaml.safe_load((_REPO / ".github" / "workflows" / workflow).read_text(encoding="utf-8"))
    return [str(s.get("run") or "") for s in data["jobs"][job]["steps"] if isinstance(s, dict)]


_SCRIPT = "python scripts/release/wheel_license_files.py "


@pytest.mark.parametrize(
    ("workflow", "job", "wheels"),
    [
        ("ci.yml", "packaging-build", "toolkit-dist/*.whl"),
        ("ci.yml", "packaging-build", "webconsole-dist/*.whl"),
        ("ci.yml", "packaging-build", "harness-dist/*.whl"),
        ("release.yml", "release", "toolkit-dist/*.whl"),
        ("release.yml", "release-webconsole", "webconsole-dist/*.whl"),
        ("release.yml", "release-harness", "harness-dist/*.whl"),
    ],
)
def test_each_workflow_checks_the_wheels_it_built(workflow: str, job: str, wheels: str) -> None:
    """The script guards nothing unless a workflow runs it on each separate wheel it built.

    The toolkit (BACKLOG #1192), web console and harness (BACKLOG #2513) wheels, in CI's
    packaging-build job and in the release job that builds each one.
    """
    calls = [
        line.strip()
        for run in _step_runs(workflow, job)
        for line in run.splitlines()
        if line.strip().startswith(_SCRIPT)
    ]
    assert calls, f"{workflow} `{job}` never runs {_SCRIPT.strip()}"
    naming = [call for call in calls if f"'{wheels}'" in call]
    assert len(naming) == 1, f"{workflow} `{job}` checks {wheels!r} in {len(naming)} calls: {calls}"
