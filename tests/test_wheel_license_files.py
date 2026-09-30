# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""``scripts/release/wheel_license_files.py``: what it refuses, and that both workflows run it.

BACKLOG #1192. The toolkit wheel shipped no LICENSE or NOTICE. The declaration is checked in
tests/test_packaging.py; this script checks the BUILT wheel, in ci.yml's packaging-build job and
in release.yml's toolkit gate.
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


@pytest.mark.parametrize(
    ("workflow", "job"), [("ci.yml", "packaging-build"), ("release.yml", "release")]
)
def test_both_workflows_check_the_built_toolkit_wheel(workflow: str, job: str) -> None:
    """The script guards nothing unless a workflow runs it on the toolkit wheel it built."""
    call = "python scripts/release/wheel_license_files.py 'toolkit-dist/*.whl'"
    runs = [r for r in _step_runs(workflow, job) if call in r]
    assert len(runs) == 1, f"{workflow} `{job}` runs {call!r} in {len(runs)} steps"
