# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The CI `packaging` path gate admits what the `packaging-build` job reads (BACKLOG #5472).

`ci.yml`'s `changes` job decides whether `packaging-build` runs on a pull request. That job is the
only one outside a release tag that builds every distribution, and `ci-gate` reads a skipped need
as a pass, so a file the build reads that no arm names merges green unbuilt. Before #5472 the arm
missed `ci/locks/release-tools.lock`, which the job installs its build backend from, and the root
files the engine build reads by name: README.md, CHANGELOG.md, LICENSE and NOTICE.

Both sides are READ, never copied: the regex out of `ci.yml`, and the inputs out of the job's own
`-r` installs and the root `pyproject.toml`, so a new lock or a new shipped root file is met here.
Pure text analysis: Python's ``re`` reads this pattern as GNU ``grep -E`` does, since it uses only
groups, alternation, escaped dots and ``^``/``$``.
"""

from __future__ import annotations

import functools
import re
import tomllib
from pathlib import Path

import pytest

from tests._workflow_contexts import changes_arm_pattern, jobs_of

_ROOT = Path(__file__).resolve().parents[1]
_PYPROJECT = _ROOT / "pyproject.toml"


@functools.cache
def _packaging_pattern() -> re.Pattern[str]:
    return re.compile(changes_arm_pattern("packaging", "scripts/release/"))


def gate(changed: list[str]) -> bool:
    return any(_packaging_pattern().search(path) for path in changed)


def _locks_the_job_installs() -> set[str]:
    """Every ``-r <lock>`` the packaging-build job installs from, comment lines left out."""
    lines = "\n".join(
        str(step.get("run", "")) for step in jobs_of("ci.yml")["packaging-build"]["steps"]
    ).splitlines()
    code = "\n".join(line for line in lines if not line.lstrip().startswith("#"))
    return set(re.findall(r"-r\s+(\S+\.lock)\b", code))


def _root_files_the_engine_build_reads() -> set[str]:
    """The repo-ROOT files the engine build reads by name, from pyproject.toml.

    The sdist's ``only-include``, the ``readme`` and the ``license-files``. A directory (the
    package) and a nested path are left out: the packaged trees are not this arm's by design, as
    the comment above it in ci.yml says.
    """
    doc = tomllib.loads(_PYPROJECT.read_text(encoding="utf-8"))
    project = doc["project"]
    sdist = doc["tool"]["hatch"]["build"]["targets"]["sdist"]
    names = {*sdist["only-include"], project["readme"], *project["license-files"]}
    return {name for name in names if "/" not in name and (_ROOT / name).is_file()}


def test_every_lock_the_job_installs_trips_the_gate() -> None:
    locks = _locks_the_job_installs()
    assert "ci/locks/release-tools.lock" in locks, (
        f"the job's lock reader found {sorted(locks)}; it has drifted from the job"
    )
    missed = sorted(lock for lock in locks if not gate([lock]))
    assert not missed, f"packaging-build installs from these, yet a bump to one skips it: {missed}"


def test_every_root_file_the_engine_build_reads_trips_the_gate() -> None:
    files = _root_files_the_engine_build_reads()
    assert {"README.md", "CHANGELOG.md", "LICENSE", "NOTICE"} <= files, (
        f"the pyproject reader found {sorted(files)}; it has drifted from pyproject.toml"
    )
    missed = sorted(path for path in files if not gate([path]))
    assert not missed, (
        f"the engine build reads these, yet a PR touching one skips the build: {missed}"
    )


@pytest.mark.parametrize(
    "path",
    [
        "pyproject.toml",
        "packaging/messagefoundry-toolkit/pyproject.toml",
        "packaging/messagefoundry-harness/LICENSE",
        "scripts/release/forbidden_members.py",
        "ci/python-version",
        ".github/workflows/release.yml",
    ],
)
def test_the_existing_arms_still_trip_the_gate(path: str) -> None:
    assert gate([path]), f"the packaging arm no longer admits {path}"


@pytest.mark.parametrize(
    ("path", "why"),
    [
        ("messagefoundry/pipeline/engine.py", "a packaged tree, left to push-to-main by design"),
        ("docs/ARCHITECTURE.md", "a docs file no build reads"),
        ("ci/locks/ci-quality.lock", "a lock this job does not install"),
        ("COMMERCIAL-LICENSE.md", "SHAPE: matches only if `LICENSE` loses its `^`"),
        ("LICENSE.md", "SHAPE: matches only if `LICENSE` loses its `$`"),
        ("NOTICE.txt", "SHAPE: matches only if `NOTICE` loses its `$`"),
        ("docs/README.md", "SHAPE: matches only if `README` loses its `^`"),
    ],
)
def test_the_gate_refuses(path: str, why: str) -> None:
    assert not gate([path]), f"the packaging arm admits {path}: {why}"
