# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The console release refuses a wheel whose engine requirement has no floor (BACKLOG #1585).

The console's engine requirement is a floor with no ceiling, set at each console release
(``packaging/messagefoundry-webconsole/RELEASE.md`` step 2; the reasons are in
``docs/WEBCONSOLE-PACKAGE.md``). Because it is a release step, a person can skip it, and a skipped
one ships a bare ``messagefoundry`` dependency. ``release-webconsole`` has a step that reads the
BUILT wheel's ``Requires-Dist`` and refuses that wheel.

The step only runs on a ``webconsole-v*`` ref, so nothing else would notice if it stopped firing.
This file extracts its ``PYFLOOR`` script and RUNS it over synthetic wheels. Each refusal also has
a mutation arm: the guarding line is disabled and the same input must then pass, so a green here
means that line is what refused, not some earlier crash.
"""

from __future__ import annotations

import re
import subprocess
import sys
import zipfile
from pathlib import Path
from typing import Any

import pytest

_REPO = Path(__file__).resolve().parents[1]
RELEASE_YML = _REPO / ".github" / "workflows" / "release.yml"
_JOB = "release-webconsole"
_HEREDOC = re.compile(r"<<'PYFLOOR'\n(.*?)\nPYFLOOR\n", re.S)
_ENGINE_DEV_EXTRA = 'messagefoundry[dev]; extra == "dev"'


def _steps() -> list[dict[str, Any]]:
    import yaml

    jobs = yaml.safe_load(RELEASE_YML.read_text(encoding="utf-8"))["jobs"]
    return [s for s in jobs[_JOB]["steps"] if isinstance(s, dict)]


def _floor_step() -> tuple[int, dict[str, Any]]:
    found = [(i, s) for i, s in enumerate(_steps()) if "<<'PYFLOOR'" in str(s.get("run") or "")]
    assert len(found) == 1, f"{_JOB} must hold exactly one PYFLOOR step, found {len(found)}"
    return found[0]


def _script() -> str:
    m = _HEREDOC.search(str(_floor_step()[1]["run"]))
    assert m, "the floor step has no terminated PYFLOOR heredoc"
    return m.group(1)


def _wheel(tmp_path: Path, requires: list[str], name: str = "w") -> Path:
    """A zip shaped like the console wheel, carrying only the METADATA the gate reads."""
    (tmp_path / name).mkdir()
    path = tmp_path / name / "messagefoundry_webconsole-9.9.9-py3-none-any.whl"
    lines = ["Metadata-Version: 2.4", "Name: messagefoundry-webconsole", "Version: 9.9.9"]
    lines += [f"Requires-Dist: {r}" for r in requires]
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("messagefoundry_webconsole/__init__.py", "")
        zf.writestr("messagefoundry_webconsole-9.9.9.dist-info/METADATA", "\n".join(lines) + "\n\n")
    return path


def _run(script: str, *wheels: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-I", "-", *map(str, wheels)],
        input=script,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )


# --- where the step sits ---------------------------------------------------------------------------


def test_the_floor_step_sits_between_the_smoke_and_the_first_publish() -> None:
    """After the smoke, whose venv supplies ``packaging``; before anything leaves the job."""
    steps = _steps()
    idx, step = _floor_step()
    names = [str(s.get("name") or "") for s in steps]
    smoke = next(i for i, n in enumerate(names) if n.startswith("Smoke-check the console wheel"))
    release = next(i for i, n in enumerate(names) if n.startswith("Create or update the console"))
    publish = next(
        i for i, n in enumerate(names) if n.startswith("Publish messagefoundry-webconsole")
    )
    assert smoke < idx < release < publish
    # Not "Smoke-check...": tests/test_release_pipeline.py requires exactly one such step per job.
    assert not str(step.get("name")).startswith("Smoke-check")
    # Unconditional, so a dispatch dry run on a release branch fails here before a tag does.
    assert "if" not in step
    assert "/tmp/webconsolesmoke/bin/python -I - webconsole-dist/*.whl <<'PYFLOOR'" in step["run"]


def test_the_refusal_names_the_release_step_that_fixes_it() -> None:
    assert "RELEASE.md step 2" in _script()


# --- what it accepts and refuses -------------------------------------------------------------------

_ACCEPTED = {
    "floor": ["messagefoundry>=0.4.1"],
    "pin": ["messagefoundry==0.4.1"],
    "floor_and_ceiling": ["messagefoundry>=0.4.1,<0.5"],
    "compatible_release": ["messagefoundry~=0.4.1"],
    "floor_beside_the_dev_extra": ["messagefoundry>=0.4.1", _ENGINE_DEV_EXTRA],
    "spelled_in_capitals": ["MessageFoundry>=0.4.1"],
}

_REFUSED = {
    "bare": (["messagefoundry"], "no lower bound"),
    "bare_beside_the_dev_extra": (["messagefoundry", _ENGINE_DEV_EXTRA], "no lower bound"),
    "ceiling_only": (["messagefoundry<0.5"], "no lower bound"),
    "marker": (['messagefoundry>=0.4.1; sys_platform == "linux"'], "environment marker"),
    "wrong_name": (["messagefoundry-core>=0.4.1"], "no unconditional"),
    "dev_extra_only": ([_ENGINE_DEV_EXTRA], "no unconditional"),
    "no_requirements": ([], "no unconditional"),
}


@pytest.mark.parametrize("requires", _ACCEPTED.values(), ids=list(_ACCEPTED))
def test_a_floored_requirement_passes(tmp_path: Path, requires: list[str]) -> None:
    r = _run(_script(), _wheel(tmp_path, requires))
    assert r.returncode == 0, r.stderr
    assert "console engine requirement:" in r.stdout


@pytest.mark.parametrize(("requires", "reason"), _REFUSED.values(), ids=list(_REFUSED))
def test_a_requirement_without_a_floor_is_refused(
    tmp_path: Path, requires: list[str], reason: str
) -> None:
    r = _run(_script(), _wheel(tmp_path, requires))
    assert r.returncode != 0
    # The message, not only the exit code: a crash also exits non-zero.
    assert "::error::" in r.stderr and reason in r.stderr, r.stderr
    assert "RELEASE.md step 2" in r.stderr


def test_two_wheels_are_refused(tmp_path: Path) -> None:
    ok = ["messagefoundry>=0.4.1"]
    r = _run(_script(), _wheel(tmp_path, ok, "a"), _wheel(tmp_path, ok, "b"))
    assert r.returncode != 0
    assert "exactly one console wheel" in r.stderr


# --- mutation arms: disable one guard, and the input it refused must now pass ------------------------


def _disable(script: str, condition: str) -> str:
    """Replace one guard's ``if <condition>:`` with ``if False:``, and prove there was one."""
    old = f"if {condition}:\n"
    assert script.count(old) == 1, f"the guard {condition!r} moved; re-point this mutation"
    return script.replace(old, "if False:\n")


#: guard condition -> the refused case it alone should stop
_MUTATIONS = {
    "marker": ("req.marker is not None", "marker"),
    "floor": ("not any(spec.operator in FLOOR_OPERATORS for spec in req.specifier)", "bare"),
    "name": ("canonicalize_name(req.name) != ENGINE", "wrong_name"),
}


@pytest.mark.parametrize(("condition", "case"), _MUTATIONS.values(), ids=list(_MUTATIONS))
def test_disabling_the_guard_lets_its_case_through(
    tmp_path: Path, condition: str, case: str
) -> None:
    wheel = _wheel(tmp_path, _REFUSED[case][0])
    assert _run(_script(), wheel).returncode != 0  # the control arm
    mutated = _run(_disable(_script(), condition), wheel)
    assert mutated.returncode == 0, mutated.stderr


def test_the_extra_skip_is_what_lets_the_dev_extra_ride_beside_the_floor(tmp_path: Path) -> None:
    """Without the skip, the console's own ``[dev]`` extra reads as a marker-gated engine
    requirement and every real console wheel is refused."""
    wheel = _wheel(tmp_path, _ACCEPTED["floor_beside_the_dev_extra"])
    assert _run(_script(), wheel).returncode == 0
    mutated = _run(
        _disable(_script(), 'req.marker is not None and "extra" in str(req.marker)'), wheel
    )
    assert mutated.returncode != 0
    assert "environment marker" in mutated.stderr
