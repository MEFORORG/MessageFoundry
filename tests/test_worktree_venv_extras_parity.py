# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""A lane virtualenv must install what CI installs, or the lane reads green over a tree it never ran.

BACKLOG #1335. ``scripts/worktree/new.ps1`` installed ``.[dev,harness]`` while ``ci.yml``'s test leg
installs ``.[dev,harness,fhir,dicom,x12,xml,webauthn]`` **plus the web console package** -- five
extras and one package short.

WHY THAT IS A FALSE GREEN AND NOT A SPEED CHOICE
--------------------------------------------------
The extras-gated suites skip at **module** scope. So a lane missing ``fhir`` does not see a hundred
failures; it sees ONE skip line, and a hundred tests that were never collected. `pyproject.toml`'s
``testpaths`` also collects ``packaging/messagefoundry-webconsole/tests``, so without the console
package installed **that entire suite is silently absent**. The lane runs `pytest`, reads green, and
has not executed the code CI will execute.

**The BUILDER playbook already names this trap** -- *"the correct command in a stock worktree venv
still does not reproduce CI's collection, and nothing in the output says so"* -- and prescribes
diffing the install line against ``ci.yml``. This test is that diff, run automatically, so the
prescription stops depending on somebody remembering it.

WHY A PARITY TEST RATHER THAN A SHARED SOURCE
-----------------------------------------------
Making the PowerShell installer parse the workflow YAML would couple a bootstrap script to a CI file
and fail in a shell where the parse breaks. The repository already chose the other remedy for exactly
this shape: ``tests/test_lint_scope_parity.py`` exists because **ruff and bandit each had their scope
written twice, drifted, and needed a test to hold them together**. Two declarations kept honest by a
test is the established pattern here, and this follows it.

THE NARROW LIST CARRIED NO STATED RATIONALE
---------------------------------------------
Read before changing it: ``new.ps1`` had **no comment** explaining why the lane list was shorter than
CI's, while the neighbouring ``-Sqlserver`` switch shows the author did think about extras. An
unexplained divergence from CI is an oversight until something says otherwise, and nothing did. If a
future reader wants the lane list DELIBERATELY narrower, that is a decision -- and it needs to be
written down and this test updated, which is the point.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[1]
_NEW_PS1 = _ROOT / "scripts" / "worktree" / "new.ps1"
_CI = _ROOT / ".github" / "workflows" / "ci.yml"

#: The lane's own extra. CI has no SQL Server service on the ordinary test leg, so `-Sqlserver` adding
#: it is a lane-only option rather than a divergence, and it is excluded from the comparison.
_LANE_ONLY = frozenset({"sqlserver"})


def _lane_extras() -> set[str]:
    """The default (non -Sqlserver) extras `new.ps1` installs."""
    text = _NEW_PS1.read_text(encoding="utf-8")
    m = re.search(
        r"^\$extras = if \(\$Sqlserver\) \{ \"([^\"]+)\" \} else \{ \"([^\"]+)\" \}", text, re.M
    )
    assert m is not None, (
        "could not find the $extras assignment in new.ps1 -- has it been rewritten?"
    )
    return {e.strip() for e in m.group(2).split(",") if e.strip()}


def _ci_install_lines() -> list[str]:
    """Every `uv pip install ... -e ".[...]"` line in the workflow, as raw text."""
    text = _CI.read_text(encoding="utf-8")
    lines = [ln.strip() for ln in text.splitlines() if "uv pip install" in ln and '-e ".[' in ln]
    assert lines, "no `uv pip install -e .[...]` line found in ci.yml -- has the workflow changed?"
    return lines


def _ci_test_leg_extras() -> set[str]:
    """The extras on the widest CI install line -- the one the engine test legs use."""
    best: set[str] = set()
    for line in _ci_install_lines():
        m = re.search(r'-e "\.\[([^\]]+)\]"', line)
        if m:
            extras = {e.strip() for e in m.group(1).split(",") if e.strip()}
            if len(extras) > len(best):
                best = extras
    assert best, "could not parse extras from any ci.yml install line"
    return best


def test_the_lane_venv_installs_every_extra_the_ci_test_leg_installs() -> None:
    """THE REGRESSION. Missing extras do not fail loudly -- they skip at module scope, so the lane
    sees a handful of skip lines instead of the tests it did not run."""
    lane = _lane_extras()
    ci = _ci_test_leg_extras()
    missing = ci - lane - _LANE_ONLY
    assert not missing, (
        f"scripts/worktree/new.ps1 installs .[{','.join(sorted(lane))}] but ci.yml's test leg installs "
        f".[{','.join(sorted(ci))}] -- missing {sorted(missing)}. A lane without these COLLECTS FEWER "
        f"TESTS and reads green over a tree it never ran (BACKLOG #1335)."
    )


def test_the_lane_venv_installs_the_web_console_package() -> None:
    """SEPARATE FROM THE EXTRAS, and separately invisible. `pyproject.toml`'s `testpaths` collects
    `packaging/messagefoundry-webconsole/tests`, so without this editable install that whole suite is
    absent rather than failing."""
    text = _NEW_PS1.read_text(encoding="utf-8")
    assert "-e packaging/messagefoundry-webconsole" in text, (
        "new.ps1 does not install the web console package, but pyproject's testpaths collects its "
        "suite -- a lane would silently not run it (BACKLOG #1335)"
    )


def test_ci_still_installs_the_console_package_so_this_comparison_is_not_vacuous() -> None:
    """THE ANTI-VACUITY ARM. If CI stopped installing the console package, the test above would keep
    passing while asserting a parity that no longer means anything. This pins the OTHER side."""
    assert any("packaging/messagefoundry-webconsole" in ln for ln in _ci_install_lines()), (
        "no ci.yml install line mentions the web console package -- the parity assertion above is "
        "now comparing against nothing"
    )


@pytest.mark.parametrize("extra", sorted({"fhir", "dicom", "x12", "xml", "webauthn"}))
def test_each_extra_this_item_added_is_declared_in_pyproject(extra: str) -> None:
    """A NAMED EXTRA MUST EXIST. Widening the lane list to an extra `pyproject.toml` does not declare
    would make every future `new.ps1` run fail at pip time -- which is loud, but only for whoever runs
    it next, and only after the venv is half-built."""
    pyproject = (_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert re.search(rf"^{re.escape(extra)}\s*=\s*\[", pyproject, re.M), (
        f"new.ps1 installs the {extra!r} extra but pyproject.toml declares no such optional dependency"
    )


def test_the_sqlserver_switch_still_adds_its_extra() -> None:
    """The lane-only option must survive the widening. `-Sqlserver` is not a divergence from CI -- the
    ordinary test leg has no SQL Server service -- so it is excluded from the parity comparison, and
    that exclusion must not quietly become a deletion."""
    text = _NEW_PS1.read_text(encoding="utf-8")
    m = re.search(r"^\$extras = if \(\$Sqlserver\) \{ \"([^\"]+)\" \}", text, re.M)
    assert m is not None
    assert "sqlserver" in {e.strip() for e in m.group(1).split(",")}, (
        "the -Sqlserver branch no longer adds the sqlserver extra"
    )
