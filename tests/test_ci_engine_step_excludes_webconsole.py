# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""CI's engine pytest step must subtract the web console package that ``testpaths`` now includes.

BACKLOG #1027 added ``packaging/messagefoundry-webconsole/tests`` to the root ``testpaths`` so a
bare local ``pytest`` stops silently excluding roughly 350 tests. That fix has a CI-side
consequence the original change did not carry: ``ci.yml`` runs a bare ``pytest`` for the engine
step AND a second explicit step for the console package, so once ``testpaths`` includes the
console the SAME tests run TWICE on every leg.

Measured 2026-08-08: bare collection 11,956; console-only 356; with the subtraction 11,600.

**The obvious spelling does not work, which is why this guard pins the working one.**
``--ignore=packaging/messagefoundry-webconsole/tests`` was measured and does NOT prune a directory
that ``testpaths`` names as a collection root -- it still collected all 11,956. Only the glob form
subtracts. A future edit "simplifying" the flag back to ``--ignore`` would restore the double-run
silently, with every check still green, which is the same shape as the defect #1027 fixed.

``pytest tests`` is also rejected, and deliberately: hardcoding the engine path would make CI miss
any future third entry in ``testpaths``. Subtracting FROM ``testpaths`` keeps it the one source of
truth for what the suite is.
"""

from __future__ import annotations

import re
import tomllib
from pathlib import Path

import pytest
import yaml

_ROOT = Path(__file__).resolve().parents[1]
_CI = _ROOT / ".github" / "workflows" / "ci.yml"
_PYPROJECT = _ROOT / "pyproject.toml"
_CONSOLE = "packaging/messagefoundry-webconsole/tests"
#: The engine suite's step, addressed by NAME so this guard survives changes to how it is invoked.
_ENGINE_STEP = "Tests (pytest)"


def _engine_step_run_line() -> str:
    """The `run:` line of the engine `Tests (pytest)` step."""
    # LOCATED STRUCTURALLY, BY STEP NAME, NOT BY SPELLING (BACKLOG #1260).
    #
    # This used to scan for a line starting with `run: pytest -q`, which pinned the step to being a
    # ONE-LINE `run:`. Wrapping the invocation in a block -- so a native crash can be named as a
    # crash rather than reported as a test failure -- broke the LOOKUP rather than any assertion, and
    # the failure then read "no engine step found" instead of "the step moved". A locator coupled to
    # a step's spelling blocks every change to how that step is invoked, which is not what this guard
    # is for: it exists to assert the console package is SUBTRACTED.
    #
    # THE OBVIOUS RELAXATION IS WORSE AND WAS MEASURED. Broadening the scan to any `pytest -q` line
    # matches `.github/workflows/ci.yml`'s EARLIER doc-guards step (`pytest -q -rs $DOC_GUARDS`) and
    # asserts against the wrong invocation entirely -- caught here because this test went red on it.
    # Disambiguating by `--ignore-glob` would have been circular: that is the thing under assertion,
    # so the locator would be satisfied by its own subject and could never fail.
    workflow = yaml.safe_load(_CI.read_text(encoding="utf-8"))
    for job in workflow["jobs"].values():
        for step in job.get("steps") or []:
            if step.get("name") == _ENGINE_STEP:
                run = step.get("run", "")
                for line in run.splitlines():
                    stripped = line.strip()
                    if stripped.startswith("pytest "):
                        return stripped
                pytest.fail(f"the {_ENGINE_STEP!r} step runs no `pytest` command:\n{run}")
    pytest.fail(f"no step named {_ENGINE_STEP!r} found in {_CI}")


def test_console_is_in_testpaths() -> None:
    """Precondition: this guard is only meaningful while #1027's change is in place."""
    cfg = tomllib.loads(_PYPROJECT.read_text(encoding="utf-8"))
    testpaths = cfg["tool"]["pytest"]["ini_options"]["testpaths"]
    assert _CONSOLE in testpaths, (
        f"expected {_CONSOLE!r} in testpaths (BACKLOG #1027); got {testpaths!r}. "
        "If that was reverted deliberately, this guard and the ci.yml subtraction go with it."
    )


def test_engine_step_subtracts_the_console_package() -> None:
    """Without this, the console's ~356 tests run twice per leg."""
    run = _engine_step_run_line()
    assert "--ignore-glob" in run and "messagefoundry-webconsole" in run, (
        "ci.yml's engine `Tests (pytest)` step must subtract the web console package, which "
        f"`testpaths` now includes and which runs as its own step. Found:\n    {run}"
    )


def test_engine_step_does_not_use_plain_ignore() -> None:
    """`--ignore=<path>` was measured NOT to prune a `testpaths` collection root."""
    run = _engine_step_run_line()
    plain = re.search(r"--ignore(?!-glob)[= ]", run)
    assert plain is None, (
        "`--ignore=<path>` does not prune a directory named by `testpaths` -- measured 2026-08-08, "
        "it still collected all 11,956 tests. Use `--ignore-glob`. Found:\n    " + run
    )
