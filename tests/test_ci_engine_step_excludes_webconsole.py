# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""CI's engine pytest step must subtract the web console package that ``testpaths`` now includes.

BACKLOG #1027 added ``packaging/messagefoundry-webconsole/tests`` to the root ``testpaths`` so a
bare local ``pytest`` stops silently excluding roughly 350 tests. That fix has a CI-side
consequence the original change did not carry: ``ci.yml`` runs a bare ``pytest`` for the engine
step AND a second explicit invocation for the console package -- now in its own ``webconsole`` job
rather than a second step on the same leg -- so once ``testpaths`` includes the console the SAME
tests run TWICE per leg unless the engine step subtracts them.

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
import shlex
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


def _logical_lines(run: str) -> list[str]:
    """The WHOLE `run:` block, with backslash-continuations joined so one command is one string."""
    return [line.strip() for line in re.sub(r"\\\n[ \t]*", " ", run).splitlines() if line.strip()]


def _pytest_command(line: str) -> str | None:
    """This line's pytest command, shell-normalized -- or None when `pytest` is not a command word.

    Normalizing through `shlex` is what makes prose and shell comments non-answers: a mention inside
    quotes stays one argument to whatever quoted it, and a `#` comment is dropped before either
    assertion reads the line. The assertions therefore run over the ARGUMENTS, not over the YAML
    text, so a comment beside the command cannot trip them.
    """
    try:
        argv = shlex.split(line, comments=True)
    except ValueError:
        # An untokenizable line cannot be SHOWN to be an invocation, so it is not treated as one.
        # This can only ever lose a candidate, and losing every candidate in the step is a loud
        # failure below -- never a silent green.
        return None
    if not any(word == "pytest" or word.endswith("/pytest") for word in argv):
        return None
    return shlex.join(argv)


def _engine_step_invocations() -> list[tuple[str, str]]:
    """Every pytest invocation in every `Tests (pytest)` step, as `(job id, joined command)`."""
    # LOCATED STRUCTURALLY, BY STEP NAME, NOT BY SPELLING (BACKLOG #1389; #1260 is what moved it).
    #
    # WHAT WENT WRONG WAS A SILENT GREEN, NOT A FAILURE. This used to scan the whole file for a line
    # whose stripped form starts `run: pytest -q`. #1260 then wrapped the engine invocation in
    # `bash scripts/ci/retry-native-crash.sh ...` -- so a native crash can be named as a crash
    # rather than reported as a test failure -- and the engine line stopped starting that way.
    # Exactly one OTHER line in ci.yml still did: the `tooling` job's step. The locator bound THAT
    # step, it happens to carry `--ignore-glob`, and all three assertions passed. So the guard was
    # green while asserting against a step it was not written for; it never said "no engine step
    # found", and nothing ever went red, which is why it survived. #1389 records the measurement.
    #
    # READ THE WHOLE `run:` BLOCK, NOT ONE LINE -- #1389's acceptance criterion, in its words: read
    # the whole `run:` block "rather than pattern-matching a one-line spelling that a formatting
    # change can move". Returning a single line was wrong in BOTH directions, both MEASURED:
    #   * a plain `--ignore=` moved onto a backslash-continuation line was invisible -- the exact
    #     regression this file exists to catch, passing;
    #   * reformatting the invocation across continuation lines with the flag PRESERVED went red --
    #     a false alarm on a harmless edit.
    # Joining continuations first makes one command one string, so neither answer depends on layout.
    #
    # ASSERT OVER EVERY MATCHING STEP, NOT THE FIRST. Returning on first match meant a second job
    # whose `Tests (pytest)` step dropped the subtraction was never examined, and a correct step in
    # an earlier job masked a broken one in `test`. Both MEASURED green before this change. ci.yml
    # today has exactly one step with this name (`test`, `id: tests`) -- MEASURED -- and the loop is
    # what keeps that a fact rather than an assumption. The bind stays on `name:` alone: `id: tests`
    # is unique today too, but an id is scoped to its job, so matching on it invites a second job's
    # `id: tests` to be swept in silently.
    #
    # ZERO MATCHES FAILS LOUDLY, DELIBERATELY. A guard that finds nothing and passes IS the defect
    # #1389 filed, one rename away. Renaming the step must break this file, so whoever renames it
    # re-points the guard.
    #
    # THE ANCHOR IS THE INVOCATION, NOT THE WORD `pytest`. Searching for the bare token let a line
    # that merely MENTIONS pytest -- `echo "starting pytest for the engine leg"` -- win over the real
    # command below it, MEASURED red on a step that was correct. `shlex.split` sees that mention as
    # one quoted argument to `echo` and never as a command word, so prose cannot claim the match.
    # Matching mid-line is safe ONLY because the step is already located by NAME: a mid-line search
    # over the whole file is what bound the tooling step above.
    workflow = yaml.safe_load(_CI.read_text(encoding="utf-8"))
    found: list[tuple[str, str]] = []
    for job_id, job in workflow["jobs"].items():
        for step in job.get("steps") or []:
            if step.get("name") != _ENGINE_STEP:
                continue
            run = step.get("run", "")
            invocations = [
                command
                for line in _logical_lines(run)
                if (command := _pytest_command(line)) is not None
            ]
            if not invocations:
                pytest.fail(
                    f"the {_ENGINE_STEP!r} step in job {job_id!r} runs no `pytest` command:\n{run}"
                )
            found.extend((job_id, invocation) for invocation in invocations)
    if not found:
        pytest.fail(f"no step named {_ENGINE_STEP!r} found in {_CI}")
    return found


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
    for job_id, run in _engine_step_invocations():
        assert "--ignore-glob" in run and "messagefoundry-webconsole" in run, (
            f"ci.yml's {_ENGINE_STEP} step in job {job_id!r} must subtract the web console "
            "package, which `testpaths` now includes and which runs as its own job. Found:\n"
            f"    {run}"
        )


def test_engine_step_does_not_use_plain_ignore() -> None:
    """`--ignore=<path>` was measured NOT to prune a `testpaths` collection root."""
    for job_id, run in _engine_step_invocations():
        plain = re.search(r"--ignore(?!-glob)[= ]", run)
        assert plain is None, (
            "`--ignore=<path>` does not prune a directory named by `testpaths` -- measured "
            f"2026-08-08, it still collected all 11,956 tests. Use `--ignore-glob`. Job {job_id!r} "
            "runs:\n    " + run
        )
