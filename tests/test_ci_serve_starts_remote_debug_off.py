# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Every engine a workflow step starts by command line starts with remote debugging off (vault
BACKLOG #2700, owner ruling (b) of 2026-10-16).

``serve`` and ``supervise`` refuse to start under ``enforce`` while ``sys.is_remote_debug_enabled()``
is True (engine PR 2394). The ruling: CI launches the interpreter with ``-X disable-remote-debug``,
as the shipped service does, including on the legs that run at ``warn`` for another reason.

The interpreter accepts ``-X disable_remote_debug`` and does nothing with it
(``tests/test_isolated_launch.py`` runs that), so the reader compares the exact spelling.

THESE READ TEXT, NOT A RUN. Most of those legs run on a schedule, on dispatch or in the merge queue,
so a pull request never shows their result. At least these start an engine where no step text
shows it, and nothing here reads them: the Windows service smoke (NSSM, read by
``tests/test_isolated_launch.py``), the image smoke (the image's entry point, read there too), and
any engine a harness module starts from Python, such as ``harness/load/failover.py``.
"""

from __future__ import annotations

import functools
import itertools
from pathlib import PurePosixPath
from typing import Any

import pytest

from messagefoundry.startupcode import ISOLATED_LAUNCH_OPTIONS

_SUBCOMMANDS = ("serve", "supervise")
#: The remote-debug pair of the shipped launch options, which ``tests/test_isolated_launch.py``
#: holds to one spelling with the children's flags.
_OPTION = (ISOLATED_LAUNCH_OPTIONS[-2], ISOLATED_LAUNCH_OPTIONS[-1])


def engine_starts(script: str) -> list[tuple[str, str | None]]:
    """``(line, problem or None)`` for each engine start in ``script``.

    ``script`` is a step's ``run`` text with its comment lines already dropped. A backslash line
    continuation is joined first, so a start split across lines is still one start."""
    starts: list[tuple[str, str | None]] = []
    for line in script.replace("\\\n", " ").splitlines():
        tokens = line.split()
        for at, token in enumerate(tokens[:-1]):
            if PurePosixPath(token).name not in ("messagefoundry", "messagefoundry.exe"):
                continue
            if tokens[at + 1] not in _SUBCOMMANDS:
                continue
            problem = None
            if at == 0 or tokens[at - 1] != "-m":
                # The console-script launcher cannot pass an option to the interpreter it starts.
                problem = "started through the launcher, not the interpreter"
            else:
                interpreter = max(
                    (i for i in range(at - 1) if "python" in tokens[i].lower()), default=-1
                )
                options = tokens[interpreter + 1 : at - 1]
                if interpreter == -1 or _OPTION not in itertools.pairwise(options):
                    problem = "remote debugging is not turned off"
            starts.append((line.strip(), problem))
    return starts


def start_problems(script: str) -> list[str]:
    """The engine starts in ``script`` that do not turn remote debugging off, one line each."""
    return [f"{problem}: {line}" for line, problem in engine_starts(script) if problem]


@functools.cache
def _step_scripts() -> tuple[tuple[str, str, str], ...]:
    """``(workflow, job, comment-free script)`` for every step script of every workflow, parsed
    once for the module: ci.yml alone takes a measurable share of a second."""
    from tests._workflow_contexts import WORKFLOWS, jobs_of

    found: list[tuple[str, str, str]] = []
    for path in sorted(WORKFLOWS.glob("*.yml")):
        jobs: dict[str, dict[str, Any]] = jobs_of(path.name)
        for key, job in jobs.items():
            for step in job.get("steps") or []:
                run = str(step.get("run") or "")
                script = "\n".join(
                    line for line in run.splitlines() if not line.lstrip().startswith("#")
                )
                if script:
                    found.append((path.name, key, script))
    return tuple(found)


def test_every_command_line_engine_start_turns_remote_debugging_off() -> None:
    pytest.importorskip("yaml")
    problems = {
        f"{workflow} / {job}": found
        for workflow, job, script in _step_scripts()
        if (found := start_problems(script))
    }
    assert not problems, (
        f"start the interpreter as `python {' '.join(ISOLATED_LAUNCH_OPTIONS)} -m messagefoundry "
        f"serve ...`, as the shipped service does (vault BACKLOG #2700): {problems}"
    )


def test_the_reader_meets_the_starts_it_was_written_for() -> None:
    """CONTROL: the reader above recognises the five load-leg starts as starts, so a reader that
    matched nothing would fail here rather than pass there."""
    pytest.importorskip("yaml")
    starting = {
        (workflow, job) for workflow, job, script in _step_scripts() if engine_starts(script)
    }
    expected = {
        ("benchmark.yml", "baseline-sqlite"),
        ("benchmark.yml", "baseline-postgres"),
        ("benchmark.yml", "baseline-sqlserver"),
        ("ci.yml", "load-test"),
        ("ci.yml", "load-test-sqlserver"),
    }
    assert expected <= starting, sorted(expected - starting)


@pytest.mark.parametrize(
    "start",
    [
        # The bare start the three `warn` legs carried until this item.
        "python -m messagefoundry serve --config harness/config/load --env dev \\\n  --port 8765 &",
        "python -m messagefoundry supervise --config c",
        # Misspelt: the interpreter accepts it and leaves remote debugging on.
        "python -I -X disable_remote_debug -m messagefoundry serve --config c",
        # Another -X option, not this one.
        "python -I -X utf8 -m messagefoundry serve --config c",
        # The option after the module is the engine's argument, not the interpreter's.
        "python -I -m messagefoundry serve -X disable-remote-debug --config c",
        # The launcher cannot pass it at all.
        "messagefoundry serve --config c",
        ".venv/bin/messagefoundry serve --config c",
        # Split across a continuation.
        "python -I \\\n  -m messagefoundry serve --config c",
    ],
)
def test_the_reader_objects_to_a_planted_start(start: str) -> None:
    assert start_problems("set -e\n" + start + "\n"), start


@pytest.mark.parametrize(
    "start",
    [
        "python -I -X disable-remote-debug -m messagefoundry serve --config c > engine.log 2>&1 &",
        "python -P -X disable-remote-debug -m messagefoundry supervise --config c",
        "python -I -X disable-remote-debug \\\n  -m messagefoundry serve --config c",
    ],
)
def test_the_reader_passes_a_start_with_the_option(start: str) -> None:
    assert engine_starts(start + "\n") == [(start.replace("\\\n", " ").strip(), None)], start


@pytest.mark.parametrize(
    "line",
    [
        # Another subcommand, and the image smoke's argument to the image entry point.
        "python -m messagefoundry protect-key --out key.bin",
        "docker run -d --name mefor image \\\n  serve --config /config",
    ],
)
def test_the_reader_sees_no_start_where_none_is(line: str) -> None:
    assert engine_starts(line + "\n") == [], line
