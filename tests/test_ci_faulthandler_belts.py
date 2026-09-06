# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""The hang-diagnostic belts on CI's two pytest steps, pinned so a silent removal goes red.

BACKLOG #1304. The ``repo harness tests (windows-2025)`` leg intermittently hangs on a ``pwsh``
launch. The engine ``Tests (pytest)`` step already carried two watchdogs against a hung Windows
leg; the tooling step carried one, and the second was ported to it. This file stops either half
drifting off either step without a reader.

**WHAT EACH BELT IS, because they are easy to conflate.**

* ``--timeout-method=thread`` reaches BOTH steps through ``addopts`` in ``pyproject.toml``, so it is
  repo-wide and is not asserted per-step here -- ``test_thread_method_is_repo_wide`` pins it at its
  one source instead.
* ``PYTHONFAULTHANDLER=1`` plus ``-o faulthandler_timeout=`` is per-step, and that is the half that
  was missing from the tooling step.

**THIS BELT IS A SECOND OPINION, NOT THE THING THAT NAMES THE FAILURE, and the measurement says so.**
Paired local arms on a test blocking in ``subprocess.run`` with no ``timeout=`` of its own: without
the faulthandler belt the thread method already fires and already names the frame down to
``_winapi.WaitForSingleObject``. Reading the pinned ``pytest_timeout`` on disk says why -- its
``timeout_timer`` dumps from a watchdog THREAD and calls ``os._exit(1)``, so it never needs to
interrupt the wedged main thread. What the belt adds is an independent mechanism (CPython's
``dump_traceback_later``) writing down a different path (a dup'd raw stderr fd, not
``config.get_terminal_writer()``), which matters most on the one tier that runs ``-n 4``.

**THE ORDERING IS THE CONTRACT, NOT THE NUMBERS.** ``faulthandler_timeout`` must sit ABOVE the
step's own ``--timeout`` so the per-test bound is attributed first and the faulthandler dump stays
the last resort. Asserted numerically where both are literals; the engine step passes both through
env from the matrix, so only presence is checkable there without re-implementing the matrix.
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

#: Both pytest steps, addressed by NAME. A rename must break this file, so whoever renames a step
#: re-points the guard -- the failure mode ``test_ci_engine_step_excludes_webconsole`` records is a
#: locator that quietly binds the wrong step and passes.
_ENGINE_STEP = "Tests (pytest)"
_TOOLING_STEP = "Harness tests (pytest)"


def _logical_lines(run: str) -> list[str]:
    """The whole ``run:`` block with backslash-continuations joined, so one command is one string."""
    return [line.strip() for line in re.sub(r"\\\n[ \t]*", " ", run).splitlines() if line.strip()]


def _is_pytest_command(line: str) -> list[str] | None:
    """This line's argv when ``pytest`` appears as a command WORD, else None.

    Normalizing through ``shlex`` is what makes prose a non-answer: a mention inside quotes stays one
    argument to whatever quoted it, and a shell comment is dropped before any assertion reads it.
    """
    try:
        argv = shlex.split(line, comments=True)
    except ValueError:
        # An untokenizable line cannot be SHOWN to be an invocation, so it is not treated as one.
        # This can only lose a candidate, and losing every candidate fails loudly below.
        return None
    if not any(word == "pytest" or word.endswith("/pytest") for word in argv):
        return None
    return argv


def _step(step_name: str) -> tuple[str, dict[str, object]]:
    """The single step with this name, as ``(job id, step)``. Zero or many fails loudly.

    A guard that finds nothing and passes is the defect, one rename away.
    """
    workflow = yaml.safe_load(_CI.read_text(encoding="utf-8"))
    found = [
        (job_id, step)
        for job_id, job in workflow["jobs"].items()
        for step in (job.get("steps") or [])
        if step.get("name") == step_name
    ]
    if len(found) != 1:
        pytest.fail(
            f"expected exactly one step named {step_name!r} in {_CI}; found {len(found)} "
            f"({[job for job, _ in found]}). Re-point this guard rather than deleting it."
        )
    return found[0]


def _invocation(step_name: str) -> tuple[str, list[str]]:
    """The step's one pytest argv, as ``(job id, argv)``."""
    job_id, step = _step(step_name)
    run = str(step.get("run", ""))
    argvs = [argv for line in _logical_lines(run) if (argv := _is_pytest_command(line)) is not None]
    if len(argvs) != 1:
        pytest.fail(
            f"expected exactly one pytest invocation in the {step_name!r} step of job {job_id!r}; "
            f"found {len(argvs)}:\n{run}"
        )
    return job_id, argvs[0]


def _ini_override(argv: list[str], key: str) -> str | None:
    """The value of ``-o key=value``, in either the ``-o k=v`` or ``-ok=v`` spelling."""
    for i, word in enumerate(argv):
        if word == "-o" and i + 1 < len(argv) and argv[i + 1].startswith(f"{key}="):
            return argv[i + 1].split("=", 1)[1]
        if word.startswith(f"-o{key}="):
            return word.split("=", 1)[1]
    return None


def _flag_value(argv: list[str], flag: str) -> str | None:
    """The value of ``--flag=value`` or ``--flag value``."""
    for i, word in enumerate(argv):
        if word.startswith(f"{flag}="):
            return word.split("=", 1)[1]
        if word == flag and i + 1 < len(argv):
            return argv[i + 1]
    return None


def test_thread_method_is_repo_wide() -> None:
    """Belt one lives in ``addopts``, so both steps inherit it. Pin it at its single source."""
    cfg = tomllib.loads(_PYPROJECT.read_text(encoding="utf-8"))
    addopts = cfg["tool"]["pytest"]["ini_options"]["addopts"]
    assert "--timeout-method=thread" in addopts, (
        "`--timeout-method=thread` is the ONLY timeout method available on Windows (SIGALRM is "
        f"POSIX-only) and it reaches every leg through addopts. Got: {addopts!r}"
    )


@pytest.mark.parametrize("step_name", [_ENGINE_STEP, _TOOLING_STEP])
def test_step_exports_pythonfaulthandler(step_name: str) -> None:
    """Arms the fatal-signal handler from interpreter start, and is inherited by Python children."""
    job_id, step = _step(step_name)
    env = step.get("env") or {}
    assert isinstance(env, dict)
    assert str(env.get("PYTHONFAULTHANDLER", "")) == "1", (
        f"the {step_name!r} step in job {job_id!r} must export PYTHONFAULTHANDLER=1 (BACKLOG "
        f"#1304). Got env: {env!r}"
    )


@pytest.mark.parametrize("step_name", [_ENGINE_STEP, _TOOLING_STEP])
def test_step_arms_faulthandler_timeout(step_name: str) -> None:
    """The env var alone arms no watchdog -- the per-test dump needs the ini key as well."""
    job_id, argv = _invocation(step_name)
    value = _ini_override(argv, "faulthandler_timeout")
    assert value, (
        f"the {step_name!r} step in job {job_id!r} must pass `-o faulthandler_timeout=` (BACKLOG "
        "#1304). The plugin exposes this as an ini key, NOT as a `--faulthandler-*` CLI flag, so "
        f"`-o` is the only spelling that arms it. Got: {shlex.join(argv)}"
    )


def test_tooling_faulthandler_sits_above_its_own_pytest_timeout() -> None:
    """Below the per-test bound the last-resort dump fires FIRST and steals the attribution.

    Only the tooling step is checked numerically: it is the one carrying both values as literals.
    The engine step passes both through env from the runtime matrix, so a numeric check here would
    re-implement that matrix and drift from it.
    """
    job_id, argv = _invocation(_TOOLING_STEP)
    fault = _ini_override(argv, "faulthandler_timeout")
    per_test = _flag_value(argv, "--timeout")
    assert fault is not None and per_test is not None, (
        f"the {_TOOLING_STEP!r} step in job {job_id!r} must carry both bounds as literals; got "
        f"faulthandler_timeout={fault!r}, --timeout={per_test!r}"
    )
    assert float(fault) > float(per_test), (
        f"faulthandler_timeout ({fault}) must sit ABOVE --timeout ({per_test}) so the per-test "
        "bound is attributed first and the faulthandler dump stays the last resort. Move one, "
        "move the other."
    )
