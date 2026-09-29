# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A native crash must not report as a test failure, and a test failure must never be retried (#1260).

THE FILED DEFECT IS A NAMING ONE. A segfault kills the interpreter, so pytest returns 139 with no
verdict -- and THREE layers of naming then say "tests failed": the check name ``test (windows-2025,
py3.14)``, the step name ``Tests (pytest)``, and ``steps.tests.outcome``, which is what
``scripts/ci/step_margin.py`` consumes. **Not one of them is true.** The engine was fine; a process
died.

THE ORDER OF THE TWO HALVES IS LOAD-BEARING, and the item says so. Wrapping the step makes the
failure RETRY; it does not make it LEGIBLE. If the retry then succeeds, the crash vanishes from view
entirely -- so the legibility arms below are the point, and the coverage arm is what makes them
reachable from the main suite at all.

WHY ``exit 139`` RATHER THAN A REAL SEGFAULT. A process killed by SIGSEGV exits 128+11 = 139, and
139 is precisely what the wrapper branches on. Faulting a real process would test the operating
system; these arms test the contract the wrapper actually implements, on every runner, in
milliseconds. The one thing they cannot show is that a real crash produces 139 -- that is the
wrapper's own documented premise and is not re-derived here.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest
from _bash_resolver import probe_env, require_bash

_ROOT = Path(__file__).resolve().parents[1]
_WRAPPER = _ROOT / "scripts" / "ci" / "retry-native-crash.sh"
_CI = _ROOT / ".github" / "workflows" / "ci.yml"

# RESOLVE BASH ONCE AND INVOKE THAT EXACT BINARY. Passing the bare name "bash" to subprocess lets
# Windows resolve it against the child's PATH, which on a machine with WSL installed finds
# System32/bash.exe -- a DIFFERENT interpreter that cannot see a C:/... path and reports
# the wrapper as "No such file or directory". Measured here: bare `bash` launched WSL while
# shutil.which returned Git Bash.
#
# NOT `shutil.which("bash")` EITHER (BACKLOG #1216). It answers whether A bash exists, and on a box
# where Git Bash is off PATH or sits behind System32 it IS the WSL launcher: measured 2026-09-28,
# every arm here printed nothing. `require_bash` probes each candidate and fails loudly, never skips.


@pytest.fixture(scope="module")
def bash(tmp_path_factory: pytest.TempPathFactory) -> Path:
    return Path(require_bash(tmp_path_factory.mktemp("resolve-bash")))


def _run(
    bash: Path, exit_code: int, *, attempts: str = "3", cause: str | None = None
) -> subprocess.CompletedProcess[str]:
    """Drive the REAL wrapper against a command with a known exit code, counting invocations."""
    # probe_env supplies `seq`, which the wrapper needs.
    env = probe_env(bash, dict(os.environ, RETRY_NATIVE_CRASH_ATTEMPTS=attempts))
    # None means the wrapper's DEFAULT, so an inherited value must not stand in for it: ci.yml's
    # Tests (pytest) step sets RETRY_NATIVE_CRASH_CAUSE to "", which would flip the default arm.
    env.pop("RETRY_NATIVE_CRASH_CAUSE", None)
    if cause is not None:
        env["RETRY_NATIVE_CRASH_CAUSE"] = cause
    return subprocess.run(
        # as_posix, NOT str: a backslash path reaches bash as escapes and collapses to one
        # mangled word. Forward slashes survive, and `bash` pins WHICH bash reads them. The command
        # the wrapper retries is pinned too, rather than left to a by-name PATH lookup.
        [str(bash), _WRAPPER.as_posix(), bash.as_posix(), "-c", f"echo ran; exit {exit_code}"],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
        env=env,
    )


# ---------------------------------------------------------------------------------------------
# THE RETRY PAIR -- it must fire on a crash and must NEVER fire on a failure
# ---------------------------------------------------------------------------------------------


@pytest.mark.parametrize("code", [139, 134])
def test_a_native_crash_retries_and_says_so(bash: Path, code: int) -> None:
    """MUST FIRE. 139 is 128+SIGSEGV and 134 is 128+SIGABRT -- the two the wrapper branches on."""
    r = _run(bash, code, attempts="3")
    assert r.stdout.count("ran") == 3, f"expected 3 attempts, got {r.stdout!r}"
    assert r.returncode == code, "the crash exit must survive the retries, not be flattened"
    assert "NATIVE CRASH" in r.stdout


def test_an_ORDINARY_FAILURE_IS_NEVER_RETRIED(bash: Path) -> None:
    """MUST NOT FIRE, AND THIS IS THE ARM THAT KEEPS THE WRAPPER FROM LAUNDERING A REGRESSION.

    Without it, "retry on crash" could be implemented as "retry on anything" and every arm above
    would still pass -- while a real test failure got three chances to flake green."""
    r = _run(bash, 1, attempts="3")
    assert r.stdout.count("ran") == 1, "a test failure must run exactly once"
    assert r.returncode == 1
    assert "not a native crash" in r.stdout
    assert "NATIVE CRASH" not in r.stdout


def test_success_passes_straight_through(bash: Path) -> None:
    """MUST NOT FIRE. A wrapper that re-ran a passing command would triple every green leg."""
    r = _run(bash, 0, attempts="3")
    assert r.stdout.count("ran") == 1
    assert r.returncode == 0


# ---------------------------------------------------------------------------------------------
# THE ATTRIBUTION PAIR -- the wrapper must not assert a cause it has not measured
# ---------------------------------------------------------------------------------------------


def test_a_leg_with_no_established_cause_says_CAUSE_NOT_ESTABLISHED(bash: Path) -> None:
    """MUST NOT NAME pyodbc. The class is established for the DATABASE legs and for nothing else.

    A wrapper that named it unconditionally would print a mechanism it has not measured onto every
    leg it is ever added to -- a true observation (a native crash happened) carrying an invented
    cause, which is the harder error to catch because the part a reader checks is true."""
    r = _run(bash, 139, attempts="1", cause="")
    assert "CAUSE NOT ESTABLISHED" in r.stdout
    assert "pyodbc" not in r.stdout, "an unproven attribution must not reach the annotation"


def test_the_database_legs_keep_their_ESTABLISHED_attribution(bash: Path) -> None:
    """MUST NAME pyodbc -- the twin, and the reason the default is not simply blank.

    Nine call sites have that class established against an upstream issue. Making the attribution
    opt-IN would have silently stripped nine correct annotations to fix one wrong one."""
    r = _run(bash, 139, attempts="1")
    assert "pyodbc" in r.stdout
    assert "1459" in r.stdout
    assert "CAUSE NOT ESTABLISHED" not in r.stdout


def test_the_database_legs_do_not_file_every_crash_under_1459(bash: Path) -> None:
    """BACKLOG #2049. A second crash class is known on those legs: the store's cancel path freed ODBC
    handles under a running statement. Both exit 139, so the wrapper cannot pick one. Naming #1459
    alone filed that crash under an upstream bug; the default must name both and say it cannot
    tell them apart."""
    r = _run(bash, 139, attempts="1")
    assert "2049" in r.stdout, "the store cancel-path class is missing from the attribution"
    assert "cannot tell them apart" in r.stdout
    assert "likely the pyodbc" not in r.stdout, "the old single-cause wording is back"


# ---------------------------------------------------------------------------------------------
# THE COVERAGE ARM -- the gap the item was filed for
# ---------------------------------------------------------------------------------------------


def test_the_main_suite_step_is_wrapped() -> None:
    """THE FILED GAP. Every retry-native-crash invocation sat in the database legs; the main suite's
    run line was a bare pytest, so the one leg most people read could not tell a crash from a
    failure."""
    text = _CI.read_text(encoding="utf-8")
    step = text.split("- name: Tests (pytest)", 1)
    assert len(step) == 2, "the Tests (pytest) step is gone -- re-derive this from the workflow"
    body = step[1].split("- name:", 1)[0]
    assert "retry-native-crash.sh" in body, (
        "the main suite's run line is unwrapped again; a native crash there reports as a test failure"
    )


def test_the_main_suite_step_declares_its_cause_unproven() -> None:
    """The coverage arm alone would let the pyodbc clause reach a leg where it is not established --
    which would fix the legibility defect by introducing an attribution one."""
    text = _CI.read_text(encoding="utf-8")
    body = text.split("- name: Tests (pytest)", 1)[1].split("- name:", 1)[0]
    assert 'RETRY_NATIVE_CRASH_CAUSE: ""' in body


def test_the_wrappers_own_grep_hint_matches_what_it_prints() -> None:
    """The header tells a reader which string to grep CI logs for. If the annotation's wording drifts
    from that hint, the documented search returns nothing and reads as 'no crashes ever happened' --
    the same silent-zero shape the surrounding items are about."""
    src = _WRAPPER.read_text(encoding="utf-8")
    hint = [ln for ln in src.splitlines() if "grep CI logs for" in ln]
    assert len(hint) == 1, hint
    token = hint[0].split('"')[1]
    assert f"::warning::{token}" in src or f"::warning::{token}" in src.replace(
        "::warning::", "::warning::"
    )
    assert token in src.split("is_native_crash", 1)[1], (
        "the hint names a string the messages do not print"
    )


def test_the_removal_note_cannot_silently_strip_an_opted_out_caller() -> None:
    """THE DEFECT NEITHER DESIGN ADDRESSED, and it is a future-reader defect rather than a runtime one.

    The wrapper's header instructs whoever fixes upstream pyodbc #1459 to remove it. That is correct
    for the database legs and WRONG for any caller whose crash cause is not that class -- and the
    note previously named ONE call site while ci.yml had ten.

    So the failure mode is somebody deleting one line in good faith, on the strength of an upstream
    fix that does not address the leg they are stripping. Nothing at runtime can catch that; the
    only guard is that the instruction stays honest about its own caller set.

    THE PREDICATE IS THE WORKFLOW, NOT A HARDCODED NAME: if any step opts out of the pyodbc
    attribution, the removal note must say removal is caller-dependent. Add such a caller without
    updating the note and this reds."""
    ci = _CI.read_text(encoding="utf-8")
    src = _WRAPPER.read_text(encoding="utf-8")
    opted_out = 'RETRY_NATIVE_CRASH_CAUSE: ""' in ci
    assert opted_out, (
        "no caller opts out any more -- if that is deliberate this arm is now vacuous and should be "
        "deleted with a reason, not left passing over nothing"
    )
    note = src.split("REMOVING THIS WRAPPER", 1)
    assert len(note) == 2, (
        "the removal instruction no longer warns that removal depends on the caller set; a reader "
        "fixing #1459 would strip the opted-out leg's crash handling silently (BACKLOG #1260)"
    )
    assert "RETRY_NATIVE_CRASH_CAUSE" in note[1].split("set -uo", 1)[0], (
        "the note must name the DISCRIMINATOR a reader can check, not just caution them in prose"
    )
