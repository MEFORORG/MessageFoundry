# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Negative controls for the required merge contexts that had none (BACKLOG #1000).

A GATE NOBODY HAS WATCHED FAIL IS AN ASSUMPTION WEARING A GREEN TICK. Fourteen contexts are the entire
merge gate as of 2026-08-31, and several of them were guarded only by the property that they exist.
This file supplies the missing plant-and-observe controls; ``tests/negative_controls.toml`` records
which control belongs to which context and ``tests/test_negative_controls.py`` fails when a context has
none.

THE COUNT IS RECORDED HERE, NEVER DERIVED HERE. ``.github/required-contexts.txt`` is the checked-in
claim and the only thing this file reads. It said thirteen until ``a reviewer has read this`` was
reconciled onto it (BACKLOG #1404), and that is exactly how a context arrives here unproven: the
reconciliation is driven by the LIVE required set, so a newly-required context lands with zero controls
and SAYS SO, rather than quietly not being looked at.

EVERY CONTROL HERE IS ASYMMETRIC, and that is the part most likely to be skipped. It is not enough that
neutering a rule turns a control red -- the control must fail for exactly the shapes that rule covers
and KEEP PASSING for the shapes some other layer catches, or it cannot tell you which layer does the
work. Measured 2026-08-05 on a different guard: a fix believed to cover two NTFS alternate-data-stream
spellings turned out to be load-bearing for exactly one, and the eight-case control that reddened on
only one of them is what said so. A uniform red would have flattered the code and taught nothing.

So each control below is paired: a planted violation the gate must see, and a benign neighbour it must
leave alone. Where the gate's own detector is what is being checked, the detector is additionally run
against a synthetic NEUTERED form of the shipped command and observed firing -- otherwise "the shipped
command is clean" is indistinguishable from "the detector matches nothing".

WHAT IS NOT HERE, said plainly. The scanner gates (bandit, gitleaks, npm-audit, pip-audit, semgrep) run
third-party binaries that this suite does not install, so what is asserted here is the property those
jobs can lose SILENTLY: an enforcement flag removed, a severity floor added, an allowlist widened until
it swallows the class. The scanners' detection itself is exercised inside their own CI jobs -- semgrep
by ``scripts/ci/assert_semgrep_handler_taint.py`` over annotated fixtures, pip-audit's slopsquat half by
``tests/test_new_dependency_check.py`` -- and the registry records which is which rather than letting
the two read as one.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
import tomllib
from pathlib import Path
from typing import Any

import pytest
from _bash_resolver import CANNOT_RUN_CODES, bash_sees, explain_returncode, require_bash

from tests._workflow_contexts import ROOT, jobs_of, load_workflow, required_contexts

_TIMEOUT = 300


# ===================================================================================================
# Child processes. PIN THE CHILD'S ENVIRONMENT -- do not inherit it.
# ===================================================================================================
def _child_env(**extra: str) -> dict[str, str]:
    """A minimal, EXPLICIT environment for a child process.

    Measured in wave 2 of this backlog pass: a lane's new test passed in its author's shell and failed
    at integration, because that shell happened to export ``PYTHONIOENCODING=utf-8`` while the test
    pinned only the PARENT's decoding. It would have passed ubuntu and reddened the Windows legs. So
    nothing is inherited here except what a child genuinely cannot run without, and the two variables
    that incident turned on are set EXPLICITLY rather than passed through.

    ``LC_ALL=C`` and the ``GIT_CONFIG_*`` overrides exist for the same reason one level over: a global
    ``core.autocrlf``, a global hooks path, or a locale that reorders ``grep`` output would otherwise
    make the result a fact about this machine.
    """
    env = {
        "PATH": os.environ.get("PATH", ""),
        "LC_ALL": "C",
        "LANG": "C",
        "PYTHONIOENCODING": "utf-8",
        "PYTHONUTF8": "1",
        "GIT_AUTHOR_NAME": "negative control",
        "GIT_AUTHOR_EMAIL": "control@example.invalid",
        "GIT_COMMITTER_NAME": "negative control",
        "GIT_COMMITTER_EMAIL": "control@example.invalid",
        "GIT_TERMINAL_PROMPT": "0",
    }
    # Windows: a child python cannot start without these, and they carry no behaviour of their own.
    for name in ("SYSTEMROOT", "SystemRoot", "COMSPEC", "TEMP", "TMP", "WINDIR", "PATHEXT"):
        if name in os.environ:
            env[name] = os.environ[name]
    env.update(extra)
    return env


def _run(argv: list[str], cwd: Path, env: dict[str, str]) -> subprocess.CompletedProcess[bytes]:
    """Run a child and return RAW BYTES.

    Decoding is done by the caller with ``errors="replace"``. A child whose output cannot be decoded
    under the ambient code page must not be able to turn an assertion about an EXIT CODE into a
    ``UnicodeDecodeError`` -- that failure mode is a property of the console, not of the gate.
    """
    return subprocess.run(  # noqa: S603  # nosec B603 - fixed argv, no shell, test-local paths
        argv, cwd=str(cwd), env=env, capture_output=True, timeout=_TIMEOUT, check=False
    )


def _text(proc: subprocess.CompletedProcess[bytes]) -> str:
    return (proc.stdout + proc.stderr).decode("utf-8", errors="replace")


# ===================================================================================================
# `CI gate` -- the roll-up that is the ONLY way six path-gated legs reach branch protection.
# ===================================================================================================
def _ci_gate_job() -> dict[str, Any]:
    return jobs_of("ci.yml")["ci-gate"]


#: The `needs.*.result` values a leg can report. The roll-up must fire on the first two and stay
#: quiet on the last two -- see the two tests below, which are opposite halves of one property.
_LEG_RESULTS = ("failure", "cancelled", "skipped", "success")


def _rollup_fail_conditions() -> list[tuple[str, str]]:
    """Every FAILING step in `ci-gate`, as (step name, condition).

    THE ROLL-UP IS ALLOWED TO BE MORE THAN ONE STEP, and reading only the first is how this file
    went wrong. The gate was split so that a real leg failure and a whole-run cancellation print
    different messages -- 440 of 646 red runs were cancellations wearing the words of a break. A
    reader that returns the first condition then sees only `contains(..., 'failure')` and reports
    that the gate has stopped covering cancelled legs, which is false and which is exactly the
    regression the tests here exist to catch. Collect them all; assert on what they do together.

    A step counts as a failing step only if it `exit 1`s. The job's final "gated legs OK" step is
    conditioned on nothing and reports success, and must not be read as part of the gate.
    """
    found = [
        (str(step.get("name", "(unnamed)")), str(step["if"]))
        for step in _ci_gate_job().get("steps", [])
        if "needs" in str(step.get("if", "")) and "exit 1" in str(step.get("run", ""))
    ]
    if not found:
        raise AssertionError(
            "ci.yml's `ci-gate` job has no failing step conditioned on `needs.*.result`. The roll-up "
            "is the only path by which six path-gated legs reach branch protection; without that "
            "condition it reports success unconditionally."
        )
    return found


def _evaluate(condition: str, results: list[str]) -> bool:
    """Evaluate one step's `if` against a synthetic results vector.

    EVALUATED, NOT PATTERN-MATCHED, AND THE DIFFERENCE IS LOAD-BEARING. The previous reader pulled
    state names out with a regex over `contains(needs.*.result, 'X')`. That regex cannot see a
    NEGATION, so the cancelled arm's guard -- `!contains(needs.*.result, 'failure') && contains(...,
    'cancelled')` -- would have reported `failure` as covered by a step that fires only when failure
    is ABSENT. The union would then have looked correct for the wrong reason: a green proving the
    opposite of what it claims. Asking what the condition DOES cannot make that mistake.

    The translated subset is deliberately tiny. Anything outside it raises rather than being
    silently mis-evaluated, because a condition this reader cannot parse is a condition it must not
    grade.
    """
    expr = re.sub(
        r"contains\(\s*needs\.\*\.result\s*,\s*'([a-z]+)'\s*\)",
        lambda m: repr(m.group(1)) + " in results",
        condition,
    )
    expr = expr.replace("&&", " and ").replace("||", " or ").replace("!", " not ")
    # Whitelist BEFORE evaluating. The input is this repository's own workflow, so this is not a
    # trust boundary -- it is a guard against grading an expression that grew syntax this function
    # does not model.
    if not re.fullmatch(r"[\s()'a-z_]+", expr):
        raise AssertionError(
            f"the roll-up condition uses syntax this reader does not model: {condition!r}. Teach "
            "_evaluate the new form rather than loosening this check -- an unmodelled operator "
            "silently changes what the gate is graded against."
        )
    return bool(eval(expr, {"__builtins__": {}}, {"results": results}))  # noqa: S307


def _rollup_fires(condition: str, results: list[str]) -> bool:
    """Does this one condition fire on this results vector?"""
    return _evaluate(condition, results)


def _gate_fires(results: list[str]) -> bool:
    """Does the gate as a WHOLE fail on this results vector? Any failing step firing is enough."""
    return any(_evaluate(cond, results) for _, cond in _rollup_fail_conditions())


def _states_the_gate_fires_on() -> set[str]:
    """The leg results that make the gate red, derived by asking it rather than by reading it.

    One planted state against five successes, per state. That is the shape the gate actually meets.
    """
    fires = set()
    for planted in _LEG_RESULTS:
        if _gate_fires(["success", "success", "skipped", "success", "skipped", planted]):
            fires.add(planted)
    return fires


def test_the_ci_gate_rollup_fires_on_a_failed_or_cancelled_leg() -> None:
    """PLANTED: one gated leg reports `failure`, then `cancelled`. The roll-up must fire on both.

    `CI gate` is required BECAUSE the six legs behind it cannot be: a path-gated job does not report on
    a PR that touches none of its paths, which wedges every such PR forever. So the roll-up is the only
    thing that turns a red sqlserver-store, postgres-store, load-test, load-test-sqlserver or
    windows-service-smoke into a blocked merge.
    """
    conditions = _rollup_fail_conditions()
    states = _states_the_gate_fires_on()
    assert states == {"failure", "cancelled"}, (
        f"the gate fires on {sorted(states)}. `failure` alone lets a CANCELLED leg -- which is what a "
        f"timed-out or infrastructure-killed run reports -- pass the merge gate. Steps: "
        f"{[name for name, _ in conditions]}"
    )
    # ASSERTED ACROSS THE WHOLE GATE, not one step. The gate may be split so that a break and a
    # supersede print different messages; what must hold is that neither state escapes it.
    for planted in ("failure", "cancelled"):
        results = ["success", "success", "skipped", "success", "skipped", planted]
        assert _gate_fires(results), (
            f"a gated leg reporting {planted!r} fires no step of the roll-up. Steps: {conditions}"
        )


def test_the_ci_gate_rollup_stays_green_when_every_gated_leg_skipped() -> None:
    """THE ASYMMETRY, and it is the case that actually happens.

    Almost every PR touches none of the six gated paths, so all six SKIP. A roll-up that failed on
    `skipped` would block every ordinary PR -- .github/required-contexts.txt records the run where all
    six skipped and `CI gate` still returned success, which is what made requiring it safe. A control
    that reddened on everything would have destroyed that property while looking stronger.
    """
    assert not _gate_fires(["skipped"] * 6)
    assert not _gate_fires(["success"] * 6)
    assert not _gate_fires(["success", "skipped", "skipped", "success", "skipped"])


def test_the_rollup_reader_reports_a_condition_that_dropped_cancelled() -> None:
    """NEGATIVE CONTROL OF THE CONTROL. Without it, "the shipped condition is fine" and "the reader
    matches nothing" are the same green."""
    neutered = "contains(needs.*.result, 'failure')"
    assert _rollup_fires(neutered, ["failure"])
    assert not _rollup_fires(neutered, ["cancelled"]), (
        "the reader cannot see a dropped terminal state"
    )
    assert _gate_fires(["cancelled"]), (
        "...and it does see the shipped gate, so the assertion above is about the workflow rather "
        "than about the reader"
    )
    # SECOND CONTROL, for the failure mode the first one cannot reach. A reader that pattern-matched
    # state names would grade a NEGATED term as covered, so a step firing only when failure is ABSENT
    # would look like it covers failure. Evaluating cannot, and this planted condition proves the
    # reader is evaluating: it mentions 'failure' and must still not fire on it.
    inverted = "!contains(needs.*.result, 'failure') && contains(needs.*.result, 'cancelled')"
    assert not _rollup_fires(inverted, ["failure"]), (
        "the reader treats a NEGATED contains() as coverage, so a condition that fires only when a "
        "state is absent reads as covering it"
    )
    assert _rollup_fires(inverted, ["cancelled"])


def test_the_rollup_steps_partition_and_each_one_exits_nonzero() -> None:
    """Two properties the SPLIT gate rests on, and neither is implied by the coverage test above.

    PARTITION: no results vector may fire two steps. The split exists so a reader learns which kind
    of event they are looking at; two steps firing at once prints both messages and takes that back.

    EXIT: every failing step must `exit 1`. A step whose condition fires and whose body returns zero
    is a gate that reports its own failure and passes anyway.
    """
    conditions = _rollup_fail_conditions()
    steps = {str(s.get("name", "(unnamed)")): s for s in _ci_gate_job()["steps"]}

    for name, _ in conditions:
        assert "exit 1" in str(steps[name].get("run", "")), (
            f"the roll-up step {name!r} does not `exit 1`, so its condition fires and the job still "
            "reports success"
        )

    # Every vector a real run can produce, over the four results a leg can report.
    for planted in _LEG_RESULTS:
        results = ["success", "success", "skipped", "success", "skipped", planted]
        fired = [name for name, cond in conditions if _evaluate(cond, results)]
        assert len(fired) <= 1, (
            f"a leg reporting {planted!r} fires {len(fired)} steps at once ({fired}). The split exists "
            "so the message names the event; overlapping conditions print two and name neither."
        )
    # The mixed case, which is the one that actually overlaps if a guard is dropped: a run holding
    # BOTH a real failure and a cancellation. The failure arm must win and the cancelled arm stay
    # quiet, or a genuine break gets reported as a supersede and read as expected noise.
    both = ["success", "failure", "cancelled", "skipped", "success", "success"]
    fired = [name for name, cond in conditions if _evaluate(cond, both)]
    assert len(fired) == 1, (
        f"a run holding a failure AND a cancellation fires {fired}. Exactly one message must win, and "
        "it must be the failure -- a real break reported in the words of a supersede is read as noise."
    )
    # WHICH step wins is asserted BEHAVIOURALLY, never by reading its name. A name match would pass
    # or fail on wording -- and the pre-split step was called "Fail if any gated leg failed or was
    # cancelled", which contains both words and would grade as either arm. The failure arm is the
    # step that fires on a failure with no cancellation anywhere; that is a property of the
    # condition, and renaming the step cannot move it.
    failure_only = ["success", "failure", "skipped", "success", "success", "success"]
    winner_on_failure = [name for name, cond in conditions if _evaluate(cond, failure_only)]
    assert winner_on_failure == fired, (
        f"a mixed run fires {fired} but a failure-only run fires {winner_on_failure}. The step that "
        "wins when both are present must be the same one that reports a plain failure, or a real "
        "break gets announced in the words of a supersede and read as expected noise."
    )


def test_the_ci_gate_rollup_still_covers_every_leg_it_is_required_for() -> None:
    """A leg dropped from `needs:` leaves branch protection with no path to it at all -- the roll-up
    keeps reporting success and the leg's failures stop mattering, silently."""
    needs = set(_ci_gate_job().get("needs", []))
    gated = {
        "sqlserver-store",
        "postgres-store",
        "load-test",
        "load-test-sqlserver",
        "windows-service-smoke",
    }
    missing = sorted(gated - needs)
    print(f"[#1000] ci-gate needs: {sorted(needs)}")
    assert not missing, (
        f"these gated legs are no longer behind the roll-up: {missing}. They cannot be required "
        "directly (a path-gated job does not report on a PR that misses its paths), so nothing on the "
        "merge path would notice them going red."
    )


# ===================================================================================================
# `test (<os>, py3.14)` -- can the test legs go red at all?
# ===================================================================================================
_FAILING_FIXTURE = "def test_planted_failure():\n    assert 1 == 2, 'planted'\n"
_PASSING_FIXTURE = "def test_planted_pass():\n    assert 1 == 1\n"


def _run_pytest_on(fixture: str, tmp_path: Path, **env_extra: str) -> int:
    """Run a child pytest over ONE fixture file, outside this repository's rootdir.

    The assertion is on the EXIT CODE only. Exit codes are encoding-independent, which is the point:
    the wave-2 incident this guards against turned on a child's stdout ENCODING, and an assertion that
    reads the child's text is exactly the assertion that inherits it.
    """
    work = tmp_path / f"probe_{abs(hash(fixture)) % 10000}"
    work.mkdir()
    (work / "test_probe.py").write_text(fixture, encoding="utf-8")
    proc = _run(
        [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", str(work)],
        cwd=work,
        env=_child_env(**env_extra),
    )
    print(f"[#1000] child pytest exit={proc.returncode} env_extra={env_extra}")
    return proc.returncode


def test_a_failing_test_makes_the_pytest_leg_exit_nonzero(tmp_path: Path) -> None:
    """PLANTED: a test that cannot pass. The runner must exit non-zero, or the three `test` contexts --
    the largest block of the merge gate -- are decoration.

    This is not hypothetical plumbing. BACKLOG #1000 records the measured case one layer over: running
    an emitted command via `pwsh -File script.ps1` returns 0 even when the script inside died at
    parameter binding, so every execution assertion built on that return code was vacuously green. It
    was found only by writing a control that had to fail and watching it pass.
    """
    assert _run_pytest_on(_FAILING_FIXTURE, tmp_path) != 0, (
        "a deliberately failing test did not make pytest exit non-zero"
    )


def test_a_passing_fixture_leaves_the_pytest_leg_green(tmp_path: Path) -> None:
    """THE ASYMMETRY. A runner that exited non-zero unconditionally would satisfy the control above
    while blocking every PR, and nothing would say which of the two it was."""
    assert _run_pytest_on(_PASSING_FIXTURE, tmp_path) == 0


def test_the_pytest_exit_code_does_not_depend_on_the_ambient_encoding(tmp_path: Path) -> None:
    """PROVEN UNDER A HOSTILE AMBIENT VALUE, not merely a favourable one.

    A control that only ever ran under `PYTHONIOENCODING=utf-8` proves nothing about the Windows legs,
    where the ambient value is whatever the console code page says. Both probes are re-run with the
    child pinned to a HOSTILE encoding; the exit codes must be identical, because they are the only
    thing asserted.
    """
    assert _run_pytest_on(_FAILING_FIXTURE, tmp_path, PYTHONIOENCODING="ascii", PYTHONUTF8="0") != 0
    assert _run_pytest_on(_PASSING_FIXTURE, tmp_path, PYTHONIOENCODING="ascii", PYTHONUTF8="0") == 0


# ===================================================================================================
# `a PR that implements BACKLOG #N must update BACKLOG.md` -- the gate that went green enforcing
# nothing, run as the SHIPPED SHELL against a synthetic repository.
# ===================================================================================================
_HYGIENE_JOB = "banner-on-implementation"


def _hygiene_script() -> str:
    steps = jobs_of("backlog-hygiene.yml")[_HYGIENE_JOB]["steps"]
    script = next(str(s["run"]) for s in steps if "run" in s)
    assert "BASE_SHA...$HEAD_SHA" in script or "$BASE_SHA...$HEAD_SHA" in script, (
        "backlog-hygiene.yml's diff is no longer three-dot. The two-dot form reports main-side changes "
        "as reverse deltas, which credited every PR with an older base for a docs/BACKLOG.md edit it "
        "never made -- the gate went green while enforcing nothing."
    )
    return script


def _bash_sees(bash: Path, tmp_path: Path) -> bool:
    """Delegates to the shared probe, under THIS module's explicit child environment.

    The logic moved to ``tests/_bash_resolver.py`` (BACKLOG #1216): it was proven here on 2026-08-10
    and then three other modules kept their own ``shutil.which`` guards, so the defect survived
    everywhere it had not been fixed. Two copies of a resolver are free to disagree, and the copy that
    disagrees is the one still manufacturing failures. The ``env`` is passed rather than inlined
    because ``_child_env`` carries this module's git-config overrides, which the shared helper has no
    business knowing about.
    """
    return bash_sees(bash, tmp_path, _child_env())


def _require_bash(tmp_path: Path) -> str:
    """A bash that can see this process's files, or a loud failure -- never a skip.

    ci.yml sets ``defaults.run.shell: bash`` on every OS, so a leg without a usable bash could not run
    the gate this control exercises, and a skip there would be a green that proves nothing. The shared
    helper raises ``RuntimeError``; it is converted to ``pytest.fail`` here so the report reads as a
    test failure rather than an error, which is how this module already reported it.
    """
    try:
        resolved = require_bash(tmp_path, _child_env())
    except RuntimeError as exc:
        pytest.fail(str(exc))
    print(f"[#1000] bash resolved to {resolved} (namespace probe passed)")
    return resolved


def _fixture_repo(tmp_path: Path, env: dict[str, str]) -> tuple[Path, str, str, str]:
    """A repository shaped like the PR the gate exists to police.

    ``A`` is the merge base. ``B`` is the PR head: it changes engine code and NOTHING else. ``C`` is
    main moving on AFTER the branch point, touching only ``docs/BACKLOG.md`` -- the shape the archive
    move produced in bulk, and the shape the two-dot diff mis-credited.
    """
    repo = tmp_path / "fixture"
    (repo / "messagefoundry").mkdir(parents=True)
    (repo / "docs").mkdir()
    _run(["git", "init", "-b", "main", "."], repo, env)
    (repo / "messagefoundry" / "engine.py").write_text("x = 1\n", encoding="utf-8")
    (repo / "docs" / "BACKLOG.md").write_text("# ledger\n", encoding="utf-8")
    _run(["git", "add", "."], repo, env)
    _run(["git", "commit", "-m", "A"], repo, env)
    base_a = _text(_run(["git", "rev-parse", "HEAD"], repo, env)).strip()

    _run(["git", "checkout", "-b", "pr"], repo, env)
    (repo / "messagefoundry" / "engine.py").write_text("x = 2\n", encoding="utf-8")
    _run(["git", "commit", "-am", "B: engine only"], repo, env)
    head_b = _text(_run(["git", "rev-parse", "HEAD"], repo, env)).strip()

    _run(["git", "checkout", "main"], repo, env)
    (repo / "docs" / "BACKLOG.md").write_text("# ledger\n\nmain moved on\n", encoding="utf-8")
    _run(["git", "commit", "-am", "C: main-side ledger edit"], repo, env)
    base_c = _text(_run(["git", "rev-parse", "HEAD"], repo, env)).strip()
    _run(["git", "checkout", "pr"], repo, env)
    assert base_a and head_b and base_c and len({base_a, head_b, base_c}) == 3
    return repo, base_c, head_b, base_a


def _run_hygiene(
    bash: str,
    script: str,
    repo: Path,
    env: dict[str, str],
    *,
    title: str,
    body: str,
    base: str,
    head: str,
) -> tuple[int, str]:
    """Run the workflow's own script, and VALIDATE THE SHAPE OF THE RESULT before returning it.

    The script path is passed RELATIVE to ``cwd``. An absolute Windows path is not portable across
    bash builds -- backslashes are escape characters and a drive letter means nothing outside the
    Windows namespace -- and the mangling presents as "no such file", i.e. as exit 127, which a caller
    comparing `code != 0` would happily read as "the gate refused this PR".

    So 126/127 are a hard failure here rather than a verdict. That is the generalisable half of the
    probe defect recorded in BACKLOG #1000: a probe must validate its own output rather than treating
    a broken invocation as an answer.

    Read from ``CANNOT_RUN_CODES`` rather than spelled out again (BACKLOG #1272). A local copy of the
    rule is free to drift from the shared one, and the copy that drifts is the one still reading a
    broken invocation as a verdict.
    """
    (repo / "gate.sh").write_text(script, encoding="utf-8", newline="\n")
    proc = _run(
        [bash, "gate.sh"],
        repo,
        {**env, "PR_TITLE": title, "PR_BODY": body, "BASE_SHA": base, "HEAD_SHA": head},
    )
    out = _text(proc)
    assert proc.returncode not in CANNOT_RUN_CODES, (
        f"bash could not execute the gate script (exit {proc.returncode}): {out.strip()[:300]}. That "
        "is not a gate verdict -- it is a broken invocation, and reading it as one would make every "
        "assertion here vacuous."
    )
    # Printed ASCII-safe: the gate's own error text carries a status glyph, and a Windows console
    # under cp1252 would turn printing it into a UnicodeEncodeError -- an assertion about the gate
    # lost to a property of the terminal.
    return proc.returncode, out


@pytest.fixture
def hygiene(tmp_path: Path) -> tuple[str, str, Path, dict[str, str], str, str]:
    env = _child_env(
        HOME=str(tmp_path),
        GIT_CONFIG_GLOBAL=str(tmp_path / "gitconfig"),
        GIT_CONFIG_SYSTEM=str(tmp_path / "gitconfig"),
    )
    (tmp_path / "gitconfig").write_text("", encoding="utf-8")
    bash = _require_bash(tmp_path)
    repo, base_c, head_b, _base_a = _fixture_repo(tmp_path, env)
    return bash, _hygiene_script(), repo, env, base_c, head_b


def _ascii(text: str) -> str:
    """Child output, safe to print under any console code page."""
    return text.encode("ascii", "backslashreplace").decode("ascii")


def test_the_bash_namespace_probe_rejects_an_interpreter_that_cannot_see_the_fixture(
    tmp_path: Path,
) -> None:
    """NEGATIVE CONTROL OF THE RESOLVER, and it is here because this file already shipped the bug once.

    MEASURED 2026-08-10. The first version resolved bash with ``shutil.which("bash")`` and passed it an
    ABSOLUTE Windows path. Under a Git Bash parent it passed; run from PowerShell, where PATH resolves
    ``bash`` to ``C:\\Windows\\System32\\bash.exe`` -- the WSL launcher, a different filesystem
    namespace -- every hygiene control failed with exit 127 and the backslashes eaten. So the control's
    verdict was a fact about PATH ORDER, which is precisely the ambient-environment green the wave-2
    incident warned about, one variable over.

    Two things fixed it and both are asserted here rather than described: the candidate is derived from
    ``git`` (which ships bash beside it) and then made to READ A FILE this process wrote, and the
    script is invoked by a RELATIVE path so no namespace conversion is involved at all.

    A candidate that cannot read the token must be rejected. ``sys.executable`` stands in for one: it
    is a real, runnable program that is not a shell, so the probe must refuse it while accepting the
    resolved bash in the same call.
    """
    assert not _bash_sees(Path(sys.executable), tmp_path), (
        "the namespace probe accepted a non-shell interpreter, so it cannot reject a bash that is "
        "looking at the wrong filesystem either"
    )
    assert _bash_sees(Path(_require_bash(tmp_path)), tmp_path)


def test_the_backlog_hygiene_gate_fails_a_code_pr_that_leaves_the_ledger_alone(
    hygiene: tuple[str, str, Path, dict[str, str], str, str],
) -> None:
    """PLANTED: a PR that claims `BACKLOG #42`, changes engine code, and never touches the ledger --
    while main has separately moved docs/BACKLOG.md since the branch point.

    That last clause is the whole point. The gate computed its changed-file list with a two-dot
    `git diff "$BASE_SHA" "$HEAD_SHA"`, which reports main-side changes as REVERSE deltas, so any
    main-side edit to docs/BACKLOG.md credited every PR with an older base. It went green while
    enforcing nothing, on exactly the population it exists to police.
    """
    bash, script, repo, env, base, head = hygiene
    code, out = _run_hygiene(
        bash,
        script,
        repo,
        env,
        title="feat: something (BACKLOG #42)",
        body="",
        base=base,
        head=head,
    )
    print(f"[#1000] shipped three-dot gate exit={code}\n{_ascii(out)}")
    assert code == 1, f"the gate passed a PR it exists to fail. exit={code}\n{_ascii(out)}"
    assert "docs/BACKLOG.md" in out


def test_the_two_dot_form_of_the_gate_passes_the_same_planted_pull_request(
    hygiene: tuple[str, str, Path, dict[str, str], str, str],
) -> None:
    """RUN AGAINST THE PRE-FIX GATE, which is what makes the control above evidence rather than a
    claim. The identical fixture, with only the diff form reverted, must go GREEN.

    If both forms failed, the fixture would be proving something else -- and the recorded defect would
    be unreproduced.
    """
    bash, script, repo, env, base, head = hygiene
    pre_fix = script.replace('"$BASE_SHA...$HEAD_SHA"', '"$BASE_SHA" "$HEAD_SHA"')
    assert pre_fix != script, (
        "the two-dot substitution matched nothing, so this test compares the shipped gate with itself"
    )
    code, out = _run_hygiene(
        bash,
        pre_fix,
        repo,
        env,
        title="feat: something (BACKLOG #42)",
        body="",
        base=base,
        head=head,
    )
    print(f"[#1000] pre-fix two-dot gate exit={code}\n{_ascii(out)}")
    assert code == 0, (
        "the two-dot form no longer reproduces the recorded defect, so the three-dot assertion above "
        f"is not measuring what it says. exit={code}\n{_ascii(out)}"
    )


@pytest.mark.parametrize(
    ("case", "title", "body", "touch"),
    [
        ("no claim at all", "chore: tidy", "", None),
        ("claims and updates the ledger", "feat (BACKLOG #42)", "", "docs/BACKLOG.md"),
        (
            "claims and updates an ARCHIVED item",
            "feat (BACKLOG #42)",
            "",
            "docs/archive/backlog/x.md",
        ),
        ("a bare #42 is a PR number, not a claim", "fix for #42", "see #42", None),
    ],
)
def test_the_backlog_hygiene_gate_leaves_the_benign_shapes_alone(
    hygiene: tuple[str, str, Path, dict[str, str], str, str],
    case: str,
    title: str,
    body: str,
    touch: str | None,
) -> None:
    """THE ASYMMETRY, four shapes wide.

    A gate that failed everything would satisfy the planted case and block every PR in the repo. Each
    row is a shape the rule deliberately does NOT break: no claim, a claim honoured in the live ledger,
    a claim honoured in the ARCHIVE (an item retired between the claim and the PR), and the `#42`
    spelling that is a PR number in this repo rather than an item.
    """
    bash, script, repo, env, base, head = hygiene
    if touch:
        target = repo / touch
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("banner\n", encoding="utf-8")
        _run(["git", "add", "-A"], repo, env)
        _run(["git", "commit", "-m", f"branch-side {touch}"], repo, env)
        head = _text(_run(["git", "rev-parse", "HEAD"], repo, env)).strip()
    code, out = _run_hygiene(bash, script, repo, env, title=title, body=body, base=base, head=head)
    print(f"[#1000] benign case {case!r} exit={code}")
    assert code == 0, f"the gate failed a benign PR shape ({case}). exit={code}\n{_ascii(out)}"


# ===================================================================================================
# `gitleaks (secret scan)` -- the allowlist is the neutering path a scope test cannot see.
# ===================================================================================================
_GITLEAKS = ROOT / ".gitleaks.toml"


def _gitleaks_allowlist_regexes() -> list[str]:
    parsed = tomllib.loads(_GITLEAKS.read_text(encoding="utf-8"))
    return [str(r) for r in (parsed.get("allowlist") or {}).get("regexes", [])]


def _fabricated_secrets() -> list[str]:
    """Credential-shaped strings ASSEMBLED AT RUNTIME.

    Never committed as literals: gitleaks scans this repository and cannot tell a well-known test
    vector from a live credential -- the sibling redaction suite already had a fixture rejected for
    exactly that, correctly. Assembling from parts keeps the scanner useful on this file.
    """
    hexish = "0123456789abcdef" * 3
    return [
        "AKIA" + "Q" * 16,
        "ghp_" + "z" * 36,
        "xoxb-" + "1" * 12 + "-" + "2" * 24,
        "-----BEGIN " + "RSA PRIVATE KEY-----",
        hexish[:40],
        "postgres://svc:" + "P" * 24 + "@db.invalid:5432/x",
    ]


def _swallowing(regexes: list[str], corpus: list[str]) -> list[str]:
    return [r for r in regexes if any(re.search(r, s) for s in corpus)]


def test_no_gitleaks_allowlist_regex_swallows_a_fabricated_secret() -> None:
    """PLANTED: six credential shapes gitleaks' default ruleset exists to catch.

    ``.gitleaks.toml`` is the one place this required context can be disabled without touching a
    workflow: an allowlist entry broad enough to match a real credential turns the gate green while it
    keeps scanning. Every shipped entry is deliberately a LITERAL or a tightly bounded pattern, and
    this is the assertion that keeps it that way.
    """
    regexes = _gitleaks_allowlist_regexes()
    print(
        f"[#1000] scanned {len(regexes)} gitleaks allowlist regexes against "
        f"{len(_fabricated_secrets())} fabricated credential shapes"
    )
    assert regexes, (
        ".gitleaks.toml parsed to ZERO allowlist regexes -- the format changed under this"
    )
    swallowed = _swallowing(regexes, _fabricated_secrets())
    assert not swallowed, (
        f"these allowlist regexes match a fabricated credential: {swallowed}. NEVER allowlist a real "
        "secret; a broad entry here neuters a required context with no workflow edit at all."
    )


def test_the_allowlist_narrowness_detector_fires_on_a_planted_broad_regex() -> None:
    """NEGATIVE CONTROL OF THE CONTROL, and the ASYMMETRY.

    "The shipped allowlist is narrow" and "the detector matches nothing" are the same green. Two broad
    patterns are planted and must be caught; the shipped entries must stay clean in the same call, so
    the control is not merely demanding an empty allowlist -- which would delete a legitimate,
    documented set of non-secret fixtures.
    """
    planted = [r".{8,}", r"[A-Za-z0-9_/+-]{20,}"]
    assert _swallowing(planted, _fabricated_secrets()) == planted, (
        "the detector cannot see a broad regex"
    )
    assert not _swallowing(_gitleaks_allowlist_regexes(), _fabricated_secrets())


def test_the_gitleaks_config_still_extends_the_default_ruleset() -> None:
    """`useDefault = false` empties the ruleset and the job then scans for the project's own rules
    only -- of which there are none. It reports success in seconds."""
    parsed = tomllib.loads(_GITLEAKS.read_text(encoding="utf-8"))
    assert parsed.get("extend", {}).get("useDefault") is True, (
        ".gitleaks.toml no longer extends the default ruleset; the secret scan has nothing to match"
    )


# ===================================================================================================
# `bandit (Python SAST)` and `npm-audit` -- a severity floor mutes a gate without touching its scope.
# ===================================================================================================
def _step_run(workflow: str, job: str, name_fragment: str) -> str:
    for step in jobs_of(workflow)[job].get("steps", []):
        if name_fragment in str(step.get("name", "")):
            return str(step.get("run", ""))
    raise AssertionError(f"{workflow}:{job} has no step named like {name_fragment!r}")


#: Flags that keep a scanner running while discarding part of what it finds. NOT the `|| true` family
#: (tests/test_security_posture.py owns that) -- these leave the exit code intact and shrink the input
#: to it, which a neutering scan looking for added idioms cannot see.
_MUTING_FLAGS = {
    "bandit": (
        r"(?<!\w)-l{1,3}(?!\w)",
        r"--severity-level(?!\s+low)",
        r"--confidence-level",
        r"--exit-zero",
    ),
    "npm": (r"--audit-level", r"--omit(?!\s*$)", r"--production"),
}


def _muted(command: str, family: str) -> list[str]:
    body = "\n".join(line for line in command.splitlines() if not line.lstrip().startswith("#"))
    return [p for p in _MUTING_FLAGS[family] if re.search(p, body)]


def test_the_bandit_invocation_carries_no_severity_or_confidence_floor() -> None:
    """PLANTED via the detector: `bandit -ll` reports only MEDIUM and above and still exits non-zero
    on what is left, so the job stays green-looking and blocking while it stops reporting a whole
    severity band. The scope test next door asks WHAT it is pointed at; this asks what it keeps."""
    command = _step_run("security.yml", "bandit", "Scan source for insecure patterns")
    found = _muted(command, "bandit")
    print(f"[#1000] bandit invocation scanned for {len(_MUTING_FLAGS['bandit'])} muting flags")
    assert not found, (
        f"the bandit invocation carries {found}, which discards findings while the required context "
        f"keeps reporting success. Command: {command!r}"
    )


def test_the_npm_audit_invocation_carries_no_severity_floor() -> None:
    """`npm audit --audit-level=high` exits 0 on moderate advisories. security.yml's own comment says
    the default level "fails on ANY severity, matching pip-audit's strict posture" -- this is the
    assertion that keeps that sentence true."""
    command = _step_run("security.yml", "npm-audit", "Audit the locked npm dependencies")
    found = _muted(command, "npm")
    assert not found, f"the npm audit invocation carries {found}: {command!r}"


def test_the_muting_detector_fires_on_a_synthetic_floor() -> None:
    """NEGATIVE CONTROL OF THE CONTROL, plus the ASYMMETRY that matters here: the detector must NOT
    fire on the reviewed `--skip B101,...` list, which is a per-check exclusion with a stated reason
    for each entry -- not a severity floor. A detector that flagged it would be "fixed" by deleting a
    correct annotation."""
    assert _muted("bandit -r . -ll --skip B101", "bandit") == [r"(?<!\w)-l{1,3}(?!\w)"]
    assert _muted("npm audit --package-lock-only --audit-level=high", "npm") == [r"--audit-level"]
    assert _muted("bandit -r . --skip B101,B110,B311,B404,B608 --exclude ./tests", "bandit") == []
    assert _muted("npm audit --package-lock-only", "npm") == []


# ===================================================================================================
# `npm-audit` again -- the lockfile it audits has to exist, or `--package-lock-only` audits nothing.
# ===================================================================================================
def test_the_npm_audit_target_lockfile_exists() -> None:
    """`npm audit --package-lock-only` reads the committed lockfile. Without it the job errors or
    audits an empty tree, and `working-directory: ide` is the only thing pointing it at one."""
    workflow = load_workflow("security.yml")
    job = workflow["jobs"]["npm-audit"]
    workdir = str(((job.get("defaults") or {}).get("run") or {}).get("working-directory", ""))
    assert workdir, "the npm-audit job lost its working-directory; it would audit the repo root"
    lock = ROOT / workdir / "package-lock.json"
    assert lock.is_file(), f"{lock} does not exist, so --package-lock-only has nothing to audit"


# ===================================================================================================
# `cla` -- the context string IS the control surface, and it has been wrong in this repo before.
# ===================================================================================================
def test_the_cla_job_still_reports_under_the_job_key_and_not_the_workflow_name() -> None:
    """PLANTED historically, not synthetically: docs/CI.md and cla.yml both told a reader to require
    "CLA Assistant" -- the WORKFLOW name, which matches no status check. Adding it to branch
    protection would have wedged every PR forever.

    The detection this gate performs lives entirely in a third-party action, so what is controllable
    here is whether the context can report at all: the job must declare no `name:` (making the context
    its KEY, `cla`) and must run on a pull-request trigger.
    """
    jobs = jobs_of("cla.yml")
    assert "cla" in jobs, f"cla.yml's job key is no longer `cla`: {sorted(jobs)}"
    assert "name" not in jobs["cla"], (
        "the cla job declared a `name:`, which changes its status-check context string. Branch "
        "protection still requires `cla`, so the context would never report and every PR would wedge."
    )
    workflow = load_workflow("cla.yml")
    triggers = workflow.get("on") or workflow.get(True) or {}
    assert "pull_request_target" in triggers or "pull_request" in triggers, (
        f"cla.yml has no pull-request trigger ({sorted(triggers)}), so the required `cla` context can "
        "never report -- the required-but-absent trap"
    )


def test_the_cla_allowlist_is_an_enumeration_and_not_a_glob() -> None:
    """THE ASYMMETRY, and a recorded finding rather than a hypothetical: a `bot*` glob would let any
    human whose username begins with "bot" skip signing (review low-28). The allowlist is legitimate
    and must keep working -- so this asserts its SHAPE, not its absence."""
    # SELECT THE STEP BY WHAT IT IS, NOT BY "it happens to have a with block". The original
    # selector took the FIRST step carrying `with`, which was the CLA action only because no
    # earlier step had one. Adding `persist-credentials: false` to the checkout step above it
    # made the checkout match first and this test died on KeyError: 'allowlist' -- reading a
    # step it was never meant to read. It had been passing on step ORDER, not identity.
    steps = jobs_of("cla.yml")["cla"]["steps"]
    candidates = [s for s in steps if "allowlist" in (s.get("with") or {})]
    assert len(candidates) == 1, (
        f"expected exactly ONE step in cla.yml carrying an `allowlist`, found {len(candidates)}; "
        "this test asserts the shape of THAT allowlist and cannot pick between several"
    )
    allowlist = str(candidates[0]["with"]["allowlist"])
    assert allowlist.strip(), (
        "the CLA allowlist emptied; every maintainer push would need a signature"
    )
    assert "*" not in allowlist, f"the CLA allowlist contains a glob: {allowlist!r}"


# ===================================================================================================
# SIBLING CITATIONS -- the gate saw the first item and none of the rest (BACKLOG #1347).
# ===================================================================================================

# The house citation form writes the BACKLOG prefix ONCE and the siblings after it:
# `(BACKLOG #1319, #1322, #1323, #1331)`. The gate extracted the first match with
# `grep -oiE 'BACKLOG #[0-9]+' | head -1`, so a four-item PR was told to update ONE banner.
#
# The failure direction is the expensive one. It is not that the gate wrongly passes -- any
# backlog-namespace edit satisfies it -- but that its ERROR TEXT names one item of four, and a
# citation screen built on the same rule reports three landed siblings as never delivered.
#
# THE SQUASH SUFFIX IS THE TRAP ON THE OTHER SIDE, and it is why the rule is scoped to the
# parenthetical rather than "every #N after the token". A landed subject reads
# `(BACKLOG #1040) (#547)`; an unscoped rule claims item 547. Measured over `git log --all` on
# 2026-08-25: unscoped calls 641 subjects multi-item, parenthetical-scoped calls 38 of 1070.


def test_the_hygiene_gate_names_every_cited_sibling_not_just_the_first(
    hygiene: tuple[str, str, Path, dict[str, str], str, str],
) -> None:
    bash, script, repo, env, base, head = hygiene
    # A code change with no ledger edit: the gate must refuse, and its message is what we read.
    target = repo / "messagefoundry" / "x.py"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text("x = 1\n", encoding="utf-8")
    _run(["git", "add", "-A"], repo, env)
    _run(["git", "commit", "-m", "code"], repo, env)
    head = _text(_run(["git", "rev-parse", "HEAD"], repo, env)).strip()

    code, out = _run_hygiene(
        bash,
        script,
        repo,
        env,
        title="four gates (BACKLOG #1319, #1322, #1323, #1331)",
        body="",
        base=base,
        head=head,
    )
    assert code != 0, f"a code PR with no ledger edit must be refused\n{_ascii(out)}"
    for item in ("1319", "1322", "1323", "1331"):
        assert item in out, (
            f"the gate refused but never named item #{item}. It used to report only the first of a "
            f"sibling group, sending the author to update one banner of four.\n{_ascii(out)}"
        )


def test_the_hygiene_gate_does_not_read_a_squash_suffix_as_an_item(
    hygiene: tuple[str, str, Path, dict[str, str], str, str],
) -> None:
    """The negative that bounds the fix.

    Widening from "the first BACKLOG #N" to "every #N after the token" would close the sibling gap
    and open this one: a squash-merged title carries the pull-request number as a trailing group,
    and the gate would demand a status banner for a PR number. Scoping to the parenthetical is what
    buys the first without the second, so both directions are pinned.
    """
    bash, script, repo, env, base, head = hygiene
    target = repo / "messagefoundry" / "x.py"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text("x = 1\n", encoding="utf-8")
    _run(["git", "add", "-A"], repo, env)
    _run(["git", "commit", "-m", "code"], repo, env)
    head = _text(_run(["git", "rev-parse", "HEAD"], repo, env)).strip()

    code, out = _run_hygiene(
        bash,
        script,
        repo,
        env,
        title="fix(hooks): the deny text (BACKLOG #1040) (#547)",
        body="",
        base=base,
        head=head,
    )
    assert code != 0
    assert "1040" in out, f"the real item must still be named\n{_ascii(out)}"
    assert "547" not in out, (
        "the gate read the squash-merge pull-request suffix as a backlog item. A banner would be "
        f"demanded for a PR number that has no ledger row.\n{_ascii(out)}"
    )


# ===================================================================================================
# A CONTEXT THAT CAN GO ABSENT -- the structural half of the review-gate controls below.
# ===================================================================================================
#
# A required check that never REPORTS blocks every pull request forever, and it is the failure with
# the least warning attached: nothing turns red, pull requests simply stop becoming mergeable.
# codeql.yml's header records the measured case. On 2026-08-27 the first entry this repository's merge
# queue ever held sat AWAITING_CHECKS with 32 check-runs green and three CodeQL contexts absent,
# because that workflow declared no `merge_group:` trigger (BACKLOG #340).
#
# `a reviewer has read this` was armed on 2026-08-31 and is exposed to the same failure, so the
# detector is written once here rather than inline where it could grow a second copy free to disagree.


def _triggers_of(workflow: str) -> dict[str, Any]:
    """A workflow's `on:` block.

    PyYAML reads YAML 1.1, in which the bare key ``on`` is the BOOLEAN True -- so the fallback is not
    defensive padding, it is the ordinary path for a file whose key is unquoted.
    """
    parsed = load_workflow(workflow)
    block = parsed.get("on", parsed.get(True))
    assert isinstance(block, dict), f"{workflow}'s `on:` did not parse to a mapping: {block!r}"
    return block


def _absence_risks(triggers: dict[str, Any]) -> list[str]:
    """Ways this trigger set lets a REQUIRED context fail to report at all."""
    risks: list[str] = []
    if "pull_request" not in triggers and "pull_request_target" not in triggers:
        risks.append("no pull-request trigger: the context can never report on a pull request")
    if "merge_group" not in triggers:
        risks.append(
            "no `merge_group:` trigger: the context never reports on a queue entry, so nothing "
            "merges once the queue is enabled (BACKLOG #340, measured on PR 619)"
        )
    block = triggers.get("pull_request") or triggers.get("pull_request_target") or {}
    if isinstance(block, dict):
        risks.extend(
            f"`pull_request.{key}` filter: the workflow skips a pull request touching none of those "
            "paths, and a skipped required context never reports"
            for key in ("paths", "paths-ignore")
            if key in block
        )
    return risks


def test_the_absence_detector_fires_on_a_trigger_set_that_can_go_quiet() -> None:
    """NEGATIVE CONTROL OF THE DETECTOR, and the asymmetry the two controls below rest on.

    "The shipped triggers are safe" and "the detector matches nothing" are the same green, which is
    the pair this registry exists to separate. Three planted trigger sets must each be named -- and a
    set carrying EXTRA events must stay clean, because widening when a workflow reports is legitimate
    and a detector that flagged it would be "fixed" by deleting a cron nobody wanted removed.
    """
    assert _absence_risks({"push": None}), "the detector cannot see a missing pull-request trigger"
    assert _absence_risks({"pull_request": None}), "the detector cannot see a missing merge_group"
    assert _absence_risks({"pull_request": {"paths": ["ide/**"]}, "merge_group": None}), (
        "the detector cannot see a paths filter, which is how a required context goes absent without "
        "any trigger being removed at all"
    )
    assert (
        _absence_risks(
            {
                "pull_request": {"branches": ["main"]},
                "merge_group": None,
                "push": {"branches": ["main"]},
                "schedule": [{"cron": "0 7 * * 1"}],
                "workflow_dispatch": None,
            }
        )
        == []
    ), "the detector flagged a trigger set that only ADDS events; widening is not the hazard"


# ===================================================================================================
# `a reviewer has read this` -- run as the SHIPPED SHELL against planted label sets.
# ===================================================================================================
#
# ARMED 2026-08-31 (BACKLOG #1404). With `required_approving_review_count` pinned at 0 -- every
# session on this machine pushes as one GitHub identity, so a human-approval rule would wedge every
# pull request rather than review any -- this single context is the repository's ENTIRE review
# requirement. Nothing else anywhere reports that a green pull request was never read, so a gate that
# could not go red here would not be a weakened control, it would be the absence of one.
#
# The gate's OWN shell is lifted out of the workflow and run, never re-implemented: a second copy of
# that `case` would be free to agree with itself.
_REVIEW_GATE = "review-gate.yml"
_REVIEW_GATE_JOB = "reviewed"
_REVIEW_GATE_CONTEXT = "a reviewer has read this"
_LABEL_STEP = "Require the reviewed label"


def _review_gate_script() -> str:
    """The label-reading step's shell, with the shape this control depends on asserted first."""
    steps = jobs_of(_REVIEW_GATE)[_REVIEW_GATE_JOB]["steps"]
    matches = [s for s in steps if _LABEL_STEP in str(s.get("name", ""))]
    assert len(matches) == 1, (
        f"expected exactly ONE step named like {_LABEL_STEP!r} in {_REVIEW_GATE}, found "
        f"{len(matches)}; this control runs THAT step's shell and cannot pick between several"
    )
    script = str(matches[0]["run"])
    assert "$LABELS" in script and "$ACTION" in script, (
        "the label-reading step no longer reads $LABELS and $ACTION, so this control would be feeding "
        f"input to a script that ignores it and every verdict below would be about nothing: {script!r}"
    )
    return script


def _run_review_gate(
    bash: str, script: str, workdir: Path, env: dict[str, str], *, labels: str, action: str
) -> tuple[int, str]:
    """Run the step's shell UNDER THE FLAGS ACTIONS USES, and validate the invocation.

    GitHub runs a `run:` block as `bash --noprofile --norc -e -o pipefail {0}`. Reproducing those
    flags is not decoration: `-e` changes which line can end the script, and a control run under a
    friendlier shell would be measuring a step CI never executes.

    126/127 are a HARNESS fault, never a gate verdict. A caller comparing `code != 0` would otherwise
    read a broken invocation as "the gate refused this pull request" -- the shape BACKLOG #1216
    records, where a mangled script path made six assertions vacuously green.
    """
    (workdir / "review_gate.sh").write_text(script, encoding="utf-8", newline="\n")
    proc = _run(
        [bash, "--noprofile", "--norc", "-e", "-o", "pipefail", "review_gate.sh"],
        workdir,
        {**env, "LABELS": labels, "ACTION": action},
    )
    out = _text(proc)
    assert proc.returncode not in (126, 127), (
        f"{explain_returncode(proc.returncode, 'the review-gate step')} Output: {out.strip()[:300]}"
    )
    return proc.returncode, out


@pytest.fixture
def review_gate(tmp_path: Path) -> tuple[str, str, Path, dict[str, str]]:
    return _require_bash(tmp_path), _review_gate_script(), tmp_path, _child_env()


#: Label sets that must be REFUSED. The near-misses are the interesting half: the gate matches
#: `,reviewed,` against the comma-joined list, so it is an EXACT-ELEMENT test, and a substring rule
#: -- the obvious way to write this -- would pass every one of them.
_UNREAD = (
    ("", "opened", "a brand-new pull request carries no labels; the default state must be blocked"),
    ("bug,enhancement", "opened", "unrelated labels are not a review"),
    ("reviewed-by-bot", "labeled", "a label CONTAINING the token is not the token"),
    ("not-reviewed", "reopened", "a label carrying it as a suffix, which reads as the opposite"),
    ("Reviewed", "labeled", "the wrong case; the repository's label is lowercase `reviewed`"),
    ("re,viewed", "labeled", "the token split across two labels"),
)

#: Label sets that must PASS. The position cases are the asymmetry: a rule anchored to the start or
#: the end of the joined list would refuse a correctly-labelled pull request that carries others too.
_READ = (
    ("reviewed", "labeled", "the ordinary case: one label, added by a reviewer"),
    ("reviewed,bug", "opened", "the token FIRST among several"),
    ("bug,reviewed", "reopened", "the token LAST among several"),
    ("bug,reviewed,enhancement", "ready_for_review", "the token in the middle"),
)


def test_the_review_gate_refuses_a_pull_request_nobody_has_marked_read(
    review_gate: tuple[str, str, Path, dict[str, str]],
) -> None:
    """PLANTED: six label sets that are not a review, run through the shipped shell.

    This is the gate going RED, which is the whole property. Until the context was armed nothing in
    this repository had watched it do so, and it backs the only review control there is.
    """
    bash, script, workdir, env = review_gate
    for labels, action, why in _UNREAD:
        code, out = _run_review_gate(bash, script, workdir, env, labels=labels, action=action)
        print(f"[#1000] review gate labels={labels!r} action={action} exit={code}")
        assert code != 0, (
            f"the review gate PASSED a pull request nobody has read ({why}). labels={labels!r} "
            f"action={action!r}\n{_ascii(out)}"
        )
        assert "add-label reviewed" in out, (
            "the gate refused but did not name the remedy. It is a LABEL, and a reader who guesses at "
            f"a rebase fires `synchronize`, which strips one.\n{_ascii(out)}"
        )


def test_the_review_gate_refuses_a_synchronize_even_when_the_payload_shows_the_label(
    review_gate: tuple[str, str, Path, dict[str, str]],
) -> None:
    """PLANTED: the STALE PAYLOAD, and the single most load-bearing line in this gate.

    On `synchronize` the previous step has just removed the label, so the event payload is one step
    out of date. Reading it would pass a pull request that was invalidated moments earlier. This is
    the one case where the gate must refuse a payload that says `reviewed`, and it is the whole
    difference between "a reviewer read THESE commits" and "a reviewer read some earlier ones".
    """
    bash, script, workdir, env = review_gate
    code, out = _run_review_gate(
        bash, script, workdir, env, labels="reviewed", action="synchronize"
    )
    assert code != 0, (
        "the gate accepted a `synchronize` on the strength of a label the step before it had already "
        f"removed. Commits nobody has read would merge as reviewed.\n{_ascii(out)}"
    )


def test_the_review_gate_passes_a_pull_request_a_reviewer_has_marked_read(
    review_gate: tuple[str, str, Path, dict[str, str]],
) -> None:
    """THE ASYMMETRY. A gate that refused everything would satisfy both tests above while wedging every
    pull request in the repository -- and with `strict = true` on branch protection, permanently.

    The position cases are deliberate rather than padding: a reviewed pull request routinely carries
    other labels, so the token has to be found first, last and in the middle of the joined list.
    """
    bash, script, workdir, env = review_gate
    for labels, action, why in _READ:
        code, out = _run_review_gate(bash, script, workdir, env, labels=labels, action=action)
        print(f"[#1000] review gate labels={labels!r} action={action} exit={code}")
        assert code == 0, (
            f"the gate refused a pull request a reviewer HAD marked read ({why}). labels={labels!r} "
            f"action={action!r}\n{_ascii(out)}"
        )


def test_the_review_gate_still_reports_under_the_required_context_string() -> None:
    """The other way this gate dies, and the quieter one: the context stops arriving at all.

    Three surfaces, every one of them in-repo. The job NAME is the context string; a job-level `if:`
    would let the job skip, and a skipped required check reports nothing; the trigger set decides
    whether it reports on a pull request and in the merge queue. The `cla` control is this same shape
    for the same reason -- where the context string is the surface, the string is what to pin.
    """
    job = jobs_of(_REVIEW_GATE)[_REVIEW_GATE_JOB]
    # THIS TEST USED TO ASSERT THE CONTEXT WAS REQUIRED, and that assertion has been REMOVED rather
    # than weakened, because the owner retired the reviewer requirement on 2026-09-04 and the context
    # left branch protection the same day. Its message was right about the consequence and is kept
    # here so nobody re-derives it: with `required_approving_review_count` pinned at 0, dropping this
    # context does not weaken the review requirement, it removes it. That is now the recorded state,
    # not a regression -- docs/CI.md says so in the same words.
    #
    # What remains below still earns its keep while the workflow runs: the job must keep reporting
    # under its own name, must not grow a job-level `if:`, and must not acquire a trigger set that
    # goes quiet. Those are the properties that would have to hold on the day anyone re-arms it, and
    # they rot silently in the meantime.
    assert _REVIEW_GATE_CONTEXT not in required_contexts(), (
        f"{_REVIEW_GATE_CONTEXT!r} is back in .github/required-contexts.txt. Re-arming the review "
        "gate is an owner decision; if that is what happened, restore the assertion this comment "
        "replaced, its negative control in tests/negative_controls.toml, and the docs/CI.md entry."
    )
    assert str(job.get("name")) == _REVIEW_GATE_CONTEXT, (
        f"the job name is {job.get('name')!r}, so it reports under a different context string than "
        f"branch protection requires. {_REVIEW_GATE_CONTEXT!r} would never report and every pull "
        "request would wedge."
    )
    assert "if" not in job, (
        f"the {_REVIEW_GATE_JOB!r} job grew a job-level `if:` ({job.get('if')!r}). Gate the STEPS "
        "instead, which is what this workflow already does -- a skipped job reports nothing at all."
    )
    risks = _absence_risks(_triggers_of(_REVIEW_GATE))
    assert not risks, f"{_REVIEW_GATE} can leave a required context absent:\n  " + "\n  ".join(
        risks
    )


#: A line that INVOKES gh with `--add-label`, as distinct from one that PRINTS the phrase.
#:
#: That distinction is the whole detector, and the obvious spelling got it wrong first: a plain
#: `"--add-label" in body` fires on the gate's own error text, which tells a reviewer to run
#: `gh pr edit <N> --add-label reviewed`. A detector counting itself, and the "fix" it invites is
#: deleting the one line that tells an author how to clear the check. The identical trap is recorded
#: one module over, in tests/test_security_posture.py's `_gating_text`.
_GH_ADD_LABEL = re.compile(r"(?m)^\s*(?:[A-Za-z_]\w*=\S*\s+)*gh\b[^\n]*--add-label")


def _adds_its_own_label(body: str) -> list[str]:
    return [m.group(0).strip() for m in _GH_ADD_LABEL.finditer(body)]


def test_nothing_in_the_review_gate_adds_the_label_it_checks_for() -> None:
    """A gate that can satisfy itself is not a gate.

    The whole protocol is a human running `gh pr edit <N> --add-label reviewed`; the workflow's only
    write is the REMOVAL on `synchronize`, which moves toward blocked. One real `--add-label reviewed`
    call anywhere in this file -- added in good faith to "re-arm" the gate after a failed run -- would
    turn the required context into a formality that reports success on work nobody has read.

    THE ASYMMETRY IS INSIDE THE DETECTOR here, so it is asserted in the same call: a planted
    invocation must be caught, and the gate's printed INSTRUCTION carrying the same flag must not be.
    """
    body = "\n".join(
        str(step.get("run", "")) for step in jobs_of(_REVIEW_GATE)[_REVIEW_GATE_JOB]["steps"]
    )
    assert "--remove-label reviewed" in body, (
        "the review gate no longer removes the label on a new commit, so a pull request stays marked "
        "read across commits nobody has read"
    )
    assert _adds_its_own_label('gh pr edit "$NUMBER" --add-label reviewed'), (
        "the detector cannot see a real `gh ... --add-label` invocation"
    )
    assert (
        _adds_its_own_label(
            'echo "::error::Not yet read. When you have: gh pr edit <N> --add-label reviewed"'
        )
        == []
    ), "the detector flagged the gate's own instruction text rather than a call"
    found = _adds_its_own_label(body)
    assert not found, (
        f"{_REVIEW_GATE} writes the label it gates on, so the gate satisfies itself: {found}"
    )


def test_the_review_gate_lets_a_merge_queue_entry_through() -> None:
    """THE ASYMMETRY ON THE OTHER AXIS, and the one whose failure would be total.

    A merge_group event carries no pull request and therefore no labels. A gate that read them there
    would refuse every queue entry, and a required context that can never go green in the queue means
    NOTHING MERGES -- measured on this repository's first queue entry, recorded in codeql.yml's
    header. So the label-reading step has to stay confined to pull_request events.
    """
    steps = jobs_of(_REVIEW_GATE)[_REVIEW_GATE_JOB]["steps"]
    reading = [s for s in steps if _LABEL_STEP in str(s.get("name", ""))]
    assert len(reading) == 1
    expr = str(reading[0].get("if", ""))
    assert "github.event_name == 'pull_request'" in expr, (
        f"the label-reading step's `if:` is {expr!r}. It must stay confined to pull_request events: "
        "on a queue entry there are no labels to read and it would refuse every merge."
    )
    queue = [s for s in steps if "merge_group" in str(s.get("if", ""))]
    assert queue, (
        "no step handles the merge_group event, so a queue entry would run a job with every step "
        "skipped. Keep the explicit no-op -- it is what records the decision."
    )


# ---------------------------------------------------------------------------------------------------
# THE LABEL HAS TO RE-RUN THE JOB. A SURVIVING MUTATION, 2026-08-31.
# ---------------------------------------------------------------------------------------------------
#
# Dropping `labeled` from review-gate.yml's `types:` list reddened NOTHING: 65 tests passed with it
# removed. The absence detector above reads `pull_request`, `merge_group` and `paths` and never looks
# at `types`, so it cannot see the one edit that makes this gate unclearable.
#
# WHAT THAT EDIT DOES. The context reports on `opened`, goes red, and a reviewer runs
# `gh pr edit <N> --add-label reviewed`. With `labeled` absent that emits no run at all, so the red
# check-run from `opened` stands with the label already applied and nothing a reviewer can do about
# it. The only remaining trigger that re-runs the job is `synchronize` -- whose first step REMOVES the
# label and whose second exits 1. The pull request is then permanently unmergeable, and `strict = true`
# means it cannot even be brought up to date past the block.
#
# IT IS THE QUIET SHAPE OF THE SAME FAILURE THE SECTION ABOVE GUARDS: nothing turns red on the edit,
# and the wedge only surfaces on the next pull request somebody tries to clear.
#
# RE-RUN WITH THESE CONTROLS IN PLACE, same mutation, 2026-08-31: EXACTLY ONE test red by name --
# test_the_review_gate_reruns_when_a_reviewer_adds_the_label -- and 62 passed. One and not two is the
# point: the detector's own control below feeds LITERAL trigger lists rather than subtracting from the
# shipped file, so it does not move with the workflow it judges.


#: `pull_request` actions this gate cannot function without, and what each absence costs. Both
#: DIRECTIONS matter and they fail oppositely -- one wedges, one fails open -- so they are named
#: separately rather than counted.
_REQUIRED_PR_TYPES = {
    "labeled": (
        "adding the label emits no run, so the red check-run from an earlier event stands with the "
        "label already applied. Only `synchronize` re-runs the job, and that arm REMOVES the label -- "
        "so the pull request becomes permanently unmergeable and no edit turns anything red"
    ),
    "unlabeled": (
        "removing the label emits no run, so a pull request whose label was withdrawn keeps a GREEN "
        "context. The gate fails OPEN on the one edit that takes a review back"
    ),
    "synchronize": (
        "a new commit emits no run, so the removal step never executes and commits nobody has read "
        "stay marked read"
    ),
}

#: GitHub's default when a `pull_request:` block declares no `types:` at all. It carries no label
#: action, so an OMITTED list is the same defect as a list with `labeled` deleted -- and the likelier
#: accident, because removing the whole line reads as tidying rather than as disarming a gate.
_DEFAULT_PR_TYPES = ("opened", "synchronize", "reopened")


def _label_rerun_risks(triggers: dict[str, Any]) -> list[str]:
    """Ways this trigger set stops the LABEL from re-running a label-driven gate.

    A missing `pull_request:` key is not reported here: `_absence_risks` owns that, and two detectors
    naming one defect makes the second look like a second defect.
    """
    if "pull_request" not in triggers:
        return []
    block = triggers["pull_request"]
    declared = block.get("types") if isinstance(block, dict) else None
    types = [str(t) for t in declared] if declared else list(_DEFAULT_PR_TYPES)
    return [
        f"`pull_request.types` omits `{action}`: {why}"
        for action, why in _REQUIRED_PR_TYPES.items()
        if action not in types
    ]


def test_the_review_gate_reruns_when_a_reviewer_adds_the_label() -> None:
    """PLANTED BY THE PROTOCOL ITSELF: the only way to clear this check is to add a label.

    So the label has to dispatch the workflow. `.github/required-contexts.txt` states the consequence
    in the reader's own terms -- a stranded pull request needs the LABEL, not a rebase, because a
    rebase arrives as `synchronize` and strips it. That sentence is only true while `labeled` is in
    the trigger list, and nothing checked that it was.
    """
    types = _triggers_of(_REVIEW_GATE)["pull_request"]["types"]
    print(f"[#1000] {_REVIEW_GATE} pull_request types: {types}")
    risks = _label_rerun_risks(_triggers_of(_REVIEW_GATE))
    assert not risks, (
        f"{_REVIEW_GATE} cannot be cleared by the action that is supposed to clear it:\n  "
        + "\n  ".join(risks)
    )


def test_the_label_rerun_detector_fires_on_a_types_list_that_ignores_the_label() -> None:
    """NEGATIVE CONTROL OF THE DETECTOR, and the asymmetry.

    "The shipped list is complete" and "the detector reads nothing" are the same green. Each omission
    must be named on its own, an OMITTED `types:` must be treated as the default list rather than as
    permission, and a list carrying EXTRA actions must stay clean -- widening when a gate re-runs is
    legitimate, and a detector demanding exact equality would be "fixed" by deleting an action.

    THE SYNTHETIC LISTS ARE LITERALS, not derived from review-gate.yml. A control built by subtracting
    from the shipped list moves with the file it is meant to judge: mutate the workflow and this test
    fails for its own reasons, which buries the ONE test that should be naming the mutation under a
    second red that is only bookkeeping.
    """
    complete = ["opened", "reopened", "ready_for_review", "synchronize", "labeled", "unlabeled"]
    assert set(_REQUIRED_PR_TYPES) <= set(complete), (
        "this control's literal no longer contains every action the detector requires, so the "
        "subtractions below would test a list that is already failing"
    )
    for dropped in _REQUIRED_PR_TYPES:
        narrowed = [t for t in complete if t != dropped]
        risks = _label_rerun_risks({"pull_request": {"types": narrowed}, "merge_group": None})
        assert [r for r in risks if f"`{dropped}`" in r], (
            f"the detector cannot see `{dropped}` removed from a pull_request types list"
        )
    bare = _label_rerun_risks({"pull_request": None, "merge_group": None})
    assert any("`labeled`" in r for r in bare), (
        "a `pull_request:` block with no `types:` defaults to opened/synchronize/reopened, which "
        "carries no label action. The detector read the omission as permission."
    )
    widened = _label_rerun_risks(
        {"pull_request": {"types": [*complete, "edited", "assigned"]}, "merge_group": None}
    )
    assert widened == [], "the detector flagged a types list that only ADDS actions"
    assert _label_rerun_risks({"push": {"branches": ["main"]}}) == [], (
        "the detector claimed a label risk for a workflow with no pull_request trigger at all; "
        "_absence_risks owns that, and two names for one defect read as two defects"
    )
