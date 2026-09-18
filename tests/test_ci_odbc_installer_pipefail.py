# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The ODBC installer steps must guard their pipes, so a failed fetch fails THERE (BACKLOG #1544).

THE DEFECT IS A MISLEADING DIAGNOSTIC, NOT A SILENT PASS. Each of the three steps below opens with

    curl -fsSL --max-time 60 https://packages.microsoft.com/... | sudo tee <file> > /dev/null

and a pipeline reports only its LAST command's status. ``sudo tee`` succeeds at writing whatever it
was handed, including nothing, so a curl that 404s or times out leaves an EMPTY apt source and the
pipeline returns 0. Nothing stops. The retry loop underneath then fails three times against a
repository list that was never written, and the step signs off with

    ::error::apt-get failed 3 times. This is the UBUNTU RUNNER MIRROR, not the change under test.

which points a reader at Ubuntu's mirrors when the fault was the Microsoft fetch two lines up. The
run still goes red, so nothing merges untested; the cost is the time a reader spends on the wrong
suspect, plus the standing temptation to wave a mirror failure through.

``set -o pipefail`` makes the pipeline carry curl's status, and Actions already runs these bodies
under ``bash -e``, so the step would die at the fetch with curl's own message.

**WHY PIPEFAIL IS SAFE HERE AND NOT EVERYWHERE.** pipefail is not a blanket improvement: it also
surfaces a SIGPIPE from a consumer that exits before draining its input, which turns a deliberate
early exit into a failure. ``sudo tee`` reads stdin to EOF and never exits early, so these three
pipelines have no such consumer. ``ci.yml``'s ``changes`` job does, and it is pinned OFF for that
reason by ``test_changes_job_stays_off_pipefail_on_purpose`` below.

**AND WHY NOT A DECLARED SHELL.** Naming ``shell: bash`` is the blunt way to acquire pipefail, and
BACKLOG #1481 settled against it: a job-level bash default on a matrix job silently changes the
interpreter on the Windows leg for every step that did not name one. One test below pins that the
fix did not take that route.

**Falsification.** Both installer arms were run against the unmodified workflows before the fix and
observed RED, naming all three sites. The negative control below keeps that evidence live: it drives
the same predicate over synthetic bodies, so a green run is evidence the checker can still tell the
two cases apart rather than evidence it merely looked.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import pytest

yaml = pytest.importorskip("yaml")

_ROOT = Path(__file__).resolve().parents[1]
_CI = _ROOT / ".github" / "workflows" / "ci.yml"
_BENCH = _ROOT / ".github" / "workflows" / "benchmark.yml"

_PIPEFAIL = "set -o pipefail"

#: A pipe, not a logical or. Lookaround both sides so the ``changes`` job's alternation is not
#: counted as a pipeline. Deliberately naive about quoting: none of the bodies this module reads
#: holds a pipe character inside a string, and a shell-accurate tokenizer here would be a second
#: parser to keep honest. If one ever does, the assertions below fail LOUD rather than quiet -- a
#: spurious pipe makes a guarded step look unguarded, never the other way round.
_PIPE = re.compile(r"(?<!\|)\|(?!\|)")

#: The three guarded sites, NAMED rather than discovered by pattern. A step that is renamed or
#: deleted then fails this module instead of shrinking its scan in silence: an empty scan and a
#: clean scan must not look alike.
#:
#: The first two gate a merge. The third is off the merge path entirely -- ``benchmark.yml`` runs on
#: its own schedule -- and is held to the same rule because it is the SAME BODY, byte for byte.
#: A reader debugging a benchmark run is owed the same honest message.
_GUARDED: tuple[tuple[Path, str, str], ...] = (
    (_CI, "sqlserver-store", "Install Microsoft ODBC Driver 18 + sqlcmd"),
    (_CI, "load-test-sqlserver", "Install Microsoft ODBC Driver 18 + sqlcmd"),
    (_BENCH, "baseline-sqlserver", "Install Microsoft ODBC Driver 18 + sqlcmd"),
)


def _job(workflow: Path, job_id: str) -> dict[str, Any]:
    doc = yaml.safe_load(workflow.read_text(encoding="utf-8"))
    jobs = doc.get("jobs") or {}
    job = jobs.get(job_id)
    assert isinstance(job, dict), f"{workflow.name}: no job {job_id!r} (jobs: {sorted(jobs)})"
    return job


def _step(workflow: Path, job_id: str, step_name: str) -> dict[str, Any]:
    job = _job(workflow, job_id)
    named = [s for s in job.get("steps") or [] if isinstance(s, dict) and s.get("name")]
    for step in named:
        if step["name"] == step_name:
            return step
    raise AssertionError(
        f"{workflow.name}:{job_id}: no step named {step_name!r} "
        f"(steps: {[s['name'] for s in named]})"
    )


def _effective_lines(script: str) -> list[str]:
    """The body's executable lines: blanks and whole-line comments dropped."""
    lines = (line.strip() for line in script.splitlines())
    return [line for line in lines if line and not line.startswith("#")]


def _guards_its_pipes(script: str) -> bool:
    """True when ``set -o pipefail`` is already in force when the body's first pipe runs.

    Position matters, not mere presence: pipefail written after the fetch guards nothing the fetch
    did. So this walks the body in order and answers on whichever comes first.
    """
    for line in _effective_lines(script):
        if line == _PIPEFAIL:
            return True
        if _PIPE.search(line):
            return False
    return False


def _declared_shells(workflow: Path, job_id: str, step: dict[str, Any]) -> list[str]:
    """Every place a shell is named for this step: the step, its job, and the workflow."""
    doc = yaml.safe_load(workflow.read_text(encoding="utf-8"))
    found: list[str] = []
    if "shell" in step:
        found.append(f"step {step.get('name')!r}")
    for label, scope in (("job", _job(workflow, job_id)), ("workflow", doc)):
        if ((scope.get("defaults") or {}).get("run") or {}).get("shell"):
            found.append(f"{label} defaults.run.shell")
    return found


@pytest.mark.parametrize(("workflow", "job_id", "step_name"), _GUARDED)
def test_each_installer_step_still_pipes(workflow: Path, job_id: str, step_name: str) -> None:
    """The premise: these bodies pipe. Without it the guard below could pass on an empty scan."""
    script = _step(workflow, job_id, step_name)["run"]
    piping = [line for line in _effective_lines(script) if _PIPE.search(line)]
    assert piping, (
        f"{workflow.name}:{job_id}:{step_name!r} no longer pipes, so the pipefail guard beside it "
        "is asserting nothing. Re-read the step and either drop this module or re-aim it."
    )


@pytest.mark.parametrize(("workflow", "job_id", "step_name"), _GUARDED)
def test_each_installer_step_guards_its_pipes(workflow: Path, job_id: str, step_name: str) -> None:
    """A failed fetch must fail the step, not write an empty apt source and blame the mirror."""
    script = _step(workflow, job_id, step_name)["run"]
    assert _guards_its_pipes(script), (
        f"{workflow.name}:{job_id}:{step_name!r} runs a pipe with no {_PIPEFAIL!r} in force. A "
        "failed curl would write an empty apt source, return 0, and the retry loop underneath "
        "would then report the Ubuntu mirror as the cause. Put the line at the top of the body."
    )


@pytest.mark.parametrize(("workflow", "job_id", "step_name"), _GUARDED)
def test_no_installer_step_acquires_pipefail_by_switching_shells(
    workflow: Path, job_id: str, step_name: str
) -> None:
    """BACKLOG #1481: a declared shell is the blunt fix, and it reaches the Windows legs."""
    step = _step(workflow, job_id, step_name)
    declared = _declared_shells(workflow, job_id, step)
    assert not declared, (
        f"{workflow.name}:{job_id}:{step_name!r} takes a declared shell from {declared}. pipefail "
        "belongs in the run body; a shell default on a matrix job changes the interpreter on the "
        "Windows leg for every step that did not name one (BACKLOG #1481)."
    )


def test_changes_job_stays_off_pipefail_on_purpose() -> None:
    """``ci.yml``'s ``changes`` job must NOT take pipefail, because that would be a worse defect.

    Its conditions are of the form ``if echo "$changed" | grep -qE ...``. ``grep -q`` exits on its
    first match without draining stdin, so a large enough set of changed paths -- past the
    65,536-byte pipe buffer -- leaves ``echo`` killed by SIGPIPE. Under pipefail the pipeline then
    reports failure, the ``if`` takes its false arm, and ``serverdb=false`` is written for a change
    that DOES touch the store. The SQL Server leg skips, the rolled-up gate goes green over
    untested store changes, and nothing anywhere says so. That is a silent wrong answer, strictly
    worse than the loud misleading message the three installer steps were fixed for.

    Pinned here because a later sweep reading "these piped steps run without pipefail" as a to-do
    list would add it, and no other check in the tree would object.
    """
    job = _job(_CI, "changes")
    for step in job.get("steps") or []:
        if not isinstance(step, dict) or "run" not in step:
            continue
        assert "pipefail" not in step["run"], (
            "ci.yml:changes acquired pipefail. Its grep conditions exit early, so pipefail turns a "
            "SIGPIPE into a false condition and silently writes serverdb=false over a real store "
            "change. Revert it; the docstring above carries the mechanism."
        )
    assert not ((job.get("defaults") or {}).get("run") or {}).get("shell"), (
        "ci.yml:changes declared a job-level shell, which is the other way pipefail arrives."
    )


def test_the_checker_can_see_a_missing_pipefail() -> None:
    """Negative control. A guard is evidence only once it is shown to fail on the bad case."""
    unguarded = """
curl -fsSL https://example.invalid/key | sudo tee /etc/apt/x > /dev/null
apt-get update
"""
    guarded = _PIPEFAIL + unguarded
    too_late = unguarded + _PIPEFAIL
    commented = "# " + _PIPEFAIL + unguarded

    assert not _guards_its_pipes(unguarded), "the checker passed a body with no pipefail at all"
    assert _guards_its_pipes(guarded), "the checker failed a correctly guarded body"
    assert not _guards_its_pipes(too_late), "pipefail AFTER the pipe guards nothing; it was taken"
    assert not _guards_its_pipes(commented), "a commented-out pipefail was read as in force"
    assert not _PIPE.search("a || b"), "a logical or was counted as a pipe"
    assert _PIPE.search("a | b"), "a real pipe was not counted"
