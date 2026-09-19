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

**PIPEFAIL ALSO MAKES THE TWO FETCHES TERMINAL**, where before they failed onward into a retry loop
that could never fix them. That is the point, not a cost: the loop below wraps the apt pair, and
re-running apt against a repository list that was never written could never have worked.

**AND THE OBVIOUS SOFTENER IS WRONG HERE -- no ``--retry`` on these two curls.** curl cannot rewind
stdout, so it truncates on retry only when it owns the output file. Piped into ``tee``, a retry
after a PARTIAL transfer writes the fragment and then the retried body, leaving a corrupt key while
curl exits 0 -- which pipefail cannot see, because the status is clean. ``--retry`` belongs with a
``-o <file>`` fetch. This was added and reverted during review rather than merely considered.

**Falsification.** Both installer arms were run against the unmodified workflows before the fix and
observed RED, naming all three sites. The negative controls below keep that evidence live: they
drive the same predicates over synthetic bodies, so a green run is evidence the checker can still
tell the guarded, unguarded, disabled-again and pipe-free cases apart rather than evidence it
merely looked.
"""

from __future__ import annotations

import functools
import re
from typing import Any

import pytest

from tests._workflow_contexts import load_workflow

_PIPEFAIL = "set -o pipefail"

_CI = "ci.yml"
_BENCH = "benchmark.yml"

#: A pipe, not a logical or. Lookaround both sides so the ``changes`` job's alternation is not
#: counted as a pipeline. Deliberately naive about quoting: none of the bodies this module reads
#: holds a pipe character inside a string, and a shell-accurate tokenizer here would be a second
#: parser to keep honest.
#:
#: IT IS NAIVE IN BOTH DIRECTIONS, and the premise test is the side that can go quiet. A spurious
#: pipe -- one inside a quoted string or a trailing comment -- makes a GUARDED step look unguarded,
#: which is loud and wrong in the safe direction. But it also makes a step that NO LONGER PIPES look
#: like it still does, and that is exactly the empty-scan case ``test_each_installer_step_still_pipes``
#: exists to catch. If a body ever grows a quoted pipe, re-aim this regex rather than trusting either
#: test to notice.
_PIPE = re.compile(r"(?<!\|)\|(?!\|)")

#: The three guarded sites, NAMED rather than discovered by pattern. A step that is renamed or
#: deleted then fails this module instead of shrinking its scan in silence: an empty scan and a
#: clean scan must not look alike.
#:
#: The first two gate a merge. The third is off the merge path entirely -- ``benchmark.yml`` runs on
#: its own schedule -- and is held to the same rule because it is the SAME BODY, byte for byte.
#: A reader debugging a benchmark run is owed the same honest message.
_GUARDED: tuple[tuple[str, str, str], ...] = (
    (_CI, "sqlserver-store", "Install Microsoft ODBC Driver 18 + sqlcmd"),
    (_CI, "load-test-sqlserver", "Install Microsoft ODBC Driver 18 + sqlcmd"),
    (_BENCH, "baseline-sqlserver", "Install Microsoft ODBC Driver 18 + sqlcmd"),
)


@functools.cache
def _workflow(name: str) -> dict[str, Any]:
    """``load_workflow`` memoised for the life of the session.

    Reuse keeps ONE workflow parser in the tree (``tests/_workflow_contexts.py``), which is the
    point; the cache is what makes asking it repeatedly cheap. ``load_workflow`` re-reads and
    re-parses on every call, this module asks about a dozen times across its tests, and ci.yml is
    roughly 225 KB -- about a second of pure parsing in the ``tooling`` tier without this.
    """
    return load_workflow(name)


def _job(workflow: str, job_id: str) -> dict[str, Any]:
    jobs = _workflow(workflow).get("jobs") or {}
    job = jobs.get(job_id)
    assert isinstance(job, dict), f"{workflow}: no job {job_id!r} (jobs: {sorted(jobs)})"
    return job


def _step(workflow: str, job_id: str, step_name: str) -> dict[str, Any]:
    """The one step with this name.

    Collects EVERY match and insists on exactly one. Returning the first would leave a second copy
    of a duplicated step name unscanned while the module still reported green -- the same
    empty-scan-looks-like-a-clean-scan failure ``_GUARDED`` is named to avoid.
    """
    job = _job(workflow, job_id)
    named = [s for s in job.get("steps") or [] if isinstance(s, dict) and s.get("name")]
    matches = [s for s in named if s["name"] == step_name]
    if not matches:
        raise AssertionError(
            f"{workflow}:{job_id}: no step named {step_name!r} "
            f"(steps: {[s['name'] for s in named]})"
        )
    assert len(matches) == 1, (
        f"{workflow}:{job_id}: {len(matches)} steps share the name {step_name!r}, so checking "
        "'the' step would leave the others unscanned. Give them distinct names, or widen this "
        "module to assert the property over every match."
    )
    return matches[0]


def _run_body(workflow: str, job_id: str, step_name: str) -> str:
    """This step's shell body.

    Named rather than indexed so a step that STOPS having one -- replaced by a ``uses:`` composite
    action keeping its name, say -- gets this module's own sentence instead of a bare
    ``KeyError: 'run'`` traceback from inside a list comprehension.
    """
    step = _step(workflow, job_id, step_name)
    script = step.get("run")
    assert isinstance(script, str), (
        f"{workflow}:{job_id}:{step_name!r} has no `run:` body (keys: {sorted(step)}), so there is "
        "no shell for this module to read. If the installer moved into a composite action, the "
        "pipefail guard has to move with it -- re-aim this module or drop it."
    )
    return script


#: A comment opens at a ``#`` that starts a token -- beginning of line, or after whitespace.
#: Splitting on a bare ``#`` would truncate a URL fragment or a regex character class instead.
_COMMENT = re.compile(r"(?:^|\s)#")


def _statements(script: str) -> list[str]:
    """The body's executable statements, in order, with comments and blanks dropped.

    Split on ``;`` as well as on newlines, because ``set -o pipefail; curl x | tee y`` is two
    statements on one line and their ORDER is the whole question: the ``set`` runs first, so that
    pipe IS guarded. Reading the line whole would answer on whichever predicate happened to be
    tried first.

    Trailing comments go for the mirror reason -- a ``#`` that merely MENTIONS a pipe must not make
    a body that no longer pipes look like it still does, which is the quiet direction ``_PIPE``
    warns about.

    Naive about quoting, like ``_PIPE``: a ``;`` or ``#`` inside a quoted string splits a statement
    bash would keep whole. That is harmless for these two questions, because splitting preserves
    both the PRESENCE and the relative ORDER of ``set`` tokens and pipe characters, which is all
    either predicate reads. Re-aim this if a body ever needs real tokenizing.
    """
    out: list[str] = []
    for raw in script.splitlines():
        code = _COMMENT.split(raw, maxsplit=1)[0]
        out.extend(part for chunk in code.split(";") if (part := chunk.strip()))
    return out


def _pipefail_effect(statement: str) -> int:
    """``1`` if this statement turns pipefail ON, ``-1`` if OFF, ``0`` if it does neither.

    Matching one exact spelling would be a checker that falsely accuses correct code: a body
    normalised to the strictly STRONGER ``set -euo pipefail`` would read as unguarded and the
    failure message would tell its author to add the line already sitting at the top of the body.
    The likely repair is to weaken the workflow back to the one spelling the test accepts.

    So this walks tokens. Bash lets the option ride in a bundle -- in ``set -euo pipefail`` the
    ``o`` is the last letter of ``-euo`` and ``pipefail`` is its argument -- and only a bundle
    ENDING in ``o`` consumes the next token. ``set +o pipefail`` DISABLES pipefail, which is why
    the sign is reported rather than thrown away: a body that enables then disables it before its
    pipe is NOT guarded, and answering on presence alone would green exactly that.
    """
    tokens = statement.split()
    if not tokens or tokens[0] != "set":
        return 0
    for i, token in enumerate(tokens[1:], start=1):
        if len(token) < 2 or token[0] not in "-+" or token.startswith("--"):
            continue
        if token.endswith("o") and i + 1 < len(tokens) and tokens[i + 1] == "pipefail":
            return 1 if token[0] == "-" else -1
    return 0


def _enables_pipefail(statement: str) -> bool:
    """True when this statement turns pipefail on."""
    return _pipefail_effect(statement) > 0


def _guards_its_pipes(script: str) -> bool:
    """True when pipefail is in force by the time the body's first pipe runs.

    Position matters, not mere presence: pipefail written after the fetch guards nothing the fetch
    did, and pipefail turned back OFF before the fetch guards nothing either. So this tracks the
    flag as it walks and answers at the first pipe it reaches.

    A body with NO pipe at all is VACUOUSLY guarded. Answering False there would fail the guard test
    with a message asserting a pipe the body does not contain -- a true failure with a false reason,
    which sends the reader after the wrong thing. ``test_each_installer_step_still_pipes`` owns that
    case and says the useful sentence.
    """
    in_force = False
    for statement in _statements(script):
        effect = _pipefail_effect(statement)
        if effect:
            in_force = effect > 0
            continue
        if _PIPE.search(statement):
            return in_force
    return True


def _declared_shells(workflow: str, job_id: str, step: dict[str, Any]) -> list[str]:
    """Every place a shell is named for this step: the step, its job, and the workflow.

    All three scopes matter because Actions runs a declared ``bash`` as
    ``bash --noprofile --norc -eo pipefail {0}`` -- so naming the shell anywhere above a step is a
    complete way for pipefail to arrive without a line in the body.
    """
    found: list[str] = []
    if "shell" in step:
        found.append(f"step {step.get('name')!r}")
    scopes = (("job", _job(workflow, job_id)), ("workflow", _workflow(workflow)))
    for label, scope in scopes:
        if ((scope.get("defaults") or {}).get("run") or {}).get("shell"):
            found.append(f"{label} defaults.run.shell")
    return found


@pytest.mark.parametrize(("workflow", "job_id", "step_name"), _GUARDED)
def test_each_installer_step_still_pipes(workflow: str, job_id: str, step_name: str) -> None:
    """The premise: these bodies pipe. Without it the guard below could pass on an empty scan."""
    script = _run_body(workflow, job_id, step_name)
    piping = [s for s in _statements(script) if _PIPE.search(s)]
    assert piping, (
        f"{workflow}:{job_id}:{step_name!r} no longer pipes, so the pipefail guard beside it "
        "is asserting nothing. Re-read the step and either drop this module or re-aim it."
    )


@pytest.mark.parametrize(("workflow", "job_id", "step_name"), _GUARDED)
def test_each_installer_step_guards_its_pipes(workflow: str, job_id: str, step_name: str) -> None:
    """A failed fetch must fail the step, not write an empty apt source and blame the mirror."""
    script = _run_body(workflow, job_id, step_name)
    assert _guards_its_pipes(script), (
        f"{workflow}:{job_id}:{step_name!r} runs a pipe with no pipefail in force. A failed curl "
        "would write an empty apt source, return 0, and the retry loop underneath would then "
        f"report the Ubuntu mirror as the cause. Put {_PIPEFAIL!r} at the top of the body."
    )


@pytest.mark.parametrize(("workflow", "job_id", "step_name"), _GUARDED)
def test_no_installer_step_acquires_pipefail_by_switching_shells(
    workflow: str, job_id: str, step_name: str
) -> None:
    """The guard belongs in the run body, not in a declared shell.

    NOT because a declared shell would be wrong here. All three of these jobs are ``ubuntu-latest``
    with no Windows leg to surprise, and ci.yml deliberately sets ``defaults.run.shell: bash`` on
    other jobs (ci.yml:98, "available on all runners ... one set of commands"). Reading this pin as
    a general rule against that would be wrong.

    It is that a job-level default is the wrong BLAST RADIUS for a one-pipeline fix: it changes the
    interpreter for every step in the job that did not name one, and on a matrix job that reaches
    legs the fix was never reasoning about (BACKLOG #1481). The in-body line keeps the change the
    size of the defect and keeps each body self-describing.
    """
    step = _step(workflow, job_id, step_name)
    declared = _declared_shells(workflow, job_id, step)
    assert not declared, (
        f"{workflow}:{job_id}:{step_name!r} takes a declared shell from {declared}. pipefail "
        "belongs in the run body; a shell default carries it to every step in the job that did "
        "not name one, which is a wider change than this defect (BACKLOG #1481)."
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
    list would add it, and no other check in the tree would object for THIS job.

    Both routes in are checked. The body is scanned for an EXECUTABLE ``set``, not for the word
    ``pipefail`` anywhere in the text -- a substring ban would forbid the one thing this docstring
    is asking a future author to write, which is a comment beside those greps explaining why the
    line is deliberately absent.
    """
    for step in _job(_CI, "changes").get("steps") or []:
        if not isinstance(step, dict) or "run" not in step:
            continue
        enabling = [s for s in _statements(step["run"]) if _enables_pipefail(s)]
        assert not enabling, (
            f"ci.yml:changes acquired pipefail ({enabling}). Its grep conditions exit early, so "
            "pipefail turns a SIGPIPE into a false condition and silently writes serverdb=false "
            "over a real store change. Revert it; the docstring above carries the mechanism."
        )
        declared = _declared_shells(_CI, "changes", step)
        assert not declared, (
            f"ci.yml:changes takes a declared shell from {declared}, which is the other way "
            "pipefail arrives: Actions runs a declared bash with -eo pipefail. The docstring "
            "above carries why that is a silent wrong answer for this job."
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
    assert _guards_its_pipes("curl -fsSL -o /etc/apt/x https://example.invalid/key"), (
        "a body with NO pipe was reported unguarded, which would fail the guard test with a "
        "message asserting a pipe that is not there"
    )
    assert not _PIPE.search("a || b"), "a logical or was counted as a pipe"
    assert _PIPE.search("a | b"), "a real pipe was not counted"


def test_the_checker_accepts_every_spelling_that_enables_pipefail() -> None:
    """A checker that rejects the STRONGER spelling would push its author to weaken the workflow."""
    for stmt in ("set -o pipefail", "set -eo pipefail", "set -euo pipefail", "set -o pipefail -e"):
        assert _enables_pipefail(stmt), f"{stmt!r} enables pipefail and was read as not enabling it"
    for stmt in ("set -o errexit", "set -eu", "echo set -o pipefail", "set", ""):
        assert not _enables_pipefail(stmt), (
            f"{stmt!r} does not enable pipefail and was read as if it did"
        )
    assert _pipefail_effect("set +o pipefail") == -1, (
        "`set +o pipefail` DISABLES pipefail; reading it as a no-op lets an enable-then-disable "
        "body green on an unguarded pipe"
    )


def test_the_checker_reads_statements_rather_than_lines() -> None:
    """Separator and comment handling, which is where a one-spelling checker goes wrong quietly."""
    one_line = "set -o pipefail; curl x | sudo tee y"
    assert _guards_its_pipes(one_line), (
        "a one-line `set -o pipefail; cmd | cmd` was read as unguarded. The set runs FIRST, so "
        "that pipe is guarded, and failing it would tell the author to add a line already there."
    )
    assert _guards_its_pipes("set -o pipefail  # guard\ncurl x | sudo tee y"), (
        "a trailing comment after the guard defeated the match"
    )
    assert not _guards_its_pipes("set -o pipefail\nset +o pipefail\ncurl x | sudo tee y"), (
        "pipefail was turned back OFF before the pipe, so the body is NOT guarded"
    )

    mentions_a_pipe = "curl -fsSL -o /etc/apt/x https://example.invalid  # was: curl | tee"
    assert not [s for s in _statements(mentions_a_pipe) if _PIPE.search(s)], (
        "a pipe MENTIONED in a trailing comment was counted as a pipeline, which would let the "
        "premise test pass on a step that no longer pipes -- the quiet direction _PIPE warns of"
    )
    assert _statements("curl https://example.invalid/a#b") == [
        "curl https://example.invalid/a#b"
    ], "a `#` inside a URL was read as a comment and truncated the statement"
    assert _statements("a\n\n  # whole line comment\nb") == ["a", "b"], (
        "blank and whole-line-comment handling regressed"
    )
