# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A pipe with no ``pipefail`` discards its producer's exit code. This screen finds the new ones.

**The defect class.** A pipeline's exit status is the status of its LAST command. So
``curl -fsSL https://example/pkg.deb | sudo dpkg -i -`` reports whatever ``dpkg`` said about the
zero bytes it was handed, and a 404 from ``curl`` is discarded. Under ``set -e`` the step still
succeeds, the job goes green, and the thing it installed is not there. ``set -o pipefail`` makes the
pipeline report the first non-zero member instead.

**This is a SCREEN with a grandfathered baseline.** It records the unguarded pipelines already in
the tree and fails on a NEW one. It does not sweep the existing ones: that is separate work, per
site, because ``pipefail`` is not always the right answer -- see ``_ALLOWLIST_JOBS`` for a job where
turning it on would turn a real test skip into a silent false green. A screen that demanded the
whole sweep in one change would land as a blanket exemption instead, and a blanket exemption is a
control reporting success without exercising what it names.

**What the tokenizer resolves, stated as a limit rather than left implicit.** Earlier passes over
this corpus published four different counts because each searched for a bare ``|`` character. That
over-counts every alternation in a quoted ``grep -E`` program, every ``|`` in an ``awk`` script,
every ``jq`` filter, every PowerShell pipeline, and every ``case`` pattern. :func:`walk` runs a
state machine instead, and it DOES resolve:

* single quotes (nothing inside them is shell) and double quotes;
* backslash escapes, unquoted and inside double quotes alike;
* ``$( ... )`` and backtick substitution, INCLUDING inside double quotes -- a pipe in ``"$(a | b)"``
  is a real pipeline, and a quote-blind scanner gets that one backwards in both directions;
* here-documents (``<<WORD``, ``<<-WORD``, ``<<'WORD'``), whose body is data; ``<<<`` is a
  here-string and consumes no lines, so it is not mistaken for one;
* comments, including a ``#`` that is not one because it is mid-word (``foo#bar``);
* ``case`` pattern alternation -- ``uv|pip|npm)`` is three patterns, not two pipelines. Four
  workflows here contain ``case`` statements, so this is load-bearing rather than theoretical;
* ``||`` (an or-list) and ``|&`` (a pipe carrying stderr, so it IS one).

It does NOT resolve:

* ``[[ $x =~ a|b ]]`` regex alternation. Measured: ``=~`` does not occur anywhere in this corpus,
  so the gap is currently empty, and :func:`test_the_corpus_has_no_regex_match_operator` turns red
  the day it stops being empty -- which is when somebody has to decide, rather than inherit a
  silent miscount.
* ``|`` inside a ``${var//|/x}`` parameter expansion.
* whether a pipeline's producer CAN fail. ``echo x | tr a b`` is reported by this screen and needs
  no guard. The allowlist is where to say so, with a reason.

**Shell resolution runs at four levels**, because a step that is not bash cannot take
``set -o pipefail`` and flagging it would be a false accusation: step ``shell:``, then job
``defaults.run.shell``, then workflow ``defaults.run.shell``, then the runner default (pwsh on a
Windows runner, bash elsewhere). This layer is not cosmetic -- ``net-helper.yml`` is dense with
PowerShell pipelines, and a screen without it reports every one of them as a finding. A ``runs-on``
that is an unresolved ``${{ }}`` expression is AMBIGUOUS: it is counted and reported, never folded
into either answer.

**The needs walk is transitive, and that is why this is its own file.** Branch protection names
CONTEXTS, and a context resolves to one job. ``CI gate`` resolves to ``ci.yml`` job ``ci-gate``,
an ``if: always()`` roll-up that runs no pipeline of its own -- every leg it gates sits behind
``needs:``. A screen stopping at the resolved job would report a clean bill of health over exactly
the jobs the roll-up exists to aggregate. :func:`gating_jobs` walks ``needs:`` to a fixed point;
:func:`gating_jobs_without_needs_walk` is kept beside it so the difference is measured by
:func:`test_the_needs_walk_reaches_jobs_the_flat_resolution_cannot` rather than asserted from
memory.

**Scope note, measured rather than assumed.** This walks ``.github/workflows/*.yml`` only.
Composite actions under ``.github/actions/`` are not walked; the one that exists
(``cla-assistant-lite``) declares zero ``run:`` steps, so the gap is currently empty. It is left
unasserted because that directory is under active edit and a liveness claim about somebody else's
file is not this screen's to make.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest

from tests._workflow_contexts import WORKFLOWS as WORKFLOW_DIR
from tests._workflow_contexts import jobs_of, required_contexts, resolve

yaml = pytest.importorskip("yaml")

WORKFLOWS = sorted(WORKFLOW_DIR.glob("*.yml"))

#: ``${{ ... }}`` is substituted by Actions before the shell sees the script, so it is not shell and
#: must not be tokenized as shell. Non-greedy and DOTALL: a multi-line expression is still one token.
_GHA_EXPR = re.compile(r"\$\{\{.*?\}\}", re.DOTALL)

#: ``set -o pipefail``, ``set -eo pipefail``, ``set -euo pipefail``, ``set -e -o pipefail``.
_PIPEFAIL = re.compile(r"\bset\s+(?:-[A-Za-z]+\s+)*-[A-Za-z]*o\s+pipefail\b")

#: Shells that take ``set -o pipefail``. pwsh/powershell/cmd do not, and ``shell: python`` is not a
#: shell at all.
_POSIX_SHELLS = frozenset({"bash", "sh"})

#: Characters after which a word starts a COMMAND rather than continuing an argument list. Used so a
#: literal ``case`` in the middle of a line does not open a case statement. Conservative by design:
#: failing to open one costs a false POSITIVE, which a reader sees; opening one wrongly costs a
#: false negative, which nobody sees.
_COMMAND_POSITION = frozenset({"", "\n", ";", "&", "|", "(", ")"})

_WORD_CHARS = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-")

#: Liveness floors, not targets. A walk that collapses to nothing reports no findings and is
#: indistinguishable from a clean tree, which is the defect family this row belongs to. Set well
#: under the measured population so ordinary churn does not red them, and far enough over zero that
#: a broken walk cannot slip through.
MIN_WORKFLOWS = 18
MIN_STEPS = 150
MIN_POSIX_STEPS = 120
MIN_PIPED_STEPS = 20
MIN_GATING_JOBS = 10


@dataclass(frozen=True)
class Walk:
    """One pass over a script: where the real pipes are, and the script with its DATA blanked out."""

    pipes: tuple[int, ...]
    code: str


@dataclass(frozen=True)
class Step:
    """One ``run:`` step, located well enough that a human can find it from the failure text."""

    workflow: str
    job: str
    step: str
    shell: str | None
    ambiguous_runner: bool
    script: str

    @property
    def key(self) -> tuple[str, str, str]:
        return (self.workflow, self.job, self.step)

    @property
    def site(self) -> str:
        return f"{self.workflow} :: job {self.job} :: {self.step}"


@dataclass(frozen=True)
class Scan:
    """The whole census, so every number this file prints comes from one walk of the tree."""

    steps: tuple[Step, ...]
    posix: tuple[Step, ...]
    piped: tuple[Step, ...]
    unguarded: tuple[Step, ...]
    ambiguous: tuple[Step, ...]


# ---------------------------------------------------------------------------------------------
# The tokenizer -- ONE walk, so the pipe finder and the pipefail finder cannot disagree
# ---------------------------------------------------------------------------------------------


def _heredoc_delimiter(text: str, i: int) -> tuple[str, int] | None:
    """Read a here-document delimiter starting at ``<<``. Returns ``(word, index past it)``.

    ``<<`` may be followed by ``-`` and the word may be quoted. ``<<<`` is a HERE-STRING: it
    consumes no following lines, so it is rejected here rather than swallowing the rest of the
    script as data.
    """
    j = i + 2
    if j < len(text) and text[j] == "<":
        return None
    if j < len(text) and text[j] == "-":
        j += 1
    while j < len(text) and text[j] in " \t":
        j += 1
    quote = ""
    if j < len(text) and text[j] in "'\"":
        quote = text[j]
        j += 1
    start = j
    if quote:
        while j < len(text) and text[j] != quote:
            j += 1
        word = text[start:j]
        j += 1
    else:
        while j < len(text) and (text[j] in _WORD_CHARS or text[j] == "."):
            j += 1
        word = text[start:j]
    return (word, j) if word else None


def _heredoc_body_end(text: str, i: int, word: str) -> int:
    """From the newline at ``i``, the index just past the here-document body terminated by ``word``."""
    nl = text.find("\n", i)
    j = len(text) if nl == -1 else nl + 1
    while j < len(text):
        end = text.find("\n", j)
        line = text[j:] if end == -1 else text[j:end]
        if line.strip() == word:
            return len(text) if end == -1 else end + 1
        if end == -1:
            return len(text)
        j = end + 1
    return len(text)


def walk(script: str) -> Walk:
    """Tokenize ``script`` once: locate the real pipe operators and blank out everything that is DATA.

    "Data" means a comment, a here-document body, or the literal text of a quoted string. A nested
    ``$( ... )`` inside double quotes is NOT data -- it is shell, and the walk re-enters it as such.
    """
    text = _GHA_EXPR.sub("GHA_EXPR", script)
    n = len(text)
    kept = [True] * n
    pipes: list[int] = []

    # Parallel stacks, pushed and popped together. `quotes[-1]` is the current quoting context ("" is
    # unquoted shell); `cases[-1]` is the case-statement state stack for THAT frame, so a `case`
    # inside a command substitution cannot leak its pattern state out to the enclosing script.
    quotes: list[str] = [""]
    cases: list[list[str]] = [[]]
    pending: list[str] = []

    prev = ""  # last significant character of actual shell
    word = ""
    word_is_command = False

    def blank(lo: int, hi: int) -> None:
        for k in range(lo, hi):
            if text[k] != "\n":
                kept[k] = False

    def flush_word() -> None:
        nonlocal word
        if not word:
            return
        frame = cases[-1]
        if word == "case" and word_is_command:
            frame.append("header")
        elif frame and frame[-1] == "header" and word == "in":
            frame[-1] = "pattern"
        elif word == "esac" and frame:
            frame.pop()
        word = ""

    i = 0
    while i < n:
        ch = text[i]
        ctx = quotes[-1]

        if ctx == "'":
            kept[i] = kept[i] and ch == "\n"
            if ch == "'":
                quotes.pop()
                cases.pop()
            i += 1
            continue

        if ch == "\\" and i + 1 < n:
            i += 2
            continue

        if ctx == '"':
            if ch == '"':
                quotes.pop()
                cases.pop()
                i += 1
                continue
            if ch == "$" and i + 1 < n and text[i + 1] == "(":
                quotes.append("")
                cases.append([])
                i += 2
                continue
            if ch == "`":
                quotes.append("`")
                cases.append([])
                i += 1
                continue
            if ch != "\n":
                kept[i] = False
            i += 1
            continue

        if ctx == "`" and ch == "`":
            quotes.pop()
            cases.pop()
            i += 1
            continue

        # --- unquoted shell, or the body of a command substitution ---------------------------
        if ch in _WORD_CHARS:
            if not word:
                word_is_command = prev in _COMMAND_POSITION
            word += ch
            prev = ch
            i += 1
            continue
        flush_word()

        if ch == "'":
            quotes.append("'")
            cases.append([])
            kept[i] = False
            i += 1
            continue
        if ch == '"':
            quotes.append('"')
            cases.append([])
            i += 1
            continue
        if ch == "$" and i + 1 < n and text[i + 1] == "(":
            quotes.append("")
            cases.append([])
            i += 2
            continue
        if ch == "`":
            quotes.append("`")
            cases.append([])
            i += 1
            continue
        if ch == ")":
            frame = cases[-1]
            if frame and frame[-1] == "pattern":
                frame[-1] = "body"
            elif len(quotes) > 1:
                quotes.pop()
                cases.pop()
            prev = ch
            i += 1
            continue
        if ch == ";":
            frame = cases[-1]
            if i + 1 < n and text[i + 1] == ";" and frame and frame[-1] == "body":
                frame[-1] = "pattern"
                i += 2
                prev = ";"
                continue
            prev = ";"
            i += 1
            continue
        if ch == "#" and prev in _COMMAND_POSITION | {" ", "\t"}:
            end = text.find("\n", i)
            stop = n if end == -1 else end
            blank(i, stop)
            i = stop
            continue
        if ch == "<" and i + 1 < n and text[i + 1] == "<":
            got = _heredoc_delimiter(text, i)
            if got is not None:
                pending.append(got[0])
                i = got[1]
                prev = "w"
                continue
            i += 3  # a here-string
            prev = "w"
            continue
        if ch == "\n" and pending:
            start = i
            for delimiter in pending:
                i = _heredoc_body_end(text, i, delimiter)
            blank(start, i)
            pending = []
            prev = "\n"
            continue
        if ch == "|":
            if i + 1 < n and text[i + 1] == "|":
                i += 2
                prev = "|"
                continue
            frame = cases[-1]
            if not (frame and frame[-1] == "pattern"):
                pipes.append(i)
            i += 2 if (i + 1 < n and text[i + 1] == "&") else 1
            prev = "|"
            continue

        if ch not in " \t":
            prev = ch
        elif prev not in ("", "\n"):
            prev = " "
        i += 1

    flush_word()
    code = "".join(c if kept[k] else " " for k, c in enumerate(text))
    return Walk(tuple(pipes), code)


def unguarded_pipes(script: str) -> tuple[int, ...]:
    """Pipe operators in ``script`` that run with ``pipefail`` off.

    Position matters: ``set -o pipefail`` placed AFTER a pipeline does not protect it, and a script
    that pipes on line one and enables the option on line two has exactly the defect this screen is
    for. The option is looked for in the blanked script, so a ``pipefail`` inside an echoed message
    or a here-document cannot answer for the shell.
    """
    result = walk(script)
    if not result.pipes:
        return ()
    enabled = _PIPEFAIL.search(result.code)
    if enabled is None:
        return result.pipes
    return tuple(p for p in result.pipes if p < enabled.start())


def piped_lines(step: Step) -> list[str]:
    """The source lines carrying this step's unguarded pipes, for a failure a human can act on."""
    script = _GHA_EXPR.sub("GHA_EXPR", step.script)
    out: list[str] = []
    for offset in unguarded_pipes(step.script):
        start = script.rfind("\n", 0, offset) + 1
        end = script.find("\n", offset)
        line = (script[start:] if end == -1 else script[start:end]).strip()
        if line not in out:
            out.append(line)
    return out


# ---------------------------------------------------------------------------------------------
# Walking the workflows
# ---------------------------------------------------------------------------------------------


def _declared_shell(workflow: Any, job: Any, step: Any) -> str | None:
    """Levels one to three of shell resolution: step, then job defaults, then workflow defaults."""
    if isinstance(step, dict) and "shell" in step:
        return str(step["shell"]).split()[0]
    for scope in (job, workflow):
        got = (scope.get("defaults") or {}).get("run", {}).get("shell")
        if got:
            return str(got).split()[0]
    return None


def _runner_default(job: Any) -> tuple[str | None, bool]:
    """Level four: the runner's own default shell, and whether the runner label is knowable here.

    Returns ``(shell, ambiguous)``. ``runs-on: ${{ matrix.os }}`` is ambiguous -- the same step is
    bash on a Linux arm and pwsh on a Windows one -- and guessing either way would be the instrument
    inventing an answer the file does not contain.
    """
    runs_on = str(job.get("runs-on", ""))
    if "${{" in runs_on:
        return None, True
    if "windows" in runs_on.lower():
        return "pwsh", False
    return "bash", False


def _parse(path: Path) -> dict[str, Any]:
    parsed = yaml.safe_load(path.read_text(encoding="utf-8"))
    return parsed if isinstance(parsed, dict) else {}


def scan(paths: Sequence[Path] | None = None) -> Scan:
    """One walk of a workflow corpus, partitioned. Every count in this file comes from here.

    ``paths`` defaults to the real ``.github/workflows``. It is a parameter so the controls below
    can point the same walk at a planted corpus and at an EMPTY one -- a screen nobody has watched
    fail is a screen nobody has evidence for.
    """
    steps: list[Step] = []
    for path in WORKFLOWS if paths is None else paths:
        doc = _parse(path)
        jobs = {k: (v or {}) for k, v in (doc.get("jobs") or {}).items()}
        for job_id, job in jobs.items():
            if not isinstance(job, dict):
                continue
            for index, step in enumerate(job.get("steps") or []):
                if not isinstance(step, dict) or "run" not in step:
                    continue
                shell = _declared_shell(doc, job, step)
                ambiguous = False
                if shell is None:
                    shell, ambiguous = _runner_default(job)
                name = str(step.get("name") or f"step[{index}]")
                steps.append(Step(path.name, str(job_id), name, shell, ambiguous, str(step["run"])))
    posix = tuple(s for s in steps if s.shell in _POSIX_SHELLS)
    piped = tuple(s for s in posix if walk(s.script).pipes)
    return Scan(
        steps=tuple(steps),
        posix=posix,
        piped=piped,
        unguarded=tuple(s for s in piped if unguarded_pipes(s.script)),
        ambiguous=tuple(s for s in steps if s.ambiguous_runner),
    )


def _needs_of(job: Any) -> list[str]:
    needs = job.get("needs")
    if needs is None:
        return []
    if isinstance(needs, str):
        return [needs]
    return [str(n) for n in needs]


def gating_jobs_without_needs_walk() -> set[tuple[str, str]]:
    """Every required context resolved to its own job, and no further.

    This is the reach a context-to-job mapping gives on its own. Kept beside :func:`gating_jobs` so
    the difference between them is measured rather than remembered.
    """
    found: set[tuple[str, str]] = set()
    for context in required_contexts():
        where = resolve(context)
        if where is not None:
            found.add(where)
    return found


def gating_jobs() -> set[tuple[str, str]]:
    """Every job a merge waits on, following ``needs:`` to a fixed point.

    A roll-up like ``ci-gate`` executes nothing itself; the legs it aggregates are what run, and
    they are reachable only through ``needs``.
    """
    seen = gating_jobs_without_needs_walk()
    frontier = list(seen)
    while frontier:
        workflow, job_key = frontier.pop()
        jobs = jobs_of(workflow)
        job = jobs.get(job_key)
        if job is None:
            continue
        for need in _needs_of(job):
            nxt = (workflow, need)
            if need in jobs and nxt not in seen:
                seen.add(nxt)
                frontier.append(nxt)
    return seen


# ---------------------------------------------------------------------------------------------
# The allowlist, and the grandfathered baseline
# ---------------------------------------------------------------------------------------------

#: WHOLE JOBS where an unguarded pipeline is CORRECT and adding ``pipefail`` would be a regression.
#: Each entry carries its reason, because "allowed" without one is indistinguishable from
#: "unexamined", and an allowlist nobody can audit is how a screen quietly stops screening.
_ALLOWLIST_JOBS: dict[tuple[str, str], str] = {
    ("ci.yml", "changes"): (
        "PIPEFAIL WOULD BREAK THIS JOB, NOT FIX IT. Its path classification is a run of if/elif "
        'conditions shaped `echo "$changed" | grep -qE ...` -- at least eight piped greps across '
        "at least seven conditions, one joining two with `||` and the last using `grep -qvE`. "
        "`grep -q` exits the moment it matches, so its reader closes the pipe and the producing "
        "`echo` takes SIGPIPE once the payload passes the 65,536-byte pipe buffer. With pipefail "
        "on, that SIGPIPE becomes the pipeline's status and the condition silently flips: "
        "`serverdb=false` on a pull request that DID touch the store, `sqlserver-store` skips, and "
        "`CI gate` reports success over an untested store change. A false green on the job whose "
        "whole purpose is deciding which legs run is strictly worse than the defect being fixed."
    ),
}

#: SINGLE STEPS, where the job around them is ordinary and one step is deliberate.
_ALLOWLIST_STEPS: dict[tuple[str, str, str], str] = {
    (
        "release.yml",
        "release",
        "Leak gate — sdist MUST be package-only (private-doc/PHI publish guard)",
    ): (
        "DELIBERATELY NOT PIPEFAIL (BACKLOG #1313). The gate's pipeline shape is pinned by "
        "tests/test_release_pipeline.py::_run_leak_gate, which executes the extracted script. "
        "Changing it here would red that test and move a security control's semantics as a side "
        "effect of a lint sweep, which is the opposite of how a control should move."
    ),
}


def allowlist_reason(step: Step) -> str | None:
    job_reason = _ALLOWLIST_JOBS.get((step.workflow, step.job))
    return job_reason if job_reason is not None else _ALLOWLIST_STEPS.get(step.key)


#: The unguarded pipelines ALREADY IN THE TREE when this screen landed. They are GRANDFATHERED, not
#: blessed: the screen's job is to stop the population growing while each site is fixed on its own
#: merits. Removing a line is how a fix gets recorded; adding one needs a reason in the pull request
#: that adds it.
#:
#: OVERLAP WITH UNMERGED WORK, recorded because whoever lands second has to act on it. Three ODBC
#: installer steps below are already fixed on branch `b1544a-pipefail` (commit 73f0cb07e, unmerged
#: when this was written): ci.yml `sqlserver-store`, ci.yml `load-test-sqlserver`, and benchmark.yml
#: `baseline-sqlserver`. This branch is cut from `main` and does not contain that fix, so a baseline
#: omitting them would red this screen on `main`. When the two meet, the second to land drops those
#: three lines -- `test_the_baseline_is_not_stale` names them if it is forgotten.
_GRANDFATHERED: frozenset[tuple[str, str, str]] = frozenset(
    {
        ("benchmark.yml", "baseline-postgres", "Environment stamp"),
        ("benchmark.yml", "baseline-sqlite", "Environment stamp"),
        ("benchmark.yml", "baseline-sqlserver", "Environment stamp"),
        ("benchmark.yml", "baseline-sqlserver", "Install Microsoft ODBC Driver 18 + sqlcmd"),
        ("ci.yml", "docker-smoke", "Engine log (always)"),
        ("ci.yml", "load-test-sqlserver", "Install Microsoft ODBC Driver 18 + sqlcmd"),
        ("ci.yml", "sqlserver-store", "Install Microsoft ODBC Driver 18 + sqlcmd"),
        ("ci.yml", "test", "Doc guards (ungated — the docs-only blind spot; see above)"),
        (
            "dependabot-auto-merge.yml",
            "auto-merge",
            "Require the candidate release to have aged (security track)",
        ),
        (
            "dependabot-auto-merge.yml",
            "auto-merge",
            "Verify a published advisory backs the security track",
        ),
        ("freethread-smoke.yml", "freethread", "Smoke a pure test subset under 3.14t"),
        ("quality-advisory.yml", "clone", "Record gate liveness"),
        ("quality-advisory.yml", "complexity", "Install ruff (version derived from the lock)"),
        ("quality-advisory.yml", "complexity", "Record gate liveness"),
        (
            "quality-advisory.yml",
            "coverage",
            "Diff-coverage vs the PR base (advisory - never fails)",
        ),
        ("quality-advisory.yml", "coverage", "Record gate liveness"),
        (
            "quality-advisory.yml",
            "mutation",
            "Mutation-test a bounded scope (advisory - never fails)",
        ),
        (
            "release.yml",
            "release",
            "Score the SBOM quality (sbomqs — advisory, never blocks a release)",
        ),
        ("release.yml", "release", "Smoke-check the built wheel (clean venv → import + version)"),
        (
            "release.yml",
            "release-harness",
            "Smoke-check the harness wheel (version == engine == tag)",
        ),
        (
            "release.yml",
            "release-webconsole",
            "Smoke-check the console wheel (version == the console's OWN __version__ == tag)",
        ),
        ("security.yml", "sbom", "Score SBOM quality (sbomqs — advisory)"),
        ("security.yml", "trivy", "Install Trivy (pinned)"),
        ("zizmor.yml", "zizmor", "Lint workflow syntax (actionlint, pinned)"),
    }
)


def new_findings(result: Scan) -> list[Step]:
    """Unguarded pipelines that are neither allowlisted nor grandfathered. THE VERDICT.

    Everything else in this file exists to make this list trustworthy.
    """
    return [
        s for s in result.unguarded if allowlist_reason(s) is None and s.key not in _GRANDFATHERED
    ]


def liveness_receipt(result: Scan) -> str:
    """What the walk actually touched. Printed on every run, asserted by the liveness test."""
    # "workflows that produced a step" is deliberately NOT the file count: some workflow files run
    # only `uses:` steps, and reporting the glob size here would overstate what was inspected.
    return (
        f"pipefail screen walked {len(result.steps)} run: steps across "
        f"{len({s.workflow for s in result.steps})} workflow files that declare one; "
        f"{len(result.posix)} resolved to bash/sh, {len(result.piped)} contained a real pipeline, "
        f"{len(result.unguarded)} of those ran with pipefail off; "
        f"{len(result.ambiguous)} steps had an unresolvable runner label"
    )


def assert_liveness(result: Scan) -> None:
    """Fail if the walk collapsed. A screen that examines nothing reports nothing and looks clean.

    This is the assertion the control below points at an EMPTY corpus, because a floor nobody has
    watched fail is a floor nobody has evidence for.
    """
    shortfalls: list[str] = []
    if len({s.workflow for s in result.steps}) < MIN_WORKFLOWS:
        shortfalls.append(
            f"only {len({s.workflow for s in result.steps})} workflows produced a run: step "
            f"(floor {MIN_WORKFLOWS})"
        )
    if len(result.steps) < MIN_STEPS:
        shortfalls.append(f"only {len(result.steps)} run: steps walked (floor {MIN_STEPS})")
    if len(result.posix) < MIN_POSIX_STEPS:
        shortfalls.append(
            f"only {len(result.posix)} steps resolved to bash/sh (floor {MIN_POSIX_STEPS}) -- "
            "shell resolution is probably broken, which would exempt the whole corpus"
        )
    if len(result.piped) < MIN_PIPED_STEPS:
        shortfalls.append(
            f"only {len(result.piped)} steps contained a pipeline (floor {MIN_PIPED_STEPS}) -- "
            "the tokenizer is probably finding nothing, which would make every check below vacuous"
        )
    if shortfalls:
        raise AssertionError(
            "THE PIPEFAIL SCREEN'S WALK COLLAPSED. It found too little to have screened anything, "
            "so a green result here would mean 'looked nowhere', not 'found nothing':\n  "
            + "\n  ".join(shortfalls)
        )


# ---------------------------------------------------------------------------------------------
# Tokenizer controls -- the screen has to be shown SEEING before any count it prints is evidence
# ---------------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("script", "expected", "why"),
    [
        ("a | b", 1, "the plain case"),
        ("a || b", 0, "an or-list is not a pipe"),
        ("a |& b", 1, "|& pipes stdout AND stderr, so it is still a pipeline"),
        ("a | b | c", 2, "two pipes in one pipeline"),
        ("grep -E 'foo|bar' f", 0, "alternation inside single quotes is regex, not shell"),
        ('grep -E "foo|bar" f', 0, "alternation inside double quotes is still not shell"),
        ("jq -r '.[] | select(.x)' f", 0, "a jq filter is data, not a pipeline"),
        ("awk '{print $1 | \"sort\"}' f", 0, "an awk program is data"),
        ('x="$(a | b)"', 1, "a pipe inside $( ) inside double quotes IS a real pipeline"),
        ("x=`a | b`", 1, "backtick substitution is shell too"),
        ("a \\| b", 0, "an escaped pipe is a literal character"),
        ("a # b | c", 0, "a pipe in a comment is not a pipe"),
        ("foo#bar | baz", 1, "a mid-word # is not a comment, so this pipe is real"),
        ("case $x in\n  a|b) echo hi ;;\nesac", 0, "case alternation is not a pipeline"),
        ("case $x in\n  a|b) echo hi | tr a b ;;\nesac", 1, "but a pipe in the BODY is real"),
        (
            "case $x in\n  a|b) echo hi ;;\nesac\ncat f | wc -l",
            1,
            "and state does not leak past esac",
        ),
        ("cat <<'EOF'\na | b\nEOF\n", 0, "a here-document body is data"),
        ("cat <<EOF\na | b\nEOF\ncat f | wc -l\n", 1, "and the script resumes after it"),
        ('read -r x <<< "a | b"\n', 0, "<<< is a here-string, not a here-document"),
    ],
)
def test_the_tokenizer_separates_pipelines_from_look_alikes(
    script: str, expected: int, why: str
) -> None:
    """Every row is a control. The look-alikes are what made four earlier passes disagree."""
    got = len(walk(script).pipes)
    assert got == expected, f"{why}: expected {expected} pipe(s), got {got} in {script!r}"


@pytest.mark.parametrize(
    ("script", "unguarded", "why"),
    [
        ("a | b", 1, "no pipefail at all"),
        ("set -o pipefail\na | b", 0, "the plain form"),
        ("set -euo pipefail\na | b", 0, "bundled into a combined flag string"),
        ("set -e -o pipefail\na | b", 0, "as a separate flag"),
        ("a | b\nset -o pipefail\nc | d", 1, "position matters: the FIRST pipe is unprotected"),
        (
            "echo 'remember to set -o pipefail'\na | b",
            1,
            "a mention inside a quoted string does not enable the option",
        ),
        (
            "cat <<'EOF'\nset -o pipefail\nEOF\na | b",
            1,
            "and neither does one inside a here-document",
        ),
        ("# set -o pipefail\na | b", 1, "nor a commented-out one"),
    ],
)
def test_the_pipefail_detector_reads_the_shell_and_not_the_prose(
    script: str, unguarded: int, why: str
) -> None:
    assert len(unguarded_pipes(script)) == unguarded, why


def _plant(tmp_path: Path, name: str, body: str) -> Path:
    path = tmp_path / name
    path.write_text(body, encoding="utf-8")
    return path


def test_a_planted_unguarded_pipe_turns_the_screen_red(tmp_path: Path) -> None:
    """PROOF THE SCREEN CAN SEE. A guarded twin of the same step proves it is not just always red.

    This runs the real verdict function, :func:`new_findings`, not a private helper -- a control
    that exercises something other than the gate proves something other than the gate.
    """
    unguarded = _plant(
        tmp_path,
        "planted-bad.yml",
        "name: planted\non: [push]\njobs:\n"
        "  planted:\n    runs-on: ubuntu-latest\n    steps:\n"
        "      - name: Install a thing\n"
        "        run: |\n"
        "          set -eu\n"
        "          curl -fsSL https://example.invalid/key | sudo tee /etc/key > /dev/null\n",
    )
    guarded = _plant(
        tmp_path,
        "planted-good.yml",
        "name: planted\non: [push]\njobs:\n"
        "  planted:\n    runs-on: ubuntu-latest\n    steps:\n"
        "      - name: Install a thing\n"
        "        run: |\n"
        "          set -euo pipefail\n"
        "          curl -fsSL https://example.invalid/key | sudo tee /etc/key > /dev/null\n",
    )

    red = new_findings(scan([unguarded]))
    assert [s.step for s in red] == ["Install a thing"], (
        "the screen did NOT see a planted unguarded pipeline; every count it reports elsewhere is "
        f"therefore unevidenced. Findings: {[s.site for s in red]}"
    )

    green = new_findings(scan([guarded]))
    assert green == [], (
        "the screen flagged a step that DOES set pipefail, so it is failing indiscriminately and "
        f"the red above proves nothing. Findings: {[s.site for s in green]}"
    )


def test_a_planted_pipe_in_a_non_bash_step_is_not_a_finding(tmp_path: Path) -> None:
    """The shell-resolution layer, controlled. Without it every PowerShell pipeline reads as a defect.

    ``net-helper.yml`` alone carries several, and an earlier screen over this same corpus counted
    them, which is a large part of why its number disagreed with every other one.
    """
    windows = _plant(
        tmp_path,
        "planted-pwsh.yml",
        "name: planted\non: [push]\njobs:\n"
        "  planted:\n    runs-on: windows-2022\n    steps:\n"
        "      - name: Find the newest toolchain\n"
        "        run: |\n"
        "          Get-ChildItem C:\\tools | Sort-Object Name | Select-Object -Last 1\n",
    )
    assert new_findings(scan([windows])) == [], (
        "a PowerShell pipeline was reported as needing `set -o pipefail`, which it cannot take"
    )


def test_the_liveness_receipt_fails_when_the_walk_is_pointed_at_nothing(tmp_path: Path) -> None:
    """PROOF THE LIVENESS FLOOR CAN SEE. An empty corpus must be loud, not quietly green.

    This is the defect family the row this test belongs to is about: a control that reports success
    without exercising what it names. Pointed at a directory with no workflows the screen finds no
    findings, which is indistinguishable from a clean tree -- so the floor, not the finding count,
    is what has to fail.
    """
    empty = scan([])
    assert new_findings(empty) == [], "sanity: an empty corpus cannot produce findings"
    with pytest.raises(AssertionError, match="WALK COLLAPSED"):
        assert_liveness(empty)

    # One workflow is still a collapse: the floors are set against the whole corpus.
    with pytest.raises(AssertionError, match="WALK COLLAPSED"):
        assert_liveness(
            scan(
                [
                    _plant(
                        tmp_path,
                        "lonely.yml",
                        "name: x\non: [push]\njobs:\n  a:\n    runs-on: ubuntu-latest\n"
                        "    steps:\n      - run: echo hi\n",
                    )
                ]
            )
        )


# ---------------------------------------------------------------------------------------------
# The screen itself
# ---------------------------------------------------------------------------------------------


def test_the_walk_examined_the_corpus() -> None:
    """Liveness on the real tree, with the receipt printed so a reader can see what was covered."""
    result = scan()
    print(liveness_receipt(result))
    assert_liveness(result)


def test_no_new_unguarded_pipeline() -> None:
    """THE SCREEN. A new pipeline whose producer's exit code is discarded fails here.

    The remedy is one of three, in order of preference: add ``set -o pipefail`` at the top of the
    step's script; or, if the pipeline is deliberate, add it to ``_ALLOWLIST_STEPS`` WITH THE
    REASON; or, if it is a pre-existing site this screen simply had not seen, add it to
    ``_GRANDFATHERED`` and say so in the pull request. Do not widen the allowlist to a whole job to
    silence one step.
    """
    result = scan()
    print(liveness_receipt(result))
    assert_liveness(result)
    findings = new_findings(result)
    if findings:
        detail = "\n\n".join(
            f"  {s.site}\n" + "\n".join(f"      {line}" for line in piped_lines(s)[:4])
            for s in sorted(findings, key=lambda s: s.key)
        )
        raise AssertionError(
            f"{len(findings)} pipeline(s) discard their producer's exit code with pipefail off:\n\n"
            f"{detail}\n\nSee this module's docstring for the three ways to resolve one."
        )


def test_the_baseline_is_not_stale() -> None:
    """Every grandfathered entry must still name a real, still-unguarded step.

    A baseline that outlives its sites is the quiet failure here: the line stops matching anything,
    nothing reports it, and the list grows into a record of what USED to be wrong. It is also how
    the overlap with branch `b1544a-pipefail` gets noticed -- when that fix lands, three of these
    entries stop resolving and this test names them.
    """
    result = scan()
    assert_liveness(result)
    live = {s.key for s in result.unguarded}
    stale = sorted(_GRANDFATHERED - live)
    assert not stale, (
        "these grandfathered entries no longer name an unguarded pipeline. Either the step was "
        "FIXED (delete the line -- that is the point) or it was RENAMED (update it). Leaving them "
        "turns the baseline into a list of former problems that exempts nothing:\n  "
        + "\n  ".join(f"{w} :: {j} :: {s}" for w, j, s in stale)
    )


def test_every_allowlist_entry_resolves_and_says_why() -> None:
    """An allowlist entry that matches nothing is an unaudited exemption waiting to be reused."""
    result = scan()
    assert_liveness(result)
    jobs = {(s.workflow, s.job) for s in result.steps}
    steps = {s.key for s in result.steps}
    missing: list[tuple[str, ...]] = [k for k in _ALLOWLIST_JOBS if k not in jobs]
    missing.extend(k for k in _ALLOWLIST_STEPS if k not in steps)
    assert not missing, f"allowlist entries that name nothing in the tree: {missing}"
    entries: list[tuple[tuple[str, ...], str]] = [
        *_ALLOWLIST_JOBS.items(),
        *_ALLOWLIST_STEPS.items(),
    ]
    for key, reason in entries:
        assert len(reason) > 80, f"allowlist entry {key} needs a real reason, not a label"


# ---------------------------------------------------------------------------------------------
# The needs walk -- the finding this row was filed on
# ---------------------------------------------------------------------------------------------


def test_the_needs_walk_reaches_jobs_the_flat_resolution_cannot() -> None:
    """Resolving a required CONTEXT to its job reaches a fraction of what gates a merge.

    MEASURED at the time of writing: eight required contexts resolve to SIX distinct jobs, and the
    transitive ``needs:`` walk reaches FOURTEEN. Of the four unguarded piped sites inside
    merge-gating jobs, the flat resolution reaches ONE (``ci.yml`` ``test``, a context in its own
    right) and cannot reach the other three -- ``changes``, ``sqlserver-store`` and
    ``load-test-sqlserver`` all sit behind ``CI gate``'s ``needs:``, and ``CI gate`` itself runs no
    pipeline. That is the shape BACKLOG #1544 was filed on, confirmed here rather than quoted.

    The numbers are printed rather than pinned, because pinning them would red on any workflow
    churn. What is asserted is the RELATIONSHIP, which is what the row is about.
    """
    flat = gating_jobs_without_needs_walk()
    walked = gating_jobs()
    print(f"required contexts: {len(required_contexts())}")
    print(f"gating jobs, flat resolution:      {len(flat)} {sorted(flat)}")
    print(f"gating jobs, transitive needs walk: {len(walked)} {sorted(walked)}")

    assert flat, "no required context resolved to a job -- the context mapping is broken"
    assert flat < walked, (
        "the transitive walk found nothing the flat resolution did not. Either `needs:` vanished "
        "from the gating workflows or the walk is broken; both make this screen blind to the legs "
        "a roll-up aggregates."
    )
    assert len(walked) >= MIN_GATING_JOBS, (
        f"only {len(walked)} merge-gating jobs reached (floor {MIN_GATING_JOBS})"
    )

    result = scan()
    assert_liveness(result)
    unguarded_gating = {s.key for s in result.unguarded if (s.workflow, s.job) in walked}
    unreachable = {k for k in unguarded_gating if (k[0], k[1]) not in flat}
    print(f"unguarded piped steps inside merge-gating jobs: {sorted(unguarded_gating)}")
    print(f"  of which the flat resolution cannot reach:    {sorted(unreachable)}")
    assert unreachable, (
        "no merge-gating unguarded pipeline sits behind `needs:` any more. That is a GOOD outcome "
        "if the sites were fixed -- delete this assertion and the walk with it only after checking "
        "that is why, because the other explanation is that the walk stopped working."
    )


def test_the_corpus_has_no_regex_match_operator() -> None:
    """Pins the tokenizer's stated limit, so it stays vacuous or turns red when it stops being.

    ``[[ $x =~ a|b ]]`` is regex alternation in unquoted text, and :func:`walk` would call it a
    pipeline. Rather than guess at bash's conditional-expression grammar for a construct this
    corpus does not use, the absence is measured and held. The day one arrives, this test says so
    and somebody decides -- which beats a silent miscount landing in a number nobody re-derives.
    """
    result = scan()
    assert_liveness(result)
    offenders = [s.site for s in result.posix if "=~" in walk(s.script).code]
    assert not offenders, (
        "a `=~` match operator appeared in a shell step. The tokenizer does not parse "
        "conditional-expression regexes, so a `|` inside one would be miscounted as a pipeline. "
        "Teach walk() about `[[ ]]`, or exclude these steps explicitly:\n  "
        + "\n  ".join(offenders)
    )
