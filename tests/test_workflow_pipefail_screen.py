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
* subshells, so a ``)`` closing a ``( ... )`` does not close the command substitution around it and
  drop the rest of the pipeline back into quoted-data context;
* arithmetic -- ``$(( a | b ))`` and ``(( a | b ))`` are a bitwise-or, not a pipeline. ``$((``
  occurs in 13 steps across five workflows here, so this is live rather than theoretical;
* here-documents (``<<WORD``, ``<<-WORD``, ``<<'WORD'``), including two opened on one line, whose
  bodies are data; ``<<<`` is a here-string and consumes no lines, so it is not mistaken for one;
* comments, including a ``#`` that is not one because it is mid-word (``foo#bar``);
* ``case`` pattern alternation -- ``uv|pip|npm)`` is three patterns, not two pipelines. Four
  workflows here contain ``case`` statements, so this is load-bearing rather than theoretical;
* ``||`` (an or-list), ``|&`` (a pipe carrying stderr, so it IS one), and ``>|`` (a clobber
  redirection, so it is NOT one).

It does NOT resolve:

* ``[[ $x =~ a|b ]]`` regex alternation. Measured: ``=~`` does not occur anywhere in this corpus,
  so the gap is currently empty, and :func:`test_the_corpus_has_no_regex_match_operator` turns red
  the day it stops being empty -- which is when somebody has to decide, rather than inherit a
  silent miscount.
* ``|`` inside a ``${var//|/x}`` parameter expansion.
* a command substitution nested inside arithmetic (``$(( $(a | b) + 1 ))``). Its body is blanked
  with the arithmetic around it, and a quoted ``)`` inside it would close the arithmetic span early
  -- :func:`_arith_end` counts parens without re-entering quotes.
* WHERE a ``set -o pipefail`` applies. It is read as authoritative for the whole script wherever it
  appears, so one inside an ``if`` branch or a function body exempts pipes outside it. See
  :data:`_PIPEFAIL`; answering it needs a scope-aware walk.
* ``case`` opened after a word this file does not know is a keyword. ``;``, ``do``, ``then`` and
  ``else`` are resolved; the conservative direction is chosen deliberately, because failing to open
  a ``case`` costs a false POSITIVE that a reader sees, and opening one wrongly costs a false
  negative that nobody does.
* whether a pipeline's producer CAN fail. ``echo x | tr a b`` is reported by this screen and needs
  no guard. The allowlist is where to say so, with a reason.

**Shell resolution runs at four levels**, because a step that is not bash cannot take
``set -o pipefail`` and flagging it would be a false accusation: step ``shell:``, then job
``defaults.run.shell``, then workflow ``defaults.run.shell``, then the runner default (pwsh on a
Windows runner, bash elsewhere). This layer is not cosmetic -- ``net-helper.yml`` is dense with
PowerShell pipelines, and a screen without it reports every one of them as a finding. A ``runs-on``
that is an unresolved ``${{ }}`` expression is AMBIGUOUS: it is counted and reported, never folded
into either answer, and :func:`test_no_ambiguous_runner_step_contains_a_pipeline` holds that gap
empty the way the ``=~`` one is held.

**NAMING THE SHELL CHANGES THE SEMANTICS, and a screen that misses that accuses correct steps.**
Actions runs a named ``bash`` as ``bash --noprofile --norc -eo pipefail {0}`` -- pipefail already
on -- while an UNNAMED shell on a Linux or macOS runner is ``bash -e {0}``, without it. So a step
covered by ``shell: bash`` or by a job's ``defaults.run.shell: bash`` needs no ``set -o pipefail``
of its own, and reporting one is a false finding rather than a conservative one.
``.github/workflows/security.yml`` records the same substitution beside the steps that reject the
shortcut on purpose (BACKLOG #1481). Only the exact keyword implies it: a custom template such as
``shell: bash -e {0}`` is run as written and gets nothing.

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

#: Actions accepts BOTH extensions, so globbing one silently exempts a workflow added with the other
#: -- and the liveness floors below cannot see that, because an unwalked file contributes no steps to
#: fall short of them. There are no ``.yaml`` files here today.
#:
#: THIS FILE IS THE ONLY HALF THAT WIDENED. ``tests/_workflow_contexts.py`` still globs ``*.yml``, so
#: a ``.yaml`` workflow would be screened for pipes here and stay invisible to ``required_contexts``,
#: ``resolve`` and ``jobs_of`` -- which means :func:`gating_jobs` could not reach its jobs and the
#: merge-gating half of this file would silently exclude it. Widening the shared resolver is a change
#: to a module three suites import, so it belongs in its own pull request rather than riding in on
#: this one. Recorded here because the asymmetry is invisible from either file alone.
WORKFLOWS = sorted([*WORKFLOW_DIR.glob("*.yml"), *WORKFLOW_DIR.glob("*.yaml")])

#: ``${{ ... }}`` is substituted by Actions before the shell sees the script, so it is not shell and
#: must not be tokenized as shell. Non-greedy and DOTALL: a multi-line expression is still one token.
_GHA_EXPR = re.compile(r"\$\{\{.*?\}\}", re.DOTALL)

#: ``set -o pipefail``, ``set -eo pipefail``, ``set -euo pipefail``, ``set -e -o pipefail``.
#:
#: ANCHORED TO THE START OF A LINE, so an unquoted mention -- ``echo set -o pipefail`` -- cannot
#: answer for the shell. Blanking already handles the quoted, here-document and commented forms; it
#: cannot handle this one, because the words really are live shell. Measured over the corpus: all 31
#: real declarations sit at the start of their line, so the anchor costs nothing today. A declaration
#: written mid-line (``foo && set -o pipefail``) now reads as unguarded, which is the over-reporting
#: direction and visible to whoever hits it.
#:
#: IT IS NOT A SCOPE CHECK, and the anchor does not make it one. An indented declaration is accepted
#: wherever it sits, so a ``set -o pipefail`` inside an ``if`` branch, a subshell or a function body
#: reads as authoritative for the whole script and exempts pipes outside it. That is a FALSE
#: EXEMPTION, it predates the anchor, and leading whitespace has to be allowed regardless -- a shell
#: script indented inside a YAML block scalar is ordinary. Answering it needs a scope-aware walk,
#: which is real work and not this row's; it is listed among the module's stated limits rather than
#: left for a reader to infer from a regex.
_PIPEFAIL = re.compile(r"(?m)^[ \t]*set\s+(?:-[A-Za-z]+\s+)*-[A-Za-z]*o\s+pipefail\b")

#: Shells that take ``set -o pipefail``. pwsh/powershell/cmd do not, and ``shell: python`` is not a
#: shell at all.
_POSIX_SHELLS = frozenset({"bash", "sh"})

#: Shell KEYWORDS whose Actions-supplied command line ALREADY carries ``-o pipefail``. See the module
#: docstring: naming ``bash`` buys ``bash --noprofile --norc -eo pipefail {0}``, leaving it unnamed
#: gets ``bash -e {0}``. ``sh`` is deliberately absent -- it is run as ``sh -e {0}``.
_PIPEFAIL_BY_DECLARATION = frozenset({"bash"})

#: Characters after which a word starts a COMMAND rather than continuing an argument list. Used so a
#: literal ``case`` in the middle of a line does not open a case statement. Conservative by design:
#: failing to open one costs a false POSITIVE, which a reader sees; opening one wrongly costs a
#: false negative, which nobody sees.
_COMMAND_POSITION = frozenset({"", "\n", ";", "&", "|", "(", ")"})

#: Words after which a command starts. Without these, ``do case $x in a|b)`` never opens its case and
#: the alternation is counted as a pipeline. ``{`` is NOT treated this way on purpose: it would make
#: the ``#`` of ``${#var}`` read as a comment and blank the rest of the line.
_COMMAND_KEYWORDS = frozenset({"if", "elif", "then", "else", "do", "while", "until"})

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
    actions_pipefail: bool
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


def _heredoc_body_end(text: str, start: int, word: str) -> int:
    """From ``start``, the FIRST character of the body, the index just past the terminator ``word``.

    Taking the body's start rather than the newline before it is what makes two here-documents opened
    on one line work: the second body begins exactly where the first one ended, and a version that
    re-derived the start by seeking the next newline skipped a line each time -- swallowing the rest
    of the script as data whenever the skipped line was the terminator.
    """
    j = start
    while j < len(text):
        end = text.find("\n", j)
        line = text[j:] if end == -1 else text[j:end]
        if line.strip() == word:
            return len(text) if end == -1 else end + 1
        if end == -1:
            return len(text)
        j = end + 1
    return len(text)


def _arith_end(text: str, i: int) -> int:
    """From the ``$`` of ``$((`` or the first ``(`` of ``((``, the index just past the closing ``))``.

    Arithmetic is not a command list: ``|`` inside it is a bitwise-or. Parens are counted so a nested
    ``$(( (a + b) * c ))`` closes in the right place rather than at the first ``)``.
    """
    j = i + 3 if text[i] == "$" else i + 2
    depth = 2
    while j < len(text):
        if text[j] == "(":
            depth += 1
        elif text[j] == ")":
            depth -= 1
            if depth == 0:
                return j + 1
        j += 1
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
        nonlocal word, prev
        if not word:
            return
        frame = cases[-1]
        if word == "case" and word_is_command:
            frame.append("header")
        elif frame and frame[-1] == "header" and word == "in":
            frame[-1] = "pattern"
        elif word == "esac" and frame:
            frame.pop()
        if word in _COMMAND_KEYWORDS and word_is_command:
            # What follows a control keyword starts a command -- but only if the keyword was itself
            # in command position. `grep -w do f` must not hand command position to the next word.
            prev = ";"
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
            if ch == "$" and text[i + 1 : i + 3] == "((":
                # Arithmetic is arithmetic inside double quotes too. Without this the body is walked
                # as a command substitution and `"$(( a | b ))"` reads as a pipeline. The corpus
                # carries the quoted form (`sleep "$((attempt * 15))"`), so this path is live.
                end = _arith_end(text, i)
                blank(i, end)
                i = end
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
        if ch == "$" and text[i + 1 : i + 3] == "((":
            end = _arith_end(text, i)
            blank(i, end)
            i = end
            prev = "w"
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
        if ch == "(":
            frame = cases[-1]
            if text[i + 1 : i + 2] == "(" and prev in _COMMAND_POSITION:
                # `(( ... ))` in command position is arithmetic; `( (a) | b )` is two subshells, and
                # the space between its parens is what tells them apart -- as it does for bash.
                end = _arith_end(text, i)
                blank(i, end)
                i = end
                prev = "w"
                continue
            if not (frame and frame[-1] == "pattern"):
                # A SUBSHELL, pushed so its `)` closes IT. Left unpushed, that `)` popped the command
                # substitution around it and dropped the rest of the pipeline back into quoted data.
                # In `pattern` state the `(` is the optional case-pattern opener, which owns its `)`.
                quotes.append("")
                cases.append([])
            prev = ch
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
            in_body = bool(frame) and frame[-1] == "body"
            # `;;` ends a case arm, and `;&` falls through to the next one -- both put the NEXT thing
            # back in pattern state. Reading `;&` as a bare `;` leaves the frame in `body`, so the
            # following `b|c)` alternation is counted as a pipeline. `;;&` is matched by the first
            # branch and its trailing `&` is harmless.
            if in_body and text[i + 1 : i + 2] in (";", "&"):
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
            i += 1  # the first body begins after this newline; each later one where the last ended
            for delimiter in pending:
                i = _heredoc_body_end(text, i, delimiter)
            blank(start, i)
            pending = []
            prev = "\n"
            continue
        if ch == ">" and text[i + 1 : i + 2] == "|":
            # `>|` is a clobber redirection, not a pipeline. Consumed HERE, at the `>`, rather than
            # tested at the `|` against the previous character: nothing assigns `prev` when a quote
            # opens or closes, so `a >"file"|b` still carried `prev == ">"` to the pipe and dropped a
            # real pipeline. A position-local rule cannot go stale that way.
            i += 2
            prev = "w"
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
        elif prev not in _COMMAND_POSITION:
            # Whitespace must NOT erase command position, or `foo; case $x in a|b)` never opens its
            # case and the alternation is counted as a pipeline.
            prev = " "
        i += 1

    flush_word()
    code = "".join(c if kept[k] else " " for k, c in enumerate(text))
    return Walk(tuple(pipes), code)


def _unguarded_in(result: Walk) -> tuple[int, ...]:
    """The unguarded pipes of an ALREADY-WALKED script, so :func:`scan` need not tokenize twice."""
    if not result.pipes:
        return ()
    enabled = _PIPEFAIL.search(result.code)
    if enabled is None:
        return result.pipes
    return tuple(p for p in result.pipes if p < enabled.start())


def unguarded_pipes(script: str) -> tuple[int, ...]:
    """Pipe operators in ``script`` that run with ``pipefail`` off.

    Position matters: ``set -o pipefail`` placed AFTER a pipeline does not protect it, and a script
    that pipes on line one and enables the option on line two has exactly the defect this screen is
    for. The option is looked for in the blanked script, so a ``pipefail`` inside an echoed message
    or a here-document cannot answer for the shell.

    This asks about the SCRIPT only. Whether Actions already supplied the option by substituting a
    named shell is a property of the step, not of its text -- see :attr:`Step.actions_pipefail`.
    """
    return _unguarded_in(walk(script))


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
    """Levels one to three of shell resolution, VERBATIM: step, then job, then workflow defaults.

    Returned unsplit because whether Actions supplies ``-o pipefail`` turns on the exact keyword: it
    substitutes a full command line for ``bash``, while a CUSTOM template such as ``bash -e {0}`` is
    run as written and gets nothing. ``.get("run") or {}`` rather than ``.get("run", {})`` because a
    ``defaults:`` whose ``run:`` is present but empty parses to None, and the difference between the
    two spellings there is an AttributeError that takes down the module instead of reporting.
    """
    if isinstance(step, dict) and step.get("shell"):
        return str(step["shell"])
    for scope in (job, workflow):
        got = ((scope.get("defaults") or {}).get("run") or {}).get("shell")
        if got:
            return str(got)
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
                declared = _declared_shell(doc, job, step)
                ambiguous = False
                if declared is None:
                    shell, ambiguous = _runner_default(job)
                else:
                    shell = declared.split()[0]
                name = str(step.get("name") or f"step[{index}]")
                steps.append(
                    Step(
                        path.name,
                        str(job_id),
                        name,
                        shell,
                        declared in _PIPEFAIL_BY_DECLARATION,
                        ambiguous,
                        str(step["run"]),
                    )
                )
    posix = tuple(s for s in steps if s.shell in _POSIX_SHELLS)
    # Walk each script ONCE per scan, so the pipe finder and the pipefail finder read the same
    # tokenization rather than two independent ones. This does not make the walk global: a test that
    # re-walks a script for its own question still pays for that walk.
    walked = [(s, walk(s.script)) for s in posix]
    return Scan(
        steps=tuple(steps),
        posix=posix,
        piped=tuple(s for s, w in walked if w.pipes),
        unguarded=tuple(s for s, w in walked if not s.actions_pipefail and _unguarded_in(w)),
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
_GRANDFATHERED: frozenset[tuple[str, str, str]] = frozenset(
    {
        ("benchmark.yml", "baseline-postgres", "Environment stamp"),
        ("benchmark.yml", "baseline-sqlite", "Environment stamp"),
        ("benchmark.yml", "baseline-sqlserver", "Environment stamp"),
        ("ci.yml", "docker-smoke", "Engine log (always)"),
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
    # The exemption count is taken over the PIPED steps, not over all of posix, so the line
    # reconciles: piped = unguarded + named-shell + script-level `set -o pipefail`. Counted over
    # posix it reads as the whole of the gap between piped and unguarded, and it is not -- most of
    # that gap is steps that set the option themselves.
    by_declaration = len([s for s in result.piped if s.actions_pipefail])
    return (
        f"pipefail screen walked {len(result.steps)} run: steps across "
        f"{len({s.workflow for s in result.steps})} workflow files that declare one; "
        f"{len(result.posix)} resolved to bash/sh, {len(result.piped)} contained a real pipeline. "
        f"Of those, {len(result.unguarded)} ran with pipefail off, {by_declaration} were exempt by "
        f"naming the shell, and the rest set the option themselves; "
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
        (
            "cat <<A <<B\n1\nA\nB\ncurl x | tee y\n",
            1,
            "TWO here-documents on one line: the second body starts where the first ended, and a "
            "walk that re-seeks a newline skips a line and swallows the rest of the script",
        ),
        ('read -r x <<< "a | b"\n', 0, "<<< is a here-string, not a here-document"),
        ("( a | b )", 1, "a subshell is shell"),
        (
            'echo "$( (a) | b )"',
            1,
            "a subshell inside a command substitution inside double quotes: unpushed, its `)` closed "
            "the substitution and the rest of the pipeline was blanked as quoted data",
        ),
        ("x=$(( 3 | 4 ))", 0, "arithmetic expansion: | is a bitwise-or"),
        ("if (( x | y )); then :; fi", 0, "so is the arithmetic command"),
        ("x=$(( (3 | 4) * 2 ))", 0, "and nested parens close it in the right place"),
        ('echo "$(( 3 | 4 ))"', 0, "and arithmetic is still arithmetic INSIDE double quotes"),
        ('echo "$(( 1 + 2 ))" | cat', 1, "a real pipe after a quoted arithmetic expansion"),
        (
            "case $x in a) echo 1 ;& b|c) echo 2 ;; esac",
            0,
            "`;&` falls through to the next pattern, so what follows is a PATTERN not a pipeline",
        ),
        ("case $x in a) echo 1 ;;& b|c) echo 2 ;; esac", 0, "and `;;&` resumes testing"),
        ("foo; case $x in a|b) echo hi ;; esac", 0, "a case opened on the same line after `;`"),
        ("for f in 1 2; do case $f in a|b) :;; esac; done", 0, "and one opened after `do`"),
        ("if true; then case $x in a|b) :;; esac; fi", 0, "and one opened after `then`"),
        ("echo x >| file", 0, ">| is a clobber redirection, not a pipe"),
        (
            'a >"file"|b',
            1,
            "but a QUOTED redirect target then a real pipe: tested at the `|` against the previous "
            "character this read as a clobber and dropped a real pipeline",
        ),
        ("a > f | b", 1, "and a spaced redirect does not swallow the pipe after it"),
        ("a 2>&1 | tee f", 1, "nor does a stderr merge"),
        ("grep case f | wc -l", 1, "a literal `case` as an ARGUMENT opens nothing"),
        ("echo ${#items[@]} | cat", 1, "the `#` of ${#var} is not a comment"),
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
        (
            "echo set -o pipefail\na | b",
            1,
            "nor an UNQUOTED mention, which blanking cannot reach because it really is live shell",
        ),
        ("  set -o pipefail\n  a | b", 0, "but indentation is not a mention"),
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


def test_a_planted_pipe_under_a_named_bash_shell_is_not_a_finding(tmp_path: Path) -> None:
    """NAMING the shell is itself the guard, and a screen blind to that accuses correct steps.

    Actions substitutes ``bash --noprofile --norc -eo pipefail {0}`` for a named ``bash``, so these
    two steps are already protected and carry no ``set -o pipefail`` of their own. The third is the
    discriminating control: ``sh`` is run as ``sh -e {0}``, WITHOUT the option, so naming it changes
    nothing and the step is still a finding. Without that row a screen could pass this test by
    exempting every declared shell, which is a different and wrong rule.
    """
    head = "name: planted\non: [push]\njobs:\n  planted:\n    runs-on: ubuntu-latest\n"
    body = "        run: curl -fsSL https://example.invalid/k | sudo tee /etc/k > /dev/null\n"

    step_level = _plant(
        tmp_path,
        "planted-step-bash.yml",
        head + "    steps:\n      - name: Install a thing\n        shell: bash\n" + body,
    )
    job_level = _plant(
        tmp_path,
        "planted-job-bash.yml",
        head
        + "    defaults:\n      run:\n        shell: bash\n"
        + "    steps:\n      - name: Install a thing\n"
        + body,
    )
    workflow_level = _plant(
        tmp_path,
        "planted-workflow-bash.yml",
        "name: planted\non: [push]\ndefaults:\n  run:\n    shell: bash\n"
        "jobs:\n  planted:\n    runs-on: ubuntu-latest\n"
        "    steps:\n      - name: Install a thing\n" + body,
    )
    named_sh = _plant(
        tmp_path,
        "planted-step-sh.yml",
        head + "    steps:\n      - name: Install a thing\n        shell: sh\n" + body,
    )

    for planted, where in (
        (step_level, "step `shell: bash`"),
        (job_level, "job defaults"),
        (workflow_level, "WORKFLOW defaults"),
    ):
        found = new_findings(scan([planted]))
        assert found == [], (
            f"a step covered by {where} was reported as needing `set -o pipefail`, but Actions "
            f"already runs it with -eo pipefail. Findings: {[s.site for s in found]}"
        )

    assert [s.step for s in new_findings(scan([named_sh]))] == ["Install a thing"], (
        "`shell: sh` is run as `sh -e {0}` with NO pipefail, so it must still be screened -- the "
        "exemption above is for the bash keyword, not for naming a shell at all"
    )


def test_a_defaults_block_with_an_empty_run_does_not_crash_the_scan(tmp_path: Path) -> None:
    """``defaults:``/``run:`` with nothing under it parses to None, not to an empty mapping.

    A scan that reads it with ``.get("run", {})`` raises AttributeError, which takes the whole module
    down with an ERROR rather than a finding -- the shape where a screen stops screening and the
    reason is buried in a traceback about NoneType.
    """
    planted = _plant(
        tmp_path,
        "planted-empty-defaults.yml",
        "name: planted\non: [push]\njobs:\n  planted:\n    runs-on: ubuntu-latest\n"
        "    defaults:\n      run:\n    steps:\n      - name: Install a thing\n"
        "        run: curl -fsSL https://example.invalid/k | sudo tee /etc/k > /dev/null\n",
    )
    assert [s.step for s in new_findings(scan([planted]))] == ["Install a thing"]


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


def test_every_step_identity_is_unique() -> None:
    """The baseline and the allowlist are keyed by (workflow, job, step name), so it must be total.

    Actions does not require step names to be unique within a job, and this corpus already reuses
    "Record gate liveness" and the ODBC installer name across jobs -- a style that invites a collision
    WITHIN one. Two colliding steps share a single baseline line: fix one and the line still resolves
    against the other, so the unfixed one is exempted with nothing reporting it. Measured: zero
    collisions today, which is why this is a pin and not a repair.

    IT DOES NOT COVER AN UNNAMED STEP, and that is the sharper edge. One exists -- ``ci.yml``
    ``changes`` ``step[1]`` -- keyed by INDEX, so inserting a step above it renames it silently and
    a baseline or allowlist entry naming ``step[1]`` starts resolving to a different step.
    Collision-counting can never see that, because index-derived names do not collide. It is
    harmless today only because that job is covered whole by ``_ALLOWLIST_JOBS``; giving the step a
    ``name:`` in the workflow would end the exposure.
    """
    result = scan()
    assert_liveness(result)
    counts: dict[tuple[str, str, str], int] = {}
    for step in result.steps:
        counts[step.key] = counts.get(step.key, 0) + 1
    collisions = sorted(k for k, v in counts.items() if v > 1)
    assert not collisions, (
        "two run: steps in one job share a name, so they share one baseline and allowlist identity. "
        "Rename one, or key this screen by step index instead:\n  "
        + "\n  ".join(f"{w} :: {j} :: {s}" for w, j, s in collisions)
    )


def test_no_ambiguous_runner_step_contains_a_pipeline() -> None:
    """Pins the OTHER stated gap, so it stays empty or says so -- as the ``=~`` one does.

    A step whose ``runs-on`` is an unresolved expression has no knowable shell: the same script is
    bash on a Linux matrix arm and pwsh on a Windows one. :func:`scan` therefore gives it no shell,
    which drops it out of ``posix`` and puts it beyond every check below. That is the right answer to
    "which shell is this", and the wrong place to leave a silent exemption -- the liveness floors
    cannot notice, because the step still counts toward MIN_STEPS.

    Measured: six such steps, none containing a pipeline. The day one does, somebody decides -- name
    the shell, or split the matrix -- rather than inherit an exemption nobody chose.
    """
    result = scan()
    assert_liveness(result)
    offenders = [s.site for s in result.ambiguous if walk(s.script).pipes]
    assert not offenders, (
        "a step with an unresolvable `runs-on` grew something the BASH tokenizer reads as a "
        "pipeline. Read it before acting: on a Windows arm the step is pwsh and cannot take "
        "`set -o pipefail` at all, so the answer is to declare `shell:` or narrow the matrix and "
        "NOT to add the option. What this screen cannot do is leave it both unscreened and "
        "unreported:\n  " + "\n  ".join(offenders)
    )


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
    nothing reports it, and the list grows into a record of what USED to be wrong. It is also how a
    fix from another branch gets noticed: when one guards a grandfathered step, its line stops
    resolving and this test names it.
    """
    result = scan()
    assert_liveness(result)
    live = {s.key for s in result.unguarded}
    stale = sorted(_GRANDFATHERED - live)
    assert not stale, (
        "these grandfathered entries no longer name an unguarded pipeline. Find out WHY before "
        "deleting one -- at least three causes reach this message and they want different answers. "
        "The step was FIXED (delete the line; that is the point). It was RENAMED (update it). Or "
        "its job acquired a `shell: bash` declaration, which exempts it without touching the "
        "pipeline -- delete the line there and the pipeline becomes a NEW finding the moment the "
        "declaration goes. Leaving them turns the baseline into a list of former problems that "
        "exempts nothing:\n  " + "\n  ".join(f"{w} :: {j} :: {s}" for w, j, s in stale)
    )


def test_every_allowlist_entry_resolves_and_says_why() -> None:
    """An allowlist entry that matches nothing is an unaudited exemption waiting to be reused.

    Resolution is checked against the UNGUARDED set, not against every step in the tree, for the
    reason :func:`test_the_baseline_is_not_stale` checks the baseline that way: an entry whose site
    has since been fixed stops exempting anything real, but goes on exempting that step NAME against
    whatever pipeline is added to it next. Asking only whether the step still exists cannot see that.
    """
    result = scan()
    assert_liveness(result)
    jobs = {(s.workflow, s.job) for s in result.unguarded}
    steps = {s.key for s in result.unguarded}
    missing: list[tuple[str, ...]] = [k for k in _ALLOWLIST_JOBS if k not in jobs]
    missing.extend(k for k in _ALLOWLIST_STEPS if k not in steps)
    assert not missing, (
        "allowlist entries that no longer name an unguarded pipeline. Leaving one exempts a NAME "
        "rather than a reason. At least three causes reach this message -- the site was fixed, it "
        "was renamed, or its shell is now declared bash and the pipeline is untouched -- so check "
        f"which before deleting: {missing}"
    )
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

    MEASURED at the time of writing: the required contexts resolve to SIX distinct jobs, and the
    transitive ``needs:`` walk reaches FOURTEEN. All three unguarded piped sites inside merge-gating
    jobs -- ``changes``, ``sqlserver-store`` and ``load-test-sqlserver`` -- sit behind ``CI gate``'s
    ``needs:``, and ``CI gate`` itself runs no pipeline, so the flat resolution reaches NONE of them.
    That is the shape BACKLOG #1544 was filed on, confirmed here rather than quoted.

    An earlier revision of this docstring counted a fourth site, ``ci.yml`` ``test`` ``Doc guards``,
    and credited the flat resolution with reaching it. That was wrong in the instrument, not in the
    tree: the ``test`` job declares ``defaults.run.shell: bash``, so Actions already runs it with
    ``-eo pipefail`` and it was never a defect. It is recorded rather than quietly corrected because
    it was this file's headline example, and a reader who met it once should meet the retraction.

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
