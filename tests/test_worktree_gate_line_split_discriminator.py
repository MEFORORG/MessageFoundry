# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
r"""The per-line split hides a gated command only on the PAIR'S OWN LINE (BACKLOG #1427 / #1429).

TWO LEDGER ROWS SAID OPPOSITE THINGS ABOUT ONE SUBJECT, AND BOTH WERE LOCALLY TRUE. #1427 tabled the
per-line split as ``6 spellings driven, 0 allowed`` and quoted the gate's own docstring agreeing that
a quoted argument spanning lines denies today. #1429 tabled four spellings of the per-line split that
ALLOW and run. Neither row named its SHAPE closely enough for a reader to tell the two apart, so a
reader got whichever record they found first. This file is what makes it a question a machine answers.

**THE DISCRIMINATOR, and it is narrower than either record's wording.** ``Get-ScannableSegments``
splits on newlines before quoting is considered, so a quoted span crossing a newline is not one span
to the gate -- it is an unterminated quote on one line and a stray quote on the next. That only hides
anything when the gated command sits on a line carrying the CLOSING quote of one such span and the
OPENING quote of the next. Those two pair across it and blank it. Move the gated command off that
line, drop one of the two spans, or put both spans on the same side, and every rule sees it raw.

So the subject is not "the per-line split" and not "a quoted argument spanning lines". It is::

    <closing quote of a newline-crossing span>  <gated command>  <opening quote of the next>

all three on ONE line. #1429 is that shape. #1427's six spellings are recorded nowhere -- neither the
row, PR 797, nor a tree-wide search names them individually -- but every near-miss neighbour this file
could construct DENIES, which is consistent with #1427 having driven the neighbours and not the shape.

**MEASURED 2026-09-04**, gate copy hash-verified byte-identical to ``origin/main``'s
``scripts/hooks/worktree_gate.ps1`` (blob ``8d5c4d50``) at ``685d4f548``, driven as a subprocess with
a real ``PreToolUse`` payload, cwd inside a real throwaway git repo named by the repos file. Corpus:
**36 spellings across two passes**, with five controls in every batch that had to land on their stated
verdict -- a bare gated command DENY, a gated command under the PowerShell tool DENY, a quoted commit
message ALLOW, an unterminated quote DENY, and an inert command ALLOW. **Exactly 4 of the 36 ALLOWed,
all four the shape above.** Read 4 as a floor, not an enumeration: nothing ranged over the input space.

Every row that HAS a separate middle statement was additionally pinned to whether the shell really RUNS
it, with an inert marker that COMPUTES (``expr 111 \* 3`` under bash, ``111*3`` under pwsh, both
printing 333), because a DENY over a shape the shell would not execute protects nothing. All of them
run EXCEPT ``gated_inside_span``, whose text is shell DATA -- that row's DENY is a false positive, and
counting it as coverage would be wrong. It is kept as a boundary pin and labelled, not as evidence.
``gated_commands_own_argument_spans_lines`` has no middle statement to measure: the gated command IS
the whole shape there, so that row carries a verdict and no execution reading.

**THIS FILE ASSERTS THE DENY SIDE ONLY, DELIBERATELY.** The four ALLOWing corners are already pinned as
a tripwire in ``tests/test_worktree_gate_quote_straddle.py``. Restating them here would give a future
fixer of #1429 two places to find and delete, and the standing hazard in this neighbourhood is exactly
that: two shipped tripwires assert ALLOW and tell a reader who reds them to DELETE the row. So when
#1429 closes, the straddle suite reds and this file stays green -- which is the correct outcome,
because these shapes must go on denying. This is the must-NOT-trip half of the paired suite #1429 asks
a fix to bring; the must-trip half is the straddle suite's four rows.

**ALL FOUR TOOL x QUOTE CORNERS, AND THE COMPLETENESS IS PAID FOR.** Each row costs a ``pwsh`` launch
and a sampled corner set would be cheaper. The last person to sample corners here missed the
double-quoted PowerShell one, and that missing corner is the whole reason "fail-opens remaining: 3"
went out as an enumeration when the truth was a floor of four. A corner nobody drove is the failure
mode this neighbourhood actually has.
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any

import pytest
from _bash_resolver import explain_returncode, require_bash

from tests.test_worktree_gate import assert_denied, run_gate  # reuse the subprocess harness

# Built by concatenation, matching the straddle suite: a test about quote handling must not depend on
# how its own string literals nest.
SQ = "'"
DQ = '"'

#: An inert marker that ARITHMETICS. An echo-back is not a run, so the marker has to compute.
BASH_MARKER = "expr 111 \\* 3"
MARKER_RESULT = "333"

#: The four tool x quote corners: (tool, printing program, quote character, gated verb).
CORNERS = [
    ("Bash", "echo", SQ, "checkout main"),
    ("Bash", "echo", DQ, "checkout main"),
    ("PowerShell", "Write-Output", SQ, "reset --hard"),
    ("PowerShell", "Write-Output", DQ, "reset --hard"),
]


@pytest.fixture
def primary(tmp_path: Path) -> Path:
    return tmp_path / "Repo"


@pytest.fixture
def repos_file(tmp_path: Path, primary: Path) -> Path:
    f = tmp_path / "repos.txt"
    f.write_text(f"{primary}\n", encoding="utf-8")
    return f


def payload(tool: str, command: str, cwd: Path) -> dict[str, Any]:
    """A PreToolUse payload for either tool.

    ``tool_name`` carries the REAL tool name and never a display label. A label passed here produced
    an all-ALLOW table that read as a finding, twice, on the work this file settles.
    """
    return {"tool_name": tool, "tool_input": {"command": command}, "cwd": str(cwd)}


#: The near-miss family. Each template differs from the ALLOWing shape by ONE property, named in the
#: id, so a red says which property stopped mattering. ``{G}`` is the gated command.
NEAR_MISS = {
    # Two newline-crossing spans, but BOTH before the gated command -- so the pair closes before it
    # and no quote is left to bracket it. Two spans are not the condition; bracketing is.
    "both_spans_before": "{P} {Q}a\nb{Q} ; {P} {Q}c\nd{Q} ; {G}",
    # ONE newline-crossing span, gated command after it. The payload line carries a single stray
    # quote, which has nothing to pair with.
    "one_span_before": "{P} {Q}a\nb{Q} ; {G}",
    # ...and the mirror, so neither side is special-cased.
    "one_span_after": "{G} ; {P} {Q}c\nd{Q}",
    # THE SHARPEST ROW. Both spans straddle and they DO bracket the gated command -- but two extra
    # newlines give it a line of its own, so the pair is split across three lines and the gated line
    # is raw. This is what makes the discriminator the LINE rather than the newline or the span count.
    "bracketing_pair_but_gated_on_its_own_line": "{P} {Q}a\nb{Q} ;\n{G} ;\n{P} {Q}c\nd{Q}",
    # A single span crossing TWO newlines with the gated text on the interior line. This is the most
    # literal reading of the gate's old "a quoted argument spanning lines", and it denies.
    #
    # ITS DENY IS A FALSE POSITIVE AND MUST NOT BE COUNTED AS COVERAGE: the text is inside the quotes,
    # so the shell treats it as an argument to `echo`/`Write-Output` and never executes it. Measured
    # with the computing marker in the same slot -- it prints the marker's own text, not 333. Kept as
    # a boundary pin so a future over-blanking fix that stopped denying it is still visible here.
    "gated_inside_span_never_runs": "{P} {Q}a\n{G}\nb{Q}",
}


@pytest.mark.parametrize("shape", sorted(NEAR_MISS))
@pytest.mark.parametrize("tool,program,quote,verb", CORNERS)
def test_the_near_miss_line_split_shapes_still_deny(
    primary: Path,
    repos_file: Path,
    shape: str,
    tool: str,
    program: str,
    quote: str,
    verb: str,
) -> None:
    """Everything one property away from the straddling pair is still seen (BACKLOG #1427)."""
    command = (
        NEAR_MISS[shape]
        .replace("{P}", program)
        .replace("{Q}", quote)
        .replace("{G}", f"git -C {primary} {verb}")
    )
    assert_denied(run_gate(payload(tool, command, cwd=primary), repos_file))


@pytest.mark.parametrize(
    "label,tool,verb,template",
    [
        # A bare newline between statements, with no quoted span crossing it at all. Every line
        # reaches the scanner raw, which is what the gate's docstring always said correctly.
        ("statements_split_by_newline", "Bash", "checkout main", "echo hi\n{G}\necho bye"),
        (
            "statements_split_by_newline_pwsh",
            "PowerShell",
            "reset --hard",
            "Write-Output hi\n{G}\nWrite-Output bye",
        ),
        # A heredoc carrying the gated command on its own line. Named in the residual list as an
        # inherited category; it denies, and the middle statement genuinely runs.
        ("heredoc_body", "Bash", "checkout main", "bash <<{Q}EOF{Q}\n{G}\nEOF"),
        # An interpreter payload spanning lines. The recursion is not what saves this -- the payload's
        # middle line reaches the scanner raw on its own.
        (
            "interpreter_payload_spanning_lines",
            "Bash",
            "checkout main",
            "bash -c {Q}echo a\n{G}\necho b{Q}",
        ),
        # The gated command's OWN quoted argument spans lines, on a gated verb that takes a message.
        (
            "gated_commands_own_argument_spans_lines",
            "Bash",
            "stash",
            "{G} push -m {Q}line one\nline two{Q}",
        ),
    ],
)
def test_the_other_multi_line_categories_still_deny(
    primary: Path, repos_file: Path, label: str, tool: str, verb: str, template: str
) -> None:
    """The remaining multi-line categories the residual list names, driven rather than assumed."""
    command = template.replace("{Q}", SQ).replace("{G}", f"git -C {primary} {verb}")
    assert_denied(run_gate(payload(tool, command, cwd=primary), repos_file))


# ---------------------------------------------------------------------------------------------
# The over-deny arm. Without it every row above would pass against a gate that denied its own input,
# which is the cheapest wrong way to make a must-not-trip suite green.
# ---------------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "label,command",
    [
        # The reason blanking exists. `git commit -m "chore: clean up dead code"` was denied on
        # `clean` before quoted spans were blanked.
        ("quoted_commit_message", f"git commit -m {DQ}chore: clean up dead code{DQ}"),
        # A multi-line quoted message with no gated command anywhere. A fix that carried quote state
        # across the split must not start denying ordinary prose that happens to span lines.
        ("multi_line_prose", f"echo {SQ}about to clean up\nthe merge notes{SQ}"),
    ],
)
def test_ordinary_multi_line_prose_still_allows(
    primary: Path, repos_file: Path, label: str, command: str
) -> None:
    """The false positives the current design bought. A fix must not buy them back."""
    result = run_gate(payload("Bash", command, cwd=primary), repos_file)
    assert result is None, (
        f"{label} now DENIES. That is the false positive quoted-span blanking exists to prevent, and "
        "a fix for BACKLOG #1429 that reaches it has moved the cost rather than paid it. Deny "
        f"object:\n{result}"
    )


def test_the_positive_control_denies(primary: Path, repos_file: Path) -> None:
    """A bare gated command. A run where this ALLOWs is a dead probe, not a result.

    Recorded as its own row because this file's finding is a table of DENIES: if the gate stopped
    seeing `git` at all, every row above would go green for the wrong reason and only this one and the
    ALLOW rows above would say so.
    """
    assert_denied(
        run_gate(payload("Bash", f"git -C {primary} checkout main", cwd=primary), repos_file)
    )


def test_the_denied_shapes_would_really_have_executed(tmp_path: Path) -> None:
    """A DENY over a shape the shell would not run protects nothing (SDS-3.8).

    Two readings from one interpreter, with the gated slot filled by an inert marker that COMPUTES:

    * the bracketing pair with the middle statement on its own line RUNS it -- so that row's DENY is
      load-bearing, and the shape it denies is a live command;
    * the same marker INSIDE the quoted span does not run -- it is echoed back as text. That row's
      DENY is a false positive, which is why the parametrisation above labels it and this test is
      where the label is proved rather than asserted in a comment.

    No git command is built or run here. The marker is arithmetic.
    """
    bash = require_bash(tmp_path)

    def run(command: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [bash, "-c", command], capture_output=True, text=True, timeout=120, cwd=tmp_path
        )

    proc = run(f"echo {SQ}a\nb{SQ} ;\n{BASH_MARKER} ;\necho {SQ}c\nd{SQ}")
    assert MARKER_RESULT in proc.stdout, (
        "the bracketing-pair shape did not execute its middle statement, so the DENY pinned above "
        f"is over a shape no shell would run. {explain_returncode(proc.returncode, 'the marker')} "
        f"stdout={proc.stdout!r} stderr={proc.stderr!r}"
    )

    proc = run(f"echo {SQ}a\n{BASH_MARKER}\nb{SQ}")
    assert MARKER_RESULT not in proc.stdout, (
        "the marker INSIDE a quoted span executed. It is supposed to be shell data, which is why "
        "`gated_inside_span_never_runs` is labelled a false-positive DENY rather than counted as "
        f"coverage. If this is now real, that row becomes evidence. stdout={proc.stdout!r}"
    )
    assert BASH_MARKER.replace("\\", "") in proc.stdout.replace("\\", ""), (
        "the marker inside the span neither ran nor echoed, so this reading is about the harness "
        f"rather than the shape. {explain_returncode(proc.returncode, 'the inert marker')} "
        f"stdout={proc.stdout!r} stderr={proc.stderr!r}"
    )
