# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""A backticked or fenced MENTION of the claim token was read as a CLAIM (BACKLOG #1296).

``backlog-hygiene.yml`` decides whether a pull request *claims* to implement a backlog item by
grepping its title and body. Nothing stripped code, so a token written to DISCUSS the gate was
indistinguishable from one written to CLAIM an item.

**THE DIRECTION IS WHAT MAKES IT WORTH A SUITE.** This is a REQUIRED status check, so the failure is
a false DENY on a compliant pull request -- and a false failure is acted on immediately where a false
pass is merely believed. It fired for real on PR #428, where the paragraph explaining the gate is
what tripped the gate. Both obvious workarounds damage the record: delete the explanation that made
the behaviour checkable, or write a banner asserting a completion that did not happen -- which is the
exact lie this gate exists to prevent.

***THE PIPELINE IS READ OUT OF THE WORKFLOW AND EXECUTED. IT IS NEVER RE-IMPLEMENTED HERE.*** A test
that mirrors the logic in Python would pass while the workflow drifts underneath it -- and worse, it
would RESTATE the code-span rule, which is the very defect #1296 is about: one job holding two
disagreeing definitions of what counts as text. ``test_ci_docs_only_detector.py`` mirrors because
``ci.yml``'s decision spans steps and cannot be run in isolation; this one is a pure text transform
over two environment variables, so the stronger form is available and is used.

***EVERY ARM IS PAIRED, AND THAT IS THE POINT RATHER THAN THOROUGHNESS.*** A one-armed suite calls a
LOOSENED pattern a pass: delete the extraction entirely and every must-not-trip row goes green. So
each must-not-trip row below is answered by a must-trip row, and
``test_the_same_body_keeps_a_real_claim_while_dropping_a_mention`` puts both in ONE body -- the only
arm that can tell a surgical fix from a blunt one.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

import pytest
from _bash_resolver import explain_returncode, require_bash

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "backlog-hygiene.yml"

#: The shell assignments that make up the extraction, in file order. Matched by NAME so a change to
#: the pipeline's internals is picked up automatically and a change to its SHAPE fails loudly.
_ASSIGN = re.compile(r"^\s+((?:prose|items)=\"\$\(.*)$", re.M)

BT = chr(96)  # a backtick, spelled once, so this file's own literals cannot confuse the reader

FENCE = "\n".join(
    ["see the failure:", BT * 3, "ERROR: this PR says it implements BACKLOG #8888", BT * 3, "done"]
)
MENTION = f"a reviewer adding {BT}BACKLOG #9999{BT} to the body is what makes the gate ask."


def _pipeline() -> str:
    """The extraction, lifted verbatim from the workflow."""
    text = WORKFLOW.read_text(encoding="utf-8")
    found = [m.group(1) for m in _ASSIGN.finditer(text)]
    assert found, (
        f"no prose=/items= assignment found in {WORKFLOW.name}. The claim extraction was renamed or "
        "restructured -- this suite is now measuring nothing, which is why this assertion exists."
    )
    return "\n".join(found)


def _items(bash: str, title: str, body: str) -> list[str]:
    """Run the REAL pipeline and return the item numbers it extracted."""
    script = "set -euo pipefail\n" + _pipeline() + '\nprintf "%s" "$items"\n'
    # PATH is the interpreter's OWN directory rather than inherited or empty. Empty was tried and is
    # wrong: the pipeline needs awk, sed, tr, grep and sort, and an empty PATH yields exit 127 --
    # which `explain_returncode` correctly calls a HARNESS fault, not a finding about the workflow.
    # Inheriting is wrong in the other direction: it would let a tool from somewhere else on this
    # machine answer for one CI does not have. These utilities ship beside bash on both hosts.
    proc = subprocess.run(  # noqa: S603  # nosec B603 - fixed argv, test-local script
        [bash, "-c", script],
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
        env={"PR_TITLE": title, "PR_BODY": body, "PATH": str(Path(bash).parent)},
    )
    assert proc.returncode == 0, (
        f"the extraction pipeline itself failed: {explain_returncode(proc.returncode)}\n"
        f"stderr: {proc.stderr}"
    )
    return [line for line in proc.stdout.splitlines() if line.strip()]


@pytest.fixture(scope="module")
def bash(tmp_path_factory: pytest.TempPathFactory) -> str:
    return require_bash(tmp_path_factory.mktemp("bash"))


# --- the extraction must still be there at all ----------------------------------------------------


def test_the_pipeline_was_actually_found_in_the_workflow() -> None:
    """THE ANTI-VACUITY ROW. Every arm below runs whatever this returns; if it returned an empty
    string they would all pass over nothing, which is the silent-green shape this repo keeps hitting."""
    text = _pipeline()
    assert "items=" in text, f"no items= assignment extracted:\n{text}"
    assert "grep -i BACKLOG" in text, (
        f"the extracted text does not contain the claim grep, so it is not the pipeline:\n{text}"
    )


def test_the_strip_stage_is_present_and_has_no_close_paren() -> None:
    """The file documents a zizmor hazard: a close-paren appearing before a command substitution's
    own closer orphans a trailing ``|| true`` and reds a required gate on a correct script. The strip
    stage adds none, and this pins that so a later edit cannot quietly reintroduce it."""
    prose = [ln for ln in _pipeline().splitlines() if ln.startswith("prose=")]
    assert len(prose) == 1, f"expected exactly one prose= stage, got {len(prose)}"
    inner = prose[0][len('prose="$(') : -len(')"')]
    assert ")" not in inner, (
        f"the strip stage contains a close-paren, which can orphan a trailing guard:\n{inner}"
    )


# --- must NOT trip: a mention is not a claim -------------------------------------------------------


def test_a_backticked_mention_is_not_a_claim(bash: str) -> None:
    """THE DEFECT. Before the fix this returned ['9999'] and failed a compliant pull request."""
    assert _items(bash, "docs: explain how the gate works", MENTION) == [], (
        "a token quoted in backticks to DISCUSS the gate was read as a CLAIM -- the false deny that "
        "fired on PR #428"
    )


def test_a_fenced_block_quoting_the_gates_own_error_is_not_a_claim(bash: str) -> None:
    """The second half, and it needs the fence toggle rather than the inline rule: a PR that
    reproduces this job's OWN error output quotes the token across several lines."""
    assert _items(bash, "docs: quote the failure", FENCE) == [], (
        "a token inside a fenced block was read as a claim, so a PR quoting this gate's error "
        "output is enforced against"
    )


# --- must trip: the invariant the gate exists for --------------------------------------------------


def test_a_genuine_claim_in_the_subject_is_still_enforced(bash: str) -> None:
    """THE PAIRED ARM. Deleting the extraction outright would pass every row above and fail here."""
    assert _items(bash, "fix(x): a thing (BACKLOG #4242)", "an ordinary body") == ["4242"]


def test_a_genuine_claim_in_the_body_is_still_enforced(bash: str) -> None:
    assert _items(bash, "fix(x): a thing", "this implements BACKLOG #4242 as agreed") == ["4242"]


def test_a_claim_BETWEEN_two_code_spans_survives(bash: str) -> None:
    """THE STRADDLE ARM, and it was ADDED BECAUSE MUTATION TESTING FOUND THE SUITE BLIND WITHOUT IT.

    Every other row here carries at most ONE code span per line, and over that population a GREEDY
    strip (``s/`.*`/ /g``) is indistinguishable from the correct non-greedy one -- measured: the
    greedy mutant passed all nine rows. With two spans on a line, greedy consumes everything between
    them, which is the #1229 straddle one level up: a matcher pairing two delimiters ACROSS live text
    and deleting what sits between.

    So this is the row that separates "strips code spans" from "strips from the first backtick to the
    last", and without it a fix that silently swallowed real claims would have shipped green.
    """
    body = f"unlike {BT}the old rule{BT} this implements BACKLOG #4242, not {BT}the other one{BT}."
    assert _items(bash, "fix(x): a thing", body) == ["4242"], (
        "a claim sitting BETWEEN two code spans was eaten -- the strip is greedy and pairs the spans "
        "across live text"
    )


def test_the_same_body_keeps_a_real_claim_while_dropping_a_mention(bash: str) -> None:
    """THE ARM THAT DISTINGUISHES A SURGICAL FIX FROM A BLUNT ONE, and the only one that can.

    Every other row here is satisfied by a fix that is too broad or too narrow in one direction. This
    one puts a real claim and a discussed one in a SINGLE body: a fix that strips too much loses the
    4242, and a fix that strips too little keeps the 9999.
    """
    assert _items(bash, "fix(x): a thing (BACKLOG #4242)", MENTION) == ["4242"], (
        "the fix is not surgical: it must drop the quoted mention and keep the real claim"
    )


# --- the neighbouring invariant this change must not disturb ---------------------------------------


def test_the_parenthetical_scoping_still_excludes_the_squash_number(bash: str) -> None:
    """BACKLOG #1347's scoping, pinned here because #1296's fix runs immediately before it.

    A squashed subject reads ``(BACKLOG #1040) (#547)``; taking every number after the token would
    claim PR #547 as an item. The split on close-paren is what prevents that, and stripping code
    spans first must not disturb it -- a close-paren removed WITH a code span never delimited a group.
    """
    got = _items(bash, "fix(hooks): a thing (BACKLOG #1319, #1322) (#547)", "")
    assert got == ["1319", "1322"], f"parenthetical scoping changed: {got}"


def test_a_pull_request_claiming_nothing_extracts_nothing(bash: str) -> None:
    """The gate's own short-circuit: no claim means nothing to enforce."""
    assert _items(bash, "chore: tidy imports", "no item is claimed here") == []
