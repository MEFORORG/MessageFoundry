# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""The unresolved-backlog-citation detector (BACKLOG #1235).

Every false-positive shape asserted here was found by RUNNING the tool over docs/, not predicted
before it. Two of them were defects in the detector itself on its first real run: a hex colour
matching its own digit prefix, and a crash on a character a cp1252 console cannot encode. They are
pinned as tests because both re-appear the moment the pattern is loosened.
"""

from __future__ import annotations

import importlib.util
import pathlib
from pathlib import Path

import pytest

_SPEC = importlib.util.spec_from_file_location(
    "_dangling_citation_check",
    Path(__file__).resolve().parents[1] / "scripts" / "docs" / "dangling_citation_check.py",
)
assert _SPEC is not None and _SPEC.loader is not None
cc = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(cc)


def _numbers(text: str) -> list[int]:
    return [number for _lineno, number, _line, _pr in cc.citations_in(text)]


# --- what a citation IS ---------------------------------------------------------------------------


def test_a_plain_citation_is_found() -> None:
    assert _numbers("see BACKLOG #1235 for the rule") == [1235]


def test_line_numbers_are_one_indexed() -> None:
    lineno, number, _line, _pr = cc.citations_in("first\nsecond #1235\n")[0]
    assert (lineno, number) == (2, 1235)


@pytest.mark.parametrize("trailing", [".", ",", ")", "'s", " and", "]", ";"])
def test_ordinary_punctuation_still_closes_a_citation(trailing: str) -> None:
    assert _numbers(f"see #1235{trailing}") == [1235]


# --- what a citation IS NOT -----------------------------------------------------------------------


def test_a_markdown_heading_is_not_a_citation_of_itself() -> None:
    """Every item heading in the ledger would otherwise report as citing its own number."""
    assert _numbers("## 1235. a citation to an unallocated number") == []


@pytest.mark.parametrize("colour", ["#1565c0", "#06302b", "#1234ab"])
def test_a_hex_colour_does_not_match_its_own_digit_prefix(colour: str) -> None:
    """Measured, not predicted: on the first real run over docs/, `#1565c0` and `#06302b` alone
    produced 8 of 40 hits. An inflated count in a tool whose whole output is a bound is fatal."""
    assert _numbers(f"classDef x fill:#e3f2fd,stroke:{colour};") == []


def test_numbers_outside_the_window_are_ignored() -> None:
    assert _numbers("PR #995 and issue #42 and #9000 and #12345") == []


def test_the_window_is_half_open_at_both_ends() -> None:
    assert _numbers("#999") == []
    assert _numbers("#1000") == [1000]
    assert _numbers("#8999") == [8999]
    assert _numbers("#9000") == []


# --- annotation, which discloses rather than trims -------------------------------------------------


@pytest.mark.parametrize(
    "line",
    [
        "shipped in PR #1001",
        "see pull request #1001",
        "fixed by commit #1001",
        "upstream issue #1001",
        "code-server discussion #6256",
    ],
)
def test_a_pr_or_forum_reference_is_annotated(line: str) -> None:
    hits = cc.citations_in(line)
    assert len(hits) == 1
    assert hits[0][3] is True, "should be flagged as very likely not a backlog citation"


@pytest.mark.parametrize("line", ["upstream pyodbc#1459", "coder/code-server#6256"])
def test_a_foreign_repo_reference_is_annotated(line: str) -> None:
    hits = cc.citations_in(line)
    assert len(hits) == 1
    assert hits[0][3] is True


def test_a_genuine_citation_is_not_annotated() -> None:
    hits = cc.citations_in("this supersedes #1084")
    assert len(hits) == 1
    assert hits[0][3] is False


def test_an_annotated_hit_is_still_reported_and_still_counted() -> None:
    """The item's discipline is to DISCLOSE a false positive, never to trim it -- a trimmed scan
    silently understates, which is the failure this whole item is about."""
    assert len(cc.citations_in("upstream pyodbc#1459")) == 1


# --- resolution against the ledger ------------------------------------------------------------------


def test_only_unallocated_numbers_are_reported(tmp_path: Path) -> None:
    doc = tmp_path / "d.md"
    doc.write_text("real #1230, unreal #8999\n", encoding="utf-8")
    hits = cc.unresolved_citations([doc], allocated={1230})
    assert [h.number for h in hits] == [8999]


def test_a_closed_item_still_resolves(tmp_path: Path) -> None:
    """A citation to a CLOSED item points at something real. Only a number naming nothing is the trap."""
    doc = tmp_path / "d.md"
    doc.write_text("see #1230\n", encoding="utf-8")
    assert cc.unresolved_citations([doc], allocated={1230}) == []


def test_an_unreadable_file_is_skipped_not_fatal(tmp_path: Path) -> None:
    missing = tmp_path / "gone.md"
    assert cc.unresolved_citations([missing], allocated=set()) == []


def test_the_real_ledger_yields_a_plausible_allocated_set() -> None:
    """Positive control on the ledger read: if parse_items ever returns nothing, every citation in
    the repository would report as unresolved and the tool would look catastrophically alarming."""
    allocated = cc.allocated_numbers()
    assert len(allocated) > 100
    assert 1235 in allocated, "the item that defines this tool must resolve"


# --- the floor, which decides whether a citation can ever arm ---------------------------------------


def test_the_floor_is_found_and_is_plausible() -> None:
    """Positive control. If the ledger read ever silently returned nothing, the floor would be 0 and
    EVERY citation would classify as live -- 26 manufactured alarms on this repository."""
    assert cc.allocation_floor() > 1000


def test_a_number_below_the_floor_can_never_be_issued() -> None:
    """#1203 and #1231 are the two instances BACKLOG #1235 names as live traps. Both sit BELOW the
    high-water mark, and alloc.ps1 starts at `$observed + 1` and never fills a hole, so neither can
    ever be issued. The citations are inert BY CONSTRUCTION, not by luck.

    Note what this does NOT depend on: any allocation record under .git. Those are machine-local and
    losable; the unreachability is structural and survives losing them."""
    floor = cc.allocation_floor()
    assert floor >= 1203
    assert floor >= 1231
    filed = cc.allocated_numbers()
    assert 1203 not in filed, "if #1203 gets filed this test has served its purpose -- update it"
    assert 1231 not in filed


def test_a_number_above_the_floor_is_the_live_shape() -> None:
    assert cc.allocation_floor() < 8999


def test_the_floor_is_conservative_never_optimistic(tmp_path: pathlib.Path) -> None:
    """Built from the ledgers only, so it can only ever UNDERSTATE the allocator's true floor (which
    also spans refs and allocations). Understating means over-warning, never a missed trap."""
    ledger = tmp_path / "L.md"
    ledger.write_text("## 1500. an item\n\n> open\n", encoding="utf-8")
    assert cc.allocation_floor([ledger]) == 1500


# --- THE GATE ITSELF, run over the real tree (BACKLOG #1235) ---------------------------------------
#
# The detector shipped in PR #385 wired into NOTHING: repo-wide it was referenced by two lines, both
# inside this file, and its CLI exited 0 even when it reported a hit. A detector nobody invokes and
# that cannot fail is not a gate. These give it the failing arm and make the suite the caller.


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _live_shape_citations() -> list[tuple[str, int, int]]:
    """Citations naming a number that can still be issued -- the shape that can arm.

    CALLS THE SHIPPED PREDICATES RATHER THAN RE-DERIVING THEM (BACKLOG #1235 residual 2). This
    helper previously re-implemented both halves inline -- `number in filed` duplicating
    `unresolved_citations`, and `number <= floor or pr_shaped` duplicating what `main` filters on.
    Two of the three agreed with the script by convention, with nothing binding them: a rule with
    two definitions is the exact defect this tool exists to catch in other people's gates.

    The consequence is checkable and is the point: a single mutation to `cc.is_live_shape` now reds
    BOTH this real-tree gate and the exit-code arms below. Before, mutating one left the other
    green, which is what "agreeing by convention" buys you.
    """
    root = _repo_root()
    floor = cc.allocation_floor()
    hits = cc.unresolved_citations(sorted((root / "docs").rglob("*.md")), cc.allocated_numbers())
    return [
        (str(hit.path.relative_to(root)), hit.lineno, hit.number)
        for hit in hits
        if cc.is_live_shape(hit, floor)
    ]


def test_the_docs_scan_actually_covers_something() -> None:
    """PRINT AND PIN THE POPULATION. A walk that collapses to nothing reports clean forever, which
    is the exact failure this whole item is about."""
    found = sorted((_repo_root() / "docs").rglob("*.md"))
    print(f"scanned {len(found)} markdown files under docs/")
    assert len(found) > 200, f"only {len(found)} docs found -- the walk is not finding them"


def test_no_docs_citation_names_a_number_that_can_still_be_issued() -> None:
    """THE GATE. A citation to an unissued number is harmless until someone files that number, at
    which point it silently starts naming unrelated work. Catch it while it is still honest."""
    live = _live_shape_citations()
    assert not live, "citations naming a still-issuable number:\n  " + "\n  ".join(
        f"{p}:{n} #{num}" for p, n, num in live
    )


# --- main()'s EXIT CODE, which nothing above asserts (BACKLOG #1235, residual) ---------------------
#
# HOW THE GAP WAS FOUND, because the method transfers: a SET DIFFERENCE over the module's public
# surface, not a grep for something missing. The module defines six top-level names --
# _load_backlog_module, allocation_floor, allocated_numbers, citations_in, unresolved_citations,
# main -- and the suite above exercises four. `main` was the SOLE untouched public entry point.
# That is a positive enumeration on both sides, so it does not depend on anyone's choice of pattern.
#
# WHY IT MATTERS HERE SPECIFICALLY: main()'s last line IS the fail-closed contract --
#     return 1 if (live and not args.advisory) else 0
# -- and it had ZERO coverage. Invert the `not`, or return 0 unconditionally, and every test above
# still passes. This file's own header calls a detector that cannot fail "not a gate"; its exit code
# was in exactly that state.
#
# THE LAST TWO ARMS ARE THE POINT. Both produce HITS and both must exit 0, because the contract keys
# on the LIVE SHAPE rather than on the hit count. Without them, a mutation to `return 1 if hits
# else 0` passes everything -- and that mutation reds the tree today on 26 permanently-harmless
# citations, which is how a gate gets switched off.


def _unissued_above_floor() -> int:
    """A number the allocator CAN still issue -- the only shape that can ever arm."""
    # int() is load-bearing for mypy, not decoration: `cc` is loaded via importlib at runtime, so
    # every attribute on it is Any and the arithmetic silently widens the return type.
    number = int(cc.allocation_floor()) + 100
    assert number < 9000, "citations_in only scans [1000,9000); pick differently"
    return number


def _unissued_below_floor() -> int:
    """A permanent hole: at or below the high-water mark, so never issuable.

    Derived rather than hardcoded. A literal would silently become a RESOLVING number the day it is
    filed, at which point this stops testing the below-floor branch and nothing would say so.
    """
    allocated = cc.allocated_numbers()
    floor = cc.allocation_floor()
    for number in range(1000, floor + 1):
        if number not in allocated:
            return number
    raise AssertionError("no hole below the floor; this arm needs a different construction")


def _doc(tmp_path: pathlib.Path, body: str) -> str:
    path = tmp_path / "doc.md"
    path.write_text(body, encoding="utf-8")
    return str(path)


def test_a_live_shape_citation_makes_main_exit_1(tmp_path: pathlib.Path) -> None:
    """FAIL CLOSED BY DEFAULT. The whole point of the flip from opt-in `--fail`."""
    doc = _doc(tmp_path, f"see #{_unissued_above_floor()} for the rationale\n")
    assert cc.main([doc]) == 1


def test_advisory_reports_the_same_hit_and_exits_0(tmp_path: pathlib.Path) -> None:
    """The documented escape. Untested, an opt-out is indistinguishable from a broken gate."""
    doc = _doc(tmp_path, f"see #{_unissued_above_floor()} for the rationale\n")
    assert cc.main([doc]) == 1  # same corpus, so the arms differ ONLY by the flag
    assert cc.main([doc, "--advisory"]) == 0


def test_a_file_with_no_citation_exits_0(tmp_path: pathlib.Path) -> None:
    assert cc.main([_doc(tmp_path, "no citation here at all\n")]) == 0


def test_a_citation_BELOW_the_floor_is_reported_but_does_not_fail(tmp_path: pathlib.Path) -> None:
    """ASYMMETRIC ARM 1: a hit that must NOT fail. Below the high-water mark the allocator can never
    issue that number, so the citation is permanently harmless -- reported for a human, not a defect.
    """
    doc = _doc(tmp_path, f"see #{_unissued_below_floor()} for the rationale\n")
    assert cc.main([doc]) == 0


def test_a_PR_SHAPED_reference_is_reported_but_does_not_fail(tmp_path: pathlib.Path) -> None:
    """ASYMMETRIC ARM 2, on the other axis: a foreign reference is not a backlog citation at all,
    even when its number is above the floor."""
    doc = _doc(tmp_path, f"shipped in PR #{_unissued_above_floor()}\n")
    assert cc.main([doc]) == 0


# --- BACKLOG #1235: the ANNOTATION must ask the same predicate the EXIT CODE asks ----------------


def test_a_pr_shaped_hit_is_not_narrated_as_the_live_shape(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The third definition of the live-shape rule, and the only one that talks to a human.

    MEASURED at 4c28badd before this fix: six hits printed BOTH
    ``[PR/issue/foreign-repo shaped -- very likely NOT a backlog citation]`` AND
    ``This is the live shape.`` -- two contradictory annotations on the SAME hit, two lines apart --
    while the process exited 0.

    Asserted on the CONTRADICTION rather than on either sentence alone, because either one in
    isolation is correct: the hit IS above the floor, and it IS pr-shaped. Only their co-occurrence
    on one hit is the defect, so only that co-occurrence can pin it.
    """
    doc = tmp_path / "d.md"
    floor = cc.allocation_floor()
    doc.write_text(f"see upstream `someproject#{floor + 500}` for context\n", encoding="utf-8")
    assert cc.main([str(doc)]) == 0, "a pr-shaped hit must not fail the gate"
    out = capsys.readouterr().out
    assert "PR/issue/foreign-repo shaped" in out, "control failed: the hit was not annotated at all"
    assert "This is the live shape." not in out, (
        "the annotation called a pr-shaped hit the live shape while the exit code passed over it "
        "-- a third definition of the rule, disagreeing with the other two (BACKLOG #1235)"
    )


def test_a_genuinely_live_hit_is_still_narrated_as_the_live_shape(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The negative control. Suppressing the sentence everywhere would pass the test above and
    destroy the tool's only human-readable verdict -- a fix that trades a wrong answer for none."""
    doc = tmp_path / "d.md"
    floor = cc.allocation_floor()
    doc.write_text(f"resolves to BACKLOG #{floor + 500} which was never filed\n", encoding="utf-8")
    assert cc.main([str(doc)]) == 1, "a genuinely live citation must fail the gate"
    assert "This is the live shape." in capsys.readouterr().out
