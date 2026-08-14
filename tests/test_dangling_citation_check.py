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
