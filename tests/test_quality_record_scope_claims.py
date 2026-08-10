# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""The quality record's claims about its own instruments must stay true (BACKLOG #1092, #1033).

``docs/Code_Quality_Standards.md`` scores signals as "machine-checked"/"enforced". Section 4.0
rule 4 requires each such claim to name its instrument and that instrument's **measured** scope.
A scope sentence nothing checks is exactly the defect #1092 filed: prose that was accurate when
written and silently stopped being so.

These are drift guards, deliberately narrow. They do not re-derive a scope -- the boundary gate's
own ``_ENGINE_PACKAGES`` is imported as the single source of truth, so widening that tuple fails
here until Appendix A.5 is updated in the same change.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from tests.test_dependency_boundaries import _ENGINE_PACKAGES

_DOC = Path(__file__).resolve().parents[1] / "docs" / "Code_Quality_Standards.md"


@pytest.fixture(scope="module")
def doc() -> str:
    return _DOC.read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def signal_1_scope(doc: str) -> str:
    """Just signal 1's own scope block in A.5.

    Deliberately NOT the whole register: `harness/` and friends are named in several rows, so a
    whole-appendix substring search stays green when signal 1's row alone drops them. A red-first
    pass caught exactly that -- the first version of this guard could not fail.
    """
    assert "### A.5 Instrument scope register" in doc, "Appendix A.5 (the scope register) is gone"
    start = doc.index('**Signal 1 — "import/layer rules are machine-checked in CI"')
    return doc[start : doc.index("| Other claims |", start)]


def test_appendix_a5_names_the_boundary_gate_and_its_every_engine_package(
    signal_1_scope: str,
) -> None:
    """A.5 must name the instrument AND list every package it actually scans.

    The package list is read from the IN-SCOPE bullet alone. Searching the whole signal 1 block
    would stay green when a package is dropped from the in-scope list but still mentioned in the
    prose below it -- `parsing/` is named there, and a red-first pass proved that exact escape.
    """
    assert "tests/test_dependency_boundaries.py" in signal_1_scope, (
        "A.5 must NAME signal 1's instrument -- section 4.0 rule 4"
    )
    marker = "**In scope, mutation-verified red:**"
    assert marker in signal_1_scope, "A.5's signal 1 in-scope bullet is gone"
    in_scope = signal_1_scope[
        signal_1_scope.index(marker) : signal_1_scope.index("- **Out of scope")
    ]
    missing = [p for p in _ENGINE_PACKAGES if f"`{p}/`" not in in_scope]
    assert not missing, (
        f"tests/test_dependency_boundaries.py scans {list(_ENGINE_PACKAGES)}, but Appendix A.5's "
        f"signal 1 in-scope bullet does not list {missing}. Widening the gate's scope without "
        "updating the record is the drift BACKLOG #1092 filed -- update A.5 in this same change."
    )


def test_the_trees_the_boundary_gate_cannot_see_are_still_named_as_out_of_scope(
    signal_1_scope: str,
) -> None:
    """The record must keep saying where the gate is blind; that is the correction #1092 asked for."""
    for tree in ("harness/", "tee/", "scripts/"):
        assert f"`{tree}`" in signal_1_scope, (
            f"A.5's signal 1 block no longer records that the boundary gate does not open {tree} "
            "-- an unqualified 'machine-checked in CI' overclaims again"
        )


# --- BACKLOG #1033: short `#N` must not creep back in ---------------------------------------------

#: One or two digits, optionally backslash-escaped, not part of a longer number. NO lookbehind:
#: excluding a preceding word character makes the pattern blind to the `...Standards.md#3-` anchor
#: fragment, which is the one token that must be present. That blindness is why this carries a
#: self-test rather than a bare count -- an earlier hand-rolled attempt reported zero on a file that
#: demonstrably contained matches.
_SHORT_HASH = re.compile(r"(\\?)#([0-9]{1,2})(?![0-9])")

#: The markdown ANCHOR FRAGMENT, which is a link target and not a citation. Left alone deliberately.
_ANCHOR = "Secure_AI_Development_Standards.md#3-the-problem-this-standard-attacks"


def test_the_short_hash_pattern_fires_on_bare_and_escaped_shapes() -> None:
    """Guards the guard: the assertion below is worthless if the pattern cannot see both shapes."""
    assert [m.group(0) for m in _SHORT_HASH.finditer(r"(#7, \#8, \#11)")] == ["#7", r"\#8", r"\#11"]
    assert [m.group(0) for m in _SHORT_HASH.finditer("PR #1028 and PR \\#1047")] == []
    assert [m.group(0) for m in _SHORT_HASH.finditer(f"see {_ANCHOR}")] == ["#3"]


def test_rubric_signals_are_cited_as_signal_n_not_as_bare_hash_n(doc: str) -> None:
    """In this corpus a short `#N` reads as a backlog item; six such numbers are real items."""
    stray = [
        (n, m.group(0), line.strip())
        for n, line in enumerate(doc.splitlines(), 1)
        for m in _SHORT_HASH.finditer(line)
        if _ANCHOR not in line
    ]
    assert not stray, (
        "short `#N` citations reappeared in the quality record -- use the `signal N` form "
        f"(BACKLOG #1033): {stray}"
    )


def test_the_anchor_fragment_survived_the_signal_n_conversion(doc: str) -> None:
    """The one short `#N` that must stay: converting it silently breaks the link."""
    assert _ANCHOR in doc, "the §3 anchor fragment was rewritten -- that breaks the link silently"
