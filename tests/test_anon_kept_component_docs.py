# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The prose that names the CX components an identifier surrogate keeps matches the constant
(vault BACKLOG #5533 items 11 and 23).

The kept positions are stated in ``surrogates._CX_KEPT_COMPONENTS`` and restated in prose in at
least ``docs/PHI.md`` section 9 and the ADR 0030 amendment. A changelog fragment is not read
here: the release fold deletes it. A change to the constant that left the prose behind would
leave a reader told that a component is blanked when it is kept, or kept when it is blanked. This pins each restatement found here to the constant; it
does not prove there are no others.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from messagefoundry_toolkit.anon import surrogates as engine_surrogates
from tee.anon import surrogates as tee_surrogates

_REPO = Path(__file__).resolve().parents[1]
#: "CX.3 to CX.6, CX.9 and CX.10": a range, then single positions, the last after "and".
_KEPT_PHRASE = re.compile(r"CX\.(\d+) to CX\.(\d+)((?:, CX\.\d+)*) and CX\.(\d+)")
#: Where the kept CX positions are restated in prose.
_SITES = (
    "docs/PHI.md",
    "docs/adr/0030-anonymization-test-harness-tee.md",
)


def _stated(text: str) -> list[frozenset[int]]:
    """Each set of CX positions a kept-components phrase in ``text`` names, joined across lines."""
    flat = " ".join(text.split())
    sets: list[frozenset[int]] = []
    for match in _KEPT_PHRASE.finditer(flat):
        low, high, singles, last = match.groups()
        positions = set(range(int(low), int(high) + 1))
        positions.update(int(n) for n in re.findall(r"\d+", singles))
        positions.add(int(last))
        sets.append(frozenset(positions))
    return sets


@pytest.mark.parametrize("relative", _SITES)
def test_each_restatement_names_the_kept_positions(relative: str) -> None:
    stated = _stated((_REPO / relative).read_text(encoding="utf-8"))
    # A positive floor: the site is read and still states the positions.
    assert stated, f"{relative} no longer states the kept CX positions"
    for positions in stated:
        assert positions == engine_surrogates._CX_KEPT_COMPONENTS, relative


def test_the_constant_is_the_same_in_both_copies() -> None:
    assert engine_surrogates._CX_KEPT_COMPONENTS == tee_surrogates._CX_KEPT_COMPONENTS
    assert engine_surrogates._DLN_KEPT_COMPONENTS == tee_surrogates._DLN_KEPT_COMPONENTS


def test_the_constant_comment_names_the_kept_positions() -> None:
    """The comment above the constant names each kept position before it says what is blanked."""
    source = (_REPO / "messagefoundry_toolkit/anon/surrogates.py").read_text(encoding="utf-8")
    comment = source.split("#: The 1-based CX components an identifier surrogate keeps", 1)[1]
    kept_sentence = comment.split("Every other component past the first is blanked", 1)[0]
    named = {int(n) for n in re.findall(r"CX\.(\d+)", kept_sentence)}
    assert named == engine_surrogates._CX_KEPT_COMPONENTS


def test_the_phrase_parser_reads_a_wrapped_phrase() -> None:
    """The control: the parser joins a phrase a line break splits, and reads every position."""
    assert _stated("keep CX.3 to\n  CX.6, CX.9 and CX.10, the") == [frozenset({3, 4, 5, 6, 9, 10})]
    assert _stated("CX.2 to CX.3 and CX.7") == [frozenset({2, 3, 7})]
