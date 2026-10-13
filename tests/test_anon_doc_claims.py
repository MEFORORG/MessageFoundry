# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Prose about the anonymizer must not promise more than the anonymizer does (BACKLOG #2996).

Live sites said its output was free of PHI, that ``tee/anon/`` was one byte-identical copy, and
that its loaders walk up the tree to find ``scripts/security/``. None of the three is true.
``docs/PHI.md`` section 9 is the one statement of what the leak-check refuses and what it lets
through, and ``tests/test_anon_parity.py`` is the record of which files are byte-identical.

This guard matches each retired PHRASE at the site that carried it. It does not ban the bare token
"PHI-free", which the same files use correctly, for example to say a clean result does not prove
the output is PHI-free. ``tests/test_feature_map_claims.py`` holds the two index rows the same way.

Each site also carries a positive floor: the file must be read, and the corrected wording must be
there. A scan that read nothing therefore cannot pass.

It does not read the anonymizer's code, so it says nothing about what the loaders do.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

_REPO = Path(__file__).resolve().parents[1]
_PHI_SECTION = "PHI.md#9-de-identification"

# A retired phrase can come back wrapped across lines, inside emphasis, or behind a comment leader.
# The first docs/AI.md site broke between "**test" and "datasets**". So match on flattened text.
_LEADER = re.compile(r"^[ \t]*(?:#+|>)?[ \t]*", re.MULTILINE)


def _flat(text: str) -> str:
    """One case-folded line: comment and quote leaders, emphasis and code marks dropped."""
    text = _LEADER.sub("", text)
    text = text.replace("*", "").replace("`", "")
    return " ".join(text.split()).casefold()


def _read(relative: str) -> str:
    path = _REPO / relative
    assert path.is_file(), f"{relative} is missing, so this guard would scan nothing"
    flat = _flat(path.read_text(encoding="utf-8"))
    assert flat, f"{relative} is empty, so this guard would scan nothing"
    return flat


# (file, retired phrases, corrected wording, how many times the corrected wording must appear).
_SITES = (
    pytest.param(
        "docs/AI.md",
        ("PHI-free test datasets",),
        "de-identified test datasets",
        2,
        id="ai-doc",
    ),
    pytest.param(
        "messagefoundry/config/ai_policy.py",
        ("PHI-free test datasets",),
        "not guaranteed free of PHI",
        1,
        id="ai-policy-docstring",
    ),
    pytest.param(
        "harness/load/corpus.py",
        ("PHI-free corpus",),
        "de-identified corpus",
        1,
        id="load-corpus-docstring",
    ),
    pytest.param(
        "docs/USER-GUIDE.md",
        ("without ever handling PHI",),
        "not guaranteed free of PHI",
        1,
        id="user-guide",
    ),
    pytest.param(
        "tests/test_anon_parity.py",
        (
            "scripts/ above it",
            "scripts/security above it",
            "scripts/ tree above it",
            "not found above this tree",
        ),
        "scripts/security beside the package",
        2,
        id="parity-test-comments",
    ),
    # The module docstring of messagefoundry/anon/__init__.py made the blanket claim. Only some
    # files under tee/anon/ are byte-identical copies, and the docstring now points at the parity
    # test, which names them.
    pytest.param(
        "messagefoundry/anon/__init__.py",
        ("a byte-identical tee/anon/",),
        "tests/test_anon_parity.py names which",
        1,
        id="anon-package-docstring",
    ),
)


@pytest.mark.parametrize(("relative", "retired", "corrected", "floor"), _SITES)
def test_no_site_makes_a_retired_claim_about_the_anonymizer(
    relative: str, retired: tuple[str, ...], corrected: str, floor: int
) -> None:
    flat = _read(relative)
    assert retired, f"{relative}: no retired phrase is listed, so nothing would be checked"
    for phrase in retired:
        assert _flat(phrase) not in flat, (
            f"{relative} says {phrase!r} again (BACKLOG #2996). Say what the anonymizer does, "
            "and link docs/PHI.md section 9 for what its leak-check refuses and lets through."
        )
    count = flat.count(_flat(corrected))
    assert count >= floor, (
        f"{relative}: expected the corrected wording {corrected!r} at least {floor} time(s), "
        f"found {count}. If the sentence was reworded, update this guard in the same change."
    )


@pytest.mark.parametrize("relative", ["docs/AI.md", "docs/USER-GUIDE.md"])
def test_the_operator_docs_link_the_one_statement_of_the_limits(relative: str) -> None:
    # The link is the correction: these pages say "de-identified" and leave the limits to PHI.md.
    assert _PHI_SECTION.casefold() in _read(relative), (
        f"{relative} must link {_PHI_SECTION} where it describes the anonymizer's output."
    )


def test_adr_0201_carries_the_correction_under_its_dated_sentence() -> None:
    # An ADR body is a dated record, so the old sentence stays and a dated note corrects it.
    found = sorted((_REPO / "docs" / "adr").glob("0201-*.md"))
    assert len(found) == 1, f"expected one ADR 0201 file, found {len(found)}"
    flat = _read(found[0].relative_to(_REPO).as_posix())
    dated = flat.find(_flat("by walking up from `__file__`"))
    assert dated != -1, "ADR 0201 no longer holds the dated sentence this guard anchors on"
    note = flat.find(_flat("Corrected 2026-10-12 (BACKLOG #2996)"))
    assert note > dated, (
        "ADR 0201 says the anonymizer's loaders walk up from __file__, with no dated correction "
        "after it. Neither loader walks: each builds one fixed path (BACKLOG #2996)."
    )
    # Read the note itself, not the rest of the ADR: a later section could hold the same words.
    assert _flat("one fixed path") in flat[note : note + 400], (
        "the correction must say what the loaders do"
    )


def test_the_flattening_joins_what_a_wrapped_phrase_splits() -> None:
    # The control: each of these is a retired phrase in a shape a plain substring search misses.
    markdown = "exists to build PHI-free **test\n   datasets**; it does not"
    assert "PHI-free test datasets" not in markdown
    assert _flat("PHI-free test datasets") in _flat(markdown)
    comment = "    # an installed wheel with no scripts/\n    # above it) the token tables"
    assert _flat("scripts/ above it") in _flat(comment)
    quoted = "> find `scripts/security/` by walking up from\n> `__file__`, and from"
    assert _flat("by walking up from `__file__`") in _flat(quoted)
    # And it must not invent a match: the correct use of the bare token stays clean.
    assert _flat("PHI-free test datasets") not in _flat("not proof the output is PHI-free.")
