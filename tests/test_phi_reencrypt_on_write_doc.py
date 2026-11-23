# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""``docs/PHI.md``'s *Re-encryption happens on write* bullet against the section 2 inventory
(vault BACKLOG #1174 items 1 and 2).

The bullet said the store cipher re-encrypts "every PHI column", while the inventory lists columns
that can hold PHI and stay plaintext at rest, ``state.key`` and ``reference.key`` among them. The
bullet now says not every such column is covered and points at the inventory for which. This
checks that sentence against the inventory: it must hold at least one row whose PHI cell is
**Yes** or **Possibly** and whose "Encrypted at rest?" cell is **No**. Planted copies are the
positive controls. It is a text check: it does not run the store.
"""

from __future__ import annotations

import functools
from pathlib import Path

import pytest

_DOC = Path(__file__).resolve().parent.parent / "docs" / "PHI.md"
_LEAD = "- **Re-encryption happens on write.**"
_INVENTORY = "## 2. Where PHI lives"
_LINK = "(#2-where-phi-lives--data-at-rest-inventory)"
_CLOSED = ("every PHI column", "re-encrypts every")


def _bullet(text: str) -> str:
    lines = text.splitlines()
    start = next(i for i, line in enumerate(lines) if line.startswith(_LEAD))
    end = next(i for i in range(start + 1, len(lines)) if not lines[i].startswith("  "))
    return " ".join(line.strip() for line in lines[start:end])


@functools.cache
def _doc() -> str:
    return _DOC.read_text(encoding="utf-8")


def _inventory_rows(text: str) -> list[list[str]]:
    """The rows of section 2's at-rest inventory table, whose header opens with the four columns
    read here, and no other table's. A moved header stops the test rather than passing it."""
    lines = text.splitlines()
    start = next(i for i, line in enumerate(lines) if line.startswith(_INVENTORY))
    head = next(
        i
        for i in range(start + 1, len(lines))
        if lines[i].startswith("| Location | Backends | Holds PHI? | Encrypted at rest?")
    )
    end = next(i for i in range(head, len(lines)) if not lines[i].startswith("|"))
    return [
        [cell.strip() for cell in line.strip().strip("|").split("|")]
        for line in lines[head + 2 : end]
        if line.startswith("| `")
    ]


def _problems(text: str) -> list[str]:
    bullet = _bullet(text)
    found = [f"closed claim: {phrase!r}" for phrase in _CLOSED if phrase in bullet]
    if "Not every column that can hold PHI is covered" not in bullet:
        found.append("the bullet does not say some PHI columns are uncovered")
    if _LINK not in bullet:
        found.append("the bullet does not point at the inventory")
    plaintext_phi = [
        row[0]
        for row in _inventory_rows(text)
        if len(row) > 3
        and row[2].startswith(("**Yes**", "**Possibly**"))
        and row[3].startswith("**No**")
    ]
    if not plaintext_phi:
        found.append("the inventory lists no PHI-capable column left plaintext")
    return found


def test_the_bullet_matches_the_inventory() -> None:
    assert _problems(_doc()) == []


@pytest.mark.parametrize("phrase", _CLOSED)
def test_guard_detects_a_closed_claim(phrase: str) -> None:
    text = _doc()
    planted = text.replace("re-encrypts each column it", f"{phrase} column it", 1)
    assert planted != text, "the bullet's wording moved; update the plant"
    assert f"closed claim: {phrase!r}" in _problems(planted)


def test_guard_detects_a_dropped_pointer() -> None:
    text = _doc()
    bullet_start = text.index(_LEAD)
    link_at = text.index(_LINK, bullet_start)
    planted = text[:link_at] + "(#nowhere)" + text[link_at + len(_LINK) :]
    assert "the bullet does not point at the inventory" in _problems(planted)


def test_guard_detects_a_dropped_uncovered_sentence() -> None:
    text = _doc()
    planted = text.replace("Not every column that can hold PHI is covered", "All covered", 1)
    assert planted != text, "the bullet's wording moved; update the plant"
    assert "the bullet does not say some PHI columns are uncovered" in _problems(planted)


def test_guard_detects_an_inventory_with_no_plaintext_phi_column() -> None:
    text = _doc()
    planted = "\n".join(
        line.replace("| **No**", "| **Yes**") if line.startswith("| `") else line
        for line in text.splitlines()
    )
    assert planted != text
    assert "the inventory lists no PHI-capable column left plaintext" in _problems(planted)
