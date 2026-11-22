# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""``docs/PHI.md``'s *Re-encryption happens on write* bullet against the section 2 inventory
(vault BACKLOG #1174 items 1 and 2).

The bullet said the store cipher re-encrypts "every PHI column", while the bullet after it and the
inventory say the ``state.key`` and ``reference.key`` columns stay plaintext at rest. This reads
the bullet, requires every column it names as plaintext to be an inventory row whose
"Encrypted at rest?" cell says **No**, and refuses the closed claim. A planted copy of the old
sentence is the positive control. It is a text check: it does not run the store.
"""

from __future__ import annotations

import re
from pathlib import Path

_DOC = Path(__file__).resolve().parent.parent / "docs" / "PHI.md"
_LEAD = "- **Re-encryption happens on write.**"
_INVENTORY = "## 2. Where PHI lives"


def _bullet(text: str) -> str:
    lines = text.splitlines()
    start = next(i for i, line in enumerate(lines) if line.startswith(_LEAD))
    end = next(i for i in range(start + 1, len(lines)) if not lines[i].startswith("  "))
    return " ".join(line.strip() for line in lines[start:end])


def _inventory_rows(text: str) -> list[list[str]]:
    lines = text.splitlines()
    start = next(i for i, line in enumerate(lines) if line.startswith(_INVENTORY))
    end = next(i for i in range(start + 1, len(lines)) if lines[i].startswith("## "))
    return [
        [cell.strip() for cell in line.strip().strip("|").split("|")]
        for line in lines[start:end]
        if line.startswith("| `")
    ]


def _problems(text: str) -> list[str]:
    bullet = _bullet(text)
    found: list[str] = []
    if re.search(r"every PHI column", bullet):
        found.append("the bullet claims every PHI column")
    clause = re.search(r"at least (.*?) stay plaintext at rest", bullet)
    if clause is None:
        return [*found, "the bullet names no column that stays plaintext"]
    named = re.findall(r"`([a-z_]+\.[a-z_]+)`", clause.group(1))
    if not named:
        found.append("the plaintext clause names no column")
    rows = _inventory_rows(text)
    for column in named:
        hits = [row for row in rows if f"`{column}`" in row[0]]
        if not hits:
            found.append(f"{column}: no inventory row")
        elif not all(row[3].startswith("**No**") for row in hits):
            found.append(f"{column}: the inventory does not say it stays plaintext")
    return found


def test_the_bullet_matches_the_inventory() -> None:
    assert _problems(_DOC.read_text(encoding="utf-8")) == []


def test_guard_detects_the_old_closed_claim() -> None:
    text = _DOC.read_text(encoding="utf-8")
    planted = text.replace(
        "re-encrypts each column it\n  covers",
        "re-encrypts every PHI column\n  it covers",
        1,
    )
    assert planted != text, "the bullet's wording moved; update the plant"
    assert "the bullet claims every PHI column" in _problems(planted)


def test_guard_detects_a_column_the_inventory_encrypts() -> None:
    text = _DOC.read_text(encoding="utf-8")
    planted = text.replace("`state.key` and `reference.key` columns", "`state.value` column", 1)
    assert planted != text, "the bullet's wording moved; update the plant"
    assert any(p.startswith("state.value:") for p in _problems(planted))
