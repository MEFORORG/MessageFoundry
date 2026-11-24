# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""ADR 0019's Status header names the date of every amendment section below it (vault BACKLOG #1173
item 6).

The header named the 2026-07-12 and 2026-11-05 amendments and none of the six between them, so a
reader of the header alone missed them. This checks dates only, outside link targets: it does not
prove the header describes each amendment correctly, or names each of two amendments of one date.
"""

from __future__ import annotations

import re
from pathlib import Path

_ADR_0019 = (
    Path(__file__).resolve().parent.parent
    / "docs"
    / "adr"
    / "0019-pluggable-keyprovider-hsm-kms-vault.md"
)
_HEADING = re.compile(r"^## Amendment (\d{4}-\d{2}-\d{2})\b", re.MULTILINE)
_DATE = re.compile(r"\b\d{4}-\d{2}-\d{2}\b")
# A link target such as (#amendment-2026-11-24--corrections-to-the-2026-09-28-...) carries other
# amendments' dates, so it is dropped before the dates are read.
_LINK_TARGET = re.compile(r"\(#[^)]*\)")


def _status_block(text: str) -> str:
    head = text.index("- **Status:**")
    return _LINK_TARGET.sub("", text[head : text.index("Designs the pluggable", head)])


def test_the_status_header_names_every_amendment_date() -> None:
    text = _ADR_0019.read_text(encoding="utf-8")
    headings = set(_HEADING.findall(text))
    # Positive control: the instrument finds the amendment sections it is meant to check.
    assert {"2026-07-12", "2026-09-28", "2026-10-10", "2026-11-05"} <= headings, headings
    named = set(_DATE.findall(_status_block(text)))
    assert headings - named == set(), sorted(headings - named)


def test_the_status_block_reader_stops_before_the_body() -> None:
    # Negative controls: the block must not reach the amendment headings themselves, or every date
    # would match trivially, and no link target may survive to lend its dates.
    block = _status_block(_ADR_0019.read_text(encoding="utf-8"))
    assert "## Amendment" not in block
    assert "## Context" not in block
    assert "(#amendment-" not in block
