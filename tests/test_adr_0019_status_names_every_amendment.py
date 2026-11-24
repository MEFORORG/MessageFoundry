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
# Any heading level, and the date anywhere on the heading line after the word Amendment.
_HEADING = re.compile(r"^#+ [^\n]*?\bAmendment\b[^\n]*?(\d{4}-\d{2}-\d{2})", re.MULTILINE)
_DATE = re.compile(r"\b\d{4}-\d{2}-\d{2}\b")
# A link target, such as (#amendment-2026-11-24--corrections-to-the-2026-09-28-...), can carry other
# amendments' dates, so every inline link target is dropped before the dates are read.
_LINK_TARGET = re.compile(r"\]\([^)]*\)")


def _status_block(text: str) -> str:
    head = text.index("- **Status:**")
    return text[head : text.index("Designs the pluggable", head)]


def _missing(text: str) -> set[str]:
    named = set(_DATE.findall(_LINK_TARGET.sub("]", _status_block(text))))
    return set(_HEADING.findall(text)) - named


def test_the_status_header_names_every_amendment_date() -> None:
    text = _ADR_0019.read_text(encoding="utf-8")
    # Positive control: the instrument finds the amendment sections it is meant to check.
    assert {"2026-07-12", "2026-09-28", "2026-10-10", "2026-11-05"} <= set(_HEADING.findall(text))
    assert _missing(text) == set()


def test_the_check_goes_red_when_the_header_drops_a_date() -> None:
    # Negative controls on the real file: drop one date from the prose of the header and the check
    # names it, even though a link target in the header still spells it.
    text = _ADR_0019.read_text(encoding="utf-8")
    block = _status_block(text)
    targets = _LINK_TARGET.findall(block)
    assert any("2026-09-28" in target for target in targets)
    parts = [part.replace("2026-09-28", "on that date") for part in _LINK_TARGET.split(block)]
    dropped = parts[0] + "".join(t + p for t, p in zip(targets, parts[1:], strict=True))
    assert "2026-09-28" in dropped  # only inside a link target now
    assert _missing(text.replace(block, dropped)) == {"2026-09-28"}
    # And a heading at another level, with the date after other words, is still required.
    extra = text + "\n### A later Amendment, dated 2099-01-01\n"
    assert _missing(extra) == {"2099-01-01"}
