# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Read and plant into one blockquote of ``docs/SECURITY.md``, located by its bold open.

Shared by the doc-drift tests that bind a blockquote to an executed measurement
(``tests/test_monitoring_scope_doc_drift.py``, ``tests/test_single_route_data_rules_doc_drift.py``),
so a lesson learned about locating or planting fixes both at once.
"""

from __future__ import annotations

import re
from itertools import takewhile


def blockquote_lines(text: str, marker: str) -> list[str]:
    """The RAW lines of the blockquote: from the line carrying ``marker`` to the first line that is
    not part of a blockquote.

    Pin ``marker`` to the claim's NAME and its bold open, never to the punctuation after it: a
    locator that ended at ``).**`` once broke on a doc edit that appended to the same heading, and
    silently took every check built on it along."""
    lines = text.splitlines()
    start = next((i for i, line in enumerate(lines) if marker in line), None)
    assert start is not None, f"docs/SECURITY.md no longer contains {marker!r}"
    return list(takewhile(lambda line: line.startswith(">"), lines[start:]))


def unwrap(lines: list[str]) -> str:
    """Blockquote lines as one string, so a claim split across a line break reads as one."""
    return " ".join(line.lstrip("> ").rstrip() for line in lines)


def route_tokens(s: str) -> set[str]:
    """Backticked ``METHOD /path`` tokens, matched EXACTLY. A substring test would read
    ``GET /metrics`` out of ``GET /metrics/history`` and grade the wrong sentence."""
    return set(re.findall(r"`([A-Z]+ /[^`]*)`", s))


def plant_in_blockquote(text: str, marker: str, old: str, new: str) -> str:
    """Substitute INSIDE the blockquote only.

    A whole-document ``replace`` graded the wrong thing once: route tokens are backticked elsewhere
    in ``docs/SECURITY.md`` too, so the mutation landed in another section and the planted-omission
    test passed without touching the block under grade."""
    block = "\n".join(blockquote_lines(text, marker))
    assert old in block, f"the blockquote does not contain {old!r}"
    return text.replace(block, block.replace(old, new, 1), 1)
