# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""CLAUDE.md's example code-review argument reads docs/REVIEW-STANDARDS.md from origin/main.

A Builder copies that example into the code-review skill's arguments. Read from the worktree, the
standard is the branch's own copy, so a branch that edits REVIEW-STANDARDS.md would be reviewed
against its own edit: the change could rewrite its own judge. Reading it at origin/main closes that.
"""

from __future__ import annotations

import re
from pathlib import Path

CLAUDE_MD = Path(__file__).resolve().parents[1] / "CLAUDE.md"

# The instruction text as it stood before this rule: the worktree copy, with no ref named.
_OLD_EXAMPLE = (
    "xhigh round-<hex> Review this branch's diff against origin/main; "
    "read docs/REVIEW-STANDARDS.md and apply its rules."
)


def _example_arguments(text: str) -> list[str]:
    """Every backticked code-review argument example: a level, a round nonce, then the prompt."""
    return re.findall(r"`(xhigh round-<hex> [^`]*REVIEW-STANDARDS\.md[^`]*)`", text)


def _reads_standard_from_main(argument: str) -> bool:
    return "origin/main:docs/REVIEW-STANDARDS.md" in argument


def test_the_example_reads_the_standard_from_origin_main() -> None:
    examples = _example_arguments(CLAUDE_MD.read_text(encoding="utf-8"))
    assert examples, "CLAUDE.md lost its code-review argument example; this test reads nothing"
    for example in examples:
        assert _reads_standard_from_main(example), example


def test_the_check_rejects_the_worktree_copy() -> None:
    """Positive control: the pre-rule example, which names no ref, must fail the check."""
    examples = _example_arguments(f"`{_OLD_EXAMPLE}`")
    assert examples == [_OLD_EXAMPLE]
    assert not _reads_standard_from_main(examples[0])
