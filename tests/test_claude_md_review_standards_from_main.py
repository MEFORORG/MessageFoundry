# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""CLAUDE.md's example code-review argument reads docs/REVIEW-STANDARDS.md from origin/main.

A Builder copies that example into the code-review skill's arguments. Read from the worktree, the
standard is the branch's own copy, so a branch that edits REVIEW-STANDARDS.md would be reviewed
against its own edit. korus roles/BUILDER.md 4c states the reason; this test pins only that the
example gives the INSTRUCTION, fetch included, and not a mere mention of the ref.
"""

from __future__ import annotations

import re
from pathlib import Path

CLAUDE_MD = Path(__file__).resolve().parents[1] / "CLAUDE.md"

# The instruction sentence the example must carry, verbatim, ending the argument.
_INSTRUCTION = re.compile(
    r"; read docs/REVIEW-STANDARDS\.md as it stands at origin/main "
    r"\(run git fetch origin main, then git show origin/main:docs/REVIEW-STANDARDS\.md\) "
    r"and apply its rules\.$"
)

# The instruction text as it stood before this rule: the worktree copy, with no ref named.
_OLD_EXAMPLE = (
    "xhigh round-<hex> Review this branch's diff against origin/main; "
    "read docs/REVIEW-STANDARDS.md and apply its rules."
)
# A mention of the ref that does not tell the skill to read the standard there.
_MENTION_ONLY = (
    "xhigh round-<hex> Review this branch's diff against origin/main; "
    "read docs/REVIEW-STANDARDS.md and apply its rules. See origin/main:docs/REVIEW-STANDARDS.md."
)
# The ref instruction with no fetch, so a stale origin/main would be read.
_NO_FETCH = (
    "xhigh round-<hex> Review this branch's diff against origin/main; "
    "read docs/REVIEW-STANDARDS.md as it stands at origin/main "
    "(git show origin/main:docs/REVIEW-STANDARDS.md) and apply its rules."
)
# A bare fetch updates every remote-tracking ref, which disarms a later --force-with-lease.
_BARE_FETCH = (
    "xhigh round-<hex> Review this branch's diff against origin/main; "
    "read docs/REVIEW-STANDARDS.md as it stands at origin/main "
    "(run git fetch origin, then git show origin/main:docs/REVIEW-STANDARDS.md) and apply its rules."
)


def _example_arguments(text: str) -> list[str]:
    """Every backticked code-review argument example: a level first, then a prompt naming the file."""
    return re.findall(
        r"`((?:low|medium|high|xhigh|max|ultra) [^`]*REVIEW-STANDARDS\.md[^`]*)`", text
    )


def _reads_standard_from_main(argument: str) -> bool:
    return _INSTRUCTION.search(argument) is not None


def test_the_example_reads_the_standard_from_origin_main() -> None:
    examples = _example_arguments(CLAUDE_MD.read_text(encoding="utf-8"))
    assert examples, "CLAUDE.md lost its code-review argument example; this test reads nothing"
    for example in examples:
        assert _reads_standard_from_main(example), example


def test_the_check_rejects_the_worktree_copy_a_mention_and_a_missing_or_bare_fetch() -> None:
    """Positive controls: each wrong form must be found as an example and then fail the check."""
    other_level = "high Review this diff; read docs/REVIEW-STANDARDS.md and apply its rules."
    for wrong in (_OLD_EXAMPLE, _MENTION_ONLY, _NO_FETCH, _BARE_FETCH, other_level):
        examples = _example_arguments(f"`{wrong}`")
        assert examples == [wrong]
        assert not _reads_standard_from_main(examples[0]), wrong
