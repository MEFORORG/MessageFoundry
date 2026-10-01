# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Refuse an engine release tag that a verifier cannot rebuild from the wheel (BACKLOG #2534).

The release trigger fires on any ``vX.Y.Z-*`` tag, and the version gate compares the tag with the
built version as PEP 440 versions. So ``v0.5.0-rc.1``, ``v0.5.0-alpha1`` and ``v0.5.0-post1`` would
all release. But a verifier holds only the wheel, which says ``0.5.0rc1``, and must name the tag in
``gh attestation verify --source-ref``. The scaffolded CI gate rebuilds the tag from the wheel, and
that works only when each version has one tag spelling. This script allows exactly two:

* ``vX.Y.Z``, a final release;
* ``vX.Y.Z-aN``, ``vX.Y.Z-bN`` or ``vX.Y.Z-rcN``, a pre-release.

No number may carry a leading zero, because PEP 440 drops it and the wheel could not say it.
``.post`` and ``.dev`` releases have no tag spelling, so they are refused.

Usage: ``python scripts/release/tag_spelling.py "$GITHUB_REF_NAME"``.
"""

from __future__ import annotations

import re
import sys
from collections.abc import Sequence

_NUMBER = r"(?:0|[1-9][0-9]*)"

#: The only engine tag spellings a release may carry.
TAG = re.compile(rf"v{_NUMBER}\.{_NUMBER}\.{_NUMBER}(?:-(?:a|b|rc){_NUMBER})?")


def allowed(tag: str) -> bool:
    """Whether ``tag`` is spelled the one way a verifier can rebuild from its wheel."""
    return TAG.fullmatch(tag) is not None


def main(argv: Sequence[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if len(args) != 1:
        print("usage: tag_spelling.py <tag>", file=sys.stderr)
        return 2
    tag = args[0]
    if allowed(tag):
        print(f"tag {tag} is spelled vX.Y.Z or vX.Y.Z-(a|b|rc)N")
        return 0
    print(
        f"::error::tag {tag!r} is not spelled vX.Y.Z or vX.Y.Z-(a|b|rc)N with no leading zeros. "
        "A verifier rebuilds the tag from the wheel's version for --source-ref, so any other "
        "spelling would release a wheel nobody can verify. Delete the tag and push one spelled "
        "that way (BACKLOG #2534)."
    )
    return 1


if __name__ == "__main__":
    sys.exit(main())
