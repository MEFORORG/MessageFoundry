# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Refuse a release tag that a verifier cannot rebuild from the wheel (BACKLOG #2534).

The release trigger fires on any ``vX.Y.Z-*`` tag, and the version gate compares the tag with the
built version as PEP 440 versions. So ``v0.5.0-rc.1``, ``v0.5.0-alpha1`` and ``v0.5.0-post1`` would
all release. But a verifier holds only the wheel, which says ``0.5.0rc1``, and must name the tag in
``gh attestation verify --source-ref``. The scaffolded CI gate rebuilds the tag from the wheel, and
that works only when each version has one tag spelling. This script allows exactly two:

* ``vX.Y.Z``, a final release;
* ``vX.Y.Z-aN``, ``vX.Y.Z-bN`` or ``vX.Y.Z-rcN``, a pre-release.

No number may carry a leading zero, because PEP 440 drops it and the wheel could not say it.
``.post`` and ``.dev`` releases have no tag spelling, so they are refused.

``--prefix webconsole-`` checks a web console tag. The console's tag must be the prefix followed by
one of those engine spellings, because the console is released at the engine's version and never
as a ``.postN`` (docs/WEBCONSOLE-PACKAGE.md). A tag without the prefix is refused, so an engine tag
cannot pass the console's check.

Usage: ``python scripts/release/tag_spelling.py [--prefix <prefix>] "$GITHUB_REF_NAME"``.
"""

from __future__ import annotations

import re
import sys
from collections.abc import Sequence

_NUMBER = r"(?:0|[1-9][0-9]*)"

#: The only engine tag spellings a release may carry.
TAG = re.compile(rf"v{_NUMBER}\.{_NUMBER}\.{_NUMBER}(?:-(?:a|b|rc){_NUMBER})?")

_SHAPE = "vX.Y.Z or vX.Y.Z-(a|b|rc)N"


def allowed(tag: str, prefix: str = "") -> bool:
    """Whether ``tag`` is ``prefix`` followed by the one spelling a verifier can rebuild."""
    return tag.startswith(prefix) and TAG.fullmatch(tag[len(prefix) :]) is not None


def main(argv: Sequence[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    prefix = ""
    if len(args) == 3 and args[0] == "--prefix" and args[1]:
        prefix, args = args[1], args[2:]
    if len(args) != 1:
        print("usage: tag_spelling.py [--prefix <prefix>] <tag>", file=sys.stderr)
        return 2
    tag = args[0]
    shape = " or ".join(f"{prefix}{s}" for s in _SHAPE.split(" or "))
    if allowed(tag, prefix):
        print(f"tag {tag} is spelled {shape}")
        return 0
    why = (
        "The console ships at the version of the engine release it pairs with, so its tag is "
        f"{prefix!r} followed by that engine tag's spelling."
        if prefix
        else "A verifier rebuilds the tag from the wheel's version for --source-ref, so any other "
        "spelling would release a wheel nobody can verify."
    )
    print(
        f"::error::tag {tag!r} is not spelled {shape} with no leading zeros. {why} Delete the "
        "tag and push one spelled that way (BACKLOG #2534)."
    )
    return 1


if __name__ == "__main__":
    sys.exit(main())
