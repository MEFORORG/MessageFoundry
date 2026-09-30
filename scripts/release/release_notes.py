#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Cut a release-notes file down to a size GitHub will accept, in place.

WHY THIS EXISTS. The release jobs in ``.github/workflows/release.yml`` feed one CHANGELOG section to
``gh release create --notes-file`` and ``gh release edit --notes-file``. GitHub refuses a release
body longer than 125,000 characters, with ``body is too long (maximum is 125000 characters)``. The
engine's 0.5.0 section is about 233,000 characters, so the release step would fail on the tag. That
step sits BEFORE the PyPI publish, so a refusal there also stops the publish.

WHAT IT DOES. A file at or under ``--limit`` characters is left byte for byte as it was. A longer
file keeps its opening lines, whole, and ends with a line that links the full section, so the body
comes out at or under the limit. Characters are counted one per code point. The default limit sits
5,000 under GitHub's figure, which covers any difference in how GitHub counts them.

Source for the figure: the REST "create a release" page states no limit. The limit is the API's
own 422 message, as reported in cli/cli issue 7815.
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path

#: GitHub's own ceiling is 125,000. This leaves room for the footer and for any difference in how
#: GitHub counts a character.
DEFAULT_LIMIT = 120_000


def footer(full_url: str) -> str:
    """The closing lines of a cut body. ASCII only, so its length is the same however it is counted."""
    return (
        "\n\n---\n\n"
        "These notes are cut short to fit GitHub's limit on a release body. "
        f"The full section is in [CHANGELOG.md]({full_url}).\n"
    )


def bound(text: str, full_url: str, limit: int = DEFAULT_LIMIT) -> str:
    """``text`` unchanged if it fits in ``limit`` characters, else its start plus a link to the rest.

    The start is cut at a line end, so no entry is split mid-line. If not even the first line fits,
    it is cut at a character instead, since a body must still come out.
    """
    if len(text) <= limit:
        return text
    tail = footer(full_url)
    budget = limit - len(tail)
    if budget <= 0:
        raise ValueError(f"limit {limit} leaves no room for the {len(tail)}-character footer")
    head = text[:budget]
    cut = head.rfind("\n")
    if cut > 0:
        head = head[:cut]
    return head.rstrip() + tail


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0] if __doc__ else None)
    parser.add_argument("notes", type=Path, help="the release-notes file, rewritten in place")
    parser.add_argument(
        "--full-url", required=True, help="where the full section lives, linked from a cut body"
    )
    parser.add_argument("--limit", type=int, default=DEFAULT_LIMIT, help="maximum characters")
    args = parser.parse_args(argv)

    # newline="" on both sides, so a file that fits is written back exactly as it was read.
    text = args.notes.read_text(encoding="utf-8", newline="")
    out = bound(text, args.full_url, args.limit)
    if out is text:
        print(f"release notes: {len(text)} characters, within {args.limit}; unchanged")
        return 0
    args.notes.write_text(out, encoding="utf-8", newline="")
    print(
        f"release notes: {len(text)} characters is over {args.limit}; cut to {len(out)}, "
        f"linking {args.full_url}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
