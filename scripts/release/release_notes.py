#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Shrink a release-notes file to a size GitHub will accept, in place.

WHY THIS EXISTS. The release jobs in ``.github/workflows/release.yml`` feed one CHANGELOG section to
``gh release create --notes-file`` and ``gh release edit --notes-file``. GitHub refuses a release
body longer than 125,000 characters, with ``body is too long (maximum is 125000 characters)``. The
engine's 0.5.0 section is about 256,000 characters, so the release step would fail on the tag. That
step sits BEFORE the PyPI publish, so a refusal there also stops the publish.

WHAT IT DOES. A file at or under ``--limit`` characters is left byte for byte as it was. A longer
one is reduced to its HEADLINES: every heading, and the bold title of every top-level entry with
its body dropped. Cutting the text at the limit instead kept only the first half of the 0.5.0
section, which dropped both Security blocks and most of the BREAKING entries. If the headlines
still do not fit, they are cut at a line end. Either way the body ends with a link to the full
section, and comes out at or under the limit.

Characters are counted one per code point. The default limit sits 5,000 under GitHub's figure,
which covers any difference in how GitHub counts them. Source for the figure: the REST "create a
release" page states no limit; the limit is the API's own 422 message, reported in cli/cli issue
7815.
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path

#: GitHub's own ceiling is 125,000. This leaves room for any difference in how GitHub counts a
#: character.
DEFAULT_LIMIT = 120_000

#: A bold entry title that wraps is followed to its closing ``**`` for at most this many lines, so
#: an entry whose title never closes costs a few lines rather than its whole body.
_TITLE_LINES = 4


def footer(full_url: str, *, cut: bool) -> str:
    """The closing lines of a shrunk body. ASCII only, so its length is the same however counted.

    ``cut`` says the titles themselves were cut short, because even they did not fit.
    """
    what = "each entry's title only" + (", and not every title" if cut else "")
    return (
        "\n\n---\n\n"
        f"These notes show {what}, to fit GitHub's limit on a release body. "
        f"The full section is in [CHANGELOG.md]({full_url}).\n"
    )


def headlines(text: str) -> str:
    """Every heading, every top-level paragraph, and the title of every top-level ``- `` entry.

    A top-level paragraph is kept whole, since a version's preamble says what it pairs with. An entry that opens with ``- **`` keeps its bold title: followed onto later lines while the
    ``**`` is unclosed (up to :data:`_TITLE_LINES` lines), and cut just after it closes. Any other
    entry keeps its first line. Nested bullets and continuation lines are body, and are dropped.
    """
    out: list[str] = []
    lines = text.splitlines()
    i = 0
    while i < len(lines):
        line = lines[i]
        if line.startswith("#"):
            if out and out[-1] != "":
                out.append("")
            out.extend([line, ""])
        elif line.startswith("- "):
            title = [line]
            j = i + 1
            while (
                "\n".join(title).count("**") % 2 == 1
                and j < len(lines)
                and len(title) < _TITLE_LINES
                and lines[j].startswith("  ")
            ):
                title.append(lines[j])
                j += 1
            joined = "\n".join(title)
            if line.startswith("- **") and joined.count("**") >= 2:
                # Keep the bold title and drop the sentence the body starts after it.
                joined = joined[: joined.index("**", len("- **")) + len("**")]
            else:
                joined = title[0]
            out.extend(joined.split("\n"))
            i = j
            continue
        elif line and not line[0].isspace():
            # A top-level paragraph line. Open it with a blank line, or Markdown would read it as a
            # continuation of the entry above.
            if (i == 0 or not lines[i - 1].strip()) and out and out[-1] != "":
                out.append("")
            out.append(line)
        i += 1
    return "\n".join(out).strip() + "\n"


def _cut(text: str, budget: int) -> str:
    """The start of ``text`` in at most ``budget`` characters, ending at a line end where one fits."""
    head = text[:budget]
    if len(text) > budget:
        cut = head.rfind("\n")
        if cut > 0:
            head = head[:cut]
    return head.rstrip()


def bound(text: str, full_url: str, limit: int = DEFAULT_LIMIT) -> str:
    """``text`` unchanged if it fits in ``limit`` characters, else its headlines plus a link.

    Headlines that still do not fit are cut at a line end. If not even one line fits, the cut falls
    at a character, since a body must still come out.
    """
    if len(text) <= limit:
        return text
    short = headlines(text).rstrip()
    whole = short + footer(full_url, cut=False)
    if len(whole) <= limit:
        return whole
    tail = footer(full_url, cut=True)
    budget = limit - len(tail)
    if budget <= 0:
        raise ValueError(f"limit {limit} leaves no room for the {len(tail)}-character footer")
    return _cut(short, budget) + tail


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0] if __doc__ else None)
    parser.add_argument("notes", type=Path, help="the release-notes file, rewritten in place")
    parser.add_argument(
        "--full-url", required=True, help="where the full section lives, linked from a shrunk body"
    )
    parser.add_argument("--limit", type=int, default=DEFAULT_LIMIT, help="maximum characters")
    args = parser.parse_args(argv)

    # newline="" on both sides, so a file that fits is written back exactly as it was read.
    text = args.notes.read_text(encoding="utf-8", newline="")
    if len(text) <= args.limit:
        print(f"release notes: {len(text)} characters, within {args.limit}; unchanged")
        return 0
    out = bound(text, args.full_url, args.limit)
    args.notes.write_text(out, encoding="utf-8", newline="")
    print(
        f"release notes: {len(text)} characters is over {args.limit}; shrunk to {len(out)}, "
        f"linking {args.full_url}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
