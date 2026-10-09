# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The one glyph class for the CLAUDE.md section 11 tools that judge prose and diffs.

At least two tools read it: the ``new-glyph`` pre-commit hook (``scripts/quality/new_glyph_check.py``)
judges staged diffs, and ``scripts/telemetry/rule_telemetry.py`` grades session transcripts. Both
match with :data:`GLYPH`, so they cannot disagree on a codepoint. They used to carry a range list
each, and those disagreed: the hook missed U+2300-23FF and U+25A0-25FF, so it let through U+23F3
HOURGLASS WITH FLOWING SAND, which ``docs/CONNECTIONS.md`` uses as a status mark.

``_BANNED`` in ``scripts/asvs/apply.py`` is a different class on purpose: it also bans arrows, which
suits a security record and not the operator docs. Change it separately, if at all.

The ranges are the union of the two old lists. Measured 2026-10-07 over the last 200 first-parent
commits on ``main``: the union refuses 0, the same as the hook's old ranges, against a positive
control of 7 commits that staged 12 glyph-carrying lines (all net-zero edits of existing lines).

OUT ON PURPOSE, at least: the plain Arrows block (U+2190-21FF), box drawing (U+2500-257F), block
elements (U+2580-259F) and accented letters. Arrows were 167 of 167 telemetry hits on a real corpus
on 2026-09-02, and the operator docs carry many legitimately. The heavy dingbat arrows (U+2794-27BF)
and the arrows in U+2B00-2BFF are in, because they are pictures. To rule the Arrows block in, add
the pair here AND a firing case to ``tests/test_new_glyph_check.py``.

KNOWN GAPS, not a complete list. Some emoji sit outside every range, for example U+203C, U+2139,
U+2934 and U+3297, and pass when written without U+FE0F. The supplemental arrow blocks (U+27F0-27FF,
U+2900-297F) are out too. A Markdown or HTML character reference such as ``&#x2705;`` is ASCII on
the line, so the hook passes it even though it renders a glyph.

NEWLY REFUSED BY THE UNION, so a refusal is not mistaken for a false positive. The tree carries at
least these. Editing a line that holds one passes, and a NEW one is refused:

* the triangles U+25B6, U+25BA and U+25BC drawn as arrowheads in docs diagrams. Use an arrow from
  U+2190-21FF instead, such as U+2192 or U+2193;
* U+23CE, U+23ED and U+25FB in docs. Write a word;
* U+25B8, which ``messagefoundry/api/app.py`` builds into connection names, and the console's sort and
  disclosure markers (U+25B2, U+25BC, U+25BE). In code, write an escape so the source stays ASCII:
  ``\\N{BLACK RIGHT-POINTING SMALL TRIANGLE}`` or ``\\u25b8`` in Python, ``\\u25b8`` in JavaScript,
  ``\\25B8`` in CSS, ``&#x25B8;`` in HTML.

The whole of U+2300-23FF is in, so ceiling and floor marks (U+2308-230B) and U+2318 are refused too.
Nothing in the tree used them on 2026-10-07.

Written as integers so this file carries no glyph of its own.
"""

from __future__ import annotations

import re

#: Inclusive codepoint ranges that count as a glyph or emoji.
GLYPH_RANGES: tuple[tuple[int, int], ...] = (
    (0x2300, 0x23FF),  # Miscellaneous Technical: hourglass, stopwatch, media controls
    (0x25A0, 0x27BF),  # Geometric Shapes, Miscellaneous Symbols, Dingbats
    (0x2B00, 0x2BFF),  # Miscellaneous Symbols and Arrows
    (0x1F000, 0x1FAFF),  # the emoji and pictograph planes
    (0xFE0F, 0xFE0F),  # the variation selector that renders a character as emoji
)

#: One character in :data:`GLYPH_RANGES`. Built from the integers so this source stays ASCII.
GLYPH: re.Pattern[str] = re.compile(
    "[" + "".join(chr(lo) + "-" + chr(hi) for lo, hi in GLYPH_RANGES) + "]"
)
