# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Render verify results — console summary, Markdown, JSON. Dependency-free (stdlib only)."""

from __future__ import annotations

import json
import re
from collections import Counter
from collections.abc import Sequence

from messagefoundry.terminal_text import escape_for_terminal
from messagefoundry.verify.model import FAILING, CheckResult, Status


def summarize(results: Sequence[CheckResult]) -> Counter[Status]:
    """Count results by status."""
    return Counter(r.status for r in results)


def exit_code(results: Sequence[CheckResult]) -> int:
    """0 unless a check FAILed or ERRORed (MANUAL/SKIP never fail the run)."""
    return 1 if any(r.status in FAILING for r in results) else 0


def _shown(text: str) -> str:
    # A detail can carry what a peer wrote: a JWKS key id, an ACK, an exception naming a peer's
    # reply. Escaped HERE, at the console and Markdown sinks, and not in CheckResult, so the JSON
    # report keeps the value as it was (it is data, not a terminal or a rendered page). Every field
    # gets the same rule, so a detail added later is covered without anyone deciding it is peer
    # text. One line per check, so a newline is escaped too, or a peer's text could start a line
    # reading as a check that passed; printable Unicode is kept, so the engine's own em dashes print
    # as themselves.
    return escape_for_terminal(text, single_line=True, keep_printable_unicode=True)


def render_console(results: Sequence[CheckResult]) -> str:
    """A compact, aligned one-line-per-check summary for stdout, peer text escaped (ASVS 1.1.2)."""
    counts = summarize(results)
    lines = [
        f"{r.status.value:<6} {_shown(r.id):<14} {_shown(r.title)}"
        + (f"  [{_shown(r.detail)}]" if r.detail else "")
        for r in results
    ]
    tally = "  ".join(f"{s.value}={counts.get(s, 0)}" for s in Status)
    lines += ["", f"  {tally}   (exit {exit_code(results)})"]
    return "\n".join(lines)


#: What a GFM table cell would act on, each replaced by a character reference. References are
#: decoded only after the row is split into cells and never take a structural role. ``&`` is in
#: the set, or a peer's ``&#x202e;`` would render as the bidi control the terminal rule escaped.
#: ``<`` opens raw HTML, which GitHub and most viewers render; ``>`` cannot act once ``<`` is
#: escaped, and is escaped so the cell carries no raw angle bracket at all. The ``(`` after ``]``
#: is what makes ``[text](url)`` a link whose text is not its target and ``![x](url)`` a remote
#: image fetched on view; ``[`` alone stays, so the engine's own ``[store].path`` reads as typed. A
#: backtick would open a code span, inside which no reference decodes, so it goes too, and the
#: engine's own code spans render as plain backticks. ``$`` opens GitHub math, which could draw a
#: large coloured PASS in a FAIL row.
#: NOT covered, at least: a bare URL still autolinks (its text is its target); GitHub still
#: resolves an ``@name`` or ``#N`` reference in a pasted report; emphasis, strikethrough and emoji
#: shortcodes still restyle the rendered text within its cell; a viewer that runs a MathJax-style
#: auto-render over the rendered page can still find ``\(...\)``; and an invisible printable
#: character such as U+3164 is kept, as it is on the console.
_MD_CELL = {
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    "|": "&#124;",
    "](": "]&#40;",
    "`": "&#96;",
    "$": "&#36;",
}
_MD_CELL_RE = re.compile("|".join(re.escape(k) for k in _MD_CELL))
#: A backslash run Markdown would eat: two or more (each pair reads as one), or one before ASCII
#: punctuation, the references above included. Doubled, it renders as written, so the terminal
#: rule's odd/even backslash convention and a UNC path survive the renderer.
_MD_BACKSLASHES = re.compile(r"\\{2,}|\\(?=[!-/:-@\[-`{-~])")


def _md_cell(text: str) -> str:
    # The console rule first (ESC, C1 and bidi controls as visible escapes, newline and CR too, so
    # a peer cannot start a forged row and the file is safe to ``cat``), then the Markdown above.
    # The file is written UTF-8, so printable Unicode such as the engine's em dash is kept.
    cell = _MD_CELL_RE.sub(lambda m: _MD_CELL[m.group()], _shown(text))
    return _MD_BACKSLASHES.sub(lambda m: m.group() * 2, cell)


def render_markdown(results: Sequence[CheckResult]) -> str:
    """A Markdown table report, every cell escaped for a peer's text (ASVS 1.1.2).

    What the escape covers, and at least what it leaves, is stated at :data:`_MD_CELL`."""
    counts = summarize(results)
    out = [
        "# MessageFoundry — deployment verify",
        "",
        "Tally: "
        + " · ".join(f"**{s.value}** {counts.get(s, 0)}" for s in Status)
        + f" · exit `{exit_code(results)}`",
        "",
        "| Check | Title | Status | Detail |",
        "|---|---|---|---|",
    ]
    for r in results:
        cells = (r.id, r.title, r.status.value, r.detail or "")
        out.append("| " + " | ".join(_md_cell(c) for c in cells) + " |")
    return "\n".join(out) + "\n"


def render_json(results: Sequence[CheckResult]) -> str:
    """A JSON document: per-check results + tally + exit code."""
    counts = summarize(results)
    payload = {
        "results": [
            {
                "id": r.id,
                "title": r.title,
                "status": r.status.value,
                "detail": r.detail,
                "evidence": r.evidence,
            }
            for r in results
        ],
        "tally": {s.value: counts.get(s, 0) for s in Status},
        "exit_code": exit_code(results),
    }
    return json.dumps(payload, indent=2)
