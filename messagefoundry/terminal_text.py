# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Text a peer wrote, made safe to print to a terminal (ASVS 1.1.2).

A command-line tool that prints what a peer sent -- an ACK, an API answer, an attachment, the
detail of an error the peer described -- hands that peer the operator's terminal. An ESC or CSI
sequence can move the cursor, rewrite what was printed above it or retitle the window, an OSC can
do more, a bidirectional override reorders what the operator reads, and a character a Windows
console cannot encode stops the print. :func:`escape_for_terminal` is the rule at least
``samples/send_mllp.py``, ``harness/load/rigadmin.py`` ``get``, the harness ``--scenario`` and
``--load`` lines, the ``shardcert`` two-box engine-error lines, the ``--fuzz`` setup and failure
lines, the reconcile text report, the ``messagefoundry verify`` console summary, the
``check-privileges`` text report and the ``messagefoundry-toolkit`` report print by,
so a later hardening applies to all of them at once (BACKLOG #2891). It is not every such tool: at
least ``tee`` imports nothing from this package by design. ``privilege_check.printable`` still
STRIPS the characters in :data:`CONTROL_CATEGORIES`, for one job this rule cannot do, judging
whether a policy name reads as ``root``, and its docstring says why.
``tests/test_adr_analyze.py`` holds the toolkit report, the ``check-privileges`` text and
that comparison to the one set of categories.

THE RULE. Printable ASCII, newline and tab print as themselves. Every other character prints as a
visible escape: a C0 control or DEL as ``\\xNN``, and every code point past ASCII -- a C1 control,
a bidirectional override or an accented letter alike -- as ``\\uNNNN`` or ``\\UNNNNNNNN``. A
backslash is doubled only where it would otherwise read as the start of one of those escapes, so
text spelling ``\\x1b`` cannot pass for an escaped ESC, and ordinary text with a backslash in it
(``MSH|^~\\&|``, a Windows path) prints unchanged. The result is pure ASCII, so any console codec
encodes it.

TWO OPTIONS, BOTH KEYWORD-ONLY, so the default call above is the strict rule.

``single_line=True`` also escapes newline and tab. A line the tool means as ONE line -- a
``PASS``/``FAIL`` verdict, an error line, a ``verify`` check -- carries peer text in the middle of
it, and a newline there would let that text start a line of its own that reads as a verdict the
tool never gave. Output that is multi-line by nature (an ACK, an API body) keeps them.

``keep_printable_unicode=True`` keeps every code point past ASCII that a terminal shows as a
glyph -- an accented letter, an em dash, a CJK name -- and still escapes every one in
:data:`CONTROL_CATEGORIES`: the C0 and C1 controls and DEL (``Cc``), the bidirectional and other
format controls such as U+200E/F, U+202A-202E and U+2066-2069 (``Cf``), the line and paragraph
separators (``Zl``, ``Zp``), a lone surrogate (``Cs``), and the private-use and unassigned code
points (``Co``, ``Cn``), which this interpreter's Unicode tables cannot vouch for and a newer
terminal may treat as a control. Because a character it keeps can look like an ASCII one, it
also escapes a kept character that stands directly before text reading as an escape body, and
doubles a backslash before more text than the strict rule does; :data:`_ESCAPE_BODY_KEEP` says how
far that goes. It is
for a sink whose own text is not ASCII, where the strict rule would turn the tool's own em dash
into ``\\u2014``. Its output is not pure ASCII, so it is for a stream already hardened against an
unencodable character (``messagefoundry.console_streams`` does that for the engine's command
line).

A MARKDOWN TABLE CELL. :func:`escape_for_markdown_cell` is the console rule above with
``single_line`` and ``keep_printable_unicode``, then the escapes a GFM table cell needs. It is
the rule the ``messagefoundry verify`` Markdown report and the harness acceptance Markdown report
both write every cell by (BACKLOG #2897), so the two cannot drift apart again. What it covers,
and at least what it leaves, is stated at :data:`_MD_CELL`. ``scripts/asvs/scorecard.py`` keeps
a cell helper of its own, by design: its docstring says why.

WHY THIS IS NOT IN :mod:`messagefoundry.controlchars`. That module's refusals screen C0 plus DEL,
because their sinks are byte-oriented (a request line, a header, a file name). This rule is a
different alphabet -- an allowlist of printable ASCII, not a denylist of C0 -- with a
disambiguation step that one does not need. The two share one thing: :data:`CONTROL_CATEGORIES`,
which is defined in ``controlchars`` and imported here. The log escape there uses the same set,
because a log is read back as text much as a terminal is (vault BACKLOG #2815).

**This module imports only the standard library and ``controlchars``**, a leaf that itself imports
only the standard library, so a client tree (``harness/``, ``samples/``) may import it under
``tests/test_dependency_boundaries.py``, and a tool run beside an installed engine can import it
lazily.
"""

from __future__ import annotations

import re
import unicodedata

from messagefoundry.controlchars import CONTROL_CATEGORIES, json_unicode_escape

__all__ = [
    "CONTROL_CATEGORIES",
    "escape_for_markdown_cell",
    "escape_for_terminal",
    "escape_json_for_terminal",
]

#: THE STRICT ALPHABET: every character that is not printable ASCII, newline or tab. The JSON path
#: uses it as is; the text path decides per character in :func:`_is_escaped`, which spells the same
#: set and widens or narrows it by the options. Every pattern here stays a literal so the ReDoS
#: scan in ``tests/test_security_static.py`` can read it, so
#: ``tests/test_terminal_text_console_sinks.py`` holds the spellings to each other over every code
#: point instead.
_NOT_SHOWN = r"[^\t\n -~]"

#: A whole run of backslashes, or any character that is not printable ASCII. Matching the run
#: whole keeps one pass linear however many backslashes a peer sends.
_CANDIDATE = re.compile(r"\\+|[^ -~]")
#: Text that reads as one of this module's escapes when a backslash stands before it. The strict
#: rule's output is pure ASCII, so only an ASCII hex digit can read as one there.
_ESCAPE_LOOKALIKE = re.compile(r"x[0-9A-Fa-f]{2}|u[0-9A-Fa-f]{4}|U[0-9A-Fa-f]{8}")
#: ``keep_printable_unicode`` prints non-ASCII characters as themselves, and many render nearly as
#: an ASCII twin: a fullwidth digit (U+FF10 to U+FF19), ``u`` (U+FF55) or backslash (U+FF3C), a
#: Cyrillic small e or ha, a reverse solidus operator (U+29F5), or a combining overlay. A list of
#: look-alikes would miss one, so in that mode the rule keys on position instead. An escape BODY is
#: ``x``, ``u`` or ``U`` followed by the escape's width of characters that are each an ASCII hex
#: digit or non-ASCII. A kept character directly before a body is escaped, so nothing that merely
#: looks like a backslash can start one; and a backslash run is doubled before a body or before ANY
#: non-ASCII character, so a look-alike escape letter after a real backslash cannot either.
#: Over-matching only escapes a character or doubles a backslash that did not strictly need it,
#: which still decodes correctly; the cost is that a path component starting with a non-ASCII
#: letter shows its backslash doubled in this mode.
_ESCAPE_BODY_KEEP = re.compile(
    r"x(?:[0-9A-Fa-f]|[^\x00-\x7f]){2}"
    r"|u(?:[0-9A-Fa-f]|[^\x00-\x7f]){4}"
    r"|U(?:[0-9A-Fa-f]|[^\x00-\x7f]){8}"
)
#: What a backslash run is doubled before in keep mode; see :data:`_ESCAPE_BODY_KEEP`.
_ESCAPE_LOOKALIKE_KEEP = re.compile(
    r"[^\x00-\x7f]"
    r"|x(?:[0-9A-Fa-f]|[^\x00-\x7f]){2}"
    r"|u(?:[0-9A-Fa-f]|[^\x00-\x7f]){4}"
    r"|U(?:[0-9A-Fa-f]|[^\x00-\x7f]){8}"
)
_NOT_SHOWN_RE = re.compile(_NOT_SHOWN)


def _visible(char: str) -> str:
    code = ord(char)
    if code < 0x80:
        return f"\\x{code:02x}"
    return f"\\u{code:04x}" if code <= 0xFFFF else f"\\U{code:08x}"


def _is_escaped(char: str, *, single_line: bool, keep_printable_unicode: bool) -> bool:
    """Whether ``char`` prints as an escape under the given options."""
    if char in "\t\n":
        return single_line
    if " " <= char <= "~":
        return False
    if keep_printable_unicode and not char.isascii():
        return unicodedata.category(char) in CONTROL_CATEGORIES
    return True


def escape_for_terminal(
    text: str, *, single_line: bool = False, keep_printable_unicode: bool = False
) -> str:
    """``text`` made safe to print to a terminal; see the module docstring.

    By default the result is pure ASCII, so any console codec encodes it. ``single_line`` also
    escapes newline and tab; ``keep_printable_unicode`` lets a printable non-ASCII character
    through and escapes, past ASCII, :data:`CONTROL_CATEGORIES` and a kept character standing
    directly before an escape body (:data:`_ESCAPE_BODY_KEEP`).

    A run of backslashes is doubled, all of it, only where it stands before text that reads as an
    escape or before a character about to be escaped. So an odd run before an escape marks a real
    one and an even run marks text, while an ordinary Windows or UNC path prints as typed (with
    ``keep_printable_unicode``, an ASCII one: see :data:`_ESCAPE_LOOKALIKE_KEEP`). A
    component that itself reads as an escape, such as ``\\x64``, is still doubled.

    Computed per call with no cache, so a peer sending many distinct code points cannot grow this
    process's memory."""

    def escaped(char: str) -> bool:
        return _is_escaped(
            char, single_line=single_line, keep_printable_unicode=keep_printable_unicode
        )

    lookalike = _ESCAPE_LOOKALIKE_KEEP if keep_printable_unicode else _ESCAPE_LOOKALIKE

    def replace(match: re.Match[str]) -> str:
        found = match.group()
        if found[0] != "\\":
            if escaped(found):
                return _visible(found)
            # Only a kept non-ASCII character reaches here unescaped: see _ESCAPE_BODY_KEEP.
            if keep_printable_unicode and _ESCAPE_BODY_KEEP.match(text, match.end()):
                return _visible(found)
            return found
        end = match.end()
        if lookalike.match(text, end) or (end < len(text) and escaped(text[end])):
            return found * 2
        return found

    return _CANDIDATE.sub(replace, text)


def _json_escaped(match: re.Match[str]) -> str:
    code = ord(match.group())
    if code == 0x0D:
        return "\n"  # in valid JSON a CR is whitespace between tokens, so a newline means the same
    # A lone surrogate keeps JSON's own ``\udc80`` here, unlike the log's spelling, so Python's
    # ``json`` reads back the same code point. Text holds one only after a ``surrogateescape`` or
    # ``surrogatepass`` decode, which the one caller does not use. A strict decoder would refuse
    # it, and an adjacent high and low pair would read back as one astral character.
    return json_unicode_escape(code)


def escape_json_for_terminal(text: str) -> str:
    """Valid JSON ``text`` as pure ASCII that is safe to print, and that decodes to the same value.

    The caller has already parsed ``text`` as JSON. In valid JSON a character this module escapes
    can stand only inside a string, where JSON's own ``\\uNNNN`` (a surrogate pair past the BMP)
    spells the same character, or as CR whitespace between tokens, which becomes a newline. A C0
    control cannot stand raw in a JSON string, so a body holding one is not valid JSON and goes to
    :func:`escape_for_terminal` instead. Backslashes are left alone: in JSON they are already
    unambiguous, and doubling one would change the value. So JSON that is already plain prints
    byte for byte, and nothing is decoded and encoded again, which could alter a number or drop a
    duplicate key."""
    return _NOT_SHOWN_RE.sub(_json_escaped, text)


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
#: ``@`` and ``#`` become references, so the source carries no raw ``@name`` mention or ``#N``
#: issue reference, and the ``:`` of ``://`` does too, so no raw ``scheme://`` URL is left to
#: autolink (BACKLOG #2897). Each keeps the raw character out of the Markdown SOURCE. Whether a
#: renderer that looks for mentions, references or links AFTER it decodes references is stopped
#: was NOT measured; GitHub's mention handling may work that way.
#: NOT covered, at least: a ``www.`` autolink; emphasis, strikethrough and emoji shortcodes, which
#: still restyle the rendered text within its cell; a viewer that runs a MathJax-style
#: auto-render over the rendered page, which can still find ``\(...\)``; and every invisible
#: printable character but the four Hangul fillers at :data:`_MD_INVISIBLE`.
_MD_CELL = {
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    "|": "&#124;",
    "](": "]&#40;",
    "`": "&#96;",
    "$": "&#36;",
    "@": "&#64;",
    "#": "&#35;",
    "://": "&#58;//",
}
#: Spelled as a literal, not joined from the keys, so the ReDoS scan in
#: ``tests/test_security_static.py`` can read it; ``tests/test_terminal_text_console_sinks.py``
#: holds it to the keys above.
_MD_CELL_RE = re.compile(r"[&<>|`$@#]|\]\(|://")
#: Printable characters that render as blank space (Unicode category ``Lo``, so
#: ``keep_printable_unicode`` keeps them): U+115F, U+1160, U+3164 and U+FFA0, the Hangul fillers.
#: One can pad a cell so it reads as empty, or stand in for a space in a name. The cell shows
#: each as a visible ``\uNNNN`` escape. The console keeps them; this is the cell's rule only.
_MD_INVISIBLE = re.compile(r"[\u115f\u1160\u3164\uffa0]")
#: A backslash run Markdown would eat: two or more (each pair reads as one), or one before ASCII
#: punctuation, the references above included. Doubled, it renders as written, so the terminal
#: rule's odd/even backslash convention and a UNC path survive the renderer.
_MD_BACKSLASHES = re.compile(r"\\{2,}|\\(?=[!-/:-@\[-`{-~])")


def escape_for_markdown_cell(text: str) -> str:
    """``text`` made safe to write inside one cell of a GFM Markdown table (ASVS 1.1.2).

    The console rule first, with ``single_line`` and ``keep_printable_unicode``: ESC, C1 and bidi
    controls become visible escapes, and so do newline and CR, so a peer cannot start a forged
    row and the file is safe to ``cat``. Then the blank fillers at :data:`_MD_INVISIBLE` as
    visible escapes, then the Markdown escapes at :data:`_MD_CELL`, then the backslash runs at
    :data:`_MD_BACKSLASHES`. Other printable Unicode, such as an em dash, is kept, so the caller
    writes the file as UTF-8.

    A filler's escape needs no backslash handling of its own: in that mode the console rule has
    already doubled any backslash run standing before a non-ASCII character."""
    shown = escape_for_terminal(text, single_line=True, keep_printable_unicode=True)
    shown = _MD_INVISIBLE.sub(lambda m: _visible(m.group()), shown)
    cell = _MD_CELL_RE.sub(lambda m: _MD_CELL[m.group()], shown)
    return _MD_BACKSLASHES.sub(lambda m: m.group() * 2, cell)
