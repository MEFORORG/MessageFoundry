# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Text a peer wrote, made safe to print to a terminal (ASVS 1.1.2).

A command-line tool that prints what a peer sent -- an ACK, an API answer, an attachment, the
detail of an error the peer described -- hands that peer the operator's terminal. An ESC or CSI
sequence can move the cursor, rewrite what was printed above it or retitle the window, an OSC can
do more, a bidirectional override reorders what the operator reads, and a character a Windows
console cannot encode stops the print. :func:`escape_for_terminal` is the rule at least
``samples/send_mllp.py``, ``harness/load/rigadmin.py`` ``get``, the harness ``--scenario`` and
``--load`` error lines and the reconcile text report print by, so a later hardening applies to all
of them at once. It is not every such tool. At least three keep a different rule or none:
``check-privileges`` (``privilege_check.printable``) and the ``messagefoundry-toolkit`` command
(BACKLOG #2516) each keep a category-based rule, and ``tee`` imports nothing from this package by
design.

THE RULE. Printable ASCII, newline and tab print as themselves. Every other character prints as a
visible escape: a C0 control or DEL as ``\\xNN``, and every code point past ASCII -- a C1 control,
a bidirectional override or an accented letter alike -- as ``\\uNNNN`` or ``\\UNNNNNNNN``. A
backslash is doubled only where it would otherwise read as the start of one of those escapes, so
text spelling ``\\x1b`` cannot pass for an escaped ESC, and ordinary text with a backslash in it
(``MSH|^~\\&|``, a Windows path) prints unchanged. The result is pure ASCII, so any console codec
encodes it.

WHY THIS IS NOT IN :mod:`messagefoundry.controlchars`. That module states ONE alphabet, C0 plus
DEL, and builds every screen and neutraliser from it; its docstring calls widening that alphabet a
deliberate behaviour change at every call site at once, and it is deliberately blind to C1 and to
bidirectional controls because its sinks are byte-oriented (a request line, a header, a log
record). This rule is a different alphabet -- an allowlist of printable ASCII, not a denylist of
C0 -- with a disambiguation step that one does not need. Putting it there would give that module
two alphabets, which is the drift it exists to prevent. The log scrub keeps its own alphabet on
purpose.

**This module imports only the standard library**, so a client tree (``harness/``, ``samples/``)
may import it under ``tests/test_dependency_boundaries.py``, and a tool run beside an installed
engine can import it lazily.
"""

from __future__ import annotations

import re

__all__ = ["escape_for_terminal", "escape_json_for_terminal"]

#: THE ONE ALPHABET: every character that is not printable ASCII, newline or tab.
_NOT_SHOWN = r"[^\t\n -~]"

#: In one pass: a backslash that would read as the start of an escape -- one before x, u, U or
#: another backslash, or before a character about to be escaped -- or a character
#: :data:`_NOT_SHOWN` names. The lookahead consumes nothing, so the character after a doubled
#: backslash is still matched on its own.
_TO_ESCAPE = re.compile(rf"\\(?=[\\xuU]|{_NOT_SHOWN})|{_NOT_SHOWN}")
_NOT_SHOWN_RE = re.compile(_NOT_SHOWN)


def _escaped(match: re.Match[str]) -> str:
    char = match.group()
    if char == "\\":
        return "\\\\"
    code = ord(char)
    if code < 0x80:
        return f"\\x{code:02x}"
    return f"\\u{code:04x}" if code <= 0xFFFF else f"\\U{code:08x}"


def escape_for_terminal(text: str) -> str:
    """``text`` as pure ASCII that is safe to print to any terminal; see the module docstring.

    Computed per call with no cache, so a peer sending many distinct code points cannot grow this
    process's memory."""
    return _TO_ESCAPE.sub(_escaped, text)


def _json_escaped(match: re.Match[str]) -> str:
    code = ord(match.group())
    if code == 0x0D:
        return "\n"  # in valid JSON a CR is whitespace between tokens, so a newline means the same
    if code <= 0xFFFF:
        return f"\\u{code:04x}"
    code -= 0x10000
    return f"\\u{0xD800 + (code >> 10):04x}\\u{0xDC00 + (code & 0x3FF):04x}"


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
