# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A small string-aware JavaScript/TypeScript comment blanker, shared by the tests and the gates.

Moved here from ``tests/test_browser_storage_doc_drift.py`` (BACKLOG #5578) so the crypto inventory
gate's JS/TS arms read the same code view the doc-drift probes do. The gate's old line rule read a
``/*`` that began a line inside a template literal as a block comment and hid real code up to the
next ``*/`` anywhere in the file; a lexer that skips string, template and regex literals does not.
"""

from __future__ import annotations

#: Characters after which a ``/`` opens a regex literal rather than dividing.
_REGEX_OPENERS = frozenset("(,=:[!&|?{};+-*%<>~^")
#: Keywords after which a ``/`` opens a regex literal too (``return /x/.test(s)``).
_REGEX_KEYWORDS = frozenset(
    {
        "return",
        "typeof",
        "case",
        "do",
        "else",
        "in",
        "of",
        "void",
        "delete",
        "throw",
        "new",
        "yield",
    }
)


def blank_js_comments(source: str) -> str:
    """``source`` with every JavaScript comment blanked to spaces; string literals are kept.

    A small scanner, not a parser: it skips quoted strings, template literals and regex literals (a ``/``
    after an operator, an opening bracket or a keyword such as ``return``) so a ``//`` inside one is
    not read as a comment. A template literal's ``${}`` holes are treated as string. A quote with no
    closing quote on its line ends at the newline, so one misread cannot run to the end of the file.
    A ``/*`` with no ``*/`` after it is an unterminated block comment, a syntax error, so it is kept
    as code rather than blanking the rest of the file. Newlines are kept, so line numbers hold.
    """
    out: list[str] = []
    i, n = 0, len(source)
    prev = ""
    while i < n:
        char, nxt = source[i], source[i + 1 : i + 2]
        end = i + 1
        if char in "'\"`":
            while end < n and source[end] != char and (char == "`" or source[end] != "\n"):
                end += 2 if source[end] == "\\" else 1
            end += 1
        elif char.isalnum() or char in "_$":
            while end < n and (source[end].isalnum() or source[end] in "_$"):
                end += 1
            out.append(source[i:end])
            # A property named like a keyword (``obj.in``) is an operand, so a / after it divides.
            prev = "x" if i and source[i - 1] == "." else source[i:end]
            i = end
            continue
        elif char == "/" and nxt in ("/", "*") and (nxt == "/" or "*/" in source[i + 2 :]):
            close = source.find("\n" if nxt == "/" else "*/", i + 2)
            end = n if close == -1 else close + (0 if nxt == "/" else 2)
            out.append("".join(c if c == "\n" else " " for c in source[i:end]))
            i = end
            continue
        elif char == "/" and (not prev or prev in _REGEX_OPENERS or prev in _REGEX_KEYWORDS):
            in_class = False
            while end < n and source[end] != "\n":
                if source[end] == "\\":
                    end += 2
                    continue
                if source[end] == "/" and not in_class:
                    break
                if source[end] == "[":
                    in_class = True
                elif source[end] == "]":
                    in_class = False
                end += 1
            end += 1
        out.append(source[i:end])
        if not char.isspace():
            prev = char
        i = end
    return "".join(out)
