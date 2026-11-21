# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A small string-aware JavaScript/TypeScript comment blanker, shared by the tests and the gates.

Moved here from ``tests/test_browser_storage_doc_drift.py`` (BACKLOG #5578) so the crypto inventory
gate's JS/TS arms can read the same code view the doc-drift probes do. A line-based stripper that
tracked block state, tried while building #5578 and never merged, read a ``/*`` that began a line
inside a template literal as a block comment and hid real code up to the next ``*/`` anywhere in the
file. A lexer that skips string, template and regex literals does not.

Its consumers want opposite safe directions. The doc-drift probes need a comment mention NOT to
count (BACKLOG #2056: ``app.js`` names ``localStorage`` in comments, so a raw scan stayed True after
the real storage calls were deleted). The crypto gate needs a misread NOT to hide code, so it unions
this view with its per-line view rather than tuning the lexer toward keeping text, and reads the
verdict :func:`classify_js` gives to judge each token only this view finds.
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
        "await",
        "default",
        "instanceof",
    }
)


#: The verdict :func:`classify_js` gives each character: code, a literal's text on the line the
#: literal opens on, a literal's text on a later line (a template literal, or a string continued by
#: a backslash), or a comment.
CODE, LITERAL, CONTINUED, COMMENT = "c", "l", "t", "#"


def _raw_backtick(source: str, start: int, end: int) -> bool:
    """Whether ``source[start:end]`` holds a backtick no backslash escapes."""
    i, end = start, min(end, len(source))
    while i < end:
        if source[i] == "\\":
            i += 2
            continue
        if source[i] == "`":
            return True
        i += 1
    return False


def blank_js_comments(source: str) -> str:
    """``source`` with every JavaScript comment blanked to spaces; string literals are kept.

    A small scanner, not a parser: it skips quoted strings, template literals and regex literals (a ``/``
    after an operator, an opening bracket or a keyword such as ``return``) so a ``//`` inside one is
    not read as a comment. A template literal's ``${}`` holes are scanned as code up to the ``}``
    that balances their ``{``, so a template nested in a hole closes where it should (BACKLOG
    #5578). A quote with no closing quote on its line ends at the newline, so one misread stops
    there. A regex read with no closing ``/`` on its line that would swallow an unescaped backtick
    is read as a division instead, so the backtick opens its template (BACKLOG #5578: a misread such
    as TypeScript's ``x! / y`` hid the template and read its text as code); in JavaScript outside
    JSX, which no consumer reads, a backtick in code always delimits a template. Newlines are kept,
    so line numbers hold.
    """
    return _scan(source, with_verdicts=False)[0]


def classify_js(source: str) -> tuple[str, str]:
    """``(blanked, verdicts)``: :func:`blank_js_comments`'s text, and beside it one verdict per
    character of ``source``: :data:`CODE`, :data:`LITERAL` (inside a string, template or regex
    literal, its delimiters included, on the line it opens on), :data:`CONTINUED` (the same, on a
    later line) or :data:`COMMENT`. A newline is kept as itself in both, so the two split into the
    same lines. The crypto inventory gate reads the verdict at a match's first character
    (BACKLOG #5578)."""
    return _scan(source, with_verdicts=True)


def _scan(source: str, *, with_verdicts: bool) -> tuple[str, str]:
    """The one scanner behind both entry points; ``with_verdicts=False`` skips building the
    verdict string, which :func:`blank_js_comments` would only discard."""
    out: list[str] = []
    verdicts: list[str] = []
    i, n = 0, len(source)
    prev = ""
    #: One entry per open ``${}`` hole, innermost last: ``[brace depth inside it, index of the
    #: template's opening backtick]``.
    holes: list[list[int]] = []

    def emit(text: str, kind: str, first: str | None = None) -> None:
        head = first or kind
        if "\n" not in text:  # almost every segment: one run of one verdict
            out.append(" " * len(text) if kind == COMMENT else text)
            if with_verdicts:
                verdicts.append(head * len(text))
            return
        lines = text.split("\n")
        out.append("\n".join(" " * len(p) for p in lines) if kind == COMMENT else text)
        if with_verdicts:
            later = CONTINUED if kind == LITERAL else kind
            verdicts.append("\n".join([head * len(lines[0]), *(later * len(p) for p in lines[1:])]))

    def template_text(start: int) -> tuple[int, bool]:
        """Template text from ``start``: ``(end, opens_hole)``, ``end`` just past the closing
        backtick or the ``${`` that opens a hole, or the end of the source."""
        j = start
        while j < n:
            if source[j] == "\\":
                j += 2
            elif source[j] == "`":
                return j + 1, False
            elif source[j] == "$" and source[j + 1 : j + 2] == "{":
                return j + 2, True
            else:
                j += 1
        return n, False

    while i < n:
        char, nxt = source[i], source[i + 1 : i + 2]
        end = i + 1
        kind = CODE
        closes_hole = char == "}" and bool(holes) and holes[-1][0] == 0
        if char == "`" or closes_hole:
            # A template literal, or its text resumed after a ``${}`` hole closes. A hole is code:
            # it is scanned like any other code until its own ``}``, nested templates included.
            opened = holes.pop()[1] if closes_hole else i
            end, opens_hole = template_text(i + 1)
            later_line = source.find("\n", opened, i) != -1
            emit(source[i:end], LITERAL, CONTINUED if later_line else None)
            if opens_hole:
                holes.append([0, opened])
                prev = "{"
            else:
                prev = "`"
            i = end
            continue
        if holes and char in "{}":
            holes[-1][0] += 1 if char == "{" else -1
        if char in "'\"":
            kind = LITERAL
            while end < n and source[end] != char and source[end] != "\n":
                end += 2 if source[end] == "\\" else 1
            end += 1
        elif char.isalnum() or char in "_$":
            while end < n and (source[end].isalnum() or source[end] in "_$"):
                end += 1
            emit(source[i:end], CODE)
            # A property named like a keyword (``obj.in``) is an operand, so a / after it divides.
            prev = "x" if i and source[i - 1] == "." else source[i:end]
            i = end
            continue
        elif char == "/" and nxt in ("/", "*"):
            close = source.find("\n" if nxt == "/" else "*/", i + 2)
            end = n if close == -1 else close + (0 if nxt == "/" else 2)
            emit(source[i:end], COMMENT)
            i = end
            continue
        elif char == "/" and (not prev or prev in _REGEX_OPENERS or prev in _REGEX_KEYWORDS):
            kind = LITERAL
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
            if source[end : end + 1] != "/" and _raw_backtick(source, i + 1, end):
                # No closing ``/`` on the line, so the regex was a misread division (``x! / y``),
                # and the backtick it would swallow may open a template: read the ``/`` as division
                # and let the backtick open it. A closed regex with a backtick in it is kept.
                kind, end = CODE, i
            end += 1
        emit(source[i:end], kind)
        if not char.isspace():
            prev = char
        i = end
    return "".join(out), "".join(verdicts)
