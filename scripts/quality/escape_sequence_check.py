#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""An invalid escape sequence is a future ``SyntaxError``, and it fails at COLLECTION.

Python has announced that an invalid escape sequence in a string literal becomes a
``SyntaxError``. This project targets 3.14+ and will meet that upgrade. The cost is not one
failing test: a ``SyntaxError`` fails at **collection**, so the whole module disappears in one
step. **A test module that vanishes at collection does not report as a failure -- it reports as
fewer tests**, which is the quietest possible way to lose coverage. That is why this is a gate
and not a lint preference (BACKLOG #1271).

**A GREP IS THE WRONG INSTRUMENT HERE BY ABOUT A FACTOR OF A HUNDRED, AND THAT IS THE REUSABLE
PART.** Searching for backslashes in this repository returns hundreds of files, because
``|^~\\&`` is the HL7 encoding-characters field -- so a grep counts the DOMAIN rather than the
DEFECT. In a codebase whose subject matter is a format built out of escape-like punctuation,
compiling is the only instrument that answers the question being asked.

**TWO INSTRUMENTS, DELIBERATELY, BECAUSE THEY ANSWER DIFFERENT QUESTIONS.**

* The **compiler** is authoritative for WHICH lines. It sees every literal form, including
  f-strings, which the tokeniser below does not decompose. The verdict is always the
  compiler's.
* The **tokeniser** is authoritative for HOW MANY escapes a line carries. The compiler emits
  **one ``SyntaxWarning`` per LINE**, so a warning count understates a defect count whenever a
  line carries more than one. Measured on the item that prompted this gate: 3 warnings, 3
  lines, **5** invalid escapes -- one line carried three. Reporting the warning count would
  have invited a per-warning patch that left two behind and still died on the upgrade.

So a per-LINE fix is the correct unit: make the whole literal raw. Note the two forms are not
interchangeable -- ``r"..."`` for a ``str`` and ``rb"..."`` for a ``bytes`` -- so a uniform
patch is wrong in one direction and a per-warning patch is wrong in the other.

**MEASURED FALSE-POSITIVE CLASS, recorded because it cost a pass here and the fix is one
character.** On a CRLF checkout a line-continuation backslash is followed by CARRIAGE RETURN,
not newline. A first version of this scan omitted ``\\r`` from the permitted set and reported
**25 valid line continuations across three files as defects**. Nothing in that output looked
wrong; it was caught only by cross-checking against the compiler, which reported none of them.
That is this gate's own lesson turned on itself: an instrument that answers an adjacent
question is most convincing when it is confidently wrong.

Usage:
  escape_sequence_check.py [FILE ...]   # check the given files (how pre-commit would invoke it)
  escape_sequence_check.py              # check every tracked .py file (how CI invokes it)
  escape_sequence_check.py --list       # print the in-scope file list and exit 0 (auditable scope)

Exit: 0 clean, 1 violations found, 2 usage error.
"""

from __future__ import annotations

import io
import subprocess
import sys
import tokenize
import warnings
from pathlib import Path

#: Membership IS the scope. Only Python has this failure mode.
SOURCE_SUFFIXES = (".py",)

#: Escapes a ``str`` literal may contain. ``\r`` and ``\n`` are the LINE-CONTINUATION forms --
#: the raw characters, not the letters -- and CRLF is why both must be here (see module docstring).
_STR_OK = frozenset("\r\n\\'\"abfnrtv01234567xNuU")

#: A ``bytes`` literal has no ``\N``, ``\u`` or ``\U``. Keeping the two sets apart is what makes
#: the report able to say ``rb""`` rather than ``r""`` for a bytes literal.
_BYTES_OK = frozenset("\r\n\\'\"abfnrtv01234567x")


def in_scope(path: str) -> bool:
    """True when *path* carries an in-scope source extension."""
    return Path(path).suffix.lower() in SOURCE_SUFFIXES


def tracked_files() -> list[str]:
    """Every in-scope file git tracks, relative to the repo root."""
    # Decoded explicitly rather than via text=True, for the reason control_char_check.py already
    # records: text=True decodes as cp1252 here, which mangles any non-ASCII path and would
    # silently drop it from the scan.
    out = subprocess.run(  # nosec B603 B607 - fixed argv, no shell, no caller-supplied executable
        ["git", "ls-files", "-z"],
        check=True,
        capture_output=True,
    ).stdout.decode("utf-8", errors="replace")
    return sorted(p for p in out.split("\0") if p and in_scope(p))


def _literal_prefix(token: str) -> str:
    """The ``r``/``b``/``f`` prefix of a string token, lowercased."""
    i = 0
    while i < len(token) and token[i] not in "\"'":
        i += 1
    return token[:i].lower()


def escapes_by_line(path: str) -> dict[int, list[tuple[str, str]]]:
    """Invalid escapes in *path* as ``{line: [(kind, sequence), ...]}``.

    This is the MAGNITUDE instrument. It does not decompose f-strings, so it can report fewer
    lines than the compiler; ``violations`` treats the compiler as the verdict for exactly that
    reason and uses this only to enrich the count.
    """
    found: dict[int, list[tuple[str, str]]] = {}
    try:
        with open(path, "rb") as handle:
            tokens = list(tokenize.tokenize(handle.readline))
    except (OSError, tokenize.TokenError, SyntaxError):
        return found
    for token in tokens:
        if token.type != tokenize.STRING:
            continue
        prefix = _literal_prefix(token.string)
        if "r" in prefix:
            continue  # raw: there is nothing to get wrong
        permitted = _BYTES_OK if "b" in prefix else _STR_OK
        kind = "bytes" if "b" in prefix else "str"
        body = token.string[len(prefix) :]
        index = 0
        while index < len(body) - 1:
            if body[index] == "\\":
                following = body[index + 1]
                if following not in permitted:
                    found.setdefault(token.start[0], []).append((kind, "\\" + following))
                index += 2  # a backslash consumes the next character either way
                continue
            index += 1
    return found


def compiler_lines(path: str) -> list[int]:
    """Lines the COMPILER reports an invalid escape on. This is the authoritative verdict.

    A file that does not compile at all is not this gate's subject -- that is a louder defect
    which every other tool already reports -- so it is passed over rather than blamed here.
    """
    try:
        source = Path(path).read_bytes()
    except OSError:
        return []
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always", SyntaxWarning)
        try:
            compile(source, path, "exec")
        except (SyntaxError, ValueError):
            return []
    return sorted(
        w.lineno
        for w in caught
        if issubclass(w.category, SyntaxWarning) and "invalid escape sequence" in str(w.message)
    )


def violations(path: str) -> list[tuple[int, str, list[str]]]:
    """Every offending line in *path* as ``(line, kind, sequences)``.

    The line set comes from the compiler; the sequences come from the tokeniser. When the
    tokeniser cannot see a line the compiler flagged -- an f-string -- the line is still
    reported, with its sequences left empty rather than the line dropped.
    """
    counted = escapes_by_line(path)
    out: list[tuple[int, str, list[str]]] = []
    for line in compiler_lines(path):
        entries = counted.get(line, [])
        kind = entries[0][0] if entries else "str"
        out.append((line, kind, [sequence for _, sequence in entries]))
    return out


def _render(sequence: str) -> str:
    """A sequence as it appears IN THE SOURCE, but safe to print on a cp1252 console.

    Not ``ascii()`` over the whole thing: that escapes the leading backslash too and prints
    ``\\\\.`` where the file says ``\\.``, sending a reader to look for a defect they do not have.
    Only the offending character is escaped, and only when it needs to be.
    """
    following = sequence[1:]
    if following.isascii() and following.isprintable():
        return sequence
    return "\\" + ascii(following).strip("'")


def main(argv: list[str]) -> int:
    if argv and argv[0] == "--list":
        if len(argv) > 1:
            sys.stderr.write("escape-sequence: --list takes no further arguments\n")
            return 2
        for path in tracked_files():
            print(path)
        return 0

    paths = [p for p in argv if in_scope(p)] if argv else tracked_files()

    lines_hit = 0
    escapes = 0
    for path in paths:
        for line, kind, sequences in violations(path):
            lines_hit += 1
            escapes += len(sequences)
            shown = " ".join(_render(s) for s in sequences) or "(inside an f-string)"
            fix = "rb" if kind == "bytes" else "r"
            sys.stderr.write(
                f"escape-sequence: {path}:{line}: {len(sequences) or '?'} invalid escape(s) "
                f"in a {kind} literal: {shown} -- make the whole literal {fix}'...'\n"
            )

    if lines_hit:
        sys.stderr.write(
            f"escape-sequence: {escapes} invalid escape(s) across {lines_hit} line(s) "
            f"in {len(paths)} file(s) checked.\n"
            "  These become a SyntaxError on a future Python, which fails at COLLECTION -- the\n"
            "  whole module disappears and reports as FEWER TESTS rather than as a failure.\n"
            "  Fix per LINE, by making the whole literal raw. The count above is escapes, not\n"
            "  warnings: one line can carry several and the compiler only warns once per line.\n"
        )
        return 1

    print(f"escape-sequence: clean; {len(paths)} file(s) checked.")
    return 0


if __name__ == "__main__":
    # This gate reports on source text, so its own output must survive a stock cp1252 console.
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")
    raise SystemExit(main(sys.argv[1:]))
