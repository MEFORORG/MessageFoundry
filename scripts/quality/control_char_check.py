# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Refuse control bytes in tracked text, because a collapsed escape is invisible in every normal view.

An escape sequence written into a string can collapse into the byte it names. ``\\b`` becomes a
literal backspace (0x08), ``\\a`` a bell (0x07), ``\\f`` a form feed (0x0C). The file then looks
correct in an editor, in ``git diff``, in a code review and in a terminal -- the byte renders as
nothing, or moves the cursor -- while the program reads something the author never wrote.

MEASURED TWICE IN THIS REPOSITORY, INDEPENDENTLY, WITHIN A WEEK:

  * ``scripts/security/scan_forbidden.py:662`` on ``main``. A comment explaining the leak scanner's
    identifier handling reads "the only one that defeats <0x08>". The author wrote a word-boundary
    escape; the sentence is ABOUT word boundaries, and the byte ate the word. Harmless where it sits
    -- a comment cannot affect matching -- but the next person to copy that reasoning into a pattern
    inherits the byte.
  * A regex in ``scripts/coord/claim-reconcile.ps1`` while it was being written. There the same byte
    was INSIDE the pattern, so it matched nothing at all, silently, and a debug line appeared to
    prove the pattern worked because the pattern had been retyped by hand in the debug line.

THE FAILURE MODE THIS GUARDS IS NOT "A WRONG CHARACTER". It is that no ordinary view shows it. Only
``cat -A``, a hex dump, or a check like this one does -- so the defect survives every review that a
human performs by reading.

SCOPE. Text extensions only, listed in ``TEXT_SUFFIXES``; membership of that tuple IS the scope, and
adding a language is adding an entry and nothing else. Binary and data blobs are excluded because a
control byte there is content rather than a mistake. TAB, LF and CR are permitted: they are the
control characters text legitimately contains.

Usage:
  control_char_check.py [FILE ...]   # check the given files (how pre-commit invokes it)
  control_char_check.py              # check every in-scope git-tracked file (how CI invokes it)
  control_char_check.py --list       # print the in-scope file list and exit 0 (scope, auditable)

Exit: 0 clean, 1 violations found, 2 usage error.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

#: Extensions treated as text. Membership IS the scope.
TEXT_SUFFIXES = (
    ".py",
    ".ps1",
    ".sh",
    ".ts",
    ".js",
    ".go",
    ".md",
    ".toml",
    ".yml",
    ".yaml",
    ".json",
    ".cfg",
    ".ini",
    ".txt",
)

#: The control characters text is allowed to contain: TAB, LF, CR.
ALLOWED = frozenset({0x09, 0x0A, 0x0D})

#: Names for the bytes most likely to arrive from a collapsed escape, so the report says what it is
#: rather than only where. A number alone sends the reader to a table; a name ends the search.
NAMES = {
    0x00: "NUL",
    0x07: "BEL (\\a)",
    0x08: "BACKSPACE (\\b -- a collapsed word-boundary escape)",
    0x0B: "VERTICAL TAB (\\v)",
    0x0C: "FORM FEED (\\f)",
    0x1B: "ESC",
    0x7F: "DEL",
}


def in_scope(path: str) -> bool:
    """True when *path* carries an in-scope text extension."""
    return Path(path).suffix.lower() in TEXT_SUFFIXES


def tracked_files() -> list[str]:
    """Every in-scope file git tracks, relative to the repo root."""
    # Decoded explicitly rather than via text=True, for the reason licence_header_check.py
    # already records: text=True decodes as cp1252 here, which mangles any non-ASCII path and
    # would silently drop it from the scan -- a scanner that skips a file it cannot spell is
    # the silent failure this whole family of checks exists to remove.
    out = subprocess.run(  # nosec B603 B607 - fixed argv, no shell, no caller-supplied executable
        ["git", "ls-files", "-z"],
        check=True,
        capture_output=True,
    ).stdout.decode("utf-8", errors="replace")
    return sorted(p for p in out.split("\0") if p and in_scope(p))


def offences(path: str) -> list[tuple[int, int, int]]:
    """Every disallowed byte in *path* as (line, column, byte).

    Read as BYTES, deliberately. Decoding first would raise on a genuinely binary file that slipped
    the extension filter, and would report an encoding error instead of the thing being looked for.
    """
    try:
        raw = Path(path).read_bytes()
    except OSError:
        return []
    hits: list[tuple[int, int, int]] = []
    line = 1
    col = 1
    for b in raw:
        if b == 0x0A:
            line += 1
            col = 1
            continue
        if b < 0x20 and b not in ALLOWED or b == 0x7F:
            hits.append((line, col, b))
        col += 1
    return hits


def main(argv: list[str]) -> int:
    if argv and argv[0] == "--list":
        if len(argv) > 1:
            sys.stderr.write("control-char: --list takes no further arguments\n")
            return 2
        for p in tracked_files():
            print(p)
        return 0

    paths = [p for p in argv if in_scope(p)] if argv else tracked_files()

    violations = 0
    for p in paths:
        for line, col, b in offences(p):
            name = NAMES.get(b, f"0x{b:02x}")
            sys.stderr.write(f"control-char: {p}:{line}:{col}: {name}\n")
            violations += 1

    if violations:
        sys.stderr.write(
            f"control-char: {violations} control byte(s) across {len(paths)} file(s) checked.\n"
            "  These are invisible in an editor, in git diff and in review -- `cat -A` or a hex dump\n"
            "  is the only ordinary view that shows them. If you meant an escape sequence, write it\n"
            "  as two characters (backslash + letter); if you meant the byte, this is the wrong file.\n"
        )
        return 1

    # Coverage on the clean path too. "No violations" over a scope nobody stated is the silence this
    # repository keeps finding: a guard that checked nothing reports identically to one that passed.
    print(f"control-char: OK -- {len(paths)} file(s) checked, no control bytes outside TAB/LF/CR")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
