# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Resolve every citation of a root ``CLAUDE.md`` section number to a real section.

WHY THIS EXISTS. ``CLAUDE.md``'s numbered sections are a de facto API: measured 2026-08-12, 281
tracked files cite them and ``tests/test_dependency_boundaries.py`` names section 4 in its own
docstring. **Nothing validated a section number.** ``scripts/docs/link_check.py`` says so in its own
header -- it resolves the PATH and skips the ``#fragment`` -- so renumbering lands entirely green: the
link still resolves, the SDS identifiers still resolve, and only the meaning moves. That is the
half-rot shape, where the checkable half stays green.

It is not hypothetical. ``tests/test_sds_rule_ids_are_stable.py`` records the same rot landing on a
different document: inserting a new section 5 pushed 5-9 to 6-10, and four security citations still
resolve to the wrong section today. The lesson was learned for one document and the class left open
for this one.

WHAT IT DOES NOT DO, stated because a completeness claim is a liability (SDS-3.6). It validates *at
least* the citations that name ``CLAUDE.md`` and a section on the same line, within
``_WINDOW`` characters. A citation that names the file on one line and the section on the next is not
seen; neither is a bare ``section 4`` whose subject is established a paragraph earlier. This is a
deliberate floor, not a ceiling: the alternative is guessing which document a bare section number
belongs to, and a checker that guesses produces false positives, which is how a gate gets disabled.

USAGE
    python scripts/docs/claude_section_check.py            # scan, print counts, exit non-zero on a miss
    python scripts/docs/claude_section_check.py --list     # print every citation found and its verdict

The scan volume is always printed. A gate that reports only what it FOUND cannot be told apart from
one that scanned nothing.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

_REPO = Path(__file__).resolve().parents[2]
_ANCHOR = "CLAUDE.md"

# Section headings in the anchor: "## 4. Modularity & Extension Points" -> 4.
_HEADING = re.compile(r"^##\s+(\d+)\.\s")

# A citation is the anchor's name followed, within _WINDOW characters on the SAME line, by a section
# reference. Both spellings the repo actually uses are accepted.
_WINDOW = 60
_CITATION = re.compile(
    rf"CLAUDE\.md(?P<gap>.{{0,{_WINDOW}}}?)(?:§|(?<![A-Za-z])[Ss]ection\s+)(?P<num>\d+)"
)

# Files that may carry a citation. Matches the scan the finding was measured over.
_SUFFIXES = (".md", ".py", ".ps1", ".yml")


@dataclass(frozen=True)
class Citation:
    path: str
    line: int
    section: int
    text: str


def anchor_sections(anchor: Path) -> set[int]:
    """Section numbers defined by the anchor's own ``## N.`` headings."""
    found: set[int] = set()
    for line in anchor.read_text(encoding="utf-8").splitlines():
        m = _HEADING.match(line)
        if m:
            found.add(int(m.group(1)))
    return found


def tracked_files(root: Path) -> list[Path]:
    """Tracked files that may carry a citation.

    Uses ``git ls-files`` rather than a filesystem walk so the scan matches what is committed --
    an untracked scratch copy of a doc is not part of the repo's citation surface.
    """
    out = subprocess.run(  # nosec B603 B607 - fixed argv, no shell, no caller-supplied executable
        ["git", "-C", str(root), "ls-files", "-z"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=True,
    ).stdout
    paths = []
    for rel in out.split("\0"):
        if rel and rel.endswith(_SUFFIXES):
            p = root / rel
            if p.is_file():
                paths.append(p)
    return paths


def citations_in(path: Path, root: Path) -> list[Citation]:
    """Every anchor-section citation on a single line of ``path``."""
    try:
        text = path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        return []
    rel = path.relative_to(root).as_posix()
    out: list[Citation] = []
    for lineno, line in enumerate(text.splitlines(), start=1):
        if _ANCHOR not in line:
            continue
        for m in _CITATION.finditer(line):
            out.append(Citation(rel, lineno, int(m.group("num")), m.group(0).strip()))
    return out


def scan(root: Path) -> tuple[set[int], list[Citation], list[Citation]]:
    """Return (defined sections, every citation found, the unresolvable ones)."""
    anchor = root / _ANCHOR
    if not anchor.is_file():
        raise SystemExit(f"{_ANCHOR} not found at {anchor} -- refusing to report a clean scan")
    sections = anchor_sections(anchor)
    if not sections:
        raise SystemExit(
            f"parsed ZERO section headings from {_ANCHOR}. The heading format changed, or the file "
            f"is empty. Refusing to report every citation as broken, and refusing to pass."
        )
    every: list[Citation] = []
    for path in tracked_files(root):
        every.extend(citations_in(path, root))
    return sections, every, [c for c in every if c.section not in sections]


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--list", action="store_true", help="print every citation found")
    ap.add_argument("--root", type=Path, default=_REPO)
    args = ap.parse_args(argv)

    sections, every, broken = scan(args.root)

    # Print WHAT WAS SCANNED, always. A count of findings alone cannot distinguish a clean scan from
    # one that examined nothing.
    files = len({c.path for c in every})
    print(
        f"{_ANCHOR} defines sections {sorted(sections)}; "
        f"scanned {len(tracked_files(args.root))} tracked {'/'.join(_SUFFIXES)} files; "
        f"found {len(every)} section citations across {files} files."
    )
    if args.list:
        for c in sorted(every, key=lambda c: (c.path, c.line)):
            mark = "OK " if c.section in sections else "BAD"
            print(f"  {mark} {c.path}:{c.line}  section {c.section}  {c.text!r}")

    if broken:
        print(f"\n{len(broken)} citation(s) name a section {_ANCHOR} does not define:")
        for c in sorted(broken, key=lambda c: (c.path, c.line)):
            print(f"  {c.path}:{c.line} cites section {c.section}: {c.text!r}")
        print(
            f"\n{_ANCHOR} defines only {sorted(sections)}. Either the citation is wrong, or a "
            f"section was renumbered and its citers were not updated."
        )
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
