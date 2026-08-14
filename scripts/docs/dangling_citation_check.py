# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Report a `#N` backlog citation that names NO ITEM AT ALL (BACKLOG #1235).

NOT `backlog_citation_check.py`, WHICH SITS BESIDE THIS FILE AND ANSWERS A DIFFERENT QUESTION.
That gate (BACKLOG #1095) resolves a citation against the ledger FILE its item lives in, so a
reference naming the live `docs/BACKLOG.md` for an item that has been archived is caught -- the
number is real, the path is stale. This one asks whether the number names anything whatsoever.
An item that exists in either ledger is invisible here and is that gate's business; a number that
exists in neither is invisible there and is this one's. Neither subsumes the other, and the near-
identical names are the reason this paragraph is the first thing in the file.

WHAT THE DEFECT IS. While a number names nothing, a citation to it resolves to NOTHING -- honest and
harmless, and it advertises its own brokenness. If that number is later issued, the citation starts
resolving to unrelated work and NOTHING anywhere reports a problem. The ledger's own erratum names
that as the worse outcome: a wrongly-resolving reference "reads as a working cross-reference
forever". This tool catches the citation while it is still in the honest state.

THE DISTINCTION THAT DECIDES WHETHER A CITATION IS A TRAP, and it is not the obvious one. Two very
different states both look like "resolves to nothing", and only one of them can ever arm:

  * BELOW THE HIGH-WATER MARK. `scripts/coord/alloc.ps1` starts its search at ``$observed + 1`` and
    scans UPWARD, never filling a hole -- "numbers are never reclaimed ... holes are free,
    collisions are not". A number at or below the mark is therefore unreachable FOREVER, and the
    citation is harmless permanently rather than by luck. Measured here: 26 of 32 hits.
  * ABOVE IT. That number will be issued in the normal course, and on the day it is, the citation
    silently starts naming unrelated work. This is the only shape that can arm.

A tool reporting only "resolves in the ledger or not" rates those identically and raises 26 false
alarms on this repository alone.

WHY THE FLOOR AND NOT THE ALLOCATION REGISTRY. An earlier version of this tool classified by looking
for an allocation RECORD under the git common dir. It produced the same answers and rested on the
wrong thing: those records are machine-local, uncommittable and losable, so garbage-collecting a
directory would appear to change a conclusion that never depended on it. The unreachability is a
structural property of how the allocator picks a number. Reasoning from the registry makes a sound
property look fragile and invites a guard nothing needs.

WHY A TOOL AND NOT VIGILANCE. There is no gate on either side. `alloc.ps1` answers "is this number
free"; nothing asks "is anything already pointing at it". The two halves are each individually
correct, and the gap between them is the defect.

WHAT THIS DELIBERATELY DOES NOT DO.

  * It does NOT claim a defect count. Its output is an UPPER BOUND ON CITATIONS -- some hits are
    near-certainly not backlog references at all (a four-digit token in a research evaluation, one
    inside a diagram). Reporting the raw number as a defect count would be a completeness claim the
    scan cannot support, so the summary says so in those words rather than leaving it to be
    inferred. Every hit is printed with its file, line and full source line so a human judges it.
  * It does NOT sweep or edit. Fixing existing instances is a separate, owner-present task.
  * It does NOT see the private companion repository, where the known instances live. A citation in
    another repository is invisible to every check this one runs -- that limitation is inherent, is
    the reason the item exists, and is printed rather than left implicit.

The allocated set is read through `backlog_status_check.parse_items`, never a hand-rolled scan:
that module DEFINES what an item is, and a second definition here would drift from it silently.
"""

from __future__ import annotations

import argparse
import importlib.util
import re
import sys
from pathlib import Path
from typing import NamedTuple

_HERE = Path(__file__).resolve().parent

# The window the item pinned. Numbers below 1000 are the pre-partition internal sequence and the
# repository's PR/issue numbers, which share the `#N` spelling and are NOT backlog citations.
_LOW = 1000
_HIGH = 9000

#: A citation is `#` immediately followed by digits AND ENDING THERE. A Markdown heading
#: (`## 1235.`) puts a SPACE between, so it cannot match -- which matters, because every item
#: heading in the ledger would otherwise report as a citation of itself.
#:
#: The trailing boundary is not cosmetic. Without it, a CSS/Mermaid hex colour matches its own digit
#: prefix: `#1565c0` reads as a citation of #1565 and `#06302b` as one of #6302. Measured on the
#: first real run over docs/ -- those two alone produced 8 of 40 hits, all spurious, across
#: ARCHITECTURE.md and architecture-diagram.md. An inflated count in a tool whose entire output is a
#: bound is the one failure that makes it useless.
_CITATION = re.compile(r"#(\d+)(?![0-9A-Za-z])")

#: A `#N` introduced by one of these is a PULL REQUEST, issue or forum reference, not a backlog
#: citation. This repository's PR numbers ALREADY exceed 1000 (`PR #995`, `PR #1001` are both cited
#: in docs/adr/), so the [1000,9000) window does not separate the two namespaces on its own --
#: measured, not assumed. Matching hits are still REPORTED and still COUNTED; they are only
#: annotated, because this item's discipline is to DISCLOSE a false positive rather than trim it.
_PR_CONTEXT = re.compile(r"(?i)\b(?:PR|pull request|commit|issue|discussion)\s+$")

#: `pyodbc#1459`, `coder/code-server#6256` -- a `#N` glued to an identifier is ANOTHER PROJECT's
#: issue number. Both shapes are live in docs/ today.
_FOREIGN_REPO = re.compile(r"[A-Za-z0-9_./-]$")


class Hit(NamedTuple):
    path: Path
    lineno: int
    number: int
    line: str
    pr_shaped: bool


def _load_backlog_module() -> object:
    """Import backlog_status_check by path -- it is a script directory, not an installed package."""
    spec = importlib.util.spec_from_file_location(
        "_backlog_status_check", _HERE / "backlog_status_check.py"
    )
    if spec is None or spec.loader is None:  # pragma: no cover - a packaging accident, not a state
        raise RuntimeError("cannot load backlog_status_check.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def allocation_floor(sources: list[Path] | None = None) -> int:
    """The highest item number the ledgers know about. Nothing at or below it can ever be issued.

    THIS IS A STRUCTURAL PROPERTY OF THE ALLOCATOR, NOT A FACT ABOUT ANY REGISTRY FILE.
    `scripts/coord/alloc.ps1` starts its search at ``$observed + 1`` (or
    ``[Math]::Max($observed, $PublicBacklogFloor - 1) + 1`` under the public clamp) and scans
    UPWARD. It never fills a hole: "numbers are never reclaimed ... holes are free, collisions are
    not". So a number at or below the high-water mark is unreachable **forever**, and a number above
    it will be issued in the normal course. That is the whole classification.

    An earlier version of this tool read the allocation records under the git common dir instead.
    That gave the same answers here and was the wrong basis: those records are machine-local,
    uncommittable and losable, so garbage-collecting a directory would have "changed" a conclusion
    that does not actually depend on it. Reasoning from the registry makes a sound property look
    fragile and invites a guard nothing needs.

    Deliberately conservative: the true floor is the max over origin/main, every ref AND every
    allocation, so this ledger-only figure can only ever be LOWER. A number between the two is
    reported as reachable when it is not -- an over-warning, never a missed trap.
    """
    numbers = allocated_numbers(sources)
    return max(numbers) if numbers else 0


def allocated_numbers(sources: list[Path] | None = None) -> set[int]:
    """Every item number that EXISTS in the ledgers, open or closed.

    Closed items are included deliberately: a citation to a closed item resolves correctly and is
    not this defect. Only a number that names nothing at all is the trap.
    """
    module = _load_backlog_module()
    paths = sources if sources is not None else [Path(p) for p in module.DEFAULT_SOURCES]  # type: ignore[attr-defined]
    numbers: set[int] = set()
    for path in paths:
        if not path.exists():
            continue
        for item in module.parse_items(path.read_text(encoding="utf-8")):  # type: ignore[attr-defined]
            numbers.add(item.num)
    return numbers


def citations_in(text: str) -> list[tuple[int, int, str, bool]]:
    """(lineno, number, line, pr_shaped) for every in-window `#N` token. 1-indexed lines."""
    found: list[tuple[int, int, str, bool]] = []
    for lineno, line in enumerate(text.splitlines(), start=1):
        for match in _CITATION.finditer(line):
            number = int(match.group(1))
            if _LOW <= number < _HIGH:
                before = line[: match.start()]
                pr_shaped = (
                    _PR_CONTEXT.search(before) is not None
                    or _FOREIGN_REPO.search(before) is not None
                )
                found.append((lineno, number, line.strip(), pr_shaped))
    return found


def unresolved_citations(paths: list[Path], allocated: set[int]) -> list[Hit]:
    hits: list[Hit] = []
    for path in paths:
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        for lineno, number, line, pr_shaped in citations_in(text):
            if number not in allocated:
                hits.append(Hit(path, lineno, number, line, pr_shaped))
    return hits


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("paths", nargs="*", type=Path, help="files to scan (default: docs/**/*.md)")
    parser.add_argument(
        "--fail", action="store_true", help="exit non-zero when any citation is unresolved"
    )
    args = parser.parse_args(argv)

    # A scanner that CRASHES partway prints a partial list that reads as a complete one. Source lines
    # legitimately carry characters a stock Windows cp1252 console cannot encode, and this tool hit
    # exactly that on its first real run (U+2194, inside an ADR). Force UTF-8 and KEEP errors=replace:
    # the defect is the wrong codec, and replacement is what stops one exotic glyph truncating a
    # measurement.
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")

    paths = args.paths or sorted(Path("docs").rglob("*.md"))
    allocated = allocated_numbers()
    hits = unresolved_citations(list(paths), allocated)

    if not hits:
        print(f"No unresolved backlog citation in {len(paths)} file(s).")
        print(f"Resolved against {len(allocated)} allocated item numbers (open and closed).")
        return 0

    floor = allocation_floor()

    for hit in hits:
        note = (
            "  [PR/issue/foreign-repo shaped -- very likely NOT a backlog citation]"
            if hit.pr_shaped
            else ""
        )
        print(f"{hit.path}:{hit.lineno}: #{hit.number} resolves to no filed item{note}")
        print(f"    {hit.line}")
        state = (
            f"BELOW THE FLOOR ({floor}) -- the allocator only ever issues above its high-water "
            "mark, so this number can NEVER be issued and the citation is permanently harmless."
            if hit.number <= floor
            else f"ABOVE THE FLOOR ({floor}) -- this number CAN still be issued to unrelated work. "
            "This is the live shape."
        )
        print(f"    -> {state}")

    distinct = sorted({hit.number for hit in hits})
    pr_shaped = sum(1 for hit in hits if hit.pr_shaped)
    print()
    print(
        f"{len(hits)} token(s) across {len({h.path for h in hits})} file(s); "
        f"{len(distinct)} distinct number(s): {', '.join(f'#{n}' for n in distinct)}"
    )
    if pr_shaped:
        print(
            f"{pr_shaped} of those {len(hits)} TOKENS (not of the {len(distinct)} numbers) are "
            f"PR/issue/foreign-repo shaped, annotated above."
        )
    print(
        "This is an UPPER BOUND ON CITATIONS, NOT A COUNT OF DEFECTS -- some hits are very likely"
    )
    print("not backlog references at all. Each is printed above with its source line; judge them.")
    print(
        "Not scanned: the private companion repository, where a citation is invisible to this repo."
    )
    return 1 if args.fail else 0


if __name__ == "__main__":
    sys.exit(main())
