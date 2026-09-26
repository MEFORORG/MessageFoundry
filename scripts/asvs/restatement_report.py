# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""WHERE DOES A DOCUMENT RESTATE AN ANCHORED CLAIM AT A LINE NO ANCHOR POINTS AT?

BACKLOG #1396. A graded row in the scorecard cites lines of a prose document as its evidence. A
repair pass tends to visit those lines and nothing else, so a wrong restatement of the same claim
elsewhere in the file survives every pass. When it sits EARLIER than the row's first anchor, a reader
meets the wrong version first. The anchor set records where evidence was found, never where the
claim is repeated, and treating it as a work list is the defect.

**What this does.** For each graded row and each prose file (``.md``) it cites, it takes the
backticked spans on the anchored lines as the row's claim keys: config keys, routes, flags and
symbols, which are the words a stale claim most often gets wrong and which grep finds verbatim. It
then lists every line of that file that carries a key and is not one of the row's own anchored lines.
A line before the row's first anchor is EARLY; any other is LATER.

**What this cannot do, stated so nobody reads more into a short list than is there.**

* It finds restatements, not contradictions. Whether a line disagrees with the anchor is a reading.
* An anchored line with no backticked span has no key, so its claim is never searched. The report
  counts those lines, and that count is the part of the record this instrument does not reach.
* A key on more than ``--max-hits`` lines of its file is skipped as too common to discriminate.
  That count is printed too, so a raised cap shows what it costs in noise.

**Disclosure.** Same rule as ``anchor_report.py``: file paths, line numbers and counts, and never a
requirement identifier or a verdict. The finding type has no field for either, so no later edit can
print one. A key is quoted from the engine document, which is public.

Usage::

    python scripts/asvs/restatement_report.py --scorecard <vault>/docs/security/asvs-scorecard.toml \\
        --root <engine checkout> [--max-hits 3] [--early-only]
"""

from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

# Imported by PATH, as the sibling tools do: scripts/asvs has no __init__.py and the vault runs
# these as bare scripts with only this directory on sys.path.
sys.path.insert(0, str(Path(__file__).resolve().parent))

from anchor_report import EXIT_OK, _refuse, _refuse_unreadable  # noqa: E402
from scorecard import ANCHOR_LOCATED, Cell, load_scorecard, locate_anchor  # noqa: E402

#: Prose documents only. A code file restating a key is a call site, not a second claim.
PROSE_SUFFIX = ".md"
#: A backticked span of at least three characters on one line.
KEY = re.compile(r"`([^`\n]{3,})`")
EARLY = "EARLY"
LATER = "LATER"


@dataclass(frozen=True)
class Restatement:
    """One unanchored line carrying a claim key. There is NO requirement field, by construction."""

    path: str
    line: int
    key: str
    anchor_line: int
    position: str


@dataclass
class Census:
    findings: set[Restatement] = field(default_factory=set)
    anchored_lines: int = 0
    keyless_lines: int = 0
    common_keys: int = 0


def claim_keys(text: str) -> list[str]:
    """The backticked spans in ``text``, in order of first appearance, without repeats."""
    return list(dict.fromkeys(KEY.findall(text)))


def census(cells: list[Cell], root: Path, *, max_hits: int) -> Census:
    """Every unanchored restatement of every row's claim keys, per prose file the row cites."""
    result = Census()
    cache: dict[str, str | None] = {}
    for cell in cells:
        spans: dict[str, list[tuple[int, int]]] = {}
        for anchor in cell.evidence:
            if not anchor.path.endswith(PROSE_SUFFIX):
                continue
            if anchor.path not in cache:
                target = root / anchor.path
                cache[anchor.path] = (
                    target.read_text(encoding="utf-8", errors="replace")
                    if target.is_file()
                    else None
                )
            text = cache[anchor.path]
            if text is None:
                continue
            # The one locator the gate uses. A token that is gone or ambiguous has no line, and a
            # guessed line would search from a place the record does not actually point at.
            found = locate_anchor(text, anchor.expect)
            if found.status != ANCHOR_LOCATED or found.line is None:
                continue
            last = found.line + anchor.expect.count("\n")
            spans.setdefault(anchor.path, []).append((found.line, last))
        for path, cited in spans.items():
            _scan(result, path, (cache[path] or "").splitlines(), cited, max_hits)
    return result


def _scan(
    result: Census, path: str, lines: list[str], cited: list[tuple[int, int]], max_hits: int
) -> None:
    anchored = {n for first, last in cited for n in range(first, last + 1)}
    first_anchor = min(anchored)
    source: dict[str, int] = {}
    for n in sorted(anchored):
        keys = claim_keys(lines[n - 1]) if n <= len(lines) else []
        result.anchored_lines += 1
        if not keys:
            result.keyless_lines += 1
        for key in keys:
            source.setdefault(key, n)
    for key, anchor_line in source.items():
        hits = [i for i, text in enumerate(lines, start=1) if key in text]
        if len(hits) > max_hits:
            result.common_keys += 1
            continue
        for n in hits:
            if n not in anchored:
                position = EARLY if n < first_anchor else LATER
                result.findings.add(Restatement(path, n, key, anchor_line, position))


def render(result: Census, *, max_hits: int, early_only: bool) -> list[str]:
    early = sum(1 for f in result.findings if f.position == EARLY)
    shown = sorted(
        (f for f in result.findings if f.position == EARLY or not early_only),
        key=lambda f: (f.position != EARLY, f.path, f.line, f.key),
    )
    out = [
        "ASVS restatement report -- where is an anchored claim repeated where no anchor looks?",
        f"  anchored prose lines searched : {result.anchored_lines}",
        f"  of those, carrying NO key     : {result.keyless_lines} (their claim is NOT searched)",
        f"  keys skipped as too common    : {result.common_keys} (on more than {max_hits} lines)",
        f"  EARLY restatements            : {early} (before the row's first anchor)",
        f"  LATER restatements            : {len(result.findings) - early}",
    ]
    if shown:
        out.append("")
        out.extend(
            f"  {f.position:<5}  {f.path}:{f.line}  restates `{f.key}`  (anchored at :{f.anchor_line})"
            for f in shown
        )
        out.append("")
        out.append(
            "REPORTED, NOT JUDGED. Each line repeats a key an anchored line carries. Read it against "
            "that line: agreement needs no change, and an EARLY disagreement is the one a reader "
            "meets first."
        )
    return out


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Unanchored restatements of anchored claims.")
    parser.add_argument("--scorecard", type=Path, required=True)
    parser.add_argument("--root", type=Path, required=True, help="the ENGINE checkout")
    parser.add_argument("--max-hits", type=int, default=3)
    parser.add_argument("--early-only", action="store_true")
    args = parser.parse_args(argv)

    if args.max_hits < 1:
        return _refuse("--max-hits must be at least 1")
    if not args.scorecard.is_file():
        return _refuse(f"no scorecard at {args.scorecard}. This run read nothing.")
    if not args.root.is_dir():
        return _refuse(f"--root {args.root} is not a directory")
    try:
        if args.scorecard.resolve().is_relative_to(args.root.resolve()):
            return _refuse(
                f"--root {args.root} CONTAINS the scorecard, so the documents searched would be the "
                "record's own copies rather than the engine's. Pass the engine checkout."
            )
    except (OSError, ValueError):
        return _refuse(f"could not resolve {args.scorecard} against {args.root} to compare them")
    try:
        cells = load_scorecard(args.scorecard)
    except Exception as exc:
        # Broad on purpose, for the reason anchor_report.py gives at the same boundary.
        return _refuse_unreadable(args.scorecard, exc)

    result = census(cells, args.root, max_hits=args.max_hits)
    if result.anchored_lines == 0:
        # An empty search space would print a reassuring zero that examined nothing.
        return _refuse("no prose anchor resolved in this tree, so nothing was searched")
    print("\n".join(render(result, max_hits=args.max_hits, early_only=args.early_only)))
    return EXIT_OK


if __name__ == "__main__":
    raise SystemExit(main())
