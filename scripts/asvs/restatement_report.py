# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""WHERE DOES A DOCUMENT RESTATE AN ANCHORED CLAIM AT A LINE NO ANCHOR POINTS AT?

BACKLOG #1396. A graded row in the scorecard cites lines of a prose document as its evidence. A
repair pass tends to visit those lines and nothing else, so a wrong restatement of the same claim
elsewhere in the file survives every pass. When it sits EARLIER than the anchor, a reader meets the
wrong version first. The anchor set records where evidence was found, never where the claim is
repeated, and treating it as a work list is the defect.

**What this does.** For each graded row and each prose file (``.md``) it cites, it takes the
backticked spans on the anchored lines as the row's claim keys: config keys, routes, flags and
symbols, which are the words a stale claim most often gets wrong and which grep finds verbatim. It
then lists every line of that file that carries a key as a whole token and is not one of the row's
own anchored lines. A line before the first anchored line carrying that key is EARLY; any other is
LATER. A line two rows both reach is listed once.

**What this cannot do, stated so nobody reads more into a short list than is there.**

* It finds restatements, not contradictions. Whether a line disagrees with the anchor is a reading.
* A prose anchor that no longer resolves has no line, so it is not searched. The report counts them.
* An anchored line with no backticked span has no key, so its claim is never searched. The report
  counts those lines, and that count is the part of the record this instrument does not reach.
* A key on more than ``--max-hits`` unanchored lines of its file is skipped as too common to
  discriminate. That count is printed too, so a raised cap shows what it costs in noise.

**Disclosure.** No requirement identifier and no verdict: the finding type has no field for either,
so no later edit can print one. It prints MORE than ``anchor_report.py`` does, namely the document
lines that serve as evidence. So this is a local instrument. Do not wire it into a workflow whose
log is public, and do not paste its output into a public pull request.

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

from anchor_report import EXIT_OK, _refuse, _refuse_unreadable, provenance  # noqa: E402
from scorecard import ANCHOR_LOCATED, Cell, load_scorecard, locate_anchor  # noqa: E402

#: Prose documents only. A code file restating a key is a call site, not a second claim.
PROSE_SUFFIX = ".md"
#: One backticked span. Matched at ANY length so the backtick pairing stays right when a line has a
#: short span such as `on`; the length floor is applied afterwards, in :func:`claim_keys`.
SPAN = re.compile(r"`([^`\n]+)`")
MIN_KEY = 3
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
    findings: dict[tuple[str, int, str], Restatement] = field(default_factory=dict)
    anchored: set[tuple[str, int]] = field(default_factory=set)
    keyless: set[tuple[str, int]] = field(default_factory=set)
    common: set[tuple[str, str]] = field(default_factory=set)
    unresolved: int = 0


def claim_keys(text: str) -> list[str]:
    """The backticked spans in ``text`` of at least MIN_KEY characters, first appearance order."""
    return list(dict.fromkeys(k for k in SPAN.findall(text) if len(k.strip()) >= MIN_KEY))


def _hits(lines: list[str], key: str) -> list[int]:
    # Whole-token match: `require_mfa` must not be found inside `require_mfa_for_admins`.
    token = re.compile(rf"(?<![A-Za-z0-9_]){re.escape(key)}(?![A-Za-z0-9_])")
    return [n for n, text in enumerate(lines, start=1) if token.search(text)]


def census(cells: list[Cell], root: Path, *, max_hits: int) -> Census:
    """Every unanchored restatement of every row's claim keys, per prose file the row cites."""
    result = Census()
    texts: dict[str, str | None] = {}
    lines_of: dict[str, list[str]] = {}
    hits_of: dict[tuple[str, str], list[int]] = {}
    for cell in cells:
        spans: dict[str, set[int]] = {}
        for anchor in cell.evidence:
            if not anchor.path.endswith(PROSE_SUFFIX):
                continue
            if anchor.path not in texts:
                target = root / anchor.path
                text = (
                    target.read_text(encoding="utf-8", errors="replace")
                    if target.is_file()
                    else None
                )
                texts[anchor.path] = text
                # split("\n"), NOT splitlines(): locate_anchor numbers lines by "\n" alone, and
                # splitlines() also breaks on form feeds and U+2028, which would shift every number.
                lines_of[anchor.path] = text.split("\n") if text is not None else []
            text = texts[anchor.path]
            # The one locator the gate uses. A token that is gone or ambiguous has no line, and a
            # guessed line would search from a place the record does not actually point at.
            found = locate_anchor(text, anchor.expect) if text is not None else None
            if found is None or found.status != ANCHOR_LOCATED or found.line is None:
                result.unresolved += 1
                continue
            last = found.line + anchor.expect.rstrip("\n").count("\n")
            spans.setdefault(anchor.path, set()).update(range(found.line, last + 1))
        for path, anchored in spans.items():
            _scan(result, path, lines_of[path], anchored, max_hits, hits_of)
    return result


def _scan(
    result: Census,
    path: str,
    lines: list[str],
    anchored: set[int],
    max_hits: int,
    hits_of: dict[tuple[str, str], list[int]],
) -> None:
    source: dict[str, int] = {}
    for n in sorted(anchored):
        result.anchored.add((path, n))
        keys = claim_keys(lines[n - 1]) if n <= len(lines) else []
        if not keys:
            result.keyless.add((path, n))
        for key in keys:
            source.setdefault(key, n)
    for key, anchor_line in source.items():
        if (path, key) not in hits_of:
            hits_of[(path, key)] = _hits(lines, key)
        unanchored = [n for n in hits_of[(path, key)] if n not in anchored]
        if len(unanchored) > max_hits:
            result.common.add((path, key))
            continue
        for n in unanchored:
            position = EARLY if n < anchor_line else LATER
            seen = result.findings.get((path, n, key))
            # A line two rows reach is one line. EARLY wins, because it is the one a reader meets
            # before any anchored statement of the claim.
            if seen is None or (position == EARLY and seen.position == LATER):
                result.findings[(path, n, key)] = Restatement(path, n, key, anchor_line, position)


def render(
    result: Census, *, max_hits: int, early_only: bool, scorecard: Path, root: Path
) -> list[str]:
    findings = list(result.findings.values())
    early = sum(1 for f in findings if f.position == EARLY)
    shown = sorted(
        (f for f in findings if f.position == EARLY or not early_only),
        key=lambda f: (f.position != EARLY, f.path, f.line, f.key, f.anchor_line),
    )
    out = [
        provenance("asvs-restatement-report", scorecard, root),
        "ASVS restatement report -- where is an anchored claim repeated where no anchor looks?",
        f"  prose anchors NOT resolving   : {result.unresolved} (not searched)",
        f"  anchored prose lines searched : {len(result.anchored)}",
        f"  of those, carrying NO key     : {len(result.keyless)} (their claim is NOT searched)",
        f"  keys skipped as too common    : {len(result.common)} (more than {max_hits} other lines)",
        f"  EARLY restatements            : {early} (before the anchored line carrying the key)",
        f"  LATER restatements            : {len(findings) - early}",
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
    if not result.anchored:
        # An empty search space would print a reassuring zero that examined nothing.
        return _refuse("no prose anchor resolved in this tree, so nothing was searched")
    report = render(
        result,
        max_hits=args.max_hits,
        early_only=args.early_only,
        scorecard=args.scorecard,
        root=args.root,
    )
    # Keys are quoted from the documents, and some carry characters a cp1252 console cannot encode.
    # Escape them rather than die mid-report with a traceback that exits 1, the findings code.
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(errors="backslashreplace")
    print("\n".join(report))
    return EXIT_OK


if __name__ == "__main__":
    raise SystemExit(main())
