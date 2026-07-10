#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Backlog status-hygiene gate — every numbered item must declare exactly one status.

**Why this exists.** `docs/BACKLOG.md` rots silently: work ships, the item's banner is never
updated, and the file goes on describing finished work as open. On 2026-07-09 an audit found
**11 items misfiled as open** — including **#60** (turnkey DR), which shipped with ADR 0049 and a
working `messagefoundry backup` / `restore-verify` CLI while its banner still read *"PRE-RESERVED,
owner-gated"*. That stale banner was then copied into a merged PR as a factual claim. The same rot
left the Corepoint gap analysis ~22% obsolete: a fifth of it described work that no longer existed.

A doc that lies about build state is worse than no doc — it silently misdirects planning.

**The invariant.** Each `## <N>. <title>` item carries exactly one *status banner* among its leading
blockquotes:

    CLOSED   ✅ shipped/done      ⛔ declined      🪦 retired/tombstoned
    OPEN     🔢 prioritized       🚧 in progress / PR pending

An item with no status banner, or with both a CLOSED and an OPEN banner, is an error. Duplicate item
numbers are an error. This is a *structural* check: it cannot know whether a banner is truthful, only
that a claim exists and does not contradict itself. Truthfulness is enforced at the point work lands,
by the `BACKLOG #N` rule in `.github/workflows/backlog-hygiene.yml`.

**Advisory cross-reference.** With `--changelog`, items still marked OPEN that the CHANGELOG cites as
shipped are reported as warnings (never fatal). `#N` is ambiguous in this repo — it may be a backlog
item *or* a PR number — so only the unambiguous forms are matched: `BACKLOG #N`, and `(#N, [ADR ...`
(the convention that misfiled #60).

Usage::

    python scripts/docs/backlog_status_check.py
    python scripts/docs/backlog_status_check.py --changelog CHANGELOG.md

Exit 1 on errors; warnings alone keep it green.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

# Variation Selector-16 may follow an emoji; accept it. Anchored at the start of a blockquote line so
# that prose merely *containing* a word like "DECLINE" (e.g. the "Decline overturned" note) is never
# mistaken for a status claim.
_CLOSED = "✅⛔🪦"
_OPEN = "🔢🚧"
_BANNER = re.compile(rf"^>\s(?P<emoji>[{_CLOSED}{_OPEN}])️?\s")
_HEADING = re.compile(r"^## (?P<num>\d+)\.\s")

# Unambiguous CHANGELOG citations of a *backlog item* (not a PR number), considered only on a change
# *entry* (a list bullet). Narrative prose that merely mentions an item — "the correctness edge is
# closed (… BACKLOG #82) or field-confirmed benign" — is a reference, not a shipped claim, and a
# noisy advisory is an ignored advisory.
_CL_BULLET = re.compile(r"^\s*[-*]\s")
_CL_EXPLICIT = re.compile(r"BACKLOG\s+#(\d+)", re.IGNORECASE)
_CL_ADR_FORM = re.compile(r"\(#(\d+),\s*\[?ADR", re.IGNORECASE)


class Item:
    """One numbered backlog item and the status banners in its leading blockquote block."""

    __slots__ = ("num", "line", "closed", "open")

    def __init__(self, num: int, line: int) -> None:
        self.num = num
        self.line = line
        self.closed: list[str] = []
        self.open: list[str] = []

    @property
    def is_open(self) -> bool:
        return bool(self.open) and not self.closed


def parse_items(text: str) -> list[Item]:
    """Extract each item and classify the status banners in its leading blockquote block.

    The banner block runs from the heading to the first line that is neither blank nor a blockquote,
    so a status banner must appear *before* the item's prose (Cluster/Scope/Why...).
    """
    lines = text.splitlines()
    items: list[Item] = []
    i = 0
    while i < len(lines):
        m = _HEADING.match(lines[i])
        if not m:
            i += 1
            continue
        item = Item(int(m.group("num")), i + 1)
        j = i + 1
        while j < len(lines):
            line = lines[j]
            if line.strip() == "" or line.startswith(">"):
                b = _BANNER.match(line)
                if b:
                    emoji = b.group("emoji")
                    (item.closed if emoji in _CLOSED else item.open).append(emoji)
                j += 1
                continue
            break
        items.append(item)
        i = j
    return items


def scan(backlog: str, changelog: str | None = None) -> tuple[list[str], list[str]]:
    """Return ``(errors, warnings)``. Empty ``errors`` means the gate passes."""
    errors: list[str] = []
    warnings: list[str] = []
    items = parse_items(backlog)

    seen: dict[int, int] = {}
    for it in items:
        if it.num in seen:
            errors.append(
                f"BACKLOG.md:{it.line}: item #{it.num} is a duplicate "
                f"(first defined at line {seen[it.num]})"
            )
        else:
            seen[it.num] = it.line

        if not it.closed and not it.open:
            errors.append(
                f"BACKLOG.md:{it.line}: item #{it.num} declares no status. Add exactly one leading "
                f"banner: '> ✅ **SHIPPED …**', '> ⛔ **DECLINED …**', '> 🪦 **RETIRED …**', "
                f"'> 🔢 **Re-prioritized …**', or '> 🚧 **Status …**'."
            )
        elif it.closed and it.open:
            errors.append(
                f"BACKLOG.md:{it.line}: item #{it.num} contradicts itself — it carries both a closed "
                f"banner ({''.join(it.closed)}) and an open banner ({''.join(it.open)}). "
                f"A shipped/declined item must not also carry a priority."
            )

    if changelog is not None:
        open_nums = {it.num for it in items if it.is_open}
        cited: set[int] = set()
        for line in changelog.splitlines():
            if not _CL_BULLET.match(line):
                continue
            for pat in (_CL_EXPLICIT, _CL_ADR_FORM):
                cited.update(int(n) for n in pat.findall(line))
        for num in sorted(cited & open_nums):
            warnings.append(
                f"item #{num} is cited as shipped in CHANGELOG.md but is still marked OPEN in "
                f"BACKLOG.md — verify and add a ✅ banner if the work landed."
            )
    return errors, warnings


def main(argv: list[str] | None = None) -> int:
    root = Path(__file__).resolve().parents[2]
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("--backlog", type=Path, default=root / "docs" / "BACKLOG.md")
    ap.add_argument(
        "--changelog", type=Path, default=None, help="cross-check (advisory, never fatal)"
    )
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args(argv)

    backlog = args.backlog.read_text(encoding="utf-8")
    changelog = args.changelog.read_text(encoding="utf-8") if args.changelog else None
    errors, warnings = scan(backlog, changelog)

    for w in warnings:
        print(f"WARN: {w}", file=sys.stderr)
    for e in errors:
        print(f"ERROR: {e}", file=sys.stderr)

    if errors:
        print(
            f"\n{len(errors)} error(s). Every backlog item must declare exactly one status banner.\n"
            "A doc that lies about build state silently misdirects planning — see this file's docstring.",
            file=sys.stderr,
        )
        return 1
    if not args.quiet:
        n = len(parse_items(backlog))
        extra = f" ({len(warnings)} advisory warning(s))" if warnings else ""
        print(f"OK — {n} backlog items, each declaring exactly one status{extra}.")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
