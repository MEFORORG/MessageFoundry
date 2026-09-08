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

**The namespace spans more than one file.** `docs/BACKLOG.md` carries the OPEN items; retired ones are
moved verbatim into `docs/archive/backlog/`. Every default source is parsed into ONE namespace, so a
number re-used across the two is a duplicate — scanning them separately would make that collision
structurally undetectable, which is the same blind spot the file's own Ledger erratum records.

**`--min-items` is the anti-narrowing floor, and it is not optional in CI.** Every other assertion here
is satisfied just as well by a remnant of the corpus as by all of it: move items to a file this script
does not read and it goes green over what is left, having checked a third of the items while reporting
success. The count alone cannot distinguish "items were closed" from "a file stopped being scanned",
so the scanned files are always printed alongside it.

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
from collections.abc import Sequence
from pathlib import Path

# The files that together hold the numbered item namespace, relative to the repo root. The published
# backlog carries the OPEN items; the archive carries retired ones verbatim. Both are scanned as ONE
# namespace — see scan() — because a number re-used across the two is invisible to a per-file check.
# Adding an archive file here is the ONLY place that has to change; --min-items then keeps it honest.
DEFAULT_SOURCES = (
    Path("docs/BACKLOG.md"),
    Path("docs/archive/backlog/BACKLOG-CLOSED.md"),
)


def _label(path: Path, root: Path) -> str:
    """Repo-relative label for messages — an absolute temp path in an error helps nobody."""
    try:
        return path.resolve().relative_to(root).as_posix()
    except ValueError:
        return path.as_posix()


# Variation Selector-16 may follow an emoji; accept it. Anchored at the start of a blockquote line so
# that prose merely *containing* a word like "DECLINE" (e.g. the "Decline overturned" note) is never
# mistaken for a status claim.
_CLOSED = "✅⛔🪦"
_OPEN = "🔢🚧"
_BANNER = re.compile(rf"^>\s(?P<emoji>[{_CLOSED}{_OPEN}])️?\s")
_HEADING = re.compile(r"^## (?P<num>\d+)\.\s")

# Machine-readable state inside the banner blockquote: `> Verdict: build`. Only these three keys are
# recognised, because an open key set is a second, undocumented schema. They are deliberately IN the
# banner block -- the only region this parser reads.
_FIELD_KEYS = ("verdict", "research", "closing-act")
_FIELD = re.compile(rf"^>\s*(?P<key>{'|'.join(_FIELD_KEYS)})\s*:\s*(?P<value>.+?)\s*$", re.I)

# A value/difficulty SCORE inside the banner block. Deliberately keyed on the SCORE ITSELF and not
# on the sentence that usually introduces one: `Scored 2026-09-04 ->` and `Re-scored 2026-08-20 ->`
# are both common, but #1435 carries its numbers inline in a filing banner with neither phrase, and
# a check keyed on the phrase reports that correctly-scored row as unscored. Measured 2026-09-05:
# phrase-keyed and score-keyed censuses disagreed on exactly that row.
#
# The bold markers are optional because the ledger is not uniform -- #1312 was hand-written with
# `--` separators and no emphasis -- and a gate that only sees the house style teaches filers a
# magic string instead of a score.
_SCORE = re.compile(r"[Vv]alue\s*\**\s*(?P<value>\d+)\s*/\s*10", re.I)

# Closing acts a BUILDER can perform themselves. An item outside this set is still WORKABLE -- the
# seat writes the code and finishes with an open item, which is a complete outcome, not a failure.
#
# CANNOT CLOSE IS NOT CANNOT BE WORKED. Measured 2026-08-22: refusing every non-code closing act
# would have blocked #1112, #1171 and #1187, all of which reached main -- #1171 being the SMTP
# credential-exposure fix. The first version of the dispatch gate did exactly that, and this comment
# exists because the constant's old name (BUILDABLE_) invited the conflation.
BUILDER_CLOSABLE_ACTS = frozenset({"code"})

# Who performs each closing act. A dispatch NAMES this rather than refusing the item.
#
# EVERY ENTRY NAMES TWO ACTS, AND THAT IS THE POINT. The first version said "scorecard-rescore: the
# ASVS Tracker" -- one seat -- and a reader concludes the item finishes there. It does not.
# `BUILDER.md:253` forbids a builder concluding an item CLOSED ("banner flips and ledger reconciles
# are not the builder's") and `:148` gives the banner to the LANDER. So the work act and the banner
# act have different owners, and the handoff between them is where an item stalls: the re-score
# lands in a vault file gitignored from every engine checkout, so the seat that must flip the banner
# cannot see that the first act happened. Both seats do their job correctly and the item stays open.
#
# Naming only the first act is how a tool tells a reader the item is somebody else's problem, when
# what it actually needs is a message.
CLOSING_SEAT = {
    "code": "the builder writes it; the LANDER flips the banner on merge",
    "scorecard-rescore": (
        "the ASVS Tracker re-scores the cell in the vault, THEN mails the LANDER the item numbers "
        "for the banner flip. Two acts, two seats -- the re-score alone does not close it, and the "
        "vault file is invisible from an engine checkout, so the handoff must be a message"
    ),
    "owner-ruling": "the owner rules via the LIAISON; the Dispatcher or Lander records it",
    "banner-only": "the DISPATCHER or LANDER, in the ledger",
}

# BACKLOG #1259: an unresolved git conflict parses CLEANLY here without this check, and the reason is
# specific -- `>>>>>>> branch` starts with ">", so the banner-block scanner below treats it as a
# blockquote line and keeps scanning rather than ending the block. Both sides' items are then read,
# and the census counts them all. Measured: the live ledger and a marker-poisoned copy of it produced
# IDENTICAL counts with no exception raised. The counts agreeing is what made it undetectable -- a
# reader handed a conflicted source reports a plausible number, not an error.
#
# `=======` is deliberately NOT matched. A Markdown setext H1 underline is a run of "=" and can be
# exactly seven, so matching it could refuse a legitimate ledger; every real conflict carries the
# other two markers, so leaving it out costs no detection and removes the false positive.
_CONFLICT = re.compile(r"^(?:<{7}|>{7})(?:\s|$)", re.M)

# Unambiguous CHANGELOG citations of a *backlog item* (not a PR number), considered only on a change
# *entry* (a list bullet). Narrative prose that merely mentions an item — "the correctness edge is
# closed (… BACKLOG #82) or field-confirmed benign" — is a reference, not a shipped claim, and a
# noisy advisory is an ignored advisory.
_CL_BULLET = re.compile(r"^\s*[-*]\s")
_CL_EXPLICIT = re.compile(r"BACKLOG\s+#(\d+)", re.IGNORECASE)
_CL_ADR_FORM = re.compile(r"\(#(\d+),\s*\[?ADR", re.IGNORECASE)


#: One field line that was overwritten by a later line for the same key: the key, the 1-based
#: line number of the SECOND occurrence, the value it displaced, and the value that displaced it.
DuplicateField = tuple[str, int, str, str]


class Item:
    """One numbered backlog item and the status banners in its leading blockquote block."""

    __slots__ = (
        "num",
        "line",
        "closed",
        "open",
        "fields",
        "duplicate_fields",
        "body_line",
        "score",
    )

    def __init__(self, num: int, line: int) -> None:
        self.num = num
        self.line = line
        # 1-based line where the banner block ENDS and the item's own prose begins. Published
        # because a reader that needs the prose alone would otherwise re-derive "where does the
        # banner stop", which is a second definition of the boundary this parser owns -- the same
        # single-source rule the banner alphabet already carries. `dispatch_gate.py` is the first
        # such reader: the 2026-09-03 scoring pass wrote a summary blockquote INTO the banner
        # block of #1334, and that summary quotes the retirement wording of the rows it describes,
        # so a needle reading the whole item flags the row that documents the convention.
        #
        # A hand-built Item has an empty banner block, so prose starts on the line after the
        # heading. `parse_items` overwrites this with the real boundary.
        self.body_line = line + 1
        self.closed: list[str] = []
        self.open: list[str] = []
        # Machine-readable state declared INSIDE the banner block, so `parse_items` can see it.
        # BACKLOG state that lives below the banner block is invisible to every tool that reads this
        # ledger: measured 2026-08-22, `Verdict:` is present on 302 of 328 items and every one sits
        # BELOW the line where this parser stops, so nothing has ever read it. A 30-item wave was
        # dispatched whose every item carried `Verdict: research` -- a verdict that has closed ZERO
        # times in 330 closed items -- and closed zero.
        self.fields: dict[str, str] = {}
        # A DUPLICATE FIELD LINE USED TO VANISH INTO THE ASSIGNMENT BELOW (#1338). `fields` is a
        # dict, so a second `> Research: ...` overwrote the first and left NO trace: item count,
        # open count and even `len(fields)` are identical with and without the duplicate -- and
        # those totals are the entire check every seat runs after a ledger edit. The reader could
        # not represent the defect, so nothing downstream could detect it.
        self.duplicate_fields: list[DuplicateField] = []
        # The value half of a value/difficulty score, when the banner block carries one, else
        # None. Only the value is kept: this parser's job is to answer WHETHER the row is
        # ranked, and storing the difficulty too would invite a reader to rank FROM here rather
        # than from the ranked table, which is the artefact that owns ordering.
        self.score: int | None = None

    @property
    def is_open(self) -> bool:
        return bool(self.open) and not self.closed


def parse_items(text: str) -> list[Item]:
    """Extract each item and classify the status banners in its leading blockquote block.

    The banner block runs from the heading to the first line that is neither blank nor a blockquote,
    so a status banner must appear *before* the item's prose (Cluster/Scope/Why...). That boundary
    is published as ``Item.body_line`` so a reader wanting the prose alone does not re-derive it.

    Raises :class:`ValueError` when ``text`` still carries git conflict markers (#1259). The refusal
    lives in the READER, not in a pre-commit hook, because the way this bit was a gate handed a tree
    IN MEMORY -- a merge-tree blob read before its exit code was checked. A hook on the working copy
    would not have been running at all.
    """
    conflict = _CONFLICT.search(text)
    if conflict is not None:
        line_no = text.count("\n", 0, conflict.start()) + 1
        raise ValueError(
            f"refusing to parse a source with an unresolved conflict marker (line {line_no}). "
            "This is not a formatting complaint: a conflicted ledger parses WITHOUT error here and "
            "yields a census that silently counts items from BOTH sides, so the number looks right. "
            "Resolve the merge, or check the merge's exit status, before reading it."
        )
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
                s = _SCORE.search(line)
                if s is not None and item.score is None:
                    # FIRST match wins, because the newest score sits FIRST in the block by this
                    # file's convention -- a re-score is prepended above the superseded one, which
                    # is often still present and explicitly labelled SUPERSEDED. Taking the last
                    # would read the retired number.
                    item.score = int(s.group("value"))
                f = _FIELD.match(line)
                if f:
                    key = f.group("key").strip().lower()
                    value = f.group("value").strip()
                    # Record before overwriting. `dispatch_gate.py` reads verdict / research /
                    # closing-act out of this dict and would otherwise act on whichever copy
                    # happened to come last, with nothing reporting that a second one existed.
                    if key in item.fields:
                        item.duplicate_fields.append((key, j + 1, item.fields[key], value))
                    item.fields[key] = value
                j += 1
                continue
            break
        item.body_line = j + 1
        items.append(item)
        i = j
    return items


def scan(
    sources: Sequence[tuple[str, str]], changelog: str | None = None
) -> tuple[list[str], list[str]]:
    """Return ``(errors, warnings)``. Empty ``errors`` means the gate passes.

    ``sources`` is ``(label, text)`` pairs — the published backlog *and* every archive file that
    holds retired items. They are parsed into **one namespace**: an item number must be unique
    across the whole set, not merely within the file it happens to live in. Scanning them
    separately is the failure this signature exists to prevent — a number re-used across
    ``docs/BACKLOG.md`` and an archive file is exactly the collision the file's own Ledger erratum
    documents, and a per-file ``seen`` map cannot see it.
    """
    errors: list[str] = []
    warnings: list[str] = []
    items: list[tuple[str, Item]] = []
    for label, text in sources:
        items.extend((label, it) for it in parse_items(text))

    seen: dict[int, tuple[str, int]] = {}
    for label, it in items:
        if it.num in seen:
            first_label, first_line = seen[it.num]
            where = f"line {first_line}" if first_label == label else f"{first_label}:{first_line}"
            errors.append(
                f"{label}:{it.line}: item #{it.num} is a duplicate (first defined at {where})"
            )
        else:
            seen[it.num] = (label, it.line)

        # THE CHECK ITSELF MUST REPORT IT, not merely the reader (#1338). This gate runs UNGATED
        # on every pull request including docs-only ones, which is the change shape that
        # introduces a duplicate; the pytest guard covers the same ground but rides a lane that a
        # curated allowlist could silently drop it from.
        for key, dup_line, displaced, kept in it.duplicate_fields:
            errors.append(
                f"{label}:{dup_line}: item #{it.num} declares '{key}' twice — {displaced!r} is "
                f"overwritten by {kept!r}. A duplicate moves NO count, so the item and open "
                f"totals every seat checks after a ledger edit report success over it, and "
                f"dispatch_gate.py then acts on whichever copy happened to come last."
            )

        if not it.closed and not it.open:
            errors.append(
                f"{label}:{it.line}: item #{it.num} declares no status. Add exactly one leading "
                f"banner: '> ✅ **SHIPPED …**', '> ⛔ **DECLINED …**', '> 🪦 **RETIRED …**', "
                f"'> 🔢 **Re-scored …**', or '> 🚧 **Status …**'."
            )
        elif it.closed and it.open:
            errors.append(
                f"{label}:{it.line}: item #{it.num} contradicts itself — it carries both a closed "
                f"banner ({''.join(it.closed)}) and an open banner ({''.join(it.open)}). "
                f"A shipped/declined item must not also carry a priority."
            )

    if changelog is not None:
        open_nums = {it.num for _, it in items if it.is_open}
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

    # ADVISORY ONLY, BY OWNER RULING 2026-09-05 (BACKLOG #1455, filed and not yet on main).
    #
    # An open row with no value or difficulty is absent from the ranked table while present in the
    # ledger, so the instrument that answers "what next" reads complete while being incomplete.
    # Measured over three days: 73 rows carried no score on 2026-09-03, 5 on 2026-09-04 and 1 on
    # 2026-09-05 -- each pass closed the gap and ordinary filing re-opened it, and none of the three
    # was found by a gate.
    #
    # WHY IT IS NOT FATAL, and this is the ruling rather than a hedge. This module runs in the
    # required `test` leg, so an error here would red the pull request of anyone who FILES an
    # unscored row. That prices filing, which is the act this project wants cheap, to buy ranking,
    # which a later pass can supply. The owner weighed advisory against a fatal gate and chose
    # advisory. Do not promote this to an error without a new ruling.
    #
    # CLOSED ROWS ARE EXEMPT BY DESIGN: a score prices the REMAINDER, and a shipped or declined row
    # has none, so demanding one there would ask for a number with no referent.
    #
    # KNOWN LIMIT, stated rather than discovered later: this sees the BANNER BLOCK only, because
    # that is all `parse_items` reads. A row whose score sits below the block would be reported
    # here as unscored. Measured 2026-09-05 over all 277 open rows: ZERO are shaped that way, every
    # scored row carries its numbers in the block, so the limit costs nothing today. It is written
    # down because the day a row is scored below the block, this advisory is wrong about it, and a
    # reader should reach for the boundary rather than for the score pattern.
    for label, it in items:
        if it.is_open and it.score is None:
            warnings.append(
                f"{label}:{it.line}: item #{it.num} is OPEN and carries no value/difficulty score, "
                f"so it is absent from the ranked table while present in the ledger. Add a "
                # ASCII ONLY, DELIBERATELY. Warnings go to STDERR, and main() hardens stdout
                # alone (#1030), so a middot here could raise UnicodeEncodeError on a stock
                # cp1252 console -- turning an advisory into a crash, which is the opposite of
                # advisory. The house separator is a middot; this says so in words instead.
                f"'Value **N/10**' and a difficulty, separated by a middot, inside the banner "
                f"block. "
                f"Advisory by owner ruling (BACKLOG #1455); this never fails the gate."
            )

    return errors, warnings


def main(argv: list[str] | None = None) -> int:
    # THIS MODULE MUST CARRY NON-cp1252 CHARACTERS, so it hardens the stream instead of losing them
    # (BACKLOG #1030). The docstring below is argparse's description and quotes the machine-parsed
    # banner alphabet CLAUDE.md section 11 protects; remediation text that cannot show an author the
    # character it wants added is not actionable. On a stock Windows cp1252 console `--help` therefore
    # raised UnicodeEncodeError on U+2705 before this line -- measured, not theorised.
    #
    # `errors="replace"` is deliberate and is NOT a way of tolerating mangled text: the codec is what
    # was wrong, and it is fixed here to UTF-8. Replacement is the backstop for a stream that cannot
    # be reconfigured at all, so one exotic codepoint can never again truncate a gate's output
    # mid-sentence. Scoped to the CLI entry point: importers get their own stdout untouched.
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")

    root = Path(__file__).resolve().parents[2]
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument(
        "--backlog",
        type=Path,
        action="append",
        dest="backlogs",
        metavar="PATH",
        help="a file holding numbered items; repeatable. Defaults to the published backlog plus "
        f"every archive file in {DEFAULT_SOURCES[1].parent.as_posix()}.",
    )
    ap.add_argument(
        "--min-items",
        type=int,
        default=None,
        metavar="N",
        help="fail when fewer than N items are found across every scanned file. This is the only "
        "guard against SILENT NARROWING — moving items to an archive the scan does not read "
        "leaves every other check passing over a smaller corpus.",
    )
    ap.add_argument(
        "--changelog", type=Path, default=None, help="cross-check (advisory, never fatal)"
    )
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args(argv)

    explicit = args.backlogs is not None
    paths = args.backlogs if explicit else [root / p for p in DEFAULT_SOURCES]

    sources: list[tuple[str, str]] = []
    missing: list[Path] = []
    for p in paths:
        if not p.exists():
            # An explicitly-named file that is absent is an error: the caller asked for it, so
            # silently scanning less than they requested is the narrowing this flag guards against.
            # A *default* that is absent is tolerated — the archive does not exist before the first
            # retirement — but --min-items still has to hold, so it cannot vanish unnoticed.
            missing.append(p)
            continue
        sources.append((_label(p, root), p.read_text(encoding="utf-8")))

    if missing and explicit:
        for p in missing:
            print(f"ERROR: --backlog {p} does not exist", file=sys.stderr)
        return 1

    # BACKLOG #1259: surface the conflict refusal as a REPORT, not a traceback, and NAME THE FILE.
    #
    # `parse_items` already refuses a source carrying conflict markers, and that refusal is what makes
    # this file safe to read. But it raises from inside `scan`, so every caller -- the CI leg and now
    # the pre-commit hook -- rendered it as an uncaught ValueError. Two costs, and the second is the
    # one that matters: a traceback reads as *the checker is broken* rather than *your ledger is
    # conflicted*, which sends an author to the wrong file; and the exception carries a LINE number
    # but no PATH, so with several sources scanned it does not say which one to open.
    #
    # Parsing each source here also removes a real double-parse -- the count and the scanned-list
    # below each called `parse_items` again on every source.
    parsed: list[tuple[str, int]] = []
    for label, text in sources:
        try:
            parsed.append((label, len(parse_items(text))))
        except ValueError as exc:
            print(f"ERROR: {label}: {exc}", file=sys.stderr)
            return 1

    changelog = args.changelog.read_text(encoding="utf-8") if args.changelog else None
    errors, warnings = scan(sources, changelog)

    for w in warnings:
        print(f"WARN: {w}", file=sys.stderr)
    for e in errors:
        print(f"ERROR: {e}", file=sys.stderr)

    n = sum(count for _, count in parsed)
    scanned = ", ".join(f"{label} ({count})" for label, count in parsed)

    if args.min_items is not None and n < args.min_items:
        # Printed to stderr *with the file list*, because "which files did you actually read" is the
        # question a narrowing bug turns on, and a bare count cannot answer it.
        print(
            f"ERROR: found {n} backlog items, below the required floor of {args.min_items}.\n"
            f"       scanned: {scanned or '(nothing)'}\n"
            "       Items were removed, or a file holding them was not scanned. If items moved to "
            "an archive, pass it with --backlog so it is read as part of the same namespace.",
            file=sys.stderr,
        )
        return 1

    if errors:
        print(
            f"\n{len(errors)} error(s). Every backlog item must declare exactly one status banner.\n"
            "A doc that lies about build state silently misdirects planning — see this file's docstring.",
            file=sys.stderr,
        )
        return 1
    if not args.quiet:
        extra = f" ({len(warnings)} advisory warning(s))" if warnings else ""
        print(f"OK — {n} backlog items, each declaring exactly one status{extra}.")
        # Always name what was read. A count alone cannot distinguish "the corpus shrank" from
        # "a file was silently skipped", and those need different fixes.
        print(f"     scanned: {scanned}")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
