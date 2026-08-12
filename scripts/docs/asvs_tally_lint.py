# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Refuse a NEW hard-coded ASVS verdict tally in a Markdown document (ADR 0156).

ADR 0156 made the count computed. It did not stop anyone writing one down. Measured on the
assessment corpus: 44 documents assert a whole-corpus tally, roughly 50 distinct tallies exist, and
approximately one is correct -- and the correct one is a rendered Markdown table that a grep for the
corpus's own ``N / N / N / N`` idiom does not even find.

**This is forward-only and it is not a sweep.** A one-time pass over a file list was tried, cost
about 850 net lines, needed its own repair commit, and the defect regenerated inside four days
because eight new documents were written after it. Existing tallies are recorded in a frozen
baseline that may only SHRINK; a tally that is not in the baseline fails.

WHAT COUNTS AS A TALLY, stated as a rule rather than left to the regexes. A tally is a hard-coded
count of cells **by verdict or survey status** -- the numbers that move whenever anything is
re-scored. Facts about the **structure** of the pinned corpus do not move and are deliberately NOT
flagged: "345 requirements", "253 L1+L2, 92 L3-only", "all 345 cells have a row". Flagging those was
the previous attempt's biggest source of noise, and it is what made it red the method document's own
worked example.

THE IDIOM SET WAS REBUILT FROM THE CORPUS, NOT GUESSED. The previous attempt matched two shapes --
an ``N / N / N / N`` tuple and ``N of 345`` -- and missed 6 of the 8 chapter reports that were its
own motivating evidence. Every idiom below is anchored to real text in the corpus, and the two that
the old attempt lacked (``TABLE_ROW`` and ``ARITHMETIC``) are exactly the shapes it could not see.

Runnable on its own::

    python scripts/docs/asvs_tally_lint.py docs
    python scripts/docs/asvs_tally_lint.py --baseline scripts/docs/asvs_tally_baseline.txt docs

It prints the files it scanned, the idioms it matched and the per-file counts, so a run that scanned
nothing cannot be mistaken for a run that found nothing. Stdlib only, so it can be mirrored into the
assessment repo and run there without an install -- the same property ``scripts/asvs/scorecard.py``
is held to.
"""

from __future__ import annotations

import argparse
import re
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from pathlib import Path

# The pinned ASVS 5.0.0 corpus size. It is a CONSTANT, which is the whole reason a number that sums
# to it is a whole-corpus tally rather than a coincidence.
CORPUS_TOTAL = 345

# Verdict and survey-status words, as the corpus actually writes them. `verified` / `re-verified` /
# `unverified` are in here because the survey moved on those words for a fortnight and every one of
# those counts went stale the same way a verdict count does.
_VERDICT = (
    r"pass(?:es|ed)?|partials?|fail(?:s|ed|ures?)?|n/?a|unverified|not[- ]re-?verified"
    r"|re-?verified|verified|needs[- ]review|contingent|examined"
)
# Markdown emphasis sits BETWEEN the number and the word all over this corpus -- "24 `pass`, 15
# `partial`, 5 `na`" is the V6 chapter report's tally, and it is why a naive `\s*` misses 1 in 8.
_EMPH = r"[`*_\"']*"
_GAP = rf"\s*{_EMPH}\s*"

# I1 -- a slash-separated run of integers that SUMS TO THE CORPUS TOTAL.
#   "current scorecard 189 / 20 / 3 / 133"      (docs/adr/0019)
#   "ASVS score synced to 212/0/0/133"          (docs/BACKLOG.md)
# The sum test is what keeps HL7 field notation (PID-3/4/18), status-code lists (403 / 401 / 400 /
# 409) and config defaults (5 / 2 / 300) out. An unbounded slash tuple produced 73 false hits.
_SLASH_RUN = re.compile(r"\b\d{1,3}(?:\s*/\s*\d{1,3}){2,}\b")

# I2 -- a MARKDOWN TABLE ROW whose integers sum to the corpus total.
#   "| Interim re-score (#1208, merged) | 236 | 48 | 0 | 61 | 345 |"
# This is the shape the old idiom set could not see at all, and it is the shape the ONE correct
# record is written in.
_TABLE_ROW = re.compile(r"^\s*\|.*\|\s*$")

# I3 -- three or more DISTINCT verdict classes each carrying a count, on one line.
#   "168 pass / 105 partial / 3 fail / 65 na / 4 needs-review"
#   "175 P / 50 Part / 2 Fail / 118 N/A"
# Three classes rather than two: two co-occurring counts happen in ordinary prose, three do not.
_LABELLED = re.compile(rf"\b(\d{{1,3}}){_GAP}(?:cells?\s+)?({_VERDICT})\b", re.IGNORECASE)
_LABELLED_REV = re.compile(rf"\b({_VERDICT}){_GAP}[:=]{_GAP}(\d{{1,3}})\b", re.IGNORECASE)
_ABBREV = re.compile(rf"\b(\d{{1,3}}){_GAP}(P|Part|F|NA|N/A)\b")

# I4 -- a count stated AGAINST the corpus total. Any such number is a whole-corpus claim by
# construction, and it goes stale on the next re-score.
#   "Combined survey is now 316/345 verified"    "205 of those 345 cells rest on an assumption"
# A bare letter placeholder is NOT a count: the method document's worked example is literally
# "N of 345", and redding that was a defect of the previous attempt.
_AGAINST_TOTAL = re.compile(
    rf"\b\d{{1,3}}\s*(?:/|of(?:\s+(?:the|those))?|out\s+of)\s*(?:the\s+)?{CORPUS_TOTAL}\b",
    re.IGNORECASE,
)

# I5 -- an arithmetic assertion that closes to the corpus total.
#   "`195 + 89 + 0 + 61 = 345`"   "`205 + 140 = 345`"
_ARITHMETIC = re.compile(rf"\b\d{{1,3}}(?:\s*\+\s*\d{{1,3}})+\s*=\s*{CORPUS_TOTAL}\b")

_INT = re.compile(r"\d{1,3}")


@dataclass(frozen=True)
class Hit:
    """One matched tally."""

    path: str
    line: int
    idiom: str
    token: str
    text: str

    def key(self) -> str:
        """Baseline identity: file, idiom, and the TALLY ITSELF -- never the line number, and
        never the surrounding prose.

        Not the line number, because a baseline keyed on one is invalidated by any edit above it;
        that turns a frozen list into a list that has to be re-typed, which is the decaying-budget
        failure this programme is unpicking elsewhere.

        Not the whole line either, for the same reason one step in: fixing a typo in the sentence
        around a grandfathered tally would red the build and invite a re-type. The key moves only
        when the NUMBERS move -- which is exactly the moment the claim should be looked at again.
        """
        return f"{self.path}\t{self.idiom}\t{self.token}"


def _normalize_verdict(raw: str) -> str:
    v = raw.lower().replace("n/a", "na").replace("_", "").replace(" ", "-")
    v = re.sub(r"(?:ures|ure|es|ed|s)$", "", v)
    v = {"p": "pass", "part": "partial", "f": "fail", "pas": "pass"}.get(v, v)
    return v.replace("re-verified", "reverified")


#: An inline code span. Used ONLY to tell EMPHASIS from QUOTATION -- see :func:`_quoted_whole`.
_CODE_SPAN = re.compile(r"`[^`]*`")


def _quoted_whole(line: str) -> list[tuple[int, int]]:
    """Half-open ranges of this line's inline code spans."""
    return [(m.start(), m.end()) for m in _CODE_SPAN.finditer(line)]


def _counted_verdicts(line: str) -> set[tuple[int, str]]:
    """Every (count, verdict-class) pair ASSERTED on one line.

    A pair whose number AND verdict word both sit inside ONE inline code span is a QUOTATION, not an
    assertion, and is skipped. The distinction is emphasis-versus-enclosure and it is the whole of the
    rule:

        24 `pass`, 15 `partial`, 5 `na`        -> the numbers are OUTSIDE the spans; the backticks
                                                  decorate individual words. A real claim. COUNTED.
        `scanned 3 cells (1 pass / 0 partial)` -> number and word inside the SAME span. The document
                                                  is QUOTING output, not asserting it. SKIPPED.

    Found the hard way: this lint red on docs/BACKLOG.md #1012, whose closing banner quotes the
    falsification transcript that PROVES the bug it fixed -- ``scanned 3 cells (1 pass / 0 partial /
    0 fail / 0 na / 1 unverified)``, three synthetic cells, and the sentence's own point is that the
    components DISAGREE with the stated total. A lint against stale tallies fired on a demonstration
    that a tally was wrong. The precedent for the rule is already in the house style: CLAUDE.md
    section 11 permits quoting a glyph as a token in backticks and calls that code rather than
    decoration. A backticked span is a MENTION, not a USE.

    Deliberately NOT done: stripping code spans wholesale before matching. That would blind
    :data:`_ARITHMETIC`, whose own documented examples are backticked real tallies
    (``195 + 89 + 0 + 61 = 345``), and it would also delete the very words that make the
    emphasis case above matchable. The narrow rule is the one that keeps every documented idiom.
    """
    spans = _quoted_whole(line)

    def quoted(start: int, end: int) -> bool:
        return any(lo <= start and end <= hi for lo, hi in spans)

    pairs: set[tuple[int, str]] = set()
    for m in _LABELLED.finditer(line):
        if not quoted(m.start(), m.end()):
            pairs.add((int(m.group(1)), _normalize_verdict(m.group(2))))
    for m in _LABELLED_REV.finditer(line):
        if not quoted(m.start(), m.end()):
            pairs.add((int(m.group(2)), _normalize_verdict(m.group(1))))
    for m in _ABBREV.finditer(line):
        if not quoted(m.start(), m.end()):
            pairs.add((int(m.group(1)), _normalize_verdict(m.group(2))))
    return pairs


def idioms_for_line(line: str) -> list[tuple[str, str]]:
    """Every (idiom, tally-token) this single line trips, in a stable order.

    The token is the tally reduced to its numbers, so it identifies the CLAIM rather than the
    sentence that carries it.
    """
    out: list[tuple[str, str]] = []

    seen: set[str] = set()
    for m in _SLASH_RUN.finditer(line):
        nums = [int(x) for x in _INT.findall(m.group(0))]
        tok = "/".join(str(n) for n in nums)
        if sum(nums) == CORPUS_TOTAL and tok not in seen:
            seen.add(tok)
            out.append(("SLASH_RUN", tok))

    if _TABLE_ROW.match(line):
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        nums = [int(c) for c in cells if re.fullmatch(r"\d{1,3}", c)]
        # Two or more numeric cells, and some contiguous run of them closes to the total. A single
        # numeric cell is a per-cell table, not a tally.
        for i in range(len(nums)):
            acc = 0
            for j in range(i, len(nums)):
                acc += nums[j]
                if acc == CORPUS_TOTAL and j > i:
                    out.append(("TABLE_ROW", "|".join(str(n) for n in nums[i : j + 1])))
                    break
            else:
                continue
            break

    verdicts = _counted_verdicts(line)
    if len({v for _, v in verdicts}) >= 3:
        out.append(("LABELLED_VERDICTS", ",".join(f"{n}{v}" for n, v in sorted(verdicts))))

    for m in _AGAINST_TOTAL.finditer(line):
        tok = re.sub(r"\s+", "", m.group(0)).lower()
        out.append(("AGAINST_TOTAL", tok))

    for m in _ARITHMETIC.finditer(line):
        out.append(("ARITHMETIC", re.sub(r"\s+", "", m.group(0))))

    return out


def scan_text(path: str, text: str) -> list[Hit]:
    """Every tally in one document."""
    hits: list[Hit] = []
    for n, line in enumerate(text.splitlines(), 1):
        for idiom, token in idioms_for_line(line):
            hits.append(Hit(path, n, idiom, token, line.strip()))
    return hits


def iter_markdown(roots: Iterable[Path], repo: Path) -> Iterator[tuple[str, Path]]:
    for root in roots:
        base = root if root.is_absolute() else repo / root
        if base.is_file():
            yield base.relative_to(repo).as_posix(), base
            continue
        for p in sorted(base.rglob("*.md")):
            yield p.relative_to(repo).as_posix(), p


def load_baseline(path: Path | None) -> dict[str, int]:
    """Grandfathered tallies as ``key -> occurrence count``.

    The count is what stops the baseline being a licence to add more of the same: one extra copy of
    an already-grandfathered tally is a NEW tally, and removing one leaves the recorded count too
    high, which fails and forces the entry down. The list can only shrink.
    """
    out: dict[str, int] = {}
    if path is None or not path.is_file():
        return out
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.rstrip("\n")
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        key, _, count = line.rpartition("\t")
        if not key or not count.isdigit():
            raise ValueError(f"malformed baseline line (expected 'key<TAB>count'): {line!r}")
        out[key] = int(count)
    return out


def counted(hits: Iterable[Hit]) -> dict[str, int]:
    out: dict[str, int] = {}
    for h in hits:
        out[h.key()] = out.get(h.key(), 0) + 1
    return out


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("roots", nargs="*", default=["docs"], help="files or directories to scan")
    ap.add_argument("--repo", type=Path, default=Path(__file__).resolve().parents[2])
    ap.add_argument("--baseline", type=Path, default=None)
    ap.add_argument(
        "--allow",
        action="append",
        default=[],
        help="a path prefix that is exempt (the rendered record).",
    )
    ap.add_argument("--print-keys", action="store_true", help="emit baseline keys for the findings")
    args = ap.parse_args(argv)

    docs = list(iter_markdown([Path(r) for r in args.roots], args.repo))
    baseline = load_baseline(args.baseline)
    allow = tuple(args.allow)

    scanned = 0
    skipped = 0
    hits: list[Hit] = []
    for rel, p in docs:
        if rel.startswith(allow):
            skipped += 1
            continue
        scanned += 1
        hits.extend(scan_text(rel, p.read_text(encoding="utf-8", errors="replace")))

    observed = counted(hits)
    new = [h for h in hits if observed[h.key()] > baseline.get(h.key(), 0)]
    grandfathered = sum(min(n, baseline.get(k, 0)) for k, n in observed.items())

    print(
        f"SCANNED: {scanned} markdown files ({skipped} allowlisted) under {[str(r) for r in args.roots]}"
    )
    print(
        f"SCANNED: baseline {args.baseline} carries {len(baseline)} grandfathered claims "
        f"({sum(baseline.values())} occurrences)"
    )
    print(
        f"FOUND:   {len(hits)} tallies total, {grandfathered} grandfathered, "
        f"{len(hits) - grandfathered} NEW"
    )
    per_idiom: dict[str, int] = {}
    for h in hits:
        per_idiom[h.idiom] = per_idiom.get(h.idiom, 0) + 1
    print(f"FOUND:   idioms {per_idiom or '{}'}")
    per_file: dict[str, int] = {}
    for h in hits:
        per_file[h.path] = per_file.get(h.path, 0) + 1
    for path in sorted(per_file, key=lambda k: (-per_file[k], k)):
        print(f"         {per_file[path]:4d}  {path}")

    if args.print_keys:
        for key in sorted(observed):
            print(f"{key}\t{observed[key]}")

    stale = sorted(k for k, n in baseline.items() if observed.get(k, 0) < n)
    rc = 0
    if new:
        rc = 1
        print(f"\nFAIL: {len(new)} hard-coded ASVS tally/tallies are not grandfathered:")
        for h in sorted(new, key=lambda h: (h.path, h.line)):
            print(f"  {h.path}:{h.line}: [{h.idiom} {h.token}] {h.text[:150]}")
        print(
            "\nThe count is computed (ADR 0156). Cite the rendered record instead of copying a "
            "number out of it: every copy goes stale on the next re-score, and of the roughly "
            "fifty that exist, approximately one is correct."
        )
    if stale:
        rc = 1
        print(f"\nFAIL: {len(stale)} baseline entr(ies) now over-count what is in the tree.")
        print("The baseline may only SHRINK -- lower or delete these in the change that removed")
        print("the tally, so a fix is recorded rather than leaving a licence behind:")
        for k in stale:
            print(f"  have {observed.get(k, 0)}, baseline says {baseline[k]}:  {k}")
    if rc == 0:
        print("\nOK: no new hard-coded ASVS tally.")
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
