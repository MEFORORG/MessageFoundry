# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
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

EXAMINING NOTHING, OR A BASELINE THAT DOES NOT LOAD, IS EXIT 2, never a clean run and never the
exit 1 a finding gets (BACKLOG #5469). At least these:

  * a root that yields ZERO Markdown files, or only blank ones, after the allowlist -- a root that
    moved, was misspelt, is wholly allowlisted or holds only empty files. Checked per root, so a
    misspelt root beside a good one is not hidden. "no new tally" and "nothing was read" must not
    share an exit code;
  * a ``--baseline`` that names no file. Read as empty, it reclassifies every grandfathered tally
    as NEW, and the cause reads as a finding rather than as a wrong path;
  * a ``--baseline`` file with no content at all. The generating command below redirects stdout,
    and the shell truncates the target before this program starts, so a generating run that
    refused leaves exactly that file behind;
  * a baseline that cannot be read, is malformed, is UTF-16 (what a Windows PowerShell 5.1
    redirect writes) or is not UTF-8.

Scanning with no baseline is allowed and explicit: omit ``--baseline``. That is the form the
generating command uses. A baseline that holds a ``#`` header and zero claims is the ratchet's end
state -- every tally retired -- and loads as empty; only a file with nothing in it is refused.

    python scripts/docs/asvs_tally_lint.py docs --print-keys > <baseline.txt>

Under ``--print-keys`` stdout carries a ``#`` header and baseline lines, as UTF-8, and nothing else;
the inventory and the verdict go to stderr, still printed for a person to read but not swallowed
into the artifact. The output therefore loads as a baseline as written. The generating run exits 1
whenever the tree holds a tally, because against no baseline every tally is NEW; verify the result
by re-running with ``--baseline <baseline.txt>`` and requiring exit 0. Windows PowerShell 5.1
re-encodes a native command's output on ``>`` and on a pipe, so run the generating command from a
POSIX shell or ``cmd``, not from PowerShell. The loader refuses the UTF-16 file a 5.1
redirect writes rather than reading it as empty.
"""

from __future__ import annotations

import argparse
import re
import shlex
import sys
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from functools import partial
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


class EmptyScan(RuntimeError):
    """Raised when nothing was examined. Never let that report as success."""


def load_baseline(path: Path | None) -> dict[str, int]:
    """Grandfathered tallies as ``key -> occurrence count``.

    The count is what stops the baseline being a licence to add more of the same: one extra copy of
    an already-grandfathered tally is a NEW tally, and removing one leaves the recorded count too
    high, which fails and forces the entry down. The list can only shrink.

    ``None`` -- no ``--baseline`` given -- is the one explicit way to scan without a baseline. A
    path that is not a file, or a file with no content, raises :class:`EmptyScan`; a file that does
    not decode or holds a malformed line raises ``ValueError``. A ``#`` header with zero claims
    loads as empty: see the module docstring.
    """
    out: dict[str, int] = {}
    if path is None:
        return out
    if not path.is_file():
        what = "is a directory, not a file" if path.is_dir() else "does not exist"
        raise EmptyScan(
            f"baseline {path} {what}. Read as empty, it would report every grandfathered tally as "
            f"NEW. Omit --baseline to scan without one deliberately."
        )
    try:
        data = path.read_bytes()
    except OSError as exc:
        raise ValueError(f"baseline {path} could not be read: {exc}") from exc
    if data.startswith((b"\xff\xfe", b"\xfe\xff")):
        raise ValueError(
            f"baseline {path} is UTF-16, which a Windows PowerShell 5.1 redirect writes. "
            f"Regenerate it as UTF-8 (see the module docstring)."
        )
    # utf-8-sig, so a BOM some editors and shells add cannot fuse onto the first key -- and so a
    # file holding only a BOM reads as the empty file it is.
    try:
        text = data.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise ValueError(f"baseline {path} is not UTF-8: {exc}") from exc
    if not text.strip():
        raise EmptyScan(
            f"baseline {path} is empty. A generating run redirects stdout and the shell truncates "
            f"the target before this program starts, so a refused generation leaves exactly this "
            f"file behind. Omit --baseline to scan without one deliberately."
        )
    for line in text.splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        key, _, count = line.rpartition("\t")
        if not key or not count.isascii() or not count.isdigit() or key.count("\t") != 2:
            raise ValueError(
                f"malformed baseline line in {path} "
                f"(expected 'path<TAB>idiom<TAB>token<TAB>count'): {line!r}"
            )
        out[key] = int(count)
    return out


def counted(hits: Iterable[Hit]) -> dict[str, int]:
    out: dict[str, int] = {}
    for h in hits:
        out[h.key()] = out.get(h.key(), 0) + 1
    return out


def _harden_stdout() -> None:
    """Make this tool's own output survive a cp1252 console (BACKLOG #1221).

    The gate prints DOCUMENT CONTENT, and the corpus it scans is documentation, so a hit whose line
    carries a glyph killed the run with ``UnicodeEncodeError`` before the finding could be read. The
    defect is invisible until the gate has something to say: with a clean corpus it exits 0 and looks
    healthy, so it fails exactly when it is needed.

    STREAM-LEVEL rather than a targeted safe-print at the one obvious site, and that is not a style
    preference. Python's ``\\d`` is Unicode-aware, so ``_AGAINST_TOTAL`` / ``_ARITHMETIC`` take
    ``m.group(0)`` VERBATIM into the token -- ``idioms_for_line("34 of 345 cells")`` with Arabic-Indic
    digits yields a token carrying non-ASCII. That token flows into the ``--print-keys`` output, the
    stale-baseline report AND the baseline file, so a fix at the findings loop alone leaves the class
    open in three other places.

    Copied rather than imported: this file is on ``MIRRORED_TOOLS`` and is contractually stdlib-only
    (tests/test_asvs_verifier_vault_contract.py), so it cannot reach for a shared helper. The guard
    mirrors messagefoundry/__main__.py's shape, including its reason for being guarded: some stream
    wrappers (PYTHONLEGACYWINDOWSSTDIO, pytest capture) lack ``reconfigure`` or reject it, and
    hardening must never itself crash the tool.
    """
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            try:  # noqa: SIM105
                reconfigure(errors="replace")
            except (ValueError, OSError):
                pass


def main(argv: list[str] | None = None) -> int:
    _harden_stdout()
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

    # Everything this run has to SAY goes through `say`; the only bare `print` calls left are the
    # baseline lines themselves. Under --print-keys stdout is the artifact, so the inventory and the
    # verdict move to stderr rather than being mixed into a file that then cannot load.
    say = partial(print, file=sys.stderr if args.print_keys else sys.stdout)
    if args.print_keys:
        # The artifact is read back as UTF-8, so write it as UTF-8 whatever the console's code page.
        reconfigure = getattr(sys.stdout, "reconfigure", None)
        if reconfigure is not None:
            try:  # noqa: SIM105
                # errors= again, or reconfigure resets it to 'strict' and undoes _harden_stdout.
                reconfigure(encoding="utf-8", errors="replace")
            except (ValueError, OSError):
                pass

    try:
        baseline = load_baseline(args.baseline)
    except (EmptyScan, ValueError) as exc:
        # ValueError covers a malformed line and an undecodable file. Exit 2, not the 1 a finding
        # gets, so a broken baseline never reads as "the docs carry a new tally".
        say(f"FAIL: {exc}")
        return 2

    allow = tuple(args.allow)

    scanned = 0
    skipped = 0
    n_chars = 0
    # Roots that yielded no non-blank file after the allowlist. Per root, so a misspelt root beside
    # a good one cannot hide behind the good one's characters.
    unread: list[str] = []
    hits: list[Hit] = []
    for root in args.roots:
        root_read = False
        for rel, p in iter_markdown([Path(root)], args.repo):
            if rel.startswith(allow):
                skipped += 1
                continue
            scanned += 1
            text = p.read_text(encoding="utf-8", errors="replace")
            n_chars += len(text)
            # "".isspace() is False, hence the explicit empty check.
            root_read = root_read or (text != "" and not text.isspace())
            hits.extend(scan_text(rel, text))
        if not root_read:
            unread.append(root)

    observed = counted(hits)
    new = [h for h in hits if observed[h.key()] > baseline.get(h.key(), 0)]
    grandfathered = sum(min(n, baseline.get(k, 0)) for k, n in observed.items())

    say(
        f"SCANNED: {scanned} markdown files ({skipped} allowlisted), {n_chars} characters, "
        f"under {[str(r) for r in args.roots]}"
    )
    say(
        f"SCANNED: baseline {args.baseline} carries {len(baseline)} grandfathered claims "
        f"({sum(baseline.values())} occurrences)"
    )
    if unread:
        say(
            f"FAIL: root(s) {unread} yielded ZERO non-blank markdown files (repo {args.repo}). "
            f"That is a root that moved, is misspelt, is wholly allowlisted or holds only empty "
            f"files, not a clean tree: 'no new tally' and 'nothing was read' must not share an "
            f"exit code."
        )
        return 2
    say(
        f"FOUND:   {len(hits)} tallies total, {grandfathered} grandfathered, "
        f"{len(hits) - grandfathered} NEW"
    )
    per_idiom: dict[str, int] = {}
    for h in hits:
        per_idiom[h.idiom] = per_idiom.get(h.idiom, 0) + 1
    say(f"FOUND:   idioms {per_idiom or '{}'}")
    per_file: dict[str, int] = {}
    for h in hits:
        per_file[h.path] = per_file.get(h.path, 0) + 1
    for path in sorted(per_file, key=lambda k: (-per_file[k], k)):
        say(f"         {per_file[path]:4d}  {path}")

    if args.print_keys:
        # A `#` line is skipped by load_baseline, so the artifact describes itself, and a tree with
        # every tally retired still generates a non-empty baseline that loads (as empty).
        # The provenance line spells out every flag that changes the result, so it reproduces the
        # file; --repo is left out because it names a machine path, not a choice.
        flags = [*args.roots, *(f for a in args.allow for f in ("--allow", a)), "--print-keys"]
        print("# Grandfathered ASVS tallies -- FROZEN, and this list may only SHRINK.")
        print("# Format:  <path> TAB <idiom> TAB <tally token> TAB <occurrence count>")
        print(f"# Produced by:  python scripts/docs/asvs_tally_lint.py {shlex.join(flags)}")
        print("# To retire one: delete the tally from the document AND lower or delete its line")
        print("# here, in the same change. A line left behind over-counts the tree and FAILS.")
        for key in sorted(observed):
            print(f"{key}\t{observed[key]}")

    stale = sorted(k for k, n in baseline.items() if observed.get(k, 0) < n)
    rc = 0
    if new:
        rc = 1
        say(f"\nFAIL: {len(new)} hard-coded ASVS tally/tallies are not grandfathered:")
        for h in sorted(new, key=lambda h: (h.path, h.line)):
            say(f"  {h.path}:{h.line}: [{h.idiom} {h.token}] {h.text[:150]}")
        say(
            "\nThe count is computed (ADR 0156). Cite the rendered record instead of copying a "
            "number out of it: every copy goes stale on the next re-score, and of the roughly "
            "fifty that exist, approximately one is correct."
        )
    if stale:
        rc = 1
        say(f"\nFAIL: {len(stale)} baseline entr(ies) now over-count what is in the tree.")
        say("The baseline may only SHRINK -- lower or delete these in the change that removed")
        say("the tally, so a fix is recorded rather than leaving a licence behind:")
        for k in stale:
            say(f"  have {observed.get(k, 0)}, baseline says {baseline[k]}:  {k}")
    if rc == 0:
        say("\nOK: no new hard-coded ASVS tally.")
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
