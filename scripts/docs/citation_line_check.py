# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A ``path:line`` citation into source must point at the symbol its prose names.

BACKLOG #1263. The two ledgers carry thousands of ``path:line`` citations into code and **nothing
checks that the cited line still holds what the citation says it does**. A drifted citation does not
break -- it resolves to a line that EXISTS and says something else, which this project already treats
as the worse failure. `link_check.py` answers *"does this path resolve"*; `backlog_citation_check.py`
resolves a backlog number against the ledger namespace. Neither asks this question, and their own
docstrings draw that distinction.

WHY NOT A BOUNDS CHECK, WHICH IS THE OBVIOUS CHEAP DETECTOR
-------------------------------------------------------------
Measured at HEAD: of **3,086** citations, exactly **THREE** cite a line past end of file, and all
three are range ENDS overshooting by one or two. A bounds check would run green over 1,142 resolvable
citations forever and read as citation integrity while never once firing for the filed reason.

The filed class is a citation pointing at the WRONG line, and the row's evidence is five for five --
``engine.py:827`` when the subject is at ``:919``; ``mail-drain.ps1:37-42`` when the assertion is at
``:57``. Those lines all exist. Only their CONTENT is wrong.

WHAT THIS CHECKS INSTEAD, AND THE DISCRIMINATOR THAT MAKES IT ACTIONABLE
-------------------------------------------------------------------------
For a citation whose prose names a code symbol nearby, look for that symbol in the cited span. If it
is absent, ask a second question that turns a complaint into a fix: **is the symbol elsewhere in the
same file?**

    symbol in the cited span          -> AGREES, silent
    symbol absent, found elsewhere    -> DRIFTED, and the report says WHERE it actually is
    symbol absent from the file       -> UNRESOLVED, reported separately and NOT as drift
                                         (a rename, or the matcher picking a word that is not
                                         the citation's subject -- either way it is not a
                                         line-number claim this tool can adjudicate)

Measured at HEAD: **143 DRIFTED** with a provable correct line, **29 UNRESOLVED**. `_audit_upload_prune`
cited at ``api/app.py:5891-5907`` is actually at ``:6154``; ``verify_audit_chain`` cited at
``__main__.py:3596`` is at ``:3812``.

BARE FILENAMES ARE REFUSED, LOUDLY, WITH A COUNT
--------------------------------------------------
**935 of the 3,086 citations carry no directory** -- ``store.py:1638``, ``runner.py:373-377``. This
repository has several files with each of those names, so no tool can know which is meant. They are
counted and reported as REFUSED, never resolved by guessing.

***THAT REFUSAL EXISTS BECAUSE THE FIRST VERSION OF THIS TOOL DID GUESS, AND IT PRODUCED A FINDING
THAT WAS ENTIRELY AN ARTEFACT OF ITS OWN RESOLVER.*** It resolved bare names with ``rglob`` and took
the first match, then reported **79** past-end-of-file hits. The corrected number is 3. The tell was
in its own output -- *"store.py:1638 -- file is 382 lines"*, against a real
``messagefoundry/store/store.py`` of over 8,000 -- so **the instrument printed its own refutation in a
field nobody reads.** That is precisely the defect class this item exists to catch, produced by the
tool written to catch it. Guessing a path is not a convenience here; it is the bug.

WHAT THIS DOES NOT COVER, STATED SO ITS GREEN IS NOT READ WIDER
-----------------------------------------------------------------
A citation whose prose names no symbol is invisible to this check -- that is the majority. A citation
naming a symbol that legitimately appears in many places can agree by coincidence. And a span whose
symbol moved only a line or two reads as agreement by design, because the span is deliberately
tolerant. This reduces one class; it does not certify the corpus, and the summary line reports the
denominator so the covered fraction is never implied to be the whole.

THE BASELINE, AND WHY A DETECTOR THIS FAR BEHIND NEEDS ONE (BACKLOG #1525)
---------------------------------------------------------------------------
204 of the 309 checkable citations drift today. Wired without a baseline this reports a finding on
every run forever, which is the state a check gets switched off in -- ``backlog_citation_check.py``
records the same reasoning for its diff scope, in its own words: *"a gate that fails on a legitimate
archive is one people delete"*. ``--baseline FILE`` records today's population, so a run can separate
**a drift somebody just wrote** from the 204 that were already here.

``--advisory`` downgrades a FINDING to exit 0. **It never downgrades a MALFUNCTION** -- an unreadable
ledger or an unreadable baseline still exits 2, because a scan that read nothing and a scan that found
nothing must not render alike.

**THE KEY CARRIES NO ACTUAL LINE AND NO LEDGER FILE, and both omissions are deliberate.** A key is
``<cited path>:<cited span>::<symbol>``:

* the **actual** line is where the symbol really is, and it moves on every refactor -- putting it in
  the key would retire a baseline entry and re-report the same drift as new, on a change that touched
  no citation at all;
* the **ledger file** is where the row sits today, and retiring an item MOVES it verbatim from
  ``docs/BACKLOG.md`` into the archive -- keying on it would make every archived row read as new drift.

So an entry retires when the CITATION changes or the symbol leaves the file, which is what a reader
means by "that one is dealt with". Both directions print on every run: a key no longer reported is
either a fixed citation or a screen that stopped seeing it, and those are opposite facts.

**A NEW KEY IS NOT ALWAYS A NEW CITATION.** Moving the code under a citation that agreed yesterday
produces one too, and that citation is now genuinely wrong -- the same defect arriving from the other
side. The report names the symbol and the line it is really on, so either remedy is one edit.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path
from typing import NamedTuple

_ROOT = Path(__file__).resolve().parent.parent.parent

#: `path/to/file.py:123` or `:123-145`, with or without surrounding backticks.
_CITE = re.compile(r"`?([A-Za-z0-9_./-]+\.(?:py|ts|ps1|sh|js))`?:(\d+)(?:-(\d+))?")

#: A backticked identifier. DELIBERATELY LINEAR: one character class, one quantifier, no alternation
#: and no nesting.
#:
#: THE FIRST VERSION WAS A ReDoS AND CodeQL CAUGHT IT AS HIGH SEVERITY. It read
#: ``[A-Za-z_][A-Za-z0-9_]*(?:_[A-Za-z0-9_]+)+``, where ``[A-Za-z0-9_]*`` and the ``(?:_...)+`` group
#: BOTH match an underscore. On an input like ``A_0_0_0_0...`` the engine can split those repetitions
#: exponentially many ways before failing, so a crafted ledger line hangs the checker. That is
#: catastrophic backtracking, and the fix is to remove the AMBIGUITY rather than to tune the pattern:
#: two constructs that can consume the same character are the defect, not the length of the input.
#:
#: The "must carry an underscore or a call form" requirement -- which is what takes the flag rate from
#: two thirds down to something reviewable -- now lives in :func:`_is_symbol`, where it is a linear
#: string test and cannot backtrack at all.
_SYM = re.compile(r"`([A-Za-z_][A-Za-z0-9_]*(?:\(\))?)`")


def _is_symbol(token: str) -> bool:
    """True for a CODE IDENTIFIER, false for a prose word.

    A bare word like ``client`` is prose as often as it is a symbol; requiring an underscore or a
    call form is the narrowing measured to take a naive matcher from 379 flags of 575 down to a
    reviewable number. Expressed here rather than in the regex because a regex that encodes it
    needs alternation over overlapping classes, which is exactly what made the first version a ReDoS.
    """
    if token.endswith("()"):
        return True
    return "_" in token


#: How far either side of the citation to look for the symbol it is about.
_PROSE_WINDOW = 80

#: Lines of slack around the cited span. A symbol that moved a line or two is not the filed defect.
_SPAN_SLACK = 3


#: Judged drifts, one key per line. See the module docstring for what a key deliberately OMITS.
DEFAULT_BASELINE = _ROOT / "scripts" / "docs" / "citation_line_baseline.txt"


class Drift(NamedTuple):
    source: str
    path: str
    cited: str
    symbol: str
    actual_line: int

    @property
    def key(self) -> str:
        """Stable across a refactor and across archival. ``actual_line`` and ``source`` are out."""
        return f"{self.path}:{self.cited}::{self.symbol}"


def load_baseline(path: Path) -> set[str]:
    """Read judged keys. Raises rather than defaulting to empty: a baseline that cannot be read and
    one that is genuinely empty have opposite meanings, and the caller turns the first into exit 2.

    The same six lines exist in ``scripts/quality/username_access_key_screen.py``, whose baseline
    this one is modelled on, and the duplication is deliberate: ``scripts/`` is not a package, so
    there is no import path between them and a shared helper would mean a seventh bespoke module
    loader. Named here rather than left to be rediscovered.
    """
    keys: set[str] = set()
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.split("#", 1)[0].strip()
        if line:
            keys.add(line)
    return keys


class Report(NamedTuple):
    total: int
    refused_bare: int
    unreadable: int
    checkable: int
    agreed: int
    unresolved: int
    drifted: list[Drift]


def scan(ledgers: list[Path], root: Path) -> Report:
    total = refused = unreadable = checkable = agreed = unresolved = 0
    drifted: list[Drift] = []
    # One read per cited FILE, not per citation. Measured on the real ledgers: 311 checkable
    # citations resolve to 127 distinct files, `settings.py` alone 25 times. It was never the
    # bottleneck at hand-run scale; it becomes repeated work now that a nightly job runs this.
    source: dict[Path, list[str]] = {}

    for ledger in ledgers:
        text = ledger.read_text(encoding="utf-8", errors="replace")
        for m in _CITE.finditer(text):
            path, start, end = m.group(1), int(m.group(2)), m.group(3)
            total += 1
            if "/" not in path:
                refused += 1  # a bare filename resolves to several files; guessing IS the bug
                continue
            target = root / path
            if not target.is_file():
                unreadable += 1  # link_check.py owns this question; not ours to duplicate
                continue

            lo = max(0, m.start() - _PROSE_WINDOW)
            hi = min(len(text), m.end() + _PROSE_WINDOW)
            symbols = {s.rstrip("()") for s in _SYM.findall(text[lo:hi]) if _is_symbol(s)}
            symbols = {
                s for s in symbols if "/" not in s and not s.endswith((".py", ".ts", ".ps1"))
            }
            if not symbols:
                continue  # no symbol named: nothing to check against, and that is most citations

            checkable += 1
            if (lines := source.get(target)) is None:
                lines = source[target] = target.read_text(
                    encoding="utf-8", errors="replace"
                ).splitlines()
            span_lo = max(1, start - _SPAN_SLACK)
            span_hi = min(len(lines), (int(end) if end else start) + _SPAN_SLACK)
            span = "\n".join(lines[span_lo - 1 : span_hi])
            if any(s in span for s in symbols):
                agreed += 1
                continue

            found = None
            for sym in sorted(symbols):
                for i, line in enumerate(lines):
                    if sym in line:
                        found = (sym, i + 1)
                        break
                if found:
                    break
            if found is None:
                unresolved += 1
                continue
            cited = f"{start}-{end}" if end else str(start)
            drifted.append(Drift(str(ledger), path, cited, found[0], found[1]))

    return Report(total, refused, unreadable, checkable, agreed, unresolved, drifted)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("ledgers", nargs="*", type=Path)
    ap.add_argument("--root", type=Path, default=_ROOT)
    ap.add_argument(
        "--max-report", type=int, default=25, help="drifted citations to print (0 = all)"
    )
    ap.add_argument(
        "--baseline",
        type=Path,
        nargs="?",
        const=DEFAULT_BASELINE,
        default=None,
        metavar="FILE",
        help="judged drifts; fail only on a key that is not in it (bare flag = the shipped file)",
    )
    ap.add_argument(
        "--advisory",
        action="store_true",
        help="report findings without failing; a MALFUNCTION still exits 2",
    )
    args = ap.parse_args(argv)

    ledgers = args.ledgers or [
        _ROOT / "docs" / "BACKLOG.md",
        _ROOT / "docs" / "archive" / "backlog" / "BACKLOG-CLOSED.md",
    ]
    ledgers = [p for p in ledgers if p.exists()]
    if not ledgers:
        print("citation-line: no ledger to read -- refusing to report clean", file=sys.stderr)
        return 2

    r = scan(ledgers, args.root)

    # THE DENOMINATOR IS PART OF THE RESULT. A run that checked 253 of 3,086 citations and one that
    # checked all of them must not print the same reassuring line.
    print(
        f"citation-line: {r.total} path:line citation(s); {r.refused_bare} REFUSED as bare filenames "
        f"(unresolvable to one file), {r.unreadable} path(s) absent, {r.checkable} carried a named "
        f"symbol and were checked -- {r.agreed} agree, {r.unresolved} name a symbol not in the file, "
        f"{len(r.drifted)} DRIFTED"
    )
    if r.drifted:
        print("")
        shown = r.drifted if args.max_report == 0 else r.drifted[: args.max_report]
        for d in shown:
            print(f"  {d.path}:{d.cited} names `{d.symbol}` -- which is at :{d.actual_line}")
        if len(shown) < len(r.drifted):
            print(f"  ... and {len(r.drifted) - len(shown)} more (--max-report 0 for all)")

    if args.baseline is None:
        if not r.drifted:
            print(
                "citation-line: OK -- every checkable citation points at the symbol its prose names"
            )
            return 0
        return 0 if args.advisory else 1

    try:
        judged = load_baseline(args.baseline)
    except OSError as exc:
        # A malfunction, and `--advisory` does not reach it. An unreadable baseline makes every
        # known drift read as new, which is the alarm-on-everything direction this file warns about.
        print(f"citation-line: cannot read baseline {args.baseline}: {exc}", file=sys.stderr)
        return 2

    seen = {d.key for d in r.drifted}
    new = sorted(seen - judged)
    retired = sorted(judged - seen)

    # STATED EVEN WHEN EMPTY: a retired key is either a fixed citation or a screen that stopped
    # seeing it, and printing the count is what lets a reader notice the second one.
    print("")
    print(
        f"citation-line: baseline {args.baseline.name} -- {len(judged)} judged, {len(seen)} seen, "
        f"{len(retired)} no longer reported, {len(new)} NEW"
    )
    for key in retired:
        print(f"    NO LONGER REPORTED (citation fixed, or the screen stopped seeing it): {key}")
    if not new:
        return 0
    print("")
    print(
        "citation-line: NEW DRIFTED CITATION(S) -- re-anchor each, or add its key to the baseline:"
    )
    for key in new:
        print(f"    {key}")
    return 0 if args.advisory else 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
