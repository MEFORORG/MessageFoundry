# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A ledger banner claiming a commit closed an item must cite a commit that names THAT item.

BACKLOG #1301. The incident: a retirement banner meant for one item was written onto another. The
Markdown stayed valid, the item count did not move, the status glyph was untouched, and the misplaced
paragraph carried no glyph of its own -- so ``parse_items`` had no second banner to object to and
every ledger gate passed. **One edit corrupted two items in opposite directions and nothing could
see it**: one over-reported its status, one under-reported it.

The signal was there all along. The overwritten banner cited shas whose subjects named that item's own
number; the paragraph that replaced it cited a sha whose subject named a DIFFERENT item.

THE RULE IS NARROWER THAN THE ITEM STATED, AND THE NARROWING IS MEASURED
------------------------------------------------------------------------
The row said: *"a banner citing a commit sha must cite a commit whose subject names the item the
banner sits under."* Applied literally to every sha in every banner, that fires **85 times in
docs/BACKLOG.md alone** and 94 across both ledgers -- and none of them is the defect. Characterised:

    53  the subject names a DIFFERENT item and the citation is CORRECT PROSE. #320's banner says the
        CI symptom "is already fixed (#115, 06fd327d)" -- a true, useful cross-reference.
    26  the subject names no item at all: ordinary commits, legitimately cited.
     6  merge commits, whose subject names a PR.

**A check that flags correct prose is not noisy, it is WRONG** -- it asserts a defect where the ledger
is doing exactly what it should. The row warned that a screen finding NOTHING reads as a clean corpus;
the literal rule finds EVERYTHING and reads as a broken ledger. Both are unusable and the row
anticipated only one direction.

So three narrowings, each removing a class that is not the incident:

1. **CLOSED items only.** The incident is a retirement/SHIPPED banner. A `Filed -- not started` banner
   carries no closing claim.
2. **Only a line making a CLOSING CLAIM.** A sha mentioned in passing is a cross-reference; a sha on a
   line saying SHIPPED/DONE/CLOSED is being offered as this item's own closing evidence.
3. **Only the unambiguous ``BACKLOG #N`` spelling**, never a bare ``#N``.

WHY NARROWING 3 IS NOT FUSSINESS -- IT IS THE ONLY DECIDABLE SPELLING
---------------------------------------------------------------------
``#N`` is AMBIGUOUS between a pull request and a backlog item, they share one numeric space, and a
squash-merge APPENDS the PR number in exactly that form. Measured on real closing commits:

    (WP-L3-16, ASVS 7.5.3) (#319)          <- #319 is a PR. Item #8's closing commit.
    ... (BACKLOG #1220) (#346)             <- an item AND a PR, in one subject
    ... (#1106)                            <- a PR that is indistinguishable from item #1106

A bare-``#N`` needle therefore cannot tell "this commit closed item 1106" from "this commit was merged
by PR 1106", and it would manufacture agreement as readily as disagreement.

A BARE ``#N`` THE ``BACKLOG`` TOKEN GOVERNS IS A DIFFERENT CASE, AND IT WAS BEING MISSED (BACKLOG
#1347). The house form writes the prefix once and the siblings bare, so a four-item commit cites four
items and the first reading of this check saw one. A sibling's correct closing banner then read as
citing a different item -- a false alarm on work that landed months ago, which is the direction this
file says is WRONG rather than merely noisy. :func:`cited_items` carries the fix and the measurement;
the governing scope is the parenthetical, which is what keeps the squash suffix out.

THE THIRD BUCKET IS THE ONE THAT MAKES THIS SHIPPABLE
------------------------------------------------------
Three outcomes, not two, and the middle one is the whole design:

    subject names BACKLOG #<this item>     -> AGREES
    subject names BACKLOG #<another item>  -> DISAGREES, and this is the defect class
    subject names no BACKLOG item at all   -> UNDECIDABLE, and MUST NOT FIRE

Firing on the third bucket is what produced the 94. A legitimate closing commit whose subject names a
PR and a work-package but no item is not evidence of anything, and **positive evidence of
transposition is the only thing worth alarming on**. Measured at the time of writing: 37 shas reach
the check, 8 agree, 26 are undecidable, and **3 disagree** -- a reviewable number, which 94 was not.

THE THREE LIVE FINDINGS, TRIAGED -- READ THIS BEFORE TREATING A HIT AS CORRUPTION
-----------------------------------------------------------------------------------
All three were examined by hand at the time of writing. They are NOT three defects.

**#1221 -- A TRUE POSITIVE, AND IT VALIDATES THE WHOLE CHECK.** Its own banner says the fix
*"landed under an unrelated #1220 commit title, which is why a title-level search missed it for NINE
DAYS."* The ledger documents precisely the failure this check detects, with a recorded nine-day
detection delay. This check would have found it on day zero. It still fires because the citation is
still a #1220-titled commit -- correctly, since that is genuinely where the work landed.

**#1094 -- AN EXPLAINED FALSE POSITIVE, AND IT NAMES A REAL CLASS.** The item was ALREADY SATISFIED
WHEN FILED: *"the repoint this item asks for merged as befe997e (PR #271) one commit before this item
itself landed."* An **already-done item legitimately cites another item's commit as its closing
evidence**, and no reading of a commit subject can distinguish that from a transposed banner. This
class is a known limit, not a bug to fix by widening the needle -- widening it is how the 94 came
back.

**#1025 -- UNTRIAGED at the time of writing.** Left as a hit deliberately rather than dismissed
unexamined; whoever reviews it should read the banner, not this paragraph.

So the honest summary of a run is *"N things to look at"*, never *"N defects"*, and the per-finding
message says *"either the banner sits under the wrong item, OR the citation is wrong"* for that
reason -- the check locates a disagreement it cannot itself adjudicate.

PARTIAL BY CONSTRUCTION, AND SAYING SO IS PART OF THE CONTROL
--------------------------------------------------------------
This reduces the blast radius of one class of ledger corruption. It does not eliminate it. It cannot
see a transposed banner that cites no sha, cites a sha whose subject names no item, or names the right
item for the wrong reason. The row says this and it is repeated here because a partial control
described as a total one is worse than no control.

A KNOWN WAY TO MIS-VERIFY THIS, from the row itself
-----------------------------------------------------
A first attempt at the "has anyone already fixed this" screen used a needle that omitted the backticks
around the symbol, returned False everywhere, and read as ALREADY FIXED. **A screen that finds nothing
is indistinguishable from a clean corpus until a positive control says otherwise**, which is why this
script prints its coverage and its agreement count on every run, including a clean one.

Item status is read with ``parse_items`` from ``backlog_status_check.py`` and never re-derived here:
that function DEFINES where a banner block ends, and a second hand-rolled scan would be a silently
different definition of item status. CLAUDE.md section 11 states this as a rule.
"""

from __future__ import annotations

import argparse
import importlib.util
import re
import subprocess
import sys
from pathlib import Path
from typing import NamedTuple

_HERE = Path(__file__).resolve().parent
_ROOT = _HERE.parent.parent

#: A sha in backticks. Bare hex in prose is not a citation and is not read as one.
_SHA = re.compile(r"`([0-9a-f]{7,40})`")

#: A line offering this item's own closing evidence, as opposed to mentioning a commit in passing.
_CLOSING_CLAIM = re.compile(r"\b(SHIPPED|DONE|CLOSED|RETIRED|LANDED|FIXED|MERGED)\b", re.I)

#: A `BACKLOG` token and everything up to the nearest parenthesis on either side. The item numbers
#: this check will read live inside that run and nowhere else.
_BACKLOG_RUN = re.compile(r"\bBACKLOG\b[^()]*", re.I)

#: A `#N` token, read ONLY out of a run above -- never out of a whole subject.
_HASH_N = re.compile(r"#(\d+)")


def cited_items(subject: str) -> list[str]:
    """Every BACKLOG item number a commit subject cites, in order, without duplicates.

    THE HOUSE FORM WRITES THE PREFIX ONCE AND THE SIBLINGS BARE (BACKLOG #1347):
    ``(BACKLOG #1319, #1322, #1323, #1331)`` declares FOUR items. Taking only the number directly
    after the token returned 1319 alone, so a sibling's correct closing banner read as citing a
    different item -- a visible false alarm on work that landed months ago.

    THE SCOPING IDEA IS TAKEN FROM THE TWO COPIES ALREADY HERE; THE BOUNDARY IS TIGHTER THAN EITHER,
    AND SAYING SO IS THE POINT. Both carry the measurement and the reasoning:
    scripts/coord/claim-adjudicate.ps1 (``Get-Citations``) and .github/workflows/backlog-hygiene.yml
    (the ``items=`` pipeline, which splits on ``)`` to get its scope without a regex). An unscoped
    "every ``#N`` after the token" rule inflates by about 17x -- 641 subjects called multi-item
    against 38 of 1070 -- because a squash-merge APPENDS the pull-request number as a trailing group,
    and ``(BACKLOG #1040) (#547)`` is one item and one pull request.

    **THE THREE DO NOT AGREE EVERYWHERE, AND CLAIMING THEY DID WOULD BE THE DEFECT #1347 IS ABOUT.**
    Each draws the boundary differently, and both existing copies over-reach where this one does not.
    Executed, not reasoned about::

        "fix: see #547 and (BACKLOG #1040)"
            the YAML pipeline  -> ['547', '1040']   its chunk runs from the line START to the ')'
            this function      -> ['1040']

        "(BACKLOG #1040) #547"
            the PowerShell     -> TRUE for 547      its `[^(]*?` crosses the ')'
            this function      -> ['1040']

    Stopping at the nearest parenthesis on EITHER side is the tightest of the three and is the one
    that holds narrowing 3's promise, so it is what this uses. Making all four implementations
    (``scripts/hooks/claim_check.py`` is a fourth) agree is real work in three languages and is not
    this item: the affordable shape is a shared conformance corpus of subjects plus one test per
    language, which would have caught both rows above. Filed as a subject, not a number.

    THE SCOPE IS EXPRESSED AS "UP TO THE NEAREST PARENTHESIS", which covers both shapes in one pass:

        ``(BACKLOG #1040) (#547)``           -> ['1040']     the squash suffix is out of the run
        ``(BACKLOG #1319, #1322, #1331)``    -> three items   siblings are in
        ``... BACKLOG #1136, #1474 ...``     -> both          a bare token with no parenthetical
        ``(BACKLOG #1171, ASVS 11.4.1)``     -> ['1171']      a comma before a non-item
        ``fix(x): something (#999)``         -> []            no token, so nothing is decidable

    Narrowing 3 in the module docstring is UNCHANGED by this: a bare ``#N`` is still only read when a
    ``BACKLOG`` token governs it. What moved is how far that token's governance reaches.

    WHAT THE WIDENING ACTUALLY DID TO THE REAL LEDGERS, measured at ``817db9651`` over 175 examined
    shas, because the useful number is not the one the row predicted:

        agreed        69 -> 76     siblings, including #1347's own control ``df8acc95``
        undecidable   74 -> 62
        findings      32 -> 37

    **THE COUNT WENT UP, AND THAT IS THE HONEST RESULT RATHER THAN A REGRESSION.** Three findings
    went away -- the sibling false alarms this was built for -- and eight arrived, every one of them
    a subject that was previously UNDECIDABLE and now decides. They share a shape: ``backlog:`` used
    as a conventional-commit TYPE, as in ``backlog: close #1091 -- ...``. The token governs the
    numbers after it, so those subjects now name items instead of naming nothing, and a banner citing
    one as its own closing evidence reports as the disagreement it is. Triaging them is BACKLOG
    #1525's fourth arm, which exists for exactly this.

    **THE RESIDUAL, NAMED SO THE GREEN IS NOT READ WIDER.** In a ``backlog:``-typed subject with no
    parenthetical, a trailing PULL-REQUEST number would now read as an item -- the ambiguity
    narrowing 3 exists to avoid, reachable again through the commit type. It is left standing because
    both existing copies of this rule have it and #1347's whole finding is that a THIRD, silently
    different rule is the defect. The two copies are membership tests asking about one known number,
    so the shape rarely surfaces there; enumerating is what exposes it.
    """
    return list(
        dict.fromkeys(n for run in _BACKLOG_RUN.findall(subject) for n in _HASH_N.findall(run))
    )


def _load_parser():  # type: ignore[no-untyped-def]
    """Import ``parse_items`` from the status checker rather than re-deriving banner-block bounds."""
    path = _HERE / "backlog_status_check.py"
    spec = importlib.util.spec_from_file_location("_backlog_status_check", path)
    if spec is None or spec.loader is None:  # pragma: no cover - defensive
        raise RuntimeError(f"cannot import {path}")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class Finding(NamedTuple):
    """One banner claiming a commit that names a DIFFERENT item."""

    path: str
    item: int
    line: int
    sha: str
    names: list[str]
    subject: str


class Report(NamedTuple):
    examined: int
    agreed: int
    undecidable: int
    unresolved: int
    findings: list[Finding]


def _subject(sha: str, repo: Path) -> str | None:
    """The commit's subject, or None when the object is not in this clone.

    Unresolvable is NOT a finding. A shallow clone, a dropped branch or a rescue-only sha would
    otherwise read as corruption, which is the false-alarm direction this check exists to avoid.
    """
    # `sha` is not free text: it reaches here only through `_SHA`, which admits 7-40 characters of
    # [0-9a-f] and nothing else, so it can carry no shell metacharacter and cannot be mistaken for an
    # option (it cannot begin with `-`). `repo` is an argparse path. `git` is resolved from PATH
    # deliberately -- a developer tool must use the same git the operator does, and an absolute path
    # would break every box. The markers sit ON this line because that is where bandit reads them.
    proc = subprocess.run(  # noqa: S603  # nosec B603 B607 - fixed argv, no shell
        ["git", "-C", str(repo), "log", "-1", "--format=%s", sha],
        capture_output=True,
        text=True,
        timeout=30,
    )
    return proc.stdout.strip() if proc.returncode == 0 else None


def scan(paths: list[Path], repo: Path) -> Report:
    parser = _load_parser()
    examined = agreed = undecidable = unresolved = 0
    findings: list[Finding] = []

    for path in paths:
        text = path.read_text(encoding="utf-8", newline="")
        lines = text.split("\r\n") if "\r\n" in text else text.split("\n")
        for item in parser.parse_items(text):
            if not item.closed:  # narrowing 1
                continue
            for offset in range(item.line, len(lines)):
                line = lines[offset]
                if not (line.strip() == "" or line.startswith(">")):
                    break  # end of the banner block, per parse_items' own definition
                if not _CLOSING_CLAIM.search(line):  # narrowing 2
                    continue
                for sha in dict.fromkeys(_SHA.findall(line)):
                    subject = _subject(sha, repo)
                    if subject is None:
                        unresolved += 1
                        continue
                    examined += 1
                    cited = cited_items(subject)  # narrowing 3
                    if not cited:
                        undecidable += 1
                    elif str(item.num) in cited:
                        agreed += 1
                    else:
                        findings.append(
                            Finding(str(path), item.num, offset + 1, sha, cited, subject)
                        )
    return Report(examined, agreed, undecidable, unresolved, findings)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("paths", nargs="*", type=Path)
    ap.add_argument("--repo", type=Path, default=_ROOT)
    ap.add_argument(
        "--advisory",
        action="store_true",
        help="report findings without failing; a MALFUNCTION still exits 2",
    )
    args = ap.parse_args(argv)

    paths = args.paths or [
        _ROOT / "docs" / "BACKLOG.md",
        _ROOT / "docs" / "archive" / "backlog" / "BACKLOG-CLOSED.md",
    ]
    paths = [p for p in paths if p.exists()]
    if not paths:
        print("banner-sha: no ledger file to read -- refusing to report clean", file=sys.stderr)
        return 2

    report = scan(paths, args.repo)

    # COVERAGE ALWAYS, INCLUDING ON A CLEAN RUN. A run that examined nothing and a run that examined
    # everything must not print the same reassuring line -- the row's own warning, in the direction
    # that reads as a clean corpus.
    print(
        f"banner-sha: examined {report.examined} closing-claim sha(s) across {len(paths)} ledger "
        f"file(s); {report.agreed} name their own item, {report.undecidable} name no item "
        f"(undecidable, not a finding), {report.unresolved} unresolvable in this clone"
    )
    if not report.findings:
        print("banner-sha: OK -- no banner claims a commit that names a different item")
        return 0

    print("")
    for f in report.findings:
        others = ", ".join(f"#{n}" for n in f.names)
        print(f"banner-sha: {f.path}:{f.line}")
        print(f"  item #{f.item} claims it was closed by `{f.sha}`,")
        print(f"  but that commit's subject names BACKLOG {others}:")
        print(f"    {f.subject}")
        print(
            "  Either the banner sits under the wrong item, or the citation is wrong. "
            "Both corrupt two items in opposite directions."
        )
        print("")
    # `--advisory` downgrades a FINDING and nothing else. The empty-population refusal above is a
    # MALFUNCTION -- what running from the wrong directory looks like -- and still exits 2, so a scan
    # that read nothing stays distinguishable from one that found nothing.
    return 0 if args.advisory else 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
