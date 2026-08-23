# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
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

#: The ONLY unambiguous item citation in a commit subject. A bare `#N` is a PR as often as an item.
_ITEM_CITATION = re.compile(r"BACKLOG\s+#(\d+)", re.I)


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
                    cited = _ITEM_CITATION.findall(subject)  # narrowing 3
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
    return 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
