# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Did a cell get re-scored AFTER its item's banner was last touched?

BACKLOG #1328, remaining limb. A research-verdict item closes by TWO acts in different seats: a
re-score in the vault scorecard, then a banner flip in the ledger. Step one without step two leaves an
item open while the work is genuinely done, and nothing anywhere reports the disagreement.

**THIS IMPLEMENTS THE DATE COMPARISON, WHICH IS THE PART THAT WAS STILL UNRUN.** The item's first pass
compared banner OPEN/CLOSED STATE, and its own amendment records why that is weaker: *"a flip that
happened, but happened LATE, would not appear."* A state comparison cannot see a flip that arrived
after the re-score that should have caused it; a date comparison can.

**THE MAP IS NOT BUILT AND MUST NOT BE.** #1328's original ask -- a cell-to-item map readable from an
engine checkout -- was WITHDRAWN by amendment because ``CLAUDE.md`` section 12 forbids it: the ASVS
vocabulary is public and the content is not, and completeness is itself the disclosure. The pairs
attached to OPEN items are already public; a COMPLETE map would hand out the rest by subtraction. This
check needs no map -- it reads the partial linkage already present in the record, and its OUTPUT is a
list of backlog item numbers, which are public rows.

***ONLY THE LITERAL "BACKLOG #N" FORM IS MATCHED, AND THAT IS A CORRECTNESS RULE RATHER THAN A STYLE
ONE.*** A bare ``#N`` in that record also spells a PULL REQUEST number and the two namespaces are
indistinguishable by shape. The item records a worked case: an entry citing ``#156`` refers to PR 156,
while backlog #156 is an unrelated alert-hysteresis row. **A cross-reference that resolves cleanly to
the wrong thing reads as a working link forever**, so bare references are counted and reported as
AMBIGUOUS, never resolved.

**WHAT "BANNER LAST TOUCHED" MEANS HERE, AND THE DIRECTION OF THE APPROXIMATION.** The fingerprint is
the banner state ``parse_items`` itself exposes -- the closed and open banner sets plus the
machine-readable fields. It is deliberately NOT a re-derived block boundary: ``parse_items`` is the
single source for where an item's banner begins and ends, and a second definition of that boundary is
exactly the drift ``CLAUDE.md`` warns about.

The cost is stated rather than hidden: **a banner edit that changes only PROSE is invisible to this
fingerprint.** That makes the check report the banner as OLDER than it really is, so it OVER-fires
rather than under-fires. Over-firing is the tolerable direction here -- the item's own text says *"a
nonzero count still needs the entry read"* -- but a hit is a prompt to read, never a finding on its own.

**A TRUNCATED LEDGER IS NOT AUTOMATICALLY AN UNANSWERABLE RUN, AND TREATING IT AS ONE REFUSED EVERY
REAL RUN THIS TOOL HAS.** The engine checkout is shallow, its whole visible history begins at a graft,
and both ledger files exist at that boundary -- so the truncation test fired, the tool exited 3, and
the date comparison the item calls "the open work" never produced an answer at all. Deepening the clone
writes to an object store shared by every worktree and is the owner's call, so the tool has to be
correct on the clone it actually ships into.

***THE TRUNCATION TEST WAS NECESSARY BUT NOT SUFFICIENT, AND THE MISSING HALF IS A DATE.*** A graft
floors an affected item's last-touch at the boundary, and a floored date is always LATER than or equal
to the true one. So the floor can only ever suppress a hit whose re-score is AT OR BEFORE that
boundary; a re-score strictly AFTER it is decided identically on the floored date and on the true one,
because ``re-score > floored >= true``. The same inequality rules out the other direction: a flag
raised against a floored date is still a true flag, so truncation cannot manufacture one.

**THE VERDICT IS THEREFORE PER PAIR, NOT PER RUN.** Pairs dated after the boundary are answered
exactly. Pairs dated at or before it are UNDECIDABLE, and they are named and held out of the all-clear
rather than folded into it -- the whole run is refused only when nothing is decidable, because an
all-clear over zero decided pairs is the same reassuring-answer-to-an-unasked-question this file
already refuses twice.

**THE OTHER HALF OF THE DISTINCTION HOLDS BY CONSTRUCTION AND IS NOW PINNED RATHER THAN ASSUMED.** A
graft OLDER than the ledger's first revision hides nothing, and ``git log -- <path>`` never reports it,
because that walk lists only revisions where the path changed. So the oldest listed revision is a graft
exactly when the path already existed at the boundary. That is why the test below is on the walk's own
first revision and not on the repository's shallowness.

***AND A DATE MOVE IS NOT A RE-SCORE, WHICH IS THE QUESTION THIS FILE'S OWN TITLE ASKS.***
``last_verified`` bumps every time a cell is looked at again -- when the grade changes, and
identically when a re-check CONFIRMS the grade already there. So the date comparison above answers
*"was this cell revisited after the banner moved"*, which is adjacent to the question asked and not
the same sentence (``CLAUDE.md`` section 11, SDS-3.8).

**Measured 2026-09-04 against the vault record at engine ``a2eef0f37``: 35 hits over 28 items, of
which 22 items had NO covering grade change at all after the banner moved.** Four in five hits were
confirmations, and each one still cost a reader the full two-record read. The screen was not wrong --
over-firing is its documented safe direction -- but a prompt list that is four-fifths noise is one
nobody finishes, which is the failure the item was filed about. ``grade_history`` and ``classify``
below split the list, and the reading order is MOVED first.

**IT NAMES NO CELLS.** Output is item numbers, dates, and a direction. Cell identifiers and grade
VALUES stay vaulted; "the grade moved down" is the actionable fact and discloses no value.

Usage::

    python scripts/asvs/rescore_handoff_check.py \\
        --scorecard <vault>/docs/security/asvs-scorecard.toml --root <engine checkout>
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from dataclasses import dataclass
from itertools import pairwise
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "docs"))

from backlog_status_check import (  # type: ignore[import-not-found]  # noqa: E402
    parse_items,
)

# The AUTHORITATIVE verdict vocabulary, imported rather than retyped. ``scorecard.py`` is this
# script's own sibling, so it is already importable wherever this file runs.
from scorecard import VERDICTS  # noqa: E402

#: The ONLY accepted spelling. See the module docstring: a bare ``#N`` is not reliably a backlog number.
ITEM_REF = re.compile(r"BACKLOG #(\d+)")
#: Counted so the ambiguous population is reported rather than silently dropped -- an unreported
#: exclusion is how a denominator quietly stops meaning what it says.
BARE_REF = re.compile(r"(?<!BACKLOG )#(\d+)")
#: ``[[cell]]`` tables are flat, so a cell's own span runs to the next top-level table header.
CELL_START = re.compile(r"^\[\[cell\]\]", re.M)
LAST_VERIFIED = re.compile(r'^\s*last_verified\s*=\s*"([^"]*)"', re.M)
#: Read to JOIN a cell to its own grade history. Never printed -- cell ids stay vaulted.
CELL_ID = re.compile(r'^\s*id\s*=\s*"([^"]*)"', re.M)
VERDICT = re.compile(r'^\s*verdict\s*=\s*"([^"]*)"', re.M)
#: Strength order, used ONLY to say which DIRECTION a grade moved. The ORDER is this file's own
#: judgement and is not derivable from :data:`scorecard.Verdict`, which declares the vocabulary
#: without ranking it -- so the ranking is written here and the VOCABULARY is checked against the
#: type below rather than retyped a third time.
GRADE_RANK = {  # nosec B105 - "pass" here is an ASVS grade name, not a credential
    "unverified": 0,
    "fail": 1,
    "needs-review": 2,
    "partial": 3,
    "pass": 4,
}
#: Outside the ordering on purpose: ``na`` means the requirement does not apply, so a move into or out
#: of it is a scope change, and ranking it would report that as a strengthening or a weakening.
UNRANKED = frozenset({"na"})

# A SEVENTH VERDICT MUST NOT LAND HERE SILENTLY, AND THIS EXACT DRIFT HAS ALREADY HAPPENED ONCE.
# ``scorecard.py`` derives VERDICT_ORDER from the ``Verdict`` type precisely because a hand-written
# second list enumerated five states against a stated six (BACKLOG #1012). GRADE_RANK is a third such
# list, and an unranked verdict does not raise in ``classify`` -- it makes the comparison skip, so a
# genuine downgrade renders as GRADE MOVED instead of GRADE MOVED DOWN, which is the one direction the
# classifier exists for. Failing at import is the whole point: a checker whose vocabulary has silently
# gone stale gives a confident wrong answer, which is what every refusal in this file exists to stop.
if set(GRADE_RANK) | UNRANKED != VERDICTS:
    raise RuntimeError(
        "GRADE_RANK has drifted from scorecard.Verdict. Ranked "
        f"{sorted(set(GRADE_RANK) | UNRANKED)}, but the record defines {sorted(VERDICTS)}. "
        "Rank the new verdict or add it to UNRANKED -- leaving it out makes a downgrade into or out "
        "of it render as a neutral move."
    )


@dataclass(frozen=True)
class Pair:
    """One (item, re-score date) linkage, read from a single cell's own text.

    ``cell`` is carried so the grade history below can be looked up per cell, and it is NEVER
    printed. Cell identifiers stay vaulted (``CLAUDE.md`` section 12); this field exists only to join
    two in-memory tables.
    """

    item: int
    last_verified: str
    cell: str = ""


#: What ``classify`` returns, in the order a reader should care about them.
GRADE_UNCHANGED = "GRADE UNCHANGED since before the banner moved"
GRADE_MOVED = "GRADE MOVED after the banner"
GRADE_MOVED_DOWN = "GRADE MOVED DOWN after the banner -- a closed banner here may rest on a premise"
GRADE_UNKNOWN = "grade history unavailable"


@dataclass(frozen=True)
class Flag:
    item: int
    last_verified: str
    banner_touched: str
    cell: str = ""


def _by_item(entry: tuple[Flag, str]) -> int:
    """Sort key for the printed hit list. A named function rather than a lambda, so mypy --strict
    checks the tuple shape at the call site instead of inferring it."""
    return entry[0].item


def read_pairs(scorecard_text: str) -> tuple[list[Pair], int]:
    """Every (item, last_verified) pair the record states literally, plus the ambiguous count.

    Scoped to each cell's own span rather than the whole file, so an item mentioned in one cell is not
    paired with another cell's date.
    """
    starts = [m.start() for m in CELL_START.finditer(scorecard_text)]
    # NO CELLS MEANS NO SPANS, and the guard is here because ``strict=True`` caught the alternative
    # loudly: with an empty ``starts`` the second sequence still carries the end offset, so the zip
    # raised rather than quietly yielding nothing. A silent empty result would have been read as
    # "this scorecard contains no pairs", which is the answer an unreadable file also gives.
    if not starts:
        return [], 0
    spans = list(zip(starts, starts[1:] + [len(scorecard_text)], strict=True))
    pairs: list[Pair] = []
    ambiguous = 0
    for lo, hi in spans:
        block = scorecard_text[lo:hi]
        verified = LAST_VERIFIED.search(block)
        if verified is None:
            continue
        cell = CELL_ID.search(block)
        ambiguous += len(set(BARE_REF.findall(block)))
        for num in sorted({int(n) for n in ITEM_REF.findall(block)}):
            pairs.append(
                Pair(
                    item=num,
                    last_verified=verified.group(1),
                    cell=cell.group(1) if cell else "",
                )
            )
    return pairs, ambiguous


def grade_history(scorecard: Path) -> dict[str, list[tuple[str, str]]] | None:
    """Per cell, the dates its GRADE actually changed -- or None when that cannot be read.

    ***THIS IS THE HALF THAT SEPARATES A RE-SCORE FROM A RE-VERIFICATION, AND WITHOUT IT THIS TOOL
    ANSWERS A QUESTION ADJACENT TO THE ONE ITS OWN TITLE ASKS.*** ``last_verified`` moves every time a
    cell is looked at again. It moves when the grade changes, and it moves identically when a re-check
    CONFIRMS the grade already there. The date comparison cannot tell those apart, so it fires on both.

    **Measured 2026-09-04 against the vault record at engine ``a2eef0f37``: of 28 flagged items, 22
    had no covering grade change at all after the banner moved.** So roughly four in five hits were
    confirmations, and every one of them cost a reader the full two-record read the item demands. The
    screen was not wrong -- over-firing is its documented safe direction -- but a prompt list that is
    four-fifths noise is one nobody finishes, which is the failure mode the item was filed about.

    The grade is read from the scorecard's OWN git history, oldest first, recording only the
    revisions where a cell's verdict differs from the previous one. A cell absent from a revision
    simply contributes nothing there.

    **RETURNS None RATHER THAN AN EMPTY DICT WHEN THE HISTORY CANNOT BE READ**, because an empty dict
    would classify every hit as ``GRADE UNCHANGED`` -- the most reassuring possible answer, produced
    by having failed to look. That is the same shape as the refusals this file already carries twice.

    **IT STORES GRADES BUT PRINTS NONE.** The caller turns this into MOVED / UNCHANGED / MOVED DOWN.
    Cell ids and grade values stay vaulted; a direction is the actionable fact and discloses no value.
    """
    repo = subprocess.run(  # nosec B603 B607 - fixed argv, no shell; read-only
        ["git", "-C", str(scorecard.parent), "rev-parse", "--show-toplevel"],
        capture_output=True,
        text=True,
        # EXPLICIT, like the two calls below it. This one sets the root the others use, and it was
        # the one call in this function that first went without -- which is exactly how the cp1252
        # trap recorded at length further down got in the first time.
        encoding="utf-8",
    )
    if repo.returncode != 0:
        return None
    root = Path(repo.stdout.strip())
    try:
        relative = scorecard.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return None
    walk = subprocess.run(  # nosec B603 B607 - fixed argv, no shell; read-only git log
        ["git", "-C", str(root), "log", "--format=%H %cs", "--reverse", "--", relative],
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    if walk.returncode != 0 or not walk.stdout.strip():
        return None
    history: dict[str, list[tuple[str, str]]] = {}
    for line in walk.stdout.splitlines():
        sha, _, date = line.partition(" ")
        blob = subprocess.run(  # nosec B603 B607 - fixed argv, no shell; one blob read
            # EXPLICIT ENCODING, for the reason the ledger walk below records at length: locale
            # decoding on this box is cp1252 and silently mangles the file.
            ["git", "-C", str(root), "show", f"{sha}:{relative}"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        if blob.returncode != 0:
            continue
        starts = [m.start() for m in CELL_START.finditer(blob.stdout)]
        if not starts:
            continue
        for lo, hi in zip(starts, starts[1:] + [len(blob.stdout)], strict=True):
            block = blob.stdout[lo:hi]
            cell, verdict = CELL_ID.search(block), VERDICT.search(block)
            if cell is None or verdict is None:
                continue
            seen = history.setdefault(cell.group(1), [])
            if not seen or seen[-1][1] != verdict.group(1):
                seen.append((date.strip(), verdict.group(1)))
    return history or None


def classify(
    flag: Flag, history: dict[str, list[tuple[str, str]]] | None, boundary: str = ""
) -> str:
    """Did this cell's GRADE move after the banner did, or was it merely looked at again?

    A change strictly AFTER ``banner_touched`` is the real handoff signal. A cell whose grade has not
    moved since before the banner moved was re-verified and confirmed, which is the in-sync state.

    ``na`` sits outside the ordering rather than at one end of it: it means the requirement does not
    apply, so a move into or out of it is a scope change and not a strengthening or a weakening.

    ***THE FLOORED-DATE REASONING RUNS THE OPPOSITE WAY HERE, AND REUSING IT UNEXAMINED INVERTED THE
    ANSWER TO THE REASSURING SIDE.*** ``evaluate`` compares ``re-score > banner_touched``, where a
    floored banner date is safe: it is later than or equal to the truth, so it can only SUPPRESS a
    hit. This function asks whether any grade change lands after that same date -- and pushing the
    date later DELETES change points from the window, turning a real MOVED into a confident
    UNCHANGED. Same date, same inequality, opposite direction, because one asks whether a single
    point clears the date and the other asks what survives above it.

    So a floored banner date is answered per case rather than as a whole:

    * a change ABOVE the floor is still a true change, since ``change > floored >= true``, and it is
      reported as MOVED exactly as it would be on the real date;
    * NO change above the floor decides nothing, because a change could sit between the true touch
      and the floor where this walk cannot see it. That is UNKNOWN, never UNCHANGED.

    Without ``boundary`` no date is treated as floored, which is right for an untruncated run.
    """
    # No history at all and no history FOR THIS CELL are the same answer: nothing was read, so
    # nothing is claimed.
    timeline = history.get(flag.cell) if history else None
    if not timeline:
        return GRADE_UNKNOWN
    # A touch date sitting exactly ON the boundary is a floor, not a measurement -- the same test the
    # printer uses when it refuses to render that date bare.
    floored = bool(boundary) and flag.banner_touched == boundary
    if not any(point[0] > flag.banner_touched for point in timeline):
        # UNCHANGED is a claim about everything above the reference date, so it is only available
        # when that date was measured. See the docstring: the floor hides the window it would need.
        return GRADE_UNKNOWN if floored else GRADE_UNCHANGED
    for earlier, later in pairwise(timeline):
        if later[0] <= flag.banner_touched:
            continue
        before_rank, after_rank = GRADE_RANK.get(earlier[1]), GRADE_RANK.get(later[1])
        if before_rank is not None and after_rank is not None and after_rank < before_rank:
            return GRADE_MOVED_DOWN
    return GRADE_MOVED


@dataclass(frozen=True)
class LedgerWalk:
    """What ONE ledger path's walk actually saw, including where it began and why it stopped there.

    Round two recorded truncation as a bare path name, which is enough to REFUSE and not enough to
    decide anything finer. The boundary DATE is the whole discriminator -- it is what separates a pair
    the floor could suppress from one it provably cannot -- so it is carried here rather than
    re-derived by a caller that would have to walk the history again to find it.
    """

    path: str
    #: Revisions the walk found for this path, before ``--limit`` narrows the window.
    revisions_found: int
    #: Revisions actually opened and fingerprinted. Equal to the above unless ``--limit`` was used.
    revisions_walked: int
    #: The oldest revision touching this path, and its committer date. Empty when the path has none.
    oldest_rev: str
    oldest_date: str
    #: True when that oldest revision is a graft point git itself recorded, which means the path
    #: already existed at the boundary and its earlier history is invisible.
    graft_bounded: bool


@dataclass(frozen=True)
class Walk:
    """The walk's answer AND the two ways it can be incomplete, returned together on purpose.

    Round one returned a bare dict. Both caveats below then had to be discovered by a caller that
    knew to ask, and neither was asked for -- so a truncated walk and a walk with unreadable
    revisions both rendered as a complete one. Bundling them makes the incomplete case impossible
    to take without seeing it.
    """

    touched: dict[int, str]
    #: Revisions whose blob ``git show`` could not read. A revision that DELETED the path fails
    #: legitimately, so this is reported rather than refused.
    unreadable_revisions: int
    #: Every ledger path walked, in the order given. Reported in full so an empty scan and a clean
    #: scan cannot render alike.
    ledgers: tuple[LedgerWalk, ...]
    #: Every graft point read from ``.git/shallow``, whether or not it bounded any of these walks.
    grafts_considered: tuple[str, ...]

    @property
    def truncated(self) -> tuple[LedgerWalk, ...]:
        """The ledgers whose walk began at a graft, so history before that point is invisible."""
        return tuple(walked for walked in self.ledgers if walked.graft_bounded)

    @property
    def boundary(self) -> str:
        """The LATEST graft boundary date over every truncated ledger, or "" when none is.

        The latest rather than the earliest, because this date is used as a floor that a pair must
        clear to be decidable, and a pair must clear every floor that could apply to it. An item is
        walked in both ledgers and the later touch wins, so the safe bound is the later boundary.
        """
        return max((walked.oldest_date for walked in self.truncated), default="")


def banner_fingerprint(text: str) -> dict[int, str]:
    """Per item, a fingerprint of the banner state ``parse_items`` exposes.

    A conflicted ledger raises inside ``parse_items`` rather than yielding a census that counts both
    sides -- which is why the historical walk below lets that exception through instead of skipping.
    """
    out: dict[int, str] = {}
    for item in parse_items(text):
        fields = getattr(item, "fields", {}) or {}
        out[item.num] = repr((sorted(item.closed), sorted(item.open), sorted(fields.items())))
    return out


def banner_last_touched(root: Path, backlog_paths: list[str], limit: int | None) -> Walk:
    """The date each item's banner state last CHANGED, walking the ledger's own history.

    Oldest-first, so a change is attributed to the commit that introduced it. An item absent from the
    previous revision counts as touched at the commit that added it.

    **BOTH LEDGER FILES ARE WALKED, AND READING ONLY THE LIVE ONE INVERTED THE ANSWER.** A CLOSED item
    moves to ``docs/archive/backlog/BACKLOG-CLOSED.md``, so a live-only walk reported every closed item
    as *absent from the ledger* -- and a closed item is exactly the case where the banner flip DID
    happen. The check would have hidden its own successes and reported them as missing data. Each file
    is walked separately and the LATEST touch wins, because an item is touched in one file, then moved,
    then touched in the other.
    """
    touched: dict[int, str] = {}
    unreadable = 0
    ledgers: list[LedgerWalk] = []
    # A SHALLOW CLONE IS THE ORDINARY STATE OF THIS REPOSITORY, NOT AN EDGE CASE. Measured
    # 2026-08-29: the primary and every worktree report true, over 856 commits with 3 graft points.
    # RE-MEASURED 2026-09-03 AND BOTH NUMBERS HAD MOVED: 719 commits and 20 graft points, and the
    # ONLY parentless commit reachable from HEAD is itself a graft. So the shape of this is not
    # stable across re-fetches and neither figure should be relied on -- only the per-path test is.
    # So refusing on shallowness ALONE would refuse every real run on this machine -- which is why
    # the discriminator below is per-path rather than per-repository.
    #
    # THE GRAFT POINTS ARE READ BY NAME RATHER THAN INFERRED FROM "HAS NO PARENT", AND THE
    # DIFFERENCE IS A FALSE REFUSAL THIS CHECK ALREADY SHIPPED ONCE. A TRUE ROOT also has no parent.
    # This repository carries a deliberate 2026-07-06 history reset whose root commit appears in NONE
    # of the three graft points, so every file present in it -- .gitattributes, .gitignore, .github --
    # was reported as truncated on a COMPLETE history, with remediation advice that cannot help,
    # because a reset root's ancestors are not on the remote either.
    grafts: set[str] = set()
    common = subprocess.run(  # nosec B603 B607 - fixed argv, no shell; read-only
        ["git", "-C", str(root), "rev-parse", "--path-format=absolute", "--git-common-dir"],
        capture_output=True,
        text=True,
    )
    if common.returncode == 0:
        shallow_file = Path(common.stdout.strip()) / "shallow"
        if shallow_file.is_file():
            grafts = {
                line.strip()
                for line in shallow_file.read_text(encoding="utf-8").splitlines()
                if line.strip()
            }
    for backlog_path in backlog_paths:
        walk = subprocess.run(  # nosec B603 B607 - fixed argv, no shell; read-only git log
            ["git", "-C", str(root), "log", "--format=%H %cs", "--reverse", "--", backlog_path],
            capture_output=True,
            text=True,
            encoding="utf-8",
        )
        # A FAILED WALK YIELDS NO LINES, AND NO LINES IS EXACTLY WHAT A LEDGER WHOSE BANNERS NEVER
        # MOVED ALSO YIELDS. Raising is the only thing that keeps the two apart, and the caller's
        # emptiness guard is not a substitute: a walk that fails over ONE of the two ledgers while
        # the other succeeds leaves a PARTIAL result, which is non-empty and reads as complete.
        if walk.returncode != 0:
            raise RuntimeError(
                f"git log failed over {backlog_path} in {root} "
                f"(exit {walk.returncode}): {walk.stderr.strip()}"
            )
        revs = walk.stdout.splitlines()

        # TRUNCATION IS A DIFFERENT FAILURE FROM AN ERROR, AND IT EXITS ZERO. On a shallow clone
        # ``git log`` succeeds over the visible window, so no returncode guard can see it. Every
        # banner date then floors at the clone boundary, which makes the last touch look LATER than
        # it was -- and ``evaluate`` fires only on a re-score strictly later than the touch, so real
        # hits are SUPPRESSED. That is the under-fire direction the module docstring rules out.
        #
        # THE TEST IS WHETHER THIS PATH'S WALK STOPPED AT A GRAFT, not whether the repo is shallow
        # and not whether the oldest revision has a parent. Only a commit git itself recorded in
        # ``.git/shallow`` marks history it cannot see; a parentless commit that is not in that list
        # is a real beginning, and the walk that reached it saw everything there is.
        #
        # AND THIS IS ALSO WHERE THE OTHER HALF OF THE DISTINCTION IS DECIDED, BY CONSTRUCTION
        # RATHER THAN BY A SECOND TEST. ``git log -- <path>`` lists only revisions where the path
        # CHANGED, so a graft that predates the ledger's own first revision is never the oldest line
        # here -- the oldest line is the commit that created the ledger, which has a visible parent.
        # The oldest revision is a graft exactly when the path ALREADY EXISTED at the boundary, which
        # is exactly when earlier banner history is hidden. Recording the boundary DATE rather than
        # just the fact lets the caller decide which pairs that hidden history could actually move.
        oldest_rev, _, oldest_date = revs[0].partition(" ") if revs else ("", "", "")
        graft_bounded = bool(grafts and revs and oldest_rev in grafts)

        found = len(revs)
        if limit is not None:
            revs = revs[-limit:]
        ledgers.append(
            LedgerWalk(
                path=backlog_path,
                revisions_found=found,
                revisions_walked=len(revs),
                oldest_rev=oldest_rev,
                oldest_date=oldest_date.strip(),
                graft_bounded=graft_bounded,
            )
        )

        previous: dict[int, str] = {}
        for line in revs:
            sha, _, date = line.partition(" ")
            blob = subprocess.run(  # nosec B603 B607 - fixed argv, no shell; one blob read
                # ENCODING IS EXPLICIT, AND ITS ABSENCE MADE THIS TOOL SILENTLY USELESS.
                # ``text=True`` decodes with the LOCALE encoding -- cp1252 on this box -- which
                # destroys every banner glyph, so ``parse_items`` found no banners, every
                # fingerprint came back empty, and the walk reported that NO banner had ever
                # changed. The output stayed perfectly plausible.
                ["git", "-C", str(root), "show", f"{sha}:{backlog_path}"],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
            )
            if blob.returncode != 0:
                # A revision that DELETED the path fails here legitimately, so this is counted and
                # reported rather than refused. It is NOT harmless: the skip leaves ``previous``
                # untouched, so the next readable revision is diffed against a stale fingerprint and
                # its change is dated LATER than it happened -- the hit-suppressing direction again.
                unreadable += 1
                continue
            try:
                current = banner_fingerprint(blob.stdout)
            except ValueError:
                # A conflicted revision in history is not this check's business, but skipping it
                # silently would let the NEXT revision's diff read as a change that never happened.
                continue
            for num, fingerprint in current.items():
                if previous.get(num) != fingerprint:
                    # LATEST WINS ACROSS FILES: an item is touched in the live ledger, then moved to
                    # the archive, then touched there. Taking the max keeps the move from reading as
                    # an older banner than the item really has.
                    stamp = date.strip()
                    if stamp > touched.get(num, ""):
                        touched[num] = stamp
            previous = current
    return Walk(
        touched=touched,
        unreadable_revisions=unreadable,
        ledgers=tuple(ledgers),
        grafts_considered=tuple(sorted(grafts)),
    )


def evaluate(pairs: list[Pair], touched: dict[int, str]) -> tuple[list[Flag], list[int]]:
    """Flag a pair whose re-score is strictly LATER than its item's last banner touch.

    Strictly later, not later-or-equal: a re-score and a flip landing on the same day is the in-sync
    case, and treating it as a hit would fire on every correctly handled item.
    """
    flags: list[Flag] = []
    unknown: list[int] = []
    for pair in pairs:
        when = touched.get(pair.item)
        if when is None:
            unknown.append(pair.item)
            continue
        if pair.last_verified and pair.last_verified > when:
            flags.append(Flag(pair.item, pair.last_verified, when, pair.cell))
    return flags, sorted(set(unknown))


def split_by_boundary(
    pairs: list[Pair], boundary: str, touched: dict[int, str]
) -> tuple[list[Pair], list[Pair]]:
    """Split pairs into the ones a graft boundary cannot affect and the ones it can.

    A graft floors an affected item's last-touch date AT the boundary, and the floor is always later
    than or equal to the truth. So for a pair dated strictly after the boundary,
    ``re-score > floored >= true`` holds and the verdict is the same on either date -- decidable. A
    pair dated at or before it could have a true touch on either side of its own date, and no reading
    of the visible history can say which -- undecidable, and the reason it is named rather than
    silently answered.

    ***THE SAME INEQUALITY DECIDES A SECOND CLASS, AND READING IT ONLY ONE WAY CALLED MEASURED DATES
    UNDECIDABLE.*** Hidden revisions all sit at or before the boundary, so an item's true last touch
    is ``max(visible, something <= boundary)``. When the VISIBLE touch is already strictly after the
    boundary, that max is the visible date itself -- the walk measured it, the graft cannot raise it,
    and the pair is decidable whatever its own re-score date is. Only an item whose visible touch is
    still at or before the boundary is genuinely floored.

    **The measured gain is small and is stated rather than implied**: against the vault record at
    engine ``a2eef0f37``, this widening decides one further pair at the 2026-09-03 graft boundary and
    none at the 2026-08-31 one. It is here because calling a measured date undecidable is a wrong
    answer, not because it moved a count.

    ``touched`` is REQUIRED, not defaulted. There is one production caller and nothing outside this
    file imports the function, so a compatibility default protects nobody (section 0: with zero
    deployments the cost of a breaking signature is zero). It would instead leave a silently weaker
    path where "the caller passed no map" and "these items have no measured touch" collapse into the
    same expression -- and that path errs toward UNDECIDABLE, which suppresses hits and makes the
    whole-run refusal more likely. An empty ``boundary`` means no walk began at a graft, so
    everything is decidable.
    """
    if not boundary:
        return list(pairs), []
    decidable: list[Pair] = []
    undecidable: list[Pair] = []
    for pair in pairs:
        clears = pair.last_verified > boundary or touched.get(pair.item, "") > boundary
        (decidable if clears else undecidable).append(pair)
    return decidable, undecidable


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--scorecard", type=Path, required=True)
    ap.add_argument("--root", type=Path, required=True, help="engine checkout holding the ledger")
    ap.add_argument(
        "--backlog",
        action="append",
        help="ledger path to walk; repeatable. Defaults to the live ledger AND the closed archive, "
        "because a closed item lives only in the second and that is the case where the flip happened.",
    )
    ap.add_argument(
        "--limit",
        type=int,
        help="walk only the newest N revisions of each ledger. DIAGNOSTIC ONLY -- it floors every "
        "last-touched date at the window boundary, which manufactures hits, so the flag list is "
        "suppressed when it is used.",
    )
    args = ap.parse_args(argv)

    if not args.scorecard.is_file():
        sys.stderr.write(f"scorecard not found: {args.scorecard}\n")
        return 2
    if not (args.root / ".git").exists():
        sys.stderr.write(f"--root is not a git checkout: {args.root}\n")
        return 2

    # THE REF PAIR IS PART OF THE MEASUREMENT, SO AN UNRESOLVABLE HEAD IS A REFUSAL. On a repo with
    # no commits ``git rev-parse HEAD`` exits 128 and still ECHOES THE LITERAL ``HEAD`` ON STDOUT, so
    # an unchecked read stamps ``engine=HEAD`` -- which reads as a deliberate value rather than as a
    # failure, and passes review forever. An empty string would at least have invited a second look.
    rev = subprocess.run(  # nosec B603 B607 - fixed argv, no shell; rev-parse takes no input
        ["git", "-C", str(args.root), "rev-parse", "HEAD"], capture_output=True, text=True
    )
    if rev.returncode != 0:
        sys.stderr.write(
            f"REFUSING: cannot resolve HEAD in {args.root} (exit {rev.returncode}). The engine ref "
            "is part of this measurement, and git echoes the literal 'HEAD' on this failure, so an "
            "unchecked read would stamp engine=HEAD and look deliberate.\n"
        )
        return 3
    head = rev.stdout.strip()

    pairs, ambiguous = read_pairs(args.scorecard.read_text(encoding="utf-8", errors="replace"))
    if not pairs:
        sys.stderr.write(
            "REFUSING: zero literal 'BACKLOG #N' pairs found. An empty result here is "
            "indistinguishable from a scorecard this tool could not read.\n"
        )
        return 3

    ledgers = args.backlog or ["docs/BACKLOG.md", "docs/archive/backlog/BACKLOG-CLOSED.md"]
    try:
        walk = banner_last_touched(args.root, ledgers, args.limit)
    except RuntimeError as exc:
        sys.stderr.write(f"REFUSING: {exc}\n")
        return 3
    touched = walk.touched
    boundary = walk.boundary
    decidable, undecidable = split_by_boundary(pairs, boundary, touched)
    if boundary and not decidable:
        oldest = min((pair.last_verified for pair in pairs if pair.last_verified), default="")
        sys.stderr.write(
            "REFUSING: the ledger history is TRUNCATED at a shallow graft boundary dated "
            f"{boundary} for {[walked.path for walked in walk.truncated]}, and EVERY pair read is "
            "dated at or before it, so this run can decide nothing. A floored date reads as a LATER "
            "touch, which SUPPRESSES real hits rather than inventing them -- the one direction this "
            "check exists to rule out.\n"
            "\n"
            "THE CHEAP REMEDY IS A SEPARATE CLONE, NOT A DEEPER SHARED ONE, and the difference is "
            "who has to approve it. 'git fetch --unshallow' writes to an object store shared by "
            "every worktree, which is why deepening this checkout is the owner's call. A throwaway "
            "clone shares no object store, so that objection does not reach it, and this tool "
            "already takes the history source as an argument:\n"
            "\n"
            "    git clone --single-branch --branch main --no-checkout <remote> <scratch>\n"
            f"    {Path(sys.argv[0]).name} --scorecard <scorecard> --root <scratch>\n"
            "\n"
            "Measured 2026-09-04: 35 MB in 17 seconds, against 3.7 GB for the shared store. "
            f"The oldest re-score this run must cover is {oldest}, so a clone reaching that date is "
            "enough; --unshallow is more than the question needs.\n"
            "\n"
            "DO NOT pass --filter=blob:none for this. A blobless clone fetches each ledger revision "
            "on demand, one network round trip per revision, and did not finish in ten minutes.\n"
        )
        return 3
    # THE GUARD THIRTY LINES ABOVE, FOR THE OTHER INPUT, AND THE REASONING TRANSFERS VERBATIM. With
    # no history every pair falls to ``unknown``, ``flags`` is empty, and the tool prints the
    # all-clear -- the most reassuring possible answer to a question it never got to ask.
    if not touched:
        sys.stderr.write(
            "REFUSING: the ledger walk found no banner history at all. An empty result here is "
            "indistinguishable from a ledger this tool could not read, and every pair would fall "
            f"to 'unknown' while the verdict still printed the all-clear. Walked: {ledgers}\n"
        )
        return 3
    flags, unknown = evaluate(decidable, touched)

    print(f"# rescore-handoff scorecard={args.scorecard} engine={head[:12]}")
    print(
        f"pairs read (literal 'BACKLOG #N' only): {len(pairs)} over {len({p.item for p in pairs})} items"
    )
    print(f"bare '#N' references NOT resolved (ambiguous with PR numbers): {ambiguous}")
    print(f"items whose banner history was found: {len(touched)}")
    # STATED EVEN WHEN ZERO. An absent line cannot be checked; a printed zero can.
    print(f"revisions the walk could not read: {walk.unreadable_revisions}")
    # WHAT THE WALK ACTUALLY SCANNED, PER PATH. An empty scan and a clean scan must not render
    # alike, and this tool has already shipped one failure of exactly that shape: a locale-decoded
    # blob destroyed every banner glyph, so the walk found no change anywhere and said so in
    # perfectly plausible output. A revision count is the cheapest thing that would have caught it.
    print(f"graft points git recorded in .git/shallow: {len(walk.grafts_considered)}")
    for walked in walk.ledgers:
        began = (
            f"oldest {walked.oldest_rev[:12]} ({walked.oldest_date})"
            if walked.oldest_rev
            else "none"
        )
        where = (
            "AT A GRAFT, so earlier banner history is hidden"
            if walked.graft_bounded
            else "not at a graft, so the walk saw every revision of this path there is"
        )
        print(
            f"walked {walked.path}: {walked.revisions_walked} of {walked.revisions_found} "
            f"revisions, {began}, {where}"
        )
    # WHICH BRANCH OF THE DISTINCTION THIS RUN TOOK, NAMED RATHER THAN INFERRED FROM THE ABSENCE OF
    # A REFUSAL. The two branches produce different guarantees, and a reader cannot tell them apart
    # from a verdict line that reads the same either way.
    if not boundary:
        print(
            "truncation branch: NONE -- no ledger walk began at a graft, so every pair is decided "
            "against a true last-touch date"
        )
    else:
        print(
            f"truncation branch: BOUNDED at {boundary}. A floored date can only suppress a hit "
            f"dated at or before it, so {len(decidable)} pairs are decided exactly and "
            f"{len(undecidable)} are UNDECIDABLE"
        )
    if undecidable:
        print(
            "items NOT covered by the verdict below (re-scored at or before the graft boundary): "
            f"{sorted({pair.item for pair in undecidable})}"
        )
    if unknown:
        print(f"items referenced but absent from every ledger walked: {sorted(unknown)}")
    print()
    # A TRUNCATED WALK CANNOT ANSWER THIS QUESTION, so it is not allowed to look as though it did.
    # With --limit the oldest revision in the window becomes every item's apparent last touch, so
    # every re-score after that date reports as a missing flip. Measured on a 40-revision window: 16
    # hits, all dated at the boundary. Refusing the list is the only honest output.
    if args.limit is not None:
        print(
            f"--limit {args.limit} was used, so last-touched dates are FLOORED at the window "
            "boundary and the flag list is SUPPRESSED. Re-run without --limit for a real answer."
        )
        return 0
    if not flags:
        # THE QUALIFIER IS THE POINT. An unqualified all-clear over a run that could not decide some
        # of its pairs is the same wrong answer the refusals above exist to prevent, arriving one
        # step later -- so the scope of the clean verdict is stated in the verdict itself, not left
        # to a reader who is expected to have read the branch line four lines earlier.
        if undecidable:
            print(
                f"no DECIDABLE item was re-scored after its banner was last touched "
                f"({len(decidable)} of {len(pairs)} pairs). The "
                f"{len({pair.item for pair in undecidable})} undecidable items above are NOT "
                "covered by this line."
            )
        else:
            print("no item was re-scored after its banner was last touched")
        return 0
    history = grade_history(args.scorecard)
    # ONE ORDERED LIST, COUNTED AND PRINTED FROM THE SAME STRUCTURE. Keying this on the Flag itself
    # made the counts silently disagree with the lines below: two flags equal in every field collapse
    # to one dict entry, so the summary would describe fewer hits than it went on to print.
    ranked = sorted(((flag, classify(flag, history, boundary)) for flag in flags), key=_by_item)
    if history is None:
        print(
            "GRADE HISTORY UNAVAILABLE -- the scorecard is not in a readable git checkout, so every "
            "hit below is a bare date move and cannot be told apart from a re-verification that "
            "confirmed the grade already there."
        )
    else:
        # THREE BUCKETS, NOT TWO, AND COUNTING THEM AS TWO MADE THIS LINE SAY THE OPPOSITE OF THE
        # TRUTH. The first cut counted everything that was not UNCHANGED as "moved", so a hit whose
        # grade history could not be read was reported as a grade that MOVED -- failure-to-look
        # rendering as the strongest possible signal, in the one summary sentence a reader acts on.
        # Each bucket is now counted by naming it, so a fourth verdict cannot silently join another.
        confirmed = sum(1 for _, verdict in ranked if verdict == GRADE_UNCHANGED)
        unreadable = sum(1 for _, verdict in ranked if verdict == GRADE_UNKNOWN)
        moved = sum(1 for _, verdict in ranked if verdict in (GRADE_MOVED, GRADE_MOVED_DOWN))
        print(
            f"of these, {moved} sit on a cell whose GRADE moved after the banner, {confirmed} on a "
            f"cell that was only re-verified, and {unreadable} could not be decided. A "
            "re-verification bumps last_verified without changing anything, so it is the IN-SYNC "
            "state and not a handoff."
        )
        # A COUNT THAT DOES NOT ADD UP TO THE LINES PRINTED BELOW IS THE BUG THIS BLOCK ALREADY HAD
        # ONCE, so the arithmetic is asserted rather than trusted.
        assert confirmed + unreadable + moved == len(ranked), "a verdict escaped every bucket"
    print(f"RE-SCORED AFTER THE BANNER WAS LAST TOUCHED: {len(ranked)}")
    for flag, verdict in ranked:
        # A TOUCH DATE SITTING EXACTLY ON THE BOUNDARY IS A FLOOR, NOT A MEASUREMENT, AND PRINTING
        # IT BARE WOULD HAND A READER A FLIP DATE THAT NEVER HAPPENED. The FLAG is still sound --
        # the re-score cleared the floor and the floor is later than or equal to the truth -- but
        # the item's real last touch is somewhere before the boundary and this walk cannot see it.
        # Equality cannot separate "floored" from "genuinely touched by the graft revision", and it
        # does not need to: the true date is at or before the boundary in both cases.
        when = (
            f"at or before {boundary} (FLOORED at the graft, not measured)"
            if boundary and flag.banner_touched == boundary
            else flag.banner_touched
        )
        print(
            f"  BACKLOG #{flag.item}: re-scored {flag.last_verified}, banner last touched {when}"
            f"  [{verdict}]"
        )
    print()
    # ONLY WHEN THERE IS SUCH A LINE TO READ. Printed unconditionally, this told a reader to start
    # with a category the output above did not contain.
    if any(verdict in (GRADE_MOVED, GRADE_MOVED_DOWN) for _, verdict in ranked):
        print(
            "READ THE 'GRADE MOVED' LINES FIRST. A 'GRADE UNCHANGED' line is a cell that was looked"
        )
        print("at again and confirmed, which is what an in-sync pair looks like.")
    print(
        "A hit is a PROMPT TO READ THE ENTRY, not a finding. The item's own first run produced two"
    )
    print("apparent hits that dissolved on reading -- one a PR-number collision, one an explicit")
    print("'not graded here' cross-reference.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
