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

**IT NAMES NO CELLS.** Output is item numbers and dates. Cell identifiers stay vaulted.

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
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "docs"))

from backlog_status_check import (  # type: ignore[import-not-found]  # noqa: E402
    parse_items,
)

#: The ONLY accepted spelling. See the module docstring: a bare ``#N`` is not reliably a backlog number.
ITEM_REF = re.compile(r"BACKLOG #(\d+)")
#: Counted so the ambiguous population is reported rather than silently dropped -- an unreported
#: exclusion is how a denominator quietly stops meaning what it says.
BARE_REF = re.compile(r"(?<!BACKLOG )#(\d+)")
#: ``[[cell]]`` tables are flat, so a cell's own span runs to the next top-level table header.
CELL_START = re.compile(r"^\[\[cell\]\]", re.M)
LAST_VERIFIED = re.compile(r'^\s*last_verified\s*=\s*"([^"]*)"', re.M)


@dataclass(frozen=True)
class Pair:
    """One (item, re-score date) linkage, read from a single cell's own text."""

    item: int
    last_verified: str


@dataclass(frozen=True)
class Flag:
    item: int
    last_verified: str
    banner_touched: str


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
        ambiguous += len(set(BARE_REF.findall(block)))
        for num in sorted({int(n) for n in ITEM_REF.findall(block)}):
            pairs.append(Pair(item=num, last_verified=verified.group(1)))
    return pairs, ambiguous


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
            flags.append(Flag(pair.item, pair.last_verified, when))
    return flags, sorted(set(unknown))


def split_by_boundary(pairs: list[Pair], boundary: str) -> tuple[list[Pair], list[Pair]]:
    """Split pairs into the ones a graft boundary cannot affect and the ones it can.

    A graft floors an affected item's last-touch date AT the boundary, and the floor is always later
    than or equal to the truth. So for a pair dated strictly after the boundary,
    ``re-score > floored >= true`` holds and the verdict is the same on either date -- decidable. A
    pair dated at or before it could have a true touch on either side of its own date, and no reading
    of the visible history can say which -- undecidable, and the reason it is named rather than
    silently answered.

    An empty ``boundary`` means no walk began at a graft, so everything is decidable.
    """
    if not boundary:
        return list(pairs), []
    decidable = [pair for pair in pairs if pair.last_verified > boundary]
    undecidable = [pair for pair in pairs if pair.last_verified <= boundary]
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
    decidable, undecidable = split_by_boundary(pairs, boundary)
    if boundary and not decidable:
        sys.stderr.write(
            "REFUSING: the ledger history is TRUNCATED at a shallow graft boundary dated "
            f"{boundary} for {[walked.path for walked in walk.truncated]}, and EVERY pair read is "
            "dated at or before it, so this run can decide nothing. A floored date reads as a LATER "
            "touch, which SUPPRESSES real hits rather than inventing them -- the one direction this "
            "check exists to rule out. Deepen the clone (git fetch --unshallow, which writes to an "
            "object store shared by every worktree) and re-run.\n"
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
    print(f"RE-SCORED AFTER THE BANNER WAS LAST TOUCHED: {len(flags)}")
    for flag in sorted(flags, key=lambda f: f.item):
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
        print(f"  BACKLOG #{flag.item}: re-scored {flag.last_verified}, banner last touched {when}")
    print()
    print(
        "A hit is a PROMPT TO READ THE ENTRY, not a finding. The item's own first run produced two"
    )
    print("apparent hits that dissolved on reading -- one a PR-number collision, one an explicit")
    print("'not graded here' cross-reference.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
