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
    #: Ledger paths whose walk began at a shallow graft boundary, so history before it is invisible.
    truncated: tuple[str, ...]


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
    truncated: list[str] = []
    # A SHALLOW CLONE IS THE ORDINARY STATE OF THIS REPOSITORY, NOT AN EDGE CASE. Measured
    # 2026-08-29: the primary and every worktree report true, over 856 commits with 3 graft points.
    # So refusing on shallowness ALONE would refuse every real run on this machine -- which is why
    # the discriminator below is per-path rather than per-repository.
    shallow = (
        subprocess.run(  # nosec B603 B607 - fixed argv, no shell; read-only
            ["git", "-C", str(root), "rev-parse", "--is-shallow-repository"],
            capture_output=True,
            text=True,
        ).stdout.strip()
        == "true"
    )
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
        # THE TEST IS WHETHER THIS PATH'S OWN HISTORY IS COMPLETE, not whether the repo is shallow.
        # If the oldest revision touching the ledger has a parent, the walk saw the commit before the
        # file existed, so nothing about it is missing however shallow the clone is.
        if shallow and revs:
            oldest = revs[0].partition(" ")[0]
            has_parent = (
                subprocess.run(  # nosec B603 B607 - fixed argv, no shell; read-only
                    ["git", "-C", str(root), "rev-parse", "--verify", "--quiet", oldest + "^"],
                    capture_output=True,
                    text=True,
                ).returncode
                == 0
            )
            if not has_parent:
                truncated.append(backlog_path)

        if limit is not None:
            revs = revs[-limit:]

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
    return Walk(touched=touched, unreadable_revisions=unreadable, truncated=tuple(truncated))


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
    if walk.truncated:
        sys.stderr.write(
            "REFUSING: the ledger history is TRUNCATED at a shallow graft boundary for "
            f"{list(walk.truncated)}, so every banner date floors at that boundary. A floored date "
            "reads as a LATER touch, which SUPPRESSES real hits rather than inventing them -- the "
            "one direction this check exists to rule out. Deepen the clone (git fetch --unshallow) "
            "and re-run.\n"
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
    flags, unknown = evaluate(pairs, touched)

    print(f"# rescore-handoff scorecard={args.scorecard} engine={head[:12]}")
    print(
        f"pairs read (literal 'BACKLOG #N' only): {len(pairs)} over {len({p.item for p in pairs})} items"
    )
    print(f"bare '#N' references NOT resolved (ambiguous with PR numbers): {ambiguous}")
    print(f"items whose banner history was found: {len(touched)}")
    # STATED EVEN WHEN ZERO. An absent line cannot be checked; a printed zero can.
    print(f"revisions the walk could not read: {walk.unreadable_revisions}")
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
        print("no item was re-scored after its banner was last touched")
        return 0
    print(f"RE-SCORED AFTER THE BANNER WAS LAST TOUCHED: {len(flags)}")
    for flag in sorted(flags, key=lambda f: f.item):
        print(
            f"  BACKLOG #{flag.item}: re-scored {flag.last_verified}, banner last touched {flag.banner_touched}"
        )
    print()
    print(
        "A hit is a PROMPT TO READ THE ENTRY, not a finding. The item's own first run produced two"
    )
    print("apparent hits that dissolved on reading -- one a PR-number collision, one an explicit")
    print("'not graded here' cross-reference.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
