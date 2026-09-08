#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Ask the TREE whether landed code cites a backlog row's number (BACKLOG #1398).

**The failure this exists to catch, measured.** On 2026-08-29 a dispatcher screened row #1300 as
open, unclaimed, in no pull-request title or body, and carrying no bar: *"P1, quick win, not
started"*. It was already built and shipped on ``main``. The only way anyone found out was by
starting the work.

**THERE WAS NOTHING IN THE TEXT TO MISS.** That is what separates this from the class where a row
SAYS its work shipped and a screen misses the word. #1300 said nothing at all: no bar, no ``DO
NOT``, no shipped sentence. No amount of reading the ledger finds that row, however carefully. A
banner is a hand-maintained claim ABOUT the code, and it goes stale in the direction nothing
detects, because the incentive structure produces stale banners as its NORMAL output: a builder's
commit reliably cites the row number, since gates require it, and the row is the one artefact in the
loop that nothing forces anyone to update.

So this asks the tree instead.

**WHAT IT ANSWERS, AND THE SENTENCE IS NOT THE ONE YOU WANT.** It answers *"does code on
``origin/main`` cite this number"*. That is NOT *"this row is built"*, and the two must never be
printed as if they were. Both directions are live on today's corpus:

* **A citation is not a completion.** Landed code can cite a row while FILING it, while testing
  around it, or while recording why it was NOT done. Row #1375 is the worked example: two files on
  ``origin/main`` carry a bare ``#1375`` asserting the allowlist backup exists, and the row itself
  refutes both from source. A reader who took a hit as a verdict would close a live defect.
* **Silence is not proof of unbuilt.** This screen sees LANDED code, and built work does not always
  land. #1375 again: it was fully built on 2026-08-29 onto a branch that never reached ``origin``,
  and the row's own published needle returns **zero** for it. BUILT and LANDED are different
  questions and this instrument answers only the second.

**IT IS A MUST-BE-READ SIGNAL, NEVER A VERDICT, AND THE FLAG RATE IS WHY.** Measured at
``fd44b0f17`` and again at ``46ea10a78``: **118 of 275 open rows are cited by code that landed, a
42.9 percent flag rate.** At that density a refusal is a wave that never dispatches, so nothing here
exits non-zero on a finding. Only the INSTRUMENT can fail this tool.

**BOTH CONTROLS RUN ON EVERY INVOCATION AND THE RESULT IS WORTHLESS WITHOUT THEM.** A broken
pattern, an unfetched ref or a mistyped path list returns zero for every row and reads as *"nothing
is built"* -- a false zero that has fired twice in one session. One control must come back cited and
one must come back clear, or no line below it is evidence. See :data:`CONTROLS`.

**NOT THE SAME QUESTION AS THE TWO CITATION CHECKERS IN ``scripts/docs/``.**
``backlog_citation_check.py`` asks whether a citation names the ledger FILE its item lives in, and
``dangling_citation_check.py`` asks whether a cited number exists at all. Both read documents and
ask about the CITATION. This reads code and asks about the ROW. Neither subsumes any other.

Usage::

    python scripts/coord/landed_citation_screen.py 1300 1375 1396
    python scripts/coord/landed_citation_screen.py --all-open
    python scripts/coord/landed_citation_screen.py --range 1380-1399
    python scripts/coord/landed_citation_screen.py --self-test

Exit 0 whenever the screen ran, however many rows it flagged. Exit 1 only on an INSTRUMENT ERROR:
a control that did not hold, a ref that would not resolve, or a ledger that did not parse.
"""

from __future__ import annotations

import argparse
import re
import subprocess  # nosec B404 - fixed argv, no shell; see _git
import sys
from dataclasses import dataclass
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "docs"))

from backlog_status_check import (  # type: ignore[import-not-found]  # noqa: E402
    DEFAULT_SOURCES,
    parse_items,
)

#: The tree this screen asks. LANDED code, which is the whole point -- a branch nobody pushed is
#: invisible here by design, and that is a limit to state rather than a gap to close.
DEFAULT_REF = "origin/main"

#: Exactly the paths the row names. Widening this changes what a hit means, so it is a decision with
#: its own review rather than a convenience default: ``docs/`` in particular would make the ledger
#: cite itself and every row would flag.
SEARCH_PATHS: tuple[str, ...] = ("tests/", "scripts/", "messagefoundry/", ".github/")

# Below this the ledger did not resolve and no flag rate computed from it is evidence. Same floor
# argument as `dispatch_gate.MIN_ITEMS` and `backlog_status_check --min-items`: every assertion here
# is satisfied just as well by a remnant of the corpus as by all of it.
MIN_ITEMS = 50

# THE NEEDLE IS BUILT FROM THE NUMBER AT RUN TIME AND NEVER WRITTEN OUT WITH ITS DIGITS ATTACHED.
# This file and its test live INSIDE the searched paths, so a source line reading the joined form for
# a control number would be found by the very sweep it is a control for -- the instrument would
# answer its own question, and the negative control would flip the day it landed.
# `test_no_control_number_is_written_as_a_citation` pins that rather than trusting this comment.
_STRICT_PREFIX = "BACKLOG #"

# One sweep serves both needles: a strict line is a subset of a loose one. Case-sensitive, matching
# the row's own published command, so the two can be held against each other (see `check_agreement`).
#
# THIS PATTERN BOUNDS THE BARE EXTRACTOR BELOW IT, which is worth knowing before anyone widens
# either. Measured 2026-09-03: widening `_LOOSE` alone changes NOTHING on the real tree, because git
# only ever returns lines that already carry a `#` followed by digits. It takes widening BOTH to
# flood the weaker level, and that is the mutation the sentinel's bare arm is pinned against.
_SWEEP_PATTERN = "#[0-9]+"
_STRICT = re.compile(re.escape(_STRICT_PREFIX) + r"(\d+)")
_LOOSE = re.compile(r"#(\d+)")

#: Landed code carries the joined ``BACKLOG`` form of this number. The strongest signal here, and
#: still only a reason to read the row.
CITED = "CITED"

#: Landed code carries a bare ``#N`` and never the joined form. WEAKER ON PURPOSE: a bare ``#N`` is
#: ambiguous in this repository -- it may name a pull request rather than an item -- and it is the
#: form a claim ABOUT a row takes as often as a claim of work done. It earns its place by
#: measurement, not by theory: at ``fd44b0f17`` it raises the flag rate from 42.9 to 47.3 percent,
#: twelve extra open rows, and one of those twelve is #1375.
MENTIONED = "MENTIONED"

#: No citation of any form. NOT a clean bill of health: see the module docstring on built-but-unlanded
#: work, which this screen cannot see and must not pretend to.
CLEAR = "CLEAR"


class InstrumentError(RuntimeError):
    """The screen could not be trusted to answer. Never raised for a row's result."""


@dataclass(frozen=True)
class Sighting:
    """One landed line naming one number.

    ``strict`` is the field this whole module turns on, so bind the two vocabularies once: STRICT is
    the JOINED form, ``BACKLOG #N``, which is the needle the row publishes. Not strict is the BARE
    form, ``#N`` alone. Every ``joined`` and ``bare`` in the prose here means those two fields.
    """

    num: int
    path: str
    line: int
    strict: bool


@dataclass(frozen=True)
class Finding:
    """What the tree says about one row.

    ``strict`` and ``loose`` are ``path:line`` locations, sorted and de-duplicated. A reader whose
    next act is to open the file is the whole audience for this tool, so it hands over the line
    rather than the file and a second grep.
    """

    num: int
    strict: tuple[str, ...]
    loose: tuple[str, ...]

    @property
    def level(self) -> str:
        # Explicit, ordered dispatch rather than a truthiness test over a widened value. The
        # dispatch gate carries the scar: `if good` on a function that had started returning a
        # LEVEL STRING made every level truthy, and an undeclared item reported as dispatchable.
        if self.strict:
            return CITED
        if self.loose:
            return MENTIONED
        return CLEAR

    @property
    def flagged(self) -> bool:
        return self.level != CLEAR


@dataclass(frozen=True)
class Control:
    """A row whose answer is known, so a sweep that lost its needle cannot pass silently."""

    num: int
    expect_cited: bool
    why: str
    #: Grade the BARE form too, or leave it ungraded. Grading it is only safe on a number no item
    #: and no pull request can hold: a real row's number collides with pull-request numbers in
    #: comments, so a real row graded here would red on a coincidence. Set on the sentinel, where it
    #: is the ONLY control the MENTIONED level has. Measured 2026-09-03: widening the bare extractor
    #: to plain digits moves the corpus flag rate by 130 to 138 of 275, which is far too small a
    #: change for any rate-shaped guard to notice, so the level needs a pinned arm or none at all.
    expect_bare: bool | None = None


# THE PAIR IS MANDATORY AND NEITHER HALF IS OPTIONAL. Without the positive arm a broken sweep reads
# as "nothing is built"; without a negative arm a sweep matching every line reads as "everything is".
# Only the pair distinguishes a working screen from one that cannot tell those apart.
#
# WHEN THE NEGATIVE ARM REDDENS, READ THE LEDGER BEFORE READING THIS CODE. A pinned row can be built
# for real, and then the control is doing its job by telling you the corpus moved. Re-pin it on a row
# filed recently enough that nobody has cited it, and record the day you measured it.
CONTROLS = (
    Control(
        1027,
        True,
        "landed 2026-08-06 and cited from four files on origin/main (ci.yml, scorecard.py and two "
        "tests). Measured at fd44b0f17; the row itself named this control returning 4",
    ),
    Control(
        1396,
        False,
        "filed 2026-08-29 and unbuilt: zero hits in either form at fd44b0f17. If this arm reddens, "
        "check whether the row got built before you suspect the sweep",
    ),
    Control(
        999999,
        False,
        "no item holds this number and the allocator will not reach it, so this arm cannot go stale "
        "the way a real row can. It proves the needle discriminates, never that the ledger is right",
        expect_bare=False,
    ),
)


def _git(root: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # nosec B603 B607 - fixed argv, no shell; read-only git
        ["git", "-C", str(root), *args],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )


def resolve_ref(root: Path, ref: str) -> str:
    """The commit the answer is about. Printed with every result, because a number without the ref
    it was taken at is not a measurement."""
    done = _git(root, "rev-parse", "--verify", f"{ref}^{{commit}}")
    if done.returncode != 0:
        raise InstrumentError(
            f"cannot resolve {ref!r} in {root}: {done.stderr.strip() or 'no such ref'}. "
            f"Fetch it first ('git fetch origin main'). A ref that does not resolve returns no "
            f"lines, which is indistinguishable from a tree where nothing is cited."
        )
    return done.stdout.strip()


def sweep(
    root: Path, ref: str = DEFAULT_REF, paths: tuple[str, ...] = SEARCH_PATHS
) -> dict[int, list[Sighting]]:
    """Every number named by landed code under ``paths``, in one pass.

    One ``git grep`` rather than one per candidate: the row's own workaround costs four minutes for
    nine rows, and a screen that has to be cheap enough to run on a whole wave cannot pay that.
    ``check_agreement`` holds this pass against the per-number command so the shortcut stays honest.
    """
    done = _git(root, "grep", "-I", "-n", "-E", _SWEEP_PATTERN, ref, "--", *paths)
    # git grep exits 1 for "no matches found", which is a result and not a failure. Anything above
    # that is the tool refusing, and reporting it as an empty corpus is the false zero this file
    # exists to prevent.
    if done.returncode > 1:
        raise InstrumentError(
            f"git grep failed over {ref} (exit {done.returncode}): {done.stderr.strip()}"
        )

    found: dict[int, list[Sighting]] = {}
    for raw in done.stdout.splitlines():
        # <ref>:<path>:<line>:<content>. maxsplit keeps colons in the content intact.
        parts = raw.split(":", 3)
        if len(parts) < 4 or not parts[2].isdigit():
            continue
        path, line_no, content = parts[1], int(parts[2]), parts[3]
        strict_nums = {int(n) for n in _STRICT.findall(content)}
        for text in _LOOSE.findall(content):
            num = int(text)
            found.setdefault(num, []).append(
                Sighting(num=num, path=path, line=line_no, strict=num in strict_nums)
            )
    return found


def screen(nums: list[int], sightings: dict[int, list[Sighting]]) -> list[Finding]:
    """Turn the sweep into one Finding per requested row, in ascending order."""
    out: list[Finding] = []
    for num in sorted(set(nums)):
        seen = sightings.get(num, [])
        strict = sorted({f"{s.path}:{s.line}" for s in seen if s.strict})
        loose = sorted({f"{s.path}:{s.line}" for s in seen if not s.strict})
        out.append(Finding(num=num, strict=tuple(strict), loose=tuple(loose)))
    return out


def check_controls(sightings: dict[int, list[Sighting]]) -> list[str]:
    """Failures, empty when the pinned controls held. Pure: the anti-vacuity arms need no git.

    Every control grades the JOINED form. Only the sentinel grades the bare one, because a real
    row's number collides with pull-request numbers in comments and an arm that reds on a
    coincidence is an arm somebody deletes. See :class:`Control.expect_bare`.
    """
    failures: list[str] = []
    for control in CONTROLS:
        seen = sightings.get(control.num, [])
        cited = any(s.strict for s in seen)
        if cited != control.expect_cited:
            wanted = "cited" if control.expect_cited else "NOT cited"
            failures.append(
                f"control #{control.num} came back {'cited' if cited else 'clear'} in the joined "
                f"form, wanted {wanted} ({control.why})"
            )
        if control.expect_bare is None:
            continue
        bare = any(not s.strict for s in seen)
        if bare != control.expect_bare:
            wanted = "present" if control.expect_bare else "ABSENT"
            failures.append(
                f"control #{control.num} came back {'present' if bare else 'absent'} in the bare "
                f"form, wanted {wanted}. This is the only arm the weaker level has ({control.why})"
            )
    return failures


def check_agreement(root: Path, ref: str, sightings: dict[int, list[Sighting]]) -> list[str]:
    """Hold the one-pass sweep against the row's own published per-number command.

    THE QUESTION IS WHETHER THE INSTRUMENT ANSWERS THE ONE THAT WAS ASKED. The row publishes
    ``git grep -l -E "BACKLOG #<N>\\b"`` as the workaround; this file replaces it with a single sweep
    plus a Python regex, and those are two different programs that could easily disagree on a word
    boundary. Running both over the controls makes the substitution checkable instead of assumed.
    """
    failures: list[str] = []
    for control in CONTROLS:
        needle = rf"{_STRICT_PREFIX}{control.num}\b"
        done = _git(root, "grep", "-I", "-l", "-E", needle, ref, "--", *SEARCH_PATHS)
        if done.returncode > 1:
            failures.append(
                f"the per-number command failed for #{control.num}: {done.stderr.strip()}"
            )
            continue
        published = {line.split(":", 1)[1] for line in done.stdout.splitlines() if ":" in line}
        ours = {s.path for s in sightings.get(control.num, []) if s.strict}
        if published != ours:
            failures.append(
                f"the sweep and the row's own per-number command disagree on #{control.num}: "
                f"sweep {sorted(ours)}, published command {sorted(published)}"
            )
    return failures


def open_rows(root: Path) -> list[int]:
    """Every OPEN row across the ledger namespace, read with the shared parser and never a rescan."""
    nums: list[int] = []
    parsed = 0
    for src in DEFAULT_SOURCES:
        path = root / src
        if not path.is_file():
            continue
        for item in parse_items(path.read_text(encoding="utf-8", errors="replace")):
            parsed += 1
            if item.is_open:
                nums.append(item.num)
    if parsed < MIN_ITEMS:
        raise InstrumentError(
            f"parsed {parsed} ledger items under {root}, below the floor of {MIN_ITEMS}. The ledger "
            f"did not resolve, so no flag rate computed from it is evidence."
        )
    return nums


_READ_THIS = """MUST BE READ, NOT A VERDICT.
This asked the TREE: does code on {ref} cite this number. That is NOT the same
sentence as "this row is built", and it must not be reported as if it were.
  A citation is not a completion. Landed code can cite a row while FILING it, while
  testing around it, or while recording why it was NOT done.
  CLEAR is not proof of unbuilt. This sees LANDED code only, and built work does not
  always land. Row #1375 was built on 2026-08-29 onto a branch that never reached
  origin, and the joined needle returns zero for it -- the strongest signal here
  would have missed a finished job.
  A hit can point the wrong way too. The two bare #1375 lines this screen does find
  on main assert the allowlist backup already exists, and the row refutes both from
  source. Read the row, never the level.
What a flag buys is a four-minute read of the row before a lane-window is spent on it."""


def _self_test() -> int:
    """Prove the screen can tell cited from clear before anyone trusts a pass from it.

    THE TWO ARMS THAT MATTER ARE THE DEGENERATE SWEEPS. A screen that matches nothing and a screen
    that matches everything both produce a confident, uniform, wrong answer, and neither is visible
    in a report of the rows themselves. If `check_controls` cannot redden on those, every number this
    tool prints is decoration.
    """
    failures: list[str] = []

    def sight(num: int, strict: bool) -> Sighting:
        return Sighting(num=num, path="scripts/x.py", line=1, strict=strict)

    healthy = {c.num: [sight(c.num, True)] for c in CONTROLS if c.expect_cited}
    if check_controls(healthy):
        failures.append("a sweep answering every control correctly must pass check_controls")

    empty: dict[int, list[Sighting]] = {}
    if not check_controls(empty):
        failures.append(
            "A SWEEP THAT FOUND NOTHING MUST FAIL. This is the false zero the row names: a broken "
            "pattern or an unfetched ref returns clear for every row and reads as 'nothing is built'"
        )

    everything = {c.num: [sight(c.num, True)] for c in CONTROLS}
    if not check_controls(everything):
        failures.append(
            "A SWEEP THAT MATCHED EVERY ROW MUST FAIL. Without a negative arm, a needle that matches "
            "any line at all reports the whole ledger as cited and nothing contradicts it"
        )

    # The same failure one level down, and it is invisible to every rate-shaped guard: widening the
    # bare extractor to plain digits moved the real corpus by 130 to 138 of 275 open rows. Only a
    # pinned arm is sharp enough to see that, which is why the sentinel grades the bare form.
    bare_flood = dict(healthy)
    for control in CONTROLS:
        if control.expect_bare is False:
            bare_flood[control.num] = [sight(control.num, False)]
    if not check_controls(bare_flood):
        failures.append(
            "A BARE NEEDLE THAT MATCHED THE SENTINEL MUST FAIL. It is the only control the weaker "
            "level has, and a widened bare extractor moves no rate far enough to be noticed"
        )

    cases: list[tuple[list[Sighting], str, str]] = [
        ([sight(7, True)], CITED, "the joined form is the row's own needle"),
        ([sight(7, False)], MENTIONED, "a bare number is weaker, never absent"),
        (
            [sight(7, False), sight(7, True)],
            CITED,
            "one joined hit outranks any number of bare ones",
        ),
        ([], CLEAR, "no citation, which is not the same as no work"),
    ]
    for seen, want, why in cases:
        got = screen([7], {7: seen} if seen else {})[0].level
        if got != want:
            failures.append(f"{why}: wanted {want}, got {got}")

    for line in failures:
        print(f"SELF-TEST FAIL: {line}", file=sys.stderr)
    if failures:
        return 1
    print(
        f"self-test PASS: {len(cases)} level cases and 4 control arms, including the degenerate "
        f"sweeps (matches nothing, matches everything, bare needle floods)."
    )
    return 0


def _parse_range(spec: str) -> list[int]:
    lo, _, hi = spec.partition("-")
    if not hi:
        return [int(lo)]
    return list(range(int(lo), int(hi) + 1))


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("items", nargs="*", type=int, help="row numbers to screen")
    ap.add_argument("--range", action="append", default=[], help="inclusive range, e.g. 1380-1399")
    ap.add_argument(
        "--all-open", action="store_true", help="screen every OPEN row and report the flag rate"
    )
    ap.add_argument("--ref", default=DEFAULT_REF, help=f"tree to ask (default {DEFAULT_REF})")
    ap.add_argument("--root", type=Path, default=Path.cwd())
    ap.add_argument(
        "--strict-only",
        action="store_true",
        help="report only the joined form, which is exactly the check the row publishes. Drops the "
        "twelve open rows the bare form alone reaches.",
    )
    ap.add_argument("--quiet", action="store_true", help="omit CLEAR rows from the listing")
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args(argv)

    if args.self_test:
        return _self_test()

    wanted: list[int] = list(args.items)
    for spec in args.range:
        wanted.extend(_parse_range(spec))

    root = args.root.resolve()
    try:
        opens = open_rows(root) if args.all_open else []
        wanted.extend(opens)
        if not wanted:
            ap.error("name at least one row, a --range, --all-open, or pass --self-test")

        head = resolve_ref(root, args.ref)
        sightings = sweep(root, args.ref)
        broken = check_controls(sightings) + check_agreement(root, args.ref, sightings)
    except InstrumentError as exc:
        print(f"INSTRUMENT ERROR: {exc}", file=sys.stderr)
        return 1

    if broken:
        # Print NOTHING about the rows. A reader handed a plausible listing under a failed control
        # keeps the listing and forgets the caveat, which is how a false zero becomes a fact.
        print(
            "INSTRUMENT ERROR: the controls did not hold, so no row result below would be",
            file=sys.stderr,
        )
        print("evidence. Nothing was screened.", file=sys.stderr)
        for line in broken:
            print(f"  {line}", file=sys.stderr)
        return 1

    findings = screen(wanted, sightings)
    print(f"asked: {args.ref} at {head[:12]}")
    print(f"paths: {' '.join(SEARCH_PATHS)}")
    print(
        "controls: PASS -- "
        + ", ".join(f"#{c.num} {'cited' if c.expect_cited else 'clear'}" for c in CONTROLS)
        + "; the one-pass sweep agrees with the row's own per-number command on each."
    )
    print()

    flagged = 0
    for finding in findings:
        level = finding.level
        if args.strict_only and level == MENTIONED:
            level = CLEAR
        if level != CLEAR:
            flagged += 1
        elif args.quiet:
            continue
        paths = finding.strict if level == CITED else finding.loose if level == MENTIONED else ()
        shown = ", ".join(paths[:4]) + (" ..." if len(paths) > 4 else "")
        print(f"  #{finding.num:<6} {level:<10} {shown}")

    print()
    if findings:
        rate = flagged / len(findings) * 100
        scope = "open rows" if args.all_open and not args.items else "rows screened"
        print(f"flagged {flagged} of {len(findings)} {scope} ({rate:.1f} percent).")
    print()
    print(_READ_THIS.format(ref=args.ref))
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
