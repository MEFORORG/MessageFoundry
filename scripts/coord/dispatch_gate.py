#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Dispatch gate — refuse a wave containing items a builder cannot close.

**The failure this exists to prevent, measured.** On 2026-08-21 thirty items were dispatched to two
builder lanes overnight. Nine product-code commits landed and reached ``main``. **Zero items
closed.** Not because the builders failed -- one lane was measured shipping a tested limb every
twelve minutes -- but because **every item in the assigned range closes by an act no builder can
perform.**

All 93 items in the range declared ``Verdict: research``. Across all 330 closed items in this
ledger, 145 carry ``Verdict: build`` and **zero** carry ``Verdict: research``. No research-verdict
item has ever closed. They close by a re-score in the vault ASVS scorecard, which is gitignored in
the engine repo and invisible from any engine checkout. All 93 mention "scorecard"; ``BUILDER.md``
contains the word **zero times**, so the seat receiving the item is never told what its closing act
is. A 76-item open *build* pool sat untouched beside it.

``DISPATCHER.md`` predicted this before the wave, in these words: *"a builder can finish the
research, the code and the tests and still be unable to close the item."* The prediction was
written down and nothing enforced it. This is the enforcement.

**How it decides.** Each item's banner blockquote may declare three fields, read by the SAME parser
that defines item status (``backlog_status_check.parse_items``), never a second scan::

    > Verdict: build | research | demand-gate | owner-ruling
    > Research: none | done <date>
    > Closing-act: code | scorecard-rescore | owner-ruling | banner-only

**IT NAMES THE CLOSING ACT. IT DOES NOT REFUSE THE ITEM.** That is a correction to this tool's first
version, and the correction matters more than the tool. That version refused any closing act a
builder could not perform. Measured against the very range it was built for, it would have blocked
#1112, #1171 and #1187 -- all three of which reached ``main``, #1171 being the SMTP
credential-exposure fix.

**CANNOT CLOSE IS NOT CANNOT BE WORKED.** A seat that ships the code and leaves the item open has
produced a complete outcome. A gate that calls that a failure suppresses real work to protect a
counter, which is the same error as the wave it was built to prevent, pointing the other way: the
wave picked unclosable items believing they would close, and the first gate proposed refusing
workable items because they would not. Both fuse *can a builder do it* with *can anyone here close
it*.

So each item comes back as one of three levels. ``ok`` closes by the builder's own act. ``advise``
is workable, with the closing act and its owning seat named. ``refuse`` is reserved for an item
whose state nobody has declared, because there the dispatch can name nothing at all -- and even that
blocks only under ``--refuse``.

**It is a DISPATCH aid, not a CI gate, on purpose.** Making missing fields a CI error would red the
build for all 330 items at once and be disabled within a day.

Usage::

    python scripts/coord/dispatch_gate.py 1107 1112 1122
    python scripts/coord/dispatch_gate.py --range 1107-1199 --explain
    python scripts/coord/dispatch_gate.py --self-test

Exit 0 only when EVERY named item is dispatchable. Exit 1 otherwise, listing each refusal and why.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "docs"))

from backlog_status_check import (  # type: ignore[import-not-found]  # noqa: E402
    BUILDER_CLOSABLE_ACTS,
    CLOSING_SEAT,
    DEFAULT_SOURCES,
    Item,
    parse_items,
)

# Below this, the ledger did not parse and no verdict from this gate is evidence.
MIN_ITEMS = 50

# VERDICTS THAT MEAN DO NOT JUST BUILD IT, and what lifts each (BACKLOG #1334).
#
# This is DISPATCH POLICY -- what a verdict says about STARTING work -- not ledger parsing, so it
# lives here rather than in the shared parser. The closed verdict vocabulary itself is ``_VERDICTS``
# in ``scripts/docs/verdict_divergence_check.py``; these keys must stay a SUBSET of it, and
# ``test_the_gated_verdicts_are_a_subset_of_the_closed_vocabulary`` enforces that rather than
# trusting this sentence.
#
# WHY THIS EXISTS -- and read the second paragraph, because the obvious story is WRONG.
#
# This gate green-lit BACKLOG #1336 to a dispatcher on 2026-08-24. #1336 was not startable: an owner
# ruling in its body put a shell tokeniser out of scope with no fifth candidate, and that ruling sat
# ~105 lines BELOW the banner block this gate reads. The item was dispatched, and a builder lost a
# slot to it.
#
# THIS CHANGE WOULD NOT HAVE CAUGHT IT, and saying otherwise would be a false justification on a true
# observation. Measured at 883f7734^, #1336's banner read `Verdict: build, Closing-act: code` -- so
# this branch, which keys on the VERDICT FIELD, returns ``ok`` on it exactly as the old code did. The
# banner was WRONG, and a reader of the banner cannot detect a wrong banner. What fixed #1336 was a
# person reading the body and correcting the row (PR 578). The two are COMPLEMENTARY: that corrected
# the DATA, this corrects the READER, and neither substitutes for the other.
#
# WHAT THIS DOES BUY, stated at its real size. 31 items on the ledger at 883f7734 declare a gated
# verdict. Every one of them is ALREADY ``advise`` on its closing act, so on today's corpus this
# changes NO LEVEL -- it changes the REASON for 31 items, from one naming only who closes them to one
# naming what gates them and who lifts it. The level arm is real and unexercised: it fires the moment
# a gated-verdict item carries a ``code`` closing act, which today's 31 do not (29 close by
# owner-ruling, 2 by blocked). The self-test drives that case directly rather than waiting for the
# ledger to produce one.
GATED_VERDICTS = {
    "demand-gate": (
        "the DEMAND is unproven, not the design -- nobody has ruled that this should exist. "
        "Scoping and research are legitimate. SHIPPING THE CODE IS NOT A COMPLETE OUTCOME here, "
        "because the gate is lifted by an owner ruling via the LIAISON, never by a merge."
    ),
    "owner-ruling": (
        "the SCOPE question belongs to the owner and is routed as one. Do not build a candidate "
        "before it is answered; the ruling comes via the LIAISON, and the Dispatcher or Lander "
        "records it."
    ),
}


def load_items(root: Path) -> dict[int, Item]:
    """Every item across the ledger namespace, keyed by number."""
    out: dict[int, Item] = {}
    for src in DEFAULT_SOURCES:
        path = root / src
        if not path.is_file():
            continue
        for item in parse_items(path.read_text(encoding="utf-8", errors="replace")):
            out[item.num] = item
    return out


def judge(item: Item) -> tuple[str, str]:
    """Return (level, note). Levels: ``ok``, ``advise``, ``refuse``.

    **This ADVISES by default and refuses almost nothing, which is a correction.** The first version
    returned a boolean and refused any closing act a builder could not perform. Measured against the
    range it was built for, that would have blocked #1112, #1171 and #1187 -- all of which reached
    main, #1171 being the SMTP credential-exposure fix. Cannot close is not cannot be worked: a seat
    that ships the code and leaves the item open has produced a complete outcome, and a gate that
    calls that a failure suppresses real work to protect a counter.

    So the rule is NAME THE CLOSING ACT, NEVER REFUSE IT. The only ``refuse`` left is an item whose
    state nobody has declared, because there the dispatch cannot name anything at all.

    **The gated verdicts ADVISE, they do not refuse** -- the same correction governs them. A
    ``demand-gate`` item can legitimately be scoped or researched; what it cannot be is silently
    treated as ordinary build work. So the note leads with what gates it and who lifts it, and the
    seat still decides.
    """
    act = item.fields.get("closing-act", "").strip().lower()
    verdict = item.fields.get("verdict", "").strip().lower()
    research = item.fields.get("research", "").strip().lower()

    if not act:
        missing = [k for k in ("verdict", "research", "closing-act") if k not in item.fields]
        return "refuse", (
            f"declares no Closing-act (missing: {', '.join(missing)}). The dispatch cannot tell the "
            f"seat what would close this, or who closes it. Add the three lines to the banner."
        )

    notes: list[str] = []

    # THIS BRANCH GOES FIRST, and the order is load-bearing rather than cosmetic. The closing-act
    # note below ends "That is a complete outcome, not a failure." Left to lead, it tells the reader
    # of a demand-gate item that shipping the code finishes the job -- the exact opposite of what a
    # demand gate means. test_the_gated_note_leads pins the ordering, because a comment cannot.
    #
    # AND IT IS UNCONDITIONAL ON `Research:`, deliberately NOT mirroring the research branch's
    # `research in ("", "none")` guard below. A demand gate is not lifted by finishing research; it
    # is lifted by a ruling. Copying that guard is the plausible wrong fix and it re-greens the item
    # the moment someone records a completed pass -- which is why two tests here drive these
    # verdicts WITH research done.
    if verdict in GATED_VERDICTS:
        notes.append(f"Verdict is {verdict!r} -- DO NOT JUST BUILD IT: {GATED_VERDICTS[verdict]}")

    if act not in BUILDER_CLOSABLE_ACTS:
        who = CLOSING_SEAT.get(act, "a seat this tool does not know")
        notes.append(
            f"closes by {act!r}, performed by {who} -- NOT by the builder. Expect shipped code and "
            f"an open item. That is a complete outcome, not a failure."
        )
    if verdict == "research" and research in ("", "none"):
        notes.append(
            "Verdict is 'research' with no completed pass recorded, so the question may still be "
            "open. Read the item's CURRENT body before briefing it."
        )
    if notes:
        return "advise", " ".join(notes)
    return "ok", f"closes by {act!r}, performed by {CLOSING_SEAT.get(act, 'the builder')}"


def _self_test() -> int:
    """Prove the gate refuses what it must before anyone trusts a pass from it."""
    failures: list[str] = []

    def mk(fields: dict[str, str]) -> Item:
        it = Item(1, 1)
        it.fields.update(fields)
        return it

    cases: list[tuple[dict[str, str], str, str]] = [
        ({}, "refuse", "an item declaring nothing has nothing to name"),
        (
            {"closing-act": "code", "verdict": "build", "research": "none"},
            "ok",
            "a build item the seat can close itself",
        ),
        (
            {
                "closing-act": "scorecard-rescore",
                "verdict": "research",
                "research": "done 2026-08-20",
            },
            "advise",
            "THE WAVE SHAPE IS WORKABLE AND MUST BE ADVISED, NEVER REFUSED -- refusing it would "
            "have blocked #1112, #1171 and #1187, all of which reached main",
        ),
        (
            {"closing-act": "code", "verdict": "research", "research": "none"},
            "advise",
            "an open research question is a warning to read the body, not a bar to working it",
        ),
        (
            {"closing-act": "code", "verdict": "research", "research": "done 2026-08-20"},
            "ok",
            "research done, closing act is code",
        ),
        (
            {"closing-act": "code", "verdict": "demand-gate", "research": "none"},
            "advise",
            "a demand gate means the DEMAND is unproven -- shipping the code does not close it",
        ),
        (
            {"closing-act": "code", "verdict": "demand-gate", "research": "done 2026-08-20"},
            "advise",
            "THE DISCRIMINATOR: a demand gate is lifted by a RULING, never by finished research, so "
            "mirroring the research branch's guard here would wrongly re-green this",
        ),
        (
            {"closing-act": "code", "verdict": "owner-ruling", "research": "none"},
            "advise",
            "an owner-ruling verdict routes the scope question to the owner before anyone builds",
        ),
        (
            {"closing-act": "code", "verdict": "owner-ruling", "research": "done 2026-08-20"},
            "advise",
            "DISCRIMINATOR TWIN: research done does not answer a question routed to the owner",
        ),
    ]
    for fields, want, why in cases:
        got, reason = judge(mk(fields))
        if got != want:
            failures.append(f"{why}: wanted {want!r}, got {got!r} ({reason})")

    for line in failures:
        print(f"SELF-TEST FAIL: {line}", file=sys.stderr)
    if failures:
        return 1
    print(f"self-test PASS: {len(cases)} cases; the wave shape is ADVISED, not refused")
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
    ap.add_argument("items", nargs="*", type=int, help="item numbers to dispatch")
    ap.add_argument("--range", action="append", default=[], help="inclusive range, e.g. 1107-1199")
    ap.add_argument("--root", type=Path, default=Path.cwd())
    ap.add_argument("--explain", action="store_true", help="show every item, not only refusals")
    ap.add_argument(
        "--refuse",
        action="store_true",
        help="exit 1 when any item is UNDECLARED or unknown. OFF by default: a dispatch names "
        "closing acts, it does not block work.",
    )
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args(argv)

    if args.self_test:
        return _self_test()

    wanted: list[int] = list(args.items)
    for spec in args.range:
        wanted.extend(_parse_range(spec))
    if not wanted:
        ap.error("name at least one item, or a --range, or pass --self-test")

    items = load_items(args.root)
    if len(items) < MIN_ITEMS:
        print(
            f"INSTRUMENT ERROR: parsed {len(items)} items from {args.root}, below the floor of "
            f"{MIN_ITEMS}. The ledger did not resolve, so no verdict below is evidence.",
            file=sys.stderr,
        )
        return 1

    ok: list[tuple[int, str]] = []
    advise: list[tuple[int, str]] = []
    refused: list[tuple[int, str]] = []
    unknown: list[int] = []
    for num in sorted(set(wanted)):
        item = items.get(num)
        if item is None:
            unknown.append(num)
            continue
        level, note = judge(item)
        # Explicit dispatch on the level. The first version did `if good` on judge()'s return, and
        # when judge started returning a LEVEL STRING every level became truthy -- an undeclared
        # item reported as dispatchable. A truthiness test over a widened return type is exactly the
        # silent-wrong-answer shape this tool exists to catch.
        {"ok": ok, "advise": advise, "refuse": refused}[level].append((num, note))

    print(f"items closing by the builder's own act: {len(ok)} of {len(set(wanted))}")
    print(f"  ledger parsed: {len(items)} items from {args.root}")
    print()

    for num in unknown:
        print(f"  #{num}: NOT IN THE LEDGER")
    for num, note in refused:
        print(f"  #{num}: UNDECLARED -- {note}")
    for num, note in advise:
        print(f"  #{num}: workable -- {note}")
    if args.explain:
        for num, note in ok:
            print(f"  #{num}: {note}")

    print()
    print(
        "NAMING, NOT REFUSING. An item the builder cannot close is still worth building: the seat\n"
        "ships the code and the item stays open until its named seat closes it. What the 2026-08-21\n"
        "wave lacked was the NAME, not permission -- nobody was told the closing act was elsewhere."
    )
    if args.refuse and (refused or unknown):
        print("--refuse given: the wave contains undeclared or unknown items.")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
