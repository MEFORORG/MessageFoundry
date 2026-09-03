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

It also reads the item's **heading and prose** for a retirement declaration, because the ledger
retires an item **in place**: the number is kept, the banner and the fields stay exactly as filed,
and the retirement is prose. Every field above therefore still says buildable on a row that must not
be built. The banner block itself is excluded from that read -- it is where a machine writes ABOUT
the item, including a scoring summary that quotes the retirement wording of other rows.

And it reads the item's **whole text, banner included**, for a declaration that the work is
**already built** (BACKLOG #1393). That produces a fourth level, ``read``, which says **MUST BE
READ** and decides nothing. Four open rows state plainly that their work shipped and must not be
built again, and every field above still says buildable on all four, because the verb in them is
**REBUILD** and no screen in this repo reads for it.

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

So each item comes back as one of four levels. ``ok`` closes by the builder's own act. ``advise``
is workable, with the closing act and its owning seat named. ``read`` is **MUST BE READ**: the row
itself says the work is already built, so this gate stops claiming to know and hands the question
back. ``refuse`` is reserved for an item whose state nobody has declared, because there the dispatch
can name nothing at all -- and even that blocks only under ``--refuse``.

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
import re
import sys
from pathlib import Path
from typing import NamedTuple

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


# RETIREMENT IS PROSE, NOT A FIELD, AND THAT IS WHY NOTHING WAS READING IT (BACKLOG #1334).
#
# The ledger retires an item IN PLACE: the number is kept -- commits and mail already cite it -- and
# the banner and the fields stay exactly as filed. So every field this gate reads still says
# buildable on a row whose first body line says it must not be built. Measured on `main` at
# 3760a93b, before this limb: #1332 graded ``ok`` with a note BYTE-IDENTICAL to an ordinary build
# item's, and #1309 and #1311 graded ``advise`` for their closing act. None of the three notes said
# the word. Three rows, all dispatchable, all retired.
#
# WHICH WAY THIS ERRS, ON PURPOSE. A MISSED retirement green-lights an item the ledger says must not
# be built -- the whole failure this limb exists to stop, and what happened to #1332. A false STOP
# costs a reader one minute of reading the body. So the needles match a DECLARATION about this item
# and never a bare word, and where the two errors trade off, the miss is the expensive one.
#
# THE BARE WORD IS NOT A CANDIDATE: it appears in 49 of the 657 bodies read this way, including
# #1086 -- the item #1332's own body tells builders to build INSTEAD.
#
# WHAT THE NEEDLES READ IS THE ITEM'S PROSE, NOT ITS BANNER BLOCK, AND THAT SPLIT IS MEASURED RATHER
# THAN TIDY. The banner block is where a machine writes ABOUT the item: the status glyph, the three
# dispatch fields, and since the 2026-09-03 scoring pass a summary paragraph per row. That pass wrote
# into #1334's banner a sentence quoting the very rows #1334 documents -- "three open rows are
# retired in place ... and should not be built" -- and the body needle fired on it. So on `main` at
# 2b8bccb43 the limb flagged #1334, the row that DOCUMENTS the convention and is the worst false
# positive available, because a reader who stops there never reaches the rows that are actually
# retired. Reading prose only, the same corpus fires on #1309, #1311 and #1332 and on nothing else,
# and no row anywhere fires from its banner alone -- so the split costs no detection today.
#
#: The declaration, in the body: retired, and therefore not to be built. Newline-tolerant because
#: the ledger hard-wraps at ~100 columns and #1332's declaration already wraps mid-sentence.
_RETIRED_DECLARATION = re.compile(
    r"RETIRED\b[\s\S]{0,160}?(?:SHOULD|MUST)\s+NOT\s+BE\s+BUILT", re.I
)

#: The declaration, in the heading: `## 1311. WITHDRAWN -- duplicate of #1310`. #1311's body never
#: says "should not be built", so the needle above MISSES it entirely -- one form, one whole row.
_RETIRED_HEADING = re.compile(
    r"^##\s+\d+\.\s*\**\s*(?:WITHDRAWN|RETIRED|SUPERSEDED)\b", re.I | re.M
)

# A THIRD NEEDLE WAS PROPOSED FOR THIS LIMB AND MEASURED OUT: "retired in place" adjacent to a
# duplicate-of declaration. Over the ledger namespace it fires on #1309, #1332 -- and #1334, the
# row that DOCUMENTS the convention and lists the other two by number. That is exactly the landmine
# `verdict_divergence_check.py` records in its own docstring: the migration that writes a vocabulary
# into an item body makes that item look governed by it. A detector that flags correct prose is not
# noisy, it is wrong. The two needles above carry all three retired rows without it.


def retirement_marker(body: str) -> str | None:
    """The declaration text if ``body`` retires this item, else ``None``.

    ``body`` is the item's heading and its own prose. ``load_ledger`` drops the banner block before
    calling this, because a banner is what a machine writes ABOUT an item and it quotes other rows.

    Returns WHAT FIRED, whitespace-collapsed and clipped, so the note can quote it and a reader can
    check the claim instead of taking the gate's word for it.
    """
    for pattern in (_RETIRED_HEADING, _RETIRED_DECLARATION):
        found = pattern.search(body)
        if found is not None:
            return " ".join(found.group(0).split())[:140]
    return None


# ALREADY BUILT IS THE OTHER WAY A ROW STOPS BEING BUILDABLE, AND THE VERB IS WHY NOTHING READ IT
# (BACKLOG #1393).
#
# Four open rows say their work has shipped and must not be built again -- #1107, #1130, #1183 and
# #1242 -- and every field this gate reads still says buildable on all four, because closing them is
# a judgement the building seat cannot make. So the ledger accumulates done-but-open rows by
# construction and nothing prunes them. The item's own measurement: two independently-written
# blocker screens were run over this population on 2026-08-29 and BOTH missed all four, because a
# screen matches a verb list -- BUILD, START, DISPATCH, IMPLEMENT, LAND -- and none of those matches
# REBUILD. That makes it a property of the vocabulary rather than of one tool.
#
# THIS RETURNS A LEVEL THAT DECIDES NOTHING, ON PURPOSE. 35 of the 275 open rows carry the bare
# words at this branch's base. A gate that refused them would be the noise failure #1394 already
# records, where a screen matching "DO NOT" discarded 46 percent of the live ledger. What a reader
# gets here is the sentence and an instruction to go and read the row.
#
# THE BARE WORD IS NOT A CANDIDATE, measured the same way the retirement limb measured its own:
# "rebuild" or "already shipped/built" anywhere in an open row fires on 35 of 275. The needle below
# fires on 7 of them (9 rows across the whole namespace). Both figures count OPEN rows at the same
# ref, so they are comparable, and `test_the_needle_does_not_fire_on_rows_that_describe_the_defect`
# re-derives the pair rather than trusting this sentence.
#
# THREE SHAPES WERE MEASURED OUT, and each failed on a row it must not stop:
#   * the bar alone (`do not rebuild`, no shipped assertion) fires on #353, #1007 and #347, which
#     say "do not REWRITE" about output, and on #1393 ITSELF -- see the two guards below;
#   * reading the item's prose without its banner LOSES #1242, one of the four rows this limb
#     exists for: #1242 is written almost entirely as blockquote, so its declaration sits at
#     `BACKLOG.md:12345` and its prose region is two lines long;
#   * a needle allowed to start mid-line fires on #1393's own table, which QUOTES all four
#     declarations verbatim in cells that begin `| #1107 | "`.
#
#: A declaration that the work is already done. The two guards are what keep it off the row that
#: describes the defect, and both are measured rather than defensive:
#:
#: ``^(?!#)`` -- a HEADING may not start a match. #1393's own title reads "four open rows say their
#: work ALREADY SHIPPED and must not be rebuilt", which is a perfect instance of the pattern written
#: as narration. The retirement limb reads headings safely because its heading needle is anchored at
#: the TITLE's start (`## 1311. WITHDRAWN`); this one scans free text, so a narrating title matches.
#:
#: ``[^\n|"]`` in the prefix -- a match may not begin after a table pipe or an opening quotation
#: mark. #1393's table quotes all four rows' declarations verbatim, and #1394 and #1398 restate the
#: same class in prose. Without this guard the needle flags #1393, and a reader stopped by the row
#: that DOCUMENTS the trap never reaches the four rows that are the trap.
_ALREADY_BUILT_DECLARATION = re.compile(
    r"(?m)^(?!#)[ \t]*(?:>[ \t]*)*[^\n|\"]{0,140}?"
    r"(?:ALREADY\b|SHIPPED\s+IN\b"
    r"|(?:HAS|HAVE|IS|ARE|WAS|WERE)\s+(?:BEEN\s+)?(?:LANDED|BUILT|SHIPPED|MERGED|PUSHED|DONE))"
    r"[^|\"]{0,160}?"
    r"(?:DO\s+NOT|DOES\s+NOT|DON'?T|NEVER|(?:MUST|SHOULD|CANNOT|CAN'?T)\s+NOT?\s*BE|NOT\s+BE)"
    r"[\s\S]{0,12}?RE-?(?:BUILD|BUILT|DO\b|DOING|IMPLEMENT)",
    re.I,
)


def rebuild_marker(text: str) -> str | None:
    """The declaration text if ``text`` says this row's work is already built, else ``None``.

    ``text`` is the item's WHOLE text -- heading, banner block and prose. That differs from
    :func:`retirement_marker`, which reads prose only, and the difference is measured: #1242
    declares "THE CORRECTION IS ALREADY BUILT AND PUSHED. Do not rebuild it." inside its banner
    block, so a prose-only read loses one of the four rows this needle exists for. The two guards
    documented on the pattern above are what make the wider region safe.

    Returns WHAT FIRED, whitespace-collapsed and clipped, so the note can quote it and a reader can
    check the claim instead of taking the gate's word for it.
    """
    found = _ALREADY_BUILT_DECLARATION.search(text)
    if found is None:
        return None
    # The blockquote marker is stripped from the QUOTE only. It is load-bearing to the match -- it
    # is how #1242's banner declaration is reached at all -- and noise to a reader checking it.
    return " ".join(found.group(0).split()).lstrip("> ")[:180]


class Row(NamedTuple):
    """One ledger item, its heading plus prose, and its banner block on its own."""

    item: Item
    body: str
    banner: str


def load_ledger(root: Path) -> dict[int, Row]:
    """Every item across the ledger namespace, with its body, keyed by number.

    **The body comes from the SAME read as the status, and the pairing is why this replaced a
    status-only loader.** A second pass for bodies could come back empty -- a renamed file, a
    narrowed source list -- while the item count, the levels and every printed total stayed exactly
    right, and the retirement limb would simply be off with nothing reporting it. Here an empty
    result is an empty result: the MIN_ITEMS floor in ``main`` already refuses to report on one.

    **The banner block is dropped and the heading is kept, which is not a tidy-up.** A banner is
    what a machine writes ABOUT an item -- the status glyph, the three dispatch fields, and a
    scoring summary that quotes the rows it describes -- so a needle reading it grades an item on
    somebody else's prose. The heading stays because #1311 declares its withdrawal there and
    nowhere else. ``Item.body_line`` supplies the boundary; deriving it here would put a second
    definition of the banner block beside the parser that owns it.

    **The banner is CARRIED rather than discarded, from that same boundary** (BACKLOG #1393). It is
    not safe for the retirement needle and it is required by the already-built one: #1242 declares
    "THE CORRECTION IS ALREADY BUILT AND PUSHED. Do not rebuild it." in its banner block, and its
    prose region is two lines long. Splitting the region here, from one ``Item.body_line`` read,
    keeps both needles reading a boundary the parser owns and neither re-deriving one.
    """
    out: dict[int, Row] = {}
    heading = re.compile(r"^## \d+\.\s")
    for src in DEFAULT_SOURCES:
        path = root / src
        if not path.is_file():
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        lines = text.splitlines()
        for item in parse_items(text):
            end = len(lines)
            for k in range(item.line, len(lines)):
                if heading.match(lines[k]):
                    end = k
                    break
            banner = lines[item.line : min(item.body_line - 1, end)]
            prose = lines[min(item.body_line - 1, end) : end]
            out[item.num] = Row(item, "\n".join([lines[item.line - 1], *prose]), "\n".join(banner))
    return out


def judge(item: Item, body: str = "", banner: str = "") -> tuple[str, str]:
    """Return (level, note). Levels: ``ok``, ``read``, ``advise``, ``refuse``.

    ``body`` is the item's prose, and it DEFAULTS TO EMPTY on purpose: a caller with no body gets
    exactly the answer this function gave before the retirement limb existed, rather than a
    retirement claim derived from a body nobody read. No body, no claim.

    ``banner`` is the item's banner block, and it defaults to empty for the same reason. It is read
    ONLY by the already-built needle, never by the retirement one -- see :func:`rebuild_marker` and
    :func:`load_ledger` for why the two regions differ and how both come off one boundary.

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

    **``read`` DECIDES NOTHING AND OUTRANKS ``advise``, which are two separate claims.** It decides
    nothing because the row's own sentence is the evidence and this function has not checked the
    tree; it says MUST BE READ and hands the question back. It outranks ``advise`` because of what
    each one costs a reader who acts on the level alone: an ``advise`` row is workable and the note
    only names who closes it, while a row that may already be built can cost a whole lane-window
    rebuilding shipped code. Nothing is hidden by the ranking -- every ``advise`` reason still rides
    in the note, after the MUST BE READ lead.
    """
    act = item.fields.get("closing-act", "").strip().lower()
    verdict = item.fields.get("verdict", "").strip().lower()
    research = item.fields.get("research", "").strip().lower()

    # THE ONE CONSULT. Everything below reads this variable, so the mutation that turns this limb off
    # is a single line and every retirement test dies with it.
    retired = retirement_marker(body)
    retired_note = (
        ""
        if retired is None
        else (
            f'RETIRED IN PLACE -- DO NOT BUILD IT. The body declares: "{retired}". The number is '
            f"kept, so the banner and every field this gate reads still describe a live item; the "
            f"retirement is prose. Read the item this one names instead."
        )
    )

    # THE SECOND CONSULT, and the same single-line shape: turning this limb off kills every
    # already-built test at once. It reads the WHOLE row -- banner included -- because #1242
    # declares in its banner and its prose region is two lines long.
    already_built = rebuild_marker("\n".join((body, banner)))
    read_note = (
        ""
        if already_built is None
        else (
            f'MUST BE READ -- THE ROW SAYS THIS WORK IS ALREADY BUILT. It declares: "'
            f'{already_built}". THIS GATE HAS DECIDED NOTHING: it read the row, not the tree, and '
            f"the row can be stale in either direction. Closing such a row is a judgement the "
            f"building seat cannot make, so the ledger carries done-but-open rows by construction "
            f"and every field here still says buildable. Read it before briefing it."
        )
    )

    if not act:
        missing = [k for k in ("verdict", "research", "closing-act") if k not in item.fields]
        # REFUSE STILL WINS THE LEVEL -- the dispatch can name nothing here -- but not the whole
        # message. Without the lead, the reader of a retired undeclared row is sent to add three
        # banner lines to an item that must not be built at all. The already-built lead is here for
        # the identical reason, and it comes second because a retirement is the stronger claim: it
        # says the row is dead, where this one says the row may be finished.
        undeclared = (
            f"declares no Closing-act (missing: {', '.join(missing)}). The dispatch cannot tell the "
            f"seat what would close this, or who closes it. Add the three lines to the banner."
        )
        leads = [n for n in (retired_note, read_note) if n]
        return "refuse", " ".join([*leads, undeclared])

    notes: list[str] = []

    # THE RETIREMENT LEADS, ahead of the gated-verdict note that leads for the same reason. Both of
    # the notes below tell a reader there is work to start: the gated one says scoping and research
    # are legitimate, and the closing-act one ends "That is a complete outcome, not a failure". On a
    # retired row there is no work to start, and the row it points at is where the work is.
    # test_the_retirement_note_leads pins the order, because a comment cannot.
    if retired_note:
        notes.append(retired_note)

    # AND THE ALREADY-BUILT NOTE LEADS THE REST, for that same reason: on a row whose work has
    # shipped there is no work to start either. It sits behind the retirement note because a
    # retirement is the stronger claim. test_the_must_be_read_note_leads pins this.
    if read_note:
        notes.append(read_note)

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
    # ORDER MATTERS HERE AND A SWAP IS SILENT. `read` is tested BEFORE `advise` because most rows
    # that fire the already-built needle also earn an advise reason, so an `if notes` first would
    # make this level unreachable on the live ledger while every fixture still passed.
    if read_note:
        return "read", " ".join(notes)
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

    # A RETIRED BODY, WORDED AS THE LEDGER WORDS IT. #1332's declaration, with the number changed.
    retired_body = (
        "## 4242. Scope the widget to the caller's allowed_channels\n\n"
        "**RETIRED THE HOUR IT WAS FILED -- THIS IS A DUPLICATE OF `#1152` AND SHOULD NOT BE BUILT.\n"
        "The number is kept, retired in place, because commits and mail already cite it.**\n"
    )
    withdrawn_body = "## 4244. WITHDRAWN -- duplicate of #1310, same defect, same fix\n"
    # The row that DOCUMENTS the convention. A bare-word needle stops it; these needles must not.
    documents_body = (
        "## 4245. The gate green-lights the verdicts that mean do not just build it\n\n"
        "An item retired in place keeps its number, its banner and its fields -- the established\n"
        "convention. | `#1332` | **retired in place**, duplicate of `#1086` | `build` / `code` |\n"
    )

    # AN ALREADY-BUILT BODY, WORDED AS THE LEDGER WORDS IT. #1107's declaration, number changed.
    shipped_body = (
        "## 4248. research an honest pass for ASVS 1.2.2\n\n"
        "**SHIPPED IN `#488` AT `cf38e16a`, AND STILL OPEN ON PURPOSE. DO NOT REBUILD IT.** The\n"
        "build landed; the banner has not moved because closing it is a judgement this seat cannot\n"
        "make alone.\n"
    )
    # #1242's shape, and it is the whole reason the banner is read. Its declaration is a BLOCKQUOTE
    # inside the banner block, and its prose region is two lines long.
    shipped_in_banner = (
        "> **THE CORRECTION IS ALREADY BUILT AND PUSHED. Do not rebuild it.**\n"
        "> Closing-act: code\n"
    )
    # THE SELF-REFERENCE TWIN, and it is #1393's own table verbatim with the numbers changed. This
    # row DESCRIBES the class the needle detects, so a needle allowed to start mid-line stops the
    # only row that explains the trap.
    quotes_the_declarations = (
        "## 4249. four open rows say their work ALREADY SHIPPED and must not be rebuilt\n\n"
        "| row | the sentence in it |\n"
        "|---|---|\n"
        '| #4248 | "SHIPPED IN `#488` AT `cf38e16a`, AND STILL OPEN ON PURPOSE. '
        '**DO NOT REBUILD IT.**" |\n'
    )

    cases: list[tuple[dict[str, str], str, str, str, str]] = [
        ({}, "", "", "refuse", "an item declaring nothing has nothing to name"),
        (
            {"closing-act": "code", "verdict": "build", "research": "none"},
            "",
            "",
            "ok",
            "a build item the seat can close itself",
        ),
        (
            {
                "closing-act": "scorecard-rescore",
                "verdict": "research",
                "research": "done 2026-08-20",
            },
            "",
            "",
            "advise",
            "THE WAVE SHAPE IS WORKABLE AND MUST BE ADVISED, NEVER REFUSED -- refusing it would "
            "have blocked #1112, #1171 and #1187, all of which reached main",
        ),
        (
            {"closing-act": "code", "verdict": "research", "research": "none"},
            "",
            "",
            "advise",
            "an open research question is a warning to read the body, not a bar to working it",
        ),
        (
            {"closing-act": "code", "verdict": "research", "research": "done 2026-08-20"},
            "",
            "",
            "ok",
            "research done, closing act is code",
        ),
        (
            {"closing-act": "code", "verdict": "demand-gate", "research": "none"},
            "",
            "",
            "advise",
            "a demand gate means the DEMAND is unproven -- shipping the code does not close it",
        ),
        (
            {"closing-act": "code", "verdict": "demand-gate", "research": "done 2026-08-20"},
            "",
            "",
            "advise",
            "THE DISCRIMINATOR: a demand gate is lifted by a RULING, never by finished research, so "
            "mirroring the research branch's guard here would wrongly re-green this",
        ),
        (
            {"closing-act": "code", "verdict": "owner-ruling", "research": "none"},
            "",
            "",
            "advise",
            "an owner-ruling verdict routes the scope question to the owner before anyone builds",
        ),
        (
            {"closing-act": "code", "verdict": "owner-ruling", "research": "done 2026-08-20"},
            "",
            "",
            "advise",
            "DISCRIMINATOR TWIN: research done does not answer a question routed to the owner",
        ),
        (
            {"closing-act": "code", "verdict": "build", "research": "none"},
            retired_body,
            "",
            "advise",
            "THE RETIREMENT CASE: identical fields to the ok case above, and only the body differs. "
            "#1332 graded ok here, byte-identical to an ordinary build item",
        ),
        (
            {"closing-act": "code", "verdict": "build", "research": "none"},
            withdrawn_body,
            "",
            "advise",
            "#1311's shape: WITHDRAWN in the heading, and its body never says 'not be built', so the "
            "body needle misses it entirely",
        ),
        (
            {"closing-act": "code", "verdict": "build", "research": "none"},
            documents_body,
            "",
            "ok",
            "THE FALSE-POSITIVE TWIN: prose DOCUMENTING the convention is not a retirement, and a "
            "bare-word needle would stop the row that describes the rule",
        ),
        (
            {"closing-act": "code", "verdict": "build", "research": "none"},
            shipped_body,
            "",
            "read",
            "THE ALREADY-BUILT CASE: identical fields to the ok case, only the body differs. #1107, "
            "#1130 and #1183 all carry this sentence and all three dispatched without it being said",
        ),
        (
            {"closing-act": "code", "verdict": "build", "research": "none"},
            "## 4250. a lossy writer\n\nCluster: security tooling.\n",
            shipped_in_banner,
            "read",
            "#1242's shape: the declaration is in the BANNER, so a prose-only read loses one of the "
            "four rows this limb exists for",
        ),
        (
            {"closing-act": "code", "verdict": "build", "research": "none"},
            quotes_the_declarations,
            "",
            "ok",
            "THE SELF-REFERENCE TWIN: #1393's own table QUOTES all four declarations, so a needle "
            "allowed to start after a table pipe flags the row that documents the trap",
        ),
        (
            {"closing-act": "scorecard-rescore", "verdict": "research", "research": "none"},
            shipped_body,
            "",
            "read",
            "MUST BE READ OUTRANKS ADVISE: #1107's real shape, where the advise reasons are present "
            "too and would otherwise take the headline off a row that may already be built",
        ),
    ]
    for fields, body, banner, want, why in cases:
        got, reason = judge(mk(fields), body=body, banner=banner)
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

    items = load_ledger(args.root)
    if len(items) < MIN_ITEMS:
        print(
            f"INSTRUMENT ERROR: parsed {len(items)} items from {args.root}, below the floor of "
            f"{MIN_ITEMS}. The ledger did not resolve, so no verdict below is evidence.",
            file=sys.stderr,
        )
        return 1

    ok: list[tuple[int, str]] = []
    advise: list[tuple[int, str]] = []
    must_read: list[tuple[int, str]] = []
    refused: list[tuple[int, str]] = []
    unknown: list[int] = []
    for num in sorted(set(wanted)):
        row = items.get(num)
        if row is None:
            unknown.append(num)
            continue
        level, note = judge(row.item, body=row.body, banner=row.banner)
        # Explicit dispatch on the level. The first version did `if good` on judge()'s return, and
        # when judge started returning a LEVEL STRING every level became truthy -- an undeclared
        # item reported as dispatchable. A truthiness test over a widened return type is exactly the
        # silent-wrong-answer shape this tool exists to catch. A level missing from this map is a
        # KeyError here, which is the loud failure that shape lacked.
        {"ok": ok, "advise": advise, "read": must_read, "refuse": refused}[level].append(
            (num, note)
        )

    print(f"items closing by the builder's own act: {len(ok)} of {len(set(wanted))}")
    print(f"  ledger parsed: {len(items)} items from {args.root}")
    print()

    for num in unknown:
        print(f"  #{num}: NOT IN THE LEDGER")
    for num, note in refused:
        print(f"  #{num}: UNDECLARED -- {note}")
    # MUST BE READ prints ahead of the workable rows because it is the only line here that can cost
    # a whole lane-window if a reader skips it. No bucket label: the note already opens with the
    # words, and a label would print them twice.
    for num, note in must_read:
        print(f"  #{num}: {note}")
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
    if must_read:
        print(
            "A MUST BE READ ROW IS NOT REFUSED, AND --refuse DOES NOT BLOCK ON ONE. The row's own\n"
            "sentence says the work is built; this gate read the row, not the tree, and the row can\n"
            "be stale in either direction. Blocking on it would rebuild the screen #1394 records,\n"
            "which discarded 46 percent of the live ledger on a token match."
        )
    if args.refuse and (refused or unknown):
        print("--refuse given: the wave contains undeclared or unknown items.")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
