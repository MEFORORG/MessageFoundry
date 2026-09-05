# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Tests for the dispatch gate and the banner fields it reads.

**These pin that the gate NAMES rather than REFUSES, which is a correction to its first version.**
That version refused any closing act a builder could not perform. Measured against the very range it
was built for, it would have blocked #1112, #1171 and #1187 -- all of which reached main, #1171
being the SMTP credential-exposure fix. Cannot close is not cannot be worked, and a gate that calls
shipped-code-plus-open-item a failure suppresses real work to protect a counter.

So the weight here is on the ADVISE path, and on the one thing still refused: an item whose state
nobody has declared, because there the dispatch can name nothing at all.

The field parsing is tested against the SHARED parser, because putting a second field scanner beside
`parse_items` would be exactly the two-definitions defect the ledger rules forbid.
"""

from __future__ import annotations

import importlib.util
import re
import subprocess
import sys
from pathlib import Path
from types import ModuleType

import pytest

_ROOT = Path(__file__).resolve().parents[1]
_GATE = _ROOT / "scripts" / "coord" / "dispatch_gate.py"
_PARSER = _ROOT / "scripts" / "docs" / "backlog_status_check.py"

_OPEN = "> \U0001f522 prioritized"


def _load(path: Path, name: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture(scope="module")
def gate() -> ModuleType:
    return _load(_GATE, "dispatch_gate")


@pytest.fixture(scope="module")
def parser() -> ModuleType:
    return _load(_PARSER, "backlog_status_check_fields")


def _item(gate: ModuleType, **fields: str) -> object:
    it = gate.Item(1, 1)
    it.fields.update(fields)
    return it


def test_self_test_passes(gate: ModuleType) -> None:
    """Includes the shape of the wave that closed zero. If it cannot fire, the gate is decoration."""
    assert gate._self_test() == 0


def test_an_item_declaring_nothing_is_refused(gate: ModuleType) -> None:
    """Fail closed. Today almost every item is in this state, and that is the migration, not a bug.

    The assertion names the MISSING FIELDS specifically, not just the refusal. Deleting the
    missing-field branch still refuses the item -- an empty closing act is not buildable either --
    so a test that only checked `ok is False` passed with the branch gone, and a mutation caught
    that. What is lost without it is the only message that tells the reader what to add.
    """
    level, reason = gate.judge(_item(gate))
    assert level == "refuse"
    assert "missing:" in reason, f"the refusal must enumerate what to add; got {reason!r}"
    for key in ("verdict", "research", "closing-act"):
        assert key in reason


def test_the_wave_shape_is_advised_never_refused(gate: ModuleType) -> None:
    """Research verdict, research done, closing act a scorecard re-score. All 93 items looked so.

    REFUSING THIS SHAPE WAS THE BUG. #1112, #1171 and #1187 carry it and all three reached main.
    """
    level, reason = gate.judge(
        _item(
            gate,
            **{
                "closing-act": "scorecard-rescore",
                "verdict": "research",
                "research": "done 2026-08-20",
            },
        )
    )
    assert level == "advise", (
        "the wave shape is workable; refusing it blocked shipped security work"
    )
    assert "NOT by the builder" in reason
    assert "ASVS Tracker" in reason, "the advice must NAME who does the work act"
    # A re-score is TWO acts with different owners, and naming only the first tells the reader the
    # item finishes elsewhere when what it needs is a handoff message. BUILDER.md:253 forbids a
    # builder concluding an item CLOSED; :148 gives the banner to the lander.
    assert "LANDER" in reason, "the advice must also name who flips the banner"
    assert "Two acts" in reason


def test_a_build_item_passes(gate: ModuleType) -> None:
    level, _ = gate.judge(
        _item(gate, **{"closing-act": "code", "verdict": "build", "research": "none"})
    )
    assert level == "ok"


def test_an_unfinished_research_question_is_advised_not_barred(gate: ModuleType) -> None:
    """A warning to read the item's current body, not a bar to working it."""
    level, reason = gate.judge(
        _item(gate, **{"closing-act": "code", "verdict": "research", "research": "none"})
    )
    assert level == "advise"
    assert "CURRENT body" in reason


def test_completed_research_with_a_code_closing_act_passes(gate: ModuleType) -> None:
    """This is the state the 93 items SHOULD have been rewritten into before dispatch."""
    level, _ = gate.judge(
        _item(gate, **{"closing-act": "code", "verdict": "research", "research": "done 2026-08-20"})
    )
    assert level == "ok"


def test_fields_are_read_only_from_the_banner_block(parser: ModuleType) -> None:
    """Below the banner block is invisible to every tool that reads this ledger.

    Measured 2026-08-22: `Verdict:` was present on 302 of 328 items and every one sat below the line
    where the parser stops, so nothing had ever read it. Putting the field in the banner is the
    whole point of the schema.
    """
    inside = f"## 5. t\n{_OPEN}\n> Verdict: build\n\nbody\n"
    outside = f"## 6. t\n{_OPEN}\n\nVerdict: build\n"
    got_in = parser.parse_items(inside)[0]
    got_out = parser.parse_items(outside)[0]
    assert got_in.fields.get("verdict") == "build"
    assert "verdict" not in got_out.fields


def test_field_keys_are_a_closed_set(parser: ModuleType) -> None:
    """An open key set is a second, undocumented schema. Only the three are recognised."""
    text = f"## 7. t\n{_OPEN}\n> Verdict: build\n> Priority: urgent\n\nbody\n"
    fields = parser.parse_items(text)[0].fields
    assert "verdict" in fields
    assert "priority" not in fields


def test_field_parsing_did_not_break_status_parsing(parser: ModuleType) -> None:
    """The status alphabet still governs. Adding fields must not change what open or closed means."""
    text = f"## 8. t\n{_OPEN}\n> Closing-act: code\n\nbody\n"
    item = parser.parse_items(text)[0]
    assert item.is_open is True
    assert item.fields["closing-act"] == "code"


# THESE TWO POINTED AT A REAL ITEM NUMBER IN THE LIVE LEDGER, AND THE LEDGER MOVED UNDER THEM.
# Measured 2026-08-23 while landing this branch: the item they used carried no `Closing-act` at this
# branch's base and carries one on `main`, because somebody declared it in between. The refuse test
# then failed -- and the DEFAULT test above it kept PASSING FOR THE WRONG REASON, asserting exit 0
# against an item that no longer had the property under test. A green that survives the loss of its
# own subject is worse than the red beside it.
#
# The subject is "an item whose state nobody has declared", so the fixture must OWN that property
# rather than borrow it from a file other people edit.
# PADDED PAST THE GATE'S OWN INSTRUMENT-ERROR FLOOR, which is 50 items. A one-item fixture is
# REFUSED as an unresolved ledger -- and the refuse test then passes on the instrument error rather
# than on the refusal, which is the same wrong-reason green this whole change exists to remove.
_FILLER = "".join(
    f"## {n}. filler\n{_OPEN}\n> Closing-act: code\n\nbody\n" for n in range(999900, 999960)
)
_UNDECLARED = _FILLER + f"## 999998. an item whose state nobody has declared\n{_OPEN}\n\nbody\n"


def _ledger_root(tmp_path: Path, body: str) -> Path:
    """A throwaway repo root whose ledger contains exactly the item under test."""
    (tmp_path / "docs").mkdir(parents=True, exist_ok=True)
    (tmp_path / "docs" / "BACKLOG.md").write_text(body, encoding="utf-8")
    return tmp_path


def test_an_undeclared_item_does_not_block_by_default(
    gate: ModuleType, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Exit 0 without --refuse. A dispatch names closing acts; it does not withhold permission."""
    root = _ledger_root(tmp_path, _UNDECLARED)
    assert gate.main(["999998", "--root", str(root)]) == 0
    out = capsys.readouterr().out
    assert "NAMING, NOT REFUSING" in out
    # AND ASSERT THE SUBJECT, not just the banner. "NAMING, NOT REFUSING" is printed on EVERY run,
    # so on its own it survives the item becoming declared and this test would pass having tested
    # nothing. Measured with a negative control: give the fixture item a Closing-act and the two
    # assertions above BOTH still hold. Only this one falls.
    assert "declares no Closing-act" in out


def test_refuse_flag_makes_an_undeclared_item_blocking(
    gate: ModuleType, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The strict behaviour survives, opt-in, for a wave planned specifically to close items."""
    root = _ledger_root(tmp_path, _UNDECLARED)
    assert gate.main(["999998", "--root", str(root), "--refuse"]) == 1


def test_a_ledger_that_did_not_parse_refuses_to_report(
    gate: ModuleType, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """An empty read must be an INSTRUMENT ERROR, never a quiet pass on zero items."""
    rc = gate.main(["1107", "--root", str(tmp_path)])
    assert rc == 1
    assert "INSTRUMENT ERROR" in capsys.readouterr().err


def test_an_item_absent_from_the_ledger_is_reported(
    gate: ModuleType, capsys: pytest.CaptureFixture[str]
) -> None:
    """A number nobody filed is named, and blocks only under --refuse."""
    assert gate.main(["999999", "--root", str(_ROOT)]) == 0
    assert "NOT IN THE LEDGER" in capsys.readouterr().out
    assert gate.main(["999999", "--root", str(_ROOT), "--refuse"]) == 1


# ------------------------------------------------------------------ gated verdicts (BACKLOG #1334)
#
# `judge()` tested exactly ONE verdict value. `demand-gate` and `owner-ruling` -- the two that mean
# DO NOT JUST BUILD IT -- fell through and were green-lit as ordinary build work.
#
# WHAT THESE TESTS ARE AND ARE NOT ABOUT. They pin the READER, not the data. A banner that declares
# the wrong verdict is invisible to any of this, which is why the fix could not have caught #1336:
# that row read `Verdict: build` while an owner ruling 105 lines below said otherwise.


def test_a_demand_gate_verdict_is_advised_not_green(gate: ModuleType) -> None:
    level, reason = gate.judge(
        _item(gate, **{"closing-act": "code", "verdict": "demand-gate", "research": "none"})
    )
    assert level == "advise"
    # The LEVEL alone is a weak assertion: an over-broad fix that advises every non-build verdict
    # would also produce it. The reason text is the only thing that tells a seat what gates the item.
    assert "DO NOT JUST BUILD IT" in reason
    assert "LIAISON" in reason


def test_a_demand_gate_verdict_stays_advised_when_research_is_done(gate: ModuleType) -> None:
    """THE DISCRIMINATOR. A demand gate is lifted by a RULING, never by finished research.

    The plausible wrong fix mirrors the research branch's ``research in ("", "none")`` guard. That
    passes the test above and fails this one, re-greening the item the moment somebody records a
    completed pass.
    """
    level, reason = gate.judge(
        _item(
            gate,
            **{"closing-act": "code", "verdict": "demand-gate", "research": "done 2026-08-20"},
        )
    )
    assert level == "advise"
    assert "DO NOT JUST BUILD IT" in reason


def test_an_owner_ruling_verdict_is_advised_not_green(gate: ModuleType) -> None:
    level, reason = gate.judge(
        _item(gate, **{"closing-act": "code", "verdict": "owner-ruling", "research": "none"})
    )
    assert level == "advise"
    assert "DO NOT JUST BUILD IT" in reason
    assert "owner" in reason.lower()
    assert "LIAISON" in reason


def test_an_owner_ruling_verdict_stays_advised_when_research_is_done(gate: ModuleType) -> None:
    """Discriminator twin. Research done does not answer a question routed to the owner."""
    level, _ = gate.judge(
        _item(
            gate,
            **{"closing-act": "code", "verdict": "owner-ruling", "research": "done 2026-08-20"},
        )
    )
    assert level == "advise"


def test_a_plain_build_verdict_is_still_green(gate: ModuleType) -> None:
    """The opposite direction: this must NOT become a blanket advisory.

    A NOTE ON WHAT THIS DOES AND DOES NOT CATCH, because the obvious claim is wrong. It does catch a
    blanket advise. It does NOT catch ``if verdict != "build"`` -- that variant leaves build items
    untouched, so this test passes over it. The guard against THAT shape is
    ``test_completed_research_with_a_code_closing_act_passes``, which goes red under it. Do not trim
    that test as redundant, and see the mutation note in the module docstring above.
    """
    level, reason = gate.judge(
        _item(gate, **{"closing-act": "code", "verdict": "build", "research": "none"})
    )
    assert level == "ok"
    assert "DO NOT JUST BUILD IT" not in reason


def test_the_gated_note_leads(gate: ModuleType) -> None:
    """Ordering is load-bearing, so it is asserted rather than left to a comment.

    The closing-act note ends "That is a complete outcome, not a failure." Left to lead, it tells the
    reader of a gated item that shipping the code finishes the job -- the opposite of what a demand
    gate means.
    """
    _, reason = gate.judge(
        _item(
            gate,
            **{"closing-act": "scorecard-rescore", "verdict": "demand-gate", "research": "none"},
        )
    )
    assert "DO NOT JUST BUILD IT" in reason
    assert "complete outcome" in reason, "precondition: both notes must be present to order them"
    assert reason.index("DO NOT JUST BUILD IT") < reason.index("complete outcome")


def test_the_gated_verdicts_are_a_subset_of_the_closed_vocabulary(gate: ModuleType) -> None:
    """Makes the constant's own comment executable instead of merely true when written.

    ``GATED_VERDICTS`` is dispatch policy and lives here; the closed verdict vocabulary lives in
    ``verdict_divergence_check.py``. A typo here would silently gate nothing, and every test above
    would still pass because they all drive ``judge()`` with the same spelling this module defines.
    Reaching for the private ``_VERDICTS`` is deliberate: a second copy of the vocabulary is the
    defect, not the fix.
    """
    checker = _load(
        Path(__file__).resolve().parents[1] / "scripts" / "docs" / "verdict_divergence_check.py",
        "verdict_divergence_check_for_gate_test",
    )
    assert set(gate.GATED_VERDICTS) <= set(checker._VERDICTS), (
        f"GATED_VERDICTS has a value the ledger vocabulary does not know: "
        f"{set(gate.GATED_VERDICTS) - set(checker._VERDICTS)}"
    )


# ------------------------------------------ retirement in place (BACKLOG #1334, the third limb)
#
# THE LEDGER RETIRES AN ITEM IN PLACE: the number is kept -- commits and mail already cite it -- and
# the banner and the fields stay exactly as filed. Every field `judge()` reads therefore still says
# buildable, and the retirement is prose in the body, which nothing was reading.
#
# Measured on `origin/main` at 3760a93b, before this limb: #1332 declares "RETIRED THE HOUR IT WAS
# FILED ... SHOULD NOT BE BUILT" as its first body line and graded `ok`, with a note BYTE-IDENTICAL
# to the one an ordinary build item gets. #1309 and #1311 graded `advise` for their closing act.
# Not one of the three notes said the word.
#
# THE FIXTURES BELOW OWN THE PROPERTY UNDER TEST rather than borrowing it from a file other people
# edit -- the correction the undeclared-item fixtures above record. The live-ledger arm is separate
# and comes last, because a detector proven only against its own fixtures is indistinguishable from
# one that fires on nothing real.

_RETIRED_BODY = (
    "## 4242. Scope the widget to the caller's allowed_channels\n"
    "\n"
    "**RETIRED THE HOUR IT WAS FILED -- THIS IS A DUPLICATE OF `#1152` AND SHOULD NOT BE BUILT. The\n"
    "number is kept, retired in place, because commits and mail already cite it.**\n"
    "\n"
    "**Everything below is superseded. Read `#1152`.**\n"
)

_PLAIN_BODY = (
    "## 4243. Scope the widget to the caller's allowed_channels\n"
    "\n"
    "**Cluster:** api. **Priority:** P2. `render_metrics(engine)` takes no identity, so nothing\n"
    "downstream can scope it. The fix passes the caller's identity in.\n"
)

_WITHDRAWN_HEADING_BODY = (
    "## 4244. WITHDRAWN -- duplicate of #1310, same defect, same sites, same fix\n"
    "\n"
    "**READ `#1310` INSTEAD.** It carries the same finding and was written first.\n"
)

# THE FALSE-POSITIVE FIXTURE, and it is a real row rather than an invention. #1334 is the item that
# DOCUMENTS the retirement convention, and its table lists the retired rows by number. A bare-word
# detector flags it -- and so does the "retired in place adjacent to a duplicate-of" needle that was
# proposed for this limb and measured out. Either would stop the row that describes the rule.
_DOCUMENTS_THE_CONVENTION_BODY = (
    "## 4245. The dispatch gate green-lights the verdicts that mean do not just build it\n"
    "\n"
    "An item retired in place keeps its number, its banner and its fields -- that is the established\n"
    "convention, so the ledger is right and the gate is not reading enough:\n"
    "\n"
    "| item | state | fields | gate says |\n"
    "| `#1332` | **retired in place**, duplicate of `#1086` | `build` / `code` | ***`ok`*** |\n"
)

_BUILDABLE = {"closing-act": "code", "verdict": "build", "research": "none"}


def test_a_retired_item_is_not_graded_like_a_live_one(gate: ModuleType) -> None:
    """THE DISCRIMINATION. Identical fields, identical call -- only the body differs.

    Before this limb both calls returned the same level AND the same note, byte for byte: "closes by
    'code', performed by the builder writes it; the LANDER flips the banner on merge". A dispatcher
    reading that about #1332 is told to build an item whose first body line says it must not be.
    """
    retired_level, retired_note = gate.judge(_item(gate, **_BUILDABLE), body=_RETIRED_BODY)
    plain_level, plain_note = gate.judge(_item(gate, **_BUILDABLE), body=_PLAIN_BODY)

    assert retired_note != plain_note, (
        "same fields, different bodies, identical note -- judge() is not reading the body at all"
    )
    assert "RETIRED IN PLACE" in retired_note
    assert "RETIRED" not in plain_note
    assert retired_level == "advise"
    # The opposite direction, and it has to be asserted here rather than trusted: a limb that
    # advised every item would satisfy every assertion above it.
    assert plain_level == "ok"


def test_a_withdrawn_heading_is_a_retirement(gate: ModuleType) -> None:
    """#1311's shape, which the body needle MISSES -- it never says "should not be built".

    One measured form, one whole retired row. Dropping it loses the item entirely.
    """
    level, note = gate.judge(_item(gate, **_BUILDABLE), body=_WITHDRAWN_HEADING_BODY)
    assert level == "advise"
    assert "RETIRED IN PLACE" in note
    assert "WITHDRAWN" in note, "the note must QUOTE what fired, so a reader can check the claim"


def test_prose_that_documents_the_convention_is_not_a_retirement(gate: ModuleType) -> None:
    """The landmine `verdict_divergence_check.py` records, in this limb's own vocabulary.

    Writing the convention into an item body makes that item look governed by it. A detector that
    flags correct prose is not noisy, it is wrong -- and this particular false positive would stop
    the row that documents the rule.
    """
    level, note = gate.judge(_item(gate, **_BUILDABLE), body=_DOCUMENTS_THE_CONVENTION_BODY)
    assert level == "ok"
    assert "RETIRED IN PLACE" not in note


def test_the_retirement_note_leads(gate: ModuleType) -> None:
    """Ordering, pinned rather than left to a comment -- the same reason the gated note is pinned.

    The gated-verdict note says scoping and research are legitimate; the closing-act note ends "That
    is a complete outcome, not a failure". Either one, read first, tells a seat there is work to
    start here. On a retired row there is none.
    """
    _, note = gate.judge(
        _item(gate, **{"closing-act": "owner-ruling", "verdict": "demand-gate"}),
        body=_RETIRED_BODY,
    )
    assert "RETIRED IN PLACE" in note
    assert "DO NOT JUST BUILD IT" in note, "precondition: both notes present, or there is no order"
    assert "complete outcome" in note, "precondition: the closing-act note is present too"
    assert note.index("RETIRED IN PLACE") < note.index("DO NOT JUST BUILD IT")
    assert note.index("RETIRED IN PLACE") < note.index("complete outcome")


def test_an_item_that_declares_nothing_is_still_told_it_is_retired(gate: ModuleType) -> None:
    """Refuse still wins the LEVEL -- the dispatch can name nothing -- but not the whole message.

    Without this the reader of a retired, undeclared row is told to go and add three banner lines to
    an item that must not be built. The level is unchanged; the first sentence is not.
    """
    level, note = gate.judge(_item(gate), body=_RETIRED_BODY)
    assert level == "refuse"
    assert "missing:" in note, "the refusal must still enumerate what to add"
    assert note.startswith("RETIRED IN PLACE")


def test_no_body_returns_todays_answer(gate: ModuleType) -> None:
    """The default is EMPTY, and that default is the honest failure mode: no body, no claim.

    It is also what keeps every test above this section meaningful -- they all call `judge()` with
    one argument, and so do the nine self-test cases.
    """
    assert gate.judge(_item(gate, **_BUILDABLE)) == gate.judge(_item(gate, **_BUILDABLE), body="")
    level, note = gate.judge(_item(gate, **_BUILDABLE))
    assert level == "ok"
    assert "RETIRED" not in note


# ---------------------------------------------------------------------------- the live-ledger arm
#
# Measured on `origin/main` at 3760a93b: 620 items across the two ledger files, 247 of them open.
# These three are retired or withdrawn IN PLACE and all three dispatched clean before this limb.
#
# WHEN THIS GOES RED, RE-MEASURE -- do not delete the number. A row moving to the archive is fine:
# both files are read as one namespace, exactly as the dispatch reads them. What this catches is the
# retirement WORDING drifting out from under the needles, and that is a real miss, not a test fault.
_RETIRED_ROWS = {1309, 1311, 1332}

# Rows that must NOT fire, each a different trap, each measured:
#   #1022  "THE 2026-08-15 DO-NOT-BUILD BANNER IS RETIRED" -- a BANNER was retired, not the item
#   #340   "HALF B MUST NOT BE BUILT SPECULATIVELY" -- a scope carve-out inside a live item
#   #1334  the row that DOCUMENTS the convention and lists the retired rows by number
#   #1342  prose about a lane building what the ledger says in prose must not be built
#   #1343  prose about a fix that must not be built without measurement
#   #1086  the item #1332 tells builders to build INSTEAD -- stopping it is the worst false positive
_MUST_NOT_FIRE = {340, 1022, 1086, 1334, 1342, 1343}


def test_every_retired_row_in_the_live_ledger_is_named(gate: ModuleType) -> None:
    """Non-vacuity. A needle proven only on fixtures fires on nothing real and looks identical."""
    rows = gate.load_ledger(_ROOT)
    assert len(rows) >= gate.MIN_ITEMS, (
        f"instrument: parsed {len(rows)} items from {_ROOT}, below the gate's own floor of "
        f"{gate.MIN_ITEMS}. The ledger did not resolve, so nothing below is evidence."
    )
    absent = _RETIRED_ROWS - set(rows)
    assert not absent, f"the ledger no longer carries {sorted(absent)} -- re-measure this test"

    for num in sorted(_RETIRED_ROWS):
        level, note = gate.judge(rows[num].item, body=rows[num].body)
        assert "RETIRED IN PLACE" in note, f"#{num} dispatches without its retirement named: {note}"
        # #1309 and #1311 already reached `advise` by another route, and that is the point: the
        # level was right and the REASON was about who closes them, not about not building them.
        assert level == "advise", f"#{num}: {level}"


def test_the_needles_do_not_fire_on_correct_prose(gate: ModuleType) -> None:
    """The over-fire arm, with the denominator, because a clean run otherwise reads as coverage."""
    rows = gate.load_ledger(_ROOT)
    assert len(rows) >= gate.MIN_ITEMS, "instrument: the ledger did not resolve"

    fired = {n for n, row in rows.items() if gate.retirement_marker(row.body) is not None}
    bare = {n for n, row in rows.items() if "retired" in row.body.lower()}

    hit = _MUST_NOT_FIRE & fired
    assert not hit, f"fired on correct prose: {sorted(hit)}"
    # THE DENOMINATOR IS PART OF THE RESULT. Measured at 2b8bccb43: 49 bodies mention the bare word
    # and 3 declare a retirement. If those two numbers converge, the corpus has stopped containing
    # the landmine and a bare-word detector would pass this file -- which is the wrong needle.
    assert len(fired) * 3 < len(bare), (
        f"the narrowing is not exercised: {len(bare)} bodies carry the bare word and {len(fired)} "
        f"fired. Close numbers mean this file no longer proves the needle is narrow."
    )


# ----------------------------------------------- the banner block is somebody else's prose
#
# THE LIMB SHIPPED LATE AND THE CORPUS MOVED UNDER IT. It was written against `main` at 3760a93b.
# By 2b8bccb43 the 2026-09-03 scoring pass had added a summary blockquote to every unscored row, and
# #1334's summary quotes the retirement wording of the rows #1334 documents -- "three open rows are
# retired in place ... and should not be built", inside the 160-character window the body needle
# allows. The live arm above went red naming #1334: the worst false positive available, because a
# reader stopped by the row that DESCRIBES the convention never reaches the rows it describes.
#
# The fix reads the item's prose and not its banner block, and the fixtures below OWN that property
# rather than borrowing it from #1334, whose wording is somebody else's to edit. Narrowing a needle
# by shrinking that window would have passed the arm above and pinned nothing.

_BANNER_QUOTES_A_RETIREMENT = (
    "## 4246. The dispatch gate green-lights the verdicts that mean do not just build it\n"
    "\n"
    f"{_OPEN} **Filed 2026-08-23 - not started.** The gate names the closing act and says nothing\n"
    "> about whether the item should be started at all.\n"
    ">\n"
    "> **Scored 2026-09-03 -> P1.** I ran the limb's own needles over the ledger at HEAD -- three\n"
    "> open rows are RETIRED in place (#1309, #1311, #1332) and the gate grades #1332 ok, the row\n"
    "> whose body says it is a duplicate of #1086 and should not be built.\n"
    "> Verdict: build\n"
    "> Closing-act: code\n"
    "\n"
    "**Cluster:** coord. The gate reads three banner fields and stops there.\n"
)

_PROSE_DECLARES_A_RETIREMENT = (
    "## 4247. Scope the widget to the caller's allowed_channels\n"
    "\n"
    f"{_OPEN} **Filed 2026-08-23 - not started.** `render_metrics(engine)` takes no identity.\n"
    "> Verdict: build\n"
    "> Closing-act: code\n"
    "\n"
    "**RETIRED THE HOUR IT WAS FILED -- THIS IS A DUPLICATE OF `#1152` AND SHOULD NOT BE BUILT. The\n"
    "number is kept, retired in place, because commits and mail already cite it.**\n"
)


def _mini_ledger(tmp_path: Path, *items: str) -> Path:
    """A ledger root holding just these items, so the arms below own what they assert."""
    published = tmp_path / "docs" / "BACKLOG.md"
    published.parent.mkdir(parents=True, exist_ok=True)
    published.write_text("# Backlog\n\n" + "\n".join(items), encoding="utf-8")
    return tmp_path


def test_a_scoring_summary_in_the_banner_is_not_this_items_retirement(
    gate: ModuleType, tmp_path: Path
) -> None:
    """A banner is what a machine writes ABOUT a row, and it quotes other rows verbatim.

    Both fixtures carry the same words. Only the one that declares them in its own prose is retired.
    """
    rows = gate.load_ledger(
        _mini_ledger(tmp_path, _BANNER_QUOTES_A_RETIREMENT, _PROSE_DECLARES_A_RETIREMENT)
    )
    assert set(rows) == {4246, 4247}, "instrument: the mini ledger did not parse"

    assert gate.retirement_marker(rows[4246].body) is None, (
        "the row whose BANNER quotes a retirement was graded as retired itself"
    )
    # The must-fire half, in the same call, because a loader that returned empty bodies would
    # satisfy the assertion above and nothing else here would notice.
    assert gate.retirement_marker(rows[4247].body) is not None
    assert gate.judge(rows[4246].item, body=rows[4246].body)[0] == "ok"
    assert gate.judge(rows[4247].item, body=rows[4247].body)[0] == "advise"


def test_the_body_keeps_the_heading_and_drops_only_the_banner(
    gate: ModuleType, tmp_path: Path
) -> None:
    """The heading STAYS: #1311 declares its withdrawal there and nowhere else.

    Dropping the banner by taking everything after the first blank line would take the heading too,
    and #1311 would go undetected while every arm above this one stayed green.
    """
    rows = gate.load_ledger(_mini_ledger(tmp_path, _BANNER_QUOTES_A_RETIREMENT))
    body = rows[4246].body

    assert body.startswith("## 4246."), "the heading is the one line #1311's needle reads"
    assert "Cluster:" in body, "the item's own prose must survive"
    assert "Scored 2026-09-03" not in body, "the banner block is still being read"
    assert "Verdict: build" not in body, "the fields belong to parse_items, not to the needles"


# ------------------------------------------- already built, MUST BE READ (BACKLOG #1393)
#
# FOUR OPEN ROWS SAY THEIR WORK HAS SHIPPED AND MUST NOT BE BUILT AGAIN -- #1107, #1130, #1183 and
# #1242 -- and every field `judge()` reads still says buildable on all four. They stay open because
# CLOSING them is a judgement the building seat cannot make, so the ledger accumulates done-but-open
# rows by construction and nothing prunes them.
#
# THE MECHANISM IS ONE WORD, and it is why this is a property of the vocabulary rather than of one
# tool: a blocker screen matches a verb list -- BUILD, START, DISPATCH, IMPLEMENT, LAND -- and none
# of those matches REBUILD. #1393 records two independently-written screens run over this population
# on 2026-08-29, and BOTH missed all four.
#
# THE LEVEL DECIDES NOTHING, AND THAT IS THE DESIGN. 35 of the 275 open rows carry the bare words at
# this branch's base. A gate that refused them would rebuild the screen #1394 records, which
# discarded 46 percent of the live ledger on a "DO NOT" token match. `read` says MUST BE READ and
# hands the question back.
#
# THE FIXTURES OWN THE PROPERTY UNDER TEST rather than borrowing it from rows other people edit.
# The live-ledger arm comes last, because a detector proven only on its own fixtures is
# indistinguishable from one that fires on nothing real.

_ALREADY_BUILT_BODY = (
    "## 4248. research an honest pass for ASVS 1.2.2\n"
    "\n"
    "**SHIPPED IN `#488` AT `cf38e16a`, AND STILL OPEN ON PURPOSE. DO NOT REBUILD IT.** The build\n"
    "landed; the banner has not moved because closing it is a judgement this seat cannot make.\n"
)

# #1242's shape, and the ONLY reason `judge()` reads a banner at all. #1242 is written almost
# entirely as blockquote: its declaration sits at `docs/BACKLOG.md:12345`, inside the banner block,
# and its prose region is two lines long. A prose-only read loses one of the four rows outright.
_ALREADY_BUILT_IN_BANNER = (
    f"{_OPEN} **Filed 2026-08-13.** `asvs-apply-cells.py` is a lossy writer in four ways.\n"
    "> **THE CORRECTION IS ALREADY BUILT AND PUSHED. Do not rebuild it.**\n"
    "> Closing-act: code\n"
)

# THE SELF-REFERENCE TWIN, AND IT IS #1393'S OWN TABLE with the numbers changed. This row DESCRIBES
# the class the needle detects and QUOTES all four declarations verbatim, so a needle allowed to
# start mid-line stops the only row that explains the trap. Measured while building this limb: with
# the table-pipe guard removed the needle fires on #1393 on the live ledger.
_QUOTES_OTHER_ROWS_DECLARATIONS = (
    "## 4249. four open rows say their work shipped and every screen passes them as buildable\n"
    "\n"
    "| row | the sentence in it |\n"
    "|---|---|\n"
    '| #4248 | "SHIPPED IN `#488` AT `cf38e16a`, AND STILL OPEN ON PURPOSE. '
    '**DO NOT REBUILD IT.**" |\n'
)

# THE OTHER HALF OF THE SAME TRAP. #1393's TITLE is a perfect instance of the pattern, written as
# narration: "four open rows say their work ALREADY SHIPPED and must not be rebuilt". The retirement
# limb reads headings safely because its heading needle is anchored at the title's start; this
# needle scans free text, so it must refuse to start on a heading line at all.
_NARRATING_HEADING = (
    "## 4251. four open rows say their work ALREADY SHIPPED and must not be rebuilt, and every\n"
    "\n"
    "**Cluster:** coord. Nothing on the dispatch path reads an item's body for this.\n"
)

# "Do not REWRITE" is about output, not about work already done. Measured: a bar-only needle fires
# on #347, #353 and #1007, all of which say exactly this and none of which is built.
_DO_NOT_REWRITE = (
    "## 4252. the ledger gate must report rather than correct\n"
    "\n"
    "- **Do not auto-correct.** The gate must **report**, never rewrite the file it checked.\n"
)


def test_an_already_built_row_is_not_graded_like_a_live_one(gate: ModuleType) -> None:
    """THE DISCRIMINATION. Identical fields, identical call -- only the body differs.

    Before this limb both calls returned the same level AND the same note, byte for byte. A
    dispatcher reading that about #1107 is told to build work that shipped in `#488`.
    """
    built_level, built_note = gate.judge(_item(gate, **_BUILDABLE), body=_ALREADY_BUILT_BODY)
    plain_level, plain_note = gate.judge(_item(gate, **_BUILDABLE), body=_PLAIN_BODY)

    assert built_note != plain_note, (
        "same fields, different bodies, identical note -- judge() is not reading the body at all"
    )
    assert "MUST BE READ" in built_note
    assert "SHIPPED IN" in built_note, "the note must QUOTE what fired, so a reader can check it"
    assert built_level == "read"
    # The opposite direction, asserted rather than trusted: a limb that flagged every row would
    # satisfy every assertion above it.
    assert plain_level == "ok"
    assert "MUST BE READ" not in plain_note


def test_a_declaration_in_the_banner_block_still_fires(gate: ModuleType) -> None:
    """#1242's shape, and the reason this needle reads a region the retirement needle must not.

    Dropping the banner here loses #1242 entirely -- one of the four rows the item names.
    """
    level, note = gate.judge(_item(gate, **_BUILDABLE), banner=_ALREADY_BUILT_IN_BANNER)
    assert level == "read"
    assert "ALREADY BUILT AND PUSHED" in note


def test_a_table_quoting_other_rows_is_not_this_rows_declaration(gate: ModuleType) -> None:
    """The self-reference trap, in this limb's own vocabulary.

    #1393 documents the class and quotes all four declarations in a markdown table. A detector that
    flags it is not noisy, it is wrong: a reader stopped by the row that DESCRIBES the trap never
    reaches the four rows that are the trap.
    """
    level, note = gate.judge(_item(gate, **_BUILDABLE), body=_QUOTES_OTHER_ROWS_DECLARATIONS)
    assert level == "ok"
    assert "MUST BE READ" not in note


def test_a_heading_that_narrates_the_pattern_is_not_a_declaration(gate: ModuleType) -> None:
    """#1393's own title. The heading is in the body this needle reads, and it must not start one.

    Removing the heading guard passes every other arm in this section and flags #1393 on the live
    ledger, so this is the arm that carries it.
    """
    level, _ = gate.judge(_item(gate, **_BUILDABLE), body=_NARRATING_HEADING)
    assert level == "ok"


def test_do_not_rewrite_is_not_do_not_rebuild(gate: ModuleType) -> None:
    """A bar with no already-done claim beside it is not a rebuild bar.

    The plausible wrong needle is the imperative alone. It fires on #347, #353 and #1007, which say
    "do not rewrite" about a tool's OUTPUT, and none of those rows is built.
    """
    level, _ = gate.judge(_item(gate, **_BUILDABLE), body=_DO_NOT_REWRITE)
    assert level == "ok"


def test_the_must_be_read_note_leads(gate: ModuleType) -> None:
    """Ordering is load-bearing, so it is asserted rather than left to a comment.

    The gated-verdict note says scoping and research are legitimate; the closing-act note ends "That
    is a complete outcome, not a failure". Either one, read first, tells a seat there is work to
    start here. On a row whose work has already shipped there is none.
    """
    _, note = gate.judge(
        _item(gate, **{"closing-act": "scorecard-rescore", "verdict": "demand-gate"}),
        body=_ALREADY_BUILT_BODY,
    )
    assert "MUST BE READ" in note
    assert "DO NOT JUST BUILD IT" in note, "precondition: both notes present, or there is no order"
    assert "complete outcome" in note, "precondition: the closing-act note is present too"
    assert note.index("MUST BE READ") < note.index("DO NOT JUST BUILD IT")
    assert note.index("MUST BE READ") < note.index("complete outcome")


def test_must_be_read_outranks_advise(gate: ModuleType) -> None:
    """#1107's real shape: the advise reasons are present too, and must not take the headline.

    The plausible wrong wiring tests `if notes` before the read level. That passes every fixture in
    this section that carries no advise reason, and makes the level unreachable on the live ledger:
    three of the four rows this limb exists for close by `scorecard-rescore`.
    """
    level, note = gate.judge(
        _item(
            gate,
            **{
                "closing-act": "scorecard-rescore",
                "verdict": "research",
                "research": "done 2026-08-20",
            },
        ),
        body=_ALREADY_BUILT_BODY,
    )
    assert level == "read"
    # Nothing is hidden by the ranking -- the advise reason still rides in the note.
    assert "ASVS Tracker" in note


def test_a_retirement_still_leads_a_must_be_read(gate: ModuleType) -> None:
    """A retirement is the stronger claim: the row is dead, not merely finished."""
    _, note = gate.judge(_item(gate, **_BUILDABLE), body=_RETIRED_BODY + _ALREADY_BUILT_BODY)
    assert "RETIRED IN PLACE" in note
    assert "MUST BE READ" in note, "precondition: both leads present, or there is no order"
    assert note.index("RETIRED IN PLACE") < note.index("MUST BE READ")


def test_an_undeclared_row_is_still_told_its_work_is_built(gate: ModuleType) -> None:
    """Refuse still wins the LEVEL, but not the whole message.

    Without the lead, the reader of an already-built undeclared row is told to go and add three
    banner lines to a row whose work has shipped.
    """
    level, note = gate.judge(_item(gate), body=_ALREADY_BUILT_BODY)
    assert level == "refuse"
    assert "missing:" in note, "the refusal must still enumerate what to add"
    assert note.startswith("MUST BE READ")


def test_no_banner_returns_todays_answer(gate: ModuleType) -> None:
    """The default is EMPTY, and that default is the honest failure mode: no text, no claim."""
    assert gate.judge(_item(gate, **_BUILDABLE), body=_PLAIN_BODY) == gate.judge(
        _item(gate, **_BUILDABLE), body=_PLAIN_BODY, banner=""
    )
    level, note = gate.judge(_item(gate, **_BUILDABLE))
    assert level == "ok"
    assert "MUST BE READ" not in note


def test_the_loader_carries_the_banner_and_the_body_apart(gate: ModuleType, tmp_path: Path) -> None:
    """Both regions come off ONE `Item.body_line` read, and neither re-derives the boundary.

    The retirement needle must not see the banner and the already-built needle must. A loader that
    returned the banner inside `body` would pass every arm above while re-opening the false positive
    the retirement limb was corrected to remove.
    """
    rows = gate.load_ledger(_mini_ledger(tmp_path, _BANNER_QUOTES_A_RETIREMENT))
    row = rows[4246]
    assert "Scored 2026-09-03" not in row.body, "the banner leaked into the retirement region"
    assert "Scored 2026-09-03" in row.banner, "the banner region came back empty"
    assert row.body.startswith("## 4246."), "the heading belongs to the body, for #1311's needle"
    assert not row.banner.startswith("## 4246."), "the heading must not be counted twice"


# ------------------------------------------------------------- the live-ledger arm (BACKLOG #1393)
#
# Measured on this branch's base: 657 items across the two ledger files, 275 of them open. These
# four are the rows #1393 names, all four still open, and all four dispatched clean before this
# limb -- #1242 as `ok`, with a note byte-identical to an ordinary build item's.
#
# WHEN THIS GOES RED, RE-MEASURE -- do not delete the number. A row moving to the archive is fine:
# both files are read as one namespace. What this catches is the declaration WORDING drifting out
# from under the needle, and that is a real miss, not a test fault.
_ALREADY_BUILT_ROWS = {1107, 1130, 1183, 1242}

# Rows that must NOT fire, each a different trap, each measured on the live ledger:
#   #1393  this row itself -- its TITLE narrates the pattern and its TABLE quotes all four rows
#   #1394  the sibling row, which restates the same class in prose
#   #1398  the third row of that family: a row can be built with nothing in its text saying so
#   #353   "Do not auto-correct ... never rewrite" -- a bar about OUTPUT, not about work
#   #1007  the same wording, in a different row
#   #1020  the mirror defect #1393 names: a bar that has already expired by its own terms
#   #1334  the row that documents the RETIREMENT convention, whose banner quotes other rows
_MUST_NOT_FIRE_REBUILD = {353, 1007, 1020, 1334, 1393, 1394, 1398}


def test_every_already_built_row_in_the_live_ledger_is_named(gate: ModuleType) -> None:
    """Non-vacuity. A needle proven only on fixtures fires on nothing real and looks identical."""
    rows = gate.load_ledger(_ROOT)
    assert len(rows) >= gate.MIN_ITEMS, (
        f"instrument: parsed {len(rows)} items from {_ROOT}, below the gate's own floor of "
        f"{gate.MIN_ITEMS}. The ledger did not resolve, so nothing below is evidence."
    )
    absent = _ALREADY_BUILT_ROWS - set(rows)
    assert not absent, f"the ledger no longer carries {sorted(absent)} -- re-measure this test"

    for num in sorted(_ALREADY_BUILT_ROWS):
        row = rows[num]
        level, note = gate.judge(row.item, body=row.body, banner=row.banner)
        assert "MUST BE READ" in note, f"#{num} dispatches without its own sentence read: {note}"
        assert level == "read", f"#{num}: {level}"


def test_the_needle_does_not_fire_on_rows_that_describe_the_defect(gate: ModuleType) -> None:
    """The over-fire arm, with the denominator, because a clean run otherwise reads as coverage."""
    rows = gate.load_ledger(_ROOT)
    assert len(rows) >= gate.MIN_ITEMS, "instrument: the ledger did not resolve"

    open_rows = {n: r for n, r in rows.items() if r.item.is_open}
    fired = {
        n
        for n, r in open_rows.items()
        if gate.rebuild_marker("\n".join((r.body, r.banner))) is not None
    }
    bare = {
        n
        for n, r in open_rows.items()
        if re.search(r"rebuild|already (?:shipped|built)", r.body + r.banner, re.I)
    }

    hit = _MUST_NOT_FIRE_REBUILD & fired
    assert not hit, f"fired on a row that describes the defect rather than declaring one: {hit}"
    # THE DENOMINATOR IS PART OF THE RESULT. Measured on this branch's base: 35 open rows carry the
    # bare words and 7 declare their work built. If those numbers converge, the corpus has stopped
    # containing the landmine and a bare-word screen would pass this file -- the wrong needle.
    assert len(fired) * 3 < len(bare), (
        f"the narrowing is not exercised: {len(bare)} open rows carry the bare words and "
        f"{len(fired)} fired. Close numbers mean this file no longer proves the needle is narrow."
    )


def test_a_must_be_read_row_does_not_block_even_under_refuse(
    gate: ModuleType, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """MUST BE READ is a level, never a verdict, and --refuse is the place that would betray it.

    Blocking here would rebuild the screen #1394 records, which discarded 46 percent of the live
    ledger on a token match and produced a withdrawn "nothing is dispatchable" finding.
    """
    ledger = _FILLER + (
        f"## 999997. research an honest pass for ASVS 1.2.2\n{_OPEN}\n> Closing-act: code\n\n"
        "**SHIPPED IN `#488` AT `cf38e16a`, AND STILL OPEN ON PURPOSE. DO NOT REBUILD IT.**\n"
    )
    root = _ledger_root(tmp_path, ledger)
    assert gate.main(["999997", "--root", str(root), "--refuse"]) == 0
    out = capsys.readouterr().out
    assert "MUST BE READ" in out
    assert "DOES NOT BLOCK" in out


# ---------------------------------------------------------------------------
# The tree limb (BACKLOG #1398): the gate stops reading the row and asks git.
#
# THE WEIGHT HERE IS ON THE PAIR, NOT ON EITHER ARM. A limb that elevates every row and one that
# elevates none both look correct against a single-sided check, and both fail silently -- the first
# floods a wave until the level is ignored, the second is invisible and lets a shipped row dispatch,
# which is the failure the limb was added for. So the live tests below always drive both.
#
# NO CONTROL NUMBER IS EVER WRITTEN HERE IN THE JOINED CITATION FORM. This file lives under
# ``tests/``, which the sweep searches, so a joined form for a control would make this file answer
# the question it asks: the negative arm would flip the day it landed and the positive would pass
# for the wrong reason. ``test_no_dispatch_control_number_is_written_as_a_citation`` pins that
# rather than trusting this comment.
# ---------------------------------------------------------------------------

#: Open on the ledger, and BUILT AND SHIPPED ON ``main`` with nothing in its text saying so. This is
#: the live instance the row was filed from: a dispatcher screened it as open, unclaimed, in no pull
#: request and carrying no bar, and only found out by starting the work.
_TREE_POSITIVE = 1300

#: Filed 2026-08-29 and unbuilt, so landed code cites it nowhere. IF THIS ARM REDDENS, READ THE
#: LEDGER BEFORE READING THE CODE: a pinned negative row can be built for real, and then the control
#: is doing its job by reporting that the corpus moved. Re-pin on a row filed recently enough that
#: nobody has cited it, and record the day it was measured.
_TREE_NEGATIVE = 1396


@pytest.fixture(scope="module")
def screen_mod(gate: ModuleType) -> ModuleType:
    """The screen module the GATE actually calls, resolved through a function it imported.

    NOT ``sys.modules`` by name. ``test_coord_landed_citation_screen.py`` loads this same module
    under that same name with ``importlib``, and if it ran second the name would point at a second
    module object while the gate's imported functions kept reading the first one's globals. A
    monkeypatch on the wrong object silently does nothing and the control arm below passes empty.
    """
    return sys.modules[gate.check_controls.__module__]


@pytest.fixture(scope="module")
def live_ref(gate: ModuleType) -> str:
    """A real tree to ask.

    The fallbacks exist so this never SKIPS. A control that quietly does not run is the same nothing
    as a control that cannot fail, and both pinned answers hold on any of these refs, because
    neither number is written into this change in the form the sweep matches.
    """
    for ref in (gate.DEFAULT_REF, "main", "HEAD"):
        done = subprocess.run(
            ["git", "-C", str(_ROOT), "rev-parse", "--verify", f"{ref}^{{commit}}"],
            capture_output=True,
            text=True,
            check=False,
        )
        if done.returncode == 0:
            return str(ref)
    pytest.fail("no git ref resolved, so nothing below could have measured a tree")


def test_a_cited_row_is_raised_to_must_be_read(gate: ModuleType) -> None:
    """THE POSITIVE ARM, and on #1300's own shape.

    #1300 grades ``ok`` on every field this gate reads -- ``Closing-act: code``, nothing in its
    prose, no bar -- so the tree is the only limb here that can say anything about it at all.
    """
    level, note = gate.merge_tree_finding(
        "ok", "closes by 'code'", "origin/main", ("tests/t.py:9",)
    )
    assert level == "read", "a row landed code cites must stop being reported as ordinary work"
    assert note.startswith("MUST BE READ -- LANDED CODE"), (
        "on an ok row the tree sentence is the only one contradicting 'there is work to start', so "
        "it leads; appended, it sits behind a sentence that says the opposite"
    )
    assert "tests/t.py:9" in note, (
        "the reader's next act is to open the file, so hand them the line"
    )


def test_a_clear_row_comes_back_byte_identical(gate: ModuleType) -> None:
    """THE NEGATIVE ARM, and the one a single-sided check cannot distinguish.

    A fold that elevated everything passes the test above and fails this one. The assertion is
    equality rather than absence: the gate's answer for a row the tree did not cite must be exactly
    what it was before this limb existed, never a fresh claim derived from a measurement.
    """
    for level in ("ok", "advise", "read", "refuse"):
        got_level, got_note = gate.merge_tree_finding(level, "the original note", "origin/main", ())
        assert (got_level, got_note) == (level, "the original note"), (
            f"a clear {level!r} row was modified by a tree limb that found nothing"
        )


def test_a_tree_hit_does_not_displace_the_rows_own_claim(gate: ModuleType) -> None:
    """The ordering the existing note tests pin must survive the new limb.

    A ``read`` note already opens with the row's own already-built declaration and a ``refuse`` note
    may open with a RETIREMENT, which is the strongest claim this file makes. Leading with a weaker
    tree signal there would invert an order two other tests hold, so the tree note is appended.
    """
    for level in ("read", "refuse"):
        got_level, got_note = gate.merge_tree_finding(
            level, "RETIRED IN PLACE -- DO NOT BUILD IT.", "origin/main", ("tests/t.py:9",)
        )
        assert got_level == level, "a tree hit does not lower a stronger level"
        assert got_note.startswith("RETIRED IN PLACE"), "the stronger claim keeps the lead"
        assert "LANDED CODE" in got_note, "and the tree sentence still travels, after it"


def test_only_the_joined_form_elevates(gate: ModuleType) -> None:
    """A bare ``#N`` spells a pull-request number just as well as an item number.

    The two namespaces cannot be told apart by shape, so the weaker level buys nothing a dispatcher
    can act on and is left to the standalone screen. Widening this to ``Finding.loose`` is the
    plausible wrong fix -- it looks like more coverage and is more noise.
    """
    joined = gate.Finding(num=7, strict=("tests/t.py:1",), loose=())
    bare = gate.Finding(num=7, strict=(), loose=("tests/t.py:2",))
    assert gate.cited_locations(joined) == ("tests/t.py:1",)
    assert gate.cited_locations(bare) == (), "a bare mention must not reach the dispatch path"
    assert gate.cited_locations(None) == (), "a row the sweep never saw is not a finding"


def test_the_tree_limb_holds_both_arms_against_a_real_tree(gate: ModuleType, live_ref: str) -> None:
    """THE CONTROL PAIR THE ROW NAMES, run against real git rather than a fixture.

    A known-BUILT row must come back cited and a known-UNBUILT one must come back clear. Without
    both, a broken pattern or an unfetched ref returns zero for every row and reads as *"nothing is
    built"* -- a false zero the row records firing twice in one session.
    """
    found, why = gate.ask_the_tree(_ROOT, [_TREE_POSITIVE, _TREE_NEGATIVE], live_ref)
    assert why is None, (
        f"the tree could not be asked, so neither arm below measured anything: {why}"
    )

    built = gate.cited_locations(found.get(_TREE_POSITIVE))
    unbuilt = gate.cited_locations(found.get(_TREE_NEGATIVE))
    assert built, (
        f"#{_TREE_POSITIVE} is built and shipped on main and came back clear. The sweep lost its "
        f"needle, or the ref is stale -- either way nothing else in this file is evidence"
    )
    assert not unbuilt, (
        f"#{_TREE_NEGATIVE} came back cited at {unbuilt}. Read the ledger before the code: the row "
        f"may have been built, in which case re-pin this arm on a newer unbuilt row"
    )


def test_the_control_pair_travels_all_the_way_through_main(
    gate: ModuleType, live_ref: str, capsys: pytest.CaptureFixture[str]
) -> None:
    """The wiring, not the screen. A limb that answers correctly and prints nothing is not wired.

    This is the test that would have caught the shape the row describes: #1300 grading ``ok`` and
    dispatching with no sentence anywhere in the output about the tree.
    """
    code = gate.main(
        [str(_TREE_POSITIVE), str(_TREE_NEGATIVE), "--root", str(_ROOT), "--tree-ref", live_ref]
    )
    out = capsys.readouterr().out
    assert code == 0, "MUST BE READ is a level, never a verdict, and the exit code is the promise"

    lines = {
        line.strip().split(":", 1)[0]: line for line in out.splitlines() if line.startswith("  #")
    }
    assert f"#{_TREE_POSITIVE}" in lines, "the cited row printed nothing at all"
    assert "LANDED CODE" in lines[f"#{_TREE_POSITIVE}"]
    assert "LANDED CODE" not in lines.get(f"#{_TREE_NEGATIVE}", ""), (
        "the clear row was given a tree sentence, so the limb is not discriminating"
    )
    assert "tree asked:" in out, "the header must say the tree was asked and over what"
    assert "CLEAR IS NOT PROOF OF UNBUILT" in out, (
        "the half nobody guesses has to travel with the finding, not sit in a docstring"
    )


def test_a_tree_hit_never_changes_the_exit_code(
    gate: ModuleType, live_ref: str, capsys: pytest.CaptureFixture[str]
) -> None:
    """At the measured flag rate a blocking tree limb refuses most waves and is off within a day.

    ``--refuse`` is the place that would betray it, exactly as it is for the row's own claim.
    """
    code = gate.main(
        [str(_TREE_POSITIVE), "--root", str(_ROOT), "--tree-ref", live_ref, "--refuse"]
    )
    assert code == 0
    assert "LANDED CODE" in capsys.readouterr().out


def test_an_unreachable_ref_returns_a_reason_never_an_empty_result(gate: ModuleType) -> None:
    """THE FAILURE MODE THAT LOOKS EXACTLY LIKE DATA.

    A ref that does not resolve yields no lines, which is byte-identical to a tree where nothing is
    cited. Returning ``{}`` with no reason would report every candidate as clear and reproduce the
    failure this limb exists for, while looking greener than before it was added.
    """
    found, why = gate.ask_the_tree(_ROOT, [_TREE_POSITIVE], "refs/heads/no-such-ref-for-this-test")
    assert found == {}
    assert why is not None and "resolve" in why


def test_a_failed_control_discards_the_whole_sweep(
    gate: ModuleType, screen_mod: ModuleType, live_ref: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A reader handed a plausible listing under a caveat keeps the listing and forgets the caveat.

    So a broken instrument yields no row result at all rather than a qualified one. The controls are
    the screen's own and this pins that the gate honours them instead of reading past them.
    """
    inverted = tuple(
        screen_mod.Control(c.num, not c.expect_cited, c.why) for c in screen_mod.CONTROLS
    )
    monkeypatch.setattr(screen_mod, "CONTROLS", inverted)

    found, why = gate.ask_the_tree(_ROOT, [_TREE_POSITIVE], live_ref)
    assert found == {}
    assert why is not None and "controls did not hold" in why


def test_a_run_that_could_not_ask_the_tree_says_which_class_it_cannot_see(
    gate: ModuleType, capsys: pytest.CaptureFixture[str]
) -> None:
    """A LIMB THAT DEGRADES QUIETLY IS WORSE THAN NO LIMB.

    The output looks the same, one whole class of row stops being detected, and the reader has no
    way to tell. A fresh worktree with no fetched remote is the ordinary case, not the exotic one.
    """
    assert gate.main([str(_TREE_POSITIVE), "--root", str(_ROOT), "--no-tree"]) == 0
    out = capsys.readouterr().out
    assert "TREE NOT ASKED" in out
    assert "NOTHING IN ITS TEXT SAYING SO" in out, "name the class that went undetected"
    assert "LANDED CODE" not in out, "no tree claim may survive a run that did not ask the tree"


def test_no_dispatch_control_number_is_written_as_a_citation(screen_mod: ModuleType) -> None:
    """THE INSTRUMENT MUST NOT ENTER ITS OWN DATA.

    The gate and this file both live under paths the sweep searches. Writing a control number in the
    joined form here would make these files answer the question they are asking: the positive arm
    would pass for the wrong reason and the negative arm would flip the moment this landed. The
    needles are built from the numbers at run time, and this pins that they stayed that way.

    Deliberately scoped to this change's own two files. Sweeping the repository would block an
    unrelated builder legitimately working the pinned row, and the run-time control already reports
    that case with a message naming the fix.
    """
    guarded = {_TREE_POSITIVE, _TREE_NEGATIVE} | {c.num for c in screen_mod.CONTROLS}
    for path in (_GATE, Path(__file__)):
        text = path.read_text(encoding="utf-8")
        for num in sorted(guarded):
            joined = f"{screen_mod._STRICT_PREFIX}{num}"
            assert joined not in text, (
                f"{path.name} writes the joined citation form for #{num}, so the sweep would find "
                f"this very file and the control would be measuring itself"
            )
