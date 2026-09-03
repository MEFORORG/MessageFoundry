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
