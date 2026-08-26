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
