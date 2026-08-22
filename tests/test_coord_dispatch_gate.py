# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Tests for the dispatch gate and the banner fields it reads.

**The behaviour that matters most here is the refusal, so that is what these weight.** A gate that
passes an item a builder cannot close reproduces the 2026-08-21 wave: thirty items dispatched, nine
product-code commits landed, zero items closed. Fail-closed on a missing field is therefore pinned
as hard as the happy path.

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
    ok, reason = gate.judge(_item(gate))
    assert ok is False
    assert "missing:" in reason, f"the refusal must enumerate what to add; got {reason!r}"
    for key in ("verdict", "research", "closing-act"):
        assert key in reason


def test_the_wave_shape_is_refused(gate: ModuleType) -> None:
    """Research verdict, research done, closing act a scorecard re-score. All 93 items looked so."""
    ok, reason = gate.judge(
        _item(
            gate,
            **{
                "closing-act": "scorecard-rescore",
                "verdict": "research",
                "research": "done 2026-08-20",
            },
        )
    )
    assert ok is False
    assert "no builder can perform" in reason


def test_a_build_item_passes(gate: ModuleType) -> None:
    ok, _ = gate.judge(
        _item(gate, **{"closing-act": "code", "verdict": "build", "research": "none"})
    )
    assert ok is True


def test_an_unfinished_research_question_is_not_dispatchable_as_a_build(gate: ModuleType) -> None:
    ok, reason = gate.judge(
        _item(gate, **{"closing-act": "code", "verdict": "research", "research": "none"})
    )
    assert ok is False
    assert "research first" in reason


def test_completed_research_with_a_code_closing_act_passes(gate: ModuleType) -> None:
    """This is the state the 93 items SHOULD have been rewritten into before dispatch."""
    ok, _ = gate.judge(
        _item(gate, **{"closing-act": "code", "verdict": "research", "research": "done 2026-08-20"})
    )
    assert ok is True


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


def test_a_ledger_that_did_not_parse_refuses_to_report(
    gate: ModuleType, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """An empty read must be an INSTRUMENT ERROR, never a quiet pass on zero items."""
    rc = gate.main(["1107", "--root", str(tmp_path)])
    assert rc == 1
    assert "INSTRUMENT ERROR" in capsys.readouterr().err


def test_an_item_absent_from_the_ledger_is_refused(gate: ModuleType) -> None:
    """A number nobody filed must not dispatch as though it were fine."""
    rc = gate.main(["999999", "--root", str(_ROOT)])
    assert rc == 1
