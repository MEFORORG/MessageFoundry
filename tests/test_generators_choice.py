# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The generator emits exactly one alternative of a choice group (BACKLOG #2497).

ORM^O01's order detail holds a choice of OBR, RQD, RQ1, RXO, ODS or ODT. Strict validation
needs exactly one, so the generator picks one instead of emitting every required child. All
data is synthetic.
"""

from __future__ import annotations

import random
from typing import Any

import pytest

from messagefoundry.generators import _core, orm  # noqa: F401  (importing orm registers ORM)
from messagefoundry.parsing import Peek
from messagefoundry.parsing.validate import _SEQUENCES_LABELLED_CHOICE

_ORDER_ALTERNATIVES = ("OBR", "RQD", "RQ1", "RXO", "ODS", "ODT")


def _alternatives(*names: str) -> list[list[Any]]:
    return [[name, ("sequence", ()), (1, 1), "SEG"] for name in names]


def _spec(*buildable: str) -> _core.MessageSpec:
    builders = {
        name: (lambda rng, ctx, name=name: f"{name}|{rng.randint(1, 9)}") for name in buildable
    }
    return _core.MessageSpec(code="T", trigger_to_structure={}, builders=builders)


# The generator writes v2.5.1 only (MSH-12), so that is the version strict validation checks.
# A few seeds, because the optional PD1/PV2 around the order vary with the seed.
@pytest.mark.parametrize("index", range(1, 6))
def test_generated_orm_o01_has_one_order_detail_and_is_strictly_valid(index: int) -> None:
    msg = _core.generate_message("ORM", "O01", index)
    peek = Peek.parse(msg)
    assert peek.version == "2.5.1"
    names = peek.segments()
    assert names[-2:] == ["ORC", "OBR"], names
    assert [n for n in names if n in _ORDER_ALTERNATIVES] == ["OBR"], names
    ok, errors = _core.gate("ORM", msg, "ORM_O01")
    assert ok, errors


def test_obr_is_picked_without_drawing_from_the_seed() -> None:
    """OBR leaves the random stream alone, so adding a choice moves no other generated value."""
    rng = random.Random("seed")
    before = rng.getstate()
    alt = _core._pick_alternative("G", _alternatives(*_ORDER_ALTERNATIVES), rng, _spec("RXO"))
    assert alt[0] == "OBR"
    assert rng.getstate() == before


def test_without_obr_the_pick_is_seeded_and_buildable() -> None:
    spec = _spec("RXO", "ODS")
    alternatives = _alternatives("RQD", "RXO", "ODS")
    picks = {
        seed: _core._pick_alternative("G", alternatives, random.Random(seed), spec)[0]
        for seed in range(40)
    }
    assert set(picks.values()) == {"RXO", "ODS"}  # never RQD, which has no builder
    for seed, pick in picks.items():  # the same seed always picks the same alternative
        assert _core._pick_alternative("G", alternatives, random.Random(seed), spec)[0] == pick


def test_a_choice_with_no_buildable_alternative_names_the_group() -> None:
    with pytest.raises(RuntimeError, match="choice group G_SUPPGRP"):
        _core._pick_alternative("G_SUPPGRP", _alternatives("RQD", "RQ1"), random.Random(0), _spec())


def _emitted(group: str) -> list[str]:
    ctx = _core.Ctx("ORM", "O01", "ORM_O01", "CID", _core.BASE_DT, "A", "F", "B", "G")
    group_ref = ("choice", tuple(_alternatives("PID", "PV1")))
    out: list[str] = []
    _core._emit(
        [[group, group_ref, (1, 1), "GRP"]], random.Random(0), ctx, _spec(), frozenset(), out
    )
    return [segment[:3] for segment in out]


def test_a_choice_group_emits_one_alternative() -> None:
    assert len(_emitted("ORM_O01_OBRRQDRQ1RXOODSODT_SUPPGRP")) == 1


def test_a_sequence_hl7apy_labels_choice_emits_every_part() -> None:
    """The control arm: QBP_E22_QUERY is QPD then RCP in HL7, though hl7apy labels it a choice.
    The generator follows the validator's list of such groups, so it still emits both parts.
    The generator walks only v2.5.1 today, where no such group occurs; this pins the rule for
    the day it walks a later version."""
    assert "QBP_E22_QUERY" in _SEQUENCES_LABELLED_CHOICE
    assert _emitted("QBP_E22_QUERY") == ["PID", "PV1"]
