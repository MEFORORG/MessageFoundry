# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Strict validation treats an hl7apy ``choice`` group as "exactly one of", not "all of".

hl7apy 1.3.5 validates a ``choice`` group with its ``sequence`` code path, so every alternative
counts as required (upstream crs4/hl7apy issue 151; fix PR 152, unmerged on 2026-09-30). The
common shape it hits is the order detail of ``ORM^O01``: ORC followed by OBR is valid HL7, and
without the carried fix the strict tier would reject it with ``Missing required child
ORM_O01_CHOICE.RQD`` (the group's name varies by version). The same false reject would hit
``ORR^O02`` and every other structure with a choice group, in every hl7apy version from 2.2 on.

All messages here are synthetic.
"""

from __future__ import annotations

from typing import Any

import pytest

from messagefoundry.parsing import validate
from messagefoundry.parsing.validate import (
    _CHOICE_PROBE,
    _LABELLED_CHOICE_PROBE,
    _SEQUENCES_LABELLED_CHOICE,
    _TWO_ALTERNATIVES_PROBE,
    _choice_error,
    _choice_fix_needed,
    _references,
)

_PID = "PID|1||12345^^^HOSP^MR||DOE^JOHN||19800101|M"
# ORC-7 is filled because v2.3 makes it required; later versions do not care.
_ORC = "ORC|NW|ORD1|||||1^^^20260101120000|20260101120000"
# OBR-27 is filled because v2.3 makes it required.
_OBR = "OBR|1|ORD1||PANEL^Panel|||20260101090000" + "|" * 20 + "1^^^20260101120000"
_RXO = "RXO|RX1^Drug|1||MG"


def _msh(trigger: str, version: str) -> str:
    # v2.6 makes MSH-9.3 (the structure) required, and v2.2 and v2.3 have no such component.
    structure = "^" + trigger.replace("^", "_") if version == "2.6" else ""
    return f"MSH|^~\\&|SND|SND|RCV|RCV|20260101120000||{trigger}{structure}|MSG001|P|{version}"


def _msg(*segments: str) -> str:
    return "\r".join(segments)


@pytest.mark.parametrize("version", ["2.2", "2.3", "2.3.1", "2.4", "2.5", "2.5.1", "2.6"])
@pytest.mark.parametrize("detail", [_OBR, _RXO], ids=["OBR", "RXO"])
def test_orm_o01_with_one_order_detail_alternative_is_conformant(version: str, detail: str) -> None:
    # hl7apy's v2.2 ORM_O01_ORDER_DETAIL lists NTE twice, the second time as required, so v2.2
    # needs a trailing NTE. That is a separate table question from issue 151.
    trailer = ["NTE|1||synthetic note"] if version == "2.2" else []
    result = validate(_msg(_msh("ORM^O01", version), _PID, _ORC, detail, *trailer))
    assert result.ok, result.errors


@pytest.mark.parametrize("version", ["2.2", "2.3.1", "2.4", "2.5", "2.5.1"])
def test_orr_o02_with_one_order_detail_alternative_is_conformant(version: str) -> None:
    result = validate(_msg(_msh("ORR^O02", version), "MSA|AA|MSG000", _PID, _ORC, _OBR))
    assert result.ok, result.errors


def test_the_issue_151_message_is_conformant() -> None:
    """The reproduction from the upstream issue, verbatim apart from line splitting."""
    result = validate(
        "MSH|^~\\&|SND|SND|RCV|RCV|20260101120000||ORM^O01|MSG001|P|2.3\r"
        "PID|1||12345||DOE^JOHN|||19800101|M\r"
        "ORC|NW||||||1^^^20260101120000|20260101120000\r"
        "OBR|1|||SPEC-001|PANEL|||20260101090000|||||||CSF||||||||||||1^^^20260101120000\r"
    )
    assert result.ok, result.errors


# The control arm: a choice still has to be exactly ONE. The parser puts OBR and RXO in the same
# choice group, so this message is not conformant and must stay rejected -- a fix that simply
# stopped checking choice groups would pass every test above and fail this one.
@pytest.mark.parametrize("version", ["2.3.1", "2.4", "2.5.1"])
def test_two_alternatives_in_one_choice_group_are_rejected(version: str) -> None:
    result = validate(_msg(_msh("ORM^O01", version), _PID, _ORC, _OBR, _RXO))
    assert not result.ok
    assert any("Only one child allowed for choice group" in e for e in result.errors), result.errors


def test_a_sequence_hl7apy_labels_choice_keeps_all_its_parts() -> None:
    """RSP_E22_QUERY_ACK is QAK then QPD, both required. hl7apy's table calls it a choice, so an
    "exactly one of" rule applied to every choice would reject every valid RSP^E22. Unaided
    hl7apy accepts this message; the shim must not start rejecting it."""
    result = validate(
        _msg(_msh("RSP^E22", "2.6"), "MSA|AA|MSG000", "QAK|Q1|OK", "QPD|E22^Auth^HL70471|Q1")
    )
    assert result.ok, result.errors


def _choice_groups() -> dict[str, list[tuple[Any, ...]]]:
    """Every group any shipped hl7apy table labels ``choice``, with its alternatives."""
    import hl7apy

    found: dict[str, list[tuple[Any, ...]]] = {}
    for hl7_version in hl7apy.SUPPORTED_LIBRARIES:
        for name, ref in hl7apy.load_library(hl7_version).GROUPS.items():
            if ref[0] == "choice":
                found.setdefault(name, []).extend(tuple(alt) for alt in ref[1])
    return found


def test_the_choice_group_census_still_matches_the_shim() -> None:
    """Goes red when hl7apy's tables change under the shim.

    Every entry of the sequence list must still be labelled choice somewhere, or it is stale.
    Every other choice group must be a plain list of alternatives, each present exactly once.
    An optional or repeating alternative is the mark of a sequence mislabelled as a choice,
    which is how some of the listed ones were found; and ``_choice_error`` relies on no
    alternative needing more than one occurrence.

    That mark does not catch every mislabel: QBP_E22_QUERY is QPD then RCP, both (1, 1), and
    reads exactly like a real choice. So the count of choice-group names is pinned too, as
    read from hl7apy 1.3.5. If it moves, a table changed, and each new choice group needs the
    same by-hand check against the standard before this number is updated.
    """
    groups = _choice_groups()
    assert len(groups) == 73, sorted(groups)
    assert set(_SEQUENCES_LABELLED_CHOICE) <= set(groups)
    for name, alternatives in groups.items():
        if name not in _SEQUENCES_LABELLED_CHOICE:
            assert {alt[2] for alt in alternatives} == {(1, 1)}, name


def test_every_shipped_structure_table_takes_the_rewrite() -> None:
    """``validate`` falls back to unaided hl7apy, with a warning, if the rewrite cannot read a
    table. This walks every message structure of every HL7 version hl7apy ships, so a table
    shape the rewrite does not know fails here instead."""
    import hl7apy

    rewritten = 0
    for hl7_version in hl7apy.SUPPORTED_LIBRARIES:
        for structure in hl7apy.load_library(hl7_version).MESSAGES:
            _references(structure, "Message", hl7_version)
            rewritten += 1
    assert rewritten > 1000, rewritten  # the control: the loop really walked the tables


def test_an_empty_choice_group_is_reported() -> None:
    """The parser never builds an empty group from message text, so this arm is reached only
    through hl7apy's element API. It keeps the branch honest."""
    from hl7apy import load_reference
    from hl7apy.core import Group

    name = "ORM_O01_OBRRQDRQ1RXOODSODT_SUPPGRP"
    error = _choice_error(Group(name, version="2.5.1"), load_reference(name, "Group", "2.5.1"))
    assert error is not None
    assert error.startswith(f"Missing required child for choice group {name}")


def test_hl7apy_still_has_the_bug_so_the_shim_is_still_on() -> None:
    """Goes red on the first hl7apy release that fixes issue 151. Then delete the shim.

    The shim switches itself off on such a release, since :func:`_choice_fix_needed` asks
    hl7apy rather than its version number. The code it leaves behind is dead, and this test is
    what says so. It also pins that hl7apy rejects the probe for issue 151 and not for some
    other reason, which would keep the shim on for the wrong cause. Before deleting the shim,
    check that the new release still accepts ``_LABELLED_CHOICE_PROBE``: PR 152 as written
    would not, and the shim then stays on by design.
    """
    from hl7apy.consts import VALIDATION_LEVEL
    from hl7apy.exceptions import ValidationError
    from hl7apy.parser import parse_message
    from hl7apy.validation import Validator

    def parsed(raw: str) -> Any:
        return parse_message(raw, find_groups=True, validation_level=VALIDATION_LEVEL.TOLERANT)

    with pytest.raises(ValidationError, match="Missing required child ORM_O01_OBRRQDRQ1RXOODSODT"):
        Validator.validate(parsed(_CHOICE_PROBE))
    # The third probe arm is live: unaided hl7apy accepts it today, so only a release that
    # starts rejecting it (PR 152 as written would) can keep the shim on through that arm.
    assert Validator.validate(parsed(_LABELLED_CHOICE_PROBE))
    assert _choice_fix_needed()
    # The control: the engine gets all three probes right.
    assert validate(_CHOICE_PROBE).ok
    assert not validate(_TWO_ALTERNATIVES_PROBE).ok
    assert validate(_LABELLED_CHOICE_PROBE).ok
