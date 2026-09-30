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
from messagefoundry.parsing.validate import _choice_fix_needed, _reference_without_choices

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


def _has_choice_group(ref: tuple[Any, ...]) -> bool:
    if ref[0] == "choice":
        return True
    return any(_has_choice_group(child[1]) for child in ref[1] if child[3] == "GRP")


def test_every_shipped_structure_table_takes_the_rewrite() -> None:
    """``validate`` falls back to unaided hl7apy if the rewrite cannot read a table, which would
    bring the bug back for that structure without a sound. This walks every message structure of
    every HL7 version hl7apy ships, so a table shape the rewrite does not know fails here."""
    import importlib

    import hl7apy

    rewritten = 0
    for hl7_version, module in hl7apy.SUPPORTED_LIBRARIES.items():
        for structure in importlib.import_module(f"{module}.messages").MESSAGES:
            ref = _reference_without_choices(structure, "Message", hl7_version)
            assert not _has_choice_group(ref), (hl7_version, structure)
            rewritten += 1
    assert rewritten > 1000, rewritten  # the control: the loop really walked the tables


def test_the_carried_fix_is_on_exactly_while_upstream_still_has_the_bug() -> None:
    """Goes red the day hl7apy changes, in either direction, so the shim is never forgotten.

    If an hl7apy release fixes issue 151, the upstream validator stops rejecting this message.
    The shim is version-guarded to 1.3.5 and earlier, so it switches itself off on any newer
    release. This test then says whether that was right: if the new release still has the bug,
    ``upstream_rejects`` stays True while the guard is False, and this fails. If a release at
    or below the guard fixed it, the guard would still be True and this fails the other way.
    Either failure means: re-read the guard in ``parsing/validate.py`` and delete the shim once
    upstream is fixed.
    """
    from hl7apy.consts import VALIDATION_LEVEL
    from hl7apy.exceptions import ValidationError
    from hl7apy.parser import parse_message
    from hl7apy.validation import Validator

    message = parse_message(
        _msg(_msh("ORM^O01", "2.5.1"), _PID, _ORC, _OBR),
        find_groups=True,
        validation_level=VALIDATION_LEVEL.TOLERANT,
    )
    try:
        Validator.validate(message)
    except ValidationError as exc:
        assert "Missing required child ORM_O01_OBRRQDRQ1RXOODSODT_SUPPGRP" in str(exc), exc
        upstream_rejects = True
    else:
        upstream_rejects = False
    assert _choice_fix_needed() == upstream_rejects
