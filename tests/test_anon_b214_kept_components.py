# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The components an identifier rule keeps as captured are still shape-scanned (BACKLOG #5533,
#5534).

BACKLOG #5533 mapped PID-2 and PID-21 (``mrn``), GT1-2 and NK1-33 (``id``) and NK1-37 (``ssn``),
and BACKLOG #5534 has those kinds keep CX.3 to CX.6, CX.9 and CX.10 as the sender wrote them. A
mapped field was never shape-scanned, so a dashed SSN or a punctuated phone in a kept component
passed ``anonymize_checked``, where the same field unmapped had been refused. The leak-check now
scans every field one of those kinds rewrites, with component 1 left out, as written and decoded.

Every value here is synthetic (CLAUDE.md section 9).
"""

from __future__ import annotations

from types import ModuleType

import pytest

import messagefoundry_toolkit.anon as engine_anon
import tee.anon as tee_anon

_SALT = "b214-kept-salt-0123456789abcdef"
_EACH = pytest.mark.parametrize("anon", (engine_anon, tee_anon), ids=("engine", "tee"))
_HEADER = "MSH|^~\\&|SAPP|SFAC|RAPP|RFAC|20260315142233||ADT^A01|MSGCTRL|P|2.5.1"
_PID3 = "12345^^^HOSP^MR"


def _message(address: str, value: str) -> str:
    """A message whose only populated field past the basics is ``address``, holding ``value``."""
    seg_id, number = address.split("-")
    index = int(number)
    fields = [seg_id, "1", *([""] * max(index - 1, 4))]
    if seg_id == "PID":
        fields[3] = _PID3
    fields[index] = value
    lines = [_HEADER]
    if seg_id != "PID":
        lines.append(f"PID|1||{_PID3}||DOE^JOHN")
    lines.append("|".join(fields))
    return "\r".join(lines)


# (address, value, the shape as the output would carry it). Each was measured to pass
# anonymize_checked at 8898d05af2 with the shape in the output, and to refuse on origin/main,
# where the field was unmapped. PID-20 was mapped on origin/main too; it is here for the dln kind.
_KEPT_SHAPES = [
    pytest.param("PID-21", "M77^^^123-45-6789^MR", "123-45-6789", id="PID-21-ssn-in-CX.4"),
    pytest.param("PID-2", "M77^^^HOSP^MR^202-555-0188", "202-555-0188", id="PID-2-phone-in-CX.6"),
    pytest.param("GT1-2", "G88^^123-45-6789^HOSP^GN", "123-45-6789", id="GT1-2-ssn-in-CX.3"),
    pytest.param(
        "NK1-33",
        "N99^^^HOSP^PI^^^^(202) 555-0188",
        "(202) 555-0188",
        id="NK1-33-paren-phone-in-CX.9",
    ),
    pytest.param(
        "NK1-37", "987654321^^^SSA^SS^202-555-0188", "202-555-0188", id="NK1-37-phone-in-CX.6"
    ),
    pytest.param("PID-20", "D12345^123-45-6789", "123-45-6789", id="PID-20-ssn-in-DLN.2"),
    pytest.param(
        "PID-21", "M77^^^123\\X2D\\45\\X2D\\6789^MR", "123\\X2D\\45", id="PID-21-escaped-ssn"
    ),
    pytest.param(
        "GT1-2", "G1^^^H^GN~G2^^^202-555-0188^GN", "202-555-0188", id="GT1-2-second-repetition"
    ),
    pytest.param(
        "NK1-33", "N99^^^HOSP&123-45-6789&L^PI", "123-45-6789", id="NK1-33-in-a-subcomponent"
    ),
]


@_EACH
@pytest.mark.parametrize(("address", "value", "shape"), _KEPT_SHAPES)
def test_a_shape_in_a_kept_component_is_refused(
    anon: ModuleType, address: str, value: str, shape: str
) -> None:
    raw = _message(address, value)
    # The control: the surrogate really keeps the shape, so a pass would emit it.
    assert shape in anon.anonymize(raw, salt=_SALT)
    with pytest.raises(anon.LeakError) as caught:
        anon.anonymize_checked(raw, salt=_SALT)
    text = str(caught.value)
    assert f"{anon.leak.KEPT_COMPONENT} in {address}" in text
    assert anon.leak.KEPT_COMPONENT_ADVICE in text
    # A kept-component hit is not advice to extend the rule map: the field is already mapped.
    assert "Extend the rule map" not in text
    # PHI-safe: the refusal names the shape and the address, never the value.
    assert shape not in text


# A shape in component 1, or in a component the surrogate blanks, does not reach the output, so
# it is no hit. These pin that the scan reads the output, not the input.
_SCRUBBED_SHAPES = [
    pytest.param("PID-21", "123-45-6789^^^HOSP^PI", id="PID-21-ssn-as-the-id"),
    pytest.param("PID-21", "M77^202-555-0188^^HOSP^PI", id="PID-21-phone-in-CX.2"),
    pytest.param("GT1-2", "G88^^^HOSP^GN^^202-555-0188", id="GT1-2-phone-in-CX.7"),
    pytest.param("PID-20", "D12345^CA^123-45-6789", id="PID-20-ssn-in-DLN.3"),
]


@_EACH
@pytest.mark.parametrize(("address", "value"), _SCRUBBED_SHAPES)
def test_a_shape_the_surrogate_drops_passes(anon: ModuleType, address: str, value: str) -> None:
    out = anon.anonymize_checked(_message(address, value), salt=_SALT)
    assert "123-45-6789" not in out
    assert "202-555-0188" not in out


@_EACH
def test_a_retargeted_field_is_reported_once_as_a_retarget(anon: ModuleType) -> None:
    """A retarget to an identifier kind keeps components too; it is reported by the retarget
    scan alone, with its own advice, so one shape is one hit."""
    rules = (
        *(rule for rule in anon.DEFAULT_RULES if rule.path != "PV1-7"),
        anon.FieldRule("PV1-7", anon.SurrogateKind.ID),
    )
    text = "\r".join((_HEADER, f"PID|1||{_PID3}", "PV1|1|I|||||X99^^^123-45-6789"))
    assert anon.leak.kept_component_hits(text, rules) == []
    report = anon.leak.leak_report(text, rules=rules)
    assert report.structural_hits == [
        f"SSN-shaped value {anon.leak.RETARGET_RESIDUE} in PV1-7",
    ]


@_EACH
def test_a_keep_on_the_field_leaves_it_to_the_unmapped_scan(anon: ModuleType) -> None:
    """A keep in place of the default rewrite leaves the field unmapped, so its own detectors
    refuse it; the kept-component scan has nothing to add."""
    rules = (
        *(rule for rule in anon.DEFAULT_RULES if rule.path != "PID-21"),
        anon.FieldRule("PID-21", anon.SurrogateKind.KEEP),
    )
    text = "\r".join((_HEADER, f"PID|1||{_PID3}" + "|" * 18 + "M77^^^123-45-6789^PI"))
    assert anon.leak.kept_component_hits(text, rules) == []
    assert anon.leak.leak_report(text, rules=rules).structural_hits == [
        "unmapped SSN-shaped value in PID-21",
    ]
