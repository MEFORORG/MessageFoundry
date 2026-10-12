# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A numeric OBX-5 is kept only when it fits the grammar of its own type (BACKLOG #2961).

One character class used to serve ``NM``, ``SN`` and ``TM``, and any run of digits and marks fitted
it. So an identifier written with dashes or dots under a numeric label was kept whole, in a field
the leak check does not scan. Each type now has its own grammar.

Every value here is synthetic (CLAUDE.md section 9). ``000-12-3456`` has the shape of a Social
Security number in an area that is never issued, and ``555-555-0100`` is in the range reserved for
fiction. Each behavioural case runs through both adapters, the engine's and the tee's.

``_REFUSED`` holds the cases the old class kept, so each one fails on the unfixed code. ``_KEPT``
holds the controls: values the change must leave alone, kept before and after.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import pytest

from messagefoundry.anon import anonymize as engine_anonymize
from messagefoundry.anon import anonymize_checked as engine_anonymize_checked
from messagefoundry.anon import surrogates as engine_surrogates
from tee.anon import anonymize as tee_anonymize
from tee.anon import anonymize_checked as tee_anonymize_checked
from tee.anon import surrogates as tee_surrogates

_SALT = "b254-salt-0123456789abcdef"
_HEADER = r"MSH|^~\&|SAPP|SFAC|RAPP|RFAC|20260315142233||ORU^R01|MSGCTRL|P|2.5.1"
_EACH_ADAPTER = pytest.mark.parametrize(
    "adapter", (engine_anonymize, tee_anonymize), ids=("engine", "tee")
)
_EACH_CHECKED = pytest.mark.parametrize(
    "checked", (engine_anonymize_checked, tee_anonymize_checked), ids=("engine", "tee")
)
_EACH_MODULE = pytest.mark.parametrize(
    "module", (engine_surrogates, tee_surrogates), ids=("engine", "tee")
)

_SSN_SHAPE = "000-12-3456"
_PHONE_SHAPE = "555-555-0100"
_PHONE_DOTTED = "555.555.0100"


def _message(value_type: str, value: str) -> str:
    """One OBX under a synthetic ORU."""
    obx = f"OBX|1|{value_type}|8480-6^Result^LN||{value}|"
    return "\r".join((_HEADER, "PID|1||12345^^^HOSP^MR||DOE^JOHN", obx))


def _obx5_of(message: str) -> str:
    """The OBX-5 field, read by position so a value surviving elsewhere cannot pass by luck."""
    line = next(seg for seg in message.split("\r") if seg.startswith("OBX|"))
    return line.split("|")[5]


# (OBX-2, OBX-5). The old class kept every one of these whole.
_REFUSED: dict[str, tuple[str, str]] = {
    "NM ssn shape": ("NM", _SSN_SHAPE),
    "NM phone shape": ("NM", _PHONE_SHAPE),
    "NM dotted phone shape": ("NM", _PHONE_DOTTED),
    "NM two signs": ("NM", "--5"),
    "NM ratio": ("NM", "1/2"),
    "NM clock": ("NM", "12:30"),
    "NM second component": ("NM", "128^5"),
    "NM comparator after the number": ("NM", "5<"),
    "SN ssn shape in the comparator place": ("SN", _SSN_SHAPE),
    "SN phone shape in the comparator place": ("SN", _PHONE_SHAPE),
    "SN bare number in the comparator place": ("SN", "100"),
    "SN ssn shape in the number place": ("SN", f"^{_SSN_SHAPE}"),
    "SN dotted phone shape in the number place": ("SN", f"^{_PHONE_DOTTED}"),
    "SN phone shape in the second number place": ("SN", f"^1^-^{_PHONE_SHAPE}"),
    "SN number in the separator place": ("SN", "^1^555^128"),
    "SN fifth component": ("SN", "^1^:^128^9"),
    "TM ssn shape": ("TM", _SSN_SHAPE),
    "TM phone shape": ("TM", _PHONE_SHAPE),
    "TM eight digit date": ("TM", "19800315"),
    "TM hour out of range": ("TM", "2500"),
    "TM minute out of range": ("TM", "1260"),
    "TM odd digit count": ("TM", "12000"),
    "TM fraction before the seconds": ("TM", "1200.5"),
    "TM five fraction digits": ("TM", "120000.12345"),
    "TM offset out of range": ("TM", "1200+9900"),
    "TM comparator": ("TM", ">1200"),
}

# Over-redaction destroys real results, and a scrubbed corpus still looks scrubbed, so these are
# asserted too. None of them is new behaviour: each was kept before the change.
_KEPT: dict[str, tuple[str, str]] = {
    "NM integer": ("NM", "128"),
    "NM signed decimal": ("NM", "-1.5"),
    "NM plus sign": ("NM", "+0.25"),
    "NM leading point": ("NM", ".5"),
    "NM trailing point": ("NM", "5."),
    "NM leading comparator": ("NM", "<5"),
    "NM two character comparator": ("NM", ">=100"),
    "NM repetitions": ("NM", "128~130"),
    "SN comparator and number": ("SN", ">^100"),
    "SN ratio": ("SN", "^1^:^128"),
    "SN slash ratio": ("SN", "^1^/^2"),
    "SN range": ("SN", "^100^-^200"),
    "SN suffix": ("SN", ">^3^+"),
    "SN signed number": ("SN", "<=^-0.5"),
    "TM hours": ("TM", "12"),
    "TM hours and minutes": ("TM", "1200"),
    "TM seconds": ("TM", "235959"),
    "TM fraction": ("TM", "120000.1234"),
    "TM offset": ("TM", "1200-0500"),
    "TM widest offset": ("TM", "000000+1400"),
}


@pytest.mark.parametrize("case", sorted(_REFUSED), ids=lambda c: c.replace(" ", "_"))
@_EACH_ADAPTER
def test_a_value_outside_its_type_grammar_is_redacted(
    adapter: Callable[..., str], case: str
) -> None:
    value_type, value = _REFUSED[case]
    out = adapter(_message(value_type, value), salt=_SALT)
    assert _obx5_of(out) == "[REDACTED]", f"{case} left OBX-5 intact"


@pytest.mark.parametrize("case", sorted(_KEPT), ids=lambda c: c.replace(" ", "_"))
@_EACH_ADAPTER
def test_a_value_inside_its_type_grammar_is_kept(adapter: Callable[..., str], case: str) -> None:
    value_type, value = _KEPT[case]
    out = adapter(_message(value_type, value), salt=_SALT)
    assert _obx5_of(out) == value, f"{case} was over-redacted"


@pytest.mark.parametrize("value_type", ("NM", "SN", "TM"))
@pytest.mark.parametrize("value", (_SSN_SHAPE, _PHONE_SHAPE), ids=("ssn_shape", "phone_shape"))
@_EACH_CHECKED
def test_the_checked_run_no_longer_returns_the_shape_whole(
    checked: Callable[..., str], value: str, value_type: str
) -> None:
    """The row's closing step: the end-to-end run. It used to return clean with the value whole,
    because OBX-5 is a mapped field and the leak check does not scan a mapped field."""
    out = checked(_message(value_type, value), salt=_SALT)
    assert _obx5_of(out) == "[REDACTED]"
    assert value not in out


@pytest.mark.parametrize("value_type", ("NM", "SN", "TM"))
@_EACH_MODULE
def test_a_subcomponent_separator_is_refused_under_a_numeric_type(
    module: Any, value_type: str
) -> None:
    """A message may declare any subcomponent separator. Under ``-`` the old code split the value
    first and matched ``000``, ``12`` and ``3456`` one by one, so the whole value was kept."""
    odd = module.Seps(subcomponent="-")
    value = _SSN_SHAPE if value_type != "SN" else f"^{_SSN_SHAPE}"
    assert module.preserve_obx5_value(value_type, value, odd) is False


@_EACH_MODULE
def test_the_grammar_reads_ascii_digits_only(module: Any) -> None:
    """Control for the ``[0-9]`` in the patterns: ``\\d`` would also match these digits. The old
    class refused them too, so this case does not fail on the unfixed code."""
    arabic_indic_128 = "١٢٨"
    assert arabic_indic_128.isdigit() and not arabic_indic_128.isascii()
    assert module.preserve_obx5_value("NM", arabic_indic_128, module.Seps()) is False


# --- the gap that stays (docs/PHI.md section 9) ------------------------------------------------------

# A grammar says what a number is. It cannot say what a number MEANS, so an identifier written as a
# plain run of digits is a valid NM and is kept. Kept before the change and after it.
_STILL_KEPT_BY_DESIGN: dict[str, tuple[str, str]] = {
    "NM undashed nine digits": ("NM", "900000001"),
    "NM undashed ten digits": ("NM", "5555550100"),
    "NM signed eleven digits": ("NM", "+15555550100"),
    "SN undashed nine digits": ("SN", "^900000001"),
    "NM identifier split across repetitions": ("NM", "000~12~3456"),
}


@pytest.mark.parametrize("case", sorted(_STILL_KEPT_BY_DESIGN), ids=lambda c: c.replace(" ", "_"))
@_EACH_CHECKED
def test_an_undashed_number_is_still_kept_whole(checked: Callable[..., str], case: str) -> None:
    """The named gap. If this starts refusing, the grammar changed: update docs/PHI.md section 9
    in the same change."""
    value_type, value = _STILL_KEPT_BY_DESIGN[case]
    assert _obx5_of(checked(_message(value_type, value), salt=_SALT)) == value
