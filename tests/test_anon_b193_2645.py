# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The batch_18 field list is covered: by a default rule, or by the committed overlay (BACKLOG #2645).

BACKLOG #331 lists the fields a hand-written overlay had to add before the batch_18 sample corpus
could be de-identified. That overlay was never committed. This pins where each field is decided now,
so the list cannot quietly lose a field again. Every message here is synthetic (CLAUDE.md section 9).
"""

from __future__ import annotations

import functools
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from messagefoundry.anon import SurrogateKind
from messagefoundry.anon import anonymize as engine_anonymize
from messagefoundry.anon import rules as engine_rules
from tee.anon import anonymize as tee_anonymize
from tee.anon import rules as tee_rules

_OVERLAY = Path(__file__).resolve().parent / "fixtures" / "anon" / "batch_18.anon.toml"
_SALT = "b193-salt-0123456789abcdef"
_EACH_RULES = pytest.mark.parametrize("module", (engine_rules, tee_rules), ids=("engine", "tee"))
_EACH_ADAPTER = pytest.mark.parametrize(
    "adapter", (engine_anonymize, tee_anonymize), ids=("engine", "tee")
)

# The fields this row added to DEFAULT_RULES, with the kind each takes.
_NEW_DEFAULTS = {
    "GT1-16": SurrogateKind.NAME,
    "GT1-17": SurrogateKind.ADDRESS,
    "GT1-18": SurrogateKind.PHONE,
    "IN1-5": SurrogateKind.ADDRESS,
    "IN1-6": SurrogateKind.NAME,
    "IN1-7": SurrogateKind.PHONE,
    "IN1-11": SurrogateKind.NAME,
    "IN1-44": SurrogateKind.ADDRESS,
    "OBR-35": SurrogateKind.PROVIDER,
}
# The two that BACKLOG #2330 mapped. They are on the batch_18 list, so they are checked here too.
_DATES_OF_BIRTH = {"GT1-8": SurrogateKind.DOB, "IN1-18": SurrogateKind.DOB}
# The fields the overlay holds because they are NOT defaults. The file says why for each.
_OVERLAY_ONLY = {
    "IN1-4": SurrogateKind.NAME,
    "DST-2": SurrogateKind.NAME,
    "DST-7": SurrogateKind.NAME,
    "DST-9": SurrogateKind.DOB,
    "DST-27": SurrogateKind.ID,
    "DST-35": SurrogateKind.ADDRESS,
}
# BACKLOG #331's list, with the DST fields the sample corpus README names.
_BATCH_18_FIELDS = (
    *("GT1-8", "GT1-16", "GT1-17", "GT1-18"),
    *("IN1-4", "IN1-5", "IN1-6", "IN1-7", "IN1-11", "IN1-18", "IN1-44"),
    "OBR-35",
    *("DST-2", "DST-7", "DST-9", "DST-27", "DST-35"),
)


def test_the_three_tables_are_the_batch_18_list_and_nothing_else() -> None:
    """A guard on this file: a field added to the list with no table entry would be checked nowhere."""
    decided = {**_NEW_DEFAULTS, **_DATES_OF_BIRTH, **_OVERLAY_ONLY}
    assert sorted(decided) == sorted(_BATCH_18_FIELDS)


@_EACH_RULES
def test_every_batch_18_field_is_scrubbed_under_the_overlay(module: Any) -> None:
    kinds = {rule.path: rule.kind for rule in module.load_rules(_OVERLAY)}
    for address, kind in {**_NEW_DEFAULTS, **_DATES_OF_BIRTH, **_OVERLAY_ONLY}.items():
        assert kinds.get(address) == kind, address


@_EACH_RULES
def test_the_default_rules_cover_every_standard_field_on_the_list(module: Any) -> None:
    kinds = {rule.path: rule.kind for rule in module.DEFAULT_RULES}
    for address, kind in {**_NEW_DEFAULTS, **_DATES_OF_BIRTH}.items():
        assert kinds.get(address) == kind, address


@_EACH_RULES
def test_the_overlay_only_fields_are_not_defaults(module: Any) -> None:
    """ADR 0030 section 3 keeps IN1-4, and DST is no HL7 segment. If either becomes a default, the
    overlay's reasons are stale and this test is the prompt to rewrite them."""
    defaults = {rule.path for rule in module.DEFAULT_RULES}
    assert defaults.isdisjoint(_OVERLAY_ONLY)


# One synthetic message with a distinct made-up value in every listed field.
_VALUES = {
    "GT1-8": "19570412",
    "GT1-16": "EMPLOYERCO^GUARANTOR",
    "GT1-17": "1 GUARANTOR WORK RD^^TESTVILLE^ZZ^00001",
    "GT1-18": "000-555-0161",
    "IN1-4": "INSURERNAME^PLAN",
    "IN1-5": "2 INSURER RD^^TESTVILLE^ZZ^00002",
    "IN1-6": "CONTACTFAMILY^CONTACTGIVEN",
    "IN1-7": "000-555-0162",
    "IN1-11": "GROUPEMPLOYER^INSURED",
    "IN1-18": "19610923",
    "IN1-44": "3 INSURED WORK RD^^TESTVILLE^ZZ^00003",
    "OBR-35": "T99^SCRIBEFAMILY^SCRIBEGIVEN",
    "DST-2": "DSTFAMILY^DSTGIVEN",
    "DST-7": "DSTOTHERFAMILY^DSTOTHERGIVEN",
    "DST-9": "19480215",
    "DST-27": "900000001",
    "DST-35": "4 DST RD^^TESTVILLE^ZZ^00004",
}


def _segment(seg_id: str) -> str:
    fields = {int(a.split("-")[1]): v for a, v in _VALUES.items() if a.startswith(seg_id + "-")}
    return "|".join([seg_id, "1"] + [fields.get(i, "") for i in range(2, max(fields) + 1)])


_MESSAGE = "\r".join(
    (
        r"MSH|^~\&|SAPP|SFAC|RAPP|RFAC|20260315142233||ORU^R01|MSGCTRL|P|2.5.1",
        "PID|1||12345^^^HOSP^MR||DOE^JOHN",
        _segment("GT1"),
        _segment("IN1"),
        _segment("OBR"),
        _segment("DST"),
    )
)


def _field_of(message: str, address: str) -> str:
    seg_id, num = address.split("-")
    line = next(seg for seg in message.split("\r") if seg.startswith(seg_id + "|"))
    fields = line.split("|")
    return fields[int(num)] if int(num) < len(fields) else ""


@functools.cache
def _out(adapter: Callable[..., str]) -> str:
    return adapter(_MESSAGE, salt=_SALT, overlay=_OVERLAY)


@pytest.mark.parametrize("address", _BATCH_18_FIELDS)
def test_the_control_message_carries_a_value_in_every_listed_field(address: str) -> None:
    """Without this, a field the control never populated would read as scrubbed."""
    assert _field_of(_MESSAGE, address) == _VALUES[address] != ""


@pytest.mark.parametrize("address", _BATCH_18_FIELDS)
@_EACH_ADAPTER
def test_every_batch_18_value_is_replaced(adapter: Callable[..., str], address: str) -> None:
    replaced = _field_of(_out(adapter), address)
    assert replaced and replaced != _VALUES[address]
    assert _VALUES[address].split("^")[0] not in _out(adapter)


@pytest.mark.parametrize("address", sorted(_OVERLAY_ONLY))
@_EACH_ADAPTER
def test_without_the_overlay_the_overlay_only_fields_pass_unchanged(
    adapter: Callable[..., str], address: str
) -> None:
    """The discriminating half: this is what the overlay is for. It also pins that IN1-4 is kept."""
    assert _field_of(adapter(_MESSAGE, salt=_SALT), address) == _VALUES[address]


def test_both_adapters_agree_on_the_batch_18_message() -> None:
    assert _out(engine_anonymize) == _out(tee_anonymize)
