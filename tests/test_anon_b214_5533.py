# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The default rules map the identity, location and contact fields BACKLOG #5533 found unmapped.

Each of these fields sat inside a segment the default map already scrubbed, so with
``require_full_coverage`` off its value passed into the dataset as captured. This pins each field
to a kind, and checks on both adapters that a made-up value in each one is gone from the output.
Every message here is synthetic (CLAUDE.md section 9).
"""

from __future__ import annotations

import functools
from collections.abc import Callable
from typing import Any

import pytest

from messagefoundry_toolkit.anon import SurrogateKind
from messagefoundry_toolkit.anon import anonymize as engine_anonymize
from messagefoundry_toolkit.anon import rules as engine_rules
from tee.anon import anonymize as tee_anonymize
from tee.anon import rules as tee_rules

_SALT = "b214-salt-0123456789abcdef"
_EACH_RULES = pytest.mark.parametrize("module", (engine_rules, tee_rules), ids=("engine", "tee"))
_EACH_ADAPTER = pytest.mark.parametrize(
    "adapter", (engine_anonymize, tee_anonymize), ids=("engine", "tee")
)

# The fields this row added to DEFAULT_RULES, with the kind each takes.
_NEW_DEFAULTS = {
    "PID-2": SurrogateKind.MRN,
    "PID-21": SurrogateKind.MRN,
    "PID-23": SurrogateKind.FREETEXT,
    "NK1-13": SurrogateKind.NAME,
    "NK1-30": SurrogateKind.NAME,
    "NK1-31": SurrogateKind.PHONE,
    "NK1-32": SurrogateKind.ADDRESS,
    "NK1-33": SurrogateKind.ID,
    "NK1-37": SurrogateKind.SSN,
    "GT1-2": SurrogateKind.ID,
    "PV1-6": SurrogateKind.FREETEXT,
    "PV1-11": SurrogateKind.FREETEXT,
    "PV1-42": SurrogateKind.FREETEXT,
    "PV1-43": SurrogateKind.FREETEXT,
}

# A distinct made-up value in every listed field. Each first component is a token found nowhere
# else in the message, so its absence from the output is a reading about that field alone.
_VALUES = {
    "PID-2": "EXT55501^^^HOSP^PI",
    "PID-21": "MOM77701^^^HOSP^MR",
    "PID-23": "BIRTHPLACETOWN",
    "NK1-13": "ACMEORGNAME^L^ORG123",
    "NK1-30": "CONTACTSMITH^CONTACTJANE",
    "NK1-31": "000-555-0171",
    "NK1-32": "9 CONTACT LANE^^CONTACTCITY^ZZ^00009",
    "NK1-33": "NKID99901^^^HOSP^PI",
    "NK1-37": "000-12-3456",
    "GT1-2": "GUAR88801^^^HOSP^GN",
    "PV1-6": "PRIORWARD^101^A",
    "PV1-11": "TEMPLOC^202^B",
    "PV1-42": "PENDINGWARD^303^C",
    "PV1-43": "PRIORTEMPWARD^404^D",
}


def _segment(seg_id: str, **known: str) -> str:
    """One segment with field 1 set to ``1``, each listed value in place, and ``known`` (a field
    number written ``f3``) filled in too."""
    fields = {int(a.split("-")[1]): v for a, v in _VALUES.items() if a.startswith(seg_id + "-")}
    fields.update({int(key[1:]): value for key, value in known.items()})
    return "|".join([seg_id, "1"] + [fields.get(i, "") for i in range(2, max(fields) + 1)])


_MESSAGE = "\r".join(
    (
        r"MSH|^~\&|SAPP|SFAC|RAPP|RFAC|20260315142233||ADT^A01|MSGCTRL|P|2.5.1",
        _segment("PID", f3="12345^^^HOSP^MR", f5="DOE^JOHN"),
        _segment("NK1"),
        _segment("GT1"),
        _segment("PV1"),
    )
)


def _field_of(message: str, address: str) -> str:
    seg_id, num = address.split("-")
    line = next(seg for seg in message.split("\r") if seg.startswith(seg_id + "|"))
    fields = line.split("|")
    return fields[int(num)] if int(num) < len(fields) else ""


@functools.cache
def _out(adapter: Callable[..., str]) -> str:
    return adapter(_MESSAGE, salt=_SALT)


def test_the_tables_name_the_same_fields() -> None:
    """A guard on this file: a field with a kind and no value would be checked nowhere."""
    assert sorted(_NEW_DEFAULTS) == sorted(_VALUES)


@_EACH_RULES
def test_the_default_rules_map_every_field_on_the_list(module: Any) -> None:
    kinds = {rule.path: rule.kind for rule in module.DEFAULT_RULES}
    for address, kind in _NEW_DEFAULTS.items():
        assert kinds.get(address) == kind, address


@pytest.mark.parametrize("address", sorted(_VALUES))
def test_the_control_message_carries_a_value_in_every_listed_field(address: str) -> None:
    """Without this, a field the control never populated would read as scrubbed."""
    assert _field_of(_MESSAGE, address) == _VALUES[address] != ""


@pytest.mark.parametrize("address", sorted(_VALUES))
@_EACH_ADAPTER
def test_every_listed_value_is_replaced(adapter: Callable[..., str], address: str) -> None:
    replaced = _field_of(_out(adapter), address)
    assert replaced and replaced != _VALUES[address]
    assert _VALUES[address].split("^")[0] not in _out(adapter)


def test_both_adapters_agree_on_the_message() -> None:
    assert _out(engine_anonymize) == _out(tee_anonymize)
