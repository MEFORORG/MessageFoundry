# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The default rules map the dates and job titles BACKLOG #5533's second pass left unmapped, and
MRG-4 takes the identifier kind of its pair field.

After the second pass (``tests/test_anon_5533_remaining_defaults.py``) the rules comment listed
PID-33, NK1-8/9, GT1-13/14/31/32 and PV1-25/30/35 (dates) and NK1-10 and GT1-49 (job titles) as
fields of the same class with no rule, so plain ``anonymize`` passed them through as captured.
MRG-4, the prior patient id, is a CX paired with PID-2, yet took the name kind, so a merge did
not key it like the id it was. This pins each to a kind, checks on both adapters that a made-up
value in each is gone, and keeps a control that shows the value survives when its rule is taken
away. Every message here is synthetic (CLAUDE.md section 9), and no test prints a message body.
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

_SALT = "b5533-third-salt-0123456789abcdef-fedcba"
_EACH_RULES = pytest.mark.parametrize("module", (engine_rules, tee_rules), ids=("engine", "tee"))
_EACH_ADAPTER = pytest.mark.parametrize(
    "adapter", (engine_anonymize, tee_anonymize), ids=("engine", "tee")
)

_DATES = (
    "PID-33",
    "NK1-8",
    "NK1-9",
    "GT1-13",
    "GT1-14",
    "GT1-31",
    "GT1-32",
    "PV1-25",
    "PV1-30",
    "PV1-35",
)
_NEW_DEFAULTS = {
    **dict.fromkeys(_DATES, SurrogateKind.DATE),
    "NK1-10": SurrogateKind.FREETEXT,
    "GT1-49": SurrogateKind.FREETEXT,
    "MRG-4": SurrogateKind.MRN,
}

# Each date has its own month and day, found nowhere else in the message, so the absence of
# that MMDD from the field's output is a reading about that field alone. The date kind keeps the
# year, so only the year 2019 may survive.
_VALUES = {
    "PID-33": "20190103101500",
    "NK1-8": "20190105",
    "NK1-9": "20190107",
    "GT1-13": "20190109",
    "GT1-14": "20190111",
    "GT1-31": "20190113",
    "GT1-32": "20190115",
    "PV1-25": "20190117",
    "PV1-30": "20190119",
    "PV1-35": "20190121",
    "NK1-10": "NKJOBTITLEWELDER",
    "GT1-49": "GTJOBTITLEPILOT",
    "MRG-4": "PRIORPAT4401^^^HOSP^PI",
}


def _segment(seg_id: str, **known: str) -> str:
    """One segment with field 1 set to ``1``, each listed value in place, and ``known`` (a field
    number written ``f3``) filled in too."""
    fields = {int(a.split("-")[1]): v for a, v in _VALUES.items() if a.startswith(seg_id + "-")}
    fields.update({int(key[1:]): value for key, value in known.items()})
    return "|".join([seg_id, "1"] + [fields.get(i, "") for i in range(2, max(fields) + 1)])


_MESSAGE = "\r".join(
    (
        r"MSH|^~\&|SAPP|SFAC|RAPP|RFAC|20260315142233||ADT^A40|MSGCTRL|P|2.5.1",
        _segment("PID", f3="12345^^^HOSP^MR", f5="DOE^JOHN"),
        _segment("MRG"),
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


def _secret_part(address: str) -> str:
    """The part of a value that must not survive: a date's MMDD, else its first component."""
    value = _VALUES[address]
    return value[4:8] if address in _DATES else value.split("^")[0]


@functools.cache
def _out(adapter: Callable[..., str]) -> str:
    return adapter(_MESSAGE, salt=_SALT)


@functools.cache
def _out_without_new_rules(adapter: Callable[..., str]) -> str:
    """Each adapter runs on its own copy of the defaults, less the fields this pass mapped."""
    module: Any = tee_rules if adapter is tee_anonymize else engine_rules
    rules = tuple(r for r in module.DEFAULT_RULES if r.path not in _NEW_DEFAULTS)
    return adapter(_MESSAGE, salt=_SALT, rules=rules)


def test_the_tables_name_the_same_fields() -> None:
    """A guard on this file: a field with a kind and no value would be checked nowhere."""
    assert sorted(_NEW_DEFAULTS) == sorted(_VALUES)


@_EACH_RULES
def test_the_default_rules_map_every_field_on_the_list(module: Any) -> None:
    kinds = {rule.path: rule.kind for rule in module.DEFAULT_RULES}
    for address, kind in _NEW_DEFAULTS.items():
        assert kinds.get(address) == kind, address


@_EACH_RULES
def test_mrg4_takes_the_kind_of_pid2(module: Any) -> None:
    kinds = {rule.path: rule.kind for rule in module.DEFAULT_RULES}
    assert kinds["MRG-4"] == kinds["PID-2"]


@_EACH_ADAPTER
def test_a_shared_prior_patient_id_gets_one_surrogate_across_the_merge(
    adapter: Callable[..., str],
) -> None:
    shared = "SHAREDPAT77^^^HOSP^PI"
    message = "\r".join(
        (
            r"MSH|^~\&|SAPP|SFAC|RAPP|RFAC|20260315142233||ADT^A40|MSGCTRL|P|2.5.1",
            f"PID|1|{shared}|12345^^^HOSP^MR",
            f"MRG|1|||{shared}",
        )
    )
    out = adapter(message, salt=_SALT)
    assert _field_of(message, "MRG-4") == _field_of(message, "PID-2") == shared
    assert _field_of(out, "MRG-4") == _field_of(out, "PID-2") != shared


@pytest.mark.parametrize("address", sorted(_VALUES))
def test_the_control_message_carries_a_value_in_every_listed_field(address: str) -> None:
    """Without this, a field the control never populated would read as scrubbed."""
    assert _field_of(_MESSAGE, address) == _VALUES[address] != ""


@pytest.mark.parametrize("address", sorted(set(_VALUES) - {"MRG-4"}))
@_EACH_ADAPTER
def test_without_its_rule_the_value_passes_as_captured(
    adapter: Callable[..., str], address: str
) -> None:
    """The negative control: the rule is what removes the value, not something else in the run.
    MRG-4 had a rule before this pass, so it has no such control."""
    assert _field_of(_out_without_new_rules(adapter), address) == _VALUES[address]


@pytest.mark.parametrize("address", sorted(_VALUES))
@_EACH_ADAPTER
def test_every_listed_value_is_replaced(adapter: Callable[..., str], address: str) -> None:
    replaced = _field_of(_out(adapter), address)
    assert replaced != _VALUES[address]
    assert _secret_part(address) not in replaced


@pytest.mark.parametrize("address", sorted(_VALUES))
@_EACH_ADAPTER
def test_no_listed_secret_survives_anywhere_in_the_output(
    adapter: Callable[..., str], address: str
) -> None:
    assert _secret_part(address) not in _out(adapter)


@_EACH_ADAPTER
def test_mrg4_keeps_the_identifier_shape(adapter: Callable[..., str]) -> None:
    """Under the name kind a CX in MRG-4 was rewritten as a person name; the identifier kind
    keeps its assigning authority and id type, as it does on PID-2."""
    components = _field_of(_out(adapter), "MRG-4").split("^")
    assert components[3:5] == ["HOSP", "PI"]


def test_both_adapters_agree_on_the_message() -> None:
    assert _out(engine_anonymize) == _out(tee_anonymize)
