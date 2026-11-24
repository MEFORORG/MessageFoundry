# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The default rules map twenty more GT1, NK1, MRG and PV1 fields BACKLOG #5533 left unmapped.

The first pass on this row mapped fourteen fields (``tests/test_anon_b214_5533.py``). Fields of
the same class stayed unmapped inside segments the default map already scrubbed: names, ids,
phones, birth places, a death date and visit locations. At least some fields of these segments
still have no rule; ``rules.py`` names them. Plain ``anonymize`` passed these twenty through,
apart from what the site-code pass rewrites. ``anonymize_checked`` refused at least a dashed SSN,
a phone written ``NNN-NNN-NNNN`` or ``(NNN) NNN-NNNN``, or an ``MR``- or ``MRN``-typed id in them.
Under the default rules, only ``require_full_coverage`` refused a message with any value in them.
This pins each to a kind, checks on both adapters that a made-up value in each is gone from the
output, and keeps a control that shows the same value survives when its rule is taken away. Every
message here is synthetic (CLAUDE.md section 9), and no test prints a message body.
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

_SALT = "b5533-salt-fedcba9876543210-0123456789"
_EACH_RULES = pytest.mark.parametrize("module", (engine_rules, tee_rules), ids=("engine", "tee"))
_EACH_ADAPTER = pytest.mark.parametrize(
    "adapter", (engine_anonymize, tee_anonymize), ids=("engine", "tee")
)

# The fields this pass added to DEFAULT_RULES, with the kind each takes. An MRG field takes the
# kind of the field it is the prior value of (MRG-2 with PID-4, MRG-5 with PV1-19, MRG-6 with
# PV1-50), so a prior value gets the same surrogate as that value written identically in its pair.
_NEW_DEFAULTS = {
    "GT1-4": SurrogateKind.NAME,
    "GT1-19": SurrogateKind.ID,
    "GT1-21": SurrogateKind.FREETEXT,
    "GT1-24": SurrogateKind.DATE,
    "GT1-29": SurrogateKind.ID,
    "GT1-42": SurrogateKind.NAME,
    "GT1-45": SurrogateKind.NAME,
    "GT1-46": SurrogateKind.PHONE,
    "GT1-51": SurrogateKind.FREETEXT,
    "GT1-56": SurrogateKind.FREETEXT,
    "NK1-12": SurrogateKind.ID,
    "NK1-26": SurrogateKind.NAME,
    "NK1-38": SurrogateKind.FREETEXT,
    "MRG-2": SurrogateKind.ID,
    "MRG-5": SurrogateKind.ID,
    "MRG-6": SurrogateKind.ID,
    "PV1-5": SurrogateKind.ID,
    "PV1-37": SurrogateKind.FREETEXT,
    "PV1-50": SurrogateKind.ID,
    "PV1-52": SurrogateKind.PROVIDER,
}

# A distinct made-up value in every listed field. Each first component is a token found nowhere
# else in the message, so its absence from the output is a reading about that field alone.
_VALUES = {
    "GT1-4": "SPOUSESMITH^SPOUSEJANE",
    "GT1-19": "GTEMPID44401^^^EMPR^EI",
    "GT1-21": "GUARORGNAME^L^777",
    "GT1-24": "20250412083000",
    "GT1-29": "GTEMPLOYER2901^^^EMPR^EI",
    "GT1-42": "GTMAIDENJONES^MARY",
    "GT1-45": "GTCONTACTLEE^PAT",
    "GT1-46": "000-555-0172",
    "GT1-51": "EMPLOYERORGNAME^L^888",
    "GT1-56": "GUARBIRTHTOWN",
    "NK1-12": "NKEMP33301^^^EMPR^EI",
    "NK1-26": "NKMAIDENBROWN^ANN",
    "NK1-38": "NKBIRTHTOWN",
    "MRG-2": "ALTPAT2201^^^HOSP^PI",
    "MRG-5": "PRIORVIS501^^^HOSP^VN",
    "MRG-6": "ALTVIS601^^^HOSP^AN",
    "PV1-5": "PREADM501^^^HOSP^VN",
    "PV1-37": "DESTFACILITY^20260310",
    "PV1-50": "ALTVISIT5001^^^HOSP^AN",
    "PV1-52": "OTHPROV123^OTHERDOC^ANNE",
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


def _first_component(address: str) -> str:
    return _VALUES[address].split("^")[0]


@functools.cache
def _out(adapter: Callable[..., str]) -> str:
    return adapter(_MESSAGE, salt=_SALT)


@functools.cache
def _out_without_new_rules(adapter: Callable[..., str]) -> str:
    """Each adapter runs on its own copy of the defaults, less the fields this pass added."""
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


_MRG_PAIRS = (("MRG-2", "PID-4"), ("MRG-5", "PV1-19"), ("MRG-6", "PV1-50"))


@_EACH_RULES
def test_each_new_mrg_field_takes_the_kind_of_its_current_value(module: Any) -> None:
    """The merge linkage for the MRG fields this pass maps: each prior id is keyed with the same
    kind as the field it was the value of. MRG-3 and MRG-4 are not this pass's (see BACKLOG #5533)."""
    kinds = {rule.path: rule.kind for rule in module.DEFAULT_RULES}
    for prior, current in _MRG_PAIRS:
        assert kinds[prior] == kinds[current], prior


@pytest.mark.parametrize(("prior", "current"), _MRG_PAIRS)
@_EACH_ADAPTER
def test_a_shared_value_gets_one_surrogate_across_the_merge(
    adapter: Callable[..., str], prior: str, current: str
) -> None:
    """The same id in an MRG field and in the field it was the value of maps to one surrogate."""
    shared = "SHAREDID4242^^^HOSP^AN"
    pv1 = "|".join(["PV1", "1"] + [shared if f"PV1-{i}" == current else "" for i in range(2, 51)])
    pid = "|".join(["PID", "1", "", "12345^^^HOSP^MR", shared if current == "PID-4" else ""])
    mrg = "|".join(["MRG", "1"] + [shared if f"MRG-{i}" == prior else "" for i in range(2, 7)])
    message = "\r".join(
        (r"MSH|^~\&|SAPP|SFAC|RAPP|RFAC|20260315142233||ADT^A40|MSGCTRL|P|2.5.1", pid, mrg, pv1)
    )
    out = adapter(message, salt=_SALT)
    assert _field_of(message, prior) == _field_of(message, current) == shared
    assert _field_of(out, prior) == _field_of(out, current) != shared


@pytest.mark.parametrize("address", sorted(_VALUES))
def test_the_control_message_carries_a_value_in_every_listed_field(address: str) -> None:
    """Without this, a field the control never populated would read as scrubbed."""
    assert _field_of(_MESSAGE, address) == _VALUES[address] != ""


@pytest.mark.parametrize("address", sorted(_VALUES))
@_EACH_ADAPTER
def test_without_its_rule_the_value_passes_as_captured(
    adapter: Callable[..., str], address: str
) -> None:
    """The negative control: the rule is what removes the value, not something else in the run."""
    assert _field_of(_out_without_new_rules(adapter), address) == _VALUES[address]


@pytest.mark.parametrize("address", sorted(_VALUES))
@_EACH_ADAPTER
def test_every_listed_value_is_replaced(adapter: Callable[..., str], address: str) -> None:
    replaced = _field_of(_out(adapter), address)
    assert replaced and replaced != _VALUES[address]
    assert _first_component(address) not in _out(adapter)


@_EACH_ADAPTER
def test_no_listed_date_survives(adapter: Callable[..., str]) -> None:
    """The month and day of the guarantor's death and of the discharge are gone (the date kind
    keeps the year; the discharge location's whole field is redacted)."""
    assert "0412" not in _field_of(_out(adapter), "GT1-24")
    assert "20260310" not in _out(adapter)


def test_both_adapters_agree_on_the_message() -> None:
    assert _out(engine_anonymize) == _out(tee_anonymize)
