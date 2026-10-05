# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The anonymizer follow-ups engine PR 1734 shipped open (BACKLOG #2330), one group per item.

Every message here is synthetic (CLAUDE.md section 9). Each behavioural case runs through both
adapters, the engine's and the tee's, because the two reach a field by different routes.
"""

from __future__ import annotations

import functools
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from messagefoundry.anon import DEFAULT_RULES, SurrogateKind
from messagefoundry.anon import anonymize as engine_anonymize
from messagefoundry.anon import rules as engine_rules
from messagefoundry.anon import surrogates as engine_surrogates
from tee.anon import DEFAULT_RULES as TEE_DEFAULT_RULES
from tee.anon import anonymize as tee_anonymize
from tee.anon import rules as tee_rules
from tee.anon import surrogates as tee_surrogates

_SALT = "b193-salt-0123456789abcdef"
_HEADER = r"MSH|^~\&|SAPP|SFAC|RAPP|RFAC|20260315142233||ADT^A01|MSGCTRL|P|2.5.1"
_ADAPTERS = (engine_anonymize, tee_anonymize)
_EACH_ADAPTER = pytest.mark.parametrize("adapter", _ADAPTERS, ids=("engine", "tee"))


def _msg(*segments: str) -> str:
    return "\r".join(segments)


def _seg(seg_id: str, **fields: str) -> str:
    """A segment with the named 1-based fields set (``f4="x"``) and every other field empty."""
    by_index = {int(name[1:]): value for name, value in fields.items()}
    return "|".join([seg_id] + [by_index.get(i, "") for i in range(1, max(by_index) + 1)])


def _field_of(message: str, address: str) -> str:
    """The whole field at ``address`` in the first segment of that id, read positionally."""
    seg_id, num = address.split("-")
    line = next(seg for seg in message.split("\r") if seg.startswith(seg_id + "|"))
    fields = line.split("|")
    return fields[int(num)] if int(num) < len(fields) else ""


# --- item 1: the date fields that had no rule -----------------------------------------------------

# Each field carries a full synthetic timestamp, so a month, day or time that survived would show.
_EVENT_DATE = "20260315142233"
_BIRTH_DATE = "19570412"
_DATE_FIELDS_MSG = _msg(
    _HEADER,
    "PID|1||12345^^^HOSP^MR||DOE^JOHN",
    _seg("NK1", f1="1", f16=_BIRTH_DATE),
    _seg("GT1", f1="1", f8=_BIRTH_DATE),
    _seg("IN1", f1="1", f18=_BIRTH_DATE),
    _seg("AIS", f1="1", f4=_EVENT_DATE),
    _seg("RXA", f1="0", f2="1", f3=_EVENT_DATE, f4=_EVENT_DATE),
    _seg("PR1", f1="1", f5=_EVENT_DATE),
    _seg("FT1", f1="1", f4=_EVENT_DATE),
)
_EVENT_DATE_FIELDS = ("AIS-4", "RXA-3", "RXA-4", "PR1-5", "FT1-4")
_BIRTH_DATE_FIELDS = ("GT1-8", "IN1-18", "NK1-16")


@functools.cache
def _date_fields_out(adapter: Callable[..., str]) -> str:
    return adapter(_DATE_FIELDS_MSG, salt=_SALT)


@pytest.mark.parametrize("address", _EVENT_DATE_FIELDS + _BIRTH_DATE_FIELDS)
def test_the_control_message_carries_a_real_date_in_every_listed_field(address: str) -> None:
    """Without this, a field the control never populated would read as scrubbed."""
    assert _field_of(_DATE_FIELDS_MSG, address) in (_EVENT_DATE, _BIRTH_DATE)


@pytest.mark.parametrize("rules", (DEFAULT_RULES, TEE_DEFAULT_RULES), ids=("engine", "tee"))
def test_every_listed_date_field_has_a_default_rule_of_the_right_kind(
    rules: tuple[object, ...],
) -> None:
    kinds = {rule.path: rule.kind for rule in rules}  # type: ignore[attr-defined]
    for address in _EVENT_DATE_FIELDS:
        assert kinds.get(address) == SurrogateKind.DATE, address
    for address in _BIRTH_DATE_FIELDS:
        assert kinds.get(address) == SurrogateKind.DOB, address


@pytest.mark.parametrize("address", _EVENT_DATE_FIELDS)
@_EACH_ADAPTER
def test_an_event_date_keeps_only_its_year(adapter: Callable[..., str], address: str) -> None:
    assert _field_of(_date_fields_out(adapter), address) == "20260101000000"


@pytest.mark.parametrize("address", _BIRTH_DATE_FIELDS)
@_EACH_ADAPTER
def test_a_date_of_birth_is_replaced_at_the_same_width(
    adapter: Callable[..., str], address: str
) -> None:
    out = _field_of(_date_fields_out(adapter), address)
    assert out != _BIRTH_DATE
    assert len(out) == len(_BIRTH_DATE) and out.isdigit()


def test_both_adapters_agree_on_the_date_fields() -> None:
    assert _date_fields_out(engine_anonymize) == _date_fields_out(tee_anonymize)


# --- item 5: a rule built in code has its path checked --------------------------------------------

_BAD_PATHS = (
    "pid-29",  # lower case: matched no segment, so the rule silently did nothing
    "PID-29.1",  # a component path: a raw ValueError inside the tee, on the first message
    "PID-0",  # the segment id itself, which the tee would overwrite
    "PID-05",  # a leading zero: the tee reads field 5, the leak-check reads no rule
    "PID-" + chr(0x0665),  # a non-ASCII digit, which int() and a regex digit class both accept
    "PID-5\n",  # a trailing newline, which a bare match with an end anchor lets through
    "PID5",
    "PATIENT-5",
    "",
)


@pytest.mark.parametrize("path", _BAD_PATHS)
@pytest.mark.parametrize("module", (engine_rules, tee_rules), ids=("engine", "tee"))
def test_a_field_rule_refuses_a_path_that_is_not_a_whole_field(module: Any, path: str) -> None:
    with pytest.raises(module.RuleError, match="not a whole-field HL7 address"):
        module.FieldRule(path, module.SurrogateKind.DATE)


@pytest.mark.parametrize("module", (engine_rules, tee_rules), ids=("engine", "tee"))
def test_a_field_rule_refuses_a_path_that_is_not_a_string(module: Any) -> None:
    with pytest.raises(module.RuleError, match="not a whole-field HL7 address"):
        module.FieldRule(29, module.SurrogateKind.DATE)


@pytest.mark.parametrize("path", ("PID-29", "ZPD-2", "IN2-3", "MSH-14", "OBX-120"))
@pytest.mark.parametrize("module", (engine_rules, tee_rules), ids=("engine", "tee"))
def test_a_field_rule_accepts_a_whole_field_path(module: Any, path: str) -> None:
    assert module.FieldRule(path, "date").path == path


@pytest.mark.parametrize("module", (engine_rules, tee_rules), ids=("engine", "tee"))
def test_an_overlay_key_is_held_to_the_same_path_check(module: Any, tmp_path: Path) -> None:
    overlay = tmp_path / "anon.toml"
    overlay.write_text('[hl7.fields]\n"PID-05" = "date"\n', encoding="utf-8")
    with pytest.raises(module.RuleError, match="not a whole-field HL7 address"):
        module.load_rules(overlay)


# --- item 2: a date-typed OBX-5 is a date ---------------------------------------------------------

_ORU_HEADER = r"MSH|^~\&|SAPP|SFAC|RAPP|RFAC|20260315142233||ORU^R01|MSGCTRL|P|2.5.1"

# OBX line -> the OBX-5 the anonymizer must produce.
_DATE_TYPED_OBX5 = {
    "DT keeps its year": ("OBX|1|DT|8665-2^LMP^LN||20260315|", "20260101"),
    "TS keeps its year": ("OBX|1|TS|CL^Collected^L||20260315142233-0500|", "20260101000000+0000"),
    "lower-case label": ("OBX|1|ts|CL^Collected^L||20260315142233|", "20260101000000"),
    "each repetition": ("OBX|1|DT|8665-2^LMP^LN||20260315~20250704|", "20260101~20250101"),
    # A label is never taken on trust. Under a date label, a value that is not a timestamp is
    # scrubbed to empty: digits and dashes passed the old shared character class whole.
    "dashed date": ("OBX|1|DT|8665-2^LMP^LN||2026-03-15|", ""),
    "SSN shape": ("OBX|1|DT|8665-2^LMP^LN||123-45-6789|", ""),
    "prose": ("OBX|1|TS|CL^Collected^L||seen 15 March|", ""),
    "US order": ("OBX|1|DT|8665-2^LMP^LN||03152026|", ""),
    # DTM is not on either list, so it stays a whole redact.
    "DTM label": ("OBX|1|DTM|CL^Collected^L||20260315142233|", "[REDACTED]"),
}
# Values the change must leave alone. The NM and SN cases share the character class the date types
# used to share, so they prove the class itself did not move.
_STILL_PRESERVED = {
    "NM": ("OBX|1|NM|8480-6^Systolic^LN||128|", "128"),
    "NM that reads as a date": ("OBX|1|NM|8480-6^Count^LN||20260315|", "20260315"),
    "SN": ("OBX|1|SN|RG^Range^L||>^100|", ">^100"),
    "TM": ("OBX|1|TM|CL^Collected^L||142233|", "142233"),
}


def _obx_out(adapter: Callable[..., str], obx: str) -> str:
    return _field_of(
        adapter(_msg(_ORU_HEADER, "PID|1||12345^^^HOSP^MR||DOE^JOHN", obx), salt=_SALT), "OBX-5"
    )


@pytest.mark.parametrize("case", sorted(_DATE_TYPED_OBX5))
@_EACH_ADAPTER
def test_a_date_typed_obx5_takes_the_date_kind(adapter: Callable[..., str], case: str) -> None:
    obx, expected = _DATE_TYPED_OBX5[case]
    assert _obx_out(adapter, obx) == expected


@pytest.mark.parametrize("case", sorted(_STILL_PRESERVED))
@_EACH_ADAPTER
def test_a_numeric_or_time_obx5_is_still_preserved(adapter: Callable[..., str], case: str) -> None:
    obx, expected = _STILL_PRESERVED[case]
    assert _obx_out(adapter, obx) == expected


@pytest.mark.parametrize("module", (engine_surrogates, tee_surrogates), ids=("engine", "tee"))
def test_obx5_kind_is_date_only_for_a_date_type(module: Any) -> None:
    assert module.obx5_kind("DT") == SurrogateKind.DATE
    assert module.obx5_kind(" ts ") == SurrogateKind.DATE
    for other in ("NM", "TM", "DTM", "TX", "", None):
        assert module.obx5_kind(other) == SurrogateKind.FREETEXT, other
    for date_type in ("DT", "TS"):
        assert not module.preserve_obx5_value(date_type, "20260315", module.Seps())


def test_an_overlay_keep_still_leaves_a_date_typed_obx5_alone() -> None:
    """The date treatment belongs to the OBX-5 free-text rule. A keep is a different decision."""
    message = _msg(_ORU_HEADER, "OBX|1|DT|8665-2^LMP^LN||20260315|")
    rules = (engine_rules.FieldRule("OBX-5", SurrogateKind.KEEP),)
    assert _field_of(engine_anonymize(message, salt=_SALT, rules=rules), "OBX-5") == "20260315"
