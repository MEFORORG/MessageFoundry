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
from tee.anon import DEFAULT_RULES as TEE_DEFAULT_RULES
from tee.anon import anonymize as tee_anonymize
from tee.anon import rules as tee_rules

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
