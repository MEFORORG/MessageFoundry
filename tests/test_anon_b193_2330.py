# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The anonymizer follow-ups engine PR 1734 shipped open (BACKLOG #2330), one group per item.

Every message here is synthetic (CLAUDE.md section 9). Each behavioural case runs through both
adapters, the engine's and the tee's, because the two reach a field by different routes.
"""

from __future__ import annotations

import functools
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest

from messagefoundry.anon import DEFAULT_RULES, SurrogateKind
from messagefoundry.anon import anonymize as engine_anonymize
from messagefoundry.anon import anonymize_checked as engine_anonymize_checked
from messagefoundry.anon import keying as engine_keying
from messagefoundry.anon import leak as engine_leak
from messagefoundry.anon import rules as engine_rules
from messagefoundry.anon import surrogates as engine_surrogates
from tee.anon import DEFAULT_RULES as TEE_DEFAULT_RULES
from tee.anon import anonymize as tee_anonymize
from tee.anon import anonymize_checked as tee_anonymize_checked
from tee.anon import leak as tee_leak
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


# --- item 4: the site-code pass leaves DATE output alone ------------------------------------------

# A year-and-month date. Its first two digits are the century, and an estate whose site-code prefix
# is that same pair turns every such date into the shape of a site code. The prefix is derived from
# the date so that no literal prefix sits in this scanned file.
_YEAR_MONTH = "202603"
_FILLED = "202601"
_SITE_CODE = _YEAR_MONTH[:2] + "5588"  # the prefix and four digits that are not a month and a day
_CHECKED = (engine_anonymize_checked, tee_anonymize_checked)
_SURROGATES = pytest.mark.parametrize(
    "module", (engine_surrogates, tee_surrogates), ids=("engine", "tee")
)


@pytest.fixture
def century_site_prefix(monkeypatch: pytest.MonkeyPatch) -> Iterator[str]:
    """Configure a synthetic site-code prefix equal to the century, in BOTH copies of the module.
    The engine's scanner is loaded first, so it never reads the patched token source."""
    engine_leak._scanner()
    prefix = _YEAR_MONTH[:2]
    monkeypatch.setenv("MEFOR_FORBIDDEN_TOKENS", f"[site_prefix]\n{prefix}\n")
    engine_surrogates.reload_site_prefixes()
    tee_surrogates.reload_site_prefixes()
    yield prefix
    monkeypatch.undo()  # restore the real source BEFORE recomputing, as tests/test_anon_core.py does
    engine_surrogates.reload_site_prefixes()
    tee_surrogates.reload_site_prefixes()


def _site_message(*segments: str) -> str:
    return _msg(_HEADER, "PID|1||12345^^^HOSP^MR||DOE^JOHN", *segments)


@_SURROGATES
def test_the_control_values_have_the_shape_of_a_site_code(
    module: Any, century_site_prefix: str
) -> None:
    """Without this the cases below pass with no prefix configured at all."""
    for value in (_YEAR_MONTH, _FILLED, _SITE_CODE):
        assert module.SITE_CODE_RE.fullmatch(value), value


@pytest.mark.parametrize("checked", _CHECKED, ids=("engine", "tee"))
def test_a_year_and_month_date_survives_the_site_code_pass(
    checked: Callable[..., str], century_site_prefix: str
) -> None:
    """Before, the pass replaced the filled date with a salted number, which is not a date."""
    out = checked(_site_message("EVN|A01|" + _YEAR_MONTH), salt=_SALT)
    assert _field_of(out, "EVN-2") == _FILLED


@pytest.mark.parametrize("checked", _CHECKED, ids=("engine", "tee"))
def test_a_date_typed_obx5_survives_the_site_code_pass(
    checked: Callable[..., str], century_site_prefix: str
) -> None:
    out = checked(_site_message("OBX|1|DT|8665-2^LMP^LN||" + _YEAR_MONTH), salt=_SALT)
    assert _field_of(out, "OBX-5") == _FILLED


@_EACH_ADAPTER
def test_a_site_code_outside_a_date_field_is_still_scrubbed(
    adapter: Callable[..., str], century_site_prefix: str
) -> None:
    """The exemption is per field. An unmapped field and a numeric OBX-5 keep the old behaviour."""
    out = adapter(
        _site_message("ZPD|" + _SITE_CODE, "OBX|1|NM|8480-6^Count^LN||" + _SITE_CODE), salt=_SALT
    )
    for address in ("ZPD-1", "OBX-5"):
        value = _field_of(out, address)
        assert value != _SITE_CODE and len(value) == len(_SITE_CODE), address


@_EACH_ADAPTER
def test_a_date_of_birth_field_is_not_exempt(
    adapter: Callable[..., str], century_site_prefix: str
) -> None:
    """Only the DATE kind is exempt. The value is one the DATE kind would write, so the path's kind
    is the only thing that separates the two halves: DOB is checked, DATE is skipped."""
    module = engine_surrogates if adapter is engine_anonymize else tee_surrogates
    text = _site_message("ZPD|" + _FILLED)
    assert module.message_has_site_code(text, (engine_rules.FieldRule("ZPD-1", SurrogateKind.DOB),))
    assert not module.message_has_site_code(
        text, (engine_rules.FieldRule("ZPD-1", SurrogateKind.DATE),)
    )


@_SURROGATES
def test_the_leak_check_skips_only_a_value_the_date_kind_wrote(
    module: Any, century_site_prefix: str
) -> None:
    rules = (engine_rules.FieldRule("EVN-2", SurrogateKind.DATE),)

    def flagged(value: str, with_rules: bool = True) -> bool:
        text = _site_message("EVN|A01|" + value)
        return bool(module.message_has_site_code(text, rules if with_rules else ()))

    assert not flagged(_FILLED)
    assert flagged(_FILLED, with_rules=False)  # no rules, no exemption: the old behaviour
    assert flagged(_YEAR_MONTH)  # a date field that never went through the DATE kind
    assert flagged(_SITE_CODE)  # a site code that is not a date at all
    assert flagged(_FILLED + "~" + _SITE_CODE)  # one bad repetition spoils the field


@_SURROGATES
def test_the_exemption_never_reaches_an_msh_line(module: Any, century_site_prefix: str) -> None:
    """Both adapters apply a DATE rule to an MSH field (BACKLOG #2265), but the exemption does not
    number MSH fields the MSH way, so it never reaches an MSH line: the value is still checked
    and scrubbed."""
    rules = tuple(engine_rules.FieldRule(f"MSH-{n}", SurrogateKind.DATE) for n in (12, 13, 14))
    text = _HEADER + "|" + _FILLED  # one field after the version, whichever way MSH is numbered
    assert module.message_has_site_code(text, rules)
    assert _FILLED not in module.scrub_message_site_codes(text, engine_keying.Keyer(_SALT), rules)


def test_a_date_rule_on_an_msh_field_is_applied_and_still_not_exempt(
    century_site_prefix: str,
) -> None:
    """The whole route, both adapters: the DATE rule on MSH-13 runs (BACKLOG #2265), then the
    site-code pass rewrites the ``YYYYMM`` it left, because the exemption stops at an MSH line.
    So the two sides give the same bytes and neither keeps the filled date. The control is the
    same value in a segment the exemption does reach."""
    paths = ("MSH-13", "ZPD-1")
    msg = _msg(
        _HEADER + "|" + _YEAR_MONTH, "PID|1||12345^^^HOSP^MR||DOE^JOHN", "ZPD|" + _YEAR_MONTH
    )
    # Each side gets rules built from its own package's classes, as a real caller would.
    engine = engine_anonymize(
        msg,
        salt=_SALT,
        rules=(*DEFAULT_RULES, *(engine_rules.FieldRule(p, SurrogateKind.DATE) for p in paths)),
    )
    tee = tee_anonymize(
        msg,
        salt=_SALT,
        rules=(
            *TEE_DEFAULT_RULES,
            *(tee_rules.FieldRule(p, tee_rules.SurrogateKind.DATE) for p in paths),
        ),
    )
    assert engine == tee
    header, _pid, zpd = tee.split("\r")
    assert header.split("|")[12] not in (_YEAR_MONTH, _FILLED)  # MSH-13 sits at split index 12
    assert zpd == "ZPD|" + _FILLED


@_SURROGATES
def test_a_path_with_a_second_non_date_rule_is_not_exempt(
    module: Any, century_site_prefix: str
) -> None:
    rules = (
        engine_rules.FieldRule("EVN-2", SurrogateKind.DATE),
        engine_rules.FieldRule("EVN-2", SurrogateKind.ID),
    )
    assert module.message_has_site_code(_site_message("EVN|A01|" + _FILLED), rules)


# --- item 7: a date scrubbed to empty leaves a record ---------------------------------------------

_NOT_A_DATE = "2026-03-15"  # dashes: not an HL7 timestamp, so the DATE kind scrubs it to empty

# EVN-2 value -> whether the anonymizer must record EVN-2 as emptied.
_EVN2_CASES = {
    "a malformed date": (_NOT_A_DATE, True),
    "one malformed repetition": ("20260315~" + _NOT_A_DATE, True),
    "a valid date": ("20260315142233", False),
    "the HL7 null": ('""', False),
    "an absent value": ("", False),
}


@pytest.mark.parametrize("case", sorted(_EVN2_CASES))
@_EACH_ADAPTER
def test_anonymize_records_a_date_field_it_emptied(adapter: Callable[..., str], case: str) -> None:
    value, recorded = _EVN2_CASES[case]
    blanked: list[str] = []
    out = adapter(_site_message("EVN|A01|" + value + "|x"), salt=_SALT, blanked=blanked)
    assert blanked == (["EVN-2"] if recorded else [])
    assert _NOT_A_DATE not in out


@_EACH_ADAPTER
def test_a_date_typed_obx5_that_was_emptied_is_recorded(adapter: Callable[..., str]) -> None:
    blanked: list[str] = []
    adapter(_site_message("OBX|1|DT|8665-2^LMP^LN||" + _NOT_A_DATE), salt=_SALT, blanked=blanked)
    assert blanked == ["OBX-5"]


@_EACH_ADAPTER
def test_a_drop_or_a_redact_is_not_recorded_as_an_emptied_date(adapter: Callable[..., str]) -> None:
    """A DROP is the rule map's own decision, and a redact leaves a marker. Neither is a surprise."""
    rules = (
        engine_rules.FieldRule("EVN-2", SurrogateKind.DROP),
        engine_rules.FieldRule("EVN-3", SurrogateKind.FREETEXT),
    )
    blanked: list[str] = []
    adapter(
        _site_message("EVN|A01|" + _NOT_A_DATE + "|x"), salt=_SALT, rules=rules, blanked=blanked
    )
    assert blanked == []


@pytest.mark.parametrize("checked", _CHECKED, ids=("engine", "tee"))
def test_the_coverage_report_names_every_emptied_date_field_once(
    checked: Callable[..., str],
) -> None:
    reports: list[Any] = []
    message = _site_message(
        "EVN|A01|" + _NOT_A_DATE,
        "OBX|1|DT|8665-2^LMP^LN||" + _NOT_A_DATE,
        "OBX|2|DT|8665-2^LMP^LN||" + _NOT_A_DATE,
    )
    checked(message, salt=_SALT, on_report=reports.append)
    assert [report.blanked_fields for report in reports] == [("EVN-2", "OBX-5")]


@pytest.mark.parametrize("checked", _CHECKED, ids=("engine", "tee"))
def test_the_coverage_report_is_empty_when_nothing_was_emptied(
    checked: Callable[..., str],
) -> None:
    reports: list[Any] = []
    checked(_site_message("EVN|A01|20260315"), salt=_SALT, on_report=reports.append)
    assert [report.blanked_fields for report in reports] == [()]


@pytest.mark.parametrize(
    ("checked", "leak"),
    ((engine_anonymize_checked, engine_leak), (tee_anonymize_checked, tee_leak)),
    ids=("engine", "tee"),
)
def test_the_run_summary_counts_emptied_date_fields_and_never_shows_a_value(
    checked: Callable[..., str], leak: Any
) -> None:
    tally = leak.CoverageTally()
    quiet = tally.summary()
    for _ in range(2):
        checked(_site_message("EVN|A01|" + _NOT_A_DATE), salt=_SALT, on_report=tally.add)
    checked(_site_message("EVN|A01|20260315"), salt=_SALT, on_report=tally.add)
    summary = tally.summary()
    assert (
        "Date fields emptied because the value was not a timestamp it could keep: EVN-2 x2."
        in summary
    )
    assert _NOT_A_DATE not in summary
    assert "emptied" not in quiet  # no sentence at all when nothing was emptied


@pytest.mark.parametrize("leak", (engine_leak, tee_leak), ids=("engine", "tee"))
def test_a_bare_leak_report_cannot_know_what_was_emptied(leak: Any) -> None:
    """The report is built from the output, where an emptied field looks like an absent one. Only
    ``anonymize_checked`` can fill ``blanked_fields``, and this pins that the field says so."""
    report = leak.leak_report(_site_message("EVN|A01|"), rules=engine_rules.DEFAULT_RULES)
    assert report.blanked_fields == ()


# --- item 6: a six-digit date that reads two ways -------------------------------------------------

# EVN-2 value -> what the DATE kind must write.
_SIX_DIGIT_CASES = {
    # July 2011, or 7 November 2020. Kept, the output would show the second reading's month.
    "reads as YYYYMM and as YYMMDD": ("201107", ""),
    "the same with an offset": ("201107+0500", ""),
    "the same with a precision code": ("201107^L", ""),
    # The accepted cost: a true year and month whose year ends in 01 to 12.
    "a true YYYYMM that also fits": ("200803", ""),
    # Not a YYMMDD: 26 is no month, so only one reading exists and the year is kept.
    "only a YYYYMM": ("202603", "202601"),
    "a year ending in 00": ("200011", "200001"),
    "a year ending in 13": ("201311", "201301"),
    # Eight digits and four digits are not ambiguous in this way.
    "a full date in an ambiguous year": ("20110703", "20110101"),
    "a bare year": ("2011", "2011"),
}


@pytest.mark.parametrize("case", sorted(_SIX_DIGIT_CASES))
@_EACH_ADAPTER
def test_a_six_digit_date_with_two_readings_is_emptied(
    adapter: Callable[..., str], case: str
) -> None:
    value, expected = _SIX_DIGIT_CASES[case]
    blanked: list[str] = []
    out = adapter(_site_message("EVN|A01|" + value + "|x"), salt=_SALT, blanked=blanked)
    assert _field_of(out, "EVN-2") == expected
    assert blanked == ([] if expected else ["EVN-2"])


# --- found by the QA pass on this branch ----------------------------------------------------------

# GT1-8 value -> what must NOT survive, and whether the time after the date is kept.
_DOB_TAILS = {
    "an SSN after the date": ("19570412 123-45-6789", "123-45-6789", ""),
    "a name after the date": ("19570412^ROE^JANE", "ROE", ""),
    "a US date": ("03/15/1957", "57", ""),
    "a time and an offset": ("19570412083000-0500", "19570412", "083000-0500"),
}


@pytest.mark.parametrize("case", sorted(_DOB_TAILS))
@_EACH_ADAPTER
def test_a_date_of_birth_keeps_only_a_time_after_the_date(
    adapter: Callable[..., str], case: str
) -> None:
    """GT1-8 used to be unmapped, so the leak-check scanned it. Mapped, it is not scanned, so the
    DOB kind must not carry text through."""
    value, gone, kept_tail = _DOB_TAILS[case]
    out = _field_of(adapter(_site_message(_seg("GT1", f1="1", f8=value)), salt=_SALT), "GT1-8")
    assert len(out) == 8 + len(kept_tail) and out[:8].isdigit() and out.endswith(kept_tail)
    assert gone not in out[:8] and (kept_tail or gone not in out)


@_EACH_ADAPTER
def test_a_plus_sign_as_the_repetition_separator_does_not_break_the_record(
    adapter: Callable[..., str],
) -> None:
    """The filled offset is +0000. Where the message declares + as its repetition separator, the
    output holds more repetitions than the input, and the record must not be worked out from it."""
    message = (
        "MSH|^+\\&|SAPP|SFAC|RAPP|RFAC|20260315142233||ADT^A01|MSGCTRL|P|2.5.1"
        "\rEVN|A01|20260315120000-0500"
    )
    blanked: list[str] = []
    out = adapter(message, salt=_SALT, blanked=blanked)
    assert _field_of(out, "EVN-2") == "20260101000000+0000"
    assert blanked == []
