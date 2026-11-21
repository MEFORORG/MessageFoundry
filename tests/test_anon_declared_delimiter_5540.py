# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A surrogate value that holds a delimiter the message's own MSH-2 declares is refused by BOTH
adapters (vault BACKLOG #5540, #5533 item 13).

Under a custom MSH-2, a value a surrogate writes itself can hold the component, repetition or
subcomponent separator or the escape character: every street in the address pool holds a space,
the free-text redaction writes ``[`` and ``]``, and a date's or a date of birth's offset is filled
as ``+0000``. Joined back, such a value restructures the field: it gains a
component, a repetition or a subcomponent, or opens an escape sequence, so every later component
moves for any reader of the output. Both adapters emitted it. They now refuse, body-free, naming
the rule.

The drift probe of ``tests/test_tee_anon_field_separator.py`` read the default delimiters only;
the probe here reads each message's own MSH-1 and MSH-2 too.

Every value here is synthetic.
"""

from __future__ import annotations

from types import ModuleType

import pytest

import messagefoundry_toolkit.anon as engine_anon
import tee.anon as tee_anon
from messagefoundry.parsing.message import Message
from messagefoundry_toolkit.anon import hl7 as engine_hl7
from messagefoundry_toolkit.anon import surrogates as engine_surrogates
from messagefoundry_toolkit.anon.keying import Keyer
from messagefoundry_toolkit.anon.rules import FieldRule, SurrogateKind
from tee.anon import hl7 as tee_hl7
from tee.anon import rules as tee_rules
from tee.anon import surrogates as tee_surrogates
from tee.anon.keying import Keyer as TeeKeyer

_SALT = "b214-5540-delim-salt-0123456789abcdef"
#: A value in a field no rule rewrites, after the scrubbed one, so a moved field would show.
_MARK = "AFTERMARK"

_SIDES = pytest.mark.parametrize("anon", [engine_anon, tee_anon], ids=["engine", "tee"])


def _message(encoding: str, seg_id: str, fields: dict[int, str]) -> str:
    """A ``|`` header declaring ``encoding`` as MSH-2, and one ``seg_id`` line."""
    header = "|".join(
        ("MSH", encoding, "APP", "FAC", "RCV", "RFAC", "20260101", "", "ADT", "M1", "P", "2.5.1")
    )
    line = "|".join([seg_id, *(fields.get(n, "") for n in range(1, max(fields) + 1))])
    return f"{header}\r{line}"


#: (MSH-2, segment, fields, the rule's field, the role the refusal names, the input value).
_CASES = {
    # Every street in the address pool holds a space, here the component separator.
    "address-component-space": (
        " ~\\&",
        "PID",
        {1: "1", 11: "12MAIN", 15: _MARK},
        "PID-11",
        "component separator",
        "12MAIN",
    ),
    # The free-text redaction ``[REDACTED]`` holds ``[``, here the escape character.
    "freetext-escape-bracket": (
        "^~[&",
        "NTE",
        {1: "1", 3: "SOME NOTE", 4: _MARK},
        "NTE-3",
        "escape character",
        "SOME NOTE",
    ),
    # A date of birth's offset is filled as ``+0000``, here holding the repetition separator.
    "dob-offset-repetition-plus": (
        "^+\\&",
        "PID",
        {1: "1", 7: "19800315-0500", 8: _MARK},
        "PID-7",
        "repetition separator",
        "19800315",
    ),
    # A date's offset is filled as ``+0000`` too, here holding the subcomponent separator.
    "date-offset-subcomponent-plus": (
        "^~\\+",
        "PID",
        {1: "1", 29: "20260315142233-0500", 30: _MARK},
        "PID-29",
        "subcomponent separator",
        "0315142233",
    ),
}
_EACH_CASE = pytest.mark.parametrize("case", sorted(_CASES))


@_SIDES
@_EACH_CASE
def test_a_surrogate_holding_a_declared_delimiter_is_refused(anon: ModuleType, case: str) -> None:
    encoding, seg_id, fields, path, role, needle = _CASES[case]
    with pytest.raises(anon.AnonError) as caught:
        anon.anonymize(_message(encoding, seg_id, fields), salt=_SALT)
    reason = str(caught.value)
    assert f"the surrogate for {path} would hold the {role} the message declares" in reason
    # Body-free: the refusal names neither the input value nor anything after it.
    assert needle not in reason
    assert _MARK not in reason


@_EACH_CASE
def test_both_adapters_raise_the_same_refusal_naming_the_rule(case: str) -> None:
    """Called directly, each adapter raises the one shared refusal, with the rule's address."""
    encoding, seg_id, fields, path, _, _ = _CASES[case]
    message = _message(encoding, seg_id, fields)
    for adapter, rules, keyer in (
        (engine_hl7, engine_anon.DEFAULT_RULES, Keyer(_SALT)),
        (tee_hl7, tee_anon.DEFAULT_RULES, TeeKeyer(_SALT)),
    ):
        refused = (
            engine_surrogates.SurrogateSeparatorRefused
            if adapter is engine_hl7
            else tee_surrogates.SurrogateSeparatorRefused
        )
        live = tuple(r for r in rules if r.kind != SurrogateKind.KEEP)
        with pytest.raises(refused) as caught:
            adapter.anonymize_message(message, keyer, live)
        assert getattr(caught.value, "path", None) == path


@_EACH_CASE
def test_the_same_values_under_the_default_encoding_agree_on_both_sides(case: str) -> None:
    """The positive control: under ``^~\\&`` no surrogate holds a delimiter, both adapters emit
    the same output, and the field after the rule is still in its place."""
    _, seg_id, fields, _, _, _ = _CASES[case]
    message = _message("^~\\&", seg_id, fields)
    engine_out = engine_anon.anonymize(message, salt=_SALT)
    assert engine_out == tee_anon.anonymize(message, salt=_SALT)
    mark_at = next(n for n, value in fields.items() if value == _MARK)
    assert engine_out.split("\r")[1].split("|")[mark_at] == _MARK


def test_a_custom_encoding_no_surrogate_writes_agrees_on_both_sides() -> None:
    """A custom MSH-2 alone is not refused: under ``*%$#`` no pool value, fill or constant holds
    a declared delimiter, so a full patient line comes out the same on both sides."""
    message = _message(
        "*%$#",
        "PID",
        {1: "1", 3: "12345***H*MR", 5: "DOE*JANE", 7: "19800315-0500", 11: "1 ST**T*S*1", 13: "1"},
    )
    engine_out = engine_anon.anonymize(message, salt=_SALT)
    assert engine_out == tee_anon.anonymize(message, salt=_SALT)
    assert "DOE" not in engine_out and "12345" not in engine_out


@_SIDES
@pytest.mark.parametrize(
    "fields",
    [{1: "1", 7: "19800315", 8: _MARK}, {1: "1", 13: "2025550100", 15: _MARK}],
    ids=["dob", "phone"],
)
def test_a_digit_delimiter_refuses_under_every_salt(
    anon: ModuleType, fields: dict[int, str]
) -> None:
    """Under a digit escape character, what a phone or date-of-birth surrogate COULD write is
    judged, not the digits one salt drew, so the refusal does not depend on the secret salt."""
    message = _message("^~5&", "PID", fields)
    path = "PID-7" if 7 in fields else "PID-13"
    for n in range(8):
        with pytest.raises(anon.AnonError, match=f"{path} would hold the escape character"):
            anon.anonymize(message, salt=f"{_SALT}-{n}")


@pytest.mark.parametrize("surrogates", [engine_surrogates, tee_surrogates], ids=["engine", "tee"])
@pytest.mark.parametrize(
    ("encoding", "year"),
    [("^~1&", "2010"), ("^~\\0", "2026")],
    ids=["digit-escape", "digit-subcomponent"],
)
def test_a_dates_year_is_the_senders_and_is_not_checked(
    surrogates: ModuleType, encoding: str, year: str
) -> None:
    """A bare year is copied from the sender, so a declared delimiter in it is no reason to
    refuse; only the fill and offset are written. The control: a month and day the fill writes
    as ``0101`` hold the same delimiter, and are refused."""
    component, repetition, escape, subcomponent = tuple(encoding)
    seps = surrogates.Seps(component, repetition, subcomponent, escape)
    kept = surrogates.surrogate_field_recorded(
        "PID-29", SurrogateKind.DATE, year, Keyer(_SALT), seps, None
    )
    assert kept == year
    with pytest.raises(surrogates.SurrogateSeparatorRefused):
        surrogates.surrogate_field_recorded(
            "PID-29", SurrogateKind.DATE, f"{year}0315", Keyer(_SALT), seps, None
        )


@pytest.mark.parametrize("field_sep", ["|", "+", "#", "[", " "])
@pytest.mark.parametrize("path", ["MSH-1", "MSH-2"])
def test_a_keep_on_a_delimiter_field_agrees_on_both_sides(field_sep: str, path: str) -> None:
    """A keep on MSH-1 or MSH-2 rewrites nothing (BACKLOG #2265), so in a direct call both
    adapters emit the message as it came, under the default MSH-1 and custom ones alike. The
    engine adapter once refused it while the tee emitted it."""
    header = field_sep.join(
        ("MSH", "^~\\&", "A", "B", "C", "D", "20260101", "", "ADT^A01", "M1", "P", "2.5.1")
    )
    message = f"{header}\r{field_sep.join(('PID', '1', '', '9^^^H^MR', '', 'X^Y'))}"
    engine_out = engine_hl7.anonymize_message(
        message, Keyer(_SALT), (FieldRule(path, SurrogateKind.KEEP),)
    )
    tee_out = tee_hl7.anonymize_message(
        message, TeeKeyer(_SALT), (tee_rules.FieldRule(path, tee_rules.SurrogateKind.KEEP),)
    )
    assert engine_out == tee_out == message


#: Headers whose MSH-1 and MSH-2 are not the defaults, for the drift probe below.
_PROBE_HEADERS = ("MSH|^~\\&|A|B", "MSH#*%$&#A#B", "MSH+^~\\&+A+B", "MSH!@ ?.!A!B", "MSH|5~\\&|A|B")


def _probe_chars(header: str) -> list[str]:
    """Every C0 byte, DEL, the default delimiters, and this header's own MSH-1 and MSH-2."""
    own = header[3:8]
    chars = [chr(n) for n in (*range(0x20), 0x7F)] + list("|^~\\&") + list(own)
    return list(dict.fromkeys(chars))


@pytest.mark.parametrize(
    ("header", "char"),
    [(header, char) for header in _PROBE_HEADERS for char in _probe_chars(header)],
)
def test_the_guard_refuses_what_the_engine_refuses_under_the_message_delimiters(
    header: str, char: str
) -> None:
    """The tee keeps a copy of the engine's whole-field refusal, so this probes both with every C0
    byte, DEL, each default delimiter and each delimiter the probed header declares, under that
    header's own field separator. A character refused on one side alone would be a new
    divergence."""
    field_sep = header[3]
    msg = Message.parse(f"{header}\rPID{field_sep}1")
    value = f"A{char}1"
    try:
        msg.set("PID-3", value)
        engine_refuses = False
    except ValueError:
        engine_refuses = True
    try:
        tee_hl7._whole_field("PID-3", value, field_sep)
        tee_refuses = False
    except tee_anon.AnonError:
        tee_refuses = True
    assert tee_refuses == engine_refuses
    # The control: the header's own field separator is refused on both sides.
    if char == field_sep:
        assert tee_refuses


@_SIDES
@pytest.mark.parametrize("encoding", ["^~-&", "-~\\&", "^~\\-"], ids=["escape", "component", "sub"])
def test_a_phones_written_dashes_are_checked(anon: ModuleType, encoding: str) -> None:
    """A dashed phone is written ``NNN-NNN-NNNN`` whatever the sender's dash places, so a dash the
    message declares is refused rather than emitted as a new escape sequence or component."""
    message = _message(encoding, "PID", {1: "1", 13: "555-1234", 15: _MARK})
    with pytest.raises(anon.AnonError, match="PID-13 would hold the"):
        anon.anonymize(message, salt=_SALT)


@_SIDES
def test_a_field_separator_a_pool_could_write_refuses_under_every_salt(anon: ModuleType) -> None:
    """Under MSH-1 ``Z``, some names in the pool hold a ``Z``: the whole pool is judged, so both
    adapters refuse under every salt, with the one shared refusal naming the rule."""
    header = "Z".join(
        ("MSH", "^~\\&", "APP", "FAC", "RCV", "RFAC", "20260101", "", "ADT^A01", "M1", "P", "2.5.1")
    )
    message = f"{header}\rPIDZ1ZZZZDOE^JANE"
    surrogates = engine_surrogates if anon is engine_anon else tee_surrogates
    for n in range(8):
        with pytest.raises(
            surrogates.SurrogateSeparatorRefused, match="PID-5 would hold the field"
        ):
            anon.anonymize(message, salt=f"{_SALT}-{n}")
