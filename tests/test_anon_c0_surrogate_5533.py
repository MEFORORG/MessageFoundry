# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A C0 control byte in a field a surrogate rule writes is refused by BOTH adapters (vault BACKLOG
#5533 item 14, which closes #5540; decision d20261121T180600851-e821ef).

The identifier kinds copy every character of the sender's value that is not a letter or digit, so
a BEL, an ESC or a TAB in a captured identifier reached the output. Of the C0 bytes the message
does not declare as a delimiter, the engine adapter's whole-field ``Message.set`` refuses only CR,
LF, the two MLLP frame bytes and NUL, and the tee copied that set, so both emitted the rest. Both
now refuse a C0 byte the message does not declare, TAB included, in a field a surrogate rule
writes, with the same :class:`SurrogateSeparatorRefused` naming the rule and never the value. A
``keep`` writes nothing, so a field it keeps is not checked. DEL (0x7F) is not a C0 byte and the
decision does not name it.

Every value here is synthetic.
"""

from __future__ import annotations

from types import ModuleType

import pytest

import messagefoundry_toolkit.anon as engine_anon
import tee.anon as tee_anon
from messagefoundry_toolkit.anon import hl7 as engine_hl7
from messagefoundry_toolkit.anon import surrogates as engine_surrogates
from tee.anon import hl7 as tee_hl7
from tee.anon import surrogates as tee_surrogates

_SALT = "b5533-c0-salt-0123456789abcdef-0123456789"
#: A value in a field no rule rewrites, after the scrubbed one, so a leaked body would show.
_MARK = "AFTERMARK"
#: The sender's identifier digits, so a refusal that quotes the value would show.
_NEEDLE = "Q77"

_SIDES = pytest.mark.parametrize(
    ("anon", "refused"),
    [
        (engine_anon, engine_surrogates.SurrogateSeparatorRefused),
        (tee_anon, tee_surrogates.SurrogateSeparatorRefused),
    ],
    ids=["engine", "tee"],
)

#: Every C0 byte a captured field can still hold once ``normalized_message`` has run: CR and LF
#: split the message into lines, and the two MLLP frame bytes are stripped.
_REACHABLE_C0 = [chr(n) for n in range(0x20) if chr(n) not in "\r\n\x0b\x1c"]


def _message(pid3: str) -> str:
    header = "|".join(
        ("MSH", "^~\\&", "APP", "FAC", "RCV", "RFAC", "20260101", "", "ADT^A01", "M1", "P", "2.5.1")
    )
    return f"{header}\rPID|1||{pid3}|||||{_MARK}"


@_SIDES
@pytest.mark.parametrize("char", _REACHABLE_C0, ids=lambda c: f"U+{ord(c):04X}")
def test_a_c0_byte_an_identifier_surrogate_copies_is_refused(
    anon: ModuleType, refused: type[Exception], char: str
) -> None:
    with pytest.raises(refused, match="the surrogate for PID-3 would hold") as caught:
        anon.anonymize(_message(f"{_NEEDLE}{char}34^^^H^MR"), salt=_SALT)
    assert _NEEDLE not in str(caught.value)
    assert _MARK not in str(caught.value)


@_SIDES
def test_a_tab_kept_inside_an_identifier_component_is_refused(
    anon: ModuleType, refused: type[Exception]
) -> None:
    """The identifier kinds keep the assigning authority (CX.4) as the sender wrote it, so a TAB
    there is sender text the rule wrote back; the whole field is checked, not only what the
    surrogate fabricated."""
    with pytest.raises(refused, match="PID-3"):
        anon.anonymize(_message(f"{_NEEDLE}34^^^HOSP\tA^MR"), salt=_SALT)


@pytest.mark.parametrize("char", ["\x07", "\t", "\x1b"], ids=["BEL", "TAB", "ESC"])
def test_a_field_a_keep_rule_leaves_is_not_checked(char: str) -> None:
    """``anonymize`` drops a keep rule before either adapter runs, so no rule writes the field and
    a control byte in it passes on both adapters, the same way."""
    rules_engine = (engine_anon.FieldRule("PID-3", engine_anon.SurrogateKind.KEEP),)
    rules_tee = (tee_anon.FieldRule("PID-3", tee_anon.SurrogateKind.KEEP),)
    message = _message(f"{_NEEDLE}{char}34^^^H^MR")
    engine_out = engine_anon.anonymize(message, salt=_SALT, rules=rules_engine)
    assert engine_out == tee_anon.anonymize(message, salt=_SALT, rules=rules_tee)
    assert f"{_NEEDLE}{char}34" in engine_out


@pytest.mark.parametrize("char", ["\x07", "\t"], ids=["BEL", "TAB"])
def test_a_keep_rule_passed_straight_to_an_adapter_is_not_checked(char: str) -> None:
    """Each adapter's ``anonymize_message`` takes keep rules too. A keep writes nothing, so the
    field it keeps passes, as on origin/main, on both adapters alike."""
    message = _message(f"{_NEEDLE}{char}34^^^H^MR")
    engine_keep = (engine_anon.FieldRule("PID-3", engine_anon.SurrogateKind.KEEP),)
    tee_keep = (tee_anon.FieldRule("PID-3", tee_anon.SurrogateKind.KEEP),)
    outs = [
        engine_hl7.anonymize_message(message, engine_anon.Keyer(_SALT), engine_keep),
        tee_hl7.anonymize_message(message, tee_anon.Keyer(_SALT), tee_keep),
    ]
    assert outs[0] == outs[1]
    assert f"{_NEEDLE}{char}34" in outs[0]


@pytest.mark.parametrize("encoding", ["\x1f~\\&", "\t~\\&", "^\x1e\\&"], ids=["US", "TAB", "RS"])
def test_a_control_character_the_message_declares_as_a_delimiter_is_not_refused(
    encoding: str,
) -> None:
    """A delimiter MSH-2 declares is the field's structure, so an identifier rule writing its
    components under a control-character component or repetition separator is not refused, and
    both adapters emit it alike. A C0 byte the message does not declare is still refused."""
    header = "|".join(
        ("MSH", encoding, "APP", "FAC", "RCV", "RFAC", "20260101", "", "ADT", "M1", "P", "2.5.1")
    )
    comp, rep = encoding[0], encoding[1]
    cx = f"34{comp}{comp}{comp}H{comp}MR"
    message = f"{header}\rPID|1||{_NEEDLE}{cx}{rep}Q78{cx}|||||{_MARK}"
    engine_out = engine_anon.anonymize(message, salt=_SALT)
    assert engine_out == tee_anon.anonymize(message, salt=_SALT)
    assert _MARK in engine_out
    stray = f"{header}\rPID|1||{_NEEDLE}\x0734{comp}{comp}{comp}H{comp}MR|||||{_MARK}"
    for anon in (engine_anon, tee_anon):
        with pytest.raises(anon.AnonError, match="C0 control character"):
            anon.anonymize(stray, salt=_SALT)


@pytest.mark.parametrize("char", ["\t", "\x0c", "\x1f"], ids=["TAB", "FF", "US"])
def test_a_control_byte_ending_the_message_is_a_known_difference(char: str) -> None:
    """The engine's parser trims white space after the last field of the last line before a rule
    reads it, and the tee does not (``docs/PHI.md`` section 9 lists the difference). So a TAB
    ending the message in the CX.5 an identifier rule keeps is emitted without it by the engine
    and refused by the tee. Both fail closed on the byte: neither emits it."""
    message = _message(f"{_NEEDLE}34^^^H^MR").split("|||||")[0] + char
    assert char not in engine_anon.anonymize(message, salt=_SALT)
    with pytest.raises(tee_surrogates.SurrogateSeparatorRefused, match="C0 control character"):
        tee_anon.anonymize(message, salt=_SALT)


def test_del_is_not_refused_and_both_sides_agree() -> None:
    """DEL is outside the C0 range the decision names, so both adapters still emit it alike."""
    message = _message(f"{_NEEDLE}\x7f34^^^H^MR")
    engine_out = engine_anon.anonymize(message, salt=_SALT)
    assert engine_out == tee_anon.anonymize(message, salt=_SALT)
    assert "\x7f" in engine_out


@pytest.mark.parametrize("char", [chr(n) for n in range(0x80)], ids=lambda c: f"U+{ord(c):04X}")
def test_both_adapters_refuse_the_same_bytes_in_a_ruled_field(char: str) -> None:
    """Every ASCII byte in a ruled identifier: the two adapters refuse alike, with the same class
    and cause, or emit the same output. A byte refused on one side alone would be a new
    divergence."""
    message = _message(f"{_NEEDLE}{char}34^^^H^MR")
    outcomes = []
    for anon in (engine_anon, tee_anon):
        try:
            outcomes.append(("emitted", anon.anonymize(message, salt=_SALT)))
        except anon.AnonError as exc:
            outcomes.append((type(exc).__name__, str(exc)))
    assert outcomes[0] == outcomes[1]
