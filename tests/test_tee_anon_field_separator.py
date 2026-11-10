# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A surrogate that holds the message's own field separator is refused by BOTH adapters (vault
BACKLOG #5540).

Under a custom MSH-1, a surrogate value can hold the field separator: the date fill writes ``+``,
the free-text redaction writes ``[`` and ``]``, and every street in the address pool holds a space.
The engine adapter writes through ``Message.set``, which refuses a whole-field value holding the
field separator, so it refused these messages. The tee adapter joined the value back on the
separator and emitted it, which would add fields and renumber every later field for any reader of
the output, the leak-check included. These tests pin that the two now agree.

Every value here is synthetic.
"""

from __future__ import annotations

from types import ModuleType

import pytest

import messagefoundry_toolkit.anon as engine_anon
import tee.anon as tee_anon
from messagefoundry.parsing.message import _STRUCTURE_REFUSED
from tee.anon import hl7 as tee_hl7
from tee.anon.keying import Keyer

_SALT = "b214-5540-salt-0123456789abcdef"
#: A value in a field no rule rewrites, after the scrubbed one, so a shifted field would show.
_MARK = "AFTERMARK"

_SIDES = pytest.mark.parametrize("anon", [engine_anon, tee_anon], ids=["engine", "tee"])


def _message(sep: str, seg_id: str, fields: dict[int, str]) -> str:
    """A header and one ``seg_id`` line under ``sep``, with ``fields`` set by field number."""
    header = sep.join(
        ("MSH", "^~\\&", "APP", "FAC", "RCV", "RFAC", "20260101", "", "ADT^A01", "M1", "P", "2.5.1")
    )
    line = sep.join([seg_id, *(fields.get(n, "") for n in range(1, max(fields) + 1))])
    return f"{header}\r{line}"


#: (separator, segment, fields, the rule that writes the separator, the input value it scrubs).
_CASES = {
    # PID-7 under the dob rule: a timestamp offset is filled as ``+0000``.
    "date-offset-plus": ("+", "PID", {1: "1", 7: "19800315-0500", 8: _MARK}, "PID-7", "19800315"),
    # NTE-3 under the free-text rule: the redaction constant holds ``[`` and ``]``.
    "freetext-bracket": ("[", "NTE", {1: "1", 3: "some note", 4: _MARK}, "NTE-3", "some note"),
    # PID-11 under the address rule: every street in the pool holds a space. The input holds none,
    # since the line is split on it.
    "address-space": (" ", "PID", {1: "1", 11: "12MAIN^^TOWN^ST^1", 15: _MARK}, "PID-11", "MAIN"),
}
_EACH_CASE = pytest.mark.parametrize("case", sorted(_CASES))


@_SIDES
@_EACH_CASE
def test_a_surrogate_holding_the_field_separator_is_refused(anon: ModuleType, case: str) -> None:
    sep, seg_id, fields, _, needle = _CASES[case]
    with pytest.raises(anon.AnonError) as caught:
        anon.anonymize(_message(sep, seg_id, fields), salt=_SALT)
    # The refusal is the field-separator check, not an earlier parse failure on an unusual MSH-1.
    # The engine adapter relabels ``Message.set``'s ValueError, so its reason is the cause.
    assert "field separator" in str(caught.value.__cause__ or caught.value)
    # Body-free: the refusal names neither the input value nor anything after it.
    assert needle not in str(caught.value)
    assert _MARK not in str(caught.value)


@_EACH_CASE
def test_the_tee_refusal_names_the_rule(case: str) -> None:
    """Called directly, the tee adapter names the rule whose surrogate it refused."""
    sep, seg_id, fields, path, _ = _CASES[case]
    rules = tuple(r for r in tee_anon.DEFAULT_RULES if r.kind != tee_anon.SurrogateKind.KEEP)
    with pytest.raises(tee_anon.AnonError, match=f"the surrogate for {path} would"):
        tee_hl7.anonymize_message(_message(sep, seg_id, fields), Keyer(_SALT), rules)


@_EACH_CASE
def test_the_same_values_under_a_pipe_agree_on_both_sides(case: str) -> None:
    """The positive control: under ``|`` no surrogate holds the separator, and both adapters emit
    the same output, with the unscrubbed field after the rule still in its place."""
    _, seg_id, fields, _, _ = _CASES[case]
    message = _message("|", seg_id, fields)
    engine_out = engine_anon.anonymize(message, salt=_SALT)
    assert engine_out == tee_anon.anonymize(message, salt=_SALT)
    mark_at = next(n for n, value in fields.items() if value == _MARK)
    assert engine_out.split("\r")[1].split("|")[mark_at] == _MARK


@pytest.mark.parametrize("value", ["A\r1", "A\n1", "A+1", "A\x0b1", "A\x1c1", "A\x001"])
def test_the_guard_refuses_each_structure_character(value: str) -> None:
    """CR, LF and the two MLLP frame bytes cannot reach a surrogate today, since the message is split
    on the first two and stripped of the others first; the guard refuses them anyway, as the
    engine's ``Message.set`` does."""
    with pytest.raises(tee_anon.AnonError):
        tee_hl7._whole_field("PID-3", value, "+")


def test_the_guard_refuses_what_the_engine_refuses() -> None:
    """The tee cannot import the engine's list, so it keeps a copy; this pins the two equal. A byte
    added to one side alone would be a new divergence."""
    assert set(tee_hl7._REFUSED_IN_FIELD) == {"\r", "\n", *_STRUCTURE_REFUSED}


def test_the_guard_passes_a_value_with_no_structure_character() -> None:
    assert tee_hl7._whole_field("PID-3", "A^1\x07", "|") == "A^1\x07"


@_SIDES
def test_a_nul_kept_by_an_identifier_surrogate_is_refused(anon: ModuleType) -> None:
    """The identifier kinds keep every character that is not a letter or digit, NUL included. The
    engine's ``Message.set`` refuses NUL in a whole-field write, so the tee must too."""
    message = _message("|", "PID", {1: "1", 3: "A12\x0034^^^H^MR", 8: _MARK})
    with pytest.raises(anon.AnonError) as caught:
        anon.anonymize(message, salt=_SALT)
    assert "A12" not in str(caught.value)
    assert _MARK not in str(caught.value)


@pytest.mark.parametrize(
    ("fields", "why"),
    [
        ({1: "1", 3: "A12\x0734^^^H^MR"}, "a control byte the engine passes, in a ruled field"),
        ({1: "1", 8: "F\x00M"}, "NUL in a field no rule rewrites"),
    ],
)
def test_what_the_engine_passes_the_tee_passes_too(fields: dict[int, str], why: str) -> None:
    """The refusal is no wider than the engine's: a value the engine adapter emits, the tee emits
    the same way. A tee-only refusal here would be a new divergence."""
    message = _message("|", "PID", fields)
    assert engine_anon.anonymize(message, salt=_SALT) == tee_anon.anonymize(message, salt=_SALT), (
        why
    )
