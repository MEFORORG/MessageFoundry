# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A surrogate that holds the message's own field separator is refused by BOTH adapters (vault
BACKLOG #5540).

Under a custom MSH-1, a surrogate value can hold the field separator: the date fill writes ``+``,
the free-text redaction writes ``[`` and ``]``, and every street in the address pool holds a space.
The engine adapter writes through ``Message.set``, which refuses a whole-field value holding the
field separator, so it refused these messages. The tee adapter joined the value back on the
separator and emitted it, which added fields and renumbered every later field for any reader of the
output, the leak-check included. These tests pin that the two now agree.

Every value here is synthetic.
"""

from __future__ import annotations

from types import ModuleType

import pytest

import messagefoundry_toolkit.anon as engine_anon
import tee.anon as tee_anon
from tee.anon import hl7 as tee_hl7
from tee.anon.keying import Keyer

_SALT = "b214-5540-salt-0123456789abcdef"
#: A value after the scrubbed field that no rule rewrites, so a shifted field would be visible.
_MARK = "AFTERMARK"

_SIDES = pytest.mark.parametrize("anon", [engine_anon, tee_anon], ids=["engine", "tee"])


def _header(sep: str) -> str:
    return sep.join(
        ("MSH", "^~\\&", "APP", "FAC", "RCV", "RFAC", "20260101120000", "", "ADT^A01", "M1", "P")
    ) + (sep + "2.5.1")


def _pid(sep: str, fields: dict[int, str]) -> str:
    """A PID line under ``sep`` with ``fields`` set by field number, every other field empty."""
    width = max(fields)
    return sep.join(["PID", *(fields.get(n, "") for n in range(1, width + 1))])


#: (separator, a line whose rule writes that separator into its surrogate, the input value).
_CASES = {
    # PID-7 under the dob rule: a timestamp offset is filled as ``+0000``.
    "date-offset-plus": ("+", lambda s: _pid(s, {1: "1", 7: "19800315-0500", 8: _MARK})),
    # NTE-3 under the free-text rule: the redaction constant holds ``[`` and ``]``.
    "freetext-bracket": ("[", lambda s: s.join(("NTE", "1", "", "some note", _MARK))),
    # PID-11 under the address rule: every street in the pool holds a space.
    "address-space": (" ", lambda s: _pid(s, {1: "1", 11: "1 MAIN^^TOWN^ST^12345", 15: _MARK})),
}


def _message(case: str) -> str:
    sep, line = _CASES[case]
    return "\r".join((_header(sep), line(sep)))


@_SIDES
@pytest.mark.parametrize("case", sorted(_CASES))
def test_a_surrogate_holding_the_field_separator_is_refused(anon: ModuleType, case: str) -> None:
    with pytest.raises(anon.AnonError) as caught:
        anon.anonymize(_message(case), salt=_SALT)
    # Body-free: the refusal names neither the input value nor anything after it.
    assert _MARK not in str(caught.value)
    assert "19800315" not in str(caught.value)
    assert "MAIN" not in str(caught.value)


@pytest.mark.parametrize("case", sorted(_CASES))
def test_the_tee_refusal_names_the_rule_and_not_the_value(case: str) -> None:
    """Called directly, the tee adapter names the rule whose surrogate it refused."""
    rules = tuple(r for r in tee_anon.DEFAULT_RULES if r.kind != tee_anon.SurrogateKind.KEEP)
    with pytest.raises(tee_anon.AnonError, match=r"the surrogate for (PID-7|NTE-3|PID-11) would"):
        tee_hl7.anonymize_message(_message(case), Keyer(_SALT), rules)


@pytest.mark.parametrize("case", sorted(_CASES))
def test_the_same_values_under_a_pipe_agree_on_both_sides(case: str) -> None:
    """The positive control: under ``|`` no surrogate holds the separator, and both adapters emit
    the same output, with the unscrubbed field after the rule still in its place."""
    _, line = _CASES[case]
    message = "\r".join((_header("|"), line("|")))
    engine_out = engine_anon.anonymize(message, salt=_SALT)
    assert engine_out == tee_anon.anonymize(message, salt=_SALT)
    assert f"|{_MARK}" in engine_out


@pytest.mark.parametrize("value", ["A\r1", "A\n1", "A+1"])
def test_the_guard_refuses_each_structure_character(value: str) -> None:
    """CR and LF cannot reach a surrogate today, since the message is split on them first; the guard
    refuses them anyway, as the engine's ``Message.set`` does."""
    with pytest.raises(tee_anon.AnonError):
        tee_hl7._whole_field("PID-3", value, "+")
    assert tee_hl7._whole_field("PID-3", "A^1", "|") == "A^1"
