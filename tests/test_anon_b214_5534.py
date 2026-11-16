# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Identifier surrogates leave no residue of the real id (BACKLOG #5534).

The identifier kinds fabricated component 1 and joined every other component back as captured, and
they kept a non-ASCII letter of the id as it was. So a check digit, the CX.7 and CX.8 dates, and a
driver's licence state and expiry survived inside a field the rule map reported as scrubbed, and
nothing scans a mapped field. Now a CX keeps only the components that name its issuer (CX.3 to
CX.6, CX.9 and CX.10), a driver's licence keeps only its state, and every letter of the id is
fabricated as ASCII. The leak-check scans a kept component only for a dashed SSN and a punctuated
phone (``tests/test_anon_b214_kept_components.py``), so for every other residue these tests are
the only check.

Every value here is synthetic.
"""

from __future__ import annotations

from types import ModuleType

import pytest

import messagefoundry_toolkit.anon as engine_anon
import tee.anon as tee_anon
from messagefoundry_toolkit.anon import keying as engine_keying
from messagefoundry_toolkit.anon import surrogates as engine_surrogates
from tee.anon import keying as tee_keying
from tee.anon import surrogates as tee_surrogates

_SALT = "b214-5534-salt-0123456789abcdef"
_MODULES = pytest.mark.parametrize(
    ("surrogates", "keying"),
    [(engine_surrogates, engine_keying), (tee_surrogates, tee_keying)],
    ids=["engine", "tee"],
)


def _call(surrogates: ModuleType, keying: ModuleType, name: str, rep: str) -> str:
    out: str = getattr(surrogates, name)(rep, keying.Keyer(_SALT), surrogates.Seps())
    return out


@_MODULES
@pytest.mark.parametrize("name", ["surrogate_mrn", "surrogate_id", "surrogate_dln"])
@pytest.mark.parametrize("real_id", ["MÜLLER12345", "ЖЖ123", "ABçé-9"])
def test_every_letter_of_the_id_is_fabricated_as_ascii(
    surrogates: ModuleType, keying: ModuleType, name: str, real_id: str
) -> None:
    out = _call(surrogates, keying, name, f"{real_id}^^^HOSP^MR")
    fabricated = out.split("^")[0]
    assert fabricated.isascii(), out
    assert len(fabricated) == len(real_id)
    # The shape survives: a digit stays a digit, ASCII punctuation stays itself.
    for was, now in zip(real_id, fabricated, strict=True):
        assert was.isdigit() == now.isdigit()
        if was.isascii() and not was.isalnum():
            assert now == was


@_MODULES
@pytest.mark.parametrize("name", ["surrogate_mrn", "surrogate_id"])
def test_a_cx_keeps_its_issuer_and_loses_its_check_digit_and_dates(
    surrogates: ModuleType, keying: ModuleType, name: str
) -> None:
    real = "12345^7^M10^HOSP&1.2.3&ISO^MR^FAC^20200101^20301231^JURIS^AGENCY^SECCHECK^SC"
    comps = _call(surrogates, keying, name, real).split("^")
    assert comps[1:] == ["", "M10", "HOSP&1.2.3&ISO", "MR", "FAC", "", "", "JURIS", "AGENCY"]
    assert comps[0] != "12345" and len(comps[0]) == 5


@_MODULES
def test_blanked_trailing_components_leave_no_run_of_separators(
    surrogates: ModuleType, keying: ModuleType
) -> None:
    out = _call(surrogates, keying, "surrogate_mrn", "12345^^^HOSP^MR^^20200101^20301231")
    assert out.endswith("^^^HOSP^MR")
    assert "2020" not in out and "2030" not in out


@_MODULES
def test_a_cx_shaped_ssn_loses_its_check_digit_and_dates(
    surrogates: ModuleType, keying: ModuleType
) -> None:
    out = _call(surrogates, keying, "surrogate_ssn", "123-45-6789^4^^SSA^SS^^20200101")
    head, _, tail = out.partition("^")
    assert len(head) == 11 and head != "123-45-6789"
    assert tail == "^^SSA^SS"


@_MODULES
def test_a_driver_s_licence_keeps_its_state_and_loses_its_expiry(
    surrogates: ModuleType, keying: ModuleType
) -> None:
    out = _call(surrogates, keying, "surrogate_dln", "D1234567^CA^20291231^EXTRA")
    number, state = out.split("^")
    assert state == "CA"
    assert len(number) == 8 and number[0].isalpha() and number != "D1234567"


@pytest.mark.parametrize("anon", [engine_anon, tee_anon], ids=["engine", "tee"])
def test_pid_20_takes_the_dln_kind_by_default(anon: ModuleType) -> None:
    kinds = {rule.path: rule.kind for rule in anon.DEFAULT_RULES}
    assert kinds["PID-20"] == anon.SurrogateKind.DLN


_MESSAGE = (
    "MSH|^~\\&|A|B|C|D|20260101||ADT^A01|M1|P|2.5.1\r"
    "PID|1||MÜLLER12345^7^M10^HOSP^MR^^20200101^20301231~99^3^^OTHER^MR||DOE^JOHN"
    "||19800101|M||||||||||||D1234567^CA^20291231"
)


def _field(message: str, number: int) -> str:
    pid = next(seg for seg in message.split("\r") if seg.startswith("PID|"))
    return pid.split("|")[number]


@pytest.mark.parametrize("anon", [engine_anon, tee_anon], ids=["engine", "tee"])
def test_the_adapters_leave_no_residue_in_pid_3_or_pid_20(anon: ModuleType) -> None:
    out = anon.anonymize(_MESSAGE, salt=_SALT)
    first, second = _field(out, 3).split("~")
    assert first.isascii() and first.split("^")[1:] == ["", "M10", "HOSP", "MR"]
    assert second.split("^")[1:] == ["", "", "OTHER", "MR"]
    assert _field(out, 20).split("^")[1:] == ["CA"]
    for residue in ("Ü", "20200101", "20301231", "20291231"):
        assert residue not in out


def test_both_adapters_agree_on_the_message() -> None:
    assert engine_anon.anonymize(_MESSAGE, salt=_SALT) == tee_anon.anonymize(_MESSAGE, salt=_SALT)
