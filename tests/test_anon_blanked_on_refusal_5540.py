# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A refused message adds nothing to the caller's ``blanked`` list (vault BACKLOG #5540, the
"blanked records a path before the refusal" limb of #5533 item 13).

``blanked`` names the fields the ``date`` kind scrubbed to empty in an output. A message an adapter
refuses has no output, so a path recorded for it names a field of nothing. Before this fix the
shared ``surrogate_field_recorded`` appended the path before the surrogate ran and before the
checks that refuse, so a caller that kept one list across a run and went on past a refusal held an
address for a message it never emitted. Both adapters now hand the caller's list the paths only
once the message has been written.

Every value here is synthetic.
"""

from __future__ import annotations

from types import ModuleType
from typing import Any, NamedTuple

import pytest

import messagefoundry_toolkit.anon as engine_anon
import tee.anon as tee_anon
from messagefoundry_toolkit.anon import hl7 as engine_hl7
from messagefoundry_toolkit.anon import surrogates as engine_surrogates
from messagefoundry_toolkit.anon.keying import Keyer as EngineKeyer
from messagefoundry_toolkit.anon.rules import FieldRule as EngineRule
from messagefoundry_toolkit.anon.rules import SurrogateKind as EngineKind
from tee.anon import hl7 as tee_hl7
from tee.anon import surrogates as tee_surrogates
from tee.anon.keying import Keyer as TeeKeyer
from tee.anon.rules import FieldRule as TeeRule
from tee.anon.rules import SurrogateKind as TeeKind

_SALT = "b5540-blanked-salt-0123456789abcdef-012345"
#: Not a timestamp, so the date kind scrubs it to empty and records EVN-2.
_NOT_A_DATE = "SOMEDAY"
_DEFAULT_ENCODING = r"^~\&"
#: ``.`` declared as the subcomponent separator, which the date kind's fill writes.
_DOT_ENCODING = r"^~\."


class _Side(NamedTuple):
    anon: ModuleType
    hl7: ModuleType
    surrogates: ModuleType
    keyer: Any
    rule: Any
    kind: Any
    refused: type[Exception]


_SIDES = pytest.mark.parametrize(
    "side",
    [
        _Side(
            engine_anon,
            engine_hl7,
            engine_surrogates,
            EngineKeyer,
            EngineRule,
            EngineKind,
            engine_surrogates.SurrogateSeparatorRefused,
        ),
        _Side(
            tee_anon,
            tee_hl7,
            tee_surrogates,
            TeeKeyer,
            TeeRule,
            TeeKind,
            tee_surrogates.SurrogateSeparatorRefused,
        ),
    ],
    ids=["engine", "tee"],
)


def _message(pid3: str, evn2: str = _NOT_A_DATE, encoding: str = _DEFAULT_ENCODING) -> str:
    header = "|".join(
        (
            "MSH",
            encoding,
            "APP",
            "FAC",
            "RCV",
            "RFAC",
            "20260101",
            "",
            "ADT^A01",
            "M1",
            "P",
            "2.5.1",
        )
    )
    return f"{header}\rEVN|A01|{evn2}\rPID|1||{pid3}"


def _rules(side: _Side) -> tuple[Any, ...]:
    """EVN-2 is applied before PID-3, so the date is emptied before PID-3 is refused."""
    return (side.rule("EVN-2", side.kind.DATE), side.rule("PID-3", side.kind.MRN))


@_SIDES
def test_the_control_message_records_the_emptied_date(side: _Side) -> None:
    """Positive control: with nothing to refuse, the same message records EVN-2."""
    blanked: list[str] = []
    side.anon.anonymize(_message("Q7734^^^H^MR"), salt=_SALT, rules=_rules(side), blanked=blanked)
    assert blanked == ["EVN-2"]


@_SIDES
def test_a_refusal_in_a_later_field_leaves_the_callers_list_as_it_was(side: _Side) -> None:
    """EVN-2 is scrubbed to empty first, then PID-3's surrogate would copy a BEL and is refused."""
    blanked: list[str] = ["EARLIER-1"]
    with pytest.raises(side.refused, match="PID-3"):
        side.anon.anonymize(
            _message("Q77\x0734^^^H^MR"), salt=_SALT, rules=_rules(side), blanked=blanked
        )
    assert blanked == ["EARLIER-1"]


@_SIDES
def test_a_refusal_in_the_emptied_field_itself_records_nothing(side: _Side) -> None:
    """One date field: its first repetition is scrubbed to empty, and the fill for its second holds
    ``.``, which this message declares as its subcomponent separator, so the field is refused after
    the path was found. Called on each adapter directly, as a caller of ``anonymize_message`` may."""
    blanked: list[str] = []
    raw = _message("Q7734^^^H^MR", evn2=f"{_NOT_A_DATE}~20260315142233.12", encoding=_DOT_ENCODING)
    with pytest.raises(side.refused, match="EVN-2"):
        side.hl7.anonymize_message(
            raw, side.keyer(_SALT), (side.rule("EVN-2", side.kind.DATE),), blanked
        )
    assert blanked == []


@_SIDES
def test_a_refusal_in_the_site_code_pass_records_nothing(
    side: _Side, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The site-code pass runs after every rule, so the list is handed over only once it returns.
    It refuses only under a configured site-code prefix, so a refusal from it is stood in for."""

    def _refuse(*_args: object) -> str:
        raise side.anon.AnonError("site-code pass refused")

    monkeypatch.setattr(side.hl7, "scrub_message_site_codes", _refuse)
    blanked: list[str] = []
    with pytest.raises(side.anon.AnonError, match="site-code pass refused"):
        side.anon.anonymize(
            _message("Q7734^^^H^MR"), salt=_SALT, rules=_rules(side), blanked=blanked
        )
    assert blanked == []


@_SIDES
def test_the_shared_helper_does_not_record_a_field_it_refuses(side: _Side) -> None:
    """``surrogate_field_recorded`` called directly: a date field it refuses is not recorded, and
    the same field it returns is."""
    module = side.surrogates
    refused_seps = module.read_message_seps(_message("Q7734", encoding=_DOT_ENCODING))[0]
    plain_seps = module.read_message_seps(_message("Q7734"))[0]
    keyer = side.keyer(_SALT)
    value = f"{_NOT_A_DATE}~20260315142233.12"
    blanked: list[str] = []
    with pytest.raises(side.refused, match="EVN-2"):
        module.surrogate_field_recorded(
            "EVN-2", side.kind.DATE, value, keyer, refused_seps, blanked
        )
    assert blanked == []
    module.surrogate_field_recorded("EVN-2", side.kind.DATE, value, keyer, plain_seps, blanked)
    assert blanked == ["EVN-2"]


@_SIDES
def test_a_refusal_by_the_adapters_own_whole_field_check_records_nothing(side: _Side) -> None:
    """MSH-2 declares NUL as the component separator. The shared helper passes the date field and
    records EVN-2, then each adapter's own whole-field check (the tee's ``_whole_field``, the
    engine's ``Message.set``) refuses the NUL it would write. The helper's record cannot cover
    that refusal; the adapter's held list does."""
    nul = chr(0)
    raw = _message(
        "Q7734", evn2=f"{_NOT_A_DATE}~20260315{nul}S", encoding=nul + _DEFAULT_ENCODING[1:]
    )
    blanked: list[str] = []
    with pytest.raises(side.anon.AnonError):
        side.hl7.anonymize_message(
            raw, side.keyer(_SALT), (side.rule("EVN-2", side.kind.DATE),), blanked
        )
    assert blanked == []
