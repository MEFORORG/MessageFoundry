# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Plain ``anonymize`` refuses a line no rule can reach (vault BACKLOG #2246).

Before this, only ``anonymize_checked`` refused such a line, in its leak-check. Plain ``anonymize``
passed it through untouched, so a wrapped name could reach a dataset. The refusal now lives in the
shared ``normalized_message``, which both entry points and both copies (engine and tee) run first.

A legal empty segment, such as a bare ``PV2``, is not such a line (vault BACKLOG #2247), so each
refusal here is paired with a line that must still pass. Synthetic text only.

Measured red: with the refusal taken out of the engine copy of normalized_message, 30 tests
across the five anonymizer test files failed. The tee arms stayed green, which is the control.
"""

from __future__ import annotations

import importlib
from collections.abc import Callable
from types import ModuleType
from typing import Any

import pytest

from messagefoundry.anon import anonymize as engine_anonymize
from messagefoundry.anon import anonymize_checked as engine_anonymize_checked
from messagefoundry.anon import leak as engine_leak
from messagefoundry.anon.surrogates import normalized_message as engine_normalized
from tee.anon import anonymize as tee_anonymize
from tee.anon import anonymize_checked as tee_anonymize_checked
from tee.anon import leak as tee_leak
from tee.anon.surrogates import normalized_message as tee_normalized

_SALT = "b193-salt-0123456789abcdef"
_HEADER = "MSH|^~\\&|A|B|C|D|20260101||ADT^A01|M1|P|2.5.1"
_PID = "PID|1||1^^^H^MR||X^Y"

_ENTRY_POINTS = pytest.mark.parametrize(
    "entry",
    (engine_anonymize, tee_anonymize, engine_anonymize_checked, tee_anonymize_checked),
    ids=("engine-plain", "tee-plain", "engine-checked", "tee-checked"),
)

_UNREACHABLE = pytest.mark.parametrize(
    ("line", "needle"),
    [
        ("ZZTEST SYNTH|wrapped note", "ZZTEST"),  # first field is not a segment id
        ("ZZTEST SYNTH", "ZZTEST"),  # the same, with no field separator
        ("LEE", "LEE"),  # three letters shaped like a segment id that no HL7 version defines
        ("ZOE", "ZOE"),  # a Z-prefix alone does not make bare text a segment
        ("msh|ZZTEST SYNTH", "ZZTEST"),  # a second, lowercase MSH line is not the header
        ("|ZZTEST", "ZZTEST"),  # an empty first field
    ],
    ids=("not-an-id", "not-an-id-bare", "bare-name", "bare-z-name", "second-msh", "empty-id"),
)


def _msg(*lines: str) -> str:
    return "\r".join((_HEADER, _PID, *lines))


@_ENTRY_POINTS
@_UNREACHABLE
def test_every_entry_point_refuses_a_line_no_rule_can_reach(
    entry: Callable[..., str], line: str, needle: str
) -> None:
    """The four entry points agree: each raises the same body-free ``AnonError``."""
    with pytest.raises(ValueError, match="a line no rule can reach") as exc:
        entry(_msg(line), salt=_SALT)
    assert type(exc.value).__name__ == "AnonError"
    assert needle not in str(exc.value)  # the refusal never carries the line's text


@_ENTRY_POINTS
@_UNREACHABLE
def test_the_refusal_does_not_depend_on_where_the_line_sits(
    entry: Callable[..., str], line: str, needle: str
) -> None:
    """A wrapped line is as often in the middle of a message as at its end."""
    with pytest.raises(ValueError, match="a line no rule can reach"):
        entry(_msg(line, "NK1|1|Q^Z"), salt=_SALT)


_REACHABLE = pytest.mark.parametrize(
    "line",
    [
        "PV2",  # a legal empty segment, no separator (BACKLOG #2247 defect 1)
        "PV2|",  # the same with a trailing separator
        "NK1|1|Q^Z",  # an ordinary mapped segment
        "ZPD|free",  # a Z-segment with a field is reachable: an overlay rule can name ZPD-1
        "KIM|F",  # shaped like a segment, so its fields are checked; the id is never printed
    ],
    ids=("empty-segment", "empty-segment-sep", "mapped", "z-segment", "unknown-id"),
)


@_ENTRY_POINTS
@_REACHABLE
def test_a_reachable_line_is_not_refused(entry: Callable[..., str], line: str) -> None:
    """The control for the refusals above. Without it, a rule that refused every message would pass
    them. A bare ``PV2`` is the case the old no-separator rule got wrong."""
    out = entry(_msg(line), salt=_SALT)
    assert out.split("\r")[-1].split("|")[0] == line.split("|")[0]  # the line is still there


@_REACHABLE
def test_engine_and_tee_agree_on_a_reachable_line(line: str) -> None:
    msg = _msg(line, "NK1|1|Q^Z")
    assert engine_anonymize(msg, salt=_SALT) == tee_anonymize(msg, salt=_SALT)


def test_a_bare_segment_id_is_legal_only_where_the_hl7_version_defines_it() -> None:
    """``DON`` is a segment from HL7 2.8 on. Bare, it is an empty segment in a 2.8 message and
    unreachable text in a 2.5.1 one, where it may as well be a wrapped name."""
    v28 = _HEADER.replace("2.5.1", "2.8")
    for side in (engine_anonymize, tee_anonymize):
        assert side("\r".join((v28, _PID, "DON")), salt=_SALT).endswith("\rDON")
        with pytest.raises(ValueError, match="a line no rule can reach"):
            side("\r".join((_HEADER, _PID, "DON")), salt=_SALT)


def test_a_message_with_no_msh_keeps_its_own_refusal() -> None:
    """The unreachable-line check needs the field separator, so it stays out of the way when there
    is no header to read one from. The adapters' older refusal still names the real cause."""
    for side in (engine_anonymize, tee_anonymize):
        with pytest.raises(ValueError, match="no parseable MSH"):
            side("ZZTEST SYNTH|wrapped note", salt=_SALT)


def _refuses(normalized: Callable[..., str], msg: str, paths: tuple[str, ...]) -> bool:
    try:
        normalized(msg, paths)
    except ValueError:
        return True
    return False


def test_the_leak_check_and_the_anonymizer_use_one_definition() -> None:
    """For each line and each rule set, the anonymizer refuses exactly when the leak-check reports
    a malformed line. The rule sets matter: a bare ``ZPD`` flips with them."""
    lines = ["ZZTEST SYNTH|x", "LEE", "ZOE", "msh|x", "PV2", "PV2|", "KIM|F", "ZPD|free", "ZPD"]
    rule_sets: tuple[tuple[str, ...], ...] = ((), ("ZPD-1",), ("PID-5", "NK1-2"))
    seen: set[tuple[str, bool]] = set()
    for leak, normalized in ((engine_leak, engine_normalized), (tee_leak, tee_normalized)):
        for paths in rule_sets:
            for line in lines:
                msg = _msg(line)
                reported = leak.MALFORMED_LINE_HIT in leak.structural_phi_hits(msg, set(paths))
                assert _refuses(normalized, msg, paths) is reported, (line, paths)
                seen.add((line, reported))
    # Both outcomes occur, and the bare Z id is the line whose outcome the rules decide.
    assert ("ZPD", True) in seen and ("ZPD", False) in seen
    assert ("LEE", True) in seen and ("LEE", False) not in seen
    assert ("PV2", False) in seen and ("PV2", True) not in seen


# --- a rule naming a segment is the operator's decision about it ------------------------------------
# Review finding on the first cut of this change: the anonymizer judged a bare id with no rules in
# hand, so it refused a bare ``ZPD`` that a rule names while the leak-check, given the same rules,
# passed it. Both now get the same rule paths. A message ending in a bare ``ZPD`` under a rule for
# ``ZPD-1`` also anonymized on main before this item, so refusing it was a new refusal.

_BARE_ZPD = "\r".join((_HEADER, _PID, "ZPD"))
_SIDES = pytest.mark.parametrize(
    ("plain", "checked", "leak"),
    [
        (engine_anonymize, engine_anonymize_checked, engine_leak),
        (tee_anonymize, tee_anonymize_checked, tee_leak),
    ],
    ids=("engine", "tee"),
)


def _outcomes(
    plain: Callable[..., str], checked: Callable[..., str], leak: ModuleType, rules: tuple[Any, ...]
) -> tuple[bool, bool, bool]:
    """Whether plain ``anonymize``, ``anonymize_checked`` and ``leak_report`` each ACCEPT the bare
    ``ZPD`` message under ``rules``."""
    accepted: list[bool] = []
    for entry in (plain, checked):
        try:
            out = entry(_BARE_ZPD, salt=_SALT, rules=rules)
        except ValueError as exc:
            assert "a line no rule can reach" in str(exc)
            accepted.append(False)
        else:
            assert out.endswith("\rZPD")
            accepted.append(True)
    hits = leak.leak_report(_BARE_ZPD, rules=rules).hits
    assert hits in ([], [leak.MALFORMED_LINE_HIT])
    accepted.append(hits == [])
    return accepted[0], accepted[1], accepted[2]


@_SIDES
def test_a_bare_id_that_a_rule_names_is_accepted_by_all_three(
    plain: Callable[..., str], checked: Callable[..., str], leak: ModuleType
) -> None:
    rules = (*_default_rules(leak), _rule(leak, "ZPD-1", "name"))
    assert _outcomes(plain, checked, leak, rules) == (True, True, True)


@_SIDES
def test_a_bare_z_id_that_no_rule_names_is_refused_by_all_three(
    plain: Callable[..., str], checked: Callable[..., str], leak: ModuleType
) -> None:
    """The control: without the rule, the same message is refused, by the same three."""
    assert _outcomes(plain, checked, leak, _default_rules(leak)) == (False, False, False)


@_SIDES
def test_a_keep_rule_does_not_make_a_bare_id_reachable(
    plain: Callable[..., str], checked: Callable[..., str], leak: ModuleType
) -> None:
    """A KEEP rule rewrites nothing, so the leak-check does not count it as mapping the segment,
    and the anonymizer is not handed it. The three still agree: all refuse."""
    rules = (*_default_rules(leak), _rule(leak, "ZPD-1", "keep"))
    assert _outcomes(plain, checked, leak, rules) == (False, False, False)


def _default_rules(leak: ModuleType) -> tuple[Any, ...]:
    """The default rules of the package ``leak`` belongs to (engine or tee)."""
    package = importlib.import_module(leak.__name__.rsplit(".", 1)[0])
    return tuple(package.DEFAULT_RULES)


def _rule(leak: ModuleType, path: str, kind: str) -> Any:
    package = importlib.import_module(leak.__name__.rsplit(".", 1)[0])
    return package.FieldRule(path, package.SurrogateKind(kind))
