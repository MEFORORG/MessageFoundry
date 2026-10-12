# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Anonymizer follow-ups engine PR 2025 shipped open (vault BACKLOG #3004), one group per part.

Part 3: a very long run of digits in MSH-12 is refused with a body-free ``AnonError``, where the
interpreter raised a plain ``ValueError`` only while its own digit limit was on.

Part 2: ``anonymize_checked`` judges a bare line by the HL7 version the message came with. It
read the version from its own output, so a rule that rewrote MSH-12 could change which bare
segment ids counted as defined, and a message that passed plain ``anonymize`` was refused.

Every value here is synthetic.
"""

from __future__ import annotations

import sys
from collections.abc import Iterator
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

import messagefoundry.anon as engine_anon
import tee.anon as tee_anon
from messagefoundry.anon import leak as engine_leak
from messagefoundry.anon import rules as engine_rules
from tee.anon import leak as tee_leak
from tee.anon import rules as tee_rules

_LEAK_SCANNER = Path(__file__).resolve().parents[1] / "scripts" / "security" / "scan_forbidden.py"
_NO_SCANNER = pytest.mark.skipif(
    not _LEAK_SCANNER.exists(),
    reason="leak-check needs scripts/security/scan_forbidden.py (absent on an installed wheel)",
)

_SALT = "b254-3004-Kq7#vT2m!xW9$eR4zL8p-Hd5"
_PID = "PID|1||1^^^H^MR||X^Y"

#: Each side with its own package's classes, as a real caller would hold them.
_ENGINE = SimpleNamespace(anon=engine_anon, rules=engine_rules, leak=engine_leak)
_TEE = SimpleNamespace(anon=tee_anon, rules=tee_rules, leak=tee_leak)
_SIDES = pytest.mark.parametrize("side", (_ENGINE, _TEE), ids=("engine", "tee"))


def _msh(version: str) -> str:
    return rf"MSH|^~\&|APP|FAC|RCV|RFAC|20260101120000||ADT^A01|M1|P|{version}"


def _message(*lines: str, version: str = "2.5") -> str:
    """A header of ``version``, a PID, then ``lines``."""
    return "\r".join((_msh(version), _PID, *lines))


# --- part 3: an over-long version is a body-free refusal ------------------------------------------

#: One digit past the interpreter's default limit for turning a run of digits into a number.
_PAST_THE_INTERPRETER_LIMIT = "7" * 4301
_TOO_LONG = "run of digits too long to read"
#: The longest run that is still read, written out so the control runs on the code before the fix.
_CAP = 32


@pytest.fixture
def no_interpreter_digit_limit() -> Iterator[None]:
    """Turn the interpreter's digit limit off, as a deployment can, and put it back after."""
    before = sys.get_int_max_str_digits()
    sys.set_int_max_str_digits(0)
    try:
        yield
    finally:
        sys.set_int_max_str_digits(before)


@_SIDES
def test_a_version_at_the_cap_is_still_read(side: Any) -> None:
    """The control. A run exactly as long as the cap is read as a number, as before."""
    at_cap = "9" * _CAP
    assert side.leak._version_key(f"2.{at_cap}") == (2, int(at_cap))
    out = side.anon.anonymize(_message("PV2", version=f"2.{at_cap}"), salt=_SALT)
    assert out.split("\r")[-1] == "PV2"


@_SIDES
def test_plain_anonymize_refuses_an_over_long_version(side: Any) -> None:
    """The reproduction. Before the fix this raised a plain ``ValueError`` from ``int()``."""
    with pytest.raises(ValueError) as exc:
        side.anon.anonymize(_message(version=f"2.{_PAST_THE_INTERPRETER_LIMIT}"), salt=_SALT)
    assert type(exc.value) is side.anon.AnonError
    assert _TOO_LONG in str(exc.value)
    assert "777" not in str(exc.value)


@_SIDES
def test_anonymize_checked_refuses_an_over_long_version(side: Any) -> None:
    reports: list[Any] = []
    with pytest.raises(ValueError) as exc:
        side.anon.anonymize_checked(
            _message(version=_PAST_THE_INTERPRETER_LIMIT), salt=_SALT, on_report=reports.append
        )
    assert type(exc.value) is side.anon.AnonError
    assert reports == []


@pytest.mark.parametrize(
    "side", (pytest.param(_ENGINE, marks=_NO_SCANNER), _TEE), ids=("engine", "tee")
)
def test_a_direct_leak_report_refuses_an_over_long_version(side: Any) -> None:
    """The leak-check is callable by itself, on text ``anonymize`` never saw."""
    with pytest.raises(ValueError) as exc:
        side.leak.leak_report(
            _message(version=f"2.{_PAST_THE_INTERPRETER_LIMIT}"), rules=side.rules.DEFAULT_RULES
        )
    assert type(exc.value) is side.anon.AnonError
    assert _TOO_LONG in str(exc.value)


@_SIDES
def test_the_refusal_does_not_depend_on_the_interpreter_limit(
    side: Any, no_interpreter_digit_limit: None
) -> None:
    """With the interpreter's limit off, ``int()`` converts any run and nothing raised before the
    fix. The cap is on the length, so the refusal is the same either way."""
    with pytest.raises(side.anon.AnonError, match=_TOO_LONG):
        side.anon.anonymize(_message(version=f"2.{_PAST_THE_INTERPRETER_LIMIT}"), salt=_SALT)


@_SIDES
def test_one_digit_past_the_cap_is_refused(side: Any) -> None:
    past_cap = "9" * (_CAP + 1)
    with pytest.raises(side.anon.AnonError, match=_TOO_LONG):
        side.leak.known_segments(f"2.{past_cap}")


@_SIDES
def test_a_version_that_is_not_digits_is_still_not_a_refusal(side: Any) -> None:
    """Only a run of digits is capped. Long text that is not a number was never converted, so it
    still falls back to the ids of every version."""
    assert side.leak._version_key("x" * 5000) is None
    assert side.leak.known_segments("x" * 5000) == side.leak._ANY_VERSION_SEGMENTS


# --- part 2: a rule on MSH-12 does not change which bare line passes ------------------------------

#: The sides whose case reaches the engine's leak-check, which needs the publish guard.
_LEAK_SIDES = pytest.mark.parametrize(
    "side", (pytest.param(_ENGINE, marks=_NO_SCANNER, id="engine"), pytest.param(_TEE, id="tee"))
)


def _salt(index: int) -> str:
    return f"b254-3004-Kq7#vT2m!xW9$eR4zL8p-{index:04d}"


#: Three of the thirteen salts, of the first 200, under which the unfixed code refused the
#: reproduction on BOTH adapters. Whether it refused depended on the surrogate the salt gave
#: MSH-12, so one fixed salt that happened to pass would have proved nothing.
_REFUSING_SALTS = (28, 47, 48)
#: ``PRT`` is a segment id HL7 2.7 added, so a bare ``PRT`` passes in a 2.7 message only.
_BARE_PRT = "PRT"


def _with_version_rule(side: Any) -> tuple[Any, ...]:
    return (*side.rules.DEFAULT_RULES, side.rules.FieldRule("MSH-12", "id"))


def _output_version(output: str) -> str:
    return output.split("\r")[0].split("|")[11]


@pytest.mark.parametrize("index", _REFUSING_SALTS)
@_SIDES
def test_the_pinned_salts_write_a_version_that_leaves_out_the_bare_id(
    side: Any, index: int
) -> None:
    """The premise of every pinned case below. Under these salts the surrogate in MSH-12 is a
    version that does not define ``PRT``, where the real version does."""
    message = _message(_BARE_PRT, version="2.7")
    out = side.anon.anonymize(message, salt=_salt(index), rules=_with_version_rule(side))
    assert _output_version(out) != "2.7"
    assert _BARE_PRT in side.leak.known_segments("2.7")
    assert _BARE_PRT not in side.leak.known_segments(_output_version(out))


@pytest.mark.parametrize("index", _REFUSING_SALTS)
@_LEAK_SIDES
def test_a_rule_on_msh12_does_not_refuse_a_bare_line_the_input_defines(
    side: Any, index: int
) -> None:
    """The reproduction. Before the fix this raised ``LeakError`` for a malformed line."""
    message = _message(_BARE_PRT, version="2.7")
    out = side.anon.anonymize_checked(message, salt=_salt(index), rules=_with_version_rule(side))
    assert out.split("\r")[-1] == _BARE_PRT


@_LEAK_SIDES
def test_no_salt_of_the_first_sixty_refuses_the_bare_line(side: Any) -> None:
    """The same case over a run of salts. Plain ``anonymize`` passed every one before the fix."""
    message = _message(_BARE_PRT, version="2.7")
    refused = []
    for index in range(60):
        try:
            side.anon.anonymize_checked(message, salt=_salt(index), rules=_with_version_rule(side))
        except side.anon.LeakError:
            refused.append(index)
    assert refused == []


@pytest.mark.parametrize("index", _REFUSING_SALTS)
@_LEAK_SIDES
def test_the_default_rules_never_refused_the_bare_line(side: Any, index: int) -> None:
    """The control. With no rule on MSH-12 the version is not rewritten, so this passed before."""
    message = _message(_BARE_PRT, version="2.7")
    out = side.anon.anonymize_checked(message, salt=_salt(index), rules=side.rules.DEFAULT_RULES)
    assert _output_version(out) == "2.7"


@pytest.mark.parametrize("index", range(0, 60, 7))
@_SIDES
def test_a_bare_id_the_input_version_lacks_is_still_refused(side: Any, index: int) -> None:
    """The guard on the fix. A bare ``PRT`` in a 2.3 message is refused under every salt, whatever
    version the rule writes. Judging a bare id against every HL7 version would pass it."""
    message = _message(_BARE_PRT, version="2.3")
    with pytest.raises(side.anon.AnonError, match="no rule can reach"):
        side.anon.anonymize_checked(message, salt=_salt(index), rules=_with_version_rule(side))


@_SIDES
def test_the_walk_judges_a_bare_line_by_the_version_it_is_given(side: Any) -> None:
    """The walk by itself, both ways round. Left out, the version is the header's own."""
    paths = {rule.path for rule in _with_version_rule(side)}
    malformed = side.leak._MALFORMED_LINE
    older = _message(_BARE_PRT, version="2.3")
    newer = _message(_BARE_PRT, version="2.8")
    assert malformed in dict(side.leak.unmapped_field_values(older, paths))
    assert malformed not in dict(side.leak.unmapped_field_values(older, paths, version="2.7"))
    assert malformed not in dict(side.leak.unmapped_field_values(newer, paths))
    assert malformed in dict(side.leak.unmapped_field_values(newer, paths, version="2.3"))
    assert side.leak.structural_phi_hits(older, paths, version="2.7") == []
    assert side.leak.structural_phi_hits(newer, paths, version="2.3") == [
        side.leak.MALFORMED_LINE_HIT
    ]


@_LEAK_SIDES
def test_a_direct_leak_report_takes_the_version(side: Any) -> None:
    """A direct caller holding output and the input's version gets the same answer as
    ``anonymize_checked``. Without the version the report reads the header it was given."""
    rules = _with_version_rule(side)
    older = _message(_BARE_PRT, version="2.3")
    assert side.leak.leak_report(older, rules=rules).structural_hits == [
        side.leak.MALFORMED_LINE_HIT
    ]
    report = side.leak.leak_report(older, rules=rules, version="2.7")
    assert report.structural_hits == []
    assert "PRT (line with no fields)" in report.unmapped_fields


@pytest.mark.parametrize(
    ("text", "expected"),
    (
        (_message(version="2.7"), "2.7"),
        ("\x0b" + _message(version="2.7") + "\x1c\r", "2.7"),
        (_message(version="2.5.1^USA"), "2.5.1"),
        ("\r".join(("LEE", "MSH", _msh("2.4"), _PID)), "2.4"),
        (_message(version="2.6").replace("\r", "\r\n"), "2.6"),
        (r"MSH|^~\&|APP|FAC", ""),
        ("PID|1", None),
        ("", None),
    ),
    ids=("plain", "framed", "components", "lines-ahead", "crlf", "short", "no-msh", "empty"),
)
@_SIDES
def test_message_version_reads_the_header_the_walk_reads(
    side: Any, text: str, expected: str | None
) -> None:
    assert side.leak.message_version(text) == expected
