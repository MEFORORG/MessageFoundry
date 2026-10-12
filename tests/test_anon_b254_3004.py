# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Anonymizer follow-ups engine PR 2025 shipped open (vault BACKLOG #3004), one group per part.

Part 3: a very long run of digits in MSH-12 is refused with a body-free ``AnonError``, where the
interpreter raised a plain ``ValueError`` only while its own digit limit was on.

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
