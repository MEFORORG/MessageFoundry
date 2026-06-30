# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Strict X12 validation (messagefoundry.parsing.x12.validate) — the opt-in pyx12 slow path behind the
tolerant X12Peek/X12Message hot path (ADR 0012, BACKLOG #32).

Covers: a clean interchange validates; a conformance-violating interchange reports structural errors +
emits a 999 ack; non-X12 input raises X12ValidationError (not a generic crash); and the PHI guard —
the offending data *value* never appears in the surfaced errors (only schema-label locators)."""

from __future__ import annotations

import logging

import pytest

pytest.importorskip("pyx12")

from messagefoundry.parsing.x12 import (  # noqa: E402 - after importorskip
    X12SegmentError,
    X12ValidationError,
    X12ValidationResult,
    validate,
)

_ISA = (
    "ISA*00*          *00*          *ZZ*SENDER         *ZZ*RECEIVER       "
    "*060501*1200*^*00501*000000001*0*P*:~"
)
_GS = "GS*HC*SENDERAPP*RECVAPP*20060501*1200*1*X*005010X222A1~"
_GE = "GE*1*1~"
_IEA = "IEA*1*000000001~"


def _interchange(*body: str) -> str:
    return _ISA + _GS + "".join(body) + _GE + _IEA


def test_validate_reports_conformance_errors_and_emits_999() -> None:
    # An 837 stub missing mandatory loops + a wrong SE count — pyx12 finds real violations.
    msg = _interchange(
        "ST*837*0001*005010X222A1~",
        "BHT*0019*00*0123*20060501*1200*CH~",
        "SE*4*0001~",
    )
    result = validate(msg)
    assert isinstance(result, X12ValidationResult)
    assert result.valid is False
    assert result.errors, "expected at least one conformance error"
    assert all(isinstance(e, X12SegmentError) for e in result.errors)
    # The 999 Functional Acknowledgment is generated for free off the 005010 walk.
    assert result.ack is not None
    assert result.ack_transaction == "999"
    assert "ST*999" in result.ack


def test_validate_bytes_input_is_decoded() -> None:
    result = validate(_interchange("ST*837*0001*005010X222A1~", "SE*2*0001~").encode("utf-8"))
    assert isinstance(result, X12ValidationResult)
    assert result.valid is False  # incomplete 837


def test_non_x12_input_raises_validation_error() -> None:
    with pytest.raises(X12ValidationError):
        validate("this is not an X12 interchange at all")


def test_errors_never_leak_the_offending_value() -> None:
    """PHI guard: a bad data-element value (here a fake date) must NOT appear anywhere in the surfaced
    errors — only the structural locators (code, segment id, element position, schema type name)."""
    secret = "NOTADATE99"
    msg = _interchange(
        "ST*837*0001*005010X222A1~",
        f"BHT*0019*00*0123*{secret}*1200*CH~",  # BHT04 invalid/too-long date
        "SE*4*0001~",
    )
    result = validate(msg)
    assert result.valid is False
    rendered = "\n".join(
        f"{e.code}|{e.message}|{e.segment_id}|{e.element_position}|{e.element_name}|{e.loop}"
        for e in result.errors
    )
    assert secret not in rendered, "the offending data value leaked into a surfaced error"


def test_validation_silences_the_value_bearing_pyx12_logger(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """pyx12 logs raw, value-bearing error strings at ERROR; the pass must suppress them so the
    secret never reaches the general log, and must restore the logger's state afterward."""
    secret = "LEAKYVALUE"
    msg = _interchange(
        "ST*837*0001*005010X222A1~",
        f"BHT*0019*00*0123*{secret}*1200*CH~",
        "SE*4*0001~",
    )
    pyx12_logger = logging.getLogger("pyx12")
    was_level = pyx12_logger.level
    # Capture at the root (where pyx12's records would propagate); do NOT force the pyx12 logger level
    # — the validator's own suppression must win on its own.
    with caplog.at_level(logging.DEBUG):
        validate(msg)
    assert secret not in caplog.text
    # The logger's level is restored (we only mute it for the duration of the pass).
    assert pyx12_logger.level == was_level


def test_segment_error_is_frozen_dataclass() -> None:
    err = X12SegmentError(code="3", message="segment NM1: error 3", segment_id="NM1")
    with pytest.raises(Exception):
        err.code = "9"  # type: ignore[misc]
