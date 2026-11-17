# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #5378: an ``mfb64:v1:`` binary-carriage body quoted in a log record or exception is
withheld by the write-time log scrub. Synthetic HL7 only (CLAUDE.md section 9)."""

from __future__ import annotations

import logging
import sys

import pytest

from messagefoundry import logging_setup
from messagefoundry.parsing.binary import MARKER, encode
from messagefoundry.redaction import _BINARY_CARRIAGE, redact, redact_untrusted, safe_text

_BODY = b"MSH|^~\\&|SND|FAC|RCV|FAC|20260101||ADT^A01|MSG1|P|2.5\rPID|1||SYN123^^^H||ZZTEST^ALPHA\r"
_CARRIAGE = encode(_BODY)
_PAYLOAD = _CARRIAGE.removeprefix(MARKER)


def test_the_literal_marker_is_the_carriage_marker() -> None:
    assert _BINARY_CARRIAGE.match(MARKER + "QQ==") is not None
    assert _BINARY_CARRIAGE.pattern.startswith("(?i)(" + MARKER + ")")


@pytest.mark.parametrize(
    "text",
    [
        f"could not route {_CARRIAGE}",
        f"could not route {_CARRIAGE} after retry",
        repr(_CARRIAGE),
        f"{{'raw': {_CARRIAGE!r}}}",
        f'{{"raw": "{_CARRIAGE.replace("/", chr(92) + "/")}"}}',
        "body " + _CARRIAGE.replace("+", "%2B").replace("/", "%2F").replace("=", "%3D"),
        "body " + _CARRIAGE.upper(),
        "body " + _CARRIAGE.replace("+", "-").replace("/", "_"),
    ],
)
def test_a_carriage_payload_is_withheld(text: str) -> None:
    out = redact_untrusted(text)
    assert _PAYLOAD[:12] not in out
    assert _PAYLOAD[:12].upper() not in out
    assert "mfb64:v1:[redacted]" in out.lower()
    assert redact(out) == out


def test_prose_naming_the_marker_is_kept() -> None:
    text = "not a binary-carriage value (missing mfb64:v1: marker); check .is_binary first"
    assert redact(text) == text


def test_the_surrounding_text_is_kept() -> None:
    assert redact(f"route failed for {_CARRIAGE} on IB_TEST") == (
        "route failed for mfb64:v1:[redacted] on IB_TEST"
    )


def test_safe_text_withholds_a_carriage() -> None:
    assert _PAYLOAD[:12] not in safe_text(f"bad {_CARRIAGE}")


def test_the_shipped_log_filters_withhold_a_carriage_in_message_and_traceback() -> None:
    record = logging.LogRecord("mf.test", logging.ERROR, __file__, 1, "body %s", (_CARRIAGE,), None)
    try:
        raise ValueError(f"cannot decode {_CARRIAGE}")
    except ValueError:
        record.exc_info = sys.exc_info()
    handler = logging.NullHandler()
    logging_setup._install_phi_filters(handler)
    for flt in handler.filters:
        assert isinstance(flt, logging.Filter)
        assert flt.filter(record)
    rendered = logging.Formatter().format(record)
    assert _PAYLOAD[:12] not in rendered
    assert "mfb64:v1:[redacted]" in rendered
