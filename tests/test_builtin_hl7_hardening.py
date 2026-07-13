# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Security hardening for the built-ins HL7 unescape (DELTA-01 / DELTA-02).

The built-in tolerant parser is the **default** hot-path backend (ADR 0054). Its rich-text
repetition escape (``\\.inN\\`` etc.) must not expand an attacker-controlled count without bound — a
~15-byte ``\\.in2000000000\\`` would otherwise allocate gigabytes synchronously on the pre-ACK path
(memory-exhaustion DoS, DELTA-01) — and a malformed count must not raise out of a field read
(DELTA-02, which severed the connection and dropped a parseable message with no disposition, breaking
the count-and-log invariant).

These tests assert the clamp/guard and **intentionally diverge** from python-hl7's unbounded
behavior, so they live outside the byte-parity suite.
"""

from __future__ import annotations

import pytest

import messagefoundry.parsing._backend as _backend
from messagefoundry.parsing._builtin_hl7 import MAX_ESCAPE_REPEAT, unescape
from messagefoundry.parsing.peek import Peek
from messagefoundry.parsing.summary import summarize
import logging
import hl7
import messagefoundry.parsing._builtin_hl7 as _builtin_hl7
from messagefoundry.parsing.message import Message
from messagefoundry.parsing.peek import HL7PeekError

SEPS = ("|", "^", "~", "&", "\\")

_MSG = (
    "MSH|^~\\&|SEND|FAC|RECV|FAC|20260101000000||ADT^A01|MSG00001|P|2.5\rPID|1||{pid3}||DOE^JOHN\r"
)


def _peek(raw: str) -> Peek:
    with _backend.backend(builtin=True):
        return Peek.parse(raw)


# --- unit: unescape repeat-count guard --------------------------------------


def test_unescape_drops_oversized_repeat_count() -> None:
    # ~15 bytes that would expand to ~8 GB without the clamp: dropped, no allocation.
    assert unescape("\\.in2000000000\\", SEPS) == ""


def test_unescape_allows_count_at_cap_and_drops_above() -> None:
    indent = "    "  # ".in" -> 4 spaces
    assert unescape(f"\\.in{MAX_ESCAPE_REPEAT}\\", SEPS) == indent * MAX_ESCAPE_REPEAT
    assert unescape(f"\\.in{MAX_ESCAPE_REPEAT + 1}\\", SEPS) == ""


@pytest.mark.parametrize("seq", ["\\.inX\\", "\\.in \\", "\\.br9z\\", "\\.in-5\\"])
def test_unescape_drops_malformed_or_negative_count_without_raising(seq: str) -> None:
    # DELTA-02: a non-numeric/negative count must not raise; unmappable -> dropped.
    assert unescape(seq, SEPS) == ""


def test_unescape_preserves_small_legitimate_repeat() -> None:
    assert unescape("\\.in3\\", SEPS) == "    " * 3


def test_unescape_preserves_ordinary_delimiter_and_hex_escapes() -> None:
    # The count guard must not disturb byte-parity for the common escape cases.
    assert unescape("A\\F\\B", SEPS) == "A|B"
    assert unescape("A\\X0a\\B", SEPS) == "A\nB"


# --- reachability: pre-ACK field reads must stay safe -----------------------


def test_peek_field_huge_count_returns_none_not_oom() -> None:
    peek = _peek(_MSG.format(pid3="\\.in2000000000\\^^^MRN"))
    assert peek.field("PID-3.1") is None  # dropped -> "" -> None; completes without OOM


def test_peek_field_malformed_count_does_not_raise() -> None:
    peek = _peek(_MSG.format(pid3="\\.inX\\^^^MRN"))
    assert peek.field("PID-3.1") is None


def test_summarize_is_safe_on_hostile_repeat_escape() -> None:
    # summary.summarize() runs on the pre-ACK path (wiring_runner); it must neither OOM nor raise
    # (DELTA-01/02). A well-formed message carrying a hostile PID-3.1 summarizes cleanly.
    for pid3 in ("\\.in2000000000\\^^^MRN", "\\.inX\\^^^MRN"):
        with _backend.backend(builtin=True):
            peek = Peek.parse(_MSG.format(pid3=pid3))
            result = summarize(peek)
        assert isinstance(result, str)


# --- ADR 0054 Phase-1 fallback guard ----------------------------------------
#
# Each built-ins parse is wrapped so an *unexpected* internal fault falls back to python-hl7 (never
# crashing a connection) and is logged; the contract errors still re-raise without falling back
# (Message.parse re-raises hl7.ParseException; Peek.parse raises HL7PeekError from its no-MSH
# pre-guard, before the try). None of these branches are exercised by the parity or unescape-DoS
# suites. The forced-fault log also sits on the pre-ACK ingress path (Peek.parse runs inside
# summarize()), so it must stay PHI-free.

_FALLBACK_MSG = "falling back to python-hl7"

# A unique PID-5 marker that must never leak into the fallback log (PHI-safety regression guard).
_PHI_MARKER = "ZZSECRETNAME9137X"
_PHI_MSG = (
    "MSH|^~\\&|SEND|FAC|RECV|FAC|20260101000000||ADT^A01|MSG00001|P|2.5\r"
    f"PID|1||MRN001||{_PHI_MARKER}^JOHN\r"
)


def _raise_builtin_fault(*_args: object, **_kwargs: object) -> None:
    # Stand-in for an unexpected internal built-ins bug (anything other than the contract's
    # ParseException / HL7PeekError). Carries no body text of its own.
    raise RuntimeError("forced built-ins fault")


def _fallback_records(caplog: pytest.LogCaptureFixture) -> list[logging.LogRecord]:
    return [r for r in caplog.records if _FALLBACK_MSG in r.getMessage()]


def test_peek_falls_back_to_python_hl7_on_builtin_fault(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    monkeypatch.setattr(_builtin_hl7, "parse", _raise_builtin_fault)
    with caplog.at_level(logging.WARNING), _backend.backend(builtin=True):
        peek = Peek.parse(_MSG.format(pid3="MRN001"))
    # Landed on the proven python-hl7 backend, and the routing read still works.
    assert isinstance(peek.message, hl7.Message)
    assert peek.field("MSH-9.1") == "ADT"
    records = _fallback_records(caplog)
    assert len(records) == 1
    assert records[0].levelno == logging.WARNING
    # exc_info=True is attached, but the PHI-redaction log filter (when installed) redacts it into
    # exc_text and clears exc_info — so a diagnostic traceback is present in one form or the other.
    assert records[0].exc_info is not None or records[0].exc_text is not None


def test_message_falls_back_to_python_hl7_on_builtin_fault(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    monkeypatch.setattr(_builtin_hl7, "parse", _raise_builtin_fault)
    with caplog.at_level(logging.WARNING), _backend.backend(builtin=True):
        msg = Message.parse(_MSG.format(pid3="MRN001"))
    assert msg._builtin is False
    assert isinstance(msg._m, hl7.Message)
    assert msg.field("MSH-9.1") == "ADT"
    records = _fallback_records(caplog)
    assert len(records) == 1
    assert records[0].levelno == logging.WARNING
    # exc_info=True is attached, but the PHI-redaction log filter (when installed) redacts it into
    # exc_text and clears exc_info — so a diagnostic traceback is present in one form or the other.
    assert records[0].exc_info is not None or records[0].exc_text is not None


def test_message_parse_reraises_parseexception_without_fallback(
    caplog: pytest.LogCaptureFixture,
) -> None:
    # A non-MSH-leading body is the built-ins parser matching python-hl7's contract, not an internal
    # fault: Message.parse re-raises hl7.ParseException as-is, with no fallback and no warning.
    with caplog.at_level(logging.WARNING), _backend.backend(builtin=True):
        with pytest.raises(hl7.ParseException):
            Message.parse("PID|1||X\r")
    assert _fallback_records(caplog) == []


def test_peek_parse_raises_hl7peekerror_without_fallback(
    caplog: pytest.LogCaptureFixture,
) -> None:
    # Peek's no-MSH pre-guard raises HL7PeekError *before* the try, so the fallback never runs and
    # nothing is logged.
    with caplog.at_level(logging.WARNING), _backend.backend(builtin=True):
        with pytest.raises(HL7PeekError):
            Peek.parse("PID|1||X\r")
    assert _fallback_records(caplog) == []


def test_fallback_log_is_phi_free_for_both_entry_points(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    # Regression guard: the fallback warning is a constant string and exc_info=True renders a
    # traceback *without* local variables, so the message body (held only in the ``norm`` local)
    # never reaches the log. Fails if the warning ever interpolates the raw, or an exception starts
    # carrying body text.
    monkeypatch.setattr(_builtin_hl7, "parse", _raise_builtin_fault)
    with caplog.at_level(logging.WARNING), _backend.backend(builtin=True):
        peek = Peek.parse(_PHI_MSG)
        msg = Message.parse(_PHI_MSG)
    # The body really was carried through the fallback (the marker survives the parse)...
    assert peek.field("PID-5.1") == _PHI_MARKER
    assert msg.field("PID-5.1") == _PHI_MARKER
    # ...both fallbacks logged, yet the marker never appears anywhere in the emitted log text.
    assert len(_fallback_records(caplog)) == 2
    assert _PHI_MARKER not in caplog.text
