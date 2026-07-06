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
