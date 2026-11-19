# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #5395, last pass: the two verify_leaf renderers quote no character of a Unicode error's
input, which is what lets ``tests/test_unicode_error_log_paths.py`` allow them, and the harness
scrub logs its own failure by type name only. All data here is synthetic."""

from __future__ import annotations

import logging

import pytest

import messagefoundry.verify_leaf as verify_leaf
from harness.acceptance import probes
from messagefoundry.verify_leaf import DRIVER_DETAIL_LIMIT, safe_exc_detail, safe_exc_text

# Synthetic: a made-up name and MRN, then non-ASCII bytes the codec fails on.
_BAD = b"\xff\xfe\xc3"
_INPUT = b"Zqxsmith MRN7712345 " + _BAD + b" tail"
_START = _INPUT.index(_BAD)
_REASON = "Zqxreason Kv9x7Qz3 secret words"


def _forbidden() -> list[str]:
    """Every form in which the input's bytes or the free-text reason could reach the output."""
    raw = [_INPUT[_START:].decode("latin-1"), "Zqxsmith", "MRN7712345", "tail"]
    # Each non-ASCII byte as repr() escapes it, as a codec error names it, and as latin-1 text.
    forms = [form for b in _BAD for form in (f"\\x{b:02x}", f"0x{b:02x}", chr(b))]
    return [*raw, *forms, "Zqxreason", "Kv9x7Qz3", "secret words"]


def _errors() -> list[UnicodeDecodeError]:
    standard: UnicodeDecodeError | None = None
    try:
        _INPUT.decode("utf-8")
    except UnicodeDecodeError as exc:
        standard = exc
    assert standard is not None
    # Positive control: str() names the byte and the free reason, repr() quotes the whole input, so
    # the assertions below can fail.
    custom = UnicodeDecodeError("utf-8", _INPUT, _START, _START + len(_BAD), _REASON)
    assert "0xff" in str(standard) and _REASON in str(custom) and "\\xff" in repr(custom)
    return [standard, custom]


@pytest.mark.parametrize("exc", _errors(), ids=["codec-raised", "free-text-reason"])
def test_safe_exc_detail_quotes_no_input_byte(exc: UnicodeDecodeError) -> None:
    for out in (safe_exc_detail(exc), safe_exc_detail(exc, limit=DRIVER_DETAIL_LIMIT)):
        assert out.startswith("UnicodeDecodeError")
        for fragment in _forbidden():
            assert fragment not in out, (fragment, out)


@pytest.mark.parametrize("exc", _errors(), ids=["codec-raised", "free-text-reason"])
def test_safe_exc_text_quotes_no_input_byte(exc: UnicodeDecodeError) -> None:
    for out in (safe_exc_text(exc), safe_exc_text(exc, before="could not inspect m: ")):
        assert "UnicodeDecodeError" in out
        for fragment in _forbidden():
            assert fragment not in out, (fragment, out)


def test_harness_scrub_failure_logs_the_type_name_only(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    def broken(exc: BaseException, *, before: str = "") -> str:
        raise RuntimeError("Zqxscrubtext PWD=Kv9x7Qz3")

    monkeypatch.setattr(verify_leaf, "safe_exc_text", broken)
    with caplog.at_level(logging.WARNING, logger=probes.__name__):
        row = probes.scrubbed_exc(OSError("Zqxdetail"), before="cannot write C:\\Zqxpath: ")
    assert "withheld" in row and "Zqxdetail" not in row and "Zqxpath" not in row
    warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
    assert len(warnings) == 1
    logged = warnings[0].getMessage()
    assert "RuntimeError" in logged
    for fragment in ("Zqxscrubtext", "Kv9x7Qz3", "Zqxdetail", "Zqxpath"):
        assert fragment not in logged
