# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #5395, last pass: the two verify_leaf renderers quote no character of a Unicode error's
input, which is what lets ``tests/test_unicode_error_log_paths.py`` allow them, and the harness
scrub logs its own failure by type name only. All data here is synthetic."""

from __future__ import annotations

import logging
from collections.abc import Iterator

import pytest

import messagefoundry.verify_leaf as verify_leaf
from harness.acceptance import probes
from messagefoundry.verify_leaf import DRIVER_DETAIL_LIMIT, safe_exc_detail, safe_exc_text
from tests._content_free import escapes

# Synthetic: a made-up name and MRN, then non-ASCII bytes the codec fails on.
_BAD = b"\xff\xfe\xc3"
_INPUT = b"Zqxsmith MRN7712345 " + _BAD + b" Zqxtail"
_START = _INPUT.index(_BAD)
_TEXT = _INPUT.decode("latin-1")
_REASON = "Zqxreason Kv9x7Qz3 secret words"


def _forbidden() -> list[str]:
    """At least these forms in which the input or the free-text reason could reach the output: the
    planted words, and each non-ASCII byte in every spelling ``escapes`` names, plus ``0xNN``, which a
    decode error uses."""
    planted = ["Zqxsmith", "MRN7712345", "Zqxtail", "Zqxreason", "Kv9x7Qz3", "secret words"]
    forms = [form for b in _BAD for form in (*escapes(chr(b)), f"0x{b:02x}")]
    return [*planted, *forms]


def _raised_decode() -> UnicodeDecodeError:
    try:
        _INPUT.decode("utf-8")
    except UnicodeDecodeError as exc:
        return exc
    raise AssertionError("the synthetic input decoded")


def _raised_encode() -> UnicodeEncodeError:
    try:
        _TEXT.encode("ascii")
    except UnicodeEncodeError as exc:
        return exc
    raise AssertionError("the synthetic text encoded")


def _errors() -> Iterator[BaseException]:
    end = _START + len(_BAD)
    decode = _raised_decode()
    yield decode
    yield UnicodeDecodeError("utf-8", _INPUT, _START, end, _REASON)
    yield _raised_encode()
    yield UnicodeEncodeError("ascii", _TEXT, _START, end, _REASON)
    yield UnicodeTranslateError(_TEXT, _START, end, _REASON)
    yield UnicodeError(_TEXT, _REASON)
    # A broad arm also receives an exception that holds one, whose str() is the codec error's own.
    yield RuntimeError(decode)


_IDS = [
    "decode",
    "decode-free-reason",
    "encode",
    "encode-free-reason",
    "translate",
    "bare",
    "holder",
]


def test_the_positive_control_quotes_the_input() -> None:
    """Every case's own str() or repr() quotes something the tests below forbid, so they can fail."""
    forbidden = _forbidden()
    for exc in _errors():
        raw = str(exc) + repr(exc)
        assert any(fragment in raw for fragment in forbidden), exc


@pytest.mark.parametrize("exc", list(_errors()), ids=_IDS)
def test_safe_exc_detail_quotes_no_input_byte(exc: BaseException) -> None:
    for out in (safe_exc_detail(exc), safe_exc_detail(exc, limit=DRIVER_DETAIL_LIMIT)):
        assert out.startswith(type(exc).__name__)
        for fragment in _forbidden():
            assert fragment not in out, (fragment, out)


@pytest.mark.parametrize("exc", list(_errors()), ids=_IDS)
def test_safe_exc_text_quotes_no_input_byte(exc: BaseException) -> None:
    for out in (safe_exc_text(exc), safe_exc_text(exc, before="could not inspect m: ")):
        for fragment in _forbidden():
            assert fragment not in out, (fragment, out)


class _Collect(logging.Handler):
    """A handler on the emitting logger itself, so the capture does not depend on propagation or
    the root's level, which caplog does and which has lost records under xdist in this suite."""

    def __init__(self) -> None:
        super().__init__(logging.DEBUG)
        self.records: list[logging.LogRecord] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.records.append(record)


@pytest.mark.parametrize("typed", [False, True])
def test_harness_scrub_failure_logs_the_type_names_only(
    monkeypatch: pytest.MonkeyPatch, typed: bool
) -> None:
    def broken(*_args: object, **_kwargs: object) -> str:
        raise RuntimeError("Zqxscrubtext PWD=Kv9x7Qz3")

    monkeypatch.setattr(verify_leaf, "safe_exc_text", broken)
    monkeypatch.setattr(verify_leaf, "safe_detail_text", broken)
    logger = logging.getLogger(probes.__name__)
    collect = _Collect()
    monkeypatch.setattr(logger, "disabled", False)
    monkeypatch.setattr(logger, "level", logging.DEBUG)
    logger.addHandler(collect)
    previous = logging.root.manager.disable
    logging.disable(logging.NOTSET)
    try:
        row = probes.scrubbed_exc(
            OSError("Zqxdetail"), before="cannot write C:\\Zqxpath: ", typed=typed
        )
    finally:
        logging.disable(previous)
        logger.removeHandler(collect)
    assert "withheld" in row and "Zqxdetail" not in row and "Zqxpath" not in row
    warnings = [r for r in collect.records if r.levelno == logging.WARNING]
    assert len(warnings) == 1
    logged = warnings[0].getMessage()
    assert "RuntimeError" in logged and "OSError" in logged
    for fragment in ("Zqxscrubtext", "Kv9x7Qz3", "Zqxdetail", "Zqxpath"):
        assert fragment not in logged


def test_a_raising_log_filter_propagates_from_the_harness_scrub(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A raising filter is not silently swallowed (CLAUDE.md section 6). ``ran`` is the positive
    control: the ValueError is the filter's, not one raised before the log call."""

    def broken(*_args: object, **_kwargs: object) -> str:
        raise RuntimeError("Zqxscrubtext")

    ran: list[str] = []

    def refuse(record: logging.LogRecord) -> bool:
        ran.append(record.getMessage())
        raise ValueError("the filter refuses")

    monkeypatch.setattr(verify_leaf, "safe_exc_text", broken)
    logger = logging.getLogger(probes.__name__)
    monkeypatch.setattr(logger, "disabled", False)
    monkeypatch.setattr(logger, "level", logging.DEBUG)
    previous = logging.root.manager.disable
    logging.disable(logging.NOTSET)
    logger.addFilter(refuse)
    try:
        with pytest.raises(ValueError, match="the filter refuses"):
            probes.scrubbed_exc(OSError("Zqxdetail"))
    finally:
        logger.removeFilter(refuse)
        logging.disable(previous)
    assert len(ran) == 1 and "RuntimeError" in ran[0] and "Zqxdetail" not in ran[0]
