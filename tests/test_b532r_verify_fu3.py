# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #5395, last pass: the two verify_leaf renderers quote no character of a Unicode error's
input, which is what lets ``tests/test_unicode_error_log_paths.py`` allow them, and the harness
scrub logs its own failure by type name only. All data here is synthetic."""

from __future__ import annotations

import logging
from collections.abc import Callable, Iterator

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


_FILTER_ORIG = "Zqxfiltorig PWD=Kv9x7Qz3filt"
_FILTER_SCRUB = "Zqxfiltscrub PWD=Kv9x7Qz3fscr"
_FILTER_PLANTED = ("Zqxfiltorig", "Kv9x7Qz3filt", "Zqxfiltscrub", "Kv9x7Qz3fscr")


def _direct(typed: bool) -> str:
    return probes.scrubbed_exc(OSError(_FILTER_ORIG), before="Zqxfiltorig ", typed=typed)


def _inside_except(typed: bool) -> str:
    try:
        raise OSError(_FILTER_ORIG)
    except OSError as exc:
        return probes.scrubbed_exc(exc, before="Zqxfiltorig ", typed=typed)


@pytest.mark.parametrize("typed", [False, True])
@pytest.mark.parametrize("call", [_direct, _inside_except], ids=["direct", "inside_except"])
def test_a_raising_log_filter_is_dropped_by_the_harness_scrub(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    typed: bool,
    call: Callable[[bool], str],
) -> None:
    """The log call is the scrub's last resort, so a filter that raises inside it must not escape:
    an escape would leave ``run_probe``'s catch-all and abort ``run_matrix``, carrying frames that
    hold the raw text. ``ran`` is the positive control that the filter was called and raised."""

    def broken(*_args: object, **_kwargs: object) -> str:
        raise RuntimeError(_FILTER_SCRUB)

    ran: list[str] = []

    def refuse(record: logging.LogRecord) -> bool:
        ran.append(record.getMessage())
        raise ValueError("the filter refuses")

    monkeypatch.setattr(verify_leaf, "safe_exc_text", broken)
    monkeypatch.setattr(verify_leaf, "safe_detail_text", broken)
    monkeypatch.setattr(logging, "raiseExceptions", True)
    logger = logging.getLogger(probes.__name__)
    monkeypatch.setattr(logger, "disabled", False)
    monkeypatch.setattr(logger, "level", logging.DEBUG)
    previous = logging.root.manager.disable
    logging.disable(logging.NOTSET)
    logger.addFilter(refuse)
    try:
        row = call(typed)
    finally:
        logger.removeFilter(refuse)
        logging.disable(previous)
    assert len(ran) == 1 and "RuntimeError" in ran[0] and "OSError" in ran[0]
    assert row == "OSError (detail withheld: the detail scrub failed with RuntimeError)"
    captured = capsys.readouterr()
    for fragment in _FILTER_PLANTED:
        assert fragment not in row
        assert fragment not in captured.err
        assert fragment not in ran[0]
