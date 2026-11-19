# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #5395, last pass: the two verify_leaf renderers quote no character of a Unicode error's
input, which is what lets ``tests/test_unicode_error_log_paths.py`` allow them, and the harness
scrub logs its own failure by type name only. All data here is synthetic."""

from __future__ import annotations

import logging
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from typing import Any

import pytest

import messagefoundry.verify_leaf as verify_leaf
from harness.acceptance import probes
from harness.acceptance.matrix import Status
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


@contextmanager
def _raising_log_call(
    monkeypatch: pytest.MonkeyPatch,
    where: str,
    ran: list[str],
    error: Callable[[str], BaseException] = ValueError,
) -> Iterator[None]:
    """A broken scrub, and a log call on the probes logger that raises ``error`` from ``where``: a
    logger filter, or the record factory. Each appends the formatted message to ``ran`` first,
    which is the positive control that it was called. The factory is process-global, so it
    intercepts only the probes logger's records and hands every other logger's to the previous
    factory."""

    def broken(*_args: object, **_kwargs: object) -> str:
        raise RuntimeError(_FILTER_SCRUB)

    def refuse(record: logging.LogRecord) -> bool:
        ran.append(record.getMessage())
        raise error("the filter refuses")

    previous_factory = logging.getLogRecordFactory()

    def factory(*args: Any, **kwargs: Any) -> logging.LogRecord:
        if args[0] != probes.__name__:
            return previous_factory(*args, **kwargs)
        ran.append(args[4] % args[5])
        raise error("the factory refuses")

    monkeypatch.setattr(verify_leaf, "safe_exc_text", broken)
    monkeypatch.setattr(verify_leaf, "safe_detail_text", broken)
    logger = logging.getLogger(probes.__name__)
    monkeypatch.setattr(logger, "disabled", False)
    monkeypatch.setattr(logger, "level", logging.DEBUG)
    previous = logging.root.manager.disable
    logging.disable(logging.NOTSET)
    if where == "filter":
        logger.addFilter(refuse)
    elif where == "factory":
        logging.setLogRecordFactory(factory)
    else:
        raise AssertionError(f"unknown raiser {where!r}")
    try:
        yield
    finally:
        logger.removeFilter(refuse)
        logging.setLogRecordFactory(previous_factory)
        logging.disable(previous)


_STDERR_LINE = (
    "harness.acceptance.probes: the scrub-failure warning's log call raised 'ValueError'; the "
    "scrub failed with 'RuntimeError', and the row's 'OSError' detail is withheld\n"
)


def _assert_nothing_planted(row: str, err: str, ran: list[str]) -> None:
    assert len(ran) == 1 and "RuntimeError" in ran[0] and "OSError" in ran[0]
    # Positive control for the stderr capture, and the whole of what was written: one line.
    assert err == _STDERR_LINE
    for fragment in (*_FILTER_PLANTED, "refuses"):
        assert fragment not in row
        assert fragment not in err
        assert fragment not in ran[0]


@pytest.mark.parametrize("where", ["filter", "factory"])
@pytest.mark.parametrize("typed", [False, True])
@pytest.mark.parametrize("call", [_direct, _inside_except], ids=["direct", "inside_except"])
def test_a_raising_log_call_is_dropped_by_the_harness_scrub(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    where: str,
    typed: bool,
    call: Callable[[bool], str],
) -> None:
    """The log call is the scrub's last resort, so a filter or record factory that raises inside it
    must not escape: an escape would leave ``run_probe``'s catch-all and abort ``run_matrix``,
    carrying frames that hold the raw text."""
    ran: list[str] = []
    with _raising_log_call(monkeypatch, where, ran):
        row = call(typed)
    assert row == "OSError (detail withheld: the detail scrub failed with RuntimeError)"
    _assert_nothing_planted(row, capsys.readouterr().err, ran)


def test_run_probe_reports_an_error_row_when_the_scrub_and_its_log_both_fail(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The contract the drop protects: ``run_probe`` returns a row rather than raising."""

    def raising_probe() -> probes.ProbeResult:
        raise OSError(_FILTER_ORIG)

    monkeypatch.setitem(probes.PROBES, "zqx_raising", raising_probe)
    ran: list[str] = []
    with _raising_log_call(monkeypatch, "filter", ran):
        result = probes.run_probe("zqx_raising")
    assert result.status is Status.ERROR
    assert result.detail == "OSError (detail withheld: the detail scrub failed with RuntimeError)"
    _assert_nothing_planted(result.detail, capsys.readouterr().err, ran)


def test_a_base_exception_from_the_log_call_still_propagates(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The documented boundary: only an ``Exception`` is dropped, so an interrupt is not
    swallowed. ``ran`` shows the filter, not something before it, raised the interrupt."""
    ran: list[str] = []
    with (
        _raising_log_call(monkeypatch, "filter", ran, KeyboardInterrupt),
        pytest.raises(KeyboardInterrupt, match="the filter refuses"),
    ):
        probes.scrubbed_exc(OSError(_FILTER_ORIG))
    assert len(ran) == 1
    assert capsys.readouterr().err == ""
