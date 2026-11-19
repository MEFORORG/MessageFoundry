# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #5395, last pass: when the harness scrub fails and a log handler's ``emit`` fails too,
``logging``'s ``handleError`` prints the current exception chain to stderr. That output, and the
chain object itself walked past ``__suppress_context__``, must hold neither the scrub failure's
text nor the text of the exception the row is about, whether the caller calls the scrub directly
or from inside its own ``except`` block. The positive controls show that a log call inside the
``except`` block, and one outside it with no chain cut, both leak. All data here is synthetic, and
the planted values are module constants so that no source line ``handleError`` prints in its call
stack spells them."""

from __future__ import annotations

import io
import logging
import sys
from collections.abc import Callable, Iterator

import pytest

import messagefoundry.verify_leaf as verify_leaf
from harness.acceptance import probes

_ORIGINAL = "Zqxorig PWD=Kv9x7Qz3orig"
_SCRUB = "Zqxscrub PWD=Kv9x7Qz3scrub"
_PLANTED = ("Zqxorig", "Kv9x7Qz3orig", "Zqxscrub", "Kv9x7Qz3scrub")


class _FailingEmit(logging.Handler):
    """Fails the way a real stream handler does: inside ``emit``, reporting through
    ``handleError``, which prints the current exception chain to stderr."""

    def __init__(self) -> None:
        super().__init__(logging.DEBUG)
        self.calls = 0
        self.failures: list[BaseException] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.calls += 1
        try:
            raise OSError("Zqxemitfail")
        except OSError as failure:
            self.failures.append(failure)
            self.handleError(record)


def _chain(exc: BaseException) -> list[BaseException]:
    """Every exception reachable through ``__cause__`` and ``__context__``, ignoring
    ``__suppress_context__``, as a chain walker that is not the default printer would."""
    seen: list[BaseException] = []
    pending: list[BaseException] = [exc]
    while pending:
        current = pending.pop()
        if any(current is s for s in seen):
            continue
        seen.append(current)
        pending.extend(e for e in (current.__cause__, current.__context__) if e is not None)
    return seen


def _broken(*_args: object, **_kwargs: object) -> str:
    raise RuntimeError(_SCRUB)


@pytest.fixture
def stderr_of(monkeypatch: pytest.MonkeyPatch) -> Iterator[Callable[[Callable[[], object]], str]]:
    monkeypatch.setattr(verify_leaf, "safe_exc_text", _broken)
    monkeypatch.setattr(verify_leaf, "safe_detail_text", _broken)
    monkeypatch.setattr(logging, "raiseExceptions", True)
    logger = logging.getLogger(probes.__name__)
    handler = _FailingEmit()
    monkeypatch.setattr(logger, "disabled", False)
    monkeypatch.setattr(logger, "level", logging.DEBUG)
    previous = logging.root.manager.disable
    logging.disable(logging.NOTSET)
    logger.addHandler(handler)

    def run(call: Callable[[], object]) -> str:
        before = handler.calls
        buffer = io.StringIO()
        saved = sys.stderr
        sys.stderr = buffer
        try:
            call()
        finally:
            sys.stderr = saved
        # Positive control: the handler ran, failed and printed its report to the captured stderr.
        assert handler.calls == before + 1
        text = buffer.getvalue()
        assert "Zqxemitfail" in text
        # The chain object too, not only what the default printer rendered from it.
        linked = " | ".join(repr(e) for e in _chain(handler.failures[-1]))
        return f"{text}\n{linked}"

    try:
        yield run
    finally:
        logger.removeHandler(handler)
        logging.disable(previous)


def _from_inside_except(scrub: Callable[[BaseException], object]) -> Callable[[], object]:
    def call() -> object:
        try:
            raise OSError(_ORIGINAL)
        except OSError as exc:
            return scrub(exc)

    return call


def _old_in_except_placement(exc: BaseException) -> str:
    """The placement this pass removed: the warning logged inside the ``except`` block."""
    try:
        _broken()
    except RuntimeError as scrub_failure:
        probes._log.warning(
            "the detail scrub failed with %s; a row's %s detail is withheld",
            type(scrub_failure).__name__,
            type(exc).__name__,
        )
    return "withheld"


def _outside_except_without_cut(exc: BaseException) -> str:
    """The log call with no ``except`` block of its own and no chain cut, so a caller's exception
    stays current at it."""
    probes._log.warning("the detail scrub failed; a row's %s detail is withheld", "OSError")
    return "withheld"


@pytest.mark.parametrize("typed", [False, True])
def test_a_failing_handler_prints_no_planted_text_to_stderr_on_a_direct_call(
    stderr_of: Callable[[Callable[[], object]], str], typed: bool
) -> None:
    original = OSError(_ORIGINAL)
    text = stderr_of(lambda: probes.scrubbed_exc(original, typed=typed))
    for fragment in _PLANTED:
        assert fragment not in text


@pytest.mark.parametrize("typed", [False, True])
def test_a_failing_handler_prints_no_planted_text_when_called_inside_an_except(
    stderr_of: Callable[[Callable[[], object]], str], typed: bool
) -> None:
    text = stderr_of(_from_inside_except(lambda exc: probes.scrubbed_exc(exc, typed=typed)))
    for fragment in _PLANTED:
        assert fragment not in text


def test_control_the_old_in_except_placement_leaks_the_scrub_failure(
    stderr_of: Callable[[Callable[[], object]], str],
) -> None:
    original = OSError(_ORIGINAL)
    text = stderr_of(lambda: _old_in_except_placement(original))
    assert "Zqxscrub" in text and "Kv9x7Qz3scrub" in text


def test_control_a_log_outside_the_except_with_no_cut_leaks_the_callers_exception(
    stderr_of: Callable[[Callable[[], object]], str],
) -> None:
    text = stderr_of(_from_inside_except(_outside_except_without_cut))
    assert "Zqxorig" in text and "Kv9x7Qz3orig" in text
