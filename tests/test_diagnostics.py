# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Diagnostic helpers (ADR 0106) — redact-by-default (§9) + never-raise."""

from __future__ import annotations

import logging
import sys

import pytest

import messagefoundry.diagnostics as diag
from messagefoundry import checkpoint, log_note
from messagefoundry.parsing.message import Message

_LOGGER = "messagefoundry.diagnostics"

ADT = "MSH|^~\\&|A|B|C|D|20260101||ADT^A01|1|P|2.5.1\rPID|1||100||doe^jane\r"


def _msg() -> Message:
    return Message.parse(ADT)


def test_log_note_redacts_every_value_by_default(caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level(logging.DEBUG, logger=_LOGGER):
        log_note("MRN {} name {}", "100", "doe")
    assert "100" not in caplog.text  # no PHI reaches the log
    assert "doe" not in caplog.text
    assert diag.TRACE_REDACTED in caplog.text  # both operands redacted


def test_log_note_reveals_only_under_the_dev_flag(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """The flag is what this measures, so caplog must be the only handler that sees the record. An
    earlier test can leave a root handler carrying the PHI filter chain, which rewrites the shared
    LogRecord; since BACKLOG #2079 that chain scrubs ``MRN 100``, so this arm went red whenever such
    a test ran first in the same process (``tests/test_asvs_phase0.py`` does).

    That is also what a real process does: once ``configure_logging`` installs the chain, it scrubs
    an ``MRN 100`` note on its way to stdout and the forwarder whatever this flag says, as it already
    did a name or a date. The flag opens ``log_note``'s own redaction and nothing downstream of it."""
    monkeypatch.setattr(diag, "_reveal", True)
    monkeypatch.setattr(logging.getLogger(), "handlers", [caplog.handler])
    with caplog.at_level(logging.DEBUG, logger=_LOGGER):
        log_note("MRN {}", "100")
    assert "100" in caplog.text


def test_log_note_bad_template_never_raises(caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level(logging.DEBUG, logger=_LOGGER):
        log_note("{} {}", "only-one")  # too few args -> IndexError, swallowed
    assert caplog.records  # a fallback line was logged, no exception propagated


@pytest.mark.parametrize(
    ("template", "raised"),
    [
        ("{0.x}", "AttributeError"),  # an attribute the (redacted, str) value lacks
        ("{0[k]}", "TypeError"),  # a str indexed by a non-integer key
        ("{name}", "KeyError"),  # a named slot with no keyword to fill it
        (f"{{:>{sys.maxsize}}}", "MemoryError"),  # a width no allocation can satisfy
        ("{0!z}", "ValueError"),  # an unknown conversion
        (b"{}", "AttributeError"),  # not a str at all: bytes has no .format
    ],
)
def test_log_note_never_raises_on_any_malformed_template(
    template: object, raised: str, caplog: pytest.LogCaptureFixture
) -> None:
    """Every raising path of ``template.format`` is swallowed and logged (vault BACKLOG #2789). At
    INFO the template is not formatted at all (it used to be, so the raise reached a transform at a
    production level too); at DEBUG the fallback names the failure type."""
    for level in (logging.INFO, logging.DEBUG):
        caplog.clear()
        with caplog.at_level(level, logger=_LOGGER):
            log_note(template, "100")  # type: ignore[arg-type]  # a non-str template is one arm
    assert [r.getMessage() for r in caplog.records] == [
        f"log_note: could not format {template!r} with 1 value(s): {raised}"
    ]


def test_log_note_never_raises_on_a_revealed_value_out_of_range(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """A revealed number outside a spec's range raises ``OverflowError`` from the format."""
    monkeypatch.setattr(diag, "_reveal", True)
    monkeypatch.setattr(logging.getLogger(), "handlers", [caplog.handler])
    with caplog.at_level(logging.DEBUG, logger=_LOGGER):
        log_note("{:c}", 10**20)
    assert caplog.text.rstrip().endswith("with 1 value(s): OverflowError")


def test_log_note_fallback_never_quotes_a_revealed_value(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """With the dev reveal on, the fallback still names only the template, the count and the failure
    type, never the value that failed to format."""
    monkeypatch.setattr(diag, "_reveal", True)
    monkeypatch.setattr(logging.getLogger(), "handlers", [caplog.handler])
    with caplog.at_level(logging.DEBUG, logger=_LOGGER):
        log_note("{0.x}", "doe-jane-synthetic")
    assert "could not format" in caplog.text
    assert "doe-jane-synthetic" not in caplog.text


class _RaisingValue:
    """A revealed value whose own ``__format__`` raises, as a deeply nested repr or a domain type can."""

    def __init__(self, exc: BaseException) -> None:
        self.exc = exc

    def __format__(self, spec: str) -> str:
        raise self.exc


class _DomainError(LookupError):
    """A custom exception no fixed list of format failures would name."""


@pytest.mark.parametrize(
    "exc", [RecursionError("maximum recursion depth exceeded"), _DomainError("doe-jane-synthetic")]
)
def test_log_note_never_raises_whatever_a_revealed_value_raises(
    exc: Exception, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """The contract is "never raises", so the catch is Exception, not a list of types (vault BACKLOG
    #2789): a fixed tuple let RecursionError and any domain exception escape into the transform."""
    monkeypatch.setattr(diag, "_reveal", True)
    monkeypatch.setattr(logging.getLogger(), "handlers", [caplog.handler])
    with caplog.at_level(logging.DEBUG, logger=_LOGGER):
        log_note("{}", _RaisingValue(exc))
    assert [r.getMessage() for r in caplog.records] == [
        f"log_note: could not format '{{}}' with 1 value(s): {type(exc).__name__}"
    ]
    assert "doe-jane-synthetic" not in caplog.text  # the exception's text is never logged


def test_log_note_lets_an_interrupt_through(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """Exception, not BaseException: Ctrl-C (and SystemExit, CancelledError) still propagate."""
    monkeypatch.setattr(diag, "_reveal", True)
    with caplog.at_level(logging.DEBUG, logger=_LOGGER), pytest.raises(KeyboardInterrupt):
        log_note("{}", _RaisingValue(KeyboardInterrupt()))


def test_checkpoint_logs_segment_ids_not_field_values(caplog: pytest.LogCaptureFixture) -> None:
    m = _msg()
    with caplog.at_level(logging.DEBUG, logger=_LOGGER):
        checkpoint(m, "after parse")
    assert "MSH" in caplog.text  # structural segment ids only
    assert "PID" in caplog.text
    assert "doe" not in caplog.text  # never field values
