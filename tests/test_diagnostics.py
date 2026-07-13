# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Diagnostic helpers (ADR 0106) — redact-by-default (§9) + never-raise."""

from __future__ import annotations

import logging

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
    monkeypatch.setattr(diag, "_reveal", True)
    with caplog.at_level(logging.DEBUG, logger=_LOGGER):
        log_note("MRN {}", "100")
    assert "100" in caplog.text


def test_log_note_bad_template_never_raises(caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level(logging.DEBUG, logger=_LOGGER):
        log_note("{} {}", "only-one")  # too few args -> IndexError, swallowed
    assert caplog.records  # a fallback line was logged, no exception propagated


def test_checkpoint_logs_segment_ids_not_field_values(caplog: pytest.LogCaptureFixture) -> None:
    m = _msg()
    with caplog.at_level(logging.DEBUG, logger=_LOGGER):
        checkpoint(m, "after parse")
    assert "MSH" in caplog.text  # structural segment ids only
    assert "PID" in caplog.text
    assert "doe" not in caplog.text  # never field values
