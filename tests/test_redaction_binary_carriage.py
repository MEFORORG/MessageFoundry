# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #5378: an ``mfb64:v1:`` binary-carriage body quoted in a log record or exception is
withheld by the write-time log scrub, and by the support bundle with the same pattern. Synthetic HL7
only (CLAUDE.md section 9)."""

from __future__ import annotations

import logging
import sys

import pytest

from messagefoundry import logging_setup
from messagefoundry.parsing.binary import MARKER, encode
from messagefoundry.redaction import _BINARY_CARRIAGE, redact, redact_untrusted, safe_text
from messagefoundry.support.redact import redact_log_line

_BODY = b"MSH|^~\\&|SND|FAC|RCV|FAC|20260101||ADT^A01|MSG1|P|2.5\rPID|1||SYN123^^^H||ZZTEST^ALPHA\rNTE|1||A??>\r"
_CARRIAGE = encode(_BODY)
_PAYLOAD = _CARRIAGE.removeprefix(MARKER)
_KEPT = "mfb64:v1:[redacted]"
_JSON_ESCAPED = _CARRIAGE.replace("/", "\\/")
_PERCENT_RUN = _CARRIAGE.replace("+", "%2B").replace("/", "%2F").replace("=", "%3D")
_PERCENT_ALL = _PERCENT_RUN.replace(":", "%3A")
_UNICODE_ESCAPED = (
    _CARRIAGE.replace("+", "\\u002B").replace("/", "\\u002f").replace("=", "\\u003D")
).replace(":", "\\u003A")


def test_the_payload_holds_every_character_the_run_reads_encoded() -> None:
    """Non-vacuity for the encoded cases below: each has something to encode."""
    assert {"+", "/", "="} <= set(_PAYLOAD)


def test_the_literal_marker_is_the_carriage_marker() -> None:
    assert _BINARY_CARRIAGE.fullmatch(MARKER + "QQ==") is not None
    assert MARKER == "mfb64:v1:"


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        (f"could not route {_CARRIAGE}", f"could not route {_KEPT}"),
        (f"could not route {_CARRIAGE} after retry", f"could not route {_KEPT} after retry"),
        (repr(_CARRIAGE), f"'{_KEPT}'"),
        (f'{{"raw": "{_JSON_ESCAPED}"}}', f'{{"raw": "{_KEPT}"}}'),
        (f"body {_PERCENT_RUN} end", f"body {_KEPT} end"),
        (f"body {_PERCENT_ALL} end", "body mfb64%3Av1%3A[redacted] end"),
        (f"body {_CARRIAGE.upper()} end", "body MFB64:V1:[redacted] end"),
        (f"body {_UNICODE_ESCAPED} end", "body mfb64\\u003Av1\\u003A[redacted] end"),
    ],
    ids=[
        "plain",
        "mid-line",
        "repr",
        "json-escaped",
        "percent-run",
        "percent-marker",
        "upper",
        "unicode-escaped",
    ],  # fmt: skip
)
def test_a_carriage_payload_is_withheld_whole(text: str, expected: str) -> None:
    out = redact_untrusted(text)
    assert out == expected
    assert redact(out) == out


def test_prose_naming_the_marker_is_kept() -> None:
    text = "not a binary-carriage value (missing mfb64:v1: marker); check .is_binary first"
    assert redact(text) == text


def test_safe_text_withholds_a_carriage() -> None:
    assert _PAYLOAD[:12] not in safe_text(f"bad {_CARRIAGE}")


def _through_the_shipped_filters(record: logging.LogRecord) -> str:
    handler = logging.NullHandler()
    logging_setup._install_phi_filters(handler)
    for flt in handler.filters:
        assert isinstance(flt, logging.Filter)
        assert flt.filter(record)
    return logging.Formatter().format(record)


def test_the_shipped_log_filters_withhold_a_carriage_in_message_and_traceback() -> None:
    record = logging.LogRecord("mf.test", logging.ERROR, __file__, 1, "body %s", (_CARRIAGE,), None)
    try:
        raise ValueError(f"cannot decode {_CARRIAGE}")
    except ValueError:
        record.exc_info = sys.exc_info()
    rendered = _through_the_shipped_filters(record)
    assert _PAYLOAD[:12] not in rendered
    assert rendered.count(_KEPT) == 2


#: Not ``_``: ``QUJDRA==_Password: v`` prints its value with this rule switched off too, a
#: credential-filter gap of its own, outside BACKLOG #5378.
@pytest.mark.parametrize("glue", ["\\n", "\\r\\n", " ", "-", "", "/", "+", "="])
def test_a_credential_label_after_a_carriage_still_reaches_the_credential_filter(glue: str) -> None:
    """Found by code review rounds 1 and 2: a run that read ``\\``, ``-`` or ``_``, or ran on past
    its padding, swallowed the label, and the credential filter then had no label to find the
    value by. The run ends at its padding, so glue in the base64 alphabet after it is kept too."""
    record = logging.LogRecord(
        "mf.test",
        logging.ERROR,
        __file__,
        1,
        "dump %r",
        (f"{MARKER}QUJDRA=={glue}Password: zqsecretvalue",),
        None,
    )
    rendered = _through_the_shipped_filters(record)
    assert "zqsecretvalue" not in rendered
    assert "QUJDRA" not in rendered


@pytest.mark.parametrize("glue", ["", "/", " "], ids=["glued", "slash", "space"])
def test_an_mrn_label_after_a_padded_carriage_keeps_its_value_withheld(glue: str) -> None:
    out = safe_text(f"bad {MARKER}QUJDRA=={glue}MRN: 12345678")
    assert "12345678" not in out
    assert "QUJDRA" not in out


@pytest.mark.parametrize(
    "carriage",
    [_CARRIAGE, _JSON_ESCAPED, _PERCENT_RUN, _PERCENT_ALL, _UNICODE_ESCAPED],
    ids=["plain", "json-escaped", "percent-run", "percent-marker", "unicode-escaped"],
)
def test_the_support_bundle_withholds_the_same_forms(carriage: str) -> None:
    """The bundle's own carriage rule is the shared pattern, so it cuts an encoded run whole too."""
    out = redact_log_line(f"2026-01-01 00:00:00 ERROR bad {carriage} end")
    for at in range(0, len(_PAYLOAD) - 8, 4):
        assert _PAYLOAD[at : at + 8] not in out
    assert "%2B" not in out and "\\/" not in out
