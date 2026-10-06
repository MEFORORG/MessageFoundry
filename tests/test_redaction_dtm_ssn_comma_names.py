# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""``safe_text`` redacts a full HL7 DTM, an ISO date-time, a comma name and a dashed SSN (vault
BACKLOG #2784, review finding G-7).

Each shape below used to come back as written from ``safe_text("PID-7 <value> in future")``: the date
arms ended in ``\\b``, which a time glued to the date removes; the name run joined its tokens with
whitespace alone; and nothing read an SSN. A Handler that quoted one in an exception would, on a first
deployment, have put it into an INFO log line and into ``last_error``. Every value here is synthetic.
"""

from __future__ import annotations

import json
import re

import pytest

from messagefoundry import redaction
from messagefoundry.redaction import clamp_untrusted, redact, redact_untrusted, safe_text
from messagefoundry.support.redact import redact_log_line
from tests.test_redaction import _best_of, _over_window

#: Each shape the row measured, plus the neighbours the same fix covers.
_LEAKED_BEFORE = [
    "198005051230",
    "19800505123000",
    "19800505123000-0500",
    "19800505123000.1234+0530",
    "1980050512",
    "19800505T123000",
    "19800505T1230-0500",
    "1980-05-05T12:30",
    "1980-05-05T12:30:00Z",
    "1980-05-05T12:30:00.123-05:00",
    "Doe, Jane",
    "DOE, JANE",
    "DOE,JANE",
    "Van Doe, Jane Marie",
    "ROE DOE, JANE",
    "123-45-6789",
]

#: The row's controls: shapes the redactor already caught, which must still be caught.
_CAUGHT_BEFORE = ["19800505", "Jane Doe", "1980-05-05", "05/05/1980"]


@pytest.mark.parametrize("value", _LEAKED_BEFORE + _CAUGHT_BEFORE)
def test_safe_text_redacts_the_value_whole(value: str) -> None:
    assert safe_text(f"PID-7 {value} in future") == "PID-7 [redacted] in future"


@pytest.mark.parametrize("value", _LEAKED_BEFORE + _CAUGHT_BEFORE)
def test_the_redaction_is_a_fixed_point(value: str) -> None:
    once = redact(f"PID-7 {value} in future")
    assert redact(once) == once


#: Ordinary engine and operations text that none of the new arms may touch: times without a date,
#: numbers that are not a date opening 19 or 20, a three-three-four phone shape, a comma after a
#: capital followed by a lower-case word, and the reworded list of acknowledgment codes.
_UNTOUCHED = [
    "retry 3/5 scheduled at 04:12:37 (backoff 2.5s)",
    "hl7 version 2.5.1 != expected 2.3",
    "connect 192.0.2.10:2575 failed: WinError 10061",
    "port 2575, retry 3, timeout 30s",
    "Connection refused, retrying in 5s",
    "delivered 12345678901 rows",
    "call 555-123-4567 for support",
    "unknown ack code 'XX' (expected one of AA/AE/AR)",
    "message does not start with an MSH segment or an FHS/BHS batch header",
]


@pytest.mark.parametrize("line", _UNTOUCHED)
def test_ordinary_text_is_not_redacted(line: str) -> None:
    assert redact(line) == line


def test_a_name_with_an_mrn_label_keeps_the_label() -> None:
    """The comma arm reuses the name run's replacement, so an ``MRN`` that ends it stays and the
    number after it is still read."""
    assert redact("DOE, JANE MRN 12345678") == "[redacted] MRN [redacted]"


def test_the_ssn_pass_is_what_catches_a_dashed_ssn(monkeypatch: pytest.MonkeyPatch) -> None:
    """Negative control: with the SSN pass matching nothing, the value walks through again, so the
    positive arm above measures that pass and not another."""
    monkeypatch.setattr(redaction, "_SSN_RUN", re.compile(r"(?!)"))
    assert "123-45-6789" in redact("ssn 123-45-6789 rejected")


# --- a cut at a space inside a comma name ---------------------------------------------------------


def test_a_cut_after_the_comma_drops_the_family_name() -> None:
    """The register on ``_CUT_CHARS`` asks whether a cut at a space inside a span leaves a fragment
    the pattern no longer reads. For a comma name it does: ``ZQXDOE,`` alone is no run. So the walk
    reads a trailing comma as name-shaped and drops the token."""
    text = _over_window(" ZQXDOE, VANJA")
    assert "ZQXDOE" not in clamp_untrusted(text)
    for out in (redact_untrusted(text), safe_text(text, limit=100_000)):
        assert "ZQXDOE" not in out and "VANJA" not in out


def test_without_the_comma_rule_the_cut_keeps_the_family_name(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Negative control for the arm above: a walk that ignores the comma keeps ``ZQXDOE,``."""
    original = redaction._ends_with_name_token
    monkeypatch.setattr(
        redaction,
        "_ends_with_name_token",
        lambda token: not token.endswith(",") and original(token),
    )
    assert "ZQXDOE" in redact_untrusted(_over_window(" ZQXDOE, VANJA"))


# --- log file lines keep their own timestamp ------------------------------------------------------


def test_a_text_log_line_keeps_its_timestamp_and_loses_a_dob_in_its_message() -> None:
    line = "2026-10-06T12:30:00Z INFO     messagefoundry.pipeline: PID-7 19800505123000 in future"
    assert redact_log_line(line) == (
        "2026-10-06T12:30:00Z INFO     messagefoundry.pipeline: PID-7 [redacted] in future"
    )


def test_a_json_log_line_keeps_its_timestamp_and_loses_a_dob_in_its_message() -> None:
    """The JSON format opens every line with its timestamp as the ``time`` key. The ISO arm would read
    it, so ``support.redact`` carves it the way it carves a text line's."""
    record = {
        "time": "2026-10-06T12:30:00Z",
        "level": "INFO",
        "logger": "messagefoundry.pipeline",
        "message": "PID-7 1980-05-05T12:30 in future",
    }
    out = json.loads(redact_log_line(json.dumps(record, ensure_ascii=False)))
    assert out == {**record, "message": "PID-7 [redacted] in future"}


# --- cost -----------------------------------------------------------------------------------------

#: Inputs shaped to make the new arms work hardest: a match every few characters, and near misses
#: that each open an attempt and fail late.
_HOSTILE = {
    "comma-title": "Aa, ",
    "comma-caps": "AA, ",
    "comma-caps-no-space": "AA,",
    "comma-near-miss": "Aa Aa Aa x ",
    "dtm-run": "19800505123000-0500 ",
    "dtm-long-digits": "1980050512345678901 ",
    "iso-run": "1980-05-05T12:30:00.123+05:00 ",
    "iso-near-miss": "1980-05-05Tx ",
    "ssn-run": "123-45-6789 ",
    "ssn-near-miss": "123-45-678x ",
}


@pytest.mark.parametrize("unit", list(_HOSTILE.values()), ids=list(_HOSTILE))
def test_the_new_arms_stay_linear_and_affordable(unit: str) -> None:
    """8x the input must cost well under 64x the time, and a whole window stays well under a second
    on the event loop. The ceiling is the one the other redaction cost arms use."""

    def sized(chars: int) -> str:
        return (unit * (chars // len(unit) + 1))[:chars]

    small, large = sized(8 * 1024), sized(64 * 1024)
    t_small = max(_best_of(lambda: redact(small), 5), 1e-4)
    t_large = _best_of(lambda: redact(large), 5)
    assert t_large / t_small < 24, f"{t_large / t_small:.1f}x for 8x the input on {unit!r}"
    window = sized(redaction._REDACT_WINDOW)
    assert _best_of(lambda: redact(window)) < 0.5


@pytest.mark.parametrize(
    "text",
    ["patient VAN DOE, MARIA DE LOS ANGELES not found", "GARCIA LOPEZ, MARIA JOSE ANA LUCIA"],
)
def test_a_four_token_side_goes_whole(text: str) -> None:
    out = redact(text)
    assert not any(word in out for word in ("ANGELES", "LUCIA", "GARCIA", "MARIA")), out


@pytest.mark.parametrize("text", ["DOE,MRN 12345678", "Doe,Mrn 12345678"])
def test_an_mrn_label_glued_to_the_comma_keeps_its_number_redacted(text: str) -> None:
    assert "12345678" not in redact(text)


@pytest.mark.parametrize("text", ["SSN123-45-6789 rejected", "id_123-45-6789 rejected"])
def test_an_ssn_glued_to_a_word_is_redacted(text: str) -> None:
    assert "6789" not in redact(text)


def test_documented_residual_a_us_date_with_a_time_passes() -> None:
    """DOCUMENTED RESIDUAL, pinned so a change to it is deliberate: the US date arm takes no time."""
    assert redact("at 05/05/1980T12:30 now") == "at 05/05/1980T12:30 now"


@pytest.mark.parametrize(
    "name",
    [
        "mefor-backup-dev-20261006T123000Z.mfbak",
        "mefor-backup-dev-20261006T123000Z.mfbak.part",
        "mefor-backup-dev-20261006T123000Z.mfbak.plain",
        "mefor-backup-dev-20261006T123000Z.corrupt.mfbak",
    ],
)
def test_a_backup_archive_name_is_carved_out(name: str) -> None:
    """The one engine-owned basic-form stamp the date pass leaves, by its ``.mfbak`` suffix."""
    assert redact(f"published {name} ok") == f"published {name} ok"


def test_the_carve_does_not_reach_a_stamp_without_the_suffix() -> None:
    """Control: the same stamp with any other suffix is read as a date-time, and the time's atomic
    group stops a match giving back its ``Z`` to dodge the lookahead."""
    assert redact("dob 20261006T123000Z.txt") == "dob [redacted].txt"
    assert redact("dob 19800505T123000Z") == "dob [redacted]"
    # The carve needs the archive's own shape: a `-` before the date, seconds and `Z` after it.
    assert redact("dob 19800505T123000Z.mfbak") == "dob [redacted].mfbak"
    assert redact("x-19800505T1230.mfbak") == "x-[redacted].mfbak"


def test_an_engine_time_rendered_by_log_timestamp_survives() -> None:
    from datetime import UTC, datetime

    stamp = redaction.log_timestamp(datetime(2026, 10, 6, 12, 30, tzinfo=UTC))
    assert redact(f"CRL not in effect until {stamp}") == f"CRL not in effect until {stamp}"


def test_the_json_carve_matches_what_the_json_formatter_writes() -> None:
    """Pins the carve to the real formatter, not to a hand-built line: a change to the key order,
    the separators or the time format makes this fail instead of silently redacting every JSON
    line's timestamp."""
    import logging

    from messagefoundry.logging_setup import JsonFormatter

    record = logging.LogRecord(
        "messagefoundry.pipeline", logging.INFO, __file__, 1, "PID-7 %s in future", ("x",), None
    )
    line = JsonFormatter().format(record)
    stamp = json.loads(line)["time"]
    assert json.loads(redact_log_line(line))["time"] == stamp
