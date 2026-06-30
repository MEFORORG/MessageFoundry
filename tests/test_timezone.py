# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""DST-aware named-zone HL7 timestamp conversion (Tier 2.4): convert_hl7_timestamp() and to_zone()
shift HL7 v2 timestamps between IANA zones using zoneinfo's DST rules, preserving precision.

All data here is synthetic (fabricated timestamps), never PHI.
"""

from __future__ import annotations

from datetime import date, datetime, timedelta

import pytest

from messagefoundry.timezone import (
    age_from_dob,
    convert_hl7_timestamp,
    hl7_now,
    length_of_stay,
    parse_hl7_timestamp,
    to_zone,
)

EASTERN = "America/New_York"
CENTRAL = "America/Chicago"


# --- DST correctness: the whole point of the helper -------------------------


def test_dst_boundary_offset_differs_by_the_dst_hour() -> None:
    """The same Eastern→Central pair must yield different absolute offsets in winter (EST/CST) vs
    summer (EDT/CDT) — proving the offset is derived from the date, not a flat constant."""
    # January = standard time (EST = UTC-05:00); 09:00 Eastern → 08:00 Central.
    winter = convert_hl7_timestamp("20260115090000", CENTRAL, from_tz=EASTERN)
    # July = daylight time (EDT = UTC-04:00); 09:00 Eastern → 08:00 Central.
    summer = convert_hl7_timestamp("20260715090000", CENTRAL, from_tz=EASTERN)

    # Wall-clock both convert to 08:00 Central (the zones share the 1h gap year-round)...
    assert winter.startswith("20260115080000")
    assert summer.startswith("20260715080000")

    # ...but the trailing offset reflects DST: Central is -0600 in Jan, -0500 in Jul — a 1h difference.
    assert winter.endswith("-0600")
    assert summer.endswith("-0500")
    assert winter[-5:] != summer[-5:]  # the DST hour shows up in the offset


def test_dst_aware_conversion_from_utc_offset() -> None:
    """An instant fixed by an embedded UTC offset lands on the DST-correct Eastern wall-clock."""
    # 2026-01-15 14:00 UTC in winter → 09:00 EST (-0500).
    assert convert_hl7_timestamp("20260115140000+0000", EASTERN) == "20260115090000-0500"
    # 2026-07-15 14:00 UTC in summer → 10:00 EDT (-0400) — same UTC wall-clock, different offset/hour.
    assert convert_hl7_timestamp("20260715140000+0000", EASTERN) == "20260715100000-0400"


def test_to_zone_convenience_matches_convert() -> None:
    assert to_zone("20260715140000+0000", CENTRAL) == convert_hl7_timestamp(
        "20260715140000+0000", CENTRAL
    )
    assert to_zone("20260115140000+0000", EASTERN) == "20260115090000-0500"


# --- precision preservation -------------------------------------------------


@pytest.mark.parametrize(
    ("ts", "expected"),
    [
        ("2026", "2026-0500"),  # year only — offset still applied, no lower fields invented
        ("202601", "202601-0500"),  # year+month
        ("20260115", "20260115-0500"),  # date
        ("2026011509", "2026011509-0500"),  # +hour (no minutes)
        ("202601150930", "202601150930-0500"),  # +minute
        ("20260115093045", "20260115093045-0500"),  # +second
    ],
)
def test_precision_is_preserved(ts: str, expected: str) -> None:
    """Output precision matches input precision; a same-zone conversion only appends the offset."""
    assert convert_hl7_timestamp(ts, EASTERN, from_tz=EASTERN) == expected


def test_fractional_seconds_preserved_verbatim() -> None:
    # Fractional seconds are re-emitted exactly; only the offset/wall-clock changes.
    out = convert_hl7_timestamp("20260115093045.1234+0000", EASTERN)
    assert out == "20260115043045.1234-0500"


def test_hour_precision_conversion_can_cross_midnight() -> None:
    # 00:00 UTC → previous-day 19:00 EST (date rolls back), at hour precision.
    assert convert_hl7_timestamp("2026011500+0000", EASTERN) == "2026011419-0500"


# --- round trip -------------------------------------------------------------


def test_round_trip_eastern_central_eastern() -> None:
    original = "20260715093045-0400"  # EDT
    central = convert_hl7_timestamp(original, CENTRAL)
    back = convert_hl7_timestamp(central, EASTERN)
    assert back == original


def test_embedded_offset_pins_instant_ignoring_from_tz() -> None:
    # When an offset is embedded, from_tz must not change the result (the instant is already fixed).
    with_from = convert_hl7_timestamp("20260115140000+0000", EASTERN, from_tz=CENTRAL)
    without = convert_hl7_timestamp("20260115140000+0000", EASTERN)
    assert with_from == without == "20260115090000-0500"


# --- malformed / error cases (must raise, never silently coerce) ------------


@pytest.mark.parametrize(
    "bad",
    [
        "",  # empty
        "not-a-date",
        "202613",  # impossible month
        "20260230",  # impossible day (Feb 30)
        "20260115250000",  # hour 25
        "2026011509306",  # odd trailing digit (not a valid field width)
        "20260115093045+9999",  # offset minutes out of range
        "2026__15",  # gap: month missing but day present
    ],
)
def test_malformed_input_raises_value_error(bad: str) -> None:
    with pytest.raises(ValueError):
        convert_hl7_timestamp(bad, EASTERN, from_tz=EASTERN)


def test_missing_offset_and_no_from_tz_raises() -> None:
    with pytest.raises(ValueError, match="source zone"):
        convert_hl7_timestamp("20260115093045", EASTERN)


def test_to_zone_requires_embedded_offset() -> None:
    with pytest.raises(ValueError, match="embedded offset"):
        to_zone("20260115093045", EASTERN)


def test_fractional_without_seconds_raises() -> None:
    with pytest.raises(ValueError, match="fractional seconds without seconds"):
        convert_hl7_timestamp("202601150930.5", EASTERN, from_tz=EASTERN)


def test_whitespace_is_tolerated() -> None:
    # Leading/trailing whitespace is stripped (a common artifact of field extraction).
    assert convert_hl7_timestamp("  20260115140000+0000  ", EASTERN) == "20260115090000-0500"


# --- public parse alias -----------------------------------------------------


def test_parse_hl7_timestamp_public_alias_exposes_instant_precision_offset() -> None:
    naive, precision, offset = parse_hl7_timestamp("20260115093045+0100")
    assert naive == datetime(2026, 1, 15, 9, 30, 45)
    assert precision == "second"
    assert offset == "+0100"
    # A partial-precision value reports its precision and no offset.
    naive2, precision2, offset2 = parse_hl7_timestamp("199006")
    assert (naive2.year, naive2.month) == (1990, 6)
    assert precision2 == "month"
    assert offset2 is None


def test_parse_hl7_timestamp_raises_on_malformed() -> None:
    with pytest.raises(ValueError):
        parse_hl7_timestamp("nope")


# --- hl7_now ----------------------------------------------------------------


def test_hl7_now_default_is_a_14_digit_local_second_stamp() -> None:
    out = hl7_now()
    assert len(out) == 14 and out.isdigit()  # no offset for a bare local stamp


@pytest.mark.parametrize(
    ("precision", "length"),
    [("year", 4), ("month", 6), ("day", 8), ("hour", 10), ("minute", 12), ("second", 14)],
)
def test_hl7_now_precision_controls_stem_length(precision: str, length: int) -> None:
    out = hl7_now(precision=precision)
    assert len(out) == length and out.isdigit()


def test_hl7_now_zoned_appends_a_numeric_offset_for_time_precision() -> None:
    out = hl7_now(precision="second", tz=EASTERN)
    # 14-digit stem + a ±HHMM offset; Eastern is -0400 (EDT) or -0500 (EST).
    assert len(out) == 19
    assert out[14] in "+-"
    assert out[-5:] in ("-0400", "-0500")


def test_hl7_now_zoned_date_precision_carries_no_offset() -> None:
    # An offset on a date-only value is nonsensical; the tz only sets which day it is.
    out = hl7_now(precision="day", tz=EASTERN)
    assert len(out) == 8 and out.isdigit()


def test_hl7_now_rejects_bad_precision() -> None:
    with pytest.raises(ValueError, match="precision"):
        hl7_now(precision="century")


# --- age_from_dob -----------------------------------------------------------


def test_age_full_precision_before_and_after_birthday() -> None:
    # Birthday already passed in the reference year.
    assert age_from_dob("19800110", asof="20260115") == 46
    # Birthday not yet reached -> one fewer completed year.
    assert age_from_dob("19800120", asof="20260115") == 45
    # Exactly on the birthday counts as the completed year.
    assert age_from_dob("19800115", asof="20260115") == 46


def test_age_partial_precision_dob_is_conservative() -> None:
    # Year-only DOB -> treated as Jan 1; year+month -> the 1st.
    assert age_from_dob("1990", asof="20260601") == 36
    assert age_from_dob("199006", asof="20260601") == 36
    assert age_from_dob("199007", asof="20260601") == 35  # birthday month not yet reached


def test_age_ignores_time_and_offset_components() -> None:
    assert age_from_dob("19800110093000+0100", asof="20260115") == 46


def test_age_asof_accepts_date_and_datetime_and_defaults_to_today() -> None:
    assert age_from_dob("19800110", asof=date(2026, 1, 15)) == 46
    assert age_from_dob("19800110", asof=datetime(2026, 1, 15, 8, 0)) == 46
    # Default asof=None reads today's local date; a same-year DOB is age 0.
    assert age_from_dob(f"{datetime.now().year:04d}0101") in (0, 0)


def test_age_negative_raises() -> None:
    with pytest.raises(ValueError, match="after the reference date"):
        age_from_dob("20260101", asof="20250101")


def test_age_malformed_dob_raises() -> None:
    with pytest.raises(ValueError):
        age_from_dob("not-a-date", asof="20260101")


# --- length_of_stay ---------------------------------------------------------


def test_los_naive_pair_returns_wall_clock_delta() -> None:
    los = length_of_stay("20260101080000", "20260104120000")
    assert los == timedelta(days=3, hours=4)
    assert los.days == 3


def test_los_partial_precision_day_pair() -> None:
    assert length_of_stay("20260101", "20260105") == timedelta(days=4)


def test_los_offset_pair_accounts_for_zone_difference() -> None:
    # Same wall-clock 12:00, but admit is +0000 and discharge -0500 -> 5h later actual.
    los = length_of_stay("20260101120000+0000", "20260101120000-0500")
    assert los == timedelta(hours=5)


def test_los_mixed_offset_pair_raises() -> None:
    with pytest.raises(ValueError, match="both"):
        length_of_stay("20260101120000+0000", "20260104120000")


def test_los_negative_raises() -> None:
    with pytest.raises(ValueError, match="before admit"):
        length_of_stay("20260104120000", "20260101120000")


def test_los_zero_length_is_allowed() -> None:
    assert length_of_stay("20260101120000", "20260101120000") == timedelta(0)
