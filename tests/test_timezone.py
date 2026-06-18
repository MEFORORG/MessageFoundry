# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""DST-aware named-zone HL7 timestamp conversion (Tier 2.4): convert_hl7_timestamp() and to_zone()
shift HL7 v2 timestamps between IANA zones using zoneinfo's DST rules, preserving precision.

All data here is synthetic (fabricated timestamps), never PHI.
"""

from __future__ import annotations

import pytest

from messagefoundry.timezone import convert_hl7_timestamp, to_zone

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
