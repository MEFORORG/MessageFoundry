# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""DST-aware named-zone HL7 timestamp conversion (Tier 2.4): convert_hl7_timestamp() and to_zone()
shift HL7 v2 timestamps between IANA zones using zoneinfo's DST rules, preserving precision.

Includes the daylight-saving edges (BACKLOG #1686): a wall time that occurs twice or never is refused
rather than silently resolved, and the opt-in resolutions are pinned either way.

All data here is synthetic (fabricated timestamps), never PHI.
"""

from __future__ import annotations

from datetime import date, datetime, timedelta
from zoneinfo import ZoneInfoNotFoundError

import pytest

from messagefoundry.timezone import (
    AmbiguousLocalTimeError,
    DstTransitionError,
    NonExistentLocalTimeError,
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


# --- DST edges: a wall time that happens twice, or never (BACKLOG #1686) -----
#
# A named source zone only pins an instant for wall-clock times that happen exactly once. On the two
# transition days it does not, and the old code resolved both silently via datetime.replace()'s
# implicit fold=0 — emitting a well-formed timestamp that could be an hour wrong. These pin the
# refusal and the opt-in resolutions. America/Chicago 2026: the spring-forward gap is 02:00-03:00 on
# March 8, the fall-back overlap is 01:00-02:00 on November 1.

AMBIGUOUS_CENTRAL = "20261101013000"  # 01:30 on fall-back day — occurs twice
NONEXISTENT_CENTRAL = "20260308023000"  # 02:30 on spring-forward day — never occurs
NO_DST = "Asia/Kolkata"  # fixed UTC+05:30, no transitions ever — the negative control


def test_ambiguous_local_time_raises_rather_than_picking_one() -> None:
    # 01:30 Central on the fall-back day happens twice and the timestamp carries no offset to say
    # which. Guessing yields a plausible, well-formed, possibly hour-wrong clinical time.
    with pytest.raises(AmbiguousLocalTimeError) as excinfo:
        convert_hl7_timestamp(AMBIGUOUS_CENTRAL, "UTC", from_tz=CENTRAL)
    assert excinfo.value.ts == AMBIGUOUS_CENTRAL
    assert excinfo.value.tz == CENTRAL


def test_nonexistent_local_time_raises_rather_than_inventing_an_instant() -> None:
    # 02:30 Central on the spring-forward day never happened — as impossible as Feb 30, which this
    # module already rejects.
    with pytest.raises(NonExistentLocalTimeError) as excinfo:
        convert_hl7_timestamp(NONEXISTENT_CENTRAL, "UTC", from_tz=CENTRAL)
    assert excinfo.value.ts == NONEXISTENT_CENTRAL
    assert excinfo.value.tz == CENTRAL


def test_dst_edge_errors_are_value_errors() -> None:
    # Both subclass ValueError, so a caller already guarding this module's malformed-input path keeps
    # catching them; only code that wants the distinction needs the new names. The two tests above
    # already pin that these are what gets raised, so this states the hierarchy and nothing else.
    assert issubclass(AmbiguousLocalTimeError, DstTransitionError)
    assert issubclass(NonExistentLocalTimeError, DstTransitionError)
    assert issubclass(DstTransitionError, ValueError)


def test_ambiguous_opt_in_resolutions_differ_by_exactly_one_hour() -> None:
    # "earlier"/"later" name the offset in force before/after the transition. For an overlap those
    # are the first (CDT, -0500) and second (CST, -0600) occurrence of the same wall clock.
    # The two differ by exactly the DST hour, and "earlier" reproduces the pre-fix fold=0 reading —
    # now chosen by the caller rather than defaulted into.
    earlier = convert_hl7_timestamp(
        AMBIGUOUS_CENTRAL, "UTC", from_tz=CENTRAL, on_dst_edge="earlier"
    )
    later = convert_hl7_timestamp(AMBIGUOUS_CENTRAL, "UTC", from_tz=CENTRAL, on_dst_edge="later")
    assert earlier == "20261101063000+0000"
    assert later == "20261101073000+0000"


def test_nonexistent_opt_in_resolutions_invert_because_the_wall_time_never_happened() -> None:
    # For a gap the naming inverts, and the docstring says so: "earlier" keeps the PRE-gap offset
    # (CST) and so lands after the gap; "later" keeps the POST-gap offset (CDT) and lands before it.
    # The exact values below pin that inversion, so an edit that quietly swapped them would fail.
    earlier = convert_hl7_timestamp(
        NONEXISTENT_CENTRAL, "UTC", from_tz=CENTRAL, on_dst_edge="earlier"
    )
    later = convert_hl7_timestamp(NONEXISTENT_CENTRAL, "UTC", from_tz=CENTRAL, on_dst_edge="later")
    assert earlier == "20260308083000+0000"
    assert later == "20260308073000+0000"


@pytest.mark.parametrize(
    ("ts", "expected"),
    [
        # Either side of the fall-back overlap (01:00-02:00 Nov 1) — both happen exactly once.
        ("20261101003000", "20261101053000+0000"),  # 00:30 CDT, before
        ("20261101033000", "20261101093000+0000"),  # 03:30 CST, after
        # Either side of the spring-forward gap (02:00-03:00 Mar 8).
        ("20260308013000", "20260308073000+0000"),  # 01:30 CST, before
        ("20260308033000", "20260308083000+0000"),  # 03:30 CDT, after
    ],
)
def test_ordinary_times_beside_each_transition_still_convert(ts: str, expected: str) -> None:
    # The normal path must be untouched: only the two unresolvable wall times change behaviour.
    assert convert_hl7_timestamp(ts, "UTC", from_tz=CENTRAL) == expected


def test_a_zone_without_dst_never_trips_the_check() -> None:
    # Asia/Kolkata has no transitions, so no wall time is ever ambiguous or missing there — including
    # the very clock readings that are unresolvable in Central.
    assert convert_hl7_timestamp(AMBIGUOUS_CENTRAL, "UTC", from_tz=NO_DST) == "20261031200000+0000"
    assert (
        convert_hl7_timestamp(NONEXISTENT_CENTRAL, "UTC", from_tz=NO_DST) == "20260307210000+0000"
    )


def test_an_embedded_offset_in_the_ambiguous_hour_is_never_refused() -> None:
    # The sender's own offset already says which occurrence it meant, so there is nothing to resolve.
    assert convert_hl7_timestamp("20261101013000-0500", "UTC") == "20261101063000+0000"
    assert convert_hl7_timestamp("20261101013000-0600", "UTC") == "20261101073000+0000"


def test_date_precision_on_a_transition_day_is_not_refused() -> None:
    # Below hour precision the time fields are this module's own "00" filler, not anything the sender
    # wrote — there is no sender-asserted wall time to call ambiguous.
    assert convert_hl7_timestamp("20261101", "UTC", from_tz=CENTRAL) == "20261101+0000"
    assert convert_hl7_timestamp("20260308", "UTC", from_tz=CENTRAL) == "20260308+0000"


def test_date_precision_still_honours_an_explicit_policy_in_a_midnight_transition_zone() -> None:
    # A few zones transition AT midnight, so even the "00" filler can be ambiguous — and there it
    # moves the emitted calendar DATE, not just the offset. America/Havana falls back at 01:00 on
    # 2026-11-01, making local 00:00 occur twice. The default must never refuse a date, but a caller
    # who passed a policy asked for it, so it is applied rather than silently dropped.
    havana, cancun = "America/Havana", "America/Cancun"
    assert convert_hl7_timestamp("20261101", cancun, from_tz=havana) == "20261031-0500"
    assert (
        convert_hl7_timestamp("20261101", cancun, from_tz=havana, on_dst_edge="earlier")
        == "20261031-0500"
    )
    assert (
        convert_hl7_timestamp("20261101", cancun, from_tz=havana, on_dst_edge="later")
        == "20261101-0500"
    )


def test_hour_precision_inside_the_overlap_is_refused() -> None:
    # 01:00 Central on the fall-back day is a real sender-supplied wall time, and it occurs twice.
    with pytest.raises(AmbiguousLocalTimeError):
        convert_hl7_timestamp("2026110101", "UTC", from_tz=CENTRAL)


def test_unknown_dst_edge_policy_raises() -> None:
    with pytest.raises(ValueError, match="on_dst_edge"):
        convert_hl7_timestamp(
            "20260115090000",
            "UTC",
            from_tz=CENTRAL,
            on_dst_edge="fold0",  # type: ignore[arg-type]
        )


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


def test_hl7_now_with_offset_appends_the_hosts_own_offset() -> None:
    # BACKLOG #1196: a caller stamping a value another system will correlate needs an instant, not a
    # bare wall clock, and cannot always name an IANA zone. Pin the offset value, not just the shape.
    out = hl7_now(with_offset=True)
    assert len(out) == 19 and out[14] in "+-"
    host_offset = datetime.now().astimezone().utcoffset()
    assert host_offset is not None
    total = int(host_offset.total_seconds() // 60)
    sign = "+" if total >= 0 else "-"
    assert out[14:] == f"{sign}{abs(total) // 60:02d}{abs(total) % 60:02d}"


def test_hl7_now_with_offset_is_ignored_for_date_precision() -> None:
    # Same rule the tz path already follows: an offset on a date-only value is nonsensical.
    out = hl7_now(precision="day", with_offset=True)
    assert len(out) == 8 and out.isdigit()


def test_hl7_now_tz_wins_over_with_offset() -> None:
    # A named zone already appends its own offset; with_offset must not double-stamp or override it.
    out = hl7_now(precision="second", tz=EASTERN, with_offset=True)
    assert len(out) == 19
    assert out[-5:] in ("-0400", "-0500")


def test_hl7_now_default_still_carries_no_offset() -> None:
    # The new keyword must not change the default: existing callers keep the bare local stamp.
    assert hl7_now().isdigit()


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


def test_los_naive_time_pair_without_zone_is_refused() -> None:
    """BACKLOG #1770: a bare wall-clock difference is an hour wrong across a DST change, so an
    offset-free pair with a time of day is refused rather than measured. (This pair once returned
    3 days 4 hours; the zoned form below still does, because no transition falls inside it.)"""
    with pytest.raises(ValueError, match="needs a zone"):
        length_of_stay("20260101080000", "20260104120000")


def test_los_naive_time_pair_with_zone_returns_elapsed_time() -> None:
    los = length_of_stay("20260101080000", "20260104120000", zone=EASTERN)
    assert los == timedelta(days=3, hours=4)
    assert los.days == 3


def test_los_naive_pair_spanning_spring_forward_is_elapsed_not_wall_clock() -> None:
    """The row's first measured pair. Wall clock says 48 h; the clocks sprang forward on 2026-03-08,
    so the patient stayed 47 h. Two datetimes sharing one ZoneInfo would subtract as wall clock, so
    this pins that the function goes through UTC."""
    los = length_of_stay("202603071200", "202603091200", zone=EASTERN)
    assert los == timedelta(hours=47)
    # Agrees with the same stay stamped with its offsets.
    assert length_of_stay("202603071200-0500", "202603091200-0400") == timedelta(hours=47)


def test_los_naive_pair_spanning_fall_back_is_elapsed_not_wall_clock() -> None:
    """The row's second measured pair: 48 h of wall clock across the 2026-11-01 fall-back is 49 h."""
    los = length_of_stay("202610311200", "202611021200", zone=EASTERN)
    assert los == timedelta(hours=49)
    assert length_of_stay("202610311200-0400", "202611021200-0500") == timedelta(hours=49)


def test_los_naive_time_pair_spanning_dst_without_zone_is_refused() -> None:
    for admit, discharge in (
        ("202603071200", "202603091200"),
        ("202610311200", "202611021200"),
    ):
        with pytest.raises(ValueError, match="needs a zone"):
            length_of_stay(admit, discharge)


def test_los_date_only_and_time_pair_without_zone_is_refused() -> None:
    # One stamp with a time of day is enough: the date-only one's midnight is module filler.
    with pytest.raises(ValueError, match="needs a zone"):
        length_of_stay("20260307", "202603091200")


def test_los_partial_precision_day_pair() -> None:
    assert length_of_stay("20260101", "20260105") == timedelta(days=4)


def test_los_date_only_pair_across_dst_stays_whole_days_with_or_without_zone() -> None:
    """A date-only pair has no hour to be wrong. Reading its midnights through a zone would make a
    two-day stay across spring-forward 1 day 23 hours, so the zone is not consulted for it."""
    assert length_of_stay("20260307", "20260309") == timedelta(days=2)
    assert length_of_stay("20260307", "20260309", zone=EASTERN) == timedelta(days=2)
    assert length_of_stay("20261031", "20261102", zone=EASTERN).days == 2


def test_los_offset_pair_accounts_for_zone_difference() -> None:
    # Same wall-clock 12:00, but admit is +0000 and discharge -0500 -> 5h later actual.
    los = length_of_stay("20260101120000+0000", "20260101120000-0500")
    assert los == timedelta(hours=5)


def test_los_offset_pair_ignores_zone() -> None:
    los = length_of_stay("20260101120000+0000", "20260101120000-0500", zone=CENTRAL)
    assert los == timedelta(hours=5)


def test_los_mixed_offset_pair_raises() -> None:
    with pytest.raises(ValueError, match="both"):
        length_of_stay("20260101120000+0000", "20260104120000")


def test_los_mixed_offset_pair_resolves_the_naive_stamp_in_the_zone() -> None:
    # Admit pinned at -0500 (EST); discharge is bare 12:00 on 2026-03-09, read in Eastern as EDT.
    los = length_of_stay("202603071200-0500", "202603091200", zone=EASTERN)
    assert los == timedelta(hours=47)
    # And the other way round.
    los = length_of_stay("202603071200", "202603091200-0400", zone=EASTERN)
    assert los == timedelta(hours=47)


def test_los_naive_stamp_on_a_dst_edge_is_refused() -> None:
    """The #1686 refusal applies: 02:30 never happens in Eastern on 2026-03-08, and 01:30 happens
    twice on 2026-11-01."""
    with pytest.raises(NonExistentLocalTimeError):
        length_of_stay("202603080230", "202603091200", zone=EASTERN)
    with pytest.raises(AmbiguousLocalTimeError):
        length_of_stay("202610310000", "202611010130", zone=EASTERN)


def test_los_dst_edge_resolved_by_explicit_policy() -> None:
    # 01:30 on the fall-back day: "earlier" is the first occurrence (EDT), "later" the second (EST).
    first = length_of_stay("202611010000", "202611010130", zone=EASTERN, on_dst_edge="earlier")
    second = length_of_stay("202611010000", "202611010130", zone=EASTERN, on_dst_edge="later")
    assert first == timedelta(hours=1, minutes=30)
    assert second == timedelta(hours=2, minutes=30)


def test_los_bad_policy_and_unknown_zone_raise() -> None:
    with pytest.raises(ValueError, match="on_dst_edge"):
        length_of_stay("20260101", "20260105", on_dst_edge="nearest")  # type: ignore[arg-type]
    with pytest.raises(ZoneInfoNotFoundError):
        length_of_stay("20260101120000+0000", "20260102120000+0000", zone="Not/AZone")


def test_los_negative_raises() -> None:
    with pytest.raises(ValueError, match="before admit"):
        length_of_stay("20260104120000", "20260101120000", zone=EASTERN)


def test_los_zero_length_is_allowed() -> None:
    assert length_of_stay("20260101120000", "20260101120000", zone=EASTERN) == timedelta(0)
