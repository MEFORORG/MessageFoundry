# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""DST-aware named-zone timestamp conversion for HL7 v2 timestamps (Tier 2.4).

Corepoint feeds convert HL7 timestamps between named zones DST-correctly (e.g. Eastern→Central),
where the offset that applies depends on the *date* — Eastern is UTC-05:00 in winter (EST) and
UTC-04:00 in summer (EDT). A flat fixed-hour shifter (the migration-local ``_fct.py`` only had a
constant ``-5h``) is wrong for half the year. This module does the conversion with stdlib
:mod:`zoneinfo`, which carries the IANA DST transition rules, so the correct offset is picked from the
actual instant.

Pure module (no engine state, I/O, or DB), so a Router/Handler may call it directly. It speaks **HL7
v2 timestamp strings** (DTM/TS format ``YYYYMMDD[HHMM[SS[.S+]]][+/-ZZZZ]``, HL7 v2.x §2.A.21/2.A.79):
variable precision, optional fractional seconds, and an optional embedded numeric offset. The result
is rendered at the **same precision** as the input (an input with no seconds yields no seconds), with
the target zone's numeric offset appended.

Zone names are **IANA** (``America/New_York``, ``America/Chicago``) — *not* Windows display names like
``(UTC-05:00) Eastern Time (US & Canada)``; mapping those is the caller's job (a migration concern),
kept out of this pure helper.

On Windows the stdlib has no system tz database, so :mod:`zoneinfo` needs the ``tzdata`` PyPI package
(a project dependency) — without it :class:`zoneinfo.ZoneInfoNotFoundError` is raised.
"""

from __future__ import annotations

import re
from datetime import date, datetime, timedelta, timezone
from zoneinfo import ZoneInfo

__all__ = [
    "convert_hl7_timestamp",
    "to_zone",
    "parse_hl7_timestamp",
    "hl7_now",
    "age_from_dob",
    "length_of_stay",
]

#: HL7 v2 timestamp grammar: a contiguous date/time stem at variable precision (4-, 6-, 8-, 10-, 12-,
#: or 14-digit: year → seconds), an optional ``.``-prefixed fractional-seconds run, and an optional
#: ``+``/``-`` 4-digit zone offset. Groups are kept individually so the output can be rebuilt at the
#: *same* precision as the input rather than normalising everything to full seconds.
_HL7_TS = re.compile(
    r"""
    ^
    (?P<year>\d{4})
    (?P<month>\d{2})?
    (?P<day>\d{2})?
    (?P<hour>\d{2})?
    (?P<minute>\d{2})?
    (?P<second>\d{2})?
    (?:\.(?P<frac>\d+))?
    (?P<offset>[+-]\d{4})?
    $
    """,
    re.VERBOSE,
)


def _parse_hl7_timestamp(ts: str) -> tuple[datetime, str, str | None]:
    """Parse an HL7 v2 timestamp into a naive :class:`datetime`, a precision token, and the embedded
    offset (``±HHMM``) if present.

    The precision token is the longest populated stem field name (``year``…``second``), used to
    re-render the output at the same precision. ``datetime`` always needs a full date, so a
    less-than-day-precision input (year-, or year+month-only) is filled with ``01`` for the absent
    lower fields purely to construct the instant — the precision token still bounds what is emitted.
    """
    stripped = ts.strip()
    m = _HL7_TS.match(stripped)
    if m is None:
        # Fail loudly: a malformed timestamp must never be silently coerced to a wrong/empty value.
        raise ValueError(f"not a valid HL7 v2 timestamp: {stripped!r}")

    # Lower fields require their parent (no day without a month, no minute without an hour); the regex
    # alone permits gaps like YYYY__DD, so reject those explicitly.
    parts = {name: m.group(name) for name in ("month", "day", "hour", "minute", "second")}
    order = ["month", "day", "hour", "minute", "second"]
    seen_gap = False
    precision = "year"
    for name in order:
        if parts[name] is None:
            seen_gap = True
        else:
            if seen_gap:
                raise ValueError(f"HL7 timestamp has a gap before {name!r}: {stripped!r}")
            precision = name

    frac = m.group("frac")
    if frac is not None and precision != "second":
        # Fractional seconds without a seconds field is nonsensical (.5 of what?).
        raise ValueError(f"HL7 timestamp has fractional seconds without seconds: {stripped!r}")

    # HL7 fractional seconds are a decimal fraction of a second; datetime takes whole microseconds, so
    # scale to 6 digits (pad/truncate). Sub-microsecond precision below datetime's resolution is lost,
    # but the rendered fraction is taken from the original string, so the emitted value is unchanged.
    microsecond = 0
    if frac is not None:
        microsecond = int((frac + "000000")[:6])

    naive = datetime(
        year=int(m.group("year")),
        month=int(parts["month"] or "01"),
        day=int(parts["day"] or "01"),
        hour=int(parts["hour"] or "00"),
        minute=int(parts["minute"] or "00"),
        second=int(parts["second"] or "00"),
        microsecond=microsecond,
    )
    return naive, precision, m.group("offset")


def parse_hl7_timestamp(ts: str) -> tuple[datetime, str, str | None]:
    """Public alias for :func:`_parse_hl7_timestamp`.

    Parse an HL7 v2 timestamp (``YYYYMMDD[HHMM[SS[.S+]]][+/-ZZZZ]`` at variable precision) into a
    naive :class:`datetime`, a precision token (one of ``"year"``/``"month"``/``"day"``/``"hour"``/
    ``"minute"``/``"second"`` — the longest populated stem field), and the embedded ``±HHMM`` offset
    (or None). A code-first Router/Handler may call this directly to inspect a timestamp's instant and
    declared precision without re-implementing the tolerant grammar.

    Raises:
        ValueError: ``ts`` is malformed (bad grammar, impossible date, a precision gap, or fractional
            seconds without seconds).
    """
    return _parse_hl7_timestamp(ts)


def _offset_to_timedelta(offset: str) -> timedelta:
    """Turn an HL7 ``±HHMM`` offset into a :class:`timedelta`. Raises on a non-sensical offset (e.g.
    minutes ≥ 60) rather than producing a silently wrong instant."""
    sign = 1 if offset[0] == "+" else -1
    hours = int(offset[1:3])
    minutes = int(offset[3:5])
    if minutes >= 60:
        raise ValueError(f"HL7 timestamp offset has out-of-range minutes: {offset!r}")
    return timedelta(hours=sign * hours, minutes=sign * minutes)


def _render(dt: datetime, precision: str, frac: str | None) -> str:
    """Render an aware :class:`datetime` back to an HL7 timestamp at ``precision`` with ``dt``'s
    numeric offset appended. ``frac`` is the original fractional-seconds string, re-emitted verbatim so
    round-tripping doesn't reshape the precision the sender chose."""
    # Build the stem field-by-field up to the requested precision; never emit fields below it.
    stem = f"{dt.year:04d}"
    if precision in ("month", "day", "hour", "minute", "second"):
        stem += f"{dt.month:02d}"
    if precision in ("day", "hour", "minute", "second"):
        stem += f"{dt.day:02d}"
    if precision in ("hour", "minute", "second"):
        stem += f"{dt.hour:02d}"
    if precision in ("minute", "second"):
        stem += f"{dt.minute:02d}"
    if precision == "second":
        stem += f"{dt.second:02d}"
        if frac is not None:
            stem += f".{frac}"

    utcoffset = dt.utcoffset()
    if utcoffset is None:  # pragma: no cover - we only ever render aware datetimes
        raise ValueError("cannot render an HL7 timestamp without a timezone offset")
    total_minutes = int(utcoffset.total_seconds() // 60)
    sign = "+" if total_minutes >= 0 else "-"
    total_minutes = abs(total_minutes)
    return f"{stem}{sign}{total_minutes // 60:02d}{total_minutes % 60:02d}"


def convert_hl7_timestamp(ts: str, to_tz: str, *, from_tz: str | None = None) -> str:
    """Convert an HL7 v2 timestamp from one named zone to another, DST-correctly.

    The instant's source offset is taken from, in order: the offset embedded in ``ts`` (if present),
    else ``from_tz`` resolved DST-aware at that date. It is then expressed in ``to_tz`` (also DST-aware
    at that date) and re-rendered at the **same precision** as ``ts``.

    Args:
        ts: HL7 v2 timestamp, ``YYYYMMDD[HHMM[SS[.S+]]][+/-ZZZZ]`` at variable precision.
        to_tz: target IANA zone name (e.g. ``"America/Chicago"``).
        from_tz: source IANA zone name; required only when ``ts`` carries no embedded offset.

    Returns:
        An HL7 v2 timestamp string in ``to_tz`` at the same precision, with the target offset appended.

    Raises:
        ValueError: ``ts`` is malformed, or it has no offset and no ``from_tz`` was supplied.
        zoneinfo.ZoneInfoNotFoundError: a zone name is unknown (on Windows, also if ``tzdata`` is
            missing).
    """
    naive, precision, embedded_offset = _parse_hl7_timestamp(ts)

    if embedded_offset is not None:
        # An explicit offset pins the instant directly; the source zone is then irrelevant.
        aware = naive.replace(tzinfo=timezone(_offset_to_timedelta(embedded_offset)))
    elif from_tz is not None:
        # No embedded offset: attach the source zone so zoneinfo picks the DST-correct offset for the
        # naive wall-clock time at that date.
        aware = naive.replace(tzinfo=ZoneInfo(from_tz))
    else:
        raise ValueError(
            "HL7 timestamp has no embedded offset; a source zone (from_tz) is required to convert it"
        )

    converted = aware.astimezone(ZoneInfo(to_tz))
    return _render(converted, precision, None if precision != "second" else _frac_of(ts))


def to_zone(ts: str, to_tz: str) -> str:
    """Convenience: express a UTC/offset-bearing HL7 timestamp in a target IANA zone, DST-correctly.

    ``ts`` must carry an embedded numeric offset (e.g. a ``...+0000`` UTC value); the instant is fixed
    by that offset, so no source zone is needed. Equivalent to :func:`convert_hl7_timestamp` with no
    ``from_tz``.

    Raises:
        ValueError: ``ts`` is malformed or carries no embedded offset.
    """
    _, _, embedded_offset = _parse_hl7_timestamp(ts)
    if embedded_offset is None:
        raise ValueError(
            f"to_zone requires a timestamp with an embedded offset (e.g. ...+0000): {ts.strip()!r}"
        )
    return convert_hl7_timestamp(ts, to_tz)


def _frac_of(ts: str) -> str | None:
    """Re-extract the original fractional-seconds string from ``ts`` for verbatim re-emission (the
    conversion never alters sub-second value, only the offset/wall-clock)."""
    m = _HL7_TS.match(ts.strip())
    return m.group("frac") if m is not None else None


# --- derived-value helpers (age / length-of-stay / now) ----------------------
#
# These build on the tolerant parser above so a code-first Handler can compute the common derived
# fields (a patient's age from PID-7, a length-of-stay from PV1-44/PV1-45) without re-implementing HL7
# timestamp handling. They are pure — no I/O, no wall-clock read unless one is passed in — so they stay
# safe under the at-least-once re-run invariant; ``hl7_now()`` is the one that reads the clock and is
# meant for stamping an output, not for a routing decision.


def hl7_now(*, precision: str = "second", tz: str | None = None) -> str:
    """Render the current instant as an HL7 v2 timestamp at ``precision``.

    Args:
        precision: the lowest field to emit — ``"year"``/``"month"``/``"day"``/``"hour"``/``"minute"``/
            ``"second"`` (default ``"second"``, the usual MSH-7 form). Higher fields are always
            included; lower ones are omitted (so ``"day"`` yields ``YYYYMMDD`` with no offset/time).
        tz: an IANA zone name (e.g. ``"America/Chicago"``) to stamp the local wall-clock + that zone's
            numeric offset; ``None`` (the default) uses the host's local time **without** an offset
            suffix (a bare local stamp). An offset is only appended when ``tz`` is given **and**
            ``precision`` includes a time field (``hour``/``minute``/``second``) — HL7 attaches an
            offset to a date-only value nonsensically.

    This is the **one** clock-reading helper; keep it out of routing/transform decisions (it would
    break re-run purity) — use it to stamp a freshly built outbound message.

    Raises:
        ValueError: ``precision`` is not one of the six field names.
        zoneinfo.ZoneInfoNotFoundError: ``tz`` is unknown (on Windows, also if ``tzdata`` is missing).
    """
    if precision not in ("year", "month", "day", "hour", "minute", "second"):
        raise ValueError(f"precision must be a stem field name, got {precision!r}")
    has_time = precision in ("hour", "minute", "second")
    if tz is not None and has_time:
        # _render appends the zone's DST-correct numeric offset; only meaningful with a time field.
        return _render(datetime.now(ZoneInfo(tz)), precision, None)
    now = datetime.now(ZoneInfo(tz)) if tz is not None else datetime.now()
    return _stem(now, precision)


def _stem(dt: datetime, precision: str) -> str:
    """The date/time stem of ``dt`` rendered to ``precision`` (no offset). Shared by the local-time
    ``hl7_now`` path; the zoned path reuses :func:`_render`."""
    stem = f"{dt.year:04d}"
    if precision in ("month", "day", "hour", "minute", "second"):
        stem += f"{dt.month:02d}"
    if precision in ("day", "hour", "minute", "second"):
        stem += f"{dt.day:02d}"
    if precision in ("hour", "minute", "second"):
        stem += f"{dt.hour:02d}"
    if precision in ("minute", "second"):
        stem += f"{dt.minute:02d}"
    if precision == "second":
        stem += f"{dt.second:02d}"
    return stem


def age_from_dob(dob_ts: str, asof: str | date | datetime | None = None) -> int:
    """Whole years between a date of birth and a reference date (default: today, host-local).

    ``dob_ts`` is an HL7 v2 timestamp; only its **date** is used (any time/offset is ignored), and
    **partial precision is accepted** — a year-only ``"1990"`` or year+month ``"199006"`` DOB is
    treated as the first of the missing fields (Jan 1 / the 1st), the conservative reading that never
    over-states age. ``asof`` may be another HL7 timestamp string, a :class:`datetime.date`, or a
    :class:`datetime.datetime`; ``None`` uses today's local date.

    Returns the age in completed years (the birthday-aware difference — not yet had this year's
    birthday ⇒ one less).

    Raises:
        ValueError: ``dob_ts`` is malformed, ``asof`` is a malformed timestamp string, or the
            resulting age is negative (DOB after the reference date — a data error worth surfacing,
            not silently clamping).
    """
    born = _parse_hl7_timestamp(dob_ts)[0].date()
    ref = _coerce_date(asof)
    # Completed-years: subtract the year, then take one off if this year's birthday hasn't passed.
    years = ref.year - born.year - ((ref.month, ref.day) < (born.month, born.day))
    if years < 0:
        raise ValueError(
            f"date of birth {born.isoformat()} is after the reference date {ref.isoformat()}"
        )
    return years


def _coerce_date(asof: str | date | datetime | None) -> date:
    """Resolve the ``asof`` reference into a plain :class:`date` (today's local date when None)."""
    if asof is None:
        return datetime.now().date()
    if isinstance(asof, datetime):
        return asof.date()
    if isinstance(asof, date):
        return asof
    return _parse_hl7_timestamp(asof)[0].date()


def length_of_stay(admit_ts: str, discharge_ts: str) -> timedelta:
    """The elapsed time between an admit and a discharge HL7 timestamp, as a :class:`timedelta`.

    A :class:`~datetime.timedelta` is returned (not a bare day count) so the caller keeps full
    resolution and chooses how to express it — ``.days`` for whole inpatient days,
    ``.total_seconds() / 3600`` for hours, etc. Both timestamps are parsed at whatever precision they
    carry; if **both** bear an embedded offset the difference is the true elapsed time across any DST/
    zone change, and if neither does it is the naive wall-clock difference. A **mixed** pair (one
    offset, one not) is rejected — the elapsed time would be ambiguous.

    Raises:
        ValueError: either timestamp is malformed, exactly one carries an offset, or the discharge is
            **before** the admit (a negative stay — a data error, surfaced rather than returned).
    """
    admit_dt, _ap, admit_off = _parse_hl7_timestamp(admit_ts)
    discharge_dt, _dp, discharge_off = _parse_hl7_timestamp(discharge_ts)
    if (admit_off is None) != (discharge_off is None):
        raise ValueError(
            "length_of_stay needs both timestamps with an offset or both without; "
            f"got admit offset {admit_off!r} and discharge offset {discharge_off!r}"
        )
    if admit_off is not None and discharge_off is not None:
        admit_dt = admit_dt.replace(tzinfo=timezone(_offset_to_timedelta(admit_off)))
        discharge_dt = discharge_dt.replace(tzinfo=timezone(_offset_to_timedelta(discharge_off)))
    delta = discharge_dt - admit_dt
    if delta < timedelta(0):
        raise ValueError(
            f"discharge {discharge_ts.strip()!r} is before admit {admit_ts.strip()!r} "
            "(negative length of stay)"
        )
    return delta
