# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
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

**Reading a wall clock in a named zone refuses the daylight-saving edges rather than guessing.** A
named source zone is only a complete instant for wall-clock times that happen exactly once. Twice a
year a local time happens *twice* (the fall-back overlap) or *never* (the spring-forward gap), and
there is no instant in the input to choose between them. :func:`convert_hl7_timestamp` raises
:class:`AmbiguousLocalTimeError` / :class:`NonExistentLocalTimeError` on those rather than resolving
to a plausible, well-formed, possibly hour-wrong timestamp; a caller that wants one resolved anyway
names the rule with ``on_dst_edge``. This covers the one place the module marries a naive wall clock
to a named zone — it is **not** a module-wide guarantee, and :func:`length_of_stay` documents its own
naive-pair limit separately.
"""

from __future__ import annotations

import re
from datetime import UTC, date, datetime, timedelta, timezone
from typing import Final, Literal, get_args
from zoneinfo import ZoneInfo

__all__ = [
    "convert_hl7_timestamp",
    "to_zone",
    "parse_hl7_timestamp",
    "hl7_now",
    "age_from_dob",
    "length_of_stay",
    "DstEdgePolicy",
    "DstTransitionError",
    "AmbiguousLocalTimeError",
    "NonExistentLocalTimeError",
]

#: How to treat a wall-clock time that a named zone does not map to exactly one instant.
DstEdgePolicy = Literal["raise", "earlier", "later"]

#: The policy names, derived from the alias so the runtime guard cannot drift from the type. Both
#: layers are wanted: the type rejects a wrong literal at author time, the guard catches a value a
#: dynamically-authored Handler supplies at run time (the convention in :mod:`messagefoundry.actions`).
_DST_EDGE_POLICIES: Final[tuple[str, ...]] = get_args(DstEdgePolicy)

#: Which precisions carry a time field the *sender* wrote. Below these the module fills ``00`` itself,
#: so there is no sender-asserted wall clock to validate or refuse.
_TIME_PRECISIONS: Final[tuple[str, ...]] = ("hour", "minute", "second")

#: The two ways a named zone fails to map a wall clock to one instant. Named so the type layer, not
#: proofreading, keeps :func:`_classify_dst_edge` and its caller spelling them the same way.
_DstEdge = Literal["ambiguous", "nonexistent"]


class DstTransitionError(ValueError):
    """A naive HL7 wall time does not name exactly one instant in its source zone.

    Subclasses :class:`ValueError` so a caller already guarding this module's malformed-input path
    keeps catching it, while code that cares about the distinction can catch this family (or one of
    the two subclasses) specifically.

    Attributes:
        ts: the offending HL7 timestamp, as supplied.
        tz: the IANA source zone name it was read against.
    """

    def __init__(self, message: str, *, ts: str, tz: str) -> None:
        super().__init__(message)
        self.ts = ts
        self.tz = tz


class AmbiguousLocalTimeError(DstTransitionError):
    """The wall time occurs **twice** in the source zone (the daylight-saving fall-back overlap)."""


class NonExistentLocalTimeError(DstTransitionError):
    """The wall time **never** occurs in the source zone (the daylight-saving spring-forward gap)."""


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


def _classify_dst_edge(naive: datetime, zone: ZoneInfo) -> _DstEdge | None:
    """Say whether ``naive`` sits on a daylight-saving edge of ``zone``.

    Returns ``"ambiguous"`` (the wall time occurs twice), ``"nonexistent"`` (it never occurs), or
    ``None`` (it occurs exactly once — the ordinary case, including every zone that has no DST).

    Both tests come straight from PEP 495. ``fold`` selects between the offsets in force either side
    of a transition, so a wall time whose two folds disagree on ``utcoffset()`` is *on* a transition;
    a gap is then told apart from an overlap by round-tripping through UTC, which lands back on the
    input only for a wall time that really happened.
    """
    earlier = naive.replace(tzinfo=zone, fold=0)
    later = naive.replace(tzinfo=zone, fold=1)
    if earlier.utcoffset() == later.utcoffset():
        return None
    round_tripped = earlier.astimezone(UTC).astimezone(zone).replace(tzinfo=None)
    return "ambiguous" if round_tripped == naive else "nonexistent"


def _attach_source_zone(
    naive: datetime, from_tz: str, *, ts: str, on_dst_edge: DstEdgePolicy, precision: str
) -> datetime:
    """Read ``naive`` as a wall-clock time in ``from_tz``, applying the ``on_dst_edge`` policy."""
    zone = ZoneInfo(from_tz)
    edge = _classify_dst_edge(naive, zone)
    if edge is None:
        return naive.replace(tzinfo=zone)
    if on_dst_edge != "raise":
        return naive.replace(tzinfo=zone, fold=0 if on_dst_edge == "earlier" else 1)
    if precision not in _TIME_PRECISIONS:
        # Only a wall time the SENDER wrote is worth refusing. Below hour precision the ambiguity is
        # in this module's own "00" filler — reachable only in a zone whose transition falls at
        # midnight (Havana, Santiago) — so keep the pre-transition offset rather than dead-lettering
        # a date the sender stated unambiguously. An explicit on_dst_edge is still honoured above.
        return naive.replace(tzinfo=zone)

    stamp = ts.strip()
    if edge == "ambiguous":
        raise AmbiguousLocalTimeError(
            f"HL7 timestamp {stamp!r} is ambiguous in {from_tz!r}: that wall-clock time occurs twice "
            "on the daylight-saving fall-back day, and the timestamp carries no offset to say which. "
            "Supply the sender's offset, or pass on_dst_edge='earlier'/'later' to choose.",
            ts=stamp,
            tz=from_tz,
        )
    raise NonExistentLocalTimeError(
        f"HL7 timestamp {stamp!r} does not exist in {from_tz!r}: that wall-clock time is skipped by "
        "the daylight-saving spring-forward transition. Fix the source value, or pass "
        "on_dst_edge='earlier'/'later' to resolve it to an adjacent offset.",
        ts=stamp,
        tz=from_tz,
    )


def convert_hl7_timestamp(
    ts: str, to_tz: str, *, from_tz: str | None = None, on_dst_edge: DstEdgePolicy = "raise"
) -> str:
    """Convert an HL7 v2 timestamp from one named zone to another, DST-correctly.

    The instant's source offset is taken from, in order: the offset embedded in ``ts`` (if present),
    else ``from_tz`` resolved DST-aware at that date. It is then expressed in ``to_tz`` (also DST-aware
    at that date) and re-rendered at the **same precision** as ``ts``.

    Args:
        ts: HL7 v2 timestamp, ``YYYYMMDD[HHMM[SS[.S+]]][+/-ZZZZ]`` at variable precision.
        to_tz: target IANA zone name (e.g. ``"America/Chicago"``).
        from_tz: source IANA zone name; required only when ``ts`` carries no embedded offset.
        on_dst_edge: what to do when ``from_tz`` does not map the wall-clock time to exactly one
            instant — twice a year it maps to two (the fall-back overlap) or none (the spring-forward
            gap). ``"raise"`` (the default) refuses, with the two cases told apart by exception type.
            ``"earlier"`` and ``"later"`` name the **offset** to use: the one in force *before* the
            transition, or *after* it. For an overlap those read as expected — ``"earlier"`` is the
            first of the two occurrences (daylight), ``"later"`` the second (standard). For a gap they
            invert, because the wall time itself never happened: ``"earlier"`` keeps the pre-gap offset
            and so lands *after* the gap, ``"later"`` keeps the post-gap offset and lands *before* it.
            Only ever consulted on the ``from_tz`` path — an embedded offset already pins the
            instant. Refusal is further limited to a ``ts`` that carries a time field: below hour
            precision the time is this module's own ``00`` filler, so the default resolves it
            quietly instead of dead-lettering a date the sender stated unambiguously, while an
            explicit ``"earlier"``/``"later"`` is still honoured there.

    Returns:
        An HL7 v2 timestamp string in ``to_tz`` at the same precision, with the target offset appended.

    Raises:
        AmbiguousLocalTimeError: the wall time occurs twice in ``from_tz`` and ``on_dst_edge`` is
            ``"raise"``.
        NonExistentLocalTimeError: the wall time never occurs in ``from_tz`` and ``on_dst_edge`` is
            ``"raise"``.
        ValueError: ``ts`` is malformed, ``on_dst_edge`` is not one of the three policies, or ``ts``
            has no offset and no ``from_tz`` was supplied. (Both errors above are ``ValueError``s
            too, so an existing broad guard still catches them.)
        zoneinfo.ZoneInfoNotFoundError: a zone name is unknown (on Windows, also if ``tzdata`` is
            missing).
    """
    if on_dst_edge not in _DST_EDGE_POLICIES:
        raise ValueError(f"on_dst_edge must be one of {_DST_EDGE_POLICIES}, got {on_dst_edge!r}")
    naive, precision, embedded_offset = _parse_hl7_timestamp(ts)

    if embedded_offset is not None:
        # An explicit offset pins the instant directly; the source zone is then irrelevant.
        aware = naive.replace(tzinfo=timezone(_offset_to_timedelta(embedded_offset)))
    elif from_tz is not None:
        # No embedded offset: read the wall clock in the source zone, refusing (or resolving under
        # on_dst_edge) the two dates a year where that reading is not a single instant.
        aware = _attach_source_zone(
            naive, from_tz, ts=ts, on_dst_edge=on_dst_edge, precision=precision
        )
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


def hl7_now(*, precision: str = "second", tz: str | None = None, with_offset: bool = False) -> str:
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
        with_offset: stamp the **host's** own DST-correct numeric offset when no ``tz`` is named, so
            the value pins an instant rather than a bare wall-clock reading. Use it for a timestamp a
            receiver will correlate against its own clock (an MLLP acknowledgement's MSH-7): a bare
            local stamp is ambiguous across a daylight-saving fall-back, where the same wall-clock
            hour occurs twice. Ignored when ``tz`` is given (that path already appends an offset) and
            when ``precision`` carries no time field, for the same reason as ``tz``.

    This is the **one** clock-reading helper; keep it out of routing/transform decisions (it would
    break re-run purity) — use it to stamp a freshly built outbound message.

    The bare default (no ``tz``, no ``with_offset``) emits a wall clock with no offset, which is the
    very shape :func:`convert_hl7_timestamp` refuses to read back through a named zone during a
    fall-back hour. Pass ``tz`` or ``with_offset=True`` for any stamp something downstream will
    convert.

    Raises:
        ValueError: ``precision`` is not one of the six field names.
        zoneinfo.ZoneInfoNotFoundError: ``tz`` is unknown (on Windows, also if ``tzdata`` is missing).
    """
    if precision not in ("year", "month", "day", "hour", "minute", "second"):
        raise ValueError(f"precision must be a stem field name, got {precision!r}")
    has_time = precision in _TIME_PRECISIONS
    if tz is not None and has_time:
        # _render appends the zone's DST-correct numeric offset; only meaningful with a time field.
        return _render(datetime.now(ZoneInfo(tz)), precision, None)
    if with_offset and has_time:
        # astimezone() on a naive local reading attaches the host's offset for *this* instant, so the
        # rendered value stays correct either side of a DST transition.
        return _render(datetime.now().astimezone(), precision, None)
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
