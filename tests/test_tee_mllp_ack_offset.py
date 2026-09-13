# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The tee relay's ACK must stamp MSH-7 with an explicit UTC offset (BACKLOG #1196).

The tee carries its own vendored ``build_ack`` and imports no ``messagefoundry`` module, so it
cannot reuse ``timezone.hl7_now``. The engine's copy was fixed first; this pins the tee's copy so
the two do not diverge silently. A bare local stamp is ambiguous across a daylight-saving fall-back,
where the same wall-clock hour occurs twice.

These live in their own file because ``tests/test_tee_mllp.py`` covers framing and echo semantics,
and this is about the value of one field.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime, timedelta, timezone

from tee import mllp

# Synthetic HL7 only. No real PHI.
SAMPLE = (
    b"MSH|^~\\&|EPIC|SENDFAC|MFOR|RECVFAC|20240101120000||ADT^A01|CTRL123|P|2.5.1\r"
    b"PID|1||MRN001^^^HOSP||DOE^JOHN\r"
)

#: An HL7 v2 DTM to whole seconds carrying an explicit numeric offset.
_DTM_WITH_OFFSET = re.compile(r"(?P<stem>\d{14})(?P<offset>[+-]\d{4})")


def _msh7(ack: bytes) -> str:
    return ack.decode("latin-1").split("\r")[0].split("|")[6]


def test_the_tee_ack_msh7_carries_an_explicit_offset() -> None:
    """RED when: the tee's build_ack goes back to a bare strftime.

    THE OFFSET VALUE IS ASSERTED, NOT JUST THE GRAMMAR. A stamp carrying the wrong offset still
    matches the pattern above, so the host's own current offset is computed independently and
    compared.
    """
    msh7 = _msh7(mllp.build_ack(SAMPLE))

    m = _DTM_WITH_OFFSET.fullmatch(msh7)
    assert m is not None, f"MSH-7 {msh7!r} is not a DTM with an explicit offset"

    host = datetime.now().astimezone().utcoffset()
    assert host is not None
    total = int(host.total_seconds() // 60)
    sign = "+" if total >= 0 else "-"
    expected = f"{sign}{abs(total) // 60:02d}{abs(total) % 60:02d}"
    assert m.group("offset") == expected


def test_the_tee_ack_offset_pins_the_right_instant() -> None:
    """RED when: the offset is attached to a reading it does not belong to.

    Stamping UTC digits with the local offset, or local digits with +0000, satisfies both the
    grammar and a value check on the offset alone, and is still an hour or more wrong. This resolves
    MSH-7 to an absolute instant and compares it against UTC now.
    """
    msh7 = _msh7(mllp.build_ack(SAMPLE))
    m = _DTM_WITH_OFFSET.fullmatch(msh7)
    assert m is not None

    off = m.group("offset")
    sign = 1 if off[0] == "+" else -1
    tz = timezone(timedelta(hours=sign * int(off[1:3]), minutes=sign * int(off[3:5])))
    stamped = datetime.strptime(m.group("stem"), "%Y%m%d%H%M%S").replace(tzinfo=tz)

    drift = abs((stamped - datetime.now(UTC)).total_seconds())
    assert drift < 120, (
        f"MSH-7 {msh7!r} resolves to an instant {drift:.0f}s from now; the offset is attached to a "
        "wall-clock reading it does not belong to"
    )


def test_an_explicit_timestamp_is_passed_through_verbatim() -> None:
    """RED when: build_ack starts reformatting a caller-supplied stamp.

    The caller owns the form of a timestamp it pins. The engine's copy behaves the same way, and
    tests/test_tee_mllp.py relies on it.
    """
    assert _msh7(mllp.build_ack(SAMPLE, timestamp="20240101120000")) == "20240101120000"


def test_the_tee_and_the_engine_agree_on_the_offset_form() -> None:
    """RED when: one copy is changed and the other is not.

    The two build_ack implementations cannot share code -- the tee imports no messagefoundry module
    by construction -- so the only thing holding them in step is a test that reads both. This is
    that test. It compares FORM, not the instant, since the two are stamped microseconds apart.
    """
    from messagefoundry.transports.mllp import build_ack as engine_build_ack

    tee_msh7 = _msh7(mllp.build_ack(SAMPLE))
    engine_msh7 = engine_build_ack(SAMPLE.decode("latin-1")).split("\r")[0].split("|")[6]

    tee_m = _DTM_WITH_OFFSET.fullmatch(tee_msh7)
    engine_m = _DTM_WITH_OFFSET.fullmatch(engine_msh7)
    assert tee_m is not None, f"tee MSH-7 {tee_msh7!r} lacks an offset"
    assert engine_m is not None, f"engine MSH-7 {engine_msh7!r} lacks an offset"
    assert tee_m.group("offset") == engine_m.group("offset"), (
        "the tee and the engine stamped different offsets on the same host, so one of the two "
        "copies has drifted"
    )
