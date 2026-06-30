# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Message.age() / Message.length_of_stay(): derived HL7 timestamp values read from the
conventional fields (PID-7 DOB, PV1-44/PV1-45 admit/discharge).

All data here is synthetic (fabricated names + dates), never PHI.
"""

from __future__ import annotations

from datetime import timedelta

import pytest

from messagefoundry.parsing import Message

MSH = "MSH|^~\\&|S|SF|R|RF|20260201||ADT^A03^ADT_A03|MSG1|P|2.5.1\r"


def _pv1(admit: str = "", discharge: str = "") -> str:
    """Build a PV1 with the admit (PV1-44) and discharge (PV1-45) timestamps in the right places.
    Counted out (``PV1`` + 43 empty fields lands the admit at field 44) rather than hand-typing the
    pipe run, which is error-prone."""
    return "PV1|1|I" + "|" * 42 + admit + "|" + discharge + "\r"


# Full-precision DOB (PID-7) + a 3-day-4-hour admit/discharge pair.
ADT = (
    MSH
    + "PID|1||100^^^HOSP^MR||DOE^JANE^Q||19800110|F\r"
    + _pv1("20260101080000", "20260104120000")
)


def test_age_reads_pid7_and_computes_completed_years() -> None:
    m = Message.parse(ADT)
    assert m.age(asof="20260115") == 46  # birthday (Jan 10) already passed
    assert m.age(asof="20260105") == 45  # birthday not yet reached this year


def test_age_returns_none_when_dob_absent() -> None:
    # PID with no DOB (PID-7 empty).
    m = Message.parse(MSH + "PID|1||100^^^H^MR||DOE^JANE\r")
    assert m.age(asof="20260115") is None


def test_age_partial_precision_dob() -> None:
    m = Message.parse(MSH + "PID|1||100^^^H^MR||DOE^JANE||1990\r")
    assert m.age(asof="20260601") == 36  # year-only -> Jan 1


def test_length_of_stay_reads_pv1_admit_discharge() -> None:
    m = Message.parse(ADT)
    los = m.length_of_stay()
    assert los == timedelta(days=3, hours=4)
    assert los is not None and los.days == 3


def test_length_of_stay_none_when_discharge_absent() -> None:
    # Open encounter: admit set, discharge empty.
    m = Message.parse(MSH + "PID|1||100^^^H^MR||DOE^JANE||19800110\r" + _pv1("20260101080000", ""))
    assert m.length_of_stay() is None


def test_length_of_stay_negative_raises() -> None:
    m = Message.parse(
        MSH + "PID|1||100^^^H^MR||DOE^JANE||19800110\r" + _pv1("20260104120000", "20260101080000")
    )
    with pytest.raises(ValueError, match="before admit"):
        m.length_of_stay()


def test_custom_paths_are_honored() -> None:
    # A feed that carries the dates somewhere unusual can point the helpers at other fields.
    m = Message.parse(ADT)
    assert m.age(asof="20260115", path="PID-7") == 46
    assert m.length_of_stay(admit_path="PV1-44", discharge_path="PV1-45") == timedelta(
        days=3, hours=4
    )
