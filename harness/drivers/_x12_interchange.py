# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A minimal synthetic ASC X12 interchange builder, and the TA1 a harness X12 sink answers with.

Neither ``messagefoundry.generators`` (HL7 v2 only) nor ``messagefoundry.parsing.x12`` (a codec,
not a builder) builds an interchange, so this small one lives with the harness. Every value is
synthetic and fixed except the control numbers: there is no patient, subscriber or provider in it,
only an envelope around one bare 837 transaction header. ISA15 is ``T`` (test data), so nothing
built here can be mistaken for a production interchange.

The ISA is fixed width, 106 characters with delimiters ``*`` (element), ``^`` (repetition), ``:``
(component) and ``~`` (segment). The builder checks that width rather than trusting it, because a
receiver discovers every delimiter by absolute offset into the ISA and a one-character drift would
make the whole interchange unreadable.
"""

from __future__ import annotations

from uuid import uuid4

SENDER = "MFHARNESS"
RECEIVER = "MFSINK"
_DATE, _TIME = "260101", "1200"
_ISA_PRE_TERMINATOR = 105


def fresh_control_number() -> str:
    """A random nine-digit interchange control number (ISA13). Fresh per call, so a long-lived
    store cannot satisfy a run with an earlier run's interchanges."""
    return f"{uuid4().int % 1_000_000_000:09d}"


def isa(control: str, *, sender: str = SENDER, receiver: str = RECEIVER) -> str:
    """The 106-character ISA header (terminator included) for interchange ``control``."""
    if len(control) != 9 or not control.isdigit():
        raise ValueError(f"ISA13 must be nine digits, got {control!r}")
    fields = [
        "ISA",
        "00",
        " " * 10,
        "00",
        " " * 10,
        "ZZ",
        sender.ljust(15),
        "ZZ",
        receiver.ljust(15),
        _DATE,
        _TIME,
        "^",
        "00501",
        control,
        "0",
        "T",
        ":",
    ]
    head = "*".join(fields)
    if len(head) != _ISA_PRE_TERMINATOR:
        raise ValueError(f"ISA is {len(head)} characters before its terminator, want 105")
    return head + "~"


def interchange(control: str, *, corrupt_trailer: bool = False) -> bytes:
    """One complete interchange: ISA, one GS group holding one 837 ST/BHT/SE set, GE, IEA.

    ``corrupt_trailer`` makes IEA02 disagree with ISA13 -- an envelope that frames correctly (the
    reader still finds its IEA) but does not tie out, which a receiver checking integrity rejects."""
    group = str(int(control) or 1)
    trailer = f"{(int(control) + 1) % 1_000_000_000:09d}" if corrupt_trailer else control
    segments = [
        f"GS*HC*{SENDER}*{RECEIVER}*20{_DATE}*{_TIME}*{group}*X*005010X222A1",
        "ST*837*0001*005010X222A1",
        f"BHT*0019*00*{control}*20{_DATE}*{_TIME}*CH",
        "SE*3*0001",
        f"GE*1*{group}",
        f"IEA*1*{trailer}",
    ]
    return (isa(control) + "".join(s + "~" for s in segments)).encode("ascii")


def ta1(acknowledged: str, code: str, *, control: str | None = None) -> bytes:
    """A TA1 interchange acknowledging interchange ``acknowledged`` with TA104 ``code``: ``A``
    accepted, ``E`` accepted with errors, ``R`` rejected. Its own ISA13 is ``control`` (fresh when
    omitted); IEA01 is 0 because a TA1 interchange carries no functional group."""
    if code not in ("A", "E", "R"):
        raise ValueError(f"TA104 must be A, E or R, got {code!r}")
    own = control or fresh_control_number()
    note = "000" if code == "A" else "022"
    body = f"TA1*{acknowledged}*{_DATE}*{_TIME}*{code}*{note}~IEA*0*{own}~"
    return (isa(own, sender=RECEIVER, receiver=SENDER) + body).encode("ascii")
