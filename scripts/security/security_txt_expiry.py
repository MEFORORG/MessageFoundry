#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Remind the owner to renew ``.well-known/security.txt`` before its ``Expires`` passes.

BACKLOG #277, Lane 2. RFC 9116 section 2.5.5 tells a reader not to trust the file after
``Expires``, so an expired file fails silently: nothing breaks, and researchers are told to
ignore it. This script is the reminder. It goes red ``LEAD_DAYS`` before the date, and stays
red after it, so the owner hears about it while there is still time to act.

IT ONLY REMINDS. Renewing is the owner's act, because renewal means re-checking that both
``Contact`` channels still reach a maintainer before moving the date. A script that bumped the
date would discard the whole value of the field, which the file's own comment says in words.

THE DATE CHECK MUST NEVER GATE A MERGE. ``main`` runs only from
``.github/workflows/security-txt-renewal.yml``, which has a ``schedule`` and a
``workflow_dispatch`` trigger and nothing else, so it never reports on a pull request or a
merge-queue batch. ``tests/test_security_txt_rfc9116.py`` records why a blocking "has not
expired" check was written and removed.

THE PARSER DOES GATE, ON PURPOSE. ``tests/test_security_txt_rfc9116.py`` calls
``parse_expires`` on the committed file in the required test legs, so a renewal this script
could not read reds its own pull request instead of a later weekly run. Tightening
``_RFC3339`` therefore reaches every pull request if the committed value stops matching.

Exit codes, following the repository's DAST convention:

* ``0`` -- more than ``LEAD_DAYS`` remain. Nothing to do.
* ``1`` -- renewal is due: ``LEAD_DAYS`` or fewer remain, or the date has already passed.
* ``2`` -- could not measure: the file is missing or not UTF-8, it has no single ``Expires``
  in RFC 3339 form, or the script itself failed. Red too, because a reminder that cannot read
  the date must not look like one that found nothing to say. A crash must not exit 1 either,
  because 1 tells the reader to renew rather than to fix something.

Stdlib only, so the workflow installs nothing.
"""

from __future__ import annotations

import argparse
import datetime as dt
import re
import sys
from pathlib import Path

#: How far ahead of ``Expires`` the reminder goes red. The workflow runs weekly, so 30 days
#: gives at least four red runs before the date. Renewal needs a person to re-check two contact
#: channels and then land a pull request through the merge queue, which a four-week window
#: allows for even across an absence. It is also under a tenth of the file's one-year lifetime,
#: so the reminder is quiet for most of the year rather than a standing nag.
LEAD_DAYS = 30

_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_FILE = _ROOT / ".well-known" / "security.txt"

#: RFC 3339 section 5.6 ``date-time``: full date, ``T``, full time with seconds, then ``Z`` or a
#: ``+hh:mm`` offset. Checked BEFORE ``fromisoformat``, which on 3.14 also accepts forms RFC 3339
#: does not (no seconds, basic format, week dates, a ``+hhmm`` offset). A renewal written in one
#: of those would stay green here while a strict reader rejected the field. The RFC allows a
#: lowercase ``t`` and ``z`` and ``fromisoformat`` does not, so the value is upcased first.
_RFC3339 = re.compile(
    r"^\d{4}-\d{2}-\d{2}[Tt]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[Zz]|[+-]\d{2}:\d{2})$", re.ASCII
)


class ExpiresError(ValueError):
    """The file carries no single ``Expires`` that parses as RFC 3339 with an offset."""


def parse_expires(text: str) -> dt.datetime:
    """Return the one published ``Expires``, as an aware datetime.

    Blank lines and ``#`` comments are skipped, as RFC 9116's grammar does. Field names match
    without regard to case. The RFC allows exactly one ``Expires``, so zero or several is an
    error rather than a guess at which one a reader would use.
    """
    values: list[str] = []
    for raw in text.splitlines():
        line = raw.rstrip()
        if not line or line.startswith("#"):
            continue
        name, sep, value = line.partition(":")
        if sep and name.strip().lower() == "expires":
            values.append(value.strip())
    if len(values) != 1:
        raise ExpiresError(
            f"expected exactly one Expires field, found {len(values)}: {ascii(values)}"
        )
    raw_value = values[0]
    if not _RFC3339.match(raw_value):
        raise ExpiresError(
            f"Expires is not an RFC 3339 date-time with an offset: {raw_value!a}. "
            "Use a form like 2027-09-01T00:00:00.000Z."
        )
    try:
        return dt.datetime.fromisoformat(raw_value.upper())
    except ValueError as exc:  # the shape is right but a value is out of range, e.g. month 13
        raise ExpiresError(f"Expires is not a real date-time: {raw_value!a} ({exc})") from exc


def renewal_due(expires: dt.datetime, now: dt.datetime, lead_days: int = LEAD_DAYS) -> bool:
    """True when ``lead_days`` or fewer remain before ``expires``, including once it has passed."""
    return expires - now <= dt.timedelta(days=lead_days)


def _message(expires: dt.datetime, now: dt.datetime, lead_days: int) -> tuple[int, str]:
    """The exit code and the one sentence a reader needs, for a file that parsed."""
    remaining = expires - now
    stamp = expires.isoformat()
    if remaining <= dt.timedelta(0):
        return 1, (
            f"security.txt EXPIRED at {stamp}. RFC 9116 tells readers to ignore it from that "
            "date. Re-check that both Contact channels still reach a maintainer, then move "
            "Expires forward by less than a year."
        )
    if renewal_due(expires, now, lead_days):
        return 1, (
            f"security.txt expires at {stamp}, in {remaining.days} day(s), inside the "
            f"{lead_days}-day renewal window. Re-check that both Contact channels still reach "
            "a maintainer, then move Expires forward by less than a year."
        )
    return 0, (
        f"security.txt expires at {stamp}, in {remaining.days} day(s). The reminder goes "
        f"red {lead_days} days before that."
    )


def _parse_now(value: str) -> dt.datetime:
    parsed = dt.datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        raise argparse.ArgumentTypeError(f"--now needs a UTC offset: {value!r}")
    return parsed


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0] if __doc__ else None)
    parser.add_argument("--file", type=Path, default=DEFAULT_FILE, help="the security.txt to read")
    parser.add_argument(
        "--lead-days",
        type=int,
        default=LEAD_DAYS,
        help=f"go red this many days before Expires (default {LEAD_DAYS})",
    )
    parser.add_argument(
        "--now",
        type=_parse_now,
        default=None,
        help="the current instant, RFC 3339 with an offset; for tests only",
    )
    parser.add_argument(
        "--summary", type=Path, default=None, help="append the verdict here (GITHUB_STEP_SUMMARY)"
    )
    args = parser.parse_args(argv)
    now: dt.datetime = args.now or dt.datetime.now(dt.UTC)

    try:
        expires = parse_expires(args.file.read_text(encoding="utf-8"))
    # ValueError covers ExpiresError and a file that is not UTF-8 (UnicodeDecodeError). Either
    # way the date could not be read, which is exit 2 and never the "renewal due" exit 1.
    except (OSError, ValueError) as exc:
        code, text = 2, f"could not read the Expires date from {args.file}: {exc}"
    else:
        code, text = _message(expires, now, args.lead_days)

    # A GitHub annotation on a red run, so the reason shows on the run page without opening the log.
    # ASCII-escaped, because a non-ASCII path or value on a cp1252 console would raise here.
    safe = text.encode("ascii", "backslashreplace").decode("ascii")
    print(f"::error title=security.txt renewal::{safe}" if code else safe)
    if args.summary is not None:
        try:
            with args.summary.open("a", encoding="utf-8") as fh:
                fh.write(f"### security.txt renewal\n\n{text}\n")
        except OSError as exc:
            # The verdict is already printed above; a lost summary must not change it.
            print(f"::warning::could not write the run summary: {exc!a}")
    return code


def run_guarded(argv: list[str] | None = None) -> int:
    """``main``, failing closed to exit 2 on anything it did not anticipate.

    An uncaught exception exits 1, which is this script's "renewal is due" code, and the issue
    body tells that reader nothing is broken. So a crash is turned into 2, the "could not
    measure" code, and named. The same shape as the DAST sweeps' top-level guard.
    """
    try:
        return main(argv)
    except Exception as exc:  # noqa: BLE001 - fail closed; the exception is named below
        print(
            "::error title=security.txt renewal::the reminder crashed and measured nothing: "
            f"{type(exc).__name__}: {exc!a}"
        )
        return 2


if __name__ == "__main__":
    sys.exit(run_guarded())
