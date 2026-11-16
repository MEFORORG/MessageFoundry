# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Shared result model for the deployment verifier."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Final


class Status(str, Enum):  # noqa: UP042
    """Outcome of a single verify check. ``str`` mix-in so it serialises as its value."""

    PASS = "PASS"  # nosec B105 — a check-status enum value, not a credential
    FAIL = "FAIL"
    SKIP = "SKIP"  # not applicable / not reachable here (e.g. driver extra not installed)
    MANUAL = "MANUAL"  # a human on the box must confirm it; not auto-checkable
    ERROR = "ERROR"  # the check itself broke


#: Statuses that make the overall run fail (exit 1). MANUAL/SKIP never fail a run.
FAILING: tuple[Status, ...] = (Status.FAIL, Status.ERROR)


#: How much of an exception a detail keeps. Longer than ``safe_exc``'s 200 because a verify detail
#: is read by the operator fixing the box, and a driver's remedy is often the tail of its message.
DETAIL_LIMIT: Final = 1000

#: ``safe_exc``'s own limit when :func:`safe_exc_detail` cuts the text itself, after the credentials.
_UNCUT: Final = 1 << 30


def safe_exc_detail(exc: BaseException) -> str:
    """``exc`` for a :class:`CheckResult` detail, with credentials as well as PHI redacted (BACKLOG
    #5395).

    A verify report is written to JSON and Markdown that an operator pastes into a ticket, so it
    leaves the box. The exception text a check quotes is a driver's, a config module's or the OS's: a
    store driver can quote its DSN or a ``password=`` / ``PWD=`` pair, and a config module can raise
    anything. :func:`~messagefoundry.redaction.safe_exc` is a PHI pass, and on such a text it left
    the DSN password and the ``PWD=`` and ``password=`` values in place
    (``tests/test_verify_detail_redaction.py``). So its rendering then takes
    :func:`~messagefoundry.secretscrub.scrub_credentials`, the write-time credential vocabulary the
    log filter and wiring's own diagnostics use, over the whole text at once.

    Not the support bundle's ``redact_log_line``, though that was the first choice: its long-base64
    sweep blanked any 24-character run, which is an exception class name such as
    ``SSLCertVerificationError`` and the segments of a POSIX path, the words an operator needs here.
    The shared vocabulary carries the residuals ``secretscrub`` states, so this is best-effort too.

    The cut comes after the credential pass, so that pass reads the text whole."""
    from messagefoundry.redaction import safe_exc, safe_text
    from messagefoundry.secretscrub import scrub_credentials

    return safe_text(scrub_credentials(safe_exc(exc, limit=_UNCUT)), limit=DETAIL_LIMIT)


@dataclass
class CheckResult:
    """One verify check and its outcome."""

    id: str
    title: str
    status: Status
    detail: str
    evidence: str = ""
