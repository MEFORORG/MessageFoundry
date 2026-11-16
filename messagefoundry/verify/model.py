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


#: The bound for an arm that quotes a store driver, a socket or the TLS stack rather than a
#: Router/Handler. Those arms printed the whole text before BACKLOG #5395, and the engine's own
#: refusals there, such as the store's Vault revocation remedy, run past ``safe_text``'s 200; the
#: arms that can quote a message (config load, dry run, BACKLOG #1779) keep 200.
DRIVER_DETAIL_LIMIT: Final = 2000


def safe_detail_text(text: str, *, limit: int | None = None) -> str:
    """``text`` for a :class:`CheckResult` detail: credentials first, then PHI and the length bound
    (BACKLOG #5395).

    A verify report is written to JSON and Markdown that an operator pastes into a ticket, so it
    leaves the box. The text a check quotes is a driver's, a config module's or the OS's: a store
    driver can quote its DSN or a ``password=`` / ``PWD=`` pair, and a config module can raise
    anything. :func:`~messagefoundry.redaction.safe_text` is a PHI pass, and on such a text it left
    the DSN password and the ``PWD=`` and ``password=`` values in place
    (``tests/test_verify_detail_redaction.py``). So the text first takes
    :func:`~messagefoundry.secretscrub.scrub_credentials`, the write-time credential vocabulary the
    log filter and wiring's own diagnostics use.

    CREDENTIALS RUN FIRST. The PHI pass reads a capitalized two-word label such as ``Login
    Password`` as a name and replaces it, after which no credential pass can find the label, and its
    value printed. Run first, the credential pass also reads the text before any cut.

    Not the support bundle's ``redact_log_line``, though that was the first choice: its long-base64
    sweep blanked any 24-character run, which is an exception class name such as
    ``SSLCertVerificationError`` and the segments of a POSIX path, the words an operator needs here.
    The shared vocabulary carries the residuals ``secretscrub`` states, and the PHI pass can still
    blank a capitalized two-word path segment such as ``Program Files``, so this is best-effort."""
    from messagefoundry.redaction import safe_text
    from messagefoundry.secretscrub import scrub_credentials

    cleaned = scrub_credentials(text)
    return safe_text(cleaned) if limit is None else safe_text(cleaned, limit=limit)


def safe_exc_detail(exc: BaseException, *, limit: int | None = None) -> str:
    """``exc`` for a :class:`CheckResult` detail: its type, then its text through
    :func:`safe_detail_text`. A ``UnicodeError`` takes :func:`~messagefoundry.redaction.safe_exc`
    whole, which builds the text from its attributes and quotes no character of the message; an
    exception holding one renders as ``codec_safe_str``'s fixed note. ``limit`` as
    :func:`safe_detail_text`."""
    from messagefoundry.redaction import codec_safe_str, safe_exc

    if isinstance(exc, UnicodeError):
        return safe_exc(exc)
    message = safe_detail_text(codec_safe_str(exc), limit=limit)
    return f"{type(exc).__name__}: {message}" if message else type(exc).__name__


@dataclass
class CheckResult:
    """One verify check and its outcome."""

    id: str
    title: str
    status: Status
    detail: str
    evidence: str = ""
