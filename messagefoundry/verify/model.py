# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Shared result model for the deployment verifier."""

from __future__ import annotations

import re
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


#: A credential label word right after a capitalized word and a space, as in ``Login Password=`` or
#: ``Access Token:``. The PHI name pass reads two capitalized words as a name and takes both, and
#: the credential pass after it then finds no label, so the value printed. Lower-casing the label
#: word alone breaks that pair and changes nothing else; after a lower-case word there is no pair,
#: so ``word PWD=`` keeps its spelling. The words are ``secretscrub``'s password and token
#: families, spelled here so the static ReDoS gate reads a literal;
#: ``tests/test_verify_detail_redaction.py`` holds them to ``secretscrub``. Each match starts at a
#: word boundary and the word runs are not nested, so the scan is linear.
_PAIRED_CREDENTIAL_LABEL: Final = re.compile(
    r"\b([A-Z][A-Za-z0-9]*[ \t]+)"
    r"((?i:password|passwd|passphrase|pass|pwd|secret|credential"
    r"|authorization|bearer|token|session|api_key|api-key|apikey))\b(?=['\"]?\s*[:=])"
)


def safe_detail_text(text: str, *, limit: int | None = None) -> str:
    """``text`` for a :class:`CheckResult` detail: bounded, then PHI, then credentials over the whole
    result, then the length bound (BACKLOG #5395).

    A verify report is written to JSON and Markdown that an operator pastes into a ticket, so it
    leaves the box. The text a check quotes is a driver's, a config module's or the OS's: a store
    driver can quote its DSN or a ``password=`` / ``PWD=`` pair, and a config module can raise
    anything. :func:`~messagefoundry.redaction.safe_text` is a PHI pass, and on such a text it left
    the DSN password and the ``PWD=`` and ``password=`` values in place
    (``tests/test_verify_detail_redaction.py``). So the text also takes
    :func:`~messagefoundry.secretscrub.scrub_credentials`, the write-time credential vocabulary the
    log filter and wiring's own diagnostics use.

    THE PHI PASS RUNS FIRST, AND THE CREDENTIAL PASS READS ITS WHOLE RESULT. Run first, the
    credential pass read ``tk-1,mrn:`` in ``token=tk-1,mrn: MRN7712345`` as the token's value, the
    PHI pass then found no ``mrn:`` label, and the MRN printed. Run after, over the whole text, it can
    only hide more than the PHI pass did. Not split at the PHI placeholders, as the support bundle's
    second layer is: the placeholder is a run of non-space characters, so ``postgresql://19800505:<pw>@``
    still reads as a DSN once the PHI pass has replaced the user, where a split cut it in two and the
    password printed.

    The one thing the PHI pass takes that the credential pass needs is a label read as a name, such
    as ``Login Password``. :data:`_PAIRED_CREDENTIAL_LABEL` lower-cases its label word first, so the
    name pass leaves it. The input is cut to
    :func:`~messagefoundry.redaction.clamp_untrusted`'s window before any pass reads it, and its note
    is kept past the length bound.

    Not the support bundle's ``redact_log_line``: its long-base64 sweep blanked any 24-character run,
    which is an exception class name such as ``SSLCertVerificationError`` and the segments of a POSIX
    path, the words an operator needs here. This is best-effort, with at least the residuals
    ``secretscrub`` states, and the PHI pass can blank a capitalized two-word phrase such as ``Program
    Files``."""
    from messagefoundry.redaction import clamp_untrusted, redact, safe_text
    from messagefoundry.secretscrub import scrub_credentials

    bounded = clamp_untrusted(text)
    # clamp_untrusted ends a cut text with "\n" and its note. The note says what no pass read, so it
    # must outlive the length bound below, which would otherwise drop it with the tail.
    head, note = bounded.rsplit("\n", 1) if bounded is not text else (bounded, "")
    lowered = _PAIRED_CREDENTIAL_LABEL.sub(lambda m: m[1] + m[2].lower(), head)
    cleaned = scrub_credentials(redact(lowered))
    shown = safe_text(cleaned) if limit is None else safe_text(cleaned, limit=limit)
    return f"{shown} {note}" if note else shown


def safe_exc_detail(exc: BaseException, *, limit: int | None = None) -> str:
    """``exc`` for a :class:`CheckResult` detail: its type, then its text through
    :func:`safe_detail_text`. A ``UnicodeError`` takes :func:`~messagefoundry.redaction.safe_exc`
    whole, which builds the text from its attributes and quotes no character of the message; an
    exception holding one renders as ``codec_safe_str``'s fixed note. ``limit`` as
    :func:`safe_detail_text`, on both branches."""
    from messagefoundry.redaction import codec_safe_str, safe_exc

    if isinstance(exc, UnicodeError):
        return safe_exc(exc) if limit is None else safe_exc(exc, limit=limit)
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
