# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Shared result model for the deployment verifier."""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum
from functools import cache
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
    """``text`` for a :class:`CheckResult` detail: bounded, then PHI, then credentials, then the
    length bound (BACKLOG #5395).

    A verify report is written to JSON and Markdown that an operator pastes into a ticket, so it
    leaves the box. The text a check quotes is a driver's, a config module's or the OS's: a store
    driver can quote its DSN or a ``password=`` / ``PWD=`` pair, and a config module can raise
    anything. :func:`~messagefoundry.redaction.safe_text` is a PHI pass, and on such a text it left
    the DSN password and the ``PWD=`` and ``password=`` values in place
    (``tests/test_verify_detail_redaction.py``). So the text also takes
    :func:`~messagefoundry.secretscrub.scrub_credentials`, the write-time credential vocabulary the
    log filter and wiring's own diagnostics use.

    THE ORDER IS THE SUPPORT BUNDLE'S (``redact_log_line``), which measured it. The input is cut to
    :func:`~messagefoundry.redaction.clamp_untrusted`'s window before any pass reads it. Then a
    labelled credential's value is masked with a value class that stops at a comma, so a capitalized
    label such as ``Login Password``, which the PHI pass reads as a name and replaces, has already
    lost its value. Then the PHI pass, then the shared vocabulary over the text between the PHI
    pass's placeholders. That vocabulary ran first before, and its value class runs past a comma:
    ``token=tk-1,mrn: MRN7712345`` lost the ``mrn:`` label inside the token's value, and the MRN
    printed. Split at the placeholders, it can no longer reach across a span the PHI pass took.

    Not ``redact_log_line`` itself, though that was the first choice: its long-base64 sweep blanked
    any 24-character run, which is an exception class name such as ``SSLCertVerificationError`` and
    the segments of a POSIX path, the words an operator needs here. This is best-effort, with at
    least the residuals ``secretscrub`` states, and the PHI pass can blank a capitalized two-word path
    segment such as ``Program Files``."""
    from messagefoundry.redaction import _REDACTED, clamp_untrusted, redact, safe_text
    from messagefoundry.secretscrub import scrub_credentials

    bounded = clamp_untrusted(text)
    masked = _premask_labelled_values(bounded)
    phi = redact(masked)
    # A text that already held the placeholder is read whole, as the bundle reads such a line: a
    # split there would cut wherever the text's own author wrote it.
    pieces = [phi] if _REDACTED in bounded else phi.split(_REDACTED)
    cleaned = _REDACTED.join(scrub_credentials(piece) for piece in pieces)
    return safe_text(cleaned) if limit is None else safe_text(cleaned, limit=limit)


def _premask_labelled_values(text: str) -> str:
    """``text`` with the value after a password or token label masked, the label kept, before the
    PHI pass can take the label. The password family is the support bundle's ``_CREDENTIAL_KV``,
    quoted and ODBC-braced values included; the token family, which that pattern does not carry, is
    :func:`_token_label_value`. Both write ``secretscrub``'s placeholder."""
    from messagefoundry.secretscrub import CREDENTIAL_PLACEHOLDER, _keep_label
    from messagefoundry.support.redact import _CREDENTIAL_KV

    text = _CREDENTIAL_KV.sub(lambda m: _keep_label(m, CREDENTIAL_PLACEHOLDER), text)
    return _token_label_value().sub(lambda m: f"{m[1]}{m[2]}{CREDENTIAL_PLACEHOLDER}", text)


@cache
def _token_label_value() -> re.Pattern[str]:
    """A ``<token word>`` label and its separator, an optional auth-scheme word, then a quoted value
    whole, or a plain one that stops at whitespace, a quote, a comma, ``;`` or ``&``. The scheme word
    is taken with the value, so ``Authorization: Bearer <tok>`` hides the token and not the word
    ``Bearer``. The words are ``secretscrub``'s token family."""
    from messagefoundry.secretscrub import _TOKEN_WORDS

    words = "|".join(re.escape(word) for word in _TOKEN_WORDS)
    scheme = r"(?:(?:bearer|basic|digest|negotiate|ntlm|token)\s+)?"
    value = r"""(?:'[^']*'|"[^"]*"|[^\s'",;&]+)"""
    return re.compile(rf"(?i)\b({words})\b(['\"]?\s*[:=]\s*){scheme}{value}")


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
