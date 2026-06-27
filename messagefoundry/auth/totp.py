# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""RFC 6238 TOTP — the local-account second factor (WP-14, ADR 0002 §3).

Pure standard-library crypto (``hmac`` / ``hashlib`` / ``base64`` / ``secrets``) so MFA adds **no new
dependency**: a software authenticator app (Google/Microsoft Authenticator, Authy, 1Password) and the
engine independently compute the same short code from a shared base32 secret plus the current
30-second time step. Used only for **local** users — AD/Kerberos MFA is delegated to the directory
(see :class:`~messagefoundry.auth.service.AuthService`). This module is side-effect-free and unit-
tested against the RFC 6238 vectors; it never touches the store, the event loop, or config.

Security notes:

- TOTP is a *shared-secret* factor: it satisfies OWASP ASVS 5.0 **6.3.3** at L2 but is phishable and
  replayable inside its step window. The L3 preference for phishing-resistant factors (WebAuthn /
  FIDO2) is the **WP-14b** follow-on, not implemented here.
- Verification uses a constant-time compare (:func:`hmac.compare_digest`) over a fixed candidate set
  and a small clock-skew window. The secret is high-entropy (160-bit); the caller stores it encrypted
  at rest (the store cipher) and never logs it.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import time
from urllib.parse import quote, urlencode

__all__ = [
    "DEFAULT_DIGITS",
    "DEFAULT_PERIOD",
    "DEFAULT_WINDOW",
    "generate_secret",
    "totp",
    "verify_totp",
    "verify_totp_step",
    "otpauth_uri",
    "generate_recovery_codes",
]

#: Authenticator-app conventions (what Google/Microsoft Authenticator assume by default).
DEFAULT_DIGITS = 6
DEFAULT_PERIOD = 30  # seconds per time step
#: ± steps of clock skew tolerated at verify time (one step each side ≈ 30 s).
DEFAULT_WINDOW = 1

_SECRET_BYTES = 20  # 160 bits — RFC 4226 recommends ≥ 128 bits, 160 for HMAC-SHA1

# Recovery codes: human-legible groups from an unambiguous alphabet (no 0/O/1/I/L confusion).
_RECOVERY_ALPHABET = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"
_RECOVERY_GROUP_LEN = 5
_RECOVERY_GROUPS = 3  # e.g. "K7QF2-9DMNA-3XZP4" → ~74 bits of entropy


def generate_secret() -> str:
    """Return a fresh base32-encoded TOTP secret (no padding) to share with the authenticator app."""
    return base64.b32encode(secrets.token_bytes(_SECRET_BYTES)).decode("ascii").rstrip("=")


def _decode_secret(secret: str) -> bytes:
    """Decode a base32 secret tolerantly: ignore spaces/case and restore any stripped padding."""
    cleaned = secret.strip().replace(" ", "").upper()
    padding = "=" * (-len(cleaned) % 8)
    return base64.b32decode(cleaned + padding, casefold=True)


def _hotp(key: bytes, counter: int, digits: int) -> str:
    """RFC 4226 HOTP: HMAC-SHA1 over the 8-byte counter, dynamically truncated to ``digits`` decimals."""
    mac = hmac.new(key, counter.to_bytes(8, "big"), hashlib.sha1).digest()
    offset = mac[-1] & 0x0F
    truncated = int.from_bytes(mac[offset : offset + 4], "big") & 0x7FFFFFFF
    return str(truncated % (10**digits)).zfill(digits)


def totp(
    secret: str,
    *,
    now: float | None = None,
    period: int = DEFAULT_PERIOD,
    digits: int = DEFAULT_DIGITS,
) -> str:
    """The current RFC 6238 TOTP code for ``secret`` (base32) at ``now`` (defaults to the wall clock)."""
    moment = time.time() if now is None else now
    counter = int(moment // period)
    return _hotp(_decode_secret(secret), counter, digits)


def verify_totp_step(
    secret: str,
    code: str,
    *,
    now: float | None = None,
    period: int = DEFAULT_PERIOD,
    digits: int = DEFAULT_DIGITS,
    window: int = DEFAULT_WINDOW,
) -> int | None:
    """Return the time-step counter ``code`` matches within ±``window`` steps of ``now``, or ``None``.

    Unlike :func:`verify_totp` this returns *which* step matched, so the caller can enforce single-use
    by rejecting a step that was already consumed — RFC 6238 codes are otherwise replayable inside
    their ~30 s step window (ASVS 6.5.1). Constant-time compared over a fixed set of candidate steps
    (no early break) so a match near the window edge can't be distinguished by timing; a non-numeric
    or wrong-length ``code`` returns ``None``.

    The forward half of the skew window is *accepted* (so a near-boundary fast-clock authenticator can
    still log in) but the returned step is **clamped to the current step** (SEC-014, CWE-287): a
    tolerated future code (``counter+1``) reports ``counter``, never advancing the single-use high-
    water mark past the genuinely-current step. Otherwise burning ``counter+1`` would reject the user's
    own current-step code (a non-greater step) for up to ~30 s — a self-inflicted lockout, not a
    bypass. The clamp only lowers the recorded step, so single-use is preserved.
    """
    candidate = code.strip()
    if len(candidate) != digits or not candidate.isdigit():
        return None
    moment = time.time() if now is None else now
    key = _decode_secret(secret)
    counter = int(moment // period)
    matched: int | None = None
    for step in range(counter - window, counter + window + 1):
        if step < 0:
            continue
        if hmac.compare_digest(_hotp(key, step, digits), candidate):
            matched = step
    return min(matched, counter) if matched is not None else None


def verify_totp(
    secret: str,
    code: str,
    *,
    now: float | None = None,
    period: int = DEFAULT_PERIOD,
    digits: int = DEFAULT_DIGITS,
    window: int = DEFAULT_WINDOW,
) -> bool:
    """True iff ``code`` matches the TOTP for ``secret`` within ±``window`` steps of ``now``.

    A thin bool wrapper over :func:`verify_totp_step` (which also reports *which* step matched, for
    single-use enforcement). Constant-time; rejects a non-numeric or wrong-length ``code`` outright.
    """
    return (
        verify_totp_step(secret, code, now=now, period=period, digits=digits, window=window)
        is not None
    )


def otpauth_uri(
    secret: str,
    account: str,
    *,
    issuer: str = "MessageFoundry",
    period: int = DEFAULT_PERIOD,
    digits: int = DEFAULT_DIGITS,
) -> str:
    """Build the ``otpauth://totp/…`` URI an authenticator app scans (the UI renders it as a QR code)."""
    # The "issuer:account" colon is the conventional literal label separator (keep it; encode the rest).
    label = quote(f"{issuer}:{account}", safe=":")
    params = urlencode(
        {
            "secret": secret,
            "issuer": issuer,
            "algorithm": "SHA1",
            "digits": digits,
            "period": period,
        }
    )
    return f"otpauth://totp/{label}?{params}"


def generate_recovery_codes(count: int) -> list[str]:
    """Return ``count`` fresh, single-use recovery codes in plaintext (the caller hashes before storing)."""
    codes: list[str] = []
    for _ in range(count):
        groups = [
            "".join(secrets.choice(_RECOVERY_ALPHABET) for _ in range(_RECOVERY_GROUP_LEN))
            for _ in range(_RECOVERY_GROUPS)
        ]
        codes.append("-".join(groups))
    return codes
