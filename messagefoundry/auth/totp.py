# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""RFC 6238 TOTP — the engine's own second factor (WP-14, ADR 0002 §3).

Pure standard-library crypto (``hmac`` / ``hashlib`` / ``base64`` / ``secrets``) so MFA adds **no new
dependency**: a software authenticator app (Google/Microsoft Authenticator, Authy, 1Password) and the
engine independently compute the same short code from a shared base32 secret plus the current
30-second time step. Available to **every** account, directory ones included — a Kerberos ticket
asserts no factor strength the engine can read, so the engine asks for its own factor rather than
assuming one (BACKLOG #1144; see :class:`~messagefoundry.auth.service.AuthService`). This module is
side-effect-free and unit-tested against the RFC 6238 vectors; it never touches the store, the event
loop, or config.

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
from dataclasses import dataclass
from urllib.parse import quote, urlencode

__all__ = [
    "DEFAULT_DIGITS",
    "DEFAULT_PARAMETERS",
    "DEFAULT_PERIOD",
    "DEFAULT_WINDOW",
    "UNMARKED_PARAMETERS",
    "RefusedEnrolment",
    "TotpParameters",
    "generate_secret",
    "needs_reenrolment",
    "new_enrolment",
    "parse_enrolment",
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

# 160 bits. RFC 4226 requires >= 128 and recommends 160. RFC 6238 R6 additionally says the key
# SHOULD match the HMAC output length -- 32 bytes now that the digest is SHA-256 (see _TOTP_DIGEST).
# Kept at 20 DELIBERATELY: that clause is about interoperability convention rather than strength, 160
# bits is ample against HMAC-SHA256, and 32 bytes would lengthen manual entry from 32 to 52 base32
# characters on a screen an operator types from. Revisit only with a real interop failure, not on the
# SHOULD alone.
_SECRET_BYTES = 20

# Recovery codes: human-legible groups from an unambiguous alphabet (no 0/O/1/I/L confusion).
_RECOVERY_ALPHABET = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"
_RECOVERY_GROUP_LEN = 5
# SIX groups, not three. Three gave 74.31 bits per code; against the 50-code ceiling
# `[auth].mfa_recovery_code_count` permits, an attacker needs any ONE of them, so the guessing
# strength is 74.31 - log2(50) = 68.67 bits -- 59 bits UNDER a 128-bit floor. Six gives 148.63,
# i.e. 142.98 after the same adjustment, clearing the floor by 15 bits (BACKLOG #1172).
# The floor is asserted in tests/test_recovery_code_entropy.py, DERIVED from these three constants
# and from the validator's own ceiling, so none of them can drift away from it silently.
# e.g. "K7QF2-9DMNA-3XZP4-B8VWR-6JTCH-2YQD5"
_RECOVERY_GROUPS = 6


def wall_clock() -> float:
    """The wall-clock instant this module judges codes against when no ``now`` is given.

    A caller that may wait before it checks a code reads this when the request ARRIVES and passes
    it as ``now`` (BACKLOG #1943), so the code is judged as of then. Reading it here rather than
    from ``time.time()`` keeps that caller on the same clock as the rest of this module."""
    return time.time()


def generate_secret() -> str:
    """Return a fresh base32-encoded TOTP secret (no padding) to share with the authenticator app."""
    return base64.b32encode(secrets.token_bytes(_SECRET_BYTES)).decode("ascii").rstrip("=")


def _decode_secret(secret: str) -> bytes:
    """Decode a base32 secret tolerantly: ignore spaces/case and restore any stripped padding."""
    cleaned = secret.strip().replace(" ", "").upper()
    padding = "=" * (-len(cleaned) % 8)
    return base64.b32decode(cleaned + padding, casefold=True)


#: The HOTP MAC a NEW enrolment is made with. RFC 6238 permits SHA-1, SHA-256 and SHA-512; SHA-1 is
#: the RFC default and was the shipped choice until 2026-08-11, when it was retired under the G18
#: ruling. An existing enrolment computes with the digest it records (:func:`parse_enrolment`), so a
#: change here moves only enrolments made after it (BACKLOG #3422).
#:
#: THIS CONSTANT AND THE ADVERTISED ALGORITHM MUST NEVER DIVERGE. The authenticator computes with
#: whatever ``otpauth_uri`` told it and the engine computes with this — so a change to one alone does
#: not fail loudly, it silently produces codes that never match, for every user, with no diagnostic.
#: That is why :data:`_TOTP_ALGORITHM` is DERIVED from this rather than written beside it: the two
#: cannot be edited apart. ``hashlib.sha256().name.upper()`` is exactly the otpauth spelling, and the
#: same derivation is correct for all three permitted digests.
_TOTP_DIGEST = hashlib.sha256
_TOTP_ALGORITHM = _TOTP_DIGEST().name.upper()


@dataclass(frozen=True)
class TotpParameters:
    """The three values an authenticator and the engine must agree on to compute the same code:
    the HOTP digest (by its ``otpauth`` spelling), the digit count, and the step in seconds."""

    algorithm: str
    digits: int
    period: int


#: What a NEW enrolment is made with: this release's default. The algorithm is DERIVED from
#: :data:`_TOTP_DIGEST`, for the reason given there.
DEFAULT_PARAMETERS = TotpParameters(_TOTP_ALGORITHM, DEFAULT_DIGITS, DEFAULT_PERIOD)

#: What an enrolment that records no parameters was made with (BACKLOG #3422). Before that change
#: the stored cell held the bare base32 secret and the parameters were the module constants above,
#: which were SHA-256, 6 digits and 30 seconds from 2026-08-11. THESE ARE LITERALS AND MUST NEVER
#: CHANGE, and above all they must never be derived from the defaults: they describe enrolments
#: already written, so a release that moves a default must leave them where they are, or every
#: unmarked authenticator stops matching, which is exactly the failure this item closed.
UNMARKED_PARAMETERS = TotpParameters("SHA256", 6, 30)

#: The digests this release computes with: ``otpauth`` spelling to :mod:`hashlib` name. The
#: default's entry is DERIVED, so moving :data:`_TOTP_DIGEST` cannot leave new enrolments without
#: one; the SHA-256 literal stays for :data:`UNMARKED_PARAMETERS`. SHA-1 is absent on purpose: it
#: was retired under the G18 ruling, and nothing this release writes names it.
_DIGESTS = {"SHA256": "sha256", _TOTP_ALGORITHM: _TOTP_DIGEST().name}

#: Every parameter set a stored enrolment may name. This is the runtime-selection refusal: a stored
#: marker CHOOSES among these and can never introduce another, so a cell naming anything else,
#: SHA-1 or a four-digit code included, is refused rather than computed with. A release that
#: changes :data:`DEFAULT_PARAMETERS` must add the outgoing default here as a LITERAL, beside
#: :data:`UNMARKED_PARAMETERS`, or every enrolment made under it is refused. An enrolment the
#: engine cannot use is named by the startup census and by ``messagefoundry verify``.
_COMPILED_PARAMETERS = frozenset({DEFAULT_PARAMETERS, UNMARKED_PARAMETERS})

#: Opens a stored enrolment that records its parameters: ``totp1:<algorithm>:<digits>:<period>:``
#: then the base32 secret. A colon is outside the base32 alphabet, so no bare secret carries one,
#: and an unmarked cell is told apart from a marked one by its content alone.
_ENROLMENT_MARKER = "totp1"


class RefusedEnrolment(ValueError):
    """A stored TOTP enrolment whose marker is malformed or names parameters outside
    :data:`_COMPILED_PARAMETERS`. Refused, never computed with. The message names no value."""


def new_enrolment(secret: str) -> str:
    """The stored form of a new enrolment of ``secret``: the bare base32 secret marked with
    :data:`DEFAULT_PARAMETERS`, which :func:`otpauth_uri` then advertises and every code check
    computes with. A ``secret`` already in the stored form is returned unchanged once it parses."""
    if ":" in secret:
        parse_enrolment(secret)
        return secret
    p = DEFAULT_PARAMETERS
    return f"{_ENROLMENT_MARKER}:{p.algorithm}:{p.digits}:{p.period}:{secret}"


def parse_enrolment(stored: str) -> tuple[str, TotpParameters]:
    """Split a stored enrolment into its bare base32 secret and the parameters it was made with.

    A cell with no marker is an enrolment written before BACKLOG #3422 and gets
    :data:`UNMARKED_PARAMETERS`. Any other marker that does not name a set in
    :data:`_COMPILED_PARAMETERS` raises :class:`RefusedEnrolment`."""
    if ":" not in stored:
        return stored, UNMARKED_PARAMETERS
    fields = stored.split(":")
    if len(fields) == 5 and fields[0] == _ENROLMENT_MARKER and fields[4]:
        _, algorithm, digits, period, secret = fields
        if all(f.isascii() and f.isdigit() for f in (digits, period)):
            params = TotpParameters(algorithm, int(digits), int(period))
            if params in _COMPILED_PARAMETERS:
                return secret, params
    raise RefusedEnrolment("the stored TOTP enrolment names parameters this release cannot use")


def needs_reenrolment(stored: str) -> bool:
    """Whether the enrolment ``stored`` was made with parameters other than this release's
    default, so its holder should be offered a fresh enrolment (the ``needs_rehash`` shape, applied
    to MFA). True for a refused marker too, since a fresh enrolment is the only way past it."""
    try:
        return parse_enrolment(stored)[1] != DEFAULT_PARAMETERS
    except RefusedEnrolment:
        return True


def _resolve(secret: str, period: int | None, digits: int | None) -> tuple[str, TotpParameters]:
    """The bare secret and the parameters to compute ``secret``'s codes with. ``secret`` is a bare
    base32 secret or a stored enrolment. An explicit ``period`` or ``digits`` may restate a marked
    enrolment's own value but never contradict it, since only the stored value matches the
    authenticator; for a bare secret it overrides :data:`UNMARKED_PARAMETERS`."""
    bare, params = parse_enrolment(secret)
    if bare != secret and (
        period not in (None, params.period) or digits not in (None, params.digits)
    ):
        raise ValueError("an explicit TOTP parameter contradicts the stored enrolment")
    return bare, TotpParameters(
        params.algorithm,
        params.digits if digits is None else digits,
        params.period if period is None else period,
    )


def _hotp(key: bytes, counter: int, digits: int, digest: str) -> str:
    """RFC 4226 HOTP over the 8-byte counter, dynamically truncated to ``digits`` decimals.

    The MAC is the enrolment's digest (SHA-256 since 2026-08-11), not RFC 4226's SHA-1.
    """
    mac = hmac.new(key, counter.to_bytes(8, "big"), digest).digest()
    offset = mac[-1] & 0x0F
    truncated = int.from_bytes(mac[offset : offset + 4], "big") & 0x7FFFFFFF
    return str(truncated % (10**digits)).zfill(digits)


def totp(
    secret: str,
    *,
    now: float | None = None,
    period: int | None = None,
    digits: int | None = None,
) -> str:
    """The current RFC 6238 TOTP code for ``secret`` at ``now`` (defaults to the wall clock).

    ``secret`` is a bare base32 secret or a stored enrolment (:func:`new_enrolment`), whose recorded
    parameters it is computed with. Raises :class:`ValueError` for a refused marker
    (:func:`parse_enrolment`) or a secret that is not base32."""
    bare, params = _resolve(secret, period, digits)
    moment = time.time() if now is None else now
    counter = int(moment // params.period)
    return _hotp(_decode_secret(bare), counter, params.digits, _DIGESTS[params.algorithm])


def verify_totp_step(
    secret: str,
    code: str,
    *,
    now: float | None = None,
    period: int | None = None,
    digits: int | None = None,
    window: int = DEFAULT_WINDOW,
) -> int | None:
    """Return the time-step counter ``code`` matches within ±``window`` steps of ``now``, or ``None``.

    Unlike :func:`verify_totp` this returns *which* step matched, so the caller can enforce single-use
    by rejecting a step that was already consumed — RFC 6238 codes are otherwise replayable inside
    their ~30 s step window (ASVS 6.5.1). Constant-time compared over a fixed set of candidate steps
    (no early break) so a match near the window edge can't be distinguished by timing; a non-numeric
    or wrong-length ``code`` returns ``None``.

    ``secret`` is a bare base32 secret or a stored enrolment, checked with the parameters it records
    (BACKLOG #3422). A refused marker (:class:`RefusedEnrolment`) returns ``None``: no code matches
    an enrolment this release cannot compute, so a recovery code stays the way past it.

    The forward half of the skew window is *accepted* (so a near-boundary fast-clock authenticator can
    still log in) but the returned step is **clamped to the current step** (SEC-014, CWE-287): a
    tolerated future code (``counter+1``) reports ``counter``, never advancing the single-use high-
    water mark past the genuinely-current step. Otherwise burning ``counter+1`` would reject the user's
    own current-step code (a non-greater step) for up to ~30 s — a self-inflicted lockout, not a
    bypass.

    **WARNING: At ``window >= 1`` the clamp does not preserve single-use — it is what costs it.** Because a
    tolerated future code is recorded at ``counter`` rather than at its OWN step, that step is left
    unspent, so the SAME code verifies again once the clock reaches ``counter+1``: two successful uses
    of one code, which is what ASVS 6.5.1 forbids. Measured — ``verify_totp_step(s, totp(s, now=t+30),
    now=t, window=1)`` returns ``step(t)``, and the same code at ``now=t+30`` returns ``step(t)+1``,
    strictly greater, so a high-water store accepts both. At the shipped default ``window=0``
    (``[auth].totp_skew_steps``) single-use DOES hold, because a future code is not accepted at all.
    The second use is the price of the opt-out, not a property of the clamp. Pinned by
    tests/test_totp_window.py::test_optout_lets_one_tolerated_future_code_be_used_twice.
    """
    try:
        bare, params = _resolve(secret, period, digits)
    except RefusedEnrolment:
        return None
    digits = params.digits
    candidate = code.strip()
    # ``isascii`` FIRST, and it is a security check rather than tidiness (ADR 0197, BACKLOG #1131).
    # ``str.isdigit`` is true for Arabic-Indic and fullwidth digits, and ``hmac.compare_digest``
    # raises ``TypeError`` on a non-ASCII ``str``. On the combined sign-in that exception escaped the
    # failure pad as an unpadded 500, which told the caller the account had TOTP enrolled and, chained
    # with the second-step lock, whether a password was right. A code that is not six ASCII digits is
    # simply not a match.
    if len(candidate) != digits or not (candidate.isascii() and candidate.isdigit()):
        return None
    moment = time.time() if now is None else now
    key = _decode_secret(bare)
    digest = _DIGESTS[params.algorithm]
    counter = int(moment // params.period)
    matched: int | None = None
    # ASVS 11.2.4 DRIFT GUARD — do NOT add a `break` or an early `return` inside this loop. Every
    # candidate step must be HOTP-computed and compared so the number of hmac.compare_digest calls is
    # fixed by `window` alone, never by WHICH step matched (or whether any did). Pinned by
    # tests/test_totp_window.py::test_compare_count_is_window_fixed_regardless_of_matching_step, which
    # counts the comparisons and fails on an early exit. (The `step < 0` skip depends only on `now` —
    # public wall-clock, not secret material — so it is a clock guard, not a data-dependent branch.)
    for step in range(counter - window, counter + window + 1):
        if step < 0:
            continue
        if hmac.compare_digest(_hotp(key, step, digits, digest), candidate):
            matched = step
    return min(matched, counter) if matched is not None else None


def verify_totp(
    secret: str,
    code: str,
    *,
    now: float | None = None,
    period: int | None = None,
    digits: int | None = None,
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
) -> str:
    """Build the ``otpauth://totp/…`` URI an authenticator app scans (the UI renders it as a QR code).

    ``secret`` is the stored enrolment (:func:`new_enrolment`), and the URI advertises exactly the
    parameters it records, so the app and every later code check compute alike (BACKLOG #3422). A
    bare secret advertises :data:`UNMARKED_PARAMETERS`.

    **Advertises SHA-256, and enrolling apps must honour it.** Most modern authenticators do (1Password,
    Bitwarden, Aegis, FreeOTP, Authy). **Google Authenticator historically IGNORES the ``algorithm``
    parameter and computes SHA-1 regardless** — against which this engine's codes will simply never
    match, with no error to explain why. That is the known cost of the 2026-08-11 SHA-1 retirement
    (G18), accepted while there are zero enrolled users; it is a support burden, not a security one.
    An operator hitting it needs an app that honours the parameter, not a re-enrolment.
    """
    # The "issuer:account" colon is the conventional literal label separator (keep it; encode the rest).
    label = quote(f"{issuer}:{account}", safe=":")
    # From the enrolment, never a literal: the app computes with what this names and the engine with
    # what the enrolment records, so the two must be one reading (see _TOTP_DIGEST).
    bare, recorded = parse_enrolment(secret)
    query = urlencode(
        {
            "secret": bare,
            "issuer": issuer,
            "algorithm": recorded.algorithm,
            "digits": recorded.digits,
            "period": recorded.period,
        }
    )
    return f"otpauth://totp/{label}?{query}"


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
