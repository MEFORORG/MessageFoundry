# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Unit tests for the RFC 6238 TOTP second factor (auth/totp.py, WP-14).

The vector tests pin the implementation against the official RFC 6238 Appendix B test values. The
engine retired SHA-1 on 2026-08-11 (G18), so these are the **SHA-256** rows of that same table, and
they are asserted at the published **8 digits** rather than truncated to 6 — the RFC prints 8, so
asserting 8 tests strictly more of the truncation math than reducing them first.
"""

from __future__ import annotations

import base64

import pytest

from messagefoundry.auth import totp

# RFC 6238 Appendix B seeds each digest differently: SHA-1 uses the 20-byte ASCII
# "12345678901234567890", SHA-256 uses the 32-byte "12345678901234567890123456789012". Using the
# SHA-1 seed against the SHA-256 rows silently produces non-matching codes, so the pairing matters.
# The engine API takes base32, so encode it the way an authenticator app stores it.
_RFC_SECRET = base64.b32encode(b"12345678901234567890123456789012").decode("ascii")


@pytest.mark.parametrize(
    ("moment", "expected"),
    [
        (59, "46119246"),
        (1111111109, "68084774"),
        (1111111111, "67062674"),
        (1234567890, "91819424"),
        (2000000000, "90698825"),
        (20000000000, "77737706"),
    ],
)
def test_rfc6238_sha256_vectors_8digit(moment: int, expected: str) -> None:
    """The published SHA-256 rows of RFC 6238 Appendix B, at the RFC's own 8 digits.

    Falsified on purpose while writing: against the SHA-1 seed, or against the pre-2026-08-11 SHA-1
    digest, every one of these six goes red.
    """
    assert totp.totp(_RFC_SECRET, now=moment, digits=8) == expected


def test_the_digest_and_the_advertised_algorithm_cannot_diverge() -> None:
    """The single most dangerous edit in this module is changing one without the other.

    The authenticator computes with whatever `otpauth_uri` advertised; the engine computes with
    `_TOTP_DIGEST`. If they disagree nothing raises -- codes simply never match, for every user, with
    no diagnostic. So the advertised name is DERIVED from the digest, and this pins that it stays
    derived rather than drifting back to a literal.
    """
    assert totp._TOTP_DIGEST().name.upper() == totp._TOTP_ALGORITHM
    assert totp._TOTP_ALGORITHM == "SHA256"
    assert f"algorithm={totp._TOTP_ALGORITHM}" in totp.otpauth_uri(_RFC_SECRET, "u@example.test")
    # And the engine's own codes verify under the algorithm it advertises -- the round trip the
    # divergence would break.
    assert totp.verify_totp(_RFC_SECRET, totp.totp(_RFC_SECRET, now=59), now=59)


def test_generate_secret_is_decodable_160_bit_and_unique() -> None:
    s1 = totp.generate_secret()
    s2 = totp.generate_secret()
    assert s1 != s2
    # 20 bytes of entropy → 32 base32 chars, padding stripped, round-trips through the decoder.
    assert len(s1) == 32
    assert len(totp._decode_secret(s1)) == 20
    # A current code for a freshly generated secret verifies against itself.
    assert totp.verify_totp(s1, totp.totp(s1, now=10_000), now=10_000)


def test_verify_accepts_current_and_one_step_skew_only() -> None:
    secret = totp.generate_secret()
    now = 1_000_000.0
    current = totp.totp(secret, now=now)
    one_step_ago = totp.totp(secret, now=now - totp.DEFAULT_PERIOD)
    two_steps_ago = totp.totp(secret, now=now - 2 * totp.DEFAULT_PERIOD)
    assert totp.verify_totp(secret, current, now=now)
    assert totp.verify_totp(secret, one_step_ago, now=now)  # within ±1 window
    assert not totp.verify_totp(secret, two_steps_ago, now=now)  # outside the window


def test_verify_rejects_wrong_and_malformed_codes() -> None:
    secret = totp.generate_secret()
    now = 1_000_000.0
    current = totp.totp(secret, now=now)
    wrong = "000000" if current != "000000" else "111111"
    assert not totp.verify_totp(secret, wrong, now=now)
    assert not totp.verify_totp(secret, "12345", now=now)  # too short
    assert not totp.verify_totp(secret, "1234567", now=now)  # too long
    assert not totp.verify_totp(secret, "abcdef", now=now)  # non-numeric
    assert not totp.verify_totp(secret, "", now=now)


def test_otpauth_uri_carries_secret_and_metadata() -> None:
    secret = totp.generate_secret()
    uri = totp.otpauth_uri(secret, "alice", issuer="MessageFoundry")
    assert uri.startswith("otpauth://totp/MessageFoundry:alice?")
    assert f"secret={secret}" in uri
    assert "issuer=MessageFoundry" in uri
    assert "algorithm=SHA256" in uri  # SHA-1 retired 2026-08-11 (G18)
    assert "digits=6" in uri
    assert "period=30" in uri


def test_recovery_codes_count_format_and_uniqueness() -> None:
    codes = totp.generate_recovery_codes(10)
    assert len(codes) == 10
    assert len(set(codes)) == 10  # no collisions
    for code in codes:
        groups = code.split("-")
        assert len(groups) == 3
        assert all(len(g) == 5 for g in groups)
        # Drawn from the unambiguous alphabet only (no 0/O/1/I/L).
        assert all(ch in "ABCDEFGHJKMNPQRSTUVWXYZ23456789" for g in groups for ch in g)
