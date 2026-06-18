# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Unit tests for the RFC 6238 TOTP second factor (auth/totp.py, WP-14).

The vector tests pin the implementation against the official RFC 6238 Appendix B test values (the
SHA-1, 8-digit set) reduced to the 6-digit codes authenticator apps emit, so a regression in the
HMAC/truncation math is caught in CI.
"""

from __future__ import annotations

import base64

import pytest

from messagefoundry.auth import totp

# RFC 6238 Appendix B uses the ASCII seed "12345678901234567890" (20 bytes) for HMAC-SHA1; the
# engine API takes base32, so encode it the way an authenticator app stores it.
_RFC_SECRET = base64.b32encode(b"12345678901234567890").decode("ascii")


@pytest.mark.parametrize(
    ("moment", "expected"),
    [
        (59, "287082"),
        (1111111109, "081804"),
        (1111111111, "050471"),
        (1234567890, "005924"),
        (2000000000, "279037"),
        (20000000000, "353130"),
    ],
)
def test_rfc6238_sha1_vectors_6digit(moment: int, expected: str) -> None:
    # Each is the last 6 digits of the published 8-digit RFC 6238 SHA-1 vector at that timestamp.
    assert totp.totp(_RFC_SECRET, now=moment) == expected


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
    assert "algorithm=SHA1" in uri
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
