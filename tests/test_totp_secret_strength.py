# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A TOTP secret must be base32 and carry at least 160 bits, at enrolment and at every code check
(BACKLOG #5340).

Before this, :func:`totp.new_enrolment` refused only an empty string. A whitespace-only secret
enrolled and decoded to a ZERO-LENGTH HMAC key, so its codes were computable by anyone; a secret
that was not base32 enrolled too, and the first code check raised ``binascii.Error``, which on the
first-administrator provisioning path escaped as an uncaught error rather than a refusal. RFC 4226
section 4 requirement R6 says the shared secret MUST be at least 128 bits and recommends 160; the
floor is the recommendation, which is what :func:`totp.generate_secret` makes.

Also settles the row's unadjudicated item (S12-39), measured at origin/main da08e4da9c3: a
PARTIALLY padded secret decodes (the padding is topped up, not doubled), while an over-padded one
or one with an inner tab or newline raises ``binascii.Error``. That raise is a refusal, not an
acceptance, so the decoder is left as tolerant as it was; enrolment now refuses those shapes with
:class:`totp.RefusedTotpSecret`, so none of them reaches a stored enrolment.
"""

from __future__ import annotations

import base64

import pytest
from _totp_clock import fresh_totp

from messagefoundry.auth import totp
from messagefoundry.auth.service import (
    AuthService,
    FirstAdministratorRefused,
    _log_totp_unusable,
    _opened_totp_state,
    _totp_unusable_reason,
)
from messagefoundry.config.settings import AuthSettings
from messagefoundry.store.store import MessageStore
from tests._admin_account import ADMIN_USERNAME, PROVISION_EMAIL, login_admin

# Synthetic keys of a chosen length, encoded the way an authenticator app holds them.
_KEY_160 = base64.b32encode(bytes(range(20))).decode("ascii")
_KEY_128 = base64.b32encode(bytes(range(16))).decode("ascii")
_KEY_80 = base64.b32encode(bytes(range(10))).decode("ascii")

_PASSWORD = "a-long-enough-operator-passphrase"

# Every shape a caller-supplied secret was measured to slip through with.
_REFUSED_SECRETS = [
    pytest.param("", id="empty"),
    pytest.param("   ", id="whitespace-only"),
    pytest.param("\t\n", id="tab-newline-only"),
    pytest.param("not!base32", id="non-base32"),
    pytest.param("\u00e9" * 32, id="non-ascii"),
    # upper() maps U+00DF to "SS", inside the alphabet: refused before it can decode to a key.
    pytest.param("\u00df" * 16, id="non-ascii-folding-into-base32"),
    pytest.param(_KEY_128, id="128-bit"),
    pytest.param(_KEY_80, id="80-bit"),
    pytest.param(_KEY_160 + "========", id="over-padded"),
    pytest.param(_KEY_160[:16] + "\t" + _KEY_160[16:], id="inner-tab"),
    pytest.param(_KEY_160[:16] + "\n" + _KEY_160[16:], id="inner-newline"),
]


def test_a_generated_secret_meets_the_floor_and_enrols() -> None:
    """The floor must never refuse what the engine itself generates."""
    for _ in range(50):
        secret = totp.generate_secret()
        assert len(totp._decode_secret(secret)) >= totp._MIN_SECRET_BYTES
        assert totp.new_enrolment(secret).endswith(":" + secret)


def test_the_floor_is_at_least_rfc_4226s_requirement() -> None:
    """RFC 4226 section 4 R6: MUST be at least 128 bits. The floor is the 160-bit recommendation."""
    assert totp._MIN_SECRET_BYTES * 8 >= 160


@pytest.mark.parametrize("secret", _REFUSED_SECRETS)
def test_enrolment_refuses_a_weak_or_undecodable_secret(secret: str) -> None:
    with pytest.raises(totp.RefusedTotpSecret):
        totp.new_enrolment(secret)


@pytest.mark.parametrize("secret", _REFUSED_SECRETS)
def test_enrolment_refuses_it_in_stored_form_too(secret: str) -> None:
    """A secret handed over already marked is checked the same way, not passed through. (A marker
    with an empty secret is already refused as a malformed marker, the superclass.)"""
    marked = f"totp1:SHA256:6:30:{secret}"
    with pytest.raises(totp.RefusedEnrolment):
        totp.new_enrolment(marked)


def test_a_refused_secret_is_a_refused_enrolment() -> None:
    """Every caller that already refuses a bad marker refuses a bad secret with no new branch."""
    assert issubclass(totp.RefusedTotpSecret, totp.RefusedEnrolment)


def test_a_partially_padded_secret_still_enrols() -> None:
    """S12-39's padding half does not hold: a partial pad is topped up, not doubled."""
    padded = base64.b32encode(bytes(range(21))).decode("ascii")
    assert padded.endswith("=")
    canonical = padded.rstrip("=")
    assert totp.new_enrolment(padded[:-1]).endswith(":" + canonical)
    assert totp.new_enrolment(padded).endswith(":" + canonical)


def test_an_enrolment_stores_the_canonical_secret() -> None:
    """Spaces, case and padding the decoder tolerates are not stored, so the URI the authenticator
    scans carries exactly the key the engine computes with."""
    secret = totp.generate_secret()
    spaced = " " + " ".join(secret[i : i + 4] for i in range(0, len(secret), 4)).lower() + " "
    assert totp.new_enrolment(spaced) == totp.new_enrolment(secret)
    assert totp.new_enrolment(f"totp1:SHA256:6:30:{spaced}") == totp.new_enrolment(secret)
    assert f"secret={secret}&" in totp.otpauth_uri(totp.new_enrolment(spaced), "someone")


@pytest.mark.parametrize("secret", ["   ", _KEY_128, _KEY_80])
def test_no_code_is_computed_from_a_short_stored_key(secret: str) -> None:
    """A short key that reached a cell some other way is refused when a code is computed, and
    matches no code: a zero-length key's codes are computable by anyone."""
    for stored in (secret, f"totp1:SHA256:6:30:{secret}"):
        with pytest.raises(totp.RefusedTotpSecret):
            totp.totp(stored, now=0)
        # The code the short key itself would give, so the None is the floor and not a wrong key.
        key = base64.b32decode(secret.strip() + "=" * (-len(secret.strip()) % 8))
        own_code = totp._hotp(key, 0, 6, "sha256")
        assert totp.verify_totp_step(stored, own_code, now=0, window=0) is None
        assert totp.needs_reenrolment(stored) is True


def test_a_usable_enrolment_still_needs_no_reenrolment() -> None:
    """CONTROL for the line above: the floor does not mark a sound enrolment for re-enrolment."""
    assert totp.needs_reenrolment(totp.new_enrolment(_KEY_160)) is False


@pytest.mark.parametrize("secret", _REFUSED_SECRETS)
async def test_provisioning_refuses_cleanly_and_writes_nothing(secret: str) -> None:
    """The first-administrator path takes a caller's secret: it refuses with its own error, never
    an uncaught ``binascii.Error``, and before any write."""
    store = await MessageStore.open(":memory:")
    try:
        service = AuthService(store, AuthSettings())
        with pytest.raises(FirstAdministratorRefused, match="not one this release can enrol"):
            await service.provision_first_administrator(
                username="site-admin",
                password=_PASSWORD,
                notify_email=PROVISION_EMAIL,
                actor="test",
                totp_secret=secret,
                totp_code="123456",
                totp_code_read_at=0.0,
            )
        assert await store.count_users() == 0
    finally:
        await store.close()


# A stored secret no code can be computed from, by each way it reaches a cell: not base32, not
# ASCII (one upper() would fold into the alphabet included), or decoding to a short key.
_UNDECODABLE_STORED = [
    pytest.param("not base32 at all!", id="non-base32"),
    pytest.param("ß" * 16, id="non-ascii-folding-into-base32"),
    pytest.param("totp1:SHA256:6:30:" + "é" * 32, id="marked-non-ascii"),
]
_SHORT_STORED = [
    pytest.param(_KEY_128, id="128-bit"),
    pytest.param("totp1:SHA256:6:30:" + _KEY_80, id="marked-80-bit"),
]


@pytest.mark.parametrize("stored", _UNDECODABLE_STORED + _SHORT_STORED)
def test_an_undecodable_or_short_stored_secret_computes_and_matches_no_code(stored: str) -> None:
    """Fails closed in the module: refused, never a ``binascii.Error``, and a fresh enrolment is
    the way past it."""
    with pytest.raises(totp.RefusedTotpSecret):
        totp.totp(stored, now=0)
    assert totp.verify_totp_step(stored, "123456", now=0, window=0) is None
    assert totp.needs_reenrolment(stored) is True


@pytest.mark.parametrize("stored", _SHORT_STORED)
def test_a_short_stored_key_is_a_known_refusal_to_the_service(stored: str) -> None:
    assert _opened_totp_state(stored) == "refused"


@pytest.mark.parametrize("stored", _UNDECODABLE_STORED)
def test_an_undecodable_stored_secret_stays_unknown_to_the_service(stored: str) -> None:
    """CONTROL: a value that is not base32 cannot be judged, so the gates keep counting it as the
    plain enabled-TOTP rule does (BACKLOG #3422). It now computes no code; its state is the same."""
    assert _opened_totp_state(stored) == "unknown"


@pytest.mark.parametrize("stored", _UNDECODABLE_STORED + _SHORT_STORED)
async def test_the_two_step_verify_fails_closed_on_a_bad_stored_secret(
    stored: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``verify_mfa`` raised ``binascii.Error`` (a 500) on a stored secret that was not base32,
    before it tried a recovery code. Now a six-digit code is checked against it without raising and
    a recovery code still signs in. That no code MATCHES such a secret is pinned by
    :func:`test_an_undecodable_or_short_stored_secret_computes_and_matches_no_code`; the code here
    is an arbitrary one, so its refusal proves only that the check did not raise."""
    store = await MessageStore.open(":memory:")
    try:
        service = AuthService(
            store, AuthSettings(mfa_verify_min_elapsed_seconds=0, mfa_recovery_code_count=2)
        )
        identity, token, password = await login_admin(service)
        enroll = await service.begin_mfa_enrollment(identity)
        enrolled = await service.confirm_mfa_enrollment(
            identity, fresh_totp(enroll.secret), token=token
        )
        assert enrolled.ok and enrolled.recovery_codes

        def opener(_user_id: str, _cell: str | None) -> str:
            return stored

        monkeypatch.setattr(store, "open_totp_secret", opener)
        out = await service.login(ADMIN_USERNAME, password)
        assert out.token is not None
        assert (await service.verify_mfa(out.token, "123456")).ok is False
        assert (await service.verify_mfa(out.token, enrolled.recovery_codes[0])).ok is True
    finally:
        await store.close()


@pytest.mark.parametrize(
    "stored", [f"{totp._marker(totp.DEFAULT_PARAMETERS)}:", "AB:CD", "totp1:SHA256:6:30:AB:CD"]
)
def test_a_refused_enrolment_raised_directly_logs_a_cause_true_for_it(
    stored: str, caplog: pytest.LogCaptureFixture
) -> None:
    """An accepted marker followed by an empty secret, a malformed marker and a secret holding a
    colon each raise plain :class:`totp.RefusedEnrolment`, and the log names a cause that covers
    them, not only parameters this release does not compute with (BACKLOG #5340)."""
    with pytest.raises(totp.RefusedEnrolment) as raised:
        totp.parse_enrolment(stored)
    assert type(raised.value) is totp.RefusedEnrolment
    reason = _totp_unusable_reason(stored)
    assert reason == "refused"
    caplog.set_level("WARNING", logger="messagefoundry.auth.service")
    _log_totp_unusable("synthetic-user", reason)
    assert (
        "the TOTP enrolment of account 'synthetic-user' is refused by this release (a malformed "
        "marker, parameters it does not compute with, or no secret after the marker); no code "
        "matches it until the account enrols again"
    ) in caplog.text
