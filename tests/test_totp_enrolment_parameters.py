# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Each TOTP enrolment records the digest, digit count and period it was made with (BACKLOG #3422).

Before this, all three were module constants and no enrolment said which ones it used, so a release
that changed any of them would have stopped every enrolled authenticator matching. These tests pin
the three halves of the fix: an enrolment written before it (a bare secret, no parameters) still
verifies after a default changes; a marked enrolment computes with what it records; and a marker
naming a parameter set this release does not compile in is refused, never computed with.

"A changed default" is simulated by monkeypatching ``DEFAULT_PARAMETERS`` (and the compiled set a
real release would widen beside it), because that is the edit a future release would make.
"""

from __future__ import annotations

import hmac
import logging
from urllib.parse import parse_qs, urlsplit

import pytest
from _totp_clock import fresh_totp, pin_totp_clock

from messagefoundry.auth import totp
from messagefoundry.auth.service import AuthService, lockable_account_census
from messagefoundry.config.settings import AuthSettings
from messagefoundry.store.store import MessageStore
from tests._admin_account import ADMIN_USERNAME, login_admin

_SECRET = "JBSWY3DPEHPK3PXP"
_T0 = 1_000_000.0
#: A default a later release might move to. Eight digits keeps the digest compiled in.
_MOVED = totp.TotpParameters("SHA256", 8, 30)


#: Every parameter set a shipped release has written to a stored enrolment. APPEND ONLY: a set that
#: leaves the compiled-in list refuses every enrolment made under it, so this is the gate behind the
#: comment on ``_COMPILED_PARAMETERS``. A release that moves the default adds the new one here.
_EVER_SHIPPED = (totp.TotpParameters("SHA256", 6, 30),)


def _reference_code(secret: str, moment: float, digest: str = "sha256") -> str:
    """A 6-digit, 30 s HOTP code computed from RFC 4226 directly rather than through the module
    under test. With SHA-256 it is what an authenticator enrolled before #3422 shows."""
    key = totp._decode_secret(secret)
    mac = hmac.new(key, int(moment // 30).to_bytes(8, "big"), digest).digest()
    offset = mac[-1] & 0x0F
    return str((int.from_bytes(mac[offset : offset + 4], "big") & 0x7FFFFFFF) % 10**6).zfill(6)


def _move_default(monkeypatch: pytest.MonkeyPatch) -> None:
    """What a release changing the default does: a new default, the outgoing one kept compiled in."""
    monkeypatch.setattr(totp, "DEFAULT_PARAMETERS", _MOVED)
    monkeypatch.setattr(
        totp, "_COMPILED_PARAMETERS", totp._COMPILED_PARAMETERS | frozenset({_MOVED})
    )


def test_unmarked_parameters_are_the_ones_enrolments_were_written_with() -> None:
    # Literals, never derived: they describe cells already written.
    assert totp.TotpParameters("SHA256", 6, 30) == totp.UNMARKED_PARAMETERS
    assert totp.parse_enrolment(_SECRET) == (_SECRET, totp.UNMARKED_PARAMETERS)


def test_every_compiled_parameter_set_has_its_digest() -> None:
    assert totp.DEFAULT_PARAMETERS in totp._COMPILED_PARAMETERS
    assert totp.UNMARKED_PARAMETERS in totp._COMPILED_PARAMETERS
    for params in totp._COMPILED_PARAMETERS:
        assert params.algorithm in totp._DIGESTS
    for shipped in _EVER_SHIPPED:
        assert shipped in totp._COMPILED_PARAMETERS, f"{shipped} left the compiled-in list"
    assert totp.DEFAULT_PARAMETERS in _EVER_SHIPPED, "a new default must be appended above"


def test_new_enrolment_records_the_default_and_round_trips() -> None:
    stored = totp.new_enrolment(_SECRET)
    assert stored == f"totp1:SHA256:6:30:{_SECRET}"
    assert totp.parse_enrolment(stored) == (_SECRET, totp.DEFAULT_PARAMETERS)
    assert totp.new_enrolment(stored) == stored  # already stored: unchanged
    assert totp.needs_reenrolment(stored) is False
    code = totp.totp(stored, now=_T0)
    assert code == totp.totp(_SECRET, now=_T0) == _reference_code(_SECRET, _T0)
    assert totp.verify_totp_step(stored, code, now=_T0, window=0) == int(_T0 // 30)


def test_an_unmarked_enrolment_still_verifies_after_the_default_changes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _move_default(monkeypatch)
    code = _reference_code(_SECRET, _T0)
    assert totp.verify_totp_step(_SECRET, code, now=_T0, window=0) == int(_T0 // 30)
    assert totp.totp(_SECRET, now=_T0) == code
    assert totp.needs_reenrolment(_SECRET) is True  # offered a fresh one, still working meanwhile


def test_a_marked_enrolment_computes_with_what_it_records(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    before = totp.new_enrolment(_SECRET)  # written under the 6-digit default
    _move_default(monkeypatch)
    after = totp.new_enrolment(_SECRET)
    assert after == f"totp1:SHA256:8:30:{_SECRET}"
    old_code = _reference_code(_SECRET, _T0)
    assert totp.verify_totp_step(before, old_code, now=_T0, window=0) == int(_T0 // 30)
    assert totp.needs_reenrolment(before) is True
    assert totp.needs_reenrolment(after) is False
    assert len(totp.totp(after, now=_T0)) == 8
    # The URI advertises the enrolment's own parameters, so the app computes alike.
    query = parse_qs(urlsplit(totp.otpauth_uri(before, "u")).query)
    assert query["digits"] == ["6"] and query["algorithm"] == ["SHA256"]
    assert query["secret"] == [_SECRET]
    assert parse_qs(urlsplit(totp.otpauth_uri(after, "u")).query)["digits"] == ["8"]


@pytest.mark.parametrize(
    "stored",
    [
        f"totp1:SHA1:6:30:{_SECRET}",  # retired under G18, not compiled in
        f"totp1:SHA512:6:30:{_SECRET}",  # permitted by RFC 6238, not compiled in
        f"totp1:MD5:6:30:{_SECRET}",
        f"totp1:SHA256:4:30:{_SECRET}",  # a weaker code length is not selectable by a cell
        f"totp1:SHA256:6:1:{_SECRET}",
        f"totp2:SHA256:6:30:{_SECRET}",
        f"totp1:SHA256:6:{_SECRET}",
        f"totp1:SHA256:06:30:{_SECRET}",  # a compiled-in set, but not its canonical spelling
        f"totp1:SHA256:{'9' * 5000}:30:{_SECRET}",  # past int()'s digit limit: still refused
        f"totp1:SHA256:6:30:extra:{_SECRET}",
        "totp1:SHA256:6:30:",
        f"totp1:SHA256:\uff16:30:{_SECRET}",  # a fullwidth digit is not a digit here
        f"mfenc:v1:{_SECRET}",  # ciphertext a keyless open hands through
    ],
)
def test_an_unknown_marker_is_refused(stored: str) -> None:
    with pytest.raises(totp.RefusedEnrolment):
        totp.parse_enrolment(stored)
    with pytest.raises(ValueError):
        totp.totp(stored, now=_T0)
    with pytest.raises(ValueError):
        totp.otpauth_uri(stored, "u")
    with pytest.raises(ValueError):
        totp.new_enrolment(stored)
    assert totp.needs_reenrolment(stored) is True
    # Refused rather than computed with: not even the code the named digest would give matches.
    for code in (_reference_code(_SECRET, _T0, "sha1"), _reference_code(_SECRET, _T0)):
        assert totp.verify_totp_step(stored, code, now=_T0, window=1) is None


def test_an_explicit_parameter_never_contradicts_a_marked_enrolment() -> None:
    stored = totp.new_enrolment(_SECRET)
    assert totp.totp(stored, now=_T0, digits=6, period=30) == totp.totp(stored, now=_T0)
    with pytest.raises(ValueError):
        totp.totp(stored, now=_T0, digits=8)
    with pytest.raises(ValueError):
        totp.verify_totp_step(stored, "123456", now=_T0, period=60)
    # A bare secret keeps the override the RFC vectors use.
    assert len(totp.totp(_SECRET, now=_T0, digits=8)) == 8


async def test_service_enrolment_stores_its_parameters_and_reports_none_to_redo() -> None:
    store = await MessageStore.open(":memory:")
    try:
        service = AuthService(store, AuthSettings(mfa_verify_min_elapsed_seconds=0))
        identity, token, _ = await login_admin(service)
        enroll = await service.begin_mfa_enrollment(identity)
        stored = await store.get_totp_secret(identity.user_id)
        assert stored == totp.new_enrolment(enroll.secret)
        assert "digits=6" in enroll.otpauth_uri and enroll.secret in enroll.otpauth_uri
        confirmed = await service.confirm_mfa_enrollment(
            identity, fresh_totp(enroll.secret), token=token
        )
        assert confirmed.ok
        assert (await service.mfa_status(identity)).totp_reenrolment_recommended is False
    finally:
        await store.close()


async def test_an_enrolment_written_before_the_change_signs_in_after_a_default_moves(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = await MessageStore.open(":memory:")
    try:
        service = AuthService(store, AuthSettings(mfa_verify_min_elapsed_seconds=0))
        identity, token, password = await login_admin(service)
        await service.begin_mfa_enrollment(identity)
        # Overwrite the staged cell with today's shape: the bare secret, no parameters recorded.
        staged = await store.set_totp_secret(identity.user_id, secret=_SECRET)
        assert staged is not None
        pin_totp_clock(monkeypatch, _T0)
        confirmed = await service.confirm_mfa_enrollment(
            identity, _reference_code(_SECRET, _T0), token=token
        )
        assert confirmed.ok
        assert (await service.mfa_status(identity)).totp_reenrolment_recommended is False

        _move_default(monkeypatch)
        status = await service.mfa_status(identity)
        assert status.enabled and status.totp_reenrolment_recommended is True

        out = await service.login(ADMIN_USERNAME, password)
        assert out.ok and out.mfa_required and out.token is not None
        t1 = _T0 + 30
        pin_totp_clock(monkeypatch, t1)
        verified = await service.verify_mfa(out.token, _reference_code(_SECRET, t1))
        assert verified.ok is True
    finally:
        await store.close()


async def test_a_refused_enrolment_is_named_by_the_census_with_its_own_cause(
    caplog: pytest.LogCaptureFixture,
) -> None:
    store = await MessageStore.open(":memory:")
    try:
        service = AuthService(store, AuthSettings(mfa_verify_min_elapsed_seconds=0))
        identity, _, _ = await login_admin(service)
        cell = await store.set_totp_secret(identity.user_id, secret=f"totp1:SHA1:6:30:{_SECRET}")
        assert await store.enable_totp(
            identity.user_id, recovery_code_hashes=[], expected_secret_cell=cell
        )
        with caplog.at_level(logging.WARNING, logger="messagefoundry.auth.service"):
            census = await lockable_account_census(store, AuthSettings())
        assert census.undecryptable_totp == (ADMIN_USERNAME,)
        assert any("does not compute with" in r.getMessage() for r in caplog.records)
        assert not any("does not decrypt" in r.getMessage() for r in caplog.records)
    finally:
        await store.close()
