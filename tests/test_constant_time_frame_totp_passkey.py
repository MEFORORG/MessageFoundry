# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""ASVS 11.2.4 (BACKLOG #1167): two short-circuits removed, each pinned by a count, and one kept.

1. ``backup_codec.decrypt_stream`` runs BOTH AAD tries on every frame, the final one included.
2. ``AuthService._check_both_factors`` KEEPS its short-circuit: ``consume_totp_step`` is asked only
   once a code matched a step. The comment above that line says why.
3. ``finish_webauthn_assertion`` compares every held passkey, each in constant time.

Synthetic data only: random keys, a test administrator, software passkeys.
"""

from __future__ import annotations

import hashlib
import io
import json
import os
import sqlite3
from collections import Counter
from collections.abc import AsyncIterator
from typing import Any

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from messagefoundry import credential
from messagefoundry.auth import service as service_mod
from messagefoundry.auth import totp
from messagefoundry.auth.service import AuthService
from messagefoundry.config.settings import AuthSettings
from messagefoundry.store import backup_codec as bc
from messagefoundry.store.store import MessageStore
from tests._admin_account import ADMIN_USERNAME, create_admin, login_admin
from tests._totp_clock import pin_totp_clock

# --- 1. decrypt_stream: both tries on every frame -------------------------------------------------


class _CountingAes:
    """Wraps the archive's frame AESGCM and records the AAD of every decrypt attempt."""

    def __init__(self, aes: AESGCM, tries: list[bytes]) -> None:
        self._aes = aes
        self._tries = tries

    def decrypt(self, nonce: bytes, data: bytes, aad: bytes) -> bytes:
        self._tries.append(aad)
        return self._aes.decrypt(nonce, data, aad)


def _archive(key: bytes, payload: bytes) -> bytes:
    enc = io.BytesIO()
    bc.encrypt_stream(io.BytesIO(payload), enc, key, chunk_size=4096)
    return enc.getvalue()


def _counted(monkeypatch: pytest.MonkeyPatch) -> list[bytes]:
    tries: list[bytes] = []
    real = bc._frame_aes

    def counted(header: bc.ArchiveHeader, key: bytes) -> Any:
        return _CountingAes(real(header, key), tries)

    monkeypatch.setattr(bc, "_frame_aes", counted)
    return tries


def test_every_frame_takes_both_tries_and_the_payload_is_unchanged(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """RED when: the frame loop gets its ``break`` back, so a non-final frame takes one try."""
    key = os.urandom(32)
    payload = os.urandom(9000)  # three frames at 4096 bytes: two non-final, one final
    blob = _archive(key, payload)
    tries = _counted(monkeypatch)
    out = io.BytesIO()

    bc.decrypt_stream(io.BytesIO(blob), out, key)

    assert out.getvalue() == payload
    digest = hashlib.sha256(bc.read_header(io.BytesIO(blob)).to_json_bytes()).digest()
    # Frame by frame: the non-final AAD, then the final one, for all three frames.
    assert tries == [bc._aad(digest, i, final=f) for i in range(3) for f in (False, True)]


def test_a_tampered_frame_still_fails_closed() -> None:
    key = os.urandom(32)
    blob = bytearray(_archive(key, os.urandom(9000)))
    blob[-20] ^= 0x01  # inside the last frame's ciphertext or tag
    with pytest.raises(bc.BackupCodecError, match="authentication failed"):
        bc.decrypt_stream(io.BytesIO(bytes(blob)), io.BytesIO(), key)


# --- 2. _check_both_factors: the store is asked only once a code matched -----------------------


@pytest.fixture
async def store() -> AsyncIterator[MessageStore]:
    s = await MessageStore.open(":memory:")
    yield s
    await s.close()


def _spy_consume(monkeypatch: pytest.MonkeyPatch, store: MessageStore) -> list[tuple[str, int]]:
    calls: list[tuple[str, int]] = []
    real = store.consume_totp_step

    async def spy(user_id: str, step: int) -> bool:
        calls.append((user_id, step))
        return await real(user_id, step)

    monkeypatch.setattr(store, "consume_totp_step", spy)
    return calls


async def _factors(
    monkeypatch: pytest.MonkeyPatch, store: MessageStore, step: int | None
) -> tuple[AuthService, str, str]:
    """A test administrator whose TOTP check resolves to ``step`` (``None`` is a wrong code)."""
    service = AuthService(store, AuthSettings())
    admin = await create_admin(service)

    async def secret(_user: object) -> str:
        return "SYNTHETICSECRET"

    monkeypatch.setattr(service, "_totp_secret", secret)
    monkeypatch.setattr(totp, "verify_totp_step", lambda *a, **k: step)
    return service, admin.user_id, admin.password


async def test_a_wrong_code_does_not_ask_the_store(
    monkeypatch: pytest.MonkeyPatch, store: MessageStore
) -> None:
    """RED when: ``_check_both_factors`` asks ``consume_totp_step`` on a wrong code."""
    service, user_id, password = await _factors(monkeypatch, store, None)
    calls = _spy_consume(monkeypatch, store)
    user = await service._load_user(user_id)
    assert user is not None

    assert await service._check_both_factors(user, password, "000000") == (True, False)

    assert calls == []


async def test_a_right_code_is_consumed_once(
    monkeypatch: pytest.MonkeyPatch, store: MessageStore
) -> None:
    service, user_id, password = await _factors(monkeypatch, store, 4242)
    calls = _spy_consume(monkeypatch, store)
    user = await service._load_user(user_id)
    assert user is not None

    assert await service._check_both_factors(user, password, "123456") == (True, True)
    user = await service._load_user(user_id)
    assert user is not None
    assert await service._check_both_factors(user, "wrong", "123456") == (False, False)  # replay

    assert calls == [(user_id, 4242), (user_id, 4242)]


async def _totp_enrolled(service: AuthService, monkeypatch: pytest.MonkeyPatch) -> tuple[str, str]:
    """The test administrator with TOTP on. Returns ``(user_id, password)``."""
    identity, token, password = await login_admin(service)
    enroll = await service.begin_mfa_enrollment(identity)
    now = 3_000_000.0
    pin_totp_clock(monkeypatch, now)
    code = totp.totp(enroll.secret, now=now)
    assert (await service.confirm_mfa_enrollment(identity, code, token=token)).ok
    return identity.user_id, password


async def test_a_wrong_code_beside_a_refusing_store_answers_as_a_plain_wrong_code(
    monkeypatch: pytest.MonkeyPatch, store: MessageStore
) -> None:
    """RED when: ``consume_totp_step`` is asked on a wrong code, so a store refusal there escapes
    ``login`` unpadded (a lock error here) instead of answering as a plain wrong code."""
    service = AuthService(store, AuthSettings(mfa_verify_min_elapsed_seconds=0))
    user_id, password = await _totp_enrolled(service, monkeypatch)
    monkeypatch.setattr(totp, "verify_totp_step", lambda *a, **k: None)  # every code is wrong
    padded: list[service_mod.LoginOutcome] = []
    real_pad = service._equalize_failure

    async def spy_pad(
        outcome: service_mod.LoginOutcome, started: float, **kw: Any
    ) -> service_mod.LoginOutcome:
        padded.append(outcome)
        return await real_pad(outcome, started, **kw)

    monkeypatch.setattr(service, "_equalize_failure", spy_pad)

    plain = await service.login(ADMIN_USERNAME, password, totp_code="000000")
    after_plain = await store.get_user(user_id)

    asked: list[int] = []

    async def refused(_user_id: str, step: int) -> bool:
        asked.append(step)
        raise sqlite3.OperationalError("database is locked")

    monkeypatch.setattr(store, "consume_totp_step", refused)
    failed = await service.login(ADMIN_USERNAME, password, totp_code="000000")
    after_failed = await store.get_user(user_id)

    # The refusing call never made, and the same answer handed to the same pad. This checks the
    # pad's entry, not its deadline; tests/test_asvs_login_deadline.py measures the deadline.
    assert asked == []
    assert plain == failed == service_mod.LoginOutcome(ok=False, error="invalid credentials")
    assert padded == [plain, failed]
    # Counted as a right password with a wrong code, on the second-step counter, both times.
    assert after_plain is not None and after_failed is not None
    assert after_plain.second_step_failed_attempts == 1
    assert after_failed.second_step_failed_attempts == 2
    rows = await store.list_audit(actor=ADMIN_USERNAME, action="auth.login_failed")
    assert len(rows) == 2 and rows[0]["detail"] == rows[1]["detail"]


# --- 3. finish_webauthn_assertion: every held passkey compared ------------------------------------

_RP, _ORIGIN = "t", "http://t"


async def _three_passkeys(store: MessageStore) -> tuple[AuthService, str, str, list[Any]]:
    """A test administrator holding three passkeys, and a fresh session that owes one."""
    pytest.importorskip("webauthn")
    from webauthn.helpers import base64url_to_bytes

    from tests._soft_webauthn import SoftAuthenticator

    service = AuthService(store, AuthSettings(require_mfa=False, mfa_verify_min_elapsed_seconds=0))
    identity, token, password = await login_admin(service)
    keys = [SoftAuthenticator(rp_id=_RP, origin=_ORIGIN) for _ in range(3)]
    for n, key in enumerate(keys):
        options = json.loads(
            await service.begin_webauthn_registration(
                identity, token=token, rp_id=_RP, rp_name="MessageFoundry"
            )
        )
        enrolled = await service.finish_webauthn_registration(
            identity,
            key.create_response(base64url_to_bytes(options["challenge"])),
            label=f"key-{n}",
            token=token,
            rp_id=_RP,
            origin=_ORIGIN,
        )
        assert enrolled.ok and enrolled.token is not None, n
        token = enrolled.token  # an enrolment rotates the session
    out = await service.login(ADMIN_USERNAME, password)
    assert out.ok and out.token is not None
    return service, out.token, identity.user_id, keys


async def _assert_with(service: AuthService, token: str, key: Any) -> str:
    from webauthn.helpers import base64url_to_bytes

    challenge = await service.begin_webauthn_assertion(token, rp_id=_RP)
    assert challenge is not None
    response: str = key.get_response(base64url_to_bytes(json.loads(challenge)["challenge"]))
    return response


def _spy_equal(monkeypatch: pytest.MonkeyPatch) -> list[tuple[str | bytes, str | bytes]]:
    calls: list[tuple[str | bytes, str | bytes]] = []
    real = credential.constant_time_equal

    def spy(a: str | bytes, b: str | bytes) -> bool:
        calls.append((a, b))
        return real(a, b)

    monkeypatch.setattr(service_mod, "constant_time_equal", spy)
    return calls


async def test_an_unknown_passkey_is_compared_against_every_held_one(
    monkeypatch: pytest.MonkeyPatch, store: MessageStore
) -> None:
    """RED when: the lookup goes back to ``next(... == wanted)``, which compares with ``==``."""
    service, token, user_id, _keys = await _three_passkeys(store)
    from tests._soft_webauthn import SoftAuthenticator

    response = await _assert_with(service, token, SoftAuthenticator(rp_id=_RP, origin=_ORIGIN))
    held = {c.credential_id_hash for c in await store.list_webauthn_credentials(user_id)}
    assert len(held) == 3
    calls = _spy_equal(monkeypatch)

    refused = await service.finish_webauthn_assertion(token, response, rp_id=_RP, origin=_ORIGIN)

    assert refused.ok is False
    lookups = [(a, b) for a, b in calls if a in held]
    assert Counter(a for a, _ in lookups) == dict.fromkeys(held, 1)
    assert len({b for _, b in lookups}) == 1  # all against the one presented id


async def test_the_first_held_passkey_still_signs_in_after_a_full_walk(
    monkeypatch: pytest.MonkeyPatch, store: MessageStore
) -> None:
    """RED when: the walk stops at the matching slot. The FIRST passkey signs, and the lookup plus
    ``_passkey_held``'s re-check must still compare all three, twice each."""
    service, token, user_id, keys = await _three_passkeys(store)
    response = await _assert_with(service, token, keys[0])
    held = {c.credential_id_hash for c in await store.list_webauthn_credentials(user_id)}
    calls = _spy_equal(monkeypatch)

    verified = await service.finish_webauthn_assertion(token, response, rp_id=_RP, origin=_ORIGIN)

    assert verified.ok is True
    assert Counter(a for a, _ in calls if a in held) == dict.fromkeys(held, 2)
