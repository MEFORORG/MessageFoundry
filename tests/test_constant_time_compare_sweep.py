# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""ASVS 11.2.4 (BACKLOG #1167): the constant-time compare sweep.

Sections 1 to 5 cover the converted compares. Each gets an outcome test, on a match and on a
mismatch, and a spy on the module's own ``constant_time_equal`` binding, so a revert to ``==`` turns
the spy test RED while the outcome tests stay green.

Section 6 is not a compare. It covers the store cipher's keyring fallback, which now tries every
key with no early exit, and it counts decrypt calls rather than spying on a helper.

The web console's session-list route is pinned beside its existing tests in
``packaging/messagefoundry-webconsole/tests/test_webui_search_sso.py``, because its fixtures live
there.

Synthetic data only: random keys, made-up hashes, a throwaway PEM-shaped file.
"""

from __future__ import annotations

import base64
import hashlib
import io
import os
from collections.abc import AsyncIterator, Callable, Iterator
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from messagefoundry import credential
from messagefoundry.api import auth_routes
from messagefoundry.auth import service as service_mod
from messagefoundry.auth import trust_anchors
from messagefoundry.auth.service import STEP_UP_ACTION_MFA_ENROLL, AuthService
from messagefoundry.config.settings import AuthSettings, EgressSettings
from messagefoundry.pipeline import Engine
from messagefoundry.store import backup_codec as bc
from messagefoundry.store import crypto
from messagefoundry.store.store import SessionRecord

# Fixed-width, hex, made up: the shape of a session token hash (SHA-256 hex).
OLD = "a" * 64
NEW = "b" * 64
OTHER = "c" * 64


def _spy(
    monkeypatch: pytest.MonkeyPatch, module: ModuleType
) -> list[tuple[str | bytes, str | bytes]]:
    """Wrap ``module.constant_time_equal`` and record every call. The real helper still decides."""
    calls: list[tuple[str | bytes, str | bytes]] = []
    real: Callable[[str | bytes, str | bytes], bool] = credential.constant_time_equal

    def spy(a: str | bytes, b: str | bytes) -> bool:
        calls.append((a, b))
        return real(a, b)

    monkeypatch.setattr(module, "constant_time_equal", spy)
    return calls


# --- 1. AuthService._rekey_token_state -----------------------------------------------------------


@pytest.fixture
async def service(tmp_path: Path) -> AsyncIterator[AuthService]:
    eng = await Engine.create(
        tmp_path / "ct_sweep.db",
        poll_interval=0.02,
        egress_settings=EgressSettings(deny_by_default=False),
    )
    svc = AuthService(eng.store, AuthSettings(login_rate_limit_enabled=False))
    await svc.initialize()
    yield svc
    await eng.stop()


async def test_rekey_moves_the_matching_grant_and_leaves_the_other(service: AuthService) -> None:
    """RED when: the grant walk stops matching on the old hash, or matches every hash."""
    service._action_step_up_grants[(OLD, STEP_UP_ACTION_MFA_ENROLL)] = 111.0
    service._action_step_up_grants[(OTHER, STEP_UP_ACTION_MFA_ENROLL)] = 222.0

    service._rekey_token_state(OLD, NEW)

    assert service._action_step_up_grants == {
        (NEW, STEP_UP_ACTION_MFA_ENROLL): 111.0,
        (OTHER, STEP_UP_ACTION_MFA_ENROLL): 222.0,
    }


async def test_rekey_compares_grant_hashes_in_constant_time(
    service: AuthService, monkeypatch: pytest.MonkeyPatch
) -> None:
    """RED when: `_rekey_token_state` goes back to `h == old_hash`."""
    calls = _spy(monkeypatch, service_mod)
    service._action_step_up_grants[(OLD, STEP_UP_ACTION_MFA_ENROLL)] = 111.0
    service._action_step_up_grants[(OTHER, STEP_UP_ACTION_MFA_ENROLL)] = 222.0

    service._rekey_token_state(OLD, NEW)

    assert sorted(calls) == [(OLD, OLD), (OTHER, OLD)]


# --- 2. api/auth_routes._session_info ------------------------------------------------------------


def _session(token_hash: str) -> SessionRecord:
    return SessionRecord(
        token_hash=token_hash,
        user_id="u-ct",
        created_at=1.0,
        expires_at=3.0,
        last_used_at=2.0,
        revoked_at=None,
        client="198.51.100.7",
    )


def test_session_info_flags_only_the_current_session() -> None:
    assert auth_routes._session_info(_session(OLD), OLD).current is True
    assert auth_routes._session_info(_session(OTHER), OLD).current is False


def test_session_info_compares_in_constant_time(monkeypatch: pytest.MonkeyPatch) -> None:
    """RED when: `_session_info` goes back to `session.token_hash == current_token_hash`."""
    calls = _spy(monkeypatch, auth_routes)
    assert auth_routes._session_info(_session(OTHER), OLD).current is False
    assert calls == [(OTHER, OLD)]


# --- 3. web console ui_account_sessions: pinned in test_webui_search_sso.py (see the module docstring)


# --- 4. auth/trust_anchors.evaluate_anchor -------------------------------------------------------


def _anchor(tmp_path: Path) -> tuple[Path, str]:
    path = tmp_path / "anchor.pem"
    path.write_bytes(b"-----BEGIN CERTIFICATE-----\nc3ludGhldGlj\n-----END CERTIFICATE-----\n")
    return path, hashlib.sha256(path.read_bytes()).hexdigest()


def _with_colons_upper(digest: str) -> str:
    """The same pin as an operator might paste it: upper case, colon-separated pairs."""
    return ":".join(digest[i : i + 2] for i in range(0, len(digest), 2)).upper()


def test_pin_outcome_is_unchanged(tmp_path: Path) -> None:
    path, digest = _anchor(tmp_path)
    spec = trust_anchors.AnchorSpec

    assert trust_anchors.evaluate_anchor(spec("t", "[t].ca", str(path), digest)).pin_ok is True
    # Normalization still applies: case and ':' separators do not change a match.
    pasted = _with_colons_upper(digest)
    assert trust_anchors.evaluate_anchor(spec("t", "[t].ca", str(path), pasted)).pin_ok is True
    assert trust_anchors.evaluate_anchor(spec("t", "[t].ca", str(path), "0" * 64)).pin_ok is False
    assert trust_anchors.evaluate_anchor(spec("t", "[t].ca", str(path))).pin_ok is None


def test_pin_compare_is_constant_time(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """RED when: `evaluate_anchor` goes back to `fingerprint == _normalize_pin(spec.pin)`."""
    path, digest = _anchor(tmp_path)
    calls = _spy(monkeypatch, trust_anchors)

    spec = trust_anchors.AnchorSpec("t", "[t].ca", str(path), _with_colons_upper(digest))
    assert trust_anchors.evaluate_anchor(spec).pin_ok is True
    # Both sides reach the helper already normalized to 64 lowercase hex characters.
    assert calls == [(digest, digest)]

    calls.clear()
    assert (
        trust_anchors.evaluate_anchor(trust_anchors.AnchorSpec("t", "x", str(path))).pin_ok is None
    )
    assert calls == [], "no pin, no compare"


# --- 5. store/backup_codec.decrypt_stream --------------------------------------------------------


def _archive(key: bytes, payload: bytes) -> bytes:
    enc = io.BytesIO()
    bc.encrypt_stream(io.BytesIO(payload), enc, key, chunk_size=4096)
    return enc.getvalue()


def test_key_id_outcome_is_unchanged() -> None:
    key = os.urandom(32)
    payload = os.urandom(5000)
    out = io.BytesIO()
    bc.decrypt_stream(io.BytesIO(_archive(key, payload)), out, key)
    assert out.getvalue() == payload

    with pytest.raises(bc.BackupKeyMismatch):
        bc.decrypt_stream(io.BytesIO(_archive(key, payload)), io.BytesIO(), os.urandom(32))


def test_key_id_compare_is_constant_time(monkeypatch: pytest.MonkeyPatch) -> None:
    """RED when: `decrypt_stream` goes back to `header.key_id != expected_kid`."""
    key = os.urandom(32)
    blob = _archive(key, b"synthetic")
    calls = _spy(monkeypatch, bc)

    bc.decrypt_stream(io.BytesIO(blob), io.BytesIO(), key)

    kid = bc.key_fingerprint(key)
    assert calls == [(kid, kid)]


# --- 6. store/crypto AesGcmCipher.decrypt: the keyring fallback has no early exit ----------------
# Manager decision 2026-10-10 under the owner's driver rule, not an owner ruling (see the comment
# in AesGcmCipher.decrypt). The fast path still stops at the key the marker names.


def _keyring() -> tuple[crypto.AesGcmCipher, list[bytes]]:
    """An active key plus three retired keys: the first, middle and last retired slots."""
    b64 = [crypto.generate_key() for _ in range(4)]
    cipher = crypto.make_cipher(b64[0], b64[1:])
    assert isinstance(cipher, crypto.AesGcmCipher)
    return cipher, [base64.b64decode(k) for k in b64]


def _sealed(key: bytes, plaintext: bytes, *, key_id: str = "0") -> str:
    """A v1 row sealed by ``key`` whose marker names ``key_id``. The default "0" is a legacy row."""
    nonce = os.urandom(12)
    blob = base64.b64encode(nonce + AESGCM(key).encrypt(nonce, plaintext, None)).decode()
    return f"{crypto.PREFIX}{key_id}:{blob}"


class _Counting:
    """Wraps one candidate AESGCM and counts its decrypt calls."""

    def __init__(self, aes: AESGCM, calls: list[int]) -> None:
        self._aes = aes
        self._calls = calls

    def decrypt(self, nonce: bytes, data: bytes, aad: bytes | None) -> bytes:
        self._calls.append(1)
        return self._aes.decrypt(nonce, data, aad)


def _count_tries(monkeypatch: pytest.MonkeyPatch, cipher: crypto.AesGcmCipher) -> list[int]:
    calls: list[int] = []
    real = cipher._candidates

    def counted(key_id: str, salt: bytes | None) -> Iterator[Any]:
        return (_Counting(aes, calls) for aes in real(key_id, salt))

    monkeypatch.setattr(cipher, "_candidates", counted)
    return calls


@pytest.mark.parametrize("slot", [1, 2, 3], ids=["first-retired", "middle-retired", "last-retired"])
def test_a_fallback_row_sealed_by_any_retired_key_still_decrypts(slot: int) -> None:
    cipher, keys = _keyring()
    assert cipher.decrypt(_sealed(keys[slot], b"synthetic-legacy")) == "synthetic-legacy"


def test_a_row_whose_named_key_fails_tries_every_key_and_decrypts(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """RED when: the loop breaks on any hit once the marker names a key (`if named: break`)."""
    cipher, keys = _keyring()
    calls = _count_tries(monkeypatch, cipher)
    # The marker names the ACTIVE key, but the FIRST retired key (candidate 2 of 4) sealed it.
    row = _sealed(keys[1], b"synthetic-misnamed", key_id=cipher.active_key_id)
    assert cipher.decrypt(row) == "synthetic-misnamed"
    assert len(calls) == 4


def test_a_row_no_key_opens_raises_the_same_error() -> None:
    cipher, _ = _keyring()
    with pytest.raises(crypto.CipherError, match="no configured key decrypts this value"):
        cipher.decrypt(_sealed(os.urandom(32), b"synthetic-orphan"))


def test_an_unreadable_plaintext_still_raises_the_utf8_error() -> None:
    cipher, keys = _keyring()
    with pytest.raises(crypto.CipherError, match="not valid UTF-8"):
        cipher.decrypt(_sealed(keys[1], b"\xff\xfe"))


def test_the_fallback_tries_every_key_even_after_an_early_one_verifies(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """RED when: the fallback loop gets its early exit back. The FIRST retired key (candidate 2 of
    4) opens this legacy row, and all four candidates must still be tried."""
    cipher, keys = _keyring()
    calls = _count_tries(monkeypatch, cipher)
    assert cipher.decrypt(_sealed(keys[1], b"synthetic-legacy")) == "synthetic-legacy"
    assert len(calls) == 4


def test_the_named_fast_path_still_stops_at_the_named_key(monkeypatch: pytest.MonkeyPatch) -> None:
    """RED when: the fast path loses its early exit and every read pays for the whole keyring."""
    cipher, keys = _keyring()
    calls = _count_tries(monkeypatch, cipher)
    row = _sealed(keys[0], b"synthetic-current", key_id=cipher.active_key_id)
    assert cipher.decrypt(row) == "synthetic-current"
    assert len(calls) == 1
