# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""ASVS 11.2.4 (BACKLOG #1167): the constant-time compare sweep.

Each converted site gets two tests. One pins that the outcome is unchanged, on a match and on a
mismatch. The other spies on the module's own ``constant_time_equal`` binding and asserts the site
called it, so a revert to ``==`` turns the spy test RED while the outcome tests stay green.

The web console's session-list route is pinned beside its existing tests in
``packaging/messagefoundry-webconsole/tests/test_webui.py``, because its fixtures live there.

Synthetic data only: random keys, made-up hashes, a throwaway PEM-shaped file.
"""

from __future__ import annotations

import hashlib
import io
import os
from collections.abc import AsyncIterator, Callable
from pathlib import Path
from types import ModuleType

import pytest

from messagefoundry import credential
from messagefoundry.api import auth_routes
from messagefoundry.auth import service as service_mod
from messagefoundry.auth import trust_anchors
from messagefoundry.auth.service import STEP_UP_ACTION_MFA_ENROLL, AuthService
from messagefoundry.config.settings import AuthSettings, EgressSettings
from messagefoundry.pipeline import Engine
from messagefoundry.store import backup_codec as bc
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


# --- 3. web console ui_account_sessions: pinned in test_webui.py (see the module docstring) ---


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
