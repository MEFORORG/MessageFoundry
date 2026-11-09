# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The stamp-to-rotation window (ADR 0217; decided by the Manager under the Owner's standing
instruction of 2026-10-22, widening "Revoke both"). Synthetic data only.

Once a ceremony's session stamp lands, a refusal :func:`_rotation_store_errors` names, raised
before the rotation begins, revokes the stamped hash and answers ``session_lost`` with an
``auth.session_rotation_failed`` row, as a refused rotation does. One test per site the decision
names. Each injects the refusal at that one call: a Transit Outage
(``TransitSealUnavailableError``) where the call is sealed, and a store refusal (``OSError``, a
connection lost at the socket) at the audit row, whose Transit form is ``CipherError`` and is not
in the tuple. The control is a refusal before any stamp landed, which propagates as before.
"""

from __future__ import annotations

import json
import time
from typing import Any

import pytest
from _extras_probe import OPTIONAL_EXTRAS, extra_is_installed
from _totp_clock import pin_totp_clock
from cryptography.hazmat.primitives.asymmetric import rsa

from messagefoundry.auth import totp
from messagefoundry.auth.service import STEP_UP_ACTION_SESSION_TERMINATE, AuthService
from messagefoundry.auth.tokens import hash_token
from messagefoundry.config.settings import AuthSettings
from messagefoundry.store.row_seal import TransitSealUnavailableError
from messagefoundry.store.store import MessageStore
from tests._admin_account import ADMIN_USERNAME, login_admin
from tests.test_oidc_step_up import _begin, _oidc_session, _return_from_idp
from tests.test_session_token_at_elevation_sites import (
    _assert_passkey,
    _enroll_passkey,
    _enroll_totp,
)

requires_webauthn = pytest.mark.skipif(
    not extra_is_installed(OPTIONAL_EXTRAS["webauthn"]),
    reason="the [webauthn] extra is not installed",
)


@pytest.fixture(scope="module")
def rsa_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=3072)


@pytest.fixture(autouse=True)
def _no_failure_pad(monkeypatch: pytest.MonkeyPatch) -> None:
    async def _no_sleep(deadline: float) -> None:
        return None

    monkeypatch.setattr("messagefoundry.auth.service._sleep_until", _no_sleep)


def _raising(exc: Exception) -> Any:
    async def refused(*_args: object, **_kwargs: object) -> Any:
        raise exc

    return refused


async def _service() -> tuple[MessageStore, AuthService]:
    store = await MessageStore.open(":memory:")
    return store, AuthService(
        store,
        AuthSettings(mfa_verify_min_elapsed_seconds=0, mfa_recovery_code_count=1),
    )


async def _assert_lost(
    store: MessageStore, service: AuthService, token: str, *, ceremony: str, reason: str
) -> None:
    """The stamped hash is revoked and the refusal is recorded as a refused rotation."""
    session = await store.get_session(hash_token(token))
    assert session is not None and session.revoked_at is not None
    rows = await store.list_audit(action="auth.session_rotation_failed")
    assert [json.loads(str(r["detail"])) for r in rows] == [
        {"ceremony": ceremony, "reason": reason, "revokes_landed": True}
    ]
    rotated = await store.list_audit(action="auth.session_rotated")
    assert all(json.loads(str(r["detail"]))["ceremony"] != ceremony for r in rotated)
    assert await service.identity_for_token(token) is None


async def _pre_mfa(service: AuthService, monkeypatch: pytest.MonkeyPatch) -> tuple[str, str, float]:
    """An enrolled admin's pre-MFA session: ``(token, secret, the TOTP time to verify at)``."""
    identity, enrolling, password = await login_admin(service)
    t0 = 1_000_000.0
    pin_totp_clock(monkeypatch, t0)
    secret, _ = await _enroll_totp(service, identity, enrolling, now=t0)
    out = await service.login(ADMIN_USERNAME, password)
    assert out.ok and out.token is not None
    t1 = t0 + totp.DEFAULT_PERIOD
    pin_totp_clock(monkeypatch, t1)
    return out.token, secret, t1


@pytest.mark.parametrize(
    ("site", "exc", "reason"),
    [
        ("mark_session_reauthed", TransitSealUnavailableError(), "transit_unavailable"),
        ("record_login_success", TransitSealUnavailableError(), "transit_unavailable"),
        ("record_audit", OSError("synthetic socket loss"), "store_error"),
    ],
    ids=["second_stamp", "record_login_success", "audit_after_the_stamp"],
)
async def test_verify_mfa_after_its_stamp_answers_session_lost(
    monkeypatch: pytest.MonkeyPatch, site: str, exc: Exception, reason: str
) -> None:
    store, service = await _service()
    try:
        token, secret, t1 = await _pre_mfa(service, monkeypatch)
        if site == "record_audit":
            record_audit = store.record_audit

            async def refused(action: str, **kwargs: Any) -> Any:
                if action == "auth.mfa_verified":
                    raise exc
                return await record_audit(action, **kwargs)

            monkeypatch.setattr(store, "record_audit", refused)
        else:
            monkeypatch.setattr(store, site, _raising(exc))
        lost = await service.verify_mfa(token, totp.totp(secret, now=t1))
        assert lost.session_lost and lost.token is None
        await _assert_lost(store, service, token, ceremony="mfa_verify", reason=reason)
    finally:
        await store.close()


async def test_a_refusal_before_any_stamp_landed_propagates_as_before(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Control: the first stamp itself refused, so no stamp landed and the window is not armed."""
    store, service = await _service()
    try:
        token, secret, t1 = await _pre_mfa(service, monkeypatch)
        monkeypatch.setattr(
            store, "mark_session_mfa_verified", _raising(TransitSealUnavailableError())
        )
        with pytest.raises(TransitSealUnavailableError):
            await service.verify_mfa(token, totp.totp(secret, now=t1))
        assert await store.list_audit(action="auth.session_rotation_failed") == []
    finally:
        await store.close()


@requires_webauthn
async def test_the_passkey_assertion_after_its_stamp_answers_session_lost(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store, service = await _service()
    try:
        identity, enrolling, password = await login_admin(service)
        _, enrolled = await _enroll_totp(service, identity, enrolling)
        soft, _ = await _enroll_passkey(service, identity, enrolled)
        out = await service.login(ADMIN_USERNAME, password)
        assert out.ok and out.token is not None
        monkeypatch.setattr(store, "record_login_success", _raising(TransitSealUnavailableError()))
        ok, after = await _assert_passkey(service, out.token, soft)
        assert not ok and after == out.token  # no rotated token came back
        await _assert_lost(
            store,
            service,
            out.token,
            ceremony="webauthn_assert",
            reason="transit_unavailable",
        )
    finally:
        await store.close()


async def test_reauth_after_its_stamp_answers_session_lost(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The factor-binding check runs between the stamp and the rotation."""
    store, service = await _service()
    try:
        identity, token, password = await login_admin(service)
        monkeypatch.setattr(
            service, "_factor_binding_is_blocked", _raising(TransitSealUnavailableError())
        )
        lost = await service.reauth(
            identity, password, token=token, purpose=STEP_UP_ACTION_SESSION_TERMINATE
        )
        assert lost.session_lost and lost.token is None
        await _assert_lost(store, service, token, ceremony="reauth", reason="transit_unavailable")
        rows = await store.list_audit(action="auth.reauth")
        assert json.loads(str(rows[-1]["detail"]))["session_lost"] is True
    finally:
        await store.close()


async def test_the_federated_callback_after_its_stamp_answers_session_lost(
    rsa_key: rsa.RSAPrivateKey, monkeypatch: pytest.MonkeyPatch
) -> None:
    from tests.test_auth_oidc_service import _service as _oidc_service

    store = await MessageStore.open(":memory:")
    try:
        service = await _oidc_service(store, rsa_key)
        token = await _oidc_session(service, monkeypatch, rsa_key)
        flow_id, _url = await _begin(service, token, purpose=STEP_UP_ACTION_SESSION_TERMINATE)
        monkeypatch.setattr(
            service, "_factor_binding_is_blocked_hash", _raising(TransitSealUnavailableError())
        )
        out = await _return_from_idp(service, monkeypatch, rsa_key, flow_id, auth_time=time.time())
        assert out.elevation.session_lost and out.elevation.token is None
        await _assert_lost(
            store, service, token, ceremony="reauth_oidc", reason="transit_unavailable"
        )
    finally:
        await store.close()
