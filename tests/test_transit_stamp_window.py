# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The stamp-to-rotation window (ADR 0217; decided by the Manager under the Owner's standing
instruction of 2026-10-22, widening "Revoke both"). Synthetic data only.

Once a ceremony's session stamp lands, a refusal :func:`_rotation_store_errors` names, raised
before the rotation begins, revokes the stamped hash and answers ``session_lost`` with an
``auth.session_rotation_failed`` row, as a refused rotation does. One test per site the decision
names. Each injects the refusal at that one call: a Transit Outage
(``TransitSealUnavailableError``) where the call is sealed, and a store refusal (``OSError``, a
connection lost at the socket) at the audit row. The control is a refusal before any stamp landed,
which propagates as before.

Decision d20261109T200352805-599b24 (item 1) widens it: once armed, ANY exception revokes the
stamped hash, shielded from a cancel. The success audit row's ``CipherError`` is answered too; every
other exception (Forged, Unverifiable, any other ``CipherError``, a cancel, a defect) is re-raised.

Decision d20261110T004920629-fb8ff6 (Q4) arms the window before the first stamp's write, so the
control above no longer holds: the first stamp's own refusal revokes too.
"""

from __future__ import annotations

import asyncio
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
from messagefoundry.store.crypto import CipherError
from messagefoundry.store.row_seal import (
    RowSealError,
    RowSealUnverifiableError,
    TransitSealUnavailableError,
)
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


@pytest.mark.parametrize(
    "commit_landed", [True, False], ids=["commit_landed", "commit_never_landed"]
)
async def test_the_first_stamps_own_refusal_revokes_the_hash(
    monkeypatch: pytest.MonkeyPatch, commit_landed: bool
) -> None:
    """Decision d20261110T004920629-fb8ff6, Q4: the window is armed before the first stamp's
    write, so a write that raised, whether or not its commit landed first, revokes the hash and
    answers session_lost. Revoking where it never landed is the accepted availability cost."""
    store, service = await _service()
    try:
        token, secret, t1 = await _pre_mfa(service, monkeypatch)
        stamp = store.mark_session_mfa_verified

        async def ambiguous(*args: Any, **kwargs: Any) -> Any:
            if commit_landed:
                await stamp(*args, **kwargs)
            raise OSError("synthetic: the connection dropped before the commit's ack")

        monkeypatch.setattr(store, "mark_session_mfa_verified", ambiguous)
        lost = await service.verify_mfa(token, totp.totp(secret, now=t1))
        assert lost.session_lost and lost.token is None
        await _assert_lost(store, service, token, ceremony="mfa_verify", reason="store_error")
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


# --- decision d20261109T200352805-599b24, item 3: the lost step-up's auth.reauth row ---------------


def _refuse_audit(monkeypatch: pytest.MonkeyPatch, store: MessageStore, action: str) -> list[str]:
    """Refuse ``action``'s audit write; the returned list grows by one per refused write, so a
    test asserting the row is absent can first show the write was attempted."""
    record_audit = store.record_audit
    refusals: list[str] = []

    async def refused(name: str, **kwargs: Any) -> Any:
        if name == action:
            refusals.append(name)
            raise CipherError("synthetic audit MAC outage")
        return await record_audit(name, **kwargs)

    monkeypatch.setattr(store, "record_audit", refused)
    return refusals


@pytest.mark.parametrize("audit_up", [True, False], ids=["audit_up", "audit_refused"])
async def test_a_lost_reauth_writes_its_row_softly_with_no_grant_verdict(
    monkeypatch: pytest.MonkeyPatch, audit_up: bool
) -> None:
    store, service = await _service()
    try:
        identity, token, password = await login_admin(service)
        monkeypatch.setattr(
            service, "_factor_binding_is_blocked", _raising(TransitSealUnavailableError())
        )
        refusals: list[str] = []
        if not audit_up:
            refusals = _refuse_audit(monkeypatch, store, "auth.reauth")
        lost = await service.reauth(
            identity, password, token=token, purpose=STEP_UP_ACTION_SESSION_TERMINATE
        )
        assert lost.session_lost and lost.token is None
        rows = [json.loads(str(r["detail"])) for r in await store.list_audit(action="auth.reauth")]
        if audit_up:
            assert rows[-1]["session_lost"] is True and rows[-1]["grant_refused"] is None
        else:
            assert len(refusals) >= 1  # the soft write was attempted and refused
            assert await store.list_audit(action="auth.reauth") == []
    finally:
        await store.close()


@pytest.mark.parametrize("audit_up", [True, False], ids=["audit_up", "audit_refused"])
async def test_a_lost_federated_step_up_writes_its_row_softly_with_no_grant_verdict(
    rsa_key: rsa.RSAPrivateKey, monkeypatch: pytest.MonkeyPatch, audit_up: bool
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
        refusals: list[str] = []
        if not audit_up:
            refusals = _refuse_audit(monkeypatch, store, "auth.reauth")
        out = await _return_from_idp(service, monkeypatch, rsa_key, flow_id, auth_time=time.time())
        assert out.elevation.session_lost and out.elevation.token is None
        rows = [json.loads(str(r["detail"])) for r in await store.list_audit(action="auth.reauth")]
        if audit_up:
            assert rows[-1]["session_lost"] is True and rows[-1]["grant_refused"] is None
        else:
            assert len(refusals) >= 1  # the soft write was attempted and refused
            assert await store.list_audit(action="auth.reauth") == []
    finally:
        await store.close()


# --- decision d20261109T200352805-599b24, item 1: any exception revokes once armed -----------------


async def _revoked_unanswered(store: MessageStore, service: AuthService, token: str) -> None:
    """The stamped hash is revoked, and no refused-rotation row answers for it."""
    session = await store.get_session(hash_token(token))
    assert session is not None and session.revoked_at is not None
    assert await service.identity_for_token(token) is None
    assert await store.list_audit(action="auth.session_rotation_failed") == []


@pytest.mark.parametrize(
    "exc",
    [
        RowSealError("user", ""),
        RowSealUnverifiableError("user", ""),
        CipherError("synthetic: not the audit row"),
        KeyError("synthetic code defect"),
        asyncio.CancelledError(),
    ],
    ids=["forged", "unverifiable", "cipher_error_elsewhere", "code_defect", "cancelled"],
)
async def test_any_other_exception_after_the_stamp_revokes_then_reraises(
    monkeypatch: pytest.MonkeyPatch, exc: BaseException
) -> None:
    store, service = await _service()
    try:
        token, secret, t1 = await _pre_mfa(service, monkeypatch)

        async def raising(*_args: object, **_kwargs: object) -> None:
            raise exc

        monkeypatch.setattr(store, "record_login_success", raising)
        with pytest.raises(type(exc)):
            await service.verify_mfa(token, totp.totp(secret, now=t1))
        monkeypatch.undo()
        await _revoked_unanswered(store, service, token)
    finally:
        await store.close()


@pytest.mark.parametrize(
    "exc",
    [
        RowSealError("session", ""),
        RowSealUnverifiableError("session", ""),
        KeyError("synthetic code defect"),
    ],
    ids=["forged", "unverifiable", "code_defect"],
)
async def test_an_exception_at_the_lapse_check_still_revokes_the_stamped_hash(
    monkeypatch: pytest.MonkeyPatch, exc: BaseException
) -> None:
    """The lapse check runs before the rotation, so an exception there that the rotation's own
    handlers do not take is still the window's: it revokes the stamped hash, then re-raises."""
    store, service = await _service()
    try:
        token, secret, t1 = await _pre_mfa(service, monkeypatch)

        async def raising(*_args: object, **_kwargs: object) -> bool:
            raise exc

        monkeypatch.setattr(service, "_rotation_lapsed", raising)
        with pytest.raises(type(exc)):
            await service.verify_mfa(token, totp.totp(secret, now=t1))
        monkeypatch.undo()
        await _revoked_unanswered(store, service, token)
    finally:
        await store.close()


async def test_a_real_cancel_after_the_stamp_still_lands_the_revoke(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The task is cancelled while it waits after the stamp; the revoke is shielded."""
    store, service = await _service()
    try:
        token, secret, t1 = await _pre_mfa(service, monkeypatch)
        entered = asyncio.Event()

        async def hang(*_args: object, **_kwargs: object) -> None:
            entered.set()
            await asyncio.Event().wait()

        monkeypatch.setattr(store, "record_login_success", hang)
        task = asyncio.ensure_future(service.verify_mfa(token, totp.totp(secret, now=t1)))
        await entered.wait()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        monkeypatch.undo()
        await _revoked_unanswered(store, service, token)
    finally:
        await store.close()


@pytest.mark.parametrize(
    "exc",
    [asyncio.CancelledError(), TransitSealUnavailableError()],
    ids=["cancelled", "answered_outage"],
)
async def test_a_failed_window_revoke_never_replaces_the_windows_own_exception(
    monkeypatch: pytest.MonkeyPatch, exc: BaseException
) -> None:
    """The revoke itself fails with an error ``_revoke_unrotated`` does not take (a closed
    aiosqlite connection's ``ValueError``): a cancel is still re-raised as a cancel, and an
    answered Outage still answers ``session_lost``, rather than either turning into that error."""
    store, service = await _service()
    try:
        token, secret, t1 = await _pre_mfa(service, monkeypatch)

        async def raising(*_args: object, **_kwargs: object) -> None:
            raise exc

        async def closed(*_args: object, **_kwargs: object) -> None:
            raise ValueError("synthetic: no active connection")

        monkeypatch.setattr(store, "record_login_success", raising)
        monkeypatch.setattr(store, "revoke_session", closed)
        if isinstance(exc, asyncio.CancelledError):
            with pytest.raises(asyncio.CancelledError):
                await service.verify_mfa(token, totp.totp(secret, now=t1))
        else:
            elevation = await service.verify_mfa(token, totp.totp(secret, now=t1))
            assert elevation.session_lost
    finally:
        await store.close()


async def test_verify_mfa_answers_a_refused_success_audit_row(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The audit set's CipherError at ``auth.mfa_verified`` (on vault_transit, the audit MAC under
    a Transit Outage) answers session_lost."""
    store, service = await _service()
    try:
        token, secret, t1 = await _pre_mfa(service, monkeypatch)
        record_audit = store.record_audit

        async def refused(action: str, **kwargs: Any) -> Any:
            if action == "auth.mfa_verified":
                raise CipherError("synthetic audit MAC outage")
            return await record_audit(action, **kwargs)

        monkeypatch.setattr(store, "record_audit", refused)
        lost = await service.verify_mfa(token, totp.totp(secret, now=t1))
        assert lost.session_lost and lost.token is None
        await _assert_lost(store, service, token, ceremony="mfa_verify", reason="audit_refused")
    finally:
        await store.close()


@requires_webauthn
async def test_the_passkey_assertion_answers_a_refused_success_audit_row(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store, service = await _service()
    try:
        identity, enrolling, password = await login_admin(service)
        _, enrolled = await _enroll_totp(service, identity, enrolling)
        soft, _ = await _enroll_passkey(service, identity, enrolled)
        out = await service.login(ADMIN_USERNAME, password)
        assert out.ok and out.token is not None
        record_audit = store.record_audit

        async def refused(action: str, **kwargs: Any) -> Any:
            if action == "auth.webauthn_verified":
                raise CipherError("synthetic audit MAC outage")
            return await record_audit(action, **kwargs)

        monkeypatch.setattr(store, "record_audit", refused)
        ok, after = await _assert_passkey(service, out.token, soft)
        assert not ok and after == out.token
        await _assert_lost(
            store, service, out.token, ceremony="webauthn_assert", reason="audit_refused"
        )
    finally:
        await store.close()


# --- decision d20261110T004916856-814db8, Q1: a step-up lost at the rotation writes softly --------


@pytest.mark.parametrize("site", ["rotate_session", "lapse_check"])
async def test_a_reauth_lost_at_the_rotation_writes_its_row_softly(
    monkeypatch: pytest.MonkeyPatch, site: str
) -> None:
    """A Transit Outage at the re-key, or at the lapse check, answers session_lost from
    ``_elevated_hash`` with the window closed; the ``auth.reauth`` row, refused by the same
    Outage's audit MAC, is then written softly rather than turning the answer into an error."""
    store, service = await _service()
    try:
        identity, token, password = await login_admin(service)
        if site == "rotate_session":
            monkeypatch.setattr(store, "rotate_session", _raising(TransitSealUnavailableError()))
        else:
            monkeypatch.setattr(
                service, "_rotation_lapsed", _raising(TransitSealUnavailableError())
            )
        _refuse_audit(monkeypatch, store, "auth.reauth")
        lost = await service.reauth(identity, password, token=token)
        assert lost.session_lost and lost.token is None
        assert await store.list_audit(action="auth.reauth") == []
    finally:
        await store.close()


async def test_a_federated_step_up_lost_at_the_rotation_writes_its_row_softly(
    rsa_key: rsa.RSAPrivateKey, monkeypatch: pytest.MonkeyPatch
) -> None:
    from tests.test_auth_oidc_service import _service as _oidc_service

    store = await MessageStore.open(":memory:")
    try:
        service = await _oidc_service(store, rsa_key)
        token = await _oidc_session(service, monkeypatch, rsa_key)
        flow_id, _url = await _begin(service, token, purpose=None)
        monkeypatch.setattr(store, "rotate_session", _raising(TransitSealUnavailableError()))
        _refuse_audit(monkeypatch, store, "auth.reauth")
        out = await _return_from_idp(service, monkeypatch, rsa_key, flow_id, auth_time=time.time())
        assert out.elevation.session_lost and out.elevation.token is None
        assert await store.list_audit(action="auth.reauth") == []
    finally:
        await store.close()


async def test_a_reproof_budget_exhaustion_row_stays_hard(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The flag is the rotation's, not ``Elevation.session_lost``: a failed re-proof that spends
    the session's budget also answers session_lost, and its ``auth.reauth`` row stays hard."""
    store, service = await _service()
    try:
        identity, token, _password = await login_admin(service)
        threshold = service.policy.lockout_threshold
        for _ in range(threshold - 1):
            out = await service.reauth(identity, "synthetic-wrong-password", token=token)
            assert not out.ok and not out.session_lost
        _refuse_audit(monkeypatch, store, "auth.reauth")
        with pytest.raises(CipherError):
            await service.reauth(identity, "synthetic-wrong-password", token=token)
    finally:
        await store.close()


# --- decision d20261110T004916856-814db8, Q3: an Unverifiable answer at the rotation revokes -----


@pytest.mark.parametrize("site", ["load", "rekey"])
async def test_an_unverifiable_answer_at_the_rotation_revokes_the_stamped_hash(
    monkeypatch: pytest.MonkeyPatch, site: str
) -> None:
    """``TransitSealUnverifiableError`` at the rotation's load, or ``RowSealUnverifiableError`` at
    its re-key, arrives after the window has closed; the rotation itself revokes the stamped old
    hash, then re-raises."""
    from messagefoundry.store.row_seal import TransitSealUnverifiableError

    store, service = await _service()
    try:
        token, secret, t1 = await _pre_mfa(service, monkeypatch)
        exc: Exception
        if site == "rekey":
            exc = RowSealUnverifiableError("session", "")
            monkeypatch.setattr(store, "rotate_session", _raising(exc))
        else:
            exc = TransitSealUnverifiableError("session", 2, 3)
            rotating: list[bool] = []
            load_session = service._load_session

            async def lapsed(*_args: object, **_kwargs: object) -> bool:
                rotating.append(True)
                return False

            async def load(token_hash: str) -> Any:
                if rotating:
                    raise exc
                return await load_session(token_hash)

            monkeypatch.setattr(service, "_rotation_lapsed", lapsed)
            monkeypatch.setattr(service, "_load_session", load)
        with pytest.raises(type(exc)):
            await service.verify_mfa(token, totp.totp(secret, now=t1))
        monkeypatch.undo()
        await _revoked_unanswered(store, service, token)
    finally:
        await store.close()
