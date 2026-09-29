# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The ASVS 2.4.2 minimum-elapsed floors on a second step (BACKLOG #2301).

Three pairs are floored: sign-in then the second factor (a TOTP or recovery code, or a passkey),
the federated sign-in start then its callback, and the federated step-up start then its callback.
Each floor is tested just inside it, where the step is refused, and just past it, where the same
step is served. No test sleeps: the clock each floor reads is faked, and only that clock.

The MFA floor reads the service module's wall clock against the session's ``created_at``, so those
tests replace ``messagefoundry.auth.service.time`` (``time()`` faked, ``monotonic()`` real). The
federated floors read the flow cache's own clock, so those tests replace that one clock. The TOTP
module keeps its own clock throughout, pinned where a code must land in a known step.
"""

from __future__ import annotations

import json
import time
import urllib.parse
from collections.abc import Callable
from types import SimpleNamespace
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from pydantic import ValidationError

from messagefoundry.auth import oidc, totp
from messagefoundry.auth.service import TOO_EARLY, AuthService, Elevation
from messagefoundry.auth.tokens import hash_token
from messagefoundry.config.settings import AuthSettings
from messagefoundry.store.store import MessageStore
from tests._admin_account import ADMIN_USERNAME, login_admin
from tests._totp_clock import pin_totp_clock
from tests.test_auth_oidc_service import (
    AUTH_CODE,
    DEFAULT_SUB,
    _audit_rows,
    _oidc_login,
    _service,
)

ORIGIN = "https://ops.example"
MFA_FLOOR = AuthSettings().mfa_verify_min_elapsed_seconds
OIDC_FLOOR = AuthSettings().oidc_callback_min_elapsed_seconds


@pytest.fixture(scope="module")
def rsa_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=3072)


@pytest.fixture(autouse=True)
def _no_failure_pad(monkeypatch: pytest.MonkeyPatch) -> None:
    # A refused sign-in callback is held to a fixed deadline (BACKLOG #1947). Waiting it out adds
    # nothing here, so the wait is skipped, as the step-up suite skips it.
    async def _no_sleep(deadline: float) -> None:
        return None

    monkeypatch.setattr("messagefoundry.auth.service._sleep_until", _no_sleep)


def _fake_service_wall_clock(monkeypatch: pytest.MonkeyPatch, now: list[float]) -> None:
    """Fake only the service module's ``time.time()``; its ``monotonic()`` stays real."""
    monkeypatch.setattr(
        "messagefoundry.auth.service.time",
        SimpleNamespace(time=lambda: now[0], monotonic=time.monotonic),
    )


def _reasons(rows: list[Any]) -> list[str | None]:
    return [json.loads(str(r["detail"])).get("reason") if r["detail"] else None for r in rows]


# --- settings -------------------------------------------------------------------------------------


def test_both_second_step_floors_ship_on_at_their_provisional_defaults() -> None:
    # Pinned, because each default is a provisional human-timing floor derived in the comment on its
    # setting. Changing one must be a deliberate act that moves docs/SECURITY.md too.
    assert MFA_FLOOR == 1.0
    assert OIDC_FLOOR == 1.0


@pytest.mark.parametrize(
    "field", ["mfa_verify_min_elapsed_seconds", "oidc_callback_min_elapsed_seconds"]
)
@pytest.mark.parametrize("value", [-0.5, float("nan"), float("inf")])
def test_a_floor_refuses_a_value_that_would_switch_it_off_or_jam_it(
    field: str, value: float
) -> None:
    # nan compares False against everything, so `elapsed < nan` would switch a floor off silently.
    with pytest.raises(ValidationError):
        AuthSettings(**{field: value})  # type: ignore[arg-type]


def test_a_federated_floor_as_long_as_the_flow_ttl_is_refused_at_load() -> None:
    # Every flow would expire before its callback could clear the floor.
    with pytest.raises(ValidationError, match="shorter than oidc_flow_ttl_seconds"):
        AuthSettings(oidc_flow_ttl_seconds=30, oidc_callback_min_elapsed_seconds=30.0)
    AuthSettings(oidc_flow_ttl_seconds=30, oidc_callback_min_elapsed_seconds=29.0)


# --- sign-in then the TOTP second factor ----------------------------------------------------------


async def _pending_totp_session(
    monkeypatch: pytest.MonkeyPatch, **settings: Any
) -> tuple[MessageStore, AuthService, str, str, float]:
    """An account with TOTP enrolled, signed in again so its new session OWES the second factor.

    Returns ``(store, service, pending token, the code for the next step, the session's mint)``."""
    store = await MessageStore.open(":memory:")
    service = AuthService(store, AuthSettings(**settings))
    identity, token, password = await login_admin(service)
    enroll = await service.begin_mfa_enrollment(identity)
    # Enrollment consumes the activating step, so the sign-in's code sits in the NEXT step.
    t0 = 1_000_000.0
    pin_totp_clock(monkeypatch, t0)
    await service.confirm_mfa_enrollment(identity, totp.totp(enroll.secret, now=t0), token=token)
    t1 = t0 + totp.DEFAULT_PERIOD
    pin_totp_clock(monkeypatch, t1)
    out = await service.login(ADMIN_USERNAME, password)
    assert out.ok and out.mfa_required and out.token is not None
    session = await store.get_session(hash_token(out.token))
    assert session is not None and session.mfa_verified_at is None
    return store, service, out.token, totp.totp(enroll.secret, now=t1), session.created_at


async def test_a_code_just_inside_the_floor_is_refused_like_a_wrong_one(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store, service, token, code, minted = await _pending_totp_session(monkeypatch)
    try:
        now = [minted + MFA_FLOOR - 0.001]
        _fake_service_wall_clock(monkeypatch, now)

        early = await service.verify_mfa(token, code)

        # The SAME outcome a wrong code gets, so the caller learns nothing about timing.
        assert early == Elevation()
        assert not await service.mfa_satisfied(token)
        assert _reasons(await _audit_rows(store, "auth.mfa_failed")) == [TOO_EARLY]
        pending = await store.get_session(hash_token(token))
        assert pending is not None
        user = await store.get_user(pending.user_id)
        assert user is not None and user.second_step_failed_attempts == 0, "it charged the lockout"

        # CONTROL: just past the floor, the SAME code is served, so the refusal spent nothing.
        now[0] = minted + MFA_FLOOR + 0.001
        served = await service.verify_mfa(token, code)
        assert served.ok and served.token is not None
    finally:
        await store.close()


async def test_a_session_whose_factor_is_satisfied_is_not_floored(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The floor is on the login-then-MFA PAIR. A step-up code on a session that already proved its
    # factor is a different flow, so it is not held to the time since sign-in.
    store, service, token, code, minted = await _pending_totp_session(monkeypatch)
    try:
        now = [minted + MFA_FLOOR + 0.001]
        _fake_service_wall_clock(monkeypatch, now)
        served = await service.verify_mfa(token, code)
        assert served.ok and served.token is not None
        rotated = await store.get_session(hash_token(served.token))
        assert rotated is not None and rotated.mfa_verified_at is not None

        now[0] = rotated.created_at  # no time at all since this session's mint
        secret = await store.get_totp_secret(rotated.user_id)
        assert secret is not None
        t2 = 1_000_000.0 + 2 * totp.DEFAULT_PERIOD
        pin_totp_clock(monkeypatch, t2)
        step_up = await service.verify_mfa(served.token, totp.totp(secret, now=t2))
        assert step_up.ok, "a satisfied session's step-up code was held to the sign-in floor"
    finally:
        await store.close()


async def test_a_floor_of_zero_serves_a_code_at_the_instant_of_sign_in(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store, service, token, code, minted = await _pending_totp_session(
        monkeypatch, mfa_verify_min_elapsed_seconds=0
    )
    try:
        _fake_service_wall_clock(monkeypatch, [minted])
        assert (await service.verify_mfa(token, code)).ok
    finally:
        await store.close()


# --- sign-in then a passkey as the second factor --------------------------------------------------


async def test_a_passkey_just_inside_the_floor_is_refused_and_just_past_it_served(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pytest.importorskip("webauthn")
    from webauthn.helpers import base64url_to_bytes

    from tests._soft_webauthn import SoftAuthenticator

    rp, origin = "t", "http://t"
    store = await MessageStore.open(":memory:")
    try:
        service = AuthService(store, AuthSettings(require_mfa=False))
        identity, token, password = await login_admin(service)
        auth = SoftAuthenticator(rp_id=rp, origin=origin)
        options = json.loads(
            await service.begin_webauthn_registration(
                identity, token=token, rp_id=rp, rp_name="MessageFoundry"
            )
        )
        enrolled = await service.finish_webauthn_registration(
            identity,
            auth.create_response(base64url_to_bytes(options["challenge"]), transports=["usb"]),
            label="key",
            token=token,
            rp_id=rp,
            origin=origin,
        )
        assert enrolled.ok

        out = await service.login(ADMIN_USERNAME, password)
        assert out.ok and out.mfa_required and out.token is not None
        session = await store.get_session(hash_token(out.token))
        assert session is not None and session.mfa_verified_at is None
        challenge = await service.begin_webauthn_assertion(out.token, rp_id=rp)
        assert challenge is not None
        response = auth.get_response(base64url_to_bytes(json.loads(challenge)["challenge"]))

        now = [session.created_at + MFA_FLOOR - 0.001]
        _fake_service_wall_clock(monkeypatch, now)
        early = await service.finish_webauthn_assertion(
            out.token, response, rp_id=rp, origin=origin
        )
        assert early == Elevation()
        assert _reasons(await _audit_rows(store, "auth.webauthn_failed")) == [TOO_EARLY]

        # CONTROL: the refusal left the ceremony in flight, so the SAME response is served now.
        now[0] = session.created_at + MFA_FLOOR + 0.001
        served = await service.finish_webauthn_assertion(
            out.token, response, rp_id=rp, origin=origin
        )
        assert served.ok
    finally:
        await store.close()


# --- the federated sign-in: start then callback ---------------------------------------------------


def _answer(auth_time: float) -> Callable[..., oidc.FederatedPrincipal]:
    """Stand in for the token exchange and claims ladder, answering with this ``auth_time``."""

    def exchange(*_a: object, **_k: object) -> oidc.FederatedPrincipal:
        return oidc.FederatedPrincipal(
            username="jdoe",
            subject=DEFAULT_SUB,
            issuer="https://idp.example",
            amr=("pwd", "mfa"),
            acr=None,
            expires_at=time.time() + 600,
            auth_time=auth_time,
        )

    return exchange


async def _sign_in_callback_after(
    service: AuthService, clock: list[float], elapsed: float, *, auth_time_offset: float
) -> Any:
    """Stage a sign-in flow, let ``elapsed`` pass on the flow cache's clock, then redeem it."""
    flow_id, url = await service.begin_oidc_login(client="127.0.0.1", public_origin=ORIGIN)
    state = dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(url).query))["state"]
    assert service._oidc_flows is not None
    issued_at = service._oidc_flows.peek(flow_id).issued_at  # type: ignore[union-attr]
    service._exchange_and_validate = _answer(issued_at + auth_time_offset)  # type: ignore[method-assign]
    clock[0] += elapsed
    return await service.complete_oidc_login(
        flow_id=flow_id, state=state, code=AUTH_CODE, client="127.0.0.1", public_origin=ORIGIN
    )


async def _floored_federated_service(
    store: MessageStore, rsa_key: rsa.RSAPrivateKey, monkeypatch: pytest.MonkeyPatch
) -> tuple[AuthService, list[float]]:
    service = await _service(store, rsa_key, oidc_callback_min_elapsed_seconds=OIDC_FLOOR)
    clock = [5000.0]
    assert service._oidc_flows is not None
    monkeypatch.setattr(service._oidc_flows, "_clock", lambda: clock[0])
    return service, clock


async def test_a_sign_in_callback_just_inside_the_floor_is_refused(
    rsa_key: rsa.RSAPrivateKey, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The person signed in at the IdP during this flow (auth_time after its start), so a human step
    # sits inside the pair and the floor applies.
    store = await MessageStore.open(":memory:")
    try:
        service, clock = await _floored_federated_service(store, rsa_key, monkeypatch)
        early = await _sign_in_callback_after(
            service, clock, OIDC_FLOOR - 0.001, auth_time_offset=0.5
        )
        assert not early.ok and early.token is None
        assert early.error == "federated sign-in failed"
        assert early.reason == TOO_EARLY
        assert TOO_EARLY in _reasons(await _audit_rows(store, "auth.login_failed"))

        # CONTROL: just past the floor, the same answer signs the person in.
        served = await _sign_in_callback_after(
            service, clock, OIDC_FLOOR + 0.001, auth_time_offset=0.5
        )
        assert served.ok and served.token is not None, served
    finally:
        await store.close()


async def test_a_single_sign_on_answer_with_no_human_step_is_not_floored(
    rsa_key: rsa.RSAPrivateKey, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The IdP answered from a sign-on made before this flow started (auth_time before the start),
    # so no person acted inside the pair. Flooring it would refuse this sign-in on every retry.
    store = await MessageStore.open(":memory:")
    try:
        service, clock = await _floored_federated_service(store, rsa_key, monkeypatch)
        served = await _sign_in_callback_after(service, clock, 0.0, auth_time_offset=-120.0)
        assert served.ok and served.token is not None, served
    finally:
        await store.close()


# --- the federated step-up: start then callback ---------------------------------------------------


async def _step_up_callback_after(
    service: AuthService, token: str, clock: list[float], elapsed: float
) -> Any:
    flow_id, url = await service.begin_oidc_step_up(
        token, return_to="/ui", purpose=None, client="10.0.0.9", public_origin=ORIGIN
    )
    state = dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(url).query))["state"]
    # A fresh IdP sign-in, as max_age=0 and prompt=login demand.
    service._exchange_and_validate = _answer(time.time())  # type: ignore[method-assign]
    clock[0] += elapsed
    return await service.complete_oidc_step_up(
        flow_id=flow_id, state=state, code=AUTH_CODE, client="10.0.0.9", public_origin=ORIGIN
    )


async def test_a_step_up_callback_just_inside_the_floor_is_refused_and_just_past_it_served(
    rsa_key: rsa.RSAPrivateKey, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = await MessageStore.open(":memory:")
    try:
        service, clock = await _floored_federated_service(store, rsa_key, monkeypatch)
        # The session comes from a hand-built flow, which was never staged and so is never floored.
        signed_in = await _oidc_login(service, monkeypatch, rsa_key)
        assert signed_in.ok and signed_in.token is not None

        early = await _step_up_callback_after(service, signed_in.token, clock, OIDC_FLOOR - 0.001)
        assert not early.elevation.ok and early.reason == TOO_EARLY
        assert not early.elevation.session_lost, "a too-early step-up must not end the session"
        rows = [json.loads(str(r["detail"])) for r in await _audit_rows(store, "auth.reauth")]
        assert rows[-1]["reason"] == TOO_EARLY and rows[-1]["ok"] is False
        assert not await service.has_recent_step_up(signed_in.token)

        # CONTROL: a new step-up whose callback lands just past the floor elevates the session.
        served = await _step_up_callback_after(service, signed_in.token, clock, OIDC_FLOOR + 0.001)
        assert served.elevation.ok and served.elevation.token is not None, served
    finally:
        await store.close()
