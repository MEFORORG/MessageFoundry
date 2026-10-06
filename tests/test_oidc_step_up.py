# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The federated step-up leg and the session mechanism field (BACKLOG #296, #295).

ADR 0184 item (iv) adds ``sessions.auth_mechanism``: how a session was minted. ADR 0142 Amendment B
gives it its one consumer: a session the federated login minted steps up at the IdP, with
``max_age=0`` and ``prompt=login``, and never by a password.

Hermetic, on the ``test_auth_oidc_service`` scaffolding: the ``id_token`` is minted with the shipped
signer over a throwaway key and the token exchange is stubbed at the seam the service calls. The
cross-backend half of the field (persisted at mint, carried by rotation) is in
``tests/_session_rotation_contract.py``, which the Postgres and SQL Server suites also run.
"""

from __future__ import annotations

import asyncio
import json
import time
import urllib.parse
from collections.abc import Callable, Coroutine
from dataclasses import replace
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from messagefoundry.auth import oidc
from messagefoundry.auth.identity import SessionMechanism
from messagefoundry.auth.ldap import AdPrincipal
from messagefoundry.auth.service import (
    DIRECTORY_ROLES_DEMOTED,
    FLOW_PURPOSE_MISMATCH,
    IDP_STEP_UP_REQUIRED,
    STEP_UP_ACTION_SESSION_TERMINATE,
    STEP_UP_IDP_AUTH_TIME_MISSING,
    STEP_UP_IDP_AUTH_TIME_NOT_LATER,
    STEP_UP_NOT_FRESH,
    STEP_UP_SUBJECT_MISMATCH,
    AuthService,
)
from messagefoundry.auth.tokens import hash_token, mint_token
from messagefoundry.store.store import MessageStore
from tests.test_auth_oidc_service import (
    AUTH_CODE,
    DEFAULT_SUB,
    PRINCIPAL,
    _audit_rows,
    _claims,
    _FakeLdap,
    _flow,
    _mint,
    _oidc_login,
    _service,
    _stub_exchange,
)

ORIGIN = "https://ops.example"
#: A second directory account, with no federated binding, so Windows SSO still signs it in.
UNBOUND_PRINCIPAL = AdPrincipal(
    username="asmith",
    display_name="A Smith",
    email="a@corp.example",
    dn="CN=asmith,DC=corp,DC=example",
    groups=PRINCIPAL.groups,
    directory_object_id="guid-asmith",
)
NEXT = "/ui/config/reload"


@pytest.fixture(scope="module")
def rsa_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=3072)


@pytest.fixture(autouse=True)
def _no_failure_pad(monkeypatch: pytest.MonkeyPatch) -> None:
    async def _no_sleep(deadline: float) -> None:
        return None

    monkeypatch.setattr("messagefoundry.auth.service._sleep_until", _no_sleep)


class _CountingLdap(_FakeLdap):
    """Records every password bind, so a test can prove none was attempted."""

    def __init__(self, principal: AdPrincipal | None = PRINCIPAL) -> None:
        super().__init__(principal)
        self.binds: list[str] = []

    def authenticate(self, username: str, password: str, **_: object) -> AdPrincipal | None:
        self.binds.append(username)
        return super().authenticate(username, password)


async def _oidc_session(
    service: AuthService,
    monkeypatch: pytest.MonkeyPatch,
    rsa_key: rsa.RSAPrivateKey,
    **claim_over: Any,
) -> str:
    out = await _oidc_login(service, monkeypatch, rsa_key, **claim_over)
    assert out.ok and out.token is not None, out
    return out.token


async def _begin(
    service: AuthService, token: str, *, purpose: str | None = None, client: str = "10.0.0.9"
) -> tuple[str, str]:
    return await service.begin_oidc_step_up(
        token, return_to=NEXT, purpose=purpose, client=client, public_origin=ORIGIN
    )


def _staged(service: AuthService, flow_id: str) -> oidc.PendingFlow:
    assert service._oidc_flows is not None
    flow = service._oidc_flows.peek(flow_id)
    assert flow is not None
    return flow


async def _return_from_idp(
    service: AuthService,
    monkeypatch: pytest.MonkeyPatch,
    rsa_key: rsa.RSAPrivateKey,
    flow_id: str,
    *,
    client: str | None = "10.0.0.9",
    **claim_over: Any,
) -> Any:
    """Answer the staged flow the way the IdP would, with claims the test may vary."""
    flow = _staged(service, flow_id)
    claim_over.setdefault("nonce", flow.nonce)
    claim_over.setdefault("auth_time", time.time())
    _stub_exchange(monkeypatch, _mint(rsa_key, _claims(**claim_over)))
    return await service.complete_oidc_step_up(
        flow_id=flow_id, state=flow.state, code=AUTH_CODE, client=client, public_origin=ORIGIN
    )


async def _mechanism(store: MessageStore, token: str) -> str | None:
    session = await store.get_session(hash_token(token))
    assert session is not None
    return session.auth_mechanism


# --- the field: each mint path states its mechanism -------------------------------------------------


async def test_a_federated_session_is_minted_as_oidc_and_a_kerberos_one_as_kerberos(
    rsa_key: rsa.RSAPrivateKey, monkeypatch: pytest.MonkeyPatch
) -> None:
    """ADR 0184 item (iv): two mechanisms, and the SESSION says which ran.

    Two directory accounts, because one account no longer holds both: a bound account is refused
    Windows SSO, and the bind ends the sessions it held (vault BACKLOG #2609)."""
    store = await MessageStore.open(":memory:")
    try:
        service = await _service(store, rsa_key)
        federated = await _oidc_session(service, monkeypatch, rsa_key)
        kerberos = await service._complete_ad_login(UNBOUND_PRINCIPAL, None, mfa_verified=False)
        assert kerberos.ok and kerberos.token is not None
        assert await _mechanism(store, federated) == SessionMechanism.OIDC.value
        assert await _mechanism(store, kerberos.token) == SessionMechanism.KERBEROS.value
        assert await service.session_steps_up_at_idp(federated)
        assert not await service.session_steps_up_at_idp(kerberos.token)
    finally:
        await store.close()


# --- the regression: an OIDC session cannot step up with a password ---------------------------------


async def test_an_oidc_session_cannot_step_up_with_a_password(
    rsa_key: rsa.RSAPrivateKey, monkeypatch: pytest.MonkeyPatch
) -> None:
    """RED when: ``reauth`` re-binds a password for a session the federated login minted.

    The directory would ACCEPT this password (the fake answers every bind), so a pass here is the
    refusal itself and not a wrong password. Nothing is sent to the directory and nothing is charged:
    the caller asked the wrong leg, it did not guess wrong."""
    store = await MessageStore.open(":memory:")
    try:
        ldap = _CountingLdap()
        service = await _service(store, rsa_key, ldap=ldap)
        token = await _oidc_session(service, monkeypatch, rsa_key)
        identity = await service.identity_for_token(token)
        assert identity is not None

        elevation = await service.reauth(identity, "correct-horse", token=token)

        assert not elevation.ok and elevation.idp_step_up_required
        assert not elevation.session_lost
        assert ldap.binds == [], "a password was sent to the directory for an OIDC session"
        assert await service.identity_for_token(token) is not None, "the session must survive"
        assert not await service.has_recent_step_up(token)
        user = await store.get_user(identity.user_id)
        assert user is not None and user.failed_attempts == 0
        rows = [json.loads(str(r["detail"])) for r in await _audit_rows(store, "auth.reauth")]
        assert rows[-1]["reason"] == IDP_STEP_UP_REQUIRED and rows[-1]["ok"] is False
    finally:
        await store.close()


async def test_a_kerberos_session_of_the_same_account_keeps_the_password_leg(
    rsa_key: rsa.RSAPrivateKey,
) -> None:
    """The inverse: the refusal keys on the SESSION, so a Kerberos session still re-binds (ADR 0142
    Amendment B: "those sessions keep their existing step-up"). The account has no binding, because
    a bound account holds no Kerberos session (vault BACKLOG #2609)."""
    store = await MessageStore.open(":memory:")
    try:
        ldap = _CountingLdap()
        service = await _service(store, rsa_key, ldap=ldap, bind=None)
        login = await service._complete_ad_login(PRINCIPAL, None, mfa_verified=False)
        assert login.ok and login.token is not None and login.identity is not None

        elevation = await service.reauth(login.identity, "pw", token=login.token)

        assert elevation.ok and not elevation.idp_step_up_required
        assert ldap.binds == ["jdoe"]
    finally:
        await store.close()


# --- the start leg -----------------------------------------------------------------------------------


async def test_the_step_up_request_sends_max_age_zero_and_prompt_login(
    rsa_key: rsa.RSAPrivateKey, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = await MessageStore.open(":memory:")
    try:
        service = await _service(store, rsa_key, oidc_prompt="select_account")
        token = await _oidc_session(service, monkeypatch, rsa_key)
        flow_id, url = await _begin(service, token)
        query = dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(url).query))
        assert query["max_age"] == "0"
        # prompt=login REPLACES the operator's configured prompt: select_account could answer from
        # the IdP's existing session, which is the single sign-on a step-up must not reuse.
        assert query["prompt"] == "login"
        flow = _staged(service, flow_id)
        assert flow.step_up_session_hash == hash_token(token)
        assert flow.return_to == NEXT
        assert flow.issued_at > 0
        assert service.oidc_flow_is_step_up(flow_id)
    finally:
        await store.close()


async def test_a_non_oidc_session_cannot_start_the_idp_leg(rsa_key: rsa.RSAPrivateKey) -> None:
    store = await MessageStore.open(":memory:")
    try:
        # An account with no binding: a bound one holds no Kerberos session (vault BACKLOG #2609).
        service = await _service(store, rsa_key, bind=None)
        login = await service._complete_ad_login(PRINCIPAL, None, mfa_verified=False)
        assert login.token is not None
        with pytest.raises(oidc.FlowError):
            await _begin(service, login.token)
    finally:
        await store.close()


def test_a_step_up_url_refuses_a_second_prompt() -> None:
    with pytest.raises(ValueError, match="prompt=login"):
        oidc.build_authorization_url(
            authorization_endpoint="https://idp.example/authorize",
            client_id="c",
            redirect_uri="https://ops.example/ui/oidc/callback",
            state="s",
            nonce="n",
            code_challenge="x",
            scopes=["openid"],
            max_age=300,
            prompt="consent",
            step_up=True,
        )


# --- the callback: success -------------------------------------------------------------------------


async def test_a_fresh_idp_proof_elevates_rotates_and_grants(
    rsa_key: rsa.RSAPrivateKey, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The success path runs the password leg's order: stamp, rotate, then the action grant."""
    store = await MessageStore.open(":memory:")
    try:
        service = await _service(store, rsa_key)
        token = await _oidc_session(service, monkeypatch, rsa_key)
        flow_id, _url = await _begin(service, token, purpose=STEP_UP_ACTION_SESSION_TERMINATE)

        out = await _return_from_idp(service, monkeypatch, rsa_key, flow_id)

        assert out.ok and out.reason is None and out.return_to == NEXT
        new = out.elevation.token
        assert new is not None and new != token
        assert await service.identity_for_token(token) is None, "the old token still works"
        assert await service.identity_for_token(new) is not None
        assert await service.has_recent_step_up(new)
        assert await service.mfa_satisfied(new), "rotation dropped mfa_verified_at"
        assert await _mechanism(store, new) == SessionMechanism.OIDC.value
        assert await service.has_action_step_up(new, STEP_UP_ACTION_SESSION_TERMINATE)
        rows = [json.loads(str(r["detail"])) for r in await _audit_rows(store, "auth.reauth")]
        assert rows[-1]["ok"] is True and rows[-1]["mech"] == "oidc"
        # Single use: the flow is gone.
        assert not service.oidc_flow_is_step_up(flow_id)
    finally:
        await store.close()


async def test_the_idp_step_up_re_anchors_the_session_and_clears_the_new_address_signal(
    rsa_key: rsa.RSAPrivateKey, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``POST /me/reauth`` refuses an ``oidc`` session, so the IdP leg is how such a session clears
    the admin new-address signal. Without the re-anchor, every admin action from the new address
    would demand another step-up.

    The browser starts the step-up from one address and returns from another, on purpose. This pins
    today's behaviour: the session moves to the callback's address. The signal still fires for any
    other address."""
    store = await MessageStore.open(":memory:")
    try:
        service = await _service(store, rsa_key, admin_new_ip_step_up=True)
        _stub_exchange(monkeypatch, _mint(rsa_key, _claims()))
        login = await service.authenticate_oidc(
            AUTH_CODE,
            _flow(),
            redirect_uri="https://ops.example/ui/oidc/callback",
            client="10.0.0.1",
        )
        assert login.ok and login.token is not None, login
        token = login.token
        anchored = await store.get_session(hash_token(token))
        assert anchored is not None and anchored.client == "10.0.0.1"
        assert await service.flag_new_client_ip(token, "10.0.0.9", path=NEXT)

        flow_id, _url = await _begin(service, token, client="10.0.0.8")
        out = await _return_from_idp(service, monkeypatch, rsa_key, flow_id, client="10.0.0.9")

        assert out.ok, out
        new = out.elevation.token
        assert new is not None
        session = await store.get_session(hash_token(new))
        assert session is not None and session.client == "10.0.0.9"
        assert not await service.flag_new_client_ip(new, "10.0.0.9", path=NEXT)
        # Moved, not disarmed: the old anchor and the start leg's address both count as new now.
        assert await service.flag_new_client_ip(new, "10.0.0.1", path=NEXT)
        assert await service.flag_new_client_ip(new, "10.0.0.8", path=NEXT)
    finally:
        await store.close()


@pytest.mark.parametrize(
    ("start", "callback", "start_client", "moved"),
    [
        # The re-anchor test's own pair: started at one address, returned from another.
        ("10.0.0.8", "10.0.0.9", "10.0.0.8", True),
        ("10.0.0.9", "10.0.0.9", "10.0.0.9", False),
        # One host in two spellings: compared as the new-address signal compares (BACKLOG #2159).
        ("::ffff:10.0.0.9", "10.0.0.9", "::ffff:10.0.0.9", False),
        ("127.0.0.1", "::1", "127.0.0.1", False),
        # An address missing on either leg proves no move either way.
        ("", "10.0.0.9", None, None),
        ("10.0.0.8", None, "10.0.0.8", None),
    ],
    ids=["moved", "same", "mapped-same-host", "loopback", "start-unknown", "callback-unknown"],
)
async def test_the_step_up_row_records_whether_the_address_moved_mid_ceremony(
    rsa_key: rsa.RSAPrivateKey,
    monkeypatch: pytest.MonkeyPatch,
    start: str,
    callback: str | None,
    start_client: str | None,
    moved: bool | None,
) -> None:
    """BACKLOG #2160. The start leg stages its caller's address and the callback re-anchors to its
    own. The success row records both and whether they differ. A move is recorded, never refused,
    and the anchor stays on the callback's address: either change is an ADR 0142 Amendment B
    ruling."""
    store = await MessageStore.open(":memory:")
    try:
        service = await _service(store, rsa_key)
        token = await _oidc_session(service, monkeypatch, rsa_key)
        flow_id, _url = await _begin(service, token, client=start)
        out = await _return_from_idp(service, monkeypatch, rsa_key, flow_id, client=callback)

        assert out.ok, out
        assert out.elevation.token is not None
        session = await store.get_session(hash_token(out.elevation.token))
        assert session is not None
        if callback is not None:  # with none, the store keeps the earlier anchor
            assert session.client == callback
        rows = await _audit_rows(store, "auth.reauth")
        assert len(rows) == 1, rows
        row = rows[0]
        assert row["client"] == callback
        detail = json.loads(str(row["detail"]))
        assert detail["ok"] is True
        assert detail["start_client"] == start_client
        assert detail["client_moved"] is moved
    finally:
        await store.close()


# --- the callback: every refusal elevates nothing -----------------------------------------------------


async def _assert_untouched(service: AuthService, token: str) -> None:
    assert await service.identity_for_token(token) is not None, "a refusal ended the session"
    assert not await service.has_recent_step_up(token), "a refusal opened the step-up window"


async def test_an_idp_answer_from_before_the_request_is_refused(
    rsa_key: rsa.RSAPrivateKey, monkeypatch: pytest.MonkeyPatch
) -> None:
    """RED when: the engine trusts an IdP that ignored max_age=0 and answered from its own session.

    ``auth_time`` two skew-widths before the flow was staged is still inside
    ``oidc_max_age_seconds``, so the sign-in ladder accepts it. Only the step-up check refuses it.

    The sign-in is older still, so the stored IdP ``auth_time`` (BACKLOG #2143) does not refuse this
    answer. What refuses it is the engine-clock test, which that item kept."""
    store = await MessageStore.open(":memory:")
    try:
        service = await _service(store, rsa_key)
        skew = service._settings.oidc_clock_skew_seconds
        token = await _oidc_session(
            service, monkeypatch, rsa_key, auth_time=time.time() - 10 * skew
        )
        flow_id, _url = await _begin(service, token)
        stale = _staged(service, flow_id).issued_at - 2 * skew - 1
        held = await store.get_session(hash_token(token))
        assert held is not None and held.idp_auth_time is not None
        assert stale > held.idp_auth_time, "the stored auth_time would refuse this on its own"

        out = await _return_from_idp(service, monkeypatch, rsa_key, flow_id, auth_time=stale)

        assert not out.ok and out.reason == STEP_UP_NOT_FRESH
        assert out.error and "max_age=0" in out.error
        await _assert_untouched(service, token)
        # Filed under the staged session's account, not an anonymous actor.
        assert (await _audit_rows(store, "auth.reauth"))[-1]["actor"] == "jdoe"
    finally:
        await store.close()


# --- freshness against the IdP's own clock (BACKLOG #2143, ADR 0142 AC-15) --------------------------


async def _held_auth_time(store: MessageStore, token: str) -> float | None:
    session = await store.get_session(hash_token(token))
    assert session is not None
    return session.idp_auth_time


async def test_the_sign_in_stores_the_raw_idp_auth_time(
    rsa_key: rsa.RSAPrivateKey, monkeypatch: pytest.MonkeyPatch
) -> None:
    """RED when: the session stores the clamped ``min(auth_time, now)`` the lifetime cap uses, or
    nothing. An IdP clock ahead of ours, inside the skew, shows the difference."""
    store = await MessageStore.open(":memory:")
    try:
        service = await _service(store, rsa_key)
        ahead = time.time() + 30.5
        token = await _oidc_session(service, monkeypatch, rsa_key, auth_time=ahead)
        assert await _held_auth_time(store, token) == ahead
    finally:
        await store.close()


async def test_an_idp_answering_from_the_sign_in_within_the_skew_is_refused(
    rsa_key: rsa.RSAPrivateKey, monkeypatch: pytest.MonkeyPatch
) -> None:
    """RED when: the residual AC-15 named is open again. An IdP that ignores ``max_age=0`` answers
    with the sign-in's own ``auth_time``. That is inside the engine-clock skew, so only the stored
    IdP value can refuse it. A later ``auth_time`` from the same IdP still passes."""
    store = await MessageStore.open(":memory:")
    try:
        service = await _service(store, rsa_key)
        token = await _oidc_session(service, monkeypatch, rsa_key)
        signed_in_at = await _held_auth_time(store, token)
        assert signed_in_at is not None
        flow_id, _url = await _begin(service, token)
        skew = service._settings.oidc_clock_skew_seconds
        assert signed_in_at >= _staged(service, flow_id).issued_at - skew, "not inside the skew"

        out = await _return_from_idp(service, monkeypatch, rsa_key, flow_id, auth_time=signed_in_at)

        assert not out.ok and out.reason == STEP_UP_IDP_AUTH_TIME_NOT_LATER
        rows = [json.loads(str(r["detail"])) for r in await _audit_rows(store, "auth.reauth")]
        assert rows and rows[-1]["reason"] == STEP_UP_IDP_AUTH_TIME_NOT_LATER, rows
        await _assert_untouched(service, token)
        assert await _held_auth_time(store, token) == signed_in_at, "a refusal moved the value"

        flow_id, _url = await _begin(service, token)
        later = await _return_from_idp(
            service, monkeypatch, rsa_key, flow_id, auth_time=signed_in_at + 1
        )
        assert later.ok, later
    finally:
        await store.close()


async def test_a_replayed_step_up_answer_is_refused_the_second_time(
    rsa_key: rsa.RSAPrivateKey, monkeypatch: pytest.MonkeyPatch
) -> None:
    """RED when: a successful step-up does not write its ``auth_time`` back. The IdP answers a
    second step-up with the first one's ``auth_time``, which is still inside the engine-clock skew
    and later than the sign-in's, so only the write-back refuses it. Rotation carries the value."""
    store = await MessageStore.open(":memory:")
    try:
        service = await _service(store, rsa_key)
        token = await _oidc_session(service, monkeypatch, rsa_key)
        flow_id, _url = await _begin(service, token)
        first_at = time.time()
        first = await _return_from_idp(service, monkeypatch, rsa_key, flow_id, auth_time=first_at)
        assert first.ok, first
        rotated = first.elevation.token
        assert rotated is not None
        assert await _held_auth_time(store, rotated) == first_at, "not written back, or not carried"

        flow_id, _url = await _begin(service, rotated)
        replay = await _return_from_idp(service, monkeypatch, rsa_key, flow_id, auth_time=first_at)

        assert not replay.ok and replay.reason == STEP_UP_IDP_AUTH_TIME_NOT_LATER
        assert await service.identity_for_token(rotated) is not None
        assert await _held_auth_time(store, rotated) == first_at
    finally:
        await store.close()


@pytest.mark.parametrize(("held", "elevates"), [(None, False), (1.0, True)], ids=["null", "held"])
async def test_an_oidc_session_with_no_stored_auth_time_is_refused(
    rsa_key: rsa.RSAPrivateKey,
    monkeypatch: pytest.MonkeyPatch,
    held: float | None,
    elevates: bool,
) -> None:
    """RED when: an ``oidc`` session with no stored IdP ``auth_time`` (a row written before the
    column existed) steps up at all. Nothing can be compared, so it is refused with its own reason,
    not the engine-clock ``step_up_not_fresh``. The control arm is the same row holding a value,
    which elevates on the same answer."""
    store = await MessageStore.open(":memory:")
    try:
        service = await _service(store, rsa_key)
        user = await store.get_user_by_username("jdoe")
        assert user is not None
        token = mint_token()
        assert await store.create_session(
            token_hash=hash_token(token),
            user_id=user.id,
            expires_at=time.time() + 3600,
            seed_reauth=False,
            auth_mechanism=SessionMechanism.OIDC.value,
            idp_auth_time=held,
        )
        assert await _held_auth_time(store, token) == held
        flow_id, _url = await _begin(service, token)

        out = await _return_from_idp(service, monkeypatch, rsa_key, flow_id)

        if elevates:
            assert out.ok, out
        else:
            assert not out.ok and out.reason == STEP_UP_IDP_AUTH_TIME_MISSING
            rows = [json.loads(str(r["detail"])) for r in await _audit_rows(store, "auth.reauth")]
            assert rows and rows[-1]["reason"] == STEP_UP_IDP_AUTH_TIME_MISSING, rows
            await _assert_untouched(service, token)
    finally:
        await store.close()


def test_the_idp_clock_refusals_have_their_own_reasons_and_say_sign_in_again() -> None:
    """BACKLOG #2143. RED when: the IdP-clock refusals fold back into ``step_up_not_fresh``, or
    their text says to try again. A retry on the same session cannot pass either of them, so the
    text sends the operator to sign in again. The engine-clock refusal keeps its own text."""
    from messagefoundry.auth.service import _STEP_UP_ERRORS

    reasons = {STEP_UP_NOT_FRESH, STEP_UP_IDP_AUTH_TIME_MISSING, STEP_UP_IDP_AUTH_TIME_NOT_LATER}
    assert len(reasons) == 3, reasons
    assert STEP_UP_IDP_AUTH_TIME_MISSING == "step_up_idp_auth_time_missing"
    assert STEP_UP_IDP_AUTH_TIME_NOT_LATER == "step_up_idp_auth_time_not_later"
    for reason in (STEP_UP_IDP_AUTH_TIME_MISSING, STEP_UP_IDP_AUTH_TIME_NOT_LATER):
        text = _STEP_UP_ERRORS[reason]
        assert "sign in again" in text.lower(), text
        assert "try again" not in text.lower(), text
    assert "Try again" in _STEP_UP_ERRORS[STEP_UP_NOT_FRESH]


async def test_an_account_gone_from_the_directory_is_refused(
    rsa_key: rsa.RSAPrivateKey, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The password re-bind this leg replaces failed for a deleted or disabled AD object, so the IdP
    leg asks the directory too, even though the IdP signed the user in."""
    store = await MessageStore.open(":memory:")
    try:
        ldap = _CountingLdap()
        service = await _service(store, rsa_key, ldap=ldap)
        token = await _oidc_session(service, monkeypatch, rsa_key)
        flow_id, _url = await _begin(service, token)
        ldap._principal = None  # the directory no longer returns the account

        out = await _return_from_idp(service, monkeypatch, rsa_key, flow_id)

        assert not out.ok and out.reason == "not_in_directory"
        await _assert_untouched(service, token)
    finally:
        await store.close()


#: A second mapped group, for the demotion arms below (BACKLOG #2154). Synthetic.
_VIEWERS = "cn=mf-viewers,dc=corp,dc=example"


@pytest.mark.parametrize(
    ("now_in", "elevates"),
    [
        (frozenset(), False),
        (frozenset({_VIEWERS}), False),
        (PRINCIPAL.groups, True),
        (PRINCIPAL.groups | {_VIEWERS}, True),
    ],
    ids=["every-role-lost", "moved-to-another-role", "unchanged", "promoted"],
)
async def test_an_account_demoted_in_the_directory_since_sign_in_is_refused(
    rsa_key: rsa.RSAPrivateKey,
    monkeypatch: pytest.MonkeyPatch,
    now_in: frozenset[str],
    elevates: bool,
) -> None:
    """BACKLOG #2154. RED when: the IdP leg elevates a session whose account lost a role in the
    directory after it signed in, or refuses one whose groups are unchanged or only grew.

    The roles are compared by id, as the TOTP and passkey legs compare them (#2240), so a move to
    another role refuses even though it is not a strict subset. A refusal writes no roles."""
    store = await MessageStore.open(":memory:")
    try:
        ldap = _CountingLdap()
        service = await _service(store, rsa_key, ldap=ldap)
        await service.set_ad_group_map(
            [("cn=mf-ops,dc=corp,dc=example", "operator"), (_VIEWERS, "viewer")], actor="admin"
        )
        token = await _oidc_session(service, monkeypatch, rsa_key)
        user_id = await _user_id(service, token)
        assert set(await store.get_user_role_ids(user_id)) == {"operator"}
        flow_id, _url = await _begin(service, token)
        ldap._principal = replace(PRINCIPAL, groups=now_in)

        out = await _return_from_idp(service, monkeypatch, rsa_key, flow_id)

        rows = [json.loads(str(r["detail"])) for r in await _audit_rows(store, "auth.reauth")]
        assert len(rows) == 1, rows
        if elevates:
            assert out.ok, out
            assert rows[0]["ok"] is True
        else:
            assert not out.ok and out.reason == DIRECTORY_ROLES_DEMOTED
            assert out.error and "sign in again" in out.error, out.error
            assert "administrator" not in out.error, out.error
            assert rows[0] == {
                "ok": False,
                "provider": "ad",
                "mech": "oidc",
                "reason": DIRECTORY_ROLES_DEMOTED,
            }
            await _assert_untouched(service, token)
        assert set(await store.get_user_role_ids(user_id)) == {"operator"}, "roles were written"
    finally:
        await store.close()


async def test_a_different_idp_subject_is_refused(
    rsa_key: rsa.RSAPrivateKey, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The IdP signed in someone, but not the identity bound to this session's account."""
    store = await MessageStore.open(":memory:")
    try:
        service = await _service(store, rsa_key)
        token = await _oidc_session(service, monkeypatch, rsa_key)
        flow_id, _url = await _begin(service, token)

        out = await _return_from_idp(
            service, monkeypatch, rsa_key, flow_id, sub=DEFAULT_SUB + "-someone-else"
        )

        assert not out.ok and out.reason == STEP_UP_SUBJECT_MISMATCH
        assert not out.elevation.session_lost
        await _assert_untouched(service, token)
    finally:
        await store.close()


async def test_another_persons_older_idp_answer_is_a_subject_mismatch_not_stale(
    rsa_key: rsa.RSAPrivateKey, monkeypatch: pytest.MonkeyPatch
) -> None:
    """BACKLOG #2143. RED when: the IdP-clock freshness test runs before the subject check again.

    Another person's IdP session answers, with an ``auth_time`` inside the engine-clock skew but
    not later than the one this session holds. Both the subject test and the IdP-clock test would
    refuse it. The audit row must say subject mismatch, which is the signal that another person's
    IdP session answered; "not fresh" would hide it."""
    store = await MessageStore.open(":memory:")
    try:
        service = await _service(store, rsa_key)
        token = await _oidc_session(service, monkeypatch, rsa_key)
        held = await _held_auth_time(store, token)
        assert held is not None
        flow_id, _url = await _begin(service, token)
        skew = service._settings.oidc_clock_skew_seconds
        assert held >= _staged(service, flow_id).issued_at - skew, "the engine-clock test refuses"

        out = await _return_from_idp(
            service,
            monkeypatch,
            rsa_key,
            flow_id,
            sub=DEFAULT_SUB + "-someone-else",
            auth_time=held,
        )

        assert not out.ok and out.reason == STEP_UP_SUBJECT_MISMATCH
        rows = [json.loads(str(r["detail"])) for r in await _audit_rows(store, "auth.reauth")]
        assert len(rows) == 1, rows
        assert rows[0]["reason"] == STEP_UP_SUBJECT_MISMATCH
        await _assert_untouched(service, token)
    finally:
        await store.close()


async def test_a_session_revoked_mid_flight_is_not_elevated(
    rsa_key: rsa.RSAPrivateKey, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = await MessageStore.open(":memory:")
    try:
        service = await _service(store, rsa_key)
        token = await _oidc_session(service, monkeypatch, rsa_key)
        flow_id, _url = await _begin(service, token)
        await service.logout(token)

        out = await _return_from_idp(service, monkeypatch, rsa_key, flow_id)

        assert not out.ok and out.elevation.session_lost
    finally:
        await store.close()


async def test_a_wrong_state_is_refused(
    rsa_key: rsa.RSAPrivateKey, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = await MessageStore.open(":memory:")
    try:
        service = await _service(store, rsa_key)
        token = await _oidc_session(service, monkeypatch, rsa_key)
        flow_id, _url = await _begin(service, token)
        out = await service.complete_oidc_step_up(
            flow_id=flow_id, state="forged", code=AUTH_CODE, client=None, public_origin=ORIGIN
        )
        assert not out.ok and out.reason == "state_mismatch"
        await _assert_untouched(service, token)
        # PEEKED, not popped: a forged callback must not cancel the step-up in flight.
        assert service.oidc_flow_is_step_up(flow_id)
        rows = await _audit_rows(store, "auth.reauth")
        assert rows[-1]["actor"] == "<oidc>", "an unverified refusal was filed under the account"
    finally:
        await store.close()


async def test_a_step_up_flow_never_mints_and_a_sign_in_flow_never_elevates(
    rsa_key: rsa.RSAPrivateKey, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Each completion refuses the other kind of flow, so a cookie swap cannot cross the legs."""
    store = await MessageStore.open(":memory:")
    try:
        service = await _service(store, rsa_key)
        token = await _oidc_session(service, monkeypatch, rsa_key)
        step_up_id, _url = await _begin(service, token)
        flow = _staged(service, step_up_id)
        _stub_exchange(monkeypatch, _mint(rsa_key, _claims(nonce=flow.nonce)))
        sessions_before = len(await store.list_sessions(await _user_id(service, token)))

        login = await service.complete_oidc_login(
            flow_id=step_up_id, state=flow.state, code=AUTH_CODE, client=None, public_origin=ORIGIN
        )

        assert not login.ok and login.reason == FLOW_PURPOSE_MISMATCH and login.token is None
        assert len(await store.list_sessions(await _user_id(service, token))) == sessions_before

        sign_in_id, _url = await service.begin_oidc_login(client=None, public_origin=ORIGIN)
        sign_in = _staged(service, sign_in_id)
        out = await service.complete_oidc_step_up(
            flow_id=sign_in_id,
            state=sign_in.state,
            code=AUTH_CODE,
            client=None,
            public_origin=ORIGIN,
        )
        assert not out.ok and out.reason == FLOW_PURPOSE_MISMATCH
        await _assert_untouched(service, token)
    finally:
        await store.close()


async def test_an_abandoned_step_up_consumes_the_flow_and_keeps_the_continuation(
    rsa_key: rsa.RSAPrivateKey, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The user cancelled at the IdP: the operator lands back on the page they started from."""
    store = await MessageStore.open(":memory:")
    try:
        service = await _service(store, rsa_key)
        token = await _oidc_session(service, monkeypatch, rsa_key)
        flow_id, _url = await _begin(service, token)

        forged = await service.abandon_oidc_step_up(
            flow_id, state="forged", reason="idp_error", client=None
        )
        # A cancel without the flow's own state (any page can send error=) consumes nothing.
        assert not forged.ok and forged.reason == "state_mismatch"
        assert service.oidc_flow_is_step_up(flow_id)

        out = await service.abandon_oidc_step_up(
            flow_id, state=_staged(service, flow_id).state, reason="idp_error", client=None
        )

        assert not out.ok and out.reason == "idp_error" and out.return_to == NEXT
        assert not service.oidc_flow_is_step_up(flow_id)
        await _assert_untouched(service, token)
    finally:
        await store.close()


async def _user_id(service: AuthService, token: str) -> str:
    identity = await service.identity_for_token(token, activity=False)
    assert identity is not None
    return identity.user_id


# --- the known-address record (vault BACKLOG #2145) --------------------------------------------------


@pytest.mark.parametrize(("require_mfa", "recorded"), [(False, ["10.0.0.9"]), (True, [])])
async def test_the_idp_step_up_records_its_address_only_for_an_account_that_owes_no_factor(
    rsa_key: rsa.RSAPrivateKey,
    monkeypatch: pytest.MonkeyPatch,
    require_mfa: bool,
    recorded: list[str],
) -> None:
    """A step-up is how a first-seen address passes its challenge, so the IdP leg writes the
    callback's address to the account's known-address record. It writes only for an account that
    owes no second factor, asked of the account and not of this session's own MFA stamp. Under the
    shipped ``require_mfa`` every directory account owes one (the directory floor), so there the
    step-up writes nothing, even though the IdP re-proved the MFA claim. A later sign-in from the
    host records it once that sign-in finishes.

    The sign-in passes no client address, so it writes nothing itself; the row the first case finds
    can only have come from the step-up."""
    store = await MessageStore.open(":memory:")
    try:
        service = await _service(store, rsa_key, require_mfa=require_mfa)
        token = await _oidc_session(service, monkeypatch, rsa_key)
        uid = await _user_id(service, token)
        assert await store.list_known_login_addresses(uid, since=0.0) == []
        flow_id, _url = await _begin(service, token, client="10.0.0.8")

        out = await _return_from_idp(service, monkeypatch, rsa_key, flow_id, client="10.0.0.9")

        assert out.ok, out
        assert await store.list_known_login_addresses(uid, since=0.0) == recorded
    finally:
        await store.close()


# --- BACKLOG #2153: the reads after the token exchange are freshness checks -------------------------


async def _revoke(store: MessageStore, token: str, user_id: str) -> None:
    await store.revoke_session(hash_token(token))


async def _disable(store: MessageStore, token: str, user_id: str) -> None:
    await store.set_user_disabled(user_id, disabled=True)


async def _rebind(store: MessageStore, token: str, user_id: str) -> None:
    await store.set_user_federated_subject(user_id, "https://idp.example", "someone-else")
    user = await store.get_user(user_id)
    # Without this the arm could pass on a write that never happened.
    assert user is not None and user.oidc_subject == "someone-else"


async def _nothing(store: MessageStore, token: str, user_id: str) -> None:
    return None


@pytest.mark.parametrize(
    ("change", "elevated"),
    [(_revoke, False), (_disable, False), (_rebind, False), (_nothing, True)],
    ids=["revoked", "disabled", "rebound", "control"],
)
async def test_an_account_change_during_the_token_exchange_is_not_elevated(
    rsa_key: rsa.RSAPrivateKey,
    monkeypatch: pytest.MonkeyPatch,
    change: Callable[[MessageStore, str, str], Coroutine[Any, Any, None]],
    elevated: bool,
) -> None:
    """BACKLOG #2153 step 2 asked to reuse the reads taken before the exchange. It is declined, and
    this pins why. The exchange is a network round trip, and the session or the account can change
    while it runs. The session and user reads after it are what see that change, so reusing the
    earlier reads would elevate a session revoked, disabled or re-bound in the meantime. The control
    arm changes nothing and must elevate, or the refusals prove nothing about the race."""
    store = await MessageStore.open(":memory:")
    try:
        service = await _service(store, rsa_key)
        token = await _oidc_session(service, monkeypatch, rsa_key)
        uid = await _user_id(service, token)
        flow_id, _url = await _begin(service, token)
        loop = asyncio.get_running_loop()
        real = service._exchange_and_validate

        def _racing(code: str, flow: oidc.PendingFlow, redirect_uri: str) -> Any:
            principal = real(code, flow, redirect_uri)
            # This runs in the worker thread while the loop waits on it, so the loop is free to
            # run the change. It lands after the IdP answered and before the service reads again.
            asyncio.run_coroutine_threadsafe(change(store, token, uid), loop).result(timeout=10)
            return principal

        monkeypatch.setattr(service, "_exchange_and_validate", _racing)
        out = await _return_from_idp(service, monkeypatch, rsa_key, flow_id)

        assert out.ok is elevated, out
        if elevated:
            assert out.elevation.token is not None
            session = await store.get_session(hash_token(out.elevation.token))
            assert session is not None and session.reauth_at is not None
        else:
            # The staged session was neither rotated nor stamped.
            session = await store.get_session(hash_token(token))
            assert session is not None and session.reauth_at is None
    finally:
        await store.close()
