# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The JSON step-up refusal names the IdP leg for an ``oidc`` session (BACKLOG #2158).

``POST /me/reauth`` refuses a session the federated sign-in minted (BACKLOG #296), so a step-up
gate that told such a session to "POST /me/reauth then retry" sent it to a second 403. Every JSON
step-up gate now answers an ``oidc`` session with a detail naming ``/ui/reauth`` and the header
``X-Step-Up-Via: idp``. Every other session's refusal stays byte-for-byte what it was.

The five raise sites are the dependencies built by ``require_step_up``, ``require_step_up_action``,
``require_reauth_only``, ``require_reauth_only_action`` and ``refuse_from_new_address``. No live
route uses ``require_reauth_only`` today, so this file mounts one probe route on it.

The ``oidc`` session here is minted straight into the store with ``auth_mechanism="oidc"``. The
gates read only that column (``AuthService.session_steps_up_at_idp``), so the full federated
sign-in, which ``tests/test_oidc_step_up.py`` drives, adds nothing to what this file pins.
"""

from __future__ import annotations

import time
from collections.abc import AsyncIterator, Callable
from pathlib import Path

import httpx
import pytest
from fastapi import Depends, FastAPI

from messagefoundry.api import create_app
from messagefoundry.api.security import require_reauth_only
from messagefoundry.apiclient import ApiError, EngineClient, IdpStepUpRequired
from messagefoundry.auth import Role
from messagefoundry.auth.identity import ALL_CHANNELS, Identity
from messagefoundry.auth.service import (
    STEP_UP_ACTION_MFA_DISABLE,
    STEP_UP_ACTION_MFA_ENROLL,
    AuthService,
)
from messagefoundry.auth.tokens import hash_token
from messagefoundry.config.settings import AuthSettings, EgressSettings
from messagefoundry.pipeline import Engine
from tests._admin_account import create_local_user_chosen

PW = "a-strong-test-passphrase"
HOME = "10.0.0.1"
ROAMED = "10.9.9.9"
PROBE = "/probe/reauth-only"

#: Written out, not imported: the point is that the non-oidc refusal did not move.
PASSWORD_DETAIL = "step-up re-verification required; POST /me/reauth then retry"

#: (method, path, json body, the X-Step-Up-Action the gate names or None, which raise site).
_GATES: tuple[tuple[str, str, dict[str, object] | None, str | None, str], ...] = (
    (
        "POST",
        "/users",
        {"username": "n1", "roles": ["viewer"], "email": "n1@example.org"},
        None,
        "require_step_up",
    ),
    ("DELETE", "/me/mfa", None, STEP_UP_ACTION_MFA_DISABLE, "require_step_up_action"),
    ("POST", PROBE, None, None, "require_reauth_only"),
    ("POST", "/me/mfa/enroll", None, STEP_UP_ACTION_MFA_ENROLL, "require_reauth_only_action"),
    ("GET", "/messages", None, None, "refuse_from_new_address"),
    ("POST", "/statistics/reset", {"all": True}, None, "refuse_from_new_address via require_paced"),
    ("GET", "/events?reveal=1", None, None, "refuse_from_new_address via _admit_reveal"),
)


@pytest.fixture
async def engine(tmp_path: Path) -> AsyncIterator[Engine]:
    eng = await Engine.create(
        tmp_path / "oidc-hint.db",
        poll_interval=0.02,
        egress_settings=EgressSettings(deny_by_default=False),
    )
    yield eng
    await eng.stop()


@pytest.fixture
async def service(engine: Engine) -> AuthService:
    svc = AuthService(
        engine.store,
        AuthSettings(
            admin_write_min_interval_seconds=0, admin_new_ip_step_up=True, require_mfa=False
        ),
    )
    await svc.initialize()
    return svc


_REAUTH_ONLY = require_reauth_only()


def _app(engine: Engine, service: AuthService) -> FastAPI:
    app = create_app(engine, auth=service)

    async def _probe(identity: Identity = Depends(_REAUTH_ONLY)) -> dict[str, str]:
        return {"user": identity.username}

    app.add_api_route(PROBE, _probe, methods=["POST"])
    return app


def _client_at(engine: Engine, service: AuthService, ip: str) -> httpx.AsyncClient:
    transport = httpx.ASGITransport(app=_app(engine, service), client=(ip, 12345))
    return httpx.AsyncClient(transport=transport, base_url="http://t")


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


async def _add_admin(service: AuthService, username: str = "boss") -> str:
    user_id = await create_local_user_chosen(
        service,
        username=username,
        password=PW,
        display_name=None,
        email=None,
        roles=[Role.ADMINISTRATOR.value],
        actor="test",
    )
    await service.set_channel_scope(user_id, [ALL_CHANNELS], actor="test")
    user = await service.store.get_user(user_id)
    assert user is not None and user.password_hash is not None
    await service.store.set_password(
        user_id,
        password_hash=user.password_hash,
        must_change_password=False,
        password_generated=False,
    )
    return user_id


async def _session(
    service: AuthService, user_id: str, token: str, *, mechanism: str | None, fresh: bool = True
) -> str:
    """A live session anchored at ``HOME``, minted the way ``mechanism`` names."""
    created = await service.store.create_session(
        token_hash=hash_token(token),
        user_id=user_id,
        expires_at=time.time() + 3600,
        client=HOME,
        seed_reauth=fresh,
        auth_mechanism=mechanism,
    )
    assert created
    return token


async def _refusals(
    engine: Engine, service: AuthService, token: str, ip: str
) -> list[tuple[str, httpx.Response]]:
    out = []
    async with _client_at(engine, service, ip) as c:
        for method, path, body, _action, site in _GATES:
            r = await c.request(method, path, headers=_auth(token), json=body)
            out.append((site, r))
    return out


def _assert_idp_hint(site: str, r: httpx.Response, action: str | None) -> None:
    assert r.status_code == 403, (site, r.status_code, r.text)
    assert r.headers.get("X-Step-Up-Required") == "1", site
    assert r.headers.get("X-Step-Up-Via") == "idp", site
    assert r.headers.get("X-Step-Up-Action") == action, site
    detail = r.json()["detail"]
    assert "/ui/reauth" in detail, (site, detail)
    assert "/me/reauth" not in detail, (site, detail)
    # BACKLOG #2142 owns whether a code may clear this step-up; the hint must not answer it.
    assert "mfa-verify" not in detail, (site, detail)
    assert "X-MFA-Required" not in r.headers, site


def _assert_password_refusal(site: str, r: httpx.Response, action: str | None) -> None:
    assert r.status_code == 403, (site, r.status_code, r.text)
    assert r.json()["detail"] == PASSWORD_DETAIL, site
    assert r.headers.get("X-Step-Up-Required") == "1", site
    assert r.headers.get("X-Step-Up-Action") == action, site
    assert "X-Step-Up-Via" not in r.headers, site


def _actions() -> dict[str, str | None]:
    return {site: action for _m, _p, _b, action, site in _GATES}


async def test_an_oidc_session_from_a_new_address_is_told_the_idp_leg_at_every_gate(
    engine: Engine, service: AuthService
) -> None:
    """RED when: any of the five raise sites still sends an ``oidc`` session to POST /me/reauth."""
    uid = await _add_admin(service)
    token = await _session(service, uid, "tok-oidc", mechanism="oidc")
    actions = _actions()
    refused = await _refusals(engine, service, token, ROAMED)
    assert [site for site, _ in refused] == list(actions), "a gate was skipped"
    # Every site that missed, named at once, rather than only the first one the loop meets.
    missed = [site for site, r in refused if r.headers.get("X-Step-Up-Via") != "idp"]
    assert missed == [], missed
    for site, r in refused:
        _assert_idp_hint(site, r, actions[site])


async def test_an_oidc_session_with_a_lapsed_window_is_told_the_idp_leg(
    engine: Engine, service: AuthService
) -> None:
    """The window half, from the anchor address: no new-address signal, only a stale window or no
    grant. ``refuse_from_new_address`` asks nothing here, so its callers answer."""
    uid = await _add_admin(service)
    token = await _session(service, uid, "tok-oidc-stale", mechanism="oidc", fresh=False)
    actions = _actions()
    for site, r in await _refusals(engine, service, token, HOME):
        if site.startswith("refuse_from_new_address"):
            assert r.status_code == 200, (site, r.status_code, r.text)
            continue
        _assert_idp_hint(site, r, actions[site])


@pytest.mark.parametrize("mechanism", ["password", "kerberos", None])
@pytest.mark.parametrize(("ip", "fresh"), [(ROAMED, True), (HOME, False)], ids=["roamed", "lapsed"])
async def test_every_other_session_keeps_the_password_refusal_byte_for_byte(
    engine: Engine, service: AuthService, mechanism: str | None, ip: str, fresh: bool
) -> None:
    """RED when: the non-oidc detail or headers move, on either the new-address branch or the
    window branch. ``None`` is a row written before the mechanism column existed; it takes the
    password leg."""
    uid = await _add_admin(service)
    token = await _session(service, uid, f"tok-{mechanism}", mechanism=mechanism, fresh=fresh)
    actions = _actions()
    for site, r in await _refusals(engine, service, token, ip):
        if site.startswith("refuse_from_new_address") and ip == HOME:
            assert r.status_code == 200, (site, r.status_code, r.text)
            continue
        _assert_password_refusal(site, r, actions[site])


async def test_the_hint_is_true_because_post_me_reauth_refuses_the_oidc_session(
    engine: Engine, service: AuthService
) -> None:
    """The premise, measured: following the old hint gets an ``oidc`` session a second 403, and
    that 403 names the same leg the gate now names. The password session is the control."""
    uid = await _add_admin(service)
    oidc_token = await _session(service, uid, "tok-premise-oidc", mechanism="oidc")
    password_token = await _session(service, uid, "tok-premise-pw", mechanism="password")
    async with _client_at(engine, service, ROAMED) as c:
        refused = await c.post("/me/reauth", headers=_auth(oidc_token), json={"password": PW})
        assert refused.status_code == 403
        assert "/ui/reauth" in refused.json()["detail"]
        # docs/SECURITY.md says this refusal carries no X-Step-Up-Via; only the gates send it.
        assert "X-Step-Up-Via" not in refused.headers
        control = await c.post("/me/reauth", headers=_auth(password_token), json={"password": PW})
        assert control.status_code == 200, control.text


# --- the client half --------------------------------------------------------------------------


def _client_answering(answer: Callable[[httpx.Request], httpx.Response]) -> EngineClient:
    client = EngineClient("http://127.0.0.1:8765")

    def _send(request: httpx.Request, *args: object, **kwargs: object) -> httpx.Response:
        return answer(request)

    client._http.send = _send  # type: ignore[method-assign]
    return client


def test_the_client_raises_instead_of_prompting_for_a_password() -> None:
    """RED when: ``EngineClient`` meets ``X-Step-Up-Via: idp`` and runs the password prompt, or
    raises a plain ``ApiError`` a caller cannot tell apart."""
    prompted: list[str] = []
    seen: list[str] = []

    def _answer(request: httpx.Request) -> httpx.Response:
        seen.append(f"{request.method} {request.url.path}")
        headers = {"X-Step-Up-Required": "1", "X-Step-Up-Via": "idp"}
        return httpx.Response(403, json={"detail": "idp"}, headers=headers, request=request)

    def _prompt() -> bool:
        prompted.append("step-up")
        return True

    client = _client_answering(_answer)
    client.set_step_up_handler(_prompt)
    try:
        with pytest.raises(IdpStepUpRequired) as raised:
            client.health()
    finally:
        client.close()
    assert isinstance(raised.value, ApiError) and raised.value.status == 403
    assert prompted == []
    assert seen == ["GET /health"], "the client retried or posted /me/reauth"


def test_the_client_still_prompts_for_a_password_without_the_header() -> None:
    """Control: the same 403 without ``X-Step-Up-Via`` still runs the step-up handler."""
    prompted: list[str] = []

    def _answer(request: httpx.Request) -> httpx.Response:
        headers = {"X-Step-Up-Required": "1"}
        return httpx.Response(403, json={"detail": "x"}, headers=headers, request=request)

    def _prompt() -> bool:
        prompted.append("step-up")
        return False

    client = _client_answering(_answer)
    client.set_step_up_handler(_prompt)
    try:
        with pytest.raises(ApiError) as raised:
            client.health()
    finally:
        client.close()
    assert not isinstance(raised.value, IdpStepUpRequired)
    assert prompted == ["step-up"]
