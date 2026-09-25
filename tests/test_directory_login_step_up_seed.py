# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #1144 step 5 (ASVS 6.8.4): no directory sign-in seeds the step-up window.

``_complete_ad_login`` used to take ``seed_reauth: bool = True``. The console's ``GET /ui/sso``
passed False, while the JSON ``POST /auth/negotiate`` took the default. So a bearer session was born
with ``reauth_at = now``, and the engine's own login stamp passed ``has_recent_step_up`` for the
whole ``step_up_max_age_seconds`` window with no directory interaction. One pathway, two postures.

Now ``_complete_ad_login`` passes ``seed_reauth=False`` itself, and no directory entry point takes
the argument. Each test names the change that turns it RED. The console half of the pair lives in
``packaging/messagefoundry-webconsole/tests/test_webui.py``, ``test_sso_session_not_reauth_seeded``.
"""

from __future__ import annotations

import ast
import base64
import inspect
import textwrap
from collections.abc import AsyncIterator
from pathlib import Path

import httpx
import pytest
from _ast_sites import call_sites

from messagefoundry.api import create_app
from messagefoundry.auth import Role
from messagefoundry.auth.identity import ALL_CHANNELS
from messagefoundry.auth.ldap import AdPrincipal
from messagefoundry.auth.service import AuthService
from messagefoundry.auth.tokens import hash_token
from messagefoundry.config.settings import AuthSettings
from messagefoundry.pipeline import Engine

PW = "a-strong-test-passphrase"
AD_PW = "directory-pw"
ADMINS = "cn=mf-admins,dc=x"
#: A route behind ``require_step_up`` and nothing stranger: a GET, so the admin write pacing does not
#: apply, and an empty store answers it without fixtures. The route wants exactly one criterion, and
#: a field path is the one a query string may carry.
GATED = "/messages/search?field_path=PID-5"


@pytest.fixture
async def engine(tmp_path: Path) -> AsyncIterator[Engine]:
    eng = await Engine.create(tmp_path / "no_login_seed.db", poll_interval=0.02)
    yield eng
    await eng.stop()


def _principal(username: str = "jdoe") -> AdPrincipal:
    return AdPrincipal(
        username=username,
        display_name="J Doe",
        email=None,
        dn=f"CN={username},DC=x",
        groups=frozenset({ADMINS}),
    )


class _FakeLdap:
    """``authenticate`` is the live re-bind ``POST /me/reauth`` makes for a directory account."""

    def authenticate(self, username: str, password: str) -> AdPrincipal | None:
        return _principal(username) if password == AD_PW else None

    def resolve_principal(self, username: str) -> AdPrincipal | None:
        return _principal(username)


async def _service(
    engine: Engine, *, require_mfa: bool = False, require_action_step_up: bool = True
) -> AuthService:
    """``require_mfa`` OFF by default, so the step-up gate is the ONLY thing between a session and
    ``GATED``.

    With it on, an un-enrolled directory session is refused at the MFA gate first, and a test of the
    window would pass whatever the seeding did. Off, a directory account with no factor owes none,
    so the login stamp is exactly what decides the gated call. The enrollment test turns it on,
    because that route skips the MFA gate."""
    settings = AuthSettings(
        ad_enabled=True,
        kerberos_enabled=True,
        ad_server="ldaps://x",
        ad_user_search_base="DC=x",
        ad_bind_dn="CN=svc,DC=x",
        ad_bind_password="x",
        login_rate_limit_enabled=False,
        require_mfa=require_mfa,
        require_action_step_up=require_action_step_up,
    )
    service = AuthService(engine.store, settings, ldap=_FakeLdap())  # type: ignore[arg-type]
    await service.initialize()
    await engine.store.set_ad_group_role_map([(ADMINS, Role.ADMINISTRATOR.value)])
    return service


def _client(engine: Engine, service: AuthService) -> httpx.AsyncClient:
    transport = httpx.ASGITransport(app=create_app(engine, auth=service), client=("127.0.0.1", 123))
    return httpx.AsyncClient(transport=transport, base_url="http://t")


def _bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


async def test_a_json_negotiate_session_is_refused_a_gated_action_until_it_steps_up(
    engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    """RED when: a directory login seeds ``reauth_at`` again, by any route.

    The whole defect in one walk: sign in through the JSON route, find no window, be refused the
    gated call with the step-up header, step up by a live directory re-bind, and be admitted. The
    last two steps are the lockout check: a directory account with no engine factor must still be
    able to reach the action, or the change is a lockout rather than a control."""
    monkeypatch.setattr("messagefoundry.auth.service.kerberos_principal", lambda t, s: "jdoe")
    service = await _service(engine)
    async with _client(engine, service) as c:
        r = await c.post(
            "/auth/negotiate",
            headers={"Authorization": "Negotiate " + base64.b64encode(b"tok").decode()},
        )
        assert r.status_code == 200, r.text
        body = r.json()
        token = body["token"]
        # Owes no factor (require_mfa off, none enrolled), so the refusal below is the step-up gate's
        # and not the MFA gate's.
        assert body["mfa_required"] is False

        session = await engine.store.get_session(hash_token(token))
        assert session is not None and session.reauth_at is None
        assert await service.has_recent_step_up(token) is False

        refused = await c.get(GATED, headers=_bearer(token))
        assert refused.status_code == 403
        assert refused.headers.get("X-Step-Up-Required") == "1"
        assert refused.headers.get("X-MFA-Required") is None

        wrong = await c.post("/me/reauth", json={"password": "not-it"}, headers=_bearer(token))
        assert wrong.status_code == 403

        stepped = await c.post("/me/reauth", json={"password": AD_PW}, headers=_bearer(token))
        assert stepped.status_code == 200, stepped.text
        fresh = stepped.json()["token"]  # re-keyed on success (ASVS 7.2.4)
        assert await service.has_recent_step_up(fresh) is True
        admitted = await c.get(GATED, headers=_bearer(fresh))
        assert admitted.status_code == 200, admitted.text


async def test_a_federated_shaped_login_is_born_without_a_window_even_when_mfa_verified(
    engine: Engine,
) -> None:
    """RED when: ``_complete_ad_login`` lets ``mfa_verified`` decide the seeding again.

    The federated leg passes ``mfa_verified=True`` when the IdP asserted a factor, and
    ``_issue_session`` used to fall back to seeding from ``mfa_verified``. So this is the case a
    missing constant would seed, and the Kerberos test above (always ``mfa_verified=False``) could
    not see."""
    service = await _service(engine)
    out = await service._complete_ad_login(_principal("fed"), None, mfa_verified=True, mech="oidc")
    assert out.ok and out.token is not None
    session = await engine.store.get_session(hash_token(out.token))
    assert session is not None
    assert session.mfa_verified_at is not None  # the grant stands; only the window is withheld
    assert session.reauth_at is None
    assert await service.has_recent_step_up(out.token) is False


def test_no_directory_entry_point_lets_a_caller_choose_the_seeding() -> None:
    """RED when: ``seed_reauth`` comes back as a parameter on any directory entry point,
    ``_complete_ad_login`` stops passing the constant ``False``, or ``_issue_session`` regains a
    default for it.

    A parameter is how the two Kerberos routes came to disagree, so its absence IS the single
    posture. The default matters too: ``_issue_session`` used to fall back to ``mfa_verified``, so a
    new directory caller that named nothing would seed whenever it granted the factor. The source
    read is paired with the behavioural tests in this module rather than trusted alone."""
    for method in (
        AuthService.authenticate_kerberos,
        AuthService._authenticate_kerberos,
        AuthService.authenticate_oidc,
        AuthService._complete_ad_login,
    ):
        assert "seed_reauth" not in inspect.signature(method).parameters, method.__name__

    param = inspect.signature(AuthService._issue_session).parameters["seed_reauth"]
    assert param.default is inspect.Parameter.empty, "_issue_session gives seed_reauth a default"

    tree = ast.parse(textwrap.dedent(inspect.getsource(AuthService._complete_ad_login)))
    seeds = [
        kw.value
        for call in call_sites(tree, "_issue_session")
        for kw in call.keywords
        if kw.arg == "seed_reauth"
    ]
    # Empty means the call moved or stopped naming the argument. That is a failure, not a pass.
    assert len(seeds) == 1, "_complete_ad_login no longer passes seed_reauth to _issue_session"
    assert isinstance(seeds[0], ast.Constant) and seeds[0].value is False


async def test_a_pending_directory_session_cannot_ride_the_login_to_enroll_a_factor(
    engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    """RED when: a directory login seeds the window again, on the shipped ``require_mfa`` default.

    This is where the seeded window reached with ``require_mfa`` ON. The session owes a factor, so
    every ordinary gate refuses it at the MFA gate first. But factor enrollment skips that gate, so
    an account with no factor can bootstrap one. With ``require_action_step_up`` off (the documented
    opt-out) that route falls back to the session window. So a seeded window let a stolen ticket
    session bind an attacker's authenticator with no re-proof: the WP-14 hazard."""
    monkeypatch.setattr("messagefoundry.auth.service.kerberos_principal", lambda t, s: "jdoe")
    service = await _service(engine, require_mfa=True, require_action_step_up=False)
    async with _client(engine, service) as c:
        r = await c.post(
            "/auth/negotiate",
            headers={"Authorization": "Negotiate " + base64.b64encode(b"tok").decode()},
        )
        assert r.status_code == 200, r.text
        assert r.json()["mfa_required"] is True
        token = r.json()["token"]

        refused = await c.post("/me/mfa/enroll", headers=_bearer(token))
        assert refused.status_code == 403
        assert refused.headers.get("X-Step-Up-Required") == "1"

        # Not a lockout: the directory re-bind opens the window, and enrollment proceeds.
        stepped = await c.post("/me/reauth", json={"password": AD_PW}, headers=_bearer(token))
        assert stepped.status_code == 200, stepped.text
        fresh = stepped.json()["token"]
        enrolled = await c.post("/me/mfa/enroll", headers=_bearer(fresh))
        assert enrolled.status_code == 200, enrolled.text


async def test_the_local_password_leg_still_counts_login_as_the_first_verification(
    engine: Engine,
) -> None:
    """RED when: the change reaches the local leg, which step 5 does not touch.

    A local sign-in that owes no second factor keeps the sudo-timestamp model: login stamps the
    window, and the gated call is admitted with no step-up. This is also the control for the first
    test: the same route and the same settings admit a local session, so its refusal there is the
    directory seeding and not the fixture."""
    service = await _service(engine)
    user_id = await service.create_local_user(
        username="loc",
        password=PW,
        display_name=None,
        email=None,
        roles=[Role.ADMINISTRATOR.value],
        actor="test",
    )
    await service.set_channel_scope(user_id, [ALL_CHANNELS], actor="test")
    # Admin-created accounts force first-login rotation; clear it so it does not mask the gate.
    user = await engine.store.get_user(user_id)
    assert user is not None and user.password_hash is not None
    await engine.store.set_password(
        user_id, password_hash=user.password_hash, must_change_password=False
    )
    async with _client(engine, service) as c:
        r = await c.post(
            "/auth/login", json={"username": "loc", "password": PW, "provider": "local"}
        )
        assert r.status_code == 200, r.text
        token = r.json()["token"]
        session = await engine.store.get_session(hash_token(token))
        assert session is not None and session.reauth_at is not None
        assert await service.has_recent_step_up(token) is True
        admitted = await c.get(GATED, headers=_bearer(token))
        assert admitted.status_code == 200, admitted.text
