# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Signed-in /ui browser clients for the console suite, and the seeding each needs.

A sibling helper module rather than fixtures in ``conftest.py`` (the pattern ``_soft_webauthn.py``
already uses here): these are plain functions a test composes, not state pytest should inject.

They exist because two input-validation modules -- ``test_ui_input_substitution.py`` and
``test_ui_input_rules.py`` -- need the same six steps to reach a /ui route at all: an auth service,
an ASGI client over the mounted console, a provisioned local user with an explicit channel scope, a
cookie login, and for the JSON-parity tests a bearer token. Two copies drift, and the copy that
drifts silently is ``_provision``, whose BACKLOG #1152 channel-scope grant is the difference between
a test that measures input validation and one that measures an RBAC denial.
"""

from __future__ import annotations

import httpx

from messagefoundry.api import create_app
from messagefoundry.auth.identity import ALL_CHANNELS
from messagefoundry.auth.service import AuthService
from messagefoundry.config.settings import AuthSettings
from messagefoundry.pipeline import Engine

#: >=15 characters, no app or vendor terms -- satisfies the ASVS password policy (WP-3).
PW = "a-strong-test-passphrase"

#: A synthetic ADT^A01, the one message these suites seed. Never real PHI (CLAUDE.md section 9).
ADT = "MSH|^~\\&|S|F|R|RF|20260604||ADT^A01|MSG1|P|2.5.1\rPID|1||100^^^H^MR||DOE^JANE\r"

#: The same-origin header the console's CSRF guard requires on a /ui POST.
SAME_ORIGIN = {"Sec-Fetch-Site": "same-origin"}


async def auth_service(engine: Engine) -> AuthService:
    """An initialized auth service with MFA off.

    ``require_mfa=False`` because these suites exercise input validation and their fixtures never
    enroll an authenticator; an MFA gate would refuse before any input was read.
    """
    service = AuthService(engine.store, AuthSettings(require_mfa=False))
    await service.initialize()
    return service


def ui_client(engine: Engine, service: AuthService) -> httpx.AsyncClient:
    """An ASGI client over the engine app with the console mounted -- the real ``mount_ui`` path."""
    transport = httpx.ASGITransport(app=create_app(engine, auth=service, serve_ui=True))
    return httpx.AsyncClient(transport=transport, base_url="http://t")


async def provision(service: AuthService, username: str, roles: list[str]) -> str:
    """Create a local user who can actually sign in, and return its id.

    Two steps beyond ``create_local_user`` and both are load-bearing. BACKLOG #1152 made an UNSET
    channel scope deny, so the estate is granted explicitly or every route 403s on scope rather than
    reaching the input under test. And the must-change-password flag is cleared, or the first
    request redirects to the password-change page instead of the route.
    """
    user_id = await service.create_local_user(
        username=username,
        password=PW,
        display_name=None,
        email=None,
        roles=roles,
        actor="test",
    )
    await service.set_channel_scope(user_id, [ALL_CHANNELS], actor="test")
    user = await service.store.get_user(user_id)
    assert user is not None and user.password_hash is not None
    await service.store.set_password(
        user_id, password_hash=user.password_hash, must_change_password=False
    )
    return user_id


async def cookie_login(client: httpx.AsyncClient, username: str) -> None:
    """Sign in over /ui/login, leaving the session cookie on ``client``.

    200 or 303 both mean signed in: the console 303s to the dashboard and renders 200 in the cases
    where it lands somewhere else, and which one is not what these suites are measuring.
    """
    r = await client.post("/ui/login", data={"username": username, "password": PW})
    assert r.status_code in (200, 303), f"login for {username!r} returned {r.status_code}"


async def bearer(client: httpx.AsyncClient, username: str) -> dict[str, str]:
    """A native bearer header, so a test can ask the JSON twin the SAME question.

    The /ui cookie is confined to /ui and is rejected on the JSON API, so it cannot stand in for
    this -- which is the whole reason a parity test pays for a second login.
    """
    token = (await client.post("/auth/login", json={"username": username, "password": PW})).json()[
        "token"
    ]
    return {"Authorization": f"Bearer {token}"}


async def seed_message(engine: Engine) -> str:
    """One delivered-shaped message in the store, so a filter has something to include or exclude."""
    return await engine.store.enqueue_message(
        channel_id="ch1",
        raw=ADT,
        deliveries=[("archive", ADT)],
        control_id="MSG1",
        message_type="ADT^A01",
        source_type="file",
    )
