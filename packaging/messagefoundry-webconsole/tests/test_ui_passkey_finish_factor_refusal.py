# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The console's passkey finish route, ``POST /ui/account/webauthn/verify``, and the factor refusal.

BACKLOG #3014 made ``finish_webauthn_registration`` refuse a pending session on an account that
gained a factor after the ceremony was staged. ``tests/test_passkey_finish_factor_binding.py`` pins
that at the service. This file drives it through the route (BACKLOG #3690 item 4), and pins two
things the route adds: it does not charge the per-actor ceremony budget for a session the finish
will refuse that way (item 6, the BACKLOG #1973 rule), and its 429 sends the ceremony routes'
constant ``Retry-After`` (item 5).

The account is a directory account: its unstamped session may register a first passkey, which a
local sign-in that owes nothing never needs. The ceremony is begun at the service, as
``test_ui_mfa_enrolment_floor.py`` does, because the begin route takes an action-bound password
re-proof a directory account makes at the directory. All directory data is synthetic.
"""

from __future__ import annotations

import json
import uuid
from typing import Any

import pytest
from _ui_clients import SAME_ORIGIN, PresentDirectory, held_totp_code, ui_client

from messagefoundry.auth.identity import Identity
from messagefoundry.auth.ldap import AdPrincipal
from messagefoundry.auth.service import AuthService
from messagefoundry.auth.tokens import hash_token
from messagefoundry.config.settings import AuthSettings
from messagefoundry.pipeline import Engine

pytest.importorskip("webauthn")

_VERIFY = "/ui/account/webauthn/verify"

_PRINCIPAL = AdPrincipal(
    username="adfinish",
    display_name=None,
    email=None,
    dn="CN=adfinish,DC=x",
    groups=frozenset(),
    directory_object_id=str(uuid.uuid5(uuid.NAMESPACE_URL, "adfinish")),
)


async def _service(engine: Engine) -> AuthService:
    """require_mfa on (the default), so the directory session mints owing its factor. The two
    human-timing floors are off: neither is under test."""
    service = AuthService(
        engine.store,
        AuthSettings(admin_write_min_interval_seconds=0, mfa_verify_min_elapsed_seconds=0),
        ldap=PresentDirectory(_PRINCIPAL),  # type: ignore[arg-type]
    )
    await service.initialize()
    return service


async def _sign_in(service: AuthService) -> tuple[Identity, str]:
    out = await service._complete_ad_login(_PRINCIPAL, None, mfa_verified=False)
    assert out.ok and out.token is not None and out.identity is not None
    return out.identity, out.token


async def _staged_body(service: AuthService, identity: Identity, token: str) -> dict[str, Any]:
    """Stage a registration ceremony at the service and return the route body answering it. The
    session is stamped re-authed, which is all the finish route's gate asks."""
    from _soft_webauthn import SoftAuthenticator
    from webauthn.helpers import base64url_to_bytes

    options = json.loads(
        await service.begin_webauthn_registration(
            identity, token=token, rp_id="t", rp_name="MessageFoundry"
        )
    )
    await service.store.mark_session_reauthed(hash_token(token))
    key = SoftAuthenticator(rp_id="t", origin="http://t")
    response = json.loads(key.create_response(base64url_to_bytes(options["challenge"])))
    return {"label": "key", "response": response}


async def _enrol_totp_elsewhere(service: AuthService) -> None:
    """Enrol TOTP on a SECOND session of the same account."""
    identity, token = await _sign_in(service)
    enrollment = await service.begin_mfa_enrollment(identity)
    with held_totp_code(enrollment.secret) as code:
        assert (await service.confirm_mfa_enrollment(identity, code, token=token)).ok


def _spy_ceremony_budget(service: AuthService, monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """Record every ``allow_reauth_attempt`` charge from here on, and still apply it."""
    calls: list[str] = []
    real = service.allow_reauth_attempt

    def spy(actor: str) -> bool:
        calls.append(actor)
        return real(actor)

    monkeypatch.setattr(service, "allow_reauth_attempt", spy)
    return calls


async def test_the_route_refuses_a_finish_after_the_account_gained_a_factor(
    engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    """RED when: the route stops reaching the service's factor refusal, answers it as anything but
    a 400 the page's fetch can read, stores a passkey, stamps the session, or charges the per-actor
    ceremony budget for a request the finish refuses for owing a factor (BACKLOG #3690 items 4, 6).
    """
    service = await _service(engine)
    identity, token = await _sign_in(service)
    body = await _staged_body(service, identity, token)
    await _enrol_totp_elsewhere(service)
    assert await service.mfa_satisfied(token) is False  # the staging session never proved it
    calls = _spy_ceremony_budget(service, monkeypatch)

    async with ui_client(engine, service, webauthn_rp_from_request=True) as c:
        c.cookies.set("mf_session", token)
        refused = await c.post(_VERIFY, json=body, headers=SAME_ORIGIN)
        assert refused.status_code == 400, refused.text
        assert refused.json()["ok"] is False
        assert "already has a second factor" in refused.json()["error"]
        # The refusal ended the ceremony, so a retry is answered "ceremony expired". Neither it nor
        # the refusal drew the budget: a password holder refused in a loop spends none of it.
        for _ in range(2):
            again = await c.post(_VERIFY, json=body, headers=SAME_ORIGIN)
            assert again.status_code == 400 and "ceremony expired" in again.json()["error"]

    assert calls == [], f"a session the finish refuses was charged: {calls}"
    assert await service.store.list_webauthn_credentials(identity.user_id) == []
    assert await service.mfa_satisfied(token) is False
    rows = await service.store.list_audit(action="auth.mfa_denied")
    assert {"path": "finish_webauthn_registration"} in [json.loads(r["detail"]) for r in rows]


async def test_the_route_still_charges_a_finish_it_lets_through(
    engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The control for the test above. RED when: the charge is skipped for everyone, or the spy is
    not wired, which would let an empty list there mean "not observed" rather than "not charged"."""
    service = await _service(engine)
    identity, token = await _sign_in(service)
    body = await _staged_body(service, identity, token)
    calls = _spy_ceremony_budget(service, monkeypatch)

    async with ui_client(engine, service, webauthn_rp_from_request=True) as c:
        c.cookies.set("mf_session", token)
        served = await c.post(_VERIFY, json=body, headers=SAME_ORIGIN)
    assert served.status_code == 200 and served.json()["ok"] is True, served.text
    assert calls == [identity.user_id]
    assert len(await service.store.list_webauthn_credentials(identity.user_id)) == 1


async def test_the_routes_429_sends_the_ceremony_retry_after(
    engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    """RED when: the passkey finish's 429 sends no ``Retry-After``, or one other than the constant
    the other console ceremony 429s on the same budget send (BACKLOG #3690 item 5). The ceremony
    survives the throttle, so nothing is stored."""
    service = await _service(engine)
    identity, token = await _sign_in(service)
    body = await _staged_body(service, identity, token)
    monkeypatch.setattr(service, "allow_reauth_attempt", lambda _actor: False)

    async with ui_client(engine, service, webauthn_rp_from_request=True) as c:
        c.cookies.set("mf_session", token)
        refused = await c.post(_VERIFY, json=body, headers=SAME_ORIGIN)
    assert refused.status_code == 429 and refused.json()["ok"] is False, refused.text
    assert refused.headers["Retry-After"] == "30"
    assert await service.store.list_webauthn_credentials(identity.user_id) == []
