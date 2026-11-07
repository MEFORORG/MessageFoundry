# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""ADR 0207 on the web console: the passkey arm of AC-4, the code field in the passkey page and
the TOTP confirm form, and the Administrator's issue button and one-time page (AC-8).

The passkey ceremony is begun at the service, as ``test_ui_passkey_finish_factor_refusal.py`` does,
because the begin route takes an action-bound password re-proof a directory account makes at the
directory. All accounts and directory data are synthetic; the codes are minted by the engine.
"""

from __future__ import annotations

import json
import uuid
from typing import Any

import pytest
from _ui_clients import (
    SAME_ORIGIN,
    PresentDirectory,
    cookie_login,
    mint_bound_proof,
    provision,
    ui_client,
)

from messagefoundry.auth import Role
from messagefoundry.auth.identity import Identity
from messagefoundry.auth.ldap import AdPrincipal
from messagefoundry.auth.service import ENROLMENT_CODE_REFUSED, AuthService
from messagefoundry.auth.tokens import enrolment_code_digest, hash_token
from messagefoundry.config.settings import AuthSettings
from messagefoundry.pipeline import Engine
from messagefoundry_webconsole.pages import account as account_pages

_VERIFY = "/ui/account/webauthn/verify"

_PRINCIPAL = AdPrincipal(
    username="adcode",
    display_name=None,
    email=None,
    dn="CN=adcode,DC=x",
    groups=frozenset(),
    directory_object_id=str(uuid.uuid5(uuid.NAMESPACE_URL, "adcode")),
)


async def _service(engine: Engine) -> AuthService:
    service = AuthService(
        engine.store,
        AuthSettings(
            require_mfa=False,
            mfa_verify_min_elapsed_seconds=0,
            admin_write_min_interval_seconds=0,
            ad_enabled=True,
            ad_server="ldaps://dc.x",
            ad_user_search_base="DC=x",
            ad_bind_dn="CN=svc,DC=x",
            ad_bind_password="synthetic",
        ),
        ldap=PresentDirectory(_PRINCIPAL),  # type: ignore[arg-type]
    )
    await service.initialize()
    return service


async def _staged(service: AuthService) -> tuple[Identity, str, dict[str, Any]]:
    from _soft_webauthn import SoftAuthenticator
    from webauthn.helpers import base64url_to_bytes

    out = await service._complete_ad_login(_PRINCIPAL, None, mfa_verified=False)
    assert out.ok and out.token is not None and out.identity is not None
    options = json.loads(
        await service.begin_webauthn_registration(
            out.identity, token=out.token, rp_id="t", rp_name="MessageFoundry"
        )
    )
    await service.store.mark_session_reauthed(hash_token(out.token))
    key = SoftAuthenticator(rp_id="t", origin="http://t")
    response = json.loads(key.create_response(base64url_to_bytes(options["challenge"])))
    return out.identity, out.token, {"label": "key", "response": response}


async def test_ac4_the_console_passkey_finish_needs_the_code(engine: Engine) -> None:
    """AC-4 and AC-19 on the console: with no code the finish answers the one reply, stores no
    credential and leaves the ceremony staged, so the same attestation with the code then binds."""
    pytest.importorskip("webauthn")
    service = await _service(engine)
    identity, token, body = await _staged(service)
    issued = await service.issue_enrolment_code(
        identity.user_id, actor="test-host", issuer_id=None, via="host"
    )
    async with ui_client(engine, service, webauthn_rp_from_request=True) as c:
        c.cookies.set("mf_session", token)
        refused = await c.post(_VERIFY, json=body, headers=SAME_ORIGIN)
        assert refused.status_code == 400
        assert refused.json() == {"ok": False, "error": ENROLMENT_CODE_REFUSED}
        assert await service.store.list_webauthn_credentials(identity.user_id) == []
        served = await c.post(
            _VERIFY, json={**body, "enrolment_code": issued.code}, headers=SAME_ORIGIN
        )
        assert served.status_code == 200 and served.json()["ok"] is True, served.text
    assert len(await service.store.list_webauthn_credentials(identity.user_id)) == 1
    user = await service.store.get_user(identity.user_id)
    assert user is not None and user.enrolment_code_digest is None


def test_the_binding_forms_carry_the_code_field_only_when_owed() -> None:
    """The TOTP confirm form and the passkey page carry the field when the session owes a code, and
    the passkey page says how to ask for one (ADR 0207 section 8)."""
    assert 'name="enrolment_code"' in str(account_pages.mfa_confirm_page(enrolment_code=True))
    assert 'name="enrolment_code"' not in str(account_pages.mfa_confirm_page())
    owed = str(account_pages.webauthn_enroll_page("{}", enrolment_code=True))
    assert 'name="enrolment_code"' in owed
    assert "identity check" in owed and "do not ask for the code by mail or chat" in owed
    assert 'name="enrolment_code"' not in str(account_pages.webauthn_enroll_page("{}"))


async def test_ac8_an_administrator_issues_a_code_from_the_user_page(engine: Engine) -> None:
    """AC-8 on the console: the issue lane is action-bound, the page shows the code once with the
    handover rule, and the store holds only its digest."""
    service = await _service(engine)
    await provision(service, "opsadmin", [Role.ADMINISTRATOR.value])
    out = await service._complete_ad_login(_PRINCIPAL, None, mfa_verified=False)
    assert out.identity is not None
    target = out.identity.user_id
    path = f"/ui/users/{target}/enrolment-code"
    async with ui_client(engine, service) as c:
        await cookie_login(c, "opsadmin")
        page = await c.get(f"/ui/users/{target}")
        assert path in page.text  # the button is offered for a directory account
        await mint_bound_proof(c, path)
        r = await c.post(path, headers=SAME_ORIGIN)
        assert r.status_code == 200, r.text
        assert "shown once" in r.text and "identity check" in r.text
    user = await service.store.get_user(target)
    assert user is not None and user.enrolment_code_digest is not None
    shown = [
        line.split("<code>")[1].split("</code>")[0]
        for line in r.text.splitlines()
        if "<code>" in line
    ]
    assert any(enrolment_code_digest(s) == user.enrolment_code_digest for s in shown)
