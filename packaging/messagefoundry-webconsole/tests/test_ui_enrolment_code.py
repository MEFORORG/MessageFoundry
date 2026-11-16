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
from messagefoundry.auth.tokens import ENROLMENT_CODE_MAX, enrolment_code_digest, hash_token
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


async def _code_refusals(service: AuthService) -> list[str]:
    return [
        json.loads(r["detail"])["reason"]
        for r in await service.store.list_audit(action="auth.enrolment_code_refused")
    ]


async def test_an_oversized_passkey_enrolment_code_is_refused_where_the_engine_reads_it(
    engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    """BACKLOG #5399. RED when: the console passkey finish cuts the enrolment code to a length, or
    the engine reads a code past MfaConfirmRequest's bound rather than refusing it as a refused
    code, audited. The controls: a wrong code at the bound is refused the same way, and the ceremony
    both refusals left staged then binds with the issued code."""
    pytest.importorskip("webauthn")
    service = await _service(engine)
    identity, token, body = await _staged(service)
    issued = await service.issue_enrolment_code(
        identity.user_id, actor="test-host", issuer_id=None, via="host"
    )
    calls: list[object] = []
    real = service.finish_webauthn_registration

    async def spy(*args: Any, **kwargs: Any) -> Any:
        calls.append(kwargs.get("enrolment_code"))
        return await real(*args, **kwargs)

    monkeypatch.setattr(service, "finish_webauthn_registration", spy)
    async with ui_client(engine, service, webauthn_rp_from_request=True) as c:
        c.cookies.set("mf_session", token)
        # The issued code with junk after it: cut to the bound, the old handler kept a prefix.
        oversized = (issued.code + "x" * ENROLMENT_CODE_MAX)[: ENROLMENT_CODE_MAX + 1]
        at_bound = "x" * ENROLMENT_CODE_MAX
        for code in (oversized, at_bound):
            refused = await c.post(
                _VERIFY, json={**body, "enrolment_code": code}, headers=SAME_ORIGIN
            )
            assert refused.status_code == 400
            assert refused.json() == {"ok": False, "error": ENROLMENT_CODE_REFUSED}
        assert calls == [oversized, at_bound]
        assert await _code_refusals(service) == ["code_refused", "code_refused"]
        served = await c.post(
            _VERIFY, json={**body, "enrolment_code": issued.code}, headers=SAME_ORIGIN
        )
        assert served.status_code == 200 and served.json()["ok"] is True, served.text
    assert len(await service.store.list_webauthn_credentials(identity.user_id)) == 1


async def test_a_lost_session_with_an_oversized_enrolment_code_is_still_answered_lost(
    engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    """BACKLOG #5399. RED when: the enrolment-code bound answers a finish whose session died ahead
    of the service's lost-session reply, the 401 main gave. The session dies after the route's own
    factor read passed, so the route holds no refusal of its own to explain the 401."""
    pytest.importorskip("webauthn")
    service = await _service(engine)
    identity, token, body = await _staged(service)
    await service.issue_enrolment_code(
        identity.user_id, actor="test-host", issuer_id=None, via="host"
    )
    real = service.factor_binding_is_blocked

    async def read_then_revoked(token_: str | None, action: str) -> bool:
        blocked = await real(token_, action)
        await service.store.revoke_session(hash_token(token))
        return blocked

    monkeypatch.setattr(service, "factor_binding_is_blocked", read_then_revoked)
    async with ui_client(engine, service, webauthn_rp_from_request=True) as c:
        c.cookies.set("mf_session", token)
        lost = await c.post(
            _VERIFY,
            json={**body, "enrolment_code": "x" * (ENROLMENT_CODE_MAX + 1)},
            headers=SAME_ORIGIN,
        )
    assert lost.status_code == 401 and lost.json()["error"] == "session expired", lost.text
    assert await _code_refusals(service) == []
    assert await service.store.list_webauthn_credentials(identity.user_id) == []


async def test_an_expired_ceremony_with_an_oversized_enrolment_code_is_still_the_expired_reply(
    engine: Engine,
) -> None:
    """BACKLOG #5399. RED when: the enrolment-code bound answers a finish with no staged ceremony
    ahead of the service's own "ceremony expired" reply, the one main gave, or writes an
    enrolment-code refusal for it."""
    pytest.importorskip("webauthn")
    service = await _service(engine)
    identity, token, body = await _staged(service)
    await service.issue_enrolment_code(
        identity.user_id, actor="test-host", issuer_id=None, via="host"
    )
    service._webauthn_challenges.pop((hash_token(token), "register"))
    async with ui_client(engine, service, webauthn_rp_from_request=True) as c:
        c.cookies.set("mf_session", token)
        expired = await c.post(
            _VERIFY,
            json={**body, "enrolment_code": "x" * (ENROLMENT_CODE_MAX + 1)},
            headers=SAME_ORIGIN,
        )
    assert expired.status_code == 400, expired.text
    assert "ceremony expired" in expired.json()["error"]
    assert await _code_refusals(service) == []


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
