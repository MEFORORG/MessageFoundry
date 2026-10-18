# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""/ui content search and audit view, WebAuthn passkeys (ADR 0068), off-loopback hardening, AD password
and Kerberos SSO login, account sessions, and the web-console parity closeout (BACKLOG #75)."""

from __future__ import annotations

import json
from urllib.parse import quote

import httpx
import pytest
from _webui_support import (
    PW,
    _add,
    _boss_client,
    _client,
    _cookie_login,
    _mint_action,
    _seed,
    _service,
    _uid,
)

from messagefoundry.api import create_app
from messagefoundry.auth import Role
from messagefoundry.auth.identity import AuthProvider
from messagefoundry.auth.service import AuthService
from messagefoundry.auth.tokens import hash_token
from messagefoundry.config.settings import AuthSettings
from messagefoundry.pipeline import Engine

# --- content-search (step-up-unlock GET over the JSON search) + L1c audit view --------------------


async def test_search_page_renders_bare_form(engine: Engine) -> None:
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    async with _client(engine, service) as c:
        await _cookie_login(c, "op")
        r = await c.get("/ui/messages/search")
        assert r.status_code == 200
        # The form POSTs its criteria (BACKLOG #1184) — the page path renders it, /run executes it.
        assert 'action="/ui/messages/search/run"' in r.text
        assert 'name="field_path"' in r.text and 'name="field_value"' in r.text
        assert "Content search" in r.text
        # No criteria → no results section (no decrypt/audit ran).
        assert "match(es)" not in r.text


async def test_search_finds_by_field(engine: Engine) -> None:
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    mid = await _seed(engine)  # ADT with PID-3 = 100
    async with _client(engine, service) as c:
        await _cookie_login(c, "op")  # fresh login = a recent step-up
        r = await c.get("/ui/messages/search", params={"field_path": "PID-3", "field_value": "100"})
        assert r.status_code == 200
        assert "match(es)" in r.text
        assert f"/ui/messages/{mid}" in r.text  # links to the audited detail view
        # A dedicated message_search audit row was written (metadata only).
        rows = await service.store.list_audit(limit=20)
        assert any(x["action"] == "message_search" for x in rows)


async def test_search_field_presence_test_runs(engine: Engine) -> None:
    # A field_path alone (no value) is a valid presence-test search — /ui must run it, matching the
    # JSON API (review D2). It renders results (a decrypt + audit ran), not the bare form.
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    await _seed(engine)
    async with _client(engine, service) as c:
        await _cookie_login(c, "op")
        r = await c.get("/ui/messages/search", params={"field_path": "PID-3"})
        assert r.status_code == 200
        assert "match(es)" in r.text  # a search ran (not the bare form)


async def test_search_requires_messages_read(engine: Engine) -> None:
    # DEPLOYMENT holds monitoring/config perms but NOT messages:read → refused before any decrypt.
    service = await _service(engine)
    await _add(service, "dep", Role.DEPLOYMENT)
    async with _client(engine, service) as c:
        await _cookie_login(c, "dep")
        r = await c.get("/ui/messages/search", params={"field_path": "PID-3", "field_value": "100"})
        assert r.status_code == 403


async def test_search_registered_as_unlock_action(engine: Engine) -> None:
    from messagefoundry_webconsole import is_safe_ui_action, is_unlock_action

    service = await _service(engine)
    create_app(engine, auth=service, serve_ui=True)
    assert is_unlock_action("/ui/messages/search")
    assert not is_safe_ui_action("/ui/messages/search")  # a GET form, never a POST auto-retry


async def test_search_stale_stepup_bounces_to_reauth(engine: Engine) -> None:
    service = AuthService(engine.store, AuthSettings(step_up_max_age_seconds=-1, require_mfa=False))
    await service.initialize()
    await _add(service, "op", Role.OPERATOR)
    async with _client(engine, service) as c:
        await _cookie_login(c, "op")
        r = await c.get("/ui/messages/search", params={"field_path": "PID-3", "field_value": "1"})
        assert r.status_code == 303
        assert r.headers["location"] == "/ui/reauth?next=/ui/messages/search"
        # The reauth flow accepts the search page as an unlock target and GET-redirects back to it.
        r = await c.get("/ui/reauth", params={"next": "/ui/messages/search"})
        assert r.status_code == 200 and 'name="password"' in r.text


async def test_search_hostile_field_value_is_escaped(engine: Engine) -> None:
    # A submitted search term is reflected into the form input — it must render escaped.
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    async with _client(engine, service) as c:
        await _cookie_login(c, "op")
        # The term now arrives in the POST body (BACKLOG #1184); it is still reflected into the
        # form input on the way back, which is what must render escaped.
        r = await c.post(
            "/ui/messages/search/run",
            data={"content": '"><script>alert(1)</script>'},
        )
        assert r.status_code == 200
        assert "<script>alert(1)</script>" not in r.text
        assert "&lt;script&gt;alert(1)&lt;/script&gt;" in r.text


async def test_audit_page_requires_audit_read(engine: Engine) -> None:
    service = await _service(engine)
    await _add(service, "auditor", Role.AUDITOR)
    await _add(service, "op", Role.OPERATOR)
    async with _client(engine, service) as c:
        await _cookie_login(c, "auditor")
        r = await c.get("/ui/audit")
        assert r.status_code == 200
        assert "Audit log" in r.text
        # The auditor's own sign-in is in the trail.
        assert "auth.login_success" in r.text
    async with _client(engine, service) as c:
        await _cookie_login(c, "op")  # no audit:read
        assert (await c.get("/ui/audit")).status_code == 403


async def test_security_events_self_service(engine: Engine) -> None:
    # Any signed-in user sees their OWN security events (no special permission).
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    async with _client(engine, service) as c:
        await _cookie_login(c, "op")
        r = await c.get("/ui/security-events")
        assert r.status_code == 200
        assert "My security events" in r.text and "auth.login_success" in r.text
        # The nav entries are registered.
        assert 'href="/ui/audit"' in r.text and 'href="/ui/security-events"' in r.text


async def test_audit_cookie_not_accepted_on_json_routes(engine: Engine) -> None:
    service = await _service(engine)
    await _add(service, "auditor", Role.AUDITOR)
    async with _client(engine, service) as c:
        await _cookie_login(c, "auditor")
        assert (await c.get("/audit")).status_code == 401
        assert (await c.get("/me/security-events")).status_code == 401


# --- L5a: WebAuthn passkeys (ADR 0068, WP-14b), #75 phase 4 -----------------------------------------
#
# Browser-level ceremony tests use the in-repo soft authenticator and are gated FUNCTION-LOCALLY on
# the [webauthn] extra (a module-level importorskip here would skip the whole webui suite on an
# extra-less install). The passkey assertion satisfies ONLY the MFA leg; the mandatory password leg
# of POST /ui/reauth stamps step-up freshness + the new-IP re-anchor (decision 1). Options ride
# HTML-escaped data-* attributes (CSP: no inline script); only the verify legs are JSON POSTs — the
# sanctioned first cookie-authed JSON under /ui.

_SFS = {"Sec-Fetch-Site": "same-origin"}


def _data_attr(text: str, attr: str) -> dict:
    """Extract + unescape the ceremony-options JSON riding an HTML data-* attribute."""
    import html as _html
    import re as _re

    m = _re.search(attr + '="([^"]*)"', text)
    assert m, f"{attr} hook not found in page"
    return json.loads(_html.unescape(m.group(1)))


async def _browser_stage(c: httpx.AsyncClient) -> tuple[object, dict]:
    """Stage a browser registration ceremony; returns the soft authenticator and its attestation."""
    from _soft_webauthn import SoftAuthenticator
    from webauthn.helpers import base64url_to_bytes

    await _mint_action(
        c, "/ui/account/webauthn/enroll"
    )  # 7.5.1: enroll is action-bound (single-use)
    r = await c.post("/ui/account/webauthn/enroll", headers=_SFS)
    assert r.status_code == 200, r.text
    options = _data_attr(r.text, "data-mf-webauthn-create")
    auth = SoftAuthenticator(rp_id="t", origin="http://t")
    return auth, json.loads(auth.create_response(base64url_to_bytes(options["challenge"])))


async def _browser_enroll(c: httpx.AsyncClient, *, label: str) -> object:
    """Run the full browser registration ceremony; returns the enrolled soft authenticator."""
    auth, resp = await _browser_stage(c)
    r = await c.post(
        "/ui/account/webauthn/verify", json={"label": label, "response": resp}, headers=_SFS
    )
    assert r.status_code == 200 and r.json()["ok"] is True, r.text
    return auth


async def test_webauthn_browser_enroll_and_stepup_e2e(engine: Engine) -> None:
    pytest.importorskip("webauthn")
    from webauthn.helpers import base64url_to_bytes

    service = await _service(engine)
    async with _boss_client(engine, service) as c:
        # Fresh login seeds step-up freshness (boss has no factor yet), so enroll passes the
        # password-only gate directly. Enroll TWO passkeys so one can be deleted via the dance.
        auth_a = await _browser_enroll(c, label="key A")
        await _browser_enroll(c, label="key B")
        r = await c.get("/ui/account")
        assert "key A" in r.text and "key B" in r.text
        assert 'action="/ui/account/webauthn/' in r.text  # per-row Remove forms

        # A FRESH session is MFA-pending (webauthn-enrolled => required) with no freshness.
        await _cookie_login(c, "boss")
        boss_id = await _uid(service, "boss")
        creds = await service.store.list_webauthn_credentials(boss_id)
        target = next(x.credential_id_hash for x in creds if x.label == "key B")
        delete_path = f"/ui/account/webauthn/{target}/delete"

        # The registered step_up action 303s to /ui/reauth — NOT the enroll_first divert
        # (the generalized anti-loop: this user IS enrolled, decision 1(a)).
        r = await c.post(delete_path, headers=_SFS)
        assert r.status_code == 303 and r.headers["location"].startswith("/ui/reauth?next=")

        # The reauth page renders password + passkey hook and NO code field (decision 1(b)).
        r = await c.get("/ui/reauth?next=" + quote(delete_path, safe=""))
        assert r.status_code == 200
        assert "data-mf-webauthn-get" in r.text and 'name="code"' not in r.text

        # Password-only POST from a WebAuthn-only user: the pre-limiter guard (decision 1(d)) —
        # never "Invalid code.", and the passkey button survives with FRESH options (1(e)).
        r = await c.post("/ui/reauth", data={"next": delete_path, "password": PW}, headers=_SFS)
        assert r.status_code == 400
        assert "Complete the passkey prompt first" in r.text
        assert "Invalid code." not in r.text
        options = _data_attr(r.text, "data-mf-webauthn-get")

        # The passkey leg: assert -> MFA satisfied (ONLY the MFA leg — the delete is still stale).
        resp = json.loads(
            auth_a.get_response(base64url_to_bytes(options["challenge"]), sign_count=0)
        )
        r = await c.post("/ui/reauth/webauthn", json={"response": resp}, headers=_SFS)
        assert r.status_code == 200 and r.json() == {"ok": True}
        r = await c.post(delete_path, headers=_SFS)
        assert r.status_code == 303  # still 303s: reauth_at is NOT stamped by the assertion

        # The password leg completes the pair -> continuation auto-retries the delete.
        r = await c.post("/ui/reauth", data={"next": delete_path, "password": PW}, headers=_SFS)
        assert r.status_code == 200 and 'action="' + delete_path + '"' in r.text
        r = await c.post(delete_path, headers=_SFS)
        assert r.status_code == 303 and r.headers["location"] == "/ui/account?m=passkey_removed"
        assert len(await service.store.list_webauthn_credentials(boss_id)) == 1


async def test_webauthn_enroll_requires_password_reproof(engine: Engine) -> None:
    # WP-14 (AC-1): a require_mfa MFA-pending session has NO step-up freshness — the enroll POST
    # walks the password-only reauth continuation before any ceremony starts.
    pytest.importorskip("webauthn")
    service = AuthService(
        engine.store,
        AuthSettings(
            admin_write_min_interval_seconds=0, mfa_verify_min_elapsed_seconds=0, require_mfa=True
        ),
    )
    await service.initialize()
    await _add(service, "boss", Role.ADMINISTRATOR)
    async with _client(engine, service) as c:
        await _cookie_login(c, "boss")
        r = await c.post("/ui/account/webauthn/enroll", headers=_SFS)
        assert r.status_code == 303
        assert r.headers["location"].startswith("/ui/reauth?next=")
        # The password-only continuation (enroll is step_up=False) renders and auto-retries.
        r = await c.post(
            "/ui/reauth",
            data={"next": "/ui/account/webauthn/enroll", "password": PW},
            headers=_SFS,
        )
        assert r.status_code == 200 and 'action="/ui/account/webauthn/enroll"' in r.text
        # ADR 0197 Amendment A, AC-A3: the continuation still works, and then the service refuses a
        # passkey as this covered account's FIRST factor -- it has no way past the sign-in lock.
        r = await c.post("/ui/account/webauthn/enroll", headers=_SFS)
        assert r.status_code == 400 and "enrol an authenticator app first" in r.text


async def test_reauth_both_factors_enrolled_renders_code_and_passkey(engine: Engine) -> None:
    # decision 1(b) both-enrolled + 1(e): a bad code re-render still carries a FRESH passkey hook.
    pytest.importorskip("webauthn")
    service = await _service(engine)
    async with _boss_client(engine, service) as c:
        await _browser_enroll(c, label="key A")
        # Enroll TOTP alongside via the service (the browser TOTP flow is L4b-tested).
        boss_id = await _uid(service, "boss")
        from messagefoundry.auth import totp as totp_mod

        secret = totp_mod.generate_secret()
        staged_cell = await service.store.set_totp_secret(boss_id, secret=secret)
        await service.store.enable_totp(
            boss_id, expected_secret_cell=staged_cell, recovery_code_hashes=[]
        )

        await _cookie_login(c, "boss")  # fresh MFA-pending session
        boss_creds = await service.store.list_webauthn_credentials(boss_id)
        delete_path = f"/ui/account/webauthn/{boss_creds[0].credential_id_hash}/delete"
        r = await c.get("/ui/reauth?next=" + quote(delete_path, safe=""))
        assert 'name="code"' in r.text and "data-mf-webauthn-get" in r.text
        first = _data_attr(r.text, "data-mf-webauthn-get")
        r = await c.post(
            "/ui/reauth",
            data={"next": delete_path, "password": PW, "code": "000000"},
            headers=_SFS,
        )
        assert "Invalid code." in r.text
        second = _data_attr(r.text, "data-mf-webauthn-get")
        assert second["challenge"] != first["challenge"]  # re-staged, not replayed (1(e))


async def test_webauthn_json_endpoints_reject_bearer_without_cookie(engine: Engine) -> None:
    # The inverse cookie boundary (AC-8): the /ui JSON ceremony endpoints are cookie-authed —
    # a bearer header alone (the JSON API credential) must not reach them.
    service = await _service(engine)
    await _add(service, "boss", Role.ADMINISTRATOR)
    out = await service.login("boss", PW)
    assert out.ok and out.token is not None
    async with _client(engine, service) as c:
        headers = {"Authorization": f"Bearer {out.token}", **_SFS}
        r = await c.post("/ui/reauth/webauthn", json={"response": {}}, headers=headers)
        assert r.status_code == 401
        r = await c.post("/ui/account/webauthn/verify", json={"response": {}}, headers=headers)
        assert r.status_code == 303  # require_ui-family: no cookie -> login redirect


async def test_webauthn_verify_draws_on_the_ceremony_budget(
    engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    # BACKLOG #3014: the passkey finish draws on the per-actor ceremony budget, as mfa/verify does.
    # RED when: a denied budget still reaches the service, or answers with a body the page's fetch
    # cannot read. The throttle comes before the service, so the ceremony survives it.
    pytest.importorskip("webauthn")
    service = await _service(engine)
    async with _boss_client(engine, service) as c:
        _auth, resp = await _browser_stage(c)
        real = service.allow_reauth_attempt
        monkeypatch.setattr(service, "allow_reauth_attempt", lambda _actor: False)
        r = await c.post(
            "/ui/account/webauthn/verify", json={"label": "k", "response": resp}, headers=_SFS
        )
        body = r.json()
        assert r.status_code == 429 and body["ok"] is False and body["error"]
        uid = await _uid(service, "boss")
        assert await service.store.list_webauthn_credentials(uid) == []

        monkeypatch.setattr(service, "allow_reauth_attempt", real)
        r = await c.post(
            "/ui/account/webauthn/verify", json={"label": "k", "response": resp}, headers=_SFS
        )
        assert r.status_code == 200 and r.json()["ok"] is True, r.text


async def test_webauthn_cross_site_posts_rejected(engine: Engine) -> None:
    # AC-9: every new /ui POST joins the cross-site sweep (403 via assert_same_origin).
    service = await _service(engine)
    async with _boss_client(engine, service) as c:
        # 7.5.1: mint the action grants for the two action-bound webauthn POSTs so the cross-site
        # sweep still reaches (and 403s at) their in-body assert_same_origin (see the admin sweep note).
        await _mint_action(c, "/ui/account/webauthn/enroll")
        await _mint_action(c, "/ui/account/webauthn/abc123/delete")
        for path in (
            "/ui/account/webauthn/enroll",
            "/ui/account/webauthn/verify",
            "/ui/account/webauthn/abc123/delete",
            "/ui/reauth/webauthn",
        ):
            r = await c.post(path, headers={"Sec-Fetch-Site": "cross-site"})
            assert r.status_code == 403, path


async def test_webauthn_rp_fail_closed_legible(engine: Engine) -> None:
    # AC-7: public_origin unset + request-derivation disallowed (the declared-proxy topology) —
    # ceremonies fail closed with the shared notice on every surface, never a redirect loop.
    pytest.importorskip("webauthn")
    # BACKLOG #1361: PINNED AGAINST THE RELOCATION MAP, NOT A REMEMBERED LITERAL. `[api].public_origin`
    # is the INTERNAL field this code reads; ADR 0118 relocated the OPERATOR-FACING key and
    # `_reject_relocated_keys` REFUSES the old spelling as file or env input, so a notice naming it
    # hands the operator a remediation that dies at load. Asserting some literal here would pass just
    # as well after the next relocation moved the key again -- the notice and the loader would drift
    # apart silently, which is the defect the pin exists to stop. Same shape, and the same reasoning,
    # as tests/test_api_tls.py::test_the_refusal_names_a_key_the_loader_actually_accepts.
    from messagefoundry.config.settings import _RELOCATED_TO_SECURITY

    # The SECTION is part of the remediation: "[api].web_console_public_address" is the right key in a
    # section the loader still refuses, and a bare-key assertion would pass on it. So pin the spelling an
    # operator can actually paste into messagefoundry.toml.
    expected_key = f"[security].{_RELOCATED_TO_SECURITY[('api', 'public_origin')]}"
    service = await _service(engine)
    await _add(service, "boss", Role.ADMINISTRATOR)
    transport = httpx.ASGITransport(
        app=create_app(engine, auth=service, serve_ui=True, webauthn_rp_from_request=False)
    )
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        await _cookie_login(c, "boss")
        r = await c.get("/ui/account")
        assert expected_key in r.text
        # The OLD spelling must be ABSENT, so a revert reds HERE -- on the rendered page a user
        # actually reads -- and not only in the #1361 static census.
        assert "[api].public_origin" not in r.text
        await _mint_action(c, "/ui/account/webauthn/enroll")  # 7.5.1: enroll is action-bound
        r = await c.post("/ui/account/webauthn/enroll", headers=_SFS)
        assert r.status_code == 409 and expected_key in r.text
        assert "[api].public_origin" not in r.text
        r = await c.post("/ui/reauth/webauthn", json={"response": {}}, headers=_SFS)
        assert r.status_code == 409 and r.json()["error"] == "rp_unavailable"


async def test_webauthn_extra_less_renders_notice(engine: Engine, monkeypatch) -> None:
    # AC-16 (page half): the account page renders the extra-missing notice instead of the Add
    # form — a legible message, never a crash or a loop. (The startup advisory is PR-B.)
    service = await _service(engine)
    monkeypatch.setattr(type(service), "webauthn_available", lambda self: False)
    async with _boss_client(engine, service) as c:
        r = await c.get("/ui/account")
        assert r.status_code == 200
        assert "[webauthn] extra is not installed" in r.text
        assert 'action="/ui/account/webauthn/enroll"' not in r.text


async def test_webauthn_malformed_ceremony_responses_are_400_not_500(engine: Engine) -> None:
    # PR-A review HIGH regression: py_webauthn raises WebAuthnException SIBLINGS of the two leaf
    # Invalid*Response classes (InvalidJSONStructure/InvalidCBORData/...) for structurally-
    # malformed browser input — every one must land on the audited 400 path, never a 500.
    pytest.importorskip("webauthn")
    service = await _service(engine)
    async with _boss_client(engine, service) as c:
        # Registration leg: stage a real ceremony, then post structurally-broken responses.
        await _mint_action(c, "/ui/account/webauthn/enroll")  # 7.5.1: enroll is action-bound
        r = await c.post("/ui/account/webauthn/enroll", headers=_SFS)
        assert r.status_code == 200
        for bad in ({}, "just a string", {"rawId": "AQID"}):
            r = await c.post(
                "/ui/account/webauthn/verify",
                json={"label": "mykey", "response": bad},
                headers=_SFS,
            )
            assert r.status_code == 400, (bad, r.status_code, r.text)
            assert r.json()["ok"] is False

        # Assertion leg: enroll for real, then pair the KNOWN credential id with a broken body.
        auth = await _browser_enroll(c, label="real key")
        await _cookie_login(c, "boss")  # fresh MFA-pending session
        r = await c.post(
            "/ui/reauth/webauthn",
            json={
                "response": {
                    "id": auth.credential_id_b64,
                    "rawId": auth.credential_id_b64,
                    "type": "public-key",
                    "response": {},
                }
            },
            headers=_SFS,
        )
        assert r.status_code == 400 and r.json()["ok"] is False
        events = [e["action"] for e in await service.security_events_for("boss")]
        assert "auth.webauthn_failed" in events  # audited, not a silent 500


async def test_reauth_rp_migrated_credentials_render_legible_notice(engine: Engine) -> None:
    # PR-A review MEDIUM regression: a WebAuthn-only user whose credentials were all minted under
    # a DIFFERENT rp_id (origin migration) must see the rp-changed notice at /ui/reauth — never a
    # bare password form plus a misleading "complete the passkey prompt" error.
    pytest.importorskip("webauthn")
    service = await _service(engine)
    async with _boss_client(engine, service) as c:
        await _browser_enroll(c, label="old key")
        # Simulate the origin migration white-box: re-pin the credential to the old rp.
        await engine.store._db.execute(  # noqa: SLF001
            "UPDATE webauthn_credentials SET rp_id='old.example'"
        )
        await engine.store._db.commit()  # noqa: SLF001

        await _cookie_login(c, "boss")  # fresh MFA-pending session
        boss_id = await _uid(service, "boss")
        creds = await service.store.list_webauthn_credentials(boss_id)
        delete_path = f"/ui/account/webauthn/{creds[0].credential_id_hash}/delete"
        r = await c.get("/ui/reauth?next=" + quote(delete_path, safe=""))
        assert r.status_code == 200
        assert "enrolled under a different origin" in r.text
        assert "data-mf-webauthn-get" not in r.text
        # The (d)-guard's error copy matches the notice — not "complete the passkey prompt".
        r = await c.post("/ui/reauth", data={"next": delete_path, "password": PW}, headers=_SFS)
        assert r.status_code == 400
        assert "enrolled under a different origin" in r.text
        assert "Complete the passkey prompt" not in r.text


async def test_reauth_extra_less_with_credentials_renders_notice(
    engine: Engine, monkeypatch
) -> None:
    # AC-16 (reauth half): enrolled credentials + the [webauthn] extra absent — the reauth page
    # renders the extra-missing notice (a legible dead-end), never a loop or a bare form.
    from messagefoundry.store.store import WebAuthnCredential

    service = await _service(engine)
    await _add(service, "boss", Role.ADMINISTRATOR)
    boss_id = await _uid(service, "boss")
    await service.store.add_webauthn_credential(
        WebAuthnCredential(
            credential_id_hash="h1",
            credential_id="AQID",
            user_id=boss_id,
            rp_id="t",
            public_key="cose",
            sign_count=0,
            transports=None,
            device_type="multi_device",
            backed_up=False,
            label="stranded key",
            aaguid=None,
            created_at=1.0,
        )
    )
    monkeypatch.setattr(type(service), "webauthn_available", lambda self: False)
    async with _client(engine, service) as c:
        await _cookie_login(c, "boss")
        creds = await service.store.list_webauthn_credentials(boss_id)
        delete_path = f"/ui/account/webauthn/{creds[0].credential_id_hash}/delete"
        r = await c.get("/ui/reauth?next=" + quote(delete_path, safe=""))
        assert r.status_code == 200
        assert "[webauthn] extra is not installed" in r.text
        assert "data-mf-webauthn-get" not in r.text


# --- L5b: off-loopback hardening + AD-password browser login (ADR 0068 §8/§10), #75 phase 4 --------


def _ad_service(engine: Engine) -> AuthService:
    """An AuthService with a duck-typed fake directory (the _FakeLdap pattern)."""
    from messagefoundry.auth.ldap import AdPrincipal, DirectoryAnswer, DirectoryBind

    principal = AdPrincipal(
        username="jdoe",
        display_name="J Doe",
        email="j@x",
        dn="CN=jdoe,DC=x",
        groups=frozenset({"cn=mf-admins,dc=x"}),
        directory_object_id="75920276-799f-51a3-9e67-4e4b9c43fd0c",
    )

    class _FakeLdap:
        def authenticate(self, username: str, password: str, **_: object) -> DirectoryBind:
            if username != "jdoe":
                return DirectoryBind(DirectoryAnswer.NOT_FOUND)
            return DirectoryBind(DirectoryAnswer.FOUND, principal if password == "pw" else None)

        def resolve_principal(self, username: str, **_: object) -> AdPrincipal | None:
            return principal if username == "jdoe" else None

    settings = AuthSettings(
        ad_enabled=True,
        ad_server="ldaps://x",
        ad_user_search_base="DC=x",
        ad_bind_dn="CN=svc,DC=x",
        ad_bind_password="x",
    )
    return AuthService(engine.store, settings, ldap=_FakeLdap())  # type: ignore[arg-type]


async def test_login_offers_no_ad_provider_even_with_a_live_directory(engine: Engine) -> None:
    """The sign-in form never offers Active Directory (BACKLOG #1137).

    The simple-bind login pathway is retired, so the engine refuses a directory password. Rendering
    the option anyway would advertise a route that can only produce a refusal -- worse than absent,
    because it tells the operator the route exists.

    The AD-configured service is the load-bearing half: a directory BIND is still live (Kerberos,
    OIDC and the step-up re-bind all need it), and the selector must stay absent anyway. That is
    exactly what regressed once -- a getattr fallback fell through to the bind flag and re-rendered
    the form after the pathway was removed.
    """
    service = await _service(engine)
    async with _client(engine, service) as c:
        r = await c.get("/ui/login")
        assert 'name="provider"' not in r.text
        assert "Active Directory" not in r.text
        assert 'name="username"' in r.text  # CONTROL: the form itself rendered

    ad = _ad_service(engine)
    await ad.initialize()
    async with _client(engine, ad) as c:
        r = await c.get("/ui/login")
        assert 'name="provider"' not in r.text
        assert "Active Directory" not in r.text
        assert 'name="username"' in r.text  # CONTROL: still a real login page


async def test_ad_password_browser_login_is_refused(engine: Engine) -> None:
    """A hand-posted provider=ad is refused at the browser surface too (BACKLOG #1137).

    The form no longer offers the option, but removing an affordance is not a control -- anyone can
    post the field. The refusal must come from the ENGINE, which is why the console's provider
    allow-list was deliberately left alone: one refusal point, not two that can drift.

    The bounce is the ordinary bad-credentials landing rather than a distinct "retired" page, on
    purpose: a browser surface that distinguishes them tells an unauthenticated caller which
    directory names exist.
    """
    ad = _ad_service(engine)
    await ad.initialize()
    async with _client(engine, ad) as c:
        r = await c.post("/ui/login", data={"username": "jdoe", "password": "pw", "provider": "ad"})
        assert r.status_code == 303 and r.headers["location"] == "/ui/login?e=bad"
        # And no session was minted -- the refusal is not a redirect over a live cookie.
        r = await c.get("/ui/account")
        assert r.status_code in (302, 303) or "Signed in as" not in r.text

    # CONTROL: the directory this service talks to is LIVE. Without it the refusal above would pass
    # on a service with no directory at all, which proves nothing about the pathway being retired.
    # ad_enabled is the BIND capability and it deliberately survives the retirement -- Kerberos,
    # OIDC and the step-up re-bind all still need it.
    assert ad.ad_enabled is True


async def test_login_provider_allowlist(engine: Engine) -> None:
    # Garbage provider values bounce (never reach auth.login); ABSENT stays LOCAL (the regression
    # pin for every existing form in the wild).
    service = await _service(engine)
    await _add(service, "boss", Role.ADMINISTRATOR)
    async with _client(engine, service) as c:
        r = await c.post(
            "/ui/login", data={"username": "boss", "password": PW, "provider": "kerberos"}
        )
        assert r.status_code == 303 and r.headers["location"] == "/ui/login?e=bad"
        r = await c.post("/ui/login", data={"username": "boss", "password": PW})
        assert r.status_code == 303 and r.headers["location"] == "/ui"


async def test_forced_secure_cookie_and_hsts_when_protected(engine: Engine) -> None:
    # AC-12 (ADR 0068 §8): exposure_protected forces Secure + HSTS regardless of the
    # per-request scheme. SINGLE-RESPONSE assertions by convention — httpx's jar refuses to SEND
    # a Secure cookie back over http://, so no follow-on navigation here (design Part 5).
    service = await _service(engine)
    await _add(service, "boss", Role.ADMINISTRATOR)
    transport = httpx.ASGITransport(
        app=create_app(engine, auth=service, serve_ui=True, exposure_protected=True)
    )
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        r = await c.post("/ui/login", data={"username": "boss", "password": PW})
        assert r.status_code == 303
        set_cookie = r.headers["set-cookie"]
        assert "Secure" in set_cookie and "HttpOnly" in set_cookie
        assert "Strict-Transport-Security" in r.headers
    # The plain-loopback halves (no Secure, no HSTS over http) stay pinned by the existing
    # login-cookie test — extend-never-weaken.


async def test_xfp_tripwire_fires_once(engine: Engine, caplog: pytest.LogCaptureFixture) -> None:
    # ADR 0068 §8: a /ui request arriving scheme=http while an upstream terminator is DECLARED
    # trips exactly ONE warning naming both causes (XFP missing / peer not trusted).
    import logging

    service = await _service(engine)
    transport = httpx.ASGITransport(
        app=create_app(
            engine,
            auth=service,
            serve_ui=True,
            exposure_protected=True,
            tls_terminated_upstream=True,
        )
    )
    with caplog.at_level(logging.WARNING, logger="messagefoundry.api.app"):
        async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
            await c.get("/ui/login")
            await c.get("/ui/login")
    hits = [r for r in caplog.records if "X-Forwarded-Proto" in r.getMessage()]
    assert len(hits) == 1
    assert "trusted_proxies" in hits[0].getMessage()


async def test_proxy_headers_middleware_rewrites_scheme_and_client() -> None:
    # fill1's named blind spot: drive uvicorn's ProxyHeadersMiddleware DIRECTLY as an ASGI
    # callable with hand-built http AND websocket scopes — trusted peer rewrites scheme+client,
    # untrusted peer and an empty trust list rewrite NOTHING. No live server, no WS client.
    from uvicorn.middleware.proxy_headers import ProxyHeadersMiddleware

    seen: list[dict] = []

    async def inner(scope, receive, send):  # type: ignore[no-untyped-def]
        seen.append(dict(scope))

    async def _drive(mw, scope) -> None:  # type: ignore[no-untyped-def]
        async def _recv():  # type: ignore[no-untyped-def]
            return {"type": "http.request"}

        async def _send(_msg):  # type: ignore[no-untyped-def]
            return None

        await mw(scope, _recv, _send)

    def _scope(kind: str, client_ip: str, *, xfp: bool) -> dict:
        headers = [(b"host", b"t")]
        if xfp:
            headers += [(b"x-forwarded-proto", b"https"), (b"x-forwarded-for", b"203.0.113.9")]
        return {
            "type": kind,
            "scheme": "http" if kind == "http" else "ws",
            "client": (client_ip, 12345),
            "headers": headers,
            "path": "/ui",
            "method": "GET",
        }

    trusted = ProxyHeadersMiddleware(inner, trusted_hosts="10.0.0.2")
    await _drive(trusted, _scope("http", "10.0.0.2", xfp=True))
    assert seen[-1]["scheme"] == "https" and seen[-1]["client"][0] == "203.0.113.9"
    await _drive(trusted, _scope("websocket", "10.0.0.2", xfp=True))
    assert seen[-1]["scheme"] == "wss" and seen[-1]["client"][0] == "203.0.113.9"
    # Untrusted peer: headers ignored (spoofing defense).
    await _drive(trusted, _scope("http", "192.0.2.1", xfp=True))
    assert seen[-1]["scheme"] == "http" and seen[-1]["client"][0] == "192.0.2.1"
    # The default posture trap (fill1): trusted_proxies=[] is an installed NO-OP.
    noop = ProxyHeadersMiddleware(inner, trusted_hosts=[])
    await _drive(noop, _scope("http", "10.0.0.2", xfp=True))
    assert seen[-1]["scheme"] == "http" and seen[-1]["client"][0] == "10.0.0.2"


# --- L5c: browser Kerberos SSO (GET /ui/sso, ADR 0068 §9), #75 phase 4 -----------------------------
#
# Mock-seam coverage only (no AD exists in any test infra — same confidence tier as the JSON
# sibling): kerberos_principal is monkeypatched on messagefoundry.auth.service (import-by-name —
# patching auth.ldap does NOT take), the directory via the duck-typed _FakeLdap. Kerberos-only
# SINGLE-LEG is a hard line: any failure is an audited 303 to e=sso_failed, never a second 401.


def _sso_service(engine: Engine) -> AuthService:
    from messagefoundry.auth.ldap import AdPrincipal, DirectoryAnswer, DirectoryBind

    principal = AdPrincipal(
        username="jdoe",
        display_name="J Doe",
        email="j@x",
        dn="CN=jdoe,DC=x",
        groups=frozenset({"cn=mf-admins,dc=x"}),
        directory_object_id="75920276-799f-51a3-9e67-4e4b9c43fd0c",
    )

    class _FakeLdap:
        def authenticate(self, username: str, password: str, **_: object) -> DirectoryBind:
            if username != "jdoe":
                return DirectoryBind(DirectoryAnswer.NOT_FOUND)
            return DirectoryBind(DirectoryAnswer.FOUND, principal if password == "pw" else None)

        def resolve_principal(self, username: str, **_: object) -> AdPrincipal | None:
            return principal if username == "jdoe" else None

    settings = AuthSettings(
        ad_enabled=True,
        kerberos_enabled=True,
        ad_server="ldaps://x",
        ad_user_search_base="DC=x",
        ad_bind_dn="CN=svc,DC=x",
        ad_bind_password="x",
    )
    return AuthService(engine.store, settings, ldap=_FakeLdap())  # type: ignore[arg-type]


def _negotiate_headers() -> dict[str, str]:
    import base64 as _b64

    return {"Authorization": "Negotiate " + _b64.b64encode(b"spnego-token").decode()}


async def _kerberos_audits(engine: Engine) -> list[str]:
    audit = await engine.store.list_audit()
    return [
        str(a["detail"])
        for a in audit  # login_failed = mocked rejects, and a token the REAL pyspnego path refused
        # (BACKLOG #3196; the JSON /auth/negotiate unchanged-endpoint pin runs it live, and SSPI
        # rejects the fake token); login_error = a directory fault, or an acceptor that could not
        # be built from settings.
        if a["action"] in ("auth.login_failed", "auth.login_error") and a["detail"]
    ]


async def test_sso_challenge_and_single_leg_failure(
    engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    # AC-13: the challenge leg is 401 + WWW-Authenticate: Negotiate and NEVER consumes a
    # rate-limit slot; a failed token-validation is an audited 303 e=sso_failed — no 401 loop.
    service = _sso_service(engine)
    await service.initialize()
    async with _client(engine, service) as c:
        for _ in range(30):  # far past the login limiter window — challenges are unthrottled
            r = await c.get("/ui/sso")
            assert r.status_code == 401
            assert r.headers["www-authenticate"] == "Negotiate"
            assert "Sign in with a password instead" in r.text
        # An unknown principal fails the single leg: audited + 303, never a second challenge.
        monkeypatch.setattr(
            "messagefoundry.auth.service.kerberos_principal", lambda t, s: "stranger"
        )
        r = await c.get("/ui/sso", headers=_negotiate_headers())
        assert r.status_code == 303 and r.headers["location"] == "/ui/login?e=sso_failed"
        assert any("not_in_directory" in d for d in await _kerberos_audits(engine))
        # Malformed base64 in the header: audited reject, same shape.
        r = await c.get("/ui/sso", headers={"Authorization": "Negotiate !!!not-base64!!!"})
        assert r.status_code == 303 and r.headers["location"] == "/ui/login?e=sso_failed"
        assert any("malformed_token" in d for d in await _kerberos_audits(engine))


async def test_sso_success_mints_one_cookie_session(
    engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    service = _sso_service(engine)
    await service.initialize()
    monkeypatch.setattr("messagefoundry.auth.service.kerberos_principal", lambda t, s: "jdoe")
    async with _client(engine, service) as c:
        r = await c.get("/ui/sso", headers=_negotiate_headers())
        assert r.status_code == 303 and r.headers["location"] == "/ui"
        assert "mf_session" in r.headers.get("set-cookie", "")
        sessions = await service.store.list_sessions(
            (await service.store.get_user_by_username("jdoe")).id
        )
        assert len(sessions) == 1  # ONE session per navigation into the route
        r = await c.get("/ui/account")
        assert r.status_code == 200 and "Signed in as jdoe (ad)" in r.text
        # BACKLOG #1144: the enrolment surface is REACHABLE for a directory account. The Kerberos leg
        # mints MFA-pending, and /ui/account is MFA-pending-exempt, so this page is where such a user
        # lands and where the confinement has to be survivable. The page used to say "AD accounts use
        # directory MFA, not an engine TOTP" and offer nothing.
        assert 'action="/ui/account/mfa/enroll"' in r.text
        assert "Add a passkey" in r.text
        # Still directory-gated, and correctly so: there is no engine password to change.
        assert 'href="/ui/account/password"' not in r.text


async def test_sso_session_not_reauth_seeded(
    engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    # AC-14: the SSO proof is AMBIENT — the session is born WITHOUT a step-up window (a step_up
    # action 303s to /ui/reauth), and the directory-password reauth then completes it. BACKLOG
    # #1144 step 5 closed the recorded asymmetry: the JSON /auth/negotiate leg is born the same way.
    from messagefoundry.auth.tokens import hash_token

    service = _sso_service(engine)
    await service.initialize()
    monkeypatch.setattr("messagefoundry.auth.service.kerberos_principal", lambda t, s: "jdoe")
    async with _client(engine, service) as c:
        r = await c.get("/ui/sso", headers=_negotiate_headers())
        assert r.status_code == 303
        jdoe = await service.store.get_user_by_username("jdoe")
        sessions = await service.store.list_sessions(jdoe.id)
        assert sessions[0].reauth_at is None  # seed_reauth=False (ADR 0068 §9)
        # BACKLOG #1144: the ticket asserts no factor strength the engine can read, so the leg grants
        # nothing and the session is born MFA-pending. This assertion used to read `is not None`,
        # under the delegated-directory relaxation that is now retired. The two stamps are
        # INDEPENDENT and both must be pinned: reauth_at is the step-up window (ADR 0068 s9; since
        # BACKLOG #1144 step 5 the engine withholds it on every directory login), mfa_verified_at
        # is the second-factor grant.
        assert sessions[0].mfa_verified_at is None

        # The step_up action 303s to /ui/reauth, issuing its continuation (vault BACKLOG #2764).
        r = await c.post("/ui/account/webauthn/enroll", headers=_SFS)
        assert r.headers["location"] == "/ui/reauth?next=/ui/account/webauthn/enroll"
        # The directory-password step-up completes at /ui/reauth (auth.reauth live-rebinds AD).
        r = await c.post(
            "/ui/reauth",
            data={"next": "/ui/account/webauthn/enroll", "password": "pw"},
            headers=_SFS,
        )
        assert r.status_code == 200 and 'action="/ui/account/webauthn/enroll"' in r.text

    # The asymmetry this used to pin is GONE (BACKLOG #1144 step 5). AD-password login is retired
    # (BACKLOG #1137). The JSON negotiate route called authenticate_kerberos with no seeding
    # argument and took the default True, while /ui/sso passed False. The method takes no such
    # argument now, so this bare call is exactly what that route makes, and it must be born with
    # no window. The ROUTE itself is driven in tests/test_directory_login_step_up_seed.py.
    out = await service.login("jdoe", "pw", provider=AuthProvider.AD)
    assert out.ok is False and out.token is None  # the retired pathway, refused

    out = await service.authenticate_kerberos(b"tok")
    assert out.ok and out.token is not None
    session = await service.store.get_session(hash_token(out.token))
    assert session is not None and session.reauth_at is None
    # The grant is the same on BOTH Kerberos legs, and so is the seeding now (BACKLOG #1144).
    assert session.mfa_verified_at is None


async def test_sso_cross_site_hygiene(engine: Engine, monkeypatch: pytest.MonkeyPatch) -> None:
    # A non-navigation fetch on the token leg is drive-by ambient-auth probing: rejected AND
    # audited (AUTH-K-AUDIT). A cross-site TOP-LEVEL navigation is allowed (intranet links).
    service = _sso_service(engine)
    await service.initialize()
    monkeypatch.setattr("messagefoundry.auth.service.kerberos_principal", lambda t, s: "jdoe")
    async with _client(engine, service) as c:
        r = await c.get("/ui/sso", headers={**_negotiate_headers(), "Sec-Fetch-Mode": "cors"})
        assert r.status_code == 303 and r.headers["location"] == "/ui/login?e=sso_failed"
        assert any("non_navigation_fetch" in d for d in await _kerberos_audits(engine))
        r = await c.get(
            "/ui/sso",
            headers={
                **_negotiate_headers(),
                "Sec-Fetch-Mode": "navigate",
                "Sec-Fetch-Site": "cross-site",
                # A real browser sends this on a top-level navigation; #1122 made the middleware's
                # destination check an allowlist, so omitting it here would 403 at the middleware
                # and this test would stop exercising the SSO leg it is named for.
                "Sec-Fetch-Dest": "document",
            },
        )
        assert r.status_code == 303 and r.headers["location"] == "/ui"


async def test_sso_rate_limits_token_leg_only(
    engine: Engine, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    # The limiter runs FIRST on the token leg (review fix): exhaustion is a _log.warning, NOT an
    # audit — an attacker looping token requests can't amplify into unbounded audit_log growth
    # (parity with the JSON _rate_limited anti-flood posture).
    import logging

    service = AuthService(
        engine.store,
        AuthSettings(
            ad_enabled=True,
            kerberos_enabled=True,
            ad_server="ldaps://x",
            ad_user_search_base="DC=x",
            ad_bind_dn="CN=svc,DC=x",
            ad_bind_password="x",
            login_rate_limit_per_ip=2,
        ),
        ldap=object(),  # type: ignore[arg-type]  # never reached: the limiter fires first
    )
    await service.initialize()
    monkeypatch.setattr("messagefoundry.auth.service.kerberos_principal", lambda t, s: None)
    async with _client(engine, service) as c:
        for _ in range(2):
            await c.get("/ui/sso", headers=_negotiate_headers())
        audits_before = len(await _kerberos_audits(engine))
        with caplog.at_level(logging.WARNING, logger="messagefoundry.api.app"):
            r = await c.get("/ui/sso", headers=_negotiate_headers())
        assert r.status_code == 303 and r.headers["location"] == "/ui/login?e=rate_limited"
        assert any("SSO rate limit exceeded" in rec.getMessage() for rec in caplog.records)
        # No audit row was written by the throttle — the anti-flood invariant.
        assert len(await _kerberos_audits(engine)) == audits_before
        # The challenge leg still answers 401 (unthrottled) even while the limiter is exhausted.
        r = await c.get("/ui/sso")
        assert r.status_code == 401


async def test_kerberos_preflight_requires_capable_provider(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Review LOW: the boot preflight must mark SSO unavailable on a host whose only SPNEGO provider
    # is the pure-Python NTLM fallback (no Kerberos) — otherwise a Linux-without-gssapi install
    # advertises a dead SSO link. _kerberos_capable fails OPEN if it can't introspect.
    from messagefoundry.auth import ldap as ldap_mod

    monkeypatch.setattr(ldap_mod, "_kerberos_capable", lambda: False)
    settings = AuthSettings(
        ad_enabled=True,
        kerberos_enabled=True,
        ad_server="ldaps://x",
        ad_user_search_base="DC=x",
        ad_bind_dn="CN=svc,DC=x",
        ad_bind_password="x",
    )
    with pytest.raises(ldap_mod.LdapError, match="Kerberos-capable"):
        ldap_mod.kerberos_acceptor_preflight(settings)


async def test_sso_unavailable_states(engine: Engine) -> None:
    # kerberos disabled -> e=sso_unavailable and the login page hides the SSO link; a degraded
    # boot preflight (mark_kerberos_unavailable) flips providers/link/route the same way while
    # the JSON /auth/negotiate still attempts-and-audits per-request (the unchanged-endpoint pin).
    plain = await _service(engine)
    async with _client(engine, plain) as c:
        r = await c.get("/ui/sso")
        assert r.status_code == 303 and r.headers["location"] == "/ui/login?e=sso_unavailable"
        assert "Sign in with Windows" not in (await c.get("/ui/login")).text

    sso = _sso_service(engine)
    await sso.initialize()
    async with _client(engine, sso) as c:
        assert "Sign in with Windows" in (await c.get("/ui/login")).text
        assert (await c.get("/auth/providers")).json()["kerberos"] is True
        sso.mark_kerberos_unavailable("no keytab")
        assert (await c.get("/auth/providers")).json()["kerberos"] is False
        assert "Sign in with Windows" not in (await c.get("/ui/login")).text
        r = await c.get("/ui/sso", headers=_negotiate_headers())
        assert r.status_code == 303 and r.headers["location"] == "/ui/login?e=sso_unavailable"
        # The JSON endpoint is UNCHANGED: it still attempts per-request and audits its reject.
        before = len(await _kerberos_audits(engine))
        r = await c.post("/auth/negotiate", headers=_negotiate_headers())
        assert r.status_code in (400, 401)
        assert len(await _kerberos_audits(engine)) > before


# --- L6b: web-console parity closeout (#75) — session mgmt, replay-all, event-kind, update, reset ---
#
# Five small server-rendered additions closing the verified desktop-vs-web parity gaps. Each reuses
# an existing JSON handler; no new backend. Page-builder tests where a builder carries the logic,
# route tests where the wiring/RBAC/step-up is the point.


# Gap 1 — self-service session management -----------------------------------------------------------


async def test_account_links_to_sessions(engine: Engine) -> None:
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    async with _client(engine, service) as c:
        await _cookie_login(c, "op")
        r = await c.get("/ui/account")
        assert 'href="/ui/account/sessions"' in r.text


async def test_sessions_page_lists_and_flags_current(engine: Engine) -> None:
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    # A second, separate login → a second session for the same user.
    other = await service.login("op", PW)
    assert other.ok
    async with _client(engine, service) as c:
        await _cookie_login(c, "op")
        op_id = await _uid(service, "op")
        assert len(await service.store.list_sessions(op_id)) == 2
        r = await c.get("/ui/account/sessions")
        assert r.status_code == 200
        assert "Active sessions" in r.text
        assert "(this session)" in r.text  # the current cookie session is flagged
        assert "Sign out everywhere else (1)" in r.text  # one OTHER session
        # The nav highlights "My account" (active= is on page(), not the wrapper div).
        assert '<a href="/ui/account" class="active"' in r.text
        assert "<div active=" not in r.text


async def test_sessions_page_flags_current_in_constant_time(
    engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    """ASVS 11.2.4 (BACKLOG #1167). RED when: the sessions page goes back to
    `s.token_hash == current`. Every listed session is compared through the helper, and exactly one
    (the cookie's own) matches."""
    from messagefoundry.credential import constant_time_equal as real
    from messagefoundry_webconsole.routes import account as account_routes

    results: list[bool] = []

    def spy(a: str | bytes, b: str | bytes) -> bool:
        results.append(real(a, b))
        return results[-1]

    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    assert (await service.login("op", PW)).ok  # a second session, which must not match
    async with _client(engine, service) as c:
        await _cookie_login(c, "op")
        monkeypatch.setattr(account_routes, "constant_time_equal", spy)
        r = await c.get("/ui/account/sessions")
        assert r.status_code == 200
        assert r.text.count("(this session)") == 1
    assert sorted(results) == [False, True]


async def test_sessions_revoke_others(engine: Engine) -> None:
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    await service.login("op", PW)  # a second session to be signed out
    async with _client(engine, service) as c:
        await _cookie_login(c, "op")
        op_id = await _uid(service, "op")
        assert len(await service.store.list_sessions(op_id)) == 2
        # BACKLOG #1149 (ASVS 7.5.2): the login window no longer unlocks a terminate, so the
        # freshly-logged-in POST bounces to /ui/reauth and revokes NOTHING. That bounce is the
        # console half of the defect this item closes -- it used to succeed here.
        bounced = await c.post(
            "/ui/account/sessions/revoke-others", headers={"Sec-Fetch-Site": "same-origin"}
        )
        assert bounced.status_code == 303
        assert bounced.headers["location"] == "/ui/reauth?next=/ui/account/sessions/revoke-others"
        assert len(await service.store.list_sessions(op_id)) == 2  # nothing signed out yet
        await _mint_action(c, "/ui/account/sessions/revoke-others")
        r = await c.post(
            "/ui/account/sessions/revoke-others", headers={"Sec-Fetch-Site": "same-origin"}
        )
        assert r.status_code == 303
        assert r.headers["location"] == "/ui/account/sessions?m=signed_out_others"
        # Only the caller's current session survives.
        assert len(await service.store.list_sessions(op_id)) == 1
        # And the current session still works (was NOT revoked).
        assert (await c.get("/ui/account/sessions")).status_code == 200


async def test_sessions_revoke_one(engine: Engine) -> None:
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    other = await service.login("op", PW)
    async with _client(engine, service) as c:
        await _cookie_login(c, "op")
        op_id = await _uid(service, "op")
        other_id = hash_token(other.token or "")
        # BACKLOG #1149: same inversion as revoke-others -- a fresh login is no longer a terminate
        # grant, so this bounces first and the target session survives it.
        path = f"/ui/account/sessions/{other_id}/revoke"
        bounced = await c.post(path, headers={"Sec-Fetch-Site": "same-origin"})
        assert bounced.status_code == 303
        assert bounced.headers["location"] == f"/ui/reauth?next={path}"
        assert other_id in {s.token_hash for s in await service.store.list_sessions(op_id)}
        await _mint_action(c, path)
        r = await c.post(path, headers={"Sec-Fetch-Site": "same-origin"})
        assert r.status_code == 303 and r.headers["location"] == "/ui/account/sessions?m=revoked"
        remaining = {s.token_hash for s in await service.store.list_sessions(op_id)}
        assert other_id not in remaining and len(remaining) == 1


async def test_sessions_posts_reject_cross_site(engine: Engine) -> None:
    service = await _service(engine)
    async with _boss_client(engine, service) as c:
        for path in ("/ui/account/sessions/x/revoke", "/ui/account/sessions/revoke-others"):
            # BACKLOG #1149: the action gate now runs BEFORE assert_same_origin, so without a grant
            # this would 303 to reauth and the assertion below would be measuring the STEP-UP rather
            # than the CSRF defence it is named for. Mint the grant first so the origin guard is the
            # thing actually under test -- the same shadowing the JSON ownership-404 test had to
            # avoid. A cross-site POST must be refused outright, never bounced to a login form.
            await _mint_action(c, path)
            r = await c.post(path, headers={"Sec-Fetch-Site": "cross-site"})
            assert r.status_code == 403, path
