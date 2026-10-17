# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""/ui message edit and resubmit, and dead-letter bulk replay (ADR 0065 / BACKLOG #75)."""

from __future__ import annotations

import json
from pathlib import Path

from _webui_support import (
    ADT,
    EDITED,
    XSS_RAW,
    _add,
    _add_with_role_ids,
    _client,
    _cookie_login,
    _mint_action,
    _seed,
    _service,
)

from messagefoundry.auth import Role
from messagefoundry.auth.service import AuthService
from messagefoundry.config.models import ConnectorType
from messagefoundry.config.settings import AuthSettings, EgressSettings
from messagefoundry.config.wiring import (
    ConnectionSpec,
    InboundConnection,
    OutboundConnection,
    Registry,
    Send,
)
from messagefoundry.pipeline import Engine

# --- UI-12: message edit & resubmit -------------------------------------------
#
# The engine JSON route + the STORE invariants (byte-identical origin, correlated child, idempotent
# once-only, direct OB2 rows, the PHI-safe 422 no-echo) are covered engine-side in
# tests/test_edit_resend.py. What is exercised HERE is the DISTINCT /ui glue that is otherwise
# uncovered: the GET editor PAGE markup (a COPY textarea + Modified badge + Revert + data-original),
# the form-POST mode routing (reroute → 303 to the child, direct → 303 back to the origin), the
# stale-step-up reauth_next that points a body-carrying POST at the /edit FORM (never the POST path),
# the MESSAGES_EDIT + MESSAGES_VIEW_RAW gate and its per-actor PHI-read budget (BACKLOG #324, both
# verbs), same-origin CSRF defense, cookie-confinement, and the generic 400 reject
# that never leaks pydantic's structured echo. The /ui routes mount on the real engine app
# (create_app(serve_ui=True)) and call the shared "core" handlers in-process over an ASGI transport.


async def test_message_edit_page_renders_copy_editor(engine: Engine) -> None:
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    mid = await _seed(engine)
    async with _client(engine, service) as c:
        await _cookie_login(c, "op")  # a fresh login counts as a recent step-up
        await _mint_action(c, f"/ui/messages/{mid}/edit")  # vault BACKLOG #2625
        r = await c.get(f"/ui/messages/{mid}/edit")
        assert r.status_code == 200
        body = r.text
        # The editable COPY textarea + its pristine-copy attribute (for the client-side Revert).
        assert 'id="edit-raw"' in body
        assert "data-original=" in body
        # The "Modified" badge (revealed by app.js once the copy diverges) starts hidden.
        assert 'id="edit-modified" class="badge-modified" hidden' in body
        assert "Modified" in body
        # Revert starts disabled (nothing to revert on a pristine copy).
        assert 'id="edit-revert" disabled' in body
        # The banner states this is a COPY — the original log entry is never mutated.
        assert "You are editing a COPY" in body
        # The form POSTs the edit to the resubmit route and carries a per-open idempotency token.
        assert f'action="/ui/messages/{mid}/edit-resend"' in body
        assert 'name="idempotency_key"' in body


async def test_message_edit_page_escapes_xss(engine: Engine) -> None:
    # The textarea body + data-original attribute are attacker-influenced HL7 — they must render as
    # escaped text, never live markup.
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    mid = await _seed(engine, raw=XSS_RAW, control_id="X1")
    async with _client(engine, service) as c:
        await _cookie_login(c, "op")
        await _mint_action(c, f"/ui/messages/{mid}/edit")  # vault BACKLOG #2625
        r = await c.get(f"/ui/messages/{mid}/edit")
        assert r.status_code == 200
        assert "<script>alert(1)</script>" not in r.text
        assert "&lt;script&gt;alert(1)&lt;/script&gt;" in r.text


async def test_message_edit_requires_edit_permission(engine: Engine) -> None:
    # A viewer holds MESSAGES_READ but not MESSAGES_EDIT — the editor is refused before any step-up.
    service = await _service(engine)
    await _add(service, "viewer", Role.VIEWER)
    mid = await _seed(engine)
    async with _client(engine, service) as c:
        await _cookie_login(c, "viewer")
        r = await c.get(f"/ui/messages/{mid}/edit")
        assert r.status_code == 403


# BACKLOG #324. The editor DISPLAYS the body it edits, so both verbs require MESSAGES_VIEW_RAW
# alongside MESSAGES_EDIT. The case above (a VIEWER) holds NEITHER and so cannot see the pair come
# apart; these four hold `messages:edit` WITHOUT `messages:view_raw` — the custom role that ADR 0045
# still permits — and pin the refusal, the positive control, and the PHI-read budget on both verbs.


async def test_edit_editor_refused_to_a_custom_role_without_view_raw(engine: Engine) -> None:
    service = await _service(engine)
    role = await service.create_custom_role(
        display_name="Resubmit Only",
        description=None,
        permissions=["messages:edit", "messages:read"],
        actor="test",
    )
    await _add_with_role_ids(service, "resubmitter", [role.id])
    mid = await _seed(engine)
    before = len(await engine.store.list_messages(limit=50, allowed_channels=None))
    async with _client(engine, service) as c:
        await _cookie_login(c, "resubmitter")  # a fresh login counts as a recent step-up
        r = await c.get(f"/ui/messages/{mid}/edit")
        assert r.status_code == 403
        # Not just the status: the seeded synthetic body and the pristine Revert copy must be absent.
        assert "DOE^JANE" not in r.text
        assert "data-original" not in r.text
        # The POST's REJECT arm re-renders the pristine stored body too, so it needs the same gate.
        # Sec-Fetch-Site is set deliberately: a 403 here can then only come from the permission gate,
        # never from assert_same_origin.
        r = await c.post(
            f"/ui/messages/{mid}/edit-resend",
            data={"raw": "", "idempotency_key": "k1", "mode": "reroute"},
            headers={"Sec-Fetch-Site": "same-origin"},
        )
        assert r.status_code == 403
        assert "DOE^JANE" not in r.text
        assert "data-original" not in r.text
    assert (
        len(await engine.store.list_messages(limit=50, allowed_channels=None)) == before
    )  # no child was minted


async def test_edit_editor_opens_for_a_custom_role_holding_both(engine: Engine) -> None:
    # Positive control: the fix must be a TIGHTENING, not a lockout. Without this, the refusal test
    # above passes just as well if the gate were broken to deny everyone.
    service = await _service(engine)
    role = await service.create_custom_role(
        display_name="Resubmit And Read",
        description=None,
        # view_summary too: minting refuses view_raw without it (vault BACKLOG #1187). This test is
        # about edit + view_raw, and the summary permission does not touch the editor's gate.
        permissions=[
            "messages:edit",
            "messages:view_raw",
            "messages:view_summary",
            "messages:read",
        ],
        actor="test",
    )
    await _add_with_role_ids(service, "editor", [role.id])
    mid = await _seed(engine)
    async with _client(engine, service) as c:
        await _cookie_login(c, "editor")
        await _mint_action(c, f"/ui/messages/{mid}/edit")  # vault BACKLOG #2625
        r = await c.get(f"/ui/messages/{mid}/edit")
        assert r.status_code == 200
        assert 'id="edit-raw"' in r.text


async def test_edit_editor_charges_the_phi_read_budget(engine: Engine) -> None:
    # The `phi=` thread through require_ui_step_up: this route puts a body on the wire, so it charges
    # the same per-actor anti-automation budget the sibling raw views do (WP-8, ASVS 2.4.1).
    service = AuthService(
        engine.store, AuthSettings(require_mfa=False, phi_read_rate_limit_per_actor=1)
    )
    await service.initialize()
    await _add(service, "op", Role.OPERATOR)
    mid = await _seed(engine)
    async with _client(engine, service) as c:
        await _cookie_login(c, "op")
        await _mint_action(c, f"/ui/messages/{mid}/edit")  # vault BACKLOG #2625
        assert (await c.get(f"/ui/messages/{mid}/edit")).status_code == 200
        r = await c.get(f"/ui/messages/{mid}/edit")
        assert r.status_code == 429
        assert r.headers["Retry-After"]


async def test_edit_resend_reject_path_charges_the_phi_read_budget(engine: Engine) -> None:
    # The POST's reject arm re-reads and re-ships the PRISTINE stored body, so it charges the budget
    # too — otherwise it is an unthrottled channel for re-reading what the GET throttles.
    service = AuthService(
        engine.store, AuthSettings(require_mfa=False, phi_read_rate_limit_per_actor=1)
    )
    await service.initialize()
    await _add(service, "op", Role.OPERATOR)
    mid = await _seed(engine)
    async with _client(engine, service) as c:
        await _cookie_login(c, "op")
        await _mint_action(c, f"/ui/messages/{mid}/edit")  # vault BACKLOG #2625
        body = {"raw": "", "idempotency_key": "k1", "mode": "reroute"}
        same_origin = {"Sec-Fetch-Site": "same-origin"}
        r = await c.post(f"/ui/messages/{mid}/edit-resend", data=body, headers=same_origin)
        assert r.status_code == 400  # the reject re-render — one token spent
        r = await c.post(f"/ui/messages/{mid}/edit-resend", data=body, headers=same_origin)
        assert r.status_code == 429
        assert r.headers["Retry-After"]


async def test_edit_resend_reroute_redirects_to_child(engine: Engine, tmp_path: Path) -> None:
    # Re-route re-ingresses the EDITED body as a fresh correlated child on the origin channel; the /ui
    # route lands the operator on the NEW child's detail. Store-level reingress needs no started
    # pipeline, but the origin inbound must be registered: its ingress guards run on the edited body,
    # and with no inbound to guard with the re-route refuses (BACKLOG #1911).
    (tmp_path / "in").mkdir(exist_ok=True)
    reg = Registry()
    reg.add_inbound(
        InboundConnection(
            "ch1",
            ConnectionSpec(
                ConnectorType.FILE,
                {"directory": str(tmp_path / "in"), "pattern": "*.hl7", "poll_seconds": 0.05},
            ),
            router="r",
        )
    )
    reg.add_router("r", lambda m: [])
    engine.add_registry(reg)
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    mid = await _seed(engine)
    async with _client(engine, service) as c:
        await _cookie_login(c, "op")
        await _mint_action(c, f"/ui/messages/{mid}/edit")  # vault BACKLOG #2625
        r = await c.post(
            f"/ui/messages/{mid}/edit-resend",
            data={"raw": EDITED, "idempotency_key": "k1", "mode": "reroute"},
            headers={"Sec-Fetch-Site": "same-origin"},
        )
        assert r.status_code == 303
        child = r.headers["location"].removeprefix("/ui/messages/")
        assert child and child != mid
    origin = await engine.store.get_message(mid)
    assert origin is not None and origin["raw"] == ADT  # the ORIGINAL is byte-identical
    child_row = await engine.store.get_message(child)
    assert child_row is not None and child_row["raw"] == EDITED  # the child carries the edited body
    assert json.loads(child_row["metadata"])["edited_from"] == mid  # correlated to the origin
    # Vault BACKLOG #2615: the plain origin names the operator who sent it.
    assert (child_row["origin"], child_row["origin_actor"]) == ("operator_edit", "op")


async def test_console_edit_resend_audits_keyed_digests_and_origin(tmp_path: Path) -> None:
    # Vault BACKLOG #2615: the console route reaches the engine's own handler, so its audit row
    # carries the same provenance as the JSON route's: the origin and keyed digests of both bodies,
    # which reproduce from the bodies under the store key.
    from messagefoundry.store.crypto import generate_key, make_cipher, verify_audit_body_digest
    from messagefoundry.store.store import MessageStore

    (tmp_path / "in").mkdir(exist_ok=True)
    store = await MessageStore.open(tmp_path / "keyed.db", cipher=make_cipher(generate_key()))
    engine = Engine(store, egress_settings=EgressSettings(deny_by_default=False))
    try:
        reg = Registry()
        reg.add_inbound(
            InboundConnection(
                "ch1",
                ConnectionSpec(
                    ConnectorType.FILE,
                    {"directory": str(tmp_path / "in"), "pattern": "*.hl7", "poll_seconds": 0.05},
                ),
                router="r",
            )
        )
        reg.add_router("r", lambda m: [])
        engine.add_registry(reg)
        service = await _service(engine)
        await _add(service, "op", Role.OPERATOR)
        mid = await _seed(engine)
        async with _client(engine, service) as c:
            await _cookie_login(c, "op")
            await _mint_action(c, f"/ui/messages/{mid}/edit")
            r = await c.post(
                f"/ui/messages/{mid}/edit-resend",
                data={"raw": EDITED, "idempotency_key": "k1", "mode": "reroute"},
                headers={"Sec-Fetch-Site": "same-origin"},
            )
            assert r.status_code == 303
        [rec] = [a for a in await store.list_audit() if a["action"] == "message_edit_resend"]
        assert rec["actor"] == "op"
        detail = json.loads(str(rec["detail"]))
        assert detail["origin"] == "operator_edit"
        digest = detail["body_digest"]
        cipher = store.cipher()
        kid = digest["key_id"]
        assert verify_audit_body_digest(cipher, ADT, key_id=kid, digest=digest["original"])
        assert verify_audit_body_digest(cipher, EDITED, key_id=kid, digest=digest["edited"])
        assert "DOE^JOHN" not in str(rec["detail"])
        child = await store.get_message(detail["new_message_id"])
        assert child is not None and (child["origin"], child["origin_actor"]) == (
            "operator_edit",
            "op",
        )
    finally:
        await engine.stop()


async def test_edit_resend_direct_redirects_to_origin(engine: Engine, tmp_path: Path) -> None:
    # The DIRECT power-path delivers the edited body straight to a registered/running alternate
    # outbound and lands back on the ORIGIN (which now carries the new outbound row). The shared engine
    # handler validates `to` against the registry + running state, so this path needs a started
    # pipeline with OB2 registered.
    for d in ("in", "o2"):
        (tmp_path / d).mkdir(exist_ok=True)
    reg = Registry()
    reg.add_inbound(
        InboundConnection(
            "in1",
            ConnectionSpec(
                ConnectorType.FILE,
                {"directory": str(tmp_path / "in"), "pattern": "*.hl7", "poll_seconds": 0.05},
            ),
            router="r",
        )
    )
    reg.add_outbound(
        OutboundConnection(
            "OB2", ConnectionSpec(ConnectorType.FILE, {"directory": str(tmp_path / "o2")})
        )
    )
    reg.add_router("r", lambda m: ["h"])
    reg.add_handler("h", lambda m: Send("OB2", m))
    engine.add_registry(reg)
    await engine.start()
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    mid = await _seed(engine)
    async with _client(engine, service) as c:
        await _cookie_login(c, "op")
        await _mint_action(c, f"/ui/messages/{mid}/edit")  # vault BACKLOG #2625
        r = await c.post(
            f"/ui/messages/{mid}/edit-resend",
            data={"raw": EDITED, "idempotency_key": "k1", "mode": "direct", "to": "OB2"},
            headers={"Sec-Fetch-Site": "same-origin"},
        )
        assert r.status_code == 303
        assert r.headers["location"] == f"/ui/messages/{mid}"  # back to the ORIGIN
    rec = [a for a in await engine.store.list_audit() if a["action"] == "message_edit_resend"]
    assert len(rec) == 1
    detail = str(rec[0]["detail"] or "")
    assert '"mode": "direct"' in detail
    assert EDITED not in detail and "DOE^JOHN" not in detail  # the edited body is NEVER audited
    # Vault BACKLOG #2615: a keyless store records the origin and no digest, never a plain hash.
    parsed = json.loads(detail)
    assert parsed["origin"] == "operator_edit" and parsed["body_digest"] is None
    child = await engine.store.get_message(parsed["new_message_id"])
    assert child is not None and (child["origin"], child["origin_actor"]) == ("operator_edit", "op")


async def test_edit_resend_direct_missing_to_rejects_generic(engine: Engine) -> None:
    # A direct send with no chosen outbound is rejected with a generic prompt — and the operator's
    # mode choice (direct) survives so the form doesn't silently reset to re-route (review #153-4).
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    mid = await _seed(engine)
    async with _client(engine, service) as c:
        await _cookie_login(c, "op")
        await _mint_action(c, f"/ui/messages/{mid}/edit")  # vault BACKLOG #2625
        r = await c.post(
            f"/ui/messages/{mid}/edit-resend",
            data={"raw": EDITED, "idempotency_key": "k1", "mode": "direct", "to": ""},
            headers={"Sec-Fetch-Site": "same-origin"},
        )
        assert r.status_code == 400
        assert "choose an outbound connection" in r.text
        assert 'value="direct" checked' in r.text  # the direct radio stays selected
        assert '"input"' not in r.text  # never a pydantic structured echo


async def test_edit_resend_phi_safe_reject_no_pydantic_echo(engine: Engine) -> None:
    # An empty edited body fails EditResendRequest(min_length=1). The webconsole re-renders a GENERIC
    # error — never pydantic's structured echo (which for a body-carrying route would surface the
    # offending value). The 422 no-echo is covered engine-side; this is the webconsole 400 analogue.
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    mid = await _seed(engine)
    async with _client(engine, service) as c:
        await _cookie_login(c, "op")
        await _mint_action(c, f"/ui/messages/{mid}/edit")  # vault BACKLOG #2625
        r = await c.post(
            f"/ui/messages/{mid}/edit-resend",
            data={"raw": "", "idempotency_key": "k1", "mode": "reroute"},
            headers={"Sec-Fetch-Site": "same-origin"},
        )
        assert r.status_code == 400
        assert "invalid input" in r.text
        # The operator's own edited raw IS re-shown (raw_value=), so assert on the ABSENCE of the
        # pydantic error STRUCTURE, not a blanket substring check of the whole page.
        assert '"type":' not in r.text
        assert '"input":' not in r.text
        assert "string_too_long" not in r.text
        assert "string_too_short" not in r.text


async def test_edit_stale_stepup_redirects_get_and_post_to_edit_form(engine: Engine) -> None:
    # With an expired step-up window BOTH the GET editor and the body-carrying POST bounce to
    # /ui/reauth pointing at the /edit FORM page — never at the POST path (a re-POST across re-auth
    # would drop the edited body). No child is minted from the bounced request.
    # require_mfa=False takes the MFA leg out of require_ui_step_up, so the stale window below is
    # what redirects; without it this unenrolled session is refused first with the SAME 303 and the
    # same Location, and the window measured nothing (BACKLOG #1851). Reasoning, and the third
    # new-IP leg that stays unpinned: the docstring of
    # test_purge_stale_stepup_redirects_to_reauth (BACKLOG #1700).
    service = AuthService(engine.store, AuthSettings(require_mfa=False, step_up_max_age_seconds=-1))
    await service.initialize()
    await _add(service, "op", Role.OPERATOR)
    mid = await _seed(engine)
    async with _client(engine, service) as c:
        await _cookie_login(c, "op")  # negative window -> the fresh login is already stale
        tok = c.cookies.get("mf_session")
        assert tok is not None
        assert await service.mfa_satisfied(tok) is True  # the MFA leg is NOT what refuses here
        assert await service.has_recent_step_up(tok) is False  # the stale window is
        r = await c.get(f"/ui/messages/{mid}/edit")
        assert r.status_code == 303
        assert r.headers["location"] == f"/ui/reauth?next=/ui/messages/{mid}/edit"
        r = await c.post(
            f"/ui/messages/{mid}/edit-resend",
            data={"raw": EDITED, "idempotency_key": "k1", "mode": "reroute"},
            headers={"Sec-Fetch-Site": "same-origin"},
        )
        assert r.status_code == 303
        # The reauth_next maps the POST to the /edit FORM, never the /edit-resend POST path.
        assert r.headers["location"] == f"/ui/reauth?next=/ui/messages/{mid}/edit"
    # The body never outlived the bounced request — only the origin exists.
    assert await engine.store.count_messages(allowed_channels=None) == 1


async def test_edit_resend_cross_site_and_cookie_on_json(engine: Engine) -> None:
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    mid = await _seed(engine)
    async with _client(engine, service) as c:
        await _cookie_login(c, "op")
        # (a) A cross-site POST to the /ui route is rejected by the same-origin CSRF defense.
        r = await c.post(
            f"/ui/messages/{mid}/edit-resend", headers={"Sec-Fetch-Site": "cross-site"}
        )
        assert r.status_code == 403
        # (b) The /ui cookie is not accepted on the JSON engine route (header-only auth there).
        r = await c.post(
            f"/messages/{mid}/edit-resend",
            json={"raw": EDITED, "idempotency_key": "k1"},
        )
        assert r.status_code == 401


# --- M3: dead-letter bulk replay (per-channel, step-up + approval-gated) ------


async def test_dl_replay_rejects_cross_site(engine: Engine) -> None:
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    async with _client(engine, service) as c:
        await _cookie_login(c, "op")
        r = await c.post("/ui/dead-letters/ch1/replay", headers={"Sec-Fetch-Site": "cross-site"})
        assert r.status_code == 403


async def test_dl_replay_requires_replay_permission(engine: Engine) -> None:
    service = await _service(engine)
    await _add(service, "viewer", Role.VIEWER)
    async with _client(engine, service) as c:
        await _cookie_login(c, "viewer")
        r = await c.post("/ui/dead-letters/ch1/replay", headers={"Sec-Fetch-Site": "same-origin"})
        assert r.status_code == 403


async def test_dl_replay_cookie_not_accepted_on_json_route(engine: Engine) -> None:
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    async with _client(engine, service) as c:
        await _cookie_login(c, "op")
        assert (await c.post("/dead-letters/replay", json={"channel_id": "ch1"})).status_code == 401


async def test_dl_replay_reaches_handler_after_login_stepup(engine: Engine) -> None:
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    async with _client(engine, service) as c:
        await _cookie_login(c, "op")
        r = await c.post("/ui/dead-letters/ch1/replay", headers={"Sec-Fetch-Site": "same-origin"})
        assert r.status_code not in (401, 403)
        assert "reauth" not in r.headers.get("location", "")


async def test_reauth_accepts_dead_letter_replay_next(engine: Engine) -> None:
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    async with _client(engine, service) as c:
        await _cookie_login(c, "op")
        r = await c.get("/ui/reauth", params={"next": "/ui/dead-letters/IB_ACME_ADT/replay"})
        assert r.status_code == 200
        assert 'name="password"' in r.text
