# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Browser ops dashboard (/ui, ADR 0065 / BACKLOG #75): serving, confined-cookie auth, headers, XSS."""

from __future__ import annotations

import asyncio
import base64
import json

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from urllib.parse import quote, urlencode
from pathlib import Path

import httpx
import pytest

from messagefoundry.api import create_app
from messagefoundry.auth import Role
from messagefoundry.auth.identity import AuthProvider
from messagefoundry.auth.tokens import hash_token
from messagefoundry.auth.service import AuthService
from messagefoundry.config.models import ConnectorType
from messagefoundry.config.settings import ApprovalsSettings, AuthSettings
from messagefoundry.config.wiring import (
    ConnectionSpec,
    InboundConnection,
    OutboundConnection,
    Registry,
    Send,
)
from messagefoundry.pipeline import Engine

SAMPLES_CONFIG = Path(__file__).resolve().parent.parent / "samples" / "config"
PW = "a-strong-test-passphrase"  # ≥15, no app/vendor terms — satisfies the ASVS policy (WP-3)
ADT = "MSH|^~\\&|S|F|R|RF|20260604||ADT^A01|MSG1|P|2.5.1\rPID|1||100^^^H^MR||DOE^JANE\r"
# An HL7 field carrying HTML metacharacters — the XSS payload the browser must never execute.
XSS_RAW = "MSH|^~\\&|S|F|R|RF|20260604||ADT^A01|X1|P|2.5.1\rPID|1||1||<script>alert(1)</script>\r"


@pytest.fixture
async def engine(tmp_path: Path) -> AsyncIterator[Engine]:
    eng = await Engine.create(tmp_path / "webui.db", poll_interval=0.02)
    yield eng
    await eng.stop()


async def _service(engine: Engine) -> AuthService:
    service = AuthService(engine.store, AuthSettings())
    await service.initialize()
    return service


def _client(engine: Engine, service: AuthService, *, serve_ui: bool = True) -> httpx.AsyncClient:
    transport = httpx.ASGITransport(app=create_app(engine, auth=service, serve_ui=serve_ui))
    return httpx.AsyncClient(transport=transport, base_url="http://t")


async def _add(service: AuthService, username: str, *roles: Role) -> None:
    user_id = await service.create_local_user(
        username=username,
        password=PW,
        display_name=None,
        email=None,
        roles=[r.value for r in roles],
        actor="test",
    )
    user = await service.store.get_user(user_id)
    assert user is not None and user.password_hash is not None
    await service.store.set_password(
        user_id, password_hash=user.password_hash, must_change_password=False
    )


async def _cookie_login(c: httpx.AsyncClient, username: str) -> httpx.Response:
    """Sign in via the browser cookie flow (urlencoded form; the client keeps the Set-Cookie)."""
    return await c.post("/ui/login", data={"username": username, "password": PW})


async def _seed(engine: Engine, raw: str = ADT, control_id: str = "MSG1") -> str:
    return await engine.store.enqueue_message(
        channel_id="ch1",
        raw=raw,
        deliveries=[("archive", raw)],
        control_id=control_id,
        message_type="ADT^A01",
        source_type="file",
    )


# --- AC-1: off by default ----------------------------------------------------


async def test_ui_absent_when_disabled(engine: Engine) -> None:
    service = await _service(engine)
    async with _client(engine, service, serve_ui=False) as c:
        assert (await c.get("/ui")).status_code == 404
        assert (await c.get("/ui/login")).status_code == 404
        assert (await c.get("/ui/static/app.css")).status_code == 404
        # The JSON API is unaffected.
        assert (await c.get("/health")).status_code == 200


async def test_ui_present_when_enabled(engine: Engine) -> None:
    service = await _service(engine)
    async with _client(engine, service) as c:
        r = await c.get("/ui/login")
        assert r.status_code == 200
        assert "text/html" in r.headers["content-type"]
        assert (await c.get("/ui/static/app.css")).status_code == 200
        assert (await c.get("/ui/static/app.js")).status_code == 200


# --- AC-2: the cookie is confined to /ui; the JSON API stays header-only ------


async def test_cookie_not_accepted_on_json_api(engine: Engine) -> None:
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    async with _client(engine, service) as c:
        await _cookie_login(c, "op")
        assert c.cookies.get("mf_session")  # the browser now holds the session cookie
        # ...but presenting ONLY that cookie to a JSON API route must be rejected (bearer header only).
        assert (await c.get("/connections")).status_code == 401
        assert (await c.get("/stats")).status_code == 401
        assert (await c.get("/messages")).status_code == 401


async def test_header_bearer_still_authorizes_json(engine: Engine) -> None:
    # Sanity: the native bearer path is untouched by the cookie mode.
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    async with _client(engine, service) as c:
        token = (await c.post("/auth/login", json={"username": "op", "password": PW})).json()[
            "token"
        ]
        r = await c.get("/connections", headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 200


# --- AC-3: login sets a confined cookie; logout clears + revokes --------------


async def test_login_sets_confined_cookie_and_logout_revokes(engine: Engine) -> None:
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    async with _client(engine, service) as c:
        r = await _cookie_login(c, "op")
        assert r.status_code == 303 and r.headers["location"] == "/ui"
        set_cookie = r.headers["set-cookie"].lower()
        assert "mf_session=" in set_cookie
        assert "httponly" in set_cookie
        assert "samesite=strict" in set_cookie
        assert "secure" not in set_cookie  # http request → Secure not set (scheme-gated)
        # The session works for /ui.
        assert (await c.get("/ui")).status_code == 200
        # Log out: cookie cleared AND the server-side session revoked.
        out = await c.post("/ui/logout")
        assert out.status_code == 303
        # After logout the (now-revoked) session no longer grants /ui — a fresh request redirects.
        c.cookies.clear()
        assert (await c.get("/ui")).status_code == 303  # → /ui/login


async def test_bad_credentials_redirect_without_cookie(engine: Engine) -> None:
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    async with _client(engine, service) as c:
        r = await c.post("/ui/login", data={"username": "op", "password": "wrong-password-xyz"})
        assert r.status_code == 303 and r.headers["location"] == "/ui/login?e=bad"
        assert not c.cookies.get("mf_session")


async def test_unauthenticated_ui_redirects_to_login(engine: Engine) -> None:
    service = await _service(engine)
    async with _client(engine, service) as c:
        r = await c.get("/ui")
        assert r.status_code == 303 and r.headers["location"] == "/ui/login"


# --- AC-4: attacker-influenced HL7 is escaped --------------------------------


async def test_hostile_hl7_is_escaped(engine: Engine) -> None:
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    mid = await _seed(engine, raw=XSS_RAW, control_id="X1")
    async with _client(engine, service) as c:
        await _cookie_login(c, "op")
        r = await c.get(f"/ui/messages/{mid}")
        assert r.status_code == 200
        body = r.text
        assert "<script>alert(1)</script>" not in body  # never rendered as live markup
        assert "&lt;script&gt;alert(1)&lt;/script&gt;" in body  # escaped instead


# --- AC-5: /ui security headers ----------------------------------------------


async def test_ui_security_headers(engine: Engine) -> None:
    service = await _service(engine)
    async with _client(engine, service) as c:
        r = await c.get("/ui/login")
        csp = r.headers["content-security-policy"]
        assert "script-src 'self'" in csp
        assert "unsafe-eval" not in csp and "unsafe-inline" not in csp
        assert "frame-ancestors 'none'" in csp
        assert r.headers["cache-control"] == "no-store"
        # The existing hardening still applies.
        assert r.headers["x-frame-options"] == "DENY"
        assert r.headers["x-content-type-options"] == "nosniff"


async def test_phi_json_reads_are_no_store(engine: Engine) -> None:
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    mid = await _seed(engine)
    async with _client(engine, service) as c:
        token = (await c.post("/auth/login", json={"username": "op", "password": PW})).json()[
            "token"
        ]
        r = await c.get(f"/messages/{mid}", headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 200
        assert r.headers["cache-control"] == "no-store"


# --- AC-7: the /ui detail view reuses the audited PHI path --------------------


async def test_ui_message_detail_audits_like_json(engine: Engine) -> None:
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    mid = await _seed(engine)
    async with _client(engine, service) as c:
        await _cookie_login(c, "op")
        r = await c.get(f"/ui/messages/{mid}")
        assert r.status_code == 200
    audits = await engine.store.list_audit(limit=100)
    dumped = [dict(a) for a in audits]
    assert any(
        "message_view" in str(row.values())
        and mid in str(row.values())
        and "op" in str(row.values())
        for row in dumped
    ), "the /ui raw view must record the same message_view audit as GET /messages/{id}"


# --- AC-6: off-loopback /ui requires TLS, even under --allow-insecure-bind ----


def test_serve_ui_offloopback_requires_tls(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from messagefoundry.__main__ import main
    from messagefoundry.store.crypto import generate_key

    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("MEFOR_STORE_ENCRYPTION_KEY", generate_key())
    monkeypatch.setattr("uvicorn.run", lambda *a, **k: None)
    (tmp_path / "messagefoundry.toml").write_text(
        '[api]\nhost = "0.0.0.0"\nserve_ui = true\n', encoding="utf-8"
    )
    # --allow-insecure-bind clears the JSON-API cleartext gate, but the stricter /ui gate still refuses.
    rc = main(["serve", "--config", str(SAMPLES_CONFIG), "--env", "dev", "--allow-insecure-bind"])
    assert rc == 2
    assert "browser ops dashboard" in capsys.readouterr().err


# --- M2: connection controls (writes) — CSRF + permission + confinement ------


async def test_control_rejects_cross_site_post(engine: Engine) -> None:
    # An authenticated operator POST carrying a cross-site Sec-Fetch-Site is refused (CSRF defense-in-
    # depth). require_ui passes (valid cookie + CONNECTIONS_CONTROL), so this isolates assert_same_origin.
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    async with _client(engine, service) as c:
        await _cookie_login(c, "op")
        r = await c.post("/ui/connections/anything/stop", headers={"Sec-Fetch-Site": "cross-site"})
        assert r.status_code == 403


async def test_control_requires_control_permission(engine: Engine) -> None:
    # A VIEWER (no connections:control) is refused even same-origin — require_ui enforces the permission
    # the direct handler call would otherwise skip.
    service = await _service(engine)
    await _add(service, "viewer", Role.VIEWER)
    async with _client(engine, service) as c:
        await _cookie_login(c, "viewer")
        r = await c.post("/ui/connections/anything/stop", headers={"Sec-Fetch-Site": "same-origin"})
        assert r.status_code == 403


async def test_control_cookie_not_accepted_on_json_route(engine: Engine) -> None:
    # Confinement extends to the write routes: the JSON control route with only the cookie still 401s.
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    async with _client(engine, service) as c:
        await _cookie_login(c, "op")
        assert (await c.post("/connections/anything/stop")).status_code == 401


async def test_control_same_origin_reaches_handler(engine: Engine) -> None:
    # A same-origin operator POST passes auth + CSRF and reaches the control handler (which then errors
    # on the unknown connection) — proving the gate lets a legitimate request through (not 401/403).
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    async with _client(engine, service) as c:
        await _cookie_login(c, "op")
        r = await c.post(
            "/ui/connections/no-such-conn/stop", headers={"Sec-Fetch-Site": "same-origin"}
        )
        assert r.status_code not in (401, 403)


# --- M2b: message replay (step-up) + the browser re-auth flow -----------------


async def test_replay_rejects_cross_site_post(engine: Engine) -> None:
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    mid = await _seed(engine)
    async with _client(engine, service) as c:
        await _cookie_login(c, "op")
        r = await c.post(f"/ui/messages/{mid}/replay", headers={"Sec-Fetch-Site": "cross-site"})
        assert r.status_code == 403


async def test_replay_requires_replay_permission(engine: Engine) -> None:
    # A viewer (no messages:replay) is refused before any step-up/CSRF logic.
    service = await _service(engine)
    await _add(service, "viewer", Role.VIEWER)
    mid = await _seed(engine)
    async with _client(engine, service) as c:
        await _cookie_login(c, "viewer")
        r = await c.post(f"/ui/messages/{mid}/replay", headers={"Sec-Fetch-Site": "same-origin"})
        assert r.status_code == 403


async def test_replay_cookie_not_accepted_on_json_route(engine: Engine) -> None:
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    mid = await _seed(engine)
    async with _client(engine, service) as c:
        await _cookie_login(c, "op")
        assert (await c.post(f"/messages/{mid}/replay")).status_code == 401


async def test_replay_after_login_stepup_reaches_handler(engine: Engine) -> None:
    # A fresh login counts as a recent step-up, so replay is NOT bounced to /ui/reauth — it reaches the
    # replay handler (proving require_ui_step_up passes for a just-authenticated operator).
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    mid = await _seed(engine)
    async with _client(engine, service) as c:
        await _cookie_login(c, "op")
        r = await c.post(f"/ui/messages/{mid}/replay", headers={"Sec-Fetch-Site": "same-origin"})
        assert r.status_code not in (401, 403)
        assert "reauth" not in r.headers.get("location", "")


async def test_reauth_rejects_unsafe_next(engine: Engine) -> None:
    # The `next` param the re-auth flow auto-retries MUST be a /ui replay action — never an arbitrary
    # URL (anti open-redirect / anti open-POST gadget). Rejected values bounce to /ui, not to the target.
    service = await _service(engine)
    async with _client(engine, service) as c:
        for bad in ("https://evil.example/x", "//evil.example", "/ui/messages", "/etc/passwd"):
            r = await c.get("/ui/reauth", params={"next": bad})
            assert r.status_code == 303 and r.headers["location"] == "/ui"


async def test_reauth_form_renders_for_safe_next(engine: Engine) -> None:
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    async with _client(engine, service) as c:
        await _cookie_login(c, "op")
        r = await c.get("/ui/reauth", params={"next": "/ui/messages/abc123/replay"})
        assert r.status_code == 200
        assert 'name="password"' in r.text
        assert 'name="next"' in r.text


async def test_reauth_rejects_cross_site_post(engine: Engine) -> None:
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    async with _client(engine, service) as c:
        await _cookie_login(c, "op")
        r = await c.post(
            "/ui/reauth",
            data={"next": "/ui/messages/abc/replay", "password": PW},
            headers={"Sec-Fetch-Site": "cross-site"},
        )
        assert r.status_code == 403


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


# --- M-ws: /ws/stats browser channel — cookie-on-handshake auth + CSWSH gate --


class _FakeWS:
    """Minimal duck-typed WebSocket for unit-testing authorize_ui_ws (headers/cookies/app.state)."""

    def __init__(
        self, origin: str | None, host: str | None, cookie: str | None, app: object
    ) -> None:
        self.headers = {k: v for k, v in (("origin", origin), ("host", host)) if v is not None}
        self.cookies = {"mf_session": cookie} if cookie is not None else {}
        self.app = app


async def _token(engine: Engine, service: AuthService, user: str) -> tuple[object, str]:
    from messagefoundry.api import create_app

    app = create_app(engine, auth=service, serve_ui=True)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t") as c:
        token = (await c.post("/auth/login", json={"username": user, "password": PW})).json()[
            "token"
        ]
    return app, token


async def test_ws_cookie_auth_same_origin_ok(engine: Engine) -> None:
    from messagefoundry_webconsole import authorize_ui_ws
    from messagefoundry.auth import Permission

    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    app, token = await _token(engine, service, "op")
    ws = _FakeWS(origin="http://t", host="t", cookie=token, app=app)
    identity, tok = await authorize_ui_ws(ws, Permission.MONITORING_READ)  # type: ignore[arg-type]
    assert identity is not None and tok == token


async def test_ws_cookie_auth_rejects_cross_origin(engine: Engine) -> None:
    # CSWSH gate: a cross-origin handshake is rejected even with a valid cookie value.
    from messagefoundry_webconsole import authorize_ui_ws
    from messagefoundry.auth import Permission

    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    app, token = await _token(engine, service, "op")
    ws = _FakeWS(origin="http://evil.example", host="t", cookie=token, app=app)
    identity, _ = await authorize_ui_ws(ws, Permission.MONITORING_READ)  # type: ignore[arg-type]
    assert identity is None


async def test_ws_cookie_auth_requires_cookie_and_origin(engine: Engine) -> None:
    from messagefoundry_webconsole import authorize_ui_ws
    from messagefoundry.auth import Permission

    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    app, token = await _token(engine, service, "op")
    # No cookie → rejected (falls back to the native header path in the handler).
    no_cookie = _FakeWS(origin="http://t", host="t", cookie=None, app=app)
    assert (await authorize_ui_ws(no_cookie, Permission.MONITORING_READ))[0] is None  # type: ignore[arg-type]
    # No Origin (a native client) → rejected here so the handler uses the header path.
    no_origin = _FakeWS(origin=None, host="t", cookie=token, app=app)
    assert (await authorize_ui_ws(no_origin, Permission.MONITORING_READ))[0] is None  # type: ignore[arg-type]
    # A bad/expired cookie value → rejected.
    bad = _FakeWS(origin="http://t", host="t", cookie="not-a-real-token", app=app)
    assert (await authorize_ui_ws(bad, Permission.MONITORING_READ))[0] is None  # type: ignore[arg-type]


# --- PR A: parse-tree endpoint + per-destination dead-letter replay ----------


async def test_parse_tree_renders_escaped(engine: Engine) -> None:
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    mid = await _seed(engine, raw=XSS_RAW, control_id="X1")
    async with _client(engine, service) as c:
        await _cookie_login(c, "op")
        r = await c.get(f"/ui/messages/{mid}/parse-tree")
        assert r.status_code == 200
        assert "MSH" in r.text and "PID" in r.text  # HL7 segment labels rendered
        # The attacker-influenced field value is escaped, never live markup.
        assert "<script>alert(1)</script>" not in r.text
        assert "&lt;script&gt;alert(1)&lt;/script&gt;" in r.text


async def test_parse_tree_non_hl7_is_unavailable(engine: Engine) -> None:
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    mid = await _seed(engine, raw="this is not an hl7 message", control_id="NOPE")
    async with _client(engine, service) as c:
        await _cookie_login(c, "op")
        r = await c.get(f"/ui/messages/{mid}/parse-tree")
        assert r.status_code == 200
        assert "No HL7 parse tree" in r.text


async def test_parse_tree_requires_view_raw(engine: Engine) -> None:
    service = await _service(engine)
    await _add(service, "auditor", Role.AUDITOR)  # MONITORING_READ only, no MESSAGES_VIEW_RAW
    mid = await _seed(engine)
    async with _client(engine, service) as c:
        await _cookie_login(c, "auditor")
        assert (await c.get(f"/ui/messages/{mid}/parse-tree")).status_code == 403


def test_is_safe_ui_action_per_destination() -> None:
    from messagefoundry_webconsole import is_safe_ui_action

    assert is_safe_ui_action("/ui/dead-letters/CH/OB_DEST/replay")
    assert is_safe_ui_action("/ui/dead-letters/CH/replay")
    assert not is_safe_ui_action("/ui/dead-letters/CH/OB/extra/replay")  # 3 segments rejected
    assert not is_safe_ui_action("/ui/dead-letters/CH/../replay")


async def test_dl_replay_per_destination_reaches_handler(engine: Engine) -> None:
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    async with _client(engine, service) as c:
        await _cookie_login(c, "op")
        r = await c.post(
            "/ui/dead-letters/ch1/OB_DEST/replay", headers={"Sec-Fetch-Site": "same-origin"}
        )
        assert r.status_code not in (401, 403)
        assert "reauth" not in r.headers.get("location", "")


async def test_dl_replay_per_destination_rejects_cross_site(engine: Engine) -> None:
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    async with _client(engine, service) as c:
        await _cookie_login(c, "op")
        r = await c.post(
            "/ui/dead-letters/ch1/OB_DEST/replay", headers={"Sec-Fetch-Site": "cross-site"}
        )
        assert r.status_code == 403


# --- PR B: WS payload enrichment (connections fragment pushed over /ws/stats) --


def test_ws_stats_payload_is_enriched(tmp_path: Path) -> None:
    # Sync TestClient drives the lifespan (engine on its own loop), like tests/test_api.py's WS test.
    # No auth → the native allow_no_auth path authorizes the socket; with serve_ui on the web console
    # installs the app.state.ui_connections_render hook, so the payload carries the server-rendered
    # connections fragment alongside the queue-by-status counts (Option B Phase 0 seam 3).
    from starlette.testclient import TestClient

    from messagefoundry.api import create_managed_app

    app = create_managed_app(db_path=tmp_path / "wsx.db", poll_interval=0.05, serve_ui=True)
    with TestClient(app) as tc, tc.websocket_connect("/ws/stats") as ws:
        data = ws.receive_json()
        assert "outbox_by_status" in data and isinstance(data["outbox_by_status"], dict)
        assert "connections_html" in data and isinstance(data["connections_html"], str)
        assert 'id="conns"' in data["connections_html"]  # the server-rendered table fragment


def test_ws_stats_payload_is_counts_only_without_serve_ui(tmp_path: Path) -> None:
    # JSON-only fallback (Option B Phase 0 seam 3): with serve_ui off the ui_connections_render hook is
    # unset, so /ws/stats pushes a COUNTS-ONLY frame (no server-rendered connections_html) over the
    # native Authorization-header WS auth path. The counts key is always present; a native client that
    # only reads outbox_by_status is unaffected.
    from starlette.testclient import TestClient

    from messagefoundry.api import create_managed_app

    app = create_managed_app(db_path=tmp_path / "wsx.db", poll_interval=0.05)
    with TestClient(app) as tc, tc.websocket_connect("/ws/stats") as ws:
        data = ws.receive_json()
        assert "outbox_by_status" in data and isinstance(data["outbox_by_status"], dict)
        assert "connections_html" not in data


# --- PR C: off-loopback exposure — [api].public_origin same-origin checks ------


def _client_po(engine: Engine, service: AuthService, public_origin: str) -> httpx.AsyncClient:
    app = create_app(engine, auth=service, serve_ui=True, public_origin=public_origin)
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t")


def test_public_origin_is_validated_and_normalized() -> None:
    from messagefoundry.config.settings import ApiSettings

    assert (
        ApiSettings(public_origin="https://ops.example.com/").public_origin
        == "https://ops.example.com"
    )
    assert ApiSettings(public_origin=None).public_origin is None
    with pytest.raises(ValueError):
        ApiSettings(public_origin="https://ops.example.com/path")  # path not allowed
    with pytest.raises(ValueError):
        ApiSettings(public_origin="ops.example.com")  # missing scheme


async def test_csrf_honors_public_origin(engine: Engine) -> None:
    # Behind a proxy (public_origin set), the Origin is matched against public_origin, not Host — so a
    # same-origin POST with a mismatching Host still passes, and a cross-origin one is still rejected.
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    async with _client_po(engine, service, "http://ops.example.com") as c:
        await _cookie_login(c, "op")
        ok = await c.post("/ui/connections/nope/stop", headers={"Origin": "http://ops.example.com"})
        assert ok.status_code != 403  # Origin matches public_origin → CSRF passes (reaches handler)
        bad = await c.post("/ui/connections/nope/stop", headers={"Origin": "http://evil.example"})
        assert bad.status_code == 403  # cross-origin → rejected


async def test_ws_cookie_auth_honors_public_origin(engine: Engine) -> None:
    from messagefoundry_webconsole import authorize_ui_ws
    from messagefoundry.auth import Permission

    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    app = create_app(engine, auth=service, serve_ui=True, public_origin="https://ops.example.com")
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://ops.example.com"
    ) as c:
        token = (await c.post("/auth/login", json={"username": "op", "password": PW})).json()[
            "token"
        ]
    # Public origin matches despite a mismatching Host (the proxy case); a wrong origin is rejected.
    good = _FakeWS(origin="https://ops.example.com", host="internal", cookie=token, app=app)
    assert (await authorize_ui_ws(good, Permission.MONITORING_READ))[0] is not None  # type: ignore[arg-type]
    bad = _FakeWS(origin="https://evil.example", host="internal", cookie=token, app=app)
    assert (await authorize_ui_ws(bad, Permission.MONITORING_READ))[0] is None  # type: ignore[arg-type]


def test_public_origin_matching_is_case_insensitive() -> None:
    # Scheme + host are case-insensitive (RFC 3986 §3.2.2): the validator lowercases the configured
    # origin, and _origin_matches canonicalizes the incoming Origin — so a case variant is not a false
    # reject (and can never be a bypass; it fails closed).
    from messagefoundry_webconsole._auth import _origin_matches
    from messagefoundry.config.settings import ApiSettings

    assert (
        ApiSettings(public_origin="https://OPS.Example.COM").public_origin
        == "https://ops.example.com"
    )

    class _WithPO:
        public_origin = "https://ops.example.com"

    assert _origin_matches(_WithPO(), "https://OPS.EXAMPLE.COM", "internal")
    assert _origin_matches(_WithPO(), "https://ops.example.com", "internal")
    assert not _origin_matches(_WithPO(), "https://evil.example", "internal")

    class _NoPO:
        public_origin = None

    assert _origin_matches(_NoPO(), "http://T", "t")  # Host fallback is case-insensitive too
    assert not _origin_matches(_NoPO(), "http://evil", "t")


# --- L1a: read-only monitoring pages (alerts + event log), BACKLOG #75 phase 1 ----------------


async def test_alerts_page_renders_for_operator(engine: Engine) -> None:
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    async with _client(engine, service) as c:
        await _cookie_login(c, "op")
        r = await c.get("/ui/alerts")
        assert r.status_code == 200
        assert "text/html" in r.headers["content-type"]
        body = r.text
        assert "Active" in body and "Rules" in body
        assert "No active alerts." in body  # empty state (no seeded alert instances)


async def test_events_page_renders_for_viewer(engine: Engine) -> None:
    # VIEWER holds monitoring:read (not diagnose) — the event log is read-only monitoring, so it renders.
    service = await _service(engine)
    await _add(service, "viewer", Role.VIEWER)
    async with _client(engine, service) as c:
        await _cookie_login(c, "viewer")
        r = await c.get("/ui/events")
        assert r.status_code == 200
        assert "No events." in r.text  # empty state


async def test_alerts_requires_diagnose(engine: Engine) -> None:
    # The alerts page requires monitoring:diagnose (active instances). A VIEWER (read-only) is 403'd,
    # but the same VIEWER can still reach the event log — the read/diagnose split is enforced per page.
    service = await _service(engine)
    await _add(service, "viewer", Role.VIEWER)
    async with _client(engine, service) as c:
        await _cookie_login(c, "viewer")
        assert (await c.get("/ui/alerts")).status_code == 403
        assert (await c.get("/ui/events")).status_code == 200


async def test_alerts_unauthenticated_redirects_to_login(engine: Engine) -> None:
    service = await _service(engine)
    async with _client(engine, service) as c:
        r = await c.get("/ui/alerts")
        assert r.status_code == 303 and r.headers["location"] == "/ui/login"


def test_alerts_builder_escapes_hostile() -> None:
    # Alert metadata (connection label, scrubbed reason) is attacker-influenceable — never live markup.
    from messagefoundry.api.models import (
        AlertInstanceInfo,
        AlertInstanceList,
        AlertsConfig,
    )
    from messagefoundry_webconsole.pages import alerts

    instances = AlertInstanceList(
        alerts=[
            AlertInstanceInfo(
                id=1,
                event_type="queue_depth",
                connection="IB_ACME",
                severity="critical",
                status="open",
                first_seen=0.0,
                last_seen=0.0,
                count=3,
                reason="<script>alert(1)</script>",
            )
        ]
    )
    config = AlertsConfig(
        webhook_configured=False,
        webhook_timeout=5.0,
        webhook_allowed_hosts=[],
        email_configured=False,
        email_smtp_port=25,
        email_use_tls=True,
        email_recipient_count=0,
        smtp_allowed_hosts=[],
        realert_seconds=300.0,
        rules=[],
    )
    html = str(alerts(instances, config))
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html


def test_events_builder_escapes_hostile() -> None:
    from messagefoundry.api.models import ConnectionEventInfo
    from messagefoundry_webconsole.pages import events

    rows = [
        ConnectionEventInfo(
            id=1,
            ts=0.0,
            connection="IB_ACME",
            transport="mllp",
            direction="inbound",
            kind="conn_open",
            peer_host="<script>",
            reason="<b>boom</b>",
        )
    ]
    html = str(events(rows))
    assert "<b>boom</b>" not in html
    assert "&lt;b&gt;boom&lt;/b&gt;" in html
    assert "&lt;script&gt;" in html  # hostile peer_host escaped


# --- L1b: read-only engine status page, BACKLOG #75 phase 1 -----------------------------------


async def test_status_page_renders_for_viewer(engine: Engine) -> None:
    # monitoring:read is enough for the whole status page (engine/store/posture/cluster/DR).
    service = await _service(engine)
    await _add(service, "viewer", Role.VIEWER)
    async with _client(engine, service) as c:
        await _cookie_login(c, "viewer")
        r = await c.get("/ui/status")
        assert r.status_code == 200
        body = r.text
        assert "Engine" in body and "Store" in body
        assert "Cluster" in body and "Disaster recovery" in body
        # Effective posture is surfaced (SQLite backend on the test engine).
        assert "sqlite" in body


async def test_status_unauthenticated_redirects_to_login(engine: Engine) -> None:
    service = await _service(engine)
    async with _client(engine, service) as c:
        r = await c.get("/ui/status")
        assert r.status_code == 303 and r.headers["location"] == "/ui/login"


def test_status_builder_escapes_and_formats() -> None:
    # Server-controlled fields, but render through the escaping builders + confirm helper formatting.
    from messagefoundry.api.models import (
        ClusterNode,
        ClusterNodeList,
        ClusterStatus,
        DbInfo,
        DrStatus,
        EngineInfo,
        SecurityPosture,
        SystemStatus,
    )
    from messagefoundry_webconsole.pages import status

    sys_status = SystemStatus(
        engine=EngineInfo(
            version="0.2.14",
            uptime_seconds=90.0,
            pid=123,
            channels_total=2,
            channels_running=1,
            channels_stopped=1,
            outbox_by_status={"queued": 4},
        ),
        db=DbInfo(
            path="/data/mf.db",
            size_bytes=2_500_000,
            disk_free_bytes=10_000_000_000,
            journal_mode="wal",
            messages=10,
            events=5,
            audit=7,
        ),
    )
    posture = SecurityPosture(
        backend="sqlite",
        encryption_enabled=True,
        key_source="auto",
        key_id="abc123",
        require_encryption=True,
        allow_unencrypted_phi=False,
    )
    cluster = ClusterStatus(
        node_id="n1", clustered=False, is_leader=True, role="single-node", config_version=0
    )
    nodes = ClusterNodeList(
        nodes=[
            ClusterNode(
                node_id="n1",
                host="<b>host</b>",
                pid=1,
                status="active",
                started_at=None,
                last_seen=None,
                is_leader=True,
            )
        ],
        leader_node_id="n1",
        lease_owner=None,
        lease_expires_at=None,
    )
    dr = DrStatus(enabled=False, active=False, threshold="P1", activation_mode="manual")
    from messagefoundry.api.models import ServiceStatusInfo

    svc = ServiceStatusInfo(enabled=True, state="running", service_name="MEFOR_Engine")
    html = str(status(sys_status, posture, cluster, nodes, dr, svc))
    assert "2.4 MiB" in html  # _bytes formatting
    assert "yes" in html and "single-node" in html  # _yn + role
    assert "<b>host</b>" not in html  # hostile node host escaped
    assert "&lt;b&gt;host&lt;/b&gt;" in html
    # L6a: the hosting-service badge renders the state + name.
    assert "Hosting service" in html and "MEFOR_Engine" in html and "running" in html
    # When reporting is off, the badge says so (no state leaked).
    off = ServiceStatusInfo(enabled=False, state="disabled", service_name="")
    assert "reporting is off" in str(status(sys_status, posture, cluster, nodes, dr, off))


# --- L0b: register_ui_action write-action registry (the extensible step-up allow-list) ---------


def test_register_ui_action_extends_the_stepup_allowlist() -> None:
    # A write-page lane extends the auto-retry allow-list by REGISTERING its action — never by editing
    # is_safe_ui_action. The migrated replay actions still resolve (behavior-preserving); a freshly
    # registered action becomes auto-retryable; the ".." reject still holds; registration is idempotent.
    from messagefoundry_webconsole import is_safe_ui_action, register_ui_action
    from messagefoundry_webconsole._auth import _UI_WRITE_ACTIONS
    from messagefoundry.auth import Permission

    # Migrated phase-0 replay actions are still allowed.
    assert is_safe_ui_action("/ui/messages/M1/replay")
    assert is_safe_ui_action("/ui/dead-letters/CH/OB_DEST/replay")

    # A not-yet-registered path is not auto-retryable.
    pat = r"^/ui/alerts/[^/?#]+/ack$"
    assert not is_safe_ui_action("/ui/alerts/7/ack")
    register_ui_action(pat, Permission.MONITORING_DIAGNOSE)
    assert is_safe_ui_action("/ui/alerts/7/ack")  # now allowed
    assert not is_safe_ui_action("/ui/alerts/7/../ack")  # .. still rejected

    # A body-carrying action (auto_retry=False) never rides the URL auto-retry.
    register_ui_action(r"^/ui/users/create$", Permission.USERS_MANAGE, auto_retry=False)
    assert not is_safe_ui_action("/ui/users/create")

    # Idempotent by pattern.
    register_ui_action(pat, Permission.MONITORING_DIAGNOSE)
    assert sum(1 for a in _UI_WRITE_ACTIONS if a.path_re.pattern == pat) == 1


# --- L3a: monitoring write ops (ack/resolve, stats reset, integrity, DR), BACKLOG #75 phase 3 -----


async def test_stats_reset_same_origin_reaches_handler(engine: Engine) -> None:
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    async with _client(engine, service) as c:
        await _cookie_login(c, "op")
        r = await c.post("/ui/statistics/reset", headers={"Sec-Fetch-Site": "same-origin"})
        assert r.status_code == 303 and r.headers["location"] == "/ui/status"


async def test_monitoring_write_requires_diagnose(engine: Engine) -> None:
    # A VIEWER (monitoring:read, no diagnose) is refused on every monitoring write — require_ui enforces
    # the permission the direct handler call would otherwise skip.
    service = await _service(engine)
    await _add(service, "viewer", Role.VIEWER)
    async with _client(engine, service) as c:
        await _cookie_login(c, "viewer")
        h = {"Sec-Fetch-Site": "same-origin"}
        assert (await c.post("/ui/statistics/reset", headers=h)).status_code == 403
        assert (await c.post("/ui/alerts/1/ack", headers=h)).status_code == 403
        assert (await c.post("/ui/alerts/1/resolve", headers=h)).status_code == 403
        assert (await c.post("/ui/status/integrity-check", headers=h)).status_code == 403


async def test_monitoring_write_rejects_cross_site(engine: Engine) -> None:
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    async with _client(engine, service) as c:
        await _cookie_login(c, "op")
        r = await c.post("/ui/statistics/reset", headers={"Sec-Fetch-Site": "cross-site"})
        assert r.status_code == 403


async def test_integrity_check_renders_result(engine: Engine) -> None:
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    async with _client(engine, service) as c:
        await _cookie_login(c, "op")
        r = await c.post("/ui/status/integrity-check", headers={"Sec-Fetch-Site": "same-origin"})
        assert r.status_code == 200
        assert "Integrity check" in r.text and "OK" in r.text  # fresh SQLite passes quick_check


async def test_dr_activate_requires_dr_operate(engine: Engine) -> None:
    # OPERATOR does NOT hold dr:operate (only ADMINISTRATOR does) — the /ui DR route enforces it.
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    async with _client(engine, service) as c:
        await _cookie_login(c, "op")
        r = await c.post("/ui/dr/activate", headers={"Sec-Fetch-Site": "same-origin"})
        assert r.status_code == 403


def test_alerts_builder_renders_write_controls() -> None:
    from messagefoundry.api.models import (
        AlertInstanceInfo,
        AlertInstanceList,
        AlertsConfig,
    )
    from messagefoundry_webconsole.pages import alerts

    instances = AlertInstanceList(
        alerts=[
            AlertInstanceInfo(
                id=42,
                event_type="queue_depth",
                connection="IB_ACME",
                severity="critical",
                status="open",
                first_seen=0.0,
                last_seen=0.0,
                count=1,
            )
        ]
    )
    config = AlertsConfig(
        webhook_configured=False,
        webhook_timeout=5.0,
        webhook_allowed_hosts=[],
        email_configured=False,
        email_smtp_port=25,
        email_use_tls=True,
        email_recipient_count=0,
        smtp_allowed_hosts=[],
        realert_seconds=300.0,
        rules=[],
    )
    html = str(alerts(instances, config))
    assert "/ui/alerts/42/ack" in html and "Ack" in html
    assert "/ui/alerts/42/resolve" in html and "Resolve" in html


# --- L3b: queue purge (step-up + dual-control), BACKLOG #75 phase 3 -------------------------------


async def test_purge_requires_purge_permission(engine: Engine) -> None:
    # A VIEWER (no messages:purge) is refused before any step-up/CSRF logic.
    service = await _service(engine)
    await _add(service, "viewer", Role.VIEWER)
    async with _client(engine, service) as c:
        await _cookie_login(c, "viewer")
        r = await c.post(
            "/ui/connections/OB_X/purge/all", headers={"Sec-Fetch-Site": "same-origin"}
        )
        assert r.status_code == 403


async def test_purge_rejects_cross_site(engine: Engine) -> None:
    # A fresh login is a recent step-up, so require_ui_step_up passes and the cross-site guard fires.
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    async with _client(engine, service) as c:
        await _cookie_login(c, "op")
        r = await c.post("/ui/connections/OB_X/purge/all", headers={"Sec-Fetch-Site": "cross-site"})
        assert r.status_code == 403


async def test_purge_cookie_not_accepted_on_json_route(engine: Engine) -> None:
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    async with _client(engine, service) as c:
        await _cookie_login(c, "op")
        assert (await c.post("/connections/OB_X/purge")).status_code == 401


async def test_purge_after_login_stepup_reaches_handler(engine: Engine) -> None:
    # A same-origin operator (stepped up by the fresh login) passes auth + step-up + CSRF and reaches
    # purge_connection, which 404s on the unknown outbound — proving the gate lets it through.
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    async with _client(engine, service) as c:
        await _cookie_login(c, "op")
        r = await c.post(
            "/ui/connections/OB_X/purge/all", headers={"Sec-Fetch-Site": "same-origin"}
        )
        assert r.status_code not in (401, 403)
        assert "reauth" not in r.headers.get("location", "")


async def test_purge_action_registered_in_stepup_allowlist(engine: Engine) -> None:
    # Creating the /ui app registers the purge action, so the re-auth flow may auto-retry it (path-based,
    # body-less). A non-purge or query-bearing path is not accepted.
    from messagefoundry_webconsole import is_safe_ui_action

    service = await _service(engine)
    create_app(engine, auth=service, serve_ui=True)
    assert is_safe_ui_action("/ui/connections/OB_X/purge/all")
    assert is_safe_ui_action("/ui/connections/OB_X/purge/top")
    assert not is_safe_ui_action("/ui/connections/OB_X/purge/some")  # bad scope
    assert not is_safe_ui_action("/ui/connections/OB_X/purge/all?x=1")  # query rejected


def test_connections_fragment_renders_selection_checkbox() -> None:
    from messagefoundry.api.models import ConnectionRow
    from messagefoundry_webconsole.pages import connections_fragment
    from messagefoundry_webconsole.pages.connections import _row_key

    dest = ConnectionRow(
        role="destination",
        channel_id="IB_ACME_ADT",
        channel_name="ACME ADT",
        destination="OB_ARCHIVE",
        name="OB_ARCHIVE",
        status="stopped",
        direction="out",
        method="File",
        peer=None,
        port=None,
        queue_depth=0,
        idle_seconds=None,
        alerts_active=0,
        errored=0,
        read=None,
        written=0,
        backlog_seconds=None,
        delivered_age_seconds=None,
        paused=True,
    )
    html = str(connections_fragment([dest]))
    # Per-row selection checkbox keyed by the stable _row_key, carrying live role/state data-* for the
    # toolbar's JS partitioning; data-paused (paused AND quiesced) gates purge eligibility.
    assert "data-mf-conns-cb" in html
    assert f'value="{_row_key(dest)}"' in html
    assert 'data-role="destination"' in html
    assert 'data-status="stopped"' in html
    assert 'data-paused="1"' in html
    assert 'data-dest="OB_ARCHIVE"' in html


def test_connections_fragment_failed_but_paused_row_is_purge_eligible() -> None:
    from messagefoundry.api.models import ConnectionRow
    from messagefoundry_webconsole.pages import connections_fragment

    # A destination whose lane FAILED to build (collapsed status "failed") but is ALSO operator-paused-
    # AND-quiesced: the checkbox still carries data-paused="1", so the toolbar keeps it purge-eligible.
    # Purge eligibility (paused) is INDEPENDENT of the collapsed display status — never gated behind it.
    row = ConnectionRow(
        role="destination",
        channel_id="IB_ACME_ADT",
        channel_name="ACME ADT",
        destination="OB_ARCHIVE",
        name="OB_ARCHIVE",
        status="failed",
        direction="out",
        method="File",
        peer=None,
        port=None,
        queue_depth=0,
        idle_seconds=None,
        alerts_active=0,
        errored=0,
        read=None,
        written=0,
        backlog_seconds=None,
        delivered_age_seconds=None,
        paused=True,
    )
    html = str(connections_fragment([row]))
    assert 'data-status="failed"' in html  # collapsed status is failed
    assert 'data-paused="1"' in html  # yet still purge-eligible (paused independent of status)
    # Select-all header checkbox present; the fragment keeps its #conns id (the poll target).
    assert "data-mf-conns-all" in html
    assert 'id="conns"' in html
    # The old per-row control/purge/reset forms are gone (they moved to the un-polled toolbar).
    assert "/ui/connections/OB_ARCHIVE/purge/" not in html
    assert "/ui/statistics/reset-one" not in html
    assert 'class="ctl"' not in html and 'class="ctls"' not in html


# --- L3c: config-deploy (reload the startup graph, #26 bright line), BACKLOG #75 phase 3 ----------


async def test_config_page_renders(engine: Engine) -> None:
    service = await _service(engine)
    await _add(service, "viewer", Role.VIEWER)
    async with _client(engine, service) as c:
        await _cookie_login(c, "viewer")
        r = await c.get("/ui/config")
        assert r.status_code == 200
        body = r.text
        assert "Reload configuration" in body
        assert "VS Code extension" in body  # the #26 bright-line note (authoring stays in the IDE)
        # The bright line: no filesystem picker / config-dir input on the page.
        assert 'name="config_dir"' not in body and 'type="file"' not in body


async def test_config_reload_requires_deploy_permission(engine: Engine) -> None:
    # A VIEWER (no config:deploy) is refused before any step-up/CSRF logic.
    service = await _service(engine)
    await _add(service, "viewer", Role.VIEWER)
    async with _client(engine, service) as c:
        await _cookie_login(c, "viewer")
        r = await c.post("/ui/config/reload", headers={"Sec-Fetch-Site": "same-origin"})
        assert r.status_code == 403


async def test_config_reload_rejects_cross_site(engine: Engine) -> None:
    # A deployment user (config:deploy) with a fresh-login step-up still fails a cross-site POST.
    service = await _service(engine)
    await _add(service, "deployer", Role.DEPLOYMENT)
    async with _client(engine, service) as c:
        await _cookie_login(c, "deployer")
        r = await c.post("/ui/config/reload", headers={"Sec-Fetch-Site": "cross-site"})
        assert r.status_code == 403


async def test_config_reload_registered_in_stepup_allowlist(engine: Engine) -> None:
    from messagefoundry_webconsole import is_safe_ui_action

    service = await _service(engine)
    create_app(engine, auth=service, serve_ui=True)
    assert is_safe_ui_action("/ui/config/reload")
    assert not is_safe_ui_action("/ui/config/reload?dir=/etc")  # query rejected (no path injection)


async def test_write_action_method_matches_its_continuation(engine: Engine) -> None:
    # R1 (refined for L0c): the re-auth continuation branches on a registered action's flags, so the HTTP
    # method serving each action MUST match its continuation style, or the branch is a hazard:
    #   * an ``auto_retry`` action is a body-less POST the re-auth re-POSTs — it must never be a
    #     side-effecting GET (CSRF / idempotency).
    #   * an ``unlock`` action is a GET admin form page the re-auth 303-GET-redirects to — it must never
    #     be a POST (a GET-redirect to a state-changing POST would be an open-POST gadget).
    from messagefoundry_webconsole._auth import _UI_WRITE_ACTIONS

    service = await _service(engine)
    app = create_app(engine, auth=service, serve_ui=True)
    ui_routes = [
        (route.path, getattr(route, "methods", set()))
        for route in app.routes
        if getattr(route, "path", "").startswith("/ui")
    ]
    for action in _UI_WRITE_ACTIONS:
        for path, methods in ui_routes:
            if not action.path_re.fullmatch(path):
                continue
            if action.auto_retry:
                assert "GET" not in methods, (
                    f"{path} is a GET but matches auto_retry action {action.path_re.pattern}"
                )
            if action.unlock:
                assert "POST" not in methods, (
                    f"{path} is a POST but matches unlock action {action.path_re.pattern}"
                )


# --- L0c: step-up-to-unlock primitive (confirm-after-step-up for body-carrying admin forms) --------
#
# The stateless confirm-after-step-up path: an admin FORM GET is registered as an ``unlock`` action, so
# a stale step-up 303s to /ui/reauth and — after a successful re-verification — 303-GET-redirects BACK
# to the form (which re-opens inside a fresh window). The body-carrying POST (incl. a create-user
# password) is then submitted in a single request that never crosses /ui/reauth, so no body — and no
# password — is ever preserved across the redirect. These tests exercise the primitive in isolation
# (PR1); the L4a admin pages that register real unlock actions land in PR2.

_UNLOCK_PAT = r"^/ui/testunlock/[^/?#]+$"  # a synthetic unlock form path, namespaced to the tests


def test_is_unlock_action_gate() -> None:
    # is_unlock_action is the GET-form analogue of is_safe_ui_action: it matches ONLY registered
    # ``unlock`` entries, is ``..``-guarded, and is disjoint from the auto-retry (POST) allow-list.
    from messagefoundry_webconsole import (
        is_safe_ui_action,
        is_unlock_action,
        register_ui_action,
    )
    from messagefoundry.auth import Permission

    assert not is_unlock_action("/ui/testunlock/new")  # not yet registered
    register_ui_action(_UNLOCK_PAT, Permission.USERS_MANAGE, auto_retry=False, unlock=True)
    assert is_unlock_action("/ui/testunlock/new")  # now an unlock target
    assert not is_safe_ui_action("/ui/testunlock/new")  # but NOT an auto-retry (POST) target
    assert not is_unlock_action("/ui/testunlock/../new")  # .. still rejected
    assert not is_unlock_action("/ui/testunlock/a/b")  # two segments — anchored pattern rejects
    assert not is_unlock_action(None) and not is_unlock_action("")
    # A replay auto_retry action is not an unlock target (the two allow-lists are disjoint).
    assert not is_unlock_action("/ui/messages/M1/replay")
    assert is_safe_ui_action("/ui/messages/M1/replay")


def test_register_ui_action_rejects_auto_retry_and_unlock() -> None:
    # A /ui action can be a body-less POST auto-retry OR a GET-form unlock, never both — the re-auth
    # continuation branches on exactly these flags, so an action that is both is a mis-registration.
    import re

    from messagefoundry_webconsole import register_ui_action
    from messagefoundry_webconsole._auth import UiWriteAction
    from messagefoundry.auth import Permission

    with pytest.raises(ValueError):
        register_ui_action(r"^/ui/bad$", Permission.USERS_MANAGE, auto_retry=True, unlock=True)
    with pytest.raises(ValueError):
        UiWriteAction(re.compile(r"^/ui/bad$"), Permission.USERS_MANAGE, True, True, True)


async def test_reauth_form_renders_for_unlock_next(engine: Engine) -> None:
    # The re-auth form accepts an ``unlock`` next (a GET admin form), exactly as it accepts a replay next.
    from messagefoundry_webconsole import register_ui_action
    from messagefoundry.auth import Permission

    register_ui_action(_UNLOCK_PAT, Permission.USERS_MANAGE, auto_retry=False, unlock=True)
    service = await _service(engine)
    await _add(service, "boss", Role.ADMINISTRATOR)  # "admin" is the seeded bootstrap admin
    async with _client(engine, service) as c:
        await _cookie_login(c, "boss")
        r = await c.get("/ui/reauth", params={"next": "/ui/testunlock/new"})
        assert r.status_code == 200
        assert 'name="password"' in r.text and 'name="next"' in r.text
        assert "/ui/testunlock/new" in r.text  # the unlock target rides the hidden next field


async def test_reauth_get_unlock_redirects_after_stepup(engine: Engine) -> None:
    # THE primitive: a successful step-up whose next is an ``unlock`` form 303-GET-redirects BACK to the
    # form (so it re-opens fresh) — it does NOT render the POST auto-submit page. No body is carried.
    from messagefoundry_webconsole import register_ui_action
    from messagefoundry.auth import Permission

    register_ui_action(_UNLOCK_PAT, Permission.USERS_MANAGE, auto_retry=False, unlock=True)
    service = await _service(engine)
    await _add(service, "boss", Role.ADMINISTRATOR)  # "admin" is the seeded bootstrap admin
    async with _client(engine, service) as c:
        await _cookie_login(c, "boss")  # a fresh login satisfies the password step-up
        r = await c.post(
            "/ui/reauth",
            data={"next": "/ui/testunlock/new", "password": PW},
            headers={"Sec-Fetch-Site": "same-origin"},
        )
        assert r.status_code == 303
        assert r.headers["location"] == "/ui/testunlock/new"
        # It is a GET redirect, NOT the auto-submit POST page — the password never rides a re-POST.
        assert "data-autosubmit" not in r.text


async def test_reauth_post_rejects_unregistered_next(engine: Engine) -> None:
    # The POST-side gate end-to-end: a next that is neither a registered auto-retry POST nor a
    # registered unlock form bounces to /ui BEFORE any credential is examined — even with a valid
    # password in the body (anti open-redirect / open-POST on the branch PR1 touched).
    service = await _service(engine)
    await _add(service, "boss", Role.ADMINISTRATOR)  # "admin" is the seeded bootstrap admin
    async with _client(engine, service) as c:
        await _cookie_login(c, "boss")
        for bad in ("https://evil.example/x", "//evil.example", "/ui/unregistered", "/ui"):
            r = await c.post(
                "/ui/reauth",
                data={"next": bad, "password": PW},
                headers={"Sec-Fetch-Site": "same-origin"},
            )
            assert r.status_code == 303 and r.headers["location"] == "/ui"


async def test_reauth_failed_stepup_rerenders_form_not_redirect(engine: Engine) -> None:
    # A WRONG password on an unlock next must re-render the reauth form (with the hidden next), never
    # 303 to the unlock target — the GET-redirect happens only after a successful re-verification.
    from messagefoundry_webconsole import register_ui_action
    from messagefoundry.auth import Permission

    register_ui_action(_UNLOCK_PAT, Permission.USERS_MANAGE, auto_retry=False, unlock=True)
    service = await _service(engine)
    await _add(service, "boss", Role.ADMINISTRATOR)
    async with _client(engine, service) as c:
        await _cookie_login(c, "boss")
        r = await c.post(
            "/ui/reauth",
            data={"next": "/ui/testunlock/new", "password": "wrong-password-xyz"},
            headers={"Sec-Fetch-Site": "same-origin"},
        )
        assert r.status_code == 200  # the form again, not a redirect
        assert "Incorrect password." in r.text
        assert 'name="next"' in r.text and "/ui/testunlock/new" in r.text


async def test_reauth_post_auto_retry_still_renders_continue(engine: Engine) -> None:
    # Regression: a body-less POST action (replay) still gets the auto-submit continue page after
    # step-up — the unlock branch must not have changed the existing auto-retry continuation.
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    async with _client(engine, service) as c:
        await _cookie_login(c, "op")
        r = await c.post(
            "/ui/reauth",
            data={"next": "/ui/messages/abc/replay", "password": PW},
            headers={"Sec-Fetch-Site": "same-origin"},
        )
        assert r.status_code == 200
        assert "data-autosubmit" in r.text  # the same-origin auto-submit POST form
        assert 'action="/ui/messages/abc/replay"' in r.text


# --- L4a: users/RBAC admin (/ui/users, /ui/roles, /ui/ad-groups), #75 phase 4 ----------------------
#
# All admin writes are require_step_up(USERS_MANAGE) in the JSON API. Body-less path actions register
# as auto_retry; every body-carrying FORM PAGE registers as an `unlock` target (the L0c primitive), and
# its POST maps a stale-step-up redirect to that form via reauth_next — a password crosses the wire
# exactly once (the create-user POST) and never rides /ui/reauth.


@asynccontextmanager
async def _boss_client(engine: Engine, service: AuthService) -> AsyncIterator[httpx.AsyncClient]:
    """An admin ('boss' — 'admin' is the seeded bootstrap account) signed in via the cookie flow."""
    await _add(service, "boss", Role.ADMINISTRATOR)
    async with _client(engine, service) as c:
        await _cookie_login(c, "boss")
        yield c


async def _uid(service: AuthService, username: str) -> str:
    user = await service.store.get_user_by_username(username)
    assert user is not None
    return user.id


async def _post_pairs(
    c: httpx.AsyncClient, url: str, pairs: list[tuple[str, str]]
) -> httpx.Response:
    """Same-origin urlencoded form POST with REPEATED fields (checkboxes/map rows) — httpx's dict
    ``data=`` collapses duplicate keys, so encode the pair list explicitly."""
    return await c.post(
        url,
        content=urlencode(pairs),
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "Sec-Fetch-Site": "same-origin",
        },
    )


async def test_users_pages_require_users_read(engine: Engine) -> None:
    # OPERATOR holds neither users:read nor users:manage — the whole admin area is refused.
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    async with _client(engine, service) as c:
        await _cookie_login(c, "op")
        assert (await c.get("/ui/users")).status_code == 403
        assert (await c.get("/ui/roles")).status_code == 403
        assert (await c.get("/ui/users/new")).status_code == 403
        assert (await c.get("/ui/ad-groups")).status_code == 403


async def test_users_page_lists_accounts(engine: Engine) -> None:
    service = await _service(engine)
    async with _boss_client(engine, service) as c:
        r = await c.get("/ui/users")
        assert r.status_code == 200
        # The seeded bootstrap 'admin' (retired once boss exists) and boss itself are listed.
        assert "admin" in r.text and "boss" in r.text
        assert "/ui/users/new" in r.text  # the create form link
        # The admin nav entry is registered (visible from any page).
        assert 'href="/ui/users"' in (await c.get("/ui")).text


async def test_l4a_actions_registered_in_correct_allowlists(engine: Engine) -> None:
    # Form pages are unlock targets; body-less path actions are auto-retry; body-carrying POST paths
    # are in NEITHER list (they can only be reached by a fresh same-origin form submit).
    from messagefoundry_webconsole import is_safe_ui_action, is_unlock_action

    service = await _service(engine)
    create_app(engine, auth=service, serve_ui=True)
    for form in (
        "/ui/users/new",
        "/ui/users/U1",
        "/ui/roles/new",
        "/ui/roles/custom:x/edit",
        "/ui/ad-groups",
    ):
        assert is_unlock_action(form), form
        assert not is_safe_ui_action(form), form
    for action in (
        "/ui/users/U1/delete",
        "/ui/users/U1/reset-password",
        "/ui/users/U1/reset-mfa",
        "/ui/users/U1/revoke-sessions",
        "/ui/roles/custom/custom:x/delete",
    ):
        assert is_safe_ui_action(action), action
        assert not is_unlock_action(action), action
    for body_post in (
        "/ui/users",
        "/ui/users/U1/roles",
        "/ui/users/U1/update",
        "/ui/users/U1/channel-scope",
        "/ui/roles/custom",
        "/ui/ad-groups/map",
        "/ui/ad-groups/scope-map",
    ):
        assert not is_safe_ui_action(body_post), body_post
        assert not is_unlock_action(body_post), body_post


async def test_create_user_end_to_end(engine: Engine) -> None:
    service = await _service(engine)
    async with _boss_client(engine, service) as c:
        r = await _post_pairs(
            c,
            "/ui/users",
            [
                ("username", "newop"),
                ("password", PW),
                ("display_name", "New Operator"),
                ("email", "newop@example.test"),
                ("roles", "operator"),
                ("roles", "viewer"),
            ],
        )
        assert r.status_code == 303
        user = await service.store.get_user_by_username("newop")
        assert user is not None
        assert r.headers["location"] == f"/ui/users/{user.id}"
        assert sorted(await service.store.get_user_role_ids(user.id)) == ["operator", "viewer"]
        assert user.must_change_password  # admin-set initial credential dies at first login


async def test_create_user_duplicate_rerenders_without_password(engine: Engine) -> None:
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    async with _boss_client(engine, service) as c:
        r = await c.post(
            "/ui/users",
            data={"username": "op", "password": PW, "display_name": "Dup"},
            headers={"Sec-Fetch-Site": "same-origin"},
        )
        assert r.status_code == 400
        assert "already exists" in r.text
        assert 'value="op"' in r.text  # non-secret fields are preserved...
        assert PW not in r.text  # ...the password is NEVER echoed back


async def test_create_user_weak_password_rejected(engine: Engine) -> None:
    service = await _service(engine)
    async with _boss_client(engine, service) as c:
        r = await c.post(
            "/ui/users",
            data={"username": "weakling", "password": "short"},
            headers={"Sec-Fetch-Site": "same-origin"},
        )
        assert r.status_code == 400 and "password must" in r.text
        assert await service.store.get_user_by_username("weakling") is None


async def test_create_user_cross_site_rejected(engine: Engine) -> None:
    service = await _service(engine)
    async with _boss_client(engine, service) as c:
        r = await c.post(
            "/ui/users",
            data={"username": "csrf", "password": PW},
            headers={"Sec-Fetch-Site": "cross-site"},
        )
        assert r.status_code == 403
        assert await service.store.get_user_by_username("csrf") is None


async def test_stale_stepup_redirects_body_post_to_unlock_form(engine: Engine) -> None:
    # THE reauth_next mapping: with an expired step-up window, the body-carrying POST /ui/users is
    # redirected to /ui/reauth pointing at its FORM PAGE (/ui/users/new) — never at the POST path —
    # and the form GET itself bounces the same way (its own path IS the unlock target).
    service = AuthService(engine.store, AuthSettings(step_up_max_age_seconds=-1))
    await service.initialize()
    async with _boss_client(engine, service) as c:
        r = await c.post(
            "/ui/users",
            data={"username": "x", "password": PW},
            headers={"Sec-Fetch-Site": "same-origin"},
        )
        assert r.status_code == 303
        assert r.headers["location"] == "/ui/reauth?next=/ui/users/new"
        r = await c.get("/ui/users/new")
        assert r.status_code == 303
        assert r.headers["location"] == "/ui/reauth?next=/ui/users/new"
        # The user was NOT created — the body never outlives the bounced request.
        assert await service.store.get_user_by_username("x") is None


async def test_reauth_unlocks_real_user_form(engine: Engine) -> None:
    # The registered /ui/users/new unlock target round-trips the reauth POST into a GET redirect.
    service = await _service(engine)
    async with _boss_client(engine, service) as c:
        r = await c.post(
            "/ui/reauth",
            data={"next": "/ui/users/new", "password": PW},
            headers={"Sec-Fetch-Site": "same-origin"},
        )
        assert r.status_code == 303 and r.headers["location"] == "/ui/users/new"
        assert (await c.get("/ui/users/new")).status_code == 200


async def test_update_user_profile_roundtrip(engine: Engine) -> None:
    service = await _service(engine)
    await _add(service, "u1", Role.VIEWER)
    async with _boss_client(engine, service) as c:
        uid = await _uid(service, "u1")
        r = await c.post(
            f"/ui/users/{uid}/update",
            data={"display_name": "User One", "email": "u1@example.test", "disabled": "on"},
            headers={"Sec-Fetch-Site": "same-origin"},
        )
        assert r.status_code == 303
        user = await service.store.get_user(uid)
        assert user is not None
        assert user.display_name == "User One" and user.disabled
        # Re-enable (checkbox absent) + clear the email ("" clears to None — full-form semantics).
        r = await c.post(
            f"/ui/users/{uid}/update",
            data={"display_name": "User One", "email": ""},
            headers={"Sec-Fetch-Site": "same-origin"},
        )
        assert r.status_code == 303
        user = await service.store.get_user(uid)
        assert user is not None
        assert not user.disabled and user.email is None


async def test_cannot_disable_self_rerenders_error(engine: Engine) -> None:
    service = await _service(engine)
    async with _boss_client(engine, service) as c:
        uid = await _uid(service, "boss")
        r = await c.post(
            f"/ui/users/{uid}/update",
            data={"display_name": "", "email": "", "disabled": "on"},
            headers={"Sec-Fetch-Site": "same-origin"},
        )
        assert r.status_code == 400
        assert "cannot disable your own account" in r.text
        user = await service.store.get_user(uid)
        assert user is not None and not user.disabled


async def test_set_roles_roundtrip_and_last_admin_guard(engine: Engine) -> None:
    service = await _service(engine)
    await _add(service, "u1", Role.VIEWER)
    async with _boss_client(engine, service) as c:
        uid = await _uid(service, "u1")
        r = await _post_pairs(c, f"/ui/users/{uid}/roles", [("roles", "operator")])
        assert r.status_code == 303
        assert await service.store.get_user_role_ids(uid) == ["operator"]
        # Creating boss retired the bootstrap admin, so boss IS the last enabled administrator.
        boss_id = await _uid(service, "boss")
        r = await _post_pairs(c, f"/ui/users/{boss_id}/roles", [("roles", "viewer")])
        assert r.status_code == 400
        assert "cannot remove the last administrator" in r.text


async def test_channel_scope_roundtrip(engine: Engine) -> None:
    # Tri-state scope_mode: a list, all-channels (None), and deny-all ([]) each round-trip; a "list"
    # save with an empty textarea is refused instead of guessing (review PR2-M3).
    import json as json_

    service = await _service(engine)
    await _add(service, "u1", Role.VIEWER)
    async with _boss_client(engine, service) as c:
        uid = await _uid(service, "u1")
        r = await c.post(
            f"/ui/users/{uid}/channel-scope",
            data={"scope_mode": "list", "channels": "IB_ACME_ADT\r\nIB_LAB_ORU\r\n\r\n"},
            headers={"Sec-Fetch-Site": "same-origin"},
        )
        assert r.status_code == 303
        user = await service.store.get_user(uid)
        assert user is not None and user.channel_scope is not None
        assert json_.loads(user.channel_scope) == ["IB_ACME_ADT", "IB_LAB_ORU"]
        # Deny-all is explicit — and the detail page re-renders it as the selected mode.
        r = await c.post(
            f"/ui/users/{uid}/channel-scope",
            data={"scope_mode": "none", "channels": ""},
            headers={"Sec-Fetch-Site": "same-origin"},
        )
        assert r.status_code == 303
        user = await service.store.get_user(uid)
        assert user is not None and json_.loads(user.channel_scope or "null") == []
        # Re-saving the deny-all page unchanged must NOT widen the scope (the PR2-M3 bug):
        # the form now posts scope_mode=none, so [] survives a no-op save.
        detail = (await c.get(f"/ui/users/{uid}")).text
        assert 'value="none" selected' in detail
        # All-channels is explicit too.
        r = await c.post(
            f"/ui/users/{uid}/channel-scope",
            data={"scope_mode": "all", "channels": ""},
            headers={"Sec-Fetch-Site": "same-origin"},
        )
        assert r.status_code == 303
        user = await service.store.get_user(uid)
        assert user is not None and user.channel_scope is None
        # "Only these" with an empty list is ambiguous — refused, scope unchanged.
        r = await c.post(
            f"/ui/users/{uid}/channel-scope",
            data={"scope_mode": "list", "channels": ""},
            headers={"Sec-Fetch-Site": "same-origin"},
        )
        assert r.status_code == 400 and "list at least one connection" in r.text
        user = await service.store.get_user(uid)
        assert user is not None and user.channel_scope is None


async def test_reset_password_shows_temp_once(engine: Engine) -> None:
    service = await _service(engine)
    await _add(service, "u2", Role.VIEWER)
    async with _boss_client(engine, service) as c:
        uid = await _uid(service, "u2")
        r = await c.post(
            f"/ui/users/{uid}/reset-password", headers={"Sec-Fetch-Site": "same-origin"}
        )
        assert r.status_code == 200
        assert "Temporary password issued" in r.text and "<code>" in r.text
        user = await service.store.get_user(uid)
        assert user is not None and user.must_change_password


async def test_reset_mfa_and_revoke_sessions_roundtrip(engine: Engine) -> None:
    service = await _service(engine)
    await _add(service, "u2", Role.VIEWER)
    async with _boss_client(engine, service) as c:
        uid = await _uid(service, "u2")
        for action in ("reset-mfa", "revoke-sessions"):
            r = await c.post(f"/ui/users/{uid}/{action}", headers={"Sec-Fetch-Site": "same-origin"})
            assert r.status_code == 303, action
            assert r.headers["location"] == f"/ui/users/{uid}", action


async def test_delete_user_roundtrip_and_self_guard(engine: Engine) -> None:
    service = await _service(engine)
    await _add(service, "u2", Role.VIEWER)
    async with _boss_client(engine, service) as c:
        uid = await _uid(service, "u2")
        r = await c.post(f"/ui/users/{uid}/delete", headers={"Sec-Fetch-Site": "same-origin"})
        assert r.status_code == 303 and r.headers["location"] == "/ui/users"
        assert await service.store.get_user(uid) is None
        boss_id = await _uid(service, "boss")
        r = await c.post(f"/ui/users/{boss_id}/delete", headers={"Sec-Fetch-Site": "same-origin"})
        assert r.status_code == 400 and "cannot delete your own account" in r.text
        assert await service.store.get_user(boss_id) is not None


async def test_custom_role_lifecycle_via_ui(engine: Engine) -> None:
    service = await _service(engine)
    async with _boss_client(engine, service) as c:
        # Create.
        r = await _post_pairs(
            c,
            "/ui/roles/custom",
            [
                ("display_name", "Ops Lite"),
                ("description", "read-only ops"),
                ("permissions", "monitoring:read"),
                ("permissions", "messages:read"),
            ],
        )
        assert r.status_code == 303
        customs = await service.list_custom_roles()
        assert len(customs) == 1 and customs[0].display_name == "Ops Lite"
        role_id = customs[0].id
        # Listed + editable.
        assert "Ops Lite" in (await c.get("/ui/roles")).text
        assert (await c.get(f"/ui/roles/{role_id}/edit")).status_code == 200
        # Update narrows the permission set.
        r = await _post_pairs(
            c,
            f"/ui/roles/custom/{role_id}/update",
            [("display_name", "Ops Lite"), ("permissions", "monitoring:read")],
        )
        assert r.status_code == 303
        customs = await service.list_custom_roles()
        assert [p.value for p in customs[0].permissions] == ["monitoring:read"]
        # Delete.
        r = await c.post(
            f"/ui/roles/custom/{role_id}/delete", headers={"Sec-Fetch-Site": "same-origin"}
        )
        assert r.status_code == 303
        assert await service.list_custom_roles() == []


async def test_custom_role_forbidden_permission_rejected(engine: Engine) -> None:
    # The escalation carve-outs (ADR 0045 D1) are not offered on the form AND are refused if posted.
    service = await _service(engine)
    async with _boss_client(engine, service) as c:
        form = await c.get("/ui/roles/new")
        assert form.status_code == 200
        assert 'value="users:manage"' not in form.text  # not offered
        r = await _post_pairs(
            c,
            "/ui/roles/custom",
            [("display_name", "Sneaky"), ("permissions", "users:manage")],
        )
        assert r.status_code == 400  # refused by the service's validator
        assert await service.list_custom_roles() == []


async def test_builtin_role_edit_is_404(engine: Engine) -> None:
    service = await _service(engine)
    async with _boss_client(engine, service) as c:
        assert (await c.get("/ui/roles/administrator/edit")).status_code == 404


async def test_ad_group_maps_roundtrip(engine: Engine) -> None:
    service = await _service(engine)
    async with _boss_client(engine, service) as c:
        assert (await c.get("/ui/ad-groups")).status_code == 200
        # Role map: one real row + one blank filler row (dropped).
        r = await _post_pairs(
            c,
            "/ui/ad-groups/map",
            [
                ("ad_group", "MEFOR-Admins"),
                ("role", "administrator"),
                ("ad_group", ""),
                ("role", ""),
            ],
        )
        assert r.status_code == 303
        rows = await service.store.list_ad_group_role_map()
        assert [(x["ad_group"], x["role_id"]) for x in rows] == [
            ("mefor-admins", "administrator")
        ]  # groups are case-normalized
        # Unknown role id: 400, map unchanged.
        r = await _post_pairs(c, "/ui/ad-groups/map", [("ad_group", "G2"), ("role", "not-a-role")])
        assert r.status_code == 400 and "unknown role" in r.text
        assert len(await service.store.list_ad_group_role_map()) == 1
        # Scope map round-trip.
        r = await _post_pairs(
            c, "/ui/ad-groups/scope-map", [("ad_group", "MEFOR-Ops"), ("channel", "*")]
        )
        assert r.status_code == 303
        rows = await service.store.list_ad_group_scope_map()
        assert [(x["ad_group"], x["channel"]) for x in rows] == [("mefor-ops", "*")]


async def test_admin_pages_escape_hostile_display_name(engine: Engine) -> None:
    # An admin-entered display name is DATA: it must render escaped on the list + detail pages.
    service = await _service(engine)
    async with _boss_client(engine, service) as c:
        r = await c.post(
            "/ui/users",
            data={
                "username": "hostile",
                "password": PW,
                "display_name": "<script>alert(9)</script>",
            },
            headers={"Sec-Fetch-Site": "same-origin"},
        )
        assert r.status_code == 303
        for url in ("/ui/users", r.headers["location"]):
            body = (await c.get(url)).text
            assert "<script>alert(9)</script>" not in body
            assert "&lt;script&gt;alert(9)&lt;/script&gt;" in body


# --- L4a review-driven regressions (adversarial review PR2: 1 high, 1 medium, test gaps) -----------


async def _add_with_role_ids(service: AuthService, username: str, role_ids: list[str]) -> None:
    """Like _add, but with raw role ids (so a CUSTOM role can be assigned)."""
    user_id = await service.create_local_user(
        username=username,
        password=PW,
        display_name=None,
        email=None,
        roles=role_ids,
        actor="test",
    )
    user = await service.store.get_user(user_id)
    assert user is not None and user.password_hash is not None
    await service.store.set_password(
        user_id, password_hash=user.password_hash, must_change_password=False
    )


async def test_ad_group_map_asymmetric_rows_never_cross_bind(engine: Engine) -> None:
    # PR2-H1 regression: blank fields MUST keep their positional slot (keep_blank_values=True) so a
    # role selected on one row can never bind to a group typed on another. Both rows here are
    # incomplete row-wise (one lost its group, the other never chose a role) — both are dropped.
    service = await _service(engine)
    async with _boss_client(engine, service) as c:
        r = await _post_pairs(
            c,
            "/ui/ad-groups/map",
            [
                ("ad_group", ""),  # row 1: group cleared...
                ("role", "administrator"),  # ...but its select still says administrator
                ("ad_group", "G2"),  # row 2: new group typed...
                ("role", ""),  # ...role never selected
            ],
        )
        assert r.status_code == 303
        # No cross-bound G2->administrator entry — the map is empty (both rows dropped row-wise).
        assert await service.store.list_ad_group_role_map() == []
        # Same invariant on the scope map (the '*' all-channels grant must never cross-bind).
        r = await _post_pairs(
            c,
            "/ui/ad-groups/scope-map",
            [("ad_group", ""), ("channel", "*"), ("ad_group", "G3"), ("channel", "")],
        )
        assert r.status_code == 303
        assert await service.store.list_ad_group_scope_map() == []


async def test_stale_stepup_bounces_body_less_action_via_reauth(engine: Engine) -> None:
    # A body-less auto-retry action under a stale window 303s to /ui/reauth carrying ITS OWN path
    # (no reauth_next mapping) — and nothing is deleted until the retry actually runs.
    service = AuthService(engine.store, AuthSettings(step_up_max_age_seconds=-1))
    await service.initialize()
    await _add(service, "u9", Role.VIEWER)
    async with _boss_client(engine, service) as c:
        uid = await _uid(service, "u9")
        r = await c.post(f"/ui/users/{uid}/delete", headers={"Sec-Fetch-Site": "same-origin"})
        assert r.status_code == 303
        assert r.headers["location"] == f"/ui/reauth?next=/ui/users/{uid}/delete"
        assert await service.store.get_user(uid) is not None  # nothing happened yet


async def test_stale_stepup_bounces_all_unlock_form_pages(engine: Engine) -> None:
    # Every unlock FORM page is step-up-gated: a stale window 303s each to /ui/reauth with its own
    # path as next (a regression to plain require_ui would silently drop the step-up gate).
    service = AuthService(engine.store, AuthSettings(step_up_max_age_seconds=-1))
    await service.initialize()
    await _add(service, "u9", Role.VIEWER)
    async with _boss_client(engine, service) as c:
        uid = await _uid(service, "u9")
        for path in (f"/ui/users/{uid}", "/ui/roles/new", "/ui/ad-groups"):
            r = await c.get(path)
            assert r.status_code == 303, path
            assert r.headers["location"] == f"/ui/reauth?next={path}", path
        # The custom-role edit form too (its role id is percent-encoded in the redirect).
        r = await c.get("/ui/roles/custom:x/edit")
        assert r.status_code == 303
        assert r.headers["location"].startswith("/ui/reauth?next=")


async def test_users_read_only_role_cannot_reach_admin_writes(engine: Engine) -> None:
    # users:read is grantable via a custom role (users:manage is a forbidden carve-out): such a user
    # sees the read pages but every form page and write is refused — the read/manage split is real.
    service = await _service(engine)
    role = await service.create_custom_role(
        display_name="User Auditor",
        description=None,
        permissions=["users:read", "monitoring:read"],
        actor="test",
    )
    await _add_with_role_ids(service, "reader", [role.id])
    async with _client(engine, service) as c:
        await _cookie_login(c, "reader")
        assert (await c.get("/ui/users")).status_code == 200
        assert (await c.get("/ui/roles")).status_code == 200
        for get_path in ("/ui/users/new", "/ui/ad-groups"):
            assert (await c.get(get_path)).status_code == 403, get_path
        r = await c.post(
            "/ui/users",
            data={"username": "nope", "password": PW},
            headers={"Sec-Fetch-Site": "same-origin"},
        )
        assert r.status_code == 403
        assert await service.store.get_user_by_username("nope") is None


async def test_all_admin_posts_reject_cross_site(engine: Engine) -> None:
    # assert_same_origin is a per-route inline call — sweep EVERY state-changing admin POST so a
    # forgotten call in any one route fails loudly.
    service = await _service(engine)
    async with _boss_client(engine, service) as c:
        boss_id = await _uid(service, "boss")
        posts = [
            "/ui/users",
            f"/ui/users/{boss_id}/update",
            f"/ui/users/{boss_id}/roles",
            f"/ui/users/{boss_id}/channel-scope",
            f"/ui/users/{boss_id}/reset-password",
            f"/ui/users/{boss_id}/reset-mfa",
            f"/ui/users/{boss_id}/revoke-sessions",
            f"/ui/users/{boss_id}/delete",
            "/ui/roles/custom",
            "/ui/roles/custom/custom:x/update",
            "/ui/roles/custom/custom:x/delete",
            "/ui/ad-groups/map",
            "/ui/ad-groups/scope-map",
            # L5a (ADR 0068): the passkey POSTs join the sweep (AC-9).
            "/ui/account/webauthn/enroll",
            "/ui/account/webauthn/verify",
            "/ui/account/webauthn/abc123/delete",
            "/ui/reauth/webauthn",
        ]
        for path in posts:
            r = await c.post(path, headers={"Sec-Fetch-Site": "cross-site"})
            assert r.status_code == 403, path


async def test_admin_cookie_not_accepted_on_json_routes(engine: Engine) -> None:
    # The /ui cookie must never authorize the JSON admin analogues (bearer-header only).
    service = await _service(engine)
    async with _boss_client(engine, service) as c:
        boss_id = await _uid(service, "boss")
        assert (await c.get("/users")).status_code == 401
        assert (await c.get("/roles")).status_code == 401
        assert (await c.get("/ad-group-map")).status_code == 401
        assert (
            await c.put(f"/users/{boss_id}/roles", json={"roles": ["viewer"]})
        ).status_code == 401
        assert (await c.delete(f"/users/{boss_id}")).status_code == 401


async def test_error_banner_escapes_hostile_input(engine: Engine) -> None:
    # _validate_roles echoes posted role ids into the 400 detail; the /ui banner must render it
    # escaped (reflected-XSS regression guard for every rerender-with-error path).
    service = await _service(engine)
    await _add(service, "u1", Role.VIEWER)
    async with _boss_client(engine, service) as c:
        uid = await _uid(service, "u1")
        hostile = "<img src=x onerror=alert(1)>"
        r = await _post_pairs(c, f"/ui/users/{uid}/roles", [("roles", hostile)])
        assert r.status_code == 400
        assert hostile not in r.text
        assert "&lt;img src=x onerror=alert(1)&gt;" in r.text


async def test_ad_user_carveouts_on_ui_surface(engine: Engine) -> None:
    # An AD account: roles come from the AD-group map and the password from the directory — the
    # detail page hides those forms, and a forged direct POST is refused by the handler guards.
    service = await _service(engine)
    await service.store.create_user(
        user_id="ad-user-1", username="aduser", auth_provider="ad", display_name="AD User"
    )
    async with _boss_client(engine, service) as c:
        detail = await c.get("/ui/users/ad-user-1")
        assert detail.status_code == 200
        assert "AD users get roles from the AD-group map" in detail.text
        assert 'action="/ui/users/ad-user-1/roles"' not in detail.text
        assert 'action="/ui/users/ad-user-1/reset-password"' not in detail.text
        r = await _post_pairs(c, "/ui/users/ad-user-1/roles", [("roles", "viewer")])
        assert r.status_code == 400 and "AD-group map" in r.text
        assert await service.store.get_user_role_ids("ad-user-1") == []
        r = await c.post(
            "/ui/users/ad-user-1/reset-password", headers={"Sec-Fetch-Site": "same-origin"}
        )
        assert r.status_code == 400  # only local users have an engine password


# --- L4b: self-service account (change password + TOTP MFA lifecycle), #75 phase 4 -----------------
#
# Change-password has NO step-up gate (the current password in the body IS the proof) and its POST is
# in neither continuation registry. MFA enroll/disable are body-less auto_retry actions gated by the
# password-only require_ui_reauth_only (an MFA gate would deadlock first enrollment); the confirm-code
# POST (/verify) is body-carrying with a standalone GET form (/confirm) as its unlock re-entry point.

NEW_PW = "another-strong-test-passphrase"


async def test_account_page_renders(engine: Engine) -> None:
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    async with _client(engine, service) as c:
        await _cookie_login(c, "op")
        r = await c.get("/ui/account")
        assert r.status_code == 200
        assert "Signed in as op" in r.text
        assert "Not enrolled" in r.text  # MFA posture
        assert 'href="/ui/account/password"' in r.text
        assert 'href="/ui/account"' in r.text  # the nav entry
        # Anonymous → login.
        c.cookies.clear()
        assert (await c.get("/ui/account")).status_code == 303


async def test_password_change_roundtrip(engine: Engine) -> None:
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    async with _client(engine, service) as c:
        await _cookie_login(c, "op")
        r = await c.post(
            "/ui/account/password",
            data={"current_password": PW, "new_password": NEW_PW, "new_password2": NEW_PW},
            headers={"Sec-Fetch-Site": "same-origin"},
        )
        assert r.status_code == 303
        assert r.headers["location"] == "/ui/login?e=pwchanged"
        assert 'mf_session=""' in r.headers.get("set-cookie", "")  # cookie cleared
        # Every session was revoked server-side — the old cookie no longer works.
        c.cookies.clear()
        assert (await _cookie_login(c, "op")).headers[
            "location"
        ] == "/ui/login?e=bad"  # old PW dead
        r = await c.post("/ui/login", data={"username": "op", "password": NEW_PW})
        assert r.headers["location"] == "/ui"  # new password signs in


async def test_password_change_wrong_current_rerenders(engine: Engine) -> None:
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    async with _client(engine, service) as c:
        await _cookie_login(c, "op")
        r = await c.post(
            "/ui/account/password",
            data={
                "current_password": "not-the-password-at-all",
                "new_password": NEW_PW,
                "new_password2": NEW_PW,
            },
            headers={"Sec-Fetch-Site": "same-origin"},
        )
        assert r.status_code == 403
        assert "current password is incorrect" in r.text
        assert NEW_PW not in r.text  # passwords are never echoed back
        # Unchanged: the old password still logs in.
        c.cookies.clear()
        assert (await _cookie_login(c, "op")).headers["location"] == "/ui"


async def test_password_change_policy_and_mismatch(engine: Engine) -> None:
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    async with _client(engine, service) as c:
        await _cookie_login(c, "op")
        r = await c.post(
            "/ui/account/password",
            data={"current_password": PW, "new_password": "short", "new_password2": "short"},
            headers={"Sec-Fetch-Site": "same-origin"},
        )
        assert r.status_code == 400 and "password must" in r.text
        r = await c.post(
            "/ui/account/password",
            data={"current_password": PW, "new_password": NEW_PW, "new_password2": "different"},
            headers={"Sec-Fetch-Site": "same-origin"},
        )
        assert r.status_code == 400 and "do not match" in r.text
        # Neither attempt changed anything.
        c.cookies.clear()
        assert (await _cookie_login(c, "op")).headers["location"] == "/ui"


async def test_password_change_rejects_cross_site(engine: Engine) -> None:
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    async with _client(engine, service) as c:
        await _cookie_login(c, "op")
        r = await c.post(
            "/ui/account/password",
            data={"current_password": PW, "new_password": NEW_PW, "new_password2": NEW_PW},
            headers={"Sec-Fetch-Site": "cross-site"},
        )
        assert r.status_code == 403


async def test_must_change_account_is_confined_to_rotation(engine: Engine) -> None:
    # A must-change account: login lands on the rotation page, every other /ui route bounces back
    # there, and completing the rotation releases it (browser-only — no desktop console needed).
    service = await _service(engine)
    await service.create_local_user(
        username="fresh",
        password=PW,
        display_name=None,
        email=None,
        roles=[Role.VIEWER.value],
        actor="test",
    )  # create_local_user leaves must_change_password=True
    async with _client(engine, service) as c:
        r = await _cookie_login(c, "fresh")
        assert r.headers["location"] == "/ui/account/password"  # login → rotation page
        for path in ("/ui", "/ui/account", "/ui/messages"):
            r = await c.get(path)
            assert r.status_code == 303, path
            assert r.headers["location"] == "/ui/account/password", path
        r = await c.get("/ui/account/password")
        assert r.status_code == 200
        assert "must be changed before you can continue" in r.text  # the forced variant
        r = await c.post(
            "/ui/account/password",
            data={"current_password": PW, "new_password": NEW_PW, "new_password2": NEW_PW},
            headers={"Sec-Fetch-Site": "same-origin"},
        )
        assert r.status_code == 303 and r.headers["location"] == "/ui/login?e=pwchanged"
        c.cookies.clear()
        r = await c.post("/ui/login", data={"username": "fresh", "password": NEW_PW})
        assert r.headers["location"] == "/ui"  # released
        assert (await c.get("/ui")).status_code == 200


async def test_mfa_enroll_confirm_disable_lifecycle(engine: Engine) -> None:
    from messagefoundry.auth import totp as totp_mod

    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    async with _client(engine, service) as c:
        await _cookie_login(c, "op")
        # Enroll: stages a secret, renders it once with the confirm form.
        r = await c.post("/ui/account/mfa/enroll", headers={"Sec-Fetch-Site": "same-origin"})
        assert r.status_code == 200
        assert "Secret:" in r.text and "otpauth://" in r.text
        assert 'action="/ui/account/mfa/verify"' in r.text
        uid = await _uid(service, "op")
        secret = await service.store.get_totp_secret(uid)
        assert secret and secret in r.text  # the staged secret is what the page shows
        # Confirm with a live code → recovery codes shown once; MFA active.
        r = await c.post(
            "/ui/account/mfa/verify",
            data={"code": totp_mod.totp(secret)},
            headers={"Sec-Fetch-Site": "same-origin"},
        )
        assert r.status_code == 200
        assert "Recovery codes" in r.text or "MFA is active" in r.text
        assert "shown once" in r.text
        user = await service.store.get_user(uid)
        assert user is not None and user.totp_enabled
        r = await c.get("/ui/account")
        assert "Enabled" in r.text and "recovery code(s) remaining" in r.text
        # Disable: step-up-gated — confirm_mfa_enrollment marked THIS session MFA-verified, and the
        # fresh login is a recent password step-up, so the gate passes without a reauth bounce.
        r = await c.post("/ui/account/mfa/disable", headers={"Sec-Fetch-Site": "same-origin"})
        assert r.status_code == 303 and r.headers["location"] == "/ui/account?m=mfa_off"
        user = await service.store.get_user(uid)
        assert user is not None and not user.totp_enabled
        assert "MFA disabled." in (await c.get("/ui/account?m=mfa_off")).text


async def test_mfa_verify_wrong_code_and_no_enrollment(engine: Engine) -> None:
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    async with _client(engine, service) as c:
        await _cookie_login(c, "op")
        # No enrollment staged yet → back to the account page with the service's message.
        r = await c.post(
            "/ui/account/mfa/verify",
            data={"code": "123456"},
            headers={"Sec-Fetch-Site": "same-origin"},
        )
        assert r.status_code == 400 and "no enrollment in progress" in r.text
        # Stage one, then a wrong (non-numeric) code re-renders the confirm form; MFA stays off.
        await c.post("/ui/account/mfa/enroll", headers={"Sec-Fetch-Site": "same-origin"})
        r = await c.post(
            "/ui/account/mfa/verify",
            data={"code": "badcod"},
            headers={"Sec-Fetch-Site": "same-origin"},
        )
        assert r.status_code == 400 and "Invalid code." in r.text
        uid = await _uid(service, "op")
        user = await service.store.get_user(uid)
        assert user is not None and not user.totp_enabled


async def test_mfa_confirm_form_is_unlock_reentry(engine: Engine) -> None:
    # The standalone GET confirm form never re-shows the secret, and the L4b actions sit in the
    # right continuation registries (password POST in NEITHER).
    from messagefoundry_webconsole import is_safe_ui_action, is_unlock_action

    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    create_app(engine, auth=service, serve_ui=True)
    assert is_safe_ui_action("/ui/account/mfa/enroll")
    assert is_safe_ui_action("/ui/account/mfa/disable")
    assert is_unlock_action("/ui/account/mfa/confirm")
    assert not is_safe_ui_action("/ui/account/mfa/confirm")
    assert not is_unlock_action("/ui/account/mfa/verify")
    assert not is_safe_ui_action("/ui/account/password")
    assert not is_unlock_action("/ui/account/password")
    async with _client(engine, service) as c:
        await _cookie_login(c, "op")
        await c.post("/ui/account/mfa/enroll", headers={"Sec-Fetch-Site": "same-origin"})
        uid = await _uid(service, "op")
        secret = await service.store.get_totp_secret(uid)
        r = await c.get("/ui/account/mfa/confirm")
        assert r.status_code == 200
        assert secret is not None and secret not in r.text  # the secret is never re-shown
        assert 'action="/ui/account/mfa/verify"' in r.text


async def test_stale_reauth_only_bounces_to_reauth(engine: Engine) -> None:
    # require_ui_reauth_only under a stale window: enroll (body-less) carries its own path; the
    # body-carrying verify maps to its unlock confirm form via reauth_next.
    service = AuthService(engine.store, AuthSettings(step_up_max_age_seconds=-1))
    await service.initialize()
    await _add(service, "op", Role.OPERATOR)
    async with _client(engine, service) as c:
        await _cookie_login(c, "op")
        r = await c.post("/ui/account/mfa/enroll", headers={"Sec-Fetch-Site": "same-origin"})
        assert r.status_code == 303
        assert r.headers["location"] == "/ui/reauth?next=/ui/account/mfa/enroll"
        r = await c.post(
            "/ui/account/mfa/verify",
            data={"code": "123456"},
            headers={"Sec-Fetch-Site": "same-origin"},
        )
        assert r.status_code == 303
        assert r.headers["location"] == "/ui/reauth?next=/ui/account/mfa/confirm"
        # The change-password POST has NO step-up gate — it proceeds under the same stale window
        # (the current password in the body is the proof).
        r = await c.post(
            "/ui/account/password",
            data={"current_password": PW, "new_password": NEW_PW, "new_password2": NEW_PW},
            headers={"Sec-Fetch-Site": "same-origin"},
        )
        assert r.status_code == 303 and r.headers["location"] == "/ui/login?e=pwchanged"


async def test_reauth_never_demands_code_from_unenrolled_user(engine: Engine) -> None:
    # The deadlock fix, half 1: a require_mfa deployment with an UNENROLLED user under a stale
    # window — the reauth page must ask for the password only (the user has no authenticator yet),
    # and a password-only re-auth must unlock the enroll action. (The -1 window keeps step-up
    # permanently stale, so the enroll completion itself is the next test, under a normal window.)
    service = AuthService(engine.store, AuthSettings(require_mfa=True, step_up_max_age_seconds=-1))
    await service.initialize()
    await _add(service, "boss", Role.ADMINISTRATOR)
    async with _client(engine, service) as c:
        await _cookie_login(c, "boss")
        # Stale window → enroll bounces to reauth; the form must NOT demand a TOTP code.
        r = await c.get("/ui/reauth", params={"next": "/ui/account/mfa/enroll"})
        assert r.status_code == 200
        assert 'name="password"' in r.text
        assert 'name="code"' not in r.text  # nothing to type — no authenticator exists yet
        # Password-only re-auth unlocks the body-less enroll action (auto-submit page).
        r = await c.post(
            "/ui/reauth",
            data={"next": "/ui/account/mfa/enroll", "password": PW},
            headers={"Sec-Fetch-Site": "same-origin"},
        )
        assert r.status_code == 200 and "data-autosubmit" in r.text


async def test_require_mfa_unenrolled_can_enroll_end_to_end(engine: Engine) -> None:
    # The deadlock fix, half 2 — the TRUE production flow: under require_mfa an MFA-pending session
    # deliberately gets NO step-up freshness from login (WP-14: a stolen pre-MFA token must not bind
    # an attacker's authenticator), so browser enrollment goes login → enroll → reauth (password
    # ONLY, no impossible code demand) → auto-retried enroll → confirm — completing end-to-end.
    from messagefoundry.auth import totp as totp_mod

    service = AuthService(engine.store, AuthSettings(require_mfa=True))
    await service.initialize()
    await _add(service, "boss", Role.ADMINISTRATOR)
    async with _client(engine, service) as c:
        await _cookie_login(c, "boss")
        # The MFA-pending session has no step-up freshness → enroll bounces to reauth.
        r = await c.post("/ui/account/mfa/enroll", headers={"Sec-Fetch-Site": "same-origin"})
        assert r.status_code == 303
        assert r.headers["location"] == "/ui/reauth?next=/ui/account/mfa/enroll"
        # The reauth form asks for the password ONLY (no authenticator exists yet — the fix).
        r = await c.get("/ui/reauth", params={"next": "/ui/account/mfa/enroll"})
        assert r.status_code == 200 and 'name="code"' not in r.text
        r = await c.post(
            "/ui/reauth",
            data={"next": "/ui/account/mfa/enroll", "password": PW},
            headers={"Sec-Fetch-Site": "same-origin"},
        )
        assert r.status_code == 200 and "data-autosubmit" in r.text  # auto-retry the enroll
        # The re-POSTed enroll now succeeds inside the refreshed window.
        r = await c.post("/ui/account/mfa/enroll", headers={"Sec-Fetch-Site": "same-origin"})
        assert r.status_code == 200 and "Secret:" in r.text
        uid = await _uid(service, "boss")
        secret = await service.store.get_totp_secret(uid)
        assert secret is not None
        r = await c.post(
            "/ui/account/mfa/verify",
            data={"code": totp_mod.totp(secret)},
            headers={"Sec-Fetch-Site": "same-origin"},
        )
        assert r.status_code == 200 and "shown once" in r.text
        user = await service.store.get_user(uid)
        assert user is not None and user.totp_enabled


# --- L4b review-driven regressions (adversarial review: 2 behavior bugs + coverage gaps) -----------


async def _enroll_mfa(c: httpx.AsyncClient, service: AuthService, username: str) -> str:
    """Enroll + confirm TOTP for `username` via the /ui flow; return the secret (for later codes)."""
    from messagefoundry.auth import totp as totp_mod

    await c.post("/ui/account/mfa/enroll", headers={"Sec-Fetch-Site": "same-origin"})
    uid = await _uid(service, username)
    secret = await service.store.get_totp_secret(uid)
    assert secret is not None
    r = await c.post(
        "/ui/account/mfa/verify",
        data={"code": totp_mod.totp(secret)},
        headers={"Sec-Fetch-Site": "same-origin"},
    )
    assert r.status_code == 200
    return secret


async def test_reauth_confines_must_change_session(engine: Engine) -> None:
    # Review bug [0]: /ui/reauth (GET+POST) must mirror require_ui's must-change confinement — the JSON
    # /me/reauth twin refuses a must-change session, so the /ui gate must not be weaker.
    service = await _service(engine)
    await service.create_local_user(
        username="fresh",
        password=PW,
        display_name=None,
        email=None,
        roles=[Role.OPERATOR.value],
        actor="test",
    )  # must_change_password stays True
    async with _client(engine, service) as c:
        await _cookie_login(c, "fresh")
        r = await c.get("/ui/reauth", params={"next": "/ui/messages/M1/replay"})
        assert r.status_code == 303 and r.headers["location"] == "/ui/account/password"
        r = await c.post(
            "/ui/reauth",
            data={"next": "/ui/messages/M1/replay", "password": PW},
            headers={"Sec-Fetch-Site": "same-origin"},
        )
        assert r.status_code == 303 and r.headers["location"] == "/ui/account/password"


async def test_required_unenrolled_full_stepup_routes_to_enroll_not_loop(engine: Engine) -> None:
    # Review bug [1]: under require_mfa an unenrolled user hitting a FULL-step-up action must be sent to
    # enroll — never a password form that "accepts" the credential then bounces straight back forever.
    service = AuthService(engine.store, AuthSettings(require_mfa=True))
    await service.initialize()
    await _add(service, "boss", Role.ADMINISTRATOR)
    async with _client(engine, service) as c:
        await _cookie_login(c, "boss")
        # A full-step-up admin form (L4a) → require_ui_step_up bounces to /ui/reauth...
        r = await c.get("/ui/users/new")
        assert r.status_code == 303 and r.headers["location"] == "/ui/reauth?next=/ui/users/new"
        # ...and /ui/reauth sends an unenrolled required user to enroll, not a looping password form.
        r = await c.get("/ui/reauth", params={"next": "/ui/users/new"})
        assert r.status_code == 303 and r.headers["location"] == "/ui/account?m=enroll_first"
        # The POST does the same BEFORE consuming a rate-limit token (no correct-password → 429 loop).
        r = await c.post(
            "/ui/reauth",
            data={"next": "/ui/users/new", "password": PW},
            headers={"Sec-Fetch-Site": "same-origin"},
        )
        assert r.status_code == 303 and r.headers["location"] == "/ui/account?m=enroll_first"
        assert "enroll an authenticator" in (await c.get("/ui/account?m=enroll_first")).text
        # But the enrollment path (step_up=False) is NOT diverted — password-only reauth still unlocks it.
        r = await c.get("/ui/reauth", params={"next": "/ui/account/mfa/enroll"})
        assert r.status_code == 200 and 'name="code"' not in r.text


async def test_reauth_demands_code_from_enrolled_unverified_session(engine: Engine) -> None:
    # WP-14 positive case: an ENROLLED-but-unverified session must still get the TOTP code demand
    # (the enrolled-aware condition must not have weakened the code requirement).
    service = AuthService(engine.store, AuthSettings())
    await service.initialize()
    await _add(service, "op", Role.OPERATOR)
    async with _client(engine, service) as c:
        await _cookie_login(c, "op")
        await _enroll_mfa(c, service, "op")
        # A fresh login is enrolled but NOT MFA-verified (login leaves the 2nd factor pending).
        c.cookies.clear()
        await _cookie_login(c, "op")
        r = await c.get("/ui/reauth", params={"next": "/ui/messages/M1/replay"})
        assert r.status_code == 200
        assert 'name="password"' in r.text and 'name="code"' in r.text  # BOTH factors demanded


async def test_disable_mfa_enforces_full_stepup_when_stale(engine: Engine) -> None:
    # Disable is require_ui_step_up (full step-up incl. MFA), matching the JSON DELETE /me/mfa: an
    # enrolled-but-unverified session is bounced to /ui/reauth, and MFA stays on until re-verified.
    service = AuthService(engine.store, AuthSettings())
    await service.initialize()
    await _add(service, "op", Role.OPERATOR)
    async with _client(engine, service) as c:
        await _cookie_login(c, "op")
        await _enroll_mfa(c, service, "op")
        uid = await _uid(service, "op")
        c.cookies.clear()  # a fresh (enrolled, MFA-unverified) session
        await _cookie_login(c, "op")
        r = await c.post("/ui/account/mfa/disable", headers={"Sec-Fetch-Site": "same-origin"})
        assert r.status_code == 303
        assert r.headers["location"] == "/ui/reauth?next=/ui/account/mfa/disable"
        user = await service.store.get_user(uid)
        assert user is not None and user.totp_enabled  # still on — the gate held


async def test_mfa_posts_reject_cross_site(engine: Engine) -> None:
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    async with _client(engine, service) as c:
        await _cookie_login(c, "op")
        for path in (
            "/ui/account/mfa/enroll",
            "/ui/account/mfa/verify",
            "/ui/account/mfa/disable",
        ):
            r = await c.post(path, headers={"Sec-Fetch-Site": "cross-site"})
            assert r.status_code == 403, path
        uid = await _uid(service, "op")
        assert await service.store.get_totp_secret(uid) is None  # nothing staged


async def test_must_change_confinement_on_posts_and_reauth_continuation(engine: Engine) -> None:
    # Confinement covers POSTs and the /ui/reauth-driven continuation, not just GETs.
    service = await _service(engine)
    await service.create_local_user(
        username="fresh",
        password=PW,
        display_name=None,
        email=None,
        roles=[Role.ADMINISTRATOR.value],
        actor="test",
    )
    async with _client(engine, service) as c:
        await _cookie_login(c, "fresh")
        # A state-changing POST is bounced, not executed.
        r = await c.post("/ui/account/mfa/enroll", headers={"Sec-Fetch-Site": "same-origin"})
        assert r.status_code == 303 and r.headers["location"] == "/ui/account/password"
        uid = await _uid(service, "fresh")
        assert await service.store.get_totp_secret(uid) is None
        # Even the reauth continuation can't be used to slip past confinement.
        r = await c.post(
            "/ui/reauth",
            data={"next": "/ui/account/mfa/enroll", "password": PW},
            headers={"Sec-Fetch-Site": "same-origin"},
        )
        assert r.status_code == 303 and r.headers["location"] == "/ui/account/password"


async def test_l4b_rate_limit_paths(engine: Engine) -> None:
    # The 429 contracts: change-password re-raises the JSON 429 (not a 400 HTML re-render); mfa/verify
    # raises _rate_limited. A throttle must never mutate state.
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)

    def _deny(_client: str | None) -> bool:
        return False

    async with _client(engine, service) as c:
        await _cookie_login(c, "op")
        await c.post("/ui/account/mfa/enroll", headers={"Sec-Fetch-Site": "same-origin"})
        service.allow_login_attempt = _deny  # type: ignore[method-assign]
        r = await c.post(
            "/ui/account/password",
            data={"current_password": PW, "new_password": NEW_PW, "new_password2": NEW_PW},
            headers={"Sec-Fetch-Site": "same-origin"},
        )
        assert r.status_code == 429
        r = await c.post(
            "/ui/account/mfa/verify",
            data={"code": "123456"},
            headers={"Sec-Fetch-Site": "same-origin"},
        )
        assert r.status_code == 429
        uid = await _uid(service, "op")
        user = await service.store.get_user(uid)
        assert user is not None and not user.totp_enabled  # nothing activated


async def test_account_cookie_not_accepted_on_json_routes(engine: Engine) -> None:
    # The /ui cookie must never authorize the JSON self-service routes (bearer-header only).
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    async with _client(engine, service) as c:
        await _cookie_login(c, "op")
        assert (
            await c.post("/me/password", json={"current_password": PW, "new_password": NEW_PW})
        ).status_code == 401
        assert (await c.post("/me/mfa/enroll")).status_code == 401
        assert (await c.post("/me/mfa/confirm", json={"code": "123456"})).status_code == 401
        assert (await c.delete("/me/mfa")).status_code == 401


# --- content-search (step-up-unlock GET over the JSON search) + L1c audit view --------------------


async def test_search_page_renders_bare_form(engine: Engine) -> None:
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    async with _client(engine, service) as c:
        await _cookie_login(c, "op")
        r = await c.get("/ui/messages/search")
        assert r.status_code == 200
        assert 'action="/ui/messages/search"' in r.text
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
    service = AuthService(engine.store, AuthSettings(step_up_max_age_seconds=-1))
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
        r = await c.get(
            "/ui/messages/search",
            params={"content": '"><script>alert(1)</script>'},
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


async def _browser_enroll(c: httpx.AsyncClient, *, label: str) -> object:
    """Run the full browser registration ceremony; returns the enrolled soft authenticator."""
    from webauthn.helpers import base64url_to_bytes

    from tests._soft_webauthn import SoftAuthenticator

    r = await c.post("/ui/account/webauthn/enroll", headers=_SFS)
    assert r.status_code == 200, r.text
    options = _data_attr(r.text, "data-mf-webauthn-create")
    auth = SoftAuthenticator(rp_id="t", origin="http://t")
    resp = json.loads(auth.create_response(base64url_to_bytes(options["challenge"])))
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
    service = AuthService(engine.store, AuthSettings(require_mfa=True))
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
        r = await c.post("/ui/account/webauthn/enroll", headers=_SFS)
        assert r.status_code == 200 and "data-mf-webauthn-create" in r.text


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
        await service.store.set_totp_secret(boss_id, secret=secret)
        await service.store.enable_totp(boss_id, recovery_code_hashes=[])

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


async def test_webauthn_cross_site_posts_rejected(engine: Engine) -> None:
    # AC-9: every new /ui POST joins the cross-site sweep (403 via assert_same_origin).
    service = await _service(engine)
    async with _boss_client(engine, service) as c:
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
    service = await _service(engine)
    await _add(service, "boss", Role.ADMINISTRATOR)
    transport = httpx.ASGITransport(
        app=create_app(engine, auth=service, serve_ui=True, webauthn_rp_from_request=False)
    )
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        await _cookie_login(c, "boss")
        r = await c.get("/ui/account")
        assert "public_origin is not set" in r.text
        r = await c.post("/ui/account/webauthn/enroll", headers=_SFS)
        assert r.status_code == 409 and "public_origin is not set" in r.text
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
    from messagefoundry.auth.ldap import AdPrincipal

    principal = AdPrincipal(
        username="jdoe",
        display_name="J Doe",
        email="j@x",
        dn="CN=jdoe,DC=x",
        groups=frozenset({"cn=mf-admins,dc=x"}),
    )

    class _FakeLdap:
        def authenticate(self, username: str, password: str) -> AdPrincipal | None:
            return principal if (username == "jdoe" and password == "pw") else None

        def resolve_principal(self, username: str) -> AdPrincipal | None:
            return principal if username == "jdoe" else None

    settings = AuthSettings(
        ad_enabled=True,
        ad_server="ldaps://x",
        ad_user_search_base="DC=x",
        ad_bind_dn="CN=svc,DC=x",
        ad_bind_password="x",
    )
    return AuthService(engine.store, settings, ldap=_FakeLdap())  # type: ignore[arg-type]


async def test_login_provider_select_renders_only_with_ad(engine: Engine) -> None:
    # Zero visual change for local-only installs; the selector appears when AD is enabled.
    service = await _service(engine)
    async with _client(engine, service) as c:
        r = await c.get("/ui/login")
        assert 'name="provider"' not in r.text
    ad = _ad_service(engine)
    await ad.initialize()
    async with _client(engine, ad) as c:
        r = await c.get("/ui/login")
        assert 'name="provider"' in r.text and "Active Directory" in r.text


async def test_ad_password_browser_login(engine: Engine) -> None:
    # provider=ad rides the SAME auth.login seam: one cookie session, MFA-delegated (AD), and the
    # /ui surface treats it exactly like the JSON path's AD identity.
    ad = _ad_service(engine)
    await ad.initialize()
    async with _client(engine, ad) as c:
        r = await c.post("/ui/login", data={"username": "jdoe", "password": "pw", "provider": "ad"})
        assert r.status_code == 303 and r.headers["location"] == "/ui"
        r = await c.get("/ui/account")
        assert r.status_code == 200 and "Signed in as jdoe (ad)" in r.text
        # Wrong AD password stays a generic bad-credentials bounce.
        c.cookies.clear()
        r = await c.post(
            "/ui/login", data={"username": "jdoe", "password": "nope", "provider": "ad"}
        )
        assert r.status_code == 303 and r.headers["location"] == "/ui/login?e=bad"


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
    from messagefoundry.auth.ldap import AdPrincipal

    principal = AdPrincipal(
        username="jdoe",
        display_name="J Doe",
        email="j@x",
        dn="CN=jdoe,DC=x",
        groups=frozenset({"cn=mf-admins,dc=x"}),
    )

    class _FakeLdap:
        def authenticate(self, username: str, password: str) -> AdPrincipal | None:
            return principal if (username == "jdoe" and password == "pw") else None

        def resolve_principal(self, username: str) -> AdPrincipal | None:
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
        for a in audit  # login_failed = mocked rejects; login_error = the REAL pyspnego path (the JSON
        # /auth/negotiate unchanged-endpoint pin runs it live; SSPI rejects the fake token).
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


async def test_sso_session_not_reauth_seeded(
    engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    # AC-14: the SSO proof is AMBIENT — the session is born WITHOUT a step-up window (a step_up
    # action 303s to /ui/reauth), and the directory-password reauth then completes it. The
    # AD-password login and the JSON /auth/negotiate keep seeding (the recorded asymmetry pins).
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
        assert sessions[0].mfa_verified_at is not None  # directory-delegated MFA

        # The directory-password step-up completes at /ui/reauth (auth.reauth live-rebinds AD).
        r = await c.post(
            "/ui/reauth",
            data={"next": "/ui/account/webauthn/enroll", "password": "pw"},
            headers=_SFS,
        )
        assert r.status_code == 200 and 'action="/ui/account/webauthn/enroll"' in r.text

    # The regression pins: AD-password login + JSON negotiate still SEED reauth (default True).
    out = await service.login("jdoe", "pw", provider=AuthProvider.AD)
    assert out.ok and out.token is not None
    session = await service.store.get_session(hash_token(out.token))
    assert session is not None and session.reauth_at is not None
    out = await service.authenticate_kerberos(b"tok")
    assert out.ok and out.token is not None
    session = await service.store.get_session(hash_token(out.token))
    assert session is not None and session.reauth_at is not None


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


async def test_sessions_revoke_others(engine: Engine) -> None:
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    await service.login("op", PW)  # a second session to be signed out
    async with _client(engine, service) as c:
        await _cookie_login(c, "op")
        op_id = await _uid(service, "op")
        assert len(await service.store.list_sessions(op_id)) == 2
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
        r = await c.post(
            f"/ui/account/sessions/{other_id}/revoke", headers={"Sec-Fetch-Site": "same-origin"}
        )
        assert r.status_code == 303 and r.headers["location"] == "/ui/account/sessions?m=revoked"
        remaining = {s.token_hash for s in await service.store.list_sessions(op_id)}
        assert other_id not in remaining and len(remaining) == 1


async def test_sessions_posts_reject_cross_site(engine: Engine) -> None:
    service = await _service(engine)
    async with _boss_client(engine, service) as c:
        for path in ("/ui/account/sessions/x/revoke", "/ui/account/sessions/revoke-others"):
            r = await c.post(path, headers={"Sec-Fetch-Site": "cross-site"})
            assert r.status_code == 403, path


# Gap 4 — replay ALL dead letters (every channel) --------------------------------------------------


async def _seed_dead(
    engine: Engine, *, channel: str = "IB_ACME_ADT", dest: str = "OB_ARCHIVE"
) -> None:
    mid = await engine.store.enqueue_message(
        channel_id=channel,
        raw=ADT,
        deliveries=[(dest, ADT)],
        control_id="DL1",
        message_type="ADT^A01",
        source_type="file",
    )
    outbox = await engine.store.outbox_for(mid)
    await engine.store.dead_letter_now(outbox[0]["id"], "boom")


async def test_dead_letters_shows_replay_all_button(engine: Engine) -> None:
    service = await _service(engine)
    await _seed_dead(engine)
    async with _boss_client(engine, service) as c:
        r = await c.get("/ui/dead-letters")
        assert r.status_code == 200
        assert 'action="/ui/dead-letters/replay-all"' in r.text
        assert "Replay all dead (every channel)" in r.text


async def test_replay_all_dead_letters_registered_and_gated(engine: Engine) -> None:
    from messagefoundry_webconsole import is_safe_ui_action

    # The new action is in the auto-retry allow-list (so a stale step-up can continue it).
    assert is_safe_ui_action("/ui/dead-letters/replay-all")
    service = await _service(engine)
    await _seed_dead(engine)
    async with _boss_client(engine, service) as c:
        # Cross-site is rejected before any work (assert_same_origin).
        r = await c.post("/ui/dead-letters/replay-all", headers={"Sec-Fetch-Site": "cross-site"})
        assert r.status_code == 403
        # boss is admin (replay + fresh step-up from login) → the all-channels replay runs (303
        # back to the list — the literal replay-all route, NOT captured by the {channel_id} routes).
        r = await c.post("/ui/dead-letters/replay-all", headers={"Sec-Fetch-Site": "same-origin"})
        assert r.status_code == 303 and r.headers["location"] == "/ui/dead-letters"


# Gap 5 — event-log kind filter --------------------------------------------------------------------


def test_events_filter_renders_kind_dropdown() -> None:
    from messagefoundry_webconsole.pages import events

    html = str(events([], connection="", kind="peer_reset"))
    assert 'name="kind"' in html
    assert "All kinds" in html
    # Every canonical kind is an option, and the selected one is marked.
    for k in ("established", "closed", "idle_timeout", "peer_not_allowlisted", "framing_error"):
        assert f'value="{k}"' in html
    assert 'value="peer_reset" selected' in html


async def test_events_kind_filter_applies(engine: Engine) -> None:
    service = await _service(engine)
    await _add(service, "viewer", Role.VIEWER)
    async with _client(engine, service) as c:
        await _cookie_login(c, "viewer")
        r = await c.get("/ui/events", params={"kind": "established"})
        assert r.status_code == 200
        assert 'value="established" selected' in r.text  # the filter round-trips into the form


# Gap 2 — update-available banner on /ui/status ----------------------------------------------------


def _sys_status(*, update: object = None) -> object:
    from messagefoundry.api.models import DbInfo, EngineInfo, SystemStatus

    return SystemStatus(
        engine=EngineInfo(
            version="0.2.14",
            uptime_seconds=1.0,
            pid=1,
            channels_total=1,
            channels_running=1,
            channels_stopped=0,
            outbox_by_status={},
        ),
        db=DbInfo(
            path="/x",
            size_bytes=1,
            disk_free_bytes=1,
            journal_mode="wal",
            messages=0,
            events=0,
            audit=0,
        ),
        update=update,
    )


def _status_html(sys_status: object) -> str:
    from messagefoundry.api.models import (
        ClusterNodeList,
        ClusterStatus,
        DrStatus,
        SecurityPosture,
        ServiceStatusInfo,
    )
    from messagefoundry_webconsole.pages import status

    posture = SecurityPosture(
        backend="sqlite",
        encryption_enabled=False,
        key_source="none",
        key_id=None,
        require_encryption=False,
        allow_unencrypted_phi=True,
    )
    cluster = ClusterStatus(
        node_id="n1", clustered=False, is_leader=True, role="single-node", config_version=0
    )
    dr = DrStatus(enabled=False, active=False, threshold="P1", activation_mode="manual")
    svc = ServiceStatusInfo(enabled=False, state="disabled", service_name="")
    nodes = ClusterNodeList(nodes=[], leader_node_id=None, lease_owner=None, lease_expires_at=None)
    return str(status(sys_status, posture, cluster, nodes, dr, svc))


def test_status_update_banner() -> None:
    from messagefoundry.api.models import UpdateInfo

    # update_available True → the banner renders with both version strings.
    html = _status_html(
        _sys_status(
            update=UpdateInfo(
                current_version="0.2.13", pinned_version="0.2.14", update_available=True
            )
        )
    )
    assert "newer MessageFoundry version is installed" in html
    assert "0.2.13" in html and "0.2.14" in html and "Restart the engine" in html
    # No update / not available → no banner.
    assert "newer MessageFoundry version" not in _status_html(_sys_status(update=None))
    assert "newer MessageFoundry version" not in _status_html(
        _sys_status(
            update=UpdateInfo(
                current_version="0.2.14", pinned_version="0.2.14", update_available=False
            )
        )
    )


# Gap 3 — per-connection stats reset ---------------------------------------------------------------


def _conn_row(
    role: str, channel_id: str, *, destination: str | None = None, name: str = ""
) -> object:
    from messagefoundry.api.models import ConnectionRow

    return ConnectionRow(
        role=role,
        channel_id=channel_id,
        channel_name=channel_id,
        destination=destination,
        name=name or destination or channel_id,
        status="running",
        direction="out" if role == "destination" else "in",
        method="File",
        peer=None,
        port=None,
        queue_depth=0,
        idle_seconds=None,
        alerts_active=0,
        errored=0,
        read=0 if role == "source" else None,
        written=0,
        backlog_seconds=None,
        delivered_age_seconds=None,
    )


def test_connections_fragment_has_no_per_row_control_forms() -> None:
    from messagefoundry_webconsole.pages import connections_fragment

    html = str(
        connections_fragment(
            [
                _conn_row("source", "IB_ACME_ADT"),
                _conn_row("destination", "IB_ACME_ADT", destination="OB_ARCHIVE"),
            ]
        )
    )
    # Each row exposes a single selection checkbox (both roles); NO per-row start/stop/restart/purge/reset
    # forms survive in the polled fragment — those actions moved to the un-polled dashboard toolbar.
    assert html.count("data-mf-conns-cb") == 2
    assert 'data-role="source"' in html
    assert 'data-role="destination"' in html
    assert "/ui/statistics/reset-one" not in html
    assert "Reset stats" not in html
    assert ">Start<" not in html and ">Stop<" not in html and ">Restart<" not in html
    assert "Purge top" not in html and "Purge all" not in html
    assert 'id="conns"' in html


def test_dashboard_renders_bulk_toolbar_outside_conns_fragment() -> None:
    from messagefoundry_webconsole.pages import connections_fragment, dashboard

    rows = [_conn_row("source", "IB_ACME_ADT")]
    page_html = str(dashboard(rows))
    fragment_html = str(connections_fragment(rows))
    # The toolbar hook, its action <select> options, Apply button, and feedback span live in the shell.
    assert "data-mf-conns-toolbar" in page_html
    assert "data-mf-conns-action" in page_html
    assert "data-mf-conns-apply" in page_html
    assert "data-mf-conns-feedback" in page_html
    for label in ("Start", "Stop", "Restart", "Reset stats", "Purge top", "Purge all"):
        assert f">{label}<" in page_html
    for value in ("start", "stop", "restart", "reset", "purge-top", "purge-all"):
        assert f'value="{value}"' in page_html
    # The toolbar is OUTSIDE the polled #conns fragment (a 5s / ~1s swap must never wipe it) and renders
    # BEFORE the live table in the DOM (an un-polled shell sibling).
    assert "data-mf-conns-toolbar" not in fragment_html
    assert page_html.index("data-mf-conns-toolbar") < page_html.index('id="conns"')


async def test_reset_one_statistics_route(engine: Engine) -> None:
    service = await _service(engine)
    async with _boss_client(engine, service) as c:
        r = await c.post(
            "/ui/statistics/reset-one",
            content=urlencode([("role", "source"), ("channel_id", "IB_ACME_ADT")]),
            headers={
                "Sec-Fetch-Site": "same-origin",
                "Content-Type": "application/x-www-form-urlencoded",
            },
        )
        assert r.status_code == 303 and r.headers["location"] == "/ui"
        # A malformed role bounces back to /ui without error (never a 500).
        r = await c.post(
            "/ui/statistics/reset-one",
            content=urlencode([("role", "bogus"), ("channel_id", "X")]),
            headers={
                "Sec-Fetch-Site": "same-origin",
                "Content-Type": "application/x-www-form-urlencoded",
            },
        )
        assert r.status_code == 303 and r.headers["location"] == "/ui"
        # Cross-site rejected.
        r = await c.post("/ui/statistics/reset-one", headers={"Sec-Fetch-Site": "cross-site"})
        assert r.status_code == 403


# --- Phase-2 (server side) connection controls: dual-role bulk-control, reset-many, bulk purge ------
#
# The presentation (checkbox column + dropdown toolbar + app.js) lands in a later phase; these cover the
# SERVER endpoints + the escaping result/confirm page builders + the require-quiesced/dual-control seams.


def _rowkey(role: str, channel_id: str, destination: str = "") -> str:
    """Mint a checkbox _row_key exactly as pages.connections._row_key does (the server-minted identity
    the bulk endpoints decode): role|b64url(channel_id)|b64url(destination)."""

    def b(value: str) -> str:
        return base64.urlsafe_b64encode(value.encode("utf-8")).decode("ascii")

    return f"{role}|{b(channel_id)}|{b(destination)}"


async def _start_two_out(engine: Engine, tmp_path: Path) -> None:
    """Attach two inbounds (in1/in2) both feeding two outbounds (out1/out2) and start the runner, so the
    pooled delivery dispatcher exists and outbound pause/quiesce is live. No traffic is sent — the bulk
    endpoints resolve control targets from the submitted row keys, not from dashboard edges."""
    reg = Registry()
    for name in ("in1", "in2", "out1", "out2"):
        (tmp_path / name).mkdir(exist_ok=True)
    for ib in ("in1", "in2"):
        reg.add_inbound(
            InboundConnection(
                ib,
                ConnectionSpec(
                    ConnectorType.FILE,
                    {"directory": str(tmp_path / ib), "pattern": "*.hl7", "poll_seconds": 0.05},
                ),
                router=f"r_{ib}",
            )
        )
    for ob in ("out1", "out2"):
        reg.add_outbound(
            OutboundConnection(
                ob, ConnectionSpec(ConnectorType.FILE, {"directory": str(tmp_path / ob)})
            )
        )
    reg.add_router("r_in1", lambda m: ["h"])
    reg.add_router("r_in2", lambda m: ["h"])
    reg.add_handler("h", lambda m: [Send("out1", m), Send("out2", m)])
    engine.add_registry(reg)
    await engine.start()


async def _wait_quiesced(engine: Engine, name: str) -> None:
    rr = engine.registry_runner
    assert rr is not None
    for _ in range(200):
        if rr.outbound_quiesced(name):
            return
        await asyncio.sleep(0.02)
    raise AssertionError(f"{name} never quiesced")


# --- bulk-control (dual-role start/stop/restart over a selection) ----------------------------------


async def test_bulk_control_requires_control_permission(engine: Engine) -> None:
    service = await _service(engine)
    await _add(service, "viewer", Role.VIEWER)  # no connections:control
    async with _client(engine, service) as c:
        await _cookie_login(c, "viewer")
        r = await _post_pairs(
            c,
            "/ui/connections/bulk-control",
            [("action", "stop"), ("sel", _rowkey("source", "in1"))],
        )
        assert r.status_code == 403


async def test_bulk_control_rejects_cross_site(engine: Engine) -> None:
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    async with _client(engine, service) as c:
        await _cookie_login(c, "op")
        r = await c.post(
            "/ui/connections/bulk-control",
            content=urlencode([("action", "stop")]),
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "Sec-Fetch-Site": "cross-site",
            },
        )
        assert r.status_code == 403


async def test_bulk_control_cookie_not_accepted_on_json_route(engine: Engine) -> None:
    # Confinement: the underlying JSON control route with only the cookie still 401s (header-only).
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    async with _client(engine, service) as c:
        await _cookie_login(c, "op")
        assert (await c.post("/connections/in1/stop")).status_code == 401


async def test_bulk_control_dispatches_both_roles_and_dedupes(
    engine: Engine, tmp_path: Path
) -> None:
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    await _start_two_out(engine, tmp_path)
    rr = engine.registry_runner
    assert rr is not None
    async with _client(engine, service) as c:
        await _cookie_login(c, "op")
        # 3 sels -> 2 unique control targets: an inbound (in1) + an outbound (out1) reached via TWO edge
        # rows (in1->out1, in2->out1), which dedupe to one control by destination.
        sels = [
            ("action", "stop"),
            ("sel", _rowkey("source", "in1")),
            ("sel", _rowkey("destination", "in1", "out1")),
            ("sel", _rowkey("destination", "in2", "out1")),
        ]
        r = await _post_pairs(c, "/ui/connections/bulk-control", sels)
        assert r.status_code == 200
        assert "2 target(s) processed" in r.text  # dedupe fired (not 3)
        assert "in1" in r.text and "out1" in r.text
    assert rr.inbound_running("in1") is False  # inbound stopped
    assert rr.outbound_running("out1") is False  # outbound paused (once)
    assert rr.outbound_running("out2") is True  # never selected


async def _start_dual_name(engine: Engine, tmp_path: Path) -> None:
    """Attach a connection name 'shared' that is BOTH an inbound AND an outbound (separate registry
    tables permit it), then start the runner — so the role-aware bulk-control disambiguation (a
    destination row targets the OUTBOUND, not the same-named inbound) is exercisable."""
    for name in ("shared_in", "shared_out"):
        (tmp_path / name).mkdir(exist_ok=True)
    reg = Registry()
    reg.add_inbound(
        InboundConnection(
            "shared",
            ConnectionSpec(
                ConnectorType.FILE,
                {
                    "directory": str(tmp_path / "shared_in"),
                    "pattern": "*.hl7",
                    "poll_seconds": 0.05,
                },
            ),
            router="r",
        )
    )
    reg.add_outbound(
        OutboundConnection(
            "shared",
            ConnectionSpec(ConnectorType.FILE, {"directory": str(tmp_path / "shared_out")}),
        )
    )
    reg.add_router("r", lambda m: ["h"])
    reg.add_handler("h", lambda m: [Send("shared", m)])
    engine.add_registry(reg)
    await engine.start()


async def test_bulk_control_same_name_source_and_destination_disambiguated(
    engine: Engine, tmp_path: Path
) -> None:
    # A name declared as BOTH an inbound and an outbound must be role-disambiguated: a destination row
    # for "shared" controls the OUTBOUND (not the same-named inbound, which the old inbound-first resolve
    # would have hit), and selecting BOTH the same-named source + destination dispatches to BOTH (two
    # distinct (role, name) targets, never deduped to one).
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    await _start_dual_name(engine, tmp_path)
    rr = engine.registry_runner
    assert rr is not None
    async with _client(engine, service) as c:
        await _cookie_login(c, "op")
        # A destination row for "shared" → the OUTBOUND is paused; the same-named inbound is untouched.
        r = await _post_pairs(
            c,
            "/ui/connections/bulk-control",
            [("action", "stop"), ("sel", _rowkey("destination", "shared", "shared"))],
        )
        assert r.status_code == 200
        assert "1 target(s) processed" in r.text
    assert rr.outbound_running("shared") is False  # the OUTBOUND was controlled
    assert (
        rr.inbound_running("shared") is True
    )  # the same-named INBOUND was NOT (role disambiguation)

    async with _client(engine, service) as c:
        await _cookie_login(c, "op")
        # Both the same-named source AND destination selected → BOTH dispatched (not deduped to one).
        r = await _post_pairs(
            c,
            "/ui/connections/bulk-control",
            [
                ("action", "stop"),
                ("sel", _rowkey("source", "shared")),
                ("sel", _rowkey("destination", "shared", "shared")),
            ],
        )
        assert r.status_code == 200
        assert "2 target(s) processed" in r.text  # NOT deduped by bare name to one
    assert rr.inbound_running("shared") is False  # the inbound stopped this time
    assert rr.outbound_running("shared") is False  # the outbound stays paused


async def test_bulk_control_forbidden_target_does_not_abort_batch(
    engine: Engine, tmp_path: Path
) -> None:
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    await service.set_channel_scope(await _uid(service, "op"), ["in1"], actor="admin")
    await _start_two_out(engine, tmp_path)
    rr = engine.registry_runner
    assert rr is not None
    async with _client(engine, service) as c:
        await _cookie_login(c, "op")
        # A channel-scoped user can't control the shared outbound out1 (403), but their in-scope inbound
        # in1 still applies -- put the forbidden target FIRST to prove the batch is not aborted.
        sels = [
            ("action", "stop"),
            ("sel", _rowkey("destination", "in1", "out1")),
            ("sel", _rowkey("source", "in1")),
        ]
        r = await _post_pairs(c, "/ui/connections/bulk-control", sels)
        assert r.status_code == 200
        assert "403" in r.text and "out1" in r.text  # the forbidden target is enumerated
    assert rr.inbound_running("in1") is False  # the in-scope target still applied (batch continued)
    assert rr.outbound_running("out1") is True  # the forbidden target was NOT stopped


async def test_bulk_control_bad_action_404(engine: Engine) -> None:
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    async with _client(engine, service) as c:
        await _cookie_login(c, "op")
        r = await _post_pairs(
            c,
            "/ui/connections/bulk-control",
            [("action", "delete"), ("sel", _rowkey("source", "in1"))],
        )
        assert r.status_code == 404


async def test_bulk_control_escapes_and_labels_bad_selection(engine: Engine) -> None:
    # An undecodable key -> the fixed 'unrecognized selection' label (never the raw bytes). A DECODABLE
    # key whose name carries markup -> the name rendered ESCAPED (no live script reaches the browser).
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    async with _client(engine, service) as c:
        await _cookie_login(c, "op")
        xss = _rowkey("source", "<script>alert(1)</script>")
        r = await _post_pairs(
            c,
            "/ui/connections/bulk-control",
            [("action", "start"), ("sel", "not-a-key"), ("sel", xss)],
        )
        assert r.status_code == 200
        assert "unrecognized selection" in r.text
        assert "<script>alert(1)</script>" not in r.text  # escaped, never reflected raw
        assert "&lt;script&gt;" in r.text


# --- reset-many (bulk counter reset) ---------------------------------------------------------------


async def test_reset_many_multi_target(engine: Engine) -> None:
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    # Seed NONZERO cumulative counters so a reset that fires is observable (not the near-tautological
    # zero-traffic case): one message bumps the source "in1" read counter and, once delivered, the
    # destination ("in1","out1") written counter.
    await engine.store.enqueue_message(
        channel_id="in1", raw=ADT, deliveries=[("out1", ADT)], now=10.0
    )
    item = (await engine.store.claim_ready(now=10.0))[0]
    await engine.store.mark_done(item.id, now=12.0)
    before = await engine.connection_metrics_view(now=100.0, rate_window=1000.0)
    assert before.inbound["in1"].read == 1
    assert before.destinations[("in1", "out1")].written == 1

    async with _client(engine, service) as c:
        await _cookie_login(c, "op")
        # An undecodable sel FIRST proves it is DROPPED (skipped), never turning the batch into a no-op —
        # the source + destination targets after it still reset.
        sels = [
            ("sel", "not-a-key"),
            ("sel", _rowkey("source", "in1")),
            ("sel", _rowkey("destination", "in1", "out1")),
        ]
        r = await _post_pairs(c, "/ui/statistics/reset-many", sels)
        assert r.status_code == 303 and r.headers["location"] == "/ui"
        cross = await c.post("/ui/statistics/reset-many", headers={"Sec-Fetch-Site": "cross-site"})
        assert cross.status_code == 403

    # BOTH targets' visible counters are now zeroed — the reset baseline captured the live counts.
    after = await engine.connection_metrics_view(now=100.0, rate_window=1000.0)
    assert after.inbound["in1"].read == 0  # source reset
    assert (
        after.destinations[("in1", "out1")].written == 0
    )  # destination reset (despite the bad sel)


async def test_reset_many_requires_diagnose(engine: Engine) -> None:
    service = await _service(engine)
    await _add(service, "viewer", Role.VIEWER)  # no monitoring:diagnose
    async with _client(engine, service) as c:
        await _cookie_login(c, "viewer")
        r = await _post_pairs(c, "/ui/statistics/reset-many", [("sel", _rowkey("source", "in1"))])
        assert r.status_code == 403


# --- bulk purge: unlock confirm page + body-carrying step-up + dual-control POST --------------------


async def test_purge_confirm_registered_as_unlock(engine: Engine) -> None:
    from messagefoundry_webconsole import is_safe_ui_action, is_unlock_action

    service = await _service(engine)
    create_app(engine, auth=service, serve_ui=True)
    assert is_unlock_action(
        "/ui/connections/purge-confirm"
    )  # GET form the re-auth may 303-redirect to
    assert not is_safe_ui_action(
        "/ui/connections/purge-confirm"
    )  # never a body-less auto-retry POST
    assert not is_safe_ui_action("/ui/connections/purge-confirm?dest=x")  # query rejected


async def test_purge_confirm_requires_purge_permission(engine: Engine) -> None:
    service = await _service(engine)
    await _add(service, "viewer", Role.VIEWER)  # no messages:purge
    async with _client(engine, service) as c:
        await _cookie_login(c, "viewer")
        r = await c.get("/ui/connections/purge-confirm", params={"scope": "all"})
        assert r.status_code == 403


async def test_purge_confirm_channel_scoped_forbidden(engine: Engine) -> None:
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    await service.set_channel_scope(await _uid(service, "op"), ["in1"], actor="admin")
    async with _client(engine, service) as c:
        await _cookie_login(c, "op")
        r = await c.get("/ui/connections/purge-confirm", params={"scope": "all", "dest": "out1"})
        assert (
            r.status_code == 403
        )  # a shared outbound spans channels -- a scoped user can't purge it


async def test_purge_confirm_lists_only_quiesced_and_validates_scope(
    engine: Engine, tmp_path: Path
) -> None:
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    await _start_two_out(engine, tmp_path)
    rr = engine.registry_runner
    assert rr is not None
    await rr.stop_outbound("out1")  # quiesce out1; leave out2 running
    await _wait_quiesced(engine, "out1")
    async with _client(engine, service) as c:
        await _cookie_login(c, "op")
        r = await c.get(
            "/ui/connections/purge-confirm",
            params=[("scope", "all"), ("dest", "out1"), ("dest", "out2")],
        )
        assert r.status_code == 200
        assert "out1" in r.text  # quiesced -> listed for confirmation
        assert "out2" not in r.text  # running -> dropped (re-derived from live quiescence)
        assert "/ui/connections/purge-bulk" in r.text  # the confirm form targets the bulk POST
        # A bad scope 404s (not a 422) -- matching the per-name purge route.
        bad = await c.get("/ui/connections/purge-confirm", params={"scope": "some", "dest": "out1"})
        assert bad.status_code == 404


async def test_purge_confirm_stale_stepup_redirects_to_reauth(engine: Engine) -> None:
    service = AuthService(engine.store, AuthSettings(step_up_max_age_seconds=0))
    await service.initialize()
    await _add(service, "op", Role.OPERATOR)
    async with _client(engine, service) as c:
        await _cookie_login(c, "op")  # step-up window is zero-length -> immediately stale
        r = await c.get("/ui/connections/purge-confirm", params={"scope": "all", "dest": "out1"})
        assert r.status_code == 303
        loc = r.headers["location"]
        assert loc.startswith("/ui/reauth") and "purge-confirm" in loc  # unlock re-auth, not a 403


async def test_purge_bulk_per_dest_409_unknown_and_scope(engine: Engine, tmp_path: Path) -> None:
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    await _start_two_out(engine, tmp_path)
    rr = engine.registry_runner
    assert rr is not None
    await rr.stop_outbound("out1")  # quiesced (empty queue -> purges 0)
    await _wait_quiesced(engine, "out1")
    async with _client(engine, service) as c:
        await _cookie_login(c, "op")
        r = await _post_pairs(
            c,
            "/ui/connections/purge-bulk",
            [("scope", "all"), ("dest", "out1"), ("dest", "out2"), ("dest", "nope")],
        )
        assert r.status_code == 200
        assert "purged 0" in r.text  # out1 quiesced -> cleanly purged (nothing queued)
        assert "409" in r.text  # out2 running -> require-stopped, per-dest, batch not aborted
        assert "404" in r.text  # nope unknown -> captured, not fatal
        # Bad scope 404s BEFORE any fan-out (a directly-called purge_connection skips its own pattern).
        bad = await _post_pairs(
            c, "/ui/connections/purge-bulk", [("scope", "wat"), ("dest", "out1")]
        )
        assert bad.status_code == 404


async def test_purge_bulk_dual_control_aggregates_pending(engine: Engine, tmp_path: Path) -> None:
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    await _start_two_out(engine, tmp_path)
    rr = engine.registry_runner
    assert rr is not None
    await rr.stop_outbound("out1")
    await _wait_quiesced(engine, "out1")
    app = create_app(
        engine,
        auth=service,
        approvals=ApprovalsSettings(enabled=True, operations=["connection_purge"]),
        serve_ui=True,
    )
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t") as c:
        await _cookie_login(c, "op")
        r = await _post_pairs(c, "/ui/connections/purge-bulk", [("scope", "all"), ("dest", "out1")])
        assert r.status_code == 200
        assert (
            "held for approval" in r.text
        )  # dual-control per dest (out1 quiesced -> reaches the gate)


async def test_purge_bulk_escapes_markup_dest(engine: Engine) -> None:
    # A ?dest carrying markup renders ESCAPED on the result page (never reflected raw). With no runner
    # the dest is unknown -> 404 captured; either way the name is only ever placed via el()/rows_table.
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    async with _client(engine, service) as c:
        await _cookie_login(c, "op")
        r = await _post_pairs(
            c, "/ui/connections/purge-bulk", [("scope", "all"), ("dest", "<script>x</script>")]
        )
        assert r.status_code == 200
        assert "<script>x</script>" not in r.text
        assert "&lt;script&gt;" in r.text
