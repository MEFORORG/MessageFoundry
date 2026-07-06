# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""ASVS 5.0 L2 Phase-0 hardening — tests for the quick-win work packages.

Covers WP-1 (security headers, header-only WS token), WP-2 (WS Origin check), WP-4 (pinned argon2
params), WP-6 (log-injection scrub + UTC + auth.logout audit), WP-7a (request length limits +
webhook egress), WP-7c (file content sniff), and WP-11a (refuse insecure TLS overrides)."""

from __future__ import annotations

import logging
import time
import urllib.request
from types import SimpleNamespace

import httpx
import pytest
from pydantic import ValidationError

from messagefoundry.api import create_app
from messagefoundry.api.models import DeadLetterReplayRequest
from messagefoundry.api.security import _ws_origin_allowed, ws_token
from messagefoundry.auth import passwords
from messagefoundry.auth.ldap import LdapAuthenticator, LdapError
from messagefoundry.auth.service import AuthService
from messagefoundry.config.settings import AuthSettings, SqlAuth, StoreBackend, StoreSettings
from messagefoundry.logging_setup import ControlCharScrubFilter, configure_logging
from messagefoundry.pipeline.alert_sinks import WebhookTransport, _NoRedirectHandler
from messagefoundry.store.sqlserver import connection_string
from messagefoundry.store.store import MessageStore
from messagefoundry.transports.file import _looks_like_hl7


# --- WP-4: argon2 parameters pinned -----------------------------------------


def test_argon2_parameters_are_pinned() -> None:
    h = passwords._hasher
    # Pinned (not library defaults) so a dependency upgrade can't silently change the work factor.
    assert h.time_cost == 3
    assert h.memory_cost == 65536  # 64 MiB — exceeds OWASP's argon2id memory minimum
    assert h.parallelism == 4
    assert h.hash_len == 32
    assert h.salt_len == 16


# --- WP-6: log-injection scrub + UTC ----------------------------------------


def _record(msg: str, args: object = None) -> logging.LogRecord:
    return logging.LogRecord("t", logging.INFO, "p", 1, msg, args, None)  # type: ignore[arg-type]


def test_control_char_filter_neutralizes_crlf() -> None:
    rec = _record("legit line\r\nINJECTED forged line")
    assert ControlCharScrubFilter().filter(rec) is True
    out = rec.getMessage()
    assert "\n" not in out and "\r" not in out
    assert "\\n" in out and "\\r" in out  # escaped, single-line


def test_control_char_filter_scrubs_interpolated_args() -> None:
    rec = _record("peer said %s", ("a\nb\x00c",))
    ControlCharScrubFilter().filter(rec)
    out = rec.getMessage()
    assert "\n" not in out and "\x00" not in out
    assert "a\\nb\\x00c" in out


def test_control_char_filter_leaves_clean_message_lazy() -> None:
    rec = _record("count=%d", (5,))
    ControlCharScrubFilter().filter(rec)
    assert rec.args == (5,)  # untouched — lazy formatting preserved for clean messages
    assert rec.getMessage() == "count=5"


def test_configure_logging_uses_utc_timestamps() -> None:
    configure_logging("INFO")
    root = logging.getLogger()
    formatter = root.handlers[0].formatter
    assert formatter is not None and formatter.converter is time.gmtime


# --- WP-2: WebSocket Origin allowlist ---------------------------------------


def _fake_ws(origin: str | None, allowed: tuple[str, ...]) -> SimpleNamespace:
    state = SimpleNamespace(ws_allowed_origins=allowed)
    headers: dict[str, str] = {} if origin is None else {"origin": origin}
    return SimpleNamespace(headers=headers, app=SimpleNamespace(state=state))


def test_ws_origin_allows_native_client_without_origin() -> None:
    assert _ws_origin_allowed(_fake_ws(None, ())) is True


def test_ws_origin_rejects_browser_origin_by_default() -> None:
    assert _ws_origin_allowed(_fake_ws("https://evil.example", ())) is False


def test_ws_origin_honors_allowlist() -> None:
    assert _ws_origin_allowed(_fake_ws("https://ok.example", ("https://ok.example",))) is True
    assert _ws_origin_allowed(_fake_ws("https://evil.example", ("https://ok.example",))) is False


# --- WP-1: header-only WS token + security headers --------------------------


def test_ws_token_is_header_only() -> None:
    assert ws_token(SimpleNamespace(headers={"Authorization": "Bearer abc"})) == "abc"  # type: ignore[arg-type]
    assert ws_token(SimpleNamespace(headers={})) is None  # type: ignore[arg-type]


async def test_security_headers_present_on_response() -> None:
    transport = httpx.ASGITransport(app=create_app(allow_no_auth=True))
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        r = await c.get("/health")
    assert r.headers["x-content-type-options"] == "nosniff"
    assert r.headers["referrer-policy"] == "no-referrer"
    assert r.headers["x-frame-options"] == "DENY"
    # No TLS on the request → no HSTS (it would be misleading over plain http).
    assert "strict-transport-security" not in r.headers


# --- WP-6: auth.logout audited ----------------------------------------------


async def test_logout_emits_audit_event() -> None:
    store = await MessageStore.open(":memory:")
    try:
        service = AuthService(store, AuthSettings())
        boot = await service.initialize()
        assert boot is not None
        out = await service.login("admin", boot.password)
        assert out.ok and out.token is not None
        await service.logout(out.token, actor="admin")
        actions = [row["action"] for row in await store.list_audit()]
        assert "auth.logout" in actions
    finally:
        await store.close()


# --- WP-7a: request length limits + webhook egress --------------------------


def test_dead_letter_replay_request_bounds_length() -> None:
    DeadLetterReplayRequest(channel_id="x" * 256)  # at the cap — fine
    with pytest.raises(ValidationError):
        DeadLetterReplayRequest(channel_id="x" * 257)


def test_webhook_rejects_non_http_scheme() -> None:
    # Non-http(s) schemes are refused at construction (urllib would otherwise honour file:/ftp:).
    with pytest.raises(ValueError, match="must be http or https"):
        WebhookTransport("ftp://host/hook")


def test_webhook_rejects_plaintext_http_by_default(monkeypatch: pytest.MonkeyPatch) -> None:
    # ASVS 12.2.1: a plaintext http:// webhook target is refused at construction (no insecure
    # fallback) unless the explicit MEFOR_ALLOW_INSECURE_TLS dev escape is set.
    monkeypatch.delenv("MEFOR_ALLOW_INSECURE_TLS", raising=False)
    with pytest.raises(ValueError, match="plaintext http"):
        WebhookTransport("http://hooks.example/x")


def test_webhook_allows_plaintext_http_with_insecure_escape(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # With the explicit escape set, a plaintext target constructs (trusted-network dev only).
    monkeypatch.setenv("MEFOR_ALLOW_INSECURE_TLS", "1")
    t = WebhookTransport("http://hooks.example/x")
    assert t.url == "http://hooks.example/x"


def test_webhook_rejects_host_outside_allowlist() -> None:
    t = WebhookTransport("https://evil.example/hook", allowed_hosts=("ok.example",))
    with pytest.raises(ValueError):
        t._post({"type": "t", "connection": "c"})


def test_webhook_no_redirect_handler_refuses_redirects() -> None:
    handler = _NoRedirectHandler()
    req = urllib.request.Request("http://a/x")
    assert handler.redirect_request(req, None, 302, "Found", {}, "http://b/y") is None  # type: ignore[arg-type]


# --- WP-7c: file content sniff ----------------------------------------------


def test_looks_like_hl7_accepts_valid_headers() -> None:
    assert _looks_like_hl7(b"MSH|^~\\&|APP")
    assert _looks_like_hl7(b"\x0bMSH|^~\\&|APP")  # MLLP start byte
    assert _looks_like_hl7(b"\xef\xbb\xbfMSH|^~\\&|APP")  # UTF-8 BOM
    assert _looks_like_hl7(b"  \r\nFHS|^~\\&|APP")  # batch file header, leading whitespace
    assert _looks_like_hl7(b"BHS|^~\\&|APP")


def test_looks_like_hl7_rejects_non_hl7() -> None:
    assert not _looks_like_hl7(b"hello world, not hl7")
    assert not _looks_like_hl7(b"")
    assert not _looks_like_hl7(b"\x00\x01\x02\x03binary")
    assert not _looks_like_hl7(b"PID|1||100")  # PID is not a leading header segment


# --- WP-11a: refuse insecure TLS overrides ----------------------------------


def test_sqlserver_connection_string_refuses_weak_tls(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("MEFOR_ALLOW_INSECURE_TLS", raising=False)
    s = StoreSettings(
        backend=StoreBackend.SQLSERVER,
        server="db",
        database="mf",
        username="svc",
        password="p",
        auth=SqlAuth.SQL,
        trust_server_certificate=True,
    )
    with pytest.raises(ValueError):
        connection_string(s)
    # The explicit dev escape permits it.
    monkeypatch.setenv("MEFOR_ALLOW_INSECURE_TLS", "1")
    assert "TrustServerCertificate=yes" in connection_string(s)


def test_ldap_authenticator_refuses_disabled_cert_verification(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("MEFOR_ALLOW_INSECURE_TLS", raising=False)
    s = AuthSettings(
        ad_enabled=True,
        ad_server="ldaps://dc.example.com",
        ad_user_search_base="DC=example,DC=com",
        ad_bind_dn="CN=svc,DC=example,DC=com",
        ad_bind_password="secret",
        ad_tls_verify=False,
    )
    with pytest.raises(LdapError):
        LdapAuthenticator(s)
    # With the dev escape, construction is allowed (it only warns; no bind happens here).
    monkeypatch.setenv("MEFOR_ALLOW_INSECURE_TLS", "1")
    LdapAuthenticator(s)
