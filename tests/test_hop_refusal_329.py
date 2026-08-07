# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""#329 — route the four remaining ``MEFOR_ALLOW_INSECURE_TLS`` cells through the ADR-0092 clamp.

Before this lane four cells still consulted the raw ``insecure_tls_allowed()`` predicate, so on first
deployment each WOULD permit weakened TLS regardless of the posture clamp: the SFTP unknown-host-key
acceptance (in-gate), and the LDAPS ``ad_tls_verify=false`` bind, the webhook alert sink and the
AI-broker cleartext-http credential hop (all out-of-gate). This suite proves each cell now REFUSES an
enforcing-PHI hop even with the escape set, that a non-enforcing / unstamped posture still crosses
(byte-identical to before), that the secure path is untouched, and — the load-bearing guard against the
item's headline "green and inert" risk — that the out-of-gate factories/constructors actually THREAD a
non-``None`` posture through the real ``create_app`` route and ``AuthService``/notifier seams.
"""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator
from pathlib import Path

import httpx
import pytest

from messagefoundry.api import create_app
from messagefoundry.auth.ldap import LdapAuthenticator, LdapError
from messagefoundry.auth.service import AuthService
from messagefoundry.config.ai_policy import AiMode
from messagefoundry.config.settings import (
    INSECURE_TLS_ESCAPE_ENV,
    AiSettings,
    AlertsSettings,
    AuthSettings,
)
from messagefoundry.config.tls_policy import HopPosture, active_hop_posture
from messagefoundry.pipeline import Engine
from messagefoundry.pipeline.alert_sinks import WebhookTransport, notifier_from_settings
from messagefoundry.store.store import MessageStore
from messagefoundry.transports import ai_broker as ai_broker_mod
from messagefoundry.transports.ai_broker import AiBroker, AiBrokerError, ai_broker_from_settings
from messagefoundry.transports.remotefile import _SftpClient

# Mirror tests/test_hop_refusal_serve_clamp.py so the two suites decide against the same postures.
PROD_PHI = HopPosture(is_phi=True, enforcing=True)
STAGING_PHI = HopPosture(is_phi=True, enforcing=False)
SYNTHETIC = HopPosture(is_phi=False, enforcing=False)  # dev / synthetic instance (no PHI)


@pytest.fixture
async def store(tmp_path: Path) -> AsyncIterator[MessageStore]:
    s = await MessageStore.open(tmp_path / "hop329.db")
    yield s
    await s.close()


# --- Cell (2): SFTP host key (IN-GATE, reads current_hop_posture via _here) ---------------------


def test_sftp_host_key_clamped_prod_phi_even_with_escape(monkeypatch: pytest.MonkeyPatch) -> None:
    # In-gate cell: with the escape set, the unknown-host-key auto-accept is CLAMPED under an enforcing
    # PHI posture (accept_unknown stays False → RejectPolicy), but a non-enforcing / synthetic posture
    # still auto-accepts. Construction reads only the posture, so no paramiko fake is needed here.
    monkeypatch.setenv(INSECURE_TLS_ESCAPE_ENV, "1")
    s = {"host": "h", "port": 22, "remote_dir": "/in"}
    with active_hop_posture(PROD_PHI):
        assert _SftpClient(s)._accept_unknown is False  # clamped: enforcing PHI refuses the escape
    with active_hop_posture(STAGING_PHI):
        assert (
            _SftpClient(s)._accept_unknown is True
        )  # non-enforcing PHI still crosses with the escape
    with active_hop_posture(SYNTHETIC):
        assert _SftpClient(s)._accept_unknown is True  # synthetic instance still crosses


def test_sftp_host_key_fail_closed_without_escape(monkeypatch: pytest.MonkeyPatch) -> None:
    # Escape-off negative control: no posture crosses (unchanged fail-closed). Asserting True here would
    # red immediately — proof the assertion binds something.
    monkeypatch.delenv(INSECURE_TLS_ESCAPE_ENV, raising=False)
    s = {"host": "h", "port": 22, "remote_dir": "/in"}
    with active_hop_posture(PROD_PHI):
        assert _SftpClient(s)._accept_unknown is False
    # Unstamped (no active_hop_posture) with the escape off is also fail-closed.
    assert _SftpClient(s)._accept_unknown is False


# --- Cell (1): LDAPS ad_tls_verify=false (OUT-OF-GATE, explicit posture) ------------------------


def _ldaps_verifyoff() -> AuthSettings:
    return AuthSettings(
        ad_enabled=True,
        ad_server="ldaps://dc.example.com",
        ad_user_search_base="DC=example,DC=com",
        ad_bind_dn="CN=svc,DC=example,DC=com",
        ad_bind_password="synthetic-bind-secret",
        ad_tls_verify=False,
    )


def test_ldaps_verifyoff_clamped_prod_phi_even_with_escape(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    monkeypatch.setenv(INSECURE_TLS_ESCAPE_ENV, "1")
    s = _ldaps_verifyoff()
    # Enforcing PHI: refused even with the escape (the clamp bites).
    with pytest.raises(LdapError, match="ad_tls_verify=false"):
        LdapAuthenticator(s, posture=PROD_PHI)
    # Non-enforcing PHI: crosses with the escape (warned loudly).
    with caplog.at_level(logging.WARNING):
        LdapAuthenticator(s, posture=STAGING_PHI)
    assert any("DISABLED" in r.getMessage() for r in caplog.records)
    # Unstamped posture (a direct/test construction) falls back to the unclamped escape — byte-identical.
    LdapAuthenticator(s, posture=None)


async def test_ldaps_authservice_threads_posture(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Seam: AuthService must thread hop_posture into the LdapAuthenticator it builds. With an enforcing
    # PHI posture + the escape set, constructing the service raises LdapError — proof the posture reaches
    # the cell. If the seam dropped it (posture=None), the escape would be unclamped and the build would
    # succeed.
    monkeypatch.setenv(INSECURE_TLS_ESCAPE_ENV, "1")
    with pytest.raises(LdapError, match="ad_tls_verify=false"):
        AuthService(store, _ldaps_verifyoff(), hop_posture=PROD_PHI)
    # A non-enforcing posture builds the service without raising (crosses with the escape).
    AuthService(store, _ldaps_verifyoff(), hop_posture=STAGING_PHI)


def test_ldaps_verifying_secure_path_unaffected(monkeypatch: pytest.MonkeyPatch) -> None:
    # Secure-path negative control: ad_tls_verify=True (verifying LDAPS) + enforcing PHI + escape UNSET
    # builds with no error — the guard only fires on the verify-OFF path, so #329 leaves the secure path
    # byte-identical.
    monkeypatch.delenv(INSECURE_TLS_ESCAPE_ENV, raising=False)
    s = AuthSettings(
        ad_enabled=True,
        ad_server="ldaps://dc.example.com",
        ad_user_search_base="DC=example,DC=com",
        ad_bind_dn="CN=svc,DC=example,DC=com",
        ad_bind_password="synthetic-bind-secret",
        ad_tls_verify=True,
    )
    LdapAuthenticator(s, posture=PROD_PHI)  # no raise: verifying LDAPS is unaffected by the change


# --- Cell (3): webhook alert sink cleartext http (OUT-OF-GATE, explicit posture) ----------------


def test_webhook_cleartext_clamped_prod_phi_even_with_escape(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(INSECURE_TLS_ESCAPE_ENV, "1")
    with pytest.raises(ValueError, match="plaintext http"):
        WebhookTransport("http://hooks.example/x", posture=PROD_PHI)
    # Non-enforcing PHI and unstamped both cross with the escape (byte-identical to before).
    WebhookTransport("http://hooks.example/x", posture=STAGING_PHI)
    WebhookTransport("http://hooks.example/x", posture=None)


def test_webhook_notifier_threads_posture(monkeypatch: pytest.MonkeyPatch) -> None:
    # Seam: notifier_from_settings must thread posture into the WebhookTransport it builds.
    monkeypatch.setenv(INSECURE_TLS_ESCAPE_ENV, "1")
    with pytest.raises(ValueError, match="plaintext http"):
        notifier_from_settings(
            AlertsSettings(webhook_url="http://hooks.example/x"), posture=PROD_PHI
        )
    # Non-enforcing posture builds the notifier (crosses with the escape).
    notifier_from_settings(
        AlertsSettings(webhook_url="http://hooks.example/x"), posture=STAGING_PHI
    )


def test_webhook_https_secure_path_unaffected(monkeypatch: pytest.MonkeyPatch) -> None:
    # Negative control: an https webhook is never refused, whatever the posture.
    monkeypatch.setenv(INSECURE_TLS_ESCAPE_ENV, "1")
    WebhookTransport("https://hooks.example/x", posture=PROD_PHI)


# --- Cell (4): AI-broker cleartext http credential hop (OUT-OF-GATE, explicit posture) ----------

_HTTP_ENDPOINT = "http://ai.internal/v1/messages"
_HTTPS_ENDPOINT = "https://ai.internal/v1/messages"


def _managed_ai(**over: object) -> AiSettings:
    kw: dict[str, object] = {
        "mode": AiMode.MANAGED_ENDPOINT,
        "environment": "prod",
        "endpoint": _HTTP_ENDPOINT,
        "api_key": "sk-synthetic-key",
        "allowed_endpoints": ["ai.internal"],
    }
    kw.update(over)
    return AiSettings(**kw)  # type: ignore[arg-type]


def test_ai_broker_cleartext_clamped_prod_phi_even_with_escape(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(INSECURE_TLS_ESCAPE_ENV, "1")

    def _build(posture: HopPosture | None) -> AiBroker:
        return AiBroker(
            endpoint=_HTTP_ENDPOINT,
            api_key="k",
            allowed_endpoints=["ai.internal"],
            posture=posture,
        )

    with pytest.raises(AiBrokerError, match="cleartext http"):
        _build(PROD_PHI)
    _build(STAGING_PHI)  # crosses with the escape on non-enforcing PHI
    _build(None)  # unstamped falls back to the unclamped escape — byte-identical


def test_ai_broker_factory_threads_posture(monkeypatch: pytest.MonkeyPatch) -> None:
    # Seam: ai_broker_from_settings must thread posture into the AiBroker it builds.
    monkeypatch.setenv(INSECURE_TLS_ESCAPE_ENV, "1")
    with pytest.raises(AiBrokerError, match="cleartext http"):
        ai_broker_from_settings(_managed_ai(), posture=PROD_PHI)
    ai_broker_from_settings(_managed_ai(), posture=STAGING_PHI)  # crosses on non-enforcing PHI


def test_ai_broker_https_secure_path_unaffected(monkeypatch: pytest.MonkeyPatch) -> None:
    # Negative control: an https endpoint is never refused on the cleartext arm, whatever the posture.
    monkeypatch.setenv(INSECURE_TLS_ESCAPE_ENV, "1")
    AiBroker(
        endpoint=_HTTPS_ENDPOINT, api_key="k", allowed_endpoints=["ai.internal"], posture=PROD_PHI
    )


# --- Anti-"green-and-inert" WIRING test: the real create_app ai_chat route threads the posture -----


@pytest.fixture
async def engine(tmp_path: Path) -> AsyncIterator[Engine]:
    eng = await Engine.create(tmp_path / "ai_wiring.db", poll_interval=0.02)
    yield eng
    await eng.stop()


def _client(app: object) -> httpx.AsyncClient:
    transport = httpx.ASGITransport(app=app)  # type: ignore[arg-type]
    return httpx.AsyncClient(transport=transport, base_url="http://t")


@pytest.fixture
def stub_chat(monkeypatch: pytest.MonkeyPatch) -> None:
    # If (and only if) the broker BUILDS, a canned reply keeps the route off the network — so a route
    # that fails to thread the posture returns 200, not a network 502. That makes the 503-vs-not signal
    # crisp for the falsification below.
    def fake_chat(self: AiBroker, prompt: str) -> str:
        return "def handle(msg): return Send('OB', msg)"

    monkeypatch.setattr(ai_broker_mod.AiBroker, "chat", fake_chat)


async def test_ai_chat_route_refuses_cleartext_under_enforcing_phi(
    engine: Engine, monkeypatch: pytest.MonkeyPatch, stub_chat: None
) -> None:
    # The load-bearing wiring guard: through the REAL route, a prod (enforcing-PHI) instance with the
    # escape set must REFUSE to build the broker over a cleartext-http endpoint → HTTP 503. This proves
    # create_app actually threads a non-None posture into ai_broker_from_settings (the "green and inert"
    # failure the item warns of). FALSIFY: drop `posture=_phi_read_posture` in the ai_chat route → the
    # broker builds over http and the route returns 200 (chat stubbed) instead of 503.
    monkeypatch.setenv(INSECURE_TLS_ESCAPE_ENV, "1")
    app = create_app(engine, ai_settings=_managed_ai(endpoint=_HTTP_ENDPOINT), allow_no_auth=True)
    async with _client(app) as c:
        r = await c.post("/ai/chat", json={"prompt": "hi"})
    assert r.status_code == 503  # broker refused by the clamp through the real route


async def test_ai_chat_route_allows_https_under_enforcing_phi(
    engine: Engine, monkeypatch: pytest.MonkeyPatch, stub_chat: None
) -> None:
    # Companion control: the SAME enforcing-PHI + escape setup over an HTTPS endpoint is NOT 503 — so the
    # 503 above is the cleartext clamp, not a blanket refusal of the route.
    monkeypatch.setenv(INSECURE_TLS_ESCAPE_ENV, "1")
    app = create_app(engine, ai_settings=_managed_ai(endpoint=_HTTPS_ENDPOINT), allow_no_auth=True)
    async with _client(app) as c:
        r = await c.post("/ai/chat", json={"prompt": "hi"})
    assert r.status_code == 200
