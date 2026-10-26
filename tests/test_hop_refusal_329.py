# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""#329 — route the four remaining ``MEFOR_ALLOW_INSECURE_TLS`` cells through the ADR-0092 clamp.

Before this lane four cells still consulted the raw ``insecure_tls_allowed()`` predicate, so on first
deployment each WOULD permit weakened TLS regardless of the posture clamp: the SFTP unknown-host-key
acceptance (in-gate), and the LDAPS ``ad_tls_verify=false`` bind, the webhook alert sink and the
AI-broker cleartext-http credential hop (all out-of-gate). This suite proves each cell now REFUSES an
enforcing-PHI hop even with the escape set, that a non-enforcing / unstamped posture still crosses
(byte-identical to before), that the secure path is untouched, and — the load-bearing guard against the
item's headline "green and inert" risk — that the out-of-gate factories/constructors actually THREAD a
non-``None`` posture through the real ``create_app`` route and ``AuthService``/notifier seams.

The AI-broker cell no longer reads the posture: vault BACKLOG #3533 item 5 refuses its http endpoint
with no escape, because every call sends the api_key. Its tests below pin that refusal instead.
"""

from __future__ import annotations

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
    EgressSettings,
    SecurityEnforcement,
    SecuritySettings,
)
from messagefoundry.config.tls_policy import HopPosture, active_hop_posture
from messagefoundry.pipeline import Engine
from messagefoundry.pipeline.alert_sinks import WebhookTransport, notifier_from_settings
from messagefoundry.store.store import MessageStore
from messagefoundry.transports import ai_broker as ai_broker_mod
from messagefoundry.transports.ai_broker import AiBroker, AiBrokerError, ai_broker_from_settings
from messagefoundry.transports.remotefile import _SftpClient

# Mirror tests/test_hop_refusal_serve_clamp.py so the two suites decide against the same postures.
PROD_PHI = HopPosture(enforcing=True)
STAGING_PHI = HopPosture(enforcing=False)
SYNTHETIC = HopPosture(enforcing=False)  # dev / synthetic instance (no PHI)


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


@pytest.mark.parametrize(
    "posture", [PROD_PHI, STAGING_PHI, None], ids=["enforcing", "warn", "no-posture"]
)
def test_ldaps_verifyoff_is_refused_in_every_posture_even_with_escape(
    posture: HopPosture | None, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Vault BACKLOG #3230: every LDAPS bind carries the service-account password, so ad_tls_verify=false
    # is refused outright. Until then the escape released it at warn (#329); now no posture does.
    monkeypatch.setenv(INSECURE_TLS_ESCAPE_ENV, "1")
    with pytest.raises(LdapError, match="ad_tls_verify=false") as info:
        LdapAuthenticator(_ldaps_verifyoff(), posture=posture)
    message = str(info.value)
    assert "with no escape" in message
    assert "ad_tls_ca_cert_file" in message  # names the lever that does cross: a pinned CA
    assert INSECURE_TLS_ESCAPE_ENV not in message  # never offers the escape it ignores
    assert "synthetic-bind-secret" not in message


def test_ldaps_verifyoff_refuses_before_the_bind_secret_is_fetched() -> None:
    """Like the plain-bind refusal, it runs before the secret provider is asked for the password."""

    class _NeverCalled:
        def get(self, ref: str) -> str:
            raise AssertionError("the bind secret was fetched for a refused build")

    s = _ldaps_verifyoff().model_copy(update={"ad_bind_password_secret": "kv/ad#pw"})
    with pytest.raises(LdapError, match="ad_tls_verify=false"):
        LdapAuthenticator(s, secret_provider=_NeverCalled(), posture=STAGING_PHI)  # type: ignore[arg-type]


async def test_authservice_threads_posture_to_the_ldap_bind(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Seam: AuthService must thread hop_posture into the LdapAuthenticator it builds. The LDAPS
    # verify-off cell no longer reads the posture (vault BACKLOG #3230), so the seam is proven on the
    # plain ldap:// cell, which still does: with the enforcement dial at warn, only the posture can
    # refuse it. If the seam dropped the posture, the enforcing arm below would build.
    plain = AuthSettings(
        ad_enabled=True,
        ad_server="ldap://dc.example.com",
        ad_allow_insecure_ldap=True,
        ad_user_search_base="DC=example,DC=com",
        ad_bind_dn="CN=svc,DC=example,DC=com",
        ad_bind_password="synthetic-bind-secret",
    )
    with pytest.raises(LdapError, match="inert under"):
        AuthService(store, plain, hop_posture=PROD_PHI, enforcing=False)
    AuthService(store, plain, hop_posture=STAGING_PHI, enforcing=False)


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
    # Non-enforcing PHI crosses with the escape; no posture fails closed (vault BACKLOG #2354).
    WebhookTransport("http://hooks.example/x", posture=STAGING_PHI)
    with pytest.raises(ValueError, match="plaintext http"):
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


# --- Cell (4): AI-broker cleartext http credential hop (refused in every posture, #3533) ---------

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


@pytest.mark.parametrize(
    "posture", [PROD_PHI, STAGING_PHI, None], ids=["enforcing", "warn", "no-posture"]
)
def test_ai_broker_cleartext_is_refused_in_every_posture_even_with_escape(
    posture: HopPosture | None, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Vault BACKLOG #3533 item 5: every call sends the api_key, so http is refused with no escape.
    # Until then the escape released it at warn (#329); now no posture does, the warn one included.
    monkeypatch.setenv(INSECURE_TLS_ESCAPE_ENV, "1")
    with pytest.raises(AiBrokerError, match="cleartext http") as info:
        ai_broker_from_settings(_managed_ai(), posture=posture)
    assert "with no escape" in str(info.value)
    assert INSECURE_TLS_ESCAPE_ENV not in str(info.value)


def test_ai_broker_https_secure_path_unaffected(monkeypatch: pytest.MonkeyPatch) -> None:
    # Negative control: an https endpoint is never refused on the cleartext arm, whatever the posture.
    monkeypatch.setenv(INSECURE_TLS_ESCAPE_ENV, "1")
    ai_broker_from_settings(_managed_ai(endpoint=_HTTPS_ENDPOINT), posture=PROD_PHI)
    AiBroker(endpoint=_HTTPS_ENDPOINT, api_key="k", allowed_endpoints=["ai.internal"])


# --- The real create_app ai_chat route refuses an http endpoint at every posture ------------------


@pytest.fixture
async def engine(tmp_path: Path) -> AsyncIterator[Engine]:
    eng = await Engine.create(
        tmp_path / "ai_wiring.db",
        poll_interval=0.02,
        egress_settings=EgressSettings(deny_by_default=False),
    )
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
    # Through the REAL route, an enforcing instance with the escape set refuses to build the broker
    # over a cleartext-http endpoint, so the route answers 503 and the stubbed chat never runs.
    monkeypatch.setenv(INSECURE_TLS_ESCAPE_ENV, "1")
    app = create_app(engine, ai_settings=_managed_ai(endpoint=_HTTP_ENDPOINT), allow_no_auth=True)
    async with _client(app) as c:
        r = await c.post("/ai/chat", json={"prompt": "hi"})
    assert r.status_code == 503


async def test_ai_chat_route_refuses_cleartext_with_the_escape_at_warn(
    engine: Engine, monkeypatch: pytest.MonkeyPatch, stub_chat: None
) -> None:
    # Vault BACKLOG #3533 item 5: the escape at warn released the api_key over http until then, and
    # this route answered 200. Every call sends the key, so no posture releases it now.
    monkeypatch.setenv(INSECURE_TLS_ESCAPE_ENV, "1")
    app = create_app(
        engine,
        ai_settings=_managed_ai(endpoint=_HTTP_ENDPOINT),
        security_settings=SecuritySettings(enforcement=SecurityEnforcement.WARN),
        allow_no_auth=True,
    )
    async with _client(app) as c:
        r = await c.post("/ai/chat", json={"prompt": "hi"})
    assert r.status_code == 503


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
