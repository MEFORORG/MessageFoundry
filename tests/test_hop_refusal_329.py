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

import asyncio
import http.client
import logging
from collections.abc import AsyncIterator
from pathlib import Path

import httpx
import pytest
from pydantic import ValidationError

from messagefoundry.api import create_app
from messagefoundry.auth.ldap import LdapAuthenticator, LdapError
from messagefoundry.config.ai_policy import AiMode
from messagefoundry.config.settings import (
    INSECURE_TLS_ESCAPE_ENV,
    AiSettings,
    AlertsSettings,
    AuthSettings,
    EgressSettings,
    SecurityEnforcement,
    SecuritySettings,
    load_settings,
)
from messagefoundry.config.tls_policy import HopPosture, active_hop_posture
from messagefoundry.pipeline import Engine, alert_sinks
from messagefoundry.pipeline.alert_sinks import (
    NotifierAlertSink,
    WebhookTransport,
    notifier_from_settings,
)
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


@pytest.mark.parametrize("enforcing", [True, False], ids=["enforcing", "warn"])
def test_ldaps_verifyoff_is_refused_in_every_posture_even_with_escape(
    enforcing: bool, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Vault BACKLOG #3230: every LDAPS bind carries the service-account password, so ad_tls_verify=false
    # is refused outright. Until then the escape released it at warn (#329); now no posture does.
    monkeypatch.setenv(INSECURE_TLS_ESCAPE_ENV, "1")
    with pytest.raises(LdapError, match="ad_tls_verify=false") as info:
        LdapAuthenticator(_ldaps_verifyoff(), enforcing=enforcing)
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
        LdapAuthenticator(s, secret_provider=_NeverCalled(), enforcing=False)  # type: ignore[arg-type]


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
    LdapAuthenticator(s)  # no raise: verifying LDAPS is unaffected by the change


# --- Cell (3): webhook alert sink cleartext http (OUT-OF-GATE, explicit posture) ----------------


@pytest.mark.parametrize(
    "posture", [PROD_PHI, STAGING_PHI, None], ids=["enforcing", "warn", "no-posture"]
)
def test_webhook_cleartext_is_refused_in_every_posture_even_with_escape(
    posture: HopPosture | None, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Vault BACKLOG #3533 item 5: the URL can carry the webhook's path token, so http is refused
    # with no escape. Until then the escape released it at warn (#329); now no posture does.
    monkeypatch.setenv(INSECURE_TLS_ESCAPE_ENV, "1")
    with pytest.raises(ValueError, match="cleartext http") as info:
        WebhookTransport("http://hooks.example/x", posture=posture)
    assert "with no escape" in str(info.value)
    assert INSECURE_TLS_ESCAPE_ENV not in str(info.value)


@pytest.mark.parametrize("posture", [PROD_PHI, STAGING_PHI], ids=["enforcing", "warn"])
def test_webhook_notifier_refuses_cleartext_in_every_posture(
    posture: HopPosture, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The notifier's own refusal, its second line; the warn posture used to build here. The section
    # is built with model_construct because settings load (#3533 item 14) refuses this URL first,
    # with a message of its own.
    monkeypatch.setenv(INSECURE_TLS_ESCAPE_ENV, "1")
    with pytest.raises(ValueError, match="cleartext http"):
        notifier_from_settings(
            AlertsSettings.model_construct(webhook_url="http://hooks.example/x"), posture=posture
        )


_WEBHOOK_TOKEN = "T0KEN-in-the-path"
_SETTING_NAMED = r"\[alerts\]\.webhook_url"

#: Each refused by the build's posture-free checks, which settings load runs too (#3533 item 14).
_REFUSED_WEBHOOK_URLS = [
    pytest.param(f"http://hooks.example/{_WEBHOOK_TOKEN}", (), id="http"),
    pytest.param(f"HTTP://hooks.example/{_WEBHOOK_TOKEN}", (), id="upper-http"),
    pytest.param(f"ftp://hooks.example/{_WEBHOOK_TOKEN}", (), id="ftp"),
    pytest.param(f"hooks.example/{_WEBHOOK_TOKEN}", (), id="no-scheme"),
    # Shapes whose urlsplit ValueError would quote the netloc. The http.client screen now
    # refuses the non-ASCII one first; the bracket one still reaches the split.
    pytest.param(f"https://svc:{_WEBHOOK_TOKEN}\uff03x@hooks.example/x", (), id="nfkc-netloc"),
    pytest.param(f"https://svc:pw@[{_WEBHOOK_TOKEN}]/x", (), id="bad-bracket"),
    pytest.param(f"https://svc:{_WEBHOOK_TOKEN}@hooks.example/x", (), id="userinfo"),
    # urlsplit drops these, so it would read the scheme as https.
    pytest.param(f"ht\ttps://hooks.example/{_WEBHOOK_TOKEN}", (), id="tab"),
    pytest.param(f"https\n://hooks.example/{_WEBHOOK_TOKEN}", (), id="lf"),
    # Stripped by urllib's dial but not by urlsplit, so it is not stripped: refused at load as at
    # the build, by the whitespace-at-either-end check.
    pytest.param(f"\xa0https://hooks.example/{_WEBHOOK_TOKEN}", (), id="nbsp"),
    pytest.param(f"\u3000https://hooks.example/{_WEBHOOK_TOKEN}", (), id="ideographic-space"),
    # At the end, urlsplit keeps it in the host it judges and the dial strips it.
    pytest.param("https://localhost\u2003", ("localhost",), id="trailing-em-space"),
    pytest.param(f"https://hooks.example/{_WEBHOOK_TOKEN}\x85", (), id="trailing-nel"),
    # Inside the URL: http.client could never send these, and for a space it raises InvalidURL
    # quoting the path, so each alert POST would log the token.
    pytest.param(f"https://hooks.example/services/T0 {_WEBHOOK_TOKEN}", (), id="inner-space"),
    pytest.param(f"https://hooks.example/x\x85{_WEBHOOK_TOKEN}", (), id="inner-nel"),
    pytest.param(f"https://hooks.example\u2003/{_WEBHOOK_TOKEN}", (), id="em-space-in-host"),
    pytest.param(f"https://hooks.example/{_WEBHOOK_TOKEN}\ufeff", (), id="trailing-bom"),
    pytest.param(f"https://hooks.example/{_WEBHOOK_TOKEN}\udc80", (), id="lone-surrogate"),
    # Percent-encoded in the host: urllib decodes it before http.client refuses it at every POST.
    pytest.param(f"https://hooks.example%20/{_WEBHOOK_TOKEN}", (), id="encoded-space-in-host"),
    pytest.param(f"https://hooks%0d%0aexample/{_WEBHOOK_TOKEN}", (), id="encoded-crlf-in-host"),
    pytest.param(f"https://hooks.example%7f/{_WEBHOOK_TOKEN}", (), id="encoded-del-in-host"),
    # Whitespace both readers strip is stripped, so an http URL inside it is still refused.
    pytest.param(f" http://hooks.example/{_WEBHOOK_TOKEN}\n", (), id="space-http"),
    pytest.param(f"https://hooks.example/{_WEBHOOK_TOKEN}", ("other.example",), id="off-allowlist"),
    pytest.param(f"https://h.example/{_WEBHOOK_TOKEN}" + "x" * 8192, (), id="over-length"),
    # No host, with no allowlist: the build's revocation guard refuses these in every posture.
    pytest.param(f"https:///{_WEBHOOK_TOKEN}", (), id="hostless"),
    pytest.param(f"https://:443/{_WEBHOOK_TOKEN}", (), id="port-only"),
]


@pytest.mark.parametrize(("url", "allowed"), _REFUSED_WEBHOOK_URLS)
def test_a_webhook_the_build_refuses_is_refused_at_load_without_echoing_it(
    url: str, allowed: tuple[str, ...]
) -> None:
    # Vault BACKLOG #3533 item 14: settings load runs the build's own checks, so check and the
    # serve pre-flight refuse what the build refuses. The path can hold the webhook's token, so
    # no message repeats the token.
    with pytest.raises(ValueError, match=_SETTING_NAMED) as built:
        WebhookTransport(url, allowed_hosts=allowed, posture=STAGING_PHI)
    with pytest.raises(ValidationError) as info:
        AlertsSettings(webhook_url=url, webhook_allowed_hosts=list(allowed))
    text = str(info.value)
    assert str(built.value) in text  # one refusal, the same at load and at the build
    assert _WEBHOOK_TOKEN not in text and _WEBHOOK_TOKEN not in info.value.json()
    assert "ftp" not in text.lower()


def test_a_non_https_webhook_is_refused_by_the_settings_loader(tmp_path: Path) -> None:
    config = tmp_path / "messagefoundry.toml"
    config.write_text(
        f'[alerts]\nwebhook_url = "http://hooks.example/{_WEBHOOK_TOKEN}"\n', encoding="utf-8"
    )
    with pytest.raises(ValidationError, match="cleartext http") as info:
        load_settings(config_path=config, environ={})
    assert _WEBHOOK_TOKEN not in str(info.value)


@pytest.mark.parametrize(
    "url",
    [None, "", "https://hooks.example/x", "HTTPS://hooks.example/x", " https://hooks.example/x\n"],
)
def test_an_https_or_unset_webhook_loads(url: str | None) -> None:
    # Negative control: an https URL loads, inside whitespace both readers strip too, and an empty
    # value stays "not configured". The value is kept as written.
    assert AlertsSettings(webhook_url=url).webhook_url == url


def test_the_allowlist_judges_the_host_urllib_dials() -> None:
    # An encoded dot dials hooks.example, so a list naming hooks.example admits it, and an entry
    # that decodes to another host does not.
    url = "https://hooks%2Eexample/x"
    assert AlertsSettings(webhook_url=url, webhook_allowed_hosts=["hooks.example"]).webhook_url
    with pytest.raises(ValidationError, match="not in"):
        AlertsSettings(webhook_url=url, webhook_allowed_hosts=["hooks%2eother"])


def test_an_ipv6_zone_entry_written_as_the_url_spells_it_still_matches() -> None:
    # Regression control: before the host was decoded, an entry spelled as in the URL ("%25")
    # matched. It still does, since each entry is decoded too.
    url = "https://[fe80::1%25eth0]/x"
    alerts = AlertsSettings(webhook_url=url, webhook_allowed_hosts=["fe80::1%25eth0"])
    assert alerts.webhook_url == url


def test_a_listed_webhook_host_loads() -> None:
    # Negative control for the allowlist case above.
    alerts = AlertsSettings(
        webhook_url="https://hooks.example/x", webhook_allowed_hosts=["HOOKS.example"]
    )
    assert alerts.webhook_allowed_hosts == ["HOOKS.example"]


class _TokenQuotingTransport:
    """A transport whose send raises an exception quoting a webhook path, as http.client's
    InvalidURL does for a URL with a space in it."""

    name = "webhook"

    async def send(self, event: object, **_: object) -> None:
        raise http.client.InvalidURL(f"URL can't contain control characters. '/{_WEBHOOK_TOKEN}'")


async def test_a_failed_send_logs_the_exception_class_only(
    caplog: pytest.LogCaptureFixture,
) -> None:
    # Vault BACKLOG #3533 item 14: the notifier's WARNING for a failed transport names the class
    # and carries no message and no exc_info, so a send whose exception quotes the URL logs no token.
    sink = NotifierAlertSink([_TokenQuotingTransport()])
    with caplog.at_level(logging.WARNING, logger="messagefoundry.pipeline.alert_sinks"):
        sink.connection_stopped("OB_X", detail="synthetic")
        sink.start()
        for _ in range(500):
            if any("alert transport webhook failed" in r.getMessage() for r in caplog.records):
                break
            await asyncio.sleep(0.01)
        await sink.aclose()
    [record] = [r for r in caplog.records if "alert transport webhook failed" in r.getMessage()]
    assert record.exc_info is None and record.exc_text is None
    assert record.getMessage().endswith(": InvalidURL")
    assert _WEBHOOK_TOKEN not in caplog.text


def test_post_re_raises_invalid_url_with_fixed_text(monkeypatch: pytest.MonkeyPatch) -> None:
    # Defence in depth (#3533 item 14): an InvalidURL the screen did not foresee is re-raised with
    # text that holds nothing of the URL, and with no chain link holding the original.
    transport = WebhookTransport(f"https://hooks.example/{_WEBHOOK_TOKEN}", posture=STAGING_PHI)

    class _Opener:
        def open(self, req: object, timeout: float) -> object:
            raise http.client.InvalidURL(
                f"URL can't contain control characters. '/{_WEBHOOK_TOKEN}'"
            )

    monkeypatch.setattr(alert_sinks, "_shared_no_redirect_opener", lambda: _Opener())
    with pytest.raises(http.client.InvalidURL) as info:
        transport._post({"type": "synthetic"})
    assert _WEBHOOK_TOKEN not in str(info.value)
    assert info.value.__context__ is None and info.value.__cause__ is None


def test_the_build_dials_the_value_it_judged() -> None:
    # The screen strips surrounding ASCII whitespace, and the transport keeps the stripped value.
    # The whitespace here sits outside the host, so this does not show which value the
    # revocation guard read; it pins the stored URL.
    transport = WebhookTransport(
        " https://localhost/x \n", allowed_hosts=("localhost",), posture=PROD_PHI
    )
    assert transport.url == "https://localhost/x"


def test_webhook_https_secure_path_unaffected(monkeypatch: pytest.MonkeyPatch) -> None:
    # Negative control: the cleartext gate never refuses an https webhook, whatever the posture.
    # Since BACKLOG #2193 an off-box https webhook on an enforcing posture also takes the revocation
    # guard, so the attestation pair is set here to keep this a test of the cleartext gate alone;
    # tests/test_alert_revocation_guard.py holds that guard's arms.
    monkeypatch.setenv(INSECURE_TLS_ESCAPE_ENV, "1")
    WebhookTransport(
        "https://hooks.example/x",
        posture=PROD_PHI,
        revocation_attested=True,
        revocation_attested_reason="synthetic: the hook host certificate is short-lived",
    )
    WebhookTransport("https://hooks.example/x", posture=STAGING_PHI)


# --- Cell (4): AI-broker cleartext http credential hop (refused in every posture, #3533) ---------

_HTTP_ENDPOINT = "http://ai.internal/v1/messages"
_HTTPS_ENDPOINT = "https://ai.internal/v1/messages"
# BACKLOG #2193 slice (e): the https controls below would otherwise be refused for revocation under
# an enforcing posture, so they carry the attestation pair. The http tests carry none: the
# cleartext refusal comes first.
_AI_ATTESTED_REASON = "synthetic: revocation covered outside the engine for these tests"
_AI_ATTESTED: dict[str, object] = {
    "endpoint_revocation_attested": True,
    "endpoint_revocation_attested_reason": _AI_ATTESTED_REASON,
}


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


def test_ai_broker_https_secure_path_unaffected() -> None:
    # Negative control: an https endpoint builds through the factory and the constructor alike.
    ai_broker_from_settings(_managed_ai(endpoint=_HTTPS_ENDPOINT, **_AI_ATTESTED), posture=PROD_PHI)
    AiBroker(
        endpoint=_HTTPS_ENDPOINT,
        api_key="k",
        allowed_endpoints=["ai.internal"],
        revocation_attested=True,
        revocation_attested_reason=_AI_ATTESTED_REASON,
    )


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
    # If (and only if) the broker BUILDS, a canned reply keeps the route off the network, so a route
    # that built it returns 200, not a network 502. That makes the 503-vs-not signal crisp.
    def fake_chat(self: AiBroker, prompt: str) -> str:
        return "def handle(msg): return Send('OB', msg)"

    monkeypatch.setattr(ai_broker_mod.AiBroker, "chat", fake_chat)


@pytest.mark.parametrize(
    "enforcement", [SecurityEnforcement.ENFORCE, SecurityEnforcement.WARN], ids=["enforce", "warn"]
)
async def test_ai_chat_route_refuses_cleartext_with_the_escape_set(
    enforcement: SecurityEnforcement,
    engine: Engine,
    monkeypatch: pytest.MonkeyPatch,
    stub_chat: None,
) -> None:
    # Through the REAL route, the broker is never built over a cleartext-http endpoint, so the route
    # answers 503 and the stubbed chat never runs. Vault BACKLOG #3533 item 5: at warn the escape
    # released the api_key over http until then, and this route answered 200.
    monkeypatch.setenv(INSECURE_TLS_ESCAPE_ENV, "1")
    app = create_app(
        engine,
        ai_settings=_managed_ai(endpoint=_HTTP_ENDPOINT),
        security_settings=SecuritySettings(enforcement=enforcement),
        allow_no_auth=True,
    )
    async with _client(app) as c:
        r = await c.post("/ai/chat", json={"prompt": "hi"})
    assert r.status_code == 503


async def test_ai_chat_route_allows_https(
    engine: Engine, monkeypatch: pytest.MonkeyPatch, stub_chat: None
) -> None:
    # Companion control: the same setup over an HTTPS endpoint is NOT 503, so the 503 above is the
    # cleartext refusal, not a blanket refusal of the route.
    monkeypatch.setenv(INSECURE_TLS_ESCAPE_ENV, "1")
    app = create_app(
        engine,
        ai_settings=_managed_ai(endpoint=_HTTPS_ENDPOINT, **_AI_ATTESTED),
        allow_no_auth=True,
    )
    async with _client(app) as c:
        r = await c.post("/ai/chat", json={"prompt": "hi"})
    assert r.status_code == 200
