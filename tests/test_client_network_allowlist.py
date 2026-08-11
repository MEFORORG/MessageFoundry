# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""``[security].allowed_client_networks`` — the operator-surface source-address allow-list.

Covers the three things that make this control either sound or useless:

1. **Which address is evaluated.** ``scope["client"]``, never a forwarding header we parse. The R1/R2
   tests below drive the REAL ``uvicorn.middleware.proxy_headers.ProxyHeadersMiddleware`` in front of
   the app, so "with a declared proxy the real client is already in scope; with none, an attacker's
   X-Forwarded-For is ignored entirely" is proven end-to-end rather than modelled.
2. **The empty default is a no-op.** Byte-identical to the pre-control behaviour, from every address.
3. **Diagnosability.** A denial is recognisable, names the setting, echoes the observed address, and
   ``/health`` stays reachable so a locked-out operator can find out what the engine sees.
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import httpx
import pytest
from starlette.middleware.base import BaseHTTPMiddleware
from uvicorn.middleware.proxy_headers import ProxyHeadersMiddleware

from messagefoundry.api import create_app
from messagefoundry.api.client_networks import DENIAL_HEADER, DENIAL_MARKER, ClientNetworkMiddleware
from messagefoundry.auth import Role
from messagefoundry.auth.service import AuthService
from messagefoundry.config.settings import (
    AlertsSettings,
    ApiSettings,
    AuthSettings,
    SecuritySettings,
    ServiceSettings,
    StoreSettings,
    load_settings,
    security_loosenings,
)
from messagefoundry.netaddr import client_network_allowed, peer_ip_allowed
from messagefoundry.pipeline import Engine


def _loosenings(sec: SecuritySettings) -> list[tuple[str, str]]:
    """``security_loosenings`` with the shipped [store]/[auth] defaults and an empty accepted set.

    The registry takes all four inputs as REQUIRED arguments deliberately (ADR 0148: one posture, and a
    deviation the registry cannot see is a second posture by the back door). The tests below are about
    the ``[security]`` switches specifically, so the other three are pinned at shipped values here."""
    return security_loosenings(
        sec, StoreSettings(), AuthSettings(), AlertsSettings(), (), (), (), None
    )


PW = "a-strong-test-passphrase"  # >=15, no app/vendor terms — satisfies the ASVS policy

WARD = ["10.0.0.0/8"]


@pytest.fixture
async def engine(tmp_path: Path) -> AsyncIterator[Engine]:
    eng = await Engine.create(tmp_path / "clientnet.db", poll_interval=0.02)
    yield eng
    await eng.stop()


async def _service(engine: Engine) -> AuthService:
    service = AuthService(engine.store, AuthSettings(require_mfa=False))
    await service.initialize()
    return service


async def _add_viewer(service: AuthService, username: str) -> None:
    user_id = await service.create_local_user(
        username=username,
        password=PW,
        display_name=None,
        email=None,
        roles=[Role.VIEWER.value],
        actor="test",
    )
    user = await service.store.get_user(user_id)
    assert user is not None and user.password_hash is not None
    await service.store.set_password(
        user_id, password_hash=user.password_hash, must_change_password=False
    )


def _app(engine: Engine, networks: list[str], **kw: Any) -> Any:
    return create_app(
        engine, security_settings=SecuritySettings(allowed_client_networks=networks), **kw
    )


def _client(app: Any, ip: str | None) -> httpx.AsyncClient:
    """A client whose requests originate from ``ip`` on the ASGI scope (``None`` = no client tuple,
    the UNIX-socket / unknown-peer case)."""
    transport = httpx.ASGITransport(app=app, client=(ip, 12345) if ip else None)
    return httpx.AsyncClient(transport=transport, base_url="http://t")


# --- the matcher --------------------------------------------------------------------------------


def test_client_network_allowed_table() -> None:
    # Empty/None allow-list: no restriction, from anywhere, including an unparseable host.
    assert client_network_allowed("203.0.113.9", None) is True
    assert client_network_allowed("203.0.113.9", []) is True
    assert client_network_allowed("testclient", []) is True
    assert client_network_allowed(None, []) is True
    # In / out of the listed network.
    assert client_network_allowed("10.4.4.4", WARD) is True
    assert client_network_allowed("192.168.9.9", WARD) is False
    # Loopback is ALWAYS allowed (every spelling), even against a v4-only allow-list.
    for host in ("127.0.0.1", "127.0.0.5", "::1", "::ffff:127.0.0.1"):
        assert client_network_allowed(host, WARD) is True, host
    # Fail closed: no address, or one that will not parse.
    assert client_network_allowed(None, WARD) is False
    assert client_network_allowed("testclient", WARD) is False
    assert client_network_allowed("", WARD) is False
    # IPv4-mapped dual-stack peer matches a plain IPv4 entry (both candidates are tested).
    assert client_network_allowed("::ffff:10.0.0.5", WARD) is True
    # 6to4 embeds 10.20.4.7 in 2002:0a14:0407::/48 but is NOT an IPv4-mapped address — fail closed
    # rather than "helpfully" unwrapping a routable v6 address into a private v4 one.
    assert client_network_allowed("2002:0a14:0407::1", ["10.20.0.0/16"]) is False
    # IPv6 networks, and a zone-id'd link-local (the '%' is stripped before parsing).
    assert client_network_allowed("fd00::5", ["fd00::/8"]) is True
    assert client_network_allowed("fe80::1%eth0", ["fe80::/10"]) is True
    assert client_network_allowed("2001:db8::5", ["fd00::/8"]) is False


def test_cross_family_entries_never_raise_and_never_widen() -> None:
    """``0.0.0.0/0`` / ``::/0`` are accepted (refusing them would be overreach) but are NOT equivalent
    to an empty list, and the asymmetry is subtle enough to pin.

    Python's ``in`` is False across address families rather than raising, so a mixed-family allow-list
    is safe. The catch is dual-stack delivery: an IPv4 client arriving as ``::ffff:a.b.c.d`` is tested
    under BOTH its v6 and unmapped v4 forms, so ``::/0`` matches it — while the SAME client reported as
    a plain ``10.0.0.5`` does not. Which form the platform reports is a bind/OS detail, so an operator
    who writes only one family gets behaviour that depends on it. Hence the runbook's rule: allow-list
    both families."""
    assert client_network_allowed("10.0.0.5", ["0.0.0.0/0"]) is True
    assert client_network_allowed("2001:db8::5", ["0.0.0.0/0"]) is False
    assert client_network_allowed("10.0.0.5", ["::/0"]) is False
    assert client_network_allowed("2001:db8::5", ["::/0"]) is True
    # Dual-stack delivery of an IPv4 client matches BOTH catch-alls (the both-candidate test).
    assert client_network_allowed("::ffff:10.0.0.5", ["0.0.0.0/0"]) is True
    assert client_network_allowed("::ffff:10.0.0.5", ["::/0"]) is True
    # A mixed-family list is evaluated entry by entry; the non-matching family is simply skipped.
    assert client_network_allowed("2001:db8::5", ["0.0.0.0/0", "2001:db8::/32"]) is True


def test_loopback_carveout_is_not_inherited_by_the_transports() -> None:
    # The inbound source_ip_allowlist must NOT silently admit anything on the local box just because
    # the operator allow-listed a partner. The carve-out belongs to the operator surface only.
    assert peer_ip_allowed(("127.0.0.1", 1), WARD) is False
    assert client_network_allowed("127.0.0.1", WARD) is True


# --- config load --------------------------------------------------------------------------------


def test_default_is_empty_and_is_not_a_loosening() -> None:
    s = SecuritySettings()
    assert s.allowed_client_networks == []
    assert s.client_networks == ()
    # An empty list on the default loopback bind is the SECURE position, not a loosening.
    assert _loosenings(s) == []


def test_entries_are_normalized_at_load() -> None:
    s = SecuritySettings(
        allowed_client_networks=["10.1.2.3/24", "10.1.2.3", "::1", "fd00::/8", "2001:db8::/32"]
    )
    # Host bits are masked off and bare addresses become /32 or /128, so `security show` and
    # GET /security/posture display exactly what is enforced — never a wider range than was typed.
    assert s.allowed_client_networks == [
        "10.1.2.0/24",
        "10.1.2.3/32",
        "::1/128",
        "fd00::/8",
        "2001:db8::/32",
    ]


@pytest.mark.parametrize(
    "entry", ["10.0.0.0/33", "999.1.1.1/8", "not-a-cidr", "", "10.0.0.0/8 ", "::ffff:10.20.0.0/112"]
)
def test_malformed_entry_refuses_at_load(entry: str) -> None:
    with pytest.raises(ValueError, match="allowed_client_networks"):
        SecuritySettings(allowed_client_networks=[entry])


def test_env_form_splits_on_comma_not_pathsep(tmp_path: Path) -> None:
    # os.pathsep is ':' on POSIX — also the IPv6 group separator — so the [api] splitter would shred
    # every v6 entry on the Linux leg. This test only bites because one entry is IPv6.
    cfg = tmp_path / "messagefoundry.toml"
    cfg.write_text("", encoding="utf-8")
    s = load_settings(
        config_path=cfg,
        environ={"MEFOR_SECURITY_ALLOWED_CLIENT_NETWORKS": "10.0.0.0/8,fd00::/8"},
    )
    assert s.security.allowed_client_networks == ["10.0.0.0/8", "fd00::/8"]


def test_toml_load_and_malformed_toml_refusal(tmp_path: Path) -> None:
    cfg = tmp_path / "messagefoundry.toml"
    cfg.write_text(
        '[security]\nallowed_client_networks = ["10.20.0.0/16", "2001:db8::/48"]\n',
        encoding="utf-8",
    )
    s = load_settings(config_path=cfg, environ={})
    assert s.security.allowed_client_networks == ["10.20.0.0/16", "2001:db8::/48"]
    cfg.write_text('[security]\nallowed_client_networks = ["10.20.0.0/99"]\n', encoding="utf-8")
    with pytest.raises(ValueError, match="allowed_client_networks"):
        load_settings(config_path=cfg, environ={})


def test_exposure_loosening_fires_on_exposure_not_on_the_bind() -> None:
    # R1: an off-box bind with no allow-list.
    names = [n for n, _ in _loosenings(SecuritySettings(local_access_only=False))]
    assert "allowed_client_networks" in names
    # R2 — the REGRESSION GUARD. The recommended off-box topology keeps the loopback bind and puts a
    # reverse proxy in front, so a `not local_access_only` test alone would never fire in the
    # most-exposed supported posture.
    names = [
        n
        for n, _ in _loosenings(
            SecuritySettings(web_console_public_address="https://ops.example.com")
        )
    ]
    assert "allowed_client_networks" in names
    # Set the allow-list and it stops being a loosening, in both postures.
    for sec in (
        SecuritySettings(local_access_only=False, allowed_client_networks=WARD),
        SecuritySettings(
            web_console_public_address="https://ops.example.com", allowed_client_networks=WARD
        ),
    ):
        assert "allowed_client_networks" not in [n for n, _ in _loosenings(sec)]


# --- the trusted_proxies pairing (a broad range would nullify the whole control) -------------------


def test_broad_trusted_proxies_refused_once_the_allowlist_is_in_use() -> None:
    # Any host inside a trusted range can set X-Forwarded-For to anything and uvicorn hands that value
    # back as scope["client"] — so a /8 of trusted spoofers reduces the allow-list to decoration.
    with pytest.raises(ValueError, match="SINGLE HOST"):
        ServiceSettings(
            security=SecuritySettings(allowed_client_networks=WARD),
            api=ApiSettings(trusted_proxies=["10.0.0.0/8"]),
        )
    with pytest.raises(ValueError, match="SINGLE HOST"):
        ServiceSettings(
            security=SecuritySettings(allowed_client_networks=WARD),
            api=ApiSettings(trusted_proxies=["10.0.0.1", "192.168.0.0/24"]),
        )
    # Single hosts — bare, /32 and /128 — are exactly what the control needs, and load.
    ServiceSettings(
        security=SecuritySettings(allowed_client_networks=WARD),
        api=ApiSettings(trusted_proxies=["10.0.0.1", "10.0.0.2/32", "fd00::1/128"]),
    )
    # "*" is refused outright (the prerequisite ApiSettings validator), allow-list or not.
    with pytest.raises(ValueError, match=r"trusted_proxies"):
        ApiSettings(trusted_proxies=["*"])
    # Scoped to the opt-in: a broad trusted_proxies with NO allow-list still loads (no regression).
    ServiceSettings(api=ApiSettings(trusted_proxies=["10.0.0.0/8"]))


# --- HTTP enforcement ----------------------------------------------------------------------------


async def test_empty_list_is_a_no_op_from_every_address(engine: Engine) -> None:
    """Load-bearing: the DEFAULT path must be unchanged. Every address — including ones a non-empty
    list would refuse, an unparseable one, and no client tuple at all — reaches the app."""
    app = _app(engine, [])
    assert app.state.client_networks == ()
    for ip in ("10.9.9.9", "192.168.5.5", "::1", "127.0.0.1", "203.0.113.7", None):
        async with _client(app, ip) as c:
            resp = await c.get("/health")
            assert resp.status_code == 200, ip
            body = resp.json()
            assert body["status"] == "ok"
            # No allow-list -> no observed_client echo: the stock /health payload is unchanged.
            assert body["observed_client"] is None
            assert DENIAL_HEADER not in resp.headers
    # And nothing was counted.
    assert app.state.client_denials == 0


async def test_r1_direct_bind_allows_in_network_and_refuses_out_of_network(engine: Engine) -> None:
    app = _app(engine, WARD)
    async with _client(app, "10.4.4.4") as c:
        assert (await c.get("/health")).status_code == 200
        # A gated route reaches the app (whatever it then answers) — the gate did not intervene.
        assert DENIAL_HEADER not in (await c.get("/status")).headers
    async with _client(app, "192.168.9.9") as c:
        resp = await c.get("/status")
    assert resp.status_code == 403
    assert resp.headers[DENIAL_HEADER] == DENIAL_MARKER
    body = resp.json()
    assert "allowed_client_networks" in body["detail"]
    assert body["denied"] == DENIAL_MARKER
    assert body["observed_client"] == "192.168.9.9"
    assert app.state.client_denials == 1
    assert app.state.client_denied_last == "192.168.9.9"


async def test_r1_forwarding_headers_are_never_consulted(engine: Engine) -> None:
    """THE central correctness rule. With no proxy declared, uvicorn performs no rewrite, so an
    attacker-authored X-Forwarded-For / X-Real-IP / RFC 7239 Forwarded must change nothing."""
    app = _app(engine, WARD)
    async with _client(app, "192.168.9.9") as c:
        resp = await c.get(
            "/status",
            headers={
                "X-Forwarded-For": "10.0.0.5",
                "X-Real-IP": "10.0.0.5",
                "Forwarded": "for=10.0.0.5",
            },
        )
    assert resp.status_code == 403
    assert resp.json()["observed_client"] == "192.168.9.9"


async def test_r1_end_to_end_through_uvicorns_proxy_middleware(engine: Engine) -> None:
    """The same claim, proven through the REAL uvicorn middleware the engine runs behind, configured
    exactly as ``__main__`` configures it from an empty ``[api].trusted_proxies``."""
    wrapped = ProxyHeadersMiddleware(_app(engine, WARD), trusted_hosts=[])
    async with _client(wrapped, "192.168.9.9") as c:
        resp = await c.get("/status", headers={"X-Forwarded-For": "10.0.0.5"})
    assert resp.status_code == 403
    assert resp.json()["observed_client"] == "192.168.9.9"


async def test_r2_declared_proxy_sees_the_real_client(engine: Engine) -> None:
    """R2, the RECOMMENDED topology: engine on loopback, nginx faces the network and is DECLARED in
    [api].trusted_proxies. uvicorn rewrites scope["client"] from XFF before any app middleware runs,
    so the gate keys on the real client — allowing an in-network browser and refusing an out-of-
    network one, even though BOTH arrive on the same socket from the proxy."""
    proxy = "203.0.113.10"
    wrapped = ProxyHeadersMiddleware(_app(engine, WARD), trusted_hosts=[proxy])
    async with _client(wrapped, proxy) as c:
        allowed = await c.get("/health", headers={"X-Forwarded-For": "10.4.4.4"})
        denied = await c.get("/status", headers={"X-Forwarded-For": "192.168.9.9"})
    assert allowed.status_code == 200
    assert denied.status_code == 403
    assert denied.json()["observed_client"] == "192.168.9.9"


async def test_r2_self_spoofing_is_defeated_by_the_reverse_walk(engine: Engine) -> None:
    """An out-of-network client that prepends its own hop cannot promote itself: uvicorn walks the
    XFF chain from the right and stops at the first UNTRUSTED hop, which is the attacker's own
    address, not the value it authored. (This holds only because a trusted_proxies entry covering the
    attacker is refused at load — see test_broad_trusted_proxies_refused_once_the_allowlist_is_in_use.)"""
    proxy = "203.0.113.10"
    wrapped = ProxyHeadersMiddleware(_app(engine, WARD), trusted_hosts=[proxy])
    async with _client(wrapped, proxy) as c:
        resp = await c.get("/status", headers={"X-Forwarded-For": "10.4.4.4, 192.168.9.9"})
    assert resp.status_code == 403
    assert resp.json()["observed_client"] == "192.168.9.9"


async def test_r3_undeclared_proxy_is_inert_and_says_so(engine: Engine) -> None:
    """R3 is an HONEST LIMIT, pinned so nobody later documents it as covered: with nothing declared,
    every request in the world resolves to the on-box proxy's loopback address, the loopback
    exemption admits it, and the control does nothing. The monoculture tripwire is the only signal."""
    app = _app(engine, WARD)
    async with _client(app, "127.0.0.1") as c:
        for _ in range(51):
            assert (
                await c.get("/health", headers={"X-Forwarded-For": "192.168.9.9"})
            ).status_code == 200
        # /health is exempt, so drive the tripwire through a gated path too.
        for _ in range(51):
            await c.get("/status")
    assert app.state.client_denials == 0  # nothing was ever refused — that is the point
    assert app.state.client_address_monoculture is True


async def test_loopback_is_allowed_unconditionally_even_with_forwarding_headers(
    engine: Engine,
) -> None:
    """Pins decision D-1 against a regression to "allow loopback only if no X-Forwarded-For". In the
    recommended R2 topology the proxy runs ON the engine box, so an on-box operator's own request
    legitimately arrives with XFF present and resolves to loopback — the conditional rule would lock
    the on-box operator out of the supported posture."""
    app = _app(engine, WARD)
    for ip in ("127.0.0.1", "::1", "::ffff:127.0.0.1"):
        async with _client(app, ip) as c:
            assert (await c.get("/health")).status_code == 200, ip
            with_xff = await c.get("/health", headers={"X-Forwarded-For": "127.0.0.1"})
            assert with_xff.status_code == 200, ip


async def test_ipv6_and_ipv4_mapped_clients(engine: Engine) -> None:
    app6 = _app(engine, ["2001:db8::/32"])
    async with _client(app6, "2001:db8::5") as c:
        assert (await c.get("/health")).status_code == 200
    async with _client(app6, "2001:dba::5") as c:
        assert (await c.get("/status")).status_code == 403
    # A dual-stack socket delivers an IPv4 client as ::ffff:a.b.c.d; it must match the v4 entry.
    app4 = _app(engine, WARD)
    async with _client(app4, "::ffff:10.0.0.5") as c:
        assert (await c.get("/health")).status_code == 200


async def test_unparseable_client_fails_closed(engine: Engine) -> None:
    # starlette's TestClient sends the literal "testclient"; a UNIX socket sends no client tuple.
    # Neither can be PROVEN in-network, so both are denied — without any ValueError escaping.
    app = _app(engine, WARD)
    for ip in ("testclient", None):
        async with _client(app, ip) as c:
            resp = await c.get("/status")
        assert resp.status_code == 403, ip
    assert (await _client(_app(engine, []), "testclient").get("/health")).status_code == 200


async def test_denial_carries_the_baseline_security_headers(engine: Engine) -> None:
    """The gate is the OUTERMOST middleware, so a denial short-circuits both the engine's
    security-headers middleware and the console's — it must set the baseline itself."""
    async with _client(_app(engine, WARD), "192.168.9.9") as c:
        resp = await c.get("/status")
    assert resp.headers["X-Content-Type-Options"] == "nosniff"
    assert resp.headers["Referrer-Policy"] == "no-referrer"
    assert resp.headers["X-Frame-Options"] == "DENY"
    assert resp.headers["Cache-Control"] == "no-store"


async def test_ui_and_html_clients_get_a_self_contained_denial_page(engine: Engine) -> None:
    app = _app(engine, WARD)
    async with _client(app, "192.168.9.9") as c:
        page = await c.get("/ui")
        accepts_html = await c.get("/status", headers={"Accept": "text/html,*/*"})
    for resp in (page, accepts_html):
        assert resp.status_code == 403
        assert resp.headers["content-type"].startswith("text/html")
        assert "allowed_client_networks" in resp.text
        assert "192.168.9.9" in resp.text  # self-diagnosing: the address the ENGINE saw
        assert resp.headers[DENIAL_HEADER] == DENIAL_MARKER
        # No external assets: /ui/static is behind this same gate, so anything external would 403.
        assert "src=" not in resp.text and "href=" not in resp.text


async def test_denial_precedes_authentication_and_authorization(engine: Engine) -> None:
    """A refused address never reaches auth (so it cannot probe credentials), and a VALID admin token
    from a refused address is refused just the same — the gate is not an authorization decision."""
    service = await _service(engine)
    await _add_viewer(service, "vw")
    app = _app(engine, WARD, auth=service)
    async with _client(app, "10.4.4.4") as c:
        token = (
            await c.post(
                "/auth/login", json={"username": "vw", "password": PW, "provider": "local"}
            )
        ).json()["token"]
    async with _client(app, "192.168.9.9") as c:
        anon = await c.get("/status")
        authed = await c.get("/status", headers={"Authorization": f"Bearer {token}"})
        login = await c.post(
            "/auth/login", json={"username": "vw", "password": PW, "provider": "local"}
        )
    for resp in (anon, authed, login):
        assert resp.status_code == 403
        assert resp.headers[DENIAL_HEADER] == DENIAL_MARKER


async def test_static_mount_is_covered(engine: Engine) -> None:
    """The /ui/static mount is a router route, so only an OUTERMOST middleware covers it."""
    app = _app(engine, WARD, serve_ui=True)
    async with _client(app, "192.168.9.9") as c:
        resp = await c.get("/ui/static/app.js")
    assert resp.status_code == 403
    async with _client(app, "10.4.4.4") as c:
        assert (await c.get("/ui/static/app.js")).status_code == 200


async def test_health_stays_reachable_and_echoes_the_observed_address(engine: Engine) -> None:
    """The one self-service diagnostic a locked-out operator has: curl /health from the machine that
    cannot get in and read back exactly which address the engine matches."""
    app = _app(engine, WARD)
    async with _client(app, "192.168.9.9") as c:
        assert (await c.get("/status")).status_code == 403  # gated
        resp = await c.get("/health")  # exempt
    assert resp.status_code == 200
    body = resp.json()
    assert body["observed_client"] == "192.168.9.9"
    # The tray's classify_health keys on status_code == 200 and "status" in body — still true.
    assert body["status"] == "ok"
    from messagefoundry.tray.probe import HealthProbe, classify_health

    assert classify_health(200, body) is HealthProbe.OK


async def test_posture_publishes_the_denial_counters(engine: Engine) -> None:
    service = await _service(engine)
    await _add_viewer(service, "vw")
    app = _app(engine, WARD, auth=service)
    async with _client(app, "192.168.9.9") as c:
        await c.get("/status")
        await c.get("/status")
    async with _client(app, "10.4.4.4") as c:
        token = (
            await c.post(
                "/auth/login", json={"username": "vw", "password": PW, "provider": "local"}
            )
        ).json()["token"]
        posture = (
            await c.get("/security/posture", headers={"Authorization": f"Bearer {token}"})
        ).json()
    assert posture["client_network_denials"] == 2
    assert posture["client_denied_last"] == "192.168.9.9"
    assert posture["client_address_monoculture"] is False
    # The allow-list itself appears in the [security] dump — topology, not secret, on a route that is
    # permission-gated and audited. Pinned so a change is deliberate.
    assert posture["security"]["allowed_client_networks"] == WARD


async def test_denial_is_logged_with_the_address_and_the_setting(
    engine: Engine, caplog: pytest.LogCaptureFixture
) -> None:
    """An undiagnosable CIDR rejection is the most likely way this control gets ripped back out, so
    the log line must name the observed address AND the setting."""
    caplog.set_level("WARNING", logger="messagefoundry.api.client_networks")
    async with _client(_app(engine, WARD), "192.168.9.9") as c:
        await c.get("/status")
    messages = [r.getMessage() for r in caplog.records]
    assert any("192.168.9.9" in m and "allowed_client_networks" in m for m in messages)


async def test_denial_logging_is_rate_limited_per_address(
    engine: Engine, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level("WARNING", logger="messagefoundry.api.client_networks")
    app = _app(engine, WARD)
    async with _client(app, "192.168.9.9") as c:
        for _ in range(20):
            await c.get("/status")
    refusals = [r for r in caplog.records if "refused an operator" in r.getMessage()]
    assert len(refusals) == 1  # one line per (address, hour) — a flood must not fill the log
    assert app.state.client_denials == 20  # ...but every refusal is still COUNTED


# --- WebSocket -----------------------------------------------------------------------------------


class _WSPeer:
    """A minimal in-memory ASGI websocket peer that drives the real app callable."""

    def __init__(self, app: Any, client: tuple[str, int] | None) -> None:
        self._app = app
        self._client = client
        self._to_server: asyncio.Queue[dict[str, object]] = asyncio.Queue()
        self.accepted = False
        self.frames: list[dict[str, object]] = []
        self.close_code: int | None = None

    async def _receive(self) -> dict[str, object]:
        return await self._to_server.get()

    async def _send(self, message: dict[str, object]) -> None:
        kind = message["type"]
        if kind == "websocket.accept":
            self.accepted = True
        elif kind == "websocket.send":
            self.frames.append(json.loads(message["text"]))  # type: ignore[arg-type]
        elif kind == "websocket.close":
            self.close_code = int(message.get("code", 1000))  # type: ignore[arg-type]

    async def run(self, timeout: float = 5.0) -> None:
        scope = {
            "type": "websocket",
            "path": "/ws/stats",
            "headers": [],
            "query_string": b"",
            "subprotocols": [],
            "client": self._client,
            "scheme": "ws",
            "app": None,  # Starlette.__call__ overwrites this with the app itself
        }
        await self._to_server.put({"type": "websocket.connect"})
        await asyncio.wait_for(self._app(scope, self._receive, self._send), timeout)


async def test_websocket_from_a_denied_address_is_closed_before_accept(engine: Engine) -> None:
    """The WS gap is the single biggest correctness trap here: BaseHTTPMiddleware passes every
    websocket scope straight through, so a BaseHTTPMiddleware gate would leave /ws/stats reachable
    from ANY address. This drives the real ASGI callable to prove the pure-ASGI form closes it."""
    app = _app(engine, WARD)
    peer = _WSPeer(app, ("192.168.9.9", 40000))
    await peer.run()
    assert peer.accepted is False  # refused BEFORE the handshake — the route never ran
    assert peer.frames == []
    # 1008 = policy violation. NOTE: uvicorn maps a pre-handshake close to HTTP 403 and DISCARDS the
    # code, so this is observable in-process (and here), not on the wire.
    assert peer.close_code == 1008
    assert app.state.client_denials == 1


async def test_websocket_from_an_allowed_address_reaches_the_route(engine: Engine) -> None:
    # No token on this scope, so the ROUTE closes it 1008 for being unauthenticated — the point is
    # that the gate let it through to the route at all (no regression), and did not count a denial.
    app = _app(engine, WARD)
    peer = _WSPeer(app, ("10.4.4.4", 40000))
    await peer.run()
    assert app.state.client_denials == 0
    assert peer.accepted is False and peer.close_code == 1008  # refused by AUTH, not by the network


async def test_gate_stays_outermost_with_the_console_mounted(engine: Engine) -> None:
    """mount_ui installs UiSecurityHeadersMiddleware; the gate is registered AFTER it and so must
    still be outermost. If it slipped inside, the console's middleware (and the /ui/static mount)
    would run for a refused address."""
    app = _app(engine, WARD, serve_ui=True)
    assert app.user_middleware[0].cls is ClientNetworkMiddleware
    assert len([m for m in app.user_middleware if m.cls is ClientNetworkMiddleware]) == 1


async def test_gate_is_not_a_basehttpmiddleware(engine: Engine) -> None:
    """Regression guard for the trap above: assert the registered class is pure ASGI."""
    app = _app(engine, WARD)
    registered = [m for m in app.user_middleware if m.cls is ClientNetworkMiddleware]
    assert len(registered) == 1
    assert not issubclass(ClientNetworkMiddleware, BaseHTTPMiddleware)
    # ...and it is registered LAST, i.e. OUTERMOST (add_middleware inserts at index 0).
    assert app.user_middleware[0].cls is ClientNetworkMiddleware


def test_web_console_keys_on_the_same_denial_marker() -> None:
    """Drift guard across the Python/JS seam. The console distinguishes a network denial from an RBAC
    403 by the marker header — if the engine renames either constant, the console silently stops
    matching and goes back to freezing on stale data with no indication. mypy cannot see this."""
    app_js = (
        Path(__file__).resolve().parents[1] / "messagefoundry_webconsole" / "static" / "app.js"
    ).read_text(encoding="utf-8")
    assert f'"{DENIAL_HEADER}"' in app_js
    assert f'"{DENIAL_MARKER}"' in app_js
    # Every poller that reloads on an auth edge must also handle the network denial, or that poller
    # keeps painting the last-good view forever.
    assert app_js.count("mfNetworkDenied(resp)") >= 6


async def test_lifespan_scope_passes_through(engine: Engine) -> None:
    """Swallowing a non-request scope would break startup/shutdown outright."""
    seen: list[str] = []

    async def inner(scope: Any, receive: Any, send: Any) -> None:
        seen.append(scope["type"])

    mw = ClientNetworkMiddleware(inner)
    await mw({"type": "lifespan"}, lambda: None, lambda m: None)  # type: ignore[arg-type]
    assert seen == ["lifespan"]


# --- serve: advisory only, never a startup gate ---------------------------------------------------

SAMPLES_CONFIG = Path(__file__).resolve().parents[1] / "samples" / "config"


def _serve(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, toml: str, *, env: str) -> int:
    """Run ``serve`` through the gate ladder with the app + uvicorn mocked (no socket opened).
    Mirrors ``tests/test_security_config.py::_serve``."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("MEFOR_STORE_ENCRYPTION_KEY", "x" * 44)
    (tmp_path / "messagefoundry.toml").write_text(toml, encoding="utf-8")
    monkeypatch.setattr("messagefoundry.api.create_managed_app", lambda **kw: object())
    monkeypatch.setattr("uvicorn.run", lambda *a, **k: None)
    from messagefoundry.__main__ import main

    return main(["serve", "--config", str(SAMPLES_CONFIG), "--env", env])


_EXPOSED = (
    "security.handles_real_patient_data = false\n"
    "security.local_access_only = false\n"
    'security.listen_address = "0.0.0.0"\n'
    "security.block_unlisted_outbound = true\n"
    "security.delete_message_bodies_after_days = 30\n"
    '[api]\ntls_terminated_upstream = true\ntrusted_proxies = ["10.0.0.1"]\n'
)


def test_serve_warns_but_does_not_refuse_an_exposed_bind_with_no_allowlist(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Owner's explicit ruling: this is ADVISORY. An exposed bind with an empty allow-list STARTS —
    leaving it to the host firewall is a defensible choice, and a new startup refusal would break
    every existing off-box deployment on upgrade."""
    assert _serve(tmp_path, monkeypatch, _EXPOSED, env="dev") == 0
    out = capsys.readouterr().out
    assert "posture loosened" in out and "allowed_client_networks" in out


def test_serve_is_silent_once_the_allowlist_is_set(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # NOTE: inserted BEFORE the [api] table header — a dotted key appended after it would land in
    # [api], not [security], and silently test nothing.
    toml = _EXPOSED.replace(
        "[api]\n", 'security.allowed_client_networks = ["10.20.0.0/16"]\n[api]\n'
    )
    assert _serve(tmp_path, monkeypatch, toml, env="dev") == 0
    assert "allowed_client_networks" not in capsys.readouterr().out


def test_default_loopback_serve_emits_nothing_new(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Byte-identity at the default: the shipped loopback posture gains no warning from this feature."""
    toml = (
        "security.handles_real_patient_data = false\n"
        "security.block_unlisted_outbound = true\n"
        "security.delete_message_bodies_after_days = 30\n"
    )
    assert _serve(tmp_path, monkeypatch, toml, env="dev") == 0
    captured = capsys.readouterr()
    assert "allowed_client_networks" not in captured.out
    assert "allowed_client_networks" not in captured.err


# NOTE: test_runbook_example_block_actually_loads, test_runbook_proxy_replaces_rather_than_appends_the_forwarded_chain moved to tests/test_off_loopback_runbook.py (2026-07-26). They asserted against
# the deny-listed off-loopback runbook, so on the public mirror they failed at runtime and took
# this whole module's required test leg red — while the rest of this file guards shipped
# behaviour that must keep running publicly. The new home already carries the doc-absent guard.
