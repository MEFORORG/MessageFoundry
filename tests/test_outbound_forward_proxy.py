# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Outbound forward/egress web proxy for the stdlib HTTP family (BACKLOG #112/#127/#128, ADR 0126).

Covers, without touching the network (everything is decided at connector construction):

* **#112** — an explicit proxy address builds a PER-CONNECTION opener carrying a ``ProxyHandler`` (never
  the shared ``_NO_REDIRECT_OPENER``); ``proxy="default"`` uses the OS default web proxy
  (``getproxies()``); no proxy is byte-identical (the shared opener, no ``Proxy-Authorization``).
* **#127** — Basic proxy auth is a pre-emptive ``Proxy-Authorization`` header (tunnelled for https by
  urllib); a cleartext-http proxy hop carrying the credential is refused REGARDLESS of destination scheme
  (loopback allowed); Digest is refused for an https destination; NTLM/Windows are refused (deferred).
* **#128** — a target host matching ``proxy_no_proxy`` bypasses the proxy entirely (no handler, no cred).
* the OAuth2/SMART **token endpoint** is proxied too; the ``[egress].proxy_url`` site-wide default merges.
"""

from __future__ import annotations

import http.server
import threading
import urllib.request
import urllib.response

import pytest

from messagefoundry.config.models import ConnectorType, Destination
from messagefoundry.config.settings import EgressSettings
from messagefoundry.config.tls_policy import (
    HopPosture,
    InsecureHopRefused,
    active_hop_posture,
)
from messagefoundry.config.wiring import FHIR, DICOMweb, OutboundConnection, Rest, Soap, WiringError
from messagefoundry.pipeline.wiring_runner import (
    _apply_egress_proxy_default,
    _dest_config,
    check_egress_allowed,
)
from messagefoundry.transports import build_destination
from messagefoundry.transports.fhir import FhirLookupExecutor
from messagefoundry.transports.http_auth import HttpAuthError, OAuth2ClientCredentialsProvider
from messagefoundry.transports.rest import (
    _NO_REDIRECT_OPENER,
    ProxyConfig,
    _proxy_bypasses,
    _ProxyDigestRecipe,
    proxy_config_from_settings,
)
from messagefoundry.transports.smart import SmartBackendTokenProvider


def _rsa_pem() -> str:
    """A throwaway RSA private key (PKCS#8 PEM) so a SMART provider can be built off-network."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()


# ADR 0153: the data label no longer relaxes a cleartext hop, so the permissive posture for these
# PROXY-behaviour tests is the non-enforcing dial (which still WARNs, never refuses). Renamed from
# _SYNTHETIC so nothing here reads as if the label were still doing the work.
_WARN_DIAL = HopPosture(enforcing=False)
_PROD = HopPosture(enforcing=True)  # enforcing → the cleartext-proxy-hop guard bites

PROXY = "http://proxy.example.com:3128"
LOOPBACK_PROXY = "http://127.0.0.1:3128"  # a local auth proxy (cntlm) — allowed under any posture
HTTPS_DEST = "https://api.example.com/ingest"
HTTP_DEST_LOOPBACK = "http://127.0.0.1:8000/x"

_FACTORY = {
    ConnectorType.REST: Rest,
    ConnectorType.SOAP: Soap,
    ConnectorType.FHIR: FHIR,
    ConnectorType.DICOMWEB: DICOMweb,
}


def _build(
    ctype: ConnectorType,
    url: str,
    *,
    posture: HopPosture = _WARN_DIAL,
    attested: bool = False,
    accepted: bool = False,
    **over: object,
) -> object:
    """Build one outbound. ``accepted`` is ADR 0153's per-connection cleartext declaration — needed by
    the tests whose PROXY hop is plain http, since the proxy crossing is decided by the same authority
    as the destination crossing."""
    settings = _FACTORY[ctype](url=url, **over).settings  # type: ignore[operator]
    with active_hop_posture(posture):
        return build_destination(
            Destination(
                name="OB",
                type=ctype,
                settings=settings,
                tls_hop_attested=attested,
                tls_hop_attested_reason="proxy-terminated trusted segment" if attested else None,
                cleartext_accepted=accepted,
                cleartext_reason="on-prem proxy listener has no TLS" if accepted else None,
                tls_revocation_attested=True,  # isolate the proxy behaviour from the #201 revocation gate
                tls_revocation_attested_reason="revocation-checking PKI at the partner edge",
            )
        )


def _proxy_handler(opener: urllib.request.OpenerDirector) -> urllib.request.ProxyHandler | None:
    for h in opener.handlers:
        if isinstance(h, urllib.request.ProxyHandler):
            return h
    return None


# --- #112: address / "Use Default Web Proxy" / byte-identical ------------------------------------


@pytest.mark.parametrize("ctype", list(_FACTORY))
def test_explicit_proxy_builds_per_connection_opener(ctype: ConnectorType) -> None:
    """AC-1: an explicit proxy → a per-connection opener with a ProxyHandler for that address, and the
    shared verifying opener is NOT reused (and never mutated)."""
    dest = _build(ctype, HTTPS_DEST, proxy=PROXY)
    opener = dest._opener  # type: ignore[attr-defined]
    assert opener is not _NO_REDIRECT_OPENER
    ph = _proxy_handler(opener)
    assert ph is not None and ph.proxies == {"http": PROXY, "https": PROXY}
    # The shared opener's own default ProxyHandler was left untouched.
    shared_ph = _proxy_handler(_NO_REDIRECT_OPENER)
    assert shared_ph is None or shared_ph.proxies == {}


def test_use_default_web_proxy(monkeypatch: pytest.MonkeyPatch) -> None:
    """AC-2: proxy="default" builds a ProxyHandler from the OS/environment default web proxy."""
    monkeypatch.setattr(urllib.request, "getproxies", lambda: {"http": "http://sys:3128"})
    dest = _build(ConnectorType.REST, HTTPS_DEST, proxy="default")
    assert dest._proxy is not None and dest._proxy.use_default is True  # type: ignore[attr-defined]
    opener = dest._opener  # type: ignore[attr-defined]
    assert opener is not _NO_REDIRECT_OPENER
    ph = _proxy_handler(opener)
    assert ph is not None and ph.proxies == {"http": "http://sys:3128"}


@pytest.mark.parametrize("ctype", list(_FACTORY))
def test_no_proxy_is_byte_identical(ctype: ConnectorType) -> None:
    """AC-3: no proxy → the shared verifying opener is reused and no Proxy-Authorization is added."""
    dest = _build(ctype, HTTPS_DEST)
    assert dest._opener is _NO_REDIRECT_OPENER  # type: ignore[attr-defined]
    assert dest._proxy is None  # type: ignore[attr-defined]
    assert "Proxy-Authorization" not in dest._headers  # type: ignore[attr-defined]


# --- #127: credential types ----------------------------------------------------------------------


def test_basic_proxy_auth_preemptive_header() -> None:
    """AC-4: Basic proxy auth adds a pre-emptive Proxy-Authorization header (urllib tunnels it for an
    https destination via CONNECT)."""
    import base64

    dest = _build(
        ConnectorType.REST,
        HTTPS_DEST,
        # The PROXY hop is cleartext http and carries a credential, so under ADR 0153 it needs the
        # connection's declaration to cross — the destination hop here is https and unaffected.
        accepted=True,
        proxy=PROXY,
        proxy_user="pu",
        proxy_password="pw",
        proxy_auth_type="basic",
    )
    hdr = dest._headers.get("Proxy-Authorization", "")  # type: ignore[attr-defined]
    assert hdr.startswith("Basic ")
    assert base64.b64decode(hdr.split(" ", 1)[1]).decode() == "pu:pw"


def test_cleartext_proxy_hop_credential_refused() -> None:
    """AC-5: a proxy credential over a cleartext-http proxy hop on a production-PHI instance is refused
    REGARDLESS of the destination scheme; a loopback proxy is allowed."""
    with pytest.raises(InsecureHopRefused):
        _build(
            ConnectorType.REST,
            HTTPS_DEST,  # https destination — the credential still crosses the proxy in the clear
            posture=_PROD,
            proxy=PROXY,
            proxy_user="pu",
            proxy_password="pw",
        )
    # A local (loopback) authenticating proxy is allowed even on production PHI.
    dest = _build(
        ConnectorType.REST,
        HTTPS_DEST,
        posture=_PROD,
        proxy=LOOPBACK_PROXY,
        proxy_user="pu",
        proxy_password="pw",
    )
    assert dest._headers["Proxy-Authorization"].startswith("Basic ")  # type: ignore[attr-defined]


def test_digest_https_and_ntlm_windows_refused() -> None:
    """AC-6: Digest is refused for an https destination (digest-over-CONNECT unsupported); NTLM/Windows
    are refused (deferred). Digest for an http destination builds a reactive ProxyDigestAuthHandler."""
    with pytest.raises(ValueError, match="digest.*https|CONNECT"):
        _build(
            ConnectorType.REST,
            HTTPS_DEST,
            proxy=LOOPBACK_PROXY,
            proxy_user="pu",
            proxy_password="pw",
            proxy_auth_type="digest",
        )
    for kind in ("ntlm", "windows"):
        with pytest.raises(ValueError, match="deferred"):
            _build(
                ConnectorType.REST,
                HTTPS_DEST,
                proxy=LOOPBACK_PROXY,
                proxy_user="pu",
                proxy_password="pw",
                proxy_auth_type=kind,
            )
    # Digest against an http destination is supported (reactive handler folded into the opener).
    dest = _build(
        ConnectorType.REST,
        HTTP_DEST_LOOPBACK,
        proxy=LOOPBACK_PROXY,
        proxy_user="pu",
        proxy_password="pw",
        proxy_auth_type="digest",
    )
    handlers = dest._opener.handlers  # type: ignore[attr-defined]
    assert any(isinstance(h, urllib.request.ProxyDigestAuthHandler) for h in handlers)
    # Digest is reactive (no pre-emptive header).
    assert "Proxy-Authorization" not in dest._headers  # type: ignore[attr-defined]


# --- #1171 (ASVS 11.4.1): the proxy's 407 picks the Digest hash, so refuse all but SHA-256 --------


class _DigestProxy:
    """A loopback forward proxy that answers the first request with a 407 Digest challenge naming
    ``algorithm`` (or naming none when it is ``None``), and a 200 to any request carrying a
    ``Proxy-Authorization`` header. It records the header it was answered with, so a test can see
    which hash the engine actually used rather than only whether the call returned."""

    def __init__(self, algorithm: str | None) -> None:
        self.answered: list[str] = []
        outer = self

        class _Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                auth = self.headers.get("Proxy-Authorization")
                if auth is None:
                    chal = 'Digest realm="r", nonce="n0nce", qop="auth"'
                    if algorithm is not None:
                        chal += f", algorithm={algorithm}"
                    self.send_response(407)
                    self.send_header("Proxy-Authenticate", chal)
                else:
                    outer.answered.append(auth)
                    self.send_response(200)
                self.send_header("Content-Length", "0")
                self.end_headers()

            def log_message(self, format: str, *args: object) -> None:  # noqa: A002
                return  # keep the test output quiet

        self._server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        self.url = f"http://127.0.0.1:{self._server.server_address[1]}"
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)

    def __enter__(self) -> _DigestProxy:
        self._thread.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self._server.shutdown()
        self._server.server_close()
        self._thread.join(timeout=5)


def _open_through_digest_proxy(
    monkeypatch: pytest.MonkeyPatch, proxy: _DigestProxy
) -> urllib.response.addinfourl:
    """Send one request through a REST destination's per-connection opener to ``proxy``.

    ``proxy_bypass`` is pinned off: on Windows urllib consults the registry's proxy override list,
    which may name local addresses, and a bypassed request would never reach the 407 at all."""
    monkeypatch.setattr(urllib.request, "proxy_bypass", lambda host: False)
    dest = _build(
        ConnectorType.REST,
        HTTP_DEST_LOOPBACK,
        proxy=proxy.url,
        proxy_user="pu",
        proxy_password="pw",
        proxy_auth_type="digest",
    )
    opener = dest._opener  # type: ignore[attr-defined]
    return opener.open(urllib.request.Request(HTTP_DEST_LOOPBACK), timeout=10)  # type: ignore[no-any-return]


@pytest.mark.parametrize(
    ("algorithm", "why"),
    [
        (None, "a proxy that names NOTHING -- urllib defaults the parameter to MD5"),
        ("MD5", "a proxy that names MD5 outright"),
        ("SHA", "urllib's non-standard SHA is SHA-1"),
        ("MD5-sess", "a -sess variant of a disallowed hash"),
        ("SHA-256-sess", "urllib cannot compute -sess; it would raise a bare ValueError"),
        ("SHA-512-256", "approved by name, but urllib cannot compute it; a bare ValueError before"),
    ],
)
def test_proxy_digest_refuses_every_algorithm_but_sha256(
    monkeypatch: pytest.MonkeyPatch, algorithm: str | None, why: str
) -> None:
    """The proxy twin of the origin refusal in test_http_auth.py. Before #1171 closed this ground the
    proxy path used urllib's bare ``ProxyDigestAuthHandler`` and answered an MD5 or SHA-1 challenge.

    Refused as ``HttpAuthError`` specifically: a bare ``ValueError`` is what urllib raises for a hash it
    cannot compute, and that escaped the seam's contract. The proxy must never see an answer."""
    with (
        _DigestProxy(algorithm) as proxy,
        pytest.raises(HttpAuthError, match="not an approved hash") as ei,
    ):
        _open_through_digest_proxy(monkeypatch, proxy)
    assert "web proxy" in str(ei.value), why
    assert proxy.answered == [], f"the engine answered the proxy's challenge: {why}"


def test_proxy_digest_handler_answers_sha256() -> None:
    """POSITIVE CONTROL at the handler: a refuse-everything handler would pass every case above.

    The request is aimed AT the proxy URL so urllib's credential lookup matches; see the end-to-end
    control below for why that matters."""
    handler = _ProxyDigestRecipe(LOOPBACK_PROXY, "pu", "pw").build()
    assert isinstance(handler, urllib.request.ProxyDigestAuthHandler)
    chal = {"realm": "r", "nonce": "n", "algorithm": "SHA-256"}
    result = handler.get_authorization(urllib.request.Request(LOOPBACK_PROXY), chal)
    assert result and 'algorithm="SHA-256"' in result


# --- #128: intranet bypass -----------------------------------------------------------------------


def test_intranet_bypass() -> None:
    """AC-7: a destination host matching proxy_no_proxy bypasses the proxy — no handler, no credential
    (byte-identical to no proxy for that host)."""
    dest = _build(
        ConnectorType.REST,
        "https://svc.intranet.local/x",
        proxy=LOOPBACK_PROXY,
        proxy_user="pu",
        proxy_password="pw",
        proxy_no_proxy=["intranet.local"],
    )
    assert dest._opener is _NO_REDIRECT_OPENER  # type: ignore[attr-defined]
    assert "Proxy-Authorization" not in dest._headers  # type: ignore[attr-defined]
    # A non-matching host on the SAME connection config still gets the proxy.
    dest2 = _build(
        ConnectorType.REST,
        HTTPS_DEST,
        proxy=LOOPBACK_PROXY,
        proxy_user="pu",
        proxy_password="pw",
        proxy_no_proxy=["intranet.local"],
    )
    assert dest2._opener is not _NO_REDIRECT_OPENER  # type: ignore[attr-defined]
    assert "Proxy-Authorization" in dest2._headers  # type: ignore[attr-defined]


def test_intranet_bypass_ipv6() -> None:
    """A ``::1`` / ``2001:db8::1`` bypass entry matches its IPv6 destination — ``urlsplit().hostname``
    returns the UNBRACKETED, port-less literal, so the match must not truncate at the first colon."""
    # ::1 bypasses an https://[::1]:8443/ destination (no proxy handler, no credential).
    dest = _build(
        ConnectorType.REST,
        "https://[::1]:8443/x",
        proxy=LOOPBACK_PROXY,
        proxy_user="pu",
        proxy_password="pw",
        proxy_no_proxy=["::1"],
    )
    assert dest._opener is _NO_REDIRECT_OPENER  # type: ignore[attr-defined]
    assert "Proxy-Authorization" not in dest._headers  # type: ignore[attr-defined]
    # A DIFFERENT IPv6 host is NOT bypassed → still proxied (the truncation bug would have bypassed it,
    # since "2001:db8::2".split(":")[0] == "2001" would never equal the "::1" entry either — but the
    # positive case above is what the old code broke; assert the negative to pin correctness both ways).
    dest2 = _build(
        ConnectorType.REST,
        "https://[2001:db8::2]:8443/x",
        proxy=LOOPBACK_PROXY,
        proxy_user="pu",
        proxy_password="pw",
        proxy_no_proxy=["::1"],
    )
    assert dest2._opener is not _NO_REDIRECT_OPENER  # type: ignore[attr-defined]
    assert "Proxy-Authorization" in dest2._headers  # type: ignore[attr-defined]


def test_proxy_bypasses_unit() -> None:
    """_proxy_bypasses: IPv6 literals match intact; a non-IPv6 name:port / IPv4:port still strips its
    port; bracketed list entries normalize; wildcard/suffix forms still work."""
    # IPv6 — matched intact (the regression: the host must not be truncated at the first ':').
    assert _proxy_bypasses("::1", ("::1",))
    assert _proxy_bypasses("2001:db8::1", ("2001:db8::1",))
    assert _proxy_bypasses("::1", ("[::1]",))  # bracketed list entry normalizes
    assert not _proxy_bypasses("2001:db8::2", ("::1",))  # different IPv6 host — NOT bypassed
    # Non-IPv6 — a name:port / IPv4:port still strips its port to match a portless entry.
    assert _proxy_bypasses("host.example.com:8080", ("host.example.com",))
    assert _proxy_bypasses("10.0.0.5:443", ("10.0.0.5",))
    # Domain-suffix + wildcard forms unaffected.
    assert _proxy_bypasses("svc.intranet.local", ("intranet.local",))
    assert _proxy_bypasses("a.b.example.com", ("*.example.com",))
    assert _proxy_bypasses("anything", ("*",))
    assert not _proxy_bypasses("example.org", ("intranet.local",))


# --- token endpoints + egress default ------------------------------------------------------------


def test_token_endpoint_is_proxied() -> None:
    """AC-8: the OAuth2 token-endpoint call is routed through the connection's forward proxy too (opener
    ProxyHandler + pre-emptive Proxy-Authorization).

    The proxy hop here is cleartext http and carries a credential, so it needs the ADR 0153 declaration
    to cross — the proxy-credential chain reads it off the resolved settings, the same mapping it
    already reads ``tls_hop_attested`` from."""
    with active_hop_posture(_WARN_DIAL):
        cfg = proxy_config_from_settings(
            {"proxy_url": PROXY, "proxy_user": "pu", "proxy_password": "pw"},
            dest_scheme="https",
            cleartext_accepted=True,
            cleartext_reason="on-prem proxy listener has no TLS",
            connection=None,
        )
    assert isinstance(cfg, ProxyConfig)
    provider = OAuth2ClientCredentialsProvider(
        token_url="https://auth.example.com/token",
        client_id="cid",
        client_secret="s3cr3t",
        proxy=cfg,
    )
    ph = _proxy_handler(provider._opener)
    assert ph is not None and ph.proxies == {"http": PROXY, "https": PROXY}
    assert provider._proxy_auth.get("Proxy-Authorization", "").startswith("Basic ")


def test_smart_token_endpoint_is_proxied() -> None:
    """AC-8 (SMART leg): the SMART Backend Services token-endpoint POST is proxied too — its OWN opener
    carries the ProxyHandler and its own pre-emptive Proxy-Authorization (distinct wiring from OAuth2)."""
    with active_hop_posture(_WARN_DIAL):
        cfg = proxy_config_from_settings(
            {"proxy_url": PROXY, "proxy_user": "pu", "proxy_password": "pw"},
            dest_scheme="https",
            cleartext_accepted=True,
            cleartext_reason="on-prem proxy listener has no TLS",
            connection=None,
        )
    assert isinstance(cfg, ProxyConfig)
    provider = SmartBackendTokenProvider(
        token_url="https://auth.example.com/token",
        client_id="cid",
        private_key=_rsa_pem(),
        proxy=cfg,
    )
    ph = _proxy_handler(provider._opener)
    assert ph is not None and ph.proxies == {"http": PROXY, "https": PROXY}
    assert provider._proxy_auth.get("Proxy-Authorization", "").startswith("Basic ")


def test_egress_default_proxy() -> None:
    """AC-9: [egress].proxy_url is inherited by a connection that sets no proxy; a per-connection value
    wins verbatim."""
    egress = EgressSettings(proxy_url=PROXY, proxy_no_proxy=["intranet.local"])
    inherited = {"url": HTTPS_DEST}
    _apply_egress_proxy_default(inherited, egress)
    assert inherited["proxy_url"] == PROXY
    assert inherited["proxy_no_proxy"] == ["intranet.local"]
    # A per-connection proxy overrides the site default.
    own = {"url": HTTPS_DEST, "proxy_url": "http://own:8080"}
    _apply_egress_proxy_default(own, egress)
    assert own["proxy_url"] == "http://own:8080"
    # No egress default → byte-identical (nothing injected).
    none_settings: dict[str, object] = {"url": HTTPS_DEST}
    _apply_egress_proxy_default(none_settings, EgressSettings())
    assert "proxy_url" not in none_settings


def test_egress_default_proxy_is_gated_by_allowed_proxy() -> None:
    """The site-wide default is gated too, through the SAME copy-in the runner does (BACKLOG #1659).

    `_apply_egress_proxy_default` runs inside `_dest_config`, ahead of `check_egress_allowed`, so the
    merged value is already in `dest.settings` when the gate reads it — asserted here rather than
    assumed, because an inherited `[egress].proxy_url` is precisely the case a per-connection-only
    gate would miss.
    """
    oc = OutboundConnection("OB", Rest(url=HTTPS_DEST))
    unlisted = EgressSettings(allowed_http=["api.example.com"], proxy_url=PROXY)
    dest = _dest_config(oc, {}, egress=unlisted)
    assert dest.settings["proxy_url"] == PROXY  # the copy-in happened before the gate sees it
    with pytest.raises(WiringError, match="allowed_proxy"):
        check_egress_allowed(dest, unlisted)

    listed = EgressSettings(
        allowed_http=["api.example.com"], proxy_url=PROXY, allowed_proxy=["proxy.example.com:3128"]
    )
    check_egress_allowed(_dest_config(oc, {}, egress=listed), listed)  # no raise


# --- FhirLookup read executor honours the proxy --------------------------------------------------


def test_fhir_lookup_executor_proxied() -> None:
    """The fhir_lookup read hop (and its SMART token endpoint) traverse the proxy too."""
    with active_hop_posture(_WARN_DIAL):
        ex = FhirLookupExecutor(
            {
                "epic": {
                    "url": "https://fhir.example.org/fhir",
                    "proxy_url": PROXY,
                }
            }
        )
    opener = ex._opener["epic"]
    assert opener is not _NO_REDIRECT_OPENER
    ph = _proxy_handler(opener)
    assert ph is not None and ph.proxies == {"http": PROXY, "https": PROXY}
