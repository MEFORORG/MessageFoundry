# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Engine openers refuse a web-proxy credential on the legs where it could be read on the way
(vault BACKLOG #3416, #3417, #3418).

The rule, with its one exception, is stated once, on ``bounded_read.ProxyCredentialsRefusedError``.
Its proxy-URL half has
its own file, ``tests/test_proxy_url_credentials_refused.py``. This file pins the three cases that
docstring used to list as outside the check:

* **#3416.** A ``Proxy-Authorization`` header a caller set, such as the one a connection's
  ``proxy_user`` makes, crossed to a proxy written ``https://`` in a cleartext ``CONNECT``. The
  posture-keyed guard judged only a proxy written ``http://``. It now judges every proxy, and the
  opener refuses any caller-set header the guard did not admit.
* **#3417.** A header on a request that goes direct, past every proxy, reached the destination
  itself. ``build_strict_opener`` also did not refuse redirects, and urllib's redirect handler
  copies the header onto the new request.
* **#3418.** On the one leg that reaches a proxy over TLS, the credential went over a context that
  did not verify the proxy: ``verify_tls=false``, ``tls_allow_expired``, or no host name check.

It also pins #3442: a connection whose target urllib's own bypass list names attaches no header,
so that send goes direct and is not refused.

Each refusal is read on the wire, at a loopback socket that records what reaches it, as well as in
the result. Each has a control in the other polarity.

Synthetic data only: the credentials are made up and every off-box host name is reserved.
"""

from __future__ import annotations

import asyncio
import base64
import contextlib
import http.server
import socket
import ssl
import sys
import threading
import urllib.error
import urllib.request
from collections.abc import Callable
from typing import Any

import pytest

from messagefoundry.auth.oidc_http import build_idp_opener
from messagefoundry.config.models import ConnectorType, Destination
from messagefoundry.config.tls_policy import (
    HopPosture,
    InsecureHopRefused,
    active_hop_posture,
    relax_verify_expiry,
    verifies_peer_fully,
)
from messagefoundry.config.wiring import Rest
from messagefoundry.pipeline import alert_sinks
from messagefoundry.transports import build_destination, rest
from messagefoundry.transports.base import DeliveryError
from messagefoundry.transports.bounded_read import (
    LoopbackDirectProxyHandler,
    NoRedirectHandler,
    ProxyCredentialsRefusedError,
    build_strict_opener,
)
from messagefoundry.transports.rest import RestDestination
from tests._egress_policy import permitting
from tests._wire_proxy import _WireProxy

_CRED = "u5er:pa55w0rd"
#: What urllib puts on the wire for that pair, and what ``proxy_user`` builds from it.
_HEADER = "Basic " + base64.b64encode(_CRED.encode()).decode()

_HTTP_TARGET = "http://partner.example.test/x"
_HTTPS_TARGET = "https://partner.example.test/x"
#: A proxy nothing could reach, for the tests that record a dial and open no socket.
_MARKER = "proxy-marker.invalid:9"

_PROXY_ENV = ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY", "REQUEST_METHOD")


@pytest.fixture(autouse=True)
def no_ambient_proxy(monkeypatch: pytest.MonkeyPatch) -> None:
    """Only the proxy a test names can route a request, and only a bypass list it sets applies."""
    for name in _PROXY_ENV:
        monkeypatch.delenv(name, raising=False)
        monkeypatch.delenv(name.lower(), raising=False)
    for source in ("registry", "macosx_sysconf"):
        monkeypatch.setattr(urllib.request, f"getproxies_{source}", dict, raising=False)
        monkeypatch.setattr(
            urllib.request, f"proxy_bypass_{source}", lambda host: False, raising=False
        )


class _Dialled(Exception):
    """Raised in place of the connection urllib was about to open."""

    def __init__(self, host: str, proxy_header: str | None) -> None:
        super().__init__(host)
        self.host = host
        self.proxy_header = proxy_header


@pytest.fixture
def recorded(monkeypatch: pytest.MonkeyPatch) -> None:
    """Replace the one method through which urllib dials with a recorder. The strict handlers'
    own checks run before it, so a refusal still raises first."""

    def do_open(
        self: object, http_class: object, req: urllib.request.Request, **kw: object
    ) -> None:
        raise _Dialled(req.host, req.get_header("Proxy-authorization"))

    monkeypatch.setattr(urllib.request.AbstractHTTPHandler, "do_open", do_open)


def _with_header(url: str) -> urllib.request.Request:
    return urllib.request.Request(url, headers={"Proxy-Authorization": _HEADER})


def _refused(
    opener: urllib.request.OpenerDirector, request: urllib.request.Request | str, item: str
) -> None:
    with pytest.raises(ProxyCredentialsRefusedError) as raised:
        opener.open(request, timeout=5)
    text = f"{raised.value!s} {raised.value!r}"
    assert f"vault BACKLOG {item}" in text or f", {item}" in text
    for part in ("u5er", "pa55w0rd", _HEADER, "127.0.0.1", "proxy-marker"):
        assert part not in text, part


def _open_and_discard(opener: urllib.request.OpenerDirector, request: object) -> None:
    """Send one request. The fake proxy serves no TLS, so most end in a transport error; what the
    test reads is what reached the socket."""
    with contextlib.suppress(urllib.error.URLError), opener.open(request, timeout=5) as resp:  # type: ignore[arg-type]
        resp.read()


def _rest(
    url: str,
    *,
    posture: HopPosture | None = None,
    accepted: bool = False,
    attested: bool = False,
    **extra: object,
) -> RestDestination:
    """One REST destination, built under ``posture``. ``accepted`` and ``attested`` set ADR 0153's
    ``cleartext_accepted`` and ``tls_hop_attested``, each with its reason field."""
    settings = Rest(url=url).settings
    settings.update(extra)
    with active_hop_posture(posture or HopPosture(enforcing=True)):
        dest = build_destination(
            Destination(
                name="OB_REST",
                type=ConnectorType.REST,
                settings=settings,
                cleartext_accepted=accepted,
                cleartext_reason="legacy partner listener has no TLS" if accepted else None,
                tls_hop_attested=attested,
                tls_hop_attested_reason="IPsec tunnel to the partner" if attested else None,
                tls_revocation_attested=True,  # isolate the proxy behaviour from the #201 gate
                tls_revocation_attested_reason="revocation-checking PKI at the partner edge",
            ),
            egress=permitting(settings),
        )
    assert isinstance(dest, RestDestination)
    return dest


def _send_refused(dest: RestDestination, item: str) -> None:
    with pytest.raises(DeliveryError) as raised:
        asyncio.run(dest.send('{"a": 1}'))
    assert isinstance(raised.value.__cause__, ProxyCredentialsRefusedError)
    text = str(raised.value)
    assert item in text
    for part in ("u5er", "pa55w0rd", _HEADER):
        assert part not in text, part


def _proxy_handler(dest: RestDestination) -> LoopbackDirectProxyHandler:
    opened = dest._opener.handlers  # type: ignore[attr-defined]
    handlers = [h for h in opened if isinstance(h, LoopbackDirectProxyHandler)]
    assert len(handlers) == 1
    return handlers[0]


# --- #3416: a caller-set header, and a proxy written https:// ------------------------------------


@pytest.mark.parametrize("target", [_HTTP_TARGET, _HTTPS_TARGET])
@pytest.mark.parametrize("scheme", ["http", "https"])
def test_a_caller_set_proxy_header_is_refused_before_a_cleartext_leg(
    target: str, scheme: str
) -> None:
    """One proxy for both schemes, written either way. Every leg reaches it before any TLS, so the
    header the caller set is refused and the proxy is not dialled (vault BACKLOG #3416)."""
    with _WireProxy() as proxy:
        value = f"{scheme}://{proxy.address}"
        opener = build_strict_opener(urllib.request.ProxyHandler({"http": value, "https": value}))
        _refused(opener, _with_header(target), "#3416")
    assert proxy.connections == 0


def test_control_an_admitted_caller_set_header_reaches_the_proxy() -> None:
    """The one way across: a handler whose connection's guard admitted the credential. The same
    proxy written ``https://`` gets the header in its ``CONNECT``, which is what the declared
    acceptance accepts."""
    with _WireProxy() as proxy:
        value = f"https://{proxy.address}"
        handler = LoopbackDirectProxyHandler(
            {"http": value, "https": value}, caller_header_admitted=True
        )
        _open_and_discard(build_strict_opener(handler), _with_header(_HTTPS_TARGET))
    assert len(proxy.cleartext) == 1
    assert proxy.cleartext[0].startswith(b"CONNECT partner.example.test:443 ")
    assert f"Proxy-Authorization: {_HEADER}\r\n".encode() in proxy.cleartext[0]


def test_admission_never_covers_a_credential_from_a_proxy_url() -> None:
    with _WireProxy() as proxy:
        value = f"https://{_CRED}@{proxy.address}"
        handler = LoopbackDirectProxyHandler(
            {"http": value, "https": value}, caller_header_admitted=True
        )
        _refused(build_strict_opener(handler), _HTTPS_TARGET, "#2572")
    assert proxy.connections == 0


_OFF_BOX_HTTPS_PROXY = "https://proxy.example.com:3128"


def test_proxy_user_with_a_proxy_written_https_is_refused_when_the_connection_is_built() -> None:
    """The report's shape: ``proxy_user`` and ``proxy_password`` with an off-box proxy written
    ``https://``, under an enforcing posture, and no declaration (vault BACKLOG #3416)."""
    with pytest.raises(InsecureHopRefused, match="before any TLS"):
        _rest(
            _HTTPS_TARGET,
            proxy_url=_OFF_BOX_HTTPS_PROXY,
            proxy_user="u5er",
            proxy_password="pa55w0rd",
        )


@pytest.mark.parametrize("declaration", ["accepted", "attested"])
def test_control_a_declared_connection_builds_and_its_handler_admits_the_header(
    declaration: str,
) -> None:
    """``cleartext_accepted`` with ``cleartext_reason``, or ``tls_hop_attested`` with
    ``tls_hop_attested_reason``: the guard admits the credential, and the proxy handler carries that
    admission to send time."""
    dest = _rest(
        _HTTPS_TARGET,
        proxy_url=_OFF_BOX_HTTPS_PROXY,
        proxy_user="u5er",
        proxy_password="pa55w0rd",
        **{declaration: True},  # type: ignore[arg-type]
    )
    assert dest._headers["Proxy-Authorization"] == _HEADER
    assert _proxy_handler(dest).caller_header_admitted is True


def test_control_a_proxy_written_https_with_no_proxy_user_builds_as_before() -> None:
    dest = _rest(_HTTPS_TARGET, proxy_url=_OFF_BOX_HTTPS_PROXY)
    assert "Proxy-Authorization" not in dest._headers
    assert _proxy_handler(dest).caller_header_admitted is False


def test_a_loopback_proxy_credential_crosses_end_to_end(monkeypatch: pytest.MonkeyPatch) -> None:
    """A REST send through a credentialed proxy on the box, which the guard allows in every
    posture. The admitted header reaches the proxy in the ``CONNECT``."""
    monkeypatch.setattr(urllib.request, "proxy_bypass", lambda host: False)
    with _WireProxy() as proxy:
        dest = _rest(
            _HTTPS_TARGET,
            proxy_url=f"https://{proxy.address}",
            proxy_user="u5er",
            proxy_password="pa55w0rd",
        )
        with contextlib.suppress(DeliveryError):
            asyncio.run(dest.send('{"a": 1}'))
    assert len(proxy.cleartext) == 1
    assert f"Proxy-Authorization: {_HEADER}\r\n".encode() in proxy.cleartext[0]


# --- #3417: a request that goes direct, and redirects -------------------------------------------


@pytest.mark.parametrize(
    "proxies",
    [
        pytest.param({}, id="no-proxy"),
        pytest.param({"http": f"http://{_MARKER}", "https": f"http://{_MARKER}"}, id="loopback"),
    ],
)
def test_a_header_on_a_direct_request_to_a_loopback_host_is_refused(
    proxies: dict[str, str],
) -> None:
    """The destination is a recording socket on the box. A loopback host is never proxied, so the
    header would reach it; it is not dialled (vault BACKLOG #3417)."""
    with _WireProxy() as destination:
        opener = build_strict_opener(urllib.request.ProxyHandler(proxies))
        _refused(opener, _with_header(f"http://{destination.address}/x"), "#3417")
    assert destination.connections == 0


def test_control_a_direct_request_with_no_header_is_sent() -> None:
    with _WireProxy() as destination:
        opener = build_strict_opener(urllib.request.ProxyHandler({}))
        with opener.open(f"http://{destination.address}/x", timeout=5) as resp:
            assert resp.read() == b"ok"
    assert len(destination.cleartext) == 1


def test_a_header_on_a_request_the_bypass_list_sends_direct_is_refused(
    recorded: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("HTTP_PROXY", f"http://{_MARKER}")
    monkeypatch.setenv("NO_PROXY", "partner.example.test")
    opener = build_strict_opener()
    _refused(opener, _with_header(_HTTP_TARGET), "#3417")
    # Control: the same opener with no header dials the host direct.
    with pytest.raises(_Dialled) as dialled:
        opener.open(_HTTP_TARGET, timeout=1)
    assert dialled.value.host == "partner.example.test"


def test_a_header_on_a_scheme_with_no_proxy_entry_is_refused(recorded: None) -> None:
    """Only ``http`` is proxied, so an ``https`` request goes direct. The handler admits the header,
    and admission covers a proxy leg only. Control: the ``http`` request reaches the proxy with
    the header."""
    handler = LoopbackDirectProxyHandler({"http": f"http://{_MARKER}"}, caller_header_admitted=True)
    opener = build_strict_opener(handler)
    _refused(opener, _with_header(_HTTPS_TARGET), "#3417")
    with pytest.raises(_Dialled) as dialled:
        opener.open(_with_header(_HTTP_TARGET), timeout=1)
    assert dialled.value.host == _MARKER
    assert dialled.value.proxy_header == _HEADER


def _dial_to(monkeypatch: pytest.MonkeyPatch, host: str, address: str) -> None:
    """Point every connection urllib opens to ``host`` at the loopback ``address`` instead, so a
    reserved name that no DNS resolves can still be dialled direct, on a real socket."""
    real = socket.create_connection
    target_host, _, target_port = address.rpartition(":")

    def create_connection(addr: tuple[str, int], *args: Any, **kwargs: Any) -> socket.socket:
        if addr[0] == host:
            addr = (target_host, int(target_port))
        return real(addr, *args, **kwargs)

    monkeypatch.setattr(socket, "create_connection", create_connection)


def _proxied_rest(proxy: _WireProxy, url: str) -> RestDestination:
    """A ``proxy_user`` connection to a cleartext target, through ``proxy`` on the box, where the
    guard allows the credential in every posture."""
    return _rest(
        url,
        accepted=True,
        proxy_url=f"http://{proxy.address}",
        proxy_user="u5er",
        proxy_password="pa55w0rd",
    )


def _bypassed_send_goes_direct(monkeypatch: pytest.MonkeyPatch, url: str, host: str) -> None:
    """The send reaches the destination direct, with no proxy header, and is not refused; the
    proxy is never dialled (vault BACKLOG #3442)."""
    with _WireProxy() as proxy, _WireProxy() as destination:
        _dial_to(monkeypatch, host, destination.address)
        dest = _proxied_rest(proxy, url)
        assert "Proxy-Authorization" not in dest._headers
        asyncio.run(dest.send('{"a": 1}'))
    assert proxy.connections == 0
    assert len(destination.cleartext) == 1
    assert b"proxy-authorization" not in destination.cleartext[0].lower()


def test_a_rest_send_the_environment_bypass_list_names_goes_direct_cleanly(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A connection's ``proxy_user`` header, and ``NO_PROXY`` naming its destination. urllib dials
    that host direct, so the header is not attached and the send is not refused into a retry
    loop (vault BACKLOG #3442). Before the fix the header went on the request and the #3417 rule
    refused every send."""
    monkeypatch.setenv("NO_PROXY", "partner.example.test")
    _bypassed_send_goes_direct(monkeypatch, _HTTP_TARGET, "partner.example.test")


def test_a_bypass_entry_with_a_port_matches_as_urllib_reads_it(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """urllib asks its bypass list about the host with its port, so an entry naming the port
    matches there. ``for_host`` reads the URL the same way."""
    monkeypatch.setenv("NO_PROXY", "partner.example.test:8080")
    _bypassed_send_goes_direct(
        monkeypatch, "http://partner.example.test:8080/x", "partner.example.test"
    )


@pytest.mark.skipif(sys.platform != "win32", reason="urllib reads the override list on Windows")
def test_a_rest_send_the_windows_override_list_names_goes_direct_cleanly(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The registry's ``<local>`` entry bypasses a host with no dot in its name. The registry itself
    is not touched: its reader is replaced by that one rule, applied to the host without its port."""
    monkeypatch.setattr(
        urllib.request, "proxy_bypass_registry", lambda host: "." not in host.partition(":")[0]
    )
    _bypassed_send_goes_direct(monkeypatch, "http://partnerhost/x", "partnerhost")


def test_control_a_host_on_no_bypass_list_still_reaches_the_proxy_with_its_header(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("NO_PROXY", "elsewhere.example.test")
    with _WireProxy() as proxy, _WireProxy() as destination:
        _dial_to(monkeypatch, "partner.example.test", destination.address)
        dest = _proxied_rest(proxy, _HTTP_TARGET)
        asyncio.run(dest.send('{"a": 1}'))
    assert destination.connections == 0
    assert len(proxy.cleartext) == 1
    assert proxy.cleartext[0].startswith(b"POST http://partner.example.test/x ")
    assert f"Proxy-Authorization: {_HEADER}\r\n".encode() in proxy.cleartext[0]


class _Redirector:
    """A loopback server that answers every GET with a 302 to ``location``."""

    def __init__(self, location: str) -> None:
        class _Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                self.send_response(302)
                self.send_header("Location", location)
                self.send_header("Content-Length", "0")
                self.end_headers()

            def log_message(self, format: str, *args: object) -> None:  # noqa: A002
                return

        self._server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        self.url = f"http://127.0.0.1:{self._server.server_address[1]}/start"
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)

    def __enter__(self) -> _Redirector:
        self._thread.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self._server.shutdown()
        self._server.server_close()
        self._thread.join(timeout=5)


def test_measured_urllib_copies_a_proxy_header_onto_the_redirected_request() -> None:
    """Plain urllib, no engine code: it follows the 302, and the new request carries the header."""
    with _WireProxy() as target, _Redirector(f"http://{target.address}/next") as start:
        plain = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        _open_and_discard(plain, _with_header(start.url))
    assert len(target.cleartext) == 1
    assert f"Proxy-Authorization: {_HEADER}\r\n".encode() in target.cleartext[0]


def test_build_strict_opener_refuses_a_redirect_itself() -> None:
    """No redirect handler is passed, and the 302 is raised, not followed: the target is never
    dialled (vault BACKLOG #3417)."""
    with _WireProxy() as target, _Redirector(f"http://{target.address}/next") as start:
        opener = build_strict_opener(urllib.request.ProxyHandler({}))
        with pytest.raises(urllib.error.HTTPError) as raised:
            opener.open(start.url, timeout=5)
        raised.value.close()
    assert raised.value.code == 302
    assert target.connections == 0


@pytest.mark.parametrize(
    "handler",
    [urllib.request.HTTPRedirectHandler, urllib.request.HTTPRedirectHandler()],
    ids=["class", "instance"],
)
def test_build_strict_opener_refuses_a_redirect_handler_that_follows(handler: object) -> None:
    with pytest.raises(TypeError, match="redirect"):
        build_strict_opener(handler)  # type: ignore[arg-type]


#: Every engine opener family, built after the environment is set.
_FAMILIES: dict[str, Callable[[], urllib.request.OpenerDirector]] = {
    "bare": build_strict_opener,
    "http-family-shared": rest._no_redirect_opener,
    "http-family-verify-off": rest._insecure_opener,
    "http-family-expiry-relaxed": lambda: rest._expiry_relaxed_opener("partner.example.test"),
    "alert-webhook": alert_sinks._build_no_redirect_opener,
    "oidc": lambda: build_idp_opener(None),
}


@pytest.mark.parametrize("family", list(_FAMILIES))
def test_every_opener_family_carries_exactly_one_no_redirect_handler(family: str) -> None:
    opened = _FAMILIES[family]().handlers  # type: ignore[attr-defined]
    redirects = [h for h in opened if isinstance(h, urllib.request.HTTPRedirectHandler)]
    assert len(redirects) == 1
    assert isinstance(redirects[0], NoRedirectHandler)


# --- #3418: the TLS leg to a proxy, on a context that does not verify it ------------------------


def _hostname_off_opener(
    *extra: urllib.request.BaseHandler,
) -> urllib.request.OpenerDirector:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    return build_strict_opener(urllib.request.HTTPSHandler(context=ctx), *extra)


_UNVERIFIED: dict[str, Callable[..., urllib.request.OpenerDirector]] = {
    "verify-off": rest._insecure_opener,
    "expiry-relaxed": lambda *extra: rest._expiry_relaxed_opener("partner.example.test", *extra),
    "hostname-off": _hostname_off_opener,
}


@pytest.mark.parametrize("family", list(_UNVERIFIED))
def test_an_environment_proxy_credential_is_refused_over_unverified_tls(
    monkeypatch: pytest.MonkeyPatch, family: str
) -> None:
    """The report's leg: an ``http`` target, ``HTTP_PROXY`` naming a credentialed ``https://``
    proxy, and no ``HTTPS_PROXY``. urllib opens TLS to the proxy first, with the opener's own
    context. That context does not verify the proxy, so nothing is sent (vault BACKLOG #3418)."""
    with _WireProxy() as proxy:
        monkeypatch.setenv("HTTP_PROXY", f"https://{_CRED}@{proxy.address}")
        _refused(_UNVERIFIED[family](), _HTTP_TARGET, "#3418")
    assert proxy.connections == 0


@pytest.mark.parametrize("family", list(_UNVERIFIED))
def test_a_caller_set_header_is_refused_over_unverified_tls(family: str) -> None:
    """The same leg for a header a caller set that no connection admitted."""
    with _WireProxy() as proxy:
        handler = LoopbackDirectProxyHandler({"http": f"https://{proxy.address}"})
        _refused(_UNVERIFIED[family](handler), _with_header(_HTTP_TARGET), "#3418")
    assert proxy.connections == 0


@pytest.mark.parametrize("family", list(_UNVERIFIED))
def test_an_admitted_caller_set_header_is_still_refused_over_unverified_tls(family: str) -> None:
    """The exception covers cleartext legs only. The guard that admits a caller-set header never
    reads the TLS context, so on a leg whose context does not fully verify the proxy the admitted
    header is refused like any other, and the proxy is never dialled (vault BACKLOG #3418)."""
    with _WireProxy() as proxy:
        handler = LoopbackDirectProxyHandler(
            {"http": f"https://{proxy.address}"}, caller_header_admitted=True
        )
        _refused(_UNVERIFIED[family](handler), _with_header(_HTTP_TARGET), "#3418")
    assert proxy.connections == 0


def test_admission_never_carries_a_proxy_url_credential_to_a_second_proxy() -> None:
    """An admitting handler sends an ``http`` target to proxy A, written ``https://`` with a
    credential, and ``https`` to proxy B, written ``http://``. urllib puts A's credential on the
    request, hands it back for ``https``, and would send it to B in a cleartext ``CONNECT``. Only
    matching the header to a proxy URL tells it from the caller's own, so the send is refused and
    neither proxy is dialled (vault BACKLOG #3410). Measured 2026-10-12: with
    ``bounded_read._proxy_url_credentials`` replaced by ``lambda p: set()``, B received the
    ``CONNECT`` with A's credential and this test failed."""
    with _WireProxy() as proxy_a, _WireProxy() as proxy_b:
        handler = LoopbackDirectProxyHandler(
            {"http": f"https://{_CRED}@{proxy_a.address}", "https": f"http://{proxy_b.address}"},
            caller_header_admitted=True,
        )
        _refused(build_strict_opener(handler), _HTTP_TARGET, "#3410")
    assert proxy_b.connections == 0
    assert proxy_a.connections == 0


@pytest.mark.parametrize("build", [build_strict_opener, rest._no_redirect_opener])
def test_control_a_verifying_opener_reaches_the_proxy_over_tls_first(
    monkeypatch: pytest.MonkeyPatch, build: Callable[[], urllib.request.OpenerDirector]
) -> None:
    """The same leg on a verifying opener is let through, as the #3410 fix lets it: the proxy sees
    one connection, TLS first, and no cleartext request head."""
    with _WireProxy() as proxy:
        monkeypatch.setenv("HTTP_PROXY", f"https://{_CRED}@{proxy.address}")
        _open_and_discard(build(), _HTTP_TARGET)
    assert proxy.connections == 1
    assert proxy.tls_first == 1
    assert proxy.cleartext == []


@pytest.mark.parametrize(
    "hop",
    [
        pytest.param({"accepted": True}, id="cleartext_accepted"),
        pytest.param({"attested": True}, id="tls_hop_attested"),
    ],
)
@pytest.mark.parametrize(
    "relaxed",
    [
        pytest.param({"verify_tls": False}, id="verify_tls-false"),
        pytest.param({"tls_allow_expired": True}, id="tls_allow_expired"),
    ],
)
def test_a_rest_send_over_an_unverified_proxy_leg_is_refused(
    monkeypatch: pytest.MonkeyPatch, hop: dict[str, bool], relaxed: dict[str, object]
) -> None:
    """The report's REST case. An off-box ``http://`` destination outside any bypass list, which
    crosses ``refuse_cleartext_egress`` by its declaration, sets a relaxed TLS flag that verifies
    nothing on its own hop. ``HTTP_PROXY`` names a credentialed ``https://`` proxy and no
    ``HTTPS_PROXY`` is set. The proxy leg uses the relaxed context, so the send is refused before
    the proxy is dialled (vault BACKLOG #3418)."""
    with _WireProxy() as proxy:
        monkeypatch.setenv("HTTP_PROXY", f"https://{_CRED}@{proxy.address}")
        _send_refused(_rest(_HTTP_TARGET, **hop, **relaxed), "#3418")  # type: ignore[arg-type]
    assert proxy.connections == 0


def test_control_a_rest_send_over_a_verifying_proxy_leg_reaches_the_proxy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The same destination with TLS verification left on. ``proxy_url = "default"`` gives it a
    per-connection opener that reads ``HTTP_PROXY`` when it is built; the shared opener read the
    environment at import. The proxy gets one connection, TLS first."""
    with _WireProxy() as proxy:
        monkeypatch.setenv("HTTP_PROXY", f"https://{_CRED}@{proxy.address}")
        dest = _rest(_HTTP_TARGET, accepted=True, proxy_url="default")
        with contextlib.suppress(DeliveryError):
            asyncio.run(dest.send('{"a": 1}'))
    assert proxy.connections == 1
    assert proxy.tls_first == 1
    assert proxy.cleartext == []


def test_verifies_peer_fully_reads_each_relaxation() -> None:
    ctx = ssl.create_default_context()
    assert verifies_peer_fully(ctx)
    assert not verifies_peer_fully(None)
    expired = ssl.create_default_context()
    relax_verify_expiry(expired, host="partner.example.test")
    assert not verifies_peer_fully(expired)
    no_name = ssl.create_default_context()
    no_name.check_hostname = False
    assert not verifies_peer_fully(no_name)
    no_name.verify_mode = ssl.CERT_NONE
    assert not verifies_peer_fully(no_name)


@pytest.mark.parametrize("family", list(_UNVERIFIED))
def test_a_proxy_url_shaped_map_rides_a_connect_whatever_tls_follows(family: str) -> None:
    """A connection's ``proxy_url`` maps both schemes to one proxy, so an ``http`` target reaches it
    through a ``CONNECT`` to the proxy itself, sent before any TLS. The cleartext rule governs that
    leg, not the TLS check: an unadmitted header is refused, and an admitted one rides only the
    ``CONNECT``. What urllib sends inside the tunnel is not read here: the fake proxy serves no
    TLS."""
    with _WireProxy() as proxy:
        value = f"https://{proxy.address}"
        plain = urllib.request.ProxyHandler({"http": value, "https": value})
        _refused(_UNVERIFIED[family](plain), _with_header(_HTTP_TARGET), "#3416")
    assert proxy.connections == 0

    with _WireProxy() as proxy:
        value = f"https://{proxy.address}"
        admitted = LoopbackDirectProxyHandler(
            {"http": value, "https": value}, caller_header_admitted=True
        )
        _open_and_discard(_UNVERIFIED[family](admitted), _with_header(_HTTP_TARGET))
    assert len(proxy.cleartext) == 1
    assert proxy.cleartext[0].startswith(b"CONNECT 127.0.0.1:")
    assert f"Proxy-Authorization: {_HEADER}\r\n".encode() in proxy.cleartext[0]


@pytest.mark.parametrize("name", ["Proxy-Authorization", "proxy-authorization", "Authorization"])
def test_a_message_cannot_set_an_auth_header(name: str) -> None:
    """A proxy handler's admission covers the connection's own ``proxy_user`` header, so a Handler
    must not be able to supply a ``Proxy-Authorization`` through message metadata."""
    headers = rest.outbound_headers_from_metadata(
        {rest.DYNAMIC_HEADER_PREFIX + name: _HEADER, rest.DYNAMIC_HEADER_PREFIX + "X-Trace": "t1"}
    )
    # Control in the same bag: an ordinary header still survives.
    assert headers == {"X-Trace": "t1"}
