# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A proxy URL that carries credentials is refused unless written ``https://`` (vault BACKLOG #2572).

urllib turns a user and a password in a proxy URL into a ``Proxy-Authorization: Basic`` header. To a
proxy reached over plain TCP that header crosses the network in cleartext. The Vault hop has refused
that since BACKLOG #2547. The urllib egress did not: REST, SOAP, FHIR, DICOMweb, the token
endpoints, the alert webhook, the OIDC legs and the AI broker all read a proxy from the environment,
from the system settings or from ``proxy_url``. ``LoopbackDirectProxyHandler`` now refuses per
request, on every opener ``build_strict_opener`` makes.

**The first section is a measurement, not a rule.** It runs a PLAIN urllib opener, with no engine
code in the path, against a loopback socket that records what arrives before any TLS. The target
is a reserved name, so only that socket is ever dialled. It pins what CPython does with a credentialed
proxy written ``https://``, because the controls below depend on it:

* For an ``https`` target, urllib opens plain TCP to the proxy and sends ``CONNECT`` with the
  credential header in cleartext. ``http.client`` has no TLS leg to a proxy.
* For an ``http`` target on an opener that also maps ``https`` to a proxy, the same happens. urllib
  re-enters the opener with the request re-addressed to the proxy, and the ``https`` entry then
  tunnels to the proxy itself.
* Only an ``http`` target on an opener with no ``https`` proxy starts TLS first.

So the one accepted control for a credentialed ``https://`` proxy is that last shape, and its test
reads the wire as well as the result. **No test here asserts that a credentialed** ``https://``
**proxy is accepted for an** ``https`` **target.** That shape is not refused by this change, and it
is not safe. If a later CPython opens TLS to a proxy, the measurement goes red and says so.

Synthetic data only: the credentials are made up and every host name is reserved.
"""

from __future__ import annotations

import asyncio
import base64
import contextlib
import copy
import pickle
import socket
import threading
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Iterator

import pytest

from messagefoundry.auth.oidc_http import build_idp_opener
from messagefoundry.config.models import ConnectorType, Destination
from messagefoundry.config.wiring import Rest
from messagefoundry.pipeline import alert_sinks
from messagefoundry.transports import bounded_read, build_destination, rest
from messagefoundry.transports.base import DeliveryError, NegativeAckError
from messagefoundry.transports.bounded_read import (
    ProxyCredentialsRefusedError,
    build_strict_opener,
)
from messagefoundry.transports.rest import RestDestination
from tests._egress_policy import permitting

_USER = "u5er"
_PASSWORD = "pa55w0rd"  # nosec B105 - a made-up test value, not a credential
_CRED = f"{_USER}:{_PASSWORD}"
#: What urllib puts on the wire for that pair.
_BASIC = base64.b64encode(_CRED.encode())

#: A proxy nothing could reach, for the tests that record a dial and open no socket.
_PROXY_HOST = "proxy-marker.invalid:9"

_HTTP_TARGET = "http://partner.example.test/x"
_HTTPS_TARGET = "https://partner.example.test/x"

#: Every variable urllib reads a proxy or a bypass list from.
_PROXY_ENV = ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY", "REQUEST_METHOD")


@pytest.fixture(autouse=True)
def no_ambient_proxy(monkeypatch: pytest.MonkeyPatch) -> None:
    """Only the proxy a test names can route a request, and no bypass list can send one direct."""
    for name in _PROXY_ENV:
        monkeypatch.delenv(name, raising=False)
        monkeypatch.delenv(name.lower(), raising=False)
    for source in ("registry", "macosx_sysconf"):
        monkeypatch.setattr(urllib.request, f"getproxies_{source}", dict, raising=False)
        monkeypatch.setattr(
            urllib.request, f"proxy_bypass_{source}", lambda host: False, raising=False
        )


def _assert_fixed_refusal(exc: BaseException) -> None:
    """The refusal's text is fixed: no user, no password, no encoded pair, no proxy host."""
    text = f"{exc!s} {exc!r} {getattr(exc, 'reason', '')}"
    assert "vault BACKLOG #2572" in text
    for part in (_USER, _PASSWORD, _BASIC.decode(), "proxy-marker", "127.0.0.1"):
        assert part not in text, part
    # No parser error that quotes the URL rides along on the chain.
    assert exc.__cause__ is None
    assert exc.__context__ is None


# --- the measurement: what urllib sends before any TLS -------------------------------------------


class _WireProxy:
    """A loopback socket that records, per connection, what arrived before any TLS.

    ``cleartext`` holds each request head that arrived in the clear. ``tls_first`` counts the
    connections whose first byte was a TLS handshake record, so nothing preceded it. A ``CONNECT``
    is answered 200, and ``tls_after_connect`` counts the tunnels the client then started TLS in.
    """

    def __init__(self) -> None:
        self.cleartext: list[bytes] = []
        self.tls_first = 0
        self.tls_after_connect = 0
        self._listener = socket.socket()
        self._listener.bind(("127.0.0.1", 0))
        self._listener.listen(4)
        # So a test that stalls fails in seconds rather than hanging the serving thread.
        self._listener.settimeout(5)
        self.address = f"127.0.0.1:{self._listener.getsockname()[1]}"
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    @property
    def connections(self) -> int:
        return len(self.cleartext) + self.tls_first

    def _serve(self) -> None:
        while True:
            try:
                conn, _ = self._listener.accept()
            except TimeoutError:
                continue  # idle, not closed: a slow test must still find the proxy serving
            except OSError:
                return
            conn.settimeout(5)
            # Suppressed: the client hung up. What was recorded stands.
            with conn, contextlib.suppress(OSError):
                self._record(conn)

    def _record(self, conn: socket.socket) -> None:
        head = conn.recv(8192)
        if head[:1] == b"\x16":
            self.tls_first += 1
            return
        while head and b"\r\n\r\n" not in head:
            more = conn.recv(8192)
            if not more:
                break
            head += more
        self.cleartext.append(head)
        if head.startswith(b"CONNECT "):
            conn.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
            if conn.recv(16)[:1] == b"\x16":
                self.tls_after_connect += 1
        else:
            conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")

    def __enter__(self) -> _WireProxy:
        return self

    def __exit__(self, *exc: object) -> None:
        # shutdown wakes a blocked accept() on Linux, where close() alone does not.
        with contextlib.suppress(OSError):
            self._listener.shutdown(socket.SHUT_RDWR)
        self._listener.close()
        self._thread.join(timeout=10)


def _open_and_discard(opener: urllib.request.OpenerDirector, url: str) -> None:
    """Send one request. The fake proxy serves no TLS, so most of these end in a transport error;
    what the test reads is what reached the proxy."""
    with contextlib.suppress(urllib.error.URLError), opener.open(url, timeout=5) as resp:
        resp.read()


@pytest.mark.parametrize(
    ("target", "schemes", "proxy_form", "request_line"),
    [
        pytest.param(
            _HTTPS_TARGET,
            ("http", "https"),
            "https://{cred}@{address}",
            b"CONNECT partner.example.test:443 ",
            id="https-target",
        ),
        pytest.param(
            _HTTP_TARGET,
            ("http", "https"),
            "https://{cred}@{address}",
            b"CONNECT 127.0.0.1:",
            id="http-target-when-https-is-proxied-too",
        ),
        pytest.param(
            _HTTPS_TARGET,
            ("https",),
            "{cred}@{address}",
            b"CONNECT partner.example.test:443 ",
            id="https-target-and-a-proxy-value-with-no-scheme",
        ),
    ],
)
def test_measured_urllib_sends_these_proxy_credentials_in_cleartext(
    target: str, schemes: tuple[str, ...], proxy_form: str, request_line: bytes
) -> None:
    """Plain urllib, no engine code. The proxy is written ``https://`` or has no scheme, the
    credential header still reaches it before any TLS, and TLS starts only inside the tunnel."""
    with _WireProxy() as proxy:
        value = proxy_form.format(cred=_CRED, address=proxy.address)
        plain = urllib.request.build_opener(
            urllib.request.ProxyHandler(dict.fromkeys(schemes, value))
        )
        _open_and_discard(plain, target)
    assert proxy.tls_first == 0
    assert len(proxy.cleartext) == 1
    head = proxy.cleartext[0]
    assert head.startswith(request_line)
    assert b"Proxy-Authorization: Basic " + _BASIC + b"\r\n" in head
    assert proxy.tls_after_connect == 1


def test_measured_urllib_opens_tls_first_for_an_http_target_with_no_https_proxy() -> None:
    """The one shape in which a proxy written ``https://`` gets a TLS session before anything
    else. Measured on plain urllib and on the engine's opener, where it is also not refused."""
    for build in (urllib.request.build_opener, build_strict_opener):
        with _WireProxy() as proxy:
            value = f"https://{_CRED}@{proxy.address}"
            _open_and_discard(build(urllib.request.ProxyHandler({"http": value})), _HTTP_TARGET)
        assert proxy.cleartext == []
        assert proxy.tls_first == 1


# --- the refusal, on the wire --------------------------------------------------------------------


@pytest.mark.parametrize("target", [_HTTP_TARGET, _HTTPS_TARGET])
@pytest.mark.parametrize("proxy_form", ["http://{cred}@{address}", "{cred}@{address}"])
def test_a_credentialed_cleartext_proxy_is_refused_before_anything_is_sent(
    target: str, proxy_form: str
) -> None:
    with _WireProxy() as proxy:
        value = proxy_form.format(cred=_CRED, address=proxy.address)
        opener = build_strict_opener(urllib.request.ProxyHandler({"http": value, "https": value}))
        with pytest.raises(ProxyCredentialsRefusedError) as raised:
            opener.open(target, timeout=5)
    assert proxy.connections == 0, "the proxy must not be dialled at all"
    _assert_fixed_refusal(raised.value)


@pytest.mark.parametrize("target", [_HTTP_TARGET, _HTTPS_TARGET])
def test_control_without_the_check_the_credentials_cross_in_cleartext(
    target: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Mutation control: the same opener and proxy, with the reading behind the refusal undone."""
    monkeypatch.setattr(
        bounded_read, "_sends_cleartext_proxy_credentials", lambda req, proxy: False
    )
    with _WireProxy() as proxy:
        value = f"http://{_CRED}@{proxy.address}"
        opener = build_strict_opener(urllib.request.ProxyHandler({"http": value, "https": value}))
        _open_and_discard(opener, target)
    assert len(proxy.cleartext) == 1
    assert b"Proxy-Authorization: Basic " + _BASIC + b"\r\n" in proxy.cleartext[0]


def test_control_a_cleartext_proxy_with_no_credentials_is_still_used() -> None:
    with _WireProxy() as proxy:
        opener = build_strict_opener(
            urllib.request.ProxyHandler({"http": f"http://{proxy.address}"})
        )
        with opener.open(_HTTP_TARGET, timeout=5) as resp:
            assert resp.read() == b"ok"
    assert len(proxy.cleartext) == 1
    assert proxy.cleartext[0].startswith(b"GET http://partner.example.test/x ")
    assert b"Proxy-Authorization" not in proxy.cleartext[0]


# --- the refusal, by source and by shape (no socket is opened below) -----------------------------


class _Dialled(Exception):
    """Raised in place of the connection urllib was about to open."""

    def __init__(self, host: str, proxy_header: str | None) -> None:
        super().__init__(host)
        self.host = host
        self.proxy_header = proxy_header


@pytest.fixture
def recorded(monkeypatch: pytest.MonkeyPatch) -> None:
    """Replace the one method through which urllib dials with a recorder."""

    def do_open(
        self: object, http_class: object, req: urllib.request.Request, **kw: object
    ) -> None:
        raise _Dialled(req.host, req.get_header("Proxy-authorization"))

    monkeypatch.setattr(urllib.request.AbstractHTTPHandler, "do_open", do_open)


def _dial(opener: urllib.request.OpenerDirector, url: str) -> _Dialled:
    with pytest.raises(_Dialled) as caught:
        opener.open(urllib.request.Request(url, data=b"synthetic", method="POST"), timeout=1)
    return caught.value


def _refused(opener: urllib.request.OpenerDirector, url: str) -> ProxyCredentialsRefusedError:
    with pytest.raises(ProxyCredentialsRefusedError) as caught:
        opener.open(urllib.request.Request(url, data=b"synthetic", method="POST"), timeout=1)
    _assert_fixed_refusal(caught.value)
    return caught.value


_CREDENTIALED = f"http://{_CRED}@{_PROXY_HOST}"

#: One builder per opener family, each called after the environment is set, as in
#: tests/test_loopback_hop_never_proxied.py. The shared module-level openers are built by these
#: same functions at import.
_FAMILIES: dict[str, Callable[[], urllib.request.OpenerDirector]] = {
    "bare": build_strict_opener,
    "http-family-shared": rest._no_redirect_opener,
    "http-family-verify-off": rest._insecure_opener,
    "http-family-expiry-relaxed": lambda: rest._expiry_relaxed_opener("partner.example.test"),
    "alert-webhook": alert_sinks._build_no_redirect_opener,
    "oidc": lambda: build_idp_opener(None),
}


@pytest.mark.parametrize("family", list(_FAMILIES))
@pytest.mark.parametrize("target", [_HTTP_TARGET, _HTTPS_TARGET])
def test_an_environment_proxy_with_credentials_is_refused_on_every_opener_family(
    recorded: None, monkeypatch: pytest.MonkeyPatch, family: str, target: str
) -> None:
    """Building the opener must not raise: the shared ones are built at import. The request does."""
    monkeypatch.setenv("HTTP_PROXY", _CREDENTIALED)
    monkeypatch.setenv("HTTPS_PROXY", _CREDENTIALED)
    opener = _FAMILIES[family]()
    _refused(opener, target)


@pytest.mark.parametrize("family", list(_FAMILIES))
def test_control_an_environment_proxy_with_no_credentials_is_used_on_every_opener_family(
    recorded: None, monkeypatch: pytest.MonkeyPatch, family: str
) -> None:
    monkeypatch.setenv("HTTP_PROXY", f"http://{_PROXY_HOST}")
    monkeypatch.setenv("HTTPS_PROXY", f"http://{_PROXY_HOST}")
    dialled = _dial(_FAMILIES[family](), _HTTPS_TARGET)
    assert dialled.host == _PROXY_HOST
    assert dialled.proxy_header is None


def test_a_system_proxy_with_credentials_is_refused(
    recorded: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Whatever ``getproxies`` reads from: on Windows that is the Internet Settings proxy. Whether
    Windows itself accepts credentials in that value is not measured here."""
    monkeypatch.setattr(
        urllib.request, "getproxies", lambda: {"http": _CREDENTIALED, "https": _CREDENTIALED}
    )
    monkeypatch.setattr(urllib.request, "proxy_bypass", lambda host: False)
    _refused(build_strict_opener(), _HTTPS_TARGET)


@pytest.mark.parametrize(
    "value",
    [
        pytest.param(f"http://{_CRED}@{_PROXY_HOST}", id="http"),
        pytest.param(f"HTTP://{_CRED}@{_PROXY_HOST}", id="scheme-in-capitals"),
        pytest.param(f"{_CRED}@{_PROXY_HOST}", id="no-scheme"),
        pytest.param(f"http://{_USER}:pa55%2Fw0rd@{_PROXY_HOST}", id="percent-encoded-password"),
        pytest.param(f"http://{_USER}:pa55/w0rd@{_PROXY_HOST}", id="slash-in-the-password"),
        pytest.param(f"socks5://{_CRED}@{_PROXY_HOST}", id="another-scheme"),
        # urllib takes the LAST "@" as the end of the userinfo, so this dials the marker host and
        # sends it a header. A reader that split at the first "/" would see 127.0.0.1 and none.
        pytest.param(f"http://127.0.0.1:3128/x@{_PROXY_HOST}", id="at-sign-after-a-path"),
        # urllib cannot parse these two, and its own error quotes the value.
        pytest.param(f"http:/{_CRED}@{_PROXY_HOST}", id="unreadable-one-slash"),
        pytest.param(f"https:/{_CRED}@{_PROXY_HOST}", id="unreadable-written-https"),
    ],
)
@pytest.mark.parametrize("target", [_HTTP_TARGET, _HTTPS_TARGET])
def test_each_refused_shape_of_proxy_value(recorded: None, value: str, target: str) -> None:
    opener = build_strict_opener(urllib.request.ProxyHandler({"http": value, "https": value}))
    _refused(opener, target)


@pytest.mark.parametrize(
    "value",
    [
        pytest.param(f"http://{_PROXY_HOST}", id="no-userinfo"),
        # urllib sends a credential only when the URL holds both parts.
        pytest.param(f"http://{_USER}@{_PROXY_HOST}", id="a-user-and-no-password"),
        pytest.param(f"http://{_USER}:@{_PROXY_HOST}", id="an-empty-password"),
    ],
)
def test_control_a_proxy_value_that_sends_no_credential_is_used(recorded: None, value: str) -> None:
    opener = build_strict_opener(urllib.request.ProxyHandler({"http": value, "https": value}))
    for target in (_HTTP_TARGET, _HTTPS_TARGET):
        dialled = _dial(opener, target)
        assert dialled.host == _PROXY_HOST
        assert dialled.proxy_header is None


def test_control_without_the_check_an_at_sign_after_a_path_moves_the_proxy_host(
    recorded: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Mutation control for the ``at-sign-after-a-path`` shape above: with the reading undone,
    urllib dials the host after the ``@`` and sends it a credential header. The check reads the
    value with urllib's own parser, so it judges the proxy urllib would dial."""
    monkeypatch.setattr(
        bounded_read, "_sends_cleartext_proxy_credentials", lambda req, proxy: False
    )
    value = f"http://127.0.0.1:3128/x@{_PROXY_HOST}"
    dialled = _dial(build_strict_opener(urllib.request.ProxyHandler({"http": value})), _HTTP_TARGET)
    assert dialled.host == _PROXY_HOST
    assert dialled.proxy_header is not None


def test_control_an_unreadable_proxy_value_with_no_credentials_is_left_to_urllib(
    recorded: None,
) -> None:
    """Nothing to protect, so urllib refuses the value in its own words, as it did before."""
    opener = build_strict_opener(urllib.request.ProxyHandler({"http": f"http:/{_PROXY_HOST}"}))
    with pytest.raises(ValueError, match="no authority"):
        opener.open(_HTTP_TARGET, timeout=1)


def test_a_loopback_target_is_dialled_direct_and_not_refused(recorded: None) -> None:
    """The loopback rule (vault BACKLOG #2579) comes first. That request sends the proxy nothing."""
    opener = build_strict_opener(
        urllib.request.ProxyHandler({"http": _CREDENTIALED, "https": _CREDENTIALED})
    )
    for url in ("http://127.0.0.1:18080/x", "https://localhost:8443/x", "http://[::1]:18080/x"):
        dialled = _dial(opener, url)
        assert dialled.host == urllib.parse.urlsplit(url).netloc
        assert dialled.proxy_header is None


def test_a_host_on_the_bypass_list_is_dialled_direct_and_not_refused(
    recorded: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    """urllib's own bypass list sends that request direct, with no proxy header. The control is
    the same opener and a host the list does not name."""
    monkeypatch.setenv("HTTP_PROXY", _CREDENTIALED)
    monkeypatch.setenv("NO_PROXY", "partner.example.test")
    opener = build_strict_opener()
    dialled = _dial(opener, _HTTP_TARGET)
    assert dialled.host == "partner.example.test"
    assert dialled.proxy_header is None
    _refused(opener, "http://other.example.test/x")


def test_the_refusal_is_a_urlerror_that_copies_and_pickles(recorded: None) -> None:
    """The class every urllib hop already maps to its own error. It crosses a process boundary
    whole, as an exception from a worker process must."""
    refusal = _refused(
        build_strict_opener(urllib.request.ProxyHandler({"http": _CREDENTIALED})), _HTTP_TARGET
    )
    assert isinstance(refusal, urllib.error.URLError)
    assert isinstance(refusal, OSError)
    assert not isinstance(refusal, urllib.error.HTTPError)
    for twin in (copy.copy(refusal), pickle.loads(pickle.dumps(refusal))):  # noqa: S301
        assert type(twin) is ProxyCredentialsRefusedError
        assert twin.reason == refusal.reason


# --- a REST connection: an explicit proxy_url, and proxy_url = "default" -------------------------


def _rest(**extra: object) -> RestDestination:
    settings = Rest(url="https://partner.example.test/ingest").settings
    settings.update(extra)
    dest = build_destination(
        Destination(name="OB_REST", type=ConnectorType.REST, settings=settings),
        egress=permitting(settings),
    )
    assert isinstance(dest, RestDestination)
    return dest


@pytest.fixture
def default_proxy(monkeypatch: pytest.MonkeyPatch) -> Iterator[Callable[[str], None]]:
    """Set the environment proxy that ``proxy_url = "default"`` reads."""

    def set_proxy(value: str) -> None:
        monkeypatch.setenv("HTTP_PROXY", value)
        monkeypatch.setenv("HTTPS_PROXY", value)

    yield set_proxy


def _assert_send_is_refused(dest: RestDestination) -> None:
    """A retryable ``DeliveryError``, the class this hop reports for a request it could not send.
    Not a permanent one: the message waits while an operator corrects the proxy setting."""
    with pytest.raises(DeliveryError) as raised:
        asyncio.run(dest.send('{"a": 1}'))
    assert not isinstance(raised.value, NegativeAckError)
    assert isinstance(raised.value.__cause__, ProxyCredentialsRefusedError)
    text = str(raised.value)
    assert "vault BACKLOG #2572" in text
    for part in (_USER, _PASSWORD, _BASIC.decode(), "proxy-marker"):
        assert part not in text, part


def test_a_rest_send_through_an_explicit_credentialed_proxy_url_is_refused(recorded: None) -> None:
    """No ``proxy_user`` is set, so the posture-keyed ``proxy_user`` guard never ran. The
    connection builds, and each send is refused."""
    _assert_send_is_refused(_rest(proxy_url=_CREDENTIALED))


def test_a_rest_send_through_a_default_proxy_with_credentials_is_refused(
    recorded: None, default_proxy: Callable[[str], None]
) -> None:
    default_proxy(_CREDENTIALED)
    _assert_send_is_refused(_rest(proxy_url="default"))


def test_control_a_rest_send_through_a_credential_free_proxy_reaches_it(
    recorded: None, default_proxy: Callable[[str], None]
) -> None:
    """Both sources, with the credentials taken out of the same proxy value."""
    default_proxy(f"http://{_PROXY_HOST}")
    for dest in (_rest(proxy_url=f"http://{_PROXY_HOST}"), _rest(proxy_url="default")):
        with pytest.raises(_Dialled) as dialled:
            asyncio.run(dest.send('{"a": 1}'))
        assert dialled.value.host == _PROXY_HOST
        assert dialled.value.proxy_header is None
