# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A proxy URL credential never reaches a proxy in cleartext (vault BACKLOG #2572, #3410).

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
reads the wire as well as the result. The first two shapes are refused (vault BACKLOG #3410), and
so is the same leak across two DIFFERENT proxies: urllib keeps the first proxy's header when it
hands the request on, so the second proxy got it in a cleartext ``CONNECT``. The two-proxy section
below runs two recording sockets at once. If a later CPython opens TLS to a proxy, the measurement
goes red and says so.

Synthetic data only: the credentials are made up and every host name is reserved.
"""

from __future__ import annotations

import asyncio
import base64
import contextlib
import copy
import pickle
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
from tests._wire_proxy import _WireProxy

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
@pytest.mark.parametrize(
    "proxy_form", ["http://{cred}@{address}", "{cred}@{address}", "https://{cred}@{address}"]
)
def test_a_credentialed_cleartext_proxy_is_refused_before_anything_is_sent(
    target: str, proxy_form: str
) -> None:
    """With one proxy for both schemes every leg is cleartext, ``https://`` included: the first two
    measured shapes above (vault BACKLOG #3410)."""
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
        bounded_read, "_sends_cleartext_proxy_credentials", lambda req, proxy, proxies: False
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


# --- two DIFFERENT proxies (vault BACKLOG #3410): each case records at both sockets ---------------


def _two_proxy_opener(
    a: _WireProxy,
    b: _WireProxy,
    *,
    credentialed: str,
    a_form: str = "https://{cred}@{address}",
    b_form: str = "http://{address}",
) -> urllib.request.OpenerDirector:
    """An opener mapping ``credentialed`` (``http`` or ``https``) to proxy A, written ``a_form``
    with the credential, and the other scheme to proxy B, written ``b_form`` with none."""
    other = "https" if credentialed == "http" else "http"
    proxies = {
        credentialed: a_form.format(cred=_CRED, address=a.address),
        other: b_form.format(address=b.address),
    }
    return build_strict_opener(urllib.request.ProxyHandler(proxies))


@pytest.mark.parametrize("a_form", ["https://{cred}@{address}", "http://{cred}@{address}"])
@pytest.mark.parametrize(
    ("credentialed", "target", "b_form"),
    [
        # The reproduction: B got CONNECT with A's credential before the change.
        pytest.param("http", _HTTP_TARGET, "http://{address}", id="http-target-plain-b"),
        pytest.param("http", _HTTP_TARGET, "https://{address}", id="http-target-https-b"),
        # The reverse order: urllib would tunnel to A with the header before any TLS.
        pytest.param("https", _HTTPS_TARGET, "http://{address}", id="https-target"),
    ],
)
def test_two_proxies_a_credential_reaches_neither_proxy_in_cleartext(
    credentialed: str, target: str, b_form: str, a_form: str
) -> None:
    with _WireProxy() as a, _WireProxy() as b:
        opener = _two_proxy_opener(a, b, credentialed=credentialed, a_form=a_form, b_form=b_form)
        with pytest.raises(ProxyCredentialsRefusedError) as raised:
            opener.open(target, timeout=5)
    assert a.connections == 0
    assert b.connections == 0
    _assert_fixed_refusal(raised.value)


def test_control_two_proxies_without_the_header_check_the_second_proxy_gets_the_credential(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Mutation control for the reproduction: with the header reading undone, the check sees only
    each proxy's own URL, and the old leak comes back on the wire."""
    monkeypatch.setattr(bounded_read, "_proxy_url_credentials", lambda proxies: set())
    with _WireProxy() as a, _WireProxy() as b:
        _open_and_discard(_two_proxy_opener(a, b, credentialed="http"), _HTTP_TARGET)
    assert a.connections == 0
    assert len(b.cleartext) == 1
    assert b.cleartext[0].startswith(b"CONNECT 127.0.0.1:")
    assert b"Proxy-Authorization: Basic " + _BASIC + b"\r\n" in b.cleartext[0]


def test_the_header_urllib_makes_is_the_one_the_check_matches() -> None:
    """The header check matches a carried header against what urllib would make from each proxy
    URL. Pinned against urllib's own ProxyHandler, so a CPython that built the header another way
    goes red here rather than letting a carried credential through unmatched."""
    proxies = {
        "http": f"https://{_USER}:pa55%2Fw0rd@{_PROXY_HOST}",
        "https": f"http://{_PROXY_HOST}",
    }
    req = urllib.request.Request(_HTTP_TARGET)
    # It then hands the request back to its opener, and an unattached handler has none.
    with contextlib.suppress(AttributeError):
        urllib.request.ProxyHandler(proxies).proxy_open(req, proxies["http"], "http")
    made = req.get_header("Proxy-authorization")
    assert made is not None
    assert bounded_read._proxy_url_credentials(proxies) == {made}


@pytest.mark.parametrize(
    ("credentialed", "target", "request_line"),
    [
        pytest.param(
            "http", _HTTPS_TARGET, b"CONNECT partner.example.test:443 ", id="https-target-to-b"
        ),
        pytest.param(
            "https", _HTTP_TARGET, b"GET http://partner.example.test/x ", id="http-target-to-b"
        ),
    ],
)
def test_control_two_proxies_a_request_that_reaches_only_the_plain_proxy_is_sent(
    credentialed: str, target: str, request_line: bytes
) -> None:
    """Both orders, for the target the credentialed proxy does not serve. That request goes to B
    alone and carries no credential, so it is sent."""
    with _WireProxy() as a, _WireProxy() as b:
        _open_and_discard(_two_proxy_opener(a, b, credentialed=credentialed), target)
    assert a.connections == 0
    assert len(b.cleartext) == 1
    assert b.cleartext[0].startswith(request_line)
    assert b"Proxy-Authorization" not in b.cleartext[0]


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
        bounded_read, "_sends_cleartext_proxy_credentials", lambda req, proxy, proxies: False
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


def test_a_proxy_url_credential_copied_onto_a_new_request_is_refused_at_a_plain_proxy(
    recorded: None,
) -> None:
    """urllib's redirect handler copies a request's headers, the minted proxy header included, onto
    the new request. That request reaches a proxy with no credential in its own URL, and the check
    reads the header (vault BACKLOG #3410)."""
    opener = build_strict_opener(
        urllib.request.ProxyHandler(
            {"http": f"https://{_CRED}@{_PROXY_HOST}", "https": f"http://{_PROXY_HOST}"}
        )
    )
    copied = {"Proxy-authorization": "Basic " + _BASIC.decode()}
    with pytest.raises(ProxyCredentialsRefusedError) as caught:
        opener.open(urllib.request.Request(_HTTPS_TARGET, headers=copied), timeout=1)
    _assert_fixed_refusal(caught.value)


def test_control_a_proxy_header_the_caller_set_is_not_this_checks(recorded: None) -> None:
    """A header no proxy URL in the opener would make, such as the one ``proxy_user`` builds, is
    judged when the connection is built, by the posture-keyed guard. This check leaves it alone."""
    opener = build_strict_opener(urllib.request.ProxyHandler({"https": f"http://{_PROXY_HOST}"}))
    own = "Basic " + base64.b64encode(b"other:value").decode()
    request = urllib.request.Request(_HTTPS_TARGET, headers={"Proxy-Authorization": own})
    with pytest.raises(_Dialled) as dialled:
        opener.open(request, timeout=1)
    assert dialled.value.host == _PROXY_HOST
    assert dialled.value.proxy_header == own


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
