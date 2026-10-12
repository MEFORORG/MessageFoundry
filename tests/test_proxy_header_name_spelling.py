# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The send-time proxy-credential rule reads a header's name with its edge whitespace removed.

The rule is stated once, on ``bounded_read.ProxyCredentialsRefusedError``, and pinned for the
plain name in ``tests/test_proxy_credential_legs.py``. This file pins the spellings of that name.

**What was wrong.** The opener matched ``name.lower() == "proxy-authorization"`` with no trim. A
caller-set header named ``Proxy-Authorization`` plus trailing whitespace was therefore not read as
a proxy credential, on any leg. Measured on Python 3.14 before the fix, with a handler that admits
no caller-set header:

* an ``http`` target through a cleartext proxy: the header reached the proxy in the clear, name
  and value;
* an ``https`` target through a proxy: the proxy got a ``CONNECT`` without the header, because
  urllib moves only the exact name into a ``CONNECT``, and the request went on into the tunnel
  with the header still on it;
* a request that goes direct: the header reached the destination.

**Which spellings can be sent.** ``http.client`` refuses a name that starts with whitespace, and
one that holds a carriage return or a line feed. It sends a name that ends in a space, a tab or
one of the other ASCII characters ``str.strip`` removes. ``_SENDABLE`` and ``_UNSENDABLE`` below
are that measurement, and ``test_measured_*`` pin it on the wire.

Each refusal is read at a loopback socket that records what reaches it, as well as in the result.

Synthetic data only: the credential is made up and every off-box host name is reserved.
"""

from __future__ import annotations

import asyncio
import base64
import contextlib
import urllib.error
import urllib.request

import pytest

from messagefoundry.config.models import ConnectorType, Destination
from messagefoundry.config.tls_policy import HopPosture, active_hop_posture
from messagefoundry.config.wiring import Rest
from messagefoundry.transports import build_destination, rest
from messagefoundry.transports.base import DeliveryError
from messagefoundry.transports.bounded_read import (
    LoopbackDirectProxyHandler,
    ProxyCredentialsRefusedError,
    build_strict_opener,
    is_proxy_credential_header_name,
)
from messagefoundry.transports.rest import RestDestination
from tests._egress_policy import permitting
from tests._wire_proxy import _WireProxy

_VALUE = "Basic " + base64.b64encode(b"u5er:pa55w0rd").decode()
_NAME = "Proxy-Authorization"

_HTTP_TARGET = "http://partner.example.test/x"
_HTTPS_TARGET = "https://partner.example.test/x"

#: Spellings ``http.client`` puts on the wire. Each trailing character is one ``str.strip`` removes.
_SENDABLE = {
    "space": _NAME + " ",
    "tab": _NAME + "\t",
    "space-tab": _NAME + " \t",
    "mixed-case-space": "pRoXy-aUtHoRiZaTiOn ",
    "vertical-tab": _NAME + "\x0b",
    "form-feed": _NAME + "\x0c",
    "file-separator": _NAME + "\x1c",
    "group-separator": _NAME + "\x1d",
    "record-separator": _NAME + "\x1e",
    "unit-separator": _NAME + "\x1f",
}

#: Spellings ``http.client`` refuses before it opens a connection, each with what it raises.
_UNSENDABLE: dict[str, tuple[str, type[Exception]]] = {
    "leading-space": (" " + _NAME, ValueError),
    "leading-tab": ("\t" + _NAME, ValueError),
    "both-ends": (" " + _NAME + " ", ValueError),
    "carriage-return": (_NAME + "\r", ValueError),
    "line-feed": (_NAME + "\n", ValueError),
    "no-break-space": (_NAME + "\xa0", UnicodeEncodeError),
}

_PROXY_ENV = ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY", "REQUEST_METHOD")


@pytest.fixture(autouse=True)
def no_ambient_proxy(monkeypatch: pytest.MonkeyPatch) -> None:
    """Only the proxy a test names can route a request, and no bypass list applies."""
    for name in _PROXY_ENV:
        monkeypatch.delenv(name, raising=False)
        monkeypatch.delenv(name.lower(), raising=False)
    for source in ("registry", "macosx_sysconf"):
        monkeypatch.setattr(urllib.request, f"getproxies_{source}", dict, raising=False)
        monkeypatch.setattr(
            urllib.request, f"proxy_bypass_{source}", lambda host: False, raising=False
        )


def _request(name: str, url: str) -> urllib.request.Request:
    return urllib.request.Request(url, headers={name: _VALUE})


def _opener(proxy: _WireProxy, *, admitted: bool = False) -> urllib.request.OpenerDirector:
    """An engine opener that sends both schemes to ``proxy``, written ``http://``."""
    value = f"http://{proxy.address}"
    return build_strict_opener(
        LoopbackDirectProxyHandler({"http": value, "https": value}, caller_header_admitted=admitted)
    )


def _refused(
    opener: urllib.request.OpenerDirector, request: urllib.request.Request, item: str
) -> None:
    with pytest.raises(ProxyCredentialsRefusedError) as raised:
        opener.open(request, timeout=5)
    text = f"{raised.value!s} {raised.value!r}"
    assert item in text
    for part in ("u5er", "pa55w0rd", _VALUE, "127.0.0.1", "partner.example"):
        assert part not in text, part


def _open_and_discard(
    opener: urllib.request.OpenerDirector, request: urllib.request.Request
) -> None:
    """Send one request. The fake proxy serves no TLS, so a tunnelled one ends in a transport
    error; what the test reads is what reached the socket."""
    with contextlib.suppress(urllib.error.URLError), opener.open(request, timeout=5) as resp:
        resp.read()


# --- the measurement: which spellings reach a socket at all --------------------------------------


@pytest.mark.parametrize("name", list(_SENDABLE.values()), ids=list(_SENDABLE))
def test_measured_http_client_sends_a_name_with_trailing_whitespace(name: str) -> None:
    """The control for every refusal below: a handler that admits a caller-set header lets the
    spelling through, and it reaches the proxy with its whitespace intact. So the spelling is
    sendable, and a refusal below is the rule's, not ``http.client``'s."""
    with _WireProxy() as proxy:
        _open_and_discard(_opener(proxy, admitted=True), _request(name, _HTTP_TARGET))
    assert len(proxy.cleartext) == 1
    assert f"{name.title()}: {_VALUE}\r\n".encode() in proxy.cleartext[0]


@pytest.mark.parametrize("admitted", [False, True])
@pytest.mark.parametrize("spelling", list(_UNSENDABLE))
def test_measured_an_unsendable_spelling_never_reaches_a_socket(
    spelling: str, admitted: bool
) -> None:
    """A name that starts with whitespace, or holds a carriage return or a line feed, is refused
    by ``http.client`` before it connects. So is a name that will not encode as ASCII. Where the
    handler admits no caller-set header, the rule refuses first whenever ``str.strip`` leaves the
    plain name. Either way the proxy is not dialled."""
    name, raised_by_http_client = _UNSENDABLE[spelling]
    with (
        _WireProxy() as proxy,
        pytest.raises((raised_by_http_client, ProxyCredentialsRefusedError)) as raised,
    ):
        _opener(proxy, admitted=admitted).open(_request(name, _HTTP_TARGET), timeout=5)
    assert proxy.connections == 0
    if admitted:
        # No rule stood in the way, so this is the standard library's own refusal.
        assert type(raised.value) is raised_by_http_client


# --- the rule, per leg -----------------------------------------------------------------------------


@pytest.mark.parametrize("target", [_HTTP_TARGET, _HTTPS_TARGET])
@pytest.mark.parametrize(
    "name", [_NAME, _NAME.lower(), *_SENDABLE.values()], ids=["plain", "lower", *_SENDABLE]
)
def test_a_caller_set_proxy_header_is_refused_before_a_cleartext_leg_in_any_spelling(
    name: str, target: str
) -> None:
    """Before the fix, only ``plain`` and ``lower`` were refused. Every other spelling here dialled
    the proxy: the ``http`` target sent it the header in a cleartext request, and the ``https``
    target sent a ``CONNECT`` and kept the header on the request bound for the tunnel."""
    with _WireProxy() as proxy:
        _refused(_opener(proxy), _request(name, target), "#3416")
    assert proxy.connections == 0


@pytest.mark.parametrize("name", [_NAME, *_SENDABLE.values()], ids=["plain", *_SENDABLE])
def test_a_proxy_header_on_a_direct_request_is_refused_in_any_spelling(name: str) -> None:
    """The destination is a recording socket on the box, which is never proxied. Before the fix,
    every spelling but ``plain`` reached it with the header."""
    with _WireProxy() as destination:
        opener = build_strict_opener(urllib.request.ProxyHandler({}))
        _refused(opener, _request(name, f"http://{destination.address}/x"), "#3417")
    assert destination.connections == 0


def test_control_a_direct_request_with_another_header_is_sent() -> None:
    """The rule reads one name. A header that only resembles it still crosses."""
    with _WireProxy() as destination:
        opener = build_strict_opener(urllib.request.ProxyHandler({}))
        request = _request("X-Proxy-Authorization", f"http://{destination.address}/x")
        with opener.open(request, timeout=5) as resp:
            assert resp.read() == b"ok"
    assert len(destination.cleartext) == 1
    assert f"X-Proxy-Authorization: {_VALUE}\r\n".encode() in destination.cleartext[0]


# --- the report's shape: a connection with no proxy_user -----------------------------------------


def _rest_with_static_header(name: str, proxy: _WireProxy) -> RestDestination:
    """A REST connection with no ``proxy_user``, so its proxy handler admits no caller-set header.
    It sets one static header and names a cleartext proxy. ``cleartext_accepted`` covers the
    ``http://`` destination hop only."""
    settings = Rest(url=_HTTP_TARGET).settings
    settings.update({"proxy_url": f"http://{proxy.address}", "headers": {name: _VALUE}})
    with active_hop_posture(HopPosture(enforcing=True)):
        dest = build_destination(
            Destination(
                name="OB_REST",
                type=ConnectorType.REST,
                settings=settings,
                cleartext_accepted=True,
                cleartext_reason="legacy partner listener has no TLS",
                tls_revocation_attested=True,
                tls_revocation_attested_reason="revocation-checking PKI at the partner edge",
            ),
            egress=permitting(settings),
        )
    assert isinstance(dest, RestDestination)
    return dest


@pytest.mark.parametrize("name", [_NAME, _NAME + " ", _NAME + "\t"], ids=["plain", "space", "tab"])
def test_a_rest_send_with_a_static_proxy_header_is_refused_in_any_spelling(name: str) -> None:
    """Before the fix, ``space`` and ``tab`` reached the proxy in a cleartext request, value and
    all. ``plain`` is the control that was already refused."""
    with _WireProxy() as proxy:
        dest = _rest_with_static_header(name, proxy)
        with pytest.raises(DeliveryError) as raised:
            asyncio.run(dest.send('{"a": 1}'))
    assert isinstance(raised.value.__cause__, ProxyCredentialsRefusedError)
    assert "#3416" in str(raised.value)
    for part in ("u5er", "pa55w0rd", _VALUE):
        assert part not in str(raised.value), part
    assert proxy.connections == 0


def test_control_a_rest_send_with_another_static_header_reaches_the_proxy() -> None:
    """The same connection with a header the rule does not read. The fake proxy may hang up
    before the body is sent, so the result is not read: what reached the socket is."""
    with _WireProxy() as proxy:
        dest = _rest_with_static_header("X-Trace", proxy)
        with contextlib.suppress(DeliveryError):
            asyncio.run(dest.send('{"a": 1}'))
    assert len(proxy.cleartext) == 1
    assert f"X-Trace: {_VALUE}\r\n".encode() in proxy.cleartext[0]


# --- the one reading of the name -----------------------------------------------------------------


@pytest.mark.parametrize(
    "name",
    [
        _NAME,
        _NAME.lower(),
        _NAME.upper(),
        *_SENDABLE.values(),
        *(n for n, _ in _UNSENDABLE.values()),
    ],
)
def test_the_name_is_read_in_any_case_with_its_edge_whitespace_removed(name: str) -> None:
    assert is_proxy_credential_header_name(name)


@pytest.mark.parametrize(
    "name",
    ["Authorization", "X-Proxy-Authorization", "Proxy-Authorization-2", "Proxy -Authorization", ""],
)
def test_control_another_name_is_not_the_proxy_credential_header(name: str) -> None:
    assert not is_proxy_credential_header_name(name)


@pytest.mark.parametrize("name", [_NAME, _NAME.lower(), "pRoXy-aUtHoRiZaTiOn"])
def test_a_message_cannot_set_the_proxy_header_through_the_shared_reading(name: str) -> None:
    """Message metadata asks the same question through the same function. A name with whitespace
    never gets that far: it is not a header-name token, so it is dropped first."""
    prefix = rest.DYNAMIC_HEADER_PREFIX
    bag = {prefix + name: _VALUE, prefix + name + " ": _VALUE, prefix + "X-Trace": "t1"}
    # Control in the same bag: an ordinary header still survives.
    assert rest.outbound_headers_from_metadata(bag) == {"X-Trace": "t1"}
