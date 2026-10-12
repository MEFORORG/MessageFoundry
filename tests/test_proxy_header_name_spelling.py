# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The send-time proxy-credential rule reads a header's name however it is spelled.

The rule is stated once, on ``bounded_read.ProxyCredentialsRefusedError``, and pinned for the
plain name in ``tests/test_proxy_credential_legs.py``. This file pins the spellings of that name.

**What was wrong.** The opener matched ``name.lower() == "proxy-authorization"`` with no trim. A
caller-set header named ``Proxy-Authorization`` plus trailing whitespace was therefore not read as
a proxy credential, on any leg. Measured on Python 3.14 before the fix, with a handler that admits
no caller-set header:

* an ``http`` target through a cleartext proxy: the header reached the proxy in the clear, name
  and value;
* an ``https`` target through a proxy: the proxy got a ``CONNECT`` without the header, because
  urllib moves only the plain name into a ``CONNECT``, and the request went on into the tunnel
  with the header still on it;
* a request that goes direct: the header reached the destination.

**Which spellings can be sent.** ``http.client`` refuses a name that starts with a space, a tab,
a vertical tab or a form feed, and one that holds a colon, a carriage return or a line feed
anywhere. It sends at least the others listed in ``_SENDABLE``: a name that ends in whitespace,
in another control character or in a punctuation mark, and one that starts with a control
character its pattern does not count as whitespace. ``_SENDABLE`` and ``_UNSENDABLE`` are that
measurement, and ``test_measured_*`` pin it on the wire with urllib's own opener.

**A spelling that can never be sent is a fault in the configuration, not a leak.** Before the
fix ``http.client`` refused it with a ``ValueError``, after every credential refusal had run.
The opener keeps that class and that order, with fixed text, so the REST send maps it to a
permanent refusal and does not retry it. A sendable spelling is refused by the rule, and that
refusal is retried like the plain name's.

Each refusal is read at a loopback socket that records what reaches it, as well as in the result.

Synthetic data only: the credentials are made up and every off-box host name is reserved.
"""

from __future__ import annotations

import asyncio
import base64
import contextlib
import json
import ssl
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

import pytest

from messagefoundry.config.models import ConnectorType, Destination
from messagefoundry.config.tls_policy import HopPosture, active_hop_posture
from messagefoundry.config.wiring import Rest
from messagefoundry.transports import build_destination, rest
from messagefoundry.transports.base import DeliveryError, NegativeAckError
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
#: A second made-up pair, written into a proxy URL, and the header urllib makes from it.
_URL_CRED = "0ther:s3cret"
_URL_VALUE = "Basic " + base64.b64encode(_URL_CRED.encode()).decode()
_NAME = "Proxy-Authorization"

_HTTP_TARGET = "http://partner.example.test/x"
_HTTPS_TARGET = "https://partner.example.test/x"

#: Spellings ``http.client`` puts on the wire as they are written.
_SENDABLE = {
    "space": _NAME + " ",
    "tab": _NAME + "\t",
    "space-tab": _NAME + " \t",
    "mixed-case-space": "pRoXy-aUtHoRiZaTiOn ",
    "vertical-tab": _NAME + "\x0b",
    "form-feed": _NAME + "\x0c",
    "file-separator": _NAME + "\x1c",
    "unit-separator": _NAME + "\x1f",
    "nul": _NAME + "\x00",
    "backspace": _NAME + "\x08",
    "delete": _NAME + "\x7f",
    "leading-file-separator": "\x1c" + _NAME,
    "leading-unit-separator": "\x1f" + _NAME,
    "leading-nul": "\x00" + _NAME,
    "leading-delete": "\x7f" + _NAME,
    "leading-backspace": "\x08" + _NAME,
    "semicolon": _NAME + ";",
    "leading-parenthesis": "(" + _NAME,
    "quotation-mark": _NAME + '"',
}

#: Spellings ``http.client`` refuses before it opens a connection, each with what it raises.
_UNSENDABLE: dict[str, tuple[str, type[Exception]]] = {
    "leading-space": (" " + _NAME, ValueError),
    "leading-tab": ("\t" + _NAME, ValueError),
    "leading-vertical-tab": ("\x0b" + _NAME, ValueError),
    "leading-form-feed": ("\x0c" + _NAME, ValueError),
    "both-ends": (" " + _NAME + " ", ValueError),
    "carriage-return": (_NAME + "\r", ValueError),
    "line-feed": (_NAME + "\n", ValueError),
    "colon": (_NAME + ":", ValueError),
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


def _stock_opener() -> urllib.request.OpenerDirector:
    """urllib's own opener with no proxy and none of the engine's rules: the measuring stick."""
    return urllib.request.build_opener(urllib.request.ProxyHandler({}))


def _refused(
    opener: urllib.request.OpenerDirector, request: urllib.request.Request, item: str
) -> None:
    with pytest.raises(ProxyCredentialsRefusedError) as raised:
        opener.open(request, timeout=5)
    text = f"{raised.value!s} {raised.value!r}"
    assert item in text
    for part in ("u5er", "pa55w0rd", _VALUE, "0ther", "s3cret", _URL_VALUE, "127.0.0.1", "partner"):
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
def test_measured_http_client_sends_the_spelling_as_written(name: str) -> None:
    """The control for every refusal below. urllib's own opener, with none of the engine's rules,
    puts the spelling on the wire with its extra characters intact. So a refusal below is the
    rule's, not ``http.client``'s."""
    with _WireProxy() as destination:
        _open_and_discard(_stock_opener(), _request(name, f"http://{destination.address}/x"))
    assert len(destination.cleartext) == 1
    assert f"\r\n{name.title()}: {_VALUE}\r\n".encode("latin-1") in destination.cleartext[0]


@pytest.mark.parametrize("spelling", list(_UNSENDABLE))
def test_measured_http_client_refuses_the_spelling_before_it_connects(spelling: str) -> None:
    name, raised_by_http_client = _UNSENDABLE[spelling]
    with _WireProxy() as destination, pytest.raises(raised_by_http_client):
        _stock_opener().open(_request(name, f"http://{destination.address}/x"), timeout=5)
    assert destination.connections == 0


def _never_sent(opener: urllib.request.OpenerDirector, request: urllib.request.Request) -> None:
    """The opener raises its fixed ``ValueError``, which holds no part of the name or the value."""
    with pytest.raises(ValueError, match="can never be sent") as raised:
        opener.open(request, timeout=5)
    assert type(raised.value) is ValueError
    assert raised.value.__cause__ is None
    assert raised.value.__context__ is None
    for part in ("u5er", "pa55w0rd", _VALUE, "made", "127.0.0.1", "partner"):
        assert part not in f"{raised.value!s} {raised.value!r}", part


@pytest.mark.parametrize("admitted", [False, True])
@pytest.mark.parametrize("target", [_HTTP_TARGET, _HTTPS_TARGET])
@pytest.mark.parametrize("spelling", list(_UNSENDABLE))
def test_an_unsendable_spelling_never_reaches_a_proxy(
    spelling: str, target: str, admitted: bool
) -> None:
    """The rule reads these as the proxy header too. No request could carry one, so the opener
    raises a ``ValueError``, the class ``http.client`` raised before the fix, and not the
    retryable refusal it keeps for a name that could be sent."""
    name, raised_by_http_client = _UNSENDABLE[spelling]
    assert issubclass(raised_by_http_client, ValueError)
    with _WireProxy() as proxy:
        _never_sent(_opener(proxy, admitted=admitted), _request(name, target))
    assert proxy.connections == 0


@pytest.mark.parametrize("spelling", list(_UNSENDABLE))
def test_an_unsendable_spelling_on_a_direct_request_is_never_sent(spelling: str) -> None:
    name, _ = _UNSENDABLE[spelling]
    with _WireProxy() as destination:
        opener = build_strict_opener(urllib.request.ProxyHandler({}))
        _never_sent(opener, _request(name, f"http://{destination.address}/x"))
    assert destination.connections == 0


@pytest.mark.parametrize("value", ["made\nup", "made\u4e0aup"], ids=["line-feed", "not-latin-1"])
def test_a_sendable_spelling_with_a_value_that_can_never_be_sent_is_never_sent(value: str) -> None:
    """``http.client`` refuses a header by its value too. Before the fix that was a
    ``ValueError`` for these spellings, which the rule did not read."""
    with _WireProxy() as proxy:
        request = urllib.request.Request(_HTTP_TARGET, headers={_NAME + " ": value})
        _never_sent(_opener(proxy), request)
    assert proxy.connections == 0


@pytest.mark.parametrize("value", ["made\nup", "made\u4e0aup"], ids=["line-feed", "not-latin-1"])
def test_control_the_plain_name_with_such_a_value_is_still_refused_by_the_rule(value: str) -> None:
    """The plain name was refused by the rule before ``http.client`` saw its value, and is."""
    with _WireProxy() as proxy:
        request = urllib.request.Request(_HTTP_TARGET, headers={_NAME: value})
        _refused(_opener(proxy), request, "#3416")
    assert proxy.connections == 0


def test_a_credential_refusal_comes_before_the_unsendable_one() -> None:
    """A plain header the handler does not admit, beside a spelling that can never be sent.
    Before the fix the rule refused the plain one first, and it still does: that refusal is the
    retried kind, and it names the credential fault."""
    with _WireProxy() as proxy:
        request = urllib.request.Request(_HTTP_TARGET, headers={" " + _NAME: _VALUE})
        request.headers[_NAME.upper()] = _VALUE
        _refused(_opener(proxy), request, "#3416")
    assert proxy.connections == 0


def test_a_proxy_url_credential_refusal_comes_before_the_unsendable_one() -> None:
    with _WireProxy() as proxy:
        value = f"http://{_URL_CRED}@{proxy.address}"
        opener = build_strict_opener(urllib.request.ProxyHandler({"http": value, "https": value}))
        _refused(opener, _request(" " + _NAME, _HTTP_TARGET), "#2572")
    assert proxy.connections == 0


def test_a_name_is_judged_as_do_open_would_send_it() -> None:
    """``do_open`` title-cases a name before it sends it. A name stored with a leading sharp s
    will not encode as ASCII as stored, and does once title-cased, so ``http.client`` would
    send it. The rule judges it as a sendable spelling and refuses it."""
    with _WireProxy() as proxy:
        request = urllib.request.Request(_HTTP_TARGET)
        request.headers[chr(0xDF) + _NAME] = _VALUE
        _refused(_opener(proxy), request, "#3416")
    assert proxy.connections == 0


# --- the order: a credential refusal first, on every leg -------------------------------------------


def _unsendable_beside_plain(url: str) -> urllib.request.Request:
    """A plain header, and beside it a spelling that can never be sent."""
    request = urllib.request.Request(url, headers={" " + _NAME: _VALUE})
    request.headers[_NAME.upper()] = _VALUE
    return request


def _hostname_unchecked() -> ssl.SSLContext:
    context = ssl.create_default_context()
    context.check_hostname = False
    return context


def test_the_direct_refusal_comes_before_the_unsendable_one() -> None:
    """The direct leg. Before the fix the rule refused the plain header here, and only a request
    that got past it met ``http.client``. The order is the same now."""
    with _WireProxy() as destination:
        opener = build_strict_opener(urllib.request.ProxyHandler({}))
        _refused(opener, _unsendable_beside_plain(f"http://{destination.address}/x"), "#3417")
    assert destination.connections == 0


@pytest.mark.parametrize("admitted", [False, True])
def test_the_unverified_tls_refusal_comes_before_the_unsendable_one(admitted: bool) -> None:
    """The leg that reaches an ``https://`` proxy over TLS, on a context that does not check the
    host name. The plain header is refused for that, admitted or not, before the unsendable
    spelling is looked at."""
    with _WireProxy() as proxy:
        handler = LoopbackDirectProxyHandler(
            {"http": f"https://{proxy.address}"}, caller_header_admitted=admitted
        )
        opener = build_strict_opener(
            urllib.request.HTTPSHandler(context=_hostname_unchecked()), handler
        )
        _refused(opener, _unsendable_beside_plain(_HTTP_TARGET), "#3418")
    assert proxy.connections == 0


def test_control_the_unsendable_one_alone_is_what_those_legs_raise() -> None:
    """The other polarity for the two tests above: with no plain header beside it, the same two
    legs raise the fixed ``ValueError``. So those tests read an order, not an absence."""
    with _WireProxy() as peer:
        direct = build_strict_opener(urllib.request.ProxyHandler({}))
        _never_sent(direct, _request(" " + _NAME, f"http://{peer.address}/x"))
        handler = LoopbackDirectProxyHandler({"http": f"https://{peer.address}"})
        over_tls = build_strict_opener(
            urllib.request.HTTPSHandler(context=_hostname_unchecked()), handler
        )
        _never_sent(over_tls, _request(" " + _NAME, _HTTP_TARGET))
    assert peer.connections == 0


# --- a value http.client refuses with another error -----------------------------------------------

#: Values ``http.client`` will not send, and refuses with a ``TypeError`` and not a ``ValueError``.
_TYPE_ERROR_VALUES: dict[str, Any] = {"none": None, "float": 1.5, "list": ["made", "up"]}


def _odd_request(value: Any, url: str = _HTTP_TARGET) -> urllib.request.Request:
    """A sendable odd spelling, holding a value ``http.client`` cannot send."""
    request = urllib.request.Request(url)
    request.headers[_NAME + " "] = value
    return request


@pytest.mark.parametrize("value", list(_TYPE_ERROR_VALUES.values()), ids=list(_TYPE_ERROR_VALUES))
def test_measured_http_client_raises_type_error_for_the_value(value: Any) -> None:
    with _WireProxy() as destination, pytest.raises(TypeError):
        _stock_opener().open(_odd_request(value, f"http://{destination.address}/x"), timeout=5)
    assert destination.connections == 0


@pytest.mark.parametrize("value", list(_TYPE_ERROR_VALUES.values()), ids=list(_TYPE_ERROR_VALUES))
def test_a_proxy_url_credential_refusal_comes_before_any_error_from_the_value(value: Any) -> None:
    """The check that decides which headers the rule judges asks ``http.client`` about this
    value. Its ``TypeError`` must not escape from there: a credential in the proxy URL is refused
    first, as it was before the rule read this spelling."""
    with _WireProxy() as proxy:
        proxy_url = f"http://{_URL_CRED}@{proxy.address}"
        opener = build_strict_opener(
            urllib.request.ProxyHandler({"http": proxy_url, "https": proxy_url})
        )
        _refused(opener, _odd_request(value), "#2572")
    assert proxy.connections == 0


@pytest.mark.parametrize("value", list(_TYPE_ERROR_VALUES.values()), ids=list(_TYPE_ERROR_VALUES))
def test_a_plain_header_refusal_comes_before_any_error_from_the_value(value: Any) -> None:
    with _WireProxy() as proxy:
        request = _odd_request(value)
        request.headers[_NAME.upper()] = _VALUE
        _refused(_opener(proxy), request, "#3416")
    assert proxy.connections == 0


@pytest.mark.parametrize("value", list(_TYPE_ERROR_VALUES.values()), ids=list(_TYPE_ERROR_VALUES))
def test_control_with_no_credential_refusal_the_type_error_stands(value: Any) -> None:
    """With nothing for the rule to refuse, the request fails as it did before the fix: with
    ``http.client``'s own ``TypeError``, and with nothing sent."""
    with _WireProxy() as proxy, pytest.raises(TypeError):
        _opener(proxy).open(_odd_request(value), timeout=5)
    assert proxy.connections == 0


# --- asking http.client opens nothing --------------------------------------------------------------

#: Run in a child process, because an audit hook cannot be removed once it is added. It imports
#: the engine first, then counts the audit events for a socket being made or connected and for a
#: name being resolved: once around a control that does both, and once around the check.
_AUDIT_SCRIPT = """
import json, socket, sys
from messagefoundry.transports import bounded_read

watched = {"socket.__new__", "socket.connect", "socket.getaddrinfo", "socket.gethostbyname",
           "socket.gethostbyaddr"}
seen = []
sys.addaudithook(lambda event, args: seen.append(event) if event in watched else None)

socket.getaddrinfo("localhost", 80)
socket.socket().close()
control = sorted(set(seen))
seen.clear()

plain = "Proxy-Authorization"
value = "made up"
answers = {
    "leading space": bounded_read._can_never_be_sent(chr(32) + plain, value),
    "line feed": bounded_read._can_never_be_sent(plain + chr(10), value),
    "not ascii": bounded_read._can_never_be_sent(plain + chr(160), value),
    "value is None": bounded_read._can_never_be_sent(plain + chr(32), None),
    "trailing space": bounded_read._can_never_be_sent(plain + chr(32), value),
    "bytes name": bounded_read._can_never_be_sent(plain.encode() + bytes([32]), value),
}
print(json.dumps({"control": control, "seen": seen, "answers": answers}))
"""


def test_asking_http_client_about_a_header_opens_no_socket_and_resolves_no_name() -> None:
    """The check runs on every request that holds an odd spelling, so it must cost no network.
    It names ``localhost`` and never resolves it. The control shows the hook fires for a socket
    and for a lookup, and the answers show the check really ran."""
    done = subprocess.run(  # noqa: S603 - this interpreter, a fixed script, no input from a test
        [sys.executable, "-c", _AUDIT_SCRIPT],
        cwd=Path(__file__).resolve().parents[1],
        capture_output=True,
        text=True,
        timeout=120,
        check=True,
    )
    report = json.loads(done.stdout)
    assert "socket.getaddrinfo" in report["control"]
    assert "socket.__new__" in report["control"]
    assert report["answers"] == {
        "leading space": True,
        "line feed": True,
        "not ascii": True,
        "value is None": True,
        "trailing space": False,
        "bytes name": False,
    }
    assert report["seen"] == []


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


@pytest.mark.parametrize("target", [_HTTP_TARGET, _HTTPS_TARGET])
@pytest.mark.parametrize("name", list(_SENDABLE.values()), ids=list(_SENDABLE))
def test_an_admission_never_covers_another_spelling(name: str, target: str) -> None:
    """An admission is for the header the connection made, which is spelled plainly. urllib moves
    only that spelling into a ``CONNECT``, so any other would stay on the request sent inside the
    tunnel, where the destination reads it. Before the fix, an admitting handler sent each of
    these: to the proxy for the ``http`` target, and into the tunnel for the ``https`` one."""
    with _WireProxy() as proxy:
        _refused(_opener(proxy, admitted=True), _request(name, target), "#3416")
    assert proxy.connections == 0


@pytest.mark.parametrize("name", [_NAME, _NAME.lower(), _NAME.upper()])
def test_control_an_admission_covers_the_plain_name_in_any_case(name: str) -> None:
    """The other polarity: the plain name crosses on an admission, in the ``CONNECT``."""
    with _WireProxy() as proxy:
        request = urllib.request.Request(_HTTPS_TARGET)
        request.headers[name] = _VALUE  # stored as written: add_header would change the case
        _open_and_discard(_opener(proxy, admitted=True), request)
    assert len(proxy.cleartext) == 1
    assert proxy.cleartext[0].startswith(b"CONNECT partner.example.test:443 ")
    assert f"{_NAME}: {_VALUE}\r\n".encode() in proxy.cleartext[0]


def _https_proxy_for_http_only(
    proxy: _WireProxy, *, admitted: bool
) -> urllib.request.OpenerDirector:
    """Only ``http`` is proxied, to a proxy written ``https://``, on a context that fully
    verifies. That is the one leg that reaches a proxy over TLS first."""
    handler = LoopbackDirectProxyHandler(
        {"http": f"https://{proxy.address}"}, caller_header_admitted=admitted
    )
    return build_strict_opener(handler)


@pytest.mark.parametrize("admitted", [False, True])
@pytest.mark.parametrize("name", [_NAME + " ", _NAME + "\x00"], ids=["space", "nul"])
def test_an_oddly_spelled_header_does_not_cross_a_verified_tls_leg(
    name: str, admitted: bool
) -> None:
    """The plain name may cross this leg, because the proxy takes it as its own. A proxy is not
    sure to take any other spelling that way, and could pass it on to the ``http`` destination."""
    with _WireProxy() as proxy:
        opener = _https_proxy_for_http_only(proxy, admitted=admitted)
        _refused(opener, _request(name, _HTTP_TARGET), "#3416")
    assert proxy.connections == 0


def test_control_the_plain_name_crosses_a_verified_tls_leg() -> None:
    with _WireProxy() as proxy:
        opener = _https_proxy_for_http_only(proxy, admitted=False)
        _open_and_discard(opener, _request(_NAME, _HTTP_TARGET))
    assert proxy.tls_first == 1
    assert proxy.cleartext == []


def test_a_second_header_never_hides_a_proxy_url_credential() -> None:
    """Two proxies. urllib makes a header from the first one's URL and carries it on to the
    second. The request also holds a caller-set header under another key, stored first. Every
    matching header is read, so the one from the proxy URL is still seen and the second proxy is
    not dialled. A reading that stopped at the first match would see only the caller's header,
    which the handler admits."""
    with _WireProxy() as first, _WireProxy() as second:
        handler = LoopbackDirectProxyHandler(
            {
                "http": f"https://{_URL_CRED}@{first.address}",
                "https": f"http://{second.address}",
            },
            caller_header_admitted=True,
        )
        request = urllib.request.Request(_HTTP_TARGET)
        request.headers[_NAME.upper()] = _VALUE
        _refused(build_strict_opener(handler), request, "#3410")
    assert first.connections == 0
    assert second.connections == 0


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


def _rest_with_static_header(name: str, proxy: _WireProxy, **extra: str) -> RestDestination:
    """A REST connection that sets one static header and names a cleartext proxy on the box. With
    no ``proxy_user`` in ``extra``, its proxy handler admits no caller-set header.
    ``cleartext_accepted`` covers the ``http://`` destination hop."""
    settings = Rest(url=_HTTP_TARGET).settings
    settings.update({"proxy_url": f"http://{proxy.address}", "headers": {name: _VALUE}, **extra})
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


@pytest.mark.parametrize(
    "name", [_NAME, _NAME + " ", _NAME + "\t", _NAME + "\x00"], ids=["plain", "space", "tab", "nul"]
)
def test_a_rest_send_with_a_static_proxy_header_is_refused_in_any_spelling(name: str) -> None:
    """Before the fix, every spelling but ``plain`` reached the proxy in a cleartext request,
    value and all. ``plain`` is the control that was already refused."""
    with _WireProxy() as proxy:
        dest = _rest_with_static_header(name, proxy)
        with pytest.raises(DeliveryError) as raised:
            asyncio.run(dest.send('{"a": 1}'))
    assert isinstance(raised.value.__cause__, ProxyCredentialsRefusedError)
    assert "#3416" in str(raised.value)
    for part in ("u5er", "pa55w0rd", _VALUE):
        assert part not in str(raised.value), part
    assert proxy.connections == 0


@pytest.mark.parametrize(
    "name",
    [_NAME, *_SENDABLE.values(), *(n for n, _ in _UNSENDABLE.values())],
    ids=["plain", *_SENDABLE, *_UNSENDABLE],
)
def test_a_static_proxy_header_beside_proxy_user_is_refused_at_build_in_any_spelling(
    name: str,
) -> None:
    """The build-time twin of the send-time rule, for a connection that sets ``proxy_user``. It
    reads the key through the same function, so a spelling one rule refuses the other refuses.
    It used ``str.strip`` of its own, which no test pinned. The error names the key in ``repr``
    form and never the value."""
    with _WireProxy() as proxy, pytest.raises(ValueError, match="#3443") as raised:
        _rest_with_static_header(name, proxy, proxy_user="u5er", proxy_password="pa55w0rd")
    text = str(raised.value)
    assert repr(name) in text
    for part in ("u5er", "pa55w0rd", _VALUE):
        assert part not in text, part
    assert proxy.connections == 0


def test_control_another_static_header_beside_proxy_user_builds() -> None:
    with _WireProxy() as proxy:
        dest = _rest_with_static_header(
            "X-Proxy-Authorization", proxy, proxy_user="u5er", proxy_password="pa55w0rd"
        )
    assert dest._headers["X-Proxy-Authorization"] == _VALUE


#: One spelling of each kind ``http.client`` can never send: its own name pattern refuses the
#: first two, and the third will not encode as ASCII.
_NEVER_SENT = {
    "leading-space": " " + _NAME,
    "trailing-line-feed": _NAME + "\n",
    "trailing-no-break-space": _NAME + "\xa0",
}


@pytest.mark.parametrize("name", list(_NEVER_SENT.values()), ids=list(_NEVER_SENT))
def test_a_rest_send_with_a_name_that_can_never_be_sent_fails_permanently(name: str) -> None:
    """A fault in what the operator wrote, which no retry can mend. Before the fix this was a
    permanent refusal, raised from ``http.client``'s own error. The rule must not turn it into
    a retryable one, which would spend the retry policy before the message dead-letters."""
    with _WireProxy() as proxy:
        dest = _rest_with_static_header(name, proxy)
        with pytest.raises(NegativeAckError) as raised:
            asyncio.run(dest.send('{"a": 1}'))
    assert raised.value.permanent is True
    assert raised.value.code == "bad-request-value"
    assert type(raised.value.__cause__) is ValueError
    assert "can never be sent" in str(raised.value.__cause__)
    for part in ("u5er", "pa55w0rd", _VALUE):
        assert part not in str(raised.value), part
    assert proxy.connections == 0


@pytest.mark.parametrize("name", [_NAME, _NAME + " "], ids=["plain", "space"])
def test_control_a_rest_send_with_a_sendable_proxy_header_is_refused_and_retried(
    name: str,
) -> None:
    """The other polarity. A name that could reach the wire is a credential on its way out: the
    rule refuses it, and the refusal is the retryable kind, as the plain name's already was."""
    with _WireProxy() as proxy:
        dest = _rest_with_static_header(name, proxy)
        with pytest.raises(DeliveryError) as raised:
            asyncio.run(dest.send('{"a": 1}'))
    assert not isinstance(raised.value, NegativeAckError)
    assert isinstance(raised.value.__cause__, ProxyCredentialsRefusedError)
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


# --- a bytes name ----------------------------------------------------------------------------------


def _bytes_request(name: bytes, url: str) -> urllib.request.Request:
    """A request that holds one header under a ``bytes`` name. urllib annotates a name as
    ``str``, but stores and sends whatever it is given."""
    request = urllib.request.Request(url)
    request.headers[name] = _VALUE  # type: ignore[index]
    return request


_BYTES_SPELLINGS = [_NAME.encode(), _NAME.lower().encode(), _NAME.encode() + b" "]


def test_measured_http_client_sends_a_bytes_name_as_written() -> None:
    """The control for the tests below: urllib's own opener puts a ``bytes`` name on the wire
    byte for byte."""
    with _WireProxy() as destination:
        request = _bytes_request(_NAME.encode(), f"http://{destination.address}/x")
        _open_and_discard(_stock_opener(), request)
    assert len(destination.cleartext) == 1
    assert f"\r\n{_NAME}: {_VALUE}\r\n".encode() in destination.cleartext[0]


@pytest.mark.parametrize("admitted", [False, True])
@pytest.mark.parametrize("target", [_HTTP_TARGET, _HTTPS_TARGET])
@pytest.mark.parametrize("name", _BYTES_SPELLINGS)
def test_a_bytes_spelling_of_the_proxy_header_is_refused_before_a_proxy_leg(
    name: bytes, target: str, admitted: bool
) -> None:
    """Before the fix a ``bytes`` name was not read at all, so it reached the proxy. It is read
    as latin-1 now. An admission never covers it: urllib looks the name up as a ``str`` when it
    fills a ``CONNECT``, so a ``bytes`` one would stay on the request sent inside the tunnel."""
    with _WireProxy() as proxy:
        _refused(_opener(proxy, admitted=admitted), _bytes_request(name, target), "#3416")
    assert proxy.connections == 0


@pytest.mark.parametrize("name", _BYTES_SPELLINGS)
def test_a_bytes_spelling_of_the_proxy_header_on_a_direct_request_is_refused(name: bytes) -> None:
    with _WireProxy() as destination:
        opener = build_strict_opener(urllib.request.ProxyHandler({}))
        _refused(opener, _bytes_request(name, f"http://{destination.address}/x"), "#3417")
    assert destination.connections == 0


@pytest.mark.parametrize("through_a_proxy", [False, True])
def test_control_another_bytes_header_is_sent(through_a_proxy: bool) -> None:
    """A ``bytes`` name the rule does not read still crosses, direct or through a proxy."""
    with _WireProxy() as peer:
        if through_a_proxy:
            opener, url = _opener(peer), _HTTP_TARGET
        else:
            opener = build_strict_opener(urllib.request.ProxyHandler({}))
            url = f"http://{peer.address}/x"
        with opener.open(_bytes_request(b"X-Trace", url), timeout=5) as resp:
            assert resp.read() == b"ok"
    assert len(peer.cleartext) == 1
    assert f"\r\nX-Trace: {_VALUE}\r\n".encode() in peer.cleartext[0]


@pytest.mark.parametrize("name", [*_BYTES_SPELLINGS, b"\x00" + _NAME.encode() + b"\xa0"])
def test_a_bytes_name_is_read_as_the_wire_would_carry_it(name: bytes) -> None:
    assert is_proxy_credential_header_name(name)


@pytest.mark.parametrize("name", [b"X-Trace", b"Authorization", b"", b"X-" + _NAME.encode()])
def test_control_another_bytes_name_is_not_the_proxy_credential_header(name: bytes) -> None:
    assert not is_proxy_credential_header_name(name)


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
def test_the_name_is_read_in_any_case_whatever_is_at_its_ends(name: str) -> None:
    assert is_proxy_credential_header_name(name)


@pytest.mark.parametrize(
    "name",
    [
        "Authorization",
        "X-Proxy-Authorization",
        "Proxy-Authorization-2",
        "Proxy -Authorization",
        "Proxy-\x00Authorization",
        "",
        " \t",
    ],
)
def test_control_another_name_is_not_the_proxy_credential_header(name: str) -> None:
    assert not is_proxy_credential_header_name(name)


def test_a_message_cannot_set_the_proxy_header_and_asks_through_the_shared_reading(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Message metadata asks the same question through the same function. A name with whitespace
    never gets that far: it is not a header-name token, so it is dropped first."""
    prefix = rest.DYNAMIC_HEADER_PREFIX
    bag = {
        prefix + _NAME: _VALUE,
        prefix + _NAME.lower(): _VALUE,
        prefix + _NAME + " ": _VALUE,
        prefix + "X-Trace": "t1",
        prefix + "X-Other": "o1",
    }
    # Control in the same bag: ordinary headers survive.
    assert rest.outbound_headers_from_metadata(bag) == {"X-Trace": "t1", "X-Other": "o1"}
    # The shared function is what decides: answer for another name, and that header goes instead.
    monkeypatch.setattr(rest, "is_proxy_credential_header_name", lambda name: name == "X-Trace")
    assert rest.outbound_headers_from_metadata(bag) == {
        _NAME: _VALUE,
        _NAME.lower(): _VALUE,
        "X-Other": "o1",
    }
