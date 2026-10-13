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
from messagefoundry.transports import bounded_read, build_destination, rest
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
    """With nothing for the rule to refuse, the request fails as it did before the fix: with a
    ``TypeError``, the class ``http.client`` raises for the value, and with nothing sent. The
    text is the opener's fixed one."""
    with _WireProxy() as proxy, pytest.raises(TypeError, match="can never be sent") as raised:
        _opener(proxy).open(_odd_request(value), timeout=5)
    assert type(raised.value) is TypeError
    assert "made" not in str(raised.value)
    assert proxy.connections == 0


def _two_unsendable(first: str) -> urllib.request.Request:
    """Two spellings that can never be sent, one by its name and one by its value, stored in
    the order asked for."""
    by_name, by_value = (" " + _NAME, _VALUE), (_NAME + " ", None)
    request = urllib.request.Request(_HTTP_TARGET)
    for name, value in (by_name, by_value) if first == "name" else (by_value, by_name):
        request.headers[name] = value  # type: ignore[assignment]
    return request


@pytest.mark.parametrize(("first", "raised_class"), [("name", ValueError), ("value", TypeError)])
def test_the_first_unsendable_header_decides_the_class(
    first: str, raised_class: type[Exception]
) -> None:
    """``http.client`` stops at the first header it will not send, so the class of the error
    follows the order the headers are sent in. The opener raises the same class as urllib's own
    opener does for the same request."""
    with _WireProxy() as destination:
        url = f"http://{destination.address}/x"
        stock = _two_unsendable(first)
        stock.full_url = url
        with pytest.raises(raised_class):
            _stock_opener().open(stock, timeout=5)
    assert destination.connections == 0
    with _WireProxy() as proxy, pytest.raises(raised_class, match="can never be sent") as raised:
        _opener(proxy).open(_two_unsendable(first), timeout=5)
    assert type(raised.value) is raised_class
    assert proxy.connections == 0


class _FaultyValue:
    """A header value whose ``encode`` fails in a way that says nothing about the header."""

    def encode(self, encoding: str) -> bytes:
        raise RuntimeError("a fault of the value's own")


def test_an_error_that_is_no_verdict_on_the_header_stops_the_request() -> None:
    """Only a ``ValueError`` or a ``TypeError`` is read as ``http.client`` refusing a header.
    Anything else stops the request where it is raised. Reading it as a refusal would leave the
    header out of the rule, and a fault that then passed would let the header go."""
    with _WireProxy() as proxy, pytest.raises(RuntimeError, match="of the value's own"):
        _opener(proxy).open(_odd_request(_FaultyValue()), timeout=5)
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
def ask(name, value):
    refusal = bounded_read._refusal_by_http_client(name, value)
    return refusal and refusal.__name__

answers = {
    "leading space": ask(chr(32) + plain, value),
    "line feed": ask(plain + chr(10), value),
    "not ascii": ask(plain + chr(160), value),
    "value is None": ask(plain + chr(32), None),
    "trailing space": ask(plain + chr(32), value),
    "bytes name": ask(plain.encode() + bytes([32]), value),
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
        "leading space": "ValueError",
        "line feed": "ValueError",
        "not ascii": "ValueError",
        "value is None": "TypeError",
        "trailing space": None,
        "bytes name": None,
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


# --- one verdict for a header in a request ---------------------------------------------------------
#
# A request is checked more than once while it is opened, and ``http.client`` is asked again at
# the send. Before this section's fix the opener put the same question about one header up to
# three times, and acted on each answer as it came. A header whose answer changed was left out of
# the rule on one answer, passed by the unsendable refusal on the next, and sent. Now a header is
# judged once, the answer is kept on the request, and either verdict ends in a refusal.

_LEGS = ("cleartext-proxy", "direct", "connect", "verified-tls-proxy")


def _on_leg(
    leg: str, peer: _WireProxy, *, admitted: bool = False
) -> tuple[urllib.request.OpenerDirector, str]:
    """An engine opener and a target that send a request down ``leg``. ``peer`` is the proxy, or
    the destination itself on the direct leg."""
    if leg == "direct":
        return build_strict_opener(urllib.request.ProxyHandler({})), f"http://{peer.address}/x"
    if leg == "verified-tls-proxy":
        return _https_proxy_for_http_only(peer, admitted=admitted), _HTTP_TARGET
    return _opener(peer, admitted=admitted), _HTTPS_TARGET if leg == "connect" else _HTTP_TARGET


def _held(name: Any, value: Any, url: str) -> urllib.request.Request:
    """A request that holds one header as the two objects given. ``add_header`` would store a
    plain ``str`` copy of the name."""
    request = urllib.request.Request(url)
    request.headers[name] = value
    return request


def _attempt(
    opener: urllib.request.OpenerDirector, request: urllib.request.Request
) -> Exception | None:
    """Open ``request`` and give back what that raised, or ``None`` if it was sent and answered.
    The caller reads the wire first, so a request that was sent fails on what reached it."""
    try:
        with opener.open(request, timeout=5) as resp:
            resp.read()
    except Exception as raised:
        return raised
    return None


@pytest.mark.parametrize("leg", _LEGS)
def test_control_each_leg_reaches_the_wire_with_another_header(leg: str) -> None:
    """The control for every ``connections == 0`` below: the same four legs, with a header the
    rule does not read, each dial the recording socket."""
    with _WireProxy() as peer:
        opener, url = _on_leg(leg, peer)
        _attempt(opener, _held("X-Trace", _VALUE, url))
    assert peer.connections == 1


class _FailsAtFirst:
    """A header value whose ``encode`` raises the first ``failures`` times it is called and
    answers after that. Asked more than once, it is first a value ``http.client`` cannot send,
    and then one it can."""

    def __init__(self, failures: int, error: type[Exception]) -> None:
        self.failures = failures
        self.error = error
        self.asked = 0

    def encode(self, encoding: str) -> bytes:
        self.asked += 1
        if self.asked <= self.failures:
            raise self.error("a refusal that will not last")
        return _VALUE.encode(encoding)


@pytest.mark.parametrize("leg", _LEGS)
@pytest.mark.parametrize("error", [ValueError, TypeError])
@pytest.mark.parametrize("failures", [1, 2])
def test_a_value_that_fails_at_first_and_then_answers_is_never_sent(
    failures: int, error: type[Exception], leg: str
) -> None:
    """A trailing-space spelling, no admission, and a value that ``http.client`` refuses once or
    twice before it takes it. The first answer is the verdict: the header can never be sent, so
    the request fails with the fixed error of that class, and nothing is dialled."""
    value = _FailsAtFirst(failures, error)
    with _WireProxy() as peer:
        opener, url = _on_leg(leg, peer)
        raised = _attempt(opener, _held(_NAME + " ", value, url))
    assert peer.connections == 0
    assert type(raised) is error
    assert "can never be sent" in str(raised)
    assert "will not last" not in str(raised)


@pytest.mark.parametrize("leg", _LEGS)
def test_such_a_value_is_put_to_http_client_once(leg: str) -> None:
    """Read at the value itself: one ``encode`` call for the whole request, on every leg."""
    value = _FailsAtFirst(1, ValueError)
    with _WireProxy() as peer:
        opener, url = _on_leg(leg, peer)
        _attempt(opener, _held(_NAME + " ", value, url))
    assert peer.connections == 0
    assert value.asked == 1


def test_the_verdict_stays_with_the_request_when_it_is_opened_again() -> None:
    """The answer is kept on the request, so a second open of the same request is refused the
    same way and asks nothing. The same value on a new request is a header not seen before. It
    answers by then, so the rule judges it, and refuses it as a credential."""
    value = _FailsAtFirst(1, ValueError)
    with _WireProxy() as peer:
        opener, url = _on_leg("direct", peer)
        request = _held(_NAME + " ", value, url)
        first = _attempt(opener, request)
        second = _attempt(opener, request)
        asked_by_then = value.asked
        on_a_new_request = _attempt(opener, _held(_NAME + " ", value, url))
    assert peer.connections == 0
    assert type(first) is ValueError
    assert type(second) is ValueError
    assert asked_by_then == 1
    assert isinstance(on_a_new_request, ProxyCredentialsRefusedError)
    assert "#3417" in str(on_a_new_request)
    assert value.asked == 2


def test_a_verdict_does_not_outlive_its_header_on_the_request() -> None:
    """The request keeps a verdict, and with it the value judged. Once the header is gone the
    next check drops both, so the request holds the value no longer than its header."""
    with _WireProxy() as peer:
        opener, url = _on_leg("direct", peer)
        request = _held(_NAME + " ", _VALUE, url)
        _refused(opener, request, "#3417")
        kept_while_held = _VALUE in repr(vars(request)["_mefor_proxy_header_verdicts"])
        request.headers.clear()
        _attempt(opener, request)
    assert kept_while_held
    assert peer.connections == 1
    assert _VALUE not in repr(vars(request))


def test_an_error_over_a_later_header_does_not_lose_an_earlier_verdict() -> None:
    """Two odd spellings. The first gets its verdict, and asking about the second raises an
    error that is no verdict, which stops the request. The first header's answer is kept all
    the same, so a second open asks about it no more."""
    value = _FailsAtFirst(1, ValueError)
    with _WireProxy() as peer:
        opener, url = _on_leg("direct", peer)
        request = _held(_NAME + " ", value, url)
        request.headers[_NAME + "\t"] = _FaultyValue()  # type: ignore[assignment]
        first = _attempt(opener, request)
        second = _attempt(opener, request)
    assert peer.connections == 0
    assert type(first) is RuntimeError
    assert type(second) is RuntimeError
    assert value.asked == 1


class _ShiftingName(str):
    """A header name whose ``title()`` gives a name that cannot be sent the first ``lies`` times
    it is called, and its real title after that. ``do_open`` sends a name by its ``title()``."""

    lies: int
    asked: int

    def __new__(cls, text: str, lies: int) -> _ShiftingName:
        made = super().__new__(cls, text)
        made.lies = lies
        made.asked = 0
        return made

    def title(self) -> str:
        self.asked += 1
        real = str(self).title()
        return " " + real if self.asked <= self.lies else real


@pytest.mark.parametrize("leg", _LEGS)
@pytest.mark.parametrize("lies", [1, 2])
def test_a_name_whose_title_changes_its_answer_is_never_sent(lies: int, leg: str) -> None:
    """The same gap from the name's side. The first title is one ``http.client`` refuses, and
    that is the verdict, whatever a later call would give."""
    name = _ShiftingName(_NAME + " ", lies)
    with _WireProxy() as peer:
        opener, url = _on_leg(leg, peer)
        raised = _attempt(opener, _held(name, _VALUE, url))
    assert peer.connections == 0
    assert type(raised) is ValueError
    assert "can never be sent" in str(raised)
    assert name.asked == 1


class _Retitled(str):
    """A name that holds the plain spelling and answers ``title()`` with another name, which is
    the one ``do_open`` would send."""

    def title(self) -> str:
        return "X-Made-Up"


@pytest.mark.parametrize(
    ("leg", "admitted"),
    [
        ("verified-tls-proxy", False),
        ("connect", True),
        ("cleartext-proxy", True),
        ("direct", False),
    ],
)
def test_a_str_subclass_is_never_taken_as_the_plain_spelling(leg: str, admitted: bool) -> None:
    """The plain spelling may cross a verified TLS leg, and an admission covers it, because
    urllib sends it as the proxy's own header. That is known of a ``str`` only. A subclass
    answers ``title()`` itself, so it is judged like any other spelling, and refused."""
    with _WireProxy() as peer:
        opener, url = _on_leg(leg, peer, admitted=admitted)
        raised = _attempt(opener, _held(_Retitled(_NAME), _VALUE, url))
    assert peer.connections == 0
    assert isinstance(raised, ProxyCredentialsRefusedError)
    assert "#3417" in str(raised) if leg == "direct" else "#3416" in str(raised)


class _ClaimsToBeAnyName(str):
    """A name that hashes like ``twin`` and says it equals any name, the first ``lies`` times it
    is asked. Stored among the unredirected headers, it tells a dictionary lookup that ``twin``
    is already there."""

    lies: int
    asked: int
    _twin_hash: int

    def __new__(cls, text: str, twin: str, lies: int) -> _ClaimsToBeAnyName:
        made = super().__new__(cls, text)
        made.lies = lies
        made.asked = 0
        made._twin_hash = hash(twin)
        return made

    def __hash__(self) -> int:
        return self._twin_hash

    def __eq__(self, other: object) -> bool:
        self.asked += 1
        return self.asked <= self.lies


def test_a_name_that_claims_to_be_a_headers_twin_cannot_hide_it() -> None:
    """``do_open`` merges the two header stores by name, and asks the names themselves. The
    opener's reading used to copy that merge. A name object that answered yes to the reading
    and no to ``do_open`` hid the header beside it from the rule, and ``do_open`` then sent it.
    The reading asks no name object now."""
    odd = _NAME + " "
    twin = _ClaimsToBeAnyName("X-Made-Up", odd, lies=2)
    with _WireProxy() as peer:
        opener, url = _on_leg("direct", peer)
        request = _held(odd, _VALUE, url)
        request.unredirected_hdrs[twin] = "made up"
        _refused(opener, request, "#3417")
    assert peer.connections == 0
    assert twin.asked == 0


def _admitting_with_a_second_proxy(peer: _WireProxy) -> urllib.request.OpenerDirector:
    """An admitting opener with two proxies. ``http`` goes to ``peer`` in cleartext. The second
    proxy's URL carries a credential, which makes ``_URL_VALUE``."""
    handler = LoopbackDirectProxyHandler(
        {
            "http": f"http://{peer.address}",
            "https": f"http://{_URL_CRED}@other.example.test:3128",
        },
        caller_header_admitted=True,
    )
    return build_strict_opener(handler)


def _held_in_both_stores(
    peer: _WireProxy, unredirected: str, in_headers: str
) -> tuple[urllib.request.OpenerDirector, urllib.request.Request]:
    """That opener, and a request that holds the plain name in both header stores."""
    request = urllib.request.Request(_HTTP_TARGET)
    request.add_unredirected_header(_NAME, unredirected)
    request.add_header(_NAME, in_headers)
    return _admitting_with_a_second_proxy(peer), request


@pytest.mark.parametrize(
    ("unredirected", "in_headers"),
    [(_VALUE, _URL_VALUE), (_URL_VALUE, _VALUE)],
    ids=["url-credential-in-headers", "url-credential-unredirected"],
)
def test_a_name_held_in_both_stores_is_judged_in_both(unredirected: str, in_headers: str) -> None:
    """``do_open`` sends one of the two values, and which one depends on the Python release:
    3.14.6 sends the unredirected one, and 3.14.8 the one in ``headers``. One value here is
    what a proxy URL makes, which no admission covers. A reading that judged one store only
    would let it cross to the other proxy in cleartext on one of those releases. Both are
    judged, so the request is refused on either."""
    with _WireProxy() as peer:
        opener, request = _held_in_both_stores(peer, unredirected, in_headers)
        _refused(opener, request, "#3410")
    assert peer.connections == 0


def test_control_a_name_held_in_both_stores_crosses_when_neither_value_is_refused() -> None:
    """The other polarity: the same request with the admitted value in both stores is sent."""
    with _WireProxy() as peer:
        opener, request = _held_in_both_stores(peer, _VALUE, _VALUE)
        _attempt(opener, request)
    assert len(peer.cleartext) == 1
    assert f"{_NAME}: {_VALUE}\r\n".encode() in peer.cleartext[0]


class _Rewritable:
    """A header value that is no ``str``, whose text can be changed in place. ``str()`` and
    ``encode`` give the same text, so the rule reads what ``http.client`` would send."""

    def __init__(self, text: str) -> None:
        self.text = text

    def __str__(self) -> str:
        return self.text

    def encode(self, encoding: str) -> bytes:
        return self.text.encode(encoding)


def test_a_value_changed_in_place_is_judged_as_it_reads_at_the_next_open() -> None:
    """The plain name, an admission, and a value object. The first open sends it to the proxy
    on the admission. The object's text is then changed in place to what the second proxy's
    URL makes, which no admission covers, and the same request is opened again. The verdict is
    kept, because the header is the same two objects, but the text judged is read from the
    value at each check. So the second open is refused and sends nothing. A check that judged
    the text it read at the first open would send the new text to the proxy in cleartext."""
    value = _Rewritable(_VALUE)
    with _WireProxy() as peer:
        opener = _admitting_with_a_second_proxy(peer)
        request = _held(_NAME, value, _HTTP_TARGET)
        first = _attempt(opener, request)
        sent_at_first = list(peer.cleartext)
        value.text = _URL_VALUE
        second = _attempt(opener, request)
        on_a_new_request = _attempt(opener, _held(_NAME, value, _HTTP_TARGET))
    assert first is None
    assert len(sent_at_first) == 1
    assert f"{_NAME}: {_VALUE}\r\n".encode() in sent_at_first[0]
    assert peer.connections == 1
    for raised in (second, on_a_new_request):
        assert isinstance(raised, ProxyCredentialsRefusedError)
        assert "#3410" in str(raised)
        assert _URL_VALUE not in f"{raised!s} {raised!r}"


def test_control_a_value_left_as_it_was_crosses_at_a_second_open() -> None:
    """The other polarity: the same request, opened twice with the value unchanged, is sent
    twice. So the refusal above comes from the changed text, not from the second open."""
    value = _Rewritable(_VALUE)
    with _WireProxy() as peer:
        opener = _admitting_with_a_second_proxy(peer)
        request = _held(_NAME, value, _HTTP_TARGET)
        first = _attempt(opener, request)
        second = _attempt(opener, request)
    assert first is None
    assert second is None
    assert len(peer.cleartext) == 2
    assert all(f"{_NAME}: {_VALUE}\r\n".encode() in head for head in peer.cleartext)


def _only_proxy_header(request: urllib.request.Request) -> tuple[str, Any]:
    """The one header ``request.headers`` holds: the name object and the value object."""
    ((name, value),) = request.headers.items()
    return name, value


def test_a_value_urllib_stores_under_a_judged_name_is_judged_as_a_new_header() -> None:
    """A verdict is matched by the value object as well as the name object. A dictionary keeps
    its first key, so a header set again keeps its name object and holds a new value.

    urllib does that while a request is opened. The first proxy here is written ``https://``
    with a credential, so its check lets the caller's admitted header go to it over TLS.
    urllib then stores that proxy's own credential under the caller's name object, and hands
    the request to the second proxy, which is cleartext. A verdict found by the name alone
    would be the caller's, which the admission covers, and the first proxy's credential would
    cross to the second in a cleartext ``CONNECT``. The new value is judged instead, so the
    request is refused and neither proxy is dialled."""
    with _WireProxy() as first, _WireProxy() as second:
        handler = LoopbackDirectProxyHandler(
            {
                "http": f"https://{_URL_CRED}@{first.address}",
                "https": f"http://{second.address}",
            },
            caller_header_admitted=True,
        )
        request = urllib.request.Request(_HTTP_TARGET)
        request.add_header(_NAME, _VALUE)
        name_at_first, value_at_first = _only_proxy_header(request)
        raised = _attempt(build_strict_opener(handler), request)
    # What the test rests on: urllib replaced the value and kept the caller's name object.
    name_now, value_now = _only_proxy_header(request)
    assert name_now is name_at_first
    assert value_at_first == _VALUE
    assert value_now == _URL_VALUE
    assert second.cleartext == []
    assert first.connections == 0
    assert second.connections == 0
    assert isinstance(raised, ProxyCredentialsRefusedError)
    assert "#3410" in str(raised)


def test_a_value_set_again_between_two_opens_is_judged_as_a_new_header() -> None:
    """The same from a caller's side. The first open sends the admitted header. The caller
    then sets the header again, to what the second proxy's URL makes, and opens the request
    once more. ``add_header`` keeps the name object, so only the value object tells the two
    headers apart. The second open is refused and sends nothing."""
    with _WireProxy() as peer:
        opener = _admitting_with_a_second_proxy(peer)
        request = urllib.request.Request(_HTTP_TARGET)
        request.add_header(_NAME, _VALUE)
        name_at_first, _ = _only_proxy_header(request)
        first = _attempt(opener, request)
        request.add_header(_NAME, _URL_VALUE)
        name_now, value_now = _only_proxy_header(request)
        second = _attempt(opener, request)
    assert name_now is name_at_first
    assert value_now == _URL_VALUE
    assert first is None
    assert peer.connections == 1
    assert isinstance(second, ProxyCredentialsRefusedError)
    assert "#3410" in str(second)


class _Undecoded(bytes):
    """A ``bytes`` name whose ``decode`` gives another name than the bytes it holds."""

    def decode(self, *args: Any, **kwargs: Any) -> str:
        return "X-Made-Up"


def test_a_bytes_name_is_read_from_the_bytes_it_holds() -> None:
    """``http.client`` sends a ``bytes`` name byte for byte and never calls ``decode``, so the
    reading must not take the name's word for it either."""
    name = _Undecoded(_NAME.encode() + b" ")
    assert is_proxy_credential_header_name(name)
    with _WireProxy() as peer:
        opener, url = _on_leg("direct", peer)
        _refused(opener, _held(name, _VALUE, url), "#3417")
    assert peer.connections == 0


@pytest.fixture
def asked(monkeypatch: pytest.MonkeyPatch) -> list[tuple[Any, Any]]:
    """Each question put to ``http.client`` about a header, in order: the name and the value."""
    calls: list[tuple[Any, Any]] = []
    ask = bounded_read._refusal_by_http_client

    def spy(name: Any, value: Any) -> type[Exception] | None:
        calls.append((name, value))
        return ask(name, value)

    monkeypatch.setattr(bounded_read, "_refusal_by_http_client", spy)
    return calls


@pytest.mark.parametrize("leg", _LEGS)
@pytest.mark.parametrize("name", [" " + _NAME, _NAME + " "], ids=["unsendable", "sendable"])
def test_http_client_is_asked_about_a_header_once_in_a_request(
    name: str, leg: str, asked: list[tuple[Any, Any]]
) -> None:
    """The pin against the repeated question coming back: one call for the header, however many
    checks the leg makes. The verified TLS leg makes the most, because urllib hands the request
    back to the opener."""
    with _WireProxy() as peer:
        opener, url = _on_leg(leg, peer)
        raised = _attempt(opener, _held(name, _VALUE, url))
    assert peer.connections == 0
    assert raised is not None
    assert asked == [(name, _VALUE)]


def test_http_client_is_asked_once_about_each_of_two_headers(asked: list[tuple[Any, Any]]) -> None:
    with _WireProxy() as peer:
        opener, _ = _on_leg("verified-tls-proxy", peer)
        raised = _attempt(opener, _two_unsendable("name"))
    assert peer.connections == 0
    assert type(raised) is ValueError
    assert asked == [(" " + _NAME, _VALUE), (_NAME + " ", None)]


def test_a_bytes_name_held_in_both_stores_is_judged_in_both(
    asked: list[tuple[Any, Any]],
) -> None:
    """The same for a ``bytes`` name: one question about each of the two headers."""
    name = _NAME.encode() + b" "
    twin = bytes(bytearray(name))
    assert twin == name
    assert twin is not name
    with _WireProxy() as peer:
        opener, url = _on_leg("direct", peer)
        request = urllib.request.Request(url)
        request.unredirected_hdrs[name] = _VALUE  # type: ignore[index]
        request.headers[twin] = "made up"  # type: ignore[index]
        _refused(opener, request, "#3417")
    assert peer.connections == 0
    assert asked == [(name, _VALUE), (twin, "made up")]


def test_control_http_client_is_never_asked_about_the_plain_name(
    asked: list[tuple[Any, Any]],
) -> None:
    """The other polarity for the spy: the plain name is judged without a question."""
    with _WireProxy() as peer:
        opener, url = _on_leg("cleartext-proxy", peer)
        _refused(opener, _held(_NAME, _VALUE, url), "#3416")
    assert peer.connections == 0
    assert asked == []


def _routed_by_hand(name: str, peer: _WireProxy, url: str) -> urllib.request.Request:
    """A request sent to ``peer`` as its proxy by ``set_proxy``, on an opener that uses no proxy.
    So no proxy handler judged it, and the strict handler's check is the only one it meets."""
    request = _held(name, _VALUE, url)
    request.set_proxy(peer.address, "http")
    return request


@pytest.mark.parametrize("url", [_HTTP_TARGET, _HTTPS_TARGET], ids=["http", "connect"])
def test_an_odd_spelling_never_leaves_the_last_check_whoever_routed_the_request(url: str) -> None:
    """A proxy handler refuses a sendable odd spelling on every leg it sets up. This request
    reaches a proxy without one. The check that opens the connection refuses it there, in the
    words the proxy handler uses."""
    with _WireProxy() as peer:
        opener = build_strict_opener(urllib.request.ProxyHandler({}))
        _refused(opener, _routed_by_hand(_NAME + " ", peer, url), "#3416")
    assert peer.connections == 0


@pytest.mark.parametrize("url", [_HTTP_TARGET, _HTTPS_TARGET], ids=["http", "connect"])
def test_control_a_request_routed_by_hand_reaches_the_proxy_with_another_header(url: str) -> None:
    with _WireProxy() as peer:
        opener = build_strict_opener(urllib.request.ProxyHandler({}))
        _attempt(opener, _routed_by_hand("X-Trace", peer, url))
    assert len(peer.cleartext) == 1
