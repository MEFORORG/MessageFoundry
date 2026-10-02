# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A loopback hop is never sent through a web proxy (vault BACKLOG #2579, ASVS 12.2.1).

The cleartext-hop authority allows an ``http://`` hop to a loopback host because that hop stays on
the box. urllib's proxy handler knows nothing of that rule: it reads ``HTTP_PROXY``, ``HTTPS_PROXY``
and, on Windows, the system proxy, and with no ``NO_PROXY`` entry it routes a loopback request to
the proxy like any other. So a hop the engine judged on-box would have left the host. Every engine
urllib opener is built by ``build_strict_opener``, and that is where the rule now lives: a host the
cleartext guard accepts as loopback is dialled direct, whatever proxy the opener carries.

**No test here opens a socket.** ``do_open`` is where urllib dials, and the ``hermetic`` fixture
replaces it with a recorder. So the whole opener runs as shipped, request processors and proxy
handler included, and the test reads the host the request would have gone to.

Each rule is paired with a control on the same opener: an off-box host still goes to the proxy. The
alert webhook, the OIDC legs and the AI broker have no proxy setting of their own, so the
environment proxy is their only route out on a network that requires one.

Synthetic data only: every host name is reserved or made up.
"""

from __future__ import annotations

import logging
import sys
import types
import urllib.parse
import urllib.request
from collections.abc import Callable

import pytest

from messagefoundry.auth.oidc_http import build_idp_opener
from messagefoundry.config.models import ConnectorType, Destination
from messagefoundry.config.tls_policy import HopPosture, InsecureHopRefused, active_hop_posture
from messagefoundry.config.wiring import Rest
from messagefoundry.pipeline import alert_sinks
from messagefoundry.transports import build_destination, rest
from messagefoundry.transports.bounded_read import build_strict_opener, is_never_proxied_host
from messagefoundry.transports.rest import RestDestination

#: The proxy every test points at. A reserved name, so nothing could reach it.
_PROXY_HOST = "proxy-marker.invalid:9"
_PROXY = f"http://{_PROXY_HOST}"
_BOTH_SCHEMES = {"http": _PROXY, "https": _PROXY}

#: Every variable urllib reads a proxy or a bypass list from. ``REQUEST_METHOD`` makes it ignore
#: ``HTTP_PROXY``, as a CGI precaution.
_PROXY_ENV = ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY", "REQUEST_METHOD")

#: Hosts the cleartext guard accepts as on-box, in the spellings a URL can carry.
_LOOPBACK_URLS = (
    "http://127.0.0.1:18080/x",
    "http://127.9.8.7/x",
    "http://localhost:18080/x",
    "http://LOCALHOST/x",
    "http://[::1]:18080/x",
    "https://127.0.0.1:8443/x",
    "https://localhost/x",
    "https://[::1]/x",
)

#: Hosts the guard does not accept. Three of them only look like loopback.
_OFF_BOX_URLS = (
    "http://partner.invalid/x",
    "https://partner.invalid/x",
    "http://127.0.0.1.partner.invalid/x",
    "http://localhost.partner.invalid/x",
    "http://127.partner.invalid/x",
    "http://10.0.0.5/x",
    "http://[2001:db8::1]:18080/x",
)


class _Dialled(Exception):
    """Raised in place of the connection urllib was about to open."""

    def __init__(self, host: str) -> None:
        super().__init__(host)
        self.host = host


@pytest.fixture(autouse=True)
def hermetic(monkeypatch: pytest.MonkeyPatch) -> None:
    """No network and no ambient proxy: only what a test sets can route a request."""

    def do_open(
        self: object, http_class: object, req: urllib.request.Request, **kw: object
    ) -> None:
        raise _Dialled(req.host)

    # The one method through which urllib dials.
    monkeypatch.setattr(urllib.request.AbstractHTTPHandler, "do_open", do_open)
    for name in _PROXY_ENV:
        monkeypatch.delenv(name, raising=False)
        monkeypatch.delenv(name.lower(), raising=False)
    # With no proxy variable left, urllib falls back to the host's own system settings, where it
    # has any: the Windows registry, or the macOS system configuration.
    for source in ("registry", "macosx_sysconf"):
        monkeypatch.setattr(urllib.request, f"getproxies_{source}", dict, raising=False)
        monkeypatch.setattr(
            urllib.request, f"proxy_bypass_{source}", lambda host: False, raising=False
        )


@pytest.fixture
def environment_proxy(monkeypatch: pytest.MonkeyPatch) -> None:
    """An environment proxy for both schemes, and no bypass list."""
    monkeypatch.setenv("HTTP_PROXY", _PROXY)
    monkeypatch.setenv("HTTPS_PROXY", _PROXY)


def _dialled(opener: urllib.request.OpenerDirector, url: str) -> str:
    """The ``host:port`` ``opener`` would connect to for ``url``."""
    with pytest.raises(_Dialled) as caught:
        opener.open(urllib.request.Request(url, data=b"synthetic", method="POST"), timeout=1)
    return caught.value.host


def _own_host(url: str) -> str:
    return urllib.parse.urlsplit(url).netloc


def _assert_only_loopback_goes_direct(opener: urllib.request.OpenerDirector) -> None:
    for url in _LOOPBACK_URLS:
        assert _dialled(opener, url) == _own_host(url), url
    for url in _OFF_BOX_URLS:
        assert _dialled(opener, url) == _PROXY_HOST, url  # CONTROL: the proxy is still in use


#: One builder per opener family, each called after the environment is set. urllib reads the
#: environment when an opener is built, and the shared module-level openers are built by these same
#: functions at import.
_FAMILIES: dict[str, Callable[[], urllib.request.OpenerDirector]] = {
    "bare": build_strict_opener,
    "http-family-shared": rest._no_redirect_opener,
    "http-family-verify-off": rest._insecure_opener,
    "http-family-expiry-relaxed": lambda: rest._expiry_relaxed_opener("partner.invalid"),
    "alert-webhook": alert_sinks._build_no_redirect_opener,
    "oidc": lambda: build_idp_opener(None),
}


@pytest.mark.parametrize("family", list(_FAMILIES))
@pytest.mark.parametrize("url", _LOOPBACK_URLS)
def test_a_loopback_hop_is_dialled_direct_under_an_environment_proxy(
    environment_proxy: None, family: str, url: str
) -> None:
    assert _dialled(_FAMILIES[family](), url) == _own_host(url)


@pytest.mark.parametrize("family", list(_FAMILIES))
@pytest.mark.parametrize("url", _OFF_BOX_URLS)
def test_an_off_box_hop_still_goes_through_the_environment_proxy(
    environment_proxy: None, family: str, url: str
) -> None:
    """CONTROL for the test above, on the same openers: the rule removes the proxy from a loopback
    hop only. A name that merely starts or ends like a loopback one is off-box."""
    assert _dialled(_FAMILIES[family](), url) == _PROXY_HOST


def test_a_configured_proxy_is_bypassed_for_a_loopback_hop() -> None:
    """A proxy the operator named is held to the same rule as one read from the environment."""
    _assert_only_loopback_goes_direct(
        build_strict_opener(urllib.request.ProxyHandler(_BOTH_SCHEMES))
    )


def test_the_proxy_handler_class_is_held_to_the_rule_too(environment_proxy: None) -> None:
    """``build_opener`` takes a handler class as well as an instance, and would build the stock one."""
    _assert_only_loopback_goes_direct(build_strict_opener(urllib.request.ProxyHandler))


def test_an_empty_proxy_map_means_no_proxy_at_all(environment_proxy: None) -> None:
    """How a caller asks for a hop that never uses a proxy: the supplied handler replaces the one
    that would have read the environment."""
    opener = build_strict_opener(urllib.request.ProxyHandler({}))
    assert _dialled(opener, "http://partner.invalid/x") == "partner.invalid"
    assert _dialled(opener, "http://127.0.0.1:18080/x") == "127.0.0.1:18080"


def test_a_proxy_map_that_is_not_a_dict_is_taken_over() -> None:
    """urllib's handler keeps whatever mapping it was given, so the replacement must read any."""
    proxies = types.MappingProxyType(_BOTH_SCHEMES)
    _assert_only_loopback_goes_direct(
        build_strict_opener(urllib.request.ProxyHandler(proxies))  # type: ignore[arg-type]
    )


def test_another_proxy_handler_type_is_refused() -> None:
    """A subclass could route a loopback hop by its own rule, so the opener is not built."""

    class _OwnRule(urllib.request.ProxyHandler):
        pass

    for handler in (_OwnRule({"http": _PROXY}), _OwnRule):
        with pytest.raises(TypeError, match="loopback"):
            build_strict_opener(handler)


def _is_http(url: str) -> bool:
    return url.startswith("http://")


@pytest.mark.parametrize(
    ("url", "on_box"),
    [(url, True) for url in filter(_is_http, _LOOPBACK_URLS)]
    + [(url, False) for url in filter(_is_http, _OFF_BOX_URLS)],
)
def test_the_rule_reads_a_host_exactly_as_the_cleartext_guard_does(
    environment_proxy: None, url: str, on_box: bool
) -> None:
    """One predicate, not two. A host the guard lets cross in cleartext as on-box is dialled direct,
    and a host the guard refuses is left to the proxy. If the two readings ever drift apart, a hop
    the guard calls on-box could reach a proxy again."""
    with active_hop_posture(HopPosture(enforcing=True)):
        if on_box:
            assert rest.refuse_cleartext_egress("http", url, connection="OB") is None
        else:
            with pytest.raises(InsecureHopRefused):
                rest.refuse_cleartext_egress("http", url, connection="OB")
    expected = _own_host(url) if on_box else _PROXY_HOST
    assert _dialled(build_strict_opener(), url) == expected


def test_a_url_with_no_host_is_not_counted_as_on_box() -> None:
    """The shared predicate reads an empty host as loopback, and the guard refuses a URL with no
    host before it asks. This rule takes the guard's side: nothing unreadable goes direct."""
    assert is_never_proxied_host("127.0.0.1")
    assert not is_never_proxied_host("")
    assert not is_never_proxied_host(None)


# --- the system proxy ----------------------------------------------------------------------------


@pytest.mark.skipif(sys.platform != "win32", reason="urllib reads the registry proxy on Windows")
def test_the_windows_system_proxy_is_bypassed_for_a_loopback_hop(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """With no proxy variable set, urllib on Windows falls back to the Internet Settings proxy. Its
    override list is pinned empty by the fixture, so the bypass seen is this rule's own."""
    monkeypatch.setattr(urllib.request, "getproxies_registry", lambda: dict(_BOTH_SCHEMES))
    _assert_only_loopback_goes_direct(build_strict_opener())


def test_a_system_proxy_from_any_source_is_bypassed_for_a_loopback_hop(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The same, on every platform: whatever ``getproxies`` reads from, the rule is applied after."""
    monkeypatch.setattr(urllib.request, "getproxies", lambda: dict(_BOTH_SCHEMES))
    monkeypatch.setattr(urllib.request, "proxy_bypass", lambda host: False)
    _assert_only_loopback_goes_direct(build_strict_opener())


# --- the ECH sidecar hop -------------------------------------------------------------------------

_SIDECAR = "http://127.0.0.1:8123"


def _rest(url: str, **extra: object) -> RestDestination:
    settings = Rest(url=url).settings
    settings.update(extra)
    dest = build_destination(
        Destination(name="OB_REST", type=ConnectorType.REST, settings=settings)
    )
    assert isinstance(dest, RestDestination)
    return dest


def test_the_ech_sidecar_opener_uses_no_proxy(environment_proxy: None) -> None:
    """The sidecar is this connection's whole egress route, so its opener carries no proxy at all.
    The off-box URL is what tells "no proxy" apart from the loopback rule alone."""
    dest = _rest("https://partner.invalid/ingest", ech_egress=True, ech_sidecar=_SIDECAR)
    request = dest._ech_request(b"synthetic", {}, "POST")
    assert _dialled(dest._opener, request.full_url) == "127.0.0.1:8123"
    assert _dialled(dest._opener, "http://partner.invalid/x") == "partner.invalid"


@pytest.mark.parametrize("host", ["127.0.0.1", "127.9.9.9", "localhost", "[::1]"])
def test_the_ech_token_hop_reaches_the_sidecar_direct(environment_proxy: None, host: str) -> None:
    """The token endpoint call is re-addressed to the same sidecar, on the opener the token
    providers share, which does read the environment. The loopback rule keeps that hop off the
    proxy, for every sidecar address the settings accept."""
    sidecar = rest.ech_sidecar_url_from_settings(
        {"ech_egress": True, "ech_sidecar": f"http://{host}:8123"}
    )
    assert sidecar is not None
    request = rest.ech_readdressed_request(
        sidecar, "https://auth.partner.invalid/token", data=b"synthetic", headers={}, method="POST"
    )
    assert _dialled(rest._no_redirect_opener(), request.full_url) == f"{host}:8123"


@pytest.mark.parametrize(
    "host", ["127.partner.invalid", "127.0.0.1.partner.invalid", "127.1", "ech.partner.invalid"]
)
def test_a_sidecar_the_loopback_rule_would_not_cover_is_refused(host: str) -> None:
    """The sidecar address is read by the same predicate. So no address is accepted as a sidecar
    and then left to the proxy on the token hop. The first three merely start like a loopback
    address."""
    with pytest.raises(ValueError, match="loopback"):
        rest.ech_sidecar_url_from_settings(
            {"ech_egress": True, "ech_sidecar": f"http://{host}:8123"}
        )


# --- a per-connection proxy and a loopback destination -------------------------------------------


#: The fixed text of the record a skipped proxy leaves.
_SKIPPED = "the configured web proxy is not used for a loopback target"


def _skip_records(caplog: pytest.LogCaptureFixture) -> list[logging.LogRecord]:
    return [r for r in caplog.records if _SKIPPED in r.getMessage()]


def test_a_loopback_destination_gets_no_proxy_handler_and_no_proxy_credential(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """A per-connection proxy resolved for a loopback target is no proxy: the shared opener, and no
    ``Proxy-Authorization`` header, which would otherwise be sent to the destination itself. The
    operator's proxy setting is inert for that host, so the log says so."""
    settings = {"proxy_url": "http://127.0.0.1:3128", "proxy_user": "pu", "proxy_password": "pw"}
    with caplog.at_level(logging.INFO, logger=rest.__name__):
        dest = _rest("http://127.0.0.1:18080/x", **settings)
    assert dest._opener is rest._NO_REDIRECT_OPENER
    assert "Proxy-Authorization" not in dest._headers
    assert [r.getMessage() for r in _skip_records(caplog)] == [
        "connection 'OB_REST'; the configured web proxy is not used for a loopback target, "
        "because a loopback hop is always dialled direct"
    ]
    # CONTROL: the same proxy settings on an off-box destination carry both, and log no skip.
    caplog.clear()
    with caplog.at_level(logging.INFO, logger=rest.__name__):
        control = _rest("https://partner.invalid/x", **settings)
    assert control._opener is not rest._NO_REDIRECT_OPENER
    assert control._headers["Proxy-Authorization"].startswith("Basic ")
    assert not _skip_records(caplog)


@pytest.mark.parametrize(
    "settings",
    [
        {
            "proxy_url": "http://127.0.0.1:3128",
            "proxy_user": "user-marker",
            "proxy_password": "secret-marker",
        },
        {"proxy_url": "http://user-marker:secret-marker@127.0.0.1:3128"},
    ],
    ids=["credential-in-settings", "credential-in-proxy-url"],
)
def test_the_skipped_proxy_record_carries_nothing_from_a_url_or_a_credential(
    caplog: pytest.LogCaptureFixture, settings: dict[str, object]
) -> None:
    """The record names the connection and states the fact. It holds no part of the proxy URL, no
    credential, and no part of the destination URL. Read on the record itself, arguments
    included, so a value that a formatter would drop is still seen."""
    with caplog.at_level(logging.INFO, logger=rest.__name__):
        _rest("http://localhost:18080/x", **settings)
    records = _skip_records(caplog)
    assert len(records) == 1  # CONTROL: the record is emitted
    record = records[0]
    assert record.args == ("'OB_REST'",)
    text = f"{record.getMessage()} {record.msg!r} {record.args!r}"
    for withheld in ("user-marker", "secret-marker", "3128", "127.0.0.1", "localhost", "18080"):
        assert withheld not in text, withheld


def test_the_public_bypass_predicate_agrees_with_the_transport() -> None:
    """The static-credential report asks this function whether a proxy is ever dialled."""
    assert rest.proxy_bypasses_host("127.0.0.1", None)
    assert rest.proxy_bypasses_host("localhost", ["intranet.invalid"])
    assert rest.proxy_bypasses_host("::1", None)
    # A bracketed literal and a port are read too, alone and together. Nothing else is trimmed.
    assert rest.proxy_bypasses_host("[::1]", None)
    assert rest.proxy_bypasses_host("127.0.0.1:8080", None)
    assert rest.proxy_bypasses_host("[::1]:8080", None)
    assert not rest.proxy_bypasses_host("partner.invalid:8080", None)
    assert not rest.proxy_bypasses_host("[2001:db8::1]:8080", None)
    assert not rest.proxy_bypasses_host("localhost ", None)
    assert not rest.proxy_bypasses_host("partner.invalid", None)
    assert not rest.proxy_bypasses_host("", None)
    assert not rest.proxy_bypasses_host(None, None)


def test_the_static_credential_report_lists_no_proxy_hop_for_a_loopback_target() -> None:
    """The report follows the transport: a proxy credential the engine never sends is not a hop."""
    from messagefoundry.config.static_credentials import _proxy_hop

    settings = {
        "proxy_url": "http://proxy.partner.invalid:3128",
        "proxy_user": "pu",
        "proxy_password": "pw",
    }
    assert _proxy_hop("OB", settings, None, targets=["http://127.0.0.1:18080/x"]) is None
    # CONTROL: one off-box target among them, and the hop is reported.
    hop = _proxy_hop(
        "OB", settings, None, targets=["http://127.0.0.1:18080/x", "https://partner.invalid/x"]
    )
    assert hop is not None and hop.name == "proxy:OB"
