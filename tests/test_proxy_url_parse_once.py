# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A ``proxy_url`` is parsed once, for the allow-list gate and for the dial (vault BACKLOG #2965).

``[egress].allowed_proxy`` judged the host ``urllib.parse.urlsplit`` reads, while urllib's proxy
handler dials the host its ``_parse_proxy`` reads. On a value whose path, query or fragment holds
an ``@`` and a second host, the two differ: the gate passed the listed host and urllib dialled the
other one, with any ``Proxy-Authorization`` the connection sends.

These tests hold both halves. The gate refuses such a value at load, on the outbound arm and on
the ``fhir_lookup`` read arm, and the connector build refuses it too, so no opener exists that
could dial the unlisted host. A plain ``host:port`` proxy is the control: it passes, and is the
host dialled. Nothing here touches the network: ``http.client.HTTPConnection.connect`` is replaced
by a recorder that refuses every connection.

The split shapes are written only in this file, on purpose; the ledger describes them in words.
"""

from __future__ import annotations

import http.client
import random
import urllib.parse
import urllib.request
from collections.abc import Iterator, Mapping
from typing import Any

import pytest

from messagefoundry.config.models import ConnectorType, Destination
from messagefoundry.config.settings import EgressSettings
from messagefoundry.config.tls_policy import HopPosture, active_hop_posture
from messagefoundry.config.wiring import WiringError
from messagefoundry.transports.bounded_read import build_strict_opener
from messagefoundry.transports.egress import check_egress_allowed, check_fhir_lookup_allowed
from messagefoundry.transports.proxy_address import parse_proxy_url, read_like_urllib
from messagefoundry.transports.rest import proxy_config_from_settings

LISTED = "proxy.listed.invalid"
UNLISTED = "other.unlisted.invalid"
DEST = "http://api.partner.invalid/x"  # off-box, so the proxy carries it (vault BACKLOG #2579)
EGRESS = EgressSettings(allowed_http=["api.partner.invalid"], allowed_proxy=[LISTED])

#: Values on which urlsplit reads LISTED and urllib's proxy parser reads UNLISTED, or some other
#: text, as the host to dial. The first is the one urllib dialled with no send-time refusal.
SPLIT_SHAPES = [
    f"http://{LISTED}/x@{UNLISTED}:8080",
    f"http://{LISTED}:3128/x@{UNLISTED}:8080",
    f"https://{LISTED}/x@{UNLISTED}:8080",
    f"https://{LISTED}:3128/x@{UNLISTED}:8080",
    f"http://{LISTED}:3128?x@{UNLISTED}:8080",
    f"https://{LISTED}:3128?x@{UNLISTED}:8080",
    f"http://{LISTED}:3128#x@{UNLISTED}:8080",
    f"https://{LISTED}#x@{UNLISTED}:8080",
    f"http://u:p@{LISTED}:3128/x@{UNLISTED}:8080",
]

PLAIN = f"http://{LISTED}:3128"


@pytest.fixture(autouse=True)
def _no_system_bypass(monkeypatch: pytest.MonkeyPatch) -> None:
    """Pin urllib's own bypass list off, as tests/test_outbound_forward_proxy.py does: on Windows
    it reads the registry's proxy override list, and an entry there would send these requests
    direct."""
    monkeypatch.setattr(urllib.request, "proxy_bypass", lambda host: False)


@pytest.fixture
def dials(monkeypatch: pytest.MonkeyPatch) -> Iterator[list[tuple[str, int]]]:
    """Every ``(host, port)`` an opener tries to connect to. Each connection is refused."""
    seen: list[tuple[str, int]] = []

    def record(self: http.client.HTTPConnection) -> None:
        seen.append((self.host, self.port))
        raise OSError("no network in this test")

    monkeypatch.setattr(http.client.HTTPConnection, "connect", record)
    yield seen


def _rest(proxy_url: str, **extra: str) -> Destination:
    return Destination(
        name="OB", type=ConnectorType.REST, settings={"url": DEST, "proxy_url": proxy_url, **extra}
    )


def _open_through(settings: Mapping[str, Any]) -> bool:
    """Build the connection's proxy opener as the transport does and send one request.

    Returns ``False`` when the build refuses the settings for the split, or for a user and
    password written in the URL (vault BACKLOG #3007), so nothing could be dialled. Any other
    refusal is raised, so a credential refused for its cleartext leg cannot pass for this one.
    The leg declares the cleartext acceptance with a reason, the one declaration that admits a
    proxy login off this machine (B462-R1), so the login is admitted as a deployment's would be."""
    with active_hop_posture(HopPosture(enforcing=False)):
        try:
            config = proxy_config_from_settings(
                settings,
                dest_scheme="http",
                cleartext_accepted=True,
                cleartext_reason="test proxy leg on a lab segment",
                connection="OB",
            )
        except ValueError as exc:
            if "2965" not in str(exc) and "holds a user and a password" not in str(exc):
                raise
            return False
    assert config is not None
    route = config.for_host(DEST)
    assert route is not None
    opener = build_strict_opener(*route.opener_handlers())
    req = urllib.request.Request(DEST, headers=route.auth_headers())  # noqa: S310
    with pytest.raises(OSError):
        opener.open(req, timeout=1)
    return True


def _assert_names_no_part(message: str) -> None:
    for part in (UNLISTED, "x@", "u:p"):
        assert part not in message, message


@pytest.mark.parametrize("proxy_url", SPLIT_SHAPES)
def test_the_gate_refuses_a_split_value_at_load(proxy_url: str) -> None:
    with pytest.raises(WiringError) as outbound:
        check_egress_allowed(_rest(proxy_url), EGRESS)
    _assert_names_no_part(str(outbound.value))
    assert "2965" in str(outbound.value)  # refused for the split, not as an allow-list miss
    with pytest.raises(WiringError) as lookup:
        check_fhir_lookup_allowed(
            "lk", {"url": "https://api.partner.invalid/fhir", "proxy_url": proxy_url}, EGRESS
        )
    _assert_names_no_part(str(lookup.value))
    assert "2965" in str(lookup.value)


@pytest.mark.parametrize("proxy_url", SPLIT_SHAPES)
@pytest.mark.parametrize("credential", [False, True])
def test_no_split_value_is_dialled_anywhere(
    proxy_url: str, credential: bool, dials: list[tuple[str, int]]
) -> None:
    """The dial half: the build refuses, so no connection is tried, to either host. With a
    ``proxy_user``/``proxy_password`` too, which before this change rode to the dialled host on an
    admitted ``Proxy-Authorization`` header."""
    settings: dict[str, str] = {"url": DEST, "proxy_url": proxy_url}
    if credential:
        settings |= {"proxy_user": "pu", "proxy_password": "pp"}
    built = _open_through(settings)
    assert all(host == LISTED for host, _ in dials), dials
    assert not built and dials == []


@pytest.mark.parametrize("proxy_url", SPLIT_SHAPES)
def test_the_build_refusal_names_no_part_of_the_value(proxy_url: str) -> None:
    with pytest.raises(ValueError) as refused:
        proxy_config_from_settings({"proxy_url": proxy_url}, dest_scheme="http", connection="OB")
    _assert_names_no_part(str(refused.value))
    assert refused.value.__cause__ is None and refused.value.__context__ is None


def test_a_plain_proxy_passes_and_is_the_host_dialled(dials: list[tuple[str, int]]) -> None:
    """The control: a plain ``host:port`` passes the gate on both arms and is dialled."""
    check_egress_allowed(_rest(PLAIN), EGRESS)
    check_fhir_lookup_allowed(
        "lk", {"url": "https://api.partner.invalid/fhir", "proxy_url": PLAIN}, EGRESS
    )
    assert _open_through(
        {"url": DEST, "proxy_url": PLAIN, "proxy_user": "pu", "proxy_password": "pp"}
    )
    assert dials == [(LISTED, 3128)]


def test_a_scheme_other_than_http_is_refused_at_the_gate_by_its_scheme() -> None:
    with pytest.raises(WiringError, match="must be 'default' or an http") as refused:
        check_egress_allowed(_rest(f"socks5://{LISTED}:1080"), EGRESS)
    assert LISTED not in str(refused.value)


def test_an_unlisted_plain_proxy_is_still_an_allow_list_miss() -> None:
    with pytest.raises(WiringError, match="is not in the \\[egress\\].allowed_proxy allowlist"):
        check_egress_allowed(_rest(f"http://{UNLISTED}:3128"), EGRESS)


def test_a_trailing_slash_is_accepted_and_dropped(dials: list[tuple[str, int]]) -> None:
    check_egress_allowed(_rest(PLAIN + "/"), EGRESS)
    config = proxy_config_from_settings(
        {"proxy_url": PLAIN + "/"}, dest_scheme="http", connection="OB"
    )
    assert config is not None and dict(config.proxies) == {"http": PLAIN, "https": PLAIN}
    assert _open_through({"url": DEST, "proxy_url": PLAIN + "/"})
    assert dials == [(LISTED, 3128)]


def test_userinfo_is_kept_in_the_rebuilt_url() -> None:
    """The parse keeps a userinfo, escapes and all, so urllib reads the same user and password
    from the rebuilt URL. A user and password there then fail the connector build for their own
    reason (vault BACKLOG #3007), so the build is asserted to refuse, not to dial."""
    proxy = f"https://us%40er:p%2Fw@{LISTED}:3128/"
    rebuilt = parse_proxy_url(proxy).url
    assert rebuilt == proxy.rstrip("/")
    assert read_like_urllib(rebuilt)[1:] == read_like_urllib(proxy)[1:]
    with (
        active_hop_posture(HopPosture(enforcing=False)),
        pytest.raises(ValueError, match="holds a user and a password"),
    ):
        proxy_config_from_settings({"proxy_url": proxy}, dest_scheme="http", connection="OB")


def test_a_user_with_no_password_is_kept_in_the_url_the_connector_dials() -> None:
    """A user alone sends nothing, so it builds, and the rebuilt URL keeps it as written."""
    proxy = f"http://us%40er@{LISTED}:3128"
    with active_hop_posture(HopPosture(enforcing=False)):
        config = proxy_config_from_settings(
            {"proxy_url": proxy}, dest_scheme="http", connection="OB"
        )
    assert config is not None and dict(config.proxies)["http"] == proxy


@pytest.mark.parametrize(
    "proxy_url",
    [
        f"http://{LISTED}:3128/path",
        f"http://{LISTED}:3128?",
        f"http://{LISTED}:3128#",
        f"http://{LISTED}:",
        f"http://{LISTED}:0",
        f"http://{LISTED}:65536",
        f"http://{LISTED}:31a8",
        "http://pro%78y.listed.invalid:3128",
        "http://pro_xy.listed.invalid:3128",
        "http://pro\txy.listed.invalid:3128",
        "http://[fe80::1%25eth0]:3128",
        "http://[not-v6]:3128",
        "http://:3128",
        "http:/" + LISTED,
        "socks5://" + LISTED,
        "u:p@" + LISTED,
        "http://010.0.0.1:3128",  # octal to a resolver
        "http://2130706433:3128",  # a bare integer address
        "http://127.1:3128",  # fewer than four parts
        "http://0x7f.1:3128",  # a hex label
        f"http://{LISTED}:03128",  # a leading zero, which urllib keeps in the port it dials
        f"https://{LISTED}:0443",
    ],
)
def test_strict_shape_refusals(proxy_url: str) -> None:
    with pytest.raises(ValueError, match="2965"):
        parse_proxy_url(proxy_url)


@pytest.mark.parametrize(
    ("proxy_url", "hostname", "port"),
    [
        (PLAIN, LISTED, 3128),
        ("HTTPS://Proxy.Listed.Invalid./", "proxy.listed.invalid.", None),
        ("http://192.0.2.10:8080", "192.0.2.10", 8080),
        ("http://[2001:DB8::1]:3128", "2001:db8::1", 3128),
        (
            f"http://u:p@x@{LISTED}:3128",
            LISTED,
            3128,
        ),  # urllib and urlsplit both split at the last @
    ],
)
def test_accepted_shapes(proxy_url: str, hostname: str, port: int | None) -> None:
    address = parse_proxy_url(proxy_url)
    assert (address.hostname, address.port) == (hostname, port)
    assert "@" not in address.label_url


def _dialled_by_http_client(proxy: str) -> tuple[str, int]:
    """The host and port ``http.client`` would dial for ``proxy``, read as urllib's handler reads
    it: ``_parse_proxy``, then ``unquote``, then ``set_proxy`` hands the result to the connection.
    An ``https`` proxy is dialled through ``HTTPSConnection``, whose default port is 443."""
    scheme, _, _, hostport = read_like_urllib(proxy)
    connection = (
        http.client.HTTPSConnection
        if (scheme or "").lower() == "https"
        else http.client.HTTPConnection
    )
    conn = connection(urllib.parse.unquote(hostport))
    return conn.host, conn.port


def test_every_accepted_value_dials_the_host_it_is_judged_on() -> None:
    """A property over generated values: wherever the parse accepts one, the host and port the
    gate matches are the ones ``http.client`` would dial, for the value as written and for the
    rebuilt URL. Both counts are asserted, so a parse that accepted nothing, or everything, fails."""
    rng = random.Random(2965)
    pieces = ["a", "b", ".", ":", "/", "@", "?", "#", "%40", "%2F", "1", "[", "]", "::1", "-"]
    accepted = refused = 0
    for _ in range(20000):
        body = "".join(rng.choice(pieces) for _ in range(rng.randint(1, 12)))
        value = rng.choice(("http://", "https://")) + body
        try:
            address = parse_proxy_url(value)
        except ValueError:
            refused += 1
            continue
        accepted += 1
        default_port = 443 if address.scheme == "https" else 80
        expected = (address.hostname, address.port or default_port)
        for form in (value, address.url):
            host, port = _dialled_by_http_client(form)
            assert (host.lower(), port) == expected, value
    assert accepted > 100 and refused > 100, (accepted, refused)


def test_the_reader_is_the_parser_the_handler_runs(monkeypatch: pytest.MonkeyPatch) -> None:
    """``read_like_urllib`` stands in for urllib's private ``_parse_proxy``. This pins that the
    handler still calls that function, so the pairing the module relies on still holds."""
    calls: list[str] = []
    real = urllib.request._parse_proxy  # type: ignore[attr-defined]

    def spy(proxy: str) -> Any:
        calls.append(proxy)
        return real(proxy)

    monkeypatch.setattr(urllib.request, "_parse_proxy", spy)
    handler = urllib.request.ProxyHandler({"http": PLAIN})
    req = urllib.request.Request(DEST)  # noqa: S310
    handler.proxy_open(req, PLAIN, "http")
    assert calls == [PLAIN]
    assert req.host == f"{LISTED}:3128"
    assert read_like_urllib(PLAIN) == real(PLAIN)
    assert calls == [PLAIN, PLAIN]  # the reader went through the same function


def test_the_static_hop_label_names_the_dialled_host() -> None:
    """The static-credential hop names the host the connector dials. A split value is refused at
    build, so its label is withheld rather than naming the host only urlsplit reads."""
    from messagefoundry.config.static_credentials import _proxy_hop
    from messagefoundry.config.wiring import _WITHHELD_PEER

    keyed = {"proxy_user": "pu", "proxy_password": "pp"}
    plain = _proxy_hop("OB", {"proxy_url": PLAIN, **keyed}, None)
    assert plain is not None and f"{LISTED}:3128" in plain.detail
    for proxy_url in SPLIT_SHAPES:
        hop = _proxy_hop("OB", {"proxy_url": proxy_url, **keyed}, None)
        assert hop is not None and _WITHHELD_PEER in hop.detail, proxy_url
        _assert_names_no_part(hop.detail)


@pytest.mark.parametrize(
    "proxy_url",
    [
        # urlsplit deletes a tab, CR or LF anywhere in the URL, and urllib's proxy parser keeps
        # them, so the two read a different user or password from the same text. The host and
        # port agree, so only a userinfo comparison can refuse these.
        f"http://u\t:p@{LISTED}:3128",
        f"http://u:p\n@{LISTED}:3128",
        f"https://u\r:p@{LISTED}:3128/",
    ],
)
def test_a_userinfo_the_two_parsers_read_differently_is_refused(proxy_url: str) -> None:
    with pytest.raises(ValueError, match="2965"):
        parse_proxy_url(proxy_url)
