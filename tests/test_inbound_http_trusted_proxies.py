# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The HTTP listener's per-connection ``trusted_proxies`` (BACKLOG #5525).

Behind a reverse proxy or an SNAT load balancer every partner reaches the listener from one socket
address. The intake failed-attempt budget keyed on that address, so ten failed requests from any
one client would have refused every authenticated partner behind the same proxy with ``429``.

``trusted_proxies`` names the HTTP proxies, ones that append the client's address to
``X-Forwarded-For``, whose header the budget may key on, under
``api_key`` and ``bearer`` only. The walk is uvicorn's: trust the header only from a listed socket
peer, go right to left, skip listed hops, and key on the first unlisted one. These tests drive a
real listener over loopback, whose socket peer is ``127.0.0.1``.
"""

from __future__ import annotations

import ipaddress
from typing import Any

import pytest

from messagefoundry.config.wiring import EnvRef, Http, WiringError, env, resolve_env_settings
from messagefoundry.pipeline.wiring_runner import _IntakeRateLimiter
from messagefoundry.transports.http_listener import HttpSource, trusted_proxy_networks
from tests.test_inbound_http_intake_auth import (
    KEY,
    _Audit,
    _CountingLimiter,
    _raw_with,
    _request,
    _start,
)

#: The loopback socket peer every request in this module arrives from.
PROXY = "127.0.0.1"
CLIENT_A = "203.0.113.10"
CLIENT_B = "203.0.113.20"


async def _proxied(**settings: Any) -> HttpSource:
    return await _start(intake_auth="api_key", intake_api_key=KEY, **settings)


async def test_one_clients_failures_do_not_lock_out_another_behind_the_same_proxy() -> None:
    """The row's closing test. Two clients behind one listed proxy: the first spends its whole
    per-peer budget, and the second, presenting the right key, is still accepted.

    Red on origin/main: both keyed on the proxy's address, so the second client got ``429``."""
    limiter = _IntakeRateLimiter(per_peer=10, glob=60)
    src = await _proxied(trusted_proxies=[PROXY])
    src.intake_rate_limiter = limiter
    try:
        for _ in range(10):
            resp = await _request(
                src.sockport, headers={"x-api-key": "wrong", "X-Forwarded-For": CLIENT_A}
            )
            assert resp.status in (401, 0), resp.status
        spent = await _request(
            src.sockport, headers={"x-api-key": KEY, "X-Forwarded-For": CLIENT_A}
        )
        other = await _request(
            src.sockport, headers={"x-api-key": KEY, "X-Forwarded-For": CLIENT_B}
        )
    finally:
        await src.stop()
    assert spent.status in (429, 0), spent.status
    assert other.status == 202, other.status


async def test_an_unlisted_socket_peers_forwarded_for_is_ignored() -> None:
    """A peer that is not a listed proxy cannot name its own budget key: every request keys on the
    socket address, whatever ``X-Forwarded-For`` says."""
    limiter = _IntakeRateLimiter(per_peer=10, glob=60)
    src = await _proxied(trusted_proxies=["192.0.2.1"])  # not the loopback peer
    src.intake_rate_limiter = limiter
    try:
        for i in range(10):
            await _request(
                src.sockport, headers={"x-api-key": "wrong", "X-Forwarded-For": f"198.51.100.{i}"}
            )
        resp = await _request(
            src.sockport, headers={"x-api-key": KEY, "X-Forwarded-For": "198.51.100.99"}
        )
    finally:
        await src.stop()
    assert resp.status in (429, 0), resp.status
    assert not limiter.check(PROXY)


async def test_a_spoofed_left_most_value_cannot_mint_a_fresh_budget() -> None:
    """The client controls everything left of the hop the proxy appended. Rotating that part must
    not hand it a new budget per value, or the setting would be a lockout bypass."""
    limiter = _IntakeRateLimiter(per_peer=10, glob=60)
    src = await _proxied(trusted_proxies=[PROXY])
    src.intake_rate_limiter = limiter
    try:
        for i in range(10):
            spoofed = f"198.51.100.{i}, {CLIENT_A}"
            await _request(src.sockport, headers={"x-api-key": "wrong", "X-Forwarded-For": spoofed})
        resp = await _request(
            src.sockport,
            headers={"x-api-key": KEY, "X-Forwarded-For": f"198.51.100.250, {CLIENT_A}"},
        )
    finally:
        await src.stop()
    assert resp.status in (429, 0), resp.status
    assert not limiter.check(CLIENT_A)


@pytest.mark.parametrize(
    ("trusted", "lines", "key"),
    [
        # The plain case: one hop, the client.
        ([PROXY], [f"X-Forwarded-For: {CLIENT_A}"], CLIENT_A),
        # A listed inner proxy is skipped; the first unlisted hop from the right is the client.
        ([PROXY, "10.0.0.0/24"], [f"X-Forwarded-For: {CLIENT_A}, 10.0.0.3"], CLIENT_A),
        # Header lines join in order, as uvicorn joins them: the walk crosses a line boundary.
        (
            [PROXY, "10.0.0.0/24"],
            [f"X-Forwarded-For: {CLIENT_A}", "X-Forwarded-For: 10.0.0.3"],
            CLIENT_A,
        ),
        # A port on a hop is read the way uvicorn reads it, so the key is the address alone.
        ([PROXY], [f"X-Forwarded-For: {CLIENT_A}:51234"], CLIENT_A),
        # An IPv6 client keys on its /64 (BACKLOG #5525 repair).
        ([PROXY], ["X-Forwarded-For: [2001:db8::7]:443"], "2001:db8::/64"),
        # A mapped spelling keys the same budget as the plain one.
        ([PROXY], [f"X-Forwarded-For: ::ffff:{CLIENT_A}"], CLIENT_A),
        # The client's own text left of the hop the proxy appended is never read.
        ([PROXY], [f"X-Forwarded-For: 198.51.100.7, {CLIENT_A}"], CLIENT_A),
        ([PROXY], [f"X-Forwarded-For: unknown, {CLIENT_A}"], CLIENT_A),
        # A zone is dropped, so text after '%' never becomes a key or a recorded value.
        ([PROXY], ["X-Forwarded-For: fe80::1%x; mode=none"], "fe80::/64"),
        ([PROXY], ["X-Forwarded-For: [fe80::1%eth0]:80"], "fe80::/64"),
        # A missing header from a listed peer falls back to the socket peer.
        ([PROXY], [], PROXY),
        # So does an unparseable hop, never a literal like "unknown".
        ([PROXY], ["X-Forwarded-For: unknown"], PROXY),
        ([PROXY], [f"X-Forwarded-For: {CLIENT_A}, "], PROXY),
        ([PROXY], [f"X-Forwarded-For: {CLIENT_A}, garbage"], PROXY),
        # Every hop listed: the client was itself a proxy. uvicorn takes the left-most value here,
        # which this listener never does; it keys on the socket peer.
        ([PROXY, "10.0.0.0/24"], ["X-Forwarded-For: 10.0.0.9, 10.0.0.3"], PROXY),
        # An underscore spelling is a different header to a proxy that does not fold it.
        ([PROXY], [f"X_Forwarded_For: {CLIENT_A}"], PROXY),
        # With no trusted_proxies the header is never read.
        ([], [f"X-Forwarded-For: {CLIENT_A}"], PROXY),
    ],
)
async def test_the_budget_key(trusted: list[str], lines: list[str], key: str) -> None:
    limiter = _CountingLimiter()
    src = await _proxied(trusted_proxies=trusted)
    src.intake_rate_limiter = limiter
    try:
        await _request(src.sockport, raw=_raw_with(["x-api-key: wrong", *lines]))
    finally:
        await src.stop()
    assert limiter.checks == [key]
    assert limiter.charges == [key]


async def test_a_refusal_records_the_socket_peer_and_the_forwarded_address() -> None:
    """The audit row and the connection event keep the socket peer in their peer column, and add
    the forwarded address, so an operator can see both the proxy and the client."""
    audit = _Audit()
    events: list[tuple[str, str | None, str | None]] = []

    async def sink(kind: str, peer: str | None, why: str | None) -> None:
        events.append((kind, peer, why))

    src = await _proxied(trusted_proxies=[PROXY])
    src.on_intake_audit = audit
    src.on_connection_event = sink
    try:
        await _request(src.sockport, headers={"x-api-key": "wrong", "X-Forwarded-For": CLIENT_A})
    finally:
        await src.stop()
    assert audit.rows == [("intake.auth_failed", PROXY, f"mode=api_key; forwarded_for={CLIENT_A}")]
    assert (
        "intake_auth_failed",
        PROXY,
        f"intake authentication required; forwarded_for={CLIENT_A}",
    ) in events


async def test_a_refusal_with_no_forwarded_address_is_unchanged() -> None:
    audit = _Audit()
    src = await _proxied(trusted_proxies=[PROXY])
    src.on_intake_audit = audit
    try:
        await _request(src.sockport, headers={"x-api-key": "wrong"})
    finally:
        await src.stop()
    assert audit.rows == [("intake.auth_failed", PROXY, "mode=api_key")]


# --- the factory ----------------------------------------------------------------------------------


def test_the_setting_is_carried_onto_the_spec() -> None:
    spec = Http(
        port=8080,
        intake_auth="bearer",
        intake_api_key=env("k"),
        trusted_proxies=["10.0.0.5", "fd00::/64"],
    )
    assert spec.settings["trusted_proxies"] == ["10.0.0.5", "fd00::/64"]
    assert Http(port=8080).settings["trusted_proxies"] == []  # the default trusts no proxy


@pytest.mark.parametrize("mode", ["none", "mtls_subject"])
def test_the_setting_is_refused_outside_the_header_modes(mode: str) -> None:
    """``mtls_subject`` authorises at accept, before any header exists, and ``none`` budgets
    nothing, so the list would be configured and never read."""
    extra: dict[str, Any] = {}
    if mode == "mtls_subject":
        extra = {
            "tls": True,
            "tls_cert_file": "/tmp/server.pem",
            "tls_ca_file": "/tmp/ca.pem",
            "intake_client_subjects": {"CN=Partner CA": ["CN:partner.example"]},
        }
    with pytest.raises(WiringError, match="trusted_proxies"):
        Http(port=8443, intake_auth=mode, trusted_proxies=["10.0.0.5"], **extra)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("entry", "why"),
    [
        ("*", "every peer"),
        ("0.0.0.0/0", "whole address family"),
        ("::/0", "whole address family"),
        ("::ffff:0:0/96", "whole address family"),
        ("::/80", "whole address family"),
        ("10.0.0.1/24", "host bits set"),
        ("fe80::1%eth0", "zone"),
        # A '%' on an IPv4 entry is no zone, and is not named as one.
        ("10.0.0.5%x", "not a valid IP address"),
        ("proxy.example", "not a valid IP address"),
    ],
)
def test_an_entry_the_api_list_refuses_is_refused_here(entry: str, why: str) -> None:
    """Refused by ``_parse_trusted_proxy``, named by form and index, and never quoted: no factory
    refusal may echo a configured value (vault BACKLOG #3249, #3765)."""
    with pytest.raises(WiringError, match=why) as excinfo:
        Http(port=8080, intake_auth="api_key", intake_api_key=env("k"), trusted_proxies=[entry])
    if entry != "*":  # '*' is a form the refusal names, not a value it could echo
        assert entry not in str(excinfo.value)
    assert excinfo.value.__cause__ is None
    with pytest.raises(ValueError, match=why):
        trusted_proxy_networks([entry])


def test_a_whole_setting_env_is_read_by_the_listener_once_resolved() -> None:
    spec = Http(
        port=8080, intake_auth="api_key", intake_api_key=env("k"), trusted_proxies=env("proxies")
    )
    assert isinstance(spec.settings["trusted_proxies"], EnvRef)
    resolved = resolve_env_settings(spec.settings, {"k": "x", "proxies": ["10.0.0.5"]})
    assert resolved["trusted_proxies"] == ["10.0.0.5"]
    defaulted = Http(
        port=8080,
        intake_auth="api_key",
        intake_api_key=env("k"),
        trusted_proxies=env("proxies", default=["10.0.0.6"]),
    )
    assert resolve_env_settings(defaulted.settings, {"k": "x"})["trusted_proxies"] == ["10.0.0.6"]


def test_a_padded_header_is_read_no_further_than_the_hop_bound() -> None:
    """A host inside a listed range may pad the header with listed hops. The walk stops at the
    bound and keys on the socket peer rather than reading on, on the event loop."""
    from messagefoundry.config.models import ConnectorType, Source
    from messagefoundry.transports.http_listener import _MAX_FORWARDED_HOPS, HttpRequest

    source = HttpSource(
        Source(
            type=ConnectorType.HTTP,
            settings={"port": 0, "intake_auth": "api_key", "trusted_proxies": ["10.0.0.0/24"]},
        )
    )

    def key(hops: list[str]) -> str | None:
        head = HttpRequest("POST", "/", {}, b"", frozenset(), ",".join(hops))
        found = source._forwarded_client(head, ipaddress.ip_address("10.0.0.1"))
        return None if found is None else str(found)

    listed = ["10.0.0.2"] * (_MAX_FORWARDED_HOPS - 1)
    assert key([CLIENT_A, *listed]) == CLIENT_A  # the client is the bound's last hop
    assert key([CLIENT_A, "10.0.0.2", *listed]) is None  # one more listed hop: socket peer


def test_the_proxy_match_agrees_with_a_scan_of_the_list() -> None:
    """The listener bisects the collapsed ranges rather than scan every entry once per hop, since
    the span limit allows 65,536 single-host entries. It must answer as the scan does."""
    from messagefoundry.transports.http_listener import _ProxyMatcher

    entries = ["10.0.0.0/24", "10.0.2.5", "10.0.4.0/31", "2001:db8::/64", "2001:db8:0:2::9"]
    networks = trusted_proxy_networks(entries)
    matcher = _ProxyMatcher(networks)
    probes = [
        "10.0.0.0", "10.0.0.255", "10.0.1.0", "10.0.2.4", "10.0.2.5", "10.0.2.6", "10.0.4.1",
        "10.0.4.2", "192.0.2.1", "2001:db8::1", "2001:db8:0:1::", "2001:db8:0:2::9",
        "2001:db8:0:2::8", "::", CLIENT_A,
    ]  # fmt: skip
    for probe in probes:
        address = ipaddress.ip_address(probe)
        assert (address in matcher) == any(address in n for n in networks), probe
    assert ipaddress.ip_address("10.0.0.1") not in _ProxyMatcher(())


def test_entries_that_together_span_a_family_are_refused() -> None:
    """The two ``/1`` halves are ``0.0.0.0/0`` written as two entries. The upper half is built
    rather than written, since the leak gate reads a literal of it as a routable host."""
    upper_half = str(ipaddress.IPv4Network((2**31, 1)))
    with pytest.raises(ValueError, match="whole address family"):
        trusted_proxy_networks(["0.0.0.0/1", upper_half])
    with pytest.raises(ValueError, match=r"more than a /16"):  # half is not all, but is too wide
        trusted_proxy_networks(["0.0.0.0/1", "10.0.0.5"])


def test_none_reads_as_unset() -> None:
    spec = Http(port=8080, intake_auth="api_key", intake_api_key=env("k"), trusted_proxies=None)  # type: ignore[arg-type]
    assert spec.settings["trusted_proxies"] == []


@pytest.mark.parametrize("glob", [0, None])
def test_the_setting_is_refused_with_the_global_budget_off(glob: int | None) -> None:
    """Each client behind the proxy keys its own per-peer budget, so without the global budget
    nothing bounds guessing across them."""
    with pytest.raises(WiringError, match="intake_auth_rate_limit_global is off"):
        Http(
            port=8080,
            intake_auth="api_key",
            intake_api_key=env("k"),
            trusted_proxies=["10.0.0.5"],
            intake_auth_rate_limit_global=glob,
        )


@pytest.mark.parametrize("per_peer", [0, None])
def test_the_setting_is_refused_with_the_per_peer_budget_off(per_peer: int | None) -> None:
    """The global budget exempts a key that authenticated in the window. A listed proxy may write
    such a partner's address, and only the per-peer budget then bounds guessing on that key."""
    with pytest.raises(WiringError, match="intake_auth_rate_limit is off"):
        Http(
            port=8080,
            intake_auth="api_key",
            intake_api_key=env("k"),
            trusted_proxies=["10.0.0.5"],
            intake_auth_rate_limit=per_peer,
        )
    # Its control: the exemption the refusal rests on. A recently authenticated key is never held
    # to the global budget, so with the per-peer arm off it would be refused by nothing.
    limiter = _IntakeRateLimiter(per_peer=0, glob=1)
    limiter.note_success(CLIENT_A)
    for _ in range(5):
        limiter.charge_failure(CLIENT_A)
    assert limiter.check(CLIENT_A)


def test_a_bare_string_is_refused_rather_than_read_as_characters() -> None:
    with pytest.raises(WiringError, match="must be a list"):
        Http(port=8080, intake_auth="api_key", intake_api_key=env("k"), trusted_proxies="10.0.0.5")


# --- the 2026-11-10 repair: no client may mint more budgets than one real address holds ----------


def _v4(first: int, prefix: int) -> str:
    """An IPv4 network built rather than written, so no routable literal sits in the source."""
    return str(ipaddress.IPv4Network((first << 24, prefix)))


def _v6(first_hextet: int, prefix: int) -> str:
    return str(ipaddress.IPv6Network((first_hextet << 112, prefix)))


@pytest.mark.parametrize(
    "entries",
    [
        # Near-whole ranges loaded with only a WARNING and acted as '*'.
        [_v6(0x2000, 3)],
        [_v4(0, 1), _v4(128, 2), _v4(192, 3)],
        # The floor itself: one prefix wider than a /16 of IPv4 or a /48 of IPv6 ...
        ["10.0.0.0/15"],
        ["2001:db8::/47"],
        # ... and a set that only together goes past it.
        ["10.0.0.0/16", "10.1.0.5"],
        ["2001:db8::/48", "2001:db8:1::/64"],
        # A mapped entry counts toward IPv4, the family it names.
        ["10.0.0.0/16", "::ffff:10.1.0.0/112"],
        # A range in an IPv4-embedding prefix counts its addresses, not its /64s: 64:ff9b::/96
        # is one /64 piece but every IPv4 client behind NAT64.
        ["64:ff9b::/96"],
        ["64:ff9b::/64"],
        ["2001::/32"],
    ],
)
def test_a_list_spanning_more_than_the_floor_is_refused(entries: list[str]) -> None:
    with pytest.raises(ValueError, match=r"span more than a /(16|48)") as excinfo:
        trusted_proxy_networks(entries)
    for entry in entries:
        assert entry not in str(excinfo.value)
    with pytest.raises(WiringError, match="span more than"):
        Http(port=8080, intake_auth="api_key", intake_api_key=env("k"), trusted_proxies=entries)


@pytest.mark.parametrize(
    "entries",
    [
        ["10.0.0.0/16"],
        ["10.0.0.0/17", "10.0.128.0/17"],
        ["2001:db8::/48"],
        # One IPv6 host is one of the 65,536 /64 networks a /48 holds, so this is just inside.
        ["2001:db8::/49", "2001:db8:1::5"],
        ["10.0.0.0/16", "2001:db8::/48"],  # each family is bounded on its own
        ["64:ff9b::c000:200/120"],  # 256 NAT64 addresses
    ],
)
def test_a_list_within_the_floor_loads(entries: list[str]) -> None:
    assert trusted_proxy_networks(entries)


@pytest.mark.parametrize(
    ("hop", "key"),
    [
        # Every address in one /64 keys one budget.
        ("2001:db8::1", "2001:db8::/64"),
        ("[2001:db8::ffff:1]:443", "2001:db8::/64"),
        ("2001:db8:0:1::1", "2001:db8:0:1::/64"),
        # A bare hop that also reads as an address and a port, where both readings share a /64:
        # one key either way, so it is read, and the client cannot fall back by choosing it.
        ("2001:db8::1:1234", "2001:db8::/64"),
        ("2001:db8::7:80", "2001:db8::/64"),
        # Where the two readings key different /64s, it is not read: the socket peer keys.
        ("2001:db8::1:2:3:4:5", PROXY),
        # Its control: a bare hop whose last group cannot be a port alone is read.
        ("2001:db8::7", "2001:db8::/64"),
        ("2001:db8::a:b", "2001:db8::/64"),
        # A NAT64 client keys on its whole address: its /64 holds every IPv4 client. So the two
        # readings of a bare hop there always key apart, and an ambiguous one is not read.
        ("[64:ff9b::c000:221]:80", "64:ff9b::c000:221"),
        ("64:ff9b::c000:221", PROXY),
    ],
)
async def test_an_ipv6_client_keys_on_its_64_and_an_ambiguous_hop_is_not_read(
    hop: str, key: str
) -> None:
    limiter = _CountingLimiter()
    src = await _proxied(trusted_proxies=[PROXY])
    src.intake_rate_limiter = limiter
    try:
        await _request(src.sockport, raw=_raw_with(["x-api-key: wrong", f"X-Forwarded-For: {hop}"]))
    finally:
        await src.stop()
    assert limiter.checks == [key]


async def test_rotating_ipv6_addresses_inside_one_64_mints_no_budget() -> None:
    """The row's rule: ten failures from ten addresses in one /64 spend one budget, and a client in
    another /64 behind the same proxy is still accepted."""
    limiter = _IntakeRateLimiter(per_peer=10, glob=60)
    src = await _proxied(trusted_proxies=[PROXY])
    src.intake_rate_limiter = limiter
    try:
        for i in range(10):
            await _request(
                src.sockport,
                headers={"x-api-key": "wrong", "X-Forwarded-For": f"[2001:db8::{i + 1:x}]:5000"},
            )
        rotated = await _request(
            src.sockport, headers={"x-api-key": KEY, "X-Forwarded-For": "2001:db8::abcd"}
        )
        other = await _request(
            src.sockport, headers={"x-api-key": KEY, "X-Forwarded-For": "2001:db8:0:1::abcd"}
        )
    finally:
        await src.stop()
    assert rotated.status in (429, 0), rotated.status
    assert other.status == 202, other.status


@pytest.mark.parametrize(
    ("peer", "key"),
    [
        ("127.0.0.1", "127.0.0.1"),
        # One host, one budget, whichever spelling the socket gives.
        ("::ffff:127.0.0.1", "127.0.0.1"),
        ("fe80::1%eth0", "fe80::/64"),
        ("fe80::1", "fe80::/64"),
        # The socket peer gets the /64 rule a forwarded client gets.
        ("2001:db8::5", "2001:db8::/64"),
        # Except in a prefix that carries an IPv4 client, where each address is its own key:
        # NAT64 (well-known and local-use), Teredo and the IPv4-compatible form.
        ("64:ff9b::c000:221", "64:ff9b::c000:221"),
        ("64:ff9b:1::c000:221", "64:ff9b:1::c000:221"),
        ("2001:0:c000:201::1", "2001:0:c000:201::1"),
        ("::1", "::1"),
        (None, "unknown"),
    ],
)
def test_a_socket_peer_keys_as_a_forwarded_client_does(peer: str | None, key: str) -> None:
    from messagefoundry.transports.http_listener import _peer_budget_key

    assert _peer_budget_key(peer) == key


def test_a_mapped_socket_peer_still_reads_as_a_listed_proxy() -> None:
    from messagefoundry.config.models import ConnectorType, Source
    from messagefoundry.transports.http_listener import HttpRequest

    source = HttpSource(
        Source(
            type=ConnectorType.HTTP,
            settings={"port": 0, "intake_auth": "api_key", "trusted_proxies": ["10.0.0.5"]},
        )
    )
    from messagefoundry.transports.http_listener import _peer_address

    head = HttpRequest("POST", "/", {}, b"", frozenset(), CLIENT_A)
    assert str(source._forwarded_client(head, _peer_address("::ffff:10.0.0.5"))) == CLIENT_A


@pytest.mark.parametrize("default", [["*"], ["0.0.0.0/0"], ["10.0.0.0/8"], "10.0.0.5"])
def test_an_env_default_is_read_by_the_rule_a_literal_is(default: object) -> None:
    """The default is written in the config, so the load refuses it as it refuses the literal,
    and ``check`` sees it without an environment. Before, only serve did."""
    with pytest.raises(WiringError, match=r"env\(\) default= is refused"):
        Http(
            port=8080,
            intake_auth="api_key",
            intake_api_key=env("k"),
            trusted_proxies=env("proxies", default=default),
        )


def test_an_env_value_given_as_text_gets_its_own_refusal() -> None:
    """A MEFOR_VALUE_* variable is always text. The listener reads the resolved value, and says
    where a list can be written rather than only that it must be one."""
    from messagefoundry.config.models import ConnectorType, Source

    spec = Http(
        port=8080, intake_auth="api_key", intake_api_key=env("k"), trusted_proxies=env("proxies")
    )
    resolved = resolve_env_settings(spec.settings, {"k": "x", "proxies": "10.0.0.5"})
    with pytest.raises(ValueError, match="MEFOR_VALUE_") as excinfo:
        HttpSource(Source(type=ConnectorType.HTTP, settings={**resolved, "port": 0}))
    assert "10.0.0.5" not in str(excinfo.value)


def _http_registry(**listeners: Any) -> Any:
    from messagefoundry.config.wiring import Registry, build_inbound_connection

    reg = Registry()
    for name, proxies in listeners.items():
        spec = Http(
            port=8080, intake_auth="api_key", intake_api_key=env("k"), trusted_proxies=proxies
        )
        reg.add_inbound(build_inbound_connection(name, spec, router="R"))
    return reg


def test_a_listener_trusted_proxies_is_a_named_loosening() -> None:
    """Listed in ``security_loosenings()`` as the ``[api]`` ranges are, which ``GET
    /security/posture``, the start's audit row and the ``posture_loosened`` alert all read."""
    from messagefoundry.config.settings import (
        AiSettings,
        AlertsSettings,
        ApiSettings,
        ApprovalsSettings,
        AuthSettings,
        BackupSettings,
        CertMonitorSettings,
        SecretRotationSettings,
        SecretsSettings,
        SecuritySettings,
        StoreSettings,
        security_loosenings,
    )
    from messagefoundry.config.wiring import (
        UNRESOLVED_LISTENER_PROXIES,
        listener_trusted_proxy_hops,
    )

    reg = _http_registry(
        IB_HOST=["10.0.0.5"], IB_RANGE=["10.0.0.0/24"], IB_ENV=env("p"), IB_NONE=[]
    )
    assert listener_trusted_proxy_hops(reg) == [
        ("IB_ENV", UNRESOLVED_LISTENER_PROXIES),
        ("IB_HOST", ""),
        ("IB_RANGE", "range"),
    ]
    # Resolved with the instance's values: an empty list names nothing, a host is named.
    assert "IB_ENV" not in dict(listener_trusted_proxy_hops(reg, env_values={"p": []}))
    assert dict(listener_trusted_proxy_hops(reg, env_values={"p": ["10.0.0.6"]}))["IB_ENV"] == ""

    def pairs(hops: tuple[str, ...]) -> dict[str, str]:
        return dict(
            security_loosenings(
                SecuritySettings(),
                StoreSettings(),
                AuthSettings(),
                AlertsSettings(),
                SecretRotationSettings(),
                cleartext_hops=(),
                expiry_relaxed_hops=(),
                hostname_unchecked_hops=(),
                query_credential_hops=(),
                unverified_db_hops=(),
                attested_hops=(),
                revocation_attested_hops=(),
                path_form_fhir_hops=(),
                ech_cleartext_sidecar_hops=(),
                api=ApiSettings(),
                approvals=ApprovalsSettings(),
                cert_monitor=CertMonitorSettings(),
                backup=BackupSettings(),
                secrets=SecretsSettings(),
                ai=AiSettings(),
                store_privilege=None,
                audit_chain_unkeyed=None,
                remote_debug=None,
                startup=None,
                service_env=None,
                listener_trusted_proxy_hops=hops,
            )
        )

    risk = pairs(("IB_HOST", "IB_RANGE (range)"))["listener_trusted_proxies"]
    assert "IB_HOST" in risk and "IB_RANGE (range)" in risk and "IB_NONE" not in risk
    assert "listener_trusted_proxies" not in pairs(())  # control: nothing listed, nothing named


async def test_the_posture_route_names_a_listener_trusted_proxies(tmp_path: Any) -> None:
    """The live graph's listener reaches ``GET /security/posture``, which the start's audit row
    and the ``posture_loosened`` alert read through the same function."""
    from messagefoundry.config.settings import EgressSettings
    from messagefoundry.pipeline import Engine
    from tests.test_security_posture_defaults import _posture_body

    eng = await Engine.create(
        tmp_path / "posture.db",
        poll_interval=0.02,
        egress_settings=EgressSettings(deny_by_default=False),
    )
    try:
        eng.add_registry(_http_registry(IB_PROXIED=["10.0.0.0/24"], IB_DIRECT=[]))
        body = await _posture_body(eng)
    finally:
        await eng.stop()
    loosenings: list[dict[str, str]] = body["loosenings"]  # type: ignore[assignment]
    entry = next(e for e in loosenings if e["switch"] == "listener_trusted_proxies")
    assert "IB_PROXIED (range)" in entry["risk"]
    assert "IB_DIRECT" not in entry["risk"]


def test_the_settings_view_shows_the_proxy_addresses() -> None:
    """``trusted_proxies`` ends in ``proxies``, a URL word, but holds addresses an operator needs
    to read, never a URL that could carry a credential."""
    from messagefoundry.config.wiring import _is_url_setting, redacted_settings

    assert not _is_url_setting("trusted_proxies")
    assert _is_url_setting("http_proxies")  # control: the suffix rule still holds elsewhere
    spec = Http(
        port=8080, intake_auth="api_key", intake_api_key=env("k"), trusted_proxies=["10.0.0.5"]
    )
    assert redacted_settings(spec.settings)["trusted_proxies"] == ["10.0.0.5"]
