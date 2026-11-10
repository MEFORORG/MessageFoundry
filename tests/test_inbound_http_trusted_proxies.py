# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The HTTP listener's per-connection ``trusted_proxies`` (BACKLOG #5525).

Behind a reverse proxy or an SNAT load balancer every partner reaches the listener from one socket
address. The intake failed-attempt budget keyed on that address, so ten failed requests from any
one client would have refused every authenticated partner behind the same proxy with ``429``.

``trusted_proxies`` names the proxies whose ``X-Forwarded-For`` the budget may key on, under
``api_key`` and ``bearer`` only. The walk is uvicorn's: trust the header only from a listed socket
peer, go right to left, skip listed hops, and key on the first unlisted one. These tests drive a
real listener over loopback, whose socket peer is ``127.0.0.1``.
"""

from __future__ import annotations

from typing import Any

import pytest

from messagefoundry.config.wiring import Http, WiringError, env
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
    assert limiter.check("198.51.100.0")


@pytest.mark.parametrize(
    ("trusted", "lines", "key"),
    [
        # The plain case: one hop, the client.
        ([PROXY], [f"X-Forwarded-For: {CLIENT_A}"], CLIENT_A),
        # A listed inner proxy is skipped; the first unlisted hop from the right is the client.
        ([PROXY, "10.0.0.0/8"], [f"X-Forwarded-For: {CLIENT_A}, 10.1.2.3"], CLIENT_A),
        # Header lines join in order, as uvicorn joins them: the walk crosses a line boundary.
        (
            [PROXY, "10.0.0.0/8"],
            [f"X-Forwarded-For: {CLIENT_A}", "X-Forwarded-For: 10.1.2.3"],
            CLIENT_A,
        ),
        # A port on a hop is read the way uvicorn reads it, so the key is the address alone.
        ([PROXY], [f"X-Forwarded-For: {CLIENT_A}:51234"], CLIENT_A),
        ([PROXY], ["X-Forwarded-For: [2001:db8::7]:443"], "2001:db8::7"),
        # A mapped spelling keys the same budget as the plain one.
        ([PROXY], [f"X-Forwarded-For: ::ffff:{CLIENT_A}"], CLIENT_A),
        # A missing header from a listed peer falls back to the socket peer.
        ([PROXY], [], PROXY),
        # So does an unparseable hop, never a literal like "unknown".
        ([PROXY], ["X-Forwarded-For: unknown"], PROXY),
        ([PROXY], [f"X-Forwarded-For: {CLIENT_A}, "], PROXY),
        ([PROXY], [f"X-Forwarded-For: {CLIENT_A}, garbage"], PROXY),
        # Every hop listed: the client was itself a proxy. uvicorn takes the left-most value here,
        # which this listener never does; it keys on the socket peer.
        ([PROXY, "10.0.0.0/8"], ["X-Forwarded-For: 10.9.9.9, 10.1.2.3"], PROXY),
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
        ("*", "EVERY peer"),
        ("0.0.0.0/0", "whole address family"),
        ("::/0", "whole address family"),
        ("::ffff:0:0/96", "whole address family"),
        ("::/80", "whole address family"),
        ("10.0.0.1/24", "host bits set"),
        ("fe80::1%eth0", "zone"),
        ("proxy.example", "not a valid IP address"),
    ],
)
def test_an_entry_the_api_list_refuses_is_refused_here(entry: str, why: str) -> None:
    with pytest.raises(WiringError, match=why):
        Http(port=8080, intake_auth="api_key", intake_api_key=env("k"), trusted_proxies=[entry])
    with pytest.raises(ValueError, match=why):
        trusted_proxy_networks([entry])


def test_a_bare_string_is_refused_rather_than_read_as_characters() -> None:
    with pytest.raises(WiringError, match="must be a list"):
        Http(port=8080, intake_auth="api_key", intake_api_key=env("k"), trusted_proxies="10.0.0.5")
