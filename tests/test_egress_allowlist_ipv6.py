# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The shared ``host`` / ``host:port`` allowlist matcher reads bracketed IPv6 entries and compares
IP literals by their canonical form (BACKLOG #5915).

The shipped matcher split every entry at its first colon and compared lowercased host text, so
``[::1]:8123`` (the form docs/CONFIGURATION.md documents) and every other IPv6 entry matched
nothing, and ``0:0:0:0:0:0:0:1`` did not match ``[::1]``. It is a security matcher, so the change
is canonical equivalence only: each case under "never equated" stays a refusal.

Every case runs through both users of the one parse: the egress gate's ``host_port_allowed`` and
the AI broker's ``endpoint_host_allowed``, so the two cannot drift.
"""

from __future__ import annotations

from collections.abc import Callable

import pytest

from messagefoundry.config.models import ConnectorType, Destination
from messagefoundry.config.settings import EgressSettings
from messagefoundry.config.wiring import Database, WiringError
from messagefoundry.transports.ai_broker import endpoint_host_allowed
from messagefoundry.transports.egress import check_egress_allowed, host_port_allowed

Match = Callable[[str, int | None, list[str]], bool]


def _egress(host: str, port: int | None, allowed: list[str]) -> bool:
    return host_port_allowed(host, port, allowed)


def _broker(host: str, port: int | None, allowed: list[str]) -> bool:
    literal = f"[{host}]" if ":" in host else host
    netloc = literal if port is None else f"{literal}:{port}"
    return endpoint_host_allowed(f"https://{netloc}/v1/messages", allowed)


@pytest.fixture(params=[_egress, _broker], ids=["egress", "ai-broker"])
def match(request: pytest.FixtureRequest) -> Match:
    fn: Match = request.param
    return fn


# --- the contract the docs state, which the shipped code broke ----------------------------------


@pytest.mark.parametrize(
    ("host", "port", "entry"),
    [
        ("::1", 8123, "[::1]:8123"),
        ("::1", 8123, "[::1]"),
        ("::1", 6432, " [::1]:6432 "),
        ("fe80::1", 443, "[FE80::1]:443"),
        ("::1", 8123, "[0:0:0:0:0:0:0:1]:8123"),
        ("2001:db8::1", 443, "[2001:0DB8:0000::0001]"),
        ("db.example.org", 5432, "DB.Example.Org:5432"),
        ("127.0.0.1", 6514, "127.0.0.1"),
    ],
)
def test_canonically_equal_entry_matches(match: Match, host: str, port: int, entry: str) -> None:
    assert match(host, port, [entry]) is True


def test_bracketed_entry_still_pins_its_port(match: Match) -> None:
    assert match("::1", 9000, ["[::1]:8123"]) is False


def test_the_shipped_first_colon_split_no_longer_matches() -> None:
    # The old parse read `[` as the host of `[::1]:8123` and `:1]:8123` as its port, so it admitted
    # a host spelled `[` on any port the entry's text did not name. Egress only: no URL has that host.
    assert host_port_allowed("[", ":1]:8123", ["[::1]:8123"]) is False
    assert host_port_allowed("[", None, ["[::1]"]) is False


# --- ambiguous entries match nothing ------------------------------------------------------------


@pytest.mark.parametrize("entry", ["::1", "fe80::1:443", "0:0:0:0:0:0:0:1", "2001:db8::1"])
def test_unbracketed_ipv6_entry_matches_nothing(match: Match, entry: str) -> None:
    # Is `fe80::1:443` the host fe80::1 on port 443, or the host fe80::1:443 on any port? It is not
    # guessed: the last group is never read as a port, and the entry is not read as host-only.
    for host, port in (("::1", 443), ("fe80::1", 443), ("fe80::1:443", 443), ("2001:db8::1", 1)):
        assert match(host, port, [entry]) is False


@pytest.mark.parametrize(
    "entry", ["[::1", "[::1]x", "[::1]8123", "[db.example.org]", "[127.0.0.1]", "[]", ":443", ""]
)
def test_malformed_entry_matches_nothing(match: Match, entry: str) -> None:
    for host in ("::1", "127.0.0.1", "db.example.org"):
        assert match(host, 443, [entry]) is False


# --- never equated: each is a different host as far as this matcher is concerned ----------------


@pytest.mark.parametrize(
    ("host", "entry"),
    [
        ("::ffff:127.0.0.1", "127.0.0.1"),  # IPv4-mapped IPv6 is not plain IPv4
        ("::ffff:7f00:1", "127.0.0.1"),
        ("127.0.0.1", "[::ffff:127.0.0.1]"),
        ("db.example.org.", "db.example.org"),  # a trailing dot is not the dotless name
        ("db.example.org", "db.example.org."),
        ("127.1", "127.0.0.1"),  # shorthand IPv4 is not the dotted quad
        ("127.0.0.1", "127.1"),
        ("2130706433", "127.0.0.1"),
    ],
)
def test_non_canonical_neighbours_do_not_match(match: Match, host: str, entry: str) -> None:
    assert match(host, 443, [entry]) is False


@pytest.mark.parametrize("entry", ["[fe80::1%eth0]", "[fe80::1%25eth0]:443", "[fe80::1%1]"])
def test_zone_id_in_an_entry_matches_nothing(match: Match, entry: str) -> None:
    assert match("fe80::1", 443, [entry]) is False


def test_zone_id_in_the_host_matches_nothing() -> None:
    # ipaddress parses `fe80::1%eth0` with a scope id; the matcher refuses it rather than drop it.
    assert host_port_allowed("fe80::1%eth0", 443, ["[fe80::1]"]) is False
    assert endpoint_host_allowed("https://[fe80::1%25eth0]:443/x", ["[fe80::1]"]) is False


# --- the DATABASE arm reads the same parse ------------------------------------------------------


def _check_db(server: str, entry: str) -> None:
    settings = Database(
        statement="INSERT INTO t (a) VALUES (:a)",
        dialect="generic",
        odbc_driver="PostgreSQL Unicode",
        server=server,
        odbc_params={"PORT": "6432"},
    ).settings
    dest = Destination(name="OB_DB_V6", type=ConnectorType.DATABASE, settings=settings)
    check_egress_allowed(dest, EgressSettings(allowed_db=[entry]))


@pytest.mark.parametrize("server", ["::1", "0:0:0:0:0:0:0:1", "[::1]"])
@pytest.mark.parametrize("entry", ["[::1]:6432", "[::1]"])
def test_database_ipv6_server_matches_its_bracketed_entry(server: str, entry: str) -> None:
    _check_db(server, entry)


def test_database_ipv6_server_off_the_pin_is_refused() -> None:
    with pytest.raises(WiringError, match="at port 6432"):
        _check_db("::1", "[::1]:5432")


def test_database_ipv6_server_against_an_unbracketed_entry_is_unlisted() -> None:
    with pytest.raises(WiringError, match=r"is not in the \[egress\]\.allowed_db allowlist$"):
        _check_db("::1", "::1")
