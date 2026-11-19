# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The shared ``host`` / ``host:port`` allowlist matcher reads bracketed IPv6 entries and compares
IP literals by their canonical form (BACKLOG #5915).

The shipped matcher split every entry at its first colon and compared lowercased host text, so
no IPv6 entry, ``[::1]:6432`` included, could match an IPv6 host: the host it read held no colon,
and ``[::1]:6432`` matched only a host spelled ``[``. (``[egress].allowed_ech_sidecar`` has its own
parse, ``pinned_host_port``, and was never read here.) It is a security matcher, so the change is
canonical equivalence only: each case under "never equated" stays a refusal.

Each case taking the ``match`` fixture runs through both the egress gate's ``host_port_allowed``
and the AI broker's ``endpoint_host_allowed``; the rest run on the arm they name.
"""

from __future__ import annotations

import ipaddress
import logging
import urllib.parse
import urllib.request
from collections.abc import Callable
from typing import Any

import pytest

from messagefoundry.config.models import ConnectorType, Destination
from messagefoundry.config.settings import EgressSettings
from messagefoundry.config.wiring import Database, WiringError
from messagefoundry.transports.ai_broker import endpoint_host_allowed
from messagefoundry.transports.egress import (
    check_egress_allowed,
    check_lookup_allowed,
    host_port_allowed,
)

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
    # The old parse read `[` as the host of `[::1]:8123` and `:1]:8123` as its port, so the one
    # thing that entry matched was a host spelled `[` with the port text `:1]:8123`, never ::1.
    # Egress only: no URL has that host.
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
    "entry",
    [
        "[::1",
        "[::1]x",
        "[::1]8123",
        "[db.example.org]",
        "[127.0.0.1]",
        "[a:b]",
        "[db.example.org:443]",
        "[]",
        ":443",
        "",
        # A colon with no port after it, as an env() that expanded to nothing leaves: not any port.
        "[::1]:",
        "[::1]: ",
        "db.example.org:",
        "127.0.0.1:",
    ],
)
def test_malformed_entry_matches_nothing(match: Match, entry: str) -> None:
    for host in ("::1", "127.0.0.1", "db.example.org"):
        assert match(host, 443, [entry]) is False


def test_no_port_never_matches_a_pin_spelled_none() -> None:
    assert host_port_allowed("::1", None, ["[::1]:None"]) is False
    assert host_port_allowed("db.example.org", None, ["db.example.org:None"]) is False
    assert host_port_allowed("::1", None, ["[::1]"]) is True


@pytest.mark.parametrize("url", ["https://ai.internal:abc/x", "https://ai.internal:99999/x"])
def test_broker_unreadable_port_is_refused_not_raised(url: str) -> None:
    # BACKLOG #1793: the ValueError quotes the port text, which can be a password's head.
    assert endpoint_host_allowed(url, ["ai.internal"]) is False


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


@pytest.mark.parametrize(
    ("host", "entry"), [("fe80::1%eth0", "[fe80::1%eth0]"), ("::1%31", "[::1%31]:8443")]
)
def test_the_same_zone_on_both_sides_matches_nothing(host: str, entry: str) -> None:
    # ipaddress reads both sides as one scoped address, so only the `%` refusal stops this; why it
    # must is in `messagefoundry.hostlist.canonical_host`'s docstring.
    assert host_port_allowed(host, 8443, [entry]) is False
    assert endpoint_host_allowed(f"https://[{host}]:8443/x", [entry]) is False


def test_a_percent_encoded_zone_is_dialled_as_another_address() -> None:
    # The premise `messagefoundry.hostlist.canonical_host`'s docstring states for refusing a `%`.
    url = "https://[::1%31]:8443/x"
    read = urllib.parse.urlsplit(url).hostname
    assert read == "::1%31"
    assert ipaddress.ip_address(read) != ipaddress.ip_address("::1")  # the zone is compared
    assert urllib.request.Request(url).host == "[::11]:8443"


# --- the DATABASE arm reads the same parse, and lists no IPv6 server ----------------------------

_UNLISTED = r"is not in the \[egress\]\.allowed_db allowlist$"
# A server holding a colon is refused as unlisted, saying why (BACKLOG #5915).
_COLON = r"is not in the \[egress\]\.allowed_db allowlist: a server holding a ':'"


_DIALECTS = ("generic", "sqlserver")


def _db_settings(server: str, dialect: str) -> dict[str, Any]:
    kw: dict[str, Any] = (
        {"dialect": "generic", "odbc_driver": "PostgreSQL Unicode", "odbc_params": {"PORT": "6432"}}
        if dialect == "generic"
        else {"port": 6432}
    )
    return dict(Database(statement="INSERT INTO t (a) VALUES (:a)", server=server, **kw).settings)


def _check_db(server: str, entry: str, *, dialect: str = "generic") -> None:
    dest = Destination(
        name="OB_DB_V6", type=ConnectorType.DATABASE, settings=_db_settings(server, dialect)
    )
    check_egress_allowed(dest, EgressSettings(allowed_db=[entry]))


@pytest.mark.parametrize("dialect", _DIALECTS)
@pytest.mark.parametrize("server", ["::1", "0:0:0:0:0:0:0:1", "fe80::1", "2001:db8::5", "[::1]"])
def test_database_ipv6_server_is_unlisted_saying_why(server: str, dialect: str) -> None:
    # docs/CONNECTIONS.md, allowed_db, says why it is refused. On origin/main the refusal was the
    # plain unlisted one, which reads as if an entry naming the address would admit it.
    with pytest.raises(WiringError, match=_COLON):
        _check_db(server, "db.example.org", dialect=dialect)


@pytest.mark.parametrize("entry", ["[::1]", "[::1]:6432", "[FE80::1]:6432", "[2001:db8::5]"])
def test_database_ipv6_entry_is_refused_at_load(entry: str) -> None:
    # On origin/main such an entry loaded and could never admit a server. The remedy names a host
    # name and never the bracketed forms this list refuses.
    with pytest.raises(ValueError, match=r"\[egress\]\.allowed_db entry 1 .* IPv6 address") as e:
        EgressSettings(allowed_db=[entry])
    assert "[v6]" not in str(e.value)


@pytest.mark.parametrize("entry", ["::1", "fe80::1:443", "db.example.org:5432:x"])
def test_database_multi_colon_entry_is_not_called_ipv6(entry: str) -> None:
    with pytest.raises(ValueError, match=r"entry 1 is refused: it holds more than one ':'") as e:
        EgressSettings(allowed_db=[entry])
    assert "IPv6" not in str(e.value) and "[v6]" not in str(e.value)


def test_database_url_entry_is_named_a_url() -> None:
    with pytest.raises(ValueError, match="is a URL or a path"):
        EgressSettings(allowed_db=["postgres://svc:pw@db.example.org:5432"])


@pytest.mark.parametrize("dialect", _DIALECTS)
def test_database_colon_refusal_does_not_quote_the_server(
    dialect: str, caplog: pytest.LogCaptureFixture
) -> None:
    # A ':' in server is where a pasted "user:password@host" lands; the refusal names the setting.
    with caplog.at_level(logging.DEBUG), pytest.raises(WiringError, match=_COLON) as e:
        _check_db("svcuser:FAKEPW@db.example.org", "db.example.org", dialect=dialect)
    assert "FAKEPW" not in str(e.value)
    assert "FAKEPW" not in caplog.text
    assert any("allowed_db" in r.getMessage() for r in caplog.records)


def test_database_ipv6_entry_refusal_counts_its_position() -> None:
    with pytest.raises(ValueError, match=r"\[egress\]\.allowed_db entry 2 "):
        EgressSettings(allowed_db=["db.example.org", "[::1]"])


@pytest.mark.parametrize("dialect", _DIALECTS)
@pytest.mark.parametrize(("server", "entry"), [("::1", "[::1]"), ("fe80::1", "[FE80::1]:6432")])
def test_database_colon_guard_holds_against_an_entry_naming_the_address(
    server: str, entry: str, dialect: str
) -> None:
    # The entry cannot load, so it is placed past the load check: the guard alone must refuse.
    dest = Destination(
        name="OB_DB_V6", type=ConnectorType.DATABASE, settings=_db_settings(server, dialect)
    )
    with pytest.raises(WiringError, match=_COLON):
        check_egress_allowed(dest, EgressSettings.model_construct(allowed_db=[entry]))


@pytest.mark.parametrize(
    ("dialect", "where"),
    [("generic", "the PORT keyword in odbc_params"), ("sqlserver", "the port setting")],
)
def test_database_colon_refusal_names_the_dialects_port(dialect: str, where: str) -> None:
    with pytest.raises(WiringError, match=where):
        _check_db("::1", "db.example.org", dialect=dialect)


@pytest.mark.parametrize("server", ["::1", "[::1]"])
def test_database_lookup_ipv6_server_is_unlisted(server: str) -> None:
    # db_lookup and DatabaseRef always build the SQL Server preset, through their own gate.
    with pytest.raises(WiringError, match=_COLON):
        check_lookup_allowed(
            "LK_V6", _db_settings(server, "sqlserver"), EgressSettings(allowed_db=["127.0.0.1"])
        )


@pytest.mark.parametrize("dialect", _DIALECTS)
def test_database_named_server_still_matches_its_entry(dialect: str) -> None:
    _check_db("db.example.org", "DB.Example.Org:6432", dialect=dialect)
    _check_db("127.0.0.1", "127.0.0.1:6432", dialect=dialect)  # an IPv4 literal is still listed


@pytest.mark.parametrize("dialect", _DIALECTS)
def test_database_unlisted_named_server_keeps_the_plain_refusal(dialect: str) -> None:
    with pytest.raises(WiringError, match=_UNLISTED):
        _check_db("other.example.org", "db.example.org", dialect=dialect)
