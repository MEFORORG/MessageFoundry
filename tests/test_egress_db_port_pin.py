# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A port in an ``[egress].allowed_db`` entry is compared with the port the connection string
sends (vault BACKLOG #2704).

The SQL Server preset sends ``SERVER={server},{port}``, so the ``port`` setting is the port sent.
The generic ODBC dialect sends ``SERVER={server}`` and never reads ``port``: its connection string
carries the ``PORT`` keyword from ``odbc_params``. The check used to read ``port`` for both, so on
the generic dialect an entry pinned to one port admitted a connection sending another port to the
same host. What a driver does with ``PORT`` is not something this file can see.

Each case below runs the egress check and, where it says what the driver is sent, the generic
connection-string builder. Nothing here opens a connection. The cases that describe a change name
what the shipped code did; each of them fails on it.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import pytest

from messagefoundry.config.models import ConnectorType, Destination, Source
from messagefoundry.config.settings import EgressSettings
from messagefoundry.config.wiring import Database, DatabasePoll, WiringError
from messagefoundry.transports.database import _build_odbc_dsn
from messagefoundry.transports.db_endpoint import (
    database_dial_endpoint,
    generic_hop_endpoint,
)
from messagefoundry.transports.egress import (
    check_egress_allowed,
    check_lookup_allowed,
    check_source_allowed,
)

HOST = "db.test.invalid"
PINNED = EgressSettings(allowed_db=[f"{HOST}:5432"])
HOST_ONLY = EgressSettings(allowed_db=[HOST])
STATEMENT = "INSERT INTO obs (mrn, val) VALUES (:mrn, :val)"
POLL = "SELECT id, payload FROM mf_inbox WHERE status='NEW' ORDER BY id"


def _generic(**kw: Any) -> dict[str, Any]:
    return {"dialect": "generic", "odbc_driver": "PostgreSQL Unicode", **kw}


def _check_destination(settings_kw: dict[str, Any], egress: EgressSettings) -> None:
    settings = Database(statement=STATEMENT, **settings_kw).settings
    dest = Destination(name="OB_DB_PIN", type=ConnectorType.DATABASE, settings=settings)
    check_egress_allowed(dest, egress)


def _check_source(settings_kw: dict[str, Any], egress: EgressSettings) -> None:
    settings = DatabasePoll(poll_statement=POLL, **settings_kw).settings
    check_source_allowed(
        Source(type=ConnectorType.DATABASE, settings=settings), "IB_DB_PIN", egress
    )


Check = Callable[[dict[str, Any], EgressSettings], None]


@pytest.fixture(params=[_check_destination, _check_source], ids=["outbound", "inbound"])
def check(request: pytest.FixtureRequest) -> Check:
    """The outbound connection and the inbound poll: the two arms that honour ``dialect``. Each case
    runs on both, so they cannot drift."""
    fn: Check = request.param
    return fn


# --- the row's probe, and its two controls ------------------------------------------------------


def test_generic_port_keyword_off_the_pin_is_refused(
    check: Check,
) -> None:
    # The probe: `port` agrees with the entry, the PORT keyword the driver is sent does not. The
    # shipped code read `port` and ADMITTED this hop.
    kw = _generic(server=HOST, port=5432, odbc_params={"PORT": "6432"})
    assert "PORT={6432}" in _build_odbc_dsn(dict(Database(statement=STATEMENT, **kw).settings))
    with pytest.raises(WiringError, match="at port 6432, the port this connection names"):
        check(kw, PINNED)


def test_sqlserver_preset_port_off_the_pin_is_refused(
    check: Check,
) -> None:
    # Control 1: the preset sends `server,port`, so its `port` setting is still what is read.
    with pytest.raises(WiringError, match="not in the \\[egress\\].allowed_db"):
        check({"server": HOST, "database": "d", "port": 6432}, PINNED)


def test_sqlserver_preset_port_on_the_pin_is_admitted(
    check: Check,
) -> None:
    # The preset's reading is unchanged: the pinned port, set as `port`, still passes.
    check({"server": HOST, "database": "d", "port": 5432}, PINNED)


@pytest.mark.parametrize("port", [1433, 5432], ids=["port-defaulted", "port-on-the-pin"])
def test_generic_without_port_keyword_against_a_pin_is_refused(check: Check, port: int) -> None:
    # Control 2, and its sharper twin. With no PORT keyword the driver uses its own default port,
    # which the engine does not know. The shipped code refused the defaulted case only by accident
    # (it read 1433) and ADMITTED `port=5432`, a setting the generic connection string never reads.
    kw = _generic(server=HOST, port=port)
    assert "PORT" not in _build_odbc_dsn(dict(Database(statement=STATEMENT, **kw).settings))
    with pytest.raises(WiringError, match="set the PORT keyword to the pinned port"):
        check(kw, PINNED)


def test_generic_port_keyword_on_the_pin_is_admitted(
    check: Check,
) -> None:
    # The reverse case: the documented generic shape, PORT in odbc_params and no `port` setting.
    # The shipped code read the defaulted `port` (1433) and REFUSED it, a false refusal.
    check(_generic(server=HOST, odbc_params={"PORT": "5432"}), PINNED)


# --- a port given twice, and a host-only entry --------------------------------------------------


@pytest.mark.parametrize("odbc_params", [None, {"PORT": "6432"}, {"PORT": "5432"}])
def test_generic_server_carrying_a_port_is_refused(
    check: Check, odbc_params: dict[str, str] | None
) -> None:
    # The host is matched as written, so only an entry naming the whole `server` text reaches the
    # port question. A port in `server` is refused whatever the entry says and whatever PORT says:
    # psqlODBC does not read it as a port, and libpq reads a comma there as a second host. The
    # shipped code ADMITTED every one of these on a host-only entry; it read neither port.
    server = f"{HOST},6432"
    for entry in (server, f"{server}:6432"):
        with pytest.raises(
            WiringError, match="holds a comma, read as a port suffix or a host list"
        ):
            check(
                _generic(server=server, odbc_params=odbc_params), EgressSettings(allowed_db=[entry])
            )


@pytest.mark.parametrize("server", [f"[{HOST}],6432", f"{HOST},", f"{HOST},replica.test.invalid"])
def test_generic_server_holding_a_comma_anywhere_is_refused(check: Check, server: str) -> None:
    # libpq reads every one of these as a host list. The first two have no suffix the split reads
    # as a port, so a check keyed on the split's port text let them through.
    for entry in (server, f"{server}:5432"):
        with pytest.raises(
            WiringError, match="holds a comma, read as a port suffix or a host list"
        ):
            check(
                _generic(server=server, odbc_params={"PORT": "5432"}),
                EgressSettings(allowed_db=[entry]),
            )


def test_a_pin_is_read_as_a_number(check: Check) -> None:
    # main matched `db:05432` against the text "05432"; the port is now a number on both sides.
    pinned = EgressSettings(allowed_db=[f"{HOST}:05432"])
    check(_generic(server=HOST, odbc_params={"PORT": "5432"}), pinned)
    check({"server": HOST, "database": "d", "port": "05432"}, pinned)
    with pytest.raises(WiringError, match="at port 6432"):
        check(_generic(server=HOST, odbc_params={"PORT": "6432"}), pinned)


def test_the_no_port_refusal_leads_with_its_remedy(check: Check) -> None:
    # A stored failure keeps about its first 200 characters, so the remedy must sit inside them.
    with pytest.raises(WiringError) as raised:
        check(_generic(server="db.example.org"), EgressSettings(allowed_db=["db.example.org:5432"]))
    message = str(raised.value)
    assert message.index("set the PORT keyword to the pinned port") < 100
    assert len(message) < 200, len(message)


@pytest.mark.parametrize("server", [f"{HOST}:6432", "[::1]:6432"])
def test_generic_server_with_a_colon_port_matches_no_entry(check: Check, server: str) -> None:
    # An entry splits at its first colon, so no entry names a `host:port` server whole: refused as
    # unlisted, as the shipped code refused it.
    for entry in (server, HOST, "[::1]"):
        with pytest.raises(WiringError, match=r"is not in the \[egress\]\.allowed_db allowlist$"):
            check(
                _generic(server=server, odbc_params={"PORT": "6432"}),
                EgressSettings(allowed_db=[entry]),
            )


@pytest.mark.parametrize(
    "odbc_params", [None, {"PORT": "not-a-port"}], ids=["no-keyword", "unreadable-keyword"]
)
def test_generic_with_no_derivable_port_against_a_host_only_entry_is_admitted(
    check: Check, odbc_params: dict[str, str] | None
) -> None:
    # The host is still bound; an entry that names no port admits any port, as it always has.
    check(_generic(server=HOST, odbc_params=odbc_params), HOST_ONLY)


def test_generic_with_an_unreadable_port_keyword_against_a_pin_is_refused(
    check: Check,
) -> None:
    with pytest.raises(WiringError, match="set the PORT keyword to the pinned port"):
        check(_generic(server=HOST, odbc_params={"PORT": "not-a-port"}), PINNED)


def test_no_port_never_matches_a_pin_spelled_like_none(
    check: Check,
) -> None:
    # "No port" is not a value that can match a pin. An entry whose port text happens to read
    # "None" must not admit a connection whose port the engine could not read.
    with pytest.raises(WiringError, match="set the PORT keyword to the pinned port"):
        check(_generic(server=HOST), EgressSettings(allowed_db=[f"{HOST}:None"]))


def test_generic_port_keyword_given_twice_is_refused(check: Check) -> None:
    # The build refuses a keyword given twice in any case; the check must not judge one copy, or its
    # verdict would depend on the order of the table.
    with pytest.raises(WiringError, match="PORT keyword more than once"):
        check(_generic(server=HOST, odbc_params={"Port": "6432", "PORT": "5432"}), PINNED)


@pytest.mark.parametrize("value", ["²", "70000", "0"], ids=["superscript", "over", "zero"])
def test_generic_port_keyword_that_is_not_a_port_is_unreadable(check: Check, value: str) -> None:
    # Not a crash, and not a match: a superscript digit passes `isdigit` and fails `int()`, and
    # 70000 is not a port, even against a pin spelled the same way.
    with pytest.raises(WiringError, match="set the PORT keyword to the pinned port"):
        check(
            _generic(server=HOST, odbc_params={"PORT": value}),
            EgressSettings(allowed_db=[f"{HOST}:{value}"]),
        )


def test_generic_port_keyword_with_leading_zeros_is_the_port(check: Check) -> None:
    # Drivers read 005432 as 5432, so the check must too; the digit bound counts after the zeros.
    check(_generic(server=HOST, odbc_params={"PORT": "005432"}), PINNED)


def test_sqlserver_preset_port_is_read_as_the_connection_string_reads_it(check: Check) -> None:
    # The preset's connection string sends int(port), so an env()-shaped " 5432" sends 5432.
    check({"server": HOST, "database": "d", "port": " 5432"}, PINNED)


def test_unlisted_host_is_refused_as_unlisted_before_its_port_is_read(check: Check) -> None:
    with pytest.raises(WiringError, match=r"is not in the \[egress\]\.allowed_db allowlist$"):
        check(_generic(server="evil.test.invalid,1", odbc_params={"PORT": "2"}), HOST_ONLY)


def test_generic_server_port_suffix_does_not_loosen_the_host(
    check: Check,
) -> None:
    # The host is the whole `server` text, as before. libpq reads `db,6432` as two hosts, so taking
    # the suffix off and matching `db` would admit a hop the shipped code refused.
    with pytest.raises(WiringError, match="not in the \\[egress\\].allowed_db"):
        check(_generic(server=f"{HOST},6432"), HOST_ONLY)


# --- the lookups build the preset, whatever their settings say ----------------------------------


@pytest.mark.parametrize("label", ["DatabaseLookup", "DATABASE reference source"])
def test_lookup_reads_the_port_setting_whatever_the_dialect_setting_says(label: str) -> None:
    # db_lookup and the DatabaseRef sync call the SQL Server builder directly, which sends
    # `server,port` and never reads odbc_params. So a `dialect="generic"` in their settings changes
    # nothing the check reads: the `port` setting is the port sent.
    settings = _generic(server=HOST, port=5432, odbc_params={"PORT": "6432"})
    check_lookup_allowed("LK", settings, PINNED, label=label)
    with pytest.raises(WiringError, match=f"{label} 'LK': server .* at port 6432"):
        check_lookup_allowed("LK", {**settings, "port": 6432}, PINNED, label=label)


# --- one reading behind the egress check and the hop guard --------------------------------------


@pytest.mark.parametrize(
    ("server", "params"),
    [
        (HOST, {}),
        (HOST, {"PORT": "5432"}),
        (HOST, {"port": " 5432 "}),  # matched in any case, as the build matches it
        (HOST, {"PORT": "not-a-port"}),
        (HOST, {"PORT": "005432"}),
        ("fe80::1", {"PORT": "5432"}),  # a bare v6 literal carries no port
    ],
)
def test_egress_port_agrees_with_the_hop_guard_port(server: str, params: dict[str, str]) -> None:
    # Where the PORT keyword settles the port, the egress reading and the hop guard read the same
    # one: the hop guard's 0 is the egress reading's None. A `server` carrying a port is where they
    # part: the hop guard reports that port, and the egress reading refuses the `server`.
    endpoint = database_dial_endpoint(
        {"server": server, "port": 1433, "odbc_params": params}, dialect="generic"
    )
    assert endpoint.conflict is None
    assert endpoint.host == server
    assert (endpoint.port or 0) == generic_hop_endpoint(server, params)[1]
