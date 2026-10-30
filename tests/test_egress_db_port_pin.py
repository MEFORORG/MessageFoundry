# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A port in an ``[egress].allowed_db`` entry binds the port the driver dials (vault BACKLOG #2704).

The SQL Server preset sends ``SERVER={server},{port}``, so the ``port`` setting is what it dials.
The generic ODBC dialect sends ``SERVER={server}`` and never reads ``port``: the driver gets its
port from the ``PORT`` keyword in ``odbc_params``. The check used to read ``port`` for both, so on
the generic dialect an entry pinned to one port admitted a hop to another port on the same host.

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


@pytest.fixture(params=[_check_destination, _check_source], ids=["destination", "source"])
def check(request: pytest.FixtureRequest) -> Check:
    """The two connector arms that honour ``dialect``. Each case runs on both, so they cannot drift."""
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
    with pytest.raises(WiringError, match="at port 6432, the port this connection dials"):
        check(kw, PINNED)


def test_sqlserver_preset_port_off_the_pin_is_refused(
    check: Check,
) -> None:
    # Control 1: the preset dials `server,port`, so its `port` setting is still what is read.
    with pytest.raises(WiringError, match="not in the \\[egress\\].allowed_db"):
        check({"server": HOST, "database": "d", "port": 6432}, PINNED)


def test_sqlserver_preset_port_on_the_pin_is_admitted(
    check: Check,
) -> None:
    # The preset's reading is unchanged: the pinned port, set as `port`, still passes.
    check({"server": HOST, "database": "d", "port": 5432}, PINNED)


@pytest.mark.parametrize("port", [1433, 5432], ids=["port-defaulted", "port-on-the-pin"])
def test_generic_without_port_keyword_against_a_pin_is_refused(check: Check, port: int) -> None:
    # Control 2, and its sharper twin. With no PORT keyword the driver dials its own default port,
    # which the engine does not know. The shipped code refused the defaulted case only by accident
    # (it read 1433) and ADMITTED `port=5432`, a setting the generic connection string never reads.
    kw = _generic(server=HOST, port=port)
    assert "PORT" not in _build_odbc_dsn(dict(Database(statement=STATEMENT, **kw).settings))
    with pytest.raises(WiringError, match="set the PORT keyword in odbc_params"):
        check(kw, PINNED)


def test_generic_port_keyword_on_the_pin_is_admitted(
    check: Check,
) -> None:
    # The reverse case: the documented generic shape, PORT in odbc_params and no `port` setting.
    # The shipped code read the defaulted `port` (1433) and REFUSED it, a false refusal.
    check(_generic(server=HOST, odbc_params={"PORT": "5432"}), PINNED)


# --- a port given twice, and a host-only entry --------------------------------------------------


@pytest.mark.parametrize("keyword", ["5432", "not-a-port"])
def test_generic_server_port_and_port_keyword_disagreeing_is_refused(
    check: Check, keyword: str
) -> None:
    # The host is matched as written, so only an entry naming the whole `server` text reaches the
    # port question. The shipped code ADMITTED both of these on that entry: it never read either port.
    server = f"{HOST},6432"
    with pytest.raises(WiringError, match="give the port once"):
        check(
            _generic(server=server, odbc_params={"PORT": keyword}),
            EgressSettings(allowed_db=[server]),
        )


def test_generic_server_port_and_port_keyword_agreeing_is_admitted(
    check: Check,
) -> None:
    server = f"{HOST},6432"
    check(
        _generic(server=server, odbc_params={"PORT": "6432"}), EgressSettings(allowed_db=[server])
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
    with pytest.raises(WiringError, match="names no port the engine can read"):
        check(_generic(server=HOST, odbc_params={"PORT": "not-a-port"}), PINNED)


def test_no_port_never_matches_a_pin_spelled_like_none(
    check: Check,
) -> None:
    # "No port" is not a value that can match a pin. An entry whose port text happens to read
    # "None" must not admit a connection whose port the engine could not read.
    with pytest.raises(WiringError, match="names no port the engine can read"):
        check(_generic(server=HOST), EgressSettings(allowed_db=[f"{HOST}:None"]))


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
    # db_lookup and the DatabaseRef sync call the SQL Server builder directly, which dials
    # `server,port` and never reads odbc_params. So a `dialect="generic"` in their settings changes
    # nothing the check reads: the `port` setting is the port dialled.
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
        (f"{HOST},6432", {}),
        (f"{HOST}:6432", {"PORT": "6432"}),
        ("[::1]:5432", {}),
        ("fe80::1", {"PORT": "5432"}),
    ],
)
def test_egress_port_agrees_with_the_hop_guard_port(server: str, params: dict[str, str]) -> None:
    # Where the port is given once, the egress reading and the hop guard read the same port: the
    # hop guard's 0 is the egress reading's None.
    endpoint = database_dial_endpoint(
        {"server": server, "port": 1433, "odbc_params": params}, dialect="generic"
    )
    assert endpoint.conflict is None
    assert endpoint.host == server
    assert (endpoint.port or 0) == generic_hop_endpoint(server, params)[1]
