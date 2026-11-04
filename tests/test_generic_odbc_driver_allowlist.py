# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #5041: the generic ODBC dialect takes an ``odbc_driver`` on its driver allowlist only.

The generic connection string sends its target as ``SERVER`` alone, and ``[egress].allowed_db`` and
the cleartext-hop guard's on-box test read that host (docs/CONNECTIONS.md, *Accepted odbc_params
keywords*). A driver that takes its target from another keyword, such as a file-based driver
(BACKLOG #2705 limb 5), would dial a host neither judged, and a free name may be a library path a
driver manager loads (BACKLOG #2628). The shipped code built any name, with a WARNING and an
advisory ``generic-db-server`` line (BACKLOG #5163). The build now refuses a name off the list,
inbound and outbound, the egress check refuses it too, and ``messagefoundry check`` lists it on
``generic-db-driver``. Synthetic hosts only.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import pytest

from messagefoundry.config.models import ConnectorType, Destination, Source
from messagefoundry.config.settings import EgressSettings
from messagefoundry.config.tls_policy import HopPosture, active_hop_posture
from messagefoundry.config.wiring import (
    POSSIBLY_GENERIC_DB_HOP,
    REFUSED_DRIVER_REASON,
    UNRESOLVED_REFUSED_DRIVER_REASON,
    Database,
    DatabasePoll,
    Registry,
    WiringError,
    build_inbound_connection,
    build_outbound_connection,
    env,
    refused_generic_db_drivers,
)
from messagefoundry.transports import build_destination, build_source
from messagefoundry.transports.database import (
    _DRIVER_FAMILIES,
    DatabaseDestination,
    DatabaseSource,
    _build_odbc_dsn,
    _driver_family,
)
from messagefoundry.transports.db_endpoint import (
    GENERIC_DRIVER_FAMILIES,
    GENERIC_DRIVER_REFUSAL,
    database_dial_endpoint,
    generic_driver_family,
)
from tests.test_connection_tls_loosenings import _TOML, _result, _write_config

_INSERT = "INSERT INTO r (a) VALUES (:a)"
_REFUSED = re.escape(GENERIC_DRIVER_REFUSAL)
_ORACLE = "Oracle in OraDB19Home1"

#: Every spelling family the allowlist accepts, with the family it places.
_ACCEPTED = {
    "PostgreSQL": "psqlodbc",
    "PostgreSQL Unicode": "psqlodbc",
    "PostgreSQL ANSI": "psqlodbc",
    "PostgreSQL Unicode(x64)": "psqlodbc",
    "postgresql ansi(x64)": "psqlodbc",
    "  PostgreSQL Unicode  ": "psqlodbc",
    "MySQL ODBC 8.0 Unicode Driver": "mysql",
    "MySQL ODBC 9.1 ANSI Driver": "mysql",
    "ODBC Driver 18 for SQL Server": "msodbc",
    "ODBC Driver 17 for SQL Server": "msodbc",
}

#: Names the build refuses: at least a driver that takes its target from another keyword, a
#: file-based driver, a library path, an odbcinst alias, another vendor's driver, and names that
#: only fold to an accepted one.
_REFUSED_NAMES = [
    _ORACLE,
    "SQLite3 ODBC Driver",
    "Microsoft Access Driver (*.mdb, *.accdb)",
    "MariaDB ODBC 3.1 Driver",
    "MySQL",
    "SQL Server",
    "/usr/lib/x86_64-linux-gnu/odbc/psqlodbcw.so",
    "/usr/lib64/libmyodbc8w.so",
    "/opt/microsoft/msodbcsql18/lib64/libmsodbcsql-18.so",
    "PostgreSQL35W",
    "PostgreSQL  Unicode",
    "MySQL  ODBC 8.0 Unicode Driver",
    "ODBC Driver 13.1 for SQL Server",
    "SQL Server Native Client 11.0",
    "Devart ODBC Driver for PostgreSQL",
]


# --- the one classifier ---------------------------------------------------------------------------


def test_the_allowlist_places_each_accepted_name_and_no_other() -> None:
    assert {name: generic_driver_family(name) for name in _ACCEPTED} == _ACCEPTED
    assert [name for name in _REFUSED_NAMES if generic_driver_family(name) is not None] == []
    assert generic_driver_family(None) is None and generic_driver_family("") is None


def test_the_tls_table_and_the_egress_check_share_one_classifier() -> None:
    """PR 2754 found two classifiers that disagreed. Each family the allowlist names has one TLS
    entry, and the database module places a name with the allowlist's own function."""
    assert set(_DRIVER_FAMILIES) == set(GENERIC_DRIVER_FAMILIES)
    assert _driver_family is generic_driver_family


# --- the build refuses, inbound and outbound ------------------------------------------------------


@pytest.mark.parametrize("driver", _REFUSED_NAMES)
def test_the_build_refuses_a_name_off_the_allowlist(driver: str) -> None:
    with pytest.raises(ValueError, match=_REFUSED) as refused:
        _build_odbc_dsn({"odbc_driver": driver, "server": "db.example.invalid"}, connection="OB_X")
    message = str(refused.value)
    assert message.startswith("connection 'OB_X'; DATABASE generic dialect; name psqlODBC")


@pytest.mark.parametrize("driver", sorted(_ACCEPTED))
def test_the_build_takes_a_name_on_the_allowlist(driver: str) -> None:
    dsn = _build_odbc_dsn({"odbc_driver": driver, "server": "db.example.invalid"})
    assert dsn.startswith(f"DRIVER={{{driver.strip()}}};SERVER=db.example.invalid;")


def _destination(driver: str, server: str, **extra: Any) -> Destination:
    return Destination(
        name="OB_ELSEWHERE",
        type=ConnectorType.DATABASE,
        settings=Database(
            server=server, dialect="generic", odbc_driver=driver, statement=_INSERT
        ).settings,
        **extra,
    )


def _source(driver: str, server: str, **extra: Any) -> Source:
    return Source(
        name="IB_ELSEWHERE",
        type=ConnectorType.DATABASE,
        settings=DatabasePoll(
            server=server, dialect="generic", odbc_driver=driver, poll_statement="SELECT 1"
        ).settings,
        **extra,
    )


def test_both_connection_kinds_refuse_it_at_construction() -> None:
    open_egress = EgressSettings(deny_by_default=False)
    with pytest.raises((ValueError, WiringError), match=_REFUSED) as out:
        build_destination(_destination(_ORACLE, "db.example.invalid"), egress=open_egress)
    assert "OB_ELSEWHERE" in str(out.value)
    with pytest.raises((ValueError, WiringError), match=_REFUSED) as inbound:
        build_source(_source(_ORACLE, "poll.example.invalid"), egress=open_egress)
    assert "inbound:IB_ELSEWHERE" in str(inbound.value)
    # The control: the same connections build under a name on the list.
    build_destination(_destination("PostgreSQL Unicode", "db.example.invalid"), egress=open_egress)
    build_source(_source("PostgreSQL Unicode", "poll.example.invalid"), egress=open_egress)


_ENFORCING = HopPosture(enforcing=True)
_ATTESTED: dict[str, Any] = {
    "tls_hop_attested": True,
    "tls_hop_attested_reason": "synthetic attestation for a test",
}


@pytest.mark.parametrize("attested", [{}, _ATTESTED], ids=["plain", "attested"])
def test_an_unplaced_driver_on_box_is_refused_not_allowed_by_the_hop_guard(
    attested: dict[str, Any],
) -> None:
    """PR 2772's open finding 1. The cleartext-hop guard ALLOWED an on-box ``server`` for a driver
    the engine could not place, though such a driver may take its target from another keyword and
    dial elsewhere. The build now refuses the name before the guard runs, and neither the on-box
    host nor an attestation lifts it. A placed driver at the same host is the control: the guard
    still allows it on-box."""
    with active_hop_posture(_ENFORCING):
        with pytest.raises(ValueError, match=_REFUSED):
            DatabaseDestination(_destination(_ORACLE, "127.0.0.1", **attested))
        with pytest.raises(ValueError, match=_REFUSED):
            DatabaseSource(_source(_ORACLE, "127.0.0.1", **attested))
        assert DatabaseDestination(_destination("PostgreSQL Unicode", "127.0.0.1", **attested))
        assert DatabaseSource(_source("PostgreSQL Unicode", "127.0.0.1", **attested))


@pytest.mark.parametrize("driver", [_ORACLE, "SQLite3 ODBC Driver", "MySQL"])
def test_the_egress_check_refuses_the_name_the_build_refuses(driver: str) -> None:
    settings = {"server": "db.example.invalid", "odbc_driver": driver}
    assert database_dial_endpoint(settings, dialect="generic").conflict == GENERIC_DRIVER_REFUSAL
    placed = {**settings, "odbc_driver": "PostgreSQL Unicode"}
    assert database_dial_endpoint(placed, dialect="generic").conflict is None
    # Not the preset's arm: it keeps its own driver rule (BACKLOG #4873).
    assert database_dial_endpoint(settings, dialect="sqlserver").conflict != GENERIC_DRIVER_REFUSAL


def test_the_refusal_names_no_value_and_survives_the_stored_cut() -> None:
    """A stored failure keeps about the first 200 characters, so the remedy leads. It quotes
    neither the driver name given nor a TLS spelling, and two upper case words never sit side by
    side, which the log redaction would blank."""
    name = "OB_DB_" + "X" * 34
    with pytest.raises(ValueError) as refused:
        _build_odbc_dsn({"odbc_driver": _ORACLE, "server": "db.example.invalid"}, connection=name)
    message = str(refused.value)
    assert _ORACLE not in message
    lead = "name psqlODBC or MySQL Connector/ODBC by its registered name in odbc_driver"
    assert message.index(lead) + len(lead) < 200, message


# --- the graph reader and the check line ----------------------------------------------------------


def _outbound(reg: Registry, name: str, *, deployed: bool = True, **settings: Any) -> None:
    reg.add_outbound(
        build_outbound_connection(
            name,
            Database(server=f"{name.lower()}.example.invalid", statement=_INSERT, **settings),
            deployed=deployed,
        )
    )


def test_the_reader_walks_both_tables_and_skips_the_preset() -> None:
    reg = Registry()
    _outbound(reg, "OB_PG", dialect="generic", odbc_driver="PostgreSQL Unicode")
    _outbound(reg, "OB_ORACLE", dialect="generic", odbc_driver=_ORACLE)
    _outbound(reg, "OB_DARK", deployed=False, dialect="generic", odbc_driver="MySQL")
    # Not this reader's arm: the preset refuses a non-Microsoft odbc_driver when its string is
    # built (BACKLOG #4873), which registering the connection here does not do.
    _outbound(reg, "OB_PRESET", database="MFDB", odbc_driver=_ORACLE)
    reg.add_inbound(
        build_inbound_connection(
            "IB_ORACLE",
            DatabasePoll(
                server="poll.example.invalid",
                dialect="generic",
                odbc_driver=_ORACLE,
                poll_statement="SELECT 1",
            ),
            router="R",
        )
    )
    hops = dict(refused_generic_db_drivers(reg))
    # A not-deployed connection is listed too: build-check never builds it.
    assert set(hops) == {"OB_ORACLE", "OB_DARK", "inbound:IB_ORACLE"}
    assert hops["OB_ORACLE"].startswith(REFUSED_DRIVER_REASON)
    # The peer label names the host the egress check reads, so an operator can find the entry.
    assert "ob_oracle.example.invalid" in hops["OB_ORACLE"]
    assert "Oracle in" not in hops["OB_ORACLE"]
    # Never the `port` setting's 1433 default: the generic string does not send it.
    assert "1433" not in hops["OB_ORACLE"]


def test_the_reader_reads_an_env_dialect_and_an_env_driver_as_possibly() -> None:
    cast_ran: list[str] = []

    def driver_cast(value: object) -> str:
        cast_ran.append(str(value))
        return str(value)

    reg = Registry()
    _outbound(reg, "OB_ENV_DIALECT", dialect=env("db_dialect"), odbc_driver=_ORACLE)
    _outbound(
        reg, "OB_ENV_DRIVER", dialect="generic", odbc_driver=env("live_driver", cast=driver_cast)
    )
    _outbound(
        reg,
        "OB_DARK_DRIVER",
        deployed=False,
        dialect="generic",
        odbc_driver=env("dark_driver", cast=driver_cast),
    )
    _outbound(reg, "OB_DARK_DIALECT", deployed=False, dialect=env("dark_dialect"))
    hops = dict(refused_generic_db_drivers(reg))
    # Not deployed: an env() dialect is skipped, and an env() driver is never resolved, so it is
    # listed as possibly refused (ADR 0111 AC-1).
    assert set(hops) == {"OB_ENV_DIALECT", "OB_ENV_DRIVER", "OB_DARK_DRIVER"}
    assert hops["OB_DARK_DRIVER"].startswith(UNRESOLVED_REFUSED_DRIVER_REASON)
    assert hops["OB_ENV_DIALECT"].startswith(POSSIBLY_GENERIC_DB_HOP)
    assert "env(db_dialect)" in hops["OB_ENV_DIALECT"]
    assert hops["OB_ENV_DRIVER"].startswith(UNRESOLVED_REFUSED_DRIVER_REASON)
    assert "env(live_driver)" in hops["OB_ENV_DRIVER"]
    assert cast_ran == []
    # Given the values, both resolve as the build resolves them, and only the live cast runs.
    values = {
        "db_dialect": "generic",
        "live_driver": "PostgreSQL Unicode",
        "dark_driver": _ORACLE,
        "dark_dialect": "generic",
    }
    resolved = dict(refused_generic_db_drivers(reg, env_values=values))
    assert set(resolved) == {"OB_ENV_DIALECT", "OB_DARK_DRIVER"}
    assert resolved["OB_DARK_DRIVER"].startswith(UNRESOLVED_REFUSED_DRIVER_REASON)
    assert resolved["OB_ENV_DIALECT"].startswith(REFUSED_DRIVER_REASON)
    assert cast_ran == ["PostgreSQL Unicode"]
    preset = refused_generic_db_drivers(reg, env_values={**values, "db_dialect": "sqlserver"})
    assert [name for name, _ in preset] == ["OB_DARK_DRIVER"]


_CHECK_MODULE = """
from messagefoundry import Database, MLLP, Send, handler, inbound, outbound, router

inbound("IB", MLLP(port=15098), router="r")
outbound(
    "OB_DB",
    Database(
        server="db.example.invalid",
        dialect="generic",
        odbc_driver="{driver}",
        statement="INSERT INTO r (a) VALUES (:a)",
        odbc_params={{"SSLmode": "verify-full"}},
    ),
)


@router("r")
def route(msg):
    return ["h"]


@handler("h")
def handle(msg):
    return Send("OB_DB", msg)
"""


def _check(tmp_path: Path, driver: str) -> Any:
    from messagefoundry.checks import run_checks

    cfg = _write_config(tmp_path, module=_CHECK_MODULE.format(driver=driver))
    # Lists the host, so build-check reaches the connector rather than the unlisted-host refusal.
    toml = tmp_path / "messagefoundry.toml"
    toml.write_text(_TOML + '\n[egress]\nallowed_db = ["db.example.invalid"]\n', encoding="utf-8")
    return run_checks(cfg, run_lint=False)


def test_check_lists_a_refused_driver_and_build_check_refuses_it(tmp_path: Path) -> None:
    report = _check(tmp_path, _ORACLE)
    line = _result(report, "generic-db-driver")
    assert line.ok and not line.required and not line.skipped
    assert "1 generic-ODBC database connection(s)" in line.detail
    assert "OB_DB" in line.detail and REFUSED_DRIVER_REASON in line.detail
    assert GENERIC_DRIVER_REFUSAL in line.detail
    # The required gate is the build itself, which refuses the same name.
    build = _result(report, "build-check")
    assert not build.ok and build.required and not build.skipped, build.detail
    assert "generic dialect accepts no other driver" in build.detail, build.detail


def test_check_says_none_when_every_driver_is_on_the_list(tmp_path: Path) -> None:
    report = _check(tmp_path, "PostgreSQL Unicode")
    line = _result(report, "generic-db-driver")
    assert line.ok and not line.required and not line.skipped
    assert line.detail.startswith("no generic-ODBC database connection names a driver")
    build = _result(report, "build-check")
    assert "generic dialect accepts no other driver" not in build.detail, build.detail
