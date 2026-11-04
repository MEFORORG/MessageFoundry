# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #5163: a generic-ODBC driver the engine cannot place as reading ``SERVER`` is reported.

The generic connection string sends its target as ``SERVER`` alone, and ``[egress].allowed_db``
checks that host (docs/CONNECTIONS.md, *Accepted odbc_params keywords*). Before this, such a driver
was reported only for its TLS mode (BACKLOG #5053). It now also gets a construction WARNING and a
line on ``messagefoundry check``'s advisory ``generic-db-server``. Neither refuses anything; the
refusal is BACKLOG #5041. Synthetic hosts only.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

import pytest

from messagefoundry.config.models import ConnectorType, Destination, Source
from messagefoundry.config.settings import EgressSettings
from messagefoundry.config.wiring import (
    POSSIBLY_GENERIC_DB_HOP,
    UNRESOLVED_SERVER_DRIVER_REASON,
    Database,
    DatabasePoll,
    Registry,
    build_inbound_connection,
    build_outbound_connection,
    env,
    server_unread_generic_db_hops,
)
from messagefoundry.transports import build_destination, build_source
from messagefoundry.transports.database import (
    _DRIVER_FAMILIES,
    SERVER_UNREAD_REASON,
    SERVER_UNREAD_REMEDY,
    _build_odbc_dsn,
    odbc_driver_reads_server,
)
from tests._phi_log_capture import filtered_sink
from tests.test_connection_tls_loosenings import _result, _write_config
from tests.test_database_transport import _MSODBC, _MYSQL, _PSQL
from tests.test_database_transport import _UNPLACED as _UNPLACED_NAMES

_LOGGER = "messagefoundry.transports.database"
_INSERT = "INSERT INTO r (a) VALUES (:a)"

_PLACED = (_PSQL, _MYSQL, _MSODBC)
#: The unplaced names the TLS tests use, less the empty and ``None`` settings the build refuses on
#: their own, plus a driver documented to take its target from ``DBQ``.
_UNPLACED = ("Oracle in OraDB19Home1", *(name for name in _UNPLACED_NAMES if name))


def _server_warnings(caplog: pytest.LogCaptureFixture) -> list[str]:
    return [
        r.getMessage()
        for r in caplog.records
        if r.levelno >= logging.WARNING and SERVER_UNREAD_REASON in r.getMessage()
    ]


@pytest.mark.parametrize("driver", _UNPLACED)
def test_an_unplaced_driver_warns_at_construction_naming_the_connection(
    driver: str, caplog: pytest.LogCaptureFixture
) -> None:
    with caplog.at_level(logging.WARNING, logger=_LOGGER):
        build_destination(
            Destination(
                name="OB_ELSEWHERE",
                type=ConnectorType.DATABASE,
                settings=Database(
                    server="db.example.invalid",
                    dialect="generic",
                    odbc_driver=driver,
                    statement=_INSERT,
                ).settings,
            ),
            egress=EgressSettings(deny_by_default=False),
        )
    warned = _server_warnings(caplog)
    assert len(warned) == 1, warned
    assert "OB_ELSEWHERE" in warned[0]
    assert "registered name" in warned[0]


@pytest.mark.parametrize("driver", _PLACED)
def test_a_family_documented_to_read_server_does_not_warn(
    driver: str, caplog: pytest.LogCaptureFixture
) -> None:
    with caplog.at_level(logging.WARNING, logger=_LOGGER):
        _build_odbc_dsn({"odbc_driver": driver, "server": "db.example.invalid"})
    assert _server_warnings(caplog) == []


def test_the_inbound_poll_warns_too(caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level(logging.WARNING, logger=_LOGGER):
        build_source(
            Source(
                name="IB_ELSEWHERE",
                type=ConnectorType.DATABASE,
                settings=DatabasePoll(
                    server="poll.example.invalid",
                    dialect="generic",
                    odbc_driver="Oracle in OraDB19Home1",
                    poll_statement="SELECT 1",
                ).settings,
            ),
            egress=EgressSettings(deny_by_default=False),
        )
    warned = _server_warnings(caplog)
    assert len(warned) == 1 and "inbound:IB_ELSEWHERE" in warned[0], warned


def test_the_warning_survives_the_log_scrub(monkeypatch: pytest.MonkeyPatch) -> None:
    """The scrub reads ``<word>: x`` as a credential pair and blanks two adjacent upper-case words,
    so the line keeps ``;`` after each keyword. Red mutation: a ``:`` after ``dialect`` blanks the
    consequence."""
    # Pinned, since other tests move these: the record must reach the handler.
    monkeypatch.setattr(logging.root.manager, "disable", logging.NOTSET)
    monkeypatch.setattr(logging.getLogger(_LOGGER), "disabled", False)
    with filtered_sink(_LOGGER) as sink:
        _build_odbc_dsn(
            {"odbc_driver": "Oracle in OraDB19Home1", "server": "db.example.invalid"},
            connection="OB_ELSEWHERE",
        )
    assert SERVER_UNREAD_REASON in sink.text, sink.text
    assert SERVER_UNREAD_REMEDY in sink.text, sink.text
    assert "OB_ELSEWHERE" in sink.text, sink.text


def test_every_placed_family_records_whether_it_reads_server() -> None:
    """The documented record, per family: each of the three is documented to read ``SERVER`` and
    none was run. A family added to the table must be added here, which is the review the field's
    missing default asks for."""
    assert {key: family.reads_server for key, family in _DRIVER_FAMILIES.items()} == {
        "psqlodbc": True,
        "mysql": True,
        "msodbc": True,
    }
    assert all(odbc_driver_reads_server(name) for name in _PLACED)
    assert not any(odbc_driver_reads_server(name) for name in _UNPLACED)
    assert not odbc_driver_reads_server(None)


def test_a_placed_family_that_does_not_read_server_still_warns(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """Placing a family for its TLS keyword must not clear this warning by itself. Red mutation:
    drop the ``reads_server`` term from ``odbc_driver_reads_server`` and no warning is logged."""
    monkeypatch.setitem(
        _DRIVER_FAMILIES, "psqlodbc", _DRIVER_FAMILIES["psqlodbc"]._replace(reads_server=False)
    )
    assert not odbc_driver_reads_server(_PSQL)
    with caplog.at_level(logging.WARNING, logger=_LOGGER):
        _build_odbc_dsn({"odbc_driver": _PSQL, "server": "db.example.invalid"})
    assert len(_server_warnings(caplog)) == 1


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
    _outbound(reg, "OB_ORACLE", dialect="generic", odbc_driver="Oracle in OraDB19Home1")
    # Not this reader's arm. The preset also sends a named odbc_driver; that is not covered here.
    _outbound(reg, "OB_PRESET", database="MFDB", odbc_driver="Oracle in OraDB19Home1")
    reg.add_inbound(
        build_inbound_connection(
            "IB_ORACLE",
            DatabasePoll(
                server="poll.example.invalid",
                dialect="generic",
                odbc_driver="Oracle in OraDB19Home1",
                poll_statement="SELECT 1",
            ),
            router="R",
        )
    )
    hops = dict(server_unread_generic_db_hops(reg))
    assert set(hops) == {"OB_ORACLE", "inbound:IB_ORACLE"}
    assert hops["OB_ORACLE"].startswith(SERVER_UNREAD_REASON)
    # The peer label names the host the egress check reads, so an operator can find the entry.
    assert "ob_oracle.example.invalid" in hops["OB_ORACLE"]
    assert "Oracle in" not in hops["OB_ORACLE"]


def test_the_reader_reads_an_env_dialect_and_an_env_driver_as_possibly() -> None:
    cast_ran: list[str] = []

    def driver_cast(value: object) -> str:
        cast_ran.append(str(value))
        return str(value)

    reg = Registry()
    _outbound(
        reg,
        "OB_ENV_DIALECT",
        dialect=env("db_dialect"),
        odbc_driver="Oracle in OraDB19Home1",
    )
    _outbound(
        reg,
        "OB_ENV_DRIVER",
        dialect="generic",
        odbc_driver=env("live_driver", cast=driver_cast),
    )
    _outbound(
        reg,
        "OB_DARK_DRIVER",
        deployed=False,
        dialect="generic",
        odbc_driver=env("dark_driver", cast=driver_cast),
    )
    _outbound(reg, "OB_DARK_DIALECT", deployed=False, dialect=env("dark_dialect"))
    hops = dict(server_unread_generic_db_hops(reg))
    # Not deployed: an env() dialect is skipped, and an env() driver is never resolved, so it is
    # listed as unread, as the TLS reader lists it (ADR 0111 AC-1).
    assert set(hops) == {"OB_ENV_DIALECT", "OB_ENV_DRIVER", "OB_DARK_DRIVER"}
    assert hops["OB_DARK_DRIVER"].startswith(UNRESOLVED_SERVER_DRIVER_REASON)
    assert hops["OB_ENV_DIALECT"].startswith(POSSIBLY_GENERIC_DB_HOP)
    assert "env(db_dialect)" in hops["OB_ENV_DIALECT"]
    assert hops["OB_ENV_DRIVER"].startswith(UNRESOLVED_SERVER_DRIVER_REASON)
    assert "env(live_driver)" in hops["OB_ENV_DRIVER"]
    assert cast_ran == []
    # Given the values, both resolve as the build resolves them, and only the live cast runs.
    values = {
        "db_dialect": "generic",
        "live_driver": "PostgreSQL Unicode",
        "dark_driver": "Oracle in OraDB19Home1",
        "dark_dialect": "generic",
    }
    resolved = dict(server_unread_generic_db_hops(reg, env_values=values))
    assert set(resolved) == {"OB_ENV_DIALECT", "OB_DARK_DRIVER"}
    assert resolved["OB_DARK_DRIVER"].startswith(UNRESOLVED_SERVER_DRIVER_REASON)
    assert resolved["OB_ENV_DIALECT"].startswith(SERVER_UNREAD_REASON)
    assert cast_ran == ["PostgreSQL Unicode"]
    preset = server_unread_generic_db_hops(reg, env_values={**values, "db_dialect": "sqlserver"})
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
    return _result(run_checks(cfg, run_lint=False), "generic-db-server")


def test_check_lists_an_unplaced_driver_and_stays_advisory(tmp_path: Path) -> None:
    r = _check(tmp_path, "Oracle in OraDB19Home1")
    assert r.ok and not r.required and not r.skipped
    assert "1 generic-ODBC database connection(s)" in r.detail
    assert "OB_DB" in r.detail and SERVER_UNREAD_REASON in r.detail


def test_check_says_none_when_every_driver_is_placed(tmp_path: Path) -> None:
    r = _check(tmp_path, "PostgreSQL Unicode")
    assert r.ok and not r.required and not r.skipped
    assert r.detail.startswith("no generic-ODBC database connection names a driver")
