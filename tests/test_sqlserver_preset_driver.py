# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The SQL Server preset sends ``SERVER={server},{port}``, so it is sound only with a driver that
reads ``,port`` as the port and the text before it as one host (BACKLOG #4873).

psqlODBC passes ``SERVER`` to libpq, which reads a comma as a host list. On the shipped code a
DATABASE connection on the preset with a psqlODBC ``odbc_driver`` sent ``SERVER=db,<port>``, so a
large integer ``port`` could name a second host that ``[egress].allowed_db`` never saw, and the
port the check compared bound nothing. A ``server`` holding a comma did the same with any driver.
Each case runs the connection-string build and the egress check, so ``messagefoundry check``
refuses what the build refuses. Nothing here opens a connection.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from typing import Any

import pytest

from messagefoundry.config.models import ConnectorType, Destination, Source
from messagefoundry.config.settings import EgressSettings
from messagefoundry.config.tls_policy import HopPosture, active_hop_posture
from messagefoundry.config.wiring import Database, DatabasePoll, WiringError
from messagefoundry.transports.database import DatabaseLookupExecutor, _build_dsn
from messagefoundry.transports.db_endpoint import SQLSERVER_DEFAULT_DRIVER, is_remote_spelling
from messagefoundry.transports.egress import (
    check_egress_allowed,
    check_lookup_allowed,
    check_source_allowed,
)
from tests._phi_log_capture import filtered_sink

HOST = "db.test.invalid"
HOST_ONLY = EgressSettings(allowed_db=[HOST])
PINNED = EgressSettings(allowed_db=[f"{HOST}:1433"])
OPEN = EgressSettings(deny_by_default=False)
STATEMENT = "INSERT INTO obs (mrn, val) VALUES (:mrn, :val)"
POLL = "SELECT id, payload FROM mf_inbox WHERE status='NEW' ORDER BY id"
DRIVER_REFUSAL = "name a Microsoft SQL Server driver, or on Database or DatabasePoll use dialect"

#: Not a whole Microsoft SQL Server driver name or library file name.
REFUSED_DRIVERS = [
    "PostgreSQL Unicode",
    "PostgreSQL",
    "psqlodbcw.so",
    "MySQL ODBC 8.0 Unicode Driver",
    "MariaDB ODBC 3.1",
    "Oracle 21",
    "",
    # Mixed names: a SQL Server word does not make a SQL Server driver on the preset.
    "PostgreSQL via SQL Server gateway",
    "MSODBCSQL-mariadb",
    "FreeTDS SQL Server",
    # FreeTDS, and the bare legacy name it is commonly registered under on Linux: nothing shows
    # it reads the preset's Encrypt and TrustServerCertificate keywords.
    "FreeTDS",
    "/usr/lib/x86_64-linux-gnu/odbc/libtdsodbc.so",
    "SQL Server",
    # Vendor drivers that mention SQL Server but configure TLS with their own keywords.
    "DataDirect 8.0 SQL Server Wire Protocol",
    "Devart ODBC Driver for SQL Server",
    "SQL Native Client",
    # Blanks are read as written, as the driver manager reads them: a doubled space, a tab, a
    # no-break space, a str.split separator or a blank at either end could name another alias.
    "ODBC Driver 18 for SQL  Server",
    "ODBC Driver 18 for SQL\tServer",
    "ODBC Driver 18 for SQL\u00a0Server",
    *(f"ODBC Driver 18 for SQL{sep}Server" for sep in "\x1c\x1d\x1e\x1f"),
    " ODBC Driver 18 for SQL Server",
    "ODBC Driver 18 for SQL Server ",
    "ODBC Driver 18 for SQL Server\n",
    "ODBC Driver 18. for SQL Server",
    # A library file name needs its dot before the extension.
    "/opt/microsoft/msodbcsql18/lib64/libmsodbcsql-18so",
    "/opt/microsoft/msodbcsql18/lib64/libmsodbcsql-18..so",
    # A path that can name a library on another host.
    r"\\files.test.invalid\share\msodbcsql18.dll",
    r"\\?\C:\Windows\System32\msodbcsql18.dll",
    "//files.test.invalid/share/libmsodbcsql-18.so",
    "file://files.test.invalid/share/libmsodbcsql-18.so",
    # The NT object-manager spelling of a share, which opens with one separator and a '?'.
    r"\??\UNC\files.test.invalid\share\msodbcsql18.dll",
    "/??/UNC/files.test.invalid/share/libmsodbcsql-18.so",
]

#: An accepted library path with each delimiter the preset refuses in its directory. The first is
#: the keyword injection a lone ``}}`` escape would stand between: ``SERVER=evil`` as a keyword.
DELIMITER_DRIVERS = [
    "/opt/x};SERVER=evil.test.invalid;Y={/libmsodbcsql-18.so",
    *(f"/opt/x{ch}y/libmsodbcsql-18.so" for ch in ";{}="),
    *(f"C:\\x{ch}y\\msodbcsql18.dll" for ch in ";{}="),
]
DELIMITER_REFUSAL = "odbc_driver must not hold ';', '{', '}' or '='"

ACCEPTED_DRIVERS = [
    "ODBC Driver 18 for SQL Server",
    "ODBC Driver 17 for SQL Server",
    "odbc driver 18 for sql server",
    "ODBC Driver 13.1 for SQL Server",
    "SQL Server Native Client 11.0",
    "/opt/microsoft/msodbcsql18/lib64/libmsodbcsql-18.3.so.3.1",
    "/opt/microsoft/msodbcsql18/lib64/libmsodbcsql-18.so",
    # Only the file name is read: a directory cannot change the library that loads.
    "/opt/mysql-compat/libmsodbcsql-18.so",
    "/opt/homebrew/lib/libmsodbcsql.18.dylib",
    r"C:\Windows\System32\msodbcsql18.dll",
    # Case is folded on a path too: Windows and macOS look a library file up in any case.
    r"C:\WINDOWS\SYSTEM32\MSODBCSQL18.DLL",
]


def _preset(**kw: Any) -> dict[str, Any]:
    return {"server": HOST, "database": "d", **kw}


def _check_destination(settings_kw: dict[str, Any], egress: EgressSettings) -> None:
    settings = Database(statement=STATEMENT, **settings_kw).settings
    check_egress_allowed(
        Destination(name="OB_DB_PRESET", type=ConnectorType.DATABASE, settings=settings), egress
    )


def _check_source(settings_kw: dict[str, Any], egress: EgressSettings) -> None:
    settings = DatabasePoll(poll_statement=POLL, **settings_kw).settings
    check_source_allowed(
        Source(type=ConnectorType.DATABASE, settings=settings), "IB_DB_PRESET", egress
    )


def _check_lookup(settings_kw: dict[str, Any], egress: EgressSettings) -> None:
    check_lookup_allowed("LK", settings_kw, egress)


def _check_reference(settings_kw: dict[str, Any], egress: EgressSettings) -> None:
    check_lookup_allowed("REF", settings_kw, egress, label="DATABASE reference source")


Check = Callable[[dict[str, Any], EgressSettings], None]


@pytest.fixture(
    params=[_check_destination, _check_source, _check_lookup, _check_reference],
    ids=["outbound", "inbound", "lookup", "reference"],
)
def check(request: pytest.FixtureRequest) -> Check:
    """Every config-time arm that reads the preset: each case runs on all four."""
    fn: Check = request.param
    return fn


# --- the driver -----------------------------------------------------------------------------------


@pytest.mark.parametrize("driver", REFUSED_DRIVERS)
def test_a_driver_that_is_not_a_sql_server_driver_is_refused_at_build(driver: str) -> None:
    with pytest.raises(ValueError, match=DRIVER_REFUSAL):
        _build_dsn(_preset(odbc_driver=driver))


@pytest.mark.parametrize("driver", REFUSED_DRIVERS)
def test_a_driver_that_is_not_a_sql_server_driver_is_refused_at_check(
    check: Check, driver: str
) -> None:
    # A host-only entry admits any port, so the shipped code ADMITTED every one of these.
    for egress in (HOST_ONLY, PINNED):
        with pytest.raises(WiringError, match=DRIVER_REFUSAL):
            check(_preset(odbc_driver=driver), egress)


@pytest.mark.parametrize("driver", DELIMITER_DRIVERS)
def test_a_driver_path_holding_a_delimiter_is_refused(check: Check, driver: str) -> None:
    # The file name is Microsoft's library, so before this the preset accepted each of these, and
    # only the `}}` escape kept the directory's text inside the DRIVER value.
    with pytest.raises(ValueError, match=DELIMITER_REFUSAL):
        _build_dsn(_preset(odbc_driver=driver))
    for egress in (HOST_ONLY, PINNED):
        with pytest.raises(WiringError, match=DELIMITER_REFUSAL):
            check(_preset(odbc_driver=driver), egress)


@pytest.mark.parametrize(
    "spelling",
    [
        r"\\host\share",
        "//host/share",
        r"\/host/share",
        r"/\host\share",
        r"\\?\UNC\host\share",
        r"\??\UNC\host\share",
        "/??/UNC/host/share",
        "  \\\\host\\share",
    ],
)
def test_a_remote_spelling_is_read_as_one(spelling: str) -> None:
    assert is_remote_spelling(spelling)


@pytest.mark.parametrize(
    "spelling",
    [r"C:\Windows\msodbcsql18.dll", "/opt/libmsodbcsql-18.so", r"\opt\x", "?", "", "/"],
)
def test_a_local_spelling_is_not_read_as_remote(spelling: str) -> None:
    assert not is_remote_spelling(spelling)


@pytest.mark.parametrize("driver", ACCEPTED_DRIVERS)
def test_a_sql_server_driver_is_accepted(check: Check, driver: str) -> None:
    assert f"SERVER={HOST},1433;" in _build_dsn(_preset(odbc_driver=driver))
    check(_preset(odbc_driver=driver), PINNED)


def test_the_default_driver_is_accepted(check: Check) -> None:
    assert _build_dsn(_preset()).startswith(
        f"DRIVER={{{SQLSERVER_DEFAULT_DRIVER}}};SERVER={HOST},1433;"
    )
    check(_preset(), PINNED)


def test_the_build_refusal_holds_with_no_allowlist() -> None:
    # Under the audited opt-out no allowed_db check runs, so the build is what refuses: the
    # executor and the outbound connection both build the preset when they are constructed.
    from messagefoundry.transports.base import build_destination

    with pytest.raises(ValueError, match=DRIVER_REFUSAL):
        DatabaseLookupExecutor({"LK": _preset(odbc_driver="PostgreSQL Unicode")}, egress=OPEN)
    settings = Database(statement=STATEMENT, **_preset(odbc_driver="PostgreSQL Unicode")).settings
    with pytest.raises(ValueError, match=DRIVER_REFUSAL):
        build_destination(
            Destination(name="OB_DB_PRESET", type=ConnectorType.DATABASE, settings=settings),
            egress=OPEN,
        )


def test_the_generic_dialect_still_takes_a_psqlodbc_driver() -> None:
    # The remedy the refusal names: this tightens the preset only.
    kw = {
        "dialect": "generic",
        "odbc_driver": "PostgreSQL Unicode",
        "server": HOST,
        "odbc_params": {"PORT": "5432"},
    }
    _check_destination(kw, EgressSettings(allowed_db=[f"{HOST}:5432"]))


# --- the server -----------------------------------------------------------------------------------


@pytest.mark.parametrize("server", [f"{HOST},6432", f"{HOST},", f"{HOST},replica.test.invalid"])
def test_a_server_holding_a_comma_is_refused(check: Check, server: str) -> None:
    # The preset adds its own `,port`, so `db,6432` sent `SERVER=db,6432,1433`. An entry naming the
    # whole server text matched it, and the shipped code ADMITTED it.
    with pytest.raises(ValueError, match="put the port in the port setting"):
        _build_dsn(_preset(server=server))
    with pytest.raises(WiringError, match="put the port in the port setting"):
        check(_preset(server=server), EgressSettings(allowed_db=[server]))


@pytest.mark.parametrize(
    "driver", ["ODBC Driver 18 for SQL Server", "SQL Server Native Client 11.0"]
)
def test_a_server_holding_an_instance_name_is_refused(check: Check, driver: str) -> None:
    # The preset always sends a port, so an instance name is not what a Microsoft driver dials,
    # and a driver that reads it in place of the port (FreeTDS, even under a SQL Server alias)
    # dials a port the check never compared. An entry naming the whole server text matched it.
    server = f"{HOST}\\SQLEXPRESS"
    with pytest.raises(ValueError, match="set port to the instance's port"):
        _build_dsn(_preset(server=server, odbc_driver=driver))
    with pytest.raises(WiringError, match="set port to the instance's port"):
        check(_preset(server=server, odbc_driver=driver), EgressSettings(allowed_db=[server]))


#: Each refusal ``_build_dsn`` can make on an attested weakened connection, with the text it raises:
#: the preset's, before the weakened-TLS check, and the auth, server and port refusals after it.
WEAKENED_HOP_REFUSALS = [
    pytest.param({"odbc_driver": "PostgreSQL Unicode"}, DRIVER_REFUSAL, id="driver"),
    pytest.param({"server": f"{HOST},6432"}, "put the port in the port setting", id="server-comma"),
    pytest.param({"auth": "kerberos"}, "auth must be sql|integrated|entra", id="auth"),
    pytest.param({"server": f"{HOST};X=1"}, "ODBC injection risk", id="server-delimiter"),
    pytest.param({"port": 70000}, "port must be from 0 to 65535", id="port"),
]


def _audit_lines(caplog: pytest.LogCaptureFixture) -> int:
    return sum("tls_hop_attested" in record.getMessage() for record in caplog.records)


def test_an_accepted_weakened_connection_writes_one_audit_line(
    caplog: pytest.LogCaptureFixture,
) -> None:
    # The control for the test below: the line is written only on an enforcing posture, once.
    with caplog.at_level(logging.WARNING), active_hop_posture(HopPosture(enforcing=True)):
        _build_dsn(_preset(encrypt=False), attested=True)
    assert _audit_lines(caplog) == 1


@pytest.mark.parametrize(("update", "match"), WEAKENED_HOP_REFUSALS)
def test_a_refused_connection_writes_no_weakened_tls_audit_line(
    caplog: pytest.LogCaptureFixture, update: dict[str, Any], match: str
) -> None:
    # A refused connection must leave no audit line saying its weakened hop was permitted.
    with (
        caplog.at_level(logging.WARNING),
        active_hop_posture(HopPosture(enforcing=True)),
        pytest.raises(ValueError, match=match),
    ):
        _build_dsn({**_preset(encrypt=False), **update}, attested=True)
    assert _audit_lines(caplog) == 0


def test_a_lookup_refusal_names_the_lookup() -> None:
    with pytest.raises(ValueError, match="'db_lookup:LK_ACME'"):
        DatabaseLookupExecutor({"LK_ACME": _preset(odbc_driver="PostgreSQL Unicode")}, egress=OPEN)


def _logged_refusal(name: str) -> str:
    """The lookup refusal for ``name`` as the engine's log handlers emit it, scrubs applied."""
    with pytest.raises(ValueError) as raised:
        DatabaseLookupExecutor({name: _preset(odbc_driver="PostgreSQL Unicode")}, egress=OPEN)
    logger_name = "test_sqlserver_preset_driver.scrub"
    with filtered_sink(logger_name) as sink:
        logging.getLogger(logger_name).warning("%s", raised.value)
    return sink.text


@pytest.mark.parametrize("name", ["LK_ACME", "LK_PASSWORD", "LK_TOKEN", "ACME_LAB", "Lk-Secret"])
def test_the_log_scrubs_keep_a_lookup_name_inside_the_name_pattern(name: str) -> None:
    # The refusal names its lookup as 'db_lookup:<name>'; the credential and name-run scrubs must
    # leave a name the connection-name pattern admits whole.
    assert f"'db_lookup:{name}';" in _logged_refusal(name)


def test_the_log_scrubs_can_blank_a_lookup_name_outside_the_name_pattern() -> None:
    # The control for the test above: the scrubs do run on this line. add_lookup does not hold a
    # lookup name to the connection-name pattern, so a two-word name is read as a person's name.
    assert "'db_lookup:[redacted]';" in _logged_refusal("Acme Lab")


# --- the refusal text ---------------------------------------------------------------------------


def test_the_refusal_leads_with_its_remedy_and_fits_a_stored_failure() -> None:
    # A stored failure keeps about its first 200 characters, so the remedy must sit inside them.
    with pytest.raises(ValueError) as raised:
        _build_dsn(_preset(odbc_driver="PostgreSQL Unicode"), connection="OB_ACME_LAB_RESULTS")
    message = str(raised.value)
    assert message.index("name a Microsoft SQL Server driver") < 80
    assert len(message) < 200, len(message)
