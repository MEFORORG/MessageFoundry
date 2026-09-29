# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Process-wide ODBC settings the engine needs before its first connect (BACKLOG #2049).

pyodbc turns ODBC driver-manager connection pooling ON by default (``pyodbc.pooling = True``). With
it on, ``Connection.close()`` does not end the server session: the driver manager parks the physical
connection in its own pool. The engine already pools through aioodbc, so this second layer only
keeps closed sessions alive. It broke a guarantee the SQL Server store relies on. ADR 0159 quarantines
a connection a cancellation abandoned by closing it, and assumes the close ends the session. On the
sqlserver-store CI legs a quarantined connection's session outlived the close, still alive with an
open transaction. Session state set on it (``SET`` options, session-owned applocks, or a transaction
whose close-time rollback failed) would live on in the driver's pool until reuse or timeout.

``pooling`` is read once, when pyodbc allocates its environment handle. That happens at the first
ODBC use in the process, a connect or a ``pyodbc.drivers()``, and a later change has no effect. So
the CLI entry point calls :func:`disable_driver_manager_pooling` before anything else, and at least
each engine connect site and the verifier's driver probe call it again, for callers that embed the
engine without the CLI. It is idempotent and runs at those sites, never per statement.
``tests/test_odbc_pooling_off.py`` fails if a site it can find stops calling it.

What this cannot do: pyodbc only asks for pooling through ``SQL_ATTR_CONNECTION_POOLING``. A driver
manager configured to pool on its own (unixODBC's ``Pooling = Yes`` in ``odbcinst.ini``) is outside
the engine's reach. The live sqlserver-store test is what shows a closed session really ends.
"""

from __future__ import annotations

__all__ = ["disable_driver_manager_pooling"]


def disable_driver_manager_pooling() -> None:
    """Turn off ODBC driver-manager pooling for this process, if pyodbc is installed."""
    try:
        import pyodbc
    except ImportError:  # the [sqlserver] extra is absent, so nothing here can connect over ODBC
        return
    pyodbc.pooling = False
