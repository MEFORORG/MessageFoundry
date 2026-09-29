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

``pooling`` is read once, when pyodbc allocates its environment handle at the first connect in the
process, and a later change has no effect. So every engine code path that opens an ODBC connection
calls :func:`disable_driver_manager_pooling` first. It is idempotent and costs one attribute read,
and it runs at connect sites, never per statement. ``tests/test_odbc_pooling_off.py`` fails if a
connect site stops calling it.
"""

from __future__ import annotations

__all__ = ["disable_driver_manager_pooling"]


def disable_driver_manager_pooling() -> None:
    """Turn off ODBC driver-manager pooling for this process, if pyodbc is installed."""
    try:
        import pyodbc
    except ImportError:  # the [sqlserver] extra is absent, so nothing here can connect over ODBC
        return
    # getattr: a test double of pyodbc may not model the attribute. The live legs pin the real one.
    if getattr(pyodbc, "pooling", False):
        pyodbc.pooling = False
