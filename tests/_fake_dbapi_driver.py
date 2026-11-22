# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A stand-in DB-API 2.0 driver for tests that fake a driver's error.

:func:`messagefoundry.redaction.raised_by_a_driver` counts an exception class whose module, or a
package above it, declares the DB-API ``apilevel``, and only such an error is read for a SQLSTATE
(vault BACKLOG #1661; engine PR 3150, finding 1). This module declares it, so every class here is a
driver's. A fake cursor that raised ``Exception("08S01", ...)`` stood in for pyodbc's error; it now
raises :class:`DriverError`, which carries the same arguments.
"""

from __future__ import annotations

#: The DB-API 2.0 marker that makes this module a driver's.
apilevel = "2.0"


class DriverError(Exception):
    """pyodbc's shape: ``args[0]`` the SQLSTATE, ``args[1]`` the driver's message."""


class RuntimeDriverError(RuntimeError):
    """:class:`DriverError`'s shape on a ``RuntimeError`` base, for a fake that raised one."""


class ConnectionDriverError(ConnectionError):
    """:class:`DriverError`'s shape on a ``ConnectionError`` base, for a fake that raised one."""


__all__ = ["ConnectionDriverError", "DriverError", "RuntimeDriverError", "apilevel"]
