# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A stand-in DB-API 2.0 driver for tests that fake a driver's error.

:func:`messagefoundry.redaction.raised_by_a_driver` counts an exception class whose module declares
the DB-API ``apilevel``, and only such an error is read for a SQLSTATE (vault BACKLOG #1661; engine
PR 3150, finding 1). A fake cursor that raised ``Exception("08S01", ...)`` stood in for pyodbc's
error; it now raises :class:`DriverError`, which carries the same arguments from a module that says
it is a driver. Importing this module registers that module in ``sys.modules`` under a name no real
package uses.
"""

from __future__ import annotations

import sys
import types

MODULE_NAME = "tests_fake_dbapi_driver"

_module = sys.modules.get(MODULE_NAME)
if _module is None:
    _module = types.ModuleType(MODULE_NAME)
    _module.apilevel = "2.0"  # type: ignore[attr-defined]
    sys.modules[MODULE_NAME] = _module


class DriverError(Exception):
    """pyodbc's shape: ``args[0]`` the SQLSTATE, ``args[1]`` the driver's message."""

    __module__ = MODULE_NAME


class RuntimeDriverError(RuntimeError):
    """:class:`DriverError`'s shape on a ``RuntimeError`` base, for a fake that raised one."""

    __module__ = MODULE_NAME


__all__ = ["MODULE_NAME", "DriverError", "RuntimeDriverError"]
