# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The closed sets of SQL Server fixed roles that the engine's role probes read by name.

A leaf, with no engine import, so ``store/`` and ``transports/`` share one spelling of the sets.
``transports/`` may not import ``store/`` (``tests/test_dependency_boundaries.py``, ADR 0154 AC-17),
and two copies of one list are how a probe that reads one role fewer than its twin goes unnoticed.

* The store's own preflight, ``store/sqlserver.py`` ``probe_principal_privileges``, judged by
  ``store/privilege.py`` (BACKLOG #1008).
* The partner-login probe that ``db_lookup`` and ``DatabaseRef`` run when their pool first opens,
  ``transports/database.py`` ``probe_login_roles`` (BACKLOG #2617).

Both read each role with ``IS_SRVROLEMEMBER`` or ``IS_ROLEMEMBER``, by name rather than by catalog
enumeration: catalog visibility is permission-filtered, so an enumeration that comes back empty is
indistinguishable from "a member of nothing". Both built-ins answer for the CURRENT login and need no
catalog permission, and both answer NULL, not 0, for a name that does not resolve for the caller.

The server set is the eight classic roles. The ``##MS_...##`` fixed server roles SQL Server 2022
added are not in it, so neither probe reads them.

Both probes read each answer with :func:`probed_grant`, which lives here for the same reason. It
is not SQL Server specific: the PostgreSQL store probe reads its audit-table answers with it too,
and reads its other answers another way.
"""

from __future__ import annotations

__all__ = ["SQLSERVER_FIXED_DATABASE_ROLES", "SQLSERVER_FIXED_SERVER_ROLES", "probed_grant"]

#: The closed set of SQL Server FIXED SERVER roles.
SQLSERVER_FIXED_SERVER_ROLES: tuple[str, ...] = (
    "sysadmin",
    "securityadmin",
    "serveradmin",
    "setupadmin",
    "processadmin",
    "diskadmin",
    "dbcreator",
    "bulkadmin",
)

#: The closed set of SQL Server FIXED DATABASE roles.
SQLSERVER_FIXED_DATABASE_ROLES: tuple[str, ...] = (
    "db_owner",
    "db_securityadmin",
    "db_accessadmin",
    "db_backupoperator",
    "db_ddladmin",
    "db_datareader",
    "db_datawriter",
    "db_denydatareader",
    "db_denydatawriter",
)


def probed_grant(value: object) -> bool | None:
    """Read one privilege-probe answer THREE ways: ``True`` held, ``False`` not held, ``None`` **not
    read**. Only an int or a bool that is 0 or 1 reads; anything else, a NULL, the text ``"1"``, a
    ``2``, ``1.0`` or bytes, is not read (BACKLOG #6015).

    ``IS_SRVROLEMEMBER``, ``IS_ROLEMEMBER`` and ``HAS_PERMS_BY_NAME`` each return NULL, not 0, when
    the name they are asked about does not resolve for this caller: an unknown or renamed role, a
    principal the caller cannot see, a permission name this server version does not carry
    (BACKLOG #1234). Folding that NULL, or an answer of a type a driver changed to, into "not held"
    would read as clean, so a probe that read nothing could render as a clean bill of health.
    ``True`` and ``False`` from a driver that returns booleans read as ``1`` and ``0``.

    Callers include the SQL Server store preflight (``store/privilege.py`` re-exports it), the
    PostgreSQL store preflight for its audit-table columns only, and the partner-login probe
    (``transports/database.py`` ``classify_login_roles``), so a change here changes how each of
    them reads."""
    if isinstance(value, int) and value in (0, 1):
        return bool(value)
    return None
