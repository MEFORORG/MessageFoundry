# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Endpoints of ``harness/config/database/``: the SQL Server the DATABASE family polls and writes.

Unlike every other family's endpoints these name a server the harness does NOT own: the engine's
DatabasePoll inbound and Database outbound dial it, and so do the harness's database driver and
sink. The database name and the credentials are not endpoints -- an endpoint carries a default, and
a credential must not -- so they come only from the environment (``harness/drivers/_database.py``).
"""

from __future__ import annotations

from harness.endpoints import HOST, PORT, Endpoint

#: Values the graph reads as ``env("harness_<key>")`` with NO default, and the harness reads from
#: ``MEFOR_VALUE_HARNESS_<KEY>``: the database name and the credentials. They are never endpoints,
#: since an endpoint carries a default and a credential must not sit in source.
ENVIRONMENT_ONLY = ("database_name", "database_username", "database_password")

ENDPOINTS = (
    Endpoint(
        "database_server",
        HOST,
        "127.0.0.1",
        "DB-IN_Harness / DB-OUT_Harness: the SQL Server host the engine and the harness both dial",
    ),
    Endpoint(
        "database_port",
        PORT,
        "1433",
        "DB-IN_Harness / DB-OUT_Harness: that SQL Server's port (the server's, not a harness port)",
    ),
)
