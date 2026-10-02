# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""DATABASE family graph: a DatabasePoll inbound reading a harness-owned table, and a Database
outbound writing another. It lives in its own directory because it needs a SQL Server, and
``serve --config harness/config`` loads only that directory's top-level modules, so serving the
coverage graph without a database stays clean. Serve it on its own::

    MEFOR_VALUE_HARNESS_DATABASE_NAME=... MEFOR_VALUE_HARNESS_DATABASE_USERNAME=... \\
    MEFOR_VALUE_HARNESS_DATABASE_PASSWORD=... \\
    python -m messagefoundry serve --config harness/config/database --db ./harness-db.db --env dev

It needs the ``[sqlserver]`` extra, the Microsoft ODBC Driver 18, and a SQL Server whose TLS
certificate this host trusts: the graph never weakens TLS. ``[egress].allowed_db`` must list the
server (``serve`` turns deny-by-default on, so an empty list refuses it). The two tables are created by the harness driver and sink
(``harness/drivers/_database.py``), which hold the same SQL as below; a test keeps the copies equal.

| Row inserted into dbo.mf_harness_inbox | Router/Handler decision            | Disposition |
|----------------------------------------|------------------------------------|-------------|
| an ADT message                         | written to dbo.mf_harness_outbox   | PROCESSED   |
| anything else                          | router returns []                  | UNROUTED    |

Every row the poll hands on is marked 'DONE' once the engine has durably received it (the ingress
commit), so DONE says nothing about the row's later disposition.
All data is synthetic; never point a real PHI feed at a harness config.
"""

import json

from messagefoundry import Database, DatabasePoll, Send, env, handler, inbound, outbound, router

# The server is an endpoint (harness/endpoints/database.py holds the same defaults; a test holds
# them equal). The database name and the credentials have NO default on purpose: they come only
# from the environment, and without them the engine refuses to START these two connections
# (isolated, the engine DEGRADED) rather than dial with a blank. This module imports nothing from
# `harness`, like every graph here.
_CONNECTION = {
    "server": env("harness_database_server", default="127.0.0.1"),
    "port": env("harness_database_port", default=1433, cast=int),
    "database": env("harness_database_name"),
    "username": env("harness_database_username"),
    "password": env("harness_database_password"),
}

inbound(
    "DB-IN_Harness",
    DatabasePoll(
        **_CONNECTION,
        # The status column is the marker: a handled row leaves the poll's own predicate.
        poll_statement="SELECT id, payload FROM dbo.mf_harness_inbox WHERE status = 'NEW' ORDER BY id",
        mark_statement="UPDATE dbo.mf_harness_inbox SET status = 'DONE' WHERE id = :id",
        body_column="payload",  # the column holds one HL7 message, handed on verbatim
        poll_seconds=0.5,
    ),
    router="harness_db_router",
)

outbound(
    "DB-OUT_Harness",
    Database(
        **_CONNECTION,
        # Idempotent on control_id: delivery is at-least-once and a retry re-executes the write.
        # UPDLOCK + HOLDLOCK keep two overlapping executions from both passing NOT EXISTS.
        statement=(
            "INSERT INTO dbo.mf_harness_outbox (control_id, message_type, payload) "
            "SELECT :control_id, :message_type, :payload "
            "WHERE NOT EXISTS (SELECT 1 FROM dbo.mf_harness_outbox WITH (UPDLOCK, HOLDLOCK) "
            "WHERE control_id = :control_id)"
        ),
    ),
)


@router("harness_db_router")
def route(msg):  # type: ignore[no-untyped-def]
    if msg["MSH-9.1"] != "ADT":
        return []  # logged UNROUTED, and the row is still marked
    return ["harness_db_handler"]


@handler("harness_db_handler")
def handle(msg):  # type: ignore[no-untyped-def]
    msg["MSH-6"] = "HARNESS_DB"  # a transform, so the written copy differs from the polled row
    body = {
        "control_id": msg["MSH-10"],
        "message_type": f"{msg['MSH-9.1']}^{msg['MSH-9.2']}",
        "payload": str(msg),
    }
    return Send("DB-OUT_Harness", json.dumps(body))
