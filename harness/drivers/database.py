# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Database driver: insert each payload as a 'NEW' row in the table an engine DatabasePoll polls.

The polled table is the harness-owned ``dbo.mf_harness_inbox`` (``harness/drivers/_database.py``);
the inbound reads ``status = 'NEW'`` rows and marks each 'DONE' once it is durably received. One
parameterized INSERT per payload, on an autocommit connection, so a row is committed (and visible to
the poll) as soon as its insert returns. Needs the ``[sqlserver]`` extra and a SQL Server; ``pyodbc``
is imported lazily so discovery works without either, and every failure, including a missing
extra, is reported per payload in its :class:`Injection`, never raised.
"""

from __future__ import annotations

from collections.abc import Sequence

from harness.drivers import Driver, Injection, _database
from harness.endpoints import Endpoints

KIND = "database"


class DatabaseDriver(Driver):
    kind = KIND

    def __init__(self, endpoints: Endpoints) -> None:
        self.endpoints = endpoints

    def inject(self, payloads: Sequence[bytes]) -> list[Injection]:
        try:
            conn = _database.connect(self.endpoints)
        except ConnectionError as exc:
            return [Injection(error=str(exc)) for _ in payloads]
        error = _database.driver_error()
        outcomes: list[Injection] = []
        try:
            for payload in payloads:
                try:
                    conn.cursor().execute(_database.INSERT_INBOX, payload.decode("utf-8"))
                    outcomes.append(Injection())
                except (error, UnicodeDecodeError) as exc:
                    # The class name only: a driver's refusal text can quote the bound value back.
                    outcomes.append(Injection(error=f"insert refused: {type(exc).__name__}"))
        finally:
            conn.close()
        return outcomes


def build(endpoints: Endpoints, key: str) -> Driver:
    if key != "database_server":
        raise KeyError(f"the database driver dials database_server, not {key!r}")
    return DatabaseDriver(endpoints)
