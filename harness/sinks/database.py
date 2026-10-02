# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Database sink: record each row an engine Database outbound writes to the harness outbox table.

This sink binds nothing, so the loopback rule every listening sink keeps does not arise: it DIALS
the SQL Server named by ``database_server`` and reads ``dbo.mf_harness_outbox``
(``harness/drivers/_database.py``). Rows already in the table when the sink starts are ignored --
it records the high-water ``id`` at start and reads only above it -- so a long-lived table cannot
satisfy a scenario with an earlier run's rows. Needs the ``[sqlserver]`` extra and a SQL Server;
``pyodbc`` is imported lazily so discovery works without either.

Each payload is bounded before it is fetched (ASVS 5.1.1): the read withholds, server-side, any
payload over :data:`~harness.drivers._database.MAX_OUTBOX_PAYLOAD_CHARS` (the engine's per-message
cap), and the sink records such a row with an empty payload and a ``refused`` reason naming its
length, so it is counted rather than silently dropped. The same cap is applied again to what is
fetched, and :attr:`DatabaseSink.max_payload_chars` can lower it.
"""

from __future__ import annotations

import contextlib
import logging
from typing import Any

from harness.drivers import _database
from harness.endpoints import Endpoints
from harness.sinks import Record, Sink

KIND = "database"

log = logging.getLogger(__name__)


class DatabaseSink(Sink):
    kind = KIND

    def __init__(self, endpoints: Endpoints) -> None:
        super().__init__()
        self.endpoints = endpoints
        self._conn: Any = None
        self._started = False
        self._high_water = 0
        #: The last read that failed, by exception class only; the next poll retries it.
        self.last_error = ""
        #: The most characters one payload may hold and still be recorded. It can only LOWER the cap:
        #: the read never fetches more than :data:`~harness.drivers._database.MAX_OUTBOX_PAYLOAD_CHARS`.
        self.max_payload_chars = _database.MAX_OUTBOX_PAYLOAD_CHARS

    def start(self) -> None:
        """Connect, create the tables if absent, and note where this run's rows begin. Raises
        :class:`ConnectionError` when the database cannot be used, and leaves nothing open."""
        conn = _database.connect(self.endpoints)
        try:
            row = conn.cursor().execute(_database.OUTBOX_HIGH_WATER).fetchone()
        except _database.driver_error() as exc:
            conn.close()
            raise ConnectionError(f"cannot read the harness outbox: {exc}") from None
        self._high_water = int(row[0]) if row is not None else 0
        self._conn = conn
        self._started = True

    def stop(self) -> None:
        self._started = False
        self._drop()

    def _drop(self) -> None:
        if self._conn is not None:
            with contextlib.suppress(_database.driver_error()):  # closing a dead session can raise
                self._conn.close()
            self._conn = None

    def _read(self) -> list[Any]:
        """Rows above the high-water mark. A failed read drops the session, so the next poll dials a
        fresh one: a pyodbc connection does not recover from a lost session on its own. What already
        arrived is kept, and the verdict names what did not; the cause is logged by class only."""
        try:
            if self._conn is None:
                self._conn = _database.connect(self.endpoints)
            cursor = self._conn.cursor()
            rows: list[Any] = cursor.execute(
                _database.SELECT_OUTBOX_AFTER, self._high_water
            ).fetchall()
        except (ConnectionError, _database.driver_error()) as exc:
            self.last_error = type(exc).__name__
            log.warning("database sink: outbox read failed (%s); retrying", self.last_error)
            self._drop()
            return []
        return rows

    def records(self) -> list[Record]:
        if self._started:
            for row_id, control_id, message_type, payload, length in self._read():
                self._high_water = max(self._high_water, int(row_id))
                meta = {"id": str(row_id), "control_id": control_id, "message_type": message_type}
                # The attribute can only lower the cap: the read withholds anything over the
                # server-side cap whatever it says, and a withheld payload names that cap.
                cap = min(self.max_payload_chars, _database.MAX_OUTBOX_PAYLOAD_CHARS)
                if payload is None:
                    cap = _database.MAX_OUTBOX_PAYLOAD_CHARS
                if payload is None or len(str(payload)) > cap:
                    meta["refused"] = f"{length} characters, over the {cap}-character cap; not read"
                    self._add(Record(b"", meta))
                    continue
                self._add(Record(str(payload).encode("utf-8"), meta))
        return super().records()


def build(endpoints: Endpoints, key: str) -> Sink:
    if key != "database_server":
        raise KeyError(f"the database sink dials database_server, not {key!r}")
    return DatabaseSink(endpoints)
