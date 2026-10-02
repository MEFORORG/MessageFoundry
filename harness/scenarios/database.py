# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""DATABASE scenarios against ``harness/config/database/``: insert rows into the polled table, and
observe what the Database outbound writes to the outbox table.

These need a SQL Server, the ``[sqlserver]`` extra and the ODBC Driver 18, and the engine must be
serving the database graph. Where any of that is missing the run reports SKIPPED -- never a pass
-- naming the missing piece. A skip is not coverage evidence, and ``--coverage`` cannot tell the
two apart: it counts the claim below, which these scenarios make good only where a server exists.

What is NOT a skip: the engine serves the graph but its database inbound is not running (a missing
credential on the engine side, an unlisted ``[egress].allowed_db``), or the harness cannot use the
database it was pointed at. Both are failures, named as such.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import ClassVar

from harness.drivers import _database
from harness.scenarios._core import Scenario, ScenarioContext, ScenarioResult


@dataclass(frozen=True)
class DatabaseScenario(Scenario):
    """A :class:`Scenario` that first checks its preconditions and reports SKIPPED without them."""

    # Served on its own (harness/config/database/), so the shared real-graph test does not start an
    # engine on the top-level graph only to skip; tests/test_harness_database.py runs these.
    graph: ClassVar[str] = "database"

    def run(self, ctx: ScenarioContext) -> ScenarioResult:
        reason = _database.unavailable(ctx.endpoints)
        if reason:
            return ScenarioResult(self, False, reason, skipped=True)
        channels = {channel.id: channel for channel in ctx.client.list_channels()}
        inbound = channels.get(_database.INBOUND_NAME)
        if inbound is None:
            return ScenarioResult(
                self,
                False,
                f"the engine does not serve {_database.INBOUND_NAME} "
                "(serve harness/config/database to run the database scenarios)",
                skipped=True,
            )
        if not inbound.running:
            return ScenarioResult(
                self,
                False,
                f"the engine serves {_database.INBOUND_NAME} but it is not running (check the "
                "engine's MEFOR_VALUE_HARNESS_DATABASE_* values, [egress].allowed_db, and the "
                "[sqlserver] extra)",
            )
        try:
            return super().run(ctx)
        except ConnectionError as exc:  # the sink could not use the database
            return ScenarioResult(self, False, f"the harness database is unusable: {exc}")


SCENARIOS = (
    DatabaseScenario(
        "database_roundtrip",
        "ADT^A05 rows in the polled table -> PROCESSED, and written to the outbox table",
        "ADT",
        "A05",
        3,
        "processed",
        driver="database",
        inbound="database_server",
        sink="database",
        sink_endpoint="database_server",
    ),
    DatabaseScenario(
        "database_unrouted",
        "ORU^R01 rows in the polled table -> UNROUTED (the database router takes ADT only)",
        "ORU",
        "R01",
        2,
        "unrouted",
        driver="database",
        inbound="database_server",
    ),
)
