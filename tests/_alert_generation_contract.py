# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The generation-bounded alert resolve, one contract for every store backend (BACKLOG #3269).

``open_alert_generations`` reads a live instance's ``(id, count)``, and ``resolve_alert_generation``
closes it only while no raise has folded in past that count. SQLite runs it in
``tests/test_intake_alert_expiry.py``; the Postgres and SQL Server store suites call it on their
hosted legs, so the three backends cannot drift apart unseen.
"""

from __future__ import annotations

from typing import Any


async def check_alert_generation_contract(store: Any) -> None:
    kind = "intake_paused"
    await store.upsert_alert_instance(
        event_type=kind, connection="intake:a@node:1", severity="warning", now=10.0
    )
    await store.upsert_alert_instance(
        event_type=kind, connection="intake:b@node:2", severity="warning", now=10.0
    )
    await store.upsert_alert_instance(
        event_type="connection_error", connection="intake:a@node:1", severity="warning", now=10.0
    )
    every = await store.open_alert_generations(event_type=kind)
    assert [(g.connection, g.count) for g in every] == [
        ("intake:a@node:1", 1),
        ("intake:b@node:2", 1),
    ], "one type only, every subject, ordered by id"
    [seen] = await store.open_alert_generations(event_type=kind, connection="intake:a@node:1")
    assert seen == every[0]

    # A raise that lands after the read keeps the row open: no clock is compared.
    await store.upsert_alert_instance(
        event_type=kind, connection="intake:a@node:1", severity="warning", now=1.0
    )
    assert await store.resolve_alert_generation(alert_id=seen.id, through_count=seen.count) == 0
    [moved] = await store.open_alert_generations(event_type=kind, connection="intake:a@node:1")
    assert (moved.id, moved.count) == (seen.id, seen.count + 1)

    assert await store.resolve_alert_generation(alert_id=moved.id, through_count=moved.count) == 1
    assert await store.open_alert_generations(event_type=kind, connection="intake:a@node:1") == []
    assert await store.resolve_alert_generation(alert_id=moved.id, through_count=99) == 0, (
        "an already-resolved row is not resolved twice"
    )
    left = await store.open_alert_generations(event_type=kind)
    assert [g.connection for g in left] == ["intake:b@node:2"]
    other = await store.open_alert_generations(event_type="connection_error")
    assert [g.connection for g in other] == ["intake:a@node:1"], "another type is untouched"
