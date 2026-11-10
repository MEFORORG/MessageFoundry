# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The generation-bounded alert resolves, one contract for every store backend (BACKLOG #3269,
#4916).

``open_alert_generations`` reads a live instance's ``(id, count)``. ``resolve_alert_generation``
closes it only while no raise has folded in past that count, and ``resolve_alert_instances_fenced``
closes it only while that holds or its newest raise is the resolving writer's own. SQLite runs it in
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


async def check_fenced_resolve_contract(store: Any) -> None:
    """BACKLOG #4916: a fenced resolve closes the key's instance when it has taken no raise past
    the writer's snapshot, or when its newest raise is the writer's own; never otherwise."""
    kind, key = "connection_error", "IB_FENCE"

    async def raise_(by: str | None) -> None:
        await store.upsert_alert_instance(
            event_type=kind, connection=key, severity="warning", now=5.0, raised_by=by
        )

    async def live() -> list[Any]:
        return list(await store.open_alert_generations(event_type=kind, connection=key))

    async def fenced(by: str, seen: Any) -> int:
        return int(
            await store.resolve_alert_instances_fenced(
                event_type=kind, connection=key, raised_by=by, seen=seen, now=1.0
            )
        )

    await raise_("A")
    [seen] = await live()
    await raise_("B")
    assert await fenced("A", seen) == 0, "B's raise after A's snapshot keeps it open"
    [moved] = await live()
    assert moved.count == seen.count + 1
    assert await fenced("B", None) == 1, "B's own newest raise is B's to close, snapshot or not"
    assert await live() == []

    await raise_("B")
    await raise_("A")
    [seen] = await live()
    assert await fenced("A", None) == 1, "A's own newest raise"
    await raise_("B")
    [seen] = await live()
    assert await fenced("A", seen) == 1, "no raise past A's snapshot: a skewed clock is not read"
    await raise_(None)
    [seen] = await live()
    await raise_(None)
    assert await fenced("A", seen) == 0, "an unfenced writer's newer raise keeps it open too"
    assert await fenced("A", None) == 0
    [left] = await live()
    assert await fenced("A", left) == 1
    assert await fenced("A", left) == 0, "an already-resolved row is not resolved twice"
