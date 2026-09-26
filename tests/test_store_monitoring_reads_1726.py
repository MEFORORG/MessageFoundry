# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #1726: the tracking view's first page must not cost the store's lifetime volume.

The SQLite store gains ``ix_messages_received ON messages(received_at, id)`` and the list view's
latest-event subquery picks its row by ``MAX(id)``. These tests pin three things:

* the plan -- page 1 walks the new index and builds no temp B-tree;
* the answer -- every figure ``list_messages`` and ``connection_metrics`` returned before the change
  they still return, measured by running the OLD form and the NEW form on one seeded store;
* the upgrade -- a store opened before the index existed gains it on its next open.

No row is deleted and no figure changes meaning; retention is out of scope here.
"""

from __future__ import annotations

import contextlib
import random
from collections.abc import AsyncIterator, Sequence
from pathlib import Path
from typing import Any

import pytest

from messagefoundry.store import MessageStore, OutboxStatus
from messagefoundry.store.store import Stage

_INDEX = "ix_messages_received"

# The list query exactly as it shipped before BACKLOG #1726: the reference the new form is compared to.
_OLD_LIST_SQL = (
    "SELECT id, channel_id, received_at, source_type, control_id, message_type,"
    " status, error, summary, metadata,"
    " (SELECT event FROM message_events e WHERE e.message_id = messages.id"
    "  ORDER BY e.id DESC LIMIT 1) AS last_event"
    " FROM messages{where}"
    " ORDER BY received_at DESC, id DESC LIMIT ? OFFSET ?"
)

_CHANNELS = ("IB_A", "IB_B", "IB_C")
_DESTS = ("OB_X", "OB_Y", "OB_Z")
_STATUSES = (
    OutboxStatus.PENDING.value,
    OutboxStatus.INFLIGHT.value,
    OutboxStatus.DONE.value,
    OutboxStatus.DEAD.value,
    OutboxStatus.CANCELLED.value,
)


@pytest.fixture
async def store(tmp_path: Path) -> AsyncIterator[MessageStore]:
    s = await MessageStore.open(tmp_path / "t1726.db")
    yield s
    await s.close()


async def _seed(store: MessageStore, n: int = 240) -> None:
    """Deterministic, deliberately awkward rows written straight to the tables.

    Awkward on purpose: received_at ties (so the id tie-break decides order), events whose ts runs
    against their id (so ordering by ts would pick a different "latest" than ordering by id), messages
    with no events, every outbound status, rows before and after the since and rate windows, and a
    (channel, destination) pair holding only cancelled rows.
    """
    rnd = random.Random(1726)
    messages: list[tuple[Any, ...]] = []
    events: list[tuple[Any, ...]] = []
    queue: list[tuple[Any, ...]] = []
    for i in range(n):
        mid = f"m{i:04d}"
        channel = _CHANNELS[i % len(_CHANNELS)]
        received_at = 100.0 + (i // 3)  # three messages share each timestamp
        status = "error" if i % 7 == 0 else "processed"
        mtype = ("ADT^A01", "ORU^R01")[i % 2]
        messages.append((mid, channel, received_at, f"C{i % 40}", mtype, status))
        # 0 to 3 events; ts DEcreasing with id, so the ts order and the id order disagree.
        events += [(mid, received_at + 10.0 - k, f"ev{k}") for k in range(i % 4)]
        for dest in rnd.sample(_DESTS, 2):
            q_status = _STATUSES[rnd.randrange(len(_STATUSES))]
            created = received_at + rnd.random()
            updated = created + rnd.random() * 20.0
            queue.append(
                (
                    f"q{i:04d}{dest}",
                    mid,
                    Stage.OUTBOUND.value,
                    channel,
                    dest,
                    q_status,
                    created,
                    updated,
                )
            )
        # An ingress row the outbound aggregate must ignore.
        queue.append((f"i{i:04d}", mid, Stage.INGRESS.value, channel, None, "done", 0.0, 0.0))
    # A pair with only cancelled rows: it must still appear, with every figure zero or None.
    messages.append(("m_cancel", "IB_ONLY_CANCELLED", 50.0, None, None, "processed"))
    queue.append(
        (
            "q_cancel",
            "m_cancel",
            Stage.OUTBOUND.value,
            "IB_ONLY_CANCELLED",
            "OB_Q",
            OutboxStatus.CANCELLED.value,
            50.0,
            51.0,
        )
    )
    db = store._db
    await db.executemany(
        "INSERT INTO messages (id, channel_id, received_at, control_id, message_type, raw, status)"
        " VALUES (?,?,?,?,?,'MSH|x',?)",
        messages,
    )
    await db.executemany(
        "INSERT INTO message_events (message_id, ts, event) VALUES (?,?,?)", events
    )
    await db.executemany(
        "INSERT INTO queue (id, message_id, stage, channel_id, destination_name, status,"
        " created_at, updated_at, payload, attempts, next_attempt_at)"
        " VALUES (?,?,?,?,?,?,?,?,'p',0,0.0)",
        queue,
    )
    await db.commit()


async def _plan(store: MessageStore, sql: str, params: tuple[Any, ...]) -> list[str]:
    cur = await store._db.execute("EXPLAIN QUERY PLAN " + sql, params)
    return [str(r[3]) for r in await cur.fetchall()]


async def _rows(store: MessageStore, sql: str, params: tuple[Any, ...]) -> list[tuple[Any, ...]]:
    cur = await store._db.execute(sql, params)
    return [tuple(r) for r in await cur.fetchall()]


async def _drop_index(store: MessageStore) -> None:
    await store._db.execute(f"DROP INDEX {_INDEX}")
    await store._db.commit()


async def _has_index(store: MessageStore) -> bool:
    cur = await store._db.execute(
        "SELECT 1 FROM sqlite_master WHERE type='index' AND name=?", (_INDEX,)
    )
    return await cur.fetchone() is not None


_FILTER_KEYS = (
    "channel_id",
    "status",
    "message_type",
    "control_id",
    "allowed_channels",
    "received_from",
    "received_to",
)
_NO_FILTER: tuple[Any, ...] = (None,) * len(_FILTER_KEYS)


async def _shipped_sql(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch, f: tuple[Any, ...]
) -> str:
    """The SQL ``list_messages`` really executes for filter ``f``, read off its read connection.

    Captured rather than rebuilt, so the plan and differential tests cannot drift from the method.
    Its filter params are ``_message_filter(*f)``'s; LIMIT and OFFSET are the last two."""
    seen: list[str] = []
    real_read = store._read

    class _Spy:
        def __init__(self, db: Any) -> None:
            self._db = db

        async def execute(self, sql: str, params: Sequence[Any] = ()) -> Any:
            seen.append(sql)
            return await self._db.execute(sql, params)

    @contextlib.asynccontextmanager
    async def spy_read() -> AsyncIterator[_Spy]:
        async with real_read() as db:
            yield _Spy(db)

    with monkeypatch.context() as m:
        m.setattr(store, "_read", spy_read)
        await store.list_messages(**dict(zip(_FILTER_KEYS, f, strict=True)), limit=1)
    [sql] = seen
    return sql


# --- plan ------------------------------------------------------------------------------------------


async def test_list_messages_page_one_walks_the_index_and_sorts_nothing(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    await _seed(store, n=30)
    plan = await _plan(store, await _shipped_sql(store, monkeypatch, _NO_FILTER), (50, 0))
    # An index walk in ORDER BY order that stops at LIMIT; never a bare table scan.
    assert f"SCAN messages USING INDEX {_INDEX}" in plan, plan
    assert "SCAN messages" not in plan, plan
    assert not any("TEMP B-TREE" in line for line in plan), plan
    # The latest-event subquery is a covering index read plus one primary-key fetch.
    assert "SEARCH e USING INTEGER PRIMARY KEY (rowid=?)" in plan, plan
    assert any(
        line.startswith("SEARCH e2 USING COVERING INDEX ix_events_message") for line in plan
    ), plan


async def test_list_messages_date_filter_seeks_the_index(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    await _seed(store, n=30)
    f = (None, None, None, None, None, 105.0, 108.0)
    _, params = MessageStore._message_filter(*f)
    plan = await _plan(store, await _shipped_sql(store, monkeypatch, f), (*params, 50, 0))
    assert any(line.startswith(f"SEARCH messages USING INDEX {_INDEX}") for line in plan), plan
    assert not any("TEMP B-TREE" in line for line in plan), plan


async def test_the_old_plan_sorted_the_whole_table(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Control: without the index the same query scans messages and sorts it, so the plan test
    above is measuring the index and not a query that could never sort."""
    await _seed(store, n=30)
    await _drop_index(store)
    plan = await _plan(store, await _shipped_sql(store, monkeypatch, _NO_FILTER), (50, 0))
    assert "SCAN messages" in plan, plan
    assert any("TEMP B-TREE FOR ORDER BY" in line for line in plan), plan


# --- same answer -----------------------------------------------------------------------------------


_FILTERS: tuple[tuple[Any, ...], ...] = (
    (None, None, None, None, None, None, None),
    ("IB_B", None, None, None, None, None, None),
    (None, "error", None, None, None, None, None),
    (None, None, None, None, ["IB_A", "IB_C"], None, None),
    (None, None, None, None, None, 110.0, 140.0),
    ("IB_A", None, None, None, None, 120.0, None),
    (None, None, None, "C7", None, None, None),  # control_id repeats across channels
    ("IB_B", None, None, "C7", None, None, None),
    (None, None, "ORU^R01", None, None, None, None),
    (None, None, None, "no-such-control", None, None, None),  # a miss walks everything
)


_PAGES = ((50, 0), (50, 50), (7, 13), (500, 0), (50, 10_000))


async def _every_page(
    store: MessageStore, sqls: Sequence[str]
) -> dict[tuple[int, int, int], list[tuple[Any, ...]]]:
    """Every filter in _FILTERS (``sqls[i]`` is filter i's SQL) times every page in _PAGES, keyed
    (filter no, limit, offset)."""
    out: dict[tuple[int, int, int], list[tuple[Any, ...]]] = {}
    for f_no, f in enumerate(_FILTERS):
        _, params = MessageStore._message_filter(*f)
        for limit, offset in _PAGES:
            out[(f_no, limit, offset)] = await _rows(store, sqls[f_no], (*params, limit, offset))
    return out


async def test_list_messages_old_and_new_return_the_same_rows(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Differential: the pre-#1726 world (old SQL, no index) against the new one (new SQL, index)
    on one store, for several filters and pages, including an offset past the end."""
    await _seed(store)
    new_sqls = [await _shipped_sql(store, monkeypatch, f) for f in _FILTERS]
    new = await _every_page(store, new_sqls)
    await _drop_index(store)
    old_sqls = [_OLD_LIST_SQL.format(where=MessageStore._message_filter(*f)[0]) for f in _FILTERS]
    old = await _every_page(store, old_sqls)
    assert old == new
    # The seed must exercise what the comparison is about, or equality proves nothing.
    everything = new[(0, 500, 0)]  # no filter, one page holding every row
    assert len(everything) == 241
    last_events = {r[0]: r[-1] for r in everything}
    assert last_events["m0001"] == "ev0"  # one event
    assert last_events["m0003"] == "ev2"  # highest id wins although it has the LOWEST ts
    assert last_events["m0004"] is None  # no events


async def test_connection_metrics_returns_every_figure_unchanged(store: MessageStore) -> None:
    """Every inbound and destination figure, with the new index and with it dropped, across since
    and rate windows. The metrics SQL did not change, and today's planner picks the same plan in both
    arms, so this guards the day a planner or a later edit starts using ix_messages_received there."""
    await _seed(store)
    windows = (
        (0.0, 200.0, 60.0),
        (140.0, 190.0, 30.0),
        (1_000.0, 1_000.0, 60.0),  # since after every row
        (120.0, 500.0, 1_000.0),
    )
    new = [
        await store.connection_metrics(since=s, now=now, rate_window=rw) for s, now, rw in windows
    ]
    await _drop_index(store)
    old = [
        await store.connection_metrics(since=s, now=now, rate_window=rw) for s, now, rw in windows
    ]
    assert old == new
    # The seed reaches every figure, so the comparison is not vacuous.
    first = new[0]
    assert set(first.inbound) == {*_CHANNELS, "IB_ONLY_CANCELLED"}
    assert first.inbound["IB_A"].errored > 0
    assert ("IB_ONLY_CANCELLED", "OB_Q") in first.destinations
    dests = first.destinations.values()
    assert any(d.queue_depth for d in dests)
    assert any(d.written for d in dests)
    assert any(d.dead for d in dests)
    assert any(d.oldest_pending_at is not None for d in dests)
    assert any(d.recent_done for d in dests)
    assert any(d.last_done_at is not None for d in dests)
    # The since window moves the windowed counts, so the windows are distinct cases.
    assert new[1] != new[0]


# --- upgrade ---------------------------------------------------------------------------------------


async def test_an_existing_store_gains_the_index_on_its_next_open(tmp_path: Path) -> None:
    path = tmp_path / "old.db"
    s = await MessageStore.open(path)
    try:
        await _seed(s, n=10)
        await _drop_index(s)  # the store as a build before #1726 left it
        assert not await _has_index(s)
    finally:
        await s.close()
    s = await MessageStore.open(path)
    try:
        assert await _has_index(s)
        rows = await s.list_messages(limit=500)
        assert len(rows) == 11
    finally:
        await s.close()
