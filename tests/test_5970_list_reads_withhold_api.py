# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #5970, through the API: a list read whose page holds one cell sealed under a key the
store does not hold answers 200 with that cell withheld, rather than HTTP 500 for the whole page.

The store-level cases are in ``tests/_cell_tag_contract.py`` (``_assert_foreign_key_cells``); this
file pins what an operator sees on ``GET /events``, ``GET /alerts/active``, ``GET /dead-letters``
and ``GET /messages``. Red before engine PR 3128 (squash ``9599c615579``), on its first parent
``cc1b376f15d``: each route answered 500. Each page has an untouched row beside the planted one as
its control. Synthetic data only.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import httpx
import pytest

from messagefoundry.api import create_app
from messagefoundry.config.settings import EgressSettings
from messagefoundry.pipeline import Engine
from messagefoundry.store import MessageStatus
from messagefoundry.store.crypto import generate_key, make_cipher
from messagefoundry.store.store import MessageStore

RAW = "MSH|^~\\&|S|F|R|RF|20260101||ADT^A01|MSG5970|P|2.5.1\rPID|1||100^^^H^MR||DOE^JANE\r"


@pytest.fixture
async def keyed(tmp_path: Path) -> AsyncIterator[tuple[Engine, MessageStore]]:
    store = await MessageStore.open(
        tmp_path / "withhold.db", cipher=make_cipher(generate_key(), write_v2=True)
    )
    engine = Engine(
        store, poll_interval=0.02, egress_settings=EgressSettings(deny_by_default=False)
    )
    try:
        yield engine, store
    finally:
        await engine.stop()


def _foreign() -> str:
    """A cell sealed under a key this store does not hold, as a retired key's cell reads."""
    return make_cipher(generate_key(), write_v2=True).encrypt("SYNTH-FOREIGN")


async def _plant(store: MessageStore, sql: str, args: tuple[Any, ...]) -> None:
    await store._db.execute(sql, args)
    await store._db.commit()


async def _client(engine: Engine) -> httpx.AsyncClient:
    app = create_app(engine, allow_no_auth=True)
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t")


async def test_events_and_alerts_withhold_a_foreign_key_reason(
    keyed: tuple[Engine, MessageStore],
) -> None:
    engine, store = keyed
    planted, kept = "IB_W_PLANTED", "IB_W_KEPT"
    for conn in (planted, kept):
        await store.record_connection_event(
            connection=conn, transport="mllp", direction="in", kind="closed", reason="SYNTH-REASON"
        )
        await store.upsert_alert_instance(
            event_type="connection_error", connection=conn, severity="warning", reason="SYNTH-ALERT"
        )
    foreign = _foreign()
    await _plant(
        store, "UPDATE connection_event SET reason=? WHERE connection=?", (foreign, planted)
    )
    await _plant(store, "UPDATE alert_instance SET reason=? WHERE connection=?", (foreign, planted))
    async with await _client(engine) as c:
        events = await c.get("/events")
        assert events.status_code == 200, events.text
        reasons = {e["connection"]: e["reason"] for e in events.json()["events"]}
        # The reason is masked for this caller, so the control reads as a non-empty mask.
        assert reasons[planted] is None and reasons[kept]
        alerts = await c.get("/alerts/active")
        assert alerts.status_code == 200, alerts.text
        by_conn = {a["connection"]: a["reason"] for a in alerts.json()["alerts"]}
        assert by_conn[planted] is None and by_conn[kept]
    assert "SYNTH-FOREIGN" not in events.text + alerts.text


async def test_dead_letters_and_messages_withhold_a_foreign_key_cell(
    keyed: tuple[Engine, MessageStore],
) -> None:
    engine, store = keyed
    ch, out, ch_msg = "IB_W_DEAD", "OB_W_DEAD", "IB_W_MSG"
    for _ in range(2):
        await store.enqueue_message(channel_id=ch, raw=RAW, deliveries=[(out, "B")])
        item = await store.claim_next_fifo(out)
        assert item is not None
        await store.dead_letter_now(item.id, "synthetic permanent reject")
        await store.record_received(
            channel_id=ch_msg,
            raw=RAW,
            status=MessageStatus.ERROR,
            error="SYNTH-ERROR",
            summary="SYNTH-SUMMARY",
        )
    async with await _client(engine) as c:
        before = await c.get("/dead-letters", params={"destination_name": out})
        assert before.status_code == 200, before.text
        dead = before.json()["dead_letters"]
        assert len(dead) == 2 and all(d["last_error"] for d in dead)
        listed = (await c.get("/messages", params={"channel_id": ch_msg})).json()["messages"]
        assert len(listed) == 2 and all(m["summary"] for m in listed)
        planted_msg, kept_msg = listed[0]["id"], listed[1]["id"]
        foreign = _foreign()
        await _plant(
            store, "UPDATE queue SET last_error=? WHERE id=?", (foreign, dead[0]["outbox_id"])
        )
        await _plant(store, "UPDATE messages SET summary=? WHERE id=?", (foreign, planted_msg))

        after = await c.get("/dead-letters", params={"destination_name": out})
        assert after.status_code == 200, after.text
        errors = {d["outbox_id"]: d["last_error"] for d in after.json()["dead_letters"]}
        assert errors[dead[0]["outbox_id"]] is None
        assert errors[dead[1]["outbox_id"]] == dead[1]["last_error"]  # control

        page = await c.get("/messages", params={"channel_id": ch_msg})
        assert page.status_code == 200, page.text
        summaries = {m["id"]: m["summary"] for m in page.json()["messages"]}
        assert summaries[planted_msg] is None
        assert summaries[kept_msg] == listed[1]["summary"]  # control
    assert "SYNTH-FOREIGN" not in after.text + page.text
