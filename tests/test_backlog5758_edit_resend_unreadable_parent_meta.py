# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The operator's way out of the dead letter for a message whose metadata cell a pass-through
transform handoff refused (BACKLOG #5758).

That handoff now dead-letters the cell. Edit-and-resend and edit-and-resubmit read the same cell to
correlate their child, and their unguarded ``int(correlation_depth)`` raised out of the API as a
500. They now refuse it as a 409 that names the message only, and write nothing: the dead-lettered
row stays, and the idempotency key stays free. A cell that resubmitted before still resubmits.

SQLite runs for real, through ``POST /messages/{id}/edit-resend``. Postgres and SQL Server build
the child's metadata with the same helper, which is tested directly here."""

from __future__ import annotations

import inspect
import json
import logging
from pathlib import Path

import httpx
import pytest

from messagefoundry.config.settings import EgressSettings
from messagefoundry.pipeline import Engine
from messagefoundry.pipeline.refused_body import head_only_resubmit_refusal
from messagefoundry.store import MessageStatus, OutboxStatus, Stage
from messagefoundry.store.base import ResendError, ResendOriginMetadataUnreadable
from messagefoundry.store.postgres import PostgresStore
from messagefoundry.store.sqlserver import SqlServerStore
from messagefoundry.store.store import MessageStore, edit_child_metadata
from tests.test_backlog5758_transform_handoff_parent_meta import (
    _OVERFLOW_ROOT_CELL,
    _SENTINEL,
    BAD_CELLS,
    DELIVERED_CELLS,
    encoder_overflows_on_root,  # noqa: F401 -- a fixture, used by name
)
from tests.test_edit_resend import ADT, EDITED, _registry

# Every cell the transform handoff dead-letters that the edit paths cannot correlate. A cell that is
# not JSON at all is dead-lettered too, but the edit paths read it as no lineage, as on main.
REFUSED = {name: cell for name, cell in BAD_CELLS.items() if name != "malformed-json"}
# Cells the edit paths resubmit, on main and here.
RESUBMITTED = {**DELIVERED_CELLS, "malformed-json": BAD_CELLS["malformed-json"]}

_MODES = pytest.mark.parametrize("to", [None, "OB2"], ids=["reroute", "direct"])


async def _dead_lettered(engine: Engine, cell: str) -> str:
    """A message on ``in1`` whose routed row the pass-through handoff dead-lettered for ``cell``."""
    store = engine.store
    assert isinstance(store, MessageStore)
    mid = await store.enqueue_ingress(channel_id="in1", raw=ADT)
    ing = await store.claim_next_fifo("in1", stage=Stage.INGRESS.value)
    assert ing is not None
    await store.route_handoff(
        ingress_id=ing.id,
        message_id=mid,
        channel_id="in1",
        handlers=[("h", ADT)],
        disposition=MessageStatus.ROUTED,
    )
    rtd = await store.claim_next_fifo("in1", stage=Stage.ROUTED.value)
    assert rtd is not None
    await store._db.execute("UPDATE messages SET metadata=? WHERE id=?", (cell, mid))
    await store._db.commit()
    assert (
        await store.transform_handoff(
            routed_id=rtd.id,
            message_id=mid,
            channel_id="in1",
            deliveries=[],
            pt_deliveries=[("PT_5758", ADT)],
        )
        is False
    )
    return mid


async def _queue_rows(store: MessageStore, mid: str) -> list[tuple[str, str]]:
    cur = await store._db.execute("SELECT stage, status FROM queue WHERE message_id=?", (mid,))
    return [(str(r[0]), str(r[1])) for r in await cur.fetchall()]


async def _count(store: MessageStore, table: str) -> int:
    cur = await store._db.execute(f"SELECT COUNT(*) FROM {table}")  # noqa: S608 -- a fixed name
    row = await cur.fetchone()
    assert row is not None
    return int(row[0])


async def _post_edit(engine: Engine, mid: str, to: str | None) -> httpx.Response:
    from messagefoundry.api import create_app

    payload: dict[str, object] = {"raw": EDITED, "idempotency_key": "k5758"}
    if to is not None:
        payload["to"] = to
    # raise_app_exceptions=False: an unhandled error reaches the test as the 500 an operator sees.
    transport = httpx.ASGITransport(
        app=create_app(engine, allow_no_auth=True), raise_app_exceptions=False
    )
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as client:
        return await client.post(f"/messages/{mid}/edit-resend", json=payload)


async def _engine(tmp_path: Path) -> Engine:
    pytest.importorskip("psutil")
    engine = await Engine.create(
        tmp_path / "t5758edit.db",
        poll_interval=0.02,
        egress_settings=EgressSettings(deny_by_default=False),
    )
    engine.add_registry(_registry(tmp_path))
    return engine


async def _assert_refused_and_untouched(
    engine: Engine, mid: str, to: str | None, caplog: pytest.LogCaptureFixture
) -> None:
    store = engine.store
    assert isinstance(store, MessageStore)
    messages_before = await _count(store, "messages")
    caplog.clear()
    with caplog.at_level(logging.WARNING):
        r = await _post_edit(engine, mid, to)
    assert r.status_code == 409, r.text
    # The positive control for the redaction check below: the refusal was logged, and captured.
    assert any(
        "edit was refused" in rec.getMessage() and mid in rec.getMessage() for rec in caplog.records
    )
    assert "does not hold readable correlation metadata" in r.json()["detail"]
    assert mid in r.json()["detail"]
    assert _SENTINEL not in r.text and _SENTINEL not in caplog.text
    # Nothing was written: no child, the dead-lettered row as it was, and the key still free.
    assert await _count(store, "messages") == messages_before
    assert await _queue_rows(store, mid) == [(Stage.ROUTED.value, OutboxStatus.DEAD.value)]
    message = await store.get_message(mid)
    assert message is not None and message["status"] == MessageStatus.ERROR.value
    assert await store.get_resend_record("k5758") is None


@_MODES
@pytest.mark.parametrize("cell", list(REFUSED.values()), ids=list(REFUSED))
async def test_edit_resend_of_a_dead_lettered_cell_is_a_409(
    tmp_path: Path, cell: str, to: str | None, caplog: pytest.LogCaptureFixture
) -> None:
    engine = await _engine(tmp_path)
    try:
        mid = await _dead_lettered(engine, cell)
        await engine.start()
        await _assert_refused_and_untouched(engine, mid, to, caplog)
    finally:
        await engine.stop()


@_MODES
@pytest.mark.usefixtures("encoder_overflows_on_root")
async def test_edit_resend_of_a_root_the_encoder_cannot_serialize_is_a_409(
    tmp_path: Path, to: str | None, caplog: pytest.LogCaptureFixture
) -> None:
    engine = await _engine(tmp_path)
    try:
        mid = await _dead_lettered(engine, _OVERFLOW_ROOT_CELL)
        await engine.start()
        await _assert_refused_and_untouched(engine, mid, to, caplog)
    finally:
        await engine.stop()


@_MODES
async def test_edit_resend_of_a_non_json_cell_still_resubmits(
    tmp_path: Path, to: str | None
) -> None:
    """The handoff dead-letters a cell that is not JSON, and the edit paths read it as no lineage,
    as on main, so the operator's way out still works for it."""
    engine = await _engine(tmp_path)
    try:
        mid = await _dead_lettered(engine, BAD_CELLS["malformed-json"])
        await engine.start()
        r = await _post_edit(engine, mid, to)
        assert r.status_code == 200, r.text
        assert r.json()["status"] == ("resent" if to else "resubmitted")
    finally:
        await engine.stop()


# --- the shared helper, which all three stores call -------------------------------------------


@pytest.mark.parametrize("cell", list(REFUSED.values()), ids=list(REFUSED))
def test_helper_refuses_a_cell_it_cannot_correlate(
    cell: str, caplog: pytest.LogCaptureFixture
) -> None:
    with caplog.at_level(logging.WARNING), pytest.raises(ResendOriginMetadataUnreadable) as caught:
        edit_child_metadata(cell, origin_message_id="origin-1")
    assert any("origin-1" in rec.getMessage() for rec in caplog.records)
    assert _SENTINEL not in caplog.text
    err = caught.value
    assert isinstance(err, ResendError)  # the API's 409 mapping
    assert _SENTINEL not in str(err)
    # Raised outside the except: json's error holds the whole cell.
    assert err.__cause__ is None and err.__context__ is None


@pytest.mark.usefixtures("encoder_overflows_on_root")
def test_helper_refuses_a_root_the_encoder_cannot_serialize() -> None:
    with pytest.raises(ResendOriginMetadataUnreadable):
        edit_child_metadata(_OVERFLOW_ROOT_CELL, origin_message_id="origin-1")


@pytest.mark.parametrize(
    "cell", [None, "", *RESUBMITTED.values()], ids=["none", "empty", *RESUBMITTED]
)
def test_helper_still_correlates_every_cell_main_correlated(cell: str | None) -> None:
    meta = json.loads(edit_child_metadata(cell, origin_message_id="origin-1"))
    assert meta["correlation_id"] == "origin-1" and meta["edited_from"] == "origin-1"
    assert isinstance(meta["correlation_depth"], int)


def test_helper_carries_a_readable_lineage() -> None:
    cell = json.dumps({"correlation_depth": 4, "correlation_root_id": "the-root"})
    meta = json.loads(edit_child_metadata(cell, origin_message_id="origin-1"))
    assert meta == {
        "correlation_id": "origin-1",
        "correlation_root_id": "the-root",
        "correlation_depth": 5,
        "edited_from": "origin-1",
    }


@pytest.mark.parametrize("store_cls", [MessageStore, PostgresStore, SqlServerStore])
@pytest.mark.parametrize("method", ["resend_to", "reingress"])
def test_every_store_builds_the_edit_child_with_the_helper(store_cls: type, method: str) -> None:
    """Postgres and SQL Server have no live server here, so this pins that they share the helper."""
    source = inspect.getsource(getattr(store_cls, method))
    assert "edit_child_metadata(" in source
    assert 'int(parent_meta.get("correlation_depth"' not in source


def test_head_only_check_reads_a_too_deep_cell_as_no_refusal() -> None:
    """The route's head-only check runs before the store; a cell too deep to decode is not a
    head-only refusal, so the store's own 409 answers it rather than a RecursionError."""
    assert head_only_resubmit_refusal("origin-1", BAD_CELLS["deep-nesting"]) is None
