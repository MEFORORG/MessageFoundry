# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Cross-backend contract for the message and preset cell tags (BACKLOG #2593).

Extra-free, on the ``_queue_tag_contract`` precedent: it imports nothing optional, so the live
Postgres and SQL Server suites import it inside their test functions and run the same assertions on
legs that install only their own driver extra.

The caller passes a store opened with a store key under the cell-bound writer (``write_v2=True``),
and two adapters for the same database that bypass the store: ``raw`` runs one statement and commits,
and ``fetch`` runs one query and returns its rows as dicts. Both take SQL written with ``?``
placeholders; each backend's adapter respells them for its driver.

Every refused read has a control beside it: the same kind of row, left alone, reads. A tag that
refused everything, or bound nothing, fails this contract.
"""

from __future__ import annotations

import json
from collections.abc import Awaitable, Callable
from typing import Any

from messagefoundry.store.cell_tag import MESSAGE_TAG_FAILED_ACTION, PRESET_TAG_FAILED_ACTION
from messagefoundry.store.content_search import make_spec
from messagefoundry.store.store import MessageStatus, OutboxStatus, Stage

#: Runs one statement with ``?`` placeholders against the store's database, outside the store.
RawSql = Callable[[str, tuple[Any, ...]], Awaitable[None]]
#: Runs one query with ``?`` placeholders outside the store and returns its rows as dicts.
RawFetch = Callable[[str, tuple[Any, ...]], Awaitable[list[dict[str, Any]]]]

_RAW = "MSH|^~\\&|SYNTH|F|R|RF|20260101||ADT^A01|CT1|P|2.5.1\rPID|1||SYNTH-200||DOE^JOHN\r"
_META = json.dumps({"user": {"k": "SYNTH-META"}})


class _Hook:
    """Records each tag-failure alert the store's cipher raises."""

    def __init__(self) -> None:
        self.alerts: list[tuple[str, str]] = []

    def __call__(self, table: str, reason: str) -> None:
        self.alerts.append((table, reason))

    def saw(self, table: str, row_id: str) -> bool:
        return any(t == table and row_id[:12] in r for t, r in self.alerts)


async def _message(store: Any, channel_id: str) -> str:
    return str(
        await store.record_received(
            channel_id=channel_id,
            raw=_RAW,
            status=MessageStatus.ERROR,
            error="SYNTH-ERROR",
            summary="SYNTH-SUMMARY",
            metadata=_META,
        )
    )


async def _audited(fetch: RawFetch, action: str, row_id: str) -> int:
    rows = await fetch(
        "SELECT detail FROM audit_log WHERE action=? AND detail LIKE ?",
        (action, f"%{row_id[:12]}%"),
    )
    return len(rows)


async def _refused(call: Callable[[], Awaitable[Any]], label: str) -> None:
    try:
        await call()
    except Exception as exc:  # noqa: BLE001 -- the refusal type is the cipher's, asserted below
        assert "integrity" in str(exc), (label, exc)
    else:
        raise AssertionError(f"{label}: a read of a cell that fails its tag was not refused")


def _assert_reads(message: dict[str, Any] | None) -> None:
    assert message is not None
    assert message["raw"] == _RAW
    assert message["error"] == "SYNTH-ERROR"
    assert message["summary"] == "SYNTH-SUMMARY"
    assert message["metadata"] == _META


async def assert_cell_tag_contract(store: Any, raw: RawSql, fetch: RawFetch) -> None:
    """Drive the message and preset tags through their whole contract on ``store``'s backend."""
    cipher = store.cipher()
    assert cipher.encrypts, "the contract needs a store opened with a store key"
    hook = _Hook()
    cipher.set_tag_failure_hook(hook)

    # --- control: an untouched message reads in full ------------------------------------------
    ctl = await _message(store, "IB_CT_A")
    _assert_reads(await store.get_message(ctl))
    assert await store.message_metadata_json(ctl) == _META

    # --- a message moved to another channel is refused, alerted and audited ---------------------
    moved = await _message(store, "IB_CT_B")
    await raw("UPDATE messages SET channel_id=? WHERE id=?", ("IB_CT_A", moved))
    await _refused(lambda: store.get_message(moved), "get_message")
    assert hook.saw("messages", moved)
    assert await _audited(fetch, MESSAGE_TAG_FAILED_ACTION, moved) == 1
    await _refused(lambda: store.message_metadata_json(moved), "message_metadata_json")
    assert await _audited(fetch, MESSAGE_TAG_FAILED_ACTION, moved) == 2

    # The list still shows the moved row by its plaintext columns, its cells withheld; the
    # untouched row beside it lists in full.
    listed = {
        r["id"]: r for r in await store.list_messages(channel_id="IB_CT_A", allowed_channels=None)
    }
    assert listed[ctl]["summary"] == "SYNTH-SUMMARY" and listed[ctl]["metadata"] == _META
    assert listed[moved]["summary"] is None and listed[moved]["error"] is None
    assert listed[moved]["metadata"] is None and listed[moved]["channel_id"] == "IB_CT_A"

    # Content search cannot match a moved row; the untouched row still matches.
    found = await store.search_messages(
        make_spec(content="SYNTH-200", field_path=None, field_value=None),
        channel_id="IB_CT_A",
        allowed_channels=None,
    )
    assert [r["id"] for r in found.rows] == [ctl], found.rows

    # --- a cell copied onto another row of the same channel is refused --------------------------
    m1 = await _message(store, "IB_CT_C")
    m2 = await _message(store, "IB_CT_C")
    cells = {
        r["id"]: r for r in await fetch("SELECT id, raw FROM messages WHERE id IN (?, ?)", (m1, m2))
    }
    await raw("UPDATE messages SET raw=? WHERE id=?", (cells[m2]["raw"], m1))
    await _refused(lambda: store.get_message(m1), "swapped raw")
    _assert_reads(await store.get_message(m2))  # control: the source row still reads

    # --- a dead-letter list keeps a moved message's row and withholds its summary ---------------
    dmid = await store.enqueue_message(
        channel_id="IB_CT_D", raw=_RAW, summary="SYNTH-SUMMARY", deliveries=[("OB_CT_D", "B")]
    )
    item = await store.claim_next_fifo("OB_CT_D")
    assert item is not None
    await store.dead_letter_now(item.id, "synthetic permanent reject")
    dctl = await store.enqueue_message(
        channel_id="IB_CT_D", raw=_RAW, summary="SYNTH-SUMMARY", deliveries=[("OB_CT_D", "B")]
    )
    item = await store.claim_next_fifo("OB_CT_D")
    assert item is not None
    await store.dead_letter_now(item.id, "synthetic permanent reject")
    await raw("UPDATE messages SET channel_id=? WHERE id=?", ("IB_CT_E", dmid))
    dead = {
        r["message_id"]: r
        for r in await store.list_dead(destination_name="OB_CT_D", allowed_channels=None)
    }
    assert dead[dctl]["summary"] == "SYNTH-SUMMARY"  # control
    assert dead[dmid]["summary"] is None
    assert await _audited(fetch, MESSAGE_TAG_FAILED_ACTION, dmid) == 1

    # --- an edit-and-resubmit from a moved origin is refused -----------------------------------
    outcome = await store.reingress(
        origin_message_id=ctl, raw=_RAW, idempotency_key="ct-reingress-ctl"
    )
    assert outcome.status != "duplicate"  # control: an untouched origin resubmits
    await _refused(
        lambda: store.reingress(
            origin_message_id=moved, raw=_RAW, idempotency_key="ct-reingress-moved"
        ),
        "reingress",
    )

    # --- a transform handoff on a moved message dead-letters the routed row --------------------
    await _assert_transform_handoff(store, raw, fetch, hook)

    # --- presets: one moved to another owner is refused ----------------------------------------
    await _assert_presets(store, raw, fetch, hook)


async def _routed(store: Any, fetch: RawFetch, channel_id: str) -> tuple[str, str]:
    """A message with metadata, routed to one handler; returns its id and the routed row id."""
    mid = await store.enqueue_ingress(channel_id=channel_id, raw=_RAW, metadata=_META)
    ingress = await store.claim_next_fifo(channel_id, stage=Stage.INGRESS.value)
    assert ingress is not None
    await store.route_handoff(
        ingress_id=ingress.id,
        message_id=mid,
        channel_id=channel_id,
        handlers=[("H_CT", _RAW)],
        disposition=MessageStatus.ROUTED,
    )
    routed = await store.claim_next_fifo(channel_id, stage=Stage.ROUTED.value)
    assert routed is not None
    return mid, str(routed.id)


async def _assert_transform_handoff(store: Any, raw: RawSql, fetch: RawFetch, hook: _Hook) -> None:
    async def handoff(mid: str, routed_id: str, channel_id: str) -> bool:
        return bool(
            await store.transform_handoff(
                routed_id=routed_id,
                message_id=mid,
                channel_id=channel_id,
                deliveries=[("OB_CT_T", "SYNTH-OUT")],
                meta_ops=[("added", "SYNTH-ADDED")],
            )
        )

    # Control: an untouched message hands off, and its merged metadata reads back.
    mid, rid = await _routed(store, fetch, "IB_CT_T")
    assert await handoff(mid, rid, "IB_CT_T") is True
    merged = json.loads(await store.message_metadata_json(mid) or "{}")
    assert merged["user"]["added"] == "SYNTH-ADDED"

    mid, rid = await _routed(store, fetch, "IB_CT_U")
    await raw("UPDATE messages SET channel_id=? WHERE id=?", ("IB_CT_T", mid))
    assert await handoff(mid, rid, "IB_CT_U") is False
    rows = await fetch("SELECT status, stage FROM queue WHERE message_id=?", (mid,))
    assert rows == [{"status": OutboxStatus.DEAD.value, "stage": Stage.ROUTED.value}], rows
    status = await fetch("SELECT status FROM messages WHERE id=?", (mid,))
    assert status[0]["status"] == MessageStatus.ERROR.value
    assert hook.saw("messages", mid)
    assert await _audited(fetch, MESSAGE_TAG_FAILED_ACTION, mid) == 1


async def _assert_presets(store: Any, raw: RawSql, fetch: RawFetch, hook: _Hook) -> None:
    criteria = json.dumps({"content": "SYNTH-200"})
    ctl, _ = await store.upsert_search_preset(
        preset_id="ct-preset-ctl", owner_user_id="u-ct-2", name="ctl", criteria=criteria
    )
    pid, _ = await store.upsert_search_preset(
        preset_id="ct-preset-moved", owner_user_id="u-ct-1", name="moved", criteria=criteria
    )
    got = await store.get_search_preset(preset_id=pid, owner_user_id="u-ct-1")
    assert got is not None and got["criteria"] == criteria  # control, before the move
    await raw("UPDATE search_presets SET owner_user_id=? WHERE id=?", ("u-ct-2", pid))
    await _refused(lambda: store.get_search_preset(preset_id=pid, owner_user_id="u-ct-2"), "preset")
    assert hook.saw("search_presets", pid)
    assert await _audited(fetch, PRESET_TAG_FAILED_ACTION, pid) == 1
    got = await store.get_search_preset(preset_id=ctl, owner_user_id="u-ct-2")
    assert got is not None and got["criteria"] == criteria  # control: the owner's own preset
