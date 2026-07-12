# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Per-message metadata bag — BACKLOG #150 / ADR 0081 acceptance criteria.

`SetMeta(key, value)` (a handler return, like `SetState`) is merged under the message's
`metadata.user` sub-key **inside** the exactly-once `transform_handoff` transaction, surfaced read-only
(PHI-redacted, internal correlation-lineage stripped) on the message API. The store-level merge is
verified on **both** SQLite and (gated) SQL Server; the partition/cap/API-strip logic is verified
directly.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, AsyncIterator

import pytest

from messagefoundry.config.wiring import META_MAX_KEYS, Registry, SetMeta
from messagefoundry.pipeline.dryrun import transform_one
from messagefoundry.store import MessageStatus, MessageStore, Stage
from messagefoundry.store.metadata import merge_user_metadata, user_metadata

RAW = "MSH|^~\\&|A|B|C|D|20260101||ADT^A01|MSG1|P|2.5.1\r"


# --- store fixture: SQLite always, SQL Server when MEFOR_TEST_SQLSERVER is set --------------------


async def _open_sqlserver() -> Any:
    from messagefoundry.config.settings import load_settings
    from messagefoundry.store.sqlserver import SqlServerStore

    store = await SqlServerStore.open(load_settings(environ=os.environ).store)
    async with store._pool.acquire() as conn:  # a clean slate — mirrors the other SS suites
        cur = await conn.cursor()
        for table in ("message_events", "state", "queue", "response", "outbox", "messages"):
            await cur.execute(f"DELETE FROM {table}")
        await conn.commit()
    return store


@pytest.fixture(params=["sqlite", "sqlserver"])
async def store(request: Any, tmp_path: Path) -> AsyncIterator[Any]:
    if request.param == "sqlserver":
        if not os.getenv("MEFOR_TEST_SQLSERVER"):
            pytest.skip("set MEFOR_TEST_SQLSERVER=1 (+ MEFOR_STORE_* env) for the SQL Server leg")
        s = await _open_sqlserver()
    else:
        s = await MessageStore.open(tmp_path / "meta.db")
    yield s
    await s.close()


async def _to_routed(store: Any, channel: str = "IB") -> tuple[str, Any]:
    """Drive a message ingress -> routed and return (message_id, claimed_routed_row)."""
    mid = await store.enqueue_ingress(channel_id=channel, raw=RAW)
    ing = await store.claim_next_fifo(channel, stage=Stage.INGRESS.value)
    await store.route_handoff(
        ingress_id=ing.id,
        message_id=mid,
        channel_id=channel,
        handlers=[("h", RAW)],
        disposition=MessageStatus.ROUTED,
    )
    rtd = await store.claim_next_fifo(channel, stage=Stage.ROUTED.value)
    return mid, rtd


async def _metadata(store: Any, mid: str) -> dict[str, Any] | None:
    msg = await store.get_message(mid)
    raw = msg["metadata"]
    return json.loads(raw) if raw else None


# --- criterion 1: SetMeta persists under metadata.user, inside the handoff transaction -----------


async def test_setmeta_persists_under_user_key(store: Any) -> None:
    mid, rtd = await _to_routed(store)
    handed = await store.transform_handoff(
        routed_id=rtd.id,
        message_id=mid,
        channel_id="IB",
        deliveries=[("OB1", "OUTBODY")],
        meta_ops=[("mrn_source", "ACME"), ("priority", "stat")],
    )
    assert handed is True
    meta = await _metadata(store, mid)
    assert meta is not None and meta["user"] == {"mrn_source": "ACME", "priority": "stat"}


# --- criterion 2: a re-run (already-consumed routed row) is an idempotent no-op ------------------


async def test_setmeta_idempotent_on_rerun(store: Any) -> None:
    mid, rtd = await _to_routed(store)
    await store.transform_handoff(
        routed_id=rtd.id,
        message_id=mid,
        channel_id="IB",
        deliveries=[("OB1", "B")],
        meta_ops=[("k", "v1")],
    )
    after_first = await _metadata(store, mid)
    # The routed row is consumed; a re-run with the same id is a no-op and must NOT re-merge.
    handed_again = await store.transform_handoff(
        routed_id=rtd.id,
        message_id=mid,
        channel_id="IB",
        deliveries=[("OB1", "B")],
        meta_ops=[("k", "v2")],
    )
    assert handed_again is False
    assert await _metadata(store, mid) == after_first  # unchanged: exactly-once


# --- criterion 3: the user bag coexists with ADR-0013 correlation lineage (pure merge) ----------


def test_user_bag_coexists_with_correlation_lineage() -> None:
    existing = json.dumps({"correlation_id": "PARENT", "correlation_depth": 2})
    merged = json.loads(merge_user_metadata(existing, [("mrn_source", "ACME")]))
    assert merged["correlation_id"] == "PARENT"  # lineage preserved, not clobbered
    assert merged["correlation_depth"] == 2
    assert merged["user"] == {"mrn_source": "ACME"}
    # last-writer-wins on a repeated key within a message
    twice = json.loads(merge_user_metadata(merge_user_metadata(None, [("k", "a")]), [("k", "b")]))
    assert twice["user"] == {"k": "b"}


# --- criterion 4: the API view is the user bag ONLY (internal lineage keys stripped) -------------


def test_metadata_surfaced_readonly_and_lineage_stripped() -> None:
    blob = json.dumps(
        {"correlation_id": "X", "correlation_depth": 1, "user": {"mrn_source": "ACME"}}
    )
    surfaced = user_metadata(blob)
    assert surfaced is not None
    assert json.loads(surfaced) == {"mrn_source": "ACME"}  # only the user bag
    assert "correlation_id" not in surfaced  # lineage never leaks
    assert user_metadata(json.dumps({"correlation_id": "X"})) is None  # no user bag -> null
    assert user_metadata(None) is None
    assert user_metadata(json.dumps({"user": {}})) is None  # empty bag -> null, not "{}"


# --- criterion 5: str values, and the per-message cap dead-letters (raises at transform) ---------


def test_setmeta_flows_through_transform_one() -> None:
    reg = Registry()
    reg.add_router("r", lambda m: ["h"])
    reg.add_handler("h", lambda m: [SetMeta("mrn_source", "ACME")])
    _deliveries, _state, meta = transform_one(reg, "h", RAW)
    assert [(m.key, m.value) for m in meta] == [("mrn_source", "ACME")]


def test_non_str_value_rejected_at_construction() -> None:
    with pytest.raises(Exception):  # WiringError: value must be a str
        SetMeta("k", 123)  # type: ignore[arg-type]


def test_key_count_cap_dead_letters() -> None:
    reg = Registry()
    reg.add_router("r", lambda m: ["h"])
    reg.add_handler("h", lambda m: [SetMeta(f"k{i}", "v") for i in range(META_MAX_KEYS + 1)])
    with pytest.raises(ValueError, match="per message"):
        transform_one(reg, "h", RAW)


def test_byte_cap_dead_letters() -> None:
    reg = Registry()
    reg.add_router("r", lambda m: ["h"])
    reg.add_handler("h", lambda m: [SetMeta("big", "x" * 5000)])
    with pytest.raises(ValueError, match="per message"):
        transform_one(reg, "h", RAW)


# --- criterion 6 (BACKLOG #68): the metadata bag feeds per-message dynamic HTTP headers ----------


async def test_message_metadata_json_feeds_dynamic_headers(store: Any) -> None:
    # The lightweight delivery-path read (#68) returns the SAME decrypted metadata get_message does,
    # and drives the exact chain the delivery worker + REST/FHIR use to derive per-message headers.
    from messagefoundry.transports.rest import outbound_headers_from_metadata

    mid, rtd = await _to_routed(store)
    await store.transform_handoff(
        routed_id=rtd.id,
        message_id=mid,
        channel_id="IB",
        deliveries=[("OB1", "OUTBODY")],
        meta_ops=[("http.header.X-Idempotency-Key", "idem-1"), ("note", "display-only")],
    )
    raw = await store.message_metadata_json(mid)
    assert raw is not None
    assert json.loads(raw) == json.loads((await store.get_message(mid))["metadata"])
    user_json = user_metadata(raw)
    assert user_json is not None
    headers = outbound_headers_from_metadata(json.loads(user_json))
    assert headers == {"X-Idempotency-Key": "idem-1"}  # the display-only 'note' key is not a header


async def test_message_metadata_json_absent_and_unknown(store: Any) -> None:
    mid, _rtd = await _to_routed(store)  # ingress/routed only — no SetMeta merged
    assert user_metadata(await store.message_metadata_json(mid)) is None  # no user bag yet
    assert await store.message_metadata_json("nonexistent-id") is None  # unknown message -> None
