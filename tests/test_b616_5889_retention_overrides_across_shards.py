# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Per-connection body-retention overrides span every engine shard (BACKLOG #5889).

Under ``serve --shard`` each engine shard's ``RetentionRunner`` reads a registry that holds only its
own inbounds, while the body purge runs over the ONE unified store every engine shard shares (ADR
0063). Keyed off that filtered view, an engine shard applied the global cutoff to a sibling engine
shard's keep-forever or longer-window bodies. The engine-shard filter now pins the whole config's
``messages_days`` overrides, and the runner reads them. Synthetic HL7 only."""

from __future__ import annotations

from collections.abc import AsyncIterator
from pathlib import Path

import pytest

from messagefoundry.config.settings import RetentionSettings
from messagefoundry.config.wiring import MLLP, Registry, build_inbound_connection
from messagefoundry.pipeline.retention import RetentionRunner
from messagefoundry.pipeline.sharding import filter_registry_for_shard
from messagefoundry.store import MessageStore

DAY = 86_400.0
RAW = "MSH|^~\\&|SYNTH|SYNTH|||20260101000000||ADT^A01|C1|P|2.5.1"


@pytest.fixture
async def store(tmp_path: Path) -> AsyncIterator[MessageStore]:
    s = await MessageStore.open(tmp_path / "b616_5889.db")
    yield s
    await s.close()


async def _delivered(store: MessageStore, *, channel_id: str, control: str) -> str:
    mid = await store.enqueue_message(
        channel_id=channel_id,
        raw=RAW,
        deliveries=[("OB", "OUT|delivered")],
        control_id=control,
        now=0.0,
    )
    [row] = await store.outbox_for(mid)
    await store.claim_ready(now=0.0)
    await store.mark_done(row["id"], now=0.0)
    return mid


async def _raw(store: MessageStore, mid: str) -> str:
    msg = await store.get_message(mid)
    assert msg is not None
    return str(msg["raw"])


def _two_shard_registry() -> Registry:
    reg = Registry()
    reg.add_inbound(build_inbound_connection("IB_MINE", MLLP(port=2700), router="r", shard="s1"))
    reg.add_inbound(
        build_inbound_connection(
            "IB_SIB_KEEP", MLLP(port=2701), router="r", shard="s2", messages_days=0
        )
    )
    reg.add_inbound(
        build_inbound_connection(
            "IB_SIB_LONG", MLLP(port=2702), router="r", shard="s2", messages_days=365
        )
    )
    return reg


async def test_a_shard_purge_honours_a_sibling_shards_overrides(store: MessageStore) -> None:
    """Engine shard s1's runner purges its own inheriting inbound at the global window and leaves
    sibling engine shard s2's keep-forever and 365-day bodies alone.

    Mutation: read ``registry.inbound`` in ``RetentionRunner._resolve_overrides``, or drop
    ``all_inbound_messages_days`` from the engine-shard filter. Red."""
    mine = await _delivered(store, channel_id="IB_MINE", control="S-MINE")
    keep = await _delivered(store, channel_id="IB_SIB_KEEP", control="S-KEEP")
    long_ = await _delivered(store, channel_id="IB_SIB_LONG", control="S-LONG")

    s1 = filter_registry_for_shard(_two_shard_registry(), "s1")
    assert set(s1.inbound) == {"IB_MINE"}  # the precondition the purge must not rely on

    runner = RetentionRunner(
        store,
        RetentionSettings(messages_days=1),
        clock=lambda: 100 * DAY,
        registry_source=lambda: s1,
    )
    await runner.run_once()

    assert await _raw(store, mine) == ""  # this engine shard's inheriting inbound, global window
    assert await _raw(store, keep) == RAW  # sibling's keep-forever override
    assert await _raw(store, long_) == RAW  # sibling's 365-day override


def test_a_single_shard_config_pins_nothing() -> None:
    """A single-engine-shard config stays byte-identical to plain ``serve``: nothing is pinned."""
    reg = Registry()
    reg.add_inbound(build_inbound_connection("IB_A", MLLP(port=2710), router="r", messages_days=0))

    assert filter_registry_for_shard(reg, "default").all_inbound_messages_days is None


async def test_a_shard_id_matching_no_inbound_still_honours_the_overrides(
    store: MessageStore,
) -> None:
    """``serve --shard other`` against a single-engine-shard config selects no inbound, yet its
    runner still purges the unified store, so it must keep the keep-forever body.

    Mutation: pin ``all_inbound_messages_days`` only when sharded. Red."""
    reg = Registry()
    reg.add_inbound(build_inbound_connection("IB_A", MLLP(port=2711), router="r", messages_days=0))
    keep = await _delivered(store, channel_id="IB_A", control="S-A")
    gone = await _delivered(store, channel_id="IB_INHERIT", control="S-I")

    view = filter_registry_for_shard(reg, "other")
    assert view.inbound == {}  # the precondition: nothing selected, one shard in the config

    runner = RetentionRunner(
        store,
        RetentionSettings(messages_days=1),
        clock=lambda: 100 * DAY,
        registry_source=lambda: view,
    )
    await runner.run_once()

    assert await _raw(store, keep) == RAW
    assert await _raw(store, gone) == ""  # positive control: the purge ran


def test_the_override_map_is_keyed_by_connection_name() -> None:
    """The store keys bodies by ``channel_id`` = the connection's NAME, so the map must be too, even
    when a hand-built ``inbound`` dict's key differs.

    Mutation: key ``Registry.inbound_messages_days`` by the dict key. Red."""
    conn = build_inbound_connection("IB_REAL", MLLP(port=2720), router="r", messages_days=0)
    reg = Registry(inbound={"some_other_key": conn})

    assert reg.inbound_messages_days() == {"IB_REAL": 0}
