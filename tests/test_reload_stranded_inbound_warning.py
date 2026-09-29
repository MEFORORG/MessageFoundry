# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #2348 (ADR 0157 Amendment A): a reload that drops an inbound WARNS, per inbound, with the
count of rows it leaves waiting.

Those rows key on the dropped inbound's ``channel_id``. No worker drains them and no queue alert asks
about them, and ``dead_letter_missing_inbounds`` runs only at the next engine start. Before this the
reload said nothing about them at all. The report runs as a detached task after the swap commits, so
each test settles it (:func:`_settle`) before reading the log.
"""

from __future__ import annotations

import asyncio
import logging
from pathlib import Path
from typing import Any

import pytest

from messagefoundry.pipeline.wiring_runner import RegistryRunner
from messagefoundry.store import MessageStore
from tests.test_adr0157_inc2_reload_recovery import RAW, _registry, _seed_pending_routed

_LOGGER = "messagefoundry.pipeline.wiring_runner"


@pytest.fixture
async def store(tmp_path: Path):
    s = await MessageStore.open(tmp_path / "reload-warn.db")
    yield s
    await s.close()


def _stranded_warnings(caplog: pytest.LogCaptureFixture) -> list[str]:
    return [
        r.getMessage()
        for r in caplog.records
        if r.name == _LOGGER
        and r.levelno == logging.WARNING
        and "reload dropped inbound" in r.getMessage()
    ]


async def _settle(runner: RegistryRunner) -> None:
    """Wait for every detached post-reload report to finish."""
    await asyncio.gather(*list(runner._reload_report_tasks))


async def _parked_runner(store: MessageStore, tmp_path: Path) -> RegistryRunner:
    """A running graph over IB and IB_LIVE. Its workers poll rarely, and the tests below push each
    seeded row's due time far out (:func:`_not_due`), so no worker can claim one whatever the timing.
    The rows stay PENDING, which is the state a dropped inbound's backlog is in."""
    runner = RegistryRunner(
        _registry(tmp_path / "in"), store, claim_mode="per_lane", poll_interval=30.0
    )
    await runner.start()
    return runner


async def _not_due(store: MessageStore) -> None:
    """Every PENDING row due in the far future: still PENDING, never claimable during a test."""
    await store._db.execute("UPDATE queue SET next_attempt_at=1e12 WHERE status='pending'")
    await store._db.commit()


async def test_a_reload_that_drops_an_inbound_warns_with_its_row_count(
    store: MessageStore, tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    for _ in range(2):
        await store.enqueue_ingress(channel_id="IB", raw=RAW)
    await _seed_pending_routed(store, "IB", "h", 1)
    await store.enqueue_ingress(channel_id="IB_LIVE", raw=RAW)  # control: kept, never warned
    await _not_due(store)
    runner = await _parked_runner(store, tmp_path)
    try:
        caplog.set_level(logging.WARNING, logger=_LOGGER)

        await runner.reload(_registry(tmp_path / "in", names=("IB_LIVE",)))
        await _settle(runner)

        warned = _stranded_warnings(caplog)
        assert len(warned) == 1, warned
        assert "'IB'" in warned[0]
        assert "at least 3 row(s)" in warned[0]
        assert "ingress 2, routed 1, response 0" in warned[0]
    finally:
        await runner.stop()


async def test_a_reload_that_drops_nothing_or_strands_nothing_is_silent(
    store: MessageStore, tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """The negative controls: the same graph reloaded, and a dropped inbound with no rows."""
    runner = await _parked_runner(store, tmp_path)
    try:
        await store.enqueue_ingress(channel_id="IB", raw=RAW)
        caplog.set_level(logging.WARNING, logger=_LOGGER)

        await runner.reload(runner.registry)
        await runner.reload(_registry(tmp_path / "in", names=("IB", "IB_LIVE", "IB_NEW")))
        await runner.reload(_registry(tmp_path / "in", names=("IB", "IB_LIVE")))  # drops IB_NEW
        await _settle(runner)

        assert _stranded_warnings(caplog) == []
    finally:
        await runner.stop()


async def test_a_rolled_back_reload_warns_of_nothing(
    store: MessageStore,
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The swap never committed, so IB was never dropped and no report starts. Mutation: start the
    report inside reload's ``try`` and this fails."""
    await store.enqueue_ingress(channel_id="IB", raw=RAW)
    await _not_due(store)
    runner = await _parked_runner(store, tmp_path)
    try:

        async def fail_reconcile(*_a: Any, **_k: Any) -> None:
            raise RuntimeError("outbound reconcile failed")

        monkeypatch.setattr(runner, "_reconcile_outbounds", fail_reconcile)
        caplog.set_level(logging.WARNING, logger=_LOGGER)

        with pytest.raises(RuntimeError, match="outbound reconcile failed"):
            await runner.reload(_registry(tmp_path / "in", names=("IB_LIVE",)))

        assert not runner._reload_report_tasks  # no report was started
        assert "IB" in runner.registry.inbound  # rolled back
        await _settle(runner)
        assert _stranded_warnings(caplog) == []
    finally:
        await runner.stop()


async def test_the_drop_is_keyed_on_the_whole_deployment(
    store: MessageStore, tmp_path: Path
) -> None:
    """Keyed on ``inbound_names()``, as the startup sweep is. Under engine sharding an inbound absent
    from THIS shard's slice but still in the deployment is a sibling's live lane. Covered as a slice
    move between two filtered registries, which is the shape a sharded reload has, and as a real drop
    from the deployment."""
    await store.enqueue_ingress(channel_id="IB", raw=RAW)
    whole = frozenset({"IB", "IB_LIVE"})
    old_slice = _registry(tmp_path / "in", names=("IB",))
    old_slice.all_inbound = whole
    new_slice = _registry(tmp_path / "in", names=("IB_LIVE",))
    new_slice.all_inbound = whole
    runner = RegistryRunner(new_slice, store, claim_mode="per_lane")

    # IB moved to a sibling shard: still in the deployment, so not dropped.
    assert await runner._warn_stranded_by_dropped_inbounds(old_slice, new_slice) == {}

    # IB left the deployment.
    gone = _registry(tmp_path / "in", names=("IB_LIVE",))
    gone.all_inbound = frozenset({"IB_LIVE"})
    runner.registry = gone
    assert await runner._warn_stranded_by_dropped_inbounds(old_slice, gone) == {"IB": 1}


async def test_an_inbound_a_later_reload_re_added_is_skipped(
    store: MessageStore, tmp_path: Path
) -> None:
    """The report runs detached, so a later reload can restore the inbound before it counts. Its lane
    is live again, and warning about it would be a false alert."""
    await store.enqueue_ingress(channel_id="IB", raw=RAW)
    full = _registry(tmp_path / "in")
    runner = RegistryRunner(full, store, claim_mode="per_lane")  # the live registry still has IB

    dropped = _registry(tmp_path / "in", names=("IB_LIVE",))
    assert await runner._warn_stranded_by_dropped_inbounds(full, dropped) == {}


async def test_a_failed_count_logs_and_never_fails_the_reload(
    store: MessageStore,
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runner = await _parked_runner(store, tmp_path)
    try:
        await store.enqueue_ingress(channel_id="IB", raw=RAW)

        async def boom(*_a: Any, **_k: Any) -> Any:
            raise RuntimeError("store blip")

        monkeypatch.setattr(store, "pending_depth", boom)
        caplog.set_level(logging.WARNING, logger=_LOGGER)

        await runner.reload(_registry(tmp_path / "in", names=("IB_LIVE",)))  # must not raise
        await _settle(runner)

        assert any("could not count" in m for m in _stranded_warnings(caplog))
        assert set(runner.registry.inbound) == {"IB_LIVE"}
    finally:
        await runner.stop()
