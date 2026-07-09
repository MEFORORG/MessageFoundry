# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Bench-gated per-delivery phase timing (attribute the ~83 ms outbound delivery ceiling).

The rig measured a ~83 ms/delivery outbound ceiling with every tier idle; static analysis exonerated
engine CPU, the store, the claim path, and the dispatcher cadence, so the ~83 ms is a runtime cross-box
latency INSIDE the per-delivery body that loopback can't reproduce — either the connector send->ACK or
the store completion round-trip. ``RegistryRunner`` times BOTH sub-phases behind
``MEFOR_DELIVERY_PHASE_TIMING`` (default OFF) and emits a throttled per-process summary.

These prove: the env toggle parsing + OFF default; the accumulator's bounded aggregates + throttled
emit + window reset; and end-to-end that a real pooled delivery drives the accumulator and emits the
summary when ON, and takes NEITHER the timing nor the log path when OFF (byte-identical default). All
localhost / offscreen-safe / deterministic (no sleeps gate the assertions). No crypto imports here.
"""

from __future__ import annotations

import asyncio
import logging
import time
from pathlib import Path

import pytest

from messagefoundry.config.wiring import (
    ConnectionSpec,
    ConnectorType,
    InboundConnection,
    OutboundConnection,
    Registry,
    Send,
)
from messagefoundry.pipeline.wiring_runner import (
    DELIVERY_PHASE_TIMING_ENV,
    DeliveryPhaseTiming,
    RegistryRunner,
    _DELIVERY_PHASE_EMIT_INTERVAL,
    delivery_phase_timing_enabled,
)
from messagefoundry.store import MessageStatus, MessageStore, OutboxStatus

_LOGGER = "messagefoundry.pipeline.wiring_runner"

ADT = (
    "MSH|^~\\&|SND|SF|RCV|RF|20260604||ADT^A01|PT0001|P|2.5.1\r"
    "EVN|A01|20260604\r"
    "PID|1||100^^^H^MR||DOE^JANE\r"
)


# --- env toggle -------------------------------------------------------------------------------------


def test_toggle_off_by_default(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(DELIVERY_PHASE_TIMING_ENV, raising=False)
    assert delivery_phase_timing_enabled() is False


@pytest.mark.parametrize("val", ["1", "true", "TRUE", "yes", "on", " On "])
def test_toggle_on_for_truthy(monkeypatch: pytest.MonkeyPatch, val: str) -> None:
    monkeypatch.setenv(DELIVERY_PHASE_TIMING_ENV, val)
    assert delivery_phase_timing_enabled() is True


@pytest.mark.parametrize("val", ["", "0", "false", "no", "off", "banana"])
def test_toggle_off_for_falsey(monkeypatch: pytest.MonkeyPatch, val: str) -> None:
    monkeypatch.setenv(DELIVERY_PHASE_TIMING_ENV, val)
    assert delivery_phase_timing_enabled() is False


# --- accumulator ------------------------------------------------------------------------------------


def test_accumulator_bounded_aggregates() -> None:
    acc = DeliveryPhaseTiming()
    acc.record_send_ack(10_000_000)  # 10 ms
    acc.record_send_ack(30_000_000)  # 30 ms
    acc.record_mark_done(2_000_000)  # 2 ms
    assert acc.send_ack.count == 2
    assert acc.send_ack.sum_ns == 40_000_000
    assert acc.send_ack.max_ns == 30_000_000
    assert acc.send_ack.mean_ms() == pytest.approx(20.0)
    assert acc.send_ack.max_ms() == pytest.approx(30.0)
    assert acc.mark_done.count == 1
    assert acc.mark_done.mean_ms() == pytest.approx(2.0)


def test_accumulator_emits_then_resets_then_throttles(caplog: pytest.LogCaptureFixture) -> None:
    # The accumulator now lives in pipeline.phase_timing and defaults to that module's logger; the
    # RUNNER injects wiring_runner's logger so the shipped INFO line is unchanged (asserted by the
    # RegistryRunner tests below, which still capture on _LOGGER). Capture at the root so this unit
    # test pins the emit/reset/throttle behaviour rather than the class's home module.
    caplog.set_level(logging.INFO)
    acc = DeliveryPhaseTiming()  # _last_emit starts at 0.0 → the first maybe_emit always emits
    acc.record_send_ack(5_000_000)
    acc.record_mark_done(7_000_000)
    acc.maybe_emit(stage="outbound")

    summaries = [m for m in caplog.messages if "delivery phase timing" in m]
    assert len(summaries) == 1
    assert "stage=outbound" in summaries[0]
    assert "send_ack n=1" in summaries[0]
    assert "mark_done n=1" in summaries[0]
    # The window reset after emitting.
    assert acc.send_ack.count == 0
    assert acc.mark_done.count == 0

    # A second record immediately after is THROTTLED (well within the ~5 s window) — no new line, and
    # the counters accumulate into the next window rather than emitting per delivery.
    caplog.clear()
    acc.record_send_ack(9_000_000)
    acc.maybe_emit(stage="outbound")
    assert not [m for m in caplog.messages if "delivery phase timing" in m]
    assert acc.send_ack.count == 1  # retained for the next window


def test_accumulator_emit_interval_is_five_seconds() -> None:
    # Documented cadence: a per-process summary roughly every 5 s (never a line per delivery).
    assert _DELIVERY_PHASE_EMIT_INTERVAL == 5.0


# --- end-to-end through a real pooled delivery ------------------------------------------------------


class _Collector:
    """Non-capturing outbound (returns None → the mark_done phase). Records deliveries."""

    def __init__(self) -> None:
        self.deliveries: list[str] = []

    async def send(self, payload: str) -> None:
        self.deliveries.append(payload)
        return None

    async def aclose(self) -> None:
        return None


def _reg(inbox: Path, outdir: Path) -> Registry:
    reg = Registry()
    reg.add_inbound(
        InboundConnection(
            "file_in",
            ConnectionSpec(
                ConnectorType.FILE,
                {"directory": str(inbox), "pattern": "*.hl7", "poll_seconds": 0.05},
            ),
            router="r",
        )
    )
    reg.add_outbound(
        OutboundConnection(
            "file_out",
            ConnectionSpec(
                ConnectorType.FILE, {"directory": str(outdir), "filename": "{MSH-10}.hl7"}
            ),
        )
    )
    reg.add_router("r", lambda m: ["h"])
    reg.add_handler("h", lambda m: Send("file_out", m))
    return reg


@pytest.fixture
async def store(tmp_path: Path):  # type: ignore[no-untyped-def]
    s = await MessageStore.open(tmp_path / "phase.db")
    yield s
    await s.close()


async def _until(pred, *, timeout: float = 5.0) -> None:  # type: ignore[no-untyped-def]
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if await pred():
            return
        await asyncio.sleep(0.02)
    raise AssertionError("timed out waiting for condition")


async def test_delivery_records_and_emits_when_enabled(
    store: MessageStore,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    # Flag ON (set BEFORE construction — the runner resolves it once in __init__): one real pooled
    # delivery drives BOTH phases and emits the throttled summary. The first delivery emits immediately
    # (_last_emit starts at 0.0), so the assertion is deterministic without waiting a full window.
    monkeypatch.setenv(DELIVERY_PHASE_TIMING_ENV, "1")
    caplog.set_level(logging.INFO, logger=_LOGGER)
    inbox, outdir = tmp_path / "in", tmp_path / "out"
    inbox.mkdir()
    outdir.mkdir()
    runner = RegistryRunner(
        _reg(inbox, outdir), store, claim_mode="pooled", pooled_sweep_interval=0.05
    )
    assert runner._delivery_phase_timing is True
    await runner.start()
    collector = _Collector()
    runner._destinations["file_out"] = collector
    try:
        await runner._handle_inbound(runner.registry.inbound["file_in"], ADT.encode("utf-8"))

        async def _delivered() -> bool:
            return (await store.stats()).get(OutboxStatus.DONE.value, 0) >= 1

        await _until(_delivered)
        assert len(collector.deliveries) == 1
    finally:
        await runner.stop()

    summaries = [m for m in caplog.messages if "delivery phase timing" in m]
    assert summaries, "expected a phase-timing summary line when the flag is on"
    # BOTH sub-phases were recorded on the delivered row.
    assert "send_ack n=1" in summaries[0]
    assert "mark_done n=1" in summaries[0]
    assert "stage=outbound" in summaries[0]


async def test_delivery_untouched_when_disabled(
    store: MessageStore,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    # Default OFF: the timing path is NOT taken — no summary log, and the accumulator stays at zero
    # (a single bool check per delivery, no perf_counter / allocation).
    monkeypatch.delenv(DELIVERY_PHASE_TIMING_ENV, raising=False)
    caplog.set_level(logging.INFO, logger=_LOGGER)
    inbox, outdir = tmp_path / "in", tmp_path / "out"
    inbox.mkdir()
    outdir.mkdir()
    runner = RegistryRunner(
        _reg(inbox, outdir), store, claim_mode="pooled", pooled_sweep_interval=0.05
    )
    assert runner._delivery_phase_timing is False
    await runner.start()
    collector = _Collector()
    runner._destinations["file_out"] = collector
    try:
        await runner._handle_inbound(runner.registry.inbound["file_in"], ADT.encode("utf-8"))

        async def _delivered() -> bool:
            return (await store.stats()).get(OutboxStatus.DONE.value, 0) >= 1

        await _until(_delivered)
        assert len(collector.deliveries) == 1

        async def _processed() -> bool:
            msgs = await store.list_messages()
            return len(msgs) == 1 and msgs[0]["status"] == MessageStatus.PROCESSED.value

        await _until(_processed)
    finally:
        await runner.stop()

    assert not [m for m in caplog.messages if "delivery phase timing" in m]
    # The accumulator was never touched.
    assert runner._delivery_phase_stats.send_ack.count == 0
    assert runner._delivery_phase_stats.mark_done.count == 0
