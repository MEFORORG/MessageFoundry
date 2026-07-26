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

**S_lane (STEP 4 ARM 1)** — the second half of this file pins :class:`LaneEpisodeTiming`, the LANE
EPISODE instrument: reserve (READY→CLAIMING, ``_slots_free`` decrements) → release at quiesce after
PROCESSING. A lane is a single-server queue, so ``lambda_max ~= 1/S_lane`` **by definition** — measured,
not derived from ``N = lambda x W`` (Little's law is an identity and cannot test itself). The
load-bearing property is the DROP set: a pause / claim-error / empty / rearm / RETRY / STOP / teardown
release rendered no service. The empty + rearm releases in particular are frequent and sub-millisecond —
booking them would drag ``S_lane`` toward the bare claim time and manufacture the "lanes do not bind"
verdict on the very question ARM 1 exists to answer. So the drops are tested as hard as the book.
"""

from __future__ import annotations

import asyncio
import logging
import re
import time
from pathlib import Path
from typing import Any

import pytest

from messagefoundry.config.wiring import (
    ConnectionSpec,
    ConnectorType,
    InboundConnection,
    OutboundConnection,
    Registry,
    Send,
)
from messagefoundry.pipeline.phase_timing import (
    LANE_EPISODE_TIMING_ENV,
    LaneEpisodeTiming,
)
from messagefoundry.pipeline.stage_dispatcher import (
    LaneItemResult,
    LaneResultKind,
    StageDispatcher,
)
from messagefoundry.pipeline.wiring_runner import (
    _DELIVERY_PHASE_EMIT_INTERVAL,
    DELIVERY_PHASE_TIMING_ENV,
    DeliveryPhaseTiming,
    RegistryRunner,
    delivery_phase_timing_enabled,
)
from messagefoundry.store import (
    ClaimedHeads,
    MessageStatus,
    MessageStore,
    OutboxItem,
    OutboxStatus,
    Stage,
)

_LOGGER = "messagefoundry.pipeline.wiring_runner"
_DISPATCHER_LOGGER = "messagefoundry.pipeline.stage_dispatcher"

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
    monkeypatch.setenv(
        LANE_EPISODE_TIMING_ENV, "1"
    )  # S_lane rides its OWN lever (see phase_timing)
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


# =====================================================================================================
# S_lane — the LANE EPISODE instrument (STEP 4 ARM 1). Reserve (READY→CLAIMING, _slots_free--) →
# release at quiesce after PROCESSING. lambda_max = 1/S_lane BY DEFINITION (single-server lane), so
# nothing here touches Little's law. The DROP set is the correctness crux — see the module docstring.
# =====================================================================================================

#: A lane key IS a destination_name (a partner name) — the PHI canary these tests assert never leaks.
_LANE = "OB_ACME_ADT"

#: Kept in lockstep with ``shardcert_ladder._EPISODE_RE`` — the harness parses this exact line, so a shape
#: change that broke the rig's parser would otherwise show up only on the rig.
_EPISODE_RE = re.compile(
    r"lane episode timing \(stage=(?P<stage>\w+)\): "
    r"episode n=(?P<n>\d+) mean=(?P<mean>[\d.]+)ms max=(?P<max>[\d.]+)ms \| "
    r"rows/episode=(?P<rows>[\d.]+) lambda_max_per_lane=(?P<lam>[\d.]+)/s \| "
    r"dropped n=(?P<dropn>\d+) sum=(?P<dropsum>[\d.]+)ms \| "
    r"lanes=(?P<lanes>\d+) slots=(?P<slots>\d+) window=(?P<window>[\d.]+)s "
    r"utilization=(?P<util>[\d.]+)"
)


def _episode_lines(caplog: pytest.LogCaptureFixture) -> list[str]:
    return [m for m in caplog.messages if "lane episode timing" in m]


def _item(lane: str, n: int = 1) -> OutboxItem:
    return OutboxItem(
        id=f"{lane}-{n}",
        message_id=f"m{n}",
        channel_id="ib",
        destination_name=lane,
        payload="MSH|^~\\&|SND|SF|RCV|RF|20260604||ADT^A01|PT0001|P|2.5.1\r",
        attempts=1,
        stage=Stage.OUTBOUND.value,
    )


class _EpisodeStore:
    """Serves each seeded lane ONE head on its first claim and nothing after — so a lane runs exactly one
    real episode (reserve → claim → PROCESSING → drain → release) and every later claim comes back EMPTY
    (a DROP). ``rearm_lanes`` makes the FIRST claim a rearm-only (H2 skip-and-complete) claim instead."""

    def __init__(self, *, lanes: set[str], rearm_lanes: set[str] | None = None) -> None:
        self.claim_calls = 0
        self.released: list[str] = []
        self.rescheduled: list[str] = []
        self._pending: dict[str, list[OutboxItem]] = {lane: [_item(lane)] for lane in lanes}
        self._rearm: set[str] = set(rearm_lanes or ())

    async def claim_fifo_heads(
        self, stage: str, lanes: list[str], *, now: float | None = None, per_lane_limit: int = 1
    ) -> ClaimedHeads:
        self.claim_calls += 1
        await asyncio.sleep(0)  # a real store awaits; keep the suspension point honest
        by_lane: dict[str, list[OutboxItem]] = {}
        rearm: set[str] = set()
        for lane in lanes:
            if lane in self._rearm:
                self._rearm.discard(lane)  # rearm ONCE, then the lane claims empty
                rearm.add(lane)
                continue
            items = self._pending.pop(lane, None)
            if items:
                by_lane[lane] = items
        return ClaimedHeads(by_lane=by_lane, rearm=frozenset(rearm))

    async def list_fifo_lanes(
        self, stage: str, now: float | None = None, *, limit: int = 4096, after: str | None = None
    ) -> list[tuple[str, float]]:
        return []

    async def release_claimed(self, ids: list[str]) -> None:
        self.released.extend(ids)

    async def reschedule_claimed(self, ids: list[str], when: float) -> None:
        self.rescheduled.extend(ids)


async def _resolved(lane: str, item: OutboxItem) -> LaneItemResult:
    return LaneItemResult(kind=LaneResultKind.RESOLVED)


def _episode_dispatcher(
    store: Any, lanes: set[str], process_item: Any = _resolved
) -> StageDispatcher:
    return StageDispatcher(
        Stage.OUTBOUND,
        store,
        process_item=process_item,
        lane_provider=lambda: set(lanes),
        per_lane_limit=1,  # hard-1, as OUTBOUND forces
        claimers_per_stage=1,
        sweep_interval=10_000.0,  # never sweep — start()'s seed drives the one claim these tests need
    )


# --- the accumulator ---------------------------------------------------------------------------------


def test_lane_episode_accumulator_bounded_aggregates() -> None:
    acc = LaneEpisodeTiming()
    acc.record_episode(60_000_000)  # 60 ms
    acc.record_episode(65_000_000)  # 65 ms
    acc.record_dropped(13_000_000)  # 13 ms of empty-claim occupancy — NOT a service
    assert acc.episode.count == 2
    assert acc.episode.sum_ns == 125_000_000
    assert acc.episode.max_ns == 65_000_000
    assert acc.episode.mean_ms() == pytest.approx(62.5)
    assert acc.rows == 2  # rows defaults to 1/episode (the hard-1 OUTBOUND shape)
    # The DROP is booked to its OWN window: it must never touch S_lane's mean...
    assert acc.dropped.count == 1
    assert acc.dropped.sum_ns == 13_000_000
    assert acc.episode.mean_ms() == pytest.approx(62.5)  # ...unchanged


def test_lane_episode_line_reports_lambda_max_as_the_reciprocal(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """The whole point of ARM 1: a lane is a single-server queue, so its ceiling is the reciprocal of its
    service time — computed here, on the line, so no reader reaches for Little's law to recover it.
    62.5 ms ⇒ 16/s per lane; at 8 lanes that is the ~128 deliveries/s the rig measured (the CONFIRMING
    outcome)."""
    caplog.set_level(logging.INFO)
    acc = LaneEpisodeTiming()
    acc.record_episode(62_500_000)  # 62.5 ms
    acc.maybe_emit(stage="outbound", lanes=8, slots=256)

    line = _episode_lines(caplog)[0]
    m = _EPISODE_RE.search(line)
    assert m is not None
    assert m.group("stage") == "outbound"
    assert m.group("n") == "1"
    assert float(m.group("mean")) == pytest.approx(62.5)
    assert float(m.group("lam")) == pytest.approx(16.0, rel=1e-3)  # 1 row / 62.5 ms
    assert float(m.group("rows")) == pytest.approx(1.0)  # SELF-CHECK: hard-1 on outbound
    assert m.group("lanes") == "8"
    assert m.group("slots") == "256"  # the bound is min(lanes, slots) / S_lane, not lanes / S_lane
    assert acc.episode.count == 0  # the window reset on emit

    # Throttled: an immediate second record does NOT emit again (5 s window), it accumulates.
    acc.record_episode(60_000_000)
    acc.maybe_emit(stage="outbound", lanes=8, slots=256)
    assert len(_episode_lines(caplog)) == 1
    assert acc.episode.count == 1


def test_lambda_is_rows_based_so_a_batching_prefix_stage_is_not_understated(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """``lambda_max_per_lane`` is a MESSAGE rate, not an episode rate. On INGRESS/ROUTED one episode
    drains a PREFIX of many rows, so a ``1/mean`` lambda would under-state that stage's per-lane message
    rate by the batch factor while looking identical in shape to the (hard-1) outbound line — the exact
    cross-stage blend the claim line already got wrong once. ``rows/episode`` makes it self-checking."""
    caplog.set_level(logging.INFO)
    acc = LaneEpisodeTiming()
    acc.record_episode(100_000_000, rows=8)  # 100 ms, 8 rows drained in the one episode
    acc.maybe_emit(stage="ingress", lanes=4, slots=256)

    m = _EPISODE_RE.search(_episode_lines(caplog)[0])
    assert m is not None
    assert float(m.group("rows")) == pytest.approx(8.0)
    # 8 rows / 0.1 s = 80 msg/s — NOT 1/0.1 = 10/s, which is what a naive reciprocal would print.
    assert float(m.group("lam")) == pytest.approx(80.0, rel=1e-3)


def test_utilization_makes_the_lanes_do_not_bind_branch_falsifiable(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """THE UNFALSIFIABILITY FIX. Dropping empty/rearm releases is right for the MEAN, but those releases
    still OCCUPY the lane (it sits RESERVED across the whole shared claim round-trip and cannot serve).
    If S_lane_booked reads ~25 ms while the lane ALSO burns ~39 ms/cycle on empty claims, the lane's real
    cycle is ~64 ms — the lanes DO bind — yet an instrument that only reported the booked mean would say
    25 ms and send ARM 1 down the 'not the lanes' blind alley. ``utilization`` is what prevents that."""
    caplog.set_level(logging.INFO)
    acc = LaneEpisodeTiming()
    # One lane, a ~1 s window: 25 ms of SERVICE + 39 ms of empty-claim occupancy, x ~15 cycles ⇒ ~0.96.
    for _ in range(15):
        acc.record_episode(25_000_000)
        acc.record_dropped(39_000_000)
    acc._window_start = (
        time.monotonic() - 1.0
    )  # pin the window span so the assertion is deterministic
    acc.maybe_emit(stage="outbound", lanes=1, slots=256)

    m = _EPISODE_RE.search(_episode_lines(caplog)[0])
    assert m is not None
    # S_lane alone still reads a benign 25 ms — the "lanes do not bind" number...
    assert float(m.group("mean")) == pytest.approx(25.0)
    # ...but the lane was busy ~96% of the window, so the lanes DO bind. Both facts are on the line.
    assert float(m.group("dropsum")) == pytest.approx(585.0, rel=0.01)  # 15 x 39 ms
    assert m.group("dropn") == "15"
    assert float(m.group("util")) == pytest.approx(0.96, abs=0.02)
    assert float(m.group("window")) == pytest.approx(1.0, abs=0.05)


def test_an_all_empty_window_emits_nothing_and_never_divides_by_zero(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """maybe_emit runs inside the serializer's terminal transition AND on the claimer loop's idle tick,
    both of which sit OUTSIDE a try — a ZeroDivisionError there would wedge a lane in PROCESSING. A window
    with nothing in it rolls forward SILENTLY (no all-zero line every 5 s on an idle stage)."""
    caplog.set_level(logging.INFO)
    acc = LaneEpisodeTiming()
    acc.maybe_emit(stage="outbound", lanes=0, slots=0)  # zero lanes, zero slots, zero samples
    assert not _episode_lines(caplog)

    # A window with ONLY drops still emits (that occupancy is the signal) and still must not divide by 0.
    acc.record_dropped(1_000_000)
    acc.maybe_emit(stage="outbound", lanes=0, slots=0, force=True)
    line = _episode_lines(caplog)[0]
    assert "episode n=0" in line
    assert "lambda_max_per_lane=0.00/s" in line
    assert "utilization=0.000" in line  # lanes=0 ⇒ the denominator is 0 ⇒ guarded, not raised
    assert "dropped n=1" in line


# --- (b) a completed episode is booked ---------------------------------------------------------------


async def test_clean_drain_books_one_episode_with_a_plausible_duration(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    monkeypatch.setenv(DELIVERY_PHASE_TIMING_ENV, "1")
    monkeypatch.setenv(
        LANE_EPISODE_TIMING_ENV, "1"
    )  # S_lane rides its OWN lever (see phase_timing)  # read at CONSTRUCTION — set it first
    caplog.set_level(logging.INFO, logger=_DISPATCHER_LOGGER)
    store = _EpisodeStore(lanes={_LANE})
    stamps: list[int] = []

    async def _slow_body(lane: str, item: OutboxItem) -> LaneItemResult:
        # Observed from INSIDE the episode: the lane is PROCESSING and the slot is stamped.
        stamps.append(disp._states[lane].episode_start_ns)
        await asyncio.sleep(0.02)  # 20 ms of real service inside the episode
        return LaneItemResult(kind=LaneResultKind.RESOLVED)

    disp = _episode_dispatcher(store, {_LANE}, _slow_body)
    await disp.start()
    try:

        async def _emitted() -> bool:
            return bool(_episode_lines(caplog))

        await _until(_emitted)
    finally:
        await disp.stop()

    assert stamps and stamps[0] > 0  # the lever ON stamps the slot at RESERVE
    m = _EPISODE_RE.search(_episode_lines(caplog)[0])
    assert m is not None
    assert m.group("stage") == "outbound"  # the ONLY stage ARM 1's arithmetic is about
    assert m.group("n") == "1"
    mean = float(m.group("mean"))
    # The episode spans claim + the whole prefix drain, so it must be AT LEAST the body's 20 ms of
    # service — a real interval, never a zero-length stamp. Upper bound is generous (slow CI box).
    assert 20.0 <= mean < 5_000.0
    assert float(m.group("rows")) == pytest.approx(
        1.0
    )  # hard-1 OUTBOUND: one episode == one delivery
    assert float(m.group("lam")) == pytest.approx(1000.0 / mean, rel=0.01)  # rows / S_lane
    assert m.group("lanes") == "1"
    assert m.group("slots") == "256"  # the dispatcher's max_processing_lanes default


# --- (a) default OFF: no stamp, no book, no line -----------------------------------------------------


async def test_lever_off_takes_no_stamp_and_books_nothing(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """Default OFF must cost nothing: no perf_counter at the reserve site (the stamp stays 0), no
    accumulation, no line — even though the rig ALWAYS sets the flag, production never does."""
    monkeypatch.delenv(DELIVERY_PHASE_TIMING_ENV, raising=False)
    caplog.set_level(logging.INFO, logger=_DISPATCHER_LOGGER)
    store = _EpisodeStore(lanes={_LANE})
    stamps: list[int] = []
    done = asyncio.Event()

    async def _body(lane: str, item: OutboxItem) -> LaneItemResult:
        stamps.append(disp._states[lane].episode_start_ns)
        done.set()
        return LaneItemResult(kind=LaneResultKind.RESOLVED)

    disp = _episode_dispatcher(store, {_LANE}, _body)
    assert disp._claim_phase_timing is False
    await disp.start()
    try:

        async def _drained() -> bool:
            return done.is_set() and disp.processing_lanes == 0

        await _until(_drained)
    finally:
        await disp.stop()

    assert stamps == [0]  # NO clock read at the reserve site
    assert disp._lane_episode_stats.episode.count == 0
    assert disp._lane_episode_stats.dropped.count == 0
    assert not _episode_lines(caplog)


async def test_the_claim_lever_alone_does_not_arm_s_lane(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """THE INSTRUMENT-OFF CONTROL RUNG DEPENDS ON THIS, so it is pinned.

    The rig sets ``MEFOR_DELIVERY_PHASE_TIMING=1`` on EVERY arm — it is a hard prerequisite of the
    harness's claim parsing. If ``S_lane`` rode that same lever it would be ON in every arm, and the one
    control that matters would be unbuildable: an instrument-OFF rung at the same offered rate, proving
    this hot-path stamp did not move the ceiling it exists to explain.

    So: claim lever ON, lane lever OFF ⇒ the claim accumulator arms and ``S_lane`` stays cold."""
    monkeypatch.setenv(DELIVERY_PHASE_TIMING_ENV, "1")
    monkeypatch.delenv(LANE_EPISODE_TIMING_ENV, raising=False)
    caplog.set_level(logging.INFO, logger=_DISPATCHER_LOGGER)
    store = _EpisodeStore(lanes={_LANE})
    stamps: list[int] = []
    done = asyncio.Event()

    async def _body(lane: str, item: OutboxItem) -> LaneItemResult:
        stamps.append(disp._states[lane].episode_start_ns)
        done.set()
        return LaneItemResult(kind=LaneResultKind.RESOLVED)

    disp = _episode_dispatcher(store, {_LANE}, _body)
    assert disp._claim_phase_timing is True  # the rig's lever IS on ...
    assert disp._lane_episode_timing is False  # ... and S_lane is STILL off
    await disp.start()
    try:

        async def _drained() -> bool:
            return done.is_set() and disp.processing_lanes == 0

        await _until(_drained)
    finally:
        await disp.stop()

    assert stamps == [0]  # no reserve-site clock read: the OFF path is genuinely free
    assert disp._lane_episode_stats.episode.count == 0
    assert disp._lane_episode_stats.dropped.count == 0
    assert not _episode_lines(caplog)


# --- (c) the DROP set: pause / error / stop / empty / rearm ------------------------------------------
# Each of these releases a RESERVED slot without rendering a completed service. It must NOT reach
# ``episode`` (S_lane) — booking it would poison the mean — but it MUST reach ``dropped``: the lane was
# occupied for that interval and could not serve, and discarding it outright is what would make the
# "lanes do not bind" branch of the ARM 1 test unfalsifiable.


async def test_pause_release_is_dropped_not_booked(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """An operator PAUSE that lands mid-PROCESSING quiesces the lane to PAUSED at the terminal
    transition. That release is NOT a completed service episode — booking it would mix an
    operator-truncated interval into the service-time mean."""
    monkeypatch.setenv(DELIVERY_PHASE_TIMING_ENV, "1")
    monkeypatch.setenv(
        LANE_EPISODE_TIMING_ENV, "1"
    )  # S_lane rides its OWN lever (see phase_timing)
    caplog.set_level(logging.INFO, logger=_DISPATCHER_LOGGER)
    store = _EpisodeStore(lanes={_LANE})
    entered = asyncio.Event()
    release = asyncio.Event()

    async def _held_body(lane: str, item: OutboxItem) -> LaneItemResult:
        entered.set()
        await release.wait()  # hold the lane in PROCESSING so the pause lands mid-episode
        return LaneItemResult(kind=LaneResultKind.RESOLVED)

    disp = _episode_dispatcher(store, {_LANE}, _held_body)
    await disp.start()
    try:

        async def _processing() -> bool:
            return entered.is_set()

        await _until(_processing)
        disp.pause_lane(_LANE)  # mid-episode: deferred (pause_pending), never a task.cancel
        release.set()

        async def _paused() -> bool:
            return disp.paused(_LANE)

        await _until(_paused)
        assert disp._lane_episode_stats.episode.count == 0  # DROPPED — never a service
        assert disp._lane_episode_stats.dropped.count == 1  # ...but it IS booked as lane occupancy
        assert not _episode_lines(caplog)
        assert (
            disp._states[_LANE].episode_start_ns == 0
        )  # stamp consumed — cannot be re-booked later
    finally:
        await disp.stop()


async def test_infra_fault_release_is_dropped_not_booked(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """A T17 machinery fault (the body raises) ends the episode in a RETRY/park — a FAILED service, not
    a completed one. This is the path a ``try/finally`` around the serializer would have silently booked."""
    monkeypatch.setenv(DELIVERY_PHASE_TIMING_ENV, "1")
    monkeypatch.setenv(
        LANE_EPISODE_TIMING_ENV, "1"
    )  # S_lane rides its OWN lever (see phase_timing)
    caplog.set_level(logging.INFO, logger=_DISPATCHER_LOGGER)
    store = _EpisodeStore(lanes={_LANE})

    async def _boom(lane: str, item: OutboxItem) -> LaneItemResult:
        raise RuntimeError("connector down")  # T17 infra fault

    disp = _episode_dispatcher(store, {_LANE}, _boom)
    await disp.start()
    try:

        async def _faulted() -> bool:
            return disp.infra_error_streak(_LANE) >= 1

        await _until(_faulted)
        assert disp._lane_episode_stats.episode.count == 0  # DROPPED — a FAILED service is not one
        assert disp._lane_episode_stats.dropped.count == 1  # ...but the lane WAS occupied for it
        assert not _episode_lines(caplog)
        assert disp._states[_LANE].episode_start_ns == 0
    finally:
        await disp.stop()


async def test_stop_outcome_release_is_dropped_not_booked(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """A content STOP (T16) halts the lane — no completed service, so no episode."""
    monkeypatch.setenv(DELIVERY_PHASE_TIMING_ENV, "1")
    monkeypatch.setenv(
        LANE_EPISODE_TIMING_ENV, "1"
    )  # S_lane rides its OWN lever (see phase_timing)
    caplog.set_level(logging.INFO, logger=_DISPATCHER_LOGGER)
    store = _EpisodeStore(lanes={_LANE})

    async def _stop(lane: str, item: OutboxItem) -> LaneItemResult:
        return LaneItemResult(kind=LaneResultKind.STOP)

    disp = _episode_dispatcher(store, {_LANE}, _stop)
    await disp.start()
    try:

        async def _stopped() -> bool:
            # Poll the ACTUAL condition. The old predicate (`processing_lanes == 0 and phase is not
            # None`) is already true at start() — before the lane has even been claimed — so it returned
            # immediately and asserted nothing about the STOP path.
            phase = disp.phase(_LANE)
            return phase is not None and phase.name == "STOPPED"

        await _until(_stopped)
        assert disp._lane_episode_stats.episode.count == 0
        assert disp._lane_episode_stats.dropped.count == 1  # occupancy, not service
        assert not _episode_lines(caplog)
    finally:
        await disp.stop()


async def test_empty_and_rearm_claims_are_never_booked(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """THE DEFLATION HAZARD, pinned. Empty and rearm-only claims release a RESERVED slot without the lane
    ever entering PROCESSING — they are claim-only, frequent and sub-millisecond. Booking either would
    drag S_lane_mean down toward the bare claim time (~13 ms) and read as the CONFIRMING-NEGATIVE 'lanes
    do not bind' verdict: a silent false negative on the load-bearing question."""
    monkeypatch.setenv(DELIVERY_PHASE_TIMING_ENV, "1")
    monkeypatch.setenv(
        LANE_EPISODE_TIMING_ENV, "1"
    )  # S_lane rides its OWN lever (see phase_timing)
    caplog.set_level(logging.INFO, logger=_DISPATCHER_LOGGER)
    # No pending rows at all: the lane's first claim REARMS (H2 consumed the head in store), and the
    # re-claim that follows comes back EMPTY. Two releases, zero PROCESSING, zero episodes.
    store = _EpisodeStore(lanes=set(), rearm_lanes={_LANE})
    disp = _episode_dispatcher(store, {_LANE})
    await disp.start()
    try:

        async def _rearmed_then_empty() -> bool:
            return store.claim_calls >= 2

        await _until(_rearmed_then_empty)
        assert disp.processing_lanes == 0  # the lane never processed anything
        assert disp._lane_episode_stats.episode.count == 0  # ZERO services booked — the whole point
        assert disp._lane_episode_stats.rows == 0
        # ...but the releases ARE booked as OCCUPANCY: the lane sat RESERVED across each shared claim
        # round-trip and could serve nothing meanwhile. The claim round-trip flushes the window, so the
        # first drop is on the LINE and the second is still in the (throttled) accumulator.
        line = _episode_lines(caplog)[0]
        assert "episode n=0" in line  # no service — S_lane is NOT deflated by an empty claim
        assert "dropped n=1" in line  # ...and the empty churn is visible instead of vanishing
        assert disp._lane_episode_stats.dropped.count >= 1
        assert disp._states[_LANE].episode_start_ns == 0
    finally:
        await disp.stop()


# --- (e) the stamp cannot be double-booked -----------------------------------------------------------


async def test_stamp_is_consumed_so_a_reentered_lane_cannot_double_book(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """``_release_slot`` CLAMPS an over-release instead of raising and the conservation law is asserted
    only in tests, so a leaked stamp would produce no runtime signal. The instrument must therefore be
    self-guarding: the stamp is consumed (zeroed) at the terminal transition, and a zero stamp DROPS."""
    monkeypatch.setenv(DELIVERY_PHASE_TIMING_ENV, "1")
    monkeypatch.setenv(
        LANE_EPISODE_TIMING_ENV, "1"
    )  # S_lane rides its OWN lever (see phase_timing)
    caplog.set_level(logging.INFO, logger=_DISPATCHER_LOGGER)
    store = _EpisodeStore(lanes={_LANE})
    disp = _episode_dispatcher(store, {_LANE})
    await disp.start()
    try:

        async def _emitted() -> bool:
            return bool(_episode_lines(caplog))

        await _until(_emitted)  # one clean episode booked (and emitted, which RESETS the window)

        assert disp._states[_LANE].episode_start_ns == 0  # consumed by the terminal transition
        # A replayed terminal transition (or any leaked/absent stamp) must DROP, never book again.
        disp._book_lane_episode(
            disp._states[_LANE].episode_start_ns, time.perf_counter_ns(), rows=1, service=True
        )
        assert disp._lane_episode_stats.episode.count == 0

        # A genuine RE-ENTRY: the lane is re-readied and re-claimed. The claim comes back EMPTY (its one
        # row is gone), so the re-entry books nothing and the stale stamp cannot resurface.
        disp.mark_ready(_LANE)

        async def _reclaimed() -> bool:
            return store.claim_calls >= 2

        await _until(_reclaimed)
        assert disp._lane_episode_stats.episode.count == 0
        assert len(_episode_lines(caplog)) == 1  # still exactly ONE line
    finally:
        await disp.stop()


# --- (d) PHI hygiene + the harness log-parse collision ------------------------------------------------


async def test_episode_line_never_contains_a_lane_name(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """PHI rule: a lane IS a destination_name (a partner name). The episode line carries the stage enum,
    counts, ms and a rate — never a lane key, no matter how many lanes were served."""
    monkeypatch.setenv(DELIVERY_PHASE_TIMING_ENV, "1")
    monkeypatch.setenv(
        LANE_EPISODE_TIMING_ENV, "1"
    )  # S_lane rides its OWN lever (see phase_timing)
    caplog.set_level(logging.INFO, logger=_DISPATCHER_LOGGER)
    lanes = {_LANE, "OB_LAB_ORU", "OB_PARTNER_ADT"}
    store = _EpisodeStore(lanes=lanes)
    disp = _episode_dispatcher(store, lanes)
    await disp.start()
    try:

        async def _emitted() -> bool:
            return bool(_episode_lines(caplog))

        await _until(_emitted)
    finally:
        await disp.stop()

    for line in _episode_lines(caplog):
        for secret in (*lanes, "OB_", "ACME", "acme", "MRN", "destination", "MSH"):
            assert secret not in line


def test_harness_regexes_do_not_false_match_the_episode_line() -> None:
    """The ladder parses the node logs with THREE regexes now, and ``_PHASE_RE`` doubles as the
    5-second-window COUNTER that recovers the true delivery SPAN (D3). A new INFO line that cross-matched
    either would silently inflate the measured delivered rate on every rung — a corruption with no error.
    The harness's ``_EPISODE_RE`` must ALSO match the line this module actually emits, or ``S_lane``
    silently never reaches the rig's report (the failure this test exists to prevent, one level up)."""
    from harness.load.shardcert_ladder import (
        _CLAIM_RE,
        _PHASE_RE,
    )
    from harness.load.shardcert_ladder import (
        _EPISODE_RE as _HARNESS_EPISODE_RE,
    )

    episode = (
        "lane episode timing (stage=outbound): episode n=12 mean=62.50ms max=190.10ms "
        "| rows/episode=1.00 lambda_max_per_lane=16.00/s | dropped n=37 sum=481.20ms "
        "| lanes=8 slots=256 window=5.01s utilization=0.982"
    )
    assert _PHASE_RE.search(episode) is None
    assert _CLAIM_RE.search(episode) is None
    # ...and the episode regex is itself disjoint from the two lines it sits beside in the node log.
    delivery = (
        "delivery phase timing (stage=outbound): send_ack n=12 mean=0.60ms max=24.42ms "
        "| mark_done n=12 mean=16.06ms max=126.73ms"
    )
    claim = (
        "claim phase timing (stage=outbound): claim n=12 mean=62.20ms max=190.10ms "
        "| lanes/claim=8.00 rows/claim=8.00 rearm=0 empty=0 claimers=1"
    )
    assert _EPISODE_RE.search(delivery) is None
    assert _EPISODE_RE.search(claim) is None
    assert _EPISODE_RE.search(episode) is not None
    # THE ONE THAT MATTERS: the HARNESS's parser and the ENGINE's emitter agree on the shape.
    assert _HARNESS_EPISODE_RE.search(episode) is not None
    assert _HARNESS_EPISODE_RE.search(delivery) is None
    assert _HARNESS_EPISODE_RE.search(claim) is None


# --- (f) the emitted `lanes` multiplier + the slot cap ------------------------------------------------


async def test_lanes_multiplier_counts_only_servable_lanes(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """``lanes=`` is the MULTIPLIER a reader applies straight off the line (``min(lanes, slots)/S_lane``),
    so it must count only lanes that can SERVE. ``len(self._states)`` would include PAUSED and STOPPED
    lanes, which serve nothing until an operator/reload re-arms them — silently over-stating the ceiling."""
    monkeypatch.setenv(DELIVERY_PHASE_TIMING_ENV, "1")
    monkeypatch.setenv(
        LANE_EPISODE_TIMING_ENV, "1"
    )  # S_lane rides its OWN lever (see phase_timing)
    caplog.set_level(logging.INFO, logger=_DISPATCHER_LOGGER)
    lanes = {_LANE, "OB_LAB_ORU", "OB_PARTNER_ADT"}
    store = _EpisodeStore(lanes=lanes)
    disp = _episode_dispatcher(store, lanes)
    # Register + PAUSE one lane BEFORE start: it holds a _LaneState but can never serve.
    disp.pause_lane("OB_PARTNER_ADT")
    await disp.start()
    try:

        async def _emitted() -> bool:
            return bool(_episode_lines(caplog))

        await _until(_emitted)
    finally:
        await disp.stop()

    m = _EPISODE_RE.search(_episode_lines(caplog)[0])
    assert m is not None
    assert len(disp_states_seen := lanes) == 3  # three lanes are KNOWN...
    assert m.group("lanes") == "2"  # ...but only two can serve (the third is PAUSED)
    assert disp_states_seen  # (keep the intermediate binding meaningful to the reader)


async def test_a_quiet_stage_still_flushes_its_final_window(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """The tail of every bench rung is a DRAIN: the offer stops, the backlog clears, the stage goes quiet.
    If the window only flushed on a BOOK, those last episodes — the most interesting ones — would be
    silently discarded. ``stop()`` force-flushes, and the claimer's idle tick flushes too."""
    monkeypatch.setenv(DELIVERY_PHASE_TIMING_ENV, "1")
    monkeypatch.setenv(
        LANE_EPISODE_TIMING_ENV, "1"
    )  # S_lane rides its OWN lever (see phase_timing)
    caplog.set_level(logging.INFO, logger=_DISPATCHER_LOGGER)
    store = _EpisodeStore(lanes={_LANE})
    disp = _episode_dispatcher(store, {_LANE})
    await disp.start()

    async def _drained() -> bool:
        return disp.processing_lanes == 0 and store.claim_calls >= 1

    await _until(_drained)
    # The 5 s throttle means the FIRST book emitted and reset; force a second, un-emitted window so there
    # is something real to lose, then prove stop() does not lose it.
    caplog.clear()
    disp._lane_episode_stats.record_episode(42_000_000)
    assert not _episode_lines(caplog)  # throttled — nothing on the wire yet

    await disp.stop()  # the force-flush

    lines = _episode_lines(caplog)
    assert lines, "stop() must flush the final partial window"
    m = _EPISODE_RE.search(lines[-1])
    assert m is not None
    assert float(m.group("mean")) == pytest.approx(42.0)


async def test_a_metrics_failure_degrades_to_silence_and_never_wedges_a_lane(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """The booking site is the serializer's SYNCHRONOUS terminal transition, which runs OUTSIDE a try (the
    module says so). A raise there lands AFTER ``_release_slot()`` but BEFORE ``_lane_done`` — pinning the
    lane in PROCESSING forever with its slot already returned: the conservation law broken and the lane
    silently dead. A metrics bug must therefore degrade to SILENCE, never to a wedge."""
    monkeypatch.setenv(DELIVERY_PHASE_TIMING_ENV, "1")
    monkeypatch.setenv(
        LANE_EPISODE_TIMING_ENV, "1"
    )  # S_lane rides its OWN lever (see phase_timing)
    caplog.set_level(logging.INFO, logger=_DISPATCHER_LOGGER)
    store = _EpisodeStore(lanes={_LANE})
    disp = _episode_dispatcher(store, {_LANE})

    def _boom_episode(ns: int, *, rows: int = 1) -> None:
        raise RuntimeError("metrics exploded")

    def _boom_dropped(ns: int) -> None:
        raise RuntimeError("metrics exploded")

    monkeypatch.setattr(disp._lane_episode_stats, "record_episode", _boom_episode)
    monkeypatch.setattr(disp._lane_episode_stats, "record_dropped", _boom_dropped)
    await disp.start()
    try:

        async def _drained() -> bool:
            return disp.processing_lanes == 0 and store.claim_calls >= 1

        await _until(_drained)

        # The lane completed its terminal transition despite the metrics raise: it is NOT stuck in
        # PROCESSING, and the slot budget is whole (the conservation law holds).
        assert disp.processing_lanes == 0
        assert disp._slots_free == disp._max_processing_lanes
        assert disp.phase(_LANE) is not None
        assert not _episode_lines(caplog)  # degraded to silence
    finally:
        await disp.stop()
