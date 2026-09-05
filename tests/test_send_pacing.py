# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Per-connection egress send pacing — BACKLOG #82 (the OPEN half of the bundle).

``send_min_interval_seconds`` on an outbound holds each ``send`` until at least that many seconds have
elapsed since the lane's previous send began, so a partner that cannot absorb bursts sees a bounded send
rate. Pacing is enforced ONCE at the pipeline delivery seam (``_pace_outbound``, called before the
item/batch body in both the per_lane worker and the pooled dispatcher), keyed per-lane, and is
byte-identical when unset. These tests cover the seam gate, the per-lane clock, lane independence, the
no-pacing default, and the wiring validation. The BATCH seam proof lives in ``test_outbound_batch.py``.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from pathlib import Path

import pytest
from _pace_probe import install_pace_probe

from messagefoundry.config.models import ConnectorType, RetryPolicy
from messagefoundry.config.wiring import (
    MLLP,
    ConnectionSpec,
    Registry,
    WiringError,
    build_outbound_connection,
)
from messagefoundry.pipeline.wiring_runner import RegistryRunner, _resolve_send_pace
from messagefoundry.store import MessageStore

DEST = "OB_ADT"
DEST2 = "OB_LAB"


def _msg(n: int) -> str:
    return f"MSH|^~\\&|A|B|C|D|20260101000000||ADT^A0{n}|MSG{n}|P|2.5.1\rPID|1||{n}00||DOE^P{n}\r"


class _Recorder:
    """A minimal non-capturing outbound (returns None → mark_done). Records each delivered payload."""

    def __init__(self) -> None:
        self.sent: list[str] = []

    async def send(self, payload: str) -> None:
        self.sent.append(payload)
        return None

    async def aclose(self) -> None:
        return None


@pytest.fixture
async def store(tmp_path: Path) -> AsyncIterator[MessageStore]:
    s = await MessageStore.open(tmp_path / "pacing.db")
    yield s
    await s.close()


def _runner(store: MessageStore) -> RegistryRunner:
    return RegistryRunner(Registry(), store, poll_interval=0.02)


# --- _resolve_send_pace: None/absent/0 → off; positive kept; negative clamped ----------------------


def test_resolve_send_pace() -> None:
    assert _resolve_send_pace({}) == 0.0  # absent → no pacing
    assert _resolve_send_pace({"send_min_interval_seconds": None}) == 0.0
    assert _resolve_send_pace({"send_min_interval_seconds": 0}) == 0.0
    assert _resolve_send_pace({"send_min_interval_seconds": 0.25}) == 0.25
    # A negative can't reach here past wiring, but the seam must never be asked to sleep negative.
    assert _resolve_send_pace({"send_min_interval_seconds": -5}) == 0.0


# --- wiring validation: a negative interval is rejected loud at build; a positive one is carried ---


def test_negative_send_pace_rejected() -> None:
    with pytest.raises(WiringError, match="send_min_interval_seconds"):
        build_outbound_connection(
            "OB", MLLP(host="127.0.0.1", port=1234, send_min_interval_seconds=-0.5)
        )


def test_positive_send_pace_carried() -> None:
    oc = build_outbound_connection(
        "OB", MLLP(host="127.0.0.1", port=1234, send_min_interval_seconds=0.5)
    )
    assert oc.spec.settings["send_min_interval_seconds"] == 0.5
    # And a File outbound (no such setting) resolves to off — pacing is opt-in where meaningful.
    file_oc = build_outbound_connection(
        "OB_F",
        ConnectionSpec(ConnectorType.FILE, {"directory": "/tmp", "filename": "{MSH-10}.hl7"}),
    )
    assert _resolve_send_pace(file_oc.spec.settings) == 0.0


# --- _pace_outbound: (a) a single lane's second send is held >= the interval ----------------------


async def test_pace_second_send_delayed(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    # THE ASSERTION IS THE WAIT THE PACER ASKED FOR, NOT ONE THE TEST TIMES. An elapsed-time bound
    # cannot do this job on a loaded runner: tests/_pace_probe.py has the measurement, the
    # reproduction, and why Windows timer granularity is not the mechanism.
    runner = _runner(store)
    interval = 0.05
    runner._send_pace[DEST] = interval
    work = 0.02  # the first send's body, charged to the pacer's clock
    probe = install_pace_probe(monkeypatch, runner)

    await runner._pace_outbound(DEST)  # first: no prior send → returns at once, stamps the clock
    assert probe.slept == []  # nothing owed
    first_stamp = runner._send_pace_at[DEST]

    probe.advance(work)
    await runner._pace_outbound(DEST)  # second: elapsed < interval → holds the REMAINDER
    # The wait is the REMAINDER: the pacer credits the work already done against the interval.
    assert probe.slept == [pytest.approx(interval - work, abs=1e-9)]
    # Stamped AFTER the wait, so the next interval is measured from THIS send's start (a send-to-send
    # rate). Mutation: stamp before the sleep instead, and this reads first_stamp + work.
    assert runner._send_pace_at[DEST] == pytest.approx(first_stamp + interval, abs=1e-9)


# --- _pace_outbound: (b) two DIFFERENT lanes pace INDEPENDENTLY (per-lane clock, not a global bucket) ---


async def test_lanes_pace_independently(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    runner = _runner(store)
    interval = 0.05
    runner._send_pace[DEST] = interval
    runner._send_pace[DEST2] = interval
    probe = install_pace_probe(monkeypatch, runner)

    await runner._pace_outbound(DEST)  # stamps DEST's clock (a recent send on lane A)
    await runner._pace_outbound(DEST2)  # lane B has NO prior send → must NOT be delayed by A
    # A global (cross-lane) bucket would make B wait ~interval here; an independent per-lane clock asks
    # for no wait at all. Asserted as "the pacer requested nothing", which a slow box cannot perturb —
    # the `elapsed < interval * 0.4` bound this replaces would fail on a runner that merely stalled.
    assert probe.slept == []
    assert (
        DEST in runner._send_pace_at and DEST2 in runner._send_pace_at
    )  # each lane has its own clock


# --- _pace_outbound: (c) unset / 0 is byte-identical — no delay, clock never touched ---------------


async def test_unset_is_noop(store: MessageStore) -> None:
    runner = _runner(store)
    # DEST absent from _send_pace (the default) → off.
    await runner._pace_outbound(DEST)
    await runner._pace_outbound(DEST)
    assert DEST not in runner._send_pace_at  # never stamped → the delivery path is byte-identical

    runner._send_pace[DEST2] = 0.0  # explicit 0 is likewise off
    await runner._pace_outbound(DEST2)
    assert DEST2 not in runner._send_pace_at


# --- integration: the SINGLE-MESSAGE seam is paced end-to-end via _dispatch_delivery (non-batch) --


async def test_single_message_seam_is_paced(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A non-batch lane routes _dispatch_delivery → _process_delivery_item; the pacing gate sits before
    # that call, so the SECOND single-message delivery is held for the remainder of the interval. Same
    # shape as the batch proof in test_outbound_batch.py, and asserted the same way: on the pacer's
    # decision, never on elapsed time (tests/_pace_probe.py).
    for i in (1, 2):
        await store.enqueue_message(
            channel_id="c1", raw=_msg(i), deliveries=[(DEST, _msg(i))], now=100.0 + i
        )
    runner = _runner(store)
    rec = _Recorder()
    runner._destinations[DEST] = rec
    runner._retry[DEST] = RetryPolicy()
    interval = 0.05
    runner._send_pace[DEST] = interval
    work = 0.02  # the first delivery's body, charged to the pacer's clock
    probe = install_pace_probe(monkeypatch, runner)

    head1 = await store.claim_next_fifo(DEST)
    assert head1 is not None
    await runner._dispatch_delivery(DEST, head1)  # first: not paced (no prior send)
    assert len(rec.sent) == 1
    assert probe.calls == [DEST]  # the seam reached the pacer
    assert probe.slept == []  # …and nothing was owed yet

    probe.advance(work)
    head2 = await store.claim_next_fifo(DEST)
    assert head2 is not None
    await runner._dispatch_delivery(DEST, head2)  # second: held for the remainder before its send
    assert len(rec.sent) == 2  # both delivered, in order
    assert probe.calls == [DEST, DEST]  # ONE interval per send
    assert probe.slept == [pytest.approx(interval - work, abs=1e-9)]
    depth, _ = await store.pending_depth(DEST)
    assert depth == 0
