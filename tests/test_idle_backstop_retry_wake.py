# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""WS-C Phase-0 (ADR 0061 amendment) — the long idle backstop + the armed retry wake.

With per-lane wake ON, the idle backstop backs off from ``poll_interval`` to
``_PER_LANE_IDLE_BACKSTOP_SECONDS`` (the 0.25 s re-poll from O(lanes × stages) idle workers was the
WS-C empty-claim storm: ~92% store CPU at zero messages). The short poll used to double as the retry
re-check, so the backstop change only holds at-least-once if a ``mark_failed`` reschedule ARMS its
own wake at ``next_attempt_at`` — these tests pin exactly that contract:

* backstop selection (ON → 30 s safety net; OFF → poll_interval, byte-identical);
* ``mark_failed`` returns the reschedule time (the timer's input) and ``None`` on dead-letter;
* the pinned at-least-once case: a delivery that fails transiently on an OTHERWISE-IDLE lane is
  retried ON THE BACKOFF SCHEDULE (well inside the 30 s backstop) — the armed wake, not the poll,
  drives the retry. Without the arm this test would sleep out the backstop and time out.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

import pytest

from messagefoundry.config.models import ConnectorType, RetryPolicy
from messagefoundry.config.wiring import (
    ConnectionSpec,
    InboundConnection,
    OutboundConnection,
    Registry,
    Send,
)
from messagefoundry.parsing.message import Message
from messagefoundry.pipeline.wiring_runner import (
    _PER_LANE_IDLE_BACKSTOP_SECONDS,
    RegistryRunner,
)
from messagefoundry.store import MessageStatus, MessageStore
from messagefoundry.transports.base import DeliveryError

ADT = (
    "MSH|^~\\&|SENDINGAPP|SENDINGFAC|RECV|RFAC|20260604||ADT^A01|{cid}|P|2.5.1\r"
    "EVN|A01|20260604\r"
    "PID|1||100^^^H^MR||DOE^JANE\r"
)


@pytest.fixture
async def store(tmp_path: Path) -> Any:
    s = await MessageStore.open(tmp_path / "ws1.db")
    yield s
    await s.close()


def _registry(inbox: Path, out_dir: Path) -> Registry:
    reg = Registry()
    reg.add_outbound(
        OutboundConnection(
            "out_a",
            ConnectionSpec(
                ConnectorType.FILE, {"directory": str(out_dir), "filename": "{MSH-10}.hl7"}
            ),
        )
    )
    reg.add_inbound(
        InboundConnection(
            "file_in",
            ConnectionSpec(
                ConnectorType.FILE,
                {"directory": str(inbox), "pattern": "*.hl7", "poll_seconds": 0.02},
            ),
            router="r",
        )
    )
    reg.add_router("r", lambda m: ["h"])

    def handle(msg: Message) -> list[Send]:
        return [Send("out_a", msg)]

    reg.add_handler("h", handle)
    return reg


# --- backstop selection --------------------------------------------------------


def test_idle_backstop_is_poll_interval_when_wake_off(store: MessageStore) -> None:
    r = RegistryRunner(Registry(), store, poll_interval=0.25, per_lane_wake=False)
    assert r._idle_backstop == 0.25  # byte-identical to pre-WS-C


def test_idle_backstop_is_long_safety_net_when_wake_on(store: MessageStore) -> None:
    r = RegistryRunner(Registry(), store, poll_interval=0.25, per_lane_wake=True)
    assert r._idle_backstop == _PER_LANE_IDLE_BACKSTOP_SECONDS == 30.0


# --- mark_failed returns the reschedule time ------------------------------------


async def test_mark_failed_returns_next_attempt_at(store: MessageStore) -> None:
    await store.enqueue_message(
        channel_id="IB", raw=ADT.format(cid="M1"), deliveries=[("OB1", "p")], now=100.0
    )
    item = (await store.claim_ready(now=200.0))[0]
    # attempts is post-increment (=1) → backoff = 5.0 * 2**0; rescheduled at now + 5.
    next_at = await store.mark_failed(item.id, "transient", RetryPolicy(), now=1000.0)
    assert next_at == pytest.approx(1005.0)


async def test_mark_failed_returns_none_on_dead_letter_and_missing(store: MessageStore) -> None:
    await store.enqueue_message(
        channel_id="IB", raw=ADT.format(cid="M2"), deliveries=[("OB1", "p")], now=100.0
    )
    item = (await store.claim_ready(now=200.0))[0]
    # max_attempts=1 with attempts already 1 → dead-letter: nothing to re-claim, no timer.
    assert await store.mark_failed(item.id, "boom", RetryPolicy(max_attempts=1), now=1000.0) is None
    # A vanished row is equally not re-claimable.
    assert await store.mark_failed("no-such-row", "x", RetryPolicy(), now=1000.0) is None


# --- the armed retry wake (the pinned at-least-once case) ------------------------


async def test_transient_failure_on_idle_lane_retries_on_schedule(
    store: MessageStore, tmp_path: Path
) -> None:
    """Delivery fails twice (transient), lane otherwise idle, per-lane wake ON (30 s backstop): the
    message must still deliver on the ~0.2 s backoff schedule — the armed mark_failed wake drives the
    re-claim. If the arm were missing, each retry would wait out the 30 s backstop and this test
    would blow its 6 s ceiling (the pre-WS-C short poll that used to mask this is gone)."""
    inbox, out_dir = tmp_path / "in", tmp_path / "out"
    inbox.mkdir()
    reg = _registry(inbox, out_dir)
    r = RegistryRunner(
        reg,
        store,
        poll_interval=0.05,
        per_lane_wake=True,
        delivery_defaults=RetryPolicy(backoff_seconds=0.2, backoff_multiplier=1.0),
    )
    await r.start()
    try:
        connector = r._destinations["out_a"]
        real_send = connector.send
        failures = 2
        calls = {"n": 0}

        async def flaky_send(payload: str) -> Any:
            calls["n"] += 1
            if calls["n"] <= failures:
                raise DeliveryError("transient partner outage (test)")
            return await real_send(payload)

        connector.send = flaky_send  # type: ignore[method-assign]
        (inbox / "m.hl7").write_bytes(ADT.format(cid="MSG1").encode("utf-8"))

        deadline = asyncio.get_running_loop().time() + 6.0
        while True:
            msgs = await store.list_messages(
                channel_id="file_in", status=MessageStatus.PROCESSED.value
            )
            if msgs:
                break
            assert asyncio.get_running_loop().time() < deadline, (
                f"retry never fired inside the backstop window (send calls: {calls['n']})"
            )
            await asyncio.sleep(0.05)
    finally:
        await r.stop()
    assert calls["n"] == failures + 1  # failed, failed, delivered — on the armed schedule
    assert (out_dir / "MSG1.hl7").exists()
