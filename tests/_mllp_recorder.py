# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The recording MLLP destination and the one-batch drive the batch-member refusal tests share
(ADR 0205, ADR 0209; BACKLOG #3759 item 3.3, #4973).

tests/test_outbound_batch.py and tests/test_permanent_refusal_log.py each held a copy of both,
and neither copy closed the destination it built. One copy here, and the drive closes the lane's
connector however the batch ends.
"""

from __future__ import annotations

from typing import Any

from messagefoundry.config.models import ConnectorType, Destination
from messagefoundry.pipeline.wiring_runner import RegistryRunner
from messagefoundry.transports.mllp import MLLPDestination


class MllpRecorder(MLLPDestination):
    """A real MLLP destination, so ``check_frame`` is the real one, whose send only records."""

    def __init__(self, name: str, *, encoding: str = "utf-8", **field: Any) -> None:
        settings: dict[str, object] = {"host": "127.0.0.1", "port": 1, "encoding": encoding}
        super().__init__(
            Destination(name=name, type=ConnectorType.MLLP, settings=settings, **field)
        )
        self.sent: list[str] = []

    async def send(self, payload: str, *, metadata: object = None) -> None:
        self.sent.append(payload)


async def run_one_batch(runner: RegistryRunner, lane: str) -> str:
    """Claim ``lane``'s FIFO head and run the runner's batch body over it once, as the delivery
    worker would. Returns the head row's id. The connector wired on ``lane`` is closed afterwards,
    whether the batch completed or raised, so a test never leaves one open."""
    connector = runner._destinations[lane]
    try:
        head = await runner.store.claim_next_fifo(lane)
        cfg = runner._batch[lane]
        # A raise, not an assert: this module is not assert-rewritten, and -O would strip one.
        if head is None or cfg is None:
            raise AssertionError(f"lane {lane!r}: no FIFO head ({head!r}) or no batch ({cfg!r})")
        await runner._process_delivery_batch(lane, head, cfg)
        return head.id
    finally:
        await connector.aclose()
