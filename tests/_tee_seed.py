# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A synthetic capture for the tee's ``anonymize-captures`` tests, shared by the CLI and the
integration suites so the two do not each keep a copy (vault BACKLOG #3166)."""

from __future__ import annotations

import asyncio

from tee.store import RelayStore

#: A synthetic ADT^A01 with control id ``C1``. No real patient data.
SYNTHETIC_ADT = (
    "MSH|^~\\&|SAPP|SFAC|RAPP|RFAC|20260101||ADT^A01|C1|P|2.5.1\r"
    "PID|1||999^^^H^MR||DOE^JOHN||19800101|M"
)


def seed_capture(db: str, raw: bytes, *, direction: str = "corepoint_copy") -> None:
    """Record ``raw`` as one capture with control id ``C1`` in the relay store at ``db``."""

    async def seed() -> None:
        store = await RelayStore.open(db)
        try:
            await store.record_capture(direction=direction, control_id="C1", raw=raw)
        finally:
            await store.close()

    asyncio.run(seed())
