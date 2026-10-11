# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Cross-backend contract: ``mark_failed`` and ``mark_batch_failed`` say what they did (vault BACKLOG
#3211).

Each returns a :class:`~messagefoundry.store.FailOutcome`. The delivery worker logs a dead-letter at
the retry cap from it, so it must tell a DEAD write apart from a re-pend, a vanished row and an empty
batch, and it must name the row the store decided from, with the attempts the store read. Before
#3211 the store returned only ``float | None``, and the runner read the row back to find out.

Deliberately **extra-free**: the live server legs import it inside a test function. Every name it
writes is unique per run, so a shared server database is safe.
"""

from __future__ import annotations

from typing import Any
from uuid import uuid4

from messagefoundry.config.models import RetryPolicy
from messagefoundry.store import FailOutcome

_RAW = "MSH|^~\\&|A|B|C|D|20260101||ADT^A01|MSG1|P|2.5.1\r"


async def assert_fail_outcomes(store: Any) -> None:
    """Drive both calls through every branch on ``store`` and pin the outcome each returns."""
    run = uuid4().hex[:8]
    single, batch = f"OB_FAIL_{run}", f"OB_BATCH_{run}"
    await store.enqueue_message(
        channel_id=f"IB_{run}",
        raw=_RAW,
        deliveries=[(single, "p"), (batch, "q")],
        now=100.0,
    )
    (row,) = await store.claim_ready(now=200.0, destination_name=single)
    capped = RetryPolicy(max_attempts=2)

    # The retry branch: a retry time, nothing dead, decided from this row at the claim's attempts.
    assert await store.mark_failed(row.id, "transient", capped, now=1000.0) == FailOutcome(
        retry_at=1005.0, head_id=row.id, attempts=1
    )
    # The second attempt reaches the cap: one row DEAD, and the attempts the store itself read.
    (again,) = await store.claim_ready(now=2000.0, destination_name=single)
    assert again.id == row.id
    assert await store.mark_failed(row.id, "transient", capped, now=2000.0) == FailOutcome(
        dead=1, head_id=row.id, attempts=2
    )
    # A late retry on the row that is already DEAD keeps its state: a retry time, nothing dead.
    late = await store.mark_failed(row.id, "late", RetryPolicy(max_attempts=None), now=3000.0)
    assert late.dead == 0 and late.retry_at is not None and late.head_id == row.id

    # A vanished row and an empty batch write nothing and name no row.
    assert await store.mark_failed(f"gone-{run}", "x", capped, now=3000.0) == FailOutcome()
    assert await store.mark_batch_failed([], "x", capped, now=3000.0) == FailOutcome()

    # A batch decides from the first member still PRESENT, not the first id it was handed.
    (member,) = await store.claim_ready(now=4000.0, destination_name=batch)
    outcome = await store.mark_batch_failed(
        [f"gone-{run}", member.id], "envelope failed", RetryPolicy(max_attempts=1), now=4000.0
    )
    assert outcome == FailOutcome(dead=1, head_id=member.id, attempts=1)
