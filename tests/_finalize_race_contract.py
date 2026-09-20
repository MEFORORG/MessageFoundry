# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Cross-backend store contract for the PER-MESSAGE FINALIZE LOCK under concurrent completion.

Deliberately **extra-free**, on the ``_session_rotation_contract`` / ``_webauthn_store_contract``
precedent: nothing optional is imported here, so the gated suites can import this module *inside*
their test functions and run the same contract on legs that install only ``.[dev,postgres]`` /
``.[dev,sqlserver]``. A module-level driver import would break the very legs it exists to cover.

THE PROPERTY. The finalizer is the SINGLE authority on a message's disposition (CLAUDE.md section 2,
the count-and-log invariant). Both destinations of one message complete at the same moment, each
``mark_done`` in its own transaction on its own pool connection, and the message must still land on
PROCESSED.

WHAT BREAKS WITHOUT THE LOCK is a LOST finalize, not a double one, and the shape is the same on both
backends. Each finalizer's ``FROM queue`` scan reads a statement snapshot (Postgres READ COMMITTED,
SQL Server RCSI) in which the sibling's DONE flip is still uncommitted, so both take the "pending or
inflight at any stage -> still moving" branch and NEITHER writes the terminal status. The message is
stranded at its handoff disposition with every delivery already made: accepted, delivered, and then
mis-reported, which is exactly what the invariant forbids. Every other finalize path in the two
gated suites is sequential and cannot observe this.

WHY THE REPETITION, AND WHERE THE NUMBER COMES FROM. The defect is a race, so one pass proves
nothing -- it can pick the benign interleaving and stay green over a store carrying no lock at all.
Paired arms against a local PostgreSQL 16.14, running THIS function rather than a sketch of it: with
the lock, all 30 rounds pass; with the per-message finalize advisory lock patched out, it raises at
round 1, and a counting twin of the same body stranded 28 of 30. ROUND 0 PASSED EVEN IN THE MUTANT
ARM, so a single-round test would have falsely passed over a store with no lock at all. At roughly a
0.93 per-round failure rate, 30 rounds is far more headroom than that backend needs -- it is kept
because the SQL Server rate below is unmeasured, not because Postgres needs it.

The SQL Server figure is CARRIED OVER from Postgres, never measured there -- its applock is a
different mechanism (``sp_getapplock``) under a different snapshot rule, so the per-round failure
rate could differ. Read the gated ``sqlserver-store`` CI job for that backend's first real result.

TWO CALLERS, DELIBERATELY: THERE IS NO SQLITE ARM, and one would be vacuous rather than missing.
SQLite has no per-message finalize lock to remove -- ``_lock_finalize_batch`` exists only in
``postgres.py`` and ``sqlserver.py``, and ``MessageStore`` serializes every multi-statement
transaction on ONE global ``asyncio.Lock`` (``messagefoundry/store/store.py``, "Serialise
multi-statement transactions"). Two concurrent ``mark_done`` calls there run one at a time over one
connection, so this contract would pass unconditionally and could not be made to fail by deleting
anything. A test that cannot fail is worse than no test: it licenses the behaviour while withdrawing
the caution its absence preserved. If SQLite ever grows a narrower finalize lock, add the arm then.
"""

from __future__ import annotations

import asyncio
from typing import Any

from messagefoundry.store import MessageStatus

#: Rounds per run. See "WHY THE REPETITION" above for the measurement behind the number.
FINALIZE_RACE_ROUNDS = 30

# A synthetic ADT, never real PHI. Carried here so the contract needs nothing from its caller.
_RAW = "MSH|^~\\&|A|B|C|D|20260101||ADT^A01|MSG1|P|2.5.1\r"


async def assert_concurrent_finalize_reaches_processed(
    store: Any, *, rounds: int = FINALIZE_RACE_ROUNDS
) -> None:
    """Complete BOTH destinations of one message concurrently, ``rounds`` times over.

    Every round must reach PROCESSED. Creates its own messages, so the caller needs no fixture
    beyond a live store on a clean slate.
    """
    for round_no in range(rounds):
        # Flat timestamps, as every neighbouring test uses: an earlier round's rows are DONE, so no
        # `now` can make them claimable again, and `mark_done` spends `now` only on updated_at and
        # the delivered-key stamp, neither of which this contract reads.
        mid = await store.enqueue_message(
            channel_id="IB", raw=_RAW, deliveries=[("OB1", "p1"), ("OB2", "p2")], now=100.0
        )
        # Claim per DESTINATION rather than one limit=N sweep. SQL Server's claim opens with
        # SET LOCK_TIMEOUT 0 and may fail-close a batch to empty (see _claim_until in that suite),
        # which would flake a bare `len(items) == 2` for a reason that has nothing to do with the
        # finalizer -- and a flake here reads as the very defect this contract is pinning.
        items = []
        for dest in ("OB1", "OB2"):
            claimed = await store.claim_ready(now=200.0, destination_name=dest)
            assert len(claimed) == 1, (
                f"round {round_no}: {dest} claimed {len(claimed)} rows, want 1"
            )
            items.append(claimed[0])

        await asyncio.gather(*(store.mark_done(item.id, now=300.0) for item in items))

        msg = await store.get_message(mid)
        assert msg is not None, f"round {round_no}: message {mid} vanished"
        assert msg["status"] == MessageStatus.PROCESSED.value, (
            f"round {round_no}: finalized {msg['status']!r}, not PROCESSED -- both deliveries are "
            "DONE, so the two finalizers raced and neither claimed the terminal write"
        )
