# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Per-message bookkeeping the FAILOVER verdict needs — the facts aggregate counters can't give.

A steady-state load run never constructs one of these (the sender/sink fast paths stay byte-identical
— the ``tracker`` arg defaults to ``None``); only ``--failover`` wires it in. It answers the three
questions a crash-mid-load raises that ``sent==engine_read`` cannot:

* **No loss (acknowledged):** every message the engine **accept-ACKed** (so it durably committed to the
  ingress stage, by the ACK-on-receipt invariant) reached the sink at least once — ``acked ⊆ delivered``.
  The un-ACKed-at-kill window (``sent − acked``) is the expected MLLP reconnect gap, reported separately
  and *not* counted as engine loss (a real partner resends un-ACKed frames; the harness sender doesn't).
* **Bounded duplicates:** at-least-once re-deliveries are expected across a failover (rows in-flight at the
  kill re-deliver after their lease/stale recovery); the exact dup count is the report's ``sink_received −
  engine_delivered`` (engine-side, DB-backed), so the tracker only needs the delivered SET for no-loss.
* **Per-lane FIFO ordering:** a FIFO lane is one engine **outbound destination**. The MLLP connector opens
  a *fresh* TCP connection per delivery, so the lane is NOT the socket — it is the destination, recovered
  from the delivered message's MSH-6 (the load graph stamps ``SINK_{lane}_{index}`` there under the ``edit``
  transform). Across a destination's many short-lived connections the **first** arrival of each seq must be
  monotonically non-decreasing (with a serialized sender, ``pool_size = 1``, harness seq order == engine
  insertion order); a *new* seq arriving below the lane's high-water first-arrival is a true FIFO break.
  An at-least-once re-delivery is an *already-seen* seq on the lane — counted as a repeat (a duplicate),
  never an ordering violation.

All state is bounded by the run's sent count (a failover run is a short burst, not a millions-message soak).
"""

from __future__ import annotations


class FailoverTracker:
    """Records acks (sender side) and deliveries (sink side) for the failover no-loss/ordering verdict."""

    __slots__ = (
        "_acked",
        "_delivered",
        "_lane_seen",
        "_lane_max",
        "lane_inversions",
        "lane_repeats",
    )

    def __init__(self) -> None:
        self._acked: set[int] = set()  # seqs the engine accept-ACKed (durably in the ingress stage)
        self._delivered: set[int] = set()  # seqs that reached the sink at least once
        self._lane_seen: dict[
            str, set[int]
        ] = {}  # per destination lane: seqs already delivered to it
        self._lane_max: dict[str, int] = {}  # per destination lane: highest first-arrival seq seen
        self.lane_inversions = 0  # NEW seqs that arrived out of order on a lane (true FIFO breaks)
        self.lane_repeats = (
            0  # re-deliveries (an already-seen seq on a lane) — duplicates, not reorders
        )

    # --- sender side ---------------------------------------------------------

    def on_ack(self, seq: int) -> None:
        """A message whose MSA-1 was an accept (AA/CA) — the engine has it durably committed."""
        self._acked.add(seq)

    # --- sink side -----------------------------------------------------------

    def on_delivery(self, lane: str, seq: int) -> None:
        """One delivery of ``seq`` arrived for outbound destination ``lane`` (MSH-6). First arrivals per
        lane must be monotonic; a re-delivery of an already-seen seq is a duplicate, not a reorder."""
        self._delivered.add(seq)
        seen = self._lane_seen.setdefault(lane, set())
        if seq in seen:
            self.lane_repeats += (
                1  # already delivered to this lane — an at-least-once re-delivery (dup)
            )
            return
        seen.add(seq)
        prev = self._lane_max.get(lane)
        if prev is not None and seq < prev:
            self.lane_inversions += (
                1  # a NEW seq arrived below this lane's high-water — a FIFO break
            )
        else:
            self._lane_max[lane] = seq

    # --- verdict -------------------------------------------------------------

    @property
    def acked_count(self) -> int:
        return len(self._acked)

    @property
    def delivered_count(self) -> int:
        """Distinct seqs delivered at least once (NOT total deliveries — fan-out sends each many times)."""
        return len(self._delivered)

    @property
    def lanes_observed(self) -> int:
        """Distinct destination lanes seen (== fan-out destinations). A value of 1 when fan-out > 1 means
        the lane key collapsed (e.g. MSH-6 wasn't stamped) and the ordering check went vacuous — the gated
        tests assert this is ≥ 2 so the per-lane FIFO verdict can never silently certify nothing."""
        return len(self._lane_seen)

    def acked_not_delivered(self) -> int:
        """Acknowledged messages that never reached the sink — the headline loss number (must be 0)."""
        return len(self._acked - self._delivered)

    @property
    def acked_all_delivered(self) -> bool:
        return self._acked <= self._delivered
