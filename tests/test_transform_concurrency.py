# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""BACKLOG #214 — intra-message concurrent transform of a message's routed rows.

A message that routes to N handlers produces N ``routed``-stage rows. Today they transform
SEQUENTIALLY in the transform worker; #214 overlaps their **pure** transforms (distinct destinations
carry no mutual ordering dependency) while keeping every store handoff SERIAL and in ascending claim
order — so the single-serial-writer invariant that per-destination outbound FIFO (ADR 0059) relies on
is preserved.

These tests pin the two hard invariants the seam must never break:

* **strict-FIFO** — a message's routed rows targeting the SAME destination still yield outbound rows in
  the original (routed-row) order, and message N's rows still commit before N+1's for a lane. The
  reorder test FAILS if the handoff were applied in transform-COMPLETION order instead of claim order.
* **at-least-once** — a crash mid-batch (a handoff raises after K of N committed) recovers via
  ``reset_stale_inflight`` and re-derives an IDENTICAL delivered set + per-destination order, no dupes,
  no loss.

Plus a liveness proof (a ``threading.Barrier(N)`` inside the handlers only clears if N transforms run
concurrently) and the default-off byte-identity (concurrency cap 1 == the sequential path).

One further test PINS the sibling state-visibility semantics under concurrency (BACKLOG #214
state-snapshot guard): because every sibling's pure transform runs before any sibling's handoff
commits, the concurrent run reads a FROZEN point-in-time snapshot of the committed transform-state
captured at run-start, so every sibling DETERMINISTICALLY observes message-batch-start state — a later
sibling never sees an earlier sibling's same-run ``state_set``/``set_meta`` write, regardless of how the
transforms interleave. Final committed state is identical to the sequential path (the apply is serial),
so this is a defined, interleaving-independent READ semantics, not a FIFO/at-least-once break; the
opt-in knob's contract is "sibling handlers read batch-start state; they do not chain it to each other".
The sequential path is unchanged (live view; the reader still sees a prior sibling's committed write).
"""

from __future__ import annotations

import asyncio
import threading
import time
from collections.abc import AsyncIterator, Iterator, Mapping
from pathlib import Path
from typing import Any

import pytest

from messagefoundry.config.models import ConnectorType
from messagefoundry.config.state import state_get
from messagefoundry.config.wiring import (
    ConnectionSpec,
    InboundConnection,
    OutboundConnection,
    Registry,
    Send,
    SetState,
)
from messagefoundry.pipeline.wiring_runner import RegistryRunner
from messagefoundry.store import MessageStore
from messagefoundry.transports import base as transport_base
from messagefoundry.transports.base import DeliveryResponse, DestinationConnector

ADT = (
    "MSH|^~\\&|SENDINGAPP|SENDINGFAC|RECV|RFAC|20260604||ADT^A01|MSG1|P|2.5.1\r"
    "EVN|A01|20260604\r"
    "PID|1||100^^^H^MR||DOE^JANE\r"
)


# --- a recording outbound connector (records delivery ORDER per destination) -------------------------
# The delivery worker drains one destination's outbound rows strictly in ``seq`` order (one serial
# consumer per lane), so the order this records IS the per-destination outbound FIFO the invariant is
# about. We register it over ConnectorType.FILE for the duration of a test and restore the real builder.


class _RecordingDestination(DestinationConnector):
    def __init__(self, name: str, sink: list[tuple[str, str]]) -> None:
        self._name = name
        self._sink = sink

    async def send(
        self, payload: str, *, metadata: Mapping[str, str] | None = None
    ) -> DeliveryResponse | None:
        self._sink.append((self._name, payload))
        return None


@pytest.fixture
def sink() -> Iterator[list[tuple[str, str]]]:
    """A shared (destination_name, payload) delivery log + a recording FILE-destination builder that
    appends to it. Saves/restores the real FILE destination builder so other tests are unaffected."""
    recorded: list[tuple[str, str]] = []
    original = transport_base._DESTINATIONS.get(ConnectorType.FILE)

    def _build(config: Any) -> _RecordingDestination:
        return _RecordingDestination(config.name, recorded)

    transport_base.register_destination(ConnectorType.FILE, _build)
    try:
        yield recorded
    finally:
        if original is not None:
            transport_base.register_destination(ConnectorType.FILE, original)
        else:  # pragma: no cover - FILE is always registered in practice
            transport_base._DESTINATIONS.pop(ConnectorType.FILE, None)


@pytest.fixture
async def store(tmp_path: Path) -> AsyncIterator[MessageStore]:
    s = await MessageStore.open(tmp_path / "engine.db")
    yield s
    await s.close()


def _dest(name: str) -> OutboundConnection:
    # Settings are valid FILE settings but the recording builder ignores them.
    return OutboundConnection(
        name,
        ConnectionSpec(ConnectorType.FILE, {"directory": ".", "filename": "{MSH-10}.hl7"}),
    )


def _drop(inbox: Path, control_id: str = "MSG1") -> None:
    inbox.mkdir(exist_ok=True)
    body = ADT.replace("MSG1", control_id)
    (inbox / f"{control_id}.hl7").write_bytes(body.encode("utf-8"))


async def _wait_until(pred: Any, timeout: float = 5.0, tick: float = 0.02) -> None:
    elapsed = 0.0
    while not pred():
        await asyncio.sleep(tick)
        elapsed += tick
        if elapsed > timeout:
            raise AssertionError("condition not met within timeout")


def _runner(reg: Registry, store: MessageStore, *, concurrency: int, batch: int) -> RegistryRunner:
    # #214's seam lives in the per-lane transform worker's batch loop. The pooled StageDispatcher
    # (the default claim_mode) drains the routed lane one head at a time and is an explicit follow-up
    # (design brief §2), so the concurrency tests select claim_mode="per_lane".
    runner = RegistryRunner(
        reg, store, poll_interval=0.02, fifo_claim_batch=batch, claim_mode="per_lane"
    )
    runner._transform_concurrency = concurrency
    return runner


# --- strict-FIFO: same-destination siblings keep routed-row order under concurrency ------------------


async def test_same_destination_siblings_deliver_in_routed_order(
    store: MessageStore, sink: list[tuple[str, str]], tmp_path: Path
) -> None:
    """One message → H_a then H_b, BOTH sending to the SAME destination D, with the EARLIER routed row
    (H_a) transforming SLOWER. Under intra-message concurrency H_b's transform completes first — yet the
    handoff is applied in claim (routed-row) order, so D delivers A before B. This FAILS if the handoff
    were applied in transform-completion order (it would deliver B before A)."""
    inbox = tmp_path / "in"
    _drop(inbox)

    def h_a(m: Any) -> Send:
        time.sleep(0.25)  # the earlier row transforms SLOWER (off-loop; does not stall the loop)
        return Send("D", "A")

    def h_b(m: Any) -> Send:
        return Send("D", "B")  # the later row transforms instantly → completes first

    reg = Registry()
    reg.add_outbound(_dest("D"))
    reg.add_inbound(
        InboundConnection(
            "IB",
            ConnectionSpec(
                ConnectorType.FILE,
                {"directory": str(inbox), "pattern": "*.hl7", "poll_seconds": 0.02},
            ),
            router="r",
        )
    )
    reg.add_router("r", lambda m: ["h_a", "h_b"])
    reg.add_handler("h_a", h_a)
    reg.add_handler("h_b", h_b)

    runner = _runner(reg, store, concurrency=4, batch=8)
    await runner.start()
    try:
        await _wait_until(lambda: len(sink) == 2)
    finally:
        await runner.stop()

    # Per-destination FIFO: A (lower routed rowid) before B, despite B's transform finishing first.
    assert sink == [("D", "A"), ("D", "B")]


# --- strict-FIFO: independent destinations really overlap (liveness proof) ---------------------------


async def test_distinct_destinations_transform_concurrently(
    store: MessageStore, sink: list[tuple[str, str]], tmp_path: Path
) -> None:
    """One message → N handlers → N DISTINCT destinations, each handler rendezvousing on a
    ``threading.Barrier(N)``. The barrier only clears if all N transforms run CONCURRENTLY (a sequential
    run would leave the first handler waiting alone → BrokenBarrierError). All N destinations delivered
    proves the overlap actually occurs."""
    inbox = tmp_path / "in"
    _drop(inbox)
    n = 4
    barrier = threading.Barrier(n, timeout=5.0)

    def make(i: int) -> Any:
        def handler(m: Any) -> Send:
            barrier.wait()  # blocks until all N sibling transforms are in-flight together
            return Send(f"D{i}", f"p{i}")

        return handler

    reg = Registry()
    for i in range(n):
        reg.add_outbound(_dest(f"D{i}"))
        reg.add_handler(f"h{i}", make(i))
    reg.add_inbound(
        InboundConnection(
            "IB",
            ConnectionSpec(
                ConnectorType.FILE,
                {"directory": str(inbox), "pattern": "*.hl7", "poll_seconds": 0.02},
            ),
            router="r",
        )
    )
    reg.add_router("r", lambda m: [f"h{i}" for i in range(n)])

    runner = _runner(reg, store, concurrency=n, batch=n)
    await runner.start()
    try:
        await _wait_until(lambda: len(sink) == n)
    finally:
        await runner.stop()

    assert {name for name, _ in sink} == {f"D{i}" for i in range(n)}
    assert {payload for _, payload in sink} == {f"p{i}" for i in range(n)}


# --- strict-FIFO: cross-message rows are NOT overlapped (message N before N+1) -----------------------


async def test_cross_message_order_preserved(
    store: MessageStore, sink: list[tuple[str, str]], tmp_path: Path
) -> None:
    """Two messages M1, M2 each → one handler → the SAME destination D, with M1 (the earlier message)
    transforming SLOWER. Intra-message concurrency must NOT overlap ACROSS messages: M1's row commits
    before M2's, so D delivers M1 before M2 even though M2's transform would finish first if overlapped.
    Guards against a mis-scoped concurrency that fans out across message boundaries."""
    inbox = tmp_path / "in"
    _drop(inbox, "M1")
    _drop(inbox, "M2")

    def slow(m: Any) -> Send:
        time.sleep(0.25)
        return Send("D", "M1")

    def fast(m: Any) -> Send:
        return Send("D", "M2")

    reg = Registry()
    reg.add_outbound(_dest("D"))
    reg.add_inbound(
        InboundConnection(
            "IB",
            ConnectionSpec(
                ConnectorType.FILE,
                {"directory": str(inbox), "pattern": "*.hl7", "poll_seconds": 0.02},
            ),
            router="r",
        )
    )
    # Route by control id so M1→slow, M2→fast (single handler each → one routed row each).
    reg.add_router("r", lambda m: ["slow"] if str(m).find("M1") != -1 else ["fast"])
    reg.add_handler("slow", slow)
    reg.add_handler("fast", fast)

    runner = _runner(reg, store, concurrency=4, batch=8)
    await runner.start()
    try:
        await _wait_until(lambda: len(sink) == 2)
    finally:
        await runner.stop()

    # M1 (earlier message, lower rowid) delivers before M2 despite M2's faster transform.
    assert sink == [("D", "M1"), ("D", "M2")]


# --- at-least-once: crash mid-batch re-derives an identical, in-order delivered set ------------------


async def test_crash_midbatch_recovers_identical_and_in_order(
    store: MessageStore, sink: list[tuple[str, str]], tmp_path: Path
) -> None:
    """One message → N handlers → the SAME destination D with ordered payloads p0..p{N-1}. Inject a
    handoff fault on p2 the FIRST time it is applied (after p0, p1 committed). The worker backs off,
    leaving p2..p{N-1} INFLIGHT; ``reset_stale_inflight`` re-pends them and a restarted runner re-runs
    them. The final D delivery is EXACTLY p0..p{N-1}, in order, each once — no dupes, no loss."""
    inbox = tmp_path / "in"
    _drop(inbox)
    n = 5
    fail_payload = "p2"

    reg = Registry()
    reg.add_outbound(_dest("D"))
    for i in range(n):
        reg.add_handler(f"h{i}", (lambda p: lambda m: Send("D", p))(f"p{i}"))
    reg.add_inbound(
        InboundConnection(
            "IB",
            ConnectionSpec(
                ConnectorType.FILE,
                {"directory": str(inbox), "pattern": "*.hl7", "poll_seconds": 0.02},
            ),
            router="r",
        )
    )
    reg.add_router("r", lambda m: [f"h{i}" for i in range(n)])

    # Wrap transform_handoff to raise ONCE, the first time it would commit p2's outbound row. Serial,
    # in-claim-order apply guarantees this fires only after p0, p1 have committed.
    original_handoff = store.transform_handoff
    fired = {"done": False}

    async def failing_handoff(*args: Any, **kwargs: Any) -> None:
        deliveries = kwargs.get("deliveries") or []
        if not fired["done"] and any(p == fail_payload for _, p in deliveries):
            fired["done"] = True
            raise RuntimeError("injected mid-batch crash")
        return await original_handoff(*args, **kwargs)

    store.transform_handoff = failing_handoff  # type: ignore[method-assign]

    runner = _runner(reg, store, concurrency=n, batch=n)
    await runner.start()
    try:
        # Fault fires; p0, p1 delivered. The remaining rows are stuck INFLIGHT (no further progress).
        await _wait_until(lambda: fired["done"] and len(sink) == 2)
        # A beat to confirm no further deliveries happen while the tail is stranded INFLIGHT.
        await asyncio.sleep(0.2)
        assert sorted(p for _, p in sink) == ["p0", "p1"]
    finally:
        await runner.stop()

    # Recover: restore the store, re-pend the INFLIGHT tail (engine-startup behavior), restart.
    store.transform_handoff = original_handoff  # type: ignore[method-assign]
    recovered = await store.reset_stale_inflight()
    assert recovered >= 1  # p2..p4 (routed rows) came back to pending

    runner2 = _runner(reg, store, concurrency=n, batch=n)
    await runner2.start()
    try:
        await _wait_until(lambda: len(sink) == n)
        # Give any stray duplicate a chance to appear (it must not).
        await asyncio.sleep(0.2)
    finally:
        await runner2.stop()

    # Identical delivered SET (each once) and per-destination ORDER == routed order.
    assert [p for _, p in sink] == [f"p{i}" for i in range(n)]


# --- default-off byte-identity: cap 1 is the sequential path ----------------------------------------


async def test_concurrency_default_is_sequential(
    store: MessageStore, sink: list[tuple[str, str]], tmp_path: Path
) -> None:
    """With the default cap (1) a multi-handler message still delivers every row, in routed order — the
    concurrency seam is inert. Uses the constructor default (no ``_transform_concurrency`` override)."""
    inbox = tmp_path / "in"
    _drop(inbox)
    n = 4

    reg = Registry()
    reg.add_outbound(_dest("D"))
    for i in range(n):
        reg.add_handler(f"h{i}", (lambda p: lambda m: Send("D", p))(f"p{i}"))
    reg.add_inbound(
        InboundConnection(
            "IB",
            ConnectionSpec(
                ConnectorType.FILE,
                {"directory": str(inbox), "pattern": "*.hl7", "poll_seconds": 0.02},
            ),
            router="r",
        )
    )
    reg.add_router("r", lambda m: [f"h{i}" for i in range(n)])

    # Default fifo_claim_batch is 1 too, so rows drain one-at-a-time; assert byte-identical FIFO output.
    runner = RegistryRunner(reg, store, poll_interval=0.02)
    assert runner._transform_concurrency == 1  # default OFF
    await runner.start()
    try:
        await _wait_until(lambda: len(sink) == n)
    finally:
        await runner.stop()

    assert [p for _, p in sink] == [f"p{i}" for i in range(n)]


# --- deterministic snapshot: intra-message sibling state-visibility is interleaving-independent -------


async def test_sibling_state_visibility_is_deterministic_under_concurrency(
    sink: list[tuple[str, str]], tmp_path: Path
) -> None:
    """PIN the sibling state-visibility semantics under concurrency (BACKLOG #214 state-snapshot guard).
    Transform-state (ADR 0005) is read through a LIVE ``state_view()`` that only reflects a write once
    that row's ``transform_handoff`` commits. One message routes to a WRITER handler (``SetState(ns, K,
    V)``) then a READER handler (``state_get(ns, K)``), writer routed FIRST (lower rowid).

    * SEQUENTIAL path (``concurrency=1``): the writer's row commits before the reader transforms, so the
      reader reads the live view and OBSERVES ``V`` — unchanged from before this guard.
    * CONCURRENT path (``concurrency>1`` + co-claimed batch): every sibling's pure transform runs BEFORE
      any sibling's handoff commits, so the run captures ONE frozen point-in-time snapshot of the
      committed state at run-start and every sibling reads THAT. The reader therefore deterministically
      observes ``None`` (K is absent at message-batch start) — it never sees the writer's same-run write,
      and the result is interleaving-INDEPENDENT (asserted by repeating the concurrent run). This is the
      #214 state-snapshot guard: what was a scheduling-dependent visibility divergence is now a defined,
      deterministic READ semantics ("siblings read batch-start state; they don't chain it to each other").

    The FINAL committed state is ``V`` in both cases (the apply is serial in claim order), so this is
    READ-side only, NOT a FIFO/at-least-once break.

    SCOPE (what this test does and does NOT pin): it pins the *ordering* semantics — the sequential
    reader chains (sees ``V``) and the concurrent reader does not observe a sibling's SAME-RUN write
    (sees ``None``), the latter because every pure compute in a run finishes before any sibling's handoff
    commits. It does **not** by itself pin the state SNAPSHOT: reverting :meth:`_prepare_routed` to the
    live ``state_view()`` leaves it GREEN, because within one run a live read already sees run-start state
    (no sibling has committed yet). The snapshot's distinct guarantee — isolating a compute from a write
    that COMMITS mid-gather (a cross-lane worker) — is pinned separately by
    :func:`test_snapshot_isolates_a_write_committed_during_the_gather`. This test reds only if the
    sequential reader ever saw ``None``, or the concurrent reader ever saw ``V`` (a sibling handoff
    committing before the gather completes — a compute/commit-ordering break)."""
    ns, key, val = "sib214", "K", "V"

    def writer(m: Any) -> SetState:
        return SetState(ns, key, val)  # no Send: this row only declares a state write

    def reader(m: Any) -> Send:
        # Encode what the reader OBSERVED into its delivered payload so the sink captures it:
        # "'V'" on a hit (committed sibling write visible), "None" on a miss.
        return Send("D", f"{state_get(ns, key)!r}")

    def _build(inbox: Path) -> Registry:
        reg = Registry()
        reg.add_outbound(_dest("D"))
        reg.add_inbound(
            InboundConnection(
                "IB",
                ConnectionSpec(
                    ConnectorType.FILE,
                    {"directory": str(inbox), "pattern": "*.hl7", "poll_seconds": 0.02},
                ),
                router="r",
            )
        )
        # writer routed FIRST (lower rowid) → its handoff would commit before the reader transforms
        # in the sequential path; reader SECOND reads the same key back.
        reg.add_router("r", lambda m: ["writer", "reader"])
        reg.add_handler("writer", writer)
        reg.add_handler("reader", reader)
        return reg

    async def _observe(concurrency: int, sub: str) -> str:
        # Fresh inbox + store per scenario so the runs never share committed state.
        inbox = tmp_path / sub
        _drop(inbox)
        s = await MessageStore.open(tmp_path / f"{sub}.db")
        # batch=8 co-claims BOTH sibling routed rows into one batch: at concurrency>1 they form one
        # concurrent run; at concurrency=1 the batch loop is the exact sequential per-item path.
        runner = _runner(_build(inbox), s, concurrency=concurrency, batch=8)
        sink.clear()
        await runner.start()
        try:
            await _wait_until(lambda: len(sink) == 1)  # only the reader delivers
        finally:
            await runner.stop()
            await s.close()
        return sink[0][1]

    # Sequential path: the reader SEES the writer's committed state (live view, unchanged).
    assert await _observe(1, "seq") == repr(val)  # "'V'"
    # Concurrent path: every sibling reads the frozen run-start snapshot → the reader deterministically
    # does NOT see the same-run write. Repeat to demonstrate convergence to the one defined result
    # (interleaving-independent), not a scheduling-dependent divergence.
    for i in range(5):
        assert await _observe(4, f"conc{i}") == repr(None)  # "None", every time


# --- pin the snapshot itself: a write COMMITTED during the gather is isolated (reds on revert-to-live) -


async def test_snapshot_isolates_a_write_committed_during_the_gather(
    sink: list[tuple[str, str]], tmp_path: Path
) -> None:
    """PIN the #214 state SNAPSHOT — the guard the test above deliberately does NOT catch (a revert to
    the live view leaves that one green, because within one run every pure compute finishes before any
    sibling's handoff commits, so a live read there already sees run-start state). The snapshot's real,
    load-bearing effect is isolating a sibling's compute from a state write that COMMITS *during* the
    gather window — in production a CROSS-LANE transform worker (a different inbound) committing the same
    ``(namespace, key)`` into the shared read-through cache.

    We reproduce that mid-gather commit DETERMINISTICALLY (no sleeps/timing races) with a
    ``threading.Event`` handshake: one message routes to two sibling handlers (``reader`` + ``filler``),
    so the batch forms a >=2-row concurrent run. The ``reader``'s transform runs off-loop INSIDE the
    gather — hence necessarily AFTER the run-start snapshot was captured — signals that it is parked at a
    barrier, then blocks BEFORE reading state. While it is parked the test publishes ``K=V`` straight
    into the live state cache (exactly what ``transform_handoff`` does on commit — store.py
    ``self._state_cache[ck] = cv``), then releases the reader, so ``state_get`` is guaranteed to run
    after that write. Ordering is fixed by the handshake: snapshot < reader-parked < mid-gather commit <
    release < ``state_get``.

    * SNAPSHOT (shipped): the reader reads the FROZEN run-start mapping → observes ``None`` — the
      mid-gather commit is invisible.
    * LIVE view (revert ``_prepare_routed``'s ``state_view`` to ``self.store.state_view()``): the reader
      reads the live cache, which now holds ``V`` → observes ``'V'`` → **this test REDS**.

    So unlike ``test_sibling_state_visibility_is_deterministic_under_concurrency``, this one FAILS if the
    snapshot is removed: it pins the guard, not the pre-existing compute-before-commit ordering."""
    ns, key, val = "gate214", "K", "V"
    reader_parked = threading.Event()  # reader sets this once its compute reaches the read barrier
    release_reader = threading.Event()  # test sets this after publishing the mid-gather commit

    def reader(m: Any) -> Send:
        # Runs OFF the loop (to_thread) INSIDE the gather → after the run-start snapshot was captured.
        # Announce we are parked, block until the test has published the live-cache write, THEN read —
        # so state_get observes the post-commit cache. Frozen snapshot → None; live view → V.
        reader_parked.set()
        release_reader.wait(timeout=5.0)
        return Send("R", f"{state_get(ns, key)!r}")

    def filler(m: Any) -> Send:
        # A second sibling row so the run is >=2 rows and the CONCURRENT branch is taken (len(run) < 2
        # falls back to the sequential per-item path). It touches no state.
        return Send("F", "f")

    inbox = tmp_path / "in"
    _drop(inbox)
    reg = Registry()
    reg.add_outbound(_dest("R"))
    reg.add_outbound(_dest("F"))
    reg.add_inbound(
        InboundConnection(
            "IB",
            ConnectionSpec(
                ConnectorType.FILE,
                {"directory": str(inbox), "pattern": "*.hl7", "poll_seconds": 0.02},
            ),
            router="r",
        )
    )
    reg.add_router("r", lambda m: ["reader", "filler"])
    reg.add_handler("reader", reader)
    reg.add_handler("filler", filler)

    s = await MessageStore.open(tmp_path / "gate.db")
    # batch=8 co-claims BOTH sibling rows into one batch; concurrency=4 makes them one concurrent run.
    runner = _runner(reg, s, concurrency=4, batch=8)
    sink.clear()
    await runner.start()
    try:
        # The reader's compute has reached the barrier: the run-start snapshot is already captured and
        # the gather is in-flight (this is the deterministic sync point — not a sleep).
        await _wait_until(reader_parked.is_set)
        # Publish a state write into the LIVE read-through cache mid-gather, exactly as transform_handoff
        # does on commit (store.py `_state_cache[ck] = cv`). WHITE-BOX by necessity: the only public path
        # to a committed state write is a handler's SetState, which commits at _apply_routed — i.e. AFTER
        # the gather — so there is no in-gather public seam; this direct write faithfully models the
        # cross-lane commit the snapshot must isolate.
        s._state_cache[(ns, key)] = val
        release_reader.set()
        await _wait_until(lambda: len(sink) == 2)
    finally:
        release_reader.set()  # never leave the worker thread parked if we bailed out early
        await runner.stop()
        await s.close()

    observed = dict(sink)  # {destination_name: delivered payload}
    # The snapshot froze run-start state (K absent), so the reader is isolated from the mid-gather commit.
    # Under a revert to the live view this would be repr("V") and the assert would RED.
    assert observed["R"] == repr(None)  # "None"
