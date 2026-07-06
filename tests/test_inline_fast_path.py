# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""ADR 0057 — inline Step-A fast-path (collapse the routed stage for no-lookup, all-deliver,
single-handler messages).

These drive a real :class:`RegistryRunner` end-to-end (File-in → Router → Handler → File-out over a
temp dir + a real store) and assert the invariant-test matrix: byte-identity when OFF, the inline
happy path (route+transform+handoff fused into ONE commit via ``store.handoff``), every eligibility
fallback (multi-handler / filter / state-op / pass-through / db_lookup graph), the G1 poison-loop
bound, and the INV-1 crash-replay (re-pend → pure re-run → exactly one outbound row, no dup).

The path actually taken is observed by spying on the store handoff primitives: the INLINE path calls
``store.handoff`` exactly once and NEVER ``route_handoff``; the SPLIT path calls ``route_handoff``
(router half) + ``transform_handoff`` (transform half) and never ``handoff``.

Synthetic HL7 only; the SQLite leg runs here, the SQL Server + Postgres legs run in CI (the gate
lives in backend-agnostic ``wiring_runner.py`` and ``handoff`` exists in all three backends).
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

import pytest

from messagefoundry.config.models import ConnectorType, InternalErrorPolicy, RetryPolicy
from messagefoundry.config.wiring import (
    ConnectionSpec,
    DatabaseLookupSpec,
    InboundConnection,
    OutboundConnection,
    Registry,
    Send,
    SetState,
)
from messagefoundry.parsing.message import Message
from messagefoundry.pipeline.wiring_runner import RegistryRunner
from messagefoundry.store import MessageStatus, MessageStore, OutboxStatus, Stage

ADT = (
    "MSH|^~\\&|SENDINGAPP|SENDINGFAC|RECV|RFAC|20260604||ADT^A01|MSG1|P|2.5.1\r"
    "EVN|A01|20260604\r"
    "PID|1||100^^^H^MR||DOE^JANE\r"
)


@pytest.fixture
async def store(tmp_path: Path):  # type: ignore[no-untyped-def]
    s = await MessageStore.open(tmp_path / "engine.db")
    yield s
    await s.close()


def _registry(
    inbox: Path,
    outdir: Path,
    route,  # type: ignore[no-untyped-def]
    handlers: dict,  # type: ignore[type-arg]
    *,
    inline: bool = False,
    with_lookup: bool = False,
    second_outdir: Path | None = None,
) -> Registry:
    """A File-in → router → handler → File-out graph. ``inline`` opts the inbound into the ADR 0057
    fast-path; ``with_lookup`` declares a ``DatabaseLookup`` (forcing P-lookup False graph-wide)."""
    reg = Registry()
    reg.add_outbound(
        OutboundConnection(
            "file_out",
            ConnectionSpec(
                ConnectorType.FILE, {"directory": str(outdir), "filename": "{MSH-10}.hl7"}
            ),
        )
    )
    if second_outdir is not None:
        reg.add_outbound(
            OutboundConnection(
                "file_out2",
                ConnectionSpec(
                    ConnectorType.FILE,
                    {"directory": str(second_outdir), "filename": "{MSH-10}.hl7"},
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
            inline=inline,
        )
    )
    reg.add_router("r", route)
    for name, fn in handlers.items():
        reg.add_handler(name, fn)
    if with_lookup:
        reg.add_lookup(
            DatabaseLookupSpec(name="clarity", settings={"server": "db.local", "database": "C"})
        )
    return reg


class _HandoffSpy:
    """Records which staged-handoff primitive the runner used, delegating to the real store so the
    pipeline still runs. ``handoff`` = inline fast-path; ``route_handoff`` = split path."""

    def __init__(self, store: MessageStore) -> None:
        self.store = store
        self.handoff_calls = 0
        self.route_handoff_calls = 0
        self.transform_handoff_calls = 0
        self._real_handoff = store.handoff
        self._real_route_handoff = store.route_handoff
        self._real_transform_handoff = store.transform_handoff

    def install(self) -> None:
        async def handoff(**kw: Any) -> bool:
            self.handoff_calls += 1
            return await self._real_handoff(**kw)

        async def route_handoff(**kw: Any) -> bool:
            self.route_handoff_calls += 1
            return await self._real_route_handoff(**kw)

        async def transform_handoff(**kw: Any) -> bool:
            self.transform_handoff_calls += 1
            return await self._real_transform_handoff(**kw)

        self.store.handoff = handoff  # type: ignore[method-assign]
        self.store.route_handoff = route_handoff  # type: ignore[method-assign]
        self.store.transform_handoff = transform_handoff  # type: ignore[method-assign]


async def _run(reg: Registry, store: MessageStore, **kw: Any) -> RegistryRunner:
    runner = RegistryRunner(reg, store, poll_interval=0.02, **kw)
    await runner.start()
    return runner


async def _until_message(
    store: MessageStore, status: str, *, channel_id: str = "file_in", timeout: float = 4.0
) -> None:
    for _ in range(int(timeout / 0.02)):
        if await store.list_messages(channel_id=channel_id, status=status):
            return
        await asyncio.sleep(0.02)
    raise AssertionError(f"no {status} message within {timeout}s")


async def _until_stat(
    store: MessageStore, status: str, expected: int, timeout: float = 4.0
) -> None:
    for _ in range(int(timeout / 0.02)):
        if (await store.stats()).get(status, 0) == expected:
            return
        await asyncio.sleep(0.02)
    raise AssertionError(f"{status} != {expected} within {timeout}s")


def _route_arch(msg: Message) -> list[str]:
    return ["arch"]


def _handle_deliver(msg: Message) -> Send:
    msg["MSH-3"] = "FOUNDRY"
    return Send("file_out", msg)


# --- matrix #1: byte-identity when OFF ---------------------------------------


async def test_inline_off_uses_split_path_and_processes(
    store: MessageStore, tmp_path: Path
) -> None:
    """A no-lookup single-handler all-deliver graph with ``inline=False`` takes the SPLIT path
    (route_handoff + transform_handoff, NEVER handoff) — the zero-blast-radius default."""
    inbox, outdir = tmp_path / "in", tmp_path / "out"
    inbox.mkdir()
    (inbox / "a.hl7").write_bytes(ADT.encode("utf-8"))
    spy = _HandoffSpy(store)
    spy.install()

    reg = _registry(inbox, outdir, _route_arch, {"arch": _handle_deliver}, inline=False)
    runner = await _run(reg, store)
    try:
        await _until_stat(store, OutboxStatus.DONE.value, 1)
    finally:
        await runner.stop()

    assert spy.handoff_calls == 0  # never the inline primitive
    assert spy.route_handoff_calls == 1 and spy.transform_handoff_calls == 1  # the split path
    assert runner._inline_ok["file_in"] is False
    msgs = await store.list_messages(channel_id="file_in")
    assert len(msgs) == 1 and msgs[0]["status"] == MessageStatus.PROCESSED.value
    assert "FOUNDRY" in (outdir / "MSG1.hl7").read_bytes().decode("utf-8")


# --- matrix #2: inline happy path --------------------------------------------


async def test_inline_happy_path_fuses_handoff_and_processes(
    store: MessageStore, tmp_path: Path
) -> None:
    """``inline=True``, single-handler, all-deliver → one ``store.handoff`` (fused commit), never
    route_handoff/transform_handoff; finalizes PROCESSED with exactly one outbound row."""
    inbox, outdir = tmp_path / "in", tmp_path / "out"
    inbox.mkdir()
    (inbox / "a.hl7").write_bytes(ADT.encode("utf-8"))
    spy = _HandoffSpy(store)
    spy.install()

    reg = _registry(inbox, outdir, _route_arch, {"arch": _handle_deliver}, inline=True)
    runner = await _run(reg, store)
    try:
        await _until_stat(store, OutboxStatus.DONE.value, 1)
    finally:
        await runner.stop()

    assert runner._inline_ok["file_in"] is True
    assert spy.handoff_calls == 1  # the fused inline commit
    assert (
        spy.route_handoff_calls == 0 and spy.transform_handoff_calls == 0
    )  # routed stage bypassed
    msgs = await store.list_messages(channel_id="file_in")
    assert len(msgs) == 1 and msgs[0]["status"] == MessageStatus.PROCESSED.value
    mid = msgs[0]["id"]
    outbound = await store.outbox_for(mid)
    assert len(outbound) == 1  # exactly one outbound row per delivery
    assert outbound[0]["destination_name"] == "file_out"
    assert "FOUNDRY" in (outdir / "MSG1.hl7").read_bytes().decode("utf-8")
    # No routed-stage row was ever created on the inline path.
    cur = await store._db.execute(
        "SELECT COUNT(*) AS n FROM queue WHERE message_id=? AND stage=?",
        (mid, Stage.ROUTED.value),
    )
    assert (await cur.fetchone())["n"] == 0


# --- matrix #1/#3: eligibility fallbacks -------------------------------------


async def test_inline_multi_handler_falls_back_to_split(
    store: MessageStore, tmp_path: Path
) -> None:
    """M-single (G3): two handlers selected on an ``inline=True`` inbound → fall back to the split
    path; both handlers' Sends are delivered (no partial-handler loss)."""
    inbox = tmp_path / "in"
    out1, out2 = tmp_path / "out1", tmp_path / "out2"
    inbox.mkdir()
    (inbox / "a.hl7").write_bytes(ADT.encode("utf-8"))
    spy = _HandoffSpy(store)
    spy.install()

    def route(msg: Message) -> list[str]:
        return ["h1", "h2"]

    def h1(msg: Message) -> Send:
        return Send("file_out", msg)

    def h2(msg: Message) -> Send:
        return Send("file_out2", msg)

    reg = _registry(inbox, out1, route, {"h1": h1, "h2": h2}, inline=True, second_outdir=out2)
    runner = await _run(reg, store)
    try:
        await _until_stat(store, OutboxStatus.DONE.value, 2)
    finally:
        await runner.stop()

    assert spy.handoff_calls == 0  # multi-handler never fuses
    assert (
        spy.route_handoff_calls == 1 and spy.transform_handoff_calls == 2
    )  # split, one per handler
    assert (out1 / "MSG1.hl7").exists() and (out2 / "MSG1.hl7").exists()  # neither delivery lost
    msgs = await store.list_messages(channel_id="file_in")
    assert msgs[0]["status"] == MessageStatus.PROCESSED.value


async def test_inline_filtering_handler_falls_back_and_finalizes_filtered(
    store: MessageStore, tmp_path: Path
) -> None:
    """G2 / M-deliver: a single handler that returns no Sends (a filter) on an ``inline=True`` inbound
    → fall back to the split path → finalizes FILTERED (never stranded, no fused empty handoff)."""
    inbox, outdir = tmp_path / "in", tmp_path / "out"
    inbox.mkdir()
    (inbox / "a.hl7").write_bytes(ADT.encode("utf-8"))
    spy = _HandoffSpy(store)
    spy.install()

    def drop(msg: Message) -> None:
        return None  # filtered

    reg = _registry(inbox, outdir, _route_arch, {"arch": drop}, inline=True)
    runner = await _run(reg, store)
    try:
        await _until_message(store, MessageStatus.FILTERED.value)
    finally:
        await runner.stop()

    assert spy.handoff_calls == 0  # G2: never a zero-delivery fused handoff (would strand)
    assert spy.route_handoff_calls == 1 and spy.transform_handoff_calls == 1
    assert not (outdir / "MSG1.hl7").exists()


async def test_inline_state_op_handler_falls_back_to_split(
    store: MessageStore, tmp_path: Path
) -> None:
    """A handler returning a SetState (plus a delivery) on an ``inline=True`` inbound → fall back to
    the split path (handoff lacks the state-MERGE machinery transform_handoff carries)."""
    inbox, outdir = tmp_path / "in", tmp_path / "out"
    inbox.mkdir()
    (inbox / "a.hl7").write_bytes(ADT.encode("utf-8"))
    spy = _HandoffSpy(store)
    spy.install()

    def handle(msg: Message) -> list[Send | SetState]:
        return [Send("file_out", msg), SetState("seen", "MSG1", True)]

    reg = _registry(inbox, outdir, _route_arch, {"arch": handle}, inline=True)
    runner = await _run(reg, store)
    try:
        await _until_stat(store, OutboxStatus.DONE.value, 1)
    finally:
        await runner.stop()

    assert spy.handoff_calls == 0  # state-op present → split path
    assert spy.route_handoff_calls == 1 and spy.transform_handoff_calls == 1
    assert (outdir / "MSG1.hl7").exists()


async def test_db_lookup_graph_disables_inline_ok(store: MessageStore, tmp_path: Path) -> None:
    """P-lookup (matrix #7): a graph declaring a ``db_lookup`` connection with ``inline=True`` →
    ``inline_ok`` is False (graph-level, lookup presence disables inline for the WHOLE graph)."""
    inbox, outdir = tmp_path / "in", tmp_path / "out"
    inbox.mkdir()
    reg = _registry(
        inbox, outdir, _route_arch, {"arch": _handle_deliver}, inline=True, with_lookup=True
    )
    runner = await _run(reg, store)
    try:
        # The lookup executor built (graph declares a DatabaseLookup), so P-lookup excludes inline.
        assert runner._lookup_executor is not None
        assert runner._inline_ok["file_in"] is False
    finally:
        await runner.stop()


# --- matrix #3: poison-loop bound (G1) ---------------------------------------


async def test_inline_handler_raises_dead_letters_via_internal_error_policy(
    store: MessageStore, tmp_path: Path
) -> None:
    """G1: a handler that raises every run on ``inline=True`` → the raise from ``transform_one`` is
    caught by the inner try → the internal_error CONTINUE policy dead-letters it at the FIRST failure
    (message ERROR), NOT the outer retry-forever except. No infinite loop."""
    inbox, outdir = tmp_path / "in", tmp_path / "out"
    inbox.mkdir()
    (inbox / "a.hl7").write_bytes(ADT.encode("utf-8"))
    spy = _HandoffSpy(store)
    spy.install()

    def boom(msg: Message) -> Send:
        raise ValueError("inline transform always fails")

    reg = _registry(inbox, outdir, _route_arch, {"arch": boom}, inline=True)
    runner = await _run(reg, store, internal_error_default=InternalErrorPolicy.CONTINUE)
    try:
        await _until_message(store, MessageStatus.ERROR.value)
    finally:
        await runner.stop()

    assert spy.handoff_calls == 0  # the fused commit never ran (transform raised first)
    msgs = await store.list_messages(channel_id="file_in", status=MessageStatus.ERROR.value)
    assert len(msgs) == 1  # dead-lettered exactly once — not looping


async def test_inline_handler_raises_stop_policy_halts_lane(
    store: MessageStore, tmp_path: Path
) -> None:
    """G1 STOP variant: with internal_error=STOP, a raising inline handler halts the router lane
    (mark_failed retry-forever, connection_stopped alert) rather than dead-lettering or looping."""
    inbox, outdir = tmp_path / "in", tmp_path / "out"
    inbox.mkdir()
    (inbox / "a.hl7").write_bytes(ADT.encode("utf-8"))

    class _Sink:
        def __init__(self) -> None:
            self.stopped: list[str] = []

        def connection_stopped(self, name: str, *, detail: str = "") -> None:
            self.stopped.append(name)

        def __getattr__(self, _n: str):  # type: ignore[no-untyped-def]
            return lambda *a, **k: None

    def boom(msg: Message) -> Send:
        raise ValueError("inline transform fails")

    sink = _Sink()
    reg = _registry(inbox, outdir, _route_arch, {"arch": boom}, inline=True)
    # Pinned to per_lane: this asserts the STOP path emits connection_stopped EXACTLY once. Pooled
    # emits it twice (the shared item body at wiring_runner.py:2501 AND the dispatcher's lane-STOP
    # handler at stage_dispatcher.py:511) before the lane latches STOPPED — a bounded, deduped
    # (ADR 0044) duplicate ALERT, not a reliability difference. Pooled STOP is unit-tested in
    # test_stage_dispatcher.py (T16); this exact-count assertion is per_lane-specific.
    runner = await _run(
        reg,
        store,
        internal_error_default=InternalErrorPolicy.STOP,
        alert_sink=sink,
        claim_mode="per_lane",
    )
    try:
        for _ in range(200):
            if sink.stopped:
                break
            await asyncio.sleep(0.02)
        assert sink.stopped == ["file_in"]  # lane halted + alerted
        # The message is NOT dead-lettered (STOP preserves the row for replay after a fix+reload).
        assert not await store.list_messages(channel_id="file_in", status=MessageStatus.ERROR.value)
    finally:
        await runner.stop()


# --- matrix #1 (INV-1): crash-replay -----------------------------------------


async def test_inline_crash_after_claim_repend_pure_rerun_one_outbound(
    store: MessageStore, tmp_path: Path
) -> None:
    """INV-1: an eligible message, crash AFTER C2 (claim) BEFORE CF (handoff) → reset_stale_inflight
    re-pends the ingress row → the pure re-run produces EXACTLY ONE outbound row + PROCESSED (no dup).

    Simulated deterministically: enqueue the ingress row, claim it (C2 — leaves it INFLIGHT), then
    re-pend it (the crash-recovery step) and start the runner so the inline path runs to completion.
    """
    inbox, outdir = tmp_path / "in", tmp_path / "out"
    inbox.mkdir()
    spy = _HandoffSpy(store)
    spy.install()

    # Pre-stage one ingress row, then simulate a crash after the standalone claim (C2): the row is
    # INFLIGHT with attempts bumped, no handoff committed.
    mid = await store.enqueue_ingress(channel_id="file_in", raw=ADT, control_id="MSG1")
    claimed = await store.claim_next_fifo("file_in", stage=Stage.INGRESS.value)
    assert claimed is not None and claimed.message_id == mid
    repended = await store.reset_stale_inflight(stage=Stage.INGRESS.value)
    assert repended == 1  # the crashed in-flight ingress row re-pends to pending

    reg = _registry(inbox, outdir, _route_arch, {"arch": _handle_deliver}, inline=True)
    runner = await _run(reg, store)
    try:
        await _until_stat(store, OutboxStatus.DONE.value, 1)
    finally:
        await runner.stop()

    assert spy.handoff_calls == 1  # the re-run fused exactly once
    outbound = await store.outbox_for(mid)
    assert len(outbound) == 1  # EXACTLY ONE outbound row — no duplicate from the re-run
    assert (await store.get_message(mid))["status"] == MessageStatus.PROCESSED.value


async def test_inline_handoff_after_commit_is_idempotent_noop(
    store: MessageStore, tmp_path: Path
) -> None:
    """INV-1 after-CF: once the fused handoff has committed (ingress row deleted), a re-invocation of
    ``handoff`` for the same ingress row is an idempotent no-op (DELETE-guard → False), so a crash
    after the commit cannot duplicate the outbound row."""
    mid = await store.enqueue_ingress(channel_id="file_in", raw=ADT, control_id="MSG1")
    claimed = await store.claim_next_fifo("file_in", stage=Stage.INGRESS.value)
    assert claimed is not None
    # CF: the fused commit (ingress → outbound, ROUTED).
    first = await store.handoff(
        ingress_id=claimed.id,
        message_id=mid,
        channel_id="file_in",
        deliveries=[("file_out", ADT)],
        disposition=MessageStatus.ROUTED,
    )
    assert first is True
    # Re-run after the commit (the ingress row is gone) → idempotent no-op, no second outbound row.
    second = await store.handoff(
        ingress_id=claimed.id,
        message_id=mid,
        channel_id="file_in",
        deliveries=[("file_out", ADT)],
        disposition=MessageStatus.ROUTED,
    )
    assert second is False
    assert len(await store.outbox_for(mid)) == 1  # still exactly one outbound row


# --- matrix #3 (G6): ingress-lane attempts ceiling ---------------------------


async def test_inline_g6_dead_letters_at_finite_attempts_ceiling(
    store: MessageStore, tmp_path: Path
) -> None:
    """G6: on the inline path, a re-claimed ingress row whose attempts have reached the finite delivery
    ``max_attempts`` is dead-lettered ("ingress attempts exhausted") — closing the hard-crash-loop
    ceiling on the ingress lane (a deterministic process-crash bumps attempts each pass with no
    exception to catch). Simulated by pre-bumping attempts to the cap before the router worker runs.
    """
    inbox, outdir = tmp_path / "in", tmp_path / "out"
    inbox.mkdir()

    mid = await store.enqueue_ingress(channel_id="file_in", raw=ADT, control_id="MSG1")
    # Drive attempts up to the cap as repeated crash-restarts would (claim bumps, re-pend leaves it).
    for _ in range(3):
        claimed = await store.claim_next_fifo("file_in", stage=Stage.INGRESS.value)
        assert claimed is not None
        await store.reset_stale_inflight(stage=Stage.INGRESS.value)
    cur = await store._db.execute(
        "SELECT attempts FROM queue WHERE message_id=? AND stage=?",
        (mid, Stage.INGRESS.value),
    )
    assert (await cur.fetchone())["attempts"] == 3  # at the cap before the worker's next claim

    reg = _registry(inbox, outdir, _route_arch, {"arch": _handle_deliver}, inline=True)
    runner = await _run(reg, store, delivery_defaults=RetryPolicy(max_attempts=3))
    try:
        await _until_message(store, MessageStatus.ERROR.value)
    finally:
        await runner.stop()

    msgs = await store.list_messages(channel_id="file_in", status=MessageStatus.ERROR.value)
    assert len(msgs) == 1  # dead-lettered at the ceiling, not looping
    assert not (outdir / "MSG1.hl7").exists()
