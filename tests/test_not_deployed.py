# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Connection present in the config but NOT DEPLOYED (#233, ADR 0111) — engine enforcement.

``deployed=False`` is a first-class lifecycle state: the connection stays in the graph (history,
traceability, a future go-live) but the engine NEVER wires it, starts it, or queues to it, and never
resolves its ``env()`` values — so a connection whose credentials do not exist yet can sit in the
config without failing ``messagefoundry check`` or bringing the engine up DEGRADED at every boot.

The four gates this pins, in the order they bite:
  NEVER BUILT   — ``_build_check_connectors`` skips it, so ``check`` / reload / promote / every
                  ``connection upsert`` stop exploding on its absent secrets (the headline).
  NEVER WIRED   — both boot gates, both reload loops, the scheduler, and the operator start/restart
                  path all refuse it. ``deployed=False`` WINS over ``auto_start``.
  NEVER A LANE  — unlike ``auto_start=False``, a not-deployed OUTBOUND spawns NO delivery worker at
                  all, so nothing can claim, back off, buildup-alert or stall-alert on it.
  NEVER QUEUED  — ``transform_one`` DECLINES a ``Send`` to it, so it can never become a
                  ``DeliveryPreview`` and therefore can never be committed to the outbound stage.

Distinct from all three neighbours: ``simulate`` (lane IS built and DOES take rows), a DR/schedule
park (rows are RETAINED, queued and RETRIED), and ``auto_start=False`` (deployed, just not up right
now — an operator start is the designed override). Its rows are neither retried nor stranded: they
are never produced. The default (``deployed=True``) is byte-identical."""

from __future__ import annotations

import asyncio
import socket
from collections.abc import Sequence
from datetime import UTC, datetime, time
from pathlib import Path

import httpx
import pytest

from messagefoundry.config.models import ActiveWindow, ConnectorType, Schedule
from messagefoundry.config.wiring import (
    MLLP,
    ConnectionSpec,
    InboundConnection,
    OutboundConnection,
    Registry,
    Send,
    WiringError,
    build_inbound_connection,
    build_outbound_connection,
    env,
)
from messagefoundry.pipeline import Engine
from messagefoundry.pipeline.dryrun import transform_one
from messagefoundry.pipeline.wiring_runner import NotDeployedError, RegistryRunner
from messagefoundry.store import MessageStatus, MessageStore, Stage

ADT = (
    "MSH|^~\\&|SENDINGAPP|SENDINGFAC|RECV|RFAC|20260604||ADT^A01|MSG1|P|2.5.1\r"
    "EVN|A01|20260604\r"
    "PID|1||100^^^H^MR||DOE^JANE\r"
)


def _free_port() -> int:
    s = socket.socket()
    try:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])
    finally:
        s.close()


@pytest.fixture
async def store(tmp_path: Path):  # type: ignore[no-untyped-def]
    s = await MessageStore.open(tmp_path / "notdeployed.db")
    yield s
    await s.close()


def _file_out(name: str, directory: Path, **kw: object) -> OutboundConnection:
    return build_outbound_connection(
        name,
        ConnectionSpec(
            ConnectorType.FILE, {"directory": str(directory), "filename": "{MSH-10}.hl7"}
        ),
        **kw,  # type: ignore[arg-type]
    )


def _unresolvable_out(name: str, *, deployed: bool) -> OutboundConnection:
    """An outbound whose settings are ENTIRELY env() refs with no values on this instance — the
    motivating case: a partner whose credentials have not been provisioned yet."""
    return build_outbound_connection(
        name,
        ConnectionSpec(
            ConnectorType.MLLP,
            {"host": env("partner_host"), "port": env("partner_port", cast=int)},
        ),
        deployed=deployed,
    )


def _unresolvable_in(name: str, *, deployed: bool) -> InboundConnection:
    return build_inbound_connection(
        name,
        ConnectionSpec(ConnectorType.MLLP, {"port": env("partner_in_port", cast=int)}),
        router="r",
        deployed=deployed,
    )


async def _outbound_rows(store: MessageStore, message_id: str) -> list[tuple[str, str]]:
    """Every row this message has at the OUTBOUND stage, whatever its status — the assertion the
    count-and-log rule turns on ('assert no row is left in the outbound stage')."""
    cur = await store._db.execute(
        "SELECT destination_name, status FROM queue WHERE message_id=? AND stage=? ORDER BY rowid",
        (message_id, Stage.OUTBOUND.value),
    )
    return [(r["destination_name"], r["status"]) for r in await cur.fetchall()]


async def _drive(runner: RegistryRunner, store: MessageStore, ic_name: str = "IB") -> str:
    """Push one message through ingress -> router -> transform with the REAL per-item worker bodies
    (the same ones the per_lane loop and the pooled dispatcher call), and return its message id."""
    await store.enqueue_ingress(
        channel_id=ic_name, raw=ADT, control_id="MSG1", message_type="ADT^A01"
    )
    item = await store.claim_next_fifo(ic_name, stage=Stage.INGRESS.value)
    assert item is not None
    await runner._process_ingress_item(ic_name, item)
    while True:
        routed = await store.claim_next_fifo(ic_name, stage=Stage.ROUTED.value)
        if routed is None:
            return item.message_id
        await runner._process_routed_item(ic_name, routed)


# === NEVER BUILT — the headline: its env() is never resolved =================


def test_build_check_skips_a_not_deployed_connection() -> None:
    """AC-1. ``_build_check_connectors`` is the ONE loop that build-checks every connection with no
    lifecycle filter, and it is what ``messagefoundry check`` (the required commit gate), every
    reload/promote and every ``connection upsert`` run. Skipping a not-deployed connection there is
    the whole feature: without it, absent secrets still explode on all of those paths."""
    reg = Registry()
    reg.add_inbound(_unresolvable_in("IB_OFF", deployed=False))
    reg.add_outbound(_unresolvable_out("OB_OFF", deployed=False))
    reg.add_router("r", lambda m: [])
    runner = RegistryRunner(reg, store=None, env_values={})  # type: ignore[arg-type]
    runner.build_check(reg)  # must not raise, though NOT ONE env() value exists


def test_build_check_still_fails_loud_for_a_deployed_connection() -> None:
    """The antagonist guarantee, unchanged: a DEPLOYED connection with a missing env() value still
    fails loud at build_check — the promote-time gate ("a graph whose env keys aren't defined for the
    target never goes live"). The carve-out is scoped to the flag, not a general softening."""
    reg = Registry()
    reg.add_outbound(_unresolvable_out("OB_ON", deployed=True))
    runner = RegistryRunner(reg, store=None, env_values={})  # type: ignore[arg-type]
    with pytest.raises(WiringError, match="partner_host"):
        runner.build_check(reg)


def test_a_not_deployed_listener_cannot_collide_on_a_port() -> None:
    """A not-deployed inbound binds no socket, ever, so it can contend for none — which is what lets
    the SUPERSEDED half of a retired/replacement pair keep its real port in the config (carrying the
    record IS the point) instead of failing the port pre-flight against its successor."""
    port = _free_port()
    reg = Registry()
    reg.add_inbound(build_inbound_connection("IB_OLD", MLLP(port=port), router="r", deployed=False))
    reg.add_inbound(build_inbound_connection("IB_NEW", MLLP(port=port), router="r"))
    reg.add_router("r", lambda m: [])
    reg.validate()  # literal-port collisions (Registry.port_collisions)
    runner = RegistryRunner(reg, store=None, env_values={})  # type: ignore[arg-type]
    runner.build_check(reg)  # env-resolved conflicts (inbound_binding_conflicts)


# === NEVER WIRED / NEVER A LANE — boot ======================================


async def test_engine_starts_clean_with_a_not_deployed_outbound(store: MessageStore) -> None:
    """AC-1. The motivating pain: two outbounds whose credentials do not exist yet made the engine
    come up DEGRADED at EVERY boot, so the operator stopped reading the line. Not a fault (ADR 0031),
    not a DR park (#61) — a clean, deliberate, non-degraded 'stopped'."""
    reg = Registry()
    reg.add_outbound(_unresolvable_out("OB_OFF", deployed=False))
    runner = RegistryRunner(reg, store, poll_interval=0.02, env_values={})
    await runner.start()
    try:
        assert runner.running
        assert runner.degraded_connections() == {}  # NOT degraded — the whole point
        assert runner.connection_failed("OB_OFF") is None
        assert runner.connection_filtered("OB_OFF") is None
        assert "OB_OFF" not in runner._destinations  # env() never resolved, no connector built
        assert runner.outbound_status("OB_OFF") == "stopped"
        assert not runner.outbound_running("OB_OFF")
        assert runner.outbound_quiesced("OB_OFF")  # never started => zero in flight
    finally:
        await runner.stop()


async def test_not_deployed_outbound_spawns_no_delivery_worker(
    store: MessageStore, tmp_path: Path
) -> None:
    """NEVER A LANE. This is the one behaviour that separates not-deployed from every other down
    state. ``auto_start=False`` / DR-park / ADR-0031-failed all KEEP the delivery worker so a routed
    row queues + retries + self-heals — right for a lane that is coming back. A not-deployed lane is
    not coming back without a config change, so a row queued there could only sit forever and
    buildup-alert on an INTENTIONAL state. No worker => nothing can claim, back off, or page."""
    reg = Registry()
    reg.add_outbound(_file_out("OB_OFF", tmp_path, deployed=False))
    reg.add_outbound(_file_out("OB_DISABLED", tmp_path, auto_start=False))
    reg.add_outbound(_file_out("OB_ON", tmp_path))
    runner = RegistryRunner(reg, store, poll_interval=0.02, claim_mode="per_lane")
    await runner.start()
    try:
        assert "OB_ON" in runner._workers
        assert "OB_DISABLED" in runner._workers  # start-disabled: parked worker, rows RETAINED
        assert "OB_OFF" not in runner._workers  # not deployed: no lane at all
    finally:
        await runner.stop()


async def test_not_deployed_inbound_is_not_bound_but_still_drains_its_backlog(
    store: MessageStore, tmp_path: Path
) -> None:
    """Only the LISTENER is withheld. The router + transform workers still spawn (the ADR-0048 AC-3
    rule): flipping a live feed to not-deployed WITH ROWS IN FLIGHT must not strand them — it stops
    accepting NEW work while the existing ingress/routed backlog drains to completion."""
    out = tmp_path / "egress"
    out.mkdir()
    reg = Registry()
    reg.add_inbound(
        build_inbound_connection("IB", MLLP(port=_free_port()), router="r", deployed=False)
    )
    reg.add_router("r", lambda m: ["h"])
    reg.add_handler("h", lambda m: Send("OB_ON", str(m)))
    reg.add_outbound(_file_out("OB_ON", out))
    runner = RegistryRunner(reg, store, poll_interval=0.02, claim_mode="per_lane")
    # A row that predates the flag flip, already committed at the ingress stage.
    await store.enqueue_ingress(channel_id="IB", raw=ADT, control_id="MSG1", message_type="ADT^A01")
    await runner.start()
    try:
        assert not runner.inbound_running("IB")  # the listener is NOT bound
        assert runner.connection_failed("IB") is None  # and that is not a fault
        assert "IB" in runner._router_workers  # but the workers ARE armed...
        assert "IB" in runner._transform_workers
        # ...so the in-flight backlog drains all the way to the deployed destination.
        for _ in range(500):
            if [p.name for p in out.iterdir()] == ["MSG1.hl7"]:
                break
            await asyncio.sleep(0.02)
        assert [p.name for p in out.iterdir()] == ["MSG1.hl7"]
    finally:
        await runner.stop()


async def test_deployed_false_wins_over_auto_start(store: MessageStore, tmp_path: Path) -> None:
    """Both flags set: ``auto_start`` is ignored ENTIRELY. Otherwise the two could disagree about
    whether a lane comes up (auto_start=True + deployed=False is the natural spelling of "it will
    auto-start once we deploy it") and an operator start would half-wire a connection the graph says
    does not exist yet."""
    reg = Registry()
    reg.add_outbound(_unresolvable_out("OB_OFF", deployed=False))
    reg.add_inbound(_unresolvable_in("IB_OFF", deployed=False))
    reg.add_router("r", lambda m: [])
    assert reg.outbound["OB_OFF"].auto_start is True  # explicitly NOT start-disabled
    assert reg.inbound["IB_OFF"].auto_start is True
    runner = RegistryRunner(reg, store, poll_interval=0.02, claim_mode="per_lane", env_values={})
    await runner.start()
    try:
        assert "OB_OFF" not in runner._workers  # the auto_start branch WOULD have spawned one
        assert "OB_OFF" not in runner._destinations
        assert not runner.inbound_running("IB_OFF")
        assert runner.degraded_connections() == {}
    finally:
        await runner.stop()


async def test_default_deployed_is_byte_identical(store: MessageStore, tmp_path: Path) -> None:
    """No ``deployed`` argument (the default True) — every connection wires exactly as before."""
    reg = Registry()
    reg.add_inbound(build_inbound_connection("IB", MLLP(port=_free_port()), router="r"))
    reg.add_router("r", lambda m: [])
    reg.add_outbound(_file_out("OB", tmp_path))
    assert reg.inbound["IB"].deployed is True and reg.outbound["OB"].deployed is True
    runner = RegistryRunner(reg, store, poll_interval=0.02, claim_mode="per_lane")
    await runner.start()
    try:
        assert runner.inbound_running("IB")
        assert runner.outbound_running("OB") and runner.outbound_status("OB") == "running"
        assert "OB" in runner._destinations and "OB" in runner._workers
    finally:
        await runner.stop()


# === NEVER QUEUED — the transform_one seam ==================================


def test_transform_one_declines_a_send_to_a_not_deployed_outbound(tmp_path: Path) -> None:
    """The seam itself. The declined destination never becomes a ``DeliveryPreview`` (a caller turns
    those, and only those, into outbound-stage rows) — and it is REPORTED in ``declined`` rather than
    silently omitted, because a decline no caller can see would be an accept-and-drop (CLAUDE.md §12).
    Keyed on the REGISTRY flag, so a crash re-run re-derives an identical delivery set (ADR 0001)."""
    reg = Registry()
    reg.add_inbound(build_inbound_connection("IB", MLLP(port=1), router="r"))
    reg.add_router("r", lambda m: ["h"])
    reg.add_handler("h", lambda m: [Send("OB_ON", str(m)), Send("OB_OFF", str(m))])
    reg.add_outbound(_file_out("OB_ON", tmp_path))
    reg.add_outbound(_file_out("OB_OFF", tmp_path, deployed=False))

    deliveries, _state, _meta, declined = transform_one(reg, "h", ADT, "hl7v2")

    assert [d.to for d in deliveries] == ["OB_ON"]  # the not-deployed leg is NOT a delivery
    assert declined == ["OB_OFF"]  # but it IS recorded


async def test_send_to_a_not_deployed_outbound_queues_no_outbound_row(
    store: MessageStore, tmp_path: Path
) -> None:
    """AC-2, the load-bearing assertion: **no row is left in the outbound stage**. Not a pending row
    (which would retry forever and buildup-alert), not a dead row, not any row — because the decline
    happens BEFORE anything is committed to that stage."""
    reg = Registry()
    reg.add_inbound(build_inbound_connection("IB", MLLP(port=1), router="r"))
    reg.add_router("r", lambda m: ["h"])
    reg.add_handler("h", lambda m: Send("OB_OFF", str(m)))
    reg.add_outbound(_unresolvable_out("OB_OFF", deployed=False))
    runner = RegistryRunner(reg, store, poll_interval=0.02, env_values={})

    mid = await _drive(runner, store)

    assert await _outbound_rows(store, mid) == []
    depth, _ = await store.pending_depth("OB_OFF", stage=Stage.OUTBOUND.value)
    assert depth == 0


async def test_a_deployed_sibling_still_delivers(store: MessageStore, tmp_path: Path) -> None:
    """A fan-out where one leg is not deployed: the DEPLOYED sibling is unaffected — it gets its
    outbound row and delivers. The decline is per-destination, never per-message."""
    reg = Registry()
    reg.add_inbound(build_inbound_connection("IB", MLLP(port=1), router="r"))
    reg.add_router("r", lambda m: ["h"])
    reg.add_handler("h", lambda m: [Send("OB_ON", str(m)), Send("OB_OFF", str(m))])
    reg.add_outbound(_file_out("OB_ON", tmp_path))
    reg.add_outbound(_unresolvable_out("OB_OFF", deployed=False))
    runner = RegistryRunner(reg, store, poll_interval=0.02, env_values={})

    mid = await _drive(runner, store)

    assert await _outbound_rows(store, mid) == [("OB_ON", "pending")]


async def test_inline_fast_path_declines_without_double_logging(
    store: MessageStore, tmp_path: Path
) -> None:
    """#233 review finding (log hygiene): on an ADR-0057 inline-fast-path inbound, a Send to a
    not-deployed connection must be logged EXACTLY ONCE. A non-empty ``declined`` fails the fusion gate
    (``and not declined``), so the message falls back to the split transform worker, which logs — and
    durably records — the decline. The inline attempt must NOT log it too, or every declined Send on an
    inline inbound emits a duplicate INFO line (the ``message_events`` record stays single regardless)."""
    inbox = tmp_path / "in"
    inbox.mkdir()
    reg = Registry()
    reg.add_inbound(
        build_inbound_connection(
            "IB",
            ConnectionSpec(ConnectorType.FILE, {"directory": str(inbox)}),
            router="r",
            inline=True,
        )
    )
    reg.add_outbound(_unresolvable_out("OB_OFF", deployed=False))
    reg.add_router("r", lambda m: ["h"])
    reg.add_handler("h", lambda m: Send("OB_OFF", str(m)))
    runner = RegistryRunner(reg, store, poll_interval=0.02, env_values={})
    # Activate the inline fast-path WITHOUT start() (whose pooled dispatchers would race _drive's manual
    # claims): the graph declares no lookup, so recompute yields inline_ok=True directly.
    runner._lookup_executor = None
    runner._fhir_lookup_executor = None
    runner._recompute_inline_ok()
    assert runner._inline_ok["IB"] is True  # the inline-attempt path is actually exercised

    # Count invocations of the decline-logging seam DIRECTLY (spy on the method), not captured log
    # records. `_log_declined` IS the "log the decline" step, and each in-pipeline transform site (inline,
    # split, fused) calls it; the fix removed the inline attempt's call. The spy runs inside the awaited
    # transform (before the disposition is committed), so it is deterministic — whereas a captured LOG
    # RECORD can reach its handler a beat after the awaited transform completes under load, racing a
    # record-count read (the failure mode that made the first cut of this test order-dependent).
    decline_calls: list[list[str]] = []
    original = runner._log_declined

    def _spy(hname: str, message_id: str, declined: Sequence[str]) -> None:
        decline_calls.append(list(declined))
        original(hname, message_id, declined)

    runner._log_declined = _spy  # type: ignore[method-assign]
    try:
        mid = await _drive(runner, store)
    finally:
        runner._log_declined = original  # type: ignore[method-assign]

    logged = [c for c in decline_calls if c]  # invocations carrying a non-empty declined list
    assert logged == [["OB_OFF"]], f"decline logged {logged} (want exactly one [['OB_OFF']])"
    # The disposition confirms the decline actually happened — single, NOT_DEPLOYED, no queued row.
    assert await _outbound_rows(store, mid) == []
    assert await _status(store, mid) == MessageStatus.NOT_DEPLOYED.value


async def test_already_queued_rows_are_retained_not_dead_lettered(
    store: MessageStore, tmp_path: Path
) -> None:
    """A connection flipped to not-deployed KEEPS ITS PLACE IN THE REGISTRY, so the startup orphan
    sweep (``dead_letter_missing_destinations``, which keys on ``set(registry.outbound)``) leaves its
    already-queued rows alone. Commenting the connection out — today's only way to express this —
    would dead-letter every one of them on the next start. Retained, not retried, not dropped: they
    drain untouched the moment it IS deployed."""
    reg = Registry()
    reg.add_outbound(_unresolvable_out("OB_OFF", deployed=False))
    await store.enqueue_message(channel_id="IB", raw=ADT, deliveries=[("OB_OFF", ADT)])
    runner = RegistryRunner(reg, store, poll_interval=0.02, claim_mode="per_lane", env_values={})
    await runner.start()
    try:
        assert "OB_OFF" in runner.registry.outbound  # still in the graph — the sweep's key
        await store.dead_letter_missing_destinations(set(runner.registry.outbound))
        await asyncio.sleep(0.15)  # nothing exists that could claim it
        depth, _ = await store.pending_depth("OB_OFF", stage=Stage.OUTBOUND.value)
        assert depth == 1  # RETAINED pending, never claimed connector-less, never dead-lettered
        msgs = await store.list_messages(channel_id="IB", status=MessageStatus.ERROR.value)
        assert msgs == []
    finally:
        await runner.stop()


# === NEVER WIRED — reload / scheduler / operator ============================


async def test_reload_cannot_resurrect_a_not_deployed_outbound(
    store: MessageStore, tmp_path: Path
) -> None:
    """A reload (and every connections.toml GUI save, which reloads) re-evaluates the flag. Unlike
    the auto_start gate — which honours an operator who started the lane at runtime — this one is
    unconditional: ``deployed`` is a config fact, and there is no runtime override of it."""
    out = tmp_path / "egress"
    out.mkdir()

    def _reg(*, deployed: bool) -> Registry:
        r = Registry()
        r.add_outbound(_file_out("OB_OFF", out, deployed=deployed))
        return r

    runner = RegistryRunner(_reg(deployed=False), store, poll_interval=0.02)
    await runner.start()
    try:
        await store.enqueue_message(channel_id="IB", raw=ADT, deliveries=[("OB_OFF", ADT)])
        await runner.reload(_reg(deployed=False))
        assert "OB_OFF" not in runner._destinations
        assert runner.outbound_status("OB_OFF") == "stopped"
        await asyncio.sleep(0.15)
        assert list(out.iterdir()) == []  # a resurrected lane would have delivered by now

        # AC-4: flip the ONE flag (no other change) and reload -> it deploys and drains.
        await runner.reload(_reg(deployed=True))
        assert "OB_OFF" in runner._destinations
        assert runner.outbound_running("OB_OFF")
        for _ in range(500):
            if [p.name for p in out.iterdir()] == ["MSG1.hl7"]:
                break
            await asyncio.sleep(0.02)
        assert [p.name for p in out.iterdir()] == ["MSG1.hl7"]  # the retained row drained
    finally:
        await runner.stop()


async def test_reload_cannot_bind_a_not_deployed_inbound(store: MessageStore) -> None:
    port = _free_port()

    def _reg() -> Registry:
        r = Registry()
        r.add_inbound(
            build_inbound_connection("IB_OFF", MLLP(port=port), router="r", deployed=False)
        )
        r.add_router("r", lambda m: [])
        return r

    runner = RegistryRunner(_reg(), store, poll_interval=0.02)
    await runner.start()
    try:
        assert not runner.inbound_running("IB_OFF")
        await runner.reload(_reg())
        assert not runner.inbound_running("IB_OFF")
    finally:
        await runner.stop()


async def test_scheduler_cannot_start_a_not_deployed_connection(
    store: MessageStore, tmp_path: Path
) -> None:
    """A not-deployed connection has no listener and no delivery worker, so it has no calendar to
    keep — a ``schedule`` on it is inert config, retained (like the rest of the connection) for the
    day it IS deployed. A scheduler tick is the ENGINE, not an operator."""
    schedule = Schedule(
        windows=[
            ActiveWindow(
                days=frozenset({0, 1, 2, 3, 4}), start=time(8), end=time(17), timezone="UTC"
            )
        ]
    )
    inside = datetime(2026, 7, 13, 9, tzinfo=UTC)  # Monday 09:00 — inside the window
    reg = Registry()
    reg.add_inbound(
        build_inbound_connection(
            "IB_OFF", MLLP(port=_free_port()), router="r", deployed=False, schedule=schedule
        )
    )
    reg.add_router("r", lambda m: [])
    reg.add_outbound(_file_out("OB_OFF", tmp_path, deployed=False, schedule=schedule))
    runner = RegistryRunner(reg, store, poll_interval=0.02, schedule_clock=lambda: inside)
    await runner.start()
    try:
        await runner._reconcile_schedule("IB_OFF", "inbound", schedule)
        await runner._reconcile_schedule("OB_OFF", "outbound", schedule)
        assert not runner.inbound_running("IB_OFF")
        assert not runner.outbound_running("OB_OFF")
        assert "OB_OFF" not in runner._destinations
    finally:
        await runner.stop()


async def test_operator_start_refuses_a_not_deployed_connection(
    store: MessageStore, tmp_path: Path
) -> None:
    """Unlike ``auto_start=False`` — a boot gate an operator is MEANT to override at runtime — a
    not-deployed connection refuses the start outright. Deploying is a config change, not a runtime
    action: starting it here would resolve secrets that were never provisioned."""
    reg = Registry()
    reg.add_inbound(_unresolvable_in("IB_OFF", deployed=False))
    reg.add_router("r", lambda m: [])
    reg.add_outbound(_unresolvable_out("OB_OFF", deployed=False))
    runner = RegistryRunner(reg, store, poll_interval=0.02, env_values={})
    await runner.start()
    try:
        with pytest.raises(NotDeployedError, match="NOT deployed"):
            await runner.start_outbound("OB_OFF")
        with pytest.raises(NotDeployedError, match="NOT deployed"):
            await runner.start_inbound("IB_OFF")
        with pytest.raises(NotDeployedError):
            await runner.restart_outbound("OB_OFF")
        # The refusal left nothing half-wired: no connector, no listener, no env() resolved.
        assert "OB_OFF" not in runner._destinations
        assert not runner.inbound_running("IB_OFF")
        assert runner.degraded_connections() == {}
    finally:
        await runner.stop()


# === COUNT-AND-LOG — the NOT_DEPLOYED disposition + the per-destination event ===
#
# Commit 5. The seam (above) keeps the declined destination out of the outbound stage; a decline with
# no operator-visible disposition would still be an accept-and-drop (CLAUDE.md §12). So the decline is
# turned into a durable, counted record: a per-destination ``not_deployed`` message_events row, plus —
# when EVERY selected destination was declined — the 7th disposition, ``MessageStatus.NOT_DEPLOYED``.
# Both are written INSIDE the same handoff transaction as the routed-row consume, so the finalizer (it
# reads only persisted rows) can see the decline and never collapses the message to FILTERED by absence.


async def _not_deployed_dests(store: MessageStore, message_id: str) -> list[str]:
    """The connection name of every ``not_deployed`` message_events row for this message, in order —
    the count-and-log record of each skipped leg. ``destination`` is stored in plaintext (only
    ``detail`` is encrypted), so this is exactly what an operator sees for the skip."""
    return [
        e["destination"] for e in await store.events_for(message_id) if e["event"] == "not_deployed"
    ]


async def _status(store: MessageStore, message_id: str) -> str:
    msg = await store.get_message(message_id)
    assert msg is not None
    return str(msg["status"])


async def test_sole_not_deployed_target_finalizes_not_deployed(
    store: MessageStore, tmp_path: Path
) -> None:
    """AC-2. A handler whose ONLY Send is to a not-deployed connection: the message finalizes the 7th
    disposition ``NOT_DEPLOYED`` — NOT ``FILTERED`` (the handler did not drop it; it would have
    delivered, but the target is not deployed) — leaves ZERO rows in the outbound stage, and carries a
    ``not_deployed`` event naming the connection."""
    reg = Registry()
    reg.add_inbound(build_inbound_connection("IB", MLLP(port=1), router="r"))
    reg.add_router("r", lambda m: ["h"])
    reg.add_handler("h", lambda m: Send("OB_OFF", str(m)))
    reg.add_outbound(_unresolvable_out("OB_OFF", deployed=False))
    runner = RegistryRunner(reg, store, poll_interval=0.02, env_values={})

    mid = await _drive(runner, store)

    assert await _status(store, mid) == MessageStatus.NOT_DEPLOYED.value
    assert await _outbound_rows(store, mid) == []  # AC-2: not one row in the outbound stage
    assert await _not_deployed_dests(store, mid) == ["OB_OFF"]  # the counted record of the skip


async def test_filtered_message_stays_distinguishable_from_not_deployed(
    store: MessageStore, tmp_path: Path
) -> None:
    """The single most likely silent-wrong outcome of the whole build (spec §3.3): FILTERED is decided
    by ABSENCE, so a genuinely filtered message (the handler returned nothing) must still finalize
    ``FILTERED`` and NOT be mistaken for ``NOT_DEPLOYED``. Both leave zero outbound rows; the ONLY
    thing that separates them is the persisted ``not_deployed`` event, which a real filter never
    writes. Contrast with the test above — same driver, different handler, different disposition."""
    reg = Registry()
    reg.add_inbound(build_inbound_connection("IB", MLLP(port=1), router="r"))
    reg.add_router("r", lambda m: ["h"])
    reg.add_handler("h", lambda m: [])  # a real filter — no Send at all
    runner = RegistryRunner(reg, store, poll_interval=0.02, env_values={})

    mid = await _drive(runner, store)

    assert await _status(store, mid) == MessageStatus.FILTERED.value
    assert await _not_deployed_dests(store, mid) == []  # no decline → no such record → FILTERED


async def test_deployed_sibling_delivers_message_processed_event_retained(
    store: MessageStore, tmp_path: Path
) -> None:
    """A fan-out with one deployed leg and one not: the deployed sibling delivers and the message
    finalizes ``PROCESSED`` (it DID deliver somewhere — not ``NOT_DEPLOYED``), while the
    ``not_deployed`` event for the skipped leg is STILL present as the record of it. Driven through
    the real running engine so delivery actually completes."""
    out = tmp_path / "egress"
    out.mkdir()
    reg = Registry()
    reg.add_inbound(build_inbound_connection("IB", MLLP(port=_free_port()), router="r"))
    reg.add_router("r", lambda m: ["h"])
    reg.add_handler("h", lambda m: [Send("OB_ON", str(m)), Send("OB_OFF", str(m))])
    reg.add_outbound(_file_out("OB_ON", out))
    reg.add_outbound(_unresolvable_out("OB_OFF", deployed=False))
    runner = RegistryRunner(reg, store, poll_interval=0.02, claim_mode="per_lane")
    mid = await store.enqueue_ingress(
        channel_id="IB", raw=ADT, control_id="MSG1", message_type="ADT^A01"
    )
    await runner.start()
    try:
        for _ in range(500):
            if await _status(store, mid) == MessageStatus.PROCESSED.value:
                break
            await asyncio.sleep(0.02)
        assert await _status(store, mid) == MessageStatus.PROCESSED.value
        assert [p.name for p in out.iterdir()] == ["MSG1.hl7"]  # the deployed sibling delivered
        assert await _not_deployed_dests(store, mid) == ["OB_OFF"]  # skipped leg still recorded
    finally:
        await runner.stop()


@pytest.mark.parametrize("verbosity", ["errors", "off"])
async def test_not_deployed_record_and_disposition_survive_thinned_logs(
    tmp_path: Path, verbosity: str
) -> None:
    """The #63 verbosity trap (spec §3.3, commit 5c): the message_events gate drops any event outside
    the audit floor at ``errors``/``off``. ``not_deployed`` is IN the floor, so at exactly the
    verbosities that thinned the log BOTH survive — the operator-visible record AND the finalizer's own
    signal. Without the floor entry the disposition would evaporate to ``FILTERED``, re-creating the
    accept-and-drop the feature exists to forbid."""
    s = await MessageStore.open(tmp_path / f"nd_{verbosity}.db", message_events=verbosity)
    try:
        reg = Registry()
        reg.add_inbound(build_inbound_connection("IB", MLLP(port=1), router="r"))
        reg.add_router("r", lambda m: ["h"])
        reg.add_handler("h", lambda m: Send("OB_OFF", str(m)))
        reg.add_outbound(_unresolvable_out("OB_OFF", deployed=False))
        runner = RegistryRunner(reg, s, poll_interval=0.02, env_values={})

        mid = await _drive(runner, s)

        assert await _not_deployed_dests(s, mid) == ["OB_OFF"]  # the record survived the gate...
        assert await _status(s, mid) == MessageStatus.NOT_DEPLOYED.value  # ...and so did the signal
    finally:
        await s.close()


# === OPERATOR SURFACE — status, refusals, KPI (commit 6) ====================
#
# The lane must never be invisible on /connections, and it must be distinguishable at a GLANCE from a
# "stopped" lane (= should be running, isn't) — that distinction is the whole point of the state. Two
# runtime CONTROLS that would half-wire a not-deployed lane are refused with 409: start/restart (one
# choke point, _dual_role_control, also backs the web console bulk toolbar), and — separately, because
# they bypass transform_one entirely — the resend / edit-resend back door.


def _client(engine: Engine) -> httpx.AsyncClient:
    from messagefoundry.api import create_app

    transport = httpx.ASGITransport(app=create_app(engine, allow_no_auth=True))
    return httpx.AsyncClient(transport=transport, base_url="http://t")


async def test_connections_surfaces_not_deployed_distinct_from_stopped(tmp_path: Path) -> None:
    """AC-3 (operator view). /connections shows a not-deployed lane as status:"not_deployed" on both an
    inbound SOURCE row and an outbound STANDALONE row (a never-trafficked not-deployed lane is otherwise
    invisible). The load-bearing contrast: an ``auto_start=False`` outbound — deployed, just not up — is
    "stopped" on the same view, so the operator can tell "I chose not to deploy this" from "this should
    be running and isn't"."""
    reg = Registry()
    reg.add_inbound(build_inbound_connection("IB_ON", MLLP(port=_free_port()), router="r"))
    reg.add_inbound(_unresolvable_in("IB_OFF", deployed=False))
    reg.add_router("r", lambda m: [])
    reg.add_outbound(_file_out("OB_OFF", tmp_path, deployed=False))  # present, NOT deployed
    reg.add_outbound(_file_out("OB_STOPPED", tmp_path, auto_start=False))  # deployed, just not up
    engine = await Engine.create(tmp_path / "conns.db", poll_interval=0.02)
    engine.add_registry(reg)
    await engine.start()
    try:
        async with _client(engine) as c:
            rows = (await c.get("/connections")).json()
        by_src = {r["channel_id"]: r for r in rows if r["role"] == "source"}
        assert by_src["IB_ON"]["status"] == "running"
        assert by_src["IB_OFF"]["status"] == "not_deployed"  # never wired
        by_dest = {r["destination"]: r for r in rows if r["role"] == "destination"}
        assert by_dest["OB_OFF"]["status"] == "not_deployed"
        assert by_dest["OB_STOPPED"]["status"] == "stopped"  # THE distinction
    finally:
        await engine.stop()


async def test_connections_not_deployed_outbound_edge_row_carries_the_status(
    tmp_path: Path,
) -> None:
    """The edge-row path: a not-deployed outbound that already carried traffic (a row that predates the
    flag flip) has a metrics edge, so it renders as a DESTINATION row, not a standalone one. Its parked
    lane reports "stopped" via outbound_status, so without the deployed-flag override on the edge ladder
    it would read "stopped" — the flag must win here too. Exactly one row (edge, not also standalone)."""
    reg = Registry()
    reg.add_inbound(build_inbound_connection("IB", MLLP(port=_free_port()), router="r"))
    reg.add_router("r", lambda m: [])
    reg.add_outbound(_unresolvable_out("OB_OFF", deployed=False))
    engine = await Engine.create(tmp_path / "edge.db", poll_interval=0.02)
    engine.add_registry(reg)
    # A retained row from before the flip → a (IB, OB_OFF) outbound metrics edge.
    await engine.store.enqueue_message(channel_id="IB", raw=ADT, deliveries=[("OB_OFF", ADT)])
    await engine.start()
    try:
        async with _client(engine) as c:
            rows = (await c.get("/connections")).json()
        edge = [r for r in rows if r["role"] == "destination" and r["destination"] == "OB_OFF"]
        assert len(edge) == 1  # the edge row, and NOT also a duplicate standalone row
        assert edge[0]["status"] == "not_deployed"
    finally:
        await engine.stop()


async def test_operator_start_restart_refuses_not_deployed_with_409(tmp_path: Path) -> None:
    """POST /connections/{name}/start|restart on a not-deployed inbound OR outbound → 409 ("deploying it
    is a config change, not a runtime action"). This is the one choke point (_dual_role_control) that
    also backs the web console bulk toolbar, so a single refusal covers both surfaces. ``stop`` is a
    no-op on an already-parked lane and is deliberately NOT refused."""
    reg = Registry()
    reg.add_inbound(_unresolvable_in("IB_OFF", deployed=False))
    reg.add_router("r", lambda m: [])
    reg.add_outbound(_unresolvable_out("OB_OFF", deployed=False))
    engine = await Engine.create(tmp_path / "ctrl.db", poll_interval=0.02)
    engine.add_registry(reg)
    await engine.start()
    try:
        async with _client(engine) as c:
            for name in ("IB_OFF", "OB_OFF"):
                for action in ("start", "restart"):
                    r = await c.post(f"/connections/{name}/{action}")
                    assert r.status_code == 409, (name, action, r.text)
                    assert "not deployed" in r.text.lower()
                # stop is not a config change → not refused (a no-op on an already-parked lane).
                assert (await c.post(f"/connections/{name}/stop")).status_code == 200
        # The refusals left nothing half-wired.
        assert "OB_OFF" not in engine.registry_runner._destinations  # type: ignore[union-attr]
        assert not engine.registry_runner.inbound_running("IB_OFF")  # type: ignore[union-attr]
        assert engine.registry_runner.degraded_connections() == {}  # type: ignore[union-attr]
    finally:
        await engine.stop()


async def test_resend_and_edit_resend_to_not_deployed_are_409_and_queue_no_row(
    tmp_path: Path,
) -> None:
    """THE BACK DOOR (spec §4 commit 6c): /messages/{id}/resend + /edit-resend insert an outbound-stage
    row DIRECTLY (store.resend_to), never through transform_one — so commit 4's transform-time decline
    does NOT cover them. Both must 409 on a not-deployed target, and — the load-bearing assertion — NOT
    ONE outbound-stage row may be hand-queued to the lane (otherwise an operator queues a row into a lane
    with no connector, where it can only sit forever). Engine not started, so the deployed OB_ON row
    stays a stable ``pending`` for the assertion."""
    reg = Registry()
    reg.add_inbound(build_inbound_connection("IB", MLLP(port=_free_port()), router="r"))
    reg.add_router("r", lambda m: [])
    reg.add_outbound(_file_out("OB_ON", tmp_path))
    reg.add_outbound(_unresolvable_out("OB_OFF", deployed=False))
    engine = await Engine.create(tmp_path / "resend.db", poll_interval=0.02)
    engine.add_registry(reg)  # sets registry_runner; the resend routes need no started engine
    mid = await engine.store.enqueue_message(
        channel_id="IB", raw=ADT, deliveries=[("OB_ON", ADT)], source_type="file"
    )
    try:
        async with _client(engine) as c:
            r = await c.post(
                f"/messages/{mid}/resend", json={"to": "OB_OFF", "idempotency_key": "k1"}
            )
            assert r.status_code == 409 and "not deployed" in r.text.lower()
            er = await c.post(
                f"/messages/{mid}/edit-resend",
                json={"raw": ADT, "idempotency_key": "k2", "to": "OB_OFF"},
            )
            assert er.status_code == 409 and "not deployed" in er.text.lower()
        # No row was hand-queued to the not-deployed lane; the deployed sibling's row is untouched.
        assert await _outbound_rows(engine.store, mid) == [("OB_ON", "pending")]
    finally:
        await engine.stop()


async def test_status_kpi_counts_not_deployed_in_its_own_bucket(tmp_path: Path) -> None:
    """The /status KPI roll-up (spec §4 commit 6d): a not-deployed connection is in the registry but is
    NOT a lane, so it is counted in ``connections_not_deployed`` and EXCLUDED from ``connections_total``
    — the running/stopped split counts only lanes and the pinned identity
    ``connections_stopped == connections_total - connections_running`` holds. Counting it toward total
    would inflate ``connections_stopped`` and read as "should be running, isn't"."""
    reg = Registry()
    reg.add_inbound(build_inbound_connection("IB_ON", MLLP(port=_free_port()), router="r"))
    reg.add_inbound(_unresolvable_in("IB_OFF", deployed=False))
    reg.add_router("r", lambda m: [])
    reg.add_outbound(_file_out("OB_ON", tmp_path))
    reg.add_outbound(_unresolvable_out("OB_OFF", deployed=False))
    engine = await Engine.create(tmp_path / "kpi.db", poll_interval=0.02)
    engine.add_registry(reg)
    await engine.start()
    try:
        async with _client(engine) as c:
            kpis = (await c.get("/status")).json()["kpis"]
        assert kpis["connections_total"] == 2  # 1 deployed inbound + 1 deployed outbound ONLY
        assert kpis["connections_not_deployed"] == 2  # IB_OFF + OB_OFF, their own bucket
        assert kpis["connections_running"] == 2  # IB_ON listening + OB_ON delivering
        assert kpis["connections_stopped"] == 0
        assert (
            kpis["connections_stopped"]
            == kpis["connections_total"] - kpis["connections_running"]  # the pinned identity
        )
    finally:
        await engine.stop()
