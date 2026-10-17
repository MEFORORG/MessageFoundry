# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The inbound exposure gates at build check and at start, and the listeners they run on (vault
BACKLOG #3063 items 6, 9, 10, 12 and 13).

Each gate kind is driven through the shared ``check_inbound_tls_exposure`` list, never through its
own function, so dropping a kind from that list turns its rows red at both sites. Every refusal is
matched on the text only its own gate writes: a sibling gate refusing the same listener does not
satisfy the row."""

from __future__ import annotations

import asyncio
import textwrap
from datetime import UTC, datetime, time
from pathlib import Path
from typing import Any, cast

import pytest
from pydantic import ValidationError

from messagefoundry.checks import run_checks
from messagefoundry.config.models import AckAfter, ActiveWindow, ConnectorType, Schedule
from messagefoundry.config.settings import EgressSettings, InboundSettings
from messagefoundry.config.tls_policy import HopPosture
from messagefoundry.config.wiring import (
    ConnectionSpec,
    InboundConnection,
    Registry,
    WiringError,
    load_config,
)
from messagefoundry.pipeline import Engine
from messagefoundry.pipeline.wiring_runner import RegistryRunner, build_check_registry
from messagefoundry.store import MessageStore
from messagefoundry.transports import SourceConnector

#: kind -> (connector type, the text only that kind's exposure gate writes).
_KINDS: dict[str, tuple[ConnectorType, str]] = {
    "MLLP": (ConnectorType.MLLP, "HL7 bodies would cross"),
    "DIMSE": (ConnectorType.DIMSE, "DICOM-carried PHI"),
    "TCP": (ConnectorType.TCP, "plaintext-only TCP listener"),
    # The TCP gate's second type: dropping X12 from its tuple turns this row red.
    "X12": (ConnectorType.X12, "plaintext-only X12 listener"),
    "HTTP": (ConnectorType.HTTP, "POSTed bodies"),
}

_ENFORCING = HopPosture(enforcing=True)


@pytest.fixture
async def store(tmp_path: Path):
    s = await MessageStore.open(tmp_path / "gates.db")
    yield s
    await s.close()


def _one_listener(kind: ConnectorType, **lifecycle: Any) -> Registry:
    reg = Registry()
    reg.add_inbound(
        InboundConnection("ib", ConnectionSpec(kind, {"port": 0}), router="r", **lifecycle)
    )
    reg.add_router("r", lambda m: [])
    return reg


def _offline_check(reg: Registry) -> None:
    build_check_registry(
        reg,
        inbound_bind_host="0.0.0.0",
        env_values={},
        egress=EgressSettings(deny_by_default=False),
        posture=_ENFORCING,
    )


def _strict_runner(reg: Registry, store: MessageStore, **kw: Any) -> RegistryRunner:
    """Off loopback, enforcing, with no cleartext escape: every exposure gate that runs refuses.
    The shape of ``tests/test_wiring_engine.py``'s helper of the same name, kept local so this
    file does not import another test module."""
    return RegistryRunner(
        reg,
        store,
        inbound_bind_host="0.0.0.0",
        poll_interval=0.02,
        egress=EgressSettings(deny_by_default=False),
        hop_posture=_ENFORCING,
        **kw,
    )


# --- item 6: one row per gate kind, at build check and at start -------------------------------------


@pytest.mark.parametrize("kind", sorted(_KINDS))
def test_each_gate_kind_refuses_at_build_check(kind: str) -> None:
    ctype, own_text = _KINDS[kind]
    with pytest.raises(WiringError, match=own_text) as refused:
        _offline_check(_one_listener(ctype))
    text = str(refused.value)
    # Item 10: the tail. `check` and `connection` key their note on serve's flag, so it must survive
    # in the refusal text whatever the tail says.
    assert "--allow-insecure-bind" in text
    assert "'ib' would be bound" in text
    assert "A deployed = false listener cannot be started" in text
    assert "the reload that deploys it meets the refusal" in text
    assert "a later start meets the same refusal" not in text


@pytest.mark.parametrize("kind", sorted(_KINDS))
async def test_each_gate_kind_isolates_its_listener_at_start(
    kind: str, store: MessageStore
) -> None:
    ctype, own_text = _KINDS[kind]
    runner = _strict_runner(_one_listener(ctype), store)
    await runner.start()
    try:
        assert runner.running
        assert not runner.inbound_running("ib")
        reason = runner.inbound_failed("ib")
        assert reason is not None and own_text in reason, reason
    finally:
        await runner.stop()


# --- item 6: the flag toggle passes the runner's predicate ------------------------------------------

_LOGIC_PY = textwrap.dedent(
    """
    from messagefoundry import Send, handler, router

    @router("r")
    def route(msg):
        return ["h"]

    @handler("h")
    def handle(msg):
        return Send("OB_TOML", msg)
    """
)

_CONNECTIONS_TOML = textwrap.dedent(
    """
    [[inbound]]
    name = "IB_TOML"
    transport = "mllp"
    router = "r"
    auto_start = false
    [inbound.settings]
    port = 2600

    [[outbound]]
    name = "OB_TOML"
    transport = "mllp"
    [outbound.settings]
    host = "127.0.0.1"
    port = 2700
    """
)


async def test_the_flag_toggle_gates_a_listener_an_operator_started(tmp_path: Path) -> None:
    """IB_TOML binds 0.0.0.0 in cleartext with no escape, and has ``auto_start = false``. Left down,
    the toggle applies: neither start nor reload binds it. Once an operator has started it, a reload
    keeps it bound, so the toggle must refuse. Only the runner's predicate knows it is listening:
    the offline default would pass it."""
    (tmp_path / "logic.py").write_text(_LOGIC_PY, encoding="utf-8")
    (tmp_path / "connections.toml").write_text(_CONNECTIONS_TOML, encoding="utf-8")
    eng = await Engine.create(
        tmp_path / "flag.db",
        poll_interval=0.02,
        config_dir=tmp_path,
        inbound_bind_host="0.0.0.0",
        allow_insecure_bind=False,
        hop_posture=HopPosture(enforcing=False),
        egress_settings=EgressSettings(deny_by_default=False),
    )
    try:
        runner = eng.add_registry(load_config(tmp_path))
        await runner.start()
        assert not runner.inbound_running("IB_TOML")
        await eng.set_connection_flag(
            "OB_TOML", direction="outbound", flagged=True, actor="tester", client=None
        )
        # Stand in for an operator start without binding a socket: _sources is what both read.
        runner._sources["IB_TOML"] = cast(SourceConnector, object())
        try:
            with pytest.raises(WiringError, match="HL7 bodies would cross") as refused:
                await eng.set_connection_flag(
                    "OB_TOML", direction="outbound", flagged=False, actor="tester", client=None
                )
            assert "'IB_TOML' would be bound" in str(refused.value)
        finally:
            runner._sources.pop("IB_TOML")
    finally:
        await eng.stop()


async def test_a_queued_toggle_checks_the_listening_set_of_its_own_turn(tmp_path: Path) -> None:
    """The toggle's snapshot is taken under the engine's write lock (vault BACKLOG #2945 kept main's
    placement). A toggle queued behind another write, while an operator starts IB_TOML, must see
    that start when its turn comes. A snapshot taken when it queued would pass it."""
    (tmp_path / "logic.py").write_text(_LOGIC_PY, encoding="utf-8")
    (tmp_path / "connections.toml").write_text(_CONNECTIONS_TOML, encoding="utf-8")
    eng = await Engine.create(
        tmp_path / "flag.db",
        poll_interval=0.02,
        config_dir=tmp_path,
        inbound_bind_host="0.0.0.0",
        allow_insecure_bind=False,
        hop_posture=HopPosture(enforcing=False),
        egress_settings=EgressSettings(deny_by_default=False),
    )
    try:
        runner = eng.add_registry(load_config(tmp_path))
        await runner.start()
        assert not runner.inbound_running("IB_TOML")
        await eng._toml_write_lock.acquire()
        try:
            caller = asyncio.ensure_future(
                eng.set_connection_flag(
                    "OB_TOML", direction="outbound", flagged=True, actor="tester", client=None
                )
            )
            await asyncio.sleep(0.1)
            assert not caller.done(), "control: the toggle is queued on the held lock"
            # The operator start lands while the toggle waits.
            runner._sources["IB_TOML"] = cast(SourceConnector, object())
        finally:
            eng._toml_write_lock.release()
        try:
            with pytest.raises(WiringError, match="HL7 bodies would cross") as refused:
                await caller
            assert "'IB_TOML' would be bound" in str(refused.value)
        finally:
            runner._sources.pop("IB_TOML")
    finally:
        await eng.stop()


# --- items 12 and 13: the predicate reads the skips the reload applies ------------------------------

_MONDAY_8_TO_9 = Schedule(
    windows=[ActiveWindow(days=frozenset({0}), start=time(8), end=time(9), timezone="UTC")]
)
_IN_WINDOW = datetime(2026, 7, 13, 8, 30, tzinfo=UTC)  # a Monday
_OUT_OF_WINDOW = datetime(2026, 7, 13, 12, tzinfo=UTC)


@pytest.mark.parametrize(
    ("auto_start", "listening", "clock", "gated"),
    [
        # Item 13: the reload leaves it unbound and the scheduler never starts an auto_start = false
        # listener, so nothing binds it again.
        (False, True, _OUT_OF_WINDOW, False),
        # Controls. In its window the reload rebinds the operator's start.
        (False, True, _IN_WINDOW, True),
        # The scheduler binds an auto_start listener when its window opens.
        (True, False, _OUT_OF_WINDOW, True),
        (True, False, _IN_WINDOW, True),
        # Never started, so nothing binds it.
        (False, False, _IN_WINDOW, False),
    ],
)
async def test_a_scheduled_listener_is_gated_only_where_something_binds_it(
    store: MessageStore, auto_start: bool, listening: bool, clock: datetime, gated: bool
) -> None:
    reg = _one_listener(ConnectorType.MLLP, auto_start=auto_start, schedule=_MONDAY_8_TO_9)
    runner = _strict_runner(reg, store, schedule_clock=lambda: clock)
    if listening:
        runner._sources["ib"] = cast(SourceConnector, object())
    try:
        assert runner.listener_bind_predicate()(reg.inbound["ib"]) is gated
        if gated:
            with pytest.raises(WiringError, match="HL7 bodies would cross"):
                runner.build_check(reg)
        else:
            runner.build_check(reg)
    finally:
        runner._sources.pop("ib", None)


async def test_a_reload_after_the_window_closes_leaves_an_operator_start_unbound(
    store: MessageStore,
) -> None:
    """Item 13's premise, measured: the reload the predicate stops gating really leaves the listener
    down. On loopback, so the operator start binds a real socket."""
    now = [_IN_WINDOW]
    reg = _one_listener(ConnectorType.MLLP, auto_start=False, schedule=_MONDAY_8_TO_9)
    runner = RegistryRunner(
        reg,
        store,
        inbound_bind_host="127.0.0.1",
        poll_interval=0.02,
        egress=EgressSettings(deny_by_default=False),
        schedule_clock=lambda: now[0],
        schedule_tick=3600,
    )
    await runner.start()
    try:
        assert not runner.inbound_running("ib")
        await runner.start_inbound("ib")
        assert runner.inbound_running("ib")
        now[0] = _OUT_OF_WINDOW
        assert runner.listener_bind_predicate()(reg.inbound["ib"]) is False
        await runner.reload(reg)
        assert not runner.inbound_running("ib")
    finally:
        await runner.stop()


async def test_a_reload_judges_the_window_once(store: MessageStore) -> None:
    """The build check and the listener loop of one reload read one schedule time. Here the
    window reopens just after the reload's first read. The gates were skipped for that read, so the
    loop must not bind on a later one: off loopback, that bind would be refused after intake had
    stopped, and the whole reload rolled back."""
    clock = [_IN_WINDOW]
    pending: list[datetime] = []

    def read() -> datetime:
        return pending.pop(0) if pending else clock[0]

    reg = _one_listener(ConnectorType.MLLP, auto_start=False, schedule=_MONDAY_8_TO_9)
    runner = RegistryRunner(
        reg,
        store,
        inbound_bind_host="127.0.0.1",
        poll_interval=0.02,
        egress=EgressSettings(deny_by_default=False),
        schedule_clock=read,
        schedule_tick=3600,
    )
    await runner.start()
    try:
        await runner.start_inbound("ib")
        assert runner.inbound_running("ib")
        pending.append(_OUT_OF_WINDOW)  # the reload's read; every later one is in the window
        await runner.reload(reg)
        assert not pending
        assert not runner.inbound_running("ib")
    finally:
        await runner.stop()


# --- item 9: [inbound].ack_after = "delivered" ------------------------------------------------------


def test_inbound_ack_after_delivered_is_refused_at_load() -> None:
    assert InboundSettings().ack_after is AckAfter.INGEST
    assert InboundSettings.model_validate({"ack_after": "ingest"}).ack_after is AckAfter.INGEST
    with pytest.raises(ValidationError, match="not yet implemented"):
        InboundSettings.model_validate({"ack_after": "delivered"})


#: One loopback listener and no outbound, so no other build-check refusal can fire.
_ACK_GRAPH = textwrap.dedent(
    """
    from messagefoundry import MLLP, inbound, router

    inbound("IB_ACK", MLLP(port=2600), router="r")

    @router("r")
    def route(msg):
        return []
    """
)


def test_check_build_leg_refuses_inbound_ack_after_delivered(tmp_path: Path) -> None:
    """Listener start isolated every inbound that inherited it, while ``messagefoundry check``
    said OK. The ``ingest`` control shows the leg is not refusing the file for another reason."""
    config = tmp_path / "config"
    config.mkdir()
    (config / "ib.py").write_text(_ACK_GRAPH, encoding="utf-8")

    def _build_leg(ack_after: str) -> Any:
        toml = tmp_path / f"{ack_after}.toml"
        toml.write_text(f'[inbound]\nack_after = "{ack_after}"\n', encoding="utf-8")
        report = run_checks(config, run_lint=False, service_config=toml)
        return next(r for r in report.results if r.name == "build-check")

    refused = _build_leg("delivered")
    assert not refused.ok and not refused.skipped
    assert "ack_after" in refused.detail and "not yet implemented" in refused.detail
    passed = _build_leg("ingest")
    assert passed.ok, passed.detail
