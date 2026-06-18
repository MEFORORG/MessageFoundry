# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Atomic config reload (quiesce-and-swap) on a running RegistryRunner / Engine.

Covers the CD linchpin: applying a new code-first graph to a *running* engine without losing
in-flight outbox deliveries, and rejecting a bad/empty config without disturbing the live graph.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from messagefoundry.config.models import ConnectorType
from messagefoundry.config.wiring import (
    ConnectionSpec,
    InboundConnection,
    OutboundConnection,
    Registry,
    Send,
    WiringError,
    load_config,
)
from messagefoundry.pipeline import Engine
from messagefoundry.pipeline.wiring_runner import RegistryRunner
from messagefoundry.store import MessageStatus, MessageStore, OutboxStatus

ADT = (
    "MSH|^~\\&|SENDINGAPP|SENDINGFAC|RECV|RFAC|20260604||ADT^A01|MSG1|P|2.5.1\r"
    "EVN|A01|20260604\r"
    "PID|1||100^^^H^MR||DOE^JANE\r"
)
ADT2 = ADT.replace("MSG1", "MSG2")


@pytest.fixture
async def store(tmp_path: Path):
    s = await MessageStore.open(tmp_path / "reload.db")
    yield s
    await s.close()


# --- helpers -----------------------------------------------------------------


def _registry(inbox: Path, outdir: Path, route, handlers: dict) -> Registry:  # type: ignore[no-untyped-def]
    reg = Registry()
    reg.add_outbound(
        OutboundConnection(
            "file_out",
            ConnectionSpec(
                ConnectorType.FILE, {"directory": str(outdir), "filename": "{MSH-10}.hl7"}
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
    reg.add_router("r", route)
    for name, fn in handlers.items():
        reg.add_handler(name, fn)
    return reg


def _deliver_registry(inbox: Path, outdir: Path) -> Registry:
    """A registry that routes every message to file_out (→ outdir)."""
    return _registry(inbox, outdir, lambda m: ["h"], {"h": lambda m: Send("file_out", m)})


async def _until_stat(
    store: MessageStore, status: str, expected: int, timeout: float = 3.0
) -> None:
    elapsed = 0.0
    while (await store.stats()).get(status, 0) != expected:
        await asyncio.sleep(0.02)
        elapsed += 0.02
        if elapsed > timeout:
            raise AssertionError(f"{status} != {expected} within timeout")


async def _until_message(
    store: MessageStore, status: str, *, channel_id: str = "file_in", timeout: float = 3.0
) -> None:
    elapsed = 0.0
    while not await store.list_messages(channel_id=channel_id, status=status):
        await asyncio.sleep(0.02)
        elapsed += 0.02
        if elapsed > timeout:
            raise AssertionError(f"no {status} message within timeout")


class _Recorder:
    """Destination connector that records payloads and returns immediately."""

    def __init__(self) -> None:
        self.delivered: list[str] = []

    async def send(self, payload: str) -> None:
        self.delivered.append(payload)

    async def aclose(self) -> None:
        return None


class _Gate:
    """Destination connector that blocks every send until ``event`` is set."""

    def __init__(self) -> None:
        self.event = asyncio.Event()
        self.delivered: list[str] = []

    async def send(self, payload: str) -> None:
        await self.event.wait()
        self.delivered.append(payload)

    async def aclose(self) -> None:
        return None


# --- runner-level reload -----------------------------------------------------


async def test_reload_swaps_router_and_handler(store: MessageStore, tmp_path: Path) -> None:
    inbox, outdir = tmp_path / "in", tmp_path / "out"
    inbox.mkdir()

    # v1: the router forwards nowhere → the first message is logged UNROUTED, never delivered.
    runner = RegistryRunner(_registry(inbox, outdir, lambda m: [], {}), store, poll_interval=0.02)
    await runner.start()
    try:
        (inbox / "a.hl7").write_bytes(ADT.encode("utf-8"))
        await _until_message(store, MessageStatus.UNROUTED.value)

        # v2: now route → handler → file_out. Reload applies the new logic live.
        await runner.reload(_deliver_registry(inbox, outdir))
        (inbox / "b.hl7").write_bytes(ADT2.encode("utf-8"))
        await _until_stat(store, OutboxStatus.DONE.value, 1)
    finally:
        await runner.stop()

    assert (outdir / "MSG2.hl7").exists()  # delivered under the new graph
    assert not (outdir / "MSG1.hl7").exists()  # the pre-reload message stayed unrouted


async def test_reload_changes_outbound_directory(store: MessageStore, tmp_path: Path) -> None:
    inbox, out_a, out_b = tmp_path / "in", tmp_path / "outA", tmp_path / "outB"
    inbox.mkdir()

    runner = RegistryRunner(_deliver_registry(inbox, out_a), store, poll_interval=0.02)
    await runner.start()
    try:
        (inbox / "a.hl7").write_bytes(ADT.encode("utf-8"))
        await _until_stat(store, OutboxStatus.DONE.value, 1)
        assert (out_a / "MSG1.hl7").exists()

        # Reload changes file_out's directory (connector settings change → connector is rebuilt).
        await runner.reload(_deliver_registry(inbox, out_b))
        (inbox / "b.hl7").write_bytes(ADT2.encode("utf-8"))
        await _until_stat(store, OutboxStatus.DONE.value, 2)
    finally:
        await runner.stop()

    assert (out_b / "MSG2.hl7").exists()  # new traffic went to the new directory


async def test_reload_preserves_inflight_outbox(store: MessageStore, tmp_path: Path) -> None:
    """Rows already claimed/sending when a reload happens must still be delivered (no loss)."""
    reg = Registry()
    reg.add_outbound(
        OutboundConnection("out", ConnectionSpec(ConnectorType.FILE, {"directory": str(tmp_path)}))
    )
    runner = RegistryRunner(reg, store, poll_interval=0.02, claim_limit=20)
    await runner.start()
    gate = _Gate()
    runner._destinations["out"] = gate  # block delivery so rows are in-flight across the reload

    for i in range(5):
        await store.enqueue_message(
            channel_id="c", raw=ADT, deliveries=[("out", f"p{i}")], source_type="file"
        )
    runner.notify_work()
    await asyncio.sleep(0.1)  # let the worker claim the batch and block in send()

    # Reload with the SAME outbound spec: the worker is not bounced and keeps the in-flight batch.
    same = Registry()
    same.add_outbound(
        OutboundConnection("out", ConnectionSpec(ConnectorType.FILE, {"directory": str(tmp_path)}))
    )
    await runner.reload(same)

    gate.event.set()  # release delivery
    try:
        await _until_stat(store, OutboxStatus.DONE.value, 5)
    finally:
        await runner.stop()
    assert len(gate.delivered) == 5  # nothing dropped by the reload


async def test_reload_build_check_rejects_bad_connector(
    store: MessageStore, tmp_path: Path
) -> None:
    """A new config whose connector can't be built is rejected BEFORE quiesce — old graph intact."""
    inbox, outdir = tmp_path / "in", tmp_path / "out"
    inbox.mkdir()
    runner = RegistryRunner(_deliver_registry(inbox, outdir), store, poll_interval=0.02)
    await runner.start()

    bad = _registry(inbox, outdir, lambda m: ["h"], {"h": lambda m: Send("file_out", m)})
    # Replace file_out with a FILE connector missing its required 'directory' setting.
    bad.outbound["file_out"] = OutboundConnection(
        "file_out", ConnectionSpec(ConnectorType.FILE, {})
    )
    try:
        with pytest.raises(WiringError):
            await runner.reload(bad)
        # The original graph is untouched and still delivering.
        (inbox / "a.hl7").write_bytes(ADT.encode("utf-8"))
        await _until_stat(store, OutboxStatus.DONE.value, 1)
    finally:
        await runner.stop()
    assert (outdir / "MSG1.hl7").exists()


async def test_route_to_unknown_outbound_is_error(store: MessageStore, tmp_path: Path) -> None:
    """A handler that Sends to an unregistered outbound is recorded ERROR, never accept-and-strand."""
    inbox, outdir = tmp_path / "in", tmp_path / "out"
    inbox.mkdir()
    reg = _registry(inbox, outdir, lambda m: ["h"], {"h": lambda m: Send("nope", m)})
    runner = RegistryRunner(reg, store, poll_interval=0.02)
    await runner.start()
    try:
        (inbox / "a.hl7").write_bytes(ADT.encode("utf-8"))
        await _until_message(store, MessageStatus.ERROR.value)
    finally:
        await runner.stop()
    assert (await store.stats()) == {}  # no outbox row was enqueued (not stranded)
    assert not (outdir / "MSG1.hl7").exists()


async def test_reload_removed_outbound_keeps_draining(store: MessageStore, tmp_path: Path) -> None:
    """An outbound dropped by the new config still drains rows already queued to it."""
    reg = Registry()
    reg.add_outbound(
        OutboundConnection("out", ConnectionSpec(ConnectorType.FILE, {"directory": str(tmp_path)}))
    )
    runner = RegistryRunner(reg, store, poll_interval=0.02)
    await runner.start()
    rec = _Recorder()
    runner._destinations["out"] = rec

    for i in range(3):
        await store.enqueue_message(
            channel_id="c", raw=ADT, deliveries=[("out", f"p{i}")], source_type="file"
        )

    # Reload to a graph WITHOUT "out" — its lingering worker must finish draining the 3 rows.
    other = Registry()
    other.add_outbound(
        OutboundConnection(
            "other", ConnectionSpec(ConnectorType.FILE, {"directory": str(tmp_path / "z")})
        )
    )
    await runner.reload(other)
    try:
        await _until_stat(store, OutboxStatus.DONE.value, 3)
    finally:
        await runner.stop()
    assert len(rec.delivered) == 3
    assert "out" not in runner.registry.outbound  # gone from the live graph, but rows still drained


# --- engine-level reload (load_config from a directory) ----------------------


def _write_valid_config(cfg: Path, inbox: Path, outdir: Path) -> None:
    cfg.mkdir(parents=True, exist_ok=True)
    inbox.mkdir(parents=True, exist_ok=True)
    body = (
        "from messagefoundry import inbound, outbound, router, handler, Send, File\n"
        f"inbound('IB_T_ADT', File(directory={str(inbox)!r}, pattern='*.hl7', "
        "poll_seconds=0.02), router='r')\n"
        f"outbound('FILE-OUT_T_ADT', File(directory={str(outdir)!r}, filename='{{MSH-10}}.hl7'))\n"
        "@router('r')\n"
        "def route(msg):\n"
        "    return ['h']\n"
        "@handler('h')\n"
        "def handle(msg):\n"
        "    return Send('FILE-OUT_T_ADT', msg)\n"
    )
    (cfg / "cfg.py").write_text(body, encoding="utf-8")


async def test_engine_reload_invalid_config_leaves_graph_untouched(tmp_path: Path) -> None:
    inbox, outdir, good = tmp_path / "in", tmp_path / "out", tmp_path / "good"
    _write_valid_config(good, inbox, outdir)
    eng = await Engine.create(tmp_path / "e.db", poll_interval=0.02)
    eng.add_registry(load_config(good))
    await eng.start()
    try:
        bad = tmp_path / "bad"
        bad.mkdir()
        (bad / "bad.py").write_text(
            "from messagefoundry import inbound, File\n"
            "inbound('IB_T_ADT', File(directory='.', pattern='*.hl7'), router='missing')\n",
            encoding="utf-8",
        )
        with pytest.raises(WiringError):
            await eng.reload(bad)

        # The good graph is still live and still delivering.
        assert eng.registry_runner is not None
        assert "IB_T_ADT" in eng.registry_runner.registry.inbound
        (inbox / "a.hl7").write_bytes(ADT.encode("utf-8"))
        await _until_stat(eng.store, OutboxStatus.DONE.value, 1)
    finally:
        await eng.stop()
    assert (outdir / "MSG1.hl7").exists()


async def test_engine_reload_missing_dir_raises(tmp_path: Path) -> None:
    eng = await Engine.create(tmp_path / "e.db", poll_interval=0.02)
    await eng.start()
    try:
        with pytest.raises(FileNotFoundError):
            await eng.reload(tmp_path / "does_not_exist")
    finally:
        await eng.stop()


async def test_engine_reload_empty_dir_refused(tmp_path: Path) -> None:
    eng = await Engine.create(tmp_path / "e.db", poll_interval=0.02)
    await eng.start()
    empty = tmp_path / "empty"
    empty.mkdir()
    try:
        with pytest.raises(WiringError):
            await eng.reload(empty)
    finally:
        await eng.stop()


def _write_bad_connector_config(cfg: Path, inbox: Path) -> None:
    """Valid wiring (router resolves) but an outbound connector that fails to build (no directory)."""
    cfg.mkdir(parents=True, exist_ok=True)
    inbox.mkdir(parents=True, exist_ok=True)
    body = (
        "from messagefoundry import inbound, outbound, router, handler, Send, File\n"
        "from messagefoundry.config.wiring import ConnectionSpec\n"
        "from messagefoundry.config.models import ConnectorType\n"
        f"inbound('IB_T_ADT', File(directory={str(inbox)!r}, pattern='*.hl7', "
        "poll_seconds=0.02), router='r')\n"
        "outbound('OUT_BAD', ConnectionSpec(ConnectorType.FILE, {}))\n"
        "@router('r')\n"
        "def route(msg):\n"
        "    return ['h']\n"
        "@handler('h')\n"
        "def handle(msg):\n"
        "    return Send('OUT_BAD', msg)\n"
    )
    (cfg / "cfg.py").write_text(body, encoding="utf-8")


async def test_engine_reload_no_runner_start_failure_resets(tmp_path: Path) -> None:
    """If the first (no-runner) reload fails to start, the runner ref is cleared so a retry works."""
    eng = await Engine.create(tmp_path / "e.db", poll_interval=0.02)
    await eng.start()
    assert eng.registry_runner is None
    try:
        bad = tmp_path / "badconn"
        _write_bad_connector_config(bad, tmp_path / "in")
        with pytest.raises(ValueError):
            await eng.reload(bad)
        assert eng.registry_runner is None  # not wedged with a half-started runner

        good = tmp_path / "good"
        _write_valid_config(good, tmp_path / "in2", tmp_path / "out2")
        await eng.reload(good)
        assert eng.registry_runner is not None and eng.registry_runner.running
    finally:
        await eng.stop()


async def test_engine_reload_starts_graph_when_none_loaded(tmp_path: Path) -> None:
    inbox, outdir, good = tmp_path / "in", tmp_path / "out", tmp_path / "good"
    _write_valid_config(good, inbox, outdir)
    eng = await Engine.create(tmp_path / "e.db", poll_interval=0.02)
    await eng.start()  # no registry added
    assert eng.registry_runner is None
    try:
        await eng.reload(good)
        assert eng.registry_runner is not None and eng.registry_runner.running
        (inbox / "a.hl7").write_bytes(ADT.encode("utf-8"))
        await _until_stat(eng.store, OutboxStatus.DONE.value, 1)
    finally:
        await eng.stop()
    assert (outdir / "MSG1.hl7").exists()


def _write_env_config(cfg: Path, inbox: Path) -> None:
    """A valid graph whose outbound peer is env()-driven (resolved per environment)."""
    cfg.mkdir(parents=True, exist_ok=True)
    inbox.mkdir(parents=True, exist_ok=True)
    (cfg / "c.py").write_text(
        "from messagefoundry import inbound, outbound, router, handler, Send, File, MLLP, env\n"
        f"inbound('IB_E', File(directory={str(inbox)!r}, pattern='*.hl7', poll_seconds=0.02), router='r')\n"
        "outbound('OUT_PEER', MLLP(host=env('peer_host'), port=env('peer_port', cast=int)))\n"
        "@router('r')\n"
        "def route(msg):\n"
        "    return ['h']\n"
        "@handler('h')\n"
        "def handle(msg):\n"
        "    return Send('OUT_PEER', msg)\n",
        encoding="utf-8",
    )


async def test_engine_reload_dry_run_validates_without_swapping(tmp_path: Path) -> None:
    """dry_run validates the candidate graph but never swaps the live one (the promote pre-flight)."""
    inbox, outdir, live = tmp_path / "in", tmp_path / "out", tmp_path / "live"
    _write_valid_config(live, inbox, outdir)
    eng = await Engine.create(tmp_path / "e.db", poll_interval=0.02)
    eng.add_registry(load_config(live))
    await eng.start()
    try:
        other = tmp_path / "other"
        other.mkdir()
        (other / "c.py").write_text(
            "from messagefoundry import inbound, outbound, router, handler, Send, File\n"
            f"inbound('IB_OTHER', File(directory={str(inbox)!r}, pattern='*.hl7', poll_seconds=0.02), router='r')\n"
            f"outbound('OUT2', File(directory={str(outdir)!r}, filename='{{MSH-10}}.hl7'))\n"
            "@router('r')\n"
            "def route(msg):\n"
            "    return ['h']\n"
            "@handler('h')\n"
            "def handle(msg):\n"
            "    return Send('OUT2', msg)\n",
            encoding="utf-8",
        )
        reg = await eng.reload(other, dry_run=True)
        assert "IB_OTHER" in reg.inbound  # the would-be graph was loaded + validated
        # ...but the LIVE graph is untouched and still running.
        assert eng.registry_runner is not None
        assert set(eng.registry_runner.registry.inbound) == {"IB_T_ADT"}
        assert eng.registry_runner.running
    finally:
        await eng.stop()


async def test_engine_reload_dry_run_rejects_missing_env_value(tmp_path: Path) -> None:
    """dry_run resolves env() against THIS instance's values, so a key the target lacks fails loud."""
    inbox, outdir, live = tmp_path / "in", tmp_path / "out", tmp_path / "live"
    _write_valid_config(live, inbox, outdir)
    eng = await Engine.create(tmp_path / "e.db", poll_interval=0.02)  # no env_values defined
    eng.add_registry(load_config(live))
    await eng.start()
    try:
        envcfg = tmp_path / "envcfg"
        _write_env_config(envcfg, inbox)
        with pytest.raises(WiringError, match="peer_host"):
            await eng.reload(envcfg, dry_run=True)
        # The live graph is untouched — a failed pre-flight never disturbs running traffic.
        assert eng.registry_runner is not None
        assert set(eng.registry_runner.registry.inbound) == {"IB_T_ADT"}
    finally:
        await eng.stop()


async def test_reload_regathers_env_values_no_restart(tmp_path: Path) -> None:
    """A reload/promote re-reads the environment values, so an operator editing a values file (adding
    a missing key) takes effect without a service restart — the WiringError's own remedy works (M-23)."""
    values = {"peer_host": "10.0.0.1", "peer_port": "6661"}
    eng = await Engine.create(
        tmp_path / "e.db", poll_interval=0.02, env_values_provider=lambda: dict(values)
    )
    await eng.start()
    try:
        envcfg = tmp_path / "envcfg"
        _write_env_config(envcfg, tmp_path / "in")  # outbound MLLP(host=env, port=env)
        await eng.reload(envcfg, dry_run=True)  # passes with the current values

        del values["peer_host"]  # operator's environment now lacks the key
        with pytest.raises(WiringError, match="peer_host"):
            await eng.reload(envcfg, dry_run=True)  # re-gathered → fails loud (not stale)

        values["peer_host"] = "10.0.0.9"  # operator fixes the values file
        await eng.reload(envcfg, dry_run=True)  # passes again WITHOUT a restart
    finally:
        await eng.stop()


async def test_engine_reload_dry_run_resolves_present_env_value(tmp_path: Path) -> None:
    """With the values defined for this instance, the same env()-driven graph dry-runs clean."""
    inbox = tmp_path / "in"
    eng = await Engine.create(
        tmp_path / "e.db",
        poll_interval=0.02,
        env_values={"peer_host": "10.0.0.9", "peer_port": "6661"},
    )
    await eng.start()  # no graph yet
    try:
        envcfg = tmp_path / "envcfg"
        _write_env_config(envcfg, inbox)
        reg = await eng.reload(envcfg, dry_run=True)
        assert set(reg.outbound) == {"OUT_PEER"}
        assert eng.registry_runner is None  # dry-run on a no-graph engine starts nothing
    finally:
        await eng.stop()
