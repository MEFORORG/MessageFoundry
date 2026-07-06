# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Per-outbound **simulate** (egress-suppressed) mode — shadow / parallel-run (#15).

Covers the config surface (Destination model, outbound() factory, connections.toml, [shadow] settings)
and the end-to-end behaviour: a simulate outbound runs the full pipeline + finalizes PROCESSED but
**never delivers** to the real peer, and a deployment-wide ``simulate_all_egress`` forces it on.
"""

from __future__ import annotations

import asyncio
import textwrap
from pathlib import Path

import pytest

from messagefoundry.config.connections_edit import list_connections, upsert_connection
from messagefoundry.config.models import ConnectorType, Destination
from messagefoundry.config.settings import ServiceSettings, ShadowSettings
from messagefoundry.config.wiring import (
    ConnectionSpec,
    InboundConnection,
    OutboundConnection,
    Registry,
    Send,
    WiringError,
    build_outbound_connection,
    load_config,
)
from messagefoundry.parsing.message import Message
from messagefoundry.pipeline.wiring_runner import RegistryRunner
from messagefoundry.store import MessageStatus, MessageStore, OutboxStatus

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


def _registry(inbox: Path, outdir: Path, *, simulate: bool = False) -> Registry:
    """File in → handler (transforms) → File out, with the outbound's simulate flag configurable."""
    reg = Registry()
    reg.add_outbound(
        OutboundConnection(
            "file_out",
            ConnectionSpec(
                ConnectorType.FILE, {"directory": str(outdir), "filename": "{MSH-10}.hl7"}
            ),
            simulate=simulate,
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
    reg.add_router("r", lambda m: ["h"])

    def handle(msg: Message) -> Send:
        msg["MSH-3"] = "FOUNDRY"  # a transform, so MEFOR's would-send output is observable
        return Send("file_out", msg)

    reg.add_handler("h", handle)
    return reg


async def _until_stat(
    store: MessageStore, status: str, expected: int, timeout: float = 3.0
) -> None:
    elapsed = 0.0
    while (await store.stats()).get(status, 0) != expected:
        await asyncio.sleep(0.02)
        elapsed += 0.02
        if elapsed > timeout:
            raise AssertionError(f"{status} != {expected} within timeout")


async def _until_message(store: MessageStore, status: str, timeout: float = 3.0) -> None:
    elapsed = 0.0
    while not await store.list_messages(channel_id="file_in", status=status):
        await asyncio.sleep(0.02)
        elapsed += 0.02
        if elapsed > timeout:
            raise AssertionError(f"no {status} message within timeout")


# --- config surface ----------------------------------------------------------


def test_destination_model_simulate_defaults_false() -> None:
    assert Destination(name="d", type=ConnectorType.FILE).simulate is False
    assert Destination(name="d", type=ConnectorType.FILE, simulate=True).simulate is True


def test_build_outbound_connection_threads_simulate() -> None:
    spec = ConnectionSpec(ConnectorType.FILE, {"directory": "/tmp/x"})
    assert build_outbound_connection("OB", spec, simulate=True).simulate is True
    assert build_outbound_connection("OB2", spec).simulate is False  # default off


def test_shadow_settings() -> None:
    assert ShadowSettings().simulate_all_egress is False
    parsed = ServiceSettings.model_validate({"shadow": {"simulate_all_egress": True}})
    assert parsed.shadow.simulate_all_egress is True


_LOGIC_PY = textwrap.dedent(
    """
    from messagefoundry import Send, handler, router

    @router("r")
    def route(msg):
        return ["h"]

    @handler("h")
    def handle(msg):
        return Send("OB", msg)
    """
)


def _config(tmp_path: Path, toml: str) -> Path:
    (tmp_path / "logic.py").write_text(_LOGIC_PY, encoding="utf-8")
    (tmp_path / "connections.toml").write_text(textwrap.dedent(toml), encoding="utf-8")
    return tmp_path


def test_connections_toml_simulate_true(tmp_path: Path) -> None:
    reg = load_config(
        _config(
            tmp_path,
            """
            [[inbound]]
            name = "IB"
            transport = "mllp"
            router = "r"
              [inbound.settings]
              port = 2600

            [[outbound]]
            name = "OB"
            transport = "mllp"
            simulate = true
              [outbound.settings]
              host = "epic.example"
              port = 2700
            """,
        )
    )
    assert reg.outbound["OB"].simulate is True


def test_connections_toml_simulate_defaults_false(tmp_path: Path) -> None:
    reg = load_config(
        _config(
            tmp_path,
            """
            [[inbound]]
            name = "IB"
            transport = "mllp"
            router = "r"
              [inbound.settings]
              port = 2600

            [[outbound]]
            name = "OB"
            transport = "mllp"
              [outbound.settings]
              host = "epic.example"
              port = 2700
            """,
        )
    )
    assert reg.outbound["OB"].simulate is False


def test_connections_toml_simulate_non_bool_errors(tmp_path: Path) -> None:
    with pytest.raises(WiringError):
        load_config(
            _config(
                tmp_path,
                """
                [[inbound]]
                name = "IB"
                transport = "mllp"
                router = "r"
                  [inbound.settings]
                  port = 2600

                [[outbound]]
                name = "OB"
                transport = "mllp"
                simulate = "yes"
                  [outbound.settings]
                  host = "epic.example"
                  port = 2700
                """,
            )
        )


# --- GUI/CLI editor round-trip -----------------------------------------------


def test_upsert_preserves_simulate(tmp_path: Path) -> None:
    # Regression guard: the connections.toml editor must round-trip the simulate flag (it lives in
    # _SCALAR_FIELDS) — a GUI/CLI edit of a shadow outbound must not silently turn it live again.
    (tmp_path / "connections.toml").write_text(
        textwrap.dedent(
            """
            [[outbound]]
            name = "OB"
            transport = "mllp"
            simulate = true
              [outbound.settings]
              host = "epic.example"
              port = 2700
            """
        ),
        encoding="utf-8",
    )
    [obj] = [c for c in list_connections(tmp_path) if c["name"] == "OB"]
    assert obj["simulate"] is True
    upsert_connection(tmp_path, obj, validate=lambda _p: None)  # re-save (a no-op GUI edit)
    [reloaded] = [c for c in list_connections(tmp_path) if c["name"] == "OB"]
    assert reloaded["simulate"] is True  # preserved across the round-trip


# --- end-to-end: egress is suppressed, message still finalizes PROCESSED ------


async def test_simulate_capturing_outbound_captures_nothing(
    store: MessageStore, tmp_path: Path
) -> None:
    # A *capturing* outbound in simulate finalizes PROCESSED but captures NO response — with egress
    # suppressed there is no real reply, so it can't (e.g.) re-ingress an empty body and ERROR a child.
    inbox = tmp_path / "in"
    inbox.mkdir()
    (inbox / "a.hl7").write_bytes(ADT.encode("utf-8"))
    reg = Registry()
    reg.add_outbound(
        OutboundConnection(
            "mllp_out",
            ConnectionSpec(
                ConnectorType.MLLP,
                {"host": "127.0.0.1", "port": 65000, "capture_response": True},
            ),
            simulate=True,
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
    reg.add_router("r", lambda m: ["h"])
    reg.add_handler("h", lambda m: Send("mllp_out", m))
    runner = RegistryRunner(reg, store, poll_interval=0.02)
    await runner.start()
    try:
        await _until_message(store, MessageStatus.PROCESSED.value)
    finally:
        await runner.stop()
    cur = await store._db.execute("SELECT COUNT(*) AS n FROM response")  # noqa: SLF001 — test query
    assert (await cur.fetchone())["n"] == 0  # nothing captured — egress (and its reply) suppressed


async def test_reload_toggles_simulate(store: MessageStore, tmp_path: Path) -> None:
    inbox, outdir = tmp_path / "in", tmp_path / "out"
    inbox.mkdir()
    runner = RegistryRunner(_registry(inbox, outdir, simulate=False), store, poll_interval=0.02)
    await runner.start()
    try:
        assert runner.outbound_simulated("file_out") is False
        await runner.reload(_registry(inbox, outdir, simulate=True))
        assert runner.outbound_simulated("file_out") is True  # reload turned the lane into a shadow
        await runner.reload(_registry(inbox, outdir, simulate=False))
        assert runner.outbound_simulated("file_out") is False  # ...and back
    finally:
        await runner.stop()


async def test_simulate_suppresses_egress_but_finalizes_processed(
    store: MessageStore, tmp_path: Path
) -> None:
    inbox, outdir = tmp_path / "in", tmp_path / "out"
    inbox.mkdir()
    (inbox / "a.hl7").write_bytes(ADT.encode("utf-8"))
    runner = RegistryRunner(_registry(inbox, outdir, simulate=True), store, poll_interval=0.02)
    await runner.start()
    try:
        await _until_stat(store, OutboxStatus.DONE.value, 1)  # the outbound row finalizes done...
        await _until_message(store, MessageStatus.PROCESSED.value)  # ...and the message PROCESSED
        assert (
            runner.outbound_simulated("file_out") is True
        )  # query while running (stop() clears it)
    finally:
        await runner.stop()
    # Egress was SUPPRESSED — the File connector's send() never ran, so nothing was written.
    assert not (outdir / "MSG1.hl7").exists()


async def test_non_simulate_delivers_normally(store: MessageStore, tmp_path: Path) -> None:
    # Control (keeps the suppression assertion above non-vacuous): without simulate, the file IS written.
    inbox, outdir = tmp_path / "in", tmp_path / "out"
    inbox.mkdir()
    (inbox / "a.hl7").write_bytes(ADT.encode("utf-8"))
    runner = RegistryRunner(_registry(inbox, outdir, simulate=False), store, poll_interval=0.02)
    await runner.start()
    try:
        await _until_stat(store, OutboxStatus.DONE.value, 1)
        assert (
            runner.outbound_simulated("file_out") is False
        )  # query while running (stop() clears it)
    finally:
        await runner.stop()
    assert (outdir / "MSG1.hl7").read_bytes().decode("utf-8").find("FOUNDRY") != -1


async def test_simulate_all_egress_master_switch(store: MessageStore, tmp_path: Path) -> None:
    # The outbound itself is NOT simulate, but the deployment-wide switch forces every outbound off-air.
    inbox, outdir = tmp_path / "in", tmp_path / "out"
    inbox.mkdir()
    (inbox / "a.hl7").write_bytes(ADT.encode("utf-8"))
    runner = RegistryRunner(
        _registry(inbox, outdir, simulate=False), store, poll_interval=0.02, simulate_all=True
    )
    await runner.start()
    try:
        await _until_message(store, MessageStatus.PROCESSED.value)
        assert (
            runner.outbound_simulated("file_out") is True
        )  # query while running (stop() clears it)
    finally:
        await runner.stop()
    assert not (outdir / "MSG1.hl7").exists()  # forced egress suppression
