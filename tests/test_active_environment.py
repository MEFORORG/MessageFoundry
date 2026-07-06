# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""The active-environment accessor for per-face transform logic (current_environment)."""

from __future__ import annotations

from pathlib import Path

from messagefoundry.config.active_environment import (
    activated,
    current_environment,
    reset,
    set_active,
)
from messagefoundry.config.models import ConnectorType, Validation
from messagefoundry.config.wiring import (
    ConnectionSpec,
    InboundConnection,
    OutboundConnection,
    Registry,
    Send,
)
from messagefoundry.pipeline.dryrun import transform_one
from messagefoundry.store import MessageStore

ADT = "MSH|^~\\&|A|B|C|D|20260101||ADT^A01|MSG1|P|2.5.1\rPID|1||100^^^H^MR||DOE^JANE\r"


def test_current_environment_none_outside_run() -> None:
    assert current_environment() is None


def test_activated_publishes_and_restores() -> None:
    with activated("staging"):
        assert current_environment() == "staging"
        with activated("prod"):
            assert current_environment() == "prod"
        assert current_environment() == "staging"  # inner restored
    assert current_environment() is None  # outer restored


def test_set_active_reset() -> None:
    token = set_active("dev")
    try:
        assert current_environment() == "dev"
    finally:
        reset(token)
    assert current_environment() is None


def _registry_with_face_handler() -> Registry:
    reg = Registry()
    reg.add_inbound(
        InboundConnection(
            "in",
            ConnectionSpec(ConnectorType.MLLP, {"port": 2575}),
            router="r",
            validation=Validation(strict=False, hl7_version="2.5.1"),
        )
    )
    reg.add_outbound(
        OutboundConnection("out", ConnectionSpec(ConnectorType.FILE, {"directory": "./out"}))
    )
    reg.add_router("r", lambda m: ["h"])

    def handle(msg):  # type: ignore[no-untyped-def]
        # Corepoint "If ActiveFace=Test -> MSH-11.1=T"; prod / unknown -> leave P.
        if current_environment() in ("staging", "dev"):
            msg.set("MSH-11.1", "T")
        return Send("out", msg)

    reg.add_handler("h", handle)
    return reg


def test_handler_reads_active_environment_via_runner_bracket() -> None:
    # transform_one is exactly what the transform worker calls; the runner brackets it with
    # environment_activated(...). Simulate that bracket and confirm the handler branches on the face.
    reg = _registry_with_face_handler()

    with activated("staging"):
        deliveries, _ = transform_one(reg, "h", ADT, "hl7v2")
    assert "|T|2.5.1" in deliveries[0].payload  # MSH-11 stamped T on the test face

    with activated("prod"):
        deliveries, _ = transform_one(reg, "h", ADT, "hl7v2")
    assert "|P|2.5.1" in deliveries[0].payload  # left P in prod

    # No active environment (e.g. a pure dry-run): defaults to the leave-as-is (P) branch.
    deliveries, _ = transform_one(reg, "h", ADT, "hl7v2")
    assert "|P|2.5.1" in deliveries[0].payload


async def test_engine_threads_active_environment_to_runner(tmp_path: Path) -> None:
    from messagefoundry.pipeline import Engine

    store = await MessageStore.open(tmp_path / "e.db")
    try:
        eng = Engine(store, active_environment="prod")
        runner = eng.add_registry(_registry_with_face_handler())
        assert runner._active_environment == "prod"
    finally:
        await store.close()
