#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Bring up the ingress-plane scan target: a real Engine with live MLLP, raw-TCP and X12 listeners.

WHY A REAL ENGINE AND REAL SOCKETS. Every other test of these listeners either calls the decoder
directly or drives one connector with a stub handler. Neither can see the property the ingress pass
exists for: what the WHOLE path does with hostile bytes -- listener, framing, decode, parse, the
ingress commit and the synchronous NAK -- and whether the engine's own invariants still hold after.
So this module builds the same graph an operator would wire, on an engine created over an empty store
in a temporary directory, and binds every listener to ``127.0.0.1`` on an ephemeral port.

THE SCANNED POSTURE IS NOT THE SHIPPED DEFAULT, and the receipt prints every difference. The frame
cap, the idle bound and the frame deadline are all shortened through supported settings so a case
that must be CLOSED by the listener closes in about a second rather than a minute, and an oversize
frame costs 64 KiB rather than 16 MiB. Each is still the real control, only with a smaller number.

CANARIES ARE INJECTED AT THE RUNTIME SEAM, NEVER BY A SOURCE PATCH. Each one wraps the handler the
engine hands a listener (or, for ``no-reply``, uses the supported ``ack_mode=none`` setting), so it
survives any refactor of the code under ``messagefoundry/`` and there is nothing anchored to a line
number to rot. Each canary injects exactly the defect one detector exists to see.

PHI. The store is created empty and destroyed with the temporary directory. Every message the sweep
sends is synthetic and built in this repository; see the sweep module for the sentinel it carries.
The scope boundary for this tier is stated once, in ADR 0155; this file carries no wording of it.
"""

from __future__ import annotations

import asyncio
import logging
import socket
import tempfile
from collections.abc import AsyncIterator, Mapping
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from messagefoundry.config.models import ConnectorType, ContentType
from messagefoundry.config.wiring import ConnectionSpec, InboundConnection, Registry
from messagefoundry.mllpcodec import AckMode, build_ack
from messagefoundry.pipeline import Engine
from messagefoundry.pipeline.wiring_runner import RegistryRunner
from messagefoundry.transports.base import InboundHandler
from messagefoundry.transports.mllp import MLLPSource
from messagefoundry.transports.tcp import TcpSource
from messagefoundry.transports.x12 import X12Source

MLLP_INBOUND = "IB_DAST_MLLP"
TCP_INBOUND = "IB_DAST_TCP"
X12_INBOUND = "IB_DAST_X12"

#: Plane name -> inbound connection name. The sweep keys every case by plane.
PLANES: Mapping[str, str] = {"mllp": MLLP_INBOUND, "tcp": TCP_INBOUND, "x12": X12_INBOUND}

#: Each canary names the ONE detector it exists to prove can fire. The sweep's evaluator reads this
#: map, so a canary whose detector stays silent is "blind" (exit 2), never a pass.
CANARY_DETECTOR: Mapping[str, str] = {
    "no-reply": "reply",
    "ack-and-drop": "count_and_log",
    "log-body": "log_body",
    "stall": "time",
    "leak": "resources",
    "listener-down": "liveness",
}
CANARIES = tuple(CANARY_DETECTOR)

#: What the ``leak`` canary retains per frame: this many heap bytes and this many open sockets. Sized
#: so the canary's two measured passes (four frames each) clear the policy's heap and handle bounds by
#: a factor of two, while a canary run stays cheap.
_LEAK_BYTES_PER_FRAME = 1024 * 1024
_LEAK_SOCKETS_PER_FRAME = 4

_log = logging.getLogger("messagefoundry.transports.mllp")


class IngressTargetUnusable(RuntimeError):
    """The target came up without the listeners the sweep needs. The runner turns this into exit 2."""


@dataclass
class IngressTarget:
    """A handle on the running target. ``ports`` maps a plane name to its bound port."""

    engine: Engine
    runner: RegistryRunner
    ports: dict[str, int]
    posture: dict[str, str]
    canary: str | None
    #: What the ``leak`` canary retains. Released at teardown.
    leaked: list[Any] = field(default_factory=list)

    async def after_case(self, index: int) -> None:
        """Called by the sweep after every case with its zero-based index. A no-op except under the
        ``listener-down`` canary, which stops the MLLP listener after the first case."""
        if self.canary == "listener-down" and index == 0:
            await self.runner.stop_inbound(MLLP_INBOUND)

    def active_connections(self, plane: str) -> int:
        """Live client connections the plane's listener holds -- the sweep's settle point.

        Read off the listener's own counter with no default, so a rename raises rather than making
        every settle return at once. A stopped listener is absent and holds nothing.
        """
        source = self.runner._sources.get(PLANES[plane])
        if source is None:
            return 0
        assert isinstance(source, MLLPSource | TcpSource | X12Source), type(source)
        return source._active

    def connection_tasks(self) -> int:
        """Per-connection listener tasks still running on this loop, released or not.

        A listener drops ``_active`` BEFORE it closes the socket and writes the ``closed`` event, so
        a connection can be released and its task still alive, holding a socket, until the store
        write lands. The resource snapshot waits on this so a slow store write is not read as growth.
        Matched on each listener's own ``_on_client`` read with no default, so a rename raises rather
        than making the wait return at once.
        """
        names = set()
        for source in self.runner._sources.values():
            assert isinstance(source, MLLPSource | TcpSource | X12Source), type(source)
            names.add(type(source)._on_client.__qualname__)
        return sum(
            1
            for task in asyncio.all_tasks()
            if not task.done() and getattr(task.get_coro(), "__qualname__", "") in names
        )


def _free_ports(count: int) -> list[int]:
    """``count`` distinct loopback ports the OS has just handed out.

    Only the FIRST inbound may ask for port 0: the runner's port-conflict guard compares configured
    port numbers, so a second ``port: 0`` is refused as "already bound" before anything binds. The
    other listeners therefore take a port picked here. Held open together, so the ports are distinct;
    released before the engine binds them, so a collision with another process is possible but rare,
    and it surfaces as IngressTargetUnusable (exit 2), never as a clean run.
    """
    held = [socket.socket(socket.AF_INET, socket.SOCK_STREAM) for _ in range(count)]
    try:
        for sock in held:
            sock.bind(("127.0.0.1", 0))
        return [int(sock.getsockname()[1]) for sock in held]
    finally:
        for sock in held:
            sock.close()


def _registry(settings: Mapping[str, Any], *, canary: str | None) -> Registry:
    cap = int(settings["max_frame_bytes"])
    tcp_port, x12_port = _free_ports(2)
    idle = float(settings["receive_timeout"])
    reg = Registry()
    reg.add_router("dast_router", lambda _message: [])
    reg.add_inbound(
        InboundConnection(
            MLLP_INBOUND,
            ConnectionSpec(
                ConnectorType.MLLP,
                {
                    "port": 0,
                    "max_frame_bytes": cap,
                    "receive_timeout": idle,
                    "max_frame_seconds": float(settings["max_frame_seconds"]),
                },
            ),
            router="dast_router",
            # The no-reply canary is SUPPORTED CONFIGURATION: a listener that persists every frame and
            # answers none of them. The reply detector must see every one of those silences.
            ack_mode=AckMode.NONE if canary == "no-reply" else AckMode.ORIGINAL,
        )
    )
    reg.add_inbound(
        InboundConnection(
            TCP_INBOUND,
            ConnectionSpec(
                ConnectorType.TCP,
                {
                    "port": tcp_port,
                    "framing": "stx_etx",
                    "max_frame_bytes": cap,
                    "receive_timeout": idle,
                },
            ),
            router="dast_router",
            content_type=ContentType.X12,
        )
    )
    reg.add_inbound(
        InboundConnection(
            X12_INBOUND,
            ConnectionSpec(
                ConnectorType.X12,
                {"port": x12_port, "max_interchange_bytes": cap, "receive_timeout": idle},
            ),
            router="dast_router",
            content_type=ContentType.X12,
        )
    )
    return reg


def _posture(settings: Mapping[str, Any], *, canary: str | None) -> dict[str, str]:
    return {
        "listeners": "MLLP, raw TCP (STX/ETX, content x12) and X12, each on 127.0.0.1:<ephemeral>",
        "store": "empty SQLite store in a temporary directory, destroyed after the run",
        "router": "one Router that routes nowhere, so an accepted message ends UNROUTED",
        "max_frame_bytes": f"{settings['max_frame_bytes']} (RELAXED from the shipped 16 MiB)",
        "receive_timeout": f"{settings['receive_timeout']}s (RELAXED from the shipped 60s)",
        "max_frame_seconds": f"{settings['max_frame_seconds']}s on MLLP (RELAXED from the shipped 60s)",
        "tls": "none -- plaintext loopback; TLS listeners are outside this pass",
        "canary": canary or "none",
    }


def _wrap(
    real: InboundHandler, target: IngressTarget, settings: Mapping[str, Any]
) -> InboundHandler:
    """The injected defect for ``target.canary``. Only the MLLP handler is wrapped."""
    canary = target.canary
    stalled = False

    async def ack_and_drop(raw: bytes) -> str | None:
        # ACCEPTED AND DROPPED: an AA goes back and nothing is persisted.
        return build_ack(raw, code="AA")

    async def log_body(raw: bytes) -> str | None:
        _log.info("canary: received body %s", raw.decode("utf-8", errors="replace"))
        return await real(raw)

    async def stall(raw: bytes) -> str | None:
        nonlocal stalled
        if not stalled:  # one-shot, so the canary costs one budget and not one per frame
            stalled = True
            await asyncio.sleep(float(settings["canary_stall_seconds"]))
        return await real(raw)

    async def leak(raw: bytes) -> str | None:
        target.leaked.append(bytearray(_LEAK_BYTES_PER_FRAME))
        target.leaked.extend(
            socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            for _ in range(_LEAK_SOCKETS_PER_FRAME)
        )
        return await real(raw)

    wrappers: dict[str, InboundHandler] = {
        "ack-and-drop": ack_and_drop,
        "log-body": log_body,
        "stall": stall,
        "leak": leak,
    }
    return wrappers.get(canary or "", real)


@asynccontextmanager
async def ingress_target(
    settings: Mapping[str, Any], *, canary: str | None = None
) -> AsyncIterator[IngressTarget]:
    """Bring up engine + listeners, yield the handle, tear it all down. Every wait is bounded."""
    if canary is not None and canary not in CANARY_DETECTOR:
        raise ValueError(f"unknown canary {canary!r}; expected one of {CANARIES}")
    tmp = tempfile.TemporaryDirectory(prefix="mefor-dast-ingress-", ignore_cleanup_errors=True)
    engine = await Engine.create(Path(tmp.name) / "dast-ingress.db", poll_interval=0.02)
    target: IngressTarget | None = None
    try:
        runner = engine.add_registry(_registry(settings, canary=canary))
        await engine.start()
        mllp = runner._sources.get(MLLP_INBOUND)
        tcp = runner._sources.get(TCP_INBOUND)
        x12 = runner._sources.get(X12_INBOUND)
        if not (
            isinstance(mllp, MLLPSource)
            and isinstance(tcp, TcpSource)
            and isinstance(x12, X12Source)
        ):
            raise IngressTargetUnusable(
                "the engine did not bind all three listeners; nothing to scan"
            )
        ports = {"mllp": mllp.sockport, "tcp": tcp.sockport, "x12": x12.sockport}
        target = IngressTarget(
            engine=engine,
            runner=runner,
            ports=ports,
            posture=_posture(settings, canary=canary),
            canary=canary,
        )
        # The listener reads `_handler` afresh for every decoded frame, so the swap takes effect at
        # once. If that ever changes, the four wrapped canaries go blind and exit 2, which reds
        # tests/test_dast_ingress_sweep.py::test_each_canary_trips_its_own_detector.
        assert mllp._handler is not None
        mllp._handler = _wrap(mllp._handler, target, settings)
        yield target
    finally:
        if target is not None:
            for item in target.leaked:
                if isinstance(item, socket.socket):
                    item.close()
            target.leaked.clear()
        await engine.stop()
        tmp.cleanup()
