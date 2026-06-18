# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Raw-TCP transport with **configurable delimiter framing** — source + destination.

Built to relay **X12 (and other non-HL7) feeds over custom-framed TCP** opaquely: the payload
is carried as bytes and never parsed (no ISA/GS/ST inspection, no 997/TA1 acks — those are a
documented follow-up). Whether a received body is routed as a structured HL7
:class:`~messagefoundry.parsing.message.Message` or a
:class:`~messagefoundry.parsing.message.RawMessage` is decided by the **inbound's
``content_type``** (set ``x12`` for these feeds), not by this connector (ADR 0004).

Framing is the shared :mod:`messagefoundry.transports.framing` codec, configured per connection
by a preset name (``stx_etx`` / ``vt_fs`` / ``mllp``) or explicit ``start``/``end``/``trailer``
delimiter byte ints. The 8 X12-over-TCP feeds we target split STX/ETX (``0x02``/``0x03``) and
VT/FS (the same bytes MLLP uses). The listener mirrors :class:`~messagefoundry.transports.mllp.MLLPSource`'s
DoS guards (``max_connections`` / ``receive_timeout`` / ``max_frame_bytes``) and cooperative stop.

**No HL7 ACK.** The source hands each deframed payload to the pipeline handler; if the handler
returns a non-``None`` reply it is framed and sent back on the same connection (so a Handler
*could* emit a framed reply), otherwise nothing is sent (fire-and-forget). The destination frames
and sends; with ``expect_reply`` it reads one framed reply (bounded by timeout + max-frame) and
treats any received frame as confirmation — it does **not** parse or validate the reply.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Callable

from messagefoundry.config.models import ConnectorType, Destination, Source
from messagefoundry.redaction import safe_exc
from messagefoundry.transports.base import (
    DeliveryError,
    DeliveryResponse,
    DestinationConnector,
    InboundHandler,
    SourceConnector,
    peer_ip_allowed,
    probe_tcp_reachable,
    register_destination,
    register_source,
)
from messagefoundry.transports.framing import FrameCodec, FrameError, codec_for
from messagefoundry.transports.mllp import (
    DEFAULT_MAX_CONNECTIONS,
    DEFAULT_MAX_FRAME_BYTES,
    DEFAULT_RECEIVE_TIMEOUT,
)

__all__ = ["TcpSource", "TcpDestination"]

logger = logging.getLogger(__name__)

# Established clients are closed and their handlers given this long to finish an in-flight commit on
# stop()/reload before the connection tasks are cancelled (mirrors MLLPSource; bounds shutdown).
_CLIENT_SHUTDOWN_GRACE = 5.0


def _codec_from_settings(settings: dict[str, object]) -> FrameCodec:
    """Resolve the connection's :class:`FrameCodec` from its settings (preset OR explicit bytes).

    Validates at construction so a bad preset/byte fails when the connector is built (caught in
    dry-run / ``messagefoundry check``), not deep in a read loop."""
    framing = settings.get("framing")
    try:
        return codec_for(
            None if framing is None else str(framing),
            start=_opt_byte(settings.get("start")),
            end=_opt_byte(settings.get("end")),
            trailer=_opt_byte(settings.get("trailer")),
        )
    except ValueError as exc:
        raise ValueError(f"TCP framing misconfigured: {exc}") from exc


def _opt_byte(value: object) -> int | None:
    """Coerce an optional delimiter setting to an int (``None`` passes through). A non-int value
    raises ``ValueError`` so a mistyped delimiter fails loud at construction."""
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, (int, str)):
        raise ValueError(f"delimiter byte must be an int in 0..255, got {value!r}")
    return int(value)


# --- destination -------------------------------------------------------------


class TcpDestination(DestinationConnector):
    """Send a payload to a raw-TCP receiver with the configured framing, relayed opaquely.

    Opens a fresh connection per delivery (simple, robust to flaky peers; pooling can come later).
    Any connect/IO/timeout raises :class:`DeliveryError`, so the pipeline retries. With
    ``expect_reply`` it waits for one framed reply and treats receiving any frame as confirmation —
    it does **not** parse the reply (no ACK/NAK semantics; X12 acks are deferred).

    Note (at-least-once): a payload sent whose reply (when expected) is lost is re-delivered on
    retry — the receiver may see a **duplicate**, so the outbound receiver must be idempotent.
    """

    def __init__(self, config: Destination) -> None:
        s = config.settings
        self.host: str = s.get("host", "127.0.0.1")
        self.port: int = int(s["port"])
        self.codec = _codec_from_settings(s)
        self.timeout: float = float(s.get("timeout_seconds", 30.0))
        self.connect_timeout: float = float(s.get("connect_timeout", 10.0))
        self.encoding: str = s.get("encoding", "utf-8")
        self.expect_reply: bool = bool(s.get("expect_reply", False))
        mf = s.get("max_frame_bytes", DEFAULT_MAX_FRAME_BYTES)
        self.max_frame_bytes: int | None = int(mf) if mf else None
        # ADR 0013: capture the framed reply. Requires expect_reply=True (enforced at wiring). A missing
        # reply is already a retryable DeliveryError (peer-close in _read_reply) and stays one — enabling
        # capture does NOT change delivery semantics, it only returns the frame that was already read.
        self.capture_response: bool = bool(s.get("capture_response", False))

    async def test_connection(self) -> None:
        # Reachability only: open + close a connection (no frame sent) so a test never delivers.
        await probe_tcp_reachable(self.host, self.port, self.connect_timeout, "TCP")

    async def send(self, payload: str) -> DeliveryResponse | None:
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(self.host, self.port), self.connect_timeout
            )
        except (OSError, asyncio.TimeoutError) as exc:
            raise DeliveryError(f"TCP connect to {self.host}:{self.port} failed: {exc}") from exc
        reply: bytes | None = None
        try:
            writer.write(self.codec.frame(payload, self.encoding))
            await asyncio.wait_for(writer.drain(), self.timeout)
            if self.expect_reply:
                reply = await asyncio.wait_for(self._read_reply(reader), self.timeout)
        except asyncio.TimeoutError as exc:
            raise DeliveryError("TCP timed out") from exc
        except OSError as exc:
            raise DeliveryError(f"TCP I/O error: {exc}") from exc
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except OSError:
                pass
        if self.capture_response and reply is not None:
            return DeliveryResponse(
                body=reply.decode(self.encoding, errors="replace"), outcome="accepted"
            )
        return None

    async def _read_reply(self, reader: asyncio.StreamReader) -> bytes:
        """Read one framed reply; any frame counts as confirmation (the bytes are not inspected)."""
        decoder = self.codec.decoder(max_frame_bytes=self.max_frame_bytes)
        while True:
            chunk = await reader.read(4096)
            if not chunk:
                raise DeliveryError("TCP peer closed before sending a reply")
            try:
                for message in decoder.feed(chunk):
                    return message
            except FrameError as exc:
                raise DeliveryError(f"reply exceeded max frame size: {exc}") from exc


# --- source ------------------------------------------------------------------


class TcpSource(SourceConnector):
    """Listen for inbound raw-TCP connections, deframe each message with the configured codec, and
    hand its **raw bytes** to the pipeline handler. No HL7 ACK: if the handler returns a non-``None``
    reply, frame and send it on the same connection; otherwise send nothing (fire-and-forget)."""

    def __init__(self, config: Source) -> None:
        s = config.settings
        # The bind interface is injected from the service's [inbound].bind_host (authors never set a
        # host on an inbound). Fall back to loopback for a missing/None value — never bind all
        # interfaces (0.0.0.0) by accident, since raw TCP has no transport auth. See docs/CONNECTIONS.md.
        self.host: str = s.get("host") or "127.0.0.1"
        self.port: int = int(s["port"])
        self.codec = _codec_from_settings(s)
        self.encoding: str = s.get("encoding", "utf-8")
        # Caps below: key absent → secure default; present-but-falsy (None/0) → disabled.
        mc = s.get("max_connections", DEFAULT_MAX_CONNECTIONS)
        self.max_connections: int | None = int(mc) if mc else None
        rt = s.get("receive_timeout", DEFAULT_RECEIVE_TIMEOUT)
        self.receive_timeout: float | None = float(rt) if rt else None
        mf = s.get("max_frame_bytes", DEFAULT_MAX_FRAME_BYTES)
        self.max_frame_bytes: int | None = int(mf) if mf else None
        # Per-connection peer-IP allowlist (Tier 4 operability): refuse a non-listed peer at accept.
        # Absent/empty = no restriction. Mirrors MLLPSource.
        sa = s.get("source_ip_allowlist")
        self.source_ip_allowlist: list[str] | None = [str(x) for x in sa] if sa else None
        self._server: asyncio.Server | None = None
        self._handler: InboundHandler | None = None
        self._active = 0
        # Live client writers + handler tasks so stop()/reload can actively close established
        # connections and bound the wait (mirrors MLLPSource, review H-2).
        self._clients: set[asyncio.StreamWriter] = set()
        self._client_tasks: set[asyncio.Task[None]] = set()

    async def start(
        self, handler: InboundHandler, *, leader_gate: Callable[[], bool] | None = None
    ) -> None:
        # leader_gate is ignored: a listen source runs on every node (each binds its own endpoint),
        # so there is no shared-resource double-read to gate. Accepted only so the runner's call is
        # uniform across all sources (mirrors MLLPSource).
        self._handler = handler
        self._server = await asyncio.start_server(self._on_client, self.host, self.port)

    @property
    def sockport(self) -> int:
        """The actual bound port (useful when configured with port 0 in tests)."""
        assert self._server is not None
        port: int = self._server.sockets[0].getsockname()[1]
        return port

    async def stop(self) -> None:
        if self._server is not None:
            self._server.close()
        # Close established clients BEFORE awaiting the server (server.wait_closed() hangs on
        # py3.12.1+ waiting for in-flight handlers of a peer holding its connection open). A message
        # mid-handler still finishes its commit (the body is durably stored before any reply, so
        # at-least-once holds). Then await the connection tasks with a bounded grace (review H-2).
        for writer in list(self._clients):
            writer.close()
        pending = [task for task in self._client_tasks if not task.done()]
        if pending:
            _done, still_running = await asyncio.wait(pending, timeout=_CLIENT_SHUTDOWN_GRACE)
            for task in still_running:
                task.cancel()
            if still_running:
                await asyncio.gather(*still_running, return_exceptions=True)
        self._clients.clear()
        self._client_tasks.clear()
        if self._server is not None:
            await self._server.wait_closed()
            self._server = None

    async def _on_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        assert self._handler is not None
        # Register before anything else so stop() can always find + close this connection (H-2).
        task = asyncio.current_task()
        self._clients.add(writer)
        if task is not None:
            self._client_tasks.add(task)
        try:
            if self.source_ip_allowlist is not None:
                peer = writer.get_extra_info("peername")
                if not peer_ip_allowed(peer, self.source_ip_allowlist):
                    logger.warning(
                        "TCP connection from %s refused: not in source_ip_allowlist", peer
                    )
                    return  # not allowlisted — refuse (closed in the outer finally; _active untouched)
            if self.max_connections is not None and self._active >= self.max_connections:
                return  # at capacity — refuse the new client (closed in the outer finally)
            self._active += 1
            try:
                decoder = self.codec.decoder(max_frame_bytes=self.max_frame_bytes)
                while True:
                    if self.receive_timeout:
                        try:
                            chunk = await asyncio.wait_for(reader.read(4096), self.receive_timeout)
                        except asyncio.TimeoutError:
                            break  # idle past receive_timeout — close the connection
                    else:
                        chunk = await reader.read(4096)
                    if not chunk:
                        break
                    try:
                        for message in decoder.feed(chunk):
                            reply = await self._handler(message)
                            if reply is not None:
                                writer.write(self.codec.frame(reply, self.encoding))
                                await writer.drain()
                    except FrameError as exc:
                        peer = writer.get_extra_info("peername")
                        logger.warning(
                            "TCP frame from %s over cap; closing connection: %s", peer, exc
                        )
                        break  # drop the connection rather than buffer without bound
                    except OSError:
                        raise  # peer reset / write failure → handled by the outer OSError catch (quiet)
                    except Exception as exc:
                        # Last-resort (ASVS 16.5.4): an unexpected handler/codec error must not let the
                        # per-connection task die silently or leak detail. Log redacted; drop the conn.
                        peer = writer.get_extra_info("peername")
                        logger.error(
                            "TCP connection from %s failed unexpectedly: %s", peer, safe_exc(exc)
                        )
                        break
            except OSError:
                pass  # peer reset; nothing to do but drop the connection
            finally:
                self._active -= 1
        finally:
            self._clients.discard(writer)
            if task is not None:
                self._client_tasks.discard(task)
            writer.close()
            try:
                await writer.wait_closed()
            except OSError:
                pass


register_destination(ConnectorType.TCP, TcpDestination)
register_source(ConnectorType.TCP, TcpSource)
