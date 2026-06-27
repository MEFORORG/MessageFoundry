# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Raw-TCP ASC X12 EDI transport — source + destination (ADR 0012).

X12-over-TCP has **no transport sentinel**: the *frame is the interchange* (``ISA…IEA<terminator>``),
and the segment terminator is **discovered from each ISA header** (possibly a two-byte ``CR``+``LF``),
so the shared single-byte :class:`~messagefoundry.transports.framing.FrameDecoder` cannot frame it.
This connector therefore swaps that codec for the ISA/IEA assembler
(:class:`~messagefoundry.parsing.x12.interchange.X12FrameReader`, pure parsing layer) but reuses
:class:`~messagefoundry.transports.tcp.TcpSource`'s socket-plumbing *shape* (DoS guards, cooperative
stop). For partners who *do* wrap each interchange in a fixed sentinel (STX/ETX, VT/FS), the existing
``Tcp(framing=...)`` connector already applies — use this one when the interchange itself is the frame.

The payload is relayed **opaquely**: each received interchange's raw bytes are handed to the pipeline
handler and routed as a :class:`~messagefoundry.parsing.message.RawMessage` (pair it with
``content_type="x12"`` on the inbound, ADR 0004); a Router/Handler parses it on demand via the pure
:mod:`messagefoundry.parsing.x12` codec. There is **no X12 acknowledgment** (TA1/997/999 are deferred)
— if a Handler returns a reply it is written back verbatim, otherwise nothing is sent. Delivery is
at-least-once, so the receiving system must be **idempotent**.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Callable

from messagefoundry.config.models import ConnectorType, Destination, Source
from messagefoundry.parsing.x12.delimiters import DEFAULT_MAX_INTERCHANGE_BYTES
from messagefoundry.parsing.x12.errors import X12FrameError, X12PeekError
from messagefoundry.parsing.x12.interchange import X12FrameReader
from messagefoundry.parsing.x12.message import X12Message
from messagefoundry.redaction import safe_exc
from messagefoundry.transports.base import (
    DeliveryError,
    DeliveryResponse,
    DestinationConnector,
    InboundHandler,
    NegativeAckError,
    SourceConnector,
    peer_ip_allowed,
    probe_tcp_reachable,
    register_destination,
    register_source,
)
from messagefoundry.transports.mllp import DEFAULT_MAX_CONNECTIONS, DEFAULT_RECEIVE_TIMEOUT

__all__ = ["X12Source", "X12Destination"]

logger = logging.getLogger(__name__)

# Established clients get this long to finish an in-flight commit on stop()/reload before cancellation
# (mirrors MLLPSource/TcpSource; bounds shutdown).
_CLIENT_SHUTDOWN_GRACE = 5.0


# --- destination -------------------------------------------------------------


class X12Destination(DestinationConnector):
    """Send a complete X12 interchange to a raw-TCP receiver, **verbatim** (no synthetic framing — the
    interchange is its own frame). Opens a fresh connection per delivery. Any connect/IO/timeout raises
    :class:`DeliveryError`, so the pipeline retries.

    *Fire-and-forget* (default): with ``expect_reply`` it reads one returned interchange and treats it
    as confirmation — **not** parsed. *Synchronous request/response* (``capture_response``/``reingress_to``,
    ADR 0016): it blocks for the returned interchange on the same socket, classifies a **TA1** interchange
    acknowledgement (``_check_ta1``: TA1*A → accepted; TA1*R → permanent reject → dead-letter; TA1*E →
    accepted-with-warning, *not* retried), and **returns** the reply as a :class:`DeliveryResponse` for the
    delivery worker to capture (ADR 0013). A business response (271/277/278) returned *instead of* a TA1
    is itself the confirmation. ``ta1_required`` makes a no-reply a retry. At-least-once: a lost reply
    re-delivers, so the receiver must be idempotent."""

    def __init__(self, config: Destination) -> None:
        s = config.settings
        self.host: str = str(s.get("host", "127.0.0.1"))
        self.port: int = int(s["port"])
        self.encoding: str = str(s.get("encoding", "utf-8"))
        self.timeout: float = float(s.get("timeout_seconds", 30.0))
        self.connect_timeout: float = float(s.get("connect_timeout", 10.0))
        self.expect_reply: bool = bool(s.get("expect_reply", False))
        # ADR 0016: capture the returned interchange (the 271/TA1) as a reply; ta1_required makes a
        # no-reply a retry. capture_response is forced True by reingress_to at wiring time (ADR 0013).
        self.capture_response: bool = bool(s.get("capture_response", False))
        self.ta1_required: bool = bool(s.get("ta1_required", False))
        mib = s.get("max_interchange_bytes", DEFAULT_MAX_INTERCHANGE_BYTES)
        self.max_interchange_bytes: int | None = int(mib) if mib else None

    async def send(self, payload: str) -> DeliveryResponse | None:
        # Read the returned interchange when capturing it, when a TA1 is contractually required, or for
        # the legacy expect_reply confirmation. Fire-and-forget (none set) is byte-identical to before.
        need_reply = self.expect_reply or self.capture_response or self.ta1_required
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(self.host, self.port), self.connect_timeout
            )
        except (OSError, asyncio.TimeoutError) as exc:
            raise DeliveryError(f"X12 connect to {self.host}:{self.port} failed: {exc}") from exc
        try:
            writer.write(payload.encode(self.encoding))  # verbatim — the interchange is the frame
            await asyncio.wait_for(writer.drain(), self.timeout)
            if need_reply:
                interchange = await asyncio.wait_for(self._read_reply(reader), self.timeout)
                # Classify only when capturing or a TA1 is required; a plain expect_reply stays a
                # not-inspected confirmation (byte-identical legacy behavior). _check_ta1 returns the
                # captured reply, raises on a TA1 reject/error, and returns None for a non-capturing
                # accept (so a ta1_required-only outbound still fails fast on a reject).
                if self.capture_response or self.ta1_required:
                    response = self._check_ta1(interchange)
                    if self.capture_response:
                        return response
        except asyncio.TimeoutError as exc:
            raise DeliveryError("X12 timed out") from exc
        except OSError as exc:
            raise DeliveryError(f"X12 I/O error: {exc}") from exc
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except OSError:
                pass
        return None

    async def test_connection(self) -> None:
        # Reachability only: open + close a connection (no interchange sent) so a test never delivers.
        await probe_tcp_reachable(self.host, self.port, self.connect_timeout, "X12")

    async def _read_reply(self, reader: asyncio.StreamReader) -> bytes:
        """Read one returned interchange. A peer-close / frame-size breach is a **read failure** — the
        partner's disposition is UNKNOWN — so it raises :class:`DeliveryError` and **retries** (it is
        never a captured ``no_reply``), mirroring MLLP ``_read_ack`` (ADR 0013/0016 read/parse split)."""
        decoder = X12FrameReader(max_interchange_bytes=self.max_interchange_bytes)
        while True:
            chunk = await reader.read(4096)
            if not chunk:
                raise DeliveryError("X12 peer closed before returning an interchange")
            try:
                for interchange in decoder.feed(chunk):
                    return interchange
            except X12FrameError as exc:
                raise DeliveryError(f"reply exceeded max interchange size: {exc}") from exc

    def _check_ta1(self, interchange: bytes) -> DeliveryResponse | None:
        """Classify a fully-read returned interchange (ADR 0016 Q2), modelled on MLLP ``_check_ack``.

        Only a **TA1** (interchange acknowledgement) is a transport-level retry gate; a 999/997 functional
        ack or a 271/277/278 application response is **content** that rides re-ingress. Uses only the
        existing ``parsing/x12`` codec (separators discovered from the ISA, never hardcoded — CLAUDE.md §8);
        the socket read and retry decision stay in the transport, so ``parsing/x12`` gains nothing."""
        text = interchange.decode(self.encoding, errors="replace")
        try:
            msg = X12Message.parse(interchange)
        except X12PeekError as exc:
            # A reply interchange WAS received but won't parse. Capturing → outcome='unparseable' (a reply
            # arrived; we just can't read it — NOT "no reply"). Non-capturing → a retryable DeliveryError.
            if self.capture_response:
                return DeliveryResponse(
                    body=text,
                    outcome="unparseable",
                    detail=f"unparseable X12 reply: {safe_exc(exc)}",  # scrub: a bad reply can embed a fragment (#120)
                )
            raise DeliveryError(f"unparseable X12 reply: {exc}") from exc
        functional = [sid for sid in msg.segment_ids() if sid != "ISA"]
        if functional and functional[0] == "TA1":
            ta104 = (msg.get("TA1-04") or "").upper()
            control = msg.get("ISA-13") or "?"  # interchange control number — not PHI
            if ta104 == "R":
                # Interchange rejected: the partner will never accept it → permanent dead-letter (AR).
                raise NegativeAckError(
                    f"X12 TA1 interchange rejected (TA1-04=R, ISA-13={control})",
                    code="AR",
                    permanent=True,
                )
            if ta104 == "E":
                # Resolved (ADR 0016): accepted-with-warning — the interchange WAS accepted, so do NOT
                # retry (re-sending an accepted interchange is unsafe for a state-changing 278N). Logged
                # for operators (code + control id only, never the body); a structured AlertSink for
                # delivered-with-warning is a follow-up.
                logger.warning(
                    "X12 TA1 accepted-with-errors (TA1-04=E, ISA-13=%s) — delivered, not retried",
                    control,
                )
                if self.capture_response:
                    return DeliveryResponse(
                        body=text, outcome="accepted", detail="TA1*E accepted-with-errors"
                    )
                return None
            # TA1*A (or any other present code) → accepted.
            if self.capture_response:
                return DeliveryResponse(body=text, outcome="accepted", detail=f"TA1*{ta104 or 'A'}")
            return None
        # No TA1: a business response (271/277/278) returned instead — it IS the confirmation.
        if self.capture_response:
            return DeliveryResponse(body=text, outcome="accepted", detail="business response")
        return None


# --- source ------------------------------------------------------------------


class X12Source(SourceConnector):
    """Listen for inbound raw-TCP connections, reassemble each ``ISA…IEA`` interchange, and hand its
    **raw bytes** to the pipeline handler. No HL7/X12 ACK: if the handler returns a non-``None`` reply,
    it is written back verbatim on the same connection; otherwise nothing is sent (fire-and-forget)."""

    def __init__(self, config: Source) -> None:
        s = config.settings
        # The bind interface is injected from [inbound].bind_host (authors never set a host on an
        # inbound); fall back to loopback for a missing/None value — never bind all interfaces by
        # accident, since raw TCP has no transport auth. See docs/CONNECTIONS.md.
        self.host: str = str(s.get("host") or "127.0.0.1")
        self.port: int = int(s["port"])
        self.encoding: str = str(s.get("encoding", "utf-8"))
        # Caps below: key absent → secure default; present-but-falsy (None/0) → disabled.
        mc = s.get("max_connections", DEFAULT_MAX_CONNECTIONS)
        self.max_connections: int | None = int(mc) if mc else None
        rt = s.get("receive_timeout", DEFAULT_RECEIVE_TIMEOUT)
        self.receive_timeout: float | None = float(rt) if rt else None
        mib = s.get("max_interchange_bytes", DEFAULT_MAX_INTERCHANGE_BYTES)
        self.max_interchange_bytes: int | None = int(mib) if mib else None
        # Per-connection peer-IP allowlist (Tier 4 operability): refuse a non-listed peer at accept.
        # Absent/empty = no restriction. Mirrors TcpSource/MLLPSource.
        sa = s.get("source_ip_allowlist")
        self.source_ip_allowlist: list[str] | None = [str(x) for x in sa] if sa else None
        self._server: asyncio.Server | None = None
        self._handler: InboundHandler | None = None
        self._active = 0
        # Live client writers + handler tasks so stop()/reload can actively close connections (H-2).
        self._clients: set[asyncio.StreamWriter] = set()
        self._client_tasks: set[asyncio.Task[None]] = set()

    async def start(
        self, handler: InboundHandler, *, leader_gate: Callable[[], bool] | None = None
    ) -> None:
        # leader_gate is ignored: a listen source runs on every node (each binds its own endpoint), so
        # there is no shared-resource double-read to gate. Accepted only so the runner's call is uniform.
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
        # py3.12.1+ waiting for in-flight handlers). A message mid-handler still finishes its commit
        # (the body is durably stored before any reply, so at-least-once holds). Mirrors TcpSource.
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
        task = asyncio.current_task()
        self._clients.add(writer)
        if task is not None:
            self._client_tasks.add(task)
        try:
            if self.source_ip_allowlist is not None:
                peer = writer.get_extra_info("peername")
                if not peer_ip_allowed(peer, self.source_ip_allowlist):
                    logger.warning(
                        "X12 connection from %s refused: not in source_ip_allowlist", peer
                    )
                    return  # not allowlisted — refuse (closed in the outer finally; _active untouched)
            if self.max_connections is not None and self._active >= self.max_connections:
                return  # at capacity — refuse the new client (closed in the outer finally)
            self._active += 1
            try:
                decoder = X12FrameReader(max_interchange_bytes=self.max_interchange_bytes)
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
                        for interchange in decoder.feed(chunk):
                            reply = await self._handler(interchange)
                            if reply is not None:
                                writer.write(reply.encode(self.encoding))  # verbatim reply
                                await writer.drain()
                    except X12FrameError as exc:
                        peer = writer.get_extra_info("peername")
                        logger.warning(
                            "X12 interchange from %s over cap; closing connection: %s", peer, exc
                        )
                        break  # drop the connection rather than buffer without bound
                    except OSError:
                        raise  # peer reset / write failure → handled by the outer OSError catch (quiet)
                    except Exception as exc:
                        # Last-resort (ASVS 16.5.4): an unexpected handler/codec error must not let the
                        # per-connection task die silently or leak detail. Log redacted; drop the conn.
                        peer = writer.get_extra_info("peername")
                        logger.error(
                            "X12 connection from %s failed unexpectedly: %s", peer, safe_exc(exc)
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


register_destination(ConnectorType.X12, X12Destination)
register_source(ConnectorType.X12, X12Source)
