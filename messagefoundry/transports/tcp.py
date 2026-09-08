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
import time
from collections.abc import Callable, Mapping

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
    InsecureHopGuard,
    _MessagePacer,
    _pacing_settings,
    _peer_host,
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
        # ADR 0067 §9 (BACKLOG #97): persistent outbound connection — opt-in reuse of ONE lazily-
        # established TCP connection across deliveries (default False = connect-per-send, byte-identical).
        # Same knobs/semantics as MLLP (ADR 0067) minus TLS (raw TCP has none). Key absent → off; the two
        # freshness knobs follow the receive_timeout convention (present-but-falsy None/0 = disabled).
        self.persistent: bool = bool(s.get("persistent", False))
        it = s.get("idle_timeout_seconds", 60.0)
        self.idle_timeout_seconds: float | None = float(it) if it else None
        ma = s.get("max_connection_age_seconds")
        self.max_connection_age_seconds: float | None = float(ma) if ma else None
        # Cached connection + freshness stamps (monotonic clock — a wall-clock jump must not expire a
        # healthy socket); cached only after a fully-successful transaction, discarded on any failure.
        self._conn: tuple[asyncio.StreamReader, asyncio.StreamWriter] | None = None
        self._last_used = 0.0
        self._established_at = 0.0
        # Fail-loud serial-send guard (no lock — a lock would mask the invariant violation).
        self._sending = False
        self._closed = False
        #: Reconnects observed (stale-detect, post-error discard, desync guard) — log-only.
        self.reconnects: int = 0
        # #200 (ADR 0092): raw TCP has NO TLS option, so every off-loopback egress is a cleartext hop.
        # Refuse it at the enforced construction gate; allow loopback / per-connection-attested hops
        # (tls_hop_attested for a trusted-segment / proxy-terminated hop), or cross it with a loud,
        # audited WARN on a `cleartext_accepted` declaration. ADR 0153: no data label relaxes this.
        self._hop_guard = InsecureHopGuard.capture(
            host=self.host,
            port=self.port,
            cell="TCP outbound",
            description="cleartext raw-TCP egress",
            attested=config.tls_hop_attested,
            attested_reason=config.tls_hop_attested_reason,
            # ADR 0153 decision 4: raw TCP has NO TLS support at all — no `tls` parameter, no ssl import
            # — so here `cleartext_accepted` is a PERMANENT, STRUCTURAL declaration, not a transitional
            # one. There is no `tls = true` for it to migrate to (BACKLOG #311).
            cleartext_accepted=config.cleartext_accepted,
            cleartext_reason=config.cleartext_reason,
            connection=config.name,
        )
        self._hop_guard.enforce_construction()

    async def test_connection(self) -> None:
        # Reachability only: open + close a connection (no frame sent) so a test never delivers.
        await probe_tcp_reachable(self.host, self.port, self.connect_timeout, "TCP")

    async def send(
        self, payload: str, *, metadata: Mapping[str, str] | None = None
    ) -> DeliveryResponse | None:  # metadata (#68): unused — no per-message header knob here
        # ADR 0067 §2.5 (via §9): the delivery worker is the lane's single serial sender — ASSERT it
        # rather than trust it; a concurrent send() on one instance would interleave two frames.
        if self._sending:
            raise RuntimeError(
                "TcpDestination.send() called concurrently on one instance — the delivery worker "
                "must be the lane's single serial sender (per-lane FIFO invariant, ADR 0067)"
            )
        self._sending = True
        try:
            # Zero-I/O byte-crossing backstop (#200) before the first byte (defense in depth against a
            # reload routing PHI around the construction gate).
            self._hop_guard.assert_send()
            if not self.persistent:
                return await self._send_once(payload)
            return await self._send_persistent(payload)
        finally:
            self._sending = False

    async def _dial(self) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        """One connection attempt — a charged :class:`DeliveryError` on failure. Exactly one dial per
        send in every mode (no internal connect-retry loop; ADR 0067 §9)."""
        try:
            return await asyncio.wait_for(
                asyncio.open_connection(self.host, self.port), self.connect_timeout
            )
        except (TimeoutError, OSError) as exc:
            raise DeliveryError(f"TCP connect to {self.host}:{self.port} failed: {exc}") from exc

    async def _send_once(self, payload: str) -> DeliveryResponse | None:
        """Connect-per-send (``persistent=false``) — byte-identical wire behavior to the pre-#97 code,
        with the close now bounded (the #55 Proactor-wedge pattern; the legacy path awaited
        ``wait_closed()`` unbounded) and the fail-loud serial-``send()`` assert in :meth:`send`."""
        reader, writer = await self._dial()
        reply: bytes | None = None
        try:
            writer.write(self.codec.frame(payload, self.encoding))
            await asyncio.wait_for(writer.drain(), self.timeout)
            if self.expect_reply:
                reply = await asyncio.wait_for(self._read_reply(reader), self.timeout)
        except TimeoutError as exc:
            raise DeliveryError("TCP timed out") from exc
        except OSError as exc:
            raise DeliveryError(f"TCP I/O error: {exc}") from exc
        finally:
            await self._close_bounded(writer)
        if self.capture_response and reply is not None:
            return DeliveryResponse(
                body=reply.decode(self.encoding, errors="replace"), outcome="accepted"
            )
        return None

    async def _send_persistent(self, payload: str) -> DeliveryResponse | None:
        """One delivery over the cached connection (ADR 0067 §9): reuse-time liveness →
        reconnect-before-first-byte (uncharged) → write/drain → (``expect_reply``) read reply → re-cache
        on a fully-successful transaction unless the peer left extra bytes behind (desync guard)."""
        if self._closed:
            raise DeliveryError(
                f"TCP destination {self.host}:{self.port} is closed (stop/reload); "
                "delivery retries on the replacement connector"
            )
        conn = self._conn
        if conn is not None:
            reason = self._stale_reason(*conn)
            if reason is not None:
                # Reconnect-before-first-byte: zero payload bytes touched this socket during THIS send,
                # so a fresh dial cannot duplicate — uncharged. Exactly one dial follows.
                self._conn = None
                self.reconnects += 1
                logger.info(
                    "TCP %s:%d persistent connection not reused (%s); reconnecting",
                    self.host,
                    self.port,
                    reason,
                )
                await self._close_bounded(conn[1])
                conn = None
        if conn is None:
            conn = await self._dial()
            self._established_at = time.monotonic()
        reader, writer = conn
        # Keep the in-flight connection visible so a concurrent aclose() (the reload race) closes it
        # under us — this send then fails loud and is retried.
        self._conn = conn
        reply: bytes | None = None
        leftover = False
        try:
            try:
                writer.write(self.codec.frame(payload, self.encoding))
                await asyncio.wait_for(writer.drain(), self.timeout)
            except (TimeoutError, OSError) as exc:
                raise DeliveryError(
                    "TCP send failed in the drain phase (payload written — delivery "
                    f"indeterminate): {exc}"
                ) from exc
            if self.expect_reply:
                try:
                    reply, leftover = await asyncio.wait_for(
                        self._read_reply_reuse(reader), self.timeout
                    )
                except TimeoutError as exc:
                    raise DeliveryError(
                        "TCP timed out reading the reply (delivery indeterminate)"
                    ) from exc
                except OSError as exc:
                    raise DeliveryError(
                        f"TCP I/O error reading the reply (delivery indeterminate): {exc}"
                    ) from exc
        except DeliveryError:
            # ANY failed transaction discards the connection — a socket in an unknown framing state must
            # never bleed a late/partial reply into the next send. Charged; the next send re-dials.
            self._conn = None
            self.reconnects += 1
            logger.warning(
                "TCP %s:%d persistent connection discarded after delivery failure",
                self.host,
                self.port,
            )
            await self._close_bounded(writer)
            raise
        except BaseException:
            # Cancellation mid-transaction is still a failed transaction — discard synchronously.
            self._conn = None
            self.reconnects += 1
            writer.close()
            raise
        if leftover:
            # Desync guard (ADR 0067 §2.2): the peer packed extra bytes past its reply — reusing would
            # corrupt the next transaction's framing. Conservative: costs a reconnect.
            self._conn = None
            self.reconnects += 1
            logger.warning(
                "TCP %s:%d peer sent extra bytes after its reply; closing instead of reusing "
                "(desync guard)",
                self.host,
                self.port,
            )
            await self._close_bounded(writer)
        elif self._closed:
            # aclose() raced this send after the reply was read — don't cache past the connector's death.
            self._conn = None
            await self._close_bounded(writer)
        else:
            self._last_used = time.monotonic()
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

    async def _read_reply_reuse(self, reader: asyncio.StreamReader) -> tuple[bytes, bool]:
        """Read one framed reply plus a ``leftover`` flag — ``True`` when the peer packed a second
        complete frame or an opened partial one past the reply (a desync that would corrupt the next
        transaction, so the caller closes instead of reusing). ADR 0067 §9 / §2.2."""
        decoder = self.codec.decoder(max_frame_bytes=self.max_frame_bytes)
        while True:
            chunk = await reader.read(4096)
            if not chunk:
                raise DeliveryError("TCP peer closed before sending a reply")
            try:
                messages = list(decoder.feed(chunk))
            except FrameError as exc:
                raise DeliveryError(f"reply exceeded max frame size: {exc}") from exc
            if messages:
                return messages[0], len(messages) > 1 or decoder.in_frame

    def _stale_reason(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> str | None:
        """Why the cached connection must not be reused, or ``None`` when it looks live — cheap, no I/O
        round-trip (ADR 0067 §2.3; TLS-free variant)."""
        if writer.is_closing():
            return "socket is closing/closed"
        if getattr(reader, "_buffer", b""):
            return "unsolicited bytes received while idle"
        if reader.at_eof():
            return "peer closed while idle (EOF)"
        now = time.monotonic()
        if self.idle_timeout_seconds is not None:
            idle = now - self._last_used
            if idle > self.idle_timeout_seconds:
                return f"idle {idle:.1f}s > idle_timeout_seconds={self.idle_timeout_seconds:g}"
        if self.max_connection_age_seconds is not None:
            age = now - self._established_at
            if age > self.max_connection_age_seconds:
                return f"age {age:.1f}s > max_connection_age_seconds={self.max_connection_age_seconds:g}"
        return None

    @staticmethod
    async def _close_bounded(writer: asyncio.StreamWriter) -> None:
        """Bounded close (#55): an unbounded Proactor ``wait_closed()`` can wedge the delivery worker
        forever on a pending overlapped op. Abandoning after the grace is safe (the socket is closed)."""
        writer.close()
        try:  # noqa: SIM105
            await asyncio.wait_for(writer.wait_closed(), _CLIENT_SHUTDOWN_GRACE)
        except (TimeoutError, OSError):
            pass

    async def aclose(self) -> None:
        """Close the cached persistent connection (engine stop / reload swap — the runner calls this for
        every replaced/removed connector). Idempotent; bounded; safe concurrently with an in-flight send
        (closing the socket under it makes that send fail loud → charged → retried)."""
        self._closed = True
        conn = self._conn
        self._conn = None
        if conn is not None:
            await self._close_bounded(conn[1])


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
        # Message-rate pacing (BACKLOG #1114), read through the shared helper so this connector
        # cannot drift from MLLP on what "unset" means. Absent -> OFF, unlike the caps above. The
        # port changed REACHABILITY (raw TCP had no rate control in any configuration), never the
        # default -- a stock raw-TCP inbound still has no rate bound.
        self.max_messages_per_second, self.message_burst = _pacing_settings(s)
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
        # Bound wait_closed() so a Windows ProactorEventLoop overlapped-op wedge can't hang teardown on
        # the suite's shared session loop (#55, mirrors MLLPSource.stop()). The listener is closed and
        # every client task is resolved, so a wait_closed() past the grace is an OS wedge, not in-flight
        # work — abandoning it is safe (the socket is closed) and bounds an otherwise infinite teardown.
        if self._server is not None:
            try:
                await asyncio.wait_for(self._server.wait_closed(), timeout=_CLIENT_SHUTDOWN_GRACE)
            except TimeoutError:
                logger.warning("TCP server.wait_closed() exceeded shutdown grace; abandoning")
            self._server = None

    async def _emit_event(
        self, kind: str, *, peer_host: str | None = None, reason: str | None = None
    ) -> None:
        """Fire one connection event (Corepoint-style log, #46) to the injected sink, fail-soft — a
        capture/store hiccup must never raise into the per-client loop. No-op when the sink is unset."""
        sink = self.on_connection_event
        if sink is None:
            return
        try:
            await sink(kind, peer_host, reason)
        except Exception as exc:
            logger.warning("TCP connection-event emit failed: %s", safe_exc(exc))

    async def _on_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        assert self._handler is not None
        # Register before anything else so stop() can always find + close this connection (H-2).
        task = asyncio.current_task()
        self._clients.add(writer)
        if task is not None:
            self._client_tasks.add(task)
        peer_host = _peer_host(writer)
        established = False  # paired with a single `closed` event on a clean/idle end
        failed = False  # an error close is covered by its specific failure kind — don't double-emit
        close_reason = "eof"
        try:
            if self.source_ip_allowlist is not None:
                peer = writer.get_extra_info("peername")
                if not peer_ip_allowed(peer, self.source_ip_allowlist):
                    logger.warning(
                        "TCP connection from %s refused: not in source_ip_allowlist", peer
                    )
                    await self._emit_event("peer_not_allowlisted", peer_host=peer_host)
                    return  # not allowlisted — refuse (closed in the outer finally; _active untouched)
            if self.max_connections is not None and self._active >= self.max_connections:
                await self._emit_event("at_capacity", peer_host=peer_host)
                return  # at capacity — refuse the new client (closed in the outer finally)
            self._active += 1
            established = True
            await self._emit_event("established", peer_host=peer_host)
            try:
                decoder = self.codec.decoder(max_frame_bytes=self.max_frame_bytes)
                pacer = _MessagePacer.for_rate(self.max_messages_per_second, self.message_burst)
                while True:
                    # ASVS 2.4.1 / 15.2.2 — the wait is BEFORE the read, never around the handler.
                    if pacer is not None:
                        await pacer.pace()
                    if self.receive_timeout:
                        try:
                            chunk = await asyncio.wait_for(reader.read(4096), self.receive_timeout)
                        except TimeoutError:
                            close_reason = "idle_timeout"
                            break  # idle past receive_timeout — close the connection
                    else:
                        chunk = await reader.read(4096)
                    if not chunk:
                        break
                    try:
                        decoded = 0
                        for message in decoder.feed(chunk):
                            decoded += 1
                            reply = await self._handler(message)
                            if reply is not None:
                                writer.write(self.codec.frame(reply, self.encoding))
                                await writer.drain()
                        # Charge AFTER the messages in this chunk are fully handled.
                        if pacer is not None:
                            pacer.settle(decoded)
                    except FrameError as exc:
                        peer = writer.get_extra_info("peername")
                        logger.warning(
                            "TCP frame from %s over cap; closing connection: %s", peer, exc
                        )
                        failed = True
                        await self._emit_event(
                            "frame_oversize", peer_host=peer_host, reason=safe_exc(exc)
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
                        failed = True
                        await self._emit_event(
                            "framing_error", peer_host=peer_host, reason=safe_exc(exc)
                        )
                        break
            except OSError as exc:
                failed = True  # peer reset; nothing to do but drop the connection
                await self._emit_event("peer_reset", peer_host=peer_host, reason=safe_exc(exc))
            finally:
                self._active -= 1
        finally:
            self._clients.discard(writer)
            if task is not None:
                self._client_tasks.discard(task)
            writer.close()
            try:  # noqa: SIM105
                # Bound the close (see stop()): an unbounded Proactor writer.wait_closed() would never
                # let the per-client task finish, so stop()'s grace never sees it done (#55).
                await asyncio.wait_for(writer.wait_closed(), timeout=_CLIENT_SHUTDOWN_GRACE)
            except (TimeoutError, OSError):
                pass
            if established and not failed:
                await self._emit_event("closed", peer_host=peer_host, reason=close_reason)


register_destination(ConnectorType.TCP, TcpDestination)
register_source(ConnectorType.TCP, TcpSource)
