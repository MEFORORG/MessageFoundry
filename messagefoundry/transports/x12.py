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
import time
from collections.abc import Callable, Mapping

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
    encode_wire_body,
    peer_ip_allowed,
    probe_tcp_reachable,
    register_destination,
    register_source,
)
from messagefoundry.transports.mllp import (
    DEFAULT_MAX_CONNECTIONS,
    DEFAULT_RECEIVE_TIMEOUT,
    InsecureHopGuard,
    _MessagePacer,
    _pacing_settings,
)

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
        # ADR 0067 §9 (BACKLOG #97): persistent outbound connection — opt-in reuse of ONE lazily-
        # established TCP connection across deliveries (default False = connect-per-send, byte-identical).
        # Same knobs/semantics as MLLP (ADR 0067) minus TLS (X12-over-TCP has none). Key absent → off; the
        # two freshness knobs follow the receive_timeout convention (present-but-falsy None/0 = disabled).
        self.persistent: bool = bool(s.get("persistent", False))
        it = s.get("idle_timeout_seconds", 60.0)
        self.idle_timeout_seconds: float | None = float(it) if it else None
        ma = s.get("max_connection_age_seconds")
        self.max_connection_age_seconds: float | None = float(ma) if ma else None
        # Cached connection + freshness stamps (monotonic clock); cached only after a fully-successful
        # transaction (including a TA1 — a complete request/response on a healthy transport).
        self._conn: tuple[asyncio.StreamReader, asyncio.StreamWriter] | None = None
        self._last_used = 0.0
        self._established_at = 0.0
        # Fail-loud serial-send guard (no lock — a lock would mask the invariant violation).
        self._sending = False
        self._closed = False
        #: Reconnects observed (stale-detect, post-error discard, desync guard) — log-only.
        self.reconnects: int = 0
        # #200 (ADR 0092): X12-over-TCP has NO TLS at all, so every off-loopback egress is a cleartext
        # hop. Refuse it at the enforced construction gate; allow loopback / per-connection-attested hops
        # (tls_hop_attested for a trusted-segment / proxy-terminated hop), or cross it with a loud,
        # audited WARN on a `cleartext_accepted` declaration. ADR 0153: no data label relaxes this.
        self._hop_guard = InsecureHopGuard.capture(
            host=self.host,
            port=self.port,
            cell="X12 outbound",
            description="cleartext X12-over-TCP egress",
            attested=config.tls_hop_attested,
            attested_reason=config.tls_hop_attested_reason,
            # ADR 0153 decision 4: X12-over-TCP has NO TLS support at all, so `cleartext_accepted` is a
            # PERMANENT, STRUCTURAL declaration here — there is no `tls = true` to migrate to (#311).
            cleartext_accepted=config.cleartext_accepted,
            cleartext_reason=config.cleartext_reason,
            connection=config.name,
        )
        self._hop_guard.enforce_construction()

    async def send(
        self, payload: str, *, metadata: Mapping[str, str] | None = None
    ) -> DeliveryResponse | None:  # metadata (#68): unused — no per-message header knob here
        # ADR 0067 §2.5 (via §9): the delivery worker is the lane's single serial sender — ASSERT it
        # rather than trust it; a concurrent send() on one instance would interleave two interchanges.
        if self._sending:
            raise RuntimeError(
                "X12Destination.send() called concurrently on one instance — the delivery worker "
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
            raise DeliveryError(f"X12 connect to {self.host}:{self.port} failed: {exc}") from exc

    async def _send_once(self, payload: str) -> DeliveryResponse | None:
        """Connect-per-send (``persistent=false``) — byte-identical wire behavior to the pre-#97 code,
        with the close now bounded (#55) and the fail-loud serial-``send()`` assert in :meth:`send`.
        Reads the returned interchange when capturing it, when a TA1 is contractually required, or for
        the legacy ``expect_reply`` confirmation; fire-and-forget (none set) is byte-identical."""
        need_reply = self.expect_reply or self.capture_response or self.ta1_required
        reader, writer = await self._dial()
        try:
            # verbatim — the interchange is the frame. encode_wire_body, not a bare .encode(): a
            # UnicodeEncodeError is a ValueError, so the `except (TimeoutError, OSError)` below would
            # miss it and the escaping exception names the offending character of the interchange.
            writer.write(encode_wire_body(payload, self.encoding, transport="X12"))
            await asyncio.wait_for(writer.drain(), self.timeout)
            if need_reply:
                interchange = await asyncio.wait_for(self._read_reply(reader), self.timeout)
                # _check_ta1 returns the captured reply, raises on a TA1 reject/error, and returns None
                # for a non-capturing accept (a ta1_required-only outbound still fails fast on a reject).
                if self.capture_response or self.ta1_required:
                    response = self._check_ta1(interchange)
                    if self.capture_response:
                        return response
        except TimeoutError as exc:
            raise DeliveryError("X12 timed out") from exc
        except OSError as exc:
            raise DeliveryError(f"X12 I/O error: {exc}") from exc
        finally:
            await self._close_bounded(writer)
        return None

    async def _send_persistent(self, payload: str) -> DeliveryResponse | None:
        """One delivery over the cached connection (ADR 0067 §9): reuse-time liveness →
        reconnect-before-first-byte (uncharged) → write/drain → (need_reply) read + classify → re-cache
        on a fully-successful transaction unless the peer left extra bytes (desync guard). A TA1 (or a
        business 271/277/278) reply is a **complete transaction on a healthy transport**, so the
        connection stays cached and a TA1*R :class:`NegativeAckError` does NOT discard it (mirrors
        MLLP's NAK-keeps-connection, AC-10)."""
        if self._closed:
            raise DeliveryError(
                f"X12 destination {self.host}:{self.port} is closed (stop/reload); "
                "delivery retries on the replacement connector"
            )
        need_reply = self.expect_reply or self.capture_response or self.ta1_required
        conn = self._conn
        if conn is not None:
            reason = self._stale_reason(*conn)
            if reason is not None:
                self._conn = None
                self.reconnects += 1
                logger.info(
                    "X12 %s:%d persistent connection not reused (%s); reconnecting",
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
        interchange: bytes | None = None
        leftover = False
        try:
            try:
                writer.write(encode_wire_body(payload, self.encoding, transport="X12"))
                await asyncio.wait_for(writer.drain(), self.timeout)
            except (TimeoutError, OSError) as exc:
                raise DeliveryError(
                    "X12 send failed in the drain phase (payload written — delivery "
                    f"indeterminate): {exc}"
                ) from exc
            if need_reply:
                try:
                    interchange, leftover = await asyncio.wait_for(
                        self._read_reply_reuse(reader), self.timeout
                    )
                except TimeoutError as exc:
                    raise DeliveryError(
                        "X12 timed out reading the reply (delivery indeterminate)"
                    ) from exc
                except OSError as exc:
                    raise DeliveryError(
                        f"X12 I/O error reading the reply (delivery indeterminate): {exc}"
                    ) from exc
        except DeliveryError:
            self._conn = None
            self.reconnects += 1
            logger.warning(
                "X12 %s:%d persistent connection discarded after delivery failure",
                self.host,
                self.port,
            )
            await self._close_bounded(writer)
            raise
        except BaseException:
            self._conn = None
            self.reconnects += 1
            writer.close()
            raise
        # Reuse decision BEFORE _check_ta1 so a TA1*R NegativeAckError (a complete transaction on a
        # healthy transport) cannot discard a good connection (mirrors MLLP's _send_persistent).
        if leftover:
            self._conn = None
            self.reconnects += 1
            logger.warning(
                "X12 %s:%d peer sent extra bytes after its interchange; closing instead of reusing "
                "(desync guard)",
                self.host,
                self.port,
            )
            await self._close_bounded(writer)
        elif self._closed:
            self._conn = None
            await self._close_bounded(writer)
        else:
            self._last_used = time.monotonic()
        if need_reply and interchange is not None and (self.capture_response or self.ta1_required):
            response: DeliveryResponse | None = None
            try:
                response = self._check_ta1(interchange)
            except NegativeAckError:
                raise  # a complete transaction on a healthy transport — connection fate decided above
            except DeliveryError:
                # An unparseable interchange (non-capturing) means the transaction was NOT fully
                # successful — discard the cached connection rather than trust a peer talking garbage.
                await self._discard_after_bad_reply(conn, writer)
                raise
            if response is not None and response.outcome == "unparseable":
                # capture turned the unparseable reply into a captured outcome — same wire garbage.
                await self._discard_after_bad_reply(conn, writer)
            if self.capture_response:
                return response
        return None

    async def _discard_after_bad_reply(
        self,
        conn: tuple[asyncio.StreamReader, asyncio.StreamWriter],
        writer: asyncio.StreamWriter,
    ) -> None:
        """Discard the cached connection after a read-but-unparseable interchange (both the raising
        non-capturing path and the captured ``outcome='unparseable'`` path). Mirrors MLLP's
        ``_discard_unparseable``; fixed reason in the log (a parse error can embed a reply fragment)."""
        if self._conn is conn:
            self._conn = None
            self.reconnects += 1
            logger.warning(
                "X12 %s:%d persistent connection discarded after delivery failure: unparseable reply",
                self.host,
                self.port,
            )
            await self._close_bounded(writer)

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

    async def _read_reply_reuse(self, reader: asyncio.StreamReader) -> tuple[bytes, bool]:
        """Read one returned interchange plus a ``leftover`` flag — ``True`` when the peer packed a
        second interchange (or an opened partial one) past the reply (a desync that would corrupt the
        next transaction, so the caller closes instead of reusing). ADR 0067 §9 / §2.2."""
        decoder = X12FrameReader(max_interchange_bytes=self.max_interchange_bytes)
        while True:
            chunk = await reader.read(4096)
            if not chunk:
                raise DeliveryError("X12 peer closed before returning an interchange")
            try:
                interchanges = list(decoder.feed(chunk))
            except X12FrameError as exc:
                raise DeliveryError(f"reply exceeded max interchange size: {exc}") from exc
            if interchanges:
                # A non-empty decoder buffer after the first interchange = bytes of a further one.
                return interchanges[0], len(interchanges) > 1 or bool(decoder._buf)

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
        # Message-rate pacing (BACKLOG #1114), read through the shared helper so this connector
        # cannot drift from MLLP on what "unset" means. Absent -> OFF, unlike the caps above. One
        # token per INTERCHANGE, which is what this connector's frame is. The port changed
        # REACHABILITY, never the default -- a stock X12 inbound still has no rate bound.
        self.max_messages_per_second, self.message_burst = _pacing_settings(s)
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
        # Bound wait_closed() so a Windows ProactorEventLoop overlapped-op wedge can't hang teardown on
        # the suite's shared session loop (#55, mirrors MLLPSource/TcpSource.stop()). The listener is
        # closed and every client task is resolved, so a wait_closed() past the grace is an OS wedge,
        # not in-flight work — abandoning it is safe (the socket is closed).
        if self._server is not None:
            try:
                await asyncio.wait_for(self._server.wait_closed(), timeout=_CLIENT_SHUTDOWN_GRACE)
            except TimeoutError:
                logger.warning("X12 server.wait_closed() exceeded shutdown grace; abandoning")
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
                pacer = _MessagePacer.for_rate(self.max_messages_per_second, self.message_burst)
                while True:
                    # ASVS 2.4.1 / 15.2.2 — the wait is BEFORE the read, never around the handler.
                    if pacer is not None:
                        await pacer.pace()
                    if self.receive_timeout:
                        try:
                            chunk = await asyncio.wait_for(reader.read(4096), self.receive_timeout)
                        except TimeoutError:
                            break  # idle past receive_timeout — close the connection
                    else:
                        chunk = await reader.read(4096)
                    if not chunk:
                        break
                    try:
                        decoded = 0
                        for interchange in decoder.feed(chunk):
                            decoded += 1
                            reply = await self._handler(interchange)
                            if reply is not None:
                                writer.write(reply.encode(self.encoding))  # verbatim reply
                                await writer.drain()
                        # Charge AFTER the interchanges in this chunk are fully handled.
                        if pacer is not None:
                            pacer.settle(decoded)
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
            try:  # noqa: SIM105
                # Bound the close (see stop()): an unbounded Proactor writer.wait_closed() would never
                # let the per-client task finish, so stop()'s grace never sees it done (#55).
                await asyncio.wait_for(writer.wait_closed(), timeout=_CLIENT_SHUTDOWN_GRACE)
            except (TimeoutError, OSError):
                pass


register_destination(ConnectorType.X12, X12Destination)
register_source(ConnectorType.X12, X12Source)
