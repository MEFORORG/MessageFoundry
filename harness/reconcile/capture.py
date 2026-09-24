# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Capture sink for the parallel-run **shadow** phase (TEST-ENVIRONMENT-PLAN.md §5).

A headless MLLP receiver that ACKs (``AA``) every message and appends it to a per-connection capture
file, so MEFOR Test's shadow output can be diffed **offline** against Corepoint's export. In shadow mode
each MEFOR Test outbound's ``env()`` host/port points at one of these sinks (one sink ⇒ one connection's
output), so the captured stream *is* that connection's output — without delivering duplicates to the real
ancillaries/Epic.

Reuses the engine's own MLLP framing/ACK primitives (``MLLPDecoder`` / ``build_ack`` / ``frame``) so the
sink ACKs exactly as a real downstream would; it never touches the store. Each captured message is one
JSON line ``{"control_id", "raw", "received_at"}`` (``raw`` is latin-1 — lossless byte⇄char — so the
exact bytes round-trip into the offline normalizer). The reconciler reads these back via
:func:`harness.reconcile.compare.load_messages`.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import time
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import TextIO

from harness.frame_cap import resolve_max_frame_bytes
from messagefoundry.config.models import AckMode
from messagefoundry.parsing import Peek
from messagefoundry.parsing.peek import HL7PeekError
from messagefoundry.transports.mllp import (
    DEFAULT_MAX_FRAME_BYTES,
    MLLPDecoder,
    MLLPFrameError,
    build_ack,
    frame,
)

_READ_BYTES = 65536  # the sink only absorbs + ACKs, never routes

log = logging.getLogger(__name__)


class CaptureSink:
    """Bind one or more MLLP ports, ACK every received message, and append each to a JSONL capture."""

    def __init__(
        self,
        out_path: str | Path,
        *,
        host: str = "127.0.0.1",
        ports: Sequence[int] = (2800,),
        ack_mode: AckMode = AckMode.ORIGINAL,
        anonymizer: Callable[[str], str] | None = None,
        max_frame_bytes: int | None = DEFAULT_MAX_FRAME_BYTES,
    ) -> None:
        if not ports:
            raise ValueError("the capture sink needs at least one port")
        self._out = Path(out_path)
        self._host = host
        # 0 turns the cap off and a negative value is refused (harness/frame_cap.py).
        self._max_frame_bytes = resolve_max_frame_bytes(max_frame_bytes)
        self._ports = tuple(ports)
        self._ack_mode = ack_mode
        # Optional de-identifier (ADR 0030 §6): when set, each captured message is anonymized at the
        # single _write choke point so the persisted JSONL carries PHI-free bodies. Wire it as e.g.
        # ``anonymizer=lambda raw: anonymize_checked(raw, salt=salt)``.
        self._anonymizer = anonymizer
        self._servers: list[asyncio.Server] = []
        self._writers: set[asyncio.StreamWriter] = set()
        self._file: TextIO | None = None
        self.captured = 0
        self.unparseable = 0
        self.anon_failed = 0
        self.refused = 0  # connections dropped over an over-cap frame

    async def start(self) -> None:
        self._out.parent.mkdir(parents=True, exist_ok=True)
        # Append so a restarted sink adds to (never truncates) an in-progress connection capture.
        self._file = self._out.open("a", encoding="utf-8")
        for port in self._ports:
            self._servers.append(await asyncio.start_server(self._on_client, self._host, port))

    @property
    def bound_ports(self) -> tuple[int, ...]:
        """The actually-bound ports (resolves an ephemeral ``0`` to the OS-assigned port)."""
        return tuple(
            int(sock.getsockname()[1]) for server in self._servers for sock in server.sockets
        )

    async def stop(self) -> None:
        for server in self._servers:
            server.close()
        for writer in list(self._writers):
            writer.close()
        await asyncio.gather(
            *(server.wait_closed() for server in self._servers), return_exceptions=True
        )
        self._servers.clear()
        if self._file is not None:
            self._file.flush()
            self._file.close()
            self._file = None

    async def _on_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        self._writers.add(writer)
        # Bounded like the engine's MLLP source: this listener takes frames from another party, so it is
        # an ASVS 5.1.1 upload feature (docs/CONNECTIONS.md, BACKLOG #1127).
        decoder = MLLPDecoder(max_frame_bytes=self._max_frame_bytes)
        try:
            while True:
                chunk = await reader.read(_READ_BYTES)
                if not chunk:
                    break
                replies = bytearray()
                dropping = False
                try:
                    for payload in decoder.feed(chunk):
                        self._handle(payload, replies)
                except MLLPFrameError as exc:
                    # Drop the connection rather than buffer, keep or ACK an over-cap frame, as the
                    # engine does. The feed is lazy, so every frame before it in this read was handled.
                    # Counted, because a refused delivery is a finding to reconcile, like an
                    # unparseable one.
                    dropping = True
                    self.refused += 1
                    peer = writer.get_extra_info("peername")
                    log.warning("MLLP frame from %s over cap; closing connection: %s", peer, exc)
                if replies:
                    # Frames accepted before a refusal still get their ACKs, sent before the drop.
                    writer.write(bytes(replies))
                    await writer.drain()
                if dropping:
                    break
        except (ConnectionError, OSError):
            pass  # peer reset/closed mid-stream — expected when the sender or run stops
        finally:
            self._writers.discard(writer)
            writer.close()
            with contextlib.suppress(ConnectionError, OSError):
                await writer.wait_closed()

    def _handle(self, payload: bytes, replies: bytearray) -> None:
        # latin-1 is a lossless byte<->char map, so the captured `raw` round-trips the exact delivered
        # bytes into the offline normalizer (which works on str).
        raw = payload.decode("latin-1")
        try:
            peek = Peek.parse(payload)
        except HL7PeekError:
            # Capture it anyway (with no control id) + count it: an unparseable delivery is itself a
            # finding to reconcile, not something to silently drop. No ACK echo is possible without a
            # parseable header, so skip the ACK for this one.
            self.unparseable += 1
            self._write(None, raw)
            return
        self._write(peek.control_id, raw)
        replies += frame(build_ack(peek, code="AA", ack_mode=self._ack_mode))

    def _write(self, control_id: str | None, raw: str) -> None:
        assert self._file is not None, "CaptureSink.start() must be called before messages arrive"
        if self._anonymizer is not None:
            try:
                raw = self._anonymizer(raw)
            except Exception:
                # Fail closed on ANY anonymizer error at this PHI choke point: an anonymization
                # failure must NEVER write the un-anonymized body (PHI). Drop it and count it — a
                # finding to reconcile, not a silent leak (CLAUDE.md §9). Broad on purpose: the engine
                # path can raise a parser exception that is not a ValueError/RuntimeError.
                self.anon_failed += 1
                return
        json.dump(
            {"control_id": control_id, "raw": raw, "received_at": time.time()},
            self._file,
            ensure_ascii=False,
        )
        self._file.write("\n")
        self._file.flush()  # flush per message so a kill mid-shadow keeps everything captured so far
        self.captured += 1
