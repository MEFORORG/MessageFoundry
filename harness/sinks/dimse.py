# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""DICOM DIMSE sink: a loopback C-STORE SCP that records every object the engine's SCU sends.

Each C-STORE is recorded, accepted or not: :class:`~harness.sinks.Record` ``payload`` is the object
re-encoded to its Part-10 bytes, and ``meta`` carries ``sop_instance_uid`` (as the C-STORE request
named it), ``calling_ae`` and the ``status`` this sink answered (four hex digits). ``status`` picks
the answer: ``0x0000`` (Success, the default), ``0xA700`` (Out of Resources, which the engine
retries), or a hard refusal such as ``0xC000`` (Cannot Understand, which it dead-letters at once).
Recording refused attempts too is what lets a scenario count retries at the peer rather than
trusting the engine's own count.

The SCP accepts the standard storage SOP classes plus Verification (C-ECHO), and requires callers
to address it as :data:`SINK_AE_TITLE`, which ``harness/config/dimse.py`` names as the outbound's
``called_ae_title``. ``pynetdicom`` and ``pydicom`` are imported inside :meth:`DimseSink.start`, so
harness discovery never fails without the ``[dicom]`` extra.

Each object is bounded the way the engine's own SCP bounds one, before it is decoded (ASVS 5.1.1): the
raw received Data Set is charged against ``max_object_bytes`` (default the engine's per-message cap,
which also clamps the engine's SCP), and a Deflated Explicit VR LE object is inflated in bounded
memory, discarding the output, against the lesser of that and the codec's inflate ceiling. An object
over either is answered :data:`CANNOT_UNDERSTAND`, never decoded, and still recorded, with an empty
payload and a ``refused`` reason.
"""

from __future__ import annotations

import socket
import sys
import threading
from io import BytesIO
from typing import Any

from harness.endpoints import Endpoints
from harness.sinks import LOOPBACK, Record, Sink
from messagefoundry.parsing.dicom._inflate import (
    DEFAULT_MAX_INFLATED_BYTES,
    DEFLATED_EXPLICIT_VR_LE,
    bounded_inflate_or_error,
)
from messagefoundry.parsing.dicom.errors import DicomBombError
from messagefoundry.parsing.peek import DEFAULT_MAX_MESSAGE_BYTES

KIND = "dimse"

#: This sink's AE title; the harness graph's outbound names it as ``called_ae_title``.
SINK_AE_TITLE = "HARNESS_SINK"

SUCCESS = 0x0000
OUT_OF_RESOURCES = 0xA700
CANNOT_UNDERSTAND = 0xC000


class DimseSink(Sink):
    kind = KIND

    def __init__(
        self,
        host: str = LOOPBACK,
        port: int = 0,
        *,
        status: int = SUCCESS,
        ae_title: str = SINK_AE_TITLE,
        max_object_bytes: int = DEFAULT_MAX_MESSAGE_BYTES,
    ) -> None:
        super().__init__()
        if not 0 <= status <= 0xFFFF:
            raise ValueError(f"a DIMSE status is a 16-bit value, got {status!r}")
        if max_object_bytes <= 0:
            raise ValueError(
                f"max_object_bytes must be a positive byte count, got {max_object_bytes}"
            )
        self.max_object_bytes = max_object_bytes
        self.host = host
        self.status = status
        self.ae_title = ae_title
        self._requested_port = port
        self._bound_port = 0
        self._ae: Any = None
        self._thread: threading.Thread | None = None

    @property
    def port(self) -> int:
        """The bound port once started (the ephemeral one when 0 was asked for), and still after
        :meth:`stop`, so a caller can report where the sink was."""
        return self._bound_port or self._requested_port

    def start(self) -> None:
        from pynetdicom import AE, StoragePresentationContexts, evt
        from pynetdicom.sop_class import Verification  # type: ignore[attr-defined]

        ae = AE(ae_title=self.ae_title)
        ae.supported_contexts = StoragePresentationContexts
        ae.add_supported_context(Verification)
        ae.require_called_aet = True
        # make_server binds, raising OSError when the port is taken, and the accept loop runs on a
        # thread of ours so stop() can join it.
        server: Any = ae.make_server(
            (self.host, self._requested_port),
            evt_handlers=[(evt.EVT_C_STORE, self._on_c_store)],
            server_class=_server_class(),
        )
        thread = threading.Thread(target=server.serve_forever, daemon=True, name="harness-dimse")
        thread.start()
        # What AE.start_server(block=False) does after it builds its server; the server's own
        # shutdown() removes itself from this list, and AE.shutdown() walks it.
        ae._servers.append(server)
        self._ae, self._thread = ae, thread
        self._bound_port = int(server.server_address[1])

    def stop(self) -> None:
        ae, thread = self._ae, self._thread
        self._ae = self._thread = None
        if ae is not None:
            # Aborts any association still open, so a stopped sink never goes on answering, then
            # shuts the server down and closes its socket.
            ae.shutdown()
        if thread is not None:
            thread.join(timeout=5)

    def _on_c_store(self, event: Any) -> int:
        # Runs on a pynetdicom association thread. Never logs the dataset: it is recorded in memory.
        # Every attempt is recorded and answered with the configured status, even one this sink cannot
        # re-encode -- otherwise pynetdicom would answer its own 0xC211 and a retry scenario would
        # blame the engine for the sink's fault. Such a record has an empty payload, so a scenario
        # that counts the UID inside each delivered object still misses it. The one exception is an
        # object over the cap: it is refused before decode and answered CANNOT_UNDERSTAND, which no
        # configured status may override, so a sink can never be told to accept what it did not read.
        meta = {
            "sop_instance_uid": str(getattr(event.request, "AffectedSOPInstanceUID", "") or ""),
            "calling_ae": str(getattr(event.assoc.requestor, "ae_title", "") or "").strip(),
            "status": f"{self.status:04X}",
        }
        try:
            refused = self._over_cap(event)
        except Exception as exc:  # noqa: BLE001 - never raise to pynetdicom; refuse and record it
            refused = f"could not be measured ({type(exc).__name__}); not decoded"
        if refused:
            meta["refused"] = refused
            meta["status"] = f"{CANNOT_UNDERSTAND:04X}"
            self._add(Record(b"", meta))
            return CANNOT_UNDERSTAND
        payload = b""
        try:
            dataset = event.dataset
            dataset.file_meta = event.file_meta
            buffer = BytesIO()
            dataset.save_as(buffer, enforce_file_format=True)
            payload = buffer.getvalue()
        except Exception as exc:  # noqa: BLE001 - untrusted object; record it and answer anyway
            meta["decode_error"] = type(exc).__name__
        if len(payload) > self.max_object_bytes:
            # The engine's second charge: the preamble, DICM and file meta are not in the raw count.
            meta["refused"] = (
                f"{len(payload)} bytes re-encoded, over the {self.max_object_bytes}-byte cap"
            )
            meta["status"] = f"{CANNOT_UNDERSTAND:04X}"
            self._add(Record(b"", meta))
            return CANNOT_UNDERSTAND
        self._add(Record(payload, meta))
        return self.status

    def _over_cap(self, event: Any) -> str:
        """Why the received object is refused before decode, or ``""``. Reads only the raw Data Set
        pynetdicom buffered, as the engine's SCP does: its length, then, for a Deflated context, how
        far it inflates. ``event.dataset`` would inflate it unbounded. pynetdicom has already
        buffered the whole Data Set when this runs, so the cap bounds decoding, not receipt, which
        is the engine SCP's shape too."""
        data_set = getattr(getattr(event, "request", None), "DataSet", None)
        if data_set is None:
            return ""
        syntax = str(getattr(getattr(event, "context", None), "transfer_syntax", "") or "")
        with data_set.getbuffer() as raw:  # a view: neither check copies the buffered bytes
            size = raw.nbytes
            if size > self.max_object_bytes:
                return f"{size} bytes, over the {self.max_object_bytes}-byte cap; not decoded"
            if syntax == DEFLATED_EXPLICIT_VR_LE:
                cap = min(self.max_object_bytes, DEFAULT_MAX_INFLATED_BYTES)
                try:
                    bounded_inflate_or_error(raw, max_bytes=cap)
                except DicomBombError:
                    return f"inflates past the {cap}-byte cap; not decoded"
        return ""


def _server_class() -> type[Any]:
    """pynetdicom's threaded server, except that on Windows it binds with SO_EXCLUSIVEADDRUSE.

    pynetdicom sets SO_REUSEADDR before it binds, and Windows reads that as "let another socket share
    this port", so a sink could silently co-own a port with a stale sink or another listener. That is
    the hazard ``harness/sinks/_tcp.py`` guards the same way."""
    from pynetdicom.transport import ThreadedAssociationServer

    if sys.platform != "win32":
        return ThreadedAssociationServer

    class _ExclusiveServer(ThreadedAssociationServer):
        def server_bind(self) -> None:
            sock = self.socket
            assert sock is not None  # socketserver creates it before calling server_bind
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
            if self.ae.network_timeout is not None:
                sock.settimeout(self.ae.network_timeout)
            sock.bind(self.server_address)
            self.server_address = sock.getsockname()

    return _ExclusiveServer


def build(endpoints: Endpoints, key: str) -> Sink:
    return DimseSink(LOOPBACK, endpoints.port(key))
