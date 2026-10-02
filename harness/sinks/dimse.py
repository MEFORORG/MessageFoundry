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
"""

from __future__ import annotations

import socket
import sys
import threading
from io import BytesIO
from typing import Any

from harness.endpoints import Endpoints
from harness.sinks import LOOPBACK, Record, Sink

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
    ) -> None:
        super().__init__()
        if not 0 <= status <= 0xFFFF:
            raise ValueError(f"a DIMSE status is a 16-bit value, got {status!r}")
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
        # that counts the UID inside each delivered object still misses it.
        meta = {
            "sop_instance_uid": str(getattr(event.request, "AffectedSOPInstanceUID", "") or ""),
            "calling_ae": str(getattr(event.assoc.requestor, "ae_title", "") or "").strip(),
            "status": f"{self.status:04X}",
        }
        payload = b""
        try:
            dataset = event.dataset
            dataset.file_meta = event.file_meta
            buffer = BytesIO()
            dataset.save_as(buffer, enforce_file_format=True)
            payload = buffer.getvalue()
        except Exception as exc:  # noqa: BLE001 - untrusted object; record it and answer anyway
            meta["decode_error"] = type(exc).__name__
        self._add(Record(payload, meta))
        return self.status


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
