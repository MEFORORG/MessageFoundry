# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""DICOM DIMSE driver: C-STORE each Part-10 payload into the engine's C-STORE SCP inbound.

One association per payload, proposing exactly the payload's SOP class and transfer syntax, the way
a modality does. The engine answers Success only after the object is durably committed
(commit-before-SUCCESS, ADR 0025), so the C-STORE status IS the inbound's acknowledgement: it comes
back in :attr:`Injection.reply` as four upper-case hex digits (``b"0000"`` for Success, ``b"A700"``
for Out of Resources, ``b"C000"`` for Cannot Understand). A status is an answer, not a send error,
the same way an MLLP ``AE`` is; ``error`` is set only when no status came back at all.

``pynetdicom`` and ``pydicom`` are the ``[dicom]`` extra and are imported inside :meth:`inject`, so
harness discovery never fails without them; without them every payload reports an error.
"""

from __future__ import annotations

import functools
from collections.abc import Sequence
from io import BytesIO
from typing import Any

from harness.drivers import Driver, Injection
from harness.endpoints import Endpoints

KIND = "dimse"

#: The engine SCP's AE title in ``harness/config/dimse.py``. The SCP requires the called AE to be
#: its own (``require_called_ae_title`` defaults on), so a driver that addressed anything else would
#: be rejected at association. A test holds this equal to the graph.
ENGINE_AE_TITLE = "MEFOR_HARNESS"
#: The calling AE this driver presents. The harness graph sets no calling-AE allowlist.
CALLING_AE_TITLE = "HARNESS_SCU"

#: The most bytes the driver reads from the engine on one association (ASVS 5.1.1, BACKLOG #1127):
#: the accept, the C-STORE response and the release together. Those are a few hundred bytes, so
#: 1 MiB is ample, the figure the fuzzer allows an ACK. pynetdicom reads any PDU length a peer
#: announces, so the cap is charged in the socket, before each read, and a PDU that would pass it
#: is never read. The engine may still have stored the object; the driver records no reply.
MAX_ASSOCIATION_READ_BYTES = 1 << 20


def dicom_extra_missing() -> str | None:
    """None when pydicom and pynetdicom both import, else why not (a reason to report, not a pass)."""
    try:
        import pydicom  # noqa: F401
        import pynetdicom  # noqa: F401
    except ImportError as exc:
        return f"the [dicom] extra (pydicom + pynetdicom) is not installed: {exc}"
    return None


class _ReadCapExceeded(OSError):
    """Raised inside pynetdicom's reader thread, which reads it as a closed connection and aborts."""


@functools.cache
def _capped_ae_class() -> type[Any]:
    """pynetdicom's ``AE``, with every association's socket charged against
    :data:`MAX_ASSOCIATION_READ_BYTES`. Built on first use, so the ``[dicom]`` extra stays lazy.

    It overrides ``AE._create_socket``, a private hook read against pynetdicom 3.0.4, the locked
    release. ``tests/test_harness_dimse.py`` fires the cap against a peer that announces an
    oversized PDU, so a pynetdicom that stopped calling the hook fails there."""
    from pynetdicom import AE
    from pynetdicom.transport import AssociationSocket

    class _CappedSocket(AssociationSocket):
        received = 0
        refused = False

        def recv(self, nr_bytes: int) -> bytearray:
            # nr_bytes is what the peer announced, so the charge comes before any of it is read.
            if self.received + nr_bytes > MAX_ASSOCIATION_READ_BYTES:
                self.refused = True
                raise _ReadCapExceeded(f"over the {MAX_ASSOCIATION_READ_BYTES}-byte read cap")
            data = super().recv(nr_bytes)
            self.received += len(data)
            return data

    class _CappedAE(AE):
        capped_socket: _CappedSocket | None = None

        def _create_socket(self, assoc: Any, address: Any, tls_args: Any) -> _CappedSocket:
            sock = _CappedSocket(assoc, address=address)
            sock.tls_args = tls_args
            self.capped_socket = sock
            return sock

    return _CappedAE


def _refused(ae: Any) -> Injection | None:
    """The refusal to record when ``ae``'s association passed the read cap, else None."""
    sock = ae.capped_socket
    if sock is not None and sock.refused:
        return Injection(
            error=f"reply refused: the engine sent over {MAX_ASSOCIATION_READ_BYTES} bytes "
            "on the association"
        )
    return None


def status_of(injection: Injection) -> int | None:
    """The C-STORE status an injection got back, or None when it got none."""
    if injection.error or injection.reply is None:
        return None
    try:
        return int(injection.reply, 16)
    except ValueError:
        return None


class DimseDriver(Driver):
    kind = KIND

    def __init__(
        self,
        host: str,
        port: int,
        *,
        called_ae_title: str = ENGINE_AE_TITLE,
        calling_ae_title: str = CALLING_AE_TITLE,
        timeout: float = 20.0,  # longer than the harness SCP's 10s commit wait
    ) -> None:
        self.host = host
        self.port = port
        self.called_ae_title = called_ae_title
        self.calling_ae_title = calling_ae_title
        self.timeout = timeout

    def inject(self, payloads: Sequence[bytes]) -> list[Injection]:
        missing = dicom_extra_missing()
        if missing:
            return [Injection(error=missing) for _ in payloads]
        from pydicom import dcmread

        from messagefoundry.parsing.dicom._deps import parse_error_types

        capped_ae = _capped_ae_class()

        unreadable = parse_error_types()
        outcomes: list[Injection] = []
        for payload in payloads:
            try:
                dataset = dcmread(BytesIO(payload))
                sop_class = dataset.SOPClassUID
                transfer_syntax = dataset.file_meta.TransferSyntaxUID
                dataset.SOPInstanceUID  # noqa: B018  (send_c_store needs it; refuse here, not there)
            except unreadable as exc:
                outcomes.append(
                    Injection(error=f"not a DICOM Part-10 object ({type(exc).__name__})")
                )
                continue
            outcomes.append(self._store(capped_ae, dataset, sop_class, transfer_syntax))
        return outcomes

    def _store(
        self, ae_class: Any, dataset: Any, sop_class: Any, transfer_syntax: Any
    ) -> Injection:
        try:
            ae = ae_class(ae_title=self.calling_ae_title)
            ae.acse_timeout = self.timeout
            ae.dimse_timeout = self.timeout
            ae.network_timeout = self.timeout
            ae.connection_timeout = self.timeout
            ae.add_requested_context(sop_class, transfer_syntax)
            assoc = ae.associate(self.host, self.port, ae_title=self.called_ae_title)
        except (
            ValueError,
            OSError,
        ) as exc:  # ValueError: an AE title or context pynetdicom refuses
            return Injection(error=f"association to {self.host}:{self.port} failed: {exc}")
        if not assoc.is_established:
            return _refused(ae) or Injection(
                error=f"no association with {self.host}:{self.port} "
                f"(called AE {self.called_ae_title!r}): refused, aborted or unreachable"
            )
        try:
            status = assoc.send_c_store(dataset)
        except (ValueError, RuntimeError, OSError) as exc:
            # The cap can abort the association before the send; say so rather than "not sent".
            return _refused(ae) or Injection(
                error=f"C-STORE could not be sent: {type(exc).__name__}: {exc}"
            )
        finally:
            assoc.release()
        code = getattr(status, "Status", None)
        if code is None:
            return _refused(ae) or Injection(
                error="no C-STORE response status (aborted or timed out)"
            )
        # A status read inside the cap stands, even if the release then passed it.
        return Injection(reply=f"{int(code):04X}".encode("ascii"))


def build(endpoints: Endpoints, key: str) -> Driver:
    return DimseDriver(endpoints.host, endpoints.port(key))
