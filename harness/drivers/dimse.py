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


def dicom_extra_missing() -> str | None:
    """None when pydicom and pynetdicom both import, else why not (a reason to report, not a pass)."""
    try:
        import pydicom  # noqa: F401
        import pynetdicom  # noqa: F401
    except ImportError as exc:
        return f"the [dicom] extra (pydicom + pynetdicom) is not installed: {exc}"
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
        from pynetdicom import AE

        from messagefoundry.parsing.dicom._deps import parse_error_types

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
            outcomes.append(self._store(AE, dataset, sop_class, transfer_syntax))
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
            return Injection(
                error=f"no association with {self.host}:{self.port} "
                f"(called AE {self.called_ae_title!r}): refused, aborted or unreachable"
            )
        try:
            status = assoc.send_c_store(dataset)
        except (ValueError, RuntimeError, OSError) as exc:
            return Injection(error=f"C-STORE could not be sent: {type(exc).__name__}: {exc}")
        finally:
            assoc.release()
        code = getattr(status, "Status", None)
        if code is None:
            return Injection(error="no C-STORE response status (aborted or timed out)")
        return Injection(reply=f"{int(code):04X}".encode("ascii"))


def build(endpoints: Endpoints, key: str) -> Driver:
    return DimseDriver(endpoints.host, endpoints.port(key))
