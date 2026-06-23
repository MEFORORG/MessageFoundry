# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Real-association loopback tests for the DICOM C-STORE SCU destination (ADR 0025 Phase 2): the
``DicomScuDestination`` associates with a live ``pynetdicom`` Storage SCP and C-STOREs the object,
proving byte-faithful forwarding, C-ECHO ``test_connection``, the status→retry classification
(Out-of-Resources → transient :class:`DeliveryError`; a hard refusal → permanent
:class:`NegativeAckError`), the bad-carriage / over-cap permanent failures, and the PHI-no-log rule."""

from __future__ import annotations

import logging
from contextlib import contextmanager
from io import BytesIO
from typing import Any, Iterator

import pytest

pytest.importorskip("pydicom", reason="DICOM SCU tests need the [dicom] extra")
pytest.importorskip("pynetdicom", reason="DICOM SCU tests need the [dicom] extra")

from messagefoundry.config.models import ConnectorType, Destination  # noqa: E402
from messagefoundry.parsing import RawMessage  # noqa: E402
from messagefoundry.parsing.dicom import DicomPeek  # noqa: E402
from messagefoundry.transports.base import DeliveryError, NegativeAckError  # noqa: E402
from messagefoundry.transports.dicom import DicomScuDestination  # noqa: E402

from tests._dicom_sample import BASIC_TEXT_SR, make_sr_part10  # noqa: E402

_SCP_AE = "PACS_SCP"


@contextmanager
def _storage_scp(
    *, status: int = 0x0000, received: list[bytes] | None = None, storage: bool = True
) -> Iterator[int]:
    """Run a live ``pynetdicom`` SCP on an ephemeral loopback port, returning the bound port. Its C-STORE
    handler appends the received object's Part-10 bytes to ``received`` (when given) and returns the
    configured DIMSE ``status``. With ``storage=False`` the SCP supports **only** the Verification context
    (no SR storage), so the SCU's proposed storage context is rejected — exercising the permanent
    no-accepted-context path."""
    from pydicom.uid import ExplicitVRLittleEndian
    from pynetdicom import AE, evt
    from pynetdicom.sop_class import Verification  # type: ignore[attr-defined]

    def handle_store(event: Any) -> int:
        if received is not None:
            ds = event.dataset
            ds.file_meta = event.file_meta
            buf = BytesIO()
            ds.save_as(buf, enforce_file_format=True)
            received.append(buf.getvalue())
        return status

    ae = AE(ae_title=_SCP_AE)
    if storage:
        ae.add_supported_context(BASIC_TEXT_SR, ExplicitVRLittleEndian)
    ae.add_supported_context(Verification)
    server = ae.start_server(
        ("127.0.0.1", 0), block=False, evt_handlers=[(evt.EVT_C_STORE, handle_store)]
    )
    try:
        yield int(server.socket.getsockname()[1])
    finally:
        server.shutdown()


def _scu(port: int, **over: object) -> DicomScuDestination:
    settings: dict[str, object] = {
        "ae_title": "MEFOR_SCU",
        "host": "127.0.0.1",
        "port": port,
        "called_ae_title": _SCP_AE,
        "connect_timeout": 2.0,
        "timeout_seconds": 5.0,
    }
    settings.update(over)
    return DicomScuDestination(
        Destination(name="OB_SCU", type=ConnectorType.DIMSE, settings=settings)
    )


def _carry(data: bytes) -> str:
    """The base64-carried payload a Handler hands a destination (ADR 0028)."""
    return RawMessage.from_bytes(data, "dicom").encode()


async def test_scu_c_store_delivers_byte_faithfully() -> None:
    received: list[bytes] = []
    with _storage_scp(received=received) as port:
        data = make_sr_part10()
        result = await _scu(port).send(_carry(data))
    assert result is None  # one-way DIMSE delivery
    assert len(received) == 1
    # The forwarded object round-trips: the SCP saw the same SOP instance the Handler sent.
    assert DicomPeek.parse(received[0]).sop_instance_uid == DicomPeek.parse(data).sop_instance_uid


async def test_scu_c_echo_test_connection_succeeds() -> None:
    with _storage_scp() as port:
        await _scu(port).test_connection()  # C-ECHO returns Success → no raise


async def test_scu_unreachable_is_transient_delivery_error() -> None:
    # Bind then shut down an SCP to get a definitely-closed port; the association is refused.
    with _storage_scp() as port:
        pass
    with pytest.raises(DeliveryError):
        await _scu(port).send(_carry(make_sr_part10()))


async def test_scu_out_of_resources_is_transient() -> None:
    with _storage_scp(status=0xA700) as port:  # Refused: Out of Resources
        with pytest.raises(DeliveryError) as exc:
            await _scu(port).send(_carry(make_sr_part10()))
    assert not isinstance(exc.value, NegativeAckError)  # transient, not a permanent dead-letter


async def test_scu_hard_refusal_is_permanent() -> None:
    with _storage_scp(status=0xC000) as port:  # Cannot Understand — a hard refusal
        with pytest.raises(NegativeAckError) as exc:
            await _scu(port).send(_carry(make_sr_part10()))
    assert exc.value.permanent is True


async def test_scu_warning_status_is_delivered() -> None:
    # A Warning (0xB0xx) means the peer STORED the object with a caveat → delivered, NOT an error.
    with _storage_scp(status=0xB007) as port:
        assert await _scu(port).send(_carry(make_sr_part10())) is None


async def test_scu_unsupported_sop_class_is_permanent() -> None:
    # The peer answers the association but accepts no presentation context for the object's SOP class
    # (storage rejected) — deterministic, so it must dead-letter permanently, never retry forever.
    with _storage_scp(storage=False) as port:
        with pytest.raises(NegativeAckError) as exc:
            await _scu(port).send(_carry(make_sr_part10()))
    assert exc.value.permanent is True


async def test_scu_bad_object_is_permanent() -> None:
    # A valid carriage whose decoded bytes are NOT a parseable Part-10 object → permanent (code=bad-object),
    # distinct from the bad-carriage path. No association is attempted.
    with _storage_scp() as port:
        with pytest.raises(NegativeAckError) as exc:
            await _scu(port).send(_carry(b"not-a-dicom-object"))
    assert exc.value.permanent is True
    assert exc.value.code == "bad-object"


async def test_scu_bad_carriage_is_permanent() -> None:
    with _storage_scp() as port:
        with pytest.raises(NegativeAckError) as exc:
            await _scu(port).send("not-a-carriage-value")
    assert exc.value.permanent is True


async def test_scu_over_max_object_bytes_is_permanent() -> None:
    with _storage_scp() as port:
        with pytest.raises(NegativeAckError) as exc:
            await _scu(port, max_object_bytes=64).send(_carry(make_sr_part10()))
    assert exc.value.permanent is True


async def test_scu_does_not_log_phi(caplog: pytest.LogCaptureFixture) -> None:
    received: list[bytes] = []
    with _storage_scp(received=received) as port:
        phi_name = "Secretpatient^Phicanary^DoNotLog"
        data = make_sr_part10(patient_name=phi_name)
        with caplog.at_level(logging.DEBUG, logger="messagefoundry.transports.dicom"):
            await _scu(port).send(_carry(data))
    blob = "\n".join(r.getMessage() for r in caplog.records)
    assert phi_name not in blob and "Secretpatient" not in blob
