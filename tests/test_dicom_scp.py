# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Real-association loopback tests for the DICOM C-STORE SCP source (ADR 0025 Phase 1): a live
``pynetdicom`` SCU associates and C-STOREs into the ``DicomScpSource``, proving commit-before-SUCCESS
(via a stub ingress handler), the AE-title / peer-IP allowlists, the ``max_object_bytes`` cap, the
timeout-failure policy, the PHI-no-log rule, and clean shutdown."""

from __future__ import annotations

import asyncio
import logging
from io import BytesIO

import pytest

pytest.importorskip("pydicom", reason="DICOM SCP tests need the [dicom] extra")
pytest.importorskip("pynetdicom", reason="DICOM SCP tests need the [dicom] extra")

from messagefoundry.config.models import ConnectorType, Source  # noqa: E402
from messagefoundry.parsing import RawMessage  # noqa: E402
from messagefoundry.parsing.dicom import DicomPeek  # noqa: E402
from messagefoundry.transports.dicom import DicomScpSource  # noqa: E402

from tests._dicom_sample import make_sr_part10  # noqa: E402

_SCP_AE = "MEFOR_SCP"


def _build_scp(captured: list[bytes], **settings_overrides: object) -> DicomScpSource:
    settings: dict[str, object] = {
        "ae_title": _SCP_AE,
        "host": "127.0.0.1",
        "port": 0,  # ephemeral — read the real port from .sockport
    }
    settings.update(settings_overrides)
    return DicomScpSource(Source(type=ConnectorType.DIMSE, settings=settings))


def _scu_cstore(
    port: int, data: bytes, *, calling_ae: str = "MODALITY1"
) -> tuple[bool, int | None]:
    """Run a blocking pynetdicom SCU: associate + C-STORE ``data``. Returns
    ``(established, status)`` — ``status`` is the DIMSE C-STORE status (``None`` if not established)."""
    from pydicom import dcmread
    from pynetdicom import AE

    ds = dcmread(BytesIO(data))
    ae = AE(ae_title=calling_ae)
    ae.add_requested_context(ds.SOPClassUID, ds.file_meta.TransferSyntaxUID)
    # Address the SCP's called AE title (it runs with require_called_ae_title=True).
    assoc = ae.associate("127.0.0.1", port, ae_title=_SCP_AE)
    if not assoc.is_established:
        return (False, None)
    try:
        status = assoc.send_c_store(ds)
        return (True, int(status.Status))
    finally:
        assoc.release()


async def _capture_handler_factory(captured: list[bytes]):
    async def handler(data: bytes) -> None:
        # Mimics the binary _handle_inbound: durably "commit" then return None (DIMSE owns the reply).
        captured.append(data)
        return None

    return handler


async def test_scp_receives_and_commits_before_success() -> None:
    captured: list[bytes] = []
    scp = _build_scp(captured)
    handler = await _capture_handler_factory(captured)
    await scp.start(handler)
    try:
        port = scp.sockport
        data = make_sr_part10()
        established, status = await asyncio.to_thread(_scu_cstore, port, data)
        assert established is True
        assert status == 0x0000  # Success — returned only after the commit (handler ran)
        assert len(captured) == 1, "object must be committed before Success"
        # The committed bytes are a faithful Part-10 object: a codec round-trips them.
        peek = DicomPeek.parse(RawMessage.from_bytes(captured[0], "dicom"))
        sent = DicomPeek.parse(data)
        assert peek.sop_instance_uid == sent.sop_instance_uid
        assert peek.is_structured_report() is True
    finally:
        await scp.stop()


async def test_scp_rejects_unlisted_calling_ae() -> None:
    captured: list[bytes] = []
    scp = _build_scp(captured, calling_ae_allowlist=["MODALITY1"])
    handler = await _capture_handler_factory(captured)
    await scp.start(handler)
    try:
        established, _ = await asyncio.to_thread(
            _scu_cstore, scp.sockport, make_sr_part10(), calling_ae="EVIL_AE"
        )
        assert established is False, "an unlisted calling AE must be refused at association"
        assert captured == []
    finally:
        await scp.stop()


async def test_scp_rejects_unlisted_peer_ip() -> None:
    captured: list[bytes] = []
    # An allowlist that excludes loopback → the C-STORE is refused before any commit.
    scp = _build_scp(captured, source_ip_allowlist=["10.0.0.0/8"])
    handler = await _capture_handler_factory(captured)
    await scp.start(handler)
    try:
        established, status = await asyncio.to_thread(_scu_cstore, scp.sockport, make_sr_part10())
        assert established is True  # association ok; C-STORE refused
        assert status == 0x0124  # Refused: Not authorized
        assert captured == [], "a non-allowlisted peer's object must never be committed"
    finally:
        await scp.stop()


async def test_scp_rejects_oversized_object() -> None:
    captured: list[bytes] = []
    scp = _build_scp(captured, max_object_bytes=64)  # any real SR exceeds this
    handler = await _capture_handler_factory(captured)
    await scp.start(handler)
    try:
        established, status = await asyncio.to_thread(_scu_cstore, scp.sockport, make_sr_part10())
        assert established is True
        assert status == 0xA700  # Refused: Out of Resources — over the cap, before commit
        assert captured == []
    finally:
        await scp.stop()


async def test_scp_commit_failure_returns_dimse_failure_not_success() -> None:
    # A failing ingress commit must surface as a DIMSE failure (the SCU re-sends), never a false Success.
    async def failing_handler(data: bytes) -> None:
        raise RuntimeError("store down")

    scp = _build_scp([])
    await scp.start(failing_handler)
    try:
        established, status = await asyncio.to_thread(_scu_cstore, scp.sockport, make_sr_part10())
        assert established is True
        assert status not in (None, 0x0000), "a commit failure must not return Success"
    finally:
        await scp.stop()


async def test_scp_does_not_log_phi(caplog: pytest.LogCaptureFixture) -> None:
    captured: list[bytes] = []
    scp = _build_scp(captured)
    handler = await _capture_handler_factory(captured)
    await scp.start(handler)
    try:
        phi_name = "Secretpatient^Phicanary^DoNotLog"
        data = make_sr_part10(patient_name=phi_name)
        with caplog.at_level(logging.DEBUG, logger="messagefoundry.transports.dicom"):
            established, status = await asyncio.to_thread(_scu_cstore, scp.sockport, data)
        assert established and status == 0x0000
        blob = "\n".join(r.getMessage() for r in caplog.records)
        assert phi_name not in blob and "Secretpatient" not in blob
    finally:
        await scp.stop()


async def test_scp_stop_is_idempotent() -> None:
    scp = _build_scp([])
    handler = await _capture_handler_factory([])
    await scp.start(handler)
    await scp.stop()
    await scp.stop()  # second stop must not raise
