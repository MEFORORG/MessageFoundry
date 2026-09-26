# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #1910: the C-STORE status the SCP answers and the disposition the engine records must agree.

Before this fix the SCP answered Success for any object the handler did not RAISE on, and the binary
ingress handler never raises: it records ``ERROR`` and returns ``None`` for an object over the engine's
16 MiB binary ingress ceiling. So an object between 16 MiB and the SCP's own 128 MiB default was answered
Success and recorded ERROR. The modality believed the object delivered and would not re-send it, while
the engine never processed it. That is accept-and-drop.

These tests drive a REAL runner and a REAL ``pynetdicom`` association, so the status and the disposition
are read from the same send. Each pins both halves together, never one alone."""

from __future__ import annotations

import asyncio
import logging
from io import BytesIO
from pathlib import Path

import pytest

pytest.importorskip("pydicom", reason="DICOM SCP tests need the [dicom] extra")
pytest.importorskip("pynetdicom", reason="DICOM SCP tests need the [dicom] extra")

from messagefoundry.config.models import ConnectorType, ContentType, Source  # noqa: E402
from messagefoundry.config.wiring import DICOM, Registry, build_inbound_connection  # noqa: E402
from messagefoundry.pipeline import wiring_runner  # noqa: E402
from messagefoundry.pipeline.wiring_runner import RegistryRunner  # noqa: E402
from messagefoundry.store import MessageStatus, MessageStore  # noqa: E402
from messagefoundry.transports.dicom import DicomScpSource  # noqa: E402
from tests._dicom_sample import make_sr_part10  # noqa: E402

_SCP_AE = "MEFOR_SCP"
_NAME = "IB_DICOM"
_MIB = 1024 * 1024

_SUCCESS = 0x0000
_OUT_OF_RESOURCES = 0xA700
_CANNOT_UNDERSTAND = 0xC000


@pytest.fixture
async def store(tmp_path: Path):
    s = await MessageStore.open(tmp_path / "dicom.db")
    yield s
    await s.close()


def _big_sr(payload_bytes: int) -> bytes:
    """A synthetic SR Part-10 object grown by one large OB element, so its size lands where a test
    needs it. The filler is zero bytes: it carries no PHI and nothing reads it."""
    from pydicom import dcmread

    ds = dcmread(BytesIO(make_sr_part10()))
    ds.EncapsulatedDocument = b"\x00" * payload_bytes  # (0042,0011) OB
    out = BytesIO()
    ds.save_as(out, enforce_file_format=True)
    return out.getvalue()


def _scu_cstore(port: int, data: bytes) -> int:
    """Associate and C-STORE ``data``; return the DIMSE status the SCP answered."""
    from pydicom import dcmread
    from pynetdicom import AE

    ds = dcmread(BytesIO(data))
    ae = AE(ae_title="MODALITY1")
    ae.add_requested_context(ds.SOPClassUID, ds.file_meta.TransferSyntaxUID)
    ae.maximum_pdu_size = 0  # unlimited on our side; the SCP's max_pdu_size still fragments
    ae.dimse_timeout = 120
    ae.network_timeout = 120
    assoc = ae.associate("127.0.0.1", port, ae_title=_SCP_AE)
    assert assoc.is_established, "the association must be accepted; the C-STORE is under test"
    try:
        status = assoc.send_c_store(ds)
        return int(status.Status)
    finally:
        assoc.release()


async def _rows(store: MessageStore) -> list[dict]:
    cur = await store._db.execute("SELECT status, error FROM messages")
    return [dict(r) for r in await cur.fetchall()]


async def _send_through_runner(store: MessageStore, data: bytes) -> int:
    """Start a real runner with one DICOM inbound on an ephemeral loopback port, send ``data`` over a
    real association, and return the status. The runner binds the handler exactly as production does."""
    reg = Registry()
    reg.add_inbound(
        build_inbound_connection(
            _NAME,
            DICOM(ae_title=_SCP_AE, port=0, timeout_seconds=120.0),
            router="r",
            content_type=ContentType.DICOM,
        )
    )
    reg.add_router("r", lambda m: [])
    runner = RegistryRunner(reg, store)
    await runner.start()
    try:
        source = runner._sources[_NAME]
        assert isinstance(source, DicomScpSource)
        return await asyncio.to_thread(_scu_cstore, source.sockport, data)
    finally:
        await asyncio.wait_for(runner.stop(), timeout=30.0)


async def test_an_object_in_the_16_to_128_mib_band_is_refused_to_the_sender(
    store: MessageStore,
) -> None:
    """The reported defect, reproduced directly: the SHIPPED defaults, one object just over 16 MiB.

    Before the fix this answered Success and recorded ERROR. Now the SCP refuses it before any commit,
    so the sender sees a failure and nothing is half-recorded. Refusal is the right side of the row's
    either/or: the engine's binary ingress ceiling is 16 MiB, so accepting the band would mean raising a
    CWE-770 bound, which is a separate decision."""
    data = _big_sr(wiring_runner._INGRESS_MAX_BYTES + _MIB)
    assert wiring_runner._INGRESS_MAX_BYTES < len(data) < 128 * _MIB  # the band the row names

    status = await _send_through_runner(store, data)

    assert status == _OUT_OF_RESOURCES
    assert await _rows(store) == [], "a refused object must not also be recorded as received"


async def test_a_handler_refusal_is_a_dimse_failure_and_keeps_its_error_row(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The core defect, isolated from the size cap: whenever the ingress handler records ERROR instead
    of committing, the sender must hear a failure. The engine ceiling is lowered under a normal SR so the
    SCP's own cap passes it and only the handler refuses it. Count-and-log still holds: the ERROR row
    exists, and it is the ONLY row."""
    monkeypatch.setattr(wiring_runner, "_INGRESS_MAX_BYTES", 256)
    data = make_sr_part10()
    assert len(data) > 256

    status = await _send_through_runner(store, data)

    assert status == _CANNOT_UNDERSTAND
    rows = await _rows(store)
    assert [r["status"] for r in rows] == [MessageStatus.ERROR.value]
    assert "ingress exceeds max size" in (rows[0]["error"] or "")


async def test_a_committed_object_still_answers_success(store: MessageStore) -> None:
    """Positive control for both tests above: the same runner and association, an object the engine
    accepts, and the answer is Success with a non-ERROR row. Without this, a fix that answered failure
    to everything would pass them."""
    status = await _send_through_runner(store, make_sr_part10())

    assert status == _SUCCESS
    rows = await _rows(store)
    assert len(rows) == 1
    assert rows[0]["status"] != MessageStatus.ERROR.value


def _scp(max_object_bytes: int | None, name: str | None = None) -> DicomScpSource:
    settings: dict[str, object] = {
        "ae_title": _SCP_AE,
        "host": "127.0.0.1",
        "port": 0,
        "max_object_bytes": max_object_bytes,
    }
    return DicomScpSource(Source(type=ConnectorType.DIMSE, name=name, settings=settings))


@pytest.mark.parametrize("configured", [128 * _MIB, None, 0])
def test_the_scp_cap_never_exceeds_the_engine_ingress_ceiling(configured: int | None) -> None:
    """The shipped 128 MiB default, and an uncapped SCP, both resolve to the engine's binary ingress
    ceiling. An object above it could only ever be recorded ERROR, so the SCP must not accept one."""
    assert _scp(configured)._max_object_bytes == wiring_runner._INGRESS_MAX_BYTES


def test_a_cap_below_the_ceiling_is_kept() -> None:
    assert _scp(_MIB)._max_object_bytes == _MIB


@pytest.mark.parametrize(
    ("configured", "warns"),
    [
        (64 * _MIB, True),
        (wiring_runner._INGRESS_MAX_BYTES + 1, True),
        (wiring_runner._INGRESS_MAX_BYTES, False),
        (_MIB, False),
        # The shipped default is clamped too, but the factory always passes it, so it cannot be told
        # from an explicit setting. Warning on every default SCP would be noise.
        (128 * _MIB, False),
    ],
)
def test_a_clamped_cap_is_logged_at_build(
    configured: int, warns: bool, caplog: pytest.LogCaptureFixture
) -> None:
    """BACKLOG #1962: an operator who sets a cap above the ingress ceiling is told, at build, that the
    SCP will refuse anything over the ceiling. A cap at or below it, and the shipped default, stay
    silent."""
    with caplog.at_level(logging.WARNING, logger="messagefoundry.transports.dicom"):
        _scp(configured, name=_NAME)

    hits = [r for r in caplog.records if "ingress ceiling" in r.getMessage()]
    if not warns:
        assert hits == []
        return
    assert len(hits) == 1
    assert hits[0].levelno == logging.WARNING
    message = hits[0].getMessage()
    assert _NAME in message
    assert str(configured) in message
    assert str(wiring_runner._INGRESS_MAX_BYTES) in message


def test_the_receipt_contract_is_declared_by_the_transport() -> None:
    """The runner picks the handler from ``wants_receipt``, not from the connector type. The two
    sources whose answer is their own protocol status declare it; a wire-reply source does not. Were
    the SCP ever started with the standard handler, every committed object would read as refused."""
    from messagefoundry.transports.base import SourceConnector
    from messagefoundry.transports.http_listener import HttpSource
    from messagefoundry.transports.mllp import MLLPSource

    assert SourceConnector.wants_receipt is False
    assert DicomScpSource.wants_receipt is True
    assert HttpSource.wants_receipt is True
    assert MLLPSource.wants_receipt is False
