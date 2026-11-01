# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""What the DICOM C-STORE SCP holds of what a peer sends on an association it accepted (vault BACKLOG
#2712, limb 2, owner ruling B462-R3): a PDU longer than the SCP offered, an object past twice the
object cap, and a send to a peer that reads slowly.

Every listener here binds ``127.0.0.1`` on an ephemeral port. Every object is a synthetic SR from
``tests/_dicom_sample.py``; none holds real PHI.

**These tests need the ``[dicom]`` extra and SKIP without it.** A skipped test is not evidence: see
the note at the top of ``tests/test_dicom_scp_admission.py``.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import socket
import struct
import time
from io import BytesIO
from pathlib import Path
from typing import Any

import pytest

pytest.importorskip("pydicom", reason="DICOM SCP tests need the [dicom] extra")
pytest.importorskip("pynetdicom", reason="DICOM SCP tests need the [dicom] extra")

from messagefoundry.transports import dicom as dicom_module  # noqa: E402
from tests._dicom_sample import make_sr_part10  # noqa: E402
from tests.test_dicom_scp import _SCP_AE, _build_scp, _scu_cstore  # noqa: E402
from tests.test_dicom_scp_admission import _LOG, _running_scp, _until, _warnings  # noqa: E402
from tests.test_dicom_scp_pre_association import (  # noqa: E402
    _a_held_association,
    _a_real_association_request,
    _c_echo_rq,
    _closed_within,
    _rj,
    _stall,
    _thread_baseline,
    _threads_outside_the_test,
)

#: The A-ABORT a PDU longer than the SCP takes gets: service provider, invalid PDU parameter value.
_ABORT_PDU_TOO_LONG = b"\x07\x00" + (4).to_bytes(4, "big") + bytes((0, 0, 0x02, 0x06))
#: The A-ABORT an object past twice the cap, or a command set past its bound, gets: service user,
#: no reason.
_ABORT_OVER_LIMIT = b"\x07\x00" + (4).to_bytes(4, "big") + bytes(4)
#: The A-ABORT a P-DATA-TF pynetdicom would fail on gets: service provider, no reason.
_ABORT_INVALID = b"\x07\x00" + (4).to_bytes(4, "big") + bytes((0, 0, 0x02, 0x00))

_CAP = 4096
_C_STORE_REFUSED_OVER_CAP = 0xC010


def _data_set_bytes(part10: bytes) -> int:
    """The bytes of ``part10``'s data set as a pynetdicom SCU sends them, in its own transfer
    syntax: what the SCP counts against its cap."""
    from pydicom import dcmread
    from pynetdicom.dsutils import encode

    ds = dcmread(BytesIO(part10))
    encoded = encode(ds, ds.file_meta.TransferSyntaxUID.is_implicit_VR, True)
    assert encoded is not None
    return len(encoded)


def _sr_of_at_least(data_set_bytes: int) -> bytes:
    """A synthetic SR whose data set is at least ``data_set_bytes`` long."""
    count = 1
    while True:
        measurements = tuple((f"{n}-1", f"Measure {n}", str(n), "1") for n in range(count))
        part10 = make_sr_part10(measurements=measurements)
        if _data_set_bytes(part10) >= data_set_bytes:
            return part10
        count += 1


def _store_each(port: int, objects: list[bytes]) -> tuple[list[int | None], bool]:
    """C-STORE each of ``objects`` in turn on ONE association. Returns each status, ``None`` for one
    with no answer, and whether the association ended aborted."""
    from pydicom import dcmread
    from pynetdicom import AE

    datasets = [dcmread(BytesIO(data)) for data in objects]
    ae = AE(ae_title="MODALITY1")
    for ds in datasets[:1]:
        ae.add_requested_context(ds.SOPClassUID, ds.file_meta.TransferSyntaxUID)
    assoc = ae.associate("127.0.0.1", port, ae_title=_SCP_AE)
    assert assoc.is_established
    statuses: list[int | None] = []
    try:
        for ds in datasets:
            if not assoc.is_established:
                statuses.append(None)
                continue
            status = assoc.send_c_store(ds)
            statuses.append(int(status.Status) if "Status" in status else None)
    finally:
        if assoc.is_established:
            assoc.release()
    return statuses, assoc.is_aborted


def _p_data(control: int, payload: bytes, *, context_id: int = 1) -> bytes:
    """A P-DATA-TF of one PDV item carrying ``payload`` with message control header ``control``."""
    item = struct.pack(">IBB", len(payload) + 2, context_id, control) + payload
    return b"\x04\x00" + struct.pack(">I", len(item)) + item


def _c_echo_rsp() -> bytes:
    """A whole C-ECHO-RSP P-DATA-TF, as pynetdicom encodes one: a response the SCP never asked for."""
    from pynetdicom.dimse_messages import C_ECHO_RSP
    from pynetdicom.dimse_primitives import C_ECHO
    from pynetdicom.pdu import P_DATA_TF

    response = C_ECHO()
    response.MessageIDBeingRespondedTo = 1
    response.AffectedSOPClassUID = "1.2.840.10008.1.1"
    response.Status = 0x0000
    message = C_ECHO_RSP()
    message.primitive_to_message(response)
    (primitive,) = message.encode_msg(1, 16384)
    pdu = P_DATA_TF()
    pdu.from_primitive(primitive)
    return pdu.encode()


def _c_store_command(
    *,
    message_id: int = 1,
    priority: int = 0x0000,
    data_set_type: int = 0x0000,
    instance_uid: bytes | None = b"1.2.826.0.1.3680043.2.1\x00",
) -> bytes:
    """A whole C-STORE-RQ command set, implicit VR little endian, that says a data set follows."""

    def element(tag: tuple[int, int], value: bytes) -> bytes:
        return struct.pack("<HHI", *tag, len(value)) + value

    rest = (
        element((0x0000, 0x0002), b"1.2.840.10008.5.1.4.1.1.88.11\x00")
        + element((0x0000, 0x0100), struct.pack("<H", 0x0001))
        + element((0x0000, 0x0110), struct.pack("<H", message_id))
        + element((0x0000, 0x0700), struct.pack("<H", priority))
        + element((0x0000, 0x0800), struct.pack("<H", data_set_type))
        + (b"" if instance_uid is None else element((0x0000, 0x1000), instance_uid))
    )
    return element((0x0000, 0x0000), struct.pack("<I", len(rest))) + rest


def _first_bytes(sock: socket.socket, count: int, *, wait: float = 3.0) -> bytes:
    """Up to ``count`` bytes the SCP sends next, or what arrived before it closed or ``wait`` ran out."""
    sock.settimeout(wait)
    received = b""
    with contextlib.suppress(OSError):
        while len(received) < count:
            chunk = sock.recv(count - len(received))
            if not chunk:
                break
            received += chunk
    return received


# --- A PDU longer than the SCP offered -------------------------------------------------------------


@pytest.mark.parametrize("declared", [16384 + 1, 0xFFFFFFFF], ids=["one-over", "4-gib"])
async def test_a_p_data_pdu_over_max_pdu_size_is_aborted_on_its_declared_length(
    declared: int, caplog: pytest.LogCaptureFixture
) -> None:
    # Before this, the SCP read the body the peer announced, into memory, for as long as the read
    # deadline allowed. Here no body follows the header at all, so an SCP that waits for one is
    # still waiting when this test looks, 25 seconds before its deadline.
    async with _running_scp({"timeout_seconds": 30.0, "max_pdu_size": 16384}) as scp:
        sock = await _a_held_association(scp.sockport)
        try:
            with caplog.at_level(logging.WARNING, logger=_LOG):
                sock.sendall(b"\x04\x00" + declared.to_bytes(4, "big"))
                answer = await asyncio.to_thread(_first_bytes, sock, len(_ABORT_PDU_TOO_LONG))
                assert answer == _ABORT_PDU_TOO_LONG, answer
                assert await asyncio.to_thread(_closed_within, sock, 3.0)
                await _until(lambda: scp._ended_log.refusals == 1)
                await _until(lambda: scp._server.active_associations == [])
        finally:
            sock.close()
    ended = [m for m in _warnings(caplog) if "ended an association with 127.0.0.1" in m]
    assert len(ended) == 1, _warnings(caplog)
    assert "over the 16384 bytes the SCP takes" in ended[0]
    assert str(declared) not in ended[0], "the line repeats a number the peer sent"
    assert scp._refusal_log.refusals == 0


async def test_another_pdu_over_the_request_cap_is_aborted_on_its_declared_length() -> None:
    # An A-RELEASE-RQ is four bytes long in PS3.8, so one that announces a MiB is not a release.
    async with _running_scp({"timeout_seconds": 30.0}) as scp:
        sock = await _a_held_association(scp.sockport)
        try:
            sock.sendall(b"\x05\x00" + (1024 * 1024).to_bytes(4, "big"))
            answer = await asyncio.to_thread(_first_bytes, sock, len(_ABORT_PDU_TOO_LONG))
            assert answer == _ABORT_PDU_TOO_LONG, answer
        finally:
            sock.close()


async def test_a_real_sender_at_exactly_max_pdu_size_is_served() -> None:
    # The CONTROL for the two above: pynetdicom fragments to exactly the max_pdu_size the SCP
    # offered, so the comparison must take a PDU of that length, and only one longer is refused.
    from pynetdicom import evt

    lengths: list[int] = []
    captured: list[bytes] = []
    settings: dict[str, object] = {"timeout_seconds": 30.0, "max_pdu_size": 4096}
    async with _running_scp(settings, captured=captured) as scp:
        scp._server.bind(
            evt.EVT_PDU_RECV,
            lambda event: lengths.append(event.pdu.pdu_length) if event.pdu.pdu_type == 4 else None,
        )
        data = _sr_of_at_least(5 * 4096)
        assert await asyncio.to_thread(_scu_cstore, scp.sockport, data) == (True, 0x0000)
    assert max(lengths) == 4096, lengths
    assert len(captured) == 1


@pytest.mark.parametrize("value", [0, -1, 6, 4095, 1024 * 1024 + 1, 0xFFFFFFFF])
def test_a_max_pdu_size_out_of_range_is_refused_at_build(value: int) -> None:
    # 0 offers no limit, 6 or less breaks a pynetdicom sender, which fragments to six bytes less,
    # and a larger size is read whole before any of it is counted.
    with pytest.raises(ValueError, match="max_pdu_size must be from 4096 to 1048576"):
        _build_scp([], max_pdu_size=value)
    for edge in (4096, 1024 * 1024):  # CONTROL
        assert _build_scp([], max_pdu_size=edge)._max_pdu_size == edge


# --- An object past twice the cap ------------------------------------------------------------------


async def test_an_object_past_twice_the_cap_ends_the_association_and_one_under_it_is_refused() -> (
    None
):
    # Owner ruling B462-R3: a final 0xC010 up to twice the cap, an A-ABORT past it. Before this
    # build every over-cap object got 0xC010, however large, after pynetdicom had held all of it.
    over = _sr_of_at_least(_CAP + 1)
    past = _sr_of_at_least(2 * _CAP + 1)
    assert _CAP < _data_set_bytes(over) <= 2 * _CAP, "CONTROL: the first object is over the cap"
    captured: list[bytes] = []
    settings: dict[str, object] = {"timeout_seconds": 30.0, "max_object_bytes": _CAP}
    async with _running_scp(settings, captured=captured) as scp:
        # Over the cap, under twice it: refused, final, and the association carries on.
        statuses, aborted = await asyncio.to_thread(_store_each, scp.sockport, [over, over])
        assert statuses == [_C_STORE_REFUSED_OVER_CAP] * 2 and not aborted
        # Past twice the cap: no status, and the association is ended.
        statuses, aborted = await asyncio.to_thread(_store_each, scp.sockport, [past, over])
        assert statuses == [None, None] and aborted, statuses
        await _until(lambda: scp._ended_log.refusals == 1)
        await _until(lambda: scp._server.active_associations == [])
        # The listener goes on serving.
        small = make_sr_part10()
        assert await asyncio.to_thread(_scu_cstore, scp.sockport, small) == (True, 0x0000)
    assert len(captured) == 1


async def test_a_run_of_objects_under_the_cap_is_never_counted_together() -> None:
    # The count starts again at each object's last fragment, so a long association of objects each
    # under the cap is served whatever their total. These five come to more than twice the cap.
    under = _sr_of_at_least(_CAP // 2)
    assert _data_set_bytes(under) <= _CAP
    captured: list[bytes] = []
    settings: dict[str, object] = {"timeout_seconds": 30.0, "max_object_bytes": _CAP}
    async with _running_scp(settings, captured=captured) as scp:
        statuses, aborted = await asyncio.to_thread(_store_each, scp.sockport, [under] * 5)
    assert 5 * _data_set_bytes(under) > 2 * _CAP
    assert statuses == [0x0000] * 5 and not aborted
    assert len(captured) == 5


async def test_a_run_of_echoes_is_never_counted_together(monkeypatch: pytest.MonkeyPatch) -> None:
    # A command with no data set completes its message at its own last fragment, as pynetdicom
    # takes it, so the command-set count starts again there too.
    from pynetdicom import AE
    from pynetdicom.sop_class import Verification  # type: ignore[attr-defined]

    monkeypatch.setattr(dicom_module, "_MAX_COMMAND_SET_BYTES", 1024)
    async with _running_scp({"timeout_seconds": 30.0}) as scp:

        def echo_forty() -> list[int]:
            ae = AE(ae_title="MODALITY1")
            ae.add_requested_context(Verification)
            assoc = ae.associate("127.0.0.1", scp.sockport, ae_title=_SCP_AE)
            try:
                return [int(assoc.send_c_echo().Status) for _ in range(40)]
            finally:
                assoc.release()

        assert await asyncio.to_thread(echo_forty) == [0x0000] * 40
    # The command set alone, without the PDU and item headers, is what the count adds up.
    command_set = len(_c_echo_rq(1)) - 12
    assert command_set < 1024 < 40 * command_set


async def test_data_fragments_after_a_command_are_counted_past_twice_the_cap() -> None:
    # The raw form of the object test above: a command that says a data set follows, then data
    # fragments with no last one. pynetdicom would hold them all until a last fragment came.
    fragment = b"\x00" * 3000
    async with _running_scp({"timeout_seconds": 30.0, "max_object_bytes": _CAP}) as scp:
        sock = await _a_held_association(scp.sockport)
        try:
            sock.sendall(_p_data(0x03, _c_store_command()))
            for _ in range(3):
                sock.sendall(_p_data(0x00, fragment))
            answer = await asyncio.to_thread(_first_bytes, sock, len(_ABORT_OVER_LIMIT))
            assert answer == _ABORT_OVER_LIMIT, answer
        finally:
            sock.close()
    assert 3 * len(fragment) > 2 * _CAP


#: P-DATA-TF bodies pynetdicom would fail on, each after the message so far. A second command set
#: in one message is the one that matters most: pynetdicom goes on adding to the same message, so a
#: count that started again there would let a peer grow that message without end.
_INVALID_MESSAGES = {
    "second-command": _p_data(0x03, _c_store_command()) + _p_data(0x03, _c_store_command()),
    "data-before-command": _p_data(0x00, b"\x00" * 16),
    "command-does-not-decode": _p_data(0x03, b"\xff" * 7),
    "item-with-no-control-byte": b"\x04\x00" + (5).to_bytes(4, "big") + b"\x00\x00\x00\x01\x01",
    "item-longer-than-the-pdu": b"\x04\x00" + (6).to_bytes(4, "big") + b"\x00\x00\x00\x09\x01\x03",
    "more-after-the-last": (
        b"\x04\x00"
        + (2 * (len(_c_echo_rq(1)) - 6)).to_bytes(4, "big")
        + _c_echo_rq(1)[6:]
        + _c_echo_rq(2)[6:]
    ),
    "a-command-the-scp-does-not-serve": _c_echo_rsp(),
    "a-value-pynetdicom-refuses": _p_data(0x03, _c_store_command(priority=5))
    + _p_data(0x02, b"\x00" * 16),
    "a-pdu-type-ps3-8-does-not-define": b"\x09\x00" + (4).to_bytes(4, "big") + bytes(4),
    # pynetdicom answers such a request with nothing and a WARNING, and keeps the association, so a
    # peer could stream them as fast as it can send: three in a row here.
    "a-stream-of-requests-that-lack-a-field": _p_data(
        0x03, _c_store_command(data_set_type=0x0101, instance_uid=None)
    )
    * 3,
}


@pytest.mark.filterwarnings("error::pytest.PytestUnhandledThreadExceptionWarning")
@pytest.mark.parametrize("sends", list(_INVALID_MESSAGES.values()), ids=list(_INVALID_MESSAGES))
async def test_a_message_pynetdicom_would_fail_on_ends_the_association_quietly(
    sends: bytes, caplog: pytest.LogCaptureFixture
) -> None:
    # Before, each of these reached pynetdicom: it logged an ERROR with a traceback, lost its DUL
    # thread to an uncaught exception, or went on adding to a message whose count here had started
    # again. A peer could repeat any of them once per association.
    async with _running_scp({"timeout_seconds": 30.0}) as scp:
        baseline = await _thread_baseline()
        sock = await _a_held_association(scp.sockport)
        try:
            # WARNING: pynetdicom's 'Received unexpected ... service message' line is one.
            with caplog.at_level(logging.WARNING):
                sock.sendall(sends)
                answer = await asyncio.to_thread(_first_bytes, sock, len(_ABORT_INVALID))
                assert answer == _ABORT_INVALID, answer
                await _until(lambda: len(_threads_outside_the_test()) <= baseline)
        finally:
            sock.close()
    # The capture saw the SCP's own line for this end, so the two empty lists below are read from a
    # capture that works, not from one that caught nothing.
    assert caplog.records
    assert any("ended an association" in r.getMessage() for r in caplog.records), caplog.text
    tracebacks = [r for r in caplog.records if r.exc_info and r.name.startswith("pynetdicom")]
    assert tracebacks == [], [r.getMessage() for r in tracebacks]
    unthrottled = [
        r.getMessage()
        for r in caplog.records
        if r.name.startswith("pynetdicom")
        and any(s in r.getMessage() for s in ("Unknown PDU", "invalid DIMSE", "unexpected"))
    ]
    assert unthrottled == []


async def test_chunked_receipt_turned_on_mid_association_ends_it(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The flag is process-wide and pynetdicom reads it at each command, so the check at start and
    # at each connection does not cover an association already open.
    from pynetdicom import _config

    async with _running_scp({"timeout_seconds": 30.0}) as scp:
        sock = await _a_held_association(scp.sockport)
        try:
            monkeypatch.setattr(_config, "STORE_RECV_CHUNKED_DATASET", True)
            sock.sendall(_p_data(0x03, _c_store_command()))
            answer = await asyncio.to_thread(_first_bytes, sock, len(_ABORT_OVER_LIMIT))
            assert answer == _ABORT_OVER_LIMIT, answer
        finally:
            sock.close()


async def test_a_peer_that_does_not_wait_for_its_statuses_is_held_back() -> None:
    # pynetdicom's queue of whole messages has no bound, and the Association thread serves one at a
    # time. While the first commit is held, a peer sending objects back to back used to have every
    # one read and queued; now the DUL stops reading while one waits.
    from pydicom import dcmread
    from pynetdicom import AE
    from pynetdicom.dimse_primitives import C_STORE
    from pynetdicom.dsutils import encode

    release = asyncio.Event()
    captured: list[bytes] = []

    async def held(data: bytes) -> str | None:
        captured.append(data)
        await release.wait()
        return f"mid-{len(captured)}"

    scp = _build_scp(captured, timeout_seconds=30.0)
    await scp.start(held)
    opened: list[Any] = []
    try:
        ds = dcmread(BytesIO(make_sr_part10()))
        ae = AE(ae_title="MODALITY1")
        ae.add_requested_context(ds.SOPClassUID, ds.file_meta.TransferSyntaxUID)
        assoc = await asyncio.to_thread(ae.associate, "127.0.0.1", scp.sockport, ae_title=_SCP_AE)
        opened.append(assoc)
        assert assoc.is_established
        context = assoc.accepted_contexts[0]
        context_id = context.context_id
        assert context_id is not None
        data_set = encode(ds, context.transfer_syntax[0].is_implicit_VR, True)
        assert data_set is not None
        for message_id in range(1, 6):
            request = C_STORE()
            request.MessageID = message_id
            request.AffectedSOPClassUID = ds.SOPClassUID
            request.AffectedSOPInstanceUID = ds.SOPInstanceUID
            request.Priority = 0x0002
            request.DataSet = BytesIO(data_set)
            assoc.dimse.send_msg(request, context_id)
        await _until(lambda: len(captured) == 1)
        await _until(lambda: len(scp._server.active_associations) == 1)
        queue = scp._server.active_associations[0].dimse.msg_queue
        await asyncio.sleep(1.0)  # time for the DUL to read everything the peer sent, were it to
        assert queue.qsize() <= 1, f"{queue.qsize()} whole messages waiting behind the first"
        release.set()
        await _until(lambda: len(captured) == 5)
        await asyncio.to_thread(assoc.release)
    finally:
        release.set()
        for assoc in opened:
            if assoc.is_established:  # a failure above: do not leave its threads to later tests
                await asyncio.to_thread(assoc.abort)
        await scp.stop()


async def test_a_command_set_past_its_bound_ends_the_association() -> None:
    limit = dicom_module._MAX_COMMAND_SET_BYTES
    async with _running_scp({"timeout_seconds": 30.0}) as scp:
        sock = await _a_held_association(scp.sockport)
        try:
            piece = b"\x00" * 8000
            for _ in range(limit // len(piece) + 1):
                sock.sendall(_p_data(0x01, piece))
            answer = await asyncio.to_thread(_first_bytes, sock, len(_ABORT_OVER_LIMIT))
            assert answer == _ABORT_OVER_LIMIT, answer
        finally:
            sock.close()


def test_a_request_with_every_field_it_needs_gets_past_the_tally() -> None:
    # The CONTROL for the stream of requests that lack a field: the same command set with its
    # instance UID is a request pynetdicom would serve, and the tally lets it through.
    whole = dicom_module._ReceiptTally(max_data_set_bytes=1000)
    command = _c_store_command(data_set_type=0x0101)
    assert whole.take(_p_data(0x03, command)[6:]) is None
    lacking = dicom_module._ReceiptTally(max_data_set_bytes=1000)
    command = _c_store_command(data_set_type=0x0101, instance_uid=None)
    assert lacking.take(_p_data(0x03, command)[6:]) == (
        dicom_module._ABORT_INVALID_MESSAGE,
        "a request that lacks a field it must carry",
    )


def test_the_tally_splits_items_as_pynetdicom_does() -> None:
    """``_ReceiptTally`` counts what ``P_DATA_TF`` decodes and ``decode_msg`` holds of the same
    bytes: every fragment but its control byte, in every item of the PDU."""
    from pynetdicom.pdu import P_DATA_TF

    tally = dicom_module._ReceiptTally(max_data_set_bytes=1000)
    assert tally.take(_p_data(0x03, _c_store_command())[6:]) is None  # a data set follows
    body = (
        struct.pack(">IBB", 12, 1, 0x00)
        + b"a" * 10
        + struct.pack(">IBB", 6, 1, 0x00)
        + b"b" * 4
        + struct.pack(">IBB", 3, 1, 0x00)
        + b"c"
    )
    pdu = P_DATA_TF()
    pdu.decode(b"\x04\x00" + len(body).to_bytes(4, "big") + body)
    held = 0
    for item in pdu.presentation_data_value_items:
        value = item.presentation_data_value
        assert value is not None
        held += len(value) - 1  # decode_msg holds all but the control byte
    assert tally.take(body) is None
    assert tally.data_set_bytes == held == 15
    tally.take(struct.pack(">IBB", 3, 1, 0x02) + b"d")  # the last fragment
    assert tally.data_set_bytes == 0


# --- Sends -----------------------------------------------------------------------------------------


class _SlowReaderSocket:
    """A connected socket's sending side, as it looks when the peer reads a little at a time: each
    send call waits ``gap`` seconds and then takes one byte. A real one does this on Linux, where a
    send to a nearly full buffer returns part of what it was given. Windows loopback takes a whole
    send once there is any room, so a real socket cannot show this there."""

    def __init__(self, gap: float) -> None:
        self.gap = gap
        self.timeout: float | None = None
        self.taken = 0

    def gettimeout(self) -> float | None:
        return self.timeout

    def settimeout(self, value: float | None) -> None:
        self.timeout = value

    def send(self, data: memoryview) -> int:
        time.sleep(self.gap)
        self.taken += 1
        return 1


async def test_a_send_to_a_slow_reader_is_bounded_as_a_whole(
    caplog: pytest.LogCaptureFixture,
) -> None:
    # A timeout per call restarts each time the peer takes a little, so a reader that keeps taking a
    # little held the DUL thread, and a stop, for as long as it liked: limb 1 bounded only each
    # call. 1000 bytes here would take 50 s that way. The bound is now on the whole send.
    async with _running_scp({"timeout_seconds": 1.0}) as scp:
        peer = _SlowReaderSocket(gap=0.05)
        started = time.monotonic()
        with caplog.at_level(logging.WARNING, logger=_LOG):
            sent = await asyncio.to_thread(
                scp._server.send_for_association, peer, b"\x00" * 1000, "127.0.0.1"
            )
        took = time.monotonic() - started
        assert sent is False
        assert took < 3.0, f"the send ran {took:.1f}s against a 1s bound"
        assert 0 < peer.taken < 1000
        assert peer.timeout is None, "the socket's own timeout was not restored"
    assert any("a send did not finish within 1s" in m for m in _warnings(caplog)), _warnings(caplog)


async def test_stop_does_not_wait_out_a_send_the_peer_never_reads() -> None:
    # Limb 1 bounded each send by timeout_seconds but never looked at the stop, so a stop waited for
    # a DUL blocked here for up to that long. 30 s is the shipped default.
    request = await asyncio.to_thread(_a_real_association_request)
    async with _running_scp({"timeout_seconds": 30.0, "max_associations": 2}) as scp:
        baseline = await _thread_baseline()
        sock = socket.socket()
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
        sock.settimeout(5.0)
        sock.connect(("127.0.0.1", scp.sockport))
        try:
            sock.sendall(request)
            assert await asyncio.to_thread(sock.recv, 1) == b"\x02"

            def flood() -> None:
                pending = memoryview(b"".join(_c_echo_rq(n) for n in range(1, 40000)))
                sock.settimeout(1.0)
                with contextlib.suppress(OSError):
                    while pending:
                        pending = pending[sock.send(pending[:65536]) :]

            await asyncio.to_thread(flood)
            started = time.monotonic()
            await scp.stop()
            took = time.monotonic() - started
            assert took < 5.0, f"stop() took {took:.1f}s"
            await _until(lambda: len(_threads_outside_the_test()) < baseline)
        finally:
            sock.close()


# --- The association request ------------------------------------------------------------------------


async def test_a_requestor_that_also_offers_other_protocol_versions_is_accepted() -> None:
    # PS3.8 section 9.3.2: a receiver that implements only version 1 tests only bit 0.
    request = await asyncio.to_thread(_a_real_association_request)
    more_versions = request[:6] + b"\x00\x03" + request[8:]
    async with _running_scp({"timeout_seconds": 30.0}) as scp:
        sock = _stall(scp.sockport, more_versions)
        try:
            sock.settimeout(3.0)
            assert await asyncio.to_thread(sock.recv, 1) == b"\x02", "no A-ASSOCIATE-AC"
        finally:
            sock.close()
        # CONTROL: bit 0 clear is still refused, rejected-permanent, version not supported.
        sock = _stall(scp.sockport, request[:6] + b"\x00\x02" + request[8:])
        try:
            sock.settimeout(3.0)
            assert await asyncio.to_thread(sock.recv, 64) == _rj(0x01, 0x02, 0x02)
        finally:
            sock.close()


@pytest.mark.parametrize("seconds", [0.001, 0.5, 0.999])
def test_a_timeout_under_the_floor_is_refused_at_build(seconds: float) -> None:
    with pytest.raises(ValueError, match="timeout_seconds must be at least 1 second"):
        _build_scp([], timeout_seconds=seconds)
    assert _build_scp([], timeout_seconds=1.0)._timeout == 1.0  # CONTROL


# --- The pins ----------------------------------------------------------------------------------------


def test_the_doc_states_the_receipt_bounds() -> None:
    doc = (Path(__file__).resolve().parents[1] / "docs" / "DICOM.md").read_text(encoding="utf-8")
    assert "twice the effective `max_object_bytes`" in doc
    assert f"{dicom_module._MAX_COMMAND_SET_BYTES // 1024} KiB" in doc
    assert f"at least {dicom_module._MIN_TIMEOUT_SECONDS:g} second" in doc
    assert "`STORE_RECV_CHUNKED_DATASET`" in doc


async def test_the_scp_refuses_to_run_with_chunked_receipt_on(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # pynetdicom's STORE_RECV_CHUNKED_DATASET writes each received object to a temporary file in
    # plaintext, outside the store and its encryption. It is process-wide, so anything in the
    # process could set it: the SCP will not start with it set, and refuses each connection while
    # it is set.
    from pynetdicom import _config

    assert _config.STORE_RECV_CHUNKED_DATASET is False  # CONTROL: the shipped default
    with monkeypatch.context() as patched:
        patched.setattr(_config, "STORE_RECV_CHUNKED_DATASET", True)
        scp = _build_scp([])
        with pytest.raises(RuntimeError, match="STORE_RECV_CHUNKED_DATASET is set"):
            await scp.start(_never_called)
    async with _running_scp({"timeout_seconds": 30.0}) as scp:
        monkeypatch.setattr(_config, "STORE_RECV_CHUNKED_DATASET", True)
        assert await asyncio.to_thread(_scu_cstore, scp.sockport, make_sr_part10()) == (False, None)
        await _until(lambda: scp._refusal_log.refusals == 1)


async def _never_called(data: bytes) -> str | None:
    raise AssertionError("no object should reach the handler")


def test_the_pynetdicom_seams_the_receipt_bounds_rely_on_are_still_there() -> None:
    """What ``_AdmittedSocket._read_pdu`` and ``_ReceiptTally`` assume about pynetdicom. Read
    against 3.0.4; the ``[dicom]`` comment in ``pyproject.toml`` says to re-read these before moving
    the pin."""
    import inspect

    from pynetdicom import evt
    from pynetdicom.dimse_messages import DIMSEMessage
    from pynetdicom.dul import DULServiceProvider
    from pynetdicom.pdu import P_DATA_TF
    from pynetdicom.transport import AssociationSocket

    reader = inspect.getsource(DULServiceProvider._read_pdu_data)
    # The header is read alone, then the body; an unknown type is answered with its body unread.
    assert reader.index("recv(6)") < reader.index(
        "not in (0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07)"
    )
    assert reader.index("not in (0x01") < reader.index("recv(pdu_length)")
    # A short header read is a closed connection with no log line: the ERROR call is commented out.
    short = reader[reader.index("except struct.error") : reader.index("# If the `pdu_type`")]
    assert '"Evt17"' in short and "\n            LOGGER" not in short
    # The items are split, and each fragment held, as _ReceiptTally counts them.
    items = inspect.getsource(P_DATA_TF._generate_items)
    assert "bytestream[offset + 5 : offset + 4 + item_length]" in items
    assert "offset += 4 + item_length" in items
    decode = inspect.getsource(DIMSEMessage.decode_msg)
    assert "if control_header_byte & 1:" in decode
    assert "self.encoded_command_set.write(data[1:])" in decode
    assert "decode(self.encoded_command_set, True, True)" in decode
    assert "CommandDataSetType == 0x0101" in decode
    assert decode.index("_MESSAGE_TYPES[") < decode.index("CommandDataSetType == 0x0101")
    # ready holds off while a whole message waits: DT-2 decodes on the DUL thread and queues it.
    from pynetdicom.association import Association
    from pynetdicom.dimse import DIMSEServiceProvider
    from pynetdicom.fsm import DT_2

    assert "dimse.receive_primitive" in inspect.getsource(DT_2)
    receive = inspect.getsource(DIMSEServiceProvider.receive_primitive)
    assert "self.msg_queue.put(" in receive and "message_to_primitive()" in receive
    from pynetdicom.dimse_messages import _MESSAGE_TYPES

    assert _MESSAGE_TYPES[0x0001][0] == "C-STORE-RQ" and _MESSAGE_TYPES[0x0030][0] == "C-ECHO-RQ"
    assert "self.dimse.get_msg(block=False)" in inspect.getsource(Association._run_reactor)
    # A request that is not valid is answered with nothing, which is why the tally ends it.
    serve = inspect.getsource(Association._serve_request)
    assert "if not msg.is_valid_request:" in serve
    assert "cast(BytesIO, self.data_set).write(data[1:])" in decode
    assert "if control_header_byte & 2 != 0:" in decode
    # The replaced send does what the stock one does on success and on failure.
    stock_send = inspect.getsource(AssociationSocket.send)
    assert "evt.EVT_DATA_SENT" in stock_send and '"Evt17"' in stock_send
    assert evt.EVT_DATA_SENT.is_notification
    assert isinstance(vars(AssociationSocket)["event_queue"], property)
