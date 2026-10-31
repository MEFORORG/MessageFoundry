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
#: The A-ABORT an object past twice the cap gets: service user, no reason.
_ABORT_OBJECT_TOO_LARGE = b"\x07\x00" + (4).to_bytes(4, "big") + bytes(4)

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


def _c_store_command(*, message_id: int = 1) -> bytes:
    """A whole C-STORE-RQ command set, implicit VR little endian, that says a data set follows."""

    def element(tag: tuple[int, int], value: bytes) -> bytes:
        return struct.pack("<HHI", *tag, len(value)) + value

    rest = (
        element((0x0000, 0x0002), b"1.2.840.10008.5.1.4.1.1.88.11\x00")
        + element((0x0000, 0x0100), struct.pack("<H", 0x0001))
        + element((0x0000, 0x0110), struct.pack("<H", message_id))
        + element((0x0000, 0x0700), struct.pack("<H", 0x0000))
        + element((0x0000, 0x0800), struct.pack("<H", 0x0000))
        + element((0x0000, 0x1000), b"1.2.826.0.1.3680043.2.1\x00")
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


@pytest.mark.parametrize("value", [0, -1])
def test_a_max_pdu_size_that_offers_no_limit_is_refused_at_build(value: int) -> None:
    with pytest.raises(ValueError, match="max_pdu_size must be above zero"):
        _build_scp([], max_pdu_size=value)
    assert _build_scp([], max_pdu_size=1)._max_pdu_size == 1  # CONTROL


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
    assert 40 * len(_c_echo_rq(1)) > 1024


async def test_a_command_that_says_a_data_set_follows_does_not_start_the_count_again() -> None:
    # pynetdicom goes on adding to the same message after such a command's last fragment, so a peer
    # that slips one in between data fragments must not reset what the SCP counts.
    command = _c_store_command()
    fragment = b"\x00" * 3000
    async with _running_scp({"timeout_seconds": 30.0, "max_object_bytes": _CAP}) as scp:
        sock = await _a_held_association(scp.sockport)
        try:
            sock.sendall(_p_data(0x03, command))
            for _ in range(3):
                sock.sendall(_p_data(0x00, fragment) + _p_data(0x03, command))
            answer = await asyncio.to_thread(_first_bytes, sock, len(_ABORT_OBJECT_TOO_LARGE))
            assert answer == _ABORT_OBJECT_TOO_LARGE, answer
        finally:
            sock.close()
    assert 3 * len(fragment) > 2 * _CAP


async def test_a_command_set_past_its_bound_ends_the_association() -> None:
    limit = dicom_module._MAX_COMMAND_SET_BYTES
    async with _running_scp({"timeout_seconds": 30.0}) as scp:
        sock = await _a_held_association(scp.sockport)
        try:
            piece = b"\x00" * 8000
            for _ in range(limit // len(piece) + 1):
                sock.sendall(_p_data(0x01, piece))
            answer = await asyncio.to_thread(_first_bytes, sock, len(_ABORT_OBJECT_TOO_LARGE))
            assert answer == _ABORT_OBJECT_TOO_LARGE, answer
        finally:
            sock.close()


def test_the_tally_splits_items_as_pynetdicom_does() -> None:
    """``_ReceiptTally`` counts what ``P_DATA_TF`` decodes and ``decode_msg`` holds of the same
    bytes: every fragment but its control byte, in every item of the PDU."""
    from pynetdicom.pdu import P_DATA_TF

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
    tally = dicom_module._ReceiptTally(max_data_set_bytes=1000)
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


def test_the_scp_never_turns_on_chunked_receipt() -> None:
    # pynetdicom's STORE_RECV_CHUNKED_DATASET writes each received object to a temporary file in
    # plaintext, outside the store and its encryption. The SCP must never set it.
    source = Path(dicom_module.__file__).read_text(encoding="utf-8")
    assert "STORE_RECV_CHUNKED_DATASET =" not in source
    from pynetdicom import _config

    assert _config.STORE_RECV_CHUNKED_DATASET is False


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
    assert "cast(BytesIO, self.data_set).write(data[1:])" in decode
    assert "if control_header_byte & 2 != 0:" in decode
    # The replaced send does what the stock one does on success and on failure.
    stock_send = inspect.getsource(AssociationSocket.send)
    assert "evt.EVT_DATA_SENT" in stock_send and '"Evt17"' in stock_send
    assert evt.EVT_DATA_SENT.is_notification
    assert isinstance(vars(AssociationSocket)["event_queue"], property)
