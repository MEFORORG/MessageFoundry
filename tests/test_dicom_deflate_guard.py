# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #1926: the Part-10 deflate guard must bound exactly the bytes pydicom inflates.

``guard_part10_deflate`` used to find the deflated Data Set by its own walk of the file-meta group. On
a header its walk could not follow, it returned early, and early meant "passed". pydicom reads the same
header more leniently, so it went on to inflate the whole body with no bound. Each shape below is one
way the two readings disagreed. Every one of them is a header pydicom 3.0.2 accepts.

All objects here are synthetic and PHI-free (runs of NUL bytes and fabricated names). The cap is
lowered for the test, so no test inflates more than 1 MiB.
"""

from __future__ import annotations

import random
import zlib
from collections.abc import Callable
from types import SimpleNamespace
from typing import Any

import pytest

pytest.importorskip("pydicom", reason="DICOM deflate-guard tests need the [dicom] extra")

from messagefoundry.parsing.dicom import (  # noqa: E402
    DicomBombError,
    DicomDataset,
    DicomPeek,
    DicomPeekError,
    _inflate,
)
from tests._dicom_sample import (  # noqa: E402
    make_deflated_bomb_part10,
    make_deflated_ok_part10,
    make_sr_part10,
)

#: The lowered cap. The bomb inflates to 16x this, so a guard that bounds the right bytes refuses it,
#: and one that stands aside lets pydicom inflate a whole MiB.
_CAP = 64 * 1024
_BOMB_INFLATED = 1024 * 1024

_META_START = 132  # after the 128-byte preamble and b"DICM"
_GROUP_LENGTH_VALUE = _META_START + 8  # (0002,0000) UL: tag 4 + VR 2 + length 2, then the value
_GROUP_LENGTH_END = _GROUP_LENGTH_VALUE + 4


def _with_group_length(obj: bytes, new_length: Callable[[int], int | None]) -> bytes:
    """Rewrite the (0002,0000) group length of a well-formed Part-10 object to
    ``new_length(declared)``, or drop the element when that returns ``None``."""
    declared = int.from_bytes(obj[_GROUP_LENGTH_VALUE:_GROUP_LENGTH_END], "little")
    value = new_length(declared)
    element = (
        b"" if value is None else obj[_META_START:_GROUP_LENGTH_VALUE] + value.to_bytes(4, "little")
    )
    return obj[:_META_START] + element + obj[_GROUP_LENGTH_END:]


def _decoy_transfer_syntax(obj: bytes) -> bytes:
    # A first (0002,0010) naming plain Explicit VR LE. The old walk stopped at the first one it met;
    # pydicom keeps the last, which is the deflated one.
    uid = b"1.2.840.10008.1.2.1\x00"
    decoy = b"\x02\x00\x10\x00UI" + len(uid).to_bytes(2, "little") + uid
    obj = _with_group_length(obj, lambda n: n + len(decoy))
    return obj[:_GROUP_LENGTH_END] + decoy + obj[_GROUP_LENGTH_END:]


def _command_set_before_body(obj: bytes) -> bytes:
    # An Implicit VR (0000,0100) element between the meta and the deflated body. pydicom reads group
    # 0000 as a command set and starts the inflate after it, so the old offset was 10 bytes early.
    meta_end = _GROUP_LENGTH_END + int.from_bytes(
        obj[_GROUP_LENGTH_VALUE:_GROUP_LENGTH_END], "little"
    )
    command = b"\x00\x00\x00\x01" + (2).to_bytes(4, "little") + b"\x01\x00"
    return obj[:meta_end] + command + obj[meta_end:]


# (mutation, force). ``force`` is the dcmread flag the object needs to be read at all.
_SHAPES = [
    pytest.param(lambda o: _with_group_length(o, lambda n: None), False, id="missing-group-length"),
    pytest.param(lambda o: _with_group_length(o, lambda n: 10), False, id="short-group-length"),
    pytest.param(lambda o: _with_group_length(o, lambda n: n + 1), False, id="group-length-plus-1"),
    pytest.param(
        lambda o: _with_group_length(o, lambda n: n - 4), False, id="group-length-minus-4"
    ),
    pytest.param(
        lambda o: _with_group_length(o, lambda n: 0xFFFFFFFF), False, id="group-length-0xFFFFFFFF"
    ),
    pytest.param(_decoy_transfer_syntax, False, id="decoy-transfer-syntax"),
    # The file meta with no preamble and no DICM magic. pydicom reads it under force=True.
    pytest.param(lambda o: o[_META_START:], True, id="force-without-preamble"),
    pytest.param(_command_set_before_body, False, id="command-set-before-body"),
]
_UNFORCED = [pytest.param(shape.values[0], id=shape.id) for shape in _SHAPES if not shape.values[1]]


def _bomb() -> bytes:
    return make_deflated_bomb_part10(inflated_bytes=_BOMB_INFLATED)


@pytest.fixture
def low_cap(monkeypatch: pytest.MonkeyPatch) -> None:
    """Lower the codec default cap that DicomPeek.parse and DicomDataset.parse fall back to."""
    monkeypatch.setattr(_inflate, "DEFAULT_MAX_INFLATED_BYTES", _CAP)


def test_the_unmutated_bomb_is_refused_at_the_lowered_cap(low_cap: None) -> None:
    # Positive control: the lowered cap and the bomb are armed, so a refusal below is the guard's.
    with pytest.raises(DicomBombError):
        DicomDataset.parse(_bomb())


@pytest.mark.parametrize(("mutate", "force"), _SHAPES)
def test_dataset_parse_refuses_a_bomb_behind_a_malformed_meta(
    low_cap: None, mutate: Callable[[bytes], bytes], force: bool
) -> None:
    with pytest.raises(DicomBombError):
        DicomDataset.parse(mutate(_bomb()), force=force)


@pytest.mark.parametrize("mutate", _UNFORCED)
def test_peek_refuses_a_bomb_behind_a_malformed_meta(
    low_cap: None, mutate: Callable[[bytes], bytes]
) -> None:
    with pytest.raises(DicomBombError):
        DicomPeek.parse(mutate(_bomb()))


def test_peek_without_force_still_reports_a_missing_preamble_as_unparseable(low_cap: None) -> None:
    # DicomPeek never forces, so pydicom refuses the object before any inflate. The guard leaves that
    # to dcmread, whose error the codec already turns into a DicomPeekError.
    with pytest.raises(DicomPeekError):
        DicomPeek.parse(_bomb()[_META_START:])


async def _scu_send(data: bytes) -> None:
    """Send ``data`` through an outbound SCU capped at :data:`_CAP`. Every case here is refused before
    any association, so no peer is needed and port 9 is never dialled."""
    pytest.importorskip("pynetdicom", reason="the DICOM SCU needs the [dicom] extra")
    from messagefoundry.config.models import ConnectorType, Destination
    from messagefoundry.parsing import RawMessage
    from messagefoundry.transports.dicom import DicomScuDestination

    settings: dict[str, object] = {
        "ae_title": "MEFOR_SCU",
        "host": "127.0.0.1",
        "port": 9,
        "called_ae_title": "PACS_SCP",
        "max_object_bytes": _CAP,
    }
    scu = DicomScuDestination(
        Destination(name="OB_SCU", type=ConnectorType.DIMSE, settings=settings)
    )
    await scu.send(RawMessage.from_bytes(data, "dicom").encode())


@pytest.mark.parametrize("mutate", _UNFORCED)
async def test_scu_refuses_a_bomb_behind_a_malformed_meta(mutate: Callable[[bytes], bytes]) -> None:
    # The outbound SCU calls the same guard with its own max_object_bytes.
    from messagefoundry.transports.base import NegativeAckError

    data = mutate(_bomb())
    assert len(data) < _CAP  # the raw object passes max_object_bytes; only its inflate is over
    with pytest.raises(NegativeAckError) as exc:
        await _scu_send(data)
    assert exc.value.code == "deflate-bomb"
    assert exc.value.permanent is True


async def test_scu_still_dead_letters_a_header_pydicom_rejects_outside_the_parse_errors() -> None:
    # An unknown VR on (0002,0010) makes pydicom raise NotImplementedError, which is not one of the
    # codec's parse-error types. The guard now meets it before dcmread does, and the SCU must still
    # record it as a permanent bad-object, never let it escape as an internal error.
    from messagefoundry.transports.base import NegativeAckError

    obj = make_sr_part10()
    at = obj.index(b"\x02\x00\x10\x00UI")
    data = obj[: at + 4] + b"U " + obj[at + 6 :]
    with pytest.raises(NegativeAckError) as exc:
        await _scu_send(data)
    assert exc.value.code == "bad-object"
    assert exc.value.permanent is True


@pytest.mark.parametrize(("mutate", "force"), _SHAPES)
def test_guard_bounds_exactly_the_bytes_pydicom_inflates(
    monkeypatch: pytest.MonkeyPatch, mutate: Callable[[bytes], bytes], force: bool
) -> None:
    """The invariant behind the fix: the stream the guard bounds IS the stream pydicom decompresses.

    Uses a small, valid deflated object, so it also proves the guard does not over-refuse: every shape
    pydicom tolerates still parses. If a pydicom upgrade moves where it starts the inflate, this fails
    before a bomb can get through."""
    guarded: list[bytes] = []
    inflated: list[bytes] = []
    real_bound = _inflate.bounded_inflate_or_error

    def record_bound(stream: bytes | memoryview, *, max_bytes: int) -> None:
        guarded.append(bytes(stream))
        real_bound(stream, max_bytes=max_bytes)

    def record_decompress(data: bytes, *args: Any) -> bytes:
        inflated.append(data)
        return zlib.decompress(data, *args)

    import pydicom.filereader

    monkeypatch.setattr(_inflate, "bounded_inflate_or_error", record_bound)
    monkeypatch.setattr(
        pydicom.filereader,
        "zlib",
        SimpleNamespace(decompress=record_decompress, MAX_WBITS=zlib.MAX_WBITS),
    )

    data = mutate(make_deflated_ok_part10(patient_name="Guard^Agreement"))
    parsed = DicomDataset.parse(data, force=force)

    assert parsed.patient_name == "Guard^Agreement"
    assert len(inflated) == 1
    assert guarded == inflated


def test_guard_is_a_no_op_for_a_non_deflated_object() -> None:
    _inflate.guard_part10_deflate(make_sr_part10(), force=False, max_bytes=1)


def test_guard_leaves_an_unreadable_header_to_dcmread() -> None:
    # pydicom runs the same header reader first and fails there, before its inflate, so the guard
    # stands aside and the codec records dcmread's own parse error.
    _inflate.guard_part10_deflate(b"not a DICOM object", force=False, max_bytes=1)
    with pytest.raises(DicomPeekError):
        DicomPeek.parse(b"not a DICOM object")


def test_guard_refuses_when_pydicom_no_longer_has_a_header_reader(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Two of the readers are private pydicom functions. If an upgrade drops one, the guard must refuse
    # every object rather than stand aside, because dcmread would still run and inflate unbounded.
    import pydicom.filereader

    monkeypatch.delattr(pydicom.filereader, "_read_file_meta_info")
    with pytest.raises(RuntimeError, match="_read_file_meta_info"):
        _inflate.guard_part10_deflate(make_deflated_ok_part10(), force=False, max_bytes=_CAP)


def test_bound_counts_a_stream_that_spans_many_input_windows() -> None:
    # Stored (level 0) blocks do not compress, so this stream is many input windows long. The bound
    # feeds it one window at a time, stops at the end of the stream, and ignores bytes after it.
    payload = random.Random(1926).randbytes(8 * _CAP)
    compressor = zlib.compressobj(0, zlib.DEFLATED, -zlib.MAX_WBITS)
    stream = compressor.compress(payload) + compressor.flush() + b"trailing bytes after the stream"
    assert len(stream) > 8 * _CAP

    _inflate.bounded_inflate_or_error(stream, max_bytes=len(payload))
    with pytest.raises(DicomBombError):
        _inflate.bounded_inflate_or_error(stream, max_bytes=len(payload) - 1)


@pytest.mark.timeout(20)
def test_bound_stops_at_the_end_of_a_padded_stream() -> None:
    # pydicom and pynetdicom pad an odd-length deflated Data Set with one NUL. On a stream whose output
    # needs more than one round, zlib keeps that byte in unconsumed_tail after the end, and a loop that
    # only watched the tail spun forever. The payload is compressible, so it takes many rounds.
    compressor = zlib.compressobj(9, zlib.DEFLATED, -zlib.MAX_WBITS)
    payload = bytes(range(256)) * 800
    stream = compressor.compress(payload) + compressor.flush() + b"\x00"

    _inflate.bounded_inflate_or_error(stream, max_bytes=len(payload))
    with pytest.raises(DicomBombError):
        _inflate.bounded_inflate_or_error(stream, max_bytes=len(payload) - 1)


@pytest.mark.parametrize("drift", [AttributeError, KeyError, IndexError, TypeError, ValueError])
def test_guard_does_not_stand_aside_when_the_replay_itself_breaks(
    monkeypatch: pytest.MonkeyPatch, drift: type[Exception]
) -> None:
    # These are what a pydicom API change raises inside the replay. If the guard treated one as "a
    # malformed header, dcmread will fail first", it would stand aside while dcmread inflated. It must
    # propagate instead, so the object is refused.
    import pydicom.filereader

    def broken_reader(fp: object) -> None:
        raise drift("simulated pydicom API drift")

    monkeypatch.setattr(pydicom.filereader, "_read_file_meta_info", broken_reader)
    with pytest.raises(drift, match="simulated pydicom API drift"):
        _inflate.guard_part10_deflate(_bomb(), force=False, max_bytes=_CAP)
