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
    make_deflated_bomb_stream,
    make_deflated_ok_part10,
    make_deflated_part10,
    make_sr_part10,
)

#: The lowered cap. The bomb inflates to 16x this, so a guard that bounds the right bytes refuses it,
#: and one that stands aside lets pydicom inflate a whole MiB.
_CAP = 64 * 1024
_BOMB_INFLATED = 1024 * 1024

_PREAMBLE_AND_MAGIC = 132  # 128-byte preamble + b"DICM"
_GROUP_LENGTH_ELEMENT = 12  # (0002,0000) UL: tag 4 + VR 2 + length 2 + value 4


def _split(obj: bytes) -> tuple[bytes, bytes, bytes, int]:
    """Cut a well-formed Part-10 object into (preamble + magic, rest of the file meta after the group
    length element, deflated Data Set, the declared group length)."""
    group_length = int.from_bytes(obj[140:144], "little")
    meta_end = _PREAMBLE_AND_MAGIC + _GROUP_LENGTH_ELEMENT + group_length
    return obj[:_PREAMBLE_AND_MAGIC], obj[144:meta_end], obj[meta_end:], group_length


def _group_length_element(value: int) -> bytes:
    return b"\x02\x00\x00\x00UL\x04\x00" + value.to_bytes(4, "little")


def _missing_group_length(obj: bytes) -> bytes:
    head, rest, body, _ = _split(obj)
    return head + rest + body


def _short_group_length(obj: bytes) -> bytes:
    head, rest, body, _ = _split(obj)
    return head + _group_length_element(10) + rest + body


def _group_length_plus_one(obj: bytes) -> bytes:
    head, rest, body, gl = _split(obj)
    return head + _group_length_element(gl + 1) + rest + body


def _group_length_minus_four(obj: bytes) -> bytes:
    head, rest, body, gl = _split(obj)
    return head + _group_length_element(gl - 4) + rest + body


def _group_length_all_ones(obj: bytes) -> bytes:
    head, rest, body, _ = _split(obj)
    return head + _group_length_element(0xFFFFFFFF) + rest + body


def _decoy_transfer_syntax(obj: bytes) -> bytes:
    # A first (0002,0010) naming plain Explicit VR LE. The old walk stopped at the first one it met;
    # pydicom keeps the last, which is the deflated one.
    head, rest, body, gl = _split(obj)
    uid = b"1.2.840.10008.1.2.1\x00"
    decoy = b"\x02\x00\x10\x00UI" + len(uid).to_bytes(2, "little") + uid
    return head + _group_length_element(gl + len(decoy)) + decoy + rest + body


def _no_preamble(obj: bytes) -> bytes:
    # The file meta with no 128-byte preamble and no DICM magic. pydicom reads it under force=True.
    return obj[_PREAMBLE_AND_MAGIC:]


def _command_set_before_body(obj: bytes) -> bytes:
    # An Implicit VR (0000,0100) element between the meta and the deflated body. pydicom reads group
    # 0000 as a command set and starts the inflate after it, so the old offset was 10 bytes early.
    head, rest, body, gl = _split(obj)
    command = b"\x00\x00\x00\x01" + (2).to_bytes(4, "little") + b"\x01\x00"
    return head + _group_length_element(gl) + rest + command + body


# (id, mutation, force). ``force`` is the dcmread flag the object needs to be read at all.
_SHAPES: list[tuple[str, Callable[[bytes], bytes], bool]] = [
    ("missing-group-length", _missing_group_length, False),
    ("short-group-length", _short_group_length, False),
    ("group-length-plus-1", _group_length_plus_one, False),
    ("group-length-minus-4", _group_length_minus_four, False),
    ("group-length-0xFFFFFFFF", _group_length_all_ones, False),
    ("decoy-transfer-syntax", _decoy_transfer_syntax, False),
    ("force-without-preamble", _no_preamble, True),
    ("command-set-before-body", _command_set_before_body, False),
]
_IDS = [shape[0] for shape in _SHAPES]
_UNFORCED = [shape for shape in _SHAPES if not shape[2]]
_UNFORCED_IDS = [shape[0] for shape in _UNFORCED]


def _bomb() -> bytes:
    return make_deflated_part10(make_deflated_bomb_stream(inflated_bytes=_BOMB_INFLATED))


@pytest.fixture
def low_cap(monkeypatch: pytest.MonkeyPatch) -> None:
    """Lower the codec default cap that DicomPeek.parse and DicomDataset.parse fall back to."""
    monkeypatch.setattr(_inflate, "DEFAULT_MAX_INFLATED_BYTES", _CAP)


def test_the_unmutated_bomb_is_refused_at_the_lowered_cap(low_cap: None) -> None:
    # Positive control: the lowered cap and the bomb are armed, so a refusal below is the guard's.
    with pytest.raises(DicomBombError):
        DicomDataset.parse(_bomb())


@pytest.mark.parametrize(("name", "mutate", "force"), _SHAPES, ids=_IDS)
def test_dataset_parse_refuses_a_bomb_behind_a_malformed_meta(
    low_cap: None, name: str, mutate: Callable[[bytes], bytes], force: bool
) -> None:
    with pytest.raises(DicomBombError):
        DicomDataset.parse(mutate(_bomb()), force=force)


@pytest.mark.parametrize(("name", "mutate", "force"), _UNFORCED, ids=_UNFORCED_IDS)
def test_peek_refuses_a_bomb_behind_a_malformed_meta(
    low_cap: None, name: str, mutate: Callable[[bytes], bytes], force: bool
) -> None:
    with pytest.raises(DicomBombError):
        DicomPeek.parse(mutate(_bomb()))


def test_peek_without_force_still_reports_a_missing_preamble_as_unparseable(low_cap: None) -> None:
    # DicomPeek never forces, so pydicom refuses the object before any inflate. The guard leaves that
    # to dcmread, whose error the codec already turns into a DicomPeekError.
    with pytest.raises(DicomPeekError):
        DicomPeek.parse(_no_preamble(_bomb()))


@pytest.mark.parametrize(("name", "mutate", "force"), _UNFORCED, ids=_UNFORCED_IDS)
async def test_scu_refuses_a_bomb_behind_a_malformed_meta(
    name: str, mutate: Callable[[bytes], bytes], force: bool
) -> None:
    # The outbound SCU calls the same guard with its own max_object_bytes. The refusal happens before
    # any association, so no peer is needed and port 9 is never dialled.
    pytest.importorskip("pynetdicom", reason="the DICOM SCU needs the [dicom] extra")
    from messagefoundry.config.models import ConnectorType, Destination
    from messagefoundry.parsing import RawMessage
    from messagefoundry.transports.base import NegativeAckError
    from messagefoundry.transports.dicom import DicomScuDestination

    data = mutate(_bomb())
    assert len(data) < _CAP  # the raw object passes max_object_bytes; only its inflate is over
    scu = DicomScuDestination(
        Destination(
            name="OB_SCU",
            type=ConnectorType.DIMSE,
            settings={
                "ae_title": "MEFOR_SCU",
                "host": "127.0.0.1",
                "port": 9,
                "called_ae_title": "PACS_SCP",
                "max_object_bytes": _CAP,
            },
        )
    )
    with pytest.raises(NegativeAckError) as exc:
        await scu.send(RawMessage.from_bytes(data, "dicom").encode())
    assert exc.value.code == "deflate-bomb"
    assert exc.value.permanent is True


@pytest.mark.parametrize(("name", "mutate", "force"), _SHAPES, ids=_IDS)
def test_guard_bounds_exactly_the_bytes_pydicom_inflates(
    monkeypatch: pytest.MonkeyPatch, name: str, mutate: Callable[[bytes], bytes], force: bool
) -> None:
    """The invariant behind the fix: the stream the guard bounds IS the stream pydicom decompresses.

    Uses a small, valid deflated object, so it also proves the guard does not over-refuse: every shape
    pydicom tolerates still parses. If a pydicom upgrade moves where it starts the inflate, this fails
    before a bomb can get through."""
    guarded: list[bytes] = []
    inflated: list[bytes] = []
    real_bound = _inflate.bounded_inflate_or_error

    def record_bound(stream: bytes, *, max_bytes: int) -> None:
        guarded.append(stream)
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
    _inflate.guard_part10_deflate(make_sr_part10(), max_bytes=1)


def test_guard_leaves_an_unreadable_header_to_dcmread() -> None:
    # pydicom runs the same header reader first and fails there, before its inflate, so the guard
    # stands aside and the codec records dcmread's own parse error.
    _inflate.guard_part10_deflate(b"not a DICOM object", max_bytes=1)
    with pytest.raises(DicomPeekError):
        DicomPeek.parse(b"not a DICOM object")
