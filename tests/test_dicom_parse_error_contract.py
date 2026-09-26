# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #1893: a malformed DICOM object must fail both parse surfaces as a ``DicomError``.

``DicomPeek.parse`` promises ``DicomPeekError`` and ``DicomDataset.parse`` promises ``DicomError``.
pydicom 3.0.2 raises at least two classes that no member of ``parse_error_types()`` covered:
``BytesLengthException`` (from ``pydicom.errors``, rooted at ``Exception``) and
``NotImplementedError`` (an unknown VR, from ``values.py``). Each case below is one surface, one
seed and one path, and asserts the pydicom class as the wrapped cause, so a test that fails names it.

There are three paths, because pydicom meets a malformed value at three different times:

* the deflate guard's header replay, which runs before ``dcmread`` (BACKLOG #1926);
* ``dcmread`` itself, for an element it converts while reading the body;
* a lazy read after ``dcmread`` returns, which only the peek does inside ``parse``.

All objects here are synthetic and PHI-free.
"""

from __future__ import annotations

import base64
from collections.abc import Callable, Sequence

import pytest

pytest.importorskip("pydicom", reason="DICOM parse-contract tests need the [dicom] extra")

from pydicom.errors import BytesLengthException  # noqa: E402

from messagefoundry.parsing.dicom import (  # noqa: E402
    DicomDataset,
    DicomError,
    DicomPeek,
    DicomPeekError,
)
from messagefoundry.parsing.dicom import dataset as dataset_module  # noqa: E402
from messagefoundry.parsing.dicom import peek as peek_module  # noqa: E402
from messagefoundry.parsing.dicom._deps import parse_error_types  # noqa: E402
from tests._dicom_sample import make_sr_part10  # noqa: E402

#: A preamble, ``DICM``, then a (0002,0000) group length with VR UL and a 3-byte value. UL needs a
#: multiple of 4 bytes, so pydicom raises BytesLengthException when it reads the file meta.
_ODD_UL_META = b"\x00" * 128 + b"DICM" + b"\x02\x00\x00\x00UL\x03\x00" + b"\x00\x00\x00"

#: The 155-byte crash unit from fuzz run 35761703252, the run that found this. The same bytes are
#: ``_REPRO_B64`` in ``tests/test_fuzz_targets.py``, where they test the reporter, not the parser.
_REPRO = base64.b64decode(
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "RElDTQAAAAACAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABESUNNAgAAAAAAAAAAAP//AABESUNNAgAAAPz/"
    "//8AAAAAAAAA//////////8="
)


def _with_vr(obj: bytes, tag_and_vr: bytes, new_vr: bytes) -> bytes:
    """Rewrite one explicit-VR element's two VR bytes, found by its tag and old VR."""
    at = obj.index(tag_and_vr)
    return obj[: at + 4] + new_vr + obj[at + 6 :]


def _unknown_vr_in_meta() -> bytes:
    # TransferSyntaxUID (0002,0010) with VR "U ", which no pydicom converter knows.
    return _with_vr(make_sr_part10(), b"\x02\x00\x10\x00UI", b"U ")


def _unknown_vr_character_set() -> bytes:
    # A SpecificCharacterSet (0008,0005) with VR "QQ", inserted in tag order before SOPClassUID.
    # dcmread converts this element while it reads the body, so the file meta stays well formed and
    # the guard passes. That makes it the one seed that reaches dcmread's raise with the real guard.
    obj = make_sr_part10()
    at = obj.index(b"\x08\x00\x16\x00UI")
    value = b"ISO_IR 100"
    element = b"\x08\x00\x05\x00QQ" + len(value).to_bytes(2, "little") + value
    return obj[:at] + element + obj[at:]


def _modality_as(vr: bytes) -> bytes:
    # Modality (0008,0060) holds "SR", two bytes. As FD (8 bytes a value) it cannot be read, and as
    # "QQ" it has no converter. dcmread leaves both raw; the peek reads Modality after it returns.
    return _with_vr(make_sr_part10(), b"\x08\x00\x60\x00CS", vr)


def _no_guard(data: bytes, *, force: bool, max_bytes: int | None = None) -> None:
    """Stand-in for the deflate guard, so a file-meta seed reaches dcmread's own read of it."""


_Parse = Callable[[bytes], object]
_SURFACES: list[tuple[str, _Parse, type[DicomError]]] = [
    ("peek", DicomPeek.parse, DicomPeekError),
    ("dataset", DicomDataset.parse, DicomError),
]

#: (id, seed, the pydicom class it raises). With the real guard, a file-meta seed raises from the
#: guard's header replay, because the guard reads the header before dcmread does.
_GUARD_PATH = [
    ("odd-ul-meta", _ODD_UL_META, BytesLengthException),
    ("fuzz-repro", _REPRO, BytesLengthException),
    ("unknown-vr-meta", _unknown_vr_in_meta(), NotImplementedError),
]


def _cases(seeds: Sequence[tuple[str, bytes, type[BaseException]]]) -> list[object]:
    return [
        pytest.param(parse, wrapper, seed, cause, id=f"{surface}-{name}")
        for surface, parse, wrapper in _SURFACES
        for name, seed, cause in seeds
    ]


def _assert_wrapped(
    parse: _Parse, wrapper: type[DicomError], seed: bytes, cause: type[BaseException]
) -> None:
    with pytest.raises(wrapper) as excinfo:
        parse(seed)
    assert isinstance(excinfo.value.__cause__, cause), (
        f"expected the {wrapper.__name__} to wrap a {cause.__name__}, "
        f"got {type(excinfo.value.__cause__).__name__}"
    )


@pytest.mark.parametrize(("parse", "wrapper", "seed", "cause"), _cases(_GUARD_PATH))
def test_a_header_the_guard_replay_rejects_is_a_dicom_error(
    parse: _Parse, wrapper: type[DicomError], seed: bytes, cause: type[BaseException]
) -> None:
    _assert_wrapped(parse, wrapper, seed, cause)


@pytest.mark.parametrize(
    ("parse", "wrapper", "seed", "cause"),
    _cases([("unknown-vr-charset", _unknown_vr_character_set(), NotImplementedError)]),
)
def test_a_body_element_dcmread_rejects_is_a_dicom_error(
    parse: _Parse, wrapper: type[DicomError], seed: bytes, cause: type[BaseException]
) -> None:
    _assert_wrapped(parse, wrapper, seed, cause)


@pytest.mark.parametrize(("parse", "wrapper", "seed", "cause"), _cases(_GUARD_PATH))
def test_a_header_dcmread_rejects_is_a_dicom_error_without_the_guard(
    monkeypatch: pytest.MonkeyPatch,
    parse: _Parse,
    wrapper: type[DicomError],
    seed: bytes,
    cause: type[BaseException],
) -> None:
    """dcmread's own read of the same header. No seed found reaches a BytesLengthException in
    dcmread past the real guard, because the guard replays that read first, so the guard is stubbed
    here. It covers the order in which the two run changing, or the guard being taken out."""
    monkeypatch.setattr(peek_module, "guard_part10_deflate", _no_guard)
    monkeypatch.setattr(dataset_module, "guard_part10_deflate", _no_guard)
    _assert_wrapped(parse, wrapper, seed, cause)


@pytest.mark.parametrize(
    ("seed", "cause"),
    [
        pytest.param(_modality_as(b"FD"), BytesLengthException, id="modality-fd"),
        pytest.param(_modality_as(b"QQ"), NotImplementedError, id="modality-unknown-vr"),
    ],
)
def test_a_value_the_peek_reads_after_dcmread_is_a_peek_error(
    seed: bytes, cause: type[BaseException]
) -> None:
    """pydicom converts a value only when it is read. The peek reads its routing fields after
    dcmread returns, so those reads must sit inside the same handler."""
    _assert_wrapped(DicomPeek.parse, DicomPeekError, seed, cause)


def test_the_tuple_names_every_exception_class_pydicom_errors_defines() -> None:
    """The narrow guard the row asked about: a future pydicom that adds an ``Exception``-rooted class
    to ``pydicom.errors`` fails here, before a fuzzer or a site finds it.

    It reads one public module only. It cannot see ``NotImplementedError`` or any other class
    pydicom raises from elsewhere, so it is a floor, not proof of coverage."""
    import pydicom.errors

    defined = sorted(
        (
            obj
            for obj in vars(pydicom.errors).values()
            if isinstance(obj, type)
            and issubclass(obj, BaseException)
            and obj.__module__ == pydicom.errors.__name__
        ),
        key=lambda cls: cls.__name__,
    )
    names = [cls.__name__ for cls in defined]
    # Positive control: an instrument that finds nothing would pass the check below vacuously.
    assert "InvalidDicomError" in names, f"pydicom.errors enumerated to {names}"
    missing = [cls.__name__ for cls in defined if not issubclass(cls, parse_error_types())]
    assert not missing, f"checked {names}; parse_error_types() does not cover {missing}"


@pytest.mark.parametrize("deploy_error", [RuntimeError, Exception, BaseException])
def test_the_tuple_never_catches_a_deploy_error(deploy_error: type[BaseException]) -> None:
    """A missing or broken ``[dicom]`` extra raises ``RuntimeError``. Catching it would dead-letter
    every DICOM message as bad data instead of failing the deploy."""
    assert not issubclass(deploy_error, parse_error_types())
