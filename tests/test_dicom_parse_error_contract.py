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
import sys
import traceback
from collections.abc import Callable, Sequence

import pytest

pytest.importorskip("pydicom", reason="DICOM parse-contract tests need the [dicom] extra")

from pydicom.dataset import Dataset  # noqa: E402
from pydicom.errors import BytesLengthException  # noqa: E402

from messagefoundry.parsing.dicom import (  # noqa: E402
    DicomDataset,
    DicomError,
    DicomPeek,
    DicomPeekError,
    _inflate,
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
    parse: _Parse,
    wrapper: type[DicomError],
    seed: bytes,
    cause: type[BaseException],
    raised_in: str | None = None,
) -> None:
    """``parse(seed)`` raises ``wrapper`` around a ``cause``. With ``raised_in``, the cause's
    traceback must pass through that function, which pins the path a case says it covers."""
    with pytest.raises(wrapper) as excinfo:
        parse(seed)
    inner = excinfo.value.__cause__
    assert isinstance(inner, cause), (
        f"expected the {wrapper.__name__} to wrap a {cause.__name__}, got {type(inner).__name__}"
    )
    if raised_in is not None:
        frames = [frame.name for frame in traceback.extract_tb(inner.__traceback__)]
        assert raised_in in frames, f"expected the {cause.__name__} from {raised_in}, got {frames}"


@pytest.mark.parametrize(("parse", "wrapper", "seed", "cause"), _cases(_GUARD_PATH))
def test_a_header_the_guard_replay_rejects_is_a_dicom_error(
    parse: _Parse, wrapper: type[DicomError], seed: bytes, cause: type[BaseException]
) -> None:
    # dcmread would raise the same class, so the frame check is what separates this path from the
    # without-the-guard test below.
    _assert_wrapped(parse, wrapper, seed, cause, raised_in="guard_part10_deflate")


@pytest.mark.parametrize(
    ("parse", "wrapper", "seed", "cause"),
    _cases([("unknown-vr-charset", _unknown_vr_character_set(), NotImplementedError)]),
)
def test_a_body_element_dcmread_rejects_is_a_dicom_error(
    parse: _Parse, wrapper: type[DicomError], seed: bytes, cause: type[BaseException]
) -> None:
    _inflate.guard_part10_deflate(seed, force=False)  # the guard passes it, so dcmread meets it
    _assert_wrapped(parse, wrapper, seed, cause, raised_in="read_partial")


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
    _assert_wrapped(parse, wrapper, seed, cause, raised_in="read_partial")


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


# --- BACKLOG #1599: a deeply nested sequence --------------------------------------------------------


def _recursing_dcmread(*_args: object, **_kwargs: object) -> object:
    raise RecursionError("simulated deep SQ nesting")


@pytest.mark.parametrize(("surface", "parse", "wrapper"), _SURFACES, ids=[s[0] for s in _SURFACES])
def test_a_recursion_error_from_dcmread_is_a_dicom_error(
    monkeypatch: pytest.MonkeyPatch, surface: str, parse: _Parse, wrapper: type[DicomError]
) -> None:
    """pydicom's sequence reader recurses once per nesting level, so a crafted object with a few
    hundred nested ``ContentSequence`` items raises ``RecursionError`` out of ``dcmread``.

    THE TRIGGER IS A RAISED ``RecursionError``, NOT REAL NESTING. The depth at which a real object
    overflows is a property of the runner's stack, not of this code, and a test keyed to it went
    red on one runner and green on another (BACKLOG #1222; the write-up is
    ``tests/test_sandbox_codec.py::test_recursion_error_is_not_a_value_error``). What the contract
    needs is the handler, and that needs no real overflow."""
    module = peek_module if surface == "peek" else dataset_module
    monkeypatch.setattr(module, "load_dcmread", lambda: _recursing_dcmread)
    seed = make_sr_part10()
    _inflate.guard_part10_deflate(seed, force=False)  # the guard passes it, so dcmread is reached
    _assert_wrapped(parse, wrapper, seed, RecursionError, raised_in="_recursing_dcmread")


def test_recursion_error_is_named_and_is_not_a_deploy_error() -> None:
    # The type facts the handler depends on: RecursionError is a RuntimeError, so naming it must
    # not widen the tuple to the RuntimeError a missing [dicom] extra raises (checked above).
    assert issubclass(RecursionError, parse_error_types())
    assert issubclass(RecursionError, RuntimeError)
    assert not issubclass(RecursionError, ValueError)


def _sr_item(value_type: str, code: str = "") -> Dataset:
    item = Dataset()
    item.ValueType = value_type
    if value_type == "NUM":
        concept = Dataset()
        concept.CodeValue = code
        item.ConceptNameCodeSequence = [concept]
    return item


def test_the_measurement_walk_keeps_depth_first_order() -> None:
    """Control for the iterative walk: pre-order, a parent's NUM before its subtree, and a subtree
    before the parent's later siblings."""
    root = Dataset()
    container = _sr_item("CONTAINER")
    inner = _sr_item("CONTAINER")
    inner.ContentSequence = [_sr_item("NUM", "c")]
    parent_num = _sr_item("NUM", "b")
    parent_num.ContentSequence = [inner, _sr_item("NUM", "d")]
    container.ContentSequence = [parent_num, _sr_item("NUM", "e")]
    root.ContentSequence = [_sr_item("NUM", "a"), container, _sr_item("NUM", "f")]
    codes = [m.concept_code for m in DicomDataset(root).measurements()]
    assert codes == ["a", "b", "c", "d", "e", "f"]


def test_the_measurement_walk_does_not_recurse_on_a_deep_tree() -> None:
    """The walk runs after ``parse`` returns, outside the parse wrap, so a recursive walk would raise
    ``RecursionError`` out of ``measurements()`` on an in-memory tree nested past the interpreter
    limit. The depth is keyed to ``sys.getrecursionlimit()``: the walk is pure Python, so that limit,
    not the C stack, is what a recursive walk would meet."""
    depth = sys.getrecursionlimit() + 200
    root = Dataset()
    level = root
    for _ in range(depth):
        child = _sr_item("CONTAINER")
        level.ContentSequence = [child]
        level = child
    level.ContentSequence = [_sr_item("NUM", "deepest")]
    assert [m.concept_code for m in DicomDataset(root).measurements()] == ["deepest"]
