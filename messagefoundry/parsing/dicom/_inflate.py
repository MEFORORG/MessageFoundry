# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Bounded-inflate guard for **Deflated Explicit VR Little Endian** DICOM (ASVS 5.2.3).

A DICOM object whose transfer syntax is ``1.2.840.10008.1.2.1.99`` (Deflated Explicit VR LE, DICOM
PS3.5 A.5) carries its Data Set as a **raw DEFLATE stream** (RFC 1951 — no zlib/gzip wrapper). ``pydicom``
inflates that whole stream into memory with an **unbounded** ``zlib.decompress`` *before* it parses (it
cannot seek inside a deflate stream, so ``stop_before_pixels``/``specific_tags`` do not help). A tiny
compressed "bomb" (a few KiB that inflates to hundreds of MiB) therefore exhausts memory the moment
``dcmread`` touches it. This module pre-checks the inflate **in bounded memory** and rejects an over-cap
object *before* any ``dcmread``.

The raw-stream bound, :func:`bounded_inflate_or_error`, is stdlib-only (``zlib``). The Part-10 guard,
:func:`guard_part10_deflate`, is not, on purpose (BACKLOG #1926). To bound the bytes ``dcmread`` will
inflate, it must read the header exactly as ``dcmread`` does, so it runs ``pydicom``'s own header
readers, the ones ``read_partial`` calls before its inflate. Any second reading of the header can
disagree with ``pydicom``'s, and each disagreement lets a bomb through. Two of those readers are
private; :func:`~messagefoundry.parsing.dicom._deps.load_header_readers` refuses a ``pydicom`` without
them, and ``tests/test_dicom_deflate_guard.py`` pins that the guard bounds exactly the bytes ``pydicom``
hands to ``zlib``. ``pydicom`` is imported lazily, so importing this module still needs no ``[dicom]``
extra. It imports nothing from ``messagefoundry.config`` / ``pipeline`` / ``store`` / ``transports``
(the codec's purity). ``zlib`` is stdlib and **not** a crypto-gate import.

Two entry points:

* :func:`bounded_inflate_or_error` — the core: bound the inflate of a **raw deflate stream** (the shape
  the SCP holds in ``event.request.DataSet`` for a negotiated deflated context).
* :func:`guard_part10_deflate` — for a full **Part-10 file** (the shape the codec peek/dataset and the
  SCU hold): find, as ``dcmread`` will, whether the object is deflated and where its deflated Data Set
  starts, and bound that stream. A no-op when ``dcmread`` will not inflate anything.

Both raise :class:`~messagefoundry.parsing.dicom.errors.DicomBombError` (a ``DicomError``) for an
over-cap deflated object. A corrupt deflate stream that stays under the cap before it breaks is left to
``dcmread``, which fails on it within one :data:`_INFLATE_CHUNK` of what the guard counted. The
Part-10 guard catches nothing from its header replay: whatever ``pydicom`` raises there propagates,
and the callers run the guard inside the same handler that wraps ``dcmread``.
"""

from __future__ import annotations

import zlib
from io import BytesIO

from messagefoundry.parsing.dicom._deps import load_header_readers
from messagefoundry.parsing.dicom.errors import DicomBombError

__all__ = [
    "DEFLATED_EXPLICIT_VR_LE",
    "DEFAULT_MAX_INFLATED_BYTES",
    "bounded_inflate_or_error",
    "guard_part10_deflate",
]

#: Transfer Syntax UID for Deflated Explicit VR Little Endian (DICOM PS3.5 A.5) — the only standard
#: transfer syntax that DEFLATE-compresses the Data Set, so the only one this guard acts on.
DEFLATED_EXPLICIT_VR_LE = "1.2.840.10008.1.2.1.99"

#: Default max **uncompressed** size the deflate stream may reach before it is rejected as a bomb —
#: matches :data:`messagefoundry.parsing.peek.DEFAULT_MAX_MESSAGE_BYTES` (16 MiB, the MLLP/file ingress
#: cap). A module constant; the guard functions take a ``max_bytes`` override (the DIMSE SCP/SCU pass
#: their own ``max_object_bytes`` so the inflate bound matches the object-size policy they already
#: enforce).
DEFAULT_MAX_INFLATED_BYTES = 16 * 1024 * 1024

# The working window: never materialise more than this much decompressed output at once. The inflate is
# cancelled the instant the running total crosses ``max_bytes``, so peak memory is ~this + the shrinking
# compressed remainder, regardless of the declared/actual inflated size.
_INFLATE_CHUNK = 65536


def bounded_inflate_or_error(compressed: bytes | memoryview, *, max_bytes: int) -> None:
    """Inflate a **raw DEFLATE** stream (RFC 1951, DICOM Deflated Explicit VR LE) in bounded memory,
    **discarding** the output, and raise :class:`DicomBombError` if the cumulative uncompressed size
    would exceed ``max_bytes``. Streams the decompression in :data:`_INFLATE_CHUNK`-bounded chunks so a
    small compressed bomb with a huge inflated size never materialises in memory.

    A silent no-op when ``compressed`` is empty or is not a valid deflate stream (``zlib.error``) — those
    are not bombs; the normal ``dcmread`` path then produces the real parse error / dead-letters."""
    if not compressed:
        return
    decompressor = zlib.decompressobj(-zlib.MAX_WBITS)  # negative wbits ⇒ raw deflate, no header
    total = 0
    view = memoryview(compressed)
    try:
        # Feed the input one window at a time. ``unconsumed_tail`` is a copy of the input not yet
        # consumed, so handing the whole stream in at once copies the remainder on every round, and the
        # guard's CPU grows with the square of the compressed size (4 s at 32 MiB, measured 2026-09-24).
        for offset in range(0, len(view), _INFLATE_CHUNK):
            pending: bytes | memoryview = view[offset : offset + _INFLATE_CHUNK]
            # Stop at the end of the stream as well as at the end of the window. After the end, zlib
            # keeps any trailing input in ``unconsumed_tail`` and never consumes it, so a loop on
            # ``pending`` alone spins forever. pydicom and pynetdicom both pad an odd-length stream
            # with one NUL, so a legitimate object is enough to hit that.
            while pending and not decompressor.eof:
                out = decompressor.decompress(pending, _INFLATE_CHUNK)
                total += len(out)
                if total > max_bytes:
                    raise DicomBombError(
                        "deflated DICOM object exceeds the maximum uncompressed size "
                        f"({max_bytes} bytes); refusing to decode (possible decompression bomb)"
                    )
                pending = decompressor.unconsumed_tail
            if decompressor.eof:
                break  # dcmread's one-shot inflate also stops at the end of the first stream
        tail = decompressor.flush()
        total += len(tail)
        if total > max_bytes:
            raise DicomBombError(
                "deflated DICOM object exceeds the maximum uncompressed size "
                f"({max_bytes} bytes); refusing to decode (possible decompression bomb)"
            )
    except zlib.error:
        # Not a valid deflate stream, so dcmread's one-shot inflate fails on it too, at the same point.
        # By then it has produced at most what the loop counted plus one working window, and the loop
        # held its count under the cap. Let dcmread surface the real parse error.
        return


def guard_part10_deflate(data: bytes, *, force: bool, max_bytes: int | None = None) -> None:
    """Bound the inflate ``dcmread(BytesIO(data), force=force)`` would do, **before** it does it.

    ``force`` is required and must be the value the caller then passes to ``dcmread``: with it,
    ``pydicom`` reads an object that has no preamble, and so inflates one. ``max_bytes`` defaults to
    :data:`DEFAULT_MAX_INFLATED_BYTES`, read at call time.

    Raises :class:`DicomBombError` when the deflated Data Set would inflate past the cap. A no-op when
    ``dcmread`` will not inflate: a transfer syntax other than Deflated Explicit VR LE, or no Data Set
    after the header. Raises :class:`RuntimeError` if the ``[dicom]`` extra is missing or no longer has
    the readers. Anything the header replay raises propagates unchanged, so call this inside the same
    handler that wraps the ``dcmread`` it guards; see :func:`_deflated_data_set`."""
    stream = _deflated_data_set(data, force=force)
    if stream is None:
        return
    bounded_inflate_or_error(
        stream, max_bytes=DEFAULT_MAX_INFLATED_BYTES if max_bytes is None else max_bytes
    )


def _deflated_data_set(data: bytes, *, force: bool) -> memoryview | None:
    """The bytes ``dcmread`` would inflate, or ``None`` when it would inflate nothing.

    Replays the header half of ``pydicom.filereader.read_partial`` with the same functions, in the same
    order, on the same bytes: preamble, file-meta group, command set. ``read_partial`` then inflates
    everything after that point when the file meta's ``TransferSyntaxUID`` equals
    ``DeflatedExplicitVRLittleEndian``. That constant is a plain ``str`` subclass, so comparing with
    :data:`DEFLATED_EXPLICIT_VR_LE` is the same comparison.

    It catches nothing. A malformed header raises here what ``dcmread`` would raise at the same step,
    and the caller's handler records it exactly as it would have. A pydicom API change raises here too.
    Either way the object is refused. Standing aside on any error would mean choosing which errors are
    "malformed input" and which are "the replay broke", and a wrong choice fails open."""
    filereader = load_header_readers()
    fp = BytesIO(data)
    filereader.read_preamble(fp, force)
    file_meta = filereader._read_file_meta_info(fp)
    filereader._read_command_set_elements(fp)
    if file_meta.get("TransferSyntaxUID") != DEFLATED_EXPLICIT_VR_LE:
        return None
    return memoryview(data)[fp.tell() :]  # a view: the body can be up to max_object_bytes
